//! Listen / dial / sync / tip-follow orchestration.

use crate::cache::BlockCache;
use crate::chain::{AcceptOutcome, ChainHub};
use crate::error::NetError;
use crate::ibd::IbdConfig;
use crate::peer::{
    connect_and_handshake_timed, inbound_connect_and_handshake, peer_session_with,
    FollowSessionMeta, HandshakePolicy, HANDSHAKE_TIMEOUT,
};
use crate::peer_dos::{inbound_semaphore, DEFAULT_MAX_INBOUND};
use crate::peers::{DialRequest, LivePeer, PeerConnType, PeerHub};
use crate::v2::{V2Reader, V2Writer};
use bitcoin::p2p::Magic;
use bitcoin::Block;
use bitcoin::BlockHash;
use rbitcoin_consensus::{signet_magic, ChainParams, Milestone};
use rbitcoin_primitives::Network as RNetwork;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub magic: Magic,
    pub listen: Option<SocketAddr>,
    pub user_agent: String,
}

impl NetConfig {
    pub fn for_regtest(listen: Option<SocketAddr>) -> Self {
        Self {
            magic: Magic::REGTEST,
            listen,
            user_agent: rbitcoin_primitives::rbitcoin_subversion(
                env!("CARGO_PKG_VERSION"),
                &[] as &[&str],
            )
            .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION"))),
        }
    }
}

/// Running P2P node handle (listen + optional outbound sync / tip follow).
pub struct P2PNode {
    /// Shared RAM cache (also on hub).
    pub cache: Arc<BlockCache>,
    /// Shared query store (also on hub).
    pub query: Arc<Query>,
    pub hub: Arc<ChainHub>,
    pub local_addr: SocketAddr,
    magic: Magic,
    shutdown: Arc<AtomicBool>,
    /// Live outbound tip-follow sessions (inc/dec inside session task).
    follow_live: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
    /// Nested inbound / dial session tasks (not in `tasks` so accept/dial
    /// abort does not leave them running through process exit).
    session_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Live sessions for RPC getpeerinfo / addnode / disconnectnode.
    pub peers: Arc<PeerHub>,
    user_agent: String,
    /// Inbound session cap used by the accept loop (not process env).
    pub max_inbound: usize,
}

pub struct P2PHandle {
    pub cache: Arc<BlockCache>,
    pub query: Arc<Query>,
    pub local_addr: SocketAddr,
}

impl P2PNode {
    /// Bind listener. Serves getheaders/getdata and participates in tip announce/follow.
    pub async fn start(
        listen: SocketAddr,
        query: Query,
        params: ChainParams,
        milestone: Milestone,
    ) -> Result<Self, NetError> {
        Self::start_with_agent(
            listen,
            query,
            params,
            milestone,
            default_user_agent(),
            DEFAULT_MAX_INBOUND,
        )
        .await
    }

    /// Like [`Self::start`] with an explicit BIP14 user-agent (RPC `subversion`)
    /// and inbound session cap.
    pub async fn start_with_agent(
        listen: SocketAddr,
        query: Query,
        params: ChainParams,
        milestone: Milestone,
        user_agent: String,
        max_inbound: usize,
    ) -> Result<Self, NetError> {
        let magic = magic_for_params(&params);
        let hub = Arc::new(ChainHub::new(query, params, milestone));
        hub.ensure_genesis()?;
        let cache = hub.cache.clone();
        let query = hub.query.clone();
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));

        let peers = PeerHub::new();
        let (dial_tx, mut dial_rx) = tokio::sync::mpsc::unbounded_channel::<DialRequest>();
        peers.set_dialer(dial_tx);

        let hub_c = hub.clone();
        let shutdown_c = shutdown.clone();
        let magic_c = magic;
        let peers_in = peers.clone();
        let ua_in = user_agent.clone();
        let max_inbound = max_inbound.max(1);
        let inbound_sem = inbound_semaphore(max_inbound);
        let session_tasks = Arc::new(Mutex::new(Vec::<JoinHandle<()>>::new()));
        let sessions_in = session_tasks.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                if shutdown_c.load(Ordering::SeqCst) {
                    break;
                }
                let accept =
                    tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
                match accept {
                    Ok(Ok((stream, peer_addr))) => {
                        let Ok(permit) = inbound_sem.clone().try_acquire_owned() else {
                            rbitcoin_log::warn!(
                                "p2p: reject inbound {peer_addr} (at max_inbound={max_inbound})"
                            );
                            drop(stream);
                            continue;
                        };
                        let our = local_addr;
                        let hub = hub_c.clone();
                        let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
                        let tip_rx = hub.subscribe_tips();
                        let peers = peers_in.clone();
                        let ua = ua_in.clone();
                        let bind = match stream.local_addr() {
                            Ok(a) => a,
                            Err(_) => our,
                        };
                        let sessions = sessions_in.clone();
                        let h = tokio::spawn(async move {
                            let _session_slot = permit;
                            let (ver, reader, writer, wire) = match inbound_connect_and_handshake(
                                stream,
                                magic_c,
                                our,
                                peer_addr,
                                height,
                                &ua,
                                HandshakePolicy {
                                    hub: Some(hub.as_ref()),
                                    peers: Some(peers.as_ref()),
                                    conn_type: PeerConnType::Inbound,
                                },
                            )
                            .await
                            {
                                Ok(x) => x,
                                Err(e) => {
                                    // V1-only peers fail BIP324; log once-style message.
                                    rbitcoin_log::debug!(
                                        "p2p: inbound handshake {peer_addr} failed: {e}"
                                    );
                                    return;
                                }
                            };
                            let sess =
                                peers.register(peer_addr, bind, &ver, true, PeerConnType::Inbound);
                            if let Some(mp) = hub.mempool() {
                                sess.set_inv_gen_floor(mp.next_accept_gen());
                            }
                            sess.attach_wire(wire);
                            let id = sess.id;
                            let meta = FollowSessionMeta {
                                peer: Some(peer_addr),
                                live: None,
                                session: Some(sess),
                            };
                            let _ =
                                peer_session_with(reader, writer, magic_c, hub, tip_rx, meta).await;
                            peers.unregister(id);
                        });
                        push_session_task(&sessions, h);
                    }
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                }
            }
        });

        let follow_live = Arc::new(AtomicUsize::new(0));
        let dial_hub = hub.clone();
        let dial_peers = peers.clone();
        let dial_ua = user_agent.clone();
        let dial_live = follow_live.clone();
        let dial_shutdown = shutdown.clone();
        let sessions_dial = session_tasks.clone();
        let dial_task = tokio::spawn(async move {
            while let Some(req) = dial_rx.recv().await {
                if dial_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let hub = dial_hub.clone();
                let peers = dial_peers.clone();
                let ua = dial_ua.clone();
                let live = dial_live.clone();
                let h = tokio::spawn(async move {
                    let _ = run_outbound_session(
                        req.addr, magic, local_addr, hub, peers, ua, live, req.typ,
                    )
                    .await;
                });
                push_session_task(&sessions_dial, h);
            }
        });

        Ok(Self {
            cache,
            query,
            hub,
            local_addr,
            magic,
            shutdown,
            follow_live,
            tasks: vec![accept_task, dial_task],
            session_tasks,
            peers,
            user_agent,
            max_inbound,
        })
    }

    /// BIP14 subversion advertised in `version` (same as RPC `getnetworkinfo`).
    pub fn set_user_agent(&mut self, ua: impl Into<String>) {
        self.user_agent = ua.into();
    }

    /// Number of live outbound tip-follow sessions.
    pub fn follow_live_count(&self) -> usize {
        self.follow_live.load(Ordering::SeqCst)
    }

    pub fn handle(&self) -> P2PHandle {
        P2PHandle {
            cache: self.cache.clone(),
            query: self.query.clone(),
            local_addr: self.local_addr,
        }
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.hub.tip_height()
    }

    /// Push a validated block into cache + store.
    pub fn ingest_block(&self, height: u32, block: Block) -> Result<(), NetError> {
        let _ = height;
        match self.hub.accept_received_block(block)? {
            AcceptOutcome::Accepted { .. } | AcceptOutcome::AlreadyHave => Ok(()),
            AcceptOutcome::IgnoredWeaker => Err(NetError::Protocol("weaker tip ignored")),
        }
    }

    /// IBD / catch-up: multi-peer download window across `peers` (libbitcoin-class).
    ///
    /// This is the only history-sync path. Tip-follow is [`Self::follow_from`].
    pub async fn sync(&self, peers: &[SocketAddr], cfg: IbdConfig) -> Result<u32, NetError> {
        self.sync_cancellable(peers, cfg, None).await
    }

    /// IBD with optional cooperative cancel flag (SIGINT / SIGTERM path).
    pub async fn sync_cancellable(
        &self,
        peers: &[SocketAddr],
        cfg: IbdConfig,
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<u32, NetError> {
        crate::ibd::ibd_cancellable(
            self.hub.clone(),
            self.magic,
            self.local_addr,
            peers,
            cfg,
            cancel,
        )
        .await
    }

    /// IBD with default window (1024 concurrent getdata, 16/peer).
    pub async fn sync_default(&self, peers: &[SocketAddr]) -> Result<u32, NetError> {
        self.sync(peers, IbdConfig::default()).await
    }

    /// Persistent outbound peer: tip-follow + announce for the session lifetime.
    ///
    /// Handshake completes on this task (so an 8s connect timeout is meaningful);
    /// the session itself is spawned so the caller does not sit in the read loop.
    /// After handshake the session sends `getheaders` from our tip locator so
    /// any gap (e.g. blocks mined during SH materialize) is filled actively.
    /// Call [`Self::sync`] first when far behind (multi-thousand height IBD).
    pub async fn follow_from(&mut self, peer: SocketAddr) -> Result<(), NetError> {
        let prepared = prepare_outbound_session(
            peer,
            self.magic,
            self.local_addr,
            self.hub.clone(),
            self.peers.clone(),
            self.user_agent.clone(),
            self.follow_live.clone(),
            PeerConnType::OutboundFullRelay,
        )
        .await?;
        let handle = tokio::spawn(async move {
            let _ = run_prepared_outbound(prepared).await;
        });
        self.tasks.push(handle);
        Ok(())
    }

    pub async fn wait_height(&self, height: u32, timeout: Duration) -> Result<(), NetError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.tip_height().unwrap_or(0) >= height {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetError::Timeout);
            }
            tokio::select! {
                _ = self.hub.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    }

    pub async fn wait_tip_hash(&self, hash: BlockHash, timeout: Duration) -> Result<(), NetError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.hub.tip_hash() == Some(hash) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetError::Timeout);
            }
            tokio::select! {
                _ = self.hub.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    }

    pub async fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for p in self.peers.live_peers() {
            p.request_disconnect();
        }
        let mut join = Vec::new();
        for t in self.tasks.drain(..) {
            t.abort();
            join.push(t);
        }
        if let Ok(mut g) = self.session_tasks.lock() {
            for t in g.drain(..) {
                t.abort();
                join.push(t);
            }
        }
        let _ = tokio::time::timeout(Duration::from_millis(250), async {
            for t in join {
                let _ = t.await;
            }
        })
        .await;
    }
}

fn push_session_task(bag: &Mutex<Vec<JoinHandle<()>>>, h: JoinHandle<()>) {
    if let Ok(mut g) = bag.lock() {
        g.retain(|t| !t.is_finished());
        g.push(h);
    }
}

fn default_user_agent() -> String {
    rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
        .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")))
}

struct PreparedOutbound {
    peer: SocketAddr,
    magic: Magic,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    follow_live: Arc<AtomicUsize>,
    reader: V2Reader,
    writer: V2Writer,
    sess: Arc<LivePeer>,
    id: u64,
}

async fn prepare_outbound_session(
    peer: SocketAddr,
    magic: Magic,
    local: SocketAddr,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    user_agent: String,
    follow_live: Arc<AtomicUsize>,
    typ: PeerConnType,
) -> Result<PreparedOutbound, NetError> {
    rbitcoin_log::debug!("trying v1 connection ({}) to {}", typ.as_str(), peer);
    let stream = TcpStream::connect(peer).await?;
    let bind = stream.local_addr().unwrap_or(local);
    let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
    // Core adds CNode before VERSION. Provisional row so getpeerinfo is non-empty
    // during handshake (p2p_handshake self-connect wait_until + assert_debug_log).
    let provisional = peers.register_connecting(peer, bind, typ);
    let provisional_id = provisional.id;
    let handshake = connect_and_handshake_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        local,
        peer,
        height,
        false,
        &user_agent,
        HandshakePolicy {
            hub: Some(hub.as_ref()),
            peers: Some(peers.as_ref()),
            conn_type: typ,
        },
    )
    .await;
    let (ver, reader, writer, wire) = match handshake {
        Ok(x) => x,
        Err(e) => {
            peers.unregister(provisional_id);
            return Err(e);
        }
    };
    peers.unregister(provisional_id);
    let sess = peers.register_with_id(provisional_id, peer, bind, &ver, false, typ);
    if let Some(mp) = hub.mempool() {
        sess.set_inv_gen_floor(mp.next_accept_gen());
    }
    sess.attach_wire(wire);
    let id = sess.id;
    follow_live.fetch_add(1, Ordering::SeqCst);
    Ok(PreparedOutbound {
        peer,
        magic,
        hub,
        peers,
        follow_live,
        reader,
        writer,
        sess,
        id,
    })
}

async fn run_prepared_outbound(prepared: PreparedOutbound) -> Result<(), NetError> {
    let tip_rx = prepared.hub.subscribe_tips();
    let meta = FollowSessionMeta {
        peer: Some(prepared.peer),
        live: Some(prepared.follow_live),
        session: Some(prepared.sess),
    };
    let out = peer_session_with(
        prepared.reader,
        prepared.writer,
        prepared.magic,
        prepared.hub,
        tip_rx,
        meta,
    )
    .await;
    prepared.peers.unregister(prepared.id);
    out
}

async fn run_outbound_session(
    peer: SocketAddr,
    magic: Magic,
    local: SocketAddr,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    user_agent: String,
    follow_live: Arc<AtomicUsize>,
    typ: PeerConnType,
) -> Result<(), NetError> {
    if typ == PeerConnType::Feeler {
        let stream = TcpStream::connect(peer).await?;
        let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
        return crate::peer::run_feeler(stream, magic, local, peer, height, &user_agent).await;
    }
    let prepared =
        prepare_outbound_session(peer, magic, local, hub, peers, user_agent, follow_live, typ)
            .await?;
    run_prepared_outbound(prepared).await
}

/// Map our Network enum to bitcoin Magic.
pub fn magic_for(network: RNetwork) -> Magic {
    Magic::from(match network {
        RNetwork::Mainnet => bitcoin::Network::Bitcoin,
        RNetwork::Testnet => bitcoin::Network::Testnet,
        RNetwork::Signet => bitcoin::Network::Signet,
        RNetwork::Regtest => bitcoin::Network::Regtest,
    })
}

/// Resolve P2P message magic, including BIP325 custom-Signet derivation.
pub fn magic_for_params(params: &ChainParams) -> Magic {
    match params.signet_challenge.as_ref() {
        Some(challenge) => Magic::from_bytes(signet_magic(challenge.as_script())),
        None => Magic::from(params.network),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_for_all_networks_and_regtest_config() {
        assert_eq!(
            magic_for(RNetwork::Mainnet),
            Magic::from(bitcoin::Network::Bitcoin)
        );
        assert_eq!(
            magic_for(RNetwork::Testnet),
            Magic::from(bitcoin::Network::Testnet)
        );
        assert_eq!(
            magic_for(RNetwork::Signet),
            Magic::from(bitcoin::Network::Signet)
        );
        assert_eq!(magic_for(RNetwork::Regtest), Magic::REGTEST);
        let cfg = NetConfig::for_regtest(None);
        assert_eq!(cfg.magic, Magic::REGTEST);
        assert!(cfg.listen.is_none());
        assert_eq!(
            cfg.user_agent,
            rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
                .unwrap()
        );
    }

    #[test]
    fn custom_signet_uses_challenge_derived_magic() {
        use bitcoin::ScriptBuf;

        let challenge = ScriptBuf::from_bytes(vec![0x51]);
        let params = ChainParams::custom_signet(challenge, 60).unwrap();
        assert_eq!(
            magic_for_params(&params),
            Magic::from_bytes([0x54, 0xd2, 0x6f, 0xbd])
        );
    }

    #[tokio::test]
    async fn shutdown_aborts_lingering_session_task() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-p2p-shutdown-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = rbitcoin_query::Query::open_or_create(&dir).unwrap();
        let mut node = P2PNode::start(
            "127.0.0.1:0".parse().unwrap(),
            q,
            ChainParams::regtest(),
            Milestone::NONE,
        )
        .await
        .unwrap();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        node.tasks.push(sleeper);
        let t0 = std::time::Instant::now();
        node.shutdown().await;
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "shutdown must not wait out a 30s session task"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
