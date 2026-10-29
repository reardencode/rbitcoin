//! Listen / dial / sync / tip-follow orchestration.

use crate::cache::BlockCache;
use crate::chain::{AcceptOutcome, ChainHub};
use crate::error::NetError;
use crate::peer::{
    connect_and_handshake_timed, inbound_connect_and_handshake, peer_session_with,
    FollowSessionMeta, HandshakePolicy, HANDSHAKE_TIMEOUT,
};
use crate::peer_dos::{inbound_semaphore, DEFAULT_MAX_INBOUND};
use crate::peers::{DialRequest, DialTarget, LivePeer, PeerConnType, PeerHub};
use crate::v2::{V2Reader, V2Writer};
use bitcoin::p2p::Magic;
use bitcoin::Block;
use bitcoin::BlockHash;
use rbitcoin_consensus::{signet_magic, ChainParams, Milestone};
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Running P2P node handle (listen + optional outbound sync / tip follow).
pub struct P2PNode {
    /// Shared RAM cache (also on hub).
    pub cache: Arc<BlockCache>,
    /// Shared query store (also on hub).
    pub query: Arc<Query>,
    pub hub: Arc<ChainHub>,
    pub local_addr: SocketAddr,
    pub magic: Magic,
    pub shutdown: Arc<AtomicBool>,
    /// Live outbound tip-follow sessions (inc/dec inside session task).
    pub follow_live: Arc<AtomicUsize>,
    pub tasks: Vec<JoinHandle<()>>,
    /// Nested inbound / dial session tasks (not in `tasks` so accept/dial
    /// abort does not leave them running through process exit).
    pub session_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Live sessions for RPC getpeerinfo / addnode / disconnectnode.
    pub peers: Arc<PeerHub>,
    pub user_agent: String,
    /// Inbound session cap used by the accept loop (not process env).
    pub max_inbound: usize,
    /// Shared inbound slots across all listen sockets.
    inbound_sem: Arc<tokio::sync::Semaphore>,
    dialer: crate::socks::Dialer,
    /// Wakes accept, dial, and connect-retry so `shutdown` does not sit out
    /// its grace waiting on a recv or a 2s tick.
    stop_tx: tokio::sync::watch::Sender<bool>,
}

impl P2PNode {
    /// Bind listener. Serves getheaders/getdata and participates in tip announce/follow.
    pub async fn start(
        listen: SocketAddr,
        query: Query,
        params: ChainParams,
        milestone: Milestone,
        redial: Duration,
    ) -> Result<Self, NetError> {
        Self::start_with_agent(
            listen,
            query,
            params,
            milestone,
            default_user_agent(),
            DEFAULT_MAX_INBOUND,
            redial,
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
        redial: Duration,
    ) -> Result<Self, NetError> {
        Self::start_with_dialer(
            listen,
            query,
            params,
            milestone,
            user_agent,
            max_inbound,
            crate::socks::Dialer::Direct,
            redial,
        )
        .await
    }

    /// Like [`Self::start_with_agent`] with an outbound [`crate::Dialer`].
    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    pub async fn start_with_dialer(
        listen: SocketAddr,
        query: Query,
        params: ChainParams,
        milestone: Milestone,
        user_agent: String,
        max_inbound: usize,
        dialer: crate::socks::Dialer,
        redial: Duration,
    ) -> Result<Self, NetError> {
        let bind = (max_inbound > 0).then_some(listen);
        Self::start_inner(
            bind,
            query,
            params,
            milestone,
            user_agent,
            max_inbound,
            dialer,
            redial,
        )
        .await
    }

    /// Outbound dials only: no P2P `TcpListener`. `local_addr` is `127.0.0.1:0`.
    pub async fn start_outbound_only(
        query: Query,
        params: ChainParams,
        milestone: Milestone,
        user_agent: String,
        max_inbound: usize,
        dialer: crate::socks::Dialer,
        redial: Duration,
    ) -> Result<Self, NetError> {
        Self::start_inner(
            None,
            query,
            params,
            milestone,
            user_agent,
            max_inbound,
            dialer,
            redial,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    pub async fn start_inner(
        listen: Option<SocketAddr>,
        query: Query,
        params: ChainParams,
        milestone: Milestone,
        user_agent: String,
        max_inbound: usize,
        dialer: crate::socks::Dialer,
        redial: Duration,
    ) -> Result<Self, NetError> {
        let magic = magic_for_params(&params);
        let hub = ChainHub::into_arc(ChainHub::new(query, params, milestone));
        hub.ensure_genesis()?;
        let cache = hub.cache.clone();
        let query = hub.query.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);

        let (listener, local_addr) = if let Some(addr) = listen {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            (Some(listener), local_addr)
        } else {
            (None, SocketAddr::from(([127, 0, 0, 1], 0)))
        };

        let peers = PeerHub::new();
        let (dial_tx, mut dial_rx) = tokio::sync::mpsc::unbounded_channel::<DialRequest>();
        peers.set_dialer(dial_tx);

        let max_inbound = if listener.is_some() {
            max_inbound.max(1)
        } else {
            0
        };
        let inbound_sem = inbound_semaphore(max_inbound.max(1));
        let session_tasks = Arc::new(Mutex::new(Vec::<JoinHandle<()>>::new()));
        let mut tasks = Vec::new();
        if let Some(listener) = listener {
            tasks.push(spawn_inbound_accept(
                listener,
                local_addr,
                hub.clone(),
                peers.clone(),
                user_agent.clone(),
                magic,
                max_inbound.max(1),
                inbound_sem.clone(),
                shutdown.clone(),
                session_tasks.clone(),
                stop_tx.subscribe(),
            ));
        }

        let follow_live = Arc::new(AtomicUsize::new(0));
        let dial_hub = hub.clone();
        let dial_peers = peers.clone();
        let dial_ua = user_agent.clone();
        let dial_live = follow_live.clone();
        let dial_shutdown = shutdown.clone();
        let sessions_dial = session_tasks.clone();
        let dialer_task = dialer.clone();
        let mut dial_stop = stop_tx.subscribe();
        let dial_task = tokio::spawn(async move {
            loop {
                let req = tokio::select! {
                    biased;
                    _ = dial_stop.changed() => break,
                    r = dial_rx.recv() => match r {
                        Some(req) => req,
                        None => break,
                    },
                };
                if dial_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let hub = dial_hub.clone();
                let peers = dial_peers.clone();
                let ua = dial_ua.clone();
                let live = dial_live.clone();
                let d = dialer_task.clone();
                let (ah_tx, ah_rx) = tokio::sync::oneshot::channel::<tokio::task::AbortHandle>();
                let h = tokio::spawn(async move {
                    let _ = run_outbound_session_with_abort(
                        req.target,
                        req.in_flight,
                        magic,
                        local_addr,
                        hub,
                        peers,
                        ua,
                        live,
                        req.typ,
                        ah_rx,
                        d,
                    )
                    .await;
                });
                let _ = ah_tx.send(h.abort_handle());
                push_session_task(&sessions_dial, h);
            }
        });
        tasks.push(dial_task);

        // DNS for remembered `--connect` / `addnode add` runs on the blocking
        // pool (`PeerHub::redial_remembered_off_runtime`).
        let retry_peers = peers.clone();
        let retry_shutdown = shutdown.clone();
        let mut retry_stop = stop_tx.subscribe();
        let retry_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(redial);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = retry_stop.changed() => break,
                    _ = interval.tick() => {}
                }
                if retry_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                retry_peers.redial_remembered_off_runtime().await;
            }
        });
        tasks.push(retry_task);

        Ok(Self {
            cache,
            query,
            hub,
            local_addr,
            magic,
            shutdown,
            follow_live,
            tasks,
            session_tasks,
            peers,
            user_agent,
            max_inbound,
            inbound_sem,
            dialer,
            stop_tx,
        })
    }

    /// Outbound TCP path (direct or SOCKS).
    pub fn dialer(&self) -> crate::socks::Dialer {
        self.dialer.clone()
    }

    pub fn magic(&self) -> Magic {
        self.magic
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Bind an additional listen socket (Core multi-`-bind`).
    pub async fn add_listen(&mut self, listen: SocketAddr) -> Result<SocketAddr, NetError> {
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let accept_task = spawn_inbound_accept(
            listener,
            local_addr,
            self.hub.clone(),
            self.peers.clone(),
            self.user_agent.clone(),
            self.magic,
            self.max_inbound,
            self.inbound_sem.clone(),
            self.shutdown.clone(),
            self.session_tasks.clone(),
            self.stop_tx.subscribe(),
        );
        self.tasks.push(accept_task);
        Ok(local_addr)
    }

    /// Number of live outbound tip-follow sessions.
    pub fn follow_live_count(&self) -> usize {
        self.follow_live.load(Ordering::SeqCst)
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.hub.tip_height()
    }

    /// Push a validated block into cache + store.
    pub fn ingest_block(&self, block: Block) -> Result<(), NetError> {
        match self.hub.accept_received_block(block)? {
            AcceptOutcome::Accepted { .. } | AcceptOutcome::AlreadyHave => Ok(()),
            AcceptOutcome::IgnoredWeaker => Err(NetError::Protocol("weaker tip ignored")),
        }
    }

    /// Persistent outbound peer: tip-follow + announce for the session lifetime.
    ///
    /// Handshake completes on this task (so an 8s connect timeout is meaningful);
    /// the session itself is spawned so the caller does not sit in the read loop.
    /// After handshake the session sends `getheaders` from our tip locator so
    /// any gap (e.g. blocks mined during SH materialize) is filled actively.
    /// Call `rbitcoin_ibd::sync` first when far behind (multi-thousand height IBD).
    pub async fn follow_from(&mut self, peer: SocketAddr) -> Result<(), NetError> {
        self.follow_from_net(crate::NetAddr::Ip(peer)).await
    }

    pub async fn follow_from_net(&mut self, peer: crate::NetAddr) -> Result<(), NetError> {
        self.follow_from_net_as(peer, PeerConnType::OutboundFullRelay)
            .await
    }

    /// [`Self::follow_from_net`] with the session's `connection_type`
    /// (`Manual` for a `--connect` target).
    pub async fn follow_from_net_as(
        &mut self,
        peer: crate::NetAddr,
        typ: PeerConnType,
    ) -> Result<(), NetError> {
        if let Err(msg) = self.peers.trust_allows_net(peer) {
            return Err(NetError::Consensus(msg));
        }
        let target = DialTarget::from_net(peer);
        let prepared = prepare_outbound_session(
            target,
            None,
            self.magic,
            self.local_addr,
            self.hub.clone(),
            self.peers.clone(),
            self.user_agent.clone(),
            self.follow_live.clone(),
            typ,
            self.dialer.clone(),
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
                let hub = Arc::clone(&self.hub);
                tokio::task::spawn_blocking(move || hub.wait_tip_stable_for_rpc())
                    .await
                    .expect("wait tip idle");
                if self.tip_height().unwrap_or(0) >= height {
                    return Ok(());
                }
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
                let hub = Arc::clone(&self.hub);
                tokio::task::spawn_blocking(move || hub.wait_tip_stable_for_rpc())
                    .await
                    .expect("wait tip idle");
                if self.hub.tip_hash() == Some(hash) {
                    return Ok(());
                }
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
        let _ = self.stop_tx.send(true);
        for p in self.peers.live_peers() {
            p.request_disconnect();
        }
        let mut join = Vec::new();
        join.append(&mut self.tasks);
        if let Ok(mut g) = self.session_tasks.lock() {
            join.append(&mut *g);
        }
        let grace = tokio::time::Instant::now() + Duration::from_millis(750);
        while tokio::time::Instant::now() < grace && join.iter().any(|t| !t.is_finished()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for t in &join {
            t.abort();
        }
        let _ = tokio::time::timeout(Duration::from_millis(750), async {
            for t in join {
                let _ = t.await;
            }
        })
        .await;
    }
}

impl Drop for P2PNode {
    fn drop(&mut self) {
        // The connect-retry interval runs until this flag or an abort.
        // Dropping the handle without `shutdown` must not pin the test runtime.
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.stop_tx.send(true);
        for t in &self.tasks {
            t.abort();
        }
        if let Ok(g) = self.session_tasks.lock() {
            for t in g.iter() {
                t.abort();
            }
        }
    }
}

#[doc(hidden)]
pub fn push_session_task(bag: &Mutex<Vec<JoinHandle<()>>>, h: JoinHandle<()>) {
    if let Ok(mut g) = bag.lock() {
        g.retain(|t| !t.is_finished());
        g.push(h);
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[doc(hidden)]
pub fn spawn_inbound_accept(
    listener: TcpListener,
    local_addr: SocketAddr,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    user_agent: String,
    magic: Magic,
    max_inbound: usize,
    inbound_sem: Arc<tokio::sync::Semaphore>,
    shutdown: Arc<AtomicBool>,
    session_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            let accept = tokio::select! {
                biased;
                _ = stop.changed() => break,
                a = listener.accept() => a,
            };
            match accept {
                Ok((stream, peer_addr)) => {
                    if peers.inbound_discouraged(peer_addr) {
                        rbitcoin_log::info!("p2p: reject discouraged inbound {peer_addr}");
                        drop(stream);
                        continue;
                    }
                    let permit = match inbound_sem.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            if !peers.try_evict_inbound() {
                                rbitcoin_log::warn!(
                                    "p2p: reject inbound {peer_addr} (at max_inbound={max_inbound})"
                                );
                                drop(stream);
                                continue;
                            }
                            match tokio::time::timeout(
                                Duration::from_millis(500),
                                inbound_sem.clone().acquire_owned(),
                            )
                            .await
                            {
                                Ok(Ok(p)) => p,
                                _ => {
                                    rbitcoin_log::warn!(
                                        "p2p: reject inbound {peer_addr} (evict slot wait)"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                        }
                    };
                    let our = local_addr;
                    let hub = hub.clone();
                    let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
                    let tip_rx = hub.subscribe_tips();
                    let peers = peers.clone();
                    let ua = user_agent.clone();
                    let sessions = session_tasks.clone();
                    let (ah_tx, ah_rx) =
                        tokio::sync::oneshot::channel::<tokio::task::AbortHandle>();
                    let h = tokio::spawn(async move {
                        let _session_slot = permit;
                        let (_ver, reader, writer, wire, tcp_shutdown, sess) =
                            match inbound_connect_and_handshake(
                                stream, magic, our, peer_addr, height, &ua, &peers, our,
                            )
                            .await
                            {
                                Ok(x) => x,
                                Err(e) => {
                                    rbitcoin_log::debug!(
                                        "p2p: inbound handshake {peer_addr} failed: {e}"
                                    );
                                    return;
                                }
                            };
                        sess.attach_tcp_shutdown(tcp_shutdown);
                        if !peers.make_room_for_tx_relay_inbound(&sess, max_inbound) {
                            rbitcoin_log::debug!(
                                "failed to find a tx-relaying eviction candidate - connection dropped after the handshake, peer={}",
                                sess.id
                            );
                            peers.disconnect_id(sess.id);
                            return;
                        }
                        if let Ok(ah) = ah_rx.await {
                            sess.set_session_abort(ah);
                        }
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
                        let _ = peer_session_with(reader, writer, magic, hub, tip_rx, meta).await;
                        peers.unregister(id);
                    });
                    let _ = ah_tx.send(h.abort_handle());
                    push_session_task(&sessions, h);
                }
                Err(e) => {
                    if accept_error_ends_listen(&e) {
                        rbitcoin_log::warn!("p2p: accept ended: {e}");
                        break;
                    }
                    rbitcoin_log::warn!("p2p: accept retry: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
}

#[doc(hidden)]
pub fn default_user_agent() -> String {
    rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
        .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")))
}

#[doc(hidden)]
pub struct PreparedOutbound {
    pub peer_hint: SocketAddr,
    pub magic: Magic,
    pub hub: Arc<ChainHub>,
    pub peers: Arc<PeerHub>,
    pub follow_live: Arc<AtomicUsize>,
    pub reader: V2Reader,
    pub writer: V2Writer,
    pub sess: Arc<LivePeer>,
    pub id: u64,
}

/// A transient accept error should not stop the listen loop.
///
/// `ConnectionAborted` is a peer that vanished during accept.
/// `Interrupted` is a signal. `EMFILE` / `ENFILE` (24 / 23) clear once a
/// socket is closed. Anything else, including a closed listener, ends accept.
#[doc(hidden)]
pub fn accept_error_ends_listen(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
    ) {
        return false;
    }
    !matches!(err.raw_os_error(), Some(23 | 24))
}

/// How often a down `--connect` / `addnode` target is tried again.
pub const REDIAL_INTERVAL: Duration = Duration::from_secs(2);
/// What the suite passes to [`P2PNode::start`] so a test that waits on the
/// tick stays at the old debug cadence. The node binary passes
/// [`REDIAL_INTERVAL`].
#[doc(hidden)]
pub const REDIAL_INTERVAL_TEST: Duration = Duration::from_millis(250);

/// Bound on the TCP / SOCKS / SAM connect of an outbound dial, the same 8 s
/// as the IBD and tip-follow dials ([`crate::socks::Dialer::connect_timeout`]
/// gives SOCKS and I2P longer). Without it a proxy that accepts and never answers holds the
/// dial, and its [`crate::peers::DialInFlight`] mark, for good, so the
/// redial pass would never try that target again. Debug builds keep 8 s.
/// The short redial interval is separate.
#[doc(hidden)]
pub const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn prepare_outbound_session(
    peer: DialTarget,
    in_flight: Option<crate::peers::DialInFlight>,
    magic: Magic,
    local: SocketAddr,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    user_agent: String,
    follow_live: Arc<AtomicUsize>,
    typ: PeerConnType,
    dialer: crate::socks::Dialer,
) -> Result<PreparedOutbound, NetError> {
    hub.clock.note_connection_attempt();
    rbitcoin_log::debug!("{}", crate::peers::trying_connection_log(typ, &peer));
    // Until this returns, the redial pass and `addnode` treat `peer` as
    // already dialling. A queued dial was counted when it was queued.
    let _dialing = in_flight.unwrap_or_else(|| peers.dial_in_flight(&peer));
    let peer_net = peer.net_addr();
    if peers.net_discouraged(peer_net) {
        return Err(NetError::Protocol("discouraged"));
    }
    let connect = async {
        match &peer {
            DialTarget::Socket(_) => dialer.connect_net(peer_net).await,
            DialTarget::Domain { host, port } => dialer.connect_domain(host, *port).await,
        }
    };
    let stream = tokio::time::timeout(
        dialer.connect_timeout(peer_net, OUTBOUND_CONNECT_TIMEOUT),
        connect,
    )
    .await
    .map_err(|_| NetError::Timeout)??;
    let peer_hint = peer.version_socket();
    let bind = stream.local_addr().unwrap_or(local);
    let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
    // Core adds CNode before VERSION. Provisional row so getpeerinfo is non-empty
    // during handshake (p2p_handshake self-connect wait_until + assert_debug_log).
    let provisional = peers.register_connecting_net(peer_hint, peer_net, bind, false, typ);
    let provisional_id = provisional.id;
    let handshake = connect_and_handshake_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        local,
        peer_hint,
        height,
        false,
        &user_agent,
        HandshakePolicy {
            hub: Some(hub.as_ref()),
            peers: Some(peers.as_ref()),
            session: Some(provisional.as_ref()),
            conn_type: typ,
        },
    )
    .await;
    let (ver, reader, writer, wire, tcp_shutdown) = match handshake {
        Ok(x) => x,
        Err(e) => {
            peers.unregister(provisional_id);
            return Err(e);
        }
    };
    let wants_addrv2 = provisional.wants_addrv2();
    let wtxid_relay = provisional.wtxid_relay();
    let conntime = provisional.conntime.load(Ordering::Relaxed);
    peers.unregister(provisional_id);
    let sess = peers.register_with_id_net(
        provisional_id,
        crate::peers::PeerEndpoint {
            addr: peer_hint,
            net: peer_net,
            addrbind: bind,
        },
        &ver,
        false,
        typ,
    );
    sess.conntime.store(conntime, Ordering::Relaxed);
    sess.mark_handshake_complete();
    if wants_addrv2 {
        sess.set_wants_addrv2();
    }
    if wtxid_relay {
        sess.set_wtxid_relay();
    }
    sess.note_recv("version", 100);
    sess.note_recv("verack", 0);
    sess.attach_tcp_shutdown(tcp_shutdown);
    if let Some(mp) = hub.mempool() {
        sess.set_inv_gen_floor(mp.next_accept_gen());
    }
    sess.attach_wire(wire);
    let id = sess.id;
    follow_live.fetch_add(1, Ordering::SeqCst);
    Ok(PreparedOutbound {
        peer_hint,
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

pub async fn run_prepared_outbound(prepared: PreparedOutbound) -> Result<(), NetError> {
    let tip_rx = prepared.hub.subscribe_tips();
    let meta = FollowSessionMeta {
        peer: Some(prepared.peer_hint),
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

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn run_outbound_session_with_abort(
    peer: DialTarget,
    in_flight: Option<crate::peers::DialInFlight>,
    magic: Magic,
    local: SocketAddr,
    hub: Arc<ChainHub>,
    peers: Arc<PeerHub>,
    user_agent: String,
    follow_live: Arc<AtomicUsize>,
    typ: PeerConnType,
    ah_rx: tokio::sync::oneshot::Receiver<tokio::task::AbortHandle>,
    dialer: crate::socks::Dialer,
) -> Result<(), NetError> {
    if typ == PeerConnType::Feeler {
        let peer_addr = match peer {
            DialTarget::Socket(addr) => addr,
            DialTarget::Domain { .. } => {
                return Err(NetError::Encode("feeler requires ip:port target".into()))
            }
        };
        let peer_net = crate::NetAddr::Ip(peer_addr);
        if peers.net_discouraged(peer_net) {
            return Err(NetError::Protocol("discouraged"));
        }
        let stream = dialer.connect_net(peer_net).await?;
        let height = hub.tip_height().map(|h| h as i32).unwrap_or(0);
        return crate::peer::run_feeler(
            stream,
            magic,
            local,
            peer_addr,
            height,
            &user_agent,
            peers.as_ref(),
        )
        .await;
    }
    let prepared = prepare_outbound_session(
        peer,
        in_flight,
        magic,
        local,
        hub,
        peers,
        user_agent,
        follow_live,
        typ,
        dialer,
    )
    .await?;
    if let Ok(ah) = ah_rx.await {
        prepared.sess.set_session_abort(ah);
    }
    run_prepared_outbound(prepared).await
}

/// Resolve P2P message magic, including BIP325 custom-Signet derivation.
pub fn magic_for_params(params: &ChainParams) -> Magic {
    match params.signet_challenge.as_ref() {
        Some(challenge) => Magic::from_bytes(signet_magic(challenge.as_script())),
        None => Magic::from(params.network),
    }
}
