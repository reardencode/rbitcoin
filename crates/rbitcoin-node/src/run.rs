use crate::config::{parse_btc_to_sat, ListenOpts, NodeConfig};
use crate::error::NodeError;
use crate::health::{run_health, NodeStatus, Phase};
use bitcoin::consensus::Encodable;
use rbitcoin_electrum::{run_electrum, ElectrumConfig, ElectrumHandle, TipNotify};
use rbitcoin_esplora::{run_esplora, BlockTemplateFn, EsploraConfig, EsploraHandle, EsploraListen};
use rbitcoin_ibd::{
    read_platform_rss, tip_perf_json, IbdConfig, Peerless, TipPerfLog, PEERLESS_REDIAL_CAP,
};
use rbitcoin_log::{debug, enabled, info, warn, Level};
use rbitcoin_net::{
    default_port, netgroup, sample_reset_serve_perf, socks_dns_seed_dests, AddrMan, AsMap,
    BlockingRegion, ChainHub, Dialer, MempoolHub, NetAddr, OutboundPass, P2PNode, PeerConnType,
    TipEvent,
};
use rbitcoin_primitives::Network;
use rbitcoin_query::connect::ShWritebehind;
use rbitcoin_query::{spawn_sh_writebehind, Query, SpendSync};
use rbitcoin_rpc::{
    gbt_template, run_rpc, HubRegtest, RpcActive, RpcConfig, RpcContext, RpcHandle, RpcRegtest,
};
use rbitcoin_store::StoreError;
use rbitcoin_sv2::{run_sv2_tp, Sv2TpConfig, Sv2TpHandle};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Notify};

/// Running node state (store open; optional P2P).
pub struct NodeHandle {
    pub config: NodeConfig,
    pub query: Query,
    /// Durable cluster mempool (opened in `run_p2p` and attached to `ChainHub`).
    /// Smoke-only `run_node` leaves this `None`.
    pub mempool: Option<std::sync::Arc<MempoolHub>>,
    /// Exclusive datadir flock (released on drop).
    pub _dir_locks: crate::lock::DirLocks,
}

impl std::fmt::Debug for NodeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeHandle")
            .field("config", &self.config)
            .field("network", &self.config.network)
            .field(
                "mempool_gen",
                &self.mempool.as_ref().map(|m| m.generation()),
            )
            .finish()
    }
}

impl NodeHandle {
    pub fn network_name(&self) -> &'static str {
        self.config.network.as_str()
    }

    pub fn shutdown(self) -> Result<(), NodeError> {
        self.query.flush()?;
        if let Some(mp) = &self.mempool {
            mp.flush()
                .map_err(|e| NodeError::Config(format!("mempool flush: {e}")))?;
        }
        Ok(())
    }
}

/// Cooperative shutdown flag shared across the process lifetime.
#[derive(Debug)]
pub struct Shutdown {
    /// Polled by IBD / long loops for cooperative cancel.
    pub flag: Arc<AtomicBool>,
    /// Set only by [`Self::fail`]. SIGTERM, Ctrl+C, and RPC `stop` leave it empty.
    failure: std::sync::Mutex<Option<NodeError>>,
    pub notify: Notify,
}

impl Shutdown {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: Arc::new(AtomicBool::new(false)),
            failure: std::sync::Mutex::new(None),
            notify: Notify::new(),
        })
    }

    /// Stop the process with `err` as its exit error. The first one is kept.
    pub fn fail(&self, err: NodeError) {
        self.failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(err);
        self.request();
    }

    /// The started value, or [`Self::fail`] and an empty one.
    pub fn or_fail<T: Default>(&self, started: Result<T, NodeError>) -> T {
        started.unwrap_or_else(|e| {
            self.fail(e);
            T::default()
        })
    }

    /// `Ok` for SIGTERM, Ctrl+C, and RPC `stop`. The [`Self::fail`] error
    /// otherwise, so `process_main` exits non-zero and `Restart=on-failure` runs.
    pub fn result(&self) -> Result<(), NodeError> {
        match self
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub fn request(&self) {
        if !self.flag.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub fn requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Completes when shutdown has been requested.
    pub async fn cancelled(&self) {
        if self.requested() {
            return;
        }
        self.notify.notified().await;
        while !self.requested() {
            self.notify.notified().await;
        }
    }
}

/// Clearnet follow handshake bound. Overlay STREAM CONNECT is slower; see
/// [`follow_connect_timeout`].
#[doc(hidden)]
pub const FOLLOW_CONNECT_SECS: u64 = 8;

#[doc(hidden)]
pub fn follow_connect_timeout(dialer: &Dialer, peer: rbitcoin_net::NetAddr) -> Duration {
    dialer.connect_timeout(peer, Duration::from_secs(FOLLOW_CONNECT_SECS))
}

/// Install SIGTERM / SIGINT (and Ctrl+C) handlers that trip `shutdown`.
#[doc(hidden)]
pub fn spawn_signal_handler(shutdown: Arc<Shutdown>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("signal: failed to install SIGTERM handler: {e}");
                    return;
                }
            };
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("signal: failed to install SIGINT handler: {e}");
                    return;
                }
            };
            tokio::select! {
                _ = sigterm.recv() => info!("signal: received SIGTERM"),
                _ = sigint.recv() => info!("signal: received SIGINT"),
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(e) = tokio::signal::ctrl_c().await {
                warn!("signal: ctrl_c error: {e}");
                return;
            }
            info!("signal: received Ctrl+C");
        }
        shutdown.request();
    });
}

/// Bind RPC. A catch-up that waits for peers starts it early so the
/// operator can inspect, stop, or add a peer; the tip-follow path starts it
/// after wallet services are published.
pub async fn start_rpc_listener(
    config: &NodeConfig,
    node: &P2PNode,
    mempool: &Arc<MempoolHub>,
    shared_peers: &Arc<std::sync::Mutex<AddrMan>>,
) -> Result<Option<RpcHandle>, NodeError> {
    if !(config.rpc.socket || config.rpc.listen.is_some()) {
        return Ok(None);
    }
    let rcfg = RpcConfig {
        listen: config.rpc.listen,
        socket_path: if config.rpc.socket {
            Some(config.rpc_socket_path())
        } else {
            None
        },
        socket_shared: config.rpc.socket_path.is_some(),
        datadir: config.datadir.path.clone(),
        network: config.network,
        token_path: Some(config.rpc_token_path()),
        cookie_path: config.rpc_cookie_path(),
        cookie_perms: config.rpc.cookie_perms,
        work_queue: config.rpc.work_queue,
        rest: config.rpc.rest,
        subversion: Some(
            rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
                .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION"))),
        ),
        alert_notify: config.alert_notify.clone(),
        blocksonly: config.mempool.blocksonly,
        package_dialect: config.rpc.package_dialect,
    };
    let op_true_signet = config.network == Network::Signet
        && config
            .signet_challenge
            .as_ref()
            .is_some_and(|s| s.as_bytes() == [rbitcoin_primitives::OP_TRUE]);
    let miner: Option<Arc<dyn RpcRegtest>> = if config.network == Network::Regtest || op_true_signet
    {
        Some(Arc::new(HubRegtest(Arc::clone(&node.hub))))
    } else {
        None
    };
    let h = run_rpc(
        rcfg,
        Arc::clone(&node.hub.query),
        Some(Arc::clone(mempool)),
        miner,
        Some(Arc::clone(&node.peers)),
        Some(Arc::clone(&node.hub)),
        Some(Arc::clone(shared_peers)),
    )
    .await
    .map_err(|e| NodeError::Config(format!("rpc start: {e}")))?;
    h.initial_block_download
        .store(node.hub.in_ibd(), Ordering::SeqCst);
    h.connections.store(0, Ordering::Relaxed);
    info!(
        "rpc: listening tcp={:?} sock={:?} token={}",
        h.local_addr,
        h.socket_path,
        h.token_path.display()
    );
    if let Some(addr) = h.local_addr {
        publish_listener_addr(config.datadir.path(), "rpc", addr);
    }
    Ok(Some(h))
}

/// Restore fee history from the mempool dir and read the rest of up to 1 GiB
/// of txstat rows once relay is on, off the tip path.
#[doc(hidden)]
pub fn spawn_fee_history_backfill(mempool: &Arc<MempoolHub>) {
    let mp = Arc::clone(mempool);
    info!("mempool: fee history preload started (file, then txstat, budget=1 GiB)");
    tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        let t = Instant::now();
        let stats = mp.backfill_block_fee_history();
        info!(
            "mempool: fee history preload complete: txstat_bytes={}, heights={}, from_file={}, retained={}, samples={}, ready_targets={}/{}, skipped={}, failed={}, range={}..{}, elapsed={:.1?}{}",
            stats.txstat_bytes,
            stats.heights_scanned,
            stats.file_heights,
            stats.retained_heights,
            stats.valid_samples,
            stats.ready_targets,
            stats.total_targets,
            stats.skipped_heights,
            stats.failed_heights,
            stats.oldest_height.map_or_else(|| "none".to_owned(), |h| h.to_string()),
            stats.tip_height.map_or_else(|| "none".to_owned(), |h| h.to_string()),
            t.elapsed(),
            if stats.history_exhausted { ", history exhausted before budget" } else { "" }
        );
        if let Some(error) = stats.first_error {
            warn!(
                "mempool: fee history preload had {} read error(s); first error: {error}",
                stats.failed_heights
            );
        }
    });
}

pub async fn mempool_blocking<T: Send + 'static>(
    mp: &Arc<MempoolHub>,
    f: impl FnOnce(&MempoolHub) -> T + Send + 'static,
) -> Result<T, NodeError> {
    let mp = Arc::clone(mp);
    tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        f(&mp)
    })
    .await
    .map_err(|e| NodeError::Config(format!("mempool task: {e}")))
}

/// Start the node: ensure datadir, exclusive-lock, open store.
pub fn run_node(config: NodeConfig) -> Result<NodeHandle, NodeError> {
    config.ensure_datadir()?;
    let dir_locks = crate::lock::lock_node_dirs(&config)?;
    let query = Query::open_or_create_layout_checkblocks(
        config.store_layout(),
        config.check_blocks_window(),
    )?;
    rbitcoin_query::replay_spend_annotations(&query)
        .map_err(|e| NodeError::Init(format!("spend annotation replay: {e}")))?;
    Ok(NodeHandle {
        config,
        query,
        mempool: None,
        _dir_locks: dir_locks,
    })
}

/// Long-running P2P (+ optional Electrum): seed resolve, catch-up, persistent follow, progress logs.
///
/// Cleanly exits on **SIGTERM** / **SIGINT** (`kill <pid>` or Ctrl+C): flushes the store
/// and aborts peer tasks (runtime `shutdown_timeout` so leftover sessions cannot
/// hold the process).
#[allow(clippy::cognitive_complexity)] // node bring-up / P2P follow loop
pub async fn run_p2p(config: NodeConfig) -> Result<(), NodeError> {
    let status = NodeStatus::new(config.network, config.shindex);
    let _health = match config.listen.health {
        Some(addr) => {
            let health = run_health(addr, Arc::clone(&status), config.metrics)
                .await
                .map_err(|e| NodeError::Config(format!("health listen {addr}: {e}")))?;
            publish_listener_addr(config.datadir.path(), "health", health.local_addr);
            Some(health)
        }
        None => None,
    };
    let handle = run_node(config.clone())?;
    status.enter(Phase::Starting);
    let params = config.chain_params()?;
    let milestone = config.milestone();
    if let Some(anchor) = milestone.anchor {
        info!(
            "ibd: milestone height={} hash={} (script/sig skip once this header path contains that hash and the block is its ancestor; prevouts always)",
            milestone.height, anchor.hash
        );
    } else {
        info!(
            "ibd: milestone height={} (script/sig checks skipped at/below; prevouts always)",
            milestone.height
        );
    }
    apply_startup_index_mode(&handle.query, &config, params.taproot_height())?;
    rbitcoin_query::prepare_live_indexes(&handle.query)
        .map_err(|e| crate::error::NodeError::Init(format!("index startup repair failed: {e}")))?;
    let bind = config.listen.start_p2p_bind(config.network);

    let start_tip = handle.query.tip_height().map(|h| h.0).unwrap_or(0);
    let run_started = Instant::now();
    info!(
        "rbitcoin-node starting version={} network={} datadir={}{} tip={start_tip} io={}",
        env!("CARGO_PKG_VERSION"),
        config.network.as_str(),
        config.datadir.path().display(),
        config
            .datadir
            .cold
            .as_ref()
            .map(|p| format!(" datadir_cold={}", p.display()))
            .unwrap_or_default(),
        std::env::var("RBITCOIN_IO").unwrap_or_else(|_| "default".into()),
    );

    handle.query.set_trust_peer(config.trust_peer_set());
    let query = handle.query;
    let p2p_ua =
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
            .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")));
    let mut node = match bind {
        Some(listen) => {
            P2PNode::start_with_dialer(
                listen,
                query,
                params.clone(),
                milestone,
                p2p_ua,
                config.listen.max_inbound as usize,
                config.listen.dialer(),
                config.connect_redial,
            )
            .await
        }
        None => {
            P2PNode::start_outbound_only(
                query,
                params.clone(),
                milestone,
                p2p_ua,
                config.listen.max_inbound as usize,
                config.listen.dialer(),
                config.connect_redial,
            )
            .await
        }
    }
    .map_err(|e| NodeError::Config(format!("p2p start: {e}")))?;
    node.peers
        .set_trust_peer(config.trust_peer, config.trust_peer_host.clone());
    if config.trust_peer_set() {
        let who = config
            .trust_peer
            .map(|a| a.to_string())
            .or_else(|| config.trust_peer_host.clone())
            .unwrap_or_default();
        info!("node: trust-peer {who} is the only dial target");
    }
    publish_listener_addr(config.datadir.path(), "p2p", node.local_addr);
    let spend_sync = SpendSync::spawn(std::sync::Arc::clone(&node.hub.query));
    status.attach_p2p(&node.hub, &node.peers);
    for extra in &config.listen.p2p_extra {
        let bound = node
            .add_listen(*extra)
            .await
            .map_err(|e| NodeError::Config(format!("p2p extra listen {extra}: {e}")))?;
        info!(
            "rbitcoin-node listening on {} ({})",
            bound,
            config.network.as_str()
        );
    }
    node.hub.set_minimum_chain_work(config.minimum_chain_work);
    node.hub.set_blocks_only(config.mempool.blocksonly);
    if let Some(secs) = config.max_tip_age_secs {
        node.hub.set_max_tip_age_secs(secs);
    }
    node.hub.set_prefill_compact(config.prefill_compact);
    node.hub.set_rpc_wait_tip_idle(config.rpc.wait_tip_idle);
    if let Some(t) = config.mock_time {
        node.hub.clock.set_mock(t);
    }
    if let Some(h) = node.hub.query.tip_height() {
        if let Ok(Some((_, rec))) = node.hub.query.header_at_height(h) {
            if crate::error::tip_too_far_in_future(rec.timestamp, node.hub.clock.now_secs()) {
                eprintln!("{}", crate::error::FUTURE_BLOCK_DB_MSG);
                return Err(NodeError::FutureTip);
            }
        }
    }
    if let Some(v) = config.block_version {
        node.hub.set_block_version(v);
    }
    if let Some(s) = config.block_min_tx_fee_btc.as_deref() {
        match parse_btc_to_sat(s) {
            Ok(sat) => node.hub.set_block_min_tx_fee_sat_kvb(sat),
            Err(e) => {
                return Err(NodeError::Config(format!(
                    "bad --block-min-tx-fee {s}: {e}"
                )));
            }
        }
    }

    let mempool_path = config.mempool_path();
    let query = node.hub.query.clone();
    let max_weight = config.mempool.max_weight;
    let persist = config.mempool.persist;
    let cluster_count = config.mempool.limit_cluster_count;
    let cluster_kvb = config.mempool.limit_cluster_size_kvb;
    let bytes_per_sigop = config.mempool.bytes_per_sigop;
    let block_reserved_sigops = config.mempool.block_reserved_sigops;
    let min_relay_sat = match config.mempool.min_relay_fee_btc.as_deref() {
        Some(s) => Some(
            parse_btc_to_sat(s)
                .map_err(|e| NodeError::Config(format!("bad --min-relay-tx-fee {s}: {e}")))?,
        ),
        None => None,
    };
    let expiry_hours = config.mempool.expiry_hours;
    let table = config.finalized_net_perms();
    let immediate_relay = config.trusted;
    let hub = Arc::clone(&node.hub);
    let (mempool, mp_gen, mp_live) = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        let mp = MempoolHub::open_with_weight_persist_and_sigop_reserve(
            mempool_path,
            query,
            max_weight,
            persist,
            block_reserved_sigops,
        )?;
        mp.set_cluster_limits(cluster_count, cluster_kvb);
        if let Some(b) = bytes_per_sigop {
            mp.set_bytes_per_sigop(b);
        }
        if immediate_relay {
            mp.set_immediate_relay(true);
        }
        if let Some(sat) = min_relay_sat {
            mp.set_min_relay_sat_kvb(sat);
        }
        if let Some(h) = expiry_hours {
            mp.set_expiry_hours(h);
        }
        hub.attach_mempool(mp.clone())
            .map_err(|_| "mempool already attached".to_string())?;
        let gen = mp.generation();
        let live = mp.live_count();
        Ok::<_, String>((mp, gen, live))
    })
    .await
    .map_err(|e| NodeError::Config(format!("mempool open join: {e}")))?
    .map_err(NodeError::Config)?;
    node.peers.attach_mempool(&mempool);
    status.attach_mempool(&mempool);
    // Proxy and onion are how the one trusted peer is reached. This node's
    // own txs stay on that session. Isolated broadcast dials other nodes.
    if proxy_or_onion_without_trust(&config) {
        mempool.set_isolated_broadcast(true);
    }
    node.peers.set_net_perms(table.clone());
    if let Some(secs) = config.listen.peer_timeout_secs {
        node.peers.set_peer_timeout_secs(secs);
    }
    node.peers.set_discover(config.listen.discover);
    node.peers
        .set_clearnet_listen(!matches!(config.listen.p2p, crate::config::P2pListen::Off));
    if node.local_addr.port() != 0 {
        node.peers.set_listen_port(node.local_addr.port());
    }
    for host in &config.listen.external_onions {
        node.peers
            .set_wallet_onion(host.clone(), node.local_addr.port());
    }
    let external = external_ips_with_cjdns_bind(
        &config.listen.external_ips,
        node.local_addr,
        config.listen.cjdns_reachable,
    );
    if !external.is_empty() {
        node.peers.set_external_ips(external);
    }
    if immediate_relay {
        node.peers.set_noban(true);
    }
    if config.relay {
        node.peers.set_relay_perm(true);
    }
    if config.always_relay {
        node.peers.set_forcerelay_perm(true);
        node.peers.set_relay_perm(true);
    }
    info!(
        "mempool: open {} gen={mp_gen} live={mp_live} max_weight={} (relay off until tip mode)",
        config.mempool_path().display(),
        config.mempool.max_weight
    );

    if node.local_addr.port() == 0 {
        info!(
            "rbitcoin-node P2P outbound-only ({})",
            config.network.as_str()
        );
    } else {
        info!(
            "rbitcoin-node listening on {} ({})",
            node.local_addr,
            config.network.as_str()
        );
    }

    let shutdown = Shutdown::new();
    spawn_signal_handler(shutdown.clone());
    let mut tor_ctl = crate::tor_control::TorControl::connect_if_configured(
        config.tor.control,
        config.tor.cookie.as_deref(),
        config.tor.password.as_deref(),
    )
    .await?;
    if tor_ctl.is_some() {
        info!(
            "tor control authenticated on {}",
            config
                .tor
                .control
                .expect("control addr set when session exists")
        );
    }
    if config.listen.listen_onion {
        let ctl = tor_ctl
            .as_mut()
            .expect("validate requires --tor-control with --listen-onion");
        let virt = config.network.default_p2p_port();
        let hs = ctl
            .add_p2p_onion(config.datadir.path(), node.local_addr, virt)
            .await?;
        info!("p2p onion {}.onion:{}", hs.service_id, virt);
        node.peers
            .set_p2p_onion(format!("{}.onion", hs.service_id), virt);
    }
    if config.listen.i2p_sam.is_some() {
        node.peers.set_i2p_reachable(true);
    }
    let mut i2p_sam = if let Some(addr) = config.listen.i2p_sam {
        let s = if config.listen.i2p_accept_incoming {
            let dest = config.datadir.path().join("i2p").join("p2p.priv");
            rbitcoin_net::I2pSam::connect_persistent(addr, &dest, rbitcoin_net::SAM_RETRY).await
        } else {
            rbitcoin_net::I2pSam::connect(addr, rbitcoin_net::SAM_RETRY).await
        }
        .map_err(|e| NodeError::Init(format!("i2p sam {addr}: {e}")))?;
        info!("i2p SAM session on {addr}");
        Some(s)
    } else {
        None
    };
    if config.listen.i2p_accept_incoming {
        let port = node.local_addr.port();
        let sam = i2p_sam
            .as_mut()
            .expect("validate requires --i2p-sam with --i2p-accept-incoming");
        sam.stream_forward(port)
            .await
            .map_err(|e| NodeError::Init(format!("i2p STREAM FORWARD {port}: {e}")))?;
        let local = sam
            .local_netaddr()
            .map_err(|e| NodeError::Init(format!("i2p address: {e}")))?;
        info!("i2p address {local}");
        node.peers.set_p2p_i2p(local);
        info!("i2p STREAM FORWARD to {}", node.local_addr);
    }
    if let Some(sam) = i2p_sam.as_ref() {
        rbitcoin_net::install_i2p_dialer(sam.dialer());
    }
    let _i2p_sam = i2p_sam;
    // Joined at shutdown. A durable Tip head starts now, before catch-up.
    // Direct stays down until materialize enters Tip.
    let mut sh_writebehind = None;
    ensure_sh_writebehind(
        &mut sh_writebehind,
        Arc::clone(&node.hub.query),
        Arc::clone(&shutdown.flag),
        {
            let sd = Arc::clone(&shutdown);
            move || {
                sd.fail(NodeError::Init(
                    "scripthash or index write-behind failed".into(),
                ))
            }
        },
    );
    let peers_path = config.datadir.path().join("peers");
    let mut addrman = match AddrMan::load(&peers_path) {
        Ok(am) => {
            if !am.is_empty() {
                info!(
                    "peers: loaded {} address(es) with flags from {}",
                    am.len(),
                    peers_path.display()
                );
            }
            am
        }
        Err(e) => {
            warn!(
                "peers: load {}: {e} — starting empty book",
                peers_path.display()
            );
            AddrMan::new()
        }
    };
    let asmap = load_asmap(config.datadir.path(), config.asmap.as_deref());
    addrman.set_asmap(asmap.clone());
    let len_before_reach = addrman.len();
    // Reachability before `--only-net`, so a sweep does not drop a net this
    // process can dial and then forget the rows.
    addrman.set_onion_reachable(config.listen.proxy.is_some() || config.listen.onion.is_some());
    addrman.set_i2p_reachable(config.listen.i2p_sam.is_some());
    addrman.set_cjdns_reachable(config.listen.cjdns_reachable);
    addrman.set_only_net(config.listen.only_net.clone());
    let reachability_removed_rows = addrman.len() < len_before_reach;
    node.peers
        .set_cjdns_reachable(config.listen.cjdns_reachable);
    node.peers.set_proxies(rbitcoin_net::NetProxies {
        dialer: config.listen.dialer(),
        i2p_sam: config.listen.i2p_sam,
    });
    node.peers.set_pruned(config.prune_seqsigwit);
    node.peers.set_asmap(asmap);
    node.peers.set_connect_hosts(
        config.listen.connect_dns.clone(),
        config.network.default_p2p_port(),
    );
    let dns_resolved = resolve_connect_dns(&config.listen.connect_dns, config.network).await;
    if config.trust_peer_host.is_some() {
        for addr in &dns_resolved {
            if let rbitcoin_net::NetAddr::Ip(sock) = addr {
                node.peers.note_trust_resolved(*sock);
            }
        }
    }
    for c in &config.listen.connect {
        addrman.add_addr(*c);
    }
    for c in &dns_resolved {
        addrman.add_addr(*c);
    }
    let mut proxy_seeds_queued = false;
    if should_resolve_default_seeds(&config) {
        info!(
            "ibd: resolving DNS/fixed seeds for {}…",
            config.network.as_str()
        );
        let n_before = addrman.len();
        addrman.inject(rbitcoin_net::resolve_dns_seeds(config.network));
        let fixed = addrman.add_fixed_seeds(config.network);
        info!(
            "ibd: seeds resolved (+{} new, {fixed} fixed, book={})",
            addrman.len().saturating_sub(n_before),
            addrman.len()
        );
    } else if !config.trust_peer_set() && config.listen.proxy.is_some() && config.listen.use_seeds {
        proxy_seeds_queued = true;
        let n = queue_proxy_seed_addrfetch(&node.peers, config.network);
        info!("ibd: SOCKS proxy set — queued {n} seed hostnames via SOCKS addrfetch");
    } else if config.signet_challenge.is_some()
        && !config.listen.has_pinned_connect()
        && addrman.is_empty()
    {
        warn!("custom signet has no peers; use --connect ADDR or reuse a datadir with known peers");
    }
    let shared_peers = std::sync::Arc::new(std::sync::Mutex::new(addrman.clone()));
    node.peers.set_addrman(std::sync::Arc::clone(&shared_peers));
    if proxy_or_onion_without_trust(&config) {
        let _iso = rbitcoin_net::spawn_isolated_broadcast_loop(
            Arc::clone(&mempool),
            config.listen.isolated_dialer(),
            std::sync::Arc::clone(&shared_peers),
            node.magic(),
        );
    }
    if proxy_seeds_queued && addrman.is_empty() {
        info!("ibd: waiting for a SOCKS seed addrfetch answer…");
        if let Some(book) = await_proxy_seed_book(
            &node.peers,
            config.network,
            &shared_peers,
            &shutdown,
            || node.peers.addrfetch_replies(),
            PROXY_SEED_RETRY,
            PROXY_SEED_WAIT,
        )
        .await
        {
            addrman = book;
            info!(
                "ibd: seed addrfetch filled the book (book={})",
                addrman.len()
            );
        }
    }

    let max_out = config.listen.max_outbound.max(1) as usize;
    let candidate_n = max_out.saturating_mul(2).clamp(16, 48);
    let occupied = node.peers.live_outbound_full_relay_nets();
    let mut pinned = config.listen.connect.clone();
    pinned.extend(dns_resolved);
    let trust_peer = config.trust_peer_set();
    let follow_type = follow_dial_type(&pinned);
    let ibd_targets = outbound_dial_targets(trust_peer, &pinned, &addrman, candidate_n, &occupied);
    let awaiting_dialable = addrman.is_empty() && (reachability_removed_rows || proxy_seeds_queued);
    let mut rpc_handle: Option<RpcHandle> = None;
    status.enter(Phase::CatchUp);
    let peerless = main_catch_up_peerless(
        node.hub
            .query
            .index_mode()
            .expect("index mode cell")
            .is_tip(),
        config.max_run_secs,
    );
    // A peerless catch-up can wait indefinitely. Bring RPC up first so
    // `stop`, `addnode`, and status calls still work while it waits.
    if matches!(peerless, Peerless::Redial { .. }) && !shutdown.requested() {
        rpc_handle =
            shutdown.or_fail(start_rpc_listener(&config, &node, &mempool, &shared_peers).await);
        if let Some(h) = &rpc_handle {
            let stop = Arc::clone(&h.stop);
            let sd = Arc::clone(&shutdown);
            tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                sd.request();
            });
        }
    }
    let catch_up = run_ibd_or_skip(
        &node,
        &ibd_targets,
        max_out,
        &shared_peers,
        &mut addrman,
        &peers_path,
        &shutdown,
        awaiting_dialable,
        peerless,
        &pinned,
        proxy_seeds_queued,
        config.network,
        config.bq_assign_stop_bytes,
    )
    .await;

    // Catch-up may have waited for a peer discovered after the startup book
    // was read. Refresh the follow dial list before tip mode; IBD disconnects
    // its own peers on the way out.
    let occupied_now = node.peers.live_outbound_full_relay_nets();
    let targets = refresh_follow_targets(
        trust_peer,
        &pinned,
        &shared_peers,
        &mut addrman,
        max_out,
        &occupied_now,
    );

    let catch_up = catch_up_with_connect(
        catch_up,
        config.listen.has_pinned_connect(),
        shutdown.requested(),
        node.tip_height().unwrap_or(0),
    );

    // Still enter tip-follow when work is below `--min-chain-work` so later
    // blocks can raise the tip. Relay / getheaders stay gated on the hub floor.
    if catch_up.is_complete() && !tip_meets_min_work(&config, &node.hub) {
        info!("ibd: tip work below --min-chain-work — following without relay");
    }

    // tip_follow_ready ≠ sh_tip_ready: follow/relay do not wait on SH materialize.
    let mut tip_follow_ready = false;
    let mut sh_tip_ready = false;
    let mut index_writebehind = None;
    if catch_up.is_complete() && !shutdown.requested() {
        status.enter(Phase::Indexing);
        let query = Arc::clone(&node.hub.query);
        let cancel = Arc::clone(&shutdown.flag);
        let shindex = config.shindex;
        let gates = tokio::task::spawn_blocking(move || {
            let _region = BlockingRegion::enter();
            enter_tip_mode(&query, Some(cancel), shindex)
        })
        .await
        .map_err(|e| NodeError::Config(format!("tip entry: {e}")))?;
        ensure_sh_writebehind(
            &mut sh_writebehind,
            Arc::clone(&node.hub.query),
            Arc::clone(&shutdown.flag),
            {
                let sd = Arc::clone(&shutdown);
                move || {
                    sd.fail(NodeError::Init(
                        "scripthash or index write-behind failed".into(),
                    ))
                }
            },
        );
        tip_follow_ready = gates.tip_follow_ready;
        sh_tip_ready = gates.sh_tip_ready;
        if tip_follow_ready && !shutdown.requested() {
            let index_entry = rbitcoin_query::index_tip_entry(&node.hub.query);
            if index_entry.advertise_filters {
                info!("blockfilter: already at tip; advertising NODE_COMPACT_FILTERS");
                node.peers.set_compact_filters_service(true);
            }
            if index_entry.spawn {
                let advertise_later = !index_entry.advertise_filters;
                let filter_peers = Arc::clone(&node.peers);
                index_writebehind = Some(rbitcoin_query::spawn_index_writebehind(
                    Arc::clone(&node.hub.query),
                    Arc::clone(&shutdown.flag),
                    {
                        let sd = Arc::clone(&shutdown);
                        move || {
                            sd.fail(NodeError::Init(
                                "scripthash or index write-behind failed".into(),
                            ))
                        }
                    },
                    // Version carries the bit once per peer: advertise only
                    // when served filters reach the tip, not during materialize.
                    move || {
                        if advertise_later {
                            filter_peers.set_compact_filters_service(true);
                        }
                    },
                ));
            }
            sync_tx_relay(&node, &config, &mempool).await?;
            let mp_live = mempool_blocking(&mempool, MempoolHub::live_count).await?;
            info!(
                "node: catch-up complete tip={:?} — tip tracking + block/tx relay \
                 (mempool live={}, shindex={}, sh_tip_ready={})",
                node.tip_height(),
                mp_live,
                config.shindex,
                sh_tip_ready
            );
        } else if shutdown.requested() {
            warn!("node: tip entry interrupted — restart to resume");
        }
    } else if !catch_up.is_complete() && !shutdown.requested() {
        warn!(
            "node: catch-up not complete tip={:?} — skip tip mode; restart to resume IBD",
            node.tip_height()
        );
    }

    if tip_follow_ready
        && !shutdown.requested()
        && addrman.is_empty()
        && seednodes_allowed(&config.listen)
    {
        for raw in &config.listen.seednodes {
            let addr = match resolve_seednode(raw, config.network) {
                Ok(a) => a,
                Err(e) => {
                    warn!("seednode {raw}: {e}");
                    continue;
                }
            };
            let host = raw.split(':').next().unwrap_or(raw);
            info!("Empty addrman, adding seednode ({host}) to addrfetch");
            if let Err(e) = node.peers.dial_net(addr, PeerConnType::AddrFetch) {
                warn!("seednode dial {addr}: {e}");
            }
        }
    }
    if tip_follow_ready && !shutdown.requested() {
        // Pinned `--connect` / `--trust-peer` dial every target. The address
        // book fills up to `--max-outbound` on its own path below.
        let pinned_follow = config.trust_peer_set() || config.listen.has_pinned_connect();
        let follow_n = if pinned_follow {
            targets.len()
        } else {
            max_out
        };
        // Arm before those connects. A dead proxy holds the connect, and
        // `setmocktime` during that hold must not restart the 10s. Catch-up
        // already stored a dial; drop it here. No queued dial means the
        // window opens on this clock.
        if addrman.is_empty() && seednodes_allowed(&config.listen) {
            arm_seednode_follow_wait(&node.hub.clock, 0);
        }
        if !addrman.is_empty() && seednodes_allowed(&config.listen) {
            arm_seednode_follow_wait(&node.hub.clock, follow_n);
            let seeds = config.listen.seednodes.clone();
            let network = config.network;
            let peers = Arc::clone(&node.peers);
            let clock = Arc::clone(&node.hub.clock);
            let stop = Arc::clone(&shutdown.flag);
            tokio::spawn(async move {
                let started = loop {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Some(at) = seednode_window_start(clock.connection_attempt_at()) {
                        break at;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                loop {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if seednode_delay_elapsed(started, clock.now_secs()) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if peers.outbound_full_relay_ids().len() >= 2 {
                    return;
                }
                for raw in &seeds {
                    let addr = match resolve_seednode(raw, network) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("seednode {raw}: {e}");
                            continue;
                        }
                    };
                    let host = raw.split(':').next().unwrap_or(raw);
                    info!(
                        "Couldn't connect to peers from addrman after {ADD_NEXT_SEEDNODE_SECS} seconds. Adding seednode ({host}) to addrfetch"
                    );
                    if let Err(e) = peers.dial_net(addr, PeerConnType::AddrFetch) {
                        warn!("seednode dial {addr}: {e}");
                    }
                }
            });
        }
        if pinned_follow {
            if catch_up.dial_failed_all() {
                for peer in targets.iter().take(follow_n) {
                    if let Err(e) = node.peers.dial_net(*peer, follow_type) {
                        warn!("node: follow dial {peer}: {e}");
                    }
                }
            } else {
                for (i, peer) in targets.iter().take(follow_n).enumerate() {
                    if shutdown.requested() {
                        break;
                    }
                    let to = follow_connect_timeout(&node.dialer(), *peer);
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => {
                            warn!("signal: skip remaining follow connects");
                            break;
                        }
                        result = tokio::time::timeout(to, node.follow_from_net_as(*peer, follow_type)) => {
                            match result {
                                Ok(Ok(())) => {
                                    info!(
                                        "node: following peer[{i}] {peer} (live={})",
                                        node.follow_live_count()
                                    );
                                }
                                Ok(Err(e)) => warn!("node: follow {peer} failed: {e}"),
                                Err(_) => warn!("node: follow {peer} timed out ({to:?})"),
                            }
                        }
                    }
                }
                if node.follow_live_count() == 0 && !targets.is_empty() {
                    warn!("node: no follow peers connected — tip announce may stall");
                }
            }
        } else {
            // Queued, not awaited: a shortfall must not block the supervisor,
            // and `follow_live` is still 0 until the handshakes finish.
            refill_outbound_full_relay(&config, &node.peers, &shared_peers, max_out);
        }
        // From here the 2 s redial pass reconnects any `--connect` address
        // without a live session. Hostnames were registered before catch-up
        // (`set_connect_hosts`).
        node.peers.set_connect_addrs(config.listen.connect.clone());
        // Dial can leave IBD before the tip-follow loop. Relay has to match
        // that edge before Electrum binds.
        sync_tx_relay(&node, &config, &mempool).await?;
    }

    let (mut electrum_handles, mut electrum_bridge, electrum_onion) = shutdown.or_fail(
        start_electrum_if_ready(
            sh_tip_ready,
            config.listen.electrum,
            config.sptweaks_dust,
            config.electrum_max_subs,
            &shutdown,
            &node.hub,
            &params,
            &mempool,
        )
        .await,
    );
    if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), electrum_handles.first()) {
        if let Some(hs) = shutdown.or_fail(
            ctl.add_named_onion(config.datadir.path(), "electrum", h.local_addr)
                .await
                .map(Some),
        ) {
            info!(
                "electrum onion {}.onion:{}",
                hs.service_id,
                h.local_addr.port()
            );
            let _ = electrum_onion.set((format!("{}.onion", hs.service_id), h.local_addr.port()));
            node.peers
                .set_wallet_onion(format!("{}.onion", hs.service_id), h.local_addr.port());
        }
    }
    if let Some(h) = electrum_handles.first() {
        publish_listener_addr(config.datadir.path(), "electrum", h.local_addr);
    }
    let mut esplora_handles = shutdown.or_fail(
        start_esplora_if_ready(
            sh_tip_ready,
            config.listen.esplora.clone(),
            config.network,
            config
                .esplora_block_template
                .then_some(config.mempool.blocksonly),
            config.esplora_max_inflight,
            &shutdown,
            Arc::clone(&node.hub),
            &mempool,
        )
        .await,
    );
    if config.esplora_onion {
        if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), esplora_handles.first()) {
            if let Some(hs) = shutdown.or_fail(
                ctl.add_named_onion(config.datadir.path(), "esplora", h.local_addr)
                    .await
                    .map(Some),
            ) {
                info!(
                    "esplora onion http://{}.onion:{} (/ws same port)",
                    hs.service_id,
                    h.local_addr.port()
                );
                node.peers
                    .set_wallet_onion(format!("{}.onion", hs.service_id), h.local_addr.port());
            }
        }
    }
    if let Some(h) = esplora_handles.first() {
        publish_listener_addr(config.datadir.path(), "esplora", h.local_addr);
    }
    if rpc_handle.is_none() && !shutdown.requested() {
        rpc_handle =
            shutdown.or_fail(start_rpc_listener(&config, &node, &mempool, &shared_peers).await);
    }
    let sv2_tp = shutdown.or_fail(start_sv2_tp(&config, &node.hub).await);
    let sv2_stats = sv2_tp.as_ref().map(Sv2TpHandle::stats);
    if let Some(s) = &sv2_stats {
        status.attach_sv2(Arc::clone(s));
    }
    let mut i2p_wallet = Vec::new();
    if config.listen.i2p_accept_incoming && !shutdown.requested() {
        if let Some(addr) = config.listen.i2p_sam {
            if let Some(h) = electrum_handles.first() {
                i2p_wallet.extend(
                    shutdown.or_fail(
                        start_i2p_named_forward(
                            addr,
                            config.datadir.path(),
                            "electrum",
                            h.local_addr.port(),
                        )
                        .await
                        .map(Some),
                    ),
                );
            }
            if let Some(h) = esplora_handles.first() {
                i2p_wallet.extend(
                    shutdown.or_fail(
                        start_i2p_named_forward(
                            addr,
                            config.datadir.path(),
                            "esplora",
                            h.local_addr.port(),
                        )
                        .await
                        .map(Some),
                    ),
                );
            }
        }
    }

    if let Some(cmd) = config
        .startup_notify
        .as_deref()
        .filter(|_| !shutdown.requested())
    {
        match std::process::Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(st) if st.success() => {}
            Ok(st) => warn!("startup-notify exited {st}: {cmd}"),
            Err(e) => warn!("startup-notify failed: {e}: {cmd}"),
        }
    }

    if tip_follow_ready && config.max_run_secs != Some(0) && !shutdown.requested() {
        status.enter(Phase::Following);
        let deadline = config
            .max_run_secs
            .map(|s| Instant::now() + Duration::from_secs(s));
        let mut last_tip = node.tip_height().unwrap_or(0);
        let started = Instant::now();
        let mut last_tip_change = Instant::now();
        const TIP_PERF_SECS: u64 = 5;
        let stale_tip = config.stale_tip;
        let mut tip_rx = node.hub.subscribe_tips();
        let mut perf_tick = tokio::time::interval(Duration::from_secs(TIP_PERF_SECS));
        perf_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        perf_tick.tick().await;
        let mut rpc_stop_tick = tokio::time::interval(Duration::from_millis(50));
        rpc_stop_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        rpc_stop_tick.tick().await;
        // Persistent — a one-shot sleep in the select is reset by perf/RPC ticks.
        let mut stale_poll = tokio::time::interval(config.stale_poll);
        stale_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stale_poll.tick().await;
        // Same clock as `--connect` redial. Below-cap full-relay refill uses
        // this tick, not the 600s stale poll.
        let mut refill_tick = tokio::time::interval(config.connect_redial);
        refill_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        refill_tick.tick().await;
        let mut window_blocks: u64 = 0;

        loop {
            if shutdown.requested() {
                break;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    break;
                }
            }

            // A durable head can lag `include_hwm` at tip entry. Electrum stays
            // down until write-behind covers the tip, then this same process binds.
            let electrum_due =
                config.shindex && config.listen.electrum.is_some() && electrum_handles.is_empty();
            let esplora_due =
                config.shindex && config.listen.esplora.is_some() && esplora_handles.is_empty();
            if (electrum_due || esplora_due) && node.hub.query.sh_is_tip_ready() {
                let mut bound_now = false;
                if electrum_due {
                    let (handles, bridge, onion) = shutdown.or_fail(
                        start_electrum_if_ready(
                            true,
                            config.listen.electrum,
                            config.sptweaks_dust,
                            config.electrum_max_subs,
                            &shutdown,
                            &node.hub,
                            &params,
                            &mempool,
                        )
                        .await,
                    );
                    if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), handles.first()) {
                        if let Some(hs) = shutdown.or_fail(
                            ctl.add_named_onion(config.datadir.path(), "electrum", h.local_addr)
                                .await
                                .map(Some),
                        ) {
                            info!(
                                "electrum onion {}.onion:{}",
                                hs.service_id,
                                h.local_addr.port()
                            );
                            let _ = onion
                                .set((format!("{}.onion", hs.service_id), h.local_addr.port()));
                            node.peers.set_wallet_onion(
                                format!("{}.onion", hs.service_id),
                                h.local_addr.port(),
                            );
                        }
                    }
                    if config.listen.i2p_accept_incoming {
                        if let Some(addr) = config.listen.i2p_sam {
                            if let Some(h) = handles.first() {
                                i2p_wallet.extend(
                                    shutdown.or_fail(
                                        start_i2p_named_forward(
                                            addr,
                                            config.datadir.path(),
                                            "electrum",
                                            h.local_addr.port(),
                                        )
                                        .await
                                        .map(Some),
                                    ),
                                );
                            }
                        }
                    }
                    if let Some(h) = handles.first() {
                        bound_now = true;
                        publish_listener_addr(config.datadir.path(), "electrum", h.local_addr);
                    }
                    electrum_bridge = bridge;
                    electrum_handles = handles;
                }
                if esplora_due {
                    let handles = shutdown.or_fail(
                        start_esplora_if_ready(
                            true,
                            config.listen.esplora.clone(),
                            config.network,
                            config
                                .esplora_block_template
                                .then_some(config.mempool.blocksonly),
                            config.esplora_max_inflight,
                            &shutdown,
                            Arc::clone(&node.hub),
                            &mempool,
                        )
                        .await,
                    );
                    if config.esplora_onion {
                        if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), handles.first()) {
                            if let Some(hs) = shutdown.or_fail(
                                ctl.add_named_onion(config.datadir.path(), "esplora", h.local_addr)
                                    .await
                                    .map(Some),
                            ) {
                                info!(
                                    "esplora onion http://{}.onion:{} (/ws same port)",
                                    hs.service_id,
                                    h.local_addr.port()
                                );
                                node.peers.set_wallet_onion(
                                    format!("{}.onion", hs.service_id),
                                    h.local_addr.port(),
                                );
                            }
                        }
                    }
                    if config.listen.i2p_accept_incoming {
                        if let Some(addr) = config.listen.i2p_sam {
                            if let Some(h) = handles.first() {
                                i2p_wallet.extend(
                                    shutdown.or_fail(
                                        start_i2p_named_forward(
                                            addr,
                                            config.datadir.path(),
                                            "esplora",
                                            h.local_addr.port(),
                                        )
                                        .await
                                        .map(Some),
                                    ),
                                );
                            }
                        }
                    }
                    if let Some(h) = handles.first() {
                        bound_now = true;
                        publish_listener_addr(config.datadir.path(), "esplora", h.local_addr);
                    }
                    esplora_handles = handles;
                }
                if bound_now {
                    info!("node: scripthash inclusion reached the tip — wallet services bound");
                }
            }

            // Prefer shutdown, then the 5s perf tick when both ready. Do **not**
            // put tip_rx ahead of perf under `biased` — multi-block catch-up can
            // keep tip events always ready and starve meters (no tip: perf lines).
            let rpc_live = rpc_handle.is_some();
            let wake = tip_follow_next_wake(
                shutdown.cancelled(),
                rpc_live.then_some(&mut rpc_stop_tick),
                &mut perf_tick,
                &mut tip_rx,
                &mut stale_poll,
                &mut refill_tick,
                node.peers.addrfetch_learned(),
                deadline,
            )
            .await;
            if finish_tip_follow_wake(
                &node,
                &config,
                &mempool,
                rpc_handle.as_ref(),
                &wake,
                &shutdown,
            )
            .await?
            {
                break;
            }

            if matches!(wake, TipFollowWake::Perf) {
                if let Err(e) = mempool_blocking(&mempool, |mp| {
                    mp.publish_fee_floor();
                    mp.persist_due()
                })
                .await?
                {
                    warn!("mempool persist_due: {e}");
                }
                let mp = mempool.sample_reset_perf();
                let (esp_n, esp_us, esp_max) = rbitcoin_esplora::sample_reset_perf();
                let (el_n, el_us, el_max) = rbitcoin_electrum::sample_reset_perf();
                let serve = sample_reset_serve_perf();
                let sv2 = sv2_stats
                    .as_ref()
                    .map(|s| (s.fee_checks.take_window().0, s.builds.take_window()));
                let blks = std::mem::take(&mut window_blocks);
                if enabled(Level::Debug) {
                    let live = mempool_blocking(&mempool, MempoolHub::live_count).await?;
                    let follow_live = node.follow_live_count();
                    let acc_avg = mp
                        .accept_us
                        .checked_div(mp.accepts + mp.rejects)
                        .unwrap_or(mp.accept_us);
                    let esp_avg = esp_us.checked_div(esp_n).unwrap_or(0);
                    let el_avg = el_us.checked_div(el_n).unwrap_or(0);
                    let (sv2_checks, sv2_builds, sv2_build_us, sv2_build_max_us) = sv2
                        .map(|(checks, (n, us, max))| (checks, n, us, max))
                        .unwrap_or((0, 0, 0, 0));
                    let line = tip_perf_json(&TipPerfLog {
                        rss: read_platform_rss(),
                        cache_bodies: node.hub.cache_body_count(),
                        held_bodies: node.hub.held_body_count(),
                        mp_live: live,
                        follow_live,
                        blocks: blks,
                        accepts: mp.accepts,
                        rejects: mp.rejects,
                        accept_avg_us: acc_avg,
                        accept_max_us: mp.accept_max_us,
                        accept_lock_us: mp.accept_lock_us,
                        accept_utxo_us: mp.accept_utxo_us,
                        accept_script_us: mp.accept_script_us,
                        accept_durable_us: mp.accept_durable_us,
                        inv_tx: mp.inv_tx,
                        getdata_tx: mp.getdata_tx,
                        announce: mp.announce,
                        esplora_n: esp_n,
                        esplora_avg_us: esp_avg,
                        esplora_max_us: esp_max,
                        electrum_n: el_n,
                        electrum_avg_us: el_avg,
                        electrum_max_us: el_max,
                        serve_n: serve.n,
                        serve_bytes: serve.bytes,
                        serve_tx: serve.tx_count,
                        serve_avg_us: serve.wall_ns.checked_div(serve.n).unwrap_or(0) / 1_000,
                        serve_max_us: serve.max_ns / 1_000,
                        sv2_checks,
                        sv2_builds,
                        sv2_build_avg_us: sv2_build_us.checked_div(sv2_builds).unwrap_or(0),
                        sv2_build_max_us,
                    });
                    debug!("tip: perf {line}");
                }
            }

            if matches!(wake, TipFollowWake::Refill) {
                refill_outbound_full_relay(&config, &node.peers, &shared_peers, max_out);
                continue;
            }

            let tip = node.tip_height().unwrap_or(0);
            let elapsed = started.elapsed().as_secs().max(1);
            let delta = tip.saturating_sub(start_tip);

            let follow_live = node.follow_live_count();
            let kind = tip_follow_wake_kind(&wake, last_tip);
            if let TipFollowWake::Tip(ev) = &wake {
                let h = ev.height;
                if h != last_tip {
                    debug!(
                        "node: tip={h} (+{delta} since start, elapsed {elapsed}s, follow_live={follow_live})"
                    );
                    window_blocks = window_blocks.saturating_add(h.saturating_sub(last_tip) as u64);
                    last_tip = h;
                    last_tip_change = Instant::now();
                }
            }
            if !tip_follow_checks_stale(kind) {
                continue;
            }

            if tip != last_tip {
                debug!(
                    "node: tip={tip} (+{delta} since start, elapsed {elapsed}s, follow_live={follow_live})"
                );
                window_blocks = window_blocks.saturating_add(tip.saturating_sub(last_tip) as u64);
                last_tip = tip;
                last_tip_change = Instant::now();
                continue;
            }

            let stagnant = last_tip_change.elapsed() >= stale_tip;
            if !stagnant {
                node.peers.note_outbound_pass(OutboundPass::NotStagnant);
                continue;
            }
            if config.listen.has_pinned_connect() {
                node.peers.note_outbound_pass(OutboundPass::SkippedPinned);
                continue;
            }
            if !config.listen.use_seeds {
                node.peers.note_outbound_pass(OutboundPass::SkippedSeedsOff);
                continue;
            }
            if shutdown.requested() {
                continue;
            }
            // Below `--max-outbound` the refill tick adds peers. This arm
            // only rotates one full-relay session once the quota is full.
            let rows = node.peers.outbound_full_relay_rows();
            if !stale_follow_needs_room(rows.len(), max_out) {
                node.peers.note_outbound_pass(OutboundPass::NoSpare);
                continue;
            }
            let ids: Vec<u64> = rows.iter().map(|(id, _)| *id).collect();
            let addrs: Vec<SocketAddr> = rows.iter().map(|(_, addr)| *addr).collect();
            let groups: Vec<u64> = addrs
                .iter()
                .map(|a| netgroup(*a, addrman.asmap()))
                .collect();
            let salt = node.hub.clock.now_secs();
            let Some(evict_id) = rbitcoin_net::pick_stale_follow_evict(&ids, salt, &groups) else {
                node.peers.note_outbound_pass(OutboundPass::NoSpare);
                continue;
            };
            let (occupied, _, _) = outbound_slots(&node.peers);
            let replacement = outbound_full_relay_candidates(&shared_peers, 1, &occupied);
            if replacement.is_empty() {
                node.peers.note_outbound_pass(OutboundPass::NoSpare);
                continue;
            }
            last_tip_change = Instant::now();
            node.peers.disconnect_id(evict_id);
            info!("node: stale tip — replacing outbound {evict_id}");
            queue_outbound_full_relay(&node.peers, &shared_peers, &replacement);
            node.peers.note_outbound_pass(OutboundPass::Rotated);
        }
    }

    status.enter(Phase::Stopping);
    {
        let end_tip = node.tip_height().unwrap_or(0);
        let blocks_this_run = end_tip.saturating_sub(start_tip);
        let uptime = run_started.elapsed();
        let uptime_secs = uptime.as_secs_f64().max(1e-9);
        let blocks_per_hour = (blocks_this_run as f64) * 3600.0 / uptime_secs;
        info!(
            "node: shutting down tip={end_tip:?} (+{blocks_this_run} blocks this run, \
             uptime={uptime:?}, ~{blocks_per_hour:.1} blk/h)"
        );
    }

    if let Ok(g) = shared_peers.lock() {
        addrman.merge_from(&g);
    }
    if let Err(e) = addrman.save(&peers_path) {
        warn!("peers: final save {}: {e}", peers_path.display());
    } else {
        info!(
            "peers: saved {} address(es) to {}",
            addrman.len(),
            peers_path.display()
        );
    }

    for e in electrum_handles {
        e.shutdown().await;
    }
    if let Some(h) = electrum_bridge {
        h.abort();
        let _ = h.await;
    }
    for e in esplora_handles {
        e.shutdown().await;
    }
    if let Some(h) = sv2_tp {
        h.shutdown().await;
    }
    if let Some(h) = rpc_handle {
        if h.stop.load(Ordering::SeqCst) {
            info!("rpc: stop requested via JSON-RPC");
        }
        h.shutdown().await;
    }
    shutdown.request();
    if let Some(h) = sh_writebehind {
        let _ = h.join();
    }
    if let Some(h) = index_writebehind {
        let _ = h.join();
    }
    // In-flight tip accepts hold the hub. Drain them before the store flush.
    let hub = std::sync::Arc::clone(&node.hub);
    tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        hub.wait_tip_accept_idle();
    })
    .await
    .map_err(|e| NodeError::Config(format!("tip-accept idle: {e}")))?;
    // One spend checkpoint at the snapshot, then Class C. Not `Store::flush`.
    spend_sync.shutdown();
    // Host-friendly: fsync tip tables; MS_ASYNC Class A.
    // Full multi‑GiB fdatasync froze the desktop for 1–2+ minutes on exit.
    if let Err(e) = node.hub.query.flush_for_shutdown() {
        warn!("node: flush warning: {e}");
    } else {
        info!("node: store flushed (shutdown-friendly)");
    }
    if let Err(e) = mempool_blocking(&mempool, |mp| mp.flush()).await? {
        warn!("node: mempool flush warning: {e}");
    } else {
        let (gen, live) =
            mempool_blocking(&mempool, |mp| (mp.generation(), mp.live_count())).await?;
        info!("node: mempool flushed gen={gen} live={live}");
    }
    node.shutdown().await;
    shutdown.result()?;
    info!("node: clean exit");
    Ok(())
}

#[doc(hidden)]
pub fn tip_meets_min_work(config: &NodeConfig, hub: &rbitcoin_net::ChainHub) -> bool {
    match hub.chain_work() {
        Ok(w) => config.meets_minimum_chain_work(w.to_be_bytes()),
        Err(_) => config.minimum_chain_work.is_none(),
    }
}

#[doc(hidden)]
pub fn should_resolve_default_seeds(config: &NodeConfig) -> bool {
    config.listen.use_seeds
        && !config.listen.has_pinned_connect()
        && config.signet_challenge.is_none()
        && config.listen.proxy.is_none()
}

/// Isolated broadcast dials peers other than the pinned session.
/// A proxy or onion path to that one peer does not turn it on.
pub fn proxy_or_onion_without_trust(config: &NodeConfig) -> bool {
    let proxy_or_onion = config.listen.proxy.is_some() || config.listen.onion.is_some();
    proxy_or_onion && !config.trust_peer_set()
}

/// Genesis `--connect` whose first catch-up accepts nothing is treated as
/// finished so the process stays up. The later dial is a follow session
/// (16 blocks in flight on the tip index path), not a return to the IBD
/// window. A non-zero tip that has not finished catch-up stays in IBD.
pub fn catch_up_with_connect(
    catch_up: CatchUp,
    has_connect: bool,
    shutdown: bool,
    tip: u32,
) -> CatchUp {
    if catch_up.is_complete() || shutdown || !has_connect || tip > 0 {
        catch_up
    } else {
        CatchUp::complete_dial_failed()
    }
}

/// Tip-follow may run below `--min-chain-work`. Relay stays off until the floor.
pub fn relay_while_following(meets_min_work: bool, blocks_only: bool, in_ibd: bool) -> bool {
    meets_min_work && !blocks_only && !in_ibd
}

pub async fn resolve_connect_dns(hosts: &[String], network: Network) -> Vec<rbitcoin_net::NetAddr> {
    if hosts.is_empty() {
        return Vec::new();
    }
    let hosts = hosts.to_vec();
    let port = network.default_p2p_port();
    tokio::task::spawn_blocking(move || {
        hosts
            .iter()
            .filter_map(|h| {
                rbitcoin_net::parse_peer_addr_with_port(h, Some(port))
                    .ok()
                    .map(rbitcoin_net::NetAddr::from_socket)
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

#[doc(hidden)]
pub fn queue_proxy_seed_addrfetch(peers: &Arc<rbitcoin_net::PeerHub>, network: Network) -> usize {
    let mut n = 0usize;
    for (host, port) in socks_dns_seed_dests(network) {
        match peers.dial_domain(host.clone(), port, PeerConnType::AddrFetch) {
            Ok(()) => n += 1,
            Err(e) => warn!("seednode dial {host}:{port}: {e}"),
        }
    }
    n
}

/// A SOCKS seed answer that lost its circuit is not retried by the dial
/// queue, so the wait re-queues the seeds on this period.
const PROXY_SEED_RETRY: Duration = Duration::from_secs(60);

/// How long catch-up waits for a `--proxy` seed answer. Past it the empty
/// book falls through to the `awaiting_dialable` path.
const PROXY_SEED_WAIT: Duration = Duration::from_secs(180);

/// The shared book once an addr-fetch `getaddr` reply has been learned
/// since the wait began (`replies` counts them; a self-announce does not),
/// or `None` on shutdown or after `wait`. Re-queues the seeds every `retry`
/// while no addr-fetch session is live.
#[doc(hidden)]
pub async fn await_proxy_seed_book(
    peers: &Arc<rbitcoin_net::PeerHub>,
    network: Network,
    shared_peers: &Arc<std::sync::Mutex<AddrMan>>,
    shutdown: &Shutdown,
    replies: impl Fn() -> u64,
    retry: Duration,
    wait: Duration,
) -> Option<AddrMan> {
    let start = replies();
    let deadline = tokio::time::sleep(wait);
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    let mut requeue = tokio::time::interval_at(tokio::time::Instant::now() + retry, retry);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return None,
            _ = &mut deadline => {
                warn!(
                    "ibd: no SOCKS seed addrfetch answer in {}s — catch-up stays open",
                    wait.as_secs()
                );
                return None;
            }
            _ = requeue.tick() => {
                let answering = peers
                    .snapshot()
                    .iter()
                    .any(|p| p.conn_type == PeerConnType::AddrFetch);
                if !answering {
                    let n = queue_proxy_seed_addrfetch(peers, network);
                    info!("ibd: no seed answer yet — re-queued {n} seed hostnames via SOCKS addrfetch");
                }
            }
            _ = poll.tick() => {
                if replies() > start {
                    let book = shared_peers.lock().unwrap_or_else(|e| e.into_inner());
                    if !book.is_empty() {
                        return Some(book.clone());
                    }
                }
            }
        }
    }
}

/// IBD horizon after `sync_cancellable` (or no peers to dial).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchUp {
    Incomplete,
    Complete { dial_failed_all: bool },
}

impl CatchUp {
    pub fn complete() -> Self {
        Self::Complete {
            dial_failed_all: false,
        }
    }

    pub fn complete_dial_failed() -> Self {
        Self::Complete {
            dial_failed_all: true,
        }
    }

    pub fn is_complete(self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    pub fn dial_failed_all(self) -> bool {
        matches!(
            self,
            Self::Complete {
                dial_failed_all: true
            }
        )
    }
}

/// No outbound targets.
///
/// An empty book that this process just swept, or that is still waiting on
/// proxy seed fetch, is not a finished catch-up. A book that was already
/// empty, with nothing in flight, keeps the serve-only path.
pub fn catch_up_without_targets(awaiting_dialable: bool) -> CatchUp {
    if awaiting_dialable {
        CatchUp::Incomplete
    } else {
        CatchUp::complete()
    }
}

/// Wait in catch-up until the shared book yields a dial target or shutdown.
///
/// Used when the process has no target but discovery is still in flight (a
/// proxy seed fetch or reachability sweep). Re-queues proxy seed hostnames on
/// the normal retry period and re-reads the shared book; it does not enter
/// tip mode with a partial chain.
#[allow(clippy::too_many_arguments)] // IO/discovery args stay unbundled
pub async fn wait_for_dialable_targets(
    peers: &std::sync::Arc<rbitcoin_net::PeerHub>,
    shared_peers: &std::sync::Arc<std::sync::Mutex<AddrMan>>,
    addrman: &mut AddrMan,
    pinned: &[rbitcoin_net::NetAddr],
    max_out: usize,
    occupied: &[rbitcoin_net::NetAddr],
    shutdown: &Shutdown,
    proxy_seeds: bool,
    network: Network,
) -> Option<Vec<rbitcoin_net::NetAddr>> {
    let candidate_n = max_out.saturating_mul(2).clamp(16, 48);
    let queue_seeds = || {
        if !proxy_seeds {
            return;
        }
        let answering = peers
            .snapshot()
            .iter()
            .any(|p| p.conn_type == PeerConnType::AddrFetch);
        if !answering {
            let n = queue_proxy_seed_addrfetch(peers, network);
            if n > 0 {
                info!("ibd: no dialable address yet — re-queued {n} seed hostname(s)");
            }
        }
    };
    queue_seeds();
    let mut requeue = tokio::time::interval(PROXY_SEED_RETRY);
    requeue.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    requeue.tick().await;
    loop {
        if shutdown.requested() {
            return None;
        }
        let mut sample = || {
            {
                let g = shared_peers.lock().unwrap_or_else(|e| e.into_inner());
                if !g.is_empty() {
                    *addrman = g.clone();
                }
            }
            follow_dial_targets(pinned, addrman, candidate_n, occupied)
        };
        let targets = sample();
        if !targets.is_empty() {
            return Some(targets);
        }
        peers.note_dial_parked();
        let added = shared_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .added();
        let wake = added.notified();
        tokio::pin!(wake);
        let targets = sample();
        if !targets.is_empty() {
            return Some(targets);
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return None,
            _ = &mut wake => {}
            _ = requeue.tick() => queue_seeds(),
        }
    }
}

/// Recompute the tip-follow dial list after catch-up may have learned peers.
/// IBD disconnects its own sessions before returning, so the pre-catch-up list
/// can be stale (or empty) even when the shared book now has rows.
#[doc(hidden)]
pub fn refresh_follow_targets(
    trust_peer: bool,
    pinned: &[rbitcoin_net::NetAddr],
    shared_peers: &std::sync::Arc<std::sync::Mutex<AddrMan>>,
    addrman: &mut AddrMan,
    max_out: usize,
    occupied: &[rbitcoin_net::NetAddr],
) -> Vec<rbitcoin_net::NetAddr> {
    if !trust_peer {
        let g = shared_peers.lock().unwrap_or_else(|e| e.into_inner());
        if !g.is_empty() {
            *addrman = g.clone();
        }
    }
    outbound_dial_targets(trust_peer, pinned, addrman, max_out, occupied)
}

pub fn catch_up_after_ok(accepted: u32, tip: u32, shutdown: bool) -> CatchUp {
    if shutdown || (tip == 0 && accepted == 0) {
        CatchUp::Incomplete
    } else {
        CatchUp::complete()
    }
}

pub fn catch_up_after_err(tip: u32, index_is_tip: bool, shutdown: bool) -> CatchUp {
    if !shutdown && tip > 0 && index_is_tip {
        CatchUp::complete_dial_failed()
    } else {
        CatchUp::Incomplete
    }
}

/// A stored header path with more work than the confirmed tip.
///
/// Hash and height come from one confirmed row. A missing row or a read
/// error stays in catch-up. The scan climbs to genesis, not the 32-hop
/// IBD seed window.
#[doc(hidden)]
pub fn stored_header_chain_heavier_than_tip(hub: &ChainHub) -> bool {
    let Some(tip_h) = hub.tip_height() else {
        return true;
    };
    let rec = match hub
        .query
        .header_at_height(rbitcoin_primitives::Height(tip_h))
    {
        Ok(Some((_, rec))) => rec,
        Ok(None) => {
            warn!("node: startup tip header missing — catch-up");
            return true;
        }
        Err(e) => {
            warn!("node: startup tip header read failed: {e} — catch-up");
            return true;
        }
    };
    let invalid: Vec<[u8; 32]> = hub
        .invalid_blocks()
        .into_iter()
        .map(bitcoin::hashes::Hash::to_byte_array)
        .collect();
    match hub
        .query
        .has_heavier_header_chain_than_tip(rec.hash, tip_h, &invalid)
    {
        Ok(heavier) => heavier,
        Err(e) => {
            warn!("node: startup header scan failed: {e} — catch-up");
            true
        }
    }
}

#[doc(hidden)]
pub fn startup_skip_from_hub(hub: &ChainHub) -> bool {
    // Genesis stays in catch-up, same as a catch-up that accepts nothing.
    // The header walk runs only when age and work would already skip.
    let Some(tip_h) = hub.tip_height() else {
        return false;
    };
    if tip_h == 0 || hub.tip_is_stale_for_ibd() || !hub.meets_minimum_chain_work() {
        return false;
    }
    !stored_header_chain_heavier_than_tip(hub)
}

pub async fn startup_follows_without_catch_up(hub: &Arc<ChainHub>) -> bool {
    let hub = Arc::clone(hub);
    let joined = tokio::task::spawn_blocking(move || {
        let _region = BlockingRegion::enter();
        startup_skip_from_hub(&hub)
    })
    .await;
    match joined {
        Ok(skip) => skip,
        Err(e) => {
            warn!("node: startup tip check failed: {e} — catch-up");
            false
        }
    }
}

#[doc(hidden)]
pub fn apply_startup_index_mode(
    query: &Query,
    config: &NodeConfig,
    taproot_height: u32,
) -> Result<(), NodeError> {
    query.store().set_datadir_hdd(config.datadir_hdd);
    query.set_sh_index_enabled(config.shindex);
    query.set_sh_force_rebuild(config.sh_force_rebuild);
    query.set_block_filter_index(config.block_filter_index)?;
    query.set_max_sh_creates(config.max_sh_creates);
    query.set_heavy_sh_creates(config.heavy_sh_creates);
    query.set_seqsigwit_ram_threshold_bytes(config.prune_seqsigwit_ram_threshold_bytes)?;
    if !config.prune_seqsigwit && query.prune_seqsigwit() {
        return Err(NodeError::Config(
            "datadir is pruned-seqsigwit; restart with --prune-seqsigwit enabled".into(),
        ));
    }
    if config.prune_seqsigwit {
        query.set_prune_seqsigwit(true)?;
        query.apply_prune_seqsigwit_tip()?;
    }
    if let Err(e) =
        query.set_sptweaks_enabled(config.sptweaks, rbitcoin_primitives::Height(taproot_height))
    {
        warn!("sp_tweaks: enable failed: {e}");
    } else if config.sptweaks {
        info!("sp_tweaks: enabled origin={taproot_height}");
    }
    if config.shindex && query.sh_use_writebehind() {
        let _ = query.sync_sh_seal_from_include_hwm();
        query.enter_tip_index_mode();
        info!(
            "node: durable scripthash head — resume IndexMode::Tip \
             (skip Class A recollect; write-behind already started)"
        );
    } else {
        query
            .enter_direct_index_mode_sh(config.shindex)
            .map_err(|e| NodeError::Config(format!("index direct mode: {e}")))?;
        if config.shindex {
            info!(
                "ibd: IndexMode::Direct (archive tx.head; confirm spend batch; \
                 SH deferred until post-IBD Class A collect)"
            );
        } else {
            info!(
                "ibd: IndexMode::Direct without scripthash (shindex off; tip follow independent of SH)"
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn run_ibd_or_skip(
    node: &P2PNode,
    ibd_targets: &[rbitcoin_net::NetAddr],
    max_out: usize,
    shared_peers: &std::sync::Arc<std::sync::Mutex<AddrMan>>,
    addrman: &mut AddrMan,
    peers_path: &std::path::Path,
    shutdown: &Shutdown,
    awaiting_dialable: bool,
    peerless: Peerless,
    pinned: &[rbitcoin_net::NetAddr],
    proxy_seeds: bool,
    network: Network,
    assign_stop_bytes: u64,
) -> CatchUp {
    let mut targets = ibd_targets.to_vec();
    // `--trust-peer` has one pinned dial. An empty list is a failed resolve,
    // not a reason to wait for the peers file.
    let wait_for_discovery = !node.hub.query.trust_peer()
        && awaiting_dialable
        && matches!(peerless, Peerless::Redial { .. });
    if targets.is_empty() {
        if wait_for_discovery {
            info!("ibd: no dialable address yet — keeping catch-up open while discovery continues");
            let occupied = node.peers.live_outbound_full_relay_nets();
            let Some(found) = wait_for_dialable_targets(
                &node.peers,
                shared_peers,
                addrman,
                pinned,
                max_out,
                &occupied,
                shutdown,
                proxy_seeds,
                network,
            )
            .await
            else {
                return CatchUp::Incomplete;
            };
            targets = found;
            info!(
                "ibd: discovered {} dialable target(s) — resuming catch-up",
                targets.len()
            );
        } else {
            let catch_up = catch_up_without_targets(awaiting_dialable);
            if catch_up.is_complete() {
                info!("ibd: no outbound peers; serving only (use --connect or seeds)");
            } else {
                warn!(
                    "ibd: no dialable address yet — catch-up stays open \
                     (reachability sweep or seed fetch still in flight)"
                );
            }
            return catch_up;
        }
    }
    if shutdown.requested() {
        return CatchUp::Incomplete;
    }
    if startup_follows_without_catch_up(&node.hub).await {
        info!("node: stored tip is current — tip follow (skip catch-up)");
        return CatchUp::complete();
    }
    let target_peers = max_out.clamp(8, 32);
    // Window, per-peer cap, and stall come from `IbdConfig::default`.
    // A 5s stall caused reassign storms (clearing 200+ inflight before peers
    // could deliver mid-chain blocks). Default 30s is enough.
    let ibd_cfg = IbdConfig {
        target_peers,
        peerless,
        peers: ibd_shared_peers(node.hub.query.trust_peer(), shared_peers),
        dialer: node.dialer(),
        assign_stop_bytes,
        connect: pinned.to_vec(),
        ..IbdConfig::default()
    };
    info!(
        "ibd: catch-up candidates={} target_peers={} (window={}, per_peer={})…",
        targets.len(),
        ibd_cfg.target_peers,
        ibd_cfg.window,
        ibd_cfg.per_peer
    );
    // Cooperative cancel only: IBD polls `shutdown.flag` and exits its own
    // teardown path. Do **not** `select!`+drop the IBD future on SIGINT —
    // that used to drop a nested multi-thread runtime mid-async and panic
    // (`Cannot drop a runtime in an async context`), making Ctrl+C slow/noisy.
    let cancel = Some(Arc::clone(&shutdown.flag));
    let catch_up = match rbitcoin_ibd::sync_cancellable(node, &targets, ibd_cfg, cancel).await {
        Ok(n) => {
            if shutdown.requested() {
                warn!(
                    "ibd: catch-up interrupted accepted≈{n} tip={:?}",
                    node.tip_height()
                );
            } else {
                let tip = node.tip_height().unwrap_or(0);
                if tip == 0 && n == 0 {
                    warn!(
                        "ibd: returned ok with tip=0 accepted=0 — treating as incomplete (no tip mode)"
                    );
                } else {
                    info!("ibd: catch-up accepted≈{n} tip={:?}", node.tip_height());
                }
            }
            catch_up_after_ok(n, node.tip_height().unwrap_or(0), shutdown.requested())
        }
        Err(e) => {
            if shutdown.requested() {
                warn!("signal: IBD cancelled ({e})");
            } else {
                let tip = node.tip_height().unwrap_or(0);
                if tip > 0
                    && node
                        .hub
                        .query
                        .index_mode()
                        .expect("index mode cell")
                        .is_tip()
                {
                    warn!(
                        "ibd: incomplete: {e}; tip={tip:?} — tip indexes present, continuing tip-follow"
                    );
                } else {
                    warn!(
                        "ibd: incomplete: {e}; tip={tip:?} — keeping catch-up indexes (no tip mode; restart to resume)"
                    );
                }
            }
            catch_up_after_err(
                node.tip_height().unwrap_or(0),
                node.hub
                    .query
                    .index_mode()
                    .expect("index mode cell")
                    .is_tip(),
                shutdown.requested(),
            )
        }
    };
    if let Ok(g) = shared_peers.lock() {
        *addrman = g.clone();
    }
    if let Err(e) = addrman.save(peers_path) {
        warn!("peers: save {}: {e}", peers_path.display());
    } else {
        info!(
            "peers: saved {} address(es) to {}",
            addrman.len(),
            peers_path.display()
        );
    }
    catch_up
}

#[doc(hidden)]
pub fn spawn_hub_tip_bridge<T, F>(
    mut hub_tips: broadcast::Receiver<TipEvent>,
    tx: broadcast::Sender<T>,
    stop: Arc<AtomicBool>,
    map: F,
) -> tokio::task::JoinHandle<()>
where
    T: Clone + Send + 'static,
    F: Fn(TipEvent) -> Option<T> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match hub_tips.recv().await {
                Ok(ev) => {
                    if let Some(v) = map(ev) {
                        let _ = tx.send(v);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn listener_addr_path(datadir: &Path, name: &str) -> PathBuf {
    datadir.join("run").join(format!("{name}.addr"))
}

fn listener_wakes() -> &'static Mutex<HashMap<PathBuf, Arc<Notify>>> {
    static WAKES: OnceLock<Mutex<HashMap<PathBuf, Arc<Notify>>>> = OnceLock::new();
    WAKES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn listener_addr_wake(path: &Path) -> Arc<Notify> {
    let mut wakes = listener_wakes().lock().unwrap_or_else(|e| e.into_inner());
    wakes
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone()
}

fn read_listener_addr(path: &Path) -> Option<SocketAddr> {
    let addr: SocketAddr = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    (addr.port() != 0).then_some(addr)
}

/// Bound TCP address, including the kernel port when the configured port was 0.
/// Unix Esplora's placeholder `127.0.0.1:0` is not a listener and is skipped.
/// A same-process waiter blocked in [`wait_published_listener`] is woken.
#[doc(hidden)]
pub fn publish_listener_addr(datadir: &Path, name: &str, addr: SocketAddr) {
    if addr.port() == 0 {
        return;
    }
    let dir = datadir.join("run");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!("listener address {}: {e}", dir.display());
        return;
    }
    let path = listener_addr_path(datadir, name);
    let tmp = dir.join(format!("{name}.addr.tmp"));
    if let Err(e) = std::fs::write(&tmp, format!("{addr}\n")) {
        warn!("listener address {}: {e}", tmp.display());
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        warn!("listener address {}: {e}", path.display());
        return;
    }
    if let Some(wake) = listener_wakes()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&path)
        .cloned()
    {
        wake.notify_waiters();
    }
}

/// The address `run_p2p` published for `name`. Same-process publish wakes this.
/// A child process has no shared wake, so the wait also retries until `wait`.
#[doc(hidden)]
pub async fn wait_published_listener(datadir: &Path, name: &str, wait: Duration) -> SocketAddr {
    let path = listener_addr_path(datadir, name);
    let wake = listener_addr_wake(&path);
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let notified = wake.notified();
        if let Some(addr) = read_listener_addr(&path) {
            return addr;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("{name} listener not up at {}", path.display());
        }
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

#[doc(hidden)]
pub fn electrum_tip_notify(ev: TipEvent) -> Option<TipNotify> {
    let mut buf = Vec::with_capacity(80);
    if ev.header.consensus_encode(&mut buf).is_err() {
        return None;
    }
    Some(TipNotify {
        height: ev.height,
        header_hex: rbitcoin_primitives::hex_encode(&(buf)),
        reorg_from_height: if ev.reorg_branch_len > 0 {
            Some(ev.height.saturating_sub(ev.reorg_branch_len))
        } else {
            None
        },
    })
}

pub async fn start_i2p_named_forward(
    sam_addr: SocketAddr,
    datadir: &Path,
    name: &str,
    port: u16,
) -> Result<rbitcoin_net::I2pSam, NodeError> {
    let dest = datadir.join("i2p").join(format!("{name}.priv"));
    let mut sam =
        rbitcoin_net::I2pSam::connect_persistent(sam_addr, &dest, rbitcoin_net::SAM_RETRY)
            .await
            .map_err(|e| NodeError::Init(format!("i2p {name} session: {e}")))?;
    sam.stream_forward(port)
        .await
        .map_err(|e| NodeError::Init(format!("i2p {name} STREAM FORWARD {port}: {e}")))?;
    info!("i2p {name} STREAM FORWARD to 127.0.0.1:{port}");
    Ok(sam)
}

/// One tip-follow wake: RPC stop and IBD flags, then fee-history preload.
///
/// A tip-mode accept turns relay on and owes the preload. That accept does
/// not run this loop. The default node has no RPC server, so the take has
/// to run on every wake that is not an RPC stop. Returns true when the
/// loop should exit.
#[doc(hidden)]
pub async fn finish_tip_follow_wake(
    node: &P2PNode,
    config: &NodeConfig,
    mempool: &Arc<MempoolHub>,
    rpc: Option<&RpcHandle>,
    wake: &TipFollowWake,
    shutdown: &Shutdown,
) -> Result<bool, NodeError> {
    if let Some(h) = rpc {
        if h.stop.load(Ordering::SeqCst) {
            // Core keeps the RPC server up until in-flight handlers
            // finish (`feature_shutdown.py` waitfornewblock must
            // return tip height 0, not a proxy -28 on close).
            for _ in 0..200 {
                let n = h.active.lock().map(|a| a.len()).unwrap_or(0);
                if n == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            info!("rpc: stop — shutting down");
            shutdown.request();
            return Ok(true);
        }
        h.connections
            .store(node.follow_live_count() as u64, Ordering::Relaxed);
        let minwork = tip_meets_min_work(config, &node.hub);
        let ibd = node.hub.in_ibd();
        h.initial_block_download
            .store(!minwork || ibd, Ordering::SeqCst);
    }
    sync_tx_relay(node, config, mempool).await?;
    Ok(matches!(wake, TipFollowWake::Stop))
}

/// Turn peer tx relay on or off to match IBD. One place for indexing
/// finished, the bind before Electrum, and the tip-follow loop.
pub async fn sync_tx_relay(
    node: &P2PNode,
    config: &NodeConfig,
    mempool: &Arc<MempoolHub>,
) -> Result<(), NodeError> {
    let want = relay_while_following(
        tip_meets_min_work(config, &node.hub),
        config.mempool.blocksonly,
        node.hub.in_ibd(),
    );
    if want == mempool.relay_enabled() {
        // A tip-mode accept may have set the bit and left preload due.
        if want && mempool.take_fee_backfill_due() {
            spawn_fee_history_backfill(mempool);
        }
        return Ok(());
    }
    let edge = mempool_blocking(mempool, move |mp| mp.apply_relay_edge(want)).await?;
    // A purge fault leaves the bit unchanged. The next wake retries. Do not
    // tell peers relay is on, or log that it flipped, until the store moved.
    let Some(backfill) = edge else {
        return Ok(());
    };
    node.peers
        .queue_feefilter_all(node.hub.feefilter_sat_kvb() as i64);
    if want {
        info!("ibd: leaving IBD — enabling tx relay");
    } else {
        info!("ibd: entering IBD — pausing tx relay");
    }
    if backfill {
        spawn_fee_history_backfill(mempool);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn start_electrum_if_ready(
    sh_tip_ready: bool,
    addr: Option<SocketAddr>,
    tweaks_min_dust: u64,
    electrum_max_subs: usize,
    shutdown: &Shutdown,
    hub: &ChainHub,
    params: &rbitcoin_consensus::ChainParams,
    mempool: &std::sync::Arc<MempoolHub>,
) -> Result<
    (
        Vec<ElectrumHandle>,
        Option<tokio::task::JoinHandle<()>>,
        Arc<OnceLock<(String, u16)>>,
    ),
    NodeError,
> {
    let onion_tcp = Arc::new(OnceLock::new());
    let Some(addr) = addr else {
        return Ok((Vec::new(), None, onion_tcp));
    };
    if !sh_tip_ready || shutdown.requested() {
        return Ok((Vec::new(), None, onion_tcp));
    }
    let q = hub.query.clone();
    let (electrum_tip_tx, _) = broadcast::channel::<TipNotify>(64);
    let hub_tips = hub.subscribe_tips();
    let bridge = spawn_hub_tip_bridge(
        hub_tips,
        electrum_tip_tx.clone(),
        Arc::clone(&shutdown.flag),
        electrum_tip_notify,
    );
    let mut ecfg = ElectrumConfig::for_params(addr, params);
    ecfg.max_scripthash_subs = electrum_max_subs;
    ecfg.tweaks_min_dust = tweaks_min_dust;
    ecfg.onion_tcp = Arc::clone(&onion_tcp);
    ecfg.batch_window = rbitcoin_electrum::batch_window(crate::cli::blocking_pool_size());
    let max_conn = ecfg.limits.max_connections;
    let max_line = ecfg.limits.max_request_bytes;
    let idle_secs = ecfg.limits.idle_timeout.as_secs();
    match run_electrum(
        ecfg,
        q,
        params.clone(),
        electrum_tip_tx,
        Some(Arc::clone(mempool)),
    )
    .await
    {
        Ok(h) => {
            info!(
                "electrum TCP on {} (Query + mempool; max_conn={} max_line={} idle={}s; TLS via reverse proxy if public)",
                h.local_addr, max_conn, max_line, idle_secs
            );
            Ok((vec![h], Some(bridge), onion_tcp))
        }
        Err(e) => {
            bridge.abort();
            Err(NodeError::Config(format!("electrum start: {e}")))
        }
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn start_esplora_if_ready(
    sh_tip_ready: bool,
    listen: Option<EsploraListen>,
    network: Network,
    // `Some(blocksonly)` turns on `/block-template`. `None` leaves it off.
    block_template: Option<bool>,
    // Requests in flight across the listener (`--esplora-max-inflight`).
    max_inflight: usize,
    shutdown: &Shutdown,
    hub: Arc<ChainHub>,
    mempool: &std::sync::Arc<MempoolHub>,
) -> Result<Vec<EsploraHandle>, NodeError> {
    let Some(listen) = listen else {
        return Ok(Vec::new());
    };
    if !sh_tip_ready || shutdown.requested() {
        return Ok(Vec::new());
    }
    let q = hub.query.clone();
    let btc_net = rbitcoin_rpc::methods::mine::rpc_btc_network(network);
    let mut ecfg = EsploraConfig::with_listen(listen, btc_net);
    ecfg.limits.max_connections = max_inflight;
    if let Some(blocksonly) = block_template {
        let q = Arc::clone(&hub.query);
        let mp = Arc::clone(mempool);
        let chain = Arc::clone(&hub);
        ecfg.block_template = Some(BlockTemplateFn(Arc::new(move || {
            let ctx = RpcContext {
                query: Arc::clone(&q),
                mempool: Some(Arc::clone(&mp)),
                network,
                start: Instant::now(),
                stop: rbitcoin_rpc::methods::StopFlag::new(false),
                connections: Arc::new(AtomicU64::new(0)),
                initial_block_download: Arc::new(AtomicBool::new(false)),
                subversion: String::new(),
                regtest: None,
                peers: None,
                chain: Some(Arc::clone(&chain)),
                addrman: None,
                logpath: String::new(),
                active: Arc::new(std::sync::Mutex::new(RpcActive::default())),
                alert_notify: None,
                alert_fired: Arc::new(AtomicBool::new(false)),
                blocksonly,
                package_dialect: false,
            };
            gbt_template(&ctx).map_err(|v| {
                v.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("block-template")
                    .to_string()
            })
        })));
    }
    let max_conn = ecfg.limits.max_connections;
    let max_body = ecfg.limits.max_request_bytes;
    let idle_secs = ecfg.limits.idle_timeout.as_secs();
    let h = run_esplora(ecfg, q, Some(Arc::clone(mempool)))
        .await
        .map_err(|e| NodeError::Config(format!("esplora start: {e}")))?;
    info!(
        "esplora HTTP on {} (max_conn={} max_body={} idle={}s; TLS via reverse proxy if public)",
        h.socket_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| h.local_addr.to_string()),
        max_conn,
        max_body,
        idle_secs
    );
    Ok(vec![h])
}

pub async fn start_sv2_tp(
    config: &NodeConfig,
    hub: &Arc<ChainHub>,
) -> Result<Option<Sv2TpHandle>, NodeError> {
    let (Some(listen), Some(authority_secret)) =
        (config.sv2_tp_listen, config.sv2_tp_authority_sec)
    else {
        return Ok(None);
    };
    let authority_secret = authority_secret.0;
    let cfg = Sv2TpConfig {
        listen,
        chain: Arc::clone(hub),
        authority_secret,
        cert_validity: Duration::from_secs(config.sv2_tp_cert_validity_secs),
        stale_grace: config.sv2_tp_stale_grace,
        setup_timeout: rbitcoin_sv2::SETUP_TIMEOUT,
        idle_timeout: (!config.sv2_tp_idle_timeout.is_zero()).then_some(config.sv2_tp_idle_timeout),
        write_timeout: rbitcoin_sv2::WRITE_TIMEOUT,
        fee_delta: config.sv2_tp_fee_delta,
        template_interval: config.sv2_tp_template_interval,
        constraints_cooldown: config.sv2_tp_constraints_cooldown,
    };
    let h = run_sv2_tp(cfg)
        .await
        .map_err(|e| NodeError::Config(format!("sv2 start: {e}")))?;
    info!(
        "sv2 TP on {} (authority pubkey {})",
        h.local_addr,
        h.authority_key()
    );
    Ok(Some(h))
}

/// Result of post-IBD tip entry: follow/mempool gates vs Electrum SH gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipModeGates {
    /// Class A + spends ready: follow peers, tip loop, mempool tip-relay.
    pub tip_follow_ready: bool,
    /// Electrum / Esplora may bind. With `--sh-index` this waits until the
    /// index is caught up. Without it the listeners still bind; address
    /// methods fail closed.
    pub sh_tip_ready: bool,
}

#[doc(hidden)]
pub fn sh_cancel_resume_note(query: &Query) -> &'static str {
    let root = query.store().path();
    if root.join("scripthash.cold_progress").is_file() {
        "partial cold shards kept (scripthash.cold_progress) — \
         restart to resume; Electrum not ready yet (stay Direct; tip follow on)"
    } else if root.join("scripthash.unsorted").is_dir() {
        "partial scripthash extract kept (scripthash.unsorted) — \
         restart to resume; Electrum not ready yet (stay Direct; tip follow on)"
    } else {
        "cancelled before a durable scripthash extract — \
         restart to resume; Electrum not ready yet (stay Direct; tip follow on)"
    }
}

#[doc(hidden)]
pub fn sh_tip_ready_gates(query: &Query) -> TipModeGates {
    let ready = query.sh_is_tip_ready();
    if ready {
        info!("node: tip-mode complete — safe to start Electrum");
    } else {
        info!("node: scripthash head is not tip-ready; Electrum stays down");
    }
    TipModeGates {
        tip_follow_ready: true,
        sh_tip_ready: ready,
    }
}

/// Start the Class B appender once. A second call does not spawn another thread.
pub fn ensure_sh_writebehind(
    slot: &mut Option<ShWritebehind>,
    query: Arc<Query>,
    stop: Arc<AtomicBool>,
    on_fatal: impl FnOnce() + Send + 'static,
) {
    if slot.is_some() {
        return;
    }
    *slot = sh_writebehind_at_tip_entry(query, stop, on_fatal);
}

/// Class B scripthash appender. `None` until Tip mode with `--sh-index`.
pub fn sh_writebehind_at_tip_entry(
    query: Arc<Query>,
    stop: Arc<AtomicBool>,
    on_fatal: impl FnOnce() + Send + 'static,
) -> Option<ShWritebehind> {
    if !query.enqueues_sh_writebehind() {
        return None;
    }
    Some(spawn_sh_writebehind(query, stop, on_fatal))
}

/// Enter steady-state after true catch-up.
///
/// **Preconditions (enforced by IBD, not repaired here):** Direct catch-up already
/// wrote durable **`tx.head`** (archive) and **spend annotations** (confirm).
/// Incomplete IBD must not call this. `CatchUp::Complete` is a finished
/// horizon, or a stored tip above genesis already inside min chain work and
/// max tip age with no heavier local header chain.
///
/// **SH methods (exactly two):**
/// - Durable head: stay/flip `IndexMode::Tip`, discard leftover runs.
///   The appender is already running from startup. `sh_tip_ready` only when
///   inclusion already covers the tip.
/// - No head: Class A collect + unsorted pack **while Direct** (the appender
///   is not started yet), then Tip. Cancel leaves Direct; Electrum stays closed.
///
/// **When `!shindex`:** skip SH materialize. Listeners may bind
/// (`sh_tip_ready`); address methods fail closed.
pub fn enter_tip_mode(
    query: &Query,
    cancel: Option<Arc<AtomicBool>>,
    shindex: bool,
) -> TipModeGates {
    rbitcoin_net::reactor::assert_not_reactor("enter_tip_mode");
    query.set_sh_index_enabled(shindex);

    if !shindex {
        query.enter_tip_index_mode();
        info!(
            "node: IndexMode::Tip (tx.head + spend annotations already live) mode={:?}",
            query.index_mode().expect("index mode cell")
        );
        info!(
            "node: tip-follow ready without scripthash (shindex off); Electrum/Esplora listen, address methods fail closed"
        );
        return TipModeGates {
            tip_follow_ready: true,
            sh_tip_ready: true,
        };
    }

    if query.sh_use_writebehind() {
        query.enter_tip_index_mode();
        info!(
            "node: IndexMode::Tip (tx.head + spend annotations already live) mode={:?}",
            query.index_mode().expect("index mode cell")
        );
        match query.finalize_sh_runs_cancellable(cancel.as_deref()) {
            Ok(_) => {}
            Err(e) => warn!("node: scripthash leftover-run discard: {e}"),
        }
        info!(
            "node: scripthash write-behind — skip collect; rows={}",
            query.scripthash_entry_count()
        );
        return sh_tip_ready_gates(query);
    }

    info!("node: index materialize from Class A (Direct collect, then Tip)…");
    if !query.index_mode().expect("index mode cell").is_direct() {
        if let Err(e) = query.enter_direct_index_mode_sh(true) {
            warn!("node: enter Direct for SH collect: {e}");
        }
    }
    let cancel_ref = cancel.as_deref();
    let sh_ok = match query.finalize_sh_runs_cancellable(cancel_ref) {
        Ok(n) => {
            info!("node: index materialize scripthash creates≈{n}");
            true
        }
        Err(StoreError::Cancelled(msg)) => {
            warn!("node: index materialize cancelled ({msg})");
            warn!("node: {}", sh_cancel_resume_note(query));
            false
        }
        Err(e) => {
            warn!("node: index materialize failed: {e}");
            warn!(
                "node: Electrum history incomplete until materialize succeeds — \
                 restart resumes from scripthash.unsorted or scripthash.cold_progress; \
                 stay Direct (no write-behind onto an incomplete head)"
            );
            false
        }
    };
    if !sh_ok {
        return TipModeGates {
            tip_follow_ready: true,
            sh_tip_ready: false,
        };
    }

    query.enter_tip_index_mode();
    info!(
        "node: IndexMode::Tip (tx.head + spend annotations already live) mode={:?}",
        query.index_mode().expect("index mode cell")
    );

    let leftover = query.scripthash_run_count();
    if leftover > 0 {
        warn!(
            "node: scripthash still has {leftover} on-disk run(s) after materialize — \
             Electrum deferred until drain succeeds (restart finalize); tip follow on"
        );
        return TipModeGates {
            tip_follow_ready: true,
            sh_tip_ready: false,
        };
    }

    info!(
        "node: scripthash rows={} (thin creates from Class A collect; spentness = confirmed-strong annotations)",
        query.scripthash_entry_count()
    );
    sh_tip_ready_gates(query)
}

/// No-peer policy for the startup catch-up. With tip indexes a give-up still
/// enters tip follow, whose supervisor keeps dialing. A run capped by
/// `max_run_secs` must return to its caller. Otherwise a give-up ends the
/// process, so catch-up keeps dialing instead, as Bitcoin Core does.
#[doc(hidden)]
pub fn main_catch_up_peerless(tip_indexes: bool, max_run_secs: Option<u64>) -> Peerless {
    if tip_indexes || max_run_secs.is_some() {
        Peerless::GiveUp
    } else {
        Peerless::Redial {
            cap: PEERLESS_REDIAL_CAP,
        }
    }
}

/// Peers-file book for catch-up. `--trust-peer` starts empty so only the
/// pinned targets seeded by the caller are dial candidates.
#[doc(hidden)]
pub fn ibd_shared_peers(
    trust_peer: bool,
    shared: &std::sync::Arc<std::sync::Mutex<AddrMan>>,
) -> Option<std::sync::Arc<std::sync::Mutex<AddrMan>>> {
    if trust_peer {
        None
    } else {
        Some(std::sync::Arc::clone(shared))
    }
}

/// Tip-follow supervisor wake. A 5s perf tick or 50ms RPC-stop tick must not
/// skip the stale-tip extra-outbound check (mainnet 962723 sat 3h after the
/// last follow peer died because a one-shot 60s sleep was reset every wake).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipFollowWakeKind {
    TipChanged,
    TipSame,
    Perf,
    Poll,
    RpcStop,
    /// Below-cap outbound full-relay refill. Not a stale-tip check.
    Refill,
    Stop,
}

/// One `select!` result from [`tip_follow_next_wake`].
pub enum TipFollowWake {
    Tip(TipEvent),
    Poll,
    Perf,
    RpcStop,
    Refill,
    Stop,
}

/// Classify a wake against the last logged tip height.
pub fn tip_follow_wake_kind(wake: &TipFollowWake, last_tip: u32) -> TipFollowWakeKind {
    match wake {
        TipFollowWake::Stop => TipFollowWakeKind::Stop,
        TipFollowWake::Perf => TipFollowWakeKind::Perf,
        TipFollowWake::Poll => TipFollowWakeKind::Poll,
        TipFollowWake::RpcStop => TipFollowWakeKind::RpcStop,
        TipFollowWake::Refill => TipFollowWakeKind::Refill,
        TipFollowWake::Tip(ev) => {
            if ev.height != last_tip {
                TipFollowWakeKind::TipChanged
            } else {
                TipFollowWakeKind::TipSame
            }
        }
    }
}

/// Load Core asmap bytecode. Missing/invalid file: warn (if a path was
/// selected) and return `None` so prefix netgroups still work.
pub fn load_asmap(datadir: &Path, configured: Option<&Path>) -> Option<Arc<AsMap>> {
    let path = match configured {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => datadir.join(p),
        None => {
            let d = datadir.join("ip_asn.dat");
            if !d.is_file() {
                return None;
            }
            d
        }
    };
    match AsMap::from_path(&path) {
        Ok(Some(m)) => {
            info!(
                "Opened asmap file {} ({} bytes, digest {})",
                path.display(),
                m.len(),
                m.digest_hex8()
            );
            Some(Arc::new(m))
        }
        Ok(None) => {
            warn!(
                "Sanity check of asmap file {} failed — using prefix netgroups",
                path.display()
            );
            None
        }
        Err(e) => {
            warn!(
                "Failed to open asmap file {}: {e} — using prefix netgroups",
                path.display()
            );
            None
        }
    }
}

/// Dial targets for catch-up and tip-follow.
///
/// `--trust-peer` never falls through to the peers file when DNS resolution
/// produced no address. `--connect` still bypasses the netgroup filter.
pub fn outbound_dial_targets(
    trust_peer: bool,
    pinned: &[rbitcoin_net::NetAddr],
    book: &AddrMan,
    max: usize,
    occupied: &[rbitcoin_net::NetAddr],
) -> Vec<rbitcoin_net::NetAddr> {
    if trust_peer {
        pinned.to_vec()
    } else {
        follow_dial_targets(pinned, book, max, occupied)
    }
}

/// `--connect` is operator-pinned: no netgroup filter. Otherwise rank + diversity.
pub fn follow_dial_targets(
    connect: &[rbitcoin_net::NetAddr],
    book: &AddrMan,
    max: usize,
    occupied: &[rbitcoin_net::NetAddr],
) -> Vec<rbitcoin_net::NetAddr> {
    if !connect.is_empty() {
        connect.to_vec()
    } else {
        let exclude: std::collections::HashSet<_> = occupied.iter().copied().collect();
        let socks: Vec<SocketAddr> = occupied
            .iter()
            .copied()
            .filter_map(rbitcoin_net::NetAddr::socket_addr)
            .collect();
        book.take_dial_candidates_net(max, &exclude, &socks)
    }
}

/// Session type for the tip-follow dials of `targets`. `--connect` targets
/// are `manual`, as Core dials `-connect` (`getpeerinfo.connection_type`).
pub fn follow_dial_type(connect: &[rbitcoin_net::NetAddr]) -> PeerConnType {
    if connect.is_empty() {
        PeerConnType::OutboundFullRelay
    } else {
        PeerConnType::Manual
    }
}

#[doc(hidden)]
pub const ADD_NEXT_SEEDNODE_SECS: u64 = 10;

/// Drop a dial sample taken before tip-follow.
///
/// Catch-up records the process's first dial and then drops those
/// sessions. Call this once, before follow dials. `follow_dials == 0`
/// opens the 10s window on this clock: nothing queued will record a
/// later sample. A positive count leaves the sample clear until that dial.
#[doc(hidden)]
pub fn arm_seednode_follow_wait(clock: &rbitcoin_consensus::clock::NodeClock, follow_dials: usize) {
    clock.forget_connection_attempt();
    if follow_dials == 0 {
        clock.note_connection_attempt();
    }
}

/// Clock sample that opens the 10s seednode wait.
///
/// `None` until the next outbound dial, or until [`arm_seednode_follow_wait`]
/// when follow queues none. A later `setmocktime` does not move this
/// sample, so the wait still ends. Sampling `now` after that jump would
/// start the wait at the mock, and mock time does not advance. A catch-up
/// dial is not this sample: arming clears it before follow dials.
#[doc(hidden)]
pub fn seednode_window_start(attempt_at: u64) -> Option<u64> {
    if attempt_at == 0 {
        None
    } else {
        Some(attempt_at)
    }
}

/// True once `now` is at least 10s after the sampled outbound dial.
///
/// `started_at == 0` means that dial has not happened. A later `setmocktime`
/// moves `now` and leaves `started_at` on the dial sample.
pub fn seednode_delay_elapsed(started_at: u64, now: u64) -> bool {
    started_at != 0 && now.saturating_sub(started_at) >= ADD_NEXT_SEEDNODE_SECS
}

/// Whether `--seednode` may be dialled as addr-fetch: at startup with an
/// empty addrman, or by the 10 s fallback when fewer than 2 outbound
/// full-relay peers are live. Core never dials seednodes under `-connect`.
/// `--connect` peers are `manual`, so they would never hold the fallback off.
pub fn seednodes_allowed(listen: &ListenOpts) -> bool {
    !listen.seednodes.is_empty() && !listen.has_pinned_connect()
}

/// Whether this wake should run the stale-tip redial check.
///
/// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale. A one-shot
/// `sleep` in the same `select!` is reset on every such wake and never fires.
pub fn stale_follow_needs_room(follow_live: usize, max_outbound: usize) -> bool {
    follow_live >= max_outbound.max(1)
}

pub fn tip_follow_checks_stale(kind: TipFollowWakeKind) -> bool {
    matches!(
        kind,
        TipFollowWakeKind::Perf
            | TipFollowWakeKind::Poll
            | TipFollowWakeKind::RpcStop
            | TipFollowWakeKind::TipSame
    )
}

/// One supervisor wake. `stale` and `refill` must be **persistent** intervals,
/// not a one-shot sleep created inside the loop (that sleep restarts on every
/// faster tick and never completes).
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn tip_follow_next_wake(
    shutdown: impl std::future::Future<Output = ()>,
    rpc_stop: Option<&mut tokio::time::Interval>,
    perf: &mut tokio::time::Interval,
    tip_rx: &mut broadcast::Receiver<TipEvent>,
    stale: &mut tokio::time::Interval,
    refill: &mut tokio::time::Interval,
    addrfetch: &Notify,
    run_deadline: Option<Instant>,
) -> TipFollowWake {
    tokio::select! {
        biased;
        _ = shutdown => TipFollowWake::Stop,
        _ = async {
            match run_deadline {
                Some(d) => tokio::time::sleep(d.saturating_duration_since(Instant::now())).await,
                None => std::future::pending::<()>().await,
            }
        } => TipFollowWake::Stop,
        _ = async {
            match rpc_stop {
                Some(tick) => {
                    tick.tick().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => TipFollowWake::RpcStop,
        _ = refill.tick() => TipFollowWake::Refill,
        _ = addrfetch.notified() => TipFollowWake::Refill,
        _ = perf.tick() => TipFollowWake::Perf,
        ev = tip_rx.recv() => match ev {
            Ok(e) => TipFollowWake::Tip(e),
            Err(broadcast::error::RecvError::Lagged(_)) => TipFollowWake::Poll,
            Err(broadcast::error::RecvError::Closed) => TipFollowWake::Stop,
        },
        _ = stale.tick() => TipFollowWake::Poll,
    }
}

/// Dial `outbound-full-relay` until the live count plus in-flight dials
/// reaches `max_out`. `--connect` and `--trust-peer` do not use the book.
/// `--trusted` (noban) still fills. Stale rotation does not evict that hub:
/// `outbound_full_relay_rows` is empty while noban is set.
pub fn refill_outbound_full_relay(
    config: &NodeConfig,
    peers: &rbitcoin_net::PeerHub,
    shared_peers: &Arc<std::sync::Mutex<AddrMan>>,
    max_out: usize,
) {
    if config.trust_peer_set() || config.listen.has_pinned_connect() {
        peers.note_outbound_pass(OutboundPass::SkippedPinned);
        return;
    }
    let (occupied, live, pending) = outbound_slots(peers);
    if live >= max_out {
        peers.note_outbound_pass(OutboundPass::NoSpare);
        return;
    }
    let room = max_out.saturating_sub(live).saturating_sub(pending);
    let picked = outbound_full_relay_candidates(shared_peers, room, &occupied);
    if picked.is_empty() {
        peers.note_outbound_pass(OutboundPass::NoSpare);
        return;
    }
    queue_outbound_full_relay(peers, shared_peers, &picked);
}

/// Live outbound full-relay nets, every other live session (so a full-relay
/// dial does not stick on an address that is already inbound, manual, or
/// addr-fetch), and in-flight dials. `live` is the quota count. `pending`
/// is in-flight dials that are not already one of those sessions.
fn outbound_slots(peers: &rbitcoin_net::PeerHub) -> (Vec<rbitcoin_net::NetAddr>, usize, usize) {
    let mut occupied = peers.live_outbound_full_relay_nets();
    let live = occupied.len();
    for peer in peers.live_peers() {
        if !occupied.contains(&peer.net) {
            occupied.push(peer.net);
        }
    }
    let inflight = peers.in_flight_nets();
    let pending = inflight
        .iter()
        .filter(|net| !occupied.contains(net))
        .count();
    for net in inflight {
        if !occupied.contains(&net) {
            occupied.push(net);
        }
    }
    (occupied, live, pending)
}

fn outbound_full_relay_candidates(
    shared_peers: &Arc<std::sync::Mutex<AddrMan>>,
    room: usize,
    occupied: &[NetAddr],
) -> Vec<NetAddr> {
    if room == 0 {
        return Vec::new();
    }
    let book = shared_peers.lock().unwrap_or_else(|e| e.into_inner());
    follow_dial_targets(&[], &book, room, occupied)
}

fn queue_outbound_full_relay(
    peers: &rbitcoin_net::PeerHub,
    shared_peers: &Arc<std::sync::Mutex<AddrMan>>,
    picked: &[NetAddr],
) {
    let mut queued = Vec::new();
    for addr in picked {
        if peers.dial_outbound_full_relay(*addr) {
            queued.push(*addr);
        }
    }
    if queued.is_empty() {
        return;
    }
    let mut book = shared_peers.lock().unwrap_or_else(|e| e.into_inner());
    for addr in queued {
        book.note_attempt_addr(addr);
    }
}

/// A CJDNS listen bind is the address peers should learn. `--external-ip`
/// still wins when the operator set the same address already.
#[doc(hidden)]
pub fn external_ips_with_cjdns_bind(
    configured: &[std::net::IpAddr],
    bind: SocketAddr,
    cjdns_reachable: bool,
) -> Vec<std::net::IpAddr> {
    let mut ips = configured.to_vec();
    if !cjdns_reachable {
        return ips;
    }
    let std::net::IpAddr::V6(ip) = bind.ip() else {
        return ips;
    };
    if !rbitcoin_net::is_cjdns_ip(ip) || ips.contains(&std::net::IpAddr::V6(ip)) {
        return ips;
    }
    ips.push(std::net::IpAddr::V6(ip));
    ips
}

/// Parse Core `-seednode` host or host:port using the chain default P2P port.
#[doc(hidden)]
pub fn resolve_seednode(raw: &str, network: Network) -> Result<NetAddr, String> {
    if let Ok(a) = raw.parse::<NetAddr>() {
        return Ok(a);
    }
    let ip: std::net::IpAddr = raw
        .parse()
        .map_err(|e| format!("bad seednode address: {e}"))?;
    Ok(NetAddr::from_socket(SocketAddr::new(
        ip,
        default_port(network),
    )))
}
