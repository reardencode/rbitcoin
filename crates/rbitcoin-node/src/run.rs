use crate::config::{parse_btc_to_sat, NodeConfig};
use crate::error::NodeError;
use crate::regtest_rpc::HubRegtest;
use bitcoin::consensus::Encodable;
use rbitcoin_electrum::{run_electrum, ElectrumConfig, ElectrumHandle, TipNotify};
use rbitcoin_esplora::{run_esplora, EsploraConfig, EsploraHandle};
use rbitcoin_log::{debug, enabled, info, warn, Level};
use rbitcoin_net::{
    default_port, format_serve_perf, format_tip_perf_sizes, netgroup, read_proc_rss,
    sample_reset_serve_perf, AddrMan, AsMap, ChainHub, IbdConfig, MempoolHub, P2PNode,
    PeerConnType, TipEvent, TipPerfSizes,
};
use rbitcoin_primitives::Network;
use rbitcoin_query::{spawn_sh_writebehind, Query};
use rbitcoin_rpc::{run_rpc, RpcConfig, RpcHandle, RpcRegtest};
use rbitcoin_store::StoreError;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Notify};

/// Running node state (store open; optional P2P).
pub struct NodeHandle {
    pub config: NodeConfig,
    pub query: Query,
    /// Durable cluster mempool (opened in `run_p2p` and attached to `ChainHub`).
    /// Smoke-only `run_node` leaves this `None`.
    pub mempool: Option<std::sync::Arc<MempoolHub>>,
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
    notify: Notify,
}

impl Shutdown {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Notify::new(),
        })
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

/// Install SIGTERM / SIGINT (and Ctrl+C) handlers that trip `shutdown`.
fn spawn_signal_handler(shutdown: Arc<Shutdown>) {
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

/// Start the node: ensure datadir, open store.
pub fn run_node(config: NodeConfig) -> Result<NodeHandle, NodeError> {
    config.ensure_datadir()?;
    let query = Query::open_or_create_layout(config.store_layout())?;
    Ok(NodeHandle {
        config,
        query,
        mempool: None,
    })
}

/// Long-running P2P (+ optional Electrum): seed resolve, catch-up, persistent follow, progress logs.
///
/// Cleanly exits on **SIGTERM** / **SIGINT** (`kill <pid>` or Ctrl+C): flushes the store
/// and aborts peer tasks (runtime `shutdown_timeout` so leftover sessions cannot
/// hold the process).
pub async fn run_p2p(config: NodeConfig) -> Result<(), NodeError> {
    let handle = run_node(config.clone())?;
    let params = config.chain_params()?;
    let milestone = config.milestone();
    if milestone.height > 0 {
        info!(
            "ibd: milestone height={} (script/sig checks skipped at/below; prevouts always)",
            milestone.height
        );
    }
    apply_startup_index_mode(&handle.query, &config, params.taproot_height())?;
    let listen = config
        .listen
        .p2p
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], default_port(config.network))));

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

    let query = handle.query;
    let p2p_ua =
        rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &config.uacomments)
            .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")));
    let mut node = P2PNode::start_with_agent(
        listen,
        query,
        params.clone(),
        milestone,
        p2p_ua,
        config.listen.max_inbound as usize,
    )
    .await
    .map_err(|e| NodeError::Config(format!("p2p start: {e}")))?;
    for extra in &config.listen.p2p_extra {
        node.add_listen(*extra)
            .await
            .map_err(|e| NodeError::Config(format!("p2p extra listen {extra}: {e}")))?;
    }
    node.hub.set_minimum_chain_work(config.minimum_chain_work);
    if let Some(secs) = config.max_tip_age_secs {
        node.hub.set_max_tip_age_secs(secs);
    }
    if let Some(t) = config.mock_time {
        node.hub.clock.set_mock(t);
    }
    if let Some(h) = node.hub.query.tip_height() {
        if let Ok(Some((_, rec))) = node.hub.query.header_at_height(h) {
            if crate::error::tip_too_far_in_future(rec.timestamp, node.hub.clock.now_secs()) {
                // Core InitError / ThreadSafeQuestion recover text (rpc_blockchain).
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
                return Err(NodeError::Config(format!("bad --blockmintxfee {s}: {e}")));
            }
        }
    }

    let mempool = MempoolHub::open_with_weight_persist(
        config.mempool_path(),
        node.hub.query.clone(),
        config.mempool.max_weight,
        config.mempool.persist,
    )
    .map_err(|e| NodeError::Config(e))?;
    mempool.set_cluster_limits(
        config.mempool.limit_cluster_count,
        config.mempool.limit_cluster_size_kvb,
    );
    if let Some(secs) = config.listen.peer_timeout_secs {
        node.peers.set_peer_timeout_secs(secs);
    }
    node.peers.set_listen_port(listen.port());
    if !config.listen.external_ips.is_empty() {
        node.peers
            .set_external_ips(config.listen.external_ips.clone());
    }
    if config.whitelist.iter().any(|w| w.contains("noban")) {
        mempool.set_immediate_relay(true);
        node.peers.set_noban(true);
    }
    if config.whitelist.iter().any(|w| w.contains("relay")) {
        node.peers.set_relay_perm(true);
    }
    if config.whitelist.iter().any(|w| w.contains("forcerelay")) {
        node.peers.set_forcerelay_perm(true);
        node.peers.set_relay_perm(true);
    }
    if let Some(s) = config.mempool.min_relay_fee_btc.as_deref() {
        match parse_btc_to_sat(s) {
            Ok(sat) => mempool.set_min_relay_sat_kvb(sat),
            Err(e) => {
                return Err(NodeError::Config(format!("bad --minrelaytxfee {s}: {e}")));
            }
        }
    }
    if let Some(h) = config.mempool.expiry_hours {
        mempool.set_expiry_hours(h);
    }
    node.hub
        .attach_mempool(mempool.clone())
        .map_err(|_| NodeError::Config("mempool already attached".into()))?;
    info!(
        "mempool: open {} gen={} live={} max_weight={} (relay off until tip mode)",
        config.mempool_path().display(),
        mempool.generation(),
        mempool.live_count(),
        config.mempool.max_weight
    );

    info!(
        "rbitcoin-node listening on {} ({})",
        node.local_addr,
        config.network.as_str()
    );

    let shutdown = Shutdown::new();
    spawn_signal_handler(shutdown.clone());
    // One Class B appender thread. Join it at shutdown so apply does not race flush.
    let sh_writebehind = if config.shindex {
        Some(spawn_sh_writebehind(
            Arc::clone(&node.hub.query),
            Arc::clone(&shutdown.flag),
            {
                let sd = Arc::clone(&shutdown);
                move || sd.request()
            },
        ))
    } else {
        None
    };
    if config.sptweaks && node.hub.query.index_mode().is_tip() {
        spawn_sptweaks_backfill(
            Arc::clone(&node.hub.query),
            params.clone(),
            Arc::clone(&shutdown.flag),
        );
    }

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
    node.peers.set_asmap(asmap);
    for c in &config.listen.connect {
        addrman.add(*c);
    }
    if should_resolve_default_seeds(&config) {
        info!(
            "ibd: resolving DNS/fixed seeds for {}…",
            config.network.as_str()
        );
        let n_before = addrman.len();
        addrman.inject(rbitcoin_net::resolve_all_seeds(config.network));
        info!(
            "ibd: seeds resolved (+{} new, book={})",
            addrman.len().saturating_sub(n_before),
            addrman.len()
        );
    } else if config.signet_challenge.is_some()
        && config.listen.connect.is_empty()
        && addrman.is_empty()
    {
        warn!("custom signet has no peers; use --connect ADDR or reuse a datadir with known peers");
    }
    let shared_peers = std::sync::Arc::new(std::sync::Mutex::new(addrman.clone()));
    node.peers.set_addrman(std::sync::Arc::clone(&shared_peers));

    let max_out = config.listen.max_outbound.max(1) as usize;
    let candidate_n = max_out.saturating_mul(2).clamp(16, 48);
    let occupied = node.peers.live_outbound_full_relay_addrs();
    let targets = follow_dial_targets(&config.listen.connect, &addrman, max_out, &occupied);
    let ibd_targets = follow_dial_targets(&config.listen.connect, &addrman, candidate_n, &occupied);
    let catch_up = run_ibd_or_skip(
        &node,
        &ibd_targets,
        max_out,
        &shared_peers,
        &mut addrman,
        &peers_path,
        &shutdown,
    )
    .await;

    // Still enter tip-follow when work is below `-minimumchainwork` so later
    // blocks can raise the tip. Relay / getheaders stay gated on the hub floor.
    if catch_up.is_complete() && !tip_meets_min_work(&config, &node.hub) {
        info!("ibd: tip work below -minimumchainwork — following without relay");
    }

    // tip_follow_ready ≠ sh_tip_ready: follow/relay do not wait on SH materialize.
    let mut tip_follow_ready = false;
    let mut sh_tip_ready = false;
    if catch_up.is_complete() && !shutdown.requested() {
        let gates = enter_tip_mode(
            &node.hub.query,
            Some(Arc::clone(&shutdown.flag)),
            config.shindex,
        );
        tip_follow_ready = gates.tip_follow_ready;
        sh_tip_ready = gates.sh_tip_ready;
        if tip_follow_ready && !shutdown.requested() {
            if config.sptweaks {
                spawn_sptweaks_backfill(
                    Arc::clone(&node.hub.query),
                    params.clone(),
                    Arc::clone(&shutdown.flag),
                );
            }
            if !config.mempool.blocksonly
                && tip_meets_min_work(&config, &node.hub)
                && !node.hub.in_ibd()
            {
                mempool.set_relay_enabled(true);
            }
            info!(
                "node: catch-up complete tip={:?} — tip tracking + block/tx relay \
                 (mempool live={}, shindex={}, sh_tip_ready={})",
                node.tip_height(),
                mempool.live_count(),
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

    if tip_follow_ready && !shutdown.requested() && addrman.is_empty() {
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
            if let Err(e) = node.peers.dial(addr, PeerConnType::AddrFetch) {
                warn!("seednode dial {addr}: {e}");
            }
        }
    }
    if !shutdown.requested() && !config.listen.seednodes.is_empty() && !addrman.is_empty() {
        const ADD_NEXT_SEEDNODE_SECS: u64 = 10;
        let seeds = config.listen.seednodes.clone();
        let network = config.network;
        let peers = Arc::clone(&node.peers);
        let clock = Arc::clone(&node.hub.clock);
        let stop = Arc::clone(&shutdown.flag);
        let start_secs = clock.now_secs();
        tokio::spawn(async move {
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if clock.now_secs().saturating_sub(start_secs) >= ADD_NEXT_SEEDNODE_SECS {
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
                if let Err(e) = peers.dial(addr, PeerConnType::AddrFetch) {
                    warn!("seednode dial {addr}: {e}");
                }
            }
        });
    }

    if tip_follow_ready && !shutdown.requested() {
        let follow_n = targets.len().min(max_out.min(3));
        const FOLLOW_CONNECT_SECS: u64 = 8;
        if catch_up.dial_failed_all() {
            for peer in targets.iter().take(follow_n) {
                if let Err(e) = node.peers.dial(*peer, PeerConnType::OutboundFullRelay) {
                    warn!("node: follow dial {peer}: {e}");
                }
            }
            if node.follow_live_count() == 0 && !targets.is_empty() {
                warn!("node: no follow peers connected — tip announce may stall");
            }
        } else {
            for (i, peer) in targets.iter().take(follow_n).enumerate() {
                if shutdown.requested() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        warn!("signal: skip remaining follow connects");
                        break;
                    }
                    result = tokio::time::timeout(
                        Duration::from_secs(FOLLOW_CONNECT_SECS),
                        node.follow_from(*peer),
                    ) => {
                        match result {
                            Ok(Ok(())) => {
                                info!(
                                    "node: following peer[{i}] {peer} (live={})",
                                    node.follow_live_count()
                                );
                            }
                            Ok(Err(e)) => warn!("node: follow {peer} failed: {e}"),
                            Err(_) => warn!(
                                "node: follow {peer} timed out ({FOLLOW_CONNECT_SECS}s)"
                            ),
                        }
                    }
                }
            }
            if node.follow_live_count() == 0 && !targets.is_empty() {
                warn!("node: no follow peers connected — tip announce may stall");
            }
        }
    }

    let (electrum_handles, electrum_bridge) = start_electrum_if_ready(
        sh_tip_ready,
        config.listen.electrum,
        config.sptweaks_dust,
        &shutdown,
        &node.hub,
        &params,
        &mempool,
    )
    .await;
    let (esplora_handles, esplora_tip_bridge) = start_esplora_if_ready(
        sh_tip_ready,
        config.listen.esplora,
        config.network,
        &shutdown,
        &node.hub,
        &mempool,
    )
    .await;

    let mut rpc_handle: Option<RpcHandle> = None;
    if let Some(addr) = config.rpc.listen {
        if !shutdown.requested() {
            let rcfg = RpcConfig {
                listen: addr,
                datadir: config.datadir.path.clone(),
                network: config.network,
                rpc_user: config.rpc.user.clone(),
                rpc_password: config.rpc.password.clone(),
                cookie_path: Some(config.rpc_cookie_path()),
                work_queue: config.rpc.work_queue,
                subversion: Some(
                    rbitcoin_primitives::rbitcoin_subversion(
                        env!("CARGO_PKG_VERSION"),
                        &config.uacomments,
                    )
                    .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION"))),
                ),
                alert_notify: config.alert_notify.clone(),
            };
            let miner: Option<Arc<dyn RpcRegtest>> = if config.network == Network::Regtest {
                Some(Arc::new(HubRegtest(Arc::clone(&node.hub))))
            } else {
                None
            };
            match run_rpc(
                rcfg,
                Arc::clone(&node.hub.query),
                Some(mempool.clone()),
                miner,
                Some(Arc::clone(&node.peers)),
                Some(Arc::clone(&node.hub)),
                Some(Arc::clone(&shared_peers)),
            )
            .await
            {
                Ok(h) => {
                    h.initial_block_download
                        .store(!tip_follow_ready || node.hub.in_ibd(), Ordering::SeqCst);
                    h.connections
                        .store(node.follow_live_count() as u64, Ordering::Relaxed);
                    info!(
                        "rpc: listening on {} (auth={})",
                        h.local_addr,
                        if config.rpc.user.is_some() {
                            "rpcuser/rpcpassword"
                        } else {
                            "cookie"
                        }
                    );
                    rpc_handle = Some(h);
                }
                Err(e) => warn!("rpc start warning: {e}"),
            }
        }
    }

    if let Some(cmd) = config.startup_notify.as_deref() {
        match std::process::Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(st) if st.success() => {}
            Ok(st) => warn!("startupnotify exited {st}: {cmd}"),
            Err(e) => warn!("startupnotify failed: {e}: {cmd}"),
        }
    }

    if tip_follow_ready && config.max_run_secs != Some(0) && !shutdown.requested() {
        let deadline = config
            .max_run_secs
            .map(|s| Instant::now() + Duration::from_secs(s));
        let mut last_tip = node.tip_height().unwrap_or(0);
        let mut seed_offset = targets.len().min(max_out.min(3));
        let started = Instant::now();
        let mut last_tip_change = Instant::now();
        const STALE_TIP_SECS: u64 = 600;
        const STALE_POLL_SECS: u64 = 60;
        const TIP_PERF_SECS: u64 = 5;
        let mut tip_rx = node.hub.subscribe_tips();
        let mut perf_tick = tokio::time::interval(Duration::from_secs(TIP_PERF_SECS));
        perf_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        perf_tick.tick().await;
        let mut rpc_stop_tick = tokio::time::interval(Duration::from_millis(50));
        rpc_stop_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        rpc_stop_tick.tick().await;
        // Persistent — a one-shot sleep in the select is reset by perf/RPC ticks.
        let mut stale_poll = tokio::time::interval(Duration::from_secs(STALE_POLL_SECS));
        stale_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stale_poll.tick().await;
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
            )
            .await;
            if let Some(ref h) = rpc_handle {
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
                    break;
                }
                h.connections
                    .store(node.follow_live_count() as u64, Ordering::Relaxed);
                let minwork = tip_meets_min_work(&config, &node.hub);
                let ibd = node.hub.in_ibd();
                h.initial_block_download
                    .store(!minwork || ibd, Ordering::SeqCst);
                let want_relay = !config.mempool.blocksonly && minwork && !ibd;
                if want_relay != mempool.relay_enabled() {
                    mempool.set_relay_enabled(want_relay);
                    if want_relay {
                        info!("ibd: leaving IBD — enabling tx relay");
                    } else {
                        info!("ibd: entering IBD — pausing tx relay");
                    }
                    node.peers
                        .queue_feefilter_all(node.hub.feefilter_sat_kvb() as i64);
                }
            }
            if matches!(wake, TipFollowWake::Stop) {
                break;
            }

            if matches!(wake, TipFollowWake::Perf) {
                let mp = mempool.sample_reset_perf();
                let (esp_n, esp_us, esp_max) = rbitcoin_esplora::sample_reset_perf();
                let (el_n, el_us, el_max) = rbitcoin_electrum::sample_reset_perf();
                let serve = sample_reset_serve_perf();
                let blks = std::mem::take(&mut window_blocks);
                if enabled(Level::Debug) {
                    let live = mempool.live_count();
                    let follow_live = node.follow_live_count();
                    let acc_avg = if mp.accepts + mp.rejects > 0 {
                        mp.accept_us / (mp.accepts + mp.rejects)
                    } else if mp.accept_us > 0 {
                        mp.accept_us
                    } else {
                        0
                    };
                    let esp_avg = if esp_n > 0 { esp_us / esp_n } else { 0 };
                    let el_avg = if el_n > 0 { el_us / el_n } else { 0 };
                    let serve_s = format_serve_perf(&serve);
                    let sizes = format_tip_perf_sizes(&TipPerfSizes {
                        rss: read_proc_rss(),
                        cache_bodies: node.hub.cache_body_count(),
                        held_bodies: node.hub.held_body_count(),
                        sh_heads: node.query.process_owned_size_snapshot().sh_heads,
                        mp_live: live,
                    });
                    debug!(
                        "tip: perf {sizes} follow_live={follow_live} blocks={blks} \
                         mempool live={live} accepts={} rejects={} accept_avg_us={acc_avg} \
                         accept_max_us={} accept_lock_us={} accept_utxo_us={} \
                         accept_script_us={} accept_durable_us={} \
                         inv_tx={} getdata_tx={} announce={} \
                         esplora req={esp_n} avg_us={esp_avg} max_us={esp_max} \
                         electrum req={el_n} avg_us={el_avg} max_us={el_max} \
                         {serve_s}",
                        mp.accepts,
                        mp.rejects,
                        mp.accept_max_us,
                        mp.accept_lock_us,
                        mp.accept_utxo_us,
                        mp.accept_script_us,
                        mp.accept_durable_us,
                        mp.inv_tx,
                        mp.getdata_tx,
                        mp.announce
                    );
                }
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

            let stagnant = last_tip_change.elapsed() >= Duration::from_secs(STALE_TIP_SECS);
            if !stagnant || config.listen.connect.is_empty() == false || !config.listen.use_seeds {
                continue;
            }
            if addrman.is_empty() || shutdown.requested() {
                continue;
            }

            last_tip_change = Instant::now();
            let occupied = node.peers.live_outbound_full_relay_addrs();
            let extra = addrman.take_outbound_offset_occupied(1, seed_offset, &occupied);
            seed_offset = seed_offset.saturating_add(1);
            if extra.is_empty() {
                continue;
            }
            if stale_follow_needs_room(follow_live, max_out) {
                let ids = node.peers.outbound_full_relay_ids();
                let addrs = node.peers.outbound_full_relay_addrs();
                let groups: Vec<u64> = addrs
                    .iter()
                    .map(|a| netgroup(*a, addrman.asmap()))
                    .collect();
                let salt = node.hub.clock.now_secs();
                let Some(evict_id) = rbitcoin_net::pick_stale_follow_evict(&ids, salt, &groups)
                else {
                    continue;
                };
                node.peers.disconnect_id(evict_id);
                info!(
                    "node: stale tip — replacing outbound {evict_id} with {}",
                    extra[0]
                );
            }
            for peer in extra {
                if shutdown.requested() {
                    break;
                }
                if catch_up.is_complete() {
                    if !stale_follow_needs_room(follow_live, max_out) {
                        info!(
                            "node: tip may be stale (height={tip}, no update ≥{STALE_TIP_SECS}s, follow_live={follow_live}) — connecting {peer} for a higher tip"
                        );
                    }
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        result = tokio::time::timeout(
                            Duration::from_secs(8),
                            node.follow_from(peer),
                        ) => {
                            match result {
                                Ok(Ok(())) => {
                                    info!(
                                        "node: added follow peer {peer} (follow_live={})",
                                        node.follow_live_count()
                                    );
                                }
                                Ok(Err(e)) => warn!("node: stale-tip peer {peer} failed: {e}"),
                                Err(_) => warn!("node: stale-tip peer {peer} connect timed out"),
                            }
                        }
                    }
                } else {
                    info!("ibd: retry catch-up from {peer} (tip stagnant, catch-up incomplete)");
                    let retry_cfg = catch_up_retry_config(std::sync::Arc::clone(&shared_peers));
                    let cancel = Some(Arc::clone(&shutdown.flag));
                    let retry_peers = [peer];
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        result = node.sync_cancellable(&retry_peers, retry_cfg, cancel) => {
                            match result {
                                Ok(n) if n > 0 => {
                                    info!(
                                        "ibd: retry got {n} tip={:?} — still catch-up (no tip mode until full catch-up)",
                                        node.tip_height()
                                    );
                                }
                                Ok(_) => {}
                                Err(e) => info!("ibd: retry {peer}: {e}"),
                            }
                        }
                    }
                }
            }
        }
    }

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
    if let Some(h) = esplora_tip_bridge {
        h.abort();
        let _ = h.await;
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
    // Host-friendly: fsync tip tables; MS_ASYNC Class A.
    // Full multi‑GiB fdatasync froze the desktop for 1–2+ minutes on exit.
    if let Err(e) = node.hub.query.flush_for_shutdown() {
        warn!("node: flush warning: {e}");
    } else {
        info!("node: store flushed (shutdown-friendly)");
    }
    if let Err(e) = mempool.flush() {
        warn!("node: mempool flush warning: {e}");
    } else {
        info!(
            "node: mempool flushed gen={} live={}",
            mempool.generation(),
            mempool.live_count()
        );
    }
    node.shutdown().await;
    info!("node: clean exit");
    Ok(())
}

fn tip_meets_min_work(config: &NodeConfig, hub: &rbitcoin_net::ChainHub) -> bool {
    match hub.chain_work() {
        Ok(w) => config.meets_minimum_chain_work(w.to_be_bytes()),
        Err(_) => config.minimum_chain_work.is_none(),
    }
}

fn should_resolve_default_seeds(config: &NodeConfig) -> bool {
    config.listen.use_seeds && config.listen.connect.is_empty() && config.signet_challenge.is_none()
}

/// One walker per process: SH-warm start and post-IBD `enter_tip_mode` both call this.
fn spawn_sptweaks_backfill(
    query: Arc<Query>,
    params: rbitcoin_consensus::ChainParams,
    cancel: Arc<AtomicBool>,
) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(move || {
        std::thread::Builder::new()
            .name("sptweaks-backfill".into())
            .spawn(move || {
                match rbitcoin_consensus::backfill_sp_tweaks_cancellable(
                    &query,
                    &params,
                    Some(cancel.as_ref()),
                ) {
                    Ok(n) => info!("sp_tweaks: backfill wrote {n} heights"),
                    Err(e) => warn!("sp_tweaks: backfill: {e}"),
                }
            })
            .ok();
    });
}

/// IBD horizon after `sync_cancellable` (or no peers to dial).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatchUp {
    Incomplete,
    Complete { dial_failed_all: bool },
}

impl CatchUp {
    pub(crate) fn complete() -> Self {
        Self::Complete {
            dial_failed_all: false,
        }
    }

    pub(crate) fn complete_dial_failed() -> Self {
        Self::Complete {
            dial_failed_all: true,
        }
    }

    pub(crate) fn is_complete(self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    pub(crate) fn dial_failed_all(self) -> bool {
        matches!(
            self,
            Self::Complete {
                dial_failed_all: true
            }
        )
    }
}

pub(crate) fn catch_up_after_ok(accepted: u32, tip: u32, shutdown: bool) -> CatchUp {
    if shutdown || (tip == 0 && accepted == 0) {
        CatchUp::Incomplete
    } else {
        CatchUp::complete()
    }
}

pub(crate) fn catch_up_after_err(tip: u32, index_is_tip: bool, shutdown: bool) -> CatchUp {
    if !shutdown && tip > 0 && index_is_tip {
        CatchUp::complete_dial_failed()
    } else {
        CatchUp::Incomplete
    }
}

fn apply_startup_index_mode(
    query: &Query,
    config: &NodeConfig,
    taproot_height: u32,
) -> Result<(), NodeError> {
    query.set_sh_index_enabled(config.shindex);
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
             (skip Class A recollect; catch-up uses write-behind)"
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

async fn run_ibd_or_skip(
    node: &P2PNode,
    ibd_targets: &[SocketAddr],
    max_out: usize,
    shared_peers: &std::sync::Arc<std::sync::Mutex<AddrMan>>,
    addrman: &mut AddrMan,
    peers_path: &std::path::Path,
    shutdown: &Shutdown,
) -> CatchUp {
    if ibd_targets.is_empty() {
        info!("ibd: no outbound peers; serving only (use --connect or seeds)");
        return CatchUp::complete();
    }
    if shutdown.requested() {
        return CatchUp::Incomplete;
    }
    let target_peers = max_out.clamp(8, 32);
    let ibd_cfg = IbdConfig {
        window: rbitcoin_net::DEFAULT_IBD_WINDOW,
        per_peer: rbitcoin_net::DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER,
        target_peers,
        // 5s caused reassign storms (clearing 200+ inflight before peers
        // could deliver mid-chain blocks). Default 30s is enough.
        stall: std::time::Duration::from_secs(30),
        peers: Some(std::sync::Arc::clone(shared_peers)),
        ..IbdConfig::default()
    };
    info!(
        "ibd: catch-up candidates={} target_peers={} (window={}, per_peer={})…",
        ibd_targets.len(),
        ibd_cfg.target_peers,
        ibd_cfg.window,
        ibd_cfg.per_peer
    );
    // Cooperative cancel only: IBD polls `shutdown.flag` and exits its own
    // teardown path. Do **not** `select!`+drop the IBD future on SIGINT —
    // that used to drop a nested multi-thread runtime mid-async and panic
    // (`Cannot drop a runtime in an async context`), making Ctrl+C slow/noisy.
    let cancel = Some(Arc::clone(&shutdown.flag));
    let catch_up = match node.sync_cancellable(ibd_targets, ibd_cfg, cancel).await {
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
                if tip > 0 && node.hub.query.index_mode().is_tip() {
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
                node.hub.query.index_mode().is_tip(),
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

fn spawn_hub_tip_bridge<T, F>(
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

fn electrum_tip_notify(ev: TipEvent) -> Option<TipNotify> {
    let mut buf = Vec::with_capacity(80);
    if ev.header.consensus_encode(&mut buf).is_err() {
        return None;
    }
    Some(TipNotify {
        height: ev.height,
        header_hex: rbitcoin_primitives::hex_encode(buf),
        reorg_from_height: if ev.reorg_branch_len > 0 {
            Some(ev.height.saturating_sub(ev.reorg_branch_len))
        } else {
            None
        },
    })
}

async fn start_electrum_if_ready(
    sh_tip_ready: bool,
    addr: Option<SocketAddr>,
    tweaks_min_dust: u64,
    shutdown: &Shutdown,
    hub: &ChainHub,
    params: &rbitcoin_consensus::ChainParams,
    mempool: &std::sync::Arc<MempoolHub>,
) -> (Vec<ElectrumHandle>, Option<tokio::task::JoinHandle<()>>) {
    let Some(addr) = addr else {
        return (Vec::new(), None);
    };
    if !sh_tip_ready || shutdown.requested() {
        return (Vec::new(), None);
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
    ecfg.tweaks_min_dust = tweaks_min_dust;
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
            (vec![h], Some(bridge))
        }
        Err(e) => {
            warn!("electrum TCP start warning: {e}");
            (Vec::new(), Some(bridge))
        }
    }
}

async fn start_esplora_if_ready(
    sh_tip_ready: bool,
    addr: Option<SocketAddr>,
    network: Network,
    shutdown: &Shutdown,
    hub: &ChainHub,
    mempool: &std::sync::Arc<MempoolHub>,
) -> (Vec<EsploraHandle>, Option<tokio::task::JoinHandle<()>>) {
    let Some(addr) = addr else {
        return (Vec::new(), None);
    };
    if !sh_tip_ready || shutdown.requested() {
        return (Vec::new(), None);
    }
    let q = hub.query.clone();
    let btc_net = match network {
        rbitcoin_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        rbitcoin_primitives::Network::Testnet => bitcoin::Network::Testnet,
        rbitcoin_primitives::Network::Signet => bitcoin::Network::Signet,
        rbitcoin_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let (esplora_tip_tx, _) = broadcast::channel::<TipEvent>(64);
    let hub_tips = hub.subscribe_tips();
    let bridge = spawn_hub_tip_bridge(
        hub_tips,
        esplora_tip_tx.clone(),
        Arc::clone(&shutdown.flag),
        Some,
    );
    let ecfg = EsploraConfig::with_network(addr, btc_net);
    let max_conn = ecfg.limits.max_connections;
    let max_body = ecfg.limits.max_request_bytes;
    let idle_secs = ecfg.limits.idle_timeout.as_secs();
    let max_ws = ecfg.max_ws_connections;
    match run_esplora(ecfg, q, Some(Arc::clone(mempool)), Some(esplora_tip_tx)).await {
        Ok(h) => {
            info!(
                "esplora HTTP+WS on {} (REST + /v1/ws; max_conn={} max_body={} idle={}s max_ws={}; TLS via reverse proxy if public)",
                h.local_addr, max_conn, max_body, idle_secs, max_ws
            );
            (vec![h], Some(bridge))
        }
        Err(e) => {
            warn!("esplora HTTP start warning: {e}");
            (Vec::new(), Some(bridge))
        }
    }
}

/// Result of post-IBD tip entry: follow/mempool gates vs Electrum SH gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TipModeGates {
    /// Class A + spends ready: follow peers, tip loop, mempool tip-relay.
    pub tip_follow_ready: bool,
    /// Durable SH tip-ready: Electrum / Esplora may start.
    pub sh_tip_ready: bool,
}

/// Enter steady-state after true catch-up.
///
/// **Preconditions (enforced by IBD, not repaired here):** Direct catch-up already
/// wrote durable **`tx.head`** (archive) and **spend annotations** (confirm).
/// Incomplete IBD must not call this (`CatchUp::Complete` only after full horizon).
///
/// **SH methods (exactly two):**
/// - Durable head: stay/flip [`IndexMode::Tip`], discard leftover runs, Electrum
///   on (`sh_tip_ready`); catch-up / follow use write-behind.
/// - No head: Class A collect + unsorted pack **while Direct** (write-behind
///   no-ops), then Tip. Cancel leaves Direct; Electrum stays closed.
///
/// **When `!shindex`:** skip SH; `sh_tip_ready = false`; Tip for follow/relay.
pub(crate) fn enter_tip_mode(
    query: &Query,
    cancel: Option<Arc<AtomicBool>>,
    shindex: bool,
) -> TipModeGates {
    query.set_sh_index_enabled(shindex);

    if !shindex {
        query.enter_tip_index_mode();
        info!(
            "node: IndexMode::Tip (tx.head + spend annotations already live) mode={:?}",
            query.index_mode()
        );
        info!("node: tip-follow ready without scripthash (shindex off); Electrum/Esplora disabled");
        return TipModeGates {
            tip_follow_ready: true,
            sh_tip_ready: false,
        };
    }

    if query.sh_use_writebehind() {
        query.enter_tip_index_mode();
        info!(
            "node: IndexMode::Tip (tx.head + spend annotations already live) mode={:?}",
            query.index_mode()
        );
        match query.finalize_sh_runs_cancellable(cancel.as_deref()) {
            Ok(_) => {}
            Err(e) => warn!("node: scripthash leftover-run discard: {e}"),
        }
        info!(
            "node: scripthash write-behind — skip collect; rows={}",
            query.scripthash_entry_count()
        );
        info!("node: tip-mode complete — safe to start Electrum");
        return TipModeGates {
            tip_follow_ready: true,
            sh_tip_ready: true,
        };
    }

    info!("node: scripthash bulk materialize from Class A (Direct collect, then Tip)…");
    if !query.index_mode().is_direct() {
        if let Err(e) = query.enter_direct_index_mode_sh(true) {
            warn!("node: enter Direct for SH collect: {e}");
        }
    }
    let cancel_ref = cancel.as_deref();
    let sh_ok = match query.finalize_sh_runs_cancellable(cancel_ref) {
        Ok(n) => {
            info!("node: scripthash bulk materialize creates≈{n}");
            true
        }
        Err(StoreError::Cancelled(msg)) => {
            warn!("node: scripthash bulk materialize cancelled ({msg})");
            warn!(
                "node: partial cold shards kept (scripthash.cold_progress) — \
                 restart to resume; Electrum not ready yet (stay Direct; tip follow on)"
            );
            false
        }
        Err(e) => {
            warn!("node: scripthash bulk materialize failed: {e}");
            warn!(
                "node: Electrum history incomplete until materialize succeeds — \
                 keep store/scripthash.runs (incl. *.run.mat / merge/) and restart; \
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
        query.index_mode()
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
    info!("node: tip-mode complete — safe to start Electrum");
    TipModeGates {
        tip_follow_ready: true,
        sh_tip_ready: true,
    }
}

/// Production IBD knobs for a single-peer catch-up retry (stale tip, incomplete catch-up).
///
/// Uses [`IbdConfig::default`] (window 1024, stall 30s, connect 8s, …) — not
/// [`IbdConfig::for_test`], which is only for unit/integration test harnesses.
fn catch_up_retry_config(peers: std::sync::Arc<std::sync::Mutex<AddrMan>>) -> IbdConfig {
    IbdConfig {
        target_peers: 1,
        peers: Some(peers),
        ..IbdConfig::default()
    }
}

/// Tip-follow supervisor wake. A 5s perf tick or 50ms RPC-stop tick must not
/// skip the stale-tip extra-outbound check (mainnet 962723 sat 3h after the
/// last follow peer died because a one-shot 60s sleep was reset every wake).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TipFollowWakeKind {
    TipChanged,
    TipSame,
    Perf,
    Poll,
    RpcStop,
    Stop,
}

/// One `select!` result from [`tip_follow_next_wake`].
pub(crate) enum TipFollowWake {
    Tip(TipEvent),
    Poll,
    Perf,
    RpcStop,
    Stop,
}

/// Classify a wake against the last logged tip height.
pub(crate) fn tip_follow_wake_kind(wake: &TipFollowWake, last_tip: u32) -> TipFollowWakeKind {
    match wake {
        TipFollowWake::Stop => TipFollowWakeKind::Stop,
        TipFollowWake::Perf => TipFollowWakeKind::Perf,
        TipFollowWake::Poll => TipFollowWakeKind::Poll,
        TipFollowWake::RpcStop => TipFollowWakeKind::RpcStop,
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
pub(crate) fn load_asmap(datadir: &Path, configured: Option<&Path>) -> Option<Arc<AsMap>> {
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

/// `--connect` is operator-pinned: no netgroup filter. Otherwise rank + diversity.
pub(crate) fn follow_dial_targets(
    connect: &[SocketAddr],
    book: &AddrMan,
    max: usize,
    occupied: &[SocketAddr],
) -> Vec<SocketAddr> {
    if !connect.is_empty() {
        connect.to_vec()
    } else {
        book.take_outbound_occupied(max, occupied)
    }
}

/// Whether this wake should run the stale-tip redial check.
///
/// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale. A one-shot
/// `sleep` in the same `select!` is reset on every such wake and never fires.
pub(crate) fn stale_follow_needs_room(follow_live: usize, max_outbound: usize) -> bool {
    follow_live >= max_outbound.max(1)
}

pub(crate) fn tip_follow_checks_stale(kind: TipFollowWakeKind) -> bool {
    matches!(
        kind,
        TipFollowWakeKind::Perf
            | TipFollowWakeKind::Poll
            | TipFollowWakeKind::RpcStop
            | TipFollowWakeKind::TipSame
    )
}

/// One supervisor wake. `stale` must be a **persistent** interval, not a
/// one-shot sleep created inside the loop (that sleep restarts on every
/// faster tick and never completes).
pub(crate) async fn tip_follow_next_wake(
    shutdown: impl std::future::Future<Output = ()>,
    rpc_stop: Option<&mut tokio::time::Interval>,
    perf: &mut tokio::time::Interval,
    tip_rx: &mut broadcast::Receiver<TipEvent>,
    stale: &mut tokio::time::Interval,
) -> TipFollowWake {
    tokio::select! {
        biased;
        _ = shutdown => TipFollowWake::Stop,
        _ = async {
            match rpc_stop {
                Some(tick) => {
                    tick.tick().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => TipFollowWake::RpcStop,
        _ = perf.tick() => TipFollowWake::Perf,
        ev = tip_rx.recv() => match ev {
            Ok(e) => TipFollowWake::Tip(e),
            Err(broadcast::error::RecvError::Lagged(_)) => TipFollowWake::Poll,
            Err(broadcast::error::RecvError::Closed) => TipFollowWake::Stop,
        },
        _ = stale.tick() => TipFollowWake::Poll,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rbitcoin_query::testutil::FixtureChain;
    fn tiny_regtest(dir: impl AsRef<std::path::Path>) -> NodeConfig {
        NodeConfig::default()
            .with_datadir(dir.as_ref())
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_tiny_heads()
    }

    /// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale redial.
    /// A one-shot sleep in the same `select!` is reset on every such wake.
    #[test]
    fn stale_follow_needs_room_at_max_outbound() {
        assert!(!stale_follow_needs_room(0, 16));
        assert!(!stale_follow_needs_room(15, 16));
        assert!(stale_follow_needs_room(16, 16));
        assert!(stale_follow_needs_room(31, 16));
        assert!(stale_follow_needs_room(1, 1));
        assert!(!stale_follow_needs_room(0, 1));
    }

    #[test]
    fn follow_dial_targets_connect_bypasses_diversity() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let mut am = AddrMan::new();
        am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
        am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 0, 1)), 8333));
        let connect = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8333,
        )];
        let occupied = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)), 8333)];
        assert_eq!(follow_dial_targets(&connect, &am, 8, &occupied), connect);
    }

    #[test]
    fn follow_dial_targets_skips_occupied_group() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let mut am = AddrMan::new();
        let same = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333);
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 3, 0, 1)), 8333);
        am.add(same);
        am.add(other);
        let occupied = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)), 8333)];
        let got = follow_dial_targets(&[], &am, 1, &occupied);
        assert_eq!(got, vec![other]);
    }

    #[test]
    fn load_asmap_missing_configured_is_none() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-asmap-miss-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_asmap(&dir, Some(Path::new("no-such-asmap"))).is_none());
        assert!(load_asmap(&dir, None).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_asmap_valid_tiny_file() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-asmap-ok-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ip_asn.dat");
        std::fs::write(&path, rbitcoin_net::TWO_PREFIX_ASMAP).unwrap();
        let m = load_asmap(&dir, None).expect("default ip_asn.dat");
        assert_eq!(
            m.mapped_as(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 0, 0))),
            1
        );
        let rel = load_asmap(&dir, Some(Path::new("ip_asn.dat"))).expect("relative asmap");
        assert_eq!(rel.len(), m.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_asmap_truncated_is_none() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-asmap-bad-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.dat");
        std::fs::write(&path, [0u8]).unwrap();
        assert!(load_asmap(&dir, Some(path.as_path())).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_follow_checks_stale_on_perf_and_rpc_stop() {
        assert!(
            tip_follow_checks_stale(TipFollowWakeKind::Perf),
            "5s tip:perf tick must still consider a stale extra outbound"
        );
        assert!(
            tip_follow_checks_stale(TipFollowWakeKind::RpcStop),
            "RPC-stop tick must still consider a stale extra outbound"
        );
        assert!(tip_follow_checks_stale(TipFollowWakeKind::Poll));
        assert!(tip_follow_checks_stale(TipFollowWakeKind::TipSame));
        assert!(!tip_follow_checks_stale(TipFollowWakeKind::TipChanged));
        assert!(!tip_follow_checks_stale(TipFollowWakeKind::Stop));
    }

    #[test]
    fn parse_blockmintxfee_btc_to_sat() {
        assert_eq!(parse_btc_to_sat("0.00000001"), Ok(1));
        assert_eq!(parse_btc_to_sat("0"), Ok(0));
        assert_eq!(parse_btc_to_sat("0.025"), Ok(2_500_000));
        assert_eq!(parse_btc_to_sat("0.00000005"), Ok(5));
        assert_eq!(parse_btc_to_sat("-0.0001"), Err("must be non-negative"));
        assert_eq!(parse_btc_to_sat("nope"), Err("invalid"));
    }

    /// Persistent stale interval must complete even when a faster perf tick
    /// is in the same biased `select!` (the old one-shot sleep never did).
    #[tokio::test]
    async fn stale_interval_fires_alongside_faster_perf_tick() {
        let mut perf = tokio::time::interval(Duration::from_millis(15));
        perf.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        perf.tick().await;
        let mut stale = tokio::time::interval(Duration::from_millis(50));
        stale.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stale.tick().await;
        let (_tx, mut tip_rx) = broadcast::channel::<TipEvent>(8);
        let start = Instant::now();
        let mut saw_poll = false;
        while start.elapsed() < Duration::from_millis(200) {
            let w = tokio::time::timeout(
                Duration::from_millis(250),
                tip_follow_next_wake(
                    std::future::pending(),
                    None,
                    &mut perf,
                    &mut tip_rx,
                    &mut stale,
                ),
            )
            .await
            .expect("supervisor wake");
            if matches!(w, TipFollowWake::Poll) {
                saw_poll = true;
                break;
            }
        }
        assert!(
            saw_poll,
            "stale interval must produce Poll while perf ticks every 15ms"
        );
    }

    #[test]
    fn catch_up_ok_genesis_zero_accepts_is_incomplete() {
        assert_eq!(catch_up_after_ok(0, 0, false), CatchUp::Incomplete);
        assert_eq!(catch_up_after_ok(3, 3, true), CatchUp::Incomplete);
    }

    #[test]
    fn catch_up_ok_with_blocks_is_complete() {
        assert_eq!(
            catch_up_after_ok(3, 3, false),
            CatchUp::Complete {
                dial_failed_all: false
            }
        );
        assert_eq!(
            catch_up_after_ok(0, 1, false),
            CatchUp::Complete {
                dial_failed_all: false
            }
        );
        assert!(CatchUp::complete().is_complete());
        assert!(!CatchUp::complete().dial_failed_all());
        assert!(!CatchUp::Incomplete.is_complete());
    }

    #[test]
    fn catch_up_err_with_tip_indexes_dials_failed() {
        assert_eq!(
            catch_up_after_err(10, true, false),
            CatchUp::Complete {
                dial_failed_all: true
            }
        );
        assert!(CatchUp::complete_dial_failed().dial_failed_all());
        assert_eq!(catch_up_after_err(10, false, false), CatchUp::Incomplete);
        assert_eq!(catch_up_after_err(0, true, false), CatchUp::Incomplete);
        assert_eq!(catch_up_after_err(10, true, true), CatchUp::Incomplete);
    }

    #[test]
    fn catch_up_retry_config_uses_production_not_for_test() {
        let peers = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::AddrMan::new()));
        let cfg = catch_up_retry_config(std::sync::Arc::clone(&peers));
        let prod = IbdConfig::default();
        let test = IbdConfig::for_test();

        assert_eq!(cfg.target_peers, 1);
        assert!(cfg.peers.is_some());
        // Production class (main catch-up path), not for_test knobs.
        assert_eq!(cfg.window, prod.window);
        assert_eq!(cfg.window, rbitcoin_net::DEFAULT_IBD_WINDOW);
        assert_eq!(cfg.per_peer, prod.per_peer);
        assert_eq!(cfg.stall, prod.stall);
        assert_eq!(cfg.connect_timeout, prod.connect_timeout);
        assert_eq!(cfg.headers_batch, prod.headers_batch);
        // Guard against reintroducing for_test() base fields.
        assert_ne!(cfg.window, test.window);
        assert_ne!(cfg.stall, test.stall);
        assert_ne!(cfg.connect_timeout, test.connect_timeout);
    }

    #[test]
    fn custom_signet_does_not_use_default_signet_seeds() {
        let mut cfg = NodeConfig::default().with_network(rbitcoin_primitives::Network::Signet);
        assert!(should_resolve_default_seeds(&cfg));
        cfg.signet_challenge = Some(bitcoin::ScriptBuf::from_bytes(vec![0x51]));
        assert!(!should_resolve_default_seeds(&cfg));
    }

    fn coinbase_block(
        h: u32,
        prev: rbitcoin_primitives::Fk,
        parent_hash: Option<[u8; 32]>,
    ) -> (rbitcoin_store::HeaderRecord, rbitcoin_query::TxApply) {
        use rbitcoin_primitives::Fk;
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[4] = 0xcd;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51, h as u8])],
        };
        (header, ta)
    }

    fn seed_direct_chain(q: &Query, n: u32) {
        use rbitcoin_primitives::{Fk, Height};
        q.enter_direct_index_mode().unwrap();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..n {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
    }

    #[test]
    fn enter_tip_mode_reenables_indexes() {
        use rbitcoin_query::IndexMode;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-mode-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        q.enter_direct_index_mode().unwrap();
        assert_eq!(q.index_mode(), IndexMode::Direct);
        assert!(q.spend_index_enabled());
        assert!(q.tx_index_enabled());

        let g = enter_tip_mode(&q, None, true);
        assert!(g.tip_follow_ready);
        // Empty store: SH not "tip-ready" by watermark metric, but follow is on.
        assert_eq!(q.index_mode(), IndexMode::Tip);
        assert!(q.spend_index_enabled());
        assert!(q.tx_index_enabled());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Durable head + lagging HWM: enter_tip_mode must not collect; Electrum on.
    #[test]
    fn enter_tip_mode_durable_head_hwm_lag_writebehind() {
        use rbitcoin_query::IndexMode;
        use rbitcoin_store::{next_run_path, write_sorted_run};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-wb-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("store");
        let q = Query::open_or_create_tiny(&store).unwrap();
        seed_direct_chain(&q, 5);
        assert_eq!(q.index_mode(), IndexMode::Direct);
        let _ = q.finalize_sh_runs().unwrap();
        assert!(q.sh_use_writebehind());
        let count_before = q.scripthash_entry_count();
        let tip_max = q.store().txs.count();
        let lag = tip_max.saturating_sub(2).max(1);
        std::fs::write(
            store.join(rbitcoin_store::INCLUDE_HWM_NAME),
            lag.to_le_bytes(),
        )
        .unwrap();

        let runs_dir = store.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut body = Vec::new();
        let mut rec = [0u8; 40];
        rec[..32].fill(0xee);
        rec[32..40].copy_from_slice(&99u64.to_le_bytes());
        body.extend_from_slice(&rec);
        write_sorted_run(&next_run_path(&runs_dir, 50), 40, 40, &body).unwrap();

        let g = enter_tip_mode(&q, None, true);
        assert!(g.tip_follow_ready);
        assert!(
            g.sh_tip_ready,
            "durable head chooses write-behind; Electrum must not wait on HWM==tip"
        );
        assert_eq!(q.index_mode(), IndexMode::Tip);
        assert_eq!(q.scripthash_entry_count(), count_before);
        assert_eq!(q.scripthash_run_count(), 0);
        assert_eq!(q.store().scripthash.include_hwm(), lag);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// First-time SH: collect while Direct, then Tip.
    #[test]
    fn enter_tip_mode_collects_while_direct_then_tip() {
        use rbitcoin_query::IndexMode;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-collect-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        seed_direct_chain(&q, 4);
        assert_eq!(q.index_mode(), IndexMode::Direct);
        assert!(!q.store().scripthash.has_durable_index());
        assert!(!q.sh_use_writebehind());

        let g = enter_tip_mode(&q, None, true);
        assert!(g.tip_follow_ready);
        assert!(g.sh_tip_ready);
        assert_eq!(q.index_mode(), IndexMode::Tip);
        assert!(q.store().scripthash.has_durable_index());
        assert_eq!(q.scripthash_run_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_tip_mode_shindex_off_skips_sh_and_enables_follow() {
        use rbitcoin_query::IndexMode;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-nosh-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        q.enter_direct_index_mode_sh(false).unwrap();
        assert!(!q.sh_index_enabled());
        assert!(!q.sh_run_enabled());

        let g = enter_tip_mode(&q, None, false);
        assert!(g.tip_follow_ready, "tip follow must not wait on SH");
        assert!(
            !g.sh_tip_ready,
            "Electrum gate stays closed without shindex"
        );
        assert_eq!(q.index_mode(), IndexMode::Tip);
        assert!(!q.sh_index_enabled());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_tip_mode_disable_after_on_leaves_sh_tables() {
        use rbitcoin_query::IndexMode;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-sh-off-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("store");
        let q = Query::open_or_create_tiny(&store).unwrap();
        q.enter_direct_index_mode_sh(true).unwrap();
        assert!(q.sh_index_enabled());
        let on = enter_tip_mode(&q, None, true);
        assert!(on.tip_follow_ready);
        let sh_body = store.join("scripthash.body");
        assert!(
            sh_body.is_file() || sh_body.join("00").is_file(),
            "tip SH materialize must leave a body"
        );

        let off = enter_tip_mode(&q, None, false);
        assert!(off.tip_follow_ready, "follow stays on after disable");
        assert!(!off.sh_tip_ready, "Electrum gate closes when shindex off");
        assert!(!q.sh_index_enabled());
        assert_eq!(q.index_mode(), IndexMode::Tip);
        assert!(
            sh_body.is_file() || sh_body.join("00").is_file(),
            "disable must not purge SH tables"
        );

        let again = enter_tip_mode(&q, None, true);
        assert!(again.tip_follow_ready);
        assert!(q.sh_index_enabled());
        assert!(sh_body.is_file() || sh_body.join("00").is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shutdown_flag_and_node_handle_smoke() {
        let sd = Shutdown::new();
        assert!(!sd.requested());
        sd.request();
        assert!(sd.requested());
        // Second request is idempotent.
        sd.request();
        assert!(sd.requested());

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-node-{nanos}"));
        let cfg = tiny_regtest(&dir);
        let handle = run_node(cfg).expect("run_node");
        assert_eq!(handle.network_name(), "regtest");
        assert_eq!(
            handle.query.store().headers.head_target_slots(),
            64,
            "tiny_regtest must create Tiny header heads"
        );
        assert!(handle.mempool.is_none());
        let _ = format!("{:?}", handle);
        handle.shutdown().expect("shutdown flush");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_no_peers_exits_after_catchup() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.max_run_secs = Some(0); // exit after catch-up / tip mode
        cfg.smoke = false;
        // Bound runtime so a hang fails the test suite instead of blocking.
        // max_run_secs=0 should exit immediately after catch-up; keep bound tight.
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("run_p2p ok with no peers");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancelled_completes_after_request() {
        let sd = Shutdown::new();
        // Already-requested path returns immediately.
        sd.request();
        sd.cancelled().await;

        let sd2 = Shutdown::new();
        let s2 = Arc::clone(&sd2);
        let j = tokio::spawn(async move {
            s2.cancelled().await;
        });
        // Give the task a chance to park on notify.
        tokio::task::yield_now().await;
        sd2.request();
        j.await.unwrap();
    }

    #[tokio::test]
    async fn run_p2p_milestone_and_electrum() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-el-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.milestone_height = 100; // exercise milestone log branch
        cfg.shindex = true;
        cfg.listen.electrum = Some("127.0.0.1:0".parse().unwrap());
        // max_run_secs=0 exits after catch-up/tip (tip-follow loop uses 60s poll sleeps).
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("run_p2p with electrum");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_with_esplora_listen() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-esp-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.shindex = true;
        cfg.listen.esplora = Some("127.0.0.1:0".parse().unwrap());
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("run_p2p with esplora");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_bad_connect_peer_still_exits() {
        // Explicit dead --connect so IBD/follow attempts are exercised, then exit.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-conn-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        // Blackhole / closed port: connect fails fast under FOLLOW_CONNECT_SECS.
        cfg.listen.connect = vec!["127.0.0.1:1".parse().unwrap()];
        cfg.max_run_secs = Some(0);
        // Dead connect should fail fast (FOLLOW_CONNECT_SECS); 20s bound for hang detection.
        let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        // Incomplete IBD is ok (warn path); should not hang.
        let _ = result.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_missing_asmap_still_starts() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-asmap-miss-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.asmap = Some(dir.join("no-such-asmap"));
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("missing asmap must not panic");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_valid_asmap_starts() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-asmap-ok-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ip_asn.dat"), rbitcoin_net::TWO_PREFIX_ASMAP).unwrap();
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("valid asmap start");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_tip_mode_warns_on_leftover_runs_dir() {
        use rbitcoin_query::IndexMode;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-tip-leftover-{nanos}"));
        std::fs::create_dir_all(dir.join("store")).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        q.enter_direct_index_mode().unwrap();
        // Empty store: finalize has no runs; still flips to tip.
        let g = enter_tip_mode(&q, None, true);
        assert!(g.tip_follow_ready);
        assert_eq!(q.index_mode(), IndexMode::Tip);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_handle_shutdown_with_mempool() {
        use rbitcoin_net::MempoolHub;
        use std::sync::Arc;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-handle-mp-{nanos}"));
        let cfg = tiny_regtest(&dir);
        let mut handle = run_node(cfg).expect("run_node");
        // Dual-open same store for MempoolHub's Arc<Query> (flush only).
        // Same layout as run_node — Tiny here, Mainnet would mismatch.
        let q = Arc::new(Query::open_or_create_layout(handle.config.store_layout()).unwrap());
        let mp = MempoolHub::open(handle.config.mempool_path(), q).expect("mempool");
        handle.mempool = Some(mp);
        let _ = format!("{:?}", handle);
        handle.shutdown().expect("flush query+mempool");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_with_peers_file_and_electrum() {
        use rbitcoin_net::AddrMan;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-peers-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        // Non-empty peers book so load path logs address count.
        let mut am = AddrMan::new();
        am.add("127.0.0.1:18444".parse().unwrap());
        am.add("127.0.0.1:18445".parse().unwrap());
        am.save(&dir.join("peers")).unwrap();

        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        // Peers file is loaded for bookkeeping; do not dial those addrs as --connect
        // (would stall IBD). Empty connect + no seeds → catch-up complete immediately.
        cfg.listen.connect.clear();
        cfg.max_run_secs = Some(0);
        cfg.shindex = true;
        cfg.listen.electrum = Some("127.0.0.1:0".parse().unwrap());
        cfg.milestone_height = 50;
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("run_p2p peers+electrum");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_p2p_corrupt_peers_and_dead_connect() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-badpeers-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        // Corrupt peers file → load error branch starts empty book.
        std::fs::write(dir.join("peers"), b"not-a-valid-peers-blob\xff\x00").unwrap();

        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect = vec!["127.0.0.1:1".parse().unwrap()];
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        let _ = result.unwrap(); // incomplete IBD ok
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancelled_waits_for_request_race() {
        // Cover the while !requested re-check after spurious notify.
        let sd = Shutdown::new();
        let s = Arc::clone(&sd);
        let j = tokio::spawn(async move {
            s.cancelled().await;
        });
        tokio::task::yield_now().await;
        // Double request is idempotent; first wakes waiters.
        sd.request();
        sd.request();
        j.await.unwrap();
    }

    /// `use_seeds=true` on regtest resolves empty seed set (covers seed inject path).
    #[tokio::test]
    async fn run_p2p_use_seeds_regtest_empty() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-seeds-{nanos}"));
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = true; // regtest: resolve_all_seeds → empty
        cfg.listen.connect.clear();
        cfg.max_run_secs = Some(0);
        cfg.milestone_height = 1; // log milestone branch
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        result.unwrap().expect("run_p2p seeds regtest");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Electrum bind failure (port already taken / invalid) → warn path, still exits.
    #[tokio::test]
    async fn run_p2p_electrum_bind_fail_warns() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-el-fail-{nanos}"));
        // Hold a port so electrum bind fails.
        let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = held.local_addr().unwrap();
        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.shindex = true;
        cfg.listen.electrum = Some(addr); // already bound → fail
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        // Bind fail is non-fatal warn; run should still complete.
        result.unwrap().expect("run_p2p despite electrum fail");
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Parse Core `-seednode` host or host:port using the chain default P2P port.
fn resolve_seednode(raw: &str, network: Network) -> Result<SocketAddr, String> {
    if let Ok(a) = raw.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: std::net::IpAddr = raw
        .parse()
        .map_err(|e| format!("bad seednode address: {e}"))?;
    Ok(SocketAddr::new(ip, default_port(network)))
}
