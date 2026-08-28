use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::regtest_rpc::HubRegtest;
use bitcoin::consensus::Encodable;
use rbitcoin_electrum::{run_electrum, ElectrumConfig, TipNotify};
use rbitcoin_esplora::{run_esplora, EsploraConfig};
use rbitcoin_log::{debug, enabled, info, warn, Level};
use rbitcoin_net::{
    default_port, format_tip_perf_sizes, read_proc_rss, AddrMan, IbdConfig, MempoolHub, P2PNode,
    TipEvent, TipPerfSizes,
};
use rbitcoin_primitives::Network;
use rbitcoin_query::{spawn_sh_writebehind, Query};
use rbitcoin_rpc::{run_rpc, RpcConfig, RpcHandle, RpcRegtest};
use rbitcoin_store::StoreError;
use std::net::SocketAddr;
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

/// Parse Core BTC/kvB (`0.00000001`) to sat/kvB.
fn parse_btc_to_sat(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, rest) = s.strip_prefix('-').map(|r| (true, r)).unwrap_or((false, s));
    if neg {
        return Some(0);
    }
    let (whole_s, frac_s) = match rest.split_once('.') {
        Some((w, f)) => (w, f),
        None => (rest, ""),
    };
    if whole_s.is_empty() && frac_s.is_empty() {
        return None;
    }
    let whole: u64 = if whole_s.is_empty() {
        0
    } else {
        whole_s.parse().ok()?
    };
    let mut frac = frac_s.to_string();
    if frac.len() > 8 {
        frac.truncate(8);
    }
    while frac.len() < 8 {
        frac.push('0');
    }
    let frac_n: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    Some(whole.saturating_mul(100_000_000).saturating_add(frac_n))
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
    // Restart: durable SH head stays Tip (write-behind catch-up). Else Direct
    // IBD with SH deferred until post-horizon Class A collect.
    handle.query.set_sh_index_enabled(config.shindex);
    if let Err(e) = handle.query.set_sptweaks_enabled(
        config.sptweaks,
        rbitcoin_primitives::Height(params.taproot_height()),
    ) {
        warn!("sp_tweaks: enable failed: {e}");
    } else if config.sptweaks {
        info!("sp_tweaks: enabled origin={}", params.taproot_height());
    }
    if config.shindex && handle.query.sh_use_writebehind() {
        let _ = handle.query.sync_sh_seal_from_include_hwm();
        handle.query.enter_tip_index_mode();
        info!(
            "node: durable scripthash head — resume IndexMode::Tip \
             (skip Class A recollect; catch-up uses write-behind)"
        );
    } else {
        handle
            .query
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
    let listen = config
        .p2p_listen
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], default_port(config.network))));

    let start_tip = handle.query.tip_height().map(|h| h.0).unwrap_or(0);
    let run_started = Instant::now();
    info!(
        "rbitcoin-node starting version={} network={} datadir={}{} tip={start_tip} io={}",
        env!("CARGO_PKG_VERSION"),
        config.network.as_str(),
        config.datadir.display(),
        config
            .datadir_cold
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
        config.max_inbound as usize,
    )
    .await
    .map_err(|e| NodeError::Config(format!("p2p start: {e}")))?;
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
            Some(sat) => node.hub.set_block_min_tx_fee_sat_kvb(sat),
            None => {
                return Err(NodeError::Config(format!("bad --blockmintxfee {s}")));
            }
        }
    }

    let mempool = MempoolHub::open_with_weight_persist(
        config.mempool_path(),
        node.hub.query.clone(),
        config.mempool_max_weight,
        config.persist_mempool,
    )
    .map_err(|e| NodeError::Config(e))?;
    mempool.set_cluster_limits(config.limit_cluster_count, config.limit_cluster_size_kvb);
    if config.whitelist.iter().any(|w| w.contains("noban")) {
        mempool.set_immediate_relay(true);
        node.peers.set_noban(true);
    }
    if config.whitelist.iter().any(|w| w.contains("relay")) {
        node.peers.set_relay_perm(true);
    }
    if let Some(s) = config.min_relay_fee_btc.as_deref() {
        if let Some(sat) = parse_btc_to_sat(s) {
            mempool.set_min_relay_sat_kvb(sat);
        }
    }
    node.hub
        .attach_mempool(mempool.clone())
        .map_err(|_| NodeError::Config("mempool already attached".into()))?;
    info!(
        "mempool: open {} gen={} live={} max_weight={} (relay off until tip mode)",
        config.mempool_path().display(),
        mempool.generation(),
        mempool.live_count(),
        config.mempool_max_weight
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

    let peers_path = config.datadir.join("peers");
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
    for c in &config.connect {
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
    } else if config.signet_challenge.is_some() && config.connect.is_empty() && addrman.is_empty() {
        warn!("custom signet has no peers; use --connect ADDR or reuse a datadir with known peers");
    }
    let shared_peers = std::sync::Arc::new(std::sync::Mutex::new(addrman.clone()));

    let max_out = config.max_outbound.max(1) as usize;
    let candidate_n = max_out.saturating_mul(2).clamp(16, 48);
    let targets = if !config.connect.is_empty() {
        config.connect.clone()
    } else {
        addrman.take_outbound(max_out)
    };

    let ibd_targets = if !config.connect.is_empty() {
        config.connect.clone()
    } else {
        addrman.take_outbound(candidate_n)
    };
    // True only after IBD reports true catch-up (or no peers to dial).
    // Mid-chain peer death must not enter tip mode (materialize durable indexes).
    let mut catch_up_complete = ibd_targets.is_empty();
    if !ibd_targets.is_empty() && !shutdown.requested() {
        let target_peers = max_out.clamp(8, 32);
        let ibd_cfg = IbdConfig {
            window: rbitcoin_net::DEFAULT_IBD_WINDOW,
            per_peer: rbitcoin_net::DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER,
            target_peers,
            // 5s caused reassign storms (clearing 200+ inflight before peers
            // could deliver mid-chain blocks). Default 30s is enough.
            stall: std::time::Duration::from_secs(30),
            peers: Some(std::sync::Arc::clone(&shared_peers)),
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
        match node.sync_cancellable(&ibd_targets, ibd_cfg, cancel).await {
            Ok(n) => {
                if shutdown.requested() {
                    warn!(
                        "ibd: catch-up interrupted accepted≈{n} tip={:?}",
                        node.tip_height()
                    );
                } else {
                    // IBD only Ok-exits on true catch-up (or cancel). Mid-chain
                    // peer death returns Err so we never materialize tip indexes early.
                    // Defense: never claim complete at genesis tip with zero accepts
                    // (stall-exit regression used to enter tip mode at height 0).
                    let tip = node.tip_height().unwrap_or(0);
                    if tip == 0 && n == 0 {
                        warn!(
                            "ibd: returned ok with tip=0 accepted=0 — treating as incomplete (no tip mode)"
                        );
                        catch_up_complete = false;
                    } else {
                        info!("ibd: catch-up accepted≈{n} tip={:?}", node.tip_height());
                        catch_up_complete = true;
                    }
                }
            }
            Err(e) => {
                if shutdown.requested() {
                    warn!("signal: IBD cancelled ({e})");
                } else {
                    warn!(
                        "ibd: incomplete: {e}; tip={:?} — keeping catch-up indexes (no tip mode; restart to resume)",
                        node.tip_height()
                    );
                }
            }
        }
        if let Ok(g) = shared_peers.lock() {
            addrman = g.clone();
        }
        if let Err(e) = addrman.save(&peers_path) {
            warn!("peers: save {}: {e}", peers_path.display());
        } else {
            info!(
                "peers: saved {} address(es) to {}",
                addrman.len(),
                peers_path.display()
            );
        }
    } else if ibd_targets.is_empty() {
        info!("ibd: no outbound peers; serving only (use --connect or seeds)");
        catch_up_complete = true;
    }

    // Still enter tip-follow when work is below `-minimumchainwork` so later
    // blocks can raise the tip. Relay / getheaders stay gated on the hub floor.
    if catch_up_complete && !tip_meets_min_work(&config, &node.hub) {
        info!("ibd: tip work below -minimumchainwork — following without relay");
    }

    // tip_follow_ready ≠ sh_tip_ready: follow/relay do not wait on SH materialize.
    let mut tip_follow_ready = false;
    let mut sh_tip_ready = false;
    if catch_up_complete && !shutdown.requested() {
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
            if !config.blocksonly && tip_meets_min_work(&config, &node.hub) {
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
    } else if !catch_up_complete && !shutdown.requested() {
        warn!(
            "node: catch-up not complete tip={:?} — skip tip mode; restart to resume IBD",
            node.tip_height()
        );
    }

    if tip_follow_ready && !shutdown.requested() {
        let follow_n = targets.len().min(max_out.min(3));
        const FOLLOW_CONNECT_SECS: u64 = 8;
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

    let mut electrum_handles = Vec::new();
    let mut electrum_bridge = None;
    if sh_tip_ready {
        if let Some(addr) = config.electrum_listen {
            if !shutdown.requested() {
                let q = node.hub.query.clone();
                let (electrum_tip_tx, _) = broadcast::channel::<TipNotify>(64);
                let mut hub_tips = node.hub.subscribe_tips();
                let bridge_tx = electrum_tip_tx.clone();
                let bridge_stop = Arc::clone(&shutdown.flag);
                electrum_bridge = Some(tokio::spawn(async move {
                    loop {
                        if bridge_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        match hub_tips.recv().await {
                            Ok(ev) => {
                                let mut buf = Vec::with_capacity(80);
                                if ev.header.consensus_encode(&mut buf).is_err() {
                                    continue;
                                }
                                let _ = bridge_tx.send(TipNotify {
                                    height: ev.height,
                                    header_hex: rbitcoin_primitives::hex_encode(buf),
                                    reorg_from_height: if ev.reorg_branch_len > 0 {
                                        Some(ev.height.saturating_sub(ev.reorg_branch_len))
                                    } else {
                                        None
                                    },
                                });
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }));
                let ecfg = ElectrumConfig::for_params(addr, &params);
                let max_conn = ecfg.limits.max_connections;
                let max_line = ecfg.limits.max_request_bytes;
                let idle_secs = ecfg.limits.idle_timeout.as_secs();
                match run_electrum(
                    ecfg,
                    q,
                    params.clone(),
                    electrum_tip_tx,
                    Some(mempool.clone()),
                )
                .await
                {
                    Ok(h) => {
                        info!(
                            "electrum TCP on {} (Query + mempool; max_conn={} max_line={} idle={}s; TLS via reverse proxy if public)",
                            h.local_addr, max_conn, max_line, idle_secs
                        );
                        electrum_handles.push(h);
                    }
                    Err(e) => warn!("electrum TCP start warning: {e}"),
                }
            }
        }
    }

    let mut esplora_handles = Vec::new();
    let mut esplora_tip_bridge = None;
    if sh_tip_ready {
        if let Some(addr) = config.esplora_listen {
            if !shutdown.requested() {
                let q = node.hub.query.clone();
                let btc_net = match config.network {
                    rbitcoin_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
                    rbitcoin_primitives::Network::Testnet => bitcoin::Network::Testnet,
                    rbitcoin_primitives::Network::Signet => bitcoin::Network::Signet,
                    rbitcoin_primitives::Network::Regtest => bitcoin::Network::Regtest,
                };
                let (esplora_tip_tx, _) = broadcast::channel::<TipEvent>(64);
                let mut hub_tips = node.hub.subscribe_tips();
                let bridge_tx = esplora_tip_tx.clone();
                let bridge_stop = Arc::clone(&shutdown.flag);
                esplora_tip_bridge = Some(tokio::spawn(async move {
                    loop {
                        if bridge_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        match hub_tips.recv().await {
                            Ok(ev) => {
                                let _ = bridge_tx.send(ev);
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }));
                let ecfg = EsploraConfig::with_network(addr, btc_net);
                let max_conn = ecfg.limits.max_connections;
                let max_body = ecfg.limits.max_request_bytes;
                let idle_secs = ecfg.limits.idle_timeout.as_secs();
                let max_ws = ecfg.max_ws_connections;
                match run_esplora(ecfg, q, Some(mempool.clone()), Some(esplora_tip_tx)).await {
                    Ok(h) => {
                        info!(
                        "esplora HTTP+WS on {} (REST + /v1/ws; max_conn={} max_body={} idle={}s max_ws={}; TLS via reverse proxy if public)",
                        h.local_addr, max_conn, max_body, idle_secs, max_ws
                    );
                        esplora_handles.push(h);
                    }
                    Err(e) => warn!("esplora HTTP start warning: {e}"),
                }
            }
        }
    }

    let mut rpc_handle: Option<RpcHandle> = None;
    if let Some(addr) = config.rpc_listen {
        if !shutdown.requested() {
            let rcfg = RpcConfig {
                listen: addr,
                datadir: config.datadir.clone(),
                network: config.network,
                rpc_user: config.rpc_user.clone(),
                rpc_password: config.rpc_password.clone(),
                cookie_path: Some(config.rpc_cookie_path()),
                work_queue: config.rpc_work_queue,
                subversion: Some(
                    rbitcoin_primitives::rbitcoin_subversion(
                        env!("CARGO_PKG_VERSION"),
                        &config.uacomments,
                    )
                    .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION"))),
                ),
                permit_bare_multisig: config.permit_bare_multisig,
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
            )
            .await
            {
                Ok(h) => {
                    h.initial_block_download.store(
                        !tip_follow_ready
                            || !tip_meets_min_work(&config, &node.hub)
                            || node.hub.tip_is_stale_for_ibd(),
                        Ordering::SeqCst,
                    );
                    h.connections
                        .store(node.follow_live_count() as u64, Ordering::Relaxed);
                    info!(
                        "rpc: listening on {} (auth={})",
                        h.local_addr,
                        if config.rpc_user.is_some() {
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
                if !config.blocksonly
                    && !mempool.relay_enabled()
                    && tip_meets_min_work(&config, &node.hub)
                {
                    mempool.set_relay_enabled(true);
                    info!("ibd: tip work now meets -minimumchainwork — enabling relay");
                }
                h.initial_block_download.store(
                    !tip_meets_min_work(&config, &node.hub) || node.hub.tip_is_stale_for_ibd(),
                    Ordering::SeqCst,
                );
            }
            if matches!(wake, TipFollowWake::Stop) {
                break;
            }

            if matches!(wake, TipFollowWake::Perf) {
                let mp = mempool.sample_reset_perf();
                let (esp_n, esp_us, esp_max) = rbitcoin_esplora::sample_reset_perf();
                let (el_n, el_us, el_max) = rbitcoin_electrum::sample_reset_perf();
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
                         electrum req={el_n} avg_us={el_avg} max_us={el_max}",
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
            if !stagnant || config.connect.is_empty() == false || !config.use_seeds {
                continue;
            }
            if addrman.is_empty() || shutdown.requested() {
                continue;
            }

            last_tip_change = Instant::now();
            let extra = addrman.take_outbound_offset(1, seed_offset);
            seed_offset = seed_offset.saturating_add(1);
            if extra.is_empty() {
                continue;
            }
            if stale_follow_needs_room(follow_live, max_out) {
                let ids = node.peers.outbound_full_relay_ids();
                let salt = node.hub.clock.now_secs();
                let Some(evict_id) = rbitcoin_net::pick_stale_follow_evict(&ids, salt) else {
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
                if catch_up_complete {
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
    config.use_seeds && config.connect.is_empty() && config.signet_challenge.is_none()
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
/// Incomplete IBD must not call this (`catch_up_complete` only after full horizon).
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
        assert_eq!(parse_btc_to_sat("0.00000001"), Some(1));
        assert_eq!(parse_btc_to_sat("0"), Some(0));
        assert_eq!(parse_btc_to_sat("0.025"), Some(2_500_000));
        assert_eq!(parse_btc_to_sat("0.00000005"), Some(5));
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
        let q = Query::open_or_create(dir.join("store")).unwrap();
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
        let q = Query::open_or_create(&store).unwrap();
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
        let q = Query::open_or_create(dir.join("store")).unwrap();
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
        let q = Query::open_or_create(dir.join("store")).unwrap();
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
        let q = Query::open_or_create(&store).unwrap();
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
        let cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest);
        let handle = run_node(cfg).expect("run_node");
        assert_eq!(handle.network_name(), "regtest");
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        cfg.connect.clear();
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        cfg.connect.clear();
        cfg.milestone_height = 100; // exercise milestone log branch
        cfg.shindex = true;
        cfg.electrum_listen = Some("127.0.0.1:0".parse().unwrap());
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        cfg.connect.clear();
        cfg.shindex = true;
        cfg.esplora_listen = Some("127.0.0.1:0".parse().unwrap());
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        // Blackhole / closed port: connect fails fast under FOLLOW_CONNECT_SECS.
        cfg.connect = vec!["127.0.0.1:1".parse().unwrap()];
        cfg.max_run_secs = Some(0);
        // Dead connect should fail fast (FOLLOW_CONNECT_SECS); 20s bound for hang detection.
        let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        // Incomplete IBD is ok (warn path); should not hang.
        let _ = result.unwrap();
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
        let q = Query::open_or_create(dir.join("store")).unwrap();
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
        let cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest);
        let mut handle = run_node(cfg).expect("run_node");
        // Dual-open same store under /tmp for MempoolHub's Arc<Query> (flush only).
        let q = Arc::new(Query::open_or_create(handle.config.store_path()).unwrap());
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

        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        // Peers file is loaded for bookkeeping; do not dial those addrs as --connect
        // (would stall IBD). Empty connect + no seeds → catch-up complete immediately.
        cfg.connect.clear();
        cfg.max_run_secs = Some(0);
        cfg.shindex = true;
        cfg.electrum_listen = Some("127.0.0.1:0".parse().unwrap());
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

        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        cfg.connect = vec!["127.0.0.1:1".parse().unwrap()];
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = true; // regtest: resolve_all_seeds → empty
        cfg.connect.clear();
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
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.use_seeds = false;
        cfg.connect.clear();
        cfg.shindex = true;
        cfg.electrum_listen = Some(addr); // already bound → fail
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(15), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        // Bind fail is non-fatal warn; run should still complete.
        result.unwrap().expect("run_p2p despite electrum fail");
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
