use crate::config::{parse_btc_to_sat, ListenOpts, NodeConfig};
use crate::error::NodeError;
use crate::health::{run_health, NodeStatus, Phase};
use crate::regtest_rpc::HubRegtest;
use bitcoin::consensus::Encodable;
use rbitcoin_electrum::{run_electrum, ElectrumConfig, ElectrumHandle, TipNotify};
use rbitcoin_esplora::{run_esplora, BlockTemplateFn, EsploraConfig, EsploraHandle, EsploraListen};
use rbitcoin_log::{debug, enabled, info, warn, Level};
use rbitcoin_net::{
    default_port, format_serve_perf, format_tip_perf_sizes, netgroup, read_platform_rss,
    sample_reset_serve_perf, socks_dns_seed_dests, AddrMan, AsMap, BlockingRegion, ChainHub,
    Dialer, IbdConfig, MempoolHub, P2PNode, PeerConnType, TipEvent, TipPerfSizes,
};
use rbitcoin_primitives::Network;
use rbitcoin_query::{spawn_sh_writebehind, Query, SpendSync};
use rbitcoin_rpc::{
    gbt_template, run_rpc, RpcActive, RpcConfig, RpcContext, RpcHandle, RpcRegtest,
};
use rbitcoin_store::StoreError;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
    _dir_locks: crate::lock::DirLocks,
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

/// Clearnet follow handshake bound. Overlay STREAM CONNECT is slower; see
/// [`follow_connect_timeout`].
const FOLLOW_CONNECT_SECS: u64 = 8;

fn follow_connect_timeout(peer: rbitcoin_net::NetAddr) -> Duration {
    rbitcoin_net::connect_timeout_for(peer, Duration::from_secs(FOLLOW_CONNECT_SECS))
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

/// Restore fee history from the mempool dir and read the rest of up to 1 GiB
/// of txstat rows once relay is on, off the tip path.
fn spawn_fee_history_backfill(mempool: &Arc<MempoolHub>) {
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

async fn mempool_blocking<T: Send + 'static>(
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
    rbitcoin_consensus::replay_spend_annotations(&query)
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
        Some(addr) => Some(
            run_health(addr, Arc::clone(&status), config.metrics)
                .await
                .map_err(|e| NodeError::Config(format!("health listen {addr}: {e}")))?,
        ),
        None => None,
    };
    let handle = run_node(config.clone())?;
    status.enter(Phase::Starting);
    let params = config.chain_params()?;
    let milestone = config.milestone();
    if let Some(anchor) = milestone.anchor {
        info!(
            "ibd: milestone height={} hash={} (script/sig skip only when this header path contains that hash and chain work meets the floor; prevouts always)",
            milestone.height, anchor.hash
        );
    } else {
        info!(
            "ibd: milestone height={} (script/sig checks skipped at/below; prevouts always)",
            milestone.height
        );
    }
    apply_startup_index_mode(&handle.query, &config, params.taproot_height())?;
    rbitcoin_consensus::prepare_live_indexes(&handle.query)
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
            )
            .await
        }
    }
    .map_err(|e| NodeError::Config(format!("p2p start: {e}")))?;
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
    if let Some(secs) = config.max_tip_age_secs {
        node.hub.set_max_tip_age_secs(secs);
    }
    node.hub.set_prefill_compact(config.prefill_compact);
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
    if config.listen.proxy.is_some() || config.listen.onion.is_some() {
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
            rbitcoin_net::I2pSam::connect_persistent(addr, &dest).await
        } else {
            rbitcoin_net::I2pSam::connect(addr).await
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
    addrman.set_only_net(config.listen.only_net.clone());
    addrman.set_cjdns_reachable(config.listen.cjdns_reachable);
    node.peers
        .set_cjdns_reachable(config.listen.cjdns_reachable);
    node.peers.set_pruned(config.prune_seqsigwit);
    node.peers.set_asmap(asmap);
    node.peers.set_connect_hosts(
        config.listen.connect_dns.clone(),
        config.network.default_p2p_port(),
    );
    let dns_resolved = resolve_connect_dns(&config.listen.connect_dns, config.network).await;
    for c in &config.listen.connect {
        addrman.add_addr(*c);
    }
    for c in &dns_resolved {
        addrman.add_addr(*c);
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
    } else if config.listen.proxy.is_some() && config.listen.use_seeds {
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
    if mempool.isolated_broadcast() {
        let _iso = rbitcoin_net::spawn_isolated_broadcast_loop(
            Arc::clone(&mempool),
            config.listen.isolated_dialer(),
            std::sync::Arc::clone(&shared_peers),
            node.magic(),
            node.user_agent().to_string(),
        );
    }

    let max_out = config.listen.max_outbound.max(1) as usize;
    let candidate_n = max_out.saturating_mul(2).clamp(16, 48);
    let occupied = node.peers.live_outbound_full_relay_nets();
    let mut pinned = config.listen.connect.clone();
    pinned.extend(dns_resolved);
    let targets = follow_dial_targets(&pinned, &addrman, max_out, &occupied);
    let follow_type = follow_dial_type(&pinned);
    let ibd_targets = follow_dial_targets(&pinned, &addrman, candidate_n, &occupied);
    status.enter(Phase::CatchUp);
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
        let gates = enter_tip_mode(
            &node.hub.query,
            Some(Arc::clone(&shutdown.flag)),
            config.shindex,
        );
        tip_follow_ready = gates.tip_follow_ready;
        sh_tip_ready = gates.sh_tip_ready;
        if tip_follow_ready && !shutdown.requested() {
            let index_entry = rbitcoin_consensus::index_tip_entry(&node.hub.query);
            if index_entry.advertise_filters {
                info!("blockfilter: already at tip; advertising NODE_COMPACT_FILTERS");
                rbitcoin_net::set_compact_filters_service(true);
            }
            if index_entry.spawn {
                let advertise_later = !index_entry.advertise_filters;
                index_writebehind = Some(rbitcoin_consensus::spawn_index_writebehind(
                    Arc::clone(&node.hub.query),
                    Arc::clone(&shutdown.flag),
                    {
                        let sd = Arc::clone(&shutdown);
                        move || sd.request()
                    },
                    // Version carries the bit once per peer: advertise only
                    // when served filters reach the tip, not during materialize.
                    move || {
                        if advertise_later {
                            rbitcoin_net::set_compact_filters_service(true);
                        }
                    },
                ));
            }
            if relay_while_following(
                tip_meets_min_work(&config, &node.hub),
                config.mempool.blocksonly,
                node.hub.in_ibd(),
            ) {
                mempool_blocking(&mempool, |mp| mp.set_relay_enabled(true)).await?;
                spawn_fee_history_backfill(&mempool);
            }
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
            if let Err(e) = node.peers.dial(addr, PeerConnType::AddrFetch) {
                warn!("seednode dial {addr}: {e}");
            }
        }
    }
    if !shutdown.requested() && !addrman.is_empty() && seednodes_allowed(&config.listen) {
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
        if catch_up.dial_failed_all() {
            for peer in targets.iter().take(follow_n) {
                if let Err(e) = node.peers.dial_net(*peer, follow_type) {
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
                let to = follow_connect_timeout(*peer);
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
    }

    let (mut electrum_handles, mut electrum_bridge, electrum_onion) = start_electrum_if_ready(
        sh_tip_ready,
        config.listen.electrum,
        config.sptweaks_dust,
        config.electrum_max_subs,
        &shutdown,
        &node.hub,
        &params,
        &mempool,
    )
    .await;
    if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), electrum_handles.first()) {
        let hs = ctl
            .add_electrum_onion(config.datadir.path(), h.local_addr)
            .await?;
        info!(
            "electrum onion {}.onion:{}",
            hs.service_id,
            h.local_addr.port()
        );
        let _ = electrum_onion.set((format!("{}.onion", hs.service_id), h.local_addr.port()));
        node.peers
            .set_wallet_onion(format!("{}.onion", hs.service_id), h.local_addr.port());
    }
    let mut esplora_handles = start_esplora_if_ready(
        sh_tip_ready,
        config.listen.esplora.clone(),
        config.network,
        config.esplora_block_template,
        &shutdown,
        Arc::clone(&node.hub),
        &mempool,
    )
    .await;
    if config.esplora_onion {
        if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), esplora_handles.first()) {
            let hs = ctl
                .add_esplora_onion(config.datadir.path(), h.local_addr)
                .await?;
            info!(
                "esplora onion http://{}.onion:{} (/ws same port)",
                hs.service_id,
                h.local_addr.port()
            );
            node.peers
                .set_wallet_onion(format!("{}.onion", hs.service_id), h.local_addr.port());
        }
    }
    let mut i2p_wallet = Vec::new();
    if config.listen.i2p_accept_incoming {
        if let Some(addr) = config.listen.i2p_sam {
            if let Some(h) = electrum_handles.first() {
                i2p_wallet.push(
                    start_i2p_named_forward(
                        addr,
                        config.datadir.path(),
                        "electrum",
                        h.local_addr.port(),
                    )
                    .await?,
                );
            }
            if let Some(h) = esplora_handles.first() {
                i2p_wallet.push(
                    start_i2p_named_forward(
                        addr,
                        config.datadir.path(),
                        "esplora",
                        h.local_addr.port(),
                    )
                    .await?,
                );
            }
        }
    }

    let mut rpc_handle: Option<RpcHandle> = None;
    if (config.rpc.socket || config.rpc.listen.is_some()) && !shutdown.requested() {
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
                    "rpc: listening tcp={:?} sock={:?} token={}",
                    h.local_addr,
                    h.socket_path,
                    h.token_path.display()
                );
                rpc_handle = Some(h);
            }
            Err(e) => warn!("rpc start warning: {e}"),
        }
    }

    if let Some(cmd) = config.startup_notify.as_deref() {
        match std::process::Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(st) if st.success() => {}
            Ok(st) => warn!("startup-notify exited {st}: {cmd}"),
            Err(e) => warn!("startup-notify failed: {e}: {cmd}"),
        }
    }

    if tip_follow_ready && config.max_run_secs != Some(0) && !shutdown.requested() {
        let unbound = [
            (
                "rpc",
                config.rpc.socket || config.rpc.listen.is_some(),
                rpc_handle.is_some(),
            ),
            (
                "electrum",
                config.listen.electrum.is_some(),
                !electrum_handles.is_empty(),
            ),
            (
                "esplora",
                config.listen.esplora.is_some(),
                !esplora_handles.is_empty(),
            ),
        ];
        status.follow(
            unbound
                .into_iter()
                .filter(|&(_, configured, bound)| configured && !bound)
                .map(|(name, ..)| name)
                .collect(),
        );
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

            // A durable head can lag `include_hwm` at tip entry. Electrum stays
            // down until write-behind covers the tip, then this same process binds.
            let electrum_due =
                config.shindex && config.listen.electrum.is_some() && electrum_handles.is_empty();
            let esplora_due =
                config.shindex && config.listen.esplora.is_some() && esplora_handles.is_empty();
            if (electrum_due || esplora_due) && node.hub.query.sh_is_tip_ready() {
                if electrum_due {
                    let (handles, bridge, onion) = start_electrum_if_ready(
                        true,
                        config.listen.electrum,
                        config.sptweaks_dust,
                        config.electrum_max_subs,
                        &shutdown,
                        &node.hub,
                        &params,
                        &mempool,
                    )
                    .await;
                    if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), handles.first()) {
                        let hs = ctl
                            .add_electrum_onion(config.datadir.path(), h.local_addr)
                            .await?;
                        info!(
                            "electrum onion {}.onion:{}",
                            hs.service_id,
                            h.local_addr.port()
                        );
                        let _ =
                            onion.set((format!("{}.onion", hs.service_id), h.local_addr.port()));
                        node.peers.set_wallet_onion(
                            format!("{}.onion", hs.service_id),
                            h.local_addr.port(),
                        );
                    }
                    if config.listen.i2p_accept_incoming {
                        if let Some(addr) = config.listen.i2p_sam {
                            if let Some(h) = handles.first() {
                                i2p_wallet.push(
                                    start_i2p_named_forward(
                                        addr,
                                        config.datadir.path(),
                                        "electrum",
                                        h.local_addr.port(),
                                    )
                                    .await?,
                                );
                            }
                        }
                    }
                    electrum_bridge = bridge;
                    electrum_handles = handles;
                }
                if esplora_due {
                    let handles = start_esplora_if_ready(
                        true,
                        config.listen.esplora.clone(),
                        config.network,
                        config.esplora_block_template,
                        &shutdown,
                        Arc::clone(&node.hub),
                        &mempool,
                    )
                    .await;
                    if config.esplora_onion {
                        if let (Some(ctl), Some(h)) = (tor_ctl.as_mut(), handles.first()) {
                            let hs = ctl
                                .add_esplora_onion(config.datadir.path(), h.local_addr)
                                .await?;
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
                    if config.listen.i2p_accept_incoming {
                        if let Some(addr) = config.listen.i2p_sam {
                            if let Some(h) = handles.first() {
                                i2p_wallet.push(
                                    start_i2p_named_forward(
                                        addr,
                                        config.datadir.path(),
                                        "esplora",
                                        h.local_addr.port(),
                                    )
                                    .await?,
                                );
                            }
                        }
                    }
                    esplora_handles = handles;
                }
                info!("node: scripthash inclusion reached the tip — wallet services bound");
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
                    mempool_blocking(&mempool, move |mp| mp.set_relay_enabled(want_relay)).await?;
                    if want_relay {
                        spawn_fee_history_backfill(&mempool);
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
                if let Err(e) = mempool_blocking(&mempool, |mp| mp.persist_due()).await? {
                    warn!("mempool persist_due: {e}");
                }
                let mp = mempool.sample_reset_perf();
                let (esp_n, esp_us, esp_max) = rbitcoin_esplora::sample_reset_perf();
                let (el_n, el_us, el_max) = rbitcoin_electrum::sample_reset_perf();
                let serve = sample_reset_serve_perf();
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
                    let serve_s = format_serve_perf(&serve);
                    let sizes = format_tip_perf_sizes(&TipPerfSizes {
                        rss: read_platform_rss(),
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
            if !stagnant || config.listen.has_pinned_connect() || !config.listen.use_seeds {
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
                            node.follow_from_net(rbitcoin_net::NetAddr::Ip(peer)),
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
                    let retry_cfg =
                        catch_up_retry_config(std::sync::Arc::clone(&shared_peers), node.dialer());
                    let cancel = Some(Arc::clone(&shutdown.flag));
                    let retry_peers = [rbitcoin_net::NetAddr::Ip(peer)];
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
    config.listen.use_seeds
        && !config.listen.has_pinned_connect()
        && config.signet_challenge.is_none()
        && config.listen.proxy.is_none()
}

/// Genesis `--connect` whose first catch-up accepts nothing is treated as
/// finished so the process stays up. The later dial is a follow session
/// (16 blocks in flight on the tip index path), not a return to the IBD
/// window. A non-zero tip that has not finished catch-up stays in IBD.
pub(crate) fn catch_up_with_connect(
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
pub(crate) fn relay_while_following(meets_min_work: bool, blocks_only: bool, in_ibd: bool) -> bool {
    meets_min_work && !blocks_only && !in_ibd
}

async fn resolve_connect_dns(hosts: &[String], network: Network) -> Vec<rbitcoin_net::NetAddr> {
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

fn queue_proxy_seed_addrfetch(peers: &Arc<rbitcoin_net::PeerHub>, network: Network) -> usize {
    let mut n = 0usize;
    for (host, port) in socks_dns_seed_dests(network) {
        match peers.dial_domain(host.clone(), port, PeerConnType::AddrFetch) {
            Ok(()) => n += 1,
            Err(e) => warn!("seednode dial {host}:{port}: {e}"),
        }
    }
    n
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
    query.set_block_filter_index(config.block_filter_index)?;
    query.set_max_sh_creates(config.max_sh_creates);
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
    ibd_targets: &[rbitcoin_net::NetAddr],
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
    // Window, per-peer cap, and stall come from `IbdConfig::default`.
    // A 5s stall caused reassign storms (clearing 200+ inflight before peers
    // could deliver mid-chain blocks). Default 30s is enough.
    let ibd_cfg = IbdConfig {
        target_peers,
        peers: Some(std::sync::Arc::clone(shared_peers)),
        dialer: node.dialer(),
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

async fn start_i2p_named_forward(
    sam_addr: SocketAddr,
    datadir: &Path,
    name: &str,
    port: u16,
) -> Result<rbitcoin_net::I2pSam, NodeError> {
    let dest = datadir.join("i2p").join(format!("{name}.priv"));
    let mut sam = rbitcoin_net::I2pSam::connect_persistent(sam_addr, &dest)
        .await
        .map_err(|e| NodeError::Init(format!("i2p {name} session: {e}")))?;
    sam.stream_forward(port)
        .await
        .map_err(|e| NodeError::Init(format!("i2p {name} STREAM FORWARD {port}: {e}")))?;
    info!("i2p {name} STREAM FORWARD to 127.0.0.1:{port}");
    Ok(sam)
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
async fn start_electrum_if_ready(
    sh_tip_ready: bool,
    addr: Option<SocketAddr>,
    tweaks_min_dust: u64,
    electrum_max_subs: usize,
    shutdown: &Shutdown,
    hub: &ChainHub,
    params: &rbitcoin_consensus::ChainParams,
    mempool: &std::sync::Arc<MempoolHub>,
) -> (
    Vec<ElectrumHandle>,
    Option<tokio::task::JoinHandle<()>>,
    Arc<OnceLock<(String, u16)>>,
) {
    let onion_tcp = Arc::new(OnceLock::new());
    let Some(addr) = addr else {
        return (Vec::new(), None, onion_tcp);
    };
    if !sh_tip_ready || shutdown.requested() {
        return (Vec::new(), None, onion_tcp);
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
            (vec![h], Some(bridge), onion_tcp)
        }
        Err(e) => {
            warn!("electrum TCP start warning: {e}");
            (Vec::new(), Some(bridge), onion_tcp)
        }
    }
}

async fn start_esplora_if_ready(
    sh_tip_ready: bool,
    listen: Option<EsploraListen>,
    network: Network,
    enable_block_template: bool,
    shutdown: &Shutdown,
    hub: Arc<ChainHub>,
    mempool: &std::sync::Arc<MempoolHub>,
) -> Vec<EsploraHandle> {
    let Some(listen) = listen else {
        return Vec::new();
    };
    if !sh_tip_ready || shutdown.requested() {
        return Vec::new();
    }
    let q = hub.query.clone();
    let btc_net = match network {
        rbitcoin_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        rbitcoin_primitives::Network::Testnet => bitcoin::Network::Testnet,
        rbitcoin_primitives::Network::Signet => bitcoin::Network::Signet,
        rbitcoin_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let mut ecfg = EsploraConfig::with_listen(listen, btc_net);
    if enable_block_template {
        let q = Arc::clone(&hub.query);
        let mp = Arc::clone(mempool);
        let chain = Arc::clone(&hub);
        ecfg.block_template = Some(BlockTemplateFn(Arc::new(move || {
            let ctx = RpcContext {
                query: Arc::clone(&q),
                mempool: Some(Arc::clone(&mp)),
                network,
                start: Instant::now(),
                stop: Arc::new(AtomicBool::new(false)),
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
    match run_esplora(ecfg, q, Some(Arc::clone(mempool))).await {
        Ok(h) => {
            info!(
                "esplora HTTP on {} (max_conn={} max_body={} idle={}s; TLS via reverse proxy if public)",
                h.socket_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| h.local_addr.to_string()),
                max_conn, max_body, idle_secs
            );
            vec![h]
        }
        Err(e) => {
            warn!("esplora HTTP start warning: {e}");
            Vec::new()
        }
    }
}

/// Result of post-IBD tip entry: follow/mempool gates vs Electrum SH gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TipModeGates {
    /// Class A + spends ready: follow peers, tip loop, mempool tip-relay.
    pub tip_follow_ready: bool,
    /// Electrum / Esplora may bind. With `--sh-index` this waits until the
    /// index is caught up. Without it the listeners still bind; address
    /// methods fail closed.
    pub sh_tip_ready: bool,
}

fn sh_cancel_resume_note(query: &Query) -> &'static str {
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

fn sh_tip_ready_gates(query: &Query) -> TipModeGates {
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

/// Enter steady-state after true catch-up.
///
/// **Preconditions (enforced by IBD, not repaired here):** Direct catch-up already
/// wrote durable **`tx.head`** (archive) and **spend annotations** (confirm).
/// Incomplete IBD must not call this (`CatchUp::Complete` only after full horizon).
///
/// **SH methods (exactly two):**
/// - Durable head: stay/flip [`IndexMode::Tip`], discard leftover runs;
///   catch-up / follow use write-behind. `sh_tip_ready` only when inclusion
///   already covers the tip.
/// - No head: Class A collect + unsorted pack **while Direct** (write-behind
///   no-ops), then Tip. Cancel leaves Direct; Electrum stays closed.
///
/// **When `!shindex`:** skip SH materialize. Listeners may bind
/// (`sh_tip_ready`); address methods fail closed.
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
        return sh_tip_ready_gates(query);
    }

    info!("node: index materialize from Class A (Direct collect, then Tip)…");
    if !query.index_mode().is_direct() {
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
    sh_tip_ready_gates(query)
}

/// Production IBD knobs for a single-peer catch-up retry (stale tip, incomplete catch-up).
///
/// Uses [`IbdConfig::default`] (window 1024, stall 30s, connect 8s, …) — not
/// [`IbdConfig::for_test`], which is only for unit/integration test harnesses.
fn catch_up_retry_config(
    peers: std::sync::Arc<std::sync::Mutex<AddrMan>>,
    dialer: Dialer,
) -> IbdConfig {
    IbdConfig {
        target_peers: 1,
        peers: Some(peers),
        dialer,
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
pub(crate) fn follow_dial_type(connect: &[rbitcoin_net::NetAddr]) -> PeerConnType {
    if connect.is_empty() {
        PeerConnType::OutboundFullRelay
    } else {
        PeerConnType::Manual
    }
}

/// Whether `--seednode` may be dialled as addr-fetch: at startup with an
/// empty addrman, or by the 10 s fallback when fewer than 2 outbound
/// full-relay peers are live. Core never dials seednodes under `-connect`.
/// `--connect` peers are `manual`, so they would never hold the fallback off.
pub(crate) fn seednodes_allowed(listen: &ListenOpts) -> bool {
    !listen.seednodes.is_empty() && !listen.has_pinned_connect()
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

/// A CJDNS listen bind is the address peers should learn. `--external-ip`
/// still wins when the operator set the same address already.
fn external_ips_with_cjdns_bind(
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
fn resolve_seednode(raw: &str, network: Network) -> Result<SocketAddr, String> {
    if let Ok(a) = raw.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: std::net::IpAddr = raw
        .parse()
        .map_err(|e| format!("bad seednode address: {e}"))?;
    Ok(SocketAddr::new(ip, default_port(network)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn tiny_regtest(dir: impl AsRef<std::path::Path>) -> NodeConfig {
        NodeConfig::default()
            .with_datadir(dir.as_ref())
            .with_network(rbitcoin_primitives::Network::Regtest)
            .with_tiny_heads()
    }

    /// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale redial.
    /// A one-shot sleep in the same `select!` is reset on every such wake.
    /// `--sh-index` off still binds Electrum/Esplora. Address methods fail
    /// closed inside the servers; the listeners themselves are not the gate.
    #[test]
    fn listeners_ready_without_sh_index() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-shoff-listen-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        let gates = enter_tip_mode(&q, None, false);
        assert!(gates.tip_follow_ready);
        assert!(
            gates.sh_tip_ready,
            "Electrum/Esplora bind when --sh-index is off"
        );
        assert!(!q.sh_index_enabled());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let connect = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8333,
        ))];
        let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
            8333,
        ))];
        let want = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8333,
        ))];
        assert_eq!(follow_dial_targets(&connect, &am, 8, &occupied), want);
        // Core reports `-connect` peers as `manual`; addrman picks are full relay.
        assert_eq!(follow_dial_type(&connect), PeerConnType::Manual);
        assert_eq!(follow_dial_type(&[]), PeerConnType::OutboundFullRelay);
    }

    #[test]
    fn seednodes_are_off_under_connect() {
        let mut listen = NodeConfig::default().listen;
        assert!(!seednodes_allowed(&listen), "no seednodes");
        listen.seednodes = vec!["127.0.0.1:18444".into()];
        assert!(seednodes_allowed(&listen));
        listen.connect = vec![rbitcoin_net::NetAddr::Ip(
            "127.0.0.1:18445".parse().unwrap(),
        )];
        assert!(
            !seednodes_allowed(&listen),
            "Core skips seednodes under -connect"
        );
        listen.connect.clear();
        listen.connect_dns = vec!["localhost:18445".into()];
        assert!(!seednodes_allowed(&listen), "a --connect hostname pins too");
    }

    #[test]
    fn follow_dial_targets_keeps_i2p_connect() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let mut am = AddrMan::new();
        am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
        let i2p = rbitcoin_net::NetAddr::I2p {
            dest: [7u8; 32],
            port: 8333,
        };
        let connect = vec![i2p];
        let got = follow_dial_targets(&connect, &am, 8, &[]);
        assert_eq!(got, vec![i2p]);
    }

    #[test]
    fn follow_dial_targets_skips_occupied_group() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let mut am = AddrMan::new();
        let same = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333);
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 3, 0, 1)), 8333);
        am.add(same);
        am.add(other);
        let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
            8333,
        ))];
        let got = follow_dial_targets(&[], &am, 1, &occupied);
        assert_eq!(got, vec![rbitcoin_net::NetAddr::Ip(other)]);
    }

    #[test]
    fn follow_dial_targets_picks_addrman_onion() {
        let onion: rbitcoin_net::NetAddr =
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
                .parse()
                .unwrap();
        let mut am = AddrMan::new();
        am.set_only_net(vec![rbitcoin_net::OnlyNet::Onion]);
        am.add_addr(onion);
        assert_eq!(follow_dial_targets(&[], &am, 1, &[]), vec![onion]);
        assert!(
            follow_dial_targets(&[], &am, 1, &[onion]).is_empty(),
            "live onion net must not be re-dialed via 0.0.0.0 hint"
        );
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
    fn connect_genesis_incomplete_enters_tip_follow() {
        assert_eq!(
            catch_up_with_connect(CatchUp::Incomplete, true, false, 0),
            CatchUp::complete_dial_failed()
        );
        assert_eq!(
            catch_up_with_connect(CatchUp::Incomplete, false, false, 0),
            CatchUp::Incomplete
        );
        assert_eq!(
            catch_up_with_connect(CatchUp::Incomplete, true, true, 0),
            CatchUp::Incomplete
        );
        assert!(catch_up_with_connect(CatchUp::complete(), true, false, 0).is_complete());
    }

    #[test]
    fn connect_nongenesis_incomplete_stays_in_ibd() {
        assert_eq!(
            catch_up_with_connect(CatchUp::Incomplete, true, false, 50),
            CatchUp::Incomplete
        );
    }

    #[test]
    fn relay_requires_min_chain_work_even_when_following() {
        assert!(!relay_while_following(false, false, false));
        assert!(relay_while_following(true, false, false));
        assert!(!relay_while_following(true, true, false));
        assert!(!relay_while_following(true, false, true));
        let mut cfg = NodeConfig::default();
        assert!(cfg.meets_minimum_chain_work([0; 32]));
        cfg.minimum_chain_work = Some([0xff; 32]);
        assert!(
            !cfg.meets_minimum_chain_work([0; 32]),
            "a non-genesis tip under --min-chain-work follows, but relay stays gated"
        );
    }

    #[test]
    fn cjdns_listen_is_advertised_without_external_ip() {
        use std::net::{IpAddr, Ipv6Addr};
        let fc = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
        let bind = SocketAddr::from((fc, 8333));
        let got = external_ips_with_cjdns_bind(&[], bind, true);
        assert_eq!(got, vec![IpAddr::V6(fc)]);
        assert!(
            external_ips_with_cjdns_bind(&[], bind, false).is_empty(),
            "fc00 stays unroutable until --cjdns-reachable"
        );
        let v4 = SocketAddr::from(([1, 2, 3, 4], 8333));
        assert!(external_ips_with_cjdns_bind(&[], v4, true).is_empty());
        let ula = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 8333));
        assert!(
            external_ips_with_cjdns_bind(&[], ula, true).is_empty(),
            "fd00::/8 is not CJDNS"
        );
        let dup = external_ips_with_cjdns_bind(&[IpAddr::V6(fc)], bind, true);
        assert_eq!(dup, vec![IpAddr::V6(fc)]);
    }

    #[test]
    fn follow_connect_timeout_i2p_is_longer_than_clearnet() {
        let i2p = rbitcoin_net::NetAddr::I2p {
            dest: [0u8; 32],
            port: 1,
        };
        let ip: rbitcoin_net::NetAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(
            follow_connect_timeout(ip),
            Duration::from_secs(FOLLOW_CONNECT_SECS)
        );
        assert_eq!(follow_connect_timeout(i2p), Duration::from_secs(90));
    }

    #[test]
    fn catch_up_retry_config_uses_production_not_for_test() {
        let peers = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::AddrMan::new()));
        let cfg = catch_up_retry_config(std::sync::Arc::clone(&peers), Dialer::Direct);
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

    #[test]
    fn dns_seeds_not_resolved_locally_when_proxy() {
        let mut cfg = NodeConfig::default();
        assert!(should_resolve_default_seeds(&cfg));
        cfg.listen.proxy = Some("127.0.0.1:9050".parse().unwrap());
        assert!(
            !should_resolve_default_seeds(&cfg),
            "proxy path must not ToSocketAddrs DNS/fixed seeds"
        );
    }

    #[test]
    fn proxy_seed_bootstrap_queues_domain_addrfetch() {
        let peers = rbitcoin_net::PeerHub::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<rbitcoin_net::DialRequest>();
        peers.set_dialer(tx);
        let n = queue_proxy_seed_addrfetch(&peers, rbitcoin_primitives::Network::Signet);
        assert_eq!(n, 1, "signet has one default DNS seed");
        let req = rx.try_recv().expect("queued dial request");
        assert_eq!(req.typ, PeerConnType::AddrFetch);
        match req.target {
            rbitcoin_net::DialTarget::Domain { host, port } => {
                assert_eq!(host, "seed.signet.bitcoin.sprovoost.nl");
                assert_eq!(port, 38333);
            }
            other => panic!("expected domain target, got {other:?}"),
        }
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

    /// The `IbdConfig` literal in `run_ibd_or_skip` is not built by the config
    /// journey, so this drives `run_p2p`. A refused connect must flush a fail
    /// mark into the saved book, and the SOCKS proxy must be the socket dialed.
    #[tokio::test]
    async fn run_p2p_refused_connect_flushes_book_and_dials_proxy() {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-proxy-{nanos}"));
        let proxy_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = proxy_l.local_addr().unwrap();
        let target_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let connect = target_l.local_addr().unwrap();
        let proxy_hit = Arc::new(AtomicBool::new(false));
        let target_hit = Arc::new(AtomicBool::new(false));
        let proxy_flag = Arc::clone(&proxy_hit);
        let target_flag = Arc::clone(&target_hit);
        std::thread::spawn(move || {
            while let Ok((mut sock, _)) = proxy_l.accept() {
                proxy_flag.store(true, Ordering::SeqCst);
                let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buf = [0u8; 16];
                let _ = sock.read(&mut buf);
                // No acceptable SOCKS method: the dial fails before CONNECT.
                let _ = sock.write_all(&[0x05, 0xFF]);
            }
        });
        std::thread::spawn(move || {
            while target_l.accept().is_ok() {
                target_flag.store(true, Ordering::SeqCst);
            }
        });

        let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect = vec![rbitcoin_net::NetAddr::from_socket(connect)];
        cfg.listen.proxy = Some(proxy);
        cfg.max_run_secs = Some(0);
        let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
        assert!(result.is_ok(), "run_p2p timed out");
        let _ = result.unwrap();

        assert!(
            proxy_hit.load(Ordering::SeqCst),
            "IBD must dial the configured SOCKS proxy"
        );
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "SOCKS dial must not open a direct TCP connection to the target"
        );
        let book = AddrMan::load(&dir.join("peers")).expect("peers saved");
        assert!(
            book.flags(&connect).failed_last_connect(),
            "IBD must flush the dial failure into the saved peer book"
        );
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

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-{label}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A pack-marked head whose inclusion floor is behind the tip must not open
    /// Electrum. Tip follow still starts so write-behind can catch up.
    #[test]
    fn enter_tip_mode_does_not_ready_electrum_when_inclusion_lags() {
        let dir = scratch_dir("tip-gate");
        let q = Query::open_or_create_tiny(&dir).unwrap();
        let bump = q.store().scripthash.alloc_bump();
        q.store()
            .scripthash
            .publish_sorted_shard(0, &[], 0, bump)
            .unwrap();
        assert!(q.store().scripthash.has_durable_index());
        assert!(q.sh_use_writebehind());
        assert!(
            !q.sh_is_tip_ready(),
            "empty tip is not an inclusion-complete scripthash head"
        );
        let gates = enter_tip_mode(&q, None, true);
        assert!(gates.tip_follow_ready);
        assert!(
            !gates.sh_tip_ready,
            "lagging inclusion must not start Electrum"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cancel before any extract file exists must not tell the operator to
    /// resume from `scripthash.cold_progress`.
    #[test]
    fn enter_tip_mode_cancel_does_not_name_missing_cold_progress() {
        let dir = scratch_dir("tip-cancel");
        let q = Query::open_or_create_tiny(&dir).unwrap();
        assert!(!q.store().path().join("scripthash.cold_progress").is_file());
        assert!(!q.store().path().join("scripthash.unsorted").is_dir());
        let cancel = Arc::new(AtomicBool::new(true));
        rbitcoin_log::capture_logs(true);
        let gates = enter_tip_mode(&q, Some(cancel), true);
        let lines = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(gates.tip_follow_ready);
        assert!(!gates.sh_tip_ready);
        let joined = lines
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !joined.contains("scripthash.cold_progress"),
            "cancel warn named a resume file that is not on disk:\n{joined}"
        );
        assert!(
            joined.contains("cancelled before a durable scripthash extract"),
            "cancel warn should name the phase that actually exists:\n{joined}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
