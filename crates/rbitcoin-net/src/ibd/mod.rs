//! Concurrent multi-peer block download (libbitcoin-class windowed IBD).
//!
//! **Unified height-ordered path (current):**
//! - N outbound peer workers (TCP + cmd/event channels); decode on blocking pool
//! - Peer offers wire into the durable **body queue** and notes height/hash readiness
//! - **Confirm** pipeline: lookup (stamp create_fk) → load (reload wire + pin) →
//!   scripts (CPU) → **write** as sole Class A appender + Class C tip; dequeue body queue after tip
//! - **Densify getdata** fills missing heights tip-first while body-queue bytes have
//!   room (`window` = in-flight cap, not tip-distance); tip-batch multi-peer race
//! - Peer frames land **raw** in the body queue (no peer full-block decode);
//!   confirm pack is the sole decode site for wire
//! - Stall: 30s with no block-download progress on a peer → disconnect + cooldown
//! - Main-loop housekeeping is wall-clock cadenced (assign ≤50 ms, headers
//!   ≤500 ms, peer-slow/hygiene ≤1 s). Drain + confirm-offer stay event-driven.

mod archive;
mod assign;
mod assign_plan;
mod body;
mod cadence;
mod confirm;
mod dial;
mod events;
mod exit;
mod path;
mod peer_io;
mod perf_log;
mod progress;
mod rate;
mod reorg;
mod state;
mod status;

pub use perf_log::{format_tip_perf_sizes, read_proc_rss, ProcRss, TipPerfSizes};

use archive::{rehydrate_block_queue_into_confirm, rehydrate_class_a_into_body_queue};
use assign_plan::{remove_from_ordered, want_headers_beyond_soft_cap};
use confirm::{offer_confirm_ready, spawn_confirm_engine, ConfirmEvent, ConfirmFeed};

use assign::{archive_pipeline_saturated, assign_work_ordered, AssignDepth};
use cadence::IbdLoopCadence;
use dial::{
    apply_dial_result, dial_batch, dial_blocked_addrs, disconnect_relative_slow_block_peers,
    disconnect_stalled_block_peers, expire_addr_cooldown, request_headers,
};
use events::{
    apply_confirm_reject, apply_peer_event, disconnect_all_peers,
    drain_ready_peer_and_archive_events, try_complete_awaiting_reorg, update_confirm_lag,
};
use exit::{
    all_peers_dead_action, best_chain_remainder, empty_path_header_fan, header_lag_behind_peers,
    ibd_caught_up, path_drained, should_unlatch_headers_done, AllPeersDead,
};
use path::{path_hashes_above_tip, seed_work_path_from_store, work_path_tips};
use peer_io::{sample_peer_rates, PeerCmd, PeerEvent, PeerEventSinks};
use progress::{
    claim_ready, format_progress_line, ibd_pct, work_chain_progress, ProgressLineInput,
    TipRateTracker,
};
use state::IbdWorkState;
use status::LoopStats;

use crate::chain::ChainHub;
use crate::codec::MAX_HEADERS_RESULTS;
use crate::error::NetError;
use bitcoin::p2p::Magic;
use rbitcoin_log::{info, info_bold, warn};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Default max **concurrent** unique block downloads (in-flight getdata).
///
/// Not a tip-distance ceiling: archive may run to the end of the known header
/// path; this only limits how many bodies we pull at once (backpressure + RAM).
pub const DEFAULT_IBD_WINDOW: usize = 1024;

/// Soft cap on `ordered` length while still requesting more headers.
/// Keeps header sync from unbounded growth if peers never signal done; large
/// enough for full signet / long mainnet catch-up in one run.
/// Hard ceiling on the ordered work path (memory / hygiene bound).
pub(crate) const MAX_ORDERED_HEADERS: usize = 500_000;
/// Soft cap: stop **requesting** more headers once we have this many on the path.
/// Multi-peer getheaders while `ordered` was 100k–500k flooded the main loop with
/// expensive Headers events (drain livelock → multi-minute freezes, getdata starved).
/// ~64k is ample cache for window=1024 archive race + tip holes.
pub(crate) const ORDERED_HEADERS_SOFT_CAP: usize = 64_000;

/// Max blocks in flight to a single peer (Core `MAX_BLOCKS_IN_TRANSIT_PER_PEER`).
///
/// Keeping this at 16 avoids overloading peers with large getdata batches; total
/// concurrency scales with peer count (`peers × 16`), not by piling work on few hosts.
pub const DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;

/// Max contiguous tip+1.. holes to cover per assign.
pub(crate) const TIP_HOLE_MAX: usize = 32;
/// Max concurrent getdata peers for one tip-hole hash.
///
/// Tip+1 freezes confirm while densify can run ahead; race enough peers so a
/// single slow peer cannot pin hole=1 for minutes (mainnet: tip stuck with
/// hole=1, conf_blks=0, bq growing).
pub(crate) const TIP_HOLE_MAX_PEERS: usize = 4;
/// Immediate tip-hole race size — full race up front (no 10s third-peer delay).
pub(crate) const TIP_HOLE_IMMEDIATE_PEERS: usize = 4;
/// Kept for API/tests: extra peers beyond immediate (unused when IMMEDIATE==MAX).
pub(crate) const TIP_HOLE_THIRD_PEER_AFTER: Duration = Duration::from_secs(5);
/// Cap on IBD dial pool after getaddr learning (seeds + discovered).
pub(crate) const MAX_PEER_POOL: usize = 256;
/// Pending (framed, not Class A) longer than this → re-getdata.
pub(crate) const PENDING_STALE: Duration = Duration::from_secs(45);
/// Cap height walk for densify candidates per assign tick (safety; filled
/// heights do not consume this — only the walk range does).
///
/// Must be ≥ [`CONTIG_DENSIFY_AHEAD`] so one assign can see the full densify
/// band when the body-queue byte budget still has room.
pub(crate) const FAR_SCAN_BUDGET: usize = 65_536;
/// Body-queue densify / receive horizon past tip+1 (height count).
///
/// **Primary capacity is soft densify assign** (under ~100 MiB free ahead; over
/// that only ~1 min of confirm work at tip rate). This height cap stops
/// unbounded far getdata when the soft window is large (e.g. very high tip
/// rate). Also used as the hard receive refuse horizon past tip.
pub(crate) const CONTIG_DENSIFY_AHEAD: u32 = 65_536;

/// Tunables for IBD (defaults lean libbitcoin/Core-ish).
#[derive(Clone, Debug)]
pub struct IbdConfig {
    /// Max concurrent unique block getdata (in-flight). Not tip-distance.
    pub window: usize,
    /// Hard cap on outstanding block getdata to one peer (Core = 16).
    pub per_peer: usize,
    /// Desired number of live download peers; we keep redialing until we reach this
    /// (or exhaust the candidate pool).
    pub target_peers: usize,
    /// Disconnect a peer (and reassign its getdata) if it has outstanding block
    /// requests and no block-download progress for this long.
    pub stall: Duration,
    /// Max headers to request per getheaders round-trip.
    pub headers_batch: usize,
    /// TCP connect + handshake timeout per peer.
    pub connect_timeout: Duration,
    /// Optional shared peer book (discovered addrs + flags). Seeded at start and
    /// written back on IBD exit so the node can persist across runs.
    pub peers: Option<std::sync::Arc<std::sync::Mutex<crate::seeds::AddrMan>>>,
}

impl Default for IbdConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_IBD_WINDOW,
            per_peer: DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER,
            target_peers: crate::DEFAULT_IBD_TARGET_PEERS as usize,
            stall: Duration::from_secs(30),
            headers_batch: MAX_HEADERS_RESULTS,
            connect_timeout: Duration::from_secs(8),
            peers: None,
        }
    }
}

impl IbdConfig {
    /// Smaller window / short dials for tests (no multi-second connect stalls).
    pub fn for_test() -> Self {
        Self {
            window: 32,
            per_peer: 8,
            target_peers: 4,
            stall: Duration::from_secs(3),
            headers_batch: MAX_HEADERS_RESULTS,
            connect_timeout: Duration::from_millis(400),
            peers: None,
        }
    }
}

/// Local IBD peer book that flushes back into [`IbdConfig::peers`] on drop.
struct PeerBookSession {
    book: crate::seeds::AddrMan,
    shared: Option<std::sync::Arc<std::sync::Mutex<crate::seeds::AddrMan>>>,
}

impl PeerBookSession {
    fn new(
        shared: Option<std::sync::Arc<std::sync::Mutex<crate::seeds::AddrMan>>>,
        seed_peers: &[SocketAddr],
    ) -> Self {
        let mut book = if let Some(ref s) = shared {
            s.lock().unwrap_or_else(|e| e.into_inner()).clone()
        } else {
            crate::seeds::AddrMan::new()
        };
        book.inject(seed_peers.iter().copied());
        Self { book, shared }
    }

    fn book(&self) -> &crate::seeds::AddrMan {
        &self.book
    }

    fn book_mut(&mut self) -> &mut crate::seeds::AddrMan {
        &mut self.book
    }

    fn flush(&self) {
        if let Some(ref s) = self.shared {
            if let Ok(mut g) = s.lock() {
                *g = self.book.clone();
            }
        }
    }
}

impl Drop for PeerBookSession {
    fn drop(&mut self) {
        self.flush();
    }
}

pub async fn ibd(
    hub: Arc<ChainHub>,
    magic: Magic,
    local_addr: SocketAddr,
    peers: &[SocketAddr],
    cfg: IbdConfig,
) -> Result<u32, NetError> {
    ibd_cancellable(hub, magic, local_addr, peers, cfg, None).await
}

/// Like [`ibd`], with an optional cancel flag polled each loop turn.
pub async fn ibd_cancellable(
    hub: Arc<ChainHub>,
    magic: Magic,
    local_addr: SocketAddr,
    peers: &[SocketAddr],
    cfg: IbdConfig,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<u32, NetError> {
    if peers.is_empty() {
        return Err(NetError::Protocol("no peers for ibd"));
    }
    let cancelled = || {
        cancel
            .as_ref()
            .map(|c| c.load(std::sync::atomic::Ordering::SeqCst))
            .unwrap_or(false)
    };

    hub.ensure_genesis()?;

    // Body events must not wait behind Headers (single-FIFO waste).
    let (body_tx, mut body_rx) = mpsc::unbounded_channel::<PeerEvent>();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<PeerEvent>();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,
    };

    // Nested `ibd-net` runtime panicked on SIGINT (`Cannot drop a runtime in an
    // async context`) when the outer select dropped this future.
    {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        info!(
            "ibd: tokio worker threads≈{workers} (peer decode: blocking pool; archive: 1 OS prep + 1 OS writer; confirm: lookup+load+scripts+write OS threads)"
        );
    }
    let mut peer_sess = PeerBookSession::new(cfg.peers.clone(), peers);
    let next_peer_id = Arc::new(AtomicUsize::new(0));

    // Initial concurrent dial — cap to ~2× live target (never the whole book).
    // With DNS/peers persistence the book can be 300+ addresses; dialing them all
    // at once saturates FDs and yields 100+ "ready" slots that immediately die.
    let initial_dial_n = cfg
        .target_peers
        .saturating_mul(2)
        .max(peers.len())
        .min(peer_sess.book().len())
        .max(1);
    let initial = dial_batch(
        peer_sess.book(),
        &next_peer_id,
        initial_dial_n,
        HashSet::new(),
        magic,
        local_addr,
        hub.tip_height(),
        sinks.clone(),
        cfg.connect_timeout,
        cancel.as_ref().map(Arc::clone),
    )
    .await;
    apply_dial_result(peer_sess.book_mut(), &initial);
    let mut initial_slots = initial.slots;
    if cancelled() {
        warn!("ibd: cancel during initial dial — stopping");
        for s in &initial_slots {
            let _ = s.cmd_tx.send(PeerCmd::Shutdown);
            s.task.abort();
        }
        return Ok(0);
    }
    initial_slots.retain(|s| s.alive);
    if initial_slots.is_empty() {
        return Err(NetError::Protocol("no peers connected"));
    }
    let init_peer_tip = initial_slots
        .iter()
        .map(|s| s.peer_height)
        .max()
        .unwrap_or(0);
    info!(
        "ibd: {} / {} peers ready (target={}, book={}, max_peer_height={})",
        initial_slots.len(),
        peers.len(),
        cfg.target_peers,
        peer_sess.book().len(),
        init_peer_tip
    );
    // Background redial — never .await dial on the IBD event loop (that stalled tip).
    let mut last_redial = Instant::now() - Duration::from_secs(15);
    let mut redial_handle: Option<JoinHandle<dial::DialBatchResult>> = None;
    let mut dark_redial_empty: u32 = 0;

    let accepted = Arc::new(AtomicU32::new(0));
    let start_tip = hub.tip_height().unwrap_or(0);
    let max_ready_shared = Arc::new(AtomicU32::new(start_tip));
    let confirm_lag = Arc::new(AtomicU32::new(0));
    let mut last_progress = Instant::now();
    let mut last_status = Instant::now();
    let mut last_sample_tip = start_tip;
    let mut tip_rate_tracker = TipRateTracker::new();
    tip_rate_tracker.push(Instant::now(), start_tip);
    let window = cfg.window;

    let mut st = IbdWorkState::new(initial_slots, hub.tip_hash(), hub.tip_height());
    seed_work_path_from_store(&mut st, hub.as_ref());

    // Channel may close if handshake races the first getheaders.
    for _ in 0..st.slots.len().min(4) {
        let tips = work_path_tips(&st);
        if request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips).unwrap_or(false) {
            break;
        }
    }

    let loop_stats = Arc::new(LoopStats::default());
    let store_class_a_bodies = hub.query.archived_block_count().unwrap_or(0);
    loop_stats
        .archived_bodies
        .store(store_class_a_bodies, Ordering::Relaxed);
    if store_class_a_bodies > 0 {
        info!("ibd: store has {store_class_a_bodies} Class A bodies (seed)");
    }
    let archive_write_next = Arc::new(AtomicU32::new(if hub.tip_height().is_some() {
        st.max_ready_height.saturating_add(1)
    } else {
        0
    }));
    let confirm_feed = Arc::new(ConfirmFeed::new());
    // Body queue is RAM-only; restart is empty. Same-process residual can still note feed.
    match rehydrate_block_queue_into_confirm(hub.as_ref(), &mut st, confirm_feed.as_ref()) {
        Ok(n) if n > 0 => {
            rbitcoin_log::debug!("ibd: rehydrate: noted {n} in-RAM body queue entries");
        }
        Ok(_) => {}
        Err(e) => {
            warn!("ibd: block_queue rehydrate failed (continuing; may re-getdata): {e}");
        }
    }
    match rehydrate_class_a_into_body_queue(
        hub.as_ref(),
        &mut st,
        confirm_feed.as_ref(),
        TIP_HOLE_MAX,
    ) {
        Ok(n) if n > 0 => {
            info!("ibd: Class A rehydrate filled {n} body-queue height(s) for tip batch");
        }
        Ok(0) => {
            rbitcoin_log::debug!(
                "ibd: Class A rehydrate filled 0 (tip+1 missing height map, has_block, or no Class A)"
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!("ibd: Class A rehydrate failed (continuing; may re-getdata): {e}");
        }
    }
    hub.query.clear_confirm_cancel();

    info!("ibd: confirm pipeline lookup+load+scripts+write (raw BQ wire; single Class A commit)");
    // Unbounded: SyncSender(512) deadlocked the confirm OS thread when the main
    // loop lagged on header drain (send blocks → tip frozen, hole=0, confirm_blks=0).
    let (confirm_ev_tx, confirm_ev_rx) = std::sync::mpsc::channel::<ConfirmEvent>();
    let (confirm_engine, confirm_queues) = spawn_confirm_engine(
        hub.clone(),
        Arc::clone(&confirm_feed),
        confirm_ev_tx,
        Arc::clone(&accepted),
        Arc::clone(&loop_stats),
    );
    offer_confirm_ready(
        &confirm_feed,
        &st.height_to_hash,
        &mut st.body,
        hub.as_ref(),
        &mut st.max_ready_height,
        &max_ready_shared,
    );
    update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);

    let mut loop_n = 0u32;
    let mut cadence = IbdLoopCadence::new();
    loop {
        if cancelled() {
            warn!("ibd: cancel requested — stopping IBD");
            break;
        }
        loop_n = loop_n.wrapping_add(1);
        if loop_n.is_multiple_of(8) {
            tokio::task::yield_now().await;
        }

        while let Ok(ev) = confirm_ev_rx.try_recv() {
            match ev {
                ConfirmEvent::Accepted { hash } => {
                    last_progress = Instant::now();
                    remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
                    st.body.mark_archived(hash);
                    let tip = hub.tip_height().unwrap_or(0);
                    archive_write_next.store(tip.saturating_add(1), Ordering::Relaxed);
                    st.max_ready_height = st.max_ready_height.max(tip);
                    max_ready_shared.store(st.max_ready_height, Ordering::Relaxed);
                }
                ConfirmEvent::Reject {
                    height,
                    hash,
                    err,
                    wire,
                } => {
                    apply_confirm_reject(
                        &mut st,
                        height,
                        hash,
                        &err,
                        Some(hub.query.as_ref()),
                        Some(hub.as_ref()),
                        wire,
                    );
                }
            }
        }

        if !drain_ready_peer_and_archive_events(
            &mut st,
            hub.as_ref(),
            &mut body_rx,
            &mut ctrl_rx,
            &archive_write_next,
            &loop_stats,
            peer_sess.book_mut(),
            local_addr,
            Some(confirm_feed.as_ref()),
        )? {
            break;
        }

        let tip_now = hub.tip_height().unwrap_or(0);
        while let Some(&front) = st.ordered.front() {
            let past = hub.has_block(&front)
                || st.hash_height.get(&front).is_some_and(|&ht| ht <= tip_now);
            if past {
                st.ordered.pop_front();
                st.ordered_set.remove(&front);
            } else {
                break;
            }
        }
        let now_cadence = Instant::now();
        if cadence.hygiene_due(now_cadence, st.ordered_bloated()) {
            st.hygiene();
            cadence.mark_hygiene(now_cadence);
        }

        if cadence.assign_due(now_cadence, st.inflight.is_empty()) {
            let tip_rate_opt = tip_rate_tracker.eta_rate(now_cadence);
            let _ = hub.query.block_queue_update_soft_pressure(tip_rate_opt);
            let (_bq_budget, bq_bytes, bq_count) = hub.query.block_queue_stats();
            let bq_window_covered = rbitcoin_query::soft_confirm_window_covered(
                bq_count as u32,
                bq_bytes,
                tip_rate_opt,
            );
            let write_next = archive_write_next.load(Ordering::Relaxed);
            let depth = if archive_pipeline_saturated(
                st.body.pending_len(),
                st.inflight.len(),
                bq_window_covered,
            ) {
                AssignDepth::Critical
            } else {
                AssignDepth::Full
            };
            assign_work_ordered(
                &mut st,
                hub.as_ref(),
                &cfg,
                &loop_stats,
                write_next,
                depth,
                tip_rate_opt,
            );
            sample_peer_rates(&mut st.slots, peer_io::ibd_mono_ms());
            cadence.mark_assign(now_cadence);
        }

        if st.reorg.awaiting().is_some() && try_complete_awaiting_reorg(&mut st, hub.as_ref()) {
            last_progress = Instant::now();
        }

        offer_confirm_ready(
            &confirm_feed,
            &st.height_to_hash,
            &mut st.body,
            hub.as_ref(),
            &mut st.max_ready_height,
            &max_ready_shared,
        );
        update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
        while let Ok(ev) = confirm_ev_rx.try_recv() {
            match ev {
                ConfirmEvent::Accepted { hash } => {
                    last_progress = Instant::now();
                    remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
                    st.body.mark_archived(hash);
                    let tip = hub.tip_height().unwrap_or(0);
                    archive_write_next.store(tip.saturating_add(1), Ordering::Relaxed);
                    st.max_ready_height = st.max_ready_height.max(tip);
                    max_ready_shared.store(st.max_ready_height, Ordering::Relaxed);
                }
                ConfirmEvent::Reject {
                    height,
                    hash,
                    err,
                    wire,
                } => {
                    apply_confirm_reject(
                        &mut st,
                        height,
                        hash,
                        &err,
                        Some(hub.query.as_ref()),
                        Some(hub.as_ref()),
                        wire,
                    );
                }
            }
        }
        if !drain_ready_peer_and_archive_events(
            &mut st,
            hub.as_ref(),
            &mut body_rx,
            &mut ctrl_rx,
            &archive_write_next,
            &loop_stats,
            peer_sess.book_mut(),
            local_addr,
            Some(confirm_feed.as_ref()),
        )? {
            break;
        }

        // Soft-cap `ordered_set` (not deque ghosts). Bypass only when the path is dense
        // (sparse far-ready used to look empty forever → header flood / drain livelock).
        // Full-batch continuation still fires from apply_peer_event; this is the poll.
        let path_empty = st.ordered.is_empty() && !st.headers_done;
        if cadence.headers_due(now_cadence, path_empty) {
            let live = st.ordered_set.len();
            let known_ready = st.body.known_len();
            let ready_gap = st.max_ordered_height.saturating_sub(st.max_ready_height);
            let need_ready_headroom = want_headers_beyond_soft_cap(
                live,
                known_ready,
                ready_gap,
                (window as u32).saturating_mul(4).max(2048),
            );
            let under_hard = live < MAX_ORDERED_HEADERS;
            let under_soft = live < ORDERED_HEADERS_SOFT_CAP;
            if should_unlatch_headers_done(&st, hub.tip_height().unwrap_or(0)) {
                st.headers_done = false;
            }
            if !st.headers_done && under_hard && (under_soft || need_ready_headroom) {
                let tip_h = hub.tip_height().unwrap_or(0);
                let lag = header_lag_behind_peers(&st, tip_h);
                let min_cache = window.saturating_mul(8).max(4096);
                let alive = st.slots.iter().filter(|s| s.alive).count();
                if live == 0 {
                    let fan = empty_path_header_fan(&st, tip_h, alive);
                    if fan == 0 {
                        st.headers_done = true;
                    } else {
                        let tips = work_path_tips(&st);
                        for _ in 0..fan {
                            if !request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips)
                                .unwrap_or(false)
                            {
                                break;
                            }
                        }
                    }
                } else {
                    let want_more = live < min_cache || lag > 0 || need_ready_headroom;
                    if want_more {
                        let tips = work_path_tips(&st);
                        let _ = request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips);
                    }
                }
            }
            cadence.mark_headers(now_cadence);
        }

        // Hard reset only when ordered is empty — a full queue still waiting on getdata is not stalled.
        // Explore leftover inflight is not idle-block; a live awaiting gather is.
        if last_progress.elapsed() > cfg.stall.saturating_mul(6)
            && path_drained(&st)
            && st.reorg.awaiting().is_none()
        {
            let tip_now = hub.tip_height().unwrap_or(0);
            let mut rebuilt = 0usize;
            for (_ht, h) in path_hashes_above_tip(&st, tip_now) {
                if hub.has_block(&h) || st.body.is_rejected(&h) {
                    continue;
                }
                if st.ordered.len() >= MAX_ORDERED_HEADERS {
                    break;
                }
                if st.ordered_set.insert(h) {
                    st.ordered.push_back(h);
                    rebuilt += 1;
                }
            }
            let before_seed = st.ordered.len();
            seed_work_path_from_store(&mut st, hub.as_ref());
            let seeded = st.ordered.len().saturating_sub(before_seed);
            info!(
                "ibd: hard path reset (stall {:?}, st.ordered empty) rebuilt={rebuilt} store_seeded={seeded} ordered={}",
                last_progress.elapsed(),
                st.ordered.len()
            );
            st.headers_done = false;
            let tips = work_path_tips(&st);
            let _ = request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips);
            cadence.mark_headers(Instant::now());
            last_progress = Instant::now();
        }

        if cadence.peer_slow_due(now_cadence) {
            sample_peer_rates(&mut st.slots, peer_io::ibd_mono_ms());
            let now = Instant::now();
            disconnect_stalled_block_peers(
                &mut st.slots,
                &mut st.inflight,
                &mut st.addr_cooldown,
                now,
                cfg.stall,
            );
            disconnect_relative_slow_block_peers(
                &mut st.slots,
                &mut st.inflight,
                &mut st.addr_cooldown,
                now,
                &mut st.relative_slow_suspect,
                &mut st.relative_slow_last_kick_ms,
            );
            expire_addr_cooldown(&mut st.addr_cooldown, now);
            cadence.mark_peer_slow(now);
        }
        st.slots.retain(|s| s.alive);

        if redial_handle
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(false)
        {
            if let Some(h) = redial_handle.take() {
                match h.await {
                    Ok(result) => {
                        apply_dial_result(peer_sess.book_mut(), &result);
                        let blocked =
                            dial_blocked_addrs(&st.slots, &st.addr_cooldown, Instant::now());
                        let mut n = 0usize;
                        for s in result.slots {
                            // Race: same addr may have connected on another path.
                            if blocked.contains(&s.addr)
                                || st.slots.iter().any(|x| x.addr == s.addr)
                            {
                                warn!(
                                    "ibd: drop duplicate/cooldown dial peer[{}] {}",
                                    s.id, s.addr
                                );
                                continue;
                            }
                            st.max_peer_height = st.max_peer_height.max(s.peer_height);
                            info!(
                                "ibd: peer[{}] {} connected (peer_height={})",
                                s.id, s.addr, s.peer_height
                            );
                            st.slots.push(s);
                            n += 1;
                        }
                        if n > 0 {
                            st.slots.sort_by_key(|s| s.id);
                            info!(
                                "ibd: redial added {n} peer(s); live={}",
                                st.slots.iter().filter(|s| s.alive).count()
                            );
                            dark_redial_empty = 0;
                            if st.ordered.is_empty() && !st.headers_done {
                                let tips = work_path_tips(&st);
                                let _ =
                                    request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips);
                            }
                        } else {
                            dark_redial_empty = dark_redial_empty.saturating_add(1);
                            warn!(
                                "ibd: redial returned 0 peers (empty_rounds={dark_redial_empty})"
                            );
                        }
                    }
                    Err(e) => warn!("ibd: redial task failed: {e}"),
                }
            }
        }

        // When *all* peers are dead (network blip), do not wait for the 15s
        // interval — redial immediately so we never race the exit check.
        let alive_n = st.slots.iter().filter(|s| s.alive).count();
        let target = cfg.target_peers.max(1);
        let redial_interval = if alive_n == 0 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs(15)
        };
        if redial_handle.is_none()
            && alive_n < target
            && !peer_sess.book().is_empty()
            && last_redial.elapsed() >= redial_interval
        {
            let want = (target - alive_n).min(8).max(1);
            let already = dial_blocked_addrs(&st.slots, &st.addr_cooldown, Instant::now());
            info!(
                "ibd: redialing up to {want} peers (alive={alive_n}/{target}, book={}, blocked={})…",
                peer_sess.book().len(),
                already.len()
            );
            let book = peer_sess.book().clone();
            let next_id = next_peer_id.clone();
            let tip_h = hub.tip_height();
            let sinks_r = sinks.clone();
            let cto = cfg.connect_timeout;
            let cancel_c = cancel.as_ref().map(Arc::clone);
            redial_handle = Some(tokio::spawn(async move {
                dial_batch(
                    &book, &next_id, want, already, magic, local_addr, tip_h, sinks_r, cto,
                    cancel_c,
                )
                .await
            }));
            last_redial = Instant::now();
        }

        if last_status.elapsed() >= Duration::from_secs(5) {
            let now = Instant::now();
            let window_secs = last_status.elapsed().as_secs_f64().max(0.001);
            let scan_t0 = Instant::now();
            let prog = work_chain_progress(
                hub.as_ref(),
                &st.height_to_hash,
                &mut st.body,
                st.max_peer_height,
                st.max_ready_height,
            );
            loop_stats
                .status_scan_ns
                .fetch_add(scan_t0.elapsed().as_nanos() as u64, Ordering::Relaxed);

            let tip_delta = prog.tip.saturating_sub(last_sample_tip);
            let tip_rate = tip_delta as f64 / window_secs;
            let peers_n = st.slots.iter().filter(|s| s.alive).count();
            let (load_q, script_q, write_q) = confirm_queues.snap();
            let path_lo = hub.tip_height().map(|t| t.saturating_add(1)).unwrap_or(0);
            let inflight_h = {
                let g = confirm_feed.inner.lock().unwrap();
                g.inflight.clone()
            };
            let ready_n = confirm::confirm_ready_count(&hub.query, path_lo, &inflight_h);
            let txs = hub.query.tx_body_count();
            let pct = ibd_pct(prog.tip, prog.headers);
            let (_bq_budget, bq_bytes, bq_count) = hub.query.block_queue_stats();

            tip_rate_tracker.push(now, prog.tip);
            let eta = tip_rate_tracker.eta_string(now, prog.tip, prog.headers);
            let eta_rate = tip_rate_tracker.eta_rate(now);
            let bq_soft_stop = rbitcoin_query::soft_confirm_window_n(eta_rate);
            let _ = hub.query.block_queue_update_soft_pressure(eta_rate);

            let conf_q = confirm::format_conf_q(
                load_q,
                script_q,
                write_q,
                confirm::load_queue_cap(),
                confirm::script_queue_cap(),
                confirm::write_queue_cap(),
            );
            let progress_line = format_progress_line(&ProgressLineInput {
                pct,
                tip: prog.tip,
                tip_rate,
                tip_hole: prog.tip_hole,
                peers: peers_n,
                conf_q,
                txs,
                horizon: prog.headers,
                eta,
                bq_bytes,
                bq_count,
                bq_soft_stop,
            });
            info_bold!("{progress_line}");
            let _ = std::io::Write::flush(&mut std::io::stderr());

            last_sample_tip = prog.tip;

            let peer_cap = peers_n.saturating_mul(cfg.per_peer);
            let inflight_cap = cfg.window.min(peer_cap).max(1);
            let ahead = prog
                .ready_hwm
                .saturating_sub(prog.tip)
                .saturating_add(st.inflight.len() as u32);
            let parent_cache_snap = hub.query.parent_cache_perf_snapshot();
            let conf_q_hwm = confirm_queues.sample_hwm_and_reset();
            let mut conf_pipe = confirm_queues.content_snap();
            let (feed_ready, feed_inflight) = confirm_feed.size_snap();
            conf_pipe.ready = ready_n;
            conf_pipe.feed_ready = feed_ready;
            conf_pipe.feed_inflight = feed_inflight;
            let work_sizes = st.structure_sizes();
            let owned_sizes = hub.query.process_owned_size_snapshot();
            let rss = perf_log::read_proc_rss();
            let perf = perf_log::sample(
                &loop_stats,
                st.inflight.len(),
                inflight_cap,
                (bq_bytes, bq_count, bq_soft_stop),
                ahead,
                prog.tip_hole,
                peers_n,
                st.headers_done,
                parent_cache_snap,
                ready_n,
                script_q,
                write_q,
                conf_q_hwm,
                hub.query.scripthash_run_count(),
                work_sizes,
                owned_sizes,
                conf_pipe,
                rss,
            );
            perf_log::log_sample(&perf);

            // Stall WARN only if the pipeline is idle. ready_n is BQ inventory, not occupancy.
            let conf_busy = feed_inflight > 0
                || script_q > 0
                || write_q > 0
                || loop_stats.confirm_live_snap().is_some();
            if last_progress.elapsed() > Duration::from_secs(15)
                && prog.tip_hole == 0
                && !conf_busy
                && st.inflight.is_empty()
                && prog.ready_hwm > prog.tip.saturating_add(1)
            {
                let expect = prog.tip.saturating_add(1);
                let hth = st.height_to_hash.get(&expect).copied();
                let ready = hth
                    .map(|h| claim_ready(hub.as_ref(), &mut st.body, expect, &h))
                    .unwrap_or(false);
                let has = hth.map(|h| hub.has_block(&h)).unwrap_or(false);
                let in_set = hth.map(|h| st.ordered_set.contains(&h)).unwrap_or(false);
                let noted = offer_confirm_ready(
                    &confirm_feed,
                    &st.height_to_hash,
                    &mut st.body,
                    hub.as_ref(),
                    &mut st.max_ready_height,
                    &max_ready_shared,
                );
                update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
                warn!(
                    "ibd: tip stall tip={} expect={expect} hth={} claim_ready={ready} has_block={has} \
                     in_ordered={in_set} offer_noted={noted} hwm={} ordered_len={} feed_ready={} \
                     (idle {:?})",
                    prog.tip,
                    hth.is_some(),
                    prog.ready_hwm,
                    st.ordered.len(),
                    feed_ready,
                    last_progress.elapsed(),
                );
            }
            last_status = Instant::now();
        }

        // Exit when the connected best chain has no remainder and peers are
        // not advertising a header hole. Never exit solely on headers_done
        // while max_peer_height still dwarfs our tip (signet: false
        // headers_done at h≈2000 with peers at ~313k). See `exit` module.
        let tip_h = hub.tip_height().unwrap_or(0);
        if ibd_caught_up(&st, tip_h) {
            offer_confirm_ready(
                &confirm_feed,
                &st.height_to_hash,
                &mut st.body,
                hub.as_ref(),
                &mut st.max_ready_height,
                &max_ready_shared,
            );
            update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
            let tip_h = hub.tip_height().unwrap_or(0);
            if ibd_caught_up(&st, tip_h) {
                info!(
                    "ibd: catch-up complete tip={tip_h} max_peer_height={} max_ready={} headers_done={} — exiting IBD",
                    st.max_peer_height, st.max_ready_height, st.headers_done
                );
                break;
            }
        }
        // All peers dead — never treat mid-chain peer death as catch-up complete.
        if st.slots.iter().all(|s| !s.alive) {
            let tip_h = hub.tip_height().unwrap_or(0);
            match all_peers_dead_action(&st, tip_h, redial_handle.is_some(), dark_redial_empty) {
                AllPeersDead::CatchupComplete => {
                    info!(
                        "ibd: catch-up complete (no live peers) tip={tip_h} max_peer_height={} max_ready={} — exiting IBD",
                        st.max_peer_height, st.max_ready_height
                    );
                    break;
                }
                AllPeersDead::GiveUpMidCatchup => {
                    warn!(
                        "ibd: all peers dead mid catch-up tip={tip_h} max_peer_height={} lag={} accepted={} empty_redials={} — giving up (not tip mode)",
                        st.max_peer_height,
                        header_lag_behind_peers(&st, tip_h),
                        accepted.load(Ordering::SeqCst),
                        dark_redial_empty
                    );
                    return Err(NetError::Protocol(
                        "all peers dead mid catch-up (not complete)",
                    ));
                }
                AllPeersDead::WaitRedial => {}
            }
        }

        let tick = tokio::time::sleep(Duration::from_millis(50));
        tokio::pin!(tick);
        tokio::select! {
            biased;
            peer_ev = body_rx.recv() => {
                if cancelled() {
                    warn!("ibd: cancel requested — stopping IBD");
                    break;
                }
                let Some(ev) = peer_ev else { break };
                apply_peer_event(
                    &mut st,
                    hub.as_ref(),
                    ev,
                    &archive_write_next,
                    peer_sess.book_mut(),
                    local_addr,
                    Some(confirm_feed.as_ref()),
                );
            }
            peer_ev = ctrl_rx.recv() => {
                if cancelled() {
                    warn!("ibd: cancel requested — stopping IBD");
                    break;
                }
                let Some(ev) = peer_ev else { break };
                apply_peer_event(
                    &mut st,
                    hub.as_ref(),
                    ev,
                    &archive_write_next,
                    peer_sess.book_mut(),
                    local_addr,
                    Some(confirm_feed.as_ref()),
                );
            }
            _ = &mut tick => {
                if cancelled() {
                    warn!("ibd: cancel requested — stopping IBD");
                    break;
                }
                offer_confirm_ready(
                    &confirm_feed,
                    &st.height_to_hash,
                    &mut st.body,
                    hub.as_ref(),
                    &mut st.max_ready_height,
                    &max_ready_shared,
                );
                update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
                        while let Ok(ev) = confirm_ev_rx.try_recv() {
                    match ev {
                        ConfirmEvent::Accepted { hash } => {
                            last_progress = Instant::now();
                            remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
                            st.body.mark_archived(hash);
                            let tip = hub.tip_height().unwrap_or(0);
                            archive_write_next.store(tip.saturating_add(1), Ordering::Relaxed);
                            st.max_ready_height = st.max_ready_height.max(tip);
                            max_ready_shared.store(st.max_ready_height, Ordering::Relaxed);
                        }
                        ConfirmEvent::Reject {
                            height,
                            hash,
                            err,
                            wire,
                        } => {
                            apply_confirm_reject(
                                &mut st,
                                height,
                                hash,
                                &err,
                                Some(hub.query.as_ref()),
                                Some(hub.as_ref()),
                                wire,
                            );
                        }
                    }
                }
                // Stall with an empty work path: only Ok-exit when truly caught up.
                // Previously this bare `break` treated "no progress for 30s at tip=0
                // while peers die" as success → node entered tip mode at height 0.
                if last_progress.elapsed() > cfg.stall
                    && st.ordered.is_empty()
                    && !best_chain_remainder(&st, hub.tip_height().unwrap_or(0))
                {
                    let tip_h = hub.tip_height().unwrap_or(0);
                    if ibd_caught_up(&st, tip_h) {
                        info!(
                            "ibd: catch-up complete (stall, path empty) tip={tip_h} max_peer_height={} — exiting IBD",
                            st.max_peer_height
                        );
                        break;
                    }
                    warn!(
                        "ibd: stall with empty path tip={tip_h} max_peer_height={} lag={} peers={} — re-request headers (not complete)",
                        st.max_peer_height,
                        header_lag_behind_peers(&st, tip_h),
                        st.slots.iter().filter(|s| s.alive).count()
                    );
                    st.headers_done = false;
                    let tips = work_path_tips(&st);
                    let _ = request_headers(&st.slots, &hub, &mut st.header_req_seq, &tips);
                    last_progress = Instant::now();
                }
            }
        }
    }

    let cancelled_exit = cancelled();
    let t_teardown = Instant::now();

    disconnect_all_peers(&mut st);
    if let Some(h) = redial_handle.take() {
        h.abort();
    }
    info!("ibd: peers disconnected in {:?}", t_teardown.elapsed());

    // Always join confirm before return (no ghost rejects after "clean exit").
    confirm_feed.request_stop();
    hub.query.request_confirm_cancel();

    info!(
        "ibd: waiting for confirm engine to stop ({:?})…",
        t_teardown.elapsed()
    );
    let confirm_join = tokio::task::spawn_blocking(move || {
        let _ = confirm_engine.join();
    });
    let mut confirm_join = confirm_join;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), &mut confirm_join).await {
            Ok(Ok(())) => {
                info!("ibd: confirm engine stopped ({:?})", t_teardown.elapsed());
                break;
            }
            Ok(Err(e)) => {
                warn!("ibd: confirm join task: {e}");
                break;
            }
            Err(_) => {
                warn!(
                    "ibd: still waiting for confirm engine ({:?})…",
                    t_teardown.elapsed()
                );
            }
        }
    }

    let n = accepted.load(Ordering::SeqCst);
    info!(
        "ibd: done accepted={n} tip={:?} (started {start_tip}, cancelled={cancelled_exit}, teardown={:?})",
        hub.tip_height(),
        t_teardown.elapsed()
    );
    Ok(n)
}

#[cfg(test)]
mod peer_book_and_config_tests {
    use super::{IbdConfig, PeerBookSession};
    use crate::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    fn sa(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, o)), 18444)
    }

    #[test]
    fn ibd_config_default_and_for_test() {
        let d = IbdConfig::default();
        assert!(d.window > 0);
        assert!(d.per_peer > 0);
        assert!(d.target_peers > 0);
        assert!(d.stall.as_secs() >= 1);
        let t = IbdConfig::for_test();
        assert_eq!(t.window, 32);
        assert_eq!(t.per_peer, 8);
        assert_eq!(t.target_peers, 4);
        assert!(t.connect_timeout.as_millis() < 1000);
        assert!(t.peers.is_none());
    }

    #[test]
    fn peer_book_session_injects_seeds_and_flushes_on_drop() {
        let shared = Arc::new(Mutex::new(AddrMan::new()));
        {
            let mut sess = PeerBookSession::new(Some(Arc::clone(&shared)), &[sa(1), sa(2)]);
            assert!(sess.book().entry(&sa(1)).is_some());
            assert!(sess.book().entry(&sa(2)).is_some());
            // Mutate book via book_mut.
            sess.book_mut().add(sa(3));
            assert!(sess.book().entry(&sa(3)).is_some());
            // Shared not yet flushed until drop/flush.
            assert!(shared.lock().unwrap().entry(&sa(3)).is_none());
            sess.flush();
            assert!(shared.lock().unwrap().entry(&sa(3)).is_some());
        }
        // Drop flushes again (idempotent).
        assert!(shared.lock().unwrap().entry(&sa(1)).is_some());

        // No shared book — seeds only, flush is a no-op.
        let sess2 = PeerBookSession::new(None, &[sa(9)]);
        assert!(sess2.book().entry(&sa(9)).is_some());
        sess2.flush();
    }
}

#[cfg(test)]
mod tip_hole_race_tests {
    use super::assign::tip_hole_peer_target;
    use super::{TIP_HOLE_IMMEDIATE_PEERS, TIP_HOLE_MAX_PEERS};
    use std::time::{Duration, Instant};

    #[test]
    fn tip_hole_targets_full_race_immediately() {
        let now = Instant::now();
        // Full multi-peer race for tip+1 — do not wait 10s while densify fills bq.
        assert_eq!(tip_hole_peer_target(0, None, now), TIP_HOLE_IMMEDIATE_PEERS);
        assert_eq!(tip_hole_peer_target(1, None, now), TIP_HOLE_IMMEDIATE_PEERS);
        assert_eq!(
            tip_hole_peer_target(TIP_HOLE_IMMEDIATE_PEERS - 1, None, now),
            TIP_HOLE_IMMEDIATE_PEERS
        );
        assert_eq!(TIP_HOLE_IMMEDIATE_PEERS, TIP_HOLE_MAX_PEERS);
    }

    #[test]
    fn tip_hole_caps_at_max_peers() {
        let t0 = Instant::now();
        assert_eq!(
            tip_hole_peer_target(TIP_HOLE_MAX_PEERS, Some(t0), t0 + Duration::from_secs(60)),
            TIP_HOLE_MAX_PEERS
        );
        assert_eq!(
            tip_hole_peer_target(
                TIP_HOLE_MAX_PEERS + 5,
                Some(t0),
                t0 + Duration::from_secs(60)
            ),
            TIP_HOLE_MAX_PEERS
        );
    }
}

#[cfg(test)]
mod archive_sat_tests {
    use super::assign::archive_pipeline_saturated;

    #[test]
    fn archive_pipeline_saturated_gates_full_assign() {
        assert!(!archive_pipeline_saturated(0, 0, false));
        assert!(!archive_pipeline_saturated(200, 32, true));
        assert!(!archive_pipeline_saturated(96, 0, false));
        assert!(archive_pipeline_saturated(0, 0, true));
        assert!(archive_pipeline_saturated(200, 15, true));
    }
}
