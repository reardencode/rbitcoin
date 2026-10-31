//! Concurrent multi-peer block download (densify + per-peer inflight).
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
//! - Stall: 30s with no received block bytes on one peer → disconnect + cooldown.
//!   Tip motion is not an input. Every on-wire peer quiet in one pass is not a stall.
//! - Main-loop housekeeping is wall-clock cadenced (assign ≤50 ms, headers
//!   ≤500 ms, peer-slow/hygiene ≤1 s). Drain + confirm-offer stay event-driven.

#[doc(hidden)]
pub mod archive;
#[doc(hidden)]
pub mod assign;
#[doc(hidden)]
pub mod assign_plan;
#[doc(hidden)]
pub mod body;
#[doc(hidden)]
pub mod cadence;
#[doc(hidden)]
pub mod confirm;
#[doc(hidden)]
pub mod dial;
#[doc(hidden)]
pub mod events;
#[doc(hidden)]
pub mod exit;
#[doc(hidden)]
pub mod header_walk;
#[doc(hidden)]
pub mod path;
#[doc(hidden)]
pub mod peer_chain;
#[doc(hidden)]
pub mod peer_io;
#[doc(hidden)]
pub mod perf_log;
#[doc(hidden)]
pub mod progress;
#[doc(hidden)]
pub mod published;
#[doc(hidden)]
pub mod rate;
#[doc(hidden)]
pub mod reorg;
#[doc(hidden)]
pub mod state;
#[doc(hidden)]
pub mod status;

pub use perf_log::{read_platform_rss, tip_perf_json, ProcessRss, TipPerfLog};

use archive::{rehydrate_block_queue_into_confirm, rehydrate_class_a_into_body_queue};
pub use assign_plan::need_ready_headroom;
use assign_plan::want_headers_beyond_soft_cap;
use confirm::{offer_confirm_ready, spawn_confirm_engine, ConfirmEvent, ConfirmFeed};
#[cfg(debug_assertions)]
pub use confirm::{ConfirmRejectClass, RejectParent};

use assign::bq_pipeline_saturated;
pub use assign::{assign_work_ordered, AssignDepth};
use cadence::IbdLoopCadence;
use dial::{
    admit_cooldown_fallback, alive_dial_addrs, apply_dial_result, dial_batch, dial_blocked_addrs,
    disconnect_relative_slow_block_peers, disconnect_stalled_block_peers, expire_addr_cooldown,
    redial_want, release_peer_block_work,
};
pub use events::drain_ready_peer_and_body_events;
#[cfg(debug_assertions)]
pub use events::{apply_confirm_reject, apply_headers_event};
use events::{apply_peer_event, disconnect_all_peers, update_confirm_lag};
use exit::{
    all_peers_dead_action, best_chain_remainder, dark_empty_after, empty_path_header_fan,
    header_lag_behind_peers, ibd_caught_up, may_spawn_redial, path_drained,
    should_unlatch_headers_done, AllPeersDead,
};
pub use exit::{Peerless, PEERLESS_REDIAL_CAP};
#[cfg(debug_assertions)]
pub use header_walk::{
    candidate_tip, candidate_work, forget_walk_peer, header_poll, header_status_view,
    install_origin, load_origin, note_block_inv, note_reservation, origin_input, send_getheaders,
    settle_walk_peer, take_header_ask, HeaderPoll, HeaderPollIn,
};
pub use peer_io::{empty_header_fk_bus, PeerCmd, PeerEvent};
use peer_io::{sample_peer_rates, PeerEventSinks};
#[cfg(debug_assertions)]
pub use peer_io::{solicit_track, GetdataWire, PeerSlot};
#[cfg(debug_assertions)]
pub use progress::{log_progress_tick, StatusClock};
pub use progress::{read_progress_published, StatusSnap};
use progress::{spawn_status_thread, work_chain_progress_at, StatusBoard, TipRateTracker};
pub use published::spawn_header_thread;
pub use state::IbdWorkState;
use state::{enqueue_header_cmd, HeaderCmd};
pub use status::LoopStats;

use bitcoin::p2p::Magic;
use rbitcoin_log::{info, warn};
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::codec::MAX_HEADERS_RESULTS;
use rbitcoin_net::error::NetError;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Coordinator hold of `shared`. The flag drops with the guard.
struct HeldShared<'a> {
    guard: MutexGuard<'a, state::IbdWorkState>,
    _coord: rbitcoin_store::CoordSharedLock,
}

impl<'a> HeldShared<'a> {
    fn lock(shared: &'a std::sync::Mutex<state::IbdWorkState>) -> Self {
        let guard = shared.lock().unwrap_or_else(|err| err.into_inner());
        Self {
            guard,
            _coord: rbitcoin_store::CoordSharedLock::enter(),
        }
    }
}

impl std::ops::Deref for HeldShared<'_> {
    type Target = state::IbdWorkState;
    fn deref(&self) -> &state::IbdWorkState {
        &self.guard
    }
}

impl std::ops::DerefMut for HeldShared<'_> {
    fn deref_mut(&mut self) -> &mut state::IbdWorkState {
        &mut self.guard
    }
}

/// Off-path split heights are compared with the confirmed header. That
/// read is store IO, so `shared` is not held across it. A height that
/// appears while the lock is down is absent from the map and waits.
fn settle_off_path_splits<'a>(
    mut st_guard: HeldShared<'a>,
    shared: &'a std::sync::Mutex<state::IbdWorkState>,
    hub: &ChainHub,
) -> HeldShared<'a> {
    let off_path = header_walk::split_heights_off_path(&st_guard);
    if off_path.is_empty() {
        return st_guard;
    }
    drop(st_guard);
    let mut confirmed = HashMap::with_capacity(off_path.len());
    for height in off_path {
        confirmed.insert(height, peer_chain::confirmed_at(hub, height));
    }
    st_guard = HeldShared::lock(shared);
    header_walk::apply_split_confirms(&mut st_guard, &confirmed);
    st_guard
}

/// Same drop, read, and apply as the coordinator assign turn.
#[doc(hidden)]
pub fn settle_off_path_for_test(shared: &std::sync::Mutex<state::IbdWorkState>, hub: &ChainHub) {
    let st_guard = HeldShared::lock(shared);
    drop(settle_off_path_splits(st_guard, shared, hub));
}

/// A heavier-fork check reads headers. `shared` is down across that read.
/// No candidate keeps the lock. The commit waits until the header thread
/// is out of its own rewind, and it is skipped when that thread already
/// moved the tip.
fn settle_disconnected_heavier<'a>(
    st_guard: HeldShared<'a>,
    shared: &'a std::sync::Mutex<state::IbdWorkState>,
    hub: &ChainHub,
) -> HeldShared<'a> {
    let (cands, invalid) = match reorg::heavier_fork_candidates(&st_guard, hub) {
        Ok(pair) => pair,
        Err(_) => return st_guard,
    };
    if cands.is_empty() {
        return st_guard;
    }
    drop(st_guard);
    let _ = reorg::apply_off_lock_rewind(shared, hub, &cands, &invalid);
    HeldShared::lock(shared)
}

/// Apply confirm events, dropping `shared` while a mutated body clear waits
/// on the confirm-write thread. The post-clear updates run after the reply,
/// and only while this hash still occupies its height.
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn release_archived_clears<'a>(
    mut st_guard: HeldShared<'a>,
    shared: &'a std::sync::Mutex<state::IbdWorkState>,
    hub: &ChainHub,
    rx: &std::sync::mpsc::Receiver<confirm::ConfirmEvent>,
    archive_write_next: &AtomicU32,
    max_ready_shared: &AtomicU32,
    last_progress: &mut Instant,
    feed: Option<&confirm::ConfirmFeed>,
) -> HeldShared<'a> {
    let pending = events::take_confirm_events(
        &mut st_guard,
        hub,
        rx,
        archive_write_next,
        max_ready_shared,
        last_progress,
        feed,
    );
    if pending.is_empty() {
        return st_guard;
    }
    drop(st_guard);
    for item in &pending {
        events::send_deferred_archived_clear(hub.query.as_ref(), item);
    }
    st_guard = HeldShared::lock(shared);
    for item in pending {
        events::finish_deferred_archived_clear(&mut st_guard, Some(hub), &item);
    }
    st_guard
}

/// Drive confirm events the way the coordinator loop does.
#[doc(hidden)]
pub fn apply_confirm_events_for_test(
    shared: &std::sync::Mutex<state::IbdWorkState>,
    hub: &ChainHub,
    rx: &std::sync::mpsc::Receiver<confirm::ConfirmEvent>,
) {
    let write_next = AtomicU32::new(0);
    let max_ready = AtomicU32::new(0);
    let mut progress = Instant::now();
    let st_guard = HeldShared::lock(shared);
    let _ = release_archived_clears(
        st_guard,
        shared,
        hub,
        rx,
        &write_next,
        &max_ready,
        &mut progress,
        None,
    );
}

/// Same drop, header walk, and commit as the coordinator assign turn.
#[doc(hidden)]
pub fn settle_disconnected_heavier_for_test(
    shared: &std::sync::Mutex<state::IbdWorkState>,
    hub: &ChainHub,
) {
    let st_guard = HeldShared::lock(shared);
    drop(settle_disconnected_heavier(st_guard, shared, hub));
}

/// Default max **concurrent** unique block downloads (in-flight getdata).
///
/// Not a tip-distance ceiling: archive may run to the end of the known header
/// path; this only limits how many bodies we pull at once (backpressure + RAM).
pub const DEFAULT_IBD_WINDOW: usize = 1024;

/// Soft cap on `ordered` length while still requesting more headers.
/// Keeps header sync from unbounded growth if peers never signal done; large
/// enough for full signet / long mainnet catch-up in one run.
/// Hard ceiling on the ordered work path (memory / hygiene bound).
pub const MAX_ORDERED_HEADERS: usize = 500_000;
/// Soft cap: stop **requesting** more headers once we have this many on the path.
/// Multi-peer getheaders while `ordered` was 100k–500k flooded the main loop with
/// expensive Headers events (drain livelock → multi-minute freezes, getdata starved).
/// ~64k is ample cache for window=1024 archive race + tip holes.
pub const ORDERED_HEADERS_SOFT_CAP: usize = 64_000;

/// Max blocks in flight to a single peer.
///
/// Early blocks are small, so a fast peer can take a burst this wide. The
/// 16 MiB payload cap in assign stops the same peer holding 64 large bodies.
/// Total concurrency still scales with peer count.
pub const DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER: usize = 64;

/// Replay leftover in-RAM body-queue rows with a fresh work state.
///
/// IBD start runs the same drop / keep / empty / unknown rules on the live
/// loop state. A hub that is already serving uses this so those rules run
/// without a second store open.
pub fn rehydrate_block_queue_residue(hub: &ChainHub) -> Result<usize, String> {
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let feed = ConfirmFeed::new();
    rehydrate_block_queue_into_confirm(hub, &mut st, &feed)
}

/// Max contiguous tip+1.. holes to cover per assign.
pub const TIP_HOLE_MAX: usize = 32;
/// Max concurrent getdata peers for **tip+1** once the body queue is a quarter
/// of the confirm window or the configured assign-stop, or holds
/// [`rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS`] bodies (later contiguous holes
/// get 1).
///
/// Tip+1 freezes confirm while densify can run ahead; race enough peers so a
/// single slow peer cannot pin hole=1 for minutes (mainnet: tip stuck with
/// hole=1, conf_blks=0, bq growing). A gap below all three is the frontier,
/// not this race.
pub const TIP_HOLE_MAX_PEERS: usize = 4;
/// Max concurrent getdata peers for a **pre-hole** (first in-window gap after
/// a claim-ready prefix). One extra racer vs the frozen-prefix cap of 4.
pub const PRE_HOLE_MAX_PEERS: usize = 2;
/// Cap on IBD dial pool after getaddr learning (seeds + discovered).
///
/// Mainnet DNS seeds already return ~300–400 addrs. 256 refused all getaddr
/// once the seed book was larger than the cap. [`rbitcoin_net::seeds::MAX_ADDR_MAN`]
/// holds seeds plus learned addrs; `AddrMan::add_learned` evicts
/// incompatible/failed then oldest new when full so discovery continues.
/// `--connect` / DNS `AddrMan::add` may briefly exceed the cap when only
/// tried addrs remain.
pub const MAX_PEER_POOL: usize = rbitcoin_net::seeds::MAX_ADDR_MAN;
/// Pending (framed, not Class A) longer than this → re-getdata.
pub const PENDING_STALE: Duration = Duration::from_secs(45);
/// Cap height walk for densify candidates per assign tick (safety; filled
/// heights do not consume this — only the walk range does).
///
/// Must be ≥ [`CONTIG_DENSIFY_AHEAD`] so one assign can see the full densify
/// band when the body-queue byte budget still has room.
pub const FAR_SCAN_BUDGET: usize = 65_536;
/// Body-queue densify / receive horizon past tip+1 (height count).
///
/// **Primary capacity is soft densify assign** (under ~100 MiB free ahead; over
/// that only ~1 min of confirm work at tip rate). This height cap stops
/// unbounded far getdata when the soft window is large (e.g. very high tip
/// rate). Also used as the hard receive refuse horizon past tip.
pub const CONTIG_DENSIFY_AHEAD: u32 = 65_536;

/// Default [`IbdConfig::initial_dial_waves`]. A mainnet `--proxy` seed reply
/// took five waves of 32 to reach a first peer.
pub(crate) const DEFAULT_INITIAL_DIAL_WAVES: usize = 8;

/// Tunables for densify (per-peer inflight + confirm window).
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
    /// Initial dial waves before catch-up gives up with no peer. Each wave
    /// dials the next untried book rows; every miss is noted as a failed
    /// connect, so this bounds how much of the book one startup marks.
    pub initial_dial_waves: usize,
    /// No-peer policy for the initial dial and for a fully dark catch-up.
    pub peerless: Peerless,
    /// Optional shared peer book (discovered addrs + flags). Seeded at start and
    /// written back on IBD exit so the node can persist across runs.
    pub peers: Option<std::sync::Arc<std::sync::Mutex<rbitcoin_net::seeds::AddrMan>>>,
    /// Outbound TCP: direct or SOCKS5.
    pub dialer: rbitcoin_net::socks::Dialer,
    /// Densify assign-stop in bytes. `u64::MAX` is unlimited. The node sets
    /// it from `RBITCOIN_BLOCK_QUEUE_BYTES` / `RBITCOIN_BLOCK_QUEUE_GB`.
    pub assign_stop_bytes: u64,
    /// `--connect` targets. A session to one is a manual peer.
    pub connect: Vec<rbitcoin_net::NetAddr>,
}

impl Default for IbdConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_IBD_WINDOW,
            per_peer: DEFAULT_BLOCKS_IN_TRANSIT_PER_PEER,
            target_peers: rbitcoin_net::DEFAULT_IBD_TARGET_PEERS as usize,
            stall: Duration::from_secs(30),
            headers_batch: MAX_HEADERS_RESULTS,
            connect_timeout: Duration::from_secs(8),
            initial_dial_waves: DEFAULT_INITIAL_DIAL_WAVES,
            peerless: Peerless::GiveUp,
            peers: None,
            dialer: rbitcoin_net::socks::Dialer::Direct,
            assign_stop_bytes: rbitcoin_query::BQ_ASSIGN_STOP_BYTES,
            connect: Vec::new(),
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
            initial_dial_waves: DEFAULT_INITIAL_DIAL_WAVES,
            peerless: Peerless::GiveUp,
            peers: None,
            dialer: rbitcoin_net::socks::Dialer::Direct,
            assign_stop_bytes: rbitcoin_query::BQ_ASSIGN_STOP_BYTES,
            connect: Vec::new(),
        }
    }
}

/// Local IBD peer book that flushes back into [`IbdConfig::peers`] on drop.
#[doc(hidden)]
pub struct PeerBookSession {
    pub book: rbitcoin_net::seeds::AddrMan,
    pub shared: Option<std::sync::Arc<std::sync::Mutex<rbitcoin_net::seeds::AddrMan>>>,
}

impl PeerBookSession {
    #[doc(hidden)]
    pub fn new(
        shared: Option<std::sync::Arc<std::sync::Mutex<rbitcoin_net::seeds::AddrMan>>>,
        seed_peers: &[rbitcoin_net::NetAddr],
    ) -> Self {
        let mut book = if let Some(ref s) = shared {
            s.lock().unwrap_or_else(|e| e.into_inner()).clone()
        } else {
            rbitcoin_net::seeds::AddrMan::new()
        };
        for &addr in seed_peers {
            book.add_addr(addr);
        }
        Self { book, shared }
    }

    #[doc(hidden)]
    pub fn book(&self) -> &rbitcoin_net::seeds::AddrMan {
        &self.book
    }

    #[doc(hidden)]
    pub fn book_mut(&mut self) -> &mut rbitcoin_net::seeds::AddrMan {
        &mut self.book
    }

    #[doc(hidden)]
    pub fn flush(&self) {
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

#[doc(hidden)]
pub fn publish_status_snap(st: &IbdWorkState, hub: &ChainHub, board: &StatusBoard) {
    let headers = header_walk::header_status_view(st, hub);
    let peers = st.slots.iter().filter(|s| s.alive).count();
    board.publish(StatusSnap {
        peers,
        horizon: headers.horizon,
        hole: 0,
        header_origin: headers.origin,
        header_height: headers.height,
        header_stored: headers.stored,
        header_queue: headers.queue,
        header_work_ok: headers.work_ok,
        header_walk: headers.walk,
        header_quiet: headers.quiet,
    });
}

/// Sleep `delay` in short ticks. Returns true as soon as `cancelled` does.
async fn sleep_unless_cancelled(delay: Duration, cancelled: impl Fn() -> bool) -> bool {
    let until = Instant::now() + delay;
    while !cancelled() {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        tokio::time::sleep(left.min(Duration::from_millis(50))).await;
    }
    true
}

#[allow(clippy::cognitive_complexity)] // IBD coordination: dial, confirm, headers, stall
pub async fn ibd_cancellable(
    hub: Arc<ChainHub>,
    magic: Magic,
    local_addr: SocketAddr,
    peers: &[rbitcoin_net::NetAddr],
    cfg: IbdConfig,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    perms: Option<Arc<rbitcoin_net::peers::PeerHub>>,
) -> Result<u32, NetError> {
    struct IbdModeGuard(std::sync::Arc<rbitcoin_query::Query>);
    impl Drop for IbdModeGuard {
        fn drop(&mut self) {
            self.0.set_ibd_mode(false);
        }
    }
    hub.query.set_ibd_mode(true);
    let _ibd_mode_guard = IbdModeGuard(Arc::clone(&hub.query));

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
    let header_fks = empty_header_fk_bus();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,
        header_fks: Arc::clone(&header_fks),
    };

    // Nested `ibd-net` runtime panicked on SIGINT (`Cannot drop a runtime in an
    // async context`) when the outer select dropped this future.
    {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        info!(
            "ibd: tokio worker threads≈{workers} (peer decode: blocking pool; body queue: in-process; confirm: lookup+load+scripts+write OS threads)"
        );
    }
    let mut peer_sess = PeerBookSession::new(cfg.peers.clone(), peers);

    // Each initial dial wave — cap to ~2× live target (never the whole book).
    // With DNS/peers persistence the book can be 300+ addresses; dialing them all
    // at once saturates FDs and yields 100+ "ready" slots that immediately die.
    let initial_dial_n = cfg
        .target_peers
        .saturating_mul(2)
        .max(peers.len())
        .min(peer_sess.book().len())
        .max(1);
    // A wave that reaches no one dials the next untried addresses, up to
    // `initial_dial_waves` waves. After the last wave, `Peerless::GiveUp`
    // ends catch-up and `Peerless::Redial` waits and sweeps the book again.
    let mut boot_cooldown = HashMap::new();
    let mut boot_strikes = HashMap::new();
    let mut tried = HashSet::new();
    let mut waves = 0usize;
    let mut boot_dark = 0u32;
    let initial_slots = loop {
        waves += 1;
        let wave = dial_batch(
            peer_sess.book(),
            initial_dial_n,
            tried.clone(),
            &[],
            magic,
            local_addr,
            hub.tip_height(),
            sinks.clone(),
            cfg.connect_timeout,
            cancel.as_ref().map(Arc::clone),
            cfg.dialer.clone(),
            &hub.clock,
            perms.clone(),
            &cfg.connect,
        )
        .await;
        apply_dial_result(
            peer_sess.book_mut(),
            &wave,
            &mut boot_cooldown,
            &mut boot_strikes,
            Instant::now(),
        );
        tried.extend(wave.attempted.iter().copied());
        let mut slots = wave.slots;
        if cancelled() {
            warn!("ibd: cancel during initial dial — stopping");
            for s in &slots {
                let _ = s.cmd_tx.send(PeerCmd::Shutdown);
                s.task.abort();
            }
            return Ok(0);
        }
        slots.retain(|s| s.alive);
        if !slots.is_empty() {
            break slots;
        }
        if wave.attempted.is_empty() || waves >= cfg.initial_dial_waves {
            if cfg.peerless == Peerless::GiveUp {
                return Err(NetError::Protocol("no peers connected"));
            }
            if wave.attempted.is_empty() {
                tried.clear();
            }
            waves = 0;
            boot_dark = boot_dark.saturating_add(1);
            let delay = cfg.peerless.dark_delay(boot_dark);
            warn!(
                "ibd: no peer reachable ({} tried this sweep) — dialing again in {delay:?}",
                tried.len()
            );
            if sleep_unless_cancelled(delay, &cancelled).await {
                warn!("ibd: cancel during initial dial — stopping");
                return Ok(0);
            }
            continue;
        }
        info!(
            "ibd: no peer from {} dial(s) ({} tried) — dialing the next wave",
            wave.attempted.len(),
            tried.len()
        );
    };
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
    let mut tip_rate_tracker = TipRateTracker::new();
    tip_rate_tracker.push(Instant::now(), start_tip);
    let window = cfg.window;

    let mut st = IbdWorkState::new(initial_slots, hub.tip_hash(), hub.tip_height());
    for hash in hub.invalid_blocks() {
        st.reorg
            .invalid
            .mark(bitcoin::hashes::Hash::to_byte_array(hash));
    }
    st.addr_cooldown = boot_cooldown;
    st.addr_strikes = boot_strikes;
    st.perms = perms;
    header_walk::restore_adopt(&mut st, hub.as_ref());
    let (header_tx, header_rx) = tokio::sync::mpsc::channel(state::HEADER_CMD_BOUND);
    st.header_cmd = Some(header_tx.clone());

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
    st.confirm_feed = Some(Arc::clone(&confirm_feed));
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
    // A positive count is already logged inside `rehydrate_class_a_into_body_queue`
    // (a body-queue row or an archived body above the tip). This match only
    // speaks when that walk fills nothing.
    match rehydrate_class_a_into_body_queue(
        hub.as_ref(),
        &mut st,
        confirm_feed.as_ref(),
        TIP_HOLE_MAX,
    ) {
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
        &st.path_prev,
        &mut st.body,
        hub.as_ref(),
        &mut st.max_ready_height,
        &max_ready_shared,
    );
    update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);

    let shared = Arc::new(std::sync::Mutex::new(st));
    let header_probe = rbitcoin_store::HeaderThreadProbe::arm();
    rbitcoin_query::reset_header_lookups_under_coord_lock();
    let header_thread = spawn_header_thread(
        Arc::clone(&shared),
        Arc::clone(&hub),
        header_rx,
        header_fks,
        header_probe,
    );
    hub.query.publish_progress_snapshots();
    let _ = header_tx.try_send(HeaderCmd::Reseed);
    let _ = header_tx.try_send(HeaderCmd::Ask);

    let status_board = Arc::new(StatusBoard::new());
    let (status_stop_tx, status_stop_rx) = std::sync::mpsc::channel();
    let status_thread = spawn_status_thread(
        Arc::clone(&status_board),
        Arc::clone(&hub.query),
        Arc::clone(&confirm_queues),
        start_tip,
        status_stop_rx,
    );

    let mut loop_n = 0u32;
    let mut cadence = IbdLoopCadence::new();
    let mut halt_err: Option<String> = None;
    let mut give_up: Option<&'static str> = None;
    loop {
        if cancelled() {
            warn!("ibd: cancel requested — stopping IBD");
            break;
        }
        loop_n = loop_n.wrapping_add(1);
        if loop_n.is_multiple_of(8) {
            tokio::task::yield_now().await;
        }

        let pending_redial = {
            let mut st_guard = HeldShared::lock(&shared);
            let now_cadence = Instant::now();
            let tip_before_confirm = hub.tip_height();
            st_guard = release_archived_clears(
                st_guard,
                &shared,
                hub.as_ref(),
                &confirm_ev_rx,
                &archive_write_next,
                &max_ready_shared,
                &mut last_progress,
                Some(confirm_feed.as_ref()),
            );
            {
                let st = &mut *st_guard;
                if hub.tip_height() < tip_before_confirm {
                    confirm_feed.clear();
                }
                if let Some(msg) = st.halt.take() {
                    warn!("ibd: engine fault halt: {msg}");
                    halt_err = Some(msg);
                    break;
                }

                if !drain_ready_peer_and_body_events(
                    st,
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
                if cadence.hygiene_due(now_cadence, st.ordered_bloated()) {
                    st.hygiene();
                    cadence.mark_hygiene(now_cadence);
                }
            }

            if cadence.assign_due(now_cadence, st_guard.inflight.is_empty()) {
                let tip_rate_opt = tip_rate_tracker.eta_rate(now_cadence);
                let _ = hub.query.block_queue_update_soft_pressure(tip_rate_opt);
                let (bq_bytes, bq_count) = hub.query.block_queue_stats();
                let bq_window_covered = rbitcoin_query::soft_confirm_window_covered(
                    bq_count as u32,
                    bq_bytes,
                    tip_rate_opt,
                );
                let depth = if bq_pipeline_saturated(st_guard.inflight.len(), bq_window_covered) {
                    AssignDepth::Critical
                } else {
                    AssignDepth::Full
                };
                let tip_before_assign = hub.tip_height();
                st_guard = settle_off_path_splits(st_guard, &shared, hub.as_ref());
                st_guard = settle_disconnected_heavier(st_guard, &shared, hub.as_ref());
                assign_work_ordered(
                    &mut st_guard,
                    hub.as_ref(),
                    &cfg,
                    &loop_stats,
                    depth,
                    tip_rate_opt,
                );
                if hub.tip_height() < tip_before_assign {
                    confirm_feed.clear();
                }
                sample_peer_rates(&mut st_guard.slots, peer_io::ibd_mono_ms());
                cadence.mark_assign(now_cadence);
            }

            {
                let st = &mut *st_guard;
                offer_confirm_ready(
                    &confirm_feed,
                    &st.height_to_hash,
                    &st.path_prev,
                    &mut st.body,
                    hub.as_ref(),
                    &mut st.max_ready_height,
                    &max_ready_shared,
                );
                update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
            }
            st_guard = release_archived_clears(
                st_guard,
                &shared,
                hub.as_ref(),
                &confirm_ev_rx,
                &archive_write_next,
                &max_ready_shared,
                &mut last_progress,
                Some(confirm_feed.as_ref()),
            );
            let st = &mut *st_guard;
            if !drain_ready_peer_and_body_events(
                st,
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
            // A block inv is not a queue-depth event. Ask on this turn, not
            // after the 500 ms header period, or the announced header waits
            // behind a full queue.
            if hub.header_inv_challenge_pending() && header_walk::note_external_block_inv(st) {
                hub.clear_header_inv_challenge();
            }
            header_walk::probe_unprobed_peer(st, hub.as_ref());
            let challenge_due = header_walk::inv_challenge_due(st);
            if cadence.headers_due(now_cadence, path_empty, challenge_due) {
                let live = st.ordered_set.len();
                let known_ready = st.body.known_len();
                let ready_gap = st.max_ordered_height.saturating_sub(st.max_ready_height);
                let need_ready_headroom = need_ready_headroom(
                    want_headers_beyond_soft_cap(
                        live,
                        known_ready,
                        ready_gap,
                        (window as u32).saturating_mul(4).max(2048),
                    ),
                    st.header_walk.has_checkpoints(),
                );
                if should_unlatch_headers_done(st, hub.tip_height().unwrap_or(0)) {
                    st.headers_done = false;
                }
                let tip_h = hub.tip_height().unwrap_or(0);
                let lag = header_lag_behind_peers(st, tip_h);
                let min_cache = window.saturating_mul(8).max(4096);
                let alive = st.slots.iter().filter(|s| s.alive).count();
                let fan = empty_path_header_fan(st, tip_h, alive);
                match header_walk::header_poll(
                    st,
                    header_walk::HeaderPollIn {
                        live,
                        need_ready_headroom,
                        lag,
                        min_cache,
                        fan,
                    },
                ) {
                    header_walk::HeaderPoll::Ask => {
                        enqueue_header_cmd(st, HeaderCmd::Ask);
                    }
                    header_walk::HeaderPoll::LatchDone => {
                        st.headers_done = true;
                    }
                    header_walk::HeaderPoll::Wait => {}
                }
                cadence.mark_headers(now_cadence);
            }

            // Hard reset only when ordered is empty — a full queue still waiting on getdata is not stalled.
            if last_progress.elapsed() > cfg.stall.saturating_mul(6) && path_drained(st) {
                enqueue_header_cmd(st, HeaderCmd::Reseed);
                enqueue_header_cmd(st, HeaderCmd::Ask);
                info!(
                    "ibd: hard path reset (stall {:?}, st.ordered empty) ordered={}",
                    last_progress.elapsed(),
                    st.ordered.len()
                );
                st.headers_done = false;
                cadence.mark_headers(Instant::now());
                last_progress = Instant::now();
            }

            if cadence.peer_slow_due(now_cadence) {
                sample_peer_rates(&mut st.slots, peer_io::ibd_mono_ms());
                let now = Instant::now();
                let finished: Vec<usize> = st
                    .slots
                    .iter()
                    .filter(|s| s.alive && s.task.is_finished())
                    .map(|s| s.id)
                    .collect();
                let mut freed = Vec::new();
                for id in finished {
                    freed.extend(release_peer_block_work(
                        &mut st.slots,
                        &mut st.inflight,
                        &mut st.body,
                        id,
                    ));
                }
                freed.extend(disconnect_stalled_block_peers(
                    &mut st.slots,
                    &mut st.inflight,
                    &mut st.body,
                    &mut st.addr_cooldown,
                    &mut st.addr_strikes,
                    now,
                    cfg.stall,
                    &hub.clock,
                ));
                freed.extend(disconnect_relative_slow_block_peers(
                    &mut st.slots,
                    &mut st.inflight,
                    &mut st.body,
                    &mut st.addr_cooldown,
                    &mut st.addr_strikes,
                    now,
                    peer_sess.book(),
                    &mut st.relative_slow_suspect,
                    &mut st.relative_slow_last_kick_ms,
                ));
                st.reopen_for_densify(&freed);
                expire_addr_cooldown(
                    &mut st.addr_cooldown,
                    &mut st.addr_strikes,
                    peer_sess.book(),
                    now,
                );
                cadence.mark_peer_slow(now);
            }
            st.slots.retain(|s| s.alive);
            if redial_handle
                .as_ref()
                .map(|h| h.is_finished())
                .unwrap_or(false)
            {
                redial_handle.take()
            } else {
                None
            }
        };
        if let Some(h) = pending_redial {
            match h.await {
                Ok(result) => {
                    let mut st_guard = HeldShared::lock(&shared);
                    let st = &mut *st_guard;
                    apply_dial_result(
                        peer_sess.book_mut(),
                        &result,
                        &mut st.addr_cooldown,
                        &mut st.addr_strikes,
                        Instant::now(),
                    );
                    let blocked = dial_blocked_addrs(&st.slots, &st.addr_cooldown, Instant::now());
                    let mut n = 0usize;
                    for s in result.slots {
                        // Race: same addr may have connected on another path.
                        if blocked.contains(&s.net) || st.slots.iter().any(|x| x.net == s.net) {
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
                    let alive_now = st.slots.iter().filter(|s| s.alive).count();
                    dark_redial_empty = dark_empty_after(dark_redial_empty, n, alive_now > 0);
                    if n > 0 {
                        st.slots.sort_by_key(|s| s.id);
                        info!("ibd: redial added {n} peer(s); live={alive_now}");
                        if st.ordered.is_empty() && !st.headers_done {
                            enqueue_header_cmd(st, HeaderCmd::Ask);
                        }
                    } else if alive_now == 0 && cfg.peerless != Peerless::GiveUp {
                        last_redial = Instant::now();
                        warn!(
                            "ibd: redial returned 0 peers (empty_rounds={dark_redial_empty}) — no live peer, dialing again in {:?}",
                            cfg.peerless.dark_delay(dark_redial_empty)
                        );
                    } else {
                        warn!("ibd: redial returned 0 peers (empty_rounds={dark_redial_empty})");
                    }
                }
                Err(e) => warn!("ibd: redial task failed: {e}"),
            }
        }

        // When *all* peers are dead (network blip), do not wait for the 15s
        // interval — redial immediately so we never race the exit check.
        {
            let mut st_guard = HeldShared::lock(&shared);
            let st = &mut *st_guard;
            let alive_n = st.slots.iter().filter(|s| s.alive).count();
            let target = cfg.target_peers.max(1);
            let redial_interval = if alive_n == 0 {
                cfg.peerless.dark_delay(dark_redial_empty)
            } else {
                Duration::from_secs(15)
            };
            if redial_handle.is_none()
                && alive_n < target
                && may_spawn_redial(alive_n, dark_redial_empty, cfg.peerless)
                && !peer_sess.book().is_empty()
                && last_redial.elapsed() >= redial_interval
            {
                let want = redial_want(alive_n, target);
                let mut already = dial_blocked_addrs(&st.slots, &st.addr_cooldown, Instant::now());
                let occupied = alive_dial_addrs(&st.slots);
                let live: HashSet<_> = st.slots.iter().map(|s| s.net).collect();
                if let Some(addr) = admit_cooldown_fallback(
                    peer_sess.book(),
                    &mut already,
                    &occupied,
                    &st.addr_cooldown,
                    Instant::now(),
                    &live,
                ) {
                    info!("ibd: every candidate is cooling; retrying least-recent {addr}");
                }
                info!(
                "ibd: redialing up to {want} peers (alive={alive_n}/{target}, book={}, blocked={})…",
                peer_sess.book().len(),
                already.len()
            );
                let book = peer_sess.book().clone();
                let tip_h = hub.tip_height();
                let sinks_r = sinks.clone();
                let cto = cfg.connect_timeout;
                let cancel_c = cancel.as_ref().map(Arc::clone);
                let dialer_c = cfg.dialer.clone();
                let clock_c = Arc::clone(&hub.clock);
                let perms_c = st.perms.clone();
                let connect_c = cfg.connect.clone();
                redial_handle = Some(tokio::spawn(async move {
                    dial_batch(
                        &book, want, already, &occupied, magic, local_addr, tip_h, sinks_r, cto,
                        cancel_c, dialer_c, &clock_c, perms_c, &connect_c,
                    )
                    .await
                }));
                last_redial = Instant::now();
            }

            if last_status.elapsed() >= Duration::from_secs(5) {
                let now = Instant::now();
                let scan_t0 = Instant::now();
                let horizon = header_walk::peer_horizon(st);
                let published = read_progress_published(&hub.query);
                let prog = work_chain_progress_at(
                    hub.as_ref(),
                    published.tip,
                    &st.height_to_hash,
                    &mut st.body,
                    horizon,
                    st.max_ready_height,
                );
                loop_stats
                    .status_scan_ns
                    .fetch_add(scan_t0.elapsed().as_nanos() as u64, Ordering::Relaxed);

                let peers_n = st.slots.iter().filter(|s| s.alive).count();
                let (_load_q, script_q, write_q) = confirm_queues.snap();
                let path_lo = published.tip.map(|t| t.saturating_add(1)).unwrap_or(0);
                let inflight_h = {
                    let g = confirm_feed.inner.lock().unwrap();
                    g.inflight.clone()
                };
                let ready_n = confirm::confirm_ready_count(&hub.query, path_lo, &inflight_h);
                let (bq_bytes, bq_count) = hub.query.block_queue_stats();

                tip_rate_tracker.push(now, prog.tip);
                let eta_rate = tip_rate_tracker.eta_rate(now);
                let bq_soft_stop = rbitcoin_query::soft_confirm_window_n(eta_rate);
                let _ = hub.query.block_queue_update_soft_pressure(eta_rate);
                status_board.set_hole(prog.tip_hole);
                header_walk::retire_adopt_if_confirmed(st, &hub);
                let _ = std::io::Write::flush(&mut std::io::stderr());

                let peer_cap = peers_n.saturating_mul(cfg.per_peer);
                let inflight_cap = cfg.window.min(peer_cap).max(1);
                let ahead = prog
                    .ready_hwm
                    .saturating_sub(prog.tip)
                    .saturating_add(st.inflight.len() as u32);
                let conf_q_hwm = confirm_queues.sample_hwm_and_reset();
                let mut conf_pipe = confirm_queues.content_snap();
                let (feed_ready, feed_inflight) = confirm_feed.size_snap();
                conf_pipe.ready = ready_n;
                conf_pipe.feed_ready = feed_ready;
                conf_pipe.feed_inflight = feed_inflight;
                let work_sizes = st.structure_sizes();
                let owned_sizes = published.owned;
                let rss = perf_log::read_platform_rss();
                let perf = perf_log::sample(
                    &loop_stats,
                    st.inflight.len(),
                    inflight_cap,
                    (bq_bytes, bq_count, bq_soft_stop),
                    ahead,
                    prog.tip_hole,
                    peers_n,
                    st.headers_done,
                    ready_n,
                    script_q,
                    write_q,
                    conf_q_hwm,
                    published.sh_runs,
                    work_sizes,
                    owned_sizes,
                    conf_pipe,
                    rss,
                    hub.query.confirm_stats(),
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
                    warn!(
                    "ibd: tip stall tip={} hwm={} ordered_len={} feed_ready={} hole={} (idle {:?})",
                    prog.tip,
                    prog.ready_hwm,
                    st.ordered.len(),
                    feed_ready,
                    prog.tip_hole,
                    last_progress.elapsed(),
                );
                }
                last_status = Instant::now();
            }

            // Exit when the connected best chain has no remainder. Empty-EOF
            // (`headers_done`) means we do not chase advertised height (less-work
            // fork / bogus `version.start_height`). See `ibd_caught_up`.
            let tip_h = hub.tip_height().unwrap_or(0);
            if ibd_caught_up(st, tip_h) {
                offer_confirm_ready(
                    &confirm_feed,
                    &st.height_to_hash,
                    &st.path_prev,
                    &mut st.body,
                    hub.as_ref(),
                    &mut st.max_ready_height,
                    &max_ready_shared,
                );
                update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
                let tip_h = hub.tip_height().unwrap_or(0);
                if ibd_caught_up(st, tip_h) {
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
                match all_peers_dead_action(st, tip_h, redial_handle.is_some(), cfg.peerless) {
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
                        header_lag_behind_peers(st, tip_h),
                        accepted.load(Ordering::SeqCst),
                        dark_redial_empty
                    );
                        give_up = Some("all peers dead mid catch-up (not complete)");
                        break;
                    }
                    AllPeersDead::WaitRedial => {}
                }
            }
            publish_status_snap(st, hub.as_ref(), &status_board);
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
                let mut st_guard = HeldShared::lock(&shared);
                let st = &mut *st_guard;
                apply_peer_event(
                    st,
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
                let mut st_guard = HeldShared::lock(&shared);
                let st = &mut *st_guard;
                apply_peer_event(
                    st,
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
                let mut st_guard = HeldShared::lock(&shared);
                {
                    let st = &mut *st_guard;
                    offer_confirm_ready(
                        &confirm_feed,
                        &st.height_to_hash,
                        &st.path_prev,
                        &mut st.body,
                        hub.as_ref(),
                        &mut st.max_ready_height,
                        &max_ready_shared,
                    );
                    update_confirm_lag(&confirm_lag, hub.tip_height(), st.max_ready_height);
                }
                st_guard = release_archived_clears(
                    st_guard,
                    &shared,
                    hub.as_ref(),
                    &confirm_ev_rx,
                    &archive_write_next,
                    &max_ready_shared,
                    &mut last_progress,
                    Some(confirm_feed.as_ref()),
                );
                let st = &mut *st_guard;
                if let Some(msg) = st.halt.take() {
                    warn!("ibd: engine fault halt: {msg}");
                    halt_err = Some(msg);
                    break;
                }
                // Stall with an empty work path: only Ok-exit when truly caught up.
                // Previously this bare `break` treated "no progress for 30s at tip=0
                // while peers die" as success → node entered tip mode at height 0.
                if last_progress.elapsed() > cfg.stall
                    && st.ordered.is_empty()
                    && !best_chain_remainder(st, hub.tip_height().unwrap_or(0))
                {
                    let tip_h = hub.tip_height().unwrap_or(0);
                    if ibd_caught_up(st, tip_h) {
                        info!(
                            "ibd: catch-up complete (stall, path empty) tip={tip_h} max_peer_height={} — exiting IBD",
                            st.max_peer_height
                        );
                        break;
                    }
                    warn!(
                        "ibd: stall with empty path tip={tip_h} max_peer_height={} lag={} peers={} — re-request headers (not complete)",
                        st.max_peer_height,
                        header_lag_behind_peers(st, tip_h),
                        st.slots.iter().filter(|s| s.alive).count()
                    );
                    st.headers_done = false;
                    enqueue_header_cmd(st, HeaderCmd::Ask);
                    last_progress = Instant::now();
                }
            }
        }
    }

    let cancelled_exit = cancelled();
    let t_teardown = Instant::now();

    drop(status_stop_tx);
    let _ = status_thread.join();
    drop(header_tx);
    {
        let mut st = HeldShared::lock(&shared);
        st.header_cmd = None;
        disconnect_all_peers(&mut st);
    }
    if let Some(h) = redial_handle.take() {
        h.abort();
    }
    info!("ibd: peers disconnected in {:?}", t_teardown.elapsed());
    let _ = header_thread.join();

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
    if let Some(msg) = halt_err {
        return Err(NetError::Consensus(msg));
    }
    if let Some(msg) = give_up {
        return Err(NetError::Protocol(msg));
    }
    Ok(n)
}
