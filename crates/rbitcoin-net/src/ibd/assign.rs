//! Getdata assign for the **unified body-queue → lookup → load → scripts → write** path.
//!
//! Policy (operator-facing):
//! - **Tip batch** (tip+1 .. tip+[`TIP_HOLE_MAX`]=32, one confirm run): always
//!   request missing hashes (even if soft body-queue depth is over free floor).
//!   Multi-peer race up to [`TIP_HOLE_MAX_PEERS`] **on tip+1 only** when the
//!   body queue meets any of: 1/4 of the confirm-time block window, 1/4 of
//!   the configured assign-stop (default 1 GiB), or
//!   [`rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS`] bodies. Fullness is the
//!   queue's total blocks and bytes; gaps count. Below all three the gap is
//!   the frontier: one owner, and densify continues. Ranked by expected
//!   drain time (`(queue+1)/bps`), not queue count. Later contiguous holes
//!   in that gap get one racer until the prefix is in hand. An owner
//!   with other inflight hashes still has densify in the peer FIFO — drop them
//!   from this hash (getdata cannot be cancelled) and race a peer that can
//!   start the hole. Confirm is frozen until tip+1 is claim-ready.
//!   When that prefix is in hand, at most one extra racer on the **first**
//!   later gap in the 32-window, and only if that owner is missing, aged, or
//!   ≤ pack-median/4.
//! - **Densify** (tip+1 outward, closest first): fill missing heights up to
//!   [`CONTIG_DENSIFY_AHEAD`]. Two soft assign limits (no hysteresis):
//!   - BQ payload **≤ ~100 MiB** → usual densify ahead to the height horizon
//!   - BQ payload **> ~100 MiB** → only heights confirm will consume in the
//!     next **~1 min** at current tip rate ([`rbitcoin_query::soft_densify_band_hi`])
//!   - BQ payload **≥ assign-stop** (default 1 GiB) → holes only within the
//!     ~1 min tip-rate window **and** not past fetched_hi (do not grow past
//!     fetched; do not densify far holes outside the window)
//!   - While a quarter-full tip hole is open: **no new densify** (cap 0) so
//!     peer getdata queues can drain for tip+1. A thinner queue is the
//!     frontier and densify keeps filling ahead.
//! - Never request beyond densify horizon; events refuse far bodies too.
//! - One body-queue copy per height (receive path drops duplicates).

use super::assign_plan::densify_slots_for_peer;
use super::dial::{
    median_u64, relative_slow_pick, RelativeSlowSample, RELATIVE_SLOW_CLUSTER_SPREAD,
};
use super::peer_io::{ibd_mono_ms, PeerCmd, PeerSlot};
use super::state::{self, IbdWorkState};
use super::status::LoopStats;
use super::{
    IbdConfig, CONTIG_DENSIFY_AHEAD, FAR_SCAN_BUDGET, PENDING_STALE, PRE_HOLE_MAX_PEERS,
    TIP_HOLE_MAX, TIP_HOLE_MAX_PEERS,
};
use crate::chain::ChainHub;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// After this long with no confirm progress and nothing useful to fetch, stop getdata.
pub(crate) const STUCK_GATE_AFTER: Duration = Duration::from_secs(30);

/// True when confirm cannot advance and there is no valid body still worth fetching.
pub(crate) fn download_gate_closed(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let Some(since) = st.confirm_stuck_since else {
        return false;
    };
    if since.elapsed() < STUCK_GATE_AFTER {
        return false;
    }
    !need_any_valid_body_download(st, hub)
}

fn need_any_valid_body_download(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let tip = hub.tip_height().unwrap_or(0);
    let path_lo = if hub.tip_height().is_none() {
        0u32
    } else {
        tip.saturating_add(1)
    };
    let occupant_dead = st
        .height_to_hash
        .get(&path_lo)
        .is_some_and(|h| need_body_dead(st, h));
    if need_path_lo_alt(st, hub, path_lo) {
        return true;
    }
    if occupant_dead {
        return false;
    }
    if need_contig_ahead(st, hub, path_lo) {
        return true;
    }
    need_reorg_getdata(st, hub)
}

fn need_body_dead(st: &IbdWorkState, h: &BlockHash) -> bool {
    st.reorg.invalid.contains(h.to_byte_array()) || st.body.is_rejected(h)
}

fn need_body_in_hand(st: &IbdWorkState, hub: &ChainHub, h: &BlockHash) -> bool {
    hub.has_block(h)
        || st.body.is_known_archived(h)
        || hub.query.block_queue_has_hash(&h.to_byte_array())
}

fn need_path_lo_alt(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
    for (&h, &ht) in &st.hash_height {
        if ht != path_lo {
            continue;
        }
        if need_body_dead(st, &h) {
            continue;
        }
        if need_body_in_hand(st, hub, &h) {
            continue;
        }
        return true;
    }
    false
}

fn need_contig_ahead(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
    for ht in path_lo..=path_lo.saturating_add(CONTIG_DENSIFY_AHEAD) {
        let Some(&h) = st.height_to_hash.get(&ht) else {
            break;
        };
        if need_body_dead(st, &h) {
            continue;
        }
        if hub.has_block(&h) {
            continue;
        }
        if st.body.is_known_archived(&h) || hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        return true;
    }
    false
}

fn need_reorg_getdata(st: &IbdWorkState, hub: &ChainHub) -> bool {
    for h in st.reorg.need_getdata() {
        if need_body_dead(st, &h) {
            continue;
        }
        if hub.has_block(&h) || hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        return true;
    }
    false
}

/// How much assign work to do this call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssignDepth {
    /// Tip-batch multi-peer only (BQ soft window covered / no densify room).
    Critical,
    /// Tip batch + densify (gap always; frontier when soft depth allows).
    Full,
}

/// Drop `hash` from global inflight and every peer's in_flight set.
pub(crate) fn clear_hash_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hash: BlockHash,
) {
    inflight.remove(&hash);
    for s in slots.iter_mut() {
        s.in_flight.remove(&hash);
    }
}

/// Free peer/global slots for hashes already on the confirmed tip (RAM set).
pub(crate) fn prune_satisfied_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hub: &ChainHub,
) {
    inflight.retain(|h, _| !hub.has_block(h));
    for s in slots.iter_mut() {
        s.in_flight.retain(|h| !hub.has_block(h));
    }
}

/// Drop getdata that cannot feed the work path or a live awaiting-reorg gather.
///
/// Speculative `explore_need` is not kept: assign re-issues it while remainder
/// is live. Off-path leftovers otherwise sat in inflight forever (mainnet
/// 08:16:23 / 04:14).
pub(crate) fn prune_off_path_inflight(st: &mut IbdWorkState) {
    let drop: Vec<BlockHash> = st
        .inflight
        .keys()
        .copied()
        .filter(|h| {
            if st.ordered_set.contains(h) {
                return false;
            }
            if let Some(&ht) = st.hash_height.get(h) {
                if st.is_on_path(h, ht) {
                    return false;
                }
            }
            true
        })
        .collect();
    for h in drop {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, h);
    }
}

/// Record `peer` as requesting `hash` (tip-hole / park race may accumulate peers).
pub(crate) fn inflight_add_peer(
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hash: BlockHash,
    peer: usize,
) {
    inflight
        .entry(hash)
        .or_insert_with(|| state::InflightReq::new(peer))
        .add_peer(peer);
}

/// True when soft BQ confirm window is already covered and getdata inflight
/// is low → Critical (tip race only, skip densify walk).
pub(crate) fn bq_pipeline_saturated(inflight_len: usize, bq_confirm_window_covered: bool) -> bool {
    inflight_len < 16 && bq_confirm_window_covered
}

/// Assign getdata for the body-queue pipeline.
///
/// `tip_rate_blocks_per_s`: tip confirm rate for the soft confirm-time window
/// when BQ payload is over [`rbitcoin_query::BQ_SOFT_FREE_BYTES`].
pub(crate) fn assign_work_ordered(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    loop_stats: &LoopStats,
    depth: AssignDepth,
    tip_rate_blocks_per_s: Option<f64>,
) {
    let t0 = Instant::now();
    let mut issued = 0u64;
    let alive = super::header_walk::peers_for_blocks(st);
    if alive.is_empty() {
        return;
    }

    let (bq_stop, bq_bytes, bq_count) = hub.query.block_queue_stats();
    st.intake_stop = bq_stop;
    st.intake_queued = bq_bytes;

    if download_gate_closed(st, hub) {
        static GATE_LOG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = GATE_LOG.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 3 || n.is_multiple_of(50) {
            rbitcoin_log::warn!(
                "ibd: download gate closed (confirm stuck {:?}, no valid body to fetch, n={n})",
                st.confirm_stuck_since
                    .map(|t| t.elapsed())
                    .unwrap_or_default()
            );
        }
        finish_assign(loop_stats, t0, 0);
        return;
    }

    prune_satisfied_inflight(&mut st.slots, &mut st.inflight, hub);
    prune_off_path_inflight(st);

    let _ = super::reorg::consider_disconnected_heavier(st, hub);

    let tip = hub.tip_height().unwrap_or(0);
    let path_lo = if hub.tip_height().is_none() {
        0u32
    } else {
        tip.saturating_add(1)
    };
    let tip_batch_hi = path_lo.saturating_add(TIP_HOLE_MAX.saturating_sub(1) as u32);

    // Stale pending in tip batch only → re-get (don't thrash far pending).
    let tip_expired = st.body.expire_stale_pending_if(PENDING_STALE, |h| {
        st.hash_height
            .get(h)
            .is_some_and(|&ht| ht >= path_lo && ht <= tip_batch_hi)
    });
    for h in tip_expired {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, h);
    }

    let tip_holes = contiguous_tip_holes(st, hub, TIP_HOLE_MAX);
    let ahead_n = u32::try_from(bq_count).unwrap_or(u32::MAX);
    let race_tip = !tip_holes.is_empty()
        && rbitcoin_query::soft_ahead_quarter_full(
            ahead_n,
            bq_bytes,
            tip_rate_blocks_per_s,
            bq_stop,
        );
    if race_tip {
        issued += cover_tip_batch_holes(st, hub, cfg, &alive, &tip_holes);
    }
    if tip_holes.is_empty() {
        issued += cover_first_pre_hole(st, hub, cfg, &alive);
    }
    issued += assign_reorg_need(st, hub, cfg, &alive);

    if matches!(depth, AssignDepth::Critical) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    assign_densify(
        st,
        hub,
        cfg,
        &alive,
        DensifyCtx {
            loop_stats,
            t0,
            issued,
            path_lo,
            tip_batch_hi,
            race_tip,
            tip_rate_blocks_per_s,
        },
    );
}

fn assign_reorg_need(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
) -> u64 {
    let reorg_need = st.reorg.need_getdata();
    if reorg_need.is_empty() {
        return 0;
    }
    use bitcoin::hashes::Hash as _;
    let reserve = reorg_need.len().min(8);
    let mut room = cfg.window.saturating_sub(st.inflight.len()).max(reserve);
    let mut peer_i = st.assign_rot;
    let mut issued = 0u64;
    for h in reorg_need {
        if room == 0 {
            break;
        }
        if st.inflight.contains_key(&h) {
            continue;
        }
        if hub.has_block(&h) {
            continue;
        }
        if hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, st.hash_height.get(&h).copied());
        if st.body.skip_download(hub, &h) {
            continue;
        }
        for _ in 0..alive.len() {
            let pid = alive[peer_i % alive.len()];
            peer_i += 1;
            if !peer_has_slot(st, pid, cfg.per_peer) {
                continue;
            }
            if issue_one(st, pid, h, &mut room, &mut issued) {
                break;
            }
        }
    }
    st.assign_rot = peer_i;
    issued
}

struct DensifyCtx<'a> {
    loop_stats: &'a LoopStats,
    t0: Instant,
    issued: u64,
    path_lo: u32,
    tip_batch_hi: u32,
    race_tip: bool,
    tip_rate_blocks_per_s: Option<f64>,
}

fn assign_densify(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    ctx: DensifyCtx<'_>,
) {
    let DensifyCtx {
        loop_stats,
        t0,
        mut issued,
        path_lo,
        tip_batch_hi,
        race_tip,
        tip_rate_blocks_per_s,
    } = ctx;
    let tip_hole = race_tip;
    let (pack_median, pack_tight) = pack_ewma_bps(&st.slots, alive);
    let caps: HashMap<usize, usize> = alive
        .iter()
        .map(|&pid| {
            (
                pid,
                densify_cap_for(
                    &st.slots,
                    pid,
                    cfg.per_peer,
                    tip_hole,
                    pack_median,
                    pack_tight,
                ),
            )
        })
        .collect();
    issued += steal_hung_densify(st, hub, alive, tip_batch_hi, &caps);

    let mut room = cfg.window.saturating_sub(st.inflight.len());
    // Window is full and no retired holder is waiting for a racer. Skip the
    // densify height walk.
    if room == 0 && !st.inflight.values().any(inflight_needs_racer) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let densify_hi = path_lo.saturating_add(CONTIG_DENSIFY_AHEAD);
    let depth_bytes = hub.query.block_queue_stats().1;
    let fetched_hi = hub
        .query
        .block_queue_max_height()
        .into_iter()
        .chain(hub.query.lookup_taken_hi())
        .max();
    let band_hi = rbitcoin_query::soft_densify_band_hi(
        path_lo,
        densify_hi,
        depth_bytes,
        tip_rate_blocks_per_s,
        rbitcoin_query::bq_assign_stop_bytes(),
        fetched_hi,
    );

    if path_lo < st.assign_path_lo {
        st.densify_scan_lo = path_lo;
    }
    st.assign_path_lo = path_lo;
    st.densify_scan_lo = st.densify_scan_lo.max(path_lo);
    if !alive
        .iter()
        .any(|&pid| peer_has_slot(st, pid, caps.get(&pid).copied().unwrap_or(1)))
    {
        finish_assign(loop_stats, t0, issued);
        return;
    }
    let densify_lo = path_lo.max(st.densify_scan_lo);
    let collect_cap = if room == 0 { 1 } else { room };
    let densify = collect_height_band(st, hub, densify_lo, band_hi, collect_cap, room);
    if densify.is_empty() {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let ranked = rank_peers_by_speed(&st.slots, alive, &HashSet::new());
    let mut densify_q = densify;
    'peers: for &pid in &ranked {
        if densify_q.is_empty() {
            break;
        }
        let cap = caps.get(&pid).copied().unwrap_or(1);
        while !densify_q.is_empty() {
            if !peer_has_slot(st, pid, cap) {
                break;
            }
            let Some(h) = pop_need(&mut densify_q, st, hub) else {
                break;
            };
            if st.inflight.get(&h).is_some_and(|req| req.holds(pid)) {
                densify_q.push_front(h);
                break;
            }
            if !densify_issue_allowed(room, st.inflight.get(&h)) {
                densify_q.push_front(h);
                break 'peers;
            }
            if !issue_one(st, pid, h, &mut room, &mut issued) {
                densify_q.push_front(h);
                break;
            }
        }
    }

    finish_assign(loop_stats, t0, issued);
}

pub(crate) fn finish_assign(loop_stats: &LoopStats, t0: Instant, issued: u64) {
    loop_stats
        .assign_ns
        .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    if issued > 0 {
        loop_stats
            .assign_issued
            .fetch_add(issued, Ordering::Relaxed);
    }
}

/// Single-peer need list over an inclusive height band.
///
/// Walks closest-to-tip first. Already-pending / body-queue / archived heights
/// are skipped without consuming [`FAR_SCAN_BUDGET`] “need” slots — only the
/// raw walk length is capped — so a full tip buffer no longer blocks densify
/// from seeing the rest of the [`CONTIG_DENSIFY_AHEAD`] band.
fn collect_height_band(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    lo: u32,
    hi: u32,
    cap: usize,
    room: usize,
) -> VecDeque<BlockHash> {
    let mut out = VecDeque::new();
    if lo > hi || cap == 0 {
        return out;
    }
    let hi = hi.min(st.max_ordered_height.max(lo));
    let mut prefix = lo;
    let mut tracking = true;
    for (walked, ht) in (lo..=hi).enumerate() {
        if out.len() >= cap || walked >= FAR_SCAN_BUDGET {
            break;
        }
        let need = need_hash_at(st, hub, ht, room);
        if tracking {
            if need.is_none() && densify_prefix_filled(st, hub, ht) {
                prefix = ht.saturating_add(1);
            } else {
                tracking = false;
            }
        }
        if let Some(h) = need {
            out.push_back(h);
        }
    }
    st.densify_scan_lo = prefix.max(st.densify_scan_lo);
    out
}

fn densify_prefix_filled(st: &mut IbdWorkState, hub: &ChainHub, ht: u32) -> bool {
    let Some(&h) = st.height_to_hash.get(&ht) else {
        return false;
    };
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return true;
    }
    if st.inflight.contains_key(&h) {
        return true;
    }
    st.body.is_known_archived(&h)
}

/// Body-queue wire at `ht` for `want`: `Ready` when matching; wrong first-wins
/// is dequeued (`Gap`); empty slot is `Gap`. Shared by densify and tip-hole cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BqWireAt {
    Ready,
    Gap,
}

fn bq_wire_for_hash(hub: &ChainHub, ht: u32, want: BlockHash) -> BqWireAt {
    use bitcoin::hashes::Hash as _;
    match hub.query.block_queue_hash_at_height(ht) {
        Some(bq_h) if bq_h == want.to_byte_array() => BqWireAt::Ready,
        Some(_) => {
            let _ = hub.query.block_queue_dequeue_height(ht);
            BqWireAt::Gap
        }
        None => BqWireAt::Gap,
    }
}

/// Hash at `ht` that still needs a new single-peer getdata (not inflight/pending/done).
///
/// Order matters: BQ hash-match before pending. Pending with matching wire is done;
/// **zombie** pending (flag set, wrong/no wire) must demote and re-get — skipping
/// all pending first left densify-ahead heights frozen (tip advances past tip-batch
/// cover, soft filled, conf stuck on a later hole).
fn inflight_needs_racer(req: &state::InflightReq) -> bool {
    req.peers.is_empty() && !req.retired.is_empty()
}

/// A free getdata window slot, or a racer for a hash whose only holders are
/// retired. A retired holder already occupies a window slot, so the racer
/// does not.
fn densify_issue_allowed(room: usize, req: Option<&state::InflightReq>) -> bool {
    room > 0 || req.is_some_and(inflight_needs_racer)
}

fn need_hash_at(st: &mut IbdWorkState, hub: &ChainHub, ht: u32, room: usize) -> Option<BlockHash> {
    use bitcoin::hashes::Hash as _;
    let &h = st.height_to_hash.get(&ht)?;
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return None;
    }
    if st.inflight.get(&h).is_some_and(|req| !req.peers.is_empty())
        || st.body.is_rejected(&h)
        || st.reorg.invalid.contains(h.to_byte_array())
    {
        return None;
    }
    if !densify_issue_allowed(room, st.inflight.get(&h)) {
        return None;
    }
    // Class A seed: densify skips re-walk; tip-hole cover re-gets tip batch.
    if st.body.is_known_archived(&h) {
        return None;
    }
    if bq_wire_for_hash(hub, ht, h) == BqWireAt::Ready {
        return None;
    }
    demote_zombie_pending_for_fetch(&mut st.body, hub, h, Some(ht));
    if st.body.skip_download(hub, &h) {
        return None;
    }
    Some(h)
}

pub(crate) fn pop_need(
    q: &mut VecDeque<BlockHash>,
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Option<BlockHash> {
    while let Some(h) = q.pop_front() {
        if st.body.skip_download(hub, &h)
            || st.inflight.get(&h).is_some_and(|req| !req.peers.is_empty())
        {
            continue;
        }
        return Some(h);
    }
    None
}

/// How many recent block bodies the per-peer byte cap remembers.
const BLOCK_LEN_SAMPLES: usize = 32;
/// Below this many samples the byte cap charges [`BLOCK_LEN_STAND_IN`].
const BLOCK_LEN_MIN_SAMPLES: usize = 8;
/// Stand-in payload so the count cap binds before any bodies have arrived.
const BLOCK_LEN_STAND_IN: u64 = 1024;
/// Outstanding getdata payload on one peer.
pub(crate) const PER_PEER_BLOCK_BYTE_CAP: u64 = 16 * 1024 * 1024;

/// Remember one received block body. The ring stays at [`BLOCK_LEN_SAMPLES`].
pub(crate) fn note_block_len(st: &mut IbdWorkState, len: usize) {
    if st.block_lens.len() == BLOCK_LEN_SAMPLES {
        st.block_lens.pop_front();
    }
    st.block_lens
        .push_back(u32::try_from(len).unwrap_or(u32::MAX));
}

/// Median recent payload, or [`BLOCK_LEN_STAND_IN`] before enough samples.
pub(crate) fn block_len_estimate(st: &IbdWorkState) -> u64 {
    if st.block_lens.len() < BLOCK_LEN_MIN_SAMPLES {
        return BLOCK_LEN_STAND_IN;
    }
    let mut lens: Vec<u32> = st.block_lens.iter().copied().collect();
    lens.sort_unstable();
    u64::from(lens[lens.len() / 2])
}

/// Room for one more getdata hash: under the count cap, and the next
/// estimated body still fits in [`PER_PEER_BLOCK_BYTE_CAP`].
pub(crate) fn peer_has_block_room(in_flight: usize, per_peer: usize, estimate: u64) -> bool {
    if in_flight >= per_peer {
        return false;
    }
    let next = (in_flight as u64)
        .saturating_mul(estimate)
        .saturating_add(estimate);
    next <= PER_PEER_BLOCK_BYTE_CAP
}

fn peer_has_slot(st: &IbdWorkState, pid: usize, per_peer: usize) -> bool {
    let estimate = block_len_estimate(st);
    st.slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .is_some_and(|s| peer_has_block_room(s.in_flight.len(), per_peer, estimate))
}

pub(crate) fn issue_one(
    st: &mut IbdWorkState,
    pid: usize,
    h: BlockHash,
    room: &mut usize,
    issued: &mut u64,
) -> bool {
    issue_batch(st, pid, vec![h], room, issued)
}

/// Ceiling on the per-hash assign-stop charge. A block cannot be larger.
pub(crate) const GETDATA_RESERVE_BYTES: u64 = 4 * 1024 * 1024;

/// Bytes reserved for one new getdata hash against the assign-stop.
///
/// Fewer than [`BLOCK_LEN_MIN_SAMPLES`] recorded bodies still cost the 4 MiB
/// ceiling. After that the charge is the largest wire length in the ring,
/// and never above that ceiling.
fn intake_reserve_per_hash(st: &IbdWorkState) -> u64 {
    if st.block_lens.len() < BLOCK_LEN_MIN_SAMPLES {
        return GETDATA_RESERVE_BYTES;
    }
    let max = st.block_lens.iter().copied().max().unwrap_or(u32::MAX);
    u64::from(max).min(GETDATA_RESERVE_BYTES)
}

/// `inflight_after` unique hashes, each counted at [`intake_reserve_per_hash`],
/// plus the snapshotted queue, fit in the assign-stop budget.
fn intake_reserve_fits(st: &IbdWorkState, inflight_after: usize) -> bool {
    if st.intake_stop == u64::MAX {
        return true;
    }
    let reserved = (inflight_after as u64).saturating_mul(intake_reserve_per_hash(st));
    st.intake_queued.saturating_add(reserved) <= st.intake_stop
}

pub(crate) fn issue_batch(
    st: &mut IbdWorkState,
    pid: usize,
    batch: Vec<BlockHash>,
    room: &mut usize,
    issued: &mut u64,
) -> bool {
    if batch.is_empty() {
        return false;
    }
    let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
        return false;
    };
    let mut projected = st.inflight.len();
    let batch: Vec<BlockHash> = batch
        .into_iter()
        .filter(|h| {
            if st.slots[idx].in_flight.contains(h) {
                return false;
            }
            if st.inflight.contains_key(h) {
                return true;
            }
            let next = projected.saturating_add(1);
            if !intake_reserve_fits(st, next) {
                return false;
            }
            projected = next;
            true
        })
        .collect();
    if batch.is_empty() {
        return false;
    }
    let empty = st.slots[idx].in_flight.is_empty();
    for &h in &batch {
        st.slots[idx].in_flight.insert(h);
    }
    if empty {
        st.slots[idx].rate.note_work_started(ibd_mono_ms());
    }
    let _ = st.slots[idx].cmd_tx.send(PeerCmd::GetData {
        hashes: batch.clone(),
    });
    for &h in &batch {
        inflight_add_peer(&mut st.inflight, h, pid);
    }
    *issued += batch.len() as u64;
    let new_unique = batch
        .iter()
        .filter(|h| {
            st.inflight
                .get(*h)
                .is_some_and(|e| e.len() == 1 && e.retired.is_empty())
        })
        .count();
    *room = room.saturating_sub(new_unique);
    true
}

/// Contiguous tip+1.. hashes that still need getdata (assign tip-hole race).
///
/// Stops at the first **claim-ready** body (body-queue wire / confirmed) so
/// densify priority matches operator `hole=` (fetch gap, not confirm backlog).
pub(crate) fn contiguous_tip_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    max: usize,
) -> Vec<BlockHash> {
    use super::progress::claim_ready;
    let path_lo = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let mut holes = Vec::new();
    let limit = path_lo
        .saturating_add(max as u32 * 4)
        .max(path_lo.saturating_add(max as u32));
    for ht in path_lo..=limit {
        if holes.len() >= max {
            break;
        }
        let Some(&hash) = st.height_to_hash.get(&ht) else {
            break;
        };
        if st.body.is_rejected(&hash) {
            break;
        }
        if claim_ready(hub, &mut st.body, ht, &hash) {
            break;
        }
        holes.push(hash);
    }
    holes
}

/// First non-claim-ready height in `path_lo .. path_lo+max-1` (after a ready prefix).
pub(crate) fn first_pre_hole(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    max: usize,
) -> Option<BlockHash> {
    use super::progress::claim_ready;
    let path_lo = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let hi = path_lo.saturating_add(max.saturating_sub(1) as u32);
    for ht in path_lo..=hi {
        let &hash = st.height_to_hash.get(&ht)?;
        if st.body.is_rejected(&hash) {
            continue;
        }
        if claim_ready(hub, &mut st.body, ht, &hash) {
            continue;
        }
        return Some(hash);
    }
    None
}

/// Extra racer on a pre-hole only when there is no owner, every current owner
/// has held the hash for [`TIP_HOLE_RX_STALE`], or an owner's EWMA is ≤ pack
/// median / 4.
pub(crate) fn pre_hole_should_extra_racer(
    st: &IbdWorkState,
    hash: BlockHash,
    alive: &[usize],
) -> bool {
    let Some(req) = st.inflight.get(&hash) else {
        return true;
    };
    if req.peers.is_empty() {
        return true;
    }
    let now = Instant::now();
    let aged = req.peers.iter().all(|&pid| {
        let since = req.owner_asked_at(pid).unwrap_or(req.started_at);
        now.duration_since(since) >= TIP_HOLE_RX_STALE
    });
    if aged {
        return true;
    }
    let (Some(median), _) = pack_ewma_bps(&st.slots, alive) else {
        return false;
    };
    if median == 0 {
        return false;
    }
    let slow = median / 4;
    req.peers.iter().any(|&pid| {
        st.slots
            .iter()
            .find(|s| s.id == pid && s.alive)
            .and_then(|s| s.rate.bps())
            .is_some_and(|bps| bps <= slow)
    })
}

fn cover_first_pre_hole(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
) -> u64 {
    let Some(h) = first_pre_hole(st, hub, TIP_HOLE_MAX) else {
        return 0;
    };
    let want = if pre_hole_should_extra_racer(st, h, alive) {
        PRE_HOLE_MAX_PEERS
    } else {
        1
    };
    cover_tip_holes(st, hub, cfg, alive, &[h], want)
}

/// Demote zombie `pending` (flag set, no **matching** body-queue wire) so getdata
/// can re-issue.
///
/// Confirm intake and reorg gather need real wire (BQ / held). `mark_pending`
/// alone is not enough — without BQ it is a zombie that would `skip_download`
/// forever. Tip-hole cover and reorg densify (1b) share this; only walks the
/// small hole/need lists (not the full pending map).
#[inline]
fn demote_zombie_pending_for_fetch(
    body: &mut super::body::BodyPresence,
    hub: &ChainHub,
    hash: BlockHash,
    height: Option<u32>,
) {
    use bitcoin::hashes::Hash as _;
    if !body.is_pending(&hash) {
        return;
    }
    if hub.has_block(&hash) {
        return;
    }
    // Only keep pending when BQ holds **this** hash at its height (not a
    // different first-wins occupant).
    if let Some(ht) = height {
        if hub
            .query
            .block_queue_hash_at_height(ht)
            .is_some_and(|h| h == hash.to_byte_array())
        {
            return;
        }
    }
    body.mark_missing(hash);
}

/// Stream rx older than this is not “recent” for tip-hole owner eviction.
/// Matches the absolute stall floor so slow-but-steady 64 KiB ticks stay live.
const TIP_HOLE_RX_STALE: Duration = Duration::from_secs(30);

fn peer_has_recent_rx(slot: &PeerSlot, now_ms: u64) -> bool {
    slot.rate
        .has_recent_rx(now_ms, TIP_HOLE_RX_STALE.as_millis() as u64)
}

fn peer_queue_len(slots: &[PeerSlot], pid: usize) -> usize {
    slots
        .iter()
        .find(|s| s.id == pid)
        .map(|s| s.in_flight.len())
        .unwrap_or(usize::MAX)
}

/// Owner still has densify (or other) getdata in front of this hole.
fn hole_owner_fifo_blocked(slot: &PeerSlot) -> bool {
    slot.in_flight.len() > 1
}

/// A FIFO-blocked owner is not dropped until it has held the hash this long.
/// Every peer has other getdata in flight during IBD, so without a hold time
/// the rule fires on every assign pass.
const TIP_HOLE_FIFO_MIN_HOLD: Duration = Duration::from_secs(5);

/// A free peer must be expected to start the hash in at most 1/this of the
/// owner's drain time before a FIFO-blocked owner is dropped for it.
const TIP_HOLE_FIFO_FASTER: u128 = 2;

/// Drop an owner whose peer FIFO is not on this hash when it has held the hash
/// for [`TIP_HOLE_FIFO_MIN_HOLD`] and a free peer would start it at least
/// [`TIP_HOLE_FIFO_FASTER`]× sooner by `(queue+1)/bps`.
fn fifo_blocked_owner_to_drop(
    req: &state::InflightReq,
    hash: &BlockHash,
    slots: &[PeerSlot],
    per_peer: usize,
    estimate: u64,
) -> Option<usize> {
    if slots.iter().filter(|s| s.alive).count() <= 1 {
        return None;
    }
    let (free_q, free_bps) = slots
        .iter()
        .filter(|s| {
            s.alive
                && !req.holds(s.id)
                && !s.in_flight.contains(hash)
                && peer_has_block_room(s.in_flight.len(), per_peer, estimate)
        })
        .map(|s| (s.in_flight.len(), peer_bps(slots, s.id)))
        .min_by(|&(qa, ba), &(qb, bb)| tip_hole_drain_cmp(qa, ba, qb, bb))?;
    let now = Instant::now();
    req.peers
        .iter()
        .copied()
        .filter(|&id| {
            let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
                return false;
            };
            if !hole_owner_fifo_blocked(slot) {
                return false;
            }
            let held_long = req
                .owner_asked_at(id)
                .is_some_and(|t| now.duration_since(t) >= TIP_HOLE_FIFO_MIN_HOLD);
            // free wait <= owner wait / FASTER, cross-multiplied as in tip_hole_drain_cmp.
            let free_wait = (free_q as u128 + 1)
                .saturating_mul(TIP_HOLE_FIFO_FASTER)
                .saturating_mul(u128::from(peer_bps(slots, id).max(1)));
            let owner_wait =
                (slot.in_flight.len() as u128).saturating_mul(u128::from(free_bps.max(1)));
            held_long && free_wait <= owner_wait
        })
        .max_by(|&a, &b| {
            peer_queue_len(slots, a)
                .cmp(&peer_queue_len(slots, b))
                .then_with(|| peer_bps(slots, b).cmp(&peer_bps(slots, a)))
                .then_with(|| a.cmp(&b))
        })
}

/// Which current owner of a tip-hole hash to drop from **this hash** (not disconnect).
///
/// - Owner `in_flight.len() > 1` → densify may be in front; drop when it has
///   held the hash ≥ [`TIP_HOLE_FIFO_MIN_HOLD`] and a free peer would start it
///   clearly sooner (peer-level 64 KiB ticks are not progress on this hash).
/// - No owner has recent rx → none (too early / first 64 KiB still in flight).
/// - Some have recent rx, some do not → drop a no-rx owner (quick dead-racer).
/// - All have recent rx → [`relative_slow_pick`] among those owners (`min_samples` =
///   owner count). Tight cluster → none.
/// - Solo owner: drop when it has held the hash (its own ask time)
///   ≥ [`TIP_HOLE_RX_STALE`] and another alive peer exists. Getdata
///   cannot be cancelled, so we stop counting that owner and race a faster
///   drain instead. One live peer stays so we do not drop the only remaining
///   request.
pub(crate) fn tip_hole_owner_to_drop(
    req: &state::InflightReq,
    hash: &BlockHash,
    slots: &[PeerSlot],
    per_peer: usize,
    estimate: u64,
) -> Option<usize> {
    let owners: Vec<usize> = req.peers.iter().copied().collect();
    let owners = owners.as_slice();
    if owners.is_empty() {
        return None;
    }
    if let Some(id) = fifo_blocked_owner_to_drop(req, hash, slots, per_peer, estimate) {
        return Some(id);
    }
    let solo_since = owners
        .first()
        .and_then(|&pid| req.owner_asked_at(pid))
        .unwrap_or(req.started_at);
    let now_ms = ibd_mono_ms();
    let mut recent = Vec::new();
    let mut stale = Vec::new();
    for &id in owners {
        let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
            stale.push(id);
            continue;
        };
        if peer_has_recent_rx(slot, now_ms) {
            recent.push(id);
        } else {
            stale.push(id);
        }
    }
    if owners.len() == 1 {
        let aged = Instant::now().duration_since(solo_since) >= TIP_HOLE_RX_STALE;
        let other_alive = slots.iter().filter(|s| s.alive).count() > 1;
        if !recent.is_empty() {
            if aged && other_alive {
                return Some(owners[0]);
            }
            return None;
        }
        if aged {
            return Some(owners[0]);
        }
        return None;
    }
    if recent.is_empty() {
        return None;
    }
    if let Some(&id) = stale.iter().min() {
        return Some(id);
    }
    let samples: Vec<RelativeSlowSample> = owners
        .iter()
        .filter_map(|&id| {
            let s = slots.iter().find(|s| s.id == id && s.alive)?;
            Some(RelativeSlowSample {
                peer_id: id,
                bps: s.rate.eviction_bps(now_ms).unwrap_or(0),
                has_inflight: true,
            })
        })
        .collect();
    relative_slow_pick(&samples, samples.len())
}

/// Stop counting `pid` as a racer on `hash`. Getdata cannot be cancelled, so
/// the peer keeps the request in its `in_flight` and is not asked again.
fn retire_hash_owner(st: &mut IbdWorkState, hash: BlockHash, pid: usize) {
    if let Some(req) = st.inflight.get_mut(&hash) {
        req.retire_peer(pid);
    }
}

fn peer_bps(slots: &[PeerSlot], pid: usize) -> u64 {
    slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .and_then(|s| s.rate.bps())
        .unwrap_or(0)
}

fn pack_ewma_bps(slots: &[PeerSlot], alive: &[usize]) -> (Option<u64>, bool) {
    let mut samples: Vec<u64> = alive
        .iter()
        .filter_map(|&pid| {
            slots
                .iter()
                .find(|s| s.id == pid && s.alive)
                .and_then(|s| s.rate.bps())
        })
        .collect();
    if samples.is_empty() {
        return (None, true);
    }
    samples.sort_unstable();
    let lo = samples[0];
    let hi = samples[samples.len() - 1];
    let tight = if lo == 0 {
        hi == 0
    } else {
        hi <= lo.saturating_mul(RELATIVE_SLOW_CLUSTER_SPREAD)
    };
    (Some(median_u64(&samples)), tight)
}

fn densify_cap_for(
    slots: &[PeerSlot],
    pid: usize,
    per_peer: usize,
    tip_hole: bool,
    pack_median: Option<u64>,
    pack_tight: bool,
) -> usize {
    let bps = slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .and_then(|s| s.rate.bps());
    densify_slots_for_peer(per_peer, tip_hole, bps, pack_median, pack_tight)
}

/// Move hung single-peer densify getdata to a faster peer with a free slot.
fn steal_hung_densify(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    alive: &[usize],
    tip_batch_hi: u32,
    densify_caps: &HashMap<usize, usize>,
) -> u64 {
    let now = Instant::now();
    let now_ms = ibd_mono_ms();
    let candidates: Vec<(BlockHash, u32, usize, Instant)> = st
        .inflight
        .iter()
        .filter_map(|(h, req)| {
            if req.len() != 1 {
                return None;
            }
            let &ht = st.hash_height.get(h)?;
            if ht <= tip_batch_hi {
                return None;
            }
            let &pid = req.peers.iter().next()?;
            Some((*h, ht, pid, req.owner_asked_at(pid)?))
        })
        .collect();
    let hung: Vec<BlockHash> = candidates
        .into_iter()
        .filter(|(h, ht, pid, started)| {
            if super::progress::claim_ready(hub, &mut st.body, *ht, h) {
                return false;
            }
            let Some(slot) = st.slots.iter().find(|s| s.id == *pid && s.alive) else {
                return false;
            };
            if peer_has_recent_rx(slot, now_ms) {
                return false;
            }
            now.duration_since(*started) >= TIP_HOLE_RX_STALE
        })
        .map(|(h, _, _, _)| h)
        .collect();
    let mut issued = 0u64;
    for h in hung {
        let Some(owner) = st
            .inflight
            .get(&h)
            .and_then(|req| req.peers.iter().copied().next())
        else {
            continue;
        };
        let owner_bps = peer_bps(&st.slots, owner);
        let mut faster: Vec<usize> = alive
            .iter()
            .copied()
            .filter(|&pid| {
                pid != owner
                    && peer_bps(&st.slots, pid) > owner_bps
                    && !st.inflight.get(&h).is_some_and(|r| r.holds(pid))
            })
            .collect();
        if faster.is_empty() {
            continue;
        }
        faster.sort_by_key(|&b| std::cmp::Reverse(peer_bps(&st.slots, b)));
        let dest = faster
            .into_iter()
            .find(|&pid| peer_has_slot(st, pid, densify_caps.get(&pid).copied().unwrap_or(1)));
        let ht = st.hash_height.get(&h).copied();
        retire_hash_owner(st, h, owner);
        if let Some(pid) = dest {
            let mut room = 1usize;
            let _ = issue_one(st, pid, h, &mut room, &mut issued);
        } else if let Some(ht) = ht {
            st.densify_scan_lo = st.densify_scan_lo.min(ht);
        }
    }
    issued
}

/// Rank alive peer ids for densify getdata: prefer peers not in `avoid`, then
/// higher live EWMA bps, then lower id. Unsampled peers sort last
/// among non-avoided (bps=0).
pub(crate) fn rank_peers_by_speed(
    slots: &[PeerSlot],
    alive: &[usize],
    avoid: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut ranked: Vec<usize> = alive.to_vec();
    ranked.sort_by(|&a, &b| {
        let avoided_a = avoid.contains(&a) as u8;
        let avoided_b = avoid.contains(&b) as u8;
        avoided_a.cmp(&avoided_b).then_with(|| {
            let bps = |pid: usize| -> u64 { peer_bps(slots, pid) };
            bps(b).cmp(&bps(a)).then_with(|| a.cmp(&b))
        })
    });
    ranked
}

/// Rank for tip-hole getdata: lowest expected drain wait first, then higher EWMA.
///
/// Wait is `(queue+1)/bps` so a fast peer with leftover densify beats an idle
/// slow peer. Unsampled (`bps == 0`) uses 1 so unknown sorts behind any positive rate.
fn rank_peers_for_tip_hole(
    slots: &[PeerSlot],
    alive: &[usize],
    avoid: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut ranked: Vec<usize> = alive.to_vec();
    ranked.sort_by(|&a, &b| {
        let avoided_a = avoid.contains(&a) as u8;
        let avoided_b = avoid.contains(&b) as u8;
        avoided_a.cmp(&avoided_b).then_with(|| {
            let qa = peer_queue_len(slots, a);
            let qb = peer_queue_len(slots, b);
            let bps_a = peer_bps(slots, a);
            let bps_b = peer_bps(slots, b);
            tip_hole_drain_cmp(qa, bps_a, qb, bps_b)
                .then_with(|| bps_b.cmp(&bps_a).then_with(|| a.cmp(&b)))
        })
    });
    ranked
}

/// `wait_a < wait_b` iff `(qa+1)/bps_a < (qb+1)/bps_b`.
fn tip_hole_drain_cmp(qa: usize, bps_a: u64, qb: usize, bps_b: u64) -> std::cmp::Ordering {
    let a = bps_a.max(1);
    let b = bps_b.max(1);
    let wa = (qa as u128 + 1).saturating_mul(u128::from(b));
    let wb = (qb as u128 + 1).saturating_mul(u128::from(a));
    wa.cmp(&wb)
}

/// Full race on tip+1; one racer each on later contiguous holes in the same gap.
fn cover_tip_batch_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    holes: &[BlockHash],
) -> u64 {
    let Some((first, rest)) = holes.split_first() else {
        return 0;
    };
    let mut issued = cover_tip_holes(st, hub, cfg, alive, &[*first], TIP_HOLE_MAX_PEERS);
    issued += cover_tip_holes(st, hub, cfg, alive, rest, 1);
    issued
}

/// Cover each tip-hole hash with multi-peer getdata on short drain waits.
///
/// While the hole is open, at most one current owner of **this hash** is dropped
/// per call when a sibling is pulling, that owner is a relative-slow outlier
/// among owners, the owner's FIFO is still on densify, or a solo owner has held
/// it too long and another peer exists. The whole race set is never cleared on
/// request age. A dropped owner is retired: it keeps the request it was sent,
/// still counts toward its queue and toward the ask cap, and is not asked
/// for this hash again.
pub(crate) fn cover_tip_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    holes: &[BlockHash],
    max_peers: usize,
) -> u64 {
    if holes.is_empty() || alive.is_empty() {
        return 0;
    }
    let mut issued = 0u64;

    for &h in holes {
        let ht = st.hash_height.get(&h).copied();
        if let Some(ht) = ht {
            if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
                continue;
            }
            let _ = bq_wire_for_hash(hub, ht, h);
        } else if hub.has_block(&h) {
            continue;
        }
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, ht);
        let mut avoid: HashSet<usize> = HashSet::new();
        if let Some(req) = st.inflight.get(&h) {
            if let Some(pid) =
                tip_hole_owner_to_drop(req, &h, &st.slots, cfg.per_peer, block_len_estimate(st))
            {
                retire_hash_owner(st, h, pid);
                avoid.insert(pid);
            }
        }
        let already = st.inflight.get(&h).map(|e| e.holders()).unwrap_or(0);
        let want = max_peers;
        if already >= want {
            continue;
        }
        let mut need = want - already;
        let mut placed_any = false;
        let ranked = rank_peers_for_tip_hole(&st.slots, alive, &avoid);
        for &pid in &ranked {
            if need == 0 {
                break;
            }
            if avoid.contains(&pid) {
                continue;
            }
            let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
                continue;
            };
            if st.slots[idx].in_flight.contains(&h) {
                continue;
            }
            if st.inflight.get(&h).is_some_and(|e| e.holds(pid)) {
                continue;
            }
            if !peer_has_block_room(
                st.slots[idx].in_flight.len(),
                cfg.per_peer,
                block_len_estimate(st),
            ) {
                continue;
            }
            let mut room = 1usize;
            if issue_one(st, pid, h, &mut room, &mut issued) {
                placed_any = true;
                need = need.saturating_sub(1);
            }
        }
        if already == 0 && !placed_any {
            break;
        }
    }
    issued
}

#[cfg(test)]
pub(in crate::ibd) mod tests {
    use super::super::status::LoopStats;
    use super::*;
    use bitcoin::hashes::Hash;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn need_any_valid_body_download_empty_and_missing_tip_child() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        assert!(
            !need_any_valid_body_download(&st, &hub),
            "genesis-only path has no body download"
        );
        let want = h(0x21);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        st.body.mark_missing(want);
        assert!(
            need_any_valid_body_download(&st, &hub),
            "missing tip+1 must keep download open"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn h(n: u32) -> BlockHash {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    pub(in crate::ibd) fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444 + id as u16),
            net: crate::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                18444 + id as u16,
            )),
            cmd_tx,
            in_flight: HashSet::new(),
            peer_height: 100,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            alive: true,
            task,
        }
    }

    fn plant_work_path(st: &mut IbdWorkState, lo: u32, hi: u32) {
        for ht in lo..=hi {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
    }

    /// A known rate is not recent rx. The synthetic 5 s sample would read as
    /// recent only while the test process is under 35 s old, so rx is
    /// `note_rx` alone.
    fn seed_ewma(slot: &mut PeerSlot, bytes_per_sec: u64) {
        let progress_ms = slot.rate.progress_ms;
        slot.rate.sample(0, 0, true);
        slot.rate
            .sample(5_000, bytes_per_sec.saturating_mul(5), true);
        slot.rate.progress_ms = progress_ms;
    }

    fn wired_slots(n: usize) -> (Vec<PeerSlot>, Vec<mpsc::UnboundedReceiver<PeerCmd>>) {
        (0..n)
            .map(|id| {
                let mut slot = dummy_slot(id);
                let (tx, rx) = mpsc::unbounded_channel();
                slot.cmd_tx = tx;
                (slot, rx)
            })
            .unzip()
    }

    /// Getdata for `hash` each peer received since the last drain.
    fn getdata_asks(wire: &mut [mpsc::UnboundedReceiver<PeerCmd>], hash: BlockHash) -> Vec<usize> {
        wire.iter_mut()
            .map(|rx| {
                let mut n = 0;
                while let Ok(cmd) = rx.try_recv() {
                    if let PeerCmd::GetData { hashes } = cmd {
                        n += hashes.iter().filter(|&&x| x == hash).count();
                    }
                }
                n
            })
            .collect()
    }

    /// IBD restarts on the same hub: empty body queue, fresh work state, and
    /// the same peers with drained queues and unknown rates. Only `alive` are
    /// connected.
    fn restart_on(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        wire: &mut [mpsc::UnboundedReceiver<PeerCmd>],
        alive: &[usize],
    ) {
        for ht in hub.query.block_queue_queued_heights() {
            hub.query.block_queue_dequeue_height(ht).unwrap();
        }
        let _ = getdata_asks(wire, BlockHash::all_zeros());
        let mut slots = std::mem::take(&mut st.slots);
        for s in &mut slots {
            s.in_flight.clear();
            s.rate = Default::default();
            s.alive = alive.contains(&s.id);
        }
        *st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    }

    fn plant_tip_hole(st: &mut IbdWorkState, hash: BlockHash, ht: u32) {
        st.record_height(hash, ht);
        st.height_to_hash.insert(ht, hash);
        st.body.mark_missing(hash);
    }

    fn mark_tip_batch_ready(st: &mut IbdWorkState, hub: &ChainHub, path_lo: u32) {
        use bitcoin::hashes::Hash as _;
        for ht in path_lo..=32 {
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
            st.body.mark_pending(h(ht));
        }
    }

    fn mark_heights_ready(st: &mut IbdWorkState, hub: &ChainHub, lo: u32, hi: u32) {
        use bitcoin::hashes::Hash as _;
        for ht in lo..=hi {
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
            st.body.mark_pending(h(ht));
        }
    }

    /// 75×80-byte bodies past the tip window. At 5 blk/s the confirm window is
    /// 300 blocks, so this is a quarter of that window.
    fn plant_quarter_window(hub: &ChainHub, path_lo: u32) {
        use bitcoin::hashes::Hash as _;
        let start = path_lo.saturating_add(64);
        for i in 0..75u32 {
            let ht = start.saturating_add(i);
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
        }
    }

    fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
        crate::chain::tiny_regtest_hub_labeled("assign")
    }

    #[test]
    fn download_gate_stops_getdata_when_tip_plus_one_unconfirmable() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        plant_work_path(&mut st, 1, 20);
        st.body.mark_rejected(h(1));
        st.confirm_stuck_since = Instant::now().checked_sub(Duration::from_secs(60));
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.is_empty(),
            "gate must issue no getdata while tip+1 is unconfirmable; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_inflight_add_peer_pop_need_and_tip_holes() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let hash = h(10);
        st.slots[0].in_flight.insert(hash);
        st.slots[1].in_flight.insert(hash);
        inflight_add_peer(&mut st.inflight, hash, 0);
        inflight_add_peer(&mut st.inflight, hash, 1);
        assert_eq!(st.inflight[&hash].len(), 2);
        clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
        assert!(st.inflight.is_empty());
        assert!(st.slots[0].in_flight.is_empty());
        assert!(st.slots[1].in_flight.is_empty());

        let mut q = VecDeque::from([h(1), h(2)]);
        st.body.mark_pending(h(1));
        st.body.mark_missing(h(2));
        assert_eq!(pop_need(&mut q, &mut st, &hub), Some(h(2)));
        assert!(pop_need(&mut q, &mut st, &hub).is_none());

        st.height_to_hash.clear();
        let hole = h(21);
        let zombie = h(22);
        st.height_to_hash.insert(0, hole);
        st.height_to_hash.insert(1, zombie);
        st.body.mark_missing(hole);
        // Pending without body queue is a fetch hole (not claim-ready).
        st.body.mark_pending(zombie);
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![hole, zombie]);

        let mut room = 10usize;
        let mut issued = 0u64;
        assert!(!issue_one(&mut st, 99, h(30), &mut room, &mut issued));
        assert!(!issue_batch(&mut st, 0, vec![], &mut room, &mut issued));
        st.body.mark_missing(h(30));
        assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
        assert!(issued >= 1);
        assert!(st.inflight.contains_key(&h(30)));
        assert!(st.slots[0].in_flight.contains(&h(30)));

        st.slots.iter_mut().for_each(|s| s.alive = false);
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn issue_batch_does_not_count_as_rx() {
        let (dir, _hub) = tmp_hub();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        st.slots[0].rate.progress_ms = 42;
        st.slots[0].rate.work_started_ms = 7;
        let mut room = 10usize;
        let mut issued = 0u64;
        let t0 = super::super::peer_io::ibd_mono_ms();
        assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
        let t1 = super::super::peer_io::ibd_mono_ms();
        assert_eq!(st.slots[0].rate.progress_ms, 42);
        assert!(st.slots[0].rate.work_started_ms >= t0);
        assert!(st.slots[0].rate.work_started_ms <= t1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Off-path getdata (mainnet 08:16:23: ordered empty, h2h=0, inflight=7)
    /// must not occupy slots; tip+1 and live awaiting-reorg need stay.
    /// Speculative explore-need at an empty remainder is leftover — drop it.
    #[test]
    fn prune_off_path_inflight_drops_orphans_keeps_path_and_reorg() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        assert!(st.ordered.is_empty());
        assert!(st.height_to_hash.is_empty() || st.height_to_hash.len() <= 1);

        for i in 0..7u32 {
            let hash = h(1000 + i);
            st.slots[0].in_flight.insert(hash);
            inflight_add_peer(&mut st.inflight, hash, 0);
        }
        let want = h(0x11);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(want, ht);
        st.slots[0].in_flight.insert(want);
        inflight_add_peer(&mut st.inflight, want, 0);
        let explore_h = h(0x22);
        st.reorg.register_explore(std::iter::once(explore_h), None);
        st.slots[0].in_flight.insert(explore_h);
        inflight_add_peer(&mut st.inflight, explore_h, 0);
        assert_eq!(st.inflight.len(), 9);

        prune_off_path_inflight(&mut st);

        assert!(st.inflight.contains_key(&want), "tip+1 occupant stays");
        assert!(
            !st.inflight.contains_key(&explore_h),
            "explore-need at empty remainder is leftover"
        );
        for i in 0..7u32 {
            let hash = h(1000 + i);
            assert!(!st.inflight.contains_key(&hash), "orphan {i} dropped");
            assert!(!st.slots[0].in_flight.contains(&hash));
        }
        assert_eq!(st.inflight.len(), 1, "orphans+explore dropped; path kept");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scale_and_saturated_helpers() {
        assert!(!bq_pipeline_saturated(20, false));
        assert!(!bq_pipeline_saturated(0, false));
        assert!(!bq_pipeline_saturated(0, false));
        assert!(bq_pipeline_saturated(0, true));
        assert!(bq_pipeline_saturated(15, true));
        assert!(!bq_pipeline_saturated(32, true));
    }

    #[test]
    fn peer_block_room_is_count_until_bodies_have_a_size() {
        let mut st = IbdWorkState::new(vec![], None, None);
        let stand_in = block_len_estimate(&st);
        assert_eq!(stand_in, 1024);
        assert!(
            peer_has_block_room(16, 64, stand_in),
            "sixteen small hashes are under both caps"
        );
        assert!(
            !peer_has_block_room(64, 64, stand_in),
            "the count cap is 64 before any size samples"
        );

        for _ in 0..8 {
            note_block_len(&mut st, 1024 * 1024);
        }
        let mib = block_len_estimate(&st);
        assert_eq!(mib, 1024 * 1024);
        assert!(
            !peer_has_block_room(16, 64, mib),
            "sixteen 1 MiB bodies are the 16 MiB cap"
        );

        st.block_lens.clear();
        for _ in 0..8 {
            note_block_len(&mut st, 1024);
        }
        let kib = block_len_estimate(&st);
        assert!(peer_has_block_room(63, 64, kib));
        assert!(!peer_has_block_room(64, 64, kib));
    }

    fn drain_block_queue(hub: &ChainHub) {
        for ht in hub.query.block_queue_queued_heights() {
            hub.query.block_queue_dequeue_height(ht).unwrap();
        }
    }

    /// Fresh six-peer work on `hub` after the body queue is drained.
    fn gap_work(hub: &ChainHub) -> (IbdWorkState, IbdConfig, LoopStats) {
        drain_block_queue(hub);
        let mut st = IbdWorkState::new(
            (0..6).map(dummy_slot).collect(),
            hub.tip_hash(),
            hub.tip_height(),
        );
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        (st, cfg, LoopStats::default())
    }

    /// Tip-gap frontier versus tip-hole on the cover journey's hub.
    fn tip_gap_frontier_and_holes(hub: &ChainHub) {
        use bitcoin::hashes::Hash as _;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        let owners = |st: &IbdWorkState, ht: u32| st.inflight.get(&h(ht)).map_or(0, |e| e.len());

        let (mut st, cfg, stats) = gap_work(hub);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
        assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            owners(&st, path_lo),
            1,
            "empty queue is the frontier; tip+1 gets one owner"
        );
        let past = path_lo.saturating_add(TIP_HOLE_MAX as u32);
        assert!(
            st.inflight.contains_key(&h(past)),
            "densify continues past the tip window on the frontier"
        );

        // 74 ready bodies on the odd heights. 5 blk/s → 300-block window;
        // 74 * 4 = 296 stays under a quarter, so the tip gap is the frontier.
        let (mut st, cfg, stats) = gap_work(hub);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
        for i in 0..74u32 {
            let ht = path_lo
                .saturating_add(1)
                .saturating_add(i.saturating_mul(2));
            mark_heights_ready(&mut st, hub, ht, ht);
        }
        assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert_eq!(owners(&st, path_lo), 1, "under a quarter of the window");
        assert!(
            st.inflight.contains_key(&h(path_lo.saturating_add(2))),
            "densify fills the gap behind the first ready body"
        );

        let (mut st, cfg, stats) = gap_work(hub);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
        for i in 0..75u32 {
            let ht = path_lo
                .saturating_add(1)
                .saturating_add(i.saturating_mul(2));
            mark_heights_ready(&mut st, hub, ht, ht);
        }
        assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert_eq!(
            owners(&st, path_lo),
            4,
            "a quarter of the confirm window, with gaps, is a tip hole"
        );
        assert!(
            !st.inflight.contains_key(&h(path_lo.saturating_add(2))),
            "densify stays off while the quarter-full tip hole is open"
        );

        // Quarter of the configured assign-stop. One new hash reserves 4 MiB,
        // so the stop must still fit that reserve on top of the queued quarter.
        let stop: u64 = 8 * 1024 * 1024;
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", stop.to_string());
        let (mut st, cfg, stats) = gap_work(hub);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
        let n = (stop / 4) as usize;
        let payload = vec![0u8; n];
        hub.query
            .block_queue_offer(
                path_lo.saturating_add(64),
                h(path_lo.saturating_add(64)).to_byte_array(),
                1,
                &payload,
            )
            .unwrap();
        assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            owners(&st, path_lo),
            4,
            "a quarter of the configured assign-stop is a tip hole"
        );
        assert!(
            !st.inflight
                .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
            "densify stays off at the byte quarter"
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        drain_block_queue(hub);

        let (mut st, cfg, stats) = gap_work(hub);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(40));
        let start = path_lo.saturating_add(64);
        for i in 0..rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS {
            let ht = start.saturating_add(i);
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
        }
        assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            owners(&st, path_lo),
            4,
            "1000 queued bodies with a cold rate is a tip hole"
        );
        assert!(
            !st.inflight
                .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
            "densify stays off once the ahead-block floor is met"
        );
    }

    /// Tip+1 on one hub at genesis, raced by the same six peers across IBD
    /// restarts: when it is a fetch hole, who races it, which owner leaves the
    /// race, and that a peer is never asked for a hash twice. The same hub
    /// then decides the empty, gapped, byte-quarter, and ahead-count tip gaps.
    #[allow(clippy::cognitive_complexity)] // one hub, many tip-hole race arms
    #[test]
    fn ibd_cover_tip_holes() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::progress::claim_ready;
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let (slots, mut wire) = wired_slots(6);
        let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let tip1 = hub.tip_height().unwrap_or(0).saturating_add(1);
        let ago = |s| Instant::now() - Duration::from_secs(s);
        let rx_now =
            |st: &mut IbdWorkState, pid: usize| st.slots[pid].rate.note_rx(ibd_mono_ms().max(1));
        let race = |st: &mut IbdWorkState, alive: &[usize], hole: BlockHash, max: usize| {
            cover_tip_holes(st, &hub, &cfg, alive, &[hole], max)
        };

        // Lookup already took tip+1, so it is not a fetch hole.
        restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
        let three = [0, 1, 2];
        let hole = h(0x11);
        plant_tip_hole(&mut st, hole, tip1);
        hub.query.set_lookup_taken_hi(Some(tip1));
        assert!(contiguous_tip_holes(&mut st, &hub, 8).is_empty());
        assert_eq!(
            race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS),
            0,
            "must not race getdata for a taken height"
        );
        assert!(st.inflight.is_empty());

        // Lookup rewinds. Every live peer races tip+1, fastest first.
        hub.query.set_lookup_taken_hi(None);
        for (pid, bps) in [(0, 100_000), (1, 10_000_000), (2, 1_000_000)] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        assert_eq!(
            rank_peers_by_speed(&st.slots, &three, &HashSet::new()),
            vec![1, 2, 0]
        );
        assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![hole]);
        assert_eq!(race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS), 3);
        assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 1, 0, 0, 0]);

        // Nobody has streamed yet: too early to drop anyone.
        race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
        assert_eq!(st.inflight[&hole].len(), 3, "no rx yet is too early");

        // Slow peer 0 streams. Silent racers leave one per pass, fastest
        // first, keep the request they were sent, and are never asked for
        // it again.
        rx_now(&mut st, 0);
        race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
        let r = &st.inflight[&hole];
        assert!(
            r.holds(1) && !r.peers.contains(&1) && r.peers.contains(&0),
            "silent owner leaves when a sibling streams; peers={:?}",
            r.peers
        );
        for _ in 0..4 {
            race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
        }
        let r = &st.inflight[&hole];
        assert_eq!(r.peers, HashSet::from([0]), "the streaming racer stays");
        assert!(r.holds(1) && r.holds(2));
        assert!(
            st.slots[1].in_flight.contains(&hole),
            "dropped owner still counts the request it holds"
        );
        assert_eq!(
            getdata_asks(&mut wire, hole),
            vec![0; 6],
            "one getdata per peer per hash"
        );

        // A wrong first-wins body at tip+1 is dequeued and the path hash re-got.
        restart_on(&mut st, &hub, &mut wire, &three);
        let want = h(0xabc);
        plant_tip_hole(&mut st, want, tip1);
        hub.query
            .block_queue_offer(tip1, h(0xdef).to_byte_array(), 0, b"wrong")
            .unwrap();
        assert!(hub.query.block_queue_has_height(tip1));
        assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
        assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
        assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
        assert!(
            !hub.query.block_queue_has_height(tip1)
                || hub
                    .query
                    .block_queue_hash_at_height(tip1)
                    .is_some_and(|x| x == want.to_byte_array()),
            "wrong BQ body must be dequeued"
        );
        assert!(st.inflight.contains_key(&want));

        // After a restart the resume seed knows tip+1 from Class A, but confirm
        // reads only the body queue. Still a hole.
        restart_on(&mut st, &hub, &mut wire, &three);
        plant_tip_hole(&mut st, want, tip1);
        st.body.mark_archived(want);
        assert!(st.body.is_known_archived(&want) && !st.body.is_pending(&want));
        assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
        assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
        assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
        assert!(st.inflight.contains_key(&want));

        // Pending with no body-queue wire is a zombie: re-get it and demote it.
        restart_on(&mut st, &hub, &mut wire, &three);
        plant_tip_hole(&mut st, want, tip1);
        st.body.mark_pending(want);
        assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
        assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
        assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
        assert!(st.inflight.contains_key(&want));
        assert!(!st.body.is_pending(&want), "cover demotes zombie pending");

        // A tight pack of streaming racers keeps its owners however old the
        // request is.
        restart_on(&mut st, &hub, &mut wire, &three);
        let hole = h(0x51);
        plant_tip_hole(&mut st, hole, tip1);
        for (pid, bps) in [(0, 1_000_000), (1, 1_100_000), (2, 1_050_000)] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        race(&mut st, &three, hole, 2);
        assert_eq!(st.inflight[&hole].peers, HashSet::from([1, 2]));
        st.inflight.get_mut(&hole).unwrap().started_at = ago(7);
        rx_now(&mut st, 1);
        rx_now(&mut st, 2);
        race(&mut st, &three, hole, 2);
        assert_eq!(
            st.inflight[&hole].peers,
            HashSet::from([1, 2]),
            "tight pack with live rx keeps owners"
        );

        // A quarter-median racer among streaming racers leaves.
        restart_on(&mut st, &hub, &mut wire, &three);
        let hole = h(0x53);
        plant_tip_hole(&mut st, hole, tip1);
        for (pid, bps) in [(0, 400_000), (1, 2_000_000), (2, 1_900_000)] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        race(&mut st, &three, hole, 3);
        assert_eq!(st.inflight[&hole].len(), 3);
        for pid in three {
            rx_now(&mut st, pid);
        }
        race(&mut st, &three, hole, 3);
        let r = &st.inflight[&hole];
        assert!(
            !r.peers.contains(&0),
            "slow outlier leaves; peers={:?}",
            r.peers
        );

        // Peer 0 is the only live peer. It keeps an aged hole while it
        // streams, and loses it once rx stops for 30 s.
        restart_on(&mut st, &hub, &mut wire, &[0]);
        let hole = h(0x54);
        plant_tip_hole(&mut st, hole, tip1);
        assert_eq!(race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS), 1);
        rx_now(&mut st, 0);
        let req = st.inflight.get_mut(&hole).unwrap();
        req.started_at = ago(31);
        req.asked_at.insert(0, ago(31));
        race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS);
        assert!(
            st.inflight[&hole].peers.contains(&0),
            "a sole streaming peer keeps the hole"
        );
        st.slots[0].rate.progress_ms = 0;
        race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS);
        let r = &st.inflight[&hole];
        assert!(
            r.peers.is_empty() && r.holds(0),
            "a silent owner is dropped after 30 s even alone"
        );

        // Peer 1 connects and takes the hole.
        st.slots[1].alive = true;
        seed_ewma(&mut st.slots[1], 2_000_000);
        race(&mut st, &[0, 1], hole, TIP_HOLE_MAX_PEERS);
        assert_eq!(st.inflight[&hole].peers, HashSet::from([1]));

        // Peer 1 streams but holds it 31 s while peer 2 is connected.
        rx_now(&mut st, 1);
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(1, ago(31));
        st.slots[2].alive = true;
        seed_ewma(&mut st.slots[2], 1_000_000);
        race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
        let r = &st.inflight[&hole];
        assert!(
            !r.peers.contains(&1) && r.peers.contains(&2),
            "an aged owner leaves when another peer exists; peers={:?}",
            r.peers
        );

        // The hash is old but peer 2 was asked just now: age counts from the
        // owner's ask.
        st.inflight.get_mut(&hole).unwrap().started_at = ago(31);
        rx_now(&mut st, 2);
        st.slots[3].alive = true;
        seed_ewma(&mut st.slots[3], 1_000_000);
        race(&mut st, &[0, 1, 2, 3], hole, 1);
        let r = &st.inflight[&hole];
        assert!(
            r.peers.contains(&2) && !r.peers.contains(&3),
            "an owner asked just now is not aged; peers={:?}",
            r.peers
        );

        // A fast peer with densify queued drains sooner than an idle slow
        // one. Held 6 s, it keeps the hole: the idle peer would not start it
        // clearly sooner.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        let hole = h(0x56);
        plant_tip_hole(&mut st, hole, tip1);
        seed_ewma(&mut st.slots[0], 10_000_000);
        seed_ewma(&mut st.slots[1], 100_000);
        for i in 0..4u32 {
            st.slots[0].in_flight.insert(h(1000 + i));
        }
        assert_eq!(
            rank_peers_for_tip_hole(&st.slots, &[0, 1], &HashSet::new())[0],
            0
        );
        race(&mut st, &[0, 1], hole, 1);
        assert_eq!(st.inflight[&hole].peers, HashSet::from([0]));
        rx_now(&mut st, 0);
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(0, ago(6));
        race(&mut st, &[0, 1], hole, 1);
        assert_eq!(st.inflight[&hole].peers, HashSet::from([0]));

        // Peer 0 has densify ahead of the hole. Alone it keeps it. Once a
        // faster empty peer connects, it keeps it for 5 s, then leaves it.
        restart_on(&mut st, &hub, &mut wire, &[0]);
        let hole = h(0x57);
        plant_tip_hole(&mut st, hole, tip1);
        seed_ewma(&mut st.slots[0], 2_000_000);
        st.slots[0].in_flight.insert(h(0x99));
        race(&mut st, &[0], hole, 1);
        rx_now(&mut st, 0);
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(0, ago(6));
        race(&mut st, &[0], hole, 1);
        assert_eq!(
            st.inflight[&hole].peers,
            HashSet::from([0]),
            "no one else to race"
        );
        st.slots[1].alive = true;
        seed_ewma(&mut st.slots[1], 10_000_000);
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(0, Instant::now());
        race(&mut st, &[0, 1], hole, 1);
        assert_eq!(
            st.inflight[&hole].peers,
            HashSet::from([0]),
            "young owner has not had time to reach the hash"
        );
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(0, ago(6));
        race(&mut st, &[0, 1], hole, 2);
        let r = &st.inflight[&hole];
        assert!(
            r.holds(0) && r.peers == HashSet::from([1]),
            "densify-FIFO owner leaves for the empty fast peer; peers={:?}",
            r.peers
        );
        assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 0, 0, 0, 0]);

        // Peer 1 holds only the hole, so the FIFO rule never drops it, not
        // even for a much faster empty peer.
        st.slots[2].alive = true;
        seed_ewma(&mut st.slots[2], 50_000_000);
        rx_now(&mut st, 1);
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(1, ago(6));
        race(&mut st, &three, hole, 2);
        let r = &st.inflight[&hole];
        assert!(r.peers.contains(&1) && !r.holds(2));

        // Peers who still owe the block count toward the race cap.
        let four = [0, 1, 2, 3];
        restart_on(&mut st, &hub, &mut wire, &four);
        let hole = h(0x5c);
        plant_tip_hole(&mut st, hole, tip1);
        for pid in four {
            seed_ewma(&mut st.slots[pid], 1_000_000);
        }
        race(&mut st, &four, hole, 2);
        assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 0, 0, 0, 0]);
        st.slots[0].in_flight.insert(h(0x99));
        st.inflight
            .get_mut(&hole)
            .unwrap()
            .asked_at
            .insert(0, ago(6));
        for pid in four {
            rx_now(&mut st, pid);
        }
        for _ in 0..5 {
            race(&mut st, &four, hole, 2);
        }
        let r = &st.inflight[&hole];
        assert!(!r.peers.contains(&0) && r.holds(0) && r.holds(1));
        assert!(!r.holds(2) && !r.holds(3));
        assert_eq!(
            getdata_asks(&mut wire, hole),
            vec![0; 6],
            "two peers already owe the block; cap is 2"
        );

        // A quarter-full body queue races tip+1 on four peers and each later
        // contiguous hole on one.
        let six = [0, 1, 2, 3, 4, 5];
        restart_on(&mut st, &hub, &mut wire, &six);
        plant_work_path(&mut st, tip1, tip1.saturating_add(31));
        for pid in six {
            seed_ewma(&mut st.slots[pid], 2_000_000);
        }
        plant_quarter_window(&hub, tip1);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        let racers = |st: &IbdWorkState, ht: u32| st.inflight.get(&h(ht)).map_or(0, |r| r.len());
        assert_eq!(racers(&st, tip1), TIP_HOLE_MAX_PEERS);
        assert_eq!(racers(&st, tip1.saturating_add(1)), 1);
        assert_eq!(racers(&st, tip1.saturating_add(2)), 1);

        // With tip+2..=tip+4 in hand, tip+1 still races and the later gap waits.
        restart_on(&mut st, &hub, &mut wire, &[0, 1, 2, 3, 4]);
        plant_work_path(&mut st, tip1, tip1.saturating_add(31));
        mark_heights_ready(
            &mut st,
            &hub,
            tip1.saturating_add(1),
            tip1.saturating_add(3),
        );
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        plant_quarter_window(&hub, tip1);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert_eq!(racers(&st, tip1), TIP_HOLE_MAX_PEERS);
        assert!(
            !st.inflight.contains_key(&h(tip1.saturating_add(4))),
            "pre-hole waits while the prefix hole is open"
        );

        // Tip+1..=tip+4 in hand: the first gap is a pre-hole. A fast young
        // owner stays solo, including on an old request, until its own ask
        // ages. Then one fresh racer replaces it.
        restart_on(&mut st, &hub, &mut wire, &four);
        plant_work_path(&mut st, tip1, tip1.saturating_add(31));
        mark_heights_ready(&mut st, &hub, tip1, tip1.saturating_add(3));
        let gap_ht = tip1.saturating_add(4);
        let gap = h(gap_ht);
        assert_eq!(first_pre_hole(&mut st, &hub, TIP_HOLE_MAX), Some(gap));
        for (pid, bps) in [
            (0, 2_000_000),
            (1, 2_000_000),
            (2, 1_800_000),
            (3, 1_900_000),
        ] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        race(&mut st, &[0], gap, 1);
        rx_now(&mut st, 0);
        let past_gap_raced_once = |st: &IbdWorkState| {
            (gap_ht.saturating_add(1)..=gap_ht.saturating_add(27)).all(|ht| racers(st, ht) <= 1)
        };
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(racers(&st, gap_ht), 1, "fast young owner stays solo");
        assert!(past_gap_raced_once(&st));
        st.inflight.get_mut(&gap).unwrap().started_at = ago(31);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(racers(&st, gap_ht), 1, "an old request with a fresh ask");
        st.inflight
            .get_mut(&gap)
            .unwrap()
            .asked_at
            .insert(0, ago(31));
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&gap];
        assert!(r.holds(0) && !r.peers.contains(&0), "aged owner is retired");
        assert_eq!(r.len(), 1, "one fresh racer replaces it");
        assert_eq!(r.holders(), PRE_HOLE_MAX_PEERS);

        // A quarter-median pre-hole owner gets one extra racer, not a window.
        restart_on(&mut st, &hub, &mut wire, &four);
        plant_work_path(&mut st, tip1, tip1.saturating_add(31));
        mark_heights_ready(&mut st, &hub, tip1, tip1.saturating_add(3));
        for (pid, bps) in [(0, 250_000), (1, 1_000_000), (2, 1_000_000), (3, 1_000_000)] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        race(&mut st, &[0], gap, 1);
        rx_now(&mut st, 0);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(racers(&st, gap_ht), PRE_HOLE_MAX_PEERS);
        assert!(past_gap_raced_once(&st));

        tip_gap_frontier_and_holes(&hub);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Serialize env mutators — parallel suite races `bq_assign_stop_bytes`.
    static BQ_ASSIGN_STOP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(in crate::ibd) struct AssignStopEnvRestore(
        Option<std::ffi::OsString>,
        Option<std::ffi::OsString>,
    );
    impl Drop for AssignStopEnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", v),
                None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES"),
            }
            match self.1.take() {
                Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", v),
                None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB"),
            }
        }
    }

    /// Tuple fields drop in order: the env is restored before the lock is
    /// released, so the next holder's own setting survives.
    pub(in crate::ibd) fn lock_default_assign_stop(
    ) -> (AssignStopEnvRestore, std::sync::MutexGuard<'static, ()>) {
        let g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let restore = AssignStopEnvRestore(
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES"),
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB"),
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        (restore, g)
    }

    /// Densify on one hub at genesis across IBD restarts: assign depth, the
    /// tip batch, band limits from the body queue, per-peer caps, hung
    /// owners, and reorg need.
    #[allow(clippy::cognitive_complexity)] // one hub, many densify arms
    #[test]
    fn assign_depth_densify_cache_and_early_exits() {
        use super::super::dial::release_peer_block_work;
        use super::super::peer_io::ibd_mono_ms;
        use rbitcoin_query::{soft_confirm_window_n, BQ_SOFT_FREE_BYTES};
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let (slots, mut wire) = wired_slots(3);
        let mut st = IbdWorkState::new(slots, None, Some(0));
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 8;
        let ago = |s| Instant::now() - Duration::from_secs(s);
        let issued_heights = |st: &IbdWorkState| -> Vec<u32> {
            st.inflight
                .keys()
                .filter_map(|hash| st.hash_height.get(hash).copied())
                .collect()
        };
        let enqueue = |st: &mut IbdWorkState, ht: u32, payload: &[u8]| {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, payload)
                .unwrap();
            st.body.mark_pending(h(ht));
        };

        for ht in 1u32..=12 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        plant_quarter_window(&hub, 1);

        assign_work_ordered(
            &mut st,
            &hub,
            &cfg,
            &stats,
            AssignDepth::Critical,
            Some(5.0),
        );
        let after_crit = st.inflight.len();
        assert!(after_crit > 0, "critical should still issue tip/race");

        let n_before = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert!(st.inflight.len() <= n_before + 8);

        let hashes: Vec<_> = st.inflight.keys().copied().collect();
        for hash in hashes {
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            st.body.mark_missing(hash);
        }
        st.body.mark_pending(h(5));
        let _ = st
            .body
            .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
        st.body.mark_pending(h(5));
        st.body.mark_pending(h(1));
        let expired = st
            .body
            .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
        for hash in expired {
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            st.body.mark_missing(hash);
        }

        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(!st.inflight.is_empty());
        assert!(stats.assign_issued.load(Ordering::Relaxed) > 0);

        for ht in 20u32..20 + cfg.window as u32 {
            let hash = h(ht + 100);
            inflight_add_peer(&mut st.inflight, hash, 0);
            st.slots[0].in_flight.insert(hash);
        }
        let n_full = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(st.inflight.len() <= n_full + 2);

        st.inflight.clear();
        st.slots[0].in_flight.clear();
        st.slots[1].in_flight.clear();
        for ht in 1u32..=4 {
            let hash = h(ht);
            st.body.mark_missing(hash);
        }
        for i in 0..cfg.per_peer {
            let hash = h(200 + i as u32);
            st.slots[0].in_flight.insert(hash);
            inflight_add_peer(&mut st.inflight, hash, 0);
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(!st.slots[1].in_flight.is_empty() || st.inflight.len() > cfg.per_peer);

        // Claim-ready: pending **with** body-queue wire (not Class A alone).
        // Zombie pending without BQ is a tip fetch hole (cover_tip_holes re-gets).
        let tiny = [0u8; 8];
        for ht in 1u32..=12 {
            let hash = h(ht);
            hub.query
                .block_queue_enqueue(ht, hash.to_byte_array(), ht as u64, &tiny)
                .unwrap();
            st.body.mark_pending(hash);
        }
        st.inflight.clear();
        st.slots.iter_mut().for_each(|s| s.in_flight.clear());
        st.max_ready_height = 12;
        st.max_ordered_height = 12;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.is_empty(),
            "claim-ready tip band must not re-get; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );

        // Tip+1 is a hole behind a quarter-full queue: nothing is densified
        // past it.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 64;
        cfg.per_peer = 16;
        plant_work_path(&mut st, 1, 40);
        mark_heights_ready(&mut st, &hub, 2, 32);
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 2_000_000);
        plant_quarter_window(&hub, 1);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert_eq!(
            issued_heights(&st),
            vec![1],
            "far densify must not issue while tip+1 is a fetch hole"
        );

        // Under the free-byte floor densify fills far ahead even at a slow
        // tip rate, and skips heights lookup has already taken.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        plant_work_path(&mut st, 1, 100);
        for ht in 1u32..=10 {
            enqueue(&mut st, ht, b"x");
        }
        assert!(hub.query.block_queue_stats().1 < BQ_SOFT_FREE_BYTES);
        hub.query.set_lookup_taken_hi(Some(20));
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(0.1));
        hub.query.set_lookup_taken_hi(None);
        let issued = issued_heights(&st);
        assert!(
            issued.contains(&21) && issued.iter().all(|&ht| ht > 20),
            "the first gap is above the taken height; issued={issued:?}"
        );
        assert!(
            issued.iter().any(|&ht| ht > 21),
            "under free bytes densify runs past the 1-min window; issued={issued:?}"
        );

        // A queued prefix moves the densify cursor past it.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 128;
        cfg.per_peer = 64;
        plant_work_path(&mut st, 1, 80);
        for ht in 1u32..=40 {
            enqueue(&mut st, ht, b"x");
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.densify_scan_lo >= 41,
            "queued 1..=40 must bump scan_lo; scan_lo={}",
            st.densify_scan_lo
        );
        assert!(
            issued_heights(&st).iter().all(|&ht| ht > 40),
            "must not getdata heights already queued"
        );

        // Past the legacy 2048-height ceiling when the queue allows it.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 128;
        cfg.per_peer = 16;
        plant_work_path(&mut st, 1, 2200);
        for ht in 1u32..=2040 {
            enqueue(&mut st, ht, &[0u8; 8]);
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let far = issued_heights(&st);
        assert!(
            far.iter().any(|&ht| ht > 2048),
            "legacy CONTIG_DENSIFY_AHEAD=2048 must not be the ceiling; issued={far:?}"
        );

        // Over the free-byte floor densify stays inside the confirm window:
        // 0.1 blk/s × 60 s is heights 1..=6.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 64;
        plant_work_path(&mut st, 1, 200);
        let chunk = vec![0u8; 55 * 1024 * 1024];
        enqueue(&mut st, 1, &chunk);
        enqueue(&mut st, 2, &chunk);
        drop(chunk);
        assert!(hub.query.block_queue_stats().1 > BQ_SOFT_FREE_BYTES);
        assert_eq!(soft_confirm_window_n(Some(0.1)), 6);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(0.1));
        let issued = issued_heights(&st);
        assert!(
            !issued.is_empty() && issued.iter().all(|&ht| ht <= 6),
            "densify only inside the confirm window; issued={issued:?}"
        );

        // At the assign-stop nothing new is requested.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 128;
        cfg.per_peer = 64;
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "2048");
        plant_work_path(&mut st, 1, 500);
        for ht in 1u32..=TIP_HOLE_MAX as u32 {
            enqueue(&mut st, ht, b"x");
        }
        enqueue(&mut st, 500, &[0u8; 4096]);
        assert!(hub.query.block_queue_stats().1 >= 2048);
        assert_eq!(hub.query.block_queue_max_height(), Some(500));
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        assert!(
            st.inflight.is_empty(),
            "queue already at the assign-stop: no new getdata; issued={:?}",
            issued_heights(&st)
        );

        // Tip+1 in hand and tip+2 the pre-hole. Past it, densify re-gets a
        // zombie pending (no wire) and a wrong first-wins body by path hash.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        cfg.window = 32;
        cfg.per_peer = 8;
        plant_work_path(&mut st, 1, 4);
        enqueue(&mut st, 1, b"ok1");
        st.body.mark_pending(h(3));
        hub.query
            .block_queue_offer(4, h(0x99).to_byte_array(), 0, b"wrong4")
            .unwrap();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!((2..=4).all(|ht| st.inflight.contains_key(&h(ht))));
        assert!(
            !st.body.is_pending(&h(3)),
            "zombie pending demoted before issue"
        );
        assert!(
            !hub.query.block_queue_has_height(4)
                || hub
                    .query
                    .block_queue_hash_at_height(4)
                    .is_some_and(|x| x == h(4).to_byte_array()),
            "wrong body at a densify height is dequeued"
        );

        // A most-work reorg needs two bodies. Both are fetched by hash, one
        // although its height holds another body.
        restart_on(&mut st, &hub, &mut wire, &[0]);
        cfg.window = 16;
        cfg.per_peer = 4;
        let (need, mid) = (h(0xab), h(0xac));
        st.record_height(need, 1);
        hub.query
            .block_queue_offer(1, h(0xde).to_byte_array(), 0, b"loser")
            .unwrap();
        assert!(!hub.query.block_queue_has_hash(&need.to_byte_array()));
        st.reorg.register_explore([need, mid], None);
        st.body.mark_missing(need);
        st.body.mark_missing(mid);
        assert_eq!(
            st.reorg.need_getdata().into_iter().collect::<HashSet<_>>(),
            HashSet::from([need, mid])
        );
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(st.inflight.contains_key(&need) && st.inflight.contains_key(&mid));

        // The first densify hash goes to the fastest peer. A 2×-median peer
        // gets the full cap, the others half.
        restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
        cfg.window = 128;
        cfg.per_peer = 16;
        plant_work_path(&mut st, 1, 52);
        mark_tip_batch_ready(&mut st, &hub, 1);
        for (pid, bps) in [(0, 5_000_000), (1, 15_000_000), (2, 5_000_000)] {
            seed_ewma(&mut st.slots[pid], bps);
        }
        st.densify_scan_lo = 33;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(st.inflight[&h(33)].peers.contains(&1));
        assert_eq!(st.slots[1].in_flight.len(), 16);
        assert!(st.slots[0].in_flight.len() <= 8 && st.slots[2].in_flight.len() <= 8);

        // Every peer at its cap: no band walk, and the cursor stays.
        restart_on(&mut st, &hub, &mut wire, &[0, 1]);
        plant_work_path(&mut st, 1, 70);
        mark_tip_batch_ready(&mut st, &hub, 1);
        for i in 0..16u32 {
            let pid = (i % 2) as usize;
            let mut room = 1;
            let mut issued = 0;
            assert!(issue_one(&mut st, pid, h(40 + i), &mut room, &mut issued));
        }
        st.densify_scan_lo = 40;
        let before: HashSet<_> = st.inflight.keys().copied().collect();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let after: HashSet<_> = st.inflight.keys().copied().collect();
        assert_eq!(after, before, "no new densify when peers at cap");
        assert_eq!(st.densify_scan_lo, 40);

        // Peer 0 disconnects holding work below the cursor. Densify re-asks
        // it only once the cursor is rewound.
        restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
        plant_work_path(&mut st, 1, 49);
        mark_tip_batch_ready(&mut st, &hub, 1);
        seed_ewma(&mut st.slots[1], 1_000_000);
        seed_ewma(&mut st.slots[2], 1_000_000);
        let lost = h(45);
        let mut room = 1;
        let mut issued = 0;
        assert!(issue_one(&mut st, 0, lost, &mut room, &mut issued));
        st.densify_scan_lo = 50;
        let freed = release_peer_block_work(&mut st.slots, &mut st.inflight, &mut st.body, 0);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(!st.inflight.contains_key(&lost), "below the cursor");
        st.reopen_for_densify(&freed);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(st.inflight.contains_key(&lost), "reopened work is re-asked");

        // Only tip+40 is missing, asked of peer 0. Silent but asked just now,
        // it keeps the hash from faster peer 1. Hung 31 s with peer 1 gone,
        // nothing faster can take it. While peer 0 streams it keeps it. Once
        // silent, peer 1 takes it. When peer 1 hangs too, the steal skips
        // peer 0, which still holds the request, for peer 2.
        restart_on(&mut st, &hub, &mut wire, &[0]);
        cfg.window = 64;
        plant_work_path(&mut st, 1, 40);
        mark_heights_ready(&mut st, &hub, 1, 39);
        let hung = h(40);
        let mut room = 1;
        let mut issued = 0;
        assert!(issue_one(&mut st, 0, hung, &mut room, &mut issued));
        let age_owner = |st: &mut IbdWorkState, pid: usize| {
            let req = st.inflight.get_mut(&hung).unwrap();
            req.started_at = ago(31);
            req.asked_at.insert(pid, ago(31));
        };
        st.slots[1].alive = true;
        seed_ewma(&mut st.slots[1], 1_000_000);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            st.inflight[&hung].peers,
            HashSet::from([0]),
            "a young request is not hung"
        );
        st.slots[1].alive = false;
        age_owner(&mut st, 0);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            st.inflight[&hung].peers,
            HashSet::from([0]),
            "no faster peer"
        );
        st.slots[1].alive = true;
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(st.inflight[&hung].peers, HashSet::from([0]), "live rx");
        st.slots[0].rate.progress_ms = 0;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.peers == HashSet::from([1]) && r.holds(0),
            "hung densify moves to the faster peer; peers={:?}",
            r.peers
        );
        st.slots[0].rate = Default::default();
        seed_ewma(&mut st.slots[0], 9_000_000);
        st.slots[2].alive = true;
        seed_ewma(&mut st.slots[2], 5_000_000);
        age_owner(&mut st, 1);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.peers == HashSet::from([2]) && r.holds(0) && r.holds(1),
            "steal skips a peer that already holds the hash; peers={:?}",
            r.peers
        );

        // No faster peer has a free slot: the hung owner is retired, keeps
        // its request, and the cursor rewinds to it. Once a slot frees the
        // freed peer is asked, even with the getdata window full, and the
        // hung peer is not asked again.
        restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
        cfg.window = 64;
        cfg.per_peer = 2;
        plant_work_path(&mut st, 1, 40);
        enqueue(&mut st, 1, &[0u8; 80]);
        let mut room = 1;
        let mut issued = 0;
        assert!(issue_one(&mut st, 0, hung, &mut room, &mut issued));
        age_owner(&mut st, 0);
        for n in 0..2 {
            st.slots[1].in_flight.insert(h(300 + n));
            st.slots[2].in_flight.insert(h(400 + n));
        }
        seed_ewma(&mut st.slots[1], 5_000_000);
        seed_ewma(&mut st.slots[2], 4_000_000);
        st.densify_scan_lo = 50;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.holds(0) && r.peers.is_empty(),
            "no free faster slot retires the hung owner; peers={:?}",
            r.peers
        );
        assert!(st.slots[0].in_flight.contains(&hung));
        assert!(st.densify_scan_lo <= 40, "scan_lo={}", st.densify_scan_lo);
        seed_ewma(&mut st.slots[0], 9_000_000);
        st.slots[1].in_flight.clear();
        cfg.window = 1;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.peers.contains(&1) && r.holds(0) && !r.peers.contains(&0),
            "the freed peer is asked; the hung peer stays retired; peers={:?}",
            r.peers
        );
        assert_eq!(getdata_asks(&mut wire, hung), vec![1, 1, 0]);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Assign-stop charge is the max of the last 32 recorded bodies, capped
    /// at 4 MiB. Under 8 samples it stays 4 MiB. A hash already in flight
    /// does not need another charge.
    #[test]
    fn intake_reserve_charges_max_of_recent_bodies() {
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, None);
        let mut room = 64usize;
        let mut issued = 0u64;

        for _ in 0..7 {
            note_block_len(&mut st, 50_000);
        }
        st.intake_queued = 0;
        st.intake_stop = GETDATA_RESERVE_BYTES - 1;
        assert!(
            !issue_one(&mut st, 0, h(1), &mut room, &mut issued),
            "seven samples still need a full 4 MiB"
        );
        st.intake_stop = GETDATA_RESERVE_BYTES;
        assert!(
            issue_one(&mut st, 0, h(1), &mut room, &mut issued),
            "exactly 4 MiB fits one new hash before eight samples"
        );
        assert!(
            !issue_one(&mut st, 0, h(2), &mut room, &mut issued),
            "a second new hash still needs another 4 MiB"
        );

        st.inflight.clear();
        for slot in &mut st.slots {
            slot.in_flight.clear();
        }
        st.block_lens.clear();
        let samples = [
            100_000u32, 50_000, 200_000, 80_000, 10_000, 90_000, 120_000, 40_000,
        ];
        for n in samples {
            note_block_len(&mut st, n as usize);
        }
        let max_len = u64::from(*samples.iter().max().unwrap());
        let queued = 1_000_000u64;
        let headroom = max_len * 5 + max_len / 2;
        st.intake_queued = queued;
        st.intake_stop = queued + headroom;
        room = 64;
        let mut fit = 0u32;
        for i in 0..8u32 {
            let before = st.inflight.len();
            let _ = issue_one(&mut st, 0, h(100 + i), &mut room, &mut issued);
            if st.inflight.len() > before {
                fit += 1;
            }
        }
        let by_max = (headroom / max_len) as u32;
        let by_flat = (headroom / GETDATA_RESERVE_BYTES) as u32;
        assert_eq!(
            fit, by_max,
            "headroom {headroom} at max {max_len} fits {by_max}, flat 4 MiB would fit {by_flat}"
        );

        st.inflight.clear();
        for slot in &mut st.slots {
            slot.in_flight.clear();
        }
        st.block_lens.clear();
        note_block_len(&mut st, 4_000_000);
        for _ in 0..32 {
            note_block_len(&mut st, 100_000);
        }
        let window_max = 100_000u64;
        st.intake_queued = 0;
        st.intake_stop = window_max * 3 + window_max / 2;
        room = 16;
        fit = 0;
        for i in 0..6u32 {
            let before = st.inflight.len();
            let _ = issue_one(&mut st, 0, h(400 + i), &mut room, &mut issued);
            if st.inflight.len() > before {
                fit += 1;
            }
        }
        assert_eq!(
            fit,
            (st.intake_stop / window_max) as u32,
            "a max that aged out of the 32-ring must not keep the charge"
        );

        st.inflight.clear();
        for slot in &mut st.slots {
            slot.in_flight.clear();
        }
        st.block_lens.clear();
        for _ in 0..8 {
            note_block_len(&mut st, 5 * 1024 * 1024);
        }
        st.intake_queued = 0;
        st.intake_stop = GETDATA_RESERVE_BYTES;
        room = 8;
        assert!(
            issue_one(&mut st, 0, h(200), &mut room, &mut issued),
            "a recorded length above 4 MiB still charges 4 MiB"
        );
        assert!(
            !issue_one(&mut st, 0, h(201), &mut room, &mut issued),
            "the ceiling is one 4 MiB charge, not the recorded length"
        );

        st.inflight.clear();
        for slot in &mut st.slots {
            slot.in_flight.clear();
        }
        st.block_lens.clear();
        for _ in 0..8 {
            note_block_len(&mut st, max_len as usize);
        }
        st.intake_queued = 0;
        st.intake_stop = max_len;
        room = 8;
        assert!(issue_one(&mut st, 0, h(300), &mut room, &mut issued));
        st.intake_stop = max_len - 1;
        assert!(
            issue_one(&mut st, 1, h(300), &mut room, &mut issued),
            "a hash already in flight is issued with no new charge"
        );
        assert!(
            !issue_one(&mut st, 1, h(301), &mut room, &mut issued),
            "a different hash still needs a full charge"
        );
    }

    #[test]
    fn hostile_peer_session() {
        let _g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = AssignStopEnvRestore(
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES"),
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB"),
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let four_mib = GETDATA_RESERVE_BYTES;
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        st.intake_queued = 0;
        st.intake_stop = four_mib - 1;
        let mut room = 10usize;
        let mut issued = 0u64;
        assert!(
            !issue_one(&mut st, 0, h(32), &mut room, &mut issued),
            "one byte under 4 MiB cannot reserve a new hash"
        );
        assert!(st.inflight.is_empty());

        st.intake_stop = four_mib;
        assert!(
            issue_one(&mut st, 0, h(31), &mut room, &mut issued),
            "one new hash fits in exactly 4 MiB"
        );
        assert!(st.inflight.contains_key(&h(31)));
        let before = st.inflight.len();
        assert!(
            !issue_one(&mut st, 0, h(33), &mut room, &mut issued),
            "a second hash would pass the 4 MiB stop"
        );
        assert_eq!(st.inflight.len(), before);
        assert!(!st.inflight.contains_key(&h(33)));

        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "1000");
        plant_work_path(&mut st, 1, 2);
        let queued = vec![0u8; 1000];
        hub.query
            .block_queue_enqueue(50, h(50).to_byte_array(), 50, &queued)
            .unwrap();
        assert!(hub.query.block_queue_stats().1 >= 1000);
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            !st.inflight.contains_key(&h(1)) && !st.inflight.contains_key(&h(2)),
            "queue already at the stop: no new getdata; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
