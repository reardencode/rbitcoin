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
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_net::chain::ChainHub;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// After this long with no confirm progress and nothing useful to fetch, stop getdata.
pub const STUCK_GATE_AFTER: Duration = Duration::from_secs(30);

/// True when confirm cannot advance and there is no valid body still worth fetching.
pub fn download_gate_closed(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let Some(since) = st.confirm_stuck_since else {
        return false;
    };
    if since.elapsed() < STUCK_GATE_AFTER {
        return false;
    }
    !need_any_valid_body_download(st, hub)
}

#[doc(hidden)]
pub fn need_any_valid_body_download(st: &IbdWorkState, hub: &ChainHub) -> bool {
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

#[doc(hidden)]
pub fn need_body_dead(st: &IbdWorkState, h: &BlockHash) -> bool {
    st.reorg.invalid.contains(h.to_byte_array()) || st.body.is_rejected(h)
}

#[doc(hidden)]
pub fn need_body_in_hand(st: &IbdWorkState, hub: &ChainHub, h: &BlockHash) -> bool {
    hub.has_block(h)
        || st.body.is_known_archived(h)
        || hub.query.block_queue_has_hash(&h.to_byte_array())
}

#[doc(hidden)]
pub fn need_path_lo_alt(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
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

#[doc(hidden)]
pub fn need_contig_ahead(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
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

#[doc(hidden)]
pub fn need_reorg_getdata(st: &IbdWorkState, hub: &ChainHub) -> bool {
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
pub enum AssignDepth {
    /// Tip-batch multi-peer only (BQ soft window covered / no densify room).
    Critical,
    /// Tip batch + densify (gap always; frontier when soft depth allows).
    Full,
}

/// Drop `hash` from global inflight and every peer's in_flight set.
pub fn clear_hash_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hash: BlockHash,
) {
    inflight.remove(&hash);
    for s in slots.iter_mut() {
        s.track_remove(&hash);
    }
}

/// Free peer/global slots for hashes already on the confirmed tip (RAM set).
pub fn prune_satisfied_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hub: &ChainHub,
) {
    inflight.retain(|h, _| !hub.has_block(h));
    let now_ms = ibd_mono_ms();
    for s in slots.iter_mut() {
        s.expire_late_answers(now_ms);
        s.track_retain(|h| !hub.has_block(h));
    }
}

/// Drop getdata that cannot feed the work path or a live awaiting-reorg gather.
///
/// Speculative `explore_need` is not kept: assign re-issues it while remainder
/// is live. Off-path leftovers otherwise sat in inflight forever (mainnet
/// 08:16:23 / 04:14).
pub fn prune_off_path_inflight(st: &mut IbdWorkState) {
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
pub fn inflight_add_peer(
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
pub fn bq_pipeline_saturated(inflight_len: usize, bq_confirm_window_covered: bool) -> bool {
    inflight_len < 16 && bq_confirm_window_covered
}

/// Assign getdata for the body-queue pipeline.
///
/// `tip_rate_blocks_per_s`: tip confirm rate for the soft confirm-time window
/// when BQ payload is over [`rbitcoin_query::BQ_SOFT_FREE_BYTES`].
pub fn assign_work_ordered(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    loop_stats: &LoopStats,
    depth: AssignDepth,
    tip_rate_blocks_per_s: Option<f64>,
) {
    let t0 = Instant::now();
    let mut issued = 0u64;
    let now_secs = hub.clock.now_secs();
    for s in &mut st.slots {
        s.resume_block_download_if_due(now_secs);
    }
    let alive: Vec<usize> = st
        .slots
        .iter()
        .filter(|s| s.takes_block_requests())
        .map(|s| s.id)
        .collect();
    if alive.is_empty() {
        return;
    }

    let (bq_bytes, bq_count) = hub.query.block_queue_stats();
    let bq_stop = cfg.assign_stop_bytes;
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
    if !race_tip && ahead_n > 0 && alive.len() > 1 {
        if let Some(&hash) = tip_holes.first() {
            if retire_header_timeout_frontier_owners(st, hash) {
                issued += cover_tip_holes(st, hub, cfg, &alive, &[hash], 1);
            }
        }
    }
    if race_tip {
        issued += cover_tip_batch_holes(st, hub, cfg, &alive, &tip_holes);
    } else {
        // Densify skips a Class A seed (`need_hash_at`). Without a race,
        // only this cover gets an archived tip hole back into the queue.
        let archived: Vec<BlockHash> = tip_holes
            .iter()
            .copied()
            .filter(|h| st.body.is_known_archived(h))
            .collect();
        issued += cover_tip_holes(st, hub, cfg, &alive, &archived, 1);
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

fn retire_header_timeout_frontier_owners(st: &mut IbdWorkState, hash: BlockHash) -> bool {
    let owners: Vec<_> = st
        .inflight
        .get(&hash)
        .map(|request| {
            request
                .peers
                .iter()
                .chain(&request.retired)
                .copied()
                .filter(|peer| st.header_walk.header_timeout_peers.contains(peer))
                .collect()
        })
        .unwrap_or_default();
    let retained = !owners.is_empty();
    for peer in owners {
        retire_hash_owner(st, hash, peer);
    }
    retained
}

#[doc(hidden)]
pub fn assign_reorg_need(
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
        let ht = st.hash_height.get(&h).copied();
        let held =
            st.body.is_pending(&h) && ht.is_some_and(|ht| confirm_pipeline_holds(st, hub, h, ht));
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, ht, held);
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

#[doc(hidden)]
pub struct DensifyCtx<'a> {
    pub loop_stats: &'a LoopStats,
    pub t0: Instant,
    pub issued: u64,
    pub path_lo: u32,
    pub tip_batch_hi: u32,
    pub race_tip: bool,
    pub tip_rate_blocks_per_s: Option<f64>,
}

#[doc(hidden)]
pub fn assign_densify(
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
    if path_lo < st.assign_path_lo {
        st.densify_scan_lo = path_lo;
        st.densify_ready_through = path_lo;
    }
    st.assign_path_lo = path_lo;
    st.densify_scan_lo = st.densify_scan_lo.max(path_lo);
    rewind_densify_scan_lo(st, hub, path_lo);
    // Window is full and no retired holder is waiting for a racer. The cursor
    // already rewound. Skip issuing.
    if room == 0 && !st.inflight.values().any(inflight_needs_racer) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let densify_hi = path_lo.saturating_add(CONTIG_DENSIFY_AHEAD);
    let depth_bytes = hub.query.block_queue_stats().0;
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
        cfg.assign_stop_bytes,
        fetched_hi,
    );

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

pub fn finish_assign(loop_stats: &LoopStats, t0: Instant, issued: u64) {
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
#[doc(hidden)]
pub fn collect_height_band(
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

/// An alive peer already holds getdata for `hash`.
#[doc(hidden)]
pub fn live_getdata_cover(st: &IbdWorkState, hash: &BlockHash) -> bool {
    st.inflight.get(hash).is_some_and(|req| {
        req.peers
            .iter()
            .any(|pid| st.slots.iter().any(|s| s.id == *pid && s.alive))
    })
}

/// Pull the densify cursor back to the first height that is not claim-ready.
///
/// Heights already recorded in `densify_ready_through` are not checked again.
#[doc(hidden)]
pub fn rewind_densify_scan_lo(st: &mut IbdWorkState, hub: &ChainHub, path_lo: u32) {
    if st.densify_ready_through < path_lo {
        st.densify_ready_through = path_lo;
    }
    let hi = st.densify_scan_lo;
    let start = path_lo.max(st.densify_ready_through);
    if hi <= start {
        return;
    }
    for ht in start..hi {
        let Some(&hash) = st.height_to_hash.get(&ht) else {
            return;
        };
        if !super::progress::claim_ready(hub, &mut st.body, ht, &hash) {
            st.densify_scan_lo = ht;
            return;
        }
        st.densify_ready_through = ht.saturating_add(1);
    }
}

#[doc(hidden)]
pub fn densify_prefix_filled(st: &mut IbdWorkState, hub: &ChainHub, ht: u32) -> bool {
    let Some(&h) = st.height_to_hash.get(&ht) else {
        return false;
    };
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return true;
    }
    if live_getdata_cover(st, &h) {
        return true;
    }
    st.body.is_known_archived(&h)
}

/// Body-queue wire at `ht` for `want`: `Ready` when matching; wrong first-wins
/// is dequeued (`Gap`); empty slot is `Gap`. Shared by densify and tip-hole cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum BqWireAt {
    Ready,
    Gap,
}

#[doc(hidden)]
pub fn bq_wire_for_hash(hub: &ChainHub, ht: u32, want: BlockHash) -> BqWireAt {
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
#[doc(hidden)]
pub fn inflight_needs_racer(req: &state::InflightReq) -> bool {
    req.peers.is_empty() && !req.retired.is_empty()
}

/// A free getdata window slot, or a racer for a hash whose only holders are
/// retired. A retired holder already occupies a window slot, so the racer
/// does not.
#[doc(hidden)]
pub fn densify_issue_allowed(room: usize, req: Option<&state::InflightReq>) -> bool {
    room > 0 || req.is_some_and(inflight_needs_racer)
}

#[doc(hidden)]
pub fn need_hash_at(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    ht: u32,
    room: usize,
) -> Option<BlockHash> {
    use bitcoin::hashes::Hash as _;
    let &h = st.height_to_hash.get(&ht)?;
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return None;
    }
    if live_getdata_cover(st, &h)
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
    let held = st.body.is_pending(&h) && confirm_pipeline_holds(st, hub, h, ht);
    demote_zombie_pending_for_fetch(&mut st.body, hub, h, Some(ht), held);
    if st.body.skip_download(hub, &h) {
        return None;
    }
    Some(h)
}

pub fn pop_need(
    q: &mut VecDeque<BlockHash>,
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Option<BlockHash> {
    while let Some(h) = q.pop_front() {
        if st.body.skip_download(hub, &h) || live_getdata_cover(st, &h) {
            continue;
        }
        return Some(h);
    }
    None
}

/// How many recent block bodies the per-peer byte cap remembers.
#[doc(hidden)]
pub const BLOCK_LEN_SAMPLES: usize = 32;
/// Below this many samples the byte cap charges [`BLOCK_LEN_STAND_IN`].
#[doc(hidden)]
pub const BLOCK_LEN_MIN_SAMPLES: usize = 8;
/// Stand-in payload so the count cap binds before any bodies have arrived.
#[doc(hidden)]
pub const BLOCK_LEN_STAND_IN: u64 = 1024;
/// Outstanding getdata payload on one peer.
pub const PER_PEER_BLOCK_BYTE_CAP: u64 = 16 * 1024 * 1024;

/// Remember one received block body. The ring stays at [`BLOCK_LEN_SAMPLES`].
pub fn note_block_len(st: &mut IbdWorkState, len: usize) {
    if st.block_lens.len() == BLOCK_LEN_SAMPLES {
        st.block_lens.pop_front();
    }
    st.block_lens
        .push_back(u32::try_from(len).unwrap_or(u32::MAX));
}

/// Median recent payload, or [`BLOCK_LEN_STAND_IN`] before enough samples.
pub fn block_len_estimate(st: &IbdWorkState) -> u64 {
    if st.block_lens.len() < BLOCK_LEN_MIN_SAMPLES {
        return BLOCK_LEN_STAND_IN;
    }
    let mut lens: Vec<u32> = st.block_lens.iter().copied().collect();
    lens.sort_unstable();
    u64::from(lens[lens.len() / 2])
}

/// Room for one more getdata hash: under the count cap, and the next
/// estimated body still fits in [`PER_PEER_BLOCK_BYTE_CAP`].
pub fn peer_has_block_room(in_flight: usize, per_peer: usize, estimate: u64) -> bool {
    if in_flight >= per_peer {
        return false;
    }
    let next = (in_flight as u64)
        .saturating_mul(estimate)
        .saturating_add(estimate);
    next <= PER_PEER_BLOCK_BYTE_CAP
}

#[doc(hidden)]
pub fn peer_has_slot(st: &IbdWorkState, pid: usize, per_peer: usize) -> bool {
    let estimate = block_len_estimate(st);
    st.slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .is_some_and(|s| peer_has_block_room(s.in_flight.len(), per_peer, estimate))
}

pub fn issue_one(
    st: &mut IbdWorkState,
    pid: usize,
    h: BlockHash,
    room: &mut usize,
    issued: &mut u64,
) -> bool {
    issue_batch(st, pid, vec![h], room, issued)
}

/// Ceiling on the per-hash assign-stop charge. A block cannot be larger.
pub const GETDATA_RESERVE_BYTES: u64 = 4 * 1024 * 1024;

/// Bytes reserved for one new getdata hash against the assign-stop.
///
/// Fewer than [`BLOCK_LEN_MIN_SAMPLES`] recorded bodies still cost the 4 MiB
/// ceiling. After that the charge is the largest wire length in the ring,
/// and never above that ceiling.
#[doc(hidden)]
pub fn intake_reserve_per_hash(st: &IbdWorkState) -> u64 {
    if st.block_lens.len() < BLOCK_LEN_MIN_SAMPLES {
        return GETDATA_RESERVE_BYTES;
    }
    let max = st.block_lens.iter().copied().max().unwrap_or(u32::MAX);
    u64::from(max).min(GETDATA_RESERVE_BYTES)
}

/// `inflight_after` unique hashes, each counted at [`intake_reserve_per_hash`],
/// plus the snapshotted queue, fit in the assign-stop budget.
#[doc(hidden)]
pub fn intake_reserve_fits(st: &IbdWorkState, inflight_after: usize) -> bool {
    if st.intake_stop == u64::MAX {
        return true;
    }
    let reserved = (inflight_after as u64).saturating_mul(intake_reserve_per_hash(st));
    st.intake_queued.saturating_add(reserved) <= st.intake_stop
}

pub fn issue_batch(
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
            if st.slots[idx].in_flight.contains(h) || !super::header_walk::may_serve(st, pid, h) {
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
    for &h in &batch {
        st.slots[idx].track_insert(h);
    }
    st.slots[idx].getdata_wire.queue(batch.len());
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
pub fn contiguous_tip_holes(st: &mut IbdWorkState, hub: &ChainHub, max: usize) -> Vec<BlockHash> {
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
pub fn first_pre_hole(st: &mut IbdWorkState, hub: &ChainHub, max: usize) -> Option<BlockHash> {
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
pub fn pre_hole_should_extra_racer(st: &IbdWorkState, hash: BlockHash, alive: &[usize]) -> bool {
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

#[doc(hidden)]
pub fn cover_first_pre_hole(
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
/// small hole/need lists (not the full pending map). `held` is
/// [`confirm_pipeline_holds`]: a body the confirm engine holds has no queue
/// row but is not a zombie, and its verdict is still to come.
#[inline]
#[doc(hidden)]
pub fn demote_zombie_pending_for_fetch(
    body: &mut super::body::BodyPresence,
    hub: &ChainHub,
    hash: BlockHash,
    height: Option<u32>,
    held: bool,
) {
    use bitcoin::hashes::Hash as _;
    if held || !body.is_pending(&hash) {
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

/// `hash` is the path block at `height` and the confirm engine holds a body
/// for that height: lookup has taken it (the take mark covers it), or load
/// claimed it and write has not finished.
#[doc(hidden)]
pub fn confirm_pipeline_holds(
    st: &IbdWorkState,
    hub: &ChainHub,
    hash: BlockHash,
    height: u32,
) -> bool {
    st.height_to_hash.get(&height) == Some(&hash)
        && (hub.query.lookup_already_taken(height)
            || st.confirm_feed.as_ref().is_some_and(|f| f.holds(height)))
}

/// Stream rx older than this is not “recent” for tip-hole owner eviction.
/// Matches the absolute stall floor so slow-but-steady 64 KiB ticks stay live.
#[doc(hidden)]
pub const TIP_HOLE_RX_STALE: Duration = Duration::from_secs(30);

#[doc(hidden)]
pub fn peer_has_recent_rx(slot: &PeerSlot, now_ms: u64) -> bool {
    slot.rate
        .has_recent_rx(now_ms, TIP_HOLE_RX_STALE.as_millis() as u64)
}

#[doc(hidden)]
pub fn peer_queue_len(slots: &[PeerSlot], pid: usize) -> usize {
    slots
        .iter()
        .find(|s| s.id == pid)
        .map(|s| s.in_flight.len())
        .unwrap_or(usize::MAX)
}

/// Owner still has densify (or other) getdata in front of this hole.
#[doc(hidden)]
pub fn hole_owner_fifo_blocked(slot: &PeerSlot) -> bool {
    slot.in_flight.len() > 1
}

/// A FIFO-blocked owner is not dropped until it has held the hash this long.
/// Every peer has other getdata in flight during IBD, so without a hold time
/// the rule fires on every assign pass.
#[doc(hidden)]
pub const TIP_HOLE_FIFO_MIN_HOLD: Duration = Duration::from_secs(5);

/// A free peer must be expected to start the hash in at most 1/this of the
/// owner's drain time before a FIFO-blocked owner is dropped for it.
#[doc(hidden)]
pub const TIP_HOLE_FIFO_FASTER: u128 = 2;

#[doc(hidden)]
pub fn tip_hole_free_peer(
    s: &PeerSlot,
    req: &state::InflightReq,
    hash: &BlockHash,
    per_peer: usize,
    estimate: u64,
) -> bool {
    // A dead slot's measured rate is also zero, so it must not be a candidate.
    s.alive
        && !req.holds(s.id)
        && !s.in_flight.contains(hash)
        && peer_has_block_room(s.in_flight.len(), per_peer, estimate)
}

/// Drop an owner whose peer FIFO is not on this hash when it has held the hash
/// for [`TIP_HOLE_FIFO_MIN_HOLD`] and a free peer would start it at least
/// [`TIP_HOLE_FIFO_FASTER`]× sooner by `(queue+1)/bps`.
#[doc(hidden)]
pub fn fifo_blocked_owner_to_drop(
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
        .filter(|s| tip_hole_free_peer(s, req, hash, per_peer, estimate))
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
pub fn tip_hole_owner_to_drop(
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
/// the peer keeps the request in its `in_flight` and is not asked again
/// unless the hash goes racerless and the hold ages out [`TIP_HOLE_RX_STALE`].
#[doc(hidden)]
pub fn retire_hash_owner(st: &mut IbdWorkState, hash: BlockHash, pid: usize) {
    if let Some(req) = st.inflight.get_mut(&hash) {
        req.retire_peer(pid);
    }
}

/// Re-send `hash` to the longest-held retired owner once it has held for at
/// least [`TIP_HOLE_RX_STALE`]. Getdata cannot be cancelled, so the peer just
/// gets a second request; the original may still answer. This keeps an
/// all-retired hole moving instead of freezing once every live peer has been
/// asked once.
fn reask_aged_retired_owner(st: &mut IbdWorkState, hash: BlockHash) -> bool {
    let now = Instant::now();
    let Some(pid) = st.inflight.get(&hash).and_then(|req| {
        req.retired
            .iter()
            .copied()
            .filter_map(|pid| {
                let asked = req.owner_asked_at(pid)?;
                (now.duration_since(asked) >= TIP_HOLE_RX_STALE).then_some((pid, asked))
            })
            .min_by_key(|(_, asked)| *asked)
            .map(|(pid, _)| pid)
    }) else {
        return false;
    };
    let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
        return false;
    };
    st.slots[idx].track_insert(hash);
    st.slots[idx].getdata_wire.queue(1);
    let _ = st.slots[idx]
        .cmd_tx
        .send(PeerCmd::GetData { hashes: vec![hash] });
    inflight_add_peer(&mut st.inflight, hash, pid);
    true
}

#[doc(hidden)]
pub fn peer_bps(slots: &[PeerSlot], pid: usize) -> u64 {
    slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .and_then(|s| s.rate.bps())
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn pack_ewma_bps(slots: &[PeerSlot], alive: &[usize]) -> (Option<u64>, bool) {
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

#[doc(hidden)]
pub fn densify_cap_for(
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
#[doc(hidden)]
pub fn steal_hung_densify(
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
                    && super::header_walk::may_serve(st, pid, &h)
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
pub fn rank_peers_by_speed(
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
#[doc(hidden)]
pub fn rank_peers_for_tip_hole(
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
#[doc(hidden)]
pub fn tip_hole_drain_cmp(qa: usize, bps_a: u64, qb: usize, bps_b: u64) -> std::cmp::Ordering {
    let a = bps_a.max(1);
    let b = bps_b.max(1);
    let wa = (qa as u128 + 1).saturating_mul(u128::from(b));
    let wb = (qb as u128 + 1).saturating_mul(u128::from(a));
    wa.cmp(&wb)
}

/// Full race on tip+1; one racer each on later contiguous holes in the same gap.
#[doc(hidden)]
pub fn cover_tip_batch_holes(
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
/// request age. A dropped owner is retired: it keeps the request it was sent
/// and still counts toward its queue. Retired holders count toward the ask
/// cap only once a racer is live. A retired-only set is not coverage, so it
/// is filled with fresh peers, or with one peer when those holders already
/// meet the cap. A retired owner is not asked again unless the hash is
/// racerless and the hold has aged out [`TIP_HOLE_RX_STALE`].
pub fn cover_tip_holes(
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
        if st.body.is_pending(&h) && ht.is_some_and(|ht| confirm_pipeline_holds(st, hub, h, ht)) {
            continue;
        }
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, ht, false);
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
        // `inflight_needs_racer`: a retired-only set is not coverage. Once a
        // racer is live, retired holders count toward the cap again.
        let racerless = st.inflight.get(&h).is_some_and(inflight_needs_racer);
        if already >= want && !racerless {
            continue;
        }
        let mut need = want.saturating_sub(already).max(usize::from(racerless));
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
        // Every alive peer is already a retired holder: re-ask an aged one
        // rather than freeze until restart.
        while need > 0 && racerless && reask_aged_retired_owner(st, h) {
            placed_any = true;
            issued += 1;
            need = need.saturating_sub(1);
        }
        if already == 0 && !placed_any {
            break;
        }
    }
    issued
}
