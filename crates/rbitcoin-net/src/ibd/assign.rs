//! Getdata assign for the **unified body-queue → lookup → load → scripts → write** path.
//!
//! Policy (operator-facing):
//! - **Tip batch** (tip+1 .. tip+[`TIP_HOLE_MAX`]=32, one confirm run): always
//!   request missing hashes (even if soft body-queue depth is over free floor).
//!   Multi-peer race up to [`TIP_HOLE_MAX_PEERS`] immediately — confirm is
//!   frozen until tip+1 is claim-ready.
//! - **Densify** (tip+1 outward, closest first): fill missing heights up to
//!   [`CONTIG_DENSIFY_AHEAD`]. Two soft assign limits (no hysteresis):
//!   - BQ payload **≤ ~100 MiB** → usual densify ahead to the height horizon
//!   - BQ payload **> ~100 MiB** → only heights confirm will consume in the
//!     next **~1 min** at current tip rate ([`rbitcoin_query::soft_densify_band_hi`])
//!   - BQ payload **≥ assign-stop** (default 1 GiB) → holes only within the
//!     ~1 min tip-rate window **and** not past fetched_hi (do not grow past
//!     fetched; do not densify far holes outside the window)
//! - Never request beyond densify horizon; events refuse far bodies too.
//! - One body-queue copy per height (receive path drops duplicates).

use super::assign_plan::far_slots_per_peer;
use super::peer_io::{touch_block_progress, PeerCmd, PeerSlot};
use super::state::{self, IbdWorkState};
use super::status::LoopStats;
use super::{
    IbdConfig, CONTIG_DENSIFY_AHEAD, FAR_SCAN_BUDGET, PENDING_STALE, TIP_HOLE_IMMEDIATE_PEERS,
    TIP_HOLE_MAX, TIP_HOLE_MAX_PEERS, TIP_HOLE_THIRD_PEER_AFTER,
};
use crate::chain::ChainHub;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

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
    let await_need: HashSet<BlockHash> = st.reorg.awaiting_need_getdata().into_iter().collect();
    let drop: Vec<BlockHash> = st
        .inflight
        .keys()
        .copied()
        .filter(|h| {
            if st.ordered_set.contains(h) || await_need.contains(h) {
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
///
/// High `pending` alone is **not** saturated — pending means we already hold wire.
pub(crate) fn archive_pipeline_saturated(
    _pending_len: usize,
    inflight_len: usize,
    bq_confirm_window_covered: bool,
) -> bool {
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
    _archive_write_next: u32,
    depth: AssignDepth,
    tip_rate_blocks_per_s: Option<f64>,
) {
    let t0 = Instant::now();
    let mut issued = 0u64;
    let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
    if alive.is_empty() {
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
    issued += cover_tip_holes(st, hub, cfg, &alive, &tip_holes);

    // 1b) Most-work reorg: pull mid-path / sibling bodies by **hash** (BQ is
    // height first-wins and may hold a different block at the same height).
    // Mids sit at height ≤ tip so tip-batch expire never clears them.
    // Always reserve a few slots for reorg need even when densify filled the
    // window — without mids tip stays frozen on the loser fork.
    let reorg_need = st.reorg.need_getdata();
    if !reorg_need.is_empty() {
        use bitcoin::hashes::Hash as _;
        let reserve = reorg_need.len().min(8);
        let mut room = cfg.window.saturating_sub(st.inflight.len()).max(reserve);
        let mut peer_i = st.assign_rot;
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
            // Ready only when **this hash** is on BQ (not merely the height slot).
            if hub.query.block_queue_has_hash(&h.to_byte_array()) {
                continue;
            }
            // Shared with tip-hole cover: zombie pending without matching wire.
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
    }

    if matches!(depth, AssignDepth::Critical) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let mut room = cfg.window.saturating_sub(st.inflight.len());
    if room == 0 {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    // Leave per-peer headroom for tip races while hole>0.
    let densify_per_peer = far_slots_per_peer(cfg.per_peer, !tip_holes.is_empty());

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
    let densify_lo = path_lo.max(st.densify_scan_lo);
    let densify = collect_height_band(st, hub, densify_lo, band_hi, room.max(1));
    if densify.is_empty() {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let mut peer_i = st.assign_rot;
    st.assign_rot = st.assign_rot.wrapping_add(1);
    let mut densify_q = densify;
    while room > 0 && !densify_q.is_empty() {
        let mut any = false;
        for _ in 0..alive.len() {
            if room == 0 || densify_q.is_empty() {
                break;
            }
            let pid = alive[peer_i % alive.len()];
            peer_i += 1;
            if !peer_has_slot(st, pid, densify_per_peer) {
                continue;
            }
            let Some(h) = pop_need(&mut densify_q, st, hub) else {
                break;
            };
            if issue_one(st, pid, h, &mut room, &mut issued) {
                any = true;
            }
        }
        if !any {
            break;
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
) -> VecDeque<BlockHash> {
    let mut out = VecDeque::new();
    if lo > hi || cap == 0 {
        return out;
    }
    let hi = hi.min(st.max_ordered_height.max(lo));
    let mut walked = 0usize;
    let mut prefix = lo;
    let mut tracking = true;
    for ht in lo..=hi {
        if out.len() >= cap || walked >= FAR_SCAN_BUDGET {
            break;
        }
        walked += 1;
        let need = need_hash_at(st, hub, ht);
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
fn need_hash_at(st: &mut IbdWorkState, hub: &ChainHub, ht: u32) -> Option<BlockHash> {
    let &h = st.height_to_hash.get(&ht)?;
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return None;
    }
    if st.inflight.contains_key(&h) || st.body.is_rejected(&h) {
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
        if st.body.skip_download(hub, &h) || st.inflight.contains_key(&h) {
            continue;
        }
        return Some(h);
    }
    None
}

fn peer_has_slot(st: &IbdWorkState, pid: usize, per_peer: usize) -> bool {
    st.slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .is_some_and(|s| s.in_flight.len() < per_peer)
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
    let batch: Vec<BlockHash> = batch
        .into_iter()
        .filter(|h| !st.slots[idx].in_flight.contains(h))
        .collect();
    if batch.is_empty() {
        return false;
    }
    let empty = st.slots[idx].in_flight.is_empty();
    for &h in &batch {
        st.slots[idx].in_flight.insert(h);
    }
    if empty {
        touch_block_progress(&st.slots[idx].block_progress_ms);
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
        .filter(|h| st.inflight.get(*h).map(|e| e.len() == 1).unwrap_or(false))
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
        // Reorg gather holds tip+1 — not a fetch hole for that hash (mids densify).
        if st.reorg.is_awaiting_held_tip(&hash) {
            break;
        }
        if claim_ready(hub, &mut st.body, ht, &hash) {
            break;
        }
        holes.push(hash);
    }
    holes
}

/// Desired concurrent getdata peers for a tip-hole / park-race hash.
pub(crate) fn tip_hole_peer_target(
    already: usize,
    second_peer_at: Option<Instant>,
    now: Instant,
) -> usize {
    if already >= TIP_HOLE_MAX_PEERS {
        return TIP_HOLE_MAX_PEERS;
    }
    if already >= TIP_HOLE_IMMEDIATE_PEERS {
        let ready_for_third = second_peer_at
            .map(|t| now.duration_since(t) >= TIP_HOLE_THIRD_PEER_AFTER)
            .unwrap_or(false);
        if ready_for_third {
            TIP_HOLE_MAX_PEERS
        } else {
            TIP_HOLE_IMMEDIATE_PEERS
        }
    } else {
        TIP_HOLE_IMMEDIATE_PEERS
    }
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

/// Tip-hole getdata older than this with no claimable wire is cleared and re-issued
/// (mainnet freeze: inflight stuck, soft frozen, hole=1 forever).
///
/// Short on purpose: confirm claim waits ~5s per tick while tip is blocked; 20s
/// left the same slow race set holding hole=1 while densify progressed.
const TIP_HOLE_INFLIGHT_STALE: Duration = Duration::from_secs(6);

/// Rank alive peer ids for tip-hole getdata: prefer peers not in `avoid`, then
/// higher live EWMA bps, then lower id. Unsampled peers sort last
/// among non-avoided (bps=0).
pub(crate) fn rank_tip_hole_peers(
    slots: &[PeerSlot],
    alive: &[usize],
    avoid: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut ranked: Vec<usize> = alive.to_vec();
    ranked.sort_by(|&a, &b| {
        let avoided_a = avoid.contains(&a) as u8;
        let avoided_b = avoid.contains(&b) as u8;
        avoided_a.cmp(&avoided_b).then_with(|| {
            let bps = |pid: usize| -> u64 {
                slots
                    .iter()
                    .find(|s| s.id == pid && s.alive)
                    .and_then(|s| s.rate.bps())
                    .unwrap_or(0)
            };
            bps(b).cmp(&bps(a)).then_with(|| a.cmp(&b))
        })
    });
    ranked
}

/// Cover each tip-hole hash with multi-peer getdata, preferring faster peers.
///
/// Stale tip-batch inflight is cleared after [`TIP_HOLE_INFLIGHT_STALE`] and
/// re-raced, preferring peers that were **not** in the cleared set.
pub(crate) fn cover_tip_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    holes: &[BlockHash],
) -> u64 {
    if holes.is_empty() || alive.is_empty() {
        return 0;
    }
    let mut issued = 0u64;
    let now = Instant::now();

    for &h in holes {
        // Skip only when **claim-ready** (confirmed or body-queue wire present).
        // Class A alone and **zombie pending without BQ** are not enough — sole
        // confirm intake is BQ wire. Resume seed marks Class A as known so densify
        // does not re-walk the whole band; tip-hole race must still re-get.
        //
        // Exception: tip+1 held for incomplete reorg mid gather — re-get would
        // re-BadPrev forever while mids starve.
        if st.reorg.is_awaiting_held_tip(&h) {
            continue;
        }
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
            if now.duration_since(req.started_at) >= TIP_HOLE_INFLIGHT_STALE {
                avoid = req.peers.clone();
                clear_hash_inflight(&mut st.slots, &mut st.inflight, h);
                st.body.mark_missing(h);
            }
        }
        let (already, second_at) = st
            .inflight
            .get(&h)
            .map(|e| (e.len(), e.second_peer_at))
            .unwrap_or((0, None));
        let want = tip_hole_peer_target(already, second_at, now);
        if already >= want {
            continue;
        }
        let mut need = want - already;
        let mut placed_any = false;
        let ranked = rank_tip_hole_peers(&st.slots, alive, &avoid);
        for &pid in &ranked {
            if need == 0 {
                break;
            }
            let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
                continue;
            };
            if st.slots[idx].in_flight.contains(&h) {
                continue;
            }
            if st
                .inflight
                .get(&h)
                .map(|e| e.contains_peer(pid))
                .unwrap_or(false)
            {
                continue;
            }
            if st.slots[idx].in_flight.len() >= cfg.per_peer {
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
mod tests {
    use super::super::status::LoopStats;
    use super::*;
    use bitcoin::hashes::Hash;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::Query;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn densify_skips_at_or_below_lookup_taken_hi() {
        assert!(!Query::lookup_taken_covers(5, None));
        assert!(!Query::lookup_taken_covers(0, None));
        assert!(Query::lookup_taken_covers(5, Some(5)));
        assert!(Query::lookup_taken_covers(4, Some(5)));
        assert!(!Query::lookup_taken_covers(6, Some(5)));
        assert!(Query::lookup_taken_covers(0, Some(0)));
    }

    #[test]
    fn cover_tip_holes_skips_taken_prefix() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        let want = h(0x11);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        st.body.mark_missing(want);
        hub.query.set_lookup_taken_hi(Some(ht));
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert!(
            holes.is_empty(),
            "taken tip+1 is not a fetch hole: {holes:?}"
        );
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[want]);
        assert_eq!(issued, 0, "must not race getdata for a taken height");
        assert!(st.inflight.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn h(n: u32) -> BlockHash {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444 + id as u16),
            cmd_tx,
            in_flight: HashSet::new(),
            block_progress_ms: Arc::new(AtomicU64::new(0)),
            peer_height: 100,
            connected_ms: 1,
            first_data_ms: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            alive: true,
            task,
        }
    }

    fn tmp_hub() -> (std::path::PathBuf, ChainHub) {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-assign-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (
            dir,
            ChainHub::new(q, ChainParams::regtest(), Milestone::NONE),
        )
    }

    #[test]
    fn clear_inflight_add_peer_pop_need_and_tip_holes() {
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
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Off-path getdata (mainnet 08:16:23: ordered empty, h2h=0, inflight=7)
    /// must not occupy slots; tip+1 and live awaiting-reorg need stay.
    /// Speculative explore-need at an empty remainder is leftover — drop it.
    #[test]
    fn prune_off_path_inflight_drops_orphans_keeps_path_and_reorg() {
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
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
        let await_h = h(0x33);
        st.reorg.set_awaiting(
            bitcoin::Block {
                header: Header {
                    version: Version::from_consensus(4),
                    prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time: 1,
                    bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txdata: vec![],
            },
            vec![await_h],
        );
        st.slots[0].in_flight.insert(await_h);
        inflight_add_peer(&mut st.inflight, await_h, 0);
        assert_eq!(st.inflight.len(), 10);

        prune_off_path_inflight(&mut st);

        assert!(st.inflight.contains_key(&want), "tip+1 occupant stays");
        assert!(
            st.inflight.contains_key(&await_h),
            "awaiting reorg need stays"
        );
        assert!(
            !st.inflight.contains_key(&explore_h),
            "explore-need at empty remainder is leftover"
        );
        for i in 0..7u32 {
            let hash = h(1000 + i);
            assert!(!st.inflight.contains_key(&hash), "orphan {i} dropped");
            assert!(!st.slots[0].in_flight.contains(&hash));
        }
        assert_eq!(
            st.inflight.len(),
            2,
            "orphans+explore dropped; path+awaiting kept"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scale_and_saturated_helpers() {
        assert!(!archive_pipeline_saturated(0, 20, false));
        assert!(!archive_pipeline_saturated(96, 0, false));
        assert!(!archive_pipeline_saturated(0, 0, false));
        assert!(archive_pipeline_saturated(0, 0, true));
        assert!(archive_pipeline_saturated(200, 15, true));
        assert!(!archive_pipeline_saturated(0, 32, true));
    }

    #[test]
    fn densify_yields_peer_slots_while_tip_hole_open() {
        use super::super::assign_plan::far_slots_per_peer;
        assert_eq!(far_slots_per_peer(16, true), 2);
        assert!(far_slots_per_peer(16, true) < 16);
        assert_eq!(far_slots_per_peer(16, false), 8);
    }

    /// Wrong first-wins body at tip+1 is not claim-ready; cover must dequeue and
    /// re-get the work-path hash (general hole=1 with bq soft growing ahead).
    #[test]
    fn cover_tip_holes_drops_wrong_bq_hash_and_regets() {
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let want = h(0xabc);
        let wrong = h(0xdef);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        // First-wins wrong wire at tip+1.
        hub.query
            .block_queue_offer(ht, wrong.to_byte_array(), 0, b"wrong")
            .unwrap();
        assert!(hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &want),
            "wrong BQ hash must not be claim-ready"
        );
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![want]);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(
            issued >= 1,
            "must re-get correct tip+1 hash; issued={issued}"
        );
        assert!(
            !hub.query.block_queue_has_height(ht)
                || hub
                    .query
                    .block_queue_hash_at_height(ht)
                    .is_some_and(|x| x == want.to_byte_array()),
            "wrong BQ body must be dequeued"
        );
        assert!(st.inflight.contains_key(&want));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Resume seed marks Class A tip+1 as known without BQ wire. Confirm intake is
    /// BQ-only → hole must still race getdata (mainnet stall: hole=1, known=1,
    /// feed ready only ahead of tip, inflight→0 forever).
    #[test]
    fn cover_tip_holes_regets_class_a_without_body_queue() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(1001);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.height_to_hash.insert(ht, hole);
        st.hash_height.insert(hole, ht);
        st.record_height(hole, ht);
        // Class A seed path: known, not pending, not in body queue.
        st.body.mark_archived(hole);
        assert!(st.body.is_known_archived(&hole));
        assert!(!st.body.is_pending(&hole));
        assert!(!hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &hole),
            "Class A alone must not be claim-ready"
        );

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(
            holes,
            vec![hole],
            "tip+1 Class A without BQ is a fetch hole"
        );

        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(
            issued >= 1,
            "must re-getdata Class A tip hole (got issued={issued})"
        );
        assert!(
            st.inflight.contains_key(&hole),
            "tip hole must be inflight after cover"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Zombie pending (flag set, no BQ wire) must still be a tip hole and re-getdata.
    /// Mainnet ~97%: hole=0 + inflight=0 while tip+1 pending without claimable wire.
    #[test]
    fn cover_tip_holes_regets_zombie_pending_without_body_queue() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0xaa);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.height_to_hash.insert(ht, hole);
        st.hash_height.insert(hole, ht);
        st.record_height(hole, ht);
        // Soft-stall shape: pending set without body-queue wire.
        st.body.mark_pending(hole);
        assert!(st.body.is_pending(&hole));
        assert!(!hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &hole),
            "zombie pending must not be claim-ready"
        );

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![hole], "zombie pending is a fetch hole");

        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(
            issued >= 1,
            "must re-getdata zombie pending tip hole (got issued={issued})"
        );
        assert!(
            st.inflight.contains_key(&hole),
            "tip hole must be inflight after cover"
        );
        assert!(
            !st.body.is_pending(&hole),
            "cover demotes zombie pending to missing"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Stale tip-hole inflight (≥6s) with no claimable wire must clear and re-race.
    /// Mainnet freeze: hole=1, inflight stuck forever, soft frozen, conf=0.
    #[test]
    fn cover_tip_holes_re_races_stale_inflight() {
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x51);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        // Fresh inflight (<6s) must not re-race yet.
        let mut fresh = InflightReq::new(0);
        fresh.started_at = Instant::now() - Duration::from_secs(3);
        st.inflight.insert(hole, fresh);
        st.slots[0].in_flight.insert(hole);
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![hole]);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued_fresh = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        // Still at want peers (race fills), but started_at not cleared as stale.
        let age_fresh = Instant::now().duration_since(st.inflight[&hole].started_at);
        assert!(
            age_fresh >= Duration::from_secs(2),
            "fresh inflight must keep original started_at; age={age_fresh:?} issued={issued_fresh}"
        );

        // Frozen inflight from a prior race that never delivered wire (≥6s).
        st.inflight.clear();
        for s in st.slots.iter_mut() {
            s.in_flight.clear();
        }
        let mut frozen = InflightReq::new(0);
        frozen.started_at = Instant::now() - Duration::from_secs(7);
        st.inflight.insert(hole, frozen);
        st.slots[0].in_flight.insert(hole);
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &hole),
            "no wire → not claim-ready"
        );
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(
            issued >= 1,
            "stale inflight must re-race getdata; issued={issued}"
        );
        assert!(
            st.inflight.contains_key(&hole),
            "hash remains inflight after re-race"
        );
        // Fresh started_at (not still the 7s-old stamp).
        let age = Instant::now().duration_since(st.inflight[&hole].started_at);
        assert!(
            age < Duration::from_secs(2),
            "re-race must reset started_at; age={age:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tip-hole cover prefers higher EWMA bps peers first.
    #[test]
    fn cover_tip_holes_prefers_fast_peers() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x61);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);

        // Peer 0 slow, peer 1 fast, peer 2 medium — inject mature EWMA samples.
        for (i, bytes_per_sec) in [(0usize, 100_000u64), (1, 10_000_000u64), (2, 1_000_000u64)] {
            st.slots[i].rate.sample(0, 0, true);
            st.slots[i]
                .rate
                .sample(5_000, bytes_per_sec.saturating_mul(5), true);
        }
        // Cap want to 2 so only the top two speeds get work if ranking works.
        // TIP_HOLE_MAX_PEERS is 4 but we only have 3 peers — all may get work.
        // Assert peer 1 (fastest) is among inflight and peer order: 1 before 0.
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let avoid = HashSet::new();
        let ranked = rank_tip_hole_peers(&st.slots, &alive, &avoid);
        assert_eq!(ranked[0], 1, "fastest peer first: ranked={ranked:?}");
        assert_eq!(ranked[1], 2, "medium second: ranked={ranked:?}");
        assert_eq!(ranked[2], 0, "slow last: ranked={ranked:?}");

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(issued >= 1, "issued={issued}");
        let peers = &st.inflight[&hole].peers;
        assert!(
            peers.contains(&1),
            "fast peer must be in tip-hole race; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// After stale clear, re-race prefers peers not in the cleared set.
    #[test]
    fn cover_tip_holes_rerace_avoids_prior_peers() {
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            (0..5).map(dummy_slot).collect(),
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x71);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);

        let mut frozen = InflightReq::new(0);
        frozen.add_peer(1);
        frozen.started_at = Instant::now() - Duration::from_secs(7);
        st.inflight.insert(hole, frozen);
        st.slots[0].in_flight.insert(hole);
        st.slots[1].in_flight.insert(hole);

        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let holes = vec![hole];
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes);
        assert!(issued >= 1, "issued={issued}");
        let peers = &st.inflight[&hole].peers;
        // Prefer 2,3,4 over reusing 0,1 first — at least one new peer in race.
        let new = peers.iter().any(|&p| p >= 2);
        assert!(
            new,
            "re-race should include peers outside cleared set; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Awaiting reorg held tip+1 is not a tip fetch hole (mids densify instead).
    /// Covering it would soft re-get tip+1 forever while mids starve.
    #[test]
    fn contiguous_and_cover_skip_awaiting_held_tip() {
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, Target};
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        let gen = hub.tip_hash().unwrap();
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut held = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: gen,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1_300_000_200,
                bits,
                nonce: 0,
            },
            txdata: vec![],
        };
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            held.header.nonce = nonce;
            if held.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let held_hash = held.block_hash();
        st.record_height(held_hash, ht);
        st.height_to_hash.insert(ht, held_hash);
        st.body.mark_pending(held_hash);
        st.reorg.set_awaiting(held, vec![h(0xcc)]); // mid still missing
        assert!(st.reorg.is_awaiting_held_tip(&held_hash));
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert!(
            holes.is_empty(),
            "awaiting held tip+1 must not appear as tip hole; holes={holes:?}"
        );
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[held_hash]);
        assert_eq!(
            issued, 0,
            "cover must skip awaiting held tip+1 (mid densify only)"
        );
        assert!(
            !st.inflight.contains_key(&held_hash),
            "must not race getdata for held tip+1"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Densify-ahead zombie pending (flag set, no matching BQ) must re-get.
    /// Regression: need_hash_at used to skip all pending before BQ check, so
    /// heights past tip-batch cover never demoted and conf froze mid-IBD.
    #[test]
    fn densify_zombie_pending_regets_work_path() {
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 32;
        cfg.per_peer = 8;
        let want1 = h(0x31);
        let want2 = h(0x32);
        st.record_height(want1, 1);
        st.record_height(want2, 2);
        st.height_to_hash.insert(1, want1);
        st.height_to_hash.insert(2, want2);
        st.ordered_set.insert(want1);
        st.ordered_set.insert(want2);
        st.ordered.push_back(want1);
        st.ordered.push_back(want2);
        st.max_ordered_height = 2;
        // tip+1 claim-ready so densify walks to ht=2.
        hub.query
            .block_queue_offer(1, want1.to_byte_array(), 0, b"ok1")
            .unwrap();
        st.body.mark_pending(want1);
        // tip+2 zombie: pending without BQ wire.
        st.body.mark_pending(want2);
        assert!(!hub.query.block_queue_has_height(2));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, 2, &want2),
            "zombie pending must not be claim-ready"
        );
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&want2),
            "densify must re-get zombie pending at ht=2; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        assert!(
            !st.body.is_pending(&want2),
            "need_hash_at must demote zombie pending before issue"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Densify band: wrong first-wins BQ at a height is dropped; work-path hash
    /// is requested (`need_hash_at` hash match, not height occupancy).
    #[test]
    fn densify_drops_wrong_bq_hash_and_regets_work_path() {
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 32;
        cfg.per_peer = 8;
        // tip+1 claim-ready (correct wire) so densify walks past tip hole.
        let want1 = h(0x11);
        let want2 = h(0x22);
        let wrong2 = h(0x99);
        st.record_height(want1, 1);
        st.record_height(want2, 2);
        st.height_to_hash.insert(1, want1);
        st.height_to_hash.insert(2, want2);
        st.ordered_set.insert(want1);
        st.ordered_set.insert(want2);
        st.ordered.push_back(want1);
        st.ordered.push_back(want2);
        st.max_ordered_height = 2;
        hub.query
            .block_queue_offer(1, want1.to_byte_array(), 0, b"ok1")
            .unwrap();
        st.body.mark_pending(want1);
        // Wrong first-wins at tip+2.
        hub.query
            .block_queue_offer(2, wrong2.to_byte_array(), 0, b"wrong2")
            .unwrap();
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, 2, &want2),
            "wrong BQ at ht=2 must not be claim-ready for want2"
        );
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&want2),
            "densify must re-get correct work-path hash at ht=2; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        assert!(
            !hub.query.block_queue_has_height(2)
                || hub
                    .query
                    .block_queue_hash_at_height(2)
                    .is_some_and(|x| x == want2.to_byte_array()),
            "wrong BQ body at densify height must be dequeued"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Reorg mid densify (1b) must issue getdata for need hash even when the
    /// same height's BQ slot holds a different first-wins body (height occupancy
    /// is not readiness — only `block_queue_has_hash` of the need).
    #[test]
    fn assign_reorg_need_despite_wrong_height_bq_occupant() {
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash as _;
        use bitcoin::{CompactTarget, Target};
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 16;
        cfg.per_peer = 4;
        let gen = hub.tip_hash().unwrap();
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let need = h(0xab);
        let wrong_occupant = h(0xde);
        // Mid recorded at height 1; BQ height 1 holds a different hash.
        st.record_height(need, 1);
        hub.query
            .block_queue_offer(1, wrong_occupant.to_byte_array(), 0, b"loser")
            .unwrap();
        assert!(hub.query.block_queue_has_height(1));
        assert!(!hub.query.block_queue_has_hash(&need.to_byte_array()));
        let mut held = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: gen,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1_300_000_300,
                bits,
                nonce: 0,
            },
            txdata: vec![],
        };
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            held.header.nonce = nonce;
            if held.header.validate_pow(target).is_ok() {
                break;
            }
        }
        st.reorg.set_awaiting(held, vec![need]);
        st.body.mark_missing(need);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&need),
            "reorg need must getdata by hash despite wrong BQ height occupant; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_requests_beyond_legacy_2k_when_soft_allows() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;

        // Past legacy 2048 ceiling with headroom; keep map/BQ setup small for suite speed.
        const HI: u32 = 2200;
        // Claim-ready prefix via tiny BQ so tip-hole race stops (pending without BQ
        // is a fetch hole). Fill through just under the legacy 2048 densify ceiling
        // so the first missing heights densify issues are already past that line.
        const FILL: u32 = 2040;
        let tiny = [0u8; 8];
        for ht in 1u32..=HI {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            if ht <= FILL {
                hub.query
                    .block_queue_enqueue(ht, hash.to_byte_array(), ht as u64, &tiny)
                    .unwrap();
                st.body.mark_pending(hash);
            } else {
                st.body.mark_missing(hash);
            }
        }

        // Under free floor — full densify ahead.
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);

        let far: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .filter(|&ht| ht > FILL)
            .collect();
        assert!(
            !far.is_empty(),
            "expected densify past claim-ready prefix; inflight heights={:?}",
            st.inflight
                .keys()
                .filter_map(|hash| st.hash_height.get(hash).copied())
                .collect::<Vec<_>>()
        );
        // Runtime pin: densify must issue heights past the legacy 2048 ceiling
        // (CONTIG_DENSIFY_AHEAD is 64k — not a constant-only check).
        assert!(
            far.iter().any(|&ht| ht > 2048),
            "legacy CONTIG_DENSIFY_AHEAD=2048 must not be the ceiling; far={far:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Over free-byte floor: densify only the confirm-time window (rate * 60s).
    #[test]
    fn densify_over_free_bytes_limited_to_confirm_window() {
        use rbitcoin_query::{soft_confirm_window_n, BQ_SOFT_FREE_BYTES};

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        // Genesis tip=0 → path_lo=1.
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;

        // Heights 1..=200 missing; fill BQ over free floor with fat payloads.
        for ht in 1u32..=200 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // ~110 MiB in queue (two ~55 MiB chunks) → restricted.
        let chunk = vec![0u8; 55 * 1024 * 1024];
        hub.query
            .block_queue_enqueue(1, h(1).to_byte_array(), 1, &chunk)
            .unwrap();
        hub.query
            .block_queue_enqueue(2, h(2).to_byte_array(), 2, &chunk)
            .unwrap();
        st.body.mark_pending(h(1));
        st.body.mark_pending(h(2));
        assert!(hub.query.block_queue_stats().1 > BQ_SOFT_FREE_BYTES);

        // 0.1 blk/s × 60s → window of 6 heights (path_lo=1 → band_hi=6).
        let rate = Some(0.1);
        let win = soft_confirm_window_n(rate);
        assert_eq!(win, 6);
        let path_lo = 1u32;
        let band_hi = path_lo + win - 1;

        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, rate);

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            !issued_hts.is_empty(),
            "expected densify inside confirm window; issued={issued_hts:?}"
        );
        assert!(
            issued_hts.iter().all(|&ht| ht <= band_hi),
            "no densify past confirm window {band_hi}; issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Under free-byte floor: full densify ahead even with many queued blocks.
    #[test]
    fn densify_under_free_bytes_uses_full_ahead() {
        use rbitcoin_query::BQ_SOFT_FREE_BYTES;

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        // Genesis tip=0 → path_lo=1.
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;

        for ht in 1u32..=100 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // Tiny payloads well under free floor.
        for ht in 1u32..=10 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        assert!(hub.query.block_queue_stats().1 < BQ_SOFT_FREE_BYTES);

        // Rate would only allow 6 if restricted — must still densify past that.
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, Some(0.1));

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            issued_hts.iter().any(|&ht| ht > 16),
            "under free bytes: densify past 1-min window; issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Filled BQ prefix must advance densify_scan_lo so the next tick skips it.
    #[test]
    fn densify_watermark_skips_bq_ready_prefix() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 64;

        for ht in 1u32..=80 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        for ht in 1u32..=40 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(
            st.densify_scan_lo >= 41,
            "BQ-ready 1..=40 must bump scan_lo; scan_lo={}",
            st.densify_scan_lo
        );
        let issued_low = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .filter(|&ht| ht <= 40)
            .count();
        assert_eq!(issued_low, 0, "must not getdata heights already on BQ");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Serialize env mutators — parallel suite races `bq_assign_stop_bytes`.
    static BQ_ASSIGN_STOP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Over assign-stop: densify within confirm window ∩ fetched; not past window.
    #[test]
    fn densify_over_assign_stop_clamps_window_and_fetched() {
        let _g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev_b = std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES");
        let prev_g = std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB");
        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
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
        let _restore = Restore(prev_b, prev_g);
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "2048");

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 64;

        for ht in 1u32..=500 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // Tip batch already fetched so densify is not starved by tip-hole slots.
        for ht in 1u32..=TIP_HOLE_MAX as u32 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        // Far fetched_hi=500 trips assign-stop; rate 5 → confirm window 300.
        let chunk = vec![0u8; 4096];
        hub.query
            .block_queue_enqueue(500, h(500).to_byte_array(), 500, &chunk)
            .unwrap();
        st.body.mark_pending(h(500));
        assert!(hub.query.block_queue_stats().1 >= 2048);
        assert_eq!(hub.query.block_queue_max_height(), Some(500));

        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, Some(5.0));

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            issued_hts
                .iter()
                .any(|&ht| ht > TIP_HOLE_MAX as u32 && ht <= 300),
            "assign-stop must densify holes inside confirm window; issued={issued_hts:?}"
        );
        assert!(
            issued_hts.iter().all(|&ht| ht <= 300),
            "assign-stop must not issue past window 300 (fetched_hi=500); issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Most-work reorg awaiting densify: assign issues getdata for need_getdata hashes.
    #[test]
    fn assign_issues_reorg_need_getdata() {
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, Target};
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 16;
        cfg.per_peer = 4;
        // Synthetic held tip+1 + need winner hash.
        let gen = hub.tip_hash().unwrap();
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let need = h(0xab);
        // Minimal held tip block for awaiting state (payload not used by assign).
        let mut held = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: gen,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1_300_000_100,
                bits,
                nonce: 0,
            },
            txdata: vec![],
        };
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            held.header.nonce = nonce;
            if held.header.validate_pow(target).is_ok() {
                break;
            }
        }
        st.reorg.set_awaiting(held, vec![need]);
        st.body.mark_missing(need);
        assert_eq!(st.reorg.need_getdata(), vec![need]);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&need),
            "reorg need_getdata must be issued as getdata"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn assign_depth_densify_cache_and_early_exits() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 8;

        for ht in 1u32..=12 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }

        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Critical, None);
        let after_crit = st.inflight.len();
        assert!(after_crit > 0, "critical should still issue tip/race");

        let n_before = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
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

        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(st.inflight.len() > 0);
        assert!(stats.assign_issued.load(Ordering::Relaxed) > 0);

        for ht in 20u32..20 + cfg.window as u32 {
            let hash = h(ht + 100);
            inflight_add_peer(&mut st.inflight, hash, 0);
            st.slots[0].in_flight.insert(hash);
        }
        let n_full = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 5, AssignDepth::Full, None);
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
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 1, AssignDepth::Full, None);
        assert!(st.slots[1].in_flight.len() > 0 || st.inflight.len() > cfg.per_peer);

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
        assign_work_ordered(&mut st, &hub, &cfg, &stats, 13, AssignDepth::Full, None);
        assert!(
            st.inflight.is_empty(),
            "claim-ready tip band must not re-get; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
