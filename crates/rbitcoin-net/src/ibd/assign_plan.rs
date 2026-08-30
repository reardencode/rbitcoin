//! Pure ordered-path helpers (no peer IO).

use bitcoin::BlockHash;
use std::collections::{HashSet, VecDeque};

/// Mark `h` done in the ordered set. Prefer O(1) front pop; otherwise leave a
/// stale ordered entry. Ghosts (removed from set but still in the deque) are
/// front-trimmed here so the next front is always a live set member when possible.
///
/// **Ghosts:** middle removes only update `ordered_set`. Entries may remain in
/// the deque until front-trim or [`compact_ordered`]. Scans that walk `ordered`
/// should skip hashes not in `ordered_set` (or use set membership).
pub(crate) fn remove_from_ordered(
    ordered: &mut VecDeque<BlockHash>,
    ordered_set: &mut HashSet<BlockHash>,
    h: BlockHash,
) {
    ordered_set.remove(&h);
    if ordered.front() == Some(&h) {
        ordered.pop_front();
    }
    while let Some(&front) = ordered.front() {
        if ordered_set.contains(&front) {
            break;
        }
        ordered.pop_front();
    }
}

/// Rebuild `ordered` to match `ordered_set` (drop middle ghosts).
///
/// Cheap no-op when the deque is not much larger than the live set.
pub(crate) fn compact_ordered(ordered: &mut VecDeque<BlockHash>, ordered_set: &HashSet<BlockHash>) {
    let len = ordered.len();
    if len <= 64 {
        return;
    }
    let live = ordered_set.len();
    let ghost_budget = (live / 2).max(64);
    if len <= live.saturating_add(ghost_budget) {
        return;
    }
    let mut next = VecDeque::with_capacity(live);
    for h in ordered.iter().copied() {
        if ordered_set.contains(&h) {
            next.push_back(h);
        }
    }
    *ordered = next;
}

/// Densify slots per peer: drip while a tip hole exists, else half of `per_peer`.
///
/// When tip+1 is a fetch hole, densify must **not** fill every peer to
/// `per_peer` (16) or tip multi-peer getdata has nowhere to land — mainnet
/// sat hole=1 with conf_blks=0 while bq/feed grew tens of thousands of far
/// bodies and peers kept making densify progress (never stall-disconnect).
pub(crate) fn far_slots_per_peer(per_peer: usize, tip_hole: bool) -> usize {
    if tip_hole {
        2
    } else {
        (per_peer / 2).max(1)
    }
}

/// Per-peer densify cap: drip 2 while a tip hole is open; otherwise half of
/// `per_peer`, or `per_peer` when this peer's EWMA bps is ≥ 2× pack median
/// and the pack is not a tight cluster.
pub(crate) fn densify_slots_for_peer(
    per_peer: usize,
    tip_hole: bool,
    peer_bps: Option<u64>,
    pack_median: Option<u64>,
    pack_tight: bool,
) -> usize {
    let base = far_slots_per_peer(per_peer, tip_hole);
    if tip_hole || pack_tight {
        return base;
    }
    let Some(bps) = peer_bps else {
        return base;
    };
    let Some(med) = pack_median else {
        return base;
    };
    if med > 0 && bps >= med.saturating_mul(2) {
        per_peer
    } else {
        base
    }
}

/// Whether to request more headers past the soft cap.
///
/// Only when the ordered path is **mostly claim-ready** (dense body-queue /
/// Class A readiness) and the gap from max_ready to max_ordered is short —
/// never for sparse far-only header floods without bodies.
///
/// `live == 0` is **not** “beyond soft cap.” Empty-path getheaders is a
/// separate cadence (main loop / empty-headers lag). Treating empty as
/// headroom made every already-known 1-header announce re-issue getheaders
/// (mainnet tip: ~1k INFO lines/s).
pub(crate) fn want_headers_beyond_soft_cap(
    live: usize,
    known_ready: usize,
    ready_gap: u32,
    gap_need: u32,
) -> bool {
    if live == 0 {
        return false;
    }
    let mostly_ready = known_ready >= live.saturating_mul(3) / 4;
    mostly_ready && ready_gap < gap_need
}

/// Admit a header onto `ordered` (first time or post-drain re-admit).
///
/// Re-admit after tip-drain/hygiene emptied `ordered` is required (mainnet
/// 292k). Do not re-queue work that is already inflight, pending/BQ, rejected,
/// confirmed, or at/below tip — those 1-header announces are tip chatter.
pub(crate) fn should_enqueue_header(
    in_ordered: bool,
    inflight: bool,
    pending: bool,
    rejected: bool,
    has_block: bool,
    height: Option<u32>,
    tip_h: Option<u32>,
) -> bool {
    if in_ordered || inflight || pending || rejected || has_block {
        return false;
    }
    match (height, tip_h) {
        (Some(ht), Some(tip)) if ht <= tip => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn h(n: u16) -> BlockHash {
        let mut b = [0u8; 32];
        b[0] = (n & 0xff) as u8;
        b[1] = (n >> 8) as u8;
        BlockHash::from_byte_array(b)
    }

    /// far_slots / feed_cap scale / soft-cap density (pure policy helpers).
    #[test]
    fn assign_policy_helpers_surface() {
        assert_eq!(far_slots_per_peer(16, true), 2);
        assert_eq!(far_slots_per_peer(16, false), 8);
        assert_eq!(far_slots_per_peer(8, false), 4);

        // Sparse: 4k claim-ready of 120k live → no bypass
        assert!(!want_headers_beyond_soft_cap(120_000, 4_000, 100, 2048));
        // Dense + short ready_gap → bypass
        assert!(want_headers_beyond_soft_cap(64_000, 50_000, 100, 2048));
        // Dense but long ready_gap → no need
        assert!(!want_headers_beyond_soft_cap(64_000, 50_000, 10_000, 2048));
        // Empty path is not soft-cap headroom (tip 1-header storm).
        assert!(!want_headers_beyond_soft_cap(0, 0, 0, 2048));
    }

    #[test]
    fn densify_slots_tip_hole_is_two_for_all() {
        assert_eq!(
            densify_slots_for_peer(16, true, Some(10_000_000), Some(1_000_000), false),
            2
        );
        assert_eq!(densify_slots_for_peer(16, true, None, None, true), 2);
    }

    #[test]
    fn densify_slots_tight_pack_stays_half() {
        assert_eq!(
            densify_slots_for_peer(16, false, Some(1_500_000), Some(1_000_000), true),
            8
        );
        assert_eq!(
            densify_slots_for_peer(16, false, Some(2_000_000), Some(1_000_000), true),
            8
        );
    }

    #[test]
    fn densify_slots_fast_outlier_gets_full() {
        assert_eq!(
            densify_slots_for_peer(16, false, Some(2_000_000), Some(1_000_000), false),
            16
        );
        assert_eq!(
            densify_slots_for_peer(16, false, Some(1_500_000), Some(1_000_000), false),
            8
        );
        assert_eq!(
            densify_slots_for_peer(16, false, None, Some(1_000_000), false),
            8
        );
        assert_eq!(
            densify_slots_for_peer(16, false, Some(2_000_000), None, false),
            8
        );
    }

    /// 292k re-admit vs tip-chatter skip.
    #[test]
    fn enqueue_header_readmit_skips_inflight_pending_and_past_tip() {
        // Known, drained, still needed above tip.
        assert!(should_enqueue_header(
            false,
            false,
            false,
            false,
            false,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            true,
            false,
            false,
            false,
            false,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            false,
            true,
            false,
            false,
            false,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            false,
            false,
            true,
            false,
            false,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            false,
            false,
            false,
            true,
            false,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            false,
            false,
            false,
            false,
            true,
            Some(1),
            Some(0),
        ));
        assert!(!should_enqueue_header(
            false,
            false,
            false,
            false,
            false,
            Some(5),
            Some(5),
        ));
        assert!(!should_enqueue_header(
            false,
            false,
            false,
            false,
            false,
            Some(4),
            Some(5),
        ));
    }

    /// ordered set remove + compact ghosts (one surface).
    #[test]
    fn ordered_set_remove_and_compact_surface() {
        let mut ordered: VecDeque<_> = [h(1), h(2), h(3)].into_iter().collect();
        let mut set: HashSet<_> = ordered.iter().copied().collect();
        remove_from_ordered(&mut ordered, &mut set, h(1));
        assert_eq!(ordered.front().copied(), Some(h(2)));
        assert!(!set.contains(&h(1)));

        let mut ordered: VecDeque<_> = [h(1), h(2), h(3)].into_iter().collect();
        let mut set: HashSet<_> = ordered.iter().copied().collect();
        remove_from_ordered(&mut ordered, &mut set, h(2));
        assert_eq!(ordered.len(), 3);
        assert!(!set.contains(&h(2)));
        remove_from_ordered(&mut ordered, &mut set, h(1));
        assert_eq!(ordered.front().copied(), Some(h(3)));
        assert_eq!(ordered.len(), 1);

        let mut ordered = VecDeque::new();
        let mut set = HashSet::new();
        for i in 1u16..=100 {
            ordered.push_back(h(i));
            set.insert(h(i));
            ordered.push_back(h(1000 + i));
        }
        assert_eq!(ordered.len(), 200);
        compact_ordered(&mut ordered, &set);
        assert_eq!(ordered.len(), 100);
        for x in &ordered {
            assert!(set.contains(x));
        }

        // Small deques are left alone (compact threshold).
        let mut ordered: VecDeque<_> = [h(1), h(2)].into_iter().collect();
        let set: HashSet<_> = [h(1)].into_iter().collect();
        compact_ordered(&mut ordered, &set);
        assert_eq!(ordered.len(), 2);

        // Ghost budget: live=80, len=100 → within budget, no compact.
        let mut ordered = VecDeque::new();
        let mut set = HashSet::new();
        for i in 1u16..=80 {
            ordered.push_back(h(i));
            set.insert(h(i));
        }
        for i in 1u16..=20 {
            ordered.push_back(h(2000 + i)); // ghosts
        }
        let before = ordered.len();
        compact_ordered(&mut ordered, &set);
        assert_eq!(ordered.len(), before);

        // remove front chain of ghosts after middle remove already did set.
        let mut ordered: VecDeque<_> = [h(1), h(2), h(3), h(4)].into_iter().collect();
        let mut set: HashSet<_> = [h(3), h(4)].into_iter().collect();
        remove_from_ordered(&mut ordered, &mut set, h(3));
        // Front 1,2 not in set → popped; 3 removed; 4 remains.
        assert_eq!(ordered.front().copied(), Some(h(4)));
        assert_eq!(ordered.len(), 1);

        assert_eq!(far_slots_per_peer(1, false), 1); // max(0,1)=1
        assert_eq!(far_slots_per_peer(3, false), 1);
    }
}
