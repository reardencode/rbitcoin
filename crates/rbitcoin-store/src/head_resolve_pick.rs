//! Newest-first identity pick for head resolve (BIP30 / fence).
//!
//! A wave fills identities in at most two page-grouped `txid.body` shots
//! (first [`ID_FILL_CHUNK`] cands, then the rest). One walk of the filled
//! prefix returns the fence-connected winner (or the newest body match when
//! no fence), whether any body matched, and the miss count. Entries after
//! the winner still count as misses.

use crate::height_fence::HeightFence;
use crate::int_map::{U64Map, U64Set};
use rbitcoin_primitives::Fk;

/// First identity shot size. Later cands wait for shot B only if the key is
/// still unfinished (no connected win; unconnected body match is not enough).
pub(crate) const ID_FILL_CHUNK: usize = 4;

/// Unread prefix of `take` cands for keys that are not `skip`.
pub(crate) fn next_id_shot(
    cands_by_key: &[Vec<Fk>],
    filled: &[usize],
    skip: &[bool],
    take: usize,
) -> Vec<Fk> {
    let mut need = Vec::new();
    let mut seen = U64Set::default();
    for (ki, cands) in cands_by_key.iter().enumerate() {
        if skip.get(ki).copied().unwrap_or(false) {
            continue;
        }
        let start = filled.get(ki).copied().unwrap_or(0);
        for &fk in cands.iter().skip(start).take(take) {
            let Some(id) = fk.get() else {
                continue;
            };
            if seen.insert(id) {
                need.push(fk);
            }
        }
    }
    need
}

/// One pass over `cands[..filled]`: winner, any body match, and miss count.
///
/// `winner` is the fence-connected body match. With no fence it is the newest
/// body match. `unconnected_fallback` is the end-of-list TipThenAny case: no
/// connected hit, so the newest body match wins. Newer unconnected matches do
/// not win while a fence is present and this flag is clear.
///
/// `miss` counts prefix entries that are not `want`, including entries after
/// the winner.
pub(crate) struct PrefixWalk {
    pub winner: Option<(Fk, u64)>,
    pub had_body: bool,
    pub miss: u64,
}

pub(crate) fn walk_id_prefix(
    cands: &[Fk],
    filled: usize,
    want: &[u8; 32],
    id_of: &U64Map<[u8; 32]>,
    heights: Option<&HeightFence>,
    unconnected_fallback: bool,
) -> PrefixWalk {
    let n = filled.min(cands.len());
    let mut first_match: Option<(Fk, u64)> = None;
    let mut connected: Option<(Fk, u64)> = None;
    let mut miss = 0u64;
    for (i, &fk) in cands.iter().take(n).enumerate() {
        let rank = (i + 1) as u64;
        let body_hit = match fk.get() {
            Some(id) => id_of.get(&id).is_some_and(|got| got.as_slice() == want),
            None => false,
        };
        if !body_hit {
            // The stat covers the whole filled prefix, not only the prefix
            // before the winner.
            miss = miss.saturating_add(1);
            continue;
        }
        if first_match.is_none() {
            first_match = Some((fk, rank));
        }
        if connected.is_none() && heights.is_some_and(|ht| ht.height_of(fk).is_some()) {
            connected = Some((fk, rank));
        }
    }
    let winner = if heights.is_some() {
        connected.or(if unconnected_fallback {
            first_match
        } else {
            None
        })
    } else {
        first_match
    };
    PrefixWalk {
        winner,
        had_body: first_match.is_some(),
        miss,
    }
}

/// Which lookup table a TipOnly leftover miss failed on.
///
/// Confirm leftover is `tx.head` probe → `txid.body` identity → fence.
/// The operator line names the first table that did not produce a usable fact.
/// A connected identity is a pick, not a miss, so it is not a class here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftoverMissOn {
    /// No probe candidates (hot + cold).
    Head,
    /// Probe cands, no `txid.body` match for the wanted txid.
    Body,
    /// Identity match exists, no fence height (TipOnly drops it).
    Fence,
}

impl LeftoverMissOn {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Body => "body",
            Self::Fence => "fence",
        }
    }
}

/// Classify a TipOnly leftover miss from facts the resolve machine already has.
///
/// A connected identity always has `picked` set, and TipOnly classification
/// only runs for keys whose pick is empty. `connected == true` never arrives.
pub fn classify_leftover_miss(n_cands: usize, had_identity: bool) -> LeftoverMissOn {
    if n_cands == 0 {
        LeftoverMissOn::Head
    } else if !had_identity {
        LeftoverMissOn::Body
    } else {
        LeftoverMissOn::Fence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::height_fence::{FenceRun, HeightFence};

    fn fence_on(fks: &[u64]) -> HeightFence {
        let runs: Vec<FenceRun> = fks
            .iter()
            .map(|&id| FenceRun {
                first_fk: id,
                count: 1,
                height: 0,
            })
            .collect();
        HeightFence::from_runs(runs)
    }

    fn ids(pairs: &[(u64, [u8; 32])]) -> U64Map<[u8; 32]> {
        pairs.iter().copied().collect()
    }

    fn walked(
        cands: &[Fk],
        filled: usize,
        want: &[u8; 32],
        id_of: &U64Map<[u8; 32]>,
        heights: Option<&HeightFence>,
    ) -> PrefixWalk {
        walk_id_prefix(cands, filled, want, id_of, heights, false)
    }

    #[test]
    fn id_idx_stop_after_connected_skips_older_cand() {
        let want = [0xAAu8; 32];
        let other = [0xBBu8; 32];
        let cands = [Fk(10), Fk(20), Fk(30)];
        let ht = fence_on(&[20]);
        // Newest unconnected match is not a fence winner.
        let map1 = ids(&[(10, want)]);
        assert!(walked(&cands, 1, &want, &map1, Some(&ht)).winner.is_none());
        // Connected match at rank 2 wins; older Fk(30) is irrelevant.
        let map2 = ids(&[(10, want), (20, want)]);
        let (fk, rank) = walked(&cands, 2, &want, &map2, Some(&ht)).winner.unwrap();
        assert_eq!(fk, Fk(20));
        assert_eq!(rank, 2);
        let _ = other;
    }

    #[test]
    fn id_idx_stop_after_connected_unconnected_only_peeks_all() {
        let want = [0xAAu8; 32];
        let cands = [Fk(10), Fk(20)];
        let ht = fence_on(&[99]);
        let map = ids(&[(10, want), (20, want)]);
        let w = walked(&cands, 2, &want, &map, Some(&ht));
        assert!(w.winner.is_none());
        assert!(w.had_body);
        assert_eq!(w.miss, 0);
        let fb = walk_id_prefix(&cands, 2, &want, &map, Some(&ht), true);
        assert_eq!(fb.winner, Some((Fk(10), 1)));
        assert_eq!(fb.miss, 0);
    }

    #[test]
    fn no_fence_stops_at_first_txid_match() {
        let want = [0xAAu8; 32];
        let cands = [Fk(1), Fk(2)];
        let map = ids(&[(1, want)]);
        let (fk, rank) = walked(&cands, 1, &want, &map, None).winner.unwrap();
        assert_eq!((fk, rank), (Fk(1), 1));
    }

    /// Full cand list + complete id_map: newest unconnected body match does
    /// not win when a shallower cand is fence-connected.
    #[test]
    fn full_map_connected_beats_newer_unconnected() {
        let want = [0xAAu8; 32];
        let cands = [Fk(10), Fk(20)];
        let ht = fence_on(&[20]);
        let map = ids(&[(10, want), (20, want)]);
        let (fk, rank) = walked(&cands, cands.len(), &want, &map, Some(&ht))
            .winner
            .unwrap();
        assert_eq!(fk, Fk(20));
        assert_eq!(rank, 2);
    }

    /// A cand with no `id_map` entry is not a match (same as wrong body).
    #[test]
    fn missing_id_map_entry_is_not_a_match() {
        let want = [0xAAu8; 32];
        let cands = [Fk(10), Fk(20)];
        let ht = fence_on(&[10, 20]);
        let map = ids(&[(20, want)]);
        let (fk, rank) = walked(&cands, cands.len(), &want, &map, Some(&ht))
            .winner
            .unwrap();
        assert_eq!(fk, Fk(20));
        assert_eq!(rank, 2);
        let empty = ids(&[]);
        assert!(walked(&cands, cands.len(), &want, &empty, Some(&ht))
            .winner
            .is_none());
    }

    #[test]
    fn leftover_miss_classifies_head_body_idx_fence() {
        assert_eq!(classify_leftover_miss(0, false), LeftoverMissOn::Head);
        assert_eq!(classify_leftover_miss(3, false), LeftoverMissOn::Body);
        assert_eq!(classify_leftover_miss(3, true), LeftoverMissOn::Fence);
        assert_eq!(LeftoverMissOn::Head.as_str(), "head");
        assert_eq!(LeftoverMissOn::Body.as_str(), "body");
        assert_eq!(LeftoverMissOn::Fence.as_str(), "fence");
    }

    #[test]
    fn miss_peeks_counts_wrong_identity_only() {
        let want = [0xAAu8; 32];
        let cands = [Fk(1), Fk(2)];
        let map = ids(&[(1, [0x00; 32]), (2, want)]);
        let w = walked(&cands, 2, &want, &map, None);
        assert_eq!(w.miss, 1);
        assert_eq!(w.winner, Some((Fk(2), 2)));
        let after = [Fk(1), Fk(2), Fk(3)];
        let map_after = ids(&[(1, want), (2, [0x00; 32]), (3, [0x11; 32])]);
        let w_after = walked(&after, 3, &want, &map_after, None);
        assert_eq!(w_after.winner, Some((Fk(1), 1)));
        assert_eq!(w_after.miss, 2, "entries after the winner still miss");
    }

    #[test]
    fn next_id_shot_first_chunk_then_rest() {
        let cands = vec![vec![Fk(10), Fk(20), Fk(30), Fk(40), Fk(50), Fk(60)]];
        let filled = vec![0usize];
        let skip = vec![false];
        let a = next_id_shot(&cands, &filled, &skip, ID_FILL_CHUNK);
        assert_eq!(a, vec![Fk(10), Fk(20), Fk(30), Fk(40)]);
        let filled = vec![ID_FILL_CHUNK];
        let b = next_id_shot(&cands, &filled, &skip, usize::MAX);
        assert_eq!(b, vec![Fk(50), Fk(60)]);
    }

    #[test]
    fn two_shot_skips_tail_after_connected_in_chunk() {
        let want = [0xAAu8; 32];
        let cands = vec![vec![Fk(10), Fk(20), Fk(30), Fk(40), Fk(50)]];
        let mut filled = vec![0usize];
        let mut skip = vec![false];
        let shot_a = next_id_shot(&cands, &filled, &skip, ID_FILL_CHUNK);
        assert_eq!(shot_a.len(), ID_FILL_CHUNK);
        filled[0] = ID_FILL_CHUNK;
        let map = ids(&[(10, want), (20, want)]);
        let ht = fence_on(&[20]);
        assert!(walked(&cands[0], filled[0], &want, &map, Some(&ht))
            .winner
            .is_some());
        skip[0] = true;
        let shot_b = next_id_shot(&cands, &filled, &skip, usize::MAX);
        assert!(
            shot_b.is_empty(),
            "connected in shot A must not fetch the tail"
        );
    }

    #[test]
    fn two_shot_unconnected_body_match_still_takes_rest() {
        let want = [0xAAu8; 32];
        let cands = vec![vec![Fk(10), Fk(20), Fk(30), Fk(40), Fk(50)]];
        let mut filled = vec![0usize];
        let skip = vec![false];
        let _shot_a = next_id_shot(&cands, &filled, &skip, ID_FILL_CHUNK);
        filled[0] = ID_FILL_CHUNK;
        let map = ids(&[(10, want)]);
        let ht = fence_on(&[50]);
        assert!(
            walked(&cands[0], filled[0], &want, &map, Some(&ht))
                .winner
                .is_none(),
            "unconnected match in the chunk is not a fence win"
        );
        let shot_b = next_id_shot(&cands, &filled, &skip, usize::MAX);
        assert_eq!(shot_b, vec![Fk(50)]);
    }
}
