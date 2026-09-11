//! Process-local Class A body presence cache for IBD assign/status.

use crate::chain::ChainHub;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// O(1) occupancy of each [`BodyPresence`] set (for `ibd: sizes` logs).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BodyPresenceSizes {
    pub known: usize,
    pub pending: usize,
    pub missing: usize,
    pub rejected: usize,
}

/// Process-local Class A body presence cache.
///
/// Assign/status used to call `is_archived` (store) for every ordered hash every
/// loop — that contended with the archive writer and delayed getdata top-up
/// (spiky receive). Probe each hash at most once until archive marks it ready.
///
/// `pending` covers the wire→confirm gap: we clear getdata inflight on body
/// receipt, but must not re-request until confirm advances tip (or re-get after
/// stale expire).
///
/// `rejected` covers Class C permanent failures: never re-offer or re-download.
pub(crate) struct BodyPresence {
    known: HashSet<BlockHash>,
    /// Received on the wire / in body queue, not yet tip-confirmed.
    /// Membership **is** the pending set; value is when marked (stale expire).
    pending_since: HashMap<BlockHash, Instant>,
    /// Store-probed and not archived yet (safe to request getdata).
    missing: HashSet<BlockHash>,
    /// Confirm rejected this hash; do not re-offer or re-download.
    rejected: HashSet<BlockHash>,
}

impl BodyPresence {
    pub(crate) fn new() -> Self {
        Self {
            known: HashSet::new(),
            pending_since: HashMap::new(),
            missing: HashSet::new(),
            rejected: HashSet::new(),
        }
    }

    #[inline]
    fn is_pending_hash(&self, h: &BlockHash) -> bool {
        self.pending_since.contains_key(h)
    }

    pub(crate) fn mark_pending(&mut self, h: BlockHash) {
        if self.rejected.contains(&h) {
            return;
        }
        self.missing.remove(&h);
        self.pending_since.entry(h).or_insert_with(Instant::now);
    }

    pub(crate) fn mark_archived(&mut self, h: BlockHash) {
        if self.rejected.contains(&h) {
            return;
        }
        self.missing.remove(&h);
        self.pending_since.remove(&h);
        self.known.insert(h);
    }

    pub(crate) fn mark_missing(&mut self, h: BlockHash) {
        if self.rejected.contains(&h) {
            return;
        }
        self.known.remove(&h);
        self.pending_since.remove(&h);
        self.missing.insert(h);
    }

    /// Drop optimistic Class A cache only — next [`Self::ready`] re-probes the store.
    pub(crate) fn demote_known(&mut self, h: BlockHash) {
        self.known.remove(&h);
    }

    /// Permanent confirm failure: never re-offer this hash to the confirm engine
    /// and never re-getdata it.
    pub(crate) fn mark_rejected(&mut self, h: BlockHash) {
        self.known.remove(&h);
        self.pending_since.remove(&h);
        self.missing.remove(&h);
        self.rejected.insert(h);
    }

    /// Pending hashes older than `max_age` matching `pred` → mark missing (re-get).
    pub(crate) fn expire_stale_pending_if(
        &mut self,
        max_age: Duration,
        mut pred: impl FnMut(&BlockHash) -> bool,
    ) -> Vec<BlockHash> {
        let now = Instant::now();
        let stale: Vec<BlockHash> = self
            .pending_since
            .iter()
            .filter(|(h, t)| pred(h) && now.duration_since(**t) >= max_age)
            .map(|(h, _)| *h)
            .collect();
        for h in &stale {
            self.mark_missing(*h);
        }
        stale
    }

    pub(crate) fn is_rejected(&self, h: &BlockHash) -> bool {
        self.rejected.contains(h)
    }

    /// True if we already know Class A is present (no store probe).
    pub(crate) fn is_known_archived(&self, h: &BlockHash) -> bool {
        self.known.contains(h)
    }

    pub(crate) fn known_len(&self) -> usize {
        self.known.len()
    }

    pub(crate) fn size_snapshot(&self) -> BodyPresenceSizes {
        BodyPresenceSizes {
            known: self.known.len(),
            pending: self.pending_since.len(),
            missing: self.missing.len(),
            rejected: self.rejected.len(),
        }
    }

    pub(crate) fn is_pending(&self, h: &BlockHash) -> bool {
        self.is_pending_hash(h)
    }

    pub(crate) fn is_missing(&self, h: &BlockHash) -> bool {
        self.missing.contains(h)
    }

    /// Hot path: local sets first. Do **not** call `has_block` before checking
    /// `missing` — assign walks tens of thousands of known-missing far hashes.
    ///
    /// Does **not** treat `known` (Class A cache) as skip — that set is densify
    /// bookkeeping; tip-hole re-get after resume still needs peer wire into BQ.
    pub(crate) fn skip_download(&mut self, hub: &ChainHub, h: &BlockHash) -> bool {
        if self.rejected.contains(h) || self.is_pending_hash(h) {
            return true;
        }
        if self.is_missing(h) {
            return false;
        }
        if hub.has_block(h) {
            self.known.insert(*h);
            return true;
        }
        false
    }

    /// Drop cache entries that are no longer on the live work path.
    /// Rejected entries are never pruned.
    pub(crate) fn hygiene_retain(&mut self, mut keep: impl FnMut(&BlockHash) -> bool) {
        self.known.retain(|h| keep(h));
        self.missing.retain(|h| keep(h));
        self.pending_since.retain(|h, _| keep(h));
    }
}

#[cfg(test)]
mod tests {
    use super::BodyPresence;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use std::time::Duration;

    fn h(n: u8) -> BlockHash {
        let mut b = [0u8; 32];
        b[0] = n;
        BlockHash::from_byte_array(b)
    }

    #[test]
    fn presence_lifecycle_surface() {
        let mut body = BodyPresence::new();
        body.mark_pending(h(1));
        assert!(body.is_pending(&h(1)));
        assert!(!body.is_known_archived(&h(1)));

        body.mark_archived(h(2));
        assert!(body.is_known_archived(&h(2)));
        assert!(!body.is_pending(&h(2)));

        body.mark_missing(h(3));
        assert!(!body.is_pending(&h(3)));
        assert!(!body.is_known_archived(&h(3)));

        assert_eq!(body.size_snapshot().pending, 1);
        assert_eq!(body.known_len(), 1);

        let hash = h(4);
        body.mark_pending(hash);
        body.mark_archived(hash);
        assert!(body.is_known_archived(&hash));
        body.mark_missing(hash);
        assert!(!body.is_known_archived(&hash));
        body.mark_archived(hash);
        assert!(body.is_known_archived(&hash));

        body.demote_known(h(2));
        assert!(!body.is_known_archived(&h(2)));

        body.mark_archived(h(10));
        body.mark_missing(h(11));
        body.mark_rejected(h(12));
        body.hygiene_retain(|x| *x == h(10) || *x == h(12));
        assert!(body.is_known_archived(&h(10)));
        assert!(body.is_rejected(&h(12)));
        let snap = body.size_snapshot();
        assert_eq!(snap.known, 1);
        assert_eq!(snap.rejected, 1);
    }

    #[test]
    fn rejected_sticky_through_mark_ops() {
        let mut body = BodyPresence::new();
        let rej = h(5);
        body.mark_archived(rej);
        body.mark_rejected(rej);
        assert!(body.is_rejected(&rej));
        body.mark_archived(rej);
        assert!(body.is_rejected(&rej));
        assert!(!body.is_known_archived(&rej));

        let r = h(20);
        body.mark_rejected(r);
        body.mark_pending(r);
        body.mark_missing(r);
        body.mark_archived(r);
        assert!(body.is_rejected(&r));
        assert!(!body.is_pending(&r));
        assert!(!body.is_known_archived(&r));
    }

    #[test]
    fn expire_stale_pending_if_surface() {
        let mut body = BodyPresence::new();
        body.mark_pending(h(1));
        body.mark_pending(h(2));
        let expired = body.expire_stale_pending_if(Duration::ZERO, |_| true);
        assert_eq!(expired.len(), 2);

        body.mark_pending(h(3));
        body.mark_pending(h(4));
        let only3 = body.expire_stale_pending_if(Duration::ZERO, |x| *x == h(3));
        assert_eq!(only3, vec![h(3)]);
        assert!(body.is_pending(&h(4)));

        body.mark_archived(h(10));
        body.mark_rejected(h(11));
        let snap = body.size_snapshot();
        assert_eq!(snap.known, 1);
        assert_eq!(snap.pending, 1);
        assert_eq!(snap.rejected, 1);
    }
}
