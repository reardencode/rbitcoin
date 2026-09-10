//! Process-local confirm parent cache (header plans).
//!
//! **Header plans** (`headers` / `hash_to_height`): tip-GCed header + tx_fks.
//! Create outs / denserels / body_range are **pipeline-local** (plan `batch_pin`,
//! [`crate::BatchParents`]). Thin edges are batch-local.
//!
//! Header plans stay **always on** — multi-block wire prep needs tip-ahead
//! header plans for MTP / bits (mainnet tip freeze: `parent header plan
//! missing above tip`).

use crate::U32Map;
use rbitcoin_primitives::Fk;
use rbitcoin_store::HeaderRecord;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Cached header + body fk list for one cache height (avoids header.head/body
/// and header_txs page faults on confirm resolve).
#[derive(Debug, Clone)]
pub struct HeaderPlanCache {
    pub header_fk: Fk,
    pub header_rec: HeaderRecord,
    pub tx_fks: Vec<Fk>,
    /// Previous block hash (zeros at genesis). Filled at cache so wire rebuild
    /// never `store.get_header(prev_fk)`.
    pub prev_hash: [u8; 32],
}

struct Inner {
    /// Highest confirmed tip we have pruned to.
    tip: u32,
    /// height → immutable header + tx list (Arc-publish; tip GC drops Arc).
    headers: U32Map<Arc<HeaderPlanCache>>,
    /// hash → height for O(1) header resolve on confirm.
    hash_to_height: HashMap<[u8; 32], u32>,
}

/// Process-local confirm parent cache (header plans).
///
/// **Always active** — multi-block wire prep needs tip-ahead header plans for
/// MTP / bits (mainnet tip freeze: `parent header plan missing above tip`).
pub struct ConfirmParentCache {
    inner: Mutex<Inner>,
}

impl ConfirmParentCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                tip: 0,
                headers: U32Map::default(),
                hash_to_height: HashMap::new(),
            }),
        }
    }

    /// Advance tip: drop headers at/below tip.
    ///
    /// Thin edges / sparse pins are batch-local. Called from load
    /// `on_load_pack` (polls store tip; write does not lock this cache).
    pub fn advance_tip(&self, tip: u32) {
        let mut g = self.inner.lock().unwrap();
        g.tip = tip;
        let drop_hdr: Vec<u32> = g.headers.keys().copied().filter(|h| *h <= tip).collect();
        for h in drop_hdr {
            if let Some(plan) = g.headers.remove(&h) {
                g.hash_to_height.remove(&plan.header_rec.hash);
            }
        }
    }

    /// Cache header + tx list for a cache height (tip-GCed; required for multi-block MTP).
    pub fn put_header_plan(
        &self,
        height: u32,
        header_fk: Fk,
        header_rec: HeaderRecord,
        tx_fks: Vec<Fk>,
        prev_hash: [u8; 32],
    ) {
        let mut g = self.inner.lock().unwrap();
        // Tip-GCed window only — never re-insert at/below tip (would stick until
        // a later advance and inflate conf_plans / RSS with full tx_fks vectors).
        if height <= g.tip {
            return;
        }
        let hash = header_rec.hash;
        // Replace supersedes prior hash at this height — drop stale reverse key.
        let stale_hash = g
            .headers
            .get(&height)
            .map(|old| old.header_rec.hash)
            .filter(|old_hash| *old_hash != hash);
        if let Some(old_hash) = stale_hash {
            g.hash_to_height.remove(&old_hash);
        }
        g.hash_to_height.insert(hash, height);
        g.headers.insert(
            height,
            Arc::new(HeaderPlanCache {
                header_fk,
                header_rec,
                tx_fks,
                prev_hash,
            }),
        );
    }

    pub fn get_header_by_hash(&self, hash: &[u8; 32]) -> Option<(Fk, HeaderRecord)> {
        let g = self.inner.lock().unwrap();
        let h = *g.hash_to_height.get(hash)?;
        let plan = g.headers.get(&h)?;
        Some((plan.header_fk, plan.header_rec.clone()))
    }

    pub fn get_header_plan(&self, height: u32) -> Option<HeaderPlanCache> {
        self.inner
            .lock()
            .unwrap()
            .headers
            .get(&height)
            .map(|a| (**a).clone())
    }

    pub fn get_tx_fks_for_hash(&self, hash: &[u8; 32]) -> Option<Vec<Fk>> {
        let g = self.inner.lock().unwrap();
        let h = *g.hash_to_height.get(hash)?;
        g.headers.get(&h).map(|p| p.tx_fks.clone())
    }

    /// Number of cached header + tx_fks plans (IBD `conf_plans=` occupancy).
    pub fn header_plan_count(&self) -> usize {
        self.inner.lock().unwrap().headers.len()
    }
}

impl crate::Query {
    pub fn advance_parent_cache_tip(&self, tip: u32) {
        self.confirm_parents.advance_tip(tip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_rec(hash: [u8; 32]) -> HeaderRecord {
        HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 0,
            merkle_root: [0u8; 32],
            hash,
        }
    }

    #[test]
    fn advance_tip_prunes_headers() {
        let c = ConfirmParentCache::new();
        c.advance_tip(0);
        c.put_header_plan(1, Fk(1), header_rec([1u8; 32]), vec![Fk(10)], [0u8; 32]);
        assert!(c.get_header_plan(1).is_some());
        c.advance_tip(1);
        assert!(c.get_header_plan(1).is_none());
        assert_eq!(c.header_plan_count(), 0);
    }

    /// Header plans are replaced, not mutated in place; tip GC drops them.
    #[test]
    fn header_plan_replace_and_tip_gc() {
        let c = ConfirmParentCache::new();
        c.advance_tip(0);
        c.put_header_plan(1, Fk(1), header_rec([1u8; 32]), vec![Fk(10)], [0u8; 32]);
        let a1 = c.get_header_plan(1).expect("plan");
        assert_eq!(a1.tx_fks, vec![Fk(10)]);
        c.put_header_plan(
            1,
            Fk(1),
            header_rec([1u8; 32]),
            vec![Fk(11), Fk(12)],
            [0u8; 32],
        );
        let a2 = c.get_header_plan(1).expect("replaced");
        assert_eq!(a2.tx_fks, vec![Fk(11), Fk(12)]);
        assert_eq!(c.header_plan_count(), 1);
        c.advance_tip(1);
        assert!(c.get_header_plan(1).is_none());
        assert_eq!(c.header_plan_count(), 0);
    }

    /// Header plans must work regardless of denserels cache env (regression for
    /// mainnet tip freeze: `parent header plan missing above tip`).
    #[test]
    fn put_header_plan_always_stores_for_mtp() {
        let c = ConfirmParentCache::new();
        c.put_header_plan(1, Fk(1), header_rec([9u8; 32]), vec![Fk(1)], [0u8; 32]);
        let p = c
            .get_header_plan(1)
            .expect("header plan required for multi-block MTP");
        assert_eq!(p.header_rec.hash, [9u8; 32]);
        assert_eq!(c.header_plan_count(), 1);
    }

    /// At/below tip must not re-enter the header map (process-owned RSS).
    #[test]
    fn put_header_plan_skips_at_or_below_tip() {
        let c = ConfirmParentCache::new();
        c.advance_tip(10);
        c.put_header_plan(
            10,
            Fk(10),
            header_rec([10u8; 32]),
            vec![Fk(1); 100],
            [0u8; 32],
        );
        c.put_header_plan(5, Fk(5), header_rec([5u8; 32]), vec![Fk(1); 100], [0u8; 32]);
        assert_eq!(c.header_plan_count(), 0);
        c.put_header_plan(11, Fk(11), header_rec([11u8; 32]), vec![Fk(1)], [0u8; 32]);
        assert_eq!(c.header_plan_count(), 1);
        c.advance_tip(11);
        assert_eq!(c.header_plan_count(), 0);
    }

    /// Replacing a height drops the stale hash reverse index (no hash_to_height leak).
    #[test]
    fn put_header_plan_replaces_stale_hash_reverse() {
        let c = ConfirmParentCache::new();
        c.put_header_plan(1, Fk(1), header_rec([1u8; 32]), vec![Fk(1)], [0u8; 32]);
        c.put_header_plan(1, Fk(1), header_rec([2u8; 32]), vec![Fk(2)], [0u8; 32]);
        assert!(c.get_header_by_hash(&[1u8; 32]).is_none());
        assert!(c.get_header_by_hash(&[2u8; 32]).is_some());
        assert_eq!(c.header_plan_count(), 1);
    }
}
