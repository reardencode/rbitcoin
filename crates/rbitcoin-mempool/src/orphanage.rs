//! Transaction orphanage for txs missing in-mempool / chain parents.
//!
//! Sized after Bitcoin Core's `TxOrphanage` defaults (master 2024+):
//! - **404_000 weight reserved per peer** (`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`)
//! - **Global usage** ≈ reserved × peer budget (we use a fixed ~25-peer budget →
//!   **~10.1M weight** unique orphans — same order as Core with a modest announcer set)
//! - **Latency/count** secondary bound (Core global latency score default **3000**;
//!   we cap unique orphans at **1000** — between legacy 100-tx default and modern score)
//! - Per-tx max **404_000 weight** (standard tx weight)
//!
//! Eviction: FIFO by insert order when over weight or count (simple DoS bound;
//! Core picks DoSiest peer's oldest announcement — we are single-process).

use bitcoin::{Transaction, Txid, Wtxid};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Core `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`.
pub const ORPHAN_RESERVED_WEIGHT_PER_PEER: u64 = 404_000;
/// Peer multiplier for a fixed global weight budget (Core scales by announcer peers).
pub const ORPHAN_PEER_BUDGET: u64 = 25;
/// Global unique orphan weight cap (404k × 25 ≈ 10.1M WU).
pub const DEFAULT_ORPHAN_MAX_WEIGHT: u64 = ORPHAN_RESERVED_WEIGHT_PER_PEER * ORPHAN_PEER_BUDGET;
/// Secondary unique-count cap (Core `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE` = 3000).
pub const DEFAULT_ORPHAN_MAX_COUNT: usize = 3_000;
/// Core `MAX_STANDARD_TX_WEIGHT` — refuse larger orphans.
pub const MAX_ORPHAN_TX_WEIGHT: u64 = 404_000;

#[derive(Debug, Clone)]
struct OrphanEntry {
    tx: Transaction,
    wtxid: Wtxid,
    weight: u64,
    /// Missing parent txids (prevout.txid not in mempool/chain at insert).
    missing: BTreeSet<Txid>,
}

/// Side pool of not-yet-acceptable txs waiting on parent(s).
#[derive(Debug, Default)]
pub struct Orphanage {
    by_txid: HashMap<Txid, OrphanEntry>,
    by_wtxid: HashMap<Wtxid, Txid>,
    /// parent txid → orphan children waiting on it.
    by_parent: HashMap<Txid, HashSet<Txid>>,
    fifo: VecDeque<Txid>,
    total_weight: u64,
    max_weight: u64,
    max_count: usize,
}

impl Orphanage {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_ORPHAN_MAX_WEIGHT, DEFAULT_ORPHAN_MAX_COUNT)
    }

    pub fn with_limits(max_weight: u64, max_count: usize) -> Self {
        Self {
            by_txid: HashMap::new(),
            by_wtxid: HashMap::new(),
            by_parent: HashMap::new(),
            fifo: VecDeque::new(),
            total_weight: 0,
            max_weight: max_weight.max(MAX_ORPHAN_TX_WEIGHT),
            max_count: max_count.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.by_txid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_txid.is_empty()
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.by_txid.contains_key(txid)
    }

    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.by_wtxid.contains_key(wtxid)
    }

    pub fn missing_of(&self, txid: &Txid) -> Option<&BTreeSet<Txid>> {
        self.by_txid.get(txid).map(|e| &e.missing)
    }

    pub fn txs(&self) -> impl Iterator<Item = &Transaction> {
        self.by_txid.values().map(|e| &e.tx)
    }

    /// Insert orphan waiting on `missing` parent txids. Returns true if newly stored.
    pub fn insert(&mut self, tx: Transaction, missing: BTreeSet<Txid>) -> bool {
        if missing.is_empty() {
            return false;
        }
        let txid = tx.compute_txid();
        if self.by_txid.contains_key(&txid) {
            return false;
        }
        let wtxid = tx.compute_wtxid();
        let weight = tx.weight().to_wu();
        if weight > MAX_ORPHAN_TX_WEIGHT {
            return false;
        }
        while !self.by_txid.is_empty()
            && (self.by_txid.len() >= self.max_count
                || self.total_weight.saturating_add(weight) > self.max_weight)
        {
            if !self.evict_oldest() {
                break;
            }
        }
        if self.by_txid.len() >= self.max_count
            || self.total_weight.saturating_add(weight) > self.max_weight
        {
            return false;
        }
        for p in &missing {
            self.by_parent.entry(*p).or_default().insert(txid);
        }
        self.by_wtxid.insert(wtxid, txid);
        self.by_txid.insert(
            txid,
            OrphanEntry {
                tx,
                wtxid,
                weight,
                missing,
            },
        );
        self.fifo.push_back(txid);
        self.total_weight = self.total_weight.saturating_add(weight);
        true
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(txid) = self.fifo.pop_front() else {
            return false;
        };
        self.remove_txid(&txid);
        true
    }

    fn remove_txid(&mut self, txid: &Txid) {
        let Some(e) = self.by_txid.remove(txid) else {
            return;
        };
        self.by_wtxid.remove(&e.wtxid);
        self.total_weight = self.total_weight.saturating_sub(e.weight);
        for p in &e.missing {
            if let Some(set) = self.by_parent.get_mut(p) {
                set.remove(txid);
                if set.is_empty() {
                    self.by_parent.remove(p);
                }
            }
        }
        // fifo may still hold txid if removed mid-list; leave stale ids (skipped on pop)
    }

    /// Take all orphans that listed `parent` as missing (for re-accept).
    pub fn take_children_of(&mut self, parent: &Txid) -> Vec<Transaction> {
        let Some(children) = self.by_parent.remove(parent) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(children.len());
        for cid in children {
            if let Some(e) = self.by_txid.remove(&cid) {
                self.by_wtxid.remove(&e.wtxid);
                self.total_weight = self.total_weight.saturating_sub(e.weight);
                for p in &e.missing {
                    if p == parent {
                        continue;
                    }
                    if let Some(set) = self.by_parent.get_mut(p) {
                        set.remove(&cid);
                        if set.is_empty() {
                            self.by_parent.remove(p);
                        }
                    }
                }
                out.push(e.tx);
            }
        }
        out
    }

    /// Drop orphans that are themselves included in a confirmed block.
    ///
    /// Children of confirmed parents are **not** erased here — callers should
    /// [`take_children_of`] and re-accept (Core `AddChildrenToWorkSet` path).
    /// Spending a parent in the block does not invalidate the orphan; the parent
    /// create is now a chain UTXO.
    pub fn erase_for_block(&mut self, block_txids: &[Txid]) {
        let block: HashSet<Txid> = block_txids.iter().copied().collect();
        let drop: Vec<Txid> = self
            .by_txid
            .keys()
            .filter(|t| block.contains(*t))
            .copied()
            .collect();
        for t in drop {
            self.remove_txid(&t);
        }
        self.fifo.retain(|t| self.by_txid.contains_key(t));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn txid_n(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn make_orphan(parent: Txid, salt: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000 + salt as u64),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [salt; 20],
                )),
            }],
        }
    }

    #[test]
    fn insert_and_take_by_parent() {
        let mut o = Orphanage::new();
        let p = txid_n(1);
        let tx = make_orphan(p, 2);
        let tid = tx.compute_txid();
        let mut miss = BTreeSet::new();
        miss.insert(p);
        let wtxid = tx.compute_wtxid();
        assert!(o.insert(tx, miss));
        assert!(o.contains(&tid));
        assert!(o.contains_wtxid(&wtxid));
        assert_eq!(o.missing_of(&tid).map(|s| s.len()), Some(1));
        assert_eq!(o.len(), 1);
        let kids = o.take_children_of(&p);
        assert_eq!(kids.len(), 1);
        assert!(o.is_empty());
        assert!(!o.contains_wtxid(&wtxid));
    }

    #[test]
    fn fifo_evicts_under_count_cap() {
        let mut o = Orphanage::with_limits(DEFAULT_ORPHAN_MAX_WEIGHT, 2);
        let p = txid_n(9);
        for i in 0..3u8 {
            let tx = make_orphan(p, i + 1);
            let mut miss = BTreeSet::new();
            miss.insert(p);
            o.insert(tx, miss);
        }
        assert!(o.len() <= 2);
        assert!(o.total_weight() <= DEFAULT_ORPHAN_MAX_WEIGHT);
    }

    #[test]
    fn core_like_budget_constants() {
        assert_eq!(ORPHAN_RESERVED_WEIGHT_PER_PEER, 404_000);
        assert_eq!(DEFAULT_ORPHAN_MAX_WEIGHT, 404_000 * 25);
        // ~10 MiB class weight budget for unique orphans.
        const {
            assert!(DEFAULT_ORPHAN_MAX_WEIGHT > 10_000_000);
            assert!(DEFAULT_ORPHAN_MAX_WEIGHT < 11_000_000);
        }
    }

    #[test]
    fn reject_oversize_duplicate_and_remove() {
        let mut o = Orphanage::with_limits(DEFAULT_ORPHAN_MAX_WEIGHT, 100);
        let p = txid_n(3);
        // Empty missing parents → refuse.
        let tx = make_orphan(p, 1);
        assert!(!o.insert(tx.clone(), BTreeSet::new()));
        let mut miss = BTreeSet::new();
        miss.insert(p);
        assert!(o.insert(tx.clone(), miss.clone()));
        // Duplicate insert rejected.
        assert!(!o.insert(tx.clone(), miss.clone()));
        let tid = tx.compute_txid();
        o.remove_txid(&tid);
        assert!(!o.contains(&tid));
        // take_children on unknown parent is empty.
        assert!(o.take_children_of(&txid_n(99)).is_empty());
        // Count-cap eviction (with_limits floors max_weight at MAX_ORPHAN_TX_WEIGHT).
        let mut o2 = Orphanage::with_limits(DEFAULT_ORPHAN_MAX_WEIGHT, 3);
        for i in 0..8u8 {
            let t = make_orphan(p, i + 1);
            let mut m = BTreeSet::new();
            m.insert(p);
            o2.insert(t, m);
        }
        assert!(o2.len() <= 3);
        // erase_for_block drops matching orphans.
        let t3 = make_orphan(p, 50);
        let tid3 = t3.compute_txid();
        let mut m = BTreeSet::new();
        m.insert(p);
        o2.insert(t3, m);
        o2.erase_for_block(&[tid3]);
        assert!(!o2.contains(&tid3));
    }
}
