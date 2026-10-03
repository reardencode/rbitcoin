//! Transaction orphanage for txs missing in-mempool / chain parents.
//!
//! Weight budget: 404_000 WU reserved per peer × 25-peer budget → ~10.1M WU
//! unique orphans; unique-count cap 3000. Per-tx max 404_000 WU.
//!
//! Eviction: FIFO by insert order when over weight or count.

use bitcoin::{Transaction, Txid, Wtxid};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Reserved orphan weight per peer.
pub const ORPHAN_RESERVED_WEIGHT_PER_PEER: u64 = 404_000;
/// Peer multiplier for a fixed global weight budget.
pub const ORPHAN_PEER_BUDGET: u64 = 25;
/// Global unique orphan weight cap (404k × 25 ≈ 10.1M WU).
pub const DEFAULT_ORPHAN_MAX_WEIGHT: u64 = ORPHAN_RESERVED_WEIGHT_PER_PEER * ORPHAN_PEER_BUDGET;
/// Secondary unique-count cap.
pub const DEFAULT_ORPHAN_MAX_COUNT: usize = 3_000;
/// Refuse orphans heavier than a standard tx.
pub const MAX_ORPHAN_TX_WEIGHT: u64 = 404_000;
/// Drop an orphan this long after it was parked. Not a knob.
pub const ORPHAN_EXPIRE_MS: u64 = 20 * 60 * 1000;

#[derive(Debug, Clone)]
struct OrphanEntry {
    tx: Transaction,
    wtxid: Wtxid,
    weight: u64,
    /// Missing parent txids (prevout.txid not in mempool/chain at insert).
    missing: BTreeSet<Txid>,
    /// P2P peer ids that announced this orphan.
    announcers: BTreeSet<u64>,
    arrived_ms: u64,
}

/// One parked orphan (txid + announcer peer ids).
#[derive(Debug, Clone)]
pub struct OrphanSnapshot {
    pub tx: Transaction,
    pub announcers: Vec<u64>,
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
    /// Announced weight per peer. Eviction reads this instead of scanning the set.
    peer_weight: HashMap<u64, u64>,
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
            peer_weight: HashMap::new(),
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

    pub fn wtxid_of(&self, txid: &Txid) -> Option<Wtxid> {
        self.by_txid.get(txid).map(|e| e.wtxid)
    }

    pub fn tx_by_wtxid(&self, wtxid: &Wtxid) -> Option<&Transaction> {
        let txid = self.by_wtxid.get(wtxid)?;
        self.by_txid.get(txid).map(|e| &e.tx)
    }

    pub fn missing_of(&self, txid: &Txid) -> Option<&BTreeSet<Txid>> {
        self.by_txid.get(txid).map(|e| &e.missing)
    }

    pub fn txs(&self) -> impl Iterator<Item = &Transaction> {
        self.by_txid.values().map(|e| &e.tx)
    }

    /// Insert (or add `from` as announcer if already parked).
    pub fn insert_from(
        &mut self,
        tx: Transaction,
        missing: BTreeSet<Txid>,
        from: Option<u64>,
    ) -> bool {
        self.insert_from_at(tx, missing, from, unix_ms())
    }

    /// [`Self::insert_from`] at an explicit unix millisecond clock.
    pub fn insert_from_at(
        &mut self,
        tx: Transaction,
        missing: BTreeSet<Txid>,
        from: Option<u64>,
        now_ms: u64,
    ) -> bool {
        if missing.is_empty() {
            return false;
        }
        self.expire(now_ms);
        let txid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        if let Some(e) = self.by_txid.get(&txid) {
            if e.wtxid == wtxid {
                if let Some(peer) = from {
                    self.add_announcer(&txid, peer);
                }
                return false;
            }
            self.remove_txid(&txid);
        }
        let weight = tx.weight().to_wu();
        if weight > MAX_ORPHAN_TX_WEIGHT {
            return false;
        }
        if let Some(peer) = from {
            while self.peer_orphan_weight(peer).saturating_add(weight)
                > ORPHAN_RESERVED_WEIGHT_PER_PEER
            {
                if !self.evict_one_from_peer(peer) {
                    return false;
                }
            }
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
        let mut announcers = BTreeSet::new();
        if let Some(peer) = from {
            announcers.insert(peer);
        }
        self.by_wtxid.insert(wtxid, txid);
        self.by_txid.insert(
            txid,
            OrphanEntry {
                tx,
                wtxid,
                weight,
                missing,
                announcers,
                arrived_ms: now_ms,
            },
        );
        self.fifo.push_back(txid);
        self.total_weight = self.total_weight.saturating_add(weight);
        if let Some(peer) = from {
            self.add_peer_weight(peer, weight);
        }
        true
    }

    fn expire(&mut self, now_ms: u64) {
        let stale: Vec<Txid> = self
            .by_txid
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.arrived_ms) >= ORPHAN_EXPIRE_MS)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in stale {
            self.remove_txid(&txid);
        }
    }

    fn add_peer_weight(&mut self, peer: u64, weight: u64) {
        let w = self.peer_weight.entry(peer).or_default();
        *w = w.saturating_add(weight);
    }

    fn sub_peer_weight(&mut self, peer: u64, weight: u64) {
        let next = self
            .peer_weight
            .get(&peer)
            .copied()
            .unwrap_or(0)
            .saturating_sub(weight);
        if next == 0 {
            self.peer_weight.remove(&peer);
        } else {
            self.peer_weight.insert(peer, next);
        }
    }

    fn unaccount(&mut self, e: &OrphanEntry) {
        self.total_weight = self.total_weight.saturating_sub(e.weight);
        for peer in &e.announcers {
            self.sub_peer_weight(*peer, e.weight);
        }
    }

    fn peer_orphan_weight(&self, peer: u64) -> u64 {
        self.peer_weight.get(&peer).copied().unwrap_or(0)
    }

    fn announcers_within_reserve(&self, txid: &Txid) -> bool {
        let Some(e) = self.by_txid.get(txid) else {
            return false;
        };
        if e.announcers.is_empty() {
            return false;
        }
        e.announcers
            .iter()
            .any(|p| self.peer_orphan_weight(*p) <= ORPHAN_RESERVED_WEIGHT_PER_PEER)
    }

    fn evict_one_from_peer(&mut self, peer: u64) -> bool {
        let victim = self
            .fifo
            .iter()
            .find(|txid| {
                self.by_txid
                    .get(*txid)
                    .is_some_and(|e| e.announcers.contains(&peer))
            })
            .copied();
        let Some(txid) = victim else {
            return false;
        };
        self.remove_txid(&txid);
        self.fifo.retain(|t| self.by_txid.contains_key(t));
        true
    }

    fn evict_oldest(&mut self) -> bool {
        if self.evict_oldest_filtered(true) {
            return true;
        }
        // The reserve is a preference. A set that is entirely protected still
        // makes room for one newer orphan.
        self.evict_oldest_filtered(false)
    }

    fn evict_oldest_filtered(&mut self, honor_reserve: bool) -> bool {
        let mut skipped = VecDeque::new();
        while let Some(txid) = self.fifo.pop_front() {
            if !self.by_txid.contains_key(&txid) {
                continue;
            }
            if honor_reserve && self.announcers_within_reserve(&txid) {
                skipped.push_back(txid);
                continue;
            }
            self.remove_txid(&txid);
            skipped.append(&mut self.fifo);
            self.fifo = skipped;
            return true;
        }
        self.fifo = skipped;
        false
    }

    fn remove_txid(&mut self, txid: &Txid) {
        let Some(e) = self.by_txid.remove(txid) else {
            return;
        };
        self.by_wtxid.remove(&e.wtxid);
        self.unaccount(&e);
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
                self.unaccount(&e);
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

    pub fn announcers_of(&self, txid: &Txid) -> Vec<u64> {
        self.by_txid
            .get(txid)
            .map(|e| e.announcers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn has_announcer(&self, peer: u64) -> bool {
        self.by_txid.values().any(|e| e.announcers.contains(&peer))
    }

    pub fn add_announcer(&mut self, txid: &Txid, peer: u64) -> bool {
        let weight = {
            let Some(e) = self.by_txid.get_mut(txid) else {
                return false;
            };
            if !e.announcers.insert(peer) {
                return false;
            }
            e.weight
        };
        self.add_peer_weight(peer, weight);
        true
    }

    pub fn add_announcer_wtxid(&mut self, wtxid: &Wtxid, peer: u64) -> bool {
        let Some(txid) = self.by_wtxid.get(wtxid).copied() else {
            return false;
        };
        self.add_announcer(&txid, peer)
    }

    /// Drop `peer` as announcer; erase orphans with no remaining announcers.
    pub fn erase_for_peer(&mut self, peer: u64) {
        let hit: Vec<(Txid, u64, bool)> = self
            .by_txid
            .iter()
            .filter_map(|(txid, e)| {
                if !e.announcers.contains(&peer) {
                    return None;
                }
                Some((*txid, e.weight, e.announcers.len() == 1))
            })
            .collect();
        let mut drop = Vec::new();
        for (txid, weight, last) in hit {
            if let Some(e) = self.by_txid.get_mut(&txid) {
                e.announcers.remove(&peer);
            }
            self.sub_peer_weight(peer, weight);
            if last {
                drop.push(txid);
            }
        }
        for t in drop {
            self.remove_txid(&t);
        }
        self.fifo.retain(|t| self.by_txid.contains_key(t));
    }

    pub fn snapshot(&self) -> Vec<OrphanSnapshot> {
        let mut out = Vec::with_capacity(self.fifo.len());
        let mut seen = HashSet::new();
        for txid in &self.fifo {
            if !seen.insert(*txid) {
                continue;
            }
            if let Some(e) = self.by_txid.get(txid) {
                out.push(OrphanSnapshot {
                    tx: e.tx.clone(),
                    announcers: e.announcers.iter().copied().collect(),
                });
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

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
    fn one_peer_cannot_fill_the_orphanage() {
        let mut o = Orphanage::new();
        let parent = txid_n(8);
        let tx2 = {
            let mut tx = make_orphan(parent, 1);
            tx.input[0].witness = Witness::from_slice(&[vec![2u8; 64]]);
            tx
        };
        let mut miss = BTreeSet::new();
        miss.insert(parent);
        assert!(o.insert_from(tx2.clone(), miss.clone(), Some(2)));
        for i in 0..80u8 {
            let mut tx = make_orphan(parent, i.wrapping_add(3));
            tx.input[0].witness = Witness::from_slice(&[vec![i.wrapping_add(3); 20_000]]);
            tx.lock_time = LockTime::from_height(i as u32).unwrap();
            o.insert_from(tx, miss.clone(), Some(1));
        }
        assert!(
            o.peer_orphan_weight(1) <= ORPHAN_RESERVED_WEIGHT_PER_PEER,
            "peer weight {}",
            o.peer_orphan_weight(1)
        );
        let peer2_kept = o.announcers_of(&tx2.compute_txid()).contains(&2);
        assert!(peer2_kept, "peer 2 must keep its orphan");
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
        assert!(o.insert_from(tx, miss, None));
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
            o.insert_from(tx, miss, None);
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
        assert!(!o.insert_from(tx.clone(), BTreeSet::new(), None));
        let mut miss = BTreeSet::new();
        miss.insert(p);
        assert!(o.insert_from(tx.clone(), miss.clone(), None));
        assert!(!o.insert_from(tx.clone(), miss.clone(), None));
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
            o2.insert_from(t, m, None);
        }
        assert!(o2.len() <= 3);
        // erase_for_block drops matching orphans.
        let t3 = make_orphan(p, 50);
        let tid3 = t3.compute_txid();
        let mut m = BTreeSet::new();
        m.insert(p);
        o2.insert_from(t3, m, None);
        o2.erase_for_block(&[tid3]);
        assert!(!o2.contains(&tid3));
    }

    #[test]
    fn announcers_and_erase_for_peer() {
        let mut o = Orphanage::new();
        let p = txid_n(4);
        let tx = make_orphan(p, 7);
        let tid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        let mut miss = BTreeSet::new();
        miss.insert(p);
        assert!(o.insert_from(tx.clone(), miss, Some(3)));
        assert!(o.has_announcer(3));
        assert!(!o.has_announcer(9));
        assert_eq!(o.announcers_of(&tid), vec![3]);
        assert!(o.add_announcer_wtxid(&wtxid, 9));
        assert_eq!(o.announcers_of(&tid), vec![3, 9]);
        o.erase_for_peer(3);
        assert_eq!(o.announcers_of(&tid), vec![9]);
        assert!(o.contains(&tid));
        o.erase_for_peer(9);
        assert!(!o.contains(&tid));
        assert!(o.is_empty());
    }
    #[test]
    fn mempool_under_pressure() {
        assert_eq!(ORPHAN_EXPIRE_MS, 1_200_000);
        assert!(unix_ms() > 1_700_000_000_000);

        let mut o = Orphanage::with_limits(DEFAULT_ORPHAN_MAX_WEIGHT, 2);
        let parent = txid_n(11);
        let mut miss = BTreeSet::new();
        miss.insert(parent);

        let first = make_orphan(parent, 1);
        let second = make_orphan(parent, 2);
        assert!(o.insert_from_at(first, miss.clone(), Some(7), 0));
        let one = o.peer_orphan_weight(7);
        assert!(one > 0);
        assert!(o.insert_from_at(second.clone(), miss.clone(), Some(7), 0));
        assert!(o.peer_orphan_weight(7) > one);
        o.erase_for_block(&[second.compute_txid()]);
        assert_eq!(o.peer_orphan_weight(7), one);

        let filler = make_orphan(parent, 4);
        assert!(o.insert_from_at(filler, miss.clone(), Some(2), 0));
        assert_eq!(o.len(), 2);
        let later = make_orphan(parent, 3);
        let later_id = later.compute_txid();
        assert!(
            o.insert_from_at(later, miss.clone(), Some(3), 0),
            "a full per-peer reserve must still admit a newer orphan"
        );
        assert!(o.contains(&later_id));
        assert!(o.len() <= 2);

        let held = make_orphan(parent, 5);
        let held_id = held.compute_txid();
        assert!(o.insert_from_at(held, miss.clone(), Some(7), ORPHAN_EXPIRE_MS));
        assert!(
            !o.contains(&later_id),
            "an orphan parked for ORPHAN_EXPIRE_MS is gone"
        );
        assert!(o.contains(&held_id));
        let tail = make_orphan(parent, 6);
        assert!(o.insert_from_at(tail, miss, Some(7), ORPHAN_EXPIRE_MS + ORPHAN_EXPIRE_MS));
        assert!(
            !o.contains(&held_id),
            "the next expiry bound drops the orphan that survived the first"
        );
    }
}
