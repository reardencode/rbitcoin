//! In-memory TxGraph: clusters, topo linearization, chunk bounds.
//!
//! Cluster = maximal connected component via in-mempool parent/child edges
//! (spend of another mempool output). Caps: 64 txs / 101 kvB (plan §3.2).

use bitcoin::{OutPoint, Transaction, Txid, Wtxid};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use std::sync::Mutex;

/// Hard cap on txs in one cluster.
pub const MAX_CLUSTER_COUNT: usize = 64;
/// Hard cap on total **virtual size** of one cluster (101 kvB).
///
/// Measured as Σ [`vbytes_ceil`](rbitcoin_consensus::policy::vbytes_ceil) over cluster members.
pub const MAX_CLUSTER_VSIZE: u64 = 101_000;
/// Same limit as weight units: 101_000 vB × 4 WU/vB.
///
/// Kept for call sites that sum `tx.weight().to_wu()`; prefer comparing vsize when possible.
/// **Was incorrectly 101_000 WU** (4× too tight) — mainnet logs rejected single ~25–65 kvB txs.
pub const MAX_CLUSTER_WEIGHT: u64 = MAX_CLUSTER_VSIZE * 4;

/// Consensus block sigop cost limit (BIP141 `MAX_BLOCK_SIGOPS_COST`).
pub use rbitcoin_consensus::block::MAX_BLOCK_SIGOPS_COST;
/// Sigop cost reserved for the coinbase (Core `node/miner.cpp` `nBlockSigOpsCost = 400`).
pub const COINBASE_SIGOPS_RESERVE: u64 = 400;
/// Core `DEFAULT_BYTES_PER_SIGOP` (`-bytespersigop`).
pub const DEFAULT_BYTES_PER_SIGOP: u64 = 20;

/// Core `GetSigOpsAdjustedWeight`: `max(weight, sigop_cost × bytes_per_sigop)`.
///
/// Feerate and cluster-size policy use this; the block weight budget does not.
/// `bytes_per_sigop = 0` disables the adjustment.
pub fn sigops_adjusted_weight(weight: u64, sigop_cost: u64, bytes_per_sigop: u64) -> u64 {
    weight.max(sigop_cost.saturating_mul(bytes_per_sigop))
}

/// Whether a modified fee meets `-blockmintxfee` on sigop-adjusted weight as
/// a true sat/kvB floor (Core `CFeeRate::GetFee`: `fee * 1000 >= min * vsize`).
/// Zero min admits free chunks.
#[doc(hidden)]
pub fn meets_block_min_feerate(modified_sat: i128, adj_weight_wu: u64, min_sat_kvb: u64) -> bool {
    if min_sat_kvb == 0 {
        return true;
    }
    let vsize = rbitcoin_consensus::policy::vbytes_ceil(adj_weight_wu);
    modified_sat.saturating_mul(1000) >= i128::from(min_sat_kvb) * i128::from(vsize)
}

/// Caller's block budget for [`TxGraph::select_block_template`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectBudget {
    /// Raw weight (WU) available to mempool txs.
    pub max_weight_wu: u64,
    /// Sigop cost held back for the coinbase (Core `nBlockSigOpsCost` start).
    pub reserved_sigops: u64,
    /// `-blockmintxfee` chunk floor on modified fee (sat/kvB).
    pub min_sat_kvb: u64,
}

/// One tx picked by [`TxGraph::select_block_template`], read under the same
/// graph borrow as the selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected {
    pub txid: Txid,
    /// Base fee (sat), not the `prioritisetransaction`-modified fee.
    pub fee_sat: u64,
    /// Full BIP16 + BIP141 sigop cost recorded at admission.
    pub sigop_cost: u64,
}

/// One live mempool entry (RAM index; body lives on disk).
#[derive(Debug, Clone)]
pub struct TxEntry {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub fee_sat: u64,
    pub weight: u64,
    /// Full BIP16 + BIP141 sigop cost recorded at admission.
    pub sigop_cost: u64,
    /// Slot index in the durable slot table.
    pub slot: u32,
    /// In-mempool parents (txids this tx spends).
    pub parents: BTreeSet<Txid>,
    /// In-mempool children.
    pub children: BTreeSet<Txid>,
}

impl TxEntry {
    /// Sigop-adjusted weight (Core `CTxMemPoolEntry::GetAdjustedWeight`).
    pub fn adjusted_weight(&self, bytes_per_sigop: u64) -> u64 {
        sigops_adjusted_weight(self.weight, self.sigop_cost, bytes_per_sigop)
    }
}

/// Contiguous linearization segment used for fee comparison / eviction (P5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Txids in mining order within this chunk.
    pub txids: Vec<Txid>,
    pub fee_sat: u64,
    /// Sum of members' sigop-adjusted weight (Core txgraph chunk size).
    pub weight: u64,
}

impl Chunk {
    pub fn fee_rate_sat_per_kvb(&self) -> u64 {
        rbitcoin_consensus::policy::fee_rate_sat_per_kvb(self.fee_sat, self.weight)
    }
}

fn sort_chunks_best_first(chunks: &mut [Chunk]) {
    chunks.sort_by(|a, b| {
        b.fee_rate_sat_per_kvb()
            .cmp(&a.fee_rate_sat_per_kvb())
            .then_with(|| b.fee_sat.cmp(&a.fee_sat))
    });
}

/// Frontier feerate from a **best-first** chunk list (no graph walk).
///
/// Used by fee snapshot refresh so multi-target estimates share one linearize.
pub fn frontier_feerate_from_chunks(chunks: &[Chunk], target_wu: u64) -> Option<u64> {
    if chunks.is_empty() {
        return None;
    }
    let mut cum = 0u64;
    for ch in chunks {
        cum = cum.saturating_add(ch.weight);
        if cum >= target_wu {
            return Some(ch.fee_rate_sat_per_kvb().max(1));
        }
    }
    None
}

/// Weight strictly above `rate_sat_per_kvb` from a best-first chunk list.
pub fn weight_above_from_chunks(chunks: &[Chunk], rate_sat_per_kvb: u64) -> u64 {
    chunks
        .iter()
        .filter(|c| c.fee_rate_sat_per_kvb() > rate_sat_per_kvb)
        .map(|c| c.weight)
        .sum()
}

/// Prefix of a best-first chunk list so each candidate rate is one search.
///
/// `chunks` must be ordered by descending feerate, the same order as
/// [`frontier_feerate_from_chunks`].
#[derive(Debug, Clone)]
pub struct StockAbove {
    /// Feerate of each chunk, descending.
    pub rates: Vec<u64>,
    /// `prefix[i]` is the weight of chunks `0..i`.
    pub prefix: Vec<u64>,
}

impl StockAbove {
    pub fn from_best_first(chunks: &[Chunk]) -> Self {
        let mut rates = Vec::with_capacity(chunks.len());
        let mut prefix = Vec::with_capacity(chunks.len() + 1);
        prefix.push(0);
        for ch in chunks {
            rates.push(ch.fee_rate_sat_per_kvb());
            let cum = prefix
                .last()
                .copied()
                .unwrap_or(0u64)
                .saturating_add(ch.weight);
            prefix.push(cum);
        }
        Self { rates, prefix }
    }

    /// Weight of chunks whose feerate is strictly above `rate_sat_per_kvb`.
    pub fn above(&self, rate_sat_per_kvb: u64) -> u64 {
        let i = self.rates.partition_point(|&rate| rate > rate_sat_per_kvb);
        self.prefix[i]
    }
}

/// Cluster identity: sorted member set fingerprint (min txid as representative).
#[derive(Debug, Clone)]
pub struct Cluster {
    pub members: BTreeSet<Txid>,
    /// Sum of members' raw weight (cluster size limit basis).
    pub total_weight: u64,
    /// Mining linearization (topo, high fee-rate first among ready).
    pub linearization: Vec<Txid>,
    pub chunks: Vec<Chunk>,
}

/// Inclusive ancestor/descendant aggregates for RPC (self counts as 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolGraphStats {
    pub ancestorcount: u64,
    pub ancestorsize: u64,
    pub ancestorfees: u64,
    pub descendantcount: u64,
    pub descendantsize: u64,
    pub descendantfees: u64,
}

/// Live-set graph. Proportional to mempool size, not file size.
#[derive(Debug)]
pub struct TxGraph {
    pub entries: HashMap<Txid, TxEntry>,
    /// Live wtxid → txid (last insert wins). BIP339 inv must not scan `entries`.
    pub by_wtxid: HashMap<Wtxid, Txid>,
    /// Mempool-created outpoints spent by another mempool tx.
    pub spends: HashMap<OutPoint, Txid>,
    /// **All** outpoints spent by live mempool txs (chain UTXOs + mempool), for RBF conflicts.
    pub conflicts: HashMap<OutPoint, Txid>,
    /// Outputs created by mempool txs: (txid, vout) present while unspent in-mempool.
    pub created: HashSet<OutPoint>,
    /// Sum of live weights (WU) for eviction budget.
    pub total_weight: u64,
    /// Best-first chunks; `None` after mutate until next build.
    pub chunk_cache: Mutex<Option<Vec<Chunk>>>,
    /// Lowest-rate chunk per cluster, ordered by (rate, representative txid).
    pub worst_chunks: BTreeMap<(u64, Txid), Chunk>,
    /// Representative → rate key into [`Self::worst_chunks`].
    pub worst_rep_rate: HashMap<Txid, u64>,
    /// Core `-limitclustercount` (default [`MAX_CLUSTER_COUNT`]).
    pub cluster_count_limit: usize,
    /// Core `-limitclustersize` as vbytes (default [`MAX_CLUSTER_VSIZE`]).
    pub cluster_vsize_limit: u64,
    /// Same cap in WU (vsize × 4). Kept for call sites that sum weight.
    pub cluster_weight_limit: u64,
    /// Core `-bytespersigop` (default [`DEFAULT_BYTES_PER_SIGOP`]).
    pub bytes_per_sigop: u64,
    /// Sigop allowance held back for the block's coinbase/template overhead.
    pub block_reserved_sigops: u64,
}

impl Default for TxGraph {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            by_wtxid: HashMap::new(),
            spends: HashMap::new(),
            conflicts: HashMap::new(),
            created: HashSet::new(),
            total_weight: 0,
            chunk_cache: Mutex::new(None),
            worst_chunks: BTreeMap::new(),
            worst_rep_rate: HashMap::new(),
            cluster_count_limit: MAX_CLUSTER_COUNT,
            cluster_vsize_limit: MAX_CLUSTER_VSIZE,
            cluster_weight_limit: MAX_CLUSTER_WEIGHT,
            bytes_per_sigop: DEFAULT_BYTES_PER_SIGOP,
            block_reserved_sigops: COINBASE_SIGOPS_RESERVE,
        }
    }
}

impl TxGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overlay Core `-limitclustercount` / `-limitclustersize` (kvB → WU).
    pub fn set_cluster_limits(&mut self, count: Option<u32>, size_kvb: Option<u32>) {
        if let Some(n) = count {
            self.cluster_count_limit = (n as usize).max(1);
        }
        if let Some(kvb) = size_kvb {
            self.cluster_vsize_limit = (kvb as u64).saturating_mul(1000).max(1);
            self.cluster_weight_limit = self.cluster_vsize_limit.saturating_mul(4);
        }
    }

    /// Overlay Core `-bytespersigop` and re-rank every live chunk on it.
    pub fn set_bytes_per_sigop(&mut self, bytes_per_sigop: u64) {
        self.bytes_per_sigop = bytes_per_sigop;
        self.invalidate_chunk_cache();
        self.worst_chunks.clear();
        self.worst_rep_rate.clear();
        // ponytail: one cluster walk per live tx, startup-only config.
        let ids: Vec<Txid> = self.entries.keys().copied().collect();
        for t in ids {
            self.index_cluster_of(&t);
        }
    }

    pub fn bytes_per_sigop(&self) -> u64 {
        self.bytes_per_sigop
    }

    /// Set the admission sigop reserve (a tx must fit a block beside it).
    pub fn set_block_reserved_sigops(&mut self, reserved: u64) {
        self.block_reserved_sigops = reserved;
    }

    pub fn block_reserved_sigops(&self) -> u64 {
        self.block_reserved_sigops
    }

    #[doc(hidden)]
    pub fn adjusted_weight_of(&self, txid: &Txid) -> u64 {
        self.entries
            .get(txid)
            .map(|e| e.adjusted_weight(self.bytes_per_sigop))
            .unwrap_or(0)
    }

    /// Σ raw weight of live `set` members (cluster-limit basis).
    #[doc(hidden)]
    pub fn raw_weight_of(&self, set: &BTreeSet<Txid>) -> u64 {
        set.iter()
            .filter_map(|t| self.entries.get(t))
            .fold(0u64, |w, e| w.saturating_add(e.weight))
    }

    pub fn cluster_count_limit(&self) -> usize {
        self.cluster_count_limit
    }

    pub fn cluster_vsize_limit(&self) -> u64 {
        self.cluster_vsize_limit
    }

    pub fn cluster_weight_limit(&self) -> u64 {
        self.cluster_weight_limit
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.by_wtxid.contains_key(wtxid)
    }

    pub fn txid_for_wtxid(&self, wtxid: &Wtxid) -> Option<Txid> {
        self.by_wtxid.get(wtxid).copied()
    }

    #[doc(hidden)]
    pub fn invalidate_chunk_cache(&mut self) {
        *self.chunk_cache.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    #[doc(hidden)]
    pub fn cluster_rep(&self, txid: &Txid) -> Option<Txid> {
        self.cluster_of(txid)?.members.iter().next().copied()
    }

    #[doc(hidden)]
    pub fn drop_cluster_index(&mut self, rep: Txid) {
        if let Some(rate) = self.worst_rep_rate.remove(&rep) {
            self.worst_chunks.remove(&(rate, rep));
        }
    }

    #[doc(hidden)]
    pub fn index_cluster_of(&mut self, txid: &Txid) {
        let Some(c) = self.cluster_of(txid) else {
            return;
        };
        let Some(&rep) = c.members.iter().next() else {
            return;
        };
        self.drop_cluster_index(rep);
        let mut best: Option<(u64, Chunk)> = None;
        for ch in c.chunks {
            let rate = ch.fee_rate_sat_per_kvb();
            let take = match &best {
                None => true,
                Some((br, _)) => rate < *br,
            };
            if take {
                best = Some((rate, ch));
            }
        }
        if let Some((rate, ch)) = best {
            self.worst_rep_rate.insert(rep, rate);
            self.worst_chunks.insert((rate, rep), ch);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn get(&self, txid: &Txid) -> Option<&TxEntry> {
        self.entries.get(txid)
    }

    /// Set a live entry's sigop cost (post-migrate recompute) and re-rank its
    /// cluster on the new adjusted weight.
    pub fn set_sigop_cost(&mut self, txid: &Txid, cost: u64) {
        if let Some(e) = self.entries.get_mut(txid) {
            e.sigop_cost = cost;
            self.invalidate_chunk_cache();
            self.index_cluster_of(txid);
        }
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Txid, &TxEntry)> {
        self.entries.iter()
    }

    /// Whether this outpoint is created by a live mempool tx and not yet spent in-mempool.
    pub fn mempool_utxo(&self, op: &OutPoint) -> bool {
        self.created.contains(op) && !self.spends.contains_key(op)
    }

    /// Txid that created `op` if it is still a live mempool output (possibly spent).
    ///
    /// Prefer the created-outpoint set; fall back to a live body with this
    /// txid so a 10-input merger still unions parent clusters if a vout was
    /// missed in `created` (MiniWallet `new_utxo` / padded extra outputs).
    pub fn creator(&self, op: &OutPoint) -> Option<Txid> {
        if self.created.contains(op) || self.entries.contains_key(&op.txid) {
            Some(op.txid)
        } else {
            None
        }
    }

    /// Direct conflict: another mempool tx already spends this outpoint.
    pub fn conflict_txid(&self, op: &OutPoint) -> Option<Txid> {
        self.conflicts.get(op).copied()
    }

    /// Outpoints spent by any live mempool tx (chain + mempool parents).
    pub fn conflict_outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.conflicts.keys().copied()
    }

    /// Conflict set for RBF: conflicting txs plus all their descendants.
    pub fn conflict_set(&self, direct: &[Txid]) -> BTreeSet<Txid> {
        let mut set = BTreeSet::new();
        let mut q = VecDeque::new();
        for t in direct {
            if self.entries.contains_key(t) && set.insert(*t) {
                q.push_back(*t);
            }
        }
        while let Some(cur) = q.pop_front() {
            if let Some(e) = self.entries.get(&cur) {
                for c in &e.children {
                    if set.insert(*c) {
                        q.push_back(*c);
                    }
                }
            }
        }
        set
    }

    /// Inclusive walk of in-mempool parents (the tx itself is always in the set).
    pub fn ancestor_set(&self, txid: &Txid) -> Option<BTreeSet<Txid>> {
        self.directed_set(txid, true)
    }

    /// Inclusive walk of in-mempool children (the tx itself is always in the set).
    pub fn descendant_set(&self, txid: &Txid) -> Option<BTreeSet<Txid>> {
        self.directed_set(txid, false)
    }

    #[doc(hidden)]
    pub fn directed_set(&self, txid: &Txid, parents: bool) -> Option<BTreeSet<Txid>> {
        if !self.entries.contains_key(txid) {
            return None;
        }
        let mut set = BTreeSet::new();
        let mut q = VecDeque::new();
        set.insert(*txid);
        q.push_back(*txid);
        while let Some(cur) = q.pop_front() {
            let Some(e) = self.entries.get(&cur) else {
                continue;
            };
            let next = if parents {
                e.parents.iter()
            } else {
                e.children.iter()
            };
            for n in next {
                if set.insert(*n) {
                    q.push_back(*n);
                }
            }
        }
        Some(set)
    }

    /// Ancestor/descendant counts and vsize/fee sums, or `None` if `txid` is not live.
    pub fn graph_stats(&self, txid: &Txid) -> Option<MempoolGraphStats> {
        let anc = self.ancestor_set(txid)?;
        let desc = self.descendant_set(txid)?;
        let (a_fee, _) = self.set_fee_weight(&anc);
        let (d_fee, _) = self.set_fee_weight(&desc);
        Some(MempoolGraphStats {
            ancestorcount: anc.len() as u64,
            ancestorsize: self.set_vsize(&anc),
            ancestorfees: a_fee,
            descendantcount: desc.len() as u64,
            descendantsize: self.set_vsize(&desc),
            descendantfees: d_fee,
        })
    }

    /// Same as [`Self::graph_stats`] with `prioritisetransaction` deltas in the fee sums.
    pub fn graph_stats_delta(
        &self,
        txid: &Txid,
        delta: impl Fn(Txid) -> i64,
    ) -> Option<(MempoolGraphStats, i64, i64)> {
        let anc = self.ancestor_set(txid)?;
        let desc = self.descendant_set(txid)?;
        let (a_fee, _) = self.set_fee_weight(&anc);
        let (d_fee, _) = self.set_fee_weight(&desc);
        let a_mod = self.set_modified_fee(&anc, &delta);
        let d_mod = self.set_modified_fee(&desc, &delta);
        Some((
            MempoolGraphStats {
                ancestorcount: anc.len() as u64,
                ancestorsize: self.set_vsize(&anc),
                ancestorfees: a_fee,
                descendantcount: desc.len() as u64,
                descendantsize: self.set_vsize(&desc),
                descendantfees: d_fee,
            },
            a_mod,
            d_mod,
        ))
    }

    #[doc(hidden)]
    pub fn set_modified_fee(&self, set: &BTreeSet<Txid>, delta: &impl Fn(Txid) -> i64) -> i64 {
        let mut fee = 0i128;
        for t in set {
            if let Some(e) = self.entries.get(t) {
                fee =
                    fee.saturating_add(i128::from(e.fee_sat).saturating_add(i128::from(delta(*t))));
            }
        }
        fee.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }

    /// Chunk containing `txid` after linearising on `base + delta`.
    ///
    /// The fee is that chunk's signed modified fee, so a deprioritised child
    /// is its own chunk and does not change its parent's fee.
    pub fn chunk_of(
        &self,
        txid: &Txid,
        delta: impl Fn(Txid) -> i64,
    ) -> Option<(i64, u64, Vec<Txid>)> {
        let delta = &delta;
        let c = self.cluster_of_delta(txid, delta)?;
        for ch in c.chunks {
            if ch.txids.contains(txid) {
                let fee = self.set_modified_fee(&ch.txids.iter().copied().collect(), delta);
                return Some((fee, ch.weight, ch.txids));
            }
        }
        None
    }

    /// Aggregate fee / sigop-adjusted weight of a set of live txs.
    pub fn set_fee_weight(&self, set: &BTreeSet<Txid>) -> (u64, u64) {
        let mut fee = 0u64;
        let mut w = 0u64;
        for t in set {
            if let Some(e) = self.entries.get(t) {
                fee = fee.saturating_add(e.fee_sat);
                w = w.saturating_add(e.adjusted_weight(self.bytes_per_sigop));
            }
        }
        (fee, w)
    }

    /// Σ per-tx sigop-adjusted vsize (Core `GetTxSize`).
    #[doc(hidden)]
    pub fn set_vsize(&self, set: &BTreeSet<Txid>) -> u64 {
        let mut n = 0u64;
        for t in set {
            if self.entries.contains_key(t) {
                n = n.saturating_add(rbitcoin_consensus::policy::vbytes_ceil(
                    self.adjusted_weight_of(t),
                ));
            }
        }
        n
    }

    /// Insert entry and wire parent/child edges. Does **not** enforce cluster limits
    /// (caller checks via `cluster_of` after insert, and may remove).
    pub fn insert(&mut self, entry: TxEntry, tx: &Transaction) {
        self.invalidate_chunk_cache();
        let txid = entry.txid;
        let mut seen = BTreeSet::new();
        let mut old_reps = BTreeSet::new();
        for inp in &tx.input {
            let parent = inp.previous_output.txid;
            if !self.created.contains(&inp.previous_output) {
                continue;
            }
            if seen.contains(&parent) {
                continue;
            }
            if let Some(r) = self.component_rep(parent, &mut seen) {
                old_reps.insert(r);
            }
        }
        for (vout, _) in tx.output.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            let Some(child) = self.conflicts.get(&op).copied() else {
                continue;
            };
            if seen.contains(&child) {
                continue;
            }
            if let Some(r) = self.component_rep(child, &mut seen) {
                old_reps.insert(r);
            }
        }
        for r in old_reps {
            self.drop_cluster_index(r);
        }
        let weight = entry.weight;
        let parents: BTreeSet<Txid> = tx
            .input
            .iter()
            .filter_map(|i| {
                let op = i.previous_output;
                if self.created.contains(&op) {
                    Some(op.txid)
                } else {
                    None
                }
            })
            .collect();

        let mut e = entry;
        e.parents = parents.clone();
        for p in &parents {
            if let Some(pe) = self.entries.get_mut(p) {
                pe.children.insert(txid);
            }
        }
        for inp in &tx.input {
            let op = inp.previous_output;
            self.conflicts.insert(op, txid);
            if self.created.contains(&op) {
                self.spends.insert(op, txid);
            }
        }
        for (vout, _) in tx.output.iter().enumerate() {
            self.created.insert(OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        self.total_weight = self.total_weight.saturating_add(weight);
        self.by_wtxid.insert(e.wtxid, txid);
        self.entries.insert(txid, e);
        // Children accepted while we were confirmed (reorg re-accept).
        for (vout, _) in tx.output.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            let Some(child_id) = self.conflicts.get(&op).copied() else {
                continue;
            };
            if child_id == txid {
                continue;
            }
            if let Some(ce) = self.entries.get_mut(&child_id) {
                ce.parents.insert(txid);
            }
            if let Some(pe) = self.entries.get_mut(&txid) {
                pe.children.insert(child_id);
            }
            self.spends.insert(op, child_id);
        }
        self.index_cluster_of(&txid);
    }

    /// Remove a tx and unlink edges. Returns the removed entry if present.
    pub fn remove(&mut self, txid: &Txid, tx: &Transaction) -> Option<TxEntry> {
        self.invalidate_chunk_cache();
        let old_rep = self.cluster_rep(txid);
        let neighbors: Vec<Txid> = self
            .entries
            .get(txid)
            .map(|e| e.parents.iter().chain(e.children.iter()).copied().collect())
            .unwrap_or_default();
        if let Some(r) = old_rep {
            self.drop_cluster_index(r);
        }
        let e = self.entries.remove(txid)?;
        self.total_weight = self.total_weight.saturating_sub(e.weight);
        if self.by_wtxid.get(&e.wtxid) == Some(txid) {
            self.by_wtxid.remove(&e.wtxid);
        }
        for p in &e.parents {
            if let Some(pe) = self.entries.get_mut(p) {
                pe.children.remove(txid);
            }
        }
        for c in &e.children {
            if let Some(ce) = self.entries.get_mut(c) {
                ce.parents.remove(txid);
            }
        }
        for inp in &tx.input {
            if self.spends.get(&inp.previous_output) == Some(txid) {
                self.spends.remove(&inp.previous_output);
            }
            if self.conflicts.get(&inp.previous_output) == Some(txid) {
                self.conflicts.remove(&inp.previous_output);
            }
        }
        for (vout, _) in tx.output.iter().enumerate() {
            self.created.remove(&OutPoint {
                txid: *txid,
                vout: vout as u32,
            });
        }
        for n in neighbors {
            if self.entries.contains_key(&n) {
                if let Some(r) = self.cluster_rep(&n) {
                    self.drop_cluster_index(r);
                }
                self.index_cluster_of(&n);
            }
        }
        Some(e)
    }

    /// Membership walk from `start`. Marks every visited tx in `seen`.
    /// Representative is the least txid in the component. Does not linearize.
    #[doc(hidden)]
    pub fn component_rep(&self, start: Txid, seen: &mut BTreeSet<Txid>) -> Option<Txid> {
        if !self.entries.contains_key(&start) {
            return None;
        }
        let mut rep = start;
        let mut q = VecDeque::new();
        q.push_back(start);
        seen.insert(start);
        while let Some(cur) = q.pop_front() {
            rep = rep.min(cur);
            let Some(e) = self.entries.get(&cur) else {
                continue;
            };
            for n in e.parents.iter().chain(e.children.iter()) {
                if seen.insert(*n) {
                    q.push_back(*n);
                }
            }
        }
        Some(rep)
    }

    /// One membership walk from every seed. Weight sum of the union.
    pub fn connected_weight(&self, seeds: &BTreeSet<Txid>) -> (usize, u64) {
        self.connected_weight_except(seeds, &BTreeSet::new())
    }

    /// `connected_weight` that does not enter `except` (RBF conflicts still linked).
    pub fn connected_weight_except(
        &self,
        seeds: &BTreeSet<Txid>,
        except: &BTreeSet<Txid>,
    ) -> (usize, u64) {
        let mut seen = BTreeSet::new();
        let mut q = VecDeque::new();
        for seed in seeds {
            if except.contains(seed) {
                continue;
            }
            if self.entries.contains_key(seed) && seen.insert(*seed) {
                q.push_back(*seed);
            }
        }
        while let Some(cur) = q.pop_front() {
            let Some(e) = self.entries.get(&cur) else {
                continue;
            };
            for n in e.parents.iter().chain(e.children.iter()) {
                if except.contains(n) {
                    continue;
                }
                if seen.insert(*n) {
                    q.push_back(*n);
                }
            }
        }
        let weight = seen
            .iter()
            .filter_map(|t| self.entries.get(t).map(|e| e.weight))
            .sum();
        (seen.len(), weight)
    }

    /// Connected component containing `txid` (undirected parent/child).
    fn component_members(&self, txid: &Txid) -> Option<(BTreeSet<Txid>, u64)> {
        if !self.entries.contains_key(txid) {
            return None;
        }
        let mut members = BTreeSet::new();
        let mut q = VecDeque::new();
        q.push_back(*txid);
        members.insert(*txid);
        while let Some(cur) = q.pop_front() {
            let e = self.entries.get(&cur)?;
            for n in e.parents.iter().chain(e.children.iter()) {
                if members.insert(*n) {
                    q.push_back(*n);
                }
            }
        }
        let total_weight = self.raw_weight_of(&members);
        Some((members, total_weight))
    }

    /// Connected component containing `txid`, chunked on base fee.
    pub fn cluster_of(&self, txid: &Txid) -> Option<Cluster> {
        let (members, total_weight) = self.component_members(txid)?;
        self.cluster_from_members(members, total_weight, |_| 0)
    }

    /// Same as [`Self::cluster_of`] ranking/chunking by `base_fee + delta(txid)`.
    pub fn cluster_of_delta(&self, txid: &Txid, delta: &impl Fn(Txid) -> i64) -> Option<Cluster> {
        let (members, total_weight) = self.component_members(txid)?;
        self.cluster_from_members(members, total_weight, delta)
    }

    #[doc(hidden)]
    pub fn cluster_from_members(
        &self,
        members: BTreeSet<Txid>,
        total_weight: u64,
        delta: impl Fn(Txid) -> i64,
    ) -> Option<Cluster> {
        let linearization = self.linearize_delta(&members, &delta);
        let chunks = self.chunkify_delta(&linearization, &delta);
        Some(Cluster {
            members,
            total_weight,
            linearization,
            chunks,
        })
    }

    /// Whether adding `extra_weight` and `extra_count` txs that connect to
    /// `seed` members would exceed cluster limits. `seed` = parent txids already
    /// in mempool that the new tx spends (+ the new tx itself counts as 1).
    /// Live members count at raw weight (Libre: sigops never shrink the cap).
    pub fn cluster_would_exceed(
        &self,
        parent_txids: &BTreeSet<Txid>,
        extra_count: usize,
        extra_weight: u64,
    ) -> bool {
        let mut members = BTreeSet::new();
        for p in parent_txids {
            if let Some(c) = self.cluster_of(p) {
                members.extend(c.members);
            }
        }
        let base_weight = self.raw_weight_of(&members);
        let count = members.len() + extra_count;
        let vsize = base_weight.saturating_add(extra_weight).saturating_add(3) / 4;
        count > self.cluster_count_limit || vsize > self.cluster_vsize_limit
    }

    /// Topo linearization: among ready txs (parents already emitted or outside
    /// cluster), pick highest fee_rate, then higher fee, then txid.
    #[doc(hidden)]
    pub fn modified_fee(&self, t: &Txid, delta: &impl Fn(Txid) -> i64) -> i64 {
        self.entries
            .get(t)
            .map(|e| e.fee_sat as i64)
            .unwrap_or(0)
            .saturating_add(delta(*t))
    }

    #[doc(hidden)]
    pub fn linearize_delta(
        &self,
        members: &BTreeSet<Txid>,
        delta: &impl Fn(Txid) -> i64,
    ) -> Vec<Txid> {
        let mut remaining: BTreeSet<Txid> = members.clone();
        let mut done: HashSet<Txid> = HashSet::new();
        let mut out = Vec::with_capacity(members.len());
        while !remaining.is_empty() {
            let mut best_rate_fee_txid: Option<(u64, i64, Txid)> = None;
            for t in &remaining {
                let e = match self.entries.get(t) {
                    Some(e) => e,
                    None => continue,
                };
                let ready = e
                    .parents
                    .iter()
                    .all(|p| !members.contains(p) || done.contains(p));
                if !ready {
                    continue;
                }
                let mf = self.modified_fee(t, delta);
                let rate = if mf <= 0 {
                    0
                } else {
                    rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
                        mf as u64,
                        e.adjusted_weight(self.bytes_per_sigop),
                    )
                };
                let key = (rate, mf, *t);
                // Maximize rate, then fee. The walk is txid order, so an equal
                // rate and fee keeps the lesser txid without a third compare.
                let better = match &best_rate_fee_txid {
                    None => true,
                    Some((br, bf, _)) => rate > *br || (rate == *br && mf > *bf),
                };
                if better {
                    best_rate_fee_txid = Some(key);
                }
            }
            let pick = match best_rate_fee_txid {
                Some((_, _, t)) => t,
                None => {
                    // Cycle or bug — emit remaining in txid order.
                    let t = *remaining.iter().next().unwrap();
                    t
                }
            };
            remaining.remove(&pick);
            done.insert(pick);
            out.push(pick);
        }
        out
    }

    /// Split a linearization into prefix-maximal-feerate chunks (Core diagram).
    ///
    /// Each chunk is the longest remaining prefix whose combined feerate is
    /// maximal. A cheap parent plus hot children is one chunk (CPFP); a hot
    /// parent plus a cheap descendant stays split so the parent is not diluted.
    #[doc(hidden)]
    pub fn chunkify_delta(&self, lin: &[Txid], delta: &impl Fn(Txid) -> i64) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        let mut i = 0;
        while i < lin.len() {
            let mut acc_fee = 0i128;
            let mut acc_w = 0u64;
            let mut best_end = i;
            let mut best_fee = 0i128;
            let mut best_w = 0u64;
            for (j, t) in lin.iter().enumerate().skip(i) {
                let Some(e) = self.entries.get(t) else {
                    continue;
                };
                acc_fee = acc_fee.saturating_add(i128::from(self.modified_fee(t, delta)));
                acc_w = acc_w.saturating_add(e.adjusted_weight(self.bytes_per_sigop));
                // acc/acc_w >= best/best_w  (longest prefix on a tie).
                let better = best_w == 0
                    || acc_fee.saturating_mul(i128::from(best_w))
                        >= best_fee.saturating_mul(i128::from(acc_w));
                if better {
                    best_end = j;
                    best_fee = acc_fee;
                    best_w = acc_w;
                }
            }
            chunks.push(Chunk {
                txids: lin[i..=best_end].to_vec(),
                fee_sat: best_fee.max(0) as u64,
                weight: best_w,
            });
            i = best_end + 1;
        }
        chunks
    }

    /// All mining chunks across clusters, **best feerate first** (inclusion frontier).
    ///
    /// Used for fee estimation and future block-template ranking. CPFP packages
    /// appear as single chunks with combined fee/weight.
    pub fn mining_chunks_best_first(&self) -> Vec<Chunk> {
        {
            let g = self.chunk_cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = g.as_ref() {
                return c.clone();
            }
        }
        let mut seen = HashSet::new();
        let mut chunks = Vec::new();
        for txid in self.entries.keys() {
            if seen.contains(txid) {
                continue;
            }
            let Some(c) = self.cluster_of(txid) else {
                continue;
            };
            for m in &c.members {
                seen.insert(*m);
            }
            chunks.extend(c.chunks);
        }
        sort_chunks_best_first(&mut chunks);
        *self.chunk_cache.lock().unwrap_or_else(|p| p.into_inner()) = Some(chunks.clone());
        chunks
    }

    /// Mining chunks under `prioritisetransaction` deltas.
    ///
    /// No nonzero delta reuses [`Self::mining_chunks_best_first`]. A cluster
    /// with a nonzero delta is linearised on `base + delta`; every other
    /// cluster keeps its cached base-fee chunk. Fee estimation keeps reading
    /// the unmodified cache.
    pub fn mining_chunks_for_delta(&self, delta: &impl Fn(Txid) -> i64) -> Vec<Chunk> {
        let mut pending: Vec<Txid> = self
            .entries
            .keys()
            .copied()
            .filter(|id| delta(*id) != 0)
            .collect();
        if pending.is_empty() {
            return self.mining_chunks_best_first();
        }
        let mut touched = HashSet::new();
        let mut clusters = Vec::new();
        while let Some(id) = pending.pop() {
            if touched.contains(&id) {
                continue;
            }
            let Some((members, total_weight)) = self.component_members(&id) else {
                continue;
            };
            for member in &members {
                touched.insert(*member);
            }
            clusters.push((members, total_weight));
        }
        let mut chunks: Vec<Chunk> = self
            .mining_chunks_best_first()
            .into_iter()
            .filter(|ch| ch.txids.iter().all(|id| !touched.contains(id)))
            .collect();
        for (members, total_weight) in clusters {
            let Some(cluster) = self.cluster_from_members(members, total_weight, delta) else {
                continue;
            };
            chunks.extend(cluster.chunks);
        }
        sort_chunks_best_first(&mut chunks);
        chunks
    }

    /// Consensus max block weight (WU).
    pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
    /// Core `DEFAULT_BLOCK_RESERVED_WEIGHT` (coinbase / witness reserved).
    pub const DEFAULT_BLOCK_RESERVED_WEIGHT: u64 = 8_000;

    /// Weight available for mempool txs in a template / generate block.
    pub const fn template_tx_weight() -> u64 {
        Self::MAX_BLOCK_WEIGHT.saturating_sub(Self::DEFAULT_BLOCK_RESERVED_WEIGHT)
    }

    /// Mining-order txs that fit `budget` (best modified-fee chunks first).
    ///
    /// Chunk boundaries are the linearisation on `base_fee + delta`. A pool
    /// with no nonzero delta reuses the cached base-fee chunks. Empty pool
    /// or zero weight → `[]`. A high-feerate child chunk pulls in
    /// still-unselected in-mempool ancestors so the block is topological.
    /// A chunk (plus those ancestors) that would exceed
    /// `budget.max_weight_wu` or the block sigop limit is skipped; later
    /// chunks are still tried. The limit is 80_000 including
    /// `budget.reserved_sigops`; a total of exactly 80_000 fits.
    /// Chunks whose modified fee is **negative** are skipped. A chunk whose
    /// modified feerate is under `budget.min_sat_kvb` (`-blockmintxfee`) is
    /// skipped whole (Core `BlockAssembler` chunk floor), so a low-fee parent
    /// and its CPFP child go in or out together. `0` admits zero-fee chunks.
    /// A chunk that contains a skipped tx, or that would pull one in as an
    /// ancestor, is left out. Each [`Selected`] carries the base fee (not the
    /// modified fee).
    pub fn select_block_template(
        &self,
        budget: SelectBudget,
        delta: impl Fn(Txid) -> i64,
        skip: impl Fn(&Txid) -> bool,
    ) -> Vec<Selected> {
        let SelectBudget {
            max_weight_wu,
            reserved_sigops,
            min_sat_kvb,
        } = budget;
        if max_weight_wu == 0 {
            return Vec::new();
        }
        let delta = &delta;
        let mut scored: Vec<(u64, u64, Chunk)> = Vec::new();
        for ch in self.mining_chunks_for_delta(delta) {
            let mut mf = 0i128;
            for t in &ch.txids {
                let base = self.entries.get(t).map(|e| e.fee_sat as i128).unwrap_or(0);
                mf = mf.saturating_add(base.saturating_add(i128::from(delta(*t))));
            }
            if mf < 0 || !meets_block_min_feerate(mf, ch.weight, min_sat_kvb) {
                continue;
            }
            let fee = mf as u64;
            let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee, ch.weight);
            scored.push((rate, fee, ch));
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let mut selected = HashSet::new();
        let mut out = Vec::new();
        let mut used = 0u64;
        let mut sigops = reserved_sigops;
        for (_, _, ch) in scored {
            if ch.txids.iter().any(&skip) {
                continue;
            }
            let mut add = Vec::new();
            for t in &ch.txids {
                self.collect_selected_with_ancestors(*t, &selected, &mut add);
            }
            if add.is_empty() || add.iter().any(&skip) {
                continue;
            }
            // `add` holds only unselected txs, so these sums are the exact
            // growth. Saturating: an unknown cost is `u64::MAX` and never fits.
            // Block budget is raw weight; only ranking uses adjusted weight.
            let (extra_w, extra_sigops) = add
                .iter()
                .filter_map(|t| self.entries.get(t))
                .fold((0u64, 0u64), |(w, s), e| {
                    (w.saturating_add(e.weight), s.saturating_add(e.sigop_cost))
                });
            // Core `TestChunkBlockLimits`: skip this chunk, keep trying
            // smaller ones. Consensus allows a cost of exactly 80_000.
            if used.saturating_add(extra_w) > max_weight_wu
                || sigops.saturating_add(extra_sigops) > MAX_BLOCK_SIGOPS_COST
            {
                continue;
            }
            used = used.saturating_add(extra_w);
            sigops = sigops.saturating_add(extra_sigops);
            for t in add {
                selected.insert(t);
                if let Some(e) = self.entries.get(&t) {
                    out.push(Selected {
                        txid: t,
                        fee_sat: e.fee_sat,
                        sigop_cost: e.sigop_cost,
                    });
                }
            }
        }
        out
    }

    #[doc(hidden)]
    pub fn collect_selected_with_ancestors(
        &self,
        txid: Txid,
        already: &HashSet<Txid>,
        out: &mut Vec<Txid>,
    ) {
        if already.contains(&txid) || out.contains(&txid) {
            return;
        }
        if let Some(e) = self.entries.get(&txid) {
            for p in &e.parents {
                if self.entries.contains_key(p) {
                    self.collect_selected_with_ancestors(*p, already, out);
                }
            }
        }
        out.push(txid);
    }

    /// Feerate (sat/kvB) of the chunk that fills cumulative weight `target_wu`
    /// walking best-first. `None` if the pool is empty or thinner than `target_wu`.
    pub fn frontier_feerate_sat_per_kvb(&self, target_wu: u64) -> Option<u64> {
        frontier_feerate_from_chunks(&self.mining_chunks_best_first(), target_wu)
    }

    /// Weight (WU) of chunks with feerate strictly greater than `rate_sat_per_kvb`.
    pub fn weight_above_feerate(&self, rate_sat_per_kvb: u64) -> u64 {
        weight_above_from_chunks(&self.mining_chunks_best_first(), rate_sat_per_kvb)
    }

    /// Lowest fee-rate chunk across all clusters (for P5 eviction). `None` if empty.
    pub fn worst_chunk(&self) -> Option<(Txid, Chunk)> {
        self.worst_chunks
            .iter()
            .next()
            .map(|((_, rep), ch)| (*rep, ch.clone()))
    }

    /// Rebuild helper: clear and re-insert from an ordered list (parents first best-effort).
    pub fn rebuild_from(&mut self, items: Vec<(TxEntry, std::sync::Arc<Transaction>)>) {
        self.invalidate_chunk_cache();
        self.entries.clear();
        self.by_wtxid.clear();
        self.worst_chunks.clear();
        self.worst_rep_rate.clear();
        self.spends.clear();
        self.conflicts.clear();
        self.created.clear();
        self.total_weight = 0;
        let mut pending: BTreeMap<Txid, (TxEntry, std::sync::Arc<Transaction>)> =
            items.into_iter().map(|(e, tx)| (e.txid, (e, tx))).collect();
        let all: HashSet<Txid> = pending.keys().copied().collect();
        while !pending.is_empty() {
            let ready: Vec<Txid> = pending
                .iter()
                .filter(|(_, (_, tx))| {
                    tx.input.iter().all(|i| {
                        let creator = i.previous_output.txid;
                        !all.contains(&creator) || self.entries.contains_key(&creator)
                    })
                })
                .map(|(t, _)| *t)
                .collect();
            let batch = if ready.is_empty() {
                // Cycle — force one.
                vec![*pending.keys().next().unwrap()]
            } else {
                ready
            };
            for t in batch {
                if let Some((e, tx)) = pending.remove(&t) {
                    self.insert(e, &tx);
                }
            }
        }
    }
}
