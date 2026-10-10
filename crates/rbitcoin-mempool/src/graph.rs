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
/// Measured as Σ `get_virtual_size(weight)` over cluster members.
pub const MAX_CLUSTER_VSIZE: u64 = 101_000;
/// Same limit as weight units: 101_000 vB × 4 WU/vB.
///
/// Kept for call sites that sum `tx.weight().to_wu()`; prefer comparing vsize when possible.
/// **Was incorrectly 101_000 WU** (4× too tight) — mainnet logs rejected single ~25–65 kvB txs.
pub const MAX_CLUSTER_WEIGHT: u64 = MAX_CLUSTER_VSIZE * 4;

/// Consensus block sigop cost limit (BIP141 `MAX_BLOCK_SIGOPS_COST`).
pub(crate) const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
/// Sigop cost reserved for the coinbase (Core `node/miner.cpp` `nBlockSigOpsCost = 400`).
pub(crate) const COINBASE_SIGOPS_RESERVE: u64 = 400;
/// Core `DEFAULT_BYTES_PER_SIGOP` (`-bytespersigop`).
pub(crate) const DEFAULT_BYTES_PER_SIGOP: u64 = 20;

/// Core `GetSigOpsAdjustedWeight`: `max(weight, sigop_cost × bytes_per_sigop)`.
///
/// Feerate and cluster-size policy use this; the block weight budget does not.
/// `bytes_per_sigop = 0` disables the adjustment.
pub(crate) fn sigops_adjusted_weight(weight: u64, sigop_cost: u64, bytes_per_sigop: u64) -> u64 {
    weight.max(sigop_cost.saturating_mul(bytes_per_sigop))
}

/// Whether a modified fee meets `-blockmintxfee` on sigop-adjusted weight as
/// a true sat/kvB floor (Core `CFeeRate::GetFee`: `fee * 1000 >= min * vsize`).
/// Zero min admits free chunks.
fn meets_block_min_feerate(modified_sat: i128, adj_weight_wu: u64, min_sat_kvb: u64) -> bool {
    if min_sat_kvb == 0 {
        return true;
    }
    let vsize = adj_weight_wu.saturating_add(3) / 4;
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
    rates: Vec<u64>,
    /// `prefix[i]` is the weight of chunks `0..i`.
    prefix: Vec<u64>,
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
    entries: HashMap<Txid, TxEntry>,
    /// Live wtxid → txid (last insert wins). BIP339 inv must not scan `entries`.
    by_wtxid: HashMap<Wtxid, Txid>,
    /// Mempool-created outpoints spent by another mempool tx.
    spends: HashMap<OutPoint, Txid>,
    /// **All** outpoints spent by live mempool txs (chain UTXOs + mempool), for RBF conflicts.
    conflicts: HashMap<OutPoint, Txid>,
    /// Outputs created by mempool txs: (txid, vout) present while unspent in-mempool.
    created: HashSet<OutPoint>,
    /// Sum of live weights (WU) for eviction budget.
    total_weight: u64,
    /// Best-first chunks; `None` after mutate until next build.
    chunk_cache: Mutex<Option<Vec<Chunk>>>,
    /// Lowest-rate chunk per cluster, ordered by (rate, representative txid).
    worst_chunks: BTreeMap<(u64, Txid), Chunk>,
    /// Representative → rate key into [`Self::worst_chunks`].
    worst_rep_rate: HashMap<Txid, u64>,
    /// Core `-limitclustercount` (default [`MAX_CLUSTER_COUNT`]).
    cluster_count_limit: usize,
    /// Core `-limitclustersize` as vbytes (default [`MAX_CLUSTER_VSIZE`]).
    cluster_vsize_limit: u64,
    /// Same cap in WU (vsize × 4). Kept for call sites that sum weight.
    cluster_weight_limit: u64,
    /// Core `-bytespersigop` (default [`DEFAULT_BYTES_PER_SIGOP`]).
    bytes_per_sigop: u64,
    /// Sigop allowance held back for the block's coinbase/template overhead.
    block_reserved_sigops: u64,
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
    pub(crate) fn set_block_reserved_sigops(&mut self, reserved: u64) {
        self.block_reserved_sigops = reserved;
    }

    pub(crate) fn block_reserved_sigops(&self) -> u64 {
        self.block_reserved_sigops
    }

    fn adjusted_weight_of(&self, txid: &Txid) -> u64 {
        self.entries
            .get(txid)
            .map(|e| e.adjusted_weight(self.bytes_per_sigop))
            .unwrap_or(0)
    }

    /// Σ raw weight of live `set` members (cluster-limit basis).
    fn raw_weight_of(&self, set: &BTreeSet<Txid>) -> u64 {
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

    fn invalidate_chunk_cache(&mut self) {
        *self.chunk_cache.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    fn cluster_rep(&self, txid: &Txid) -> Option<Txid> {
        self.cluster_of(txid)?.members.iter().next().copied()
    }

    fn drop_cluster_index(&mut self, rep: Txid) {
        if let Some(rate) = self.worst_rep_rate.remove(&rep) {
            self.worst_chunks.remove(&(rate, rep));
        }
    }

    fn index_cluster_of(&mut self, txid: &Txid) {
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
    pub(crate) fn set_sigop_cost(&mut self, txid: &Txid, cost: u64) {
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

    fn directed_set(&self, txid: &Txid, parents: bool) -> Option<BTreeSet<Txid>> {
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

    fn set_modified_fee(&self, set: &BTreeSet<Txid>, delta: &impl Fn(Txid) -> i64) -> i64 {
        let mut fee = 0i128;
        for t in set {
            if let Some(e) = self.entries.get(t) {
                fee =
                    fee.saturating_add(i128::from(e.fee_sat).saturating_add(i128::from(delta(*t))));
            }
        }
        fee.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }

    /// Chunk containing `txid` (mining linearization), with modified chunk fee.
    pub fn chunk_of(
        &self,
        txid: &Txid,
        delta: impl Fn(Txid) -> i64,
    ) -> Option<(i64, u64, Vec<Txid>)> {
        let c = self.cluster_of(txid)?;
        for ch in c.chunks {
            if ch.txids.contains(txid) {
                let fee = self.set_modified_fee(&ch.txids.iter().copied().collect(), &delta);
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
    fn set_vsize(&self, set: &BTreeSet<Txid>) -> u64 {
        let mut n = 0u64;
        for t in set {
            if self.entries.contains_key(t) {
                n = n.saturating_add(rbitcoin_consensus::policy::get_virtual_size(
                    self.adjusted_weight_of(t),
                ));
            }
        }
        n
    }

    /// Insert entry and wire parent/child edges. Does **not** enforce cluster limits
    /// (caller checks via [`cluster_of`] after insert, and may remove).
    pub fn insert(&mut self, entry: TxEntry, tx: &Transaction) {
        self.invalidate_chunk_cache();
        let txid = entry.txid;
        let mut seen = BTreeSet::new();
        let mut old_reps = BTreeSet::new();
        for inp in &tx.input {
            let parent = inp.previous_output.txid;
            if !self.created.contains(&inp.previous_output) || seen.contains(&parent) {
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
    fn component_rep(&self, start: Txid, seen: &mut BTreeSet<Txid>) -> Option<Txid> {
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

    /// [`connected_weight`] that does not enter `except` (RBF conflicts still linked).
    pub(crate) fn connected_weight_except(
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
    pub fn cluster_of(&self, txid: &Txid) -> Option<Cluster> {
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
        self.cluster_from_members(members, total_weight, |_| 0)
    }

    /// Same as [`Self::cluster_of`] ranking/chunking by `base_fee + delta(txid)`.
    pub fn cluster_of_delta(&self, txid: &Txid, delta: impl Fn(Txid) -> i64) -> Option<Cluster> {
        let c = self.cluster_of(txid)?;
        let total_weight = c.total_weight;
        self.cluster_from_members(c.members, total_weight, delta)
    }

    fn cluster_from_members(
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
    fn modified_fee(&self, t: &Txid, delta: &impl Fn(Txid) -> i64) -> i64 {
        self.entries
            .get(t)
            .map(|e| e.fee_sat as i64)
            .unwrap_or(0)
            .saturating_add(delta(*t))
    }

    fn linearize_delta(&self, members: &BTreeSet<Txid>, delta: &impl Fn(Txid) -> i64) -> Vec<Txid> {
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
                // Maximize rate, then fee; for equal, smaller txid for stability.
                let better = match &best_rate_fee_txid {
                    None => true,
                    Some((br, bf, bt)) => {
                        rate > *br || (rate == *br && (mf > *bf || (mf == *bf && t < bt)))
                    }
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
    fn chunkify_delta(&self, lin: &[Txid], delta: &impl Fn(Txid) -> i64) -> Vec<Chunk> {
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
        chunks.sort_by(|a, b| {
            b.fee_rate_sat_per_kvb()
                .cmp(&a.fee_rate_sat_per_kvb())
                .then_with(|| b.fee_sat.cmp(&a.fee_sat))
        });
        *self.chunk_cache.lock().unwrap_or_else(|p| p.into_inner()) = Some(chunks.clone());
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

    /// Mining-order txs that fit `budget` (best chunks first), ranking by
    /// `base_fee + delta(txid)`.
    ///
    /// Empty pool or zero weight → `[]`. A high-feerate child chunk pulls in
    /// still-unselected in-mempool ancestors so the block is topological.
    /// A chunk (plus those ancestors) that would exceed
    /// `budget.max_weight_wu` or the block sigop limit is skipped; later
    /// chunks are still tried. The limit is 80_000 including
    /// `budget.reserved_sigops`; a total of exactly 80_000 fits.
    /// Chunks whose modified fee is **negative** are skipped. A chunk whose
    /// modified feerate is under `budget.min_sat_kvb` (`-blockmintxfee`) is
    /// skipped whole (Core `BlockAssembler` chunk floor), so a low-fee parent
    /// and its CPFP child go in or out together. `0` admits zero-fee chunks.
    /// Each [`Selected`] carries the base fee (not the modified fee).
    pub fn select_block_template(
        &self,
        budget: SelectBudget,
        delta: impl Fn(Txid) -> i64,
    ) -> Vec<Selected> {
        let SelectBudget {
            max_weight_wu,
            reserved_sigops,
            min_sat_kvb,
        } = budget;
        if max_weight_wu == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(u64, u64, Chunk)> = Vec::new();
        for ch in self.mining_chunks_best_first() {
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
            let mut add = Vec::new();
            for t in &ch.txids {
                let base = self.entries.get(t).map(|e| e.fee_sat as i128).unwrap_or(0);
                if base.saturating_add(i128::from(delta(*t))) < 0 {
                    continue;
                }
                self.collect_selected_with_ancestors(*t, &selected, &mut add);
            }
            if add.is_empty() {
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

    fn collect_selected_with_ancestors(
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn txid_n(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn make_tx(spend: Option<(Txid, u32)>, n_out: u32, seed: u8) -> Transaction {
        let prev = spend.unwrap_or_else(|| (txid_n(0xee), 0));
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev.0,
                    vout: prev.1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: (0..n_out)
                .map(|i| TxOut {
                    value: Amount::from_sat(1000 + u64::from(i) + u64::from(seed)),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51, seed, i as u8]),
                })
                .collect(),
        }
    }

    fn entry_for(tx: &Transaction, fee: u64, slot: u32) -> TxEntry {
        TxEntry {
            txid: tx.compute_txid(),
            wtxid: tx.compute_wtxid(),
            fee_sat: fee,
            weight: tx.weight().to_wu(),
            sigop_cost: 0,
            slot,
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        }
    }

    #[test]
    fn component_rep_is_the_least_txid() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let pe = entry_for(&parent, 500, 0);
        let pid = pe.txid;
        g.insert(pe, &parent);
        let child = make_tx(Some((pid, 0)), 1, 1);
        let ce = entry_for(&child, 500, 1);
        let cid = ce.txid;
        g.insert(ce, &child);
        let least = pid.min(cid);
        let greater = pid.max(cid);
        assert_ne!(least, greater);
        let mut seen = std::collections::BTreeSet::new();
        assert_eq!(g.component_rep(greater, &mut seen), Some(least));
    }

    #[test]
    fn single_tx_cluster() {
        let mut g = TxGraph::new();
        let tx = make_tx(None, 1, 1);
        let e = entry_for(&tx, 1000, 0);
        let id = e.txid;
        g.insert(e, &tx);
        let (n, _) = g.connected_weight(&std::collections::BTreeSet::from([id]));
        assert_eq!(n, 1);
        let c = g.cluster_of(&id).unwrap();
        assert_eq!(c.members.len(), 1);
        assert_eq!(c.linearization, vec![id]);
        assert_eq!(c.chunks.len(), 1);
    }

    #[test]
    fn wtxid_index_insert_remove_and_loser_collision() {
        let mut g = TxGraph::new();
        let a = make_tx(None, 1, 1);
        let b = make_tx(None, 1, 2);
        let ea = entry_for(&a, 100, 0);
        let eb = entry_for(&b, 100, 1);
        let wa = ea.wtxid;
        let wb = eb.wtxid;
        let ida = ea.txid;
        let idb = eb.txid;
        assert_ne!(wa, wb);
        g.insert(ea, &a);
        g.insert(eb, &b);
        assert!(g.contains_wtxid(&wa));
        assert!(g.contains_wtxid(&wb));
        assert_eq!(g.txid_for_wtxid(&wa), Some(ida));
        assert_eq!(g.txid_for_wtxid(&wb), Some(idb));
        assert!(g.remove(&ida, &a).is_some());
        assert!(!g.contains_wtxid(&wa));
        assert_eq!(g.txid_for_wtxid(&wb), Some(idb));

        let c = make_tx(None, 1, 3);
        let d = make_tx(None, 1, 4);
        let ec = entry_for(&c, 10, 2);
        let mut ed = entry_for(&d, 10, 3);
        let collide = ec.wtxid;
        ed.wtxid = collide;
        let idc = ec.txid;
        let idd = ed.txid;
        g.insert(ec, &c);
        g.insert(ed, &d);
        assert_eq!(g.txid_for_wtxid(&collide), Some(idd), "last insert wins");
        assert!(g.remove(&idc, &c).is_some());
        assert_eq!(
            g.txid_for_wtxid(&collide),
            Some(idd),
            "removing the loser must not drop the winner"
        );
        assert!(g.remove(&idd, &d).is_some());
        assert!(!g.contains_wtxid(&collide));

        let e = make_tx(None, 1, 5);
        let ee = entry_for(&e, 1, 4);
        let we = ee.wtxid;
        g.rebuild_from(vec![(ee, std::sync::Arc::new(e.clone()))]);
        assert_eq!(g.txid_for_wtxid(&we), Some(e.compute_txid()));
        assert!(!g.contains_wtxid(&wb));
    }

    #[test]
    fn stock_above_matches_weight_above_on_best_first_chunks() {
        let chunks = [
            Chunk {
                txids: vec![],
                fee_sat: 5_000,
                weight: 4_000,
            },
            Chunk {
                txids: vec![],
                fee_sat: 1_000,
                weight: 8_000,
            },
            Chunk {
                txids: vec![],
                fee_sat: 100,
                weight: 12_000,
            },
        ];
        let stock = StockAbove::from_best_first(&chunks);
        for rate in [0u64, 99, 100, 101, 999, 1_000, 1_001, 5_000, 5_001] {
            assert_eq!(
                stock.above(rate),
                weight_above_from_chunks(&chunks, rate),
                "rate {rate}"
            );
        }
        assert_eq!(StockAbove::from_best_first(&[]).above(0), 0);
    }

    #[test]
    fn frontier_prefers_high_rate_chunks_and_depth() {
        // Two independent txs: high rate then low rate.
        let mut g = TxGraph::new();
        let a = spend_op([1u8; 32], 50_000, 40_000); // fee 10k, high rate
        let b = spend_op([2u8; 32], 50_000, 49_000); // fee 1k, low rate
        let wa = a.weight().to_wu();
        let wb = b.weight().to_wu();
        g.insert(entry_for(&a, 10_000, 0), &a);
        g.insert(entry_for(&b, 1_000, 1), &b);
        let chunks = g.mining_chunks_best_first();
        assert!(chunks.len() >= 2);
        assert!(chunks[0].fee_rate_sat_per_kvb() >= chunks[1].fee_rate_sat_per_kvb());
        // Small target hits high-rate chunk.
        let r_hi = g.frontier_feerate_sat_per_kvb(1).unwrap();
        let r_deep = g.frontier_feerate_sat_per_kvb(wa + wb).unwrap();
        assert!(r_hi >= r_deep);
        assert!(g.weight_above_feerate(0) >= wa);
        // Shared-slice helpers match full-graph methods (fee snapshot path).
        let ch = g.mining_chunks_best_first();
        assert_eq!(
            frontier_feerate_from_chunks(&ch, 1),
            g.frontier_feerate_sat_per_kvb(1)
        );
        assert!(
            frontier_feerate_from_chunks(&ch, wa + wb + 1).is_none(),
            "under-full target must not use last_chunk as a far-horizon rate"
        );
        assert_eq!(weight_above_from_chunks(&ch, 0), g.weight_above_feerate(0));
        let a2 = g.mining_chunks_best_first();
        let b2 = g.mining_chunks_best_first();
        assert_eq!(a2, b2, "a second walk reuses the cached chunks");
    }

    #[test]
    fn select_block_txids_empty_parent_before_child_and_weight_cap() {
        let g = TxGraph::new();
        assert!(select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0).is_empty());
        assert!(select_ids(&g, budget(0), |_| 0).is_empty());

        let mut g = TxGraph::new();
        let parent = spend_op([1u8; 32], 50_000, 40_000);
        let child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        // Child pays more than parent so its chunk ranks first — still emit parent first.
        g.insert(entry_for(&parent, 1_000, 0), &parent);
        g.insert(entry_for(&child, 10_000, 1), &child);
        let order = select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0);
        assert_eq!(
            order,
            vec![parent.compute_txid(), child.compute_txid()],
            "parent before child even if child chunk is hotter: {order:?}"
        );

        let mut g = TxGraph::new();
        let hi = spend_op([2u8; 32], 50_000, 40_000);
        let lo = spend_op([3u8; 32], 50_000, 49_000);
        let wh = hi.weight().to_wu();
        let wl = lo.weight().to_wu();
        g.insert(entry_for(&hi, 10_000, 0), &hi);
        g.insert(entry_for(&lo, 1_000, 1), &lo);
        let only_hi = select_ids(&g, budget(wh), |_| 0);
        assert_eq!(only_hi, vec![hi.compute_txid()]);
        let both = select_ids(&g, budget(wh.saturating_add(wl)), |_| 0);
        assert_eq!(both, vec![hi.compute_txid(), lo.compute_txid()]);
        assert!(select_ids(&g, budget(wh.saturating_sub(1)), |_| 0).is_empty());

        let hid = hi.compute_txid();
        let lid = lo.compute_txid();
        let depri = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
            if id == hid {
                -10_000
            } else {
                0
            }
        });
        assert_eq!(
            depri,
            vec![lid, hid],
            "zero modified fee stays selectable; hotter lid ranks first"
        );
        let depri_neg = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
            if id == hid {
                -10_001
            } else {
                0
            }
        });
        assert_eq!(depri_neg, vec![lid], "negative modified fee is not mined");
        let bump = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
            if id == lid {
                86 * 100_000_000
            } else {
                0
            }
        });
        assert_eq!(bump[0], lid, "i64-sized delta reorders selection");
        let bumped = g.select_block_template(budget(TxGraph::template_tx_weight()), |id| {
            if id == lid {
                86 * 100_000_000
            } else {
                0
            }
        });
        assert_eq!(bumped[0].fee_sat, 1_000, "selection reports the base fee");

        // Child deprioritised to 0 stays out even when it shares a package with parent.
        let mut g = TxGraph::new();
        let parent = spend_op([4u8; 32], 50_000, 40_000);
        let child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        g.insert(entry_for(&parent, 10_000, 0), &parent);
        g.insert(entry_for(&child, 1_000, 1), &child);
        let cid = child.compute_txid();
        let pid = parent.compute_txid();
        let only_p = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
            if id == cid {
                -1_000
            } else {
                0
            }
        });
        assert_eq!(
            only_p,
            vec![pid, cid],
            "zero-modified child stays selectable with parent"
        );
        let only_p_neg = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
            if id == cid {
                -1_001
            } else {
                0
            }
        });
        assert_eq!(
            only_p_neg,
            vec![pid],
            "negative-modified child is not mined with parent"
        );
    }

    /// Core `TestChunkBlockLimits`: a chunk that would overflow weight is
    /// skipped and later, smaller chunks still fill the block.
    #[test]
    fn select_skips_overweight_chunk_and_continues() {
        let mut g = TxGraph::new();
        let hot = spend_op([5u8; 32], 50_000, 40_000);
        let big = make_tx(Some((txid_n(6), 0)), 40, 6);
        let cold = spend_op([7u8; 32], 50_000, 49_000);
        g.insert(entry_for(&hot, 100_000, 0), &hot);
        g.insert(entry_for(&big, 100_000, 1), &big);
        g.insert(entry_for(&cold, 100, 2), &cold);
        let cap = hot.weight().to_wu() + cold.weight().to_wu();
        assert!(big.weight().to_wu() > cold.weight().to_wu());
        assert_eq!(
            select_ids(&g, budget(cap), |_| 0),
            vec![hot.compute_txid(), cold.compute_txid()]
        );
    }

    /// Sigop budget starts at the caller's reserve. A running cost of
    /// exactly 80_000 fits; a chunk that would pass 80_000 is skipped and a
    /// later, cheaper chunk still fits. Each pick carries the base fee and
    /// sigop cost it was budgeted with.
    #[test]
    fn select_budgets_sigops_skip_and_continue() {
        let heavy = spend_op([8u8; 32], 50_000, 40_000);
        let light = spend_op([9u8; 32], 50_000, 49_000);
        let (hid, lid) = (heavy.compute_txid(), light.compute_txid());
        let pool = |heavy_cost: u64| {
            let mut g = TxGraph::new();
            // Budget only: keep heavy ranked first by raw feerate.
            g.set_bytes_per_sigop(0);
            let mut e = entry_for(&heavy, 10_000, 0);
            e.sigop_cost = heavy_cost;
            g.insert(e, &heavy);
            let mut e = entry_for(&light, 1_000, 1);
            e.sigop_cost = 1;
            g.insert(e, &light);
            g
        };
        let at = |g: &TxGraph, reserved_sigops| {
            let b = SelectBudget {
                reserved_sigops,
                ..budget(TxGraph::template_tx_weight())
            };
            select_ids(g, b, |_| 0)
        };
        let full = |heavy_cost| at(&pool(heavy_cost), COINBASE_SIGOPS_RESERVE);
        assert_eq!(full(79_601), vec![lid], "400 + 79_601 passes 80_000");
        assert_eq!(
            full(79_600),
            vec![hid],
            "400 + 79_600 equals 80_000 and fits"
        );
        assert_eq!(
            full(79_599),
            vec![hid, lid],
            "light's +1 lands on 80_000 and fits"
        );
        assert_eq!(full(u64::MAX), vec![lid], "unknown cost never selected");

        let g = pool(79_598);
        assert_eq!(
            g.select_block_template(budget(TxGraph::template_tx_weight()), |_| 0),
            vec![
                Selected {
                    txid: hid,
                    fee_sat: 10_000,
                    sigop_cost: 79_598
                },
                Selected {
                    txid: lid,
                    fee_sat: 1_000,
                    sigop_cost: 1
                },
            ]
        );
        assert_eq!(at(&g, 402), vec![hid], "a larger reserve drops the tail");
        assert_eq!(at(&g, 403), vec![lid], "skips heavy, still takes light");
        assert_eq!(at(&g, 0), vec![hid, lid]);
    }

    fn budget(max_weight_wu: u64) -> SelectBudget {
        SelectBudget {
            max_weight_wu,
            reserved_sigops: COINBASE_SIGOPS_RESERVE,
            min_sat_kvb: 0,
        }
    }

    fn select_ids(g: &TxGraph, budget: SelectBudget, delta: impl Fn(Txid) -> i64) -> Vec<Txid> {
        g.select_block_template(budget, delta)
            .into_iter()
            .map(|s| s.txid)
            .collect()
    }

    fn spend_op(seed: [u8; 32], _inv: u64, outv: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(seed),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(outv),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn insert_parent_after_child_wires_reorg_edges() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let pid = parent.compute_txid();
        let child = make_tx(Some((pid, 0)), 1, 3);
        let cid = child.compute_txid();
        g.insert(entry_for(&child, 1000, 0), &child);
        assert_eq!(g.graph_stats(&cid).unwrap().ancestorcount, 1);
        g.insert(entry_for(&parent, 1000, 1), &parent);
        assert_eq!(g.graph_stats(&cid).unwrap().ancestorcount, 2);
        assert_eq!(g.graph_stats(&pid).unwrap().descendantcount, 2);
    }

    #[test]
    fn parent_child_same_cluster_linearized() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let pe = entry_for(&parent, 500, 0);
        let pid = pe.txid;
        g.insert(pe, &parent);

        let child = make_tx(Some((pid, 0)), 1, 3);
        let ce = entry_for(&child, 5000, 1); // higher fee rate child
        let cid = ce.txid;
        g.insert(ce, &child);

        let c = g.cluster_of(&pid).unwrap();
        assert_eq!(c.members.len(), 2);
        // Parent must come before child.
        assert_eq!(c.linearization, vec![pid, cid]);

        let ps = g.graph_stats(&pid).unwrap();
        let cs = g.graph_stats(&cid).unwrap();
        assert_eq!(ps.ancestorcount, 1);
        assert_eq!(ps.descendantcount, 2);
        assert_eq!(cs.ancestorcount, 2);
        assert_eq!(cs.descendantcount, 1);
        assert_eq!(cs.ancestorfees, 500 + 5000);
        assert_eq!(ps.descendantfees, 500 + 5000);
        // Hot child pulls the cheap parent into one chunk (CPFP).
        assert_eq!(c.chunks.len(), 1);
        assert_eq!(c.chunks[0].txids, vec![pid, cid]);
    }

    #[test]
    fn graph_stats_size_sums_per_tx_virtual_size() {
        use rbitcoin_consensus::policy::get_virtual_size;
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let mut pe = entry_for(&parent, 500, 0);
        pe.weight = 1;
        let pid = pe.txid;
        g.insert(pe, &parent);
        let child = make_tx(Some((pid, 0)), 1, 3);
        let mut ce = entry_for(&child, 5000, 1);
        ce.weight = 5;
        let cid = ce.txid;
        g.insert(ce, &child);
        let ps = g.graph_stats(&pid).unwrap();
        let cs = g.graph_stats(&cid).unwrap();
        assert_eq!(ps.ancestorsize, get_virtual_size(1));
        assert_eq!(ps.descendantsize, get_virtual_size(1) + get_virtual_size(5));
        assert_eq!(cs.ancestorsize, get_virtual_size(1) + get_virtual_size(5));
        assert_eq!(cs.descendantsize, get_virtual_size(5));
        assert_ne!(ps.descendantsize, (1 + 5) / 4);
    }

    #[test]
    fn diamond_cheap_parent_hot_children_cheap_sink_two_chunks() {
        // a (cheap, 2 outs) → b,c (hot) → d (cheap). Prefix-maximal: [a,b,c] then [d].
        let mut g = TxGraph::new();
        let a = make_tx(None, 2, 1);
        let ae = entry_for(&a, 2_000, 0);
        let aid = ae.txid;
        g.insert(ae, &a);
        let b = make_tx(Some((aid, 0)), 1, 2);
        let be = entry_for(&b, 31_200, 1);
        let bid = be.txid;
        g.insert(be, &b);
        let c = make_tx(Some((aid, 1)), 1, 3);
        let ce = entry_for(&c, 31_200, 2);
        let cid = ce.txid;
        g.insert(ce, &c);
        let d = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: bid, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint { txid: cid, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        g.insert(entry_for(&d, 1_000, 3), &d);
        let did = d.compute_txid();
        let cl = g.cluster_of(&aid).unwrap();
        assert_eq!(cl.members.len(), 4);
        assert_eq!(cl.chunks.len(), 2, "chunks: {:?}", cl.chunks);
        let first: BTreeSet<Txid> = cl.chunks[0].txids.iter().copied().collect();
        assert_eq!(first, [aid, bid, cid].into_iter().collect());
        assert_eq!(cl.chunks[1].txids, vec![did]);
        let (fee, w, txs) = g.chunk_of(&aid, |_| 0).unwrap();
        assert_eq!(fee, 2_000 + 31_200 + 31_200);
        assert_eq!(w, cl.chunks[0].weight);
        assert_eq!(txs.len(), 3);
        let (d_fee, _, d_txs) = g
            .chunk_of(&did, |id| if id == bid { 9_999 } else { 0 })
            .unwrap();
        assert_eq!(d_txs, vec![did]);
        assert_eq!(d_fee, 1_000, "d's chunk fee ignores sibling deltas");
    }

    #[test]
    fn oversize_cluster_detected() {
        let mut g = TxGraph::new();
        // Build a chain of MAX_CLUSTER_COUNT txs.
        let mut prev_id = txid_n(0xee);
        let mut last = txid_n(0);
        for i in 0..MAX_CLUSTER_COUNT {
            let tx = make_tx(Some((prev_id, 0)), 1, i as u8);
            let e = entry_for(&tx, 100, i as u32);
            prev_id = e.txid;
            last = e.txid;
            g.insert(e, &tx);
        }
        let c = g.cluster_of(&last).unwrap();
        assert_eq!(c.members.len(), MAX_CLUSTER_COUNT);
        // New child would exceed count.
        let parents: BTreeSet<Txid> = [last].into_iter().collect();
        assert!(g.cluster_would_exceed(&parents, 1, 100));
    }

    #[test]
    fn cluster_limits_overlay_count() {
        let mut g = TxGraph::new();
        g.set_cluster_limits(Some(1), None);
        let parent = make_tx(None, 1, 1);
        let pe = entry_for(&parent, 100, 0);
        let pid = pe.txid;
        g.insert(pe, &parent);
        let mut parents = BTreeSet::new();
        parents.insert(pid);
        assert!(
            g.cluster_would_exceed(&parents, 1, 400),
            "count limit 1 must reject a child"
        );
        g.set_cluster_limits(Some(2), None);
        assert!(!g.cluster_would_exceed(&parents, 1, 400));
    }

    #[test]
    fn cluster_weight_cap_matches_core_101kvb() {
        // Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 → 101_000 vB → 404_000 WU.
        assert_eq!(MAX_CLUSTER_VSIZE, 101_000);
        assert_eq!(MAX_CLUSTER_WEIGHT, 404_000);
        let g = TxGraph::new();
        let empty = BTreeSet::new();
        // Single-tx 200 kWU (~50 kvB) is under the cap.
        assert!(!g.cluster_would_exceed(&empty, 1, 200_000));
        // Single-tx 405 kWU exceeds (would also fail MAX_STANDARD_TX_WEIGHT=400k).
        assert!(g.cluster_would_exceed(&empty, 1, 405_000));
        // Just over old wrong 101 kWU cap must still be allowed.
        assert!(!g.cluster_would_exceed(&empty, 1, 102_790));
    }

    #[test]
    fn conflict_set_fee_weight_remove_and_worst() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 10);
        let pe = entry_for(&parent, 100, 0);
        let pid = pe.txid;
        g.insert(pe, &parent);

        let child = make_tx(Some((pid, 0)), 1, 11);
        let ce = entry_for(&child, 50, 1);
        let cid = ce.txid;
        g.insert(ce, &child);

        // Missing cluster.
        assert!(g.cluster_of(&txid_n(0xff)).is_none());

        let direct = vec![pid];
        let set = g.conflict_set(&direct);
        assert!(set.contains(&pid));
        assert!(set.contains(&cid));
        let (fee, w) = g.set_fee_weight(&set);
        assert_eq!(fee, 150);
        assert!(w > 0);

        assert!(g.worst_chunk().is_some());

        // Remove child then parent.
        assert!(g.remove(&cid, &child).is_some());
        assert!(!g.contains(&cid));
        assert!(g.remove(&pid, &parent).is_some());
        assert!(g.worst_chunk().is_none());
        assert!(g.remove(&pid, &parent).is_none());
    }

    #[test]
    fn worst_chunk_index_picks_lowest_rate_then_repairs() {
        let mut g = TxGraph::new();
        let cheap = spend_op([1u8; 32], 50_000, 49_000);
        let dear = spend_op([2u8; 32], 50_000, 40_000);
        g.insert(entry_for(&cheap, 1_000, 0), &cheap);
        g.insert(entry_for(&dear, 10_000, 1), &dear);
        let (rep, ch) = g.worst_chunk().expect("non-empty");
        let cheap_id = cheap.compute_txid();
        let dear_id = dear.compute_txid();
        assert_eq!(rep, cheap_id);
        assert_eq!(ch.txids, vec![cheap_id]);
        assert!(g.remove(&cheap_id, &cheap).is_some());
        let (rep2, ch2) = g.worst_chunk().expect("dear remains");
        assert_eq!(rep2, dear_id);
        assert_eq!(ch2.txids, vec![dear_id]);
        let child = make_tx(Some((dear_id, 0)), 1, 9);
        g.insert(entry_for(&child, 1, 2), &child);
        let (rep3, ch3) = g.worst_chunk().expect("merged cluster");
        let members: BTreeSet<Txid> = ch3.txids.iter().copied().collect();
        assert!(members.contains(&dear_id) || rep3 == dear_id.min(child.compute_txid()));
        assert!(g.remove(&child.compute_txid(), &child).is_some());
        let (rep4, _) = g.worst_chunk().expect("split back to dear");
        assert_eq!(rep4, dear_id);
    }

    #[test]
    fn rebuild_from_orders_parents_first() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 20);
        let child = make_tx(Some((parent.compute_txid(), 0)), 1, 21);
        // Deliberately child-first in input list.
        let items = vec![
            (entry_for(&child, 10, 1), std::sync::Arc::new(child.clone())),
            (
                entry_for(&parent, 10, 0),
                std::sync::Arc::new(parent.clone()),
            ),
        ];
        g.rebuild_from(items);
        assert!(g.contains(&parent.compute_txid()));
        assert!(g.contains(&child.compute_txid()));
        let c = g.cluster_of(&parent.compute_txid()).unwrap();
        assert_eq!(c.members.len(), 2);
    }

    /// Core `GetSigOpsAdjustedWeight`: `max(weight, sigop_cost × bytes_per_sigop)`.
    #[test]
    fn adjusted_weight_is_max_of_weight_and_sigop_bytes() {
        let tx = make_tx(None, 1, 1);
        let mut e = entry_for(&tx, 0, 0);
        e.weight = 400;
        e.sigop_cost = 21;
        assert_eq!(e.adjusted_weight(20), 420);
        e.sigop_cost = 19;
        assert_eq!(e.adjusted_weight(20), 400);
        e.sigop_cost = 21;
        assert_eq!(e.adjusted_weight(0), 400, "0 B/sigop disables");
        e.sigop_cost = u64::MAX;
        assert_eq!(e.adjusted_weight(2), u64::MAX);
    }

    /// Chunk feerate, template order and eviction rank on sigop-adjusted size;
    /// re-configuring bytes-per-sigop re-ranks the live set.
    #[test]
    fn chunk_rank_uses_sigop_adjusted_weight() {
        let mut g = TxGraph::new();
        let heavy = spend_op([1u8; 32], 0, 1);
        let light = spend_op([2u8; 32], 0, 2);
        let (hid, lid) = (heavy.compute_txid(), light.compute_txid());
        let mut he = entry_for(&heavy, 2_000, 0);
        he.sigop_cost = 1_000; // 20_000 WU at 20 B/sigop
        g.insert(he, &heavy);
        g.insert(entry_for(&light, 1_000, 1), &light);
        let order = |g: &TxGraph| select_ids(g, budget(TxGraph::template_tx_weight()), |_| 0);
        assert_eq!(order(&g), vec![lid, hid]);
        assert_eq!(g.worst_chunk().unwrap().1.txids, vec![hid]);
        assert_eq!(g.mining_chunks_best_first()[1].weight, 20_000);
        g.set_bytes_per_sigop(0);
        assert_eq!(order(&g), vec![hid, lid]);
        assert_eq!(g.worst_chunk().unwrap().1.txids, vec![lid]);
        assert_eq!(
            g.mining_chunks_best_first()[0].weight,
            heavy.weight().to_wu()
        );
    }

    #[test]
    fn block_min_fee_matches_core_getfee() {
        // 200 vB paying 1 sat meets 1 sat/kvB (1e3 >= 200) and any zero floor.
        assert!(meets_block_min_feerate(1, 800, 1));
        assert!(meets_block_min_feerate(0, 800, 0));
        assert!(!meets_block_min_feerate(0, 800, 1));
        // 250 vB at 1000 sat/kvB needs 250 sat.
        assert!(meets_block_min_feerate(250, 1000, 1000));
        assert!(!meets_block_min_feerate(249, 1000, 1000));
        // 40 sat/kvB on 111 vB (5 sat) must not meet a 50 sat/kvB floor.
        assert!(!meets_block_min_feerate(5, 444, 50));
    }

    /// Core applies `-blockmintxfee` to the chunk feerate: a zero-fee parent
    /// rides in with its CPFP child (never the child alone), and a lone tx is
    /// in at exactly the floor and out one sat/kvB above it.
    #[test]
    fn block_min_fee_floors_whole_chunk() {
        let mut g = TxGraph::new();
        let p = spend_op([0x41u8; 32], 0, 50_000);
        let pid = p.compute_txid();
        let c = make_tx(Some((pid, 0)), 1, 0x42);
        let lone = spend_op([0x43u8; 32], 0, 40_000);
        let lv = lone.weight().to_wu().div_ceil(4);
        g.insert(entry_for(&p, 0, 0), &p);
        g.insert(entry_for(&c, 100_000, 1), &c);
        g.insert(entry_for(&lone, lv, 2), &lone);
        let sel = |min| {
            select_ids(
                &g,
                SelectBudget {
                    min_sat_kvb: min,
                    ..budget(TxGraph::template_tx_weight())
                },
                |_| 0,
            )
        };
        let (cid, lid) = (c.compute_txid(), lone.compute_txid());
        assert_eq!(sel(1_000), vec![pid, cid, lid]);
        assert_eq!(sel(1_001), vec![pid, cid]);
    }

    /// The block weight budget counts raw weight: two sigop-dense txs whose
    /// adjusted weight overflows the cap still both fit on raw weight.
    #[test]
    fn select_weight_budget_is_raw_not_adjusted() {
        let mut g = TxGraph::new();
        let a = spend_op([0x31u8; 32], 0, 1);
        let b = spend_op([0x32u8; 32], 0, 2);
        for (i, tx) in [&a, &b].into_iter().enumerate() {
            let mut e = entry_for(tx, 10_000, i as u32);
            e.sigop_cost = 1_000; // 20_000 WU adjusted, far above raw
            g.insert(e, tx);
        }
        let cap = a.weight().to_wu() + b.weight().to_wu();
        assert!(cap < 20_000);
        assert_eq!(select_ids(&g, budget(cap), |_| 0).len(), 2);
    }

    /// Post-migrate recompute: filling an unknown (`u64::MAX`) cost re-ranks
    /// the cluster, so eviction and mining see the real feerate.
    #[test]
    fn set_sigop_cost_reranks_cluster() {
        let mut g = TxGraph::new();
        let rich = spend_op([3u8; 32], 0, 1);
        let poor = spend_op([4u8; 32], 0, 2);
        let (rid, pid) = (rich.compute_txid(), poor.compute_txid());
        let mut re = entry_for(&rich, 100_000, 0);
        re.sigop_cost = u64::MAX;
        g.insert(re, &rich);
        g.insert(entry_for(&poor, 100, 1), &poor);
        assert_eq!(g.worst_chunk().unwrap().1.txids, vec![rid]);
        assert_eq!(
            select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0),
            vec![pid]
        );
        g.set_sigop_cost(&rid, 0);
        assert_eq!(g.worst_chunk().unwrap().1.txids, vec![pid]);
        assert_eq!(
            select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0),
            vec![rid, pid]
        );
    }

    /// Core `mempool_sigoplimit.py`: ancestor/descendant sizes sum the
    /// sigop-adjusted vsize.
    #[test]
    fn graph_stats_sizes_use_sigop_adjusted_vsize() {
        use rbitcoin_consensus::policy::get_virtual_size;
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let pid = parent.compute_txid();
        let child = make_tx(Some((pid, 0)), 1, 3);
        let cid = child.compute_txid();
        let pv = get_virtual_size(parent.weight().to_wu());
        g.insert(entry_for(&parent, 500, 0), &parent);
        let mut ce = entry_for(&child, 500, 1);
        ce.sigop_cost = 69; // 1_380 WU → 345 vB
        g.insert(ce, &child);
        let cs = g.graph_stats(&cid).unwrap();
        assert_eq!((cs.ancestorsize, cs.descendantsize), (pv + 345, 345));
        let ps = g.graph_stats(&pid).unwrap();
        assert_eq!((ps.ancestorsize, ps.descendantsize), (pv, pv + 345));
    }

    /// Libre divergence from Core `test_sigops_package`: cluster limits count
    /// raw weight, so a tx at 50,000 sigop cost (1,000,000 WU adjusted, far
    /// past 101 kvB) still takes a child; only feerate uses adjusted size.
    #[test]
    fn cluster_limits_use_raw_weight() {
        let mut g = TxGraph::new();
        let parent = make_tx(None, 1, 2);
        let pid = parent.compute_txid();
        let mut pe = entry_for(&parent, 500, 0);
        pe.sigop_cost = 50_000;
        g.insert(pe, &parent);
        let raw = parent.weight().to_wu();
        assert_eq!(g.cluster_of(&pid).unwrap().total_weight, raw);
        assert_eq!(g.mining_chunks_best_first()[0].weight, 1_000_000);
        let parents = BTreeSet::from([pid]);
        assert!(!g.cluster_would_exceed(&parents, 1, 1));
        let room = MAX_CLUSTER_WEIGHT - raw;
        assert!(!g.cluster_would_exceed(&parents, 1, room));
        assert!(g.cluster_would_exceed(&parents, 1, room + 4));
    }
}
