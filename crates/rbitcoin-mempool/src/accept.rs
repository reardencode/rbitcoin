//! Single-tx accept: Libre policy + cluster limits + durable slot write.

use crate::error::MempoolError;
use crate::graph::{TxEntry, TxGraph};
use crate::orphanage::Orphanage;
use crate::store::Mempool;
use bitcoin::consensus::encode::serialize;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use rbitcoin_consensus::policy::{self, PolicyResult};
use std::collections::BTreeSet;
use std::time::Instant;

/// Stage wall times (µs) for one accept attempt (or sum across package/orphan promote).
///
/// Used by tip:perf / microbench harness — not a consensus surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcceptStageUs {
    /// Prevout resolve (mempool graph peek + chain `UtxoProvider`).
    pub utxo_us: u64,
    /// Consensus script verify.
    pub script_us: u64,
    /// Durable slot/body append (coalesced persist when it runs).
    pub durable_us: u64,
}

/// Confirmed-chain unspent coin for mempool accept (content + maturity metadata).
///
/// Presence implies **unspent on the confirmed chain**. Missing/`None` means
/// unknown create or confirmed-strong spent (finding 010).
#[derive(Debug, Clone)]
pub struct Coin {
    pub txout: TxOut,
    /// Class C create height; `0` if unknown (BIP68 fail-closed when needed).
    pub create_height: u32,
    /// MTP of the block *before* the create block (BIP68 time locks). `0` if unknown.
    pub create_mtp: u32,
    pub is_coinbase: bool,
}

/// Tip snapshot for structural checks (finality / maturity / BIP68).
///
/// `height` is the **confirmed tip** height; absolute finality uses `height + 1`
/// as the next block height (Core mempool convention).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainTipCtx {
    pub height: u32,
    /// BIP113 median time past of the tip (locktime cutoff for time-form nLockTime).
    pub mtp: u32,
}

/// Resolve prevouts for mempool acceptance (chain UTXO + in-mempool outputs).
pub trait UtxoProvider {
    /// Unspent confirmed coin, or `None` if missing/spent on the confirmed chain.
    fn get_coin(&self, op: &OutPoint) -> Option<Coin>;

    fn get_txout(&self, op: &OutPoint) -> Option<TxOut> {
        self.get_coin(op).map(|c| c.txout)
    }

    /// Spender about to resolve coins (BIP68 time-lock MTP only when needed).
    fn note_spender(&self, _tx: &Transaction) {}
}

/// Map-backed provider for tests and simple callers.
pub struct MapUtxoProvider {
    pub map: std::collections::HashMap<OutPoint, Coin>,
}

impl MapUtxoProvider {
    /// Insert bare outputs as non-coinbase coins at height 0 (legacy test helper).
    pub fn from_txouts(map: std::collections::HashMap<OutPoint, TxOut>) -> Self {
        Self {
            map: map
                .into_iter()
                .map(|(op, txout)| {
                    (
                        op,
                        Coin {
                            txout,
                            create_height: 0,
                            create_mtp: 0,
                            is_coinbase: false,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl UtxoProvider for MapUtxoProvider {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        self.map.get(op).cloned()
    }
}

/// Max txs in one ancestor package (Core-class package limit).
pub const MAX_PACKAGE_COUNT: usize = 25;
/// Max total weight (WU) of one package.
pub const MAX_PACKAGE_WEIGHT: u64 = 404_000;
/// Default mempool weight budget (WU) — ~75 MvB class; eviction by worst chunk.
pub const DEFAULT_MAX_MEMPOOL_WEIGHT: u64 = 300_000_000;
/// Incremental relay feerate for RBF (same as Libre min: 0.1 sat/vB = 100 sat/kvB).
pub const INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB: u64 = 100;
/// Pure replace-by-fee-rate ratio (Libre Relay v27.1+): **1.25×** = 5/4.
pub const RBFR_RATIO_NUM: u64 = 5;
pub const RBFR_RATIO_DEN: u64 = 4;

/// Outcome of a successful accept.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    pub txid: Txid,
    pub fee_sat: u64,
    pub weight: u64,
    pub slot: u32,
    /// Mempool txids removed by full-RBF / RBFR when admitting this tx (empty if no conflict).
    pub replaced: Vec<Txid>,
    /// Electrum scripthashes (SHA256 of output scriptPubKeys) of **replaced** bodies,
    /// collected **before** RBF removal so wallet address tracks can drop zombie unconfs
    /// even when the old body is gone from the hub.
    pub replaced_scripthashes: Vec<[u8; 32]>,
}

/// Why accept failed (policy / graph / durable / consensus script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    Policy(&'static str),
    MissingPrevout(OutPoint),
    /// Tx parked in the orphanage waiting on missing parent(s). Not a hard reject.
    Orphaned(Txid),
    Duplicate(Txid),
    ClusterTooLarge {
        count: usize,
        weight: u64,
    },
    PackageTooLarge {
        count: usize,
        weight: u64,
    },
    PackageEmpty,
    PackageNotTopo,
    /// Conflicting mempool txs exist and replacement does not pay enough.
    RbfInsufficient,
    Coinbase,
    /// Duplicate previous_output within the same transaction (011).
    InputsDuplicate,
    /// Coinbase maturity not met at tip+1 (011).
    ImmatureCoinbase,
    /// Absolute nLockTime / sequence finality not met for next block (011).
    NotFinal,
    /// BIP68 relative lock not satisfied at tip (011).
    NonBip68Final,
    NotFound(Txid),
    Durable(String),
    /// Consensus script verification failed for one or more inputs.
    Script(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Policy(s) => write!(f, "policy: {s}"),
            AcceptError::MissingPrevout(op) => write!(f, "missing prevout {op}"),
            AcceptError::Orphaned(t) => write!(f, "orphaned {t}"),
            AcceptError::Duplicate(t) => write!(f, "duplicate {t}"),
            AcceptError::ClusterTooLarge { .. } => f.write_str("too-large-cluster"),
            AcceptError::PackageTooLarge { count, weight } => {
                write!(f, "package too large count={count} weight={weight}")
            }
            AcceptError::PackageEmpty => f.write_str("package empty"),
            AcceptError::PackageNotTopo => f.write_str("package not topologically ordered"),
            AcceptError::RbfInsufficient => f.write_str("rbf insufficient fee"),
            AcceptError::Coinbase => f.write_str("coinbase"),
            AcceptError::InputsDuplicate => f.write_str("inputs-duplicate"),
            AcceptError::ImmatureCoinbase => f.write_str("coinbase immature"),
            AcceptError::NotFinal => f.write_str("not final"),
            AcceptError::NonBip68Final => f.write_str("non-BIP68-final"),
            AcceptError::NotFound(t) => write!(f, "not found {t}"),
            AcceptError::Durable(s) => write!(f, "durable: {s}"),
            AcceptError::Script(s) => write!(f, "script: {s}"),
        }
    }
}

impl std::error::Error for AcceptError {}

impl From<MempoolError> for AcceptError {
    fn from(e: MempoolError) -> Self {
        match e {
            MempoolError::Full => AcceptError::Policy("mempool full"),
            other => AcceptError::Durable(other.to_string()),
        }
    }
}

/// Maturity, absolute finality (`is_final_tx`), and BIP68 at the next block.
pub fn check_mempool_structural(
    tx: &Transaction,
    chain_coins: &[Option<Coin>],
    tip: ChainTipCtx,
) -> Result<(), AcceptError> {
    let next_height = tip.height.saturating_add(1);
    for c in chain_coins.iter().flatten() {
        if c.is_coinbase && next_height < c.create_height.saturating_add(100) {
            return Err(AcceptError::ImmatureCoinbase);
        }
    }
    if !rbitcoin_consensus::is_final_tx(tx, next_height, tip.mtp) {
        return Err(AcceptError::NotFinal);
    }
    if rbitcoin_consensus::bip68_active_for_tx(tx) {
        let mut prev_heights = Vec::with_capacity(tx.input.len());
        let mut prev_mtps = Vec::with_capacity(tx.input.len());
        for (i, inp) in tx.input.iter().enumerate() {
            let seq = inp.sequence.to_consensus_u32();
            let lock_enabled = seq & (1u32 << 31) == 0;
            match chain_coins.get(i).and_then(|c| c.as_ref()) {
                Some(c) => {
                    // Unknown create height with an active relative lock → fail closed.
                    if lock_enabled && c.create_height == 0 && !c.is_coinbase {
                        return Err(AcceptError::NonBip68Final);
                    }
                    prev_heights.push(c.create_height);
                    prev_mtps.push(c.create_mtp);
                }
                None => {
                    // Mempool parent: treat as created at next_height (unconfirmed).
                    prev_heights.push(next_height);
                    prev_mtps.push(tip.mtp);
                }
            }
        }
        if !rbitcoin_consensus::sequence_locks_satisfied(
            tx,
            &prev_heights,
            &prev_mtps,
            next_height,
            tip.mtp,
        ) {
            return Err(AcceptError::NonBip68Final);
        }
    }
    Ok(())
}

/// Run consensus script verification for every input (mempool / tip height assumed
/// post-all-softforks: BIP16/65/66/112 active).
///
/// Always uses the shared `rbtc-scripts` detached path (same family as IBD
/// confirm) so the caller stack — peer session or tokio — never runs the
/// interpreter.
fn verify_tx_scripts(tx: &Transaction, prevouts: Vec<TxOut>) -> Result<(), AcceptError> {
    if prevouts.len() != tx.input.len() {
        return Err(AcceptError::Script("prevout count mismatch".into()));
    }
    rbitcoin_consensus::verify_tx_scripts_detached(prevouts, tx.clone())
        .map_err(|e| AcceptError::Script(e.to_string()))
}

/// Result of accept prepare (resolve + policy + structural), before script verify.
///
/// Script runs outside the mempool exclusive lock; [`ActiveMempool::commit_after_script`]
/// re-checks and durable-commits.
#[derive(Debug, Clone)]
pub struct PreparedAdmit {
    pub fee_sat: u64,
    /// `prioritisetransaction` delta applied at prepare (min-relay / RBF).
    pub fee_delta: i64,
    pub weight: u64,
    pub prevouts: Vec<TxOut>,
    pub chain_coins: Vec<Option<Coin>>,
    pub parent_txids: BTreeSet<Txid>,
    pub direct_conflicts: BTreeSet<Txid>,
    pub utxo_us: u64,
}

/// Mempool with RAM TxGraph layered on durable store.
pub struct ActiveMempool {
    pub store: Mempool,
    pub graph: TxGraph,
    /// Cached tx bodies for graph rebuild / remove (live set only).
    bodies: std::collections::HashMap<Txid, Transaction>,
    /// Evict worst chunks when live weight exceeds this.
    pub max_weight: u64,
    /// Side pool of txs waiting on missing parents (Core-class weight budget).
    pub orphanage: Orphanage,
    /// Stage µs for the most recent top-level [`Self::accept_tx`] / package member
    /// (includes nested orphan promote for that accept). Sampled by MempoolHub.
    pub last_accept_stages: AcceptStageUs,
    /// Overlay from `-limitclustercount` / `-limitclustersize` (re-applied after compact).
    cluster_count_overlay: Option<u32>,
    cluster_size_kvb_overlay: Option<u32>,
    /// Core `-minrelaytxfee` in sat/kvB (default Libre 100).
    min_relay_sat_kvb: u64,
}

impl ActiveMempool {
    pub fn open_or_create(dir: impl Into<std::path::PathBuf>) -> Result<Self, MempoolError> {
        Self::open_or_create_with_limit(dir, DEFAULT_MAX_MEMPOOL_WEIGHT)
    }

    pub fn open_or_create_with_limit(
        dir: impl Into<std::path::PathBuf>,
        max_weight: u64,
    ) -> Result<Self, MempoolError> {
        Self::open_with_limit_persist(dir, max_weight, true)
    }

    /// Overlay Core `-limitclustercount` / `-limitclustersize`.
    pub fn set_cluster_limits(&mut self, count: Option<u32>, size_kvb: Option<u32>) {
        if count.is_some() {
            self.cluster_count_overlay = count;
        }
        if size_kvb.is_some() {
            self.cluster_size_kvb_overlay = size_kvb;
        }
        self.graph.set_cluster_limits(count, size_kvb);
    }

    /// Overlay Core `-minrelaytxfee` (sat/kvB). `0` admits any non-negative fee.
    pub fn set_min_relay_sat_kvb(&mut self, sat_kvb: u64) {
        self.min_relay_sat_kvb = sat_kvb;
    }

    pub fn min_relay_sat_kvb(&self) -> u64 {
        self.min_relay_sat_kvb
    }

    /// `persist=false` abandons any on-disk live set (Core `-persistmempool=0`).
    pub fn open_with_limit_persist(
        dir: impl Into<std::path::PathBuf>,
        max_weight: u64,
        persist: bool,
    ) -> Result<Self, MempoolError> {
        let mut store = Mempool::open_or_create(dir)?;
        if !persist {
            store.abandon_live()?;
        }
        let loaded = store.load_live_txs()?;
        let mut graph = TxGraph::new();
        let mut bodies = std::collections::HashMap::new();
        let mut items = Vec::with_capacity(loaded.len());
        for (slot, fee_sat, weight, tx) in loaded {
            let txid = tx.compute_txid();
            let entry = TxEntry {
                txid,
                wtxid: tx.compute_wtxid(),
                fee_sat,
                weight,
                slot,
                parents: BTreeSet::new(),
                children: BTreeSet::new(),
            };
            bodies.insert(txid, tx.clone());
            items.push((entry, tx));
        }
        graph.rebuild_from(items);
        store.set_live_count(graph.len() as u32);
        Ok(Self {
            store,
            graph,
            bodies,
            max_weight,
            orphanage: Orphanage::new(),
            last_accept_stages: AcceptStageUs::default(),
            cluster_count_overlay: None,
            cluster_size_kvb_overlay: None,
            min_relay_sat_kvb: rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
        })
    }

    pub fn live_count(&self) -> usize {
        self.graph.len()
    }

    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    pub fn flush(&mut self) -> Result<(), MempoolError> {
        self.store.flush()
    }

    /// Best-effort sidecar persist of dirty accepts (no generation bump).
    pub fn persist_if_dirty(&mut self) -> Result<(), MempoolError> {
        self.store.persist_if_dirty()
    }

    /// Compact durable storage (drop DEAD holes) and rebuild RAM graph.
    pub fn compact(&mut self) -> Result<(u32, usize), MempoolError> {
        let (live, body_len) = self.store.compact()?;
        let loaded = self.store.load_live_txs()?;
        let mut graph = TxGraph::new();
        let mut bodies = std::collections::HashMap::new();
        let mut items = Vec::with_capacity(loaded.len());
        for (slot, fee_sat, weight, tx) in loaded {
            let txid = tx.compute_txid();
            let entry = TxEntry {
                txid,
                wtxid: tx.compute_wtxid(),
                fee_sat,
                weight,
                slot,
                parents: BTreeSet::new(),
                children: BTreeSet::new(),
            };
            bodies.insert(txid, tx.clone());
            items.push((entry, tx));
        }
        graph.rebuild_from(items);
        graph.set_cluster_limits(self.cluster_count_overlay, self.cluster_size_kvb_overlay);
        self.graph = graph;
        self.bodies = bodies;
        self.store.set_live_count(live);
        Ok((live, body_len))
    }

    /// Compact when DEAD slots are a large fraction of capacity (file growth bound).
    pub fn maybe_compact(&mut self) -> Result<Option<(u32, usize)>, MempoolError> {
        let (_free, live, dead) = self.store.slot_stats();
        if dead == 0 {
            return Ok(None);
        }
        let cap = self.store.meta().slot_cap;
        if dead * 4 >= cap || (live > 0 && dead >= live) || (live == 0 && dead > 0) {
            return Ok(Some(self.compact()?));
        }
        Ok(None)
    }

    /// Accept a single transaction under Libre policy + cluster limits.
    ///
    /// Durable order: write body → LIVE slot → RAM graph. Call [`flush`] to
    /// bump generation so a crash keeps the batch.
    ///
    /// When prevouts are missing from both mempool and chain UTXO, the tx is
    /// parked in the [`Orphanage`] (Core-class weight budget) and
    /// [`AcceptError::Orphaned`] is returned — not a hard peer reject.
    ///
    /// `tip` is the confirmed tip for maturity / `is_final_tx` / BIP68 (next block
    /// height = `tip.height + 1`, BIP113 cutoff = `tip.mtp`).
    pub fn accept_tx(
        &mut self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        self.last_accept_stages = AcceptStageUs::default();
        let prep = match self.prepare_admit(tx, utxos, tip, 0, true) {
            Ok(p) => p,
            Err(AcceptError::Orphaned(_)) => return Err(self.park_orphan(tx)),
            Err(e) => return Err(e),
        };
        self.last_accept_stages.utxo_us = prep.utxo_us;
        let t_script = Instant::now();
        let script_res = verify_tx_scripts(tx, prep.prevouts.clone());
        self.last_accept_stages.script_us = self
            .last_accept_stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        script_res?;
        let r = self.commit_after_script(tx, prep, tip)?;
        self.promote_orphans_of(r.txid, utxos, tip);
        Ok(r)
    }

    /// Graph peek + UTXO resolve (`&self`: callers may hold a read lock).
    /// Does not park orphans; [`Self::park_orphan`] does that under write.
    pub fn prepare_admit(
        &self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        fee_delta: i64,
        park_orphans: bool,
    ) -> Result<PreparedAdmit, AcceptError> {
        if tx.is_coinbase() {
            return Err(AcceptError::Coinbase);
        }
        let txid = tx.compute_txid();
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == tx.compute_wtxid() {
                return Err(AcceptError::Duplicate(txid));
            }
            // Same txid, different witness (Core testmempoolaccept /
            // mempool_accept_wtxid.py).
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        // Already parked: soft re-announce of the same orphan.
        if self.orphanage.contains(&txid) {
            return Err(AcceptError::Orphaned(txid));
        }

        // Finding 011: duplicate inputs before any value sum (phantom fee).
        {
            let mut seen = BTreeSet::new();
            for inp in &tx.input {
                if !seen.insert(inp.previous_output) {
                    return Err(AcceptError::InputsDuplicate);
                }
            }
        }

        let t_utxo = Instant::now();
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(tx.input.len());
        let mut chain_coins: Vec<Option<Coin>> = Vec::with_capacity(tx.input.len());
        let mut parent_txids = BTreeSet::new();
        let mut direct_conflicts: BTreeSet<Txid> = BTreeSet::new();
        let mut missing_parents: BTreeSet<Txid> = BTreeSet::new();
        let mut input_value = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if let Some(c) = self.graph.conflict_txid(&op) {
                if c != txid {
                    direct_conflicts.insert(c);
                }
            }
            let (txout, chain_coin) = if let Some(creator) = self.graph.creator(&op) {
                if !self.graph.mempool_utxo(&op) {
                    // Spent in-mempool — must RBF the conflict set.
                    if let Some(c) = self.graph.conflict_txid(&op) {
                        direct_conflicts.insert(c);
                    } else {
                        return Err(AcceptError::Policy("mempool double-spend"));
                    }
                }
                parent_txids.insert(creator);
                let parent_tx = self
                    .bodies
                    .get(&creator)
                    .ok_or(AcceptError::Durable("parent body missing".into()))?;
                match parent_tx.output.get(op.vout as usize).cloned() {
                    Some(o) => (o, None),
                    None => {
                        missing_parents.insert(op.txid);
                        continue;
                    }
                }
            } else if let Some(coin) = utxos.get_coin(&op) {
                // Confirmed unspent only — spent/missing create → None (finding 010).
                (coin.txout.clone(), Some(coin))
            } else {
                missing_parents.insert(op.txid);
                continue;
            };
            input_value = input_value.saturating_add(txout.value.to_sat());
            prevouts.push(txout);
            chain_coins.push(chain_coin);
        }
        let utxo_us = t_utxo.elapsed().as_micros() as u64;

        if !missing_parents.is_empty() {
            if park_orphans {
                return Err(AcceptError::Orphaned(txid));
            }
            return Err(AcceptError::MissingPrevout(tx.input[0].previous_output));
        }

        check_mempool_structural(tx, &chain_coins, tip)?;

        let mut output_value = 0u64;
        for o in &tx.output {
            let v = o.value.to_sat();
            output_value = output_value
                .checked_add(v)
                .ok_or(AcceptError::Policy("bad-txns-txouttotal-toolarge"))?;
        }
        if output_value > input_value {
            return Err(AcceptError::Policy("negative fee"));
        }
        let fee_sat = input_value - output_value;
        let weight = tx.weight().to_wu();
        let admit_fee = (i128::from(fee_sat).saturating_add(i128::from(fee_delta))).max(0) as u64;

        match policy::check_libre_admission_at(tx, admit_fee, weight, self.min_relay_sat_kvb) {
            PolicyResult::Standard => {}
            PolicyResult::NonStandard(s) => return Err(AcceptError::Policy(s)),
        }

        Ok(PreparedAdmit {
            fee_sat,
            fee_delta,
            weight,
            prevouts,
            chain_coins,
            parent_txids,
            direct_conflicts,
            utxo_us,
        })
    }

    /// Park `tx` in the orphanage (write-lock caller). Graph-only: any input
    /// not created in-mempool is a missing parent (no chain UTXO lookup).
    pub fn park_orphan(&mut self, tx: &Transaction) -> AcceptError {
        let txid = tx.compute_txid();
        if self.graph.get(&txid).is_some() {
            return AcceptError::Duplicate(txid);
        }
        if self.orphanage.contains(&txid) {
            return AcceptError::Orphaned(txid);
        }
        let mut missing = BTreeSet::new();
        for inp in &tx.input {
            let op = inp.previous_output;
            if self.graph.creator(&op).is_some() {
                continue;
            }
            missing.insert(op.txid);
        }
        if missing.is_empty() {
            return AcceptError::MissingPrevout(tx.input[0].previous_output);
        }
        if self.orphanage.insert(tx.clone(), missing) {
            AcceptError::Orphaned(txid)
        } else {
            AcceptError::MissingPrevout(tx.input[0].previous_output)
        }
    }

    /// Take orphans waiting on `parent` (hub promote outside the write lock).
    pub fn take_orphan_children(&mut self, parent: Txid) -> Vec<Transaction> {
        self.orphanage.take_children_of(&parent)
    }

    /// Drop orphans that are themselves in `block_txids`.
    pub fn erase_orphans_for_block(&mut self, block_txids: &[Txid]) {
        self.orphanage.erase_for_block(block_txids);
    }

    /// Re-check + RBF + durable insert after scripts verified off-lock.
    ///
    /// Fail closed on race (duplicate, conflict set changed, parent gone).
    /// Chain coins come from `prep` (resolved under read); no UTXO provider.
    pub fn commit_after_script(
        &mut self,
        tx: &Transaction,
        prep: PreparedAdmit,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        let (conflict_set, fee_sat, weight) = self.plan_after_script(tx, prep, tip)?;
        let txid = tx.compute_txid();

        let mut replaced_scripthashes: Vec<[u8; 32]> = Vec::new();
        for c in &conflict_set {
            if let Some(old_tx) = self.bodies.get(c) {
                for o in &old_tx.output {
                    replaced_scripthashes
                        .push(Self::electrum_scripthash(o.script_pubkey.as_bytes()));
                }
            }
        }
        replaced_scripthashes.sort_unstable();
        replaced_scripthashes.dedup();

        for c in conflict_set.iter().rev() {
            let _ = self.remove_txid(c);
        }

        self.ensure_free_slot(Some(txid))?;

        let raw = serialize(tx);
        let t_dur = Instant::now();
        let slot = self.store.append_live_tx(&raw, &txid, fee_sat, weight)?;
        self.last_accept_stages.durable_us = self
            .last_accept_stages
            .durable_us
            .saturating_add(t_dur.elapsed().as_micros() as u64);

        let entry = TxEntry {
            txid,
            wtxid: tx.compute_wtxid(),
            fee_sat,
            weight,
            slot,
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        };
        self.graph.insert(entry, tx);
        self.bodies.insert(txid, tx.clone());

        if let Some(c) = self.graph.cluster_of(&txid) {
            if c.members.len() > self.graph.cluster_count_limit()
                || c.total_weight.saturating_add(3) / 4 > self.graph.cluster_vsize_limit()
            {
                self.graph.remove(&txid, tx);
                self.bodies.remove(&txid);
                let _ = self.store.mark_slot_dead(slot);
                return Err(AcceptError::ClusterTooLarge {
                    count: c.members.len(),
                    weight: c.total_weight,
                });
            }
        }

        self.evict_to_budget(Some(txid))?;

        Ok(AcceptResult {
            txid,
            fee_sat,
            weight,
            slot,
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes,
        })
    }

    /// Prepare + RBF/cluster checks with no graph or store mutation.
    pub fn evaluate_after_script(
        &self,
        tx: &Transaction,
        prep: PreparedAdmit,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        let (conflict_set, fee_sat, weight) = self.plan_after_script(tx, prep, tip)?;
        Ok(AcceptResult {
            txid: tx.compute_txid(),
            fee_sat,
            weight,
            slot: 0,
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes: Vec::new(),
        })
    }

    fn plan_after_script(
        &self,
        tx: &Transaction,
        prep: PreparedAdmit,
        tip: ChainTipCtx,
    ) -> Result<(BTreeSet<Txid>, u64, u64), AcceptError> {
        let _ = tip;
        let txid = tx.compute_txid();
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == tx.compute_wtxid() {
                return Err(AcceptError::Duplicate(txid));
            }
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        if self.orphanage.contains(&txid) {
            return Err(AcceptError::Orphaned(txid));
        }

        let mut direct_conflicts = BTreeSet::new();
        let mut parent_txids = BTreeSet::new();
        for (i, inp) in tx.input.iter().enumerate() {
            let op = inp.previous_output;
            if let Some(c) = self.graph.conflict_txid(&op) {
                if c != txid {
                    direct_conflicts.insert(c);
                }
            }
            if let Some(creator) = self.graph.creator(&op) {
                if !self.graph.mempool_utxo(&op) {
                    if let Some(c) = self.graph.conflict_txid(&op) {
                        direct_conflicts.insert(c);
                    } else {
                        return Err(AcceptError::Policy("mempool double-spend"));
                    }
                }
                parent_txids.insert(creator);
                if self.bodies.get(&creator).is_none() {
                    return Err(AcceptError::Durable("parent body missing".into()));
                }
            } else if prep.chain_coins.get(i).and_then(|c| c.as_ref()).is_none() {
                return Err(AcceptError::MissingPrevout(op));
            }
        }
        let _ = prep.direct_conflicts;
        let _ = prep.parent_txids;

        let fee_sat = prep.fee_sat;
        let weight = prep.weight;
        let admit_fee =
            (i128::from(fee_sat).saturating_add(i128::from(prep.fee_delta))).max(0) as u64;

        let conflict_set = if !direct_conflicts.is_empty() {
            let direct: Vec<Txid> = direct_conflicts.into_iter().collect();
            let set = self.graph.conflict_set(&direct);
            let (old_fee, old_weight) = self.graph.set_fee_weight(&set);
            let (direct_fee, direct_weight) = self
                .graph
                .set_fee_weight(&direct.iter().copied().collect::<BTreeSet<_>>());
            if !rbf_allows_replacement(
                admit_fee,
                weight,
                old_fee,
                old_weight,
                direct_fee,
                direct_weight,
            ) {
                return Err(AcceptError::RbfInsufficient);
            }
            set
        } else {
            BTreeSet::new()
        };
        let parent_txids: BTreeSet<Txid> = parent_txids
            .into_iter()
            .filter(|p| !conflict_set.contains(p))
            .collect();

        let mut members = BTreeSet::new();
        for p in &parent_txids {
            if let Some(c) = self.graph.cluster_of(p) {
                members.extend(c.members);
            }
        }
        members.retain(|m| !conflict_set.contains(m));
        let base_w: u64 = members
            .iter()
            .filter_map(|t| self.graph.get(t).map(|e| e.weight))
            .sum();
        let combined_vsize = base_w.saturating_add(weight).saturating_add(3) / 4;
        if members.len() + 1 > self.graph.cluster_count_limit()
            || combined_vsize > self.graph.cluster_vsize_limit()
        {
            return Err(AcceptError::ClusterTooLarge {
                count: members.len() + 1,
                weight: base_w.saturating_add(weight),
            });
        }

        Ok((conflict_set, fee_sat, weight))
    }

    /// Full prepare → script → commit without resetting stage timers (orphan promote).
    fn accept_tx_inner(
        &mut self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        let prep = self.prepare_admit(tx, utxos, tip, 0, true)?;
        let t_script = Instant::now();
        let script_res = verify_tx_scripts(tx, prep.prevouts.clone());
        self.last_accept_stages.script_us = self
            .last_accept_stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        script_res?;
        self.commit_after_script(tx, prep, tip)
    }

    /// Electrum scripthash = SHA256(scriptPubKey) (same as store `script_hash`).
    fn electrum_scripthash(script: &[u8]) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash};
        *sha256::Hash::hash(script).as_byte_array()
    }

    /// Re-try orphans that listed `parent` as missing (recursive via accept_tx_inner).
    ///
    /// Uses inner (not top-level accept_tx) so stage timers accumulate on the
    /// parent admit that unlocked the orphan chain. Public for hub staged commit.
    pub fn promote_orphans_of(
        &mut self,
        parent: Txid,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) {
        let children = self.orphanage.take_children_of(&parent);
        for child in children {
            if let Ok(r) = self.accept_tx_inner(&child, utxos, tip) {
                self.promote_orphans_of(r.txid, utxos, tip);
            }
        }
    }

    /// Ensure the durable slot table has a FREE/DEAD entry for the next append.
    ///
    /// Order: if full of LIVE, **grow** the slot table first (weight may still have
    /// headroom — mainnet 4k-slot stall); if at max cap, **evict** worst chunks.
    /// Never surface as store corruption.
    fn ensure_free_slot(&mut self, protect: Option<Txid>) -> Result<(), AcceptError> {
        if self.store.has_free_slot() {
            return Ok(());
        }
        match self.store.grow_slots() {
            Ok(()) => {
                if self.store.has_free_slot() {
                    return Ok(());
                }
            }
            Err(MempoolError::Full) => {}
            Err(e) => return Err(e.into()),
        }
        let mut guard = 0u32;
        while !self.store.has_free_slot() && guard < 10_000 {
            guard += 1;
            let Some((_rep, chunk)) = self.graph.worst_chunk() else {
                break;
            };
            if chunk.txids.len() == 1 && protect == chunk.txids.first().copied() {
                break;
            }
            let mut removed = 0usize;
            for t in &chunk.txids {
                if protect == Some(*t) {
                    continue;
                }
                if self.graph.contains(t) {
                    self.remove_txid(t)?;
                    removed += 1;
                }
            }
            if removed == 0 {
                break;
            }
        }
        if self.store.has_free_slot() {
            return Ok(());
        }
        Err(AcceptError::Policy("mempool full"))
    }

    /// Remove lowest-feerate chunks until `total_weight <= max_weight`.
    ///
    /// Prefer not to evict `protect` (the just-accepted tx). Returns how many removed.
    pub fn evict_to_budget(&mut self, protect: Option<Txid>) -> Result<usize, AcceptError> {
        let mut removed = 0usize;
        while self.graph.total_weight() > self.max_weight {
            let Some((_rep, chunk)) = self.graph.worst_chunk() else {
                break;
            };
            if chunk.txids.len() == 1 && protect == chunk.txids.first().copied() {
                break;
            }
            for t in &chunk.txids {
                if protect == Some(*t) {
                    continue;
                }
                if self.graph.contains(t) {
                    self.remove_txid(t)?;
                    removed += 1;
                }
            }
            if removed == 0 {
                break;
            }
        }
        Ok(removed)
    }

    /// Count / weight / topo checks for an ancestor package (no graph lock).
    pub fn check_package_shape(txs: &[Transaction]) -> Result<(), AcceptError> {
        if txs.is_empty() {
            return Err(AcceptError::PackageEmpty);
        }
        let total_weight: u64 = txs.iter().map(|t| t.weight().to_wu()).sum();
        if txs.len() > MAX_PACKAGE_COUNT || total_weight > MAX_PACKAGE_WEIGHT {
            return Err(AcceptError::PackageTooLarge {
                count: txs.len(),
                weight: total_weight,
            });
        }
        let mut seen = BTreeSet::new();
        let mut pkg_ids = BTreeSet::new();
        for tx in txs {
            if tx.is_coinbase() {
                return Err(AcceptError::Coinbase);
            }
            let id = tx.compute_txid();
            if !seen.insert(id) {
                return Err(AcceptError::Duplicate(id));
            }
            pkg_ids.insert(id);
        }
        for (i, tx) in txs.iter().enumerate() {
            for inp in &tx.input {
                let parent = inp.previous_output.txid;
                if pkg_ids.contains(&parent) {
                    let parent_pos = txs.iter().position(|t| t.compute_txid() == parent);
                    match parent_pos {
                        Some(p) if p < i => {}
                        _ => return Err(AcceptError::PackageNotTopo),
                    }
                }
            }
        }
        Ok(())
    }

    /// Accept an ancestor package (CPFP): txs must be parent-before-child.
    ///
    /// On any failure, already-accepted members of this package are rolled back.
    pub fn accept_package(
        &mut self,
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<Vec<AcceptResult>, AcceptError> {
        Self::check_package_shape(txs)?;

        self.last_accept_stages = AcceptStageUs::default();
        let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
        for tx in txs {
            // Inner + promote (not top-level accept_tx) so stages are not reset per member.
            match self.accept_tx_inner(tx, utxos, tip) {
                Ok(r) => {
                    self.promote_orphans_of(r.txid, utxos, tip);
                    accepted.push(r);
                }
                Err(e) => {
                    for r in accepted.iter().rev() {
                        let _ = self.remove_txid(&r.txid);
                    }
                    return Err(e);
                }
            }
        }
        Ok(accepted)
    }

    /// Durable remove one live tx (confirm / RBF / eviction).
    pub fn remove_txid(&mut self, txid: &Txid) -> Result<(), AcceptError> {
        let entry = self
            .graph
            .get(txid)
            .ok_or(AcceptError::NotFound(*txid))?
            .clone();
        let tx = self
            .bodies
            .get(txid)
            .cloned()
            .ok_or(AcceptError::Durable("body missing".into()))?;
        self.store.mark_slot_dead(entry.slot)?;
        self.graph.remove(txid, &tx);
        self.bodies.remove(txid);
        Ok(())
    }

    /// Remove all txs that appear in a confirmed block (coinbase ignored if present).
    ///
    /// Missing mempool entries are skipped (already not in pool). Returns how many removed.
    /// May trigger compaction when DEAD slots dominate.
    ///
    /// Also drops orphanage entries that are confirmed or conflict with the block,
    /// and best-effort re-accepts orphans whose parent just confirmed (caller must
    /// pass a UTXO view that includes the new tip — use [`remove_for_block_with_utxo`]).
    pub fn remove_for_block(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        self.remove_for_block_with_utxo(
            block_txids,
            &MapUtxoProvider {
                map: std::collections::HashMap::new(),
            },
            ChainTipCtx::default(),
        )
    }

    /// Remove live graph entries listed in `block_txids` (no orphan promote).
    pub fn remove_live_txids(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        let mut n = 0usize;
        for txid in block_txids {
            if self.graph.contains(txid) {
                self.remove_txid(txid)?;
                n += 1;
            }
        }
        if n > 0 {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        Ok(n)
    }

    /// Like [`remove_for_block`], then promote orphans of confirmed parents via `utxos`.
    pub fn remove_for_block_with_utxo(
        &mut self,
        block_txids: &[Txid],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<usize, AcceptError> {
        let n = self.remove_live_txids(block_txids)?;
        for txid in block_txids {
            self.promote_orphans_of(*txid, utxos, tip);
        }
        self.orphanage.erase_for_block(block_txids);
        Ok(n)
    }

    /// Drop live txs (and their descendants) that spend `spent` outpoints.
    ///
    /// A confirmed block that double-spends mempool txs does not list those
    /// txs in `txdata`; `remove_for_block` alone would leave them hanging.
    pub fn evict_conflicts_with(&mut self, spent: &[OutPoint]) -> Vec<Txid> {
        let mut direct = Vec::new();
        for op in spent {
            if let Some(c) = self.graph.conflict_txid(op) {
                direct.push(c);
            }
        }
        if direct.is_empty() {
            return Vec::new();
        }
        let set = self.graph.conflict_set(&direct);
        let mut out = Vec::new();
        for id in set {
            if self.remove_txid(&id).is_ok() {
                out.push(id);
            }
        }
        if !out.is_empty() {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        out
    }

    pub fn orphan_count(&self) -> usize {
        self.orphanage.len()
    }

    /// Re-accept non-coinbase txs after a reorg disconnect (best-effort).
    ///
    /// Failures on individual txs are collected; successful accepts remain.
    pub fn reorg_disconnect_reaccept(
        &mut self,
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Vec<Result<AcceptResult, AcceptError>> {
        let out: Vec<Result<AcceptResult, AcceptError>> = txs
            .iter()
            .filter(|t| !t.is_coinbase())
            .map(|t| self.accept_tx(t, utxos, tip))
            .collect();
        self.evict_nonfinal(utxos, tip);
        out
    }

    /// Drop live txs whose BIP68 / finality no longer holds (reorg: parent
    /// went from confirmed to mempool).
    pub fn evict_nonfinal(&mut self, utxos: &impl UtxoProvider, tip: ChainTipCtx) {
        loop {
            let ids: Vec<Txid> = self.graph.iter().map(|(t, _)| *t).collect();
            let mut removed = false;
            for id in ids {
                let Some(tx) = self.get_tx(&id).cloned() else {
                    continue;
                };
                let mut chain_coins = Vec::with_capacity(tx.input.len());
                let mut missing_chain = false;
                for inp in &tx.input {
                    if self.graph.creator(&inp.previous_output).is_some() {
                        chain_coins.push(None);
                    } else if let Some(c) = utxos.get_coin(&inp.previous_output) {
                        chain_coins.push(Some(c));
                    } else {
                        // Parent is neither live nor a confirmed coin — reorg
                        // made the input disappear (or we just evicted it).
                        missing_chain = true;
                        break;
                    }
                }
                if missing_chain || check_mempool_structural(&tx, &chain_coins, tip).is_err() {
                    let _ = self.remove_txid(&id);
                    removed = true;
                }
            }
            if !removed {
                break;
            }
        }
    }

    /// Lookup a live body (for tests / Electrum unconf).
    pub fn get_tx(&self, txid: &Txid) -> Option<&Transaction> {
        self.bodies.get(txid)
    }

    /// Mining-order live txs that fit in `max_weight_wu` (best chunks first).
    pub fn select_block_txs(&self, max_weight_wu: u64) -> Vec<Transaction> {
        self.select_block_txs_delta(max_weight_wu, |_| 0)
    }

    /// Like [`Self::select_block_txs`] with `prioritisetransaction` fee deltas.
    pub fn select_block_txs_delta(
        &self,
        max_weight_wu: u64,
        delta: impl Fn(Txid) -> i64,
    ) -> Vec<Transaction> {
        self.graph
            .select_block_txids_delta(max_weight_wu, delta)
            .into_iter()
            .filter_map(|id| self.get_tx(&id).cloned())
            .collect()
    }
}

/// BIP125-style full-RBF fee check (no signaling required — Libre full RBF).
///
/// Requires strictly higher absolute fee over the **conflict set** (incl.
/// descendants), higher feerate, and incremental relay fee on replacement vsize.
pub fn rbf_pays_for_replacement(
    new_fee: u64,
    new_weight: u64,
    old_fee: u64,
    old_weight: u64,
) -> bool {
    if new_fee <= old_fee {
        return false;
    }
    let new_rate = policy::fee_rate_sat_per_kvb(new_fee, new_weight);
    let old_rate = policy::fee_rate_sat_per_kvb(old_fee, old_weight);
    if new_rate <= old_rate {
        return false;
    }
    let vsize = policy::get_virtual_size(new_weight);
    let inc = vsize
        .saturating_mul(INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB)
        .saturating_add(999)
        / 1000;
    new_fee.saturating_sub(old_fee) >= inc
}

/// Pure replace-by-fee-rate (Libre Relay): `new_rate ≥ 1.25 × direct_conflict_rate`.
///
/// Uses only **direct** conflict fee/weight (not the full descendant set), so a
/// high-feerate replacement can unpin low-feerate descendant packages.
///
/// Integer form: `new_fee * DEN * direct_vsize ≥ direct_fee * NUM * new_vsize`
/// with `NUM/DEN = 5/4`.
pub fn pure_rbfr_pays(new_fee: u64, new_weight: u64, direct_fee: u64, direct_weight: u64) -> bool {
    if new_weight == 0 || direct_weight == 0 {
        return false;
    }
    let new_v = policy::get_virtual_size(new_weight);
    let old_v = policy::get_virtual_size(direct_weight);
    if new_v == 0 || old_v == 0 {
        return false;
    }
    new_fee.saturating_mul(RBFR_RATIO_DEN).saturating_mul(old_v)
        >= direct_fee
            .saturating_mul(RBFR_RATIO_NUM)
            .saturating_mul(new_v)
}

/// Admit replacement if BIP125-style rules **or** pure RBFR (Libre).
pub fn rbf_allows_replacement(
    new_fee: u64,
    new_weight: u64,
    conflict_fee: u64,
    conflict_weight: u64,
    direct_fee: u64,
    direct_weight: u64,
) -> bool {
    rbf_pays_for_replacement(new_fee, new_weight, conflict_fee, conflict_weight)
        || pure_rbfr_pays(new_fee, new_weight, direct_fee, direct_weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{MAX_CLUSTER_COUNT, MAX_CLUSTER_WEIGHT};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-mempool-accept-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            n
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Tip high enough that maturity/finality/BIP68 do not block normal test txs.
    const TIP_OK: ChainTipCtx = ChainTipCtx {
        height: 1_000_000,
        mtp: u32::MAX,
    };

    fn coin(txout: TxOut) -> Coin {
        Coin {
            txout,
            create_height: 0,
            create_mtp: 0,
            is_coinbase: false,
        }
    }

    fn chain_utxo(value: u64) -> (OutPoint, TxOut, MapUtxoProvider) {
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout.clone()));
        (op, txout, MapUtxoProvider { map })
    }

    /// Finding 011: duplicate inputs rejected before fee accounting.
    #[test]
    fn reject_duplicate_inputs() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op, // same outpoint twice
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::InputsDuplicate), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 011: absolute nLockTime height form not final at tip+1.
    #[test]
    fn reject_non_final_locktime_height() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 99_000);
        // Height lock: need block_height > 500; tip.height+1 = 101 → not final.
        tx.lock_time = LockTime::from_height(500).unwrap();
        // Non-final sequence so locktime is enforced.
        tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
        let tip = ChainTipCtx {
            height: 100,
            mtp: u32::MAX,
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
        assert!(matches!(err, AcceptError::NotFinal), "got {err}");
        // At tip 500, next height 501 > 500 → final.
        let tip2 = ChainTipCtx {
            height: 500,
            mtp: u32::MAX,
        };
        mp.accept_tx(&tx, &utxos, tip2).expect("final at tip 500");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 011: immature coinbase spend rejected.
    #[test]
    fn reject_immature_coinbase() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            Coin {
                txout: TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                create_height: 50,
                create_mtp: 0,
                is_coinbase: true,
            },
        );
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 49_0000_0000);
        // tip 100 → next 101; need create+100 = 150.
        let tip = ChainTipCtx {
            height: 100,
            mtp: u32::MAX,
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
        assert!(matches!(err, AcceptError::ImmatureCoinbase), "got {err}");
        let tip2 = ChainTipCtx {
            height: 149,
            mtp: u32::MAX,
        };
        mp.accept_tx(&tx, &utxos, tip2)
            .expect("mature at tip 149 (next=150)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bip68_time_lock_uses_coin_create_mtp() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x22; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            Coin {
                txout: TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                create_height: 10,
                create_mtp: 1_000_000,
                is_coinbase: false,
            },
        );
        let utxos = MapUtxoProvider { map };
        let mut tx = spend_tx(op, 49_000);
        tx.version = Version::TWO;
        // Time-type relative lock of 2 units (2 << 9 = 1024 seconds).
        tx.input[0].sequence = Sequence::from_consensus((1 << 22) | 2);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        // prev MTP 1_000_000 + 1024 - 1 = 1_001_023; tip MTP 1_001_000 → not final.
        let err = mp
            .accept_tx(
                &tx,
                &utxos,
                ChainTipCtx {
                    height: 20,
                    mtp: 1_001_000,
                },
            )
            .unwrap_err();
        assert!(matches!(err, AcceptError::NonBip68Final), "got {err}");
        mp.accept_tx(
            &tx,
            &utxos,
            ChainTipCtx {
                height: 20,
                mtp: 1_002_000,
            },
        )
        .expect("time lock satisfied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_nonfinal_after_parent_unconfirmed() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x33; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            Coin {
                txout: TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                create_height: 10,
                create_mtp: 1,
                is_coinbase: false,
            },
        );
        let utxos = MapUtxoProvider { map };
        let mut tx = spend_tx(op, 49_000);
        tx.version = Version::TWO;
        tx.input[0].sequence = Sequence::from_consensus(1);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(
            &tx,
            &utxos,
            ChainTipCtx {
                height: 20,
                mtp: u32::MAX,
            },
        )
        .expect("seq=1 ok vs confirmed parent");
        assert_eq!(mp.graph.len(), 1);
        mp.evict_nonfinal(
            &MapUtxoProvider {
                map: HashMap::new(),
            },
            ChainTipCtx {
                height: 19,
                mtp: u32::MAX,
            },
        );
        assert_eq!(
            mp.graph.len(),
            0,
            "seq=1 child evicted when parent is unconfirmed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After invalidate drops tip below coinbase maturity, the live spend leaves.
    #[test]
    fn evict_nonfinal_drops_now_immature_coinbase_spend() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x44; 32]),
            vout: 0,
        };
        let coin = Coin {
            txout: TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 1,
            create_mtp: 0,
            is_coinbase: true,
        };
        let utxos = MapUtxoProvider {
            map: HashMap::from([(op, coin)]),
        };
        let tx = spend_tx(op, 49_0000_0000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(
            &tx,
            &utxos,
            ChainTipCtx {
                height: 200,
                mtp: u32::MAX,
            },
        )
        .expect("mature at tip 200");
        assert_eq!(mp.live_count(), 1);
        mp.evict_nonfinal(
            &utxos,
            ChainTipCtx {
                height: 9,
                mtp: u32::MAX,
            },
        );
        assert_eq!(
            mp.live_count(),
            0,
            "next_height=10 < create+100 must evict the coinbase spend"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stage timers are recorded on a successful chain-spend accept.
    #[test]
    fn accept_records_stage_us_on_success() {
        let dir = tmp_dir();
        let (op, _txout, utxos) = chain_utxo(50_000);
        let tx = spend_tx(op, 49_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).expect("accept");
        let s = mp.last_accept_stages;
        // Detached script hop + durable append should register µs on typical hosts.
        assert!(
            s.script_us > 0 || s.durable_us > 0 || s.utxo_us > 0,
            "expected non-zero stage sample, got {s:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 010: provider returns no coin for a spent/missing outpoint → reject.
    #[test]
    fn reject_when_provider_has_no_unspent_coin() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        };
        let tx = spend_tx(op, 1_000);
        let utxos = MapUtxoProvider {
            map: HashMap::new(), // spent or unknown → no coin
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp
            .accept_tx(&tx, &utxos, TIP_OK)
            .expect_err("must not admit");
        // Orphanage parks missing parents; empty map → orphaned or missing.
        assert!(
            matches!(
                err,
                AcceptError::Orphaned(_) | AcceptError::MissingPrevout(_)
            ),
            "got {err}"
        );
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn spend_tx(op: OutPoint, out_value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn prepare_admit_output_sum_overflow_is_policy_not_panic() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let half = (u64::MAX / 2) + 2;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(half),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(half),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            ],
        };
        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp
            .prepare_admit(&tx, &utxos, TIP_OK, 0, false)
            .expect_err("overflowing output sum");
        assert!(
            matches!(err, AcceptError::Policy("bad-txns-txouttotal-toolarge")),
            "got {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_single_flush_reopen() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 99_000); // fee 1000
        let txid = tx.compute_txid();
        {
            let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
            let r = mp.accept_tx(&tx, &utxos, TIP_OK).expect("accept");
            assert_eq!(r.txid, txid);
            assert_eq!(r.fee_sat, 1000);
            assert_eq!(mp.live_count(), 1);
            mp.flush().unwrap();
            assert!(mp.generation() >= 1);
        }
        {
            let mp = ActiveMempool::open_or_create(&dir).unwrap();
            assert_eq!(mp.live_count(), 1);
            assert!(mp.graph.contains(&txid));
            let e = mp.graph.get(&txid).unwrap();
            assert_eq!(e.fee_sat, 1000);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Consensus script check must reject spends of real templates with empty witness.
    /// (Regression: accept used to skip verify and only apply Libre policy.)
    #[test]
    fn reject_invalid_p2wpkh_script() {
        use bitcoin::WPubkeyHash;

        let dir = tmp_dir();
        // Standard P2WPKH spk — not anyone-can-spend; empty witness fails.
        let wpkh = WPubkeyHash::from_byte_array([0x11; 20]);
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout));
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 99_000); // empty scriptSig + empty witness
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::Script(_)),
            "expected Script reject, got {err}"
        );
        assert_eq!(mp.live_count(), 0);
        // Sanity: ACS still accepted (Libre + consensus anyone-can-spend).
        let (op2, _, utxos2) = chain_utxo(50_000);
        let ok = spend_tx(op2, 49_000);
        mp.accept_tx(&ok, &utxos2, TIP_OK).expect("ACS still ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reject_low_feerate() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        // fee 1 sat — below 0.1 sat/vB for any real tx weight
        let tx = spend_tx(op, 99_999);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::Policy("min relay fee")));
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dust_and_op_true_allowed() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        // 1-sat output is dust under Core; Libre allows it.
        let tx = spend_tx(op, 1);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).expect("dust ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_spends_parent_cluster() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let parent = spend_tx(op, 90_000);
        let pid = parent.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();

        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 80_000);
        mp.accept_tx(&child, &utxos, TIP_OK).unwrap();
        assert_eq!(mp.live_count(), 2);
        let c = mp.graph.cluster_of(&pid).unwrap();
        assert_eq!(c.members.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversize_cluster_rejected() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(10_000_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        // Chain of MAX_CLUSTER_COUNT, then one more fails.
        let mut prev_op = op;
        for i in 0..MAX_CLUSTER_COUNT {
            // Large fee so policy passes; leave enough for remaining.
            let remain = 10_000_000u64 - (i as u64 + 1) * 1_000;
            let tx = spend_tx(prev_op, remain);
            let last_txid = tx.compute_txid();
            mp.accept_tx(&tx, &utxos, TIP_OK)
                .unwrap_or_else(|e| panic!("i={i}: {e}"));
            prev_op = OutPoint {
                txid: last_txid,
                vout: 0,
            };
        }
        assert_eq!(mp.live_count(), MAX_CLUSTER_COUNT);
        let remain = 10_000_000u64 - (MAX_CLUSTER_COUNT as u64 + 1) * 1_000;
        let extra = spend_tx(prev_op, remain);
        let err = mp.accept_tx(&extra, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::ClusterTooLarge { .. }), "{err}");
        assert_eq!(mp.live_count(), MAX_CLUSTER_COUNT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn annex_reject() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 90_000);
        tx.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::Policy("libre annex")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cpfp_package_accept() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        // Parent low fee still above min relay if weight small.
        let parent = spend_tx(op, 99_000); // fee 1000
        let pid = parent.compute_txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 90_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let res = mp
            .accept_package(&[parent.clone(), child.clone()], &utxos, TIP_OK)
            .expect("package");
        assert_eq!(res.len(), 2);
        assert_eq!(mp.live_count(), 2);
        let c = mp.graph.cluster_of(&pid).unwrap();
        assert_eq!(c.members.len(), 2);
        // Wrong order rejected.
        let mut mp2 = ActiveMempool::open_or_create(tmp_dir()).unwrap();
        let err = mp2
            .accept_package(&[child, parent], &utxos, TIP_OK)
            .unwrap_err();
        assert!(matches!(err, AcceptError::PackageNotTopo));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_clears_mempool() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        assert_eq!(mp.live_count(), 1);
        let n = mp.remove_for_block(&[txid]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(mp.live_count(), 0);
        mp.flush().unwrap();
        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_evicts_conflicting_mempool_txs() {
        let dir = tmp_dir();
        let op_a = OutPoint {
            txid: Txid::from_byte_array([0xa1; 32]),
            vout: 0,
        };
        let op_b = OutPoint {
            txid: Txid::from_byte_array([0xb2; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        let out = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        map.insert(op_a, coin(out.clone()));
        map.insert(op_b, coin(out));
        let utxos = MapUtxoProvider { map };
        let tx_a = spend_tx(op_a, 90_000);
        let tx_b = spend_tx(op_b, 90_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx_a, &utxos, TIP_OK).unwrap();
        mp.accept_tx(&tx_b, &utxos, TIP_OK).unwrap();
        assert_eq!(mp.live_count(), 2);
        // Confirmed block spends both coins (the doublespend is not in the pool).
        let gone = mp.evict_conflicts_with(&[op_a, op_b]);
        assert_eq!(gone.len(), 2);
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbf_cluster_count_excludes_replaced() {
        let dir = tmp_dir();
        let mut map = HashMap::new();
        let mut parents = Vec::new();
        let mut children = Vec::new();
        for i in 0u8..3 {
            let op = OutPoint {
                txid: Txid::from_byte_array([i; 32]),
                vout: 0,
            };
            let out = TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            };
            map.insert(op, coin(out));
            parents.push(op);
        }
        let utxos = MapUtxoProvider { map };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.set_cluster_limits(Some(4), None);
        let mut parent_outs = Vec::new();
        for op in &parents {
            let p = spend_tx(*op, 90_000);
            mp.accept_tx(&p, &utxos, TIP_OK).unwrap();
            let pout = OutPoint {
                txid: p.compute_txid(),
                vout: 0,
            };
            parent_outs.push(pout);
            let c = spend_tx(pout, 80_000);
            mp.accept_tx(&c, &utxos, TIP_OK).unwrap();
            children.push(c.compute_txid());
        }
        assert_eq!(mp.live_count(), 6);
        // Merger spends the three parent outputs (replaces the three children).
        // After RBF: 3 parents + 1 merger = 4, at the cap.
        let merger = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: parent_outs
                .iter()
                .map(|op| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        mp.accept_tx(&merger, &utxos, TIP_OK)
            .expect("RBF must not count replaced children toward the cluster cap");
        assert_eq!(mp.live_count(), 4);
        for id in &children {
            assert!(!mp.graph.contains(id));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mempool_cluster.py` `test_cluster_merging_size`: 10 singletons plus a
    /// merger padded to remaining+4 vB must trip `too-large-cluster`.
    #[test]
    fn cluster_merge_size_ten_way_rejects() {
        let dir = tmp_dir();
        let limit_vb = 10_000u64;
        let mut map = HashMap::new();
        let mut parent_ops = Vec::new();
        for i in 0u8..10 {
            let op = OutPoint {
                txid: Txid::from_byte_array([i; 32]),
                vout: 0,
            };
            map.insert(
                op,
                coin(TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }),
            );
            parent_ops.push(op);
        }
        let utxos = MapUtxoProvider { map };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.set_cluster_limits(None, Some(10)); // 10 kvB
        let mut spent = Vec::new();
        let mut parent_vsize = 0u64;
        for op in &parent_ops {
            let tx = spend_tx(*op, 900_000);
            parent_vsize += tx.weight().to_wu().saturating_add(3) / 4;
            let tid = tx.compute_txid();
            mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
            spent.push(OutPoint { txid: tid, vout: 0 });
        }
        let remaining = limit_vb.saturating_sub(parent_vsize);
        assert!(remaining >= 500, "fixture remaining={remaining}");
        let mut merger = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: spent
                .iter()
                .map(|op| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
                },
            ],
        };
        let target = remaining + 4;
        while (merger.vsize() as u64) < target {
            let mut pad = merger.output[1].script_pubkey.to_bytes();
            pad.push(0x61);
            merger.output[1].script_pubkey = ScriptBuf::from_bytes(pad);
        }
        let err = mp.accept_tx(&merger, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::ClusterTooLarge { .. }),
            "ten-way merger vsize={} remaining={remaining} got {err}",
            merger.vsize()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reorg_reaccept() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        mp.remove_for_block(&[txid]).unwrap();
        assert_eq!(mp.live_count(), 0);
        let results = mp.reorg_disconnect_reaccept(&[tx], &utxos, TIP_OK);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert_eq!(mp.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_rbf_replaces_conflict() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let low = spend_tx(op, 99_000); // fee 1000
        let high = spend_tx(op, 50_000); // fee 50000 — same input, full RBF
        let low_id = low.compute_txid();
        let high_id = high.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&low, &utxos, TIP_OK).unwrap();
        assert!(mp.graph.contains(&low_id));
        let r = mp.accept_tx(&high, &utxos, TIP_OK).expect("rbf");
        assert_eq!(r.txid, high_id);
        assert!(
            r.replaced.contains(&low_id),
            "replaced should list conflict {:?}",
            r.replaced
        );
        assert!(
            !r.replaced_scripthashes.is_empty(),
            "replaced output scripthashes collected before removal"
        );
        assert!(!mp.graph.contains(&low_id));
        assert!(mp.graph.contains(&high_id));
        assert_eq!(mp.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evaluate_after_script_rbf_leaves_conflict() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let low = spend_tx(op, 99_000);
        let high = spend_tx(op, 50_000);
        let low_id = low.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&low, &utxos, TIP_OK).unwrap();
        let prep = mp.prepare_admit(&high, &utxos, TIP_OK, 0, true).unwrap();
        let r = mp
            .evaluate_after_script(&high, prep, TIP_OK)
            .expect("preview");
        assert!(r.replaced.contains(&low_id));
        assert!(mp.graph.contains(&low_id));
        assert!(!mp.graph.contains(&high.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_after_script_does_not_take_utxo_provider() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 99_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let prep = mp.prepare_admit(&tx, &utxos, TIP_OK, 0, true).unwrap();
        mp.commit_after_script(&tx, prep, TIP_OK)
            .expect("commit uses prep.chain_coins");
        assert!(mp.graph.contains(&tx.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn park_orphan_is_graph_only() {
        let dir = tmp_dir();
        let tx = spend_tx(
            OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            1,
        );
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let e = mp.park_orphan(&tx);
        assert!(matches!(e, AcceptError::Orphaned(_)), "{e}");
        assert_eq!(mp.orphan_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbf_rejects_insufficient() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let high = spend_tx(op, 50_000); // fee 50000
        let low = spend_tx(op, 99_000); // fee 1000 — cannot replace
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&high, &utxos, TIP_OK).unwrap();
        let err = mp.accept_tx(&low, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::RbfInsufficient), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chunk_eviction_under_weight_budget() {
        let dir = tmp_dir();
        // Tiny budget forces eviction after a few accepts.
        let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 800).unwrap();
        // Distinct chain UTXOs so they are independent clusters.
        for i in 0u8..8 {
            let op = OutPoint {
                txid: Txid::from_byte_array([i.wrapping_add(1); 32]),
                vout: 0,
            };
            let txout = TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            };
            let mut map = HashMap::new();
            map.insert(op, coin(txout));
            let utxos = MapUtxoProvider { map };
            // Vary fees so worst-chunk ordering is defined: low fee first.
            let out = 99_000u64 - u64::from(i) * 100; // higher i → higher fee
            let tx = spend_tx(op, out);
            mp.accept_tx(&tx, &utxos, TIP_OK)
                .unwrap_or_else(|e| panic!("i={i}: {e}"));
        }
        assert!(mp.graph.total_weight() <= mp.max_weight + 500); // allow one protected overflow
        assert!(mp.live_count() < 8, "some eviction expected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbf_pays_helper() {
        assert!(rbf_pays_for_replacement(10_000, 4000, 1000, 4000));
        assert!(!rbf_pays_for_replacement(1000, 4000, 10_000, 4000));
        assert!(!rbf_pays_for_replacement(1000, 4000, 1000, 4000));
    }

    #[test]
    fn pure_rbfr_1_25x_ratio() {
        // Same weight: new fee ≥ 1.25× old fee.
        // old fee 1000 @ 4000 WU → need new ≥ 1250 same weight.
        assert!(pure_rbfr_pays(1_250, 4000, 1_000, 4000));
        assert!(!pure_rbfr_pays(1_249, 4000, 1_000, 4000));
        // Higher rate, lower absolute fee vs a fat conflict set still passes pure RBFR
        // (BIP125 would fail): direct 1000@4000, conflict set pretends 50k@40k.
        assert!(!rbf_pays_for_replacement(2_000, 4000, 50_000, 40_000));
        assert!(pure_rbfr_pays(2_000, 4000, 1_000, 4000));
        assert!(rbf_allows_replacement(
            2_000, 4000, 50_000, 40_000, 1_000, 4000
        ));
    }

    /// Regression: single large-but-standard tx (~50 kvB) must not hit cluster cap.
    /// Pre-fix MAX_CLUSTER_WEIGHT=101_000 WU rejected these (Core allows ≤101 kvB).
    #[test]
    fn large_single_tx_under_cluster_vsize_limit_accepted() {
        let dir = tmp_dir();
        // Build a tx with many outputs so weight sits between 101k WU and 404k WU.
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let mut outs = Vec::new();
        // ~3k OP_TRUE outs ≈ 120 kWU: above the old 101 kWU bug, under 404 kWU Core cap.
        let n_out = 3_000u64;
        let each = 100u64;
        let input_val = each * n_out + 50_000; // fee headroom
        for _ in 0..n_out {
            outs.push(TxOut {
                value: Amount::from_sat(each),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outs,
        };
        let w = tx.weight().to_wu();
        assert!(
            w > 101_000 && w <= MAX_CLUSTER_WEIGHT,
            "fixture weight {w} should be in (101k, 404k] WU"
        );
        let txout = TxOut {
            value: Amount::from_sat(input_val),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout));
        let utxos = MapUtxoProvider { map };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK)
            .unwrap_or_else(|e| panic!("large single-tx should accept: {e} (weight={w})"));
        assert_eq!(mp.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pure RBFR: high-feerate replacement with lower absolute fee than parent+child package.
    #[test]
    fn pure_rbfr_unpins_descendant_package() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(1_000_000);
        // Parent: fee 1000 (low rate). Child spends parent: fee 1000 more → conflict set fee 2000.
        let parent = spend_tx(op, 999_000);
        let pid = parent.compute_txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 998_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
        mp.accept_tx(&child, &utxos, TIP_OK).unwrap();
        assert_eq!(mp.live_count(), 2);
        // Replacement of parent only: fee 5000 on same weight class — absolute fee 5000 > 2000
        // would pass BIP125; use fee that loses absolute vs set but wins rate vs direct.
        // Direct parent fee ~1000; set fee ~2000. Replacement fee 1500 fails BIP125 absolute
        // but 1500 ≥ 1.25×1000 pure RBFR if weights similar.
        let repl = spend_tx(op, 998_500); // fee 1500
        let rid = repl.compute_txid();
        // If pure RBFR works: accept. (Weights of spend_tx are equal-ish.)
        let r = mp.accept_tx(&repl, &utxos, TIP_OK);
        match r {
            Ok(_) => {
                assert!(mp.graph.contains(&rid));
                assert!(!mp.graph.contains(&pid));
            }
            Err(e) => {
                // Document failure mode if fixture fees don't hit pure path.
                panic!("expected pure RBFR admit, got {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_reclaims_dead_and_preserves_live() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        let body_before = mp.store.body_logical_len().unwrap();
        // Confirm-remove leaves a DEAD slot (body still holds the old payload).
        mp.remove_for_block(&[txid]).unwrap();
        // Re-accept so we have live + dead history in the body file.
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        let (_f, live, dead) = mp.store.slot_stats();
        assert_eq!(live, 1);
        // remove_for_block may already have auto-compacted; either way compact is safe.
        let _ = dead;
        let (live_after, body_after) = mp.compact().unwrap();
        assert_eq!(live_after, 1);
        assert!(body_after <= body_before + 256);
        assert_eq!(mp.live_count(), 1);
        mp.flush().unwrap();
        let mp2 = ActiveMempool::open_or_create(&dir).unwrap();
        assert_eq!(mp2.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mempool_cluster.py` cleanup mines the mempool empty and `maybe_compact`
    /// rebuilds the graph. Overlay limits must survive that rebuild.
    #[test]
    fn compact_preserves_cluster_size_overlay() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.set_cluster_limits(None, Some(10));
        assert_eq!(mp.graph.cluster_vsize_limit(), 10_000);
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        mp.remove_for_block(&[txid]).unwrap();
        let _ = mp.maybe_compact().unwrap();
        assert_eq!(
            mp.graph.cluster_vsize_limit(),
            10_000,
            "compact must keep -limitclustersize overlay"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_error_display_and_reject_paths() {
        use std::error::Error;
        let errs = [
            AcceptError::Policy("x".into()),
            AcceptError::MissingPrevout(OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            }),
            AcceptError::Orphaned(Txid::from_byte_array([4; 32])),
            AcceptError::Duplicate(Txid::from_byte_array([2; 32])),
            AcceptError::ClusterTooLarge {
                count: 3,
                weight: 9,
            },
            AcceptError::PackageTooLarge {
                count: 2,
                weight: 8,
            },
            AcceptError::PackageEmpty,
            AcceptError::PackageNotTopo,
            AcceptError::RbfInsufficient,
            AcceptError::Coinbase,
            AcceptError::NotFound(Txid::from_byte_array([3; 32])),
            AcceptError::Durable("d".into()),
            AcceptError::Script("s".into()),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
            let _ = e as &dyn Error;
        }
        // From MempoolError.
        let from_io: AcceptError = MempoolError::BadMagic.into();
        assert!(from_io.to_string().contains("durable"));
        let from_full: AcceptError = MempoolError::Full.into();
        assert!(matches!(from_full, AcceptError::Policy("mempool full")));

        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

        // Coinbase reject.
        let cb = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(matches!(
            mp.accept_tx(&cb, &utxos, TIP_OK),
            Err(AcceptError::Coinbase)
        ));

        // Package empty / too large.
        assert!(matches!(
            mp.accept_package(&[], &utxos, TIP_OK),
            Err(AcceptError::PackageEmpty)
        ));
        // Count over MAX_PACKAGE_COUNT (25).
        let many: Vec<Transaction> = (0..MAX_PACKAGE_COUNT + 1)
            .map(|i| {
                spend_tx(
                    OutPoint {
                        txid: Txid::from_byte_array({
                            let mut b = [0u8; 32];
                            b[0] = i as u8;
                            b
                        }),
                        vout: 0,
                    },
                    1,
                )
            })
            .collect();
        assert!(matches!(
            mp.accept_package(&many, &utxos, TIP_OK),
            Err(AcceptError::PackageTooLarge { .. })
        ));

        let tx = spend_tx(op, 99_000);
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        // Duplicate.
        assert!(matches!(
            mp.accept_tx(&tx, &utxos, TIP_OK),
            Err(AcceptError::Duplicate(_))
        ));

        // Missing prevout → parked in orphanage (Core-class soft accept).
        let (_op2, _, empty) = chain_utxo(50_000);
        let missing = spend_tx(
            OutPoint {
                txid: Txid::from_byte_array([0xcd; 32]),
                vout: 0,
            },
            1,
        );
        let missing_id = missing.compute_txid();
        assert!(matches!(
            mp.accept_tx(&missing, &empty, TIP_OK),
            Err(AcceptError::Orphaned(_))
        ));
        assert!(mp.orphanage.contains(&missing_id));
        assert_eq!(mp.orphan_count(), 1);

        // maybe_compact with only live → None.
        assert!(mp.maybe_compact().unwrap().is_none());

        // Package coinbase / not topo / oversized count.
        assert!(matches!(
            mp.accept_package(&[cb], &utxos, TIP_OK),
            Err(AcceptError::Coinbase)
        ));
        let a = spend_tx(op, 98_000);
        let b = spend_tx(
            OutPoint {
                txid: a.compute_txid(),
                vout: 0,
            },
            97_000,
        );
        // Child before parent → not topo.
        assert!(matches!(
            mp.accept_package(&[b.clone(), a.clone()], &utxos, TIP_OK),
            Err(AcceptError::PackageNotTopo)
        ));
        // Duplicate in package.
        assert!(matches!(
            mp.accept_package(&[a.clone(), a.clone()], &utxos, TIP_OK),
            Err(AcceptError::Duplicate(_))
        ));

        // remove unknown.
        assert!(matches!(
            mp.remove_txid(&Txid::from_byte_array([0xee; 32])),
            Err(AcceptError::NotFound(_))
        ));

        // Negative fee.
        let fat = spend_tx(op, 200_000);
        assert!(matches!(
            mp.accept_tx(&fat, &utxos, TIP_OK),
            Err(AcceptError::Policy(_))
        ));

        // rbf_pays_for_replacement pure unit.
        assert!(!rbf_pays_for_replacement(100, 400, 100, 400));
        assert!(!rbf_pays_for_replacement(100, 400, 200, 400));
        // Higher fee and rate with incremental cover.
        assert!(rbf_pays_for_replacement(50_000, 400, 1_000, 400));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbf_replaces_conflicting_spend() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(1_000_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let low = spend_tx(op, 999_000); // fee 1000
        mp.accept_tx(&low, &utxos, TIP_OK).unwrap();
        // Conflict: same prevout, higher fee.
        let high = spend_tx(op, 900_000); // fee 100_000
        let r = mp.accept_tx(&high, &utxos, TIP_OK).expect("rbf");
        assert_eq!(r.txid, high.compute_txid());
        assert!(!mp.graph.contains(&low.compute_txid()));
        assert!(mp.graph.contains(&high.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Child arrives before parent: park in orphanage, promote when parent accepts.
    #[test]
    fn orphan_park_then_promote_on_parent() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let parent = spend_tx(op, 99_000);
        let parent_id = parent.compute_txid();
        let child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            98_000,
        );
        let child_id = child.compute_txid();

        assert!(matches!(
            mp.accept_tx(&child, &utxos, TIP_OK),
            Err(AcceptError::Orphaned(_))
        ));
        assert_eq!(mp.orphan_count(), 1);
        assert!(!mp.graph.contains(&child_id));

        mp.accept_tx(&parent, &utxos, TIP_OK).expect("parent");
        assert!(mp.graph.contains(&parent_id));
        assert!(
            mp.graph.contains(&child_id),
            "child should promote when parent enters mempool"
        );
        assert_eq!(mp.orphan_count(), 0);
        assert_eq!(mp.live_count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dry-run must not park: a later parent accept must not promote the child.
    #[test]
    fn prepare_admit_without_park_does_not_orphan() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let parent = spend_tx(op, 99_000);
        let parent_id = parent.compute_txid();
        let child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            98_000,
        );
        let child_id = child.compute_txid();

        let err = mp
            .prepare_admit(&child, &utxos, TIP_OK, 0, false)
            .unwrap_err();
        assert!(
            matches!(
                err,
                AcceptError::MissingPrevout(_) | AcceptError::Orphaned(_)
            ),
            "{err:?}"
        );
        assert_eq!(mp.orphan_count(), 0);

        mp.accept_tx(&parent, &utxos, TIP_OK).expect("parent");
        assert!(mp.graph.contains(&parent_id));
        assert!(
            !mp.graph.contains(&child_id),
            "dry-run child must not promote when parent arrives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Slot table growth under accept: legacy tiny sidecar must not fail as Durable corrupt.
    #[test]
    fn accept_grows_legacy_tiny_slot_table() {
        use std::fs;
        let dir = tmp_dir();
        fs::create_dir_all(&dir).unwrap();
        // 4-slot meta/slots/body (same layout as store unit test).
        {
            let mut meta = [0u8; 64];
            meta[0..4].copy_from_slice(b"rBMP");
            meta[4..6].copy_from_slice(&1u16.to_le_bytes());
            meta[16..20].copy_from_slice(&4u32.to_le_bytes());
            fs::write(dir.join("meta"), meta).unwrap();
            let mut slots = vec![0u8; 16 + 4 * 48];
            slots[0..4].copy_from_slice(b"rBMP");
            slots[4..6].copy_from_slice(&1u16.to_le_bytes());
            slots[8..12].copy_from_slice(&4u32.to_le_bytes());
            fs::write(dir.join("slots"), &slots).unwrap();
            let mut body = vec![0u8; 16];
            body[0..4].copy_from_slice(b"rBMP");
            body[4..6].copy_from_slice(&1u16.to_le_bytes());
            body[8..16].copy_from_slice(&16u64.to_le_bytes());
            fs::write(dir.join("tx.body"), &body).unwrap();
        }
        // Large weight budget so eviction is not the free-slot path.
        let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 300_000_000).unwrap();
        assert_eq!(mp.store.meta().slot_cap, 4);
        // Four independent chain utxos → four live slots.
        for i in 0..4u8 {
            let op = OutPoint {
                txid: Txid::from_byte_array({
                    let mut b = [0xab; 32];
                    b[0] = i;
                    b
                }),
                vout: 0,
            };
            let mut map = HashMap::new();
            map.insert(
                op,
                coin(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }),
            );
            let utxos = MapUtxoProvider { map };
            let tx = spend_tx(op, 99_000);
            mp.accept_tx(&tx, &utxos, TIP_OK)
                .unwrap_or_else(|e| panic!("accept {i}: {e}"));
        }
        assert_eq!(mp.live_count(), 4);
        // Fifth must grow slots, not Durable(corrupt: slot table full).
        let op = OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 99_000);
        let r = mp.accept_tx(&tx, &utxos, TIP_OK);
        assert!(
            r.is_ok(),
            "expected free-slot (evict or grow), got {:?}",
            r.err().map(|e| e.to_string())
        );
        // Evict-for-slot may keep cap=4; grow path raises it. Either is fine —
        // must never be Durable(corrupt: slot table full).
        assert_eq!(mp.live_count(), 5.min(mp.store.meta().slot_cap as usize));
        // Graph and store agree we still hold a full-ish set.
        assert!(mp.live_count() >= 4);
        let _ = fs::remove_dir_all(&dir);
    }
}
