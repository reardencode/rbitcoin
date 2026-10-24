//! Single-tx accept: Libre policy + cluster limits + durable slot write.

use crate::error::MempoolError;
use crate::graph::{
    sigops_adjusted_weight, SelectBudget, Selected, TxEntry, TxGraph, MAX_BLOCK_SIGOPS_COST,
};
use crate::orphanage::{OrphanSnapshot, Orphanage};
use crate::packed::VinAux;
use crate::store::Mempool;
use bitcoin::{OutPoint, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_consensus::policy::{self, PolicyResult};
use rbitcoin_primitives::Fk;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[doc(hidden)]
pub const EXTRA_COMPACT_CAP: usize = 100;
#[doc(hidden)]
pub const RECENT_INVALID_CAP: usize = 4_096;

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
    /// Class C create height. `0` is the genesis coinbase only.
    pub create_height: u32,
    /// MTP of the block *before* the create block (BIP68 time locks). `0` if unknown.
    pub create_mtp: u32,
    pub is_coinbase: bool,
    /// Class A create fk when the UTXO provider resolved a confirmed coin.
    pub create_fk: Option<Fk>,
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
    /// Spent vs never-seen is [`Self::chain_prevout`].
    fn get_coin(&self, op: &OutPoint) -> Option<Coin>;

    fn get_txout(&self, op: &OutPoint) -> Option<TxOut> {
        self.get_coin(op).map(|c| c.txout)
    }

    /// Spent/missing vout on a *confirmed* create vs a parent we have never seen.
    fn chain_prevout(&self, op: &OutPoint) -> ChainPrevout {
        match self.get_coin(op) {
            Some(coin) => ChainPrevout::Unspent(coin),
            None => ChainPrevout::Unknown,
        }
    }

    /// Spender about to resolve coins (BIP68 time-lock MTP only when needed).
    fn note_spender(&self, _tx: &Transaction) {}

    /// Even stamp of the confirmed UTXO view. `None` while a confirm or
    /// disconnect is publishing spentness. Map and test providers stay at 0.
    fn utxo_view_stamp(&self) -> Option<u64> {
        Some(0)
    }
}

/// Confirmed-chain lookup for one prevout.
#[derive(Debug, Clone)]
pub enum ChainPrevout {
    Unspent(Coin),
    /// Create is confirmed; output spent, missing vout, or otherwise unusable.
    KnownUnavailable,
    Unknown,
}

/// Map-backed provider for tests and simple callers.
pub struct MapUtxoProvider {
    pub map: std::collections::HashMap<OutPoint, Coin>,
}

impl UtxoProvider for MapUtxoProvider {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        self.map.get(op).cloned()
    }
}

/// Max txs in one ancestor package.
pub const MAX_PACKAGE_COUNT: usize = 25;
/// Max total weight (WU) of one package.
pub const MAX_PACKAGE_WEIGHT: u64 = 404_000;
/// Default mempool weight budget (WU) — ~75 MvB class; eviction by worst chunk.
pub const DEFAULT_MAX_MEMPOOL_WEIGHT: u64 = 300_000_000;
/// Incremental relay feerate for RBF (same as Libre min).
pub const INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB: u64 =
    rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
/// Pure replace-by-fee-rate ratio (Libre Relay v27.1+): **1.25×** = 5/4.
pub const RBFR_RATIO_NUM: u64 = 5;
pub const RBFR_RATIO_DEN: u64 = 4;
/// Half-life of the eviction feerate bump once the mempool is no longer full.
pub const ROLLING_FEE_HALFLIFE_MS: u64 = 12 * 60 * 60 * 1000;

#[doc(hidden)]
pub use rbitcoin_consensus::clock::unix_ms;

/// Eviction bump decays by half toward `min_relay` once per halflife.
pub fn decayed_relay_floor(rolling: u64, min_relay: u64, elapsed_ms: u64) -> u64 {
    let rolling = rolling.max(min_relay);
    if elapsed_ms < ROLLING_FEE_HALFLIFE_MS {
        return rolling;
    }
    let steps = elapsed_ms / ROLLING_FEE_HALFLIFE_MS;
    let excess = rolling.saturating_sub(min_relay);
    let excess = if steps >= 63 { 0 } else { excess >> steps };
    min_relay.saturating_add(excess)
}

/// Min fee while full keeps the static bump and any evicted-rate floor.
/// Below the cap the evicted-rate floor decays.
pub fn relay_floor(
    min_relay: u64,
    rolling: u64,
    updated_ms: u64,
    now_ms: u64,
    near_full: bool,
) -> u64 {
    let bumped = if near_full {
        min_relay.saturating_add(INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB)
    } else {
        min_relay
    };
    let rolling_now = if near_full {
        rolling.max(min_relay)
    } else {
        decayed_relay_floor(rolling, min_relay, now_ms.saturating_sub(updated_ms))
    };
    bumped.max(rolling_now)
}

/// Outcome of a successful accept.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    pub txid: Txid,
    pub fee_sat: u64,
    /// Sigop-adjusted weight; `vsize = ceil(weight / 4)` is Core's `m_vsize`.
    pub weight: u64,
    pub slot: u32,
    /// Node-time seconds stamped on the durable record (Core `nTime`).
    pub accept_secs: u64,
    /// Mempool txids removed by full-RBF / RBFR when admitting this tx (empty if no conflict).
    pub replaced: Vec<Txid>,
    /// Electrum scripthashes (SHA256 of output scriptPubKeys) of **replaced** bodies,
    /// collected **before** RBF removal so wallet address tracks can drop zombie unconfs
    /// even when the old body is gone from the hub.
    pub replaced_scripthashes: Vec<[u8; 32]>,
    /// Replaced bodies, for package rollback to restore victims.
    pub replaced_txs: Vec<Transaction>,
    /// Accept times of [`Self::replaced_txs`], so a rollback restores each
    /// with its own time.
    pub replaced_accept_secs: std::collections::HashMap<Txid, u64>,
    /// Replaced txids that were trust-marked. Rollback puts the mark back
    /// before those bodies are re-admitted.
    pub replaced_trust: Vec<Txid>,
    /// Txids dropped to free a slot or the weight budget while admitting this tx.
    /// Distinct from [`Self::replaced`]. The admitted tx is not in this list
    /// when the commit succeeds.
    pub evicted: Vec<Txid>,
}

/// Why accept failed (policy / graph / durable / consensus script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    Policy(&'static str),
    MissingPrevout(OutPoint),
    /// Tx parked in the orphanage waiting on missing parent(s). Not a hard reject.
    /// `fresh` is true on first insert; re-delivery of the same parked tx is false.
    Orphaned {
        txid: Txid,
        missing: BTreeSet<Txid>,
        fresh: bool,
    },
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
    /// Sigop cost cannot fit the configured block-template budget, including
    /// its reserved coinbase allowance.
    TooManySigops {
        cost: u64,
    },
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Policy(s) => write!(f, "policy: {s}"),
            AcceptError::MissingPrevout(op) => write!(f, "missing prevout {op}"),
            AcceptError::Orphaned { txid, .. } => write!(f, "orphaned {txid}"),
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
            AcceptError::TooManySigops { .. } => f.write_str("bad-txns-too-many-sigops"),
        }
    }
}

impl AcceptError {
    /// Core debug.log / `was not accepted:` needle (`Policy` is the bare reason).
    pub fn mempool_reject_reason(&self) -> String {
        match self {
            AcceptError::Policy(s) => (*s).to_string(),
            other => other.to_string(),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Side effects of a recordable accept failure (recent-invalid / extra-compact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFailureRecord {
    Invalid(Txid),
    Extra,
}

impl From<MempoolError> for AcceptError {
    fn from(e: MempoolError) -> Self {
        match e {
            MempoolError::Full => AcceptError::Policy("mempool full"),
            other => AcceptError::Durable(other.to_string()),
        }
    }
}

fn is_trust_tx_fault(err: &AcceptError) -> bool {
    matches!(
        err,
        AcceptError::ImmatureCoinbase | AcceptError::NotFinal | AcceptError::NonBip68Final
    ) && rbitcoin_consensus::reason_is_warn_and_apply(&err.mempool_reject_reason())
}

/// Reorg eviction uses the same keep as [`ActiveMempool::evict_nonfinal`].
pub fn trust_keeps_structural(trust: bool, err: &AcceptError) -> bool {
    trust && is_trust_tx_fault(err)
}

fn trust_script_reason(trust: bool, err: &AcceptError) -> Option<String> {
    let AcceptError::Script(_) = err else {
        return None;
    };
    let reason = err.mempool_reject_reason();
    if !trust || !rbitcoin_consensus::reason_is_warn_and_apply(&reason) {
        return None;
    }
    Some(reason)
}

fn push_trust_warn(slot: &mut Option<Vec<String>>, reason: String) {
    slot.get_or_insert_with(Vec::new).push(reason);
}

fn warn_trust_tx(applied: bool, txid: Txid, reason: &str) {
    let verb = if applied { "applied" } else { "not applied" };
    rbitcoin_log::warn!("trust-peer: {verb} tx {txid}: {reason}");
}

fn duplicate_inputs(trust: bool, txid: Txid) -> AcceptError {
    if trust {
        warn_trust_tx(false, txid, "inputs-duplicate");
    }
    AcceptError::InputsDuplicate
}

fn kept_trust_structural(
    trust: bool,
    err: AcceptError,
) -> Result<Option<AcceptError>, AcceptError> {
    if trust && is_trust_tx_fault(&err) {
        Ok(Some(err))
    } else {
        Err(err)
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
        for i in 0..tx.input.len() {
            match chain_coins.get(i).and_then(|c| c.as_ref()) {
                Some(c) => {
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
#[doc(hidden)]
pub fn tx_has_witness(tx: &Transaction) -> bool {
    tx.input.iter().any(|i| !i.witness.is_empty())
}

/// Full BIP16 + BIP141 sigop cost (Core ATMP `GetTransactionSigOpCost`; P2SH
/// and witness flags match `STANDARD_SCRIPT_VERIFY_FLAGS`). Rejects a cost
/// that does not fit the configured template reserve.
#[doc(hidden)]
pub fn block_fit_sigop_cost(
    tx: &Transaction,
    prevouts: &[TxOut],
    reserved_sigops: u64,
) -> Result<u64, AcceptError> {
    let spks: Vec<&[u8]> = prevouts
        .iter()
        .map(|o| o.script_pubkey.as_bytes())
        .collect();
    let cost = rbitcoin_consensus::tx_sigop_cost(tx, &spks, true, true);
    if reserved_sigops.saturating_add(cost) > MAX_BLOCK_SIGOPS_COST {
        return Err(AcceptError::TooManySigops { cost });
    }
    Ok(cost)
}

#[doc(hidden)]
pub fn checked_fee_sat(tx: &Transaction, input_value: u64) -> Result<u64, AcceptError> {
    let mut output_value = 0u64;
    for output in &tx.output {
        output_value = output_value
            .checked_add(output.value.to_sat())
            .ok_or(AcceptError::Policy("bad-txns-txouttotal-toolarge"))?;
    }
    input_value
        .checked_sub(output_value)
        .ok_or(AcceptError::Policy("negative fee"))
}

/// Fee and sigop-adjusted weight of `tx` over resolved `prevouts`; `None`
/// if outputs exceed inputs.
#[doc(hidden)]
pub fn fee_and_adjusted_weight(
    tx: &Transaction,
    prevouts: &[TxOut],
    bytes_per_sigop: u64,
) -> Option<(u64, u64)> {
    let inn = prevouts
        .iter()
        .fold(0u64, |a, o| a.saturating_add(o.value.to_sat()));
    let out = tx
        .output
        .iter()
        .fold(0u64, |a, o| a.saturating_add(o.value.to_sat()));
    let fee = inn.checked_sub(out)?;
    let spks: Vec<&[u8]> = prevouts
        .iter()
        .map(|o| o.script_pubkey.as_bytes())
        .collect();
    let sigops = rbitcoin_consensus::tx_sigop_cost(tx, &spks, true, true);
    Some((
        fee,
        sigops_adjusted_weight(tx.weight().to_wu(), sigops, bytes_per_sigop),
    ))
}

#[doc(hidden)]
pub fn first_missing_outpoint(
    tx: &Transaction,
    missing: &BTreeSet<Txid>,
    extra: impl Fn(&OutPoint) -> bool,
) -> Option<OutPoint> {
    tx.input
        .iter()
        .map(|inp| inp.previous_output)
        .find(|op| missing.contains(&op.txid) && extra(op))
}

#[doc(hidden)]
pub fn verify_tx_scripts(tx: &Transaction, prevouts: Vec<TxOut>) -> Result<(), AcceptError> {
    if prevouts.len() != tx.input.len() {
        return Err(AcceptError::Script("prevout count mismatch".into()));
    }
    rbitcoin_consensus::verify_tx_scripts_detached(prevouts, tx.clone())
        .map_err(|e| AcceptError::Script(e.to_string()))
}

/// Knobs for [`ActiveMempool::prepare_admit`]. One argument so the admit
/// helper stays within the argument cap.
#[doc(hidden)]
pub struct PrepareOpts {
    pub fee_delta: i64,
    pub report_orphans: bool,
    pub min_relay: Option<u64>,
    pub waive: bool,
}

/// Result of accept prepare (resolve + policy + structural), before script verify.
///
/// Script runs outside the mempool exclusive lock; [`ActiveMempool::commit_after_script`]
/// re-checks and durable-commits.
#[derive(Debug, Clone)]
pub struct PreparedAdmit {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub fee_sat: u64,
    /// `prioritisetransaction` delta applied at prepare (min-relay / RBF).
    pub fee_delta: i64,
    pub weight: u64,
    /// Full BIP16 + BIP141 sigop cost (Core ATMP `GetTransactionSigOpCost`).
    pub sigop_cost: u64,
    pub prevouts: Vec<TxOut>,
    pub chain_coins: Vec<Option<Coin>>,
    pub utxo_us: u64,
    /// Accept time to persist instead of now. Set when a failed replacement
    /// puts an already-admitted conflict back, so it keeps its own time.
    pub keep_accept_secs: Option<u64>,
    /// Warn-and-apply faults. Logged only after [`ActiveMempool::finish_commit`]
    /// inserts the tx. Empty on the flag-off path.
    pub trust_warn: Option<Vec<String>>,
    /// This tx was already marked and is being put back. The new slot keeps
    /// the byte even when this admit itself does not warn.
    pub keep_mark: bool,
}

struct AdmitInputs {
    prevouts: Vec<TxOut>,
    chain_coins: Vec<Option<Coin>>,
    input_value: u64,
    utxo_us: u64,
}

/// Graph spend edges for one tx (conflicts + mempool parents).
#[doc(hidden)]
pub struct ConflictScan {
    pub direct_conflicts: BTreeSet<Txid>,
    pub parent_txids: BTreeSet<Txid>,
}

#[doc(hidden)]
pub enum EvictUntil {
    FreeSlot,
    WeightBudget,
}

/// What to do with orphans of a conflict that was just put back.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub enum RestoreOrphans {
    /// No walk is running. Start one for each restored tx.
    Promote,
    /// A walk is already running. Hand the restored txids back to it.
    Defer,
}

#[doc(hidden)]
pub struct IngestedLive {
    pub graph: TxGraph,
    pub bodies: std::collections::HashMap<Txid, Arc<Transaction>>,
    pub vin_aux: std::collections::HashMap<Txid, Vec<VinAux>>,
    /// `(txid, wtxid, accept_secs)` per loaded record.
    pub accept_secs: Vec<(Txid, Wtxid, u64)>,
    /// Txids whose slot trust byte was set.
    pub trust_kept: HashSet<Txid>,
}

/// Mempool with RAM TxGraph layered on durable store.
pub struct ActiveMempool {
    pub store: Mempool,
    pub graph: TxGraph,
    /// Cached tx bodies for graph rebuild / remove (live set only).
    pub bodies: std::collections::HashMap<Txid, Arc<Transaction>>,
    /// Per-vin aux from the packed sidecar (SH / purge). Missing only if a
    /// leftover record omitted it.
    pub vin_aux: std::collections::HashMap<Txid, Vec<VinAux>>,
    /// Evict worst chunks when live weight exceeds this.
    pub max_weight: u64,
    /// Side pool of txs waiting on missing parents (weight budget).
    pub orphanage: Orphanage,
    /// Stage µs for the most recent top-level [`Self::accept_tx`] / package member
    /// (includes nested orphan promote for that accept). Sampled by MempoolHub.
    pub last_accept_stages: AcceptStageUs,
    /// Overlay from `-limitclustercount` / `-limitclustersize` (re-applied after compact).
    pub cluster_count_overlay: Option<u32>,
    pub cluster_size_kvb_overlay: Option<u32>,
    /// Core `-minrelaytxfee` in sat/kvB (default Libre 100).
    pub min_relay_sat_kvb: u64,
    /// Highest evicted chunk feerate (sat/kvB). Decays toward min relay when not full.
    pub rolling_min_sat_kvb: u64,
    /// Unix ms when `rolling_min_sat_kvb` was last raised or decayed.
    pub rolling_updated_ms: u64,
    /// Txids recently rejected as invalid (not policy-reconsiderable).
    pub recent_invalid: HashSet<Txid>,
    /// Recent rejects / RBF replacements for compact fill and 1p1c.
    pub extra_compact: VecDeque<(Txid, Transaction)>,
    /// Ids removed by the latest `finish_commit` when that commit returns
    /// `Err` (the success path carries them on [`AcceptResult::evicted`]).
    pub last_evicted: Vec<Txid>,
    /// Bodies removed for replacement when `finish_commit` later returns
    /// `Err`. Success moves them onto [`AcceptResult::replaced_txs`].
    pub undone_replacements: Vec<Transaction>,
    /// Accept times of `undone_replacements`, read before their slots died.
    pub undone_accept_secs: std::collections::HashMap<Txid, u64>,
    /// `setmocktime` seconds, shared with the hub's clock (0 = wall).
    pub node_clock: Arc<AtomicU64>,
    /// Accept times of the records loaded at open, until the hub takes them.
    pub loaded_accept: Vec<(Txid, Wtxid, u64)>,
    /// Txids a trusted-session admit warned on. Eviction and restore read this.
    /// A flag-off open removes those transactions and their descendants. A
    /// removal that does not finish leaves the mark.
    pub trust_kept: HashSet<Txid>,
    /// Chain this node validates. `None` in unit tests that open a pool
    /// directly, so script flags stay pre-Inquisition. The node sets this
    /// after open.
    pub chain_params: Option<rbitcoin_consensus::ChainParams>,
}

/// A parked package member, taken out before admit.
///
/// `announcers` are the peers who announced it. The missing-parent set is
/// not kept: it is resolved again if the package puts the tx back.
pub struct LiftedOrphan {
    pub tx: Transaction,
    pub announcers: Vec<u64>,
    /// In-flight generation from the lift. Zero when the orphan was not taken.
    pub taken_gen: u64,
}

impl ActiveMempool {
    /// Share the hub's mock clock so stamped accept times follow `setmocktime`.
    pub fn set_node_clock(&mut self, clock: Arc<AtomicU64>) {
        self.node_clock = clock;
    }

    #[doc(hidden)]
    pub fn node_now_secs(&self) -> u64 {
        match self.node_clock.load(Ordering::Relaxed) {
            0 => unix_ms() / 1000,
            mock => mock,
        }
    }

    /// `(txid, wtxid, accept_secs)` of every record loaded at open. Empty
    /// after the first call; the hub indexes them for expiry and RPC.
    pub fn take_loaded_accept_times(&mut self) -> Vec<(Txid, Wtxid, u64)> {
        std::mem::take(&mut self.loaded_accept)
    }

    /// Evictions from a commit that returned `Err`. Empty after a success.
    pub fn take_failed_evictions(&mut self) -> Vec<Txid> {
        std::mem::take(&mut self.last_evicted)
    }

    /// Conflicts a failed `finish_commit` already removed. Empty after a success.
    pub fn take_undone_replacements(&mut self) -> Vec<Transaction> {
        self.undone_accept_secs.clear();
        std::mem::take(&mut self.undone_replacements)
    }
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

    /// Overlay Core `-bytespersigop` (`0` disables sigop-adjusted size).
    pub fn set_bytes_per_sigop(&mut self, bytes_per_sigop: u64) {
        self.graph.set_bytes_per_sigop(bytes_per_sigop);
    }

    /// Set the sigop reserve shared by admission and [`Self::template_budget`].
    pub fn set_block_reserved_sigops(&mut self, reserved_sigops: u64) {
        self.graph.set_block_reserved_sigops(reserved_sigops);
    }

    /// Overlay Core `-minrelaytxfee` (sat/kvB). `0` admits any non-negative fee.
    ///
    /// The rolling floor starts equal to the configured minimum. Lowering
    /// that minimum drops the seed. A floor already raised by eviction stays.
    pub fn set_min_relay_sat_kvb(&mut self, sat_kvb: u64) {
        if self.rolling_min_sat_kvb <= self.min_relay_sat_kvb {
            self.rolling_min_sat_kvb = sat_kvb;
        }
        self.min_relay_sat_kvb = sat_kvb;
    }

    pub fn min_relay_sat_kvb(&self) -> u64 {
        self.min_relay_sat_kvb
    }

    /// `persist=false` abandons any on-disk live set (Core `-persistmempool=0`).
    ///
    /// Bad magic, an unknown schema, or an in-range payload that does not
    /// decode is moved aside and the open retries empty. IO errors propagate.
    pub fn open_with_limit_persist(
        dir: impl Into<std::path::PathBuf>,
        max_weight: u64,
        persist: bool,
    ) -> Result<Self, MempoolError> {
        let dir = dir.into();
        match Self::open_loaded(&dir, max_weight, persist) {
            Ok(mp) => Ok(mp),
            Err(e) if Self::unreadable_sidecar(&e) => {
                let aside = crate::store::quarantine_sidecar(&dir)?;
                rbitcoin_log::warn!(
                    "mempool: unreadable sidecar ({e}); moved to {} and starting empty",
                    aside.display()
                );
                Self::open_loaded(&dir, max_weight, persist)
            }
            Err(e) => Err(e),
        }
    }

    #[doc(hidden)]
    pub fn unreadable_sidecar(err: &MempoolError) -> bool {
        matches!(
            err,
            MempoolError::BadMagic | MempoolError::BadSchema(_) | MempoolError::Corrupt(_)
        )
    }

    #[doc(hidden)]
    pub fn open_loaded(
        dir: &std::path::Path,
        max_weight: u64,
        persist: bool,
    ) -> Result<Self, MempoolError> {
        let mut store = Mempool::open_or_create(dir)?;
        if !persist {
            store.abandon_live()?;
        }
        let loaded = store.load_live_txs()?;
        let ingested = Self::ingest_loaded(loaded);
        store.set_live_count(ingested.graph.len() as u32);
        Ok(Self {
            store,
            graph: ingested.graph,
            bodies: ingested.bodies,
            vin_aux: ingested.vin_aux,
            max_weight,
            orphanage: Orphanage::new(),
            last_accept_stages: AcceptStageUs::default(),
            cluster_count_overlay: None,
            cluster_size_kvb_overlay: None,
            min_relay_sat_kvb: rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            rolling_min_sat_kvb: rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            rolling_updated_ms: unix_ms(),
            recent_invalid: HashSet::new(),
            extra_compact: VecDeque::new(),
            last_evicted: Vec::new(),
            undone_replacements: Vec::new(),
            undone_accept_secs: std::collections::HashMap::new(),
            node_clock: Arc::new(AtomicU64::new(0)),
            loaded_accept: ingested.accept_secs,
            trust_kept: ingested.trust_kept,
            chain_params: None,
        })
    }

    /// Signet Inquisition flags for mempool script checks. Unit tests leave
    /// this unset.
    pub fn set_chain_params(&mut self, params: rbitcoin_consensus::ChainParams) {
        self.chain_params = Some(params);
    }

    /// Buried script flags, with Inquisition opcodes overlaid from the next
    /// block height when [`Self::set_chain_params`] ran.
    fn verify_scripts_for_tip(
        &self,
        tx: &Transaction,
        prevouts: Vec<TxOut>,
        tip: ChainTipCtx,
    ) -> Result<(), AcceptError> {
        let mut flags = rbitcoin_consensus::ScriptVerifyFlags::buried(true, true, true, true, true);
        if let Some(params) = &self.chain_params {
            flags.heretical = params.heretical_at(tip.height.saturating_add(1));
        }
        if flags.heretical == rbitcoin_consensus::HereticalFlags::default() {
            return verify_tx_scripts(tx, prevouts);
        }
        rbitcoin_consensus::verify_tx_scripts_with_flags(prevouts, tx.clone(), flags)
            .map_err(|e| AcceptError::Script(e.to_string()))
    }

    /// Drop every LIVE trust slot and its descendants. A flag-off open uses
    /// this so a warned body is not an ordinary pool transaction.
    ///
    /// A slot or a descendant that is still in the graph stays marked, and
    /// this returns an error before any trust byte is cleared and before
    /// deaths are synced. A dead slot is not reloaded, so its trust byte can
    /// stay.
    pub fn discard_trust_marks(&mut self) -> Result<(), MempoolError> {
        let marked = self.live_trust_slots();
        let mut removed = false;
        for (slot, txid) in marked {
            let in_graph = self.graph.get(&txid).is_some_and(|e| e.slot == slot);
            if in_graph {
                self.unlink_marked_tree(&txid)?;
            } else {
                self.store.mark_slot_dead(slot)?;
            }
            removed = true;
        }
        if self.live_trust_slots().is_empty() {
            self.trust_kept.clear();
            if removed {
                self.store.sync_deaths()?;
            }
            return Ok(());
        }
        Err(MempoolError::Corrupt("marked tx still live"))
    }

    /// Unlink descendants, then `txid`. The root stays when a descendant stays.
    fn unlink_marked_tree(&mut self, txid: &Txid) -> Result<(), MempoolError> {
        let mut seen = BTreeSet::new();
        self.unlink_marked_from(txid, &mut seen)
    }

    fn unlink_marked_from(
        &mut self,
        txid: &Txid,
        seen: &mut BTreeSet<Txid>,
    ) -> Result<(), MempoolError> {
        if !seen.insert(*txid) {
            return Ok(());
        }
        let children: Vec<Txid> = self
            .graph
            .get(txid)
            .map(|e| e.children.iter().copied().collect())
            .unwrap_or_default();
        for child in children {
            self.unlink_marked_from(&child, seen)?;
        }
        if !self.graph.contains(txid) {
            return Ok(());
        }
        if self.unlink_txid(txid).is_err() || self.graph.contains(txid) {
            return Err(MempoolError::Corrupt("marked tx still live"));
        }
        Ok(())
    }

    /// LIVE slots whose trust byte is set, in slot order.
    fn live_trust_slots(&self) -> Vec<(u32, Txid)> {
        use crate::store::{SLOTS_HEADER, SLOT_LIVE, SLOT_REC};
        use bitcoin::hashes::Hash;

        let mut out = Vec::new();
        for slot in 0..self.store.slot_cap {
            let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
            if self.store.slots[off] != SLOT_LIVE || self.store.slots[off + 1] == 0 {
                continue;
            }
            let txid =
                Txid::from_byte_array(self.store.slots[off + 16..off + 48].try_into().unwrap());
            out.push((slot, txid));
        }
        out
    }

    pub fn live_count(&self) -> usize {
        self.graph.len()
    }

    /// `(meta syncs, slots syncs from sync_deaths)` since open.
    #[cfg(debug_assertions)]
    pub fn death_sync_counts(&self) -> (u64, u64) {
        (self.store.meta_syncs(), self.store.slots_syncs())
    }

    pub fn mempool_min_fee_sat_kvb(&self) -> u64 {
        let near_full = self
            .graph
            .total_weight()
            .saturating_add(policy::MAX_STANDARD_TX_WEIGHT)
            > self.max_weight;
        relay_floor(
            self.min_relay_sat_kvb,
            self.rolling_min_sat_kvb,
            self.rolling_updated_ms,
            unix_ms(),
            near_full,
        )
    }

    #[doc(hidden)]
    pub fn note_evicted_feerate(&mut self, rate_sat_kvb: u64) {
        let now = unix_ms();
        let decayed = decayed_relay_floor(
            self.rolling_min_sat_kvb,
            self.min_relay_sat_kvb,
            now.saturating_sub(self.rolling_updated_ms),
        );
        // One sat/kvB above the evicted chunk so that same-rate tx cannot re-enter.
        let raised = rate_sat_kvb.saturating_add(1);
        let next = decayed.max(raised);
        if next > self.rolling_min_sat_kvb {
            rbitcoin_log::info!("mempool: rolling minimum fee bumped");
        }
        self.rolling_min_sat_kvb = next;
        self.rolling_updated_ms = now;
    }

    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    pub fn flush(&mut self) -> Result<(), MempoolError> {
        self.store.flush()
    }

    /// Best-effort sidecar persist of dirty accepts (no generation bump).
    pub fn persist_if_dirty(&mut self) -> Result<(), MempoolError> {
        self.store.persist_due()
    }

    /// Time-based sidecar persist (5 s). Body `sync_data`, then new LIVE slots, then meta.
    pub fn persist_due(&mut self) -> Result<(), MempoolError> {
        self.store.persist_due()
    }

    /// Compact durable storage (drop DEAD holes) and rebuild RAM graph.
    pub fn compact(&mut self) -> Result<(u32, usize), MempoolError> {
        let (live, body_len) = self.store.compact()?;
        let loaded = self.store.load_live_txs()?;
        let mut ingested = Self::ingest_loaded(loaded);
        ingested
            .graph
            .set_cluster_limits(self.cluster_count_overlay, self.cluster_size_kvb_overlay);
        ingested
            .graph
            .set_bytes_per_sigop(self.graph.bytes_per_sigop());
        ingested
            .graph
            .set_block_reserved_sigops(self.graph.block_reserved_sigops());
        self.graph = ingested.graph;
        self.bodies = ingested.bodies;
        self.vin_aux = ingested.vin_aux;
        self.trust_kept = ingested.trust_kept;
        self.store.set_live_count(live);
        Ok((live, body_len))
    }

    #[doc(hidden)]
    pub fn ingest_loaded(loaded: Vec<crate::store::LiveTx>) -> IngestedLive {
        let mut graph = TxGraph::new();
        let mut bodies = std::collections::HashMap::new();
        let mut vin_aux = std::collections::HashMap::new();
        let mut items = Vec::with_capacity(loaded.len());
        let mut accept_secs = Vec::with_capacity(loaded.len());
        let mut trust_kept = HashSet::new();
        for live in loaded {
            let p = live.packed;
            if live.trust_kept {
                trust_kept.insert(p.txid);
            }
            accept_secs.push((p.txid, p.wtxid, p.accept_secs));
            let tx = Arc::new(p.tx);
            let entry = TxEntry {
                txid: p.txid,
                wtxid: p.wtxid,
                fee_sat: p.fee_sat,
                weight: p.weight,
                // Migrated from schema ≤ 2: unknown until
                // [`ActiveMempool::recompute_missing_sigops`]. MAX never fits a block.
                sigop_cost: p.sigop_cost.unwrap_or(u64::MAX),
                slot: live.slot,
                parents: BTreeSet::new(),
                children: BTreeSet::new(),
            };
            vin_aux.insert(p.txid, p.vins);
            bodies.insert(p.txid, Arc::clone(&tx));
            items.push((entry, tx));
        }
        graph.rebuild_from(items);
        IngestedLive {
            graph,
            bodies,
            vin_aux,
            accept_secs,
            trust_kept,
        }
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
    /// RAM graph is source of truth. Packed body is appended in RAM; sidecar
    /// write waits for [`Self::persist_due`] (5 s, body synced before LIVE slots)
    /// or [`Self::flush`]. Crash may lose admits since the last persist.
    /// When prevouts are missing from both mempool and chain UTXO, the tx is
    /// parked in the [`Orphanage`] (weight budget) and
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
        match self.accept_tx_with(tx, utxos, tip, 0, true, None) {
            Ok(r) => {
                self.promote_orphans_of(r.txid, utxos, tip);
                Ok(r)
            }
            Err(AcceptError::Orphaned { missing, .. }) => Err(self.park_orphan(tx, missing)),
            Err(e) => {
                self.restore_undone(utxos, tip);
                self.note_accept_failure(tx, &e);
                Err(e)
            }
        }
    }

    #[doc(hidden)]
    pub fn accept_tx_with(
        &mut self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        fee_delta: i64,
        report_orphans: bool,
        min_relay: Option<u64>,
    ) -> Result<AcceptResult, AcceptError> {
        // Local `accept_tx` stays strict. The session bit is on the hub admit.
        let waive = false;
        let mut prep = self.prepare_admit(
            tx,
            utxos,
            tip,
            PrepareOpts {
                fee_delta,
                report_orphans,
                min_relay,
                waive,
            },
        )?;
        self.last_accept_stages.utxo_us = prep.utxo_us;
        let t_script = Instant::now();
        let script_res = self.verify_scripts_for_tip(tx, prep.prevouts.clone(), tip);
        self.last_accept_stages.script_us = self
            .last_accept_stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        if let Err(e) = script_res {
            match trust_script_reason(waive, &e) {
                Some(reason) => push_trust_warn(&mut prep.trust_warn, reason),
                None => {
                    self.note_accept_failure(tx, &e);
                    return Err(e);
                }
            }
        }
        self.commit_after_script(tx, prep)
    }

    #[doc(hidden)]
    pub fn note_conflict_and_parent(
        &self,
        txid: Txid,
        op: OutPoint,
        mut scan: Option<&mut ConflictScan>,
    ) -> Result<Option<Txid>, AcceptError> {
        if let Some(c) = self.graph.conflict_txid(&op) {
            if c != txid {
                if let Some(s) = scan.as_mut() {
                    s.direct_conflicts.insert(c);
                }
            }
        }
        if let Some(creator) = self.graph.creator(&op) {
            if !self.graph.mempool_utxo(&op) {
                if let Some(c) = self.graph.conflict_txid(&op) {
                    if let Some(s) = scan.as_mut() {
                        s.direct_conflicts.insert(c);
                    }
                } else {
                    let parent_tx = self
                        .bodies
                        .get(&creator)
                        .ok_or(AcceptError::Durable("parent body missing".into()))?;
                    if (op.vout as usize) >= parent_tx.output.len() {
                        return Err(AcceptError::MissingPrevout(op));
                    }
                    return Err(AcceptError::Policy("mempool double-spend"));
                }
            }
            if let Some(s) = scan.as_mut() {
                s.parent_txids.insert(creator);
            }
            return Ok(Some(creator));
        }
        Ok(None)
    }

    #[doc(hidden)]
    pub fn scan_conflicts_and_parents(
        &self,
        txid: Txid,
        tx: &Transaction,
        chain_coins: &[Option<Coin>],
    ) -> Result<ConflictScan, AcceptError> {
        let mut scan = ConflictScan {
            direct_conflicts: BTreeSet::new(),
            parent_txids: BTreeSet::new(),
        };
        for (i, inp) in tx.input.iter().enumerate() {
            let op = inp.previous_output;
            if let Some(creator) = self.note_conflict_and_parent(txid, op, Some(&mut scan))? {
                if !self.bodies.contains_key(&creator) {
                    return Err(AcceptError::Durable("parent body missing".into()));
                }
            } else if chain_coins.get(i).and_then(|c| c.as_ref()).is_none() {
                return Err(AcceptError::MissingPrevout(op));
            }
        }
        Ok(scan)
    }

    /// Graph peek + UTXO resolve (`&self`: callers may hold a read lock).
    ///
    /// `report_orphans`: missing parents become [`AcceptError::Orphaned`] (caller
    /// may [`Self::park_orphan`]); otherwise [`AcceptError::MissingPrevout`].
    pub fn prepare_admit(
        &self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        opts: PrepareOpts,
    ) -> Result<PreparedAdmit, AcceptError> {
        let PrepareOpts {
            fee_delta,
            report_orphans,
            min_relay,
            waive,
        } = opts;
        if tx.is_coinbase() {
            return Err(AcceptError::Coinbase);
        }
        let txid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == wtxid {
                return Err(AcceptError::Duplicate(txid));
            }
            // Same txid, different witness (Core testmempoolaccept /
            // mempool_accept_wtxid.py).
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        // Already parked: soft re-announce of the same orphan.
        if report_orphans {
            if let Some(missing) = self.orphanage.missing_of(&txid).cloned() {
                return Err(AcceptError::Orphaned {
                    txid,
                    missing,
                    fresh: false,
                });
            }
        }

        // Finding 011: duplicate inputs before any value sum (phantom fee).
        {
            let mut seen = BTreeSet::new();
            for inp in &tx.input {
                if !seen.insert(inp.previous_output) {
                    return Err(duplicate_inputs(waive, txid));
                }
            }
        }

        let AdmitInputs {
            prevouts,
            chain_coins,
            input_value,
            utxo_us,
        } = self.collect_admit_inputs(tx, txid, utxos, report_orphans)?;

        let trust_structural = match check_mempool_structural(tx, &chain_coins, tip) {
            Ok(()) => None,
            Err(err) => kept_trust_structural(waive, err)?,
        };

        let sigop_cost = block_fit_sigop_cost(tx, &prevouts, self.graph.block_reserved_sigops())?;

        let fee_sat = checked_fee_sat(tx, input_value)?;
        let weight = tx.weight().to_wu();
        let admit_fee = (i128::from(fee_sat).saturating_add(i128::from(fee_delta))).max(0) as u64;

        let floor = self.mempool_min_fee_sat_kvb();
        let min_relay = min_relay.unwrap_or(floor);
        // Standardness on raw weight; the fee floor on sigop-adjusted vsize.
        if let PolicyResult::NonStandard(s) =
            policy::check_libre_admission_at(tx, admit_fee, weight, 0)
        {
            return Err(AcceptError::Policy(s));
        }
        let adj = sigops_adjusted_weight(weight, sigop_cost, self.graph.bytes_per_sigop());
        if !policy::meets_min_relay_fee_at(admit_fee, adj, min_relay) {
            return Err(AcceptError::Policy(if floor > self.min_relay_sat_kvb {
                "mempool min fee"
            } else {
                "min relay fee"
            }));
        }
        let trust_warn = trust_structural
            .as_ref()
            .map(|err| vec![err.mempool_reject_reason()]);

        Ok(PreparedAdmit {
            txid,
            wtxid,
            fee_sat,
            fee_delta,
            weight,
            sigop_cost,
            prevouts,
            chain_coins,
            utxo_us,
            keep_accept_secs: None,
            trust_warn,
            keep_mark: false,
        })
    }

    fn collect_admit_inputs(
        &self,
        tx: &Transaction,
        txid: Txid,
        utxos: &impl UtxoProvider,
        report_orphans: bool,
    ) -> Result<AdmitInputs, AcceptError> {
        let t_utxo = Instant::now();
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(tx.input.len());
        let mut chain_coins: Vec<Option<Coin>> = Vec::with_capacity(tx.input.len());
        let mut missing_parents: BTreeSet<Txid> = BTreeSet::new();
        let mut input_value = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            let mempool_parent = self.note_conflict_and_parent(txid, op, None)?;
            let (txout, chain_coin) = if let Some(creator) = mempool_parent {
                let parent_tx = self
                    .bodies
                    .get(&creator)
                    .ok_or(AcceptError::Durable("parent body missing".into()))?;
                match parent_tx.output.get(op.vout as usize).cloned() {
                    Some(o) => (o, None),
                    None => return Err(AcceptError::MissingPrevout(op)),
                }
            } else {
                match utxos.chain_prevout(&op) {
                    ChainPrevout::Unspent(coin) => (coin.txout.clone(), Some(coin)),
                    ChainPrevout::KnownUnavailable => {
                        return Err(AcceptError::MissingPrevout(op));
                    }
                    ChainPrevout::Unknown => {
                        missing_parents.insert(op.txid);
                        continue;
                    }
                }
            };
            input_value = input_value.saturating_add(txout.value.to_sat());
            prevouts.push(txout);
            chain_coins.push(chain_coin);
        }
        let utxo_us = t_utxo.elapsed().as_micros() as u64;
        if !missing_parents.is_empty() {
            return Err(self.missing_parent_error(tx, txid, missing_parents, report_orphans));
        }
        Ok(AdmitInputs {
            prevouts,
            chain_coins,
            input_value,
            utxo_us,
        })
    }

    fn missing_parent_error(
        &self,
        tx: &Transaction,
        txid: Txid,
        missing_parents: BTreeSet<Txid>,
        report_orphans: bool,
    ) -> AcceptError {
        if let Some(op) = first_missing_outpoint(tx, &missing_parents, |op| {
            self.recent_invalid.contains(&op.txid)
        }) {
            return AcceptError::MissingPrevout(op);
        }
        if report_orphans {
            match policy::check_libre_shape(tx, tx.weight().to_wu()) {
                policy::PolicyResult::Standard => {}
                policy::PolicyResult::NonStandard(s) => return AcceptError::Policy(s),
            }
            return AcceptError::Orphaned {
                txid,
                missing: missing_parents,
                fresh: true,
            };
        }
        AcceptError::MissingPrevout(
            first_missing_outpoint(tx, &missing_parents, |_| true)
                .expect("missing_parents is built from tx.input"),
        )
    }

    /// Park `tx` waiting on `missing` parent txids (from `prepare_admit`).
    pub fn park_orphan(&mut self, tx: &Transaction, missing: BTreeSet<Txid>) -> AcceptError {
        self.park_orphan_from(tx, missing, None)
    }

    /// Park with a P2P announcer peer id.
    pub fn park_orphan_from(
        &mut self,
        tx: &Transaction,
        missing: BTreeSet<Txid>,
        from: Option<u64>,
    ) -> AcceptError {
        let txid = tx.compute_txid();
        if self.graph.get(&txid).is_some() {
            return AcceptError::Duplicate(txid);
        }
        if let Some(parked) = self.orphanage.missing_of(&txid).cloned() {
            if self.orphanage.contains_wtxid(&tx.compute_wtxid()) {
                if let Some(peer) = from {
                    self.orphanage.add_announcer(&txid, peer);
                }
                return AcceptError::Orphaned {
                    txid,
                    missing: parked,
                    fresh: false,
                };
            }
        }
        if missing.is_empty() {
            return AcceptError::MissingPrevout(tx.input[0].previous_output);
        }
        if self
            .orphanage
            .insert_from(tx.clone(), missing.clone(), from)
        {
            AcceptError::Orphaned {
                txid,
                missing,
                fresh: true,
            }
        } else {
            AcceptError::MissingPrevout(tx.input[0].previous_output)
        }
    }

    /// Take orphans waiting on `parent` (hub promote outside the write lock).
    pub fn take_orphan_children(&mut self, parent: Txid) -> Vec<OrphanSnapshot> {
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
    ) -> Result<AcceptResult, AcceptError> {
        self.finish_commit(tx, prep, true)
    }

    /// Insert without trimming. `submitpackage` trims once after every member
    /// is in, so a parent is not dropped before its child can pay for it.
    pub fn commit_after_script_defer_trim(
        &mut self,
        tx: &Transaction,
        prep: PreparedAdmit,
    ) -> Result<AcceptResult, AcceptError> {
        self.finish_commit(tx, prep, false)
    }

    #[doc(hidden)]
    pub fn finish_commit(
        &mut self,
        tx: &Transaction,
        prep: PreparedAdmit,
        trim: bool,
    ) -> Result<AcceptResult, AcceptError> {
        self.undone_replacements.clear();
        self.undone_accept_secs.clear();
        let (conflict_set, fee_sat, adj_weight) = self.plan_after_script(tx, &prep)?;
        let txid = prep.txid;
        let weight = prep.weight;

        let mut replaced_scripthashes: Vec<[u8; 32]> = Vec::new();
        let mut replaced_txs: Vec<Transaction> = Vec::new();
        for c in &conflict_set {
            if let Some(at) = self
                .graph
                .get(c)
                .and_then(|e| self.store.live_accept_secs(e.slot))
            {
                self.undone_accept_secs.insert(*c, at);
            }
            if let Some(old) = self.bodies.get(c) {
                let old_tx = (**old).clone();
                self.note_extra(&old_tx);
                for o in &old_tx.output {
                    replaced_scripthashes
                        .push(rbitcoin_store::script_hash(o.script_pubkey.as_bytes()));
                }
                replaced_txs.push(old_tx);
            }
        }
        replaced_scripthashes.sort_unstable();
        replaced_scripthashes.dedup();

        // Kept until success so a later error can put these bodies back.
        // `unlink_txid` drops the trust mark. Put it back if this commit
        // does not finish, so the restore admits the victim again.
        let kept_conflicts: Vec<Txid> = conflict_set
            .iter()
            .copied()
            .filter(|id| self.trust_kept.contains(id))
            .collect();
        self.undone_replacements = replaced_txs;
        for c in conflict_set.iter().rev() {
            let _ = self.unlink_txid(c);
        }
        // A failed sync leaves `deaths_unsynced` set for `persist_due`.
        let _ = self.store.sync_deaths();

        self.last_evicted.clear();
        let mut evicted = match self.ensure_free_slot(Some(txid)) {
            Ok(evicted) => evicted,
            Err(e) => {
                self.trust_kept.extend(kept_conflicts);
                return Err(e);
            }
        };

        let aux = Self::vin_aux_from_prep(tx, &prep);
        let accept_secs = prep
            .keep_accept_secs
            .unwrap_or_else(|| self.node_now_secs());
        let t_dur = Instant::now();
        let slot = match self.store.append_live_tx(
            tx,
            &txid,
            &prep.wtxid,
            fee_sat,
            weight,
            prep.sigop_cost,
            accept_secs,
            &aux,
        ) {
            Ok(slot) => slot,
            Err(e) => {
                self.last_evicted = evicted;
                self.trust_kept.extend(kept_conflicts);
                return Err(e.into());
            }
        };
        self.last_accept_stages.durable_us = self
            .last_accept_stages
            .durable_us
            .saturating_add(t_dur.elapsed().as_micros() as u64);

        let entry = TxEntry {
            txid,
            wtxid: prep.wtxid,
            fee_sat,
            weight,
            sigop_cost: prep.sigop_cost,
            slot,
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        };
        let body = Arc::new(tx.clone());
        self.graph.insert(entry, tx);
        self.bodies.insert(txid, Arc::clone(&body));
        self.vin_aux.insert(txid, aux);

        if trim {
            match self.evict_to_budget(Some(txid)) {
                Ok(more) => evicted.extend(more),
                Err(e) => {
                    self.last_evicted = evicted;
                    self.trust_kept.extend(kept_conflicts);
                    return Err(e);
                }
            }
        }
        // A descendant of an evicted parent leaves with that tree.
        // A lone protected tx stays.
        if trim && !self.graph.contains(&txid) {
            self.last_evicted = evicted;
            self.trust_kept.extend(kept_conflicts);
            return Err(AcceptError::Policy("mempool full"));
        }
        if prep.trust_warn.is_some() || prep.keep_mark {
            self.trust_kept.insert(txid);
            self.store.set_slot_trust_kept(slot, true);
        }
        self.last_evicted.clear();
        debug_assert!(
            !evicted.contains(&txid),
            "a successful admit is not in its own eviction set"
        );
        if let Some(reasons) = &prep.trust_warn {
            for reason in reasons {
                rbitcoin_log::warn!("trust-peer: applied tx {txid}: {reason}");
            }
        }
        let replaced_txs = std::mem::take(&mut self.undone_replacements);
        let replaced_accept_secs = std::mem::take(&mut self.undone_accept_secs);

        Ok(AcceptResult {
            txid,
            fee_sat,
            weight: adj_weight,
            slot,
            accept_secs,
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes,
            replaced_txs,
            replaced_accept_secs,
            replaced_trust: kept_conflicts,
            evicted,
        })
    }

    /// Prepare + RBF/cluster checks with no graph or store mutation.
    /// `weight` in the result is sigop-adjusted.
    pub fn evaluate_after_script(
        &self,
        tx: &Transaction,
        prep: PreparedAdmit,
    ) -> Result<AcceptResult, AcceptError> {
        let (conflict_set, fee_sat, weight) = self.plan_after_script(tx, &prep)?;
        Ok(AcceptResult {
            txid: prep.txid,
            fee_sat,
            weight,
            slot: 0,
            accept_secs: self.node_now_secs(),
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes: Vec::new(),
            replaced_txs: Vec::new(),
            replaced_accept_secs: std::collections::HashMap::new(),
            replaced_trust: Vec::new(),
            evicted: Vec::new(),
        })
    }

    /// An unconfirmed input on a replacement must be a parent of the direct
    /// conflicts. Spending an output of a direct conflict is
    /// `bad-txns-spends-conflicting-tx`.
    #[doc(hidden)]
    pub fn reject_new_unconfirmed(
        &self,
        tx: &Transaction,
        direct: &BTreeSet<Txid>,
    ) -> Result<(), AcceptError> {
        let mut parents_of_conflicts = BTreeSet::new();
        for id in direct {
            let conflict = self
                .bodies
                .get(id)
                .ok_or_else(|| AcceptError::Durable("conflict body missing".into()))?;
            for inp in &conflict.input {
                parents_of_conflicts.insert(inp.previous_output.txid);
            }
        }
        for inp in &tx.input {
            let parent = inp.previous_output.txid;
            if !self.bodies.contains_key(&parent) {
                continue;
            }
            if !parents_of_conflicts.contains(&parent) {
                // Spending the output of a tx this replacement evicts. Core
                // names that case; any other new unconfirmed parent is the
                // broader Libre refusal.
                if direct.contains(&parent) {
                    return Err(AcceptError::Policy("bad-txns-spends-conflicting-tx"));
                }
                return Err(AcceptError::Policy("adds unconfirmed input"));
            }
        }
        Ok(())
    }

    /// Returns (conflict set, fee, sigop-adjusted weight).
    #[doc(hidden)]
    pub fn plan_after_script(
        &self,
        tx: &Transaction,
        prep: &PreparedAdmit,
    ) -> Result<(BTreeSet<Txid>, u64, u64), AcceptError> {
        let txid = prep.txid;
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == prep.wtxid {
                return Err(AcceptError::Duplicate(txid));
            }
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        if self.orphanage.contains(&txid) {
            let missing = self
                .orphanage
                .missing_of(&txid)
                .cloned()
                .unwrap_or_default();
            return Err(AcceptError::Orphaned {
                txid,
                missing,
                fresh: false,
            });
        }

        let scan = self.scan_conflicts_and_parents(txid, tx, &prep.chain_coins)?;

        let fee_sat = prep.fee_sat;
        let weight =
            sigops_adjusted_weight(prep.weight, prep.sigop_cost, self.graph.bytes_per_sigop());
        let admit_fee =
            (i128::from(fee_sat).saturating_add(i128::from(prep.fee_delta))).max(0) as u64;

        let conflict_set = if !scan.direct_conflicts.is_empty() {
            let direct: Vec<Txid> = scan.direct_conflicts.iter().copied().collect();
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
        let parent_txids = scan.parent_txids;
        // Cluster limits count raw weight (Libre): at 20 B/sigop an adjusted
        // cap would reject any tx above ~20,200 sigop cost.
        let (n_members, base_w) = self
            .graph
            .connected_weight_except(&parent_txids, &conflict_set);
        let combined_w = base_w.saturating_add(prep.weight);
        if n_members + 1 > self.graph.cluster_count_limit()
            || combined_w.saturating_add(3) / 4 > self.graph.cluster_vsize_limit()
        {
            return Err(AcceptError::ClusterTooLarge {
                count: n_members + 1,
                weight: combined_w,
            });
        }
        // Parents of the direct conflicts only, not their ancestor closure.
        // After the cap, so an over-size cluster is `too-large-cluster`.
        if !scan.direct_conflicts.is_empty() {
            self.reject_new_unconfirmed(tx, &scan.direct_conflicts)?;
        }
        // Core `bad-txns-spends-conflicting-tx`. A parent in the conflict set
        // is evicted by this accept, and its outputs with it.
        if parent_txids.iter().any(|p| conflict_set.contains(p)) {
            return Err(AcceptError::Policy("bad-txns-spends-conflicting-tx"));
        }

        Ok((conflict_set, fee_sat, weight))
    }

    /// Re-try orphans that listed `parent` as missing.
    ///
    /// Uses `accept_tx_with` (not top-level accept_tx) so stage timers accumulate
    /// on the parent admit that unlocked the orphan chain. Public for hub staged commit.
    ///
    /// A worklist, so a parked chain does not keep one frame per descendant.
    /// The first child is admitted, then its descendants, then the next sibling.
    ///
    /// A child that still misses another parent goes back to the orphanage.
    /// Conflicts put back by that failure join this same list.
    pub fn promote_orphans_of(
        &mut self,
        parent: Txid,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) {
        let mut queue = VecDeque::new();
        self.push_orphan_children(parent, &mut queue);
        while let Some(child) = queue.pop_front() {
            match self.accept_tx_with(&child.tx, utxos, tip, 0, true, None) {
                Ok(r) => {
                    self.orphanage
                        .forget_taken_gen(&child.tx.compute_txid(), child.taken_gen);
                    self.push_orphan_children(r.txid, &mut queue);
                }
                Err(e) => {
                    if let AcceptError::Orphaned { missing, .. } = e {
                        let _ = self.park_announced(&child.tx, missing, &child.announcers);
                    } else {
                        self.orphanage
                            .forget_taken_gen(&child.tx.compute_txid(), child.taken_gen);
                    }
                    for id in self.restore_conflicts(utxos, tip, RestoreOrphans::Defer) {
                        self.push_orphan_children(id, &mut queue);
                    }
                }
            }
        }
    }

    /// Orphans of `parent`, earlier children still ahead of later ones.
    #[doc(hidden)]
    pub fn push_orphan_children(&mut self, parent: Txid, queue: &mut VecDeque<OrphanSnapshot>) {
        for child in self.orphanage.take_children_of(&parent).into_iter().rev() {
            queue.push_front(child);
        }
    }

    /// Ensure the durable slot table has a FREE/DEAD entry for the next append.
    ///
    /// Order: if full of LIVE, **grow** the slot table first (weight may still have
    /// headroom — mainnet 4k-slot stall); if at max cap, **evict** worst chunks.
    /// Never surface as store corruption.
    #[doc(hidden)]
    pub fn ensure_free_slot(&mut self, protect: Option<Txid>) -> Result<Vec<Txid>, AcceptError> {
        if self.store.has_free_slot() {
            return Ok(Vec::new());
        }
        match self.store.grow_slots() {
            Ok(()) => {
                if self.store.has_free_slot() {
                    return Ok(Vec::new());
                }
            }
            Err(MempoolError::Full) => {}
            Err(e) => return Err(e.into()),
        }
        let gone = self.evict_worst_chunks(protect, EvictUntil::FreeSlot)?;
        if self.store.has_free_slot() {
            return Ok(gone);
        }
        self.last_evicted = gone;
        Err(AcceptError::Policy("mempool full"))
    }

    /// Remove lowest-feerate chunks until `total_weight <= max_weight`.
    ///
    /// Prefer not to evict `protect` (the just-accepted tx). Returns every txid dropped.
    pub fn evict_to_budget(&mut self, protect: Option<Txid>) -> Result<Vec<Txid>, AcceptError> {
        self.evict_worst_chunks(protect, EvictUntil::WeightBudget)
    }

    #[doc(hidden)]
    pub fn evict_worst_chunks(
        &mut self,
        protect: Option<Txid>,
        until: EvictUntil,
    ) -> Result<Vec<Txid>, AcceptError> {
        let mut gone = Vec::new();
        loop {
            match until {
                EvictUntil::FreeSlot => {
                    if self.store.has_free_slot() {
                        break;
                    }
                }
                EvictUntil::WeightBudget => {
                    if self.graph.total_weight() <= self.max_weight {
                        break;
                    }
                }
            }
            let n = self.evict_worst_chunk_once(protect)?;
            if n.is_empty() {
                break;
            }
            gone.extend(n);
        }
        Ok(gone)
    }

    /// One worst-chunk pass. Empty means stop.
    #[doc(hidden)]
    pub fn evict_worst_chunk_once(
        &mut self,
        protect: Option<Txid>,
    ) -> Result<Vec<Txid>, AcceptError> {
        let Some((_rep, chunk)) = self.graph.worst_chunk() else {
            return Ok(Vec::new());
        };
        if chunk.txids.len() == 1 && protect == chunk.txids.first().copied() {
            return Ok(Vec::new());
        }
        let evicted_rate = chunk.fee_rate_sat_per_kvb();
        self.note_evicted_feerate(evicted_rate);
        let mut gone = Vec::new();
        for t in &chunk.txids {
            if protect == Some(*t) {
                continue;
            }
            if self.graph.contains(t) {
                gone.extend(self.unlink_tree(t));
            }
        }
        let _ = self.store.sync_deaths();
        Ok(gone)
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
        for tx in txs {
            if tx.is_coinbase() {
                return Err(AcceptError::Coinbase);
            }
            let id = tx.compute_txid();
            if !seen.insert(id) {
                return Err(AcceptError::Duplicate(id));
            }
        }
        // `seen` still holds this tx and every tx after it. An input that
        // names one of those txids spends a parent that is not earlier in
        // the package, including a tx that spends its own txid.
        for tx in txs {
            for inp in &tx.input {
                if seen.contains(&inp.previous_output.txid) {
                    return Err(AcceptError::PackageNotTopo);
                }
            }
            seen.remove(&tx.compute_txid());
        }
        Ok(())
    }

    /// Core `IsChildWithParents`: last tx spends every other package member.
    pub fn package_is_child_with_direct_parents(txs: &[Transaction]) -> bool {
        if txs.len() < 2 {
            return false;
        }
        let spent: BTreeSet<Txid> = txs[txs.len() - 1]
            .input
            .iter()
            .map(|i| i.previous_output.txid)
            .collect();
        txs[..txs.len() - 1]
            .iter()
            .all(|tx| spent.contains(&tx.compute_txid()))
    }

    /// Last tx is a child; every other member is an in-package ancestor of it.
    #[doc(hidden)]
    pub fn package_is_child_with_parents(txs: &[Transaction]) -> bool {
        if txs.len() < 2 {
            return false;
        }
        let ids: BTreeMap<Txid, usize> = txs
            .iter()
            .enumerate()
            .map(|(i, tx)| (tx.compute_txid(), i))
            .collect();
        let child = txs.len() - 1;
        let mut ancestors = BTreeSet::new();
        let mut stack = vec![child];
        while let Some(i) = stack.pop() {
            for inp in &txs[i].input {
                let Some(&pi) = ids.get(&inp.previous_output.txid) else {
                    continue;
                };
                if ancestors.insert(txs[pi].compute_txid()) {
                    stack.push(pi);
                }
            }
        }
        !ancestors.is_empty() && ancestors.len() + 1 == txs.len()
    }

    /// Combined ancestor/CPFP package fee vs total sigop-adjusted weight
    /// against `sat_kvb`.
    pub fn package_meets_min_relay(
        &self,
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        sat_kvb: u64,
        bytes_per_sigop: u64,
    ) -> bool {
        if !Self::package_is_child_with_parents(txs) {
            return false;
        }
        let mut created: BTreeMap<Txid, &[TxOut]> = BTreeMap::new();
        let mut fee = 0u64;
        let mut weight = 0u64;
        for tx in txs {
            let mut prevouts = Vec::with_capacity(tx.input.len());
            for inp in &tx.input {
                let op = inp.previous_output;
                let prev = if let Some(outs) = created.get(&op.txid) {
                    outs.get(op.vout as usize).cloned()
                } else if let Some(parent) = self.bodies.get(&op.txid) {
                    // In-mempool parent outside this remainder (already admitted).
                    parent.output.get(op.vout as usize).cloned()
                } else {
                    utxos.get_coin(&op).map(|c| c.txout)
                };
                let Some(prev) = prev else {
                    return false;
                };
                prevouts.push(prev);
            }
            let Some((f, w)) = fee_and_adjusted_weight(tx, &prevouts, bytes_per_sigop) else {
                return false;
            };
            fee = fee.saturating_add(f);
            weight = weight.saturating_add(w);
            created.insert(tx.compute_txid(), &tx.output);
        }
        policy::meets_min_relay_fee_at(fee, weight, sat_kvb)
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
        let member_min = if self.package_meets_min_relay(
            txs,
            utxos,
            self.min_relay_sat_kvb,
            self.graph.bytes_per_sigop(),
        ) {
            Some(0)
        } else {
            None
        };
        let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
        // Members already parked are lifted so the short-circuit for a
        // re-announced orphan does not reject them. Promote waits until
        // every member is committed, so this walk cannot admit a later
        // member and then roll it back as a duplicate.
        let mut lifted: Vec<LiftedOrphan> = Vec::new();
        for tx in txs {
            if let Some(parked) = self.lift_parked_member(tx) {
                lifted.push(parked);
            }
            // accept_tx_with (not top-level accept_tx) so stages are not reset per member.
            match self.accept_tx_with(tx, utxos, tip, 0, true, member_min) {
                Ok(r) => accepted.push(r),
                Err(e) => {
                    self.restore_undone(utxos, tip);
                    self.rollback_accepted_package(&accepted, utxos, tip);
                    for item in self.repark_lifted(&lifted, utxos, tip, &|_| 0, None) {
                        let id = item.tx.compute_txid();
                        match self.accept_tx_with(&item.tx, utxos, tip, 0, true, None) {
                            Ok(r) => {
                                // Admitted, so the lift row is not in flight.
                                self.orphanage.forget_taken_gen(&id, item.taken_gen);
                                self.promote_orphans_of(r.txid, utxos, tip);
                            }
                            Err(AcceptError::Orphaned { missing, .. }) => {
                                self.park_announced(&item.tx, missing, &item.announcers);
                            }
                            Err(_) => {
                                // Rejected without a repark. Drop the lift row.
                                self.orphanage.forget_taken_gen(&id, item.taken_gen);
                                self.restore_undone(utxos, tip);
                            }
                        }
                    }
                    return Err(e);
                }
            }
        }
        // Every lifted member was admitted. A newer take keeps its own generation.
        for item in &lifted {
            self.orphanage
                .forget_taken_gen(&item.tx.compute_txid(), item.taken_gen);
        }
        let ids: Vec<Txid> = accepted.iter().map(|r| r.txid).collect();
        for id in ids {
            self.promote_orphans_of(id, utxos, tip);
        }
        Ok(accepted)
    }

    /// Take `tx` out of the orphanage so a package can admit it.
    ///
    /// `prepare_admit` and `plan_after_script` both refuse a tx that is
    /// still parked, even when its parents are already in the mempool.
    /// The announcing peers come along so a failed package can put them back.
    pub fn lift_parked_member(&mut self, tx: &Transaction) -> Option<LiftedOrphan> {
        let id = tx.compute_txid();
        self.orphanage.missing_of(&id)?;
        let announcers = self.orphanage.announcers_of(&id);
        let parked = self.orphanage.take_txid(&id)?;
        let taken_gen = self.orphanage.note_taken(id, &announcers);
        Some(LiftedOrphan {
            tx: parked,
            announcers,
            taken_gen,
        })
    }

    /// Put lifted members back, or hand back the ones that can be admitted.
    ///
    /// The missing set saved at the lift is not used. A parent can arrive
    /// while the child is out of the orphanage, and parking under that parent
    /// leaves the child with nobody left to wake it. Parents still absent are
    /// resolved again here. `fee_delta` is the caller's `prioritisetransaction`
    /// map: a child under the raw relay floor is still returned when that
    /// delta clears it. Announcers are kept on either path.
    pub fn repark_lifted(
        &mut self,
        lifted: &[LiftedOrphan],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        fee_delta: &impl Fn(&Txid) -> i64,
        trusted: Option<u64>,
    ) -> Vec<LiftedOrphan> {
        let mut ready = Vec::new();
        for item in lifted {
            let txid = item.tx.compute_txid();
            if self.graph.contains(&txid) {
                self.orphanage.forget_taken_gen(&txid, item.taken_gen);
                continue;
            }
            match self.prepare_admit(
                &item.tx,
                utxos,
                tip,
                PrepareOpts {
                    fee_delta: fee_delta(&txid),
                    report_orphans: true,
                    min_relay: None,
                    waive: trusted.is_some_and(|id| item.announcers.contains(&id)),
                },
            ) {
                Err(AcceptError::Orphaned { missing, .. }) => {
                    self.park_announced(&item.tx, missing, &item.announcers);
                }
                Ok(_) => ready.push(LiftedOrphan {
                    tx: item.tx.clone(),
                    announcers: item.announcers.clone(),
                    taken_gen: item.taken_gen,
                }),
                Err(_) => self.orphanage.forget_taken_gen(&txid, item.taken_gen),
            }
        }
        ready
    }

    /// Park `tx` under `missing` and restore every announcing peer.
    ///
    /// The first peer is recorded by the insert. The rest are added before
    /// this write lock returns, so a disconnect sees the full set.
    pub fn park_announced(
        &mut self,
        tx: &Transaction,
        missing: BTreeSet<Txid>,
        announcers: &[u64],
    ) -> AcceptError {
        let txid = tx.compute_txid();
        // A disconnect while this orphan was out of `by_txid` edited the
        // in-flight record. The slice from the take is already stale.
        let live = match self.orphanage.claim_taken(&txid) {
            Some(crate::orphanage::TakenClaim::Drop) => {
                return AcceptError::Orphaned {
                    txid,
                    missing,
                    fresh: false,
                };
            }
            Some(crate::orphanage::TakenClaim::Keep(peers)) => peers,
            None => announcers.to_vec(),
        };
        let first = live.first().copied();
        let err = self.park_orphan_from(tx, missing, first);
        for peer in live.iter().skip(1) {
            self.orphanage.add_announcer(&txid, *peer);
        }
        err
    }

    #[doc(hidden)]
    pub fn rollback_accepted_package(
        &mut self,
        accepted: &[AcceptResult],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) {
        let victims: Vec<Transaction> = accepted
            .iter()
            .flat_map(|r| r.replaced_txs.iter().cloned())
            .collect();
        let accept_secs: std::collections::HashMap<Txid, u64> = accepted
            .iter()
            .flat_map(|r| r.replaced_accept_secs.iter().map(|(t, s)| (*t, *s)))
            .collect();
        for id in accepted.iter().flat_map(|r| r.replaced_trust.iter()) {
            self.trust_kept.insert(*id);
        }
        for r in accepted.iter().rev() {
            let _ = self.unlink_tree(&r.txid);
        }
        let _ = self.store.sync_deaths();
        let _ = self.restore_victims(&victims, &accept_secs, utxos, tip, RestoreOrphans::Promote);
    }

    /// Parents before children, so a restored descendant can see its in-set parent.
    pub fn ancestor_first_order(txs: &[Transaction]) -> Vec<usize> {
        let n = txs.len();
        let mut index = BTreeMap::new();
        for (i, tx) in txs.iter().enumerate() {
            index.insert(tx.compute_txid(), i);
        }
        let mut children = vec![Vec::new(); n];
        let mut indeg = vec![0u32; n];
        for (i, tx) in txs.iter().enumerate() {
            for inp in &tx.input {
                let Some(&parent) = index.get(&inp.previous_output.txid) else {
                    continue;
                };
                if parent == i {
                    continue;
                }
                children[parent].push(i);
                indeg[i] = indeg[i].saturating_add(1);
            }
        }
        let mut ready: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
        let mut out = Vec::with_capacity(n);
        let mut q = 0;
        while q < ready.len() {
            let i = ready[q];
            q += 1;
            out.push(i);
            for &child in &children[i] {
                indeg[child] -= 1;
                if indeg[child] == 0 {
                    ready.push(child);
                }
            }
        }
        if out.len() != n {
            for i in 0..n {
                if !out.contains(&i) {
                    out.push(i);
                }
            }
        }
        out
    }

    /// Put an already-admitted body back. The fee floor does not apply again,
    /// and a missing parent is not parked.
    /// It keeps `accept_secs`, its original accept time, when known.
    #[doc(hidden)]
    pub fn reaccept_already_admitted(
        &mut self,
        tx: &Transaction,
        accept_secs: Option<u64>,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        let waive = self.trust_kept.contains(&tx.compute_txid());
        let mut prep = self.prepare_admit(
            tx,
            utxos,
            tip,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: Some(0),
                waive,
            },
        )?;
        prep.keep_mark = waive;
        prep.keep_accept_secs = accept_secs;
        if let Err(e) = self.verify_scripts_for_tip(tx, prep.prevouts.clone(), tip) {
            match trust_script_reason(waive, &e) {
                Some(reason) => push_trust_warn(&mut prep.trust_warn, reason),
                None => return Err(e),
            }
        }
        self.commit_after_script(tx, prep)
    }

    #[doc(hidden)]
    pub fn restore_victims(
        &mut self,
        victims: &[Transaction],
        accept_secs: &std::collections::HashMap<Txid, u64>,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        orphans: RestoreOrphans,
    ) -> Vec<Txid> {
        let mut noted = Vec::new();
        for i in Self::ancestor_first_order(victims) {
            let at = accept_secs.get(&victims[i].compute_txid()).copied();
            match self.reaccept_already_admitted(&victims[i], at, utxos, tip) {
                Ok(r) => match orphans {
                    RestoreOrphans::Promote => self.promote_orphans_of(r.txid, utxos, tip),
                    RestoreOrphans::Defer => noted.push(r.txid),
                },
                Err(_) => {
                    if !self.undone_replacements.is_empty() {
                        noted.extend(self.restore_conflicts(utxos, tip, orphans));
                    }
                    let id = victims[i].compute_txid();
                    if !self.graph.contains(&id) {
                        self.trust_kept.remove(&id);
                    }
                }
            }
        }
        noted
    }

    /// Re-accept conflicts a failed commit already removed.
    #[doc(hidden)]
    pub fn restore_undone(&mut self, utxos: &impl UtxoProvider, tip: ChainTipCtx) {
        let _ = self.restore_conflicts(utxos, tip, RestoreOrphans::Promote);
    }

    /// Like [`Self::restore_undone`]. `Defer` returns the restored txids
    /// instead of starting another orphan walk.
    #[doc(hidden)]
    pub fn restore_conflicts(
        &mut self,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        orphans: RestoreOrphans,
    ) -> Vec<Txid> {
        let victims = std::mem::take(&mut self.undone_replacements);
        let accept_secs = std::mem::take(&mut self.undone_accept_secs);
        self.restore_victims(&victims, &accept_secs, utxos, tip, orphans)
    }

    /// Drop one live tx from the graph and `pwrite` its slot DEAD. No `fdatasync`.
    #[doc(hidden)]
    pub fn unlink_txid(&mut self, txid: &Txid) -> Result<(), AcceptError> {
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
        self.remember_extra_compact(&tx);
        self.store.mark_slot_dead(entry.slot)?;
        self.graph.remove(txid, &tx);
        self.bodies.remove(txid);
        self.vin_aux.remove(txid);
        self.trust_kept.remove(txid);
        Ok(())
    }

    /// Durable remove one live tx (confirm / RBF / eviction).
    pub fn remove_txid(&mut self, txid: &Txid) -> Result<(), AcceptError> {
        self.unlink_txid(txid)?;
        let _ = self.store.sync_deaths();
        Ok(())
    }

    /// Remove `txid` and live mempool txs that spend it, without syncing.
    #[doc(hidden)]
    pub fn unlink_tree(&mut self, txid: &Txid) -> Vec<Txid> {
        let n_out = self
            .get_tx(txid)
            .map(|tx| tx.output.len() as u32)
            .unwrap_or(0);
        let spent: Vec<OutPoint> = (0..n_out)
            .map(|vout| OutPoint { txid: *txid, vout })
            .collect();
        let mut gone = self.unlink_conflicts(&spent);
        if self.unlink_txid(txid).is_ok() {
            gone.push(*txid);
        }
        gone
    }

    /// Remove `txid` and live mempool txs that spend it (1p1c child-fail rollback).
    ///
    /// Returns every txid dropped (spenders first, then `txid` if it was live).
    pub fn remove_txid_tree(&mut self, txid: &Txid) -> Vec<Txid> {
        let gone = self.unlink_tree(txid);
        let _ = self.store.sync_deaths();
        gone
    }

    /// Remove all txs that appear in a confirmed block (coinbase ignored if present).
    ///
    /// Missing mempool entries are skipped (already not in pool). Returns how many removed.
    /// May trigger compaction when DEAD slots dominate.
    ///
    /// Also drops orphanage entries that are confirmed or conflict with the block,
    /// and best-effort re-accepts orphans whose parent just confirmed (caller must
    /// pass a UTXO view that includes the new tip — use `remove_for_block_with_utxo`).
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
    ///
    /// One slots `fdatasync`, then one `meta` sync, for every tx this call drops.
    pub fn remove_live_txids(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        let stripped = self.unlink_listed(block_txids);
        let _ = self.store.sync_deaths();
        let n = stripped?;
        if n > 0 {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        Ok(n)
    }

    /// `pwrite` DEAD for each live id. Does not sync.
    #[doc(hidden)]
    pub fn unlink_listed(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        let mut n = 0usize;
        for txid in block_txids {
            if self.graph.contains(txid) {
                self.unlink_txid(txid)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Confirmed ids plus live txs that spend `spent`, then one death sync.
    pub fn remove_block_txids(
        &mut self,
        txids: &[Txid],
        spent: &[OutPoint],
    ) -> Result<(usize, Vec<Txid>), AcceptError> {
        let stripped = self.unlink_listed(txids);
        let gone = self.unlink_conflicts(spent);
        let _ = self.store.sync_deaths();
        let n = stripped?;
        if n > 0 || !gone.is_empty() {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        Ok((n, gone))
    }

    /// Like `remove_for_block`, then promote orphans of confirmed parents via `utxos`.
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
        let out = self.unlink_conflicts(spent);
        let _ = self.store.sync_deaths();
        if !out.is_empty() {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        out
    }

    /// Drop live txs (and their descendants) that spend `spent`. No sync.
    #[doc(hidden)]
    pub fn unlink_conflicts(&mut self, spent: &[OutPoint]) -> Vec<Txid> {
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
            if self.unlink_txid(&id).is_ok() {
                out.push(id);
            }
        }
        out
    }

    pub fn orphan_count(&self) -> usize {
        self.orphanage.len()
    }

    pub fn extra_compact_txs(&self) -> impl Iterator<Item = &Transaction> {
        self.extra_compact.iter().map(|(_, tx)| tx)
    }

    /// Recently seen body for BIP152 extra fill (compact prefill / blocktxn / strip).
    pub fn remember_extra_compact(&mut self, tx: &Transaction) {
        self.note_extra(tx);
    }

    pub fn accept_failure_record(tx: &Transaction, e: &AcceptError) -> Option<AcceptFailureRecord> {
        match e {
            AcceptError::InputsDuplicate | AcceptError::Coinbase => {
                Some(AcceptFailureRecord::Invalid(tx.compute_txid()))
            }
            AcceptError::Script(s)
                if !tx_has_witness(tx)
                    && !s.contains("WITNESS_UNEXPECTED")
                    && !s.contains("empty witness") =>
            {
                Some(AcceptFailureRecord::Invalid(tx.compute_txid()))
            }
            AcceptError::Policy("min relay fee") => Some(AcceptFailureRecord::Extra),
            _ => None,
        }
    }

    pub fn apply_accept_failure(&mut self, tx: &Transaction, rec: AcceptFailureRecord) {
        match rec {
            AcceptFailureRecord::Invalid(txid) => self.note_invalid(txid),
            AcceptFailureRecord::Extra => self.note_extra(tx),
        }
    }

    pub fn note_accept_failure(&mut self, tx: &Transaction, e: &AcceptError) {
        if let Some(rec) = Self::accept_failure_record(tx, e) {
            self.apply_accept_failure(tx, rec);
        }
    }

    #[doc(hidden)]
    pub fn note_invalid(&mut self, txid: Txid) {
        if self.recent_invalid.len() >= RECENT_INVALID_CAP {
            return;
        }
        self.recent_invalid.insert(txid);
    }

    #[doc(hidden)]
    pub fn note_extra(&mut self, tx: &Transaction) {
        if tx.is_coinbase() {
            return;
        }
        let txid = tx.compute_txid();
        self.extra_compact.retain(|(id, _)| *id != txid);
        if self.extra_compact.len() >= EXTRA_COMPACT_CAP {
            self.extra_compact.pop_front();
        }
        self.extra_compact.push_back((txid, tx.clone()));
    }

    #[doc(hidden)]
    pub fn extra_by_txid(&self, txid: Txid) -> Option<&Transaction> {
        self.extra_compact
            .iter()
            .find(|(id, _)| *id == txid)
            .map(|(_, tx)| tx)
    }

    /// 1p1c parent body from extra-compact. Parent inputs must be confirmed.
    pub fn try_one_parent_package(
        &self,
        child: &Transaction,
        missing: &BTreeSet<Txid>,
        utxos: &impl UtxoProvider,
    ) -> Option<Transaction> {
        if missing.len() != 1 {
            return None;
        }
        let pid = *missing.iter().next()?;
        if self.recent_invalid.contains(&pid) {
            return None;
        }
        let parent = self.extra_by_txid(pid)?.clone();
        if !self.package_pays_min_relay(&parent, child, utxos) {
            return None;
        }
        Some(parent)
    }

    /// Combined parent+child fee must meet min-relay. Parent inputs must be
    /// confirmed (no unconfirmed grandparent — same limit as Core 1p1c).
    #[doc(hidden)]
    pub fn package_pays_min_relay(
        &self,
        parent: &Transaction,
        child: &Transaction,
        utxos: &impl UtxoProvider,
    ) -> bool {
        let bps = self.graph.bytes_per_sigop();
        let pid = parent.compute_txid();
        let p_prev: Option<Vec<TxOut>> = parent
            .input
            .iter()
            .map(|i| utxos.get_coin(&i.previous_output).map(|c| c.txout))
            .collect();
        let c_prev: Option<Vec<TxOut>> = child
            .input
            .iter()
            .map(|i| {
                let op = i.previous_output;
                if op.txid == pid {
                    parent.output.get(op.vout as usize).cloned()
                } else {
                    utxos.get_coin(&op).map(|c| c.txout)
                }
            })
            .collect();
        let (Some(p_prev), Some(c_prev)) = (p_prev, c_prev) else {
            return false;
        };
        let (Some((pf, pw)), Some((cf, cw))) = (
            fee_and_adjusted_weight(parent, &p_prev, bps),
            fee_and_adjusted_weight(child, &c_prev, bps),
        ) else {
            return false;
        };
        policy::meets_min_relay_fee_at(
            pf.saturating_add(cf),
            pw.saturating_add(cw),
            self.min_relay_sat_kvb,
        )
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
                let structural = check_mempool_structural(&tx, &chain_coins, tip);
                let keep_fault = structural
                    .as_ref()
                    .err()
                    .is_some_and(|e| trust_keeps_structural(self.trust_kept.contains(&id), e));
                if keep_fault && !missing_chain {
                    if let Err(e) = &structural {
                        warn_trust_tx(true, id, &e.mempool_reject_reason());
                    }
                }
                if missing_chain || (structural.is_err() && !keep_fault) {
                    let _ = self.unlink_txid(&id);
                    removed = true;
                }
            }
            let _ = self.store.sync_deaths();
            if !removed {
                break;
            }
        }
    }

    /// Fill sigop cost for entries migrated from schema ≤ 2 (open-time pass).
    ///
    /// Prevouts resolve from live parents or `utxos`. Entries whose prevouts
    /// no longer resolve, or whose cost cannot fit a block, are evicted
    /// (with spenders). Filled costs are written back to the durable record.
    pub fn recompute_missing_sigops(&mut self, utxos: &impl UtxoProvider) {
        let ids: Vec<Txid> = self
            .graph
            .iter()
            .filter(|(_, e)| e.sigop_cost == u64::MAX)
            .map(|(t, _)| *t)
            .collect();
        for id in ids {
            let Some(tx) = self.get_tx(&id).cloned() else {
                continue;
            };
            let prevouts: Option<Vec<TxOut>> = tx
                .input
                .iter()
                .map(|inp| {
                    let op = inp.previous_output;
                    match self.graph.creator(&op) {
                        Some(p) => self
                            .get_tx(&p)
                            .and_then(|t| t.output.get(op.vout as usize))
                            .cloned(),
                        None => utxos.get_coin(&op).map(|c| c.txout),
                    }
                })
                .collect();
            let slot = self.graph.get(&id).map(|e| e.slot);
            match (
                prevouts.map(|p| block_fit_sigop_cost(&tx, &p, self.graph.block_reserved_sigops())),
                slot,
            ) {
                (Some(Ok(cost)), Some(slot)) => {
                    self.graph.set_sigop_cost(&id, cost);
                    if let Err(e) = self.store.set_sigop_cost(slot, cost) {
                        rbitcoin_log::warn!("mempool: sigops write-back {id}: {e}");
                    }
                }
                _ => {
                    let gone = self.unlink_tree(&id);
                    rbitcoin_log::info!(
                        "mempool: sigops recompute evicted {id} ({} with spenders): inputs gone or cost over block budget",
                        gone.len()
                    );
                }
            }
        }
        let _ = self.store.sync_deaths();
    }

    /// Lookup a live body (for tests / Electrum unconf).
    pub fn get_tx(&self, txid: &Txid) -> Option<&Transaction> {
        self.bodies.get(txid).map(|a| a.as_ref())
    }

    /// Packed vin aux for a live tx (SH reindex / purge). Empty if unknown.
    pub fn vin_aux(&self, txid: &Txid) -> &[VinAux] {
        self.vin_aux.get(txid).map_or(&[], Vec::as_slice)
    }

    #[doc(hidden)]
    pub fn vin_aux_from_prep(tx: &Transaction, prep: &PreparedAdmit) -> Vec<VinAux> {
        tx.input
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let script_hash = prep
                    .prevouts
                    .get(i)
                    .map(|o| rbitcoin_store::script_hash(o.script_pubkey.as_bytes()));
                let create_fk = prep
                    .chain_coins
                    .get(i)
                    .and_then(|c| c.as_ref())
                    .and_then(|c| c.create_fk);
                VinAux {
                    prev_txid: inp.previous_output.txid,
                    vout: inp.previous_output.vout,
                    script_hash,
                    create_fk,
                }
            })
            .collect()
    }

    /// This node's own block budget (GBT / `generate`): template weight and
    /// the admission sigop reserve, with a `-blockmintxfee` floor.
    pub fn template_budget(&self, min_sat_kvb: u64) -> SelectBudget {
        SelectBudget {
            max_weight_wu: TxGraph::template_tx_weight(),
            reserved_sigops: self.graph.block_reserved_sigops(),
            min_sat_kvb,
        }
    }

    /// Mining-order live txs that fit `budget` (best chunks first) with
    /// `prioritisetransaction` deltas, each with its [`Selected`] meta.
    ///
    /// RAM trade: the bodies are the pool's own `Arc`s, not copies. A caller
    /// that holds one past eviction or replacement keeps that body alive.
    pub fn select_block_template(
        &self,
        budget: SelectBudget,
        delta: impl Fn(Txid) -> i64,
    ) -> Vec<(Arc<Transaction>, Selected)> {
        self.graph
            .select_block_template(budget, delta, |id| self.trust_kept.contains(id))
            .into_iter()
            .filter_map(|s| self.bodies.get(&s.txid).map(|tx| (Arc::clone(tx), s)))
            .collect()
    }
}

/// BIP125-style full-RBF fee check (no signaling required — Libre full RBF).
///
/// Requires strictly higher absolute fee over the **conflict set** (incl.
/// descendants), a strictly higher true feerate, and the incremental relay
/// fee on replacement vsize. Feerate is `new_fee * old_vsize > old_fee *
/// new_vsize` in `u128`, so a replacement that lands in the same whole
/// sat/kvB bucket still pays when its real rate is higher, including when
/// either product exceeds `u64::MAX`.
pub fn rbf_pays_for_replacement(
    new_fee: u64,
    new_weight: u64,
    old_fee: u64,
    old_weight: u64,
) -> bool {
    if new_fee <= old_fee {
        return false;
    }
    let new_v = policy::vbytes_ceil(new_weight);
    let old_v = policy::vbytes_ceil(old_weight);
    if new_v == 0 || old_v == 0 {
        return false;
    }
    if u128::from(new_fee) * u128::from(old_v) <= u128::from(old_fee) * u128::from(new_v) {
        return false;
    }
    let inc = new_v
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
    // `(weight + 3) / 4` is 0 only at weight 0, so the vsize check is the zero guard.
    let new_v = policy::vbytes_ceil(new_weight);
    let old_v = policy::vbytes_ceil(direct_weight);
    if new_v == 0 || old_v == 0 {
        return false;
    }
    u128::from(new_fee) * u128::from(RBFR_RATIO_DEN) * u128::from(old_v)
        >= u128::from(direct_fee) * u128::from(RBFR_RATIO_NUM) * u128::from(new_v)
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
