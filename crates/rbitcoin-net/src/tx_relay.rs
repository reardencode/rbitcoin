//! Tip-mode transaction relay (P4): inv/getdata/tx + mempool announce.
//!
//! Heavy relay is **gated** on [`MempoolHub::set_relay_enabled`] (false during IBD).
//! Package admit is RPC `submitpackage` / Esplora `POST /txs/package` /
//! [`MempoolHub::accept_package`]. There is no P2P package command (BIP331
//! is not in rust-bitcoin 0.32 `NetworkMessage`; the old private `rbtpkg`
//! name is gone).

use crate::fee_history::{FeeHistory, HistoricalFeeBlock};
use crate::fee_history_file;
use crate::perf_meter::{PerfCounter, PerfMax};
use arc_swap::ArcSwap;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_mempool::{
    fee_at_target_sat_kvb, fine_candidate_rates, flow_for_depth, frontier_feerate_from_chunks,
    hold_defined_then_monotone, min_rate_for_capacity, percentile_sat, published_depth_rate,
    weight_above_from_chunks, AcceptError, AcceptResult, ActiveMempool, ChainPrevout, ChainTipCtx,
    Chunk, Coin, FeeFlowMeter, PrepareOpts, SelectBudget, Selected, StockAbove, UtxoProvider,
    BLOCK_WEIGHT_WU, MAX_PACKAGE_COUNT,
};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

#[cfg(debug_assertions)]
thread_local! {
    static PROMOTE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static PROMOTE_DEPTH_MAX: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub struct PromoteDepth;

#[cfg(debug_assertions)]
impl PromoteDepth {
    #[doc(hidden)]
    pub fn enter() -> Self {
        PROMOTE_DEPTH.with(|d| {
            let n = d.get().saturating_add(1);
            d.set(n);
            PROMOTE_DEPTH_MAX.with(|m| m.set(m.get().max(n)));
        });
        Self
    }
}

#[cfg(debug_assertions)]
impl Drop for PromoteDepth {
    fn drop(&mut self) {
        PROMOTE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn reset_promote_depth() {
    PROMOTE_DEPTH.with(|d| d.set(0));
    PROMOTE_DEPTH_MAX.with(|d| d.set(0));
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn promote_depth_max() -> u32 {
    PROMOTE_DEPTH_MAX.with(|d| d.get())
}

thread_local! {
    /// Txids admitted while one promote walk is running on this thread.
    /// `None` means no walk is active.
    static PROMOTE_NOTES: std::cell::RefCell<Option<Vec<Txid>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(debug_assertions)]
thread_local! {
    /// Fired while `template_prev` is held. Off until a test arms it on this thread.
    static MAINT_PUBLISH_HOOK: std::cell::Cell<Option<fn(&MempoolHub)>> =
        const { std::cell::Cell::new(None) };
}

/// Record `txid` when a walk is already running. Returns false when this
/// thread should start the walk.
#[doc(hidden)]
pub fn promote_note(txid: Txid) -> bool {
    PROMOTE_NOTES.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(notes) = slot.as_mut() else {
            return false;
        };
        notes.push(txid);
        true
    })
}

#[doc(hidden)]
pub fn promote_take_notes() -> Vec<Txid> {
    PROMOTE_NOTES.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    })
}

/// One promote walk on this thread. Drop ends it, including after a panic.
#[doc(hidden)]
pub struct PromoteWalk {
    #[cfg(debug_assertions)]
    pub _depth: PromoteDepth,
}

impl PromoteWalk {
    #[doc(hidden)]
    pub fn enter() -> Self {
        PROMOTE_NOTES.with(|slot| {
            *slot.borrow_mut() = Some(Vec::new());
        });
        Self {
            #[cfg(debug_assertions)]
            _depth: PromoteDepth::enter(),
        }
    }
}

impl Drop for PromoteWalk {
    fn drop(&mut self) {
        PROMOTE_NOTES.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[path = "parent_req.rs"]
#[doc(hidden)]
pub mod parent_req;
pub use parent_req::{DueParent, ParentNote};

/// Max age of a published fee snapshot before refresh (request path is still Arc-load only
/// after a concurrent refresh has finished; see [`MempoolHub::maybe_refresh_fee_snapshot`]).
#[doc(hidden)]
pub const FEE_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(1);

/// Dirty, older than `max_age`, or computed after `now`. Shared by the fee
/// and tx snapshot gates.
#[doc(hidden)]
pub fn is_stale(computed_at: Instant, now: Instant, dirty: bool, max_age: Duration) -> bool {
    dirty
        || now
            .checked_duration_since(computed_at)
            .map(|age| age >= max_age)
            .unwrap_or(true)
}

#[doc(hidden)]
pub fn load_unbroadcast_file(dir: &Path) -> HashSet<Txid> {
    let Ok(bytes) = std::fs::read(dir.join("unbroadcast")) else {
        return HashSet::new();
    };
    bytes
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            Txid::from_byte_array(a)
        })
        .collect()
}

#[doc(hidden)]
pub fn persist_unbroadcast_file(dir: &Path, set: &HashSet<Txid>) {
    let mut buf = Vec::with_capacity(set.len() * 32);
    for t in set {
        buf.extend_from_slice(&t.to_byte_array());
    }
    let _ = std::fs::write(dir.join("unbroadcast"), buf);
}

/// Depths the refresh evaluates. Every other confirm target is
/// [`fee_at_target_sat_kvb`] on this table (after target 0 → default map).
#[doc(hidden)]
pub const FEE_SNAPSHOT_DEPTHS: &[u32] = &[1, 2, 3, 4, 5, 6, 10, 20, 144, 504, 1008];
/// Txstat body bytes scanned and retained for historical fee estimates.
#[doc(hidden)]
pub const FEE_HISTORY_TXSTAT_BYTE_BUDGET: u64 = 1 << 30;

/// Journal of connects since the last fee history snapshot.
#[derive(Debug)]
#[doc(hidden)]
pub struct FeeJournal {
    pub file: std::fs::File,
    pub since_snapshot: u32,
}

/// Result summary for the asynchronous historical txstat preload.
#[derive(Clone, Debug, Default)]
pub struct FeeHistoryBackfillStats {
    pub tip_height: Option<u32>,
    pub oldest_height: Option<u32>,
    pub heights_scanned: u64,
    pub valid_samples: u64,
    pub skipped_heights: u64,
    pub failed_heights: u64,
    pub txstat_bytes: u64,
    /// Heights restored from the fee history file before the scan.
    pub file_heights: u64,
    /// Snapshot targets whose historical estimate answers after the preload.
    pub ready_targets: u64,
    pub total_targets: u64,
    pub history_exhausted: bool,
    /// Heights the history already held, counted without a chain read.
    pub retained_heights: u64,
    pub first_error: Option<String>,
}

/// Immutable published fee table + mining chunks (request path never walks the graph).
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct FeeSnapshot {
    /// sat/kvB at [`FEE_SNAPSHOT_DEPTHS`], same order. `None` is no rate.
    pub depth_rates_sat_kvb: Vec<Option<u64>>,
    /// Best-first mining chunks from the last refresh (histogram / frontier).
    pub chunks: Vec<Chunk>,
    /// Per-chunk Σ raw member vsize, parallel to [`Self::chunks`] (histogram).
    pub chunk_raw_vsize: Vec<u64>,
    /// Live tx count from the same graph read as [`Self::chunks`].
    pub count: usize,
    /// Σ `(weight + 3) / 4` over live entries (GET `/mempool` `vsize`).
    pub vsize: u64,
    /// Σ `fee_sat` over live entries.
    pub total_fee: u64,
    pub computed_at: Instant,
}

impl FeeSnapshot {
    #[doc(hidden)]
    pub fn empty(now: Instant) -> Self {
        Self {
            depth_rates_sat_kvb: vec![None; FEE_SNAPSHOT_DEPTHS.len()],
            chunks: Vec::new(),
            chunk_raw_vsize: Vec::new(),
            count: 0,
            vsize: 0,
            total_fee: 0,
            computed_at: now,
        }
    }

    /// `target`'s rate, at least `floor_sat_kvb`, in BTC/kvB; `-1.0` without one.
    #[doc(hidden)]
    pub fn rate_btc_per_kb(&self, target: u32, floor_sat_kvb: u64) -> f64 {
        match fee_at_target_sat_kvb(FEE_SNAPSHOT_DEPTHS, &self.depth_rates_sat_kvb, target) {
            Some(sat) => sat.max(floor_sat_kvb) as f64 / 100_000_000.0,
            None => -1.0,
        }
    }

    #[doc(hidden)]
    pub fn histogram(&self) -> Vec<(u64, u64)> {
        let mut by_rate: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
        // Raw vsize (electrs `tx.vsize()`), so buckets sum to GET `/mempool` `vsize`.
        for (ch, vsize) in self.chunks.iter().zip(&self.chunk_raw_vsize) {
            let rate = ch.fee_rate_sat_per_kvb();
            *by_rate.entry(rate).or_insert(0) += vsize;
        }
        by_rate.into_iter().rev().collect()
    }
}

/// Published live-mempool txs (txid-sorted). Lazy: unix `/internal` mempool-tx
/// pages Arc-load; admit only sets dirty. Esplora fills [`MempoolTxSnapEntry::json`]
/// once per entry. `GET /mempool` uses the fee snapshot, not this.
#[derive(Debug)]
pub struct MempoolTxSnapshot {
    pub entries: Vec<MempoolTxSnapEntry>,
    pub computed_at: Instant,
}

/// One live mempool tx in [`MempoolTxSnapshot`].
#[derive(Debug)]
pub struct MempoolTxSnapEntry {
    pub txid: Txid,
    pub fee_sat: u64,
    pub weight: u64,
    pub tx: Arc<Transaction>,
    pub json: std::sync::OnceLock<Box<str>>,
}

impl MempoolTxSnapshot {
    #[doc(hidden)]
    pub fn empty(now: Instant) -> Self {
        Self {
            entries: Vec::new(),
            computed_at: now,
        }
    }

    pub fn entries(&self) -> &[MempoolTxSnapEntry] {
        &self.entries
    }

    pub fn get(&self, txid: &Txid) -> Option<&MempoolTxSnapEntry> {
        self.entries
            .binary_search_by(|e| e.txid.cmp(txid))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Exclusive cursor: entries strictly after `last` in txid order.
    pub fn page(&self, last: Option<&Txid>, max: usize) -> &[MempoolTxSnapEntry] {
        let start = match last {
            None => 0,
            Some(tid) => match self.entries.binary_search_by(|e| e.txid.cmp(tid)) {
                Ok(i) => i.saturating_add(1),
                Err(i) => i,
            },
        };
        let end = start.saturating_add(max).min(self.entries.len());
        &self.entries[start..end]
    }
}

/// BIP68 time-form relative lock (`SEQUENCE_LOCKTIME_TYPE_FLAG`, disable unset).
#[doc(hidden)]
pub fn tx_has_bip68_time_lock(tx: &Transaction) -> bool {
    if (tx.version.0 as u32) < 2 {
        return false;
    }
    const DISABLE: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    tx.input.iter().any(|inp| {
        let seq = inp.sequence.to_consensus_u32();
        seq & DISABLE == 0 && seq & TYPE_FLAG != 0
    })
}

/// Resolve prevouts from the relational archive (confirmed **unspent** UTXOs).
///
/// Returns no coin when the create is unknown **or** a confirmed-strong spender
/// exists (finding 010 — mirror Core coins-view spentness).
pub struct QueryUtxoProvider<'a> {
    pub query: &'a Query,
    pub need_create_mtp: AtomicBool,
    pub meter_get_coin: Option<&'a AtomicU64>,
    pub meter_create_mtp: Option<&'a AtomicU64>,
    /// Test seam for the Class C coinbase read. `0` uses the store.
    /// `1` is `Ok(false)`, `2` is `Ok(true)`, anything else is a read error.
    #[cfg(debug_assertions)]
    pub coinbase_read: std::sync::atomic::AtomicU8,
}

impl<'a> QueryUtxoProvider<'a> {
    pub fn new(query: &'a Query) -> Self {
        Self {
            query,
            need_create_mtp: AtomicBool::new(false),
            meter_get_coin: None,
            meter_create_mtp: None,
            #[cfg(debug_assertions)]
            coinbase_read: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Class C coinbase bit for `fk` at `create_height`.
    ///
    /// `Ok(false)` is a height with no coinbase row. `Err` is a failed read;
    /// the caller leaves the coin unavailable.
    #[doc(hidden)]
    pub fn coinbase_flag(
        &self,
        fk: Fk,
        create_height: u32,
    ) -> Result<bool, rbitcoin_query::QueryError> {
        #[cfg(debug_assertions)]
        match self.coinbase_read.load(Ordering::Relaxed) {
            0 => {}
            1 => return Ok(false),
            2 => return Ok(true),
            _ => return Err(rbitcoin_store::StoreError::Corrupt("coinbase table")),
        }
        self.query.is_coinbase_create(fk, create_height)
    }
}

impl UtxoProvider for QueryUtxoProvider<'_> {
    fn note_spender(&self, tx: &Transaction) {
        self.need_create_mtp
            .store(tx_has_bip68_time_lock(tx), Ordering::Relaxed);
    }

    fn utxo_view_stamp(&self) -> Option<u64> {
        self.query.store().utxo_view_stamp()
    }

    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        match self.chain_prevout(op) {
            ChainPrevout::Unspent(c) => Some(c),
            _ => None,
        }
    }

    fn chain_prevout(&self, op: &OutPoint) -> ChainPrevout {
        if let Some(m) = self.meter_get_coin {
            m.fetch_add(1, Ordering::Relaxed);
        }
        let tid = op.txid.to_byte_array();
        let Some((fk, create_height, outs)) = self.query.connected_tx_outputs(&tid).ok().flatten()
        else {
            return ChainPrevout::Unknown;
        };
        let Some(tip) = self.query.tip_height().map(|h| h.0) else {
            return ChainPrevout::Unknown;
        };
        if create_height > tip {
            return ChainPrevout::Unknown;
        }
        match self.query.is_outpoint_spent(&tid, op.vout) {
            Ok(true) => return ChainPrevout::KnownUnavailable,
            Ok(false) => {}
            Err(_) => return ChainPrevout::KnownUnavailable,
        }
        let Some(out) = outs.into_iter().nth(op.vout as usize) else {
            return ChainPrevout::KnownUnavailable;
        };
        let value = Amount::from_sat(out.value);
        let is_coinbase = match self.coinbase_flag(fk, create_height) {
            Ok(flag) => flag,
            Err(_) => return ChainPrevout::KnownUnavailable,
        };
        // Height 0 is the genesis coinbase. A non-coinbase there is not a coin.
        if create_height == 0 && !is_coinbase {
            return ChainPrevout::KnownUnavailable;
        }
        let create_mtp = if create_height == 0 || !self.need_create_mtp.load(Ordering::Relaxed) {
            0
        } else {
            if let Some(m) = self.meter_create_mtp {
                m.fetch_add(1, Ordering::Relaxed);
            }
            rbitcoin_query::median_time_past(self.query, Height(create_height.saturating_sub(1)))
                .unwrap_or(0)
        };
        ChainPrevout::Unspent(Coin {
            txout: TxOut {
                value,
                script_pubkey: ScriptBuf::from_bytes(out.script),
            },
            create_height,
            create_mtp,
            is_coinbase,
            create_fk: Some(fk),
        })
    }
}

/// Cap for Esplora `/mempool/recent` (newest accepts, process-local).
pub const MEMPOOL_RECENT_CAP: usize = 32;

/// Flow fullness `0.0..=1.0` as a decile. `* 10` is the scale; `+` and `/` are not.
#[doc(hidden)]
pub fn fullness_decile(alpha: f64) -> u32 {
    (alpha * 10.0).floor().clamp(0.0, 10.0) as u32
}

/// A preload is done only when the byte budget is still open and the walk
/// reached genesis. Equality with the budget is not exhausted.
#[doc(hidden)]
pub fn fee_history_scan_exhausted(
    txstat_bytes: u64,
    budget: u64,
    oldest_height: Option<u32>,
) -> bool {
    txstat_bytes < budget && oldest_height == Some(0)
}

/// Mempool-full package stamp applies only to a remainder slot that already failed.
#[doc(hidden)]
pub fn package_full_slot(in_rest: bool, slot_err: bool) -> bool {
    in_rest && slot_err
}

/// Progress lines are at most once per ten seconds, including the instant the
/// window elapses.
#[doc(hidden)]
pub fn fee_progress_due(elapsed: Duration) -> bool {
    elapsed >= Duration::from_secs(10)
}

#[doc(hidden)]
pub fn package_rpc_retry(e: &AcceptError) -> bool {
    // A parent under the dynamic mempool floor is still package-eligible:
    // Core `AcceptPackage` CPFPs it when the child pays.
    matches!(
        e,
        AcceptError::Orphaned { .. }
            | AcceptError::Policy("min relay fee")
            | AcceptError::Policy("mempool min fee")
    )
}

#[doc(hidden)]
pub fn is_hard_recent_reject(e: &AcceptError) -> bool {
    if let AcceptError::Script(s) = e {
        if s.contains("WITNESS_UNEXPECTED") || s.contains("empty witness") {
            return false;
        }
    }
    !matches!(
        e,
        AcceptError::Duplicate(_)
            | AcceptError::Orphaned { .. }
            | AcceptError::Policy("mempool full")
            | AcceptError::Policy("min relay fee")
            | AcceptError::RbfInsufficient
            | AcceptError::ClusterTooLarge { .. }
    )
}

/// One recently accepted mempool tx (for explorer "recent" strips).
#[derive(Clone, Debug)]
pub struct RecentAccept {
    pub txid: Txid,
    pub fee_sat: u64,
    /// Raw BIP141 weight (not sigop-adjusted).
    pub weight: u64,
    /// Sum of output values (sats).
    pub value_sat: u64,
}

/// Who handed a tx to [`MempoolHub::accept_tx_from`].
///
/// A `Local` admit is marked local origin under the write lock that commits
/// it, so with isolated broadcast on no session can see the tx live, in the
/// relay maps, or on the announce channel before
/// [`MempoolHub::skip_standing_inv`] is true. A package
/// ([`MempoolHub::accept_package`], `submitpackage`) is always `Local`: there
/// is no P2P package command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxOrigin {
    /// RPC, Esplora, BlindBit, or Electrum submit on this node.
    Local,
    /// Relayed, or re-entered from the orphanage. `Some` is the peer session
    /// that sent it (orphan announcer, trusted-peer waive).
    Relay(Option<u64>),
}

impl TxOrigin {
    fn peer(self) -> Option<u64> {
        match self {
            TxOrigin::Local => None,
            TxOrigin::Relay(from) => from,
        }
    }
}

/// Broadcast unit for mempool accepts (P2P inv, Electrum status, Esplora WS).
///
/// `replaced` lists conflict txids removed by full-RBF/RBFR when admitting `txid`
/// (empty when there was no replacement). `replaced_scripthashes` are output
/// scripthashes of those bodies **before** removal (wallet address-track RBF).
/// Subscribers that only care about new inventory can ignore both.
#[derive(Clone, Debug)]
pub struct MempoolAnnounce {
    pub txid: Txid,
    pub replaced: Vec<Txid>,
    pub replaced_scripthashes: Vec<[u8; 32]>,
    /// Output + spent-input scripthashes of the **new** body (Electrum notify filter).
    pub scripthashes: Vec<[u8; 32]>,
}

/// Reverse index: scripthash → live mempool txids (Electrum status / listunspent).
#[doc(hidden)]
pub struct MempoolShIndex {
    pub by_sh: HashMap<[u8; 32], HashSet<Txid>>,
    pub by_tx: HashMap<Txid, Vec<[u8; 32]>>,
}

impl MempoolShIndex {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            by_sh: HashMap::new(),
            by_tx: HashMap::new(),
        }
    }

    #[doc(hidden)]
    pub fn insert(&mut self, txid: Txid, shs: Vec<[u8; 32]>) {
        self.remove(&txid);
        for sh in &shs {
            self.by_sh.entry(*sh).or_default().insert(txid);
        }
        self.by_tx.insert(txid, shs);
    }

    #[doc(hidden)]
    pub fn remove(&mut self, txid: &Txid) {
        let Some(shs) = self.by_tx.remove(txid) else {
            return;
        };
        for sh in shs {
            if let Some(set) = self.by_sh.get_mut(&sh) {
                set.remove(txid);
                if set.is_empty() {
                    self.by_sh.remove(&sh);
                }
            }
        }
    }

    #[doc(hidden)]
    pub fn txs_for(&self, sh: &[u8; 32]) -> impl Iterator<Item = Txid> + '_ {
        self.by_sh.get(sh).into_iter().flatten().copied()
    }
}

/// Sample-and-reset window of tip-follow mempool/relay meters (`DEBUG tip: perf`).
#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolPerfSample {
    pub accepts: u64,
    pub rejects: u64,
    /// Sum of accept_tx wall times (µs) this window.
    pub accept_us: u64,
    /// Max single accept_tx wall (µs).
    pub accept_max_us: u64,
    /// Sum of exclusive mempool-lock hold times (µs) this window.
    pub accept_lock_us: u64,
    /// Sum of prevout/UTXO resolve times (µs) this window.
    pub accept_utxo_us: u64,
    /// Sum of consensus script verify times (µs) this window.
    pub accept_script_us: u64,
    /// Sum of durable append/persist times (µs) this window.
    pub accept_durable_us: u64,
    /// Tx inventory items seen that we did not already have.
    pub inv_tx: u64,
    /// Tx getdata items we issued.
    pub getdata_tx: u64,
    /// Mempool accept announces published.
    pub announce: u64,
    /// Confirmed-chain prevouts resolved by Electrum unconfirmed-balance.
    /// Unused scripthash (sh_index miss) must stay 0.
    pub delta_prevouts: u64,
    /// Live mempool bodies loaded while building the spent-outpoint set.
    /// Unused-scripthash `listunspent` must stay 0 (use `graph.conflicts`).
    pub spent_body_loads: u64,
    /// Calls to [`MempoolHub::list_live`] (clones every live body).
    pub list_live: u64,
    /// Calls to [`MempoolHub::list_live_meta`] (full live-set scan).
    pub list_live_meta: u64,
    /// Calls to [`MempoolHub::list_live_wtxids`] / `try_list_live_wtxids`.
    pub list_live_wtxids: u64,
    /// Full `accept_at` walks for INV age (`any_tx_inv_due` before the due-log).
    pub age_scan: u64,
    /// `expire_stale` walks of live accept times.
    pub expire_full_scans: u64,
    /// Tip MTP computed for accept ctx (cache miss).
    pub tip_mtp: u64,
    /// `QueryUtxoProvider::get_coin` calls on the hub provider.
    pub get_coin: u64,
    /// Create-block MTP from `get_coin` (BIP68 time-lock spends only).
    pub get_coin_create_mtp: u64,
}

/// Core default `-mempoolexpiry` (336 hours) in seconds.
#[doc(hidden)]
pub const DEFAULT_MEMPOOL_EXPIRY_SECS: u64 = 336 * 3600;
/// Core `NONPREF_PEER_TX_DELAY` (inbound / non-preferred).
pub const NONPREF_PEER_TX_DELAY_SECS: u64 = 2;
/// Core `TXID_RELAY_DELAY` (parent GETDATA is by txid, not wtxid).
pub const TXID_RELAY_DELAY_SECS: u64 = 2;
/// Core `GETDATA_TX_INTERVAL` (in-flight parent request expiry).
pub const GETDATA_TX_INTERVAL_SECS: u64 = 60;
/// Cap unique parent GETDATA items issued from one flush.
/// Core `MAX_PEER_TX_REQUEST_IN_FLIGHT`.
#[doc(hidden)]
pub const MAX_PARENTS_PER_PARK: usize = 100;

/// INV AlreadyHave for recently confirmed txid/wtxid (Core rolling bloom is ~100k).
#[doc(hidden)]
pub const RECENT_CONFIRMED_CAP: usize = 65_536;

#[doc(hidden)]
pub struct RecentConfirmed {
    pub order: VecDeque<(Txid, Wtxid)>,
    pub txids: HashSet<Txid>,
    pub wtxids: HashSet<Wtxid>,
}

impl RecentConfirmed {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            order: VecDeque::new(),
            txids: HashSet::new(),
            wtxids: HashSet::new(),
        }
    }

    #[doc(hidden)]
    pub fn note_block(&mut self, txs: &[Transaction]) {
        self.note_block_capped(txs, RECENT_CONFIRMED_CAP);
    }

    #[doc(hidden)]
    pub fn note_block_capped(&mut self, txs: &[Transaction], cap: usize) {
        for tx in txs {
            let txid = tx.compute_txid();
            let wtxid = tx.compute_wtxid();
            if !self.txids.insert(txid) {
                continue;
            }
            self.wtxids.insert(wtxid);
            self.order.push_back((txid, wtxid));
            if self.order.len() > cap {
                if let Some((old_t, old_w)) = self.order.pop_front() {
                    self.txids.remove(&old_t);
                    self.wtxids.remove(&old_w);
                }
            }
        }
    }

    #[doc(hidden)]
    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.txids.contains(txid)
    }

    #[doc(hidden)]
    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.wtxids.contains(wtxid)
    }

    #[doc(hidden)]
    pub fn clear(&mut self) {
        self.order.clear();
        self.txids.clear();
        self.wtxids.clear();
    }
}

#[doc(hidden)]
pub struct AdmitSpec {
    pub report_orphans: bool,
    pub fee_delta: i64,
    pub time_prepare_lock: bool,
    pub min_relay: Option<u64>,
    /// This tx came from the current trusted session.
    pub waive: bool,
}

/// Local-origin txids. With isolated broadcast on, each is queued once for
/// the one-shot loop, in submit order. An entry leaves with its tx
/// ([`MempoolHub::unindex_txid`]), so the queue never outgrows the set and
/// never hands out a tx that left the mempool.
#[derive(Default)]
struct LocalOrigin {
    txs: HashMap<Txid, IsolatedTurn>,
    next: u64,
}

#[derive(Clone, Copy)]
enum IsolatedTurn {
    /// Marked under the admit write lock, not yet handed to the loop, or
    /// isolated broadcast was off when its submit finished.
    Held,
    /// Waiting for the isolated loop. The number is submit order.
    Waiting(u64),
    /// The loop took it.
    Taken,
}

impl LocalOrigin {
    fn mark(&mut self, txid: Txid) {
        self.txs.entry(txid).or_insert(IsolatedTurn::Held);
    }

    /// Queue a held txid for the loop. False when it is not held: never
    /// marked, gone with its tx, or already queued once.
    fn queue(&mut self, txid: &Txid) -> bool {
        let Some(turn) = self.txs.get_mut(txid) else {
            return false;
        };
        if !matches!(turn, IsolatedTurn::Held) {
            return false;
        }
        self.next += 1;
        *turn = IsolatedTurn::Waiting(self.next);
        true
    }

    /// The oldest waiting txid, now taken, and how many still wait.
    fn take(&mut self) -> Option<(Txid, usize)> {
        let mut oldest: Option<(u64, Txid)> = None;
        let mut waiting = 0usize;
        for (txid, turn) in &self.txs {
            let IsolatedTurn::Waiting(n) = *turn else {
                continue;
            };
            waiting += 1;
            if oldest.is_none_or(|(m, _)| n < m) {
                oldest = Some((n, *txid));
            }
        }
        let (_, txid) = oldest?;
        self.txs.insert(txid, IsolatedTurn::Taken);
        Some((txid, waiting - 1))
    }
}

/// Shared mempool + relay gate used by peer sessions and tip confirm.
pub struct MempoolHub {
    pub inner: RwLock<ActiveMempool>,
    pub query: Arc<Query>,
    /// When false, peers' tx inv/tx are ignored (IBD / catch-up).
    pub relay_enabled: AtomicBool,
    /// Set once the pool has been purged and later blocks strip it. Stays set
    /// when peer relay is paused. `-blocksonly` never sets it.
    pool_maintained: AtomicBool,
    /// Set when relay flips off to on. The node supervisor spawns fee-history
    /// backfill and clears it. That waits for peer relay, not pool maintenance.
    fee_backfill_due: AtomicBool,
    /// Session id of the current trusted peer. [`u64::MAX`] means none.
    pub trusted_session: AtomicU64,
    /// Broadcast accepts so sessions can inv (origin exclusion is per-session).
    pub announce: broadcast::Sender<MempoolAnnounce>,
    /// `setmocktime` jump: sessions INV live mempool txs (Core scheduler).
    pub inv_flush: broadcast::Sender<()>,
    /// Newest-last ring of successful accepts (Esplora `/mempool/recent`).
    pub recent: Mutex<std::collections::VecDeque<RecentAccept>>,
    /// Recently confirmed txid/wtxid for INV AlreadyHave.
    pub recent_confirmed: Mutex<RecentConfirmed>,
    /// Core `m_lazy_recent_rejects` (wtxid). Forcerelay second-send skips ATMP.
    pub recent_rejects: Mutex<HashSet<Wtxid>>,
    /// Own feerates (sat/kvB) of the 64 newest confirmed entries, for the N=1 floor.
    pub confirm_feerate_memory: Mutex<std::collections::VecDeque<u64>>,
    /// Per-block vsize-weighted p10 hurdle, bounded by txstat body bytes.
    pub block_p10_history: Mutex<FeeHistory>,
    /// Open once a preload wrote a snapshot. Lock order: this, then history.
    pub fee_journal: Mutex<Option<FeeJournal>>,
    /// Last logged `(flow fullness decile << 16) | ready targets`.
    pub fee_readiness: AtomicU32,
    /// Process-local admit/confirm/evict EMA for flow-aware fee estimates.
    pub fee_flow: Mutex<FeeFlowMeter>,
    /// Published fee table for Electrum/Esplora (refreshed dirty ∥ max-age, singleflight).
    pub fee_snapshot: ArcSwap<FeeSnapshot>,
    pub fee_dirty: AtomicBool,
    pub fee_refreshing: AtomicBool,
    /// Published live mempool txs for Esplora `/internal/mempool/*`.
    pub tx_snapshot: ArcSwap<MempoolTxSnapshot>,
    pub tx_snap_dirty: AtomicBool,
    pub tx_snap_refreshing: AtomicBool,
    pub meter_accepts: PerfCounter,
    pub meter_rejects: PerfCounter,
    pub meter_accept_us: AtomicU64,
    pub meter_accept_max_us: PerfMax,
    pub meter_accept_lock_us: AtomicU64,
    pub meter_accept_utxo_us: AtomicU64,
    pub meter_accept_script_us: AtomicU64,
    pub meter_accept_durable_us: AtomicU64,
    pub meter_inv_tx: AtomicU64,
    pub meter_getdata_tx: AtomicU64,
    pub meter_announce: AtomicU64,
    /// Chain prevouts resolved by [`Self::scripthash_unconfirmed_delta`].
    pub meter_delta_prevouts: AtomicU64,
    /// Bodies loaded by [`Self::spent_outpoints`] (must stay 0 after conflict-map).
    pub meter_spent_body_loads: AtomicU64,
    /// Full live-set clones ([`Self::list_live`]).
    pub meter_list_live: AtomicU64,
    /// Full live-set meta scans ([`Self::list_live_meta`]).
    pub meter_list_live_meta: AtomicU64,
    pub meter_list_live_wtxids: AtomicU64,
    pub meter_age_scan: AtomicU64,
    pub meter_expire_full_scans: AtomicU64,
    pub meter_tip_mtp: AtomicU64,
    pub meter_get_coin: AtomicU64,
    pub meter_get_coin_create_mtp: AtomicU64,
    /// Compact short-id walks that take the mempool read lock. Test builds only.
    #[cfg(debug_assertions)]
    pub meter_cmpct_avail: AtomicU64,
    /// Live mempool txs by Electrum scripthash (updated on accept/remove).
    pub sh_index: Mutex<MempoolShIndex>,
    /// `{datadir}/mempool` — sidecar `unbroadcast` lives here.
    pub dir: PathBuf,
    /// Locally submitted txids not yet requested by a peer (`getmempoolinfo.unbroadcastcount`).
    pub unbroadcast: Mutex<HashSet<Txid>>,
    local_origin: Mutex<LocalOrigin>,
    pub isolated_broadcast: AtomicBool,
    /// Wakes the isolated loop when a local tx is queued for it.
    isolated_wake: tokio::sync::Notify,
    /// One isolated-broadcast lap: skipped an unknown tx, blocked on a write,
    /// or found no dial targets. The wait; the send or the skip is the assert.
    isolated_skipped_unknown: AtomicU64,
    isolated_lagged: AtomicU64,
    isolated_no_targets: AtomicU64,
    isolated_lap: tokio::sync::Notify,
    /// Wtxids re-admitted from a disconnected block. Core serves these
    /// even if this peer has not been INV'd yet (`mempool_reorg`).
    pub reorg_servable: Mutex<HashSet<Wtxid>>,
    /// Core mempool entry_sequence. Regular accept starts at 1; reorg is 0.
    pub relay_seq: Mutex<HashMap<Wtxid, u64>>,
    /// Reverse of `relay_seq` / `accept_at` so `unindex_txid` can drop them
    /// after the graph entry is already gone.
    pub wtxid_by_txid: Mutex<HashMap<Txid, Wtxid>>,
    pub next_relay_seq: AtomicU64,
    /// `prioritisetransaction` fee deltas (sat), keyed by txid even if not live.
    pub fee_deltas: Mutex<HashMap<Txid, i64>>,
    /// Monotonic template generation (admit / remove / prioritise). GBT longpoll.
    template_updates: AtomicU64,
    /// Same generation as [`Self::template_updates`]. Long-poll subscribes.
    template_watch: tokio::sync::watch::Sender<u64>,
    /// Tip whose mempool strip has finished. Block templates build on this.
    /// The query tip is visible earlier, before `remove_for_block_spent`.
    template_prev: Mutex<Option<[u8; 32]>>,
    /// Odd while a [`TemplateHold`] is out, so the pool may not match the tip.
    pool_settle: AtomicU64,
    /// Nonzero from an invalidate disconnect until the replacement attempt
    /// finishes. An admit in that gap must not publish the stump.
    template_publish_pause: AtomicU64,
    /// INV immediately instead of waiting on mocktime.
    pub immediate_relay: AtomicBool,
    /// Last `setmocktime` (0 = wall). Used to age mempool txs for delayed INV.
    /// Shared with the mempool, which stamps it on each durable record.
    pub mock_now: Arc<AtomicU64>,
    /// Mock/wall seconds when each live wtxid was accepted.
    pub accept_at: Mutex<HashMap<Wtxid, u64>>,
    /// Monotonic accept generation for `p2p_tx_privacy` (skip pre-handshake txs).
    pub next_accept_gen: AtomicU64,
    pub accept_gen: Mutex<HashMap<Wtxid, u64>>,
    /// Mempool expiry in seconds (default 336h).
    pub expiry_secs: AtomicU64,
    /// Accept-time order for expiry: `(accept_at, wtxid) → txid`, one row per
    /// live tx. Extra RAM beside `accept_at` (key + txid, plus tree nodes;
    /// about 8 MiB at 100k txs) so a 256-entry scan reads the oldest accepts
    /// and does not walk `wtxid_by_txid`.
    pub expiry_order: Mutex<BTreeMap<(u64, Wtxid), Txid>>,
    /// Min-relay overlay (sat/kvB). Readers avoid `inner`.
    pub min_relay_sat_kvb: AtomicU64,
    /// Enforced admission floor (sat/kvB): configured min, the near-full
    /// bump, and the decaying eviction floor. Handshake FeeFilter and
    /// Electrum read this without taking `inner`.
    pub fee_floor_sat_kvb: AtomicU64,
    /// Age-INV log: `(due_secs, accept_gen) → (txid, wtxid)`. Not `inner`.
    pub age_inv: Mutex<BTreeMap<(u64, u64), (Txid, Wtxid)>>,
    /// Min live `accept_at` (`u64::MAX` if empty).
    pub min_live_accept_at: AtomicU64,
    /// Cached tip MTP for accept (`{header_fk, ctx}`).
    pub tip_ctx: Mutex<Option<(Fk, ChainTipCtx)>>,
    /// TxRequestTracker-shaped missing-parent GETDATA.
    pub parent_req: Mutex<parent_req::ParentTracker>,
}

#[doc(hidden)]
pub const EXPIRE_SCAN: usize = 256;

/// Oldest expired accepts, at most [`EXPIRE_SCAN`]. The map is ordered by
/// accept time, so the first still-young key ends the scan.
#[doc(hidden)]
pub fn expired_roots_in(order: &BTreeMap<(u64, Wtxid), Txid>, now: u64, lim: u64) -> Vec<Txid> {
    let mut roots = Vec::new();
    for (&(at, _), txid) in order.iter() {
        if now.saturating_sub(at) < lim {
            break;
        }
        roots.push(*txid);
        if roots.len() == EXPIRE_SCAN {
            break;
        }
    }
    roots
}

/// One `submitpackage` member after individual accept, package CPFP, and trim.
#[derive(Debug)]
pub struct SubmitPackageRow {
    pub result: Result<AcceptResult, AcceptError>,
    /// Remainder whose modified fees make up this tx's effective feerate.
    /// `None` when the tx was admitted on its own.
    pub fee_with: Option<Vec<Txid>>,
}

/// Confirmed coins sampled before the write lock. `stamp` is `None` when a
/// confirm or disconnect is already changing spentness.
#[doc(hidden)]
pub struct SampledCoins {
    pub stamp: Option<u64>,
    pub creators: Vec<bool>,
    pub coins: Vec<Option<rbitcoin_mempool::Coin>>,
}

/// One commit after the script checks, plus what a failure already removed.
#[doc(hidden)]
pub struct CommitOutcome {
    pub result: Result<AcceptResult, AcceptError>,
    pub failed_evict: Vec<Txid>,
    pub undone: Vec<Transaction>,
    pub prevouts: Vec<TxOut>,
}

/// Lock held for the whole of a block connect. `commit` records the hash
/// whose pool strip has finished; the drop writes it.
#[doc(hidden)]
pub struct TemplateHold<'a> {
    updates: &'a AtomicU64,
    watch: &'a tokio::sync::watch::Sender<u64>,
    settle: &'a AtomicU64,
    slot: std::sync::MutexGuard<'a, Option<[u8; 32]>>,
    commit: Option<[u8; 32]>,
}

impl TemplateHold<'_> {
    pub(crate) fn commit(&mut self, hash: [u8; 32]) {
        self.commit = Some(hash);
    }
}

/// Pauses [`MempoolHub::note_template_update`] for one invalidate.
#[doc(hidden)]
pub struct TemplatePublishPause {
    mp: Arc<MempoolHub>,
}

impl Drop for TemplatePublishPause {
    fn drop(&mut self) {
        self.mp
            .template_publish_pause
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for TemplateHold<'_> {
    fn drop(&mut self) {
        if let Some(hash) = self.commit {
            *self.slot = Some(hash);
            let next = self.updates.fetch_add(1, Ordering::Relaxed) + 1;
            self.watch.send_replace(next);
        }
        self.settle.fetch_add(1, Ordering::SeqCst);
    }
}

/// One isolated-broadcast lap the loop can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum IsolatedLap {
    /// `get_tx` missed: the txid was never admitted, or it left before its turn.
    SkippedUnknown,
    /// The queue was past the backlog warn, or the live read blocked on a write.
    Lagged,
    /// AddrMan had no onion or IP target.
    NoTargets,
}

/// [`MempoolHub::isolated_laps`] snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct IsolatedLapCounts {
    pub skipped_unknown: u64,
    pub lagged: u64,
    pub no_targets: u64,
}

impl MempoolHub {
    /// Short-id walks that entered the mempool, including a `try_read` miss.
    #[cfg(debug_assertions)]
    pub fn cmpct_avail_scans(&self) -> u64 {
        self.meter_cmpct_avail.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, ActiveMempool> {
        crate::reactor::assert_not_reactor("mempool inner read");
        self.inner.read().unwrap()
    }

    #[doc(hidden)]
    pub fn lock_write(&self) -> std::sync::RwLockWriteGuard<'_, ActiveMempool> {
        crate::reactor::assert_not_reactor("mempool inner write");
        self.inner.write().unwrap()
    }

    pub fn open(dir: impl AsRef<Path>, query: Arc<Query>) -> Result<Arc<Self>, String> {
        Self::open_with_weight(dir, query, rbitcoin_mempool::DEFAULT_MAX_MEMPOOL_WEIGHT)
    }

    /// Open with a weight budget (WU). `max_weight_wu` drives chunk eviction.
    pub fn open_with_weight(
        dir: impl AsRef<Path>,
        query: Arc<Query>,
        max_weight_wu: u64,
    ) -> Result<Arc<Self>, String> {
        Self::open_with_weight_persist(dir, query, max_weight_wu, true)
    }

    /// `persist=false` starts with an empty live set (Core `-persistmempool=0`).
    pub fn open_with_weight_persist(
        dir: impl AsRef<Path>,
        query: Arc<Query>,
        max_weight_wu: u64,
        persist: bool,
    ) -> Result<Arc<Self>, String> {
        Self::open_with_weight_persist_and_sigop_reserve(dir, query, max_weight_wu, persist, None)
    }

    /// Open with a configured reserve applied before migrated entries are
    /// recomputed, so admission and template selection share the same budget.
    pub fn open_with_weight_persist_and_sigop_reserve(
        dir: impl AsRef<Path>,
        query: Arc<Query>,
        max_weight_wu: u64,
        persist: bool,
        reserved_sigops: Option<u64>,
    ) -> Result<Arc<Self>, String> {
        let dir_buf = dir.as_ref().to_path_buf();
        let mut mp = ActiveMempool::open_with_limit_persist(dir.as_ref(), max_weight_wu, persist)
            .map_err(|e| format!("mempool open: {e}"))?;
        if let Some(reserved) = reserved_sigops {
            mp.set_block_reserved_sigops(reserved);
        }
        if !query.trust_peer() {
            mp.discard_trust_marks()
                .map_err(|e| format!("mempool open: {e}"))?;
        }
        let (announce, _) = broadcast::channel(256);
        let (inv_flush, _) = broadcast::channel(16);
        let unbroadcast = if persist {
            load_unbroadcast_file(&dir_buf)
        } else {
            HashSet::new()
        };
        let hub = Self {
            dir: dir_buf,
            inner: RwLock::new(mp),
            query,
            relay_enabled: AtomicBool::new(false),
            pool_maintained: AtomicBool::new(false),
            fee_backfill_due: AtomicBool::new(false),
            trusted_session: AtomicU64::new(u64::MAX),
            announce,
            inv_flush,
            recent: Mutex::new(std::collections::VecDeque::with_capacity(
                MEMPOOL_RECENT_CAP,
            )),
            recent_confirmed: Mutex::new(RecentConfirmed::new()),
            recent_rejects: Mutex::new(HashSet::new()),
            confirm_feerate_memory: Mutex::new(std::collections::VecDeque::with_capacity(64)),
            block_p10_history: Mutex::new(FeeHistory::new(
                FEE_HISTORY_TXSTAT_BYTE_BUDGET,
                FEE_SNAPSHOT_DEPTHS,
            )),
            fee_journal: Mutex::new(None),
            fee_readiness: AtomicU32::new(u32::MAX),
            fee_flow: Mutex::new(FeeFlowMeter::new(Instant::now())),
            fee_snapshot: ArcSwap::from_pointee(FeeSnapshot::empty(Instant::now())),
            fee_dirty: AtomicBool::new(true),
            fee_refreshing: AtomicBool::new(false),
            tx_snapshot: ArcSwap::from_pointee(MempoolTxSnapshot::empty(Instant::now())),
            tx_snap_dirty: AtomicBool::new(true),
            tx_snap_refreshing: AtomicBool::new(false),
            meter_accepts: PerfCounter::new(),
            meter_rejects: PerfCounter::new(),
            meter_accept_us: AtomicU64::new(0),
            meter_accept_max_us: PerfMax::new(),
            meter_accept_lock_us: AtomicU64::new(0),
            meter_accept_utxo_us: AtomicU64::new(0),
            meter_accept_script_us: AtomicU64::new(0),
            meter_accept_durable_us: AtomicU64::new(0),
            meter_inv_tx: AtomicU64::new(0),
            meter_getdata_tx: AtomicU64::new(0),
            meter_announce: AtomicU64::new(0),
            meter_delta_prevouts: AtomicU64::new(0),
            meter_spent_body_loads: AtomicU64::new(0),
            meter_list_live: AtomicU64::new(0),
            meter_list_live_meta: AtomicU64::new(0),
            meter_list_live_wtxids: AtomicU64::new(0),
            meter_age_scan: AtomicU64::new(0),
            meter_expire_full_scans: AtomicU64::new(0),
            meter_tip_mtp: AtomicU64::new(0),
            meter_get_coin: AtomicU64::new(0),
            meter_get_coin_create_mtp: AtomicU64::new(0),
            #[cfg(debug_assertions)]
            meter_cmpct_avail: AtomicU64::new(0),
            sh_index: Mutex::new(MempoolShIndex::new()),
            unbroadcast: Mutex::new(unbroadcast),
            local_origin: Mutex::new(LocalOrigin::default()),
            isolated_broadcast: AtomicBool::new(false),
            isolated_wake: tokio::sync::Notify::new(),
            isolated_skipped_unknown: AtomicU64::new(0),
            isolated_lagged: AtomicU64::new(0),
            isolated_no_targets: AtomicU64::new(0),
            isolated_lap: tokio::sync::Notify::new(),
            reorg_servable: Mutex::new(HashSet::new()),
            relay_seq: Mutex::new(HashMap::new()),
            wtxid_by_txid: Mutex::new(HashMap::new()),
            next_relay_seq: AtomicU64::new(1),
            immediate_relay: AtomicBool::new(false),
            mock_now: Arc::new(AtomicU64::new(0)),
            accept_at: Mutex::new(HashMap::new()),
            next_accept_gen: AtomicU64::new(1),
            accept_gen: Mutex::new(HashMap::new()),
            expiry_secs: AtomicU64::new(DEFAULT_MEMPOOL_EXPIRY_SECS),
            expiry_order: Mutex::new(BTreeMap::new()),
            min_relay_sat_kvb: AtomicU64::new(
                rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            ),
            fee_floor_sat_kvb: AtomicU64::new(
                rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            ),
            fee_deltas: Mutex::new(HashMap::new()),
            template_updates: AtomicU64::new(0),
            template_watch: tokio::sync::watch::channel(0).0,
            template_prev: Mutex::new(None),
            pool_settle: AtomicU64::new(0),
            template_publish_pause: AtomicU64::new(0),
            age_inv: Mutex::new(BTreeMap::new()),
            min_live_accept_at: AtomicU64::new(u64::MAX),
            tip_ctx: Mutex::new(None),
            parent_req: Mutex::new(parent_req::ParentTracker::new()),
        };
        // Schema ≤ 2 records carry no sigop cost: fill (or evict) before serving.
        let loaded = {
            let mut g = hub.lock_write();
            g.set_node_clock(Arc::clone(&hub.mock_now));
            g.recompute_missing_sigops(&QueryUtxoProvider::new(&hub.query));
            g.take_loaded_accept_times()
        };
        // Stored accept times feed expiry and `getmempoolentry.time`. A loaded
        // tx is not queued for INV. Like Core's load, it takes a fresh entry
        // sequence, so a peer cannot getdata it before an INV.
        for (txid, wtxid, at) in loaded {
            if hub.contains(&txid) {
                let seq = hub.next_relay_seq.fetch_add(1, Ordering::Relaxed);
                hub.insert_relay_maps(txid, wtxid, seq, at, false);
            }
        }
        {
            let mut u = hub.unbroadcast.lock().unwrap();
            u.retain(|t| hub.contains(t));
        }
        hub.reindex_live_scripthashes();
        hub.publish_fee_floor();
        Ok(Arc::new(hub))
    }

    /// Output + spent-input Electrum scripthashes for a live (or just-accepted) tx.
    #[doc(hidden)]
    pub fn collect_tx_scripthashes(
        &self,
        txid: &Txid,
        tx: &Transaction,
        mp: &ActiveMempool,
        missing: &mut Vec<OutPoint>,
    ) -> Vec<[u8; 32]> {
        use rbitcoin_store::script_hash;
        let mut out = Vec::with_capacity(tx.output.len() + tx.input.len());
        for o in &tx.output {
            out.push(script_hash(o.script_pubkey.as_bytes()));
        }
        let aux = mp.vin_aux(txid);
        for (i, inp) in tx.input.iter().enumerate() {
            let op = inp.previous_output;
            if let Some(creator) = mp.graph.creator(&op) {
                if let Some(s) = mp
                    .get_tx(&creator)
                    .and_then(|t| t.output.get(op.vout as usize))
                    .map(|o| script_hash(o.script_pubkey.as_bytes()))
                {
                    out.push(s);
                    continue;
                }
            }
            if let Some(sh) = aux.get(i).and_then(|a| a.script_hash) {
                out.push(sh);
                continue;
            }
            missing.push(op);
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    #[doc(hidden)]
    pub fn reindex_live_scripthashes(&self) {
        let g = self.lock_read();
        let mut idx = MempoolShIndex::new();
        let mut missing_ops: Vec<OutPoint> = Vec::new();
        let mut pending: Vec<(Txid, Vec<[u8; 32]>, Vec<OutPoint>)> = Vec::new();
        for (txid, _) in g.graph.iter() {
            let Some(tx) = g.get_tx(txid) else { continue };
            let mut miss = Vec::new();
            let shs = self.collect_tx_scripthashes(txid, tx, &g, &mut miss);
            if miss.is_empty() {
                idx.insert(*txid, shs);
            } else {
                missing_ops.extend_from_slice(&miss);
                pending.push((*txid, shs, miss));
            }
        }
        drop(g);
        let filled = self.batch_fill_script_hashes(&missing_ops);
        for (txid, mut shs, miss) in pending {
            for op in miss {
                if let Some(sh) = filled.get(&op) {
                    shs.push(*sh);
                }
            }
            shs.sort_unstable();
            shs.dedup();
            idx.insert(txid, shs);
        }
        *self.sh_index.lock().unwrap() = idx;
    }

    #[doc(hidden)]
    pub fn batch_fill_script_hashes(&self, ops: &[OutPoint]) -> HashMap<OutPoint, [u8; 32]> {
        use rbitcoin_store::script_hash;
        let mut out = HashMap::new();
        if ops.is_empty() {
            return out;
        }
        let mut by_txid: HashMap<[u8; 32], Vec<u32>> = HashMap::new();
        for op in ops {
            by_txid
                .entry(op.txid.to_byte_array())
                .or_default()
                .push(op.vout);
        }
        let txids: Vec<[u8; 32]> = by_txid.keys().copied().collect();
        let Ok(hits) = self.query.store().get_fk_by_txid_batch(&txids) else {
            return out;
        };
        for (tid, row) in hits {
            let Some((fk, _pair)) = row else { continue };
            let Some(vouts) = by_txid.get(&tid) else {
                continue;
            };
            for &vout in vouts {
                if let Ok(rec) = self.query.tx_output_at_fk(fk, vout) {
                    let op = OutPoint {
                        txid: Txid::from_byte_array(tid),
                        vout,
                    };
                    out.insert(op, script_hash(&rec.script));
                }
            }
        }
        out
    }

    #[doc(hidden)]
    pub fn index_txid(&self, txid: Txid, tx: &Transaction, prevouts: &[TxOut]) {
        use rbitcoin_store::script_hash;
        let mut shs = Vec::with_capacity(tx.output.len() + prevouts.len());
        for o in &tx.output {
            shs.push(script_hash(o.script_pubkey.as_bytes()));
        }
        for o in prevouts {
            shs.push(script_hash(o.script_pubkey.as_bytes()));
        }
        shs.sort_unstable();
        shs.dedup();
        self.sh_index.lock().unwrap().insert(txid, shs);
    }

    #[doc(hidden)]
    pub fn utxo_provider(&self) -> QueryUtxoProvider<'_> {
        let mut p = QueryUtxoProvider::new(self.query.as_ref());
        p.meter_get_coin = Some(&self.meter_get_coin);
        p.meter_create_mtp = Some(&self.meter_get_coin_create_mtp);
        p
    }

    #[doc(hidden)]
    pub fn unindex_txid(&self, txid: &Txid) {
        self.sh_index.lock().unwrap().remove(txid);
        self.remove_relay_maps(txid);
        self.local_origin.lock().unwrap().txs.remove(txid);
        let mut u = self.unbroadcast.lock().unwrap();
        if u.remove(txid) {
            persist_unbroadcast_file(&self.dir, &u);
            rbitcoin_log::info!("{}", Self::unbroadcast_removed_log(txid));
        }
    }

    pub fn relay_now_secs(&self) -> u64 {
        let mock = self.mock_now.load(Ordering::Relaxed);
        if mock != 0 {
            return mock;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Index a live tx accepted at `at` (node seconds). `age_inv` queues the
    /// delayed INV for a fresh accept.
    #[doc(hidden)]
    pub fn insert_relay_maps(&self, txid: Txid, wtxid: Wtxid, seq: u64, at: u64, age_inv: bool) {
        let gen = self.next_accept_gen.fetch_add(1, Ordering::Relaxed);
        let due = at.saturating_add(30);
        let mut by_tx = self.wtxid_by_txid.lock().unwrap();
        let mut seqs = self.relay_seq.lock().unwrap();
        let mut ats = self.accept_at.lock().unwrap();
        let mut gens = self.accept_gen.lock().unwrap();
        let mut age = self.age_inv.lock().unwrap();
        let mut order = self.expiry_order.lock().unwrap();
        if let Some(prev_w) = by_tx.insert(txid, wtxid) {
            if let Some(prev_at) = ats.get(&prev_w).copied() {
                order.remove(&(prev_at, prev_w));
            }
        }
        seqs.insert(wtxid, seq);
        ats.insert(wtxid, at);
        gens.insert(wtxid, gen);
        if age_inv {
            age.insert((due, gen), (txid, wtxid));
        }
        order.insert((at, wtxid), txid);
        self.min_live_accept_at.fetch_min(at, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn remove_relay_maps(&self, txid: &Txid) {
        let mut by_tx = self.wtxid_by_txid.lock().unwrap();
        let mut seqs = self.relay_seq.lock().unwrap();
        let mut ats = self.accept_at.lock().unwrap();
        let mut gens = self.accept_gen.lock().unwrap();
        let mut age = self.age_inv.lock().unwrap();
        let mut order = self.expiry_order.lock().unwrap();
        if let Some(w) = by_tx.remove(txid) {
            seqs.remove(&w);
            let at = ats.remove(&w);
            let gen = gens.remove(&w);
            if let (Some(at), Some(gen)) = (at, gen) {
                age.remove(&(at.saturating_add(30), gen));
            }
            if let Some(at) = at {
                order.remove(&(at, w));
            }
            let min = ats.values().copied().min().unwrap_or(u64::MAX);
            self.min_live_accept_at.store(min, Ordering::Relaxed);
        }
    }

    /// Next accept generation (for peer `inv_gen_floor` at register).
    pub fn next_accept_gen(&self) -> u64 {
        self.next_accept_gen.load(Ordering::Relaxed)
    }

    pub fn accept_gen(&self, wtxid: &Wtxid) -> Option<u64> {
        self.accept_gen.lock().unwrap().get(wtxid).copied()
    }

    /// Core `mempool_unbroadcast.py` debug.log needle when a local tx confirms
    /// before a peer getdata's it.
    pub fn unbroadcast_removed_log(txid: &Txid) -> String {
        format!(
            "p2p: Removed {txid} from set of unbroadcast txns before confirmation that txn was sent out"
        )
    }

    /// Count peer inv of txs we do not already hold (want → getdata path).
    pub fn note_inv_tx(&self, n: u64) {
        if n > 0 {
            self.meter_inv_tx.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Count tx getdata items we issued to peers.
    pub fn note_getdata_tx(&self, n: u64) {
        if n > 0 {
            self.meter_getdata_tx.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn meter_accept_wall(&self, us: u64, ok: bool) {
        if ok {
            self.meter_accepts.add(1);
        } else {
            self.meter_rejects.add(1);
        }
        self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
        self.meter_accept_max_us.note(us);
    }

    #[doc(hidden)]
    pub fn meter_accept_stages(&self, lock_us: u64, stages: rbitcoin_mempool::AcceptStageUs) {
        self.meter_accept_lock_us
            .fetch_add(lock_us, Ordering::Relaxed);
        self.meter_accept_utxo_us
            .fetch_add(stages.utxo_us, Ordering::Relaxed);
        self.meter_accept_script_us
            .fetch_add(stages.script_us, Ordering::Relaxed);
        self.meter_accept_durable_us
            .fetch_add(stages.durable_us, Ordering::Relaxed);
    }

    /// Running mempool accepts and rejects for `/metrics`. A
    /// [`Self::sample_reset_perf`] window does not reset them.
    pub fn accept_totals(&self) -> (u64, u64) {
        (self.meter_accepts.total(), self.meter_rejects.total())
    }

    /// Mempool/relay counters since the previous sample, for the tip-follow
    /// 5s DEBUG line.
    pub fn sample_reset_perf(&self) -> MempoolPerfSample {
        MempoolPerfSample {
            accepts: self.meter_accepts.take_window(),
            rejects: self.meter_rejects.take_window(),
            accept_us: self.meter_accept_us.swap(0, Ordering::Relaxed),
            accept_max_us: self.meter_accept_max_us.take(),
            accept_lock_us: self.meter_accept_lock_us.swap(0, Ordering::Relaxed),
            accept_utxo_us: self.meter_accept_utxo_us.swap(0, Ordering::Relaxed),
            accept_script_us: self.meter_accept_script_us.swap(0, Ordering::Relaxed),
            accept_durable_us: self.meter_accept_durable_us.swap(0, Ordering::Relaxed),
            inv_tx: self.meter_inv_tx.swap(0, Ordering::Relaxed),
            getdata_tx: self.meter_getdata_tx.swap(0, Ordering::Relaxed),
            announce: self.meter_announce.swap(0, Ordering::Relaxed),
            delta_prevouts: self.meter_delta_prevouts.swap(0, Ordering::Relaxed),
            spent_body_loads: self.meter_spent_body_loads.swap(0, Ordering::Relaxed),
            list_live: self.meter_list_live.swap(0, Ordering::Relaxed),
            list_live_meta: self.meter_list_live_meta.swap(0, Ordering::Relaxed),
            list_live_wtxids: self.meter_list_live_wtxids.swap(0, Ordering::Relaxed),
            age_scan: self.meter_age_scan.swap(0, Ordering::Relaxed),
            expire_full_scans: self.meter_expire_full_scans.swap(0, Ordering::Relaxed),
            tip_mtp: self.meter_tip_mtp.swap(0, Ordering::Relaxed),
            get_coin: self.meter_get_coin.swap(0, Ordering::Relaxed),
            get_coin_create_mtp: self.meter_get_coin_create_mtp.swap(0, Ordering::Relaxed),
        }
    }

    #[doc(hidden)]
    pub fn push_recent(&self, tx: &Transaction, r: &AcceptResult) {
        let value_sat: u64 = tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .fold(0u64, |a, b| a.saturating_add(b));
        let entry = RecentAccept {
            txid: r.txid,
            fee_sat: r.fee_sat,
            // Raw: Esplora `/mempool/recent` vsize is electrs `tx.vsize()`.
            weight: tx.weight().to_wu(),
            value_sat,
        };
        let mut q = self.recent.lock().unwrap();
        q.push_back(entry);
        while q.len() > MEMPOOL_RECENT_CAP {
            q.pop_front();
        }
    }

    /// Newest-first snapshot of recent accepts (at most 10 for Esplora `/mempool/recent`).
    pub fn recent_accepts(&self) -> Vec<RecentAccept> {
        const ESPLORA_RECENT: usize = 10;
        let q = self.recent.lock().unwrap();
        q.iter().rev().take(ESPLORA_RECENT).cloned().collect()
    }

    /// Compact durable mempool files (reclaim DEAD slots / body holes).
    pub fn compact(&self) -> Result<(u32, usize), String> {
        self.lock_write()
            .compact()
            .map_err(|e| format!("mempool compact: {e}"))
    }

    /// Enable/disable peer tx inv/accept (false during IBD catch-up).
    ///
    /// **False → true** starts pool maintenance when the accept path has not
    /// already, and owes fee-history preload. Turning relay off does not stop
    /// maintenance: per-block strip keeps running. Bulk IBD still skips that
    /// strip until the pool is maintained, so catch-up is not paced by a
    /// large durable mempool before the tip leaves IBD.
    pub fn set_relay_enabled(&self, on: bool) {
        let prev = self.relay_enabled();
        // A failed purge leaves maintenance off. Do not record relay as on,
        // or this edge never runs again and the purge is skipped for good.
        if on && !self.begin_pool_maintenance() {
            return;
        }
        if on && !prev {
            self.fee_backfill_due.store(true, Ordering::Release);
        }
        self.relay_enabled.store(on, Ordering::SeqCst);
    }

    /// Move relay to `want`. `Some(backfill)` when the stored bit changed.
    /// `None` when it did not, including a purge fault that leaves relay off.
    /// The preload bit is taken only on a real off-to-on edge.
    pub fn apply_relay_edge(&self, want: bool) -> Option<bool> {
        let before = self.relay_enabled();
        self.set_relay_enabled(want);
        if self.relay_enabled() == before {
            return None;
        }
        Some(want && self.take_fee_backfill_due())
    }

    pub fn relay_enabled(&self) -> bool {
        self.relay_enabled.load(Ordering::SeqCst)
    }

    /// The pool is purged and later blocks strip it. Peer relay may still be off.
    pub fn pool_maintained(&self) -> bool {
        self.pool_maintained.load(Ordering::Acquire)
    }

    /// One-shot: purge txs the chain already confirmed and mark the template
    /// tip, then publish maintenance. Later connects strip per block. Does
    /// not enable peer relay or fee-history preload. A second call does nothing.
    ///
    /// Returns false when the purge hits a store fault. The flag stays clear
    /// so the next successful call retries. The leaving tip's fee sample and
    /// the flag are stored before `template_prev` is released, so a connect
    /// waiting on that lock strips instead of skipping the block. Callers
    /// that hold [`TemplateHold`] must drop it first.
    pub fn begin_pool_maintenance(&self) -> bool {
        if self.pool_maintained.load(Ordering::Acquire) {
            return true;
        }
        // Same lock `connect_at` holds from before the query tip moves until
        // the strip is recorded. Take it before the purge so the two never
        // invert lock order with the mempool write lock. Listing and
        // `generate` do not take this lock, so the flag has to wait until
        // the purge has finished.
        let mut slot = self.template_prev.lock().unwrap();
        if self.pool_maintained.load(Ordering::Acquire) {
            return true;
        }
        let n = match self.purge_confirmed() {
            Ok(n) => n,
            Err(()) => return false,
        };
        if n > 0 {
            rbitcoin_log::info!(
                "mempool: purged {n} leftover tx(s) at tip-mode entry (deferred during IBD)"
            );
        }
        let (marked, tip_height) = if let Some(h) = self.query.tip_height() {
            let marked = if let Ok(Some((_, rec))) = self.query.header_at_height(h) {
                let changed = *slot != Some(rec.hash);
                *slot = Some(rec.hash);
                changed
            } else {
                false
            };
            (marked, Some(h))
        } else {
            (false, None)
        };
        // Publish before the unlock. `connect_at` reads the flag only after
        // it takes this mutex. Fee-history insert drops every newer height,
        // so this sample has to land before the next connect records one.
        if marked {
            self.note_template_update();
        }
        if let Some(h) = tip_height {
            self.note_block_fee_history(h);
        }
        self.pool_maintained.store(true, Ordering::Release);
        #[cfg(debug_assertions)]
        self.fire_maint_publish_hook();
        drop(slot);
        true
    }

    /// Observe maintenance publish. The hook runs on this thread.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn set_maint_publish_hook(hook: fn(&MempoolHub)) {
        MAINT_PUBLISH_HOOK.with(|slot| slot.set(Some(hook)));
    }

    #[cfg(debug_assertions)]
    fn fire_maint_publish_hook(&self) {
        let hook = MAINT_PUBLISH_HOOK.with(|slot| slot.take());
        if let Some(hook) = hook {
            assert!(
                self.template_prev.try_lock().is_err(),
                "maintenance published after the template lock was released"
            );
            hook(self);
        }
    }

    /// One-shot: relay just turned on and fee history has not been preloaded.
    pub fn take_fee_backfill_due(&self) -> bool {
        self.fee_backfill_due.swap(false, Ordering::AcqRel)
    }

    pub fn set_immediate_relay(&self, on: bool) {
        self.immediate_relay.store(on, Ordering::Relaxed);
    }

    pub fn immediate_relay(&self) -> bool {
        self.immediate_relay.load(Ordering::Relaxed)
    }

    pub fn note_mock_now(&self, ts: u64) {
        self.mock_now.store(ts, Ordering::Relaxed);
        let _ = self.inv_flush.send(());
    }

    pub fn set_expiry_hours(&self, hours: u64) {
        let secs = hours.saturating_mul(3600).max(1);
        self.expiry_secs.store(secs, Ordering::Relaxed);
    }

    pub fn expiry_hours(&self) -> u64 {
        self.expiry_secs.load(Ordering::Relaxed) / 3600
    }

    /// Entry time for `getmempoolentry.time` (mock/wall seconds at accept).
    pub fn accept_time_txid(&self, txid: &Txid) -> Option<u64> {
        let w = self.wtxid_by_txid.lock().unwrap().get(txid).copied()?;
        self.accept_at.lock().unwrap().get(&w).copied()
    }

    /// Drop live txs (and in-mempool descendants) older than `-mempoolexpiry`.
    /// Called when a new tx is admitted so expiry is checked on the accept path.
    pub fn expire_stale(&self) -> usize {
        self.expire_stale_inner(true)
    }

    /// Same scan as [`Self::expire_stale`]. A busy accept-time index skips
    /// this tick instead of waiting.
    pub fn try_expire_stale(&self) -> usize {
        self.expire_stale_inner(false)
    }

    #[doc(hidden)]
    pub fn expire_stale_inner(&self, block: bool) -> usize {
        let now = self.relay_now_secs();
        let lim = self.expiry_secs.load(Ordering::Relaxed);
        if lim == 0 || now == 0 {
            return 0;
        }
        let min_at = self.min_live_accept_at.load(Ordering::Relaxed);
        if min_at == u64::MAX || now.saturating_sub(min_at) < lim {
            return 0;
        }
        let expired_roots = {
            let order = if block {
                self.expiry_order.lock().unwrap()
            } else {
                let Ok(order) = self.expiry_order.try_lock() else {
                    return 0;
                };
                order
            };
            self.meter_expire_full_scans.fetch_add(1, Ordering::Relaxed);
            expired_roots_in(&order, now, lim)
        };
        self.remove_expired_roots(&expired_roots)
    }

    #[doc(hidden)]
    pub fn remove_expired_roots(&self, roots: &[Txid]) -> usize {
        if roots.is_empty() {
            return 0;
        }
        let mut kill = BTreeSet::new();
        {
            let g = self.lock_read();
            for t in roots {
                if let Some(set) = g.graph.descendant_set(t) {
                    kill.extend(set);
                } else {
                    kill.insert(*t);
                }
            }
        }
        let n = {
            let mut n = 0usize;
            let mut g = self.lock_write();
            let mut present = Vec::new();
            for t in kill.iter().rev() {
                if g.graph.get(t).is_some() {
                    present.push(*t);
                } else {
                    // Already gone from the graph (fee or slot eviction that
                    // did not unindex). Drop the relay maps so the scan can
                    // move past it.
                    self.unindex_txid(t);
                    n += 1;
                }
            }
            let _ = g.remove_live_txids(&present);
            for t in &present {
                if !g.graph.contains(t) {
                    self.unindex_txid(t);
                    n += 1;
                }
            }
            if n > 0 {
                self.note_template_update();
            }
            n
        };
        if n > 0 {
            self.publish_fee_floor();
        }
        n
    }

    /// Headers poll runs on `tokio-rt-worker`. Expiry takes mempool locks, so
    /// it has to enter a [`crate::reactor::BlockingRegion`] on the blocking pool.
    /// A busy index skips the tick.
    pub fn expire_stale_from_session(self: &Arc<Self>) {
        let hub = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            hub.try_expire_stale()
        });
    }

    pub fn subscribe_inv_flush(&self) -> broadcast::Receiver<()> {
        self.inv_flush.subscribe()
    }

    /// Wake session loops so they INV due / unbroadcast txs now.
    pub fn notify_inv_flush(&self) {
        let _ = self.inv_flush.send(());
    }

    pub fn accept_time(&self, wtxid: &Wtxid) -> Option<u64> {
        self.accept_at.lock().unwrap().get(wtxid).copied()
    }

    pub fn tx_inv_due(&self, wtxid: &Wtxid) -> bool {
        let now = self.relay_now_secs();
        self.accept_at
            .lock()
            .unwrap()
            .get(wtxid)
            .is_some_and(|at| now.saturating_sub(*at) >= 30)
    }

    /// Any live wtxid has passed the 30s INV age gate (mocktime when set,
    /// otherwise wall clock). Does not clone bodies.
    pub fn any_tx_inv_due(&self) -> bool {
        let min_at = self.min_live_accept_at.load(Ordering::Relaxed);
        if min_at == u64::MAX {
            return false;
        }
        let now = self.relay_now_secs();
        now.saturating_sub(min_at) >= 30
    }

    /// Live txid + wtxid from the graph (no body clone).
    pub fn list_live_wtxids(&self) -> Vec<(Txid, Wtxid)> {
        self.meter_list_live_wtxids.fetch_add(1, Ordering::Relaxed);
        let g = self.lock_read();
        g.graph.iter().map(|(txid, e)| (*txid, e.wtxid)).collect()
    }

    /// Session INV tick: never parks. Busy write → skip this tick.
    pub fn try_list_live_wtxids(&self) -> Option<Vec<(Txid, Wtxid)>> {
        self.meter_list_live_wtxids.fetch_add(1, Ordering::Relaxed);
        let g = self.inner.try_read().ok()?;
        Some(g.graph.iter().map(|(txid, e)| (*txid, e.wtxid)).collect())
    }

    #[allow(clippy::type_complexity)] // age-inv cursor `(due, gen)` plus the due txid/wtxid list
    /// Newly age-due INVs after `seen` (`(due_secs, accept_gen)` cursor).
    /// Session tick: `try_lock` — busy skip.
    pub fn try_age_inv_since(
        &self,
        seen: (u64, u64),
        now: u64,
    ) -> Option<((u64, u64), Vec<(Txid, Wtxid)>)> {
        let log = self.age_inv.try_lock().ok()?;
        let mut last = seen;
        let mut out = Vec::new();
        for (&(due, gen), &(txid, wtxid)) in
            log.range((Bound::Excluded(seen), Bound::Included((now, u64::MAX))))
        {
            out.push((txid, wtxid));
            last = (due, gen);
        }
        Some((last, out))
    }

    /// Last due-log key with `due <= now` (advance cursor after a rare full walk).
    pub fn try_age_inv_watermark(&self, now: u64) -> Option<(u64, u64)> {
        let log = self.age_inv.try_lock().ok()?;
        log.range(..=(now, u64::MAX)).next_back().map(|(k, _)| *k)
    }

    /// Drop live mempool entries that are confirmed-strong on tip, then live
    /// txs whose inputs are confirmed-spent by a different txid.
    ///
    /// Used once when enabling relay after catch-up. Same-txid hits keep
    /// in-mempool descendants; conflicts drop the loser tree. Persists DEAD
    /// marks even when compact does not fire. Returns how many txs removed.
    /// A store fault is 0 here; [`Self::begin_pool_maintenance`] uses the
    /// fallible path and does not publish maintenance when that happens.
    pub fn purge_confirmed_on_chain(&self) -> usize {
        self.purge_confirmed().unwrap_or(0)
    }

    #[allow(clippy::result_unit_err)] // a store fault is (); maintenance stays unpublished
    fn purge_confirmed(&self) -> Result<usize, ()> {
        let live: Vec<Txid> = {
            let g = self.lock_read();
            g.graph.iter().map(|(t, _)| *t).collect()
        };
        if live.is_empty() {
            return Ok(0);
        }
        let to_drop = self.live_confirmed_strong(&live)?;
        let mut g = self.lock_write();
        let drop_set: HashSet<Txid> = to_drop
            .iter()
            .copied()
            .filter(|tid| g.graph.contains(tid))
            .collect();
        let remain: Vec<Txid> = g
            .graph
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !drop_set.contains(t))
            .collect();
        let spent_ops = self.spent_chain_prevouts(&g, &remain, &drop_set)?;
        let confirmed: Vec<Txid> = drop_set.into_iter().collect();
        // A store fault still unlinks conflicts before it returns, and that
        // error drops the conflict list. Snapshot the graph and unindex the
        // diff, then fail so maintenance stays unpublished.
        let before: HashSet<Txid> = g.graph.iter().map(|(t, _)| *t).collect();
        let removed = g.remove_block_txids(&confirmed, &spent_ops);
        let gone: Vec<Txid> = before
            .into_iter()
            .filter(|t| !g.graph.contains(t))
            .collect();
        if !gone.is_empty() {
            let _ = g.maybe_compact();
            let _ = g.persist_if_dirty();
            self.mark_fee_dirty();
        }
        drop(g);
        if !gone.is_empty() {
            self.unindex_evicted(&gone);
        }
        removed.map(|_| gone.len()).map_err(|_| ())
    }

    #[doc(hidden)]
    #[allow(clippy::result_unit_err)] // a store fault is (); confirm-drop keeps the pool
    pub fn live_confirmed_strong(&self, live: &[Txid]) -> Result<Vec<Txid>, ()> {
        let tid_bytes: Vec<[u8; 32]> = live.iter().map(|t| t.to_byte_array()).collect();
        let hits = self
            .query
            .store()
            .get_fk_by_txid_batch(&tid_bytes)
            .map_err(|_| ())?;
        let mut to_drop = Vec::new();
        for (tid_b, row) in hits {
            let Some((fk, _)) = row else { continue };
            if self.query.store().is_confirmed_strong(fk).map_err(|_| ())? {
                to_drop.push(Txid::from_byte_array(tid_b));
            }
        }
        Ok(to_drop)
    }

    #[doc(hidden)]
    #[allow(clippy::result_unit_err)] // a store fault is (); confirm-drop keeps the pool
    pub fn spent_chain_prevouts(
        &self,
        g: &ActiveMempool,
        remain: &[Txid],
        confirmed_resident: &HashSet<Txid>,
    ) -> Result<Vec<OutPoint>, ()> {
        let op_fk = self.chain_create_fks(g, remain, confirmed_resident)?;
        if op_fk.is_empty() {
            return Ok(Vec::new());
        }
        let mut fk_vouts: HashMap<Fk, Vec<u32>> = HashMap::new();
        for (op, fk) in &op_fk {
            fk_vouts.entry(*fk).or_default().push(op.vout);
        }
        let items: Vec<(Fk, Vec<u32>)> = fk_vouts
            .into_iter()
            .map(|(fk, mut v)| {
                v.sort_unstable();
                v.dedup();
                (fk, v)
            })
            .collect();
        let unspent = self
            .query
            .unspent_create_vouts_batch(&items)
            .map_err(|_| ())?;
        let mut spent_pair: HashSet<(u64, u32)> = HashSet::new();
        for ((fk, vouts), keep) in items.iter().zip(unspent.iter()) {
            let keep_set: HashSet<u32> = keep.iter().copied().collect();
            for &vout in vouts {
                if !keep_set.contains(&vout) {
                    spent_pair.insert((fk.0, vout));
                }
            }
        }
        Ok(op_fk
            .into_iter()
            .filter(|(op, fk)| spent_pair.contains(&(fk.0, op.vout)))
            .map(|(op, _)| op)
            .collect())
    }

    #[doc(hidden)]
    #[allow(clippy::result_unit_err)] // a store fault is (); confirm-drop keeps the pool
    pub fn chain_create_fks(
        &self,
        g: &ActiveMempool,
        remain: &[Txid],
        confirmed_resident: &HashSet<Txid>,
    ) -> Result<HashMap<OutPoint, Fk>, ()> {
        let mut op_fk: HashMap<OutPoint, Fk> = HashMap::new();
        let mut need_id: Vec<[u8; 32]> = Vec::new();
        for tid in remain {
            let Some(tx) = g.get_tx(tid) else { continue };
            let aux = g.vin_aux(tid);
            for (i, inp) in tx.input.iter().enumerate() {
                let op = inp.previous_output;
                // Still-unconfirmed parents are mempool dependencies, not chain
                // outputs. A parent this call already knows is confirmed is on
                // chain even while it sits in the pool, so its output may be spent.
                if g.graph.contains(&op.txid) && !confirmed_resident.contains(&op.txid) {
                    continue;
                }
                if let Some(fk) = aux.get(i).and_then(|a| a.create_fk) {
                    op_fk.insert(op, fk);
                } else {
                    need_id.push(op.txid.to_byte_array());
                }
            }
        }
        if need_id.is_empty() {
            return Ok(op_fk);
        }
        need_id.sort_unstable();
        need_id.dedup();
        let rows = self
            .query
            .store()
            .get_fk_by_txid_batch(&need_id)
            .map_err(|_| ())?;
        let mut fk_of: HashMap<[u8; 32], Fk> = HashMap::new();
        for (tid, row) in rows {
            if let Some((fk, _)) = row {
                fk_of.insert(tid, fk);
            }
        }
        for tid in remain {
            let Some(tx) = g.get_tx(tid) else { continue };
            for inp in &tx.input {
                let op = inp.previous_output;
                if op_fk.contains_key(&op)
                    || (g.graph.contains(&op.txid) && !confirmed_resident.contains(&op.txid))
                {
                    continue;
                }
                if let Some(&fk) = fk_of.get(&op.txid.to_byte_array()) {
                    op_fk.insert(op, fk);
                }
            }
        }
        Ok(op_fk)
    }

    pub fn subscribe_announces(&self) -> broadcast::Receiver<MempoolAnnounce> {
        self.announce.subscribe()
    }

    #[doc(hidden)]
    pub fn publish_announce(&self, r: &AcceptResult, scripthashes: Vec<[u8; 32]>) {
        let _ = self.announce.send(MempoolAnnounce {
            txid: r.txid,
            replaced: r.replaced.clone(),
            replaced_scripthashes: r.replaced_scripthashes.clone(),
            scripthashes,
        });
        self.meter_announce.fetch_add(1, Ordering::Relaxed);
    }

    pub fn live_count(&self) -> usize {
        self.lock_read().live_count()
    }

    /// Tip confirm: connect-only pres for live graph txs, full midstates otherwise.
    pub fn tip_script_pres(
        &self,
        txs: &[Transaction],
    ) -> (
        std::sync::Arc<[rbitcoin_query::TxPrecompute]>,
        HashSet<[u8; 32]>,
    ) {
        if self.lock_read().live_count() == 0 {
            return rbitcoin_query::pres_for_tip(txs, true, |_| false);
        }
        let connects: Vec<_> = txs
            .iter()
            .map(|tx| rbitcoin_query::TxPrecompute::from_tx_connect(tx).into_connect())
            .collect();
        let skip = {
            let g = self.lock_read();
            connects
                .iter()
                .filter(|p| {
                    let id = Txid::from_byte_array(p.txid);
                    g.graph.get(&id).is_some_and(|e| {
                        e.wtxid.to_byte_array() == p.wtxid && !g.trust_kept.contains(&id)
                    })
                })
                .map(|p| p.txid)
                .collect::<HashSet<_>>()
        };
        let v: Vec<_> = txs
            .iter()
            .zip(connects)
            .map(|(tx, c)| {
                if skip.contains(&c.txid) {
                    rbitcoin_query::TxPrecompute::Connect(c)
                } else {
                    rbitcoin_query::TxPrecompute::Script(
                        rbitcoin_query::TxScriptPrecompute::from_connect(c, tx),
                    )
                }
            })
            .collect();
        (std::sync::Arc::from(v), skip)
    }

    pub fn generation(&self) -> u64 {
        self.lock_read().generation()
    }

    pub fn flush(&self) -> Result<(), String> {
        self.lock_write()
            .flush()
            .map_err(|e| format!("mempool flush: {e}"))
    }

    /// Time-based sidecar persist (5 s, no fsync). No-op when clean or too soon.
    pub fn persist_due(&self) -> Result<(), String> {
        self.lock_write()
            .persist_due()
            .map_err(|e| format!("mempool persist: {e}"))
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.lock_read().graph.contains(txid)
    }

    /// Session INV filter: never parks. Busy write → `false` (may re-getdata).
    /// Live graph, orphanage, recent-confirmed ring, or Class A at tip (Core AlreadyHave).
    pub fn try_contains(&self, txid: &Txid) -> bool {
        if self
            .inner
            .try_read()
            .ok()
            .is_some_and(|g| g.graph.contains(txid) || g.orphanage.contains(txid))
        {
            return true;
        }
        if self
            .recent_confirmed
            .try_lock()
            .ok()
            .is_some_and(|r| r.contains_txid(txid))
        {
            return true;
        }
        self.query
            .tx_fk_by_txid_tip(&txid.to_byte_array())
            .ok()
            .flatten()
            .is_some()
    }

    pub fn get_tx(&self, txid: &Txid) -> Option<Transaction> {
        self.lock_read().get_tx(txid).cloned()
    }

    /// The isolated loop's read. A held write is one lagged lap, then this
    /// waits. A successful `try_read` keeps that guard: dropping it and
    /// calling [`Self::get_tx`] lets a writer arrive in the gap and block
    /// the wait with no lap.
    #[doc(hidden)]
    pub fn read_tx_for_isolated(&self, txid: &Txid) -> Option<Transaction> {
        let guard = match self.inner.try_read() {
            Ok(guard) => guard,
            Err(_) => {
                self.note_isolated_lap(IsolatedLap::Lagged);
                self.lock_read()
            }
        };
        guard.get_tx(txid).cloned()
    }

    /// Session getdata: never parks. Busy write → `None` (notfound this round).
    pub fn try_get_tx(&self, txid: &Txid) -> Option<Transaction> {
        self.inner
            .try_read()
            .ok()
            .and_then(|g| g.get_tx(txid).cloned())
    }

    /// Look up a live mempool tx by wtxid (BIP339 / compact v2).
    pub fn get_tx_by_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        let g = self.lock_read();
        let txid = g.graph.txid_for_wtxid(wtxid)?;
        g.get_tx(&txid).cloned()
    }

    pub fn try_get_tx_by_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        let g = self.inner.try_read().ok()?;
        let txid = g.graph.txid_for_wtxid(wtxid)?;
        g.get_tx(&txid).cloned()
    }

    /// True if a live mempool entry has this wtxid (BIP339 inv filter).
    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.lock_read().graph.contains_wtxid(wtxid)
    }

    pub fn try_contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        if self
            .inner
            .try_read()
            .ok()
            .is_some_and(|g| g.graph.contains_wtxid(wtxid) || g.orphanage.contains_wtxid(wtxid))
        {
            return true;
        }
        self.recent_confirmed
            .try_lock()
            .ok()
            .is_some_and(|r| r.contains_wtxid(wtxid))
    }

    /// Remember confirmed bodies for INV AlreadyHave (txid + wtxid).
    pub fn note_recent_confirmed(&self, txs: &[Transaction]) {
        self.clear_recent_rejects();
        if let Ok(mut r) = self.recent_confirmed.lock() {
            r.note_block(txs);
        }
    }

    pub fn clear_recent_rejects(&self) {
        if let Ok(mut g) = self.recent_rejects.lock() {
            g.clear();
        }
    }

    pub fn clear_recent_confirmed(&self) {
        if let Ok(mut r) = self.recent_confirmed.lock() {
            r.clear();
        }
    }

    #[doc(hidden)]
    pub fn note_recent_reject(&self, wtxid: Wtxid) {
        let Ok(mut g) = self.recent_rejects.lock() else {
            return;
        };
        if g.len() >= 4_096 {
            return;
        }
        g.insert(wtxid);
    }

    /// Session TX filter: never parks. Busy lock → `false` (re-ATMP).
    pub fn try_recent_reject(&self, wtxid: &Wtxid) -> bool {
        self.recent_rejects
            .try_lock()
            .ok()
            .is_some_and(|g| g.contains(wtxid))
    }

    /// Confirmed tip snapshot for mempool structural checks (height + BIP113 MTP).
    #[doc(hidden)]
    pub fn chain_tip_ctx(&self) -> ChainTipCtx {
        use rbitcoin_query::median_time_past;
        let height = self.query.tip_height().map(|h| h.0).unwrap_or(0);
        let fk = self.query.tip_header_fk().ok().flatten();
        if let Some(fk) = fk {
            if let Ok(c) = self.tip_ctx.lock() {
                if let Some((cached_fk, ctx)) = *c {
                    if cached_fk == fk && ctx.height == height {
                        return ctx;
                    }
                }
            }
        }
        let mtp = if height == 0 {
            0
        } else {
            self.meter_tip_mtp.fetch_add(1, Ordering::Relaxed);
            median_time_past(self.query.as_ref(), Height(height)).unwrap_or(0)
        };
        let ctx = ChainTipCtx { height, mtp };
        if let Some(fk) = fk {
            if let Ok(mut c) = self.tip_ctx.lock() {
                *c = Some((fk, ctx));
            }
        }
        ctx
    }

    /// Accept a peer (or local) transaction when relay is enabled.
    ///
    /// **Staged:** exclusive lock for prepare + commit only. Consensus script
    /// verify runs on the shared `rbtc-scripts` path **outside** the mempool
    /// mutex so concurrent readers are not blocked by interpreter CPU.
    /// Remember the live session that is the trusted peer. `None` clears it.
    pub fn set_trusted_session(&self, id: Option<u64>) {
        self.trusted_session
            .store(id.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn tx_from_trusted(&self, from: Option<u64>) -> bool {
        let Some(id) = from else {
            return false;
        };
        id != u64::MAX && id == self.trusted_session.load(Ordering::Relaxed)
    }

    pub fn accept_tx(&self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        self.accept_tx_from(tx, TxOrigin::Relay(None))
    }

    /// Accept from `origin`. A relayed tx that parks records its peer as an
    /// orphan announcer.
    pub fn accept_tx_from(
        &self,
        tx: &Transaction,
        origin: TxOrigin,
    ) -> Result<AcceptResult, AcceptError> {
        crate::reactor::assert_not_reactor("mempool accept");
        let result = self.accept_with_utxo(tx, &self.utxo_provider(), origin, false, &[]);
        if let (TxOrigin::Local, Ok(r)) = (origin, &result) {
            self.kick_isolated_if_live(&[r.txid]);
        }
        result
    }

    /// Admit one `submitpackage` member, local origin, without trimming and
    /// without parking.
    ///
    /// The package trims once at the end. A missing-input child stays a
    /// reconsiderable error so the parent can be retried with it.
    #[doc(hidden)]
    pub fn accept_tx_defer_trim(&self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        self.accept_with_utxo(tx, &self.utxo_provider(), TxOrigin::Local, true, &[])
    }

    /// Hand each local tx still in the pool to the isolated broadcast loop.
    ///
    /// Runs once per submit, after its last trim: a member that trim drops
    /// was already published, and must not reach the wire.
    fn kick_isolated_if_live(&self, txids: &[Txid]) {
        for txid in txids {
            if self.contains(txid) {
                self.kick_isolated(txid);
            }
        }
    }

    /// Runs under the write lock that commits `result`.
    fn note_origin(&self, origin: TxOrigin, result: &Result<AcceptResult, AcceptError>) {
        if let (TxOrigin::Local, Ok(r)) = (origin, result) {
            self.local_origin.lock().unwrap().mark(r.txid);
        }
    }

    /// Prepare under read lock; scripts off-lock. Parking is the caller's job.
    #[doc(hidden)]
    pub fn admit_staged(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
        spec: AdmitSpec,
        stages: &mut rbitcoin_mempool::AcceptStageUs,
        lock_us: &mut u64,
    ) -> Result<rbitcoin_mempool::PreparedAdmit, AcceptError> {
        let tip = self.chain_tip_ctx();
        let t_prep = Instant::now();
        let prep = {
            let g = self.lock_read();
            g.prepare_admit(
                tx,
                utxo,
                tip,
                PrepareOpts {
                    fee_delta: spec.fee_delta,
                    report_orphans: spec.report_orphans,
                    min_relay: spec.min_relay,
                    waive: spec.waive,
                },
            )
        };
        if spec.time_prepare_lock {
            *lock_us = lock_us.saturating_add(t_prep.elapsed().as_micros() as u64);
        }
        let mut prep = match prep {
            Ok(p) => {
                stages.utxo_us = stages.utxo_us.saturating_add(p.utxo_us);
                p
            }
            Err(e) => return Err(e),
        };
        let t_script = Instant::now();
        if let Err(e) =
            rbitcoin_consensus::verify_tx_scripts_detached(prep.prevouts.clone(), tx.clone())
        {
            stages.script_us = stages
                .script_us
                .saturating_add(t_script.elapsed().as_micros() as u64);
            let err = AcceptError::Script(e.to_string());
            let reason = err.mempool_reject_reason();
            if spec.waive && rbitcoin_consensus::reason_is_warn_and_apply(&reason) {
                prep.trust_warn.get_or_insert_with(Vec::new).push(reason);
            } else {
                return Err(err);
            }
        }
        stages.script_us = stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        Ok(prep)
    }

    /// Confirmed coins are read again before commit. A spend that lands while
    /// scripts run must not commit from the prepare snapshot. An input whose
    /// creator is still in the graph keeps its mempool parent (`chain_coins`
    /// stays `None`). The read stays off the write lock when the UTXO view
    /// stamp and the creator set are unchanged.
    #[doc(hidden)]
    pub fn sample_chain_coins(&self, tx: &Transaction, utxo: &impl UtxoProvider) -> SampledCoins {
        let Some(stamp) = utxo.utxo_view_stamp() else {
            return SampledCoins {
                stamp: None,
                creators: Vec::new(),
                coins: Vec::new(),
            };
        };
        let creators: Vec<bool> = {
            let g = self.lock_read();
            tx.input
                .iter()
                .map(|inp| g.graph.creator(&inp.previous_output).is_some())
                .collect()
        };
        let coins = tx
            .input
            .iter()
            .zip(&creators)
            .map(|(inp, had_creator)| {
                if *had_creator {
                    None
                } else {
                    utxo.get_coin(&inp.previous_output)
                }
            })
            .collect();
        SampledCoins {
            stamp: Some(stamp),
            creators,
            coins,
        }
    }

    #[doc(hidden)]
    pub fn sampled_coins_fresh(
        g: &ActiveMempool,
        tx: &Transaction,
        utxo: &impl UtxoProvider,
        sample: &SampledCoins,
    ) -> bool {
        let Some(stamp) = sample.stamp else {
            return false;
        };
        if utxo.utxo_view_stamp() != Some(stamp) {
            return false;
        }
        tx.input
            .iter()
            .zip(&sample.creators)
            .all(|(inp, had)| g.graph.creator(&inp.previous_output).is_some() == *had)
    }

    #[doc(hidden)]
    pub fn apply_sampled_coins(
        tx: &Transaction,
        prep: &mut rbitcoin_mempool::PreparedAdmit,
        sample: &SampledCoins,
    ) -> Result<(), AcceptError> {
        for (i, inp) in tx.input.iter().enumerate() {
            if sample.creators.get(i).copied().unwrap_or(false) {
                continue;
            }
            let op = inp.previous_output;
            let Some(coin) = sample.coins.get(i).and_then(|c| c.clone()) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            let Some(prev) = prep.prevouts.get_mut(i) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            let Some(slot) = prep.chain_coins.get_mut(i) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            *prev = coin.txout.clone();
            *slot = Some(coin);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn recheck_chain_coins(
        g: &ActiveMempool,
        tx: &Transaction,
        prep: &mut rbitcoin_mempool::PreparedAdmit,
        utxo: &impl UtxoProvider,
    ) -> Result<(), AcceptError> {
        for (i, inp) in tx.input.iter().enumerate() {
            let op = inp.previous_output;
            if g.graph.creator(&op).is_some() {
                continue;
            }
            let Some(coin) = utxo.get_coin(&op) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            let Some(prev) = prep.prevouts.get_mut(i) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            let Some(slot) = prep.chain_coins.get_mut(i) else {
                return Err(AcceptError::MissingPrevout(op));
            };
            *prev = coin.txout.clone();
            *slot = Some(coin);
        }
        Ok(())
    }

    /// Recheck, then commit. A miss does not take the previous admit's
    /// eviction list: that admit already published it.
    #[doc(hidden)]
    pub fn commit_rechecked(
        g: &mut ActiveMempool,
        tx: &Transaction,
        mut prep: rbitcoin_mempool::PreparedAdmit,
        utxo: &impl UtxoProvider,
        defer_trim: bool,
        sample: &SampledCoins,
    ) -> CommitOutcome {
        let rechecked = if Self::sampled_coins_fresh(g, tx, utxo, sample) {
            Self::apply_sampled_coins(tx, &mut prep, sample)
        } else {
            Self::recheck_chain_coins(g, tx, &mut prep, utxo)
        };
        if let Err(e) = rechecked {
            return CommitOutcome {
                result: Err(e),
                failed_evict: Vec::new(),
                undone: Vec::new(),
                prevouts: Vec::new(),
            };
        }
        let prevouts = prep.prevouts.clone();
        let result = if defer_trim {
            g.commit_after_script_defer_trim(tx, prep)
        } else {
            g.commit_after_script(tx, prep)
        };
        let (failed_evict, undone) = if result.is_err() {
            (g.take_failed_evictions(), g.take_undone_replacements())
        } else {
            (Vec::new(), Vec::new())
        };
        CommitOutcome {
            result,
            failed_evict,
            undone,
            prevouts,
        }
    }

    #[doc(hidden)]
    pub fn accept_with_utxo(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
        origin: TxOrigin,
        defer_trim: bool,
        announcers: &[u64],
    ) -> Result<AcceptResult, AcceptError> {
        utxo.note_spender(tx);
        let from = origin.peer();
        let t0 = Instant::now();

        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let delta = self.fee_delta(&tx.compute_txid());
        let waive = self.tx_from_trusted(from);
        let spec = AdmitSpec {
            report_orphans: true,
            fee_delta: delta,
            time_prepare_lock: false,
            min_relay: None,
            waive,
        };
        let prep = match self.admit_staged(tx, utxo, spec, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(e) => {
                if defer_trim && matches!(e, AcceptError::Orphaned { .. }) {
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return self.finish_accept_err(us, e);
                }
                if let AcceptError::Orphaned { missing, .. } = &e {
                    if missing
                        .iter()
                        .any(|p| self.try_recent_reject(&Wtxid::from_byte_array(p.to_byte_array())))
                    {
                        self.note_recent_reject(tx.compute_wtxid());
                        self.note_recent_reject(Wtxid::from_byte_array(
                            tx.compute_txid().to_byte_array(),
                        ));
                        let us = t0.elapsed().as_micros() as u64;
                        self.meter_accept_stages(lock_us, stages);
                        return self.finish_accept_err(
                            us,
                            AcceptError::Orphaned {
                                txid: tx.compute_txid(),
                                missing: BTreeSet::new(),
                                fresh: false,
                            },
                        );
                    }
                    if from.is_none() {
                        if let Some(r) = self.admit_1p1c(tx, utxo, missing, origin) {
                            let us = t0.elapsed().as_micros() as u64;
                            self.meter_accept_wall(us, true);
                            return Ok(r);
                        }
                    }
                    let parked = {
                        let mut g = self.lock_write();
                        if announcers.is_empty() {
                            g.park_orphan_from(tx, missing.clone(), from)
                        } else {
                            g.park_announced(tx, missing.clone(), announcers)
                        }
                    };
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return self.finish_accept_err(us, parked);
                }
                self.note_if_accept_failure(tx, &e);
                let us = t0.elapsed().as_micros() as u64;
                self.meter_accept_stages(lock_us, stages);
                return self.finish_accept_err(us, e);
            }
        };

        let sample = self.sample_chain_coins(tx, utxo);
        let committed = {
            let t_lock = Instant::now();
            let mut g = self.lock_write();
            g.last_accept_stages = stages;
            let committed = Self::commit_rechecked(&mut g, tx, prep, utxo, defer_trim, &sample);
            self.note_origin(origin, &committed.result);
            stages = g.last_accept_stages;
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            committed
        };
        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        match committed.result {
            Ok(r) => {
                self.meter_accept_wall(us, true);
                self.publish_admitted(tx, &r, &committed.prevouts, utxo);
                let _ = self.expire_stale();
                self.publish_fee_floor();
                Ok(r)
            }
            Err(e) => {
                // Eviction inside the commit may have raised the rolling floor
                // before the error returned. The write guard is already gone.
                self.unindex_evicted(&committed.failed_evict);
                self.restore_replaced(&committed.undone);
                self.publish_fee_floor();
                self.finish_accept_err(us, e)
            }
        }
    }

    #[doc(hidden)]
    pub fn admit_1p1c(
        &self,
        child: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
        missing: &std::collections::BTreeSet<Txid>,
        origin: TxOrigin,
    ) -> Option<AcceptResult> {
        let parent = {
            let g = self.lock_read();
            g.try_one_parent_package(child, missing, utxo)?
        };
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let spec_p = AdmitSpec {
            report_orphans: false,
            fee_delta: self.fee_delta(&parent.compute_txid()),
            time_prepare_lock: false,
            min_relay: Some(0),
            waive: false,
        };
        let prep_p = match self.admit_staged(&parent, utxo, spec_p, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(e) => {
                self.note_if_accept_failure(&parent, &e);
                return None;
            }
        };
        // Parent is live until the child commits (or we roll it back). A
        // concurrent spender of the parent that lands in this window survives
        // `remove_txid(parent)` if the child then fails.
        let sample_p = self.sample_chain_coins(&parent, utxo);
        let parent_commit = {
            let mut g = self.lock_write();
            Self::commit_rechecked(&mut g, &parent, prep_p, utxo, true, &sample_p)
        };
        let (parent_res, prevouts_p) = match parent_commit.result {
            Ok(r) => (r, parent_commit.prevouts),
            Err(_) => {
                self.unindex_evicted(&parent_commit.failed_evict);
                self.restore_replaced(&parent_commit.undone);
                self.publish_fee_floor();
                return None;
            }
        };
        let spec_c = AdmitSpec {
            report_orphans: false,
            fee_delta: self.fee_delta(&child.compute_txid()),
            time_prepare_lock: false,
            min_relay: None,
            waive: false,
        };
        let prep_c = match self.admit_staged(child, utxo, spec_c, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(_) => {
                self.meter_accept_stages(lock_us, stages);
                self.rollback_1p1c_parent(&parent_res.txid, &parent_res.evicted);
                return None;
            }
        };
        let sample_c = self.sample_chain_coins(child, utxo);
        let child_commit = {
            let mut g = self.lock_write();
            let committed = Self::commit_rechecked(&mut g, child, prep_c, utxo, true, &sample_c);
            self.note_origin(origin, &committed.result);
            committed
        };
        self.meter_accept_stages(lock_us, stages);
        match child_commit.result {
            Ok(r) => {
                self.trim_over_budget();
                if !self.try_contains(&parent_res.txid) || !self.try_contains(&r.txid) {
                    self.rollback_package_accepted(&[parent_res, r]);
                    self.publish_fee_floor();
                    return None;
                }
                self.publish_admitted(&parent, &parent_res, &prevouts_p, utxo);
                self.publish_admitted(child, &r, &child_commit.prevouts, utxo);
                let _ = self.expire_stale();
                self.publish_fee_floor();
                Some(r)
            }
            Err(_) => {
                self.unindex_evicted(&child_commit.failed_evict);
                self.restore_replaced(&child_commit.undone);
                self.rollback_1p1c_parent(&parent_res.txid, &parent_res.evicted);
                self.publish_fee_floor();
                None
            }
        }
    }

    #[doc(hidden)]
    pub fn rollback_1p1c_parent(&self, txid: &Txid, evicted: &[Txid]) {
        let mut gone = evicted.to_vec();
        {
            let mut g = self.lock_write();
            gone.extend(g.remove_txid_tree(txid));
        }
        self.unindex_evicted(&gone);
    }

    /// Roll the package back, then return members that were parked before it.
    ///
    /// A child whose parents are already in the mempool is admitted. One that
    /// still misses a parent is parked under those parents, with the peers
    /// who announced it.
    #[doc(hidden)]
    pub fn abandon_package(
        &self,
        accepted: &[AcceptResult],
        lifted: &[rbitcoin_mempool::LiftedOrphan],
    ) {
        if !accepted.is_empty() {
            self.rollback_package_accepted(accepted);
        }
        let utxo = self.utxo_provider();
        let tip = self.chain_tip_ctx();
        // Read the priority map before the mempool write lock. A child under
        // the raw relay floor is still admissible when its delta clears it.
        let deltas = self.prioritised_txs();
        let trusted = {
            let id = self.trusted_session.load(Ordering::Relaxed);
            (id != u64::MAX).then_some(id)
        };
        let ready = {
            let mut g = self.lock_write();
            g.repark_lifted(
                lifted,
                &utxo,
                tip,
                &|id| deltas.get(id).copied().unwrap_or(0),
                trusted,
            )
        };
        for item in ready {
            let id = item.tx.compute_txid();
            // Every announcer is restored under the accept lock. A disconnect
            // during the lift already edited the in-flight record.
            let from = item
                .announcers
                .iter()
                .copied()
                .find(|&peer| self.tx_from_trusted(Some(peer)))
                .or_else(|| item.announcers.first().copied());
            let _ = self.accept_with_utxo(
                &item.tx,
                &utxo,
                TxOrigin::Relay(from),
                false,
                &item.announcers,
            );
            self.forget_taken_orphan(id, item.taken_gen);
        }
    }

    #[doc(hidden)]
    pub fn rollback_package_accepted(&self, accepted: &[AcceptResult]) {
        let victims: Vec<Transaction> = accepted
            .iter()
            .flat_map(|r| r.replaced_txs.iter().cloned())
            .collect();
        let mut gone: Vec<Txid> = accepted
            .iter()
            .flat_map(|r| r.evicted.iter().copied())
            .collect();
        {
            let mut g = self.lock_write();
            for id in accepted.iter().flat_map(|r| r.replaced_trust.iter()) {
                g.trust_kept.insert(*id);
            }
            for r in accepted.iter().rev() {
                gone.extend(g.remove_txid_tree(&r.txid));
            }
        }
        self.unindex_evicted(&gone);
        self.restore_replaced(&victims);
    }

    /// Put conflicts removed by a failed replacement back. They were already
    /// admitted, so the fee floor is not applied again and a descendant is
    /// not parked ahead of its parent. A victim that still cannot re-enter
    /// leaves the relay maps.
    #[doc(hidden)]
    pub fn restore_replaced(&self, victims: &[Transaction]) {
        if victims.is_empty() {
            return;
        }
        let utxo = self.utxo_provider();
        for i in rbitcoin_mempool::ActiveMempool::ancestor_first_order(victims) {
            let tx = &victims[i];
            match self.reaccept_waived(tx, &utxo) {
                Ok((result, prevouts)) => {
                    if self.relay_indexed(&result.txid) {
                        self.unindex_evicted(&result.evicted);
                        for old in &result.replaced {
                            self.unindex_txid(old);
                        }
                    } else {
                        self.publish_admitted(tx, &result, &prevouts, &utxo);
                    }
                }
                Err(_) => {
                    self.unindex_if_absent(tx);
                    let id = tx.compute_txid();
                    let mut g = self.lock_write();
                    if !g.graph.contains(&id) {
                        g.trust_kept.remove(&id);
                    }
                }
            }
        }
    }

    /// Re-insert one already-admitted conflict without recording a reject.
    #[doc(hidden)]
    pub fn reaccept_waived(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) -> Result<(AcceptResult, Vec<TxOut>), AcceptError> {
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let txid = tx.compute_txid();
        let waive = self.lock_read().trust_kept.contains(&txid);
        let spec = AdmitSpec {
            report_orphans: false,
            fee_delta: self.fee_delta(&txid),
            time_prepare_lock: false,
            min_relay: Some(0),
            waive,
        };
        let mut prep = self.admit_staged(tx, utxo, spec, &mut stages, &mut lock_us)?;
        prep.keep_mark = waive;
        // Keep the time the hub already holds, so disk and RAM agree.
        prep.keep_accept_secs = self.accept_time_txid(&prep.txid);
        let sample = self.sample_chain_coins(tx, utxo);
        let committed = {
            let mut g = self.lock_write();
            Self::commit_rechecked(&mut g, tx, prep, utxo, false, &sample)
        };
        match committed.result {
            Ok(r) => Ok((r, committed.prevouts)),
            Err(e) => {
                self.unindex_evicted(&committed.failed_evict);
                self.restore_replaced(&committed.undone);
                self.publish_fee_floor();
                Err(e)
            }
        }
    }

    #[doc(hidden)]
    pub fn relay_indexed(&self, txid: &Txid) -> bool {
        self.wtxid_by_txid.lock().unwrap().contains_key(txid)
    }

    #[doc(hidden)]
    pub fn unindex_if_absent(&self, tx: &Transaction) {
        let txid = tx.compute_txid();
        let parked = self.lock_read().orphanage.contains(&txid);
        if !self.contains(&txid) && !parked {
            self.unindex_txid(&txid);
        }
    }

    /// Drop relay maps for txs already removed from the live graph.
    ///
    /// A `prioritisetransaction` delta stays until the tx is mined.
    #[doc(hidden)]
    pub fn unindex_evicted(&self, gone: &[Txid]) {
        if gone.is_empty() {
            return;
        }
        self.note_template_update();
        for tid in gone {
            self.unindex_txid(tid);
        }
        self.publish_fee_floor();
    }

    #[doc(hidden)]
    pub fn drop_mined_fee_deltas(&self, txids: &[Txid]) {
        let mut deltas = self.fee_deltas.lock().unwrap();
        for tid in txids {
            deltas.remove(tid);
        }
    }

    #[doc(hidden)]
    pub fn note_if_accept_failure(&self, tx: &Transaction, e: &AcceptError) {
        if is_hard_recent_reject(e) {
            self.note_recent_reject(tx.compute_wtxid());
        }
        if let Some(rec) = rbitcoin_mempool::ActiveMempool::accept_failure_record(tx, e) {
            let mut g = self.lock_write();
            g.apply_accept_failure(tx, rec);
        }
    }

    #[doc(hidden)]
    pub fn publish_admitted(
        &self,
        tx: &Transaction,
        r: &AcceptResult,
        prevouts: &[TxOut],
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) {
        for old in &r.replaced {
            self.unindex_txid(old);
        }
        debug_assert!(
            !r.evicted.contains(&r.txid),
            "a successful admit is not in its own eviction set"
        );
        self.unindex_evicted(&r.evicted);
        let seq = self.next_relay_seq.fetch_add(1, Ordering::Relaxed);
        let w = tx.compute_wtxid();
        self.insert_relay_maps(r.txid, w, seq, r.accept_secs, true);
        self.reorg_servable.lock().unwrap().remove(&w);
        self.note_fee_flow_admit(r.weight, r.fee_sat);
        self.push_recent(tx, r);
        self.index_txid(r.txid, tx, prevouts);
        let shs = self
            .sh_index
            .lock()
            .unwrap()
            .by_tx
            .get(&r.txid)
            .cloned()
            .unwrap_or_default();
        self.publish_announce(r, shs);
        self.note_template_update();
        self.promote_orphans_staged(r.txid, utxo);
    }

    /// One frame for every orphan of every tx admitted on this thread.
    ///
    /// A publish that happens while the walk is running, including a 1p1c
    /// parent and a conflict put back after a failed admit, appends that
    /// txid here. It does not start another walk.
    #[doc(hidden)]
    pub fn promote_orphans_staged(&self, parent: Txid, utxo: &impl rbitcoin_mempool::UtxoProvider) {
        if promote_note(parent) {
            return;
        }
        let _walk = PromoteWalk::enter();
        let mut queue = VecDeque::new();
        promote_note(parent);
        self.enqueue_noted_orphans(&mut queue);
        while let Some(child) = queue.pop_front() {
            let txid = child.tx.compute_txid();
            let from = child
                .announcers
                .iter()
                .copied()
                .find(|&id| self.tx_from_trusted(Some(id)));
            let _ = self.accept_with_utxo(
                &child.tx,
                utxo,
                TxOrigin::Relay(from),
                false,
                &child.announcers,
            );
            // Admitted or rejected without a repark. A repark already consumed
            // this generation. A newer take of the same txid keeps its own.
            self.forget_taken_orphan(txid, child.taken_gen);
            self.enqueue_noted_orphans(&mut queue);
        }
    }

    /// Move orphans of every tx noted since the last drain onto `queue`.
    /// Earlier notes stay ahead of later ones. A second take of the same
    /// txid is empty.
    #[doc(hidden)]
    pub fn enqueue_noted_orphans(&self, queue: &mut VecDeque<rbitcoin_mempool::OrphanSnapshot>) {
        let notes = promote_take_notes();
        if notes.is_empty() {
            return;
        }
        let mut kids = Vec::new();
        {
            let mut g = self.lock_write();
            for txid in notes {
                kids.extend(g.take_orphan_children(txid));
            }
        }
        for child in kids.into_iter().rev() {
            queue.push_front(child);
        }
    }

    /// Accept on the tokio blocking pool (never on `tokio-rt-worker`).
    pub async fn accept_tx_from_async(
        self: &Arc<Self>,
        tx: Transaction,
        origin: TxOrigin,
    ) -> Result<AcceptResult, AcceptError> {
        let hub = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            hub.accept_tx_from(&tx, origin)
        })
        .await
        .expect("mempool accept join")
    }

    /// Package accept on the tokio blocking pool (never on `tokio-rt-worker`).
    pub async fn accept_package_async(
        self: &Arc<Self>,
        txs: Vec<Transaction>,
    ) -> Result<Vec<AcceptResult>, AcceptError> {
        let hub = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            hub.accept_package(&txs)
        })
        .await
        .expect("mempool accept join")
    }

    /// Prepare + scripts + RBF/cluster checks with no mempool mutation.
    pub fn test_accept(&self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        let t0 = Instant::now();
        let utxo = self.utxo_provider();
        utxo.note_spender(tx);

        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let delta = self.fee_delta(&tx.compute_txid());
        let spec = AdmitSpec {
            report_orphans: false,
            fee_delta: delta,
            time_prepare_lock: false,
            min_relay: None,
            waive: false,
        };
        let prep = match self.admit_staged(tx, &utxo, spec, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(e) => {
                let us = t0.elapsed().as_micros() as u64;
                self.meter_accept_stages(lock_us, stages);
                return self.finish_accept_err(us, e);
            }
        };

        let result = {
            let t_lock = Instant::now();
            let g = self.lock_read();
            let r = g.evaluate_after_script(tx, prep);
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            r
        };

        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        match result {
            Ok(r) => Ok(r),
            Err(e) => self.finish_accept_err(us, e),
        }
    }

    #[doc(hidden)]
    pub fn note_fee_flow_admit(&self, weight: u64, fee_sat: u64) {
        let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee_sat, weight);
        if let Ok(mut m) = self.fee_flow.lock() {
            m.note_admit(weight, rate, Instant::now());
        }
        self.mark_fee_dirty();
    }

    #[doc(hidden)]
    pub fn mark_fee_dirty(&self) {
        self.fee_dirty.store(true, Ordering::Release);
        self.tx_snap_dirty.store(true, Ordering::Release);
    }

    /// Map API target blocks → engine depth. `0` is the 1-block horizon.
    /// Targets 1 and 2 stay on the curve (`fee-target-curve`).
    #[doc(hidden)]
    pub fn fee_depth(target_blocks: u32) -> u32 {
        if target_blocks == 0 {
            Self::DEFAULT_HORIZON_BLOCKS
        } else {
            target_blocks
        }
    }

    /// Lazy singleflight refresh when dirty or older than [`FEE_SNAPSHOT_MAX_AGE`].
    #[doc(hidden)]
    pub fn maybe_refresh_fee_snapshot(&self) {
        let snap = self.fee_snapshot.load_full();
        // Always refresh when never populated with real data and dirty (first admit path).
        self.singleflight_if_stale(
            snap.computed_at,
            self.fee_dirty.load(Ordering::Acquire),
            &self.fee_refreshing,
            Self::refresh_fee_snapshot,
        );
    }

    /// Stale-or-dirty gate shared by the fee and tx snapshots. The refresh body stays with the caller.
    #[doc(hidden)]
    pub fn singleflight_if_stale(
        &self,
        computed_at: Instant,
        dirty: bool,
        refreshing: &AtomicBool,
        refresh: fn(&Self),
    ) {
        if !is_stale(computed_at, Instant::now(), dirty, FEE_SNAPSHOT_MAX_AGE) {
            return;
        }
        if refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Another thread is refreshing; callers use the previous Arc.
            return;
        }
        refresh(self);
        refreshing.store(false, Ordering::Release);
    }

    /// One graph linearize under short read lock, then pure math off-lock → publish.
    #[doc(hidden)]
    pub fn refresh_fee_snapshot(&self) {
        let t0 = Instant::now();
        let (chunks, chunk_raw_vsize, count, vsize, total_fee) = {
            let g = self.lock_read();
            let chunks = g.graph.mining_chunks_best_first();
            let chunk_raw_vsize = chunks
                .iter()
                .map(|c| {
                    c.txids
                        .iter()
                        .filter_map(|t| g.graph.get(t))
                        .map(|e| e.weight.saturating_add(3) / 4)
                        .sum()
                })
                .collect();
            let mut count = 0usize;
            let mut vsize = 0u64;
            let mut total_fee = 0u64;
            for (_, e) in g.graph.iter() {
                count += 1;
                total_fee = total_fee.saturating_add(e.fee_sat);
                vsize = vsize.saturating_add(e.weight.saturating_add(3) / 4);
            }
            (chunks, chunk_raw_vsize, count, vsize, total_fee)
        };

        let now = Instant::now();
        let (inflow, alpha) = match self.fee_flow.lock() {
            Ok(mut flow) => {
                let alpha = flow.fullness(now);
                (Some(flow.admit_rates_wu_s(now)), alpha)
            }
            Err(_) => (None, 0.0),
        };
        let candidates = fine_candidate_rates();
        let stock = StockAbove::from_best_first(&chunks);
        let min_r = rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
        let confirm_floor = self.confirm_memory_floor_sat_per_kvb();
        let history = self.block_p10_history.lock().unwrap().rates();

        let mut ordered: Vec<(u32, Option<u64>)> = Vec::with_capacity(FEE_SNAPSHOT_DEPTHS.len());
        for &depth in FEE_SNAPSHOT_DEPTHS {
            let target_wu = u64::from(depth).saturating_mul(BLOCK_WEIGHT_WU);
            let frontier = frontier_feerate_from_chunks(&chunks, target_wu);
            let projected = inflow
                .as_ref()
                .and_then(|inf| min_rate_for_capacity(|r| stock.above(r), inf, depth, &candidates));
            let flow = flow_for_depth(projected, frontier, depth);
            let hist = history.get(&depth).copied().flatten();
            let rate = published_depth_rate(depth, alpha, flow, frontier, hist, confirm_floor);
            ordered.push((depth, rate.map(|r| r.max(min_r))));
        }
        let decile = fullness_decile(alpha);
        self.log_fee_readiness(decile, &history);
        let mut held: Vec<Option<u64>> = ordered.iter().map(|(_, r)| *r).collect();
        hold_defined_then_monotone(&mut held);

        self.fee_snapshot.store(Arc::new(FeeSnapshot {
            depth_rates_sat_kvb: held,
            chunks,
            chunk_raw_vsize,
            count,
            vsize,
            total_fee,
            computed_at: t0,
        }));
        self.fee_dirty.store(false, Ordering::Release);
    }

    /// Lazy singleflight rebuild of the live-tx snapshot.
    #[doc(hidden)]
    pub fn maybe_refresh_tx_snapshot(&self) {
        let snap = self.tx_snapshot.load_full();
        self.singleflight_if_stale(
            snap.computed_at,
            self.tx_snap_dirty.load(Ordering::Acquire),
            &self.tx_snap_refreshing,
            Self::refresh_tx_snapshot,
        );
    }

    #[doc(hidden)]
    pub fn refresh_tx_snapshot(&self) {
        let t0 = Instant::now();
        let old = self.tx_snapshot.load_full();
        let live = self.list_live_meta();
        let mut entries: Vec<MempoolTxSnapEntry> = live
            .into_iter()
            .filter_map(|(txid, fee_sat, weight)| {
                if let Some(old_e) = old.get(&txid) {
                    let json = std::sync::OnceLock::new();
                    if old_e.fee_sat == fee_sat {
                        if let Some(s) = old_e.json.get() {
                            let _ = json.set(s.clone());
                        }
                    }
                    return Some(MempoolTxSnapEntry {
                        txid,
                        fee_sat,
                        weight,
                        tx: Arc::clone(&old_e.tx),
                        json,
                    });
                }
                let tx = self.get_tx(&txid)?;
                Some(MempoolTxSnapEntry {
                    txid,
                    fee_sat,
                    weight,
                    tx: Arc::new(tx),
                    json: std::sync::OnceLock::new(),
                })
            })
            .collect();
        entries.sort_by_key(|a| a.txid);
        self.tx_snapshot.store(Arc::new(MempoolTxSnapshot {
            entries,
            computed_at: t0,
        }));
        self.tx_snap_dirty.store(false, Ordering::Release);
    }

    /// Txid-sorted live mempool snapshot (Arc). Does not take the admit write lock.
    pub fn mempool_tx_snapshot(&self) -> Arc<MempoolTxSnapshot> {
        self.maybe_refresh_tx_snapshot();
        self.tx_snapshot.load_full()
    }

    /// Live count / vsize / total_fee from the published fee snapshot (GET `/mempool`).
    ///
    /// Request path is one Arc load after the existing fee-engine singleflight.
    /// Does not clone bodies or walk the live graph.
    pub fn mempool_live_totals(&self) -> (usize, u64, u64) {
        self.maybe_refresh_fee_snapshot();
        let snap = self.fee_snapshot.load();
        (snap.count, snap.vsize, snap.total_fee)
    }

    #[doc(hidden)]
    pub fn finish_accept_err(&self, us: u64, e: AcceptError) -> Result<AcceptResult, AcceptError> {
        // Soft outcomes (already in pool / orphan / full) are not "rejects".
        let hard = !matches!(
            e,
            AcceptError::Duplicate(_)
                | AcceptError::Orphaned { .. }
                | AcceptError::Policy("mempool full")
        );
        if hard {
            self.meter_accept_wall(us, false);
        } else {
            self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
        }
        Err(e)
    }

    /// Count / weight / topo checks for `submitpackage` / `POST /txs/package`.
    pub fn check_package_shape(txs: &[Transaction]) -> Result<(), AcceptError> {
        ActiveMempool::check_package_shape(txs)
    }

    /// Core `IsChildWithParents` (submitpackage topology).
    pub fn package_is_child_with_direct_parents(txs: &[Transaction]) -> bool {
        ActiveMempool::package_is_child_with_direct_parents(txs)
    }

    /// Core ancestor package size cap (count, not weight).
    pub fn max_package_count() -> usize {
        MAX_PACKAGE_COUNT
    }

    /// Accept an ancestor package. Every member is [`TxOrigin::Local`]: this is
    /// the RPC, Esplora, and Electrum path (BIP331 wire later).
    pub fn accept_package(&self, txs: &[Transaction]) -> Result<Vec<AcceptResult>, AcceptError> {
        let accepted = self.admit_package(txs)?;
        let txids: Vec<Txid> = accepted.iter().map(|r| r.txid).collect();
        self.kick_isolated_if_live(&txids);
        Ok(accepted)
    }

    /// [`Self::accept_package`] without the isolated kick, for a caller that
    /// trims again afterwards.
    fn admit_package(&self, txs: &[Transaction]) -> Result<Vec<AcceptResult>, AcceptError> {
        crate::reactor::assert_not_reactor("mempool accept");
        Self::check_package_shape(txs)?;
        let t0 = Instant::now();
        let utxo = self.utxo_provider();
        let sat_kvb = self.min_relay_sat_kvb();
        let member_min = {
            let g = self.lock_read();
            let bps = g.graph.bytes_per_sigop();
            if g.package_meets_min_relay(txs, &utxo, sat_kvb, bps) {
                Some(0)
            } else {
                None
            }
        };
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
        let mut prevouts: Vec<Vec<TxOut>> = Vec::with_capacity(txs.len());
        // A member that is already parked has to leave the orphanage before
        // prepare. Otherwise the parent just committed in this package is
        // rolled back and the child stays parked.
        let mut lifted: Vec<rbitcoin_mempool::LiftedOrphan> = Vec::new();
        for tx in txs {
            if let Some(parked) = {
                let mut g = self.lock_write();
                g.lift_parked_member(tx)
            } {
                lifted.push(parked);
            }
            utxo.note_spender(tx);
            let delta = self.fee_delta(&tx.compute_txid());
            let spec = AdmitSpec {
                report_orphans: true,
                fee_delta: delta,
                time_prepare_lock: true,
                min_relay: member_min,
                waive: false,
            };
            let prep = match self.admit_staged(tx, &utxo, spec, &mut stages, &mut lock_us) {
                Ok(p) => p,
                Err(e) => {
                    self.abandon_package(&accepted, &lifted);
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
            };
            let sample = self.sample_chain_coins(tx, &utxo);
            let t_lock = Instant::now();
            let committed = {
                let mut g = self.lock_write();
                g.last_accept_stages = stages;
                let committed = Self::commit_rechecked(&mut g, tx, prep, &utxo, true, &sample);
                self.note_origin(TxOrigin::Local, &committed.result);
                stages = g.last_accept_stages;
                committed
            };
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            match committed.result {
                Ok(r) => {
                    prevouts.push(committed.prevouts);
                    accepted.push(r);
                }
                Err(e) => {
                    self.unindex_evicted(&committed.failed_evict);
                    self.restore_replaced(&committed.undone);
                    self.abandon_package(&accepted, &lifted);
                    // The first member can evict and fail with nothing to roll
                    // back, so the rollback publish does not run.
                    self.publish_fee_floor();
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
            }
        }
        self.trim_over_budget();
        if accepted.iter().any(|r| !self.try_contains(&r.txid)) {
            // Trim dropped a member that had already replaced its conflicts.
            // Put those conflicts back; the package itself does not stay.
            self.abandon_package(&accepted, &lifted);
            self.publish_fee_floor();
            let us = t0.elapsed().as_micros() as u64;
            self.meter_accept_stages(lock_us, stages);
            return Err(self
                .finish_accept_err(us, AcceptError::Policy("mempool full"))
                .unwrap_err());
        }
        // The failure path forgets inside abandon. Success leaves the lifted
        // txs in the mempool, so the in-flight rows would outlive the admit.
        for item in &lifted {
            self.forget_taken_orphan(item.tx.compute_txid(), item.taken_gen);
        }
        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        let per = us / (accepted.len().max(1) as u64);
        for (i, (tx, r)) in txs.iter().zip(accepted.iter()).enumerate() {
            self.meter_accept_wall(per, true);
            self.note_fee_flow_admit(r.weight, r.fee_sat);
            self.push_recent(tx, r);
            for old in &r.replaced {
                self.unindex_txid(old);
            }
            self.unindex_evicted(&r.evicted);
            // Same relay-age clock as an individual admit (`mempool_limit.py` INV).
            let seq = self.next_relay_seq.fetch_add(1, Ordering::Relaxed);
            self.insert_relay_maps(r.txid, tx.compute_wtxid(), seq, r.accept_secs, true);
            self.index_txid(
                r.txid,
                tx,
                prevouts.get(i).map(Vec::as_slice).unwrap_or(&[]),
            );
            let shs = self
                .sh_index
                .lock()
                .unwrap()
                .by_tx
                .get(&r.txid)
                .cloned()
                .unwrap_or_default();
            self.publish_announce(r, shs);
            self.promote_orphans_staged(r.txid, &utxo);
        }
        self.note_template_update();
        self.publish_fee_floor();
        Ok(accepted)
    }

    /// Pool transactions one `generate` may put in the first block.
    ///
    /// The live set is unchanged. RPC `generate` commits them once that block
    /// is accepted, before a later block of the same call is mined. Catch-up
    /// must not call this (that block stays coinbase-only).
    /// [`Self::remove_for_block`] drops nothing until maintenance has begun.
    pub fn select_generate_txs(&self, min_sat_kvb: u64) -> Vec<Transaction> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let g = self.lock_write();
        let budget = g.template_budget(min_sat_kvb);
        let selected = g.select_block_template(budget, |id| deltas.get(&id).copied().unwrap_or(0));
        selected
            .into_iter()
            .map(|(tx, _sel)| Transaction::clone(tx.as_ref()))
            .collect()
    }

    /// Remove `txids` once the block that contains them has been accepted.
    ///
    /// Entries connect already removed are left alone, so their confirm-memory
    /// sample is not recorded twice. A failure before that block must not
    /// call this. A later block in the same `generate` can still fail.
    pub fn commit_generated_txids(&self, txids: &[Txid]) -> Result<(), AcceptError> {
        if txids.is_empty() {
            return Ok(());
        }
        let removed = {
            let mut g = self.lock_write();
            let bps = g.graph.bytes_per_sigop();
            for tid in txids {
                if let Some(e) = g.graph.get(tid) {
                    let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
                        e.fee_sat,
                        e.adjusted_weight(bps),
                    );
                    self.push_confirm_memory(rate);
                }
            }
            g.remove_live_txids(txids)?
        };
        if removed > 0 {
            self.unindex_evicted(txids);
        }
        self.drop_mined_fee_deltas(txids);
        Ok(())
    }

    /// Remove confirmed txids (tip connect / archive confirm) and re-try orphans
    /// whose parents just confirmed (Query UTXO view).
    ///
    /// Samples removed entries' feerates into confirm-memory for the standard
    /// 10-minute fee estimate floor.
    ///
    /// **Strip is a no-op until pool maintenance has begun** (the connect that
    /// leaves IBD, or [`Self::set_relay_enabled`]`(true)`). Bulk IBD does not
    /// start maintenance, so catch-up is not paced by a large pool. Mined
    /// prioritisation deltas still drop, including a tx that already left
    /// the mempool and a block that removes nothing live.
    pub fn remove_for_block(&self, txids: &[Txid]) -> usize {
        if !self.pool_maintained() {
            self.drop_mined_fee_deltas(txids);
            return 0;
        }
        let utxo = self.utxo_provider();
        let n = {
            let mut g = self.lock_write();
            let bps = g.graph.bytes_per_sigop();
            for tid in txids {
                if let Some(e) = g.graph.get(tid) {
                    // Core `CBlockPolicyEstimator` records fee over the
                    // sigop-adjusted size, like the chunk frontier.
                    let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
                        e.fee_sat,
                        e.adjusted_weight(bps),
                    );
                    self.push_confirm_memory(rate);
                }
            }
            g.remove_live_txids(txids).unwrap_or(0)
        };
        for tid in txids {
            self.promote_orphans_staged(*tid, &utxo);
        }
        {
            let mut g = self.lock_write();
            g.erase_orphans_for_block(txids);
        }
        if n > 0 {
            self.unindex_evicted(txids);
        }
        self.drop_mined_fee_deltas(txids);
        n
    }

    /// Remove confirmed txids, then evict mempool txs that spend `spent`
    /// (block inputs that conflicted with the live set).
    pub fn remove_for_block_spent(&self, txids: &[Txid], spent: &[OutPoint]) -> usize {
        if !self.pool_maintained() {
            self.drop_mined_fee_deltas(txids);
            return 0;
        }
        if spent.is_empty() {
            return self.remove_for_block(txids);
        }
        let utxo = self.utxo_provider();
        let (n, gone) = {
            let mut g = self.lock_write();
            let bps = g.graph.bytes_per_sigop();
            for tid in txids {
                if let Some(e) = g.graph.get(tid) {
                    let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
                        e.fee_sat,
                        e.adjusted_weight(bps),
                    );
                    self.push_confirm_memory(rate);
                }
            }
            g.remove_block_txids(txids, spent)
                .unwrap_or((0, Vec::new()))
        };
        for tid in txids {
            self.promote_orphans_staged(*tid, &utxo);
        }
        {
            let mut g = self.lock_write();
            g.erase_orphans_for_block(txids);
        }
        if n > 0 {
            self.unindex_evicted(txids);
        }
        self.unindex_evicted(&gone);
        self.drop_mined_fee_deltas(txids);
        n + gone.len()
    }

    /// Unique txs parked waiting on missing parents.
    pub fn orphan_count(&self) -> usize {
        self.lock_read().orphan_count()
    }

    /// `(count, weight WU)` of the orphanage.
    pub fn orphan_stats(&self) -> (usize, u64) {
        let g = self.lock_read();
        (g.orphanage.len(), g.orphanage.total_weight())
    }

    pub fn orphan_snapshot(&self) -> Vec<rbitcoin_mempool::OrphanSnapshot> {
        self.lock_read().orphanage.snapshot()
    }

    pub fn add_orphan_announcer(&self, txid: &Txid, peer: u64) -> bool {
        if let Some(r) = self.orphan_write(|g| g.orphanage.add_announcer(txid, peer)) {
            return r;
        }
        let _g = crate::reactor::BlockingRegion::enter();
        self.orphan_write(|g| g.orphanage.add_announcer(txid, peer))
            .unwrap_or(false)
    }

    pub fn add_orphan_announcer_wtxid(&self, wtxid: &Wtxid, peer: u64) -> bool {
        if let Some(r) = self.orphan_write(|g| g.orphanage.add_announcer_wtxid(wtxid, peer)) {
            return r;
        }
        let _g = crate::reactor::BlockingRegion::enter();
        self.orphan_write(|g| g.orphanage.add_announcer_wtxid(wtxid, peer))
            .unwrap_or(false)
    }

    fn forget_taken_orphan(&self, txid: Txid, gen: u64) {
        let _ = self.orphan_write(|g| g.orphanage.forget_taken_gen(&txid, gen));
    }

    pub fn erase_orphans_for_peer(&self, peer: u64) {
        self.forget_parent_anns_for_peer(peer);
        let skip = self
            .inner
            .try_read()
            .ok()
            .is_some_and(|g| !g.orphanage.has_announcer(peer));
        if skip {
            return;
        }
        let _ = self.orphan_write(|g| g.orphanage.erase_for_peer(peer));
    }

    /// Handshake/INV/disconnect run on the reactor. Prefer `try_write`; wait only off-reactor.
    #[doc(hidden)]
    pub fn orphan_write<R>(&self, f: impl FnOnce(&mut ActiveMempool) -> R) -> Option<R> {
        if let Ok(mut g) = self.inner.try_write() {
            return Some(f(&mut g));
        }
        if crate::reactor::on_tokio_worker() && !crate::reactor::in_blocking_region() {
            return None;
        }
        Some(f(&mut self.lock_write()))
    }

    #[doc(hidden)]
    pub fn parent_already_have(&self, txid: &Txid) -> bool {
        if let Ok(g) = self.inner.try_read() {
            if g.graph.contains(txid) {
                return true;
            }
            if g.orphanage.contains(txid) {
                if let Some(w) = g.orphanage.wtxid_of(txid) {
                    if w.to_byte_array() == txid.to_byte_array() {
                        return true;
                    }
                }
            }
        }
        if self
            .recent_confirmed
            .try_lock()
            .ok()
            .is_some_and(|r| r.contains_txid(txid))
        {
            return true;
        }
        self.try_recent_reject(&Wtxid::from_byte_array(txid.to_byte_array()))
    }

    pub fn orphan_getdata_parents(&self, tx: &Transaction) -> BTreeSet<Txid> {
        let mut out = BTreeSet::new();
        for inp in &tx.input {
            let p = inp.previous_output.txid;
            if self.parent_already_have(&p) {
                continue;
            }
            out.insert(p);
        }
        out
    }

    pub fn try_orphan_missing(&self, txid: &Txid) -> Option<BTreeSet<Txid>> {
        self.inner
            .try_read()
            .ok()?
            .orphanage
            .missing_of(txid)
            .cloned()
    }

    pub fn try_orphan_tx_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        self.inner
            .try_read()
            .ok()?
            .orphanage
            .tx_by_wtxid(wtxid)
            .cloned()
    }

    pub fn schedule_orphan_parents(
        &self,
        missing: &BTreeSet<Txid>,
        peer: u64,
        inbound: bool,
        now: u64,
    ) {
        let delay = TXID_RELAY_DELAY_SECS
            + if inbound {
                NONPREF_PEER_TX_DELAY_SECS
            } else {
                0
            };
        let reqtime = now.saturating_add(delay);
        let preferred = !inbound;
        let mut g = self.parent_req.lock().unwrap();
        for p in missing {
            if self.parent_already_have(p) {
                continue;
            }
            g.schedule(p.to_byte_array(), peer, preferred, reqtime);
        }
    }

    /// `wtxid` records that this announcement is a wtxid inv.
    /// [`ParentNote::RequestNow`] is the one in-flight getdata.
    /// [`ParentNote::Deferred`] is recorded and not asked yet.
    /// [`ParentNote::PeerCapped`] is this peer's own cap. [`ParentNote::GlobalFull`]
    /// skips the row and is not misbehavior.
    pub fn note_inv_tx_requested(
        &self,
        peer: u64,
        hash: [u8; 32],
        inbound: bool,
        now: u64,
        wtxid: bool,
    ) -> ParentNote {
        self.parent_req
            .lock()
            .unwrap()
            .note_inv(peer, hash, inbound, now, wtxid)
    }

    pub fn forget_parent_anns_for_peer(&self, peer: u64) {
        self.parent_req.lock().unwrap().forget_peer(peer);
    }

    pub fn note_tx_not_found(&self, peer: u64, hash: [u8; 32]) {
        self.parent_req.lock().unwrap().note_not_found(peer, hash);
    }

    pub fn announcer_peers_for(&self, txid: &Txid, wtxid: &Wtxid) -> Vec<u64> {
        self.parent_req
            .lock()
            .unwrap()
            .announcer_peers([txid.to_byte_array(), wtxid.to_byte_array()])
    }

    pub fn resolve_tx_request(&self, txid: &Txid, wtxid: &Wtxid, admitted: bool) {
        self.parent_req
            .lock()
            .unwrap()
            .resolve([txid.to_byte_array(), wtxid.to_byte_array()], admitted);
    }

    pub fn take_due_parent_getdata(&self, peer: u64, now: u64) -> Vec<DueParent> {
        let mut g = self.parent_req.lock().unwrap();
        g.take_due(peer, now, |hash, wtxid| {
            if wtxid {
                let w = Wtxid::from_byte_array(*hash);
                self.try_contains_wtxid(&w) || self.try_recent_reject(&w)
            } else {
                self.parent_already_have(&Txid::from_byte_array(*hash))
            }
        })
    }

    /// Re-admit txs after reorg disconnect (best-effort), parents first.
    pub fn reorg_reaccept(&self, txs: &[Transaction]) -> usize {
        let utxo = self.utxo_provider();
        let mut admitted: Vec<(&Transaction, Vec<TxOut>)> = Vec::new();
        for tx in txs.iter().filter(|t| !t.is_coinbase()) {
            if let Ok(prevouts) = self.staged_reorg_admit(tx, &utxo) {
                let w = tx.compute_wtxid();
                self.reorg_servable.lock().unwrap().insert(w);
                self.insert_relay_maps(tx.compute_txid(), w, 0, self.relay_now_secs(), true);
                admitted.push((tx, prevouts));
            }
        }
        self.evict_after_reorg();
        for (tx, prevouts) in &admitted {
            self.index_txid(tx.compute_txid(), tx, prevouts);
        }
        admitted.len()
    }

    #[doc(hidden)]
    pub fn staged_reorg_admit(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) -> Result<Vec<TxOut>, AcceptError> {
        utxo.note_spender(tx);
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        // Parents come first, so a missing input is a parent that did not
        // come back or a coin the new chain spent. Core drops the tx.
        let spec = AdmitSpec {
            report_orphans: false,
            fee_delta: 0,
            time_prepare_lock: false,
            min_relay: None,
            waive: false,
        };
        let prep = self.admit_staged(tx, utxo, spec, &mut stages, &mut lock_us)?;
        let sample = self.sample_chain_coins(tx, utxo);
        let committed = {
            let mut g = self.lock_write();
            Self::commit_rechecked(&mut g, tx, prep, utxo, false, &sample)
        };
        let prevouts = match committed.result {
            Ok(r) => {
                self.unindex_evicted(&r.evicted);
                committed.prevouts
            }
            Err(e) => {
                self.unindex_evicted(&committed.failed_evict);
                self.restore_replaced(&committed.undone);
                return Err(e);
            }
        };
        self.promote_orphans_staged(tx.compute_txid(), utxo);
        Ok(prevouts)
    }

    /// True if this wtxid entered the mempool from a disconnected block.
    pub fn is_reorg_servable(&self, wtxid: &Wtxid) -> bool {
        self.reorg_servable.lock().unwrap().contains(wtxid)
    }

    pub fn current_relay_seq(&self) -> u64 {
        self.next_relay_seq.load(Ordering::Relaxed)
    }

    /// True when entry_sequence < peer's last INV sequence.
    pub fn is_relay_servable(&self, wtxid: &Wtxid, last_inv_seq: u64) -> bool {
        self.relay_seq
            .lock()
            .unwrap()
            .get(wtxid)
            .is_some_and(|s| *s < last_inv_seq)
    }

    /// Entry sequence for a live wtxid, if we assigned one.
    pub fn relay_seq_of(&self, wtxid: &Wtxid) -> Option<u64> {
        self.relay_seq.lock().unwrap().get(wtxid).copied()
    }

    /// Drop live txs that are non-final / immature at the new tip (invalidate
    /// of empty blocks still has to evict mempool coinbase spends).
    pub fn evict_after_reorg(&self) {
        self.reorg_evict(|_| {});
    }

    /// Same as [`Self::evict_after_reorg`]. `between` runs after each removal
    /// and before the next coin check, while no mempool write lock is held.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn evict_after_reorg_between(&self, between: impl FnMut(&Self)) {
        self.reorg_evict(between);
    }

    #[doc(hidden)]
    pub fn reorg_evict(&self, mut between: impl FnMut(&Self)) {
        let utxo = self.utxo_provider();
        let tip = self.chain_tip_ctx();
        loop {
            let snaps: Vec<(Txid, Transaction, Vec<bool>, bool)> = {
                let g = self.lock_read();
                g.graph
                    .iter()
                    .filter_map(|(id, _)| {
                        let tx = g.get_tx(id)?.clone();
                        let in_mp: Vec<bool> = tx
                            .input
                            .iter()
                            .map(|inp| g.graph.creator(&inp.previous_output).is_some())
                            .collect();
                        Some((*id, tx, in_mp, g.trust_kept.contains(id)))
                    })
                    .collect()
            };
            let mut to_drop = Vec::new();
            for (id, tx, in_mp, trust) in snaps {
                utxo.note_spender(&tx);
                let mut chain_coins = Vec::with_capacity(tx.input.len());
                let mut missing = false;
                for (i, inp) in tx.input.iter().enumerate() {
                    if in_mp.get(i).copied().unwrap_or(false) {
                        chain_coins.push(None);
                    } else if let Some(c) = utxo.get_coin(&inp.previous_output) {
                        chain_coins.push(Some(c));
                    } else {
                        missing = true;
                        break;
                    }
                }
                if missing {
                    to_drop.push(id);
                    continue;
                }
                if let Err(err) = rbitcoin_mempool::check_mempool_structural(&tx, &chain_coins, tip)
                {
                    if !rbitcoin_mempool::trust_keeps_structural(trust, &err) {
                        to_drop.push(id);
                    }
                }
            }
            if to_drop.is_empty() {
                break;
            }
            // Parent and in-mempool descendants leave under one write lock.
            // A template read cannot observe the child after the parent is gone.
            let mut gone = Vec::new();
            {
                let mut g = self.lock_write();
                for id in &to_drop {
                    if g.graph.contains(id) {
                        gone.extend(g.remove_txid_tree(id));
                    }
                }
            }
            if gone.is_empty() {
                break;
            }
            self.unindex_evicted(&gone);
            between(self);
        }
        self.publish_fee_floor();
    }

    /// This node's own block budget (GBT / `generate`): template weight and
    /// the configured sigop reserve, with a `-blockmintxfee` floor.
    pub fn template_budget(&self, min_sat_kvb: u64) -> SelectBudget {
        self.lock_read().template_budget(min_sat_kvb)
    }

    /// Block template selection: mining-order live txs that fit `budget`
    /// (best chunks first, `prioritisetransaction` deltas applied). Base fee
    /// and sigop cost come from the same read lock as the selection, so a tx
    /// evicted afterwards still reports what it was selected with.
    pub fn select_block_template(&self, budget: SelectBudget) -> Vec<(Arc<Transaction>, Selected)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let g = self.lock_read();
        g.select_block_template(budget, |id| deltas.get(&id).copied().unwrap_or(0))
    }

    /// Additive `prioritisetransaction` delta (sat). Zero total drops the entry.
    pub fn prioritise_tx(&self, txid: Txid, fee_delta: i64) {
        let mut m = self.fee_deltas.lock().unwrap();
        let e = m.entry(txid).or_insert(0);
        *e = e.saturating_add(fee_delta);
        if *e == 0 {
            m.remove(&txid);
        }
        drop(m);
        self.note_template_update();
    }

    #[doc(hidden)]
    pub fn note_template_update(&self) {
        let next = self.template_updates.fetch_add(1, Ordering::Relaxed) + 1;
        // A hold publishes once, on drop, for the tip it commits. Sending
        // here would wake a one-shot wait on the stump, or on an
        // intermediate block of a fork that is still connecting. The pause
        // covers the gap between the disconnect hold and the next one.
        if self.template_publish_pause.load(Ordering::SeqCst) == 0
            && self.pool_settle.load(Ordering::SeqCst) & 1 == 0
        {
            self.template_watch.send_replace(next);
        }
    }

    /// Suppress [`Self::note_template_update`] until this guard drops.
    #[doc(hidden)]
    pub fn pause_template_publish(self: &Arc<Self>) -> TemplatePublishPause {
        self.template_publish_pause.fetch_add(1, Ordering::SeqCst);
        TemplatePublishPause {
            mp: Arc::clone(self),
        }
    }

    /// Wakes when [`Self::note_template_update`] bumps the generation.
    #[doc(hidden)]
    pub fn subscribe_template(&self) -> tokio::sync::watch::Receiver<u64> {
        self.template_watch.subscribe()
    }

    /// The pool has been stripped for `hash`. Templates build on this tip.
    pub fn note_template_prev(&self, hash: [u8; 32]) {
        *self.template_prev.lock().unwrap() = Some(hash);
        self.note_template_update();
    }

    /// Held across a block connect: from before the query tip moves until the
    /// strip has been recorded. [`Self::note_template_prev`] takes the same
    /// mutex, so callers must record the hash through [`TemplateHold::commit`].
    #[doc(hidden)]
    pub fn template_hold(&self) -> TemplateHold<'_> {
        let slot = self.template_prev.lock().unwrap();
        self.pool_settle.fetch_add(1, Ordering::SeqCst);
        TemplateHold {
            updates: &self.template_updates,
            watch: &self.template_watch,
            settle: &self.pool_settle,
            slot,
            commit: None,
        }
    }

    /// Odd while a connect, disconnect, or reorg holds the template mark. A
    /// reader that sees one even value before and after its reads saw a
    /// pool that matches the tip.
    pub fn pool_settle_gen(&self) -> u64 {
        self.pool_settle.load(Ordering::SeqCst)
    }

    pub fn template_prev(&self) -> Option<[u8; 32]> {
        *self.template_prev.lock().unwrap()
    }

    /// Generation for `getblocktemplate.longpollid`.
    pub fn template_updates(&self) -> u64 {
        self.template_updates.load(Ordering::Relaxed)
    }

    /// Snapshot of non-zero deltas for `getprioritisedtransactions`.
    pub fn prioritised_txs(&self) -> HashMap<Txid, i64> {
        self.fee_deltas.lock().unwrap().clone()
    }

    /// Core `GetSigOpsAdjustedWeight` for `tx` spending `prevouts`, at this
    /// pool's `-bytespersigop`.
    pub fn sigops_adjusted_weight(&self, tx: &Transaction, prevouts: &[TxOut]) -> u64 {
        let spks: Vec<&[u8]> = prevouts
            .iter()
            .map(|o| o.script_pubkey.as_bytes())
            .collect();
        let sigops = rbitcoin_consensus::tx_sigop_cost(tx, &spks, true, true);
        let bps = self.lock_read().graph.bytes_per_sigop();
        rbitcoin_mempool::graph::sigops_adjusted_weight(tx.weight().to_wu(), sigops, bps)
    }

    pub fn fee_delta(&self, txid: &Txid) -> i64 {
        self.fee_deltas
            .lock()
            .unwrap()
            .get(txid)
            .copied()
            .unwrap_or(0)
    }

    /// Snapshot of live txs (for Electrum / RPC) — clones bodies.
    pub fn list_live(&self) -> Vec<(Txid, u64, u64, Transaction)> {
        self.meter_list_live.fetch_add(1, Ordering::Relaxed);
        let g = self.lock_read();
        g.graph
            .iter()
            .filter_map(|(txid, e)| {
                g.get_tx(txid)
                    .cloned()
                    .map(|tx| (*txid, e.fee_sat, e.weight, tx))
            })
            .collect()
    }

    /// Weight budget used for chunk eviction (WU).
    /// `getmempoolinfo.maxmempool` is this divided by 4 (virtual-size bytes).
    pub fn max_weight(&self) -> u64 {
        self.lock_read().max_weight
    }

    pub fn mempool_min_fee_sat_kvb(&self) -> u64 {
        self.publish_fee_floor()
    }

    /// Reactor-safe load of the last published admission floor (sat/kvB).
    pub fn fee_floor_sat_kvb(&self) -> u64 {
        self.fee_floor_sat_kvb.load(Ordering::Acquire)
    }

    /// Recompute the admission floor and publish it. Takes `inner` read,
    /// so callers must be off the reactor and must not already hold `inner`.
    ///
    /// The guard stays alive across the store. Dropping it first lets a
    /// slower publisher write the snapshot it read before this one.
    pub fn publish_fee_floor(&self) -> u64 {
        let g = self.lock_read();
        let floor = g.mempool_min_fee_sat_kvb();
        self.fee_floor_sat_kvb.store(floor, Ordering::Release);
        floor
    }

    /// Live txid + fee + weight **without** cloning bodies (RPC/Esplora stats).
    pub fn list_live_meta(&self) -> Vec<(Txid, u64, u64)> {
        self.meter_list_live_meta.fetch_add(1, Ordering::Relaxed);
        let g = self.lock_read();
        g.graph
            .iter()
            .map(|(txid, e)| (*txid, e.fee_sat, e.weight))
            .collect()
    }

    /// Core `GetTotalTxSize` / `totalFee`: (count, sigop-adjusted vbytes, fee) for `getmempoolinfo`.
    pub fn live_adjusted_totals(&self) -> (usize, u64, u64) {
        let g = self.lock_read();
        let bps = g.graph.bytes_per_sigop();
        g.graph.iter().fold((0, 0, 0), |(n, vb, fee), (_, e)| {
            (
                n + 1,
                vb + rbitcoin_consensus::policy::vbytes_ceil(e.adjusted_weight(bps)),
                fee + e.fee_sat,
            )
        })
    }

    /// Fee/weight for one live mempool txid (no live-set scan).
    pub fn get_live_meta(&self, txid: &Txid) -> Option<(u64, u64)> {
        self.lock_read()
            .graph
            .get(txid)
            .map(|e| (e.fee_sat, e.weight))
    }

    /// Core `GetAdjustedWeight`: `max(weight, sigop_cost * bytes_per_sigop)`.
    pub fn get_live_adjusted_weight(&self, txid: &Txid) -> Option<u64> {
        let g = self.lock_read();
        let bps = g.graph.bytes_per_sigop();
        g.graph.get(txid).map(|e| e.adjusted_weight(bps))
    }

    /// Fee + sigop-adjusted weight for the feefilter announce gate (Core
    /// `txinfo.vsize` is `GetTxSize`). `None` if a writer holds `inner`.
    pub fn try_get_live_meta(&self, txid: &Txid) -> Option<(u64, u64)> {
        let g = self.inner.try_read().ok()?;
        let bps = g.graph.bytes_per_sigop();
        g.graph
            .get(txid)
            .map(|e| (e.fee_sat, e.adjusted_weight(bps)))
    }

    /// Compact fill: siphash live txid/wtxid, clone **matching** bodies only.
    ///
    /// Keys are the siphashes already computed here — callers must not
    /// `compute_txid` / `compute_wtxid` the clones again.
    ///
    /// `None` if a writer holds `inner` (reconstruct without mempool this round).
    pub fn try_clone_matching_shortids(
        &self,
        header: &bitcoin::block::Header,
        nonce: u64,
        version: u32,
        short_ids: &[bitcoin::bip152::ShortId],
    ) -> Option<HashMap<bitcoin::bip152::ShortId, Vec<Transaction>>> {
        if short_ids.is_empty() {
            return Some(HashMap::new());
        }
        Some(
            self.try_cmpct_avail(header, nonce, version, short_ids, &[])?
                .0,
        )
    }

    /// Same `try_read` as compact clone: matching bodies plus fill-source sets.
    ///
    /// `prefill_wtxids` are classified even when they have no short-id (redundant
    /// inbound prefill). `None` if a writer holds `inner`.
    pub fn try_cmpct_avail(
        &self,
        header: &bitcoin::block::Header,
        nonce: u64,
        version: u32,
        short_ids: &[bitcoin::bip152::ShortId],
        prefill_wtxids: &[bitcoin::Wtxid],
    ) -> Option<(
        HashMap<bitcoin::bip152::ShortId, Vec<Transaction>>,
        crate::compact::CmpctFillSets,
    )> {
        use bitcoin::bip152::ShortId;
        use bitcoin::Wtxid;
        let needed: std::collections::HashSet<ShortId> = short_ids.iter().copied().collect();
        if needed.is_empty() && prefill_wtxids.is_empty() {
            return Some((HashMap::new(), crate::compact::CmpctFillSets::default()));
        }
        #[cfg(debug_assertions)]
        self.meter_cmpct_avail.fetch_add(1, Ordering::Relaxed);
        let g = self.inner.try_read().ok()?;
        let keys = ShortId::calculate_siphash_keys(header, nonce);
        let sid_of = |tx: &Transaction| -> ShortId {
            if version == 1 {
                ShortId::with_siphash_keys(&tx.compute_txid().to_raw_hash(), keys)
            } else {
                ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys)
            }
        };
        let mut out: HashMap<ShortId, Vec<Transaction>> = HashMap::new();
        let mut fill = crate::compact::CmpctFillSets::default();
        for (txid, e) in g.graph.iter() {
            let sid = if version == 1 {
                ShortId::with_siphash_keys(&txid.to_raw_hash(), keys)
            } else {
                ShortId::with_siphash_keys(&e.wtxid.to_raw_hash(), keys)
            };
            if needed.contains(&sid) {
                if let Some(tx) = g.get_tx(txid) {
                    fill.mempool.insert(e.wtxid);
                    out.entry(sid).or_default().push(tx.clone());
                }
            }
        }
        for tx in g.orphanage.txs() {
            let sid = sid_of(tx);
            if needed.contains(&sid) {
                let w = tx.compute_wtxid();
                if !fill.mempool.contains(&w) {
                    fill.orphan.insert(w);
                }
                out.entry(sid).or_default().push(tx.clone());
            }
        }
        let mut extra: std::collections::HashSet<Wtxid> = std::collections::HashSet::new();
        for tx in g.extra_compact_txs() {
            let w = tx.compute_wtxid();
            extra.insert(w);
            let sid = sid_of(tx);
            if needed.contains(&sid) {
                if !fill.mempool.contains(&w) && !fill.orphan.contains(&w) {
                    fill.extra.insert(w);
                }
                out.entry(sid).or_default().push(tx.clone());
            }
        }
        for w in prefill_wtxids {
            if g.graph.contains_wtxid(w) {
                fill.mempool.insert(*w);
            } else if extra.contains(w) {
                fill.extra.insert(*w);
            } else if g.orphanage.contains_wtxid(w) {
                fill.orphan.insert(*w);
            }
        }
        Some((out, fill))
    }

    /// Best-effort extra-compact insert (ok to miss if a writer holds `inner`).
    pub fn try_note_extra_compact(&self, tx: &Transaction) -> bool {
        self.try_note_extra_compact_txs(std::iter::once(tx))
    }

    /// Best-effort extra-compact insert of compact-seen / `blocktxn` bodies.
    pub fn try_note_extra_compact_txs<'a>(
        &self,
        txs: impl IntoIterator<Item = &'a Transaction>,
    ) -> bool {
        let Ok(mut g) = self.inner.try_write() else {
            return false;
        };
        for tx in txs {
            g.remember_extra_compact(tx);
        }
        true
    }

    /// Wtxid membership of `txs` in live graph / extra-compact / orphanage.
    ///
    /// `None` if a writer holds `inner`.
    pub fn try_cmpct_fill_sets(
        &self,
        txs: &[Transaction],
    ) -> Option<crate::compact::CmpctFillSets> {
        use bitcoin::Wtxid;
        let g = self.inner.try_read().ok()?;
        let extra: std::collections::HashSet<Wtxid> =
            g.extra_compact_txs().map(|tx| tx.compute_wtxid()).collect();
        let mut sets = crate::compact::CmpctFillSets::default();
        for tx in txs {
            let w = tx.compute_wtxid();
            if g.graph.contains_wtxid(&w) {
                sets.mempool.insert(w);
            } else if extra.contains(&w) {
                sets.extra.insert(w);
            } else if g.orphanage.contains_wtxid(&w) {
                sets.orphan.insert(w);
            }
        }
        Some(sets)
    }

    /// Ancestor/descendant counts and vsize/fee sums (no live-set scan).
    pub fn graph_stats(&self, txid: &Txid) -> Option<crate::MempoolGraphStats> {
        self.lock_read().graph.graph_stats(txid)
    }

    /// Graph stats plus modified ancestor/descendant/chunk fees (sat).
    pub fn graph_fees_modified(
        &self,
        txid: &Txid,
    ) -> Option<(crate::MempoolGraphStats, i64, i64, i64, u64)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let d = |id: Txid| deltas.get(&id).copied().unwrap_or(0);
        let g = self.lock_read();
        let (stats, a_mod, d_mod) = g.graph.graph_stats_delta(txid, d)?;
        let (chunk_fee, chunk_w, _) = g.graph.chunk_of(txid, d)?;
        Some((stats, a_mod, d_mod, chunk_fee, chunk_w))
    }

    /// Core `-limitclustercount` and `-limitclustersize` (count, vbytes).
    pub fn cluster_limits(&self) -> (u32, u64) {
        let g = self.lock_read();
        (
            g.graph.cluster_count_limit() as u32,
            g.graph.cluster_vsize_limit(),
        )
    }

    /// Defaults when no hub is attached (`MAX_CLUSTER_COUNT`, `MAX_CLUSTER_VSIZE`).
    pub fn default_cluster_limits() -> (u32, u64) {
        (
            rbitcoin_mempool::MAX_CLUSTER_COUNT as u32,
            rbitcoin_mempool::MAX_CLUSTER_VSIZE,
        )
    }

    /// Cluster count/size overlay (`None` = keep default).
    pub fn set_cluster_limits(&self, count: Option<u32>, size_kvb: Option<u32>) {
        self.lock_write().set_cluster_limits(count, size_kvb);
    }

    /// Core `-bytespersigop` overlay: `0` disables sigop-adjusted sizing.
    pub fn set_bytes_per_sigop(&self, bytes_per_sigop: u64) {
        self.lock_write().set_bytes_per_sigop(bytes_per_sigop);
    }

    /// Weight budget in WU.
    pub fn set_max_weight(&self, wu: u64) {
        self.lock_write().max_weight = wu;
    }

    /// Min-relay overlay (sat/kvB). `0` admits any non-negative fee.
    pub fn set_min_relay_sat_kvb(&self, sat_kvb: u64) {
        self.min_relay_sat_kvb.store(sat_kvb, Ordering::Release);
        self.lock_write().set_min_relay_sat_kvb(sat_kvb);
        self.publish_fee_floor();
    }

    pub fn min_relay_sat_kvb(&self) -> u64 {
        self.min_relay_sat_kvb.load(Ordering::Acquire)
    }

    /// Core `IsRBFOptIn` for a live tx: it or an in-mempool ancestor has an
    /// input sequence at or below `0xfffffffd`. Full RBF replaces either way.
    /// `false` when `txid` is not live.
    pub fn signals_bip125(&self, txid: &Txid) -> bool {
        let g = self.lock_read();
        let signals = |id: &Txid| g.get_tx(id).is_some_and(Transaction::is_explicitly_rbf);
        if signals(txid) {
            return true;
        }
        g.graph
            .ancestor_set(txid)
            .is_some_and(|ancestors| ancestors.iter().any(signals))
    }

    /// In-mempool ancestors of `txid`, **excluding** itself (Core RPC).
    pub fn ancestor_txids(&self, txid: &Txid) -> Option<Vec<Txid>> {
        let g = self.lock_read();
        let mut set = g.graph.ancestor_set(txid)?;
        set.remove(txid);
        Some(set.into_iter().collect())
    }

    /// In-mempool descendants of `txid`, **excluding** itself (Core RPC).
    pub fn descendant_txids(&self, txid: &Txid) -> Option<Vec<Txid>> {
        let g = self.lock_read();
        let mut set = g.graph.descendant_set(txid)?;
        set.remove(txid);
        Some(set.into_iter().collect())
    }

    pub fn wtxid_of(&self, txid: &Txid) -> Option<bitcoin::Wtxid> {
        self.lock_read().graph.get(txid).map(|e| e.wtxid)
    }

    /// True if `txs` plus in-mempool parents would exceed cluster count/size.
    pub fn package_would_exceed_cluster(&self, txs: &[bitcoin::Transaction]) -> bool {
        if txs.is_empty() {
            return false;
        }
        let pkg: std::collections::HashSet<Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let g = self.lock_read();
        let mut parents = std::collections::BTreeSet::new();
        let mut extra_w = 0u64;
        for tx in txs {
            extra_w = extra_w.saturating_add(tx.weight().to_wu());
            for inp in &tx.input {
                let pid = inp.previous_output.txid;
                if !pkg.contains(&pid) && g.graph.contains(&pid) {
                    parents.insert(pid);
                }
            }
        }
        g.graph.cluster_would_exceed(&parents, txs.len(), extra_w)
    }

    /// Direct in-mempool parents and children (`depends` / `spentby`).
    pub fn depends_spentby(&self, txid: &Txid) -> Option<(Vec<Txid>, Vec<Txid>)> {
        let g = self.lock_read();
        let e = g.graph.get(txid)?;
        Some((
            e.parents.iter().copied().collect(),
            e.children.iter().copied().collect(),
        ))
    }

    /// Prefix-maximal mining chunks as `{weight, fee}` points (decreasing feerate).
    pub fn feerate_diagram(&self) -> Vec<(u64, i64)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let d = |id: Txid| deltas.get(&id).copied().unwrap_or(0);
        let g = self.lock_read();
        let mut scored: Vec<(u64, i64, u64)> = Vec::new();
        for ch in g.graph.mining_chunks_for_delta(&d) {
            let ids: std::collections::BTreeSet<_> = ch.txids.iter().copied().collect();
            let fee = g.graph.set_modified_fee(&ids, &d);
            if fee <= 0 {
                continue;
            }
            let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee as u64, ch.weight);
            scored.push((rate, fee, ch.weight));
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        scored.into_iter().map(|(_, fee, w)| (w, fee)).collect()
    }

    /// Live mempool spender of `op`, if any.
    pub fn spending_txid(&self, op: &OutPoint) -> Option<Txid> {
        self.lock_read().graph.conflict_txid(op)
    }

    /// Sequential submitpackage: keep successes, then package-evaluate
    /// min-relay / missing-input remainders (Core `AcceptPackage`).
    ///
    /// Trim runs once at the end. A tx admitted on its own reports `fee_with =
    /// None`. A tx that only cleared the fee floor inside the remainder reports
    /// that remainder, in package order.
    pub fn submit_package_rpc(&self, txs: &[Transaction]) -> Vec<SubmitPackageRow> {
        self.submit_package_rpc_eval(txs, true)
    }

    /// Same as [`Self::submit_package_rpc`]. `package_eval` false keeps each
    /// individual result: an RPC `maxfeerate` miss must not be waived by the
    /// child-with-parents feerate (`rpc_packages.py`).
    pub fn submit_package_rpc_eval(
        &self,
        txs: &[Transaction],
        package_eval: bool,
    ) -> Vec<SubmitPackageRow> {
        let mut out: Vec<Result<AcceptResult, AcceptError>> =
            txs.iter().map(|tx| self.accept_tx_defer_trim(tx)).collect();
        let rest: Vec<Transaction> = txs
            .iter()
            .zip(out.iter())
            .filter(|(tx, r)| {
                r.as_ref().err().is_some_and(package_rpc_retry)
                    && !self.contains(&tx.compute_txid())
            })
            .map(|(tx, _)| tx.clone())
            .collect();
        let mut admitted: Vec<Txid> = out
            .iter()
            .filter_map(|r| r.as_ref().ok().map(|r| r.txid))
            .collect();
        if package_eval && rest.len() >= 2 {
            match self.admit_package(&rest) {
                Ok(accepted) => admitted.extend(accepted.iter().map(|r| r.txid)),
                Err(AcceptError::Policy("mempool full")) => {
                    let rest_ids: std::collections::BTreeSet<Txid> =
                        rest.iter().map(|t| t.compute_txid()).collect();
                    for (tx, slot) in txs.iter().zip(out.iter_mut()) {
                        if package_full_slot(rest_ids.contains(&tx.compute_txid()), slot.is_err()) {
                            *slot = Err(AcceptError::Policy("mempool full"));
                        }
                    }
                }
                Err(_) => {}
            }
        }
        self.trim_over_budget();
        self.kick_isolated_if_live(&admitted);
        let package_kept =
            rest.len() >= 2 && rest.iter().all(|tx| self.try_contains(&tx.compute_txid()));
        let fee_with = package_kept.then(|| rest.iter().map(|tx| tx.compute_txid()).collect());
        let mut rows = Vec::with_capacity(txs.len());
        for (tx, mut slot) in txs.iter().zip(out) {
            let id = tx.compute_txid();
            let in_package = fee_with
                .as_ref()
                .is_some_and(|ids: &Vec<Txid>| ids.contains(&id));
            if self.try_contains(&id) {
                if let Some(mut ok) = self.live_accept_result(&id) {
                    // `live_accept_result` only rebuilds fee and weight. The
                    // individual admit already named who it replaced.
                    if let Ok(prev) = &slot {
                        ok.replaced = prev.replaced.clone();
                        ok.replaced_scripthashes = prev.replaced_scripthashes.clone();
                        ok.replaced_txs = prev.replaced_txs.clone();
                    }
                    slot = Ok(ok);
                }
            } else if slot.is_ok() {
                slot = Err(AcceptError::Policy("mempool full"));
            }
            rows.push(SubmitPackageRow {
                result: slot,
                fee_with: in_package.then(|| fee_with.clone().unwrap_or_default()),
            });
        }
        rows
    }

    /// Core `LimitMempoolSize` after a package: no member is protected.
    #[doc(hidden)]
    pub fn trim_over_budget(&self) {
        let gone = {
            let mut g = self.lock_write();
            g.evict_to_budget(None).unwrap_or_default()
        };
        self.unindex_evicted(&gone);
    }

    #[doc(hidden)]
    pub fn live_accept_result(&self, txid: &Txid) -> Option<AcceptResult> {
        let (txid, fee_sat, weight, slot) = {
            let g = self.lock_read();
            let e = g.graph.get(txid)?;
            (
                e.txid,
                e.fee_sat,
                e.adjusted_weight(g.graph.bytes_per_sigop()),
                e.slot,
            )
        };
        Some(AcceptResult {
            txid,
            fee_sat,
            weight,
            slot,
            accept_secs: self
                .accept_time_txid(&txid)
                .unwrap_or_else(|| self.relay_now_secs()),
            replaced: Vec::new(),
            replaced_scripthashes: Vec::new(),
            replaced_txs: Vec::new(),
            replaced_accept_secs: Default::default(),
            replaced_trust: Vec::new(),
            evicted: Vec::new(),
        })
    }

    #[allow(clippy::type_complexity)] // cluster RPC parts: adjusted weight, member count, chunks
    /// `getmempoolcluster` payload from the live graph (weights sigop-adjusted).
    pub fn cluster_rpc(&self, txid: &Txid) -> Option<(u64, usize, Vec<(i64, u64, Vec<Txid>)>)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let d = |id: Txid| deltas.get(&id).copied().unwrap_or(0);
        let g = self.lock_read();
        let c = g.graph.cluster_of_delta(txid, &d)?;
        let chunks: Vec<_> = c
            .chunks
            .iter()
            .map(|ch| {
                let ids: std::collections::BTreeSet<_> = ch.txids.iter().copied().collect();
                let fee = g.graph.set_modified_fee(&ids, &d);
                (fee, ch.weight, ch.txids.clone())
            })
            .collect();
        // Core `clusterweight` is sigop-adjusted; `total_weight` is the raw
        // cluster-limit basis, chunk weights are adjusted.
        let adjusted = chunks.iter().fold(0u64, |w, ch| w.saturating_add(ch.1));
        Some((adjusted, c.members.len(), chunks))
    }

    /// `sendrawtransaction` origin: rebroadcast until a peer getdata's it.
    pub fn note_unbroadcast(&self, txid: Txid) {
        let mut u = self.unbroadcast.lock().unwrap();
        u.insert(txid);
        persist_unbroadcast_file(&self.dir, &u);
    }

    fn kick_isolated(&self, txid: &Txid) {
        if self.isolated_broadcast() && self.local_origin.lock().unwrap().queue(txid) {
            self.isolated_wake.notify_one();
        }
    }

    /// Mark `txid` local origin and queue it for the isolated loop without an
    /// admit. Tests only: a txid the loop must skip.
    #[doc(hidden)]
    pub fn queue_isolated(&self, txid: Txid) {
        self.local_origin.lock().unwrap().mark(txid);
        self.kick_isolated(&txid);
    }

    /// How many txids were ever queued for the isolated loop.
    #[doc(hidden)]
    pub fn isolated_queued(&self) -> u64 {
        self.local_origin.lock().unwrap().next
    }

    /// The oldest local tx waiting for isolated broadcast, and how many wait
    /// behind it. Each queued tx is returned once, and only while it is in
    /// the mempool.
    pub async fn next_isolated(&self) -> (Txid, usize) {
        loop {
            if let Some(next) = self.local_origin.lock().unwrap().take() {
                return next;
            }
            // A `notify_one` with no waiter leaves a permit, so a queue
            // between `take` and here still wakes this await.
            self.isolated_wake.notified().await;
        }
    }

    pub fn is_local_origin(&self, txid: &Txid) -> bool {
        self.local_origin.lock().unwrap().txs.contains_key(txid)
    }

    pub fn set_isolated_broadcast(&self, on: bool) {
        self.isolated_broadcast.store(on, Ordering::Relaxed);
    }

    /// One finished isolated-broadcast lap. The counter is the wait.
    #[doc(hidden)]
    pub fn note_isolated_lap(&self, kind: IsolatedLap) {
        let slot = match kind {
            IsolatedLap::SkippedUnknown => &self.isolated_skipped_unknown,
            IsolatedLap::Lagged => &self.isolated_lagged,
            IsolatedLap::NoTargets => &self.isolated_no_targets,
        };
        slot.fetch_add(1, Ordering::Release);
        self.isolated_lap.notify_one();
    }

    /// How many isolated-broadcast laps of each kind have finished.
    #[doc(hidden)]
    pub fn isolated_laps(&self) -> IsolatedLapCounts {
        IsolatedLapCounts {
            skipped_unknown: self.isolated_skipped_unknown.load(Ordering::Acquire),
            lagged: self.isolated_lagged.load(Ordering::Acquire),
            no_targets: self.isolated_no_targets.load(Ordering::Acquire),
        }
    }

    /// Wakes after [`Self::note_isolated_lap`]. A permit sticks if the waiter
    /// has not armed yet.
    #[doc(hidden)]
    pub fn isolated_lap_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.isolated_lap.notified()
    }

    pub fn isolated_broadcast(&self) -> bool {
        self.isolated_broadcast.load(Ordering::Relaxed)
    }

    pub fn skip_standing_inv(&self, txid: &Txid) -> bool {
        self.isolated_broadcast() && self.is_local_origin(txid)
    }

    /// Peer getdata served this txid — it is no longer unbroadcast.
    pub fn mark_broadcast(&self, txid: &Txid) {
        let mut u = self.unbroadcast.lock().unwrap();
        if u.remove(txid) {
            persist_unbroadcast_file(&self.dir, &u);
        }
    }

    /// Re-INV still-unbroadcast local txs (15m due-now).
    pub fn rebroadcast_unbroadcast(&self) {
        let ids: Vec<Txid> = self.unbroadcast.lock().unwrap().iter().copied().collect();
        for txid in ids {
            if !self.try_contains(&txid) {
                continue;
            }
            let _ = self.announce.send(MempoolAnnounce {
                txid,
                replaced: Vec::new(),
                replaced_scripthashes: Vec::new(),
                scripthashes: Vec::new(),
            });
            self.meter_announce.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many locally submitted txs have not been requested by a peer.
    pub fn unbroadcast_count(&self) -> u64 {
        self.unbroadcast.lock().unwrap().len() as u64
    }

    /// Whether this live tx was submitted locally and is still unbroadcast.
    pub fn is_unbroadcast(&self, txid: &Txid) -> bool {
        self.unbroadcast.lock().unwrap().contains(txid)
    }

    /// True if a live mempool tx spends `op` (RBF conflict map; no body load).
    pub fn spends_outpoint(&self, op: &OutPoint) -> bool {
        self.lock_read().graph.conflict_txid(op).is_some()
    }

    /// Outpoints spent by any live mempool transaction (confirmed or mempool parents).
    ///
    /// Uses the RBF conflict map — no live-body walk.
    pub fn spent_outpoints(&self) -> std::collections::HashSet<OutPoint> {
        let g = self.lock_read();
        g.graph.conflict_outpoints().collect()
    }

    /// Electrum `blockchain.scripthash.get_mempool` rows for `scripthash` (internal order).
    pub fn scripthash_mempool(&self, scripthash: &[u8; 32]) -> Vec<ElectrumMempoolItem> {
        let want: Vec<Txid> = self.sh_index.lock().unwrap().txs_for(scripthash).collect();
        if want.is_empty() {
            return Vec::new();
        }
        let g = self.lock_read();
        let mut out = Vec::new();
        for txid in want {
            let Some(e) = g.graph.get(&txid) else {
                continue;
            };
            let Some(tx) = g.get_tx(&txid) else { continue };
            let mut height = 0i64;
            for inp in &tx.input {
                if g.graph.contains(&inp.previous_output.txid) {
                    height = -1;
                    break;
                }
            }
            out.push(ElectrumMempoolItem {
                txid: txid.to_byte_array(),
                height,
                fee: e.fee_sat as i64,
            });
        }
        out.sort_by_key(|a| a.txid);
        out
    }

    /// `true` when `txid` is in the live scripthash index for `scripthash`.
    /// The index only: no graph walk and no tx body.
    pub fn scripthash_indexes_tx(&self, scripthash: &[u8; 32], txid: &Txid) -> bool {
        self.sh_index
            .lock()
            .unwrap()
            .by_sh
            .get(scripthash)
            .is_some_and(|set| set.contains(txid))
    }

    /// Live `(txid, fee_sat)` for `scripthash`, same membership and txid order
    /// as [`Self::scripthash_mempool`]. A graph entry with no body is skipped.
    /// Bodies are not cloned.
    pub fn scripthash_mempool_fees(&self, scripthash: &[u8; 32]) -> Vec<([u8; 32], i64)> {
        let want: Vec<Txid> = self.sh_index.lock().unwrap().txs_for(scripthash).collect();
        if want.is_empty() {
            return Vec::new();
        }
        let g = self.lock_read();
        let mut out = Vec::new();
        for txid in want {
            let Some(e) = g.graph.get(&txid) else {
                continue;
            };
            if g.get_tx(&txid).is_none() {
                continue;
            }
            out.push((txid.to_byte_array(), e.fee_sat as i64));
        }
        out.sort_by_key(|row| row.0);
        out
    }

    /// Unconfirmed delta for Electrum balance (sats): +mempool outputs − spent confirmed.
    ///
    /// Hides a live entry only when it is confirmed-strong on the tip at a
    /// height [`Query::sh_visible_through_height`](rbitcoin_query::Query::sh_visible_through_height)
    /// already covers. A leftover after IBD or `-blocksonly` (`remove_for_block`
    /// is a no-op while relay is off) then cannot double-count once confirmed
    /// history includes that block. A tx the chain already has, but that view
    /// does not, stays here. Its inputs are already spent in the chain UTXO
    /// set, so those values come from the parent output instead. A parent
    /// that is still in the pool is the same case once the view covers the
    /// parent and not this spend.
    ///
    /// Uses [`MempoolShIndex`] (same as `scripthash_mempool`). A full-graph walk
    /// plus chain `get_txout` per input is ~1.5 s per empty Cake key on a live
    /// mainnet mempool.
    pub fn scripthash_unconfirmed_delta(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<i64, rbitcoin_query::QueryError> {
        use rbitcoin_store::script_hash;
        let want: Vec<Txid> = self.sh_index.lock().unwrap().txs_for(scripthash).collect();
        if want.is_empty() {
            return Ok(0);
        }
        let visible = self.query.sh_visible_through_height();
        let mut kept = Vec::with_capacity(want.len());
        for txid in want {
            let view = self
                .query
                .sh_visible_confirm(&txid.to_byte_array(), visible)?;
            if view == rbitcoin_query::ShVisibleConfirm::Covered {
                continue;
            }
            kept.push((txid, view == rbitcoin_query::ShVisibleConfirm::Awaiting));
        }
        if kept.is_empty() {
            return Ok(0);
        }
        let g = self.lock_read();
        let mut delta = 0i64;
        let provider = self.utxo_provider();
        for (txid, awaiting) in kept {
            let Some(tx) = g.get_tx(&txid) else { continue };
            for (vout, o) in tx.output.iter().enumerate() {
                if script_hash(o.script_pubkey.as_bytes()) != *scripthash {
                    continue;
                }
                let op = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                if g.graph.mempool_utxo(&op) {
                    delta = delta.saturating_add(o.value.to_sat() as i64);
                }
            }
            for inp in &tx.input {
                let op = inp.previous_output;
                // A parent still in the graph is this delta's own mempool
                // entry, so its output is not confirmed value. The exception
                // is a parent the view already covers: confirmed balance has
                // that output, and an awaiting spend must subtract it. A
                // same-block package is awaiting together and stays skipped.
                if g.graph.creator(&op).is_some() {
                    let parent_covered = awaiting
                        && self
                            .query
                            .sh_visible_confirm(&op.txid.to_byte_array(), visible)?
                            == rbitcoin_query::ShVisibleConfirm::Covered;
                    if !parent_covered {
                        continue;
                    }
                }
                self.meter_delta_prevouts.fetch_add(1, Ordering::Relaxed);
                if let Some(txout) = provider.get_txout(&op) {
                    if script_hash(txout.script_pubkey.as_bytes()) == *scripthash {
                        delta = delta.saturating_sub(txout.value.to_sat() as i64);
                    }
                    continue;
                }
                if !awaiting {
                    continue;
                }
                let parent = op.txid.to_byte_array();
                let Some(fk) = self.query.tx_fk_by_txid_tip(&parent)? else {
                    continue;
                };
                let out = match self.query.tx_output_at_fk(fk, op.vout) {
                    Ok(out) => out,
                    Err(rbitcoin_store::StoreError::NotFound) => continue,
                    Err(e) => return Err(e),
                };
                if script_hash(&out.script) == *scripthash {
                    delta = delta.saturating_sub(out.value as i64);
                }
            }
        }
        Ok(delta)
    }

    /// Block weight (WU) used for inclusion-frontier depth.
    pub const BLOCK_WEIGHT_WU: u64 = 4_000_000;

    /// Product default: **10-minute inclusion** ≈ next 1 block of weight
    /// (see `docs/mempool-fee-estimation.md`).
    pub const DEFAULT_HORIZON_BLOCKS: u32 = 1;

    /// Fee histogram buckets for Electrum: `[[feerate_sat_per_kvb, vsize], ...]`
    /// descending rate, using **published** mining-chunk rates (same refresh as fees).
    pub fn fee_histogram(&self) -> Vec<(u64, u64)> {
        self.maybe_refresh_fee_snapshot();
        self.fee_snapshot.load().histogram()
    }

    /// Standard / target-depth fee in BTC/kB (Engine v2 when flow meter warm).
    ///
    /// **Default product answer is 10-minute inclusion** (`target_blocks` 0 →
    /// depth of [`Self::DEFAULT_HORIZON_BLOCKS`] blocks).
    ///
    /// **Non-blocking vs accept:** returns from a **published snapshot** (Arc).
    /// Graph linearize runs only on dirty/stale singleflight **refresh** (≤~1 s
    /// stale; one `mining_chunks` per refresh for all depths). Request path does
    /// not hold the hub lock across multi-pass walks. The answer is at least
    /// the live `mempoolminfee`, read under a short read lock.
    pub fn estimate_fee_btc_per_kb(&self, target_blocks: u32) -> f64 {
        self.maybe_refresh_fee_snapshot();
        let depth = Self::fee_depth(target_blocks);
        self.fee_snapshot
            .load()
            .rate_btc_per_kb(depth, self.mempool_min_fee_sat_kvb())
    }

    /// Esplora `/fee-estimates` targets in one Arc load (+ optional refresh):
    /// blocks 1 through 25, then 144, 504, and 1008. Targets with no rate are
    /// left out.
    pub fn fee_estimates_btc_per_kb(&self) -> Vec<(u32, f64)> {
        self.maybe_refresh_fee_snapshot();
        let snap = self.fee_snapshot.load_full();
        let floor = self.mempool_min_fee_sat_kvb();
        (1..=25)
            .chain([144, 504, 1008])
            .filter_map(|d| {
                let rate = snap.rate_btc_per_kb(d, floor);
                (rate >= 0.0).then_some((d, rate))
            })
            .collect()
    }

    /// Weight (WU) ranking strictly above `rate_sat_per_kvb` (published chunks).
    pub fn weight_above_feerate(&self, rate_sat_per_kvb: u64) -> u64 {
        self.maybe_refresh_fee_snapshot();
        weight_above_from_chunks(&self.fee_snapshot.load().chunks, rate_sat_per_kvb)
    }

    /// Relay fee in BTC/kB (Libre 0.1 sat/vB = 100 sat/kvB).
    pub fn relay_fee_btc_per_kb() -> f64 {
        rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB as f64 / 100_000_000.0
    }

    /// p90 of the 64 newest confirmed entries' own feerates (sat/kvB), at
    /// least min relay. Filled in block order from `remove_for_block` when
    /// live entries leave the pool.
    #[doc(hidden)]
    pub fn confirm_memory_floor_sat_per_kvb(&self) -> Option<u64> {
        let mem = self.confirm_feerate_memory.lock().unwrap();
        if mem.is_empty() {
            return None;
        }
        let v: Vec<u64> = mem.iter().copied().collect();
        percentile_sat(v, 90)
            .map(|r| r.max(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB))
    }

    #[doc(hidden)]
    pub fn push_confirm_memory(&self, rate_sat_per_kvb: u64) {
        const CAP: usize = 64;
        let mut mem = self.confirm_feerate_memory.lock().unwrap();
        mem.push_back(rate_sat_per_kvb.max(1));
        while mem.len() > CAP {
            mem.pop_front();
        }
    }

    /// A height's hurdle and block hash, from `txstat` alone.
    #[doc(hidden)]
    pub fn txstat_fee_block_from_chain(
        &self,
        height: Height,
    ) -> Result<Option<(HistoricalFeeBlock, [u8; 32])>, String> {
        let block = self
            .query
            .block_txstat_rows(height)
            .map_err(|e| e.to_string())?;
        Ok(block.map(|block| {
            let p10_sat_kvb = block.rows.as_deref().and_then(|rows| {
                rbitcoin_mempool::block_individual_p10_sat_kvb(
                    rows,
                    rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
                )
            });
            let fee_block = HistoricalFeeBlock {
                p10_sat_kvb,
                txstat_bytes: block.txstat_bytes,
            };
            (fee_block, block.hash)
        }))
    }

    /// Record a newly connected block in fee history, read from the chain so it
    /// counts even when this pool never saw its txs, and journal it.
    pub fn note_block_fee_history(&self, height: Height) {
        let (block, hash) = match self.txstat_fee_block_from_chain(height) {
            Ok(Some((block, hash))) => (block, Some(hash)),
            Ok(None) => (HistoricalFeeBlock::default(), None),
            Err(e) => {
                rbitcoin_log::warn!("mempool: fee history @ {}: {e}", height.0);
                (HistoricalFeeBlock::default(), None)
            }
        };
        let mut journal = self.fee_journal.lock().unwrap();
        self.block_p10_history
            .lock()
            .unwrap()
            .insert(height.0, block, hash);
        if let (Some(j), Some(hash)) = (journal.as_mut(), hash) {
            match fee_history_file::append(&mut j.file, height.0, &block, &hash) {
                Ok(()) => j.since_snapshot += 1,
                Err(e) => {
                    rbitcoin_log::warn!("mempool: fee history journal: {e}");
                    *journal = None;
                }
            }
        }
        if journal
            .as_ref()
            .is_some_and(|j| j.since_snapshot >= fee_history_file::COMPACT_EVERY)
        {
            self.write_fee_history_snapshot(&mut journal);
        }
        drop(journal);
        self.mark_fee_dirty();
    }

    /// Rewrite the snapshot from the held history and start an empty journal.
    #[doc(hidden)]
    pub fn write_fee_history_snapshot(&self, journal: &mut Option<FeeJournal>) {
        let (rows, hashes) = {
            let history = self.block_p10_history.lock().unwrap();
            (history.entries(), history.recent_hashes())
        };
        *journal = match fee_history_file::write_snapshot(&self.dir, &rows, &hashes)
            .and_then(|generation| fee_history_file::start_journal(&self.dir, generation))
        {
            Ok(file) => Some(FeeJournal {
                file,
                since_snapshot: 0,
            }),
            Err(e) => {
                rbitcoin_log::warn!("mempool: fee history snapshot: {e}");
                None
            }
        };
    }

    /// Restore heights from the fee history file up to the newest stored
    /// block hash still on the best chain. Heights a connect already recorded
    /// are kept. Returns how many heights the file supplied.
    #[doc(hidden)]
    pub fn load_fee_history_file(&self) -> u64 {
        let loaded = match fee_history_file::load(&self.dir) {
            Ok(Some(loaded)) => loaded,
            Ok(None) => return 0,
            Err(e) => {
                rbitcoin_log::info!("mempool: fee history file dropped: {e}");
                return 0;
            }
        };
        if let Some(note) = &loaded.journal_note {
            rbitcoin_log::info!("mempool: fee history journal: {note}");
        }
        let mut restored = FeeHistory::new(FEE_HISTORY_TXSTAT_BYTE_BUDGET, FEE_SNAPSHOT_DEPTHS);
        let hashes: HashMap<u32, [u8; 32]> = loaded.hashes.iter().copied().collect();
        for (height, block) in loaded.rows {
            restored.insert(height, block, hashes.get(&height).copied());
        }
        for (height, block, hash) in loaded.journal {
            restored.insert(height, block, Some(hash));
        }
        let on_chain = restored
            .recent_hashes()
            .into_iter()
            .rev()
            .find(|(height, hash)| {
                matches!(
                    self.query.header_at_height(Height(*height)),
                    Ok(Some((_, rec))) if &rec.hash == hash
                )
            });
        let Some((fork, _)) = on_chain else {
            rbitcoin_log::info!(
                "mempool: fee history file dropped: no stored block hash is on the best chain"
            );
            return 0;
        };
        restored.truncate_above(fork);
        let rows = restored.entries();
        let hashes: HashMap<u32, [u8; 32]> = restored.recent_hashes().into_iter().collect();
        let mut live = self.block_p10_history.lock().unwrap();
        for &(height, block) in rows.iter().rev() {
            live.insert_if_absent(height, block, hashes.get(&height).copied());
        }
        rows.len() as u64
    }

    #[doc(hidden)]
    pub fn backfill_fee_history_height(&self, height: u32, stats: &mut FeeHistoryBackfillStats) {
        let held = self.block_p10_history.lock().unwrap().get(height);
        if let Some(block) = held {
            stats.retained_heights = stats.retained_heights.saturating_add(1);
            Self::count_backfill_fee_block(&block, stats);
            return;
        }
        match self.txstat_fee_block_from_chain(Height(height)) {
            Ok(Some((block, hash))) => {
                Self::count_backfill_fee_block(&block, stats);
                self.insert_backfill_fee_block(height, block, Some(hash));
            }
            Ok(None) => {
                stats.skipped_heights = stats.skipped_heights.saturating_add(1);
                self.insert_backfill_fee_block(height, HistoricalFeeBlock::default(), None);
            }
            Err(error) => {
                stats.failed_heights = stats.failed_heights.saturating_add(1);
                stats.first_error.get_or_insert(error);
                self.insert_backfill_fee_block(height, HistoricalFeeBlock::default(), None);
            }
        }
    }

    #[doc(hidden)]
    pub fn count_backfill_fee_block(
        block: &HistoricalFeeBlock,
        stats: &mut FeeHistoryBackfillStats,
    ) {
        stats.txstat_bytes = stats.txstat_bytes.saturating_add(block.txstat_bytes);
        if block.p10_sat_kvb.is_some() {
            stats.valid_samples = stats.valid_samples.saturating_add(1);
        } else {
            stats.skipped_heights = stats.skipped_heights.saturating_add(1);
        }
    }

    #[doc(hidden)]
    pub fn insert_backfill_fee_block(
        &self,
        height: u32,
        block: HistoricalFeeBlock,
        hash: Option<[u8; 32]>,
    ) {
        self.block_p10_history
            .lock()
            .unwrap()
            .insert_if_absent(height, block, hash);
    }

    /// Log when the flow-fullness decile changes or a target's history becomes ready.
    #[doc(hidden)]
    pub fn log_fee_readiness(&self, fullness_decile: u32, history: &HashMap<u32, Option<u64>>) {
        let ready = history.values().filter(|r| r.is_some()).count() as u32;
        // High and low halves never overlap, so `|` and `^` store the same code.
        let code = fullness_decile.wrapping_mul(1u32 << 16).wrapping_add(ready);
        if self.fee_readiness.swap(code, Ordering::Relaxed) != code {
            rbitcoin_log::info!(
                "mempool: fee estimates: flow fullness {fullness_decile}/10, history ready for {ready}/{} targets",
                history.len()
            );
        }
    }

    #[doc(hidden)]
    pub fn log_fee_history_progress(stats: &FeeHistoryBackfillStats, last_progress: &mut Instant) {
        let now = Instant::now();
        if !fee_progress_due(now.duration_since(*last_progress)) {
            return;
        }
        rbitcoin_log::info!(
            "mempool: fee history preload progress: {:.1} MiB / 1024 MiB, {} heights, {} valid samples",
            stats.txstat_bytes as f64 / (1024.0 * 1024.0),
            stats.heights_scanned,
            stats.valid_samples
        );
        *last_progress = now;
    }

    /// Fill historical fee hurdles from the fee history file, then from up to
    /// 1 GiB of recent `txstat.body` rows, and write a fresh snapshot. Reads
    /// no spent data or transaction bodies, and no height already held.
    pub fn backfill_block_fee_history(&self) -> FeeHistoryBackfillStats {
        let Some(tip) = self.query.tip_height() else {
            return FeeHistoryBackfillStats {
                history_exhausted: true,
                ..FeeHistoryBackfillStats::default()
            };
        };
        let mut stats = FeeHistoryBackfillStats {
            tip_height: Some(tip.0),
            ..FeeHistoryBackfillStats::default()
        };
        if self.fee_journal.lock().unwrap().is_none() {
            stats.file_heights = self.load_fee_history_file();
        }
        let mut last_progress = Instant::now();
        for height in (0..=tip.0).rev() {
            if stats.txstat_bytes >= FEE_HISTORY_TXSTAT_BYTE_BUDGET {
                break;
            }
            stats.heights_scanned = stats.heights_scanned.saturating_add(1);
            stats.oldest_height = Some(height);
            self.backfill_fee_history_height(height, &mut stats);
            Self::log_fee_history_progress(&stats, &mut last_progress);
        }
        stats.history_exhausted = fee_history_scan_exhausted(
            stats.txstat_bytes,
            FEE_HISTORY_TXSTAT_BYTE_BUDGET,
            stats.oldest_height,
        );
        let mut journal = self.fee_journal.lock().unwrap();
        self.write_fee_history_snapshot(&mut journal);
        drop(journal);
        let rates = self.block_p10_history.lock().unwrap().rates();
        stats.total_targets = rates.len() as u64;
        stats.ready_targets = rates.values().filter(|r| r.is_some()).count() as u64;
        self.mark_fee_dirty();
        stats
    }
}

/// One Electrum mempool history row.
#[derive(Debug, Clone)]
pub struct ElectrumMempoolItem {
    pub txid: [u8; 32],
    pub height: i64,
    pub fee: i64,
}
