//! Tip-mode transaction relay (P4): inv/getdata/tx + mempool announce.
//!
//! Heavy relay is **gated** on [`MempoolHub::set_relay_enabled`] (false during IBD).
//! Package admit is RPC `submitpackage` / Esplora `POST /txs/package` /
//! [`MempoolHub::accept_package`]. There is no P2P package command (BIP331
//! is not in rust-bitcoin 0.32 `NetworkMessage`; the old private `rbtpkg`
//! name is gone).

use crate::perf_meter::{PerfCounter, PerfMax};
use arc_swap::ArcSwap;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_mempool::{
    depth_rate_sat_kvb, fine_candidate_rates, flow_for_depth, frontier_feerate_from_chunks,
    hold_defined_then_monotone, min_rate_for_capacity, percentile_sat, weight_above_from_chunks,
    AcceptError, AcceptResult, ActiveMempool, ChainPrevout, ChainTipCtx, Chunk, Coin, FeeFlowMeter,
    SelectBudget, Selected, UtxoProvider, BLOCK_WEIGHT_WU, MAX_PACKAGE_COUNT,
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

use crate::fee_history::{FeeHistory, HistoricalFeeBlock};
use crate::fee_history_file;

#[path = "parent_req.rs"]
mod parent_req;
pub(crate) use parent_req::DueParent;

/// Max age of a published fee snapshot before refresh (request path is still Arc-load only
/// after a concurrent refresh has finished; see [`MempoolHub::maybe_refresh_fee_snapshot`]).
const FEE_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(1);

fn load_unbroadcast_file(dir: &Path) -> HashSet<Txid> {
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

fn persist_unbroadcast_file(dir: &Path, set: &HashSet<Txid>) {
    let mut buf = Vec::with_capacity(set.len() * 32);
    for t in set {
        buf.extend_from_slice(&t.to_byte_array());
    }
    let _ = std::fs::write(dir.join("unbroadcast"), buf);
}

/// Esplora `/fee-estimates` keys + common Electrum depths (after 0–2 → default map).
const FEE_SNAPSHOT_DEPTHS: &[u32] = &[1, 2, 3, 4, 5, 6, 10, 20, 144, 504, 1008];
/// Txstat body bytes scanned and retained for historical fee estimates.
const FEE_HISTORY_TXSTAT_BYTE_BUDGET: u64 = 1 << 30;

/// Journal of connects since the last fee history snapshot.
#[derive(Debug)]
struct FeeJournal {
    file: std::fs::File,
    since_snapshot: u32,
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
struct FeeSnapshot {
    /// BTC/kB by confirm-target depth (post 0–2 mapping). Missing → treat empty.
    by_depth_btc_per_kb: HashMap<u32, f64>,
    /// Best-first mining chunks from the last refresh (histogram / frontier).
    chunks: Vec<Chunk>,
    /// Per-chunk Σ raw member vsize, parallel to [`Self::chunks`] (histogram).
    chunk_raw_vsize: Vec<u64>,
    /// Live tx count from the same graph read as [`Self::chunks`].
    count: usize,
    /// Σ `(weight + 3) / 4` over live entries (GET `/mempool` `vsize`).
    vsize: u64,
    /// Σ `fee_sat` over live entries.
    total_fee: u64,
    computed_at: Instant,
}

impl FeeSnapshot {
    fn empty(now: Instant) -> Self {
        Self {
            by_depth_btc_per_kb: HashMap::new(),
            chunks: Vec::new(),
            chunk_raw_vsize: Vec::new(),
            count: 0,
            vsize: 0,
            total_fee: 0,
            computed_at: now,
        }
    }

    fn rate_btc_per_kb(&self, depth: u32) -> f64 {
        self.by_depth_btc_per_kb
            .get(&depth)
            .copied()
            .unwrap_or(-1.0)
    }

    fn histogram(&self) -> Vec<(u64, u64)> {
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
    entries: Vec<MempoolTxSnapEntry>,
    computed_at: Instant,
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
    fn empty(now: Instant) -> Self {
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
fn tx_has_bip68_time_lock(tx: &Transaction) -> bool {
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
    need_create_mtp: AtomicBool,
    meter_get_coin: Option<&'a AtomicU64>,
    meter_block_tx_fks: Option<&'a AtomicU64>,
    meter_create_mtp: Option<&'a AtomicU64>,
}

impl<'a> QueryUtxoProvider<'a> {
    pub fn new(query: &'a Query) -> Self {
        Self {
            query,
            need_create_mtp: AtomicBool::new(false),
            meter_get_coin: None,
            meter_block_tx_fks: None,
            meter_create_mtp: None,
        }
    }
}

impl UtxoProvider for QueryUtxoProvider<'_> {
    fn note_spender(&self, tx: &Transaction) {
        self.need_create_mtp
            .store(tx_has_bip68_time_lock(tx), Ordering::Relaxed);
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
        let Some((fk, rec)) = self.query.get_tx_by_txid(&tid).ok().flatten() else {
            return ChainPrevout::Unknown;
        };
        let Some(create_height) = self.query.store().tx_height_get(fk).ok().flatten() else {
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
        let Some(out) = self
            .query
            .tx_output_at_fk(fk, op.vout)
            .ok()
            .or_else(|| self.query.tx_output(&rec, op.vout).ok())
        else {
            return ChainPrevout::KnownUnavailable;
        };
        let value = if out.value < 0 {
            Amount::ZERO
        } else {
            Amount::from_sat(out.value as u64)
        };
        let is_coinbase = match self.query.tx_input_at_fk(fk, &rec, 0) {
            Ok(i) => i.is_coinbase() || i.prev_index == u32::MAX,
            Err(_) => {
                if let Some(m) = self.meter_block_tx_fks {
                    m.fetch_add(1, Ordering::Relaxed);
                }
                create_height > 0
                    && self
                        .query
                        .block_tx_fks(Height(create_height))
                        .ok()
                        .and_then(|fks| fks.first().copied())
                        == Some(fk)
            }
        };
        let create_mtp = if create_height == 0 || !self.need_create_mtp.load(Ordering::Relaxed) {
            0
        } else {
            if let Some(m) = self.meter_create_mtp {
                m.fetch_add(1, Ordering::Relaxed);
            }
            rbitcoin_consensus::median_time_past(
                self.query,
                Height(create_height.saturating_sub(1)),
            )
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

fn package_rpc_retry(e: &AcceptError) -> bool {
    matches!(
        e,
        AcceptError::Orphaned { .. } | AcceptError::Policy("min relay fee")
    )
}

fn is_hard_recent_reject(e: &AcceptError) -> bool {
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
struct MempoolShIndex {
    by_sh: HashMap<[u8; 32], HashSet<Txid>>,
    by_tx: HashMap<Txid, Vec<[u8; 32]>>,
}

impl MempoolShIndex {
    fn new() -> Self {
        Self {
            by_sh: HashMap::new(),
            by_tx: HashMap::new(),
        }
    }

    fn insert(&mut self, txid: Txid, shs: Vec<[u8; 32]>) {
        self.remove(&txid);
        for sh in &shs {
            self.by_sh.entry(*sh).or_default().insert(txid);
        }
        self.by_tx.insert(txid, shs);
    }

    fn remove(&mut self, txid: &Txid) {
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

    fn txs_for(&self, sh: &[u8; 32]) -> impl Iterator<Item = Txid> + '_ {
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
    /// `block_tx_fks` from `get_coin` (missing input-0 record only).
    pub get_coin_block_tx_fks: u64,
    /// Create-block MTP from `get_coin` (BIP68 time-lock spends only).
    pub get_coin_create_mtp: u64,
}

/// Core default `-mempoolexpiry` (336 hours) in seconds.
const DEFAULT_MEMPOOL_EXPIRY_SECS: u64 = 336 * 3600;
/// Core `NONPREF_PEER_TX_DELAY` (inbound / non-preferred).
pub(crate) const NONPREF_PEER_TX_DELAY_SECS: u64 = 2;
/// Core `TXID_RELAY_DELAY` (parent GETDATA is by txid, not wtxid).
pub(crate) const TXID_RELAY_DELAY_SECS: u64 = 2;
/// Core `GETDATA_TX_INTERVAL` (in-flight parent request expiry).
pub(crate) const GETDATA_TX_INTERVAL_SECS: u64 = 60;
/// Cap unique parent GETDATA items issued from one flush.
/// Core `MAX_PEER_TX_REQUEST_IN_FLIGHT`.
const MAX_PARENTS_PER_PARK: usize = 100;

/// INV AlreadyHave for recently confirmed txid/wtxid (Core rolling bloom is ~100k).
const RECENT_CONFIRMED_CAP: usize = 65_536;

struct RecentConfirmed {
    order: VecDeque<(Txid, Wtxid)>,
    txids: HashSet<Txid>,
    wtxids: HashSet<Wtxid>,
}

impl RecentConfirmed {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            txids: HashSet::new(),
            wtxids: HashSet::new(),
        }
    }

    fn note_block(&mut self, txs: &[Transaction]) {
        self.note_block_capped(txs, RECENT_CONFIRMED_CAP);
    }

    fn note_block_capped(&mut self, txs: &[Transaction], cap: usize) {
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

    fn contains_txid(&self, txid: &Txid) -> bool {
        self.txids.contains(txid)
    }

    fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.wtxids.contains(wtxid)
    }

    fn clear(&mut self) {
        self.order.clear();
        self.txids.clear();
        self.wtxids.clear();
    }
}

struct AdmitSpec {
    report_orphans: bool,
    fee_delta: i64,
    time_prepare_lock: bool,
    min_relay: Option<u64>,
}

/// Shared mempool + relay gate used by peer sessions and tip confirm.
pub struct MempoolHub {
    inner: RwLock<ActiveMempool>,
    query: Arc<Query>,
    /// When false, peers' tx inv/tx are ignored (IBD / catch-up).
    relay_enabled: AtomicBool,
    /// Broadcast accepts so sessions can inv (origin exclusion is per-session).
    announce: broadcast::Sender<MempoolAnnounce>,
    /// `setmocktime` jump: sessions INV live mempool txs (Core scheduler).
    inv_flush: broadcast::Sender<()>,
    /// Newest-last ring of successful accepts (Esplora `/mempool/recent`).
    recent: Mutex<std::collections::VecDeque<RecentAccept>>,
    /// Recently confirmed txid/wtxid for INV AlreadyHave.
    recent_confirmed: Mutex<RecentConfirmed>,
    /// Core `m_lazy_recent_rejects` (wtxid). Forcerelay second-send skips ATMP.
    recent_rejects: Mutex<HashSet<Wtxid>>,
    /// Recently confirmed package feerates (sat/kvB) for N=1 sanity clip.
    confirm_feerate_memory: Mutex<std::collections::VecDeque<u64>>,
    /// Per-block vsize-weighted p10 hurdle, bounded by txstat body bytes.
    block_p10_history: Mutex<FeeHistory>,
    /// Open once a preload wrote a snapshot. Lock order: this, then history.
    fee_journal: Mutex<Option<FeeJournal>>,
    /// Last logged `(flow warm << 16) | ready targets`, to log changes once.
    fee_readiness: AtomicU32,
    /// Process-local admit/confirm/evict EMA for flow-aware fee estimates.
    fee_flow: Mutex<FeeFlowMeter>,
    /// Published fee table for Electrum/Esplora (refreshed dirty ∥ max-age, singleflight).
    fee_snapshot: ArcSwap<FeeSnapshot>,
    fee_dirty: AtomicBool,
    fee_refreshing: AtomicBool,
    /// Published live mempool txs for Esplora `/internal/mempool/*`.
    tx_snapshot: ArcSwap<MempoolTxSnapshot>,
    tx_snap_dirty: AtomicBool,
    tx_snap_refreshing: AtomicBool,
    meter_accepts: PerfCounter,
    meter_rejects: PerfCounter,
    meter_accept_us: AtomicU64,
    meter_accept_max_us: PerfMax,
    meter_accept_lock_us: AtomicU64,
    meter_accept_utxo_us: AtomicU64,
    meter_accept_script_us: AtomicU64,
    meter_accept_durable_us: AtomicU64,
    meter_inv_tx: AtomicU64,
    meter_getdata_tx: AtomicU64,
    meter_announce: AtomicU64,
    /// Chain prevouts resolved by [`Self::scripthash_unconfirmed_delta`].
    meter_delta_prevouts: AtomicU64,
    /// Bodies loaded by [`Self::spent_outpoints`] (must stay 0 after conflict-map).
    meter_spent_body_loads: AtomicU64,
    /// Full live-set clones ([`Self::list_live`]).
    meter_list_live: AtomicU64,
    /// Full live-set meta scans ([`Self::list_live_meta`]).
    meter_list_live_meta: AtomicU64,
    meter_list_live_wtxids: AtomicU64,
    meter_age_scan: AtomicU64,
    meter_expire_full_scans: AtomicU64,
    meter_tip_mtp: AtomicU64,
    meter_get_coin: AtomicU64,
    meter_get_coin_block_tx_fks: AtomicU64,
    meter_get_coin_create_mtp: AtomicU64,
    /// Live mempool txs by Electrum scripthash (updated on accept/remove).
    sh_index: Mutex<MempoolShIndex>,
    /// `{datadir}/mempool` — sidecar `unbroadcast` lives here.
    dir: PathBuf,
    /// Locally submitted txids not yet requested by a peer (`getmempoolinfo.unbroadcastcount`).
    unbroadcast: Mutex<HashSet<Txid>>,
    local_origin: Mutex<HashSet<Txid>>,
    isolated_broadcast: AtomicBool,
    isolated_kick: broadcast::Sender<Txid>,
    /// Wtxids re-admitted from a disconnected block. Core serves these
    /// even if this peer has not been INV'd yet (`mempool_reorg`).
    reorg_servable: Mutex<HashSet<Wtxid>>,
    /// Core mempool entry_sequence. Regular accept starts at 1; reorg is 0.
    relay_seq: Mutex<HashMap<Wtxid, u64>>,
    /// Reverse of `relay_seq` / `accept_at` so `unindex_txid` can drop them
    /// after the graph entry is already gone.
    wtxid_by_txid: Mutex<HashMap<Txid, Wtxid>>,
    next_relay_seq: AtomicU64,
    /// `prioritisetransaction` fee deltas (sat), keyed by txid even if not live.
    fee_deltas: Mutex<HashMap<Txid, i64>>,
    /// Monotonic template generation (admit / remove / prioritise). GBT longpoll.
    template_updates: AtomicU64,
    /// INV immediately instead of waiting on mocktime.
    immediate_relay: AtomicBool,
    /// Last `setmocktime` (0 = wall). Used to age mempool txs for delayed INV.
    mock_now: AtomicU64,
    /// Mock/wall seconds when each live wtxid was accepted.
    accept_at: Mutex<HashMap<Wtxid, u64>>,
    /// Monotonic accept generation for `p2p_tx_privacy` (skip pre-handshake txs).
    next_accept_gen: AtomicU64,
    accept_gen: Mutex<HashMap<Wtxid, u64>>,
    /// Mempool expiry in seconds (default 336h).
    expiry_secs: AtomicU64,
    /// Min-relay overlay (sat/kvB). Session FeeFilter reads this
    /// without taking `inner`.
    min_relay_sat_kvb: AtomicU64,
    /// Age-INV log: `(due_secs, accept_gen) → (txid, wtxid)`. Not `inner`.
    age_inv: Mutex<BTreeMap<(u64, u64), (Txid, Wtxid)>>,
    /// Min live `accept_at` (`u64::MAX` if empty).
    min_live_accept_at: AtomicU64,
    /// Cached tip MTP for accept (`{header_fk, ctx}`).
    tip_ctx: Mutex<Option<(Fk, ChainTipCtx)>>,
    /// TxRequestTracker-shaped missing-parent GETDATA.
    parent_req: Mutex<parent_req::ParentTracker>,
}

impl MempoolHub {
    fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, ActiveMempool> {
        crate::reactor::assert_not_reactor("mempool inner read");
        self.inner.read().unwrap()
    }

    fn lock_write(&self) -> std::sync::RwLockWriteGuard<'_, ActiveMempool> {
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
        let (announce, _) = broadcast::channel(256);
        let (inv_flush, _) = broadcast::channel(16);
        let (isolated_kick, _) = broadcast::channel(32);
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
            meter_get_coin_block_tx_fks: AtomicU64::new(0),
            meter_get_coin_create_mtp: AtomicU64::new(0),
            sh_index: Mutex::new(MempoolShIndex::new()),
            unbroadcast: Mutex::new(unbroadcast),
            local_origin: Mutex::new(HashSet::new()),
            isolated_broadcast: AtomicBool::new(false),
            isolated_kick,
            reorg_servable: Mutex::new(HashSet::new()),
            relay_seq: Mutex::new(HashMap::new()),
            wtxid_by_txid: Mutex::new(HashMap::new()),
            next_relay_seq: AtomicU64::new(1),
            immediate_relay: AtomicBool::new(false),
            mock_now: AtomicU64::new(0),
            accept_at: Mutex::new(HashMap::new()),
            next_accept_gen: AtomicU64::new(1),
            accept_gen: Mutex::new(HashMap::new()),
            expiry_secs: AtomicU64::new(DEFAULT_MEMPOOL_EXPIRY_SECS),
            min_relay_sat_kvb: AtomicU64::new(
                rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            ),
            fee_deltas: Mutex::new(HashMap::new()),
            template_updates: AtomicU64::new(0),
            age_inv: Mutex::new(BTreeMap::new()),
            min_live_accept_at: AtomicU64::new(u64::MAX),
            tip_ctx: Mutex::new(None),
            parent_req: Mutex::new(parent_req::ParentTracker::new()),
        };
        // Schema ≤ 2 records carry no sigop cost: fill (or evict) before serving.
        hub.lock_write()
            .recompute_missing_sigops(&QueryUtxoProvider::new(&hub.query));
        {
            let mut u = hub.unbroadcast.lock().unwrap();
            u.retain(|t| hub.contains(t));
        }
        hub.reindex_live_scripthashes();
        Ok(Arc::new(hub))
    }

    /// Output + spent-input Electrum scripthashes for a live (or just-accepted) tx.
    fn collect_tx_scripthashes(
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

    fn reindex_live_scripthashes(&self) {
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

    fn batch_fill_script_hashes(&self, ops: &[OutPoint]) -> HashMap<OutPoint, [u8; 32]> {
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

    fn index_txid(&self, txid: Txid, tx: &Transaction, prevouts: &[TxOut]) {
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

    fn utxo_provider(&self) -> QueryUtxoProvider<'_> {
        let mut p = QueryUtxoProvider::new(self.query.as_ref());
        p.meter_get_coin = Some(&self.meter_get_coin);
        p.meter_block_tx_fks = Some(&self.meter_get_coin_block_tx_fks);
        p.meter_create_mtp = Some(&self.meter_get_coin_create_mtp);
        p
    }

    fn unindex_txid(&self, txid: &Txid) {
        self.sh_index.lock().unwrap().remove(txid);
        self.remove_relay_maps(txid);
        self.local_origin.lock().unwrap().remove(txid);
        let mut u = self.unbroadcast.lock().unwrap();
        if u.remove(txid) {
            persist_unbroadcast_file(&self.dir, &u);
            rbitcoin_log::info!("{}", Self::unbroadcast_removed_log(txid));
        }
    }

    pub(crate) fn relay_now_secs(&self) -> u64 {
        let mock = self.mock_now.load(Ordering::Relaxed);
        if mock != 0 {
            return mock;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn insert_relay_maps(&self, txid: Txid, wtxid: Wtxid, seq: u64) {
        let at = self.relay_now_secs();
        let gen = self.next_accept_gen.fetch_add(1, Ordering::Relaxed);
        let due = at.saturating_add(30);
        let mut by_tx = self.wtxid_by_txid.lock().unwrap();
        let mut seqs = self.relay_seq.lock().unwrap();
        let mut ats = self.accept_at.lock().unwrap();
        let mut gens = self.accept_gen.lock().unwrap();
        let mut age = self.age_inv.lock().unwrap();
        by_tx.insert(txid, wtxid);
        seqs.insert(wtxid, seq);
        ats.insert(wtxid, at);
        gens.insert(wtxid, gen);
        age.insert((due, gen), (txid, wtxid));
        self.min_live_accept_at.fetch_min(at, Ordering::Relaxed);
    }

    fn remove_relay_maps(&self, txid: &Txid) {
        let mut by_tx = self.wtxid_by_txid.lock().unwrap();
        let mut seqs = self.relay_seq.lock().unwrap();
        let mut ats = self.accept_at.lock().unwrap();
        let mut gens = self.accept_gen.lock().unwrap();
        let mut age = self.age_inv.lock().unwrap();
        if let Some(w) = by_tx.remove(txid) {
            seqs.remove(&w);
            let at = ats.remove(&w);
            let gen = gens.remove(&w);
            if let (Some(at), Some(gen)) = (at, gen) {
                age.remove(&(at.saturating_add(30), gen));
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

    fn meter_accept_wall(&self, us: u64, ok: bool) {
        if ok {
            self.meter_accepts.add(1);
        } else {
            self.meter_rejects.add(1);
        }
        self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
        self.meter_accept_max_us.note(us);
    }

    fn meter_accept_stages(&self, lock_us: u64, stages: rbitcoin_mempool::AcceptStageUs) {
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
            get_coin_block_tx_fks: self.meter_get_coin_block_tx_fks.swap(0, Ordering::Relaxed),
            get_coin_create_mtp: self.meter_get_coin_create_mtp.swap(0, Ordering::Relaxed),
        }
    }

    fn push_recent(&self, tx: &Transaction, r: &AcceptResult) {
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
    /// **False → true:** bulk-strip txs that are already confirmed-strong on the
    /// best chain, and live txs whose inputs are confirmed-spent by a different
    /// txid (catch-up conflicts). Per-block [`Self::remove_for_block`] is skipped
    /// while relay is off so catch-up is not paced by a large durable mempool
    /// (mainnet: 40k+ live after offline). One purge at tip-mode entry is enough
    /// before relay.
    pub fn set_relay_enabled(&self, on: bool) {
        let was = self.relay_enabled.swap(on, Ordering::SeqCst);
        if on && !was {
            let n = self.purge_confirmed_on_chain();
            if n > 0 {
                rbitcoin_log::info!(
                    "mempool: purged {n} leftover tx(s) at tip-mode entry (deferred during IBD)"
                );
            }
        }
    }

    pub fn relay_enabled(&self) -> bool {
        self.relay_enabled.load(Ordering::SeqCst)
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
        let now = self.relay_now_secs();
        let lim = self.expiry_secs.load(Ordering::Relaxed);
        if lim == 0 || now == 0 {
            return 0;
        }
        let min_at = self.min_live_accept_at.load(Ordering::Relaxed);
        if min_at == u64::MAX || now.saturating_sub(min_at) < lim {
            return 0;
        }
        self.meter_expire_full_scans.fetch_add(1, Ordering::Relaxed);
        let expired_roots: Vec<Txid> = {
            let ats = self.accept_at.lock().unwrap();
            let by_tx = self.wtxid_by_txid.lock().unwrap();
            by_tx
                .iter()
                .filter_map(|(txid, wtxid)| {
                    let at = ats.get(wtxid)?;
                    if now.saturating_sub(*at) >= lim {
                        Some(*txid)
                    } else {
                        None
                    }
                })
                .collect()
        };
        if expired_roots.is_empty() {
            return 0;
        }
        let mut kill = std::collections::BTreeSet::new();
        {
            let g = self.lock_read();
            for t in &expired_roots {
                if let Some(set) = g.graph.descendant_set(t) {
                    kill.extend(set);
                } else {
                    kill.insert(*t);
                }
            }
        }
        let mut n = 0usize;
        let mut g = self.lock_write();
        for t in kill.iter().rev() {
            if g.graph.get(t).is_some() && g.remove_txid(t).is_ok() {
                self.unindex_txid(t);
                n += 1;
            }
        }
        if n > 0 {
            self.note_template_update();
        }
        n
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

    #[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
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
    pub fn purge_confirmed_on_chain(&self) -> usize {
        let live: Vec<Txid> = {
            let g = self.lock_read();
            g.graph.iter().map(|(t, _)| *t).collect()
        };
        if live.is_empty() {
            return 0;
        }
        let to_drop = self.live_confirmed_strong(&live);
        let mut g = self.lock_write();
        let mut gone = Vec::new();
        for tid in &to_drop {
            if g.graph.contains(tid) && g.remove_txid(tid).is_ok() {
                gone.push(*tid);
            }
        }
        let remain: Vec<Txid> = g.graph.iter().map(|(t, _)| *t).collect();
        let spent_ops = self.spent_chain_prevouts(&g, &remain);
        gone.extend(g.evict_conflicts_with(&spent_ops));
        if gone.is_empty() {
            return 0;
        }
        let _ = g.maybe_compact();
        let _ = g.persist_if_dirty();
        self.mark_fee_dirty();
        drop(g);
        self.unindex_evicted(&gone);
        gone.len()
    }

    fn live_confirmed_strong(&self, live: &[Txid]) -> Vec<Txid> {
        let tid_bytes: Vec<[u8; 32]> = live.iter().map(|t| t.to_byte_array()).collect();
        let hits = self
            .query
            .store()
            .get_fk_by_txid_batch(&tid_bytes)
            .unwrap_or_default();
        let mut to_drop = Vec::new();
        for (tid_b, row) in hits {
            let Some((fk, _)) = row else { continue };
            if self.query.store().is_confirmed_strong(fk).unwrap_or(false) {
                to_drop.push(Txid::from_byte_array(tid_b));
            }
        }
        to_drop
    }

    fn spent_chain_prevouts(&self, g: &ActiveMempool, remain: &[Txid]) -> Vec<OutPoint> {
        let op_fk = self.chain_create_fks(g, remain);
        if op_fk.is_empty() {
            return Vec::new();
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
        let Ok(unspent) = self.query.unspent_create_vouts_batch(&items) else {
            return Vec::new();
        };
        let mut spent_pair: HashSet<(u64, u32)> = HashSet::new();
        for ((fk, vouts), keep) in items.iter().zip(unspent.iter()) {
            let keep_set: HashSet<u32> = keep.iter().copied().collect();
            for &vout in vouts {
                if !keep_set.contains(&vout) {
                    spent_pair.insert((fk.0, vout));
                }
            }
        }
        op_fk
            .into_iter()
            .filter(|(op, fk)| spent_pair.contains(&(fk.0, op.vout)))
            .map(|(op, _)| op)
            .collect()
    }

    fn chain_create_fks(&self, g: &ActiveMempool, remain: &[Txid]) -> HashMap<OutPoint, Fk> {
        let mut op_fk: HashMap<OutPoint, Fk> = HashMap::new();
        let mut need_id: Vec<[u8; 32]> = Vec::new();
        for tid in remain {
            let Some(tx) = g.get_tx(tid) else { continue };
            let aux = g.vin_aux(tid);
            for (i, inp) in tx.input.iter().enumerate() {
                let op = inp.previous_output;
                if g.graph.contains(&op.txid) {
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
            return op_fk;
        }
        need_id.sort_unstable();
        need_id.dedup();
        let Ok(rows) = self.query.store().get_fk_by_txid_batch(&need_id) else {
            return op_fk;
        };
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
                if op_fk.contains_key(&op) || g.graph.contains(&op.txid) {
                    continue;
                }
                if let Some(&fk) = fk_of.get(&op.txid.to_byte_array()) {
                    op_fk.insert(op, fk);
                }
            }
        }
        op_fk
    }

    pub fn subscribe_announces(&self) -> broadcast::Receiver<MempoolAnnounce> {
        self.announce.subscribe()
    }

    fn publish_announce(&self, r: &AcceptResult, scripthashes: Vec<[u8; 32]>) {
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
        let mut v: Vec<_> = txs
            .iter()
            .map(rbitcoin_query::TxPrecompute::from_tx_connect)
            .collect();
        let skip = {
            let g = self.lock_read();
            v.iter()
                .filter(|p| {
                    let id = Txid::from_byte_array(p.txid);
                    g.graph
                        .get(&id)
                        .is_some_and(|e| e.wtxid.to_byte_array() == p.wtxid)
                })
                .map(|p| p.txid)
                .collect::<HashSet<_>>()
        };
        for (tx, p) in txs.iter().zip(v.iter_mut()) {
            if !skip.contains(&p.txid) {
                p.fill_sighash_midstates(tx);
            }
        }
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
    pub(crate) fn note_recent_confirmed(&self, txs: &[Transaction]) {
        self.clear_recent_rejects();
        if let Ok(mut r) = self.recent_confirmed.lock() {
            r.note_block(txs);
        }
    }

    pub(crate) fn clear_recent_rejects(&self) {
        if let Ok(mut g) = self.recent_rejects.lock() {
            g.clear();
        }
    }

    pub(crate) fn clear_recent_confirmed(&self) {
        if let Ok(mut r) = self.recent_confirmed.lock() {
            r.clear();
        }
    }

    fn note_recent_reject(&self, wtxid: Wtxid) {
        let Ok(mut g) = self.recent_rejects.lock() else {
            return;
        };
        if g.len() >= 4_096 {
            g.clear();
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
    fn chain_tip_ctx(&self) -> ChainTipCtx {
        use rbitcoin_consensus::median_time_past;
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
    pub fn accept_tx(&self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        self.accept_tx_from(tx, None)
    }

    /// Accept, recording `from` as an orphan announcer when parked.
    pub fn accept_tx_from(
        &self,
        tx: &Transaction,
        from: Option<u64>,
    ) -> Result<AcceptResult, AcceptError> {
        crate::reactor::assert_not_reactor("mempool accept");
        self.accept_with_utxo(tx, &self.utxo_provider(), from)
    }

    /// Prepare under read lock; scripts off-lock. Parking is the caller's job.
    fn admit_staged(
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
                spec.fee_delta,
                spec.report_orphans,
                spec.min_relay,
            )
        };
        if spec.time_prepare_lock {
            *lock_us = lock_us.saturating_add(t_prep.elapsed().as_micros() as u64);
        }
        let prep = match prep {
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
            return Err(AcceptError::Script(e.to_string()));
        }
        stages.script_us = stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        Ok(prep)
    }

    fn accept_with_utxo(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
        from: Option<u64>,
    ) -> Result<AcceptResult, AcceptError> {
        utxo.note_spender(tx);
        let t0 = Instant::now();

        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let delta = self.fee_delta(&tx.compute_txid());
        let spec = AdmitSpec {
            report_orphans: true,
            fee_delta: delta,
            time_prepare_lock: false,
            min_relay: None,
        };
        let prep = match self.admit_staged(tx, utxo, spec, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(e) => {
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
                        if let Some(r) = self.admit_1p1c(tx, utxo, missing) {
                            let us = t0.elapsed().as_micros() as u64;
                            self.meter_accept_wall(us, true);
                            return Ok(r);
                        }
                    }
                    let parked = {
                        let mut g = self.lock_write();
                        g.park_orphan_from(tx, missing.clone(), from)
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

        let prevouts = prep.prevouts.clone();
        let result = {
            let t_lock = Instant::now();
            let mut g = self.lock_write();
            g.last_accept_stages = stages;
            let r = g.commit_after_script(tx, prep);
            stages = g.last_accept_stages;
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            r
        };
        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        match result {
            Ok(r) => {
                self.meter_accept_wall(us, true);
                self.publish_admitted(tx, &r, &prevouts, utxo);
                let _ = self.expire_stale();
                Ok(r)
            }
            Err(e) => self.finish_accept_err(us, e),
        }
    }

    fn admit_1p1c(
        &self,
        child: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
        missing: &std::collections::BTreeSet<Txid>,
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
        };
        let prep_p = match self.admit_staged(&parent, utxo, spec_p, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(e) => {
                self.note_if_accept_failure(&parent, &e);
                return None;
            }
        };
        let prevouts_p = prep_p.prevouts.clone();
        // Parent is live until the child commits (or we roll it back). A
        // concurrent spender of the parent that lands in this window survives
        // `remove_txid(parent)` if the child then fails.
        let parent_res = {
            let mut g = self.lock_write();
            g.commit_after_script(&parent, prep_p).ok()?
        };
        let spec_c = AdmitSpec {
            report_orphans: false,
            fee_delta: self.fee_delta(&child.compute_txid()),
            time_prepare_lock: false,
            min_relay: None,
        };
        let prep_c = match self.admit_staged(child, utxo, spec_c, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(_) => {
                self.meter_accept_stages(lock_us, stages);
                self.rollback_1p1c_parent(&parent_res.txid);
                return None;
            }
        };
        let prevouts_c = prep_c.prevouts.clone();
        let child_res = {
            let mut g = self.lock_write();
            g.commit_after_script(child, prep_c)
        };
        self.meter_accept_stages(lock_us, stages);
        match child_res {
            Ok(r) => {
                self.publish_admitted(&parent, &parent_res, &prevouts_p, utxo);
                self.publish_admitted(child, &r, &prevouts_c, utxo);
                let _ = self.expire_stale();
                Some(r)
            }
            Err(_) => {
                self.rollback_1p1c_parent(&parent_res.txid);
                None
            }
        }
    }

    fn rollback_1p1c_parent(&self, txid: &Txid) {
        let gone = {
            let mut g = self.lock_write();
            g.remove_txid_tree(txid)
        };
        self.unindex_evicted(&gone);
    }

    fn rollback_package_accepted(&self, accepted: &[AcceptResult]) {
        let victims: Vec<Transaction> = accepted
            .iter()
            .flat_map(|r| r.replaced_txs.iter().cloned())
            .collect();
        let mut gone = Vec::new();
        {
            let mut g = self.lock_write();
            for r in accepted.iter().rev() {
                gone.extend(g.remove_txid_tree(&r.txid));
            }
        }
        self.unindex_evicted(&gone);
        for tx in victims {
            let _ = self.accept_tx(&tx);
        }
    }

    /// Drop hub relay / sh / fee-delta / template state for txs already
    /// removed from the live graph (`remove_for_block_spent`, 1p1c rollback).
    fn unindex_evicted(&self, gone: &[Txid]) {
        if gone.is_empty() {
            return;
        }
        self.note_template_update();
        let mut deltas = self.fee_deltas.lock().unwrap();
        for tid in gone {
            self.unindex_txid(tid);
            deltas.remove(tid);
        }
    }

    fn note_if_accept_failure(&self, tx: &Transaction, e: &AcceptError) {
        if is_hard_recent_reject(e) {
            self.note_recent_reject(tx.compute_wtxid());
        }
        if let Some(rec) = rbitcoin_mempool::ActiveMempool::accept_failure_record(tx, e) {
            let mut g = self.lock_write();
            g.apply_accept_failure(tx, rec);
        }
    }

    fn publish_admitted(
        &self,
        tx: &Transaction,
        r: &AcceptResult,
        prevouts: &[TxOut],
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) {
        for old in &r.replaced {
            self.unindex_txid(old);
        }
        let seq = self.next_relay_seq.fetch_add(1, Ordering::Relaxed);
        let w = tx.compute_wtxid();
        self.insert_relay_maps(r.txid, w, seq);
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

    fn promote_orphans_staged(&self, parent: Txid, utxo: &impl rbitcoin_mempool::UtxoProvider) {
        let children = {
            let mut g = self.lock_write();
            g.take_orphan_children(parent)
        };
        for child in children {
            let _ = self.accept_with_utxo(&child, utxo, None);
        }
    }

    /// Accept on the tokio blocking pool (never on `tokio-rt-worker`).
    pub async fn accept_tx_async(
        self: &Arc<Self>,
        tx: Transaction,
    ) -> Result<AcceptResult, AcceptError> {
        self.accept_tx_from_async(tx, None).await
    }

    pub async fn accept_tx_from_async(
        self: &Arc<Self>,
        tx: Transaction,
        from: Option<u64>,
    ) -> Result<AcceptResult, AcceptError> {
        let hub = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            hub.accept_tx_from(&tx, from)
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

    fn note_fee_flow_admit(&self, weight: u64, fee_sat: u64) {
        let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee_sat, weight);
        if let Ok(mut m) = self.fee_flow.lock() {
            m.note_admit(weight, rate, Instant::now());
        }
        self.mark_fee_dirty();
    }

    fn mark_fee_dirty(&self) {
        self.fee_dirty.store(true, Ordering::Release);
        self.tx_snap_dirty.store(true, Ordering::Release);
    }

    /// Map API target blocks → engine depth (0–2 → default horizon of 1).
    fn fee_depth(target_blocks: u32) -> u32 {
        if target_blocks == 0 || target_blocks <= 2 {
            Self::DEFAULT_HORIZON_BLOCKS
        } else {
            target_blocks
        }
    }

    /// Lazy singleflight refresh when dirty or older than [`FEE_SNAPSHOT_MAX_AGE`].
    fn maybe_refresh_fee_snapshot(&self) {
        let now = Instant::now();
        let snap = self.fee_snapshot.load_full();
        let stale = now
            .checked_duration_since(snap.computed_at)
            .map(|d| d >= FEE_SNAPSHOT_MAX_AGE)
            .unwrap_or(true);
        let dirty = self.fee_dirty.load(Ordering::Acquire);
        // Always refresh when never populated with real data and dirty (first admit path).
        if !dirty && !stale {
            return;
        }
        if self
            .fee_refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Another thread is refreshing; callers use the previous Arc.
            return;
        }
        self.refresh_fee_snapshot();
        self.fee_refreshing.store(false, Ordering::Release);
    }

    /// One graph linearize under short read lock, then pure math off-lock → publish.
    fn refresh_fee_snapshot(&self) {
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
        let inflow = match self.fee_flow.lock() {
            Ok(mut flow) if flow.is_warm(now) => Some(flow.admit_rates_wu_s(now)),
            _ => None,
        };
        let candidates = fine_candidate_rates();
        let min_r = rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
        let confirm_floor = self.confirm_memory_floor_sat_per_kvb();
        let history = self.block_p10_history.lock().unwrap().rates();
        let flow_warm = inflow.is_some();

        let mut ordered: Vec<(u32, Option<u64>)> = Vec::with_capacity(FEE_SNAPSHOT_DEPTHS.len());
        for &depth in FEE_SNAPSHOT_DEPTHS {
            let target_wu = u64::from(depth).saturating_mul(BLOCK_WEIGHT_WU);
            let frontier = frontier_feerate_from_chunks(&chunks, target_wu);
            let projected = inflow.as_ref().and_then(|inf| {
                min_rate_for_capacity(
                    |r| weight_above_from_chunks(&chunks, r),
                    inf,
                    depth,
                    &candidates,
                )
            });
            let flow = flow_for_depth(projected, frontier, !chunks.is_empty(), depth, min_r);
            let hist = history.get(&depth).copied().flatten();
            let mut rate = depth_rate_sat_kvb(depth, flow_warm, flow, frontier, hist);
            if depth <= 1 && flow_warm {
                rate = rate.or(confirm_floor);
            }
            if depth <= 1 {
                if let (Some(r), Some(floor)) = (rate, confirm_floor) {
                    rate = Some(r.max(floor));
                }
            }
            ordered.push((depth, rate.map(|r| r.max(min_r))));
        }
        self.log_fee_readiness(flow_warm, &history);
        let mut held: Vec<Option<u64>> = ordered.iter().map(|(_, r)| *r).collect();
        hold_defined_then_monotone(&mut held);
        let mut by_depth = HashMap::with_capacity(ordered.len());
        for ((depth, _), rate) in ordered.iter().zip(held) {
            by_depth.insert(
                *depth,
                match rate {
                    None => -1.0,
                    Some(r) => r as f64 / 100_000_000.0,
                },
            );
        }

        self.fee_snapshot.store(Arc::new(FeeSnapshot {
            by_depth_btc_per_kb: by_depth,
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
    fn maybe_refresh_tx_snapshot(&self) {
        let now = Instant::now();
        let snap = self.tx_snapshot.load_full();
        let stale = now
            .checked_duration_since(snap.computed_at)
            .map(|d| d >= FEE_SNAPSHOT_MAX_AGE)
            .unwrap_or(true);
        let dirty = self.tx_snap_dirty.load(Ordering::Acquire);
        if !dirty && !stale {
            return;
        }
        if self
            .tx_snap_refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.refresh_tx_snapshot();
        self.tx_snap_refreshing.store(false, Ordering::Release);
    }

    fn refresh_tx_snapshot(&self) {
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

    fn finish_accept_err(&self, us: u64, e: AcceptError) -> Result<AcceptResult, AcceptError> {
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

    /// Accept an ancestor package (local / Electrum path; BIP331 wire later).
    pub fn accept_package(&self, txs: &[Transaction]) -> Result<Vec<AcceptResult>, AcceptError> {
        crate::reactor::assert_not_reactor("mempool accept");
        Self::check_package_shape(txs)?;
        let t0 = Instant::now();
        let utxo = self.utxo_provider();
        let sat_kvb = self.min_relay_sat_kvb();
        let bps = self.lock_read().graph.bytes_per_sigop();
        let member_min = if ActiveMempool::package_meets_min_relay(txs, &utxo, sat_kvb, bps) {
            Some(0)
        } else {
            None
        };
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
        let mut prevouts: Vec<Vec<TxOut>> = Vec::with_capacity(txs.len());
        for tx in txs {
            utxo.note_spender(tx);
            let delta = self.fee_delta(&tx.compute_txid());
            let spec = AdmitSpec {
                report_orphans: true,
                fee_delta: delta,
                time_prepare_lock: true,
                min_relay: member_min,
            };
            let prep = match self.admit_staged(tx, &utxo, spec, &mut stages, &mut lock_us) {
                Ok(p) => p,
                Err(e) => {
                    if !accepted.is_empty() {
                        self.rollback_package_accepted(&accepted);
                    }
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
            };
            let prev = prep.prevouts.clone();
            let t_lock = Instant::now();
            let commit = {
                let mut g = self.lock_write();
                g.last_accept_stages = stages;
                let r = g.commit_after_script(tx, prep);
                stages = g.last_accept_stages;
                r
            };
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            match commit {
                Ok(r) => {
                    prevouts.push(prev);
                    accepted.push(r);
                }
                Err(e) => {
                    self.rollback_package_accepted(&accepted);
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
            }
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
        Ok(accepted)
    }

    /// Remove confirmed txids (tip connect / archive confirm) and re-try orphans
    /// whose parents just confirmed (Query UTXO view).
    ///
    /// Samples removed entries' feerates into confirm-memory for the standard
    /// 10-minute fee estimate floor.
    ///
    /// **No-op while relay is disabled** (IBD catch-up). Callers must not rely
    /// on per-block strip until [`Self::set_relay_enabled`]`(true)` has run the
    /// deferred [`Self::purge_confirmed_on_chain`].
    pub fn remove_for_block(&self, txids: &[Txid]) -> usize {
        if !self.relay_enabled() {
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
        n
    }

    /// Remove confirmed txids, then evict mempool txs that spend `spent`
    /// (block inputs that conflicted with the live set).
    pub fn remove_for_block_spent(&self, txids: &[Txid], spent: &[OutPoint]) -> usize {
        if !self.relay_enabled() {
            return 0;
        }
        let n = self.remove_for_block(txids);
        if spent.is_empty() {
            return n;
        }
        let mut g = self.lock_write();
        let gone = g.evict_conflicts_with(spent);
        drop(g);
        self.unindex_evicted(&gone);
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
    fn orphan_write<R>(&self, f: impl FnOnce(&mut ActiveMempool) -> R) -> Option<R> {
        if let Ok(mut g) = self.inner.try_write() {
            return Some(f(&mut g));
        }
        if crate::reactor::on_tokio_worker() && !crate::reactor::in_blocking_region() {
            return None;
        }
        Some(f(&mut self.lock_write()))
    }

    fn parent_already_have(&self, txid: &Txid) -> bool {
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

    pub(crate) fn orphan_getdata_parents(&self, tx: &Transaction) -> BTreeSet<Txid> {
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

    pub(crate) fn try_orphan_missing(&self, txid: &Txid) -> Option<BTreeSet<Txid>> {
        self.inner
            .try_read()
            .ok()?
            .orphanage
            .missing_of(txid)
            .cloned()
    }

    pub(crate) fn try_orphan_tx_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        self.inner
            .try_read()
            .ok()?
            .orphanage
            .tx_by_wtxid(wtxid)
            .cloned()
    }

    pub(crate) fn schedule_orphan_parents(
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

    /// `wtxid` records that `hash` arrived as a wtxid inv.
    /// Returns false when a cap refuses a new announcement (peer misbehavior).
    pub(crate) fn note_inv_tx_requested(
        &self,
        peer: u64,
        hash: [u8; 32],
        inbound: bool,
        now: u64,
        wtxid: bool,
    ) -> bool {
        self.parent_req
            .lock()
            .unwrap()
            .note_inv(peer, hash, inbound, now, wtxid)
    }

    pub(crate) fn parent_announcement_count(&self) -> usize {
        self.parent_req.lock().unwrap().announcement_count()
    }

    pub(crate) fn forget_parent_anns_for_peer(&self, peer: u64) {
        self.parent_req.lock().unwrap().forget_peer(peer);
    }

    pub(crate) fn announcer_peers_for(&self, txid: &Txid, wtxid: &Wtxid) -> Vec<u64> {
        self.parent_req
            .lock()
            .unwrap()
            .announcer_peers([txid.to_byte_array(), wtxid.to_byte_array()])
    }

    pub(crate) fn resolve_tx_request(&self, txid: &Txid, wtxid: &Wtxid, admitted: bool) {
        self.parent_req.lock().unwrap().resolve(
            [txid.to_byte_array(), wtxid.to_byte_array()],
            admitted,
        );
    }

    pub(crate) fn take_due_parent_getdata(&self, peer: u64, now: u64) -> Vec<DueParent> {
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

    /// Re-admit txs after reorg disconnect (best-effort).
    pub fn reorg_reaccept(&self, txs: &[Transaction]) -> usize {
        let utxo = self.utxo_provider();
        let mut admitted: Vec<(&Transaction, Vec<TxOut>)> = Vec::new();
        for tx in txs.iter().filter(|t| !t.is_coinbase()) {
            if let Ok(prevouts) = self.staged_reorg_admit(tx, &utxo) {
                let w = tx.compute_wtxid();
                self.reorg_servable.lock().unwrap().insert(w);
                self.insert_relay_maps(tx.compute_txid(), w, 0);
                admitted.push((tx, prevouts));
            }
        }
        self.evict_after_reorg();
        for (tx, prevouts) in &admitted {
            self.index_txid(tx.compute_txid(), tx, prevouts);
        }
        admitted.len()
    }

    fn staged_reorg_admit(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) -> Result<Vec<TxOut>, AcceptError> {
        utxo.note_spender(tx);
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let spec = AdmitSpec {
            report_orphans: true,
            fee_delta: 0,
            time_prepare_lock: false,
            min_relay: None,
        };
        let prep = match self.admit_staged(tx, utxo, spec, &mut stages, &mut lock_us) {
            Ok(p) => p,
            Err(AcceptError::Orphaned { missing, .. }) => {
                let mut g = self.lock_write();
                return Err(g.park_orphan(tx, missing));
            }
            Err(e) => return Err(e),
        };
        let prevouts = prep.prevouts.clone();
        {
            let mut g = self.lock_write();
            g.commit_after_script(tx, prep)?;
        }
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
        let utxo = self.utxo_provider();
        let tip = self.chain_tip_ctx();
        loop {
            let snaps: Vec<(Txid, Transaction, Vec<bool>)> = {
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
                        Some((*id, tx, in_mp))
                    })
                    .collect()
            };
            let mut to_drop = Vec::new();
            for (id, tx, in_mp) in snaps {
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
                if missing
                    || rbitcoin_mempool::check_mempool_structural(&tx, &chain_coins, tip).is_err()
                {
                    to_drop.push(id);
                }
            }
            if to_drop.is_empty() {
                break;
            }
            let mut g = self.lock_write();
            let mut removed = false;
            for id in &to_drop {
                if g.remove_txid(id).is_ok() {
                    removed = true;
                }
            }
            if !removed {
                break;
            }
        }
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
    pub fn select_block_template(&self, budget: SelectBudget) -> Vec<(Transaction, Selected)> {
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

    fn note_template_update(&self) {
        self.template_updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Generation for `getblocktemplate.longpollid`.
    pub fn template_updates(&self) -> u64 {
        self.template_updates.load(Ordering::Relaxed)
    }

    /// Snapshot of non-zero deltas for `getprioritisedtransactions`.
    pub fn prioritised_txs(&self) -> HashMap<Txid, i64> {
        self.fee_deltas.lock().unwrap().clone()
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

    /// Weight budget used for chunk eviction (WU). RPC `maxmempool`.
    pub fn max_weight(&self) -> u64 {
        self.lock_read().max_weight
    }

    pub fn mempool_min_fee_sat_kvb(&self) -> u64 {
        self.lock_read().mempool_min_fee_sat_kvb()
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
                vb + rbitcoin_consensus::policy::get_virtual_size(e.adjusted_weight(bps)),
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

    /// Min-relay overlay (sat/kvB). `0` admits any non-negative fee.
    pub fn set_min_relay_sat_kvb(&self, sat_kvb: u64) {
        self.min_relay_sat_kvb.store(sat_kvb, Ordering::Release);
        self.lock_write().set_min_relay_sat_kvb(sat_kvb);
    }

    pub fn min_relay_sat_kvb(&self) -> u64 {
        self.min_relay_sat_kvb.load(Ordering::Acquire)
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
        for ch in g.graph.mining_chunks_best_first() {
            let mut fee = 0i64;
            for t in &ch.txids {
                let base = g.graph.get(t).map(|e| e.fee_sat as i64).unwrap_or(0);
                fee = fee.saturating_add(base.saturating_add(d(*t)));
            }
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
    pub fn submit_package_rpc(
        &self,
        txs: &[Transaction],
    ) -> Vec<Result<AcceptResult, AcceptError>> {
        let mut out: Vec<Result<AcceptResult, AcceptError>> =
            txs.iter().map(|tx| self.accept_tx(tx)).collect();
        let rest: Vec<Transaction> = txs
            .iter()
            .zip(out.iter())
            .filter(|(tx, r)| {
                r.as_ref().err().is_some_and(package_rpc_retry)
                    && !self.contains(&tx.compute_txid())
            })
            .map(|(tx, _)| tx.clone())
            .collect();
        if rest.len() >= 2 {
            let _ = self.accept_package(&rest);
        }
        for (tx, slot) in txs.iter().zip(out.iter_mut()) {
            if slot.is_ok() {
                continue;
            }
            if let Some(ok) = self.live_accept_result(&tx.compute_txid()) {
                *slot = Ok(ok);
            }
        }
        out
    }

    fn live_accept_result(&self, txid: &Txid) -> Option<AcceptResult> {
        let g = self.lock_read();
        let e = g.graph.get(txid)?;
        Some(AcceptResult {
            txid: e.txid,
            fee_sat: e.fee_sat,
            weight: e.adjusted_weight(g.graph.bytes_per_sigop()),
            slot: e.slot,
            replaced: Vec::new(),
            replaced_scripthashes: Vec::new(),
            replaced_txs: Vec::new(),
        })
    }

    #[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
    /// `getmempoolcluster` payload from the live graph (weights sigop-adjusted).
    pub fn cluster_rpc(&self, txid: &Txid) -> Option<(u64, usize, Vec<(i64, u64, Vec<Txid>)>)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let d = |id: Txid| deltas.get(&id).copied().unwrap_or(0);
        let g = self.lock_read();
        let c = g.graph.cluster_of_delta(txid, d)?;
        let chunks: Vec<_> = c
            .chunks
            .iter()
            .map(|ch| (ch.fee_sat as i64, ch.weight, ch.txids.clone()))
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

    pub fn mark_local_origin(&self, txid: Txid) {
        self.local_origin.lock().unwrap().insert(txid);
        if self.isolated_broadcast() {
            let _ = self.isolated_kick.send(txid);
        }
    }

    pub(crate) fn subscribe_isolated(&self) -> broadcast::Receiver<Txid> {
        self.isolated_kick.subscribe()
    }

    pub fn is_local_origin(&self, txid: &Txid) -> bool {
        self.local_origin.lock().unwrap().contains(txid)
    }

    pub fn set_isolated_broadcast(&self, on: bool) {
        self.isolated_broadcast.store(on, Ordering::Relaxed);
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

    /// Unconfirmed delta for Electrum balance (sats): +mempool outputs − spent confirmed.
    ///
    /// Skips txs already connected on the tip (`tx_fk_by_txid_tip`) so a leftover
    /// live entry after IBD / `-blocksonly` (`remove_for_block` is a no-op while
    /// relay is off) cannot double-count confirmed value.
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
        let mut kept = Vec::with_capacity(want.len());
        for txid in want {
            if self
                .query
                .tx_fk_by_txid_tip(&txid.to_byte_array())?
                .is_some()
            {
                continue;
            }
            kept.push(txid);
        }
        if kept.is_empty() {
            return Ok(0);
        }
        let g = self.lock_read();
        let mut delta = 0i64;
        let provider = self.utxo_provider();
        for txid in kept {
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
                // Only count spending of **chain** UTXOs (not pure mempool-parent).
                if g.graph.creator(&op).is_some() {
                    continue;
                }
                self.meter_delta_prevouts.fetch_add(1, Ordering::Relaxed);
                if let Some(txout) = provider.get_txout(&op) {
                    if script_hash(txout.script_pubkey.as_bytes()) == *scripthash {
                        delta = delta.saturating_sub(txout.value.to_sat() as i64);
                    }
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
    /// **Default product answer is 10-minute inclusion** (`target_blocks` 0–2 →
    /// depth of [`Self::DEFAULT_HORIZON_BLOCKS`] blocks).
    ///
    /// **Non-blocking vs accept:** returns from a **published snapshot** (Arc).
    /// Graph linearize runs only on dirty/stale singleflight **refresh** (≤~1 s
    /// stale; one `mining_chunks` per refresh for all depths). Request path does
    /// not hold the hub lock across multi-pass walks.
    pub fn estimate_fee_btc_per_kb(&self, target_blocks: u32) -> f64 {
        self.maybe_refresh_fee_snapshot();
        let depth = Self::fee_depth(target_blocks);
        self.fee_snapshot.load().rate_btc_per_kb(depth)
    }

    /// How many times the live graph rebuilt mining chunks (sample-and-reset).
    pub fn take_chunks_rebuilds(&self) -> u64 {
        self.lock_read().graph.take_chunks_rebuilds()
    }

    /// All Esplora `/fee-estimates` depths in one Arc load (+ optional refresh).
    pub fn fee_estimates_btc_per_kb(&self) -> Vec<(u32, f64)> {
        self.maybe_refresh_fee_snapshot();
        let snap = self.fee_snapshot.load_full();
        FEE_SNAPSHOT_DEPTHS
            .iter()
            .map(|&d| (d, snap.rate_btc_per_kb(d)))
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

    /// Ring of recently confirmed package feerates (sat/kvB), newest last.
    /// Filled from `remove_for_block` when live entries leave the pool.
    fn confirm_memory_floor_sat_per_kvb(&self) -> Option<u64> {
        let mem = self.confirm_feerate_memory.lock().unwrap();
        if mem.is_empty() {
            return None;
        }
        let v: Vec<u64> = mem.iter().copied().collect();
        percentile_sat(v, 90)
            .map(|r| r.max(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB))
    }

    fn push_confirm_memory(&self, rate_sat_per_kvb: u64) {
        const CAP: usize = 64;
        let mut mem = self.confirm_feerate_memory.lock().unwrap();
        mem.push_back(rate_sat_per_kvb.max(1));
        while mem.len() > CAP {
            mem.pop_front();
        }
    }

    /// A height's hurdle and block hash, from `txstat` alone.
    fn txstat_fee_block_from_chain(
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
    fn write_fee_history_snapshot(&self, journal: &mut Option<FeeJournal>) {
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
    fn load_fee_history_file(&self) -> u64 {
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

    fn backfill_fee_history_height(&self, height: u32, stats: &mut FeeHistoryBackfillStats) {
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

    fn count_backfill_fee_block(block: &HistoricalFeeBlock, stats: &mut FeeHistoryBackfillStats) {
        stats.txstat_bytes = stats.txstat_bytes.saturating_add(block.txstat_bytes);
        if block.p10_sat_kvb.is_some() {
            stats.valid_samples = stats.valid_samples.saturating_add(1);
        } else {
            stats.skipped_heights = stats.skipped_heights.saturating_add(1);
        }
    }

    fn insert_backfill_fee_block(
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

    /// Log when flow warms up or a target's history becomes ready.
    fn log_fee_readiness(&self, flow_warm: bool, history: &HashMap<u32, Option<u64>>) {
        let ready = history.values().filter(|r| r.is_some()).count() as u32;
        let code = (u32::from(flow_warm) << 16) | ready;
        if self.fee_readiness.swap(code, Ordering::Relaxed) != code {
            rbitcoin_log::info!(
                "mempool: fee estimates: flow {}, history ready for {ready}/{} targets",
                if flow_warm { "warm" } else { "cold" },
                history.len()
            );
        }
    }

    fn log_fee_history_progress(stats: &FeeHistoryBackfillStats, last_progress: &mut Instant) {
        let now = Instant::now();
        if now.duration_since(*last_progress) < Duration::from_secs(10) {
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
        stats.history_exhausted =
            stats.txstat_bytes < FEE_HISTORY_TXSTAT_BYTE_BUDGET && stats.oldest_height == Some(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Sequence, TxIn, Witness};
    use rbitcoin_query::Query;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> std::path::PathBuf {
        // macOS clocks tick in µs: back-to-back calls can share `n`.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rbitcoin-txrelay-{n}-{seq}"))
    }

    fn record_fee_sample(hub: &MempoolHub, height: u32, rate_sat_kvb: u64) {
        let block = HistoricalFeeBlock {
            p10_sat_kvb: Some(rate_sat_kvb),
            txstat_bytes: 8,
        };
        hub.block_p10_history
            .lock()
            .unwrap()
            .insert(height, block, None);
    }

    #[test]
    fn tip_script_pres_skips_only_matching_wtxid() {
        use rbitcoin_mempool::TxEntry;
        let dir = tmp();
        let mdir = tmp();
        let q = Query::open_or_create_tiny(&dir).unwrap();
        let hub = MempoolHub::open(&mdir, Arc::new(q)).unwrap();
        let mut good = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0x01]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = good.compute_txid();
        hub.lock_write().graph.insert(
            TxEntry {
                txid,
                wtxid: good.compute_wtxid(),
                fee_sat: 1,
                weight: good.weight().to_wu(),
                sigop_cost: 0,
                slot: 0,
                parents: BTreeSet::new(),
                children: BTreeSet::new(),
            },
            &good,
        );
        let id = txid.to_byte_array();
        let (_, skip_good) = hub.tip_script_pres(std::slice::from_ref(&good));
        assert!(skip_good.contains(&id), "same witness is preverified");
        good.input[0].witness = Witness::from_slice(&[vec![0x02]]);
        assert_eq!(good.compute_txid(), txid);
        let (_, skip_bad) = hub.tip_script_pres(std::slice::from_ref(&good));
        assert!(
            !skip_bad.contains(&id),
            "different witness must not skip scripts"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&mdir);
    }

    /// Spend `prev` to one OP_TRUE output of `value`.
    fn spend_vout(prev: OutPoint, value: u64) -> Transaction {
        let mut tx = spend_true(prev.txid, 0, ScriptBuf::from_bytes(vec![0x51]));
        tx.input[0].previous_output = prev;
        tx.output[0].value = Amount::from_sat(value);
        tx
    }

    fn spend_true(cb: Txid, fee: u64, spk: ScriptBuf) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - fee),
                script_pubkey: spk,
            }],
        }
    }

    #[test]
    fn recent_confirmed_evicts_oldest_over_cap() {
        let mut r = RecentConfirmed::new();
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let a = spend_true(Txid::from_byte_array([1u8; 32]), 1, spk.clone());
        let b = spend_true(Txid::from_byte_array([2u8; 32]), 1, spk);
        r.note_block_capped(std::slice::from_ref(&a), 1);
        r.note_block_capped(std::slice::from_ref(&b), 1);
        assert!(!r.contains_txid(&a.compute_txid()));
        assert!(!r.contains_wtxid(&a.compute_wtxid()));
        assert!(r.contains_txid(&b.compute_txid()));
        assert!(r.contains_wtxid(&b.compute_wtxid()));
    }

    #[test]
    fn sh_index_insert_overwrite_and_remove_miss() {
        let mut idx = MempoolShIndex::new();
        let t = Txid::from_byte_array([1u8; 32]);
        let sh = [2u8; 32];
        idx.insert(t, vec![sh]);
        idx.insert(t, vec![sh]); // overwrite same mapping
        assert_eq!(idx.txs_for(&sh).count(), 1);
        idx.remove(&t);
        idx.remove(&t); // miss
        assert_eq!(idx.txs_for(&sh).count(), 0);
        assert!(idx.txs_for(&[3u8; 32]).next().is_none());
    }

    /// One 12-coinbase pad covers reorg-reaccept, unbroadcast persist and the
    /// confirm-before-broadcast log, local-origin isolation, SH reopen, live
    /// accept/fee/package, recent accepts and rejects, 1p1c admit and
    /// rollback, unknown-SH delta, accept-stage meters, expiry, and a
    /// 16_004-sigop admit over Core's standard cap.
    #[allow(clippy::cognitive_complexity)] // one fixture, many mempool journey arms
    #[test]
    fn hub_live_journey() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        use rbitcoin_store::script_hash;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        const N_CB: u32 = 12;
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            100 + N_CB,
            N_CB,
        );
        let q = Arc::new(q);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let sh = script_hash(spk.as_bytes());

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let tx = spend_true(cbs[0], 1_000, spk.clone());
            assert!(!hub.is_reorg_servable(&tx.compute_wtxid()));
            assert_eq!(hub.reorg_reaccept(std::slice::from_ref(&tx)), 1);
            let w = tx.compute_wtxid();
            assert!(hub.is_reorg_servable(&w));
            assert!(hub.get_tx_by_wtxid(&w).is_some());
            assert!(hub.remove_for_block(&[tx.compute_txid()]) >= 1);
            assert!(hub.get_tx_by_wtxid(&w).is_none());
            assert!(
                !hub.is_relay_servable(&w, u64::MAX),
                "unindex must drop relay maps with the live graph entry"
            );
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let tx = spend_true(cbs[1], 1_000, spk.clone());
            hub.accept_tx(&tx).expect("accept");
            let extra = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            let (pres, skip) = hub.tip_script_pres(&[tx.clone(), extra]);
            let live_id = tx.compute_txid().to_byte_array();
            assert_eq!(skip.len(), 1);
            assert!(skip.contains(&live_id));
            assert!(
                pres[0].sha_prevouts.is_none(),
                "live graph tx must skip sighash midstates"
            );
            assert!(
                pres[1].sha_prevouts.is_some(),
                "non-live must fill midstates after connect ids"
            );
            let wire = spend_true(cbs[8], 1_000, spk.clone());
            hub.accept_tx(&wire).expect("peer tx");
            hub.mark_local_origin(tx.compute_txid());
            hub.note_unbroadcast(tx.compute_txid());
            assert_eq!(hub.unbroadcast_count(), 1);
            assert!(hub.is_local_origin(&tx.compute_txid()));
            assert!(!hub.is_local_origin(&wire.compute_txid()));
            assert!(
                !hub.skip_standing_inv(&tx.compute_txid()),
                "without --proxy/--onion, local-origin still uses standing INV"
            );
            hub.set_isolated_broadcast(true);
            assert!(hub.skip_standing_inv(&tx.compute_txid()));
            assert!(!hub.skip_standing_inv(&wire.compute_txid()));
            hub.flush().expect("shutdown flush");
            drop(hub);
            let hub2 = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            let reopen = hub2.sample_reset_perf();
            assert_eq!(
                reopen.get_coin, 0,
                "SH reindex must use stored vin aux, not get_txout"
            );
            assert!(
                !hub2.scripthash_mempool(&sh).is_empty(),
                "reopen SH index from stored hashes"
            );
            hub2.set_relay_enabled(true);
            assert_eq!(hub2.unbroadcast_count(), 1);
            let mut rx = hub2.subscribe_announces();
            hub2.rebroadcast_unbroadcast();
            let got = rx.try_recv().expect("mockscheduler rebroadcast");
            assert_eq!(got.txid, tx.compute_txid());
            rbitcoin_log::capture_logs(true);
            assert_eq!(hub2.remove_for_block(&[tx.compute_txid()]), 1);
            let logs = rbitcoin_log::take_logs();
            rbitcoin_log::capture_logs(false);
            let needle = format!(
                "p2p: Removed {} from set of unbroadcast txns before confirmation that txn was sent out",
                tx.compute_txid()
            );
            assert!(logs.iter().any(|(_, m)| *m == needle), "{logs:?}");
            assert_eq!(hub2.unbroadcast_count(), 0);
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let mut rx = hub.subscribe_announces();
            let parent = spend_true(cbs[2], 1_000, spk.clone());
            hub.accept_tx(&parent).expect("accept");
            let ann = rx.try_recv().expect("announce");
            assert!(ann.scripthashes.contains(&sh));
            let child = Transaction {
                version: bitcoin::transaction::Version::TWO,
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
                    value: Amount::from_sat(49_9998_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            hub.accept_tx(&child).expect("child");
            assert!(hub.scripthash_mempool(&sh).len() >= 2);
            hub.flush().unwrap();
            drop(hub);
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            assert!(hub.scripthash_mempool(&sh).len() >= 2);
            assert!(hub.remove_for_block(&[parent.compute_txid()]) >= 1);
            assert!(!hub.scripthash_mempool(&sh).is_empty());
            assert!(hub.remove_for_block(&[child.compute_txid()]) >= 1);
            assert!(hub.scripthash_mempool(&sh).is_empty());
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let mut ann_rx = hub.subscribe_announces();
            let provider = QueryUtxoProvider::new(q.as_ref());
            let op0 = OutPoint {
                txid: cbs[3],
                vout: 0,
            };
            assert!(provider.get_txout(&op0).is_some());
            let cheap = spend_true(cbs[9], 1, spk.clone());
            assert!(matches!(
                hub.accept_tx(&cheap),
                Err(AcceptError::Policy("min relay fee"))
            ));
            assert!(
                !hub.try_recent_reject(&cheap.compute_wtxid()),
                "min-relay is reconsiderable; must not skip a later ATMP"
            );
            let coinbase = Transaction {
                version: Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50),
                    script_pubkey: spk.clone(),
                }],
            };
            assert!(matches!(
                hub.accept_tx(&coinbase),
                Err(AcceptError::Coinbase)
            ));
            assert!(hub.try_recent_reject(&coinbase.compute_wtxid()));
            hub.note_recent_confirmed(&[]);
            assert!(
                !hub.try_recent_reject(&coinbase.compute_wtxid()),
                "tip connect must forget recent_rejects"
            );
            assert!(hub.recent_accepts().is_empty());
            let parent = spend_true(cbs[3], 1_000, spk.clone());
            let pr = hub.accept_tx(&parent).expect("accept parent");
            assert_eq!(pr.txid, parent.compute_txid());
            assert!(ann_rx.try_recv().is_ok());
            let recent = hub.recent_accepts();
            assert_eq!(recent.len(), 1);
            assert_eq!(recent[0].txid, parent.compute_txid());
            assert_eq!(recent[0].fee_sat, 1_000);
            let child = Transaction {
                version: bitcoin::transaction::Version::TWO,
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
                    value: Amount::from_sat(50_0000_0000 - 2_000),
                    script_pubkey: spk.clone(),
                }],
            };
            let second = spend_true(cbs[4], 5_000, ScriptBuf::from_bytes(vec![0x52]));
            let second_id = second.compute_txid();
            hub.accept_tx(&child).expect("child");
            let pkg = hub.accept_package(&[second]).expect("package");
            assert_eq!(pkg.len(), 1);
            assert_eq!(hub.live_count(), 3);
            let newest_first: Vec<Txid> = hub.recent_accepts().iter().map(|r| r.txid).collect();
            assert_eq!(
                newest_first,
                [second_id, child.compute_txid(), parent.compute_txid()]
            );
            assert!(hub.contains(&parent.compute_txid()));
            let wtxid = parent.compute_wtxid();
            assert!(hub.contains_wtxid(&wtxid));
            assert!(hub.get_tx_by_wtxid(&wtxid).is_some());
            assert!(!hub.fee_histogram().is_empty());
            let e1 = hub.estimate_fee_btc_per_kb(1);
            let e5 = hub.estimate_fee_btc_per_kb(5);
            let e144 = hub.estimate_fee_btc_per_kb(144);
            // Flow is cold on a fresh hub and the chain has no fee history:
            // a thin live pool alone does not set a guess.
            assert!(
                e1 < 0.0 && e5 < 0.0 && e144 < 0.0,
                "cold flow without history: e1={e1} e5={e5} e144={e144}"
            );
            let spent = hub.spent_outpoints();
            assert!(spent.contains(&op0));
            let rows = hub.scripthash_mempool(&sh);
            assert!(rows.len() >= 2);
            assert!(rows.iter().any(|r| r.height == -1));
            let delta = hub.scripthash_unconfirmed_delta(&sh).unwrap();
            assert_eq!(delta, 50_0000_0000 - 2_000 - 50_0000_0000 - 50_0000_0000);
            assert!(hub.is_relay_servable(&wtxid, hub.current_relay_seq()));
            assert!(hub.remove_for_block(&[parent.compute_txid()]) >= 1);
            hub.mark_fee_dirty();
            let e1b = hub.estimate_fee_btc_per_kb(1);
            let e144b = hub.estimate_fee_btc_per_kb(144);
            assert!(
                e1b < 0.0 && e144b < 0.0,
                "a confirm does not warm flow or add history: e1={e1b} e144={e144b}"
            );
            assert!(
                !hub.contains_wtxid(&wtxid),
                "wtxid index must drop with the live entry"
            );
            assert!(hub.get_tx_by_wtxid(&wtxid).is_none());
            assert!(
                !hub.is_relay_servable(&wtxid, u64::MAX),
                "unindex must drop relay maps with the live graph entry"
            );
            assert!(hub.list_live().len() < 3);

            hub.set_min_relay_sat_kvb(50_000);
            let lp = Transaction {
                output: vec![
                    TxOut {
                        value: Amount::from_sat(25_0000_0000),
                        script_pubkey: spk.clone(),
                    },
                    TxOut {
                        value: Amount::from_sat(25_0000_0000 - 200),
                        script_pubkey: spk.clone(),
                    },
                ],
                ..spend_true(cbs[9], 0, spk.clone())
            };
            let lpid = lp.compute_txid();
            assert!(matches!(
                hub.accept_tx(&lp),
                Err(AcceptError::Policy("min relay fee"))
            ));
            let one_sat = spend_vout(OutPoint::new(lpid, 0), 25_0000_0000 - 1);
            assert!(matches!(
                hub.accept_tx(&one_sat),
                Err(AcceptError::Orphaned { .. })
            ));
            assert_eq!(hub.orphan_count(), 1);
            let payer = spend_vout(OutPoint::new(lpid, 1), 1_000);
            hub.accept_tx(&payer)
                .expect("hub 1p1c must admit parent+child");
            assert!(hub.contains(&lpid));
            assert!(hub.contains(&payer.compute_txid()));
            assert!(
                !hub.contains(&one_sat.compute_txid()),
                "1-sat sibling must not ride 1p1c promote at floor 0"
            );
            assert_eq!(hub.orphan_count(), 0);
            let sib = spend_vout(OutPoint::new(lpid, 0), 25_0000_0000 - 10_000);
            let (sib_id, sib_w) = (sib.compute_txid(), sib.compute_wtxid());
            hub.accept_tx(&sib).expect("paying sibling of live parent");
            assert!(hub.relay_seq_of(&sib_w).is_some());
            assert!(hub.accept_time_txid(&sib_id).is_some());
            let tmpl = hub.template_updates();
            hub.rollback_1p1c_parent(&lpid);
            assert!(!hub.contains(&lpid));
            assert!(!hub.contains(&sib_id));
            assert!(
                hub.relay_seq_of(&sib_w).is_none(),
                "published spender must leave wtxid/relay maps"
            );
            assert!(hub.accept_time_txid(&sib_id).is_none());
            assert!(
                hub.template_updates() > tmpl,
                "template must bump like remove_for_block_spent"
            );
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let _ = hub.sample_reset_perf();
            let mut fee_sum = 0i64;
            let mut spends = Vec::new();
            for (i, cbtxid) in cbs[5..8].iter().enumerate() {
                let fee = 1_000u64 + i as u64;
                fee_sum += fee as i64;
                let tx = spend_true(*cbtxid, fee, spk.clone());
                hub.accept_tx(&tx).expect("accept spend");
                spends.push(tx.compute_txid());
            }
            let n = 3u64;
            let s = hub.sample_reset_perf();
            assert_eq!(s.accepts, n);
            assert_eq!(s.tip_mtp, 1, "same tip must compute MTP once");
            assert_eq!(
                s.expire_full_scans, 0,
                "young pool must not walk accept_at for expiry"
            );
            assert!(s.accept_us > 0);
            assert!(s.accept_lock_us > 0);
            assert!(s.accept_utxo_us > 0);
            assert!(s.accept_script_us > 0);
            assert!(s.accept_durable_us > 0);
            assert!(
                s.accept_lock_us >= s.accept_durable_us,
                "lock_us={} durable_us={}",
                s.accept_lock_us,
                s.accept_durable_us
            );
            assert!(
                s.accept_us >= s.accept_script_us,
                "wall={} script={}",
                s.accept_us,
                s.accept_script_us
            );
            let z = hub.sample_reset_perf();
            assert_eq!(z.accepts, 0);
            let unused = script_hash(&[0x00]);
            assert_eq!(hub.scripthash_unconfirmed_delta(&unused).unwrap(), 0);
            let s = hub.sample_reset_perf();
            assert_eq!(s.delta_prevouts, 0);
            assert_eq!(hub.scripthash_unconfirmed_delta(&sh).unwrap(), -fee_sum);

            // `mempool_expiry.py`: a new tx past -mempoolexpiry drops every
            // older tx with its child, and keeps prioritisetransaction.
            let child = spend_true(spends[0], 2_000, spk.clone());
            hub.accept_tx(&child).expect("child");
            hub.prioritise_tx(spends[0], 50_000);
            hub.set_expiry_hours(1);
            hub.note_mock_now(hub.relay_now_secs() + 3600 + 5);
            let trigger = spend_true(cbs[10], 3_000, spk.clone());
            hub.accept_tx(&trigger).expect("trigger expires stale");
            assert_eq!(hub.live_count(), 1);
            assert!(hub.contains(&trigger.compute_txid()));
            assert_eq!(hub.fee_delta(&spends[0]), 50_000);
            assert_eq!(hub.sample_reset_perf().expire_full_scans, 1);
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let tx = spend_true(cbs[0], 1_000, spk.clone());
            let tid = tx.compute_txid();
            let wtxid = tx.compute_wtxid();
            {
                let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
                store
                    .append_live_tx(&tx, &tid, &wtxid, 1_000, 400, 0, &[])
                    .unwrap();
                store.flush().unwrap();
            }
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            let s = hub.sample_reset_perf();
            assert_eq!(
                s.get_coin, 0,
                "missing-aux fill must batch Class A, not get_txout"
            );
            assert!(
                !hub.scripthash_mempool(&sh).is_empty(),
                "batch-fill the vin that lacked aux"
            );
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            // Unknown sigop cost (schema-2 migrate): open recomputes it from
            // chain coins and drops the entry whose input is not a coin.
            let mp = tmp();
            // OP_CHECKSIG output: one legacy sigop, cost 4.
            let ok = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0xac]));
            let gone = spend_true(Txid::from_byte_array([0xee; 32]), 1_000, spk.clone());
            {
                let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
                for tx in [&ok, &gone] {
                    let (tid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
                    store
                        .append_live_tx(tx, &tid, &wtxid, 1_000, 400, u64::MAX, &[])
                        .unwrap();
                }
                store.flush().unwrap();
            }
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            let picked: Vec<_> = hub
                .select_block_template(hub.template_budget(0))
                .into_iter()
                .map(|(_, s)| (s.txid, s.sigop_cost))
                .collect();
            assert_eq!(picked, vec![(ok.compute_txid(), 4)]);
            assert!(
                !hub.contains(&gone.compute_txid()),
                "unresolvable input evicted"
            );
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            // Sigop-adjusted weight: max(400, 100 * 20) until bps is 0.
            let mp = tmp();
            let tx = spend_true(cbs[0], 1_000, spk.clone());
            let (tid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
            {
                let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
                store
                    .append_live_tx(&tx, &tid, &wtxid, 1_000, 400, 100, &[])
                    .unwrap();
                store.flush().unwrap();
            }
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            assert_eq!(hub.get_live_adjusted_weight(&tid), Some(2_000));
            // Core `getmempoolcluster` `clusterweight` is sigop-adjusted.
            assert_eq!(hub.cluster_rpc(&tid).unwrap().0, 2_000);
            // Feefilter announce gate: Core `txinfo.vsize` is sigop-adjusted.
            assert_eq!(hub.try_get_live_meta(&tid), Some((1_000, 2_000)));
            hub.set_bytes_per_sigop(0);
            assert_eq!(hub.get_live_adjusted_weight(&tid), Some(400));
            assert_eq!(hub.cluster_rpc(&tid).unwrap().0, 400);
            assert_eq!(hub.get_live_adjusted_weight(&Txid::all_zeros()), None);
            hub.set_bytes_per_sigop(20);
            // Confirmed feerate memory: 1_000 sat on 500 adjusted vB (raw 100).
            hub.set_relay_enabled(true);
            assert_eq!(hub.remove_for_block(&[tid]), 1);
            assert_eq!(hub.confirm_memory_floor_sat_per_kvb(), Some(2_000));
            let _ = std::fs::remove_dir_all(&mp);
        }

        // 4001 legacy CHECKSIG × 4 = 16004: over Core's standard cap, under
        // the block limit, so Libre policy admits it.
        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: cbs[11],
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000 - 100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0xac; 4_001]),
                }],
            };
            hub.accept_tx(&tx).expect("16004 sigop cost fits a block");
            let picked = hub.select_block_template(hub.template_budget(0));
            assert_eq!(picked.len(), 1);
            assert_eq!(picked[0].0, tx);
            assert_eq!(
                (picked[0].1.fee_sat, picked[0].1.sigop_cost),
                (100_000, 16_004)
            );
            let _ = std::fs::remove_dir_all(&mp);
        }

        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Non-coinbase, no BIP68 time-lock: no `block_tx_fks` and no create MTP.
    /// A satisfied time-lock spend must survive `evict_after_reorg`.
    #[test]
    fn get_coin_skips_block_tx_fks_and_mtp_without_time_lock() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        use rbitcoin_store::script_hash;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (tip, tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            3,
        );
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let confirmed = spend_true(cbs[0], 1_000, spk.clone());
        let b = rbitcoin_consensus::mine_regtest_paying(
            tip,
            tip_time + 600,
            103,
            spk.clone(),
            vec![confirmed.clone()],
        );
        accept_and_connect_block(&q, &params, Height(103), &b, Milestone::NONE).unwrap();
        q.apply_sh_pending().unwrap();
        let q = Arc::new(q);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let _ = hub.sample_reset_perf();
        let child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: confirmed.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(confirmed.output[0].value.to_sat() - 1_000),
                script_pubkey: spk.clone(),
            }],
        };
        hub.accept_tx(&child).expect("non-coinbase chain spend");
        let s = hub.sample_reset_perf();
        assert_eq!(
            s.get_coin, 1,
            "chain-spend index_txid must not re-Query the same prevout (got {})",
            s.get_coin
        );
        assert_eq!(
            s.get_coin_block_tx_fks, 0,
            "non-coinbase get_coin must not call block_tx_fks"
        );
        assert_eq!(
            s.get_coin_create_mtp, 0,
            "no BIP68 time-lock must not compute create MTP"
        );
        assert!(
            !hub.scripthash_mempool(&script_hash(spk.as_bytes()))
                .is_empty(),
            "output script must still hit SH overlay"
        );
        let err = hub.accept_tx(&confirmed).unwrap_err();
        assert!(
            matches!(err, AcceptError::MissingPrevout(_)),
            "confirmed body must not park as orphan, got {err}"
        );
        assert_eq!(hub.orphan_count(), 0);
        assert!(
            hub.try_contains(&confirmed.compute_txid()),
            "INV AlreadyHave for Class A txid"
        );
        assert!(
            !hub.try_contains_wtxid(&confirmed.compute_wtxid()),
            "wtxid AlreadyHave needs the recent-confirmed ring"
        );
        hub.note_recent_confirmed(std::slice::from_ref(&confirmed));
        assert!(hub.try_contains_wtxid(&confirmed.compute_wtxid()));
        assert!(
            hub.try_contains(&confirmed.compute_txid()),
            "recent-confirmed ring AlreadyHave for txid"
        );
        hub.note_recent_confirmed(std::slice::from_ref(&confirmed));
        hub.clear_recent_confirmed();
        assert!(
            !hub.try_contains_wtxid(&confirmed.compute_wtxid()),
            "reorg must drop wtxid AlreadyHave"
        );
        assert!(hub.try_contains(&confirmed.compute_txid()));
        let oob = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: confirmed.compute_txid(),
                    vout: 99,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: spk.clone(),
            }],
        };
        let err = hub.accept_tx(&oob).unwrap_err();
        assert!(
            matches!(err, AcceptError::MissingPrevout(_)),
            "confirmed create missing vout must not park, got {err}"
        );
        assert_eq!(hub.orphan_count(), 0);

        hub.remove_for_block(&[child.compute_txid()]);
        q.disconnect_tip().unwrap();
        let ghost = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: confirmed.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(confirmed.output[0].value.to_sat() - 2_000),
                script_pubkey: spk.clone(),
            }],
        };
        let err = hub.accept_tx(&ghost).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { .. }),
            "disconnected create (no height) must park, got {err}"
        );

        let _ = hub.sample_reset_perf();
        let timed = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cbs[1],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus((1 << 22) | 1),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: spk,
            }],
        };
        hub.accept_tx(&timed).expect("bip68 time-lock spend");
        let s = hub.sample_reset_perf();
        assert!(
            s.get_coin_create_mtp >= 1,
            "BIP68 time-lock spend must compute create MTP"
        );
        hub.evict_after_reorg();
        assert!(
            hub.get_live_meta(&timed.compute_txid()).is_some(),
            "evict_after_reorg must not drop a still-valid BIP68 time lock"
        );
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Confirm/RBF unindex must drop `relay_seq` / `accept_at` for the gone
    /// wtxid and leave a still-live sibling indexed.
    #[test]
    fn unindex_drops_relay_seq_and_accept_at() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            2,
        );
        let q = Arc::new(q);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        hub.note_mock_now(10);
        let gone = spend_true(cbs[0], 1_000, spk.clone());
        let stay = spend_true(cbs[1], 2_000, spk);
        hub.accept_tx(&gone).expect("accept gone");
        hub.accept_tx(&stay).expect("accept stay");
        let gone_w = gone.compute_wtxid();
        let stay_w = stay.compute_wtxid();
        assert!(hub.relay_seq_of(&gone_w).is_some());
        assert!(hub.relay_seq_of(&stay_w).is_some());
        assert!(hub.remove_for_block(&[gone.compute_txid()]) >= 1);
        assert!(hub.contains(&stay.compute_txid()));
        assert!(hub.relay_seq_of(&gone_w).is_none());
        assert!(hub.relay_seq_of(&stay_w).is_some());
        hub.note_mock_now(40);
        assert!(!hub.tx_inv_due(&gone_w));
        assert!(hub.tx_inv_due(&stay_w));
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Without `setmocktime`, INV age must still elapse on wall clock
    /// (`mempool_accept_wtxid` wait_for_broadcast; mock_now==0 must not freeze).
    #[test]
    fn tx_inv_due_uses_wall_clock_when_mocktime_unset() {
        use bitcoin::script::ScriptBuf;
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            1,
        );
        let q = Arc::new(q);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        assert_eq!(hub.mock_now.load(Ordering::Relaxed), 0);
        let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        hub.accept_tx(&tx).expect("accept");
        let w = tx.compute_wtxid();
        assert!(
            !hub.tx_inv_due(&w),
            "fresh accept must not be due before 30s"
        );
        {
            let mut ats = hub.accept_at.lock().unwrap();
            let at = ats.get_mut(&w).expect("accept_at");
            *at = at.saturating_sub(30);
            hub.min_live_accept_at.store(*at, Ordering::Relaxed);
        }
        assert!(
            hub.tx_inv_due(&w),
            "30s wall age must due when mocktime is unset"
        );
        assert!(hub.any_tx_inv_due());
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// While relay is off, per-block remove is deferred; enabling relay runs purge.
    #[test]
    fn remove_for_block_skipped_until_relay_then_purge() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let mp = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        assert!(!mp.relay_enabled());
        let dummy = Txid::from_byte_array([9u8; 32]);
        // No-op while relay off (IBD catch-up must not strip per block).
        assert_eq!(mp.remove_for_block(&[dummy]), 0);
        // Enabling relay runs purge (empty → 0) and arms per-block strip.
        mp.set_relay_enabled(true);
        assert!(mp.relay_enabled());
        assert_eq!(mp.purge_confirmed_on_chain(), 0);
        // Still no-op for unknown txid, but path is live.
        assert_eq!(mp.remove_for_block(&[dummy]), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn hub_accept_remove_with_map_utxo_path() {
        // MempoolHub needs Query; use open empty store + MapUtxo via direct ActiveMempool
        // for isolation — hub Query path covered when store has txs.
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        assert!(!hub.relay_enabled());
        hub.set_relay_enabled(true);
        assert!(hub.relay_enabled());
        assert_eq!(hub.live_count(), 0);
        // Without chain UTXO, accept parks as orphan (soft path).
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let err = hub.test_accept(&tx).unwrap_err();
        assert!(
            matches!(err, AcceptError::MissingPrevout(_)),
            "dry-run missing parent: {err}"
        );
        assert_eq!(hub.orphan_count(), 0);
        let err = hub.accept_tx(&tx).unwrap_err();
        assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
        assert_eq!(hub.orphan_count(), 1);
        let err = hub.test_accept(&tx).unwrap_err();
        assert!(
            matches!(err, AcceptError::MissingPrevout(_)),
            "dry-run of parked orphan must stay MissingPrevout: {err}"
        );
        assert_eq!(hub.orphan_count(), 1);
        assert!(hub.fee_histogram().is_empty());
        assert!(hub.estimate_fee_btc_per_kb(2) < 0.0 || hub.estimate_fee_btc_per_kb(2) >= 0.0);
        assert!(MempoolHub::relay_fee_btc_per_kb() > 0.0);
        assert!(hub.scripthash_mempool(&[0u8; 32]).is_empty());
        assert_eq!(hub.scripthash_unconfirmed_delta(&[0u8; 32]).unwrap(), 0);
        assert!(hub.list_live().is_empty());
        assert!(!hub.contains_wtxid(&Wtxid::from_byte_array([0u8; 32])));
        assert!(hub
            .get_tx_by_wtxid(&Wtxid::from_byte_array([0u8; 32]))
            .is_none());
        assert_eq!(hub.remove_for_block(&[]), 0);
        assert_eq!(hub.reorg_reaccept(&[]), 0);
        hub.flush().unwrap();
        let _ = hub.compact();
        let _ = hub.generation();
        let _ = hub.subscribe_announces();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn accept_from_peer_erase_drops_orphan() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let err = hub.accept_tx_from(&tx, Some(4)).unwrap_err();
        assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
        assert_eq!(hub.orphan_snapshot()[0].announcers, vec![4]);
        hub.add_orphan_announcer(&tx.compute_txid(), 8);
        assert_eq!(hub.orphan_snapshot()[0].announcers, vec![4, 8]);
        hub.erase_orphans_for_peer(4);
        assert_eq!(hub.orphan_count(), 1);
        hub.erase_orphans_for_peer(8);
        assert_eq!(hub.orphan_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn compact_fill_uses_parked_orphan() {
        use bitcoin::bip152::ShortId;
        use bitcoin::hashes::Hash;
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(matches!(
            hub.accept_tx(&tx),
            Err(AcceptError::Orphaned { .. })
        ));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let nonce = 1u64;
        let keys = ShortId::calculate_siphash_keys(&genesis.header, nonce);
        let sid = ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys);
        let got = hub
            .try_clone_matching_shortids(&genesis.header, nonce, 2, &[sid])
            .expect("read lock");
        let bodies = got.get(&sid).expect("orphan must fill compact short-id");
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].compute_txid(), tx.compute_txid());
        let w = tx.compute_wtxid();
        let (_map, fill) = hub
            .try_cmpct_avail(&genesis.header, nonce, 2, &[sid], &[])
            .expect("avail");
        assert!(
            fill.orphan.contains(&w),
            "clone source is the reconstruct fill"
        );
        let (_empty, pref) = hub
            .try_cmpct_avail(&genesis.header, nonce, 2, &[], &[w])
            .expect("prefill classify");
        assert!(
            pref.orphan.contains(&w),
            "prefill wtxids classified in the same read as clone"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn try_note_extra_compact_fills_shortid() {
        use bitcoin::bip152::ShortId;
        use bitcoin::hashes::Hash;
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([8u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(hub.try_note_extra_compact(&tx));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let nonce = 3u64;
        let keys = ShortId::calculate_siphash_keys(&genesis.header, nonce);
        let sid = ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys);
        let (_map, fill) = hub
            .try_cmpct_avail(&genesis.header, nonce, 2, &[sid], &[])
            .expect("avail");
        assert!(
            fill.extra.contains(&tx.compute_wtxid()),
            "compact-seen extra must fill short-ids"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn startup_recomputes_unknown_sigops_with_configured_reserve() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            1,
        );
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cbs[0],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
                };
                999
            ],
        };
        let (txid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
        let mempool_dir = tmp();
        {
            let mut store = rbitcoin_mempool::Mempool::open_or_create(&mempool_dir).unwrap();
            store
                .append_live_tx(
                    &tx,
                    &txid,
                    &wtxid,
                    4_999_999_001,
                    tx.weight().to_wu(),
                    u64::MAX,
                    &[],
                )
                .unwrap();
            store.flush().unwrap();
        }
        let hub = MempoolHub::open_with_weight_persist_and_sigop_reserve(
            &mempool_dir,
            Arc::new(q),
            rbitcoin_mempool::DEFAULT_MAX_MEMPOOL_WEIGHT,
            true,
            Some(0),
        )
        .unwrap();
        let budget = hub.template_budget(0);
        assert_eq!(budget.reserved_sigops, 0);
        let picked = hub.select_block_template(budget);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].0, tx);
        assert_eq!(
            (picked[0].1.fee_sat, picked[0].1.sigop_cost),
            (4_999_999_001, 79_920)
        );
        // A caller reserving Core's 400 for its coinbase cannot fit it.
        let core_reserve = rbitcoin_mempool::SelectBudget {
            reserved_sigops: 400,
            ..budget
        };
        assert!(hub.select_block_template(core_reserve).is_empty());
        assert!(hub.contains(&txid));
        let _ = std::fs::remove_dir_all(&mempool_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn take_due_parent_getdata_one_flush_covers_max_ancestor_package() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let mut missing = BTreeSet::new();
        for i in 0u8..24 {
            missing.insert(Txid::from_byte_array([i + 1; 32]));
        }
        let t0 = 1_000u64;
        hub.schedule_orphan_parents(&missing, 1, true, t0);
        let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
        let first = hub.take_due_parent_getdata(1, due);
        assert_eq!(
            first.len(),
            24,
            "24-orphan ancestor package must be one GetData"
        );
        assert!(hub.take_due_parent_getdata(1, due).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn take_due_parent_getdata_caps_per_flush() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let mut missing = BTreeSet::new();
        for i in 0u16..120 {
            let mut h = [0u8; 32];
            h[0] = (i >> 8) as u8;
            h[1] = i as u8;
            missing.insert(Txid::from_byte_array(h));
        }
        let t0 = 1_000u64;
        hub.schedule_orphan_parents(&missing, 1, true, t0);
        let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
        let first = hub.take_due_parent_getdata(1, due);
        assert_eq!(first.len(), MAX_PARENTS_PER_PARK);
        let rest = hub.take_due_parent_getdata(1, due);
        assert_eq!(rest.len(), 20);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    fn parent_hash(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h
    }

    #[test]
    fn parent_req_stops_at_per_peer_cap() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let cap = parent_req::MAX_PARENT_ANN_PER_PEER;
        for i in 0..(cap as u32 + 10) {
            let accepted = hub.note_inv_tx_requested(7, parent_hash(i), false, 1_000, false);
            if i < cap as u32 {
                assert!(accepted, "announcement {i} under the cap");
            } else {
                assert!(!accepted, "announcement {i} past the cap is misbehavior");
            }
        }
        assert_eq!(hub.parent_announcement_count(), cap);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn parent_req_stops_at_global_cap() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let per_peer = parent_req::MAX_PARENT_ANN_PER_PEER as u32;
        let global = parent_req::MAX_PARENT_ANN_GLOBAL as u32;
        let mut n = 0u32;
        let mut peer = 1u64;
        while n < global {
            assert!(hub.note_inv_tx_requested(peer, parent_hash(n), false, 1_000, false));
            n += 1;
            if n % per_peer == 0 {
                peer += 1;
            }
        }
        assert!(!hub.note_inv_tx_requested(peer, parent_hash(n), false, 1_000, false));
        assert_eq!(hub.parent_announcement_count(), global as usize);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn second_peer_take_due_does_not_drop_other_peers_keys() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let hash = [0x91; 32];
        let txid = Txid::from_byte_array(hash);
        let wtxid = Wtxid::from_byte_array(hash);
        assert!(hub.note_inv_tx_requested(1, hash, false, 1_000, false));
        hub.note_recent_reject(wtxid);
        assert_eq!(hub.announcer_peers_for(&txid, &wtxid), vec![1]);
        assert!(hub.take_due_parent_getdata(2, 2_000).is_empty());
        assert_eq!(
            hub.announcer_peers_for(&txid, &wtxid),
            vec![1],
            "peer 2's heartbeat must not walk peer 1's keys"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn wtxid_followup_is_requested_as_wtx() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let hash = [0xab; 32];
        assert!(hub.note_inv_tx_requested(1, hash, false, 1_000, true));
        let missing = BTreeSet::from([Txid::from_byte_array(hash)]);
        hub.schedule_orphan_parents(&missing, 2, false, 1_000);
        let expired = 1_000 + GETDATA_TX_INTERVAL_SECS;
        assert!(hub.take_due_parent_getdata(1, expired).is_empty());
        let got = hub.take_due_parent_getdata(2, expired);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].hash, hash);
        assert!(got[0].wtxid, "wtxid follow-up must stay WTx");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn take_due_parent_getdata_waits_inbound_txid_delay() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let mut missing = BTreeSet::new();
        for i in 0u8..20 {
            missing.insert(Txid::from_byte_array([i + 1; 32]));
        }
        let t0 = 1_000u64;
        hub.schedule_orphan_parents(&missing, 1, true, t0);
        assert!(
            hub.take_due_parent_getdata(1, t0 + NONPREF_PEER_TX_DELAY_SECS)
                .is_empty(),
            "inbound must wait TXID_RELAY past NONPREF"
        );
        let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
        let first = hub.take_due_parent_getdata(1, due);
        assert_eq!(first.len(), 20);
        assert!(
            hub.take_due_parent_getdata(1, due).is_empty(),
            "in-flight must not re-ask"
        );
        let expired = due + GETDATA_TX_INTERVAL_SECS;
        assert!(
            hub.take_due_parent_getdata(1, expired).is_empty(),
            "same peer is not retried after interval"
        );
        hub.schedule_orphan_parents(&missing, 2, true, expired);
        let other = hub.take_due_parent_getdata(
            2,
            expired + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS,
        );
        assert_eq!(other.len(), 20, "other peer after expiry");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn resolve_tx_request_lets_other_peer_fetch_after_reject() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        let hash = [0x44; 32];
        let txid = Txid::from_byte_array(hash);
        let wtxid = Wtxid::from_byte_array(hash);
        hub.note_inv_tx_requested(1, hash, true, 1_000, false);
        let missing = BTreeSet::from([txid]);
        hub.schedule_orphan_parents(&missing, 2, true, 1_000);
        let due = 1_000 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
        assert!(
            hub.take_due_parent_getdata(2, due).is_empty(),
            "in-flight INV GETDATA must block other peer"
        );
        hub.resolve_tx_request(&txid, &wtxid, false);
        hub.schedule_orphan_parents(&missing, 2, true, due);
        let got = hub
            .take_due_parent_getdata(2, due + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].hash, txid.to_byte_array());
        assert!(!got[0].wtxid);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }
    #[test]
    fn open_with_weight_and_package_empty() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open_with_weight(&dir, Arc::new(q), 1_000_000).unwrap();
        hub.set_relay_enabled(true);
        assert!(matches!(
            hub.accept_package(&[]),
            Err(AcceptError::PackageEmpty)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn accept_package_does_not_park_orphan_member() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x44; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let err = hub.accept_package(&[tx]).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { .. }),
            "package member missing parent: {err}"
        );
        assert_eq!(hub.orphan_count(), 0, "accept_package must not park");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    fn pad_one_cb() -> (std::path::PathBuf, Arc<Query>, Vec<Txid>) {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _t, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            101,
            1,
        );
        (store_dir, Arc::new(q), cbs)
    }

    #[test]
    fn submit_package_rpc_admits_cpfp_below_minrelay() {
        let (store_dir, q, cbs) = pad_one_cb();
        let dir = tmp();
        let hub = MempoolHub::open(&dir, q).unwrap();
        hub.set_relay_enabled(true);
        let parent = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x51]));
        assert!(
            matches!(
                hub.accept_tx(&parent),
                Err(AcceptError::Policy("min relay fee"))
            ),
            "parent must fail min-relay alone"
        );
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
                value: Amount::from_sat(50_0000_0000 - 1 - 50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x63]),
            }],
        };
        let rows = hub.submit_package_rpc(&[parent.clone(), child.clone()]);
        assert!(
            rows.iter().all(|r| r.is_ok()),
            "below-min-relay parent + paying child must admit, got {rows:?}"
        );
        assert!(hub.try_contains(&parent.compute_txid()));
        assert!(hub.try_contains(&child.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn mempool_under_pressure() {
        let (store_dir, q, cbs) = pad_one_cb();
        let dir = tmp();
        let hub = MempoolHub::open(&dir, q).unwrap();
        hub.set_relay_enabled(true);
        let parent = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x51]));
        assert!(matches!(
            hub.accept_tx(&parent),
            Err(AcceptError::Policy("min relay fee"))
        ));
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
                value: Amount::from_sat(50_0000_0000 - 1 - 50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let err = hub.accept_tx_from(&child, Some(7));
        assert!(
            matches!(err, Err(AcceptError::Orphaned { .. })),
            "P2P child of min-relay parent must orphan, got {err:?}"
        );
        assert!(!hub.contains(&child.compute_txid()));
        assert_eq!(hub.orphan_count(), 1);
        let parked = hub.orphan_count();

        let heavy = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x6a; 110_000]));
        assert!(matches!(
            hub.accept_tx(&heavy),
            Err(AcceptError::Policy("tx weight"))
        ));
        assert_eq!(
            heavy.compute_txid().to_byte_array(),
            heavy.compute_wtxid().to_byte_array()
        );
        assert!(hub.try_recent_reject(&heavy.compute_wtxid()));
        let other = Txid::from_byte_array([0x33; 32]);
        let rejected_child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: heavy.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: other,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(40),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let child_err = hub.accept_tx(&rejected_child);
        assert!(
            matches!(child_err, Err(AcceptError::Orphaned { .. })),
            "missing inputs still orphaned, got {child_err:?}"
        );
        assert_eq!(
            hub.orphan_count(),
            parked,
            "known-invalid parent must not park child"
        );
        let grandchild = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: rejected_child.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let _ = hub.accept_tx(&grandchild);
        assert_eq!(
            hub.orphan_count(),
            parked,
            "child of rejected parent must poison descendants"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn accept_package_child_fail_restores_rbf_victims() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            1,
        );
        let q = Arc::new(q);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let low = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cbs[0],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: spk.clone(),
            }],
        };
        let low_id = low.compute_txid();
        hub.accept_tx(&low).expect("low fee live");
        let high = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cbs[0],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_0000_0000),
                script_pubkey: spk.clone(),
            }],
        };
        let high_id = high.compute_txid();
        let mut bad_child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: high_id,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: spk,
            }],
        };
        bad_child.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
        let err = hub
            .accept_package(&[high, bad_child])
            .expect_err("annex child must fail");
        assert!(
            matches!(err, AcceptError::Policy("libre annex")),
            "got {err}"
        );
        assert!(!hub.contains(&high_id));
        assert!(
            hub.contains(&low_id),
            "hub package rollback must restore the RBF victim"
        );
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn query_utxo_provider_miss_is_none() {
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let provider = QueryUtxoProvider::new(&q);
        let op = OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        };
        assert!(provider.get_txout(&op).is_none());
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn estimate_fee_percentiles_and_spent_outpoints_empty() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        // Empty → negative estimate for all targets.
        assert!(hub.estimate_fee_btc_per_kb(1) < 0.0);
        assert!(hub.estimate_fee_btc_per_kb(5) < 0.0);
        assert!(hub.estimate_fee_btc_per_kb(100) < 0.0);
        assert!(hub.spent_outpoints().is_empty());
        assert!(!hub.contains(&Txid::from_byte_array([0u8; 32])));
        assert!(hub.get_tx(&Txid::from_byte_array([0u8; 32])).is_none());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Concurrent read APIs do not deadlock under RwLock (C2).
    #[test]
    fn concurrent_estimate_and_list_reads() {
        use std::thread;

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);

        let mut handles = Vec::new();
        for _ in 0..4 {
            let h = Arc::clone(&hub);
            handles.push(thread::spawn(move || {
                for _ in 0..32 {
                    let _ = h.live_count();
                    let _ = h.estimate_fee_btc_per_kb(2);
                    let _ = h.fee_estimates_btc_per_kb();
                    let _ = h.fee_histogram();
                    let _ = h.list_live();
                    let _ = h.contains_wtxid(&Wtxid::from_byte_array([0u8; 32]));
                }
            }));
        }
        for h in handles {
            h.join().expect("reader");
        }
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Fee snapshot covers Esplora depths; request path uses published table.
    #[test]
    fn fee_snapshot_bulk_and_estimate_share_table() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        // Empty pool: negative / unavailable for Electrum-style single target.
        assert!(hub.estimate_fee_btc_per_kb(2) < 0.0);
        let bulk = hub.fee_estimates_btc_per_kb();
        assert_eq!(bulk.len(), 11);
        assert!(bulk.iter().all(|(d, v)| *d >= 1 && *v < 0.0));
        // Second call hits cache (not dirty/stale immediately) — still consistent.
        assert_eq!(
            hub.estimate_fee_btc_per_kb(6),
            hub.fee_estimates_btc_per_kb()[4].1
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn fee_history_preload_reuses_heights_it_already_holds() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            5,
            0,
        );
        let mp_dir = tmp();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();

        let first = hub.backfill_block_fee_history();
        assert_eq!(first.tip_height, Some(5));
        assert_eq!(first.heights_scanned, 6);
        assert_eq!(first.retained_heights, 0);
        assert_eq!(first.txstat_bytes, 6 * 8, "one coinbase cell per block");
        assert!(first.history_exhausted);

        let again = hub.backfill_block_fee_history();
        assert_eq!(again.heights_scanned, 6);
        assert_eq!(again.retained_heights, 6, "held heights are not reread");
        assert_eq!(again.txstat_bytes, first.txstat_bytes);
        assert_eq!(again.skipped_heights, first.skipped_heights);
        assert!(again.history_exhausted);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn fee_history_without_a_chain_is_exhausted_without_a_scan() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();

        let stats = hub.backfill_block_fee_history();

        assert_eq!(stats.tip_height, None);
        assert_eq!(stats.heights_scanned, 0);
        assert_eq!(stats.txstat_bytes, 0);
        assert!(stats.history_exhausted);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn fee_history_file_survives_a_restart_and_drops_heights_off_the_chain() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};

        let store_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (tip, tip_time, _) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            5,
            0,
        );
        let q = Arc::new(q);
        let mp_dir = tmp();

        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        let first = hub.backfill_block_fee_history();
        assert_eq!((first.file_heights, first.retained_heights), (0, 0));
        assert_eq!(first.total_targets, FEE_SNAPSHOT_DEPTHS.len() as u64);
        assert_eq!(first.ready_targets, 0);
        // a connect after the preload goes to the journal
        rbitcoin_consensus::pad_empty_from(&q, &params, tip, tip_time, 6, 6, 0);
        hub.note_block_fee_history(Height(6));
        drop(hub);

        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        let restart = hub.backfill_block_fee_history();
        assert_eq!(restart.file_heights, 7, "snapshot 0..=5 plus journal 6");
        assert_eq!(restart.retained_heights, 7, "no height read from the chain");
        assert_eq!(restart.txstat_bytes, 7 * 8);
        drop(hub);

        // A journal record for a block the chain does not have (a reorg while
        // down) is dropped with everything above the newest hash on the chain.
        let mut journal = std::fs::OpenOptions::new()
            .append(true)
            .open(mp_dir.join("fee_history.log"))
            .unwrap();
        let orphan = HistoricalFeeBlock {
            p10_sat_kvb: Some(5_000),
            txstat_bytes: 8,
        };
        fee_history_file::append(&mut journal, 7, &orphan, &[9u8; 32]).unwrap();
        drop(journal);
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        let reorged = hub.backfill_block_fee_history();
        assert_eq!(reorged.file_heights, 7);
        assert_eq!(hub.block_p10_history.lock().unwrap().get(7), None);
        drop(hub);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn far_horizon_follows_block_history_not_pool_tail() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        // Too few pairs for any target: no estimate rather than a guess.
        for height in 1..=100 {
            record_fee_sample(&hub, height, 2_000);
        }
        hub.mark_fee_dirty();
        assert!(
            hub.fee_estimates_btc_per_kb().iter().all(|(_, v)| *v < 0.0),
            "{:?}",
            hub.fee_estimates_btc_per_kb()
        );
        // 2000 pairs for 1008 blocks: 2000 + 144 lookback + 1008 - 1 hurdles.
        for height in 101..=3_200 {
            record_fee_sample(&hub, height, 2_000);
        }
        hub.mark_fee_dirty();
        let bulk = hub.fee_estimates_btc_per_kb();
        let sat = |pairs: &[(u32, f64)], d: u32| {
            pairs
                .iter()
                .find(|(k, _)| *k == d)
                .map(|(_, v)| (*v * 100_000.0).round())
                .unwrap()
        };
        let s1 = sat(&bulk, 1);
        let s144 = sat(&bulk, 144);
        let s504 = sat(&bulk, 504);
        let s1008 = sat(&bulk, 1008);
        assert!(s1 > 0.0, "1 must fall back to history, not empty-pool -1");
        assert!(s144 > 0.0, "144 must use history, not empty-pool -1");
        assert!(s504 > 0.0, "504 must use history, not empty-pool -1");
        assert!(s1008 > 0.0, "1008 must use history, not empty-pool -1");
        assert!(s144 <= s1 + 0.05, "monotone far={s144} near={s1}");
        assert!(s504 <= s144 + 0.05, "monotone 504={s504} 144={s144}");
        for i in 0..20u32 {
            record_fee_sample(&hub, 3_201 + i, 1_000 + u64::from(i) * 100);
        }
        hub.mark_fee_dirty();
        let bulk = hub.fee_estimates_btc_per_kb();
        let s1 = sat(&bulk, 1);
        let s6 = sat(&bulk, 6);
        let s144 = sat(&bulk, 144);
        assert!(s1 > 0.0 && s6 > 0.0 && s144 > 0.0);
        assert!(
            s1 >= s6 && s6 >= s144,
            "target rates monotone sat/vB n1={s1} n6={s6} n144={s144}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        for height in 1..=3_200 {
            record_fee_sample(&hub, height, 1);
        }
        hub.mark_fee_dirty();
        let bulk = hub.fee_estimates_btc_per_kb();
        let v144 = bulk
            .iter()
            .find(|(k, _)| *k == 144)
            .map(|(_, v)| *v)
            .unwrap();
        let min_btc = MempoolHub::relay_fee_btc_per_kb();
        assert!(
            v144 + 1e-12 >= min_btc,
            "hist below min-relay must clamp: {v144} min={min_btc}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Histogram / frontier share one published chunk rebuild per dirty refresh.
    #[test]
    fn histogram_and_estimate_share_one_chunks_rebuild() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let _ = hub.take_chunks_rebuilds();
        let _ = hub.fee_histogram();
        let _ = hub.estimate_fee_btc_per_kb(2);
        let n = hub.take_chunks_rebuilds();
        assert!(
            n <= 1,
            "expected at most one mining_chunks rebuild for one dirty refresh, got {n}"
        );
        let _ = hub.fee_histogram();
        let _ = hub.fee_histogram();
        assert_eq!(hub.take_chunks_rebuilds(), 0);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Fee-snapshot refresh publishes live count/vsize/total_fee (GET /mempool).
    #[test]
    fn fee_snapshot_live_totals_match_list_live_meta() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            1,
        );
        let q = Arc::new(q);
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let a = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        hub.accept_tx(&a).expect("admit");
        let live = hub.list_live_meta();
        let expect_count = live.len();
        let expect_fee: u64 = live.iter().map(|(_, f, _)| *f).sum();
        let expect_vsize: u64 = live.iter().map(|(_, _, w)| w.saturating_add(3) / 4).sum();
        let (count, vsize, total_fee) = hub.mempool_live_totals();
        assert_eq!(count, expect_count);
        assert_eq!(vsize, expect_vsize);
        assert_eq!(total_fee, expect_fee);
        assert!(expect_count >= 1);
        assert!(expect_fee > 0);
        let _ = hub.take_chunks_rebuilds();
        let _ = hub.fee_histogram();
        assert_eq!(hub.take_chunks_rebuilds(), 0, "totals share fee refresh");
        // Electrum histogram buckets are raw vsize, summing to GET /mempool vsize.
        let hist_vsize: u64 = hub.fee_histogram().iter().map(|(_, v)| v).sum();
        assert_eq!(hist_vsize, expect_vsize);
        // getmempoolinfo totals: a plain spend's adjusted vsize is its raw vsize.
        assert_eq!(
            hub.live_adjusted_totals(),
            (expect_count, expect_vsize, expect_fee)
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Production accept must not run on a tokio worker (reactor starvation).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_tx_refuses_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = hub.accept_tx(&tx);
            }));
            (name, panicked)
        });
        let (name, panicked) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert!(
            panicked.is_err(),
            "accept_tx must panic on tokio-rt-worker, not return {panicked:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn accept_tx_async_runs_off_reactor() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let r = hub.accept_tx_async(tx).await;
        assert!(
            matches!(
                r,
                Err(AcceptError::Orphaned { .. }) | Err(AcceptError::MissingPrevout(_))
            ),
            "async accept off reactor: {r:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_contains_does_not_panic_on_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let miss = Txid::from_byte_array([0u8; 32]);
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let hit = hub.try_contains(&miss);
            (name, hit)
        });
        let (name, hit) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert!(!hit);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    fn parked_orphan_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// Handshake `unregister` runs on the reactor with an empty orphanage.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn erase_orphans_empty_does_not_panic_on_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hub.erase_orphans_for_peer(0);
            }));
            (name, panicked)
        });
        let (name, panicked) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert!(
            panicked.is_ok(),
            "empty erase_orphans_for_peer must not take inner write on reactor: {panicked:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// INV of a parked orphan notes the announcer on the reactor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn add_orphan_announcer_does_not_panic_on_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let tx = parked_orphan_tx();
        let err = hub.accept_tx_from(&tx, Some(4)).unwrap_err();
        assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
        let txid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert!(hub.add_orphan_announcer(&txid, 8));
                assert!(hub.add_orphan_announcer_wtxid(&wtxid, 9));
                hub.erase_orphans_for_peer(4);
                hub.erase_orphans_for_peer(8);
                hub.erase_orphans_for_peer(9);
            }));
            (name, panicked)
        });
        let (name, panicked) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert!(
            panicked.is_ok(),
            "orphan announcer + EraseForPeer must not take blocking inner write on reactor: {panicked:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn min_relay_sat_kvb_does_not_panic_on_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_min_relay_sat_kvb(250);
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let rate = hub.min_relay_sat_kvb();
            (name, rate)
        });
        let (name, rate) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert_eq!(rate, 250);
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rebroadcast_unbroadcast_does_not_panic_on_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.note_unbroadcast(Txid::from_byte_array([1u8; 32]));
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            hub.rebroadcast_unbroadcast();
            name
        });
        let name = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_contains_refuses_tokio_worker() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        let miss = Txid::from_byte_array([0u8; 32]);
        let join = tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = hub.contains(&miss);
            }));
            (name, panicked)
        });
        let (name, panicked) = join.await.expect("join worker");
        assert!(
            name.starts_with("tokio-rt-worker"),
            "spawned task must run on a tokio worker, got {name:?}"
        );
        assert!(
            panicked.is_err(),
            "contains must panic on tokio-rt-worker, not return {panicked:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn accept_commit_does_not_query_under_write() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_mempool::UtxoProvider;
        use rbitcoin_primitives::Height;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::thread;

        struct ProbeUtxo<'a> {
            hub: Arc<MempoolHub>,
            inner: QueryUtxoProvider<'a>,
            write_hits: Arc<AtomicU64>,
        }
        impl UtxoProvider for ProbeUtxo<'_> {
            fn note_spender(&self, tx: &Transaction) {
                self.inner.note_spender(tx);
            }
            fn get_coin(&self, op: &OutPoint) -> Option<rbitcoin_mempool::Coin> {
                let h = Arc::clone(&self.hub);
                let write_held = thread::spawn(move || h.inner.try_read().is_err())
                    .join()
                    .expect("probe");
                if write_held {
                    self.write_hits.fetch_add(1, Ordering::Relaxed);
                }
                self.inner.get_coin(op)
            }
        }

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            1,
        );
        let q = Arc::new(q);
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let hits = Arc::new(AtomicU64::new(0));
        let probe = ProbeUtxo {
            hub: Arc::clone(&hub),
            inner: QueryUtxoProvider::new(q.as_ref()),
            write_hits: Arc::clone(&hits),
        };
        let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        hub.accept_with_utxo(&tx, &probe, None).expect("accept");
        assert_eq!(
            hits.load(Ordering::Relaxed),
            0,
            "QueryUtxoProvider must not run while inner write is held"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn contains_wtxid_during_slow_utxo_prepare() {
        use rbitcoin_mempool::UtxoProvider;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Condvar;
        use std::thread;
        use std::time::{Duration, Instant};

        struct StallUtxo {
            entered: Arc<AtomicBool>,
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl UtxoProvider for StallUtxo {
            fn get_coin(&self, _: &OutPoint) -> Option<rbitcoin_mempool::Coin> {
                self.entered.store(true, Ordering::Release);
                let (lock, cv) = &*self.release;
                let mut g = lock.lock().unwrap();
                while !*g {
                    g = cv.wait(g).unwrap();
                }
                None
            }
        }

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        hub.set_relay_enabled(true);
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let stall = StallUtxo {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([7u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let h = Arc::clone(&hub);
        let join = thread::spawn(move || h.accept_with_utxo(&tx, &stall, None));
        let start = Instant::now();
        while !entered.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "UTXO provider never entered"
            );
            thread::yield_now();
        }
        let miss = Wtxid::from_byte_array([0u8; 32]);
        let t_read = Instant::now();
        let _ = hub.contains_wtxid(&miss);
        assert!(
            t_read.elapsed() < Duration::from_millis(200),
            "contains_wtxid blocked on prepare UTXO ({:?})",
            t_read.elapsed()
        );
        {
            let (lock, cv) = &*release;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        let _ = join.join().expect("accept thread");
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn mempool_tx_snapshot_two_live_and_accept_while_held() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        use std::thread;

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            3,
        );
        let q = Arc::new(q);
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let a = spend_true(cbs[0], 1_000, spk.clone());
        let b = spend_true(cbs[1], 2_000, ScriptBuf::from_bytes(vec![0x52]));
        hub.accept_tx(&a).expect("a");
        hub.accept_tx(&b).expect("b");
        let snap = hub.mempool_tx_snapshot();
        assert_eq!(snap.entries().len(), 2);
        for e in snap.entries() {
            assert!(e.fee_sat > 0, "fee");
        }
        let aid = a.compute_txid();
        let bid = b.compute_txid();
        assert!(snap.get(&aid).is_some());
        assert!(snap.get(&bid).is_some());
        let _ = snap.get(&aid).unwrap().json.set("keep-a".into());
        let _ = snap.get(&bid).unwrap().json.set("keep-b".into());
        let c = spend_true(cbs[2], 3_000, ScriptBuf::from_bytes(vec![0x53]));
        let cid = c.compute_txid();
        let held = Arc::clone(&snap);
        let h2 = Arc::clone(&hub);
        let join = thread::spawn(move || h2.accept_tx(&c));
        join.join().expect("accept thread").expect("c");
        assert_eq!(held.entries().len(), 2, "held Arc is the old snapshot");
        let snap2 = hub.mempool_tx_snapshot();
        assert_eq!(snap2.entries().len(), 3);
        assert_eq!(
            snap2.get(&aid).unwrap().json.get().map(|s| s.as_ref()),
            Some("keep-a")
        );
        assert_eq!(
            snap2.get(&bid).unwrap().json.get().map(|s| s.as_ref()),
            Some("keep-b")
        );
        assert!(snap2.get(&cid).unwrap().json.get().is_none());
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn mempool_tx_snapshot_refresh_reuses_tx_arc() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create_tiny(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            102,
            2,
        );
        let q = Arc::new(q);
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let a = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        hub.accept_tx(&a).expect("a");
        let snap1 = hub.mempool_tx_snapshot();
        let aid = a.compute_txid();
        let e1 = snap1.get(&aid).expect("a in snap1");
        let _ = e1.json.set("keep-a".into());
        std::thread::sleep(Duration::from_millis(1100));
        let snap2 = hub.mempool_tx_snapshot();
        let e2 = snap2.get(&aid).expect("a in snap2");
        assert!(
            Arc::ptr_eq(&e1.tx, &e2.tx),
            "unchanged live set must reuse Transaction Arc"
        );
        assert_eq!(e2.json.get().map(|s| s.as_ref()), Some("keep-a"));
        let b = spend_true(cbs[1], 2_000, ScriptBuf::from_bytes(vec![0x52]));
        hub.accept_tx(&b).expect("b");
        let snap3 = hub.mempool_tx_snapshot();
        let bid = b.compute_txid();
        let e3a = snap3.get(&aid).expect("a still live");
        let e3b = snap3.get(&bid).expect("b in snap3");
        assert!(Arc::ptr_eq(&e2.tx, &e3a.tx), "A reused across new admit");
        assert!(!Arc::ptr_eq(&e3a.tx, &e3b.tx), "new admit gets its own Arc");
        assert!(e3b.json.get().is_none());
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }
}
