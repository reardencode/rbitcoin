//! Tip-mode transaction relay (P4): inv/getdata/tx + mempool announce.
//!
//! Heavy relay is **gated** on [`MempoolHub::set_relay_enabled`] (false during IBD).
//! Package admit is RPC `submitpackage` / Esplora `POST /txs/package` /
//! [`MempoolHub::accept_package`]. There is no P2P package command (BIP331
//! is not in rust-bitcoin 0.32 `NetworkMessage`; the old private `rbtpkg`
//! name is gone).

use arc_swap::ArcSwap;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_mempool::{
    default_candidate_rates, frontier_feerate_from_chunks, min_rate_for_capacity,
    weight_above_from_chunks, AcceptError, AcceptResult, ActiveMempool, ChainTipCtx, Chunk, Coin,
    FeeFlowMeter, UtxoProvider, BLOCK_WEIGHT_WU,
};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use rbitcoin_store::OutputRecord;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

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

/// Immutable published fee table + mining chunks (request path never walks the graph).
#[derive(Clone, Debug)]
struct FeeSnapshot {
    /// BTC/kB by confirm-target depth (post 0–2 mapping). Missing → treat empty.
    by_depth_btc_per_kb: HashMap<u32, f64>,
    /// Best-first mining chunks from the last refresh (histogram / frontier).
    chunks: Vec<Chunk>,
    computed_at: Instant,
}

impl FeeSnapshot {
    fn empty(now: Instant) -> Self {
        Self {
            by_depth_btc_per_kb: HashMap::new(),
            chunks: Vec::new(),
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
        for ch in &self.chunks {
            let rate = ch.fee_rate_sat_per_kvb();
            let vsize = rbitcoin_consensus::policy::get_virtual_size(ch.weight);
            *by_rate.entry(rate).or_insert(0) += vsize;
        }
        by_rate.into_iter().rev().collect()
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
        if let Some(m) = self.meter_get_coin {
            m.fetch_add(1, Ordering::Relaxed);
        }
        let tid = op.txid.to_byte_array();
        let (fk, rec) = self.query.get_tx_by_txid(&tid).ok().flatten()?;
        // Confirmed-strong spent ⇒ absent (do not admit double-spends of chain UTXOs).
        if self.query.is_outpoint_spent(&tid, op.vout).ok()? {
            return None;
        }
        let out: OutputRecord = self
            .query
            .tx_output_at_fk(fk, op.vout)
            .ok()
            .or_else(|| self.query.tx_output(&rec, op.vout).ok())?;
        let value = if out.value < 0 {
            Amount::ZERO
        } else {
            Amount::from_sat(out.value as u64)
        };
        let create_height = self.query.store().tx_height_get(fk).ok().flatten()?;
        let tip = self.query.tip_height()?.0;
        // Disconnected creates stay in Class A; they are not chain coins.
        if create_height > tip {
            return None;
        }
        // Coinbase: null prevout on input 0. `block_tx_fks` only when the input
        // record is missing (it can miss after a disconnect while the input
        // still says coinbase — `mempool_reorg`).
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
        Some(Coin {
            txout: TxOut {
                value,
                script_pubkey: ScriptBuf::from_bytes(out.script),
            },
            create_height,
            create_mtp,
            is_coinbase,
        })
    }
}

/// Cap for Esplora `/mempool/recent` (newest accepts, process-local).
pub const MEMPOOL_RECENT_CAP: usize = 32;

/// One recently accepted mempool tx (for explorer "recent" strips).
#[derive(Clone, Debug)]
pub struct RecentAccept {
    pub txid: Txid,
    pub fee_sat: u64,
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
    /// Recently confirmed package feerates (sat/kvB) for estimate floor.
    confirm_feerate_memory: Mutex<std::collections::VecDeque<u64>>,
    /// Process-local admit/confirm/evict EMA for flow-aware fee estimates.
    fee_flow: Mutex<FeeFlowMeter>,
    /// Published fee table for Electrum/Esplora (refreshed dirty ∥ max-age, singleflight).
    fee_snapshot: ArcSwap<FeeSnapshot>,
    fee_dirty: AtomicBool,
    fee_refreshing: AtomicBool,
    meter_accepts: AtomicU64,
    meter_rejects: AtomicU64,
    meter_accept_us: AtomicU64,
    meter_accept_max_us: AtomicU64,
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
    /// Core whitelist `noban` — INV immediately instead of waiting on mocktime.
    immediate_relay: AtomicBool,
    /// Last `setmocktime` (0 = wall). Used to age mempool txs for delayed INV.
    mock_now: AtomicU64,
    /// Mock/wall seconds when each live wtxid was accepted.
    accept_at: Mutex<HashMap<Wtxid, u64>>,
    /// Monotonic accept generation for `p2p_tx_privacy` (skip pre-handshake txs).
    next_accept_gen: AtomicU64,
    accept_gen: Mutex<HashMap<Wtxid, u64>>,
    /// Core `-mempoolexpiry` in seconds (default 336h).
    expiry_secs: AtomicU64,
    /// Core `-minrelaytxfee` overlay (sat/kvB). Session FeeFilter reads this
    /// without taking `inner`.
    min_relay_sat_kvb: AtomicU64,
    /// Age-INV log: `(due_secs, accept_gen) → (txid, wtxid)`. Not `inner`.
    age_inv: Mutex<BTreeMap<(u64, u64), (Txid, Wtxid)>>,
    /// Min live `accept_at` (`u64::MAX` if empty).
    min_live_accept_at: AtomicU64,
    /// Cached tip MTP for accept (`{header_fk, ctx}`).
    tip_ctx: Mutex<Option<(Fk, ChainTipCtx)>>,
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
        let dir_buf = dir.as_ref().to_path_buf();
        let mp = ActiveMempool::open_with_limit_persist(dir.as_ref(), max_weight_wu, persist)
            .map_err(|e| format!("mempool open: {e}"))?;
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
            announce,
            inv_flush,
            recent: Mutex::new(std::collections::VecDeque::with_capacity(
                MEMPOOL_RECENT_CAP,
            )),
            confirm_feerate_memory: Mutex::new(std::collections::VecDeque::with_capacity(64)),
            fee_flow: Mutex::new(FeeFlowMeter::new(Instant::now())),
            fee_snapshot: ArcSwap::from_pointee(FeeSnapshot::empty(Instant::now())),
            fee_dirty: AtomicBool::new(true),
            fee_refreshing: AtomicBool::new(false),
            meter_accepts: AtomicU64::new(0),
            meter_rejects: AtomicU64::new(0),
            meter_accept_us: AtomicU64::new(0),
            meter_accept_max_us: AtomicU64::new(0),
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
        };
        {
            let mut u = hub.unbroadcast.lock().unwrap();
            u.retain(|t| hub.contains(t));
        }
        hub.reindex_live_scripthashes();
        Ok(Arc::new(hub))
    }

    /// Output + spent-input Electrum scripthashes for a live (or just-accepted) tx.
    fn collect_tx_scripthashes(&self, tx: &Transaction, mp: &ActiveMempool) -> Vec<[u8; 32]> {
        use rbitcoin_store::script_hash;
        let mut out = Vec::with_capacity(tx.output.len() + tx.input.len());
        for o in &tx.output {
            out.push(script_hash(o.script_pubkey.as_bytes()));
        }
        let provider = QueryUtxoProvider::new(self.query.as_ref());
        for inp in &tx.input {
            let op = inp.previous_output;
            let spk = if let Some(creator) = mp.graph.creator(&op) {
                mp.get_tx(&creator)
                    .and_then(|t| t.output.get(op.vout as usize))
                    .map(|o| o.script_pubkey.as_bytes().to_vec())
            } else {
                provider
                    .get_txout(&op)
                    .map(|o| o.script_pubkey.as_bytes().to_vec())
            };
            if let Some(s) = spk {
                out.push(script_hash(&s));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn reindex_live_scripthashes(&self) {
        let g = self.lock_read();
        let mut idx = MempoolShIndex::new();
        for (txid, _) in g.graph.iter() {
            let Some(tx) = g.get_tx(txid) else { continue };
            let shs = self.collect_tx_scripthashes(tx, &g);
            idx.insert(*txid, shs);
        }
        drop(g);
        *self.sh_index.lock().unwrap() = idx;
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
        QueryUtxoProvider {
            query: self.query.as_ref(),
            need_create_mtp: AtomicBool::new(false),
            meter_get_coin: Some(&self.meter_get_coin),
            meter_block_tx_fks: Some(&self.meter_get_coin_block_tx_fks),
            meter_create_mtp: Some(&self.meter_get_coin_create_mtp),
        }
    }

    fn unindex_txid(&self, txid: &Txid) {
        self.sh_index.lock().unwrap().remove(txid);
        self.remove_relay_maps(txid);
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
            "Removed {txid} from set of unbroadcast txns before confirmation that txn was sent out"
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
            self.meter_accepts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.meter_rejects.fetch_add(1, Ordering::Relaxed);
        }
        self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
        let mut cur = self.meter_accept_max_us.load(Ordering::Relaxed);
        while us > cur {
            match self.meter_accept_max_us.compare_exchange_weak(
                cur,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
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

    /// Sample-and-reset mempool/relay counters for the tip-follow 5s DEBUG line.
    pub fn sample_reset_perf(&self) -> MempoolPerfSample {
        MempoolPerfSample {
            accepts: self.meter_accepts.swap(0, Ordering::Relaxed),
            rejects: self.meter_rejects.swap(0, Ordering::Relaxed),
            accept_us: self.meter_accept_us.swap(0, Ordering::Relaxed),
            accept_max_us: self.meter_accept_max_us.swap(0, Ordering::Relaxed),
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
            weight: r.weight,
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
    /// best chain. Per-block [`Self::remove_for_block`] is skipped while relay is
    /// off so catch-up is not paced by a large durable mempool (mainnet: 40k+
    /// live after offline). One purge at tip-mode entry is enough before relay.
    pub fn set_relay_enabled(&self, on: bool) {
        let was = self.relay_enabled.swap(on, Ordering::SeqCst);
        if on && !was {
            let n = self.purge_confirmed_on_chain();
            if n > 0 {
                rbitcoin_log::info!(
                    "mempool: purged {n} confirmed tx(s) at tip-mode entry (deferred during IBD)"
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
            if g.graph.get(t).is_some() {
                if g.remove_txid(t).is_ok() {
                    self.unindex_txid(t);
                    n += 1;
                }
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

    /// Drop every live mempool entry whose create is confirmed-strong on tip.
    ///
    /// Used once when enabling relay after catch-up. Compacts durable slots if
    /// DEAD dominates. Returns how many txs removed.
    pub fn purge_confirmed_on_chain(&self) -> usize {
        let live: Vec<Txid> = {
            let g = self.lock_read();
            g.graph.iter().map(|(t, _)| *t).collect()
        };
        if live.is_empty() {
            return 0;
        }
        let mut to_drop: Vec<Txid> = Vec::new();
        for tid in &live {
            let tid_b = tid.to_byte_array();
            let confirmed = match self.query.store().get_fk_by_txid_tip(&tid_b) {
                Ok(Some(fk)) => self.query.store().is_confirmed_strong(fk).unwrap_or(false),
                _ => false,
            };
            if confirmed {
                to_drop.push(*tid);
            }
        }
        if to_drop.is_empty() {
            return 0;
        }
        let mut g = self.lock_write();
        let mut n = 0usize;
        for tid in &to_drop {
            if g.graph.contains(tid) && g.remove_txid(tid).is_ok() {
                n += 1;
            }
        }
        if n > 0 {
            let _ = g.maybe_compact();
            self.mark_fee_dirty();
        }
        drop(g);
        if n > 0 {
            for tid in &to_drop {
                self.unindex_txid(tid);
            }
        }
        n
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

    /// Live mempool txids that passed consensus script verify at accept.
    ///
    /// Tip confirm may skip re-verifying these (same tip-era softfork flags).
    pub fn script_preverified_txids(&self) -> std::collections::HashSet<[u8; 32]> {
        use bitcoin::hashes::Hash;
        let g = self.lock_read();
        g.graph
            .iter()
            .map(|(txid, _)| txid.to_byte_array())
            .collect()
    }

    pub fn generation(&self) -> u64 {
        self.lock_read().generation()
    }

    pub fn flush(&self) -> Result<(), String> {
        self.lock_write()
            .flush()
            .map_err(|e| format!("mempool flush: {e}"))
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.lock_read().graph.contains(txid)
    }

    /// Session INV filter: never parks. Busy write → `false` (may re-getdata).
    pub fn try_contains(&self, txid: &Txid) -> bool {
        self.inner
            .try_read()
            .ok()
            .is_some_and(|g| g.graph.contains(txid))
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
        self.inner
            .try_read()
            .ok()
            .is_some_and(|g| g.graph.contains_wtxid(wtxid))
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
        crate::reactor::assert_not_reactor("mempool accept");
        self.accept_with_utxo(tx, &self.utxo_provider())
    }

    fn accept_with_utxo(
        &self,
        tx: &Transaction,
        utxo: &impl rbitcoin_mempool::UtxoProvider,
    ) -> Result<AcceptResult, AcceptError> {
        utxo.note_spender(tx);
        let t0 = Instant::now();
        let tip = self.chain_tip_ctx();

        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;

        let prep = {
            let g = self.lock_read();
            let delta = self.fee_delta(&tx.compute_txid());
            g.prepare_admit(tx, utxo, tip, delta, true)
        };
        let prep = match prep {
            Ok(p) => {
                stages.utxo_us = p.utxo_us;
                p
            }
            Err(AcceptError::Orphaned(_)) => {
                let t_lock = Instant::now();
                let mut g = self.lock_write();
                let e = g.park_orphan(tx);
                lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
                drop(g);
                let us = t0.elapsed().as_micros() as u64;
                self.meter_accept_stages(lock_us, stages);
                return self.finish_accept_err(us, e);
            }
            Err(e) => {
                let us = t0.elapsed().as_micros() as u64;
                self.meter_accept_stages(lock_us, stages);
                return self.finish_accept_err(us, e);
            }
        };

        let t_script = Instant::now();
        if let Err(e) =
            rbitcoin_consensus::verify_tx_scripts_detached(prep.prevouts.clone(), tx.clone())
        {
            let us = t0.elapsed().as_micros() as u64;
            stages.script_us = t_script.elapsed().as_micros() as u64;
            self.meter_accept_stages(lock_us, stages);
            return self.finish_accept_err(us, AcceptError::Script(e.to_string()));
        }
        stages.script_us = t_script.elapsed().as_micros() as u64;

        let prevouts = prep.prevouts.clone();
        let result = {
            let t_lock = Instant::now();
            let mut g = self.lock_write();
            g.last_accept_stages = stages;
            let r = g.commit_after_script(tx, prep, tip);
            stages = g.last_accept_stages;
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            r
        };
        if let Ok(ref ar) = result {
            for old in &ar.replaced {
                self.unindex_txid(old);
            }
            let seq = self.next_relay_seq.fetch_add(1, Ordering::Relaxed);
            let w = tx.compute_wtxid();
            self.insert_relay_maps(ar.txid, w, seq);
            self.reorg_servable.lock().unwrap().remove(&w);
        }

        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        match result {
            Ok(r) => {
                self.meter_accept_wall(us, true);
                self.note_fee_flow_admit(r.weight, r.fee_sat);
                self.push_recent(tx, &r);
                self.index_txid(r.txid, tx, &prevouts);
                let shs = self
                    .sh_index
                    .lock()
                    .unwrap()
                    .by_tx
                    .get(&r.txid)
                    .cloned()
                    .unwrap_or_default();
                self.publish_announce(&r, shs);
                self.note_template_update();
                self.promote_orphans_staged(r.txid, utxo);
                // Core: expiry checked when a new tx is added to the mempool.
                let _ = self.expire_stale();
                Ok(r)
            }
            Err(e) => self.finish_accept_err(us, e),
        }
    }

    fn promote_orphans_staged(&self, parent: Txid, utxo: &impl rbitcoin_mempool::UtxoProvider) {
        let children = {
            let mut g = self.lock_write();
            g.take_orphan_children(parent)
        };
        for child in children {
            let _ = self.accept_with_utxo(&child, utxo);
        }
    }

    /// Accept on the tokio blocking pool (never on `tokio-rt-worker`).
    pub async fn accept_tx_async(
        self: &Arc<Self>,
        tx: Transaction,
    ) -> Result<AcceptResult, AcceptError> {
        let hub = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            hub.accept_tx(&tx)
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
        let tip = self.chain_tip_ctx();

        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;

        let prep = {
            let g = self.lock_read();
            let delta = self.fee_delta(&tx.compute_txid());
            g.prepare_admit(tx, &utxo, tip, delta, false)
        };
        if let Ok(ref p) = prep {
            stages.utxo_us = p.utxo_us;
        }
        let prep = match prep {
            Ok(p) => p,
            Err(e) => {
                let us = t0.elapsed().as_micros() as u64;
                self.meter_accept_stages(lock_us, stages);
                return self.finish_accept_err(us, e);
            }
        };

        let t_script = Instant::now();
        if let Err(e) =
            rbitcoin_consensus::verify_tx_scripts_detached(prep.prevouts.clone(), tx.clone())
        {
            let us = t0.elapsed().as_micros() as u64;
            stages.script_us = t_script.elapsed().as_micros() as u64;
            self.meter_accept_stages(lock_us, stages);
            return self.finish_accept_err(us, AcceptError::Script(e.to_string()));
        }
        stages.script_us = t_script.elapsed().as_micros() as u64;

        let result = {
            let t_lock = Instant::now();
            let g = self.lock_read();
            let r = g.evaluate_after_script(tx, prep, tip);
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

    fn note_fee_flow_confirm(&self, weight: u64, fee_sat: u64) {
        let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee_sat, weight);
        if let Ok(mut m) = self.fee_flow.lock() {
            m.note_confirm(weight, rate, Instant::now());
        }
        self.mark_fee_dirty();
    }

    fn mark_fee_dirty(&self) {
        self.fee_dirty.store(true, Ordering::Release);
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
        let chunks = {
            let g = self.lock_read();
            g.graph.mining_chunks_best_first()
        };

        let now = Instant::now();
        let inflow = match self.fee_flow.lock() {
            Ok(mut flow) if flow.is_warm(now) => Some(flow.admit_rates_wu_s(now)),
            _ => None,
        };
        let candidates = default_candidate_rates();
        let min_r = rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
        let confirm_floor = self.confirm_memory_floor_sat_per_kvb();

        let mut by_depth = HashMap::with_capacity(FEE_SNAPSHOT_DEPTHS.len());
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
            let mut rate = match (projected, frontier) {
                (Some(p), Some(f)) => p.max(f),
                (Some(p), None) => p,
                (None, Some(f)) => f,
                (None, None) => {
                    let v = confirm_floor
                        .map(|r| (r as f64) / 100_000_000.0)
                        .unwrap_or(-1.0);
                    by_depth.insert(depth, v);
                    continue;
                }
            };
            rate = rate.max(min_r);
            if let Some(floor) = confirm_floor {
                rate = rate.max(floor);
            }
            by_depth.insert(depth, (rate as f64) / 100_000_000.0);
        }

        self.fee_snapshot.store(Arc::new(FeeSnapshot {
            by_depth_btc_per_kb: by_depth,
            chunks,
            computed_at: t0,
        }));
        self.fee_dirty.store(false, Ordering::Release);
    }

    fn finish_accept_err(&self, us: u64, e: AcceptError) -> Result<AcceptResult, AcceptError> {
        // Soft outcomes (already in pool / orphan / full) are not "rejects".
        let hard = !matches!(
            e,
            AcceptError::Duplicate(_)
                | AcceptError::Orphaned(_)
                | AcceptError::Policy("mempool full")
        );
        if hard {
            self.meter_accept_wall(us, false);
        } else {
            self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
        }
        Err(e)
    }

    /// Accept an ancestor package (local / Electrum path; BIP331 wire later).
    pub fn accept_package(&self, txs: &[Transaction]) -> Result<Vec<AcceptResult>, AcceptError> {
        crate::reactor::assert_not_reactor("mempool accept");
        rbitcoin_mempool::ActiveMempool::check_package_shape(txs)?;
        let t0 = Instant::now();
        let utxo = self.utxo_provider();
        let tip = self.chain_tip_ctx();
        let mut stages = rbitcoin_mempool::AcceptStageUs::default();
        let mut lock_us = 0u64;
        let mut preps = Vec::with_capacity(txs.len());
        for tx in txs {
            utxo.note_spender(tx);
            let prep = {
                let t_lock = Instant::now();
                let g = self.lock_read();
                let delta = self.fee_delta(&tx.compute_txid());
                let p = g.prepare_admit(tx, &utxo, tip, delta, true);
                lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
                p
            };
            let prep = match prep {
                Ok(p) => {
                    stages.utxo_us = stages.utxo_us.saturating_add(p.utxo_us);
                    p
                }
                Err(AcceptError::Orphaned(_)) => {
                    let t_lock = Instant::now();
                    let mut g = self.lock_write();
                    let e = g.park_orphan(tx);
                    lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
                Err(e) => {
                    let us = t0.elapsed().as_micros() as u64;
                    self.meter_accept_stages(lock_us, stages);
                    return Err(self.finish_accept_err(us, e).unwrap_err());
                }
            };
            let t_script = Instant::now();
            if let Err(e) =
                rbitcoin_consensus::verify_tx_scripts_detached(prep.prevouts.clone(), tx.clone())
            {
                let us = t0.elapsed().as_micros() as u64;
                stages.script_us = stages
                    .script_us
                    .saturating_add(t_script.elapsed().as_micros() as u64);
                self.meter_accept_stages(lock_us, stages);
                return Err(self
                    .finish_accept_err(us, AcceptError::Script(e.to_string()))
                    .unwrap_err());
            }
            stages.script_us = stages
                .script_us
                .saturating_add(t_script.elapsed().as_micros() as u64);
            preps.push(prep);
        }
        let prevouts: Vec<Vec<TxOut>> = preps.iter().map(|p| p.prevouts.clone()).collect();
        let result = {
            let t_lock = Instant::now();
            let mut g = self.lock_write();
            g.last_accept_stages = stages;
            let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
            let mut err = None;
            for (tx, prep) in txs.iter().zip(preps) {
                match g.commit_after_script(tx, prep, tip) {
                    Ok(r) => accepted.push(r),
                    Err(e) => {
                        for r in accepted.iter().rev() {
                            let _ = g.remove_txid(&r.txid);
                        }
                        err = Some(e);
                        break;
                    }
                }
            }
            stages = g.last_accept_stages;
            lock_us = lock_us.saturating_add(t_lock.elapsed().as_micros() as u64);
            match err {
                Some(e) => Err(e),
                None => Ok(accepted),
            }
        };
        let us = t0.elapsed().as_micros() as u64;
        self.meter_accept_stages(lock_us, stages);
        match result {
            Ok(res) => {
                let per = us / (res.len().max(1) as u64);
                for (i, (tx, r)) in txs.iter().zip(res.iter()).enumerate() {
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
                Ok(res)
            }
            Err(e) => {
                let hard = !matches!(
                    e,
                    AcceptError::Duplicate(_)
                        | AcceptError::Orphaned(_)
                        | AcceptError::Policy("mempool full")
                );
                if hard {
                    self.meter_accept_wall(us, false);
                } else {
                    self.meter_accept_us.fetch_add(us, Ordering::Relaxed);
                }
                Err(e)
            }
        }
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
    /// Evict live txids even when relay is off (`testmempoolaccept` dry-run
    /// rollback under `-blocksonly`). Do not sample confirm-memory.
    pub fn evict_live_txids(&self, txids: &[Txid]) -> usize {
        let utxo = self.utxo_provider();
        let n = {
            let mut g = self.lock_write();
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
            self.note_template_update();
            {
                let mut deltas = self.fee_deltas.lock().unwrap();
                for tid in txids {
                    self.unindex_txid(tid);
                    deltas.remove(tid);
                }
            }
            for tid in txids {
                self.mark_broadcast(tid);
            }
        }
        n
    }

    pub fn remove_for_block(&self, txids: &[Txid]) -> usize {
        if !self.relay_enabled() {
            return 0;
        }
        let utxo = self.utxo_provider();
        let n = {
            let mut g = self.lock_write();
            for tid in txids {
                if let Some(e) = g.graph.get(tid) {
                    let rate = e.fee_rate_sat_per_kvb();
                    self.push_confirm_memory(rate);
                    self.note_fee_flow_confirm(e.weight, e.fee_sat);
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
            self.note_template_update();
            let mut deltas = self.fee_deltas.lock().unwrap();
            for tid in txids {
                self.unindex_txid(tid);
                deltas.remove(tid);
            }
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
        if !gone.is_empty() {
            self.note_template_update();
            let mut deltas = self.fee_deltas.lock().unwrap();
            for tid in &gone {
                self.unindex_txid(tid);
                deltas.remove(tid);
            }
        }
        n + gone.len()
    }

    /// Unique txs parked waiting on missing parents (Core-class orphanage).
    pub fn orphan_count(&self) -> usize {
        self.lock_read().orphan_count()
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
        let tip = self.chain_tip_ctx();
        let prep = {
            let g = self.lock_read();
            g.prepare_admit(tx, utxo, tip, 0, true)
        };
        let prep = match prep {
            Ok(p) => p,
            Err(AcceptError::Orphaned(_)) => {
                let mut g = self.lock_write();
                return Err(g.park_orphan(tx));
            }
            Err(e) => return Err(e),
        };
        if let Err(e) =
            rbitcoin_consensus::verify_tx_scripts_detached(prep.prevouts.clone(), tx.clone())
        {
            return Err(AcceptError::Script(e.to_string()));
        }
        let prevouts = prep.prevouts.clone();
        {
            let mut g = self.lock_write();
            g.commit_after_script(tx, prep, tip)?;
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

    /// Core `info_for_relay`: entry_sequence < peer's last INV sequence.
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

    /// Block template / generate selection: mining-order live txs that fit
    /// in a block (best chunks first). Same helper GBT will use.
    pub fn select_block_txs(&self) -> Vec<Transaction> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let g = self.lock_read();
        g.select_block_txs_delta(rbitcoin_mempool::TxGraph::template_tx_weight(), |id| {
            deltas.get(&id).copied().unwrap_or(0)
        })
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

    /// Generation for `getblocktemplate.longpollid` (Core `nTransactionsUpdated`).
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

    /// Live txid + fee + weight **without** cloning bodies (RPC/Esplora stats).
    pub fn list_live_meta(&self) -> Vec<(Txid, u64, u64)> {
        self.meter_list_live_meta.fetch_add(1, Ordering::Relaxed);
        let g = self.lock_read();
        g.graph
            .iter()
            .map(|(txid, e)| (*txid, e.fee_sat, e.weight))
            .collect()
    }

    /// Fee/weight for one live mempool txid (no live-set scan).
    pub fn get_live_meta(&self, txid: &Txid) -> Option<(u64, u64)> {
        self.lock_read()
            .graph
            .get(txid)
            .map(|e| (e.fee_sat, e.weight))
    }

    pub fn try_get_live_meta(&self, txid: &Txid) -> Option<(u64, u64)> {
        self.inner
            .try_read()
            .ok()?
            .graph
            .get(txid)
            .map(|e| (e.fee_sat, e.weight))
    }

    /// Compact fill: siphash live txid/wtxid, clone **matching** bodies only.
    ///
    /// `None` if a writer holds `inner` (reconstruct without mempool this round).
    pub fn try_clone_matching_shortids(
        &self,
        header: &bitcoin::block::Header,
        nonce: u64,
        version: u32,
        short_ids: &[bitcoin::bip152::ShortId],
    ) -> Option<Vec<Transaction>> {
        use bitcoin::bip152::ShortId;
        let needed: std::collections::HashSet<ShortId> = short_ids.iter().copied().collect();
        if needed.is_empty() {
            return Some(Vec::new());
        }
        let g = self.inner.try_read().ok()?;
        let keys = ShortId::calculate_siphash_keys(header, nonce);
        let mut out = Vec::new();
        for (txid, e) in g.graph.iter() {
            let sid = if version == 1 {
                ShortId::with_siphash_keys(&txid.to_raw_hash(), keys)
            } else {
                ShortId::with_siphash_keys(&e.wtxid.to_raw_hash(), keys)
            };
            if needed.contains(&sid) {
                if let Some(tx) = g.get_tx(txid) {
                    out.push(tx.clone());
                }
            }
        }
        Some(out)
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

    /// Core `-limitclustercount` / `-limitclustersize` overlay (None = keep default).
    pub fn set_cluster_limits(&self, count: Option<u32>, size_kvb: Option<u32>) {
        self.lock_write().set_cluster_limits(count, size_kvb);
    }

    /// Core `-minrelaytxfee` overlay (sat/kvB). `0` admits any non-negative fee.
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

    /// Direct in-mempool parents and children (Core `depends` / `spentby`).
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

    /// Sequential submitpackage: keep successes, report per-tx errors. No rollback.
    pub fn submit_package_rpc(
        &self,
        txs: &[Transaction],
    ) -> Vec<Result<AcceptResult, AcceptError>> {
        txs.iter().map(|tx| self.accept_tx(tx)).collect()
    }

    /// `getmempoolcluster` payload from the live graph.
    pub fn cluster_rpc(&self, txid: &Txid) -> Option<(u64, usize, Vec<(i64, u64, Vec<Txid>)>)> {
        let deltas = self.fee_deltas.lock().unwrap().clone();
        let d = |id: Txid| deltas.get(&id).copied().unwrap_or(0);
        let g = self.lock_read();
        let c = g.graph.cluster_of_delta(txid, d)?;
        let chunks = c
            .chunks
            .iter()
            .map(|ch| (ch.fee_sat as i64, ch.weight, ch.txids.clone()))
            .collect();
        Some((c.total_weight, c.members.len(), chunks))
    }

    /// `sendrawtransaction` origin: rebroadcast until a peer getdata's it.
    pub fn note_unbroadcast(&self, txid: Txid) {
        let mut u = self.unbroadcast.lock().unwrap();
        u.insert(txid);
        persist_unbroadcast_file(&self.dir, &u);
    }

    /// Peer getdata served this txid — it is no longer unbroadcast.
    pub fn mark_broadcast(&self, txid: &Txid) {
        let mut u = self.unbroadcast.lock().unwrap();
        if u.remove(txid) {
            persist_unbroadcast_file(&self.dir, &u);
        }
    }

    /// Core `mockscheduler`: re-INV still-unbroadcast local txs (15m due-now).
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
        out.sort_by(|a, b| a.txid.cmp(&b.txid));
        out
    }

    /// Unconfirmed delta for Electrum balance (sats): +mempool outputs − spent confirmed.
    ///
    /// Uses [`MempoolShIndex`] (same as `scripthash_mempool`). A full-graph walk
    /// plus chain `get_txout` per input is ~1.5 s per empty Cake key on a live
    /// mainnet mempool.
    pub fn scripthash_unconfirmed_delta(&self, scripthash: &[u8; 32]) -> i64 {
        use rbitcoin_store::script_hash;
        let want: Vec<Txid> = self.sh_index.lock().unwrap().txs_for(scripthash).collect();
        if want.is_empty() {
            return 0;
        }
        let g = self.lock_read();
        let mut delta = 0i64;
        let provider = self.utxo_provider();
        for txid in want {
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
        delta
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
        let mut v: Vec<u64> = mem.iter().copied().collect();
        v.sort_unstable();
        Some(v[v.len() / 2].max(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB))
    }

    fn push_confirm_memory(&self, rate_sat_per_kvb: u64) {
        const CAP: usize = 64;
        let mut mem = self.confirm_feerate_memory.lock().unwrap();
        mem.push_back(rate_sat_per_kvb.max(1));
        while mem.len() > CAP {
            mem.pop_front();
        }
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
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rbitcoin-txrelay-{n}"))
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

    /// One 8-coinbase pad covers reorg-reaccept, unbroadcast persist, SH reopen,
    /// live accept/fee/package, unknown-SH delta, and accept-stage meters.
    #[test]
    fn hub_live_journey() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        use rbitcoin_store::script_hash;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        const N_CB: u32 = 8;
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
            hub.note_unbroadcast(tx.compute_txid());
            assert_eq!(hub.unbroadcast_count(), 1);
            hub.flush().expect("shutdown flush");
            drop(hub);
            let hub2 = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub2.set_relay_enabled(true);
            assert_eq!(hub2.unbroadcast_count(), 1);
            let mut rx = hub2.subscribe_announces();
            hub2.rebroadcast_unbroadcast();
            let got = rx.try_recv().expect("mockscheduler rebroadcast");
            assert_eq!(got.txid, tx.compute_txid());
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
            let parent = spend_true(cbs[3], 1_000, spk.clone());
            let pr = hub.accept_tx(&parent).expect("accept parent");
            assert_eq!(pr.txid, parent.compute_txid());
            assert!(matches!(ann_rx.try_recv(), Ok(_)));
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
            hub.accept_tx(&child).expect("child");
            let pkg = hub.accept_package(&[second]).expect("package");
            assert_eq!(pkg.len(), 1);
            assert_eq!(hub.live_count(), 3);
            assert!(hub.contains(&parent.compute_txid()));
            let wtxid = parent.compute_wtxid();
            assert!(hub.contains_wtxid(&wtxid));
            assert!(hub.get_tx_by_wtxid(&wtxid).is_some());
            assert!(!hub.fee_histogram().is_empty());
            let e1 = hub.estimate_fee_btc_per_kb(1);
            let e5 = hub.estimate_fee_btc_per_kb(5);
            let e20 = hub.estimate_fee_btc_per_kb(20);
            assert!(e1 >= 0.0 && e5 >= 0.0 && e20 >= 0.0);
            let spent = hub.spent_outpoints();
            assert!(spent.contains(&op0));
            let rows = hub.scripthash_mempool(&sh);
            assert!(rows.len() >= 2);
            assert!(rows.iter().any(|r| r.height == -1));
            let delta = hub.scripthash_unconfirmed_delta(&sh);
            assert_eq!(delta, 50_0000_0000 - 2_000 - 50_0000_0000 - 50_0000_0000);
            assert!(hub.is_relay_servable(&wtxid, hub.current_relay_seq()));
            assert!(hub.remove_for_block(&[parent.compute_txid()]) >= 1);
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
            let _ = std::fs::remove_dir_all(&mp);
        }

        {
            let mp = tmp();
            let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
            hub.set_relay_enabled(true);
            let _ = hub.sample_reset_perf();
            let mut fee_sum = 0i64;
            for (i, cbtxid) in cbs[5..8].iter().enumerate() {
                let fee = 1_000u64 + i as u64;
                fee_sum += fee as i64;
                hub.accept_tx(&spend_true(*cbtxid, fee, spk.clone()))
                    .expect("accept spend");
            }
            let n = 3u64;
            let s = hub.sample_reset_perf();
            assert_eq!(s.accepts, n);
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
            assert_eq!(hub.scripthash_unconfirmed_delta(&unused), 0);
            let s = hub.sample_reset_perf();
            assert_eq!(s.delta_prevouts, 0);
            assert_eq!(hub.scripthash_unconfirmed_delta(&sh), -fee_sum);
            let _ = std::fs::remove_dir_all(&mp);
        }

        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Parent+child expire together when mocktime past `-mempoolexpiry` and a
    /// new tx triggers the check (`mempool_expiry.py`).
    #[test]
    fn expire_stale_removes_parent_and_child_keeps_priority() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
            4,
        );
        let q = Arc::new(q);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        hub.set_expiry_hours(1);
        hub.note_mock_now(1_000);
        let parent = spend_true(cbs[0], 1_000, spk.clone());
        hub.accept_tx(&parent).expect("parent");
        hub.prioritise_tx(parent.compute_txid(), 50_000);
        let other = spend_true(cbs[1], 2_000, spk.clone());
        hub.accept_tx(&other).expect("other");
        let trigger_utxo = cbs[2];
        hub.note_mock_now(1_000 + 3600 + 5);
        let trigger = spend_true(trigger_utxo, 3_000, spk);
        hub.accept_tx(&trigger).expect("trigger expires stale");
        assert!(
            !hub.contains(&parent.compute_txid()),
            "parent must expire after mempoolexpiry"
        );
        assert!(
            !hub.contains(&other.compute_txid()),
            "sibling accepted before expiry must also expire"
        );
        assert!(hub.contains(&trigger.compute_txid()));
        assert_eq!(hub.fee_delta(&parent.compute_txid()), 50_000);
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Young admits must not walk live accept times for expiry.
    #[test]
    fn expire_stale_skips_full_scan_when_nothing_can_expire() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _tip_time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            130,
            16,
        );
        let q = Arc::new(q);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let mp = tmp();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        hub.note_mock_now(1_000);
        let _ = hub.sample_reset_perf();
        for (i, cb) in cbs.iter().enumerate() {
            hub.accept_tx(&spend_true(*cb, 1_000 + i as u64, spk.clone()))
                .expect("accept");
        }
        let s = hub.sample_reset_perf();
        assert_eq!(
            s.expire_full_scans, 0,
            "young pool must not walk accept_at for expiry (got {})",
            s.expire_full_scans
        );
        assert_eq!(hub.live_count(), 16);
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Two accepts at the same tip share one tip MTP computation.
    #[test]
    fn accept_tx_caches_tip_mtp() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let _ = hub.sample_reset_perf();
        hub.accept_tx(&spend_true(cbs[0], 1_000, spk.clone()))
            .expect("a");
        hub.accept_tx(&spend_true(cbs[1], 2_000, spk)).expect("b");
        let s = hub.sample_reset_perf();
        assert_eq!(
            s.tip_mtp, 1,
            "same tip must compute MTP once (got {})",
            s.tip_mtp
        );
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Non-coinbase, no BIP68 time-lock: no `block_tx_fks` and no create MTP.
    #[test]
    fn get_coin_skips_block_tx_fks_and_mtp_without_time_lock() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;
        use rbitcoin_store::script_hash;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let _ = std::fs::remove_dir_all(&mp);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Confirm/RBF unindex must drop `relay_seq` / `accept_at` for the gone
    /// wtxid and leave a still-live sibling indexed.
    #[test]
    fn unindex_drops_relay_seq_and_accept_at() {
        use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
        use rbitcoin_primitives::Height;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let q = Query::open_or_create(&store_dir).unwrap();
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
    fn unbroadcast_removed_log_matches_core_needle() {
        let txid = Txid::from_byte_array([0xab; 32]);
        let line = MempoolHub::unbroadcast_removed_log(&txid);
        assert_eq!(
            line,
            format!(
                "Removed {txid} from set of unbroadcast txns before confirmation that txn was sent out"
            )
        );
    }

    #[test]
    fn hub_accept_remove_with_map_utxo_path() {
        // MempoolHub needs Query; use open empty store + MapUtxo via direct ActiveMempool
        // for isolation — hub Query path covered when store has txs.
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        assert!(!hub.relay_enabled());
        hub.set_relay_enabled(true);
        assert!(hub.relay_enabled());
        assert_eq!(hub.live_count(), 0);
        // Without chain UTXO, accept parks as orphan (Core-class soft path).
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
            matches!(
                err,
                AcceptError::MissingPrevout(_) | AcceptError::Orphaned(_)
            ),
            "dry-run missing parent: {err}"
        );
        assert_eq!(hub.orphan_count(), 0);
        let err = hub.accept_tx(&tx).unwrap_err();
        assert!(matches!(err, AcceptError::Orphaned(_)), "{err}");
        assert_eq!(hub.orphan_count(), 1);
        assert!(hub.fee_histogram().is_empty());
        assert!(hub.estimate_fee_btc_per_kb(2) < 0.0 || hub.estimate_fee_btc_per_kb(2) >= 0.0);
        assert!(MempoolHub::relay_fee_btc_per_kb() > 0.0);
        assert!(hub.scripthash_mempool(&[0u8; 32]).is_empty());
        assert_eq!(hub.scripthash_unconfirmed_delta(&[0u8; 32]), 0);
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
    fn open_with_weight_and_package_empty() {
        let dir = tmp();
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
    fn query_utxo_provider_miss_is_none() {
        let store_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let q = Query::open_or_create(&store_dir).unwrap();
        let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
        // Empty → negative estimate for all targets.
        assert!(hub.estimate_fee_btc_per_kb(1) < 0.0);
        assert!(hub.estimate_fee_btc_per_kb(5) < 0.0);
        assert!(hub.estimate_fee_btc_per_kb(100) < 0.0);
        assert!(hub.spent_outpoints().is_empty());
        assert!(hub.contains(&Txid::from_byte_array([0u8; 32])) == false);
        assert!(hub.get_tx(&Txid::from_byte_array([0u8; 32])).is_none());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn recent_accepts_ring_newest_first() {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
        // Empty store: still can accept nothing without parents — just open hub.
        let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
        assert!(hub.recent_accepts().is_empty());
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    /// Concurrent read APIs do not deadlock under RwLock (C2).
    #[test]
    fn concurrent_estimate_and_list_reads() {
        use std::thread;

        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let q = Query::open_or_create(&store_dir).unwrap();
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

    /// Histogram / frontier share one published chunk rebuild per dirty refresh.
    #[test]
    fn histogram_and_estimate_share_one_chunks_rebuild() {
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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

    /// Production accept must not run on a tokio worker (reactor starvation).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_tx_refuses_tokio_worker() {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
                Err(AcceptError::Orphaned(_)) | Err(AcceptError::MissingPrevout(_))
            ),
            "async accept off reactor: {r:?}"
        );
        let _ = std::fs::remove_dir_all(&mp_dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_contains_does_not_panic_on_tokio_worker() {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn min_relay_sat_kvb_does_not_panic_on_tokio_worker() {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        hub.accept_with_utxo(&tx, &probe).expect("accept");
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

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let store_dir = tmp();
        let mp_dir = tmp();
        let q = Query::open_or_create(&store_dir).unwrap();
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
        let join = thread::spawn(move || h.accept_with_utxo(&tx, &stall));
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
}
