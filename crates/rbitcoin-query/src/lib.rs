//! Domain query layer over [`rbitcoin_store::Store`].

mod archive;
mod batch_parents;
mod block_filter;
mod catchup;
mod chain_view;
mod combined_stage;
mod confirm_load;
mod confirm_parent_cache;
mod confirm_stats;
mod connect;
mod id_map;
mod in_flight;
mod reconstruct;
mod resolved_wire;
mod run_builder_core;
mod scripthash;
mod sh_builder;
mod soft_densify;
mod sp_tweaks;
mod stamp;
pub mod testutil;
mod tx_precompute;
mod wave_prevout;
mod write_create_loc;

#[cfg(debug_assertions)]
pub use combined_stage::{body_ok_reads, reset_body_ok_reads};
pub use combined_stage::{load_creates_once, CombinedCreate};
pub use reconstruct::{BlockFeeRows, StampedTxstatBlock};
pub use resolved_wire::{BlockQueueWaveIntake, ResolvedWire};
pub use soft_densify::{
    bq_assign_stop_bytes, soft_assign_restricted, soft_confirm_window_covered,
    soft_confirm_window_n, soft_densify_band_hi, BQ_SOFT_FREE_BYTES,
};
pub use sp_tweaks::{ThinTweakRangeLimits, ThinTweakRow};
pub use tx_precompute::{decode_block_precomputes, pres_for_tip, TxPrecompute};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header as BlockHeader, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_store::{
    script_hash, HeaderRecord, InputRecord, OutputRecord, PointRecord, ScriptHashRecord,
    SpTweaksTable, Store, StoreError, StoreLayout, TxRecord,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex};

pub use confirm_stats::{
    add as note_confirm, add_dur as note_confirm_dur, ConfirmStats, ConfirmWindow, LastPinPhases,
    LastPlanBatch, LastUnionMiss, LastWritePhases, TipShSnap,
};

pub type QueryError = StoreError;

/// Electrum JSON-RPC error / Esplora 503 body when `--sh-index` is off.
pub const SCRIPTHASH_INDEX_DISABLED: &str = "scripthash index disabled";

/// Default unpaged scripthash join cap. `0` stays unlimited.
pub const DEFAULT_MAX_SH_CREATES: u32 = 10_000;

/// Result of [`Query::uring_recover`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UringRecover {
    Recovered,
    Exhausted,
}

pub(crate) fn uring_recover_credit(last_tip: Option<u32>, tip: u32) -> bool {
    match last_tip {
        None => true,
        Some(last) => tip.saturating_sub(last) >= Query::URING_RECOVER_MIN_TIP_GAP,
    }
}

/// Cheap process-owned cache occupancy for IBD `ibd: sizes` (O(1) lens + brief locks).
///
/// `conf_plans` is header plan occupancy in ConfirmParentCache. Pipeline pins /
/// prep-ahead CreatePins are metered via [`process_mem_stats`] (plan thread
/// publishes snapshots) plus conf_plans on Query.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessOwnedSizes {
    pub conf_plans: usize,
    pub sh_runs: usize,
    pub sh_heads: usize,
    /// Segmented `tx.head.*` occupancy (logical sizes; no shadow resize).
    pub head: rbitcoin_store::HeadResizeSizeSnapshot,
    /// Prep-ahead in-flight CreatePin occupancy (from load-thread atomics).
    pub inflight_layers: usize,
    pub inflight_pins: usize,
    pub inflight_bytes: u64,
    /// Confirmed hash→height map entries.
    pub h2h_keys: usize,
    /// Height-fence run count (no Vec clone).
    pub fence_runs: usize,
    /// Body-queue heights whose raw payload was dropped after lookup decode.
    pub bq_promoted: usize,
    /// Write-thread just-written `create.loc` packs (`wloc=`).
    pub wloc_packs: usize,
    pub wloc_pairs: usize,
    pub wloc_bytes: u64,
}

/// Plan-thread published heap meters for structures not owned by [`Query`].
///
/// Load publishes [`InFlight`] after note/prune; write publishes loc packs
/// from TLS after note/prune. Sampled by the ~5s IBD sizes line.
pub mod process_mem_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static INFLIGHT_LAYERS: AtomicU64 = AtomicU64::new(0);
    static INFLIGHT_PINS: AtomicU64 = AtomicU64::new(0);
    static INFLIGHT_BYTES: AtomicU64 = AtomicU64::new(0);
    static WLOC_PACKS: AtomicU64 = AtomicU64::new(0);
    static WLOC_PAIRS: AtomicU64 = AtomicU64::new(0);
    static WLOC_BYTES: AtomicU64 = AtomicU64::new(0);

    /// Publish latest prep-ahead occupancy (overwrite).
    pub fn note(inflight_layers: usize, inflight_pins: usize, inflight_bytes: u64) {
        INFLIGHT_LAYERS.store(inflight_layers as u64, Ordering::Relaxed);
        INFLIGHT_PINS.store(inflight_pins as u64, Ordering::Relaxed);
        INFLIGHT_BYTES.store(inflight_bytes, Ordering::Relaxed);
    }

    /// Write-thread loc window occupancy (TLS; no lock on Query).
    pub fn note_wloc(packs: usize, pairs: usize, bytes: u64) {
        WLOC_PACKS.store(packs as u64, Ordering::Relaxed);
        WLOC_PAIRS.store(pairs as u64, Ordering::Relaxed);
        WLOC_BYTES.store(bytes, Ordering::Relaxed);
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Snap {
        pub inflight_layers: usize,
        pub inflight_pins: usize,
        pub inflight_bytes: u64,
        pub wloc_packs: usize,
        pub wloc_pairs: usize,
        pub wloc_bytes: u64,
    }

    pub fn load() -> Snap {
        Snap {
            inflight_layers: INFLIGHT_LAYERS.load(Ordering::Relaxed) as usize,
            inflight_pins: INFLIGHT_PINS.load(Ordering::Relaxed) as usize,
            inflight_bytes: INFLIGHT_BYTES.load(Ordering::Relaxed),
            wloc_packs: WLOC_PACKS.load(Ordering::Relaxed) as usize,
            wloc_pairs: WLOC_PAIRS.load(Ordering::Relaxed) as usize,
            wloc_bytes: WLOC_BYTES.load(Ordering::Relaxed),
        }
    }
}

pub use archive::{
    input_records_from_wire, ArchiveWritePlan, CreatePin, CreatePinArc, CreatePinInner,
    WirePlanNeed,
};
pub(crate) use batch_parents::FkSet;
pub use batch_parents::{
    layout_covers_need, sparse_spender_rels, BatchParents, FkMap, U32Map, U64Map, U64Set,
};
pub use catchup::IndexMode;
pub use chain_view::{ChainView, ChainViewKind};
pub use confirm_load::SpendEdges;
pub use connect::{spawn_sh_writebehind, ConfirmPrepared};
pub use id_map::{IdMap, OutPointHasher, OutPointSet, TxidHasher, TxidMap, TxidSet};
pub use in_flight::InFlight;
pub use scripthash::{
    HistoryFilter, HistoryOrder, ScanUtxo, ScriptHashBalance, ScriptHashChainStats,
    ScriptHashHistoryItem, ScriptHashTxSummary, ScriptHashUtxo, ShJoinSlot,
};
pub use stamp::{
    fill_missing_parent_ranges, stamp_external_parents, BatchParentIds, ExternalParentStamp,
    ParentIdent,
};
pub use wave_prevout::SpendEdge;

/// One transaction to apply when connecting a block.
#[derive(Clone, Debug)]
pub struct TxApply {
    pub tx: TxRecord,
    pub inputs: Vec<InputRecord>,
    pub outputs: Vec<OutputRecord>,
}

/// One header on the best store path after the confirmed tip (IBD resume).
#[derive(Clone, Debug)]
pub struct ResumeWorkEntry {
    pub height: u32,
    pub hash: [u8; 32],
    pub header_fk: Fk,
    /// True if `header_txs` has a body for this header (Class A ready).
    pub has_body: bool,
}

type ResumeChildMap = U64Map<Vec<(Fk, [u8; 32])>>;
type ResumeSibPick = (Fk, [u8; 32], bool, u32);

/// Body-queue index plus decoded stash. Readers/writers share this one mutex.
struct BodyQueueInner {
    q: rbitcoin_store::BlockQueue,
    resolved: HashMap<u32, ResolvedWire>,
}

impl std::ops::Deref for BodyQueueInner {
    type Target = rbitcoin_store::BlockQueue;
    fn deref(&self) -> &Self::Target {
        &self.q
    }
}

impl std::ops::DerefMut for BodyQueueInner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.q
    }
}

#[derive(Default)]
struct SeqSigWitRamWindow {
    by_height: BTreeMap<u32, Vec<Fk>>,
    by_fk: U64Map<Vec<InputRecord>>,
    bytes: u64,
    evictions: u64,
}

/// SH write-behind: confirm enqueues; one Class B appender drains.
///
/// Separate mutexes on purpose: confirm enqueues on the write thread while
/// Electrum joins read `ram_head`. Do not merge pending / applying / ram_head.
struct ShWriteBehind {
    /// Process-local scripthash → body head fk (confirm append path).
    heads: Mutex<HashMap<[u8; 32], rbitcoin_store::ShHeadValue>>,
    /// Last height whose SH creates were applied after tip commit.
    /// `u64::MAX` = none.
    indexed_through: AtomicU64,
    pending: Mutex<VecDeque<connect::ShPendingJob>>,
    pending_cv: Condvar,
    /// Job popped for apply but not yet watermarked.
    applying: Mutex<Option<connect::ShPendingJob>>,
    /// `0` = none released; `h+1` = durable apply may run through height `h`.
    released_through: AtomicU32,
    /// Pending + in-flight SH creates keyed by scripthash.
    ram_head: Mutex<HashMap<[u8; 32], Vec<Fk>>>,
    /// Serializes the one Class B appender (worker vs generate drain).
    appender: Mutex<()>,
}

impl ShWriteBehind {
    fn new() -> Self {
        Self {
            heads: Mutex::new(HashMap::new()),
            indexed_through: AtomicU64::new(u64::MAX),
            pending: Mutex::new(VecDeque::new()),
            pending_cv: Condvar::new(),
            applying: Mutex::new(None),
            released_through: AtomicU32::new(0),
            ram_head: Mutex::new(HashMap::new()),
            appender: Mutex::new(()),
        }
    }
}

/// Domain query facade used by higher layers (consensus, net, RPC).
pub struct Query {
    store: Store,
    /// When false, confirm skips durable spend-annotation writes.
    spend_index: std::sync::atomic::AtomicBool,
    /// When false, archive skips durable `tx.head` inserts.
    tx_index: std::sync::atomic::AtomicBool,
    /// Height-ordered SH write-behind (one Class B appender). Confirm enqueues;
    /// [`Self::apply_sh_pending`] / the tip-follow worker drain.
    sh: ShWriteBehind,
    /// Block-structured confirm parent cache.
    confirm_parents: confirm_parent_cache::ConfirmParentCache,
    /// In-RAM body queue + lookup-promoted decoded map. One mutex (no ArcSwap).
    ///
    /// RAM-only by design: avoids double-writing every block (queue + Class A).
    /// Accepts redownload on restart and peak RAM of soft densify depth.
    block_queue: Mutex<BodyQueueInner>,
    /// Last soft-assign restricted flag (over free-byte floor; cache for meters).
    block_queue_pressure: AtomicBool,
    /// Last 1-min confirm window (`bq soft=n/win` `win`). 0 = rate unknown.
    soft_confirm_window: AtomicU32,
    /// Last contiguous height lookup dequeued into loadq (`u32::MAX` = none).
    lookup_taken_hi: AtomicU32,
    /// Highest height whose TipOnly **started** (`u32::MAX` = none).
    lookup_started_hi: AtomicU32,
    /// Max height whose Class A append committed (`u32::MAX` = none).
    class_a_hi: AtomicU32,
    /// Post-IBD SH SEAL + leftover-run discard (unsorted collect is tip finalize).
    sh_run: sh_builder::ShRunBuilder,
    /// Operator scripthash index intent (`--shindex`). When false, Class C skips
    /// SH collect/enqueue/durable write-through entirely (tip follow independent).
    sh_index_enabled: std::sync::atomic::AtomicBool,
    block_filter_enabled: std::sync::atomic::AtomicBool,
    /// Basic filters reached the tip in the post-IBD materialize step. Until
    /// then confirm leaves them alone, like scripthash in Direct.
    block_filters_sealed: std::sync::atomic::AtomicBool,
    /// Optional BIP-352 thin tweak index (`--sptweaks`). Files may exist when off.
    sp_tweaks: Mutex<Option<SpTweaksTable>>,
    sptweaks_enabled: AtomicBool,
    /// `taproot_height` used when creating the table. 0 until enabled / opened.
    sptweaks_origin: AtomicU32,
    /// Explicit [`IndexMode`] (Direct / Tip).
    index_mode_cell: std::sync::atomic::AtomicU8,
    /// Cooperative cancel for in-flight confirm load. Set on IBD SIGINT
    /// teardown so the confirm load thread aborts before process exit.
    confirm_cancel: std::sync::atomic::AtomicBool,
    /// Confirmed best-chain `hash → height` (kept for process life; ~60 MiB mainnet).
    ///
    /// Avoids O(tip) header walks on Esplora/P2P `height_of_hash`.
    height_by_hash: Mutex<HeightByHashIndex>,
    /// `reconstruct_archived_block` calls (`/raw` and Esplora size/weight).
    reconstruct_archived: AtomicU64,
    /// 0 = unlimited. Electrum + Esplora SH joins refuse above this create count.
    max_sh_creates: AtomicU32,
    /// Packed `tx.body` bytes read by [`Self::load_thin_tweaks`].
    thin_tweak_body_bytes: AtomicU64,
    /// Max fk `head_insert_many` has published (0 = never). Load polls this
    /// with the fence to prune in-flight **after** bind.
    head_drain_fk: AtomicU64,
    /// Disconnect height (valid when [`Self::disconnect_gen`] > 0).
    disconnect_height: AtomicU32,
    /// Bumped on each [`Self::disconnect_tip`]. Load drops in-flight layers.
    disconnect_gen: AtomicU64,
    /// Confirm / archive / load window meters (`ibd: perf`). One instance per Query.
    confirm_stats: Arc<ConfirmStats>,
    /// Tip height of last in-process io_uring recover (`u32::MAX` = none).
    uring_recover_tip: AtomicU32,
    /// Highest height whose seqsigwit was dropped (`u32::MAX` = none dropped).
    pruneheight: AtomicU32,
    /// Highest spill height already unlinked (`u32::MAX` = none yet).
    spill_unlinked_through: AtomicU32,
    /// Operator `--prune-seqsigwit` (advertise NETWORK_LIMITED even before a drop).
    prune_seqsigwit: AtomicBool,
    /// True while the net IBD engine is active.
    ibd_mode: AtomicBool,
    /// In prune+IBD mode, cap for recent witness kept in RAM.
    seqsigwit_ram_threshold_bytes: AtomicU64,
    /// Recent witness cache keyed by confirmed heights/create fks.
    seqsigwit_ram_window: Mutex<SeqSigWitRamWindow>,
    /// Inputs from the most recent Class A append wave (fk-keyed).
    seqsigwit_append_cache: Mutex<U64Map<Vec<InputRecord>>>,
    /// Header work-path height → hash plus work through the contiguous tip.
    ///
    /// Second map beside IBD `height_to_hash` so confirm threads can do two
    /// O(1) milestone lookups without the IBD state lock. RAM is one hash per
    /// header on that path for the process lifetime of the sync.
    milestone_path: Mutex<MilestonePath>,
}

/// Best header path published by IBD header intake.
#[derive(Default)]
struct MilestonePath {
    by_height: HashMap<u32, [u8; 32]>,
    /// Work through `work_height` when `work_valid` (big-endian).
    work_through: [u8; 32],
    work_height: u32,
    work_valid: bool,
}

/// In-process hash→height map for the confirmed tip chain (~33 MiB raw at 1e6 tips).
/// `tip == None` means empty (open / invalidate); any other tip is incremental.
#[derive(Default)]
struct HeightByHashIndex {
    /// Tip height the map matches (`None` = empty / needs rebuild).
    tip: Option<u32>,
    map: HashMap<[u8; 32], u32>,
}

impl Query {
    pub const DEFAULT_SEQSIGWIT_RAM_THRESHOLD_BYTES: u64 = 256 * 1024 * 1024;
    pub fn open_or_create(store_path: impl AsRef<Path>) -> Result<Self, QueryError> {
        Self::open_or_create_layout(StoreLayout::single(store_path.as_ref().to_path_buf()))
    }

    /// Tiny heads for tests (does not allocate Mainnet multi‑GiB files).
    pub fn open_or_create_tiny(store_path: impl AsRef<Path>) -> Result<Self, QueryError> {
        Self::open_or_create_layout(StoreLayout::tiny(store_path.as_ref().to_path_buf()))
    }

    pub fn open_or_create_layout(layout: StoreLayout) -> Result<Self, QueryError> {
        Self::open_or_create_layout_checkblocks(layout, rbitcoin_store::VERIFY_TIP_BLOCKS)
    }

    /// Same as [`Self::open_or_create_layout`] with Core `-checkblocks` window (`0` = all).
    pub fn open_or_create_layout_checkblocks(
        layout: StoreLayout,
        n: u32,
    ) -> Result<Self, QueryError> {
        write_create_loc::clear();
        let store = Store::open_or_create_layout(layout)?;
        // Core checkblocks-style tip window first so repair sees the final fence.
        let reval = store.revalidate_tip_window_n(n)?;
        if !reval.is_clean() {
            eprintln!(
                "rbitcoin: tip revalidate tip_before={:?} tip_after={:?} first_bad={:?} reason={:?} \
                 bodies_cleared={} shrunk={}",
                reval.tip_before,
                reval.tip_after,
                reval.first_bad_height,
                reval.first_bad_reason,
                reval.bodies_cleared,
                reval.tip_shrunk
            );
        }
        // One complement repair (holes + short suffix). Do not walk every strong bit.
        let repaired = store.repair_class_c_above_tip()?;
        if repaired > 0 {
            let _ = store.strong_tx.flush();
        }
        let store_path = store.path().to_path_buf();
        let (sp_tweaks, sptweaks_origin) = if SpTweaksTable::files_present(&store_path) {
            match SpTweaksTable::open(&store_path) {
                Ok(t) => {
                    let origin = t.origin_height().0;
                    (Some(t), origin)
                }
                Err(e) => {
                    eprintln!("rbitcoin: sp_tweaks open failed ({e}); treating as empty");
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };
        let (ph, prune_on) = Self::load_pruneheight(&store_path)?;
        let q = Self {
            store,
            spend_index: std::sync::atomic::AtomicBool::new(true),
            tx_index: std::sync::atomic::AtomicBool::new(true),
            sh: ShWriteBehind::new(),
            confirm_parents: confirm_parent_cache::ConfirmParentCache::new(),
            block_queue: Mutex::new(BodyQueueInner {
                q: rbitcoin_store::BlockQueue::open_or_create(&store_path)?,
                resolved: HashMap::new(),
            }),
            block_queue_pressure: AtomicBool::new(false),
            soft_confirm_window: AtomicU32::new(0),
            lookup_taken_hi: AtomicU32::new(u32::MAX),
            lookup_started_hi: AtomicU32::new(u32::MAX),
            class_a_hi: AtomicU32::new(u32::MAX),
            sh_run: sh_builder::ShRunBuilder::new(&store_path),
            // Library default: SH on (tests / enter_direct). Node sets false for
            // `--shindex` off before entering Direct.
            sh_index_enabled: std::sync::atomic::AtomicBool::new(true),
            block_filter_enabled: std::sync::atomic::AtomicBool::new(false),
            block_filters_sealed: std::sync::atomic::AtomicBool::new(false),
            sp_tweaks: Mutex::new(sp_tweaks),
            sptweaks_enabled: AtomicBool::new(false),
            sptweaks_origin: AtomicU32::new(sptweaks_origin),
            index_mode_cell: std::sync::atomic::AtomicU8::new(IndexMode::Tip as u8),
            confirm_cancel: std::sync::atomic::AtomicBool::new(false),
            height_by_hash: Mutex::new(HeightByHashIndex::default()),
            reconstruct_archived: AtomicU64::new(0),
            max_sh_creates: AtomicU32::new(DEFAULT_MAX_SH_CREATES),
            thin_tweak_body_bytes: AtomicU64::new(0),
            head_drain_fk: AtomicU64::new(0),
            disconnect_height: AtomicU32::new(0),
            disconnect_gen: AtomicU64::new(0),
            confirm_stats: Arc::new(ConfirmStats::default()),
            uring_recover_tip: AtomicU32::new(u32::MAX),
            pruneheight: AtomicU32::new(ph),
            spill_unlinked_through: AtomicU32::new(u32::MAX),
            prune_seqsigwit: AtomicBool::new(prune_on),
            ibd_mode: AtomicBool::new(false),
            seqsigwit_ram_threshold_bytes: AtomicU64::new(
                Self::DEFAULT_SEQSIGWIT_RAM_THRESHOLD_BYTES,
            ),
            seqsigwit_ram_window: Mutex::new(SeqSigWitRamWindow::default()),
            seqsigwit_append_cache: Mutex::new(U64Map::default()),
            milestone_path: Mutex::new(MilestonePath::default()),
        };
        if let Some(tip) = q.tip_height() {
            let _ = q.ensure_height_by_hash_index(tip);
        }
        q.recover_sh_writebehind()?;
        q.sweep_spill_at_or_below_pruneheight()?;
        Ok(q)
    }

    #[inline]
    pub fn confirm_stats(&self) -> &ConfirmStats {
        &self.confirm_stats
    }

    #[inline]
    pub fn confirm_stats_arc(&self) -> Arc<ConfirmStats> {
        Arc::clone(&self.confirm_stats)
    }

    fn milestone_path_lock(&self) -> std::sync::MutexGuard<'_, MilestonePath> {
        self.milestone_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Header hash at `height` on the published header path, else the
    /// confirmed chain, else a queued body. Missing is not an ancestor.
    pub fn milestone_header_at(&self, height: u32) -> Option<[u8; 32]> {
        if let Ok(Some((_, rec))) = self.header_at_height(rbitcoin_primitives::Height(height)) {
            return Some(rec.hash);
        }
        let g = self.milestone_path_lock();
        if let Some(h) = g.by_height.get(&height).copied() {
            return Some(h);
        }
        drop(g);
        self.block_queue_hash_at_height(height)
    }

    /// Work through the contiguous published header tip, if intake seeded it.
    pub fn milestone_best_work_be(&self) -> Option<[u8; 32]> {
        let g = self.milestone_path_lock();
        g.work_valid.then_some(g.work_through)
    }

    /// Record one header on the work path.
    ///
    /// `base_through_prev` is confirmed work through the parent, and only the
    /// caller that checked `prev` is the tip should pass it. Later headers
    /// extend that total when `prev` is the hash already stored at `height-1`.
    pub fn note_milestone_header(
        &self,
        height: u32,
        hash: [u8; 32],
        prev: [u8; 32],
        header_work: bitcoin::Work,
        base_through_prev: Option<bitcoin::Work>,
    ) {
        let mut g = self.milestone_path_lock();
        g.by_height.insert(height, hash);
        if let Some(base) = base_through_prev {
            if !g.work_valid || height >= g.work_height {
                let acc = base + header_work;
                g.work_through = acc.to_be_bytes();
                g.work_height = height;
                g.work_valid = true;
            }
            return;
        }
        let prev_h = match height.checked_sub(1) {
            Some(h) => h,
            None => return,
        };
        if g.work_valid
            && g.work_height == prev_h
            && g.by_height.get(&prev_h).copied() == Some(prev)
        {
            let acc = bitcoin::Work::from_be_bytes(g.work_through) + header_work;
            g.work_through = acc.to_be_bytes();
            g.work_height = height;
        }
    }

    /// Drop path slots above `height`. Unknown work after a rewind does not skip.
    pub fn clear_milestone_path_above(&self, height: u32) {
        let mut g = self.milestone_path_lock();
        g.by_height.retain(|h, _| *h <= height);
        if g.work_valid && g.work_height > height {
            g.work_valid = false;
            g.work_through = [0; 32];
        }
    }

    fn load_pruneheight(store_path: &Path) -> Result<(u32, bool), QueryError> {
        let path = store_path.join("seqsigwit.prune");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let arr: [u8; 4] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invariant: seqsigwit.prune size"))?;
                Ok((u32::from_le_bytes(arr), true))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((u32::MAX, false)),
            Err(e) => Err(StoreError::io(path, e)),
        }
    }

    pub fn prune_seqsigwit(&self) -> bool {
        self.prune_seqsigwit.load(AtomicOrdering::Acquire)
    }

    pub fn ibd_mode(&self) -> bool {
        self.ibd_mode.load(AtomicOrdering::Acquire)
    }

    pub fn set_ibd_mode(&self, on: bool) {
        self.ibd_mode.store(on, AtomicOrdering::Release);
    }

    pub fn seqsigwit_ram_threshold_bytes(&self) -> u64 {
        self.seqsigwit_ram_threshold_bytes
            .load(AtomicOrdering::Acquire)
    }

    pub fn set_seqsigwit_ram_threshold_bytes(&self, bytes: u64) -> Result<(), QueryError> {
        self.seqsigwit_ram_threshold_bytes
            .store(bytes, AtomicOrdering::Release);
        Ok(())
    }

    #[inline]
    pub fn prune_ibd_mode(&self) -> bool {
        self.prune_seqsigwit() && self.ibd_mode()
    }

    pub fn set_prune_seqsigwit(&self, on: bool) -> Result<(), QueryError> {
        let was_on = self.prune_seqsigwit();
        if !on && self.prune_seqsigwit() {
            return Err(StoreError::Layout(
                "refusing to disable prune-seqsigwit on a pruned datadir".into(),
            ));
        }
        self.prune_seqsigwit.store(on, AtomicOrdering::Release);
        if on {
            if self.pruneheight().is_none() {
                self.persist_pruneheight(u32::MAX)?;
            }
            if !was_on {
                self.seed_recent_seqsigwit_from_store()?;
            }
        } else {
            self.clear_seqsigwit_ram_window();
            self.set_pruneheight(None)?;
        }
        Ok(())
    }

    /// Durable-later watermark: creates at this height and below have no seqsigwit.
    pub fn pruneheight(&self) -> Option<Height> {
        match self.pruneheight.load(AtomicOrdering::Acquire) {
            u32::MAX => None,
            h => Some(Height(h)),
        }
    }

    pub fn set_pruneheight(&self, height: Option<Height>) -> Result<(), QueryError> {
        let v = height.map(|h| h.0).unwrap_or(u32::MAX);
        self.pruneheight.store(v, AtomicOrdering::Release);
        if height.is_some() {
            self.prune_seqsigwit.store(true, AtomicOrdering::Release);
            self.persist_pruneheight(v)?;
            self.unlink_spill_through(v)?;
            Ok(())
        } else {
            self.prune_seqsigwit.store(false, AtomicOrdering::Release);
            self.spill_unlinked_through
                .store(u32::MAX, AtomicOrdering::Release);
            self.persist_pruneheight_clear()
        }
    }

    fn unlink_spill_height(&self, height: u32) -> Result<(), QueryError> {
        let path = self.seqsigwit_spill_file(height)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(path, e)),
        }
    }

    /// Unlink `{start}..=new_h` spill files. Heights at or below `new_h` are pruned.
    fn unlink_spill_through(&self, new_h: u32) -> Result<(), QueryError> {
        if new_h == u32::MAX {
            return Ok(());
        }
        let last = self.spill_unlinked_through.load(AtomicOrdering::Acquire);
        let start = if last == u32::MAX {
            0
        } else {
            last.saturating_add(1)
        };
        if start > new_h {
            return Ok(());
        }
        let mut h = start;
        loop {
            self.unlink_spill_height(h)?;
            if h == new_h {
                break;
            }
            h += 1;
        }
        self.spill_unlinked_through
            .store(new_h, AtomicOrdering::Release);
        Ok(())
    }

    fn sweep_spill_at_or_below_pruneheight(&self) -> Result<(), QueryError> {
        let Some(ph) = self.pruneheight() else {
            return Ok(());
        };
        let dir = self.seqsigwit_spill_dir();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            self.spill_unlinked_through
                .store(ph.0, AtomicOrdering::Release);
            return Ok(());
        };
        for ent in rd {
            let ent = ent.map_err(|e| StoreError::io(&dir, e))?;
            let path = ent.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(h) = stem.parse::<u32>() else {
                continue;
            };
            if h <= ph.0 {
                std::fs::remove_file(&path).map_err(|e| StoreError::io(path, e))?;
            }
        }
        self.spill_unlinked_through
            .store(ph.0, AtomicOrdering::Release);
        Ok(())
    }

    fn persist_pruneheight(&self, v: u32) -> Result<(), QueryError> {
        let path = self.store.path().join("seqsigwit.prune");
        std::fs::write(&path, v.to_le_bytes()).map_err(|e| StoreError::io(path, e))
    }

    fn persist_pruneheight_clear(&self) -> Result<(), QueryError> {
        let path = self.store.path().join("seqsigwit.prune");
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(path, e)),
        }
    }

    pub const SEQSIGWIT_KEEP_HEIGHTS: u32 = 288;

    pub fn apply_prune_seqsigwit_tip(&self) -> Result<(), QueryError> {
        if !self.prune_seqsigwit() {
            return Ok(());
        }
        let Some(tip) = self.tip_height() else {
            return Ok(());
        };
        if tip.0 <= Self::SEQSIGWIT_KEEP_HEIGHTS {
            return Ok(());
        }
        self.set_pruneheight(Some(Height(tip.0 - Self::SEQSIGWIT_KEEP_HEIGHTS)))
    }

    /// `false` when this create's connected height is at/below [`Self::pruneheight`].
    pub fn seqsigwit_available(&self, fk: Fk) -> Result<bool, QueryError> {
        let Some(ph) = self.pruneheight() else {
            return Ok(true);
        };
        match self.store.tx_height_get(fk)? {
            None => Ok(true),
            Some(h) => Ok(h > ph.0),
        }
    }

    fn require_seqsigwit_at(&self, height: Height) -> Result<(), QueryError> {
        if let Some(ph) = self.pruneheight() {
            if height.0 <= ph.0 {
                return Err(StoreError::Pruned { height: height.0 });
            }
        }
        Ok(())
    }

    fn require_seqsigwit_fk(&self, fk: Fk) -> Result<(), QueryError> {
        if self.seqsigwit_available(fk)? {
            return Ok(());
        }
        let height = self.store.tx_height_get(fk)?.unwrap_or(0);
        Err(StoreError::Pruned { height })
    }

    fn drop_seqsigwit_ram_height(&self, height: u32) {
        let mut g = self.seqsigwit_ram_window.lock().unwrap();
        let Some(old_fks) = g.by_height.remove(&height) else {
            return;
        };
        for fk in old_fks {
            let Some(id) = fk.get() else {
                continue;
            };
            let Some(old) = g.by_fk.remove(&id) else {
                continue;
            };
            let n = old.iter().map(|i| i.encoded_len() as u64).sum();
            g.bytes = g.bytes.saturating_sub(n);
        }
    }

    pub(crate) fn clear_seqsigwit_ram_window(&self) {
        *self.seqsigwit_ram_window.lock().unwrap() = SeqSigWitRamWindow::default();
        self.seqsigwit_append_cache.lock().unwrap().clear();
    }

    #[cfg(test)]
    pub(crate) fn seqsigwit_ram_window_stats(&self) -> (usize, usize, u64, u64) {
        let g = self.seqsigwit_ram_window.lock().unwrap();
        (g.by_height.len(), g.by_fk.len(), g.bytes, g.evictions)
    }

    pub(crate) fn seqsigwit_ram_inputs(&self, fk: Fk) -> Option<Vec<InputRecord>> {
        let id = fk.get()?;
        self.seqsigwit_ram_window
            .lock()
            .unwrap()
            .by_fk
            .get(&id)
            .cloned()
    }

    fn seqsigwit_spill_dir(&self) -> std::path::PathBuf {
        self.store.path().join("seqsigwit.window")
    }

    fn seqsigwit_spill_file(&self, height: u32) -> Result<std::path::PathBuf, QueryError> {
        let dir = self.seqsigwit_spill_dir();
        let name = format!("{height}.bin");
        let stem_ok = name
            .strip_suffix(".bin")
            .and_then(|s| s.parse::<u32>().ok())
            == Some(height);
        if !stem_ok {
            return Err(StoreError::Corrupt("invariant: seqsigwit spill name"));
        }
        let path = dir.join(&name);
        if !path.starts_with(&dir) {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit spill path escaped window dir",
            ));
        }
        Ok(path)
    }

    fn persist_seqsigwit_spill_height(
        &self,
        height: Height,
        rows: &[(Fk, &[InputRecord])],
    ) -> Result<(), QueryError> {
        let dir = self.seqsigwit_spill_dir();
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::io(&dir, e))?;
        let path = self.seqsigwit_spill_file(height.0)?;
        let tmp_name = format!("{}.bin.tmp", height.0);
        if tmp_name
            .strip_suffix(".bin.tmp")
            .and_then(|s| s.parse::<u32>().ok())
            != Some(height.0)
        {
            return Err(StoreError::Corrupt("invariant: seqsigwit spill name"));
        }
        let tmp = dir.join(&tmp_name);
        if !tmp.starts_with(&dir) {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit spill path escaped window dir",
            ));
        }
        let mut out = Vec::new();
        for (fk, ins) in rows {
            let Some(id) = fk.get() else {
                continue;
            };
            out.extend_from_slice(&id.to_le_bytes());
            let mut enc = Vec::new();
            rbitcoin_store::encode_seqsigwit_with_secret(ins, &mut enc, None);
            out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
            out.extend_from_slice(&enc);
        }
        std::fs::write(&tmp, out).map_err(|e| StoreError::io(&tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::io(&path, e))
    }

    fn seqsigwit_spill_inputs_with_count(
        &self,
        fk: Fk,
        input_count: u32,
    ) -> Result<Option<Vec<InputRecord>>, QueryError> {
        if !self.prune_seqsigwit() {
            return Ok(None);
        }
        let Some(height) = self.store.tx_height_get(fk)? else {
            return Ok(None);
        };
        if self.pruneheight().is_some_and(|ph| height <= ph.0) {
            return Ok(None);
        }
        let path = self.seqsigwit_spill_file(height)?;
        let canon = match path.canonicalize() {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::io(&path, e)),
        };
        let root = self
            .seqsigwit_spill_dir()
            .canonicalize()
            .map_err(|e| StoreError::io(self.seqsigwit_spill_dir(), e))?;
        if !canon.starts_with(&root) {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit spill path escaped window dir",
            ));
        }
        let raw = match std::fs::read(&canon) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::io(&canon, e)),
        };
        let mut i = 0usize;
        let want = fk.get().ok_or(StoreError::InvalidFk)?;
        while i.saturating_add(12) <= raw.len() {
            let id = u64::from_le_bytes(raw[i..i + 8].try_into().unwrap());
            i += 8;
            let n = u32::from_le_bytes(raw[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i.saturating_add(n) > raw.len() {
                return Err(StoreError::Corrupt("seqsigwit spill short row"));
            }
            if id == want {
                let mut ins =
                    rbitcoin_store::decode_seqsigwit_secret(&raw[i..i + n], input_count, None)?;
                self.store.stamp_input_prevouts(fk, &mut ins)?;
                return Ok(Some(ins));
            }
            i += n;
        }
        Ok(None)
    }

    pub(crate) fn seqsigwit_cached_inputs(
        &self,
        fk: Fk,
        input_count: u32,
    ) -> Result<Option<Vec<InputRecord>>, QueryError> {
        if let Some(ins) = self.seqsigwit_ram_inputs(fk) {
            return Ok(Some(ins));
        }
        self.seqsigwit_spill_inputs_with_count(fk, input_count)
    }

    pub(crate) fn note_appended_seqsigwit_inputs(&self, fks: &[Fk], ins: Vec<Vec<InputRecord>>) {
        let mut cache = self.seqsigwit_append_cache.lock().unwrap();
        for (fk, inputs) in fks.iter().zip(ins) {
            if let Some(id) = fk.get() {
                cache.insert(id, inputs);
            }
        }
    }

    pub(crate) fn note_seqsigwit_ram_for_confirmed(
        &self,
        height: Height,
        tx_fks: &[Fk],
    ) -> Result<(), QueryError> {
        if !self.prune_seqsigwit() || tx_fks.is_empty() {
            return Ok(());
        }
        let threshold = self.seqsigwit_ram_threshold_bytes();
        let mut staged: Vec<(Fk, Vec<InputRecord>, u64)> = Vec::with_capacity(tx_fks.len());
        let mut appended = self.seqsigwit_append_cache.lock().unwrap();
        for &fk in tx_fks {
            let ins = if let Some(id) = fk.get() {
                if let Some(v) = appended.remove(&id) {
                    v
                } else {
                    let (_tx, ins, _outs) = self.store.get_tx_full(fk)?;
                    ins
                }
            } else {
                let (_tx, ins, _outs) = self.store.get_tx_full(fk)?;
                ins
            };
            let bytes = ins.iter().map(|i| i.encoded_len() as u64).sum();
            staged.push((fk, ins, bytes));
        }
        drop(appended);
        self.drop_seqsigwit_ram_height(height.0);
        let spill_rows: Vec<(Fk, &[InputRecord])> = staged
            .iter()
            .map(|(fk, ins, _)| (*fk, ins.as_slice()))
            .collect();
        self.persist_seqsigwit_spill_height(height, &spill_rows)?;
        if threshold == 0 {
            return Ok(());
        }
        let mut g = self.seqsigwit_ram_window.lock().unwrap();
        let mut at_height: Vec<Fk> = Vec::with_capacity(staged.len());
        for (fk, ins, bytes) in staged {
            if let Some(id) = fk.get() {
                if let Some(old) = g.by_fk.insert(id, ins) {
                    g.bytes = g
                        .bytes
                        .saturating_sub(old.iter().map(|i| i.encoded_len() as u64).sum::<u64>());
                }
                g.bytes = g.bytes.saturating_add(bytes);
                at_height.push(fk);
            }
        }
        g.by_height.insert(height.0, at_height);
        while g.by_height.len() > Self::SEQSIGWIT_KEEP_HEIGHTS as usize || g.bytes > threshold {
            let Some((&old_h, old_fks)) = g.by_height.first_key_value() else {
                break;
            };
            let old_fks = old_fks.clone();
            g.by_height.remove(&old_h);
            for fk in old_fks {
                if let Some(id) = fk.get() {
                    if let Some(old) = g.by_fk.remove(&id) {
                        g.bytes = g.bytes.saturating_sub(
                            old.iter().map(|i| i.encoded_len() as u64).sum::<u64>(),
                        );
                        g.evictions = g.evictions.saturating_add(1);
                    }
                }
            }
        }
        Ok(())
    }

    fn seed_recent_seqsigwit_from_store(&self) -> Result<(), QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(());
        };
        let from = tip
            .0
            .saturating_sub(Self::SEQSIGWIT_KEEP_HEIGHTS.saturating_sub(1));
        for h in from..=tip.0 {
            let tx_fks = match self.block_tx_fks(Height(h)) {
                Ok(v) => v,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            if tx_fks.is_empty() {
                continue;
            }
            self.note_seqsigwit_ram_for_confirmed(Height(h), &tx_fks)?;
        }
        Ok(())
    }

    /// After `head_insert_many` returned these fks (inclusive max).
    pub fn note_head_drain_fk(&self, max_fk: u64) {
        if max_fk == 0 {
            return;
        }
        self.head_drain_fk
            .fetch_max(max_fk, AtomicOrdering::Release);
    }

    pub fn head_drain_fk(&self) -> u64 {
        self.head_drain_fk.load(AtomicOrdering::Acquire)
    }

    /// Height both `tx.head` drain and the RAM fence have passed.
    ///
    /// Lookup snapshots this before TipOnly; load drops in-flight below it
    /// after the last batch of that wave. `None` when drain is 0 or the drain
    /// fk is not on the fence (Class C/fence can lead unpublished head).
    pub fn drain_and_fence_hi(&self) -> Option<u32> {
        self.store
            .height_fence_snapshot()
            .drain_and_fence_hi(self.head_drain_fk())
    }

    /// Record a tip shrink so load can drop in-flight layers for that height.
    pub(crate) fn note_disconnect_height(&self, height: u32) {
        self.disconnect_height
            .store(height, AtomicOrdering::Release);
        self.disconnect_gen.fetch_add(1, AtomicOrdering::Release);
        let rewind = if height == 0 {
            None
        } else {
            Some(height.saturating_sub(1))
        };
        self.set_lookup_taken_hi(rewind);
        self.set_lookup_started_hi(rewind);
        self.set_class_a_hi(rewind);
        self.block_queue_drop_resolved_from(height);
    }

    /// If `seen_gen` is stale, update it and return the disconnect height.
    pub fn take_disconnect(&self, seen_gen: &mut u64) -> Option<u32> {
        let g = self.disconnect_gen.load(AtomicOrdering::Acquire);
        if g <= *seen_gen {
            return None;
        }
        *seen_gen = g;
        Some(self.disconnect_height.load(AtomicOrdering::Acquire))
    }

    /// Every load pack: GC header plans to store tip.
    pub fn on_load_pack(&self) -> Result<(), QueryError> {
        if let Some(tip) = self.tip_height() {
            self.advance_parent_cache_tip(tip.0);
        }
        Ok(())
    }

    /// Request in-flight confirm to abort cooperative load (IBD SIGINT).
    pub fn request_confirm_cancel(&self) {
        self.confirm_cancel
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Clear cancel before a new confirm/IBD session.
    pub fn clear_confirm_cancel(&self) {
        self.confirm_cancel
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// True after [`Self::request_confirm_cancel`] until cleared.
    pub fn confirm_cancelled(&self) -> bool {
        self.confirm_cancel
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Last height with SH creates applied (after tip). `None` if empty chain.
    pub fn sh_indexed_through_height(&self) -> Option<u32> {
        let v = self.sh.indexed_through.load(AtomicOrdering::Acquire);
        if v == u64::MAX {
            None
        } else {
            Some(v as u32)
        }
    }

    /// Electrum/Esplora scripthash reads: operator `--sh-index` or a leftover
    /// watermark from a previous run. Never-indexed + flag off is fail-closed.
    pub fn sh_history_available(&self) -> bool {
        self.sh_index_enabled() || self.sh_indexed_through_height().is_some()
    }

    /// Advance SH watermark only after Class C tip commit.
    pub(crate) fn set_sh_indexed_through_height(&self, height: Option<u32>) {
        let v = height.map(|h| h as u64).unwrap_or(u64::MAX);
        self.sh.indexed_through.store(v, AtomicOrdering::Release);
    }

    /// Resolve txid → fk via durable `tx.head` (when the index is enabled).
    ///
    /// ConfirmParentCache is keyed by create fk only (no process-local txid map).
    /// IBD thin edges carry stamped create_fk; cold/soft paths use durable head.
    fn lookup_tx_fk(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        if self.tx_index_enabled() {
            // body_txid verify only — avoid full packed decode on probe misses.
            // TipThenAny: RPC / reconstruct may want a never-connected archive row.
            if let Some(fk) = self.store.get_fk_by_txid(txid)? {
                return Ok(Some(fk));
            }
        }
        Ok(None)
    }

    /// Public resolve by txid (durable head when index enabled).
    pub fn tx_fk_by_txid(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        self.lookup_tx_fk(txid)
    }

    /// Confirm / spentness: connected instance only (height fence Some).
    pub fn tx_fk_by_txid_tip(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        if self.tx_index_enabled() {
            return self.store.get_fk_by_txid_tip(txid);
        }
        Ok(None)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Stamped confirm-time econ for one create, or `None` if the row is unstamped.
    pub fn txstat_row(&self, fk: Fk) -> Result<Option<rbitcoin_store::TxStatRow>, QueryError> {
        self.store.txstat_row(fk)
    }

    /// Sample-and-reset archived wire-block reconstructs (Esplora `/raw` vs summary).
    pub fn sample_reset_reconstruct_archived(&self) -> u64 {
        self.reconstruct_archived.swap(0, AtomicOrdering::Relaxed)
    }

    pub const MAX_SH_CREATES_MSG: &'static str =
        "scripthash join exceeds --max-sh-creates (default 10000)";

    pub fn set_max_sh_creates(&self, n: u32) {
        self.max_sh_creates.store(n, AtomicOrdering::Relaxed);
    }

    pub fn max_sh_creates(&self) -> u32 {
        self.max_sh_creates.load(AtomicOrdering::Relaxed)
    }

    pub(crate) fn note_reconstruct_archived(&self) {
        self.reconstruct_archived
            .fetch_add(1, AtomicOrdering::Relaxed);
    }

    /// Sample-and-reset packed body bytes read by thin BIP-352 serve.
    pub fn sample_reset_thin_tweak_body_bytes(&self) -> u64 {
        self.thin_tweak_body_bytes.swap(0, AtomicOrdering::Relaxed)
    }

    pub(crate) fn note_thin_tweak_body_bytes(&self, n: u64) {
        if n > 0 {
            self.thin_tweak_body_bytes
                .fetch_add(n, AtomicOrdering::Relaxed);
        }
    }

    pub fn confirm_parent_cache(&self) -> &confirm_parent_cache::ConfirmParentCache {
        &self.confirm_parents
    }

    /// Enable/disable durable spend-annotation writes on confirm
    /// (schema v5 create-out annotations; default on).
    ///
    /// Direct IBD and Tip both annotate after Class C (`post_commit` on the wire
    /// path; [`Query::confirm_block`] on the Query Class C-only path).
    pub fn set_spend_index(&self, enabled: bool) {
        self.spend_index
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn spend_index_enabled(&self) -> bool {
        self.spend_index.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Host-friendly process-exit flush (durability for open tables).
    ///
    /// See [`rbitcoin_store::Store::flush_for_shutdown`].
    pub fn flush_for_shutdown(&self) -> Result<(), QueryError> {
        self.store.flush_for_shutdown()
    }
}

/// Outcome of [`Query::block_queue_offer`].
#[derive(Debug, Clone)]
pub struct BlockQueueOffer {
    /// In-RAM queue record id for this body.
    pub queue_id: u64,
}

impl Query {
    /// True if this outpoint is spent on the **best chain** (durable confirmed-strong).
    ///
    /// Does **not** treat archive-only point rows as spent: Class A may write
    /// edges before Class C; those spenders are not strong yet.
    pub fn is_outpoint_spent(&self, txid: &[u8; 32], vout: u32) -> Result<bool, QueryError> {
        let tip = self.tip_height().map(|h| h.0);
        self.is_outpoint_spent_at(txid, vout, tip)
    }

    /// Spentness as of a confirmed height (`None` = empty chain).
    pub fn is_outpoint_spent_at(
        &self,
        txid: &[u8; 32],
        vout: u32,
        tip: Option<u32>,
    ) -> Result<bool, QueryError> {
        self.store.has_confirmed_strong_spender_at(txid, vout, tip)
    }

    /// Unspent subset of vouts on a create (batch; store uses tx.idx when needed).
    pub fn unspent_create_vouts(
        &self,
        create_fk: Fk,
        vouts: &[u32],
    ) -> Result<Vec<u32>, QueryError> {
        self.store.unspent_create_vouts(create_fk, vouts, None)
    }

    /// Batch [`Self::unspent_create_vouts`]: one spent-range walk across creates.
    pub fn unspent_create_vouts_batch(
        &self,
        items: &[(Fk, Vec<u32>)],
    ) -> Result<Vec<Vec<u32>>, QueryError> {
        self.store.unspent_create_vouts_batch(items)
    }

    /// Enable/disable txid hash-head inserts on archive (default on). Off under
    /// milestone IBD; Class A bodies remain complete via header_txs fk lists.
    pub fn set_tx_index(&self, enabled: bool) {
        self.tx_index
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn tx_index_enabled(&self) -> bool {
        self.tx_index.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// In-RAM block queue stats: `(assign_stop_bytes, bytes, count)`.
    ///
    /// Bytes are process heap (wire payloads). First field is the densify
    /// assign-stop ([`bq_assign_stop_bytes`]; `u64::MAX` when unlimited).
    pub fn block_queue_stats(&self) -> (u64, u64, usize) {
        let g = self.block_queue.lock().unwrap();
        (bq_assign_stop_bytes(), g.bytes(), g.count())
    }

    /// In-RAM entry count (soft time-depth meter).
    pub fn block_queue_count(&self) -> usize {
        self.block_queue.lock().unwrap().count()
    }

    /// Highest height on the in-RAM body queue (`None` if empty).
    pub fn block_queue_max_height(&self) -> Option<u32> {
        self.block_queue.lock().unwrap().max_height()
    }

    /// Refresh soft-assign restricted flag from current BQ bytes (no latch).
    ///
    /// Returns true when payload is over [`BQ_SOFT_FREE_BYTES`] (densify limited
    /// to the confirm-time window). Does **not** affect peer reads or
    /// [`Self::block_queue_offer`]. `rate_blocks_per_s` is accepted for call-site
    /// compatibility; restriction is byte-only (window size is separate).
    pub fn block_queue_update_soft_pressure(&self, rate_blocks_per_s: Option<f64>) -> bool {
        self.soft_confirm_window.store(
            soft_confirm_window_n(rate_blocks_per_s),
            AtomicOrdering::Relaxed,
        );
        let depth_bytes = self.block_queue.lock().unwrap().bytes();
        let restricted = soft_assign_restricted(depth_bytes);
        self.block_queue_pressure
            .store(restricted, AtomicOrdering::Relaxed);
        restricted
    }

    /// Last published 1-min confirm window (`bq soft=n/win`). 0 if rate unknown.
    pub fn soft_confirm_window(&self) -> u32 {
        self.soft_confirm_window.load(AtomicOrdering::Relaxed)
    }

    /// Last contiguous height lookup took off the BQ (`None` if none yet).
    pub fn lookup_taken_hi(&self) -> Option<u32> {
        let h = self.lookup_taken_hi.load(AtomicOrdering::Acquire);
        if h == u32::MAX {
            None
        } else {
            Some(h)
        }
    }

    /// Publish lookup consume high-water. `None` resets (disconnect / reject).
    pub fn set_lookup_taken_hi(&self, hi: Option<u32>) {
        self.lookup_taken_hi
            .store(hi.unwrap_or(u32::MAX), AtomicOrdering::Release);
    }

    pub fn lookup_started_hi(&self) -> Option<u32> {
        let h = self.lookup_started_hi.load(AtomicOrdering::Acquire);
        if h == u32::MAX {
            None
        } else {
            Some(h)
        }
    }

    pub fn set_lookup_started_hi(&self, hi: Option<u32>) {
        self.lookup_started_hi
            .store(hi.unwrap_or(u32::MAX), AtomicOrdering::Release);
    }

    /// Advance [`Self::lookup_started_hi`] to `hi` if higher (never rewind).
    pub fn note_lookup_tiponly_start(&self, hi: u32) {
        let next = self.lookup_started_hi().unwrap_or(0).max(hi);
        self.set_lookup_started_hi(Some(next));
    }

    pub fn class_a_hi(&self) -> Option<u32> {
        let h = self.class_a_hi.load(AtomicOrdering::Acquire);
        if h == u32::MAX {
            None
        } else {
            Some(h)
        }
    }

    pub fn set_class_a_hi(&self, hi: Option<u32>) {
        self.class_a_hi
            .store(hi.unwrap_or(u32::MAX), AtomicOrdering::Release);
    }

    /// Keep Class A append loc until write of the last height whose TipOnly
    /// had started at note (`lookup_started_hi`). Write-thread TLS.
    /// No loc pread. `keep_until` is not bumped after note.
    pub fn note_write_create_loc(
        &self,
        fks: &[rbitcoin_primitives::Fk],
        loc: &[rbitcoin_store::CreateLocPair],
        pack_height: u32,
    ) {
        let keep_until =
            write_create_loc::keep_until_at_note(pack_height, self.lookup_started_hi());
        write_create_loc::with_ram(self, |ram| {
            ram.note(pack_height, keep_until, fks, loc);
        });
    }

    /// Drop loc packs whose last-started-at-note height has finished write.
    pub fn prune_write_create_loc(&self, written_hi: u32) {
        write_create_loc::with_ram(self, |ram| {
            ram.prune_written_through(written_hi);
        });
    }

    pub fn write_create_loc(
        &self,
        fk: rbitcoin_primitives::Fk,
    ) -> Option<rbitcoin_store::CreateLocPair> {
        write_create_loc::with_ram(self, |ram| ram.get(fk))
    }

    /// Densify / offer: height is already in the confirm pipeline.
    pub fn lookup_already_taken(&self, height: u32) -> bool {
        Self::lookup_taken_covers(height, self.lookup_taken_hi())
    }

    /// `taken_hi == None` means lookup has not consumed any height yet.
    pub fn lookup_taken_covers(height: u32, taken_hi: Option<u32>) -> bool {
        taken_hi.is_some_and(|hi| height <= hi)
    }

    /// Current soft-assign restricted flag (over free-byte floor).
    pub fn block_queue_soft_pressure(&self) -> bool {
        self.block_queue_pressure.load(AtomicOrdering::Relaxed)
    }

    /// Soft confirm-window count for logs / assign: `(window_n, free_mib)`.
    ///
    /// `window_n` = blocks confirm takes in [`BQ_SOFT_CONFIRM_SECS`] at rate.
    /// `free_mib` = free-byte floor in MiB (second log field when useful).
    pub fn block_queue_soft_targets(rate_blocks_per_s: Option<f64>) -> (u32, u32) {
        let win = soft_confirm_window_n(rate_blocks_per_s);
        let free_mib = (BQ_SOFT_FREE_BYTES / (1024 * 1024)) as u32;
        (win, free_mib)
    }

    /// Enqueue a raw block payload in the process-local RAM queue.
    ///
    /// **Always accepts** peer wire. Soft densify / assign-stop only limit
    /// **new getdata assign**; never refuse in-flight bodies here. Restart
    /// drops the queue (redownload); sole durable write is Class A on confirm.
    pub fn block_queue_offer(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: &[u8],
    ) -> Result<BlockQueueOffer, QueryError> {
        {
            let g = self.block_queue.lock().unwrap();
            if let Some(id) = g.id_for_height(height) {
                return Ok(BlockQueueOffer { queue_id: id });
            }
        }
        let n_inputs = rbitcoin_store::block_wire_input_count(payload);
        let owned = payload.to_vec();
        let mut g = self.block_queue.lock().unwrap();
        if let Some(id) = g.id_for_height(height) {
            return Ok(BlockQueueOffer { queue_id: id });
        }
        let id = g.enqueue_vec(height, hash, header_fk, owned, n_inputs)?;
        Ok(BlockQueueOffer { queue_id: id })
    }

    /// Direct RAM enqueue (tests / tools). Prefer [`Self::block_queue_offer`] on IBD.
    pub fn block_queue_enqueue(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: &[u8],
    ) -> Result<u64, QueryError> {
        let n_inputs = rbitcoin_store::block_wire_input_count(payload);
        let owned = payload.to_vec();
        let mut g = self.block_queue.lock().unwrap();
        g.enqueue_vec(height, hash, header_fk, owned, n_inputs)
    }

    /// Remove RAM queue entry after combined confirm-write (or permanent drop).
    pub fn block_queue_dequeue_height(&self, height: u32) -> Result<usize, QueryError> {
        let mut g = self.block_queue.lock().unwrap();
        g.resolved.remove(&height);
        g.dequeue_height(height)
    }

    /// Index-only queue entries (no payload clone). Empty after restart.
    pub fn block_queue_list_meta(&self) -> Vec<rbitcoin_store::QueuedBlockMeta> {
        let g = self.block_queue.lock().unwrap();
        g.list_meta()
    }

    /// Distinct queued heights (one lock). Lookup keep must not use `list_meta`.
    pub fn block_queue_queued_heights(&self) -> std::collections::BTreeSet<u32> {
        let g = self.block_queue.lock().unwrap();
        g.heights().into_iter().collect()
    }

    /// Lowest unresolved BQ heights `≥ path_lo` not in `skip`, capped at `cap`.
    ///
    /// One queue lock. Lookup wave select must use this instead of
    /// `list_meta` + per-height `is_resolve_complete`.
    ///
    /// Heights `≤ lookup_taken_hi` are already on loadq (`take_raw` removed
    /// the BQ row). They are not a fetch hole — start after that high-water.
    /// A missing height *above* the high-water still stops the walk.
    pub fn block_queue_unresolved_heights(
        &self,
        path_lo: u32,
        skip: &HashSet<u32>,
        cap: usize,
    ) -> Vec<u32> {
        let start = match self.lookup_taken_hi() {
            Some(hi) => path_lo.max(hi.saturating_add(1)),
            None => path_lo,
        };
        let g = self.block_queue.lock().unwrap();
        g.unresolved_heights(start, skip, cap)
    }

    /// Body-queue intake: raw payload for `height` without dequeue.
    ///
    /// Empty after lookup promote (decoded lives in [`Self::block_queue_resolved`]).
    /// Peer enqueues raw; lookup promotes to decoded-only — never both.
    pub fn block_queue_payload(&self, height: u32) -> Result<Option<Vec<u8>>, QueryError> {
        let g = self.block_queue.lock().unwrap();
        Ok(g.get_by_height(height)?.map(|q| q.payload))
    }

    /// Raw frame only. `None` when missing or already promoted.
    pub fn block_queue_raw_payload(&self, height: u32) -> Result<Option<Vec<u8>>, QueryError> {
        let g = self.block_queue.lock().unwrap();
        Ok(g.raw_payload(height))
    }

    /// Take-and-reset BQ raw-payload clone count (instance stats).
    pub fn block_queue_take_raw_clone_n(&self) -> u64 {
        let g = self.block_queue.lock().unwrap();
        g.take_raw_clone_n()
    }

    /// Payload for a block **hash** if present on the RAM queue (any height).
    ///
    /// Used by most-work reorg gather for same-height competitors that cannot
    /// share the tip's height slot under first-wins enqueue.
    pub fn block_queue_payload_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, QueryError> {
        use bitcoin::consensus::encode::serialize;
        let g = self.block_queue.lock().unwrap();
        for meta in g.list_meta() {
            if &meta.hash != hash {
                continue;
            }
            if let Some(w) = g.resolved.get(&meta.height) {
                return Ok(Some(serialize(w.block.as_ref())));
            }
            return Ok(g.get(meta.id)?.map(|q| q.payload));
        }
        Ok(None)
    }

    /// True if any RAM queue entry has `hash` (meta only — no payload clone).
    ///
    /// Prefer this over [`Self::block_queue_payload_by_hash`] on hot readiness
    /// checks (reorg densify / exploration gate).
    pub fn block_queue_has_hash(&self, hash: &[u8; 32]) -> bool {
        let g = self.block_queue.lock().unwrap();
        g.list_meta().iter().any(|m| &m.hash == hash)
    }

    /// True if the in-RAM body queue holds `height`.
    pub fn block_queue_has_height(&self, height: u32) -> bool {
        let g = self.block_queue.lock().unwrap();
        g.contains_height(height)
    }

    /// Take raw payload and remove the BQ row (lookup consume).
    pub fn block_queue_take_raw(&self, height: u32) -> Option<rbitcoin_store::TakenRaw> {
        let mut g = self.block_queue.lock().unwrap();
        g.take_raw(height)
    }

    /// Hash of the first body-queue entry at `height`, if any.
    ///
    /// Used by claim-ready so a **wrong** first-wins body at tip+1 is not treated
    /// as ready (hole forever / BadPrev thrash).
    pub fn block_queue_hash_at_height(&self, height: u32) -> Option<[u8; 32]> {
        let g = self.block_queue.lock().unwrap();
        g.hash_at_height(height)
    }

    /// Lookup finished TipOnly for this height (even if some keys missed).
    pub fn block_queue_mark_resolve_complete(&self, height: u32) -> Result<(), QueryError> {
        let mut g = self.block_queue.lock().unwrap();
        g.mark_resolve_complete(height)
    }

    pub fn block_queue_is_resolve_complete(&self, height: u32) -> bool {
        let g = self.block_queue.lock().unwrap();
        g.is_resolve_complete(height)
    }

    /// One lock: classify `heights` as still-raw vs already promoted.
    ///
    /// Skips resolve-complete rows. **Does not clone raw payloads.** Decode
    /// pulls [`Self::block_queue_raw_payload`] per height outside this lock.
    pub fn block_queue_wave_intake(&self, heights: &[u32]) -> BlockQueueWaveIntake {
        let g = self.block_queue.lock().unwrap();
        let mut out = BlockQueueWaveIntake::default();
        for &h in heights {
            if g.is_resolve_complete(h) {
                continue;
            }
            if let Some(w) = g.resolved.get(&h) {
                out.resolved.push((h, w.clone()));
            } else if g.has_raw(h) {
                out.raw.push((
                    h,
                    g.input_count_at(h).unwrap_or(0),
                    g.header_fk_at(h).unwrap_or(0),
                ));
            }
        }
        out
    }

    /// One lock: drop raw, insert decoded, charge `max(payload, decoded)`.
    pub fn block_queue_promote_wave(
        &self,
        items: Vec<(u32, ResolvedWire, u64)>,
    ) -> Result<usize, QueryError> {
        let mut g = self.block_queue.lock().unwrap();
        let charges: Vec<(u32, u64)> = items.iter().map(|(h, _, c)| (*h, *c)).collect();
        let n = g.promote_wave(&charges)?;
        for (h, w, _) in items {
            g.resolved.insert(h, w);
        }
        Ok(n)
    }

    pub fn block_queue_resolved(&self, height: u32) -> Option<ResolvedWire> {
        let g = self.block_queue.lock().unwrap();
        g.resolved.get(&height).cloned()
    }

    /// Disconnect: drop decoded stash at `height` and above.
    pub fn block_queue_drop_resolved_from(&self, height: u32) {
        let mut g = self.block_queue.lock().unwrap();
        g.resolved.retain(|&h, _| h < height);
    }

    pub fn block_queue_promoted_count(&self) -> usize {
        let g = self.block_queue.lock().unwrap();
        g.promoted_count()
    }

    pub fn block_queue_mark_resolve_complete_wave(
        &self,
        heights: &[u32],
    ) -> Result<usize, QueryError> {
        let mut g = self.block_queue.lock().unwrap();
        g.mark_resolve_complete_wave(heights)
    }

    /// Cheap process-owned cache sizes for the IBD `ibd: sizes` line.
    ///
    /// Brief mutex locks only (header plans / SH / heads). Call from the ~5s
    /// status tick — not the hot path.
    pub fn process_owned_size_snapshot(&self) -> ProcessOwnedSizes {
        // Header + tx_fks plans (not the unused scan-watermark `plans` BTreeMap).
        // Wire path always put_header_plan; conf_plans=0 was a metering bug.
        let conf_plans = self.confirm_parents.header_plan_count();
        let mem = process_mem_stats::load();
        let h2h_keys = self
            .height_by_hash
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len();
        let mut head = self.store.txs.head_resize_size_snapshot();
        head.class_c_l2_bytes = self.store.class_c_l2_resident_bytes();
        head.mphf_g_bytes = head
            .mphf_g_bytes
            .saturating_add(self.store.scripthash.mphf_g_resident_bytes());
        head.mphf_occ_bytes = self.store.scripthash.mphf_occ_resident_bytes();
        ProcessOwnedSizes {
            conf_plans,
            sh_runs: self.sh_run.on_disk_run_count(),
            sh_heads: self.sh.heads.lock().unwrap().len(),
            head,
            inflight_layers: mem.inflight_layers,
            inflight_pins: mem.inflight_pins,
            inflight_bytes: mem.inflight_bytes,
            h2h_keys,
            fence_runs: self.store.height_fence_run_count(),
            bq_promoted: self.block_queue_promoted_count(),
            wloc_packs: mem.wloc_packs,
            wloc_pairs: mem.wloc_pairs,
            wloc_bytes: mem.wloc_bytes,
        }
    }

    /// Rebuild durable `tx.head` from every Class A body (idempotent).
    ///
    /// Prefer **deleting `tx.head`** and reopening the store:
    /// [`Store::open`] / [`Query::open_or_create`] recreates an empty head and
    /// runs a full rebuild automatically. This method is for in-process recovery
    /// without a reopen (inserts only missing probe entries).
    ///
    /// `on_progress(done_bodies, total_bodies, inserted)` for operator logs.
    pub fn backfill_tx_index(
        &self,
        on_progress: impl FnMut(u64, u64, u64),
    ) -> Result<u64, QueryError> {
        self.store.txs.backfill_head(on_progress)
    }

    /// Class A tx body count (for backfill heuristics / logs).
    pub fn tx_body_count(&self) -> u64 {
        self.store.txs.count()
    }

    /// Durable `tx.head` occupied slots (for backfill heuristics / logs).
    pub fn tx_head_occupied(&self) -> u64 {
        self.store.txs.head_occupied()
    }

    /// Thin scripthash create row count (diagnostic / tip-mode logs).
    pub fn scripthash_entry_count(&self) -> u64 {
        self.store.scripthash.entry_count()
    }

    /// Multi-list spend body node count (diagnostic).
    ///
    /// Schema v5 **sole** spends do not allocate multi-list rows, so this is
    /// often 0 even with full spend annotations — do **not** treat as “points empty.”
    pub fn point_edge_count(&self) -> u64 {
        self.store.spender_list_count()
    }

    pub fn tip_height(&self) -> Option<Height> {
        self.store.tip_height()
    }

    /// Minimum tip advance between in-process io_uring recovers.
    pub const URING_RECOVER_MIN_TIP_GAP: u32 = 1000;

    pub fn uring_recover(&self, reason: &'static str) -> UringRecover {
        let tip = self.tip_height().map(|h| h.0).unwrap_or(0);
        loop {
            let last = self.uring_recover_tip.load(AtomicOrdering::Acquire);
            let last_opt = if last == u32::MAX { None } else { Some(last) };
            if !uring_recover_credit(last_opt, tip) {
                return UringRecover::Exhausted;
            }
            if self
                .uring_recover_tip
                .compare_exchange(last, tip, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
                .is_ok()
            {
                rbitcoin_store::note_uring_recover();
                rbitcoin_log::warn!("ibd: uring recover tip={tip} reason={reason}");
                return UringRecover::Recovered;
            }
        }
    }

    /// Take recover credit, or abort. Returns only after a credited recover.
    pub fn uring_recover_or_abort(&self, reason: &'static str) {
        match self.uring_recover(reason) {
            UringRecover::Recovered => {}
            UringRecover::Exhausted => {
                let msg = format!("recover credit exhausted on {reason}");
                rbitcoin_store::abort_uring_unusable(&msg);
            }
        }
    }

    /// Highest height on the RAM fence. Not the in-flight prune HWM
    /// ([`Self::drain_and_fence_hi`] — drain can lag this).
    pub fn fence_tip_height(&self) -> Option<u32> {
        self.store.fence_tip_height()
    }

    pub fn tip_header_fk(&self) -> Result<Option<Fk>, QueryError> {
        match self.tip_height() {
            None => Ok(None),
            Some(h) => Ok(self.store.confirmed.get(h)?),
        }
    }

    pub fn put_header(&self, rec: &HeaderRecord) -> Result<Fk, QueryError> {
        self.store.put_header(rec)
    }

    pub fn get_header(&self, fk: Fk) -> Result<HeaderRecord, QueryError> {
        self.store.get_header(fk)
    }

    pub fn get_header_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Fk, HeaderRecord)>, QueryError> {
        if let Some(v) = self.confirm_parents.get_header_by_hash(hash) {
            return Ok(Some(v));
        }
        self.store.get_header_by_hash(hash)
    }

    /// Header tx list: parent cache (load) then store.
    pub fn header_tx_fks(
        &self,
        header_fk: Fk,
        hash: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<Fk>>, QueryError> {
        if let Some(h) = hash {
            if let Some(fks) = self.confirm_parents.get_tx_fks_for_hash(h) {
                return Ok(Some(fks));
            }
        }
        self.store.header_txs.get_list(header_fk)
    }

    /// Load tx row from Class A store.
    pub fn get_tx(&self, fk: Fk) -> Result<TxRecord, QueryError> {
        self.store.get_tx(fk)
    }

    pub fn get_txstat(&self, fk: Fk) -> Result<Option<rbitcoin_store::TxStatRow>, QueryError> {
        self.store.get_txstat(fk)
    }

    pub fn get_tx_by_txid(&self, txid: &[u8; 32]) -> Result<Option<(Fk, TxRecord)>, QueryError> {
        if let Some(fk) = self.lookup_tx_fk(txid)? {
            return Ok(Some((fk, self.get_tx(fk)?)));
        }
        Ok(None)
    }

    /// Input `i` of a tx row (packed full body via txid→fk).
    ///
    /// Prefer [`Self::tx_input_at_fk`] when the create fk is known (packed Class A
    /// with `tx.head` off).
    pub fn tx_input(&self, tx: &TxRecord, i: u32) -> Result<InputRecord, QueryError> {
        if i >= tx.input_count {
            return Err(StoreError::NotFound);
        }
        let fk = self.lookup_tx_fk(&tx.txid)?.ok_or(StoreError::NotFound)?;
        self.tx_input_at_fk(fk, tx, i)
    }

    /// Input `i` keyed by known create fk (packed body, no head required).
    pub fn tx_input_at_fk(
        &self,
        create_fk: Fk,
        tx: &TxRecord,
        i: u32,
    ) -> Result<InputRecord, QueryError> {
        if i >= tx.input_count {
            return Err(StoreError::NotFound);
        }
        if let Some(inputs) = self.seqsigwit_cached_inputs(create_fk, tx.input_count)? {
            return inputs.get(i as usize).cloned().ok_or(StoreError::NotFound);
        }
        self.require_seqsigwit_fk(create_fk)?;
        let (_, inputs, _) = match self.store.get_tx_full(create_fk) {
            Ok(v) => v,
            Err(StoreError::NotFound) if self.prune_seqsigwit() => {
                let height = self.store.tx_height_get(create_fk)?.unwrap_or(0);
                return Err(StoreError::Pruned { height });
            }
            Err(e) => return Err(e),
        };
        inputs.get(i as usize).cloned().ok_or(StoreError::NotFound)
    }

    pub(crate) fn tx_prevouts_for_fk(&self, fk: Fk) -> Result<Vec<(Fk, u32)>, QueryError> {
        match self.store.get_tx_meta_and_prevouts(fk) {
            Ok((_, prevs)) => Ok(prevs),
            Err(StoreError::NotFound) if self.prune_seqsigwit() => {
                let tx = self.get_tx(fk)?;
                let Some(inputs) = self.seqsigwit_cached_inputs(fk, tx.input_count)? else {
                    let height = self.store.tx_height_get(fk)?.unwrap_or(0);
                    return Err(StoreError::Pruned { height });
                };
                Ok(inputs.iter().map(|i| (i.create_fk, i.prev_index)).collect())
            }
            Err(e) => Err(e),
        }
    }

    /// Output `vout` of a tx row (run-addressed).
    pub fn tx_output(&self, tx: &TxRecord, vout: u32) -> Result<OutputRecord, QueryError> {
        if vout >= tx.output_count {
            return Err(StoreError::NotFound);
        }
        if let Some(fk) = self.lookup_tx_fk(&tx.txid)? {
            return self.tx_output_at_fk(fk, vout);
        }
        Err(StoreError::NotFound)
    }

    /// Output at `vout` for a known create fk (packed Class A works without head).
    ///
    /// Outs-only Class A (`get_tx_meta_and_outputs`); does not zip `seqsigwit`.
    pub fn tx_output_at_fk(&self, create_fk: Fk, vout: u32) -> Result<OutputRecord, QueryError> {
        let (meta, outs) = self.store.get_tx_meta_and_outputs(create_fk)?;
        if vout >= meta.output_count {
            return Err(StoreError::NotFound);
        }
        outs.get(vout as usize).cloned().ok_or(StoreError::NotFound)
    }

    pub fn put_spend(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
        spending_tx_fk: Fk,
        spending_vin: u32,
    ) -> Result<Fk, QueryError> {
        self.store
            .put_spend(out_txid, out_index, spending_tx_fk, spending_vin)
    }

    /// Strong (best-chain confirmed) spenders only.
    pub fn spenders(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
    ) -> Result<Vec<PointRecord>, QueryError> {
        self.store.spenders(out_txid, out_index)
    }

    pub fn spenders_at(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
        tip: Option<u32>,
    ) -> Result<Vec<PointRecord>, QueryError> {
        self.store.spenders_at(out_txid, out_index, tip)
    }

    pub fn spenders_raw(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
    ) -> Result<Vec<PointRecord>, QueryError> {
        self.store.spenders_raw(out_txid, out_index)
    }

    /// True if the full block body is in Class A (`header_txs` present).
    ///
    /// Does **not** walk the confirmed chain (that was O(tip) per call and froze
    /// IBD when thousands of header-only rows existed). Callers that need
    /// "confirmed or archived" should check the confirmed set / tip first.
    pub fn is_block_archived(&self, hash: &[u8; 32]) -> Result<bool, QueryError> {
        let Some((fk, _)) = self.get_header_by_hash(hash)? else {
            return Ok(false);
        };
        self.header_has_class_a_body(fk.0)
    }

    /// Class A body present for this header fk (no hash-head probe).
    ///
    /// Load-split uses BQ-stamped `header_fk`. `0` is never archived.
    pub fn header_has_class_a_body(&self, header_fk: u64) -> Result<bool, QueryError> {
        let Some(fk) = Fk::new(header_fk) else {
            return Ok(false);
        };
        self.store.header_txs.has_body(fk)
    }

    /// Drop Class A body association for `hash` (header row kept; txs not freed).
    ///
    /// Use when reconstruct fails header checks (merkle mismatch): peer re-getdata
    /// can supply a good body for the same block hash.
    pub fn clear_archived_body(&self, hash: &[u8; 32]) -> Result<bool, QueryError> {
        let Some((fk, _)) = self.get_header_by_hash(hash)? else {
            return Ok(false);
        };
        let cleared = self.store.header_txs.clear_body(fk)?;
        if cleared {
            self.store.header_txs.flush()?;
        }
        Ok(cleared)
    }

    /// Total headers with a Class A body on disk (durable, any prior run).
    pub fn archived_block_count(&self) -> Result<u64, QueryError> {
        self.store.archived_block_count()
    }

    /// Rebuild the post-tip work path from durable headers + Class A bodies.
    ///
    /// IBD only remembered the ordered path in RAM. On restart it re-ran
    /// getheaders/getdata even though Class A was already on disk. This walks
    /// Build a prev→children map over all header rows and walk a most-work path
    /// for IBD ordered seeding.
    ///
    /// Prefer a **sibling of the confirmed tip** under tip’s parent when that
    /// sibling’s header subtree has **strictly more work** than tip’s own
    /// subtree (depth breaks remaining ties; Class A body only after that).
    /// Otherwise walk tip→children as before. Caps at `max` entries.
    pub fn resume_work_path_after_tip(
        &self,
        tip_hash: [u8; 32],
        tip_height: u32,
        max: usize,
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        self.resume_work_path_after_tip_excluding(tip_hash, tip_height, max, &[])
    }

    /// Like [`Self::resume_work_path_after_tip`] but omit `exclude` hashes from
    /// the child graph (invalid subtrees do not win most-work ranking).
    pub fn resume_work_path_after_tip_excluding(
        &self,
        tip_hash: [u8; 32],
        tip_height: u32,
        max: usize,
        exclude: &[[u8; 32]],
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let Some((tip_fk, tip_rec)) = self.get_header_by_hash(&tip_hash)? else {
            return Ok(Vec::new());
        };
        let n = self.store.header_count();
        if n == 0 {
            return Ok(Vec::new());
        }

        let children = Self::resume_index_children(&self.store, n, exclude)?;
        let mut score_memo: U64Map<(bitcoin::Work, u32)> = U64Map::default();
        let best_sib = self.resume_nearest_better_sib(
            tip_fk,
            tip_height,
            &tip_rec,
            &children,
            &mut score_memo,
        )?;
        self.resume_walk_best_kids(
            tip_fk,
            tip_height,
            max,
            best_sib,
            &children,
            &mut score_memo,
        )
    }

    fn resume_index_children(
        store: &rbitcoin_store::Store,
        n: u64,
        exclude: &[[u8; 32]],
    ) -> Result<ResumeChildMap, QueryError> {
        let mut children: ResumeChildMap = ResumeChildMap::default();
        for id in 1..=n {
            let fk = Fk(id);
            let rec = store.get_header(fk)?;
            if exclude.contains(&rec.hash) {
                continue;
            }
            let prev = rec.prev_fk.get().unwrap_or(0);
            children.entry(prev).or_default().push((fk, rec.hash));
        }
        Ok(children)
    }

    fn resume_nearest_better_sib(
        &self,
        tip_fk: Fk,
        tip_height: u32,
        tip_rec: &rbitcoin_store::HeaderRecord,
        children: &ResumeChildMap,
        score_memo: &mut U64Map<(bitcoin::Work, u32)>,
    ) -> Result<Option<ResumeSibPick>, QueryError> {
        const ANCESTOR_HOPS: u32 = 32;
        let mut best_sib: Option<ResumeSibPick> = None;
        let mut path_fk = tip_fk;
        let mut path_h = tip_height;
        let mut path_rec = tip_rec.clone();
        for _ in 0..ANCESTOR_HOPS {
            let Some(parent_fk) = path_rec.prev_fk.get() else {
                break;
            };
            let (path_sub_w, _path_sub_d) =
                Self::resume_subtree_score(&self.store, children, path_fk, score_memo)?;
            if let Some(sibs) = children.get(&parent_fk) {
                for &(fk, hash) in sibs {
                    if fk == path_fk {
                        continue;
                    }
                    let has_body = self.store.header_txs.has_body(fk)?;
                    let (sub_w, sub_d) =
                        Self::resume_subtree_score(&self.store, children, fk, score_memo)?;
                    if sub_w <= path_sub_w {
                        continue;
                    }
                    let take = match best_sib {
                        None => true,
                        Some((best_fk, _, best_body, _)) => {
                            let (best_w, best_d) = Self::resume_subtree_score(
                                &self.store,
                                children,
                                best_fk,
                                score_memo,
                            )?;
                            if sub_w != best_w {
                                sub_w > best_w
                            } else if sub_d != best_d {
                                sub_d > best_d
                            } else if has_body != best_body {
                                has_body && !best_body
                            } else {
                                fk.0 > best_fk.0
                            }
                        }
                    };
                    if take {
                        best_sib = Some((fk, hash, has_body, path_h));
                    }
                }
            }
            if best_sib.is_some() {
                break;
            }
            if path_h == 0 {
                break;
            }
            path_h = path_h.saturating_sub(1);
            path_fk = Fk(parent_fk);
            path_rec = self.store.get_header(path_fk)?;
        }
        Ok(best_sib)
    }

    fn resume_walk_best_kids(
        &self,
        tip_fk: Fk,
        tip_height: u32,
        max: usize,
        best_sib: Option<ResumeSibPick>,
        children: &ResumeChildMap,
        score_memo: &mut U64Map<(bitcoin::Work, u32)>,
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        let mut out = Vec::with_capacity(max.min(4096));
        let (mut cur_fk, mut height) = if let Some((fk, hash, has_body, sib_h)) = best_sib {
            out.push(ResumeWorkEntry {
                height: sib_h,
                hash,
                header_fk: fk,
                has_body,
            });
            (fk, sib_h)
        } else {
            (tip_fk, tip_height)
        };

        while out.len() < max {
            let Some(kids) = children.get(&cur_fk.0) else {
                break;
            };
            if kids.is_empty() {
                break;
            }
            let mut best: Option<(Fk, [u8; 32], bool, bitcoin::Work, u32)> = None;
            for &(fk, hash) in kids {
                let has_body = self.store.header_txs.has_body(fk)?;
                let (sub_work, depth) =
                    Self::resume_subtree_score(&self.store, children, fk, score_memo)?;
                let take = match best {
                    None => true,
                    Some((best_fk, _, best_body, best_w, best_d)) => {
                        if sub_work != best_w {
                            sub_work > best_w
                        } else if depth != best_d {
                            depth > best_d
                        } else if has_body != best_body {
                            has_body && !best_body
                        } else {
                            fk.0 > best_fk.0
                        }
                    }
                };
                if take {
                    best = Some((fk, hash, has_body, sub_work, depth));
                }
            }
            let Some((fk, hash, has_body, _, _)) = best else {
                break;
            };
            height = height.saturating_add(1);
            out.push(ResumeWorkEntry {
                height,
                hash,
                header_fk: fk,
                has_body,
            });
            cur_fk = fk;
        }
        Ok(out)
    }

    /// Max path work and depth under `root` (including root header work).
    ///
    /// Used by [`Self::resume_work_path_after_tip`] to prefer most-work children
    /// over body-only archived losers.
    ///
    /// **Iterative** post-order walk into a **shared** `memo` (one map per resume).
    /// Recursive DFS stack-overflowed (SIGSEGV) on mid-IBD restart; a fresh memo
    /// per call was O(depth²) on long header bands (each path step re-walked the
    /// remaining chain).
    ///
    /// Gray (`on_stack`) nodes are not re-pushed: a `prev_fk` cycle used to spin
    /// the IBD thread after `resume seed walk start` with no further log.
    pub(crate) fn resume_subtree_score(
        store: &rbitcoin_store::Store,
        children: &U64Map<Vec<(Fk, [u8; 32])>>,
        root: Fk,
        memo: &mut U64Map<(bitcoin::Work, u32)>,
    ) -> Result<(bitcoin::Work, u32), QueryError> {
        use bitcoin::{CompactTarget, Target};
        if let Some(&v) = memo.get(&root.0) {
            return Ok(v);
        }
        // false = first visit (push children), true = children done (fold).
        let mut on_stack: U64Set = U64Set::default();
        let mut stack: Vec<(Fk, bool)> = Vec::with_capacity(256);
        stack.push((root, false));
        while let Some((fk, children_done)) = stack.pop() {
            if memo.contains_key(&fk.0) {
                on_stack.remove(&fk.0);
                continue;
            }
            if !children_done {
                if !on_stack.insert(fk.0) {
                    continue;
                }
                stack.push((fk, true));
                if let Some(kids) = children.get(&fk.0) {
                    for &(ck, _) in kids {
                        if !memo.contains_key(&ck.0) && !on_stack.contains(&ck.0) {
                            stack.push((ck, false));
                        }
                    }
                }
                continue;
            }
            on_stack.remove(&fk.0);
            let rec = store.get_header(fk)?;
            let own = Target::from_compact(CompactTarget::from_consensus(rec.bits)).to_work();
            let mut best_child_w = bitcoin::Work::from_be_bytes([0u8; 32]);
            let mut best_depth = 0u32;
            if let Some(kids) = children.get(&fk.0) {
                for &(ck, _) in kids {
                    let Some(&(w, d)) = memo.get(&ck.0) else {
                        // Cycle / incomplete child — treat as zero (corrupt graph).
                        continue;
                    };
                    if w > best_child_w || (w == best_child_w && d > best_depth) {
                        best_child_w = w;
                        best_depth = d;
                    }
                }
            }
            memo.insert(fk.0, (own + best_child_w, best_depth.saturating_add(1)));
        }
        memo.get(&root.0).copied().ok_or(StoreError::Corrupt(
            "resume_subtree_score: root missing after walk",
        ))
    }

    /// Flush header rows + Class A body associations (IBD writer durability).
    pub fn flush_header_archive(&self) -> Result<(), QueryError> {
        self.store.flush_header_archive()
    }

    /// Ensure a header row exists (no txs). Idempotent by full block hash.
    ///
    /// Write gate: at most one body row per hash; non-null `prev_fk` must match
    /// the parent committed in the block hash (see store `HeaderTable::ensure`).
    /// Used to pipeline header sync so out-of-order bodies resolve parent fk.
    pub fn ensure_header(&self, header: &HeaderRecord) -> Result<Fk, QueryError> {
        // Store gate is authoritative (lock + uniqueness + prev integrity).
        // Skip confirm-parent-cache short-circuit so we never bypass ensure.
        self.store.put_header(header)
    }

    /// Batch [`Self::ensure_header`] (header-sync write path).
    pub fn ensure_headers(&self, recs: &[HeaderRecord]) -> Result<Vec<Fk>, QueryError> {
        self.store.put_headers(recs)
    }

    pub fn flush(&self) -> Result<(), QueryError> {
        if !self.store.path().exists() {
            return Err(StoreError::NotDirectory(self.store.path().to_path_buf()));
        }
        self.store.flush()
    }
}

fn wire_header(rec: &HeaderRecord, prev_blockhash: BlockHash) -> BlockHeader {
    BlockHeader {
        version: BlockVersion::from_consensus(rec.version),
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array(rec.merkle_root),
        time: rec.timestamp,
        bits: CompactTarget::from_consensus(rec.bits),
        nonce: rec.nonce,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub block_height: u32,
    pub pos: usize,
    pub merkle: Vec<[u8; 32]>,
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
