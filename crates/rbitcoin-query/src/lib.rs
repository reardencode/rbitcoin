//! Domain query layer over [`rbitcoin_store::Store`].

#[doc(hidden)]
pub mod archive;
#[doc(hidden)]
pub mod batch_parents;
#[doc(hidden)]
pub mod block_filter;

#[doc(hidden)]
pub mod catchup;
#[doc(hidden)]
pub mod chain_view;
#[doc(hidden)]
pub mod combined_stage;
#[doc(hidden)]
pub mod confirm_load;
#[doc(hidden)]
pub mod confirm_parent_cache;
#[doc(hidden)]
pub mod confirm_stats;
#[doc(hidden)]
pub mod connect;
#[doc(hidden)]
pub mod in_flight;
#[doc(hidden)]
pub mod reconstruct;
#[doc(hidden)]
pub mod resolved_wire;
#[doc(hidden)]
pub mod run_builder_core;
#[doc(hidden)]
pub mod scripthash;
#[doc(hidden)]
pub mod sh_builder;
#[doc(hidden)]
pub mod soft_densify;
#[doc(hidden)]
pub mod sp_tweaks;
#[doc(hidden)]
pub mod spend_sync;
#[doc(hidden)]
pub mod stamp;
pub mod testutil;
#[doc(hidden)]
pub mod wave_prevout;
#[doc(hidden)]
pub mod write_create_loc;

#[doc(hidden)]
pub mod block_pipeline;
#[doc(hidden)]
pub mod confirm_error;
#[doc(hidden)]
pub mod confirm_run;
#[doc(hidden)]
pub mod connect_facade;
#[doc(hidden)]
pub mod convert;
#[doc(hidden)]
pub mod header_read;

#[doc(hidden)]
pub mod index_rows;
#[doc(hidden)]
pub mod index_writebehind;
#[doc(hidden)]
pub mod milestone_gate;

#[doc(hidden)]
pub mod regtest_pad;
#[doc(hidden)]
pub mod sp_read;
pub mod versionbits;

pub use block_pipeline::assemble_lock_time_cutoff;
pub use combined_stage::{load_creates_once, CombinedCreate};
pub use confirm_error::ConfirmError;
pub use connect_facade::*;
pub use convert::header_to_record;
pub use header_read::{
    expected_next_bits, median_time_past, median_time_past_store, next_block_mintime,
    validate_header, validate_header_hashed,
};
pub use index_writebehind::{
    build_indexes_released, index_tip_entry, prepare_live_indexes, spawn_index_writebehind,
    IndexTipEntry, INDEX_STARTUP_GAP_HEIGHTS,
};
pub use rbitcoin_consensus::{
    block_wire_len_from_pres, decode_block_precomputes, pres_for_tip, IdMap, OutPointHasher,
    OutPointSet, TxConnectPrecompute, TxPrecompute, TxScriptPrecompute, TxidHasher, TxidMap,
    TxidSet,
};
pub use reconstruct::{BlockTxStatRows, StampedTxstatBlock};
pub use regtest_pad::pad_empty_from;
pub use resolved_wire::{BlockQueueWaveIntake, ResolvedWire};
pub use soft_densify::{
    soft_ahead_quarter_full, soft_assign_restricted, soft_confirm_window_covered,
    soft_confirm_window_n, soft_densify_band_hi, BQ_ASSIGN_STOP_BYTES, BQ_SOFT_FREE_BYTES,
    TIP_HOLE_MIN_AHEAD_BLOCKS,
};
pub use sp_read::{tweaks_at_height, tweaks_for_height, tweaks_from_thin_and_body};
pub use sp_tweaks::{BlockSpOutpoints, ThinTweakRangeLimits, ThinTweakRow};
pub use versionbits::{
    compute_block_version, DeploymentState, ThresholdState, VERSIONBITS_TOP_BITS,
};

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
use std::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering as AtomicOrdering,
};

use std::sync::{Arc, Condvar, Mutex};

pub use confirm_stats::{
    add as note_confirm, add_dur as note_confirm_dur, ConfirmStats, ConfirmWindow, LastPinPhases,
    LastPlanBatch, LastUnionMiss, LastWritePhases, TipShSnap,
};

pub type QueryError = StoreError;

/// A mempool tx against the visible scripthash height.
///
/// Wallet unconfirmed reads hide [`Covered`](Self::Covered) and keep the
/// other two. [`Awaiting`](Self::Awaiting) is on the tip, but confirmed
/// history does not include that height yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShVisibleConfirm {
    /// Not confirmed-strong on the tip, or there is no address view.
    NotCovered,
    /// Confirmed-strong at a height the visible view already includes.
    Covered,
    /// Confirmed-strong above the visible view.
    Awaiting,
}

/// Best-chain tip published with the `confirmed[]` update that made it the tip.
///
/// One `Arc` swap, so a reader sees a height and hash from the same commit.
#[derive(Clone, Copy, Debug)]
pub struct PublishedTip {
    pub height: u32,
    pub hash: [u8; 32],
}

/// Electrum JSON-RPC error / Esplora 503 body when `--sh-index` is off.
pub const SCRIPTHASH_INDEX_DISABLED: &str = "scripthash index disabled";

/// Default unpaged scripthash join cap. `0` stays unlimited.
pub const DEFAULT_MAX_SH_CREATES: u32 = 10_000;

/// Default create count above which an unpaged scripthash join waits for
/// every other such join. It matters once `--max-sh-creates` is raised past
/// it. `0` turns the wait off.
pub const DEFAULT_HEAVY_SH_CREATES: u32 = 10_000;

/// Result of [`Query::uring_recover`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UringRecover {
    Recovered,
    Exhausted,
}

thread_local! {
    static SCRIPTHASH_RUN_COUNT_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static OWNED_SIZE_SNAPSHOT_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[doc(hidden)]
pub fn note_scripthash_run_count_call() {
    SCRIPTHASH_RUN_COUNT_N.with(|c| c.set(c.get().saturating_add(1)));
}

#[doc(hidden)]
pub fn note_owned_size_snapshot_call() {
    OWNED_SIZE_SNAPSHOT_N.with(|c| c.set(c.get().saturating_add(1)));
}

pub fn reset_progress_snapshot_counts() {
    SCRIPTHASH_RUN_COUNT_N.with(|c| c.set(0));
    OWNED_SIZE_SNAPSHOT_N.with(|c| c.set(0));
}

pub fn progress_snapshot_counts() -> (u64, u64) {
    (
        SCRIPTHASH_RUN_COUNT_N.with(|c| c.get()),
        OWNED_SIZE_SNAPSHOT_N.with(|c| c.get()),
    )
}

pub fn uring_recover_credit(last_tip: Option<u32>, tip: u32) -> bool {
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
pub use batch_parents::FkSet;
pub use batch_parents::{
    layout_covers_need, sparse_spender_rels, BatchParents, FkMap, ParentPinView,
    SharedPrevoutScript, U32Map, U64Map, U64Set,
};
pub use block_filter::{basic_filter_from_scripts, basic_filter_of};
pub use catchup::IndexMode;
pub use chain_view::{
    header_lookup_count, header_lookups_under_coord_lock, reset_header_lookups_under_coord_lock,
    ChainView, ChainViewKind, SlotsAround,
};
pub use confirm_load::SpendEdges;
pub use connect::{spawn_sh_writebehind, ConfirmPrepared};
pub use in_flight::InFlight;
pub use scripthash::{
    BlockTouch, FilteredHistory, HistoryFilter, HistoryOrder, ScriptHashBalance,
    ScriptHashChainStats, ScriptHashHistoryItem, ScriptHashTxSummary, ScriptHashUtxo, ShJoinSlot,
};
pub use spend_sync::SpendSync;
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
    /// Parent header hash. Genesis uses the zero hash.
    pub prev_hash: [u8; 32],
    pub header_fk: Fk,
    /// True if `header_txs` has a body for this header (Class A ready).
    pub has_body: bool,
}

#[doc(hidden)]
pub type ResumeChildMap = U64Map<Vec<(Fk, [u8; 32])>>;
#[doc(hidden)]
pub type ResumeSibPick = (Fk, [u8; 32], bool, u32, [u8; 32]);

/// One sequential pass over `header.body`: child edges, `nBits`, and `prev_fk`.
#[doc(hidden)]
pub struct ResumeHeaderIndex {
    pub children: ResumeChildMap,
    pub bits: Vec<u32>,
    pub prevs: Vec<u64>,
}

#[derive(Default)]
#[doc(hidden)]
pub struct SeqSigWitRamWindow {
    pub by_height: BTreeMap<u32, Vec<Fk>>,
    pub by_fk: U64Map<Vec<InputRecord>>,
    pub bytes: u64,
    pub evictions: u64,
}

/// SH write-behind: confirm enqueues; one Class B appender drains.
///
/// Separate mutexes on purpose: confirm enqueues on the write thread while
/// Electrum joins read `ram_head`. Do not merge pending / applying / ram_head.
#[doc(hidden)]
pub struct ShWriteBehind {
    /// Last height whose SH creates were applied after tip commit.
    /// `u64::MAX` = none.
    pub indexed_through: AtomicU64,
    pub pending: Mutex<VecDeque<connect::ShPendingJob>>,
    pub pending_cv: Condvar,
    /// Job popped for apply but not yet watermarked.
    pub applying: Mutex<Option<connect::ShPendingJob>>,
    /// Pending + in-flight SH creates keyed by scripthash.
    pub ram_head: Mutex<HashMap<[u8; 32], Vec<Fk>>>,
    /// Serializes Class B `put_create_batch_append`: write-behind, the
    /// generate drain, and the Class A tail backfill.
    pub appender: Mutex<()>,
    /// Max create fk applied to the SH tables (may lead `include_hwm`).
    pub applied_max_fk: AtomicU64,
    /// Last durable `include_hwm` advance (throttles table syncs in a burst).
    pub last_durable: Mutex<std::time::Instant>,
}

impl ShWriteBehind {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            indexed_through: AtomicU64::new(u64::MAX),
            pending: Mutex::new(VecDeque::new()),
            pending_cv: Condvar::new(),
            applying: Mutex::new(None),
            ram_head: Mutex::new(HashMap::new()),
            appender: Mutex::new(()),
            applied_max_fk: AtomicU64::new(0),
            last_durable: Mutex::new(std::time::Instant::now()),
        }
    }
}

/// Domain query facade used by higher layers (consensus, net, RPC).
pub struct Query {
    pub store: Arc<Store>,
    /// When false, confirm skips durable spend-annotation writes.
    pub spend_index: std::sync::atomic::AtomicBool,
    /// When false, archive skips durable `tx.head` inserts.
    pub tx_index: std::sync::atomic::AtomicBool,
    /// Height-ordered SH write-behind (one Class B appender). Confirm enqueues;
    /// [`Self::apply_sh_pending`] / the tip-follow worker drain.
    pub sh: ShWriteBehind,
    /// Index write-behind release gate shared by every appender. `0` = none
    /// released; `h+1` = appenders may apply through height `h`.
    pub index_released_through: AtomicU32,
    /// Block-structured confirm parent cache.
    pub confirm_parents: confirm_parent_cache::ConfirmParentCache,
    /// Confirmed header hash at BIP34 height. The header row is the durable
    /// record. Dropped only when that block is disconnected.
    pub bip34_ancestor: std::sync::Mutex<Option<crate::chain_view::Bip34AncestorNote>>,
    /// Regtest `testdummy` state per period-end hash.
    pub versionbits: versionbits::VersionBitsCache,
    /// Blocks this process connected and then disconnected (Core keeps
    /// `BLOCK_VALID_SCRIPTS` on them). A reconnect drops the hash.
    pub disconnected: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    /// In-RAM body rows. `has_hash` is a map lookup on this mutex, not a scan.
    ///
    /// RAM-only by design: avoids double-writing every block (queue + Class A).
    /// Accepts redownload on restart and peak RAM of soft densify depth.
    pub block_queue: Mutex<rbitcoin_store::BlockQueue>,
    /// Lookup's decoded wires. Getdata enqueue and `has_hash` never lock this.
    pub bq_resolved: Mutex<HashMap<u32, ResolvedWire>>,
    /// Last soft-assign restricted flag (over free-byte floor; cache for meters).
    pub block_queue_pressure: AtomicBool,
    /// Last 1-min confirm window (`bq soft=n/win` `win`). 0 = rate unknown.
    pub soft_confirm_window: AtomicU32,
    /// Re-arm generation (high 32 bits) and the last contiguous height lookup
    /// dequeued into loadq (low 32 bits, `u32::MAX` = none). One word, so a
    /// take selected before a re-arm cannot overwrite it.
    pub lookup_taken: AtomicU64,
    /// Highest height whose TipOnly **started** (`u32::MAX` = none).
    pub lookup_started_hi: AtomicU32,
    /// Max height whose Class A append committed (`u32::MAX` = none).
    pub class_a_hi: AtomicU32,
    /// Post-IBD SH SEAL + leftover-run discard (unsorted collect is tip finalize).
    pub sh_run: sh_builder::ShRunBuilder,
    /// Operator scripthash index intent (`--shindex`). When false, Class C skips
    /// SH collect/enqueue/durable write-through entirely (tip follow independent).
    pub sh_index_enabled: std::sync::atomic::AtomicBool,
    /// See [`Self::set_sh_force_rebuild`].
    pub sh_force_rebuild: std::sync::atomic::AtomicBool,
    pub block_filter_enabled: std::sync::atomic::AtomicBool,
    /// Confirm appends filter and tweak rows. Set by `prepare_live_indexes`
    /// when every enabled index is contiguous with the tip. Load reads it;
    /// the write thread is the only writer.
    pub index_live: std::sync::atomic::AtomicBool,
    /// BIP158 basic filter table, opened when the index is first turned on.
    pub block_filters: std::sync::OnceLock<rbitcoin_store::BlockFilterTable>,
    pub bf_wb: block_filter::BlockFilterWriteBehind,
    /// Optional BIP-352 thin tweak index (`--sptweaks`). Files may exist when off.
    pub sp_tweaks: Mutex<Option<SpTweaksTable>>,
    pub sptweaks_enabled: AtomicBool,
    /// `taproot_height` used when creating the table. 0 until enabled / opened.
    pub sptweaks_origin: AtomicU32,
    /// Explicit [`IndexMode`] (Direct / Tip).
    pub index_mode_cell: std::sync::atomic::AtomicU8,
    /// Cooperative cancel for in-flight confirm load. Set on IBD SIGINT
    /// teardown so the confirm load thread aborts before process exit.
    pub confirm_cancel: std::sync::atomic::AtomicBool,
    /// `--trust-peer`: consensus faults warn and the plan's apply-class still connects.
    pub trust_peer: std::sync::atomic::AtomicBool,
    /// One header read returns [`StoreError::Cancelled`]. Tests only.
    #[cfg(debug_assertions)]
    pub header_read_cancel: std::sync::atomic::AtomicBool,
    /// Confirmed best-chain `hash → height` (kept for process life; ~60 MiB mainnet).
    ///
    /// Avoids O(tip) header walks on Esplora/P2P `height_of_hash`.
    pub height_by_hash: Mutex<HeightByHashIndex>,
    /// `reconstruct_archived_block` calls (`/raw` and Esplora size/weight).
    pub reconstruct_archived: AtomicU64,
    /// 0 = unlimited. Electrum + Esplora SH joins refuse above this create count.
    pub max_sh_creates: AtomicU32,
    /// 0 = off. An unpaged SH join above this create count holds
    /// [`Self::heavy_sh_join`] for its whole walk.
    pub heavy_sh_creates: AtomicU32,
    /// One heavy unpaged SH join at a time across every Electrum and Esplora
    /// client: one near the cap can peak above 2 GiB.
    pub heavy_sh_join: Mutex<()>,
    /// Unpaged SH join overlap by kind. Tests only.
    #[cfg(debug_assertions)]
    pub sh_join_probe: crate::scripthash::ShJoinProbe,
    /// Packed `tx.body` bytes read by [`Self::load_thin_tweaks`].
    pub thin_tweak_body_bytes: AtomicU64,
    /// Max fk `head_insert_many` has published (0 = never). Load polls this
    /// with the fence to prune in-flight **after** bind.
    pub head_drain_fk: AtomicU64,
    /// Disconnect height (valid when [`Self::disconnect_gen`] > 0).
    pub disconnect_height: AtomicU32,
    /// Bumped on each [`Self::disconnect_tip`]. Load drops in-flight layers.
    pub disconnect_gen: AtomicU64,
    /// Confirmed tip hash published by the write that advanced `confirmed[]`.
    /// The IBD orchestration loop loads this instead of reading the header store.
    pub published_tip: arc_swap::ArcSwapOption<PublishedTip>,
    /// Scripthash run count last published by the confirm thread.
    pub sh_runs_published: AtomicUsize,
    /// Process-owned sizes last published by the confirm thread.
    pub owned_sizes_published: arc_swap::ArcSwap<ProcessOwnedSizes>,
    /// Held from the tip-height check through `flush_class_c_tip` (IBD: through
    /// starting it) / disconnect flush. Rewind tries it and retries; it does not
    /// disconnect mid-flush.
    pub tip_commit: Mutex<()>,
    /// Confirm-write channel, installed while `ibd-confirm-write` is alive.
    /// Archived-body clear sends here instead of storing Class C itself.
    pub confirm_write: Mutex<Option<std::sync::mpsc::SyncSender<crate::ConfirmWriteMsg>>>,
    /// IBD tip barrier on `rbtc-tip-flush`, or the failure of one. The next
    /// `tip_commit` taker joins it.
    pub tip_flush: Mutex<connect::TipFlush>,
    /// Long-lived IBD Class C barrier thread. Absent in tip mode.
    pub tip_flush_worker: connect::TipFlushWorker,
    /// Test hook: IBD tip flush threads wait before writing while this is set.
    #[cfg(debug_assertions)]
    pub tip_flush_hold: Arc<rbitcoin_store::TipFlushHold>,
    /// Test hook: the next IBD tip flush thread fails to start.
    #[cfg(debug_assertions)]
    pub tip_flush_spawn_fail: std::sync::atomic::AtomicBool,
    /// Confirm / archive / load window meters (`ibd: perf`). One instance per Query.
    pub confirm_stats: Arc<ConfirmStats>,
    /// Tip height of last in-process io_uring recover (`u32::MAX` = none).
    pub uring_recover_tip: AtomicU32,
    /// Highest height whose seqsigwit was dropped (`u32::MAX` = none dropped).
    pub pruneheight: AtomicU32,
    /// Last tip a Class A seal made durable. A shrink cannot raise it.
    pub sealed_tip: connect::SealedTip,
    /// Highest spill height already unlinked (`u32::MAX` = none yet).
    pub spill_unlinked_through: AtomicU32,
    /// Operator `--prune-seqsigwit` (advertise NETWORK_LIMITED even before a drop).
    pub prune_seqsigwit: AtomicBool,
    /// True while the net IBD engine is active.
    pub ibd_mode: AtomicBool,
    /// In prune+IBD mode, cap for recent witness kept in RAM.
    pub seqsigwit_ram_threshold_bytes: AtomicU64,
    /// Recent witness cache keyed by confirmed heights/create fks.
    pub seqsigwit_ram_window: Mutex<SeqSigWitRamWindow>,
    /// Inputs from the most recent Class A append wave (fk-keyed).
    pub seqsigwit_append_cache: Mutex<U64Map<Vec<InputRecord>>>,
    /// Header work-path height → hash plus work through the contiguous tip.
    ///
    /// Second map beside IBD `height_to_hash` so confirm threads can do two
    /// O(1) milestone lookups without the IBD state lock. While the map has
    /// any height it is the only source: a missing height is not an ancestor
    /// of the milestone. When it is empty, the confirmed chain is the source.
    /// RAM is one hash per header on that path for the process lifetime of the sync.
    pub milestone_path: Mutex<MilestonePath>,
}

/// Best header path published by IBD header intake.
#[derive(Default)]
#[doc(hidden)]
pub struct MilestonePath {
    pub by_height: HashMap<u32, [u8; 32]>,
    /// Work through `work_height` when `work_valid` (big-endian).
    pub work_through: [u8; 32],
    pub work_height: u32,
    pub work_valid: bool,
}

/// In-process hash→height map for the confirmed tip chain (~33 MiB raw at 1e6 tips).
/// `tip == None` means empty (open / invalidate); any other tip is incremental.
#[derive(Default)]
#[doc(hidden)]
pub struct HeightByHashIndex {
    /// Tip height the map matches (`None` = empty / needs rebuild).
    pub tip: Option<u32>,
    pub map: HashMap<[u8; 32], u32>,
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
        let index_dir = store.cold_files_dir().to_path_buf();
        let (sp_tweaks, sptweaks_origin) = if SpTweaksTable::files_present(&index_dir) {
            match SpTweaksTable::open(&index_dir) {
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
        let sealed_tip = connect::SealedTip::at_open(store.confirmed.tip_height());
        // Open rebuilt or backfilled `tx.head` through every Class A create,
        // and nothing is queued: the drain starts there.
        let head_drained = store.txs.head_last_inserted_fk();
        let q = Self {
            store: Arc::new(store),
            spend_index: std::sync::atomic::AtomicBool::new(true),
            tx_index: std::sync::atomic::AtomicBool::new(true),
            sh: ShWriteBehind::new(),
            index_released_through: AtomicU32::new(0),
            confirm_parents: confirm_parent_cache::ConfirmParentCache::new(),
            bip34_ancestor: std::sync::Mutex::new(None),
            versionbits: versionbits::VersionBitsCache::default(),
            disconnected: std::sync::Mutex::new(std::collections::HashSet::new()),
            block_queue: Mutex::new(rbitcoin_store::BlockQueue::open_or_create(&store_path)?),
            bq_resolved: Mutex::new(HashMap::new()),
            block_queue_pressure: AtomicBool::new(false),
            soft_confirm_window: AtomicU32::new(0),
            lookup_taken: AtomicU64::new(u32::MAX as u64),
            lookup_started_hi: AtomicU32::new(u32::MAX),
            class_a_hi: AtomicU32::new(u32::MAX),
            sh_run: sh_builder::ShRunBuilder::new(&store_path),
            // Library default: SH on (tests / enter_direct). Node sets false for
            // `--shindex` off before entering Direct.
            sh_index_enabled: std::sync::atomic::AtomicBool::new(true),
            sh_force_rebuild: std::sync::atomic::AtomicBool::new(false),
            block_filter_enabled: std::sync::atomic::AtomicBool::new(false),
            index_live: std::sync::atomic::AtomicBool::new(false),
            block_filters: std::sync::OnceLock::new(),
            bf_wb: block_filter::BlockFilterWriteBehind::new(),
            sp_tweaks: Mutex::new(sp_tweaks),
            sptweaks_enabled: AtomicBool::new(false),
            sptweaks_origin: AtomicU32::new(sptweaks_origin),
            index_mode_cell: std::sync::atomic::AtomicU8::new(IndexMode::Tip as u8),
            confirm_cancel: std::sync::atomic::AtomicBool::new(false),
            trust_peer: std::sync::atomic::AtomicBool::new(false),
            #[cfg(debug_assertions)]
            header_read_cancel: std::sync::atomic::AtomicBool::new(false),
            height_by_hash: Mutex::new(HeightByHashIndex::default()),
            reconstruct_archived: AtomicU64::new(0),
            max_sh_creates: AtomicU32::new(DEFAULT_MAX_SH_CREATES),
            heavy_sh_creates: AtomicU32::new(DEFAULT_HEAVY_SH_CREATES),
            heavy_sh_join: Mutex::new(()),
            #[cfg(debug_assertions)]
            sh_join_probe: crate::scripthash::ShJoinProbe::default(),
            thin_tweak_body_bytes: AtomicU64::new(0),
            head_drain_fk: AtomicU64::new(head_drained),
            disconnect_height: AtomicU32::new(0),
            disconnect_gen: AtomicU64::new(0),
            published_tip: arc_swap::ArcSwapOption::empty(),
            sh_runs_published: AtomicUsize::new(0),
            owned_sizes_published: arc_swap::ArcSwap::from_pointee(ProcessOwnedSizes::default()),
            tip_commit: Mutex::new(()),
            confirm_write: Mutex::new(None),
            tip_flush: Mutex::new(connect::TipFlush::Idle),
            tip_flush_worker: connect::TipFlushWorker::default(),
            #[cfg(debug_assertions)]
            tip_flush_hold: Arc::new(rbitcoin_store::TipFlushHold::new(false)),
            #[cfg(debug_assertions)]
            tip_flush_spawn_fail: std::sync::atomic::AtomicBool::new(false),
            confirm_stats: Arc::new(ConfirmStats::default()),
            uring_recover_tip: AtomicU32::new(u32::MAX),
            pruneheight: AtomicU32::new(ph),
            sealed_tip,
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
        q.seed_published_tip()?;
        q.recover_sh_writebehind()?;
        if let Some(t) = q
            .sp_tweaks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            q.repair_sp_tweaks(t)?;
        }
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

    #[doc(hidden)]
    pub fn milestone_path_lock(&self) -> std::sync::MutexGuard<'_, MilestonePath> {
        self.milestone_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Header hash at `height` on one chain.
    ///
    /// While the published header path has any hash, that map is the only
    /// source. A missing height is not an ancestor of the milestone: the
    /// confirmed chain and the body queue are different chains. When the
    /// path is empty, the confirmed chain is the source.
    pub fn milestone_header_at(&self, height: u32) -> Option<[u8; 32]> {
        let g = self.milestone_path_lock();
        if !g.by_height.is_empty() {
            return g.by_height.get(&height).copied();
        }
        drop(g);
        match self.header_at_height(rbitcoin_primitives::Height(height)) {
            Ok(Some((_, rec))) => Some(rec.hash),
            _ => None,
        }
    }

    /// True when header intake has published any height on the milestone path.
    pub fn has_milestone_path(&self) -> bool {
        !self.milestone_path_lock().by_height.is_empty()
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

    /// Work through a checkpoint the header file has not stored.
    ///
    /// Later checkpoints replace earlier ones. A lower height does not rewind.
    pub fn note_milestone_checkpoint_work(&self, height: u32, work_be: [u8; 32]) {
        let mut g = self.milestone_path_lock();
        if !g.work_valid || height >= g.work_height {
            g.work_through = work_be;
            g.work_height = height;
            g.work_valid = true;
        }
    }

    /// Drop path slots above `height`. Work above the rewind is forgotten.
    pub fn clear_milestone_path_above(&self, height: u32) {
        let mut g = self.milestone_path_lock();
        g.by_height.retain(|h, _| *h <= height);
        if g.work_valid && g.work_height > height {
            g.work_valid = false;
            g.work_through = [0; 32];
        }
    }

    #[doc(hidden)]
    pub fn load_pruneheight(store_path: &Path) -> Result<(u32, bool), QueryError> {
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

    pub fn set_prune_seqsigwit(&self, on: bool) -> Result<(), QueryError> {
        let was_on = self.prune_seqsigwit();
        if on && self.sptweaks_enabled() {
            return Err(StoreError::Layout(
                "refusing --prune-seqsigwit while silent payment tweaks are enabled".into(),
            ));
        }
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

    #[doc(hidden)]
    pub fn unlink_spill_height(&self, height: u32) -> Result<(), QueryError> {
        let path = self.seqsigwit_spill_file(height)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(path, e)),
        }
    }

    /// Unlink `{start}..=new_h` spill files. Heights at or below `new_h` are pruned.
    #[doc(hidden)]
    pub fn unlink_spill_through(&self, new_h: u32) -> Result<(), QueryError> {
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

    #[doc(hidden)]
    pub fn sweep_spill_at_or_below_pruneheight(&self) -> Result<(), QueryError> {
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

    #[doc(hidden)]
    pub fn persist_pruneheight(&self, v: u32) -> Result<(), QueryError> {
        let path = self.store.path().join("seqsigwit.prune");
        std::fs::write(&path, v.to_le_bytes()).map_err(|e| StoreError::io(path, e))
    }

    #[doc(hidden)]
    pub fn persist_pruneheight_clear(&self) -> Result<(), QueryError> {
        let path = self.store.path().join("seqsigwit.prune");
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(path, e)),
        }
    }

    pub const SEQSIGWIT_KEEP_HEIGHTS: u32 = 288;

    pub fn apply_prune_seqsigwit_tip(&self) -> Result<(), QueryError> {
        self.prune_seqsigwit_below(self.tip_height())
    }

    /// Keep the last [`Self::SEQSIGWIT_KEEP_HEIGHTS`] heights at or below `tip`.
    pub fn prune_seqsigwit_below(&self, tip: Option<Height>) -> Result<(), QueryError> {
        if !self.prune_seqsigwit() {
            return Ok(());
        }
        let Some(tip) = tip else {
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

    #[doc(hidden)]
    pub fn require_seqsigwit_at(&self, height: Height) -> Result<(), QueryError> {
        if let Some(ph) = self.pruneheight() {
            if height.0 <= ph.0 {
                return Err(StoreError::Pruned { height: height.0 });
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn require_seqsigwit_fk(&self, fk: Fk) -> Result<(), QueryError> {
        if self.seqsigwit_available(fk)? {
            return Ok(());
        }
        let height = self.store.tx_height_get(fk)?.unwrap_or(0);
        Err(StoreError::Pruned { height })
    }

    #[doc(hidden)]
    pub fn drop_seqsigwit_ram_height(&self, height: u32) {
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

    pub fn clear_seqsigwit_ram_window(&self) {
        *self.seqsigwit_ram_window.lock().unwrap() = SeqSigWitRamWindow::default();
        self.seqsigwit_append_cache.lock().unwrap().clear();
    }

    #[cfg(debug_assertions)]
    pub fn seqsigwit_ram_window_stats(&self) -> (usize, usize, u64, u64) {
        let g = self.seqsigwit_ram_window.lock().unwrap();
        (g.by_height.len(), g.by_fk.len(), g.bytes, g.evictions)
    }

    pub fn seqsigwit_ram_inputs(&self, fk: Fk) -> Option<Vec<InputRecord>> {
        let id = fk.get()?;
        self.seqsigwit_ram_window
            .lock()
            .unwrap()
            .by_fk
            .get(&id)
            .cloned()
    }

    #[doc(hidden)]
    pub fn seqsigwit_spill_dir(&self) -> std::path::PathBuf {
        self.store.path().join("seqsigwit.window")
    }

    #[doc(hidden)]
    pub fn seqsigwit_spill_file(&self, height: u32) -> Result<std::path::PathBuf, QueryError> {
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

    #[doc(hidden)]
    pub fn persist_seqsigwit_spill_height(
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

    #[doc(hidden)]
    pub fn seqsigwit_spill_inputs_with_count(
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

    pub fn seqsigwit_cached_inputs(
        &self,
        fk: Fk,
        input_count: u32,
    ) -> Result<Option<Vec<InputRecord>>, QueryError> {
        if let Some(ins) = self.seqsigwit_ram_inputs(fk) {
            return Ok(Some(ins));
        }
        self.seqsigwit_spill_inputs_with_count(fk, input_count)
    }

    pub fn note_appended_seqsigwit_inputs(&self, fks: &[Fk], ins: Vec<Vec<InputRecord>>) {
        let mut cache = self.seqsigwit_append_cache.lock().unwrap();
        for (fk, inputs) in fks.iter().zip(ins) {
            if let Some(id) = fk.get() {
                cache.insert(id, inputs);
            }
        }
    }

    pub fn note_seqsigwit_ram_for_confirmed(
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

    #[doc(hidden)]
    pub fn seed_recent_seqsigwit_from_store(&self) -> Result<(), QueryError> {
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

    /// `tx.head` holds every connected create: the drain has passed the
    /// highest create fk on the fence. Every fk at or below the drain was
    /// queued before it and inserted, since a failed drain re-queues its
    /// batch and does not move the drain.
    pub fn head_covers_fence(&self) -> bool {
        self.head_drain_fk() >= self.store.fence_max_connected_fk()
    }

    /// Record a tip shrink so load can drop in-flight layers for that height.
    pub fn note_disconnect_height(&self, height: u32) {
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

    /// The next [`Self::header_at_height`] or [`Self::slots_around`] returns
    /// [`StoreError::Cancelled`].
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn fail_next_header_read_cancelled(&self) {
        self.header_read_cancel
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
    pub fn set_sh_indexed_through_height(&self, height: Option<u32>) {
        let v = height.map(|h| h as u64).unwrap_or(u64::MAX);
        self.sh.indexed_through.store(v, AtomicOrdering::Release);
    }

    /// Resolve txid → fk via durable `tx.head` (when the index is enabled).
    /// Head probe plus `txid.body` verify; no packed body decode.
    ///
    /// `TipThenAny`: RPC / reconstruct may want a never-connected archive
    /// row. A consensus-style check (confirm, spentness, proposal) wants
    /// [`Self::tx_fk_by_txid_tip`].
    ///
    /// ConfirmParentCache is keyed by create fk only (no process-local txid map).
    /// IBD thin edges carry stamped create_fk; cold/soft paths use durable head.
    #[doc(hidden)]
    pub fn lookup_tx_fk(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        if !self.tx_index_enabled() {
            return Ok(None);
        }
        self.store.get_fk_by_txid(txid)
    }

    /// Public resolve by txid (durable head when index enabled).
    pub fn tx_fk_by_txid(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        self.lookup_tx_fk(txid)
    }

    /// Confirm / spentness / block proposal: connected instance only (height
    /// fence Some).
    pub fn tx_fk_by_txid_tip(&self, txid: &[u8; 32]) -> Result<Option<Fk>, QueryError> {
        if self.tx_index_enabled() {
            return self.store.get_fk_by_txid_tip(txid);
        }
        Ok(None)
    }

    /// Where a live mempool tx sits against the visible scripthash height.
    ///
    /// `visible` is [`Self::sh_visible_through_height`], read once per wallet
    /// request. `None` (no address view) is [`ShVisibleConfirm::NotCovered`]:
    /// there is no confirmed side to hide against. The chain lookup runs only
    /// after that, and the block height is read only when the lookup hits.
    pub fn sh_visible_confirm(
        &self,
        txid: &[u8; 32],
        visible: Option<u32>,
    ) -> Result<ShVisibleConfirm, QueryError> {
        let Some(visible) = visible else {
            return Ok(ShVisibleConfirm::NotCovered);
        };
        let Some(fk) = self.tx_fk_by_txid_tip(txid)? else {
            return Ok(ShVisibleConfirm::NotCovered);
        };
        let tip = self.tip_height().map(|h| h.0);
        if !self.store().is_confirmed_strong_at(fk, tip)? {
            return Ok(ShVisibleConfirm::NotCovered);
        }
        match self.store().fence().height_of(fk) {
            Some(h) if h <= visible => Ok(ShVisibleConfirm::Covered),
            Some(_) => Ok(ShVisibleConfirm::Awaiting),
            None => Ok(ShVisibleConfirm::NotCovered),
        }
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

    /// [`StoreError::Rejected`] payload from [`Self::block_queue_offer`] for
    /// wire that does not decode. Only this refusal is the sender's fault.
    pub const UNDECODABLE_WIRE_MSG: &'static str = "block wire does not decode";

    pub fn set_max_sh_creates(&self, n: u32) {
        self.max_sh_creates.store(n, AtomicOrdering::Relaxed);
    }

    pub fn max_sh_creates(&self) -> u32 {
        self.max_sh_creates.load(AtomicOrdering::Relaxed)
    }

    pub fn set_heavy_sh_creates(&self, n: u32) {
        self.heavy_sh_creates.store(n, AtomicOrdering::Relaxed);
    }

    pub fn heavy_sh_creates(&self) -> u32 {
        self.heavy_sh_creates.load(AtomicOrdering::Relaxed)
    }

    pub fn note_reconstruct_archived(&self) {
        self.reconstruct_archived
            .fetch_add(1, AtomicOrdering::Relaxed);
    }

    /// Sample-and-reset packed body bytes read by thin BIP-352 serve.
    pub fn sample_reset_thin_tweak_body_bytes(&self) -> u64 {
        self.thin_tweak_body_bytes.swap(0, AtomicOrdering::Relaxed)
    }

    pub fn note_thin_tweak_body_bytes(&self, n: u64) {
        if n > 0 {
            self.thin_tweak_body_bytes
                .fetch_add(n, AtomicOrdering::Relaxed);
        }
    }

    pub fn confirm_parent_cache(&self) -> &confirm_parent_cache::ConfirmParentCache {
        &self.confirm_parents
    }

    /// `--trust-peer`: warn-and-apply consensus faults still connect.
    pub fn set_trust_peer(&self, on: bool) {
        self.trust_peer
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn trust_peer(&self) -> bool {
        self.trust_peer.load(std::sync::atomic::Ordering::Relaxed)
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
        let _commit = self.lock_tip_commit()?;
        self.store.flush_for_shutdown()
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        if let Err(e) = self.join_tip_flush() {
            rbitcoin_log::warn!("store: IBD tip flush failed before close: {e}");
        }
        self.stop_tip_flush_worker();
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

    /// In-RAM block queue stats: `(bytes, count)`.
    ///
    /// Bytes are process heap (wire payloads). The densify cap is the IBD
    /// config's `assign_stop_bytes`.
    pub fn block_queue_stats(&self) -> (u64, usize) {
        let g = self.block_queue.lock().unwrap();
        (g.bytes(), g.count())
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
        let h = self.lookup_taken.load(AtomicOrdering::Acquire) as u32;
        if h == u32::MAX {
            None
        } else {
            Some(h)
        }
    }

    /// Re-arm generation lookup reads before it selects a wave.
    pub fn lookup_taken_gen(&self) -> u32 {
        (self.lookup_taken.load(AtomicOrdering::Acquire) >> 32) as u32
    }

    /// Re-arm the lookup consume high-water (disconnect, reject, rewind).
    /// `None` resets. Bumps the generation so a take selected earlier does
    /// not advance past it.
    pub fn set_lookup_taken_hi(&self, hi: Option<u32>) {
        let lo = u64::from(hi.unwrap_or(u32::MAX));
        let _ =
            self.lookup_taken
                .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |cur| {
                    let gen = ((cur >> 32) as u32).wrapping_add(1);
                    Some((u64::from(gen) << 32) | lo)
                });
    }

    /// Lookup took `hi` off the BQ in a wave selected at generation `gen`.
    /// Returns false, leaving the mark, when a re-arm came in between.
    pub fn advance_lookup_taken_hi(&self, gen: u32, hi: u32) -> bool {
        let next = (u64::from(gen) << 32) | u64::from(hi);
        self.lookup_taken
            .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |cur| {
                ((cur >> 32) as u32 == gen).then_some(next)
            })
            .is_ok()
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

    /// Enqueue a raw block payload in the process-local RAM queue.
    ///
    /// **Always accepts** decodable peer wire. Soft densify / assign-stop only
    /// limit **new getdata assign**; never refuse in-flight bodies here.
    /// Restart drops the queue (redownload); sole durable write is Class A on
    /// confirm.
    ///
    /// A payload lookup would not decode is refused with
    /// [`StoreError::Rejected`] carrying [`Self::UNDECODABLE_WIRE_MSG`], and
    /// nothing is queued: a queued hash counts as in hand, so an undecodable
    /// row would block the honest copy.
    pub fn block_queue_offer(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: &[u8],
    ) -> Result<BlockQueueOffer, QueryError> {
        self.block_queue_offer_from(height, hash, header_fk, payload, None)
    }

    /// [`Self::block_queue_offer`] that records the caller's id for the peer
    /// the wire came from. Lookup carries it on [`ResolvedWire::sender`].
    pub fn block_queue_offer_from(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: &[u8],
        sender: Option<u64>,
    ) -> Result<BlockQueueOffer, QueryError> {
        if let Some(id) = self.block_queue.lock().unwrap().id_for_height(height) {
            return Ok(BlockQueueOffer { queue_id: id });
        }
        let Some(n_inputs) = rbitcoin_store::block_wire_input_count(payload) else {
            return Err(StoreError::Rejected(Self::UNDECODABLE_WIRE_MSG));
        };
        self.block_queue_offer_counted(height, hash, header_fk, payload.to_vec(), n_inputs, sender)
    }

    /// [`Self::block_queue_offer_from`] for a payload the caller already
    /// owns (moved in, not copied). An undecodable payload is refused and
    /// not queued.
    pub fn block_queue_offer_vec(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        owned: Vec<u8>,
        sender: Option<u64>,
    ) -> Result<BlockQueueOffer, QueryError> {
        let Some(n_inputs) = rbitcoin_store::block_wire_input_count(&owned) else {
            return Err(StoreError::Rejected(Self::UNDECODABLE_WIRE_MSG));
        };
        self.block_queue_offer_counted(height, hash, header_fk, owned, n_inputs, sender)
    }

    #[doc(hidden)]
    pub fn block_queue_offer_counted(
        &self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        owned: Vec<u8>,
        n_inputs: u32,
        sender: Option<u64>,
    ) -> Result<BlockQueueOffer, QueryError> {
        let id = self
            .block_queue
            .lock()
            .unwrap()
            .enqueue_vec(height, hash, header_fk, owned, n_inputs, sender)?;
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
        let n_inputs = rbitcoin_store::block_wire_input_count(payload).unwrap_or(0);
        self.block_queue.lock().unwrap().enqueue_vec(
            height,
            hash,
            header_fk,
            payload.to_vec(),
            n_inputs,
            None,
        )
    }

    /// Remove RAM queue entry after combined confirm-write (or permanent drop).
    pub fn block_queue_dequeue_height(&self, height: u32) -> Result<usize, QueryError> {
        let n = self.block_queue.lock().unwrap().dequeue_height(height)?;
        self.bq_resolved.lock().unwrap().remove(&height);
        Ok(n)
    }

    /// Index-only queue entries (ascending id, no payload clone). Empty after restart.
    pub fn block_queue_list_meta(&self) -> Vec<rbitcoin_store::QueuedBlockMeta> {
        self.block_queue.lock().unwrap().list_meta()
    }

    /// Distinct queued heights. Lookup keep must not use `list_meta`.
    pub fn block_queue_queued_heights(&self) -> std::collections::BTreeSet<u32> {
        self.block_queue
            .lock()
            .unwrap()
            .heights()
            .into_iter()
            .collect()
    }

    /// Lowest unresolved BQ heights `≥ path_lo` not in `skip`, capped at `cap`.
    ///
    /// One row-lock. Lookup wave select must use this instead of
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
        self.block_queue
            .lock()
            .unwrap()
            .unresolved_heights(start, skip, cap)
    }

    /// Body-queue intake: raw payload for `height` without dequeue.
    ///
    /// Empty after lookup promote (decoded lives in [`Self::block_queue_resolved`]).
    /// Peer enqueues raw; lookup promotes to decoded-only — never both.
    pub fn block_queue_payload(&self, height: u32) -> Result<Option<Vec<u8>>, QueryError> {
        Ok(self
            .block_queue
            .lock()
            .unwrap()
            .get_by_height(height)?
            .map(|q| q.payload))
    }

    /// Raw frame only. `None` when missing or already promoted.
    pub fn block_queue_raw_payload(
        &self,
        height: u32,
    ) -> Result<Option<std::sync::Arc<Vec<u8>>>, QueryError> {
        Ok(self.block_queue.lock().unwrap().raw_payload(height))
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
        let promoted = {
            let g = self.block_queue.lock().unwrap();
            let mut raw = None;
            let mut promoted = None;
            for height in g.heights_for_hash(hash) {
                if g.hash_at_height(height) != Some(*hash) {
                    continue;
                }
                if let Some(payload) = g.raw_payload(height) {
                    raw = Some((*payload).clone());
                    break;
                }
                if g.contains_height(height) {
                    promoted = Some(height);
                    break;
                }
            }
            if let Some(bytes) = raw {
                return Ok(Some(bytes));
            }
            promoted
        };
        let Some(height) = promoted else {
            return Ok(None);
        };
        Ok(self
            .bq_resolved
            .lock()
            .unwrap()
            .get(&height)
            .map(|w| serialize(w.block.as_ref())))
    }

    /// True if any RAM queue entry has `hash` (meta only — no payload clone).
    ///
    /// Prefer this over [`Self::block_queue_payload_by_hash`] on hot readiness
    /// checks (reorg densify / exploration gate). One map lookup on the row
    /// lock, not a scan, and never the decoded stash.
    pub fn block_queue_has_hash(&self, hash: &[u8; 32]) -> bool {
        self.block_queue.lock().unwrap().has_hash(hash)
    }

    /// True if the in-RAM body queue holds `height`.
    pub fn block_queue_has_height(&self, height: u32) -> bool {
        self.block_queue.lock().unwrap().contains_height(height)
    }

    /// Take raw payload and remove the BQ row (lookup consume).
    pub fn block_queue_take_raw(&self, height: u32) -> Option<rbitcoin_store::TakenRaw> {
        let taken = self.block_queue.lock().unwrap().take_raw(height);
        if taken.is_some() {
            self.bq_resolved.lock().unwrap().remove(&height);
        }
        taken
    }

    /// Hash of the first body-queue entry at `height`, if any.
    ///
    /// Used by claim-ready so a **wrong** first-wins body at tip+1 is not treated
    /// as ready (hole forever / BadPrev thrash).
    pub fn block_queue_hash_at_height(&self, height: u32) -> Option<[u8; 32]> {
        self.block_queue.lock().unwrap().hash_at_height(height)
    }

    /// Lookup finished TipOnly for this height (even if some keys missed).
    pub fn block_queue_mark_resolve_complete(&self, height: u32) -> Result<(), QueryError> {
        self.block_queue
            .lock()
            .unwrap()
            .mark_resolve_complete(height)
    }

    pub fn block_queue_is_resolve_complete(&self, height: u32) -> bool {
        self.block_queue.lock().unwrap().is_resolve_complete(height)
    }

    /// Classify `heights` as still-raw vs already promoted.
    ///
    /// Row lock, then the decoded stash (not held together). Skips
    /// resolve-complete rows. **Does not clone raw payloads.** Decode pulls
    /// [`Self::block_queue_raw_payload`] per height outside these locks.
    pub fn block_queue_wave_intake(&self, heights: &[u32]) -> BlockQueueWaveIntake {
        let mut out = BlockQueueWaveIntake::default();
        let mut promoted = Vec::new();
        {
            let g = self.block_queue.lock().unwrap();
            for &h in heights {
                if g.is_resolve_complete(h) {
                    continue;
                }
                if g.has_raw(h) {
                    out.raw.push((
                        h,
                        g.input_count_at(h).unwrap_or(0),
                        g.header_fk_at(h).unwrap_or(0),
                        g.sender_at(h),
                    ));
                } else if g.contains_height(h) {
                    promoted.push(h);
                }
            }
        }
        if !promoted.is_empty() {
            let stash = self.bq_resolved.lock().unwrap();
            for h in promoted {
                if let Some(wire) = stash.get(&h) {
                    out.resolved.push((h, wire.clone()));
                }
            }
        }
        out
    }

    /// Drop raw and insert decoded, charging `max(payload, decoded)`.
    ///
    /// Decoded stash first, then the row lock, so a promoted row always has
    /// a stash entry. The two locks are not held together.
    pub fn block_queue_promote_wave(
        &self,
        items: Vec<(u32, ResolvedWire, u64)>,
    ) -> Result<usize, QueryError> {
        {
            let mut stash = self.bq_resolved.lock().unwrap();
            for (height, wire, _) in &items {
                stash.insert(*height, wire.clone());
            }
        }
        let charges: Vec<(u32, u64)> = items.iter().map(|(h, _, c)| (*h, *c)).collect();
        self.block_queue.lock().unwrap().promote_wave(&charges)
    }

    pub fn block_queue_resolved(&self, height: u32) -> Option<ResolvedWire> {
        self.bq_resolved.lock().unwrap().get(&height).cloned()
    }

    /// Disconnect: drop decoded stash at `height` and above.
    pub fn block_queue_drop_resolved_from(&self, height: u32) {
        self.bq_resolved.lock().unwrap().retain(|&h, _| h < height);
    }

    pub fn block_queue_promoted_count(&self) -> usize {
        self.block_queue.lock().unwrap().promoted_count()
    }

    /// Cheap process-owned cache sizes for the IBD `ibd: sizes` line.
    ///
    /// Brief mutex locks only (header plans, height map). Call from the ~5s
    /// status tick — not the hot path.
    pub fn process_owned_size_snapshot(&self) -> ProcessOwnedSizes {
        note_owned_size_snapshot_call();
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

    /// Confirm thread: refresh the scripthash-run and owned-size counters.
    pub fn publish_progress_snapshots(&self) {
        let runs = self.scripthash_run_count();
        self.sh_runs_published.store(runs, AtomicOrdering::Relaxed);
        let owned = self.process_owned_size_snapshot();
        self.owned_sizes_published.store(Arc::new(owned));
    }

    pub fn published_scripthash_run_count(&self) -> usize {
        self.sh_runs_published.load(AtomicOrdering::Relaxed)
    }

    pub fn published_owned_sizes(&self) -> ProcessOwnedSizes {
        **self.owned_sizes_published.load()
    }

    /// Durable `tx.head` occupied slots (for backfill heuristics / logs).
    pub fn tx_head_occupied(&self) -> u64 {
        self.store.txs.head_occupied()
    }

    /// Thin scripthash create row count (diagnostic / tip-mode logs).
    pub fn scripthash_entry_count(&self) -> u64 {
        self.store.scripthash.entry_count()
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
        crate::chain_view::note_header_lookup();
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

    pub fn tx_prevouts_for_fk(&self, fk: Fk) -> Result<Vec<(Fk, u32)>, QueryError> {
        match self.store.get_tx_meta_and_prevouts(fk) {
            Ok((_, prevs)) => Ok(prevs),
            Err(StoreError::NotFound) if self.prune_seqsigwit() => {
                let tx = self.get_tx(fk)?;
                let Some(inputs) = self.seqsigwit_cached_inputs(fk, tx.input_count)? else {
                    let height = self.store.tx_height_get(fk)?.unwrap_or(0);
                    return Err(StoreError::Pruned { height });
                };
                Ok(inputs
                    .iter()
                    .map(|i| (i.create_fk(), i.prev_index()))
                    .collect())
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

    /// A parent on the connected chain for a prevout reader: tip-only fk
    /// resolve (`txid.body` verify, no decode) that also yields the create
    /// height, then one packed outs decode for every output. `None` when
    /// `txid` has no row on the best chain or the tx index is off. Mempool
    /// accept and the block proposal check share this.
    pub fn connected_tx_outputs(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<(Fk, u32, Vec<OutputRecord>)>, QueryError> {
        if !self.tx_index_enabled() {
            return Ok(None);
        }
        let Some((fk, height)) = self.store.get_fk_by_txid_tip_height(txid)? else {
            return Ok(None);
        };
        let (_, outs) = self.store.get_tx_meta_and_outputs(fk)?;
        Ok(Some((fk, height, outs)))
    }

    /// Core's coinbase test for a create on the best chain: `fk` is the first
    /// tx of the block at `height`. Class C dense tables only; no body read.
    pub fn is_coinbase_create(&self, fk: Fk, height: u32) -> Result<bool, QueryError> {
        Ok(self.store.coinbase_fk_at_heights(&[height])?.get(&height) == Some(&fk))
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
    pub fn attach_confirm_write(&self, tx: std::sync::mpsc::SyncSender<crate::ConfirmWriteMsg>) {
        *self.confirm_write.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    /// Drop the sender when `ibd-confirm-write` exits so a later clear does
    /// not wait on a thread that is gone.
    pub fn detach_confirm_write(&self) {
        *self.confirm_write.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn clear_archived_body(&self, hash: &[u8; 32]) -> Result<bool, QueryError> {
        debug_assert!(
            !rbitcoin_store::coord_shared_lock_held(),
            "archived clear waits while the coordinator holds shared"
        );
        let tx = self
            .confirm_write
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            tx.send(crate::ConfirmWriteMsg::ClearArchived {
                hash: *hash,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::Cancelled("confirm write stopped"))?;
            return reply_rx
                .recv()
                .map_err(|_| StoreError::Cancelled("confirm write stopped"))?;
        }
        self.clear_archived_body_here(hash)
    }

    /// Clear on the calling thread. The confirm-write thread calls this after
    /// it joins the tip flush. With no sender installed (unit tests, before
    /// the engine) [`Self::clear_archived_body`] calls it inline.
    #[doc(hidden)]
    pub fn clear_archived_body_here(&self, hash: &[u8; 32]) -> Result<bool, QueryError> {
        let Some((fk, _)) = self.get_header_by_hash(hash)? else {
            return Ok(false);
        };
        let write = rbitcoin_store::ClassCWrite::new();
        let cleared = self.store.header_txs.clear_body(&write, fk)?;
        if cleared {
            self.store.header_txs.flush()?;
        }
        Ok(cleared)
    }

    /// Total headers with a Class A body on disk (durable, any prior run).
    pub fn archived_block_count(&self) -> Result<u64, QueryError> {
        self.store.archived_block_count()
    }

    /// IBD seeding climbs this many ancestors looking for a heavier sibling.
    /// Startup's heavier-chain check climbs to genesis instead.
    #[doc(hidden)]
    pub const RESUME_ANCESTOR_HOPS: u32 = 32;

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
    ///
    /// The sibling search climbs at most 32 ancestors.
    pub fn resume_work_path_after_tip_excluding(
        &self,
        tip_hash: [u8; 32],
        tip_height: u32,
        max: usize,
        exclude: &[[u8; 32]],
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        self.resume_work_path_limited(
            tip_hash,
            tip_height,
            max,
            exclude,
            Self::RESUME_ANCESTOR_HOPS,
        )
    }

    /// True when any stored header path has more work than the confirmed tip.
    ///
    /// The sibling search climbs to genesis. IBD seeding keeps the 32-hop cap;
    /// startup uses this so a deep stored fork still stays in catch-up.
    /// A tip hash with no header row is an empty path (`Ok(false)`). A path
    /// through an `exclude` hash (a known-invalid block) does not count.
    pub fn has_heavier_header_chain_than_tip(
        &self,
        tip_hash: [u8; 32],
        tip_height: u32,
        exclude: &[[u8; 32]],
    ) -> Result<bool, QueryError> {
        let path = self.resume_work_path_limited(tip_hash, tip_height, 1, exclude, u32::MAX)?;
        Ok(!path.is_empty())
    }

    #[doc(hidden)]
    pub fn resume_work_path_limited(
        &self,
        tip_hash: [u8; 32],
        tip_height: u32,
        max: usize,
        exclude: &[[u8; 32]],
        ancestor_hops: u32,
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let Some((tip_fk, _)) = self.get_header_by_hash(&tip_hash)? else {
            return Ok(Vec::new());
        };
        let n = self.store.header_count();
        if n == 0 {
            return Ok(Vec::new());
        }

        let index = Self::resume_index_children(&self.store, n, exclude)?;
        let mut score_memo: U64Map<(bitcoin::Work, u32)> = U64Map::default();
        let best_sib = self.resume_nearest_better_sib(
            tip_fk,
            tip_height,
            &index,
            &mut score_memo,
            ancestor_hops,
        )?;
        self.resume_walk_best_kids(tip_fk, tip_height, max, best_sib, &index, &mut score_memo)
    }

    #[doc(hidden)]
    pub fn resume_index_children(
        store: &rbitcoin_store::Store,
        n: u64,
        exclude: &[[u8; 32]],
    ) -> Result<ResumeHeaderIndex, QueryError> {
        let mut children: ResumeChildMap = ResumeChildMap::default();
        let mut bits = vec![0u32; n as usize];
        let mut prevs = vec![0u64; n as usize];
        store.headers.for_each_record_through(n, |fk, rec| {
            let i = (fk.0 - 1) as usize;
            let Some(slot) = bits.get_mut(i) else {
                return Err(StoreError::Corrupt("resume header fk"));
            };
            *slot = rec.bits;
            let Some(slot) = prevs.get_mut(i) else {
                return Err(StoreError::Corrupt("resume header fk"));
            };
            *slot = rec.prev_fk.0;
            if exclude.contains(&rec.hash) {
                return Ok(());
            }
            let prev = rec.prev_fk.get().unwrap_or(0);
            children.entry(prev).or_default().push((fk, rec.hash));
            Ok(())
        })?;
        Ok(ResumeHeaderIndex {
            children,
            bits,
            prevs,
        })
    }

    #[doc(hidden)]
    pub fn resume_parent(index: &ResumeHeaderIndex, fk: Fk) -> Option<u64> {
        let i = fk.0.checked_sub(1)? as usize;
        Fk::new(*index.prevs.get(i)?).map(|p| p.0)
    }

    #[doc(hidden)]
    pub fn resume_nearest_better_sib(
        &self,
        tip_fk: Fk,
        tip_height: u32,
        index: &ResumeHeaderIndex,
        score_memo: &mut U64Map<(bitcoin::Work, u32)>,
        ancestor_hops: u32,
    ) -> Result<Option<ResumeSibPick>, QueryError> {
        let mut best_sib: Option<ResumeSibPick> = None;
        let mut path_fk = tip_fk;
        let mut path_h = tip_height;
        for _ in 0..ancestor_hops {
            let Some(parent_fk) = Self::resume_parent(index, path_fk) else {
                break;
            };
            let (path_sub_w, _path_sub_d) = Self::resume_subtree_score(index, path_fk, score_memo)?;
            if let Some(sibs) = index.children.get(&parent_fk) {
                for &(fk, hash) in sibs {
                    if fk == path_fk {
                        continue;
                    }
                    let has_body = self.store.header_txs.has_body(fk)?;
                    let (sub_w, sub_d) = Self::resume_subtree_score(index, fk, score_memo)?;
                    if sub_w <= path_sub_w {
                        continue;
                    }
                    let take = match best_sib {
                        None => true,
                        Some((best_fk, _, best_body, _, _)) => {
                            let (best_w, best_d) =
                                Self::resume_subtree_score(index, best_fk, score_memo)?;
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
                        let parent_hash = self.get_header(Fk(parent_fk))?.hash;
                        best_sib = Some((fk, hash, has_body, path_h, parent_hash));
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
        }
        Ok(best_sib)
    }

    #[doc(hidden)]
    pub fn resume_walk_best_kids(
        &self,
        tip_fk: Fk,
        tip_height: u32,
        max: usize,
        best_sib: Option<ResumeSibPick>,
        index: &ResumeHeaderIndex,
        score_memo: &mut U64Map<(bitcoin::Work, u32)>,
    ) -> Result<Vec<ResumeWorkEntry>, QueryError> {
        let mut out = Vec::with_capacity(max.min(4096));
        let (mut cur_fk, mut height, mut prev_hash) =
            if let Some((fk, hash, has_body, sib_h, parent)) = best_sib {
                out.push(ResumeWorkEntry {
                    height: sib_h,
                    hash,
                    prev_hash: parent,
                    header_fk: fk,
                    has_body,
                });
                (fk, sib_h, hash)
            } else {
                (tip_fk, tip_height, self.get_header(tip_fk)?.hash)
            };

        while out.len() < max {
            let Some(kids) = index.children.get(&cur_fk.0) else {
                break;
            };
            if kids.is_empty() {
                break;
            }
            let mut best: Option<(Fk, [u8; 32], bool, bitcoin::Work, u32)> = None;
            for &(fk, hash) in kids {
                let has_body = self.store.header_txs.has_body(fk)?;
                let (sub_work, depth) = Self::resume_subtree_score(index, fk, score_memo)?;
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
                prev_hash,
                header_fk: fk,
                has_body,
            });
            prev_hash = hash;
            cur_fk = fk;
        }
        Ok(out)
    }

    /// Max path work and depth under `root` (including root header work).
    ///
    /// Used by [`Self::resume_work_path_after_tip`] to prefer most-work children
    /// over body-only archived losers. Work comes from `nBits` captured while
    /// the child index was built.
    ///
    /// **Iterative** post-order walk into a **shared** `memo` (one map per resume).
    /// Recursive DFS stack-overflowed (SIGSEGV) on mid-IBD restart; a fresh memo
    /// per call was O(depth²) on long header bands (each path step re-walked the
    /// remaining chain).
    ///
    /// Gray (`on_stack`) nodes are not re-pushed: a `prev_fk` cycle used to spin
    /// the IBD thread after `resume seed walk start` with no further log.
    pub fn resume_subtree_score(
        index: &ResumeHeaderIndex,
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
                if let Some(kids) = index.children.get(&fk.0) {
                    for &(ck, _) in kids {
                        if !memo.contains_key(&ck.0) && !on_stack.contains(&ck.0) {
                            stack.push((ck, false));
                        }
                    }
                }
                continue;
            }
            on_stack.remove(&fk.0);
            let bits_i = (fk.0 - 1) as usize;
            let bits = index
                .bits
                .get(bits_i)
                .copied()
                .ok_or(StoreError::Corrupt("resume header bits"))?;
            let own = Target::from_compact(CompactTarget::from_consensus(bits)).to_work();
            let mut best_child_w = bitcoin::Work::from_be_bytes([0u8; 32]);
            let mut best_depth = 0u32;
            if let Some(kids) = index.children.get(&fk.0) {
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
        let _commit = self.lock_tip_commit()?;
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
        let _commit = self.lock_tip_commit()?;
        self.store.flush()
    }
}

#[doc(hidden)]
pub fn wire_header(rec: &HeaderRecord, prev_blockhash: BlockHash) -> BlockHeader {
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
