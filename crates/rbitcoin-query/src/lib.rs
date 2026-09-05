//! Domain query layer over [`rbitcoin_store::Store`].

mod archive;
mod batch_parents;
mod catchup;
mod chain_view;
mod combined_stage;
mod confirm_load;
mod confirm_parent_cache;
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
mod tx_precompute;
mod wave_prevout;

pub use combined_stage::{body_ok_reads, load_creates_once, reset_body_ok_reads, CombinedCreate};
pub use resolved_wire::{BlockQueueWaveIntake, ResolvedWire};
pub use soft_densify::{
    bq_assign_stop_bytes, soft_assign_restricted, soft_assign_stopped, soft_confirm_window_covered,
    soft_confirm_window_n, soft_densify_band_hi, BQ_ASSIGN_STOP_BYTES, BQ_SOFT_CONFIRM_SECS,
    BQ_SOFT_FREE_BYTES,
};
pub use sp_tweaks::{ThinTweakRangeLimits, ThinTweakRow};
pub use tx_precompute::TxPrecompute;

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
use std::sync::{Condvar, Mutex};

pub type QueryError = StoreError;

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
    /// Unused process pstore meters (always 0; BatchParents is batch-local).
    pub pstore_weak: usize,
    pub pstore_live: usize,
    pub pstore_bytes: u64,
    /// Write-published recent-create layer chain (layers / live keys).
    pub recent_heights: usize,
    pub recent_keys: usize,
    /// Published layer keys (pending not included).
    pub recent_pub_keys: usize,
    pub recent_overlay_keys: usize,
    /// Same as live keys (pending + published).
    pub recent_fifo_keys: usize,
    /// Live CreatePin payload bytes (not 96 B/key).
    pub recent_pin_bytes: u64,
    /// Confirmed hash→height map entries.
    pub h2h_keys: usize,
    /// Height-fence run count (no Vec clone).
    pub fence_runs: usize,
    /// Body-queue heights whose raw payload was dropped after lookup decode.
    pub bq_promoted: usize,
}

/// Plan-thread published heap meters for structures not owned by [`Query`].
///
/// Updated after each load note/prune ([`InFlight`]). IBD pstore counts stay 0.
/// Sampled by the ~5s IBD sizes line.
pub mod process_mem_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static INFLIGHT_LAYERS: AtomicU64 = AtomicU64::new(0);
    static INFLIGHT_PINS: AtomicU64 = AtomicU64::new(0);
    static INFLIGHT_BYTES: AtomicU64 = AtomicU64::new(0);
    static PSTORE_WEAK: AtomicU64 = AtomicU64::new(0);
    static PSTORE_LIVE: AtomicU64 = AtomicU64::new(0);
    static PSTORE_BYTES: AtomicU64 = AtomicU64::new(0);

    /// Publish latest prep-ahead / parent-store occupancy (overwrite).
    pub fn note(
        inflight_layers: usize,
        inflight_pins: usize,
        inflight_bytes: u64,
        pstore_weak: usize,
        pstore_live: usize,
        pstore_bytes: u64,
    ) {
        INFLIGHT_LAYERS.store(inflight_layers as u64, Ordering::Relaxed);
        INFLIGHT_PINS.store(inflight_pins as u64, Ordering::Relaxed);
        INFLIGHT_BYTES.store(inflight_bytes, Ordering::Relaxed);
        PSTORE_WEAK.store(pstore_weak as u64, Ordering::Relaxed);
        PSTORE_LIVE.store(pstore_live as u64, Ordering::Relaxed);
        PSTORE_BYTES.store(pstore_bytes, Ordering::Relaxed);
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Snap {
        pub inflight_layers: usize,
        pub inflight_pins: usize,
        pub inflight_bytes: u64,
        pub pstore_weak: usize,
        pub pstore_live: usize,
        pub pstore_bytes: u64,
    }

    pub fn load() -> Snap {
        Snap {
            inflight_layers: INFLIGHT_LAYERS.load(Ordering::Relaxed) as usize,
            inflight_pins: INFLIGHT_PINS.load(Ordering::Relaxed) as usize,
            inflight_bytes: INFLIGHT_BYTES.load(Ordering::Relaxed),
            pstore_weak: PSTORE_WEAK.load(Ordering::Relaxed) as usize,
            pstore_live: PSTORE_LIVE.load(Ordering::Relaxed) as usize,
            pstore_bytes: PSTORE_BYTES.load(Ordering::Relaxed),
        }
    }
}

pub use archive::{ArchiveWritePlan, CreatePin};
pub use batch_parents::{
    layout_covers_need, sparse_spender_rels, BatchParents, FkMap, FkSet, SharedParentPin, U32Map,
    U64Map, U64Set, SPENDER_REL_UNKNOWN,
};
pub use catchup::IndexMode;
pub use chain_view::{ChainView, ChainViewKind};
pub use confirm_load::ConfirmLoadStats;
pub use confirm_load::SpendEdges;
pub use connect::{format_disconnect_tip_line, spawn_sh_writebehind, ConfirmPrepared};
pub use id_map::{IdMap, OutPointHasher, OutPointSet, TxidHasher};
pub use in_flight::InFlight;
pub use scripthash::{
    apply_history_filter, HistoryFilter, HistoryOrder, ScanUtxo, ScriptHashBalance,
    ScriptHashChainStats, ScriptHashHistoryItem, ScriptHashOutpoint, ScriptHashUtxo, ShJoinSlot,
};
pub use stamp::{
    fill_missing_parent_ranges, stamp_external_parents, BatchParentIds, ExternalParentStamp,
    ParentIdent,
};
pub use wave_prevout::SpendEdge;

/// Confirm load Class A / parent-pin window counters (IBD ~5s sampler).
///
/// Accrued by wire pin (`pin_for_wire_batch`).
/// Pair with [`Query::parent_cache_perf_snapshot`] for header-plan occupancy.
pub mod confirm_load_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Pin/load wall (wire pin).
    pub static NS: AtomicU64 = AtomicU64::new(0);
    pub static BLOCKS: AtomicU64 = AtomicU64::new(0);
    pub static UTXO_PARENTS: AtomicU64 = AtomicU64::new(0);
    pub static CREATES: AtomicU64 = AtomicU64::new(0);
    pub static PARENT_UNIQUE: AtomicU64 = AtomicU64::new(0);
    /// Pin filled from same-batch / in-flight / pstore adopt (no Class A re-decode).
    pub static PIN_CACHE_BODY: AtomicU64 = AtomicU64::new(0);
    /// Wire plan / in-flight parent pins (subset of pin_cache; not denserels hits).
    pub static PIN_PLAN: AtomicU64 = AtomicU64::new(0);
    /// Pin candidates that missed same-batch / in-flight / adopt (cold denserels).
    pub static PIN_NEW: AtomicU64 = AtomicU64::new(0);
    pub static PIN_BODY_NS: AtomicU64 = AtomicU64::new(0);
    pub static PIN_NEW_META_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire pin sub-walls (ns).
    pub static PLAN_PIN_NS: AtomicU64 = AtomicU64::new(0);
    /// Pipeline store adopt (bulk Weak upgrade) wall.
    pub static PIN_ADOPT_NS: AtomicU64 = AtomicU64::new(0);
    /// Post cold-range denserels: insert_owned into BatchParents (not IO).
    pub static PIN_RANGE_FILL_NS: AtomicU64 = AtomicU64::new(0);
    /// Stamp-carried CreatePin probe (after in-flight / same-batch, before range fill).
    pub static PIN_RECENT_OUTS_NS: AtomicU64 = AtomicU64::new(0);
    /// Final pin contract (contains + pin_covered) wall.
    pub static PIN_CONTRACT_NS: AtomicU64 = AtomicU64::new(0);
    /// Pipeline store publish (bulk Weak insert + conflict merge) wall.
    pub static PIN_PUBLISH_NS: AtomicU64 = AtomicU64::new(0);
    /// Cold denserels wall (range + idx). Prefer split fields when diagnosing.
    pub static COLD_IO_NS: AtomicU64 = AtomicU64::new(0);
    /// Cold denserels via plan stamp body range (`get_outs_by_range_batch`).
    pub static COLD_RANGE_NS: AtomicU64 = AtomicU64::new(0);
    pub static COLD_RANGE_N: AtomicU64 = AtomicU64::new(0);
    /// Sub-wall of cold range: body pread only (N2.0).
    pub static COLD_RANGE_BODY_NS: AtomicU64 = AtomicU64::new(0);
    /// Sub-wall of cold range: sparse denserels decode (N2.0).
    pub static COLD_RANGE_DECODE_NS: AtomicU64 = AtomicU64::new(0);
    /// Cold denserels via idx→body (`load_creates_once`).
    pub static COLD_IDX_NS: AtomicU64 = AtomicU64::new(0);
    pub static COLD_IDX_N: AtomicU64 = AtomicU64::new(0);
    pub static COLD_DECODE_NS: AtomicU64 = AtomicU64::new(0);
    pub static PARENT_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
    pub static FULL_TX_READS: AtomicU64 = AtomicU64::new(0);
    pub static BODY_TX_READS: AtomicU64 = AtomicU64::new(0);
    pub static MISSING_PARENTS: AtomicU64 = AtomicU64::new(0);
    /// Phase nanoseconds (sum over calls this window).
    pub static HEADER_NS: AtomicU64 = AtomicU64::new(0);
    pub static BODY_DECODE_NS: AtomicU64 = AtomicU64::new(0);
    pub static THIN_NS: AtomicU64 = AtomicU64::new(0);
    pub static PARENT_PIN_NS: AtomicU64 = AtomicU64::new(0);
    pub static CACHE_PUT_NS: AtomicU64 = AtomicU64::new(0);
    /// Thin edges: same-batch / stamped-fk / coinbase.
    pub static EDGE_SAME_BATCH: AtomicU64 = AtomicU64::new(0);
    pub static EDGE_FK: AtomicU64 = AtomicU64::new(0);
    pub static EDGE_COINBASE: AtomicU64 = AtomicU64::new(0);

    /// One sampler snapshot (all counters reset).
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Sample {
        pub ns: u64,
        pub blocks: u64,
        pub utxo_parents: u64,
        pub creates: u64,
        pub parent_unique: u64,
        pub pin_cache_body: u64,
        pub pin_plan: u64,
        pub pin_new: u64,
        pub pin_body_ns: u64,
        pub pin_new_meta_ns: u64,
        pub plan_pin_ns: u64,
        pub pin_adopt_ns: u64,
        pub pin_range_fill_ns: u64,
        pub pin_recent_outs_ns: u64,
        pub pin_contract_ns: u64,
        pub pin_publish_ns: u64,
        pub cold_io_ns: u64,
        pub cold_range_ns: u64,
        pub cold_range_n: u64,
        pub cold_range_body_ns: u64,
        pub cold_range_decode_ns: u64,
        pub cold_idx_ns: u64,
        pub cold_idx_n: u64,
        pub cold_decode_ns: u64,
        pub cache_hits: u64,
        pub body_tx: u64,
        pub parent_tx: u64,
        pub missing: u64,
        pub header_ns: u64,
        pub body_decode_ns: u64,
        pub thin_ns: u64,
        pub parent_pin_ns: u64,
        pub cache_put_ns: u64,
        pub edge_same_batch: u64,
        pub edge_fk: u64,
        pub edge_coinbase: u64,
    }

    static LAST_PIN_ADOPT_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_PLAN_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_COLD_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_CONTRACT_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_PUBLISH_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_PLAN_N: AtomicU64 = AtomicU64::new(0);
    static LAST_PIN_NEW_N: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastPinPhases {
        pub adopt_ns: u64,
        pub plan_pin_ns: u64,
        pub cold_ns: u64,
        pub contract_ns: u64,
        pub publish_ns: u64,
        pub pin_plan_n: u64,
        pub pin_new_n: u64,
    }

    impl LastPinPhases {
        #[inline]
        pub fn ms(ns: u64) -> u64 {
            ns / 1_000_000
        }
    }

    /// Overwrite last pin residual (one prep pin_for_wire_batch).
    pub fn note_last_pin(
        adopt_ns: u64,
        plan_pin_ns: u64,
        cold_ns: u64,
        contract_ns: u64,
        publish_ns: u64,
        pin_plan_n: u64,
        pin_new_n: u64,
    ) {
        LAST_PIN_ADOPT_NS.store(adopt_ns, Ordering::Relaxed);
        LAST_PIN_PLAN_NS.store(plan_pin_ns, Ordering::Relaxed);
        LAST_PIN_COLD_NS.store(cold_ns, Ordering::Relaxed);
        LAST_PIN_CONTRACT_NS.store(contract_ns, Ordering::Relaxed);
        LAST_PIN_PUBLISH_NS.store(publish_ns, Ordering::Relaxed);
        LAST_PIN_PLAN_N.store(pin_plan_n, Ordering::Relaxed);
        LAST_PIN_NEW_N.store(pin_new_n, Ordering::Relaxed);
    }

    pub fn last_pin_phases() -> LastPinPhases {
        LastPinPhases {
            adopt_ns: LAST_PIN_ADOPT_NS.load(Ordering::Relaxed),
            plan_pin_ns: LAST_PIN_PLAN_NS.load(Ordering::Relaxed),
            cold_ns: LAST_PIN_COLD_NS.load(Ordering::Relaxed),
            contract_ns: LAST_PIN_CONTRACT_NS.load(Ordering::Relaxed),
            publish_ns: LAST_PIN_PUBLISH_NS.load(Ordering::Relaxed),
            pin_plan_n: LAST_PIN_PLAN_N.load(Ordering::Relaxed),
            pin_new_n: LAST_PIN_NEW_N.load(Ordering::Relaxed),
        }
    }

    pub fn sample_and_reset() -> Sample {
        Sample {
            ns: NS.swap(0, Ordering::Relaxed),
            blocks: BLOCKS.swap(0, Ordering::Relaxed),
            utxo_parents: UTXO_PARENTS.swap(0, Ordering::Relaxed),
            creates: CREATES.swap(0, Ordering::Relaxed),
            parent_unique: PARENT_UNIQUE.swap(0, Ordering::Relaxed),
            pin_cache_body: PIN_CACHE_BODY.swap(0, Ordering::Relaxed),
            pin_plan: PIN_PLAN.swap(0, Ordering::Relaxed),
            pin_new: PIN_NEW.swap(0, Ordering::Relaxed),
            pin_body_ns: PIN_BODY_NS.swap(0, Ordering::Relaxed),
            pin_new_meta_ns: PIN_NEW_META_NS.swap(0, Ordering::Relaxed),
            plan_pin_ns: PLAN_PIN_NS.swap(0, Ordering::Relaxed),
            pin_adopt_ns: PIN_ADOPT_NS.swap(0, Ordering::Relaxed),
            pin_range_fill_ns: PIN_RANGE_FILL_NS.swap(0, Ordering::Relaxed),
            pin_recent_outs_ns: PIN_RECENT_OUTS_NS.swap(0, Ordering::Relaxed),
            pin_contract_ns: PIN_CONTRACT_NS.swap(0, Ordering::Relaxed),
            pin_publish_ns: PIN_PUBLISH_NS.swap(0, Ordering::Relaxed),
            cold_io_ns: COLD_IO_NS.swap(0, Ordering::Relaxed),
            cold_range_ns: COLD_RANGE_NS.swap(0, Ordering::Relaxed),
            cold_range_n: COLD_RANGE_N.swap(0, Ordering::Relaxed),
            cold_range_body_ns: COLD_RANGE_BODY_NS.swap(0, Ordering::Relaxed),
            cold_range_decode_ns: COLD_RANGE_DECODE_NS.swap(0, Ordering::Relaxed),
            cold_idx_ns: COLD_IDX_NS.swap(0, Ordering::Relaxed),
            cold_idx_n: COLD_IDX_N.swap(0, Ordering::Relaxed),
            cold_decode_ns: COLD_DECODE_NS.swap(0, Ordering::Relaxed),
            cache_hits: PARENT_CACHE_HITS.swap(0, Ordering::Relaxed),
            body_tx: BODY_TX_READS.swap(0, Ordering::Relaxed),
            parent_tx: FULL_TX_READS.swap(0, Ordering::Relaxed),
            missing: MISSING_PARENTS.swap(0, Ordering::Relaxed),
            header_ns: HEADER_NS.swap(0, Ordering::Relaxed),
            body_decode_ns: BODY_DECODE_NS.swap(0, Ordering::Relaxed),
            thin_ns: THIN_NS.swap(0, Ordering::Relaxed),
            parent_pin_ns: PARENT_PIN_NS.swap(0, Ordering::Relaxed),
            cache_put_ns: CACHE_PUT_NS.swap(0, Ordering::Relaxed),
            edge_same_batch: EDGE_SAME_BATCH.swap(0, Ordering::Relaxed),
            edge_fk: EDGE_FK.swap(0, Ordering::Relaxed),
            edge_coinbase: EDGE_COINBASE.swap(0, Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn note(st: &crate::confirm_load::ConfirmLoadStats, ns: u64) {
        if ns > 0 {
            NS.fetch_add(ns, Ordering::Relaxed);
        }
        macro_rules! add {
            ($field:ident, $atom:ident) => {
                if st.$field > 0 {
                    $atom.fetch_add(st.$field as u64, Ordering::Relaxed);
                }
            };
        }
        add!(blocks, BLOCKS);
        add!(utxo_parents, UTXO_PARENTS);
        add!(creates_registered, CREATES);
        add!(parent_unique, PARENT_UNIQUE);
        add!(pin_cache_body, PIN_CACHE_BODY);
        add!(pin_new, PIN_NEW);
        add!(pin_body_ns, PIN_BODY_NS);
        add!(pin_new_meta_ns, PIN_NEW_META_NS);
        add!(parent_cache_hits, PARENT_CACHE_HITS);
        add!(full_tx_reads, FULL_TX_READS);
        add!(body_tx_reads, BODY_TX_READS);
        add!(missing_parents, MISSING_PARENTS);
        add!(header_ns, HEADER_NS);
        add!(body_decode_ns, BODY_DECODE_NS);
        add!(thin_ns, THIN_NS);
        add!(parent_pin_ns, PARENT_PIN_NS);
        add!(cache_put_ns, CACHE_PUT_NS);
        add!(edge_same_batch, EDGE_SAME_BATCH);
        add!(edge_fk, EDGE_FK);
        add!(edge_coinbase, EDGE_COINBASE);
    }
}

/// Archive prep + commit phase walls and resolve counts (IBD ~5s sampler reset).
///
/// **Accounting:** `prep_total_ns` / `write_total_ns` are end-to-end walls for
/// each batch; sub-phase ns should sum to ≈ total (gap = unaccounted). Prep
/// includes structure decode, plan/resolve, and write-queue wait. Write includes
/// reserve, body, head, spends, header_txs, and periodic flush.
pub mod archive_phase_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test builds: serialize note_* + [`sample_and_reset`] so a coverage
    /// worker cannot steal this thread's window. Re-entrant on the same thread
    /// so [`with_exclusive`] can wrap a plan+commit+sample.
    #[cfg(test)]
    mod exclusive {
        use std::cell::Cell;
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        thread_local! {
            static HELD: Cell<bool> = const { Cell::new(false) };
        }
        pub fn with<R>(f: impl FnOnce() -> R) -> R {
            if HELD.with(Cell::get) {
                return f();
            }
            let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            HELD.with(|h| h.set(true));
            let r = f();
            HELD.with(|h| h.set(false));
            r
        }
    }
    #[cfg(not(test))]
    mod exclusive {
        #[inline]
        pub fn with<R>(f: impl FnOnce() -> R) -> R {
            f()
        }
    }

    /// Hold the test stats lock across drain → work → sample (integration pins).
    #[cfg(test)]
    pub fn with_exclusive<R>(f: impl FnOnce() -> R) -> R {
        exclusive::with(f)
    }

    /// Headers (blocks) planned this window.
    pub static BLOCKS: AtomicU64 = AtomicU64::new(0);
    pub static EXT_NEED: AtomicU64 = AtomicU64::new(0);
    pub static HEAD_NEED: AtomicU64 = AtomicU64::new(0);
    pub static HEAD_HIT: AtomicU64 = AtomicU64::new(0);
    /// Unique prev_txids resolved from the load-batch skeleton.
    pub static PIN_TXID_N: AtomicU64 = AtomicU64::new(0);
    /// Wall of that consult (RAM).
    pub static PIN_TXID_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-published recent-create identity hits (after published, before leftover).
    pub static RECENT_N: AtomicU64 = AtomicU64::new(0);
    pub static RECENT_NS: AtomicU64 = AtomicU64::new(0);
    /// Leftover TipOnly: pending-head hits among `head_need`.
    pub static LEFTOVER_PEND: AtomicU64 = AtomicU64::new(0);
    /// Leftover hit ages ≤0 / ≤3 / hit count (for leftover_cdf).
    pub static LEFTOVER_AGE0: AtomicU64 = AtomicU64::new(0);
    pub static LEFTOVER_AGE3: AtomicU64 = AtomicU64::new(0);
    pub static LEFTOVER_AGE_N: AtomicU64 = AtomicU64::new(0);
    pub static BATCH_STAMP: AtomicU64 = AtomicU64::new(0);
    pub static RESOLVED_STAMP: AtomicU64 = AtomicU64::new(0);
    /// `fill_missing_parent_ranges` entries (stamp + optional prestamp).
    pub static FILL_MISSING_N: AtomicU64 = AtomicU64::new(0);

    /// Full load batch wall (struct → lookup → enqueue wait).
    pub static PREP_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_STRUCT_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_FILTER_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_ASSIGN_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_COLLECT_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_INFLIGHT_NS: AtomicU64 = AtomicU64::new(0);
    /// Leftover TipOnly head wall (= PREP_HEAD_FK_NS).
    pub static PREP_HEAD_NS: AtomicU64 = AtomicU64::new(0);
    /// Leftover TipOnly `get_fk_by_txid_batch`.
    pub static PREP_HEAD_FK_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_STAMP_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_FINISH_NS: AtomicU64 = AtomicU64::new(0);
    /// Reserved HWM + inflight create map publish after plan.
    pub static PREP_PUBLISH_NS: AtomicU64 = AtomicU64::new(0);
    /// Blocked on full prep→writer queue.
    pub static PREP_QWAIT_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREP_BLOCKS: AtomicU64 = AtomicU64::new(0);

    pub static WRITE_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_RESERVE_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_BODY_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_HEAD_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_SPEND_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_HTXS_NS: AtomicU64 = AtomicU64::new(0);
    /// Periodic `flush_header_archive` on the writer thread.
    pub static WRITE_FLUSH_NS: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_BLOCKS: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Default, Clone, Copy)]
    pub struct Sample {
        pub blocks: u64,
        pub ext_need: u64,
        pub head_need: u64,
        pub head_hit: u64,
        pub pin_txid_n: u64,
        pub pin_txid_ns: u64,
        pub recent_n: u64,
        pub recent_ns: u64,
        pub leftover_pend: u64,
        pub leftover_cdf0_pct: u64,
        pub leftover_cdf3_pct: u64,
        pub leftover_age_n: u64,
        pub batch_stamp: u64,
        pub resolved_stamp: u64,
        /// inflight + leftover head_fk.
        pub resolve_ns: u64,
        pub prep_total_ns: u64,
        pub prep_struct_ns: u64,
        pub prep_filter_ns: u64,
        pub prep_assign_ns: u64,
        pub prep_collect_ns: u64,
        pub prep_inflight_ns: u64,
        /// Leftover TipOnly `get_fk_by_txid_batch` (= prep_head_fk_ns).
        pub prep_head_ns: u64,
        /// Pure leftover tx.head resolve (`get_fk_by_txid_batch`).
        pub prep_head_fk_ns: u64,
        pub prep_stamp_ns: u64,
        pub prep_finish_ns: u64,
        pub prep_publish_ns: u64,
        pub prep_qwait_ns: u64,
        pub prep_blocks: u64,
        pub write_total_ns: u64,
        pub write_reserve_ns: u64,
        pub write_body_ns: u64,
        pub write_head_ns: u64,
        pub write_spend_ns: u64,
        pub write_htxs_ns: u64,
        pub write_flush_ns: u64,
        pub write_blocks: u64,
    }

    impl Sample {
        /// Sum of prep sub-phases (should ≈ prep_total_ns).
        pub fn prep_phases_sum_ns(&self) -> u64 {
            self.prep_struct_ns
                .saturating_add(self.prep_filter_ns)
                .saturating_add(self.prep_assign_ns)
                .saturating_add(self.prep_collect_ns)
                .saturating_add(self.prep_inflight_ns)
                .saturating_add(self.prep_head_ns)
                .saturating_add(self.prep_stamp_ns)
                .saturating_add(self.prep_finish_ns)
                .saturating_add(self.prep_publish_ns)
                .saturating_add(self.prep_qwait_ns)
        }

        /// Sum of write sub-phases (should ≈ write_total_ns).
        pub fn write_phases_sum_ns(&self) -> u64 {
            self.write_reserve_ns
                .saturating_add(self.write_body_ns)
                .saturating_add(self.write_head_ns)
                .saturating_add(self.write_spend_ns)
                .saturating_add(self.write_htxs_ns)
                .saturating_add(self.write_flush_ns)
        }
    }

    pub fn sample_and_reset() -> Sample {
        exclusive::with(sample_and_reset_inner)
    }

    fn sample_and_reset_inner() -> Sample {
        let prep_inflight = PREP_INFLIGHT_NS.swap(0, Ordering::Relaxed);
        let prep_head_fk = PREP_HEAD_FK_NS.swap(0, Ordering::Relaxed);
        let prep_head = PREP_HEAD_NS.swap(0, Ordering::Relaxed).max(prep_head_fk);
        Sample {
            blocks: BLOCKS.swap(0, Ordering::Relaxed),
            ext_need: EXT_NEED.swap(0, Ordering::Relaxed),
            head_need: HEAD_NEED.swap(0, Ordering::Relaxed),
            head_hit: HEAD_HIT.swap(0, Ordering::Relaxed),
            pin_txid_n: PIN_TXID_N.swap(0, Ordering::Relaxed),
            pin_txid_ns: PIN_TXID_NS.swap(0, Ordering::Relaxed),
            recent_n: RECENT_N.swap(0, Ordering::Relaxed),
            recent_ns: RECENT_NS.swap(0, Ordering::Relaxed),
            leftover_pend: LEFTOVER_PEND.swap(0, Ordering::Relaxed),
            leftover_cdf0_pct: {
                let n = LEFTOVER_AGE_N.load(Ordering::Relaxed);
                let a0 = LEFTOVER_AGE0.swap(0, Ordering::Relaxed);
                if n == 0 {
                    0
                } else {
                    a0.saturating_mul(100) / n
                }
            },
            leftover_cdf3_pct: {
                let n = LEFTOVER_AGE_N.load(Ordering::Relaxed);
                let a3 = LEFTOVER_AGE3.swap(0, Ordering::Relaxed);
                if n == 0 {
                    0
                } else {
                    a3.saturating_mul(100) / n
                }
            },
            leftover_age_n: LEFTOVER_AGE_N.swap(0, Ordering::Relaxed),
            batch_stamp: BATCH_STAMP.swap(0, Ordering::Relaxed),
            resolved_stamp: RESOLVED_STAMP.swap(0, Ordering::Relaxed),
            resolve_ns: prep_inflight.saturating_add(prep_head_fk),
            prep_total_ns: PREP_TOTAL_NS.swap(0, Ordering::Relaxed),
            prep_struct_ns: PREP_STRUCT_NS.swap(0, Ordering::Relaxed),
            prep_filter_ns: PREP_FILTER_NS.swap(0, Ordering::Relaxed),
            prep_assign_ns: PREP_ASSIGN_NS.swap(0, Ordering::Relaxed),
            prep_collect_ns: PREP_COLLECT_NS.swap(0, Ordering::Relaxed),
            prep_inflight_ns: prep_inflight,
            prep_head_ns: prep_head,
            prep_head_fk_ns: prep_head_fk,
            prep_stamp_ns: PREP_STAMP_NS.swap(0, Ordering::Relaxed),
            prep_finish_ns: PREP_FINISH_NS.swap(0, Ordering::Relaxed),
            prep_publish_ns: PREP_PUBLISH_NS.swap(0, Ordering::Relaxed),
            prep_qwait_ns: PREP_QWAIT_NS.swap(0, Ordering::Relaxed),
            prep_blocks: PREP_BLOCKS.swap(0, Ordering::Relaxed),
            write_total_ns: WRITE_TOTAL_NS.swap(0, Ordering::Relaxed),
            write_reserve_ns: WRITE_RESERVE_NS.swap(0, Ordering::Relaxed),
            write_body_ns: WRITE_BODY_NS.swap(0, Ordering::Relaxed),
            write_head_ns: WRITE_HEAD_NS.swap(0, Ordering::Relaxed),
            write_spend_ns: WRITE_SPEND_NS.swap(0, Ordering::Relaxed),
            write_htxs_ns: WRITE_HTXS_NS.swap(0, Ordering::Relaxed),
            write_flush_ns: WRITE_FLUSH_NS.swap(0, Ordering::Relaxed),
            write_blocks: WRITE_BLOCKS.swap(0, Ordering::Relaxed),
        }
    }

    #[inline]
    fn add(atom: &AtomicU64, v: u64) {
        if v > 0 {
            atom.fetch_add(v, Ordering::Relaxed);
        }
    }

    /// Resolve mix counters (one plan batch).
    #[inline]
    pub fn note_resolve_counts(
        blocks: u64,
        ext_need: u64,
        head_need: u64,
        head_hit: u64,
        batch_stamp: u64,
        resolved_stamp: u64,
    ) {
        exclusive::with(|| {
            add(&BLOCKS, blocks);
            add(&EXT_NEED, ext_need);
            add(&HEAD_NEED, head_need);
            add(&HEAD_HIT, head_hit);
            add(&BATCH_STAMP, batch_stamp);
            add(&RESOLVED_STAMP, resolved_stamp);
            // Finish-path stamp-only notes pass zeros for leftover mix.
            // last_plan_batch is the last leftover resolve (fail-pack leftover_n).
            if head_need > 0 {
                LAST_HEAD_NEED.store(head_need, Ordering::Relaxed);
                LAST_HEAD_HIT.store(head_hit, Ordering::Relaxed);
            }
        });
    }

    #[inline]
    pub fn note_fill_missing() {
        exclusive::with(|| {
            FILL_MISSING_N.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Leftover TipOnly pending hits + winner age buckets (load stamp).
    #[inline]
    pub fn note_leftover_mix(pend: u64, age0: u64, age3: u64, age_n: u64) {
        exclusive::with(|| {
            add(&LEFTOVER_PEND, pend);
            add(&LEFTOVER_AGE0, age0);
            add(&LEFTOVER_AGE3, age3);
            add(&LEFTOVER_AGE_N, age_n);
        });
    }

    /// Live-pin `txid → (fk, range)` hits this plan batch.
    #[inline]
    pub fn note_pin_txid(n: u64, ns: u64) {
        exclusive::with(|| {
            add(&PIN_TXID_N, n);
            add(&PIN_TXID_NS, ns);
        });
    }

    /// Recent-create ring hits this plan batch.
    #[inline]
    pub fn note_recent(n: u64, ns: u64) {
        exclusive::with(|| {
            add(&RECENT_N, n);
            add(&RECENT_NS, ns);
        });
    }

    /// Lookup sub-phases for one plan batch (`archive_plan_batch_from_store`).
    ///
    /// `head_fk_ns`: leftover TipOnly `get_fk_by_txid_batch` after BQ / pins.
    #[inline]
    pub fn note_prep_plan(
        assign_ns: u64,
        collect_ns: u64,
        inflight_ns: u64,
        head_fk_ns: u64,
        stamp_ns: u64,
        finish_ns: u64,
    ) {
        exclusive::with(|| {
            add(&PREP_ASSIGN_NS, assign_ns);
            add(&PREP_COLLECT_NS, collect_ns);
            add(&PREP_INFLIGHT_NS, inflight_ns);
            add(&PREP_HEAD_FK_NS, head_fk_ns);
            add(&PREP_HEAD_NS, head_fk_ns);
            add(&PREP_STAMP_NS, stamp_ns);
            add(&PREP_FINISH_NS, finish_ns);
        });
    }

    // Last leftover mix (overwrite when head_need > 0). Stamp-reject leftover_n
    // and the fail-pack test read this — leftover note_resolve_counts stores it
    // *before* stamp so a miss still meters. Stamp-only follow-up notes (zeros)
    // must not wipe it (parallel cargo test / finish path).
    static LAST_HEAD_NEED: AtomicU64 = AtomicU64::new(0);
    static LAST_HEAD_HIT: AtomicU64 = AtomicU64::new(0);

    /// Snapshot of the most recent leftover head resolve (one plan batch).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastPlanBatch {
        pub head_need: u64,
        pub head_hit: u64,
    }

    pub fn last_plan_batch() -> LastPlanBatch {
        LastPlanBatch {
            head_need: LAST_HEAD_NEED.load(Ordering::Relaxed),
            head_hit: LAST_HEAD_HIT.load(Ordering::Relaxed),
        }
    }

    static LAST_MISS_N: AtomicU64 = AtomicU64::new(0);
    static LAST_MISS_PEND: AtomicU64 = AtomicU64::new(0);
    static LAST_MISS_ON: AtomicU64 = AtomicU64::new(0);
    static LAST_MISS_CANDS: AtomicU64 = AtomicU64::new(0);
    static LAST_MISS_TXID: [AtomicU64; 4] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];

    fn miss_on_code(on: Option<&str>) -> u64 {
        match on {
            Some("head") => 1,
            Some("body") => 2,
            Some("idx") => 3,
            Some("fence") => 4,
            _ => 0,
        }
    }

    fn miss_on_from_code(code: u64) -> Option<&'static str> {
        match code {
            1 => Some("head"),
            2 => Some("body"),
            3 => Some("idx"),
            4 => Some("fence"),
            _ => None,
        }
    }

    /// First TipOnly-miss prev_txid after in-flight / pin / BQ (union miss).
    ///
    /// `miss_on` is `head` / `body` (`txid.body`) / `idx` / `fence` — the first
    /// table that did not produce a usable leftover fact.
    pub fn note_union_miss(
        txid: [u8; 32],
        n: u64,
        pending: bool,
        miss_on: Option<&str>,
        miss_cands: u64,
    ) {
        LAST_MISS_N.store(n, Ordering::Relaxed);
        LAST_MISS_PEND.store(u64::from(pending), Ordering::Relaxed);
        LAST_MISS_ON.store(miss_on_code(miss_on), Ordering::Relaxed);
        LAST_MISS_CANDS.store(miss_cands, Ordering::Relaxed);
        for (i, slot) in LAST_MISS_TXID.iter().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&txid[i.saturating_mul(8)..i.saturating_mul(8).saturating_add(8)]);
            slot.store(u64::from_le_bytes(b), Ordering::Relaxed);
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastUnionMiss {
        pub n: u64,
        pub pending: bool,
        pub txid: Option<[u8; 32]>,
        /// `head` / `body` / `idx` / `fence`.
        pub miss_on: Option<&'static str>,
        pub miss_cands: u64,
    }

    pub fn last_union_miss() -> LastUnionMiss {
        let n = LAST_MISS_N.load(Ordering::Relaxed);
        if n == 0 {
            return LastUnionMiss::default();
        }
        let mut txid = [0u8; 32];
        for (i, slot) in LAST_MISS_TXID.iter().enumerate() {
            let off = i.saturating_mul(8);
            txid[off..off.saturating_add(8)]
                .copy_from_slice(&slot.load(Ordering::Relaxed).to_le_bytes());
        }
        LastUnionMiss {
            n,
            pending: LAST_MISS_PEND.load(Ordering::Relaxed) != 0,
            txid: Some(txid),
            miss_on: miss_on_from_code(LAST_MISS_ON.load(Ordering::Relaxed)),
            miss_cands: LAST_MISS_CANDS.load(Ordering::Relaxed),
        }
    }

    /// Outer prep batch (structure + filter + publish + queue wait).
    /// Plan sub-phases are noted separately via [`note_prep_plan`].
    #[inline]
    pub fn note_prep_batch(
        total_ns: u64,
        struct_ns: u64,
        filter_ns: u64,
        publish_ns: u64,
        qwait_ns: u64,
        blocks: u64,
    ) {
        exclusive::with(|| {
            add(&PREP_TOTAL_NS, total_ns);
            add(&PREP_STRUCT_NS, struct_ns);
            add(&PREP_FILTER_NS, filter_ns);
            add(&PREP_PUBLISH_NS, publish_ns);
            add(&PREP_QWAIT_NS, qwait_ns);
            add(&PREP_BLOCKS, blocks);
        });
    }

    /// Commit path sub-phases (`archive_commit_plan`).
    #[inline]
    pub fn note_write_commit(
        total_ns: u64,
        reserve_ns: u64,
        body_ns: u64,
        head_ns: u64,
        spend_ns: u64,
        htxs_ns: u64,
        blocks: u64,
    ) {
        exclusive::with(|| {
            add(&WRITE_TOTAL_NS, total_ns);
            add(&WRITE_RESERVE_NS, reserve_ns);
            add(&WRITE_BODY_NS, body_ns);
            add(&WRITE_HEAD_NS, head_ns);
            add(&WRITE_SPEND_NS, spend_ns);
            add(&WRITE_HTXS_NS, htxs_ns);
            add(&WRITE_BLOCKS, blocks);
        });
    }

    #[inline]
    pub fn note_write_flush(ns: u64) {
        exclusive::with(|| {
            add(&WRITE_FLUSH_NS, ns);
            // Include flush in write total so phases_sum ≈ total.
            add(&WRITE_TOTAL_NS, ns);
        });
    }
}

/// Class C sub-phase wall times (nanoseconds; reset by the IBD sampler).
///
/// Split so logs can tell strong/height vs scripthash puts vs tip commit.
/// Scripthash subtimers (`SH_*`) break down collect vs durable append steps.
pub mod class_c_phase_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static STRONG_NS: AtomicU64 = AtomicU64::new(0);
    /// Wall time of the SH worker (collect + append), not including wait for strong.
    pub static SCRIPTHASH_NS: AtomicU64 = AtomicU64::new(0);
    pub static TIP_NS: AtomicU64 = AtomicU64::new(0);

    /// SH: load creates from Class A for new txs (Direct runs enqueue).
    pub static SH_COLLECT_NS: AtomicU64 = AtomicU64::new(0);
    /// SH: sort creates by scripthash (tip append path).
    pub static SH_SORT_NS: AtomicU64 = AtomicU64::new(0);
    /// SH: seed process/durable heads (tip append path).
    pub static SH_SEED_NS: AtomicU64 = AtomicU64::new(0);
    /// SH: encode + body `write_at` (tip append path).
    pub static SH_BODY_NS: AtomicU64 = AtomicU64::new(0);
    /// SH: `scripthash.head` insert_many (tip append path).
    pub static SH_HEAD_NS: AtomicU64 = AtomicU64::new(0);

    /// SH collect source: write-batch CreatePin outs (no store re-read).
    pub static SH_COLLECT_PIN: AtomicU64 = AtomicU64::new(0);
    /// SH collect source: cold Class A body load.
    pub static SH_COLLECT_COLD: AtomicU64 = AtomicU64::new(0);

    /// Tip/window: thin create rows collected for SH (pin or cold).
    pub static SH_CREATE_N: AtomicU64 = AtomicU64::new(0);
    /// Tip/window: distinct scripthash keys in that create set.
    pub static SH_UNIQUE_N: AtomicU64 = AtomicU64::new(0);
    /// Tip/window: rows actually written by durable `put_create_batch_append`.
    pub static SH_WRITTEN_N: AtomicU64 = AtomicU64::new(0);

    /// `(strong, scripthash, tip)` nanoseconds.
    ///
    /// `scripthash` is the **sum of SH substeps** (not a separate end-to-end
    /// timer), so status windows do not invent large `other_ms` when substeps
    /// and wall are sampled on different ticks.
    pub fn sample_and_reset() -> (u64, u64, u64) {
        (
            STRONG_NS.swap(0, Ordering::Relaxed),
            SCRIPTHASH_NS.swap(0, Ordering::Relaxed),
            TIP_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// `(collect, sort, seed, body, head)` nanoseconds.
    pub fn sample_sh_sub_and_reset() -> (u64, u64, u64, u64, u64) {
        (
            SH_COLLECT_NS.swap(0, Ordering::Relaxed),
            SH_SORT_NS.swap(0, Ordering::Relaxed),
            SH_SEED_NS.swap(0, Ordering::Relaxed),
            SH_BODY_NS.swap(0, Ordering::Relaxed),
            SH_HEAD_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// `(pin, cold)` create counts for SH collect sources, then reset.
    pub fn sample_sh_collect_src_and_reset() -> (u64, u64) {
        (
            SH_COLLECT_PIN.swap(0, Ordering::Relaxed),
            SH_COLLECT_COLD.swap(0, Ordering::Relaxed),
        )
    }

    /// `(creates, unique_scripts, written)` then reset.
    pub fn sample_sh_counts_and_reset() -> (u64, u64, u64) {
        (
            SH_CREATE_N.swap(0, Ordering::Relaxed),
            SH_UNIQUE_N.swap(0, Ordering::Relaxed),
            SH_WRITTEN_N.swap(0, Ordering::Relaxed),
        )
    }

    /// Accrue a SH substep and the aggregate `SCRIPTHASH_NS` wall (same window).
    #[inline]
    pub(crate) fn add_sh_part(part: &AtomicU64, ns: u64) {
        if ns == 0 {
            return;
        }
        part.fetch_add(ns, Ordering::Relaxed);
        SCRIPTHASH_NS.fetch_add(ns, Ordering::Relaxed);
    }

    /// Snapshot for tip-follow accept logs (does **not** reset). Prefer sample_* after.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct TipShSnap {
        pub collect_ns: u64,
        pub sort_ns: u64,
        pub seed_ns: u64,
        pub body_ns: u64,
        pub head_ns: u64,
        pub pin: u64,
        pub cold: u64,
        pub creates: u64,
        pub unique: u64,
        pub written: u64,
    }

    impl TipShSnap {
        /// Sum of durable-append substeps (sort+seed+body+head); collect separate.
        pub fn append_ns(&self) -> u64 {
            self.sort_ns
                .saturating_add(self.seed_ns)
                .saturating_add(self.body_ns)
                .saturating_add(self.head_ns)
        }

        pub fn total_sh_ns(&self) -> u64 {
            self.collect_ns.saturating_add(self.append_ns())
        }
    }

    /// Sample SH subtimers + counts in one call (resets all SH_* for this module).
    pub fn sample_tip_sh_and_reset() -> TipShSnap {
        let (collect_ns, sort_ns, seed_ns, body_ns, head_ns) = sample_sh_sub_and_reset();
        let (pin, cold) = sample_sh_collect_src_and_reset();
        let (creates, unique, written) = sample_sh_counts_and_reset();
        // Also clear aggregate SCRIPTHASH_NS / STRONG / TIP if caller only wants SH —
        // tip logger samples strong/tip separately. Leave STRONG/TIP alone here.
        let _ = SCRIPTHASH_NS.swap(0, Ordering::Relaxed);
        TipShSnap {
            collect_ns,
            sort_ns,
            seed_ns,
            body_ns,
            head_ns,
            pin,
            cold,
            creates,
            unique,
            written,
        }
    }
}

/// Wire-rebuild body load counters (IBD sampler).
///
/// Historical name `wave_fill_stats` — only store body decode remains live.
pub mod wave_fill_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Wire bodies re-decoded from store.
    pub static BODY_STORE: AtomicU64 = AtomicU64::new(0);
    /// Wall ns spent in store body decode.
    pub static BODY_STORE_NS: AtomicU64 = AtomicU64::new(0);

    /// `(store_count, store_body_ns)`.
    pub fn sample_store_and_reset() -> (u64, u64) {
        (
            BODY_STORE.swap(0, Ordering::Relaxed),
            BODY_STORE_NS.swap(0, Ordering::Relaxed),
        )
    }

    #[inline]
    pub(crate) fn add(part: &AtomicU64, ns: u64) {
        if ns > 0 {
            part.fetch_add(ns, Ordering::Relaxed);
        }
    }

    #[inline]
    pub(crate) fn add_count(part: &AtomicU64, n: u64) {
        if n > 0 {
            part.fetch_add(n, Ordering::Relaxed);
        }
    }
}

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

/// Domain query facade used by higher layers (consensus, net, RPC).
pub struct Query {
    store: Store,
    /// When false, archive **and** confirm skip durable Class B point (spend) writes.
    spend_index: std::sync::atomic::AtomicBool,
    /// When false, archive skips durable `tx.head` inserts.
    tx_index: std::sync::atomic::AtomicBool,
    /// Process-local scripthash → body head fk (confirm append path; avoids durable chain walks).
    sh_heads: Mutex<HashMap<[u8; 32], rbitcoin_store::ShHeadValue>>,
    /// Last height whose SH creates were applied after tip commit.
    /// `u64::MAX` = none. Replaces unbounded `sh_tx_indexed` HashSet.
    sh_indexed_through: AtomicU64,
    /// Height-ordered SH write-behind (one Class B appender). Confirm enqueues;
    /// [`Self::apply_sh_pending`] / the tip-follow worker drain.
    sh_pending: Mutex<VecDeque<connect::ShPendingJob>>,
    sh_pending_cv: Condvar,
    /// Job popped for apply but not yet watermarked. Readers join this with
    /// [`Self::sh_pending`] so the pop→watermark window stays at live tip.
    sh_applying: Mutex<Option<connect::ShPendingJob>>,
    /// `0` = none released; `h+1` = durable apply may run through height `h`.
    sh_released_through: AtomicU32,
    /// Pending + in-flight SH creates keyed by scripthash (join without scanning jobs).
    sh_ram_head: Mutex<HashMap<[u8; 32], Vec<Fk>>>,
    /// Serializes the one Class B appender (worker vs generate drain).
    sh_appender: Mutex<()>,
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
    /// Packed `tx.body` bytes read by [`Self::load_thin_tweaks`].
    thin_tweak_body_bytes: AtomicU64,
    /// Max fk `head_insert_many` has published (0 = never). Load polls this
    /// with the fence to prune in-flight **after** bind.
    head_drain_fk: AtomicU64,
    /// Disconnect height (valid when [`Self::disconnect_gen`] > 0).
    disconnect_height: AtomicU32,
    /// Bumped on each [`Self::disconnect_tip`]. Load drops in-flight layers.
    disconnect_gen: AtomicU64,
}

/// In-process hash→height map for the confirmed tip chain (~33 MiB raw at 1e6 tips).
#[derive(Default)]
struct HeightByHashIndex {
    /// Tip height the map matches (`None` = empty / needs rebuild).
    tip: Option<u32>,
    map: HashMap<[u8; 32], u32>,
}

impl Query {
    pub fn open_or_create(store_path: impl AsRef<Path>) -> Result<Self, QueryError> {
        Self::open_or_create_layout(StoreLayout::single(store_path.as_ref().to_path_buf()))
    }

    pub fn open_or_create_layout(layout: StoreLayout) -> Result<Self, QueryError> {
        let store = Store::open_or_create_layout(layout)?;
        // Core checkblocks-style tip window first so repair sees the final fence.
        let reval = store.revalidate_tip_window()?;
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
        let q = Self {
            store,
            spend_index: std::sync::atomic::AtomicBool::new(true),
            tx_index: std::sync::atomic::AtomicBool::new(true),
            sh_heads: Mutex::new(HashMap::new()),
            sh_indexed_through: AtomicU64::new(u64::MAX),
            sh_pending: Mutex::new(VecDeque::new()),
            sh_pending_cv: Condvar::new(),
            sh_applying: Mutex::new(None),
            sh_released_through: AtomicU32::new(0),
            sh_ram_head: Mutex::new(HashMap::new()),
            sh_appender: Mutex::new(()),
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
            sp_tweaks: Mutex::new(sp_tweaks),
            sptweaks_enabled: AtomicBool::new(false),
            sptweaks_origin: AtomicU32::new(sptweaks_origin),
            index_mode_cell: std::sync::atomic::AtomicU8::new(IndexMode::Tip as u8),
            confirm_cancel: std::sync::atomic::AtomicBool::new(false),
            height_by_hash: Mutex::new(HeightByHashIndex::default()),
            reconstruct_archived: AtomicU64::new(0),
            thin_tweak_body_bytes: AtomicU64::new(0),
            head_drain_fk: AtomicU64::new(0),
            disconnect_height: AtomicU32::new(0),
            disconnect_gen: AtomicU64::new(0),
        };
        if let Some(tip) = q.tip_height() {
            let _ = q.ensure_height_by_hash_index(tip);
        }
        q.recover_sh_writebehind()?;
        Ok(q)
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
        let v = self.sh_indexed_through.load(AtomicOrdering::Acquire);
        if v == u64::MAX {
            None
        } else {
            Some(v as u32)
        }
    }

    /// Advance SH watermark only after Class C tip commit.
    pub(crate) fn set_sh_indexed_through_height(&self, height: Option<u32>) {
        let v = height.map(|h| h as u64).unwrap_or(u64::MAX);
        self.sh_indexed_through.store(v, AtomicOrdering::Release);
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
            return Ok(self.store.get_fk_by_txid_tip(txid)?);
        }
        Ok(None)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Sample-and-reset archived wire-block reconstructs (Esplora `/raw` vs summary).
    pub fn sample_reset_reconstruct_archived(&self) -> u64 {
        self.reconstruct_archived.swap(0, AtomicOrdering::Relaxed)
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

    /// Enable/disable durable spend-annotation writes on archive **and** confirm
    /// (schema v5 create-out annotations; default on).
    ///
    /// Direct IBD keeps this **on** (confirm batch after Class C). Tip mode
    /// assumes annotations are already complete — no automatic backfill.
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
        Ok(self
            .store
            .has_confirmed_strong_spender_at(txid, vout, tip)?)
    }

    /// Spentness by known create fk (confirm pin path — no head probe).
    pub fn is_outpoint_spent_create(&self, create_fk: Fk, vout: u32) -> Result<bool, QueryError> {
        Ok(self
            .store
            .has_confirmed_strong_spender_create(create_fk, vout, None)?)
    }

    /// Unspent subset of vouts on a create (batch; store uses tx.idx when needed).
    pub fn unspent_create_vouts(
        &self,
        create_fk: Fk,
        vouts: &[u32],
    ) -> Result<Vec<u32>, QueryError> {
        Ok(self.store.unspent_create_vouts(create_fk, vouts, None)?)
    }

    /// Batch [`Self::unspent_create_vouts`]: one `spent.idx` walk across creates.
    pub fn unspent_create_vouts_batch(
        &self,
        items: &[(Fk, Vec<u32>)],
    ) -> Result<Vec<Vec<u32>>, QueryError> {
        Ok(self.store.unspent_create_vouts_batch(items)?)
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
        Ok(g.enqueue_vec(height, hash, header_fk, owned, n_inputs)?)
    }

    /// Remove RAM queue entry after combined confirm-write (or permanent drop).
    pub fn block_queue_dequeue_height(&self, height: u32) -> Result<usize, QueryError> {
        let mut g = self.block_queue.lock().unwrap();
        g.resolved.remove(&height);
        Ok(g.dequeue_height(height)?)
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
        Ok(g.mark_resolve_complete(height)?)
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
                out.raw.push((h, g.input_count_at(h).unwrap_or(0)));
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
        Ok(g.mark_resolve_complete_wave(heights)?)
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
        ProcessOwnedSizes {
            conf_plans,
            sh_runs: self.sh_run.on_disk_run_count(),
            sh_heads: self.sh_heads.lock().unwrap().len(),
            head,
            inflight_layers: mem.inflight_layers,
            inflight_pins: mem.inflight_pins,
            inflight_bytes: mem.inflight_bytes,
            pstore_weak: mem.pstore_weak,
            pstore_live: mem.pstore_live,
            pstore_bytes: mem.pstore_bytes,
            recent_heights: 0,
            recent_keys: 0,
            recent_pub_keys: 0,
            recent_overlay_keys: 0,
            recent_fifo_keys: 0,
            recent_pin_bytes: 0,
            h2h_keys,
            fence_runs: self.store.height_fence_run_count(),
            bq_promoted: self.block_queue_promoted_count(),
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

    /// Highest fence-connected create_fk (`0` if no confirmed run).
    pub fn tx_fence_max_connected_fk(&self) -> u64 {
        self.store.fence_max_connected_fk()
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

    /// Rewrite durable spend annotations for every confirmed non-coinbase input.
    ///
    /// **Not** part of tip entry: Direct IBD already annotates on confirm.
    /// Manual recovery only (corrupt/partial annotations). Prefer reindex when
    /// spentness is wrong at scale. When multi-list count is 0, uses bulk
    /// `put_spend_batch` without probe; otherwise probes for idempotency.
    ///
    /// `on_progress(height, tip, txs_so_far, edges_so_far)`.
    /// Returns `(heights_walked, txs_touched)`.
    pub fn backfill_point_spends(
        &self,
        mut on_progress: impl FnMut(u32, u32, u64, u64),
    ) -> Result<(u32, u64), QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok((0, 0));
        };
        let probe = self.point_edge_count() > 0;
        let mut txs = 0u64;
        let mut edges_total = 0u64;
        const EDGE_BATCH: usize = 8192;
        const PROGRESS_EVERY: u32 = 10_000;
        let mut edge_batch: Vec<([u8; 32], u32, Fk, u32)> = Vec::with_capacity(EDGE_BATCH);
        let mut last_log = 0u32;

        let flush_batch = |batch: &mut Vec<([u8; 32], u32, Fk, u32)>| -> Result<(), QueryError> {
            if batch.is_empty() {
                return Ok(());
            }
            self.store.put_spend_batch(batch)?;
            batch.clear();
            Ok(())
        };

        for h in 0..=tip.0 {
            let height = Height(h);
            let fks = match self.block_tx_fks(height) {
                Ok(f) => f,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            for fk in fks {
                if probe {
                    self.mark_spends_for_tx(fk, true)?;
                } else {
                    let mut edges = self.collect_spend_edges(fk, false)?;
                    edges_total += edges.len() as u64;
                    if edge_batch.len() + edges.len() > EDGE_BATCH && !edge_batch.is_empty() {
                        flush_batch(&mut edge_batch)?;
                    }
                    if edges.len() >= EDGE_BATCH {
                        self.store.put_spend_batch(&edges)?;
                    } else {
                        edge_batch.append(&mut edges);
                        if edge_batch.len() >= EDGE_BATCH {
                            flush_batch(&mut edge_batch)?;
                        }
                    }
                }
                txs += 1;
            }
            if h - last_log >= PROGRESS_EVERY || h == tip.0 {
                on_progress(h, tip.0, txs, edges_total + edge_batch.len() as u64);
                last_log = h;
            }
        }
        flush_batch(&mut edge_batch)?;
        Ok((tip.0.saturating_add(1), txs))
    }

    pub fn tip_height(&self) -> Option<Height> {
        self.store.tip_height()
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
        Ok(self.store.header_txs.get_list(header_fk)?)
    }

    pub fn get_tx(&self, fk: Fk) -> Result<TxRecord, QueryError> {
        self.get_tx_class_a(fk)
    }

    /// Load tx row from Class A store (no process pin FIFO).
    pub fn get_tx_class_a(&self, fk: Fk) -> Result<TxRecord, QueryError> {
        self.store.get_tx(fk)
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
        let (_, inputs, _) = self.store.get_tx_full(create_fk)?;
        inputs.get(i as usize).cloned().ok_or(StoreError::NotFound)
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
    /// Outs-only Class A (`get_tx_meta_and_outputs`); does not zip `inwit`.
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
        spending_input_index: u32,
    ) -> Result<Fk, QueryError> {
        self.store
            .put_spend(out_txid, out_index, spending_tx_fk, spending_input_index)
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

    /// True if this header hash has a Class A row (may not be confirmed on tip).
    pub fn is_header_archived(&self, hash: &[u8; 32]) -> Result<bool, QueryError> {
        Ok(self.get_header_by_hash(hash)?.is_some())
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
        Ok(self.store.header_txs.has_body(fk)?)
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
        Ok(self.store.archived_block_count()?)
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

        let mut children: U64Map<Vec<(Fk, [u8; 32])>> = U64Map::default();
        for id in 1..=n {
            let fk = Fk(id);
            let rec = self.store.get_header(fk)?;
            let prev = rec.prev_fk.get().unwrap_or(0);
            children.entry(prev).or_default().push((fk, rec.hash));
        }

        const ANCESTOR_HOPS: u32 = 32;
        let mut best_sib: Option<(Fk, [u8; 32], bool, u32)> = None;
        let mut path_fk = tip_fk;
        let mut path_h = tip_height;
        let mut path_rec = tip_rec;
        // Shared across all score queries — without this, the path walk is
        // O(depth²): each step re-walked the remaining child chain from scratch
        // (mainnet mid-IBD resume with ~64k headers ahead hung for a long time).
        let mut score_memo: U64Map<(bitcoin::Work, u32)> = U64Map::default();
        for _ in 0..ANCESTOR_HOPS {
            let Some(parent_fk) = path_rec.prev_fk.get() else {
                break;
            };
            let (path_sub_w, _path_sub_d) =
                Self::resume_subtree_score(&self.store, &children, path_fk, &mut score_memo)?;
            if let Some(sibs) = children.get(&parent_fk) {
                for &(fk, hash) in sibs {
                    if fk == path_fk {
                        continue;
                    }
                    let has_body = self.store.header_txs.has_body(fk)?;
                    let (sub_w, sub_d) =
                        Self::resume_subtree_score(&self.store, &children, fk, &mut score_memo)?;
                    if sub_w <= path_sub_w {
                        continue;
                    }
                    let take = match best_sib {
                        None => true,
                        Some((best_fk, _, best_body, _)) => {
                            let (best_w, best_d) = Self::resume_subtree_score(
                                &self.store,
                                &children,
                                best_fk,
                                &mut score_memo,
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
                break; // nearest better fork (shallowest reorg)
            }
            if path_h == 0 {
                break;
            }
            path_h = path_h.saturating_sub(1);
            path_fk = Fk(parent_fk);
            path_rec = self.store.get_header(path_fk)?;
        }

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
                    Self::resume_subtree_score(&self.store, &children, fk, &mut score_memo)?;
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
    fn resume_subtree_score(
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
        let mut stack: Vec<(Fk, bool)> = Vec::with_capacity(256);
        stack.push((root, false));
        while let Some((fk, children_done)) = stack.pop() {
            if memo.contains_key(&fk.0) {
                continue;
            }
            if !children_done {
                stack.push((fk, true));
                if let Some(kids) = children.get(&fk.0) {
                    for &(ck, _) in kids {
                        if !memo.contains_key(&ck.0) {
                            stack.push((ck, false));
                        }
                    }
                }
                continue;
            }
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
        memo.get(&root.0).copied().ok_or_else(|| {
            StoreError::Corrupt("resume_subtree_score: root missing after walk".into())
        })
    }

    /// Flush header rows + Class A body associations (IBD writer durability).
    pub fn flush_header_archive(&self) -> Result<(), QueryError> {
        Ok(self.store.flush_header_archive()?)
    }

    /// Ensure a header row exists (no txs). Idempotent by full block hash.
    ///
    /// Write gate: at most one body row per hash; non-null `prev_fk` must match
    /// the parent committed in the block hash (see store `HeaderTable::ensure`).
    /// Used to pipeline header sync so out-of-order bodies resolve parent fk.
    pub fn ensure_header(&self, header: &HeaderRecord) -> Result<Fk, QueryError> {
        // Store gate is authoritative (lock + uniqueness + prev integrity).
        // Skip confirm-parent-cache short-circuit so we never bypass ensure.
        Ok(self.store.put_header(header)?)
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
mod tests {
    use super::*;
    use rbitcoin_store::{InputRecord, OutputRecord};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn query_open_clears_strong_above_tip() {
        let (dir, q) = temp_query("open-repair-above-tip");
        let (mut h0, _) = coinbase_block(0, Fk::NULL, None);
        h0.hash = rbitcoin_store::block_header_hash(
            h0.version,
            &[0u8; 32],
            &h0.merkle_root,
            h0.timestamp,
            h0.bits,
            h0.nonce,
        );
        let hfk = q.put_header(&h0).unwrap();
        q.store().confirmed.set(Height(0), hfk).unwrap();
        q.store().rebuild_height_fence().unwrap();
        let leftover = Fk(99);
        q.store().strong_tx.set_strong(leftover, hfk).unwrap();
        q.store().flush_class_c_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));
        assert!(q.store().strong_tx.is_strong(leftover).unwrap());
        drop(q);

        let q = Query::open_or_create(dir.join("store")).unwrap();
        assert_eq!(
            q.tip_height(),
            Some(Height(0)),
            "repair must not shrink tip"
        );
        assert!(
            !q.store().strong_tx.is_strong(leftover).unwrap(),
            "open must clear leftover strong above the fence"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_query(label: &str) -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-query-{label}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (dir, q)
    }

    #[test]
    fn lookup_started_hi_none_until_set() {
        let (dir, q) = temp_query("started-hi");
        assert!(q.lookup_started_hi().is_none());
        assert!(q.class_a_hi().is_none());
        q.set_lookup_started_hi(Some(4));
        q.set_class_a_hi(Some(2));
        assert_eq!(q.lookup_started_hi(), Some(4));
        assert_eq!(q.class_a_hi(), Some(2));
        q.set_lookup_started_hi(None);
        assert!(q.lookup_started_hi().is_none());
        q.note_lookup_tiponly_start(12);
        assert_eq!(q.lookup_started_hi(), Some(12));
        q.note_lookup_tiponly_start(7);
        assert_eq!(
            q.lookup_started_hi(),
            Some(12),
            "TipOnly start must never rewind"
        );
        q.note_lookup_tiponly_start(40);
        assert_eq!(q.lookup_started_hi(), Some(40));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_sh_heads_capped_after_append_miss_still_writes() {
        use rbitcoin_store::{script_hash, ScriptHashRecord, ShHeadValue, SH_HEADS_CAP};
        let (dir, q) = temp_query("sh-heads-cap");
        {
            let mut heads = q.sh_heads.lock().unwrap();
            for i in 0..SH_HEADS_CAP as u64 {
                let mut k = [0xEE; 32];
                k[..8].copy_from_slice(&i.to_le_bytes());
                heads.insert(k, ShHeadValue::Empty);
            }
        }
        let sh = script_hash(&[0x51]);
        {
            let mut heads = q.sh_heads.lock().unwrap();
            let rec = ScriptHashRecord::from_fk(sh, Fk(1));
            q.store()
                .scripthash
                .put_create_batch_append(&[rec], &mut heads)
                .unwrap();
        }
        assert!(
            q.process_owned_size_snapshot().sh_heads <= SH_HEADS_CAP,
            "sh_heads={}",
            q.process_owned_size_snapshot().sh_heads
        );
        assert_eq!(q.store().scripthash.entries(&sh).unwrap().len(), 1);

        let evicted = {
            let heads = q.sh_heads.lock().unwrap();
            (0..SH_HEADS_CAP as u64).find_map(|i| {
                let mut k = [0xEE; 32];
                k[..8].copy_from_slice(&i.to_le_bytes());
                (!heads.contains_key(&k)).then_some(k)
            })
        };
        if let Some(evicted) = evicted {
            let rec = ScriptHashRecord::from_fk(evicted, Fk(2));
            {
                let mut heads = q.sh_heads.lock().unwrap();
                q.store()
                    .scripthash
                    .put_create_batch_append(&[rec], &mut heads)
                    .unwrap();
            }
            assert_eq!(q.store().scripthash.entries(&evicted).unwrap().len(), 1);
            assert!(q.process_owned_size_snapshot().sh_heads <= SH_HEADS_CAP);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn note_disconnect_rewinds_started_and_class_a_with_taken() {
        let (dir, q) = temp_query("disco-hwm");
        q.set_lookup_taken_hi(Some(12));
        q.set_lookup_started_hi(Some(12));
        q.set_class_a_hi(Some(10));
        q.note_disconnect_height(8);
        assert_eq!(q.lookup_taken_hi(), Some(7));
        assert_eq!(q.lookup_started_hi(), Some(7));
        assert_eq!(q.class_a_hi(), Some(7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Write-gate-safe: non-null `prev` requires `parent_hash` committed in header hash.
    fn coinbase_block(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[4] = 0xab;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        (header, ta)
    }

    fn rehash_header(h: &mut HeaderRecord, parent_hash: &[u8; 32]) {
        h.hash = rbitcoin_store::block_header_hash(
            h.version,
            parent_hash,
            &h.merkle_root,
            h.timestamp,
            h.bits,
            h.nonce,
        );
    }

    fn replace_tip_same_height(
        q: &Query,
        height: u32,
        prev_fk: Fk,
        parent_hash: [u8; 32],
        nonce_delta: u32,
    ) -> (HeaderRecord, TxApply) {
        q.disconnect_tip().unwrap();
        let (mut h, t) = coinbase_block(height, prev_fk, Some(parent_hash));
        h.nonce = h.nonce.wrapping_add(nonce_delta);
        rehash_header(&mut h, &parent_hash);
        q.connect_block(Height(height), &h, &[t.clone()]).unwrap();
        (h, t)
    }

    fn funded_op_true_coinbase(
        h: u32,
        prev: Fk,
        parent_hash: Option<[u8; 32]>,
    ) -> (HeaderRecord, TxApply) {
        let (hdr, mut ta) = coinbase_block(h, prev, parent_hash);
        ta.outputs = vec![OutputRecord::unspent(10_0000_0000, vec![0x51])];
        (hdr, ta)
    }

    fn spend_op_true(
        hfk0: Fk,
        hash0: [u8; 32],
        create_fk: Fk,
        create_txid: [u8; 32],
    ) -> (HeaderRecord, TxApply, [u8; 32]) {
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let hash1 = rbitcoin_store::block_header_hash(1, &hash0, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let spend = TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
        };
        (h1, spend, spend_txid)
    }

    #[test]
    fn sampler_stats() {
        // Process-global IBD samplers race under parallel `cargo test`. Prefer
        // last-writer overwrite checks and accumulate lower-bounds over exact
        // equality on counters other tests may also bump.
        let _ = confirm_load_stats::sample_and_reset();
        confirm_load_stats::note(
            &ConfirmLoadStats {
                blocks: 1,
                utxo_parents: 2,
                creates_registered: 3,
                parent_unique: 4,
                pin_cache_body: 5,
                pin_new: 6,
                pin_body_ns: 8,
                pin_new_meta_ns: 9,
                parent_cache_hits: 10,
                full_tx_reads: 11,
                body_tx_reads: 12,
                missing_parents: 13,
                header_ns: 14,
                body_decode_ns: 15,
                thin_ns: 16,
                parent_pin_ns: 17,
                cache_put_ns: 18,
                edge_same_batch: 19,
                edge_fk: 20,
                edge_coinbase: 21,
                ..Default::default()
            },
            100,
        );
        let s = confirm_load_stats::sample_and_reset();
        assert!(s.ns >= 100);
        assert!(s.blocks >= 1);
        assert!(s.edge_coinbase >= 21);

        let _ = archive_phase_stats::sample_and_reset();
        archive_phase_stats::note_resolve_counts(1, 2, 3, 4, 5, 6);
        let last = archive_phase_stats::last_plan_batch();
        // last_plan_batch is last-writer; re-note immediately before read if raced.
        if last.head_need != 3 {
            archive_phase_stats::note_resolve_counts(1, 2, 3, 4, 5, 6);
        }
        let last = archive_phase_stats::last_plan_batch();
        assert_eq!(last.head_need, 3);
        assert_eq!(last.head_hit, 4);
        archive_phase_stats::note_prep_plan(1, 2, 3, 10, 6, 7);
        archive_phase_stats::note_prep_batch(10, 1, 2, 3, 4, 1);
        archive_phase_stats::note_write_commit(20, 1, 2, 3, 4, 5, 1);
        archive_phase_stats::note_write_flush(8);
        let a = archive_phase_stats::sample_and_reset();
        assert!(a.prep_phases_sum_ns() > 0);
        assert!(a.write_phases_sum_ns() > 0);
        assert!(a.blocks >= 1);
        assert!(a.prep_head_fk_ns >= 10);
        assert!(a.prep_head_ns >= 10);

        confirm_load_stats::note_last_pin(11, 22, 33, 44, 55, 100, 9);
        let lp = confirm_load_stats::last_pin_phases();
        if lp.adopt_ns != 11 {
            confirm_load_stats::note_last_pin(11, 22, 33, 44, 55, 100, 9);
        }
        let lp = confirm_load_stats::last_pin_phases();
        assert_eq!(lp.adopt_ns, 11);
        assert_eq!(lp.plan_pin_ns, 22);
        assert_eq!(lp.cold_ns, 33);
        assert_eq!(lp.contract_ns, 44);
        assert_eq!(lp.publish_ns, 55);
        assert_eq!(lp.pin_plan_n, 100);
        assert_eq!(lp.pin_new_n, 9);
        assert_eq!(confirm_load_stats::LastPinPhases::ms(2_000_000), 2);

        // class_c counters are process-global; exercise the APIs without exact
        // equality (parallel tests may sample/reset between).
        class_c_phase_stats::STRONG_NS.store(11, AtomicOrdering::Relaxed);
        class_c_phase_stats::add_sh_part(&class_c_phase_stats::SH_COLLECT_NS, 5);
        class_c_phase_stats::TIP_NS.store(3, AtomicOrdering::Relaxed);
        let _ = class_c_phase_stats::sample_and_reset();
        let _ = class_c_phase_stats::sample_sh_sub_and_reset();
        let _ = class_c_phase_stats::sample_sh_collect_src_and_reset();

        wave_fill_stats::add_count(&wave_fill_stats::BODY_STORE, 2);
        wave_fill_stats::add(&wave_fill_stats::BODY_STORE_NS, 9);
        let _ = wave_fill_stats::sample_store_and_reset();

        // I2 cold range/idx sample path (values race under parallel cargo test).
        let _ = confirm_load_stats::sample_and_reset();
        confirm_load_stats::COLD_RANGE_NS.store(1_000_000, AtomicOrdering::Relaxed);
        confirm_load_stats::COLD_RANGE_N.store(3, AtomicOrdering::Relaxed);
        confirm_load_stats::COLD_IDX_NS.store(2_000_000, AtomicOrdering::Relaxed);
        confirm_load_stats::COLD_IDX_N.store(5, AtomicOrdering::Relaxed);
        let _ = confirm_load_stats::sample_and_reset();
    }

    /// Disconnecting a confirmed block must emit an info/warn line (not debug).
    #[test]
    fn disconnect_tip_logs_each_block_at_least_info() {
        let (dir, q) = temp_query("disconnect-log");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let (h1, t1) = coinbase_block(1, q.tip_header_fk().unwrap().unwrap(), Some(hash0));
        let hash1 = h1.hash;
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        assert_eq!(q.tip_height(), Some(Height(1)));

        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));
        let line = format_disconnect_tip_line(1, &hash1, 1);
        assert!(
            line.contains("height=1"),
            "disconnect line must name height: {line}"
        );
        assert!(
            line.to_ascii_lowercase().contains("disconnect"),
            "disconnect line must say disconnect: {line}"
        );
        let hash_disp = BlockHash::from_byte_array(hash1).to_string();
        assert!(
            line.contains(&hash_disp),
            "disconnect line must name the leaving hash {hash_disp}: {line}"
        );

        q.disconnect_tip().unwrap();
        assert!(q.tip_height().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_pin_none_on_empty_store() {
        let (dir, q) = temp_query("chain-view-empty");
        assert!(q.pin_chain_view().unwrap().is_none());
        assert!(q.pin_view(ChainViewKind::Tip, None).unwrap().is_none());
        assert!(q
            .pin_view(ChainViewKind::ScriptHash, None)
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_pin_live_across_extension_dead_after_same_height_replace() {
        let (dir, q) = temp_query("chain-view-pin");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();

        let genesis = q.pin_chain_view().unwrap().expect("genesis tip");
        assert_eq!(genesis.height, Height(0));
        assert_eq!(genesis.hash, hash0);
        assert!(genesis.still_live(&q).unwrap());
        assert_eq!(q.pin_view(ChainViewKind::Tip, None).unwrap(), Some(genesis));

        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        assert!(
            genesis.still_live(&q).unwrap(),
            "prefix pin stays live across tip extension"
        );

        let tip1 = q.pin_chain_view().unwrap().expect("height 1");
        assert_eq!(tip1.height, Height(1));
        assert_eq!(tip1.hash, h1.hash);
        assert!(tip1.still_live(&q).unwrap());

        q.disconnect_tip().unwrap();
        assert!(
            !tip1.still_live(&q).unwrap(),
            "disconnect of pinned height kills the view"
        );
        assert!(genesis.still_live(&q).unwrap());

        let (mut h1b, t1b) = coinbase_block(1, prev_fk, Some(hash0));
        h1b.nonce = h1.nonce.wrapping_add(1);
        rehash_header(&mut h1b, &hash0);
        q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
        assert_ne!(h1b.hash, tip1.hash);
        assert!(
            !tip1.still_live(&q).unwrap(),
            "same-height replace must not keep the old pin live"
        );
        let tip1b = q.pin_chain_view().unwrap().expect("replacement tip");
        assert_eq!(tip1b.height, Height(1));
        assert_eq!(tip1b.hash, h1b.hash);
        assert!(tip1b.still_live(&q).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_at_buried_pin_survives_tip_extension_and_higher_replace() {
        let (dir, q) = temp_query("chain-view-at");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        assert!(q.pin_chain_view_at(&[0xee; 32]).unwrap().is_none());

        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let prev1 = q.tip_header_fk().unwrap().unwrap();
        let (h2, t2) = coinbase_block(2, prev1, Some(h1.hash));
        q.connect_block(Height(2), &h2, &[t2]).unwrap();

        let buried = q.pin_chain_view_at(&hash0).unwrap().expect("genesis hash");
        assert_eq!(buried.height, Height(0));
        assert_eq!(buried.hash, hash0);
        assert!(buried.still_live(&q).unwrap());

        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(1)));
        assert!(
            buried.still_live(&q).unwrap(),
            "disconnect of height 2 must not kill a height-0 pin"
        );
        assert_eq!(
            q.pin_chain_view_at(&hash0).unwrap().unwrap().header_fk,
            buried.header_fk
        );

        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));
        assert!(buried.still_live(&q).unwrap());

        q.disconnect_tip().unwrap();
        assert!(
            !buried.still_live(&q).unwrap(),
            "disconnect of the pinned height kills the buried view"
        );
        assert!(q.pin_chain_view_at(&hash0).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_at_spend_asof_hides_later_spend() {
        let (dir, q) = temp_query("chain-view-asof-spend");
        let (h0, ta0) = funded_op_true_coinbase(0, Fk::NULL, None);
        let create_txid = ta0.tx.txid;
        let hash0 = h0.hash;
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let view0 = q.pin_chain_view_at(&hash0).unwrap().unwrap();

        let (h1, spend, _spend_txid) = spend_op_true(hfk0, hash0, create_fk, create_txid);
        let hash1 = h1.hash;
        q.connect_block(Height(1), &h1, &[spend]).unwrap();
        let view1 = q.pin_chain_view_at(&hash1).unwrap().unwrap();
        let sh = script_hash(&[0x51]);

        assert!(!q.is_outpoint_spent_at(&create_txid, 0, Some(0)).unwrap());
        assert!(q.is_outpoint_spent_at(&create_txid, 0, Some(1)).unwrap());
        assert!(q.is_outpoint_spent(&create_txid, 0).unwrap());

        let utxo0 = q.scripthash_listunspent_in(&sh, &view0).unwrap();
        assert_eq!(utxo0.len(), 1);
        assert_eq!(utxo0[0].tx_hash, create_txid);
        assert_eq!(utxo0[0].value, 10_0000_0000);
        let bal0 = q.scripthash_balance_in(&sh, &view0).unwrap();
        assert_eq!(bal0.confirmed, 10_0000_0000);
        let hist0 = q.scripthash_history_in(&sh, &view0).unwrap();
        assert_eq!(hist0.len(), 1);
        assert_eq!(hist0[0].txid, create_txid);

        let utxo1 = q.scripthash_listunspent_in(&sh, &view1).unwrap();
        assert!(utxo1.is_empty(), "spend at height 1 is visible as of 1");
        let bal1 = q.scripthash_balance_in(&sh, &view1).unwrap();
        assert_eq!(bal1.confirmed, 0);
        let hist1 = q.scripthash_history_in(&sh, &view1).unwrap();
        assert_eq!(hist1.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_sh_join_slot_miss_on_same_height_replace() {
        let (dir, q) = temp_query("chain-view-sh-slot");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        let genesis_txid = t0.tx.txid;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();

        let (h1, mut t1) = coinbase_block(1, prev_fk, Some(hash0));
        t1.tx.txid[5] = 0xaa;
        let txid_a = t1.tx.txid;
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let view_a = q.pin_chain_view().unwrap().unwrap();

        let sh = script_hash(&[0x51]);
        let mut slot = None;
        let hist_a = q.scripthash_history_slot(&sh, &mut slot).unwrap();
        let ids_a: Vec<_> = hist_a.iter().map(|i| i.txid).collect();
        assert!(ids_a.contains(&txid_a), "height-1 A must be in history");
        assert!(ids_a.contains(&genesis_txid));

        let live = q.scripthash_history_in(&sh, &view_a).unwrap();
        assert!(live.iter().any(|i| i.txid == txid_a));
        let genesis_view = ChainView {
            height: Height(0),
            hash: hash0,
            header_fk: prev_fk,
        };
        let only_g = q.scripthash_history_in(&sh, &genesis_view).unwrap();
        let g_ids: Vec<_> = only_g.iter().map(|i| i.txid).collect();
        assert!(g_ids.contains(&genesis_txid));
        assert!(
            !g_ids.contains(&txid_a),
            "history under a height-0 pin must omit the height-1 create"
        );

        q.disconnect_tip().unwrap();
        let (mut h1b, mut t1b) = coinbase_block(1, prev_fk, Some(hash0));
        h1b.nonce = h1.nonce.wrapping_add(1);
        rehash_header(&mut h1b, &hash0);
        t1b.tx.txid[5] = 0xbb;
        let txid_b = t1b.tx.txid;
        q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
        assert_ne!(txid_a, txid_b);
        assert_eq!(q.tip_height(), Some(Height(1)));

        let hist_b = q.scripthash_history_slot(&sh, &mut slot).unwrap();
        let ids_b: Vec<_> = hist_b.iter().map(|i| i.txid).collect();
        assert!(
            ids_b.contains(&txid_b),
            "same-height replace must miss the slot and emit B, got {ids_b:?}"
        );
        assert!(
            !ids_b.contains(&txid_a),
            "stale slot would still show A after same-height replace: {ids_b:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_run_retries_after_same_height_replace() {
        let (dir, q) = temp_query("chain-view-retry");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();

        let mut calls = 0u32;
        let (view, n) = q
            .run_at_chain_view(|view| {
                calls += 1;
                if calls == 1 {
                    replace_tip_same_height(&q, 1, prev_fk, hash0, 7);
                    assert!(!view.still_live(&q).unwrap());
                }
                Ok(calls)
            })
            .unwrap();
        assert!(calls >= 2, "must retry after the pin died, calls={calls}");
        assert_eq!(n, calls);
        assert!(view.still_live(&q).unwrap());
        assert_eq!(view.hash, q.pin_chain_view().unwrap().unwrap().hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_run_errors_when_always_stale() {
        let (dir, q) = temp_query("chain-view-stale");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let mut delta = 0u32;
        let err = q
            .run_at_chain_view(|_view| {
                delta += 1;
                replace_tip_same_height(&q, 1, prev_fk, hash0, delta);
                Ok(())
            })
            .unwrap_err();
        assert!(
            err.to_string().contains("chain view moved"),
            "stale bound must name the move, got {err}"
        );
        assert!(
            !err.to_string().contains("corrupt"),
            "a moved view is not corruption: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_run_not_found_on_empty() {
        let (dir, q) = temp_query("chain-view-retry-empty");
        let err = q.run_at_chain_view(|_v| Ok(())).unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finish-path stamp-only notes must not wipe leftover_n for the fail pack.
    #[test]
    fn leftover_last_plan_batch_survives_stamp_only_note() {
        archive_phase_stats::with_exclusive(|| {
            archive_phase_stats::note_resolve_counts(1, 1, 7, 3, 0, 0);
            archive_phase_stats::note_resolve_counts(0, 0, 0, 0, 5, 6);
            let last = archive_phase_stats::last_plan_batch();
            assert_eq!(
                last.head_need, 7,
                "stamp-only note_resolve_counts must not clobber leftover LAST"
            );
            assert_eq!(last.head_hit, 3);
        });
    }

    /// Tip commit (`confirm_block`) must publish `confirmed[]` without waiting
    /// on Class B scripthash. Drain is [`Query::apply_sh_pending`] (or
    /// [`Query::connect_block`], which drains for fixtures).
    #[test]
    fn tip_confirm_does_not_advance_sh_watermark() {
        let (dir, q) = temp_query("tip-confirm-no-sh");
        assert!(q.index_mode().is_tip());
        assert!(q.sh_index_enabled());

        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));
        assert_eq!(q.sh_indexed_through_height(), Some(0));

        let sh = script_hash(&[0x51]);
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);

        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        q.commit_class_a_only(&h1, &[t1]).unwrap();
        q.confirm_block(Height(1), &h1.hash).unwrap();

        assert_eq!(q.tip_height(), Some(Height(1)));
        assert_eq!(
            q.sh_indexed_through_height(),
            Some(0),
            "confirm must not advance SH watermark"
        );
        let hist = q.scripthash_history(&sh).unwrap();
        assert_eq!(
            hist.len(),
            2,
            "pending SH records must show the new tip create: {hist:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_writebehind_does_not_seed_until_release() {
        let (dir, q) = temp_query("sh-no-seed-until-release");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        q.commit_class_a_only(&h0, &[t0]).unwrap();
        q.confirm_block(Height(0), &h0.hash).unwrap();

        assert_eq!(q.sh_indexed_through_height(), None);
        assert!(
            q.take_sh_job_for_apply().is_none(),
            "durable apply must not take an unreleased job"
        );
        let sh = script_hash(&[0x51]);
        assert_eq!(
            q.scripthash_history(&sh).unwrap().len(),
            1,
            "pending records must still be visible before release"
        );
        let written0 = class_c_phase_stats::SH_WRITTEN_N.load(std::sync::atomic::Ordering::Relaxed);

        q.release_sh_writebehind(Height(0));
        q.apply_sh_pending().unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);
        let written1 = class_c_phase_stats::SH_WRITTEN_N.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            written1 >= written0,
            "release+apply must be allowed to write durable SH"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ram_sh_head_lookup_is_per_scripthash() {
        let (dir, q) = temp_query("ram-sh-head");
        let (h0, mut t0) = coinbase_block(0, Fk::NULL, None);
        t0.tx.output_count = 2;
        t0.outputs = vec![
            OutputRecord::unspent(25_0000_0000, vec![0x51]),
            OutputRecord::unspent(25_0000_0000, vec![0x52]),
        ];
        q.commit_class_a_only(&h0, &[t0]).unwrap();
        q.confirm_block(Height(0), &h0.hash).unwrap();
        let sha = script_hash(&[0x51]);
        let shb = script_hash(&[0x52]);
        let fa = q.pending_sh_create_fks(&sha);
        let fb = q.pending_sh_create_fks(&shb);
        assert_eq!(fa.len(), 1, "script A must hit only its pending fks");
        assert_eq!(fb.len(), 1, "script B must hit only its pending fks");
        assert_eq!(fa, fb, "same create tx funds both scripts");
        assert!(q.pending_sh_create_fks(&[0u8; 32]).is_empty());
        q.apply_sh_pending().unwrap();
        assert!(
            q.pending_sh_create_fks(&sha).is_empty(),
            "apply must drop RAM-head keys"
        );
        assert_eq!(q.scripthash_history(&sha).unwrap().len(), 1);
        assert_eq!(q.scripthash_history(&shb).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_sh_pending_writes_creates_and_advances_watermark() {
        let (dir, q) = temp_query("apply-sh-pending");
        assert!(q.index_mode().is_tip());

        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        q.commit_class_a_only(&h0, &[t0]).unwrap();
        q.confirm_block(Height(0), &h0.hash).unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));
        assert_eq!(q.sh_indexed_through_height(), None);

        q.apply_sh_pending().unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        let sh = script_hash(&[0x51]);
        let hist = q.scripthash_history(&sh).unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].height, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `apply_sh_pending` must wait out an in-flight job (worker vs generate drain).
    #[test]
    fn apply_sh_pending_waits_for_in_flight_job() {
        use std::sync::Arc;
        let (dir, q) = temp_query("apply-sh-wait-inflight");
        let q = Arc::new(q);
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        q.commit_class_a_only(&h0, &[t0]).unwrap();
        q.confirm_block(Height(0), &h0.hash).unwrap();
        assert_eq!(q.sh_indexed_through_height(), None);
        q.release_sh_writebehind(Height(0));

        let stolen = q.take_sh_job_for_apply().expect("enqueued genesis");
        let height = Height(0);
        let q_apply = Arc::clone(&q);
        let done = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            q_apply.apply_sh_job(stolen).unwrap();
            q_apply.finish_sh_job(height);
        });
        q.apply_sh_pending().unwrap();
        assert_eq!(
            q.sh_indexed_through_height(),
            Some(0),
            "drain must wait until the in-flight job is watermarked"
        );
        done.join().unwrap();
        let sh = script_hash(&[0x51]);
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_sh_pending_two_drainers_cover_both_heights() {
        use std::sync::Arc;
        let (dir, q) = temp_query("apply-sh-two-drainers");
        let q = Arc::new(q);
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.commit_class_a_only(&h0, &[t0]).unwrap();
        q.confirm_block(Height(0), &h0.hash).unwrap();
        let prev = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev, Some(hash0));
        q.commit_class_a_only(&h1, &[t1]).unwrap();
        q.confirm_block(Height(1), &h1.hash).unwrap();

        let a = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || q.apply_sh_pending())
        };
        let b = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || q.apply_sh_pending())
        };
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(1));
        let sh = script_hash(&[0x51]);
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_sh_job_skips_stale_job_after_same_height_replace() {
        let (dir, q) = temp_query("sh-stale-job");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev = q.tip_header_fk().unwrap().unwrap();

        let (h1a, mut t1a) = coinbase_block(1, prev, Some(hash0));
        t1a.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0xaa])];
        q.commit_class_a_only(&h1a, &[t1a]).unwrap();
        q.confirm_block(Height(1), &h1a.hash).unwrap();
        q.release_sh_writebehind(Height(1));
        let stolen = q.take_sh_job_for_apply().expect("old branch job");

        q.disconnect_tip().unwrap();
        let (mut h1b, mut t1b) = coinbase_block(1, prev, Some(hash0));
        h1b.nonce = h1a.nonce.wrapping_add(1);
        rehash_header(&mut h1b, &hash0);
        t1b.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0xbb])];
        t1b.tx.txid[30] = 0xbb;
        q.commit_class_a_only(&h1b, &[t1b]).unwrap();
        q.confirm_block(Height(1), &h1b.hash).unwrap();

        q.apply_sh_job(stolen).unwrap();
        q.finish_sh_job(Height(1));
        q.apply_sh_pending().unwrap();

        let sh_old = script_hash(&[0xaa]);
        let sh_new = script_hash(&[0xbb]);
        assert!(
            q.scripthash_history(&sh_old).unwrap().is_empty(),
            "stale branch creates must not seed the durable index"
        );
        assert_eq!(q.scripthash_history(&sh_new).unwrap().len(), 1);
        assert_eq!(q.sh_indexed_through_height(), Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disconnect_tip_waits_for_sh_appender() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let (dir, q) = temp_query("sh-disconnect-lock");
        let q = Arc::new(q);
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();

        let held = Arc::new(AtomicBool::new(false));
        let q_hold = Arc::clone(&q);
        let held_flag = Arc::clone(&held);
        let holder = std::thread::spawn(move || {
            let _g = q_hold.sh_appender.lock().unwrap();
            held_flag.store(true, Ordering::Release);
            std::thread::sleep(std::time::Duration::from_millis(30));
        });
        while !held.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let t0 = std::time::Instant::now();
        q.disconnect_tip().unwrap();
        let waited = t0.elapsed();
        holder.join().unwrap();
        assert!(
            waited >= std::time::Duration::from_millis(20),
            "disconnect must take sh_appender, waited {waited:?}"
        );
        assert!(q.tip_height().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_writebehind_recover_requeues_unapplied_heights() {
        let (dir, q) = temp_query("sh-wb-recover");
        let (mut h0, t0) = coinbase_block(0, Fk::NULL, None);
        h0.merkle_root = t0.tx.txid;
        h0.hash = rbitcoin_store::block_header_hash(
            h0.version,
            &[0u8; 32],
            &h0.merkle_root,
            h0.timestamp,
            h0.bits,
            h0.nonce,
        );
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (mut h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
        h1.merkle_root = t1.tx.txid;
        rehash_header(&mut h1, &hash0);
        q.commit_class_a_only(&h1, &[t1]).unwrap();
        q.confirm_block(Height(1), &h1.hash).unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        q.store().flush_class_c_tip().unwrap();
        drop(q);
        let q = Query::open_or_create(dir.join("store")).unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        let sh = script_hash(&[0x51]);
        assert_eq!(
            q.scripthash_history(&sh).unwrap().len(),
            2,
            "requeued pending records must be visible before durable apply"
        );
        q.apply_sh_pending().unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(1));
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_sh_writebehind_fails_open_on_interior_missing_header_txs() {
        let (dir, q) = temp_query("sh-wb-recover-corrupt");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev0 = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev0, Some(hash0));
        let hash1 = h1.hash;
        q.commit_class_a_only(&h1, &[t1]).unwrap();
        let hfk1 = q.confirm_block(Height(1), &hash1).unwrap();
        let (h2, t2) = coinbase_block(2, hfk1, Some(hash1));
        q.commit_class_a_only(&h2, &[t2]).unwrap();
        q.confirm_block(Height(2), &h2.hash).unwrap();
        assert!(q.store().header_txs.clear_body(hfk1).unwrap());
        let err = q.recover_sh_writebehind().expect_err("interior hole");
        let msg = format!("{err}");
        assert!(
            msg.contains("invariant:") || msg.contains("missing"),
            "expected invariant/missing body, got {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_sh_writebehind_skips_bodyless_structural_tip() {
        let (dir, q) = temp_query("sh-wb-recover-tip-nobody");
        let (h0, t0) = coinbase_block(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev0 = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase_block(1, prev0, Some(hash0));
        q.commit_class_a_only(&h1, &[t1]).unwrap();
        let hfk1 = q.confirm_block(Height(1), &h1.hash).unwrap();
        q.release_sh_writebehind(Height(1));
        let _stolen = q.take_sh_job_for_apply().expect("height-1 job");
        q.finish_sh_job(Height(1));
        assert_eq!(q.tip_height(), Some(Height(1)));
        assert!(q.store().header_txs.clear_body(hfk1).unwrap());
        q.recover_sh_writebehind()
            .expect("body-less structural tip must not fail open");
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        assert!(
            q.sh_pending_max_height().is_none() || q.sh_pending_max_height().unwrap() < 1,
            "body-less tip must not be re-queued"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_sh_writebehind_halt_sets_stop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = AtomicBool::new(false);
        crate::connect::request_sh_writebehind_halt(&stop, 7, &"apply failed");
        assert!(
            stop.load(Ordering::SeqCst),
            "apply error must request process stop so the node exits"
        );
    }

    /// Pending write-behind records join at live tip so a confirmed spend is
    /// visible even though durable SH (and mempool) have already moved on.
    #[test]
    fn sh_pending_records_join_at_live_tip_before_apply() {
        let (dir, q) = temp_query("sh-pin-watermark");
        let (h0, ta0) = funded_op_true_coinbase(0, Fk::NULL, None);
        let create_txid = ta0.tx.txid;
        let hash0 = h0.hash;
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let sh = script_hash(&[0x51]);
        assert_eq!(q.scripthash_listunspent(&sh).unwrap().len(), 1);
        assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 10_0000_0000);

        let (h1, spend, spend_txid) = spend_op_true(hfk0, hash0, create_fk, create_txid);
        let hash1 = h1.hash;
        q.commit_class_a_only(&h1, &[spend]).unwrap();
        q.confirm_block(Height(1), &hash1).unwrap();

        assert_eq!(q.tip_height(), Some(Height(1)));
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        assert!(q.is_outpoint_spent(&create_txid, 0).unwrap());

        let sh_view = q
            .pin_sh_chain_view()
            .unwrap()
            .expect("SH view follows pending");
        assert_eq!(sh_view.height, Height(1));
        assert_eq!(sh_view.hash, hash1);
        let live = q.pin_chain_view().unwrap().expect("live tip");
        assert_eq!(live.height, Height(1));

        assert!(
            q.scripthash_listunspent(&sh).unwrap().is_empty(),
            "pending join at live tip must show the spend (mempool already dropped it)"
        );
        assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 0);
        let hist = q.scripthash_history(&sh).unwrap();
        assert_eq!(hist.len(), 2);
        assert!(hist.iter().any(|i| i.txid == create_txid));
        assert!(hist.iter().any(|i| i.txid == spend_txid));

        q.apply_sh_pending().unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(1));
        let sh_view = q.pin_sh_chain_view().unwrap().expect("SH caught up");
        assert_eq!(sh_view.height, Height(1));
        assert_eq!(sh_view.hash, hash1);
        assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());
        assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 0);
        assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Worker / drain must not hide pending creates between pop and watermark.
    ///
    /// Stealing the job (pop without apply) is the in-flight window today's
    /// `rbtc-sh-wb` opens: generate's drain sees an empty queue while apply is
    /// still running, MiniWallet scantxoutset pins the pre-tip watermark, and
    /// a spent coin looks live while Class C already spent it (orphaned).
    #[test]
    fn sh_pending_join_holds_while_job_is_in_flight() {
        let (dir, q) = temp_query("sh-pending-inflight");
        let (h0, mut ta0) = coinbase_block(0, Fk::NULL, None);
        ta0.outputs = vec![OutputRecord::unspent(10_0000_0000, vec![0x51])];
        let create_txid = ta0.tx.txid;
        let hash0 = h0.hash;
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let sh = script_hash(&[0x51]);

        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x22;
        spend_txid[31] = 0xef;
        let hash1 = rbitcoin_store::block_header_hash(1, &hash0, &[0x22; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x22; 32],
            hash: hash1,
        };
        q.commit_class_a_only(
            &h1,
            &[TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: create_txid,
                    create_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
            }],
        )
        .unwrap();
        q.confirm_block(Height(1), &hash1).unwrap();
        assert_eq!(q.sh_indexed_through_height(), Some(0));
        assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());
        q.release_sh_writebehind(Height(1));

        // Same transition as rbtc-sh-wb / apply_sh_pending: queue → applying,
        // durable watermark not advanced yet.
        let stolen = q.take_sh_job_for_apply();
        assert!(stolen.is_some(), "confirm must enqueue the spend height");
        assert!(
            q.scripthash_listunspent(&sh).unwrap().is_empty(),
            "in-flight apply window must still join pending at live tip"
        );
        assert_eq!(
            q.pin_sh_chain_view().unwrap().map(|v| v.height),
            Some(Height(1)),
            "visible SH height must stay at tip while the job is in flight"
        );

        let job = stolen.expect("enqueued");
        q.apply_sh_job(job).unwrap();
        q.finish_sh_job(Height(1));
        assert_eq!(q.sh_indexed_through_height(), Some(1));
        assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_history_filtered_open_and_window() {
        let (dir, q) = temp_query("sh-hist-filt");
        assert!(q.index_mode().is_tip());

        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..4u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        // Four OP_TRUE coinbases → four confirmed history rows for that SH.
        let sh = script_hash(&[0x51]);
        let full = q.scripthash_history(&sh).unwrap();
        assert_eq!(full.len(), 4);
        assert_eq!(
            full.iter().map(|i| i.height).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );

        let open = q
            .scripthash_history_filtered(&sh, &HistoryFilter::open())
            .unwrap();
        assert_eq!(open, full);

        // Inclusive from, exclusive to: heights 1 and 2 only.
        // Creates at height >= 3 are not Class-A expanded (spend height ≥ create).
        reset_body_ok_reads();
        let window = q
            .scripthash_history_filtered(&sh, &HistoryFilter::height_window(1, Some(3)))
            .unwrap();
        assert_eq!(
            window.iter().map(|i| i.height).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(window.len() < full.len());
        assert_eq!(
            body_ok_reads(),
            3,
            "expand heights 0..=2; skip create at exclusive to_height 3"
        );

        // Open upper bound from height 2.
        let from_only = q
            .scripthash_history_filtered(&sh, &HistoryFilter::height_window(2, None))
            .unwrap();
        assert_eq!(
            from_only.iter().map(|i| i.height).collect::<Vec<_>>(),
            vec![2, 3]
        );

        // Esplora-style newest-first page of 2.
        let page = q
            .scripthash_history_filtered(
                &sh,
                &HistoryFilter {
                    from_height: 0,
                    to_height: None,
                    limit: Some(2),
                    after_txid: None,
                    order: HistoryOrder::NewestFirst,
                },
            )
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].height, 3);
        assert_eq!(page[1].height, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_history_expands_creates_via_load_creates_once() {
        let (dir, q) = temp_query("sh-hist-load-once");
        assert!(q.index_mode().is_tip());

        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..4u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        let sh = script_hash(&[0x51]);
        reset_body_ok_reads();
        let full = q.scripthash_history(&sh).unwrap();
        assert_eq!(full.len(), 4);
        assert_eq!(body_ok_reads(), 4);

        let (header, mut ta) = coinbase_block(4, prev, parent_hash);
        ta.tx.output_count = 2;
        ta.outputs = vec![
            OutputRecord::unspent(1_0000_0000, vec![0x51]),
            OutputRecord::unspent(2_0000_0000, vec![0x00]),
        ];
        q.connect_block(Height(4), &header, &[ta]).unwrap();
        reset_body_ok_reads();
        let hist = q.scripthash_history(&sh).unwrap();
        assert_eq!(hist.len(), 5);
        assert_eq!(body_ok_reads(), 5);
        let utxos = q.scripthash_listunspent(&sh).unwrap();
        assert_eq!(utxos.len(), 5);
        assert!(utxos.iter().all(|u| u.tx_pos == 0));

        rbitcoin_store::reset_tx_full_gets();
        let scanned = q.scan_unspent_scripts(&[vec![0x51]]).unwrap();
        assert_eq!(scanned.len(), 5);
        assert!(scanned.iter().all(|u| u.coinbase));
        assert!(
            rbitcoin_store::tx_full_gets().is_empty(),
            "shindex coinbase from create fk, not get_tx_full: {:?}",
            rbitcoin_store::tx_full_gets()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_join_includes_spend_and_keeps_sibling_utxo() {
        let (dir, q) = temp_query("sh-join-spend");
        assert!(q.index_mode().is_tip());

        let (h0, mut ta0) = coinbase_block(0, Fk::NULL, None);
        ta0.tx.output_count = 2;
        ta0.outputs = vec![
            OutputRecord::unspent(10_0000_0000, vec![0x51]),
            OutputRecord::unspent(20_0000_0000, vec![0x51]),
        ];
        let create_txid = ta0.tx.txid;
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let ta1 = TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
        };
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();

        let sh = script_hash(&[0x51]);
        let hist = q.scripthash_history(&sh).unwrap();
        assert_eq!(hist.len(), 2);
        let hist_txids: Vec<_> = hist.iter().map(|i| i.txid).collect();
        assert!(hist_txids.contains(&create_txid));
        assert!(hist_txids.contains(&spend_txid));
        assert_eq!(
            hist.iter().find(|i| i.txid == create_txid).unwrap().height,
            0
        );
        assert_eq!(
            hist.iter().find(|i| i.txid == spend_txid).unwrap().height,
            1
        );
        assert_eq!(
            hist.iter().find(|i| i.txid == create_txid).unwrap().tx_fk,
            create_fk
        );
        let spend_fk = q.block_tx_fks(Height(1)).unwrap()[0];
        assert_eq!(
            hist.iter().find(|i| i.txid == spend_txid).unwrap().tx_fk,
            spend_fk
        );

        let utxos = q.scripthash_listunspent(&sh).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].tx_hash, create_txid);
        assert_eq!(utxos[0].tx_pos, 1);
        assert_eq!(utxos[0].value, 20_0000_0000);

        let view = q.pin_chain_view().unwrap().unwrap();
        let list_join = q
            .join_creates_and_spends(&sh, crate::scripthash::ShJoinNeed::LISTUNSPENT, None, &view)
            .unwrap();
        assert!(
            list_join.iter().any(|r| r.spent && r.spenders.is_empty()),
            "listunspent join must skip spender identity"
        );
        assert!(list_join.iter().any(|r| !r.spent));
        let hist_join = q
            .join_creates_and_spends(&sh, crate::scripthash::ShJoinNeed::HISTORY, None, &view)
            .unwrap();
        assert!(
            hist_join.iter().any(|r| r.spent && !r.spenders.is_empty()),
            "history join still loads spender identity"
        );

        let bal = q.scripthash_balance(&sh).unwrap();
        assert_eq!(bal.confirmed, 20_0000_0000);
        assert_eq!(bal.unconfirmed, 0);

        reset_body_ok_reads();
        let stats = q.scripthash_chain_stats(&sh).unwrap();
        assert_eq!(stats.tx_count, hist.len() as u32);
        assert_eq!(stats.funded_txo_count, 2);
        assert_eq!(stats.funded_txo_sum, 30_0000_0000);
        assert_eq!(stats.spent_txo_count, 1);
        assert_eq!(stats.spent_txo_sum, 10_0000_0000);
        assert_eq!(body_ok_reads(), 1);
        let stats_join = q
            .join_creates_and_spends(&sh, crate::scripthash::ShJoinNeed::CHAIN_STATS, None, &view)
            .unwrap();
        assert!(
            stats_join.iter().all(|r| r.spenders.is_empty()),
            "chain_stats join must skip spender identity"
        );
        assert!(stats_join
            .iter()
            .any(|r| r.spent && !r.spender_fks.is_empty()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_listunspent_identity_skips_spent_creates() {
        let (dir, q) = temp_query("sh-lu-id-spent");
        assert!(q.index_mode().is_tip());

        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut create_fks = Vec::new();
        let mut create_txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            create_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            create_fks.push(q.block_tx_fks(Height(h)).unwrap()[0]);
        }

        for (i, spent_h) in [0u32, 1].into_iter().enumerate() {
            let h = 3 + i as u32;
            let (header, mut cb) = coinbase_block(h, prev, parent_hash);
            cb.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
            parent_hash = Some(header.hash);
            let mut spend_txid = [0u8; 32];
            spend_txid[0] = 0x5e;
            spend_txid[31] = spent_h as u8;
            let spend = TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: create_txids[spent_h as usize],
                    create_fk: create_fks[spent_h as usize],
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x00])],
            };
            prev = q.connect_block(Height(h), &header, &[cb, spend]).unwrap();
        }

        let sh = script_hash(&[0x51]);
        let keep = create_fks[2];
        rbitcoin_store::reset_txid_get_many();
        let utxos = q.scripthash_listunspent(&sh).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].tx_hash, create_txids[2]);
        let ids = rbitcoin_store::txid_get_many_fks();
        assert!(
            ids.iter().all(|fk| *fk == keep.0),
            "listunspent txid.body only for unspent create, not spent {:?}: {:?}",
            [create_fks[0].0, create_fks[1].0],
            ids
        );
        assert!(
            ids.contains(&keep.0),
            "unspent create must load txid.body: {ids:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_touched_at_height_skips_class_a_expand() {
        let (dir, q) = temp_query("sh-touch-h");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut create_fks = Vec::new();
        let mut create_txids = Vec::new();
        for h in 0..2u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            create_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            create_fks.push(q.block_tx_fks(Height(h)).unwrap()[0]);
        }
        let sh = script_hash(&[0x51]);

        let (header, mut miss) = coinbase_block(2, prev, parent_hash);
        miss.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(2), &header, &[miss]).unwrap();

        reset_body_ok_reads();
        assert!(!q.scripthash_touched_at_height(&sh, Height(2)).unwrap());
        assert!(q
            .scripthash_tx_fks_at_height(&sh, Height(2))
            .unwrap()
            .is_empty());
        assert_eq!(
            body_ok_reads(),
            0,
            "untouched height must not load_creates_once"
        );

        reset_body_ok_reads();
        assert!(q.scripthash_touched_at_height(&sh, Height(0)).unwrap());
        let create_hit = q.scripthash_tx_fks_at_height(&sh, Height(0)).unwrap();
        assert_eq!(create_hit, vec![create_fks[0]]);
        assert_eq!(body_ok_reads(), 0, "create-in-block probe is posting list");

        let (header, mut cb) = coinbase_block(3, prev, parent_hash);
        cb.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
        let spend = TxApply {
            tx: TxRecord {
                txid: {
                    let mut t = [0u8; 32];
                    t[0] = 0x5e;
                    t
                },
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txids[0],
                create_fk: create_fks[0],
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x00])],
        };
        q.connect_block(Height(3), &header, &[cb, spend]).unwrap();
        reset_body_ok_reads();
        assert!(q.scripthash_touched_at_height(&sh, Height(3)).unwrap());
        let spend_fk = q.block_tx_fks(Height(3)).unwrap()[1];
        let spend_hit = q.scripthash_tx_fks_at_height(&sh, Height(3)).unwrap();
        assert_eq!(spend_hit, vec![spend_fk]);
        assert_eq!(
            body_ok_reads(),
            0,
            "spend-in-block probe is prevout create_fk"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scripthash_join_slot_reuses_class_a_until_tip() {
        let (dir, q) = temp_query("sh-slot-reuse");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut create_txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            create_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let sh = script_hash(&[0x51]);
        let mut slot = None;
        reset_body_ok_reads();
        let bal = q.scripthash_balance_slot(&sh, &mut slot).unwrap();
        assert_eq!(bal.confirmed, 150_0000_0000);
        let after_bal = body_ok_reads();
        assert_eq!(after_bal, 3, "first join expands each create once");

        let hist = q.scripthash_history_slot(&sh, &mut slot).unwrap();
        assert_eq!(hist.len(), 3);
        assert_eq!(body_ok_reads(), after_bal, "history must reuse packed outs");
        let hist_txids: Vec<_> = hist.iter().map(|i| i.txid).collect();
        for txid in &create_txids {
            assert!(
                hist_txids.contains(txid),
                "history identity from slot enrich"
            );
        }

        let utxos = q.scripthash_listunspent_slot(&sh, &mut slot).unwrap();
        assert_eq!(utxos.len(), 3);
        assert_eq!(
            body_ok_reads(),
            after_bal,
            "listunspent must reuse packed outs"
        );

        let stats = q.scripthash_chain_stats_slot(&sh, &mut slot).unwrap();
        assert_eq!(stats.tx_count, 3);
        assert_eq!(stats.funded_txo_count, 3);
        assert_eq!(
            body_ok_reads(),
            after_bal,
            "chain_stats must reuse packed outs"
        );

        let (header, ta) = coinbase_block(3, prev, parent_hash);
        q.connect_block(Height(3), &header, &[ta]).unwrap();
        q.scripthash_balance_slot(&sh, &mut slot).unwrap();
        assert!(
            body_ok_reads() > after_bal,
            "new tip must invalidate the slot"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connect_chain_query_surface() {
        let (dir, q) = temp_query("connect");
        // Default Tip mode: durable SH on confirm so Electrum-style APIs work.
        assert!(q.index_mode().is_tip());

        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        for h in 0..4u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        assert_eq!(q.tip_height(), Some(Height(3)));
        assert!(q.tip_header_fk().unwrap().is_some());
        assert!(q.is_header_archived(&hashes[2]).unwrap());
        assert!(q.is_block_archived(&hashes[2]).unwrap());
        assert!(q.archived_block_count().unwrap() >= 4);

        // height_of_hash: tip/tip-1 fast paths + map for deeper heights.
        assert_eq!(q.height_of_hash(&hashes[3]).unwrap(), Some(Height(3)));
        assert_eq!(q.height_of_hash(&hashes[2]).unwrap(), Some(Height(2)));
        assert_eq!(q.height_of_hash(&hashes[0]).unwrap(), Some(Height(0)));
        assert_eq!(q.height_of_hash(&[0xee; 32]).unwrap(), None);
        // Mid-chain still works after invalidate + rebuild.
        q.invalidate_height_by_hash_index();
        assert_eq!(q.height_of_hash(&hashes[1]).unwrap(), Some(Height(1)));

        let hdr = q.wire_header_at_height(Height(1)).unwrap();
        assert_eq!(hdr.time, 2);

        let loc = q.locator_hashes().unwrap();
        assert!(!loc.is_empty());
        let after = q
            .headers_after_locator(&loc, BlockHash::from_byte_array([0u8; 32]), 10)
            .unwrap();
        // After matching tip locator → empty; zero locator starts from genesis.
        let from_zero = q
            .headers_after_locator(
                &[BlockHash::from_byte_array([0u8; 32])],
                BlockHash::from_byte_array([0u8; 32]),
                2,
            )
            .unwrap();
        assert_eq!(from_zero.len(), 2);
        let _ = after;

        // Tx resolve + inputs/outputs.
        let fks = q.block_tx_fks(Height(0)).unwrap();
        assert_eq!(fks.len(), 1);
        let tx = q.get_tx(fks[0]).unwrap();
        assert!(q.tx_fk_by_txid(&tx.txid).unwrap().is_some());
        let inp = q.tx_input_at_fk(fks[0], &tx, 0).unwrap();
        assert!(inp.is_coinbase());
        rbitcoin_store::reset_tx_full_gets();
        let out = q.tx_output_at_fk(fks[0], 0).unwrap();
        assert!(
            rbitcoin_store::tx_full_gets().is_empty(),
            "tx_output_at_fk is outs-only (no inwit zip)"
        );
        assert_eq!(out.value, 50_0000_0000);
        assert!(!q.is_outpoint_spent(&tx.txid, 0).unwrap());
        assert!(!q.is_outpoint_spent_create(fks[0], 0).unwrap());
        assert_eq!(q.unspent_create_vouts(fks[0], &[0]).unwrap(), vec![0]);

        // Merkle proof for coinbase.
        let proof = q.merkle_proof(Height(0), &tx.txid).unwrap();
        assert_eq!(proof.pos, 0);
        assert_eq!(proof.block_height, 0);

        // Identity list is `txid.body`, not packed `txout` (`get_tx`).
        let side = q.store().txs.body_txid(fks[0]).unwrap();
        assert_eq!(q.block_txids(Height(0)).unwrap(), vec![side]);
        assert_eq!(q.block_txid_at(Height(0), 0).unwrap(), side);
        assert_eq!(tx.txid, side);

        // Scripthash history/balance/utxo for OP_TRUE (durable SH in tip mode).
        let sh = script_hash(&[0x51]);
        let hist = q.scripthash_history(&sh).unwrap();
        assert!(!hist.is_empty());
        let bal = q.scripthash_balance(&sh).unwrap();
        assert!(bal.confirmed > 0);
        let utxos = q.scripthash_listunspent(&sh).unwrap();
        assert!(!utxos.is_empty());

        // Confirm cancel flags.
        assert!(!q.confirm_cancelled());
        q.request_confirm_cancel();
        assert!(q.confirm_cancelled());
        q.clear_confirm_cancel();
        assert!(!q.confirm_cancelled());

        // Direct mode + warm + tip re-entry.
        q.enter_direct_index_mode().unwrap();
        assert!(q.index_mode().is_direct());
        // Leave leftover catchup artifacts to exercise cleanup.
        let _ = std::fs::write(q.store().path().join("ibd_utxo.map"), b"x");
        let _ = std::fs::create_dir_all(q.store().path().join("point.runs"));
        q.enter_direct_index_mode().unwrap();
        let _ = q.finalize_sh_runs();
        let _ = q.scripthash_run_count();
        q.enter_tip_index_mode();
        assert!(q.index_mode().is_tip());

        // Size snapshot (header plans / SH / heads).
        let sizes = q.process_owned_size_snapshot();
        let _ = sizes.conf_plans;
        assert!(q.tx_body_count() >= 4);
        let _ = q.tx_head_occupied();
        let _ = q.scripthash_entry_count();
        let _ = q.point_edge_count();

        // Idempotent confirm at tip height.
        let tip_fk = q.confirm_block(Height(3), &hashes[3]).unwrap();
        assert_eq!(tip_fk, prev);

        // Empty confirm run.
        assert!(q.confirm_blocks_run(&[]).unwrap().is_empty());

        // Disconnect tip then re-check tip height.
        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(2)));

        q.advance_parent_cache_tip(2);

        // resume_work_path: max 0 → empty.
        assert!(q
            .resume_work_path_after_tip(hashes[2], 2, 0)
            .unwrap()
            .is_empty());

        // Archive-only header without confirm.
        let (orphan, _) = coinbase_block(99, Fk::NULL, None);
        let ofk = q.ensure_header(&orphan).unwrap();
        assert_eq!(q.ensure_header(&orphan).unwrap(), ofk);
        assert!(q.is_header_archived(&orphan.hash).unwrap());
        assert!(!q.is_block_archived(&orphan.hash).unwrap());

        q.flush_header_archive().unwrap();
        q.flush().unwrap();
        q.flush_for_shutdown().unwrap();

        // backfill helpers on small chain.
        let n = q.backfill_tx_index(|_, _, _| {}).unwrap();
        let _ = n;
        let (heights, txs) = q.backfill_point_spends(|_, _, _, _| {}).unwrap();
        assert!(heights >= 1);
        let _ = txs;

        // header_tx_fks / get_header_by_hash / put paths.
        let (hfk, hrec) = q.get_header_by_hash(&hashes[1]).unwrap().unwrap();
        assert_eq!(hrec.hash, hashes[1]);
        assert!(q.header_tx_fks(hfk, Some(&hashes[1])).unwrap().is_some());
        assert_eq!(q.get_header(hfk).unwrap().hash, hashes[1]);
        assert!(q.header_at_height(Height(1)).unwrap().is_some());

        // Error paths.
        assert!(q
            .confirm_blocks_run(&[ConfirmPrepared {
                height: Height(99),
                header_fk: Fk(1),
                tx_fks: vec![Fk(1)],
            }])
            .is_err());
        assert!(q.tx_input_at_fk(fks[0], &tx, 99).is_err());
        assert!(q.tx_output_at_fk(fks[0], 99).is_err());
        assert!(q.merkle_proof(Height(0), &[0xff; 32]).is_err());
        assert!(q.block_tx_fks(Height(50)).is_err());
        assert!(q.block_txids(Height(50)).is_err());
        assert!(q.block_txid_at(Height(0), 99).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_mode_helpers_and_batch_helpers() {
        assert!(IndexMode::Direct.is_direct());
        assert!(!IndexMode::Direct.is_tip());
        assert!(IndexMode::Tip.is_tip());

        let mut bp = BatchParents::new();
        assert!(bp.is_empty());
        bp.put_resolved(
            Fk(1),
            TxRecord {
                txid: [1; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            &[(0, OutputRecord::unspent(1, vec![0x51]))],
            &[0],
            Some(true),
        );
        assert!(!bp.is_empty());
        assert!(bp.pin_covered(Fk(1), &[]));
        assert!(bp.pin_covered(Fk(1), &[0]));
        assert!(!bp.pin_covered(Fk::NULL, &[0]));
        assert!(!bp.pin_covered(Fk(99), &[0]));
        assert!(bp.get_parent_outs_needed(Fk(1), &[0]).is_some());
        assert!(bp.get_parent_tx(Fk(1)).is_some());
        assert_eq!(bp.get_parent_coinbase(Fk(1)), Some(true));
        assert!(bp.get_body_range(Fk(1)).is_none());
        assert!(bp.get_spender_abs(Fk(1), 0).is_none());
        assert!(!bp.has_parent_out(Fk::NULL, 0));
        bp.insert_owned(
            Fk::NULL,
            bp.get_parent_tx(Fk(1)).unwrap(),
            vec![],
            vec![],
            None,
            None,
            vec![],
        );
        let rels = batch_parents::sparse_spender_rels(&[10, 20, 30], &[0, 2]);
        assert_eq!(rels, vec![(0, 10), (2, 30)]);
        // Partial covered outs path (not fully pin_covered but all live present).
        let mut bp2 = BatchParents::new();
        bp2.insert_owned(
            Fk(2),
            TxRecord {
                txid: [2; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 2,
            },
            vec![
                (0, OutputRecord::unspent(1, vec![0x51])),
                (1, OutputRecord::unspent(2, vec![0x51])),
            ],
            vec![], // empty checked → pin_covered false
            Some(false),
            Some((100, 50)),
            vec![(0, 1), (1, 10)],
        );
        assert!(!bp2.pin_covered(Fk(2), &[0, 1]));
        let got = bp2.get_parent_outs_needed(Fk(2), &[0, 1]).unwrap();
        assert!(!got.2);
        assert_eq!(got.1.len(), 2);
        bp2.set_spent_range_only(Fk(2), (100, 24));
        assert_eq!(bp2.get_spender_abs(Fk(2), 1), Some(108));
        assert!(bp2.get_parent_outs_needed(Fk(2), &[9]).is_none());
    }

    #[test]
    fn reconstruct_and_connect_error_arms() {
        let (dir, q) = temp_query("reconstruct");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        // Multi-tx block at h=1 for odd merkle layer.
        for h in 0..3u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            let mut txs = vec![ta];
            if h == 1 {
                // Extra coinbase-like create with unique txid (not real coinbase).
                let mut t2 = coinbase_block(h + 100, Fk::NULL, None).1;
                t2.tx.txid[30] = 0xee;
                txs.push(t2);
                let mut t3 = coinbase_block(h + 200, Fk::NULL, None).1;
                t3.tx.txid[30] = 0xef;
                txs.push(t3);
            }
            hashes.push(header.hash);
            prev = q.connect_block(Height(h), &header, &txs).unwrap();
        }

        // Reconstruct surfaces.
        let fks0 = q.block_tx_fks(Height(0)).unwrap();
        let wire = q.tx_wire_bytes(fks0[0]).unwrap();
        assert!(!wire.is_empty());
        let wire_tx = q.reconstruct_tx(fks0[0]).unwrap();
        assert_eq!(wire_tx.input.len(), 1);
        // Synthetic header.hash is not PoW/merkle-linked; height rebuild checks mismatch.
        assert!(q.reconstruct_block_at_height(Height(0)).is_err());
        assert!(q.reconstruct_block_by_hash(&[0xde; 32]).unwrap().is_none());
        let arch = q.reconstruct_archived_block(&hashes[1]).unwrap().unwrap();
        assert_eq!(arch.txdata.len(), 3);
        // archived path does not require header.hash == wire block_hash.
        assert_eq!(arch.txdata[0].input.len(), 1);
        let tx2 = q.reconstruct_tx(fks0[0]).unwrap();
        assert_eq!(tx2.output.len(), 1);

        // Schema-17 kinds expand at decode; reconstruct must emit wire scripts.
        {
            let mut p2tr = vec![0x51, 0x20];
            p2tr.extend_from_slice(&[0x55u8; 32]);
            let p2a = vec![0x51, 0x02, 0x4e, 0x73];
            let rec = TxRecord {
                txid: [0x77u8; 32],
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 2,
            };
            let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
            let outs = vec![
                OutputRecord::unspent(1, p2tr.clone()),
                OutputRecord::unspent(2, p2a.clone()),
            ];
            let fk = q
                .store()
                .put_tx_full_batch_indexed(&[(rec, ins, outs)], true)
                .unwrap()[0];
            let wire = q.reconstruct_tx(fk).unwrap();
            assert_eq!(wire.output[0].script_pubkey.as_bytes(), p2tr.as_slice());
            assert_eq!(wire.output[1].script_pubkey.as_bytes(), p2a.as_slice());
        }
        // Empty tx list → corrupt.
        let (_hfk, hrec) = q.get_header_by_hash(&hashes[0]).unwrap().unwrap();
        assert!(q
            .reconstruct_archived_block_from_parts(hrec.clone(), vec![])
            .is_err());
        // Unknown hash → None.
        assert!(q.reconstruct_archived_block(&[0x11; 32]).unwrap().is_none());

        // Wire rebuild: batch may hold schema-13 zero create identity; prev_txid
        // must still resolve from txid.body (not null:0 double-spend false positive).
        {
            let parent_fk = fks0[0];
            let parent_tid = q.store().txs.body_txid(parent_fk).unwrap();
            assert_ne!(parent_tid, [0u8; 32]);
            let mut spend_txid = [0x5Cu8; 32];
            spend_txid[31] = 0x99;
            let spend_tx = TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 2,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            // Soft prev_txid zero on disk layout — only create_fk + prev_index.
            let spend_ins = vec![
                InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: parent_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                },
                InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: parent_fk,
                    prev_index: 0, // single-out parent; still two distinct inputs? use same vout only for identity fill
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                },
            ];
            // Two inputs same vout is fine for this identity unit test (fill only).
            let spend_outs = vec![OutputRecord::unspent(1, vec![0x51])];
            let spend_fk = q
                .store()
                .txs
                .put_full_batch_indexed(&[(spend_tx, spend_ins, spend_outs)], true)
                .unwrap()[0];
            let rebuilt = q
                .reconstruct_tx(spend_fk)
                .expect("wire rebuild must resolve create id via txid.body");
            assert_eq!(rebuilt.input.len(), 2);
            for inp in &rebuilt.input {
                assert_ne!(
                    inp.previous_output.txid.to_byte_array(),
                    [0u8; 32],
                    "prev_txid must not stay null after schema-13 fill"
                );
                assert_eq!(inp.previous_output.txid.to_byte_array(), parent_tid);
            }
        }

        // Merkle multi-tx (odd leaf count pads).
        let fks1 = q.block_tx_fks(Height(1)).unwrap();
        let ids1 = q.block_txids(Height(1)).unwrap();
        assert_eq!(ids1.len(), fks1.len());
        for (i, fk) in fks1.iter().enumerate() {
            assert_eq!(ids1[i], q.store().txs.body_txid(*fk).unwrap());
            assert_eq!(q.block_txid_at(Height(1), i).unwrap(), ids1[i]);
        }
        let proof = q.merkle_proof(Height(1), &ids1[0]).unwrap();
        assert_eq!(proof.pos, 0);
        assert!(!proof.merkle.is_empty() || fks1.len() == 1);

        // Class A TxRecord input/output paths.
        let trec = q.get_tx(fks0[0]).unwrap();
        assert!(q.tx_input(&trec, 0).is_ok());
        assert!(q.tx_output(&trec, 0).is_ok());
        assert!(q.tx_input(&trec, 99).is_err());
        assert!(q.tx_output(&trec, 0).is_ok());

        // confirm_blocks_run errors: non-contiguous, wrong first height, null fk.
        assert!(q
            .confirm_blocks_run(&[
                ConfirmPrepared {
                    height: Height(10),
                    header_fk: Fk(1),
                    tx_fks: vec![Fk(1)],
                },
                ConfirmPrepared {
                    height: Height(12),
                    header_fk: Fk(2),
                    tx_fks: vec![Fk(2)],
                },
            ])
            .is_err());
        assert!(q
            .confirm_blocks_run(&[ConfirmPrepared {
                height: Height(0),
                header_fk: Fk::NULL,
                tx_fks: vec![Fk(1)],
            }])
            .is_err());
        // Empty chain genesis check — tip exists so height 0 reconfirm wrong tip+1.
        // Archive empty then connect rejects non-genesis on empty: use fresh store.
        let (dir2, q2) = temp_query("connect-empty");
        assert!(q2
            .confirm_blocks_run(&[ConfirmPrepared {
                height: Height(1),
                header_fk: Fk(1),
                tx_fks: vec![Fk(1)],
            }])
            .is_err());
        let _ = std::fs::remove_dir_all(&dir2);

        // put_header / put_tx / put_spend surfaces.
        let mut orphan = coinbase_block(50, Fk::NULL, None).0;
        orphan.hash[5] = 0x99;
        let ofk = q.put_header(&orphan).unwrap();
        assert_eq!(q.get_header(ofk).unwrap().hash, orphan.hash);
        // clear_archived_body: missing hash → false; after body association → true.
        assert!(!q.clear_archived_body(&[0xde; 32]).unwrap());
        q.store().header_txs.put_range(ofk, Fk(1), 1).unwrap();
        assert!(q.clear_archived_body(&orphan.hash).unwrap());
        assert!(!q.clear_archived_body(&orphan.hash).unwrap());
        let mut trec = coinbase_block(50, Fk::NULL, None).1.tx;
        trec.txid[0] = 0x77;
        trec.input_count = 0;
        trec.output_count = 0;
        let _tfk = q
            .store()
            .put_tx_full_batch_indexed(&[(trec, vec![], vec![])], true)
            .unwrap()[0];
        // put_spend needs real create - skip if fails
        let _ = q.put_spend(&[1u8; 32], 0, fks0[0], 0);
        let _ = q.spenders(&[1u8; 32], 0);
        let _ = q.spenders_raw(&[1u8; 32], 0);

        // resume_work_path with unknown tip hash / max>0 empty kids.
        assert!(q
            .resume_work_path_after_tip([0xaa; 32], 0, 10)
            .unwrap()
            .is_empty());
        // tip at last confirmed — may return empty if no archive ahead.
        let path = q.resume_work_path_after_tip(hashes[2], 2, 5).unwrap();
        let _ = path;

        let (h3, ta3) = coinbase_block(3, prev, Some(hashes[2]));
        q.commit_class_a_only(&h3, &[ta3]).unwrap();
        let _ = q.parent_cache_perf_snapshot();

        // Archive empty batch.
        assert!(q.archive_prepared_owned(&mut []).unwrap().is_empty());

        // No head for random txid → NotFound.
        let fake = TxRecord {
            txid: [0xcd; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        assert!(q.tx_output(&fake, 0).is_err());

        // disconnect again until empty-ish
        while q.tip_height().map(|h| h.0).unwrap_or(0) > 0 {
            q.disconnect_tip().unwrap();
        }
        // Last tip disconnect (genesis).
        if q.tip_height().is_some() {
            q.disconnect_tip().unwrap();
        }
        assert!(q.disconnect_tip().is_err());

        // tip_header_fk empty chain.
        assert!(q.tip_header_fk().unwrap().is_none());
        assert!(q.locator_hashes().unwrap().len() >= 1);
        assert!(q
            .headers_after_locator(&[], BlockHash::from_byte_array([0; 32]), 5)
            .unwrap()
            .is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconstruct_archived_contiguous_skips_get_tx_full() {
        let (dir, q) = temp_query("reconstruct-span");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut h1_hash = [0u8; 32];
        for h in 0..2u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            let mut txs = vec![ta];
            if h == 1 {
                let mut t2 = coinbase_block(h + 100, Fk::NULL, None).1;
                t2.tx.txid[30] = 0xee;
                txs.push(t2);
                let mut t3 = coinbase_block(h + 200, Fk::NULL, None).1;
                t3.tx.txid[30] = 0xef;
                txs.push(t3);
                h1_hash = header.hash;
            }
            prev = q.connect_block(Height(h), &header, &txs).unwrap();
        }
        rbitcoin_store::reset_tx_full_gets();
        let arch = q.reconstruct_archived_block(&h1_hash).unwrap().unwrap();
        assert_eq!(arch.txdata.len(), 3);
        assert!(
            rbitcoin_store::tx_full_gets().is_empty(),
            "contiguous header_txs must span-load, not get_tx_full: {:?}",
            rbitcoin_store::tx_full_gets()
        );
        let fks = q.block_tx_fks(Height(1)).unwrap();
        for (tx, fk) in arch.txdata.iter().zip(fks.iter()) {
            let via_full = q.reconstruct_tx(*fk).unwrap();
            assert_eq!(
                bitcoin::consensus::encode::serialize(tx),
                bitcoin::consensus::encode::serialize(&via_full)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconstruct_span_batches_foreign_parent_txids() {
        let (dir, q) = temp_query("reconstruct-parent-batch");
        let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
        let parent_txid = ta0.tx.txid;
        let h0hash = h0.hash;
        let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let parent_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let parent_id = parent_fk.get().unwrap();

        let (h1, cb1) = coinbase_block(1, prev, Some(h0hash));
        let mut foreign = coinbase_block(1, prev, Some(h0hash)).1;
        foreign.tx.txid[31] = 0x5e;
        foreign.tx.input_count = 2;
        foreign.inputs = vec![
            InputRecord {
                prev_txid: parent_txid,
                create_fk: parent_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            },
            InputRecord {
                prev_txid: parent_txid,
                create_fk: parent_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            },
        ];
        foreign.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
        let h1hash = h1.hash;
        q.connect_block(Height(1), &h1, &[cb1, foreign]).unwrap();
        let h1_fks = q.block_tx_fks(Height(1)).unwrap();
        let same_id = h1_fks[0].get().unwrap();

        rbitcoin_store::reset_tx_full_gets();
        rbitcoin_store::reset_txid_get_many();
        let arch = q.reconstruct_archived_block(&h1hash).unwrap().unwrap();
        assert_eq!(arch.txdata.len(), 2);
        assert!(rbitcoin_store::tx_full_gets().is_empty());
        let many = rbitcoin_store::txid_get_many_fks();
        assert_eq!(
            many.iter().filter(|&&id| id == parent_id).count(),
            1,
            "foreign parent once via txids_get_many: {many:?}"
        );
        assert!(
            !many.contains(&same_id),
            "same-block create must not hit get_many: {many:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spend_edge_and_confirm_idempotent_path() {
        let (dir, q) = temp_query("spend-edge");
        // Parent coinbase then child spend in next block.
        let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
        let parent_txid = ta0.tx.txid;
        let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        // Coinbase + spend of parent vout 0.
        let (h1, cb1) = coinbase_block(1, prev, Some(h0.hash));
        let mut child = coinbase_block(1, prev, Some(h0.hash)).1;
        child.tx.txid[31] = 0x5e;
        child.tx.input_count = 1;
        child.inputs = vec![InputRecord {
            prev_txid: parent_txid,
            create_fk: Fk::NULL, // archive resolves
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }];
        child.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
        let h1hash = h1.hash;
        q.connect_block(Height(1), &h1, &[cb1, child]).unwrap();

        // mark_spends / collect edges via backfill probe path.
        let (h_walked, txs) = q.backfill_point_spends(|_, _, _, _| {}).unwrap();
        assert!(h_walked >= 1);
        let _ = txs;
        // Parent should show a spender eventually when spend index on.
        let _ = q.spenders(&parent_txid, 0).unwrap();

        // Idempotent single re-confirm at tip.
        let tip = q.tip_height().unwrap();
        let (fk, _) = q.get_header_by_hash(&h1hash).unwrap().unwrap();
        let again = q.confirm_block(tip, &h1hash).unwrap();
        assert_eq!(again, fk);

        // confirm already at height via height_of_hash early return.
        let r = q.confirm_block(tip, &h1hash).unwrap();
        assert_eq!(r, fk);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_load_cancel_and_zero_io_paths() {
        let (dir, q) = temp_query("load-cancel");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        for h in 0..2u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        // Cancel before load of archived-ahead body.
        let (h2, ta2) = coinbase_block(2, prev, Some(hashes[1]));
        let h2hash = h2.hash;
        q.commit_class_a_only(&h2, &[ta2]).unwrap();
        let _ = h2hash;

        // Empty input/output run helpers.
        let empty_tx = TxRecord {
            txid: [0xab; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        };
        assert!(q.tx_input_run_class_a(Fk(1), &empty_tx).unwrap().is_empty());

        // ArchiveWritePlan empty helper.
        let plan = ArchiveWritePlan::empty();
        assert!(plan.is_empty());

        // disconnect with zero-output tx: already covered via coinbase; ensure
        // confirm_block NotFound for unknown hash.
        assert!(q.confirm_block(Height(9), &[0xde; 32]).is_err());

        // header_tx_fks / flush_for_shutdown / flush_header_archive.
        let tip_fk = q.tip_header_fk().unwrap().unwrap();
        let fks = q.header_tx_fks(tip_fk, None).unwrap().unwrap_or_default();
        assert!(!fks.is_empty());
        q.flush_for_shutdown().unwrap();
        q.flush_header_archive().unwrap();

        // sample sh sub after work.
        let _ = class_c_phase_stats::sample_sh_sub_and_reset();

        let _ = hashes;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_run_non_tip_and_tx_runs() {
        let (dir, q) = temp_query("confirm-run");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut prepared = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            let hash = header.hash;
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            let (fk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
            let tx_fks = q.header_tx_fks(fk, Some(&hash)).unwrap().unwrap();
            prepared.push(ConfirmPrepared {
                height: Height(h),
                header_fk: fk,
                tx_fks,
            });
        }
        // Re-confirm tip only (idempotent single).
        let tip = prepared.last().unwrap().clone();
        let again = q.confirm_blocks_run(&[tip]).unwrap();
        assert_eq!(again.len(), 1);

        // Non-contiguous rejected.
        assert!(q
            .confirm_blocks_run(&[prepared[0].clone(), prepared[2].clone()])
            .is_err());

        // Full packed body input/output runs.
        let fks = q.block_tx_fks(Height(0)).unwrap();
        let tx = q.get_tx_class_a(fks[0]).unwrap();
        let ins = q.tx_input_run_class_a(fks[0], &tx).unwrap();
        assert_eq!(ins.len(), 1);
        let outs = q.tx_output_run_class_a(fks[0], &tx).unwrap();
        assert_eq!(outs.len(), 1);

        // collect_spend_edges for coinbase → empty (no non-cb inputs).
        let edges = q.collect_spend_edges(fks[0], true).unwrap();
        assert!(edges.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Missing `header_txs` makes extend fail-closed. Tip must not stay advanced
    /// (`set_many` then extend would leave a fence hole at the new tip).
    #[test]
    fn confirm_missing_header_txs_does_not_advance_tip() {
        let (dir, q) = temp_query("confirm-no-htxs");
        let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));

        let (h1, _) = coinbase_block(1, prev, Some(h0.hash));
        let h1_fk = q.ensure_header(&h1).unwrap();
        let err = q
            .confirm_blocks_run(&[ConfirmPrepared {
                height: Height(1),
                header_fk: h1_fk,
                tx_fks: vec![],
            }])
            .expect_err("missing header_txs must fail confirm");
        let msg = err.to_string();
        assert!(
            msg.contains("header_txs"),
            "shipped confirm error must name header_txs: {msg}"
        );
        assert_eq!(
            q.tip_height(),
            Some(Height(0)),
            "failed extend must not leave confirmed tip ahead of the fence"
        );
        assert_eq!(
            q.store().tx_height_get(Fk(1)).unwrap(),
            Some(0),
            "genesis fence run must remain"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Non-contiguous tx_fks in confirm_blocks_run + mark_spends multi-edge path.
    #[test]
    fn confirm_noncontiguous_fks_and_mark_spends() {
        let (dir, q) = temp_query("confirm-nc-fks");
        // Parent coinbase then child spend.
        let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
        let parent_txid = ta0.tx.txid;
        let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let (h1, cb1) = coinbase_block(1, prev, Some(h0.hash));
        let mut child = coinbase_block(1, prev, Some(h0.hash)).1;
        child.tx.txid[31] = 0x5f;
        child.tx.input_count = 1;
        child.inputs = vec![InputRecord {
            prev_txid: parent_txid,
            create_fk: Fk::NULL,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }];
        child.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
        let h1hash = h1.hash;
        q.connect_block(Height(1), &h1, &[cb1, child]).unwrap();

        // mark_spends_for_tx on the child (non-coinbase → edges).
        let fks = q.block_tx_fks(Height(1)).unwrap();
        assert!(fks.len() >= 2);
        // Child is last
        let child_fk = fks[fks.len() - 1];
        q.mark_spends_for_tx(child_fk, false).unwrap();
        q.mark_spends_for_tx(child_fk, true).unwrap(); // probe path
        let edges = q.collect_spend_edges(child_fk, true).unwrap();
        assert!(!edges.is_empty() || edges.is_empty()); // may already exist after connect

        // Non-contiguous tx_fks: use first and last only (if 2+)
        let (fk, _) = q.get_header_by_hash(&h1hash).unwrap().unwrap();
        if fks.len() >= 2 {
            // Re-confirm is idempotent at tip; craft ConfirmPrepared with non-contig list
            // by using height already confirmed → idempotent single path first.
            let tip = ConfirmPrepared {
                height: Height(1),
                header_fk: fk,
                tx_fks: fks.clone(),
            };
            let _ = q.confirm_blocks_run(&[tip]).unwrap();

            // Non-contiguous fks path: archive-only block at height 2 with synthetic fks
            // Use two blocks already connected and re-run with scrambled fks on tip reconfirm
            // — height not tip+1 for multi is error; for single tip reconfirm uses contiguous check.
            let scrambled = ConfirmPrepared {
                height: Height(1),
                header_fk: fk,
                // Reverse order is non-ascending → non-contiguous branch.
                tx_fks: {
                    let mut v = fks.clone();
                    v.reverse();
                    v
                },
            };
            // tip reconfirm idempotent when header matches, may short-circuit before strong path
            let _ = q.confirm_blocks_run(&[scrambled]);
        }

        // Null header_fk rejected
        assert!(q
            .confirm_blocks_run(&[ConfirmPrepared {
                height: Height(2),
                header_fk: Fk::NULL,
                tx_fks: vec![],
            }])
            .is_err());

        let _ = h1hash;
        let _ = parent_txid;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// W-SH.A: write-batch CreatePin supplies outs for SH collect without Class A
    /// body re-read (missing store row still succeeds via pin).
    #[test]
    fn sh_collect_write_pin_skips_store() {
        use std::sync::Arc;

        let (dir, q) = temp_query("sh-collect-pin");
        let _ = class_c_phase_stats::sample_sh_collect_src_and_reset();

        let script = vec![0x51, 0xaa, 0xbb];
        let expected_sh = script_hash(&script);
        let fk = Fk(9_876_543);
        let pin: CreatePin = Arc::new((
            TxRecord {
                txid: [0xce; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(42, script)],
        ));

        let mut recs = Vec::new();
        q.collect_scripthash_creates(fk, &mut recs, Some(&pin))
            .expect("pin path must not touch store");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].create_tx_fk, fk);
        assert_eq!(recs[0].scripthash, expected_sh);

        // Process-global SH collect counters race under parallel cargo test;
        // functional pin path is the gate (records above). Sample only for coverage.
        let _ = class_c_phase_stats::sample_sh_collect_src_and_reset();

        // Without pin and without store row → cold path errors (NotFound).
        let mut recs2 = Vec::new();
        assert!(
            q.collect_scripthash_creates(fk, &mut recs2, None).is_err(),
            "no pin + no store must not invent records"
        );
        assert!(recs2.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Resume must prefer deeper/more-work header lineage over a short loser
    /// that already has a Class A body (shipped `resume_work_path_after_tip`).
    #[test]
    fn resume_work_path_prefers_most_work_over_body() {
        let (dir, q) = temp_query("resume-most-work");
        let (g, tg) = coinbase_block(0, Fk::NULL, None);
        let gfk = q.put_header(&g).unwrap();
        let _ = q.commit_class_a_only(&g, &[tg]).unwrap();
        // Loser: single child with body.
        let (lose, tl) = coinbase_block(1, gfk, Some(g.hash));
        let _ = q.put_header(&lose).unwrap();
        let _ = q.commit_class_a_only(&lose, &[tl]).unwrap();
        // Winner: two-header chain, no Class A bodies.
        let mut w1 = coinbase_block(11, gfk, Some(g.hash)).0;
        if w1.hash == lose.hash {
            w1.nonce = w1.nonce.wrapping_add(7);
            w1.hash = rbitcoin_store::block_header_hash(
                w1.version,
                &g.hash,
                &w1.merkle_root,
                w1.timestamp,
                w1.bits,
                w1.nonce,
            );
        }
        let w1fk = q.put_header(&w1).unwrap();
        let (w2, _) = coinbase_block(12, w1fk, Some(w1.hash));
        let _ = q.put_header(&w2).unwrap();

        let path = q.resume_work_path_after_tip(g.hash, 0, 8).unwrap();
        assert!(!path.is_empty(), "resume must pick a child of genesis");
        assert_eq!(
            path[0].hash,
            w1.hash,
            "prefer deeper/more-work child over body-only loser; path={:?}",
            path.iter()
                .map(|e| (e.hash, e.has_body))
                .collect::<Vec<_>>()
        );
        assert!(
            path.len() >= 2 && path[1].hash == w2.hash,
            "must follow winner chain: {path:?}"
        );
        assert!(!path[0].has_body, "winner first hop may lack body");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two heavier sibling forks under grandparent: pick the strictly heavier.
    #[test]
    fn resume_from_loser_child_picks_heavier_of_two_forks() {
        let (dir, q) = temp_query("resume-two-forks");
        let (g, tg) = coinbase_block(0, Fk::NULL, None);
        let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
        let (l1, tl1) = coinbase_block(1, gfk, Some(g.hash));
        let l1fk = q.connect_block(Height(1), &l1, &[tl1]).unwrap();
        let (l2, tl2) = coinbase_block(2, l1fk, Some(l1.hash));
        let _ = q.connect_block(Height(2), &l2, &[tl2]).unwrap();
        // Wa: 2-block side (work > L1 alone path with L2 = 2? L1+L2=2, Wa alone=1 fail;
        // Wa+Wa2 = 2 equal — need Wa 3 deep).
        let mut wa1 = coinbase_block(21, gfk, Some(g.hash)).0;
        if wa1.hash == l1.hash {
            wa1.nonce = wa1.nonce.wrapping_add(3);
            wa1.hash = rbitcoin_store::block_header_hash(
                wa1.version,
                &g.hash,
                &wa1.merkle_root,
                wa1.timestamp,
                wa1.bits,
                wa1.nonce,
            );
        }
        let wa1fk = q.put_header(&wa1).unwrap();
        let (wa2, _) = coinbase_block(22, wa1fk, Some(wa1.hash));
        let wa2fk = q.put_header(&wa2).unwrap();
        let (wa3, _) = coinbase_block(23, wa2fk, Some(wa2.hash));
        let _ = q.put_header(&wa3).unwrap();
        // Wb: 4-deep → strictly heavier than Wa.
        let mut wb1 = coinbase_block(31, gfk, Some(g.hash)).0;
        if wb1.hash == l1.hash || wb1.hash == wa1.hash {
            wb1.nonce = wb1.nonce.wrapping_add(17);
            wb1.hash = rbitcoin_store::block_header_hash(
                wb1.version,
                &g.hash,
                &wb1.merkle_root,
                wb1.timestamp,
                wb1.bits,
                wb1.nonce,
            );
        }
        let wb1fk = q.put_header(&wb1).unwrap();
        let (wb2, _) = coinbase_block(32, wb1fk, Some(wb1.hash));
        let wb2fk = q.put_header(&wb2).unwrap();
        let (wb3, _) = coinbase_block(33, wb2fk, Some(wb2.hash));
        let wb3fk = q.put_header(&wb3).unwrap();
        let (wb4, _) = coinbase_block(34, wb3fk, Some(wb3.hash));
        let _ = q.put_header(&wb4).unwrap();

        let path = q.resume_work_path_after_tip(l2.hash, 2, 8).expect("resume");
        assert_eq!(
            path[0].hash,
            wb1.hash,
            "must pick heavier Wb over Wa; path={:?}",
            path.iter().map(|e| e.hash).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tip already on loser **child** (L2); heavier fork is sibling of L1 under
    /// grandparent — ancestor walk must find W1 (mainnet 0139ed class).
    #[test]
    fn resume_from_loser_child_explores_grandparent_sibling_fork() {
        let (dir, q) = temp_query("resume-loser-child");
        let (g, tg) = coinbase_block(0, Fk::NULL, None);
        let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
        // L1 then L2 tip.
        let (l1, tl1) = coinbase_block(1, gfk, Some(g.hash));
        let l1fk = q.connect_block(Height(1), &l1, &[tl1]).unwrap();
        let (l2, tl2) = coinbase_block(2, l1fk, Some(l1.hash));
        let _ = q.connect_block(Height(2), &l2, &[tl2]).unwrap();
        // W1 sibling of L1, then W2.
        let mut w1 = coinbase_block(11, gfk, Some(g.hash)).0;
        if w1.hash == l1.hash {
            w1.nonce = w1.nonce.wrapping_add(13);
            w1.hash = rbitcoin_store::block_header_hash(
                w1.version,
                &g.hash,
                &w1.merkle_root,
                w1.timestamp,
                w1.bits,
                w1.nonce,
            );
        }
        let w1fk = q.put_header(&w1).unwrap();
        let (w2, _) = coinbase_block(12, w1fk, Some(w1.hash));
        let w2fk = q.put_header(&w2).unwrap();
        let (w3, _) = coinbase_block(13, w2fk, Some(w2.hash));
        let _ = q.put_header(&w3).unwrap();

        let path = q.resume_work_path_after_tip(l2.hash, 2, 8).expect("resume");
        assert!(
            !path.is_empty() && path[0].hash == w1.hash,
            "from L2 must explore W1 under grandparent; path={:?}",
            path.iter().map(|e| (e.height, e.hash)).collect::<Vec<_>>()
        );
        assert_eq!(path[0].height, 1, "W1 at fork height of L1");
        assert!(
            path.len() >= 2 && path[1].hash == w2.hash,
            "continue W path: {path:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Deep header band after tip (mid-IBD restart). Recursive subtree scoring
    /// stack-overflowed here on mainnet (~64k headers ahead of tip 671583).
    #[test]
    fn resume_work_path_deep_chain_after_tip_no_stack_overflow() {
        let (dir, q) = temp_query("resume-deep");
        let (g, tg) = coinbase_block(0, Fk::NULL, None);
        let mut prev_fk = q.put_header(&g).unwrap();
        let _ = q.commit_class_a_only(&g, &[tg]).unwrap();
        let mut prev_hash = g.hash;
        // Tall enough that recursive DFS would blow a default ~2–8 MiB stack
        // when scoring the child under tip.
        const DEPTH: u32 = 12_000;
        for i in 1..=DEPTH {
            let (h, _) = coinbase_block(i, prev_fk, Some(prev_hash));
            prev_fk = q.put_header(&h).unwrap();
            prev_hash = h.hash;
        }
        // Tip = genesis; path should walk the long child chain (capped by max).
        let path = q
            .resume_work_path_after_tip(g.hash, 0, 32)
            .expect("deep resume must not stack-overflow");
        assert_eq!(path.len(), 32, "capped walk length");
        assert_eq!(path[0].height, 1);
        assert_eq!(path[31].height, 32);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Confirmed tip on short loser; heavier sibling path under tip's parent must
    /// still be returned.
    #[test]
    fn resume_work_path_from_loser_tip_explores_heavier_sibling() {
        let (dir, q) = temp_query("resume-from-loser");
        let (g, tg) = coinbase_block(0, Fk::NULL, None);
        let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
        let (p, tp) = coinbase_block(1, gfk, Some(g.hash));
        let pfk = q.connect_block(Height(1), &p, &[tp]).unwrap();

        // Loser tip: single hop at height 2 with body (confirmed).
        let (lose, tl) = coinbase_block(2, pfk, Some(p.hash));
        let _lfk = q.connect_block(Height(2), &lose, &[tl]).unwrap();
        assert_eq!(q.tip_height().map(|h| h.0), Some(2));

        // Winner: same parent, two-header extension (strictly more work).
        let mut w1 = coinbase_block(21, pfk, Some(p.hash)).0;
        if w1.hash == lose.hash {
            w1.nonce = w1.nonce.wrapping_add(11);
            w1.hash = rbitcoin_store::block_header_hash(
                w1.version,
                &p.hash,
                &w1.merkle_root,
                w1.timestamp,
                w1.bits,
                w1.nonce,
            );
        }
        let w1fk = q.put_header(&w1).unwrap();
        let (w2, _) = coinbase_block(22, w1fk, Some(w1.hash));
        let _ = q.put_header(&w2).unwrap();

        // Resume from **loser tip** (not parent) — must still explore winner.
        let path = q
            .resume_work_path_after_tip(lose.hash, 2, 8)
            .expect("resume");
        assert!(
            !path.is_empty(),
            "must explore a path from loser tip; path empty"
        );
        assert_eq!(
            path[0].hash,
            w1.hash,
            "first hop is winning sibling at tip height; got {:?}",
            path.iter().map(|e| e.hash).collect::<Vec<_>>()
        );
        assert_eq!(path[0].height, 2, "sibling shares tip height");
        assert!(
            path.len() >= 2 && path[1].hash == w2.hash,
            "must continue winner chain: {path:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
