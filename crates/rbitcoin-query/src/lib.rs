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

#[cfg(debug_assertions)]
pub use combined_stage::{body_ok_reads, reset_body_ok_reads};
pub use combined_stage::{load_creates_once, CombinedCreate};
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
    /// When false, archive **and** confirm skip durable Class B point (spend) writes.
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
    /// Tip height of last in-process io_uring recover (`u32::MAX` = none).
    uring_recover_tip: AtomicU32,
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
            uring_recover_tip: AtomicU32::new(u32::MAX),
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
        let v = self.sh.indexed_through.load(AtomicOrdering::Acquire);
        if v == u64::MAX {
            None
        } else {
            Some(v as u32)
        }
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
            sh_heads: self.sh.heads.lock().unwrap().len(),
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

        let skip = |h: [u8; 32]| exclude.iter().any(|x| *x == h);

        let mut children: U64Map<Vec<(Fk, [u8; 32])>> = U64Map::default();
        for id in 1..=n {
            let fk = Fk(id);
            let rec = self.store.get_header(fk)?;
            if skip(rec.hash) {
                continue;
            }
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
#[path = "query_tests.rs"]
mod tests;
