//! Block and transaction validation / confirmability.

mod block;
mod clock;
mod confirm_run;
mod convert;
mod error;
mod header;
mod milestone;
mod params;
pub mod policy;
mod regtest_pad;
mod script;
mod script_pool;
mod signet;
pub mod silent_payments;

pub use block::ScriptCheckJob;

/// Consensus script verify for a single tx on the shared `rbtc-scripts` path.
///
/// Always hops to a detached script worker (same naming/pool family as IBD
/// confirm scripts). Callers on peer sessions or tokio request threads must use
/// this (or equivalent) — never run the interpreter on the I/O stack.
pub fn verify_tx_scripts_detached(
    prevouts: Vec<bitcoin::TxOut>,
    tx: bitcoin::Transaction,
) -> Result<(), ConsensusError> {
    script_pool::run_detached_join(move || {
        let job = ScriptCheckJob::new(prevouts, tx, true, true, true, true, true);
        crate::script::verify_job_all_inputs(&job)
    })
    .unwrap_or_else(|| Err(ConsensusError::BadBlock("script worker disconnected")))
}

pub use block::{
    apply_witness_commitment, bip34_height_script, bip68_active_for_tx, block_has_witness,
    block_subsidy, check_block_wire, is_final_tx, sequence_locks_satisfied, tx_gbt_sigops,
    validate_block_connect, validate_block_structure, validate_block_structure_hashed,
    validate_block_structure_precomputed, validate_block_structure_with_pres, verify_scripts_pool,
    witness_commitment_script, TxPrecompute, ValidationContext, LOCKTIME_THRESHOLD,
};
pub use clock::{current_now, wall_now, with_now, NodeClock};
pub use convert::{block_to_apply, block_to_apply_with_txids, header_to_record};
pub use error::{block_reject_log_line, block_reject_reason, script_flag_paren, ConsensusError};
pub use header::{expected_next_bits, median_time_past, validate_header};
pub use milestone::Milestone;
pub use params::{default_milestone_height, genesis_block, ChainParams, Checkpoint};
pub use policy::PolicyResult;
pub use regtest_pad::{
    grind_regtest_pow, mine_empty_regtest, mine_regtest_paying, pad_empty_from,
    prepare_regtest_candidate, REGTEST_BLOCK_SPACING, REGTEST_POW_BITS,
};
pub use signet::{default_signet_challenge, signet_magic, validate_signet_block_solution};
pub use silent_payments::{
    backfill_sp_tweaks, backfill_sp_tweaks_cancellable, tweak_from_tx, tweaks_at_height,
    tweaks_for_height, tweaks_from_thin_and_body, TaprootOut, TxTweak,
};

use bitcoin::hashes::Hash;
use bitcoin::{Block, Target};
use rbitcoin_primitives::Height;
use rbitcoin_query::{Query, TxApply};
use rbitcoin_store::HeaderRecord;

/// Confirm the next tip block if its body is already archived.
///
/// IBD diagnostics: wall time spent in each phase (nanoseconds; reset by the sampler).
pub mod confirm_phase_stats {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Total reconstruct-ish wall (wire rebuild; historical total).
    pub static RECONSTRUCT_NS: AtomicU64 = AtomicU64::new(0);
    /// Full wire `Block` rebuild from Class A rows.
    pub static RECONSTRUCT_WIRE_NS: AtomicU64 = AtomicU64::new(0);
    /// Optimistic assemble (prevout content + jobs; no durable spentness).
    pub static CONNECT_NS: AtomicU64 = AtomicU64::new(0);
    pub static SCRIPT_NS: AtomicU64 = AtomicU64::new(0);
    /// Script jobs submitted to the pool this window.
    pub static SCRIPT_JOBS: AtomicU64 = AtomicU64::new(0);
    /// Script jobs skipped because mempool already verified the tx (tip follow).
    pub static SCRIPT_SKIP_MEMPOOL: AtomicU64 = AtomicU64::new(0);
    /// Post-script durable spentness + maturity + BIP68 + subsidy (write).
    pub static STRUCTURAL_NS: AtomicU64 = AtomicU64::new(0);
    /// Durable spentness probes only (subset of structural).
    pub static STRUCTURAL_SPENT_NS: AtomicU64 = AtomicU64::new(0);
    /// Spent sub: pin abs collect + bulk 8-byte on-disk meta pread.
    pub static STRUCTURAL_SPENT_ABS_NS: AtomicU64 = AtomicU64::new(0);
    /// Spent sub: `is_confirmed_strong_at` on non-null spender fields.
    pub static STRUCTURAL_SPENT_STRONG_NS: AtomicU64 = AtomicU64::new(0);
    /// Spent sub: cold unspent_create_vouts / null-create path.
    pub static STRUCTURAL_SPENT_COLD_NS: AtomicU64 = AtomicU64::new(0);
    /// Spent sub: order-sensitive pending_spent gate (CPU).
    pub static STRUCTURAL_SPENT_PENDING_NS: AtomicU64 = AtomicU64::new(0);
    /// Create-height + coinbase maturity resolve (subset of structural).
    pub static STRUCTURAL_CREATE_H_NS: AtomicU64 = AtomicU64::new(0);
    /// BIP68 relative locks + coin MTP (subset of structural; write path).
    pub static STRUCTURAL_BIP68_NS: AtomicU64 = AtomicU64::new(0);
    /// Non-SH Class C **tables** only: strong/height + tip set/flush.
    ///
    /// **Not** the join wall of `confirm_blocks_run` (which is dominated by
    /// parallel SH on tip mode). SH time lives in query `SCRIPTHASH_NS` / `SH_*`.
    pub static CLASS_C_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-stage Class A append (`archive_commit_plan`) wall.
    ///
    /// Body/head/header_txs. Also mirrored in
    /// [`rbitcoin_query::archive_phase_stats`] write_* subtimers.
    pub static CLASS_A_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-stage BIP-352 thin tweak index (`index_sp_tweaks_batch`) wall.
    ///
    /// Zero when `--sptweaks` is off. Not inside `UTXO_APPLY_NS` / `spend=`.
    pub static TWEAK_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-stage denserels/abs ensure after Class A (fill planned + ensure spends).
    pub static ENSURE_LAYOUT_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-stage RecentCreates note+expire+one snapshot publish.
    pub static WRITE_RECENT_NS: AtomicU64 = AtomicU64::new(0);
    /// `tx_body_range_batch` inside that publish.
    pub static WRITE_RECENT_IDX_NS: AtomicU64 = AtomicU64::new(0);
    /// `publish_if_dirty` clone inside that publish.
    pub static WRITE_RECENT_CLONE_NS: AtomicU64 = AtomicU64::new(0);
    /// `class_c_commit` wall minus tables (`flush` / SH join).
    pub static WRITE_CLASS_C_JOIN_NS: AtomicU64 = AtomicU64::new(0);
    /// Residual wait on `head_insert_queued` join after Class C / annotate.
    pub static WRITE_DRAIN_JOIN_NS: AtomicU64 = AtomicU64::new(0);
    /// Write-thread body-queue dequeue after a successful confirm.
    pub static WRITE_DEQUEUE_NS: AtomicU64 = AtomicU64::new(0);
    /// Clone `planned_fks` + pin Arcs before Class A (`pins=` take=).
    pub static WRITE_PLAN_TAKE_NS: AtomicU64 = AtomicU64::new(0);
    /// `write_create_pins` FkMap insert after Class A (`pins=` map=).
    pub static WRITE_CREATE_MAP_NS: AtomicU64 = AtomicU64::new(0);
    /// `take_pending_queued` + `submit_head_insert` (`head_sub=`).
    pub static WRITE_HEAD_SUB_NS: AtomicU64 = AtomicU64::new(0);
    /// Ensure path: creates filled from pin layout (no Class A body IO).
    pub static ENSURE_RES_HIT: AtomicU64 = AtomicU64::new(0);
    /// Ensure path: cold denserels body loads.
    pub static ENSURE_COLD_N: AtomicU64 = AtomicU64::new(0);
    /// Assemble subtimers (ns; inside CONNECT_NS).
    pub static ASM_PREVOUT_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_SIGOP_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_FINAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_JOB_NS: AtomicU64 = AtomicU64::new(0);
    /// Non-coinbase inputs resolved in `resolve_prevout` (for us/in).
    pub static ASM_IN_N: AtomicU64 = AtomicU64::new(0);
    /// Prevout path splits (ns + counts; sum of path ns ≈ ASM_PREVOUT_NS).
    pub static ASM_PREV_BATCH_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_PREV_BATCH_N: AtomicU64 = AtomicU64::new(0);
    pub static ASM_PREV_SAME_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_PREV_SAME_N: AtomicU64 = AtomicU64::new(0);
    pub static ASM_PREV_COLD_NS: AtomicU64 = AtomicU64::new(0);
    pub static ASM_PREV_COLD_N: AtomicU64 = AtomicU64::new(0);
    /// Time in `tx_fk_by_txid` / durable head lookup on cold prevout path.
    pub static ASM_PREV_FK_NS: AtomicU64 = AtomicU64::new(0);
    /// Cold success with **no** `prev_fk_hint` (thin + pending + head miss at assemble).
    pub static ASM_PREV_COLD_NULL_FK_N: AtomicU64 = AtomicU64::new(0);
    /// Cold success: had fk, batch pin miss (pin did not cover parent/vout).
    pub static ASM_PREV_COLD_NOT_PIN_N: AtomicU64 = AtomicU64::new(0);
    /// Cold success: batch pin had a row but **parent txid ≠ wire prev_txid**.
    pub static ASM_PREV_COLD_TXID_MISMATCH_N: AtomicU64 = AtomicU64::new(0);
    /// Cold success: parent create is in BatchParents but **needed vout** missing.
    pub static ASM_PREV_COLD_VOUT_MISS_N: AtomicU64 = AtomicU64::new(0);
    /// Post–Class C durable spend annotation batch.
    ///
    /// Historical name `UTXO_APPLY_NS` / log field `spend=` ms — this is **not** a
    /// light-UTXO map apply (Catchup removed). Wall time for all annotate paths.
    pub static UTXO_APPLY_NS: AtomicU64 = AtomicU64::new(0);
    /// Annotate edges via abs pin denserels (pure-write known meta).
    /// Historical name: formerly also counted ranged body walks (removed on Direct write).
    pub static SPEND_ANNOTATE_RANGED: AtomicU64 = AtomicU64::new(0);
    /// Legacy cold idx annotate path (must stay 0 on Direct IBD after abs-only write).
    pub static SPEND_ANNOTATE_IDX: AtomicU64 = AtomicU64::new(0);
    /// Spends skipped (null create_fk or null spend_fk).
    pub static SPEND_ANNOTATE_SKIP: AtomicU64 = AtomicU64::new(0);
    /// Pure-write annotate wall (ns) / edge count (backend is uring or pwrite).
    pub static SPEND_ANN_NS: AtomicU64 = AtomicU64::new(0);
    pub static SPEND_ANN_N: AtomicU64 = AtomicU64::new(0);
    /// Edges annotated without body pread (should equal all annotate edges).
    pub static SPEND_ANN_PREAD_SKIP: AtomicU64 = AtomicU64::new(0);
    /// Body preads on annotate (must stay 0 on pure-write write path).
    pub static SPEND_ANN_PREAD: AtomicU64 = AtomicU64::new(0);
    /// Structural spent meta bulk read wall (ns) / peek count.
    pub static SPEND_META_NS: AtomicU64 = AtomicU64::new(0);
    pub static SPEND_META_N: AtomicU64 = AtomicU64::new(0);
    /// Header + body-fk resolve for the batch.
    pub static RESOLVE_NS: AtomicU64 = AtomicU64::new(0);
    /// Prep pre-assemble wall on the prep/load thread.
    ///
    /// Wire path: structure + plan Class A + pin parents (stops before assemble).
    /// Full prep wall ≈ `LOAD_NS` + [`CONNECT_NS`] (assemble).
    pub static LOAD_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire load sub: `Arc::new(block.clone())` (target for Arc handoff).
    pub static PREP_WIRE_ARC_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire load sub: structure + softfork shape checks.
    pub static PREP_STRUCT_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire load sub: header validate/put + parent-cache header plan seed.
    pub static PREP_HEADER_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire load sub: `prepare_block_for_archive` (tx apply packing).
    pub static PREP_PREPARE_NS: AtomicU64 = AtomicU64::new(0);
    /// Wire load sub: filter need + plan batch + meta/tx_fks wiring (not pin).
    pub static PREP_FILTER_PLAN_NS: AtomicU64 = AtomicU64::new(0);
    /// Unpin spent outs from ConfirmParentCache after Class C.
    pub static UNPIN_NS: AtomicU64 = AtomicU64::new(0);
    /// `advance_parent_cache_tip` (drop bodies / GC parents).
    pub static CACHE_TIP_NS: AtomicU64 = AtomicU64::new(0);
    pub static BLOCKS: AtomicU64 = AtomicU64::new(0);

    static LAST_WRITE_N: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_CLASS_A_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_ENSURE_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_STRUCTURAL_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_SPENT_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_CREATE_H_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_BIP68_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_CLASS_C_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_SPEND_ANN_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_TIP_GC_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_TWEAK_NS: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_WALL_NS: AtomicU64 = AtomicU64::new(0);

    /// Snapshot of the most recent successful [`super::confirm_write_phase`].
    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastWritePhases {
        pub n_blocks: u32,
        pub wall_ns: u64,
        /// Class A append (`archive_commit_plan`).
        pub class_a_ns: u64,
        /// fill planned layout + ensure denserels/abs for spends.
        pub ensure_ns: u64,
        pub structural_ns: u64,
        pub spent_ns: u64,
        pub create_h_ns: u64,
        pub bip68_ns: u64,
        pub class_c_ns: u64,
        pub spend_ann_ns: u64,
        pub tip_gc_ns: u64,
        /// BIP-352 thin tweak index (`index_sp_tweaks_batch`) after annotate.
        pub tweak_ns: u64,
    }

    impl LastWritePhases {
        #[inline]
        pub fn ms(ns: u64) -> u64 {
            ns / 1_000_000
        }
    }

    /// Record per-batch write phases (called from write stage; overwrites prior).
    pub fn note_last_write(p: LastWritePhases) {
        LAST_WRITE_N.store(u64::from(p.n_blocks), Ordering::Relaxed);
        LAST_WRITE_WALL_NS.store(p.wall_ns, Ordering::Relaxed);
        LAST_WRITE_CLASS_A_NS.store(p.class_a_ns, Ordering::Relaxed);
        LAST_WRITE_ENSURE_NS.store(p.ensure_ns, Ordering::Relaxed);
        LAST_WRITE_STRUCTURAL_NS.store(p.structural_ns, Ordering::Relaxed);
        LAST_WRITE_SPENT_NS.store(p.spent_ns, Ordering::Relaxed);
        LAST_WRITE_CREATE_H_NS.store(p.create_h_ns, Ordering::Relaxed);
        LAST_WRITE_BIP68_NS.store(p.bip68_ns, Ordering::Relaxed);
        LAST_WRITE_CLASS_C_NS.store(p.class_c_ns, Ordering::Relaxed);
        LAST_WRITE_SPEND_ANN_NS.store(p.spend_ann_ns, Ordering::Relaxed);
        LAST_WRITE_TIP_GC_NS.store(p.tip_gc_ns, Ordering::Relaxed);
        LAST_WRITE_TWEAK_NS.store(p.tweak_ns, Ordering::Relaxed);
    }

    pub fn last_write_phases() -> LastWritePhases {
        LastWritePhases {
            n_blocks: LAST_WRITE_N.load(Ordering::Relaxed) as u32,
            wall_ns: LAST_WRITE_WALL_NS.load(Ordering::Relaxed),
            class_a_ns: LAST_WRITE_CLASS_A_NS.load(Ordering::Relaxed),
            ensure_ns: LAST_WRITE_ENSURE_NS.load(Ordering::Relaxed),
            structural_ns: LAST_WRITE_STRUCTURAL_NS.load(Ordering::Relaxed),
            spent_ns: LAST_WRITE_SPENT_NS.load(Ordering::Relaxed),
            create_h_ns: LAST_WRITE_CREATE_H_NS.load(Ordering::Relaxed),
            bip68_ns: LAST_WRITE_BIP68_NS.load(Ordering::Relaxed),
            class_c_ns: LAST_WRITE_CLASS_C_NS.load(Ordering::Relaxed),
            spend_ann_ns: LAST_WRITE_SPEND_ANN_NS.load(Ordering::Relaxed),
            tip_gc_ns: LAST_WRITE_TIP_GC_NS.load(Ordering::Relaxed),
            tweak_ns: LAST_WRITE_TWEAK_NS.load(Ordering::Relaxed),
        }
    }

    /// Spent subtimers (on-disk abs pread / strong / cold / pending). Sample + reset.
    ///
    /// Sum may be ≤ [`STRUCTURAL_SPENT_NS`] (setup residual). Authority remains
    /// durable Class A meta — these only rank the probe.
    #[inline]
    pub fn sample_spent_sub_and_reset() -> (u64, u64, u64, u64) {
        (
            STRUCTURAL_SPENT_ABS_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_SPENT_STRONG_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_SPENT_COLD_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_SPENT_PENDING_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// Sample and reset write-only Class A + ensure layout windows.
    #[inline]
    pub fn sample_class_a_ensure_and_reset() -> (u64, u64) {
        (
            CLASS_A_NS.swap(0, Ordering::Relaxed),
            ENSURE_LAYOUT_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// Sample and reset write-stage RecentCreates publish wall.
    #[inline]
    pub fn sample_write_recent_and_reset() -> u64 {
        WRITE_RECENT_NS.swap(0, Ordering::Relaxed)
    }

    /// `(idx, clone)` parts of RecentCreates publish.
    #[inline]
    pub fn sample_write_recent_parts_and_reset() -> (u64, u64) {
        (
            WRITE_RECENT_IDX_NS.swap(0, Ordering::Relaxed),
            WRITE_RECENT_CLONE_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// `(drain_join, dequeue)` residual write walls.
    #[inline]
    pub fn sample_write_residuals_and_reset() -> (u64, u64) {
        (
            WRITE_DRAIN_JOIN_NS.swap(0, Ordering::Relaxed),
            WRITE_DEQUEUE_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// `(plan_take, create_map, head_sub)` write-other classification walls.
    #[inline]
    pub fn sample_write_pins_and_reset() -> (u64, u64, u64) {
        (
            WRITE_PLAN_TAKE_NS.swap(0, Ordering::Relaxed),
            WRITE_CREATE_MAP_NS.swap(0, Ordering::Relaxed),
            WRITE_HEAD_SUB_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// Sample and reset Class C join/flush residual.
    #[inline]
    pub fn sample_class_c_join_and_reset() -> u64 {
        WRITE_CLASS_C_JOIN_NS.swap(0, Ordering::Relaxed)
    }

    /// Sample and reset write-stage SP tweak index wall.
    #[inline]
    pub fn sample_tweak_and_reset() -> u64 {
        TWEAK_NS.swap(0, Ordering::Relaxed)
    }

    /// `(ensure_res_hit, ensure_cold_n)` for write ensure mix.
    #[inline]
    pub fn sample_ensure_mix_and_reset() -> (u64, u64) {
        (
            ENSURE_RES_HIT.swap(0, Ordering::Relaxed),
            ENSURE_COLD_N.swap(0, Ordering::Relaxed),
        )
    }

    /// Assemble subtimers (ns): `(prevout, sigop, finality, job_build)`.
    #[inline]
    pub fn sample_assemble_and_reset() -> (u64, u64, u64, u64) {
        (
            ASM_PREVOUT_NS.swap(0, Ordering::Relaxed),
            ASM_SIGOP_NS.swap(0, Ordering::Relaxed),
            ASM_FINAL_NS.swap(0, Ordering::Relaxed),
            ASM_JOB_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// Prevout path detail: `(in_n, batch_ns, batch_n, same_ns, same_n,
    /// cold_ns, cold_n, fk_ns)`.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn sample_assemble_prevout_detail_and_reset() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            ASM_IN_N.swap(0, Ordering::Relaxed),
            ASM_PREV_BATCH_NS.swap(0, Ordering::Relaxed),
            ASM_PREV_BATCH_N.swap(0, Ordering::Relaxed),
            ASM_PREV_SAME_NS.swap(0, Ordering::Relaxed),
            ASM_PREV_SAME_N.swap(0, Ordering::Relaxed),
            ASM_PREV_COLD_NS.swap(0, Ordering::Relaxed),
            ASM_PREV_COLD_N.swap(0, Ordering::Relaxed),
            ASM_PREV_FK_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// N1 cold-reason counts: `(null_fk, not_pin, txid_mismatch, vout_miss)`.
    ///
    /// Sum should equal [`ASM_PREV_COLD_N`] for the same window (successful cold
    /// resolves only — failures do not increment).
    #[inline]
    pub fn sample_assemble_cold_why_and_reset() -> (u64, u64, u64, u64) {
        (
            ASM_PREV_COLD_NULL_FK_N.swap(0, Ordering::Relaxed),
            ASM_PREV_COLD_NOT_PIN_N.swap(0, Ordering::Relaxed),
            ASM_PREV_COLD_TXID_MISMATCH_N.swap(0, Ordering::Relaxed),
            ASM_PREV_COLD_VOUT_MISS_N.swap(0, Ordering::Relaxed),
        )
    }

    // Thread-local N1 cold-why / batch / cold path counts for unit tests.
    // Process-global atomics race under parallel cargo test; N1 samples these TLS
    // counters updated only by this thread's resolve_prevout (cfg(test)).
    #[cfg(test)]
    thread_local! {
        static TL_COLD_WHY: std::cell::Cell<(u64, u64, u64, u64)> =
            const { std::cell::Cell::new((0, 0, 0, 0)) };
        static TL_BATCH_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static TL_COLD_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[cfg(test)]
    #[inline]
    pub fn tl_note_cold_why_null_fk() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a + 1, b, c2, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[cfg(test)]
    #[inline]
    pub fn tl_note_cold_why_not_pin() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b + 1, c2, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[cfg(test)]
    #[inline]
    pub fn tl_note_cold_why_txid_mismatch() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2 + 1, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[cfg(test)]
    #[inline]
    pub fn tl_note_cold_why_vout_miss() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2, d + 1));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[cfg(test)]
    #[inline]
    pub fn tl_note_batch_hit() {
        TL_BATCH_N.with(|c| c.set(c.get() + 1));
    }
    #[cfg(test)]
    #[inline]
    pub fn sample_tl_assemble_cold_why_and_reset() -> (u64, u64, u64, u64) {
        TL_COLD_WHY.with(|c| c.replace((0, 0, 0, 0)))
    }
    #[cfg(test)]
    #[inline]
    pub fn sample_tl_batch_cold_n_and_reset() -> (u64, u64) {
        let b = TL_BATCH_N.with(|c| c.replace(0));
        let cold = TL_COLD_N.with(|c| c.replace(0));
        (b, cold)
    }

    /// Wire-prep residual subtimers (ns): `(wire_arc, struct, header, prepare, filter_plan)`.
    ///
    /// These sit inside [`LOAD_NS`] but outside pin (confirm_load_stats). Pin and
    /// assemble remain separate (`PARENT_PIN_NS` / [`CONNECT_NS`]).
    #[inline]
    pub fn sample_prep_residual_and_reset() -> (u64, u64, u64, u64, u64) {
        (
            PREP_WIRE_ARC_NS.swap(0, Ordering::Relaxed),
            PREP_STRUCT_NS.swap(0, Ordering::Relaxed),
            PREP_HEADER_NS.swap(0, Ordering::Relaxed),
            PREP_PREPARE_NS.swap(0, Ordering::Relaxed),
            PREP_FILTER_PLAN_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// Sample and reset all confirm phases.
    ///
    /// Returns
    /// `(recon, wire, connect, script, class_c, strong, scripthash, tip,
    ///   utxo_apply, blocks, resolve, load, unpin, cache_tip,
    ///   spend_ranged, spend_idx, spend_skip, structural, structural_spent,
    ///   structural_create_h, structural_bip68)`.
    /// `class_c` is **strong+tip tables only** (not SH join wall; SH is
    /// `scripthash`). `strong` / `scripthash` / `tip` come from
    /// [`rbitcoin_query::class_c_phase_stats`].
    /// `recon` prefers wire sub-timer, else legacy total.
    /// `connect` is **load assemble**, not write structural — see `structural`.
    #[allow(clippy::type_complexity)]
    pub fn sample_and_reset() -> (
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
    ) {
        let (strong, sh, tip) = rbitcoin_query::class_c_phase_stats::sample_and_reset();
        let wire = RECONSTRUCT_WIRE_NS.swap(0, Ordering::Relaxed);
        let recon_total = RECONSTRUCT_NS.swap(0, Ordering::Relaxed);
        let recon = if wire > 0 { wire } else { recon_total };
        (
            recon,
            wire,
            CONNECT_NS.swap(0, Ordering::Relaxed),
            SCRIPT_NS.swap(0, Ordering::Relaxed),
            CLASS_C_NS.swap(0, Ordering::Relaxed),
            strong,
            sh,
            tip,
            UTXO_APPLY_NS.swap(0, Ordering::Relaxed),
            BLOCKS.swap(0, Ordering::Relaxed),
            RESOLVE_NS.swap(0, Ordering::Relaxed),
            LOAD_NS.swap(0, Ordering::Relaxed),
            UNPIN_NS.swap(0, Ordering::Relaxed),
            CACHE_TIP_NS.swap(0, Ordering::Relaxed),
            SPEND_ANNOTATE_RANGED.swap(0, Ordering::Relaxed),
            SPEND_ANNOTATE_IDX.swap(0, Ordering::Relaxed),
            SPEND_ANNOTATE_SKIP.swap(0, Ordering::Relaxed),
            STRUCTURAL_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_SPENT_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_CREATE_H_NS.swap(0, Ordering::Relaxed),
            STRUCTURAL_BIP68_NS.swap(0, Ordering::Relaxed),
        )
    }

    /// `(jobs, mempool_skips)`.
    #[inline]
    pub fn sample_script_mix_and_reset() -> (u64, u64) {
        (
            SCRIPT_JOBS.swap(0, Ordering::Relaxed),
            SCRIPT_SKIP_MEMPOOL.swap(0, Ordering::Relaxed),
        )
    }

    /// Pure-write annotate: (ann_ns, ann_n, pread_skip, pread).
    #[inline]
    pub fn sample_spend_ann_and_reset() -> (u64, u64, u64, u64) {
        (
            SPEND_ANN_NS.swap(0, Ordering::Relaxed),
            SPEND_ANN_N.swap(0, Ordering::Relaxed),
            SPEND_ANN_PREAD_SKIP.swap(0, Ordering::Relaxed),
            SPEND_ANN_PREAD.swap(0, Ordering::Relaxed),
        )
    }

    /// Structural meta: (meta_ns, meta_n).
    #[inline]
    pub fn sample_spend_meta_and_reset() -> (u64, u64) {
        (
            SPEND_META_NS.swap(0, Ordering::Relaxed),
            SPEND_META_N.swap(0, Ordering::Relaxed),
        )
    }
}

/// Confirm a contiguous tip-extension run of wire blocks (sync all stages).
///
/// See [`confirm_wire_run`]: lookup → load → scripts → write. IBD uses the split
/// phases for pipeline overlap.
pub use confirm_run::{
    confirm_bq_resolve_wave, confirm_bq_resolve_wave_capped, confirm_bq_resolve_wave_with_ids,
    confirm_scripts_feed_ahead, confirm_scripts_phase, confirm_scripts_phase_async,
    confirm_wire_load_from_plan, confirm_wire_load_phase, confirm_wire_load_phase_pipelined,
    confirm_wire_lookup_stamp, confirm_wire_run, confirm_wire_run_preverified, confirm_write_phase,
    drive_script_waves, drive_script_waves_with, join_scripts_polling, lookup_stage_stats,
    plan_stamp_sub_stats, scripts_stage_from_load_channel, take_wave_items_for_load, BqResolveWave,
    BqResolveWaveStats, ConfirmLoadOutcome, ConfirmScriptOutcome, DenserelsWarmStats, LoadedBatch,
    PlanStampOutcome, ScriptOkBatch, ScriptPreverified, ScriptsBatchMeta, ScriptsPhaseHandle,
    WireLoadPipeline, BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
    BQ_RESOLVE_WAVE_MIN_INPUTS,
};

/// Wake the IBD scripts publisher (`ibd-confirm`) after `scriptq` send or close.
pub use script_pool::unpark_script_publisher;

/// Accept + archive + confirm in one step (genesis / tip extension / tests).
///
/// **Same path as IBD confirm:** structure + header checks, then Class A
/// archive, then [`confirm_wire_run`] (lookup → load pin denserels → scripts →
/// structural → Class C → abs spend annotate). No empty-pin
/// [`validate_block_connect`] and no separate `put_spend_batch_by_create`.
///
/// Idempotent when `height` is already confirmed for this block hash.
/// Full script verify (no mempool skip) — use
/// [`accept_and_connect_block_preverified`] on tip follow with a live mempool.
pub fn accept_and_connect_block(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
) -> Result<rbitcoin_primitives::Fk, ConsensusError> {
    accept_and_connect_block_preverified(
        query,
        params,
        height,
        block,
        milestone,
        &ScriptPreverified::new(),
    )
}

/// Like [`accept_and_connect_block`], skipping script verify for `preverified`
/// txids (tip follow: live mempool after accept). Reorg disconnect stays outside.
pub fn accept_and_connect_block_preverified(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
    preverified: &ScriptPreverified,
) -> Result<rbitcoin_primitives::Fk, ConsensusError> {
    let hash = block.block_hash().to_byte_array();
    if let Some(h) = query.height_of_hash(&hash).map_err(ConsensusError::from)? {
        if h == height {
            if let Some((fk, _)) = query
                .get_header_by_hash(&hash)
                .map_err(ConsensusError::from)?
            {
                return Ok(fk);
            }
        }
    }

    // Unified height-ordered path: wire → lookup → load (pin+assemble) → scripts →
    // write (Class A + structural + Class C + annotate). No archive-then-reload.
    let fks = confirm_wire_run_preverified(
        query,
        params,
        milestone,
        &[(height, block.clone())],
        preverified,
    )?;
    if let Some(fk) = fks.into_iter().next() {
        return Ok(fk);
    }
    // Write skipped heights ≤ tip (idempotent race). A body we just ran
    // through lookup/load must have a header — missing is an invariant, not
    // a soft NotFound (inflated confirmed[] used to hit this on tip+1).
    query
        .get_header_by_hash(&hash)
        .map_err(ConsensusError::from)?
        .map(|(fk, _)| fk)
        .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: confirm write skipped but header missing",
        )))
}

/// Class A only (no tip / Class C). Crash and `plan=None` tests.
///
/// Not a production IBD API — confirm write uses `archive_plan_batch` + commit.
pub fn commit_class_a_block(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
) -> Result<(), ConsensusError> {
    let _ = (height, milestone);
    let (header_rec, txs) = prepare_block_for_archive(query, params, block)?;
    query
        .commit_class_a_only(&header_rec, &txs)
        .map_err(ConsensusError::from)?;
    Ok(())
}

/// Class A for a contiguous run in one plan (same-batch parent stamp).
///
/// Use this instead of N×[`commit_class_a_block`] when later blocks spend
/// earlier unconfirmed creates.
pub fn commit_class_a_run(
    query: &Query,
    params: &ChainParams,
    blocks: &[(Height, Block)],
    milestone: Milestone,
) -> Result<(), ConsensusError> {
    let _ = milestone;
    let mut items = Vec::with_capacity(blocks.len());
    for (_, block) in blocks {
        let (header, txs) = prepare_block_for_archive(query, params, block)?;
        query.ensure_header(&header).map_err(ConsensusError::from)?;
        items.push((header, txs));
    }
    query
        .commit_class_a_batch(&mut items)
        .map_err(ConsensusError::from)?;
    Ok(())
}

/// CPU-side prep for Class A archive.
pub fn prepare_block_for_archive(
    query: &Query,
    params: &ChainParams,
    block: &Block,
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    let hash = block.block_hash().to_byte_array();
    if query
        .is_block_archived(&hash)
        .map_err(ConsensusError::from)?
    {
        // Standalone archive helper (not confirm pipeline): one hash pass here.
        return block_to_apply(query, &block.header, &block.txdata);
    }
    prepare_block_for_archive_new(query, params, block)
}

pub fn prepare_block_for_archive_new(
    query: &Query,
    params: &ChainParams,
    block: &Block,
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    // Height-gated soft forks (BIP34 / pre-segwit witness ban) deferred to confirm.
    let ctx = ValidationContext::archive_structure(params);
    let txids = validate_block_structure_hashed(block, &ctx)?;
    let target = Target::from_compact(block.header.bits);
    if target > params.pow_limit {
        return Err(ConsensusError::BadHeader("target above pow limit"));
    }
    block
        .header
        .validate_pow(target)
        .map_err(|_| ConsensusError::InvalidPow)?;
    let prev = block.header.prev_blockhash;
    if prev.to_byte_array() != [0u8; 32]
        && query
            .get_header_by_hash(prev.as_byte_array())
            .map_err(ConsensusError::from)?
            .is_none()
    {
        return Err(ConsensusError::BadPrev);
    }
    block_to_apply_with_txids(query, &block.header, &block.txdata, &txids)
}

/// Confirm wire plan: encode `TxApply` from **already-computed** structure txids.
///
/// Callers that already ran [`validate_block_structure_hashed`] must use this so
/// the confirm pipeline hashes each create **exactly once**.
pub fn prepare_block_for_archive_with_txids(
    query: &Query,
    block: &Block,
    txids: &[[u8; 32]],
) -> Result<(HeaderRecord, Vec<TxApply>), ConsensusError> {
    if block.txdata.len() != txids.len() {
        return Err(ConsensusError::BadBlock("txid count mismatch"));
    }
    block_to_apply_with_txids(query, &block.header, &block.txdata, txids)
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use rbitcoin_primitives::Height;
    use rbitcoin_query::Query;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Once;

    static HEAD_SCALE: Once = Once::new();

    fn ensure_tiny_heads() {
        HEAD_SCALE.call_once(|| {
            if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
                // SAFETY: tests only; process-local config.
                std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
            }
        });
    }

    fn temp_store() -> (PathBuf, Query) {
        ensure_tiny_heads();
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-consensus-cov-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let q = Query::open_or_create(&path).expect("open store");
        (path, q)
    }

    fn mine_regtest(prev: BlockHash, time: u32, height: u32, extras: Vec<Transaction>) -> Block {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            bip34_height_script(height)
        };
        while ss.len() < 2 {
            ss.push(0x00);
        }
        let mut txdata = vec![Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }];
        txdata.extend(extras);
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    }

    #[test]
    fn last_write_phase_stats() {
        use confirm_phase_stats::*;
        note_last_write(LastWritePhases {
            n_blocks: 2,
            wall_ns: 3_000_000,
            class_a_ns: 500_000,
            ensure_ns: 50_000,
            structural_ns: 1_000_000,
            spent_ns: 100_000,
            create_h_ns: 200_000,
            bip68_ns: 50_000,
            class_c_ns: 400_000,
            spend_ann_ns: 300_000,
            tip_gc_ns: 10_000,
            tweak_ns: 2_500_000,
        });
        let p = last_write_phases();
        assert_eq!(p.n_blocks, 2);
        assert_eq!(LastWritePhases::ms(p.wall_ns), 3);
        assert_eq!(LastWritePhases::ms(p.class_a_ns), 0); // 500_000 ns → 0 ms
        assert_eq!(p.class_a_ns, 500_000);
        assert_eq!(p.tweak_ns, 2_500_000);
        assert_eq!(LastWritePhases::ms(p.tweak_ns), 2);
        TWEAK_NS.store(42, Ordering::Relaxed);
        assert_eq!(sample_tweak_and_reset(), 42);
        assert_eq!(sample_tweak_and_reset(), 0);
        WRITE_PLAN_TAKE_NS.store(11, Ordering::Relaxed);
        WRITE_CREATE_MAP_NS.store(22, Ordering::Relaxed);
        WRITE_HEAD_SUB_NS.store(33, Ordering::Relaxed);
        assert_eq!(sample_write_pins_and_reset(), (11, 22, 33));
        assert_eq!(sample_write_pins_and_reset(), (0, 0, 0));
        RECONSTRUCT_NS.store(5, Ordering::Relaxed);
        RECONSTRUCT_WIRE_NS.store(7, Ordering::Relaxed);
        CONNECT_NS.store(1, Ordering::Relaxed);
        SCRIPT_NS.store(1, Ordering::Relaxed);
        CLASS_C_NS.store(1, Ordering::Relaxed);
        CLASS_A_NS.store(9, Ordering::Relaxed);
        ENSURE_LAYOUT_NS.store(11, Ordering::Relaxed);
        UTXO_APPLY_NS.store(1, Ordering::Relaxed);
        BLOCKS.store(1, Ordering::Relaxed);
        RESOLVE_NS.store(1, Ordering::Relaxed);
        LOAD_NS.store(1, Ordering::Relaxed);
        UNPIN_NS.store(1, Ordering::Relaxed);
        CACHE_TIP_NS.store(1, Ordering::Relaxed);
        SPEND_ANNOTATE_RANGED.store(1, Ordering::Relaxed);
        SPEND_ANNOTATE_IDX.store(1, Ordering::Relaxed);
        SPEND_ANNOTATE_SKIP.store(1, Ordering::Relaxed);
        STRUCTURAL_NS.store(1, Ordering::Relaxed);
        STRUCTURAL_SPENT_NS.store(1, Ordering::Relaxed);
        STRUCTURAL_CREATE_H_NS.store(1, Ordering::Relaxed);
        STRUCTURAL_BIP68_NS.store(1, Ordering::Relaxed);
        let s = sample_and_reset();
        assert_eq!(s.0, 7); // wire preferred over recon total
        assert_eq!(s.1, 7);
        let (ca, en) = sample_class_a_ensure_and_reset();
        assert_eq!((ca, en), (9, 11));
        // Drain prep residual (other tests may have accrued), then set known values.
        let _ = sample_prep_residual_and_reset();
        let _ = sample_assemble_and_reset();
        let _ = sample_ensure_mix_and_reset();
        PREP_WIRE_ARC_NS.store(3, Ordering::Relaxed);
        PREP_STRUCT_NS.store(4, Ordering::Relaxed);
        PREP_HEADER_NS.store(5, Ordering::Relaxed);
        PREP_PREPARE_NS.store(6, Ordering::Relaxed);
        PREP_FILTER_PLAN_NS.store(7, Ordering::Relaxed);
        assert_eq!(sample_prep_residual_and_reset(), (3, 4, 5, 6, 7));
        ASM_PREVOUT_NS.store(10, Ordering::Relaxed);
        ASM_SIGOP_NS.store(20, Ordering::Relaxed);
        ASM_FINAL_NS.store(30, Ordering::Relaxed);
        ASM_JOB_NS.store(40, Ordering::Relaxed);
        assert_eq!(sample_assemble_and_reset(), (10, 20, 30, 40));
        // I3 assemble prevout path detail.
        let _ = sample_assemble_prevout_detail_and_reset();
        ASM_IN_N.store(100, Ordering::Relaxed);
        ASM_PREV_BATCH_NS.store(1000, Ordering::Relaxed);
        ASM_PREV_BATCH_N.store(80, Ordering::Relaxed);
        ASM_PREV_SAME_NS.store(50, Ordering::Relaxed);
        ASM_PREV_SAME_N.store(5, Ordering::Relaxed);
        ASM_PREV_COLD_NS.store(300, Ordering::Relaxed);
        ASM_PREV_COLD_N.store(5, Ordering::Relaxed);
        ASM_PREV_FK_NS.store(40, Ordering::Relaxed);
        assert_eq!(
            sample_assemble_prevout_detail_and_reset(),
            (100, 1000, 80, 50, 5, 300, 5, 40)
        );
        let _ = sample_assemble_cold_why_and_reset();
        ASM_PREV_COLD_NULL_FK_N.store(1, Ordering::Relaxed);
        ASM_PREV_COLD_NOT_PIN_N.store(2, Ordering::Relaxed);
        ASM_PREV_COLD_TXID_MISMATCH_N.store(3, Ordering::Relaxed);
        ASM_PREV_COLD_VOUT_MISS_N.store(4, Ordering::Relaxed);
        assert_eq!(sample_assemble_cold_why_and_reset(), (1, 2, 3, 4));
        ENSURE_RES_HIT.store(8, Ordering::Relaxed);
        ENSURE_COLD_N.store(9, Ordering::Relaxed);
        assert_eq!(sample_ensure_mix_and_reset(), (8, 9));
        // Drain again; do **not** require zeros — other parallel `#[test]`s may
        // `note_*` into the same process-global atomics between samples.
        let _ = sample_and_reset();
        let _ = sample_class_a_ensure_and_reset();
        let _ = sample_prep_residual_and_reset();
        let _ = sample_assemble_and_reset();
        let _ = sample_assemble_prevout_detail_and_reset();
        let _ = sample_assemble_cold_why_and_reset();
        let _ = sample_ensure_mix_and_reset();
        let _ = sample_spend_ann_and_reset();
        let _ = sample_spend_meta_and_reset();
    }

    #[test]
    fn verify_tx_scripts_detached_acs_job() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }];
        crate::verify_tx_scripts_detached(prevouts.clone(), tx.clone()).unwrap();
        let job = ScriptCheckJob::new(prevouts, tx, true, true, true, true, true);
        crate::block::verify_scripts_pool(&[job]).unwrap();
    }

    #[test]
    fn regtest_connect_archive_and_confirm_path() {
        let (path, q) = temp_store();
        let params = ChainParams::regtest();
        let ms = Milestone { height: 1_000_000 };
        let genesis = genesis_block(&params);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();

        let b1 = mine_regtest(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        // prepare helpers stay (CPU-side); confirm is sole Class A.
        let (_hr, _txs) = prepare_block_for_archive(&q, &params, &b1).unwrap();
        let (_hr2, _txs2) = prepare_block_for_archive_new(&q, &params, &b1).unwrap();
        accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
        // already-have prepare after connect
        let _ = prepare_block_for_archive(&q, &params, &b1).unwrap();

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn assemble_second_block_rejects_stale_nversion() {
        let (path, q) = temp_store();
        let params = ChainParams::regtest();
        let ms = Milestone { height: 1_000_000 };
        let genesis = genesis_block(&params);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();

        let b1 = mine_regtest(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        let mut b2 = mine_regtest(b1.block_hash(), b1.header.time + 600, 2, vec![]);
        b2.header.version = Version::from_consensus(1);
        let target = Target::from_compact(b2.header.bits);
        for nonce in 0..u32::MAX {
            b2.header.nonce = nonce;
            if b2.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let err =
            confirm_wire_run(&q, &params, ms, &[(Height(1), b1), (Height(2), b2)]).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
        let _ = std::fs::remove_dir_all(&path);
    }
}
