//! Multi-block confirm orchestrator (IBD / tip Class C path).
//!
//! **Primary height-ordered pipeline** (raw wire → validated tip):
//! ```text
//! LOOKUP STAGE (ibd-confirm-lookup OS thread):
//!   wire Block → structure → stamp create_fk (Class A planned only)
//! LOAD STAGE (ibd-confirm-load OS thread):
//!   pin denserels once → assemble (uses intake wire; **no Class-A wire rebuild**)
//! SCRIPTS STAGE (`ibd-confirm` OS thread publishes waves; `rbtc-scripts-*` steal):
//!   pure CPU verify — no Query, no disk. No coordinator threads.
//! WRITE STAGE (ibd-confirm-write OS thread, FIFO):
//!   Class A commit (if plan) + structural + class_c + spend annotate + tip GC.
//!   `tx.head` write-behind drain runs on process-wide `ibd-confirm-head`
//!   (overlap with structural + Class C; not a per-batch spawn).
//! ```
//! IBD pipelines lookup(N+1) ∥ load(N) ∥ scripts(N−1) ∥ write(N−2). One Class A appender.
//!
//! [`confirm_wire_run`] is the unified entry (tests / tip / IBD).
//!
//! **Scripts purity:** [`confirm_scripts_phase`] is pure
//! [`LoadedBatch`] → [`ScriptOkBatch`]. IBD [`drive_script_waves_with`] publishes
//! multiple waves from the stage thread when steal is empty, then writes in
//! height order. Steal workers unpark the publisher when a wave completes.

use crate::block::{
    assemble_block_prevouts, block_has_witness, structural_validate_spends, ScriptCheckJob,
    ValidationContext,
};
use crate::error::ConsensusError;
use crate::header::{
    check_header_version_and_future_time, median_time_past_times, validate_header,
};
use crate::milestone::Milestone;
use crate::params::{genesis_block, ChainParams};
use bitcoin::hashes::Hash;
use bitcoin::{Block, Target};
use rbitcoin_primitives::Height;
use rbitcoin_query::{FkMap, Query, U32Map, U64Map, U64Set};
use rbitcoin_store::{StoreError, WriteIoBackend};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

mod bq_resolve;
mod head_drain;
mod lookup;
mod phases;
mod pin;
mod scripts;
mod write;

pub use bq_resolve::{
    confirm_bq_resolve_wave_capped, take_wave_items_for_load, BQ_RESOLVE_WAVE_MAX_BLOCKS,
    BQ_RESOLVE_WAVE_MAX_INPUTS,
};
#[cfg(test)]
use head_drain::{submit_head_drain, submit_head_insert, HEAD_DRAIN_THREAD_NAME};
#[cfg(test)]
use lookup::confirm_archive_kind;
use lookup::known_create_txid_lookup;
#[cfg(test)]
use lookup::ConfirmArchiveKind;
pub use lookup::{
    confirm_wire_load_from_plan, confirm_wire_lookup_stamp, ParentPinStamp, PlanStampOutcome,
};
use phases::assemble_run;
#[cfg(test)]
use phases::{check_bip34, expected_bits_extending, post_commit};
use pin::{ensure_spend_abs_layouts, pin_for_wire_batch};
pub use scripts::{confirm_scripts_phase, drive_script_waves_with};
pub use write::confirm_write_phase;
#[cfg(test)]
use write::{write_batch_vs_tip, write_height_needed, WriteBatchVsTip};

/// Pure-write annotate backend from global `RBITCOIN_IO`.
#[inline]
fn spend_ann_backend_next() -> WriteIoBackend {
    rbitcoin_store::spend_ann_backend()
}

/// One height resolved for the confirm wave (header + Class A body fks).
struct BodyMeta {
    height: Height,
    hash: [u8; 32],
    header_fk: rbitcoin_primitives::Fk,
    header_rec: rbitcoin_store::HeaderRecord,
    tx_fks: Vec<rbitcoin_primitives::Fk>,
    /// Create txids for this block — **exactly one** `compute_txid` per entry
    /// at structure/entry (plan or archived load). Assemble must use these only.
    txids: Vec<[u8; 32]>,
    /// Same walk as `txids` (lookup/structure). Script jobs reuse these.
    pres: std::sync::Arc<[rbitcoin_query::TxPrecompute]>,
}

/// Assemble output for one height (held through scripts → write).
struct Prepared {
    height: Height,
    header_fk: rbitcoin_primitives::Fk,
    tx_fks: Vec<rbitcoin_primitives::Fk>,
    jobs: Vec<ScriptCheckJob>,
    /// `(prev_txid, vout, spending_tx_fk, create_tx_fk)` — create_fk for Direct
    /// spend annotate without `tx.head`.
    spends: Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
    )>,
    /// Total fees from assemble (for structural coinbase subsidy check).
    fees: i64,
    check_scripts: bool,
    time: u32,
    bits: bitcoin::CompactTarget,
    /// Header hash of this block (prev-link for the next height in the run).
    hash: [u8; 32],
    /// Prev-block MTP from assemble (`mtp_at(height-1)`). Write BIP68 uses this
    /// instead of `ConfirmParentCache::get_header_plan`.
    prev_mtp: u32,
}

/// Txids already consensus-script-verified under tip-era softforks (live mempool
/// after accept). Empty = verify all jobs (IBD). Passed through load → scripts only.
pub type ScriptPreverified = std::collections::HashSet<[u8; 32]>;

/// Pipeline context so lookup(N+1) can run while write(N) has not advanced tip.
///
/// Load thread owns reserved create-fk HWM and the in-flight map from
/// batches sitting in load→scripts→write queues. Write remains sole Class A
/// appender and applies batches in height order.
#[derive(Clone, Debug)]
pub struct WireLoadPipeline<'a> {
    /// Expected first height of this batch (store tip+1, or last loaded + 1).
    pub path_lo: u32,
    /// Parent of `path_lo` when ahead of store tip (last wire hash of prior loaded batch).
    pub parent_hash: Option<[u8; 32]>,
    /// Inclusive create-fk start for [`Query::archive_plan_batch_from_wire`].
    pub next_tx_start: u64,
    /// Prior uncommitted packs (load-thread map; stamp/pin borrow).
    pub in_flight: &'a rbitcoin_query::InFlight,
    /// Lookup-filled parent identity for this load batch (IBD skeleton).
    pub skeleton: Option<rbitcoin_query::BatchParentIds>,
}

/// Wire + assemble complete; script jobs still attached (not yet verified).
///
/// `Send` so IBD can hand off load → scripts threads.
/// Sparse spent-filtered parents ride on the batch (not tip-GCed).
/// When [`archive_plan`] is `Some`, commit stage appends Class A before
/// structural / annotate (single ordered commit era).
pub struct LoadedBatch {
    prepared: Vec<Prepared>,
    /// Shared wire (Arc) so load→scripts→write does not deep-clone full blocks.
    wire_blocks: Vec<Arc<Block>>,
    /// Per-batch pin map: load → assemble → write structural, then drop.
    batch_parents: rbitcoin_query::BatchParents,
    /// Mempool preverified txids for scripts stage (tip follow); empty on IBD.
    script_preverified: ScriptPreverified,
    /// Planned Class A write from wire lookup/load (committed in write stage).
    pub archive_plan: Option<rbitcoin_query::ArchiveWritePlan>,
    stats: Arc<rbitcoin_query::ConfirmStats>,
}

/// Script-verified batch ready for ordered commit (Class A + structural + C).
///
/// `Send` so IBD can hand off scripts → write.
pub struct ScriptOkBatch {
    prepared: Vec<Prepared>,
    wire_blocks: Vec<Arc<Block>>,
    batch_parents: rbitcoin_query::BatchParents,
    pub archive_plan: Option<rbitcoin_query::ArchiveWritePlan>,
}

/// Outcome of load: batch ready for scripts + pure work wall.
pub struct ConfirmLoadOutcome {
    pub batch: LoadedBatch,
    /// Full load wall (Class A + parent pin + resolve → assemble).
    pub work_ns: u64,
}

/// Outcome of the scripts stage: ready batch + pure script wall.
pub struct ConfirmScriptOutcome {
    pub batch: ScriptOkBatch,
    /// Script verify only (when produced by [`confirm_scripts_phase`]).
    pub work_ns: u64,
}

/// LOAD STAGE from **raw wire blocks** (unified height-ordered pipeline).
///
/// One-shot path (tests / tip-follow) runs lookup+load together:
/// - Structure / PoW checks, ensure headers
/// - Stamp Class A create fks **without** committing
/// - Pin external parents once (denserels); same-batch from plan
/// - Assemble using **intake wire** (no Class-A wire rebuild)
///
/// The plan rides on [`LoadedBatch::archive_plan`] and is committed in write.
///
/// `pipeline`: when `Some`, first height may be ahead of store tip (lookup(N+1)
/// while write(N) in flight). Use reserved create-fk HWM + in-flight creates.
pub fn confirm_wire_load_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
    preverified: &ScriptPreverified,
) -> Result<ConfirmLoadOutcome, ConsensusError> {
    confirm_wire_load_phase_pipelined(query, params, milestone, blocks, preverified, None)
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
fn wire_blocks_to_arcs(
    query: &Query,
    blocks: &[(Height, Block)],
) -> Vec<(
    Height,
    Arc<Block>,
    Option<Arc<[rbitcoin_query::TxPrecompute]>>,
)> {
    let t = Instant::now();
    let arcs = blocks
        .iter()
        .map(|(h, b)| {
            let pres = query.block_queue_resolved(h.0).map(|w| Arc::clone(&w.pres));
            (*h, Arc::new(b.clone()), pres)
        })
        .collect();
    let ns = t.elapsed().as_nanos() as u64;
    if ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_wire_arc_ns, ns);
    }
    arcs
}

/// Like [`confirm_wire_load_phase`] with optional pipeline caches for load-ahead.
///
/// One-shot load is stamp + [`confirm_wire_load_from_plan`] (same as IBD after
/// BQ TipOnly). `Arc` conversion is timed as `PREP_WIRE_ARC_NS`.
pub fn confirm_wire_load_phase_pipelined(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
    preverified: &ScriptPreverified,
    pipeline: Option<&WireLoadPipeline>,
) -> Result<ConfirmLoadOutcome, ConsensusError> {
    if blocks.is_empty() {
        return Err(ConsensusError::BadBlock("empty confirm batch"));
    }
    for w in blocks.windows(2) {
        if w[1].0 .0 != w[0].0 .0.saturating_add(1) {
            return Err(ConsensusError::BadBlock("confirm run not contiguous"));
        }
    }
    let arcs = wire_blocks_to_arcs(query, blocks);
    let stamped = confirm_wire_lookup_stamp(query, params, milestone, &arcs, pipeline)?;
    confirm_wire_load_from_plan(query, params, milestone, stamped, pipeline, preverified)
}

/// Unified wire → tip (lookup+load + scripts + write). Primary production entry.
pub fn confirm_wire_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    confirm_wire_run_preverified(query, params, milestone, blocks, &ScriptPreverified::new())
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Like [`confirm_wire_run`] with mempool script preverified set.
///
/// **Tip-follow / one-shot:** lookup stamp (create_fk + parent body ranges;
/// never `tx.body`) → load pin denserels by range → scripts → write.
///
/// Parent create_fk + body_range + identity are **lookup promises**. Load only
/// reads `tx.body` denserels. Soft spentness recovery for wrong pin identity
/// is not a substitute for a correct lookup/load.
pub fn confirm_wire_run_preverified(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
    preverified: &ScriptPreverified,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    if blocks.is_empty() {
        return Err(ConsensusError::BadBlock("empty confirm batch"));
    }
    let arcs: Vec<(
        Height,
        Arc<Block>,
        Option<Arc<[rbitcoin_query::TxPrecompute]>>,
    )> = {
        let t = Instant::now();
        let arcs = blocks
            .iter()
            .map(|(h, b)| (*h, Arc::new(b.clone()), None))
            .collect();
        let ns = t.elapsed().as_nanos() as u64;
        if ns > 0 {
            rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_wire_arc_ns, ns);
        }
        arcs
    };
    let stamped = confirm_wire_lookup_stamp(query, params, milestone, &arcs, None)?;
    let mat = confirm_wire_load_from_plan(query, params, milestone, stamped, None, preverified)?;
    let ok = confirm_scripts_phase(mat.batch)?;
    confirm_write_phase(query, params, milestone, ok.batch)
}

impl LoadedBatch {
    /// Heights and header hashes in this batch (for events / feed scrub).
    pub fn heights_hashes(&self) -> Vec<(u32, [u8; 32])> {
        self.prepared.iter().map(|p| (p.height.0, p.hash)).collect()
    }

    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Approx wire bytes retained in `wire_blocks` (for queue-content size logs).
    pub fn approx_wire_bytes(&self) -> usize {
        self.wire_blocks.iter().map(|b| b.total_size()).sum()
    }

    /// Parent handles in this batch (may share payloads with other batches).
    pub fn parent_count(&self) -> usize {
        self.batch_parents.len()
    }
}

impl ScriptOkBatch {
    /// Heights and header hashes in this batch (for events / feed scrub).
    pub fn heights_hashes(&self) -> Vec<(u32, [u8; 32])> {
        self.prepared.iter().map(|p| (p.height.0, p.hash)).collect()
    }

    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Approx wire bytes retained in `wire_blocks` (for queue-content size logs).
    pub fn approx_wire_bytes(&self) -> usize {
        self.wire_blocks.iter().map(|b| b.total_size()).sum()
    }

    /// Parent handles in this batch (may share Arc payloads with other batches).
    pub fn parent_count(&self) -> usize {
        self.batch_parents.len()
    }

    #[allow(clippy::result_large_err)] // public error enum
    /// Absorb another script-ok batch for write batch (FIFO drain).
    ///
    /// Scripts enqueue height-ordered tip extensions; write drains the channel
    /// and merges so Class A + Class C + annotate run once (fewer tip fsyncs).
    /// Returns `Err(other)` if not a contiguous height extension **or** if
    /// `archive_plan` polarity differs (`Some` vs `None`). Caller writes the
    /// prefix then keeps `other` for the next meta-batch.
    pub fn append_contiguous(&mut self, mut other: Self) -> Result<(), Self> {
        if other.is_empty() {
            return Ok(());
        }
        if self.is_empty() {
            *self = other;
            return Ok(());
        }
        let Some(last) = self.prepared.last() else {
            *self = other;
            return Ok(());
        };
        let Some(first) = other.prepared.first() else {
            return Ok(());
        };
        if first.height.0 != last.height.0.saturating_add(1) {
            return Err(other);
        }
        if self.prepared.len() != self.wire_blocks.len()
            || other.prepared.len() != other.wire_blocks.len()
        {
            return Err(other);
        }
        if self.archive_plan.is_some() != other.archive_plan.is_some() {
            return Err(other);
        }
        self.prepared.append(&mut other.prepared);
        self.wire_blocks.append(&mut other.wire_blocks);
        self.batch_parents.extend_from(other.batch_parents);
        if let (Some(dst), Some(src)) = (self.archive_plan.as_mut(), other.archive_plan.take()) {
            dst.append(src);
        }
        Ok(())
    }
}

#[cfg(test)]
mod write_idempotent_tests;
