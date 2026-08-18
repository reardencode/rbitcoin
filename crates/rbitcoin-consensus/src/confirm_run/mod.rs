//! Multi-block confirm orchestrator (IBD / tip Class C path).
//!
//! **Primary height-ordered pipeline** (raw wire → validated tip):
//! ```text
//! LOOKUP STAGE (ibd-confirm-lookup OS thread):
//!   wire Block → structure → stamp create_fk (Class A planned only)
//! LOAD STAGE (ibd-confirm-load OS thread):
//!   pin denserels once → assemble (uses intake wire; **no Class-A wire rebuild**)
//! SCRIPTS STAGE (ibd-confirm OS thread + script coordinators):
//!   pure CPU verify — no Query, no disk
//! WRITE STAGE (ibd-confirm-write OS thread, FIFO):
//!   Class A commit (if plan) + structural + class_c + spend annotate + tip GC
//! ```
//! IBD pipelines lookup(N+1) ∥ load(N) ∥ scripts(N−1) ∥ write(N−2). One Class A appender.
//!
//! [`confirm_wire_run`] is the unified entry (tests / tip / IBD).
//!
//! **Scripts purity:** [`confirm_scripts_phase`] is pure
//! [`LoadedBatch`] → [`ScriptOkBatch`]. IBD uses
//! [`confirm_scripts_phase_async`] / [`confirm_scripts_feed_ahead`] so the
//! script coordinators stay fed across batch boundaries (one-batch lookahead).

use crate::block::{
    assemble_block_prevouts, bip34_height_script, block_has_witness, structural_validate_spends,
    ScriptCheckJob, ValidationContext,
};
use crate::confirm_phase_stats;
use crate::error::ConsensusError;
use crate::header::{median_time_past_times, validate_header};
use crate::milestone::Milestone;
use crate::params::{genesis_block, ChainParams};
use bitcoin::hashes::Hash;
use bitcoin::{Block, Target};
use rbitcoin_primitives::Height;
use rbitcoin_query::{FkMap, Query, U32Map, U64Map, U64Set};
use rbitcoin_store::{SpendAnnBackend, StoreError};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

mod bq_resolve;
mod lookup;
mod phases;
mod pin;
mod scripts;
mod write;

pub use bq_resolve::{
    confirm_bq_resolve_wave, confirm_bq_resolve_wave_with_ids, BqResolveWaveStats,
    BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
};
pub use lookup::lookup_stage_stats;
pub use lookup::plan_stamp_sub_stats;
pub use lookup::{
    confirm_wire_load_from_plan, confirm_wire_lookup_stamp, DenserelsWarmStats, ParentPinStamp,
    PlanStampOutcome,
};
use lookup::{create_fks_from_header_ranges, known_create_txid_lookup, stamp_parent_pin_archived};
use phases::{assemble_run, script_wave};
#[cfg(test)]
use phases::{check_bip34, expected_bits_extending, post_commit};
use pin::{ensure_spend_abs_layouts, pin_for_wire_batch};
pub use scripts::scripts_feed_test_sync;
pub use scripts::{
    confirm_scripts_feed_ahead, confirm_scripts_phase, confirm_scripts_phase_async,
    join_scripts_polling, scripts_stage_from_load_channel, ScriptsBatchMeta, ScriptsPhaseHandle,
};
pub use write::confirm_write_phase;
#[cfg(test)]
use write::write_height_needed;

/// Pure-write annotate backend from global `RBITCOIN_IO`.
#[inline]
fn spend_ann_backend_next() -> SpendAnnBackend {
    rbitcoin_store::spend_annotate_uring::spend_ann_backend()
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
/// Lookup thread owns reserved create-fk HWM and in-flight creates/outs from
/// batches sitting in load→scripts→write queues. Write remains sole Class A
/// appender and applies batches in height order.
#[derive(Clone, Debug, Default)]
pub struct WireLoadPipeline {
    /// Expected first height of this batch (store tip+1, or last loaded + 1).
    pub path_lo: u32,
    /// Parent of `path_lo` when ahead of store tip (last wire hash of prior loaded batch).
    pub parent_hash: Option<[u8; 32]>,
    /// Inclusive create-fk start for [`Query::archive_plan_batch_from`].
    pub next_tx_start: u64,
    /// Prior uncommitted packs: immutable layer snapshot (no shared mutable map).
    ///
    /// Load looks up create fk / full CreatePin for parents still only in the
    /// pipeline (body-ahead-of-head). Built via [`rbitcoin_query::InFlightLog::snapshot`].
    pub in_flight: rbitcoin_query::InFlightView,
    /// Pipeline-wide sparse parent pin store (Weak map; load get-or-insert only).
    /// Batches hold `Arc` handles so concurrent stages share one payload per create.
    pub parent_store: std::sync::Arc<rbitcoin_query::PipelineParentStore>,
    /// Lookup-published parent identity union (wave hits still live in the BQ window).
    pub published: std::sync::Arc<rbitcoin_query::PublishedIds>,
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

/// Like [`confirm_wire_load_phase`] with optional pipeline caches for load-ahead.
///
/// Single pin path: denserels by body range from lookup stamp (no cold dual path).
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

    let t_work = Instant::now();
    let t_load = Instant::now();
    let mut ns_wire_arc = 0u64;
    let mut ns_struct = 0u64;
    let mut ns_header = 0u64;
    let mut ns_prepare = 0u64;

    let mut with_fk: Vec<(
        rbitcoin_primitives::Fk,
        rbitcoin_store::HeaderRecord,
        Vec<rbitcoin_query::TxApply>,
    )> = Vec::with_capacity(blocks.len());
    let mut wire_blocks: Vec<Arc<Block>> = Vec::with_capacity(blocks.len());
    let mut metas: Vec<BodyMeta> = Vec::with_capacity(blocks.len());

    let tip_h = query.tip_height().map(|h| h.0);
    let store_path_lo = match tip_h {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let path_lo = pipeline.map(|p| p.path_lo).unwrap_or(store_path_lo);

    for (i, (height, block)) in blocks.iter().enumerate() {
        let t = Instant::now();
        let block = Arc::new(block.clone());
        ns_wire_arc = ns_wire_arc.saturating_add(t.elapsed().as_nanos() as u64);
        let hash = block.block_hash().to_byte_array();
        let ctx = ValidationContext::at(params, *height, milestone);
        let t = Instant::now();
        let stashed = query.block_queue_resolved(height.0);
        let pres = crate::block::validate_block_structure_with_pres(
            block.as_ref(),
            &ctx,
            stashed.as_ref().map(|w| w.pres.as_ref()),
        )?;
        let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
        ns_struct = ns_struct.saturating_add(t.elapsed().as_nanos() as u64);
        // Later heights in the same batch validate against prior wire, not store tip.
        let t = Instant::now();
        if i == 0 {
            if height.0 != path_lo {
                return Err(ConsensusError::BadPrev);
            }
            if path_lo == store_path_lo {
                validate_header(query, params, *height, &block.header)?;
            } else {
                let expect_prev = pipeline.and_then(|p| p.parent_hash).unwrap_or([0u8; 32]);
                if block.header.prev_blockhash.to_byte_array() != expect_prev {
                    return Err(ConsensusError::BadPrev);
                }
                let target = bitcoin::Target::from_compact(block.header.bits);
                if target > params.pow_limit {
                    return Err(ConsensusError::BadHeader("target above pow limit"));
                }
                block
                    .header
                    .validate_pow(target)
                    .map_err(|_| ConsensusError::InvalidPow)?;
            }
        } else {
            // Prev wire hash already stored on metas[i-1] — no rehash.
            let prev_hash = metas[i - 1].hash;
            if block.header.prev_blockhash.to_byte_array() != prev_hash {
                return Err(ConsensusError::BadPrev);
            }
            // PoW bits/target (no store retarget mid-batch for regtest).
            let target = bitcoin::Target::from_compact(block.header.bits);
            if target > params.pow_limit {
                return Err(ConsensusError::BadHeader("target above pow limit"));
            }
            block
                .header
                .validate_pow(target)
                .map_err(|_| ConsensusError::InvalidPow)?;
        }
        ns_header = ns_header.saturating_add(t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        let (header_rec, txs) =
            crate::prepare_block_for_archive_with_txids(query, block.as_ref(), &txids)?;
        ns_prepare = ns_prepare.saturating_add(t.elapsed().as_nanos() as u64);
        let t = Instant::now();
        let header_fk = if let Some((fk, _)) = query
            .get_header_by_hash(&header_rec.hash)
            .map_err(ConsensusError::from)?
        {
            fk
        } else {
            query
                .store()
                .put_header(&header_rec)
                .map_err(ConsensusError::from)?
        };
        let prev_bytes = block.header.prev_blockhash.to_byte_array();
        query.confirm_parent_cache().put_header_plan(
            height.0,
            header_fk,
            header_rec.clone(),
            Vec::new(),
            prev_bytes,
        );
        ns_header = ns_header.saturating_add(t.elapsed().as_nanos() as u64);
        with_fk.push((header_fk, header_rec.clone(), txs));
        wire_blocks.push(block);
        metas.push(BodyMeta {
            height: *height,
            hash,
            header_fk,
            header_rec,
            tx_fks: Vec::new(),
            txids,
            pres: std::sync::Arc::from(pres),
        });
    }

    let t_fp = Instant::now();
    let (_header_fks, mut need) = query
        .archive_filter_need_bodies(&mut with_fk)
        .map_err(ConsensusError::from)?;
    let mut plan = if need.is_empty() {
        for (i, m) in metas.iter_mut().enumerate() {
            if let Some(list) = query
                .store()
                .header_txs
                .get_list(m.header_fk)
                .map_err(ConsensusError::from)?
            {
                m.tx_fks = list;
            }
            // Never rehash wire for lookup — index by batch position.
            let prev = wire_blocks[i].header.prev_blockhash.to_byte_array();
            query.confirm_parent_cache().put_header_plan(
                m.height.0,
                m.header_fk,
                m.header_rec.clone(),
                m.tx_fks.clone(),
                prev,
            );
        }
        None
    } else {
        let plan = match pipeline {
            Some(p) => query
                .archive_plan_batch_from_store(
                    &mut need,
                    p.next_tx_start.max(1),
                    &p.in_flight,
                    Some(p.published.as_ref()),
                )
                .map_err(ConsensusError::from)?,
            None => query
                .archive_plan_batch_from_store(
                    &mut need,
                    query.tx_body_count().saturating_add(1).max(1),
                    &rbitcoin_query::InFlightView::empty(),
                    None,
                )
                .map_err(ConsensusError::from)?,
        };
        let by_header = create_fks_from_header_ranges(&plan.per_header_ranges);
        for (i, m) in metas.iter_mut().enumerate() {
            if let Some(id) = m.header_fk.get() {
                if let Some(fks) = by_header.get(&id) {
                    m.tx_fks = fks.clone();
                }
            }
            if m.tx_fks.is_empty() {
                if let Some(list) = query
                    .store()
                    .header_txs
                    .get_list(m.header_fk)
                    .map_err(ConsensusError::from)?
                {
                    m.tx_fks = list;
                }
            }
            let prev = wire_blocks[i].header.prev_blockhash.to_byte_array();
            query.confirm_parent_cache().put_header_plan(
                m.height.0,
                m.header_fk,
                m.header_rec.clone(),
                m.tx_fks.clone(),
                prev,
            );
        }
        Some(plan)
    };
    let ns_filter_plan = t_fp.elapsed().as_nanos() as u64;

    let inflight = pipeline.map(|p| &p.in_flight);
    let parent_store = pipeline.map(|p| &p.parent_store);
    let parent_pin = match plan.as_mut() {
        Some(p) => ParentPinStamp::take_from_plan(p),
        None => stamp_parent_pin_archived(query, params, &metas, &wire_blocks, inflight)?,
    };
    let (batch_parents, batch_thin, _warm) = pin_for_wire_batch(
        query,
        plan.as_ref(),
        &parent_pin,
        &metas,
        &wire_blocks,
        inflight,
        parent_store,
    )?;
    if let Some(ref mut p) = plan {
        p.freeze_after_pin();
    }

    confirm_phase_stats::LOAD_NS.fetch_add(t_load.elapsed().as_nanos() as u64, Ordering::Relaxed);
    if ns_wire_arc > 0 {
        confirm_phase_stats::PREP_WIRE_ARC_NS.fetch_add(ns_wire_arc, Ordering::Relaxed);
    }
    if ns_struct > 0 {
        confirm_phase_stats::PREP_STRUCT_NS.fetch_add(ns_struct, Ordering::Relaxed);
    }
    if ns_header > 0 {
        confirm_phase_stats::PREP_HEADER_NS.fetch_add(ns_header, Ordering::Relaxed);
    }
    if ns_prepare > 0 {
        confirm_phase_stats::PREP_PREPARE_NS.fetch_add(ns_prepare, Ordering::Relaxed);
    }
    if ns_filter_plan > 0 {
        confirm_phase_stats::PREP_FILTER_PLAN_NS.fetch_add(ns_filter_plan, Ordering::Relaxed);
    }

    let prepared = assemble_run(
        query,
        params,
        milestone,
        metas,
        &wire_blocks,
        &batch_parents,
        &batch_thin,
    )?;
    drop(batch_thin);

    let work_ns = t_work.elapsed().as_nanos() as u64;
    Ok(ConfirmLoadOutcome {
        batch: LoadedBatch {
            prepared,
            wire_blocks,
            batch_parents,
            script_preverified: preverified.clone(),
            archive_plan: plan,
        },
        work_ns,
    })
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
    let arcs: Vec<(Height, Arc<Block>)> = blocks
        .iter()
        .map(|(h, b)| (*h, Arc::new(b.clone())))
        .collect();
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

    /// Absorb another script-ok batch for write batch (FIFO drain).
    ///
    /// Scripts enqueue height-ordered tip extensions; write drains the channel
    /// and merges so Class A + Class C + annotate run once (fewer tip fsyncs).
    /// Returns `Err(other)` if not a contiguous height extension (caller keeps
    /// `other` for the next batch).
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
        self.prepared.append(&mut other.prepared);
        self.wire_blocks.append(&mut other.wire_blocks);
        self.batch_parents.extend_from(other.batch_parents);
        match (self.archive_plan.as_mut(), other.archive_plan.take()) {
            (Some(dst), Some(src)) => dst.append(src),
            (None, Some(src)) => self.archive_plan = Some(src),
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod write_idempotent_tests;
