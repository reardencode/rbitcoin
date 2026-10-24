//! Assemble and spentness for confirm. This module loads rows and calls the
//! consensus rule functions. It does not decide a header, script, or spend
//! rule on its own.
use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::ScriptBuf;
use bitcoin::{Amount, OutPoint, Transaction, TxOut};
use rbitcoin_consensus::block::{
    JobPrevouts, PendingCreates, ScriptCheckJob, ScriptVerifyFlags, TxidMap,
};
use rbitcoin_consensus::ChainParams;
use rbitcoin_primitives::Height;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::time::Instant;

use crate::{ConfirmError, FkMap, Query, U32Map, U64Map};

#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod test_phase {
    use std::cell::Cell;
    thread_local! {
        static TL_COLD_WHY: Cell<(u64, u64, u64, u64)> = const { Cell::new((0, 0, 0, 0)) };
        static TL_BATCH_N: Cell<u64> = const { Cell::new(0) };
        static TL_COLD_N: Cell<u64> = const { Cell::new(0) };
    }
    #[inline]
    pub fn tl_note_cold_why_txid_mismatch() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2 + 1, d));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_cold_why_vout_miss() {
        TL_COLD_WHY.with(|c| {
            let (a, b, c2, d) = c.get();
            c.set((a, b, c2, d + 1));
        });
        TL_COLD_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn tl_note_batch_hit() {
        TL_BATCH_N.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub fn sample_tl_assemble_cold_why_and_reset() -> (u64, u64, u64, u64) {
        TL_COLD_WHY.with(|c| c.replace((0, 0, 0, 0)))
    }
    #[inline]
    pub fn sample_tl_batch_cold_n_and_reset() -> (u64, u64) {
        let batch = TL_BATCH_N.with(|c| c.replace(0));
        let cold = TL_COLD_N.with(|c| c.replace(0));
        (batch, cold)
    }
}

/// Block-local prevout path counts; the confirm pipeline flushes once.
#[derive(Default)]
pub struct AsmPrevoutAcc {
    pub in_n: u64,
    pub same_n: u64,
    pub batch_n: u64,
    pub cold_n: u64,
    pub cold_null_fk_n: u64,
    pub cold_not_pin_n: u64,
    pub cold_txid_mismatch_n: u64,
    pub cold_vout_miss_n: u64,
}

impl AsmPrevoutAcc {
    pub fn flush(&self, stats: &crate::ConfirmStats) {
        crate::note_confirm(&stats.asm_in_n, self.in_n);
        crate::note_confirm(&stats.asm_prev_same_n, self.same_n);
        crate::note_confirm(&stats.asm_prev_batch_n, self.batch_n);
        crate::note_confirm(&stats.asm_prev_cold_n, self.cold_n);
        crate::note_confirm(&stats.asm_prev_cold_null_fk_n, self.cold_null_fk_n);
        crate::note_confirm(&stats.asm_prev_cold_not_pin_n, self.cold_not_pin_n);
        crate::note_confirm(
            &stats.asm_prev_cold_txid_mismatch_n,
            self.cold_txid_mismatch_n,
        );
        crate::note_confirm(&stats.asm_prev_cold_vout_miss_n, self.cold_vout_miss_n);
    }
}

pub struct AssembleMeters {
    pub prev_ns: u64,
    pub job_ns: u64,
    pub acc: AsmPrevoutAcc,
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Sequential assemble: resolve prevout **content**, build script jobs, collect spends.
///
/// Confirm IBD path: no durable spentness / maturity / BIP68 create-height
/// resolution — those run in [`structural_validate_spends`] after scripts (load
/// must not walk create height per parent). Absolute nLockTime finality
/// (BIP113 MTP of prev block) still runs here — it only needs header MTP.
///
/// `pending_spent`: pack-local double-spend (early reject before scripts).
/// `pending_creates`: pack-local `txid → create_fk` (not per-vout).
/// Same-block outs use `txid_index` when the create index is earlier than
/// the spender; meters flush
/// once per block (no per-input Instant / atomics).
///
/// Prevouts resolve from per-batch [`crate::BatchParents`] +
/// [`crate::SpendEdges`]. Optimistic miss is `invariant:` (no head recover).
///
/// Returns `(script_jobs, spends, fees, tx_fees, meters)`. `fees` is the block sum
/// for the coinbase subsidy check. `tx_fees` is one satoshi fee per tx
/// (coinbase is 0) for the `txstat` stamp. `meters` is flushed by the caller.
///
/// `prev_mtp` / `block_hash` / `bip16_active` must be computed **once** by the
/// caller (assemble_run header window) — no re-walk of headers and no rehash.
///
/// `wire`: when `Some`, script jobs share that Arc (no `Transaction` clone).
/// When `None` (unit-test connect), jobs own a deep clone of each non-cb tx.
/// `build_script_jobs` is the caller's milestone decision.
pub fn assemble_block_prevouts(
    block: &Block,
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    pending_spent: &mut rbitcoin_consensus::OutPointSet,
    pending_creates: &mut PendingCreates,
    batch_parents: &crate::BatchParents,
    spend_edges: &crate::SpendEdges,
    create_txids: &[[u8; 32]],
    prev_mtp: u32,
    block_hash: &[u8; 32],
    bip16_active: bool,
    wire: Option<&Arc<Block>>,
    pres: Option<&Arc<[rbitcoin_consensus::TxPrecompute]>>,
    build_script_jobs: bool,
) -> Result<
    (
        Vec<ScriptCheckJob>,
        Vec<(
            [u8; 32],
            u32,
            rbitcoin_primitives::Fk,
            rbitcoin_primitives::Fk,
            u32,
        )>,
        i64,
        Vec<u64>,
        AssembleMeters,
    ),
    ConfirmError,
> {
    assemble_prevout_guards(block, archived_tx_fks, create_txids)?;
    // Caller-supplied BIP16 must match hash+prev_mtp (no silent re-resolve).
    debug_assert_eq!(
        bip16_active,
        rbitcoin_consensus::block::bip16_active_from_prev_mtp(
            ctx.params,
            ctx.height.0,
            block_hash,
            prev_mtp
        )
    );
    let flags =
        rbitcoin_consensus::block::ScriptVerifyFlags::consensus_at(ctx, block_hash, bip16_active);

    let n_tx = block.txdata.len();
    let mut txid_index: TxidMap<usize> =
        TxidMap::with_capacity_and_hasher(n_tx, Default::default());
    for (i, id) in create_txids.iter().enumerate() {
        txid_index.insert(*id, i);
    }
    let mut acc = AsmPrevoutAcc::default();
    let mut clk_job = 0u64;
    let mut fees = 0i64;
    let mut tx_fees = vec![0u64; n_tx];
    let mut script_jobs: Vec<ScriptCheckJob> = if build_script_jobs {
        Vec::with_capacity(n_tx.saturating_sub(1))
    } else {
        Vec::new()
    };
    let mut block_sigops_cost = match pres.and_then(|p| p.first()) {
        Some(p) => p.sigops.saturating_mul(4),
        None => rbitcoin_consensus::block::legacy_sigop_count(&block.txdata[0]).saturating_mul(4),
    };
    let mut spends: Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )> = Vec::with_capacity(n_tx.saturating_mul(2));

    let t_loop = Instant::now();

    let lock_time_cutoff = assemble_lock_time_cutoff(ctx, block, prev_mtp);
    // Empty until a same-block coinbase is waived. Honest blocks do not allocate.
    let mut waived_out: Option<WaivedOut> = None;

    for (ti, tx) in block.txdata.iter().enumerate() {
        let spend_fk = archived_tx_fks.map(|fks| fks[ti]);
        let txid = create_txids[ti];

        rbitcoin_consensus::block::reject_non_final(tx, ctx.height.0, lock_time_cutoff)?;
        rbitcoin_consensus::block::reject_tx_without_outputs(tx)?;
        if ti > 0 {
            tx_fees[ti] = assemble_non_cb_tx(
                ctx.params,
                block,
                tx,
                ti,
                txid,
                spend_fk,
                flags,
                bip16_active,
                wire,
                pres,
                &txid_index,
                pending_spent,
                pending_creates,
                batch_parents,
                spend_edges,
                &mut acc,
                &mut script_jobs,
                &mut spends,
                &mut fees,
                &mut block_sigops_cost,
                build_script_jobs,
                &mut clk_job,
                &mut waived_out,
            )?;
        }

        let create_fk = spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL);
        if !create_fk.is_null() {
            pending_creates.insert(txid, create_fk);
        }
        release_repeated_outputs(pending_spent, txid, tx.output.len());
    }

    let clk_prev = t_loop.elapsed().as_nanos() as u64;
    Ok((
        script_jobs,
        spends,
        fees,
        tx_fees,
        AssembleMeters {
            prev_ns: clk_prev,
            job_ns: clk_job,
            acc,
        },
    ))
}

#[doc(hidden)]
pub fn assemble_prevout_guards(
    block: &Block,
    archived_tx_fks: Option<&[rbitcoin_primitives::Fk]>,
    create_txids: &[[u8; 32]],
) -> Result<(), ConfirmError> {
    rbitcoin_consensus::block::reject_assemble_block_shape(
        block.txdata.len(),
        create_txids.len(),
        archived_tx_fks.map(|fks| fks.len()),
        block.txdata.first().is_some_and(|tx| tx.is_coinbase()),
    )?;
    Ok(())
}

pub fn assemble_lock_time_cutoff(
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    block: &Block,
    prev_mtp: u32,
) -> u32 {
    // Height 0 has no MTP history, so the cutoff is the block time even
    // when CSV is active.
    if ctx.height.0 == 0 || !ctx.params.csv_active_at(ctx.height.0) {
        block.header.time
    } else {
        prev_mtp
    }
}

#[allow(clippy::too_many_arguments)] // one non-coinbase assemble; call site stays unbundled
#[doc(hidden)]
pub fn assemble_non_cb_tx(
    params: &ChainParams,
    block: &Block,
    tx: &Transaction,
    ti: usize,
    txid: [u8; 32],
    spend_fk: Option<rbitcoin_primitives::Fk>,
    flags: ScriptVerifyFlags,
    bip16_active: bool,
    wire: Option<&Arc<Block>>,
    pres: Option<&Arc<[rbitcoin_consensus::TxPrecompute]>>,
    txid_index: &TxidMap<usize>,
    pending_spent: &mut rbitcoin_consensus::OutPointSet,
    pending_creates: &PendingCreates,
    batch_parents: &crate::BatchParents,
    spend_edges: &crate::SpendEdges,
    acc: &mut AsmPrevoutAcc,
    script_jobs: &mut Vec<ScriptCheckJob>,
    spends: &mut Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    fees: &mut i64,
    block_sigops_cost: &mut u64,
    build_script_jobs: bool,
    clk_job: &mut u64,
    waived_out: &mut Option<WaivedOut>,
) -> Result<u64, ConfirmError> {
    rbitcoin_consensus::block::reject_tx_without_inputs(tx)?;
    let (value_in, waived_cb, prevouts, tx_in_sigops) = assemble_non_cb_inputs(
        params,
        block,
        tx,
        ti,
        spend_fk,
        flags,
        bip16_active,
        txid_index,
        pending_spent,
        pending_creates,
        batch_parents,
        spend_edges,
        wire,
        acc,
        spends,
        build_script_jobs,
        waived_out,
    )?;
    let tx_legacy_sigops = match pres.and_then(|p| p.get(ti)) {
        Some(p) => p.sigops.saturating_mul(4),
        None => rbitcoin_consensus::block::legacy_sigop_count(tx).saturating_mul(4),
    };
    *block_sigops_cost =
        rbitcoin_consensus::block::add_sigops(*block_sigops_cost, tx_legacy_sigops, tx_in_sigops)?;
    let value_out = rbitcoin_consensus::block::assemble_tx_value_out(tx, ti, pres)?;
    let fee = rbitcoin_consensus::block::fee_with_waived_coinbase(value_in, waived_cb, value_out)?;
    if waived_cb > 0 {
        stamp_waived_outputs(waived_out, txid, value_in, fee, tx);
    }
    let fee_sat = rbitcoin_consensus::block::fee_sat(fee)?;
    *fees = rbitcoin_consensus::block::add_fee(*fees, fee)?;
    if build_script_jobs {
        let t_job = Instant::now();
        let mut job = match (wire, prevouts) {
            (Some(w), rbitcoin_consensus::block::JobPrevouts::Shared(v)) => {
                rbitcoin_consensus::block::ScriptCheckJob::from_parts(
                    txid,
                    rbitcoin_consensus::block::JobPrevouts::Shared(v),
                    rbitcoin_consensus::block::JobTx::shared(Arc::clone(w), ti),
                    flags,
                )
            }
            (None, rbitcoin_consensus::block::JobPrevouts::Owned(v)) => {
                rbitcoin_consensus::block::ScriptCheckJob::with_txid(txid, v, tx.clone(), flags)
            }
            _ => {
                return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: script job prevouts",
                )));
            }
        };
        if let Some(ps) = pres {
            if rbitcoin_consensus::block::should_use_pres(ti, ps.len()) {
                job = job.with_pre_slice(Arc::clone(ps), ti);
            }
        }
        script_jobs.push(job);
        *clk_job = clk_job.saturating_add(t_job.elapsed().as_nanos() as u64);
    }
    Ok(fee_sat)
}

#[allow(clippy::too_many_arguments)] // one non-coinbase input walk; call site stays unbundled
#[doc(hidden)]
pub fn assemble_non_cb_inputs(
    params: &ChainParams,
    block: &Block,
    tx: &Transaction,
    ti: usize,
    spend_fk: Option<rbitcoin_primitives::Fk>,
    flags: ScriptVerifyFlags,
    bip16_active: bool,
    txid_index: &TxidMap<usize>,
    pending_spent: &mut rbitcoin_consensus::OutPointSet,
    pending_creates: &PendingCreates,
    batch_parents: &crate::BatchParents,
    spend_edges: &crate::SpendEdges,
    wire: Option<&Arc<Block>>,
    acc: &mut AsmPrevoutAcc,
    spends: &mut Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    build_script_jobs: bool,
    waived_out: &Option<WaivedOut>,
) -> Result<(i64, i64, JobPrevouts, u64), ConfirmError> {
    let mut value_in = 0i64;
    let mut waived_cb = 0i64;
    let mut prevouts =
        if build_script_jobs && wire.is_some() {
            rbitcoin_consensus::block::JobPrevouts::Shared(Vec::with_capacity(tx.input.len()))
        } else {
            rbitcoin_consensus::block::JobPrevouts::owned(Vec::with_capacity(
                if build_script_jobs { tx.input.len() } else { 0 },
            ))
        };
    let edges = spend_fk.and_then(|fk| fk.get().and_then(|id| spend_edges.get(&id)));
    let mut tx_in_sigops = 0u64;
    for (ii, input) in tx.input.iter().enumerate() {
        let op = input.previous_output;
        let key = (op.txid.to_byte_array(), op.vout);
        // The genesis coinbase stays indexed for RPC and Electrum, but it is
        // not a coin (Core `ConnectBlock` genesis early return).
        rbitcoin_consensus::block::reject_genesis_coinbase_spend(
            params.is_genesis_coinbase(&key.0),
        )?;
        rbitcoin_consensus::block::reject_duplicate_input(pending_spent.insert(key))?;
        let (skip_fee, residue) = if let Some(&pj) = txid_index.get(&key.0) {
            let skip_fee = rbitcoin_consensus::block::reject_same_block_create(pj, ti)?;
            let residue = if skip_fee {
                0
            } else {
                same_block_residue(waived_out, key)
            };
            (skip_fee, residue)
        } else {
            (false, 0)
        };
        let prev_fk = edges
            .as_ref()
            .and_then(|t| t.get(ii))
            .and_then(|e| e.create_fk.get().map(|_| e.create_fk))
            .or_else(|| pending_creates.get(&key.0).copied());
        let prev_out = resolve_prevout(
            block,
            op,
            input,
            prev_fk,
            txid_index,
            ti,
            batch_parents,
            bip16_active,
            flags.witness_active,
            build_script_jobs,
            wire,
            acc,
        )?;
        let create_fk = prev_out.create_fk;
        tx_in_sigops = tx_in_sigops.saturating_add(prev_out.input_sigops);
        spends.push((
            key.0,
            key.1,
            spend_fk.unwrap_or(rbitcoin_primitives::Fk::NULL),
            create_fk,
            ii as u32,
        ));
        add_spent_value(
            skip_fee,
            residue,
            &mut value_in,
            &mut waived_cb,
            prev_out.txout.value.to_sat(),
        )?;
        if build_script_jobs {
            match &mut prevouts {
                rbitcoin_consensus::block::JobPrevouts::Shared(v) => {
                    let shared = prev_out.shared.ok_or(ConfirmError::Store(
                        rbitcoin_store::StoreError::Corrupt(
                            "invariant: wire confirm prevout shares script bytes",
                        ),
                    ))?;
                    v.push(shared);
                }
                rbitcoin_consensus::block::JobPrevouts::Owned(v) => v.push(prev_out.txout),
            }
        }
    }
    Ok((value_in, waived_cb, prevouts, tx_in_sigops))
}

type WaivedOut = std::collections::HashMap<([u8; 32], u32), u64>;

fn same_block_residue(waived_out: &Option<WaivedOut>, key: ([u8; 32], u32)) -> u64 {
    waived_out
        .as_ref()
        .and_then(|m| m.get(&key).copied())
        .unwrap_or(0)
}

fn stamp_waived_outputs(
    waived_out: &mut Option<WaivedOut>,
    txid: [u8; 32],
    clean_in: i64,
    fee: i64,
    tx: &Transaction,
) {
    let sats: Vec<u64> = tx.output.iter().map(|o| o.value.to_sat()).collect();
    let residue = rbitcoin_consensus::block::waived_output_residue(clean_in, fee, &sats);
    let map = waived_out.get_or_insert_with(WaivedOut::new);
    for (vout, left) in residue.into_iter().enumerate() {
        if left > 0 {
            map.insert((txid, vout as u32), left);
        }
    }
}

fn add_spent_value(
    skip_fee: bool,
    residue: u64,
    paid: &mut i64,
    waived: &mut i64,
    sat: u64,
) -> Result<(), ConfirmError> {
    let (paid_sat, waived_sat) = if skip_fee {
        (0, sat)
    } else if residue == 0 {
        (sat, 0)
    } else {
        let waived_sat = residue.min(sat);
        (sat - waived_sat, waived_sat)
    };
    if paid_sat > 0 {
        *paid = rbitcoin_consensus::block::add_value_in(*paid, paid_sat)?;
    }
    if waived_sat > 0 {
        *waived = rbitcoin_consensus::block::add_value_in(*waived, waived_sat)?;
    }
    Ok(())
}

/// Local wall times for one block's structural pass (write path diagnostics).
///
/// Measured with `Instant` — **not** deltas of window atomics (those race with
/// `sample_and_reset` mid-batch and produced false `spent=0` on slow writes).
#[derive(Debug, Clone, Copy, Default)]
pub struct StructuralPhaseNs {
    pub spent_ns: u64,
    /// Pin abs collect + bulk on-disk 8-byte spender meta pread.
    pub spent_abs_ns: u64,
    /// `is_confirmed_strong_at` on non-null fields (still durable authority).
    pub spent_strong_ns: u64,
    /// Cold unspent_create_vouts / null-create probes.
    pub spent_cold_ns: u64,
    /// pending_spent order gate (CPU).
    pub spent_pending_ns: u64,
    pub create_h_ns: u64,
    pub bip68_ns: u64,
}

/// Post-script structural checks: durable spentness, maturity, BIP68, coinbase subsidy.
///
/// Runs in height order on the write path (after scripts). `pending_spent` is
/// write-local across a multi-height run.
///
/// **BIP68** create-height lives here (not optimistic load assemble) so confirm
/// load does not walk create height for every parent. Heights: bulk fence.
/// Coin MTP only for time-type relative locks on version ≥2 txs (v1 skipped).
///
/// Write-path spend annotate slots: abs edge plus the meta structural already read.
///
/// Filled during spentness and passed to annotate. No second edge copy.
#[derive(Clone, Debug, Default)]
pub struct AnnotateSlots {
    pub abs_edges: Vec<(
        u64,
        rbitcoin_primitives::Fk,
        u32,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    pub known: Vec<(rbitcoin_primitives::Fk, u8, u32)>,
}

impl AnnotateSlots {
    pub fn push(
        &mut self,
        edge: (
            u64,
            rbitcoin_primitives::Fk,
            u32,
            rbitcoin_primitives::Fk,
            u32,
        ),
        known: (rbitcoin_primitives::Fk, u8, u32),
    ) {
        self.abs_edges.push(edge);
        self.known.push(known);
    }
}

/// Per-block spentness scratch. Capacity stays across blocks in one write batch.
/// [`AnnotateSlots`] accumulate for the whole batch.
pub struct StructuralScratch {
    pub abs_jobs: Vec<StructuralAbsJob>,
    pub unique_fks: Vec<rbitcoin_primitives::Fk>,
    pub height_by_id: U64Map<u32>,
    pub skip_n: std::collections::HashMap<
        (u64, u32),
        u32,
        BuildHasherDefault<rbitcoin_consensus::OutPointHasher>,
    >,
    pub skip: OverlayMetaSkip,
    pub disk_jobs: Vec<StructuralAbsJob>,
    pub abs_offs: Vec<u64>,
    pub field_fks: Vec<rbitcoin_primitives::Fk>,
    pub field_seen: crate::U64Set,
    pub field_h_by_id: U64Map<u32>,
    pub durable_spent: DurableSpentSet,
    pub height_list: Vec<u32>,
    pub create_height_by_fk: FkMap<u32>,
    /// BIP30 inside one batch: each txid already created here, with its height
    /// and the span of `batch_vouts` holding its spendable outputs.
    pub batch_creates: TxidMap<(u32, u32, u32)>,
    pub batch_vouts: Vec<u32>,
    pub slots: AnnotateSlots,
}

impl Default for StructuralScratch {
    fn default() -> Self {
        Self {
            abs_jobs: Vec::new(),
            unique_fks: Vec::new(),
            height_by_id: U64Map::default(),
            skip_n: std::collections::HashMap::with_hasher(Default::default()),
            skip: OverlayMetaSkip::with_hasher(Default::default()),
            disk_jobs: Vec::new(),
            abs_offs: Vec::new(),
            field_fks: Vec::new(),
            field_seen: crate::U64Set::default(),
            field_h_by_id: U64Map::default(),
            durable_spent: DurableSpentSet::with_hasher(Default::default()),
            height_list: Vec::new(),
            create_height_by_fk: FkMap::default(),
            batch_creates: TxidMap::default(),
            batch_vouts: Vec::new(),
            slots: AnnotateSlots::default(),
        }
    }
}

impl StructuralScratch {
    /// Drop annotate slots from the previous write batch. Per-block buffers
    /// stay for [`Self::begin_block`]; slots accumulate inside one batch.
    pub fn begin_batch(&mut self) {
        self.slots.abs_edges.clear();
        self.slots.known.clear();
        self.batch_creates.clear();
        self.batch_vouts.clear();
    }

    #[doc(hidden)]
    pub fn begin_block(&mut self) {
        self.abs_jobs.clear();
        self.unique_fks.clear();
        self.height_by_id.clear();
        self.skip_n.clear();
        self.skip.clear();
        self.disk_jobs.clear();
        self.abs_offs.clear();
        self.field_fks.clear();
        self.field_seen.clear();
        self.field_h_by_id.clear();
        self.durable_spent.clear();
        self.height_list.clear();
        self.create_height_by_fk.clear();
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// **Spentness:** pin denserels → abs + bulk 8-byte meta. Sparse durable-**spent**
/// set (not unspent). Missing abs / short meta is hard `Err`. **Multi-list** after
/// reorg annotate is a protocol cold walk (`has_confirmed_strong_spender_create`)
/// — not a hard fail (tip-follow reorgs leave multi flags by design). Emits
/// Annotate slots on `scratch` for pure-write annotate.
pub fn structural_validate_spends(
    query: &Query,
    block: &Block,
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    fees: i64,
    pending_spent: &mut BatchSpent,
    batch_parents: &crate::BatchParents,
    mtp_cache: &mut U32Map<u32>,
    run_create_height: &RunCreateHeight,
    class_a_wave: &ClassAWave,
    scratch: &mut StructuralScratch,
    abs_jobs: &[StructuralAbsJob],
    bip34_ancestor: Option<bitcoin::BlockHash>,
) -> Result<StructuralPhaseNs, ConfirmError> {
    use std::time::Instant;

    scratch.begin_block();
    let maturity = ctx.params.coinbase_maturity();
    // BIP30's txid batch is inside `spent_ns` (signet runs it on every block).
    let t_spent = Instant::now();
    reject_bip30_unspent_overwrite(
        query,
        block,
        ctx,
        pending_spent,
        run_create_height,
        scratch,
        bip34_ancestor,
    )?;
    let t_abs = Instant::now();
    structural_abs_heights(query, run_create_height, scratch, abs_jobs)?;
    let tip = query.tip_height().map(|h| h.0);
    let mut spent_strong_ns = 0u64;
    let mut multi_list_ns = 0u64;
    if !scratch.abs_jobs.is_empty() {
        fill_overlay_skip(spends, class_a_wave, scratch);
        let loaded = structural_load_durable_spent(query, tip, scratch)?;
        multi_list_ns = loaded.0;
        spent_strong_ns = loaded.1;
    }
    let spent_abs_ns = (t_abs.elapsed().as_nanos() as u64).saturating_sub(spent_strong_ns);
    let spent_cold_ns = multi_list_ns;
    let t_pending = Instant::now();
    structural_mark_pending(
        spends,
        pending_spent,
        run_create_height,
        &scratch.durable_spent,
    )?;
    let spent_pending_ns = t_pending.elapsed().as_nanos() as u64;
    let spent_ns = t_spent.elapsed().as_nanos() as u64;
    let t_create = Instant::now();
    structural_create_heights(
        query,
        batch_parents,
        run_create_height,
        ctx.height.0,
        maturity,
        scratch,
    )?;
    let create_h_ns = t_create.elapsed().as_nanos() as u64;
    let t_bip68 = Instant::now();
    structural_bip68(
        query,
        block,
        ctx,
        spends,
        &scratch.create_height_by_fk,
        mtp_cache,
    )?;
    let bip68_ns = t_bip68.elapsed().as_nanos() as u64;
    rbitcoin_consensus::block::check_coinbase_subsidy(block, ctx, fees)?;
    Ok(StructuralPhaseNs {
        spent_ns,
        spent_abs_ns,
        spent_strong_ns,
        spent_cold_ns,
        spent_pending_ns,
        create_h_ns,
        bip68_ns,
    })
}

pub type StructuralAbsJob = (u64, u32, u64, rbitcoin_primitives::Fk, u32);

/// Creates this write batch's Class A append committed.
///
/// Only these spent slots carry the same-batch sole-spender overlay. A run
/// create archived by an earlier wave has whatever that wave and later
/// annotates left on disk, so structural reads and annotates it.
#[derive(Default)]
pub struct ClassAWave(Vec<rbitcoin_primitives::Fk>);

impl ClassAWave {
    pub fn new(mut fks: Vec<rbitcoin_primitives::Fk>) -> Self {
        fks.sort_unstable_by_key(|f| f.0);
        Self(fks)
    }

    #[doc(hidden)]
    pub fn contains(&self, fk: rbitcoin_primitives::Fk) -> bool {
        self.0.binary_search_by_key(&fk.0, |f| f.0).is_ok()
    }
}

/// Create heights for one write batch.
///
/// Contiguous per-block fk spans are the IBD shape (`first` + count). A gap
/// or overlap uses the map so a fk between spans does not inherit a height.
/// Each block's first fk is its coinbase: a span's `first`, or the map's flag.
pub enum RunCreateHeight {
    Spans(Vec<(u64, u64, u32)>),
    Map(FkMap<(u32, bool)>),
}

impl RunCreateHeight {
    pub fn from_blocks<'a>(
        blocks: impl IntoIterator<Item = (u32, &'a [rbitcoin_primitives::Fk])>,
    ) -> Self {
        let blocks: Vec<(u32, &'a [rbitcoin_primitives::Fk])> = blocks.into_iter().collect();
        if let Some(spans) = contiguous_create_spans(&blocks) {
            Self::Spans(spans)
        } else {
            let mut map = FkMap::default();
            for (height, fks) in blocks {
                for (i, fk) in fks.iter().enumerate() {
                    map.insert(*fk, (height, i == 0));
                }
            }
            Self::Map(map)
        }
    }

    pub fn get(&self, fk: rbitcoin_primitives::Fk) -> Option<u32> {
        self.create(fk).map(|(height, _)| height)
    }

    /// Height of a create in this batch and whether it is its block's coinbase.
    pub fn create(&self, fk: rbitcoin_primitives::Fk) -> Option<(u32, bool)> {
        match self {
            Self::Map(map) => map.get(&fk).copied(),
            Self::Spans(spans) => {
                let id = fk.get()?;
                let i = spans.partition_point(|span| span.0 <= id);
                let (first, end, height) = spans.get(i.checked_sub(1)?)?;
                (*end > id).then_some((*height, *first == id))
            }
        }
    }
}

/// `Some` when every non-empty block is `[first, first+n)` and spans do not overlap.
///
/// A null fk, a gap, or an id that would wrap is `None` so the caller uses the map.
/// A wrapped end must not cover fks that are not in the block.
#[doc(hidden)]
pub fn contiguous_create_spans(
    blocks: &[(u32, &[rbitcoin_primitives::Fk])],
) -> Option<Vec<(u64, u64, u32)>> {
    let mut spans = Vec::with_capacity(blocks.len());
    for &(height, fks) in blocks {
        if fks.is_empty() {
            continue;
        }
        let mut ids = fks.iter().map(|fk| fk.get());
        let first = ids.next().flatten()?;
        let mut prev = first;
        for id in ids {
            let id = id?;
            let next = prev.checked_add(1)?;
            if id != next {
                return None;
            }
            prev = id;
        }
        let end = prev.checked_add(1)?;
        spans.push((first, end, height));
    }
    spans.sort_unstable_by_key(|span| span.0);
    for pair in spans.windows(2) {
        if pair[0].1 > pair[1].0 {
            return None;
        }
    }
    Some(spans)
}
#[doc(hidden)]
pub type DurableSpentSet =
    std::collections::HashSet<(u64, u32), BuildHasherDefault<rbitcoin_consensus::OutPointHasher>>;
#[doc(hidden)]
pub type OverlayMetaSkip = std::collections::HashMap<
    (u64, u32),
    (rbitcoin_primitives::Fk, u32),
    BuildHasherDefault<rbitcoin_consensus::OutPointHasher>,
>;

#[doc(hidden)]
pub fn fill_overlay_skip(
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    class_a_wave: &ClassAWave,
    scratch: &mut StructuralScratch,
) {
    for &(_, vout, sfk, cfk, vin) in spends {
        if !class_a_wave.contains(cfk) {
            continue;
        }
        let Some(id) = cfk.get() else {
            continue;
        };
        let key = (id, vout);
        *scratch.skip_n.entry(key).or_insert(0) += 1;
        scratch.skip.entry(key).or_insert((sfk, vin));
    }
    let skip_n = &scratch.skip_n;
    scratch
        .skip
        .retain(|k, _| skip_n.get(k).copied() == Some(1));
}

#[doc(hidden)]
pub fn overlay_meta_is_skip(
    id: u64,
    vout: u32,
    sfk: rbitcoin_primitives::Fk,
    vin: u32,
    skip: &OverlayMetaSkip,
) -> bool {
    skip.get(&(id, vout)) == Some(&(sfk, vin))
}

#[doc(hidden)]
pub fn structural_abs_heights(
    query: &Query,
    run_create_height: &RunCreateHeight,
    scratch: &mut StructuralScratch,
    abs_jobs: &[StructuralAbsJob],
) -> Result<(), ConfirmError> {
    scratch.abs_jobs.extend_from_slice(abs_jobs);
    scratch.unique_fks.extend(
        scratch
            .abs_jobs
            .iter()
            .map(|(id, _, _, _, _)| rbitcoin_primitives::Fk(*id)),
    );
    scratch.unique_fks.sort_unstable_by_key(|f| f.0);
    scratch.unique_fks.dedup();
    let durable_heights = query
        .store()
        .tx_height_get_batch(&scratch.unique_fks)
        .map_err(ConfirmError::from)?;
    for (fk, h) in scratch.unique_fks.iter().zip(durable_heights) {
        let Some(id) = fk.get() else {
            continue;
        };
        let Some(h) = h.or_else(|| run_create_height.get(*fk)) else {
            continue;
        };
        scratch.height_by_id.insert(id, h);
    }
    Ok(())
}

#[doc(hidden)]
pub fn structural_load_durable_spent(
    query: &Query,
    tip: Option<u32>,
    scratch: &mut StructuralScratch,
) -> Result<(u64, u64), ConfirmError> {
    use std::time::Instant;
    let mut ovl_n = 0u64;
    for &job in &scratch.abs_jobs {
        let (id, vout, abs, sfk, vin) = job;
        if overlay_meta_is_skip(id, vout, sfk, vin, &scratch.skip) {
            ovl_n = ovl_n.saturating_add(1);
            continue;
        }
        scratch.disk_jobs.push(job);
        scratch.abs_offs.push(abs);
    }
    crate::note_confirm(&query.confirm_stats().spend_overlay_skip_n, ovl_n);
    if scratch.abs_offs.is_empty() {
        return Ok((0, 0));
    }
    let meta_backend = rbitcoin_store::spend_meta_backend();
    let t_meta = Instant::now();
    let metas = query
        .store()
        .get_spender_meta_at_abs_batch_backend(&scratch.abs_offs, meta_backend)
        .map_err(ConfirmError::from)?;
    let meta_ns = t_meta.elapsed().as_nanos() as u64;
    crate::note_confirm(&query.confirm_stats().spend_meta_ns, meta_ns);
    crate::note_confirm(
        &query.confirm_stats().spend_meta_n,
        scratch.abs_offs.len() as u64,
    );
    let _ = meta_backend;
    if metas.len() != scratch.disk_jobs.len() {
        return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: structural meta batch length",
        )));
    }
    let t_strong = Instant::now();
    for row in &metas {
        let Some((field, _, _)) = row else {
            continue;
        };
        if field.is_null() {
            continue;
        }
        if let Some(fid) = field.get() {
            if scratch.field_seen.insert(fid) {
                scratch.field_fks.push(*field);
            }
        }
    }
    let field_heights = query
        .store()
        .tx_height_get_batch(&scratch.field_fks)
        .map_err(ConfirmError::from)?;
    for (fk, h) in scratch.field_fks.iter().zip(field_heights) {
        if let Some((id, h)) = fk.get().zip(h) {
            scratch.field_h_by_id.insert(id, h);
        }
    }
    let jobs = std::mem::take(&mut scratch.disk_jobs);
    let applied = jobs
        .iter()
        .copied()
        .zip(metas)
        .try_fold(0u64, |acc, (job, meta)| {
            let (id, vout, abs, sfk, vin) = job;
            let ns = structural_apply_one_meta(query, meta, id, vout, abs, sfk, vin, tip, scratch)?;
            Ok::<u64, ConfirmError>(acc.saturating_add(ns))
        });
    scratch.disk_jobs = jobs;
    let multi_list_ns = applied?;
    let spent_strong_ns = t_strong
        .elapsed()
        .as_nanos()
        .saturating_sub(multi_list_ns as u128) as u64;
    Ok((multi_list_ns, spent_strong_ns))
}

#[allow(clippy::too_many_arguments)] // one spent-slot apply; call site stays unbundled
pub fn structural_apply_one_meta(
    query: &Query,
    meta: Option<(rbitcoin_primitives::Fk, u8, u32)>,
    id: u64,
    vout: u32,
    abs: u64,
    sfk: rbitcoin_primitives::Fk,
    vin: u32,
    tip: Option<u32>,
    scratch: &mut StructuralScratch,
) -> Result<u64, ConfirmError> {
    use std::time::Instant;
    let Some((field, flags, field_vin)) = meta else {
        return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: structural spender meta short/OOB (cold forbidden)",
        )));
    };
    scratch.slots.push(
        (abs, rbitcoin_primitives::Fk(id), vout, sfk, vin),
        (field, flags, field_vin),
    );
    let multi = flags & rbitcoin_store::output_flags::MULTI_SPENDER != 0;
    if multi {
        let t_m = Instant::now();
        let spent = query
            .store()
            .has_confirmed_strong_spender_create(rbitcoin_primitives::Fk(id), vout, None)
            .map_err(ConfirmError::from)?;
        let ns = t_m.elapsed().as_nanos() as u64;
        if spent {
            scratch.durable_spent.insert((id, vout));
        }
        return Ok(ns);
    }
    if field.is_null() {
        return Ok(0);
    }
    let strong = query
        .store()
        .is_confirmed_strong_at(field, tip)
        .map_err(ConfirmError::from)?;
    if !strong {
        return Ok(0);
    }
    let create_h = scratch.height_by_id.get(&id).copied();
    let spend_h = field
        .get()
        .and_then(|fid| scratch.field_h_by_id.get(&fid).copied());
    if let (Some(ch), Some(sh)) = (create_h, spend_h) {
        if sh < ch {
            return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: confirmed spender below its create height",
            )));
        }
    }
    scratch.durable_spent.insert((id, vout));
    Ok(0)
}

#[doc(hidden)]
pub fn structural_mark_pending(
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    pending_spent: &mut BatchSpent,
    run_create_height: &RunCreateHeight,
    durable_spent: &DurableSpentSet,
) -> Result<(), ConfirmError> {
    for &(prev_txid, vout, spend_fk, create_fk, _vin) in spends {
        let key = (prev_txid, vout);
        let spent = if create_fk.is_null() {
            false
        } else if let Some(id) = create_fk.get() {
            durable_spent.contains(&(id, vout))
        } else {
            false
        };
        // A same-block create has no fk here. Its spender's fk has the same
        // height in this batch, which is what identifies the copy.
        let copy = if create_fk.is_null() {
            spend_fk
        } else {
            create_fk
        };
        let again = pending_spent
            .insert(key, copy)
            .is_some_and(|prev| same_copy(run_create_height, prev, copy));
        rbitcoin_consensus::block::reject_prevout_spent(spent || again)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn structural_create_heights(
    query: &Query,
    batch_parents: &crate::BatchParents,
    run_create_height: &RunCreateHeight,
    spend_height: u32,
    maturity: u32,
    scratch: &mut StructuralScratch,
) -> Result<(), ConfirmError> {
    // `confirmed[h]` for a height in this batch is written at Class C, after
    // structural; the batch index owns coinbase identity there.
    scratch.height_list.extend(
        scratch
            .height_by_id
            .iter()
            .filter(|&(&id, &h)| run_create_height.get(rbitcoin_primitives::Fk(id)) != Some(h))
            .map(|(_, &h)| h),
    );
    scratch.height_list.sort_unstable();
    scratch.height_list.dedup();
    let coinbase_fk_by_height = query
        .store()
        .coinbase_fk_at_heights(&scratch.height_list)
        .map_err(ConfirmError::from)?;
    let n_unique = scratch.unique_fks.len();
    for i in 0..n_unique {
        let create_fk = scratch.unique_fks[i];
        let Some(id) = create_fk.get() else {
            continue;
        };
        let Some(&durable_h) = scratch.height_by_id.get(&id) else {
            return rbitcoin_consensus::block::reject_one_create(
                spend_height,
                maturity,
                None,
                false,
            )
            .map_err(ConfirmError::from);
        };
        let pin_cb = batch_parents.get_parent_coinbase(create_fk);
        let is_cb = match (pin_cb, run_create_height.create(create_fk)) {
            (Some(cb), _) => cb,
            (None, Some((h, cb))) if h == durable_h => cb,
            (None, _) => {
                let cb = coinbase_fk_by_height
                    .get(&durable_h)
                    .ok_or(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                        "invariant: no coinbase fk at confirmed create height",
                    )))?;
                *cb == create_fk
            }
        };
        // Core connects a run one block at a time: a create from a later
        // block of this batch is not yet a coin when this block spends it.
        rbitcoin_consensus::block::reject_one_create(
            spend_height,
            maturity,
            Some(durable_h),
            is_cb,
        )?;
        scratch.create_height_by_fk.insert(create_fk, durable_h);
    }
    Ok(())
}

pub fn structural_bip68(
    query: &Query,
    block: &Block,
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    spends: &[(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )],
    create_height_by_fk: &FkMap<u32>,
    mtp_cache: &mut U32Map<u32>,
) -> Result<(), ConfirmError> {
    if !ctx.params.csv_active_at(ctx.height.0) {
        return Ok(());
    }
    const DISABLE: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    let prev_mtp = if ctx.height.0 == 0 {
        0
    } else {
        mtp_at(query, Height(ctx.height.0 - 1), mtp_cache)?
    };
    let mut si = 0usize;
    let mut prev_heights: Vec<u32> = Vec::new();
    let mut coin_mtps: Vec<u32> = Vec::new();
    for tx in block.txdata.iter().skip(1) {
        let n_in = tx.input.len();
        rbitcoin_consensus::block::reject_spend_cursor(si + n_in <= spends.len())?;
        let tx_spends = &spends[si..si + n_in];
        si += n_in;
        if !rbitcoin_consensus::block::bip68_active_for_tx(tx) {
            continue;
        }
        prev_heights.clear();
        coin_mtps.clear();
        prev_heights.reserve(n_in);
        coin_mtps.reserve(n_in);
        for (inp, &(_ptid, _vout, _sfk, create_fk, _vin)) in tx.input.iter().zip(tx_spends.iter()) {
            let ch = if create_fk.is_null() {
                ctx.height.0
            } else {
                rbitcoin_consensus::block::reject_csv_create_height(
                    create_height_by_fk.get(&create_fk).copied(),
                )?
            };
            prev_heights.push(ch);
            let seq = inp.sequence.to_consensus_u32();
            let need_mtp = seq & DISABLE == 0 && seq & TYPE_FLAG != 0;
            // Height 0 is the genesis coin: one median lookup of block 0.
            // A missing create height is not height 0.
            let mtp = if !need_mtp {
                0
            } else {
                mtp_at(query, Height(ch.saturating_sub(1)), mtp_cache)?
            };
            coin_mtps.push(mtp);
        }
        rbitcoin_consensus::block::reject_sequence_locks(
            tx,
            &prev_heights,
            &coin_mtps,
            ctx.height.0,
            prev_mtp,
        )?;
    }
    rbitcoin_consensus::block::reject_spend_cursor(si == spends.len())?;
    Ok(())
}

/// MTP for write structural. Prefers assemble-carried `prev_mtp` (seeded into
/// `cache`). Misses go to durable headers only — never `get_header_plan`.
/// BIP30: a connected instance with any unspent spendable output may not be
/// overwritten.
/// Skipped for the two mainnet repeats, and when the header at BIP34 height
/// is this network's BIP34 hash and the block is below
/// [`crate::params::BIP34_IMPLIES_BIP30_LIMIT`]. Signet and regtest have no
/// BIP34 hash, so every block is checked. Just-archived self is unconnected.
#[doc(hidden)]
pub fn reject_bip30_unspent_overwrite(
    query: &Query,
    block: &Block,
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    pending_spent: &BatchSpent,
    run_create_height: &RunCreateHeight,
    scratch: &mut StructuralScratch,
    bip34_ancestor: Option<bitcoin::BlockHash>,
) -> Result<(), ConfirmError> {
    if ctx.params.is_bip30_repeat(ctx.height.0, block.block_hash())
        || bip34_ancestry_skips_bip30(ctx, bip34_ancestor)
    {
        return Ok(());
    }
    let create_txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    // An earlier block of this batch is not connected yet, so the store
    // lookup below cannot see its creates.
    for txid in &create_txids {
        let Some(&(prior_height, lo, hi)) = scratch.batch_creates.get(txid) else {
            continue;
        };
        let unspent = scratch.batch_vouts[lo as usize..hi as usize]
            .iter()
            .any(|&v| {
                pending_spent
                    .get(&(*txid, v))
                    .and_then(|&copy| run_create_height.get(copy))
                    != Some(prior_height)
            });
        rbitcoin_consensus::block::reject_bip30_unspent_prior(ctx.height.0, prior_height, unspent)?;
    }
    let hits = query
        .store()
        .get_fk_by_txid_batch(&create_txids)
        .map_err(ConfirmError::from)?;
    for (txid, row) in hits {
        let Some((old_fk, _)) = row else {
            continue;
        };
        // Connected instance at *this* height is ourselves (re-validate /
        // already-confirmed fixture). BIP30 is an earlier unspent sibling.
        let prior_height = query
            .store()
            .tx_height_get(old_fk)
            .map_err(ConfirmError::from)?;
        if prior_height == Some(ctx.height.0) {
            continue;
        }
        let (_, outs) = query
            .store()
            .get_tx_meta_and_outputs(old_fk)
            .map_err(ConfirmError::from)?;
        let mut unspent = false;
        for (v, out) in (0u32..).zip(&outs) {
            // Core's AddCoins never stores an unspendable output, so it is
            // not a coin that the overwrite could clobber.
            if rbitcoin_consensus::policy::is_unspendable(&out.script) {
                continue;
            }
            // A spend earlier in this batch is not connected yet either. It
            // spent this copy, or a later one that needed this copy spent.
            let spent = pending_spent.contains_key(&(txid, v))
                || query
                    .store()
                    .has_confirmed_strong_spender_create(old_fk, v, None)
                    .map_err(ConfirmError::from)?;
            if !spent {
                unspent = true;
                break;
            }
        }
        if unspent {
            rbitcoin_consensus::block::reject_bip30_unspent_prior(
                ctx.height.0,
                prior_height.unwrap_or(u32::MAX),
                true,
            )?;
        }
    }
    for (txid, tx) in create_txids.into_iter().zip(&block.txdata) {
        let lo = scratch.batch_vouts.len() as u32;
        scratch.batch_vouts.extend(
            (0u32..)
                .zip(&tx.output)
                .filter(|(_, out)| {
                    !rbitcoin_consensus::policy::is_unspendable(out.script_pubkey.as_bytes())
                })
                .map(|(v, _)| v),
        );
        let hi = scratch.batch_vouts.len() as u32;
        scratch.batch_creates.insert(txid, (ctx.height.0, lo, hi));
    }
    Ok(())
}

/// Outpoints spent so far in one write batch, each with the copy the spend used:
/// its create fk, or for a same-block create the spender's fk. A txid can be
/// created again once its first copy is spent (below BIP34, or a pre-BIP34
/// coinbase whose scriptSig already pushes a later height), so a spend of the
/// new copy is not a second spend of the old one.
pub type BatchSpent = std::collections::HashMap<
    ([u8; 32], u32),
    rbitcoin_primitives::Fk,
    BuildHasherDefault<rbitcoin_consensus::OutPointHasher>,
>;

/// One block holds one copy of a txid, so two copies created in this batch are
/// the same copy when they have the same height.
#[doc(hidden)]
pub fn same_copy(
    run_create_height: &RunCreateHeight,
    a: rbitcoin_primitives::Fk,
    b: rbitcoin_primitives::Fk,
) -> bool {
    a == b
        || run_create_height
            .get(a)
            .is_some_and(|h| run_create_height.get(b) == Some(h))
}

/// A txid can be created again once its first copy is spent (see [`BatchSpent`]).
/// Its outputs are coins again (Core overwrites them in the view), so this
/// load batch's earlier spends of the old copy no longer block the new one.
#[doc(hidden)]
pub fn release_repeated_outputs(
    pending_spent: &mut rbitcoin_consensus::OutPointSet,
    txid: [u8; 32],
    n_out: usize,
) {
    for v in 0..n_out as u32 {
        pending_spent.remove(&(txid, v));
    }
}

#[doc(hidden)]
pub fn bip34_ancestry_skips_bip30(
    ctx: &rbitcoin_consensus::ValidationContext<'_>,
    ancestor: Option<bitcoin::BlockHash>,
) -> bool {
    let height = ctx.height.0;
    if ctx.params.bip34_hash.is_none() || height <= ctx.params.btc.bip34_height {
        return false;
    }
    // `ancestor` is resolved once for this write. Not `get_header_plan`:
    // that plan can be a sibling fork.
    ctx.params
        .bip30_skipped_for_bip34_ancestry(height, ancestor)
}

#[doc(hidden)]
pub fn mtp_at(query: &Query, height: Height, cache: &mut U32Map<u32>) -> Result<u32, ConfirmError> {
    if let Some(&t) = cache.get(&height.0) {
        return Ok(t);
    }
    let t = crate::median_time_past_store(query, height)?;
    cache.insert(height.0, t);
    Ok(t)
}

/// Create index strictly earlier in this block than the spender.
struct EarlierIndex(usize);

impl EarlierIndex {
    fn earlier_than(parent: usize, spender: usize) -> Option<Self> {
        if parent < spender {
            Some(Self(parent))
        } else {
            None
        }
    }
}

pub struct ResolvedPrevout {
    pub txout: TxOut,
    /// Set when the script bytes stay in a block or pin `Arc`.
    pub shared: Option<rbitcoin_consensus::block::SharedPrevout>,
    /// P2SH+witness sigop cost for this input's prevout script (not legacy).
    pub input_sigops: u64,
    /// Class A create fk for this prevout (or `NULL` for same-block). Load pin
    /// denserels must carry identity matching wire `prev_txid` for this fk.
    pub create_fk: rbitcoin_primitives::Fk,
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn resolve_prevout(
    block: &Block,
    op: OutPoint,
    inp: &bitcoin::TxIn,
    prev_fk_hint: Option<rbitcoin_primitives::Fk>,
    txid_index: &TxidMap<usize>,
    spend_ti: usize,
    batch_parents: &crate::BatchParents,
    bip16: bool,
    witness: bool,
    need_script_buf: bool,
    wire: Option<&Arc<Block>>,
    acc: &mut AsmPrevoutAcc,
) -> Result<ResolvedPrevout, ConfirmError> {
    let prev_txid = op.txid.to_byte_array();

    if let Some(&pj) = txid_index.get(&prev_txid) {
        if let Some(parent) = EarlierIndex::earlier_than(pj, spend_ti) {
            let pj = parent.0;
            let v = op.vout as usize;
            let o = rbitcoin_consensus::block::require_same_block_output(block.txdata.get(pj), v)?;
            // Core never puts this script in the coin view. The returned
            // `txout` is often empty; the wire output holds the real bytes.
            rbitcoin_consensus::block::reject_unspendable_prevout(
                rbitcoin_consensus::policy::is_unspendable(o.script_pubkey.as_bytes()),
            )?;
            acc.in_n = acc.in_n.saturating_add(1);
            acc.same_n = acc.same_n.saturating_add(1);
            let shared = if need_script_buf {
                wire.map(|_| rbitcoin_consensus::block::SharedPrevout::Wire {
                    tx_index: pj as u32,
                    vout: op.vout,
                })
            } else {
                None
            };
            return Ok(ResolvedPrevout {
                txout: if shared.is_some() || !need_script_buf {
                    TxOut {
                        value: o.value,
                        script_pubkey: ScriptBuf::new(),
                    }
                } else {
                    o.clone()
                },
                shared,
                input_sigops: rbitcoin_consensus::block::prevout_spk_sigops(
                    inp,
                    o.script_pubkey.as_bytes(),
                    bip16,
                    witness,
                ),
                create_fk: rbitcoin_primitives::Fk::NULL,
            });
        }
    }

    // Batch pin first (no TxRecord clone — A3). Pin identity/vout misses are
    // hard invariants (load must fill schema-13 identity + denserels).
    if let Some(prev_fk) = prev_fk_hint {
        if let Some((pinned, parent_txid)) = batch_parents.share_parent_prevout(prev_fk, op.vout) {
            if parent_txid != prev_txid {
                acc.cold_txid_mismatch_n = acc.cold_txid_mismatch_n.saturating_add(1);
                #[cfg(debug_assertions)]
                crate::block_pipeline::test_phase::tl_note_cold_why_txid_mismatch();
                return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: pin parent create identity mismatch wire prev_txid",
                )));
            }
            let (value, script) =
                pinned
                    .parts()
                    .ok_or(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                        "invariant: pin incomplete outs for spent parent vout",
                    )))?;
            // Same rule as the same-block arm. `txout.script_pubkey` below is
            // empty; `script` is the archived bytes, including when scripts
            // are not executed.
            rbitcoin_consensus::block::reject_unspendable_prevout(
                rbitcoin_consensus::policy::is_unspendable(script),
            )?;
            let input_sigops =
                rbitcoin_consensus::block::prevout_spk_sigops(inp, script, bip16, witness);
            acc.in_n = acc.in_n.saturating_add(1);
            acc.batch_n = acc.batch_n.saturating_add(1);
            #[cfg(debug_assertions)]
            crate::block_pipeline::test_phase::tl_note_batch_hit();
            return Ok(ResolvedPrevout {
                txout: TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: ScriptBuf::new(),
                },
                shared: need_script_buf.then(|| pinned.into_shared_prevout()),
                input_sigops,
                create_fk: prev_fk,
            });
        } else if batch_parents.contains(prev_fk) {
            acc.cold_vout_miss_n = acc.cold_vout_miss_n.saturating_add(1);
            #[cfg(debug_assertions)]
            crate::block_pipeline::test_phase::tl_note_cold_why_vout_miss();
            return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: pin incomplete outs for spent parent vout",
            )));
        }
    }

    Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
        "invariant: lookup stage miss (assemble parent create_fk)",
    )))
}
