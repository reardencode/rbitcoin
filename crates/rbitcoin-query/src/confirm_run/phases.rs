//! Shared confirm phase helpers (load/assemble/structural/script/commit).

use super::*;
use crate::FkMap;
use bitcoin::hashes::Hash;

#[doc(hidden)]
pub fn assemble_parent_mtp_and_bits(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &bitcoin::block::Header,
    hash: [u8; 32],
) -> Result<(u32, Vec<u32>), ConfirmError> {
    let prev_h = Height(height.0 - 1);
    let start = prev_h.0.saturating_sub(10);
    let mut times = Vec::with_capacity(11);
    let mut parent: Option<rbitcoin_consensus::ParentHeader> = None;
    for h in start..=prev_h.0 {
        let (rec_hash, timestamp, bits) =
            if let Some(plan) = query.confirm_parent_cache().get_header_plan(h) {
                (
                    plan.header_rec.hash,
                    plan.header_rec.timestamp,
                    plan.header_rec.bits,
                )
            } else if let Some((_fk, rec)) = query
                .header_at_height(Height(h))
                .map_err(ConfirmError::from)?
            {
                (rec.hash, rec.timestamp, rec.bits)
            } else {
                return Err(ConfirmError::Store(StoreError::Corrupt(
                    "confirm: load incomplete (parent header plan missing above tip)",
                )));
            };
        times.push(timestamp);
        if h == prev_h.0 {
            parent = Some(rbitcoin_consensus::ParentHeader {
                hash: rec_hash,
                time: timestamp,
                bits: bitcoin::CompactTarget::from_consensus(bits),
            });
        }
    }
    let parent = parent.ok_or(ConfirmError::Store(StoreError::Corrupt(
        "confirm: load incomplete (parent header plan missing above tip)",
    )))?;
    let period_first = retarget_first_time(query, params, height.0)?;
    let mtp = rbitcoin_consensus::check_header(
        params,
        height,
        header,
        hash,
        Some(parent),
        &times,
        period_first,
        |h| header_bits_plan_or_store(query, h),
    )?;
    Ok((mtp, times))
}

#[doc(hidden)]
pub fn assemble_chained_header(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &bitcoin::block::Header,
    hash: [u8; 32],
    prev: &Prepared,
    time_window: &[u32],
) -> Result<u32, ConfirmError> {
    let period_first = retarget_first_time(query, params, height.0)?;
    Ok(rbitcoin_consensus::check_header(
        params,
        height,
        header,
        hash,
        Some(rbitcoin_consensus::ParentHeader {
            hash: prev.hash,
            time: prev.time,
            bits: prev.bits,
        }),
        time_window,
        period_first,
        |h| header_bits_plan_or_store(query, h),
    )?)
}

#[doc(hidden)]
pub fn header_bits_plan_or_store(query: &Query, h: u32) -> Option<bitcoin::CompactTarget> {
    if let Some((_fk, rec)) = query.header_at_height(Height(h)).ok().flatten() {
        return Some(bitcoin::CompactTarget::from_consensus(rec.bits));
    }
    query
        .confirm_parent_cache()
        .get_header_plan(h)
        .map(|plan| bitcoin::CompactTarget::from_consensus(plan.header_rec.bits))
}

#[doc(hidden)]
pub fn retarget_first_time(
    query: &Query,
    params: &ChainParams,
    height: u32,
) -> Result<Option<u32>, ConfirmError> {
    let interval = params.difficulty_adjustment_interval();
    let on_boundary = interval > 0 && height.is_multiple_of(interval);
    if !on_boundary || params.no_pow_retargeting() {
        return Ok(None);
    }
    let first_height = Height(height - interval);
    let first = if let Some((_fk, rec)) = query.header_at_height(first_height)? {
        Some(rec.timestamp)
    } else {
        query
            .confirm_parent_cache()
            .get_header_plan(first_height.0)
            .map(|plan| plan.header_rec.timestamp)
    };
    // Missing period-start is the header rule, decided in consensus.
    Ok(rbitcoin_consensus::block::require_retarget_first(
        true, false, first,
    )?)
}

/// Median-time-past uses the last 11 timestamps. Older ones drop.
#[doc(hidden)]
pub fn trim_mtp_window(time_window: &mut Vec<u32>) {
    let overflow = time_window.len().saturating_sub(11);
    time_window.drain(..overflow);
}

pub struct Assembled {
    pub prepared: Vec<Prepared>,
    pub tx_fees: Vec<u64>,
    /// `(base_size, total_size)` parallel to `tx_fees`, from the lookup precompute.
    pub tx_sizes: Vec<(u32, u32)>,
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn assemble_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    metas: Vec<BodyMeta>,
    wire_blocks: &[Arc<Block>],
    batch_parents: &crate::BatchParents,
    spend_edges: &crate::SpendEdges,
    preverified: &ScriptPreverified,
) -> Result<Assembled, ConfirmError> {
    // Provisional same-run double-spend only (not durable spentness).
    let mut pending_spent: crate::OutPointSet = Default::default();
    let mut pending_creates = rbitcoin_consensus::block::PendingCreates::default();
    let mut spent_txids = rbitcoin_consensus::TxidSet::default();
    let mut time_window: Vec<u32> = Vec::with_capacity(11);
    let mut prepared: Vec<Prepared> = Vec::with_capacity(metas.len());
    let mut tx_fees: Vec<u64> = Vec::new();
    let mut tx_sizes: Vec<(u32, u32)> = Vec::new();

    for (i, meta) in metas.into_iter().enumerate() {
        let block = &wire_blocks[i];
        let height = meta.height;
        rbitcoin_consensus::note_block_height(height.0);
        // Once-computed at plan/structure — never rehash `block_hash()` here.
        let block_hash = meta.hash;
        let ctx = ValidationContext::at(params, height, milestone);

        // Prev-block MTP: resolved **once** for header rule + BIP16 + BIP113.
        let prev_mtp: u32;

        if i == 0 {
            if height.0 >= 1 {
                let (mtp, times) =
                    assemble_parent_mtp_and_bits(query, params, height, &block.header, block_hash)?;
                prev_mtp = mtp;
                time_window = times;
            } else {
                prev_mtp = 0;
                validate_header_hashed(query, params, height, &block.header, block_hash)?;
            }
        } else {
            prev_mtp = assemble_chained_header(
                query,
                params,
                height,
                &block.header,
                block_hash,
                &prepared[i - 1],
                &time_window,
            )?;
        }

        rbitcoin_consensus::block::reject_witness_before_segwit(
            block_has_witness_from_pres(&meta.pres),
            params.segwit_active_at(height.0),
        )?;

        // BIP325: full signet challenge on tip confirm only.
        if height.0 > 0 {
            if let Some(challenge) = params.signet_challenge.as_ref() {
                rbitcoin_consensus::validate_signet_block_solution(block, challenge.as_script())?;
            }
        }

        let bip16_active = rbitcoin_consensus::block::bip16_active_from_prev_mtp(
            params,
            height.0,
            &block_hash,
            prev_mtp,
        );

        let t_connect = Instant::now();
        let build_script_jobs =
            !crate::milestone_gate::skips_on_query(milestone, query, height.0, &block_hash);
        let (script_jobs, spends, fees, block_fees, meters) = assemble_block_prevouts(
            block.as_ref(),
            &ctx,
            Some(&meta.tx_fks),
            &mut pending_spent,
            &mut pending_creates,
            &mut spent_txids,
            batch_parents,
            spend_edges,
            &meta.txids,
            prev_mtp,
            &block_hash,
            bip16_active,
            Some(block),
            Some(&meta.pres),
            build_script_jobs,
            preverified,
        )?;
        meters.acc.flush(query.confirm_stats());
        crate::note_confirm(&query.confirm_stats().asm_prevout_ns, meters.prev_ns);
        crate::note_confirm(&query.confirm_stats().asm_job_ns, meters.job_ns);
        if meta.pres.len() != block.txdata.len() {
            return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: txstat size pres",
            )));
        }
        for p in meta.pres.iter() {
            let base = u32::try_from(p.base_size)
                .map_err(|_| rbitcoin_store::StoreError::Corrupt("invariant: txstat size pres"))?;
            let total = u32::try_from(p.total_size)
                .map_err(|_| rbitcoin_store::StoreError::Corrupt("invariant: txstat size pres"))?;
            tx_sizes.push((base, total));
        }
        tx_fees.extend(block_fees);
        crate::note_confirm(
            &query.confirm_stats().connect_ns,
            t_connect.elapsed().as_nanos() as u64,
        );

        time_window.push(block.header.time);
        trim_mtp_window(&mut time_window);

        prepared.push(Prepared {
            height,
            header_fk: meta.header_fk,
            tx_fks: meta.tx_fks,
            jobs: script_jobs,
            spends,
            fees,
            check_scripts: crate::milestone_gate::check_scripts(
                milestone,
                query,
                height.0,
                &block_hash,
            ),
            time: block.header.time,
            bits: block.header.bits,
            hash: block_hash,
            txids: meta.txids,
            prev_mtp,
        });
    }
    Ok(Assembled {
        prepared,
        tx_fees,
        tx_sizes,
    })
}

/// Scratch reused by the confirm write thread. Cleared at each batch.
#[derive(Default)]
pub struct StructuralReuse {
    pub scratch: crate::block_pipeline::StructuralScratch,
    pub pending: crate::block_pipeline::BatchSpent,
}

/// Prepared header at BIP34 height when this write contains that block.
#[doc(hidden)]
pub fn bip34_header_in_write(
    params: &ChainParams,
    prepared: &[Prepared],
) -> Option<bitcoin::BlockHash> {
    params.bip34_hash?;
    let (Some(first), Some(last)) = (prepared.first(), prepared.last()) else {
        return None;
    };
    let h = params.btc.bip34_height;
    if h < first.height.0 || h > last.height.0 {
        return None;
    }
    let block = &prepared[(h - first.height.0) as usize];
    if block.height.0 != h {
        return None;
    }
    Some(bitcoin::BlockHash::from_byte_array(block.hash))
}

/// Ancestor hash for every block in this write. One store read the first
/// time the chain is already past BIP34; after that the remembered hash is
/// reused. The in-write header is not remembered here: Class C does that
/// after the write commits.
#[doc(hidden)]
pub fn bip34_ancestor_for_write(
    query: &Query,
    params: &ChainParams,
    prepared: &[Prepared],
) -> Option<bitcoin::BlockHash> {
    if let Some(hash) = bip34_header_in_write(params, prepared) {
        return Some(hash);
    }
    let first = prepared.first()?;
    if params.bip34_hash.is_none() || first.height.0 <= params.btc.bip34_height {
        return None;
    }
    query.confirmed_bip34_ancestor(params.btc.bip34_height)
}

pub fn remember_connected_bip34(query: &Query, params: &ChainParams, prepared: &[Prepared]) {
    if let Some(hash) = bip34_header_in_write(params, prepared) {
        query.remember_bip34_ancestor(params.btc.bip34_height, Some(hash));
    }
}

/// Durable spentness + maturity + subsidy after scripts (height order).
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn structural_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    prepared: &[Prepared],
    wire_blocks: &[Arc<Block>],
    batch_parents: &crate::BatchParents,
    abs_jobs: &[Vec<crate::block_pipeline::StructuralAbsJob>],
    class_a_wave: &crate::block_pipeline::ClassAWave,
    reuse: &mut StructuralReuse,
) -> Result<
    (
        crate::block_pipeline::StructuralPhaseNs,
        crate::block_pipeline::AnnotateSlots,
    ),
    ConfirmError,
> {
    use crate::block_pipeline::StructuralPhaseNs;
    if abs_jobs.len() != prepared.len() {
        return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: spend abs jobs length",
        )));
    }
    let t0 = Instant::now();
    // Slots and the pack-local double-spend set are this batch only.
    reuse.scratch.begin_batch();
    reuse.pending.clear();
    let index = crate::block_pipeline::RunCreateHeight::from_blocks(
        prepared.iter().map(|p| (p.height.0, p.tx_fks.as_slice())),
    );
    let mut mtp_cache: U32Map<u32> = U32Map::default();
    for p in prepared {
        if p.height.0 > 0 {
            mtp_cache.insert(p.height.0 - 1, p.prev_mtp);
        }
    }
    let mut tot = StructuralPhaseNs::default();
    let bip34_ancestor = bip34_ancestor_for_write(query, params, prepared);
    for (i, p) in prepared.iter().enumerate() {
        rbitcoin_consensus::note_block_height(p.height.0);
        let ctx = ValidationContext::at(params, p.height, milestone);
        let ph = structural_validate_spends(
            query,
            wire_blocks[i].as_ref(),
            &ctx,
            &p.spends,
            p.fees,
            &mut reuse.pending,
            batch_parents,
            &mut mtp_cache,
            &index,
            class_a_wave,
            &mut reuse.scratch,
            &abs_jobs[i],
            bip34_ancestor,
            &p.txids,
        )?;
        tot.spent_ns = tot.spent_ns.saturating_add(ph.spent_ns);
        tot.spent_abs_ns = tot.spent_abs_ns.saturating_add(ph.spent_abs_ns);
        tot.spent_strong_ns = tot.spent_strong_ns.saturating_add(ph.spent_strong_ns);
        tot.spent_cold_ns = tot.spent_cold_ns.saturating_add(ph.spent_cold_ns);
        tot.spent_pending_ns = tot.spent_pending_ns.saturating_add(ph.spent_pending_ns);
        tot.create_h_ns = tot.create_h_ns.saturating_add(ph.create_h_ns);
        tot.bip68_ns = tot.bip68_ns.saturating_add(ph.bip68_ns);
    }
    // Window counters (may race with sampler; last-write uses `tot` instead).
    crate::note_confirm(
        &query.confirm_stats().structural_ns,
        t0.elapsed().as_nanos() as u64,
    );
    crate::note_confirm(&query.confirm_stats().structural_spent_ns, tot.spent_ns);
    crate::note_confirm(
        &query.confirm_stats().structural_spent_abs_ns,
        tot.spent_abs_ns,
    );
    crate::note_confirm(
        &query.confirm_stats().structural_spent_strong_ns,
        tot.spent_strong_ns,
    );
    crate::note_confirm(
        &query.confirm_stats().structural_spent_cold_ns,
        tot.spent_cold_ns,
    );
    crate::note_confirm(
        &query.confirm_stats().structural_spent_pending_ns,
        tot.spent_pending_ns,
    );
    crate::note_confirm(
        &query.confirm_stats().structural_create_h_ns,
        tot.create_h_ns,
    );
    crate::note_confirm(&query.confirm_stats().structural_bip68_ns, tot.bip68_ns);
    Ok((tot, std::mem::take(&mut reuse.scratch.slots)))
}

pub fn class_c_commit(
    query: &Query,
    prepared: &mut [Prepared],
    write_create_pins: &FkMap<crate::CreatePin>,
    header_ranges: &[(rbitcoin_primitives::Fk, rbitcoin_primitives::Fk, u32)],
) -> Result<Vec<rbitcoin_primitives::Fk>, ConfirmError> {
    use std::sync::atomic::Ordering as QOrd;

    let strong0 = query.confirm_stats().strong_ns.load(QOrd::Relaxed);
    let tip0 = query.confirm_stats().tip_ns.load(QOrd::Relaxed);
    let items: Vec<crate::ConfirmPrepared> = prepared
        .iter_mut()
        .map(|p| crate::ConfirmPrepared {
            height: p.height,
            header_fk: p.header_fk,
            tx_fks: std::mem::take(&mut p.tx_fks),
            hash: p.hash,
        })
        .collect();
    let pins = if write_create_pins.is_empty() {
        None
    } else {
        Some(write_create_pins)
    };
    let out = query
        .confirm_blocks_run_with_create_pins(&items, pins, header_ranges)
        .map_err(ConfirmError::from)?;
    let strong_d = query
        .confirm_stats()
        .strong_ns
        .load(QOrd::Relaxed)
        .saturating_sub(strong0);
    let tip_d = query
        .confirm_stats()
        .tip_ns
        .load(QOrd::Relaxed)
        .saturating_sub(tip0);
    crate::note_confirm(
        &query.confirm_stats().class_c_ns,
        strong_d.saturating_add(tip_d),
    );
    Ok(out)
}

/// Returns spend-annotate wall ns measured with a local `Instant`.
///
/// Pure-write annotate from structural slots (no pin `get_spender_abs`).
pub fn post_commit(
    query: &Query,
    slots: &crate::block_pipeline::AnnotateSlots,
) -> Result<u64, ConfirmError> {
    let t_spent = Instant::now();
    if query.spend_index_enabled() && !slots.abs_edges.is_empty() {
        let _utxo_view = query.store().hold_utxo_view();
        let backend = spend_ann_backend_next();
        let t_ann = Instant::now();
        let cold = query
            .store()
            .put_spend_batch_by_abs_meta_known(&slots.abs_edges, &slots.known, backend)
            .map_err(ConfirmError::from)?;
        if !cold.is_empty() {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: spend annotate abs cold (OOB or IO); load/layout bug",
            )));
        }
        let ann_ns = t_ann.elapsed().as_nanos() as u64;
        crate::note_confirm(&query.confirm_stats().spend_ann_ns, ann_ns);
        crate::note_confirm(
            &query.confirm_stats().spend_ann_n,
            slots.abs_edges.len() as u64,
        );
        let _ = backend;
        crate::note_confirm(
            &query.confirm_stats().spend_annotate_ranged,
            slots.abs_edges.len() as u64,
        );
        crate::note_confirm(
            &query.confirm_stats().spend_ann_pread_skip,
            slots.abs_edges.len() as u64,
        );
    }
    let spend_ann_ns = t_spent.elapsed().as_nanos() as u64;
    crate::note_confirm(&query.confirm_stats().utxo_apply_ns, spend_ann_ns);
    Ok(spend_ann_ns)
}

#[cfg(debug_assertions)]
pub fn expected_bits_extending(
    query: &Query,
    params: &ChainParams,
    height: Height,
    prev_bits: bitcoin::CompactTarget,
    prev_time: u32,
    header_time: u32,
) -> Result<bitcoin::CompactTarget, ConfirmError> {
    use rbitcoin_consensus::genesis_block;
    if height.0 == 0 {
        return Ok(genesis_block(params).header.bits);
    }
    let period_first = retarget_first_time(query, params, height.0)?;
    rbitcoin_consensus::block::require_next_work(rbitcoin_consensus::header::next_work_bits(
        params,
        height.0,
        prev_bits,
        prev_time,
        header_time,
        period_first,
        |h| header_bits_plan_or_store(query, h),
    ))
    .map_err(ConfirmError::from)
}
