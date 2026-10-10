//! Shared confirm phase helpers (load/assemble/structural/script/commit).

use super::*;
use rbitcoin_query::FkMap;

fn assemble_parent_mtp_and_bits(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &bitcoin::block::Header,
    block_hash: [u8; 32],
) -> Result<(u32, Vec<u32>), ConsensusError> {
    let prev_h = Height(height.0 - 1);
    let start = prev_h.0.saturating_sub(10);
    let prev_hash = header.prev_blockhash.to_byte_array();
    let mut times = Vec::with_capacity(11);
    let mut prev_bits_raw: Option<u32> = None;
    let mut prev_time: Option<u32> = None;
    for h in start..=prev_h.0 {
        if let Some(plan) = query.confirm_parent_cache().get_header_plan(h) {
            times.push(plan.header_rec.timestamp);
            if h == prev_h.0 {
                if plan.header_rec.hash != prev_hash {
                    return Err(ConsensusError::BadPrev);
                }
                prev_bits_raw = Some(plan.header_rec.bits);
                prev_time = Some(plan.header_rec.timestamp);
            }
        } else if let Some((_fk, rec)) = query
            .header_at_height(Height(h))
            .map_err(ConsensusError::from)?
        {
            times.push(rec.timestamp);
            if h == prev_h.0 {
                if rec.hash != prev_hash {
                    return Err(ConsensusError::BadPrev);
                }
                prev_bits_raw = Some(rec.bits);
                prev_time = Some(rec.timestamp);
            }
        } else {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "confirm: load incomplete (parent header plan missing above tip)",
            )));
        }
    }
    let mtp = median_time_past_times(&times)
        .map_err(|_| ConsensusError::BadHeader("empty median time"))?;
    if header.time <= mtp {
        return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
    }
    check_header_version_and_future_time(params, height, header)?;
    let (Some(prev_bits_raw), Some(prev_time)) = (prev_bits_raw, prev_time) else {
        return Err(ConsensusError::Store(StoreError::Corrupt(
            "confirm: load incomplete (parent header plan missing above tip)",
        )));
    };
    if let Some(cp) = params.checkpoint_at(height) {
        if cp.to_byte_array() != block_hash {
            return Err(ConsensusError::BadHeader("checkpoint mismatch"));
        }
    }
    let prev_bits = bitcoin::CompactTarget::from_consensus(prev_bits_raw);
    let expected =
        expected_bits_extending(query, params, height, prev_bits, prev_time, header.time)?;
    if header.bits != expected {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    Ok((mtp, times))
}

fn assemble_chained_header(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &bitcoin::block::Header,
    block_hash: [u8; 32],
    prev: &Prepared,
    time_window: &[u32],
) -> Result<u32, ConsensusError> {
    if header.prev_blockhash.to_byte_array() != prev.hash {
        return Err(ConsensusError::BadPrev);
    }
    let mtp = median_time_past_times(time_window)
        .map_err(|_| ConsensusError::BadHeader("empty median time"))?;
    if header.time <= mtp {
        return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
    }
    check_header_version_and_future_time(params, height, header)?;
    if let Some(cp) = params.checkpoint_at(height) {
        if cp.to_byte_array() != block_hash {
            return Err(ConsensusError::BadHeader("checkpoint mismatch"));
        }
    }
    let expected =
        expected_bits_extending(query, params, height, prev.bits, prev.time, header.time)?;
    if header.bits != expected {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    Ok(mtp)
}

pub(super) struct Assembled {
    pub(super) prepared: Vec<Prepared>,
    pub(super) tx_fees: Vec<u64>,
    /// `(base_size, total_size)` parallel to `tx_fees`, from the lookup precompute.
    pub(super) tx_sizes: Vec<(u32, u32)>,
}

pub(super) fn assemble_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    metas: Vec<BodyMeta>,
    wire_blocks: &[Arc<Block>],
    batch_parents: &rbitcoin_query::BatchParents,
    spend_edges: &rbitcoin_query::SpendEdges,
) -> Result<Assembled, ConsensusError> {
    // Provisional same-run double-spend only (not durable spentness).
    let mut pending_spent: rbitcoin_query::OutPointSet = Default::default();
    let mut pending_creates = crate::block::PendingCreates::default();
    let mut time_window: Vec<u32> = Vec::with_capacity(11);
    let mut prepared: Vec<Prepared> = Vec::with_capacity(metas.len());
    let mut tx_fees: Vec<u64> = Vec::new();
    let mut tx_sizes: Vec<(u32, u32)> = Vec::new();

    for (i, meta) in metas.into_iter().enumerate() {
        let block = &wire_blocks[i];
        let height = meta.height;
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

        if block_has_witness_from_pres(&meta.pres) && !params.segwit_active_at(height.0) {
            return Err(ConsensusError::BadBlock("unexpected witness before segwit"));
        }

        // BIP325: full signet challenge on tip confirm only.
        if height.0 > 0 {
            if let Some(challenge) = params.signet_challenge.as_ref() {
                crate::signet::validate_signet_block_solution(block, challenge.as_script())?;
            }
        }

        let bip16_active =
            crate::block::bip16_active_from_prev_mtp(params, height.0, &block_hash, prev_mtp);

        let t_connect = Instant::now();
        let (script_jobs, spends, fees, block_fees) = assemble_block_prevouts(
            query,
            block.as_ref(),
            &ctx,
            Some(&meta.tx_fks),
            &mut pending_spent,
            &mut pending_creates,
            batch_parents,
            spend_edges,
            &meta.txids,
            prev_mtp,
            &block_hash,
            bip16_active,
            Some(block),
            Some(&meta.pres),
        )?;
        if meta.pres.len() != block.txdata.len() {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
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
        rbitcoin_query::note_confirm(
            &query.confirm_stats().connect_ns,
            t_connect.elapsed().as_nanos() as u64,
        );

        time_window.push(block.header.time);
        if time_window.len() > 11 {
            let n = time_window.len() - 11;
            time_window.drain(0..n);
        }

        prepared.push(Prepared {
            height,
            header_fk: meta.header_fk,
            tx_fks: meta.tx_fks,
            jobs: script_jobs,
            spends,
            fees,
            check_scripts: crate::milestone::check_scripts(milestone, query, height.0, &block_hash),
            time: block.header.time,
            bits: block.header.bits,
            hash: block_hash,
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
pub(super) struct StructuralReuse {
    pub scratch: crate::block::StructuralScratch,
    pub pending: rbitcoin_query::OutPointSet,
}

/// Durable spentness + maturity + subsidy after scripts (height order).
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub(super) fn structural_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    prepared: &[Prepared],
    wire_blocks: &[Arc<Block>],
    batch_parents: &rbitcoin_query::BatchParents,
    abs_jobs: &[Vec<crate::block::StructuralAbsJob>],
    class_a_wave: &crate::block::ClassAWave,
    reuse: &mut StructuralReuse,
) -> Result<(crate::block::StructuralPhaseNs, crate::block::AnnotateSlots), ConsensusError> {
    use crate::block::StructuralPhaseNs;
    if abs_jobs.len() != prepared.len() {
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: spend abs jobs length",
        )));
    }
    let t0 = Instant::now();
    // Slots and the pack-local double-spend set are this batch only.
    reuse.scratch.begin_batch();
    reuse.pending.clear();
    let index = crate::block::RunCreateHeight::from_blocks(
        prepared.iter().map(|p| (p.height.0, p.tx_fks.as_slice())),
    );
    let mut mtp_cache: U32Map<u32> = U32Map::default();
    for p in prepared {
        if p.height.0 > 0 {
            mtp_cache.insert(p.height.0 - 1, p.prev_mtp);
        }
    }
    let mut tot = StructuralPhaseNs::default();
    for (i, p) in prepared.iter().enumerate() {
        let ctx = ValidationContext::at(params, p.height, milestone);
        let ph = structural_validate_spends(
            query,
            wire_blocks[i].as_ref(),
            &ctx,
            Some(&p.tx_fks),
            &p.spends,
            p.fees,
            &mut reuse.pending,
            batch_parents,
            &mut mtp_cache,
            &index,
            class_a_wave,
            &mut reuse.scratch,
            Some(&abs_jobs[i]),
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
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_ns,
        t0.elapsed().as_nanos() as u64,
    );
    rbitcoin_query::note_confirm(&query.confirm_stats().structural_spent_ns, tot.spent_ns);
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_spent_abs_ns,
        tot.spent_abs_ns,
    );
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_spent_strong_ns,
        tot.spent_strong_ns,
    );
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_spent_cold_ns,
        tot.spent_cold_ns,
    );
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_spent_pending_ns,
        tot.spent_pending_ns,
    );
    rbitcoin_query::note_confirm(
        &query.confirm_stats().structural_create_h_ns,
        tot.create_h_ns,
    );
    rbitcoin_query::note_confirm(&query.confirm_stats().structural_bip68_ns, tot.bip68_ns);
    Ok((tot, std::mem::take(&mut reuse.scratch.slots)))
}

pub(super) fn class_c_commit(
    query: &Query,
    prepared: &mut [Prepared],
    write_create_pins: &FkMap<rbitcoin_query::CreatePin>,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    use std::sync::atomic::Ordering as QOrd;

    let strong0 = query.confirm_stats().strong_ns.load(QOrd::Relaxed);
    let tip0 = query.confirm_stats().tip_ns.load(QOrd::Relaxed);
    let items: Vec<rbitcoin_query::ConfirmPrepared> = prepared
        .iter_mut()
        .map(|p| rbitcoin_query::ConfirmPrepared {
            height: p.height,
            header_fk: p.header_fk,
            tx_fks: std::mem::take(&mut p.tx_fks),
        })
        .collect();
    let pins = if write_create_pins.is_empty() {
        None
    } else {
        Some(write_create_pins)
    };
    let out = query
        .confirm_blocks_run_with_create_pins(&items, pins)
        .map_err(ConsensusError::from)?;
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
    rbitcoin_query::note_confirm(
        &query.confirm_stats().class_c_ns,
        strong_d.saturating_add(tip_d),
    );
    Ok(out)
}

/// Returns spend-annotate wall ns measured with a local `Instant`.
///
/// Pure-write annotate from structural slots (no pin `get_spender_abs`).
pub(super) fn post_commit(
    query: &Query,
    slots: &crate::block::AnnotateSlots,
) -> Result<u64, ConsensusError> {
    let t_spent = Instant::now();
    if query.spend_index_enabled() && !slots.abs_edges.is_empty() {
        let _utxo_view = query.store().hold_utxo_view();
        let backend = spend_ann_backend_next();
        let t_ann = Instant::now();
        let cold = query
            .store()
            .put_spend_batch_by_abs_meta_known(&slots.abs_edges, &slots.known, backend)
            .map_err(ConsensusError::from)?;
        if !cold.is_empty() {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: spend annotate abs cold (OOB or IO); load/layout bug",
            )));
        }
        let ann_ns = t_ann.elapsed().as_nanos() as u64;
        rbitcoin_query::note_confirm(&query.confirm_stats().spend_ann_ns, ann_ns);
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_ann_n,
            slots.abs_edges.len() as u64,
        );
        let _ = backend;
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_annotate_ranged,
            slots.abs_edges.len() as u64,
        );
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_ann_pread_skip,
            slots.abs_edges.len() as u64,
        );
    }
    let spend_ann_ns = t_spent.elapsed().as_nanos() as u64;
    rbitcoin_query::note_confirm(&query.confirm_stats().utxo_apply_ns, spend_ann_ns);
    Ok(spend_ann_ns)
}

pub(super) fn expected_bits_extending(
    query: &Query,
    params: &ChainParams,
    height: Height,
    prev_bits: bitcoin::CompactTarget,
    prev_time: u32,
    header_time: u32,
) -> Result<bitcoin::CompactTarget, ConsensusError> {
    use bitcoin::CompactTarget;
    if height.0 == 0 {
        return Ok(genesis_block(params).header.bits);
    }
    let interval = params.difficulty_adjustment_interval();
    let on_boundary = interval > 0 && height.0.is_multiple_of(interval);
    let period_first = if on_boundary && !params.no_pow_retargeting() {
        // Period-start may still be above confirmed tip during tip-ahead
        // multi-block load (i>0). Lookup/load already put_header_plan.
        let first_height = Height(height.0 - interval);
        let first_ts = if let Some((_fk, rec)) = query
            .header_at_height(first_height)
            .map_err(ConsensusError::from)?
        {
            rec.timestamp
        } else if let Some(plan) = query.confirm_parent_cache().get_header_plan(first_height.0) {
            plan.header_rec.timestamp
        } else {
            return Err(ConsensusError::BadHeader("missing retarget first header"));
        };
        Some(first_ts)
    } else {
        None
    };
    crate::header::next_work_bits(
        params,
        height.0,
        prev_bits,
        prev_time,
        header_time,
        period_first,
        |h| {
            if let Some((_fk, rec)) = query.header_at_height(Height(h)).ok().flatten() {
                return Some(CompactTarget::from_consensus(rec.bits));
            }
            query
                .confirm_parent_cache()
                .get_header_plan(h)
                .map(|plan| CompactTarget::from_consensus(plan.header_rec.bits))
        },
    )
    .ok_or(ConsensusError::BadPrev)
}
