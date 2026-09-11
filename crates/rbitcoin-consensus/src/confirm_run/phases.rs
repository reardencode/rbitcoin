//! Shared confirm phase helpers (load/assemble/structural/script/commit).

use super::*;
use rbitcoin_query::FkMap;

pub(super) fn assemble_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    metas: Vec<BodyMeta>,
    wire_blocks: &[Arc<Block>],
    batch_parents: &rbitcoin_query::BatchParents,
    spend_edges: &rbitcoin_query::SpendEdges,
) -> Result<Vec<Prepared>, ConsensusError> {
    // Provisional same-run double-spend only (not durable spentness).
    let mut pending_spent: rbitcoin_query::OutPointSet = Default::default();
    let mut pending_creates = crate::block::PendingCreates::default();
    let mut time_window: Vec<u32> = Vec::with_capacity(11);
    let mut prepared: Vec<Prepared> = Vec::with_capacity(metas.len());

    for (i, meta) in metas.into_iter().enumerate() {
        let block = &wire_blocks[i];
        let height = meta.height;
        // Once-computed at plan/structure — never rehash `block_hash()` here.
        let block_hash = meta.hash;
        let ctx = ValidationContext::at(params, height, milestone);

        // Prev-block MTP: resolved **once** for header rule + BIP16 + BIP113.
        let prev_mtp: u32;

        if i == 0 {
            // IBD pipelines load(N+1) ∥ scripts(N) ∥ write(N−1). Tip GC drops
            // header plans for h ≤ tip when write advances tip. Assemble must
            // not snapshot tip once: a concurrent tip_gc can drop plans while
            // our tip read is still the pre-write value → false "plan missing
            // above tip" (retryable load incomplete spam on restart / dense
            // pipeline). Prefer plan when present; else **store** if confirmed.
            if height.0 >= 1 {
                let prev_h = Height(height.0 - 1);
                let start = prev_h.0.saturating_sub(10);
                let prev_hash = block.header.prev_blockhash.to_byte_array();
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
                let mtp = median_time_past_times(&times);
                if block.header.time <= mtp {
                    return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
                }
                prev_mtp = mtp;
                time_window = times;

                // MTP + prev hash already checked. Do not call validate_header
                // (second MTP walk + header rehash).
                check_header_version_and_future_time(params, height, &block.header)?;
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
                let expected = expected_bits_extending(
                    query,
                    params,
                    height,
                    prev_bits,
                    prev_time,
                    block.header.time,
                )?;
                if block.header.bits != expected {
                    return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
                }
                let target = Target::from_compact(block.header.bits);
                if target > params.pow_limit {
                    return Err(ConsensusError::BadHeader("target above pow limit"));
                }
                block
                    .header
                    .validate_pow(target)
                    .map_err(|_| ConsensusError::InvalidPow)?;
            } else {
                prev_mtp = 0;
                validate_header(query, params, height, &block.header)?;
            }
        } else {
            let prev = &prepared[i - 1];
            if block.header.prev_blockhash.to_byte_array() != prev.hash {
                return Err(ConsensusError::BadPrev);
            }
            let mtp = median_time_past_times(&time_window);
            if block.header.time <= mtp {
                return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
            }
            prev_mtp = mtp;
            check_header_version_and_future_time(params, height, &block.header)?;
            if let Some(cp) = params.checkpoint_at(height) {
                if cp.to_byte_array() != block_hash {
                    return Err(ConsensusError::BadHeader("checkpoint mismatch"));
                }
            }
            let expected = expected_bits_extending(
                query,
                params,
                height,
                prev.bits,
                prev.time,
                block.header.time,
            )?;
            if block.header.bits != expected {
                return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
            }
            let target = Target::from_compact(block.header.bits);
            if target > params.pow_limit {
                return Err(ConsensusError::BadHeader("target above pow limit"));
            }
            block
                .header
                .validate_pow(target)
                .map_err(|_| ConsensusError::InvalidPow)?;
        }

        if params.bip34_active_at(height.0) {
            check_bip34(block, height.0)?;
        }
        if block_has_witness(block) && !params.segwit_active_at(height.0) {
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
        let (script_jobs, spends, fees) = assemble_block_prevouts(
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
            check_scripts: !milestone.skips_scripts_at(height.0),
            time: block.header.time,
            bits: block.header.bits,
            hash: block_hash,
            prev_mtp,
        });
    }
    Ok(prepared)
}

/// Durable spentness + maturity + subsidy after scripts (height order).
pub(super) fn structural_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    prepared: &[Prepared],
    wire_blocks: &[Arc<Block>],
    batch_parents: &rbitcoin_query::BatchParents,
    annotate: &mut Vec<crate::block::SpendAnnotateJob>,
) -> Result<crate::block::StructuralPhaseNs, ConsensusError> {
    use crate::block::StructuralPhaseNs;
    let t0 = Instant::now();
    let mut pending_spent: rbitcoin_query::OutPointSet = Default::default();
    let mut mtp_cache: U32Map<u32> = U32Map::default();
    for p in prepared {
        if p.height.0 > 0 {
            mtp_cache.insert(p.height.0 - 1, p.prev_mtp);
        }
    }
    let mut tot = StructuralPhaseNs::default();
    let mut run_create_height: FkMap<u32> = FkMap::default();
    for p in prepared {
        for fk in &p.tx_fks {
            run_create_height.insert(*fk, p.height.0);
        }
    }
    for (i, p) in prepared.iter().enumerate() {
        let ctx = ValidationContext::at(params, p.height, milestone);
        let ph = structural_validate_spends(
            query,
            wire_blocks[i].as_ref(),
            &ctx,
            Some(&p.tx_fks),
            &p.spends,
            p.fees,
            &mut pending_spent,
            batch_parents,
            &mut mtp_cache,
            &run_create_height,
            annotate,
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
    Ok(tot)
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
/// Pure-write annotate from structural abs+meta jobs (no pin `get_spender_abs`).
pub(super) fn post_commit(
    query: &Query,
    annotate: &[crate::block::SpendAnnotateJob],
) -> Result<u64, ConsensusError> {
    let t_spent = Instant::now();
    if query.spend_index_enabled() && !annotate.is_empty() {
        let mut abs_edges: Vec<(u64, rbitcoin_primitives::Fk, u32, rbitcoin_primitives::Fk)> =
            Vec::with_capacity(annotate.len());
        let mut known: Vec<(rbitcoin_primitives::Fk, u8)> = Vec::with_capacity(annotate.len());
        for job in annotate {
            abs_edges.push((job.abs, job.create_fk, job.vout, job.spend_fk));
            known.push((job.field, job.flags));
        }
        let backend = spend_ann_backend_next();
        let t_ann = Instant::now();
        let cold = query
            .store()
            .put_spend_batch_by_abs_meta_known(&abs_edges, &known, backend)
            .map_err(ConsensusError::from)?;
        if !cold.is_empty() {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: spend annotate abs cold (OOB or IO); load/layout bug",
            )));
        }
        let ann_ns = t_ann.elapsed().as_nanos() as u64;
        rbitcoin_query::note_confirm(&query.confirm_stats().spend_ann_ns, ann_ns);
        rbitcoin_query::note_confirm(&query.confirm_stats().spend_ann_n, abs_edges.len() as u64);
        let _ = backend;
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_annotate_ranged,
            abs_edges.len() as u64,
        );
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_ann_pread_skip,
            abs_edges.len() as u64,
        );
    }
    let spend_ann_ns = t_spent.elapsed().as_nanos() as u64;
    rbitcoin_query::note_confirm(&query.confirm_stats().utxo_apply_ns, spend_ann_ns);
    Ok(spend_ann_ns)
}

pub(super) fn check_bip34(block: &Block, height: u32) -> Result<(), ConsensusError> {
    crate::block::check_bip34_coinbase(&block.txdata[0], height)
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
    if !height.0.is_multiple_of(interval) {
        return crate::header::min_difficulty_or_walk(
            query,
            params,
            height,
            prev_bits,
            prev_time,
            header_time,
        );
    }
    if params.no_pow_retargeting() {
        return Ok(prev_bits);
    }
    // Period-start may still be above confirmed tip during tip-ahead multi-block
    // load (i>0). Lookup/load already put_header_plan for that height — use it.
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
    let timespan = prev_time.saturating_sub(first_ts) as u64;
    Ok(CompactTarget::from_next_work_required(
        prev_bits,
        timespan,
        &params.btc,
    ))
}
