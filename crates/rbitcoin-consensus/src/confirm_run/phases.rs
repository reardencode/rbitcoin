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
    batch_thin: &rbitcoin_query::BatchThin,
) -> Result<Vec<Prepared>, ConsensusError> {
    // Provisional same-run double-spend only (not durable spentness).
    let mut pending_spent: HashSet<([u8; 32], u32)> = HashSet::new();
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
                for h in start..=prev_h.0 {
                    if let Some(plan) = query.confirm_parent_cache().get_header_plan(h) {
                        times.push(plan.header_rec.timestamp);
                        if h == prev_h.0 && plan.header_rec.hash != prev_hash {
                            return Err(ConsensusError::BadPrev);
                        }
                    } else if let Some((_fk, rec)) = query
                        .header_at_height(Height(h))
                        .map_err(ConsensusError::from)?
                    {
                        times.push(rec.timestamp);
                        if h == prev_h.0 && rec.hash != prev_hash {
                            return Err(ConsensusError::BadPrev);
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

                if query
                    .header_at_height(prev_h)
                    .map_err(ConsensusError::from)?
                    .is_some()
                {
                    validate_header(query, params, height, &block.header)?;
                } else if let Some(prev_plan) =
                    query.confirm_parent_cache().get_header_plan(prev_h.0)
                {
                    if let Some(cp) = params.checkpoint_at(height) {
                        if cp.to_byte_array() != block_hash {
                            return Err(ConsensusError::BadHeader("checkpoint mismatch"));
                        }
                    }
                    let prev_bits =
                        bitcoin::CompactTarget::from_consensus(prev_plan.header_rec.bits);
                    let expected = expected_bits_extending(
                        query,
                        params,
                        height,
                        prev_bits,
                        prev_plan.header_rec.timestamp,
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
                    return Err(ConsensusError::Store(StoreError::Corrupt(
                        "confirm: load incomplete (parent header plan missing above tip)",
                    )));
                }
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
            if let Some(cp) = params.checkpoint_at(height) {
                if cp.to_byte_array() != block_hash {
                    return Err(ConsensusError::BadHeader("checkpoint mismatch"));
                }
            }
            let expected = expected_bits_extending(query, params, height, prev.bits, prev.time)?;
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
            batch_thin,
            &meta.txids,
            prev_mtp,
            &block_hash,
            bip16_active,
            Some(block),
            Some(meta.pres.as_ref()),
        )?;
        confirm_phase_stats::CONNECT_NS
            .fetch_add(t_connect.elapsed().as_nanos() as u64, Ordering::Relaxed);

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
    meta_by_abs: &mut rbitcoin_query::U64Map<(rbitcoin_primitives::Fk, u8)>,
) -> Result<crate::block::StructuralPhaseNs, ConsensusError> {
    use crate::block::StructuralPhaseNs;
    let t0 = Instant::now();
    let mut pending_spent: HashSet<([u8; 32], u32)> = HashSet::new();
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
            meta_by_abs,
            &run_create_height,
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
    confirm_phase_stats::STRUCTURAL_NS.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_SPENT_NS.fetch_add(tot.spent_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_SPENT_ABS_NS.fetch_add(tot.spent_abs_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_SPENT_STRONG_NS
        .fetch_add(tot.spent_strong_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_SPENT_COLD_NS.fetch_add(tot.spent_cold_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_SPENT_PENDING_NS
        .fetch_add(tot.spent_pending_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_CREATE_H_NS.fetch_add(tot.create_h_ns, Ordering::Relaxed);
    confirm_phase_stats::STRUCTURAL_BIP68_NS.fetch_add(tot.bip68_ns, Ordering::Relaxed);
    Ok(tot)
}

/// Verify script jobs in `prepared` (CPU only). Skips jobs whose txid is in
/// `preverified` (mempool already consensus-checked at accept).
pub(super) fn script_wave(
    prepared: &[Prepared],
    preverified: &ScriptPreverified,
) -> Result<(), ConsensusError> {
    let t_script = Instant::now();
    let mut all_jobs: Vec<&ScriptCheckJob> = Vec::new();
    let mut n_skip = 0u64;
    for p in prepared {
        if !p.check_scripts {
            continue;
        }
        for job in &p.jobs {
            if preverified.contains(&job.txid) {
                n_skip = n_skip.saturating_add(1);
                continue;
            }
            all_jobs.push(job);
        }
    }
    if n_skip > 0 {
        confirm_phase_stats::SCRIPT_SKIP_MEMPOOL.fetch_add(n_skip, Ordering::Relaxed);
    }
    confirm_phase_stats::SCRIPT_JOBS.fetch_add(all_jobs.len() as u64, Ordering::Relaxed);
    if !all_jobs.is_empty() {
        crate::block::verify_scripts_pool_jobs(&all_jobs)?;
    }
    confirm_phase_stats::SCRIPT_NS
        .fetch_add(t_script.elapsed().as_nanos() as u64, Ordering::Relaxed);
    Ok(())
}

pub(super) fn class_c_commit(
    query: &Query,
    prepared: &mut [Prepared],
    write_create_pins: &FkMap<rbitcoin_query::CreatePin>,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    use rbitcoin_query::class_c_phase_stats::{STRONG_NS, TIP_NS};
    use std::sync::atomic::Ordering as QOrd;

    // CLASS_C_NS = strong + tip only (not join wall). SH runs in parallel and
    // has its own SCRIPTHASH_NS / SH_* meters — do not fold SH into class_c.
    let strong0 = STRONG_NS.load(QOrd::Relaxed);
    let tip0 = TIP_NS.load(QOrd::Relaxed);
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
    let strong_d = STRONG_NS.load(QOrd::Relaxed).saturating_sub(strong0);
    let tip_d = TIP_NS.load(QOrd::Relaxed).saturating_sub(tip0);
    confirm_phase_stats::CLASS_C_NS.fetch_add(strong_d.saturating_add(tip_d), Ordering::Relaxed);
    Ok(out)
}

/// Returns `(spend_ann_ns, tip_gc_ns)` measured with local `Instant`s.
///
/// Pure-write annotate: body meta from `meta_by_abs` (structural snapshot);
/// no body pread. Backend from global `RBITCOIN_IO`.
pub(super) fn post_commit(
    query: &Query,
    prepared: &[Prepared],
    batch_parents: &rbitcoin_query::BatchParents,
    meta_by_abs: &rbitcoin_query::U64Map<(rbitcoin_primitives::Fk, u8)>,
) -> Result<(u64, u64), ConsensusError> {
    // Load pin must supply denserels + body_range so every edge has abs layout — one path only.
    let t_spent = Instant::now();
    if query.spend_index_enabled() {
        let mut abs_edges: Vec<(u64, rbitcoin_primitives::Fk, u32, rbitcoin_primitives::Fk)> =
            Vec::new();
        let mut known: Vec<(rbitcoin_primitives::Fk, u8)> = Vec::new();
        let mut n_skip = 0u64;
        for p in prepared {
            for &(_txid, vout, sfk, cfk) in &p.spends {
                if sfk.is_null() || cfk.is_null() {
                    n_skip = n_skip.saturating_add(1);
                    continue;
                }
                let Some(abs) = batch_parents.get_spender_abs(cfk, vout) else {
                    return Err(ConsensusError::Store(StoreError::Corrupt(
                        "invariant: spend annotate missing pin denserels/abs",
                    )));
                };
                let Some(&(field, flags)) = meta_by_abs.get(&abs) else {
                    return Err(ConsensusError::Store(StoreError::Corrupt(
                        "invariant: spend annotate missing structural meta (cold forbidden)",
                    )));
                };
                abs_edges.push((abs, cfk, vout, sfk));
                known.push((field, flags));
            }
        }
        confirm_phase_stats::SPEND_ANNOTATE_SKIP.fetch_add(n_skip, Ordering::Relaxed);
        if !abs_edges.is_empty() {
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
            confirm_phase_stats::SPEND_ANN_NS.fetch_add(ann_ns, Ordering::Relaxed);
            confirm_phase_stats::SPEND_ANN_N.fetch_add(abs_edges.len() as u64, Ordering::Relaxed);
            let _ = backend;
            confirm_phase_stats::SPEND_ANNOTATE_RANGED
                .fetch_add(abs_edges.len() as u64, Ordering::Relaxed);
            confirm_phase_stats::SPEND_ANN_PREAD_SKIP
                .fetch_add(abs_edges.len() as u64, Ordering::Relaxed);
        }
    }
    let spend_ann_ns = t_spent.elapsed().as_nanos() as u64;
    confirm_phase_stats::UTXO_APPLY_NS.fetch_add(spend_ann_ns, Ordering::Relaxed);

    // Header-cache GC is load-owned (polls store tip each pack). Write does
    // not lock ConfirmParentCache.
    let tip_gc_ns = 0u64;
    Ok((spend_ann_ns, tip_gc_ns))
}

pub(super) fn check_bip34(block: &Block, height: u32) -> Result<(), ConsensusError> {
    let coinbase = &block.txdata[0];
    let bytes = coinbase.input[0].script_sig.as_bytes();
    let expected = bip34_height_script(height);
    if bytes.len() < expected.len() || &bytes[..expected.len()] != expected.as_slice() {
        return Err(ConsensusError::BadBlock("bip34 height encoding"));
    }
    Ok(())
}

pub(super) fn expected_bits_extending(
    query: &Query,
    params: &ChainParams,
    height: Height,
    prev_bits: bitcoin::CompactTarget,
    prev_time: u32,
) -> Result<bitcoin::CompactTarget, ConsensusError> {
    use bitcoin::CompactTarget;
    if height.0 == 0 {
        return Ok(genesis_block(params).header.bits);
    }
    let interval = params.difficulty_adjustment_interval();
    if params.no_pow_retargeting() || !height.0.is_multiple_of(interval) {
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
