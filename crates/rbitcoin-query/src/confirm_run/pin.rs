//! Pin denserels / spend abs layouts for wire confirm.

use super::*;

#[doc(hidden)]
pub type CreatePin = crate::CreatePin;

#[doc(hidden)]
pub struct PlanSpend<'a> {
    pub spend_edges: std::borrow::Cow<'a, crate::SpendEdges>,
    pub parent_vouts: U64Map<Vec<u32>>,
    pub vouts_from_stamp: bool,
    pub batch_pin_by_id: U64Map<&'a CreatePin>,
}

#[doc(hidden)]
pub fn spend_edges_from_plan<'a>(
    plan: &'a crate::ArchiveWritePlan,
    parent_pin: &mut ParentPinStamp,
) -> Result<PlanSpend<'a>, ConfirmError> {
    if plan.edges.is_empty() && !plan.planned_fks.is_empty() {
        return Err(ConfirmError::Store(StoreError::Corrupt(
            "invariant: plan spend edges empty",
        )));
    }
    let spend_edges = std::borrow::Cow::Borrowed(&plan.edges);
    let fill_vouts = parent_pin.parent_vouts.is_empty();
    let (parent_vouts, vouts_from_stamp) = if fill_vouts {
        let planned_ids = if plan.per_header_ranges.is_empty() {
            plan.planned_create_ids()
        } else {
            crate::U64Set::default()
        };
        let mut parent_vouts: U64Map<Vec<u32>> = U64Map::default();
        for eds in plan.edges.values() {
            for e in eds {
                let Some(pid) = e.create_fk.get() else {
                    continue;
                };
                if plan.create_in_planned_or_header(e.spend_fk, pid, &planned_ids) {
                    continue;
                }
                parent_vouts.entry(pid).or_default().push(e.vout);
            }
        }
        (parent_vouts, false)
    } else {
        (std::mem::take(&mut parent_pin.parent_vouts), true)
    };
    let mut batch_pin_by_id: U64Map<&CreatePin> = U64Map::default();
    if !parent_vouts.is_empty() {
        for ((pin, _ins), fk) in plan.packed.iter().zip(plan.planned_fks.iter()) {
            if let Some(id) = fk.get() {
                if parent_vouts.contains_key(&id) {
                    batch_pin_by_id.insert(id, pin);
                }
            }
        }
    }
    Ok(PlanSpend {
        spend_edges,
        parent_vouts,
        vouts_from_stamp,
        batch_pin_by_id,
    })
}

#[doc(hidden)]
pub fn spend_edges_from_stamp(
    parent_pin: &ParentPinStamp,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
) -> (crate::SpendEdges, U64Map<Vec<u32>>) {
    let copies = super::lookup::batch_copies_from_metas(metas);
    let mut spend_edges = crate::SpendEdges::default();
    let mut parent_vouts: U64Map<Vec<u32>> = U64Map::default();
    for (m, block) in metas.iter().zip(wire_blocks.iter()) {
        for (ti, tx) in block.txdata.iter().enumerate() {
            let Some(sfk) = m.tx_fks.get(ti).and_then(|f| f.get()) else {
                continue;
            };
            let spender = rbitcoin_primitives::Fk(sfk);
            let mut edges = Vec::with_capacity(tx.input.len());
            for (vin, inp) in tx.input.iter().enumerate() {
                let vin = vin as u32;
                if inp.previous_output.is_null() {
                    edges.push(crate::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: spender,
                        create_fk: rbitcoin_primitives::Fk::NULL,
                        vin,
                    });
                    continue;
                }
                let prev_txid = inp.previous_output.txid.to_byte_array();
                let vout = inp.previous_output.vout;
                let repeats: Option<Vec<rbitcoin_primitives::Fk>> = copies
                    .repeats
                    .get(&prev_txid)
                    .map(|ids| ids.iter().copied().map(rbitcoin_primitives::Fk).collect());
                // Newest copy before this spend, else a connected copy, else
                // the later in-batch copy (structural rejects that as not a coin).
                let pid = crate::archive::batch_copy_before(
                    copies
                        .latest
                        .get(&prev_txid)
                        .copied()
                        .map(rbitcoin_primitives::Fk),
                    repeats.as_deref(),
                    spender,
                )
                .map(|fk| fk.0)
                .or_else(|| parent_pin.resolved.get(&prev_txid).copied())
                .or_else(|| copies.latest.get(&prev_txid).copied());
                if let Some(pid) = pid {
                    edges.push(crate::SpendEdge {
                        prev_txid,
                        vout,
                        spend_fk: spender,
                        create_fk: rbitcoin_primitives::Fk(pid),
                        vin,
                    });
                    parent_vouts.entry(pid).or_default().push(vout);
                    continue;
                }
                edges.push(crate::SpendEdge {
                    prev_txid,
                    vout,
                    spend_fk: spender,
                    create_fk: rbitcoin_primitives::Fk::NULL,
                    vin,
                });
            }
            spend_edges.insert(sfk, edges);
        }
    }
    (spend_edges, parent_vouts)
}

#[doc(hidden)]
pub fn fill_pins(
    parent_vouts: &U64Map<Vec<u32>>,
    batch_pin_by_id: &U64Map<&CreatePin>,
    parent_pin: &ParentPinStamp,
    in_flight: Option<&crate::InFlight>,
    stats: &crate::ConfirmStats,
) -> U64Map<CreatePin> {
    let mut plan_by_id: U64Map<CreatePin> = U64Map::default();
    for id in parent_vouts.keys() {
        if let Some(pin) = batch_pin_by_id.get(id) {
            plan_by_id.insert(*id, std::sync::Arc::clone(pin));
        }
    }
    if let Some(ifo) = in_flight {
        if let Some(min_out) = ifo.min_out_id() {
            for id in parent_vouts.keys() {
                if plan_by_id.contains_key(id) || *id < min_out {
                    continue;
                }
                if let Some(pin) = ifo.get_out(*id) {
                    plan_by_id.insert(*id, std::sync::Arc::clone(pin));
                }
            }
        }
    }
    let t_recent = Instant::now();
    for (id, need) in parent_vouts {
        if plan_by_id.contains_key(id) {
            continue;
        }
        let Some(pin) = parent_pin.create_pin(*id).cloned() else {
            continue;
        };
        if !need.iter().all(|&v| pin.contains_vout(v)) {
            continue;
        }
        plan_by_id.insert(*id, pin);
    }
    let recent_outs_ns = t_recent.elapsed().as_nanos() as u64;
    crate::note_confirm(&stats.pin_recent_outs_ns, recent_outs_ns);
    plan_by_id
}

/// Schema 25 leaves `input_count` at 0, which stays unknown. More than one
/// input is not a coinbase.
#[doc(hidden)]
pub fn coinbase_flag(input_count: u32) -> Option<bool> {
    if input_count > 1 {
        Some(false)
    } else {
        None
    }
}

#[doc(hidden)]
pub fn apply_plan_pins(
    parent_vouts: &U64Map<Vec<u32>>,
    plan_by_id: &U64Map<CreatePin>,
    parent_pin: &ParentPinStamp,
    batch_parents: &mut crate::BatchParents,
    still_need: &mut U64Map<Vec<u32>>,
) -> u64 {
    let mut n_plan_pin = 0u64;
    for (id, need) in parent_vouts {
        let fk = rbitcoin_primitives::Fk(*id);
        if !need.is_empty() && batch_parents.pin_covered(fk, need) {
            if let Some(pin) = plan_by_id.get(id) {
                let tx = pin.tx();
                let cb = coinbase_flag(tx.input_count);
                let plan_range = parent_pin.body_range(*id);
                if cb.is_some() || plan_range.is_some() {
                    batch_parents.refresh_pin_meta(fk, cb, plan_range, Vec::new());
                }
            }
            n_plan_pin = n_plan_pin.saturating_add(1);
            continue;
        }
        if let Some(pin) = plan_by_id.get(id) {
            if !need.iter().all(|&v| pin.contains_vout(v)) {
                still_need.insert(*id, need.clone());
                continue;
            }
            let cb = coinbase_flag(pin.tx().input_count);
            let plan_range = parent_pin.body_range(*id);
            batch_parents.insert_create_pin(
                fk,
                std::sync::Arc::clone(pin),
                need.clone(),
                cb,
                plan_range,
                Vec::new(),
            );
            n_plan_pin = n_plan_pin.saturating_add(1);
        } else {
            still_need.insert(*id, need.clone());
        }
    }
    n_plan_pin
}

/// Core `CheckTxInputs`: a spend of `vout >= n_out` on a resolved parent is
/// `bad-txns-inputs-missingorspent`.
///
/// The wire `vout` is peer-chosen. It is checked against the lookup-stamped
/// `create.loc` count, or the full wire tx of a batch / in-flight pin, before
/// any body read. A short load after this point stays store `Corrupt`.
#[doc(hidden)]
pub fn reject_vout_past_n_out(
    parent_vouts: &U64Map<Vec<u32>>,
    parent_pin: &ParentPinStamp,
    plan_by_id: &U64Map<CreatePin>,
) -> Result<(), ConfirmError> {
    for (id, need) in parent_vouts {
        let Some(&max_vout) = need.iter().max() else {
            continue;
        };
        let wire_n_out = || {
            let pin = plan_by_id.get(id)?;
            pin.wire_tx_index()?;
            Some(pin.n_out() as u64)
        };
        let n_out = parent_pin.n_out(*id).map(u64::from).or_else(wire_n_out);
        rbitcoin_consensus::block::reject_vout_past_n_out(max_vout, n_out)?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
#[doc(hidden)]
pub fn denserels_by_stamped_range(
    query: &Query,
    parent_pin: &ParentPinStamp,
    still_need: &mut U64Map<Vec<u32>>,
    batch_parents: &mut crate::BatchParents,
) -> Result<(u64, u64), ConfirmError> {
    let mut range_jobs: Vec<(rbitcoin_primitives::Fk, (u64, u64), [u8; 32], u32, Vec<u32>)> =
        Vec::new();
    let pending = std::mem::take(still_need);
    for (id, need) in pending {
        let Some(range) = parent_pin.body_range(id) else {
            still_need.insert(id, need);
            continue;
        };
        let Some(n_out) = parent_pin.n_out(id) else {
            still_need.insert(id, need);
            continue;
        };
        let tid = parent_pin.create_txid(id);
        let Some(tid) = tid else {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: lookup stage miss (load parent create identity not stamped)",
            )));
        };
        range_jobs.push((rbitcoin_primitives::Fk(id), range, tid, n_out, need));
    }
    if range_jobs.is_empty() {
        return Ok((0, 0));
    }
    let n_range = range_jobs.len() as u64;
    let (decoded, body_ns, dec_ns, extend_n, body_sqe_n, guess_full_n) = query
        .store()
        .get_outs_by_range_batch(&range_jobs)
        .map_err(ConfirmError::from)?;
    let rng_ns = body_ns.saturating_add(dec_ns);
    // Zero adds are a no-op inside `note_confirm`.
    crate::note_confirm(&query.confirm_stats().cold_io_ns, rng_ns);
    crate::note_confirm(&query.confirm_stats().cold_range_ns, rng_ns);
    crate::note_confirm(&query.confirm_stats().cold_range_body_ns, body_ns);
    crate::note_confirm(&query.confirm_stats().cold_range_decode_ns, dec_ns);
    crate::note_confirm(&query.confirm_stats().cold_range_n, n_range);
    crate::note_confirm(&query.confirm_stats().cold_range_extend_n, extend_n);
    crate::note_confirm(&query.confirm_stats().cold_range_body_sqe_n, body_sqe_n);
    crate::note_confirm(&query.confirm_stats().cold_range_guess_full_n, guess_full_n);
    crate::note_confirm(&query.confirm_stats().body_tx_reads, n_range);
    crate::note_confirm(&query.confirm_stats().pin_new, n_range);
    let t_range_fill = Instant::now();
    for ((fk, range, _tid, _n_out, need), row) in range_jobs.into_iter().zip(decoded) {
        let Some(id) = fk.get() else {
            continue;
        };
        let Some((mut tx, live, sparse)) = row else {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: load denserels by range returned none for stamped parent",
            )));
        };
        if live.len() != need.len() {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: load denserels by range incomplete outs for need_vouts",
            )));
        }
        if tx.txid == [0u8; 32] {
            tx.txid =
                parent_pin
                    .create_txid(id)
                    .ok_or(ConfirmError::Store(StoreError::Corrupt(
                        "invariant: lookup stage miss (load parent create identity not stamped)",
                    )))?;
        }
        // Schema 25 meta leaves input_count at 0. That stays "unknown":
        // coinbase_fk_at_heights still runs, and a pread of input.loc per
        // parent would sit on this range-load loop.
        let cb = coinbase_flag(tx.input_count);
        batch_parents.insert_owned(fk, tx, live, need, cb, Some(range), sparse);
        still_need.remove(&id);
    }
    let range_fill_ns = t_range_fill.elapsed().as_nanos() as u64;
    // `note_confirm` ignores a zero add, so a `> 0` gate is the same call.
    crate::note_confirm(&query.confirm_stats().pin_range_fill_ns, range_fill_ns);
    Ok((n_range, rng_ns))
}

/// Pin parents for wire load: **only spent parents** (sparse outs).
///
/// Sources: plan/in-flight offline denserels → stamp-carried CreatePin →
/// **txout body by range** from [`ParentPinStamp`] (lookup-stamped). Load never
/// reads head / `tx.idx` / `txid.body`. Load **copies** lookup-stamped
/// `spent_range` onto pins. Write [`collect_spend_abs_after_fill`] is abs-or-Corrupt.
pub fn pin_for_wire_batch<'a>(
    query: &Query,
    plan: Option<&'a crate::ArchiveWritePlan>,
    parent_pin: &mut ParentPinStamp,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    in_flight: Option<&crate::InFlight>,
) -> Result<(crate::BatchParents, std::borrow::Cow<'a, crate::SpendEdges>), ConfirmError> {
    let t_pin = Instant::now();
    let t_thin = Instant::now();

    let PlanSpend {
        spend_edges,
        mut parent_vouts,
        vouts_from_stamp,
        batch_pin_by_id,
    } = match plan {
        Some(p) => spend_edges_from_plan(p, parent_pin)?,
        None => {
            let (edges, vouts) = spend_edges_from_stamp(parent_pin, metas, wire_blocks);
            PlanSpend {
                spend_edges: std::borrow::Cow::Owned(edges),
                parent_vouts: vouts,
                vouts_from_stamp: false,
                batch_pin_by_id: U64Map::default(),
            }
        }
    };

    if !vouts_from_stamp {
        for vouts in parent_vouts.values_mut() {
            vouts.sort_unstable();
            vouts.dedup();
        }
    }

    let edges_ns = t_thin.elapsed().as_nanos() as u64;
    let t_fill = Instant::now();
    let plan_by_id = fill_pins(
        &parent_vouts,
        &batch_pin_by_id,
        parent_pin,
        in_flight,
        query.confirm_stats(),
    );
    let fill_ns = t_fill.elapsed().as_nanos() as u64;
    let t_reject = Instant::now();
    reject_vout_past_n_out(&parent_vouts, parent_pin, &plan_by_id)?;
    let reject_ns = t_reject.elapsed().as_nanos() as u64;

    let mut batch_parents = crate::BatchParents::with_capacity(parent_vouts.len());
    let thin_ns = edges_ns.saturating_add(fill_ns).saturating_add(reject_ns);
    crate::note_confirm(&query.confirm_stats().thin_edges_ns, edges_ns);
    crate::note_confirm(&query.confirm_stats().thin_fill_ns, fill_ns);
    crate::note_confirm(&query.confirm_stats().thin_reject_ns, reject_ns);
    crate::note_confirm(&query.confirm_stats().thin_ns, thin_ns);
    let mut still_need: U64Map<Vec<u32>> = U64Map::default();

    let t_plan = Instant::now();
    let n_plan_pin = apply_plan_pins(
        &parent_vouts,
        &plan_by_id,
        parent_pin,
        &mut batch_parents,
        &mut still_need,
    );
    let plan_pin_ns = t_plan.elapsed().as_nanos() as u64;

    let (n_range_new, cold_range_batch_ns) =
        denserels_by_stamped_range(query, parent_pin, &mut still_need, &mut batch_parents)?;

    for id in parent_vouts.keys() {
        if let Some(sr) = parent_pin.spent_range(*id) {
            batch_parents.set_spent_range_only(rbitcoin_primitives::Fk(*id), sr);
        }
    }

    if !still_need.is_empty() {
        return Err(ConfirmError::Store(StoreError::Corrupt(
            "invariant: lookup stage miss (load parent without body_range denserels)",
        )));
    }

    let t_contract = Instant::now();
    #[cfg(debug_assertions)]
    {
        for (id, need) in &parent_vouts {
            let fk = rbitcoin_primitives::Fk(*id);
            debug_assert!(
                batch_parents.contains(fk),
                "invariant: wire pin missing spent parent"
            );
            debug_assert!(
                need.is_empty() || batch_parents.pin_covered(fk, need),
                "invariant: wire pin incomplete outs for spent parent"
            );
        }
    }
    let contract_ns = t_contract.elapsed().as_nanos() as u64;

    let n_unique = parent_vouts.len() as u64;
    crate::note_confirm(&query.confirm_stats().parent_unique, n_unique);
    crate::note_confirm(&query.confirm_stats().utxo_parents, n_unique);
    crate::note_confirm(&query.confirm_stats().pin_plan, n_plan_pin);
    crate::note_confirm(&query.confirm_stats().pin_cache_body, n_plan_pin);
    crate::note_confirm(&query.confirm_stats().plan_pin_ns, plan_pin_ns);
    crate::note_confirm(&query.confirm_stats().pin_contract_ns, contract_ns);
    query.confirm_stats().note_last_pin(
        plan_pin_ns,
        cold_range_batch_ns,
        contract_ns,
        n_plan_pin,
        n_range_new,
    );
    let pin_ns = t_pin.elapsed().as_nanos() as u64;
    crate::note_confirm(&query.confirm_stats().parent_pin_ns, pin_ns);
    crate::note_confirm(&query.confirm_stats().pin_body_ns, pin_ns);
    crate::note_confirm(&query.confirm_stats().load_win_ns, pin_ns);
    let n_blks = metas.len() as u64;
    crate::note_confirm(&query.confirm_stats().load_blocks, n_blks);

    Ok((batch_parents, spend_edges))
}

/// One `spend_abs_jobs` walk per prepared block, after fill has stamped ranges.
///
/// Missing in-range abs is the ensure `Corrupt`. The write phase returns that
/// before `tx.head` insert and passes the jobs to structural, which does not
/// look them up again. Null create fk is skipped; duplicate abs is one job.
pub fn collect_spend_abs_after_fill(
    batch_parents: &crate::BatchParents,
    prepared: &[Prepared],
) -> Result<Vec<Vec<crate::block_pipeline::StructuralAbsJob>>, ConfirmError> {
    let mut out = Vec::with_capacity(prepared.len());
    for p in prepared {
        let jobs = batch_parents
            .spend_abs_jobs(
                p.spends
                    .iter()
                    .map(|&(_txid, vout, sfk, cfk, vin)| (cfk, vout, sfk, vin)),
            )
            .map_err(|_| {
                ConfirmError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels/abs incomplete for spend edge",
                ))
            })?;
        out.push(jobs);
    }
    Ok(out)
}

/// Ensure spend abs for every spend edge on the write batch.
///
/// Lookup stamps archived-parent spent ranges; load copies them onto
/// the pin. Same-batch abs comes from append RAM in write fill. Missing
/// abs is `Corrupt`. Never `put_spend*` and never preads `create.loc`.
///
/// Direct tests keep this walk, including its skip of a null spend fk.
/// [`collect_spend_abs_after_fill`] is the write-phase post-condition.
#[cfg(debug_assertions)]
pub fn ensure_spend_abs_layouts(
    batch_parents: &crate::BatchParents,
    prepared: &[Prepared],
) -> Result<(), ConfirmError> {
    for p in prepared {
        for &(_txid, vout, sfk, cfk, _vin) in &p.spends {
            if sfk.is_null() || cfk.is_null() {
                continue;
            }
            if batch_parents.get_spender_abs(cfk, vout).is_none() {
                return Err(ConfirmError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels/abs incomplete for spend edge",
                )));
            }
        }
    }
    Ok(())
}
