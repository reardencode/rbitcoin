//! Pin denserels / spend abs layouts for wire confirm.

use super::*;

type CreatePin = rbitcoin_query::CreatePin;

struct PlanSpend<'a> {
    spend_edges: rbitcoin_query::SpendEdges,
    parent_vouts: U64Map<Vec<u32>>,
    vouts_from_stamp: bool,
    batch_pin_by_id: U64Map<&'a CreatePin>,
}

fn spend_edges_from_plan<'a>(
    plan: &'a rbitcoin_query::ArchiveWritePlan,
    parent_pin: &mut ParentPinStamp,
) -> Result<PlanSpend<'a>, ConsensusError> {
    let mut batch_pin_by_id: U64Map<&CreatePin> = U64Map::default();
    if plan.batch_pin.len() == plan.planned_fks.len() {
        for (fk, pin) in plan.planned_fks.iter().zip(plan.batch_pin.iter()) {
            if let Some(id) = fk.get() {
                batch_pin_by_id.insert(id, pin);
            }
        }
    } else {
        for ((pin, _ins), fk) in plan.packed.iter().zip(plan.planned_fks.iter()) {
            if let Some(id) = fk.get() {
                batch_pin_by_id.insert(id, pin);
            }
        }
    }
    if plan.edges.is_empty() && !plan.planned_fks.is_empty() {
        return Err(ConsensusError::Store(StoreError::Corrupt(
            "invariant: plan spend edges empty",
        )));
    }
    let spend_edges = plan.edges.clone();
    let fill_vouts = parent_pin.parent_vouts.is_empty();
    let (parent_vouts, vouts_from_stamp) = if fill_vouts {
        let mut parent_vouts: U64Map<Vec<u32>> = U64Map::default();
        for eds in plan.edges.values() {
            for e in eds {
                let Some(pid) = e.create_fk.get() else {
                    continue;
                };
                if plan.create_in_spend_header(e.spend_fk, pid) {
                    continue;
                }
                parent_vouts.entry(pid).or_default().push(e.vout);
            }
        }
        (parent_vouts, false)
    } else {
        (std::mem::take(&mut parent_pin.parent_vouts), true)
    };
    Ok(PlanSpend {
        spend_edges,
        parent_vouts,
        vouts_from_stamp,
        batch_pin_by_id,
    })
}

fn spend_edges_from_stamp(
    parent_pin: &ParentPinStamp,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
) -> (rbitcoin_query::SpendEdges, U64Map<Vec<u32>>) {
    let mut spend_edges = rbitcoin_query::SpendEdges::default();
    let mut parent_vouts: U64Map<Vec<u32>> = U64Map::default();
    for (m, block) in metas.iter().zip(wire_blocks.iter()) {
        for (ti, tx) in block.txdata.iter().enumerate() {
            let Some(sfk) = m.tx_fks.get(ti).and_then(|f| f.get()) else {
                continue;
            };
            let mut edges = Vec::with_capacity(tx.input.len());
            for inp in &tx.input {
                if inp.previous_output.is_null() {
                    edges.push(rbitcoin_query::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: rbitcoin_primitives::Fk(sfk),
                        create_fk: rbitcoin_primitives::Fk::NULL,
                    });
                    continue;
                }
                let prev_txid = inp.previous_output.txid.to_byte_array();
                let vout = inp.previous_output.vout;
                if let Some(&pid) = parent_pin.resolved.get(&prev_txid) {
                    edges.push(rbitcoin_query::SpendEdge {
                        prev_txid,
                        vout,
                        spend_fk: rbitcoin_primitives::Fk(sfk),
                        create_fk: rbitcoin_primitives::Fk(pid),
                    });
                    parent_vouts.entry(pid).or_default().push(vout);
                    continue;
                }
                edges.push(rbitcoin_query::SpendEdge {
                    prev_txid,
                    vout,
                    spend_fk: rbitcoin_primitives::Fk(sfk),
                    create_fk: rbitcoin_primitives::Fk::NULL,
                });
            }
            spend_edges.insert(sfk, edges);
        }
    }
    (spend_edges, parent_vouts)
}

fn fill_pins(
    parent_vouts: &U64Map<Vec<u32>>,
    batch_pin_by_id: &U64Map<&CreatePin>,
    parent_pin: &ParentPinStamp,
    in_flight: Option<&rbitcoin_query::InFlight>,
    stats: &rbitcoin_query::ConfirmStats,
) -> U64Map<CreatePin> {
    let mut plan_by_id: U64Map<CreatePin> = U64Map::default();
    if let Some(ifo) = in_flight {
        for (id, need) in parent_vouts {
            if plan_by_id.contains_key(id) {
                continue;
            }
            if let Some(pin) = ifo.get_out(*id) {
                let _ = need;
                plan_by_id.insert(*id, std::sync::Arc::clone(pin));
            }
        }
    }
    for id in parent_vouts.keys() {
        if plan_by_id.contains_key(id) {
            continue;
        }
        if let Some(pin) = batch_pin_by_id.get(id) {
            plan_by_id.insert(*id, std::sync::Arc::clone(pin));
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
        let (_tx, outs) = pin.as_ref();
        if !need.iter().all(|&v| outs.get(v as usize).is_some()) {
            continue;
        }
        plan_by_id.insert(*id, pin);
    }
    let recent_outs_ns = t_recent.elapsed().as_nanos() as u64;
    if recent_outs_ns > 0 {
        rbitcoin_query::note_confirm(&stats.pin_recent_outs_ns, recent_outs_ns);
    }
    plan_by_id
}

fn apply_plan_pins(
    parent_vouts: &U64Map<Vec<u32>>,
    plan_by_id: &U64Map<CreatePin>,
    parent_pin: &ParentPinStamp,
    batch_parents: &mut rbitcoin_query::BatchParents,
    still_need: &mut U64Map<Vec<u32>>,
) -> u64 {
    let mut n_plan_pin = 0u64;
    for (id, need) in parent_vouts {
        let fk = rbitcoin_primitives::Fk(*id);
        if !need.is_empty() && batch_parents.pin_covered(fk, need) {
            if let Some(pin) = plan_by_id.get(id) {
                let (tx, _outs) = pin.as_ref();
                let cb = if tx.input_count != 1 {
                    Some(false)
                } else {
                    None
                };
                let plan_range = parent_pin.body_range(*id);
                if cb.is_some() || plan_range.is_some() {
                    batch_parents.refresh_pin_meta(fk, cb, plan_range, Vec::new());
                }
            }
            n_plan_pin = n_plan_pin.saturating_add(1);
            continue;
        }
        if let Some(pin) = plan_by_id.get(id) {
            let (tx, outs) = pin.as_ref();
            if !need.iter().all(|&v| outs.get(v as usize).is_some()) {
                still_need.insert(*id, need.clone());
                continue;
            }
            let cb = if tx.input_count != 1 {
                Some(false)
            } else {
                None
            };
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

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
fn denserels_by_stamped_range(
    query: &Query,
    parent_pin: &ParentPinStamp,
    still_need: &mut U64Map<Vec<u32>>,
    batch_parents: &mut rbitcoin_query::BatchParents,
) -> Result<(u64, u64), ConsensusError> {
    let mut range_jobs: Vec<(rbitcoin_primitives::Fk, (u64, u64), [u8; 32], Vec<u32>)> = Vec::new();
    let pending = std::mem::take(still_need);
    for (id, need) in pending {
        let Some(range) = parent_pin.body_range(id) else {
            still_need.insert(id, need);
            continue;
        };
        let tid = parent_pin.create_txid(id);
        let Some(tid) = tid else {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: lookup stage miss (load parent create identity not stamped)",
            )));
        };
        range_jobs.push((rbitcoin_primitives::Fk(id), range, tid, need));
    }
    if range_jobs.is_empty() {
        return Ok((0, 0));
    }
    let n_range = range_jobs.len() as u64;
    let (decoded, body_ns, dec_ns, extend_n, body_sqe_n, guess_full_n) = query
        .store()
        .get_outs_by_range_batch(&range_jobs)
        .map_err(ConsensusError::from)?;
    let rng_ns = body_ns.saturating_add(dec_ns);
    if rng_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().cold_io_ns, rng_ns);
        rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_ns, rng_ns);
    }
    if body_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_body_ns, body_ns);
    }
    if dec_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_decode_ns, dec_ns);
    }
    rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_n, n_range);
    rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_extend_n, extend_n);
    rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_body_sqe_n, body_sqe_n);
    rbitcoin_query::note_confirm(&query.confirm_stats().cold_range_guess_full_n, guess_full_n);
    rbitcoin_query::note_confirm(&query.confirm_stats().body_tx_reads, n_range);
    rbitcoin_query::note_confirm(&query.confirm_stats().pin_new, n_range);
    let t_range_fill = Instant::now();
    for ((fk, range, _tid, need), row) in range_jobs.into_iter().zip(decoded) {
        let Some(id) = fk.get() else {
            continue;
        };
        let Some((mut tx, live, sparse)) = row else {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: load denserels by range returned none for stamped parent",
            )));
        };
        if live.len() != need.len() {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: load denserels by range incomplete outs for need_vouts",
            )));
        }
        if tx.txid == [0u8; 32] {
            tx.txid =
                parent_pin
                    .create_txid(id)
                    .ok_or(ConsensusError::Store(StoreError::Corrupt(
                        "invariant: lookup stage miss (load parent create identity not stamped)",
                    )))?;
        }
        let cb = if tx.input_count != 1 {
            Some(false)
        } else {
            None
        };
        batch_parents.insert_owned(fk, tx, live, need, cb, Some(range), sparse);
        still_need.remove(&id);
    }
    let range_fill_ns = t_range_fill.elapsed().as_nanos() as u64;
    if range_fill_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().pin_range_fill_ns, range_fill_ns);
    }
    Ok((n_range, rng_ns))
}

/// Pin parents for wire load: **only spent parents** (sparse outs).
///
/// Sources: plan/in-flight offline denserels → stamp-carried CreatePin →
/// **txout body by range** from [`ParentPinStamp`] (lookup-stamped). Load never
/// reads head / `tx.idx` / `txid.body`. Load **copies** lookup-stamped
/// `spent_range` onto pins. Write [`ensure_spend_abs_layouts`] is holes-only.
pub(super) fn pin_for_wire_batch(
    query: &Query,
    plan: Option<&rbitcoin_query::ArchiveWritePlan>,
    parent_pin: &mut ParentPinStamp,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    in_flight: Option<&rbitcoin_query::InFlight>,
) -> Result<(rbitcoin_query::BatchParents, rbitcoin_query::SpendEdges), ConsensusError> {
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
                spend_edges: edges,
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

    let plan_by_id = fill_pins(
        &parent_vouts,
        &batch_pin_by_id,
        parent_pin,
        in_flight,
        query.confirm_stats(),
    );

    let mut batch_parents = rbitcoin_query::BatchParents::with_capacity(parent_vouts.len());
    let thin_ns = t_thin.elapsed().as_nanos() as u64;
    if thin_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().thin_ns, thin_ns);
    }
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
        return Err(ConsensusError::Store(StoreError::Corrupt(
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
    if n_unique > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().parent_unique, n_unique);
        rbitcoin_query::note_confirm(&query.confirm_stats().utxo_parents, n_unique);
    }
    if n_plan_pin > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().pin_plan, n_plan_pin);
        rbitcoin_query::note_confirm(&query.confirm_stats().pin_cache_body, n_plan_pin);
    }
    if plan_pin_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().plan_pin_ns, plan_pin_ns);
    }
    if contract_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().pin_contract_ns, contract_ns);
    }
    query.confirm_stats().note_last_pin(
        plan_pin_ns,
        cold_range_batch_ns,
        contract_ns,
        n_plan_pin,
        n_range_new,
    );
    let pin_ns = t_pin.elapsed().as_nanos() as u64;
    if pin_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().parent_pin_ns, pin_ns);
        rbitcoin_query::note_confirm(&query.confirm_stats().pin_body_ns, pin_ns);
        rbitcoin_query::note_confirm(&query.confirm_stats().load_win_ns, pin_ns);
    }
    let n_blks = metas.len() as u64;
    if n_blks > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().load_blocks, n_blks);
    }

    Ok((batch_parents, spend_edges))
}

/// Ensure spend abs for every spend edge on the write batch.
///
/// Lookup stamps archived-parent `spent.idx` ranges; load copies them onto
/// the pin. This idx-stamps remaining holes (same-batch creates after Class A,
/// missing stamp). Missing abs after that is `Corrupt`. Never `put_spend*`.
pub(super) fn ensure_spend_abs_layouts(
    query: &Query,
    batch_parents: &mut rbitcoin_query::BatchParents,
    prepared: &[Prepared],
) -> Result<(), ConsensusError> {
    use rbitcoin_store::IdxBodyMode;

    let mut need: U64Map<Vec<u32>> = U64Map::default();
    for p in prepared {
        for &(_txid, vout, sfk, cfk) in &p.spends {
            if sfk.is_null() || cfk.is_null() {
                continue;
            }
            if batch_parents.get_spender_abs(cfk, vout).is_some() {
                continue;
            }
            if let Some(id) = cfk.get() {
                need.entry(id).or_default().push(vout);
            }
        }
    }
    // Also repair pins that have outs but no layout (structural cold path would
    // skip unpinned; pinned-without-abs fails structural).
    for fk in batch_parents.fks_missing_layout() {
        if let Some(id) = fk.get() {
            need.entry(id).or_default();
        }
    }
    if need.is_empty() {
        return Ok(());
    }
    for vouts in need.values_mut() {
        vouts.sort_unstable();
        vouts.dedup();
    }

    // Stamp spent.body ranges first so abs = spent_off + SLOT×vout (idx only).
    {
        let mut spent_fks: Vec<rbitcoin_primitives::Fk> =
            need.keys().map(|id| rbitcoin_primitives::Fk(*id)).collect();
        spent_fks.sort_unstable_by_key(|f| f.0);
        spent_fks.dedup();
        if !spent_fks.is_empty() {
            let spent = query
                .store()
                .tx_spent_range_batch(&spent_fks)
                .map_err(ConsensusError::from)?;
            for (fk, opt) in spent_fks.iter().zip(spent) {
                if let Some(sr) = opt {
                    batch_parents.set_spent_range_only(*fk, sr);
                }
            }
        }
    }

    let mut ensure_res = 0u64;
    let mut still: U64Map<Vec<u32>> = U64Map::default();
    for (id, need_v) in &need {
        let fk = rbitcoin_primitives::Fk(*id);
        if batch_parents.has_abs_layout(fk)
            && (need_v.is_empty()
                || need_v
                    .iter()
                    .all(|&v| batch_parents.get_spender_abs(fk, v).is_some()))
        {
            ensure_res = ensure_res.saturating_add(1);
            continue;
        }
        still.insert(*id, need_v.clone());
    }
    rbitcoin_query::note_confirm(&query.confirm_stats().ensure_res_hit, ensure_res);

    // Class A denserels body for remainder only — must not re-load pin denserels hits.
    if !still.is_empty() {
        let fks: Vec<rbitcoin_primitives::Fk> = still
            .keys()
            .map(|id| rbitcoin_primitives::Fk(*id))
            .collect();
        rbitcoin_query::note_confirm(&query.confirm_stats().ensure_cold_n, fks.len() as u64);
        let loaded = rbitcoin_query::load_creates_once(query.store(), &fks, IdxBodyMode::Outs)
            .map_err(ConsensusError::from)?;
        let secret = query.store().txs.store_secret();
        for c in loaded {
            let Some(id) = c.fk.get() else {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels null create_fk",
                )));
            };
            let need_v = still.get(&id).cloned().unwrap_or_default();
            let (mut tx, outs, dense_rels) = if let Some(dec) = c.decoded_outs {
                dec
            } else {
                rbitcoin_store::decode_packed_tx_outs_with_spender_rels_secret(&c.raw, Some(secret))
                    .map_err(|_| {
                        ConsensusError::Store(StoreError::Corrupt(
                            "invariant: ensure denserels decode failed",
                        ))
                    })?
            };
            // Write ensure may read txid.body (not load stage).
            tx.txid = known_create_txid_lookup(query, id, None)?;
            if batch_parents.contains(c.fk) {
                batch_parents.set_layout_for_need(c.fk, c.body_range, &dense_rels, &need_v);
                continue;
            }
            // Not pinned at load (e.g. already-archived same-batch create): insert
            // with layout so annotate/structural abs paths work.
            let mut checked = need_v;
            if checked.is_empty() {
                checked = (0..outs.len() as u32).collect();
            }
            let live: Vec<(u32, rbitcoin_store::OutputRecord)> = checked
                .iter()
                .filter_map(|&v| outs.get(v as usize).map(|o| (v, o.clone())))
                .collect();
            if live.len() != checked.len() {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels incomplete outs for need_vouts",
                )));
            }
            let sparse = rbitcoin_query::sparse_spender_rels(&dense_rels, &checked);
            if !rbitcoin_query::layout_covers_need(Some(c.body_range), &sparse, &checked) {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels incomplete for need_vouts",
                )));
            }
            let cb = if tx.input_count != 1 {
                Some(false)
            } else {
                None
            };
            batch_parents.insert_owned(c.fk, tx, live, checked, cb, Some(c.body_range), sparse);
        }
        let mut spent_fks: Vec<rbitcoin_primitives::Fk> = still
            .keys()
            .map(|id| rbitcoin_primitives::Fk(*id))
            .collect();
        spent_fks.sort_unstable_by_key(|f| f.0);
        if !spent_fks.is_empty() {
            let spent = query
                .store()
                .tx_spent_range_batch(&spent_fks)
                .map_err(ConsensusError::from)?;
            for (fk, opt) in spent_fks.iter().zip(spent) {
                if let Some(sr) = opt {
                    batch_parents.set_spent_range_only(*fk, sr);
                }
            }
        }
    }

    for p in prepared {
        for &(_txid, vout, sfk, cfk) in &p.spends {
            if sfk.is_null() || cfk.is_null() {
                continue;
            }
            if batch_parents.get_spender_abs(cfk, vout).is_none() {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: ensure denserels/abs incomplete for spend edge",
                )));
            }
        }
    }
    Ok(())
}
