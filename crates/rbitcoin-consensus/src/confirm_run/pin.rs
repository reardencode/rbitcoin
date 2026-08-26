//! Pin denserels / spend abs layouts for wire confirm.

use super::*;

/// Pin parents for wire load: **only spent parents** (sparse outs).
///
/// Sources: plan/in-flight offline denserels → RecentCreates create_pin →
/// **txout body by range** from [`ParentPinStamp`] (lookup-stamped). Load never
/// reads head / `tx.idx` / `txid.body`. Load **copies** lookup-stamped
/// `spent_range` onto pins. Write [`ensure_spend_abs_layouts`] is holes-only.
pub(super) fn pin_for_wire_batch(
    query: &Query,
    plan: Option<&rbitcoin_query::ArchiveWritePlan>,
    parent_pin: &mut ParentPinStamp,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    in_flight: Option<&rbitcoin_query::InFlightView>,
    pipeline_parent_store: Option<&std::sync::Arc<rbitcoin_query::PipelineParentStore>>,
) -> Result<
    (
        rbitcoin_query::BatchParents,
        rbitcoin_query::SpendEdges,
        DenserelsWarmStats,
    ),
    ConsensusError,
> {
    use rbitcoin_query::confirm_load_stats;
    use std::sync::atomic::Ordering;

    let t_pin = Instant::now();
    let t_thin = Instant::now();
    let mut spend_edges: rbitcoin_query::SpendEdges = rbitcoin_query::SpendEdges::default();
    let mut parent_vouts: U64Map<Vec<u32>> = U64Map::default();
    let mut n_same_batch = 0u32;
    let mut vouts_from_stamp = false;

    let mut plan_by_id: U64Map<
        std::sync::Arc<(rbitcoin_store::TxRecord, Vec<rbitcoin_store::OutputRecord>)>,
    > = U64Map::default();
    let mut batch_pin_by_id: U64Map<
        &std::sync::Arc<(rbitcoin_store::TxRecord, Vec<rbitcoin_store::OutputRecord>)>,
    > = U64Map::default();
    if let Some(plan) = plan {
        if plan.batch_pin.len() == plan.planned_fks.len() {
            for (fk, pin) in plan.planned_fks.iter().zip(plan.batch_pin.iter()) {
                if let Some(id) = fk.get() {
                    batch_pin_by_id.insert(id, pin);
                }
            }
        } else {
            // Partial plans (tests): fall back to packed pin half.
            for ((pin, _ins), fk) in plan.packed.iter().zip(plan.planned_fks.iter()) {
                if let Some(id) = fk.get() {
                    batch_pin_by_id.insert(id, pin);
                }
            }
        }
        let fill_vouts = parent_pin.parent_vouts.is_empty();
        if plan.edges.is_empty() && !plan.planned_fks.is_empty() {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: plan spend edges empty",
            )));
        }
        spend_edges = plan.edges.clone();
        if fill_vouts {
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
        }
        if !fill_vouts {
            parent_vouts = std::mem::take(&mut parent_pin.parent_vouts);
            vouts_from_stamp = true;
        }
    } else {
        // plan=None: create_fk from ParentPinStamp (lookup head/idx), never load head.
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
    }

    if !vouts_from_stamp {
        for vouts in parent_vouts.values_mut() {
            vouts.sort_unstable();
            vouts.dedup();
        }
    }

    if let Some(ifo) = in_flight {
        ifo.for_each_out(|id, pin| {
            if plan_by_id.contains_key(&id) || !parent_vouts.contains_key(&id) {
                return;
            }
            plan_by_id.insert(id, std::sync::Arc::clone(pin));
        });
    }
    for (id, _need) in &parent_vouts {
        if plan_by_id.contains_key(id) {
            continue;
        }
        if let Some(pin) = batch_pin_by_id.get(id) {
            plan_by_id.insert(*id, std::sync::Arc::clone(pin));
            n_same_batch = n_same_batch.saturating_add(1);
        }
    }

    let t_recent = Instant::now();
    for (id, need) in &parent_vouts {
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
        confirm_load_stats::PIN_RECENT_OUTS_NS.fetch_add(recent_outs_ns, Ordering::Relaxed);
    }

    let mut batch_parents = match pipeline_parent_store {
        Some(store) => rbitcoin_query::BatchParents::with_store(
            std::sync::Arc::clone(store),
            parent_vouts.len(),
        ),
        None => rbitcoin_query::BatchParents::with_capacity(parent_vouts.len()),
    };
    let t_adopt = Instant::now();
    if pipeline_parent_store.is_some() {
        batch_parents.adopt_from_store(parent_vouts.keys().copied());
    }
    let adopt_ns = t_adopt.elapsed().as_nanos() as u64;
    let thin_ns = t_thin.elapsed().as_nanos() as u64;
    if thin_ns > 0 {
        confirm_load_stats::THIN_NS.fetch_add(thin_ns, Ordering::Relaxed);
    }
    let mut still_need: U64Map<Vec<u32>> = U64Map::default();
    let mut n_plan_pin = 0u64;

    let t_plan = Instant::now();
    for (id, need) in &parent_vouts {
        let fk = rbitcoin_primitives::Fk(*id);
        // Pure adopt hit: refresh meta only when plan/layout material is present
        // (skip empty refresh_pin_meta — it would reload outs).
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
    let plan_pin_ns = t_plan.elapsed().as_nanos() as u64;
    let mut cold_range_batch_ns = 0u64;
    let mut n_range_new = 0u64;

    // Body denserels by range for still_need: lookup-stamped ranges only.
    {
        let mut range_jobs: Vec<(rbitcoin_primitives::Fk, (u64, u64), [u8; 32], Vec<u32>)> =
            Vec::new();
        let pending = std::mem::take(&mut still_need);
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
        if !range_jobs.is_empty() {
            let n_range = range_jobs.len() as u64;
            let (decoded, body_ns, dec_ns) = query
                .store()
                .get_outs_by_range_batch(&range_jobs)
                .map_err(ConsensusError::from)?;
            let rng_ns = body_ns.saturating_add(dec_ns);
            cold_range_batch_ns = cold_range_batch_ns.saturating_add(rng_ns);
            if rng_ns > 0 {
                confirm_load_stats::COLD_IO_NS.fetch_add(rng_ns, Ordering::Relaxed);
                confirm_load_stats::COLD_RANGE_NS.fetch_add(rng_ns, Ordering::Relaxed);
            }
            if body_ns > 0 {
                confirm_load_stats::COLD_RANGE_BODY_NS.fetch_add(body_ns, Ordering::Relaxed);
            }
            if dec_ns > 0 {
                confirm_load_stats::COLD_RANGE_DECODE_NS.fetch_add(dec_ns, Ordering::Relaxed);
            }
            confirm_load_stats::COLD_RANGE_N.fetch_add(n_range, Ordering::Relaxed);
            confirm_load_stats::BODY_TX_READS.fetch_add(n_range, Ordering::Relaxed);
            confirm_load_stats::PIN_NEW.fetch_add(n_range, Ordering::Relaxed);
            n_range_new = n_range_new.saturating_add(n_range);
            let t_range_fill = Instant::now();
            for ((fk, range, _tid, need), row) in range_jobs.into_iter().zip(decoded.into_iter()) {
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
                // Schema-13 decode leaves zero identity — stamp from parent_pin only.
                if tx.txid == [0u8; 32] {
                    tx.txid = parent_pin
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
                // Cold range-fill: PIN_NEW only. Do not bump n_plan_pin /
                // PIN_CACHE_BODY — that would inflate pin_hit%.
            }
            let range_fill_ns = t_range_fill.elapsed().as_nanos() as u64;
            if range_fill_ns > 0 {
                confirm_load_stats::PIN_RANGE_FILL_NS.fetch_add(range_fill_ns, Ordering::Relaxed);
            }
        }
    }

    for (id, _) in &parent_vouts {
        if let Some(sr) = parent_pin.spent_range(*id) {
            batch_parents.set_spent_range_only(rbitcoin_primitives::Fk(*id), sr);
        }
    }

    // Never `tx.idx` / head cold denserels on load. `spent.idx` IO is lookup.
    let n_cold = 0u64;
    let cold_io_ns = 0u64;
    let cold_decode_ns = 0u64;
    if !still_need.is_empty() {
        return Err(ConsensusError::Store(StoreError::Corrupt(
            "invariant: lookup stage miss (load parent without body_range denserels)",
        )));
    }

    // Same-batch / load-ahead creates may still lack spent_range until write.
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

    let t_publish = Instant::now();
    batch_parents.publish_to_store();
    let publish_ns = t_publish.elapsed().as_nanos() as u64;

    let n_unique = parent_vouts.len() as u64;
    if n_unique > 0 {
        confirm_load_stats::PARENT_UNIQUE.fetch_add(n_unique, Ordering::Relaxed);
        confirm_load_stats::UTXO_PARENTS.fetch_add(n_unique, Ordering::Relaxed);
    }
    if n_plan_pin > 0 {
        confirm_load_stats::PIN_PLAN.fetch_add(n_plan_pin, Ordering::Relaxed);
        confirm_load_stats::PIN_CACHE_BODY.fetch_add(n_plan_pin, Ordering::Relaxed);
    }
    if n_cold > 0 {
        confirm_load_stats::PIN_NEW.fetch_add(n_cold, Ordering::Relaxed);
    }
    if plan_pin_ns > 0 {
        confirm_load_stats::PLAN_PIN_NS.fetch_add(plan_pin_ns, Ordering::Relaxed);
    }
    if adopt_ns > 0 {
        confirm_load_stats::PIN_ADOPT_NS.fetch_add(adopt_ns, Ordering::Relaxed);
    }
    if contract_ns > 0 {
        confirm_load_stats::PIN_CONTRACT_NS.fetch_add(contract_ns, Ordering::Relaxed);
    }
    if publish_ns > 0 {
        confirm_load_stats::PIN_PUBLISH_NS.fetch_add(publish_ns, Ordering::Relaxed);
    }
    // Last-batch pin residual for slow-load logs (overwrite; not window-summed).
    let cold_batch_ns = cold_range_batch_ns
        .saturating_add(cold_io_ns)
        .saturating_add(cold_decode_ns);
    confirm_load_stats::note_last_pin(
        adopt_ns,
        plan_pin_ns,
        cold_batch_ns,
        contract_ns,
        publish_ns,
        n_plan_pin,
        n_cold.saturating_add(n_range_new),
    );
    if cold_io_ns > 0 {
        confirm_load_stats::COLD_IO_NS.fetch_add(cold_io_ns, Ordering::Relaxed);
        confirm_load_stats::PIN_NEW_META_NS.fetch_add(cold_io_ns, Ordering::Relaxed);
    }
    if cold_decode_ns > 0 {
        confirm_load_stats::COLD_DECODE_NS.fetch_add(cold_decode_ns, Ordering::Relaxed);
    }
    let pin_ns = t_pin.elapsed().as_nanos() as u64;
    if pin_ns > 0 {
        confirm_load_stats::PARENT_PIN_NS.fetch_add(pin_ns, Ordering::Relaxed);
        confirm_load_stats::PIN_BODY_NS.fetch_add(pin_ns, Ordering::Relaxed);
        // Wire path: `NS` is pin wall (legacy load path uses full load_confirm wall).
        confirm_load_stats::NS.fetch_add(pin_ns, Ordering::Relaxed);
    }
    let n_blks = metas.len() as u64;
    if n_blks > 0 {
        confirm_load_stats::BLOCKS.fetch_add(n_blks, Ordering::Relaxed);
    }

    let warm = DenserelsWarmStats {
        parents: parent_vouts.len().saturating_sub(n_same_batch as usize) as u32,
        already: n_plan_pin.saturating_sub(n_same_batch as u64) as u32,
        cold: n_cold as u32,
        same_batch: n_same_batch,
        work_ns: pin_ns,
    };
    Ok((batch_parents, spend_edges, warm))
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
            for (fk, opt) in spent_fks.iter().zip(spent.into_iter()) {
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
    confirm_phase_stats::ENSURE_RES_HIT.fetch_add(ensure_res, Ordering::Relaxed);

    // Class A denserels body for remainder only — must not re-load pin denserels hits.
    if !still.is_empty() {
        let fks: Vec<rbitcoin_primitives::Fk> = still
            .keys()
            .map(|id| rbitcoin_primitives::Fk(*id))
            .collect();
        confirm_phase_stats::ENSURE_COLD_N.fetch_add(fks.len() as u64, Ordering::Relaxed);
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
            for (fk, opt) in spent_fks.iter().zip(spent.into_iter()) {
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
