//! Write / Class C commit stage.

use super::phases::{class_c_commit, post_commit, structural_run};
use super::*;
use std::cell::RefCell;

thread_local! {
    static WRITE_REUSE: RefCell<super::phases::StructuralReuse> =
        RefCell::new(super::phases::StructuralReuse::default());
}

pub(super) fn write_height_needed(tip: Option<u32>, height: u32) -> bool {
    match tip {
        None => true,
        Some(t) => height > t,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteBatchVsTip {
    AllOld,
    AllNew,
    SpansTip,
}

pub(super) fn write_batch_vs_tip(
    tip: Option<u32>,
    heights: impl IntoIterator<Item = u32>,
) -> WriteBatchVsTip {
    let mut any_old = false;
    let mut any_new = false;
    for h in heights {
        if write_height_needed(tip, h) {
            any_new = true;
        } else {
            any_old = true;
        }
        if any_old && any_new {
            return WriteBatchVsTip::SpansTip;
        }
    }
    if any_new {
        WriteBatchVsTip::AllNew
    } else {
        WriteBatchVsTip::AllOld
    }
}

fn finish_already_committed_write(
    query: &Query,
    batch: &ScriptOkBatch,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    let items: Vec<(u32, [u8; 32])> = batch
        .prepared
        .iter()
        .map(|p| (p.height.0, p.hash))
        .collect();
    finish_post_commit_hashes(query, &items)?;
    if let Some(h) = items.iter().map(|(h, _)| *h).max() {
        query.prune_write_create_loc(h);
    }
    Ok(Vec::new())
}

struct ArchivePlanNs {
    pins: FkMap<rbitcoin_query::CreatePin>,
    class_a_wave: crate::block::ClassAWave,
    class_a_ns: u64,
    ensure_ns: u64,
    plan_take_ns: u64,
    create_map_ns: u64,
}

fn apply_archive_plan(
    query: &Query,
    batch: &mut ScriptOkBatch,
) -> Result<ArchivePlanNs, ConsensusError> {
    let mut ns = ArchivePlanNs {
        pins: FkMap::default(),
        class_a_wave: crate::block::ClassAWave::default(),
        class_a_ns: 0,
        ensure_ns: 0,
        plan_take_ns: 0,
        create_map_ns: 0,
    };
    let Some(mut plan) = batch.archive_plan.take() else {
        return Ok(ns);
    };
    if plan.is_empty() {
        return Ok(ns);
    }
    let t_take = Instant::now();
    let planned_fks = plan.planned_fks.clone();
    let packed_pins: Vec<rbitcoin_query::CreatePin> =
        if plan.batch_pin.len() == plan.planned_fks.len() {
            std::mem::take(&mut plan.batch_pin)
        } else {
            plan.packed
                .iter()
                .map(|(pin, _)| std::sync::Arc::clone(pin))
                .collect()
        };
    ns.plan_take_ns = t_take.elapsed().as_nanos() as u64;
    let t_ca = Instant::now();
    let (committed, loc) = query
        .archive_commit_plan_defer_head_parents(plan, Some(&batch.batch_parents))
        .map_err(ConsensusError::from)?;
    ns.class_a_ns = t_ca.elapsed().as_nanos() as u64;
    if !committed {
        return Ok(ns);
    }
    let pack_hi = batch.prepared.last().map(|p| p.height.0).unwrap_or(0);
    query.note_write_create_loc(&planned_fks, &loc, pack_hi);
    if query.index_mode().is_tip() {
        let t_map = Instant::now();
        ns.pins.reserve(planned_fks.len());
        for (fk, pin) in planned_fks.iter().zip(packed_pins.iter()) {
            ns.pins.insert(*fk, std::sync::Arc::clone(pin));
        }
        ns.create_map_ns = t_map.elapsed().as_nanos() as u64;
    }
    let t_ens = Instant::now();
    fill_planned_create_layout_after_commit(
        query,
        &mut batch.batch_parents,
        &planned_fks,
        &loc,
        &packed_pins,
        &batch.prepared,
    )?;
    ns.ensure_ns = t_ens.elapsed().as_nanos() as u64;
    if let Some(last) = batch.prepared.last() {
        query.set_class_a_hi(Some(last.height.0));
    }
    // The overlay is proven only for rows this commit wrote. A plan trimmed
    // at commit wrote fewer rows than `planned_fks` names.
    if loc.len() == planned_fks.len() {
        ns.class_a_wave = crate::block::ClassAWave::new(planned_fks);
    }
    Ok(ns)
}

/// COMMIT STAGE: optional Class A plan commit → structural → class_c → spend annotate → tip GC
/// → live filter and tweak append when `index_live` assembled this batch.
///
/// When `batch.archive_plan` is set (wire lookup/load path), Class A is appended in this
/// same stage before structural/annotate — single ordered commit era.
/// **Class A never leads tip** (no dual-track archive-ahead / body DONTNEED lead).
///
/// Accrues window timers on [`Query::confirm_stats`] and snapshots the last batch
/// for slow-write logs via [`rbitcoin_query::ConfirmStats::last_write_phases`].
pub fn confirm_write_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    batch: ScriptOkBatch,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    confirm_write_phase_or_return(query, params, milestone, batch).map_err(|(e, _)| e)
}

/// [`confirm_write_phase`] that hands the batch back on error, so a caller
/// that retries the wave can offer its bodies back.
#[allow(clippy::result_large_err)] // the batch is the point of the error
pub fn confirm_write_phase_or_return(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    mut batch: ScriptOkBatch,
) -> Result<Vec<rbitcoin_primitives::Fk>, (ConsensusError, ScriptOkBatch)> {
    write_phase(query, params, milestone, &mut batch).map_err(|e| (e, batch))
}

fn write_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    batch: &mut ScriptOkBatch,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConsensusError> {
    let tip = query.tip_height().map(|h| h.0);
    match write_batch_vs_tip(tip, batch.prepared.iter().map(|p| p.height.0)) {
        WriteBatchVsTip::AllOld => return finish_already_committed_write(query, batch),
        WriteBatchVsTip::SpansTip => {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: write batch spans tip",
            )));
        }
        WriteBatchVsTip::AllNew => {}
    }
    annotate_pending_spends(query)?;

    let t_wall = Instant::now();

    let ArchivePlanNs {
        pins: write_create_pins,
        class_a_wave,
        class_a_ns,
        mut ensure_ns,
        plan_take_ns,
        create_map_ns,
    } = apply_archive_plan(query, batch)?;
    let t_ens = Instant::now();
    let abs_jobs = super::collect_spend_abs_after_fill(&batch.batch_parents, &batch.prepared)?;
    ensure_ns = ensure_ns.saturating_add(t_ens.elapsed().as_nanos() as u64);
    if class_a_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().class_a_ns, class_a_ns);
    }
    if ensure_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().ensure_layout_ns, ensure_ns);
    }
    if plan_take_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().write_plan_take_ns, plan_take_ns);
    }
    if create_map_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().write_create_map_ns, create_map_ns);
    }

    // Drain write-behind tx.head overlapping structural + Class C (one inserter).
    let t_head = Instant::now();
    let queued = query.store().txs.take_pending_queued();
    let drain_max_fk = queued.iter().filter_map(|(_, fk)| fk.get()).max();
    let drain = super::head_drain::submit_head_insert(query.store(), queued);
    let head_sub_ns = t_head.elapsed().as_nanos() as u64;
    if head_sub_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().write_head_sub_ns, head_sub_ns);
    }

    let overlap = (|| -> Result<_, ConsensusError> {
        // Local Instant totals (not atomic deltas) — sample_and_reset races mid-batch.
        let t_struct = Instant::now();
        let (struct_ph, slots) = WRITE_REUSE.with(|reuse| {
            structural_run(
                query,
                params,
                milestone,
                &batch.prepared,
                &batch.wire_blocks,
                &batch.batch_parents,
                &abs_jobs,
                &class_a_wave,
                &mut reuse.borrow_mut(),
            )
        })?;
        let structural_ns = t_struct.elapsed().as_nanos() as u64;

        let n_blocks = batch.prepared.len();
        let pending_token = batch
            .prepared
            .first()
            .map(|first| query.store().note_spend_annotate_pending(first.height.0));
        let cc0 = query.confirm_stats().class_c_ns.load(Ordering::Relaxed);
        let t_cc = Instant::now();
        let out = class_c_commit(query, &mut batch.prepared, &write_create_pins)?;
        let class_c_wall_ns = t_cc.elapsed().as_nanos() as u64;
        let class_c_ns = query
            .confirm_stats()
            .class_c_ns
            .load(Ordering::Relaxed)
            .saturating_sub(cc0);
        let class_c_join_ns = class_c_wall_ns.saturating_sub(class_c_ns);
        if class_c_join_ns > 0 {
            rbitcoin_query::note_confirm(
                &query.confirm_stats().write_class_c_join_ns,
                class_c_join_ns,
            );
        }

        let seal = std::mem::take(&mut batch.index_seal);
        let idx_put_ns = super::index::seal_live_indexes(query, seal)?;
        if idx_put_ns > 0 {
            rbitcoin_query::note_confirm(&query.confirm_stats().idx_put_ns, idx_put_ns);
            rbitcoin_query::note_confirm(&query.confirm_stats().blockfilter_ns, idx_put_ns);
        }

        let spend_ann_ns = post_commit(query, &slots)?;
        if let Some(token) = pending_token {
            query.store().clear_spend_annotate_pending(token);
        }
        if let Some(tip) = query.tip_height() {
            query.store().note_spend_snapshot(tip.0);
        }
        Ok((
            out,
            n_blocks,
            structural_ns,
            struct_ph,
            class_c_ns,
            spend_ann_ns,
        ))
    })();

    let t_join = Instant::now();
    let (drain_res, restore) = drain.join_restore();
    let drain_join_ns = t_join.elapsed().as_nanos() as u64;
    if drain_join_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().write_drain_join_ns, drain_join_ns);
    }
    if drain_res.is_err() {
        query.store().txs.head_note_pending(&restore);
    }
    let (out, n_blocks, structural_ns, struct_ph, class_c_ns, spend_ann_ns) = overlap?;
    drain_res.map_err(ConsensusError::from)?;
    if let Some(fk) = drain_max_fk {
        query.note_head_drain_fk(fk);
    }

    // No tip GC of sparse pins (dropped with ScriptOkBatch).
    if let Some(h) = batch.prepared.iter().map(|p| p.height.0).max() {
        query.prune_write_create_loc(h);
    }
    rbitcoin_query::note_confirm(&query.confirm_stats().phase_blocks, n_blocks as u64);
    query
        .confirm_stats()
        .note_last_write(rbitcoin_query::LastWritePhases {
            n_blocks: n_blocks as u32,
            wall_ns: t_wall.elapsed().as_nanos() as u64,
            class_a_ns,
            ensure_ns,
            structural_ns,
            spent_ns: struct_ph.spent_ns,
            create_h_ns: struct_ph.create_h_ns,
            bip68_ns: struct_ph.bip68_ns,
            class_c_ns,
            spend_ann_ns,
        });
    Ok(out)
}

/// Replay spend annotate + `tx.head` drain after Class C already committed.
///
/// Session-fault retry must not skip this: `height_of_hash` matching is not
/// "write finished."
pub(crate) fn finish_post_commit(
    query: &Query,
    height: u32,
    hash: &[u8; 32],
) -> Result<(), ConsensusError> {
    finish_post_commit_hashes(query, &[(height, *hash)])
}

/// IBD write-thread in-place retry: `(height, hash)` must already be connected
/// at that height.
pub fn finish_post_commit_hashes(
    query: &Query,
    items: &[(u32, [u8; 32])],
) -> Result<(), ConsensusError> {
    let queued = query.store().txs.take_pending_queued();
    if queued.is_empty() && !query.spend_index_enabled() {
        return Ok(());
    }
    let drain_max_fk = queued.iter().filter_map(|(_, fk)| fk.get()).max();
    let drain = if queued.is_empty() {
        None
    } else {
        Some(super::head_drain::submit_head_insert(query.store(), queued))
    };

    let annotate_res = (|| -> Result<(), ConsensusError> {
        if !query.spend_index_enabled() {
            return Ok(());
        }
        let mut slots = crate::block::AnnotateSlots::default();
        for &(height, hash) in items {
            annotate_slots_from_connected_hash(query, height, &hash, &mut slots)?;
        }
        post_commit(query, &slots)?;
        Ok(())
    })();

    if let Some(drain) = drain {
        let (drain_res, restore) = drain.join_restore();
        if drain_res.is_err() {
            query.store().txs.head_note_pending(&restore);
        }
        annotate_res?;
        drain_res.map_err(ConsensusError::from)?;
        if let Some(fk) = drain_max_fk {
            query.note_head_drain_fk(fk);
        }
    } else {
        annotate_res?;
    }
    Ok(())
}

const REPLAY_BATCH: usize = 8;
const REPLAY_STATUS_MS: u64 = 10_000;

/// Rewrite spend annotations above the durable marker, then `sync_data` and advance it.
///
/// Idempotent. A missing marker has no device-flushed cursor, so every height
/// above genesis is rewritten before the marker is published at the surviving tip.
/// Returns how many heights were rewritten. Call this on process open after
/// tip-window revalidation.
pub fn replay_spend_annotations(query: &Query) -> Result<u32, ConsensusError> {
    let Some(tip) = query.tip_height().map(|h| h.0) else {
        return Ok(0);
    };
    // A marker above the tip is not a cursor for this chain. Shrink and a
    // crash between the tip flush and the clamp both leave that file behind.
    // Lower it before the `a == tip` skip, or the next confirm's spends are
    // never rewritten.
    let annotated = query
        .store()
        .spend_annotated_through()
        .map_err(ConsensusError::from)?;
    if annotated.is_some_and(|h| h > tip) {
        query
            .store()
            .clamp_spend_durable()
            .map_err(ConsensusError::from)?;
    }
    let annotated = query
        .store()
        .spend_annotated_through()
        .map_err(ConsensusError::from)?;
    let a = match annotated {
        Some(h) => h.min(tip),
        None => {
            rbitcoin_log::info!("store: no spend durable marker; replaying (0, {tip}]");
            0
        }
    };
    if a == tip {
        return Ok(0);
    }
    rewrite_spend_heights(query, a, tip)
}

fn publish_spend_marker(query: &Query, tip: u32) -> Result<(), ConsensusError> {
    let sync_ns = query
        .store()
        .sync_spend_durable(tip)
        .map_err(ConsensusError::from)?;
    rbitcoin_query::note_confirm(&query.confirm_stats().spend_durable_ns, sync_ns);
    Ok(())
}

fn rewrite_spend_heights(query: &Query, annotated: u32, tip: u32) -> Result<u32, ConsensusError> {
    rbitcoin_log::info!("store: replay spend annotations ({annotated}, {tip}]");
    let replayed = annotate_spend_heights(query, annotated + 1, tip)?;
    publish_spend_marker(query, tip)?;
    Ok(replayed)
}

/// Finish the spend annotate a failed confirm write left after its tip commit.
///
/// The next batch's spentness reads those slots, so it must not run until they
/// are written. A replay that fails returns the error and the batch does not run.
fn annotate_pending_spends(query: &Query) -> Result<(), ConsensusError> {
    let token = query.store().spend_annotate_token();
    let Some(from) = query.store().spend_annotate_pending() else {
        return Ok(());
    };
    if let Some(tip) = query.tip_height().map(|h| h.0).filter(|&t| t >= from) {
        rbitcoin_log::warn!(
            "confirm: replay spend annotations [{from}, {tip}] after a failed write"
        );
        let t = Instant::now();
        annotate_spend_heights(query, from, tip)?;
        rbitcoin_query::note_confirm(
            &query.confirm_stats().spend_replay_ns,
            t.elapsed().as_nanos() as u64,
        );
    }
    query.store().clear_spend_annotate_pending(token);
    Ok(())
}

fn annotate_spend_heights(query: &Query, start: u32, tip: u32) -> Result<u32, ConsensusError> {
    let heights: Vec<u32> = (start..=tip).collect();
    let replayed = heights.len() as u32;
    let started = std::time::Instant::now();
    let mut logged_at = started;
    let mut done = 0u32;
    for chunk in heights.chunks(REPLAY_BATCH) {
        let mut items = Vec::with_capacity(chunk.len());
        for &h in chunk {
            let Some((_, rec)) = query
                .header_at_height(rbitcoin_primitives::Height(h))
                .map_err(ConsensusError::from)?
            else {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: spend replay missing header",
                )));
            };
            items.push((h, rec.hash));
        }
        finish_post_commit_hashes(query, &items)?;
        done = done.saturating_add(chunk.len() as u32);
        let elapsed = logged_at.elapsed().as_millis() as u64;
        if elapsed >= REPLAY_STATUS_MS {
            let h = *chunk.last().unwrap_or(&tip);
            rbitcoin_log::info!("store: replay spend annotations {done}/{replayed} height={h}");
            logged_at = std::time::Instant::now();
        }
    }
    Ok(replayed)
}

fn annotate_slots_from_connected_hash(
    query: &Query,
    height: u32,
    hash: &[u8; 32],
    slots: &mut crate::block::AnnotateSlots,
) -> Result<(), ConsensusError> {
    match query.height_of_hash(hash).map_err(ConsensusError::from)? {
        Some(h) if h.0 == height => {}
        _ => return Ok(()),
    }
    let Some((hfk, _)) = query
        .get_header_by_hash(hash)
        .map_err(ConsensusError::from)?
    else {
        return Ok(());
    };
    let Some(tx_fks) = query
        .store()
        .header_txs
        .get_list(hfk)
        .map_err(ConsensusError::from)?
    else {
        return Ok(());
    };
    for (tx_i, &spend_fk) in tx_fks.iter().enumerate() {
        let (_meta, ins, _outs) = query
            .store()
            .get_tx_full(spend_fk)
            .map_err(ConsensusError::from)?;
        if tx_i == 0 {
            let coinbase = ins.len() == 1 && ins[0].is_coinbase();
            if !coinbase {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: coinbase input edge",
                )));
            }
            continue;
        }
        for (inp_i, inp) in ins.into_iter().enumerate() {
            if inp.is_coinbase() || inp.create_fk.is_null() {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: non-coinbase input edge",
                )));
            }
            let create_fk = inp.create_fk;
            let (off, len) = query
                .store()
                .tx_spent_range(create_fk)
                .map_err(ConsensusError::from)?;
            let abs = rbitcoin_store::spent_abs(off, inp.prev_index);
            if abs.saturating_add(rbitcoin_store::OutputRecord::SPENT_SLOT_LEN as u64)
                > off.saturating_add(len)
            {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: finish_post_commit spent slot OOB",
                )));
            }
            let (multi, field, field_vin) = query
                .store()
                .txs
                .get_output_spender_meta(create_fk, inp.prev_index)
                .map_err(ConsensusError::from)?;
            let flags = if multi {
                rbitcoin_store::output_flags::MULTI_SPENDER
            } else {
                0
            };
            slots.push(
                (abs, create_fk, inp.prev_index, spend_fk, inp_i as u32),
                (field, flags, field_vin),
            );
        }
    }
    Ok(())
}

/// After Class A commit, stamp spend creates from append RAM loc
/// (this pack + just-written packs still in the write loc window).
/// Write never preads `create.loc`.
pub(super) fn fill_planned_create_layout_after_commit(
    query: &Query,
    batch_parents: &mut rbitcoin_query::BatchParents,
    planned_fks: &[rbitcoin_primitives::Fk],
    loc: &[rbitcoin_store::CreateLocPair],
    packed: &[rbitcoin_query::CreatePin],
    prepared: &[Prepared],
) -> Result<(), ConsensusError> {
    let mut need: U64Map<Vec<u32>> = U64Map::default();
    for p in prepared {
        for &(_txid, vout, sfk, cfk, _vin) in &p.spends {
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
    if need.is_empty() {
        return Ok(());
    }
    if !planned_fks.is_empty() {
        if loc.len() != planned_fks.len() || packed.len() != planned_fks.len() {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: append loc length",
            )));
        }
        for (fk, (pair, pin)) in planned_fks.iter().zip(loc.iter().zip(packed.iter())) {
            let Some(id) = fk.get() else { continue };
            let Some(vouts) = need.get(&id) else { continue };
            if pair.n_out != pin.n_out() as u32 {
                return Err(ConsensusError::Store(StoreError::Corrupt(
                    "invariant: append loc length",
                )));
            }
            if batch_parents.contains(*fk) {
                batch_parents.set_body_range_only(*fk, pair.txout);
                batch_parents.set_spent_range_only(*fk, pair.spent);
                continue;
            }
            let mut checked = vouts.clone();
            checked.sort_unstable();
            checked.dedup();
            let cb = if pin.tx().input_count > 1 {
                Some(false)
            } else {
                None
            };
            batch_parents.insert_create_pin(
                *fk,
                std::sync::Arc::clone(pin),
                checked,
                cb,
                Some(pair.txout),
                Vec::new(),
            );
            batch_parents.set_spent_range_only(*fk, pair.spent);
        }
    }
    for id in need.keys() {
        let fk = rbitcoin_primitives::Fk(*id);
        if !batch_parents.contains(fk) || batch_parents.has_abs_layout(fk) {
            continue;
        }
        let Some(pair) = query.write_create_loc(fk) else {
            continue;
        };
        batch_parents.set_body_range_only(fk, pair.txout);
        batch_parents.set_spent_range_only(fk, pair.spent);
    }
    Ok(())
}
