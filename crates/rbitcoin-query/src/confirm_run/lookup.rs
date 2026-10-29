//! Lookup / stamp for wire confirm.

use super::*;

/// Lookup-stamped external parent material for load body denserels.
///
/// **Lookup** fills this via `tx.head` / `create.loc` / `txid.body` (never `txout.body`).
/// **Load** denserels by range using only [`crate::ParentIdent`] (+ plan offline pins).
/// Integer create_fk map uses [`U64Map`] (identity hasher) — pack-scale win over SipHash.
#[derive(Debug, Default, Clone)]
pub struct ParentPinStamp {
    /// prev_txid → create_fk_id (plan=None edges; empty after `take_from_plan`).
    pub resolved: crate::TxidMap<u64>,
    /// create_fk_id → identity (txid + optional body/spent/pin).
    pub idents: crate::U64Map<crate::ParentIdent>,
    /// create_fk_id → spent need-vouts (packed at lookup; load pin reuses).
    pub parent_vouts: U64Map<Vec<u32>>,
}

impl ParentPinStamp {
    /// Move plan stamp identity into the load stamp (no 100k-entry clone).
    ///
    /// `resolved` stays empty: plan path pins from packed `create_fk`.
    pub fn take_from_plan(plan: &mut crate::ArchiveWritePlan) -> Self {
        Self {
            resolved: crate::TxidMap::with_hasher(Default::default()),
            idents: std::mem::take(&mut plan.external_parents),
            parent_vouts: std::mem::take(&mut plan.external_parent_vouts),
        }
    }

    #[inline]
    pub fn create_txid(&self, create_fk_id: u64) -> Option<[u8; 32]> {
        self.idents
            .get(&create_fk_id)
            .map(|p| p.txid)
            .filter(|t| *t != [0u8; 32])
    }

    #[inline]
    pub fn body_range(&self, create_fk_id: u64) -> Option<(u64, u64)> {
        self.idents.get(&create_fk_id).and_then(|p| p.body)
    }

    #[inline]
    pub fn spent_range(&self, create_fk_id: u64) -> Option<(u64, u64)> {
        self.idents.get(&create_fk_id).and_then(|p| p.spent)
    }

    #[inline]
    pub fn n_out(&self, create_fk_id: u64) -> Option<u32> {
        self.idents.get(&create_fk_id).and_then(|p| p.n_out)
    }

    #[inline]
    pub fn create_pin(&self, create_fk_id: u64) -> Option<&crate::CreatePin> {
        self.idents.get(&create_fk_id).and_then(|p| p.pin.as_ref())
    }
}

pub type WireBlockIn = (Height, Arc<Block>, Option<Arc<[crate::TxPrecompute]>>);
#[doc(hidden)]
pub type LookupPhaseOut = (
    Option<crate::ArchiveWritePlan>,
    Vec<BodyMeta>,
    Vec<Arc<Block>>,
    u64,
);

/// Lookup-stage output: structure + plan batch (create_fk + parent body ranges).
///
/// **No `tx.body` denserels on lookup.** Load denserels by range from
/// [`ParentPinStamp`] / plan ranges. Handoff is owned plan + parent pin stamp.
pub struct PlanStampOutcome {
    pub plan: Option<crate::ArchiveWritePlan>,
    /// External parent fk/range/txid stamped at lookup (always; including plan=None).
    pub parent_pin: ParentPinStamp,
    /// Wall ns for structure + plan_batch (head stamp).
    pub work_ns: u64,
    pub metas: Vec<BodyMeta>,
    pub wire_blocks: Vec<Arc<Block>>,
    pub archived_pairs: Vec<([u8; 32], rbitcoin_primitives::Fk)>,
    /// Warn-and-apply faults from this lookup. Load carries them. Not logged yet.
    pub trust_warns: Vec<(u32, rbitcoin_consensus::ConsensusError)>,
}

impl PlanStampOutcome {
    /// Create identity already on the stamp (`pres` txids + planned/archived fks).
    ///
    /// plan=None in-flight publish uses this instead of re-reading `txid.body`.
    pub fn archived_create_pairs(&self) -> Vec<([u8; 32], rbitcoin_primitives::Fk)> {
        self.archived_pairs.clone()
    }

    pub fn last_height_hash(&self) -> Option<(u32, [u8; 32])> {
        self.metas.last().map(|m| (m.height.0, m.hash))
    }
}

pub fn archived_create_pairs(
    metas: &[BodyMeta],
) -> Result<Vec<([u8; 32], rbitcoin_primitives::Fk)>, ConfirmError> {
    let mut pairs = Vec::new();
    for m in metas {
        if m.tx_fks.is_empty() {
            continue;
        }
        if m.tx_fks.len() != m.txids.len() {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: archived stamp tx_fks/txids length",
            )));
        }
        for (tid, fk) in m.txids.iter().zip(m.tx_fks.iter()) {
            if fk.is_null() || *tid == [0u8; 32] {
                continue;
            }
            pairs.push((*tid, *fk));
        }
    }
    Ok(pairs)
}

/// IBD **load** stage: structure + stamp create_fk + parent body ranges.
///
/// May read `tx.head`, `tx.idx`, `txid.body`. **Never** denserels-decode `tx.body`.
/// Parent create_fk: in-flight → skeleton (carried BQ keys) → leftover TipOnly
/// (plan=None). Wire blocks are `Arc` so IBD resolve can decode once and hand
/// off without cloning full `Block` payloads into stamp. `pres` is lookup
/// `TxPrecompute` when the caller already hashed (loadq); `None` hashes here.
pub fn confirm_wire_lookup_stamp(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<PlanStampOutcome, ConfirmError> {
    let scope = super::TrustScope::enter(query);
    let result = lookup_stamp_work(query, params, milestone, blocks, pipeline);
    let warns = scope.finish(
        &super::trust_ids_from_wire(blocks),
        result.as_ref().err(),
        false,
    );
    result.map(|mut stamp| {
        stamp.trust_warns = warns;
        stamp
    })
}

fn lookup_stamp_work(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<PlanStampOutcome, ConfirmError> {
    let t0 = Instant::now();
    query.on_load_pack().map_err(ConfirmError::from)?;
    let (mut plan, metas, wire_blocks, plan_ns) =
        wire_lookup_phase(query, params, milestone, blocks, pipeline)?;
    let ifo = pipeline.map(|p| p.in_flight);
    let (parent_pin, archived_pairs) = match plan.as_mut() {
        Some(p) => (ParentPinStamp::take_from_plan(p), Vec::new()),
        None => {
            let pairs = archived_create_pairs(&metas)?;
            let pin = stamp_parent_pin_archived(
                query,
                params,
                &metas,
                &wire_blocks,
                ifo,
                pipeline.and_then(|p| p.skeleton.as_ref()),
                pipeline.map(|p| p.carried_need.as_slice()),
            )?;
            (pin, pairs)
        }
    };
    crate::note_confirm(&query.confirm_stats().lookup_blocks, blocks.len() as u64);
    crate::note_confirm(&query.confirm_stats().lookup_head_ns, plan_ns);
    let work_ns = t0.elapsed().as_nanos() as u64;
    crate::note_confirm(&query.confirm_stats().lookup_total_ns, work_ns);
    Ok(PlanStampOutcome {
        plan,
        parent_pin,
        work_ns,
        metas,
        wire_blocks,
        archived_pairs,
        trust_warns: Vec::new(),
    })
}

/// One fk per txid (`latest`), plus every fk when a txid is created again.
pub struct BatchCopies {
    pub latest: crate::TxidMap<u64>,
    pub repeats: crate::TxidMap<Vec<u64>>,
}

/// Record each meta's creates in order. A second fk for one txid starts `repeats`.
pub fn batch_copies_from_metas(metas: &[BodyMeta]) -> BatchCopies {
    let mut latest: crate::TxidMap<u64> = crate::TxidMap::default();
    let mut repeats: crate::TxidMap<Vec<u64>> = crate::TxidMap::default();
    for m in metas {
        for (tid, fk) in m.txids.iter().zip(m.tx_fks.iter()) {
            let Some(id) = fk.get() else {
                continue;
            };
            let Some(prev) = latest.insert(*tid, id) else {
                continue;
            };
            repeats.entry(*tid).or_insert_with(|| vec![prev]).push(id);
        }
    }
    BatchCopies { latest, repeats }
}

/// Carried keys this skeleton does not already hold as an in-batch create.
/// Returns whether any carried key is also created in this batch.
#[doc(hidden)]
pub fn carried_keys_outside_batch(
    latest: &crate::TxidMap<u64>,
    carried_need: Option<&[[u8; 32]]>,
    need_external: &mut crate::TxidMap<bool>,
) -> bool {
    let mut created_here = false;
    for &prev in carried_need.unwrap_or(&[]) {
        if prev == [0u8; 32] {
            continue;
        }
        if latest.contains_key(&prev) {
            created_here = true;
            continue;
        }
        need_external.insert(prev, true);
    }
    created_here
}

#[doc(hidden)]
pub fn spend_needs_external_parent(
    copies: &BatchCopies,
    prev: &[u8; 32],
    spender: rbitcoin_primitives::Fk,
    outside: bool,
) -> bool {
    let repeats: Option<Vec<rbitcoin_primitives::Fk>> = copies
        .repeats
        .get(prev)
        .map(|ids| ids.iter().copied().map(rbitcoin_primitives::Fk).collect());
    if crate::archive::batch_copy_before(
        copies
            .latest
            .get(prev)
            .copied()
            .map(rbitcoin_primitives::Fk),
        repeats.as_deref(),
        spender,
    )
    .is_some()
    {
        return false;
    }
    if copies.latest.contains_key(prev) && !outside {
        return false;
    }
    true
}

/// Wire spends with no earlier in-batch copy. `true` means the input spends it.
#[doc(hidden)]
pub fn note_spends_without_earlier_copy(
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    copies: &BatchCopies,
    outside: impl Fn(&[u8; 32]) -> bool,
    need_external: &mut crate::TxidMap<bool>,
) {
    for (m, block) in metas.iter().zip(wire_blocks.iter()) {
        for (ti, tx) in block.txdata.iter().enumerate() {
            let Some(sfk) = m.tx_fks.get(ti).and_then(|f| f.get()) else {
                continue;
            };
            let spender = rbitcoin_primitives::Fk(sfk);
            for inp in &tx.input {
                if inp.previous_output.is_null() {
                    continue;
                }
                let prev = inp.previous_output.txid.to_byte_array();
                if prev == [0u8; 32]
                    || !spend_needs_external_parent(copies, &prev, spender, outside(&prev))
                {
                    continue;
                }
                need_external.insert(prev, true);
            }
        }
    }
}

#[doc(hidden)]
pub fn stamp_batch_idents(stamp: &mut ParentPinStamp, copies: &BatchCopies) {
    for (tid, id) in &copies.latest {
        stamp
            .idents
            .entry(*id)
            .or_insert_with(|| crate::ParentIdent::new(*tid))
            .txid = *tid;
    }
    for (tid, ids) in &copies.repeats {
        for id in ids {
            stamp
                .idents
                .entry(*id)
                .or_insert_with(|| crate::ParentIdent::new(*tid))
                .txid = *tid;
        }
    }
}

/// plan=None rehydrate: stamp external parent create_fk + body_range + txid
/// via the shared query helper so load never probes those tables.
///
/// A wire input whose parent is neither in this batch nor connected is
/// [`ConsensusError::MissingPrevout`], as on the plan path.
pub fn stamp_parent_pin_archived(
    query: &Query,
    params: &ChainParams,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    in_flight: Option<&crate::InFlight>,
    skeleton: Option<&crate::BatchParentIds>,
    carried_need: Option<&[[u8; 32]]>,
) -> Result<ParentPinStamp, ConfirmError> {
    let copies = batch_copies_from_metas(metas);
    let outside = |prev: &[u8; 32]| {
        skeleton.is_none_or(|s| s.get(prev).is_some())
            || in_flight.is_some_and(|ifo| ifo.get_create_fk(prev).is_some())
    };
    // Value: a wire input spends this txid (BIP30 probes are `false`).
    // Empty carried_need must not walk wire inputs. A carried key that this
    // batch also creates needs the walk: the spend may be before that create.
    let mut need_external: crate::TxidMap<bool> = crate::TxidMap::default();
    let walk_inputs = skeleton.is_none()
        || carried_keys_outside_batch(&copies.latest, carried_need, &mut need_external);
    if walk_inputs {
        note_spends_without_earlier_copy(metas, wire_blocks, &copies, outside, &mut need_external);
    }
    for m in metas {
        if params.bip34_active_at(m.height.0) {
            continue;
        }
        for p in m.pres.iter() {
            need_external.entry(p.txid).or_insert(false);
        }
    }
    let empty = crate::InFlight::new();
    let ifo = in_flight.unwrap_or(&empty);
    let need_vec: Vec<[u8; 32]> = need_external.keys().copied().collect();
    let ext = crate::stamp_external_parents(
        query.store(),
        &need_vec,
        ifo,
        skeleton,
        query.confirm_stats(),
    )
    .map_err(ConfirmError::from)?;
    if need_external
        .iter()
        .any(|(txid, &spent)| spent && !ext.resolved.contains_key(txid))
    {
        rbitcoin_consensus::block::reject_unresolved_spend(true)?;
    }
    let mut stamp = ParentPinStamp {
        // External parents only. Same-batch copies live in `idents`; edges
        // pick the copy that exists at the spend.
        resolved: crate::TxidMap::with_capacity_and_hasher(ext.resolved.len(), Default::default()),
        idents: ext.idents,
        parent_vouts: U64Map::default(),
    };
    for (tid, fk) in ext.resolved {
        let Some(id) = fk.get() else {
            continue;
        };
        stamp.resolved.insert(tid, id);
    }
    stamp_batch_idents(&mut stamp, &copies);
    // Identities are stamped from wire prev_txid at insert time — never soft-fill
    // from txid.body here (that would be a dual path after lookup promised identity).
    if skeleton.is_none() {
        crate::fill_missing_parent_ranges(
            query.store(),
            ifo,
            &mut stamp.idents,
            query.confirm_stats(),
        )
        .map_err(ConfirmError::from)?;
    } else {
        // The IBD skeleton carries external ranges. A parent with no body is
        // an archived create: this batch's own, or an earlier chunk's of the
        // same wave (noted in flight with no outs). Only the store has its
        // range. In-flight pins are skipped inside the fill.
        let mut archived: U64Map<crate::ParentIdent> =
            stamp.idents.extract_if(|_, e| e.body.is_none()).collect();
        crate::fill_missing_parent_ranges(query.store(), ifo, &mut archived, query.confirm_stats())
            .map_err(ConfirmError::from)?;
        stamp.idents.extend(archived);
    }
    for ident in stamp.idents.values() {
        if ident.txid == [0u8; 32] {
            return Err(ConfirmError::Store(StoreError::Corrupt(
                "invariant: plan=None parent stamp zero create identity",
            )));
        }
    }
    Ok(stamp)
}

/// A txid that `block` spends, does not create, and the connected chain
/// does not hold. One TipOnly `tx.head` read, with no in-flight plan and no
/// load-batch skeleton: the tip path's read. The miss is the block's fault
/// only when the block extends the tip and [`Query::head_covers_fence`]
/// held across the read.
///
/// A miss that `txid.body` holds at a connected fk where the head's slot
/// pages may be unsynced is a lost head row, not the block's fault:
/// `Corrupt("invariant: …")`. `stop` ends that scan early as `Cancelled`.
pub fn parent_missing_from_chain(
    query: &Query,
    block: &Block,
    stop: impl Fn() -> bool,
) -> Result<Option<[u8; 32]>, ConfirmError> {
    let created: crate::TxidSet = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    let mut need: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .flat_map(|tx| &tx.input)
        .filter(|inp| !inp.previous_output.is_null())
        .map(|inp| inp.previous_output.txid.to_byte_array())
        .filter(|txid| !created.contains(txid))
        .collect();
    need.sort_unstable();
    need.dedup();
    let unsynced_from = query.store().head_unsynced_first_fk();
    let hits: crate::TxidSet = query
        .store()
        .get_fk_by_txid_batch(&need)
        .map_err(ConfirmError::from)?
        .into_iter()
        .filter_map(|(txid, row)| row.map(|_| txid))
        .collect();
    need.retain(|txid| !hits.contains(txid));
    if need.is_empty() {
        return Ok(None);
    }
    if !query
        .store()
        .connected_in_unsynced_head(unsynced_from, &need, stop)?
        .is_empty()
    {
        return Err(ConfirmError::Store(StoreError::Corrupt(
            "invariant: tx.head misses a connected create",
        )));
    }
    Ok(need.first().copied())
}

/// IBD **load** after lookup stamp: pin + assemble.
///
/// Uses the owned stamped plan — does **not** re-run plan_batch / head resolve.
/// Single path: denserels by body range from lookup stamp (`ParentPinStamp` /
/// plan ranges). Never cold dual-path denserels / txid.body on load.
pub fn confirm_wire_load_from_plan(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    stamped: PlanStampOutcome,
    pipeline: Option<&WireLoadPipeline>,
    preverified: &ScriptPreverified,
) -> Result<ConfirmLoadOutcome, ConfirmError> {
    let ids: Vec<(u32, [u8; 32])> = stamped.metas.iter().map(|m| (m.height.0, m.hash)).collect();
    let mut stamped = stamped;
    let carried = std::mem::take(&mut stamped.trust_warns);
    let scope = super::TrustScope::enter(query);
    let result = load_from_plan_inner(query, params, milestone, stamped, pipeline, preverified);
    let warns = scope.finish(&ids, result.as_ref().err(), false);
    result.map(|mut out| {
        out.batch.trust_warns = carried;
        out.batch.trust_warns.extend(warns);
        out
    })
}

fn load_from_plan_inner(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    stamped: PlanStampOutcome,
    pipeline: Option<&WireLoadPipeline>,
    preverified: &ScriptPreverified,
) -> Result<ConfirmLoadOutcome, ConfirmError> {
    let t_work = Instant::now();
    let t_load = Instant::now();
    let PlanStampOutcome {
        mut plan,
        mut parent_pin,
        metas,
        wire_blocks,
        ..
    } = stamped;

    let ifo = pipeline.map(|p| p.in_flight);
    if let Some(ref mut p) = plan {
        p.freeze_after_pin();
    }
    let (batch_parents, spend_edges) = pin_for_wire_batch(
        query,
        plan.as_ref(),
        &mut parent_pin,
        &metas,
        &wire_blocks,
        ifo,
    )?;

    crate::note_confirm(
        &query.confirm_stats().load_ns,
        t_load.elapsed().as_nanos() as u64,
    );

    let Assembled {
        prepared,
        tx_fees,
        tx_sizes,
    } = assemble_run(
        query,
        params,
        milestone,
        metas,
        &wire_blocks,
        &batch_parents,
        &spend_edges,
        preverified,
    )?;
    drop(spend_edges);
    if let Some(ref mut plan) = plan {
        if !plan.packed.is_empty() {
            if tx_fees.len() != plan.packed.len() {
                return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: assemble tx fees length",
                )));
            }
            if tx_sizes.len() != plan.packed.len() {
                return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: txstat size length",
                )));
            }
            plan.tx_fees = tx_fees;
            plan.tx_sizes = tx_sizes;
        }
    }

    let work_ns = t_work.elapsed().as_nanos() as u64;
    Ok(ConfirmLoadOutcome {
        batch: LoadedBatch {
            prepared,
            wire_blocks,
            batch_parents,
            script_preverified: preverified.clone(),
            archive_plan: plan,
            index_want: super::index::index_want(query),
            stats: query.confirm_stats_arc(),
            trust_peer: super::confirm_waive(query),
            trust_warns: Vec::new(),
        },
        work_ns,
    })
}

struct ResolvedPrev {
    fk: rbitcoin_primitives::Fk,
    hash: [u8; 32],
}

fn header_fields_match(
    header: &bitcoin::block::Header,
    rec: &rbitcoin_store::HeaderRecord,
) -> bool {
    rec.version == header.version.to_consensus()
        && rec.timestamp == header.time
        && rec.bits == header.bits.to_consensus()
        && rec.nonce == header.nonce
        && rec.merkle_root == header.merkle_root.to_byte_array()
}

fn prev_link_for_block(
    query: &Query,
    i: usize,
    header: &bitcoin::block::Header,
    metas: &[BodyMeta],
) -> Result<ResolvedPrev, ConfirmError> {
    if i > 0 {
        let prev = &metas[i - 1];
        return Ok(ResolvedPrev {
            fk: prev.header_fk,
            hash: prev.hash,
        });
    }
    let prev_bytes = header.prev_blockhash.to_byte_array();
    if prev_bytes == [0u8; 32] {
        return Ok(ResolvedPrev {
            fk: rbitcoin_primitives::Fk::NULL,
            hash: [0u8; 32],
        });
    }
    let (fk, rec) = rbitcoin_consensus::block::require_linked_parent(
        query
            .get_header_by_hash(&prev_bytes)
            .map_err(ConfirmError::from)?,
    )?;
    Ok(ResolvedPrev { fk, hash: rec.hash })
}

/// Carried digest when the stored row is this header. A disagreeing row hashes.
///
/// Insert already checked `rec.hash` against these fields and the parent
/// (`HeaderTable::check_parent_edge`). The success path reads that row once
/// and does not hash the 80-byte header again. A mismatch, a different prev,
/// or a missing parent hashes and keeps `reject_carried_header_hash`.
fn resolve_carried_header_hash(
    query: &Query,
    i: usize,
    header: &bitcoin::block::Header,
    carried: (rbitcoin_primitives::Fk, [u8; 32]),
    metas: &[BodyMeta],
) -> Result<
    (
        [u8; 32],
        Option<rbitcoin_store::HeaderRecord>,
        Option<rbitcoin_primitives::Fk>,
    ),
    ConfirmError,
> {
    let (fk, expect) = carried;
    let matched = match query.store().get_header(fk) {
        Ok(rec) if rec.hash == expect && header_fields_match(header, &rec) => Some(rec),
        Ok(_) | Err(StoreError::NotFound) => None,
        Err(e) => return Err(ConfirmError::from(e)),
    };
    let Some(rec) = matched else {
        let hash = header.block_hash().to_byte_array();
        rbitcoin_consensus::block::reject_carried_header_hash(&hash, &expect)?;
        return Ok((hash, None, None));
    };
    let prev = match prev_link_for_block(query, i, header, metas) {
        Ok(prev) => prev,
        Err(e) => {
            let hash = header.block_hash().to_byte_array();
            rbitcoin_consensus::block::reject_carried_header_hash(&hash, &expect)?;
            return Err(e);
        }
    };
    if rec.prev_fk == prev.fk && header.prev_blockhash.to_byte_array() == prev.hash {
        return Ok((expect, Some(rec), Some(prev.fk)));
    }
    let hash = header.block_hash().to_byte_array();
    rbitcoin_consensus::block::reject_carried_header_hash(&hash, &expect)?;
    Ok((hash, None, Some(prev.fk)))
}

/// Structure + prepare + plan_batch only (stamp create_fk). Shared by lookup stage.
pub fn wire_lookup_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<LookupPhaseOut, ConfirmError> {
    lookup_require_contiguous(blocks)?;

    let mut wire_blocks: Vec<Arc<Block>> = Vec::with_capacity(blocks.len());
    let mut metas: Vec<BodyMeta> = Vec::with_capacity(blocks.len());

    let tip_h = query.tip_height().map(|h| h.0);
    let store_path_lo = match tip_h {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let path_lo = pipeline.map(|p| p.path_lo).unwrap_or(store_path_lo);
    check_carried_header_lens(pipeline, blocks.len())?;

    let mut struct_ns = 0u64;
    let mut header_ns = 0u64;
    let mut prepare_ns = 0u64;

    for (i, (height, block, caller_pres)) in blocks.iter().enumerate() {
        let block = Arc::clone(block);
        let ctx = ValidationContext::at(params, *height, milestone);
        rbitcoin_consensus::note_block_height(height.0);
        let t_struct = Instant::now();
        let stats = query.confirm_stats();
        let mut note = |txid_ns, wtxid_ns, walk_ns| {
            stats.note_struct_parts(txid_ns, wtxid_ns, walk_ns);
        };
        let pres = rbitcoin_consensus::block::validate_block_structure_with_pres(
            block.as_ref(),
            &ctx,
            caller_pres.as_ref().map(Arc::clone),
            Some(&mut note),
        )?;
        let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
        struct_ns = struct_ns.saturating_add(t_struct.elapsed().as_nanos() as u64);
        let carried = carried_header_at(pipeline, i);
        let (hash, proven, carried_prev) = match carried {
            Some(row) => resolve_carried_header_hash(query, i, &block.header, row, &metas)?,
            None => (block.block_hash().to_byte_array(), None, None),
        };
        let t_header = Instant::now();
        stamp_check_header_link(
            query,
            params,
            pipeline,
            i,
            *height,
            path_lo,
            store_path_lo,
            &block.header,
            hash,
            carried,
            (i > 0).then(|| metas[i - 1].hash),
        )?;
        header_ns = header_ns.saturating_add(t_header.elapsed().as_nanos() as u64);

        let t_prep = Instant::now();
        let prev_fk = if let Some(fk) = carried_prev {
            fk
        } else {
            prev_link_for_block(query, i, &block.header, &metas)?.fk
        };
        let header_rec = crate::convert::header_to_record(prev_fk, &block.header, hash);
        prepare_ns = prepare_ns.saturating_add(t_prep.elapsed().as_nanos() as u64);
        let t_put = Instant::now();
        let header_fk = stamp_header_fk(
            query,
            &header_rec,
            carried.map(|(fk, _)| fk),
            proven.as_ref(),
        )?;
        header_ns = header_ns.saturating_add(t_put.elapsed().as_nanos() as u64);
        wire_blocks.push(block);
        metas.push(BodyMeta {
            height: *height,
            hash,
            header_fk,
            header_rec,
            tx_fks: Vec::new(),
            txids,
            pres,
        });
    }

    let (plan, filter_ns, batch_ns) =
        lookup_bind_archive_plan(query, pipeline, &mut metas, &wire_blocks)?;
    let plan_ns = filter_ns.saturating_add(batch_ns);
    lookup_note_stamp(
        query, struct_ns, header_ns, prepare_ns, filter_ns, batch_ns, plan_ns,
    );
    Ok((plan, metas, wire_blocks, plan_ns))
}

#[doc(hidden)]
pub fn check_carried_header_lens(
    pipeline: Option<&WireLoadPipeline>,
    n_blocks: usize,
) -> Result<(), ConfirmError> {
    let Some(p) = pipeline else {
        return Ok(());
    };
    if (!p.carried_header_fks.is_empty() || !p.carried_header_hashes.is_empty())
        && (p.carried_header_fks.len() != n_blocks || p.carried_header_hashes.len() != n_blocks)
    {
        return Err(ConfirmError::Store(StoreError::Corrupt(
            "invariant: carried header length",
        )));
    }
    Ok(())
}

#[doc(hidden)]
pub fn carried_header_at(
    pipeline: Option<&WireLoadPipeline>,
    i: usize,
) -> Option<(rbitcoin_primitives::Fk, [u8; 32])> {
    pipeline.and_then(|p| {
        let fk = p.carried_header_fks.get(i).copied()?;
        if fk.is_null() {
            return None;
        }
        Some((fk, p.carried_header_hashes[i]))
    })
}

#[allow(clippy::too_many_arguments)] // one header-link stamp; call site stays unbundled
#[doc(hidden)]
pub fn stamp_check_header_link(
    query: &Query,
    params: &ChainParams,
    pipeline: Option<&WireLoadPipeline>,
    i: usize,
    height: Height,
    path_lo: u32,
    store_path_lo: u32,
    header: &bitcoin::block::Header,
    hash: [u8; 32],
    carried: Option<(rbitcoin_primitives::Fk, [u8; 32])>,
    prev_meta_hash: Option<[u8; 32]>,
) -> Result<(), ConfirmError> {
    if i == 0 {
        rbitcoin_consensus::block::reject_batch_starts_at(height.0, path_lo)?;
    }
    let prev_bytes = header.prev_blockhash.to_byte_array();
    if let Some((_, expect)) = carried {
        rbitcoin_consensus::block::reject_carried_header_hash(&hash, &expect)?;
        if i == 0 {
            if path_lo != store_path_lo {
                let expect_prev = pipeline.and_then(|p| p.parent_hash).unwrap_or([0u8; 32]);
                rbitcoin_consensus::block::reject_prev_link(&prev_bytes, &expect_prev)?;
            }
        } else {
            rbitcoin_consensus::block::reject_prev_link(
                &prev_bytes,
                &prev_meta_hash.unwrap_or([0u8; 32]),
            )?;
        }
        return Ok(());
    }
    if i == 0 {
        if path_lo == store_path_lo {
            validate_header_hashed(query, params, height, header, hash)?;
        } else {
            let expect_prev = pipeline.and_then(|p| p.parent_hash).unwrap_or([0u8; 32]);
            rbitcoin_consensus::block::reject_prev_link(&prev_bytes, &expect_prev)?;
            pow_hash_meets_target(hash, header.bits, params.pow_limit)?;
        }
        return Ok(());
    }
    rbitcoin_consensus::block::reject_prev_link(&prev_bytes, &prev_meta_hash.unwrap_or([0u8; 32]))?;
    pow_hash_meets_target(hash, header.bits, params.pow_limit)?;
    Ok(())
}

#[doc(hidden)]
pub fn stamp_header_fk(
    query: &Query,
    header_rec: &rbitcoin_store::HeaderRecord,
    carried: Option<rbitcoin_primitives::Fk>,
    proven: Option<&rbitcoin_store::HeaderRecord>,
) -> Result<rbitcoin_primitives::Fk, ConfirmError> {
    if let Some(fk) = carried {
        if proven.is_some_and(|rec| rec.hash == header_rec.hash) {
            crate::note_confirm(&query.confirm_stats().phase_prep_header_skip_n, 1);
            return Ok(fk);
        }
        match query.store().get_header(fk) {
            Ok(rec) if rec.hash == header_rec.hash => {
                crate::note_confirm(&query.confirm_stats().phase_prep_header_skip_n, 1);
                return Ok(fk);
            }
            Ok(_) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(ConfirmError::from(e)),
        }
    }
    if let Some((fk, _)) = query
        .get_header_by_hash(&header_rec.hash)
        .map_err(ConfirmError::from)?
    {
        Ok(fk)
    } else {
        query
            .store()
            .put_header(header_rec)
            .map_err(ConfirmError::from)
    }
}

#[doc(hidden)]
pub fn lookup_require_contiguous(blocks: &[WireBlockIn]) -> Result<(), ConfirmError> {
    rbitcoin_consensus::block::reject_confirm_batch(
        &blocks.iter().map(|(h, _, _)| h.0).collect::<Vec<_>>(),
    )
    .map_err(ConfirmError::from)
}

#[doc(hidden)]
pub fn lookup_note_stamp(
    query: &Query,
    struct_ns: u64,
    header_ns: u64,
    prepare_ns: u64,
    filter_ns: u64,
    batch_ns: u64,
    plan_ns: u64,
) {
    query
        .confirm_stats()
        .note_stamp(struct_ns, prepare_ns, filter_ns, batch_ns);
    // `note_confirm` already ignores a zero add. A `> 0` gate here is the
    // same call, and `>` versus `==` would drop a real sample.
    crate::note_confirm(&query.confirm_stats().phase_prep_struct_ns, struct_ns);
    crate::note_confirm(&query.confirm_stats().phase_prep_header_ns, header_ns);
    crate::note_confirm(&query.confirm_stats().phase_prep_prepare_ns, prepare_ns);
    crate::note_confirm(&query.confirm_stats().phase_prep_filter_plan_ns, plan_ns);
}

#[doc(hidden)]
pub fn lookup_bind_have_body(
    query: &Query,
    metas: &mut [BodyMeta],
    wire_blocks: &[Arc<Block>],
) -> Result<(), ConfirmError> {
    for (i, m) in metas.iter_mut().enumerate() {
        if let Some(list) = query
            .store()
            .header_txs
            .get_list(m.header_fk)
            .map_err(ConfirmError::from)?
        {
            m.tx_fks = list;
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
    Ok(())
}

#[doc(hidden)]
pub fn lookup_bind_need_body<'a>(
    query: &Query,
    pipeline: Option<&WireLoadPipeline>,
    metas: &'a mut [BodyMeta],
    wire_blocks: &'a [Arc<Block>],
    need_fks: &[rbitcoin_primitives::Fk],
) -> Result<crate::ArchiveWritePlan, ConfirmError> {
    let mut need = Vec::with_capacity(need_fks.len());
    for fk in need_fks {
        let i = metas
            .iter()
            .position(|m| m.header_fk == *fk)
            .ok_or(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: need-body header_fk not in batch",
            )))?;
        need.push((*fk, &wire_blocks[i], metas[i].txids.as_slice()));
    }
    let plan = match pipeline {
        Some(p) => query
            .archive_plan_batch_from_wire(
                &need,
                p.next_tx_start.max(1),
                p.in_flight,
                p.skeleton.as_ref(),
                p.skeleton.is_some().then_some(p.carried_need.as_slice()),
            )
            .map_err(ConfirmError::from)?,
        None => query
            .archive_plan_batch_from_wire(
                &need,
                query.tx_body_count().saturating_add(1).max(1),
                &crate::InFlight::new(),
                None,
                None,
            )
            .map_err(ConfirmError::from)?,
    };
    let by_header = create_fks_from_header_ranges(&plan.per_header_ranges);
    for (i, m) in metas.iter_mut().enumerate() {
        if let Some(id) = m.header_fk.get() {
            if let Some(fks) = by_header.get(&id) {
                m.tx_fks = fks.clone();
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
    Ok(plan)
}

#[doc(hidden)]
pub fn lookup_bind_archive_plan(
    query: &Query,
    pipeline: Option<&WireLoadPipeline>,
    metas: &mut [BodyMeta],
    wire_blocks: &[Arc<Block>],
) -> Result<(Option<crate::ArchiveWritePlan>, u64, u64), ConfirmError> {
    let t_filter = Instant::now();
    let header_fks: Vec<rbitcoin_primitives::Fk> = metas.iter().map(|m| m.header_fk).collect();
    let need_fks = query
        .archive_filter_need_header_fks(&header_fks)
        .map_err(ConfirmError::from)?;
    confirm_archive_kind(header_fks.len(), need_fks.len())?;
    let filter_ns = t_filter.elapsed().as_nanos() as u64;
    let t_batch = Instant::now();
    let plan = if need_fks.is_empty() {
        lookup_bind_have_body(query, metas, wire_blocks)?;
        None
    } else {
        Some(lookup_bind_need_body(
            query,
            pipeline,
            metas,
            wire_blocks,
            &need_fks,
        )?)
    };
    let batch_ns = t_batch.elapsed().as_nanos() as u64;
    Ok((plan, filter_ns, batch_ns))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmArchiveKind {
    AllNeedBody,
    AllHaveBody,
}

pub fn confirm_archive_kind(
    n_headers: usize,
    n_need: usize,
) -> Result<ConfirmArchiveKind, ConfirmError> {
    if n_need == 0 {
        Ok(ConfirmArchiveKind::AllHaveBody)
    } else if n_need == n_headers {
        Ok(ConfirmArchiveKind::AllNeedBody)
    } else {
        Err(ConfirmError::Store(StoreError::Corrupt(
            "invariant: confirm batch mixed archived",
        )))
    }
}

pub fn create_fks_from_header_ranges(
    per_header_ranges: &[(rbitcoin_primitives::Fk, rbitcoin_primitives::Fk, u32)],
) -> U64Map<Vec<rbitcoin_primitives::Fk>> {
    let mut by_header: U64Map<Vec<rbitcoin_primitives::Fk>> = U64Map::default();
    for &(hfk, first, n) in per_header_ranges {
        let Some(hid) = hfk.get() else { continue };
        let mut slice = Vec::with_capacity(n as usize);
        for i in 0..n {
            slice.push(rbitcoin_primitives::Fk(
                first.0.saturating_add(u64::from(i)),
            ));
        }
        by_header.insert(hid, slice);
    }
    by_header
}
