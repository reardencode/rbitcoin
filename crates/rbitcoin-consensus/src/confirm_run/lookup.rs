//! Lookup / stamp for wire confirm.

use super::*;

/// Pin-stage denserels mix (`pin_for_wire_batch`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DenserelsWarmStats {
    /// Unique external parent creates considered (stamped create_fk, not same-batch).
    pub parents: u32,
    /// Already covered via in-flight / same-batch / pstore adopt.
    pub already: u32,
    /// Cold denserels body loads (`txout` by stamped range). Always 0 on the
    /// shipped pin path — range-fill is `PIN_NEW`, not this field.
    pub cold: u32,
    /// Same-batch plan creates (offline denserels at pin).
    pub same_batch: u32,
    pub work_ns: u64,
}

/// Lookup-stamped external parent material for load body denserels.
///
/// **Lookup** fills this via `tx.head` / `tx.idx` / `txid.body` (never `tx.body`).
/// **Load** denserels by range using only these maps (+ plan offline pins).
/// Integer create_fk maps use [`U64Map`] (identity hasher) — pack-scale win over SipHash.
#[derive(Debug, Default, Clone)]
pub struct ParentPinStamp {
    /// create_fk_id → Class A body range.
    pub ranges: U64Map<(u64, u64)>,
    /// create_fk_id → create txid (wire / sidefile at lookup).
    pub txids: U64Map<[u8; 32]>,
    /// prev_txid → create_fk_id (plan=None thin edges without head on load).
    pub create_by_txid: HashMap<[u8; 32], u64>,
}

impl ParentPinStamp {
    /// Move plan stamp maps into the load stamp (no 100k-entry clone).
    pub(crate) fn take_from_plan(plan: &mut rbitcoin_query::ArchiveWritePlan) -> Self {
        Self::from_maps(
            std::mem::take(&mut plan.external_parent_ranges),
            std::mem::take(&mut plan.external_parent_txids),
        )
    }

    fn from_maps(
        ranges: rbitcoin_query::U64Map<(u64, u64)>,
        txids: rbitcoin_query::U64Map<[u8; 32]>,
    ) -> Self {
        let mut create_by_txid = HashMap::with_capacity(txids.len());
        for (id, tid) in &txids {
            create_by_txid.insert(*tid, *id);
        }
        Self {
            ranges,
            txids,
            create_by_txid,
        }
    }

    #[inline]
    pub(super) fn create_txid(&self, create_fk_id: u64) -> Option<[u8; 32]> {
        self.txids
            .get(&create_fk_id)
            .copied()
            .filter(|t| *t != [0u8; 32])
    }
}

/// Lookup-stage output: structure + plan batch (create_fk + parent body ranges).
///
/// **No `tx.body` denserels on lookup.** Load denserels by range from
/// [`ParentPinStamp`] / plan ranges. Handoff is owned plan + parent pin stamp.
pub struct PlanStampOutcome {
    pub plan: Option<rbitcoin_query::ArchiveWritePlan>,
    /// External parent fk/range/txid stamped at lookup (always; including plan=None).
    pub parent_pin: ParentPinStamp,
    /// Wall ns for structure + plan_batch (head stamp).
    pub work_ns: u64,
    metas: Vec<BodyMeta>,
    wire_blocks: Vec<Arc<Block>>,
}

/// IBD **lookup** stage: structure + stamp create_fk + parent body ranges.
///
/// May read `tx.head`, `tx.idx`, `txid.body`. **Never** denserels-decode `tx.body`.
/// Parent create_fk: in-flight → published `live_union` → recent creates → TipOnly leftover.
/// Wire blocks are `Arc` so IBD resolve can decode once and hand off without
/// cloning full `Block` payloads into stamp.
pub fn confirm_wire_lookup_stamp(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Arc<Block>)],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<PlanStampOutcome, ConsensusError> {
    let t0 = Instant::now();
    query.on_load_pack().map_err(ConsensusError::from)?;
    let (mut plan, metas, wire_blocks, plan_ns) =
        wire_lookup_phase(query, params, milestone, blocks, pipeline)?;
    let ifo = pipeline.map(|p| &p.in_flight);
    let parent_pin = match plan.as_mut() {
        Some(p) => ParentPinStamp::take_from_plan(p),
        None => stamp_parent_pin_archived(query, params, &metas, &wire_blocks, ifo)?,
    };
    lookup_stage_stats::BLOCKS.fetch_add(blocks.len() as u64, Ordering::Relaxed);
    lookup_stage_stats::HEAD_NS.fetch_add(plan_ns, Ordering::Relaxed);
    let work_ns = t0.elapsed().as_nanos() as u64;
    lookup_stage_stats::TOTAL_NS.fetch_add(work_ns, Ordering::Relaxed);
    Ok(PlanStampOutcome {
        plan,
        parent_pin,
        work_ns,
        metas,
        wire_blocks,
    })
}

/// plan=None rehydrate: stamp external parent create_fk + body_range + txid
/// via the shared query helper so load never probes those tables.
pub(super) fn stamp_parent_pin_archived(
    query: &Query,
    params: &ChainParams,
    metas: &[BodyMeta],
    wire_blocks: &[Arc<Block>],
    in_flight: Option<&rbitcoin_query::InFlightView>,
) -> Result<ParentPinStamp, ConsensusError> {
    let mut same_batch: HashMap<[u8; 32], u64> = HashMap::new();
    for m in metas {
        for (tid, fk) in m.txids.iter().zip(m.tx_fks.iter()) {
            if let Some(id) = fk.get() {
                same_batch.insert(*tid, id);
            }
        }
    }
    let mut need_external: HashMap<[u8; 32], ()> = HashMap::new();
    for (m, block) in metas.iter().zip(wire_blocks.iter()) {
        let _ = m;
        for tx in &block.txdata {
            for inp in &tx.input {
                if inp.previous_output.is_null() {
                    continue;
                }
                let prev = inp.previous_output.txid.to_byte_array();
                if same_batch.contains_key(&prev) {
                    continue;
                }
                if prev != [0u8; 32] {
                    need_external.insert(prev, ());
                }
            }
        }
        // BIP30 (pre-BIP34): same head wave as parents. TipOnly returns a
        // connected sibling if this create would overwrite a live txid.
        if !params.bip34_active_at(m.height.0) {
            for tx in &block.txdata {
                need_external.insert(tx.compute_txid().to_byte_array(), ());
            }
        }
    }
    let empty = rbitcoin_query::InFlightView::empty();
    let ifo = in_flight.unwrap_or(&empty);
    let need_vec: Vec<[u8; 32]> = need_external.into_keys().collect();
    let ext = rbitcoin_query::stamp_external_parents(
        query.store(),
        &need_vec,
        ifo,
        query.published_ids(),
        query.recent_creates(),
    )
    .map_err(ConsensusError::from)?;
    let mut stamp = ParentPinStamp {
        ranges: ext.ranges,
        txids: ext.txids,
        create_by_txid: HashMap::with_capacity(ext.resolved.len().saturating_add(same_batch.len())),
    };
    for (tid, fk) in ext.resolved {
        if let Some(id) = fk.get() {
            stamp.create_by_txid.insert(tid, id);
        }
    }
    for (tid, id) in same_batch {
        stamp.create_by_txid.insert(tid, id);
        stamp.txids.insert(id, tid);
    }
    // plan=None same-batch creates have no CreatePin offline — idx body_range.
    rbitcoin_query::fill_missing_parent_ranges(query.store(), ifo, &mut stamp.ranges, &stamp.txids)
        .map_err(ConsensusError::from)?;
    // Identities are stamped from wire prev_txid at insert time — never soft-fill
    // from txid.body here (that would be a dual path after lookup promised identity).
    for (&id, tid) in &stamp.txids {
        if *tid == [0u8; 32] {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: plan=None parent stamp zero create identity",
            )));
        }
        let _ = id;
    }
    Ok(stamp)
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
) -> Result<ConfirmLoadOutcome, ConsensusError> {
    let t_work = Instant::now();
    let t_load = Instant::now();
    let PlanStampOutcome {
        mut plan,
        parent_pin,
        metas,
        wire_blocks,
        ..
    } = stamped;

    let ifo = pipeline.map(|p| &p.in_flight);
    let parent_store = pipeline.map(|p| &p.parent_store);
    let (batch_parents, batch_thin, _warm) = pin_for_wire_batch(
        query,
        plan.as_ref(),
        &parent_pin,
        &metas,
        &wire_blocks,
        ifo,
        parent_store,
    )?;
    if let Some(ref mut p) = plan {
        p.freeze_after_pin();
    }

    confirm_phase_stats::LOAD_NS.fetch_add(t_load.elapsed().as_nanos() as u64, Ordering::Relaxed);

    let prepared = assemble_run(
        query,
        params,
        milestone,
        metas,
        &wire_blocks,
        &batch_parents,
        &batch_thin,
    )?;
    drop(batch_thin);

    let work_ns = t_work.elapsed().as_nanos() as u64;
    Ok(ConfirmLoadOutcome {
        batch: LoadedBatch {
            prepared,
            wire_blocks,
            batch_parents,
            script_preverified: preverified.clone(),
            archive_plan: plan,
        },
        work_ns,
    })
}

/// Structure + prepare + plan_batch only (stamp create_fk). Shared by lookup stage.
pub(super) fn wire_lookup_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Arc<Block>)],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<
    (
        Option<rbitcoin_query::ArchiveWritePlan>,
        Vec<BodyMeta>,
        Vec<Arc<Block>>,
        u64,
    ),
    ConsensusError,
> {
    if blocks.is_empty() {
        return Err(ConsensusError::BadBlock("empty confirm batch"));
    }
    for w in blocks.windows(2) {
        if w[1].0 .0 != w[0].0 .0.saturating_add(1) {
            return Err(ConsensusError::BadBlock("confirm run not contiguous"));
        }
    }

    let mut with_fk: Vec<(
        rbitcoin_primitives::Fk,
        rbitcoin_store::HeaderRecord,
        Vec<rbitcoin_query::TxApply>,
    )> = Vec::with_capacity(blocks.len());
    let mut wire_blocks: Vec<Arc<Block>> = Vec::with_capacity(blocks.len());
    let mut metas: Vec<BodyMeta> = Vec::with_capacity(blocks.len());

    let tip_h = query.tip_height().map(|h| h.0);
    let store_path_lo = match tip_h {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let path_lo = pipeline.map(|p| p.path_lo).unwrap_or(store_path_lo);

    let mut struct_ns = 0u64;
    let mut prepare_ns = 0u64;

    for (i, (height, block)) in blocks.iter().enumerate() {
        let block = Arc::clone(block);
        let hash = block.block_hash().to_byte_array();
        let ctx = ValidationContext::at(params, *height, milestone);
        let t_struct = Instant::now();
        let stashed = query.block_queue_resolved(height.0);
        let pres = crate::block::validate_block_structure_with_pres(
            block.as_ref(),
            &ctx,
            stashed.as_ref().map(|w| w.pres.as_ref()),
        )?;
        let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
        if i == 0 {
            if height.0 != path_lo {
                return Err(ConsensusError::BadPrev);
            }
            if path_lo == store_path_lo {
                validate_header(query, params, *height, &block.header)?;
            } else {
                let expect_prev = pipeline.and_then(|p| p.parent_hash).unwrap_or([0u8; 32]);
                if block.header.prev_blockhash.to_byte_array() != expect_prev {
                    return Err(ConsensusError::BadPrev);
                }
                let target = bitcoin::Target::from_compact(block.header.bits);
                if target > params.pow_limit {
                    return Err(ConsensusError::BadHeader("target above pow limit"));
                }
                block
                    .header
                    .validate_pow(target)
                    .map_err(|_| ConsensusError::InvalidPow)?;
            }
        } else {
            // Prev wire hash already on metas[i-1] — no rehash.
            let prev_hash = metas[i - 1].hash;
            if block.header.prev_blockhash.to_byte_array() != prev_hash {
                return Err(ConsensusError::BadPrev);
            }
            let target = bitcoin::Target::from_compact(block.header.bits);
            if target > params.pow_limit {
                return Err(ConsensusError::BadHeader("target above pow limit"));
            }
            block
                .header
                .validate_pow(target)
                .map_err(|_| ConsensusError::InvalidPow)?;
        }
        struct_ns = struct_ns.saturating_add(t_struct.elapsed().as_nanos() as u64);

        let t_prep = Instant::now();
        let (header_rec, txs) =
            crate::prepare_block_for_archive_with_txids(query, block.as_ref(), &txids)?;
        let header_fk = if let Some((fk, _)) = query
            .get_header_by_hash(&header_rec.hash)
            .map_err(ConsensusError::from)?
        {
            fk
        } else {
            query
                .store()
                .put_header(&header_rec)
                .map_err(ConsensusError::from)?
        };
        let prev_bytes = block.header.prev_blockhash.to_byte_array();
        query.confirm_parent_cache().put_header_plan(
            height.0,
            header_fk,
            header_rec.clone(),
            Vec::new(),
            prev_bytes,
        );
        prepare_ns = prepare_ns.saturating_add(t_prep.elapsed().as_nanos() as u64);
        with_fk.push((header_fk, header_rec.clone(), txs));
        wire_blocks.push(block);
        metas.push(BodyMeta {
            height: *height,
            hash,
            header_fk,
            header_rec,
            tx_fks: Vec::new(),
            txids,
            pres: std::sync::Arc::from(pres),
        });
    }

    let t_filter = Instant::now();
    let (_header_fks, mut need) = query
        .archive_filter_need_bodies(&mut with_fk)
        .map_err(ConsensusError::from)?;
    let filter_ns = t_filter.elapsed().as_nanos() as u64;
    let t_batch = Instant::now();
    let plan = if need.is_empty() {
        for (i, m) in metas.iter_mut().enumerate() {
            if let Some(list) = query
                .store()
                .header_txs
                .get_list(m.header_fk)
                .map_err(ConsensusError::from)?
            {
                m.tx_fks = list;
            }
            // Never rehash wire for lookup — index by batch position.
            let prev = wire_blocks[i].header.prev_blockhash.to_byte_array();
            query.confirm_parent_cache().put_header_plan(
                m.height.0,
                m.header_fk,
                m.header_rec.clone(),
                m.tx_fks.clone(),
                prev,
            );
        }
        None
    } else {
        let plan = match pipeline {
            Some(p) => query
                .archive_plan_batch_from_store(
                    &mut need,
                    p.next_tx_start.max(1),
                    &p.in_flight,
                    Some(p.published.as_ref()),
                )
                .map_err(ConsensusError::from)?,
            None => query
                .archive_plan_batch_from_store(
                    &mut need,
                    query.tx_body_count().saturating_add(1).max(1),
                    &rbitcoin_query::InFlightView::empty(),
                    None,
                )
                .map_err(ConsensusError::from)?,
        };
        let by_header = create_fks_from_header_ranges(&plan.per_header_ranges);
        for (i, m) in metas.iter_mut().enumerate() {
            if let Some(id) = m.header_fk.get() {
                if let Some(fks) = by_header.get(&id) {
                    m.tx_fks = fks.clone();
                }
            }
            if m.tx_fks.is_empty() {
                if let Some(list) = query
                    .store()
                    .header_txs
                    .get_list(m.header_fk)
                    .map_err(ConsensusError::from)?
                {
                    m.tx_fks = list;
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
        Some(plan)
    };
    let batch_ns = t_batch.elapsed().as_nanos() as u64;
    // plan_ns for HEAD_NS: filter + batch (legacy “lookup wall” without struct/prepare).
    let plan_ns = filter_ns.saturating_add(batch_ns);
    plan_stamp_sub_stats::note(struct_ns, prepare_ns, filter_ns, batch_ns);
    Ok((plan, metas, wire_blocks, plan_ns))
}

pub(super) fn create_fks_from_header_ranges(
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

/// Stamp-phase sub-walls for lookup_thr diagnosis (structure / prepare / filter / batch).
///
/// Batch is the archive plan_batch wall (assign+collect+inflight+head_fk+stamp+finish
/// already timed in `archive_phase_stats`). `head_fk` = leftover TipOnly
/// `get_fk_by_txid_batch`. Window sum is [`sample_and_reset`].
pub mod plan_stamp_sub_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static STRUCT_NS: AtomicU64 = AtomicU64::new(0);
    static STRUCT_TXID_NS: AtomicU64 = AtomicU64::new(0);
    static STRUCT_WTXID_NS: AtomicU64 = AtomicU64::new(0);
    static STRUCT_WALK_NS: AtomicU64 = AtomicU64::new(0);
    static PREPARE_NS: AtomicU64 = AtomicU64::new(0);
    static FILTER_NS: AtomicU64 = AtomicU64::new(0);
    static BATCH_NS: AtomicU64 = AtomicU64::new(0);

    /// Split of [`validate_block_structure_hashed`]: txid encode, wtxid encode, other walks.
    pub fn note_struct_parts(txid_ns: u64, wtxid_ns: u64, walk_ns: u64) {
        if txid_ns > 0 {
            STRUCT_TXID_NS.fetch_add(txid_ns, Ordering::Relaxed);
        }
        if wtxid_ns > 0 {
            STRUCT_WTXID_NS.fetch_add(wtxid_ns, Ordering::Relaxed);
        }
        if walk_ns > 0 {
            STRUCT_WALK_NS.fetch_add(walk_ns, Ordering::Relaxed);
        }
    }

    pub fn note(struct_ns: u64, prepare_ns: u64, filter_ns: u64, batch_ns: u64) {
        if struct_ns > 0 {
            STRUCT_NS.fetch_add(struct_ns, Ordering::Relaxed);
        }
        if prepare_ns > 0 {
            PREPARE_NS.fetch_add(prepare_ns, Ordering::Relaxed);
        }
        if filter_ns > 0 {
            FILTER_NS.fetch_add(filter_ns, Ordering::Relaxed);
        }
        if batch_ns > 0 {
            BATCH_NS.fetch_add(batch_ns, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct Sample {
        pub struct_ns: u64,
        pub struct_txid_ns: u64,
        pub struct_wtxid_ns: u64,
        pub struct_walk_ns: u64,
        pub prepare_ns: u64,
        pub filter_ns: u64,
        pub batch_ns: u64,
    }

    pub fn sample_and_reset() -> Sample {
        Sample {
            struct_ns: STRUCT_NS.swap(0, Ordering::Relaxed),
            struct_txid_ns: STRUCT_TXID_NS.swap(0, Ordering::Relaxed),
            struct_wtxid_ns: STRUCT_WTXID_NS.swap(0, Ordering::Relaxed),
            struct_walk_ns: STRUCT_WALK_NS.swap(0, Ordering::Relaxed),
            prepare_ns: PREPARE_NS.swap(0, Ordering::Relaxed),
            filter_ns: FILTER_NS.swap(0, Ordering::Relaxed),
            batch_ns: BATCH_NS.swap(0, Ordering::Relaxed),
        }
    }
}

/// Accumulators for the **lookup** pipeline stage (plan+stamp + denserels ensure).
pub mod lookup_stage_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static BLOCKS: AtomicU64 = AtomicU64::new(0);
    pub static PARENTS: AtomicU64 = AtomicU64::new(0);
    pub static ALREADY: AtomicU64 = AtomicU64::new(0);
    pub static COLD: AtomicU64 = AtomicU64::new(0);
    pub static UNRESOLVED: AtomicU64 = AtomicU64::new(0);
    pub static TOTAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static COLLECT_NS: AtomicU64 = AtomicU64::new(0);
    pub static HEAD_NS: AtomicU64 = AtomicU64::new(0);
    pub static COLD_IO_NS: AtomicU64 = AtomicU64::new(0);

    pub fn note(
        blocks: u64,
        parents: u64,
        already: u64,
        cold: u64,
        unresolved: u64,
        total_ns: u64,
        collect_ns: u64,
        head_ns: u64,
        cold_io_ns: u64,
    ) {
        if blocks > 0 {
            BLOCKS.fetch_add(blocks, Ordering::Relaxed);
        }
        if parents > 0 {
            PARENTS.fetch_add(parents, Ordering::Relaxed);
        }
        if already > 0 {
            ALREADY.fetch_add(already, Ordering::Relaxed);
        }
        if cold > 0 {
            COLD.fetch_add(cold, Ordering::Relaxed);
        }
        if unresolved > 0 {
            UNRESOLVED.fetch_add(unresolved, Ordering::Relaxed);
        }
        if total_ns > 0 {
            TOTAL_NS.fetch_add(total_ns, Ordering::Relaxed);
        }
        if collect_ns > 0 {
            COLLECT_NS.fetch_add(collect_ns, Ordering::Relaxed);
        }
        if head_ns > 0 {
            HEAD_NS.fetch_add(head_ns, Ordering::Relaxed);
        }
        if cold_io_ns > 0 {
            COLD_IO_NS.fetch_add(cold_io_ns, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct Sample {
        pub blocks: u64,
        pub parents: u64,
        pub already: u64,
        pub cold: u64,
        pub unresolved: u64,
        pub total_ns: u64,
        pub collect_ns: u64,
        pub head_ns: u64,
        pub cold_io_ns: u64,
    }

    pub fn sample_and_reset() -> Sample {
        Sample {
            blocks: BLOCKS.swap(0, Ordering::Relaxed),
            parents: PARENTS.swap(0, Ordering::Relaxed),
            already: ALREADY.swap(0, Ordering::Relaxed),
            cold: COLD.swap(0, Ordering::Relaxed),
            unresolved: UNRESOLVED.swap(0, Ordering::Relaxed),
            total_ns: TOTAL_NS.swap(0, Ordering::Relaxed),
            collect_ns: COLLECT_NS.swap(0, Ordering::Relaxed),
            head_ns: HEAD_NS.swap(0, Ordering::Relaxed),
            cold_io_ns: COLD_IO_NS.swap(0, Ordering::Relaxed),
        }
    }
}

/// Lookup-side identity fill: plan RAM first, else `txid.body` (lookup may read
/// the sidefile; load must not call this).
#[inline]
pub(super) fn known_create_txid_lookup(
    query: &Query,
    create_fk_id: u64,
    plan: Option<&rbitcoin_query::ArchiveWritePlan>,
) -> Result<[u8; 32], ConsensusError> {
    if let Some(p) = plan {
        if let Some(tid) = p.external_parent_txid(create_fk_id) {
            if tid != [0u8; 32] {
                return Ok(tid);
            }
        }
    }
    let tid = query
        .store()
        .txs
        .body_txid(rbitcoin_primitives::Fk(create_fk_id))
        .map_err(ConsensusError::from)?;
    if tid == [0u8; 32] {
        return Err(ConsensusError::Store(StoreError::Corrupt(
            "invariant: pin parent create identity still zero after txid.body",
        )));
    }
    Ok(tid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use rbitcoin_query::IdMap;
    use rbitcoin_store::HeaderRecord;
    use std::sync::Once;

    fn tmp_query() -> (std::path::PathBuf, Query) {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
                std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
            }
        });
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-stamp-archived-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let q = Query::open_or_create(&path).unwrap();
        (path, q)
    }

    fn spend_block(prev: [u8; 32]) -> Block {
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(prev),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }],
        }
    }

    /// plan=None rehydrate and the query helper stamp the same published parent.
    #[test]
    fn archived_stamp_matches_shared_helper_on_published() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x81;
            t
        };
        let mut m = IdMap::default();
        m.insert(parent_txid, (rbitcoin_primitives::Fk(88), (4000, 32)));
        q.published_ids().publish(std::sync::Arc::new(m));

        let helper = rbitcoin_query::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &rbitcoin_query::InFlightView::empty(),
            q.published_ids(),
            q.recent_creates(),
        )
        .expect("shared helper");

        let meta = BodyMeta {
            height: Height(1),
            hash: [0u8; 32],
            header_fk: rbitcoin_primitives::Fk::NULL,
            header_rec: HeaderRecord {
                prev_fk: rbitcoin_primitives::Fk::NULL,
                version: 1,
                timestamp: 1,
                bits: 1,
                nonce: 1,
                merkle_root: [0u8; 32],
                hash: [0u8; 32],
            },
            tx_fks: Vec::new(),
            txids: Vec::new(),
            pres: std::sync::Arc::from(Vec::new()),
        };
        let stamp = stamp_parent_pin_archived(
            &q,
            &params,
            &[meta],
            &[std::sync::Arc::new(spend_block(parent_txid))],
            None,
        )
        .expect("archived stamp");
        assert_eq!(stamp.ranges.get(&88), helper.ranges.get(&88));
        assert_eq!(stamp.txids.get(&88), helper.txids.get(&88));
        assert_eq!(stamp.create_by_txid.get(&parent_txid), Some(&88));
        let _ = std::fs::remove_dir_all(&path);
    }
}
