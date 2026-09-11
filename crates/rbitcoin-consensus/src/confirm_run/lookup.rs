//! Lookup / stamp for wire confirm.

use super::*;

/// Lookup-stamped external parent material for load body denserels.
///
/// **Lookup** fills this via `tx.head` / `tx.idx` / `txid.body` (never `tx.body`).
/// **Load** denserels by range using only [`rbitcoin_query::ParentIdent`] (+ plan offline pins).
/// Integer create_fk map uses [`U64Map`] (identity hasher) — pack-scale win over SipHash.
#[derive(Debug, Default, Clone)]
pub struct ParentPinStamp {
    /// prev_txid → create_fk_id (plan=None edges; empty after `take_from_plan`).
    pub resolved: HashMap<[u8; 32], u64, std::hash::BuildHasherDefault<rbitcoin_query::TxidHasher>>,
    /// create_fk_id → identity (txid + optional body/spent/pin).
    pub idents: rbitcoin_query::U64Map<rbitcoin_query::ParentIdent>,
    /// create_fk_id → spent need-vouts (packed at lookup; load pin reuses).
    pub parent_vouts: U64Map<Vec<u32>>,
}

impl ParentPinStamp {
    /// Move plan stamp identity into the load stamp (no 100k-entry clone).
    ///
    /// `resolved` stays empty: plan path pins from packed `create_fk`.
    pub(crate) fn take_from_plan(plan: &mut rbitcoin_query::ArchiveWritePlan) -> Self {
        Self {
            resolved: HashMap::with_hasher(Default::default()),
            idents: std::mem::take(&mut plan.external_parents),
            parent_vouts: std::mem::take(&mut plan.external_parent_vouts),
        }
    }

    #[inline]
    pub(super) fn create_txid(&self, create_fk_id: u64) -> Option<[u8; 32]> {
        self.idents
            .get(&create_fk_id)
            .map(|p| p.txid)
            .filter(|t| *t != [0u8; 32])
    }

    #[inline]
    pub(super) fn body_range(&self, create_fk_id: u64) -> Option<(u64, u64)> {
        self.idents.get(&create_fk_id).and_then(|p| p.body)
    }

    #[inline]
    pub(super) fn spent_range(&self, create_fk_id: u64) -> Option<(u64, u64)> {
        self.idents.get(&create_fk_id).and_then(|p| p.spent)
    }

    #[inline]
    pub(super) fn create_pin(&self, create_fk_id: u64) -> Option<&rbitcoin_query::CreatePin> {
        self.idents.get(&create_fk_id).and_then(|p| p.pin.as_ref())
    }
}

pub(super) type WireBlockIn = (
    Height,
    Arc<Block>,
    Option<Arc<[rbitcoin_query::TxPrecompute]>>,
);
type LookupPhaseOut = (
    Option<rbitcoin_query::ArchiveWritePlan>,
    Vec<BodyMeta>,
    Vec<Arc<Block>>,
    u64,
);

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
/// Parent create_fk: in-flight → skeleton → leftover TipOnly (plan=None).
/// Wire blocks are `Arc` so IBD resolve can decode once and hand off without
/// cloning full `Block` payloads into stamp. `pres` is lookup `TxPrecompute`
/// when the caller already hashed (loadq); `None` hashes here.
pub fn confirm_wire_lookup_stamp(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<PlanStampOutcome, ConsensusError> {
    let t0 = Instant::now();
    query.on_load_pack().map_err(ConsensusError::from)?;
    let (mut plan, metas, wire_blocks, plan_ns) =
        wire_lookup_phase(query, params, milestone, blocks, pipeline)?;
    let ifo = pipeline.map(|p| p.in_flight);
    let parent_pin = match plan.as_mut() {
        Some(p) => ParentPinStamp::take_from_plan(p),
        None => stamp_parent_pin_archived(
            query,
            params,
            &metas,
            &wire_blocks,
            ifo,
            pipeline.and_then(|p| p.skeleton.as_ref()),
        )?,
    };
    rbitcoin_query::note_confirm(&query.confirm_stats().lookup_blocks, blocks.len() as u64);
    rbitcoin_query::note_confirm(&query.confirm_stats().lookup_head_ns, plan_ns);
    let work_ns = t0.elapsed().as_nanos() as u64;
    rbitcoin_query::note_confirm(&query.confirm_stats().lookup_total_ns, work_ns);
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
    in_flight: Option<&rbitcoin_query::InFlight>,
    skeleton: Option<&rbitcoin_query::BatchParentIds>,
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
    let empty = rbitcoin_query::InFlight::new();
    let ifo = in_flight.unwrap_or(&empty);
    let need_vec: Vec<[u8; 32]> = need_external.into_keys().collect();
    let ext = rbitcoin_query::stamp_external_parents(
        query.store(),
        &need_vec,
        ifo,
        skeleton,
        query.confirm_stats(),
    )
    .map_err(ConsensusError::from)?;
    let mut stamp = ParentPinStamp {
        resolved: HashMap::with_capacity_and_hasher(
            ext.resolved.len().saturating_add(same_batch.len()),
            Default::default(),
        ),
        idents: ext.idents,
        parent_vouts: U64Map::default(),
    };
    for (tid, fk) in ext.resolved {
        if let Some(id) = fk.get() {
            stamp.resolved.insert(tid, id);
        }
    }
    for (tid, id) in same_batch {
        stamp.resolved.insert(tid, id);
        stamp
            .idents
            .entry(id)
            .or_insert_with(|| rbitcoin_query::ParentIdent::new(tid))
            .txid = tid;
    }
    // Identities are stamped from wire prev_txid at insert time — never soft-fill
    // from txid.body here (that would be a dual path after lookup promised identity).
    if skeleton.is_none() {
        rbitcoin_query::fill_missing_parent_ranges(
            query.store(),
            ifo,
            &mut stamp.idents,
            query.confirm_stats(),
        )
        .map_err(ConsensusError::from)?;
    }
    for ident in stamp.idents.values() {
        if ident.txid == [0u8; 32] {
            return Err(ConsensusError::Store(StoreError::Corrupt(
                "invariant: plan=None parent stamp zero create identity",
            )));
        }
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
        mut parent_pin,
        metas,
        wire_blocks,
        ..
    } = stamped;

    let ifo = pipeline.map(|p| p.in_flight);
    let (batch_parents, spend_edges) = pin_for_wire_batch(
        query,
        plan.as_ref(),
        &mut parent_pin,
        &metas,
        &wire_blocks,
        ifo,
    )?;
    if let Some(ref mut p) = plan {
        p.freeze_after_pin();
    }

    rbitcoin_query::note_confirm(
        &query.confirm_stats().load_ns,
        t_load.elapsed().as_nanos() as u64,
    );

    let prepared = assemble_run(
        query,
        params,
        milestone,
        metas,
        &wire_blocks,
        &batch_parents,
        &spend_edges,
    )?;
    drop(spend_edges);

    let work_ns = t_work.elapsed().as_nanos() as u64;
    Ok(ConfirmLoadOutcome {
        batch: LoadedBatch {
            prepared,
            wire_blocks,
            batch_parents,
            script_preverified: preverified.clone(),
            archive_plan: plan,
            stats: query.confirm_stats_arc(),
        },
        work_ns,
    })
}

/// Structure + prepare + plan_batch only (stamp create_fk). Shared by lookup stage.
pub(super) fn wire_lookup_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    pipeline: Option<&WireLoadPipeline>,
) -> Result<LookupPhaseOut, ConsensusError> {
    if blocks.is_empty() {
        return Err(ConsensusError::BadBlock("empty confirm batch"));
    }
    for w in blocks.windows(2) {
        if w[1].0 .0 != w[0].0 .0.saturating_add(1) {
            return Err(ConsensusError::BadBlock("confirm run not contiguous"));
        }
    }

    let mut wire_blocks: Vec<Arc<Block>> = Vec::with_capacity(blocks.len());
    let mut metas: Vec<BodyMeta> = Vec::with_capacity(blocks.len());

    let tip_h = query.tip_height().map(|h| h.0);
    let store_path_lo = match tip_h {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let path_lo = pipeline.map(|p| p.path_lo).unwrap_or(store_path_lo);

    let mut struct_ns = 0u64;
    let mut header_ns = 0u64;
    let mut prepare_ns = 0u64;

    for (i, (height, block, caller_pres)) in blocks.iter().enumerate() {
        let block = Arc::clone(block);
        let hash = block.block_hash().to_byte_array();
        let ctx = ValidationContext::at(params, *height, milestone);
        let t_struct = Instant::now();
        let pres = crate::block::validate_block_structure_with_pres(
            block.as_ref(),
            &ctx,
            caller_pres.as_ref().map(Arc::clone),
            Some(query.confirm_stats()),
        )?;
        let txids: Vec<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
        struct_ns = struct_ns.saturating_add(t_struct.elapsed().as_nanos() as u64);
        let t_header = Instant::now();
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
        header_ns = header_ns.saturating_add(t_header.elapsed().as_nanos() as u64);

        let t_prep = Instant::now();
        let prev_fk = if i == 0 {
            if block.header.prev_blockhash.to_byte_array() == [0u8; 32] {
                rbitcoin_primitives::Fk::NULL
            } else {
                query
                    .get_header_by_hash(block.header.prev_blockhash.as_byte_array())
                    .map_err(ConsensusError::from)?
                    .map(|(fk, _)| fk)
                    .ok_or(ConsensusError::BadPrev)?
            }
        } else {
            metas[i - 1].header_fk
        };
        let header_rec = crate::header_to_record(prev_fk, &block.header);
        prepare_ns = prepare_ns.saturating_add(t_prep.elapsed().as_nanos() as u64);
        let t_put = Instant::now();
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

    let t_filter = Instant::now();
    let header_fks: Vec<rbitcoin_primitives::Fk> = metas.iter().map(|m| m.header_fk).collect();
    let need_fks = query
        .archive_filter_need_header_fks(&header_fks)
        .map_err(ConsensusError::from)?;
    confirm_archive_kind(header_fks.len(), need_fks.len())?;
    let filter_ns = t_filter.elapsed().as_nanos() as u64;
    let t_batch = Instant::now();
    let plan = if need_fks.is_empty() {
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
        let mut need = Vec::with_capacity(need_fks.len());
        for fk in &need_fks {
            let i = metas
                .iter()
                .position(|m| m.header_fk == *fk)
                .ok_or(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: need-body header_fk not in batch",
                )))?;
            need.push((*fk, wire_blocks[i].as_ref(), metas[i].txids.as_slice()));
        }
        let plan = match pipeline {
            Some(p) => query
                .archive_plan_batch_from_wire(
                    &need,
                    p.next_tx_start.max(1),
                    p.in_flight,
                    p.skeleton.as_ref(),
                )
                .map_err(ConsensusError::from)?,
            None => query
                .archive_plan_batch_from_wire(
                    &need,
                    query.tx_body_count().saturating_add(1).max(1),
                    &rbitcoin_query::InFlight::new(),
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
    query
        .confirm_stats()
        .note_stamp(struct_ns, prepare_ns, filter_ns, batch_ns);
    if struct_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_struct_ns, struct_ns);
    }
    if header_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_header_ns, header_ns);
    }
    if prepare_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_prepare_ns, prepare_ns);
    }
    if plan_ns > 0 {
        rbitcoin_query::note_confirm(&query.confirm_stats().phase_prep_filter_plan_ns, plan_ns);
    }
    Ok((plan, metas, wire_blocks, plan_ns))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConfirmArchiveKind {
    AllNeedBody,
    AllHaveBody,
}

pub(super) fn confirm_archive_kind(
    n_headers: usize,
    n_need: usize,
) -> Result<ConfirmArchiveKind, ConsensusError> {
    if n_need == 0 {
        Ok(ConfirmArchiveKind::AllHaveBody)
    } else if n_need == n_headers {
        Ok(ConfirmArchiveKind::AllNeedBody)
    } else {
        Err(ConsensusError::Store(StoreError::Corrupt(
            "invariant: confirm batch mixed archived",
        )))
    }
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
    fn tmp_query() -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled("stamp-archived")
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

    /// plan=None rehydrate and the query helper stamp the same skeleton parent.
    #[test]
    fn archived_stamp_matches_shared_helper_on_skeleton() {
        use rbitcoin_query::BatchParentIds;
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x81;
            t
        };
        let mut m = IdMap::default();
        m.insert(parent_txid, (rbitcoin_primitives::Fk(88), (4000, 32)));
        let skel = BatchParentIds {
            ids: std::sync::Arc::new(m),
            spent: std::sync::Arc::new(rbitcoin_query::U64Map::default()),
            need_vouts: rbitcoin_query::U64Map::default(),
        };

        let helper = rbitcoin_query::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &rbitcoin_query::InFlight::new(),
            Some(&skel),
            q.confirm_stats(),
        )
        .expect("shared helper");

        let meta = BodyMeta {
            height: Height(params.btc.bip34_height),
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
            Some(&skel),
        )
        .expect("archived stamp");
        assert_eq!(
            stamp.body_range(88),
            helper.idents.get(&88).and_then(|p| p.body)
        );
        assert_eq!(
            stamp.create_txid(88),
            helper.idents.get(&88).map(|p| p.txid)
        );
        assert_eq!(stamp.resolved.get(&parent_txid), Some(&88));
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Loadq already hashed; stamp must succeed with the caller pres on the meta.
    #[test]
    fn stamp_uses_caller_pres() {
        use crate::accept_and_connect_block;
        use crate::regtest_pad::mine_empty_regtest;
        use rbitcoin_query::TxPrecompute;

        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        let pres: Arc<[TxPrecompute]> = b1
            .txdata
            .iter()
            .map(TxPrecompute::from_tx)
            .collect::<Vec<_>>()
            .into();
        let items = [(Height(1), Arc::new(b1), Some(Arc::clone(&pres)))];
        let stamped = confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
            .expect("coinbase-only stamp");
        assert_eq!(stamped.metas[0].pres.len(), pres.len());
        assert_eq!(stamped.metas[0].pres[0].txid, pres[0].txid);
        let plan = stamped.plan.as_ref().expect("new body plans");
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "wire planner packed ins stay empty"
        );
        let want = items[0].1.txdata[0].output[0].script_pubkey.to_bytes();
        assert_eq!(
            plan.batch_pin[0].1[0].script, want,
            "CreatePin outs from wire script_pubkey"
        );
        let _ = std::fs::remove_dir_all(&path);
    }
}
