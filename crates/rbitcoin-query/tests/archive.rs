use rbitcoin_primitives::Fk;
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::{Query, TxApply, WirePlanNeed};
use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
use std::sync::Arc;

fn temp_query(label: &str) -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled(label)
}

fn first_edge_create(plan: &rbitcoin_query::ArchiveWritePlan) -> Fk {
    let id = plan.planned_fks[0].get().expect("spend fk");
    plan.edges.get(&id).expect("spend edges")[0].create_fk
}

/// Planner stamp, then commit. Commit itself does not fill empty fee rows.
fn commit_stamped(
    q: &Query,
    mut plan: rbitcoin_query::ArchiveWritePlan,
) -> Result<bool, rbitcoin_query::QueryError> {
    rbitcoin_query::archive::stamp_wire_plan_txstat(q, &mut plan)?;
    q.archive_commit_plan(plan)
}

fn commit_stamped_defer(
    q: &Query,
    mut plan: rbitcoin_query::ArchiveWritePlan,
) -> Result<(bool, Vec<rbitcoin_store::CreateLocPair>), rbitcoin_query::QueryError> {
    rbitcoin_query::archive::stamp_wire_plan_txstat(q, &mut plan)?;
    q.archive_commit_plan_defer_head(plan)
}

#[test]
fn txstat_stamp_uses_plan_base_total() {
    let (path, _q) = temp_query("txstat-plan-sizes");
    let tx = TxRecord {
        txid: [0x61; 32],
        version: 1,
        locktime: 0,
        input_count: 0,
        output_count: 0,
    };
    let mut plan = rbitcoin_query::archive::ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(tx, Vec::new()),
        Vec::new(),
    )];
    plan.tx_fees = vec![1];
    plan.tx_sizes = vec![(80, 100)];
    let rows = rbitcoin_query::archive::stamp_txstat_rows(&plan).expect("sizes without wire");
    assert_eq!(rows[0].fee_sat, 1);
    assert_eq!(rows[0].base, 80);
    assert_eq!(rows[0].wit_extra, 20);
    let _ = path;
}

/// A wire plan from the planner has empty fee rows. Commit must not
/// fill them from prevouts.
#[test]
fn commit_refuses_unstamped_wire_plan() {
    let (dir, q) = temp_query("txstat-unstamped");
    let need = vec![(Fk(1), vec![coinbase_apply(1)])];
    let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None).unwrap();
    assert!(plan.tx_fees.is_empty() && plan.tx_sizes.is_empty());
    let err = q.archive_commit_plan(plan).unwrap_err();
    assert!(
        err.to_string().contains("invariant: txstat fee length"),
        "{err}"
    );
    assert_eq!(q.tx_body_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

fn size_plan(tag: u8, with_size: bool) -> rbitcoin_query::archive::ArchiveWritePlan {
    let mut plan = rbitcoin_query::archive::ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            TxRecord {
                txid: [tag; 32],
                version: 1,
                locktime: 0,
                input_count: 0,
                output_count: 0,
            },
            Vec::new(),
        ),
        Vec::new(),
    )];
    if with_size {
        plan.tx_sizes = vec![(u32::from(tag), u32::from(tag) + 10)];
    }
    plan
}

#[test]
fn append_tx_sizes_only_when_both_sides_match_packed() {
    let mut both = size_plan(1, true);
    both.append(size_plan(2, true));
    assert_eq!(both.tx_sizes, vec![(1, 11), (2, 12)]);

    let mut left_only = size_plan(1, true);
    left_only.append(size_plan(2, false));
    assert_ne!(left_only.tx_sizes.len(), left_only.packed.len());

    let mut right_only = size_plan(1, false);
    right_only.append(size_plan(2, true));
    assert_ne!(right_only.tx_sizes.len(), right_only.packed.len());
}

fn coinbase_apply(i: u64) -> TxApply {
    let mut txid = [0u8; 32];
    txid[0..8].copy_from_slice(&i.to_le_bytes());
    txid[8] = 0xcb;
    TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![i as u8],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50 * 100_000_000, vec![0x51])],
    }
}

fn plan_applies(
    q: &Query,
    need: &[(Fk, Vec<TxApply>)],
    next: u64,
    in_flight: &rbitcoin_query::InFlight,
    skeleton: Option<&rbitcoin_query::BatchParentIds>,
) -> Result<rbitcoin_query::ArchiveWritePlan, rbitcoin_query::QueryError> {
    let wires: Vec<_> = need
        .iter()
        .filter(|(_, txs)| !txs.is_empty())
        .map(|(fk, txs)| {
            let (b, ids) = rbitcoin_query::testutil::block_from_applies(txs);
            (*fk, Arc::new(b), ids)
        })
        .collect();
    let refs: Vec<WirePlanNeed<'_>> = wires
        .iter()
        .map(|(fk, b, ids)| (*fk, b, ids.as_slice()))
        .collect();
    let carried: Vec<[u8; 32]> = need
        .iter()
        .flat_map(|(_, txs)| {
            txs.iter().flat_map(|ta| {
                ta.inputs.iter().filter_map(|inp| {
                    (inp.prev_index() != u32::MAX && inp.prev_txid != [0u8; 32])
                        .then_some(inp.prev_txid)
                })
            })
        })
        .collect();
    let plan = q.archive_plan_batch_from_wire(
        &refs,
        next,
        in_flight,
        skeleton,
        skeleton.is_some().then_some(carried.as_slice()),
    )?;
    Ok(plan)
}

#[test]
fn commit_class_a_only_writes_packed_ins_from_wire() {
    use rbitcoin_store::HeaderRecord;

    let (dir, q) = temp_query("class-a-packed-ins");
    let header = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [3u8; 32],
        size: 0,
        weight: 0,
    };
    let ta = coinbase_apply(1);
    let sig = ta.inputs[0].script_sig.clone();
    let hfk = q.commit_class_a_only(&header, &[ta]).unwrap();
    assert!(q.store().header_txs.has_body(hfk).unwrap());
    let (_tx, ins, _outs) = q.store().get_tx_full(Fk(1)).unwrap();
    assert_eq!(ins.len(), 1, "plan fill must persist packed ins");
    assert_eq!(ins[0].script_sig, sig);
    let _ = std::fs::remove_dir_all(&dir);
}

/// batch_pin Arc denserels match encode+decode layout (PR-A/B pin handoff).
#[test]
fn plan_batch_pin_arc_denserels_match_layout() {
    use std::sync::Arc;
    let (dir, q) = temp_query("batch-pin-arc");
    let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
    let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None).unwrap();
    assert_eq!(plan.batch_pin.len(), plan.planned_fks.len());
    assert_eq!(plan.batch_pin.len(), plan.packed.len());
    let mut ifo: rbitcoin_query::U64Map<rbitcoin_query::archive::CreatePin> =
        rbitcoin_query::U64Map::default();
    for (fk, pin) in plan.planned_fks.iter().zip(plan.batch_pin.iter()) {
        if let Some(id) = fk.get() {
            ifo.insert(id, Arc::clone(pin));
        }
    }
    for ((pin, _ins), _) in plan.packed.iter().zip(plan.batch_pin.iter()) {
        let mut raw = Vec::new();
        rbitcoin_store::PackedCreate::encode_txout_body(pin.as_ref(), &mut raw, None);
        let (meta, dec_outs, _) =
            rbitcoin_store::decode_packed_tx_outs_with_spender_rels(&raw, 1).unwrap();
        assert_eq!(meta.output_count as usize, dec_outs.len());
        assert_eq!(pin.n_out(), dec_outs.len());
    }
    assert_eq!(ifo.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn archive_phase_stats_cover_plan_and_commit_wall() {
    // Exclusive lock so a parallel sample_and_reset cannot steal this
    // window (llvm-cov / cargo test --workspace).
    {
        let (dir, q) = temp_query("arch-phases");
        let _ = q.confirm_stats().take_window();
        let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
        let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None).unwrap();
        assert_eq!(plan.planned_fks.len(), 2);
        commit_stamped(&q, plan).unwrap();
        let s = q.confirm_stats().take_window();
        assert!(
            s.arch_blocks >= 1 || s.arch_prep_assign_ns > 0 || s.arch_prep_stamp_ns > 0,
            "plan noted"
        );
        assert!(
            s.arch_write_blocks >= 1 || s.arch_write_total_ns > 0,
            "commit total"
        );
        assert!(
            s.arch_write_blocks >= 1 || s.arch_write_body_ns > 0,
            "body put timed"
        );
        let wsum = s.write_phases_sum_ns();
        assert!(
            wsum <= s.arch_write_total_ns.saturating_add(200_000),
            "write sum {} ≫ total {}",
            wsum,
            s.arch_write_total_ns
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn plan_from_reserves_fks_for_overlap_then_commit_in_order() {
    let (dir, q) = temp_query("plan-from");
    // Seed one body so count starts at 1.
    let seed = vec![(Fk(1), vec![coinbase_apply(1)])];
    // Need a real header_fk path: plan only needs Vec<(Fk, Vec<TxApply>)>.
    let need0 = seed;
    let p0 = plan_applies(
        &q,
        &need0,
        q.tx_body_count() + 1,
        &rbitcoin_query::InFlight::new(),
        None,
    )
    .unwrap();
    commit_stamped(&q, p0).unwrap();
    assert_eq!(q.tx_body_count(), 1);

    // Reserve two plans as prep would with write queue depth 2.
    let empty = rbitcoin_query::InFlight::new();
    let mut next = q.tx_body_count() + 1;
    let need_a = vec![(Fk(10), vec![coinbase_apply(10), coinbase_apply(11)])];
    let plan_a = plan_applies(&q, &need_a, next, &empty, None).unwrap();
    assert_eq!(plan_a.planned_fks, vec![Fk(2), Fk(3)]);
    next = plan_a.planned_fks.last().unwrap().0 + 1;
    assert_eq!(next, 4);

    let need_b = vec![(Fk(20), vec![coinbase_apply(20)])];
    let plan_b = plan_applies(&q, &need_b, next, &empty, None).unwrap();
    assert_eq!(plan_b.planned_fks, vec![Fk(4)]);
    assert_eq!(q.tx_body_count(), 1);

    commit_stamped(&q, plan_a).unwrap();
    assert_eq!(q.tx_body_count(), 3);
    commit_stamped(&q, plan_b).unwrap();
    assert_eq!(q.tx_body_count(), 4);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Overlapping plan must resolve parents from a prior uncommitted plan batch.
/// Without `in_flight`, this is the "parent create_fk unresolved" corruption.
#[test]
fn overlap_plan_resolves_parent_via_inflight_creates() {
    let (dir, q) = temp_query("inflight-parent");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let empty = rbitcoin_query::InFlight::new();
    let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
    assert_eq!(plan_a.planned_fks, vec![Fk(1)]);
    let parent_txid = plan_a.batch_creates[0].0;
    let parent_fk = plan_a.batch_creates[0].1;

    // Child spends parent — not in head until plan_a commits.
    let mut child_txid = [0u8; 32];
    child_txid[0] = 0xee;
    let child = TxApply {
        tx: TxRecord {
            txid: child_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    let need_b = vec![(Fk(2), vec![child])];

    let err = plan_applies(&q, &need_b, 2, &empty, None).unwrap_err();
    assert!(
        err.to_string().contains("create_fk unresolved"),
        "expected unresolved without inflight, got {err}"
    );

    let child = TxApply {
        tx: TxRecord {
            txid: child_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    let need_b = vec![(Fk(2), vec![child])];
    let mut inflight = rbitcoin_query::InFlight::new();
    inflight.note_pins(
        plan_a
            .planned_fks
            .iter()
            .zip(plan_a.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    let plan_b = plan_applies(&q, &need_b, 2, &inflight, None).expect("inflight parent resolve");
    assert_eq!(plan_b.planned_fks, vec![Fk(2)]);
    assert_eq!(
        first_edge_create(&plan_b),
        parent_fk,
        "child input must stamp prior planned create_fk"
    );

    commit_stamped(&q, plan_a).unwrap();
    commit_stamped(&q, plan_b).unwrap();
    assert_eq!(q.tx_body_count(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

fn child_spend(prev_txid: [u8; 32], marker: u8) -> TxApply {
    let mut child_txid = [0u8; 32];
    child_txid[0] = marker;
    TxApply {
        tx: TxRecord {
            txid: child_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    }
}

/// n−1: in-flight still has the parent at child bind (prune is after pin).
#[test]
fn inflight_binds_parent_after_commit_before_prune() {
    let (dir, q) = temp_query("inflight-n-minus-1");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let empty = rbitcoin_query::InFlight::new();
    let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
    let parent_txid = plan_a.batch_creates[0].0;
    let parent_fk = plan_a.batch_creates[0].1;
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins(
        plan_a
            .planned_fks
            .iter()
            .zip(plan_a.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    commit_stamped(&q, plan_a).unwrap();
    assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);

    let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xef)])];
    let plan_b = plan_applies(&q, &need_b, 2, &log, None)
        .expect("in-flight must stamp n−1 without leftover");
    assert_eq!(first_edge_create(&plan_b), parent_fk);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn leftover_keeps_prev_pack_after_drain_done() {
    let (dir, q) = temp_query("leftover-keep-prev");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let empty = rbitcoin_query::InFlight::new();
    let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
    let parent_txid = plan_a.batch_creates[0].0;
    let parent_fk = plan_a.batch_creates[0].1;
    let header_fk = plan_a.per_header_ranges[0].0;
    commit_stamped(&q, plan_a).unwrap();
    q.store()
        .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
        .unwrap();
    q.on_load_pack().unwrap();
    let mut child_txid = [0u8; 32];
    child_txid[0] = 0xea;
    let child = TxApply {
        tx: TxRecord {
            txid: child_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    let need_b = vec![(Fk(2), vec![child])];
    let plan_b = plan_applies(&q, &need_b, 2, &empty, None)
        .expect("height-1 child must bind prev pack after drain HWM");
    assert_eq!(first_edge_create(&plan_b), parent_fk);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_gcs_header_plans_from_store_tip() {
    let (dir, q) = temp_query("tip-gc");
    let rec = rbitcoin_store::HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [9u8; 32],
        size: 0,
        weight: 0,
    };
    q.confirm_parent_cache()
        .put_header_plan(1, Fk(2), rec, vec![Fk(2)], [0u8; 32]);
    assert!(q.confirm_parent_cache().get_header_plan(1).is_some());
    q.on_load_pack().unwrap();
    assert!(
        q.confirm_parent_cache().get_header_plan(1).is_some(),
        "store tip below the plan — do not GC height 1"
    );
    q.store()
        .confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(0),
            Fk(1),
        )
        .unwrap();
    q.store()
        .confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(1),
            Fk(2),
        )
        .unwrap();
    q.on_load_pack().unwrap();
    assert!(
        q.confirm_parent_cache().get_header_plan(1).is_none(),
        "load pack must GC header plans <= store tip"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Drain done, fence not yet: TipOnly would miss. In-flight still binds.
#[test]
fn inflight_binds_after_drain_before_fence() {
    let (dir, q) = temp_query("inflight-drain-before-fence");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let empty = rbitcoin_query::InFlight::new();
    let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
    let parent_txid = plan_a.batch_creates[0].0;
    let parent_fk = plan_a.batch_creates[0].1;
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins(
        plan_a
            .planned_fks
            .iter()
            .zip(plan_a.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    commit_stamped(&q, plan_a).unwrap();
    assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);
    log.prune_below_height(q.drain_and_fence_hi());
    assert_eq!(
        q.drain_and_fence_hi(),
        None,
        "drain fk not on fence: keep inflight"
    );
    assert!(
        log.get_create_fk(&parent_txid).is_some(),
        "fence missing: prune must keep"
    );
    let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xee)])];
    let plan_b = plan_applies(&q, &need_b, 2, &log, None)
        .expect("in-flight binds after drain, before fence");
    assert_eq!(first_edge_create(&plan_b), parent_fk);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Leftover miss (unknown parent) hop-dumps once. Lookup TipOnly does not.
#[test]
fn leftover_miss_dumps_probe_diag() {
    let (dir, q) = temp_query("leftover-miss-diag");
    let empty = rbitcoin_query::InFlight::new();
    let ghost = [0xDDu8; 32];
    let need = vec![(Fk(1), vec![child_spend(ghost, 0xaa)])];
    let _ = plan_applies(&q, &need, 1, &empty, None);
    assert!(
        rbitcoin_store::leftover_probe_diag_recorded(&ghost),
        "leftover miss must hop-dump this parent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fence before drain (67438): prune keeps the layer; bind uses in-flight.
#[test]
fn inflight_binds_after_fence_before_drain() {
    let (dir, q) = temp_query("inflight-fence-before-drain");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let empty = rbitcoin_query::InFlight::new();
    let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
    let parent_txid = plan_a.batch_creates[0].0;
    let parent_fk = plan_a.batch_creates[0].1;
    let header_fk = plan_a.per_header_ranges[0].0;
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins(
        plan_a
            .planned_fks
            .iter()
            .zip(plan_a.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    commit_stamped_defer(&q, plan_a).unwrap();
    assert!(
        q.store().txs.pending_head_len() >= 1,
        "create must still be queued — drain has not inserted tx.head"
    );
    q.store()
        .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
        .unwrap();
    log.prune_below_height(q.drain_and_fence_hi());
    assert_eq!(q.drain_and_fence_hi(), None, "drain_fk 0: HWM is None");
    assert!(
        log.get_create_fk(&parent_txid).is_some(),
        "drain_fk 0: prune must keep"
    );
    let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xec)])];
    let plan_b = plan_applies(&q, &need_b, 2, &log, None)
        .expect("in-flight binds after fence, before drain");
    assert_eq!(first_edge_create(&plan_b), parent_fk);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same-header spend is not a pin parent; later header in the pack is.
#[test]
fn plan_batch_same_header_vouts_skipped_cross_height_pinned() {
    let (dir, q) = temp_query("plan-same-header-vouts");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    let child = child_spend(parent_txid, 0xcd);
    let same = vec![(Fk(1), vec![parent.clone(), child.clone()])];
    let plan_same =
        plan_applies(&q, &same, 1, &rbitcoin_query::InFlight::new(), None).expect("same header");
    assert_eq!(plan_same.planned_fks, vec![Fk(1), Fk(2)]);
    assert!(
        !plan_same.external_parent_vouts.contains_key(&1),
        "same-header create must not be in parent_vouts"
    );

    let cross = vec![
        (Fk(10), vec![parent]),
        (Fk(11), vec![child_spend(parent_txid, 0xce)]),
    ];
    let plan_cross =
        plan_applies(&q, &cross, 1, &rbitcoin_query::InFlight::new(), None).expect("cross height");
    assert_eq!(
        plan_cross
            .external_parent_vouts
            .get(&1)
            .map(|v| v.as_slice()),
        Some(&[0u32][..]),
        "later header in the pack must pin the earlier create"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// S0 plan: stamp_external already idx-filled; do not fill_missing twice.
#[test]
fn plan_batch_one_fill_missing_when_parents_already_stamped() {
    use std::sync::atomic::Ordering;
    {
        let (dir, q) = temp_query("plan-one-fill-missing");
        let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
        use rbitcoin_primitives::Height;
        use rbitcoin_store::HeaderRecord;
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let ph = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [1u8; 32],
            size: 0,
            weight: 0,
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
        let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
        let need = vec![(Fk(2), vec![child_spend(parent_txid, 0xcd)])];
        let plan = plan_applies(&q, &need, 2, &rbitcoin_query::InFlight::new(), None)
            .expect("parent via head");
        assert_eq!(first_edge_create(&plan), Fk(1));
        assert!(plan
            .external_parents
            .get(&1)
            .and_then(|p| p.body)
            .is_some_and(|r| r.1 > 0));
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.spent),
            Some(spent)
        );
        assert_eq!(
            q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed),
            0,
            "stamp_external already bound loc; finish must not fill_missing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Packed reconstruct already has create_fk: still idx-fill (not in need).
#[test]
fn plan_batch_prestamp_create_fk_still_idx_fills() {
    use rbitcoin_primitives::Height;
    use rbitcoin_store::HeaderRecord;
    let (dir, q) = temp_query("plan-prestamp-fk");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    let ph = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [1u8; 32],
        size: 0,
        weight: 0,
    };
    q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
    let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
    let mut child = child_spend(parent_txid, 0xcf);
    child.inputs[0].stamp_create_fk(Fk(1));
    let need = vec![(Fk(2), vec![child])];
    let plan = plan_applies(&q, &need, 2, &rbitcoin_query::InFlight::new(), None)
        .expect("prestamp parent");
    assert_eq!(first_edge_create(&plan), Fk(1));
    assert!(
        plan.external_parents
            .get(&1)
            .and_then(|p| p.body)
            .is_some_and(|r| r.1 > 0),
        "pre-stamped create_fk must still receive body_range"
    );
    assert_eq!(
        plan.external_parents.get(&1).and_then(|p| p.spent),
        Some(spent)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// IBD skeleton miss + InFlight pin + loc on disk: plan does not loc-by-fk.
/// Spent stays unset for write TLS / `CreatePin::set_loc` (mainnet 133433).
#[test]
fn plan_inflight_skeleton_miss_leaves_spent_unset_despite_disk_loc() {
    use std::sync::atomic::Ordering;
    let (dir, q) = temp_query("plan-inflight-skel-miss");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    let pin = rbitcoin_query::CreatePinInner::records(parent.tx.clone(), parent.outputs.clone());
    q.store
        .txs
        .put_full_batch_indexed(
            &[(parent.tx, parent.inputs, parent.outputs)],
            /*index=*/ true,
        )
        .unwrap();
    assert!(q.store.txs.spent_range(Fk(1)).expect("spent range").1 > 0);
    let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins([(Fk(1), &pin)], Some(1));
    let child = child_spend(parent_txid, 0xee);
    let need = vec![(Fk(2), vec![child])];
    let skel = rbitcoin_query::BatchParentIds::default();
    let plan = plan_applies(&q, &need, 2, &log, Some(&skel))
        .expect("inflight + empty skeleton with loc on disk");
    assert_eq!(first_edge_create(&plan), Fk(1));
    assert_eq!(
        plan.external_parents.get(&1).and_then(|p| p.spent),
        None,
        "IBD stamp must not loc-by-fk"
    );
    assert!(
        plan.external_parents
            .get(&1)
            .and_then(|p| p.pin.as_ref())
            .is_some(),
        "inflight pin is kept"
    );
    assert_eq!(
        q.confirm_stats().fill_missing_n.load(Ordering::Relaxed),
        0,
        "IBD skeleton path must not fill_missing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Creates-only in_flight (txid→fk, no denserels outs) must still get
/// body_range via idx so load denserels-by-range works (mainnet 961466 class).
#[test]
fn plan_inflight_creates_only_fills_parent_body_range() {
    let (dir, q) = temp_query("plan-inflight-range");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    q.store
        .txs
        .put_full_batch_indexed(
            &[(parent.tx, parent.inputs, parent.outputs)],
            /*index=*/ true,
        )
        .unwrap();
    // Creates-only: fk known, no CreatePin outs (archived mid-head race).
    let mut log = rbitcoin_query::InFlight::new();
    log.note_creates([(parent_txid, Fk(1))], None);
    let ifo = &log;
    assert!(ifo.get_out(1).is_none());

    let mut child_txid = [0u8; 32];
    child_txid[0] = 0xee;
    let child = TxApply {
        tx: TxRecord {
            txid: child_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1, vec![0x51])],
    };
    let need = vec![(Fk(2), vec![child])];
    let plan = plan_applies(&q, &need, 2, ifo, None).expect("parent via creates-only in_flight");
    assert_eq!(first_edge_create(&plan), Fk(1));
    assert!(
        plan.external_parents
            .get(&1)
            .and_then(|p| p.body)
            .is_some_and(|r| r.1 > 0),
        "creates-only in_flight must still stamp body_range for load denserels"
    );
    assert_eq!(plan.external_parent_txid(1), Some(parent_txid));
    assert_eq!(
        plan.external_parent_vouts.get(&1).map(|v| v.as_slice()),
        Some(&[0u32][..]),
        "lookup packing must publish parent need-vouts for load pin"
    );
    let spent = q
        .store
        .txs
        .spent_range(Fk(1))
        .expect("archived spent range");
    assert_eq!(
        plan.external_parents.get(&1).and_then(|p| p.spent),
        Some(spent),
        "creates-only in_flight must stamp spent range (write ensure skip)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// IBD skeleton miss + creates-only InFlight: load does not loc-by-fk even
/// when loc is on disk. Lookup leftover (skeleton = None) still fills.
#[test]
fn plan_inflight_creates_only_ibd_skeleton_miss_does_not_loc_fill() {
    use std::sync::atomic::Ordering;
    let (dir, q) = temp_query("plan-inflight-creates-skel-miss");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    q.store
        .txs
        .put_full_batch_indexed(
            &[(parent.tx, parent.inputs, parent.outputs)],
            /*index=*/ true,
        )
        .unwrap();
    let mut log = rbitcoin_query::InFlight::new();
    log.note_creates([(parent_txid, Fk(1))], None);
    assert!(log.get_out(1).is_none());
    let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
    let child = child_spend(parent_txid, 0xee);
    let need = vec![(Fk(2), vec![child])];
    let skel = rbitcoin_query::BatchParentIds::default();
    let plan = plan_applies(&q, &need, 2, &log, Some(&skel))
        .expect("creates-only identity with empty skeleton");
    assert_eq!(first_edge_create(&plan), Fk(1));
    assert_eq!(
        plan.external_parents.get(&1).and_then(|p| p.body),
        None,
        "IBD stamp must not loc-by-fk for creates-only"
    );
    assert_eq!(plan.external_parents.get(&1).and_then(|p| p.spent), None);
    assert_eq!(q.confirm_stats().fill_missing_n.load(Ordering::Relaxed), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TipOnly leftover parent: body range from head, spent range on the stamp.
#[test]
fn fill_missing_parent_ranges_stamps_spent_idx_for_archived() {
    use rbitcoin_primitives::Height;
    use rbitcoin_store::HeaderRecord;
    let (dir, q) = temp_query("stamp-spent-idx");
    let parent = coinbase_apply(1);
    let parent_txid = parent.tx.txid;
    let ph = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [1u8; 32],
        size: 0,
        weight: 0,
    };
    q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
    let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
    let helper = rbitcoin_query::stamp_external_parents(
        q.store(),
        &[parent_txid],
        &rbitcoin_query::InFlight::new(),
        None,
        q.confirm_stats(),
    )
    .expect("stamp archived parent");
    assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(1)));
    assert!(helper
        .idents
        .get(&1)
        .and_then(|p| p.body)
        .is_some_and(|r| r.1 > 0));
    assert_eq!(
        helper.idents.get(&1).and_then(|p| p.spent),
        Some(spent),
        "archived parent must carry spent range on the lookup stamp"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn archive_filter_need_header_fks_drops_archived() {
    use rbitcoin_store::HeaderRecord;
    let (dir, q) = temp_query("filter-header-fks");
    let header = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [2u8; 32],
        size: 0,
        weight: 0,
    };
    let hfk = q
        .commit_class_a_only(&header, &[coinbase_apply(1)])
        .unwrap();
    let need = q
        .archive_filter_need_header_fks(&[hfk, hfk, Fk(99)])
        .unwrap();
    assert_eq!(need, vec![Fk(99)], "archived + dup dropped; missing kept");
    let _ = std::fs::remove_dir_all(&dir);
}

fn wire_parent_child_big_script_sig() -> (bitcoin::Block, Vec<[u8; 32]>, Vec<u8>) {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    let parent = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0xaa]),
        }],
    };
    let parent_txid = parent.compute_txid();
    let script_sig = vec![0xab; 10_000];
    let wit_push = vec![0x21; 33];
    let child = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig.clone()),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[b"wit-item-1".as_slice(), wit_push.as_slice()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0xbb]),
        }],
    };
    let txids = vec![
        parent.compute_txid().to_byte_array(),
        child.compute_txid().to_byte_array(),
    ];
    let block = Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![parent, child],
    };
    (block, txids, script_sig)
}

#[test]
fn create_pin_loc_set_once_after_append() {
    use rbitcoin_store::CreateLocPair;
    let pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let first = CreateLocPair {
        txout: (8, 16),
        spent: (8, 8),
        n_out: 1,
    };
    pin.set_loc(first);
    pin.set_loc(CreateLocPair {
        txout: (99, 1),
        spent: (99, 1),
        n_out: 9,
    });
    assert_eq!(pin.loc().copied(), Some(first));
}

/// D1: wire planner never builds TxApply; packed ins from stamp edges; CreatePin matches wire outs.
#[test]
fn plan_batch_from_wire_skips_tx_apply() {
    use std::sync::Arc;
    let (dir, q) = temp_query("plan-from-wire");
    let (block, txids, script_sig) = wire_parent_child_big_script_sig();
    let parent_txid = txids[0];
    let block = Arc::new(block);
    let parent_spk = block.txdata[0].output[0].script_pubkey.as_bytes();
    let child_spk = block.txdata[1].output[0].script_pubkey.as_bytes();
    let parent_ptr = parent_spk.as_ptr();
    let child_ptr = child_spk.as_ptr();
    let parent_spk = parent_spk.to_vec();
    let child_spk = child_spk.to_vec();
    let plan = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            None,
            None,
        )
        .expect("wire plan");
    assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2)]);
    assert!(
        plan.packed.iter().all(|(_, ins)| ins.is_empty()),
        "wire plan must not retain scriptSig or witness"
    );
    assert_eq!(
        plan.batch_pin[0].with_out_parts(0, |_, script| script.as_ptr()),
        Some(parent_ptr),
        "plan must not copy scriptPubKey"
    );
    assert_eq!(
        plan.batch_pin[1].with_out_parts(0, |_, script| script.as_ptr()),
        Some(child_ptr),
        "plan must not copy scriptPubKey"
    );
    assert_eq!(plan.batch_pin.len(), 2);
    assert_eq!(
        plan.batch_pin[0].with_out_parts(0, |_, script| script.to_vec()),
        Some(parent_spk)
    );
    assert_eq!(
        plan.batch_pin[1].with_out_parts(0, |_, script| script.to_vec()),
        Some(child_spk)
    );
    let cb = plan.edges.get(&1).expect("coinbase edges");
    assert_eq!(cb.len(), 1);
    assert!(cb[0].create_fk.is_null());
    let edges = plan.edges.get(&2).expect("child edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].prev_txid, parent_txid);
    assert_eq!(edges[0].vout, 0);
    assert_eq!(edges[0].spend_fk, Fk(2));
    assert_eq!(edges[0].create_fk, Fk(1));
    assert!(
        plan.body_est >= 10_000,
        "body_est must count wire ins, got {}",
        plan.body_est
    );
    commit_stamped(&q, plan).expect("commit from wire");
    let (_tx, ins, _outs) = q.store().get_tx_full(Fk(2)).unwrap();
    assert_eq!(ins[0].script_sig, script_sig);
    assert_eq!(ins[0].witness, vec![b"wit-item-1".to_vec(), vec![0x21; 33]]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Class A commit drops the decoded block from a wire pin. Later spends still
/// read value and script. A reader that cloned the block before commit keeps it.
#[test]
fn wire_pin_drops_decoded_block_after_class_a_commit() {
    use std::sync::Arc;
    let (dir, q) = temp_query("pin-drop-block");
    let (block, txids, _) = wire_parent_child_big_script_sig();
    let block = Arc::new(block);
    let weak = Arc::downgrade(&block);
    let reader = Arc::clone(&block);
    let parent_val = reader.txdata[0].output[0].value.to_sat();
    let child_val = reader.txdata[1].output[0].value.to_sat();
    let parent_spk = reader.txdata[0].output[0].script_pubkey.as_bytes().to_vec();
    let child_spk = reader.txdata[1].output[0].script_pubkey.as_bytes().to_vec();
    let plan = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            None,
            None,
        )
        .expect("wire plan");
    let kept = plan.batch_pin.clone();
    commit_stamped(&q, plan).expect("commit");
    drop(block);
    assert_eq!(
        Arc::strong_count(&reader),
        1,
        "in-flight pin clones must drop the decoded block at commit"
    );
    assert!(kept[0].with_wire_tx(|_| ()).is_none());
    assert!(kept[1].with_wire_tx(|_| ()).is_none());
    assert_eq!(kept[0].retained_outs_addr(), kept[1].retained_outs_addr());
    assert!(kept[0].retained_outs_addr().is_some());
    let (v, script) = kept[0].out_parts(0).expect("parent out");
    assert_eq!(v, parent_val);
    assert_eq!(script, parent_spk.as_slice());
    let (v, script) = kept[1].out_parts(0).expect("child out");
    assert_eq!(v, child_val);
    assert_eq!(script, child_spk.as_slice());
    assert!(kept[0].loc().is_some());
    assert!(kept[1].loc().is_some());
    assert_eq!(
        reader.txdata[0].output[0].script_pubkey.as_bytes(),
        parent_spk.as_slice()
    );
    drop(kept);
    drop(reader);
    assert!(weak.upgrade().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Publish must finish while a reader is still using the decoded block.
/// The output copy and the encode callbacks must not hold the shared mutex.
#[test]
fn wire_release_finishes_while_a_reader_holds_the_block() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use rbitcoin_query::CreatePinInner;
    use std::sync::{Arc, Barrier};
    use std::thread;

    let tx = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0xaa]),
        }],
    };
    let txid = tx.compute_txid().to_byte_array();
    let block = Arc::new(Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![tx],
    });
    let pin = CreatePinInner::wire(
        Arc::clone(&block),
        0,
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
    );
    let entered = Arc::new(Barrier::new(2));
    let leave = Arc::new(Barrier::new(2));
    let reader_pin = Arc::clone(&pin);
    let entered_r = Arc::clone(&entered);
    let leave_r = Arc::clone(&leave);
    let reader = thread::spawn(move || {
        reader_pin.with_out_parts(0, |value, script| {
            assert_eq!(value, 50_0000_0000);
            assert_eq!(script, &[0x51, 0xaa]);
            entered_r.wait();
            leave_r.wait();
            true
        })
    });
    entered.wait();
    pin.release_wire_block();
    leave.wait();
    assert!(
        reader.join().expect("reader").expect("vout 0"),
        "release must return while the reader still holds the block"
    );
    let (value, script) = pin.out_parts(0).expect("blob");
    assert_eq!(value, 50_0000_0000);
    assert_eq!(script, &[0x51, 0xaa]);
    assert!(pin.with_wire_tx(|_| ()).is_none());
}

/// Edge rows and `n_out` use the counts stored on the pin. They must not
/// open the decoded block, including after commit has dropped it.
#[test]
fn wire_counts_come_from_the_tx_record() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use rbitcoin_query::archive::commit_input_edge_rows;
    use rbitcoin_query::{ArchiveWritePlan, CreatePinInner, SpendEdge};

    let tx = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = tx.compute_txid().to_byte_array();
    let block = Arc::new(Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![tx],
    });
    let pin = CreatePinInner::wire(
        block,
        0,
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
    );
    assert_eq!(pin.n_out(), 1);
    pin.release_wire_block();
    assert_eq!(pin.n_out(), 1);
    assert!(pin.contains_vout(0));
    assert!(!pin.contains_vout(1));
    let fk = Fk(7);
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(Arc::clone(&pin), Vec::new())];
    plan.planned_fks = vec![fk];
    plan.edges.insert(
        fk.get().expect("fk"),
        vec![SpendEdge {
            prev_txid: [0; 32],
            vout: u32::MAX,
            spend_fk: fk,
            create_fk: Fk::NULL,
            vin: 0,
        }],
    );
    let rows = commit_input_edge_rows(&plan).expect("edges from the stored input count");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 1);
    assert!(rows[0][0].parent.is_null());
}

/// Prune mode serves confirmed script bytes from the append cache.
/// A wire commit must fill that cache. Falling through to `get_tx_full`
/// re-reads every transaction during IBD.
#[test]
fn pruned_wire_commit_serves_seqsigwit_without_reread() {
    use rbitcoin_primitives::Height;
    use std::sync::Arc;
    let (dir, q) = temp_query("prune-wire-seqsigwit");
    q.set_prune_seqsigwit(true).unwrap();
    q.set_seqsigwit_ram_threshold_bytes(1 << 20).unwrap();
    let (block, txids, script_sig) = wire_parent_child_big_script_sig();
    let block = Arc::new(block);
    let plan = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            None,
            None,
        )
        .expect("wire plan");
    let fks = plan.planned_fks.clone();
    assert!(plan.packed.iter().all(|(_, ins)| ins.is_empty()));
    commit_stamped(&q, plan).expect("commit");

    q.note_seqsigwit_ram_for_confirmed(Height(1), &fks)
        .expect("ram window from append cache");

    let cached = q
        .seqsigwit_cached_inputs(Fk(2), 1)
        .expect("cache")
        .expect("child inputs");
    assert_eq!(cached[0].script_sig, script_sig);
    assert!(!cached[0].witness.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_refuses_empty_packed_ins() {
    use std::sync::Arc;
    let (dir, q) = temp_query("commit-empty-packed-ins");
    let (block, txids, _) = wire_parent_child_big_script_sig();
    let block = Arc::new(block);
    let plan = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            None,
            None,
        )
        .expect("wire plan");
    assert!(
        plan.packed.iter().all(|(_, ins)| ins.is_empty()),
        "wire plan leaves packed ins empty"
    );
    commit_stamped(&q, plan).expect("wire edges encode seqsigwit");
    let (_tx, ins, _outs) = q.store().get_tx_full(Fk(2)).unwrap();
    assert_eq!(ins[0].script_sig.len(), 10_000);

    let mut missing = q
        .archive_plan_batch_from_wire(
            &[(Fk(3), &block, txids.as_slice())],
            3,
            &rbitcoin_query::InFlight::new(),
            None,
            None,
        )
        .expect("second wire plan");
    missing.edges.clear();
    match q.archive_commit_plan(missing) {
        Err(e) => {
            let s = e.to_string();
            assert!(s.contains("invariant: wire plan edges missing"), "{s}");
        }
        Ok(_) => panic!("missing edges must be corrupt"),
    }

    let pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: [9u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let mut records = rbitcoin_query::ArchiveWritePlan::empty();
    records.packed.push((pin, Vec::new()));
    records.planned_fks.push(Fk(9));
    match q.archive_commit_plan(records) {
        Err(e) => {
            let s = e.to_string();
            assert!(s.contains("invariant: packed ins empty at write"), "{s}");
        }
        Ok(_) => panic!("records pin with empty ins must be corrupt"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mainnet 91842/91880 share a coinbase txid with 91812/91722. A 144-block
/// load wave includes both; batch_map must not treat that as in-block dup.
#[test]
fn plan_batch_from_wire_bip30_same_txid_across_headers() {
    let (dir, q) = temp_query("bip30-wave-txid");
    let txid = coinbase_apply(1).tx.txid;
    let child = child_spend(txid, 0x99);
    let child_txid = child.tx.txid;
    let need = vec![
        (Fk(1), vec![coinbase_apply(1)]),
        (Fk(2), vec![coinbase_apply(1)]),
        (Fk(3), vec![child]),
    ];
    let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None)
        .expect("BIP30 same-txid across headers in one wave");
    assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2), Fk(3)]);
    assert_eq!(plan.packed[0].0.tx().txid, txid);
    assert_eq!(plan.packed[1].0.tx().txid, txid);
    assert_eq!(
        plan.batch_creates,
        vec![(txid, Fk(1)), (txid, Fk(2)), (child_txid, Fk(3))]
    );
    let spend = plan.edges.get(&3).expect("child");
    assert_eq!(
        spend[0].create_fk,
        Fk(2),
        "same-wave spend binds newest BIP30 create"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A spend sitting between two copies of one txid must bind the copy that
/// already exists, not the copy this wave creates later.
#[test]
fn plan_batch_spend_between_repeated_txid_binds_the_earlier_copy() {
    let (dir, q) = temp_query("bip30-between");
    let txid = coinbase_apply(1).tx.txid;
    let child = child_spend(txid, 0x99);
    let need = vec![
        (Fk(1), vec![coinbase_apply(1)]),
        (Fk(2), vec![child]),
        (Fk(3), vec![coinbase_apply(1)]),
    ];
    let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None)
        .expect("spend between two copies of one txid");
    let spend = plan.edges.get(&2).expect("child");
    assert_eq!(
        spend[0].create_fk,
        Fk(1),
        "spend between two copies binds the earlier one, got {:?}",
        spend[0].create_fk
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn archive_plan_dup_is_in_block_only() {
    let (dir, q) = temp_query("archive-plan-dup");
    let normal = vec![(Fk(1), vec![coinbase_apply(1)])];
    let plan = plan_applies(&q, &normal, 1, &rbitcoin_query::InFlight::new(), None)
        .expect("one txid plans");
    assert_eq!(plan.planned_fks, vec![Fk(1)]);

    let intra = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(1)])];
    let err = plan_applies(&q, &intra, 1, &rbitcoin_query::InFlight::new(), None)
        .expect_err("in-block duplicate");
    assert!(
        err.to_string()
            .contains("duplicate txid in block body (consensus violation)"),
        "{err}"
    );

    let cross = vec![
        (Fk(1), vec![coinbase_apply(1)]),
        (Fk(2), vec![coinbase_apply(1)]),
    ];
    let plan = plan_applies(&q, &cross, 1, &rbitcoin_query::InFlight::new(), None)
        .expect("cross-block repeat");
    let txid = coinbase_apply(1).tx.txid;
    assert_eq!(plan.batch_creates, vec![(txid, Fk(1)), (txid, Fk(2))]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plan_batch_from_wire_duplicate_txid_in_one_block_is_corrupt() {
    let (dir, q) = temp_query("dup-txid-in-block");
    let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(1)])];
    let err = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None)
        .expect_err("in-block duplicate txid");
    assert!(
        err.to_string()
            .contains("duplicate txid in block body (consensus violation)"),
        "got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Packed plan commits the coinbase prevout the apply carried.
#[test]
fn plan_packed_commits_coinbase_prevout() {
    let (dir, q) = temp_query("shared-create-pin");
    let need = vec![(Fk(1), vec![coinbase_apply(1)])];
    let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None).unwrap();
    assert_eq!(plan.packed.len(), 1);
    assert_eq!(plan.batch_pin.len(), 1);
    let (value, script) = plan.batch_pin[0]
        .with_out_parts(0, |value, script| (value, script.to_vec()))
        .expect("vout 0");
    assert_eq!(value, 50 * 100_000_000);
    assert_eq!(script, &[0x51]);
    commit_stamped(&q, plan).unwrap();
    let (_tx, _ins, outs) = q.store().get_tx_full(Fk(1)).unwrap();
    assert_eq!(outs[0].value, 50 * 100_000_000);
    assert_eq!(outs[0].script, vec![0x51]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// BQ-ahead facts live on the published layer. A leftover hits map is not
/// a stamp source (shipped IBD already passes `None`).
#[test]
fn plan_batch_from_wire_bq_hits_map_is_not_stamp_source() {
    let (dir, q) = temp_query("bq-hits-not-stamp");
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x33;
        t
    };
    let child = child_spend(parent_txid, 0x44);
    let need = vec![(Fk(1), vec![child])];
    {
        let _ = q.confirm_stats().take_window();
        let err = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), None)
            .expect_err("bq parent_hits map is not a stamp source");
        assert!(
            err.to_string().contains("parent create_fk unresolved"),
            "got: {err}"
        );
        let mix = q.confirm_stats().take_window();
        assert_eq!(mix.pin_txid_n, 0);
        assert!(mix.head_need > 0, "bq-map-only parent must leftover");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Published union supplies create_fk + range with no pin, BQ hits, or head row.
#[test]
fn plan_batch_from_wire_hits_skeleton() {
    use rbitcoin_query::{BatchParentIds, IdMap};
    use std::sync::Arc;
    let (dir, q) = temp_query("skeleton-ids-stamp");
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x55;
        t
    };
    let mut m = IdMap::default();
    m.insert(parent_txid, (Fk(66), (3000, 24)));
    let skel = BatchParentIds {
        ids: Arc::new(m),
        spent: Arc::new(rbitcoin_query::U64Map::default()),
        n_out: Default::default(),
        need_vouts: rbitcoin_query::U64Map::default(),
    };
    let child = child_spend(parent_txid, 0x66);
    let need = vec![(Fk(1), vec![child])];
    {
        let _ = q.confirm_stats().take_window();
        let plan = plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), Some(&skel))
            .expect("skeleton stamp");
        assert_eq!(first_edge_create(&plan), Fk(66));
        assert_eq!(
            plan.external_parents.get(&66).and_then(|p| p.body),
            Some((3000, 24))
        );
        assert_eq!(plan.external_parent_txid(66), Some(parent_txid));
        let mix = q.confirm_stats().take_window();
        assert_eq!(mix.pin_txid_n, 1, "skeleton hits use the id_cache meter");
        assert_eq!(mix.head_need, 0, "skeleton must skip leftover TipOnly");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plan_batch_skeleton_empty_carried_does_not_walk_ins() {
    use rbitcoin_query::{BatchParentIds, IdMap};
    use std::sync::Arc;
    let (dir, q) = temp_query("skeleton-carried-not-ins");
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x55;
        t
    };
    let mut m = IdMap::default();
    m.insert(parent_txid, (Fk(66), (3000, 24)));
    let skel = BatchParentIds {
        ids: Arc::new(m),
        spent: Arc::new(rbitcoin_query::U64Map::default()),
        n_out: Default::default(),
        need_vouts: rbitcoin_query::U64Map::default(),
    };
    let child = child_spend(parent_txid, 0x66);
    let (block, txids) = rbitcoin_query::testutil::block_from_applies(std::slice::from_ref(&child));
    let block = Arc::new(block);
    let err = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            Some(&skel),
            Some(&[]),
        )
        .expect_err("empty carried_need must not collect PlanIn prevs");
    assert!(
        err.to_string().contains("parent create_fk unresolved"),
        "got: {err}"
    );
    let plan = q
        .archive_plan_batch_from_wire(
            &[(Fk(1), &block, txids.as_slice())],
            1,
            &rbitcoin_query::InFlight::new(),
            Some(&skel),
            Some(&[parent_txid][..]),
        )
        .expect("carried key stamps without a second input walk");
    let inp = plan
        .edges
        .values()
        .flatten()
        .find(|e| e.vout != u32::MAX)
        .expect("spend");
    assert_eq!(inp.create_fk, Fk(66));
    let _ = std::fs::remove_dir_all(&dir);
}

/// S0 plan and the shared helper stamp the same skeleton parent.
#[test]
fn stamp_external_parents_matches_plan_batch_on_skeleton() {
    use rbitcoin_query::{BatchParentIds, IdMap};
    use std::sync::Arc;
    let (dir, q) = temp_query("stamp-helper-plan");
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x71;
        t
    };
    let mut m = IdMap::default();
    m.insert(parent_txid, (Fk(88), (4000, 32)));
    let skel = BatchParentIds {
        ids: Arc::new(m),
        spent: Arc::new(rbitcoin_query::U64Map::default()),
        n_out: Default::default(),
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
    assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(88)));
    assert_eq!(
        helper.idents.get(&88).and_then(|p| p.body),
        Some((4000, 32))
    );
    assert_eq!(helper.idents.get(&88).map(|p| p.txid), Some(parent_txid));

    let child = child_spend(parent_txid, 0x72);
    let need = vec![(Fk(1), vec![child])];
    let plan =
        plan_applies(&q, &need, 1, &rbitcoin_query::InFlight::new(), Some(&skel)).expect("S0 plan");
    assert_eq!(first_edge_create(&plan), Fk(88));
    assert_eq!(
        plan.external_parents.get(&88).and_then(|p| p.body),
        helper.idents.get(&88).and_then(|p| p.body)
    );
    assert_eq!(
        plan.external_parent_txid(88),
        helper.idents.get(&88).map(|p| p.txid)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// In-flight CreatePin skips leftover TipOnly (`head_need=0`) and stamps the pin.
#[test]
fn stamp_inflight_hit_carries_create_pin() {
    use std::sync::Arc;
    let (dir, q) = temp_query("inflight-creates-pin");
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x93;
        t
    };
    let pin = rbitcoin_query::CreatePinInner::records(
        rbitcoin_store::TxRecord {
            txid: parent_txid,
            version: 1,
            locktime: 0,
            input_count: 0,
            output_count: 1,
        },
        vec![rbitcoin_store::OutputRecord::unspent(1, vec![0x51])],
    );
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins([(Fk(93), &pin)], None);
    let ifo = &log;
    {
        let _ = q.confirm_stats().take_window();
        let helper = rbitcoin_query::stamp_external_parents(
            q.store(),
            &[parent_txid],
            ifo,
            None,
            q.confirm_stats(),
        )
        .expect("inflight stamp");
        assert_eq!(helper.head_need_n, 0, "inflight hit must skip leftover");
        let got = helper
            .idents
            .get(&93)
            .and_then(|p| p.pin.as_ref())
            .expect("stamp must carry CreatePin");
        assert!(Arc::ptr_eq(got, &pin));

        let child = child_spend(parent_txid, 0x94);
        let need = vec![(Fk(1), vec![child])];
        let plan = plan_applies(&q, &need, 1, ifo, None).expect("S0 inflight");
        assert_eq!(first_edge_create(&plan), Fk(93));
        let mix = q.confirm_stats().take_window();
        assert_eq!(mix.head_need, 0, "plan path must skip leftover too");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Freeze + append: batch-merge is vector concat of frozen commit halves;
/// external staging maps are dropped (not union-mutated).
#[test]
fn freeze_after_pin_then_append_preserves_fk_order() {
    let (dir, q) = temp_query("freeze-append");
    let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
    let mut plan_a = plan_applies(&q, &need_a, 1, &rbitcoin_query::InFlight::new(), None).unwrap();
    // Simulate residual stamp staging (must not survive freeze/append).
    plan_a.external_parents.insert(
        99,
        rbitcoin_query::ParentIdent::with_body([9u8; 32], (0, 1)),
    );
    let txid = plan_a.batch_pin[0].tx().txid;
    let fk = plan_a.planned_fks[0];
    plan_a.freeze_after_pin();
    assert!(plan_a.external_parents.is_empty());
    assert!(
        plan_a.batch_creates.is_empty(),
        "freeze drops batch_creates; in-flight binds from batch_pin"
    );
    let mut log = rbitcoin_query::InFlight::new();
    log.note_pins(
        plan_a
            .planned_fks
            .iter()
            .zip(plan_a.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    assert_eq!(
        log.get_create_fk(&txid),
        Some(fk),
        "in-flight still has txid→fk after freeze"
    );

    let need_b = vec![(Fk(2), vec![coinbase_apply(2), coinbase_apply(3)])];
    let mut plan_b = plan_applies(&q, &need_b, 2, &rbitcoin_query::InFlight::new(), None).unwrap();
    plan_b.external_parents.insert(
        88,
        rbitcoin_query::ParentIdent::with_body([0u8; 32], (0, 1)),
    );
    plan_b.freeze_after_pin();

    let fks_a = plan_a.planned_fks.clone();
    let fks_b = plan_b.planned_fks.clone();
    assert_eq!(fks_a.len(), 1);
    assert_eq!(fks_b.len(), 2);

    plan_a.append(plan_b);
    assert!(
        plan_a.external_parents.is_empty(),
        "append must not keep stamp staging maps"
    );
    assert_eq!(plan_a.planned_fks.len(), 3);
    assert_eq!(&plan_a.planned_fks[..1], &fks_a[..]);
    assert_eq!(&plan_a.planned_fks[1..], &fks_b[..]);
    assert_eq!(plan_a.packed.len(), 3);
    assert_eq!(plan_a.batch_pin.len(), 3);
    // Contiguous Class A commit of the merged frozen plan.
    assert!(commit_stamped(&q, plan_a).unwrap());
    assert_eq!(q.tx_body_count(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn retain_headers_needing_body_strips_archived() {
    let mut plan = rbitcoin_query::archive::ArchiveWritePlan::empty();
    plan.planned_fks = vec![Fk(1), Fk(2), Fk(3)];
    plan.per_header_ranges = vec![(Fk(10), Fk(1), 2), (Fk(20), Fk(3), 1)];
    // Minimal packed rows so retain can compact.
    let dummy_pin = |i: u8| {
        rbitcoin_query::CreatePinInner::records(
            TxRecord {
                txid: [i; 32],
                version: 1,
                locktime: 0,
                input_count: 0,
                output_count: 0,
            },
            Vec::new(),
        )
    };
    plan.packed = vec![
        (dummy_pin(1), Vec::new()),
        (dummy_pin(2), Vec::new()),
        (dummy_pin(3), Vec::new()),
    ];
    plan.batch_pin = vec![dummy_pin(1), dummy_pin(2), dummy_pin(3)];
    // Header 10 already has body; 20 needs body.
    let keep = plan
        .retain_headers_needing_body(|hfk| Ok(hfk == Fk(10)))
        .unwrap();
    assert!(keep);
    assert_eq!(plan.per_header_ranges, vec![(Fk(20), Fk(3), 1)]);
    assert_eq!(plan.planned_fks, vec![Fk(3)]);
    assert_eq!(plan.packed.len(), 1);
}

/// retain_headers edges: empty ranges, all have body, no-op full keep, null fks.
#[test]
fn retain_headers_needing_body_edge_matrix() {
    let dummy_pin = |i: u8| {
        rbitcoin_query::CreatePinInner::records(
            TxRecord {
                txid: [i; 32],
                version: 1,
                locktime: 0,
                input_count: 0,
                output_count: 0,
            },
            Vec::new(),
        )
    };

    // No per_header_ranges: keep iff packed non-empty.
    let mut empty_ranges = rbitcoin_query::archive::ArchiveWritePlan::empty();
    empty_ranges.packed = vec![(dummy_pin(1), Vec::new())];
    assert!(empty_ranges
        .retain_headers_needing_body(|_| Ok(false))
        .unwrap());
    let mut empty_all = rbitcoin_query::archive::ArchiveWritePlan::empty();
    assert!(!empty_all
        .retain_headers_needing_body(|_| Ok(false))
        .unwrap());

    let mut all_have = rbitcoin_query::archive::ArchiveWritePlan::empty();
    all_have.planned_fks = vec![Fk(1), Fk(2)];
    all_have.per_header_ranges = vec![(Fk(10), Fk(1), 1), (Fk(20), Fk(2), 1)];
    all_have.packed = vec![(dummy_pin(1), Vec::new()), (dummy_pin(2), Vec::new())];
    all_have.batch_pin = vec![dummy_pin(1), dummy_pin(2)];
    all_have.batch_creates = vec![([1u8; 32], Fk(1)), ([2u8; 32], Fk(2))];
    assert!(!all_have.retain_headers_needing_body(|_| Ok(true)).unwrap());
    assert!(all_have.is_empty());
    assert!(all_have.per_header_ranges.is_empty());

    let mut full = rbitcoin_query::archive::ArchiveWritePlan::empty();
    full.planned_fks = vec![Fk(1)];
    full.per_header_ranges = vec![(Fk(10), Fk(1), 1)];
    full.packed = vec![(dummy_pin(1), Vec::new())];
    full.batch_pin = vec![dummy_pin(1)];
    assert!(full.retain_headers_needing_body(|_| Ok(false)).unwrap());
    assert_eq!(full.planned_fks, vec![Fk(1)]);

    let mut with_null = rbitcoin_query::archive::ArchiveWritePlan::empty();
    with_null.planned_fks = vec![Fk::NULL, Fk(5)];
    with_null.per_header_ranges = vec![(Fk(1), Fk::NULL, 1), (Fk(2), Fk(5), 1)];
    with_null.packed = vec![(dummy_pin(0), Vec::new()), (dummy_pin(5), Vec::new())];
    with_null.batch_pin = vec![dummy_pin(0), dummy_pin(5)];
    // Header 1 already has body; header 2 needs body (first=Fk(5)).
    assert!(with_null
        .retain_headers_needing_body(|hfk| Ok(hfk == Fk(1)))
        .unwrap());
    assert_eq!(with_null.planned_fks, vec![Fk(5)]);

    let mut plan = rbitcoin_query::archive::ArchiveWritePlan::empty();
    plan.external_parents
        .insert(7, rbitcoin_query::ParentIdent::new([0xab; 32]));
    assert_eq!(plan.external_parent_txid(7), Some([0xab; 32]));
    assert!(plan.external_parent_txid(8).is_none());
    plan.clear_external_parent_outs();
    assert!(plan.external_parents.is_empty());
    plan.append(rbitcoin_query::archive::ArchiveWritePlan::empty());
    assert!(plan.is_empty());
}

#[test]
fn retain_headers_missing_first_fk_is_corrupt() {
    let dummy_pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: [5u8; 32],
            version: 1,
            locktime: 0,
            input_count: 0,
            output_count: 0,
        },
        Vec::new(),
    );
    let mut plan = rbitcoin_query::archive::ArchiveWritePlan::empty();
    plan.planned_fks = vec![Fk(5)];
    plan.per_header_ranges = vec![(Fk(10), Fk(99), 1)];
    plan.packed = vec![(dummy_pin, Vec::new())];
    let err = plan
        .retain_headers_needing_body(|_| Ok(false))
        .expect_err("missing first fk must not keep the wrong span");
    let msg = err.to_string();
    assert!(
        msg.contains("invariant") && msg.contains("retain first fk"),
        "unexpected err: {msg}"
    );
}

/// `wire_edges_match` is the release tripwire for a prevout the edge
/// builder did not copy from the wire tx. A coinbase input is skipped.
#[test]
fn wire_edges_match_rejects_a_disagreeing_prevout() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_query::archive::{plan_in_from_txin, wire_edges_match};
    use rbitcoin_query::SpendEdge;
    use rbitcoin_store::StoreError;

    let prev = bitcoin::Txid::from_byte_array([0x11; 32]);
    let tx = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: prev,
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let spend = Fk(7);
    let edges = [
        SpendEdge {
            prev_txid: [0x22; 32],
            vout: 9,
            spend_fk: spend,
            create_fk: Fk::NULL,
            vin: 0,
        },
        SpendEdge {
            prev_txid: [0x33; 32],
            vout: 4,
            spend_fk: spend,
            create_fk: Fk(3),
            vin: 1,
        },
    ];
    let err = wire_edges_match(&tx, spend, &edges).unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Corrupt("invariant: write encode edge/wire prevout mismatch")
        ),
        "coinbase must be skipped; the disagreeing spend is the prevout tripwire: {err:?}"
    );

    let short = wire_edges_match(&tx, spend, &edges[..1]).unwrap_err();
    assert!(matches!(
        short,
        StoreError::Corrupt("invariant: write encode spends/tx input mismatch")
    ));
    let mut bad_fk = edges;
    bad_fk[1].spend_fk = Fk(8);
    let fk_err = wire_edges_match(&tx, spend, &bad_fk).unwrap_err();
    assert!(matches!(
        fk_err,
        StoreError::Corrupt("invariant: write encode spend_fk mismatch")
    ));

    // A non-coinbase vout of u32::MAX still takes the null-edge arm.
    // Deleting that arm would stop failing closed on this input.
    let max_vout = TxIn {
        previous_output: OutPoint {
            txid: prev,
            vout: u32::MAX,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let planned = plan_in_from_txin(&max_vout);
    assert!(!planned.is_coinbase);
    assert_eq!(planned.prev_index, u32::MAX);
}
