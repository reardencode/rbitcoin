use rbitcoin_primitives::Fk;
use rbitcoin_query::confirm_run::pin::*;
use rbitcoin_query::confirm_run::*;
use rbitcoin_query::{CreatePin, ParentIdent, U64Map};
use rbitcoin_store::{OutputRecord, TxRecord};

fn pin_with(txid: [u8; 32], inputs: u32) -> CreatePin {
    rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: inputs,
            output_count: 1,
        },
        vec![OutputRecord::unspent(50, vec![0x51])],
    )
}

#[test]
fn plan_pin_coinbase_flag_follows_input_count() {
    let one = pin_with([0x31; 32], 1);
    let two = pin_with([0x32; 32], 2);
    let mut parents = rbitcoin_query::BatchParents::new();
    parents.insert_owned(
        Fk(1),
        one.tx().clone(),
        vec![(0, OutputRecord::unspent(50, vec![0x51]))],
        vec![0],
        None,
        None,
        Vec::new(),
    );
    let mut by_id: U64Map<CreatePin> = U64Map::default();
    by_id.insert(1, one);
    let mut vouts: U64Map<Vec<u32>> = U64Map::default();
    vouts.insert(1, vec![0]);
    let mut still = U64Map::default();
    apply_plan_pins(
        &vouts,
        &by_id,
        &ParentPinStamp::default(),
        &mut parents,
        &mut still,
    );
    assert_eq!(parents.get_parent_coinbase(Fk(1)), None);

    let mut stamp = ParentPinStamp::default();
    stamp
        .idents
        .insert(1, ParentIdent::with_body([0x31; 32], (4, 8)));
    apply_plan_pins(&vouts, &by_id, &stamp, &mut parents, &mut still);
    assert_eq!(
        parents.get_body_range(Fk(1)),
        Some((4, 8)),
        "a one-input pin still publishes a body range"
    );

    let mut fresh = rbitcoin_query::BatchParents::new();
    let mut by_two: U64Map<CreatePin> = U64Map::default();
    by_two.insert(2, two);
    let mut need: U64Map<Vec<u32>> = U64Map::default();
    need.insert(2, vec![0]);
    let mut still = U64Map::default();
    apply_plan_pins(
        &need,
        &by_two,
        &ParentPinStamp::default(),
        &mut fresh,
        &mut still,
    );
    assert_eq!(fresh.get_parent_coinbase(Fk(2)), Some(false));

    let mut empty_need: U64Map<Vec<u32>> = U64Map::default();
    empty_need.insert(3, Vec::new());
    let mut by_empty: U64Map<CreatePin> = U64Map::default();
    by_empty.insert(3, pin_with([0x33; 32], 1));
    let mut dest = rbitcoin_query::BatchParents::new();
    let mut still = U64Map::default();
    apply_plan_pins(
        &empty_need,
        &by_empty,
        &ParentPinStamp::default(),
        &mut dest,
        &mut still,
    );
    assert!(
        dest.get_parent_tx(Fk(3)).is_some(),
        "an empty need list is not already covered"
    );
}

fn pin_script(txid: [u8; 32], script: Vec<u8>) -> CreatePin {
    rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(50, script)],
    )
}

fn edge(spend: u64, create: u64) -> rbitcoin_query::SpendEdge {
    rbitcoin_query::SpendEdge {
        prev_txid: [0x11; 32],
        vout: 0,
        spend_fk: Fk(spend),
        create_fk: Fk(create),
        vin: 0,
    }
}

/// Packed parent at fk 1, plus two creates that this batch does not spend.
fn packed_parent_plan(parent: &CreatePin) -> rbitcoin_query::ArchiveWritePlan {
    let mut plan = rbitcoin_query::ArchiveWritePlan::empty();
    plan.packed = vec![
        (std::sync::Arc::clone(parent), vec![]),
        (pin_script([0x22; 32], vec![0x33]), vec![]),
        (pin_script([0x23; 32], vec![0x34]), vec![]),
    ];
    plan.planned_fks = vec![Fk(1), Fk(2), Fk(3)];
    plan.external_parent_vouts.insert(1, vec![0]);
    plan.edges.insert(2, vec![edge(2, 1)]);
    plan
}

fn parent_script(parents: &rbitcoin_query::BatchParents, id: u64) -> Vec<u8> {
    parents
        .get_parent_out(Fk(id), 0)
        .expect("pinned parent")
        .1
        .script
}

#[test]
fn pin_thin_packed_parent_matches_empty_and_same_inflight() {
    let parent = pin_script([0x21; 32], vec![0x51]);
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("pin-thin-same");
    let pin_once = |inflight: Option<&rbitcoin_query::InFlight>| {
        let mut plan = packed_parent_plan(&parent);
        let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
        let (parents, _) =
            pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], inflight).expect("pin");
        parent_script(&parents, 1)
    };
    let alone = pin_once(None);
    let mut inflight = rbitcoin_query::InFlight::new();
    inflight.note_pins([(Fk(1), &parent)], Some(1));
    let with_flight = pin_once(Some(&inflight));
    assert_eq!(alone, vec![0x51]);
    assert_eq!(with_flight, alone);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn pin_thin_batch_map_keeps_only_spent_parents() {
    let parent = pin_script([0x21; 32], vec![0x51]);
    let mut plan = packed_parent_plan(&parent);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    let spend = spend_edges_from_plan(&plan, &mut stamp).expect("edges");
    let mut keys: Vec<u64> = spend.batch_pin_by_id.keys().copied().collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![1],
        "batch pin map is the spent parents, not every packed create"
    );
}

#[test]
fn pin_thin_packed_pin_beats_different_inflight() {
    let packed = pin_script([0x21; 32], vec![0x51]);
    let other = pin_script([0x99; 32], vec![0x52]);
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("pin-thin-order");
    let mut inflight = rbitcoin_query::InFlight::new();
    inflight.note_pins([(Fk(1), &other)], Some(1));
    let mut plan = packed_parent_plan(&packed);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    let (parents, _) =
        pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], Some(&inflight)).expect("pin");
    assert_eq!(
        parent_script(&parents, 1),
        vec![0x51],
        "a packed parent is the pin even when InFlight has that id"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn pin_thin_below_min_cold_ranges_and_inflight_id_adopts() {
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};

    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("pin-thin-min");
    let disk_tx = TxRecord {
        txid: [0x41; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let disk_script = vec![0x51u8];
    let fks = q
        .store()
        .txs
        .put_full_batch_indexed(
            &[(
                disk_tx.clone(),
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                vec![OutputRecord::unspent(50, disk_script.clone())],
            )],
            true,
        )
        .unwrap();
    let disk_fk = fks[0];
    let disk_id = disk_fk.get().unwrap();
    let range = q.store().txs.body_range(disk_fk).unwrap();
    let spent = q.store().tx_spent_range(disk_fk).unwrap();

    let flight_id = disk_id + 10_000;
    let flight_pin = pin_script([0x42; 32], vec![0xAB]);
    let stale = pin_script([0x41; 32], vec![0xEE]);
    let mut inflight = rbitcoin_query::InFlight::new();
    inflight.note_pins([(disk_fk, &stale)], Some(1));
    inflight.note_pins([(Fk(flight_id), &flight_pin)], Some(4));
    inflight.prune_below_height(Some(2));
    assert!(inflight.get_out(disk_id).is_none());
    assert!(inflight.get_out(flight_id).is_some());

    let mut plan = rbitcoin_query::ArchiveWritePlan::empty();
    plan.packed = vec![(pin_script([0x43; 32], vec![0x01]), vec![])];
    plan.planned_fks = vec![Fk(flight_id + 1)];
    plan.edges
        .insert(flight_id + 1, vec![edge(flight_id + 1, disk_id)]);
    plan.external_parents.insert(
        disk_id,
        rbitcoin_query::ParentIdent::with_loc(disk_tx.txid, range, spent, 1),
    );
    plan.external_parent_vouts.insert(disk_id, vec![0]);
    plan.external_parent_vouts.insert(flight_id, vec![0]);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    let (parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], Some(&inflight))
        .expect("low id cold-ranges; in-flight id is adopted");
    assert_eq!(parent_script(&parents, disk_id), disk_script);
    assert_eq!(parent_script(&parents, flight_id), vec![0xAB]);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn pin_thin_create_in_spend_header_ranges() {
    let mut plan = rbitcoin_query::ArchiveWritePlan::empty();
    plan.planned_fks = vec![Fk(10), Fk(11), Fk(20)];
    plan.per_header_ranges = vec![(Fk(100), Fk(10), 2), (Fk(101), Fk(20), 1)];
    assert!(plan.create_in_spend_header(Fk(10), 11));
    assert!(!plan.create_in_spend_header(Fk(10), 20));
    assert!(!plan.create_in_spend_header(Fk(10), 99));
    assert!(!plan.create_in_spend_header(Fk(50), 11));

    plan.per_header_ranges.clear();
    assert!(plan.create_in_spend_header(Fk(10), 11));
    assert!(plan.create_in_spend_header(Fk(20), 20));
    assert!(!plan.create_in_spend_header(Fk(10), 99));
}
