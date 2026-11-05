use rbitcoin_primitives::Fk;
use rbitcoin_query::batch_parents::*;
use rbitcoin_store::U64Map;
use rbitcoin_store::{OutputRecord, TxRecord};
use std::sync::Arc;

use rbitcoin_store::U64IdentityHasher;

fn tx(id: u8) -> TxRecord {
    let mut txid = [0u8; 32];
    txid[0] = id;
    TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    }
}

fn out(v: i64) -> OutputRecord {
    OutputRecord::unspent(v as u64, vec![0x51])
}

/// Vacant CreatePin insert must keep the script allocation (no PinOuts clone).
#[test]
fn insert_create_pin_shares_script_bytes() {
    use rbitcoin_query::CreatePinInner;
    let script = vec![0x51u8; 4096];
    let pin = CreatePinInner::records(tx(9), vec![OutputRecord::unspent(50, script)]);
    let expect = pin.out_parts(0).expect("vout 0").1.as_ptr();
    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        Fk(9),
        Arc::clone(&pin),
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let got = bp
        .get_parent_txout_parts(Fk(9), 0, |v, sc, t| {
            assert_eq!(v, 50);
            assert_eq!(t[0], 9);
            sc.as_ptr()
        })
        .expect("full pin prevout");
    assert_eq!(got, expect, "CreatePin insert must not clone script bytes");
}

/// Two blocks in one write batch spend different vouts of one in-window create.
/// The merged pin keeps that create's script allocation.
#[test]
fn extend_from_full_pins_keeps_script_bytes() {
    use rbitcoin_query::CreatePinInner;
    let pin = CreatePinInner::records(
        TxRecord {
            output_count: 2,
            ..tx(9)
        },
        vec![
            OutputRecord::unspent(1, vec![0x51u8; 64]),
            OutputRecord::unspent(2, vec![0x52u8; 64]),
        ],
    );
    let p0 = pin.out_parts(0).expect("vout 0").1.as_ptr();
    let p1 = pin.out_parts(1).expect("vout 1").1.as_ptr();
    let mut a = BatchParents::new();
    a.insert_create_pin(
        Fk(9),
        Arc::clone(&pin),
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let mut b = BatchParents::new();
    b.insert_create_pin(Fk(9), pin, vec![1], None, None, Vec::new());
    a.extend_from(b);
    assert!(a.pin_covered(Fk(9), &[0, 1]));
    let got0 = a
        .get_parent_txout_parts(Fk(9), 0, |_, script, _| script.as_ptr())
        .expect("vout 0");
    let got1 = a
        .get_parent_txout_parts(Fk(9), 1, |_, script, _| script.as_ptr())
        .expect("vout 1");
    assert_eq!(got0, p0, "merged full pin must borrow vout 0");
    assert_eq!(got1, p1, "merged full pin must borrow vout 1");
}

#[test]
fn extend_from_merges_disjoint_and_same_fk() {
    let mut a = BatchParents::new();
    a.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(1))],
        vec![0],
        Some(false),
        Some((100, 50)),
        vec![(0, 10)],
    );
    let mut b = BatchParents::new();
    b.insert_owned(
        Fk(2),
        tx(2),
        vec![(0, out(2))],
        vec![0],
        Some(true),
        None,
        Vec::new(),
    );
    b.insert_owned(
        Fk(1),
        tx(1),
        vec![(1, out(3))],
        vec![1],
        None,
        None,
        vec![(1, 20)],
    );
    a.extend_from(b);
    assert_eq!(a.len(), 2);
    assert!(a.has_parent_out(Fk(1), 0));
    assert!(a.has_parent_out(Fk(1), 1));
    assert!(a.has_parent_out(Fk(2), 0));
    a.set_spent_range_only(Fk(1), (1000, 24));
    assert_eq!(a.get_spender_abs(Fk(1), 0), Some(1000));
    assert_eq!(a.get_spender_abs(Fk(1), 1), Some(1008));
    assert_eq!(a.get_parent_coinbase(Fk(1)), Some(false));
    assert_eq!(a.get_parent_coinbase(Fk(2)), Some(true));
}

#[test]
fn insert_layout_coinbase_and_covered() {
    let mut bp = BatchParents::with_capacity(1);
    let live = vec![(0, out(42)), (2, out(99))];
    bp.insert_owned(
        Fk(9),
        tx(9),
        live,
        vec![0, 1, 2],
        Some(true),
        Some((1000, 200)),
        vec![(0, 50), (1, 70), (2, 90)],
    );
    assert_eq!(bp.len(), 1);
    assert!(bp.pin_covered(Fk(9), &[0, 1, 2]));
    assert!(!bp.pin_covered(Fk(9), &[0, 3]));
    assert!(!bp.has_parent_out(Fk(9), 1));
    bp.set_spent_range_only(Fk(9), (2000, 24));
    assert_eq!(bp.get_spender_abs(Fk(9), 2), Some(2016));
    assert_eq!(bp.get_body_range(Fk(9)), Some((1000, 200)));
    assert_eq!(bp.get_parent_coinbase(Fk(9)), Some(true));
    assert!(bp.has_abs_layout(Fk(9)));
    let (_, o) = bp.get_parent_out(Fk(9), 0).unwrap();
    assert_eq!(o.value, 42);
    let (v, script, parent_txid) = bp
        .get_parent_txout_parts(Fk(9), 0, |v, s, t| (v, s.to_vec(), t))
        .unwrap();
    assert_eq!(v, 42);
    assert_eq!(script, &[0x51]);
    assert_eq!(parent_txid[0], 9);
    assert!(bp.get_parent_txout_parts(Fk(9), 1, |_, _, _| ()).is_none());
}

#[test]
fn parent_txout_borrows_pin_script() {
    let mut bp = BatchParents::new();
    let script = vec![0x51, 0x52, 0x53];
    bp.insert_owned(
        Fk(9),
        tx(9),
        vec![(0, OutputRecord::unspent(42, script))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin_ptr = {
        let e = bp.pins.get(&9).expect("pin");
        let outs = e.load_outs();
        outs.get_parts(0).expect("vout 0").1.as_ptr()
    };
    let hit = bp
        .get_parent_txout_parts(Fk(9), 0, |value, spk, txid| {
            assert_eq!(value, 42);
            assert_eq!(spk, &[0x51, 0x52, 0x53]);
            assert_eq!(txid[0], 9);
            assert_eq!(
                spk.as_ptr(),
                pin_ptr,
                "must borrow pin script bytes, not clone"
            );
            true
        })
        .expect("hit");
    assert!(hit);
}

#[test]
fn set_body_range_only_completes_layout_when_rels_present() {
    let mut bp = BatchParents::with_capacity(1);
    bp.insert_owned(
        Fk(3),
        tx(3),
        vec![(0, out(1))],
        vec![0],
        None,
        None,
        vec![(0, 40)],
    );
    assert!(!bp.has_abs_layout(Fk(3)));
    bp.set_body_range_only(Fk(3), (500, 80));
    assert!(!bp.has_abs_layout(Fk(3)));
    bp.set_spent_range_only(Fk(3), (500, 16));
    assert!(bp.has_abs_layout(Fk(3)));
    assert_eq!(bp.get_spender_abs(Fk(3), 0), Some(500));
}

#[test]
fn sparse_spender_rels_skips_unknown() {
    let dense = vec![10, SPENDER_REL_UNKNOWN, 30];
    let sparse = sparse_spender_rels(&dense, &[0, 1, 2]);
    assert_eq!(sparse, vec![(0, 10), (2, 30)]);
    assert!(!layout_covers_need(Some((0, 100)), &sparse, &[0, 1, 2]));
    assert!(layout_covers_need(
        Some((0, 100)),
        &[(0, 10), (2, 30)],
        &[0, 2]
    ));
    assert!(!layout_covers_need(None, &[(0, 10)], &[0]));
}

#[test]
fn get_spender_abs_rejects_unknown_rel() {
    let mut bp = BatchParents::with_capacity(1);
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(1))],
        vec![0],
        None,
        Some((100, 50)),
        vec![(0, SPENDER_REL_UNKNOWN)],
    );
    assert!(bp.get_spender_abs(Fk(1), 0).is_none());
    bp.set_spent_range_only(Fk(1), (100, 8));
    assert_eq!(bp.get_spender_abs(Fk(1), 0), Some(100));
    assert!(bp.get_spender_abs(Fk(1), 1).is_none());
}

/// Identity hasher for pack-scale u64 keys is the raw key (no SipHash mix).
/// Write/lookup structural maps depend on this for the measured CPU win.
#[test]
fn u64_identity_hasher_is_raw_key_and_map_roundtrips_pack_scale() {
    // Shipped path: store identity hasher via U64Map API.
    use std::hash::Hasher;
    let mut h = U64IdentityHasher::default();
    h.write_u64(0xdead_beef_cafe_u64);
    assert_eq!(h.finish(), 0xdead_beef_cafe_u64);

    // Pack-scale create_fk map: sequential ids must insert + get without loss.
    let n = 8_000u64;
    let mut m: U64Map<u32> = U64Map::with_capacity_and_hasher(n as usize, Default::default());
    for i in 1..=n {
        m.insert(i, (i % 1_000_000) as u32);
    }
    assert_eq!(m.len(), n as usize);
    for i in 1..=n {
        assert_eq!(m.get(&i).copied(), Some((i % 1_000_000) as u32));
    }
    // Collisions / wrong finish would drop keys under open addressing.
    assert_eq!(m.get(&0), None);
    assert_eq!(m.get(&(n + 1)), None);
}

#[test]
fn vacant_insert_does_not_arcswap_until_compose() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin = bp.pins.get(&1).expect("vacant pin");
    let outs = pin.load_outs();
    assert!(outs.covers_need(&[0]));
    assert_eq!(outs.get_parts(0).expect("vout 0").0, 10);
    pin.merge_outs(vec![], &[0]);
    assert_eq!(pin.load_outs().get_parts(0).expect("vout 0").0, 10);
}

/// Q-M3: empty checked / already-covered live must not publish a new outs Arc.
#[test]
fn merge_outs_empty_checked_keeps_outs_arc() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin = Arc::clone(bp.pins.get(&1).unwrap());
    assert_eq!(pin.load_outs().get_parts(0).expect("vout 0").0, 10);
    pin.merge_outs(vec![], &[]);
    assert_eq!(
        pin.load_outs().get_parts(0).expect("vout 0").0,
        10,
        "empty checked no-op keeps the prevout"
    );
    pin.merge_outs(vec![(0, out(10))], &[]);
    assert_eq!(pin.load_outs().get_parts(0).expect("vout 0").0, 10);

    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(1, out(20))],
        vec![],
        None,
        None,
        Vec::new(),
    );
    let after = pin.load_outs();
    assert!(
        after.covers_need(&[0]) && after.get_parts(1).expect("vout 1").0 == 20,
        "Occupied empty-checked new live must still widen"
    );
}

#[test]
fn merge_outs_large_script_widens_once() {
    let script = vec![0x51u8; 4096];
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin = Arc::clone(bp.pins.get(&1).unwrap());
    let rec = OutputRecord::unspent(20, script.clone());
    pin.merge_outs(vec![(1, rec.clone())], &[1]);
    pin.merge_outs(vec![(1, rec)], &[1]);
    let snap = pin.load_outs();
    assert_eq!(snap.get_parts(0).expect("vout 0").0, 10);
    assert_eq!(snap.get_parts(1).expect("vout 1").1.len(), 4096);
    assert_eq!(snap.get_parts(1).unwrap().1, script);
}

#[test]
fn compose_adds_vout_without_mutating_old_snap() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin = Arc::clone(bp.pins.get(&1).unwrap());
    let old = pin.load_outs();
    pin.merge_outs(vec![(1, out(20))], &[1]);
    let new = pin.load_outs();
    assert!(old.get_parts(1).is_none(), "old snap must not gain vouts");
    assert_eq!(old.get_parts(0).expect("vout 0").0, 10);
    assert_eq!(old.checked(), &[0]);
    assert!(new.covers_need(&[0, 1]));
    assert_eq!(new.get_parts(1).expect("vout 1").0, 20);
}

/// Prep∥write on one SharedParentPin: write set_layout_for_need must not
/// clobber checked need-vouts or denserels composed by concurrent prep.
///
/// Bodies are immutable snapshots; concurrent compose publishes new Arcs
/// under the pin lock so peer need-vouts and denserels survive.
#[test]
fn set_layout_merges_not_clobbers_under_concurrent_prep() {
    use std::sync::Barrier;
    use std::thread;

    let mut writer = BatchParents::with_capacity(1);
    writer.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        None,
        vec![(0, 10)],
    );
    let pin = Arc::clone(writer.pins.get(&1).expect("shared pin"));

    let barrier = Arc::new(Barrier::new(2));
    let pin_prep = Arc::clone(&pin);
    let barrier_prep = Arc::clone(&barrier);
    let prep = thread::spawn(move || {
        barrier_prep.wait();
        // Concurrent prep batch spends vout 1 of the same create.
        for _ in 0..200 {
            pin_prep.merge_outs(vec![(1, out(20))], &[1]);
            pin_prep.maybe_merge_layout(None, &[(1, 20)]);
        }
    });

    barrier.wait();
    // Write-side layout fill for this batch's need (vout 0); dense has both outs.
    for _ in 0..200 {
        writer.set_layout_for_need(Fk(1), (100, 80), &[10, 20], &[0]);
    }
    prep.join().expect("prep thread");

    // Peer need-vout must still be covered (not wiped by stale checked replace).
    assert!(
        writer.pin_covered(Fk(1), &[0, 1]),
        "checked must keep prep-merged vout 1 after write set_layout"
    );
    assert!(writer.has_parent_out(Fk(1), 1));
    writer.set_spent_range_only(Fk(1), (1000, 24));
    assert_eq!(writer.get_spender_abs(Fk(1), 0), Some(1000));
    assert_eq!(
        writer.get_spender_abs(Fk(1), 1),
        Some(1008),
        "spent abs covers peer vout after merge"
    );
}

/// Sticky outs: consecutive same-parent lookups share one Arc (no re-load).
#[test]
fn sticky_assemble_reuses_outs_arc() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(7),
        tx(7),
        vec![(0, out(10)), (1, out(20)), (2, out(30))],
        vec![0, 1, 2],
        Some(false),
        None,
        Vec::new(),
    );
    let (v0, s0, t0) = bp
        .get_parent_txout_parts(Fk(7), 0, |v, s, t| (v, s.to_vec(), t))
        .unwrap();
    let (v1, s1, t1) = bp
        .get_parent_txout_parts(Fk(7), 1, |v, s, t| (v, s.to_vec(), t))
        .unwrap();
    let (v2, s2, t2) = bp
        .get_parent_txout_parts(Fk(7), 2, |v, s, t| (v, s.to_vec(), t))
        .unwrap();
    assert_eq!(v0, 10);
    assert_eq!(v1, 20);
    assert_eq!(v2, 30);
    assert_eq!(s0, vec![0x51]);
    assert_eq!(s1, vec![0x51]);
    assert_eq!(s2, vec![0x51]);
    assert_eq!(t0[0], 7);
    assert_eq!(t1[0], 7);
    assert_eq!(t2[0], 7);
    assert_eq!(bp.sticky_outs.borrow().as_ref().map(|(id, _)| *id), Some(7));
    bp.insert_owned(
        Fk(8),
        tx(8),
        vec![(0, out(99))],
        vec![0],
        None,
        None,
        Vec::new(),
    );
    bp.get_parent_txout_parts(Fk(8), 0, |_, _, _| ()).unwrap();
    assert_eq!(bp.sticky_outs.borrow().as_ref().map(|(id, _)| *id), Some(8));
}

/// Pure compose helpers: widening need and layout builds new halves without
/// mutating the source snapshots (AGENTS prefer-immutable).
#[test]
fn pin_body_compose_does_not_mutate_source() {
    let pin = SharedParentPin::new(
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        Some((100, 50)),
        vec![(0, 10)],
    );
    let before_outs = pin.load_outs();
    let before_lay = pin.load_layout();
    pin.merge_outs(vec![(1, out(20))], &[1]);
    pin.maybe_merge_layout(None, &[(1, 20)]);
    let after_outs = pin.load_outs();
    let after_lay = pin.load_layout();
    assert_eq!(before_outs.get_parts(0).expect("vout 0").0, 10);
    assert!(before_outs.get_parts(1).is_none());
    assert_eq!(before_outs.checked(), &[0]);
    assert_eq!(before_lay.spender_rels, vec![(0, 10)]);
    assert_eq!(after_outs.get_parts(1).expect("vout 1").0, 20);
    assert!(after_outs.covers_need(&[0, 1]));
    assert_eq!(after_lay.spender_rels, vec![(0, 10), (1, 20)]);
}

/// Covered share hit must not replace outs Arc (no full clone on no-op).
#[test]
fn covered_insert_keeps_outs_arc_identity() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        Some(false),
        Some((100, 50)),
        vec![(0, 10)],
    );
    let pin = Arc::clone(bp.pins.get(&1).unwrap());
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10))],
        vec![0],
        None,
        Some((100, 50)),
        vec![(0, 10)],
    );
    let outs_after = pin.load_outs();
    let lay_after = pin.load_layout();
    assert_eq!(outs_after.get_parts(0).expect("vout 0").0, 10);
    assert_eq!(lay_after.body_range, Some((100, 50)));
    assert_eq!(lay_after.spender_rels, vec![(0, 10)]);
}

/// Layout-only write must not replace outs Arc (scripts stay shared).
#[test]
fn layout_only_write_keeps_outs_arc() {
    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10)), (1, out(20))],
        vec![0, 1],
        Some(false),
        None,
        vec![(0, 10)],
    );
    let pin = Arc::clone(bp.pins.get(&1).unwrap());
    bp.set_layout_for_need(Fk(1), (500, 80), &[10, 20], &[]);
    let outs_after = pin.load_outs();
    let lay = pin.load_layout();
    assert_eq!(outs_after.get_parts(0).expect("vout 0").0, 10);
    assert_eq!(outs_after.get_parts(1).expect("vout 1").0, 20);
    assert_eq!(lay.body_range, Some((500, 80)));
    bp.set_spent_range_only(Fk(1), (800, 24));
    assert_eq!(bp.get_spender_abs(Fk(1), 1), Some(808));
}

/// `set_layout_sparse` / `set_body_range_only` edges on missing pins.
#[test]
fn layout_sparse_and_body_range_only_surface() {
    let mut bp = BatchParents::with_capacity(8);
    // Null / missing pin early-outs (set_layout_sparse + set_body_range_only).
    bp.set_layout_sparse(Fk::NULL, (0, 10), vec![(0, 1)], &[]);
    bp.set_layout_sparse(Fk(99), (0, 10), vec![(0, 1)], &[0]);
    bp.set_body_range_only(Fk::NULL, (1, 2));
    bp.set_body_range_only(Fk(99), (1, 2));
    bp.set_layout(Fk::NULL, (0, 1), &[1]);
    bp.set_layout_for_need(Fk(99), (0, 1), &[1], &[]);

    bp.insert_owned(
        Fk(1),
        tx(1),
        vec![(0, out(10)), (1, out(20))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    bp.insert_owned(
        Fk(2),
        tx(2),
        vec![(0, out(30))],
        vec![0],
        Some(false),
        Some((100, 40)),
        vec![(0, 5)],
    );

    // Grow checked via extra_need, then fill sparse layout.
    bp.set_layout_sparse(Fk(1), (200, 50), vec![(0, 7), (1, 8)], &[1]);
    assert!(bp.has_parent_out(Fk(1), 0));
    assert_eq!(bp.get_body_range(Fk(1)), Some((200, 50)));
    assert!(!bp.has_abs_layout(Fk(1)));
    bp.set_spent_range_only(Fk(1), (200, 24));
    assert!(bp.has_abs_layout(Fk(1)));
    // No-op when layout already covers same range+rels.
    bp.set_layout_sparse(Fk(1), (200, 50), vec![(0, 7), (1, 8)], &[]);
    assert_eq!(bp.get_spender_abs(Fk(1), 1), Some(208));

    // set_body_range_only updates range; same range is no-op.
    bp.set_body_range_only(Fk(2), (300, 60));
    assert_eq!(bp.get_body_range(Fk(2)), Some((300, 60)));
    bp.set_body_range_only(Fk(2), (300, 60));
    assert_eq!(bp.get_body_range(Fk(2)), Some((300, 60)));
}

#[test]
fn spend_abs_jobs_unique_and_missing_is_corrupt() {
    let mut bp = BatchParents::new();
    bp.insert_owned(Fk(1), tx(1), vec![(0, out(1))], vec![0], None, None, vec![]);
    bp.set_spent_range_only(Fk(1), (1000, 24));
    let jobs = bp
        .spend_abs_jobs([
            (Fk(1), 0, Fk(9), 0),
            (Fk::NULL, 0, Fk(9), 0),
            (Fk(1), 0, Fk(9), 1),
        ])
        .expect("abs");
    assert_eq!(
        jobs,
        vec![(1, 0, rbitcoin_store::spent_abs(1000, 0), Fk(9), 0)]
    );
    let err = bp.spend_abs_jobs([(Fk(2), 0, Fk(9), 0)]).unwrap_err();
    assert!(
        err.to_string().contains("missing pin denserels/abs"),
        "got {err}"
    );
}

/// has_abs_layout null and missing pins.
#[test]
fn has_layout_helpers_null_and_missing() {
    let bp = BatchParents::new();
    assert!(!bp.has_abs_layout(Fk::NULL));
    assert!(!bp.has_abs_layout(Fk(1)));
    assert!(bp.get_parent_tx(Fk::NULL).is_none());
    assert!(bp.get_parent_coinbase(Fk::NULL).is_none());
    assert!(bp.get_body_range(Fk::NULL).is_none());
}
