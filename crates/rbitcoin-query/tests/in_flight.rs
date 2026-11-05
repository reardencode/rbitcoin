use rbitcoin_primitives::Fk;
use rbitcoin_query::archive::CreatePin;
use rbitcoin_query::archive::CreatePinInner;
use rbitcoin_query::in_flight::*;
use rbitcoin_store::{OutputRecord, TxRecord};

fn pin(id: u64) -> CreatePin {
    let mut txid = [0u8; 32];
    txid[..8].copy_from_slice(&id.to_le_bytes());
    pin_with_txid(txid)
}

fn pin_with_txid(txid: [u8; 32]) -> CreatePin {
    CreatePinInner::records(
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    )
}

#[test]
fn creates_only_resolves_txid() {
    let mut m = InFlight::new();
    let mut tid = [0u8; 32];
    tid[0] = 0xab;
    m.note_creates([(tid, Fk(42))], None);
    assert_eq!(m.get_create_fk(&tid), Some(Fk(42)));
    assert!(m.get_out(42).is_none(), "creates-only has no denserels pin");
}

#[test]
fn size_snapshot_counts_packs_and_bytes() {
    let mut m = InFlight::new();
    let p1 = pin(1);
    let p2 = pin(2);
    m.note_pins([(Fk(1), &p1)], Some(1));
    m.note_pins([(Fk(2), &p2)], Some(2));
    let (packs, entries, bytes) = m.size_snapshot();
    assert_eq!(packs, 2);
    assert_eq!(entries, 2);
    assert!(bytes > 0, "expected non-zero approx bytes");
    assert!(bytes < 4096, "bytes={bytes}");
    rbitcoin_query::process_mem_stats::note(packs, entries, bytes);
    let s = rbitcoin_query::process_mem_stats::load();
    assert_eq!(s.inflight_layers, 2);
    assert_eq!(s.inflight_pins, 2);
    let again = m.size_snapshot();
    assert_eq!(
        (packs, entries, bytes),
        again,
        "size_snapshot must reuse cached bytes (no pin walk)"
    );
}

#[test]
fn get_misses_until_note() {
    let mut m = InFlight::new();
    let p = pin(1);
    assert!(m.get_create_fk(&p.tx().txid).is_none());
    m.note_pins([(Fk(1), &p)], Some(1));
    assert!(m.get_create_fk(&p.tx().txid).is_some());
    assert!(m.get_out(1).is_some());
}

#[test]
fn prune_drops_whole_old_packs() {
    let mut m = InFlight::new();
    let a = pin(10);
    let b = pin(50);
    m.note_pins([(Fk(10), &a)], Some(1));
    m.note_pins([(Fk(50), &b)], Some(3));
    assert_eq!(m.pack_count(), 2);
    m.prune_below_height(Some(2));
    assert_eq!(m.pack_count(), 1);
    assert!(m.get_out(50).is_some());
    assert!(m.get_out(10).is_none());
}

/// Drop is pack height vs the wave's pre-TipOnly drain+fence snapshot,
/// not `tx.head` occupied or `confirmed[]` HWM (mainnet 931147 / 945952).
#[test]
fn prune_below_height_drops_strictly_below() {
    let mut m = InFlight::new();
    let confirmed = pin(10);
    let ahead = pin(50);
    m.note_pins([(Fk(10), &confirmed)], Some(5));
    m.note_pins([(Fk(50), &ahead)], Some(6));
    m.prune_below_height(None);
    assert_eq!(m.pack_count(), 2, "no snapshot: keep every pack");

    m.prune_below_height(Some(5));
    assert!(
        m.get_create_fk(&confirmed.tx().txid).is_some(),
        "equality keeps (drop is strictly below)"
    );
    assert!(m.get_create_fk(&ahead.tx().txid).is_some());

    m.prune_below_height(Some(6));
    assert!(
        m.get_create_fk(&confirmed.tx().txid).is_none(),
        "height 5 is below noted 6"
    );
    assert!(
        m.get_create_fk(&ahead.tx().txid).is_some(),
        "height == noted keeps"
    );

    m.prune_below_height(Some(7));
    assert!(m.is_empty());
}

#[test]
fn prune_below_height_keeps_untagged() {
    let mut m = InFlight::new();
    let a = pin(10);
    let b = pin(20);
    m.note_pins([(Fk(10), &a)], Some(1));
    m.note_pins([(Fk(20), &b)], None);
    m.prune_below_height(Some(99));
    assert!(m.get_create_fk(&a.tx().txid).is_none());
    assert!(m.get_create_fk(&b.tx().txid).is_some(), "untagged stays");
}

#[test]
fn prune_below_height_drops_height_index_prefix() {
    let mut m = InFlight::new();
    let pins: Vec<_> = (1u32..=20).map(|h| (h, pin(u64::from(h)))).collect();
    for (h, p) in &pins {
        m.note_pins([(Fk(u64::from(*h)), p)], Some(*h));
    }
    m.prune_below_height(Some(10));
    assert_eq!(m.pack_count(), 11, "heights 10..=20");
    assert!(m.get_out(9).is_none());
    assert!(m.get_out(10).is_some());
    assert!(m.get_out(20).is_some());
    m.drop_from_height(15);
    assert!(m.get_out(14).is_some());
    assert!(m.get_out(15).is_none());
    assert!(m.get_out(20).is_none());
    assert_eq!(m.pack_count(), 5, "heights 10..=14");
}

#[test]
fn drop_from_height_keeps_lower_and_untagged() {
    let mut m = InFlight::new();
    let a = pin(10);
    let b = pin(20);
    let c = pin(30);
    m.note_pins([(Fk(10), &a)], Some(1));
    m.note_pins([(Fk(20), &b)], Some(3));
    m.note_pins([(Fk(30), &c)], None);
    m.drop_from_height(3);
    assert!(m.get_create_fk(&a.tx().txid).is_some());
    assert!(m.get_create_fk(&b.tx().txid).is_none());
    assert!(m.get_create_fk(&c.tx().txid).is_some(), "untagged stays");
}

#[test]
fn clear_drops_all_packs_and_entries() {
    let mut m = InFlight::new();
    for i in 1u64..=5 {
        let p = pin(i);
        m.note_pins([(Fk(i), &p)], Some(i as u32));
    }
    assert_eq!(m.pack_count(), 5);
    assert_eq!(m.entry_count(), 5);
    m.clear();
    assert_eq!(m.pack_count(), 0);
    assert_eq!(m.entry_count(), 0);
    assert!(m.is_empty());
    let p = pin(99);
    m.note_pins([(Fk(99), &p)], Some(9));
    assert_eq!(m.pack_count(), 1);
    assert!(m.get_out(99).is_some());
    assert!(m.get_out(1).is_none());
}

/// BIP30 overwrite (91722 then 91880): prune of the older pack must not
/// drop the last-write fk from `creates`.
#[test]
fn prune_older_pack_keeps_newer_same_txid_last_write() {
    let mut m = InFlight::new();
    let mut txid = [0u8; 32];
    txid[0] = 0xe3;
    let old = pin_with_txid(txid);
    let new = pin_with_txid(txid);
    m.note_pins([(Fk(91722), &old)], Some(91722));
    m.note_pins([(Fk(91880), &new)], Some(91880));
    assert_eq!(m.get_create_fk(&txid), Some(Fk(91880)));
    m.prune_below_height(Some(91750));
    assert_eq!(
        m.get_create_fk(&txid),
        Some(Fk(91880)),
        "prune of 91722 must not drop last-write at 91880"
    );
    assert!(m.get_out(91880).is_some());
    assert!(m.get_out(91722).is_none());
}

/// Disconnect drops packs newest-first. Dropping the newer of two
/// same-txid packs must not leave `creates` pointing at the dropped
/// pack's fk, and the older pack's later prune must still clean up.
#[test]
fn drop_newer_same_txid_does_not_strand_creates() {
    let mut m = InFlight::new();
    let mut txid = [0u8; 32];
    txid[0] = 0xe3;
    let old = pin_with_txid(txid);
    let new = pin_with_txid(txid);
    m.note_pins([(Fk(1), &old)], Some(91722));
    m.note_pins([(Fk(2), &new)], Some(91880));
    m.drop_from_height(91880);
    assert_ne!(
        m.get_create_fk(&txid),
        Some(Fk(2)),
        "creates must not point at the dropped pack"
    );
    assert!(m.get_out(2).is_none());
    m.prune_below_height(Some(91723));
    assert_eq!(m.get_create_fk(&txid), None);
    assert!(m.is_empty(), "no leaked entries after both packs retire");
}

#[test]
fn prune_older_creates_only_keeps_newer_same_txid() {
    let mut m = InFlight::new();
    let mut txid = [0u8; 32];
    txid[0] = 0xe3;
    m.note_creates([(txid, Fk(1))], Some(91722));
    m.note_creates([(txid, Fk(2))], Some(91880));
    m.prune_below_height(Some(91750));
    assert_eq!(m.get_create_fk(&txid), Some(Fk(2)));
}

#[test]
fn same_txid_overwrite_does_not_double_count_creates_bytes() {
    let mut m = InFlight::new();
    let mut txid = [0u8; 32];
    txid[0] = 0xe3;
    m.note_creates([(txid, Fk(1))], Some(91722));
    let (_, _, once) = m.size_snapshot();
    m.note_creates([(txid, Fk(2))], Some(91880));
    let (_, _, twice) = m.size_snapshot();
    assert_eq!(
        twice, once,
        "creates map still holds one slot; iflight= must not grow on clobber"
    );
    m.prune_below_height(Some(91750));
    let (_, _, after) = m.size_snapshot();
    assert_eq!(after, once);
}

#[test]
fn min_out_id_follows_note_and_prune() {
    let mut m = InFlight::new();
    assert_eq!(m.min_out_id(), None);
    let low = pin(10);
    let high = pin(50);
    m.note_pins([(Fk(50), &high)], Some(3));
    assert_eq!(m.min_out_id(), Some(50));
    m.note_pins([(Fk(10), &low)], Some(1));
    assert_eq!(m.min_out_id(), Some(10));
    m.prune_below_height(Some(2));
    assert_eq!(m.min_out_id(), Some(50));
    assert!(m.get_out(10).is_none());
    m.drop_from_height(3);
    assert_eq!(m.min_out_id(), None);
    assert!(m.get_out(50).is_none());
}

#[test]
fn empty_note_is_noop() {
    let mut m = InFlight::new();
    m.note_pins(std::iter::empty(), Some(1));
    m.note_creates(std::iter::empty(), Some(1));
    assert!(m.is_empty());
    assert_eq!(m.pack_count(), 0);
}
