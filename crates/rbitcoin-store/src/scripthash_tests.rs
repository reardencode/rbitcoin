use super::*;
use crate::scripthash_layout::SH_HEAD_VALUE_LEN;
use crate::scripthash_pages::{
    sh_page_as_array, sh_page_extent, SH_PAGE_EXTENT_STREAM_MAX, SH_PAGE_SIZE, SH_PAGE_STREAM_MAX,
};
use std::sync::atomic::AtomicBool;

fn tmp() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rbitcoin-sh-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn four_shard_dir_table(dir: &std::path::Path) -> ScriptHashTable {
    let body_dir = dir.join("scripthash.body");
    std::fs::create_dir_all(&body_dir).unwrap();
    let payload0 = payload_start(FILE_HEADER_LEN);
    for i in 0..4 {
        let f =
            TableFile::create(body_dir.join(format!("{i:02x}")), TableKind::ScriptHash).unwrap();
        f.ensure_capacity(payload0).unwrap();
        f.set_logical_len(payload0).unwrap();
        write_alloc_header(
            &f,
            &AllocState {
                live_count: 0,
                bump: payload0,
                free_head: [0; SH_MAX_CLASS as usize + 1],
            },
        )
        .unwrap();
    }
    std::fs::create_dir_all(dir.join("scripthash.ovf")).unwrap();
    let ovf = TableFile::create(
        dir.join("scripthash.ovf").join("body"),
        TableKind::ScriptHash,
    )
    .unwrap();
    ovf.ensure_capacity(payload0).unwrap();
    ovf.set_logical_len(payload0).unwrap();
    write_alloc_header(
        &ovf,
        &AllocState {
            live_count: 0,
            bump: payload0,
            free_head: [0; SH_MAX_CLASS as usize + 1],
        },
    )
    .unwrap();
    drop(ovf);
    ScriptHashTable::open(dir).unwrap()
}

fn sh_prefix_key(shard: u8, i: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = shard << 6 | (i & 0x3f);
    k
}

#[test]
fn sh_body_create_grows_64k_not_slab() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = ScriptHashTable::create(&dir).unwrap();
        let sh = script_hash(&[0x01]);
        t.put_create(&rec(sh, 1, 0)).unwrap();
        t.put_create(&rec(sh, 2, 0)).unwrap();
        t.flush().unwrap();
        drop(t);
        for e in std::fs::read_dir(dir.join("scripthash.body")).unwrap() {
            let p = e.unwrap().path();
            if !p.is_file() {
                continue;
            }
            let on_disk = std::fs::metadata(&p).unwrap().len();
            assert!(
                on_disk < 128 * 1024,
                "{} len {on_disk} must stay under 128 KiB after one slab",
                p.display()
            );
        }
        let ovf_len = std::fs::metadata(dir.join("scripthash.ovf").join("body"))
            .unwrap()
            .len();
        assert!(
            ovf_len < 128 * 1024,
            "ovf body {ovf_len} must stay under 128 KiB"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn sh_bodies_are_split() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_dir_table(&dir);
        assert_eq!(t.head_shard_count(), 4);
        assert_eq!(t.body_layout(), ShBodyLayout::Sharded);
        let k0 = sh_prefix_key(0, 0);
        let k2 = sh_prefix_key(2, 0);
        let ents: Vec<Fk> = (1..=8).map(|i| Fk(i)).collect();
        {
            let mut s = t.bulk_session(16).unwrap();
            s.put_chain(k0, &ents).unwrap();
            s.put_chain(k2, &ents).unwrap();
            s.finish().unwrap();
        }
        let payload0 = payload_start(FILE_HEADER_LEN);
        assert!(
            t.bodies[0].logical_len() > payload0,
            "shard 0 body must grow"
        );
        assert_eq!(
            t.bodies[1].logical_len(),
            payload0,
            "shard 1 body stays empty"
        );
        assert!(
            t.bodies[2].logical_len() > payload0,
            "shard 2 body must grow"
        );
        assert_eq!(t.bodies[3].logical_len(), payload0);
        let k_new = sh_prefix_key(1, 0);
        for i in 1..=8u64 {
            t.put_create(&rec(k_new, i, 0)).unwrap();
        }
        let ovf_len = t.ovf_body.as_ref().unwrap().logical_len();
        assert!(ovf_len > payload0, "ovf ingest slab must land in ovf/body");
        assert_eq!(
            t.bodies[1].logical_len(),
            payload0,
            "ingest must not grow a main shard body"
        );
        assert_eq!(t.entries(&k0).unwrap().len(), 8);
        assert_eq!(t.entries(&k2).unwrap().len(), 8);
        assert_eq!(t.entries(&k_new).unwrap().len(), 8);

        let file_dir = tmp();
        let ft = shared_body_table(&file_dir);
        assert_eq!(ft.body_layout(), ShBodyLayout::Shared);
        {
            let mut s = ft.bulk_session(16).unwrap();
            s.put_chain(k0, &ents).unwrap();
            s.put_chain(k2, &ents).unwrap();
            s.finish().unwrap();
        }
        for i in 1..=8u64 {
            ft.put_create(&rec(k_new, i, 0)).unwrap();
        }
        assert!(ft.bodies[0].logical_len() > payload0);
        assert!(ft.ovf_body.is_none());
        assert_eq!(ft.entries(&k0).unwrap().len(), 8);
        assert_eq!(ft.entries(&k_new).unwrap().len(), 8);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&file_dir);
    });
}

#[test]
fn sh_body_orientation() {
    let file_dir = tmp();
    TableFile::create(file_dir.join("scripthash.body"), TableKind::ScriptHash).unwrap();
    assert_eq!(
        detect_sh_body_layout(&file_dir).unwrap(),
        ShBodyLayout::Shared
    );

    let dir_dir = tmp();
    std::fs::create_dir_all(dir_dir.join("scripthash.body")).unwrap();
    TableFile::create(
        dir_dir.join("scripthash.body").join("00"),
        TableKind::ScriptHash,
    )
    .unwrap();
    std::fs::create_dir_all(dir_dir.join("scripthash.ovf")).unwrap();
    TableFile::create(
        dir_dir.join("scripthash.ovf").join("body"),
        TableKind::ScriptHash,
    )
    .unwrap();
    assert_eq!(
        detect_sh_body_layout(&dir_dir).unwrap(),
        ShBodyLayout::Sharded
    );

    let mixed = tmp();
    TableFile::create(mixed.join("scripthash.body"), TableKind::ScriptHash).unwrap();
    std::fs::create_dir_all(mixed.join("scripthash.ovf")).unwrap();
    TableFile::create(
        mixed.join("scripthash.ovf").join("body"),
        TableKind::ScriptHash,
    )
    .unwrap();
    match detect_sh_body_layout(&mixed) {
        Err(StoreError::Layout(m)) => {
            assert!(m.contains("scripthash*"), "{m}");
            assert!(m.contains("wipe"), "{m}");
        }
        other => panic!("expected Layout, got {other:?}"),
    }

    let no_ovf = tmp();
    std::fs::create_dir_all(no_ovf.join("scripthash.body")).unwrap();
    match detect_sh_body_layout(&no_ovf) {
        Err(StoreError::Layout(m)) => {
            assert!(m.contains("scripthash*"), "{m}");
        }
        other => panic!("expected Layout, got {other:?}"),
    }
    let created = tmp();
    let _t = ScriptHashTable::create(&created).unwrap();
    assert_eq!(
        detect_sh_body_layout(&created).unwrap(),
        ShBodyLayout::Sharded
    );
    assert!(created.join("scripthash.body").is_dir());
    assert!(created.join("scripthash.body").join("00").is_file());
    assert!(created.join("scripthash.ovf").join("body").is_file());
    let _ = std::fs::remove_dir_all(&file_dir);
    let _ = std::fs::remove_dir_all(&dir_dir);
    let _ = std::fs::remove_dir_all(&mixed);
    let _ = std::fs::remove_dir_all(&no_ovf);
    let _ = std::fs::remove_dir_all(&created);
}

fn rec(sh: [u8; 32], tx: u64, _vout: u32) -> ScriptHashRecord {
    ScriptHashRecord::from_fk(sh, Fk(tx))
}

fn put_unique(t: &ScriptHashTable, tag: u8, n: u32) {
    for i in 0..n {
        let sh = script_hash(&[tag, (i & 0xff) as u8, (i >> 8) as u8, 0x7e]);
        t.put_create(&rec(sh, u64::from(i) + 1, 0)).unwrap();
    }
}

#[test]
fn script_hash_record_helpers_and_table_flush_open() {
    let e = Fk(9);
    let r = ScriptHashRecord::from_fk([1u8; 32], e);
    assert_eq!(r.create_tx_fk, e);
    assert!(!r.is_tombstone());
    let tomb = ScriptHashRecord::from_fk([2u8; 32], Fk::NULL);
    assert!(tomb.is_tombstone());
    let _ = script_hash(&[0x00, 0x14]);

    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x99]);
    t.put_create(&rec(sh, 1, 0)).unwrap();
    let _ = t.put_create_batch(&[]);
    assert_eq!(t.entry_count(), 1);
    t.flush().unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = ScriptHashTable::open(&dir).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    // for_each_live across table
    let mut n = 0u32;
    t.for_each_live_create(|_fk| {
        n += 1;
    })
    .unwrap();
    assert_eq!(n, 1);
    // missing key
    assert!(t.entries(&[0u8; 32]).unwrap().is_empty());
    assert!(t.head_value(&[0u8; 32]).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_thin_roundtrip() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    t.put_create(&rec(sh, 3, 0)).unwrap();
    let entries = t.entries(&sh).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1.create_tx_fk, Fk(3));
    t.put_create(&rec(sh, 3, 0)).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    t.put_create(&rec(sh, 4, 1)).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 2);
    assert!(t.unlink_create(&sh, Fk(4), 1).unwrap());
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    assert!(t.unlink_create(&sh, Fk(3), 0).unwrap());
    assert!(t.entries(&sh).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn incremental_absent_lands_on_ingest() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    t.put_create(&rec(sh, 3, 0)).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    assert!(
        t.ingest.lock().unwrap().get(&sh).unwrap().is_some(),
        "new key must live on ingest, not live OA main"
    );
    assert!(
        !dir.join("scripthash.head").exists(),
        "create must not plant a live OA at scripthash.head"
    );
    t.flush().unwrap();
    drop(t);
    let t = ScriptHashTable::open(&dir).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    assert!(!dir.join("scripthash.head").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_uses_slabs_then_pages() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x15]);
    for i in 1..=5u64 {
        t.put_create(&rec(sh, i, 0)).unwrap();
    }
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, off } => {
            assert_eq!(class, 1, "5 fks with slack → class 1 (64 B, cap 8)");
            assert_eq!(used, 5);
            assert!(off >= 4096);
        }
        other => panic!("expected class-1 slab, got {other:?}"),
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 5);
    for i in 6..=9u64 {
        t.put_create(&rec(sh, i, 0)).unwrap();
    }
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, .. } => {
            assert_eq!(class, 2, "9th fk grows class 1 → 2");
            assert_eq!(used, 9);
        }
        other => panic!("expected class-2 slab, got {other:?}"),
    }
    assert_eq!(
        t.put_create_batch(&[rec(sh, 9, 0), rec(sh, 5, 0)]).unwrap(),
        0,
        "fk ≤ max is a skip"
    );
    let rest: Vec<_> = (10..=257u64).map(|i| rec(sh, i, 0)).collect();
    assert_eq!(t.put_create_batch(&rest).unwrap(), 248);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            assert!(last_page > 0);
        }
        other => panic!("expected page chain at 257, got {other:?}"),
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 257);
    assert!(t.contains_create(&sh, Fk(257)).unwrap());
    assert!(!t.contains_create(&sh, Fk(258)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn promote_ladder_inline_to_paged() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x52]);
    for i in 1..=5u64 {
        t.put_create(&rec(sh, i, i as u32)).unwrap();
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 5);
    let v = t.head_value(&sh).unwrap().unwrap();
    match v {
        ShHeadValue::Slab { class, used, off } => {
            assert_eq!(class, 1);
            assert_eq!(used, 5);
            assert!(off > 0);
        }
        other => panic!("expected slab, got {other:?}"),
    }
    assert_eq!(t.entry_count(), 5);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_batch_many_uses_pages() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x53]);
    let recs: Vec<_> = (0..100u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let n = t.put_create_batch(&recs).unwrap();
    assert_eq!(n, 100);
    let v = t.head_value(&sh).unwrap().unwrap();
    match v {
        ShHeadValue::Slab { class, used, off } => {
            assert_eq!(class, 5, "100 fks → class 5 (cap 128)");
            assert_eq!(used, 100);
            assert!(off > 0);
        }
        other => panic!("expected slab, got {other:?}"),
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 100);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_batch_chains() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    let recs: Vec<_> = (0..3u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let n = t.put_create_batch(&recs).unwrap();
    assert_eq!(n, 3);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    let n2 = t.put_create_batch(&recs).unwrap();
    assert_eq!(n2, 0);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Re-queued lower/equal FKs are skipped; only higher append. Multi-page max
/// from last page only (sorted chain).
#[test]
fn put_create_batch_skips_leq_max_appends_higher() {
    use crate::scripthash_pages::SH_PAGE_STREAM_MAX;
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0xab]);
    // Fill past one delta page so last page holds the max.
    let n = SH_PAGE_STREAM_MAX + 5;
    let first: Vec<_> = (1..=n as u64).map(|i| rec(sh, i, 0)).collect();
    assert_eq!(t.put_create_batch(&first).unwrap(), n);
    assert_eq!(t.entries(&sh).unwrap().len(), n);
    let max = t
        .last_create_fk_for_key(&sh, &t.head_value(&sh).unwrap().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(max, Fk(n as u64));

    // Mix re-queued older FKs with new higher ones.
    let batch = vec![
        rec(sh, 1, 0),
        rec(sh, n as u64 / 2, 0),
        rec(sh, n as u64, 0),
        rec(sh, n as u64 + 1, 0),
        rec(sh, n as u64 + 3, 0),
        rec(sh, n as u64 + 2, 0), // unsorted in batch
    ];
    let written = t.put_create_batch(&batch).unwrap();
    assert_eq!(written, 3, "only fks > max must be written");
    let got = t.entries(&sh).unwrap();
    assert_eq!(got.len(), n + 3);
    for (i, (_, e)) in got.iter().enumerate() {
        assert_eq!(e.create_tx_fk.0, (i as u64) + 1);
    }
    // Only-lower batch is no-op.
    assert_eq!(
        t.put_create_batch(&[rec(sh, 1, 0), rec(sh, 2, 0)]).unwrap(),
        0
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_batch_append_uses_heads() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    let mut heads = HashMap::new();
    let recs: Vec<_> = (0..3u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let (n, _t) = t.put_create_batch_append(&recs, &mut heads).unwrap();
    assert_eq!(n, 3);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    assert!(heads.get(&sh).is_some());
    let more = vec![rec(sh, 10, 9)];
    let (n2, _) = t.put_create_batch_append(&more, &mut heads).unwrap();
    assert_eq!(n2, 1);
    assert_eq!(t.entries(&sh).unwrap().len(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sh_heads_insert_capped_caps_and_keeps_latest() {
    let mut heads = HashMap::new();
    let cap = 8usize;
    for i in 0u8..20 {
        sh_heads_insert_capped(&mut heads, [i; 32], ShHeadValue::Empty, cap);
        assert!(heads.len() <= cap, "len={}", heads.len());
    }
    let last = [0xff; 32];
    sh_heads_insert_capped(&mut heads, last, ShHeadValue::Empty, cap);
    assert!(heads.len() <= cap);
    assert!(heads.contains_key(&last), "latest insert must stay");
}

fn dummy_sh_head_key(i: u64) -> [u8; 32] {
    let mut k = [0xEE; 32];
    k[..8].copy_from_slice(&i.to_le_bytes());
    k
}

#[test]
fn put_create_batch_append_caps_heads_and_miss_still_writes() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut heads = HashMap::new();
    for i in 0..SH_HEADS_CAP as u64 {
        heads.insert(dummy_sh_head_key(i), ShHeadValue::Empty);
    }
    assert_eq!(heads.len(), SH_HEADS_CAP);
    let sh = script_hash(&[0x51]);
    let (n, _) = t
        .put_create_batch_append(&[rec(sh, 1, 0)], &mut heads)
        .unwrap();
    assert_eq!(n, 1);
    assert!(
        heads.len() <= SH_HEADS_CAP,
        "process heads must cap, got {}",
        heads.len()
    );
    assert_eq!(t.entries(&sh).unwrap().len(), 1);

    let evicted = (0..SH_HEADS_CAP as u64).find_map(|i| {
        let k = dummy_sh_head_key(i);
        (!heads.contains_key(&k)).then_some(k)
    });
    if let Some(evicted) = evicted {
        let (n2, _) = t
            .put_create_batch_append(&[rec(evicted, 2, 0)], &mut heads)
            .unwrap();
        assert_eq!(n2, 1);
        assert_eq!(t.entries(&evicted).unwrap().len(), 1);
        assert!(heads.len() <= SH_HEADS_CAP);
    } else {
        heads.remove(&sh);
        let (n2, _) = t
            .put_create_batch_append(&[rec(sh, 3, 0)], &mut heads)
            .unwrap();
        assert_eq!(n2, 1);
        assert_eq!(t.entries(&sh).unwrap().len(), 2);
        assert!(heads.len() <= SH_HEADS_CAP);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn page_append_preserves_prefix_and_order() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x7a]);
    let mut heads = HashMap::new();
    let first: Vec<_> = (1..=5u32).map(|v| rec(sh, u64::from(v), v)).collect();
    let (n, _) = t.put_create_batch_append(&first, &mut heads).unwrap();
    assert_eq!(n, 5);
    let first_off = match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, off } => {
            assert_eq!(class, 1);
            assert_eq!(used, 5);
            off
        }
        other => panic!("expected slab, got {other:?}"),
    };
    let more: Vec<_> = (6..=7u32).map(|v| rec(sh, u64::from(v), v)).collect();
    let (n2, _) = t.put_create_batch_append(&more, &mut heads).unwrap();
    assert_eq!(n2, 2);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, off } => {
            assert_eq!(off, first_off, "in-class append must reuse slab off");
            assert_eq!(class, 1);
            assert_eq!(used, 7);
        }
        other => panic!("expected slab, got {other:?}"),
    }
    let ents = t.entries(&sh).unwrap();
    assert_eq!(ents.len(), 7);
    for (i, (_, e)) in ents.iter().enumerate() {
        assert_eq!(e.create_tx_fk, Fk(i as u64 + 1));
    }
    // Grow to megakey pages (≥257 FKs).
    let mut heads2 = HashMap::new();
    let sh2 = script_hash(&[0x7b]);
    let many: Vec<_> = (1..=600u32).map(|v| rec(sh2, u64::from(v), v)).collect();
    let (nm, _) = t.put_create_batch_append(&many, &mut heads2).unwrap();
    assert_eq!(nm, 600);
    match t.head_value(&sh2).unwrap().unwrap() {
        ShHeadValue::Extent { .. } => {}
        other => panic!("expected extent megakey, got {other:?}"),
    }
    assert_eq!(t.entries(&sh2).unwrap().len(), 600);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlink_demotes_paged_to_inline() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x54]);
    for i in 1..=3u64 {
        t.put_create(&rec(sh, i, i as u32)).unwrap();
    }
    assert!(matches!(
        t.head_value(&sh).unwrap().unwrap(),
        ShHeadValue::Slab { .. }
    ));
    t.unlink_create(&sh, Fk(2), 2).unwrap();
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { used, .. } => assert_eq!(used, 2),
        other => panic!("expected 2-fk slab, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingest_oa_slots_mainnet_is_2_25() {
    HeadScale::test_with(HeadScale::Mainnet, || {
        assert_eq!(ingest_oa_slots(), 1 << 25);
        assert_eq!(SH_HEAD_VALUE_LEN, 8);
        assert_eq!(crate::scripthash_layout::SH_HEAD_SLOT_SIZE, 24);
    });
}

#[test]
fn create_does_not_write_oa_stub() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    assert_eq!(t.head_shard_count(), crate::hashhead::sh_main_shard_count());
    drop(t);
    assert!(
        !dir.join("scripthash.head.oa_stub").exists(),
        "create must not write leftover sharded OA stub"
    );
    std::fs::create_dir_all(dir.join("scripthash.head.oa_stub")).unwrap();
    let t = ScriptHashTable::open(&dir).unwrap();
    assert!(
        !dir.join("scripthash.head.oa_stub").exists(),
        "open must unlink leftover oa_stub"
    );
    assert_eq!(t.head_shard_count(), crate::hashhead::sh_main_shard_count());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn leftover_live_oa_main_open_refuses() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    t.put_create(&rec(script_hash(&[0x01]), 1, 0)).unwrap();
    t.flush().unwrap();
    drop(t);
    ShardedScriptHashHead::create_sharded(dir.join("scripthash.head"), 1, 64).unwrap();
    match ScriptHashTable::open(&dir) {
        Ok(_) => panic!("leftover OA main must refuse"),
        Err(StoreError::Layout(m)) => {
            assert!(m.contains("scripthash*"), "{m}");
            assert!(m.contains("wipe") || m.contains("rematerialize"), "{m}");
        }
        Err(e) => panic!("expected Layout, got {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn leftover_oa_overflow_seg_open_refuses() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    t.put_create(&rec(script_hash(&[0x02]), 1, 0)).unwrap();
    t.flush().unwrap();
    drop(t);
    let ovf = dir.join("scripthash.ovf");
    std::fs::create_dir_all(&ovf).unwrap();
    std::fs::write(ovf.join("000000"), b"not-shsr").unwrap();
    match ScriptHashTable::open(&dir) {
        Ok(_) => panic!("leftover OA ovf must refuse"),
        Err(StoreError::Layout(m)) => {
            assert!(m.contains("scripthash*"), "{m}");
        }
        Err(e) => panic!("expected Layout, got {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingest_batch_update_and_new_keys() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh0 = script_hash(&[0xc0, 0, 0, 0x11]);
    t.put_create(&rec(sh0, 1, 0)).unwrap();
    let mut batch = vec![rec(sh0, 99_999, 1)];
    for i in 0..20u32 {
        let sh = script_hash(&[0xc1, (i & 0xff) as u8, 0x22, 0x33]);
        batch.push(rec(sh, 10_000 + u64::from(i), 0));
    }
    assert_eq!(t.put_create_batch(&batch).unwrap(), 21);
    assert_eq!(t.entries(&sh0).unwrap().len(), 2);
    assert!(t.ingest.lock().unwrap().get(&sh0).unwrap().is_some());
    let mut n = 0u64;
    t.for_each_live_create(|_| n += 1).unwrap();
    assert_eq!(n, 22);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingest_many_unique_keys_reopen() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    put_unique(&t, 0xa0, 80);
    let sh0 = script_hash(&[0xa0, 0, 0, 0x7e]);
    t.put_create(&rec(sh0, 10_000, 1)).unwrap();
    assert_eq!(t.entries(&sh0).unwrap().len(), 2);
    t.flush().unwrap();
    drop(t);
    let t = ScriptHashTable::open(&dir).unwrap();
    assert_eq!(t.entries(&sh0).unwrap().len(), 2);
    assert!(!dir.join("scripthash.head").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Empty SHAL v1 (schema-13 body) opens and is rewritten to alloc v2.
#[test]
fn open_empty_alloc_v1_upgrades_to_v2() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create(&dir).unwrap();
        assert!(!t.has_durable_index());
        t.flush().unwrap();
    }
    // Downgrade only the version field (layout is identical).
    let body_path = dir.join("scripthash.body").join("00");
    let body = TableFile::open(&body_path, TableKind::ScriptHash).unwrap();
    let (state, ver) = read_alloc_header(&body).unwrap();
    assert_eq!(ver, SH_ALLOC_VERSION);
    // Write v1 stamp with same empty state.
    let mut buf = vec![0u8; SH_ALLOC_HEADER_LEN];
    buf[0..4].copy_from_slice(&SH_ALLOC_MAGIC);
    buf[4..6].copy_from_slice(&1u16.to_le_bytes());
    buf[8..16].copy_from_slice(&state.live_count.to_le_bytes());
    buf[16..24].copy_from_slice(&state.bump.to_le_bytes());
    body.write_at(FILE_HEADER_LEN as u64, &buf).unwrap();
    body.flush().unwrap();
    drop(body);
    assert_eq!(
        read_alloc_version_on_disk(&TableFile::open(&body_path, TableKind::ScriptHash).unwrap())
            .unwrap(),
        1
    );

    let t = ScriptHashTable::open(&dir).unwrap();
    assert!(!t.has_durable_index());
    drop(t);
    assert_eq!(
        read_alloc_version_on_disk(&TableFile::open(&body_path, TableKind::ScriptHash).unwrap())
            .unwrap(),
        SH_ALLOC_VERSION,
        "empty v1 must be rewritten to current alloc version"
    );
    // Reopen stays v2.
    let t = ScriptHashTable::open(&dir).unwrap();
    t.put_create(&rec(script_hash(&[0x42]), 1, 0)).unwrap();
    assert_eq!(t.entries(&script_hash(&[0x42])).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Durable SH with alloc v1 is refused (slab body incompatible with page chains).
#[test]
fn open_durable_alloc_v1_refused() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create(&dir).unwrap();
        t.put_create(&rec(script_hash(&[0x99]), 7, 0)).unwrap();
        assert!(t.has_durable_index());
        t.flush().unwrap();
    }
    let body_path = dir.join("scripthash.body").join("00");
    let body = TableFile::open(&body_path, TableKind::ScriptHash).unwrap();
    let (state, _) = read_alloc_header(&body).unwrap();
    let mut buf = vec![0u8; SH_ALLOC_HEADER_LEN];
    buf[0..4].copy_from_slice(&SH_ALLOC_MAGIC);
    buf[4..6].copy_from_slice(&1u16.to_le_bytes());
    buf[8..16].copy_from_slice(&state.live_count.to_le_bytes());
    buf[16..24].copy_from_slice(&state.bump.to_le_bytes());
    let mut off = 24usize;
    for h in &state.free_head {
        buf[off..off + 8].copy_from_slice(&h.to_le_bytes());
        off += 8;
    }
    body.write_at(FILE_HEADER_LEN as u64, &buf).unwrap();
    body.flush().unwrap();
    drop(body);

    match ScriptHashTable::open(&dir) {
        Ok(_) => panic!("expected refuse for durable alloc v1"),
        Err(StoreError::Corrupt(m)) => {
            assert!(
                m.contains("alloc v1") || m.contains("slab") || m.contains("rematerialize"),
                "{m}"
            );
        }
        Err(e) => panic!("expected Corrupt, got {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Legacy full-size ovf.head is wiped on open; table remains usable.
#[test]
fn open_wipes_legacy_fullsize_ovf_head() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create(&dir).unwrap();
        t.put_create(&rec(script_hash(&[0x01]), 1, 0)).unwrap();
        t.flush().unwrap();
    }
    std::fs::write(
        dir.join(crate::scripthash_overflow::LEGACY_OVERFLOW_HEAD),
        b"x",
    )
    .unwrap();
    std::fs::write(
        dir.join(crate::scripthash_overflow::LEGACY_OVERFLOW_FUSE),
        b"SHFUSE01",
    )
    .unwrap();
    let t = ScriptHashTable::open(&dir).unwrap();
    assert!(!dir
        .join(crate::scripthash_overflow::LEGACY_OVERFLOW_HEAD)
        .exists());
    assert_eq!(t.entries(&script_hash(&[0x01])).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn freelist_reuses_page() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh1 = script_hash(&[0x61]);
    let sh2 = script_hash(&[0x62]);
    for i in 1..=3u64 {
        t.put_create(&rec(sh1, i, i as u32)).unwrap();
    }
    let off1 = match t.head_value(&sh1).unwrap().unwrap() {
        ShHeadValue::Slab { off, class, .. } => {
            assert_eq!(class, 0);
            off
        }
        other => panic!("expected slab, got {other:?}"),
    };
    for i in 1..=3u64 {
        t.unlink_create(&sh1, Fk(i), i as u32).unwrap();
    }
    for i in 1..=3u64 {
        t.put_create(&rec(sh2, 10 + i, i as u32)).unwrap();
    }
    let off2 = match t.head_value(&sh2).unwrap().unwrap() {
        ShHeadValue::Slab { off, class, .. } => {
            assert_eq!(class, 0);
            off
        }
        other => panic!("expected slab, got {other:?}"),
    };
    assert_eq!(off1, off2, "slab freelist should reuse offset");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cold_install_sorted_main_and_global_ingest() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh_main = script_hash(&[0x10]);
    let sh_new = script_hash(&[0x99]);
    let mut session = t.bulk_session(16).unwrap();
    session.put_chain(sh_main, &[Fk(1), Fk(2)]).unwrap();
    session.finish().unwrap();
    assert!(
        t.has_sorted_main(),
        "bulk must emit a sealed sorted main shard"
    );
    let head_p = dir.join("scripthash.head");
    let shard_p = if head_p.is_dir() {
        head_p.join("00")
    } else {
        head_p
    };
    assert!(
        MphfHead::exists(&shard_p),
        "bulk must emit mphf+val for shard 00"
    );
    let mut idx = shard_p.as_os_str().to_os_string();
    idx.push(".idx");
    let mut fuse = shard_p.as_os_str().to_os_string();
    fuse.push(".fuse8");
    assert!(!PathBuf::from(idx).is_file());
    assert!(
        !PathBuf::from(fuse).is_file(),
        "main shards must not write a fuse"
    );

    t.put_create(&rec(sh_main, 3, 0)).unwrap();
    assert_eq!(t.entries(&sh_main).unwrap().len(), 3);
    assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));

    t.put_create(&rec(sh_new, 10, 0)).unwrap();
    assert_eq!(t.entries(&sh_new).unwrap().len(), 1);
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    // First create of a never-seen key must still miss on main (prove Absent).
    // Later hits live on ingest and must not touch the main page.
    t.reset_sorted_main_preads();
    t.put_create(&rec(sh_new, 11, 0)).unwrap();
    assert_eq!(t.entries(&sh_new).unwrap().len(), 2);
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    assert_eq!(
        t.sorted_main_pread_count(t.shard_index(&sh_new)),
        0,
        "key already on ingest must not pread the main page"
    );
    t.flush().unwrap();
    drop(t);
    let t = ScriptHashTable::open(&dir).unwrap();
    assert_eq!(t.entries(&sh_main).unwrap().len(), 3);
    assert_eq!(t.entries(&sh_new).unwrap().len(), 2);
    assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reopen_after_ingest_seal_and_unlink_homes() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = ScriptHashTable::create(&dir).unwrap();
        let sh_main = script_hash(&[0x10]);
        let mut session = t.bulk_session(8).unwrap();
        session.put_chain(sh_main, &[Fk(1)]).unwrap();
        session.finish().unwrap();

        let mut first_new = [0u8; 32];
        for i in 0..210u32 {
            let sh = script_hash(&[0xa1, (i & 0xff) as u8, (i >> 8) as u8, 0x01]);
            if i == 0 {
                first_new = sh;
            }
            t.put_create(&rec(sh, 1000 + u64::from(i), 0)).unwrap();
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1);
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));

        t.unlink_create(&sh_main, Fk(1), 0).unwrap();
        assert!(t.entries(&sh_main).unwrap().is_empty());
        t.unlink_create(&first_new, Fk(1000), 0).unwrap();
        assert!(t.entries(&first_new).unwrap().is_empty());

        t.flush().unwrap();
        drop(t);
        let t = ScriptHashTable::open(&dir).unwrap();
        assert!(t.entries(&sh_main).unwrap().is_empty());
        assert!(t.entries(&first_new).unwrap().is_empty());
        assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn compact_merges_two_sealed_global_ovf_files() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = ScriptHashTable::create(&dir).unwrap();
        let sh_main = script_hash(&[0x10]);
        let mut session = t.bulk_session(8).unwrap();
        session.put_chain(sh_main, &[Fk(1)]).unwrap();
        session.finish().unwrap();

        let mut first_new = [0u8; 32];
        let mut second_new = [0u8; 32];
        for i in 0..210u32 {
            let sh = script_hash(&[0xa1, (i & 0xff) as u8, (i >> 8) as u8, 0x01]);
            if i == 0 {
                first_new = sh;
            }
            t.put_create(&rec(sh, 1000 + u64::from(i), 0)).unwrap();
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1, "first ingest seal");
        for i in 0..210u32 {
            let sh = script_hash(&[0xa2, (i & 0xff) as u8, (i >> 8) as u8, 0x02]);
            if i == 0 {
                second_new = sh;
            }
            t.put_create(&rec(sh, 2000 + u64::from(i), 0)).unwrap();
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 2, "second ingest seal");

        t.compact_sealed_ovf().unwrap();
        assert_eq!(
            t.sealed_ovf.lock().unwrap().len(),
            0,
            "L0 unlinked after promote"
        );
        assert!(
            t.ovf_l1.lock().unwrap().is_some(),
            "compact promotes L1 MPHF"
        );
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);
        assert_eq!(t.entries(&second_new).unwrap().len(), 1);
        assert_eq!(t.entries(&sh_main).unwrap().len(), 1);
        assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));

        t.compact_sealed_ovf().unwrap();
        assert!(t.ovf_l1.lock().unwrap().is_some());
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 0);
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);

        for i in 0..210u32 {
            let sh = script_hash(&[0xa3, (i & 0xff) as u8, (i >> 8) as u8, 0x03]);
            t.put_create(&rec(sh, 3000 + u64::from(i), 0)).unwrap();
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1);
        t.compact_sealed_ovf().unwrap();
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1, "L1 frozen: L0 stays");
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn bulk_session_packs_exact_class_from_count() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut session = t.bulk_session(16).unwrap();
    let cases: &[(u8, u32)] = &[(0x01, 1), (0x02, 2), (0x06, 6), (0x14, 20), (0x60, 600)];
    for &(tag, n) in cases {
        let mut sh = [0u8; 32];
        sh[0] = tag;
        let ents: Vec<_> = (1..=u64::from(n)).map(|i| Fk(i)).collect();
        session.put_chain(sh, &ents).unwrap();
    }
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 5);
    assert_eq!(creates, 1 + 2 + 6 + 20 + 600);

    let sh = |tag: u8| {
        let mut k = [0u8; 32];
        k[0] = tag;
        k
    };
    assert!(matches!(
        t.head_value(&sh(0x01)).unwrap().unwrap(),
        ShHeadValue::Inline { used: 1, .. }
    ));
    assert!(matches!(
        t.head_value(&sh(0x02)).unwrap().unwrap(),
        ShHeadValue::Slab { used: 2, .. }
    ));
    match t.head_value(&sh(0x06)).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, .. } => {
            assert_eq!(class, 0, "6 tight deltas fit class 0 (16 B)");
            assert_eq!(used, 6);
        }
        other => panic!("expected class-0 slab, got {other:?}"),
    }
    match t.head_value(&sh(0x14)).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, .. } => {
            assert_eq!(class, 1, "20 tight deltas fit class 1 (32 B)");
            assert_eq!(used, 20);
        }
        other => panic!("expected class-0 slab, got {other:?}"),
    }
    match t.head_value(&sh(0x60)).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, .. } => {
            assert_eq!(used, 600);
            assert!(
                class <= 6,
                "600 1-byte deltas stay in a relocating slab, class={class}"
            );
        }
        other => panic!("expected slab for 600 tight deltas, got {other:?}"),
    }
    assert_eq!(t.entries(&sh(0x06)).unwrap().len(), 6);
    assert_eq!(t.entries(&sh(0x60)).unwrap().len(), 600);

    let payload = t.body().logical_len().saturating_sub(4096);
    let tight = 32 + 32 + 1024;
    assert!(
        payload <= 2 * tight,
        "cold body {payload} must stay within 2× packed {tight}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_put_chain_roundtrip() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut session = t.bulk_session(100).unwrap();
    // Many distinct keys, mix of inline and slab.
    for i in 0..50u32 {
        let mut sh = [0u8; 32];
        sh[0] = i as u8;
        sh[1] = 0xab;
        let n = if i % 5 == 0 { 8 } else { 1 + (i % 2) };
        let ents: Vec<_> = (0..n)
            .map(|j| Fk(u64::from(i) * 100 + u64::from(j) + 1))
            .collect();
        session.put_chain(sh, &ents).unwrap();
    }
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 50);
    assert_eq!(creates, t.entry_count());
    assert!(creates > 50);
    // Spot-check a slab key (i=0 → 8 creates).
    let mut sh0 = [0u8; 32];
    sh0[1] = 0xab;
    assert_eq!(t.entries(&sh0).unwrap().len(), 8);
    // Spot-check inline.
    let mut sh1 = [0u8; 32];
    sh1[0] = 1;
    sh1[1] = 0xab;
    assert_eq!(t.entries(&sh1).unwrap().len(), 2);
    t.flush().unwrap();
    let t2 = ScriptHashTable::open(&dir).unwrap();
    assert_eq!(t2.entry_count(), creates);
    assert_eq!(t2.entries(&sh0).unwrap().len(), 8);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_stream_megakey_caps_buf_at_page() {
    use crate::scripthash_pages::SH_PAGE_STREAM_MAX;
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + 10;
    let mut sh = [0u8; 32];
    sh[0] = 0x42;
    let mut session = t.bulk_session(1).unwrap();
    let mut peak = 0usize;
    for i in 1..=n as u64 {
        session.push_sorted_fk(sh, Fk(i)).unwrap();
        peak = peak.max(session.buffered_fks());
        assert!(
            session.buffered_fks() <= SH_PAGE_STREAM_MAX,
            "buf={} after fk={i}",
            session.buffered_fks()
        );
    }
    session.finish_key().unwrap();
    assert!(peak <= SH_PAGE_STREAM_MAX, "peak buf={peak}");
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 1);
    assert_eq!(creates, n as u64);
    assert_eq!(t.entries(&sh).unwrap().len(), n);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let w = u64::from_le_bytes(pack8_bytes(&ShHeadValue::extent(last_page)).unwrap());
            assert_eq!(w >> 62, 3);
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            let (base, n) = sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .expect("ver=2 last page");
            assert_eq!(n, 2);
            assert_eq!(last_page, base + SH_PAGE_SIZE as u64);
        }
        other => panic!("expected extent, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remap_sh_body() {
    use crate::scripthash_pages::SH_PAGE_STREAM_MAX;
    let src_dir = tmp();
    let dst_dir = tmp();
    let src = ScriptHashTable::create(&src_dir).unwrap();
    let mut slab_key = [0u8; 32];
    slab_key[0] = 0x11;
    let mut mega_key = [0u8; 32];
    mega_key[0] = 0x22;
    let n_mega = SH_PAGE_STREAM_MAX + 10;
    let mut session = src.bulk_session(2).unwrap();
    for i in 1..=8u64 {
        session.push_sorted_fk(slab_key, Fk(i)).unwrap();
    }
    session.finish_key().unwrap();
    for i in 1..=n_mega as u64 {
        session.push_sorted_fk(mega_key, Fk(i)).unwrap();
    }
    session.finish_key().unwrap();
    let _ = session.finish().unwrap();
    let slab_val = src.head_value(&slab_key).unwrap().unwrap();
    let mega_val = src.head_value(&mega_key).unwrap().unwrap();
    assert!(matches!(slab_val, ShHeadValue::Slab { .. }));
    assert!(matches!(mega_val, ShHeadValue::Extent { .. }));
    let src_lo = payload_start(FILE_HEADER_LEN);
    let src_hi = src.alloc_bump();
    let delta = 3 * SH_PAGE_SIZE as u64;
    let dst = ScriptHashTable::create(&dst_dir).unwrap();
    copy_sh_body_range(src.body(), src_lo, src_hi, dst.body(), src_lo + delta).unwrap();
    let slab_r = remap_sh_head_value(&slab_val, delta);
    let mega_r = remap_sh_head_value(&mega_val, delta);
    if let ShHeadValue::Extent { last_page } = mega_r {
        let mut page = [0u8; SH_PAGE_SIZE];
        dst.body().read_at(last_page, &mut page).unwrap();
        let (base, _) = sh_page_extent(sh_page_as_array(&page).unwrap())
            .unwrap()
            .expect("ver=2 last page");
        remap_copied_page_chain(dst.body(), base.saturating_add(delta), delta).unwrap();
    }
    let recs = vec![
        (head_key_from_full(&slab_key), pack8(&slab_r).unwrap()),
        (head_key_from_full(&mega_key), pack8(&mega_r).unwrap()),
    ];
    dst.publish_sorted_shard(0, &recs, 8 + n_mega as u64, src_hi + delta)
        .unwrap();
    assert_eq!(dst.entries(&slab_key).unwrap().len(), 8);
    assert_eq!(dst.entries(&mega_key).unwrap().len(), n_mega);
    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&dst_dir);
}

#[test]
fn pack_one_shard() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_dir_table(&dir);
        assert_eq!(t.head_shard_count(), 4);
        let key = |shard: u8, i: u8| {
            let mut k = [0u8; 32];
            k[0] = shard << 6 | (i & 0x3f);
            k
        };
        let k0 = key(0, 0);
        let k1 = key(0, 1);
        let mut session = t.pack_shard_session(0).unwrap();
        session.push_sorted_fk(k0, Fk(1)).unwrap();
        session.push_sorted_fk(k1, Fk(2)).unwrap();
        let pack = session.finish_pack().unwrap();
        assert_eq!(pack.keys, 2);
        let bump0 = t.alloc_bump();
        let new_bump = t.publish_packed_shard(0, pack).unwrap();
        assert!(new_bump >= bump0);
        assert_eq!(t.entries(&k0).unwrap().len(), 1);
        assert_eq!(t.entries(&k1).unwrap().len(), 1);
        assert!(t.head_value(&key(1, 0)).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    });
}

fn shard0_key(i: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = i & 0x3f;
    k
}

#[test]
fn bulk_session_reuses_fk_scratch_across_keys() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let mut session = t.pack_shard_session(0).unwrap();
        for i in 0..32u8 {
            session
                .push_sorted_fk(shard0_key(i), Fk(u64::from(i) + 1))
                .unwrap();
        }
        session.finish_key().unwrap();
        assert!(
            session.fk_scratch_capacity() >= 512,
            "session must keep the first FK vec: cap={}",
            session.fk_scratch_capacity()
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn pack_shard_session_inline_one_fk_does_not_grow_body() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let payload0 = payload_start(FILE_HEADER_LEN);
        let mut session = t.pack_shard_session(0).unwrap();
        session.push_sorted_fk(shard0_key(1), Fk(7)).unwrap();
        let pack = session.finish_pack().unwrap();
        assert_eq!(pack.keys, 1);
        assert_eq!(pack.creates, 1);
        assert_eq!(
            pack.bump, payload0,
            "1-FK inline must not allocate body: bump={} payload0={}",
            pack.bump, payload0
        );
        t.publish_packed_shard(0, pack).unwrap();
        assert!(matches!(
            t.head_value(&shard0_key(1)).unwrap().unwrap(),
            ShHeadValue::Inline { used: 1, .. }
        ));
        assert_eq!(t.entries(&shard0_key(1)).unwrap()[0].0, Fk(7));
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn pack_shard_session_slab_flush_times_body_and_roundtrips() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let mut session = t.pack_shard_session(0).unwrap();
        const N: u8 = 32;
        for i in 0..N {
            let k = shard0_key(i);
            let base = u64::from(i) * 10 + 1;
            session.push_sorted_fk(k, Fk(base)).unwrap();
            session.push_sorted_fk(k, Fk(base + 1)).unwrap();
        }
        let pack = session.finish_pack().unwrap();
        assert!(
            pack.body_flush_ns > 0,
            "slab writes must flush through body_buf: body_flush_ns={}",
            pack.body_flush_ns
        );
        assert_eq!(pack.keys, u64::from(N));
        assert_eq!(pack.creates, u64::from(N) * 2);
        t.publish_packed_shard(0, pack).unwrap();
        for i in 0..N {
            let k = shard0_key(i);
            let ents = t.entries(&k).unwrap();
            assert_eq!(ents.len(), 2, "key {i}");
            let base = u64::from(i) * 10 + 1;
            assert_eq!(ents[0].0, Fk(base));
            assert_eq!(ents[1].0, Fk(base + 1));
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn create_fks_matches_entries() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = ScriptHashTable::create(&dir).unwrap();
        let one = script_hash(&[0x01]);
        t.put_create(&rec(one, 7, 0)).unwrap();
        assert_eq!(
            t.create_fks(&one).unwrap(),
            t.entries(&one)
                .unwrap()
                .into_iter()
                .map(|(fk, _)| fk)
                .collect::<Vec<_>>()
        );
        assert_eq!(t.create_fks(&one).unwrap(), vec![Fk(7)]);

        let two = script_hash(&[0x02]);
        t.put_create(&rec(two, 1, 0)).unwrap();
        t.put_create(&rec(two, 2, 0)).unwrap();
        assert_eq!(t.create_fks(&two).unwrap(), vec![Fk(1), Fk(2)]);
        assert_eq!(
            t.create_fks(&two).unwrap(),
            t.entries(&two)
                .unwrap()
                .into_iter()
                .map(|(fk, _)| fk)
                .collect::<Vec<_>>()
        );

        let mega = script_hash(&[0x03]);
        let recs: Vec<_> = (1..=600u64).map(|i| rec(mega, i, 0)).collect();
        t.put_create_batch(&recs).unwrap();
        let fks = t.create_fks(&mega).unwrap();
        assert_eq!(fks.len(), 600);
        assert_eq!(fks.first().copied(), Some(Fk(1)));
        assert_eq!(fks.last().copied(), Some(Fk(600)));
        assert_eq!(
            fks,
            t.entries(&mega)
                .unwrap()
                .into_iter()
                .map(|(fk, _)| fk)
                .collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn bulk_dense_five_fks_use_class0_slab() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let k = shard0_key(1);
        let mut session = t.pack_shard_session(0).unwrap();
        for fk in 1..=5u64 {
            session.push_sorted_fk(k, Fk(fk)).unwrap();
        }
        let pack = session.finish_pack().unwrap();
        t.publish_packed_shard(0, pack).unwrap();
        match t.head_value(&k).unwrap().unwrap() {
            ShHeadValue::Slab { class, used, .. } => {
                assert_eq!(used, 5);
                assert_eq!(class, 0, "5 tight deltas must fit a 32 B class-0 slab");
            }
            other => panic!("expected class-0 slab, got {other:?}"),
        }
        assert_eq!(t.entries(&k).unwrap().len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn bulk_dense_over_cap_stays_slab_until_deltas_fill() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let k = shard0_key(2);
        let n = 300u64;
        let mut session = t.pack_shard_session(0).unwrap();
        for fk in 1..=n {
            session.push_sorted_fk(k, Fk(fk)).unwrap();
        }
        let pack = session.finish_pack().unwrap();
        t.publish_packed_shard(0, pack).unwrap();
        match t.head_value(&k).unwrap().unwrap() {
            ShHeadValue::Slab { class, used, .. } => {
                assert_eq!(used, n as u16);
                assert!(
                    class <= 5,
                    "300 1-byte deltas (~302 B payload) must not jump to pages; class={class}"
                );
            }
            other => panic!("expected slab, got {other:?}"),
        }
        assert_eq!(t.entries(&k).unwrap().len(), n as usize);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn bulk_reuses_page_align_gap_for_later_slab() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_table(&dir);
        let payload0 = payload_start(FILE_HEADER_LEN);
        let small_a = shard0_key(3);
        let mega = shard0_key(4);
        let small_b = shard0_key(5);
        let mut session = t.pack_shard_session(0).unwrap();
        for fk in 1..=5u64 {
            session.push_sorted_fk(small_a, Fk(fk)).unwrap();
        }
        for fk in 1..=2100u64 {
            session.push_sorted_fk(mega, Fk(fk)).unwrap();
        }
        for fk in 1..=5u64 {
            session.push_sorted_fk(small_b, Fk(fk)).unwrap();
        }
        let pack = session.finish_pack().unwrap();
        let bump = pack.bump;
        t.publish_packed_shard(0, pack).unwrap();
        let page = SH_PAGE_SIZE as u64;
        let aligned_after_first_slab = (payload0 + 32 + page - 1) & !(page - 1);
        assert_eq!(
            bump,
            aligned_after_first_slab + page,
            "second class-0 slab must come from the align-gap freelist; bump={bump}"
        );
        match t.head_value(&small_b).unwrap().unwrap() {
            ShHeadValue::Slab { off, class, .. } => {
                assert_eq!(class, 0);
                assert!(
                    off >= payload0 && off < aligned_after_first_slab,
                    "reused slab off={off} must sit in the gap before the megakey page"
                );
            }
            other => panic!("expected reused slab, got {other:?}"),
        }
        assert_eq!(t.entries(&small_a).unwrap().len(), 5);
        assert_eq!(t.entries(&mega).unwrap().len(), 2100);
        assert_eq!(t.entries(&small_b).unwrap().len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

fn four_shard_table(dir: &std::path::Path) -> ScriptHashTable {
    four_shard_dir_table(dir)
}

fn shared_body_table(dir: &std::path::Path) -> ScriptHashTable {
    let body = TableFile::create(dir.join("scripthash.body"), TableKind::ScriptHash).unwrap();
    let payload0 = payload_start(FILE_HEADER_LEN);
    body.ensure_capacity(payload0).unwrap();
    body.set_logical_len(payload0).unwrap();
    write_alloc_header(
        &body,
        &AllocState {
            live_count: 0,
            bump: payload0,
            free_head: [0; SH_MAX_CLASS as usize + 1],
        },
    )
    .unwrap();
    drop(body);
    ScriptHashTable::open(dir).unwrap()
}

#[test]
fn bulk_session_stream_small_key_still_slab() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut sh = [0u8; 32];
    sh[0] = 0x07;
    let mut session = t.bulk_session(1).unwrap();
    for i in 1..=8u64 {
        session.push_sorted_fk(sh, Fk(i)).unwrap();
        assert_eq!(session.buffered_fks(), i as usize);
    }
    session.finish_key().unwrap();
    let _ = session.finish().unwrap();
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { .. } => {}
        other => panic!("expected slab, got {other:?}"),
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 8);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Delta stream in 4073..=4088 B fits `ver=1` but not `ver=2` last-page header.
#[test]
fn bulk_session_extent_last_page_splits_when_ver2_header_eats_stream() {
    use crate::scripthash_pages::SH_PAGE_EXTENT_STREAM_MAX;
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let n = SH_PAGE_EXTENT_STREAM_MAX + 8;
    let mut sh = [0u8; 32];
    sh[0] = 0x11;
    let ents: Vec<_> = (1..=n as u64).map(|i| Fk(i)).collect();
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &ents).unwrap();
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 1);
    assert_eq!(creates, n as u64);
    assert_eq!(t.entries(&sh).unwrap().len(), n);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            let (base, n_ext) = sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .expect("ver=2 last page");
            assert!(
                n_ext >= 2,
                "must not pack 4080-byte stream as one ver=2 page"
            );
            assert_ne!(base, last_page);
        }
        other => panic!("expected extent, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Streamed megakey: last remainder can sit in 4073..=4088 B after `ver=1` flushes.
#[test]
fn bulk_session_streamed_last_remainder_fits_ver2() {
    use crate::scripthash_pages::{SH_PAGE_EXTENT_STREAM_MAX, SH_PAGE_STREAM_MAX};
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX + 8;
    let mut sh = [0u8; 32];
    sh[0] = 0x12;
    let ents: Vec<_> = (1..=n as u64).map(|i| Fk(i)).collect();
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &ents).unwrap();
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 1);
    assert_eq!(creates, n as u64);
    assert_eq!(t.entries(&sh).unwrap().len(), n);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            assert!(sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .is_some());
        }
        other => panic!("expected extent, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cold bulk megakey: multi-page chain is contiguous at bump (single-pass pack
/// writes next links on first write — no previous-page RMW).
#[test]
fn bulk_session_megakey_page_chain_contiguous_once() {
    use crate::scripthash_pages::SH_PAGE_STREAM_MAX;
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    // Sequential FKs fill ~4080/page; this n spans two pages.
    let n = SH_PAGE_STREAM_MAX + 10;
    let mut sh = [0u8; 32];
    sh[0] = 0x10;
    sh[1] = 0xee;
    let ents: Vec<_> = (1..=n as u64).map(|i| Fk(i)).collect();
    let mut sh_next = [0u8; 32];
    sh_next[0] = 0x10;
    sh_next[1] = 0xef;
    let next_ents = vec![Fk(1), Fk(2)];
    let mut session = t.bulk_session(2).unwrap();
    session.put_chain(sh, &ents).unwrap();
    session.put_chain(sh_next, &next_ents).unwrap();
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(keys, 2);
    assert_eq!(creates, n as u64 + 2);
    let got = t.entries(&sh).unwrap();
    assert_eq!(got.len(), n);
    for (i, (_, e)) in got.iter().enumerate() {
        assert_eq!(e.create_tx_fk, Fk(i as u64 + 1));
    }
    reset_sh_page_chain_ios();
    let got2 = t.entries(&sh).unwrap();
    assert_eq!(got2.len(), n);
    assert!(
        sh_page_chain_ios() <= 2,
        "contiguous two-page chain should span-read, ios={}",
        sh_page_chain_ios()
    );
    let (first, last, extent_n) = match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let w = u64::from_le_bytes(pack8_bytes(&ShHeadValue::extent(last_page)).unwrap());
            assert_eq!(w >> 62, 3, "pack8 mode 11");
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            let (base, n) = sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .expect("ver=2 last page");
            (base, last_page, n)
        }
        other => panic!("expected extent, got {other:?}"),
    };
    assert_eq!(extent_n, 2);
    assert_eq!(
        last,
        first + SH_PAGE_SIZE as u64,
        "tight extent: last = base + (n-1)*4096"
    );
    assert!(first > 0 && first % (SH_PAGE_SIZE as u64) == 0);
    match t.head_value(&sh_next).unwrap().unwrap() {
        ShHeadValue::Slab { off, .. } => {
            assert_eq!(
                off,
                last + SH_PAGE_SIZE as u64,
                "next key must pack at extent_end (no slack hole)"
            );
        }
        other => panic!("expected slab after megakey, got {other:?}"),
    }
    // Tip-path multi-page (write_new_page_chain) also round-trips same size.
    let sh2 = script_hash(&[0xef]);
    let recs: Vec<_> = (1..=n as u32).map(|v| rec(sh2, u64::from(v), v)).collect();
    assert_eq!(t.put_create_batch(&recs).unwrap(), n);
    assert_eq!(t.entries(&sh2).unwrap().len(), n);
    match t.head_value(&sh2).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            let (base, n_ext) = sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .expect("ver=2 last page");
            assert_eq!(n_ext, 2);
            assert_ne!(base, last_page);
        }
        other => panic!("expected extent, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn extent_meta(t: &ScriptHashTable, sh: &[u8; 32]) -> (u64, u64, u32) {
    match t.head_value(sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            let mut page = [0u8; SH_PAGE_SIZE];
            t.body().read_at(last_page, &mut page).unwrap();
            let (base, n) = sh_page_extent(sh_page_as_array(&page).unwrap())
                .unwrap()
                .expect("ver=2 last page");
            (base, last_page, n)
        }
        other => panic!("expected extent, got {other:?}"),
    }
}

#[test]
fn extent_append_links_tail_when_bump_moved() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX - 1;
    let mut sh = [0u8; 32];
    sh[0] = 0x21;
    sh[1] = 0xaa;
    let ents: Vec<_> = (1..=n as u64).map(|i| Fk(i)).collect();
    let mut sh_gap = [0u8; 32];
    sh_gap[0] = 0x21;
    sh_gap[1] = 0xab;
    let mut session = t.bulk_session(2).unwrap();
    session.put_chain(sh, &ents).unwrap();
    session.put_chain(sh_gap, &[Fk(1), Fk(2)]).unwrap();
    let _ = session.finish().unwrap();
    let (base, last0, n0) = extent_meta(&t, &sh);
    assert_eq!(n0, 2);
    t.put_create(&rec(sh, n as u64 + 1, 0)).unwrap();
    let (base2, last1, n1) = extent_meta(&t, &sh);
    assert_eq!(base2, base);
    assert_eq!(n1, 2, "tail must not bump extent_n");
    assert_ne!(
        last1,
        base + (u64::from(n1) - 1) * SH_PAGE_SIZE as u64,
        "overflow last_page is a linked tail"
    );
    assert_ne!(last1, last0);
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1);
    reset_sh_page_chain_ios();
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1);
    assert!(
        sh_page_chain_ios() >= 3,
        "span + tail read, ios={}",
        sh_page_chain_ios()
    );
    let extra2: Vec<_> = ((n as u64 + 2)..=(n as u64 + 1 + SH_PAGE_EXTENT_STREAM_MAX as u64))
        .map(|i| rec(sh, i, 0))
        .collect();
    assert_eq!(t.put_create_batch(&extra2).unwrap(), extra2.len());
    let (_, last2, n2) = extent_meta(&t, &sh);
    assert_eq!(n2, 2);
    assert_ne!(last2, last1, "second overflow adds another linked page");
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1 + extra2.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extent_append_glued_bumps_extent_n() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX - 1;
    let mut sh = [0u8; 32];
    sh[0] = 0x22;
    let ents: Vec<_> = (1..=n as u64).map(|i| Fk(i)).collect();
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &ents).unwrap();
    let _ = session.finish().unwrap();
    let (base, _, n0) = extent_meta(&t, &sh);
    assert_eq!(n0, 2);
    t.put_create(&rec(sh, n as u64 + 1, 0)).unwrap();
    let (_, last, n1) = extent_meta(&t, &sh);
    assert_eq!(n1, 3, "glued HWM grows extent_n in place");
    assert_eq!(last, base + 2 * SH_PAGE_SIZE as u64);
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1);
    reset_sh_page_chain_ios();
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1);
    assert!(
        sh_page_chain_ios() <= 2,
        "glued grow stays one span, ios={}",
        sh_page_chain_ios()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_put_sorted_creates_dedups() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x99]);
    let recs = vec![
        rec(sh, 1, 0),
        rec(sh, 1, 0), // dup
        rec(sh, 2, 0),
        rec(sh, 3, 0),
    ];
    let mut session = t.bulk_session(1).unwrap();
    let n = session.put_sorted_creates(&recs).unwrap();
    let _ = session.finish().unwrap();
    assert_eq!(n, 3);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    assert_eq!(t.entry_count(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reinit_clears_head_when_live_count_already_zero() {
    // Crash mid-finish: heads durable, alloc live_count still 0.
    // bulk_session must not hard-error; reinit then cold load.
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut sh = [0u8; 32];
    sh[0] = 0x7e;
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &[Fk(42)]).unwrap();
    let _ = session.finish().unwrap();
    assert!(!t.head_is_empty());
    t.test_zero_live_count_keep_head().unwrap();
    assert_eq!(t.entry_count(), 0);
    assert!(!t.head_is_empty());
    // Old bug: only reinit when entry_count>0 → bulk_session fails here.
    assert!(t.bulk_session(1).is_err());
    t.reinit_empty_for_cold_materialize().unwrap();
    assert!(t.head_is_empty());
    assert_eq!(t.entry_count(), 0);
    let mut session = t.bulk_session(2).unwrap();
    session.put_chain(sh, &[Fk(1)]).unwrap();
    let (n, _, _, _) = session.finish().unwrap();
    assert_eq!(n, 1);
    assert_eq!(t.entries(&sh).unwrap()[0].1.create_tx_fk, Fk(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_flushes_head_on_prefix_shard_boundary() {
    // Live OA image stays off-disk until shard boundary / finish.
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    const N: u32 = 80_000;
    // Unique 16 B head prefixes (head truncates full 32 B to 16 B).
    let key = |i: u32| {
        let mut sh = [0u8; 32];
        sh[0..4].copy_from_slice(&i.to_le_bytes());
        sh[4] = (i >> 8) as u8; // spread across shard byte for multi-shard
        sh
    };
    let mut session = t.bulk_session(u64::from(N)).unwrap();
    assert!(t.head_value(&key(0)).unwrap().is_none());
    for i in 0..N {
        let sh = key(i);
        session.put_chain(sh, &[Fk(u64::from(i) + 1)]).unwrap();
        // Active shard not yet installed: this key is only in the live image.
        if i == 70_000 {
            assert!(
                t.head_value(&sh).unwrap().is_none(),
                "active-shard heads must not land until shard boundary"
            );
        }
    }
    let peak = session.peak_table_bytes;
    let (creates, keys, _, _) = session.finish().unwrap();
    assert_eq!(creates, u64::from(N));
    assert_eq!(keys, u64::from(N));
    assert_eq!(t.entry_count(), u64::from(N));
    // Peak is packed recs (32 B/key), not a 2 GiB OA slot table.
    assert_eq!(peak, (N as usize) * 24);
    // Spot-check a few keys survive live install.
    for i in [0u32, 1, 65_535, 70_000, N - 1] {
        let ents = t.entries(&key(i)).unwrap();
        assert_eq!(ents.len(), 1, "i={i}");
        assert_eq!(ents[0].1.create_tx_fk, Fk(u64::from(i) + 1));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cold_progress_and_resume_skips_complete_shards() {
    // 4-way head: fill shard 0, abandon, resume from progress, fill rest.
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let t = four_shard_dir_table(&dir);
        assert_eq!(t.head_shard_count(), 4);

        // Keys: shard = full[0] >> 6 for n=4 (top 2 bits).
        let key = |shard: u8, i: u8| {
            let mut k = [0u8; 32];
            k[0] = shard << 6 | (i & 0x3f);
            k
        };
        let mut session = t.bulk_session(64).unwrap();
        for i in 0..8u8 {
            session
                .put_chain(key(0, i), &[Fk(u64::from(i) + 1)])
                .unwrap();
        }
        // Cross into shard 1 so shard 0 is installed + checkpointed.
        session.put_chain(key(1, 0), &[Fk(100)]).unwrap();
        assert!(ColdProgress::load(&dir).unwrap().is_some());
        let p = ColdProgress::load(&dir).unwrap().unwrap();
        assert_eq!(p.next_shard, 1);
        session.abandon_incomplete();

        // Resume: skip shard 0 keys, fill 1..3.
        let p = ColdProgress::load(&dir).unwrap().unwrap();
        t.prepare_cold_resume(&p).unwrap();
        let mut session = t.bulk_session_resume(64, &p).unwrap();
        // Re-deliver shard 0 keys (must be ignored).
        for i in 0..8u8 {
            session
                .put_chain(key(0, i), &[Fk(u64::from(i) + 1)])
                .unwrap();
        }
        for shard in 1u8..4 {
            for i in 0..4u8 {
                session
                    .put_chain(key(shard, i), &[Fk(u64::from(shard) * 100 + u64::from(i))])
                    .unwrap();
            }
        }
        let (creates, keys, _, _) = session.finish().unwrap();
        assert!(ColdProgress::load(&dir).unwrap().is_none());
        // Shard0 kept (8). Resume fills shards 1..3 × 4 keys (the mid-shard1 key was abandoned).
        assert_eq!(keys, 8 + 12);
        assert_eq!(creates, 8 + 12);
        assert_eq!(t.entries(&key(0, 0)).unwrap().len(), 1);
        assert_eq!(t.entries(&key(3, 3)).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn live_session_does_not_size_from_create_count() {
    // Regression: bulk_session(total_recs) used to allocate create-count-sized
    // OA images. unique_hint=1000 must not allocate a multi-GiB table.
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let mut session = t.bulk_session(1_000).unwrap();
    let mut sh = [0u8; 32];
    sh[0] = 1;
    session.put_chain(sh, &[Fk(1)]).unwrap();
    let peak = session.peak_table_bytes;
    let _ = session.finish().unwrap();
    assert_eq!(peak, 24, "one streamed rec is 24 B, not an OA image");
    assert!(
        peak < 16 * 1024 * 1024,
        "peak {peak} looks like create-count sizing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_migrates_legacy_head_when_runs_present() {
    // Leftover live OA main is refused even when runs exist (wipe + rematerialize).
    HeadScale::test_with(HeadScale::Mainnet, || {
        let dir = tmp();
        let body = TableFile::create(dir.join("scripthash.body"), TableKind::ScriptHash).unwrap();
        let payload0 = payload_start(FILE_HEADER_LEN);
        body.ensure_capacity(payload0).unwrap();
        body.set_logical_len(payload0).unwrap();
        let state = AllocState {
            live_count: 0,
            bump: payload0,
            free_head: [0; SH_MAX_CLASS as usize + 1],
        };
        write_alloc_header(&body, &state).unwrap();
        drop(body);
        ShardedScriptHashHead::create_sharded(dir.join("scripthash.head"), 16, 64).unwrap();

        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut rec = [0u8; 40];
        rec[0] = 0xab;
        rec[32..40].copy_from_slice(&1u64.to_le_bytes());
        let path = crate::sorted_run::next_run_path(&runs_dir, 1);
        crate::sorted_run::write_sorted_run(&path, 32, 40, &rec).unwrap();

        match ScriptHashTable::open(&dir) {
            Ok(_) => panic!("leftover OA must refuse"),
            Err(StoreError::Layout(m)) => {
                assert!(m.contains("scripthash*"), "{m}");
            }
            Err(e) => panic!("expected Layout, got {e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn open_refuses_legacy_head_without_runs() {
    HeadScale::test_with(HeadScale::Mainnet, || {
        let dir = tmp();
        let body = TableFile::create(dir.join("scripthash.body"), TableKind::ScriptHash).unwrap();
        let payload0 = payload_start(FILE_HEADER_LEN);
        body.ensure_capacity(payload0).unwrap();
        body.set_logical_len(payload0).unwrap();
        let state = AllocState {
            live_count: 0,
            bump: payload0,
            free_head: [0; SH_MAX_CLASS as usize + 1],
        };
        write_alloc_header(&body, &state).unwrap();
        drop(body);
        ShardedScriptHashHead::create_sharded(dir.join("scripthash.head"), 16, 64).unwrap();
        match ScriptHashTable::open(&dir) {
            Err(StoreError::Layout(m)) => {
                assert!(m.contains("scripthash*"), "{m}");
            }
            Ok(_) => panic!("expected leftover OA refuse"),
            Err(e) => panic!("unexpected error: {e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn for_each_live_create_skips_unlinked() {
    let dir = tmp();
    let t = ScriptHashTable::create(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    let mut heads = HashMap::new();
    t.put_create_batch_append(&[rec(sh, 1, 0), rec(sh, 2, 0), rec(sh, 3, 0)], &mut heads)
        .unwrap();
    t.unlink_create(&sh, Fk(2), 0).unwrap();
    let mut seen = Vec::new();
    t.for_each_live_create(|c| seen.push(c.0)).unwrap();
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 3]);
    let _ = std::fs::remove_dir_all(&dir);
}

fn script_for_prefix_shard(shard: usize, n_shards: usize) -> Vec<u8> {
    for n in 0u32..100_000 {
        let script = vec![0x51, n as u8, (n >> 8) as u8, (n >> 16) as u8];
        if crate::prefix_shard_of(&script_hash(&script), n_shards) == shard {
            return script;
        }
    }
    panic!("no script for shard {shard} of {n_shards}");
}

fn two_scripts_same_shard_reverse_hash(shard: usize, n_shards: usize) -> (Vec<u8>, Vec<u8>) {
    let mut found: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    for n in 0u32..200_000 {
        let script = vec![0x51, n as u8, (n >> 8) as u8, (n >> 16) as u8];
        let sh = script_hash(&script);
        if crate::prefix_shard_of(&sh, n_shards) == shard {
            found.push((script, sh));
            if found.len() >= 8 {
                break;
            }
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    assert!(
        found.len() >= 2,
        "need two scripts in shard {shard}/{n_shards}"
    );
    let low = found.first().unwrap().0.clone();
    let high = found.last().unwrap().0.clone();
    assert!(script_hash(&low) < script_hash(&high));
    (low, high)
}

fn class_a_coinbase(
    txid: [u8; 32],
    script: Vec<u8>,
) -> (
    crate::TxRecord,
    Vec<crate::InputRecord>,
    Vec<crate::OutputRecord>,
) {
    (
        crate::TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![crate::InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![crate::OutputRecord::unspent(50, script)],
    )
}

fn decode_unsorted_file(path: &std::path::Path) -> Vec<ScriptHashRecord> {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.len() % 24, 0, "unsorted file must be 24-byte recs");
    bytes
        .chunks_exact(24)
        .map(|c| {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&c[..16]);
            let fk = Fk(u64::from_le_bytes(c[16..24].try_into().unwrap()));
            ScriptHashRecord::from_fk(sh, fk)
        })
        .collect()
}

#[test]
fn unsorted_collect_partitions_by_prefix_and_is_not_scripthash_sorted() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        let n_shards = 4usize;
        let (low_script, high_script) = two_scripts_same_shard_reverse_hash(1, n_shards);
        let mut txid_lo = [0u8; 32];
        txid_lo[0] = 1;
        let mut txid_hi = [0u8; 32];
        txid_hi[0] = 2;
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid_lo, high_script.clone())], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid_hi, low_script.clone())], true)
            .unwrap();
        for shard in [0usize, 2, 3] {
            let script = script_for_prefix_shard(shard, n_shards);
            let mut txid = [0u8; 32];
            txid[0] = 10 + shard as u8;
            s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
                .unwrap();
        }
        let udir = dir.join("unsorted");
        let out = crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        assert_eq!(out.per_shard.len(), n_shards);
        assert!(crate::unsorted_manifest_ok(&udir, n_shards));
        assert_eq!(out.recs, 5);
        for shard in 0..n_shards {
            let recs = decode_unsorted_file(&crate::unsorted_shard_path(&udir, shard));
            assert!(
                recs.iter()
                    .all(|r| crate::prefix_shard_of(&r.scripthash, n_shards) == shard),
                "shard {shard} must contain only its prefix"
            );
            assert_eq!(recs.len() as u64, out.per_shard[shard]);
        }
        let shard1 = decode_unsorted_file(&crate::unsorted_shard_path(&udir, 1));
        assert_eq!(shard1.len(), 2);
        assert!(
            shard1[0].scripthash > shard1[1].scripthash,
            "collect writes fk order, not scripthash order"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_materialize_four_shards_from_class_a_no_catalog_runs() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        let n_shards = 4usize;
        let mut keys = Vec::new();
        for shard in 0..n_shards {
            let script = script_for_prefix_shard(shard, n_shards);
            keys.push(script_hash(&script));
            let mut txid = [0u8; 32];
            txid[0] = shard as u8;
            s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
                .unwrap();
        }
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let udir = sh_dir.join(crate::UNSORTED_SHARD_DIR);
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 2, None).unwrap();
        let mat = crate::materialize_sh_from_unsorted(&table, &udir, 2, None).unwrap();
        assert_eq!(mat.creates, 4, "all Class A creates packed");
        assert_eq!(mat.keys, 4);
        for k in &keys {
            assert_eq!(table.entries(k).unwrap().len(), 1, "key must be queryable");
        }
        let runs = sh_dir.join("scripthash.runs");
        assert!(
            !runs.exists()
                || std::fs::read_dir(&runs)
                    .map(|it| it.count() == 0)
                    .unwrap_or(true),
            "unsorted path must not write catalog runs"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_pack_sorts_numeric_fk_and_keeps_all_creates() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let n_shards = 4usize;
        let udir = sh_dir.join(crate::UNSORTED_SHARD_DIR);
        std::fs::create_dir_all(&udir).unwrap();
        let (low, high) = two_scripts_same_shard_reverse_hash(1, n_shards);
        let sh_lo = script_hash(&low);
        let sh_hi = script_hash(&high);
        let mut bytes = Vec::new();
        let mut push = |sh: [u8; 32], fk: u64| {
            let mut r = [0u8; 24];
            r[..16].copy_from_slice(&sh[..16]);
            r[16..].copy_from_slice(&fk.to_le_bytes());
            bytes.extend_from_slice(&r);
        };
        push(sh_hi, 256);
        push(sh_hi, 2);
        push(sh_lo, 3);
        push(sh_lo, 1);
        push(sh_lo, 1);
        push(sh_hi, 0);
        std::fs::write(crate::unsorted_shard_path(&udir, 1), &bytes).unwrap();
        for shard in [0usize, 2, 3] {
            std::fs::write(crate::unsorted_shard_path(&udir, shard), []).unwrap();
        }
        rbitcoin_log::capture_logs(true);
        let mat = crate::materialize_sh_from_unsorted(&table, &udir, 1, None).unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert_eq!(mat.creates, 4, "null and duplicate (sh,fk) must not pack");
        assert_eq!(mat.keys, 2);
        let done: Vec<&str> = logs
            .iter()
            .filter_map(|(level, m)| {
                (*level == rbitcoin_log::Level::Info
                    && m.contains("scripthash unsorted pack shard="))
                .then_some(m.as_str())
            })
            .collect();
        assert_eq!(done.len(), 4, "one finish line per shard, got {logs:?}");
        for shard in 0..n_shards {
            let tag = format!("shard={shard:02x}");
            assert!(
                done.iter()
                    .any(|m| m.contains(&tag) && m.contains("elapsed=")),
                "missing finish log for {tag}: {done:?}"
            );
        }
        assert!(
            done.iter()
                .any(|m| m.contains("shard=01") && m.contains("keys=2") && m.contains("creates=4")),
            "data shard must log packed keys/creates: {done:?}"
        );
        let mut lo: Vec<u64> = table
            .entries(&sh_lo)
            .unwrap()
            .into_iter()
            .map(|e| e.0 .0)
            .collect();
        lo.sort_unstable();
        assert_eq!(lo, vec![1, 3]);
        let mut hi: Vec<u64> = table
            .entries(&sh_hi)
            .unwrap()
            .into_iter()
            .map(|e| e.0 .0)
            .collect();
        hi.sort_unstable();
        assert_eq!(
            hi,
            vec![2, 256],
            "fk 256 must sort after 2, not as LE bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_combined_skips_collect_when_done_and_resumes_unsealed() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        let n_shards = 4usize;
        let mut keys = Vec::new();
        for shard in 0..n_shards {
            let script = script_for_prefix_shard(shard, n_shards);
            keys.push(script_hash(&script));
            let mut txid = [0u8; 32];
            txid[0] = shard as u8;
            s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
                .unwrap();
        }
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let udir = sh_dir.join(crate::UNSORTED_SHARD_DIR);
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        crate::materialize_sh_from_unsorted(&table, &udir, 1, None).unwrap();
        assert!(table.unsealed_main_shards().is_empty());
        let again = crate::materialize_sh_from_unsorted(&table, &udir, 2, None).unwrap();
        assert_eq!(again.creates, 4);
        for k in &keys {
            assert_eq!(table.entries(k).unwrap().len(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_cancel_before_collect_is_cancelled() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let cancel = AtomicBool::new(true);
        let err = crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, Some(&cancel)).unwrap_err();
        assert!(
            matches!(err, StoreError::Cancelled(_)),
            "expected Cancelled, got {err}"
        );
        assert!(
            !crate::unsorted_manifest_ok(
                &crate::unsorted_shard_dir(s.path()),
                s.scripthash.head_shard_count()
            ),
            "cancel must not write DONE"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_done_records_class_a_last_fk() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        let out = crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        assert!(crate::unsorted_manifest_ok(&udir, n_shards));
        assert_eq!(out.last_fk, s.txs.count());
        assert_eq!(
            crate::unsorted_done_last_fk(&udir, n_shards),
            Some(s.txs.count())
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn unsorted_materialize_appends_when_done_lags_and_no_shards() {
    HeadScale::test_with(HeadScale::Tiny, || {
        let dir = tmp();
        let s = crate::Store::create(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        let done_last = crate::unsorted_done_last_fk(&udir, n_shards).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], vec![0x52])], true)
            .unwrap();
        assert!(s.txs.count() > done_last);
        let mat = crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
        assert!(mat.creates >= 2);
        assert_eq!(
            s.scripthash.entries(&script_hash(&[0x51])).unwrap().len(),
            1
        );
        assert_eq!(
            s.scripthash.entries(&script_hash(&[0x52])).unwrap().len(),
            1,
            "Class A grown after DONE must be appended into unsorted before pack"
        );
        let _ = std::fs::remove_dir_all(&dir);
    });
}
