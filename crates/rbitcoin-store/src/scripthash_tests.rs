use super::*;
use crate::fuse8_filter::SealedFuse8;
use crate::scripthash_head::prefix_shard_of;
use crate::scripthash_layout::{head_key_from_full, ShHeadValue, SH_HEAD_VALUE_LEN};
use crate::scripthash_materialize::{
    collect_unsorted_covering_txs, load_post_shard_entries, materialize_sh_from_unsorted,
    materialize_sh_from_unsorted_from_txs, pack_one_extract_shard, seal_mphf_from_keys,
    unsorted_done_last_fk, unsorted_keys_path, unsorted_mphf_base, unsorted_multi_fuse_path,
    unsorted_post_path, unsorted_shard_path, write_keys_spill_entries, write_post_spill_entries,
    UNSORTED_SHARD_DIR,
};
use crate::scripthash_mphf::{mix_key16, MphfHead};
use crate::scripthash_pages::{
    sh_page_as_array, sh_page_as_array_mut, sh_page_extent, sh_page_set_extent,
    SH_PAGE_EXTENT_STREAM_MAX, SH_PAGE_SIZE, SH_PAGE_STREAM_MAX,
};
use std::sync::atomic::AtomicBool;

fn tmp() -> crate::testutil::TempDir {
    crate::testutil::TempDir::labeled("sh").expect("temp dir")
}

fn assert_no_l0_ovf_leftover(dir: &std::path::Path) {
    let ovf = dir.join("scripthash.ovf");
    for ent in std::fs::read_dir(&ovf).unwrap().flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        let stem = s
            .strip_suffix(".idx")
            .or_else(|| s.strip_suffix(".fuse8"))
            .unwrap_or(s.as_ref());
        if stem.len() == 6 && stem.chars().all(|c| c.is_ascii_digit()) {
            let mphf = ovf.join(format!("{stem}.mphf"));
            assert!(
                mphf.is_file(),
                "L0 leftover {s} after compact (no {stem}.mphf)"
            );
        }
    }
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
    ScriptHashTable::open_tiny(dir).unwrap()
}

fn sh_prefix_key(shard: u8, i: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = shard << 6 | (i & 0x3f);
    k
}

#[test]
fn sh_body_create_grows_64k_not_slab() {
    {
        let dir = tmp();
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        let sh = script_hash(&[0x01]);
        put_create(&t, rec(sh, 1, 0));
        put_create(&t, rec(sh, 2, 0));
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
    }
}

#[test]
fn sh_bodies_are_split() {
    {
        let dir = tmp();
        let t = four_shard_dir_table(&dir);
        assert_eq!(t.head_shard_count(), 4);
        assert_eq!(t.body_layout(), ShBodyLayout::Sharded);
        let k0 = sh_prefix_key(0, 0);
        let k2 = sh_prefix_key(2, 0);
        let ents: Vec<Fk> = (1..=8).map(Fk).collect();
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
            put_create(&t, rec(k_new, i, 0));
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
        match shared_body_table(&file_dir) {
            Err(StoreError::Corrupt(m)) => assert_eq!(m, INDEX_REFUSE_SHARED_SH_BODY),
            Ok(_) => panic!("Shared file body must refuse ScriptHashTable::open"),
            Err(other) => panic!("expected INDEX_REFUSE_SHARED_SH_BODY, got {other}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&file_dir);
    }
}

#[test]
fn sh_body_orientation() {
    let file_dir = tmp();
    TableFile::create(file_dir.join("scripthash.body"), TableKind::ScriptHash).unwrap();
    match detect_sh_body_layout(&file_dir) {
        Err(StoreError::Corrupt(m)) => assert_eq!(m, INDEX_REFUSE_SHARED_SH_BODY),
        other => panic!("Shared file body must refuse, got {other:?}"),
    }

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
        Err(StoreError::Corrupt(m)) => assert_eq!(m, INDEX_REFUSE_SHARED_SH_BODY),
        other => panic!("mixed file body must refuse Shared, got {other:?}"),
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
    let _t = ScriptHashTable::create_tiny(&created).unwrap();
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

fn put_create(t: &ScriptHashTable, rec: ScriptHashRecord) {
    let mut heads = HashMap::new();
    t.put_create_batch_append(std::slice::from_ref(&rec), &mut heads)
        .unwrap();
}

fn put_create_batch(t: &ScriptHashTable, recs: impl AsRef<[ScriptHashRecord]>) -> usize {
    let mut heads = HashMap::new();
    t.put_create_batch_append(recs.as_ref(), &mut heads)
        .unwrap()
        .0
}

#[test]
fn open_refuses_pack8_paged_mode_10_on_ingest() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create(&t, rec([0x11u8; 32], 1, 0));
    }
    let ingest = dir.join("scripthash.ovf").join("ingest");
    plant_pack8_mode10(&ingest);
    match ScriptHashTable::open_tiny(&dir) {
        Err(StoreError::Corrupt(m)) => {
            assert_eq!(m, crate::scripthash_layout::INDEX_REFUSE_PAGED_SH);
        }
        Ok(_) => panic!("Paged pack8 must refuse ScriptHashTable::open"),
        Err(other) => panic!("expected INDEX_REFUSE_PAGED_SH, got {other}"),
    }
}

fn plant_pack8_mode10(ingest: &std::path::Path) {
    let mut bytes = std::fs::read(ingest).unwrap();
    let hdr = crate::file::FILE_HEADER_LEN;
    let slot = crate::scripthash_layout::SH_HEAD_SLOT_SIZE;
    let key_len = crate::scripthash_layout::SH_HEAD_KEY_LEN;
    let mode10 = ((2u64 << 62) | 4096u64).to_le_bytes();
    let mut i = hdr;
    while i + slot <= bytes.len() {
        let val = &bytes[i + key_len..i + slot];
        if val.iter().any(|&b| b != 0) {
            bytes[i + key_len..i + slot].copy_from_slice(&mode10);
        }
        i += slot;
    }
    std::fs::write(ingest, &bytes).unwrap();
}

fn put_unique(t: &ScriptHashTable, tag: u8, n: u32) {
    for i in 0..n {
        let sh = script_hash(&[tag, (i & 0xff) as u8, (i >> 8) as u8, 0x7e]);
        put_create(t, rec(sh, u64::from(i) + 1, 0));
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x99]);
    put_create(&t, rec(sh, 1, 0));
    let _ = put_create_batch(&t, &[] as &[ScriptHashRecord]);
    assert_eq!(t.entry_count(), 1);
    t.flush().unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    put_create(&t, rec(sh, 3, 0));
    let entries = t.entries(&sh).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1.create_tx_fk, Fk(3));
    put_create(&t, rec(sh, 3, 0));
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    put_create(&t, rec(sh, 4, 1));
    assert_eq!(t.entries(&sh).unwrap().len(), 2);
    assert!(t.unlink_create(&sh, Fk(4), 1).unwrap());
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    assert!(!t.unlink_create(&[0u8; 32], Fk(1), 0).unwrap());
    assert!(!t.unlink_create(&sh, Fk(99), 0).unwrap());
    assert!(t.unlink_create(&sh, Fk(3), 0).unwrap());
    assert!(t.entries(&sh).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn incremental_absent_lands_on_ingest() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    put_create(&t, rec(sh, 3, 0));
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
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(t.entries(&sh).unwrap().len(), 1);
    assert!(!dir.join("scripthash.head").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_uses_slabs_then_pages() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x15]);
    for i in 1..=5u64 {
        put_create(&t, rec(sh, i, 0));
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
        put_create(&t, rec(sh, i, 0));
    }
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Slab { class, used, .. } => {
            assert_eq!(class, 2, "9th fk grows class 1 → 2");
            assert_eq!(used, 9);
        }
        other => panic!("expected class-2 slab, got {other:?}"),
    }
    assert_eq!(
        put_create_batch(&t, [rec(sh, 9, 0), rec(sh, 5, 0)]),
        0,
        "fk ≤ max is a skip"
    );
    let rest: Vec<_> = (10..=257u64).map(|i| rec(sh, i, 0)).collect();
    assert_eq!(put_create_batch(&t, rest), 248);
    match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => {
            assert!(last_page > 0);
        }
        other => panic!("expected page chain at 257, got {other:?}"),
    }
    assert_eq!(t.entries(&sh).unwrap().len(), 257);
    assert!(t.create_fks(&sh).unwrap().contains(&Fk(257)));
    assert!(!t.create_fks(&sh).unwrap().contains(&Fk(258)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn promote_ladder_inline_to_paged() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x52]);
    for i in 1..=5u64 {
        put_create(&t, rec(sh, i, i as u32));
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x53]);
    let recs: Vec<_> = (0..100u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let n = put_create_batch(&t, recs);
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
fn create_count_inline_slab_no_page_io_extent_stamps() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh1 = script_hash(&[0x01]);
    put_create(&t, rec(sh1, 1, 0));
    assert_eq!(t.create_count(&sh1).unwrap(), 1);

    let sh2 = script_hash(&[0x02]);
    for i in 1..=5u64 {
        put_create(&t, rec(sh2, i, 0));
    }
    assert_eq!(t.create_count(&sh2).unwrap(), 5);

    let sh3 = script_hash(&[0x03]);
    let recs: Vec<_> = (1..=300u64).map(|i| rec(sh3, i, 0)).collect();
    assert_eq!(put_create_batch(&t, recs), 300);
    match t.head_value(&sh3).unwrap().unwrap() {
        ShHeadValue::Extent { .. } => {}
        other => panic!("expected extent, got {other:?}"),
    }
    assert_eq!(t.create_count(&sh3).unwrap(), 300);
    assert_eq!(t.create_count(&sh3).unwrap(), 300);
    let ShHeadValue::Extent { last_page } = t.head_value(&sh3).unwrap().unwrap() else {
        panic!("extent");
    };
    let home = t.key_home(&sh3).unwrap();
    let body = t.body_for(&sh3, home);
    let mut page = [0u8; SH_PAGE_SIZE];
    body.read_at(last_page, &mut page).unwrap();
    crate::scripthash_pages::sh_page_set_extent_creates(&mut page, 0);
    body.write_at(last_page, &page).unwrap();
    assert_eq!(t.create_count(&sh3).unwrap(), 300);
    put_create(&t, rec(sh3, 301, 0));
    assert_eq!(t.entries(&sh3).unwrap().len(), 301);
    assert_eq!(t.create_count(&sh3).unwrap(), 301);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_batch_chains() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    let recs: Vec<_> = (0..3u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let n = put_create_batch(&t, &recs);
    assert_eq!(n, 3);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    let n2 = put_create_batch(&t, &recs);
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0xab]);
    // Fill past one delta page so last page holds the max.
    let n = SH_PAGE_STREAM_MAX + 5;
    let first: Vec<_> = (1..=n as u64).map(|i| rec(sh, i, 0)).collect();
    assert_eq!(put_create_batch(&t, first), n);
    assert_eq!(t.entries(&sh).unwrap().len(), n);
    let val = t.head_value(&sh).unwrap().unwrap();
    let home = t.key_home(&sh).unwrap();
    let max = t
        .last_create_fk_on(t.body_for(&sh, home), &val)
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
    let written = put_create_batch(&t, batch);
    assert_eq!(written, 3, "only fks > max must be written");
    let got = t.entries(&sh).unwrap();
    assert_eq!(got.len(), n + 3);
    for (i, (_, e)) in got.iter().enumerate() {
        assert_eq!(e.create_tx_fk.0, (i as u64) + 1);
    }
    // Only-lower batch is no-op.
    assert_eq!(put_create_batch(&t, [rec(sh, 1, 0), rec(sh, 2, 0)]), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_create_batch_append_uses_heads() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x51]);
    let mut heads = HashMap::new();
    let recs: Vec<_> = (0..3u32).map(|v| rec(sh, u64::from(v) + 1, v)).collect();
    let (n, _t) = t.put_create_batch_append(&recs, &mut heads).unwrap();
    assert_eq!(n, 3);
    assert_eq!(t.entries(&sh).unwrap().len(), 3);
    assert!(heads.contains_key(&sh));
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

#[test]
fn append_after_zero_live_count_keeps_sealed_home() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x7e]);
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &[Fk(1)]).unwrap();
    let _ = session.finish().unwrap();
    assert!(matches!(t.key_home(&sh).unwrap(), KeyHome::Main));
    t.test_zero_live_count_keep_head().unwrap();
    assert_eq!(t.entry_count(), 0);
    assert!(!t.head_is_empty());
    put_create(&t, rec(sh, 2, 0));
    assert!(
        matches!(t.key_home(&sh).unwrap(), KeyHome::Main),
        "crash mid-finish (live_count=0, heads occupied) must still probe sealed main"
    );
    let fks: Vec<_> = t
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(_, r)| r.create_tx_fk)
        .collect();
    assert!(
        fks.contains(&Fk(1)) && fks.contains(&Fk(2)),
        "append must not dual-home ingest over sealed rows: {fks:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn dummy_sh_head_key(i: u64) -> [u8; 32] {
    let mut k = [0xEE; 32];
    k[..8].copy_from_slice(&i.to_le_bytes());
    k
}

#[test]
fn put_create_batch_append_caps_heads_and_miss_still_writes() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
fn extent_span_over_cap_still_unlinks() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x7c]);
    let mut heads = HashMap::new();
    let many: Vec<_> = (1..=600u32).map(|v| rec(sh, u64::from(v), v)).collect();
    let (nm, _) = t.put_create_batch_append(&many, &mut heads).unwrap();
    assert_eq!(nm, 600);
    let last_page = match t.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { last_page } => last_page,
        other => panic!("expected extent megakey, got {other:?}"),
    };

    let mut page = [0u8; SH_PAGE_SIZE];
    t.ovf_file().read_at(last_page, &mut page).unwrap();
    let arr = sh_page_as_array_mut(&mut page).unwrap();
    let (base, n) = sh_page_extent(arr).unwrap().expect("ver=2 last page");
    let over = (64 * 1024 * 1024 / SH_PAGE_SIZE as u64) as u32 + 1;
    assert!(over > n, "stamp must exceed the real page count {n}");
    sh_page_set_extent(arr, base, over).unwrap();
    t.ovf_file().write_at(last_page, &page).unwrap();

    assert_eq!(t.entries(&sh).unwrap().len(), 600);
    assert!(t.unlink_create(&sh, Fk(600), 600).unwrap());
    assert_eq!(t.entries(&sh).unwrap().len(), 599);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlink_demotes_paged_to_inline() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = script_hash(&[0x54]);
    for i in 1..=3u64 {
        put_create(&t, rec(sh, i, i as u32));
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
    assert_eq!(HeadScale::Mainnet.ingest_oa_slots(), 1 << 25);
    assert_eq!(SH_HEAD_VALUE_LEN, 8);
    assert_eq!(crate::scripthash_layout::SH_HEAD_SLOT_SIZE, 24);
}

#[test]
fn create_does_not_write_oa_stub() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    assert_eq!(t.head_shard_count(), 1);
    drop(t);
    assert!(
        !dir.join("scripthash.head.oa_stub").exists(),
        "create must not write leftover sharded OA stub"
    );
    std::fs::create_dir_all(dir.join("scripthash.head.oa_stub")).unwrap();
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(
        !dir.join("scripthash.head.oa_stub").exists(),
        "open must unlink leftover oa_stub"
    );
    assert_eq!(t.head_shard_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn leftover_live_oa_main_open_refuses() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    put_create(&t, rec(script_hash(&[0x01]), 1, 0));
    t.flush().unwrap();
    drop(t);
    std::fs::write(dir.join("scripthash.head"), b"leftover-oa").unwrap();
    match ScriptHashTable::open_tiny(&dir) {
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    put_create(&t, rec(script_hash(&[0x02]), 1, 0));
    t.flush().unwrap();
    drop(t);
    let ovf = dir.join("scripthash.ovf");
    std::fs::create_dir_all(&ovf).unwrap();
    std::fs::write(ovf.join("000000"), b"not-shsr").unwrap();
    match ScriptHashTable::open_tiny(&dir) {
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh0 = script_hash(&[0xc0, 0, 0, 0x11]);
    put_create(&t, rec(sh0, 1, 0));
    let mut batch = vec![rec(sh0, 99_999, 1)];
    for i in 0..20u32 {
        let sh = script_hash(&[0xc1, (i & 0xff) as u8, 0x22, 0x33]);
        batch.push(rec(sh, 10_000 + u64::from(i), 0));
    }
    assert_eq!(put_create_batch(&t, batch), 21);
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    put_unique(&t, 0xa0, 80);
    let sh0 = script_hash(&[0xa0, 0, 0, 0x7e]);
    put_create(&t, rec(sh0, 10_000, 1));
    assert_eq!(t.entries(&sh0).unwrap().len(), 2);
    t.flush().unwrap();
    drop(t);
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(t.entries(&sh0).unwrap().len(), 2);
    assert!(!dir.join("scripthash.head").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Empty SHAL v1 (schema-13 body) opens and is rewritten to alloc v2.
#[test]
fn open_empty_alloc_v1_upgrades_to_v2() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
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

    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(!t.has_durable_index());
    drop(t);
    assert_eq!(
        read_alloc_version_on_disk(&TableFile::open(&body_path, TableKind::ScriptHash).unwrap())
            .unwrap(),
        SH_ALLOC_VERSION,
        "empty v1 must be rewritten to current alloc version"
    );
    // Reopen stays v2.
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    put_create(&t, rec(script_hash(&[0x42]), 1, 0));
    assert_eq!(t.entries(&script_hash(&[0x42])).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Durable SH with alloc v1 is refused (slab body incompatible with page chains).
#[test]
fn open_durable_alloc_v1_refused() {
    let dir = tmp();
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create(&t, rec(script_hash(&[0x99]), 7, 0));
        assert!(t.has_index_occupancy());
        assert!(!t.has_durable_index());
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

    match ScriptHashTable::open_tiny(&dir) {
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
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create(&t, rec(script_hash(&[0x01]), 1, 0));
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
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(!dir
        .join(crate::scripthash_overflow::LEGACY_OVERFLOW_HEAD)
        .exists());
    assert_eq!(t.entries(&script_hash(&[0x01])).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn freelist_reuses_page() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh1 = script_hash(&[0x61]);
    let sh2 = script_hash(&[0x62]);
    for i in 1..=3u64 {
        put_create(&t, rec(sh1, i, i as u32));
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
        put_create(&t, rec(sh2, 10 + i, i as u32));
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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

    put_create(&t, rec(sh_main, 3, 0));
    assert_eq!(t.entries(&sh_main).unwrap().len(), 3);
    assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));

    put_create(&t, rec(sh_new, 10, 0));
    assert_eq!(t.entries(&sh_new).unwrap().len(), 1);
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    put_create(&t, rec(sh_new, 11, 0));
    assert_eq!(t.entries(&sh_new).unwrap().len(), 2);
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    t.flush().unwrap();
    drop(t);
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(t.entries(&sh_main).unwrap().len(), 3);
    assert_eq!(t.entries(&sh_new).unwrap().len(), 2);
    assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
    assert!(matches!(t.key_home(&sh_new).unwrap(), KeyHome::Ingest));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reopen_after_ingest_seal_and_unlink_homes() {
    {
        let dir = tmp();
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
            put_create(&t, rec(sh, 1000 + u64::from(i), 0));
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1);
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));
        put_create(&t, rec(first_new, 1999, 0));
        assert_eq!(t.entries(&first_new).unwrap().len(), 2);

        t.unlink_create(&sh_main, Fk(1), 0).unwrap();
        assert!(t.entries(&sh_main).unwrap().is_empty());
        t.unlink_create(&first_new, Fk(1000), 0).unwrap();
        t.unlink_create(&first_new, Fk(1999), 0).unwrap();
        assert!(t.entries(&first_new).unwrap().is_empty());

        t.flush().unwrap();
        drop(t);
        let t = ScriptHashTable::open_tiny(&dir).unwrap();
        assert!(t.entries(&sh_main).unwrap().is_empty());
        assert!(t.entries(&first_new).unwrap().is_empty());
        assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn compact_merges_two_sealed_global_ovf_files() {
    {
        let dir = tmp();
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
            put_create(&t, rec(sh, 1000 + u64::from(i), 0));
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1, "first ingest seal");
        for i in 0..210u32 {
            let sh = script_hash(&[0xa2, (i & 0xff) as u8, (i >> 8) as u8, 0x02]);
            if i == 0 {
                second_new = sh;
            }
            put_create(&t, rec(sh, 2000 + u64::from(i), 0));
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 2, "second ingest seal");

        t.compact_sealed_ovf().unwrap();
        assert_eq!(
            t.sealed_ovf.lock().unwrap().len(),
            0,
            "L0 unlinked after promote"
        );
        assert_no_l0_ovf_leftover(&dir);
        assert!(
            t.ovf_l1.lock().unwrap().is_some(),
            "compact promotes L1 MPHF"
        );
        assert_eq!(
            t.ovf_l1
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .fuse
                .fingerprint_heap_bytes(),
            0,
            "L1 fuse is mapped, not the build Box"
        );
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);
        assert_eq!(t.entries(&second_new).unwrap().len(), 1);
        assert_eq!(t.entries(&sh_main).unwrap().len(), 1);
        assert!(matches!(t.key_home(&sh_main).unwrap(), KeyHome::Main));
        assert!(matches!(
            t.key_home(&first_new).unwrap(),
            KeyHome::SealedOvf
        ));
        let mut walked = 0u64;
        t.for_each_live_create(|_| walked += 1).unwrap();
        assert_eq!(
            walked, 421,
            "occupancy walk must include compacted overflow L1"
        );

        t.compact_sealed_ovf().unwrap();
        assert!(t.ovf_l1.lock().unwrap().is_some());
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 0);
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);

        for i in 0..210u32 {
            let sh = script_hash(&[0xa3, (i & 0xff) as u8, (i >> 8) as u8, 0x03]);
            put_create(&t, rec(sh, 3000 + u64::from(i), 0));
        }
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1);
        t.compact_sealed_ovf().unwrap();
        assert_eq!(t.sealed_ovf.lock().unwrap().len(), 1, "L1 frozen: L0 stays");
        assert_eq!(t.entries(&first_new).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn bulk_session_packs_exact_class_from_count() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let mut session = t.bulk_session(16).unwrap();
    let cases: &[(u8, u32)] = &[(0x01, 1), (0x02, 2), (0x06, 6), (0x14, 20), (0x60, 600)];
    for &(tag, n) in cases {
        let mut sh = [0u8; 32];
        sh[0] = tag;
        let ents: Vec<_> = (1..=u64::from(n)).map(Fk).collect();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    let t2 = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(t2.entry_count(), creates);
    assert_eq!(t2.entries(&sh0).unwrap().len(), 8);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_stream_megakey_caps_buf_at_page() {
    use crate::scripthash_pages::SH_PAGE_STREAM_MAX;
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
fn pack_one_shard() {
    {
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
    }
}

/// Mainnet ingest is 2^25 slots. Sealing a shard must not walk that table when
/// occupancy is already known to be zero: one pass per shard holds tip entry
/// past the RPC cookie window. A truncated ingest file makes a walk fail.
#[test]
fn empty_ingest_shard_seal_does_not_walk_slots() {
    let dir = tmp();
    let t = ScriptHashTable::create(dir.path()).unwrap();
    assert!(t.head_is_empty());
    let ingest = ingest_path(dir.path());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&ingest)
        .unwrap()
        .set_len(0)
        .unwrap();
    let session = t.pack_shard_session(0).unwrap();
    let pack = session.finish_pack().unwrap();
    t.publish_packed_shard(0, pack)
        .expect("known-empty ingest is not scanned");
}

fn shard0_key(i: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = i & 0x3f;
    k
}

#[test]
fn pack_shard_session_inline_one_fk_does_not_grow_body() {
    {
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
    }
}

#[test]
fn pack_shard_session_slab_flush_times_body_and_roundtrips() {
    {
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
    }
}

#[test]
fn create_fks_matches_entries() {
    {
        let dir = tmp();
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        let one = script_hash(&[0x01]);
        put_create(&t, rec(one, 7, 0));
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
        put_create(&t, rec(two, 1, 0));
        put_create(&t, rec(two, 2, 0));
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
        put_create_batch(&t, recs);
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
    }
}

#[test]
fn bulk_dense_five_fks_use_class0_slab() {
    {
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
    }
}

#[test]
fn bulk_dense_over_cap_stays_slab_until_deltas_fill() {
    {
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
    }
}

#[test]
fn bulk_reuses_page_align_gap_for_later_slab() {
    {
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
    }
}

fn four_shard_table(dir: &std::path::Path) -> ScriptHashTable {
    four_shard_dir_table(dir)
}

fn shared_body_table(dir: &std::path::Path) -> Result<ScriptHashTable, StoreError> {
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
    ScriptHashTable::open_tiny(dir)
}

#[test]
fn bulk_session_stream_small_key_still_slab() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let n = SH_PAGE_EXTENT_STREAM_MAX + 8;
    let mut sh = [0u8; 32];
    sh[0] = 0x11;
    let ents: Vec<_> = (1..=n as u64).map(Fk).collect();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX + 8;
    let mut sh = [0u8; 32];
    sh[0] = 0x12;
    let ents: Vec<_> = (1..=n as u64).map(Fk).collect();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    // Sequential FKs fill ~4080/page; this n spans two pages.
    let n = SH_PAGE_STREAM_MAX + 10;
    let mut sh = [0u8; 32];
    sh[0] = 0x10;
    sh[1] = 0xee;
    let ents: Vec<_> = (1..=n as u64).map(Fk).collect();
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
    let got2 = t.entries(&sh).unwrap();
    assert_eq!(got2.len(), n);
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
    assert_eq!(put_create_batch(&t, recs), n);
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX - 1;
    let mut sh = [0u8; 32];
    sh[0] = 0x21;
    sh[1] = 0xaa;
    let ents: Vec<_> = (1..=n as u64).map(Fk).collect();
    let mut sh_gap = [0u8; 32];
    sh_gap[0] = 0x21;
    sh_gap[1] = 0xab;
    let mut session = t.bulk_session(2).unwrap();
    session.put_chain(sh, &ents).unwrap();
    session.put_chain(sh_gap, &[Fk(1), Fk(2)]).unwrap();
    let _ = session.finish().unwrap();
    let (base, last0, n0) = extent_meta(&t, &sh);
    assert_eq!(n0, 2);
    put_create(&t, rec(sh, n as u64 + 1, 0));
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
    let extra2: Vec<_> = ((n as u64 + 2)..=(n as u64 + 1 + SH_PAGE_EXTENT_STREAM_MAX as u64))
        .map(|i| rec(sh, i, 0))
        .collect();
    assert_eq!(put_create_batch(&t, &extra2), extra2.len());
    let (_, last2, n2) = extent_meta(&t, &sh);
    assert_eq!(n2, 2);
    assert_ne!(last2, last1, "second overflow adds another linked page");
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1 + extra2.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extent_append_glued_bumps_extent_n() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let n = SH_PAGE_STREAM_MAX + SH_PAGE_EXTENT_STREAM_MAX - 1;
    let mut sh = [0u8; 32];
    sh[0] = 0x22;
    let ents: Vec<_> = (1..=n as u64).map(Fk).collect();
    let mut session = t.bulk_session(1).unwrap();
    session.put_chain(sh, &ents).unwrap();
    let _ = session.finish().unwrap();
    let (base, _, n0) = extent_meta(&t, &sh);
    assert_eq!(n0, 2);
    put_create(&t, rec(sh, n as u64 + 1, 0));
    let (_, last, n1) = extent_meta(&t, &sh);
    assert_eq!(n1, 3, "glued HWM grows extent_n in place");
    assert_eq!(last, base + 2 * SH_PAGE_SIZE as u64);
    assert_eq!(t.entries(&sh).unwrap().len(), n + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bulk_session_put_sorted_creates_dedups() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    {
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
    }
}

#[test]
fn live_session_does_not_size_from_create_count() {
    // Regression: bulk_session(total_recs) used to allocate create-count-sized
    // OA images. unique_hint=1000 must not allocate a multi-GiB table.
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
    {
        let dir = tmp();
        let _t = ScriptHashTable::create_tiny(&dir).unwrap();
        drop(_t);
        std::fs::create_dir_all(dir.join("scripthash.head")).unwrap();
        std::fs::write(dir.join("scripthash.head").join("00"), b"leftover-oa").unwrap();

        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        std::fs::write(runs_dir.join("000001.run"), b"leftover").unwrap();

        match ScriptHashTable::open_tiny(&dir) {
            Ok(_) => panic!("leftover OA must refuse"),
            Err(StoreError::Layout(m)) => {
                assert!(m.contains("scripthash*"), "{m}");
            }
            Err(e) => panic!("expected Layout, got {e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn open_refuses_legacy_head_without_runs() {
    {
        let dir = tmp();
        let _t = ScriptHashTable::create_tiny(&dir).unwrap();
        drop(_t);
        std::fs::create_dir_all(dir.join("scripthash.head")).unwrap();
        std::fs::write(dir.join("scripthash.head").join("00"), b"leftover-oa").unwrap();
        match ScriptHashTable::open_tiny(&dir) {
            Err(StoreError::Layout(m)) => {
                assert!(m.contains("scripthash*"), "{m}");
            }
            Ok(_) => panic!("expected leftover OA refuse"),
            Err(e) => panic!("unexpected error: {e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn for_each_live_create_skips_unlinked() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
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
        if prefix_shard_of(&script_hash(&script), n_shards) == shard {
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
        if prefix_shard_of(&sh, n_shards) == shard {
            found.push((script, sh));
            if found.len() >= 8 {
                break;
            }
        }
    }
    found.sort_by_key(|a| a.1);
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

fn decode_post_keys(dir: &std::path::Path, shard: usize) -> Vec<[u8; 16]> {
    load_post_shard_entries(dir, shard)
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect()
}

#[test]
fn unsorted_collect_unique_keys_per_shard() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let script = vec![0x51];
        let mut txid_a = [0u8; 32];
        txid_a[0] = 1;
        let mut txid_b = [0u8; 32];
        txid_b[0] = 2;
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid_a, script.clone())], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid_b, script.clone())], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([3u8; 32], vec![0x52])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([4u8; 32], vec![0x53])], true)
            .unwrap();
        let udir = dir.join("unsorted");
        rbitcoin_log::capture_logs(true);
        let out = crate::collect_unsorted_shard_files(&s, &udir, n_shards, 2, None).unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let info: Vec<&str> = logs
            .iter()
            .filter_map(|(level, m)| (*level == rbitcoin_log::Level::Info).then_some(m.as_str()))
            .collect();
        assert!(
            info.iter()
                .any(|m| m.contains("scripthash keys collect start workers=")
                    && m.contains("budget_MiB=")),
            "keys collect workers and budget, got {info:?}"
        );
        let merge_starts: Vec<&str> = info
            .iter()
            .copied()
            .filter(|m| m.contains("scripthash keys merge start"))
            .collect();
        assert_eq!(merge_starts.len(), 1, "one keys merge start, got {info:?}");
        assert!(
            merge_starts[0].contains("n_shards=") && merge_starts[0].contains("workers="),
            "keys merge start workers, got {info:?}"
        );
        assert!(
            info.iter().any(|m| {
                m.contains("scripthash keys merge shard=")
                    && m.contains("fold=")
                    && m.contains("bdz=")
            }),
            "live merge shard fold/bdz, got {info:?}"
        );
        assert_eq!(out.per_shard.len(), n_shards);
        assert!(unsorted_done_last_fk(&udir, n_shards).is_some());
        assert!(udir.join("DONE.keys").is_file());
        let magic = std::fs::read(udir.join("DONE.keys")).unwrap();
        assert_eq!(&magic[0..8], b"SHKEYS02");
        assert!(!udir.join("DONE").is_file());
        let sh_dupe = script_hash(&script);
        let si = prefix_shard_of(&sh_dupe, n_shards);
        assert!(
            !unsorted_keys_path(&udir, si).exists(),
            "RAM merge unlinks keys/{si:02x}"
        );
        let base = sorted_main_shard_path(s.path(), si, n_shards);
        let h = MphfHead::open(&base).unwrap();
        let k_script = head_key_from_full(&sh_dupe);
        assert_eq!(h.get(&k_script).unwrap().unwrap(), ShHeadValue::Empty);
        assert_eq!(
            h.get(&head_key_from_full(&script_hash(&[0x52])))
                .unwrap()
                .unwrap(),
            ShHeadValue::inline_one(Fk(3))
        );
        assert_eq!(
            h.get(&head_key_from_full(&script_hash(&[0x53])))
                .unwrap()
                .unwrap(),
            ShHeadValue::inline_one(Fk(4))
        );
        assert_eq!(out.per_shard[si], 3, "dupe collapsed; two singles kept");
        assert!(unsorted_multi_fuse_path(&udir, si).is_file());
        for shard in 0..n_shards {
            assert!(
                !unsorted_keys_path(&udir, shard).exists(),
                "keys unlinked after head + fuse"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn keys_merge_seals_head_and_multi_fuse_without_keys_file() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        let n_shards = s.scripthash.head_shard_count();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], vec![0x51])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([3u8; 32], vec![0x52])], true)
            .unwrap();
        let udir = crate::unsorted_shard_dir(s.path());
        let out = crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        let sh_dupe = script_hash(&[0x51]);
        let si = prefix_shard_of(&sh_dupe, n_shards);
        assert!(
            !unsorted_keys_path(&udir, si).exists(),
            "merge folds spills to head + fuse and unlinks keys/NN/"
        );
        let base = sorted_main_shard_path(s.path(), si, n_shards);
        assert!(MphfHead::exists(&base), "map fold writes scripthash.head");
        assert!(
            unsorted_multi_fuse_path(&udir, si).is_file(),
            "dupe mix64 lands in multi fuse8, not a unique keys file"
        );
        assert_eq!(out.per_shard[si], 2, "dupe script + distinct script");
        let h = MphfHead::open(&base).unwrap();
        let k_dupe = head_key_from_full(&sh_dupe);
        assert_eq!(h.get(&k_dupe).unwrap().unwrap(), ShHeadValue::Empty);
        assert_eq!(
            h.get(&head_key_from_full(&script_hash(&[0x52])))
                .unwrap()
                .unwrap(),
            ShHeadValue::inline_one(Fk(3))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn leftover_shunsrt3_has_no_done_keys_and_recollects() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        std::fs::create_dir_all(&udir).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SHUNSRT3");
        buf.extend_from_slice(&(n_shards as u32).to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        for _ in 0..n_shards {
            buf.extend_from_slice(&1u64.to_le_bytes());
        }
        std::fs::write(udir.join("DONE"), &buf).unwrap();
        std::fs::write(unsorted_shard_path(&udir, 0), [0u8; 24]).unwrap();
        assert!(unsorted_done_last_fk(&udir, n_shards).is_none());
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        assert!(udir.join("DONE.keys").is_file());
        assert!(!udir.join("DONE").is_file());
        assert!(!unsorted_shard_path(&udir, 0).is_file());
        assert!(
            !unsorted_keys_path(&udir, 0).exists(),
            "recollect merge writes head, not keys"
        );
        let base = sorted_main_shard_path(s.path(), 0, n_shards);
        assert!(MphfHead::exists(&base));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn mphf_from_keys_unlinks_key_file_and_hits() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        rbitcoin_log::capture_logs(true);
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        seal_mphf_from_keys(&s.scripthash, &udir, n_shards, None).unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let sh = script_hash(&[0x51]);
        let si = prefix_shard_of(&sh, n_shards);
        let info: Vec<&str> = logs
            .iter()
            .filter_map(|(level, m)| (*level == rbitcoin_log::Level::Info).then_some(m.as_str()))
            .collect();
        assert_eq!(
            info.iter()
                .filter(|m| m.contains("scripthash keys merge start"))
                .count(),
            1,
            "one keys merge start, got {info:?}"
        );
        assert!(
            info.iter().any(|m| {
                m.contains(&format!("scripthash keys merge shard={si:02x}"))
                    && m.contains("fold=")
                    && m.contains("bdz=")
            }),
            "live merge shard fold/bdz, got {info:?}"
        );
        assert!(
            !unsorted_keys_path(&udir, si).exists(),
            "keys dir unlinked after MPHF"
        );
        let base = sorted_main_shard_path(s.path(), si, n_shards);
        assert!(MphfHead::exists(&base));
        assert!(!MphfHead::exists(&unsorted_mphf_base(&udir, si)));
        let h = MphfHead::open(&base).unwrap();
        let key = head_key_from_full(&sh);
        assert!(h.slot_for_key16(&key).is_ok());
        let val = h.get(&key).unwrap().unwrap();
        assert_eq!(val, ShHeadValue::inline_one(Fk(1)));
        assert!(
            s.scripthash.unsealed_main_shards().contains(&si),
            "head files are not a pack seal"
        );
        assert!(
            !unsorted_multi_fuse_path(&udir, si).is_file(),
            "single key is not a fuse8"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn mphf_from_keys_multi_is_empty_and_existing_head_does_not_skip_pack() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        seal_mphf_from_keys(&s.scripthash, &udir, n_shards, None).unwrap();
        let sh = script_hash(&[0x51]);
        let si = prefix_shard_of(&sh, n_shards);
        let base = sorted_main_shard_path(s.path(), si, n_shards);
        let h = MphfHead::open(&base).unwrap();
        let key = head_key_from_full(&sh);
        assert!(h.get(&key).unwrap().unwrap().is_empty());
        drop(h);
        assert!(
            unsorted_multi_fuse_path(&udir, si).is_file(),
            "0xFFFF key writes unsorted/multi fuse8"
        );
        let fuse = SealedFuse8::read_from(&unsorted_multi_fuse_path(&udir, si)).unwrap();
        assert!(fuse.contains(mix_key16(&key)));
        assert!(s.scripthash.unsealed_main_shards().contains(&si));
        s.scripthash.reinit_empty_for_cold_materialize().unwrap();
        assert!(
            s.scripthash.unsealed_main_shards().contains(&si),
            "RAM unsealed after reinit even if head files exist"
        );
        assert!(MphfHead::exists(&base));
        std::fs::remove_file(udir.join("DONE.keys")).unwrap();
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        seal_mphf_from_keys(&s.scripthash, &udir, n_shards, None).unwrap();
        let h = MphfHead::open(&base).unwrap();
        assert!(h.get(&key).unwrap().unwrap().is_empty());
        assert!(s.scripthash.unsealed_main_shards().contains(&si));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn postings_collect_fuse_hits_skip_singles_and_logs_workers() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        let n_shards = s.scripthash.head_shard_count();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], vec![0x51])], true)
            .unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([3u8; 32], vec![0x52])], true)
            .unwrap();
        let udir = crate::unsorted_shard_dir(s.path());
        crate::collect_unsorted_shard_files(&s, &udir, n_shards, 2, None).unwrap();
        seal_mphf_from_keys(&s.scripthash, &udir, n_shards, None).unwrap();
        rbitcoin_log::capture_logs(true);
        crate::scripthash_materialize::collect_posts_covering(
            &s.txs,
            &s.scripthash,
            &udir,
            2,
            false,
            None,
        )
        .unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let info: Vec<&str> = logs
            .iter()
            .filter_map(|(level, m)| (*level == rbitcoin_log::Level::Info).then_some(m.as_str()))
            .collect();
        assert!(
            info.iter()
                .any(|m| m.contains("scripthash postings collect start workers=")
                    && m.contains("budget_MiB=")),
            "postings workers and budget, got {info:?}"
        );
        let k_multi = head_key_from_full(&script_hash(&[0x51]));
        let k_single = head_key_from_full(&script_hash(&[0x52]));
        let si = prefix_shard_of(&script_hash(&[0x51]), n_shards);
        let posted = decode_post_keys(&udir, si);
        assert!(
            posted.contains(&k_multi),
            "multi creates land in post, got {posted:?}"
        );
        let n_single = posted.iter().filter(|k| **k == k_single).count();
        assert!(
            n_single <= 1,
            "single is fuse-miss or at most an FP, got {n_single}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn pack_slot_stream_leaves_recs_empty_and_roundtrips() {
    let dir = tmp();
    let t = four_shard_dir_table(&dir);
    let n_shards = t.head_shard_count();
    let (low, high) = two_scripts_same_shard_reverse_hash(0, n_shards);
    let sh_lo = script_hash(&low);
    let sh_hi = script_hash(&high);
    let k_lo = head_key_from_full(&sh_lo);
    let k_hi = head_key_from_full(&sh_hi);
    let base = sorted_main_shard_path(t.store_dir(), 0, n_shards);
    MphfHead::write_pack8(&base, &[(k_lo, 0), (k_hi, 0)]).unwrap();
    let head = MphfHead::open(&base).unwrap();
    let slot_lo = head.slot_for_key16(&k_lo).unwrap();
    let slot_hi = head.slot_for_key16(&k_hi).unwrap();
    drop(head);
    let mut session = t.pack_shard_session(0).unwrap();
    session.push_sorted_slot_fk(slot_lo, Fk(2)).unwrap();
    session.push_sorted_slot_fk(slot_lo, Fk(5)).unwrap();
    session.push_sorted_slot_fk(slot_hi, Fk(4)).unwrap();
    session.push_sorted_slot_fk(slot_hi, Fk(8)).unwrap();
    let pack = session.finish_pack().unwrap();
    assert!(
        pack.recs.is_empty(),
        "slot pack must not store a dummy key, recs={}",
        pack.recs.len()
    );
    assert_eq!(pack.slot_words.len(), 2);
    assert!(pack.slot_words.iter().any(|(s, _)| *s == slot_lo));
    assert!(pack.slot_words.iter().any(|(s, _)| *s == slot_hi));
    t.publish_packed_shard(0, pack).unwrap();
    let fks = |sh: &[u8; 32]| -> Vec<u64> {
        t.entries(sh).unwrap().into_iter().map(|e| e.0 .0).collect()
    };
    assert_eq!(fks(&sh_lo), vec![2, 5]);
    assert_eq!(fks(&sh_hi), vec![4, 8]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsorted_pack_sorts_numeric_fk_and_keeps_all_creates() {
    {
        let dir = tmp();
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let n_shards = 4usize;
        let udir = sh_dir.join(UNSORTED_SHARD_DIR);
        std::fs::create_dir_all(udir.join("keys")).unwrap();
        std::fs::create_dir_all(udir.join("post")).unwrap();
        let (low, high) = two_scripts_same_shard_reverse_hash(1, n_shards);
        let sh_lo = script_hash(&low);
        let sh_hi = script_hash(&high);
        let k_lo = head_key_from_full(&sh_lo);
        let k_hi = head_key_from_full(&sh_hi);
        write_keys_spill_entries(&udir, 1, 0, &[(k_lo, None), (k_hi, None)]).unwrap();
        for shard in [0usize, 2, 3] {
            write_keys_spill_entries(&udir, shard, 0, &[]).unwrap();
        }
        seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
        drop(MphfHead::open(sorted_main_shard_path(&sh_dir, 1, n_shards)).unwrap());
        write_post_spill_entries(&udir, 1, 0, &[(k_hi, &[2u64][..]), (k_lo, &[3u64, 1][..])])
            .unwrap();
        write_post_spill_entries(&udir, 1, 1, &[(k_hi, &[256u64][..])]).unwrap();
        rbitcoin_log::capture_logs(true);
        let mat = materialize_sh_from_unsorted(&table, &udir, 1, None).unwrap();
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
            "fk 256 must sort after 2 after reconstruct from two segments"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn unsorted_pack_skips_one_fk_fuse_fp_and_rewrites_multi() {
    {
        let dir = tmp();
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let n_shards = 4usize;
        let udir = sh_dir.join(UNSORTED_SHARD_DIR);
        std::fs::create_dir_all(udir.join("keys")).unwrap();
        std::fs::create_dir_all(udir.join("post")).unwrap();
        let script_fp = script_for_prefix_shard(1, n_shards);
        let script_multi = script_for_prefix_shard(2, n_shards);
        let sh_fp = script_hash(&script_fp);
        let sh_multi = script_hash(&script_multi);
        let k_fp = head_key_from_full(&sh_fp);
        let k_multi = head_key_from_full(&sh_multi);
        write_keys_spill_entries(&udir, 1, 0, &[(k_fp, Some(Fk(7)))]).unwrap();
        write_keys_spill_entries(&udir, 2, 0, &[(k_multi, None)]).unwrap();
        for shard in [0usize, 3] {
            write_keys_spill_entries(&udir, shard, 0, &[]).unwrap();
        }
        seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
        let bump_fp = table.bodies[1].logical_len();
        write_post_spill_entries(&udir, 1, 0, &[(k_fp, &[7u64][..])]).unwrap();
        write_post_spill_entries(&udir, 2, 0, &[(k_multi, &[10u64, 11][..])]).unwrap();
        rbitcoin_log::capture_logs(true);
        let mat = materialize_sh_from_unsorted(&table, &udir, 2, None).unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let info: Vec<&str> = logs
            .iter()
            .filter_map(|(level, m)| (*level == rbitcoin_log::Level::Info).then_some(m.as_str()))
            .collect();
        assert!(
            info.iter()
                .any(|m| m.contains("scripthash unsorted pack start") && m.contains("workers=2")),
            "pack start workers, got {info:?}"
        );
        if let Some(pack_done_idx) = info
            .iter()
            .position(|m| m.contains("scripthash unsorted pack done"))
        {
            if let Some(first_shard_idx) = info
                .iter()
                .position(|m| m.contains("scripthash unsorted pack shard="))
            {
                assert!(
                    first_shard_idx < pack_done_idx,
                    "pack shard line before pack done, got {info:?}"
                );
            }
        }
        assert_eq!(
            table.unsealed_main_shards().len(),
            0,
            "pack_workers=2 must finish every unsealed shard"
        );
        assert_eq!(
            table.bodies[1].logical_len(),
            bump_fp,
            "1-fk skip must not grow body"
        );
        assert_eq!(
            table
                .entries(&sh_fp)
                .unwrap()
                .into_iter()
                .map(|e| e.0 .0)
                .collect::<Vec<_>>(),
            vec![7]
        );
        let mut multi: Vec<u64> = table
            .entries(&sh_multi)
            .unwrap()
            .into_iter()
            .map(|e| e.0 .0)
            .collect();
        multi.sort_unstable();
        assert_eq!(multi, vec![10, 11]);
        let h = MphfHead::open(sorted_main_shard_path(&sh_dir, 2, n_shards)).unwrap();
        let val = h.get(&k_multi).unwrap().unwrap();
        assert!(!val.is_empty(), "2+ fks rewrite Empty → body");
        assert!(mat.creates >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn unsorted_combined_skips_collect_when_done_and_resumes_unsealed() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
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
        let udir = sh_dir.join(UNSORTED_SHARD_DIR);
        crate::scripthash_materialize::collect_unsorted_covering_txs(
            &s.txs, &table, &udir, n_shards, 1, false, None,
        )
        .unwrap();
        materialize_sh_from_unsorted_from_txs(&table, &s.txs, &udir, 1, 1, None).unwrap();
        assert!(table.unsealed_main_shards().is_empty());
        let again = materialize_sh_from_unsorted(&table, &udir, 2, None).unwrap();
        assert_eq!(again.creates, 4);
        for k in &keys {
            assert_eq!(table.entries(k).unwrap().len(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn unsorted_cancel_before_collect_is_cancelled() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let cancel = AtomicBool::new(true);
        let err = crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, Some(&cancel)).unwrap_err();
        assert!(
            matches!(err, StoreError::Cancelled(_)),
            "expected Cancelled, got {err}"
        );
        let udir = crate::unsorted_shard_dir(s.path());
        assert!(
            unsorted_done_last_fk(&udir, s.scripthash.head_shard_count()).is_none(),
            "cancel must not write DONE.keys"
        );
        assert!(!udir.join("DONE.keys").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn pass1_mphf_is_not_a_durable_head_on_reopen() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let script = vec![0x51];
    s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], script.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], script.clone())], true)
        .unwrap();
    let n_shards = s.scripthash.head_shard_count();
    let udir = crate::unsorted_shard_dir(s.path());
    crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
    assert!(udir.join("DONE.keys").is_file());
    assert!(!udir.join("DONE.post").is_file());
    drop(s);
    let s = crate::Store::open_tiny(&dir).unwrap();
    assert!(
        !s.scripthash.has_durable_index(),
        "pass-1 mphf is not a durable head"
    );
    assert!(
        !s.scripthash.unsealed_main_shards().is_empty(),
        "pass-1 mphf must stay unsealed until pack"
    );
    crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    let sh = script_hash(&script);
    let mut fks: Vec<u64> = s
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|e| e.0 .0)
        .collect();
    fks.sort_unstable();
    assert_eq!(fks, vec![1, 2]);
    assert!(s.scripthash.has_durable_index());
    let base = sorted_main_shard_path(s.path(), 0, s.scripthash.head_shard_count());
    assert!(shard_pack_mark_path(&base).is_file());
    let again = crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    assert_eq!(again.keys, 0, "packed head must not collect again");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pass1_lying_include_hwm_still_resumes_pass2() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let script = vec![0x51];
    s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], script.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], script.clone())], true)
        .unwrap();
    let n_shards = s.scripthash.head_shard_count();
    let udir = crate::unsorted_shard_dir(s.path());
    crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
    store_include_hwm(s.path(), 99).unwrap();
    drop(s);
    let s = crate::Store::open_tiny(&dir).unwrap();
    assert!(!s.scripthash.has_durable_index());
    assert_eq!(s.scripthash.include_hwm(), 99);
    crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    let mut fks: Vec<u64> = s
        .scripthash
        .entries(&script_hash(&script))
        .unwrap()
        .into_iter()
        .map(|e| e.0 .0)
        .collect();
    fks.sort_unstable();
    assert_eq!(fks, vec![1, 2]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pass1_ingest_append_does_not_hide_packed_history() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let script = vec![0x51];
    s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], script.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], script.clone())], true)
        .unwrap();
    let n_shards = s.scripthash.head_shard_count();
    let udir = crate::unsorted_shard_dir(s.path());
    crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
    let rec = ScriptHashRecord::from_fk(script_hash(&script), Fk(2));
    let mut heads = std::collections::HashMap::new();
    s.scripthash
        .put_create_batch_append(&[rec], &mut heads)
        .unwrap();
    crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    let mut fks: Vec<u64> = s
        .scripthash
        .entries(&script_hash(&script))
        .unwrap()
        .into_iter()
        .map(|e| e.0 .0)
        .collect();
    fks.sort_unstable();
    assert_eq!(fks, vec![1, 2]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_unmarked_head_soft_migrates_without_rescan() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let script = vec![0x51];
    s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], script.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], script.clone())], true)
        .unwrap();
    crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    assert!(s.scripthash.has_durable_index());
    let n_shards = s.scripthash.head_shard_count();
    let base = sorted_main_shard_path(s.path(), 0, n_shards);
    std::fs::remove_file(shard_pack_mark_path(&base)).unwrap();
    let _ = std::fs::remove_file(dir.join(crate::INCLUDE_HWM_NAME));
    drop(s);
    let s = crate::Store::open_tiny(&dir).unwrap();
    assert!(
        shard_pack_mark_path(&base).is_file(),
        "complete unmarked head must gain .packed"
    );
    assert!(s.scripthash.has_durable_index());
    assert!(s.scripthash.include_hwm() > 0);
    let again = crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    assert_eq!(again.keys, 0);
    let mut fks: Vec<u64> = s
        .scripthash
        .entries(&script_hash(&script))
        .unwrap()
        .into_iter()
        .map(|e| e.0 .0)
        .collect();
    fks.sort_unstable();
    assert_eq!(fks, vec![1, 2]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn partial_post_spills_without_done_post_are_recollected() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let multi = vec![0x51];
    let single = vec![0x52];
    s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], multi.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([2u8; 32], multi.clone())], true)
        .unwrap();
    s.put_tx_full_batch_indexed(&[class_a_coinbase([3u8; 32], single.clone())], true)
        .unwrap();
    let n_shards = s.scripthash.head_shard_count();
    let udir = crate::unsorted_shard_dir(s.path());
    crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
    let spill = udir.join("post").join("00");
    std::fs::create_dir_all(&spill).unwrap();
    std::fs::write(spill.join("000000"), b"not-a-finished-post").unwrap();
    assert!(!udir.join("DONE.post").is_file());
    crate::materialize_sh_unsorted_from_class_a(&s, 1, 1, None).unwrap();
    let mut multi_fks: Vec<u64> = s
        .scripthash
        .entries(&script_hash(&multi))
        .unwrap()
        .into_iter()
        .map(|e| e.0 .0)
        .collect();
    multi_fks.sort_unstable();
    assert_eq!(multi_fks, vec![1, 2]);
    assert_eq!(
        s.scripthash
            .entries(&script_hash(&single))
            .unwrap()
            .into_iter()
            .map(|e| e.0 .0)
            .collect::<Vec<_>>(),
        vec![3]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn packed_subset_reopen_packs_the_rest_once() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
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
    let udir = sh_dir.join(UNSORTED_SHARD_DIR);
    collect_unsorted_covering_txs(&s.txs, &table, &udir, n_shards, 1, false, None).unwrap();
    seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
    crate::scripthash_materialize::collect_posts_covering(&s.txs, &table, &udir, 1, false, None)
        .unwrap();
    pack_one_extract_shard(&table, &udir, 0).unwrap();
    pack_one_extract_shard(&table, &udir, 1).unwrap();
    assert!(shard_pack_mark_path(&sorted_main_shard_path(&sh_dir, 0, n_shards)).is_file());
    assert!(!shard_pack_mark_path(&sorted_main_shard_path(&sh_dir, 2, n_shards)).is_file());
    drop(table);
    let table = ScriptHashTable::open_tiny(&sh_dir).unwrap();
    assert!(!table.has_durable_index());
    let unsealed = table.unsealed_main_shards();
    assert!(!unsealed.contains(&0) && !unsealed.contains(&1));
    assert!(unsealed.contains(&2) && unsealed.contains(&3));
    materialize_sh_from_unsorted(&table, &udir, 1, None).unwrap();
    assert!(table.has_durable_index());
    for k in &keys {
        assert_eq!(table.entries(k).unwrap().len(), 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsorted_done_records_class_a_last_fk() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[class_a_coinbase([1u8; 32], vec![0x51])], true)
            .unwrap();
        let n_shards = s.scripthash.head_shard_count();
        let udir = crate::unsorted_shard_dir(s.path());
        let out = crate::collect_unsorted_shard_files(&s, &udir, n_shards, 1, None).unwrap();
        assert!(udir.join("DONE.keys").is_file());
        assert_eq!(out.last_fk, s.txs.count());
        assert_eq!(
            crate::unsorted_done_last_fk(&udir, n_shards),
            Some(s.txs.count())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn unsorted_materialize_appends_when_done_lags_and_no_shards() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
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
            "Class A grown after DONE.keys must be recollected before pack"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `(stage, done, total)` of the stages that ended on this thread since
/// `capture_finished(true)`; turns capture off. Other tests in the binary
/// build concurrently under the same stage names.
fn finished_here() -> Vec<(&'static str, u64, u64)> {
    let fin = rbitcoin_log::progress::take_finished()
        .into_iter()
        .map(|p| (p.stage, p.done, p.total))
        .collect();
    rbitcoin_log::progress::capture_finished(false);
    fin
}

/// Each pass of the unsorted build reports through the live progress
/// registry and ends at its total.
#[test]
fn unsorted_build_reports_each_pass_to_progress() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    for i in 0..8u8 {
        s.put_tx_full_batch_indexed(&[class_a_coinbase([i + 1; 32], vec![0x51 + i])], true)
            .unwrap();
    }
    rbitcoin_log::progress::capture_finished(true);
    crate::materialize_sh_unsorted_from_class_a(&s, 2, 2, None).unwrap();
    let mine = finished_here();
    let stages: Vec<_> = mine.iter().map(|p| p.0).collect();
    for stage in [
        "scripthash keys collect",
        "scripthash keys merge",
        "scripthash postings collect",
        "scripthash pack",
    ] {
        assert!(stages.contains(&stage), "{stage}: {mine:?}");
    }
    assert!(
        mine.iter()
            .all(|&(_, done, total)| total > 0 && done == total),
        "{mine:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Parallel merge and pack workers report each shard: four head shards, two
/// workers, every shard counted.
#[test]
fn unsorted_parallel_passes_count_every_shard() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let n_shards = 4usize;
    for shard in 0..n_shards {
        let script = script_for_prefix_shard(shard, n_shards);
        let mut txid = [0u8; 32];
        txid[0] = shard as u8;
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
            .unwrap();
    }
    let sh_dir = dir.join("sh4");
    std::fs::create_dir_all(&sh_dir).unwrap();
    let table = four_shard_dir_table(&sh_dir);
    let udir = sh_dir.join(UNSORTED_SHARD_DIR);
    rbitcoin_log::progress::capture_finished(true);
    crate::scripthash_materialize::collect_unsorted_covering_txs(
        &s.txs, &table, &udir, n_shards, 2, false, None,
    )
    .unwrap();
    materialize_sh_from_unsorted_from_txs(&table, &s.txs, &udir, 2, 2, None).unwrap();
    assert!(table.unsealed_main_shards().is_empty());
    let mine = finished_here();
    for stage in ["scripthash keys merge", "scripthash pack"] {
        assert!(mine.iter().any(|p| p.0 == stage), "{stage}: {mine:?}");
    }
    assert!(
        mine.iter()
            .all(|&(_, done, total)| total > 0 && done == total),
        "{mine:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A resumed pack starts at the shards already published, so `/progress`
/// does not drop to 0% after a restart. Cancel before the first new shard
/// leaves only that seed.
#[test]
fn unsorted_pack_resume_starts_at_published_shards() {
    let dir = tmp();
    let s = crate::Store::create_tiny(&dir).unwrap();
    let n_shards = 4usize;
    for shard in 0..n_shards {
        let script = script_for_prefix_shard(shard, n_shards);
        let mut txid = [0u8; 32];
        txid[0] = shard as u8;
        s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
            .unwrap();
    }
    let sh_dir = dir.join("sh4");
    std::fs::create_dir_all(&sh_dir).unwrap();
    let table = four_shard_dir_table(&sh_dir);
    let udir = sh_dir.join(UNSORTED_SHARD_DIR);
    crate::scripthash_materialize::collect_unsorted_covering_txs(
        &s.txs, &table, &udir, n_shards, 1, false, None,
    )
    .unwrap();
    seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
    pack_one_extract_shard(&table, &udir, 0).unwrap();
    assert_eq!(table.unsealed_main_shards().len(), 3);
    let cancel = AtomicBool::new(true);
    rbitcoin_log::progress::capture_finished(true);
    let err = materialize_sh_from_unsorted(&table, &udir, 1, Some(&cancel)).unwrap_err();
    let mine = finished_here();
    assert!(matches!(err, StoreError::Cancelled(_)), "{err}");
    assert_eq!(mine, [("scripthash pack", 1, 4)]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The keys merge from surviving key files counts in the fresh merge's frame:
/// shards with nothing to merge are done from the start, the rest as each
/// seals. Shard 0 has no key file here.
#[test]
fn keys_merge_resume_starts_at_shards_needing_no_merge() {
    let dir = tmp();
    let sh_dir = dir.join("sh4");
    std::fs::create_dir_all(&sh_dir).unwrap();
    let table = four_shard_dir_table(&sh_dir);
    let n_shards = 4usize;
    let udir = sh_dir.join(UNSORTED_SHARD_DIR);
    std::fs::create_dir_all(udir.join("keys")).unwrap();
    for shard in [1usize, 2, 3] {
        write_keys_spill_entries(&udir, shard, 0, &[]).unwrap();
    }
    rbitcoin_log::progress::capture_finished(true);
    seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
    let mine = finished_here();
    assert_eq!(mine, [("scripthash keys merge", 4, 4)]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pack_shard_unlinks_only_that_post_file() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
        let n_shards = 4usize;
        for shard in 0..n_shards {
            let script = script_for_prefix_shard(shard, n_shards);
            let mut txid = [0u8; 32];
            txid[0] = shard as u8;
            s.put_tx_full_batch_indexed(&[class_a_coinbase(txid, script)], true)
                .unwrap();
        }
        let sh_dir = dir.join("sh4");
        std::fs::create_dir_all(&sh_dir).unwrap();
        let table = four_shard_dir_table(&sh_dir);
        let udir = sh_dir.join(UNSORTED_SHARD_DIR);
        collect_unsorted_covering_txs(&s.txs, &table, &udir, n_shards, 1, false, None).unwrap();
        seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
        materialize_sh_from_unsorted_from_txs(&table, &s.txs, &udir, 1, 1, None).unwrap();
        assert!(
            table.unsealed_main_shards().is_empty(),
            "second pack via from_txs finishes remaining shards"
        );
        for shard in 0..n_shards {
            assert!(
                !unsorted_post_path(&udir, shard).exists(),
                "post/{shard:02x} unlinked after seal"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn pack_one_shard_unlinks_only_its_postings() {
    {
        let dir = tmp();
        let s = crate::Store::create_tiny(&dir).unwrap();
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
        let udir = sh_dir.join(UNSORTED_SHARD_DIR);
        collect_unsorted_covering_txs(&s.txs, &table, &udir, n_shards, 1, false, None).unwrap();
        seal_mphf_from_keys(&table, &udir, n_shards, None).unwrap();
        crate::scripthash_materialize::collect_posts_covering(
            &s.txs, &table, &udir, 1, false, None,
        )
        .unwrap();
        pack_one_extract_shard(&table, &udir, 0).unwrap();
        assert!(!unsorted_post_path(&udir, 0).exists(), "post/00 unlinked");
        let unsealed = table.unsealed_main_shards();
        assert!(!unsealed.contains(&0), "shard 0 packed");
        for shard in 1..n_shards {
            assert!(
                unsealed.contains(&shard),
                "shard {shard} remains unsealed until pack, unsealed={unsealed:?}"
            );
        }
        assert_eq!(table.entries(&keys[0]).unwrap().len(), 1);
        materialize_sh_from_unsorted(&table, &udir, 1, None).unwrap();
        assert!(table.unsealed_main_shards().is_empty());
        for k in &keys {
            assert_eq!(table.entries(k).unwrap().len(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn publish_sorted_shard_seals_dedup_and_grows_bump() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    t.publish_sorted_shard(0, &[], 0, t.alloc_bump()).unwrap();
    let mut k_a = [0u8; crate::scripthash_layout::SH_HEAD_KEY_LEN];
    k_a[0] = 0x10;
    let mut k_b = [0u8; crate::scripthash_layout::SH_HEAD_KEY_LEN];
    k_b[0] = 0x20;
    let bump = t.alloc_bump().saturating_add(64);
    t.publish_sorted_shard(0, &[(k_a, 8), (k_b, 16), (k_a, 24)], 2, bump)
        .unwrap();
    assert_eq!(t.alloc_bump(), bump);
    let _ = std::fs::remove_dir_all(&dir);
}
