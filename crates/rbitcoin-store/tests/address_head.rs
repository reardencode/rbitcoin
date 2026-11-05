use rbitcoin_primitives::Fk;
use rbitcoin_store::address_head::*;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::TRAILING_FOOTER_LEN;
use rbitcoin_store::hashhead::HeadScale;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering as AtomicOrdering;

fn tmp(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let p = std::env::temp_dir().join(format!("rbitcoin-addr-head-{name}-{id}"));
    let _ = std::fs::remove_dir_all(&p);
    let _ = std::fs::remove_file(&p);
    let meta = meta_path(&p);
    let _ = std::fs::remove_file(&meta);
    p
}

fn head_bits(path: impl Into<PathBuf>, bits: u32) -> Result<AddressHead, StoreError> {
    AddressHead::create_with_layout(path, HeadLayout::new(bits)?)
}

fn insert_one(h: &AddressHead, txid: &[u8; 32], fk: Fk) -> Result<(), StoreError> {
    h.insert_many_in_place(&mut [(*txid, fk)])
}

fn probe_one(h: &AddressHead, txid: &[u8; 32]) -> Result<Vec<Fk>, StoreError> {
    Ok(h.probe_fks_batch(std::slice::from_ref(txid))
        .pop()
        .unwrap_or_default())
}

fn probe_batch(h: &AddressHead, txids: &[[u8; 32]]) -> Result<Vec<Vec<Fk>>, StoreError> {
    Ok(h.probe_fks_batch(txids))
}

/// Raw slot word in the **file** (`rel | fp << bits`).
fn read_slot_raw(h: &AddressHead, slot: u64) -> u32 {
    let mut buf = [0u8; 4];
    h.file.read_at(entry_file_off(slot), &mut buf).unwrap();
    u32::from_le_bytes(buf)
}

/// Plain rel in the **file** at `slot`.
fn read_slot(h: &AddressHead, slot: u64) -> u64 {
    u64::from(read_slot_raw(h, slot)) & ((1u64 << h.bits()) - 1)
}

/// Two keys on one chain (same page and h1) with different fingerprints.
fn colliding_pair() -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[0] = 0x10;
    b[0] = 0x10;
    b[4] = 0x02;
    b[16] = 0x01;
    (a, b)
}

/// Rewrite every occupied slot without its tag, as a meta v1 head wrote it.
fn strip_tags(h: &AddressHead) {
    for slot in 0..h.layout.slots() {
        let rel = read_slot(h, slot) as u32;
        if rel != 0 {
            h.file
                .write_at(entry_file_off(slot), &rel.to_le_bytes())
                .unwrap();
        }
    }
}

/// Some slot of the page holds `fk` (tag bits above `bits` ignored).
fn page_has_fk(buf: &[u8], bits: u32, fk: u64) -> bool {
    let n = buf.len() / ENTRY_BYTES as usize;
    let rel_mask = (1u64 << bits) - 1;
    (0..n).any(|i| entry_from_page_buf(buf, i as u64).unwrap_or(0) & rel_mask == fk)
}

#[test]
fn probe_limits_match_policy() {
    assert_eq!(MAX_PROBE, 1024);
    assert_eq!(PAGE_SLOTS, 1024);
    assert_eq!(PAGE_SLOT_BITS, 10);
    assert_eq!(PROBE_REGION_BYTES, 4096);
    assert_eq!(PROBE_DEPTH_WARN, 128);
    assert_eq!(MAINNET_BITS, 25);
    assert_eq!(PROBE_REGION_BYTES as u64, PAGE_SLOTS * ENTRY_BYTES);
}

#[test]
fn probe_stable() {
    let k = [0xabu8; 32];
    assert_eq!(probe_index(&k, 0, 16), probe_index(&k, 0, 16));
    assert_ne!(probe_index(&k, 0, 16), probe_index(&k, 1, 16));
    assert!(probe_index(&k, 0, 16) < (1 << 16));
}

#[test]
fn hop_scan_page_stops_at_empty() {
    // Page of 4 slots: place fks at double-hash locals.
    let mut buf = vec![0u8; 16];
    // h1=0, h2=1 → locals 0,1,2,...
    buf[0..4].copy_from_slice(&1u32.to_le_bytes());
    buf[4..8].copy_from_slice(&2u32.to_le_bytes());
    let s = hop_scan_page(&buf, 0, 1, 4, MAX_PROBE);
    assert!(s.hit_empty);
    assert_eq!(
        s.cands.iter().copied().collect::<Vec<_>>(),
        vec![(0, 1), (1, 2)]
    );
    assert_eq!(s.depth_end, 2);
    assert_eq!(s.empty_local, 2);
}

#[test]
fn hop_scan_page_spills_past_inline_cap() {
    let n = PROBE_CANDS_INLINE + 1;
    let page_slots = 16usize;
    let mut buf = vec![0u8; page_slots * 4];
    for i in 0..n {
        let fk = (i as u32) + 1;
        buf[i * 4..i * 4 + 4].copy_from_slice(&fk.to_le_bytes());
    }
    let s = hop_scan_page(&buf, 0, 1, page_slots as u64, MAX_PROBE);
    assert_eq!(s.cands.len(), n);
    assert_eq!(
        s.cands.iter().last().copied(),
        Some(((n as u32) - 1, n as u64))
    );
    let got: Vec<_> = s.cands.iter().copied().collect();
    let expect: Vec<_> = (0..n as u32).map(|d| (d, u64::from(d) + 1)).collect();
    assert_eq!(got, expect);
}

#[test]
fn insert_fk_into_page_buf_empty_idempotent_and_second() {
    let bits = 16u32;
    let mut txid = [0u8; 32];
    txid[0] = 0x42;
    let page_slots = page_slot_count(bits);
    let mut buf = vec![0u8; (page_slots as usize) * ENTRY_BYTES as usize];
    let o1 = insert_fk_into_page_buf(&mut buf, bits, &txid, Fk(7)).unwrap();
    assert!(o1.wrote_new);
    assert!(page_has_fk(&buf, bits, 7));
    let o2 = insert_fk_into_page_buf(&mut buf, bits, &txid, Fk(7)).unwrap();
    assert!(!o2.wrote_new, "idempotent same fk");
    let o3 = insert_fk_into_page_buf(&mut buf, bits, &txid, Fk(8)).unwrap();
    assert!(o3.wrote_new, "second create deeper on chain");
    assert!(page_has_fk(&buf, bits, 7) && page_has_fk(&buf, bits, 8));
}

#[test]
fn page_local_double_hash_stays_in_page() {
    let k = [0x11u8; 32];
    let bits = 26u32;
    let page = page_index(&k, bits);
    for d in 0..64u32 {
        let slot = probe_index(&k, d, bits);
        assert_eq!(slot >> PAGE_SLOT_BITS, page, "d={d}");
        assert!(slot < (1u64 << bits));
    }
    // Distinct depths should differ (odd h2).
    assert_ne!(probe_index(&k, 0, bits), probe_index(&k, 1, bits));
}

#[test]
fn probe_bits_26_to_32_in_range() {
    let k = [0x11u8; 32];
    for bits in [26u32, 28, 31, 32] {
        let idx = probe_index(&k, 0, bits);
        assert!(idx < (1u64 << bits), "bits={bits} idx={idx}");
        let idx2 = probe_index(&k, 7, bits);
        assert!(idx2 < (1u64 << bits));
        if bits > PAGE_SLOT_BITS {
            assert_eq!(idx >> PAGE_SLOT_BITS, idx2 >> PAGE_SLOT_BITS);
        }
    }
}

#[test]
fn bip30_second_create_same_page() {
    let path = tmp("bip30_page");
    let h = head_bits(&path, 16).unwrap();
    let mut txid = [0u8; 32];
    txid[0] = 0x55;
    insert_one(&h, &txid, Fk(1)).unwrap();
    insert_one(&h, &txid, Fk(2)).unwrap();
    let cands = probe_one(&h, &txid).unwrap();
    assert!(cands.contains(&Fk(1)));
    assert!(cands.contains(&Fk(2)));
    assert_eq!(cands[0], Fk(1));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// FdOnly trailing head: page-coalesce insert uses pread/pwrite (phase 2 A/B path).
#[test]
fn fd_only_insert_many_probe_and_reopen() {
    let path = tmp("fd_only_head");
    let h = head_bits(&path, 14).unwrap();
    let mut batch = Vec::new();
    for i in 1..=500u64 {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        batch.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut batch).unwrap();
    for i in [1u64, 250, 500] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        let cands = probe_one(&h, &txid).unwrap();
        assert!(cands.contains(&Fk(i)), "fk={i} cands={cands:?}");
    }
    drop(h);
    let h2 = AddressHead::open(&path).unwrap();
    let mut txid = [0u8; 32];
    txid[0..8].copy_from_slice(&42u64.to_le_bytes());
    assert!(probe_one(&h2, &txid).unwrap().contains(&Fk(42)));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn meta_v1_refused_linear_probe() {
    let path = tmp("meta_v1");
    let h = head_bits(&path, 12).unwrap();
    drop(h);
    // Corrupt footer layout version (v1 = double-hash era / pre-footer meta).
    let mut raw = std::fs::read(&path).unwrap();
    let n = raw.len();
    assert!(n >= TRAILING_FOOTER_LEN);
    // Footer layout ext at [n-16..n): version at bytes 4..6 of ext.
    let ver_off = n - 16 + 4;
    raw[ver_off..ver_off + 2].copy_from_slice(&1u16.to_le_bytes());
    std::fs::write(&path, &raw).unwrap();
    match AddressHead::open(&path) {
        Err(StoreError::Corrupt(m))
            if m.contains("footer") || m.contains("rebuild") || m.contains("version") => {}
        Err(e) => panic!("expected footer layout version error, got {e}"),
        Ok(_) => panic!("expected open failure for meta v1"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn eight_byte_footer_is_refused_not_read_as_pairs() {
    let path = tmp("footer8");
    let h = head_bits(&path, 12).unwrap();
    drop(h);
    let mut raw = std::fs::read(&path).unwrap();
    let n = raw.len();
    // Footer layout ext at [n-16..n): entry width at byte 7 of ext.
    raw[n - 16 + 7] = 8;
    std::fs::write(&path, &raw).unwrap();
    match AddressHead::open(&path) {
        Err(StoreError::Corrupt(m)) => {
            assert_eq!(m, "tx.head footer entry width (rebuild tx.head)")
        }
        Err(e) => panic!("expected footer entry width error, got {e}"),
        Ok(_) => panic!("an 8-byte footer must not open as 4-byte slots"),
    }
    let _ = std::fs::remove_file(&path);
}

/// A probe that races the sole writer's page `pwrite` sees the page
/// before or after that write, never a miss of a key inserted earlier.
#[test]
fn probe_during_page_pwrite_keeps_every_published_key() {
    use std::sync::atomic::AtomicBool;
    let path = tmp("race");
    let h = head_bits(&path, 14).unwrap();
    let n = 4000u64;
    let key = |i: u64| {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        txid[16..24].copy_from_slice(&(i * 11).to_le_bytes());
        txid
    };
    let published = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        let h = &h;
        let published = &published;
        let done = &done;
        s.spawn(move || {
            let mut i = 1u64;
            while i <= n {
                let end = (i + 7).min(n);
                let mut batch: Vec<_> = (i..=end).map(|k| (key(k), Fk(k))).collect();
                h.insert_many_in_place(&mut batch).unwrap();
                published.store(end, AtomicOrdering::Release);
                i = end + 1;
            }
            done.store(true, AtomicOrdering::Release);
        });
        let mut probes = 0u64;
        loop {
            let finished = done.load(AtomicOrdering::Acquire);
            let p = published.load(AtomicOrdering::Acquire);
            if p > 0 {
                let lo = p.saturating_sub(64).max(1);
                for k in lo..=p {
                    let cands = probe_one(h, &key(k)).unwrap();
                    assert!(cands.contains(&Fk(k)), "key {k} missing at published={p}");
                    probes += 1;
                }
            }
            if finished {
                break;
            }
        }
        assert!(probes > 0);
    });
    for k in 1..=n {
        assert_eq!(probe_one(&h, &key(k)).unwrap(), vec![Fk(k)]);
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn default_layout_is_fixed_segment_geometry() {
    let layout = default_layout(HeadScale::Tiny);
    assert_eq!(layout.bits, bits_for_scale(HeadScale::Tiny));
    assert_eq!(
        default_layout(HeadScale::Tiny).bits,
        bits_for_scale(HeadScale::Tiny)
    );
}

#[test]
fn is_probe_exhausted_matches_insert_error() {
    let e = StoreError::Corrupt("address head probe exhausted on insert");
    assert!(is_probe_exhausted_error(&e));
    assert!(!is_probe_exhausted_error(&StoreError::NotFound));
    assert!(is_store_corrupt_display(&e.to_string()));
    assert!(is_store_corrupt_display(
        "corrupt record: leftover identity broken"
    ));
    assert!(!is_store_corrupt_display("bad-txnmrklroot"));
}

#[test]
fn insert_get_roundtrip() {
    let path = tmp("roundtrip");
    let h = head_bits(&path, 12).unwrap();
    let mut txid = [0u8; 32];
    txid[0] = 1;
    insert_one(&h, &txid, Fk(1)).unwrap();
    assert_eq!(probe_one(&h, &txid).unwrap(), vec![Fk(1)]);
    insert_one(&h, &txid, Fk(1)).unwrap();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn foreigner_collision_both_found() {
    let path = tmp("foreigner");
    let h = head_bits(&path, 8).unwrap();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[0] = 0x10;
    b[0] = 0x10;
    b[4] = 0x02;
    insert_one(&h, &a, Fk(1)).unwrap();
    insert_one(&h, &b, Fk(2)).unwrap();
    assert!(probe_one(&h, &a).unwrap().contains(&Fk(1)));
    assert!(probe_one(&h, &b).unwrap().contains(&Fk(2)));
    assert_eq!(probe_one(&h, &a).unwrap()[0], Fk(1));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Two keys share a probe chain but differ in the fingerprint bytes: the
/// foreigner is not a candidate, so identity never reads its txid.
#[test]
fn probe_skips_foreigner_with_other_fingerprint() {
    let path = tmp("fp-skip");
    let h = head_bits(&path, 8).unwrap();
    let (a, b) = colliding_pair();
    insert_one(&h, &a, Fk(1)).unwrap();
    insert_one(&h, &b, Fk(2)).unwrap();
    assert_eq!(probe_one(&h, &a).unwrap(), vec![Fk(1)]);
    assert_eq!(probe_one(&h, &b).unwrap(), vec![Fk(2)]);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Rows written before tags (meta v1) have a zero fingerprint, so they stay
/// candidates for every key on their chain. `fill_fingerprints` writes the
/// tag into the file, and a reopen keeps the skip.
#[test]
fn untagged_rows_match_any_key_until_filled() {
    let path = tmp("fp-untagged");
    let (a, b) = colliding_pair();
    {
        let h = head_bits(&path, 8).unwrap();
        insert_one(&h, &a, Fk(1)).unwrap();
        insert_one(&h, &b, Fk(2)).unwrap();
        strip_tags(&h);
    }
    let h = AddressHead::open(&path).unwrap();
    assert_eq!(probe_one(&h, &a).unwrap(), vec![Fk(1), Fk(2)]);
    assert_eq!(probe_one(&h, &b).unwrap(), vec![Fk(1), Fk(2)]);

    h.fill_fingerprints(&[(a, Fk(1)), (b, Fk(2)), ([7u8; 32], Fk(9))])
        .unwrap();
    assert_eq!(probe_one(&h, &a).unwrap(), vec![Fk(1)]);
    assert_eq!(probe_one(&h, &b).unwrap(), vec![Fk(2)]);
    drop(h);
    let h = AddressHead::open(&path).unwrap();
    assert_eq!(
        probe_one(&h, &b).unwrap(),
        vec![Fk(2)],
        "tags live in the file"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Every occupied slot in the file carries its key's fingerprint, and the
/// map sees each insert.
#[test]
fn insert_writes_the_fingerprint_into_the_file() {
    let path = tmp("fp-file");
    let h = head_bits(&path, 10).unwrap();
    let mut entries = Vec::new();
    for i in 1..=300u64 {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        txid[16..24].copy_from_slice(&(i * 7).to_le_bytes());
        entries.push((txid, Fk(i)));
    }
    let by_rel = entries.clone();
    h.insert_many_in_place(&mut entries).unwrap();
    let mut occupied = 0;
    for slot in 0..h.layout.slots() {
        let rel = read_slot(&h, slot);
        if rel == 0 {
            continue;
        }
        occupied += 1;
        let (txid, _) = by_rel[rel as usize - 1];
        assert_eq!(
            read_slot_raw(&h, slot) >> h.bits(),
            fingerprint(&txid, h.bits()),
            "slot {slot}"
        );
    }
    assert_eq!(occupied, 300);
    for (txid, fk) in &by_rel {
        assert_eq!(probe_one(&h, txid).unwrap(), vec![*fk]);
        assert!(h
            .dump_page_hop(txid)
            .scan
            .cands
            .iter()
            .any(|&(_, r)| r == fk.0));
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn bip30_second_create_appends_deeper() {
    let path = tmp("bip30");
    let h = head_bits(&path, 12).unwrap();
    let mut txid = [0u8; 32];
    txid[0] = 0x55;
    insert_one(&h, &txid, Fk(1)).unwrap();
    insert_one(&h, &txid, Fk(2)).unwrap();
    let cands = probe_one(&h, &txid).unwrap();
    assert_eq!(cands[0], Fk(1), "first insert stays at earliest slot");
    assert!(cands.contains(&Fk(2)));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn rejects_fk_above_u32_on_4b() {
    let path = tmp("bigu32");
    let h = head_bits(&path, 12).unwrap();
    let txid = [1u8; 32];
    let err = insert_one(&h, &txid, Fk(u64::from(u32::MAX) + 1)).unwrap_err();
    assert!(matches!(err, StoreError::InvalidFk));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn miss_empty() {
    let path = tmp("miss");
    let h = head_bits(&path, 12).unwrap();
    assert!(probe_one(&h, &[9u8; 32]).unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn reopen_with_meta() {
    let path = tmp("reopen");
    {
        let h = head_bits(&path, 12).unwrap();
        let txid = [7u8; 32];
        insert_one(&h, &txid, Fk(3)).unwrap();
        h.flush().unwrap();
    }
    let h = AddressHead::open(&path).unwrap();
    assert_eq!(h.bits(), 12);
    assert_eq!(probe_one(&h, &[7u8; 32]).unwrap(), vec![Fk(3)]);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn reject_v7_directory() {
    let path = tmp("v7dir");
    std::fs::create_dir(&path).unwrap();
    match AddressHead::open(&path) {
        Err(StoreError::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e}"),
        Ok(_) => panic!("expected error opening v7 directory"),
    }
    let _ = std::fs::remove_dir_all(&path);
}

/// Batch page-coalesced probe must match serial `probe_fks` (multi-page wave).
#[test]
fn probe_fks_batch_matches_serial() {
    let path = tmp("probe_batch");
    let h = head_bits(&path, 14).unwrap();
    let mut entries = Vec::new();
    for i in 1..=120u64 {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[3] = 0xab;
        entries.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut entries).unwrap();
    let keys: Vec<[u8; 32]> = entries.iter().map(|(t, _)| *t).collect();
    let batch = probe_batch(&h, &keys).unwrap();
    assert_eq!(batch.len(), keys.len());
    for (i, txid) in keys.iter().enumerate() {
        let serial = probe_one(&h, txid).unwrap();
        assert_eq!(batch[i], serial, "key {i}");
    }
    assert!(probe_batch(&h, &[]).unwrap().is_empty());
    let mut same_page = Vec::new();
    for i in 0..8 {
        let mut t = [0u8; 32];
        t[0] = 1;
        t[1] = i;
        same_page.push(t);
    }
    let _ = probe_batch(&h, &same_page).unwrap();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn insert_many_batch() {
    let path = tmp("batch");
    let h = head_bits(&path, 14).unwrap();
    let mut entries = Vec::new();
    for i in 1..=50u64 {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[4] = (i * 3) as u8;
        entries.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut entries).unwrap();
    for (txid, fk) in &entries {
        assert!(probe_one(&h, txid).unwrap().contains(fk));
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Many inserts spanning multiple pages (page-coalesced; call order within page).
#[test]
fn insert_many_batch_order_multi_page() {
    let path = tmp("batch_order");
    // bits=14 → 16 pages × 1024 slots (page-local at bits>10).
    let h = head_bits(&path, 14).unwrap();
    let mut entries = Vec::new();
    for i in 1..=400u64 {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[2] = ((i * 17) & 0xff) as u8;
        txid[3] = ((i * 31) & 0xff) as u8;
        txid[4] = 0xa5;
        entries.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut entries).unwrap();
    h.insert_many_in_place(&mut entries[..50]).unwrap();
    for (txid, fk) in &entries {
        assert!(
            probe_one(&h, txid).unwrap().contains(fk),
            "missing {fk:?} after batch-order insert"
        );
    }
    let mut extra = [0u8; 32];
    extra[0] = 0xee;
    extra[1] = 0xff;
    insert_one(&h, &extra, Fk(9001)).unwrap();
    assert!(probe_one(&h, &extra).unwrap().contains(&Fk(9001)));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Same txid twice in one batch: later fk is deeper; plan order preserved
/// under page sort (stable by orig_i).
#[test]
fn insert_many_same_txid_preserves_depth_order() {
    let path = tmp("same_txid");
    let h = head_bits(&path, 14).unwrap();
    let txid = [0xab; 32];
    // Interleave with other pages so sort reorders globally but keeps orig_i
    // order within this page for the two same-txid inserts.
    let mut other = [0xcd; 32];
    other[0] = 0x11;
    let mut entries = [(txid, Fk(1)), (other, Fk(99)), (txid, Fk(2))];
    h.insert_many_in_place(&mut entries).unwrap();
    let cands = probe_one(&h, &txid).unwrap();
    assert_eq!(cands.len(), 2, "two creates on chain: {cands:?}");
    // probe_fks is home→deep (hop order); first insert is shallower.
    assert_eq!(cands[0], Fk(1));
    assert_eq!(cands[1], Fk(2));
    assert_eq!(*cands.last().unwrap(), Fk(2));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn insert_many_sole_no_sort_roundtrip() {
    let path = tmp("sole");
    let h = head_bits(&path, 14).unwrap();
    let mut entries = Vec::new();
    // Reverse-ish order; page coalescing still finds all.
    for i in (1..=80u64).rev() {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[3] = 0x5e;
        entries.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut entries).unwrap();
    h.insert_many_in_place(&mut entries[..10]).unwrap();
    for (txid, fk) in &entries {
        assert!(
            probe_one(&h, txid).unwrap().contains(fk),
            "missing after sole insert"
        );
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

/// Sole writer + concurrent probes (no multi-inserter).
#[test]
fn sole_writer_with_concurrent_probes_all_found() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let path = tmp("sole_probe");
    let h = Arc::new(head_bits(&path, 16).unwrap());
    let n = 200u64;
    let barrier = Arc::new(Barrier::new(2));

    let prober = {
        let h = Arc::clone(&h);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            for _ in 0..2000 {
                let mut txid = [0u8; 32];
                txid[0] = 1;
                txid[2] = 0xca;
                let _ = probe_one(&h, &txid);
            }
        })
    };

    barrier.wait();
    // Single inserter, batched (fences between batches).
    let mut batch = Vec::new();
    for i in 1..=n {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[2] = 0xca;
        batch.push((txid, Fk(i)));
        if batch.len() >= 32 {
            h.insert_many_in_place(&mut batch).unwrap();
            batch.clear();
        }
    }
    if !batch.is_empty() {
        h.insert_many_in_place(&mut batch).unwrap();
    }
    // Deadline: infinite join if prober/barrier stuck (panic-before-wait).
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        prober.join().unwrap();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("concurrent address_head prober timed out (hang?)");
    for i in 1..=n {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[2] = 0xca;
        assert!(
            probe_one(&h, &txid).unwrap().contains(&Fk(i)),
            "missing fk {i}"
        );
    }
    let mut again = Vec::new();
    for i in 1..=20u64 {
        let mut txid = [0u8; 32];
        txid[0] = (i & 0xff) as u8;
        txid[1] = ((i >> 8) & 0xff) as u8;
        txid[2] = 0xca;
        again.push((txid, Fk(i)));
    }
    h.insert_many_in_place(&mut again).unwrap();

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(meta_path(&path));
}

#[test]
fn mainnet_default_bits_is_25() {
    assert_eq!(MAINNET_BITS, 25);
    assert_eq!(PAGE_SLOTS as usize * 4, 4096);
}

/// insert_fk_into_page_buf / store_entry error arms + empty page / invalid fk.
#[test]
fn insert_fk_page_buf_error_arms() {
    let txid = [0x11u8; 32];
    let mut page = vec![0u8; 4096];
    assert!(matches!(
        insert_fk_into_page_buf(&mut page, 12, &txid, Fk::NULL),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(
        insert_fk_into_page_buf(&mut page, 12, &txid, Fk(u64::from(u32::MAX) + 1)),
        Err(StoreError::InvalidFk)
    ));
    // A rel that does not fit in `bits` would fold into the fingerprint.
    assert!(matches!(
        insert_fk_into_page_buf(&mut page, 12, &txid, Fk(1 << 12)),
        Err(StoreError::InvalidFk)
    ));
    assert!(
        !page.iter().any(|&b| b != 0),
        "a rejected rel writes nothing"
    );
    let r = insert_fk_into_page_buf(&mut page, 12, &txid, Fk(7)).unwrap();
    assert!(r.wrote_new);
    let r2 = insert_fk_into_page_buf(&mut page, 12, &txid, Fk(7)).unwrap();
    assert!(!r2.wrote_new);
    let _ = probe_index(&txid, 0, MIN_BITS);
    let _ = probe_index(&txid, 3, PAGE_SLOT_BITS);
    let load_ratio = |tx_count: u64, slots: u64| -> f64 {
        if slots == 0 {
            0.0
        } else {
            tx_count as f64 / slots as f64
        }
    };
    assert_eq!(load_ratio(10, 0), 0.0);
    assert_eq!((100_f64 * HEAD_LOAD_START).floor() as u64, 80);
    with_tx_head_bits("999", || {
        assert_eq!(bits_for_scale(HeadScale::Tiny), TINY_BITS);
        assert_eq!(bits_for_scale(HeadScale::Mainnet), MAINNET_BITS);
    });
    with_tx_head_bits("20", || {
        assert_eq!(
            bits_for_scale(HeadScale::Tiny),
            20,
            "TX_HEAD_BITS must widen OA under tiny header heads"
        );
        assert_eq!(
            bits_for_scale(HeadScale::Mainnet),
            20,
            "TX_HEAD_BITS wins over Mainnet scale default"
        );
    });
}

/// `RBITCOIN_TX_HEAD_BITS` is not a width. Nothing else reads it, so this
/// write is only the pin that the env path stayed gone.
#[test]
fn tx_head_bits_env_does_not_change_scale() {
    let prev = std::env::var_os("RBITCOIN_TX_HEAD_BITS");
    std::env::set_var("RBITCOIN_TX_HEAD_BITS", "20");
    let tiny = bits_for_scale(HeadScale::Tiny);
    let main = bits_for_scale(HeadScale::Mainnet);
    match prev {
        Some(v) => std::env::set_var("RBITCOIN_TX_HEAD_BITS", v),
        None => std::env::remove_var("RBITCOIN_TX_HEAD_BITS"),
    }
    assert_eq!(tiny, TINY_BITS);
    assert_eq!(main, MAINNET_BITS);
}

/// One thread's head-width choice must not change another thread's scale default.
#[test]
fn tx_head_bits_on_one_thread_leaves_the_other_at_scale() {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        with_tx_head_bits("20", || {
            assert_eq!(bits_for_scale(HeadScale::Tiny), 20);
            ready_tx.send(()).unwrap();
            let _ = done_rx.recv();
        });
    });
    ready_rx.recv().unwrap();
    let tiny = bits_for_scale(HeadScale::Tiny);
    let main = bits_for_scale(HeadScale::Mainnet);
    let _ = done_tx.send(());
    worker.join().unwrap();
    assert_eq!(tiny, TINY_BITS);
    assert_eq!(main, MAINNET_BITS);
}

#[test]
fn head_access_env_probe_stats_and_layout_helpers() {
    note_probe_depth_on_insert(PROBE_DEPTH_WARN);
    note_probe_depth_on_insert(PROBE_DEPTH_WARN + 1);
    note_probe_depth_on_insert(PROBE_DEPTH_WARN + 50);
    note_probe_exhausted();

    assert!(is_probe_exhausted_error(&StoreError::Corrupt(
        "address head probe exhausted on insert"
    )));
    assert!(!is_probe_exhausted_error(&StoreError::Corrupt("other")));

    let txid = [0xABu8; 32];
    let _ = page_index(&txid, MAINNET_BITS);
    let _ = h1_in_page(&txid, MAINNET_BITS);
    let _ = h2_in_page(&txid, MAINNET_BITS);
    let _ = page_slot_count(MAINNET_BITS);
    let _ = page_base_for_txid(&txid, MAINNET_BITS);
    assert_eq!(entry_file_off(0), 0);
    assert_eq!(entry_file_off(3), 12);
    let layout = default_layout(HeadScale::Tiny);
    assert!((MIN_BITS..=MAX_BITS).contains(&layout.bits));
    assert_eq!(default_layout(HeadScale::Tiny).bits, layout.bits);
    assert_eq!(default_layout(HeadScale::Mainnet).bits, MAINNET_BITS);
    let roll_thr = (100_f64 * HEAD_LOAD_START).floor() as u64;
    assert_eq!(roll_thr, 80);
    assert!(81 >= roll_thr);
    let ext = encode_layout_ext(layout, 7);
    let (dec, gen) = decode_layout_ext(&ext).unwrap();
    assert_eq!(dec.bits, layout.bits);
    assert_eq!(gen, 7);
    let bad = [0u8; 16];
    assert!(decode_layout_ext(&bad).is_err());
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-ah-meta-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let meta = meta_path(&path);
    std::fs::write(&meta, b"x").unwrap();
    remove_legacy_meta_sidecar(&path);
    assert!(!meta.exists());
}
