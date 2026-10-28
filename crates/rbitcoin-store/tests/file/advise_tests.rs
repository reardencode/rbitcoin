use rbitcoin_primitives::{TableKind, SCHEMA_VERSION, STORE_MAGIC};
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// The first high-water persist of a shrink can return disk-full. The
/// published length and the reopened file stay at the shorter end.
#[test]
fn shrink_hwm_persists_the_short_length_after_one_disk_full() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-shrink-hwm-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let short = f.logical_len();
    f.set_logical_len(short + 64).unwrap();
    let handle = f.io_handle();
    struct Disarm(rbitcoin_store::io_handle::IoHandle);
    impl Drop for Disarm {
        fn drop(&mut self) {
            rbitcoin_store::io_handle::disarm_pwrite(self.0);
        }
    }
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(handle, 1);
    let _disarm = Disarm(handle);
    f.set_logical_len(short)
        .expect("shrink retries the high-water persist");
    drop(_disarm);
    assert_eq!(f.logical_len(), short);
    drop(f);
    let f = TableFile::open(&path, TableKind::TxOut).unwrap();
    assert_eq!(f.logical_len(), short);
    drop(f);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn grow_tight_adds_one_mib_not_slab() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-grow-tight-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::ArrayLink).unwrap();
    f.set_grow_tight(true);
    let payload = vec![0x11u8; 2048];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    let on_disk = std::fs::metadata(&path).unwrap().len();
    // need ≈ 16+2048; tight grow is need+1MiB, never a 64–256 MiB slab.
    assert!(on_disk > 2048);
    assert!(
        on_disk < 2 * 1024 * 1024,
        "tight grow should stay near 1 MiB, got {on_disk}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn grow_align_64k_not_slab() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-grow-64k-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::ArrayLink).unwrap();
    f.set_grow_policy(GrowPolicy::Align64k);
    let payload = vec![0x11u8; 16];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    let need = FILE_HEADER_LEN as u64 + 16;
    let on_disk = std::fs::metadata(&path).unwrap().len();
    assert!(on_disk >= need);
    assert!(
        on_disk < need + 128 * 1024,
        "64 KiB grow must stay < 128 KiB above need, got {on_disk}"
    );
    assert!(
        on_disk < 64 * 1024 * 1024,
        "SH-style grow must not punch a 64 MiB slab, got {on_disk}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn advise_dont_need_is_best_effort() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-advise-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let payload = vec![0xabu8; 16 * 1024];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    f.advise_dont_need(FILE_HEADER_LEN as u64, payload.len() as u64);
    f.advise_dont_need(0, 0);
    let mut buf = vec![0u8; payload.len()];
    f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
    assert_eq!(buf, payload);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn table_file_create_open_roundtrip() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path3 = std::env::temp_dir().join(format!("rbitcoin-access-idx-{id}"));
    let _ = std::fs::remove_file(&path3);
    let idx = TableFile::create(&path3, TableKind::ArrayLink).unwrap();
    let payload = 42u32.to_le_bytes();
    let off = FILE_HEADER_LEN as u64;
    idx.write_at_pwrite(off, &payload).unwrap();
    let mut got = [0u8; 4];
    idx.read_at(off, &mut got).unwrap();
    assert_eq!(got, payload);
    drop(idx);
    let idx2 = TableFile::open(&path3, TableKind::ArrayLink).unwrap();
    let mut got2 = [0u8; 4];
    idx2.read_at(off, &mut got2).unwrap();
    assert_eq!(got2, payload);
    let _ = std::fs::remove_file(&path3);
}

/// Tweet pin: first store file is `scripthash.body`. Windows
/// `FILE_FLAG_OVERLAPPED` + std `WriteFile`/`ReadFile` (NULL OVERLAPPED)
/// is os error 87. Create, payload pwrite, reopen, and grow must work.
#[test]
fn scripthash_body_create_open_roundtrip() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-sh-body-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("scripthash.body");
    let f = TableFile::create(&path, TableKind::ScriptHash).unwrap();
    let payload = [0xABu8; 32];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    f.flush().unwrap();
    drop(f);
    let f2 = TableFile::open(&path, TableKind::ScriptHash).unwrap();
    let mut got = [0u8; 32];
    f2.read_at(FILE_HEADER_LEN as u64, &mut got).unwrap();
    assert_eq!(got, payload);
    f2.ensure_capacity(4096).unwrap();
    f2.write_at(FILE_HEADER_LEN as u64 + 32, &[0xCD; 8])
        .unwrap();
    drop(f2);
    let f3 = TableFile::open(&path, TableKind::ScriptHash).unwrap();
    let mut tail = [0u8; 8];
    f3.read_at(FILE_HEADER_LEN as u64 + 32, &mut tail).unwrap();
    assert_eq!(tail, [0xCD; 8]);
    drop(f3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_readers_during_append_and_grow() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let _stress = TEST_MMAP_STRESS_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-epoch-stress-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = Arc::new(TableFile::create(&path, TableKind::TxOut).unwrap());

    let seed = vec![0x11u8; 64];
    f.write_at(FILE_HEADER_LEN as u64, &seed).unwrap();
    assert_eq!(f.logical_len(), FILE_HEADER_LEN as u64 + seed.len() as u64);

    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    {
        let f = Arc::clone(&f);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut off = f.logical_len();
            for i in 0..200u32 {
                let chunk = vec![(i % 251) as u8; 4096];
                f.write_at(off, &chunk).unwrap();
                off += chunk.len() as u64;
            }
        }));
    }

    {
        let f = Arc::clone(&f);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..500u32 {
                let b = [((i % 200) + 1) as u8; 8];
                f.write_at(FILE_HEADER_LEN as u64, &b).unwrap();
            }
        }));
    }

    for _ in 0..3 {
        let f = Arc::clone(&f);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1000 {
                let len = f.logical_len();
                if len <= FILE_HEADER_LEN as u64 {
                    continue;
                }
                let n = (len - FILE_HEADER_LEN as u64).min(64) as usize;
                let mut buf = vec![0u8; n];
                f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
                let _ = buf[0];
            }
        }));
    }

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for h in handles {
            h.join().unwrap();
        }
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("concurrent TableFile workers timed out (hang?)");
    let final_len = f.logical_len();
    assert!(final_len > FILE_HEADER_LEN as u64 + 64);
    let mut head = [0u8; 8];
    f.read_at(FILE_HEADER_LEN as u64, &mut head).unwrap();
    assert_ne!(head, [0u8; 8]);
    let _ = std::fs::remove_file(&path);
}

#[allow(clippy::cognitive_complexity)] // one fixture, many error arms
#[test]
fn load_store_u32_u64_zero_range_trailing_and_open_errors() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-file-atomics-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let payload = [0u8; 64];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    let off32 = FILE_HEADER_LEN as u64;
    let off64 = FILE_HEADER_LEN as u64 + 8;
    f.write_at(off32, &0x1122_3344u32.to_le_bytes()).unwrap();
    assert_eq!(f.load_u32_le(off32).unwrap(), 0x1122_3344);
    f.write_at(off64, &0x0102_0304_0506_0708u64.to_le_bytes())
        .unwrap();
    assert_eq!(f.load_u64_le(off64).unwrap(), 0x0102_0304_0506_0708);
    assert!(matches!(
        f.load_u32_le(off32 + 1),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(f.load_u32_le(10_000), Err(StoreError::Corrupt(_))));
    f.zero_range(0, 0).unwrap();
    f.zero_range(FILE_HEADER_LEN as u64 + 32, 16).unwrap();
    f.set_logical_len(FILE_HEADER_LEN as u64 + 48).unwrap();
    assert!(matches!(f.set_logical_len(0), Err(StoreError::Corrupt(_))));
    assert!(matches!(
        f.with_bytes(FILE_HEADER_LEN as u64, 10_000, |_| ()),
        Err(StoreError::Corrupt(_))
    ));
    drop(f);

    {
        let bad = std::env::temp_dir().join(format!("rbitcoin-file-bad-{id}"));
        let _ = std::fs::remove_file(&bad);
        std::fs::write(
            &bad,
            b"XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert!(matches!(
            TableFile::open(&bad, TableKind::TxOut),
            Err(StoreError::BadMagic)
        ));
        let _ = std::fs::remove_file(&bad);
    }
    {
        let th = std::env::temp_dir().join(format!("rbitcoin-file-trail-{id}"));
        let _ = std::fs::remove_file(&th);
        let f = TableFile::create_trailing_header(&th, TableKind::HashHead).unwrap();
        let data_bytes = 64u64;
        f.set_logical_len(data_bytes + TRAILING_FOOTER_LEN as u64)
            .unwrap();
        f.write_at(0, &[0xABu8; 64]).unwrap();
        f.flush().unwrap();
        drop(f);
        let (f2, _ext) =
            TableFile::open_trailing_header(&th, TableKind::HashHead, data_bytes).unwrap();
        let mut b = [0u8; 4];
        f2.read_at(0, &mut b).unwrap();
        assert_eq!(b, [0xAB; 4]);
        assert!(matches!(
            TableFile::open_trailing_header(&th, TableKind::HashHead, 1_000_000),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            TableFile::open_trailing_header(&th, TableKind::TxOut, data_bytes),
            Err(StoreError::BadKind { .. })
        ));
        let (mut f3, _ext) =
            TableFile::open_trailing_header(&th, TableKind::HashHead, data_bytes).unwrap();
        f3.set_trailing_ext([0x11; 16]).unwrap();
        f3.flush().unwrap();
        drop(f3);
        {
            let tight = std::env::temp_dir().join(format!("rbitcoin-file-trail-tight-{id}"));
            let _ = std::fs::remove_file(&tight);
            let data = [0xCDu8; 32];
            let logical = data.len() as u64 + TRAILING_FOOTER_LEN as u64;
            let mut footer = [0u8; TRAILING_FOOTER_LEN];
            footer[0..4].copy_from_slice(&STORE_MAGIC);
            footer[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
            footer[6..8].copy_from_slice(&TableKind::HashHead.as_u16().to_le_bytes());
            footer[8..16].copy_from_slice(&logical.to_le_bytes());
            footer[16..32].copy_from_slice(&[0x22; 16]);
            let mut raw = Vec::with_capacity(logical as usize);
            raw.extend_from_slice(&data);
            raw.extend_from_slice(&footer);
            std::fs::write(&tight, &raw).unwrap();
            let (f4, ext) =
                TableFile::open_trailing_header_from_end(&tight, TableKind::HashHead).unwrap();
            assert_eq!(ext, [0x22; 16]);
            let mut b = [0u8; 4];
            f4.read_at(0, &mut b).unwrap();
            assert_eq!(b, [0xCD; 4]);
            drop(f4);
            let _ = std::fs::remove_file(&tight);
        }
        let short = std::env::temp_dir().join(format!("rbitcoin-file-trail-short-{id}"));
        let _ = std::fs::remove_file(&short);
        std::fs::write(&short, b"tiny").unwrap();
        assert!(matches!(
            TableFile::open_trailing_header_from_end(&short, TableKind::HashHead),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_file(&short);
        let badm = std::env::temp_dir().join(format!("rbitcoin-file-trail-badm-{id}"));
        let _ = std::fs::remove_file(&badm);
        let raw = vec![0u8; 64 + TRAILING_FOOTER_LEN];
        std::fs::write(&badm, &raw).unwrap();
        assert!(matches!(
            TableFile::open_trailing_header_from_end(&badm, TableKind::HashHead),
            Err(StoreError::BadMagic)
        ));
        let _ = std::fs::remove_file(&badm);
        let _ = std::fs::remove_file(&th);
    }
    {
        let lead = std::env::temp_dir().join(format!("rbitcoin-file-lead-{id}"));
        let _ = std::fs::remove_file(&lead);
        let mut f = TableFile::create(&lead, TableKind::TxOut).unwrap();
        assert!(matches!(
            f.set_trailing_ext([0; 16]),
            Err(StoreError::Corrupt(_))
        ));
        drop(f);
        let _ = std::fs::remove_file(&lead);
    }
    {
        let p = std::env::temp_dir().join(format!("rbitcoin-file-readpast-{id}"));
        let _ = std::fs::remove_file(&p);
        let f = TableFile::create(&p, TableKind::TxOut).unwrap();
        let mut big = [0u8; 8];
        assert!(matches!(
            f.read_at(FILE_HEADER_LEN as u64 + 1000, &mut big),
            Err(StoreError::Corrupt(_))
        ));
        drop(f);
        let _ = std::fs::remove_file(&p);
    }
    let _ = ensure_nofile_budget();
    let _ = ensure_nofile_budget_at_least(64);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn trailing_header_open_error_arms() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-trail-err-{id}"));
    let _ = std::fs::create_dir_all(&dir);
    let short = dir.join("short");
    std::fs::write(&short, b"tiny").unwrap();
    assert!(matches!(
        TableFile::open_trailing_header_from_end(&short, TableKind::TxOut),
        Err(StoreError::Corrupt(_))
    ));
    let bad_magic = dir.join("badmag");
    std::fs::write(&bad_magic, vec![0u8; TRAILING_FOOTER_LEN]).unwrap();
    assert!(matches!(
        TableFile::open_trailing_header_from_end(&bad_magic, TableKind::TxOut),
        Err(StoreError::BadMagic)
    ));
    let good = dir.join("good");
    let f = TableFile::create_trailing_header(&good, TableKind::TxOut).unwrap();
    f.ensure_capacity(4096 + TRAILING_FOOTER_LEN as u64)
        .unwrap();
    f.set_logical_len(4096 + TRAILING_FOOTER_LEN as u64)
        .unwrap();
    drop(f);
    let (_f2, _ext) = TableFile::open_trailing_header_from_end(&good, TableKind::TxOut).unwrap();
    assert!(matches!(
        TableFile::open_trailing_header_from_end(&good, TableKind::Header),
        Err(StoreError::BadKind { .. })
    ));
    let good2 = dir.join("good2");
    let f = TableFile::create_trailing_header(&good2, TableKind::TxOut).unwrap();
    f.ensure_capacity(1024 + TRAILING_FOOTER_LEN as u64)
        .unwrap();
    f.set_logical_len(1024 + TRAILING_FOOTER_LEN as u64)
        .unwrap();
    drop(f);
    let (_f3, _) = TableFile::open_trailing_header(&good2, TableKind::TxOut, 1024).unwrap();
    assert!(TableFile::open_trailing_header(&good2, TableKind::TxOut, 50_000).is_err());
    let path = dir.join("normal");
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    f.write_at(FILE_HEADER_LEN as u64, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    let u = f.load_u32_le(FILE_HEADER_LEN as u64).unwrap();
    assert_eq!(u, u32::from_le_bytes([1, 2, 3, 4]));
    f.write_at(FILE_HEADER_LEN as u64, &0x1122_3344u32.to_le_bytes())
        .unwrap();
    f.write_at(
        FILE_HEADER_LEN as u64,
        &0x0102_0304_0506_0708u64.to_le_bytes(),
    )
    .unwrap();
    let _ = f.load_u64_le(FILE_HEADER_LEN as u64).unwrap();
    f.zero_range(FILE_HEADER_LEN as u64, 8).unwrap();
    f.set_logical_len(FILE_HEADER_LEN as u64 + 8).unwrap();
    let _ = f.path();
    let _ = f.data_len();
    let _ = std::fs::remove_dir_all(&dir);
}

/// pwrite payload must be visible via pread (page-cache coherency).
#[test]
fn write_at_pwrite_visible_via_pread() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-pwrite-vis-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let payload = b"fd-append-payload-0123456789abcdef";
    let off = FILE_HEADER_LEN as u64;
    f.write_at_pwrite(off, payload).unwrap();
    assert_eq!(f.logical_len(), off + payload.len() as u64);
    let mut got = vec![0u8; payload.len()];
    f.read_at(off, &mut got).unwrap();
    assert_eq!(&got[..], payload);
    let more = b"MORE";
    let off2 = f.logical_len();
    f.write_at_pwrite(off2, more).unwrap();
    let mut got2 = [0u8; 4];
    f.read_at(off2, &mut got2).unwrap();
    assert_eq!(&got2, more);
    drop(f);
    let _ = std::fs::remove_file(&path);
}

/// A write that lands while a flush syncs keeps the file dirty, so the next
/// barrier syncs it. The IBD tip flush runs beside the next batch's writes.
#[test]
fn write_during_flush_stays_pending() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-flush-late-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    f.write_at_pwrite(FILE_HEADER_LEN as u64, &[0x5Au8; 64])
        .unwrap();
    let end = f.logical_len();
    f.flush_between(|f| f.write_at_pwrite(end, b"LATE").unwrap())
        .unwrap();
    assert!(f.pending_sync(), "the late write still needs a sync");
    drop(f);
    let _ = std::fs::remove_file(&path);
}

/// A data barrier must not publish the high-water mark or take the write
/// thread's sync bit. A flush after a later append still publishes that append.
#[test]
fn sync_data_only_leaves_hwm_and_pending_sync() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-sync-data-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let payload = vec![0x5Au8; 64];
    f.write_at_pwrite(FILE_HEADER_LEN as u64, &payload).unwrap();
    let published = f.logical_len();
    let hwm = |p: &std::path::Path| {
        let raw = std::fs::read(p).unwrap();
        u64::from_le_bytes(raw[8..16].try_into().unwrap())
    };
    assert_eq!(hwm(&path), published);
    assert!(f.pending_sync());

    f.sync_data_only().unwrap();
    assert_eq!(hwm(&path), published);
    assert!(f.pending_sync());

    let more = b"AFTER!!";
    let off2 = f.logical_len();
    f.write_at_pwrite(off2, more).unwrap();
    f.flush().unwrap();
    drop(f);
    let f2 = TableFile::open(&path, TableKind::TxOut).unwrap();
    assert_eq!(f2.logical_len(), off2 + more.len() as u64);
    let mut got = vec![0u8; payload.len()];
    f2.read_at(FILE_HEADER_LEN as u64, &mut got).unwrap();
    assert_eq!(got, payload);
    let mut got2 = [0u8; 7];
    f2.read_at(off2, &mut got2).unwrap();
    assert_eq!(&got2, more);
    let _ = std::fs::remove_file(&path);
}

/// HWM on disk never exceeds what is fully written (complete-or-fail publish).
#[test]
fn hwm_publish_matches_full_payload_after_flush() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-hwm-pub-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    let payload = vec![0x5Au8; 1024];
    f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
    f.flush().unwrap();
    let published = f.logical_len();
    drop(f);
    // Raw header HWM must equal published length.
    let raw = std::fs::read(&path).unwrap();
    let hwm = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    assert_eq!(hwm, published);
    assert_eq!(hwm, FILE_HEADER_LEN as u64 + 1024);
    // Reopen sees full payload, nothing past HWM.
    let f2 = TableFile::open(&path, TableKind::TxOut).unwrap();
    assert_eq!(f2.logical_len(), published);
    let mut got = vec![0u8; 1024];
    f2.read_at(FILE_HEADER_LEN as u64, &mut got).unwrap();
    assert_eq!(got, payload);
    let mut past = [0u8; 1];
    assert!(f2.read_at(published, &mut past).is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn table_file_surface_and_nofile_budget() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-file-surface-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::TxOut).unwrap();
    assert!(f.logical_len() >= FILE_HEADER_LEN as u64);
    let payload = b"hello-table";
    f.write_at(FILE_HEADER_LEN as u64, payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
    assert_eq!(&buf, payload);
    f.with_bytes(FILE_HEADER_LEN as u64, payload.len() as u64, |b| {
        assert_eq!(b, payload);
    })
    .unwrap();
    f.ensure_capacity(f.logical_len() + 4096).unwrap();
    f.flush().unwrap();
    f.flush_async().unwrap();
    let _ = f.read_fd();
    drop(f);
    let f = TableFile::open(&path, TableKind::TxOut).unwrap();
    let mut buf2 = vec![0u8; payload.len()];
    f.read_at(FILE_HEADER_LEN as u64, &mut buf2).unwrap();
    assert_eq!(&buf2, payload);
    assert!(matches!(
        TableFile::open(&path, TableKind::Header),
        Err(StoreError::BadKind { .. })
    ));
    drop(f);
    let (soft, hard) = ensure_nofile_budget();
    assert!(soft > 0 || hard > 0 || cfg!(not(unix)));
    let (s2, _) = ensure_nofile_budget_at_least(64);
    assert!(s2 >= 64 || cfg!(not(unix)) || soft == 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn write_synced_tmp_rename_installs_dest_only() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-sync-rename-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("seal.idx");
    let tmp = tmp_sidecar_path(&dest);
    assert!(!dest.exists());
    write_synced_tmp_rename(&dest, b"sealed").unwrap();
    assert!(dest.exists());
    #[cfg(unix)]
    {
        let missing = dir.join("no-such-parent");
        let err = fsync_parent_dir(&missing).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let bare = std::path::PathBuf::from(format!("rbitcoin-bare-seal-{id}"));
        let _ = std::fs::remove_file(&bare);
        write_synced_tmp_rename(&bare, b"x").unwrap();
        assert_eq!(std::fs::read(&bare).unwrap(), b"x");
        let _ = std::fs::remove_file(&bare);
    }
    assert!(!tmp.exists());
    assert_eq!(std::fs::read(&dest).unwrap(), b"sealed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_tmp_rename_installs_dest_only() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-tmp-rename-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("spill.bin");
    let tmp = tmp_sidecar_path(&dest);
    assert!(!dest.exists());
    write_tmp_rename(&dest, b"spill").unwrap();
    assert!(dest.exists());
    assert!(!tmp.exists());
    assert_eq!(std::fs::read(&dest).unwrap(), b"spill");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A script worker must not `pread`. The flag is cleared on drop so later
/// tests on this thread can still read.
#[test]
fn script_worker_cannot_pread() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rbitcoin-script-pread-{id}"));
    let _ = std::fs::remove_file(&path);
    let f = TableFile::create(&path, TableKind::ArrayLink).unwrap();
    f.write_at(FILE_HEADER_LEN as u64, &[1, 2, 3, 4]).unwrap();
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            rbitcoin_primitives::set_script_worker(false);
        }
    }
    let _clear = Clear;
    rbitcoin_primitives::set_script_worker(true);
    let mut buf = [0u8; 4];
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.pread_exact(FILE_HEADER_LEN as u64, &mut buf).unwrap();
    }));
    assert!(panicked.is_err(), "pread_exact on rbtc-scripts must panic");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.pwrite_all(FILE_HEADER_LEN as u64, &[9, 9, 9, 9]).unwrap();
    }));
    assert!(panicked.is_err(), "pwrite_all on rbtc-scripts must panic");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut session = rbitcoin_store::uring_session::UringSession::try_open_kind(
            rbitcoin_store::uring_session::SessionKind::Pool,
            32,
        )
        .expect("pool session");
        session.submit().unwrap();
    }));
    assert!(
        panicked.is_err(),
        "io_uring submit on rbtc-scripts must panic"
    );
    drop(_clear);
    let _ = std::fs::remove_file(&path);
}
