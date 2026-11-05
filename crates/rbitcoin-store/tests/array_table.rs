use rbitcoin_primitives::TableKind;
use rbitcoin_store::array_table::*;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use std::sync::atomic::Ordering;

fn tmp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rbitcoin-array-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// `get` samples `len` and the slot under one sequence counter. A `truncate`
/// between those loads retries. The reader sees the previous value or the
/// shortened table, not a mix and not a panic.
#[test]
fn get_racing_truncate_does_not_panic() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::Confirmed).unwrap());
    let wide: Vec<_> = (0..1024u64)
        .map(|i| (i, if i == 1023 { 7 } else { 0 }))
        .collect();
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &wide)
        .unwrap();
    assert!(t.l2_resident_bytes() > 0, "test needs the in-RAM image");
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (t, stop) = (Arc::clone(&t), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let v = t.get(1023).unwrap();
                    assert!(v == 0 || v == 7, "torn read {v}");
                }
            })
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 0)
            .unwrap();
        t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &wide)
            .unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        assert!(r.join().is_ok(), "get panicked racing truncate");
    }
    let _ = std::fs::remove_file(&path);
}

/// A disk-only append publishes the named slots, and a zero gap publishes
/// zeros in the holes, before a reader can see the new length.
#[test]
fn fd_only_append_publishes_values_and_zero_gap() {
    let dir = tmp_path();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("slots.body");
    let file = rbitcoin_store::file::TableFile::create(&path, TableKind::ArrayLink).unwrap();
    file.write_at(ArrayTable::offset(0), &[0u8; 8]).unwrap();
    drop(file);
    let t =
        with_class_c_inram_max_bytes(0, || ArrayTable::open(&path, TableKind::ArrayLink).unwrap());
    assert_eq!(t.l2_resident_bytes(), 0, "disk-only table");
    let write = rbitcoin_store::ClassCWrite::for_test();
    t.set(&write, 0, 7).unwrap();
    assert_eq!(t.get_sample(0).unwrap(), (7, 1));
    t.set_zero_gap(&write, 3, 9).unwrap();
    assert_eq!(t.get_sample(0).unwrap(), (7, 4));
    assert_eq!(t.get_sample(1).unwrap(), (0, 4));
    assert_eq!(t.get_sample(2).unwrap(), (0, 4));
    assert_eq!(t.get_sample(3).unwrap(), (9, 4));
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cap installed on one thread must not change `class_c_inram_max_bytes`
/// on another. Process env fails this: both threads see the same variable.
#[test]
fn class_c_cap_on_one_thread_leaves_the_other_at_default() {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        with_class_c_inram_max_bytes(0, || {
            assert_eq!(class_c_inram_max_bytes(), 0);
            ready_tx.send(()).unwrap();
            let _ = done_rx.recv();
        });
    });
    ready_rx.recv().unwrap();
    let seen = class_c_inram_max_bytes();
    let _ = done_tx.send(());
    worker.join().unwrap();
    assert_eq!(seen, DEFAULT_CLASS_C_INRAM_MAX_BYTES);
}

/// A disk-only table returns an empty slot after truncate, without a read.
#[test]
fn fd_only_truncate_then_get_is_absent() {
    let dir = tmp_path();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("slots.body");
    let file = rbitcoin_store::file::TableFile::create(&path, TableKind::ArrayLink).unwrap();
    file.write_at(ArrayTable::offset(0), &[0u8; 16]).unwrap();
    drop(file);
    let t =
        with_class_c_inram_max_bytes(0, || ArrayTable::open(&path, TableKind::ArrayLink).unwrap());
    assert_eq!(t.l2_resident_bytes(), 0, "disk-only table");
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 22)
        .unwrap();
    t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 1)
        .unwrap();
    assert_eq!(t.get_sample(1).unwrap(), (0, 1));
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A multi-slot store publishes one generation. Each `get` is the previous
/// value or the new one for that index.
#[test]
fn get_during_set_many_is_old_or_new() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::Confirmed).unwrap());
    let n = 32u64;
    let old: Vec<_> = (0..n).map(|i| (i, 10 + i)).collect();
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &old)
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (t, stop) = (Arc::clone(&t), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for i in 0..n {
                        let v = t.get(i).unwrap();
                        assert!(v == 10 + i || v == 100 + i, "mixed slot {i} value {v}");
                    }
                }
            })
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        let new: Vec<_> = (0..n).map(|i| (i, 100 + i)).collect();
        t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &new)
            .unwrap();
        t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &old)
            .unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        assert!(r.join().is_ok(), "get panicked during set_many");
    }
    let _ = std::fs::remove_file(&path);
}

/// A store that lands after the flush has noticed it is dirty, and before
/// new stores are excluded, is still in this flush. Sampling the dirty index
/// before that exclusion would clear the mark and leave the slot off disk.
#[test]
fn store_before_exclude_is_in_this_flush() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::ArrayLink).unwrap();
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &[(0, 1), (1, 2)])
        .unwrap();
    t.flush().unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 9)
        .unwrap();
    t.flush_dirty_between(|t, step| {
        if step == FlushStep::Admit {
            t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 7)
                .unwrap();
        }
    })
    .unwrap();
    let mut buf = [0u8; 8];
    t.file.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
    assert_eq!(
        u64::from_le_bytes(buf),
        7,
        "earlier slot must be in this flush"
    );
    assert_eq!(
        t.unstored_from.load(Ordering::Acquire),
        u64::MAX,
        "the mark must stay set until that slot is persisted"
    );
    let _ = std::fs::remove_file(&path);
}

/// Flush persists the live slots of the dirty range recorded at start.
/// A store from the write hook is refused; the bytes on disk are the slots
/// after that hook, so the flush did not keep a detached image. A store
/// after flush returns is absent here and present in the next flush.
#[test]
fn flush_writes_live_slots_and_refuses_a_store_until_it_finishes() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::ArrayLink).unwrap();
    let n = 600u64;
    let pairs: Vec<(u64, u64)> = (0..n).map(|i| (i, i + 1)).collect();
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &pairs)
        .unwrap();
    t.flush().unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 5)
        .unwrap();
    let mut during = Ok(());
    t.flush_dirty_between(|t, step| {
        if step == FlushStep::Write {
            t.poke_live_slot(0, 77);
            during = t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 9);
            let _ = t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &[(2, 8)]);
            let _ = t.truncate(&rbitcoin_store::ClassCWrite::for_test(), n - 1);
        }
    })
    .unwrap();
    let slot0 = {
        let mut buf = [0u8; 8];
        t.file.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
        u64::from_le_bytes(buf)
    };
    assert!(
        during.is_err() && slot0 == 77,
        "store during flush refused={during:?} live slot0={slot0}"
    );
    assert!(n * ELEM > FLUSH_SCRATCH as u64);
    let chunk = t.flush_chunk_max.load(Ordering::Relaxed);
    assert!(chunk > 0 && chunk <= FLUSH_SCRATCH, "flush chunk {chunk}");
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 9)
        .unwrap();
    let mut buf = [0u8; 8];
    t.file
        .read_at(FILE_HEADER_LEN as u64 + 8, &mut buf)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(buf),
        2,
        "store after flush stays off disk"
    );
    t.flush().unwrap();
    t.file
        .read_at(FILE_HEADER_LEN as u64 + 8, &mut buf)
        .unwrap();
    assert_eq!(u64::from_le_bytes(buf), 9);
    let _ = std::fs::remove_file(&path);
}

/// A rewrite whose length equals the last flushed length still publishes
/// that length. A torn longer HWM must not survive the flush.
#[test]
fn same_length_rewrite_publishes_logical_len() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 1), (1, 2), (2, 3), (3, 4)],
    )
    .unwrap();
    t.flush().unwrap();
    let published = FILE_HEADER_LEN as u64 + 4 * ELEM;
    assert_eq!(t.file.logical_len(), published);
    t.file.set_logical_len(published + 64).unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 99)
        .unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.disk_len.load(Ordering::Acquire), 4);
    t.flush().unwrap();
    assert_eq!(t.file.logical_len(), published);
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.get(1).unwrap(), 99);
    let _ = std::fs::remove_file(&path);
}

/// A failed `write_at` leaves the recorded range dirty. The retry writes
/// those slots and does not truncate the table.
#[cfg(target_os = "linux")]
#[test]
fn failed_write_keeps_the_range_dirty() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::ArrayLink).unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 1), (1, 2), (2, 3), (3, 4)],
    )
    .unwrap();
    t.flush().unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 42)
        .unwrap();
    let mut swapped = None;
    let failed = t.flush_dirty_between(|t, step| {
        if step == FlushStep::Write {
            swapped = Some(crate::dev_full::DevFull::on(&t.file.read_file));
        }
    });
    drop(swapped);
    assert!(
        failed.is_err(),
        "write_at must fail while the fd is /dev/full"
    );
    assert_eq!(t.len(), 4, "a failed persist must not truncate");
    let mut buf = [0u8; 8];
    t.file
        .read_at(FILE_HEADER_LEN as u64 + 8, &mut buf)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(buf),
        2,
        "failed persist must not publish the slot"
    );
    t.flush().unwrap();
    t.file
        .read_at(FILE_HEADER_LEN as u64 + 8, &mut buf)
        .unwrap();
    assert_eq!(u64::from_le_bytes(buf), 42);
    let _ = std::fs::remove_file(&path);
}

/// A store during the clean step is refused. The store after flush returns
/// is what the next flush persists.
#[test]
fn set_after_flush_is_flushed_next() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::ArrayLink).unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 10), (1, 11), (2, 12), (3, 13)],
    )
    .unwrap();
    t.flush().unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 3, 23)
        .unwrap();
    let mut during = Ok(());
    t.flush_dirty_between(|t, step| {
        if step == FlushStep::Clean {
            during = t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 21);
        }
    })
    .unwrap();
    assert!(during.is_err(), "store during clean must be refused");
    drop(t);
    let t = ArrayTable::open(&path, TableKind::ArrayLink).unwrap();
    assert_eq!((t.get(1).unwrap(), t.get(3).unwrap()), (11, 23));
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 21)
        .unwrap();
    t.flush().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::ArrayLink).unwrap();
    assert_eq!((t.get(1).unwrap(), t.get(3).unwrap()), (21, 23));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn array_set_get_grow_set_many_truncate_flush() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 0);
    assert_eq!(t.get(0).unwrap(), 0);
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 0), (1, 0), (2, 0), (3, 30)],
    )
    .unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.get(0).unwrap(), 0);
    assert_eq!(t.get(3).unwrap(), 30);
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 11)
        .unwrap();
    assert_eq!(t.get(1).unwrap(), 11);
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &[])
        .unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(4, 0), (5, 50), (6, 0), (7, 0), (8, 0), (9, 0), (10, 100)],
    )
    .unwrap();
    assert_eq!(t.len(), 11);
    assert_eq!(t.get(5).unwrap(), 50);
    assert_eq!(t.get(10).unwrap(), 100);
    t.flush().unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 11);
    assert_eq!(t.get(3).unwrap(), 30);
    t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 4)
        .unwrap();
    assert_eq!(t.len(), 4);
    assert!(matches!(
        t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 99),
        Err(StoreError::Corrupt(_))
    ));
    t.flush().unwrap();
    {
        let mut raw = std::fs::read(&path).unwrap();
        let bad = (FILE_HEADER_LEN as u64 + 3).to_le_bytes();
        raw[8..16].copy_from_slice(&bad);
        std::fs::write(&path, &raw).unwrap();
    }
    assert!(matches!(
        ArrayTable::open(&path, TableKind::Confirmed),
        Err(StoreError::Corrupt(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn write_behind_no_flush_reopen_keeps_old_image() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(
            &rbitcoin_store::ClassCWrite::for_test(),
            &[(0, 10), (1, 20)],
        )
        .unwrap();
        t.flush().unwrap();
        t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 999)
            .unwrap();
        t.set(&rbitcoin_store::ClassCWrite::for_test(), 2, 30)
            .unwrap();
        assert_eq!(t.get(0).unwrap(), 999);
        assert_eq!(t.len(), 3);
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 2, "len must stay at last flushed image");
    assert_eq!(t.get(0).unwrap(), 10);
    assert_eq!(t.get(1).unwrap(), 20);
    assert_eq!(t.get(2).unwrap(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn write_behind_flush_reopen_sees_new_image() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &[(0, 1), (1, 2)])
            .unwrap();
        t.flush().unwrap();
        t.set_many(
            &rbitcoin_store::ClassCWrite::for_test(),
            &[(0, 7), (1, 8), (2, 9)],
        )
        .unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 3);
    assert_eq!(t.get(0).unwrap(), 7);
    assert_eq!(t.get(1).unwrap(), 8);
    assert_eq!(t.get(2).unwrap(), 9);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn write_behind_truncate_flush_reopen() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(
            &rbitcoin_store::ClassCWrite::for_test(),
            &[(0, 1), (1, 2), (2, 3), (3, 4)],
        )
        .unwrap();
        t.flush().unwrap();
        t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 2)
            .unwrap();
        assert_eq!(t.len(), 2);
        drop(t);
        let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
        assert_eq!(t.len(), 4);
        t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 2)
            .unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(0).unwrap(), 1);
    assert_eq!(t.get(1).unwrap(), 2);
    let _ = std::fs::remove_file(&path);
}

/// A store in the kept prefix, then a truncate below the last flushed
/// length, must still be on disk after the flush. Shortening the file is
/// not a substitute for that rewrite.
#[test]
fn shrink_flush_persists_a_dirty_kept_slot() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(
            &rbitcoin_store::ClassCWrite::for_test(),
            &[(0, 1), (1, 2), (2, 3), (3, 4)],
        )
        .unwrap();
        t.flush().unwrap();
        t.set(&rbitcoin_store::ClassCWrite::for_test(), 1, 20)
            .unwrap();
        t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 3)
            .unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 3);
    assert_eq!(t.get(0).unwrap(), 1);
    assert_eq!(
        t.get(1).unwrap(),
        20,
        "dirty kept slot must survive the shrink"
    );
    assert_eq!(t.get(2).unwrap(), 3);
    assert_eq!(t.get(3).unwrap(), 0);
    let _ = std::fs::remove_file(&path);
}

/// A truncate that did not store into the kept prefix only shortens the file.
#[test]
fn clean_shrink_shortens_without_rewriting() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 1), (1, 2), (2, 3), (3, 4)],
    )
    .unwrap();
    t.flush().unwrap();
    t.flush_chunk_max.store(0, Ordering::Relaxed);
    t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 2)
        .unwrap();
    t.flush().unwrap();
    assert_eq!(
        t.flush_chunk_max.load(Ordering::Relaxed),
        0,
        "a clean prefix is not rewritten"
    );
    assert_eq!(t.file.logical_len(), FILE_HEADER_LEN as u64 + 2 * ELEM);
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!((t.get(0).unwrap(), t.get(1).unwrap()), (1, 2));
    let _ = std::fs::remove_file(&path);
}

/// Tip extension is append-only: after first flush, only suffix is written.
#[test]
fn append_only_flush_extends_without_losing_prefix() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(
            &rbitcoin_store::ClassCWrite::for_test(),
            &[(0, 100), (1, 101)],
        )
        .unwrap();
        t.flush().unwrap();
        // Pure tip extension (unstored index 2, disk length 2).
        t.set(&rbitcoin_store::ClassCWrite::for_test(), 2, 102)
            .unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 3);
    assert_eq!(t.get(0).unwrap(), 100);
    assert_eq!(t.get(1).unwrap(), 101);
    assert_eq!(t.get(2).unwrap(), 102);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn contiguous_image_flush_async_and_env_cap() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    t.set_many(
        &rbitcoin_store::ClassCWrite::for_test(),
        &[(0, 0), (1, 11), (2, 0), (3, 33), (4, 0), (5, 55)],
    )
    .unwrap();
    assert_eq!(t.len(), 6);
    assert_eq!(t.get(1).unwrap(), 11);
    assert_eq!(t.get(3).unwrap(), 33);
    assert_eq!(t.get(5).unwrap(), 55);
    t.flush_async().unwrap();
    t.flush_dirty().unwrap();
    t.flush().unwrap();
    t.truncate(&rbitcoin_store::ClassCWrite::for_test(), 0)
        .unwrap();
    t.flush().unwrap();
    assert_eq!(t.len(), 0);
    drop(t);

    assert_eq!(
        class_c_inram_cap_from_mb_str(None),
        DEFAULT_CLASS_C_INRAM_MAX_BYTES
    );
    assert_eq!(
        class_c_inram_cap_from_mb_str(Some("128")),
        128 * 1024 * 1024
    );
    assert_eq!(
        class_c_inram_cap_from_mb_str(Some("not-a-number")),
        256 * 1024 * 1024
    );
    let _ = std::fs::remove_file(&path);
}

/// A store from another thread while flush is in its write step is refused.
/// The store after that flush joins is what the next flush persists.
#[test]
fn store_on_another_thread_during_flush_is_refused() {
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::Confirmed).unwrap());
    t.set_many(&rbitcoin_store::ClassCWrite::for_test(), &[(0, 1), (1, 2)])
        .unwrap();
    t.flush().unwrap();
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 5)
        .unwrap();
    let (started, start_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let flush_t = {
        let t = Arc::clone(&t);
        std::thread::spawn(move || {
            t.flush_dirty_between(|_, step| {
                if step == FlushStep::Write {
                    started.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
            })
            .unwrap();
        })
    };
    start_rx.recv().unwrap();
    let during = t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 9);
    release.send(()).unwrap();
    flush_t.join().unwrap();
    assert!(during.is_err(), "store during flush refused={during:?}");
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.get(0).unwrap(), 5);
    t.set(&rbitcoin_store::ClassCWrite::for_test(), 0, 9)
        .unwrap();
    t.flush().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.get(0).unwrap(), 9);
    let _ = std::fs::remove_file(&path);
}

/// Truncate keeps the logical length. A later store may overwrite a slot
/// below that length or append the next index. It may not skip ahead: the
/// bytes above the length are still in the buffer, and a skip would publish
/// them again.
#[test]
fn sparse_set_after_truncate_is_corrupt() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    let write = rbitcoin_store::ClassCWrite::for_test();
    t.set_many(&write, &[(0, 10), (1, 11), (2, 12), (3, 13)])
        .unwrap();
    t.truncate(&write, 1).unwrap();
    assert!(matches!(t.set(&write, 3, 99), Err(StoreError::Corrupt(_))));
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(0).unwrap(), 10);
    t.set(&write, 1, 77).unwrap();
    assert_eq!((t.len(), t.get(0).unwrap(), t.get(1).unwrap()), (2, 10, 77));
    t.set_many(&write, &[(2, 20), (3, 21)]).unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.get(3).unwrap(), 21);
    t.set(&write, 0, 1).unwrap();
    assert_eq!(t.get(0).unwrap(), 1);
    assert!(matches!(
        t.set_many(&write, &[(5, 50)]),
        Err(StoreError::Corrupt(_))
    ));
    assert_eq!(t.len(), 4);
    t.set_zero_gap(&write, 6, 60).unwrap();
    assert_eq!(t.len(), 7);
    assert_eq!(t.get(4).unwrap(), 0);
    assert_eq!(t.get(5).unwrap(), 0);
    assert_eq!(t.get(6).unwrap(), 60);
    assert_eq!(t.get(0).unwrap(), 1);
    let _ = std::fs::remove_file(&path);
}
