use rbitcoin_primitives::TableKind;
use rbitcoin_store::array_table::*;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// `get` checks `len` before taking the read lock, so a `truncate` can
/// land in between. The reader must see the shorter table, not panic.
#[test]
fn get_racing_truncate_does_not_panic() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::Confirmed).unwrap());
    t.set(1023, 7).unwrap();
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
        t.truncate(0).unwrap();
        t.set(1023, 7).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        assert!(r.join().is_ok(), "get panicked racing truncate");
    }
    let _ = std::fs::remove_file(&path);
}

/// A `set` that lands while flush marks the table clean is written by
/// the next flush. The IBD tip flush runs beside the next batch's archive.
#[test]
fn set_during_flush_clean_is_flushed_next() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::ArrayLink).unwrap();
    t.set_many(&[(0, 10), (1, 11), (2, 12), (3, 13)]).unwrap();
    t.flush().unwrap();
    t.set(3, 23).unwrap();
    t.flush_dirty_between(|t, step| {
        if step == FlushStep::Clean {
            t.set(1, 21).unwrap();
        }
    })
    .unwrap();
    t.flush().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::ArrayLink).unwrap();
    assert_eq!((t.get(1).unwrap(), t.get(3).unwrap()), (21, 23));
    let _ = std::fs::remove_file(&path);
}

/// Two flushes of one table never leave the older image on disk. A body
/// repair flushes `header_txs` beside the IBD tip flush.
#[test]
fn concurrent_flushes_keep_the_newer_image() {
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::ArrayLink).unwrap());
    t.set_many(&[(0, 10), (1, 11)]).unwrap();
    t.flush().unwrap();
    t.set(0, 20).unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    let mut other = Some(Arc::clone(&t));
    let mut second = None;
    t.flush_dirty_between(|_, step| {
        let Some(t2) = other.take().filter(|_| step == FlushStep::Write) else {
            return;
        };
        let done = done.clone();
        second = Some(std::thread::spawn(move || {
            t2.set(1, 21).unwrap();
            t2.flush().unwrap();
            done.send(()).unwrap();
        }));
        let _ = finished.recv_timeout(std::time::Duration::from_millis(200));
    })
    .unwrap();
    second.unwrap().join().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::ArrayLink).unwrap();
    assert_eq!((t.get(0).unwrap(), t.get(1).unwrap()), (20, 21));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn dirty_epoch_bump_from_max_stays_dirty() {
    let e = AtomicU64::new(u64::MAX);
    dirty_epoch_bump(&e);
    assert_ne!(e.load(Ordering::Acquire), 0);
    assert_eq!(e.load(Ordering::Acquire), 1);
}

#[test]
fn array_set_get_grow_set_many_truncate_flush() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 0);
    assert_eq!(t.get(0).unwrap(), 0);
    t.set(3, 30).unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.get(0).unwrap(), 0);
    assert_eq!(t.get(3).unwrap(), 30);
    t.set(1, 11).unwrap();
    assert_eq!(t.get(1).unwrap(), 11);
    t.set_many(&[]).unwrap();
    t.set_many(&[(10, 100), (5, 50)]).unwrap();
    assert_eq!(t.len(), 11);
    assert_eq!(t.get(5).unwrap(), 50);
    assert_eq!(t.get(10).unwrap(), 100);
    t.flush().unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 11);
    assert_eq!(t.get(3).unwrap(), 30);
    t.truncate(4).unwrap();
    assert_eq!(t.len(), 4);
    assert!(matches!(t.truncate(99), Err(StoreError::Corrupt(_))));
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
        t.set_many(&[(0, 10), (1, 20)]).unwrap();
        t.flush().unwrap();
        t.set(0, 999).unwrap();
        t.set(2, 30).unwrap();
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
        t.set_many(&[(0, 1), (1, 2)]).unwrap();
        t.flush().unwrap();
        t.set_many(&[(0, 7), (1, 8), (2, 9)]).unwrap();
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
        t.set_many(&[(0, 1), (1, 2), (2, 3), (3, 4)]).unwrap();
        t.flush().unwrap();
        t.truncate(2).unwrap();
        assert_eq!(t.len(), 2);
        drop(t);
        let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
        assert_eq!(t.len(), 4);
        t.truncate(2).unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(0).unwrap(), 1);
    assert_eq!(t.get(1).unwrap(), 2);
    let _ = std::fs::remove_file(&path);
}

/// A set below the old on-disk length after a truncate was dropped by the
/// shrink-only flush.
#[test]
fn truncate_then_set_below_old_disk_len_persists() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(&[(0, 1), (1, 2), (2, 3), (3, 4)]).unwrap();
        t.flush().unwrap();
        t.truncate(2).unwrap();
        t.set(2, 9).unwrap();
        t.set(0, 99).unwrap();
        t.flush().unwrap();
    }
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!((t.len(), t.get(0).unwrap(), t.get(2).unwrap()), (3, 99, 9));
    assert_eq!(t.get(1).unwrap(), 2);
    let _ = std::fs::remove_file(&path);
}

/// Tip extension is append-only: after first flush, only suffix is written.
#[test]
fn append_only_flush_extends_without_losing_prefix() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    {
        let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
        t.set_many(&[(0, 100), (1, 101)]).unwrap();
        t.flush().unwrap();
        // Pure tip extension (dirty_lo = 2 >= disk_len = 2).
        t.set(2, 102).unwrap();
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
fn set_gap_zeros_prefix_and_env_cap_and_flush_async() {
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = ArrayTable::create(&path, TableKind::Confirmed).unwrap();
    t.set(3, 42).unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.get(0).unwrap(), 0);
    assert_eq!(t.get(1).unwrap(), 0);
    assert_eq!(t.get(2).unwrap(), 0);
    assert_eq!(t.get(3).unwrap(), 42);
    t.set_many(&[(1, 11), (5, 55), (3, 33)]).unwrap();
    assert_eq!(t.len(), 6);
    assert_eq!(t.get(1).unwrap(), 11);
    assert_eq!(t.get(3).unwrap(), 33);
    assert_eq!(t.get(5).unwrap(), 55);
    t.flush_async().unwrap();
    t.flush_dirty().unwrap();
    t.flush().unwrap();
    t.truncate(0).unwrap();
    t.flush().unwrap();
    assert_eq!(t.len(), 0);
    drop(t);

    let prev = std::env::var_os("RBITCOIN_CLASS_C_INRAM_MAX_MB");
    std::env::remove_var("RBITCOIN_CLASS_C_INRAM_MAX_MB");
    assert_eq!(class_c_inram_max_bytes(), DEFAULT_CLASS_C_INRAM_MAX_BYTES);
    std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", "128");
    assert_eq!(class_c_inram_max_bytes(), 128 * 1024 * 1024);
    std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", "not-a-number");
    assert_eq!(class_c_inram_max_bytes(), 256 * 1024 * 1024); // parse fallback
    match prev {
        Some(v) => std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", v),
        None => std::env::remove_var("RBITCOIN_CLASS_C_INRAM_MAX_MB"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn concurrent_set_during_flush_persists_new() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomOrd};
    use std::sync::Arc;
    let path = tmp_path();
    let _ = std::fs::remove_file(&path);
    let t = Arc::new(ArrayTable::create(&path, TableKind::Confirmed).unwrap());
    let n = 32_768u64;
    let pairs: Vec<(u64, u64)> = (0..n).map(|i| (i, i)).collect();
    t.set_many(&pairs).unwrap();
    t.flush().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flush_t = {
        let t = Arc::clone(&t);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(AtomOrd::Relaxed) {
                t.flush_dirty().unwrap();
            }
        })
    };
    for i in 1..2_000u64 {
        t.set(0, i).unwrap();
    }
    stop.store(true, AtomOrd::Relaxed);
    flush_t.join().unwrap();
    let want = t.get(0).unwrap();
    t.flush().unwrap();
    drop(t);
    let t = ArrayTable::open(&path, TableKind::Confirmed).unwrap();
    assert_eq!(
        t.get(0).unwrap(),
        want,
        "set that races flush must still persist"
    );
    let _ = std::fs::remove_file(&path);
}
