use rbitcoin_primitives::{Fk, TableKind};
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::var_table::*;
use std::sync::atomic::AtomicU64;

#[test]
fn class_a_body_waves_serial_is_one_stem_each() {
    assert_eq!(
        class_a_body_waves(false, 0),
        Vec::<std::ops::Range<usize>>::new()
    );
    assert_eq!(class_a_body_waves(false, 3), vec![0..3]);
    assert_eq!(
        class_a_body_waves(true, 0),
        Vec::<std::ops::Range<usize>>::new()
    );
    assert_eq!(class_a_body_waves(true, 2), vec![0..1, 1..2]);
    assert_eq!(class_a_body_waves(true, 3), vec![0..1, 1..2, 2..3]);
}
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::{Arc, Barrier};
use std::thread;

fn put_batch(
    t: &VarTable,
    n: usize,
    estimate_bytes: usize,
    encode: impl FnMut(usize, &mut Vec<u8>),
) -> Result<(Vec<Fk>, Vec<u64>, u64), StoreError> {
    let Some(prep) = t.prepare_batch_encode(n, estimate_bytes, encode)? else {
        return Ok((Vec::new(), Vec::new(), 0));
    };
    let start = prep.start;
    let starts = prep.starts.clone();
    t.write_body_blob_bulk(prep.start, &prep.body_blob)?;
    let fks = t.finish_prepared(prep)?;
    Ok((fks, starts, start))
}

fn read_at(t: &VarTable, off: u64, len: u64) -> Vec<u8> {
    t.with_bytes_at(off, len, |b| Ok(b.to_vec())).unwrap()
}

#[test]
fn body_read_past_published_end_is_corrupt() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-pub-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let err = t
        .with_bytes_at(FILE_HEADER_LEN as u64, 16, |_| Ok(()))
        .expect_err("past published end");
    match err {
        StoreError::Corrupt(msg) => assert!(msg.contains("published"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn body_read_above_the_cap_is_refused() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-cap-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let len = 64 * 1024 * 1024 + 8;
    let err = t
        .with_bytes_at(FILE_HEADER_LEN as u64, len, |_| Ok(()))
        .expect_err("above the body read cap");
    match err {
        StoreError::Rejected(msg) => assert!(msg.contains("too large"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let err = t
        .pread_span(FILE_HEADER_LEN as u64, len)
        .expect_err("span above the body read cap");
    match err {
        StoreError::Rejected(msg) => assert!(msg.contains("too large"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A caller that already paired `(count, end)` still reads inside that
/// end after a later shrink. A fresh load of the shrunk end is corrupt.
#[test]
fn body_read_uses_the_caller_published_end() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-snap-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let (_fks, starts, _) = put_batch(&t, 1, 64, |_i, buf| {
        buf.extend_from_slice(&[0xab; 16]);
    })
    .unwrap();
    let (_count, end) = t.published_meta();
    let off = starts[0];
    t.truncate_body_to(0, FILE_HEADER_LEN as u64).unwrap();
    let body = t
        .with_bytes_at_published(end, off, 16, |b| Ok(b.to_vec()))
        .expect("snapshot end still covers the record");
    assert_eq!(body, vec![0xab; 16]);
    let err = t
        .with_bytes_at(off, 16, |_| Ok(()))
        .expect_err("fresh published end is the shrink");
    match err {
        StoreError::Corrupt(msg) => assert!(msg.contains("published"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file end moves before `finish_prepared` releases the locator count.
/// Point reads follow that end. A caller-supplied seqlock end still rejects
/// the same bytes.
#[test]
fn point_read_follows_body_hwm_ahead_of_the_locator_seqlock() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-hwm-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let seqlock_end = t.body_published_len();
    assert_eq!(seqlock_end, FILE_HEADER_LEN as u64);
    let payload = [0x11u8; 16];
    t.write_body_blob_bulk(seqlock_end, &payload).unwrap();
    assert_eq!(t.body_published_len(), seqlock_end);
    assert!(t.body_logical_len() >= seqlock_end + payload.len() as u64);

    let got = t
        .with_bytes_at(seqlock_end, 16, |b| Ok(b.to_vec()))
        .unwrap();
    assert_eq!(got, payload);
    let mut buf = vec![0u8; 32];
    let got = t
        .with_bytes_at_into(seqlock_end, 16, &mut buf, |b| Ok(b.to_vec()))
        .unwrap();
    assert_eq!(got, payload);
    let got = t
        .with_bytes_at_pread(seqlock_end, 16, |b| Ok(b.to_vec()))
        .unwrap();
    assert_eq!(got, payload);
    assert_eq!(t.pread_span(seqlock_end, 16).unwrap(), payload);

    let err = t
        .with_bytes_at_published(seqlock_end, seqlock_end, 16, |_| Ok(()))
        .expect_err("seqlock end still excludes the HWM bytes");
    match err {
        StoreError::Corrupt(msg) => assert!(msg.contains("published"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_batch_fd_append_roundtrip() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-fd-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let (fks, starts, _) = put_batch(&t, 3, 64, |i, buf| {
        buf.extend_from_slice(&[i as u8 + 1; 16]);
    })
    .unwrap();
    assert_eq!(fks.len(), 3);
    assert_eq!(t.count(), 3);
    let (_c, end) = t.published_meta();
    for (i, off) in starts.iter().enumerate() {
        let nxt = starts.get(i + 1).copied().unwrap_or(end);
        let body = read_at(&t, *off, nxt - *off);
        assert!(body.len() >= 16);
        assert_eq!(&body[..16], &[i as u8 + 1; 16]);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_batch_publish_visible_to_concurrent_readers() {
    let _stress = rbitcoin_store::file::TEST_MMAP_STRESS_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-pub-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = Arc::new(VarTable::create(&dir, "tx", TableKind::TxOut).unwrap());

    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    {
        let t = Arc::clone(&t);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for batch in 0..200u8 {
                let payload = vec![batch; 128];
                put_batch(&t, 4, 512, |_i, buf| {
                    buf.extend_from_slice(&payload);
                })
                .unwrap();
            }
        }));
    }

    for _ in 0..4 {
        let t = Arc::clone(&t);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..20_000 {
                let c = t.count();
                if c == 0 {
                    continue;
                }
                let (meta_c, meta_end) = t.published_meta();
                if meta_c == 0 {
                    continue;
                }
                let rec_len = 128u64;
                let start = FILE_HEADER_LEN as u64 + (meta_c - 1) * rec_len;
                assert!(
                    meta_end >= start + rec_len,
                    "torn publish meta_c={meta_c} meta_end={meta_end} count={c}"
                );
                let raw = read_at(&t, start, rec_len);
                assert!(raw[..128].iter().all(|&b| b == raw[0]));
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
        .expect("concurrent var_table workers timed out (hang?)");
    assert_eq!(t.count(), 800);
    let (c, end) = t.published_meta();
    let start = FILE_HEADER_LEN as u64 + (c - 1) * 128;
    let raw = read_at(&t, start, end - start);
    assert!(raw.len() >= 128);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn published_meta_seqlock_matches_last_record_len() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-var-seqlock-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = Arc::new(VarTable::create(&dir, "tx", TableKind::TxOut).unwrap());
    let stop = Arc::new(AtomicU64::new(0));
    let t_w = Arc::clone(&t);
    let stop_w = Arc::clone(&stop);
    let writer = thread::spawn(move || {
        let mut batch = 0u8;
        while stop_w.load(AtomicOrdering::Acquire) == 0 {
            let payload = vec![batch; 64];
            put_batch(&t_w, 8, 512, |_i, buf| {
                buf.extend_from_slice(&payload);
            })
            .unwrap();
            batch = batch.wrapping_add(1);
        }
    });
    for _ in 0..50_000 {
        let (c, end) = t.published_meta();
        if c == 0 {
            continue;
        }
        let start = end.saturating_sub(64);
        assert!(end >= start + 64, "end={end} start={start} c={c}");
        assert_eq!(
            end - start,
            64,
            "seqlock pair torn: c={c} end={end} start={start}"
        );
    }
    stop.store(1, AtomicOrdering::Release);
    writer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one fixture, many surface arms
#[test]
fn var_table_surface_helpers_and_errors() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-var-surface-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    assert_eq!(t.count(), 0);
    assert!(t.body_logical_len() >= FILE_HEADER_LEN as u64);
    t.advise_body_dont_need(0, 0);
    assert_eq!(put_batch(&t, 0, 0, |_, _| {}).unwrap().0.len(), 0);
    t.reserve_append(1024, 8).unwrap();
    let (fks, starts, _) = put_batch(&t, 3, 64, |i, buf| {
        buf.extend_from_slice(&[i as u8; 16]);
    })
    .unwrap();
    assert_eq!(fks.len(), 3);
    assert_eq!(t.count(), 3);
    let (_c, end) = t.published_meta();
    let off1 = starts[1];
    let len1 = starts.get(2).copied().unwrap_or(end) - off1;
    let raw = read_at(&t, off1, len1);
    assert!(raw.len() >= 16);
    assert_eq!(raw[0], 1);
    let via = t
        .with_bytes_at(off1, len1, |b| {
            assert!(b.len() >= 16);
            Ok(b[0])
        })
        .unwrap();
    assert_eq!(via, 1);
    let off = starts[0];
    let len = starts[1] - off;
    assert_eq!(off % 8, 0);
    let mut prefix = [0u8; 4];
    assert_eq!(
        t.read_prefix_at_published(end, off, len, &mut prefix)
            .unwrap(),
        4
    );
    assert_eq!(prefix, [0, 0, 0, 0]);
    assert_eq!(
        t.read_prefix_at_published(end, off, len, &mut []).unwrap(),
        0
    );
    t.with_bytes_at(off, len, |b| {
        assert!(b.len() >= 16);
        Ok(())
    })
    .unwrap();
    t.with_bytes_at_pread(off, len, |b| {
        assert!(b.len() >= 16);
        Ok(())
    })
    .unwrap();
    t.write_body_abs(off, &[0xff]).unwrap();
    assert_eq!(read_at(&t, off, len)[0], 0xff);
    t.flush().unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = VarTable::open_body_only(&dir, "tx", TableKind::TxOut, 0).unwrap();
    assert_eq!(t.count(), 0, "open_body_only without loc count is 0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn with_bytes_at_into_overwrites_dirty_capacity() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-var-into-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let (_fks, starts, _) = put_batch(&t, 2, 64, |i, buf| {
        buf.extend_from_slice(&[(i as u8).saturating_add(0x5a); 16]);
    })
    .unwrap();
    let (_c, end) = t.published_meta();
    let off = starts[1];
    let len = end - off;
    let mut buf = vec![0xFFu8; (len as usize).saturating_add(32)];
    buf.clear();
    t.with_bytes_at_into(off, len, &mut buf, |b| {
        assert!(!b.is_empty());
        assert_ne!(b[0], 0xFF);
        assert_eq!(b[0], 0x5b);
        Ok(())
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncate_and_empty_helpers() {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, AtomicOrdering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-var-trunc-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
    let (fks, starts, _) = put_batch(&t, 5, 64, |i, buf| {
        buf.extend_from_slice(&[i as u8; 16]);
    })
    .unwrap();
    assert_eq!(fks.len(), 5);
    assert_eq!(t.count(), 5);
    t.truncate_body_to(5, t.published_meta().1).unwrap();
    assert_eq!(t.count(), 5);
    t.truncate_body_to(2, starts[2]).unwrap();
    assert_eq!(t.count(), 2);
    let raw = read_at(&t, starts[0], starts[1] - starts[0]);
    assert!(raw.len() >= 16);
    t.advise_body_dont_need(0, 0);
    let _ = t.body_logical_len();
    let empty = put_batch(&t, 0, 0, |_, _| {}).unwrap().0;
    assert!(empty.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
