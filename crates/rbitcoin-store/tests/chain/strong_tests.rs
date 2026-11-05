use rbitcoin_primitives::Fk;
use rbitcoin_store::chain::*;
use rbitcoin_store::error::StoreError;

fn tmp() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rbitcoin-strong-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Growing the bit image keeps one committed prefix. Earlier bits stay.
#[test]
fn strong_commit_is_the_used_prefix_not_a_second_image() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    let write = rbitcoin_store::ClassCWrite::for_test();
    t.set_bit(&write, 0, true).unwrap();
    t.set_bit(&write, 1_000, true).unwrap();
    let bytes = 4 * 1024 * 1024 + 100;
    t.ensure_bits(&write, bytes * 8).unwrap();
    assert!(t.get_bit(0).unwrap());
    assert!(t.get_bit(1_000).unwrap());
    let page = rbitcoin_store::array_table::class_c_commit_quantum();
    let words = bytes.div_ceil(8);
    let expect = words.saturating_mul(8).div_ceil(page) * page;
    let committed = t.committed_bytes();
    assert_eq!(committed, expect, "committed {committed} prefix {expect}");
    let pow2 = words.next_power_of_two() * 8;
    assert_ne!(committed, pow2, "prefix is not the next power of two");
    assert!(
        t.l2_resident_bytes() == bytes,
        "meter stays the logical body"
    );
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A bit past the 256 MiB reservation is corrupt and does not commit that range.
#[test]
fn strong_bit_past_the_reservation_is_corrupt() {
    use rbitcoin_store::array_table::DEFAULT_CLASS_C_INRAM_MAX_BYTES;
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    let err = t
        .ensure_bits(
            &rbitcoin_store::ClassCWrite::for_test(),
            (DEFAULT_CLASS_C_INRAM_MAX_BYTES + 1) * 8,
        )
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Corrupt(msg) if msg.contains("reservation")),
        "{err:?}"
    );
    assert_eq!(t.committed_bytes(), 0);
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two flushes of the bit image and one store all return. Loom cannot run
/// this: the flush lock is a real mutex, and a second waiter blocks the
/// model thread. A store that returned is on disk once the mark is clean.
#[test]
fn two_strong_flushes_keep_a_store_that_returned() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let dir = tmp();
    let table = Arc::new(StrongTxTable::create(&dir).unwrap());
    table
        .set_bit(&rbitcoin_store::ClassCWrite::for_test(), 0, true)
        .unwrap();
    table.flush().unwrap();
    let stored = Arc::new(AtomicBool::new(false));
    let writing = Arc::clone(&table);
    let stored_w = Arc::clone(&stored);
    let writer = std::thread::spawn(move || {
        if writing
            .set_bit(&rbitcoin_store::ClassCWrite::for_test(), 8, true)
            .is_ok()
        {
            stored_w.store(true, Ordering::Relaxed);
        }
    });
    let first = Arc::clone(&table);
    let second = Arc::clone(&table);
    let flush_a = std::thread::spawn(move || first.table.flush_dirty().unwrap());
    let flush_b = std::thread::spawn(move || second.table.flush_dirty().unwrap());
    writer.join().unwrap();
    flush_a.join().unwrap();
    flush_b.join().unwrap();
    if stored.load(Ordering::Relaxed)
        && table.table.unstored_from.load(Ordering::Relaxed) == u64::MAX
    {
        let opened = StrongTxTable::open(&dir).unwrap();
        assert!(
            opened.get_bit(8).unwrap(),
            "store that returned is not on disk"
        );
    }
    drop(table);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A bit store after the flush has noticed dirt, and before new stores are
/// excluded, is still in this flush.
#[test]
fn strong_store_before_exclude_is_in_this_flush() {
    use rbitcoin_store::array_table::FlushStep;
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 16, Fk(1))
        .unwrap();
    t.flush().unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(9))
        .unwrap();
    t.flush_observing(|t, step| {
        if step == FlushStep::Admit {
            t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1))
                .unwrap();
        }
    })
    .unwrap();
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(
        !t.is_strong(Fk(1)).unwrap(),
        "earlier byte must be in this flush"
    );
    assert!(!t.is_strong(Fk(9)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Flush persists the live bit image. A bit store from the write hook is
/// refused; a store after flush returns lands in the next flush.
#[test]
fn strong_flush_writes_live_bytes_and_refuses_a_store() {
    use rbitcoin_store::array_table::{FlushStep, FLUSH_SCRATCH};
    use std::sync::atomic::Ordering;
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    let bits = (FLUSH_SCRATCH as u32) * 8 + 64;
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), bits, Fk(1))
        .unwrap();
    t.flush().unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1))
        .unwrap();
    let mut during = Ok(());
    t.flush_observing(|t, step| {
        if step == FlushStep::Write {
            t.poke_live_byte(0, 0xff);
            during = t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(2));
        }
    })
    .unwrap();
    assert!(during.is_err(), "store during flush refused={during:?}");
    let chunk = t.table.flush_chunk_max.load(Ordering::Relaxed);
    assert!(chunk > 0 && chunk <= FLUSH_SCRATCH, "flush chunk {chunk}");
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(
        t.is_strong(Fk(1)).unwrap(),
        "live byte must be the flushed image"
    );
    assert!(t.is_strong(Fk(2)).unwrap(), "refused store stays off disk");
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(2))
        .unwrap();
    t.flush().unwrap();
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(!t.is_strong(Fk(2)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed bit-image `write_at` leaves that range dirty. The retry writes it.
#[cfg(target_os = "linux")]
#[test]
fn strong_failed_write_keeps_the_range_dirty() {
    use rbitcoin_store::array_table::FlushStep;
    use rbitcoin_store::file::FILE_HEADER_LEN;
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
        .unwrap();
    t.flush().unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1))
        .unwrap();
    let mut swapped = None;
    let failed = t.flush_observing(|t, step| {
        if step == FlushStep::Write {
            swapped = Some(crate::dev_full::DevFull::on(&t.table.file.read_file));
        }
    });
    drop(swapped);
    assert!(
        failed.is_err(),
        "write_at must fail while the fd is /dev/full"
    );
    let mut byte = [0u8; 1];
    t.table
        .file
        .read_at(FILE_HEADER_LEN as u64, &mut byte)
        .unwrap();
    assert_eq!(byte[0] & 1, 1, "failed persist must not publish the clear");
    t.flush().unwrap();
    t.table
        .file
        .read_at(FILE_HEADER_LEN as u64, &mut byte)
        .unwrap();
    assert_eq!(byte[0] & 1, 0, "retry writes the same slots");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A same-length bit rewrite still publishes the recorded body length.
#[test]
fn strong_same_length_rewrite_publishes_logical_len() {
    use rbitcoin_store::file::FILE_HEADER_LEN;
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 16, Fk(1))
        .unwrap();
    t.flush().unwrap();
    let published = t.table.file.logical_len();
    assert!(published > FILE_HEADER_LEN as u64);
    t.table.file.set_logical_len(published + 64).unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(3))
        .unwrap();
    t.flush_dirty().unwrap();
    assert_eq!(t.table.file.logical_len(), published);
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(!t.is_strong(Fk(3)).unwrap());
    assert!(t.is_strong(Fk(1)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strong_bitset_range_and_clear() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 10, Fk(99))
        .unwrap();
    for i in 1..=10 {
        assert!(t.is_strong(Fk(i)).unwrap());
    }
    assert!(!t.is_strong(Fk(11)).unwrap());
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(5))
        .unwrap();
    assert!(!t.is_strong(Fk(5)).unwrap());
    assert!(t.is_strong(Fk(4)).unwrap());
    assert!(t.get(Fk(1)).unwrap().is_some());
    assert!(t.get(Fk(5)).unwrap().is_none());
    t.flush().unwrap();
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(t.is_strong(Fk(1)).unwrap());
    assert!(!t.is_strong(Fk(5)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn count_strong_in_fk_range_skips_zero_bytes() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    assert_eq!(t.count_strong_in_fk_range(0, 8).unwrap(), 0);
    assert_eq!(t.count_strong_in_fk_range(5, 5).unwrap(), 0);
    assert_eq!(t.count_strong_in_fk_range(100, 200).unwrap(), 0);
    t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
        .unwrap();
    t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(16), Fk(1))
        .unwrap();
    assert_eq!(t.count_strong_in_fk_range(1, 17).unwrap(), 2);
    assert_eq!(t.count_strong_in_fk_range(2, 16).unwrap(), 0);
    t.flush().unwrap();
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert_eq!(t.count_strong_in_fk_range(1, 17).unwrap(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Count uses the L2 image. A scribbled `strong_tx.body` does not change it.
#[test]
fn strong_tx_count_reads_l2_not_the_file() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 20, Fk(1))
        .unwrap();
    t.flush().unwrap();
    assert!(t.l2_resident_bytes() > 0);
    assert_eq!(t.count_strong_in_fk_range(1, 21).unwrap(), 20);
    let path = dir.join("strong_tx.body");
    let mut bytes = std::fs::read(&path).unwrap();
    let header = rbitcoin_store::file::FILE_HEADER_LEN;
    assert!(bytes.len() > header);
    for b in &mut bytes[header..] {
        *b = 0;
    }
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(t.count_strong_in_fk_range(1, 21).unwrap(), 20);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `strong_tx` stays L2 even when the Class C array cap would demote it.
#[test]
fn strong_tx_always_l2_above_class_c_cap() {
    let dir = tmp();
    // 1 MiB + 1 byte of bits → body > class_c_inram_max_bytes() (1 MiB).
    let fk = Fk(8_388_608 + 8);
    rbitcoin_store::array_table::with_class_c_inram_max_bytes(1024 * 1024, || {
        {
            let t = StrongTxTable::create(&dir).unwrap();
            t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), fk, Fk(1))
                .unwrap();
            t.flush().unwrap();
            assert!(
                t.l2_resident_bytes() > 1024 * 1024,
                "create path L2={}",
                t.l2_resident_bytes()
            );
        }
        let t = StrongTxTable::open(&dir).unwrap();
        assert!(
            t.l2_resident_bytes() > 1024 * 1024,
            "reopen must keep L2 under a 1 MiB Class C cap; got {}",
            t.l2_resident_bytes()
        );
        assert!(t.is_strong(fk).unwrap());
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strong_store_on_another_thread_during_flush_is_refused() {
    use rbitcoin_store::array_table::FlushStep;
    use std::sync::Arc;
    let dir = tmp();
    let t = Arc::new(StrongTxTable::create(&dir).unwrap());
    t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
        .unwrap();
    t.flush().unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1))
        .unwrap();
    let (started, start_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let flush_t = {
        let t = Arc::clone(&t);
        std::thread::spawn(move || {
            t.table
                .flush_dirty_between(|_, step| {
                    if step == FlushStep::Write {
                        started.send(()).unwrap();
                        release_rx.recv().unwrap();
                    }
                })
                .unwrap();
        })
    };
    start_rx.recv().unwrap();
    let during = t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1));
    release.send(()).unwrap();
    flush_t.join().unwrap();
    assert!(during.is_err(), "store during flush refused={during:?}");
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(!t.is_strong(Fk(1)).unwrap());
    t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
        .unwrap();
    t.flush().unwrap();
    drop(t);
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(t.is_strong(Fk(1)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strong_write_behind_no_flush_keeps_old() {
    let dir = tmp();
    {
        let t = StrongTxTable::create(&dir).unwrap();
        t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 8, Fk(1))
            .unwrap();
        t.flush().unwrap();
        t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(9), Fk(1))
            .unwrap();
        // Drop without flush.
    }
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(t.is_strong(Fk(1)).unwrap());
    assert!(
        !t.is_strong(Fk(9)).unwrap(),
        "unflushed strong must not survive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// High-fk-only dirties must write a suffix, not the full L2 image.
#[test]
fn strong_high_fk_flush_writes_suffix_not_full_image() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    // 80_000 bits = 10_000 payload bytes.
    t.set_strong_range(
        &rbitcoin_store::ClassCWrite::for_test(),
        Fk(1),
        80_000,
        Fk(1),
    )
    .unwrap();
    t.flush_dirty().unwrap();
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(80_000))
        .unwrap();
    t.flush_dirty().unwrap();
    assert!(t.is_strong(Fk(1)).unwrap());
    assert!(!t.is_strong(Fk(80_000)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// In-prefix high-bit dirties must flush without losing low bits (suffix write).
#[test]
fn strong_suffix_dirty_flush_preserves_prefix() {
    let dir = tmp();
    {
        let s = StrongTxTable::create(&dir).unwrap();
        // Allocate a wide bit image then flush so disk_bytes covers it.
        s.set_strong_range(
            &rbitcoin_store::ClassCWrite::for_test(),
            Fk(1),
            10_000,
            Fk(1),
        )
        .unwrap();
        s.flush().unwrap();
        // Flip only high bits (still within disk image) — suffix dirty path.
        s.set_strong_range(
            &rbitcoin_store::ClassCWrite::for_test(),
            Fk(9000),
            100,
            Fk(1),
        )
        .unwrap();
        s.flush().unwrap();
    }
    let s = StrongTxTable::open(&dir).unwrap();
    assert!(s.is_strong(Fk(1)).unwrap());
    assert!(s.is_strong(Fk(5000)).unwrap());
    assert!(s.is_strong(Fk(9000)).unwrap());
    assert!(s.is_strong(Fk(9099)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strong_write_behind_flush_reopen() {
    let dir = tmp();
    {
        let t = StrongTxTable::create(&dir).unwrap();
        t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 16, Fk(1))
            .unwrap();
        t.flush().unwrap();
        t.set_unstrong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(5), 4)
            .unwrap();
        t.flush().unwrap();
    }
    let t = StrongTxTable::open(&dir).unwrap();
    assert!(t.is_strong(Fk(1)).unwrap());
    assert!(!t.is_strong(Fk(5)).unwrap());
    assert!(!t.is_strong(Fk(8)).unwrap());
    assert!(t.is_strong(Fk(9)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strong_partial_bytes_unstrong_range_and_errors() {
    let dir = tmp();
    let t = StrongTxTable::create(&dir).unwrap();
    // Unaligned start so partial-first-byte path runs.
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(3), 20, Fk(1))
        .unwrap();
    for i in 3..23 {
        assert!(t.is_strong(Fk(i)).unwrap(), "i={i}");
    }
    assert!(!t.is_strong(Fk(2)).unwrap());
    t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 0, Fk(1))
        .unwrap();
    t.set_unstrong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 0)
        .unwrap();
    // Clear a mid-range with partial ends.
    t.set_unstrong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(5), 10)
        .unwrap();
    for i in 5..15 {
        assert!(!t.is_strong(Fk(i)).unwrap());
    }
    assert!(t.is_strong(Fk(4)).unwrap());
    assert!(t.is_strong(Fk(15)).unwrap());
    // past allocated → no-op
    t.set_unstrong(&rbitcoin_store::ClassCWrite::for_test(), Fk(9999))
        .unwrap();
    t.set_unstrong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(9000), 10)
        .unwrap();
    assert!(matches!(
        t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk::NULL, Fk(1)),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(
        t.set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk::NULL),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(
        t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk::NULL, 1, Fk(1)),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(
        t.set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 1, Fk::NULL),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(t.is_strong(Fk::NULL), Err(StoreError::InvalidFk)));
    t.flush_async().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
