//! Disk-only Class C. An append's length covers that store's slot. A get
//! that races a truncate reads as absent.
//!
//! The file is pre-sized so `open` stays fd-only under a zero RAM cap. An
//! empty `create` is in RAM even when that cap is 0. Index 0 of a one-slot
//! file is an overwrite. The append is the next index.

use rbitcoin_primitives::TableKind;
use rbitcoin_store::array_table::ArrayTable;
use rbitcoin_store::file::TableFile;
use rbitcoin_store::ClassCWrite;
use std::path::Path;

fn open_fd_only(dir: &Path, slots: u64) -> ArrayTable {
    // `set_var` is process-global. The model binary runs these tests in
    // parallel, so one open must not restore the cap under the other.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let path = dir.join("slots.body");
    let file = TableFile::create(&path, TableKind::ArrayLink).unwrap();
    let zeros = vec![0u8; (slots * 8) as usize];
    if slots > 0 {
        file.write_at(ArrayTable::offset(0), &zeros).unwrap();
    }
    drop(file);
    let prev = std::env::var_os("RBITCOIN_CLASS_C_INRAM_MAX_MB");
    std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", "0");
    let table = ArrayTable::open(&path, TableKind::ArrayLink).unwrap();
    match prev {
        Some(v) => std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", v),
        None => std::env::remove_var("RBITCOIN_CLASS_C_INRAM_MAX_MB"),
    }
    assert_eq!(table.l2_resident_bytes(), 0, "disk-only table");
    table
}

/// One append against one sample. A length that covers the new index has
/// that store's value.
#[test]
fn fd_only_append_publishes_its_value() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-fd-append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let slots = std::sync::Arc::new(open_fd_only(&dir, 1));
        let slots_w = std::sync::Arc::clone(&slots);
        let writer = loom::thread::spawn(move || {
            slots_w.set(&ClassCWrite::for_test(), 1, 99).unwrap();
        });
        let reader = loom::thread::spawn(move || {
            let (value, len) = slots.get_sample(1).unwrap();
            if len > 1 {
                assert_eq!(value, 99, "new length with a zero fill");
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// One truncate against one sample of a primed slot. Absent, or the value
/// with a length that still covers the index. Not a past-end pread.
#[test]
fn fd_only_get_during_truncate_is_absent_or_present() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-fd-trunc");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let slots = std::sync::Arc::new(open_fd_only(&dir, 2));
        slots.set(&ClassCWrite::for_test(), 0, 11).unwrap();
        slots.set(&ClassCWrite::for_test(), 1, 22).unwrap();
        let slots_w = std::sync::Arc::clone(&slots);
        let truncator = loom::thread::spawn(move || {
            slots_w.truncate(&ClassCWrite::for_test(), 0).unwrap();
        });
        let reader = loom::thread::spawn(move || match slots.get_sample(1) {
            Ok((0, len)) => assert!(len <= 1, "zero slot while length covers it: {len}"),
            Ok((22, len)) if len > 1 => {}
            Ok((value, len)) => panic!("sample {value} at len {len}"),
            Err(e) => panic!("pread raced truncate: {e}"),
        });
        truncator.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// A reorg shape against one sample: truncate below a slot, then append a
/// new value there. The sample is one generation: the old value with the old
/// length, absent, or the new value with a length that covers it. Not the
/// old value with the new length.
#[test]
fn fd_only_sample_is_one_generation() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-fd-gen");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let slots = std::sync::Arc::new(open_fd_only(&dir, 3));
        for (index, value) in [(0, 1), (1, 2), (2, 3)] {
            slots.set(&ClassCWrite::for_test(), index, value).unwrap();
        }
        let slots_w = std::sync::Arc::clone(&slots);
        let writer = loom::thread::spawn(move || {
            slots_w.truncate(&ClassCWrite::for_test(), 1).unwrap();
            slots_w.set(&ClassCWrite::for_test(), 1, 20).unwrap();
        });
        let reader = loom::thread::spawn(move || match slots.get_sample(1).unwrap() {
            (2, 3) | (0, 1) | (20, 2) => {}
            (value, len) => panic!("sample {value} at len {len}"),
        });
        writer.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}
