//! Class C sequence counter. One `get_sample` is one generation: a length that
//! covers the index has that store's slot. One `get_range` is one header pair.
//! The two checks are separate closures.

use rbitcoin_primitives::{Fk, TableKind};
use rbitcoin_store::chain::HeaderTxsTable;
use rbitcoin_store::ClassCWrite;

/// One slot store against one sample. The length that covers the index has
/// that store's value.
#[test]
fn slot_length_carries_its_slot() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-seq-slot");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let slots = std::sync::Arc::new(
            rbitcoin_store::array_table::ArrayTable::create(
                dir.join("slots.body"),
                TableKind::ArrayLink,
            )
            .unwrap(),
        );
        let slots_w = std::sync::Arc::clone(&slots);
        let writer = loom::thread::spawn(move || {
            slots_w.set(&ClassCWrite::for_test(), 0, 99).unwrap();
        });
        let reader = loom::thread::spawn(move || {
            let (value, len) = slots.get_sample(0).unwrap();
            if len > 0 {
                assert_eq!(value, 99, "new length with a slot from before the store");
            } else {
                assert_eq!(value, 0);
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// One later header pair against a pair stored before either thread starts.
/// A mix of the two generations panics.
#[test]
fn header_pair_is_one_generation() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-seq-header");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let headers = std::sync::Arc::new(HeaderTxsTable::create(&dir).unwrap());
        headers
            .put_range(&ClassCWrite::for_test(), Fk(1), Fk(10), 4)
            .unwrap();
        let headers_w = std::sync::Arc::clone(&headers);
        let writer = loom::thread::spawn(move || {
            headers_w
                .put_range(&ClassCWrite::for_test(), Fk(1), Fk(50), 9)
                .unwrap();
        });
        let reader = loom::thread::spawn(move || match headers.get_range(Fk(1)).unwrap() {
            None | Some((Fk(10), 4)) | Some((Fk(50), 9)) => {}
            other => panic!("torn header range {other:?}"),
        });
        writer.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// Two slots and the length against a truncate and re-append, in RAM. Every
/// answer is one state the writer passed through.
#[test]
fn slot_pair_is_one_generation() {
    super::engine::check_at_most(2, || {
        let dir = std::env::temp_dir().join("rbtc-seq-pair");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let slots = std::sync::Arc::new(
            rbitcoin_store::array_table::ArrayTable::create(
                dir.join("slots.body"),
                TableKind::ArrayLink,
            )
            .unwrap(),
        );
        for (index, value) in [(0, 1), (1, 2), (2, 3)] {
            slots.set(&ClassCWrite::for_test(), index, value).unwrap();
        }
        let slots_w = std::sync::Arc::clone(&slots);
        let writer = loom::thread::spawn(move || {
            slots_w.truncate(&ClassCWrite::for_test(), 1).unwrap();
            slots_w.set(&ClassCWrite::for_test(), 1, 20).unwrap();
        });
        let reader = loom::thread::spawn(move || match slots.get_pair_sample(1).unwrap() {
            ([2, 3], 3) | ([0, 0], 1) | ([20, 0], 2) => {}
            (pair, len) => panic!("sample {pair:?} at len {len}"),
        });
        writer.join().unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    });
}
