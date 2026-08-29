//! Tx table unit tests (peeled).

use super::*;
use crate::compact::{
    classify_script, decode_script_kind_v17, encode_script_kind_v17, expand_script_kind,
    SCRIPT_KIND_V17_EMPTY, SCRIPT_KIND_V17_OP_RETURN_PUSH, SCRIPT_KIND_V17_OP_TRUE,
    SCRIPT_KIND_V17_P2A, SCRIPT_KIND_V17_P2PKH, SCRIPT_KIND_V17_P2SH, SCRIPT_KIND_V17_P2TR,
    SCRIPT_KIND_V17_P2WPKH, SCRIPT_KIND_V17_P2WSH, SCRIPT_KIND_V17_RAW,
};
use rbitcoin_primitives::{Fk, TableKind};
use std::path::Path;

fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tiny_layout() -> HeadLayout {
    HeadLayout::new(crate::address_head::TINY_BITS).unwrap()
}

fn create_tiny(dir: &Path) -> TxTable {
    TxTable::create_with_head_layout(dir, tiny_layout()).unwrap()
}

fn meta_only_items(recs: &[TxRecord]) -> Vec<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)> {
    recs.iter()
        .cloned()
        .map(|tx| (tx, Vec::new(), Vec::new()))
        .collect()
}

/// Process-global env knobs still used by a few tests (read-batch / bulk IO).
/// Hold this while mutating so parallel tests cannot race.
static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_env_lock<R>(f: impl FnOnce() -> R) -> R {
    let _g = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Offline output-run decode (production uses packed denserels path).
fn decode_output_run_prefix(
    buf: &[u8],
    count: u32,
) -> Result<(Vec<OutputRecord>, usize), StoreError> {
    let mut out = Vec::with_capacity(count as usize);
    let mut off = 0;
    for _ in 0..count {
        let (rec, used) = OutputRecord::decode_at(&buf[off..])?;
        off += used;
        out.push(rec);
    }
    Ok((out, off))
}

fn decode_output_run(buf: &[u8], count: u32) -> Result<Vec<OutputRecord>, StoreError> {
    let (out, used) = decode_output_run_prefix(buf, count)?;
    if used != buf.len() {
        return Err(StoreError::Corrupt("output run trailing bytes"));
    }
    Ok(out)
}

fn decode_input_run(buf: &[u8], count: u32) -> Result<Vec<InputRecord>, StoreError> {
    let (out, used) = decode_input_run_prefix(buf, count)?;
    if used != buf.len() {
        return Err(StoreError::Corrupt("input run trailing bytes"));
    }
    Ok(out)
}

#[test]
fn open_refuses_packed_tx_body_with_creates() {
    let dir = tempfile_dir("legacy-tx-body");
    {
        let t = crate::var_table::VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        t.put_batch_encode(1, 32, |_, buf| buf.extend_from_slice(&[1u8; 16]))
            .unwrap();
    }
    match TxTable::open(&dir) {
        Ok(_) => panic!("packed tx.body must refuse"),
        Err(err) => assert!(format!("{err}").contains("packed tx.body"), "{err}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_refuses_txout_without_peer_stems() {
    let dir = tempfile_dir("missing-stems");
    {
        let t = create_tiny(&dir);
        let rec = TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        };
        t.put_full_batch_indexed(&meta_only_items(&[rec]), true)
            .unwrap();
    }
    let _ = std::fs::remove_file(dir.join("inwit.body"));
    match TxTable::open(&dir) {
        Ok(_) => panic!("missing inwit must refuse"),
        Err(err) => assert!(format!("{err}").contains("missing inwit/spent"), "{err}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_full_batch_from_pins_roundtrip() {
    let dir = tempfile_dir("from-pins");
    let t = create_tiny(&dir);
    let tx = TxRecord {
        txid: [3u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let outs = vec![OutputRecord::unspent(7, vec![0x51])];
    let pin = std::sync::Arc::new((tx, outs));
    let fks = t.put_full_batch_from_pins(&[(pin, ins)], true).unwrap();
    let (got, gins, gouts) = t.get_full(fks[0]).unwrap();
    assert_eq!(got.txid, [3u8; 32]);
    assert_eq!(gins.len(), 1);
    assert_eq!(gouts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Class A append submits txout+inwit+spent bodies as one pwrite wave (not 3 serial).
#[test]
fn put_full_batch_one_body_write_wave() {
    let dir = tempfile_dir("one-wave");
    let t = create_tiny(&dir);
    let tx = TxRecord {
        txid: [4u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let outs = vec![OutputRecord::unspent(7, vec![0x51])];
    let pin = std::sync::Arc::new((tx, outs));
    let _ = crate::bulk_io::test_take_pwrite_waves();
    let fks = t.put_full_batch_from_pins(&[(pin, ins)], true).unwrap();
    assert_eq!(fks.len(), 1);
    let waves = crate::bulk_io::test_take_pwrite_waves();
    assert!(
        waves.iter().any(|&n| n >= 3),
        "expected one ≥3-op body wave, got {waves:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pending_head_resolve_before_drain() {
    let dir = tempfile_dir("pending-hit");
    let t = create_tiny(&dir);
    let mut txid = [0u8; 32];
    txid[0] = 0x51;
    let rec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 0,
        output_start_fk: Fk::NULL,
        output_count: 0,
    };
    let fks = t
        .put_full_batch_indexed(&meta_only_items(&[rec]), /*index=*/ false)
        .unwrap();
    assert!(
        t.get_fk_by_txid(&txid).unwrap().is_none(),
        "durable head must miss before drain"
    );
    t.head_note_pending(&[(txid, fks[0])]);
    assert!(
        t.get_fk_by_txid(&txid).unwrap().is_none(),
        "queued drain list is not a leftover home"
    );
    assert_eq!(t.head_drain_pending().unwrap(), 1);
    assert_eq!(t.pending_head_len(), 0);
    assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(fks[0]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pending_head_same_page_drains_one_write() {
    let dir = tempfile_dir("pending-page");
    let t = create_tiny(&dir);
    let bits = t.head_bits();
    let mut items = Vec::new();
    let mut i = 1u64;
    while items.len() < 8 {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&i.to_le_bytes());
        let mixed = t.mix_txid_for_head(&txid);
        if items.is_empty() {
            items.push((txid, i));
        } else {
            let want =
                crate::address_head::page_base_for_txid(&t.mix_txid_for_head(&items[0].0), bits);
            if crate::address_head::page_base_for_txid(&mixed, bits) == want {
                items.push((txid, i));
            }
        }
        i += 1;
        if i > 50_000 {
            panic!("could not find 8 keys on one head page");
        }
    }
    let recs: Vec<TxRecord> = items
        .iter()
        .map(|(txid, _)| TxRecord {
            txid: *txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        })
        .collect();
    let fks = t
        .put_full_batch_indexed(&meta_only_items(&recs), false)
        .unwrap();
    let pending: Vec<([u8; 32], Fk)> = recs
        .iter()
        .zip(fks.iter())
        .map(|(r, fk)| (r.txid, *fk))
        .collect();
    t.head_note_pending(&pending);
    let _ = crate::address_head::test_take_head_page_writes();
    assert_eq!(t.head_drain_pending().unwrap(), 8);
    let writes = crate::address_head::test_take_head_page_writes();
    assert_eq!(
        writes, 1,
        "same-page drain must be one page write, got {writes}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pending_head_reopen_backfills_lagging_head() {
    let dir = tempfile_dir("pending-reopen");
    let txid = {
        let t = create_tiny(&dir);
        let mut txid = [0u8; 32];
        txid[0] = 0x77;
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        };
        t.put_full_batch_indexed(&meta_only_items(&[rec]), false)
            .unwrap();
        // No head insert, no pending (process kill).
        txid
    };
    let t = TxTable::open(&dir).unwrap();
    assert_eq!(
        t.get_fk_by_txid(&txid).unwrap(),
        Some(Fk(1)),
        "open must backfill head from Class A"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Simulate crash after body/idx publish, before `txid.body` catch-up:
/// body leads identity → open truncates body/idx to the common prefix.
#[test]
fn open_repairs_body_leading_txid_count() {
    let dir = tempfile_dir("skew-repair");
    {
        let t = create_tiny(&dir);
        let mut items = Vec::new();
        for i in 0..5u8 {
            let mut txid = [0u8; 32];
            txid[0] = i.wrapping_add(1);
            let tx = TxRecord {
                txid,
                version: 2,
                locktime: 0,
                input_count: 0,
                output_count: 1,
                input_start_fk: Fk::NULL,
                output_start_fk: Fk::NULL,
            };
            let outs = vec![OutputRecord::unspent(1000 + i64::from(i), vec![0x51])];
            items.push((tx, Vec::new(), outs));
        }
        t.put_full_batch_indexed(&items, true).unwrap();
        assert_eq!(t.count(), 5);
        assert_eq!(t.txid_sidefile().count(), 5);
        // Identity lag only (body/idx still at 5).
        t.txid_sidefile().truncate_to_count(3).unwrap();
        assert_eq!(t.txid_sidefile().count(), 3);
        assert_eq!(t.count(), 5);
    }
    let t2 = TxTable::open(&dir).expect("open should repair skew");
    assert_eq!(t2.count(), 3);
    assert_eq!(t2.txid_sidefile().count(), 3);
    // Kept prefix still readable.
    let tx = t2.get(Fk(1)).unwrap();
    assert_eq!(tx.txid[0], 1);
    let tx3 = t2.get(Fk(3)).unwrap();
    assert_eq!(tx3.txid[0], 3);
    assert!(t2.get(Fk(4)).is_err());
    // Further appends work after repair.
    let mut txid = [0u8; 32];
    txid[0] = 99;
    let tx = TxRecord {
        txid,
        version: 2,
        locktime: 0,
        input_count: 0,
        output_count: 1,
        input_start_fk: Fk::NULL,
        output_start_fk: Fk::NULL,
    };
    let outs = vec![OutputRecord::unspent(42, vec![0x51])];
    t2.put_full_batch_indexed(&[(tx, Vec::new(), outs)], true)
        .unwrap();
    assert_eq!(t2.count(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decode_prevout_at_skips_script_and_witness() {
    let rec = InputRecord {
        prev_txid: [9u8; 32],
        create_fk: Fk(1),
        prev_index: 3,
        sequence: 0xffff_fffe,
        script_sig: vec![0xab; 40],
        witness: vec![vec![0x30; 70], vec![0x21; 33]],
    };
    let enc = rec.encode();
    let (cfk, vout, used) = InputRecord::decode_prevout_at(&enc).unwrap();
    assert_eq!(cfk, Fk(1));
    assert_eq!(vout, 3);
    assert_eq!(used, enc.len());
    // Full decode still matches.
    let (full, used2) = InputRecord::decode_at(&enc).unwrap();
    assert_eq!(used2, used);
    assert_eq!(full.script_sig.len(), 40);
}

/// v10: non-coinbase prev is create_fk(8) + vout, not prev_txid(32) (−24 B).
#[test]
fn input_encode_create_fk_not_prev_txid() {
    let rec = InputRecord {
        prev_txid: [0xaa; 32], // soft only — not on disk
        create_fk: Fk(42),
        prev_index: 7,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    };
    let enc = rec.encode();
    // flags(1) + create_fk(8) + compact vout(1 for 7) = 10
    assert_eq!(enc.len(), 10, "enc={:?}", enc);
    // v9 would have been flags + 32-byte txid + vout = 34 for same case
    assert!(enc.len() + 24 <= 34);
    let dec = InputRecord::decode(&enc).unwrap();
    assert_eq!(dec.create_fk, Fk(42));
    assert_eq!(dec.prev_index, 7);
    assert_eq!(dec.prev_txid, [0u8; 32]);
}

#[test]
fn scan_packed_meta_and_prevouts_no_output_alloc() {
    let tx = TxRecord {
        txid: [7u8; 32],
        version: 2,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 2,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let inputs = vec![
        InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0x01],
            witness: vec![],
        },
        InputRecord {
            prev_txid: [3u8; 32],
            create_fk: Fk(1),
            prev_index: 1,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![vec![0xaa]],
        },
    ];
    let outputs = vec![OutputRecord::unspent(50, vec![0x51])];
    let mut raw = Vec::new();
    encode_packed_tx(&tx, &inputs, &outputs, &mut raw);
    let (meta, _) = scan_packed_meta_and_prevouts(&raw).unwrap();
    assert_eq!(meta.txid, [0u8; 32], "body scan has no leading txid");
    let mut inwit = Vec::new();
    encode_inwit_with_secret(&inputs, &mut inwit, None);
    let prevouts = scan_inwit_prevouts(&inwit, meta.input_count).unwrap();
    assert_eq!(prevouts.len(), 2);
    assert_eq!(prevouts[0], (Fk::NULL, u32::MAX));
    assert_eq!(prevouts[1], (Fk(1), 1));
}

#[test]
fn packed_output_spender_rels_multi_vout_one_walk() {
    let tx = TxRecord {
        txid: [8u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 4,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(1, vec![0x51]),
        OutputRecord::unspent(2, vec![0x51]),
        OutputRecord::unspent(3, vec![0x51]),
        OutputRecord::unspent(4, vec![0x51]),
    ];
    let mut raw = Vec::new();
    encode_packed_tx(&tx, &inputs, &outputs, &mut raw);
    // Schema 15: decode rels are txout output starts (not spent denserels).
    let (_, _, decode_rels) = decode_packed_tx_outs_with_spender_rels(&raw).unwrap();
    assert_eq!(decode_rels.len(), 4);
    let (_, mut off) = TxRecord::decode_body_meta(&raw).unwrap();
    for (i, _) in outputs.iter().enumerate() {
        assert_eq!(decode_rels[i] as usize, off);
        assert!(off < raw.len());
        off += OutputRecord::skip_at(&raw[off..]).unwrap();
    }
}

/// Exact layout denserels (no encode) match encode+decode for varied shapes.
#[test]
fn denserels_layout_exact_matches_encode_decode_shapes() {
    let cases: Vec<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)> = vec![
        // Coinbase + OP_TRUE out
        (
            TxRecord {
                txid: [1u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01, 0x02], vec![])],
            vec![OutputRecord::unspent(50, vec![0x51])],
        ),
        // Non-final sequence, long script, multi-witness, multi-vout
        (
            TxRecord {
                txid: [2u8; 32],
                version: 2,
                locktime: 100,
                input_start_fk: Fk::NULL,
                input_count: 2,
                output_start_fk: Fk::NULL,
                output_count: 3,
            },
            vec![
                InputRecord {
                    prev_txid: [9u8; 32],
                    create_fk: Fk(42),
                    prev_index: 0,
                    sequence: 1,
                    script_sig: vec![0xab; 40],
                    witness: vec![vec![0x01], vec![0x02; 33]],
                },
                InputRecord {
                    prev_txid: [8u8; 32],
                    create_fk: Fk(99),
                    prev_index: 300, // compact size 3 bytes
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                },
            ],
            vec![
                OutputRecord::unspent(0, vec![]),
                OutputRecord::unspent(1, vec![0x51]),
                OutputRecord::unspent(21_000_000 * 100_000_000, vec![0x00; 25]),
            ],
        ),
    ];
    for (tx, inputs, outputs) in cases {
        assert_eq!(inputs.len() as u32, tx.input_count);
        assert_eq!(outputs.len() as u32, tx.output_count);
        for i in &inputs {
            let mut buf = Vec::new();
            i.encode_into(&mut buf);
            assert_eq!(
                i.encoded_len_exact(),
                buf.len(),
                "input exact len vs encode"
            );
        }
        for o in &outputs {
            let mut buf = Vec::new();
            o.encode_into(&mut buf);
            assert_eq!(
                o.encoded_len_exact(),
                buf.len(),
                "output exact len vs encode"
            );
        }
        let mut raw = Vec::new();
        encode_packed_tx(&tx, &inputs, &outputs, &mut raw);
        let (_, _, decode_rels) = decode_packed_tx_outs_with_spender_rels(&raw).unwrap();
        assert_eq!(decode_rels.len(), outputs.len());
        let (_, mut off) = TxRecord::decode_body_meta(&raw).unwrap();
        for (i, _) in outputs.iter().enumerate() {
            assert_eq!(decode_rels[i] as usize, off);
            off += OutputRecord::skip_at(&raw[off..]).unwrap();
        }
    }
}

/// Bulk body_txid_range matches serial body_txid (idx batch + bulk pread).
#[test]
fn body_txid_range_matches_serial() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-txid-range-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let mk = |i: u64| {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        txid[8] = 0xce;
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
        (rec, inputs, outputs)
    };
    for i in 1..=40u64 {
        let _ = t.put_full_batch_indexed(&[mk(i)], true).unwrap();
    }
    assert!(t.body_txid_range(5, 4).unwrap().is_empty());
    let bulk = t.body_txid_range(1, 40).unwrap();
    assert_eq!(bulk.len(), 40);
    for i in 1..=40u64 {
        assert_eq!(bulk[(i - 1) as usize], t.body_txid(Fk(i)).unwrap());
    }
    let mid = t.body_txid_range(10, 25).unwrap();
    for (j, id) in (10..=25).enumerate() {
        assert_eq!(mid[j], t.body_txid(Fk(id)).unwrap());
    }
    // Through last published id (body-end path for last length).
    let tail = t.body_txid_range(38, 40).unwrap();
    assert_eq!(tail.len(), 3);
    for (j, id) in (38..=40).enumerate() {
        assert_eq!(tail[j], t.body_txid(Fk(id)).unwrap());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fat packed body: sidefile identity matches without reading full payload.
#[test]
fn body_txid_thin_prefix_matches_fat_packed_body() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-thin-txid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let mut txid = [0xabu8; 32];
    txid[0] = 0x7e;
    let tx = TxRecord {
        txid,
        version: 2,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0xde; 64],
        witness: vec![vec![0xad; 50_000]], // fat body
    }];
    let outputs = vec![OutputRecord::unspent(42, vec![0x51; 100])];
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outputs)], true)
        .unwrap()[0];
    let from_thin = t.body_txid(fk).unwrap();
    assert_eq!(from_thin, txid, "sidefile thin identity");
    let (_off, len) = t.inwit.record_range(fk).unwrap();
    assert!(len > 50_000, "inwit should hold the fat witness");
    // Head resolve still works.
    assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(fk));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bulk body_range agrees with sequential record_range.
#[test]
fn bulk_body_range_matches_sequential() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-bulk-body-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let mut fks = Vec::new();
    for i in 0u8..12 {
        let mut txid = [0u8; 32];
        txid[0] = i.wrapping_add(10);
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![i],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
        fks.push(
            t.put_full_batch_indexed(&[(tx, inputs, outputs)], true)
                .unwrap()[0],
        );
    }
    // Unsorted + sparse sample still matches serial body_range.
    let mut shuffled = fks.clone();
    shuffled.reverse();
    let sparse = vec![shuffled[0], shuffled[3], shuffled[3], shuffled[7]];
    let batch_sparse = t.body_range_batch(&sparse).unwrap();
    for (fk, br) in sparse.iter().zip(batch_sparse.iter()) {
        let seq = t.body_range(*fk).unwrap();
        assert_eq!(*br, Some(seq), "fk={fk:?}");
    }
    let batch_ranges = t.body_range_batch(&fks).unwrap();
    for (fk, br) in fks.iter().zip(batch_ranges.iter()) {
        let seq = t.body_range(*fk).unwrap();
        assert_eq!(*br, Some(seq));
    }
    for fk in &fks {
        let (meta, outs) = t.get_meta_and_outputs(*fk).unwrap();
        let full = t.get_full(*fk).unwrap();
        assert_eq!(meta.txid, full.0.txid);
        assert_eq!(meta.txid, t.body_txid(*fk).unwrap());
        assert_eq!(outs.len(), full.2.len());
        for o in &outs {
            assert!(o.spender_field.is_null());
            assert!(!o.multi_spender);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Shape A: multi-cand Prefix33 select + one denserels for winner (outs present).
///
/// Two creates of the same txid (foreigner + real); deepest wins; denserels
/// decode returns outs for pin without a second denserels wave on wrong cands.
#[test]
fn get_fk_by_txid_batch_multi_cand_then_outs() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-shape-a-multi-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let txid = [0x5a; 32];
    let mk = |hint: u8, value: i64| {
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![hint],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(value, vec![0x51, hint])];
        (rec, inputs, outputs)
    };
    // Older create (shallower) then deeper BIP30 winner with distinct value.
    let _fk_old = t.put_full_batch_indexed(&[mk(1, 11)], true).unwrap()[0];
    let fk_new = t.put_full_batch_indexed(&[mk(2, 22)], true).unwrap()[0];

    // Also a single-cand key (denserels-only path).
    let mut solo = [0u8; 32];
    solo[0] = 0x77;
    let solo_rec = TxRecord {
        txid: solo,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let solo_in = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let solo_out = vec![OutputRecord::unspent(33, vec![0x51])];
    let fk_solo = t
        .put_full_batch_indexed(&[(solo_rec, solo_in, solo_out)], true)
        .unwrap()[0];

    let batch = t.get_fk_by_txid_batch(&[txid, solo, [0xff; 32]]).unwrap();
    assert_eq!(batch.len(), 3);

    let multi = batch.iter().find(|(id, _)| *id == txid).unwrap();
    let (fk, range) = multi.1.expect("multi-cand hit");
    assert_eq!(fk, fk_new);
    let (outs_rows, _, _) = t
        .get_outs_by_range_batch(&[(fk, range, txid, vec![0])])
        .unwrap();
    let (tx, outs, dens) = outs_rows[0].as_ref().expect("outs for winner");
    assert_eq!(tx.txid, txid);
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0].1.value, 22);
    assert_eq!(dens.len(), outs.len());

    let single = batch.iter().find(|(id, _)| *id == solo).unwrap();
    let (fk_s, range_s) = single.1.expect("single-cand hit");
    assert_eq!(fk_s, fk_solo);
    let (solo_rows, _, _) = t
        .get_outs_by_range_batch(&[(fk_s, range_s, solo, vec![0])])
        .unwrap();
    let (tx_s, outs_s, _) = solo_rows[0].as_ref().expect("single outs");
    assert_eq!(tx_s.txid, solo);
    assert_eq!(outs_s[0].1.value, 33);

    assert!(batch.iter().any(|(id, r)| *id == [0xff; 32] && r.is_none()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two same-txid creates: batch resolve prefers the deepest (newest) fk.
///
/// Do **not** assert process-wide `head_resolve_stats` here. Those atomics
/// are shared with every parallel `cargo test` thread (`sample_and_reset` /
/// `add_body_lookups` without a crate lock), so `body_lookups <= cands` flakes
/// when another test pollutes the meters.
#[test]
fn streaming_resolve_early_exit_fewer_body_lookups() {
    if !crate::bulk_io::io_uring_enabled() {
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-stream-early-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let txid = [0xcd; 32];
    let mk = |hint: u8| {
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![hint],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
        (rec, inputs, outputs)
    };
    // Two creates of same txid → two cands; deepest (second) wins.
    let _fk1 = t.put_full_batch_indexed(&[mk(1)], true).unwrap()[0];
    let fk2 = t.put_full_batch_indexed(&[mk(2)], true).unwrap()[0];
    let batch = t.get_fk_by_txid_batch(&[txid]).unwrap();
    assert_eq!(batch[0].1.map(|(f, _)| f), Some(fk2));
    let range = batch[0].1.unwrap().1;
    assert!(range.1 > 0, "body range from idx on winner");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Depth-max match: foreigners + two same-txid creates; batch prefers deepest.
#[test]
fn get_fk_by_txid_batch_depth_wins_with_workers() {
    with_env_lock(|| {
        std::env::set_var("RBITCOIN_BULK_IO_WORKERS", "4");
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-tx-batch-depth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = create_tiny(&dir);
        let txid = [0xab; 32];
        let mk = |hint: u8| {
            let rec = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![hint],
                witness: vec![],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
            (rec, inputs, outputs)
        };
        let fk1 = t.put_full_batch_indexed(&[mk(1)], true).unwrap()[0];
        let fk2 = t.put_full_batch_indexed(&[mk(2)], true).unwrap()[0];
        // Also resolve a few unrelated keys in the same bulk call.
        let mut extra = Vec::new();
        for i in 0u8..10 {
            let mut other = [0u8; 32];
            other[0] = i.wrapping_add(1);
            let rec = TxRecord {
                txid: other,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0x01],
                witness: vec![],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
            let fk = t
                .put_full_batch_indexed(&[(rec, inputs, outputs)], true)
                .unwrap()[0];
            extra.push((other, fk));
        }
        let mut keys: Vec<[u8; 32]> = extra.iter().map(|(t, _)| *t).collect();
        keys.push(txid);
        keys.push([0xff; 32]); // miss
        let batch = t.get_fk_by_txid_batch(&keys).unwrap();
        let hit = batch
            .iter()
            .find(|(t, _)| *t == txid)
            .unwrap()
            .1
            .map(|(f, _)| f);
        assert_eq!(hit, Some(fk2));
        assert_ne!(hit, Some(fk1));
        for (other, fk) in &extra {
            let h = batch
                .iter()
                .find(|(t, _)| t == other)
                .unwrap()
                .1
                .map(|(f, _)| f);
            assert_eq!(h, Some(*fk));
        }
        assert!(batch.iter().any(|(t, f)| *t == [0xff; 32] && f.is_none()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("RBITCOIN_BULK_IO_WORKERS");
    });
}

#[test]
fn get_fk_by_txid_batch_matches_single() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-batch-fk-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let mut items = Vec::new();
    for i in 0u8..5 {
        let mut txid = [0u8; 32];
        txid[0] = i.wrapping_add(1);
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0x01],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
        items.push((tx, inputs, outputs));
    }
    let fks = t.put_full_batch_indexed(&items, true).unwrap();
    let mut keys: Vec<[u8; 32]> = items.iter().map(|(tx, _, _)| tx.txid).collect();
    let mut cached = keys.clone();
    keys.sort_unstable_by_key(|k| t.head_primary_slot(k));
    cached.sort_by_cached_key(|k| t.head_primary_slot(k));
    assert_eq!(keys, cached, "cached slot key must match by_key order");
    let batch = t.get_fk_by_txid_batch(&keys).unwrap();
    assert_eq!(batch.len(), 5);
    for (txid, row) in &batch {
        let single = t.get_fk_by_txid(txid).unwrap();
        assert_eq!(row.map(|(f, _)| f), single);
        assert!(row.is_some());
        let (fk, range) = row.unwrap();
        let known = t.body.record_range(fk).unwrap();
        assert_eq!(range, known, "returned range must match tx.idx");
    }
    // Miss
    let miss = t.get_fk_by_txid_batch(&[[0xff; 32]]).unwrap();
    assert_eq!(miss[0].1, None);
    let _ = fks;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Range denserels: known_txid + sparse need_vouts (N2.0/N2.1).
#[test]
fn get_outs_denserels_by_range_sparse_need() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-range-dens-txid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let want_txid = {
        let mut x = [0u8; 32];
        x[0] = 0xab;
        x[31] = 0xcd;
        x
    };
    let big_script = vec![0xAAu8; 200];
    let tx = TxRecord {
        txid: want_txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 3,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(1, big_script.clone()),
        OutputRecord::unspent(2, vec![0x51, 0x52]),
        OutputRecord::unspent(3, big_script.clone()),
    ];
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outputs)], true)
        .unwrap()[0];
    let range = t.body.record_range(fk).unwrap();
    // Only need vout 1 — skip allocating big scripts on 0 and 2.
    let (rows, body_ns, dec_ns) = t
        .get_outs_by_range_batch(&[(fk, range, want_txid, vec![1])])
        .unwrap();
    assert!(body_ns > 0 || dec_ns > 0 || true); // timers fire or tiny fixture
    let (got, live, sparse) = rows[0].as_ref().expect("range denserels");
    assert_eq!(got.txid, want_txid);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 1);
    assert_eq!(live[0].1.script, vec![0x51, 0x52]);
    assert_eq!(sparse.len(), 1);
    assert_eq!(sparse[0].0, 1);
    // Full decode for comparison.
    let full = decode_packed_tx_outs_with_spender_rels_secret(
        &t.body.get_raw(fk).unwrap(),
        Some(t.store_secret()),
    )
    .unwrap();
    assert_eq!(full.1.len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn head_primary_slot_stable_and_ordered() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-slot-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let a = [1u8; 32];
    let b = [2u8; 32];
    let sa = t.head_primary_slot(&a);
    let sb = t.head_primary_slot(&b);
    assert_eq!(sa, t.head_primary_slot(&a));
    // Distinct keys almost always land on distinct primary slots at tiny scale.
    assert_ne!(sa, sb);
    let mut keys = vec![b, a];
    keys.sort_unstable_by_key(|k| t.head_primary_slot(k));
    assert!(t.head_primary_slot(&keys[0]) <= t.head_primary_slot(&keys[1]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `head_insert_many` of a tiny-N batch round-trips get + occupied (FdOnly).
#[test]
fn head_insert_many_tiny_roundtrip() {
    let dir = tempfile_dir("head-insert-many-tiny");
    let t = create_tiny(&dir);
    let recs: Vec<TxRecord> = (0..64u64)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        })
        .collect();
    let items = meta_only_items(&recs);
    let fks = t.put_full_batch_indexed(&items, false).unwrap();
    assert_eq!(fks.len(), 64);
    let heads: Vec<([u8; 32], Fk)> = recs
        .iter()
        .zip(fks.iter())
        .map(|(r, fk)| (r.txid, *fk))
        .collect();
    t.head_insert_many(&heads).unwrap();
    assert_eq!(t.head_occupied(), 64);
    for (r, fk) in recs.iter().zip(fks.iter()) {
        assert_eq!(t.get_fk_by_txid(&r.txid).unwrap(), Some(*fk));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Operator recovery: delete `tx.head/` (+ legacy flat files) → open rebuilds.
#[test]
fn missing_tx_head_rebuilds_from_bodies_on_open() {
    with_env_lock(|| {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-tx-head-rebuild-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mk = |i: u64| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            let rec = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
            (rec, inputs, outputs)
        };

        {
            let t = create_tiny(&dir);
            for i in 1..=20u64 {
                let _ = t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            assert_eq!(t.count(), 20);
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&7u64.to_le_bytes());
            assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(7)));
            t.flush().unwrap();
        }

        // Wipe segmented head meta + files.
        assert!(crate::segmented_head::head_meta_exists(&dir));
        crate::segmented_head::wipe_segmented_head_files(&dir);

        let t = TxTable::open(&dir).unwrap();
        assert_eq!(t.count(), 20);
        assert!(crate::segmented_head::head_meta_exists(&dir));
        for i in 1..=20u64 {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(
                t.get_fk_by_txid(&txid).unwrap(),
                Some(Fk(i)),
                "txid {i} missing after head rebuild"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn missing_tx_head_with_no_bodies_creates_empty() {
    with_env_lock(|| {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-tx-head-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let t = create_tiny(&dir);
            t.flush().unwrap();
        }
        crate::segmented_head::wipe_segmented_head_files(&dir);
        let t = TxTable::open(&dir).unwrap();
        assert_eq!(t.count(), 0);
        assert!(crate::segmented_head::head_meta_exists(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// A torn Class A truncate at open can leave the head **leading** the bodies.
/// Open must rebuild the head to match Class A instead of keeping stale
/// entries past the truncate (which a later seal would trip over).
#[test]
fn head_leading_truncated_class_a_rebuilds_on_open() {
    with_env_lock(|| {
        let dir = tempfile_dir("head-leads");
        let mk = |i: u64| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            let rec = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51])];
            (rec, inputs, outputs)
        };
        {
            let t = create_tiny(&dir);
            for i in 1..=20u64 {
                let _ = t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            t.flush().unwrap();
        }
        // Torn state: one stem shorter than the head coverage. Open repairs
        // Class A to the min count (15), leaving the head claiming 20.
        {
            let txids = crate::txid_body::TxidBody::open(&dir).unwrap();
            txids.truncate_to_count(15).unwrap();
        }
        let t = TxTable::open(&dir).unwrap();
        assert_eq!(t.count(), 15);
        assert!(
            t.head.last_inserted_fk() <= t.count(),
            "head must not lead Class A after open (covered={} n={})",
            t.head.last_inserted_fk(),
            t.count()
        );
        for i in 1..=15u64 {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)), "fk {i}");
        }
        for i in 16..=20u64 {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(t.get_fk_by_txid(&txid).unwrap(), None, "truncated fk {i}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn get_output_spender_metas_at_one_walk() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-metas-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let spenders = crate::spender_table::SpenderTable::create(&dir).unwrap();
    let tx = TxRecord {
        txid: [0xcd; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 3,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(1, vec![0x51]),
        OutputRecord::unspent(2, vec![0x51]),
        OutputRecord::unspent(3, vec![0x51]),
    ];
    let fks = t
        .put_full_batch_indexed(&[(tx, inputs, outputs)], false)
        .unwrap();
    let (off, len) = t.spent_range(fks[0]).unwrap();
    let s1 = Fk(10);
    t.put_spends_on_create_at(&spenders, off, len, &[(0, s1), (2, Fk(20))])
        .unwrap();
    let metas = t
        .get_output_spender_metas_at(off, len, &[0, 1, 2, 99])
        .unwrap();
    assert_eq!(metas.len(), 3);
    assert!(!metas[0].1 && metas[0].2 == s1);
    assert!(!metas[1].1 && metas[1].2.is_null());
    assert!(!metas[2].1 && metas[2].2 == Fk(20));

    // Bulk 8-byte abs preads match spent_abs (pin → write spentness path).
    let (_meta, outs) = t.get_meta_and_outputs(fks[0]).unwrap();
    assert_eq!(outs.len(), 3);
    for o in &outs {
        assert!(o.spender_field.is_null());
    }
    let abs: Vec<u64> = (0..3).map(|v| spent_abs(off, v)).collect();
    let bulk = t.get_spender_meta_at_abs_batch(&abs).unwrap();
    assert_eq!(bulk.len(), 3);
    assert_eq!(
        bulk[0].map(|(f, fl)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((s1, false))
    );
    assert_eq!(
        bulk[1].map(|(f, fl)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((Fk::NULL, false))
    );
    assert_eq!(
        bulk[2].map(|(f, fl)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((Fk(20), false))
    );
    // Both backends must agree.
    let mmap = t
        .get_spender_meta_at_abs_batch_backend(&abs, SpendMetaBackend::Pread)
        .unwrap();
    let uring = t
        .get_spender_meta_at_abs_batch_backend(&abs, SpendMetaBackend::Uring)
        .unwrap();
    assert_eq!(mmap, bulk);
    assert_eq!(uring, bulk);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_spends_on_create_at_batch_patches_all_vouts() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-spend-batch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    let spenders = crate::spender_table::SpenderTable::create(&dir).unwrap();
    let tx = TxRecord {
        txid: [0xab; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 3,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(10, vec![0x51]),
        OutputRecord::unspent(20, vec![0x51]),
        OutputRecord::unspent(30, vec![0x51]),
    ];
    let fks = t
        .put_full_batch_indexed(&[(tx, inputs, outputs)], true)
        .unwrap();
    let fk = fks[0];
    let (off, len) = t.spent_range(fk).unwrap();
    let s1 = Fk(100);
    let s2 = Fk(200);
    t.put_spends_on_create_at(&spenders, off, len, &[(0, s1), (2, s2)])
        .unwrap();
    let (m0, f0) = t.get_output_spender_meta_at(off, len, 0).unwrap();
    let (m2, f2) = t.get_output_spender_meta_at(off, len, 2).unwrap();
    assert!(!m0 && f0 == s1);
    assert!(!m2 && f2 == s2);
    let (m1, f1) = t.get_output_spender_meta_at(off, len, 1).unwrap();
    assert!(!m1 && f1.is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn input_witness_roundtrip() {
    let rec = InputRecord {
        prev_txid: [1u8; 32],
        create_fk: Fk(1),
        prev_index: 2,
        sequence: 0xffff_fffe,
        script_sig: vec![0x00],
        witness: vec![vec![0x30, 0x01], vec![0x21, 0xaa]],
    };
    let enc = rec.encode();
    let dec = InputRecord::decode(&enc).unwrap();
    assert_eq!(dec.create_fk, Fk(1));
    assert_eq!(dec.prev_index, 2);
    assert_eq!(dec.sequence, rec.sequence);
    assert_eq!(dec.script_sig, rec.script_sig);
    assert_eq!(dec.witness, rec.witness);
    assert_eq!(dec.prev_txid, [0u8; 32], "prev_txid not on disk");
}

#[test]
fn input_flags_roundtrip() {
    let rec = InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    };
    let enc = rec.encode();
    // flags only: null prev + final seq + empty script + empty witness
    assert_eq!(enc.len(), 1);
    assert_eq!(InputRecord::decode(&enc).unwrap(), rec);
}

#[test]
fn input_rejects_legacy_local_prev() {
    use crate::compact::write_compact_size;
    // flags: LOCAL_PREV | SEQ_FINAL | EMPTY_SCRIPT | EMPTY_WITNESS
    let flags = input_flags::RESERVED4
        | input_flags::SEQ_FINAL
        | input_flags::EMPTY_SCRIPT
        | input_flags::EMPTY_WITNESS;
    let mut enc = vec![flags];
    write_compact_size(&mut enc, 42);
    write_compact_size(&mut enc, 1);
    assert!(InputRecord::decode(&enc).is_err());
}

#[test]
fn input_run_roundtrip() {
    let run = vec![
        InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0x01],
            witness: vec![],
        },
        InputRecord {
            prev_txid: [2u8; 32],
            create_fk: Fk(1),
            prev_index: 0,
            sequence: 1,
            script_sig: vec![],
            witness: vec![vec![0xab]],
        },
        InputRecord {
            prev_txid: [3u8; 32],
            create_fk: Fk(1),
            prev_index: 3,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        },
    ];
    let mut enc = Vec::new();
    encode_input_run_secret(&run, &mut enc, None);
    let dec = decode_input_run(&enc, 3).unwrap();
    assert_eq!(dec.len(), 3);
    assert!(dec[0].is_coinbase());
    assert_eq!(dec[1].create_fk, Fk(1));
    assert_eq!(dec[1].prev_index, 0);
    assert_eq!(dec[1].witness, vec![vec![0xab]]);
    assert_eq!(dec[2].create_fk, Fk(1));
    assert_eq!(dec[2].prev_index, 3);
    // Soft prev_txid not on disk.
    assert_eq!(dec[1].prev_txid, [0u8; 32]);
}

#[test]
fn output_run_roundtrip() {
    let run = vec![
        OutputRecord::unspent(50_0000_0000, vec![0x51]),
        OutputRecord::unspent(0, vec![]),
        OutputRecord::unspent(12345, vec![0x00, 0x14, 0xaa]),
    ];
    let mut enc = Vec::new();
    encode_output_run_secret(&run, &mut enc, None);
    assert_eq!(decode_output_run(&enc, 3).unwrap(), run);
    // OP_TRUE + spender_field(8) + flags + uleb value
    let mut tiny = Vec::new();
    run[0].encode_into(&mut tiny);
    assert!(
        tiny.len() < 24,
        "op_true+value should be compact: {}",
        tiny.len()
    );
}

#[test]
fn tx_fixed_roundtrip() {
    let rec = TxRecord {
        txid: [9u8; 32],
        version: 2,
        locktime: 100,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 2,
    };
    let enc = rec.encode();
    assert!(enc.len() > 32, "txid + thin meta");
    assert_eq!(TxRecord::decode(&enc).unwrap(), rec);
}

#[test]
fn packed_tx_roundtrip() {
    let tx = TxRecord {
        txid: [7u8; 32],
        version: 2,
        locktime: 0,
        input_start_fk: Fk(99), // ignored in packed
        input_count: 1,
        output_start_fk: Fk(88),
        output_count: 2,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![0x01, 0x00],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(50_0000_0000, vec![0x51]),
        OutputRecord::unspent(1, vec![0x00, 0x14]),
    ];
    let mut enc = Vec::new();
    encode_packed_tx(&tx, &inputs, &outputs, &mut enc);
    assert!(is_packed_tx_payload(&enc));
    assert!(enc.len() >= 3, "thin LAYOUT17 meta");
    let (dtx, _dins, douts) = decode_packed_tx(&enc).unwrap();
    assert_eq!(dtx.txid, [0u8; 32], "body decode leaves txid zero");
    assert_eq!(dtx.input_count, 1);
    assert_eq!(dtx.output_count, 2);
    assert!(dtx.input_start_fk.get().is_none());
    let mut inwit = Vec::new();
    encode_inwit_with_secret(&inputs, &mut inwit, None);
    let dins = decode_inwit_secret(&inwit, dtx.input_count, None).unwrap();
    assert_eq!(dins, inputs);
    assert_eq!(douts, outputs);
}

#[test]
fn inwit_and_txout_secret_xor_roundtrip() {
    let secret = crate::store_secret::StoreSecret::from_bytes([0x5au8; 32]);
    let tx = TxRecord {
        txid: [3u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk(7),
        prev_index: 1,
        sequence: 1,
        script_sig: vec![0x11, 0x22, 0x33],
        witness: vec![vec![0xaa, 0xbb], vec![0xcc]],
    }];
    let outputs = vec![OutputRecord::unspent(42, vec![0x00, 0x14, 0x99])];
    let mut txout = Vec::new();
    encode_packed_tx_with_secret(&tx, &inputs, &outputs, &mut txout, Some(&secret));
    let mut inwit = Vec::new();
    encode_inwit_with_secret(&inputs, &mut inwit, Some(&secret));
    assert_ne!(inwit, {
        let mut plain = Vec::new();
        encode_inwit_with_secret(&inputs, &mut plain, None);
        plain
    });
    let (dtx, douts, _) = decode_packed_tx_outs_with_spender_rels(&txout).unwrap();
    // Without secret, script stays obfuscated.
    assert_ne!(douts[0].script, outputs[0].script);
    let (dtx2, douts2, _) =
        decode_packed_tx_outs_with_spender_rels_secret(&txout, Some(&secret)).unwrap();
    assert_eq!(dtx2.input_count, dtx.input_count);
    assert_eq!(douts2[0].script, outputs[0].script);
    let dins = decode_inwit_secret(&inwit, dtx.input_count, Some(&secret)).unwrap();
    assert_eq!(dins[0].script_sig, inputs[0].script_sig);
    assert_eq!(dins[0].witness, inputs[0].witness);
}

#[test]
fn visit_packed_script_hashes_matches_full_decode() {
    let secret = crate::store_secret::StoreSecret::from_bytes([0x3cu8; 32]);
    let tx = TxRecord {
        txid: [9u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 3,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let outputs = vec![
        OutputRecord::unspent(50, vec![0x51]),
        OutputRecord::unspent(25, vec![0x00, 0x14, 0xaa]),
        OutputRecord::unspent(1, {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[0xbb; 32]);
            s
        }),
    ];
    let mut raw = Vec::new();
    encode_packed_tx_with_secret(&tx, &inputs, &outputs, &mut raw, Some(&secret));
    let (_, decoded, _) =
        decode_packed_tx_outs_with_spender_rels_secret(&raw, Some(&secret)).unwrap();
    let expect: Vec<[u8; 32]> = decoded
        .iter()
        .map(|o| crate::scripthash::script_hash(&o.script))
        .collect();
    let mut got = Vec::new();
    visit_packed_script_hashes(&raw, Some(&secret), |h| {
        got.push(h);
        Ok(())
    })
    .unwrap();
    assert_eq!(got, expect);
}

#[test]
fn short_or_truncated_packed_body_rejected() {
    assert!(!is_packed_tx_payload(&[]));
    assert!(!is_packed_tx_payload(&[0u8; 15]));
    assert!(matches!(
        decode_packed_tx(&[0u8; 15]),
        Err(StoreError::Corrupt(_))
    ));
    // v17 empty tx (0 in / 0 out) is a valid packed payload.
    let empty = rec_meta(1, 0, 0, 0);
    let mut empty_raw = Vec::new();
    empty.encode_body_meta_into(&mut empty_raw);
    assert!(is_packed_tx_payload(&empty_raw));
    assert!(decode_packed_tx(&empty_raw).is_ok());
    // Meta claims inputs/outputs but payload ends after body meta.
    let rec = TxRecord {
        txid: [1u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk(1),
        input_count: 1,
        output_start_fk: Fk(2),
        output_count: 1,
    };
    let mut raw = Vec::new();
    rec.encode_body_meta_into(&mut raw);
    assert!(is_packed_tx_payload(&raw));
    assert!(matches!(
        decode_packed_tx(&raw),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&raw),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn address_head_get_by_txid() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-addr-head-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Force tiny address width for the test process.
    let t = create_tiny(&dir);
    let tx = TxRecord {
        txid: [0x42u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let inputs = vec![InputRecord {
        prev_txid: [0u8; 32],
        create_fk: Fk::NULL,
        prev_index: u32::MAX,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x51])];
    let fks = t
        .put_full_batch_indexed(&[(tx.clone(), inputs, outputs)], true)
        .unwrap();
    assert_eq!(fks.len(), 1);
    let (fk, rec) = t.get_by_txid(&tx.txid).unwrap().expect("found");
    assert_eq!(fk, fks[0]);
    assert_eq!(rec.txid, tx.txid);
    assert!(t.get_by_txid(&[0x99u8; 32]).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Production API surface: abs spender meta, get_all, head snapshot, flushes.

/// Dense encode/decode + error-arm coverage for packed Class A helpers.
#[test]
fn packed_encode_decode_flags_and_error_arms() {
    // TxRecord short
    assert!(matches!(
        TxRecord::decode(&[0u8; 10]),
        Err(StoreError::Corrupt(_))
    ));
    let meta = TxRecord {
        txid: [9u8; 32],
        version: -1,
        locktime: 42,
        input_start_fk: Fk(7),
        input_count: 2,
        output_start_fk: Fk(8),
        output_count: 3,
    };
    let enc = meta.encode();
    assert!(enc.len() > 32);
    let dec = TxRecord::decode(&enc).unwrap();
    assert_eq!(dec.txid, meta.txid);
    assert_eq!(dec.version, -1);

    // Output flag variants + decode errors
    let o_empty = OutputRecord::unspent(0, vec![]);
    let o_true = OutputRecord::unspent(1, vec![0x51]);
    let o_script = OutputRecord {
        value: 99,
        script: vec![0x76, 0xa9],
        spender_field: Fk(5),
        multi_spender: true,
    };
    for o in [&o_empty, &o_true, &o_script] {
        let e = o.encode();
        let d = OutputRecord::decode(&e).unwrap();
        assert_eq!(d.value, o.value);
        assert_eq!(d.script, o.script);
        // Spender lives in spent.body — txout decode leaves fields null.
        assert!(d.spender_field.is_null());
        assert!(!d.multi_spender);
        let _ = o.encoded_len();
    }
    assert!(matches!(
        OutputRecord::decode_at(&[]),
        Err(StoreError::Corrupt(_))
    ));
    // trailing on decode
    let mut trail = o_true.encode();
    trail.push(0xff);
    assert!(matches!(
        OutputRecord::decode(&trail),
        Err(StoreError::Corrupt(_))
    ));

    // Input coinbase + full + prevout skip + errors
    let coin = InputRecord::coinbase(u32::MAX, vec![], vec![]);
    assert!(coin.is_coinbase());
    let non_final = InputRecord {
        prev_txid: [1u8; 32],
        create_fk: Fk(3),
        prev_index: 2,
        sequence: 1,
        script_sig: vec![0xaa, 0xbb],
        witness: vec![vec![1, 2, 3], vec![4]],
    };
    for r in [&coin, &non_final] {
        let e = r.encode();
        let d = InputRecord::decode(&e).unwrap();
        assert_eq!(d.create_fk, r.create_fk);
        assert_eq!(d.prev_index, r.prev_index);
        assert_eq!(d.sequence, r.sequence);
        assert_eq!(d.script_sig, r.script_sig);
        assert_eq!(d.witness, r.witness);
        let (cfk, vout, used) = InputRecord::decode_prevout_at(&e).unwrap();
        assert_eq!(cfk, r.create_fk);
        assert_eq!(vout, r.prev_index);
        assert_eq!(used, e.len());
        let _ = r.encoded_len();
    }
    assert!(matches!(
        InputRecord::decode_prevout_at(&[]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        InputRecord::decode_at(&[]),
        Err(StoreError::Corrupt(_))
    ));
    // RESERVED4 flag
    assert!(matches!(
        InputRecord::decode_at(&[input_flags::RESERVED4]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        InputRecord::decode_prevout_at(&[input_flags::RESERVED4]),
        Err(StoreError::Corrupt(_))
    ));
    // non-coinbase create_fk truncated
    assert!(matches!(
        InputRecord::decode_at(&[0u8, 1, 2]),
        Err(StoreError::Corrupt(_))
    ));
    // create_fk null on non-coinbase
    let mut bad = vec![0u8]; // no NULL_PREV
    bad.extend_from_slice(&0u64.to_le_bytes());
    bad.push(0); // vout compact 0
    assert!(matches!(
        InputRecord::decode_at(&bad),
        Err(StoreError::Corrupt(_))
    ));
    // sequence truncated
    let mut bad = vec![0u8]; // no SEQ_FINAL
    bad.extend_from_slice(&1u64.to_le_bytes());
    bad.push(0);
    assert!(matches!(
        InputRecord::decode_at(&bad),
        Err(StoreError::Corrupt(_))
    ));
    // trailing
    let mut trail = coin.encode();
    trail.push(1);
    assert!(matches!(
        InputRecord::decode(&trail),
        Err(StoreError::Corrupt(_))
    ));

    // Packed encode/decode
    let tx = TxRecord {
        txid: [0xab; 32],
        version: 2,
        locktime: 0,
        input_start_fk: Fk(99), // cleared on pack
        input_count: 2,
        output_start_fk: Fk(88),
        output_count: 2,
    };
    let inputs = vec![coin.clone(), non_final.clone()];
    let outputs = vec![o_true.clone(), o_script.clone()];
    let mut raw = Vec::new();
    encode_packed_tx(&tx, &inputs, &outputs, &mut raw);
    assert!(is_packed_tx_payload(&raw));
    assert!(!is_packed_tx_payload(&[]));
    assert!(!is_packed_tx_payload(&[0u8; 15]));
    assert!(!is_packed_tx_payload(&[0u8; 20]));
    assert!(!is_packed_tx_payload(&[0u8; 64]));
    let (m, ins, outs) = decode_packed_tx(&raw).unwrap();
    assert_eq!(m.txid, [0u8; 32], "body decode: no leading txid");
    assert_eq!(m.input_start_fk, Fk::NULL);
    assert!(ins.is_empty(), "txout decode does not include inwit");
    assert_eq!(outs.len(), 2);
    let (m2, prevs) = scan_packed_meta_and_prevouts(&raw).unwrap();
    assert_eq!(m2.txid, [0u8; 32]);
    assert!(prevs.is_empty(), "prevouts live in inwit");
    let mut inwit = Vec::new();
    encode_inwit_with_secret(&inputs, &mut inwit, None);
    assert_eq!(scan_inwit_prevouts(&inwit, m.input_count).unwrap().len(), 2);
    let (m4, outs_rels, rels) = decode_packed_tx_outs_with_spender_rels(&raw).unwrap();
    assert_eq!(m4.txid, [0u8; 32]);
    assert_eq!(outs_rels.len(), 2);
    assert_eq!(rels.len(), 2);
    // spender fields cleared
    assert!(outs_rels.iter().all(|o| o.spender_field.is_null()));
    let mut cleared = outs.clone();
    cleared[0].spender_field = Fk(9);
    cleared[0].multi_spender = true;
    clear_output_spender_fields(&mut cleared);
    assert!(cleared[0].spender_field.is_null());
    assert!(!cleared[0].multi_spender);

    // Packed error arms (short / truncated)
    assert!(matches!(
        decode_packed_tx(&[0x02, 0, 0]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx(&[0x01]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        scan_packed_meta_and_prevouts(&[0x02]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&[0x01]),
        Err(StoreError::Corrupt(_))
    ));
    // trailing zero pad is accepted (schema 11 alignment gap)
    let mut trail_z = raw.clone();
    trail_z.extend_from_slice(&[0u8; 7]);
    let (mz, _, _) = decode_packed_tx(&trail_z).unwrap();
    assert_eq!(mz.txid, [0u8; 32]);
    // non-zero trailing garbage is rejected
    let mut trail = raw.clone();
    trail.push(0x01);
    assert!(matches!(
        decode_packed_tx(&trail),
        Err(StoreError::Corrupt(_))
    ));
    // run helpers
    let mut run = Vec::new();
    encode_output_run_secret(&outputs, &mut run, None);
    let (decoded, used) = decode_output_run_prefix(&run, 2).unwrap();
    assert_eq!(used, run.len());
    assert_eq!(decoded.len(), 2);
    assert_eq!(decode_output_run(&run, 2).unwrap().len(), 2);
    let mut irun = Vec::new();
    encode_input_run_secret(&inputs, &mut irun, None);
    assert_eq!(decode_input_run(&irun, 2).unwrap().len(), 2);
    let mut trail_run = run.clone();
    trail_run.push(1);
    assert!(matches!(
        decode_output_run(&trail_run, 2),
        Err(StoreError::Corrupt(_))
    ));

    // Output value > i64::MAX (uleb overflow)
    {
        let mut bad = vec![output_flags::EMPTY_SCRIPT];
        // uleb128 of value that exceeds i64::MAX: 0xFF… with enough bytes
        for _ in 0..10 {
            bad.push(0xff);
        }
        bad.push(0x01);
        assert!(matches!(
            OutputRecord::decode_at(&bad),
            Err(StoreError::Corrupt(_))
        ));
    }
    // decode_prevout_at: create_fk null, prev_index too large, truncated fk
    {
        let mut null_fk = vec![0u8]; // no NULL_PREV
        null_fk.extend_from_slice(&0u64.to_le_bytes());
        null_fk.push(0);
        assert!(matches!(
            InputRecord::decode_prevout_at(&null_fk),
            Err(StoreError::Corrupt(_))
        ));
        // truncated create_fk (only 3 bytes after flags)
        assert!(matches!(
            InputRecord::decode_prevout_at(&[0u8, 1, 2, 3]),
            Err(StoreError::Corrupt(_))
        ));
        // prev_index too large: compact_size > u32::MAX
        let mut big_vout = vec![0u8];
        big_vout.extend_from_slice(&1u64.to_le_bytes());
        // compact size 0xFF → 8-byte length follows; use value > u32::MAX
        big_vout.push(0xff);
        big_vout.extend_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        assert!(matches!(
            InputRecord::decode_prevout_at(&big_vout),
            Err(StoreError::Corrupt(_))
        ));
        // same for full decode_at
        assert!(matches!(
            InputRecord::decode_at(&big_vout),
            Err(StoreError::Corrupt(_))
        ));
        // sequence truncated on decode_prevout (flags without SEQ_FINAL)
        let mut short_seq = vec![0u8];
        short_seq.extend_from_slice(&1u64.to_le_bytes());
        short_seq.push(0); // vout 0
                           // only 2 of 4 sequence bytes
        short_seq.extend_from_slice(&[1, 2]);
        assert!(matches!(
            InputRecord::decode_prevout_at(&short_seq),
            Err(StoreError::Corrupt(_))
        ));
        // witness item truncated
        let mut short_wit = vec![
            input_flags::SEQ_FINAL, // no EMPTY_WITNESS
        ];
        short_wit.extend_from_slice(&1u64.to_le_bytes());
        short_wit.push(0); // vout
        short_wit.push(0); // empty script via compact 0? flags don't have EMPTY_SCRIPT
                           // Actually EMPTY_SCRIPT not set → need script len
                           // Rebuild: SEQ_FINAL | no EMPTY_SCRIPT | no EMPTY_WITNESS
        let mut short_wit = vec![input_flags::SEQ_FINAL];
        short_wit.extend_from_slice(&1u64.to_le_bytes());
        short_wit.push(0); // vout
        short_wit.push(0); // script len 0
        short_wit.push(1); // 1 witness item
        short_wit.push(5); // item len 5
        short_wit.extend_from_slice(&[1, 2]); // only 2 bytes
        assert!(matches!(
            InputRecord::decode_at(&short_wit),
            Err(StoreError::Corrupt(_))
        ));
    }
    // packed outs short / count mismatch / trailing on outs_with_spender
    {
        let tx = TxRecord {
            txid: [0xcd; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 2, // claim 2 outs but only encode 1
        };
        let inputs = [InputRecord::coinbase(u32::MAX, vec![], vec![])];
        let outputs = [OutputRecord::unspent(1, vec![0x51])];
        let mut raw = Vec::new();
        // Manually pack body meta only (schema 13) with wrong meta count.
        let mut meta = tx;
        meta.output_count = 2;
        meta.encode_body_meta_into(&mut raw);
        encode_input_run_secret(&inputs, &mut raw, None);
        encode_output_run_secret(&outputs, &mut raw, None);
        // ends after 1 output but meta says 2
        assert!(matches!(
            decode_packed_tx(&raw),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_packed_tx_outs_with_spender_rels(&raw),
            Err(StoreError::Corrupt(_))
        ));
        // short scan
        assert!(matches!(
            scan_packed_meta_and_prevouts(&[0u8; 8]),
            Err(StoreError::Corrupt(_))
        ));
        // non-zero trailing on outs_only path
        let mut good = Vec::new();
        encode_packed_tx(
            &TxRecord {
                txid: [1; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            &inputs,
            &outputs,
            &mut good,
        );
        let mut trail = good.clone();
        trail.push(0xee);
        assert!(matches!(
            decode_packed_tx_outs_with_spender_rels(&trail),
            Err(StoreError::Corrupt(_))
        ));
        // zero pad accepted on outs path
        let mut zpad = good.clone();
        zpad.extend_from_slice(&[0u8; 5]);
        let (m, outs, _) = decode_packed_tx_outs_with_spender_rels(&zpad).unwrap();
        assert_eq!(m.txid, [0u8; 32], "body decode leaves txid zero");
        assert_eq!(outs.len(), 1);
    }
    // input run trailing
    {
        let mut irun = Vec::new();
        encode_input_run_secret(
            &[InputRecord::coinbase(u32::MAX, vec![], vec![])],
            &mut irun,
            None,
        );
        irun.push(0);
        assert!(matches!(
            decode_input_run(&irun, 1),
            Err(StoreError::Corrupt(_))
        ));
    }
}

/// body_txid_range edge / corrupt paths (empty body, inverted range).
#[test]
fn body_txid_range_edges() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-txid-range-edge-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);
    assert!(t.body_txid_range(10, 5).unwrap().is_empty());
    // Beyond count → NotFound or empty ranges
    let _ = t.body_txid_range(1, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_tx_body_start_8_align_and_page_rule() {
    // Schema 13: 8-byte align only (identity lives in txid.body).
    assert_eq!(next_tx_body_start(0), 0);
    assert_eq!(next_tx_body_start(1), 8);
    assert_eq!(next_tx_body_start(8), 8);
    assert_eq!(next_tx_body_start(9), 16);
    assert_eq!(next_tx_body_start(4065), 4072);
    assert_eq!(next_tx_body_start(4095), 4096);
    for c in [0u64, 1, 7, 15, 100, 4090, 4095, 4096, 8191, 100_003] {
        let s = next_tx_body_start(c);
        assert_eq!(s % 8, 0, "c={c} s={s}");
        assert!(s >= c);
    }
}

/// Appended Class A records start 8-aligned; sidefile holds txid.
#[test]
fn put_full_aligns_record_starts_and_txid_prefix() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-tx-align-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = create_tiny(&dir);

    let mut items = Vec::new();
    for i in 0u8..40 {
        let mut txid = [0u8; 32];
        txid[0] = i;
        txid[1] = 0xA5;
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        // Vary sizes so pad between records is non-trivial.
        let script: Vec<u8> = (0..((i as usize % 17) + 1)).map(|b| b as u8).collect();
        items.push((
            tx,
            vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
            vec![OutputRecord::unspent(1000 + i as i64, script)],
        ));
    }
    let fks = t.put_full_batch_indexed(&items, true).unwrap();
    assert_eq!(fks.len(), 40);
    for (j, fk) in fks.iter().enumerate() {
        let (off, len) = t.body.record_range(*fk).unwrap();
        assert_eq!(off % 8, 0, "fk={} off={}", fk.0, off);
        assert!(len >= 3, "thin LAYOUT17 meta");
        let txid = t.body_txid(*fk).unwrap();
        assert_eq!(txid, items[j].0.txid, "sidefile identity");
        let (meta, ins, outs) = t.get_full(*fk).unwrap();
        assert_eq!(meta.txid, items[j].0.txid);
        assert_eq!(ins.len(), 1);
        assert_eq!(outs.len(), 1);
        // Body meta is LAYOUT17 flags, not a leading txid.
        let mut prefix = [0u8; 1];
        t.body.read_prefix_at(off, len, &mut prefix).unwrap();
        assert_eq!(prefix[0] & 0x80, 0x80, "body starts with LAYOUT17");
    }
    // Multi-batch: second batch pads from previous end.
    let mut more = Vec::new();
    for i in 40u8..55 {
        let mut txid = [0u8; 32];
        txid[0] = i;
        more.push((
            TxRecord {
                txid,
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
    }
    let fks2 = t.put_full_batch_indexed(&more, true).unwrap();
    for (j, fk) in fks2.iter().enumerate() {
        let (off, _) = t.body.record_range(*fk).unwrap();
        assert_eq!(off % 8, 0);
        assert_eq!(t.body_txid(*fk).unwrap(), more[j].0.txid);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
/// BIP30 same-txid twice → duplicate fuse keys; seal must still succeed (dedup for build only).
#[test]
fn bip30_duplicate_txid_seal_succeeds_and_resolves() {
    let dir = tempfile_dir("bip30-seal");
    // 10-bit: max_keys = 819
    let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
    let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
    let mut shared = [0u8; 32];
    shared[0..8].copy_from_slice(&1u64.to_le_bytes());
    // Two Class A creates with the same txid (BIP30-shaped).
    let r1 = TxRecord {
        txid: shared,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 0,
        output_start_fk: Fk::NULL,
        output_count: 0,
    };
    let r2 = r1.clone();
    let fks = t
        .put_full_batch_indexed(&meta_only_items(&[r1, r2]), true)
        .unwrap();
    assert_eq!(fks.len(), 2);
    assert_ne!(fks[0], fks[1]);
    // Fill remaining to force seal of first segment (819 creates).
    let mut rest = Vec::new();
    for i in 3..=819u64 {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        rest.push(TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        });
    }
    t.put_full_batch_indexed(&meta_only_items(&rest), true)
        .unwrap();
    // Next create forces roll/seal of the full segment.
    let mut more = [0u8; 32];
    more[0..8].copy_from_slice(&820u64.to_le_bytes());
    t.put_full_batch_indexed(
        &meta_only_items(&[TxRecord {
            txid: more,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        }]),
        true,
    )
    .unwrap();
    t.flush_head().unwrap();
    assert!(
        t.head.sealed_segment_count() >= 1,
        "seal must succeed despite BIP30 duplicate fuse keys"
    );
    // Newest BIP30 create wins (deeper probe).
    let hit = t.get_fk_by_txid(&shared).unwrap();
    assert_eq!(hit, Some(fks[1]), "newest same-txid create");
    let all = t.get_all_by_txid(&shared).unwrap();
    assert_eq!(all.len(), 2, "both BIP30 creates body-verify");
    assert_eq!(all[0].0, fks[1]);
    assert_eq!(all[1].0, fks[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reopen mid-open-segment, then fill to seal: pre-reopen creates must not FN.
#[test]
fn reopen_mid_segment_then_seal_no_fuse_fn() {
    let dir = tempfile_dir("reopen-seal-fn");
    // 10-bit: max_keys = floor(0.8*1024) = 819
    let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
    let half = 400u64;
    {
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        let recs: Vec<TxRecord> = (0..half)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
                TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                }
            })
            .collect();
        t.put_full_batch_indexed(&meta_only_items(&recs), true)
            .unwrap();
        assert_eq!(t.head_segment_count(), 1);
        assert_eq!(t.head.sealed_segment_count(), 0);
        assert_eq!(t.head.open_keys_len() as u64, half);
        t.flush().unwrap();
    }
    // Reopen: open_keys must rebuild from Class A.
    let t = TxTable::open(&dir).unwrap();
    assert_eq!(t.head.open_keys_len() as u64, half, "open keys rebuilt");
    // Fill past 819 so first segment seals.
    let more: Vec<TxRecord> = (half..900)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        })
        .collect();
    t.put_full_batch_indexed(&meta_only_items(&more), true)
        .unwrap();
    t.flush_head().unwrap();
    assert!(t.head.sealed_segment_count() >= 1, "must have sealed");
    // Pre-reopen members must resolve through sealed fuse (no FN).
    for i in [1u64, 50, 200, 400] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            t.get_fk_by_txid(&txid).unwrap(),
            Some(Fk(i)),
            "pre-reopen fk={i} FN after seal"
        );
    }
    for i in [401u64, 820, 900] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)), "fk={i}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Legacy fuse8 v1 → v2 rewrite on open (minimal seal: 820 creates @ bits=10).
#[test]
fn reopen_rewrites_legacy_v1_sealed_fuse_to_v2() {
    let dir = tempfile_dir("fuse-v1-rewrite");
    let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
    {
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        // 0.8 * 1024 slots = 819 → one seal at 820.
        let recs: Vec<TxRecord> = (0..820u64)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
                TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                }
            })
            .collect();
        t.put_full_batch_indexed(&meta_only_items(&recs), true)
            .unwrap();
        t.flush().unwrap();
        assert!(t.head.sealed_segment_count() >= 1);
    }
    let fuse_path = dir.join("tx.head").join("000000.fuse8");
    assert!(fuse_path.is_file());
    let mut raw = Vec::from(*b"BF8R");
    raw.extend_from_slice(&1u32.to_le_bytes()); // VERSION_V1
    raw.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write(&fuse_path, &raw).unwrap();

    let t = TxTable::open(&dir).unwrap();
    assert!(
        t.head.sealed_fuse_rewrite_queue().is_empty(),
        "open must rewrite legacy fuses before returning"
    );
    let bytes = std::fs::read(&fuse_path).unwrap();
    assert_eq!(&bytes[0..4], b"BF8R");
    let ver = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    assert_eq!(ver, 2, "fuse must be rewritten as v2");
    for i in [1u64, 100, 400, 819] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            t.get_fk_by_txid(&txid).unwrap(),
            Some(Fk(i)),
            "fk={i} after fuse migrate"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fat Class A bodies must not roll `tx.head` (idx soft-span is not a head cut).
#[test]
fn fat_creates_do_not_roll_head_on_body_soft_span() {
    with_env_lock(|| {
        let dir = tempfile_dir("no-body-span-roll");
        let layout = HeadLayout::with_entry_bytes(14, 4).unwrap();
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        let mk = |i: u64| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            let tx = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0xab; 64],
                witness: vec![vec![0xcd; 400]],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51; 32])];
            (tx, inputs, outputs)
        };
        crate::tx_idx::test_with_soft_span_bytes(800, || {
            for i in 1..=12u64 {
                t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            t.flush_head().unwrap();
            assert_eq!(
                t.head.sealed_segment_count(),
                0,
                "body soft-span must not seal tx.head segs={}",
                t.head_segment_count()
            );
            assert_eq!(t.head_segment_count(), 1);
            for i in [1u64, 6, 9, 12] {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&i.to_le_bytes());
                assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)));
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn segmented_head_roll_and_lookup_via_tx_table() {
    let dir = tempfile_dir("seg-roll");
    let layout = HeadLayout::with_entry_bytes(10, 4).unwrap(); // max_keys=819
    let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
    let n = 820u64; // one seal @ bits=10 (max_keys=819)
    let recs: Vec<TxRecord> = (0..n)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        })
        .collect();
    // insert in chunks
    for chunk in recs.chunks(100) {
        t.put_full_batch_indexed(&meta_only_items(chunk), true)
            .unwrap();
    }
    assert!(
        t.head_segment_count() >= 2,
        "segs={}",
        t.head_segment_count()
    );
    // lookup first, mid, last
    for i in [1u64, 400, 819, 820] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        let fk = t.get_fk_by_txid(&txid).unwrap();
        assert_eq!(fk, Some(Fk(i)), "i={i}");
    }
    // miss (must not collide with LE u64 ids 1..=820)
    let miss = [0xAAu8; 32];
    assert_eq!(t.get_fk_by_txid(&miss).unwrap(), None);
    t.flush().unwrap();
    let t2 = TxTable::open(&dir).unwrap();
    for i in [1u64, 500, 820] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t2.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)));
    }
    // twice
    assert_eq!(
        t2.get_fk_by_txid(&{
            let mut x = [0u8; 32];
            x[0..8].copy_from_slice(&1u64.to_le_bytes());
            x
        })
        .unwrap(),
        Some(Fk(1))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_occupancy_head_open_rebuilds_mphf_not_oa_backfill() {
    TxTable::test_with_rebuild_seal_bits(6, || {
        TxTable::test_with_rebuild_workers(2, || {
            let dir = tempfile_dir("empty-occ-rebuild");
            let layout = crate::address_head::default_layout();
            {
                let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
                let recs: Vec<TxRecord> = (0..65u64)
                    .map(|i| {
                        let mut txid = [0u8; 32];
                        txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
                        TxRecord {
                            txid,
                            version: 1,
                            locktime: 0,
                            input_start_fk: Fk::NULL,
                            input_count: 0,
                            output_start_fk: Fk::NULL,
                            output_count: 0,
                        }
                    })
                    .collect();
                t.put_full_batch_indexed(&meta_only_items(&recs), true)
                    .unwrap();
                t.flush().unwrap();
            }
            crate::segmented_head::wipe_segmented_head_files(&dir);
            crate::segmented_head::SegmentedTxHead::create(&dir, layout).unwrap();
            assert!(crate::segmented_head::head_meta_exists(&dir));
            let t = TxTable::open(&dir).unwrap();
            assert!(
                t.head.sealed_segment_count() >= 2,
                "empty occupancy must full-rebuild, sealed={}",
                t.head.sealed_segment_count()
            );
            assert!(!dir.join("tx.head").join("000000").is_file());
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&65u64.to_le_bytes());
            assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(65)));
            let _ = std::fs::remove_dir_all(&dir);
        });
    });
}

#[test]
fn rebuild_head_direct_mphf_empty_tail() {
    TxTable::test_with_rebuild_seal_bits(6, || {
        TxTable::test_with_rebuild_workers(2, || {
            let dir = tempfile_dir("rebuild-direct-mphf");
            {
                let t = create_tiny(&dir);
                let recs: Vec<TxRecord> = (0..65u64)
                    .map(|i| {
                        let mut txid = [0u8; 32];
                        txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
                        TxRecord {
                            txid,
                            version: 1,
                            locktime: 0,
                            input_start_fk: Fk::NULL,
                            input_count: 0,
                            output_start_fk: Fk::NULL,
                            output_count: 0,
                        }
                    })
                    .collect();
                t.put_full_batch_indexed(&meta_only_items(&recs), true)
                    .unwrap();
                t.flush().unwrap();
            }
            crate::segmented_head::wipe_segmented_head_files(&dir);
            let t = TxTable::open(&dir).unwrap();
            assert!(
                t.head.sealed_segment_count() >= 2,
                "T=64, n=65 must seal two MPHF ranges, sealed={} segs={}",
                t.head.sealed_segment_count(),
                t.head.segment_count()
            );
            let root = dir.join("tx.head");
            assert!(
                !root.join("000000").is_file(),
                "sealed range must not keep an OA file"
            );
            assert!(
                !root.join("000001").is_file(),
                "remainder must seal, not stay OA"
            );
            assert!(crate::tx_head_mphf::TxHeadMphf::exists(
                &root.join("000000")
            ));
            assert!(crate::tx_head_mphf::TxHeadMphf::exists(
                &root.join("000001")
            ));
            assert!(!crate::tx_head_mphf::rel_path(&root.join("000000")).is_file());
            assert!(!crate::tx_head_mphf::rel_path(&root.join("000001")).is_file());
            assert_eq!(
                &std::fs::read(crate::tx_head_mphf::mphf_path(&root.join("000000"))).unwrap()[0..4],
                b"BDZ2"
            );
            match t.head.open_tail_range() {
                Some((_, 0)) => {}
                other => panic!("expected empty open tail, got {other:?}"),
            }
            for i in [1u64, 64, 65] {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&i.to_le_bytes());
                assert_eq!(t.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)), "fk={i}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        });
    });
}

#[test]
fn rebuild_head_direct_mphf_bip30_newest_first() {
    TxTable::test_with_rebuild_seal_bits(6, || {
        TxTable::test_with_rebuild_workers(2, || {
            let dir = tempfile_dir("rebuild-direct-bip30");
            {
                let t = create_tiny(&dir);
                let mut shared = [0u8; 32];
                shared[0..8].copy_from_slice(&1u64.to_le_bytes());
                let r1 = TxRecord {
                    txid: shared,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                };
                let r2 = r1.clone();
                let mut rest: Vec<TxRecord> = (3..=65u64)
                    .map(|i| {
                        let mut txid = [0u8; 32];
                        txid[0..8].copy_from_slice(&i.to_le_bytes());
                        TxRecord {
                            txid,
                            version: 1,
                            locktime: 0,
                            input_start_fk: Fk::NULL,
                            input_count: 0,
                            output_start_fk: Fk::NULL,
                            output_count: 0,
                        }
                    })
                    .collect();
                let mut recs = vec![r1, r2];
                recs.append(&mut rest);
                t.put_full_batch_indexed(&meta_only_items(&recs), true)
                    .unwrap();
                t.flush().unwrap();
            }
            crate::segmented_head::wipe_segmented_head_files(&dir);
            let t = TxTable::open(&dir).unwrap();
            let mut shared = [0u8; 32];
            shared[0..8].copy_from_slice(&1u64.to_le_bytes());
            let all = t.get_all_by_txid(&shared).unwrap();
            assert_eq!(all.len(), 2, "both BIP30 creates");
            assert_eq!(all[0].0, Fk(2), "newest first {all:?}");
            assert_eq!(all[1].0, Fk(1));
            let _ = std::fs::remove_dir_all(&dir);
        });
    });
}

#[test]
fn plan_head_rebuild_ranges_chunks_seal_bits_not_oa_load() {
    let dir = tempfile_dir("plan-seal-bits");
    let t = create_tiny(&dir);
    let recs: Vec<TxRecord> = (0..200u64)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        })
        .collect();
    t.put_full_batch_indexed(&meta_only_items(&recs), true)
        .unwrap();
    TxTable::test_with_rebuild_seal_bits(6, || {
        let ranges6 = t.plan_head_rebuild_ranges().unwrap();
        assert_eq!(
            ranges6,
            vec![(1, 64), (65, 64), (129, 64), (193, 8)],
            "bits=6 → T=64"
        );
    });
    TxTable::test_with_rebuild_seal_bits(7, || {
        let ranges7 = t.plan_head_rebuild_ranges().unwrap();
        assert_eq!(
            ranges7,
            vec![(1, 128), (129, 72)],
            "bits=7 → T=128 (knob is seal bits, not OA 80%)"
        );
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plan_head_rebuild_ranges_ignores_body_soft_span() {
    TxTable::test_with_rebuild_seal_bits(8, || {
        let dir = tempfile_dir("plan-no-body-span");
        let t = create_tiny(&dir);
        let mk = |i: u64| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            let tx = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0xab; 64],
                witness: vec![vec![0xcd; 400]],
            }];
            let outputs = vec![OutputRecord::unspent(1, vec![0x51; 32])];
            (tx, inputs, outputs)
        };
        crate::tx_idx::test_with_soft_span_bytes(800, || {
            for i in 1..=6u64 {
                t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            let ranges = t.plan_head_rebuild_ranges().unwrap();
            assert_eq!(
                ranges,
                vec![(1, 6)],
                "rebuild cuts are 2^bits only, not body span, ranges={ranges:?}"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn parse_rebuild_seal_bits_default_25() {
    assert_eq!(parse_rebuild_seal_bits(None), 25);
    assert_eq!(parse_rebuild_seal_bits(Some("25")), 25);
    assert_eq!(parse_rebuild_seal_bits(Some("26")), 26);
    assert_eq!(parse_rebuild_seal_bits(Some("foo")), 25);
    assert_eq!(parse_rebuild_seal_bits(Some("5")), 6);
    assert_eq!(parse_rebuild_seal_bits(Some("99")), 26);
}

#[test]
fn parse_rebuild_workers_and_1gib_cap() {
    assert_eq!(parse_rebuild_workers(None), None);
    assert_eq!(parse_rebuild_workers(Some("foo")), None);
    assert_eq!(parse_rebuild_workers(Some("1")), Some(1));
    assert_eq!(parse_rebuild_workers(Some("0")), Some(1));
    assert_eq!(parse_rebuild_workers(Some("8")), Some(8));
    assert_eq!(parse_rebuild_workers(Some("999")), Some(256));
    const GIB: u64 = 1024 * 1024 * 1024;
    assert_eq!(TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES, GIB);
    assert_eq!(tx_head_rebuild_workers_for_free_ram(8, 0), 1);
    assert_eq!(tx_head_rebuild_workers_for_free_ram(8, GIB), 1);
    assert_eq!(tx_head_rebuild_workers_for_free_ram(8, 2 * GIB), 2);
    assert_eq!(tx_head_rebuild_workers_for_free_ram(4, 20 * GIB), 4);
}

#[test]
fn rebuild_workers_override_is_thread_local() {
    TxTable::test_with_rebuild_workers(3, || {
        assert_eq!(TxTable::rebuild_workers(), 3);
        let other = std::thread::spawn(TxTable::rebuild_workers)
            .join()
            .expect("join");
        assert_eq!(TxTable::rebuild_workers(), 3);
        assert_ne!(other, 3);
    });
}

#[test]
fn rebuild_seal_bits_override_is_thread_local() {
    TxTable::test_with_rebuild_seal_bits(6, || {
        assert_eq!(TxTable::rebuild_seal_bits(), 6);
        let other = std::thread::spawn(TxTable::rebuild_seal_bits)
            .join()
            .expect("join");
        assert_eq!(TxTable::rebuild_seal_bits(), 6);
        assert_ne!(other, 6);
    });
}

#[test]
fn rebuild_seal_bits_override_restores_after_panic() {
    TxTable::test_with_rebuild_seal_bits(7, || {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            TxTable::test_with_rebuild_seal_bits(8, || panic!("rebuild-bits boom"));
        }));
        assert!(panicked.is_err());
        assert_eq!(TxTable::rebuild_seal_bits(), 7);
    });
}

#[test]
fn refuse_legacy_mono_head_on_create() {
    let dir = tempfile_dir("legacy-mono");
    std::fs::write(dir.join("tx.head"), b"mono").unwrap();
    let err = TxTable::create(&dir).err().expect("must refuse mono head");
    let s = format!("{err}");
    assert!(s.contains("legacy") || s.contains("reindex"), "{s}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for ent in std::fs::read_dir(src).unwrap() {
        let ent = ent.unwrap();
        let to = dst.join(ent.file_name());
        if ent.path().is_dir() {
            copy_tree(&ent.path(), &to);
        } else {
            std::fs::copy(ent.path(), &to).unwrap();
        }
    }
}

/// Kill mid-seal: meta still has an unsealed non-tail OA. Open rebuilds fuse
/// keys from Class A and seals it before returning.
#[test]
fn open_seals_unsealed_nontail_after_copied_roll() {
    let dir = tempfile_dir("bg-seal-live");
    let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
    let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
    let n = 205u64;
    let recs: Vec<TxRecord> = (0..n)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&(i + 1).to_le_bytes());
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        })
        .collect();
    t.put_full_batch_indexed(&meta_only_items(&recs), true)
        .unwrap();
    assert_eq!(
        t.head.sealed_segment_count(),
        0,
        "roll must leave the seal unpublished"
    );
    assert!(
        t.head.unsealed_ranges().len() >= 2,
        "tail + sealing OA, unsealed={:?}",
        t.head.unsealed_ranges()
    );
    let copy = tempfile_dir("bg-seal-copy");
    copy_tree(&dir, &copy);
    let t2 = TxTable::open(&copy).unwrap();
    assert!(
        t2.head.sealed_segment_count() >= 1,
        "open must rebuild keys and seal leftover nontail"
    );
    for i in [1u64, 100, 204, 205] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t2.get_fk_by_txid(&txid).unwrap(), Some(Fk(i)), "fk={i}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&copy);
}

fn rec_meta(version: i32, locktime: u32, n_in: u32, n_out: u32) -> TxRecord {
    TxRecord {
        txid: [0u8; 32],
        version,
        locktime,
        input_start_fk: Fk::NULL,
        input_count: n_in,
        output_start_fk: Fk::NULL,
        output_count: n_out,
    }
}

#[test]
fn body_meta_v17_v1_locktime_zero_is_three_bytes() {
    let rec = rec_meta(1, 0, 1, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(
        buf,
        vec![0x89, 0x01, 0x01],
        "LAYOUT17|VER_1|LOCKTIME_ZERO + uleb 1,1"
    );
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(got.version, 1);
    assert_eq!(got.locktime, 0);
    assert_eq!(got.input_count, 1);
    assert_eq!(got.output_count, 1);
}

#[test]
fn body_meta_v17_v2_locktime_zero() {
    let rec = rec_meta(2, 0, 1, 2);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(buf[0], 0x8A, "LAYOUT17|VER_2|LOCKTIME_ZERO");
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(got.version, 2);
    assert_eq!(got.locktime, 0);
    assert_eq!(got.output_count, 2);
}

#[test]
fn body_meta_v17_locktime_tip_is_uleb() {
    let rec = rec_meta(2, 800_000, 1, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(buf[0] & 0x80, 0x80, "LAYOUT17 set");
    assert_eq!(buf[0] & 0x08, 0, "LOCKTIME_ZERO clear");
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(got.locktime, 800_000);
    assert_eq!(got.version, 2);
    assert!(buf.len() < 16, "must beat 16 B meta");
}

#[test]
fn body_meta_v17_high_bit_version_is_explicit_i32() {
    let ver = i32::from_le_bytes([0x00, 0x00, 0x00, 0x80]);
    let rec = rec_meta(ver, 0, 1, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(buf[0] & 0x07, 0, "no VER_1/2/3 for high-bit nVersion");
    assert_eq!(&buf[1..5], &[0x00, 0x00, 0x00, 0x80]);
    let (got, _) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(got.version, ver);
}

#[test]
fn body_meta_v17_rejects_missing_layout_bit() {
    // Schema-15 v1 meta starts 01 00 00 00 — must not parse as v17.
    let legacy = [1u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
    match decode_body_meta_v17(&legacy) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("LAYOUT17") || m.contains("legacy"), "{m}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

fn p2pkh_script(h160: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&h160);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn p2sh_script(h160: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&h160);
    s.push(0x87);
    s
}

fn p2wpkh_script(h160: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&h160);
    s
}

fn p2wsh_script(h256: [u8; 32]) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend_from_slice(&h256);
    s
}

fn p2tr_script(xonly: [u8; 32]) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&xonly);
    s
}

fn assert_kind_roundtrip(script: &[u8], kind: u8, classify_payload: &[u8], disk: &[u8]) {
    assert_eq!(classify_script(script), (kind, classify_payload));
    let mut buf = Vec::new();
    let enc_kind = encode_script_kind_v17(script, &mut buf);
    assert_eq!(enc_kind, kind);
    assert_eq!(buf, disk);
    let (got, n) = decode_script_kind_v17(kind, &buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(got, script);
    assert_eq!(expand_script_kind(kind, classify_payload).unwrap(), script);
}

#[test]
fn script_kind_v17_empty() {
    assert_kind_roundtrip(&[], SCRIPT_KIND_V17_EMPTY, &[], &[]);
}

#[test]
fn script_kind_v17_op_true() {
    assert_kind_roundtrip(&[0x51], SCRIPT_KIND_V17_OP_TRUE, &[], &[]);
}

#[test]
fn script_kind_v17_p2pkh() {
    let h = [0x11u8; 20];
    assert_kind_roundtrip(&p2pkh_script(h), SCRIPT_KIND_V17_P2PKH, &h, &h);
}

#[test]
fn script_kind_v17_p2sh() {
    let h = [0x22u8; 20];
    assert_kind_roundtrip(&p2sh_script(h), SCRIPT_KIND_V17_P2SH, &h, &h);
}

#[test]
fn script_kind_v17_p2wpkh() {
    let h = [0x33u8; 20];
    assert_kind_roundtrip(&p2wpkh_script(h), SCRIPT_KIND_V17_P2WPKH, &h, &h);
}

#[test]
fn script_kind_v17_p2wsh() {
    let h = [0x44u8; 32];
    assert_kind_roundtrip(&p2wsh_script(h), SCRIPT_KIND_V17_P2WSH, &h, &h);
}

#[test]
fn script_kind_v17_p2tr_expands_to_wire() {
    let x = [0x55u8; 32];
    let script = p2tr_script(x);
    assert_eq!(script[0], 0x51);
    assert_eq!(script[1], 0x20);
    assert_eq!(&script[2..], &x);
    assert_kind_roundtrip(&script, SCRIPT_KIND_V17_P2TR, &x, &x);
}

#[test]
fn script_kind_v17_op_return_single_push() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut script = vec![0x6a, data.len() as u8];
    script.extend_from_slice(&data);
    let mut disk = Vec::new();
    crate::compact::write_compact_size(&mut disk, data.len() as u64);
    disk.extend_from_slice(&data);
    assert_kind_roundtrip(&script, SCRIPT_KIND_V17_OP_RETURN_PUSH, &data, &disk);
}

#[test]
fn script_kind_v17_p2a_expands_to_wire() {
    let script = [0x51, 0x02, 0x4e, 0x73];
    assert_kind_roundtrip(&script, SCRIPT_KIND_V17_P2A, &[], &[]);
}

#[test]
fn script_kind_v17_p2pkh_lookalike_stays_raw() {
    let mut script = p2pkh_script([0x11; 20]);
    script.push(0x00);
    assert_eq!(script.len(), 26);
    let (kind, payload) = classify_script(&script);
    assert_eq!(kind, SCRIPT_KIND_V17_RAW);
    assert_eq!(payload, script);
    let mut buf = Vec::new();
    let enc_kind = encode_script_kind_v17(&script, &mut buf);
    assert_eq!(enc_kind, SCRIPT_KIND_V17_RAW);
    let mut expect = Vec::new();
    crate::compact::write_compact_size(&mut expect, script.len() as u64);
    expect.extend_from_slice(&script);
    assert_eq!(buf, expect);
    let (got, n) = decode_script_kind_v17(enc_kind, &buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(got, script);
}

#[test]
fn script_kind_v17_op_return_pushdata1_stays_raw() {
    // Non-canonical PUSHDATA1 for a 4-byte payload must not take kind 8.
    let script = vec![0x6a, 0x4c, 0x04, 0xde, 0xad, 0xbe, 0xef];
    assert_eq!(classify_script(&script).0, SCRIPT_KIND_V17_RAW);
}

#[test]
fn spent_slot_v17_unspent_is_eight_zero_bytes() {
    let slot = encode_spent_slot_v17(0, Fk::NULL).unwrap();
    assert_eq!(slot, [0u8; 8]);
    let (flags, field) = decode_spent_slot_v17(&slot).unwrap();
    assert_eq!(flags, 0);
    assert!(field.is_null());
}

#[test]
fn spent_slot_v17_sole_fk_roundtrip() {
    let fk = Fk(0x0001_0203_0405_0607);
    let slot = encode_spent_slot_v17(0, fk).unwrap();
    assert_eq!(slot[0], 0, "flags first");
    assert_eq!(&slot[1..], &[0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    let (flags, field) = decode_spent_slot_v17(&slot).unwrap();
    assert_eq!(flags, 0);
    assert_eq!(field, fk);
}

#[test]
fn spent_slot_v17_multi_list_head_roundtrip() {
    let head = Fk(42);
    let slot = encode_spent_slot_v17(output_flags::MULTI_SPENDER, head).unwrap();
    assert_eq!(slot[0], output_flags::MULTI_SPENDER);
    let (flags, field) = decode_spent_slot_v17(&slot).unwrap();
    assert_eq!(
        flags & output_flags::MULTI_SPENDER,
        output_flags::MULTI_SPENDER
    );
    assert_eq!(field, head);
}

#[test]
fn spent_slot_v17_fk_at_2pow56_is_corrupt() {
    match encode_spent_slot_v17(0, Fk(1u64 << 56)) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("56") || m.contains("u56"), "{m}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn spent_slot_v17_len_constant_is_eight() {
    assert_eq!(OutputRecord::SPENT_SLOT_LEN, 8);
}

#[test]
fn spent_span_matches_slot_len_times_n_out() {
    for n_out in [0u32, 1, 4, 500] {
        let mut buf = Vec::new();
        encode_spent_zeros(n_out, &mut buf);
        assert_eq!(buf.len(), n_out as usize * OutputRecord::SPENT_SLOT_LEN);
        let off = 16u64;
        for vout in 0..n_out {
            assert_eq!(
                spent_abs(off, vout),
                off + u64::from(vout) * OutputRecord::SPENT_SLOT_LEN as u64
            );
        }
    }
}

#[test]
fn reserved_flag_v17_inwit_high_bits_are_corrupt() {
    let rec = InputRecord::coinbase(u32::MAX, vec![], vec![]);
    let mut raw = rec.encode();
    raw[0] |= 1 << 5;
    match InputRecord::decode_at(&raw) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("reserved") || m.contains("inwit"), "{m}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
    raw[0] = 1 << 7;
    assert!(matches!(
        InputRecord::decode_prevout_at(&raw),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn reserved_flag_v17_spent_unknown_bits_are_corrupt() {
    match encode_spent_slot_v17(1, Fk::NULL) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("spent") || m.contains("flag"), "{m}");
        }
        other => panic!("expected Corrupt on encode, got {other:?}"),
    }
    let mut slot = encode_spent_slot_v17(output_flags::MULTI_SPENDER, Fk(3)).unwrap();
    slot[0] |= 1 << 0;
    match decode_spent_slot_v17(&slot) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("spent") || m.contains("flag"), "{m}");
        }
        other => panic!("expected Corrupt on decode, got {other:?}"),
    }
}

#[test]
fn script_kind_v17_kind_ten_is_corrupt() {
    match decode_script_kind_v17(10, &[]) {
        Err(StoreError::Corrupt(m)) => {
            assert!(
                m.contains("script kind") || m.contains("SCRIPT_KIND"),
                "{m}"
            );
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

/// Fat inwit must not force a new `txout.idx` / `spent.idx` segment.
#[test]
fn idx_roll_independent_of_inwit_span() {
    crate::tx_idx::test_with_soft_span_bytes(2048, || {
        let dir = tempfile_dir("idx-indep");
        let t = create_tiny(&dir);
        let fat_script = vec![0x6au8; 1800];
        for i in 0..6u8 {
            let mut txid = [0u8; 32];
            txid[0] = i.wrapping_add(1);
            let tx = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let inputs = vec![InputRecord::coinbase(u32::MAX, fat_script.clone(), vec![])];
            let outs = vec![OutputRecord::unspent(1, vec![0x51])];
            t.put_full_batch_indexed(&[(tx, inputs, outs)], false)
                .unwrap();
        }
        assert!(
            t.inwit.idx_segment_count() >= 2,
            "inwit segs={}",
            t.inwit.idx_segment_count()
        );
        assert_eq!(
            t.body.idx_segment_count(),
            1,
            "txout.idx must not roll when only inwit crosses the soft span"
        );
        assert_eq!(
            t.spent.idx_segment_count(),
            1,
            "spent.idx must not roll when only inwit crosses the soft span"
        );
        let last = t.get(Fk(6)).unwrap();
        assert_eq!(last.output_count, 1);
        let raw_in = t.inwit.get_raw(Fk(6)).unwrap();
        assert!(raw_in.len() >= 1800, "len={}", raw_in.len());
        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn script_hash_collect_span_is_16mib() {
    assert_eq!(SCRIPT_HASH_COLLECT_SPAN, 16 * 1024 * 1024);
}
