//! Tx table unit tests (peeled).

use super::*;
use crate::compact::{
    classify_script, decode_script_kind_v17, encode_script_kind_v17, expand_script_kind,
    SCRIPT_KIND_V17_EMPTY, SCRIPT_KIND_V17_OP_RETURN_PUSH, SCRIPT_KIND_V17_OP_TRUE,
    SCRIPT_KIND_V17_P2A, SCRIPT_KIND_V17_P2PKH, SCRIPT_KIND_V17_P2SH, SCRIPT_KIND_V17_P2TR,
    SCRIPT_KIND_V17_P2WPKH, SCRIPT_KIND_V17_P2WSH, SCRIPT_KIND_V17_RAW,
};
use crate::hashhead::{HeadOpenOpts, HeadScale};
use rbitcoin_primitives::{read_uleb128, write_compact_size, write_uleb128, Fk};
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

#[test]
fn flush_clears_pending_sync_on_replay_stems() {
    let dir = tempfile_dir("flush-pending");
    let t = create_tiny(&dir);
    t.txids.append_batch(0, &[[9u8; 32]]).unwrap();
    t.input
        .append(&[vec![crate::input::InputEdge::coinbase()]])
        .unwrap();
    assert!(t.txids.pending_sync());
    assert!(t.txstat.pending_sync());
    assert!(t.input.pending_sync());
    t.flush().unwrap();
    assert!(!t.txids.pending_sync());
    assert!(!t.txstat.pending_sync());
    assert!(!t.input.pending_sync());
    let _ = std::fs::remove_dir_all(&dir);
}

fn rebuild_opts(bits: u32, workers: usize) -> HeadOpenOpts {
    HeadOpenOpts::TINY
        .with_rebuild_seal_bits(bits)
        .with_rebuild_workers(workers)
}

fn create_tiny_rebuild(dir: &Path, bits: u32, workers: usize) -> TxTable {
    TxTable::create_with_head_layout_opts(dir, tiny_layout(), rebuild_opts(bits, workers)).unwrap()
}

fn open_tiny_rebuild(dir: &Path, bits: u32, workers: usize) -> TxTable {
    TxTable::open_with_opts(dir, rebuild_opts(bits, workers)).unwrap()
}

fn meta_only_items(recs: &[TxRecord]) -> Vec<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)> {
    recs.iter()
        .cloned()
        .map(|mut tx| {
            tx.output_count = 1;
            (tx, Vec::new(), vec![OutputRecord::unspent(0, vec![0x51])])
        })
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
    let _ = std::fs::remove_file(dir.join("seqsigwit.body"));
    match TxTable::open_tiny(&dir) {
        Ok(_) => panic!("missing seqsigwit must refuse"),
        Err(err) => assert!(
            format!("{err}").contains("missing seqsigwit/spent"),
            "{err}"
        ),
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
    let (fks, loc) = t
        .put_full_batch_from_pins(&[(pin, ins)], true, &[])
        .unwrap();
    assert_eq!(loc.len(), 1);
    assert_eq!(loc[0].txout, t.body_range(fks[0]).unwrap());
    assert_eq!(loc[0].spent, t.spent_range(fks[0]).unwrap());
    assert_eq!(loc[0].n_out, 1);
    let (got, gins, gouts) = t.get_full(fks[0]).unwrap();
    assert_eq!(got.txid, [3u8; 32]);
    assert_eq!(gins.len(), 1);
    assert_eq!(gouts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_full_batch_writes_txstat_and_reopen() {
    let dir = tempfile_dir("txstat-append");
    let t = create_tiny(&dir);
    let tx = TxRecord {
        txid: [9u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let outs = vec![OutputRecord::unspent(7, vec![0x51])];
    let fks = t.put_full_batch_indexed(&[(tx, ins, outs)], true).unwrap();
    assert_eq!(fks, vec![Fk(1)]);
    assert_eq!(t.txstat.count(), 1);
    assert_eq!(
        crate::txstat::parse_cell(t.txstat.get_cell(Fk(1)).unwrap()).unwrap(),
        crate::txstat::CellParse::Unstamped
    );
    assert_eq!(t.input.n_in(Fk(1)).unwrap(), Some(1));
    drop(t);
    let t2 = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t2.count(), 1);
    assert_eq!(t2.txid_sidefile().count(), 1);
    assert_eq!(t2.txstat.count(), 1);
    assert_eq!(
        crate::txstat::parse_cell(t2.txstat.get_cell(Fk(1)).unwrap()).unwrap(),
        crate::txstat::CellParse::Unstamped
    );
    assert_eq!(t2.input.n_in(Fk(1)).unwrap(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

fn two_input_item() -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let tx = TxRecord {
        txid: [0x11u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 2,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let ins = vec![
        InputRecord::coinbase(u32::MAX, vec![0x01], vec![]),
        InputRecord {
            prev_txid: [2u8; 32],
            create_fk: Fk(1),
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        },
    ];
    let outs = vec![OutputRecord::unspent(7, vec![0x51])];
    (tx, ins, outs)
}

#[test]
fn range_outs_leave_n_in_unstamped() {
    let dir = tempfile_dir("range-outs-no-nin");
    let t = create_tiny(&dir);
    let (tx, ins, outs) = two_input_item();
    let txid = tx.txid;
    let fk = t.put_full_batch_indexed(&[(tx, ins, outs)], true).unwrap()[0];
    assert_eq!(t.input.n_in(fk).unwrap(), Some(2));
    let range = t.body_range(fk).unwrap();
    let (rows, _, _, _, _, _) = t
        .get_outs_by_range_batch(&[(fk, range, txid, 1, vec![0])])
        .unwrap();
    let (got, _, _) = rows[0].as_ref().expect("range outs");
    assert_eq!(got.input_count, 0);
    assert_eq!(t.get_meta_and_outputs(fk).unwrap().0.input_count, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prevouts_use_txstat_n_in_without_full_txout() {
    let dir = tempfile_dir("prevouts-txstat");
    let t = create_tiny(&dir);
    let fk = t.put_full_batch_indexed(&[two_input_item()], true).unwrap()[0];
    let (off, len) = t.body_range(fk).unwrap();
    t.body
        .write_body_abs(off, &vec![0u8; len as usize])
        .unwrap();
    assert!(t.get(fk).is_err(), "txout zeros must fail full get");
    let (meta, prevs) = t.get_meta_and_prevouts(fk).unwrap();
    assert_eq!(meta.input_count, 2);
    assert_eq!(prevs.len(), 2);
    assert_eq!(prevs[0], (Fk::NULL, u32::MAX));
    assert_eq!(prevs[1], (Fk(1), 0));
    let edges = t.input.edges(fk).unwrap().unwrap();
    assert_eq!(edges[0], crate::input::InputEdge::coinbase());
    assert_eq!(
        edges[1],
        crate::input::InputEdge {
            parent: Fk(1),
            vout: 0,
        }
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn new_create_txout_meta_omits_n_in() {
    let dir = tempfile_dir("txout-omit-nin");
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
    let pin = std::sync::Arc::new((tx.clone(), outs.clone()));
    let mut pin_bytes = Vec::new();
    pin.encode_txout_body(&mut pin_bytes, None);
    assert_eq!(
        pin_bytes[0] & BODY_META_V17_N_IN_TXSTAT,
        BODY_META_V17_N_IN_TXSTAT,
        "pin first-wave txout omits n_in"
    );
    let fk = t.put_full_batch_indexed(&[(tx, ins, outs)], true).unwrap()[0];
    let (off, len) = t.body_range(fk).unwrap();
    let raw = t.with_body_span(off, len, |b| Ok(b.to_vec())).unwrap();
    assert_eq!(
        raw[0] & BODY_META_V17_N_IN_TXSTAT,
        BODY_META_V17_N_IN_TXSTAT
    );
    let (meta, n) = decode_body_meta_v17(&raw).unwrap();
    assert_eq!(n, 1, "v1 locktime 0 omit n_in is one flag byte");
    assert_eq!(meta.input_count, 0);
    let (got, gouts) = t.get_meta_and_outputs(fk).unwrap();
    assert_eq!(got.input_count, 1, "input.loc fills n_in");
    assert_eq!(gouts.len(), 1);
    let leftover = [0x89u8, 0x01];
    let (old, on) = decode_body_meta_v17(&leftover).unwrap();
    assert_eq!(on, 2);
    assert_eq!(old.input_count, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reopen_without_inputs_refuses_new_seqsigwit() {
    let dir = tempfile_dir("input-backfill");
    let t = create_tiny(&dir);
    let _fk = t.put_full_batch_indexed(&[two_input_item()], true).unwrap()[0];
    drop(t);
    for name in ["input.loc", "input.off", "input.body"] {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    match TxTable::open_tiny(&dir) {
        Err(StoreError::Corrupt("seqsigwit prevout is on inputs")) => {}
        Err(e) => panic!("open without inputs: {e}"),
        Ok(_) => panic!("open without inputs recovered a new seqsigwit"),
    }
    let _ = std::fs::remove_dir_all(&dir);

    // New-layout tail: one stamped create, one missing. That create is not
    // stamped n_in = 0. Class A truncates to the stamped input count.
    let dir = tempfile_dir("input-unstamped-tail");
    let t = create_tiny(&dir);
    t.put_full_batch_indexed(&[two_input_item(), two_input_item()], true)
        .unwrap();
    drop(t);
    for name in ["input.loc", "input.off", "input.body"] {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    let partial = crate::input::Input::create(&dir).unwrap();
    partial
        .append(&[vec![
            crate::input::InputEdge::coinbase(),
            crate::input::InputEdge {
                parent: Fk(1),
                vout: 0,
            },
        ]])
        .unwrap();
    drop(partial);
    let t2 = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t2.count(), 1, "short new-layout input truncates Class A");
    assert_eq!(t2.input.count(), 1);
    assert!(
        t2.input.edges(Fk(1)).unwrap().is_some(),
        "the stamped create keeps its edges"
    );
    assert!(
        t2.input.edges(Fk(2)).is_err(),
        "the edgeless create is not left unstamped"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn input_n_in_scans_both_prevouts() {
    let dir = tempfile_dir("input-nin-prevouts");
    let t = create_tiny(&dir);
    let fk = t.put_full_batch_indexed(&[two_input_item()], true).unwrap()[0];
    t.txstat
        .write_row(
            fk,
            &crate::txstat::TxStatRow {
                fee_sat: 0,
                base: 0,
                wit_extra: 0,
            },
        )
        .unwrap();
    let (meta, prevs) = t.get_meta_and_prevouts(fk).unwrap();
    assert_eq!(meta.input_count, 2);
    assert_eq!(prevs.len(), 2);
    assert_eq!(t.input.n_in(fk).unwrap(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Class A append submits txout+seqsigwit+spent bodies as one pwrite wave (not 3 serial).
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
    let (fks, _loc) = t
        .put_full_batch_from_pins(&[(pin, ins)], true, &[])
        .unwrap();
    assert_eq!(fks.len(), 1);
    let (tx, got_ins, got_outs) = t.get_full(fks[0]).unwrap();
    assert_eq!(tx.output_count, 1);
    assert_eq!(got_ins.len(), 1);
    assert_eq!(got_outs[0].value, 7);
    assert_eq!(got_outs[0].script, vec![0x51]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_full_batch_from_pins_same_batch_spent_slot() {
    let dir = tempfile_dir("same-batch-spent");
    let t = create_tiny(&dir);
    let parent_tx = TxRecord {
        txid: [1u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 2,
    };
    let child_tx = TxRecord {
        txid: [2u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let parent_pin = std::sync::Arc::new((
        parent_tx,
        vec![
            OutputRecord::unspent(7, vec![0x51]),
            OutputRecord::unspent(8, vec![0x52]),
        ],
    ));
    let child_pin = std::sync::Arc::new((child_tx, vec![OutputRecord::unspent(5, vec![0x51])]));
    let parent_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let child_ins = vec![InputRecord {
        prev_txid: [1u8; 32],
        create_fk: Fk(1),
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![0x01],
        witness: vec![],
    }];
    let overlay = [vec![(0u32, Fk(2), 0)], vec![]];
    let (fks, loc) = t
        .put_full_batch_from_pins(
            &[(parent_pin, parent_ins), (child_pin, child_ins)],
            false,
            &overlay,
        )
        .unwrap();
    assert_eq!(fks, vec![Fk(1), Fk(2)]);
    assert_eq!(loc[0].spent, t.spent_range(fks[0]).unwrap());
    assert_eq!(loc[0].n_out, 2);
    let (off, _len) = t.spent_range(fks[0]).unwrap();
    let abs0 = spent_abs(off, 0);
    let abs1 = spent_abs(off, 1);
    let bulk = t.get_spender_meta_at_abs_batch(&[abs0, abs1]).unwrap();
    assert_eq!(bulk[0].unwrap().0, Fk(2));
    assert!(bulk[1].unwrap().0.is_null());
    let (coff, _) = t.spent_range(fks[1]).unwrap();
    let cabs = spent_abs(coff, 0);
    let cbulk = t.get_spender_meta_at_abs_batch(&[cabs]).unwrap();
    assert!(cbulk[0].unwrap().0.is_null());
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
        t.probe_body_match_fk(&txid).unwrap().is_none(),
        "durable head must miss before drain"
    );
    t.head_note_pending(&[(txid, fks[0])]);
    assert!(
        t.probe_body_match_fk(&txid).unwrap().is_none(),
        "queued drain list is not a leftover home"
    );
    assert_eq!(t.head_drain_pending().unwrap(), 1);
    assert_eq!(t.pending_head_len(), 0);
    assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(fks[0]));
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
    assert_eq!(t.head_drain_pending().unwrap(), 8);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    for (txid, fk) in &pending {
        assert_eq!(
            t.probe_body_match_fk(txid).unwrap(),
            Some(*fk),
            "reopen must show each same-page key"
        );
    }
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
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(
        t.probe_body_match_fk(&txid).unwrap(),
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
    let t2 = TxTable::open_tiny(&dir).expect("open should repair skew");
    assert_eq!(t2.count(), 3);
    assert_eq!(t2.txid_sidefile().count(), 3);
    assert_eq!(t2.txstat.count(), 3);
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
fn seqsigwit_backfill_spans_split_on_gap_and_cap() {
    fn leg_coinbase() -> Vec<u8> {
        vec![
            input_flags::NULL_PREV
                | input_flags::SEQ_FINAL
                | input_flags::EMPTY_SCRIPT
                | input_flags::EMPTY_WITNESS,
        ]
    }
    fn leg_spend(parent: u64, vout: u64) -> Vec<u8> {
        let mut v =
            vec![input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS];
        v.extend_from_slice(&parent.to_le_bytes());
        write_compact_size(&mut v, vout);
        v
    }
    let a = leg_coinbase();
    let b = leg_spend(1, 0);
    let c = leg_spend(2, 4);
    let mut blob = [0u8; 40];
    blob[..a.len()].copy_from_slice(&a);
    blob[a.len()..a.len() + b.len()].copy_from_slice(&b);
    let c_at = 30usize;
    blob[c_at..c_at + c.len()].copy_from_slice(&c);
    let ranges = vec![
        Some((0u64, a.len() as u64)),
        Some((a.len() as u64, b.len() as u64)),
        Some((c_at as u64, c.len() as u64)),
    ];
    let reads = std::cell::Cell::new(0u32);
    let mut buf = Vec::new();
    let edges = edges_from_seqsigwit_ranges(
        &mut |off, len, buf| {
            reads.set(reads.get() + 1);
            let s = off as usize;
            let n = len as usize;
            buf.clear();
            buf.extend_from_slice(&blob[s..s + n]);
            Ok(())
        },
        &ranges,
        1024,
        &mut buf,
    )
    .unwrap();
    assert_eq!(
        reads.get(),
        2,
        "contiguous a+b are one pread; the gap is another"
    );
    assert_eq!(edges[0], vec![crate::input::InputEdge::coinbase()]);
    assert_eq!(
        edges[1],
        vec![crate::input::InputEdge {
            parent: Fk(1),
            vout: 0
        }]
    );
    assert_eq!(
        edges[2],
        vec![crate::input::InputEdge {
            parent: Fk(2),
            vout: 4
        }]
    );
    reads.set(0);
    let edges = edges_from_seqsigwit_ranges(
        &mut |off, len, buf| {
            reads.set(reads.get() + 1);
            let s = off as usize;
            buf.clear();
            buf.extend_from_slice(&blob[s..s + len as usize]);
            Ok(())
        },
        &ranges[..2],
        (a.len() + b.len() - 1) as u64,
        &mut buf,
    )
    .unwrap();
    assert_eq!(reads.get(), 2, "a span cap splits contiguous records");
    assert_eq!(edges.len(), 2);

    let cap = (a.len() + b.len()) as u64;
    reads.set(0);
    let _ = edges_from_seqsigwit_ranges(
        &mut |off, len, buf| {
            reads.set(reads.get() + 1);
            assert_ne!(len, 0);
            let s = off as usize;
            buf.clear();
            buf.extend_from_slice(&blob[s..s + len as usize]);
            Ok(())
        },
        &ranges[..2],
        cap,
        &mut buf,
    )
    .unwrap();
    assert_eq!(
        reads.get(),
        1,
        "a span that lands on the cap stays one pread"
    );

    let base = 1_000u64;
    let mut far = [0u8; 1_100];
    far[base as usize..base as usize + a.len()].copy_from_slice(&a);
    far[base as usize + a.len()..base as usize + a.len() + b.len()].copy_from_slice(&b);
    let far_ranges = [
        Some((base, a.len() as u64)),
        Some((base + a.len() as u64, b.len() as u64)),
    ];
    reads.set(0);
    let far_edges = edges_from_seqsigwit_ranges(
        &mut |off, len, buf| {
            reads.set(reads.get() + 1);
            assert_ne!(len, 0);
            let s = off as usize;
            buf.clear();
            buf.extend_from_slice(&far[s..s + len as usize]);
            Ok(())
        },
        &far_ranges,
        64,
        &mut buf,
    )
    .unwrap();
    assert_eq!(
        reads.get(),
        1,
        "the cap is the span length, not the file offset"
    );
    assert_eq!(far_edges[0], vec![crate::input::InputEdge::coinbase()]);
    assert_eq!(far_edges[1][0].parent, Fk(1));

    reads.set(0);
    let empty = edges_from_seqsigwit_ranges(
        &mut |_off, len, buf| {
            reads.set(reads.get() + 1);
            assert_ne!(len, 0, "a zero-length record is not a pread");
            buf.clear();
            Ok(())
        },
        &[Some((5, 0))],
        1024,
        &mut buf,
    )
    .unwrap();
    assert_eq!(reads.get(), 0);
    assert_eq!(empty, vec![vec![]]);

    assert_eq!(backfill_chunk_end(1, u64::MAX), INPUT_BACKFILL_FKS);
    assert_eq!(backfill_chunk_end(2, u64::MAX), INPUT_BACKFILL_FKS + 1);
    assert_eq!(backfill_chunk_end(1, 10), 10);
    assert!(!backfill_progress_due(500_000, 1));
    assert!(backfill_progress_due(1_000_000, 1));
    assert!(!backfill_progress_due(1_500_000, 1_000_001));
    assert!(backfill_progress_due(1_000_000, 1_000_000));
    assert_eq!(unstamped_tail(2, 1), 1);
    assert_eq!(unstamped_tail(1_000, 1), 999);
    input_open_tail_cases();
}

fn input_open_tail_cases() {
    assert_eq!(
        input_open_tail(0, 3, 3),
        InputOpenTail::Backfill { from: 1 }
    );
    assert_eq!(
        input_open_tail(1, 3, 2),
        InputOpenTail::Unstamped { n: 2 },
        "short input with a seqsigwit count mismatch is the unstamped tail"
    );
    assert_eq!(input_open_tail(3, 3, 2), InputOpenTail::Ready);
    assert_eq!(input_open_tail(4, 3, 3), InputOpenTail::Ahead);
}

#[test]
fn reopen_backfills_legacy_seqsigwit_as_spans() {
    let dir = tempfile_dir("input-backfill-span");
    let t = create_tiny(&dir);
    let coinbase = (
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let spend = (
        TxRecord {
            txid: [2u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [1u8; 32],
            create_fk: Fk(1),
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![0xab; 8],
            witness: vec![vec![0x30; 16]],
        }],
        vec![OutputRecord::unspent(2, vec![0x51])],
    );
    t.put_full_batch_indexed(&[coinbase, spend.clone(), spend], true)
        .unwrap();
    let payloads = [
        vec![
            input_flags::NULL_PREV
                | input_flags::SEQ_FINAL
                | input_flags::EMPTY_SCRIPT
                | input_flags::EMPTY_WITNESS,
        ],
        {
            let mut v = vec![
                input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS,
            ];
            v.extend_from_slice(&1u64.to_le_bytes());
            write_compact_size(&mut v, 0);
            v
        },
        {
            let mut v = vec![
                input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS,
            ];
            v.extend_from_slice(&2u64.to_le_bytes());
            write_compact_size(&mut v, 1);
            v
        },
    ];
    for (i, payload) in payloads.iter().enumerate() {
        let (off, len) = t.seqsigwit_range(Fk((i + 1) as u64)).unwrap();
        assert!(
            (payload.len() as u64) <= len,
            "legacy prevout must fit the existing record"
        );
        let mut raw = payload.clone();
        raw.resize(len as usize, 0);
        t.seqsigwit.write_body_abs(off, &raw).unwrap();
    }
    drop(t);
    for name in ["input.loc", "input.off", "input.body"] {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    let t2 = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(
        t2.input.edges(Fk(1)).unwrap().unwrap(),
        vec![crate::input::InputEdge::coinbase()]
    );
    assert_eq!(
        t2.input.edges(Fk(2)).unwrap().unwrap(),
        vec![crate::input::InputEdge {
            parent: Fk(1),
            vout: 0
        }]
    );
    assert_eq!(
        t2.input.edges(Fk(3)).unwrap().unwrap(),
        vec![crate::input::InputEdge {
            parent: Fk(2),
            vout: 1
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reopen_resumes_partial_legacy_input_backfill() {
    let dir = tempfile_dir("input-backfill-resume");
    let t = create_tiny(&dir);
    let coinbase = (
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let spend = (
        TxRecord {
            txid: [2u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [1u8; 32],
            create_fk: Fk(1),
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![0xab; 8],
            witness: vec![vec![0x30; 16]],
        }],
        vec![OutputRecord::unspent(2, vec![0x51])],
    );
    t.put_full_batch_indexed(&[coinbase, spend], true).unwrap();
    for (i, payload) in [
        vec![
            input_flags::NULL_PREV
                | input_flags::SEQ_FINAL
                | input_flags::EMPTY_SCRIPT
                | input_flags::EMPTY_WITNESS,
        ],
        {
            let mut v = vec![
                input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS,
            ];
            v.extend_from_slice(&1u64.to_le_bytes());
            write_compact_size(&mut v, 0);
            v
        },
    ]
    .iter()
    .enumerate()
    {
        let (off, len) = t.seqsigwit_range(Fk((i + 1) as u64)).unwrap();
        assert!((payload.len() as u64) <= len);
        let mut raw = payload.clone();
        raw.resize(len as usize, 0);
        t.seqsigwit.write_body_abs(off, &raw).unwrap();
    }
    drop(t);
    for name in ["input.loc", "input.off", "input.body"] {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    let partial = crate::input::Input::create(&dir).unwrap();
    partial
        .append(&[vec![crate::input::InputEdge::coinbase()]])
        .unwrap();
    drop(partial);
    rbitcoin_log::progress::capture_finished(true);
    let t2 = TxTable::open_tiny(&dir).unwrap();
    let fin = finished_stages();
    assert!(fin.contains(&("input backfill", 2, 2)), "{fin:?}");
    assert_eq!(
        t2.input.edges(Fk(1)).unwrap().unwrap(),
        vec![crate::input::InputEdge::coinbase()]
    );
    assert_eq!(
        t2.input.edges(Fk(2)).unwrap().unwrap(),
        vec![crate::input::InputEdge {
            parent: Fk(1),
            vout: 0
        }],
        "resume must read the legacy prevout, not stamp n_in 0"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A resumed input backfill starts at the creates already backfilled, so
/// `/progress` does not drop to 0% after a restart. fk 1 was done before the
/// restart; fk 2's record is garbage, so the stage ends at the seed.
#[test]
fn input_backfill_resume_starts_at_backfilled_count() {
    let dir = tempfile_dir("input-backfill-progress");
    let t = create_tiny(&dir);
    let coinbase = (
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let spend = (
        TxRecord {
            txid: [2u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [1u8; 32],
            create_fk: Fk(1),
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![0xab; 8],
            witness: vec![vec![0x30; 16]],
        }],
        vec![OutputRecord::unspent(2, vec![0x51])],
    );
    t.put_full_batch_indexed(&[coinbase, spend], true).unwrap();
    for (i, payload) in [
        vec![
            input_flags::NULL_PREV
                | input_flags::SEQ_FINAL
                | input_flags::EMPTY_SCRIPT
                | input_flags::EMPTY_WITNESS,
        ],
        {
            let mut v = vec![
                input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS,
            ];
            v.extend_from_slice(&1u64.to_le_bytes());
            write_compact_size(&mut v, 0);
            v
        },
    ]
    .iter()
    .enumerate()
    {
        let (off, len) = t.seqsigwit_range(Fk((i + 1) as u64)).unwrap();
        assert!((payload.len() as u64) <= len);
        let mut raw = payload.clone();
        raw.resize(len as usize, 0);
        if i == 1 {
            // Declares a script longer than the span holds.
            raw.clear();
            raw.push(input_flags::SEQ_FINAL | input_flags::EMPTY_WITNESS);
            raw.extend_from_slice(&1u64.to_le_bytes());
            write_compact_size(&mut raw, 0);
            write_compact_size(&mut raw, 0xffff);
            raw.resize(len as usize, 0);
        }
        t.seqsigwit.write_body_abs(off, &raw).unwrap();
    }
    drop(t);
    for name in ["input.loc", "input.off", "input.body"] {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    let partial = crate::input::Input::create(&dir).unwrap();
    partial
        .append(&[vec![crate::input::InputEdge::coinbase()]])
        .unwrap();
    drop(partial);
    rbitcoin_log::progress::capture_finished(true);
    let r = TxTable::open_tiny(&dir);
    let fin = finished_stages();
    assert!(r.is_err(), "fk 2's record is garbage");
    assert_eq!(fin, [("input backfill", 1, 2)]);
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
    assert!(matches!(
        InputRecord::decode_prevout_at(&enc),
        Err(StoreError::Corrupt("seqsigwit prevout is on inputs"))
    ));
    let (full, used) = InputRecord::decode_at(&enc).unwrap();
    assert_eq!(used, enc.len());
    assert_eq!(full.script_sig.len(), 40);
    assert_eq!(full.sequence, 0xffff_fffe);
    assert!(full.create_fk.is_null());
    let mut legacy =
        vec![input_flags::SEQ_FINAL | input_flags::EMPTY_SCRIPT | input_flags::EMPTY_WITNESS];
    legacy.extend_from_slice(&1u64.to_le_bytes());
    legacy.push(3);
    let (cfk, vout, used) = InputRecord::decode_prevout_at(&legacy).unwrap();
    assert_eq!(cfk, Fk(1));
    assert_eq!(vout, 3);
    assert_eq!(used, legacy.len());

    // Script length 4 so the cursor must advance. Subtracting that length
    // lands inside create_fk on a zero compact size and stops short.
    let mut rich = vec![input_flags::SEQ_FINAL];
    rich.extend_from_slice(&1u64.to_le_bytes());
    rich.push(3);
    rich.push(4);
    rich.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    rich.push(1);
    rich.push(1);
    rich.push(0x11);
    let (cfk, vout, used) = InputRecord::decode_prevout_at(&rich).unwrap();
    assert_eq!(cfk, Fk(1));
    assert_eq!(vout, 3);
    assert_eq!(used, rich.len());
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
    assert_eq!(
        enc.len(),
        1,
        "seqsigwit stores no parent outpoint, enc={enc:?}"
    );
    assert_eq!(
        enc[0] & input_flags::PREV_ON_INPUTS,
        input_flags::PREV_ON_INPUTS
    );
    let dec = InputRecord::decode(&enc).unwrap();
    assert!(dec.create_fk.is_null());
    assert_eq!(dec.prev_index, 0);
    assert_eq!(dec.prev_txid, [0u8; 32]);
    assert_eq!(dec.sequence, u32::MAX);
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
    let (meta, _) = TxRecord::decode_body_meta(&raw).unwrap();
    assert_eq!(meta.txid, [0u8; 32], "body scan has no leading txid");
    assert_eq!(meta.input_count, 0, "txout meta omits n_in");
    let mut seqsigwit = Vec::new();
    encode_seqsigwit_with_secret(&inputs, &mut seqsigwit, None);
    assert!(matches!(
        scan_seqsigwit_prevouts(&seqsigwit, tx.input_count),
        Err(StoreError::Corrupt("seqsigwit prevout is on inputs"))
    ));
    let edges = vec![
        crate::input::InputEdge::coinbase(),
        crate::input::InputEdge {
            parent: Fk(1),
            vout: 1,
        },
    ];
    assert_eq!(
        prevouts_from_edges(&edges),
        vec![(Fk::NULL, u32::MAX), (Fk(1), 1)]
    );
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
    let (_, _, decode_rels) = decode_packed_tx_outs_with_spender_rels(&raw, 4).unwrap();
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
        let (_, _, decode_rels) =
            decode_packed_tx_outs_with_spender_rels(&raw, outputs.len() as u32).unwrap();
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
    let (_off, len) = t.seqsigwit_range(fk).unwrap();
    assert!(len > 50_000, "seqsigwit should hold the fat witness");
    // Head resolve still works.
    assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(fk));
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

/// Shape A: multi-cand `txid.body` select + one denserels for winner (outs present).
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
    let (outs_rows, _, _, _, _, _) = t
        .get_outs_by_range_batch(&[(fk, range.txout, txid, range.n_out, vec![0])])
        .unwrap();
    let (tx, outs, dens) = outs_rows[0].as_ref().expect("outs for winner");
    assert_eq!(tx.txid, txid);
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0].1.value, 22);
    assert_eq!(dens.len(), outs.len());

    let single = batch.iter().find(|(id, _)| *id == solo).unwrap();
    let (fk_s, range_s) = single.1.expect("single-cand hit");
    assert_eq!(fk_s, fk_solo);
    let (solo_rows, _, _, _, _, _) = t
        .get_outs_by_range_batch(&[(fk_s, range_s.txout, solo, range_s.n_out, vec![0])])
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
    let pair = batch[0].1.unwrap().1;
    assert!(pair.txout.1 > 0, "body range from loc on winner");
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
    let rev: Vec<[u8; 32]> = keys.iter().copied().rev().collect();
    let batch_rev = t.get_fk_by_txid_batch(&rev).unwrap();
    for (fwd, back) in batch.iter().zip(batch_rev.iter().rev()) {
        assert_eq!(fwd.0, back.0);
        assert_eq!(fwd.1.map(|(fk, _)| fk), back.1.map(|(fk, _)| fk));
    }
    assert_eq!(batch.len(), 5);
    for (txid, row) in &batch {
        let single = t.probe_body_match_fk(txid).unwrap();
        assert_eq!(row.map(|(f, _)| f), single);
        assert!(row.is_some());
        let (fk, pair) = row.unwrap();
        let known = t.body_range(fk).unwrap();
        assert_eq!(pair.txout, known, "returned range must match create.loc");
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
    let range = t.body_range(fk).unwrap();
    // Only need vout 1 — skip allocating big scripts on 0 and 2.
    let (rows, _, _, _, _, _) = t
        .get_outs_by_range_batch(&[(fk, range, want_txid, 3, vec![1])])
        .unwrap();
    let (got, live, sparse) = rows[0].as_ref().expect("range denserels");
    assert_eq!(got.txid, want_txid);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 1);
    assert_eq!(live[0].1.script, vec![0x51, 0x52]);
    assert_eq!(sparse.len(), 1);
    assert_eq!(sparse[0].0, 1);
    // Full decode for comparison.
    let full = decode_packed_tx_outs_with_spender_rels_secret(
        &{
            let (off, len) = t.body_range(fk).unwrap();
            t.with_body_span(off, len, |b| Ok(b.to_vec())).unwrap()
        },
        3,
        Some(t.store_secret()),
    )
    .unwrap();
    assert_eq!(full.1.len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_outs_by_range_batch_skips_extend_when_need_in_first_page() {
    let dir = tempfile_dir("range-need-first-page");
    let t = create_tiny(&dir);
    let mut txid = [0u8; 32];
    txid[0] = 0x5a;
    let n_out = 80u32;
    let tx = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: n_out,
    };
    let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let mut outputs = Vec::with_capacity(n_out as usize);
    outputs.push(OutputRecord::unspent(1, vec![0x51]));
    for _ in 1..n_out {
        outputs.push(OutputRecord::unspent(1, vec![0x51; 64]));
    }
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outputs)], true)
        .unwrap()[0];
    let range = t.body_range(fk).unwrap();
    assert!(range.1 > 4096);
    let (rows, _, _, extend_n, _, guess_full_n) = t
        .get_outs_by_range_batch(&[(fk, range, txid, 80, vec![0])])
        .unwrap();
    assert_eq!(extend_n, 0);
    assert_eq!(guess_full_n, 0);
    let (got, live, sparse) = rows[0].as_ref().expect("range denserels");
    assert_eq!(got.txid, txid);
    assert_eq!(got.input_count, 0, "range pin does not read input.loc");
    assert_eq!(t.get_meta_and_outputs(fk).unwrap().0.input_count, 1);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 0);
    assert_eq!(sparse.len(), 1);
    let (_, _, _, extend_all, _, guess_all) = t
        .get_outs_by_range_batch(&[(fk, range, txid, 80, vec![])])
        .unwrap();
    assert_eq!(extend_all, 0);
    assert_eq!(guess_all, 1);
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
    let mut keys = [b, a];
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
        assert_eq!(t.probe_body_match_fk(&r.txid).unwrap(), Some(*fk));
    }
    let _ = std::fs::remove_dir_all(&dir);
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
        let t = TxTable::open_tiny(&dir).unwrap();
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
        let t = TxTable::open_tiny(&dir).unwrap();
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
            assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)), "fk {i}");
        }
        for i in 16..=20u64 {
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(
                t.probe_body_match_fk(&txid).unwrap(),
                None,
                "truncated fk {i}"
            );
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
    t.put_spends_on_create_at(&spenders, off, len, &[(0, s1, 0), (2, Fk(20), 1)])
        .unwrap();
    let metas = t
        .get_output_spender_metas_at(off, len, &[0, 1, 2, 99])
        .unwrap();
    assert_eq!(metas.len(), 3);
    assert!(!metas[0].1 && metas[0].2 == s1 && metas[0].3 == 0);
    assert!(!metas[1].1 && metas[1].2.is_null());
    assert!(!metas[2].1 && metas[2].2 == Fk(20) && metas[2].3 == 1);

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
        bulk[0].map(|(f, fl, _vin)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((s1, false))
    );
    assert_eq!(
        bulk[1].map(|(f, fl, _vin)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((Fk::NULL, false))
    );
    assert_eq!(
        bulk[2].map(|(f, fl, _vin)| (f, fl & output_flags::MULTI_SPENDER != 0)),
        Some((Fk(20), false))
    );
    // Both backends must agree.
    let mmap = t
        .get_spender_meta_at_abs_batch_backend(&abs, crate::io_backend::ReadIoBackend::Pread)
        .unwrap();
    let uring = t
        .get_spender_meta_at_abs_batch_backend(&abs, crate::io_backend::ReadIoBackend::Uring)
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
    t.put_spends_on_create_at(&spenders, off, len, &[(0, s1, 4), (2, s2, 5)])
        .unwrap();
    let (m0, f0, v0) = t.get_output_spender_meta_at(off, len, 0).unwrap();
    let (m2, f2, v2) = t.get_output_spender_meta_at(off, len, 2).unwrap();
    assert!(!m0 && f0 == s1 && v0 == 4);
    assert!(!m2 && f2 == s2 && v2 == 5);
    let (m1, f1, v1) = t.get_output_spender_meta_at(off, len, 1).unwrap();
    assert!(!m1 && f1.is_null() && v1 == 0);
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
    assert!(dec.create_fk.is_null());
    assert_eq!(dec.prev_index, 0);
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
    assert_eq!(
        enc,
        vec![
            input_flags::PREV_ON_INPUTS
                | input_flags::SEQ_FINAL
                | input_flags::EMPTY_SCRIPT
                | input_flags::EMPTY_WITNESS
        ]
    );
    let dec = InputRecord::decode(&enc).unwrap();
    assert_eq!(dec.sequence, rec.sequence);
    assert!(dec.script_sig.is_empty());
    assert!(dec.witness.is_empty());
    assert!(dec.create_fk.is_null());
    assert_eq!(dec.prev_index, 0);
}

#[test]
fn input_rejects_legacy_local_prev() {
    // flags: LOCAL_PREV | SEQ_FINAL | EMPTY_SCRIPT | EMPTY_WITNESS
    let flags = input_flags::PREV_ON_INPUTS
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
    let mut dec = decode_input_run(&enc, 3).unwrap();
    assert_eq!(dec.len(), 3);
    assert!(!dec[0].is_coinbase());
    assert!(dec[1].create_fk.is_null());
    assert_eq!(dec[1].witness, vec![vec![0xab]]);
    assert_eq!(dec[1].prev_txid, [0u8; 32]);
    let edges = [
        crate::input::InputEdge::coinbase(),
        crate::input::InputEdge {
            parent: Fk(1),
            vout: 0,
        },
        crate::input::InputEdge {
            parent: Fk(1),
            vout: 3,
        },
    ];
    apply_input_edges(&mut dec, &edges).unwrap();
    assert!(dec[0].is_coinbase());
    assert_eq!(dec[1].create_fk, Fk(1));
    assert_eq!(dec[1].prev_index, 0);
    assert_eq!(dec[2].create_fk, Fk(1));
    assert_eq!(dec[2].prev_index, 3);
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
fn output_1btc_uses_exp_nibble_and_uleb_mantissa() {
    let rec = OutputRecord::unspent(100_000_000, vec![0x51]);
    let enc = rec.encode();
    assert_eq!(enc[0] & 0x0f, SCRIPT_KIND_V17_OP_TRUE);
    assert_eq!(enc[0] >> 4, 8);
    assert_eq!(enc[1], 1);
    assert_eq!(enc.len(), 2);
    assert_eq!(OutputRecord::decode(&enc).unwrap().value, 100_000_000);
    assert_eq!(OutputRecord::skip_at(&enc).unwrap(), enc.len());
    assert_eq!(rec.encoded_len_exact(), enc.len());
}

#[test]
fn output_messy_546_keeps_zero_exp() {
    let rec = OutputRecord::unspent(546, vec![0x51]);
    let enc = rec.encode();
    assert_eq!(enc[0] >> 4, 0);
    let (v, n) = read_uleb128(&enc[1..]).unwrap();
    assert_eq!(v, 546);
    assert_eq!(n + 1, enc.len());
    assert_eq!(OutputRecord::decode(&enc).unwrap().value, 546);
}

#[test]
fn output_zero_and_50btc_exp() {
    let zero = OutputRecord::unspent(0, vec![0x51]).encode();
    assert_eq!(zero[0] >> 4, 0);
    assert_eq!(zero[1], 0);
    assert_eq!(OutputRecord::decode(&zero).unwrap().value, 0);

    let rec = OutputRecord::unspent(5_000_000_000, vec![0x51]);
    let enc = rec.encode();
    assert_eq!(enc[0] >> 4, 9);
    assert_eq!(enc[1], 5);
    assert_eq!(OutputRecord::decode(&enc).unwrap().value, 5_000_000_000);
}

#[test]
fn output_live_utxo_mantissa_stays_one_byte() {
    for (sats, exp, mantissa) in [
        (330, 1u8, 33u8),
        (1_250_000_000, 7, 125),
        (2_500_000_000, 8, 25),
    ] {
        let rec = OutputRecord::unspent(sats, vec![0x51]);
        let enc = rec.encode();
        assert_eq!(enc[0] >> 4, exp, "{sats}");
        assert_eq!(enc[1], mantissa, "{sats}");
        assert_eq!(enc.len(), 2, "{sats}");
        assert_eq!(OutputRecord::decode(&enc).unwrap().value, sats);
        assert_eq!(rec.encoded_len_exact(), enc.len());
    }
}

#[test]
fn output_exp_nibble_10_is_corrupt() {
    let mut enc = OutputRecord::unspent(1, vec![0x51]).encode();
    enc[0] = SCRIPT_KIND_V17_OP_TRUE | (10 << 4);
    let err = OutputRecord::decode(&enc).unwrap_err();
    assert!(format!("{err}").contains("amount exp"), "{err}");
    let skip = OutputRecord::skip_at(&enc).unwrap_err();
    assert!(format!("{skip}").contains("amount exp"), "{skip}");
}

#[test]
fn output_negative_value_is_corrupt() {
    let rec = OutputRecord::unspent(-1, vec![0x51]);
    let err = rec.try_encode_into(&mut Vec::new()).unwrap_err();
    assert!(format!("{err}").contains("txout amount negative"), "{err}");
}

#[test]
fn put_full_batch_from_pins_negative_value_is_corrupt() {
    let dir = tempfile_dir("from-pins-neg");
    let t = create_tiny(&dir);
    let tx = TxRecord {
        txid: [9u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let outs = vec![OutputRecord::unspent(-1, vec![0x51])];
    let pin = std::sync::Arc::new((tx, outs));
    let err = t
        .put_full_batch_from_pins(&[(pin, ins)], true, &[])
        .unwrap_err();
    assert!(format!("{err}").contains("txout amount negative"), "{err}");
    assert_eq!(t.count(), 0, "negative pin append must not write Class A");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn output_noncanonical_mantissa_is_corrupt() {
    let mut enc = Vec::new();
    enc.push(SCRIPT_KIND_V17_OP_TRUE | (1 << 4));
    write_uleb128(&mut enc, 10);
    let err = OutputRecord::decode(&enc).unwrap_err();
    assert!(format!("{err}").contains("amount exp"), "{err}");
    let skip = OutputRecord::skip_at(&enc).unwrap_err();
    assert!(format!("{skip}").contains("amount exp"), "{skip}");
}

#[test]
fn skip_at_overflow_amount_is_corrupt() {
    let mut raw = Vec::new();
    raw.push(SCRIPT_KIND_V17_OP_TRUE);
    write_uleb128(&mut raw, i64::MAX as u64 + 1);
    let err = OutputRecord::skip_at(&raw).unwrap_err();
    assert!(format!("{err}").contains("output value too large"), "{err}");

    let mut scaled = Vec::new();
    scaled.push(SCRIPT_KIND_V17_OP_TRUE | (9 << 4));
    write_uleb128(&mut scaled, i64::MAX as u64 / 1_000_000_000 + 1);
    let err = OutputRecord::skip_at(&scaled).unwrap_err();
    assert!(format!("{err}").contains("output value too large"), "{err}");
    let dec = OutputRecord::decode(&scaled).unwrap_err();
    assert!(format!("{dec}").contains("output value too large"), "{dec}");
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
        output_count: 0,
    };
    let enc = rec.encode();
    assert!(enc.len() > 32, "txid + thin meta");
    let mut got = TxRecord::decode(&enc).unwrap();
    assert_eq!(got.input_count, 0, "encode omits n_in");
    got.input_count = rec.input_count;
    assert_eq!(got, rec);
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
    assert!(TxRecord::decode_body_meta(&enc).is_ok());
    assert!(enc.len() >= 3, "thin LAYOUT17 meta");
    let (dtx, douts, _) = decode_packed_tx_outs_with_spender_rels(&enc, 2).unwrap();
    assert_eq!(dtx.txid, [0u8; 32], "body decode leaves txid zero");
    assert_eq!(dtx.input_count, 0, "txout meta omits n_in");
    assert_eq!(dtx.output_count, 2);
    assert!(dtx.input_start_fk.get().is_none());
    let mut seqsigwit = Vec::new();
    encode_seqsigwit_with_secret(&inputs, &mut seqsigwit, None);
    let dins = decode_seqsigwit_secret(&seqsigwit, tx.input_count, None).unwrap();
    assert_eq!(dins[0].script_sig, inputs[0].script_sig);
    assert_eq!(dins[0].sequence, inputs[0].sequence);
    assert_eq!(dins[0].witness, inputs[0].witness);
    assert_eq!(douts, outputs);
}

#[test]
fn seqsigwit_and_txout_secret_xor_roundtrip() {
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
    let mut seqsigwit = Vec::new();
    encode_seqsigwit_with_secret(&inputs, &mut seqsigwit, Some(&secret));
    assert_ne!(seqsigwit, {
        let mut plain = Vec::new();
        encode_seqsigwit_with_secret(&inputs, &mut plain, None);
        plain
    });
    let (dtx, douts, _) = decode_packed_tx_outs_with_spender_rels(&txout, 1).unwrap();
    // Without secret, script stays obfuscated.
    assert_ne!(douts[0].script, outputs[0].script);
    assert_eq!(dtx.input_count, 0, "txout meta omits n_in");
    let (dtx2, douts2, _) =
        decode_packed_tx_outs_with_spender_rels_secret(&txout, 1, Some(&secret)).unwrap();
    assert_eq!(dtx2.input_count, 0, "txout meta omits n_in");
    assert_eq!(douts2[0].script, outputs[0].script);
    let dins = decode_seqsigwit_secret(&seqsigwit, tx.input_count, Some(&secret)).unwrap();
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
        decode_packed_tx_outs_with_spender_rels_secret(&raw, 3, Some(&secret)).unwrap();
    let expect: Vec<[u8; 32]> = decoded
        .iter()
        .map(|o| crate::scripthash::script_hash(&o.script))
        .collect();
    let mut got = Vec::new();
    visit_packed_script_hashes(&raw, 3, Some(&secret), |h| {
        got.push(h);
        Ok(())
    })
    .unwrap();
    assert_eq!(got, expect);
}

#[test]
fn short_or_truncated_packed_body_rejected() {
    assert!(TxRecord::decode_body_meta(&[]).is_err());
    assert!(TxRecord::decode_body_meta(&[0u8; 15]).is_err());
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&[0u8; 15], 1),
        Err(StoreError::Corrupt(_))
    ));
    // v17 empty meta (0 in) is valid; loc n_out 0 is Corrupt.
    let empty = rec_meta(1, 0, 0, 0);
    let mut empty_raw = Vec::new();
    empty.encode_body_meta_into(&mut empty_raw);
    assert!(TxRecord::decode_body_meta(&empty_raw).is_ok());
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&empty_raw, 0),
        Err(StoreError::Corrupt(_))
    ));
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
    assert!(TxRecord::decode_body_meta(&raw).is_ok());
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&raw, 1),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&raw, 1),
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

/// Dense encode/decode + error-arm coverage for packed Class A helpers.
#[allow(clippy::cognitive_complexity)] // one fixture, many error arms
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
        assert!(d.create_fk.is_null());
        assert_eq!(d.prev_index, 0);
        assert_eq!(d.sequence, r.sequence);
        assert_eq!(d.script_sig, r.script_sig);
        assert_eq!(d.witness, r.witness);
        assert!(matches!(
            InputRecord::decode_prevout_at(&e),
            Err(StoreError::Corrupt("seqsigwit prevout is on inputs"))
        ));
        assert_eq!(r.encoded_len_exact(), e.len());
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
    // PREV_ON_INPUTS without a sequence payload is truncated.
    assert!(matches!(
        InputRecord::decode_at(&[input_flags::PREV_ON_INPUTS]),
        Err(StoreError::Corrupt(_))
    ));
    // Hostile CompactSize must be Corrupt, not a capacity or add overflow panic.
    let flags = input_flags::PREV_ON_INPUTS | input_flags::SEQ_FINAL;
    let mut huge_script = vec![flags];
    huge_script.push(0xff);
    huge_script.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        matches!(
            InputRecord::decode_at(&huge_script),
            Err(StoreError::Corrupt(_))
        ),
        "hostile script length"
    );
    let mut huge_wit = vec![flags | input_flags::EMPTY_SCRIPT];
    huge_wit.push(0xff);
    huge_wit.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        matches!(
            InputRecord::decode_at(&huge_wit),
            Err(StoreError::Corrupt(_))
        ),
        "hostile witness count"
    );
    assert!(matches!(
        InputRecord::decode_prevout_at(&[input_flags::PREV_ON_INPUTS]),
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
    assert!(TxRecord::decode_body_meta(&raw).is_ok());
    assert!(TxRecord::decode_body_meta(&[]).is_err());
    assert!(TxRecord::decode_body_meta(&[0u8; 15]).is_err());
    assert!(TxRecord::decode_body_meta(&[0u8; 20]).is_err());
    assert!(TxRecord::decode_body_meta(&[0u8; 64]).is_err());
    let (m, outs, _) = decode_packed_tx_outs_with_spender_rels(&raw, 2).unwrap();
    assert_eq!(m.txid, [0u8; 32], "body decode: no leading txid");
    assert_eq!(m.input_start_fk, Fk::NULL);
    assert_eq!(outs.len(), 2);
    let (m2, _) = TxRecord::decode_body_meta(&raw).unwrap();
    assert_eq!(m2.txid, [0u8; 32]);
    let mut seqsigwit = Vec::new();
    encode_seqsigwit_with_secret(&inputs, &mut seqsigwit, None);
    assert!(matches!(
        scan_seqsigwit_prevouts(&seqsigwit, tx.input_count),
        Err(StoreError::Corrupt("seqsigwit prevout is on inputs"))
    ));
    let (m4, outs_rels, rels) = decode_packed_tx_outs_with_spender_rels(&raw, 2).unwrap();
    assert_eq!(m4.txid, [0u8; 32]);
    assert_eq!(outs_rels.len(), 2);
    assert_eq!(rels.len(), 2);
    // spender fields cleared
    assert!(outs_rels.iter().all(|o| o.spender_field.is_null()));
    let mut cleared = outs.clone();
    cleared[0].spender_field = Fk(9);
    cleared[0].multi_spender = true;
    cleared[0].spender_field = Fk::NULL;
    cleared[0].multi_spender = false;
    assert!(cleared[0].spender_field.is_null());
    assert!(!cleared[0].multi_spender);

    // Packed error arms (short / truncated)
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&[0x02, 0, 0], 1),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&[0x01], 1),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        TxRecord::decode_body_meta(&[0x02]),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&[0x01], 1),
        Err(StoreError::Corrupt(_))
    ));
    // trailing zero pad is accepted (schema 11 alignment gap)
    let mut trail_z = raw.clone();
    trail_z.extend_from_slice(&[0u8; 7]);
    let (mz, _, _) = decode_packed_tx_outs_with_spender_rels(&trail_z, 2).unwrap();
    assert_eq!(mz.txid, [0u8; 32]);
    // non-zero trailing garbage is rejected
    let mut trail = raw.clone();
    trail.push(0x01);
    assert!(matches!(
        decode_packed_tx_outs_with_spender_rels(&trail, 2),
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
        bad.extend(std::iter::repeat_n(0xff, 10));
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
    // packed outs short / trailing on outs_with_spender (loc n_out is the count)
    {
        let tx = TxRecord {
            txid: [0xcd; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 2,
        };
        let inputs = [InputRecord::coinbase(u32::MAX, vec![], vec![])];
        let outputs = [OutputRecord::unspent(1, vec![0x51])];
        let mut raw = Vec::new();
        tx.encode_body_meta_into(&mut raw);
        encode_input_run_secret(&inputs, &mut raw, None);
        encode_output_run_secret(&outputs, &mut raw, None);
        // ends after 1 output but meta says 2
        assert!(matches!(
            decode_packed_tx_outs_with_spender_rels(&raw, 2),
            Err(StoreError::Corrupt(_))
        ));
        // short scan
        assert!(matches!(
            TxRecord::decode_body_meta(&[0u8; 8]),
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
            decode_packed_tx_outs_with_spender_rels(&trail, 1),
            Err(StoreError::Corrupt(_))
        ));
        // zero pad accepted on outs path
        let mut zpad = good.clone();
        zpad.extend_from_slice(&[0u8; 5]);
        let (m, outs, _) = decode_packed_tx_outs_with_spender_rels(&zpad, 1).unwrap();
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
        let (off, len) = t.body_range(*fk).unwrap();
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
        t.body
            .read_prefix_at_published(t.body.body_published_len(), off, len, &mut prefix)
            .unwrap();
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
        let (off, _) = t.body_range(*fk).unwrap();
        assert_eq!(off % 8, 0);
        assert_eq!(t.body_txid(*fk).unwrap(), more[j].0.txid);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn span_prevouts_match_per_create() {
    let dir = tempfile_dir("span-prevouts");
    let t = create_tiny(&dir);
    let mut items = Vec::with_capacity(1025);
    items.push((
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(50, vec![0x51])],
    ));
    for i in 1u32..1024 {
        let mut txid = [2u8; 32];
        txid[0..4].copy_from_slice(&i.to_le_bytes());
        items.push((
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk(1),
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
    }
    items.push((
        TxRecord {
            txid: [9u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 2,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![
            InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk(1),
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            },
            InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk(2),
                prev_index: 0,
                sequence: 1,
                script_sig: vec![0xaa],
                witness: vec![vec![0xbb]],
            },
        ],
        vec![OutputRecord::unspent(2, vec![0x51])],
    ));
    let fks = t.put_full_batch_indexed(&items, true).unwrap();
    let first = fks[0].get().unwrap();
    let last = fks[1024].get().unwrap();
    let span = t.get_full_span(first, last).unwrap();
    assert!(span[0].1[0].is_coinbase());
    assert_eq!(span[1024].1[0].create_fk, Fk(1));
    assert_eq!(span[1024].1[1].create_fk, Fk(2));
    assert_eq!(span[1024].1[1].prev_index, 0);
    let one = t.get_full(fks[1024]).unwrap();
    assert_eq!(span[1024].1, one.1);
    let mid = t.get_full_span(2, 2).unwrap();
    assert_eq!(mid.len(), 1);
    assert_eq!(mid[0].1.len(), 1);
    assert_eq!(mid[0].1[0].create_fk, Fk(1));
    let tail = t.get_full_span(1025, 1025).unwrap();
    assert_eq!(tail[0].1.len(), 2);
    assert_eq!(tail[0].1[1].create_fk, Fk(2));
    assert_eq!(tail[0].1, t.get_full(Fk(1025)).unwrap().1);
    let early = t.get_full_span(1, 2).unwrap();
    assert_eq!(early.len(), 2);
    assert!(early[0].1[0].is_coinbase());
    assert_eq!(early[1].1[0].create_fk, Fk(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_full_span_matches_per_fk_get_full() {
    let dir = tempfile_dir("span-vs-full");
    let t = create_tiny(&dir);
    let mut items = Vec::new();
    for i in 0u8..3 {
        let mut txid = [0u8; 32];
        txid[0] = i.saturating_add(1);
        items.push((
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(
                u32::MAX,
                vec![i],
                vec![vec![0x51, i]],
            )],
            vec![OutputRecord::unspent(100 + i as i64, vec![0x51])],
        ));
    }
    let fks = t.put_full_batch_indexed(&items, true).unwrap();
    let first = fks[0].get().unwrap();
    let last = fks[2].get().unwrap();
    let span = t.get_full_span(first, last).unwrap();
    assert_eq!(span.len(), 3);
    for (fk, got) in fks.iter().zip(span.iter()) {
        let one = t.get_full(*fk).unwrap();
        assert_eq!(got.0, one.0);
        assert_eq!(got.1, one.1);
        assert_eq!(got.2, one.2);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pread_two_spans_parallel_matches_serial() {
    let dir = tempfile_dir("span-pair");
    let t = create_tiny(&dir);
    let mut items = Vec::new();
    for i in 0u8..4 {
        let mut txid = [0u8; 32];
        txid[0] = i.saturating_add(9);
        items.push((
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x02, i], vec![])],
            vec![OutputRecord::unspent(i as i64 + 1, vec![0x00, i])],
        ));
    }
    let fks = t.put_full_batch_indexed(&items, true).unwrap();
    let first = fks[0].get().unwrap();
    let last = fks[3].get().unwrap();
    let txout_ranges = t.body_ranges(first, last).unwrap();
    let seqsigwit_fks: Vec<Fk> = (first..=last).map(Fk).collect();
    let seqsigwit_pairs = t.seqsigwit_loc.range_batch(&seqsigwit_fks).unwrap();
    let seqsigwit_ranges: Vec<(u64, u64)> = seqsigwit_pairs
        .into_iter()
        .map(|p| p.expect("seqsigwit range"))
        .collect();
    let (t0, _) = txout_ranges[0];
    let (tn, tln) = *txout_ranges.last().unwrap();
    let tspan = tn + tln - t0;
    let (i0, _) = seqsigwit_ranges[0];
    let (inn, iln) = *seqsigwit_ranges.last().unwrap();
    let ispan = inn + iln - i0;
    let serial = pread_two_spans(&t.body, t0, tspan, &t.seqsigwit, i0, ispan, false).unwrap();
    let parallel = pread_two_spans(&t.body, t0, tspan, &t.seqsigwit, i0, ispan, true).unwrap();
    assert_eq!(serial, parallel);
    assert!(!serial.0.is_empty());
    assert!(!serial.1.is_empty());
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
    let hit = t.probe_body_match_fk(&shared).unwrap();
    assert_eq!(hit, Some(fks[1]), "newest same-txid create");
    let all = t.fks_by_txid(&shared).unwrap();
    assert_eq!(all.len(), 2, "both BIP30 creates body-verify");
    assert_eq!(all[0], fks[1]);
    assert_eq!(all[1], fks[0]);
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
        t.flush().unwrap();
    }
    // Reopen: keys are not retained; seal collects from Class A.
    let t = TxTable::open_tiny(&dir).unwrap();
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
            t.probe_body_match_fk(&txid).unwrap(),
            Some(Fk(i)),
            "pre-reopen fk={i} FN after seal"
        );
    }
    for i in [401u64, 820, 900] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)), "fk={i}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mainnet 963556 (reardencode/rbitcoin#843): two confirm writes appended
/// their bodies and then rejected on the planned-fk check, so Class A held
/// 9,506 bodies the head never received. The segment rolled on entry count,
/// the seal re-read a range that included those orphans, and the last 9,506
/// real entries were dropped with the OA. Here: 10 orphan bodies, drain across
/// a roll, then every indexed txid must resolve before and after reopen.
#[test]
fn orphan_class_a_bodies_do_not_drop_head_entries_at_seal() {
    let dir = tempfile_dir("orphan-gap-seal");
    // 8-bit: max_keys = floor(0.8*256) = 204.
    let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
    let rec = |i: u64| {
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
    };
    let orphan = |fk: u64| (51..=60).contains(&fk);
    let check = |t: &TxTable, when: &str| {
        let mut lost = Vec::new();
        for fk in (1..=301u64).filter(|fk| !orphan(*fk)) {
            if t.probe_body_match_fk(&rec(fk).txid).unwrap() != Some(Fk(fk)) {
                lost.push(fk);
            }
        }
        assert!(
            lost.is_empty(),
            "{when}: head lost {} entries: {lost:?}",
            lost.len()
        );
    };
    {
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        let recs: Vec<TxRecord> = (1..=300).map(rec).collect();
        let fks = t
            .put_full_batch_indexed(&meta_only_items(&recs), /*index=*/ false)
            .unwrap();
        assert_eq!(fks.first(), Some(&Fk(1)));
        // The rejected writes never queued their head entries.
        let pending: Vec<([u8; 32], Fk)> = recs
            .iter()
            .zip(fks.iter())
            .filter(|(_, fk)| !orphan(fk.0))
            .map(|(r, fk)| (r.txid, *fk))
            .collect();
        t.flush().unwrap();
        t.head_note_pending(&pending);
        t.head_drain_pending().unwrap();
        // One more create publishes the finished seal (OA unlinked).
        let tail = t
            .put_full_batch_indexed(&meta_only_items(&[rec(301)]), false)
            .unwrap();
        t.head_note_pending(&[(rec(301).txid, tail[0])]);
        t.flush().unwrap();
        t.head_drain_pending().unwrap();
        t.flush_head().unwrap();
        assert!(
            t.head.sealed_segment_count() >= 1,
            "segment 0 must have sealed"
        );
        check(&t, "live");
        assert_eq!(
            t.head.last_inserted_fk(),
            301,
            "coverage must reach the last fk"
        );
        t.flush().unwrap();
    }
    let t = TxTable::open_tiny(&dir).unwrap();
    check(&t, "reopen");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Insert does not retain fuse keys; seal still membership-tests from Class A.
#[test]
fn seal_without_retained_keys_matches_fuse_contains() {
    let dir = tempfile_dir("seal-no-retain-keys");
    let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
    let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
    let recs: Vec<TxRecord> = (0..205u64)
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
    t.flush_head().unwrap();
    assert!(t.head.sealed_segment_count() >= 1);
    for i in [1u64, 50, 204, 205] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            t.probe_body_match_fk(&txid).unwrap(),
            Some(Fk(i)),
            "fk={i} after seal without retained keys"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fat Class A bodies must not roll `tx.head` (OA 80% is the only head cut).
#[test]
fn fat_creates_do_not_roll_head() {
    with_env_lock(|| {
        let dir = tempfile_dir("no-body-span-roll");
        let layout = HeadLayout::with_entry_bytes(14, 4).unwrap();
        let t = TxTable::create_with_head_layout_opts(&dir, layout, HeadOpenOpts::TINY).unwrap();
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
        {
            for i in 1..=12u64 {
                t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            t.flush_head().unwrap();
            assert_eq!(
                t.head.sealed_segment_count(),
                0,
                "fat Class A bodies must not seal tx.head segs={}",
                t.head_segment_count()
            );
            assert_eq!(t.head_segment_count(), 1);
            for i in [1u64, 6, 9, 12] {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&i.to_le_bytes());
                assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)));
            }
        }
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
        let fk = t.probe_body_match_fk(&txid).unwrap();
        assert_eq!(fk, Some(Fk(i)), "i={i}");
    }
    // miss (must not collide with LE u64 ids 1..=820)
    let miss = [0xAAu8; 32];
    assert_eq!(t.probe_body_match_fk(&miss).unwrap(), None);
    t.flush().unwrap();
    let t2 = TxTable::open_tiny(&dir).unwrap();
    for i in [1u64, 500, 820] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t2.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)));
    }
    // twice
    assert_eq!(
        t2.probe_body_match_fk(&{
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
    {
        {
            let dir = tempfile_dir("empty-occ-rebuild");
            let layout = crate::address_head::default_layout(HeadScale::Tiny);
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
            let t = open_tiny_rebuild(&dir, 6, 2);
            assert!(
                t.head.sealed_segment_count() >= 2,
                "empty occupancy must full-rebuild, sealed={}",
                t.head.sealed_segment_count()
            );
            assert!(!dir.join("tx.head").join("000000").is_file());
            let mut txid = [0u8; 32];
            txid[0..8].copy_from_slice(&65u64.to_le_bytes());
            assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(65)));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[test]
fn rebuild_head_direct_mphf_empty_tail() {
    {
        {
            let dir = tempfile_dir("rebuild-direct-mphf");
            {
                let t = create_tiny_rebuild(&dir, 6, 2);
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
            let t = open_tiny_rebuild(&dir, 6, 2);
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
            for i in [1u64, 64, 65] {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&i.to_le_bytes());
                assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)), "fk={i}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// `(stage, done, total)` of the stages that ended on this thread since
/// `capture_finished(true)`; turns capture off.
fn finished_stages() -> Vec<(&'static str, u64, u64)> {
    let fin = rbitcoin_log::progress::take_finished()
        .into_iter()
        .map(|p| (p.stage, p.done, p.total))
        .collect();
    rbitcoin_log::progress::capture_finished(false);
    fin
}

/// The rebuild counts sealed ranges into the live progress registry as the
/// workers finish (its `on_progress` only runs after all of them), and the
/// stage ends with the call.
#[test]
fn rebuild_head_reports_live_progress() {
    let dir = tempfile_dir("rebuild-progress");
    let t = create_tiny_rebuild(&dir, 6, 2);
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
    rbitcoin_log::progress::capture_finished(true);
    t.rebuild_head_from_bodies(|_, _, _| {}).unwrap();
    let fin = finished_stages();
    // `on_progress` runs only after every range seals; the count comes from
    // the workers.
    assert_eq!(fin, [("tx.head rebuild", 65, 65)]);
    for i in [1u64, 64, 65] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(t.probe_body_match_fk(&txid).unwrap(), Some(Fk(i)), "fk={i}");
    }
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A range that fails leaves the ranges that sealed before it counted: the
/// stage ends short of its total, not at 0. T=64, n=65: range 1 is fks 1..=64,
/// range 2 is fk 65, whose txid the truncated identity file no longer has.
#[test]
fn rebuild_head_failure_keeps_sealed_ranges_counted() {
    let dir = tempfile_dir("rebuild-progress-fail");
    let t = create_tiny_rebuild(&dir, 6, 2);
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
    t.txid_sidefile().truncate_to_count(64).unwrap();
    rbitcoin_log::progress::capture_finished(true);
    let r = t.rebuild_head_from_bodies(|_, _, _| {});
    let fin = finished_stages();
    assert!(r.is_err(), "fk 65 has no txid");
    assert_eq!(fin, [("tx.head rebuild", 64, 65)]);
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rebuild_head_direct_mphf_bip30_newest_first() {
    {
        {
            let dir = tempfile_dir("rebuild-direct-bip30");
            {
                let t = create_tiny_rebuild(&dir, 6, 2);
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
            let t = open_tiny_rebuild(&dir, 6, 2);
            let mut shared = [0u8; 32];
            shared[0..8].copy_from_slice(&1u64.to_le_bytes());
            let all = t.fks_by_txid(&shared).unwrap();
            assert_eq!(all.len(), 2, "both BIP30 creates");
            assert_eq!(all[0], Fk(2), "newest first {all:?}");
            assert_eq!(all[1], Fk(1));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
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
    assert_eq!(t.count(), 200);
    assert_eq!(
        plan_rebuild_ranges(t.count(), 6),
        vec![(1, 64), (65, 64), (129, 64), (193, 8)],
        "bits=6 → T=64"
    );
    assert_eq!(
        plan_rebuild_ranges(t.count(), 7),
        vec![(1, 128), (129, 72)],
        "bits=7 → T=128 (knob is seal bits, not OA 80%)"
    );
    let t6 = create_tiny_rebuild(&tempfile_dir("plan-seal-bits-6"), 6, 1);
    assert_eq!(t6.rebuild_seal_bits(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plan_head_rebuild_ranges_ignores_body_soft_span() {
    {
        let dir = tempfile_dir("plan-no-body-span");
        let t = TxTable::create_with_head_layout_opts(
            &dir,
            tiny_layout(),
            HeadOpenOpts::TINY.with_rebuild_seal_bits(8),
        )
        .unwrap();
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
        {
            for i in 1..=6u64 {
                t.put_full_batch_indexed(&[mk(i)], true).unwrap();
            }
            let ranges = t.plan_head_rebuild_ranges().unwrap();
            assert_eq!(
                ranges,
                vec![(1, 6)],
                "rebuild cuts are 2^bits only, not body span, ranges={ranges:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
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
fn rebuild_opts_are_per_table() {
    let dir_a = tempfile_dir("rebuild-opts-a");
    let dir_b = tempfile_dir("rebuild-opts-b");
    let a = create_tiny_rebuild(&dir_a, 6, 3);
    let b = create_tiny_rebuild(&dir_b, 7, 4);
    assert_eq!(a.rebuild_workers(), 3);
    assert_eq!(a.rebuild_seal_bits(), 6);
    assert_eq!(b.rebuild_workers(), 4);
    assert_eq!(b.rebuild_seal_bits(), 7);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn refuse_legacy_mono_head_on_create() {
    let dir = tempfile_dir("legacy-mono");
    std::fs::write(dir.join("tx.head"), b"mono").unwrap();
    let err = TxTable::create_tiny(&dir)
        .err()
        .expect("must refuse mono head");
    let s = format!("{err}");
    assert!(s.contains("legacy") || s.contains("reindex"), "{s}");
    let _ = std::fs::remove_dir_all(&dir);
}

// Crash snapshot: seal worker may unlink OA / `.tmp` between readdir and copy.
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    let rd = match std::fs::read_dir(src) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("read_dir {src:?}: {e}"),
    };
    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => panic!("read_dir entry {src:?}: {e}"),
        };
        let name = ent.file_name();
        if name.to_string_lossy().ends_with(".tmp") {
            continue;
        }
        let from = ent.path();
        let to = dst.join(&name);
        let is_dir = match ent.file_type() {
            Ok(t) => t.is_dir(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => panic!("file_type {from:?}: {e}"),
        };
        if is_dir {
            copy_tree(&from, &to);
            continue;
        }
        match std::fs::copy(&from, &to) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("copy {from:?} -> {to:?}: {e}"),
        }
    }
}

/// Kill mid-seal: meta still has an unsealed non-tail OA. Open rebuilds fuse
/// keys from Class A and seals it before returning.
#[test]
fn open_seals_unsealed_nontail_after_copied_roll() {
    let dir = tempfile_dir("bg-seal-live");
    let copy = tempfile_dir("bg-seal-copy");
    {
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
        copy_tree(&dir, &copy);
    }
    let t2 = TxTable::open_tiny(&copy).unwrap();
    assert!(
        t2.head.sealed_segment_count() >= 1,
        "open must rebuild keys and seal leftover nontail"
    );
    for i in [1u64, 100, 204, 205] {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            t2.probe_body_match_fk(&txid).unwrap(),
            Some(Fk(i)),
            "fk={i}"
        );
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
fn body_meta_v17_v1_locktime_zero_is_one_byte() {
    let rec = rec_meta(1, 0, 1, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(
        buf,
        vec![0x89 | BODY_META_V17_N_IN_TXSTAT],
        "LAYOUT17|VER_1|LOCKTIME_ZERO|N_IN_TXSTAT"
    );
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(got.version, 1);
    assert_eq!(got.locktime, 0);
    assert_eq!(got.input_count, 0);
    assert_eq!(got.output_count, 0);
}

#[test]
fn body_meta_v17_v2_locktime_zero() {
    let rec = rec_meta(2, 0, 1, 2);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(
        buf[0],
        0x8A | BODY_META_V17_N_IN_TXSTAT,
        "LAYOUT17|VER_2|LOCKTIME_ZERO|N_IN_TXSTAT"
    );
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(got.version, 2);
    assert_eq!(got.locktime, 0);
    assert_eq!(got.output_count, 0);
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

#[test]
fn decode_body_meta_v17_omitted_n_in() {
    let rec = rec_meta(1, 0, 7, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    assert_eq!(buf, vec![0x89 | BODY_META_V17_N_IN_TXSTAT]);
    let (got, n) = decode_body_meta_v17(&buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(got.version, 1);
    assert_eq!(got.locktime, 0);
    assert_eq!(got.input_count, 0);
}

#[test]
fn decode_body_meta_v17_reserved_bits_still_corrupt() {
    let rec = rec_meta(1, 0, 1, 1);
    let mut buf = Vec::new();
    encode_body_meta_v17(&rec, &mut buf);
    buf[0] |= 0x20;
    match decode_body_meta_v17(&buf) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("reserved"), "{m}");
        }
        other => panic!("expected reserved Corrupt, got {other:?}"),
    }
    buf[0] = (buf[0] & !0x20) | 0x40;
    match decode_body_meta_v17(&buf) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("reserved"), "{m}");
        }
        other => panic!("expected reserved Corrupt, got {other:?}"),
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
    write_compact_size(&mut disk, data.len() as u64);
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
    write_compact_size(&mut expect, script.len() as u64);
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
fn spent_slot_unspent_is_eight_zero_bytes() {
    let slot = encode_spent_slot(0, Fk::NULL, 0).unwrap();
    assert_eq!(slot, [0u8; 8]);
    let (flags, field, vin) = decode_spent_slot(&slot).unwrap();
    assert_eq!(flags, 0);
    assert!(field.is_null());
    assert_eq!(vin, 0);
}

#[test]
fn spent_slot_sole_fk_vin_roundtrip() {
    let fk = Fk(0x0000_0001_0203_0405);
    let slot = encode_spent_slot(0, fk, 0x1122).unwrap();
    assert_eq!(slot[0], 0, "flags first");
    let (flags, field, vin) = decode_spent_slot(&slot).unwrap();
    assert_eq!(flags, 0);
    assert_eq!(field, fk);
    assert_eq!(vin, 0x1122);
}

#[test]
fn spent_slot_multi_list_head_roundtrip_vin_zero() {
    let head = Fk(42);
    let slot = encode_spent_slot(output_flags::MULTI_SPENDER, head, 0).unwrap();
    assert_eq!(slot[0], output_flags::MULTI_SPENDER);
    let (flags, field, vin) = decode_spent_slot(&slot).unwrap();
    assert_eq!(
        flags & output_flags::MULTI_SPENDER,
        output_flags::MULTI_SPENDER
    );
    assert_eq!(field, head);
    assert_eq!(vin, 0);
}

#[test]
fn spent_slot_fk_at_2pow40_is_corrupt() {
    match encode_spent_slot(0, Fk(1u64 << 40), 0) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("40") || m.contains("u40"), "{m}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn spent_slot_vin_at_2pow16_is_corrupt() {
    match encode_spent_slot(0, Fk(1), 1u32 << 16) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("16") || m.contains("u16"), "{m}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn spent_slot_v17_len_constant_is_eight() {
    assert_eq!(OutputRecord::SPENT_SLOT_LEN, 8);
}

#[test]
fn encode_spent_slots_overlays_one_vout() {
    let mut buf = Vec::new();
    encode_spent_slots(3, &[(1, Fk(9), 3)], &mut buf).unwrap();
    assert_eq!(buf.len(), 24);
    let (f0, field0, v0) = decode_spent_slot(&buf[0..8]).unwrap();
    assert_eq!(f0, 0);
    assert!(field0.is_null());
    assert_eq!(v0, 0);
    let (f1, field1, v1) = decode_spent_slot(&buf[8..16]).unwrap();
    assert_eq!(f1, 0);
    assert_eq!(field1, Fk(9));
    assert_eq!(v1, 3);
    let (f2, field2, _v2) = decode_spent_slot(&buf[16..24]).unwrap();
    assert_eq!(f2, 0);
    assert!(field2.is_null());
}

#[test]
fn encode_spent_slots_empty_matches_zeros() {
    let mut a = Vec::new();
    let mut b = Vec::new();
    encode_spent_zeros(4, &mut a);
    encode_spent_slots(4, &[], &mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn encode_spent_slots_vout_oob_is_corrupt() {
    let mut buf = Vec::new();
    match encode_spent_slots(1, &[(1, Fk(2), 0)], &mut buf) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("vout"), "{m}"),
        other => panic!("expected Corrupt vout, got {other:?}"),
    }
}

#[test]
fn encode_spent_slots_duplicate_vout_last_wins() {
    let mut buf = Vec::new();
    encode_spent_slots(1, &[(0, Fk(1), 0), (0, Fk(2), 1)], &mut buf).unwrap();
    assert_eq!(decode_spent_slot(&buf).unwrap().1, Fk(2));
    assert_eq!(decode_spent_slot(&buf).unwrap().2, 1);
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
        let rec = spent_record_len(n_out);
        assert_eq!(rec, buf.len() as u64);
    }
}

#[test]
fn reserved_flag_v17_seqsigwit_high_bits_are_corrupt() {
    let rec = InputRecord::coinbase(u32::MAX, vec![], vec![]);
    let mut raw = rec.encode();
    raw[0] |= 1 << 5;
    match InputRecord::decode_at(&raw) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("reserved") || m.contains("seqsigwit"), "{m}");
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
    match encode_spent_slot(1, Fk::NULL, 0) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("spent") || m.contains("flag"), "{m}");
        }
        other => panic!("expected Corrupt on encode, got {other:?}"),
    }
    let mut slot = encode_spent_slot(output_flags::MULTI_SPENDER, Fk(3), 0).unwrap();
    slot[0] |= 1 << 0;
    match decode_spent_slot(&slot) {
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

/// Fat seqsigwit uses `seqsigwit.loc` (no `{stem}.idx` dirs).
#[test]
fn fat_seqsigwit_uses_delta_loc_not_idx() {
    {
        let dir = tempfile_dir("seqsigwit-loc");
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
        assert!(dir.join("create.loc").is_file());
        assert!(dir.join("seqsigwit.loc").is_file());
        assert!(!dir.join("txout.idx").exists());
        assert!(!dir.join("spent.idx").exists());
        assert!(!dir.join("seqsigwit.idx").exists());
        let last = t.get(Fk(6)).unwrap();
        assert_eq!(last.output_count, 1);
        let (off, len) = t.seqsigwit_range(Fk(6)).unwrap();
        let raw_in = t
            .seqsigwit
            .with_bytes_at(off, len, |b| Ok(b.to_vec()))
            .unwrap();
        assert!(raw_in.len() >= 1800, "len={}", raw_in.len());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn script_hash_collect_span_is_16mib() {
    assert_eq!(SCRIPT_HASH_COLLECT_SPAN, 16 * 1024 * 1024);
}

fn put_n_out(t: &TxTable, tag: u8, n_out: u32) -> Fk {
    let mut txid = [0u8; 32];
    txid[0] = tag;
    let tx = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: n_out,
    };
    let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x51], vec![])];
    let outs: Vec<OutputRecord> = (0..n_out)
        .map(|i| OutputRecord::unspent(1 + i64::from(i), vec![0x51]))
        .collect();
    t.put_full_batch_indexed(&[(tx, inputs, outs)], false)
        .unwrap()[0]
}

#[test]
fn class_a_append_writes_create_loc() {
    let dir = tempfile_dir("create-loc");
    let t = create_tiny(&dir);
    let f1 = put_n_out(&t, 1, 1);
    let f3 = put_n_out(&t, 3, 3);
    assert!(
        dir.join("create.loc").is_file(),
        "create.loc must be created"
    );
    assert!(dir.join("create.off").is_file());
    assert!(!dir.join("spent.idx").exists());
    assert!(!dir.join("txout.idx").exists());
    let (o1, l1) = t.spent_range(f1).unwrap();
    let (o3, l3) = t.spent_range(f3).unwrap();
    assert_eq!(l1, spent_record_len(1));
    assert_eq!(l3, spent_record_len(3));
    assert_eq!(o3, o1 + l1);
    assert_eq!(spent_abs(o3, 2), o3 + 16);
    let batch = t.spent_range_batch(&[f3, f1]).unwrap();
    assert_eq!(batch[0], Some((o3, l3)));
    assert_eq!(batch[1], Some((o1, l1)));
    t.flush().unwrap();
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert!(
        dir.join("create.loc").is_file(),
        "reopen must keep create.loc"
    );
    assert_eq!(t.spent_range(f1).unwrap(), (o1, l1));
    assert_eq!(t.spent_range(f3).unwrap(), (o3, l3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spent_range_uses_loc_not_txout_body() {
    let dir = tempfile_dir("spent-loc-not-body");
    let t = create_tiny(&dir);
    let f1 = put_n_out(&t, 1, 1);
    let f3 = put_n_out(&t, 3, 3);
    let want = t.spent_range_batch(&[f3, f1]).unwrap();
    t.flush().unwrap();
    {
        use crate::file::FILE_HEADER_LEN;
        let p = dir.join("txout.body");
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(FILE_HEADER_LEN as u64).unwrap();
    }
    let got = t.spent_range_batch(&[f3, f1]).unwrap();
    assert_eq!(got, want);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tail backfill starts at the bodies already in tx.head, so `/progress`
/// does not read 0% for the whole tail at open. fk 2's txid is gone, so the
/// stage ends at that start.
#[test]
fn backfill_head_from_starts_at_covered() {
    let dir = tempfile_dir("backfill-head-covered");
    let t = create_tiny(&dir);
    let _ = put_n_out(&t, 1, 1);
    let f2 = put_n_out(&t, 2, 1).get().expect("indexed create fk");
    t.flush().unwrap();
    t.txid_sidefile().truncate_to_count(f2 - 1).unwrap();
    rbitcoin_log::progress::capture_finished(true);
    let r = t.backfill_head_from(f2);
    let fin = finished_stages();
    assert!(r.is_err(), "fk {f2} has no txid");
    assert_eq!(fin, [("tx.head backfill", f2 - 1, f2)]);
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backfill_head_from_empty_and_unindexed() {
    let dir = tempfile_dir("backfill-head");
    let t = create_tiny(&dir);
    assert_eq!(t.backfill_head_from(0).unwrap(), 0);
    assert_eq!(t.backfill_head_from(1).unwrap(), 0);
    let f1 = put_n_out(&t, 1, 1);
    let n = t.count();
    assert_eq!(t.backfill_head_from(n + 1).unwrap(), 0);
    let first = f1.get().expect("indexed create fk");
    rbitcoin_log::progress::capture_finished(true);
    let inserted = t.backfill_head_from(first).unwrap();
    assert_eq!(finished_stages(), [("tx.head backfill", 1, 1)]);
    assert_eq!(inserted, 1);
    let txid = t.body_txid(f1).unwrap();
    let batch = t.get_fk_by_txid_batch(&[txid]).unwrap();
    assert_eq!(batch[0].1.map(|(f, _)| f), Some(f1));
    // A tail past fk 1 counts in Class A's frame: the bodies already in
    // tx.head are done from the start.
    let f2 = put_n_out(&t, 2, 1).get().expect("indexed create fk");
    rbitcoin_log::progress::capture_finished(true);
    assert_eq!(t.backfill_head_from(f2).unwrap(), 1);
    assert_eq!(finished_stages(), [("tx.head backfill", f2, f2)]);
    let _ = std::fs::remove_dir_all(&dir);
}
