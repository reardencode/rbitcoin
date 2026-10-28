use rbitcoin_primitives::Fk;
use rbitcoin_store::create_loc::*;
use rbitcoin_store::delta_loc::IDX_STRIDE;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::IoCtx;
use std::path::Path;

use rbitcoin_store::testutil::TempDir;

fn rec(txout_start: u64, txout_len: u64, spent_start: u64, n_out: u32) -> CreateLocAppend {
    CreateLocAppend {
        txout_start,
        txout_len,
        spent_start,
        n_out,
    }
}

fn chain(n_out: &[u32], txout_len: &[u64]) -> Vec<CreateLocAppend> {
    assert_eq!(n_out.len(), txout_len.len());
    let mut tx = FILE_HEADER_LEN as u64;
    let mut sp = FILE_HEADER_LEN as u64;
    let mut out = Vec::with_capacity(n_out.len());
    for (&n, &tlen) in n_out.iter().zip(txout_len.iter()) {
        out.push(rec(tx, tlen, sp, n));
        tx += tlen;
        sp += u64::from(n) * IDX_STRIDE;
    }
    out
}

fn ovf_data_len(dir: &Path) -> u64 {
    let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
    let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    logical - FILE_HEADER_LEN as u64
}

fn write_legacy_create_ovf_v22(dir: &Path, rows: &[(u64, u16, u16)]) {
    use rbitcoin_primitives::{TableKind, STORE_MAGIC};
    let mut payload = Vec::new();
    for &(fk, st, n) in rows {
        payload.extend_from_slice(&fk.to_le_bytes());
        payload.extend_from_slice(&st.to_le_bytes());
        payload.extend_from_slice(&n.to_le_bytes());
    }
    let logical = FILE_HEADER_LEN as u64 + payload.len() as u64;
    let mut blob = vec![0u8; FILE_HEADER_LEN];
    blob[0..4].copy_from_slice(&STORE_MAGIC);
    blob[4..6].copy_from_slice(&22u16.to_le_bytes());
    blob[6..8].copy_from_slice(&TableKind::DeltaLoc.as_u16().to_le_bytes());
    blob[8..16].copy_from_slice(&logical.to_le_bytes());
    blob.extend_from_slice(&payload);
    std::fs::write(dir.join("create.loc.ovf"), blob).unwrap();
}

/// A checkpoint write that runs out of space must not keep the overflow row
/// from that append. The same batch connects once writes work, including
/// after reopen.
#[test]
fn create_loc_checkpoint_enospc_drops_the_ovf_row() {
    let dir = TempDir::labeled("create-loc-ovf-rewind").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    let mut n_out = vec![1u32; 1024];
    n_out[1023] = 256;
    let batch = chain(&n_out, &vec![8u64; 1024]);
    let off = loc.off.io_handle();
    struct Disarm(rbitcoin_store::io_handle::IoHandle);
    impl Drop for Disarm {
        fn drop(&mut self) {
            rbitcoin_store::io_handle::disarm_pwrite(self.0);
        }
    }
    rbitcoin_store::io_handle::arm_short_pwrite(off);
    let _disarm = Disarm(off);
    let err = loc.append(&batch).expect_err("create.off disk full");
    assert!(matches!(err, StoreError::Io { .. }), "{err}");
    drop(_disarm);
    assert!(
        loc.ovf_rows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "ovf row survived the failed checkpoint"
    );
    assert_eq!(loc.count(), 0);
    loc.append(&batch)
        .expect("retry once the checkpoint write works");
    assert_eq!(loc.count(), 1024);
    let path = dir.path().to_path_buf();
    drop(loc);
    let loc = CreateLoc::open(&path).unwrap();
    assert_eq!(loc.range_batch(&[Fk(1024)]).unwrap()[0].unwrap().n_out, 256);
}

#[test]
fn create_loc_read_past_published_end_is_corrupt() {
    let dir = TempDir::labeled("create-loc-pub").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[1], &[16])).unwrap();
    loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
    match loc.range_batch(&[Fk(1)]) {
        Err(StoreError::Corrupt(msg)) => assert!(msg.contains("published"), "{msg}"),
        Ok(v) => panic!("read past published end returned {v:?}"),
        Err(other) => panic!("{other}"),
    }
}

/// The window pread compares the end `plan_range_batch` paired with
/// `count`. A later publish must not change that integer.
#[test]
fn create_loc_window_read_uses_the_planned_published_end() {
    let dir = TempDir::labeled("create-loc-snap").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[1], &[16])).unwrap();
    let full = loc.loc.logical_len();
    let mut plan = loc.plan_range_batch(&[Fk(1)]).unwrap();
    loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
    loc.pread_windows(&mut IoCtx::none(), &mut plan)
        .expect("in-snapshot window stays readable after a shrink");
    // The short-read fallback must not load `logical_len` again.
    loc.read_planned_windows(&mut plan.windows)
        .expect("planned window pread keeps the snapshot end");
    let got = loc.finish_range_batch(&plan).unwrap();
    assert_eq!(
        got[0],
        Some(CreateLocPair {
            txout: (FILE_HEADER_LEN as u64, 16),
            spent: (FILE_HEADER_LEN as u64, 8),
            n_out: 1,
        })
    );

    loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
    match loc.plan_range_batch(&[Fk(1)]) {
        Err(StoreError::Corrupt(msg)) => assert!(msg.contains("published"), "{msg}"),
        Ok(_) => panic!("a short published end still planned a window"),
        Err(other) => panic!("{other}"),
    }
    loc.loc.set_logical_len(full).unwrap();
    let mut again = loc.plan_range_batch(&[Fk(1)]).unwrap();
    loc.pread_windows(&mut IoCtx::none(), &mut again).unwrap();
    let got = loc.finish_range_batch(&again).unwrap();
    assert_eq!(got[0].unwrap().n_out, 1);
}

#[test]
fn create_loc_n_out_1_and_3() {
    let dir = TempDir::labeled("create-loc-13").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[1, 3], &[16, 32])).unwrap();
    let got = loc.range_batch(&[Fk(1), Fk(2)]).unwrap();
    assert_eq!(
        got[0],
        Some(CreateLocPair {
            txout: (FILE_HEADER_LEN as u64, 16),
            spent: (FILE_HEADER_LEN as u64, 8),
            n_out: 1,
        })
    );
    assert_eq!(
        got[1],
        Some(CreateLocPair {
            txout: (FILE_HEADER_LEN as u64 + 16, 32),
            spent: (FILE_HEADER_LEN as u64 + 8, 24),
            n_out: 3,
        })
    );
    let last = got[1].unwrap();
    assert_eq!(last.txout.0 + last.txout.1, FILE_HEADER_LEN as u64 + 48);
    assert_eq!(last.spent.0 + last.spent.1, FILE_HEADER_LEN as u64 + 32);
}

#[test]
fn create_loc_batch_preserves_caller_order() {
    let dir = TempDir::labeled("create-loc-order").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[1, 1, 1], &[8, 8, 8])).unwrap();
    let got = loc
        .range_batch(&[Fk(3), Fk(1), Fk(2), Fk::NULL, Fk(9)])
        .unwrap();
    assert_eq!(got[0].unwrap().txout.0, FILE_HEADER_LEN as u64 + 16);
    assert_eq!(got[1].unwrap().txout.0, FILE_HEADER_LEN as u64);
    assert_eq!(got[2].unwrap().txout.0, FILE_HEADER_LEN as u64 + 8);
    assert_eq!(got[3], None);
    assert_eq!(got[4], None);
}

#[test]
fn create_loc_window_1024_and_1025() {
    let dir = TempDir::labeled("create-loc-win").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    let n_out = vec![1u32; 1025];
    let lens = vec![8u64; 1025];
    loc.append(&chain(&n_out, &lens)).unwrap();
    assert_eq!(loc.count(), 1025);
    let got = loc.range_batch(&[Fk(1), Fk(1024), Fk(1025)]).unwrap();
    assert_eq!(got[0].unwrap().txout, (FILE_HEADER_LEN as u64, 8));
    assert_eq!(
        got[1].unwrap().txout,
        (FILE_HEADER_LEN as u64 + 1023 * 8, 8)
    );
    assert_eq!(
        got[2].unwrap().txout,
        (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
    );
    assert_eq!(
        got[2].unwrap().spent,
        (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
    );
    drop(loc);
    let loc = CreateLoc::open(dir.path()).unwrap();
    let got = loc.range_batch(&[Fk(1024), Fk(1025)]).unwrap();
    assert_eq!(
        got[0].unwrap().txout,
        (FILE_HEADER_LEN as u64 + 1023 * 8, 8)
    );
    assert_eq!(
        got[1].unwrap().txout,
        (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
    );
}

#[test]
fn create_loc_n_out_zero_append_corrupt() {
    let dir = TempDir::labeled("create-loc-zero").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    match loc.append(&[rec(FILE_HEADER_LEN as u64, 8, FILE_HEADER_LEN as u64, 0)]) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("create n_out"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn create_loc_n_out_256_overflow() {
    let dir = TempDir::labeled("create-loc-256").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[256], &[8])).unwrap();
    let got = loc.range_batch(&[Fk(1)]).unwrap();
    assert_eq!(got[0].unwrap().n_out, 256);
    assert_eq!(got[0].unwrap().spent.1, 256 * 8);
    assert!(dir.path().join("create.loc.ovf").exists());
    drop(loc);
    let loc = CreateLoc::open(dir.path()).unwrap();
    assert_eq!(loc.range_batch(&[Fk(1)]).unwrap()[0].unwrap().n_out, 256);
}

#[test]
fn create_loc_fat_txout_overflow() {
    let dir = TempDir::labeled("create-loc-fat").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[1], &[2048])).unwrap();
    let got = loc.range_batch(&[Fk(1)]).unwrap();
    assert_eq!(got[0].unwrap().txout.1, 2048);
    assert_eq!(got[0].unwrap().n_out, 1);
}

#[test]
fn create_loc_txout_past_u16_strides() {
    let dir = TempDir::labeled("create-loc-u16-strides").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    let len = 65536 * IDX_STRIDE;
    loc.append(&chain(&[1], &[len])).unwrap();
    let got = loc.range_batch(&[Fk(1)]).unwrap();
    assert_eq!(got[0].unwrap().txout.1, len);
    assert_eq!(got[0].unwrap().n_out, 1);
    drop(loc);
    let loc = CreateLoc::open(dir.path()).unwrap();
    let got = loc.range_batch(&[Fk(1)]).unwrap();
    assert_eq!(got[0].unwrap().txout.1, len);
    assert_eq!(got[0].unwrap().n_out, 1);
    assert_eq!(ovf_data_len(dir.path()), 16);
}

#[test]
fn create_loc_n_out_past_u16() {
    let dir = TempDir::labeled("create-loc-u16-nout").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[65536], &[8])).unwrap();
    let got = loc.range_batch(&[Fk(1)]).unwrap();
    assert_eq!(got[0].unwrap().n_out, 65536);
    assert_eq!(got[0].unwrap().spent.1, 65536 * IDX_STRIDE);
    drop(loc);
    let loc = CreateLoc::open(dir.path()).unwrap();
    assert_eq!(loc.range_batch(&[Fk(1)]).unwrap()[0].unwrap().n_out, 65536);
    assert_eq!(ovf_data_len(dir.path()), 16);
}

#[test]
fn create_loc_opens_legacy_12b_ovf() {
    let dir = TempDir::labeled("create-loc-ovf12").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[256, 256, 256, 256], &[8, 8, 8, 8]))
        .unwrap();
    drop(loc);
    write_legacy_create_ovf_v22(
        dir.path(),
        &[(1, 1, 256), (2, 1, 256), (3, 1, 256), (4, 1, 256)],
    );
    assert_eq!(ovf_data_len(dir.path()), 48);
    let loc = CreateLoc::open(dir.path()).unwrap();
    let got = loc.range_batch(&[Fk(1), Fk(2), Fk(3), Fk(4)]).unwrap();
    for g in &got {
        assert_eq!(g.unwrap().n_out, 256);
        assert_eq!(g.unwrap().spent.1, 256 * IDX_STRIDE);
    }
    assert_eq!(ovf_data_len(dir.path()), 64);
}

#[test]
fn create_loc_mixed_window_overflow() {
    let dir = TempDir::labeled("create-loc-mix").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    let mut n_out = vec![1u32; 16];
    n_out[7] = 256;
    let lens = vec![8u64; 16];
    loc.append(&chain(&n_out, &lens)).unwrap();
    let got = loc.range_batch(&[Fk(8), Fk(1), Fk(16)]).unwrap();
    assert_eq!(got[0].unwrap().n_out, 256);
    assert_eq!(got[0].unwrap().spent.1, 256 * 8);
    assert_eq!(got[1].unwrap().n_out, 1);
    assert_eq!(got[2].unwrap().n_out, 1);
    assert_eq!(got[0].unwrap().spent.0, FILE_HEADER_LEN as u64 + 7 * 8);
    assert_eq!(
        got[2].unwrap().spent.0,
        FILE_HEADER_LEN as u64 + 7 * 8 + 256 * 8 + 7 * 8
    );
    if let Ok(mut sess) = rbitcoin_store::uring_session::UringSession::try_open(
        rbitcoin_store::uring_session::DEFAULT_ENTRIES,
    ) {
        let held = loc
            .range_batch_ctx(
                &[Fk(8), Fk(1), Fk(16)],
                &mut rbitcoin_store::IoCtx::held(&mut sess),
            )
            .unwrap();
        assert_eq!(held, got);
    }
}

#[test]
fn create_loc_mixed_window_u32_strides() {
    let dir = TempDir::labeled("create-loc-mix-u32").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    let n_out = vec![1u32; 8];
    let mut lens = vec![8u64; 8];
    lens[3] = 65536 * IDX_STRIDE;
    loc.append(&chain(&n_out, &lens)).unwrap();
    let got = loc.range_batch(&[Fk(4), Fk(1), Fk(8)]).unwrap();
    assert_eq!(got[0].unwrap().txout.1, 65536 * IDX_STRIDE);
    assert_eq!(got[1].unwrap().txout.1, 8);
    assert_eq!(
        got[2].unwrap().txout.0,
        FILE_HEADER_LEN as u64 + 3 * 8 + 65536 * IDX_STRIDE + 3 * 8
    );
}

#[test]
fn create_loc_missing_ovf_is_corrupt() {
    let dir = TempDir::labeled("create-loc-missing-ovf").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&[256], &[8])).unwrap();
    drop(loc);
    std::fs::remove_file(dir.path().join("create.loc.ovf")).unwrap();
    let loc = CreateLoc::open(dir.path()).unwrap();
    match loc.range_batch(&[Fk(1)]) {
        Err(StoreError::Corrupt(m)) => {
            assert!(m.contains("overflow missing"), "{m}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn spent_len_is_8_times_n_out() {
    assert_eq!(IDX_STRIDE, 8);
    assert_eq!(3u64.saturating_mul(IDX_STRIDE), 24);
    assert_eq!(256u64.saturating_mul(IDX_STRIDE), 2048);
}

#[test]
fn loc_window_need_n_stops_at_max_id() {
    assert_eq!(loc_window_need_n(3, 1, 1024), 3);
    assert_eq!(loc_window_need_n(1024, 1, 1024), 1024);
    assert_eq!(loc_window_need_n(1025, 1025, 2048), 1);
    assert_eq!(loc_window_need_n(1100, 1025, 2048), 76);
    assert_eq!(loc_window_need_n(1, 1025, 2048), 0);
}

#[test]
fn range_batch_multi_window_matches_serial_and_held() {
    let dir = TempDir::labeled("create-loc-batch-win").unwrap();
    let loc = CreateLoc::create(dir.path()).unwrap();
    loc.append(&chain(&vec![1u32; 2000], &vec![8u64; 2000]))
        .unwrap();
    let fks = [Fk(3), Fk(50), Fk(1024), Fk(1025), Fk(2000), Fk::NULL];
    let batch = loc.range_batch(&fks).unwrap();
    for (i, fk) in fks.iter().enumerate() {
        let one = loc.range_batch(&[*fk]).unwrap();
        assert_eq!(batch[i], one[0], "fk={}", fk.0);
    }
    if let Ok(mut sess) = rbitcoin_store::uring_session::UringSession::try_open(
        rbitcoin_store::uring_session::DEFAULT_ENTRIES,
    ) {
        let held = loc
            .range_batch_ctx(&fks, &mut rbitcoin_store::IoCtx::held(&mut sess))
            .unwrap();
        assert_eq!(held, batch);
    }
}
