use rbitcoin_primitives::Fk;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::input::*;
use rbitcoin_store::testutil::TempDir;

fn edge(parent: u64, vout: u32) -> InputEdge {
    InputEdge {
        parent: Fk(parent),
        vout,
    }
}

#[test]
fn pack_rejects_wide_fk_and_vout() {
    let err = InputEdge {
        parent: Fk(FK_LIMIT),
        vout: 0,
    }
    .pack();
    assert!(matches!(err, Err(StoreError::Corrupt("input create_fk"))));
    let err = InputEdge {
        parent: Fk(1),
        vout: VOUT_LIMIT,
    }
    .pack();
    assert!(matches!(err, Err(StoreError::Corrupt("input vout"))));
    let err = InputEdge {
        parent: Fk::NULL,
        vout: 1,
    }
    .pack();
    assert!(matches!(
        err,
        Err(StoreError::Corrupt("input coinbase vout"))
    ));
}

#[test]
fn roundtrip_coinbase_and_parents_across_reopen() {
    let dir = TempDir::labeled("input-rt").unwrap();
    let t = Input::create(dir.path()).unwrap();
    t.append(&[
        vec![InputEdge::coinbase()],
        vec![edge(1, 0), edge(1, 3)],
        vec![],
    ])
    .unwrap();
    assert_eq!(t.n_in(Fk(1)).unwrap(), Some(1));
    assert_eq!(
        t.edges(Fk(1)).unwrap().unwrap(),
        vec![InputEdge::coinbase()]
    );
    assert_eq!(
        t.edges(Fk(2)).unwrap().unwrap(),
        vec![edge(1, 0), edge(1, 3)]
    );
    assert_eq!(t.n_in(Fk(3)).unwrap(), None);
    assert!(t.edges(Fk(3)).unwrap().is_none());
    drop(t);
    let t = Input::open(dir.path()).unwrap();
    assert_eq!(t.count(), 3);
    assert_eq!(
        t.edges(Fk(2)).unwrap().unwrap(),
        vec![edge(1, 0), edge(1, 3)]
    );
    t.truncate_to_count(1).unwrap();
    assert_eq!(t.count(), 1);
    assert!(matches!(t.edges(Fk(2)), Err(StoreError::NotFound)));
    assert_eq!(
        t.edges(Fk(1)).unwrap().unwrap(),
        vec![InputEdge::coinbase()]
    );
}

#[test]
fn window_checkpoint_serves_create_1025() {
    let dir = TempDir::labeled("input-win").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let one = vec![edge(7, 1)];
    let batch = vec![one; 1025];
    t.append(&batch).unwrap();
    assert_eq!(t.edges(Fk(1)).unwrap().unwrap(), vec![edge(7, 1)]);
    assert_eq!(t.edges(Fk(1024)).unwrap().unwrap(), vec![edge(7, 1)]);
    assert_eq!(t.edges(Fk(1025)).unwrap().unwrap(), vec![edge(7, 1)]);
    drop(t);
    let t = Input::open(dir.path()).unwrap();
    assert_eq!(t.edges(Fk(1025)).unwrap().unwrap(), vec![edge(7, 1)]);
    assert_eq!(t.n_in(Fk(1025)).unwrap(), Some(1));
}

#[test]
fn edges_span_bounds_and_mid_create() {
    let dir = TempDir::labeled("input-span-bounds").unwrap();
    let t = Input::create(dir.path()).unwrap();
    t.append(&[
        vec![edge(1, 0)],
        vec![edge(4, 1), edge(4, 2)],
        vec![edge(7, 3)],
    ])
    .unwrap();
    assert!(matches!(t.edges_span(0, 1), Err(StoreError::InvalidFk)));
    assert!(matches!(t.edges_span(3, 1), Err(StoreError::InvalidFk)));
    assert!(matches!(t.edges_span(1, 4), Err(StoreError::NotFound)));
    assert_eq!(
        t.edges_span(2, 2).unwrap(),
        vec![Some(vec![edge(4, 1), edge(4, 2)])]
    );
    assert_eq!(
        t.edges_span(1, 2).unwrap(),
        vec![Some(vec![edge(1, 0)]), Some(vec![edge(4, 1), edge(4, 2)]),]
    );
}

#[test]
fn input_append_reopen_reads_last_edges() {
    let dir = TempDir::labeled("input-reopen-last").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let mut batch = Vec::with_capacity(1025);
    for i in 0..1024u32 {
        batch.push(vec![edge(1, i)]);
    }
    batch.push(vec![edge(9, 3), edge(9, 4)]);
    t.append(&batch).unwrap();
    drop(t);
    let t = Input::open(dir.path()).unwrap();
    assert_eq!(t.n_in(Fk(1025)).unwrap(), Some(2));
    assert_eq!(
        t.edges(Fk(1025)).unwrap().unwrap(),
        vec![edge(9, 3), edge(9, 4)]
    );
    assert_eq!(t.edges(Fk(1)).unwrap().unwrap(), vec![edge(1, 0)]);
}

#[test]
fn new_store_creates_inputs_stems() {
    let (dir, _store) = rbitcoin_store::testutil::tiny_store_labeled("input-files");
    assert!(dir.path().join("input.loc").is_file());
    assert!(dir.path().join("input.off").is_file());
    assert!(dir.path().join("input.body").is_file());
}

#[test]
fn reopen_after_short_body_keeps_the_prefix_inputs() {
    let dir = TempDir::labeled("input-short-body").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let mut batch = Vec::with_capacity(1025);
    for i in 0..1023u32 {
        batch.push(vec![edge(1, i)]);
    }
    // Create 1024 adds no body bytes. Create 1025's input is the tail a
    // second subtraction would take from create 1023.
    batch.push(vec![]);
    batch.push(vec![edge(9, 4)]);
    t.append(&batch).unwrap();
    let kept = t.edges(Fk(1023)).unwrap();
    let path = dir.path().to_path_buf();
    drop(t);

    let header = rbitcoin_store::file::FILE_HEADER_LEN as u64;
    write_hwm(&path.join("input.off"), header);
    write_hwm(&path.join("input.body"), header + 1023 * REC_LEN);
    let t = Input::open(&path).expect("a short body with a long locator opens");
    assert_eq!(t.count(), 1023);
    assert_eq!(t.body.logical_len(), header + 1023 * REC_LEN);
    assert_eq!(t.edges(Fk(1)).unwrap().unwrap(), vec![edge(1, 0)]);
    assert_eq!(t.edges(Fk(1023)).unwrap(), kept);
    drop(t);
    let t = Input::open(&path).unwrap();
    assert_eq!(t.count(), 1023);
    assert_eq!(t.edges(Fk(1023)).unwrap(), kept);
}

/// The locator names creates whose inputs were not written. Open refuses
/// that datadir instead of publishing a body end over the spare bytes.
#[test]
fn open_refuses_a_body_short_of_the_kept_prefix() {
    let dir = TempDir::labeled("input-short-of-prefix").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let batch = vec![vec![edge(1, 0)]; 1050];
    t.append(&batch).unwrap();
    let path = dir.path().to_path_buf();
    drop(t);

    let header = rbitcoin_store::file::FILE_HEADER_LEN as u64;
    write_hwm(&path.join("input.off"), header);
    write_hwm(&path.join("input.body"), header + 1000 * REC_LEN);
    match Input::open(&path) {
        Err(StoreError::Corrupt("invariant: input.body truncate")) => {}
        Err(err) => panic!("{err}"),
        Ok(_) => panic!("open kept a body short of the prefix"),
    }
}

/// The locator header was shortened and the body was not. Open cuts the
/// body back to the prefix, so the next append is not shifted by the tail.
#[test]
fn long_body_reopen_cuts_back_to_the_locator_prefix() {
    let dir = TempDir::labeled("input-long-body").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let batch: Vec<_> = (0..1024u32).map(|i| vec![edge(1, i)]).collect();
    t.append(&batch).unwrap();
    let path = dir.path().to_path_buf();
    drop(t);

    let header = rbitcoin_store::file::FILE_HEADER_LEN as u64;
    write_hwm(&path.join("input.loc"), header + 1023 * LOC_SLOT);
    let t = Input::open(&path).expect("a long body with a short locator opens");
    assert_eq!(t.count(), 1023);
    assert_eq!(t.body.logical_len(), header + 1023 * REC_LEN);
    assert_eq!(t.edges(Fk(1023)).unwrap().unwrap(), vec![edge(1, 1022)]);
    t.append(&[vec![edge(9, 4)]]).unwrap();
    assert_eq!(t.edges(Fk(1024)).unwrap().unwrap(), vec![edge(9, 4)]);
}

fn write_hwm(path: &std::path::Path, logical: u64) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(8)).unwrap();
    f.write_all(&logical.to_le_bytes()).unwrap();
}

#[test]
fn append_rejects_n_in_past_u16() {
    let dir = TempDir::labeled("input-wide").unwrap();
    let t = Input::create(dir.path()).unwrap();
    let edges = vec![edge(1, 0); usize::from(u16::MAX) + 1];
    let err = t.append(&[edges]).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt("input n_in")));
    assert_eq!(t.count(), 0);
}
