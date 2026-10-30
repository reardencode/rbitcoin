fn connect_range(
    q: &Query,
    mut prev: Fk,
    mut parent_hash: Option<[u8; 32]>,
    n: u32,
    witness: &[u8],
    hashes: &mut Vec<[u8; 32]>,
) -> Fk {
    let start = hashes.len() as u32;
    for h in start..start + n {
        let (header, mut ta) = coinbase_block(h, prev, parent_hash);
        if !witness.is_empty() {
            ta.inputs[0].witness = vec![witness.to_vec()];
        }
        parent_hash = Some(header.hash);
        hashes.push(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    prev
}

fn witness_of(q: &Query, fk: Fk) -> Vec<Vec<u8>> {
    let tx = q.get_tx(fk).unwrap();
    q.tx_input_at_fk(fk, &tx, 0).unwrap().witness
}

fn resume(q: &Query, hashes: &mut Vec<[u8; 32]>) -> (Fk, [u8; 32]) {
    let tip = q.tip_height().unwrap().0;
    hashes.truncate(tip as usize + 1);
    let prev = q.tip_header_fk().unwrap().unwrap();
    (prev, hashes[tip as usize])
}

fn prune_life_window(q: Query, dir: &rbitcoin_query::testutil::TempDir, hashes: &mut Vec<[u8; 32]>) -> Query {
    connect_range(&q, Fk::NULL, None, 300, &[0x55; 72], hashes);
    let tip_fk = q.block_tx_fks(Height(299)).unwrap()[0];
    q.set_prune_seqsigwit(true).unwrap();
    q.apply_prune_seqsigwit_tip().unwrap();
    assert_eq!(witness_of(&q, tip_fk).len(), 1);
    // The synthetic genesis hash is not a header hash. A tip marker keeps
    // reopen on the default window; a missing marker walks from genesis.
    q.store()
        .sync_spend_durable(q.tip_height().unwrap().0)
        .unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_eq!(witness_of(&q, tip_fk).len(), 1);
    assert!(q.prune_seqsigwit());
    let (prev, parent) = resume(&q, hashes);
    q.set_ibd_mode(true);
    q.set_seqsigwit_ram_threshold_bytes(1 << 30).unwrap();
    connect_range(&q, prev, Some(parent), 320, &[0x44; 96], hashes);
    let (heights, fks, _, evictions) = q.seqsigwit_ram_window_stats();
    assert!(heights <= Query::SEQSIGWIT_KEEP_HEIGHTS as usize);
    assert!(fks <= Query::SEQSIGWIT_KEEP_HEIGHTS as usize);
    assert!(evictions > 0, "old heights must be evicted");
    let (parent_prev, parent_hash) = resume(&q, hashes);
    connect_range(&q, parent_prev, Some(parent_hash), 1, &[0x22; 16], hashes);
    let after = q.seqsigwit_ram_window_stats().1;
    assert!(after <= Query::SEQSIGWIT_KEEP_HEIGHTS as usize);
    q.disconnect_tip().unwrap();
    hashes.pop();
    assert!(q.seqsigwit_ram_window_stats().1 < after);
    connect_range(&q, parent_prev, Some(parent_hash), 1, &[0x33; 16], hashes);
    assert_eq!(q.seqsigwit_ram_window_stats().1, after);
    q
}

fn prune_life_thresholds(q: &Query, dir: &rbitcoin_query::testutil::TempDir, hashes: &mut Vec<[u8; 32]>) {
    let (prev, parent) = resume(q, hashes);
    q.set_seqsigwit_ram_threshold_bytes(80).unwrap();
    connect_range(q, prev, Some(parent), 8, &[0x77; 128], hashes);
    let (_heights, _fks, bytes, evictions) = q.seqsigwit_ram_window_stats();
    assert!(bytes <= 80, "bytes={bytes}");
    assert!(evictions > 0);
    let (prev, parent) = resume(q, hashes);
    q.set_seqsigwit_ram_threshold_bytes(0).unwrap();
    let tiny_h = hashes.len() as u32;
    connect_range(q, prev, Some(parent), 1, &[0x11], hashes);
    let (heights, fks, bytes, _) = q.seqsigwit_ram_window_stats();
    assert_eq!(heights, 0, "threshold 0 keeps no RAM heights");
    assert_eq!(fks, 0);
    assert_eq!(bytes, 0);
    let tiny = q.block_tx_fks(Height(tiny_h)).unwrap()[0];
    assert_eq!(witness_of(q, tiny), vec![vec![0x11]]);
    let spill = q.store.path().join(format!("seqsigwit.window/{tiny_h}.bin"));
    assert!(spill.is_file());
    #[cfg(unix)]
    {
        let outside = dir.path().join("outside.bin");
        std::fs::rename(&spill, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &spill).unwrap();
        q.clear_seqsigwit_ram_window();
        let tx = q.get_tx(tiny).unwrap();
        let err = q.tx_input_at_fk(tiny, &tx, 0).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(msg) if msg.contains("escaped")),
            "{err}"
        );
    }
    let _ = dir;
}

fn prune_life_watermark(q: Query, dir: &rbitcoin_query::testutil::TempDir, hashes: &mut Vec<[u8; 32]>) {
    let (prev, parent) = resume(&q, hashes);
    q.set_seqsigwit_ram_threshold_bytes(1 << 20).unwrap();
    let ram_h = hashes.len() as u32;
    connect_range(&q, prev, Some(parent), 1, &[0x11, 0x22], hashes);
    assert_eq!(q.seqsigwit_ram_window_stats().1, 1);
    let ram_fk = q.block_tx_fks(Height(ram_h)).unwrap()[0];
    assert_eq!(witness_of(&q, ram_fk), vec![vec![0x11, 0x22]]);
    q.clear_seqsigwit_ram_window();
    assert_eq!(witness_of(&q, ram_fk), vec![vec![0x11, 0x22]]);
    let (prev, parent) = resume(&q, hashes);
    q.set_seqsigwit_ram_threshold_bytes(0).unwrap();
    let fall = hashes.len() as u32;
    let prev = connect_range(&q, prev, Some(parent), 2, &[0xab, 0xcd], hashes);
    let window = q.store.path().join("seqsigwit.window");
    assert!(window.join(format!("{fall}.bin")).is_file());
    assert!(window.join(format!("{}.bin", fall + 1)).is_file());
    q.set_pruneheight(Some(Height(fall))).unwrap();
    assert!(!window.join(format!("{fall}.bin")).exists());
    let kept = q
        .reconstruct_archived_block(&hashes[(fall + 1) as usize])
        .unwrap()
        .unwrap();
    assert_eq!(kept.txdata.len(), 1);
    q.set_pruneheight(Some(Height(fall + 1))).unwrap();
    assert!(!window.join(format!("{}.bin", fall + 1)).exists());
    std::fs::write(window.join("0.bin"), b"orphan").unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_eq!(q.pruneheight(), Some(Height(fall + 1)));
    assert!(!window.join("0.bin").exists());
    let err = q.disconnect_tip().unwrap_err();
    assert!(matches!(err, StoreError::Pruned { .. }), "{err:?}");
    let err = q.set_prune_seqsigwit(false).unwrap_err().to_string();
    assert!(err.contains("refusing to disable prune-seqsigwit"), "{err}");
    let err = q.reconstruct_archived_block(&hashes[0]).unwrap_err();
    assert!(matches!(err, StoreError::Pruned { height: 0 }), "{err:?}");
    let err = q.reconstruct_block_at_height(Height(0)).unwrap_err();
    assert!(matches!(err, StoreError::Pruned { height: 0 }), "{err:?}");
    let _ = (prev, std::fs::remove_dir_all(dir));
}

/// Chain taller than the keep window. Two withheld locator headers leave
/// the new blocks confirmed in RAM. Prune must stay on the last sealed tip,
/// so the block at `sealed - 288` still has its witness.
fn withheld_locator_keeps_prune(direct: bool) {
    let (dir, q) = temp_query(if direct {
        "withheld-locator-prune-ibd"
    } else {
        "withheld-locator-prune"
    });
    let mut hashes = Vec::new();
    connect_range(&q, Fk::NULL, None, 290, &[0x55; 8], &mut hashes);
    assert_eq!(q.tip_height(), Some(Height(289)));
    q.set_prune_seqsigwit(true).unwrap();
    q.apply_prune_seqsigwit_tip().unwrap();
    assert_eq!(q.pruneheight(), Some(Height(1)));
    let kept = q.block_tx_fks(Height(2)).unwrap()[0];
    q.clear_seqsigwit_ram_window();
    assert_eq!(witness_of(&q, kept), vec![vec![0x55; 8]]);
    if direct {
        q.enter_direct_index_mode_sh(false).unwrap();
    }

    let loc = q.store().txs.create_loc.loc.read_fd();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc, 16);
    let _disarm = Disarm(loc);
    let (prev, parent) = resume(&q, &mut hashes);
    connect_range(&q, prev, Some(parent), 2, &[0x66; 8], &mut hashes);
    assert_eq!(q.tip_height(), Some(Height(291)));
    assert_eq!(
        q.pruneheight(),
        Some(Height(1)),
        "a second withheld locator header does not move seqsigwit.prune"
    );
    q.clear_seqsigwit_ram_window();
    assert_eq!(witness_of(&q, kept), vec![vec![0x55; 8]]);
    if !direct {
        // Drop one unsealed block. The shrink flush must not become the
        // prune anchor, and the next withheld connect must not move it.
        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height(), Some(Height(290)));
        rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc, 16);
        let (prev, parent) = resume(&q, &mut hashes);
        connect_range(&q, prev, Some(parent), 1, &[0x77; 8], &mut hashes);
        assert_eq!(q.tip_height(), Some(Height(291)));
        assert_eq!(
            q.pruneheight(),
            Some(Height(1)),
            "disconnect of an unsealed tip does not move seqsigwit.prune"
        );
        q.clear_seqsigwit_ram_window();
        assert_eq!(witness_of(&q, kept), vec![vec![0x55; 8]]);
    }
    let _ = dir;
}

#[test]
fn withheld_locator_does_not_prune_a_confirmed_witness() {
    withheld_locator_keeps_prune(false);
}

#[test]
fn withheld_locator_during_ibd_does_not_prune_a_confirmed_witness() {
    withheld_locator_keeps_prune(true);
}

struct Disarm(rbitcoin_store::io_handle::IoHandle);

impl Drop for Disarm {
    fn drop(&mut self) {
        rbitcoin_store::io_handle::disarm_pwrite(self.0);
    }
}

#[test]
fn pruned_seqsigwit_life() {
    let (dir, q) = temp_query("pruned-seqsigwit-life");
    let mut hashes = Vec::new();
    let q = prune_life_window(q, &dir, &mut hashes);
    prune_life_thresholds(&q, &dir, &mut hashes);
    prune_life_watermark(q, &dir, &mut hashes);
}
