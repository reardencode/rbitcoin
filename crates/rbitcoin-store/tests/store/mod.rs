use rbitcoin_primitives::{Fk, Height, SCHEMA_VERSION, STORE_MAGIC};
use rbitcoin_store::error::StoreError;
use rbitcoin_store::hashhead::HeadScale;
use rbitcoin_store::head_resolve_pick::LeftoverMissOn;
use rbitcoin_store::header_table::HeaderRecord;
use rbitcoin_store::point_table::{self};
use rbitcoin_store::store::*;
use rbitcoin_store::tx_table::{InputRecord, OutputRecord, TxRecord};
use std::path::Path;

mod legacy_rename_tests;

fn tmp() -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled("store").unwrap()
}

fn sh_put_create(s: &Store, rec: rbitcoin_store::scripthash::ScriptHashRecord) {
    s.scripthash
        .put_create_batch_append(std::slice::from_ref(&rec))
        .unwrap();
}

#[test]
fn datadir_bytes_cache_skips_the_walk_inside_thirty_seconds() {
    use std::time::{Duration, Instant};
    let t0 = Instant::now();
    let ttl = Duration::from_secs(30);
    let mut walks = 0u32;
    let (at, n) = cached_dir_bytes(None, t0, ttl, || {
        walks += 1;
        10
    });
    assert_eq!((at, n, walks), (t0, 10, 1));
    let (at2, n2) = cached_dir_bytes(Some((at, n)), t0 + Duration::from_secs(29), ttl, || {
        walks += 1;
        99
    });
    assert_eq!(at2, at);
    assert_eq!(n2, 10);
    assert_eq!(walks, 1, "a new file inside the ttl must not be walked");
    let (at3, n3) = cached_dir_bytes(Some((at2, n2)), t0 + ttl, ttl, || {
        walks += 1;
        99
    });
    assert_eq!(at3, t0 + ttl);
    assert_eq!(n3, 99);
    assert_eq!(walks, 2);
}

#[test]
fn publish_dir_bytes_keeps_the_newer_sample() {
    use std::time::{Duration, Instant};
    let t0 = Instant::now();
    let later = t0 + Duration::from_millis(1);
    let mut slot = None;
    assert_eq!(publish_dir_bytes(&mut slot, t0, 10), 10);
    assert_eq!(publish_dir_bytes(&mut slot, later, 40), 40);
    assert_eq!(
        publish_dir_bytes(&mut slot, t0, 10),
        40,
        "a slower walk must not replace a newer total"
    );
    assert_eq!(slot, Some((later, 40)));
}

#[test]
fn spindle_wait_blocks_only_while_datadir_hdd_is_held() {
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = tmp();
    let store = Store::create_tiny(&dir).unwrap();
    for hdd in [false, true] {
        store.set_datadir_hdd(hdd);
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let _hold = store.spindle_hold();
            scope.spawn(|| {
                store.spindle_wait();
                let _ = tx.send(());
            });
            let early = rx.recv_timeout(Duration::from_millis(300));
            drop(_hold);
            if hdd {
                assert!(early.is_err(), "wait returned while the hold was alive");
                rx.recv_timeout(Duration::from_secs(2))
                    .expect("waiter finishes after the hold drops");
            } else {
                early.expect("flag off does not block");
            }
        });
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_tiny_reopen_still_works() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let s = Store::open_tiny(&dir).unwrap();
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn occupied_schema23_header_body_opens_as_24() {
    use rbitcoin_store::file::{TableFile, FILE_HEADER_LEN};
    use rbitcoin_store::header_table::HeaderRecord;
    let dir = tmp();
    let hash = [0x44u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        let hdr = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash,
            size: 0,
            weight: 0,
        };
        s.put_header(&hdr).unwrap();
        s.flush().unwrap();
    }
    {
        let body_path = dir.join("header.body");
        let src = TableFile::open(&body_path, rbitcoin_primitives::TableKind::Header).unwrap();
        let rec = HeaderRecord::decode(&{
            let mut b = [0u8; rbitcoin_store::header_table::HEADER_RECORD_LEN];
            src.read_at(FILE_HEADER_LEN as u64, &mut b).unwrap();
            b
        })
        .unwrap();
        drop(src);
        let dst = TableFile::create(
            dir.join("header.body.v23tmp"),
            rbitcoin_primitives::TableKind::Header,
        )
        .unwrap();
        dst.write_at(FILE_HEADER_LEN as u64, &rec.encode()).unwrap();
        dst.set_logical_len(
            FILE_HEADER_LEN as u64 + rbitcoin_store::header_table::HEADER_RECORD_LEN as u64,
        )
        .unwrap();
        dst.flush().unwrap();
        drop(dst);
        std::fs::rename(dir.join("header.body.v23tmp"), dir.join("header.body")).unwrap();
        let mut meta = STORE_MAGIC.to_vec();
        meta.extend_from_slice(&23u16.to_le_bytes());
        std::fs::write(dir.join("meta"), meta).unwrap();
    }
    let s = Store::open_tiny(&dir).unwrap();
    let got = s.headers.get_by_hash(&hash).unwrap().unwrap().1;
    assert_eq!(got.hash, hash);
    assert_eq!(got.size, 0);
    assert_eq!(got.weight, 0);
    drop(s);
    let meta = std::fs::read(dir.join("meta")).unwrap();
    assert_eq!(u16::from_le_bytes([meta[4], meta[5]]), SCHEMA_VERSION);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_refuses_shared_file_scripthash_body() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let body = dir.join("scripthash.body");
    std::fs::remove_dir_all(&body).unwrap();
    rbitcoin_store::file::TableFile::create(&body, rbitcoin_primitives::TableKind::ScriptHash)
        .unwrap();
    match Store::open_tiny(&dir) {
        Err(StoreError::Corrupt(m)) => {
            assert_eq!(m, rbitcoin_store::scripthash::INDEX_REFUSE_SHARED_SH_BODY);
            assert!(m.contains("Class A kept"), "{m}");
        }
        Ok(_) => panic!("Shared scripthash.body must refuse Store::open"),
        Err(other) => panic!("expected INDEX_REFUSE_SHARED_SH_BODY, got {other}"),
    }
    assert!(dir.join("txout.body").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_refuses_pack8_paged_mode_10() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        sh_put_create(
            &s,
            rbitcoin_store::scripthash::ScriptHashRecord::from_fk([0x11u8; 32], Fk(1)),
        );
        s.flush().unwrap();
    }
    let ingest = dir.join("scripthash.ovf").join("ingest");
    let mut bytes = std::fs::read(&ingest).unwrap();
    let hdr = rbitcoin_store::file::FILE_HEADER_LEN;
    let slot = rbitcoin_store::scripthash_layout::SH_HEAD_SLOT_SIZE;
    let key_len = rbitcoin_store::scripthash_layout::SH_HEAD_KEY_LEN;
    let mode10 = ((2u64 << 62) | 4096u64).to_le_bytes();
    let mut i = hdr;
    while i + slot <= bytes.len() {
        let val = &bytes[i + key_len..i + slot];
        if val.iter().any(|&b| b != 0) {
            bytes[i + key_len..i + slot].copy_from_slice(&mode10);
        }
        i += slot;
    }
    std::fs::write(&ingest, &bytes).unwrap();
    match Store::open_tiny(&dir) {
        Err(StoreError::Corrupt(m)) => {
            assert_eq!(m, rbitcoin_store::scripthash_layout::INDEX_REFUSE_PAGED_SH);
            assert!(m.contains("Class A kept"), "{m}");
        }
        Ok(_) => panic!("Paged pack8 must refuse Store::open"),
        Err(other) => panic!("expected INDEX_REFUSE_PAGED_SH, got {other}"),
    }
    assert!(dir.join("txout.body").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shared_tiny_store_fixture_is_tiny_unique_and_drop_cleans() {
    let path;
    {
        let (dir, store) = rbitcoin_store::testutil::tiny_store();
        path = dir.path().to_path_buf();
        assert!(path.is_dir(), "fixture must create {path:?}");
        assert_eq!(store.headers.head_target_slots(), 64);
        assert_eq!(store.head_scale(), HeadScale::Tiny);
        let (dir2, store2) = rbitcoin_store::testutil::tiny_store();
        assert_ne!(dir.path(), dir2.path(), "each open must be a unique path");
        assert_eq!(store2.headers.head_target_slots(), 64);
    }
    assert!(
        !path.exists(),
        "drop must remove the Tiny store directory {path:?}"
    );
}

#[test]
fn open_time_scale_is_explicit_not_env_or_cargo_test_sniff() {
    // Production constructors are Mainnet even under `cargo test`.
    let mainnet = StoreLayout::single("/tmp/rbitcoin-scale-unused");
    assert_eq!(mainnet.head_scale, HeadScale::Mainnet);
    assert_eq!(mainnet.header_slots(), 1 << 22);
    assert_eq!(mainnet.sh_shard_count(), 64);
    assert_eq!(
        mainnet.tx_head_bits(),
        rbitcoin_store::address_head::MAINNET_BITS
    );
    // Do not create those files in the default suite.

    let tiny_layout = StoreLayout::tiny("/tmp/rbitcoin-scale-unused-tiny");
    assert_eq!(tiny_layout.head_scale, HeadScale::Tiny);
    assert_eq!(tiny_layout.header_slots(), 64);
    assert_eq!(tiny_layout.sh_shard_count(), 1);
    assert_eq!(
        tiny_layout.tx_head_bits(),
        rbitcoin_store::address_head::TINY_BITS
    );

    let prev = std::env::var_os("RBITCOIN_HEAD_SCALE");
    std::env::set_var("RBITCOIN_HEAD_SCALE", "mainnet");
    let dir = tmp();
    let s = Store::create_layout(StoreLayout::tiny(&dir)).unwrap();
    assert_eq!(s.head_scale(), HeadScale::Tiny);
    assert_eq!(s.headers.head_target_slots(), 64);
    assert_eq!(s.scripthash.head_shard_count(), 1);
    assert_eq!(s.txs.head_bits(), rbitcoin_store::address_head::TINY_BITS);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);

    std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    let still_mainnet = StoreLayout::single("/tmp/rbitcoin-scale-unused-2");
    assert_eq!(
        still_mainnet.head_scale,
        HeadScale::Mainnet,
        "RBITCOIN_HEAD_SCALE must not win over explicit Mainnet open"
    );
    assert_eq!(still_mainnet.header_slots(), 1 << 22);
    match prev {
        Some(v) => std::env::set_var("RBITCOIN_HEAD_SCALE", v),
        None => std::env::remove_var("RBITCOIN_HEAD_SCALE"),
    }
}

fn coinbase_item(
    txid: [u8; 32],
    outs: Vec<OutputRecord>,
) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let n_out = outs.len() as u32;
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: n_out,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        outs,
    )
}

/// Class C only: coinbase fk at height is header_txs first — no body.
#[test]
fn coinbase_fk_at_heights_matches_first_tx() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let hdr = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x1d00ffff,
        nonce: 1,
        merkle_root: [1u8; 32],
        hash: [2u8; 32],
        size: 0,
        weight: 0,
    };
    let hfk = s.put_header(&hdr).unwrap();
    // Two txs: coinbase + one non-cb (contiguous Class A ids).
    let (cb_tx, cb_in, cb_out) = coinbase_item(
        [10u8; 32],
        vec![OutputRecord {
            value: 50_0000_0000,
            script: vec![0x51],
            spender_field: Fk::NULL,
            multi_spender: false,
        }],
    );
    let cb_fks = s
        .put_tx_full_batch_indexed(&[(cb_tx, cb_in, cb_out)], false)
        .unwrap();
    let non_tx = TxRecord {
        txid: [11u8; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let non_in = vec![InputRecord {
        prev_txid: [10u8; 32],
        parent: rbitcoin_store::InputParent::Prevout {
            create_fk: cb_fks[0],
            vout: 0,
        },
        script_sig: vec![],
        sequence: 0xffff_ffff,
        witness: vec![],
    }];
    let non_out = vec![OutputRecord {
        value: 1,
        script: vec![0x51],
        spender_field: Fk::NULL,
        multi_spender: false,
    }];
    let non_fks = s
        .put_tx_full_batch_indexed(&[(non_tx, non_in, non_out)], false)
        .unwrap();
    let fks = [cb_fks[0], non_fks[0]];
    assert_eq!(fks.len(), 2);
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), hfk, fks[0], 2)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), hfk)
        .unwrap();
    s.rebuild_height_fence().unwrap();

    let map = s.coinbase_fk_at_heights(&[0, 1, 99]).unwrap();
    assert_eq!(map.get(&0).copied(), Some(fks[0]));
    assert!(!map.contains_key(&1)); // no confirmed height 1
    assert!(!map.contains_key(&99));
    assert_ne!(map.get(&0).copied().unwrap(), fks[1]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one fixture, many error arms
#[test]
fn store_create_open_archive_spend_and_meta_errors() {
    let dir = tmp();
    {
        let file = dir.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            Store::create_tiny(&file),
            Err(StoreError::NotDirectory(_))
        ));
    }
    assert!(matches!(
        Store::open_tiny(dir.join("missing")),
        Err(StoreError::NotDirectory(_))
    ));
    {
        let file = dir.join("open-file-not-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            Store::open_tiny(&file),
            Err(StoreError::NotDirectory(_))
        ));
    }

    let s = Store::create_tiny(&dir).unwrap();
    assert_eq!(s.path(), dir.as_path());
    assert!(s.tip_height().is_none());
    assert_eq!(s.header_count(), 0);
    assert_eq!(s.archived_block_count().unwrap(), 0);
    assert_eq!(s.spender_list_count(), 0);

    let hdr = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 0x1d00ffff,
        nonce: 1,
        merkle_root: [3u8; 32],
        hash: [4u8; 32],
        size: 0,
        weight: 0,
    };
    let hfk = s.put_header(&hdr).unwrap();
    assert_eq!(s.get_header(hfk).unwrap().hash, [4u8; 32]);
    assert_eq!(s.get_header_by_hash(&[4u8; 32]).unwrap().unwrap().0, hfk);

    let create = coinbase_item(
        [10u8; 32],
        vec![
            OutputRecord::unspent(50, vec![0x51]),
            OutputRecord::unspent(25, vec![0x51]),
        ],
    );
    let fks = s.put_tx_full_batch_indexed(&[create], true).unwrap();
    let create_fk = fks[0];
    let _ = s.txs.sample_reset_body_decodes();
    let (meta, outs) = s.get_tx_meta_and_outputs(create_fk).unwrap();
    assert_eq!(meta.txid, [10u8; 32]);
    assert_eq!(outs.len(), 2);
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        1,
        "one packed body decode"
    );
    assert_eq!(s.get_tx(create_fk).unwrap().txid, [10u8; 32]);
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        1,
        "get_tx is the same packed decode with the outs dropped"
    );
    let full = s.get_tx_full(create_fk).unwrap();
    assert_eq!(full.2.len(), 2);
    let (m2, prevs) = s.get_tx_meta_and_prevouts(create_fk).unwrap();
    assert_eq!(m2.txid, [10u8; 32]);
    assert_eq!(prevs.len(), 1);
    assert_eq!(s.get_tx_full(create_fk).unwrap().0.txid, [10u8; 32]);
    assert_eq!(s.get_tx_meta_and_prevouts(create_fk).unwrap().1.len(), 1);
    assert_eq!(s.get_tx_meta_and_outputs(create_fk).unwrap().1.len(), 2);
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        1,
        "one outs read decodes; full and prevout reads are not outs decodes"
    );
    let mut span_hashes = Vec::new();
    s.for_each_create_script_hashes_in_fk_span(create_fk.0, create_fk.0, |_fk, sh| {
        span_hashes.push(sh);
        Ok(())
    })
    .unwrap();
    let expect: Vec<[u8; 32]> = outs
        .iter()
        .map(|o| rbitcoin_store::scripthash::script_hash(&o.script))
        .collect();
    assert_eq!(
        span_hashes, expect,
        "fk-span script hashes must match per-fk decode"
    );
    assert_eq!(s.get_fk_by_txid(&[10u8; 32]).unwrap(), Some(create_fk));
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        0,
        "fk resolve verifies txid.body only"
    );
    assert_eq!(s.get_tx_by_txid(&[10u8; 32]).unwrap().unwrap().0, create_fk);
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        1,
        "one decode for the returned record"
    );

    let spend = (
        TxRecord {
            txid: [11u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [10u8; 32],
            parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        vec![OutputRecord::unspent(49, vec![0x51])],
    );
    let spend_fk = s.put_tx_full_batch_indexed(&[spend], true).unwrap()[0];
    s.put_spend_create(create_fk, 0, spend_fk, 0).unwrap();
    s.put_spend_create(create_fk, 0, spend_fk, 0).unwrap();
    let spend2 = (
        TxRecord {
            txid: [12u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [10u8; 32],
            parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let spend2_fk = s.put_tx_full_batch_indexed(&[spend2], true).unwrap()[0];
    s.put_spend_create(create_fk, 0, spend2_fk, 0).unwrap();
    assert!(s.spender_list_count() >= 2);

    // Third spender prepends multi list.
    let spend3 = (
        TxRecord {
            txid: [13u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord {
            prev_txid: [10u8; 32],
            parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let spend3_fk = s.put_tx_full_batch_indexed(&[spend3], true).unwrap()[0];
    let _ = s.txs.sample_reset_body_decodes();
    s.put_spend(&[10u8; 32], 0, spend3_fk, 0).unwrap();
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        0,
        "put_spend resolves the create by head probe only"
    );
    s.put_spend_batch(&[([10u8; 32], 1, spend_fk, 0)]).unwrap();
    s.put_spend_create(create_fk, 1, spend2_fk, 0).unwrap();
    let (soff, slen) = s.tx_spent_range(create_fk).unwrap();
    point_table::put_spend_on_create_at(
        &s.txs,
        &s.spenders,
        create_fk,
        1,
        spend3_fk,
        0,
        Some((soff, slen)),
    )
    .unwrap();
    point_table::put_spend_on_create_at(
        &s.txs,
        &s.spenders,
        create_fk,
        1,
        spend_fk,
        0,
        Some((soff, slen)),
    )
    .unwrap();

    // Class C: confirm spenders + heights. Body list must include spend_fk
    // (membership is part of is_confirmed_strong).
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), hfk)
        .unwrap();
    // Contiguous body covering create..spend (sequential put order).
    let body_first = create_fk.0.min(spend_fk.0);
    let body_last = create_fk.0.max(spend_fk.0);
    s.header_txs
        .put_range(
            &rbitcoin_store::ClassCWrite::for_test(),
            hfk,
            Fk(body_first),
            (body_last - body_first + 1) as u32,
        )
        .unwrap();
    s.strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), spend_fk, hfk)
        .unwrap();
    s.rebuild_height_fence().unwrap();
    assert!(s.is_confirmed_strong(spend_fk).unwrap());
    assert!(!s.is_confirmed_strong(spend2_fk).unwrap());
    assert!(s
        .has_confirmed_strong_spender_create(create_fk, 0, Some((soff, slen)))
        .unwrap());
    let _ = s.txs.sample_reset_body_decodes();
    assert!(s.has_confirmed_strong_spender(&[10u8; 32], 0).unwrap());
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        0,
        "the spentness probe resolves the create by head probe only"
    );
    let unspent = s
        .unspent_create_vouts(create_fk, &[0, 1], Some((soff, slen)))
        .unwrap();
    // vout 0 has confirmed strong spender; vout1 multi without strong may still be unspent
    assert!(!unspent.contains(&0));
    let raw = s.spenders_raw(&[10u8; 32], 0).unwrap();
    assert!(raw.len() >= 2);
    let strong_sp = s.spenders(&[10u8; 32], 0).unwrap();
    assert_eq!(strong_sp.len(), 1);
    assert_eq!(strong_sp[0].spending_tx_fk, spend_fk);
    assert_eq!(
        s.txs.sample_reset_body_decodes(),
        0,
        "spender walks resolve the create by head probe only"
    );

    let ranges = s.tx_body_range_batch(&[create_fk, spend_fk]).unwrap();
    assert_eq!(ranges.len(), 2);
    let full_b = s.get_tx_full(create_fk).unwrap();
    assert_eq!(full_b.0.txid, [10u8; 32]);
    let outs_b = s.get_tx_meta_and_outputs(create_fk).unwrap();
    assert_eq!(outs_b.1.len(), 2);
    let heights = s.tx_height_get_batch(&[spend_fk, create_fk]).unwrap();
    assert_eq!(heights[0], Some(0));

    assert_eq!(s.archived_block_count().unwrap(), 1);
    s.flush_header_archive().unwrap();
    s.flush_for_shutdown().unwrap();

    // repair: strong not on the fence
    s.strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), spend2_fk, hfk)
        .unwrap();
    let cleared = s.repair_class_c_above_tip().unwrap();
    assert!(cleared >= 1);
    assert!(!s.is_confirmed_strong(spend2_fk).unwrap());

    s.flush().unwrap();
    drop(s);

    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.header_count(), 1);
    let s2 = Store::open_or_create_tiny(&dir).unwrap();
    assert_eq!(s2.header_count(), 1);
    drop(s2);

    let dir2 = tmp();
    let s3 = Store::open_or_create_tiny(&dir2).unwrap();
    assert_eq!(s3.header_count(), 0);
    drop(s3);

    assert!(matches!(
        check_meta(std::path::Path::new("/no/such")),
        Err(StoreError::Io { .. })
    ));
    {
        let bad = tmp();
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("meta"), b"xx").unwrap();
        assert!(matches!(check_meta(&bad), Err(StoreError::Corrupt(_))));
        std::fs::write(bad.join("meta"), b"XXXX\x00\x00").unwrap();
        assert!(matches!(check_meta(&bad), Err(StoreError::BadMagic)));
        let mut good_magic = STORE_MAGIC.to_vec();
        good_magic.extend_from_slice(&0u16.to_le_bytes());
        std::fs::write(bad.join("meta"), &good_magic).unwrap();
        match check_meta(&bad) {
            Err(StoreError::Corrupt(m)) => assert_eq!(m, PRE22_WIPE),
            other => panic!("meta 0: {other:?}"),
        }
        let mut v13 = STORE_MAGIC.to_vec();
        v13.extend_from_slice(&13u16.to_le_bytes());
        std::fs::write(bad.join("meta"), &v13).unwrap();
        match check_meta(&bad) {
            Err(StoreError::Corrupt(m)) => assert_eq!(m, PRE22_WIPE),
            other => panic!("meta 13: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&bad);
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn open_schema24_occupied_creates_zero_txstat() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        let item = coinbase_item([0x25u8; 32], vec![OutputRecord::unspent(50, vec![0x51])]);
        s.put_tx_full_batch_indexed(&[item], true).unwrap();
        s.flush().unwrap();
    }
    std::fs::remove_file(dir.join("txstat.body")).unwrap();
    write_store_meta_ver(&dir, 24);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txstat.count(), 1);
    assert_eq!(s.txs.txstat.get_cell(Fk(1)).unwrap(), [0u8; 8]);
    drop(s);
    assert_eq!(read_store_meta_ver(&dir), SCHEMA_VERSION);
    assert!(dir.join("txstat.body").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_meta_refuses_schema_past_this_binary() {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let mut bytes = STORE_MAGIC.to_vec();
    bytes.extend_from_slice(&(SCHEMA_VERSION + 1).to_le_bytes());
    std::fs::write(dir.join("meta"), bytes).unwrap();
    assert!(matches!(
        check_meta(&dir),
        Err(StoreError::BadSchema(v)) if v == SCHEMA_VERSION + 1
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_store_meta_ver(dir: &Path, ver: u16) {
    let mut bytes = STORE_MAGIC.to_vec();
    bytes.extend_from_slice(&ver.to_le_bytes());
    std::fs::write(dir.join("meta"), bytes).unwrap();
}

fn read_store_meta_ver(dir: &Path) -> u16 {
    let bytes = std::fs::read(dir.join("meta")).unwrap();
    u16::from_le_bytes([bytes[4], bytes[5]])
}

#[test]
fn open_schema_before_22_refuses_wipe_and_ibd() {
    for ver in [21u16, 13u16] {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.flush().unwrap();
        }
        write_store_meta_ver(&dir, ver);
        match Store::open_tiny(&dir) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, PRE22_WIPE, "meta {ver}");
                eprintln!("meta {ver} StoreError::Corrupt: {m}");
            }
            Ok(_) => panic!("meta {ver} opened"),
            Err(other) => panic!("meta {ver}: {other}"),
        }
        assert_eq!(
            read_store_meta_ver(&dir),
            ver,
            "meta {ver} must not rewrite"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn ovf_data_len(dir: &Path) -> u64 {
    let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
    let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    logical - rbitcoin_store::file::FILE_HEADER_LEN as u64
}

fn write_legacy_create_ovf_v22(dir: &Path, rows: &[(u64, u16, u16)]) {
    use rbitcoin_primitives::TableKind;
    use rbitcoin_store::file::FILE_HEADER_LEN;
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

fn snapshot_create_ovf_as_v22_12b(dir: &Path) {
    use rbitcoin_store::file::FILE_HEADER_LEN;
    let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
    let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let data = &bytes[FILE_HEADER_LEN..logical as usize];
    let mut rows = Vec::new();
    if data.len().is_multiple_of(16)
        && (!data.len().is_multiple_of(12) || { data.len() >= 16 && data[10..12] == [0, 0] })
    {
        for chunk in data.chunks_exact(16) {
            let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let st = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
            let n = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
            rows.push((fk, st as u16, n as u16));
        }
    } else {
        for chunk in data.chunks_exact(12) {
            let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let st = u16::from_le_bytes(chunk[8..10].try_into().unwrap());
            let n = u16::from_le_bytes(chunk[10..12].try_into().unwrap());
            rows.push((fk, st, n));
        }
    }
    write_legacy_create_ovf_v22(dir, &rows);
}

#[test]
fn put_full_fat_txout_past_u16_strides() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let script = vec![0u8; 524_288];
    let item = coinbase_item([0x89u8; 32], vec![OutputRecord::unspent(0, script.clone())]);
    let fk = s.put_tx_full_batch_indexed(&[item], true).unwrap()[0];
    let (tx, _ins, outs) = s.get_tx_full(fk).unwrap();
    assert_eq!(tx.output_count, 1);
    assert_eq!(outs[0].script.len(), 524_288);
    drop(s);
    let s = Store::open_tiny(&dir).unwrap();
    let (_tx, _ins, outs) = s.get_tx_full(fk).unwrap();
    assert_eq!(outs[0].script.len(), 524_288);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_schema22_occupied_rewrites_create_ovf_12_to_16() {
    let dir = tmp();
    let n_out = 256u32;
    {
        let s = Store::create_tiny(&dir).unwrap();
        let outs = vec![OutputRecord::unspent(1, vec![0x51]); n_out as usize];
        let item = coinbase_item([0x22u8; 32], outs);
        s.put_tx_full_batch_indexed(&[item], true).unwrap();
        s.flush().unwrap();
    }
    snapshot_create_ovf_as_v22_12b(&dir);
    write_store_meta_ver(&dir, 22);
    assert_eq!(ovf_data_len(&dir), 12);
    let s = Store::open_tiny(&dir).unwrap();
    let (tx, _ins, outs) = s.get_tx_full(Fk(1)).unwrap();
    assert_eq!(tx.output_count, n_out);
    assert_eq!(outs.len(), n_out as usize);
    drop(s);
    assert_eq!(read_store_meta_ver(&dir), SCHEMA_VERSION);
    assert_eq!(ovf_data_len(&dir), 16);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_full_and_seqsigwit_prevouts_at() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let item = (
        TxRecord {
            txid: [8u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let fk = s.put_tx_full_batch_indexed(&[item], true).unwrap()[0];
    let (m, prevs) = s.get_tx_meta_and_prevouts(fk).unwrap();
    assert_eq!(m.input_count, 1);
    assert_eq!(prevs.len(), 1);
    assert!(s.tx_seqsigwit_range(fk).unwrap().1 > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_unlinks_scripthash_run_leftovers_and_keeps_seal() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let runs = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(runs.join("000001.run"), b"not a catalog").unwrap();
    std::fs::write(runs.join("SEAL"), b"seal").unwrap();
    Store::open_tiny(&dir).unwrap();
    assert!(
        !runs.join("000001.run").exists(),
        "leftover run must be unlinked"
    );
    assert_eq!(std::fs::read(runs.join("SEAL")).unwrap(), b"seal");
    let dir2 = tmp();
    {
        let s = Store::create_tiny(&dir2).unwrap();
        s.flush().unwrap();
    }
    assert!(!dir2.join("scripthash.runs").exists());
    Store::open_tiny(&dir2).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn open_fails_when_scripthash_runs_cannot_be_read() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let runs = dir.join("scripthash.runs");
    std::fs::write(&runs, b"not a directory").unwrap();
    let msg = match Store::open_tiny(&dir) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("open must fail when leftovers cannot be read"),
    };
    assert!(
        msg.contains("scripthash.runs"),
        "open must fail when leftovers cannot be read: {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn class_a_v17_roundtrip_templates() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let p2pkh = {
        let mut sc = vec![0x76, 0xa9, 0x14];
        sc.extend_from_slice(&[0x11u8; 20]);
        sc.extend_from_slice(&[0x88, 0xac]);
        sc
    };
    let p2tr = {
        let mut sc = vec![0x51, 0x20];
        sc.extend_from_slice(&[0x55u8; 32]);
        sc
    };
    let p2wsh = {
        let mut sc = vec![0x00, 0x20];
        sc.extend_from_slice(&[0x44u8; 32]);
        sc
    };
    let opreturn = {
        let data = [0xdeu8, 0xad, 0xbe, 0xef];
        let mut sc = vec![0x6a, data.len() as u8];
        sc.extend_from_slice(&data);
        sc
    };
    let p2a = vec![0x51, 0x02, 0x4e, 0x73];
    let high_ver = i32::from_le_bytes([0x00, 0x00, 0x00, 0x80]);

    let v1 = (
        TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(1, p2pkh.clone())],
    );
    let v2 = (
        TxRecord {
            txid: [2u8; 32],
            version: 2,
            locktime: 0,
            input_count: 1,
            output_count: 2,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![
            OutputRecord::unspent(2, p2tr.clone()),
            OutputRecord::unspent(3, p2wsh.clone()),
        ],
    );
    let v3 = (
        TxRecord {
            txid: [3u8; 32],
            version: 3,
            locktime: 0,
            input_count: 1,
            output_count: 2,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![
            OutputRecord::unspent(0, opreturn.clone()),
            OutputRecord::unspent(4, p2a.clone()),
        ],
    );
    let hi = (
        TxRecord {
            txid: [4u8; 32],
            version: high_ver,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(5, vec![0x51])],
    );
    let fks = s
        .put_tx_full_batch_indexed(&[v1, v2, v3, hi], true)
        .unwrap();
    assert_eq!(fks.len(), 4);

    let (off, len) = s.txs.body_range(fks[0]).unwrap();
    let raw = s.txs.with_body_span(off, len, |b| Ok(b.to_vec())).unwrap();
    assert_eq!(raw[0] & 0x80, 0x80, "LAYOUT17 on first create");
    let (rec1, outs1) = s.get_tx_meta_and_outputs(fks[0]).unwrap();
    assert_eq!(rec1.version, 1);
    assert_eq!(outs1[0].script, p2pkh);

    let (rec2, outs2) = s.get_tx_meta_and_outputs(fks[1]).unwrap();
    assert_eq!(rec2.version, 2);
    assert_eq!(outs2[0].script, p2tr);
    assert_eq!(outs2[1].script, p2wsh);
    let (off2, len2) = s.txs.body_range(fks[1]).unwrap();
    let raw2 = s
        .txs
        .with_body_span(off2, len2, |b| Ok(b.to_vec()))
        .unwrap();
    let (_, meta_n) = TxRecord::decode_body_meta(&raw2).unwrap();
    assert_eq!(
        raw2[meta_n] & 0x0f,
        rbitcoin_store::compact::SCRIPT_KIND_V17_P2TR
    );

    let (rec3, outs3) = s.get_tx_meta_and_outputs(fks[2]).unwrap();
    assert_eq!(rec3.version, 3);
    assert_eq!(outs3[0].script, opreturn);
    assert_eq!(outs3[1].script, p2a);

    let (rec4, outs4) = s.get_tx_meta_and_outputs(fks[3]).unwrap();
    assert_eq!(rec4.version, high_ver);
    assert_eq!(outs4[0].script, vec![0x51]);

    let (soff, slen) = s.tx_spent_range(fks[1]).unwrap();
    assert_eq!(slen, 2 * OutputRecord::SPENT_SLOT_LEN as u64);
    assert_eq!(
        s.txs.get_output_spender_meta_at(soff, slen, 0).unwrap().1,
        Fk::NULL
    );

    s.flush().unwrap();
    drop(s);
    let s2 = Store::open_tiny(&dir).unwrap();
    let (_, outs) = s2.get_tx_meta_and_outputs(fks[1]).unwrap();
    assert_eq!(outs[0].script, p2tr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mid-barrier kill: pre-tip flush only must not advance durable tip.
///
/// Simulates kill after strong/height durable but before confirmed flush.
/// Reopen: tip stays old; strong above tip is repaired; no permanent unstrong tip.
#[test]
fn class_c_barrier_pre_tip_only_does_not_advance_tip() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        // Genesis tip: height 0 → header fk 1, one strong tx.
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
            .unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(0)));

        // In-RAM tip extension (height 1) + strong for new txs — no full barrier.
        s.strong_tx
            .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), 3, Fk(2))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(2), 3)
            .unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
            .unwrap();
        // Mid-barrier: strong/height durable, confirmed still unflushed.
        s.flush_class_c_pre_tip().unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
        // Drop without flushing confirmed (kill mid-barrier).
    }
    let s = Store::open_tiny(&dir).unwrap();
    // Durable tip must remain 0 — confirmed was not in pre_tip flush.
    assert_eq!(
        s.confirmed.tip_height(),
        Some(Height(0)),
        "mid-barrier kill must not leave tip ahead of last full barrier"
    );
    assert!(s.strong_tx.is_strong(Fk(1)).unwrap());
    // New strong may be durable above tip; repair clears them.
    let cleared = s.repair_class_c_above_tip().unwrap();
    assert!(
        cleared >= 1,
        "strong/height above tip should be repairable (got cleared={cleared})"
    );
    assert!(!s.is_confirmed_strong(Fk(2)).unwrap());
    assert!(!s.is_confirmed_strong(Fk(3)).unwrap());
    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Full barrier: tip + strong both durable; reopen matches.
#[test]
fn class_c_barrier_full_flush_reopen_tip_with_strong() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
            .unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();

        s.strong_tx
            .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), 2, Fk(2))
            .unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(2), 2)
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();
    }
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
    assert_eq!(s.confirmed.get(Height(1)).unwrap(), Some(Fk(2)));
    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    assert!(s.is_confirmed_strong(Fk(2)).unwrap());
    assert!(s.is_confirmed_strong(Fk(3)).unwrap());
    assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// RPC TipOnly misses write-behind until drain. Confirm leftover is load-owned.
#[test]
fn get_fk_by_txid_tip_hits_pending_before_head_drain() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
        .unwrap();
    s.strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
        .unwrap();
    let item = coinbase_item([0x51; 32], vec![OutputRecord::unspent(1, vec![0x51])]);
    let fks = s
        .put_tx_full_batch_indexed(&[item], /*index=*/ false)
        .unwrap();
    s.txs.head_note_pending(&[([0x51; 32], fks[0])]);
    s.rebuild_height_fence().unwrap();
    assert_eq!(
        s.get_fk_by_txid_tip(&[0x51; 32]).unwrap(),
        None,
        "pre-drain TipOnly is durable head only"
    );
    assert_eq!(s.txs.head_drain_pending().unwrap(), 1);
    assert_eq!(s.get_fk_by_txid_tip(&[0x51; 32]).unwrap(), Some(fks[0]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `confirmed.set` publishes tip HWM; fence stays at the last extend.
/// In-flight prune must use [`Store::fence_tip_height`], not tip HWM
/// (mainnet 945952: leftover TipOnly wiped open-head parents).
#[test]
fn fence_tip_height_lags_unextended_confirmed() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
        .unwrap();
    s.rebuild_height_fence().unwrap();
    assert_eq!(s.tip_height(), Some(Height(0)));
    assert_eq!(s.fence_tip_height(), Some(0));

    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(2), 2)
        .unwrap();
    assert_eq!(
        s.tip_height(),
        Some(Height(1)),
        "set_many/set publishes tip"
    );
    assert_eq!(
        s.fence_tip_height(),
        Some(0),
        "fence stays at last extend until height_fence_extend"
    );
    assert_eq!(s.tx_height_get(Fk(2)).unwrap(), None);

    s.height_fence_extend(Height(1), Fk(2)).unwrap();
    assert_eq!(s.fence_tip_height(), Some(1));
    assert_eq!(s.tx_height_get(Fk(2)).unwrap(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Confirmed tip + missing `header_txs` range: extend must not return `Ok`
/// and leave `height_of` None (live TipOnly hole; restart rebuild heals).
#[test]
fn height_fence_extend_missing_header_txs_is_not_ok_hole() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
        .unwrap();
    s.rebuild_height_fence().unwrap();

    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
        .unwrap();
    let err = s
        .height_fence_extend(Height(1), Fk(2))
        .expect_err("missing header_txs must not silently skip");
    let msg = err.to_string();
    assert!(
        msg.contains("header_txs"),
        "shipped error must name the missing range: {msg}"
    );
    assert_eq!(
        s.tx_height_get(Fk(2)).unwrap(),
        None,
        "must not invent a connected height"
    );
    assert_eq!(s.fence_tip_height(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unknown prev_txid: no probe cands → leftover miss is `head`, not body/idx.
#[test]
fn tiponly_unknown_txid_miss_on_head() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let miss = [0x11u8; 32];
    let hits = s.get_fk_by_txid_batch(&[miss]).unwrap();
    assert!(hits[0].1.is_none());
    let (on, cands) = rbitcoin_store::head_resolve_stats::take_leftover_miss().expect("classified");
    assert_eq!(on, LeftoverMissOn::Head);
    assert_eq!(cands, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Head + txid.body exist, no fence run → TipOnly leftover miss is `fence`.
#[test]
fn tiponly_unconnected_identity_miss_on_fence() {
    use rbitcoin_store::tx_table::OutputRecord;
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let txid = [0x22u8; 32];
    let rec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_count: 0,
        output_count: 1,
    };
    let _fk = s
        .put_tx_full_batch_indexed(
            &[(rec, vec![], vec![OutputRecord::unspent(1, vec![0x51])])],
            true,
        )
        .unwrap()[0];
    let hits = s.get_fk_by_txid_batch(&[txid]).unwrap();
    assert!(
        hits[0].1.is_none(),
        "TipOnly must drop unconnected identity"
    );
    let (on, cands) = rbitcoin_store::head_resolve_stats::take_leftover_miss().expect("classified");
    assert_eq!(on, LeftoverMissOn::Fence);
    assert!(
        cands >= 1,
        "open-head probe must have produced the create fk"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same-page foreigner: leftover TipOnly miss is `body`, and the shipped
/// miss path records a hop dump (A's fk, no body match, empty stop).
#[test]
fn tiponly_same_page_foreigner_records_probe_diag() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let a = [0xAAu8; 32];
    let rec = TxRecord {
        txid: a,
        version: 1,
        locktime: 0,
        input_count: 0,
        output_count: 1,
    };
    let a_fk = s
        .put_tx_full_batch_indexed(
            &[(rec, vec![], vec![OutputRecord::unspent(1, vec![0x51])])],
            true,
        )
        .unwrap()[0];
    let bits = s.txs.head.bits();
    let mix_a = s.txs.secret.mix_txid(&a);
    let page_a = rbitcoin_store::address_head::page_base_for_txid(&mix_a, bits);
    let h1_a = rbitcoin_store::address_head::h1_in_page(&mix_a, bits);
    let mut b = [0xBBu8; 32];
    let mut found = false;
    // Tiny heads take page and h1 from 16 mixed bits (1 in 65536).
    // Half a million draws misses often enough to fail CI; the cap is
    // many times the mean, and the loop stops at the first hit.
    for i in 0u64..8_000_000 {
        b[24..32].copy_from_slice(&i.to_le_bytes());
        let mix_b = s.txs.secret.mix_txid(&b);
        if rbitcoin_store::address_head::page_base_for_txid(&mix_b, bits) == page_a
            && rbitcoin_store::address_head::h1_in_page(&mix_b, bits) == h1_a
        {
            found = true;
            break;
        }
    }
    assert!(found, "need a same-slot miss key (page+h1)");
    let hits = s.get_fk_by_txid_batch(&[b]).unwrap();
    assert!(hits[0].1.is_none(), "B is not in the head");
    // A sits on B's chain but carries another fingerprint, so the probe
    // drops it before identity: the miss is on the head, with no cands.
    let (on, n_cands) =
        rbitcoin_store::head_resolve_stats::take_leftover_miss().expect("classified");
    assert_eq!(on, LeftoverMissOn::Head);
    assert_eq!(n_cands, 0, "fingerprint must skip A, n_cands={n_cands}");
    assert!(
        !rbitcoin_store::head_resolve_stats::leftover_probe_diag_recorded(&b),
        "resolve must not dump this key; leftover caller does"
    );
    s.diagnose_leftover_probe(&b);
    let diag = rbitcoin_store::head_resolve_stats::take_leftover_probe_diag()
        .expect("leftover miss path must record a probe dump");
    assert_eq!(diag.txid, b);
    assert_eq!(diag.page_base, page_a);
    assert!(diag.hit_empty, "hop must stop at empty");
    assert!(
        diag.cands
            .iter()
            .any(|c| c.abs_fk == a_fk.0 && !c.body_match),
        "dump must list A's fk with body≠B, cands={:?}",
        diag.cands
            .iter()
            .map(|c| (c.abs_fk, c.body_match))
            .collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Open `tx.head` page is `page_base_for_txid(mix_txid(txid))`, not raw txid.
#[test]
fn open_head_page_uses_mix_txid_not_raw() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let bits = s.txs.head.bits();
    let mut txid = [0x11u8; 32];
    let mut found = false;
    for i in 0u64..100_000 {
        txid[24..32].copy_from_slice(&i.to_le_bytes());
        let mixed = s.txs.secret.mix_txid(&txid);
        let raw_page = rbitcoin_store::address_head::page_base_for_txid(&txid, bits);
        let mix_page = rbitcoin_store::address_head::page_base_for_txid(&mixed, bits);
        if raw_page != mix_page {
            s.diagnose_leftover_probe(&txid);
            let diag =
                rbitcoin_store::head_resolve_stats::take_leftover_probe_diag().expect("probe dump");
            assert_eq!(diag.page_base, mix_page);
            assert_ne!(diag.page_base, raw_page);
            found = true;
            break;
        }
    }
    assert!(found, "need a txid whose mix moves the open-head page");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lookup / BQ-ahead also use TipOnly `get_fk_by_txid_batch`. A miss there
/// is routine (parent not published yet). Dump + WARN only on leftover.
#[test]
fn tiponly_resolve_miss_does_not_dump_probe_diag() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let miss = [0xCCu8; 32];
    let hits = s.get_fk_by_txid_batch(&[miss]).unwrap();
    assert!(hits[0].1.is_none(), "unknown txid must miss");
    assert!(
        !rbitcoin_store::head_resolve_stats::leftover_probe_diag_recorded(&miss),
        "resolve TipOnly miss must not hop-dump this key; leftover miss path only"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kill after the tip shrink, before unstrong, is repairable.
#[test]
fn class_c_disconnect_tip_first_mid_barrier_is_repairable() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        // Tip 0 + tip 1 fully durable.
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
            .unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
            .unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(2), 2)
            .unwrap();
        s.strong_tx
            .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), 2, Fk(2))
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));

        // Disconnect tip-first: shrink tip + flush confirmed only (kill before unstrong).
        s.confirmed
            .disconnect_tip(&rbitcoin_store::ClassCWrite::for_test(), Height(1))
            .unwrap();
        s.flush_confirmed_only().unwrap();
        // Do not unstrong — simulate kill mid-disconnect.
    }
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(
        s.confirmed.tip_height(),
        Some(Height(0)),
        "tip shrink must be durable after flush_confirmed_only"
    );
    // Strong may still mark height-1 txs; they are not on the new fence.
    assert!(s.strong_tx.is_strong(Fk(2)).unwrap());
    let cleared = s.repair_class_c_above_tip().unwrap();
    assert!(
        cleared >= 1,
        "strong/height above new tip must be repairable (cleared={cleared})"
    );
    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    assert!(!s.is_confirmed_strong(Fk(2)).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Full disconnect barrier sequence (tip shrink → unstrong/height → flush).
#[test]
fn class_c_disconnect_full_sequence_reopen_clean() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 1)
            .unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1))
            .unwrap();
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(2), 2)
            .unwrap();
        s.strong_tx
            .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), 2, Fk(2))
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.flush_class_c_tip().unwrap();

        // Production disconnect order (store half).
        s.confirmed
            .disconnect_tip(&rbitcoin_store::ClassCWrite::for_test(), Height(1))
            .unwrap();
        s.flush_confirmed_only().unwrap();
        s.strong_tx
            .set_unstrong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), 2)
            .unwrap();
        s.height_fence_pop_tip(Height(1));
        s.flush_class_c_after_disconnect_tip().unwrap();
    }
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.confirmed.tip_height(), Some(Height(0)));
    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    assert!(!s.strong_tx.is_strong(Fk(2)).unwrap());
    assert_eq!(s.tx_height_get(Fk(2)).unwrap(), None);
    assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn orphan_class_c_at_tip_height_not_confirmed_strong_and_repairable() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    // Real tip body: txs 1..=2 under header 1.
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 2)
        .unwrap();
    s.strong_tx
        .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 2, Fk(1))
        .unwrap();
    s.rebuild_height_fence().unwrap();
    // Orphan second copy: txs 3..=4 strong, not in header_txs.
    s.strong_tx
        .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(3), 2, Fk(99))
        .unwrap();
    s.flush_class_c_tip().unwrap();

    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    assert!(s.is_confirmed_strong(Fk(2)).unwrap());
    assert!(
        !s.is_confirmed_strong(Fk(3)).unwrap(),
        "orphan at tip height must not be confirmed-strong"
    );
    assert!(!s.is_confirmed_strong(Fk(4)).unwrap());

    let n = s.repair_class_c_above_tip().unwrap();
    assert!(n >= 2, "cleared={n}");
    assert!(!s.strong_tx.is_strong(Fk(3)).unwrap());
    assert_eq!(s.tx_height_get(Fk(3)).unwrap(), None);
    assert!(s.is_confirmed_strong(Fk(1)).unwrap());
    assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// No tip → repair is a no-op; gapped orphans clear as separate runs.
#[test]
fn repair_class_c_above_tip_empty_tip_and_gapped_orphans() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        rbitcoin_log::capture_logs(true);
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let text = logs
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("rbitcoin: class_c repair cleared=0 ranges="),
            "{text}"
        );
        // Tip body 1..=2; orphans 5 and 10 (non-adjacent → two clear runs).
        s.confirmed
            .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
            .unwrap();
        s.header_txs
            .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 2)
            .unwrap();
        s.strong_tx
            .set_strong_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), 2, Fk(1))
            .unwrap();
        s.rebuild_height_fence().unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(5), Fk(99))
            .unwrap();
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(10), Fk(99))
            .unwrap();
        s.flush_class_c_tip().unwrap();
        let n = s.repair_class_c_above_tip().unwrap();
        assert_eq!(n, 2, "cleared gapped orphans");
        assert!(!s.strong_tx.is_strong(Fk(5)).unwrap());
        assert!(!s.strong_tx.is_strong(Fk(10)).unwrap());
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        // Strong not on the fence (same repair as above-tip leftovers).
        s.strong_tx
            .set_strong(&rbitcoin_store::ClassCWrite::for_test(), Fk(20), Fk(1))
            .unwrap();
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 1);
        assert!(!s.strong_tx.is_strong(Fk(20)).unwrap());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Upgrade open paths: missing optional tables recreated; unspent without range.
#[test]
fn store_open_upgrade_missing_tables_and_unspent_no_range() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        let create = coinbase_item([20u8; 32], vec![OutputRecord::unspent(10, vec![0x51])]);
        let fk = s.put_tx_full_batch_indexed(&[create], true).unwrap()[0];
        s.flush().unwrap();
        drop(s);
        // Remove optional tables so open recreate branches run.
        let _ = std::fs::remove_file(dir.join("scripthash.body"));
        let _ = std::fs::remove_dir_all(dir.join("scripthash.body"));
        let _ = std::fs::remove_dir_all(dir.join("scripthash.ovf"));
        let _ = std::fs::remove_dir_all(dir.join("scripthash.head"));
        let _ = std::fs::remove_file(dir.join("scripthash.head"));
        let _ = std::fs::remove_file(dir.join("header_txs_first.body"));
        let _ = std::fs::remove_file(dir.join("header_txs_count.body"));
        let _ = std::fs::remove_file(dir.join("tx_height.body"));
        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(s.get_tx(fk).unwrap().txid, [20u8; 32]);
        let u = s.unspent_create_vouts(fk, &[0], None).unwrap();
        assert_eq!(u, vec![0]);
        assert!(s.unspent_create_vouts(fk, &[], None).unwrap().is_empty());
        let batch = s
            .unspent_create_vouts_batch(&[(fk, vec![0u32]), (fk, vec![])])
            .unwrap();
        assert_eq!(batch[0], vec![0]);
        assert!(batch[1].is_empty());
        assert!(!s.has_confirmed_strong_spender_create(fk, 0, None).unwrap());
        assert!(!s.has_confirmed_strong_spender(&[20u8; 32], 0).unwrap());
        assert!(s.spenders_raw(&[20u8; 32], 0).unwrap().is_empty());
        assert!(s.spenders(&[9u8; 32], 0).unwrap().is_empty());
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
        drop(s);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unspent_create_vouts_batch_matches_serial() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let mut fks = Vec::new();
    for i in 1u8..=4 {
        let item = coinbase_item(
            [i; 32],
            vec![
                OutputRecord::unspent(10, vec![0x51]),
                OutputRecord::unspent(11, vec![0x51]),
            ],
        );
        fks.push(s.put_tx_full_batch_indexed(&[item], true).unwrap()[0]);
    }
    s.flush().unwrap();
    let items: Vec<(Fk, Vec<u32>)> = fks.iter().map(|fk| (*fk, vec![0, 1])).collect();
    let batch = s.unspent_create_vouts_batch(&items).unwrap();
    assert_eq!(batch.len(), 4);
    for (i, fk) in fks.iter().enumerate() {
        assert_eq!(
            batch[i],
            s.unspent_create_vouts(*fk, &[0, 1], None).unwrap(),
            "fk {fk:?}"
        );
    }
    assert!(s.unspent_create_vouts_batch(&[]).unwrap().is_empty());
    // A create with no locator fails in spent_range. The None arm must
    // return that error, not a later spent-body metas error.
    let missing = Fk(9_000_001);
    let err = s.unspent_create_vouts(missing, &[0, 1], None).unwrap_err();
    let range_err = s.txs.spent_range(missing).unwrap_err();
    assert!(
        matches!(
            (&err, &range_err),
            (StoreError::NotFound, StoreError::NotFound)
        ),
        "missing create is the spent_range error, not a metas error: {err:?} vs {range_err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keep_unspent_vout_subsequence_keeps_in_order_subset() {
    let mut v = vec![0u32, 1, 2, 3];
    keep_unspent_vout_subsequence(&mut v, &[0, 2], |x| *x);
    assert_eq!(v, vec![0, 2]);

    let mut all = vec![5u32, 7];
    keep_unspent_vout_subsequence(&mut all, &[5, 7], |x| *x);
    assert_eq!(all, vec![5, 7]);

    let mut none = vec![1u32, 2];
    keep_unspent_vout_subsequence(&mut none, &[], |x| *x);
    assert!(none.is_empty());
}

/// Two Class A rows for one txid, the older connected and the newer not
/// (a competing block at the same height, archived and then reorged
/// away): the tip resolvers pick the connected row and the any-row
/// resolve the newest. The last beat stamps a connected spender on the
/// connected row's vout 0 at height 1; the newer row has no spenders, so
/// the spentness probe and the spender walk must read the connected row.
/// A store unit, not a journey: the result is pure (which row each reader
/// picks), and reaching two rows for one txid through a session needs a
/// competing stale block, a fixture cost with no extra observation.
#[test]
fn resolve_txid_prefers_connected_over_newer_unconnected() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let txid = [0xABu8; 32];
    let rec = |lock| TxRecord {
        txid,
        version: 1,
        locktime: lock,
        input_count: 0,
        output_count: 1,
    };
    let out = vec![OutputRecord::unspent(1, vec![0x51])];
    let old = s
        .put_tx_full_batch_indexed(&[(rec(1), vec![], out.clone())], true)
        .unwrap()[0];
    let new = s
        .put_tx_full_batch_indexed(&[(rec(2), vec![], out)], true)
        .unwrap()[0];
    assert_ne!(old, new);
    assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(new));
    assert_eq!(s.get_fk_by_txid_tip(&txid).unwrap(), None);
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), old, 1)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.rebuild_height_fence().unwrap();
    assert_eq!(
        s.get_fk_by_txid_tip(&txid).unwrap(),
        Some(old),
        "connected older row must win"
    );
    assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(old));
    let batch_tip = s
        .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
        .unwrap();
    assert_eq!(batch_tip[0].1.map(|(f, _)| f), Some(old));
    let batch_any = s
        .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
        .unwrap();
    assert_eq!(batch_any[0].1.map(|(f, _)| f), Some(old));

    let spender = s
        .put_tx_full_batch_indexed(
            &[(
                TxRecord {
                    txid: [0xBAu8; 32],
                    version: 1,
                    locktime: 0,
                    input_count: 1,
                    output_count: 1,
                },
                vec![InputRecord {
                    prev_txid: txid,
                    parent: rbitcoin_store::InputParent::Prevout {
                        create_fk: old,
                        vout: 0,
                    },
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                }],
                vec![OutputRecord::unspent(1, vec![0x51])],
            )],
            true,
        )
        .unwrap()[0];
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), spender, 1)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(2))
        .unwrap();
    s.strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), spender, Fk(2))
        .unwrap();
    s.rebuild_height_fence().unwrap();
    s.put_spend_create(old, 0, spender, 0).unwrap();
    assert!(
        s.has_confirmed_strong_spender(&txid, 0).unwrap(),
        "spentness is probed on the connected create, not the newest row"
    );
    assert_eq!(
        s.spenders(&txid, 0).unwrap()[0].spending_tx_fk,
        spender,
        "spenders walk the connected create"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connected sibling in a **cold** sealed age must beat a newer unconnected
/// hot hit (`TipThenAny` and `TipOnly`). Stopping after the unconnected
/// newer cand would regress to that row.
#[test]
fn tip_then_any_connected_in_cold_beats_unconnected_hot() {
    use rbitcoin_store::address_head::HeadLayout;
    use rbitcoin_store::head_resolve_stats::sealed_age_for_fk;
    use rbitcoin_store::tx_table::OutputRecord;

    fn put_one(s: &Store, txid: [u8; 32], lock: u32) -> Fk {
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: lock,
            input_count: 0,
            output_count: 1,
        };
        let out = vec![OutputRecord::unspent(1, vec![0x51])];
        s.put_tx_full_batch_indexed(&[(rec, vec![], out)], true)
            .unwrap()[0]
    }

    let dir = tmp();
    // bits=8 → 256 slots, seal ~204 keys. Five segments ⇒ oldest age ≥4.
    let s = Store::create_layout_with_head(StoreLayout::tiny(&dir), HeadLayout::new(8).unwrap())
        .unwrap();
    let txid = [0xCDu8; 32];
    let old = put_one(&s, txid, 1);
    let n = 204u32.saturating_mul(5);
    let mut items = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut dummy = [0u8; 32];
        dummy[0..8].copy_from_slice(&(u64::from(i) + 10).to_le_bytes());
        dummy[15] = 0xee;
        items.push((
            TxRecord {
                txid: dummy,
                version: 1,
                locktime: i,
                input_count: 0,
                output_count: 1,
            },
            vec![],
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
    }
    s.put_tx_full_batch_indexed(&items, true).unwrap();
    s.txs.flush_head().unwrap();
    let first = s.txs.head.first_fks_snapshot();
    let age = sealed_age_for_fk(&first, old.0).unwrap_or(0);
    assert!(
        s.txs.head.sealed_segment_count() >= 4,
        "oldest must sit behind newer sealed segments age={age} segs={} sealed={}",
        s.txs.head.segment_count(),
        s.txs.head.sealed_segment_count()
    );
    let new = put_one(&s, txid, 2);
    assert_ne!(old, new);
    let first = s.txs.head.first_fks_snapshot();
    let age_old = sealed_age_for_fk(&first, old.0).unwrap();
    let age_new = sealed_age_for_fk(&first, new.0).unwrap();
    assert!(
        age_old > age_new,
        "old fk must be older than the new row age_old={age_old} age_new={age_new}"
    );

    // Neither connected yet: newest unconnected row for TipThenAny.
    assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(new));
    assert_eq!(
        s.get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
            .unwrap()[0]
            .1
            .map(|(f, _)| f),
        Some(new),
        "batch TipThenAny must keep newer unconnected when cold has no connected"
    );
    assert_eq!(
        s.get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
            .unwrap()[0]
            .1,
        None
    );

    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), old, 1)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    s.rebuild_height_fence().unwrap();

    assert_eq!(s.get_fk_by_txid_tip(&txid).unwrap(), Some(old));
    assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(old));
    let batch_tip = s
        .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
        .unwrap();
    assert_eq!(
        batch_tip[0].1.map(|(f, _)| f),
        Some(old),
        "TipOnly must take connected cold sibling, not unconnected hot"
    );
    let batch_any = s
        .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
        .unwrap();
    assert_eq!(
        batch_any[0].1.map(|(f, _)| f),
        Some(old),
        "TipThenAny must take connected cold sibling over newer unconnected hot"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_does_not_write_archive_epoch() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    assert!(
        !dir.join("archive_epoch").exists(),
        "unread leftover must not be created"
    );
    assert!(dir.join("spent.ovf").exists());
    assert!(!dir.join("spenders.body").exists());
    assert!(!dir.join("tx.body").exists());
    assert!(!dir.join("wire").exists());
    s.flush().unwrap();
    drop(s);
    std::fs::write(dir.join("archive_epoch"), b"junk").unwrap();
    std::fs::create_dir_all(dir.join("wire")).unwrap();
    std::fs::write(dir.join("wire").join("leftover"), b"x").unwrap();
    std::fs::write(dir.join("sp_tweaks.idx"), b"old-idx").unwrap();
    std::fs::write(dir.join("sp_tweaks.body"), b"old-body").unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert!(!dir.join("archive_epoch").exists());
    assert!(!dir.join("wire").exists());
    assert!(!dir.join("sp_tweaks.idx").is_file());
    assert!(!dir.join("sp_tweaks.body").is_file());
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_does_not_write_tx_height_and_fence_has_reorg_holes() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    assert!(
        !dir.join("tx_height.body").exists(),
        "live create must not write tx_height.body"
    );
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(1), Fk(1), 2)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), Fk(1))
        .unwrap();
    // Discarded block used fks 3..=5 under header 2 (not confirmed).
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(2), Fk(3), 3)
        .unwrap();
    s.header_txs
        .put_range(&rbitcoin_store::ClassCWrite::for_test(), Fk(3), Fk(6), 2)
        .unwrap();
    s.confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(1), Fk(3))
        .unwrap();
    s.rebuild_height_fence().unwrap();
    assert_eq!(s.tx_height_get(Fk(1)).unwrap(), Some(0));
    assert_eq!(s.tx_height_get(Fk(3)).unwrap(), None);
    assert_eq!(s.tx_height_get(Fk(5)).unwrap(), None);
    assert_eq!(s.tx_height_get(Fk(6)).unwrap(), Some(1));
    s.flush().unwrap();
    drop(s);
    assert!(!dir.join("tx_height.body").exists());
    // Leftover 15 file is unlinked on open.
    std::fs::write(dir.join("tx_height.body"), b"junk").unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert!(!dir.join("tx_height.body").exists());
    assert_eq!(s.tx_height_get(Fk(5)).unwrap(), None);
    assert_eq!(s.tx_height_get(Fk(6)).unwrap(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_renames_legacy_inwit_stem() {
    let dir = tmp();
    Store::create_tiny(&dir).unwrap();
    std::fs::rename(dir.join("seqsigwit.body"), dir.join("inwit.body")).unwrap();
    std::fs::rename(dir.join("seqsigwit.loc"), dir.join("inwit.loc")).unwrap();
    Store::open_tiny(&dir).unwrap();
    assert!(dir.join("seqsigwit.body").is_file());
    assert!(dir.join("seqsigwit.loc").is_file());
    assert!(!dir.join("inwit.body").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_renames_legacy_inputs_stem() {
    let dir = tmp();
    Store::create_tiny(&dir).unwrap();
    std::fs::rename(dir.join("input.loc"), dir.join("inputs.loc")).unwrap();
    std::fs::rename(dir.join("input.off"), dir.join("inputs.off")).unwrap();
    std::fs::rename(dir.join("input.body"), dir.join("inputs.body")).unwrap();
    Store::open_tiny(&dir).unwrap();
    assert!(dir.join("input.loc").is_file());
    assert!(dir.join("input.body").is_file());
    assert!(!dir.join("inputs.loc").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn split_create_puts_seqsigwit_only_on_cold() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    let s = Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    assert_eq!(s.path(), hot.as_path());
    assert_eq!(s.cold_path(), Some(cold.as_path()));
    assert!(hot.join("txout.body").is_file());
    assert!(hot.join("spent.body").is_file());
    assert!(!hot.join("seqsigwit.body").exists());
    assert!(!hot.join("seqsigwit.loc").exists());
    assert!(cold.join("seqsigwit.body").is_file());
    assert!(cold.join("seqsigwit.loc").is_file());
    assert!(!hot.join("txstat.body").exists());
    assert!(!hot.join("input.loc").exists());
    assert!(cold.join("txstat.body").is_file());
    assert!(cold.join("input.loc").is_file());
    assert!(cold.join("input.body").is_file());
    assert!(hot.join(SEQSIGWIT_RELOC_NAME).is_file());
    drop(s);
    let s = Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    assert_eq!(s.cold_path(), Some(cold.as_path()));
    let hot_n = dir_file_bytes(&hot);
    let cold_n = dir_file_bytes(&cold);
    assert!(hot_n > 0 && cold_n > 0);
    assert_eq!(s.datadir_bytes(), hot_n.saturating_add(cold_n));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_open_without_cold_flag_refuses_reloc() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    match Store::open_tiny(&hot) {
        Ok(_) => panic!("must refuse when seqsigwit.reloc is present"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("datadir-cold"), "{msg}");
            assert!(msg.contains(SEQSIGWIT_RELOC_NAME), "{msg}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_refuses_seqsigwit_left_in_hot() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    Store::create_tiny(&hot).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
        Ok(_) => panic!("must refuse leftover seqsigwit in hot"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("move seqsigwit.body"), "{msg}");
            assert!(msg.contains("seqsigwit.loc"), "{msg}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_refuses_seqsigwit_in_both_dirs() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    Store::create_tiny(&hot).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    std::fs::copy(hot.join("seqsigwit.body"), cold.join("seqsigwit.body")).unwrap();
    match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
        Ok(_) => panic!("must refuse dual seqsigwit copies"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("both"), "{msg}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_refuses_blockfilter_left_in_hot() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    std::fs::create_dir_all(hot.join("blockfilter.idx")).unwrap();
    match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
        Ok(_) => panic!("must refuse blockfilter left on the hot store"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("blockfilter.idx"), "{msg}");
            assert!(msg.contains("move"), "{msg}");
            assert!(msg.contains(cold.to_str().unwrap()), "{msg}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_refuses_sp_tweaks_in_both_dirs() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    std::fs::create_dir_all(hot.join("sp_tweaks.body")).unwrap();
    std::fs::create_dir_all(cold.join("sp_tweaks.body")).unwrap();
    match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
        Ok(_) => panic!("must refuse sp_tweaks in both stores"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("sp_tweaks.body"), "{msg}");
            assert!(msg.contains("both"), "{msg}");
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_roundtrip_create_fk_and_seqsigwit_range() {
    let root = tmp();
    let hot = root.join("hot");
    let cold = root.join("cold");
    let s = Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    let item = coinbase_item([9u8; 32], vec![OutputRecord::unspent(1, vec![0x51])]);
    let fks = s
        .txs
        .put_full_batch_indexed(std::slice::from_ref(&item), true)
        .unwrap();
    assert_eq!(fks.len(), 1);
    let range = s.tx_seqsigwit_range(fks[0]).unwrap();
    assert!(range.1 > 0);
    s.flush().unwrap();
    drop(s);
    let s = Store::open_or_create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
    assert_eq!(s.txs.count(), 1);
    let range = s.tx_seqsigwit_range(fks[0]).unwrap();
    assert!(range.1 > 0);
    assert!(!hot.join("seqsigwit.body").exists());
    let _ = std::fs::remove_dir_all(&root);
}
