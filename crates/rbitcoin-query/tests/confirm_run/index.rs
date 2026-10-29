use bitcoin::hashes::Hash;
use bitcoin::{Amount, Transaction, TxOut};
use rbitcoin_consensus::silent_payments::tweak_from_tx;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::confirm_run::index::*;
use rbitcoin_query::confirm_run::{LoadedBatch, Prepared};
use rbitcoin_query::testutil::tiny_query_labeled;
use rbitcoin_query::Query;
use std::sync::Arc;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::hash160;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{OutPoint, Sequence, TxIn, Witness};

use rbitcoin_consensus::{
    genesis_block, mine_empty_regtest, mine_regtest_paying, ChainParams, Milestone,
};
use rbitcoin_query::sp_read::tweak_records_from_window;
use rbitcoin_query::{accept_and_connect_block, confirm_wire_run};

fn keys() -> (Vec<u8>, bitcoin::ScriptBuf, bitcoin::ScriptBuf) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let ser = pk.serialize().to_vec();
    let h160 = hash160::Hash::hash(&ser);
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(h160.as_ref());
    let (xonly, _) = pk.x_only_public_key();
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&xonly.serialize());
    (
        ser,
        bitcoin::ScriptBuf::from_bytes(p2wpkh),
        bitcoin::ScriptBuf::from_bytes(p2tr),
    )
}

fn enable(q: &Query) {
    q.set_block_filter_index(true).unwrap();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
}

fn go_live(q: &Query) {
    rbitcoin_query::prepare_live_indexes(q).unwrap();
}

fn assert_sealed_matches_window(q: &Query, tip: u32) {
    assert_eq!(q.filter_index_next(), Some(tip + 1));
    assert_eq!(q.tweak_index_next(), Some(tip + 1));
    for h in 0..=tip {
        let stored = q.basic_filter_at(h).unwrap().unwrap().0;
        let heights = q.index_heights(h, h, Some(0)).unwrap();
        let window = q.read_index_window(&heights).unwrap();
        let expect = q.basic_filter_from_window(&window, 0).unwrap();
        assert_eq!(stored, expect.content, "filter h={h}");
        let recs = tweak_records_from_window(&window, 0).unwrap();
        let want: Vec<[u8; 33]> = recs.into_iter().flatten().collect();
        let got = q.load_thin_tweaks(Height(h)).unwrap().unwrap_or_default();
        let got: Vec<[u8; 33]> = got.into_iter().map(|r| r.tweak).collect();
        assert_eq!(got, want, "tweaks h={h}");
    }
}

/// Three roles in one batch: a P2WPKH coinbase, a same-batch spend into
/// P2TR once that coinbase is mature, and the blocks between them.
#[test]
fn live_batch_matches_window_and_reaches_tip() {
    let _gate = rbitcoin_consensus::script_pool::steal_test_gate();
    let (_dir, q) = tiny_query_labeled("idx-live");
    enable(&q);
    go_live(&q);
    let params = ChainParams::regtest();
    let ms = Milestone::height(u32::MAX);
    let genesis = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height(0), &genesis, ms).unwrap();

    let (ser, p2wpkh, p2tr) = keys();
    let spend_h = 101u32;
    let mut blocks = Vec::new();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut pay_value = Amount::ZERO;
    let mut pay_txid = None;
    for h in 1..=spend_h {
        time += 600;
        let block = if h == 1 {
            mine_regtest_paying(prev, time, h, p2wpkh.clone(), Vec::new())
        } else if h == spend_h {
            let txid = pay_txid.expect("paying coinbase");
            let spend = bitcoin::Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(txid, 0),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[vec![0u8; 64].as_slice(), ser.as_slice()]),
                }],
                output: vec![TxOut {
                    value: pay_value,
                    script_pubkey: p2tr.clone(),
                }],
            };
            let child = bitcoin::Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(spend.compute_txid(), 0),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: pay_value,
                    script_pubkey: p2tr.clone(),
                }],
            };
            mine_regtest_paying(prev, time, h, p2wpkh.clone(), vec![spend, child])
        } else {
            mine_empty_regtest(prev, time, h)
        };
        if h == 1 {
            pay_value = block.txdata[0].output[0].value;
            pay_txid = Some(block.txdata[0].compute_txid());
        }
        prev = block.block_hash();
        time = block.header.time;
        blocks.push((Height(h), block));
    }
    confirm_wire_run(&q, &params, ms, &blocks).unwrap();
    assert_sealed_matches_window(&q, spend_h);
    let rows = q.load_thin_tweaks(Height(spend_h)).unwrap().unwrap();
    assert_eq!(
        rows.len(),
        2,
        "the P2TR spend and its same-block child are eligible"
    );
}

#[test]
fn far_watermark_does_not_advance() {
    let _gate = rbitcoin_consensus::script_pool::steal_test_gate();
    let (_dir, q) = tiny_query_labeled("idx-gap");
    let params = ChainParams::regtest();
    let ms = Milestone::height(u32::MAX);
    let genesis = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height(0), &genesis, ms).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=4 {
        time += 600;
        let block = mine_empty_regtest(prev, time, h);
        accept_and_connect_block(&q, &params, Height(h), &block, ms).unwrap();
        prev = block.block_hash();
        time = block.header.time;
    }
    enable(&q);
    rbitcoin_query::index_writebehind::prepare_live_indexes_limited(&q, 2).unwrap();
    assert!(!q.index_live());
    assert_eq!(q.filter_index_next(), Some(0));
    time += 600;
    let block = mine_empty_regtest(prev, time, 5);
    confirm_wire_run(&q, &params, ms, &[(Height(5), block)]).unwrap();
    assert_eq!(q.tip_height(), Some(Height(5)));
    assert_eq!(q.filter_index_next(), Some(0));
    assert_eq!(q.tweak_index_next(), Some(0));
}

#[test]
fn startup_seals_a_short_gap_then_the_batch_appends() {
    let _gate = rbitcoin_consensus::script_pool::steal_test_gate();
    let (_dir, q) = tiny_query_labeled("idx-repair");
    let params = ChainParams::regtest();
    let ms = Milestone::height(u32::MAX);
    let genesis = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height(0), &genesis, ms).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    enable(&q);
    go_live(&q);
    assert!(q.index_live());
    assert_eq!(q.filter_index_next(), Some(2));
    let b2 = mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
    confirm_wire_run(&q, &params, ms, &[(Height(2), b2)]).unwrap();
    assert_sealed_matches_window(&q, 2);
}

/// Filters still at genesis and tweaks at a later origin are two holes.
/// A limit that fits only the tweak hole does not turn live append on.
#[test]
fn startup_repairs_each_fitting_index() {
    let _gate = rbitcoin_consensus::script_pool::steal_test_gate();
    let (_dir, q) = tiny_query_labeled("idx-split");
    let params = ChainParams::regtest();
    let ms = Milestone::height(u32::MAX);
    let genesis = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height(0), &genesis, ms).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=3 {
        time += 600;
        let block = mine_empty_regtest(prev, time, h);
        accept_and_connect_block(&q, &params, Height(h), &block, ms).unwrap();
        prev = block.block_hash();
        time = block.header.time;
    }
    q.set_block_filter_index(true).unwrap();
    q.set_sptweaks_enabled(true, Height(2)).unwrap();
    rbitcoin_query::index_writebehind::prepare_live_indexes_limited(&q, 2).unwrap();
    assert!(!q.index_live());
    assert_eq!(q.filter_index_next(), Some(0));
    assert_eq!(q.tweak_index_next(), Some(4));
    time += 600;
    let block = mine_empty_regtest(prev, time, 4);
    confirm_wire_run(&q, &params, ms, &[(Height(4), block)]).unwrap();
    assert_eq!(q.filter_index_next(), Some(0));
    assert_eq!(q.tweak_index_next(), Some(4));

    let (_dir, both) = tiny_query_labeled("idx-split-both");
    accept_and_connect_block(&both, &params, Height(0), &genesis, ms).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    accept_and_connect_block(&both, &params, Height(1), &b1, ms).unwrap();
    both.set_block_filter_index(true).unwrap();
    both.set_sptweaks_enabled(true, Height(0)).unwrap();
    go_live(&both);
    assert!(both.index_live());
    assert_sealed_matches_window(&both, 1);
}

/// Filters come first, one per block. Tweaks are ranges of at most 32
/// eligible transactions. A coinbase and a transaction with no Taproot
/// output are not jobs. A prevout cell filled before either job runs is
/// what both the filter and the tweak range read.
#[test]
fn index_jobs_are_filters_then_tweak_ranges() {
    let (ser, p2wpkh, p2tr) = keys();
    let batch = two_block_index_batch(&ser, &p2wpkh, &p2tr);
    let jobs = prepare_index_jobs(&batch).expect("prepare");
    let mut lens = Vec::new();
    for job in &jobs.jobs {
        match job {
            IndexJob::Filter(_) => lens.push(0),
            IndexJob::Tweaks(work, txs) => {
                assert!(txs.len() <= TWEAK_TXS_PER_JOB);
                for &ti in txs {
                    let tx = &work.block.txdata[ti];
                    assert!(!tx.is_coinbase(), "coinbase is not a tweak job");
                    assert!(
                        tx_has_taproot_out(tx),
                        "a transaction with no Taproot output is not a tweak job"
                    );
                }
                lens.push(txs.len());
            }
        }
    }
    // Two filters, then 40 and 33 eligible txs split at 32.
    assert_eq!(lens, vec![0, 0, 32, 8, 32, 1]);

    let IndexJob::Filter(filter0) = &jobs.jobs[0] else {
        panic!("first job is a filter");
    };
    let IndexJob::Tweaks(tweak0, _) = &jobs.jobs[2] else {
        panic!("tweak range follows both filters");
    };
    assert!(
        Arc::ptr_eq(filter0, tweak0),
        "filter and tweak share prevouts"
    );

    let ti = 1usize;
    let tx = &filter0.block.txdata[ti];
    let real = prevouts_for_tx(filter0, ti, tx).expect("prevouts");
    assert!(tweak_from_tx(tx, &real).is_some());
    let wrong = vec![TxOut {
        value: real[0].value,
        script_pubkey: bitcoin::ScriptBuf::new(),
    }];
    assert!(tweak_from_tx(tx, &wrong).is_none());
    filter0.prevouts[ti].set(wrong.clone()).expect("seed once");

    for job in &jobs.jobs {
        apply_index_job(job).expect("apply");
    }
    assert_eq!(filter0.prevouts[ti].get(), Some(&wrong));

    let rows = rows_from_heights(&jobs.slots).expect("rows");
    assert_eq!(rows.tweaks.len(), 2);
    assert_eq!(rows.filters.len(), 2);
    for (block_i, (_h, _fk, got)) in rows.tweaks.iter().enumerate() {
        let block = &batch.wire_blocks[block_i];
        let expect = expected_tweaks(
            block,
            if block_i == 0 {
                Some((ti, &wrong))
            } else {
                None
            },
        );
        assert_eq!(got, &expect, "tweaks block {block_i}");
    }
    let mut prevs = Vec::new();
    for (i, tx) in filter0.block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            prevs.push(Vec::new());
        } else if i == ti {
            prevs.push(wrong.clone());
        } else {
            let vout = tx.input[0].previous_output.vout as usize;
            prevs.push(vec![filter0.block.txdata[0].output[vout].clone()]);
        }
    }
    let expect_filter =
        basic_filter_from_wire(&filter0.hash, &filter0.block, &prevs).expect("filter");
    assert_eq!(&rows.filters[0].1, &expect_filter);
}

fn expected_tweaks(
    block: &bitcoin::Block,
    seeded: Option<(usize, &[TxOut])>,
) -> Vec<Option<[u8; 33]>> {
    block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            if tx.is_coinbase() {
                return None;
            }
            let prev = if seeded.is_some_and(|(ti, _)| ti == i) {
                seeded.expect("seed").1.to_vec()
            } else {
                let vout = tx.input[0].previous_output.vout as usize;
                vec![block.txdata[0].output[vout].clone()]
            };
            tweak_from_tx(tx, &prev).map(|t| t.tweak)
        })
        .collect()
}

fn taproot_spend(
    prev: bitcoin::Txid,
    vout: u32,
    spk: &bitcoin::ScriptBuf,
    ser: &[u8],
) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev, vout),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0u8; 64].as_slice(), ser]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_0000_0000),
            script_pubkey: spk.clone(),
        }],
    }
}

fn bare_block(txdata: Vec<Transaction>) -> bitcoin::Block {
    use bitcoin::block::{Header, Version};
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([1; 32]),
            merkle_root: TxMerkleNode::from_byte_array([2; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    }
}

/// Two blocks, filters and tweaks on. Block 0 has 40 Taproot spends and
/// one non-Taproot spend. Block 1 has 33 Taproot spends.
fn two_block_index_batch(
    ser: &[u8],
    p2wpkh: &bitcoin::ScriptBuf,
    p2tr: &bitcoin::ScriptBuf,
) -> LoadedBatch {
    let (b0, p0) = index_block(10, 40, ser, p2wpkh, p2tr);
    let (b1, p1) = index_block(11, 33, ser, p2wpkh, p2tr);
    LoadedBatch {
        prepared: vec![p0, p1],
        wire_blocks: vec![Arc::new(b0), Arc::new(b1)],
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: rbitcoin_query::confirm_run::ScriptPreverified::new(),
        archive_plan: None,
        index_want: IndexWant {
            filters: true,
            tweak_origin: Some(0),
        },
        stats: Arc::new(rbitcoin_query::ConfirmStats::default()),
        trust_peer: false,
        trust_warns: Vec::new(),
    }
}

fn index_block(
    height: u32,
    n_taproot: usize,
    ser: &[u8],
    p2wpkh: &bitcoin::ScriptBuf,
    p2tr: &bitcoin::ScriptBuf,
) -> (bitcoin::Block, Prepared) {
    let n_out = n_taproot + 1;
    let cb = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x01, height as u8]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..n_out)
            .map(|_| TxOut {
                value: Amount::from_sat(2_0000_0000),
                script_pubkey: p2wpkh.clone(),
            })
            .collect(),
    };
    let cb_txid = cb.compute_txid();
    let mut txs = vec![cb];
    for vout in 0..n_taproot {
        txs.push(taproot_spend(cb_txid, vout as u32, p2tr, ser));
    }
    txs.push(taproot_spend(cb_txid, n_taproot as u32, p2wpkh, ser));
    let mut tx_fks = Vec::with_capacity(txs.len());
    let mut spends = Vec::new();
    for i in 0..txs.len() {
        tx_fks.push(Fk(1 + i as u64 + u64::from(height) * 100));
    }
    let cb_bytes = cb_txid.to_byte_array();
    for (i, tx) in txs.iter().enumerate().skip(1) {
        let vout = tx.input[0].previous_output.vout;
        spends.push((cb_bytes, vout, tx_fks[i], Fk::NULL, 0));
    }
    let block = bare_block(txs);
    let prep = Prepared {
        height: Height(height),
        header_fk: Fk(7 + u64::from(height)),
        tx_fks,
        jobs: Vec::new(),
        spends,
        fees: 0,
        check_scripts: false,
        time: block.header.time,
        bits: block.header.bits,
        hash: [height as u8; 32],
        txids: Vec::new(),
        prev_mtp: 0,
    };
    (block, prep)
}

#[test]
fn tip_entry_spawns_only_while_a_watermark_is_behind() {
    let (_dir, q) = tiny_query_labeled("idx-tip");
    enable(&q);
    go_live(&q);
    let idle = rbitcoin_query::index_tip_entry(&q);
    assert!(!idle.spawn);
    assert!(!idle.advertise_filters);

    let params = ChainParams::regtest();
    let ms = Milestone::height(u32::MAX);
    let genesis = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height(0), &genesis, ms).unwrap();
    let caught = rbitcoin_query::index_tip_entry(&q);
    assert!(!caught.spawn);
    assert!(caught.advertise_filters);

    let (_dir, behind) = tiny_query_labeled("idx-tip-behind");
    accept_and_connect_block(&behind, &params, Height(0), &genesis, ms).unwrap();
    enable(&behind);
    let gap = rbitcoin_query::index_tip_entry(&behind);
    assert!(gap.spawn);
    assert!(!gap.advertise_filters);
}
