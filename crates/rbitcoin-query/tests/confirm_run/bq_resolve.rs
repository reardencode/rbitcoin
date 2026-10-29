use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::Block;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use rbitcoin_consensus::mine_empty_regtest;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_query::accept_and_connect_block;
use rbitcoin_query::confirm_run::bq_resolve::*;
use rbitcoin_query::Query;
use rbitcoin_query::{TxPrecompute, TxidHasher};
use std::collections::HashSet;
use std::hash::BuildHasherDefault;
fn tmp_query() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("bq-resolve")
}

fn take_emitted(q: &Query, wave: &BqResolveWave) {
    assert!(take_wave_items_for_load(q, &wave.items, q.lookup_taken_gen()).unwrap());
}

fn resolve_wave(
    q: &Query,
    params: &ChainParams,
    milestone: Milestone,
    heights: &[u32],
) -> BqResolveWave {
    confirm_bq_resolve_wave_capped(
        q,
        params,
        milestone,
        heights,
        BQ_RESOLVE_WAVE_MAX_BLOCKS,
        BQ_RESOLVE_WAVE_MAX_INPUTS,
    )
    .unwrap()
}

fn resolve_and_take(q: &Query, params: &ChainParams, heights: &[u32]) -> BqResolveWaveStats {
    let wave = resolve_wave(q, params, Milestone::NONE, heights);
    take_emitted(q, &wave);
    wave.stats
}

fn spend_op_true(prev: Txid, vout: u32, value: Amount) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn coinbase_tx(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        rbitcoin_consensus::bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn mine_with_txs(prev: BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut txdata = vec![coinbase_tx(height)];
    txdata.extend(extra);
    let mut block = Block { header, txdata };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    block
}

#[test]
fn wire_input_count_matches_serialized_block() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let n: u32 = genesis
        .txdata
        .iter()
        .map(|tx| tx.input.len() as u32)
        .fold(0u32, u32::saturating_add);
    assert_eq!(
        rbitcoin_store::block_wire_input_count(&serialize(&genesis)),
        Some(n)
    );
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    let n1: u32 = b1
        .txdata
        .iter()
        .map(|tx| tx.input.len() as u32)
        .fold(0u32, u32::saturating_add);
    assert_eq!(
        rbitcoin_store::block_wire_input_count(&serialize(&b1)),
        Some(n1)
    );
    assert!(n1 >= 2, "coinbase + spend");
}

#[test]
fn push_resolve_keys_dedups_same_prev_txid() {
    let params = ChainParams::regtest();
    let prev = Txid::from_byte_array([0x11u8; 32]);
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: prev,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: prev,
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let height = params.btc.bip34_height;
    let block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 0,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase_tx(height), spend],
    };
    let pres: Vec<TxPrecompute> = block.txdata.iter().map(TxPrecompute::from_tx).collect();
    let mut keys: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    let skip = HashSet::with_hasher(BuildHasherDefault::default());
    let spends = push_resolve_keys(&params, height, &block, &pres, &skip, &mut keys, 1);
    assert_eq!(keys.len(), 1);
    assert!(keys.contains(&prev.to_byte_array()));
    assert_eq!(
        spends,
        vec![(prev.to_byte_array(), 0), (prev.to_byte_array(), 1),]
    );
    let mut skip_same = HashSet::with_hasher(BuildHasherDefault::default());
    skip_same.insert(prev.to_byte_array());
    let mut keys2: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    let skipped = push_resolve_keys(&params, height, &block, &pres, &skip_same, &mut keys2, 1);
    assert!(keys2.is_empty(), "same-wave creates are not TipOnly need");
    assert_eq!(
        skipped,
        vec![(prev.to_byte_array(), 0), (prev.to_byte_array(), 1),],
        "spend_keys must still carry same-wave prevs for in-flight stamp"
    );

    // Regtest BIP34 starts at height 1. Height 0 still records the create txid.
    let pre = Block {
        header: block.header,
        txdata: block.txdata.clone(),
    };
    let pre_pres: Vec<TxPrecompute> = pre.txdata.iter().map(TxPrecompute::from_tx).collect();
    let cb = pre_pres[0].txid;
    let mut pre_keys: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    push_resolve_keys(&params, 0, &pre, &pre_pres, &skip, &mut pre_keys, 1);
    assert!(
        pre_keys.contains(&cb),
        "before BIP34 the create txid is a resolve key"
    );
    let mut skip_cb = HashSet::with_hasher(BuildHasherDefault::default());
    skip_cb.insert(cb);
    let mut hidden: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    push_resolve_keys(&params, 0, &pre, &pre_pres, &skip_cb, &mut hidden, 1);
    assert!(
        !hidden.contains(&cb),
        "a skipped create txid is not a TipOnly key"
    );
}

#[test]
fn same_wave_create_is_not_tiponly_need() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    let h1_create = b1.txdata[1].compute_txid();
    let b2 = mine_with_txs(
        b1.block_hash(),
        b1.header.time + 600,
        2,
        vec![spend_op_true(h1_create, 0, Amount::from_sat(48_0000_0000))],
    );
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
        .unwrap();
    let wave = resolve_wave(&q, &params, Milestone::NONE, &[1, 2]);
    assert_eq!(wave.items.len(), 2);
    assert_eq!(
        wave.stats.keys, 1,
        "same-wave h=1 create must not be TipOnly need; archived genesis still is"
    );
    assert!(
        wave.stats.hits >= 1,
        "archived genesis parent must still TipOnly-hit"
    );
    let h1 = h1_create.to_byte_array();
    assert!(
        wave.parent_ids.get(&h1).is_none(),
        "same-wave create is not a TipOnly skeleton id"
    );
    assert!(
        wave.items[1].2.spend_keys.iter().any(|&(t, _)| t == h1),
        "h=2 spend_keys must name the same-wave parent so load stamp can in-flight bind"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn bq_resolve_wave_attaches_tiponly_hits_multi_height() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    let b2 = mine_with_txs(
        b1.block_hash(),
        b1.header.time + 600,
        2,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(48_0000_0000))],
    );
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
        .unwrap();

    let wave = resolve_wave(&q, &params, Milestone::NONE, &[1, 2]);
    let st = wave.stats;
    assert_eq!(st.heights, 2);
    assert_eq!(wave.items.len(), 2);
    assert!(st.keys >= 1);
    assert!(st.hits >= 1);
    assert!(
        st.decode_ns > 0 && st.precompute_ns > 0 && st.collect_ns > 0 && st.head_ns > 0,
        "raw-payload wave must meter decode=/precompute=/collect=/head= (decode={} pre={} collect={} head={})",
        st.decode_ns,
        st.precompute_ns,
        st.collect_ns,
        st.head_ns
    );
    let g = g_cb.to_byte_array();
    let (fk, _body, spent, n_out) = wave
        .parent_ids
        .get(&g)
        .expect("genesis coinbase must be a TipOnly skeleton hit");
    assert!(!fk.is_null());
    assert!(
        spent.is_some(),
        "archived parent must carry spent range on the skeleton"
    );
    assert_eq!(n_out, Some(1), "loc n_out on TipOnly skeleton");
    take_emitted(&q, &wave);
    assert!(!q.block_queue_has_height(1));
    assert!(!q.block_queue_has_height(2));
    let spend_pre = &wave.items[0].2.pres[1];
    assert!(
        spend_pre.sha_prevouts().is_none(),
        "a legacy spend stores no bip143 midstates"
    );
    assert_eq!(spend_pre.txid, b1.txdata[1].compute_txid().to_byte_array());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn bq_resolve_wave_connect_precompute_omits_midstates() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    let expect_txid = TxPrecompute::from_tx(&b1.txdata[1]).txid;
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    let wave = resolve_wave(&q, &params, Milestone::height(100), &[1]);
    assert_eq!(wave.items.len(), 1);
    let spend_pre = &wave.items[0].2.pres[1];
    assert_eq!(spend_pre.txid, expect_txid);
    assert_eq!(spend_pre.sha_prevouts(), None);
    assert_eq!(spend_pre.sha_sequences(), None);
    assert_eq!(spend_pre.sha_outputs(), None);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn resolve_wave_takes_nine_tiny_heights() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut heights = Vec::new();
    for h in 1..=9u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
            .unwrap();
        prev = b.block_hash();
        heights.push(h);
    }
    let wave = resolve_wave(&q, &params, Milestone::NONE, &heights);
    assert_eq!(
        wave.stats.heights, 9,
        "lookup wave must outgrow the old 8-height cap (soft 64000 inputs / hard 1080 blocks)"
    );
    take_emitted(&q, &wave);
    assert!(
        !q.block_queue_has_height(1),
        "take after send dequeues the BQ row"
    );
    assert!(q.block_queue_resolved(1).is_none());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn resolve_wave_pack_limits_are_4x_load_class() {
    assert_eq!(BQ_RESOLVE_WAVE_MAX_BLOCKS, 1080);
    assert_eq!(BQ_RESOLVE_WAVE_MAX_INPUTS, 64_000);
    assert_eq!(BQ_RESOLVE_WAVE_MIN_INPUTS, 8000);
    assert_eq!(BQ_RESOLVE_WAVE_MAX_KEYS, 256_000);
    assert!(!stop_for_key_cap(BQ_RESOLVE_WAVE_MAX_KEYS, 0));
    assert!(stop_for_key_cap(BQ_RESOLVE_WAVE_MAX_KEYS, 1));
    assert!(!stop_for_key_cap(BQ_RESOLVE_WAVE_MAX_KEYS - 1, 1));
    assert!(!wave_queue_still_filling(143, 10));
    assert!(wave_queue_still_filling(144, 143));
    assert!(wave_queue_still_filling(200, 10));
    assert!(!wave_queue_still_filling(144, 144));
    assert!(!wave_queue_still_filling(100, 50));
    assert!(wave_more_remain(1, 2, false));
    assert!(!wave_more_remain(1, 1, false));
    assert!(wave_more_remain(1, 1, true));
    const {
        assert!(BQ_RESOLVE_WAVE_MAX_BLOCKS >= 144 * 4);
        assert!(BQ_RESOLVE_WAVE_MAX_INPUTS >= BQ_RESOLVE_WAVE_MIN_INPUTS * 8);
    }
    // Include-overshoot: take the crossing block, then stop.
    assert!(!bq_resolve_wave_stop_after(63_900, 1, 64_000, 1080));
    assert!(bq_resolve_wave_stop_after(64_100, 2, 64_000, 1080));
    assert!(bq_resolve_wave_stop_after(1, 1080, 64_000, 1080));
    assert!(!bq_resolve_wave_stop_after(64_000, 1079, 64_000, 1080));
}

#[test]
fn hold_partial_table() {
    const MAX_IN: u32 = BQ_RESOLVE_WAVE_MAX_INPUTS;
    const MAX_BL: usize = BQ_RESOLVE_WAVE_MAX_BLOCKS;
    // far unresolved (beyond first half of win) + fat + short → hold
    assert!(bq_resolve_wave_hold_partial(
        330, 180, 4_000, 1, 100, 191, false, MAX_IN, MAX_BL
    ));
    // above min, gap in the first half of the window → emit (load needs it)
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 9_000, 2, 100, 190, true, MAX_IN, MAX_BL
    ));
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 9_000, 2, 100, 100, true, MAX_IN, MAX_BL
    ));
    // fat BQ + full input wave → emit
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 64_100, 16, 100, 250, true, MAX_IN, MAX_BL
    ));
    // fat BQ + full block cap → emit
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 1, 1080, 100, 250, true, MAX_IN, MAX_BL
    ));
    // thin BQ + short wave, nothing more to join → emit
    assert!(!bq_resolve_wave_hold_partial(
        50, 180, 4_000, 1, 100, 250, false, MAX_IN, MAX_BL
    ));
    // rate unknown (win=0), nothing more to join → emit
    assert!(!bq_resolve_wave_hold_partial(
        330, 0, 4_000, 1, 100, 250, false, MAX_IN, MAX_BL
    ));
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 0, 0, 100, 100, true, MAX_IN, MAX_BL
    ));
    // Hard min 8000: hold a thin *far* layer when more BQ heights can
    // still join. A single block at the load frontier (tip+1) must emit.
    assert!(
        bq_resolve_wave_hold_partial(0, 180, 4_000, 1, 100, 150, true, MAX_IN, MAX_BL),
        "ready=0 must still hold a far <8000-input layer when more remain"
    );
    assert!(
        !bq_resolve_wave_hold_partial(330, 180, 4_000, 1, 100, 100, true, MAX_IN, MAX_BL),
        "one tip+1 block must emit even under the 8000-input floor"
    );
    assert!(
        bq_resolve_wave_hold_partial(0, 0, 4_000, 1, 100, 150, true, MAX_IN, MAX_BL),
        "unknown window must still hold a far <8000 layer when more remain"
    );
    assert!(
        !bq_resolve_wave_hold_partial(0, 180, 4_000, 1, 100, 100, false, MAX_IN, MAX_BL),
        "last available thin wave must emit (tip / empty BQ)"
    );
    assert!(
        !bq_resolve_wave_hold_partial(0, 0, 8_000, 1, 100, 150, true, MAX_IN, MAX_BL),
        "exactly 8000 inputs is not under the floor"
    );
    assert!(
        !bq_resolve_wave_hold_partial(90, 180, 9_000, 1, 100, 191, false, MAX_IN, MAX_BL),
        "ready equal to half the window does not hold"
    );
    assert!(!bq_resolve_wave_hold_partial(
        0, 180, 8_000, 2, 100, 100, true, MAX_IN, MAX_BL
    ));
    // remaining-loadq cap counts as at_max so a packed remaining=1 wave emits
    assert!(!bq_resolve_wave_hold_partial(
        330, 180, 8_001, 2, 100, 250, true, 8_000, 144
    ));
}

#[test]
fn fat_bq_holds_short_unresolved_tail() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=8u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
            .unwrap();
        prev = b.block_hash();
    }
    for h in 1..=7u32 {
        q.block_queue_mark_resolve_complete(h).unwrap();
    }
    // win = 0.2 * 60 = 12; ready=8 > 6 → hold the 1-block tail
    let _ = q.block_queue_update_soft_pressure(Some(0.2));
    let st = resolve_wave(&q, &params, Milestone::NONE, &[8]).stats;
    assert_eq!(st.heights, 0, "fat BQ must not mint a 1-block layer");
    assert_eq!(
        st.decode_ns, 0,
        "hold must not consensus_decode; n_inputs is stamped at enqueue"
    );
    assert_eq!(
        st.precompute_ns, 0,
        "hold must not TxPrecompute::from_tx_wire"
    );
    assert!(!q.block_queue_is_resolve_complete(8));
    assert!(
        q.block_queue_has_height(8),
        "hold leaves raw on BQ until the wave emits"
    );
    assert!(q.block_queue_raw_payload(8).unwrap().is_some());
    assert!(q.block_queue_resolved(8).is_none());

    let _ = q.block_queue_update_soft_pressure(None);
    let st = resolve_and_take(&q, &params, &[8]);
    assert_eq!(st.heights, 1, "unknown window must allow a short wave");
    assert!(!q.block_queue_has_height(8));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn fat_bq_emits_short_wave_when_gap_is_at_load_frontier() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=20u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
            .unwrap();
        prev = b.block_hash();
    }
    for h in 2..=20u32 {
        q.block_queue_mark_resolve_complete(h).unwrap();
    }
    // win=12; ready=20 > 6 (fat) but height 1 is path_lo — load is waiting on it.
    let _ = q.block_queue_update_soft_pressure(Some(0.2));
    let st = resolve_and_take(&q, &params, &[1]);
    assert_eq!(
        st.heights, 1,
        "unresolved height in the first half of the soft window must emit"
    );
    assert!(!q.block_queue_has_height(1));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn tip_block_emits_under_min_inputs_while_bq_filling() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=10u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
            .unwrap();
        prev = b.block_hash();
    }
    // IBD-sized window, BQ still filling (10 < 180). Height 1 is tip+1.
    let _ = q.block_queue_update_soft_pressure(Some(3.0));
    let all: Vec<u32> = (1..=10).collect();
    let st = resolve_and_take(&q, &params, &all);
    assert_eq!(
        st.heights, 10,
        "tip+1 must emit even under 8000 inputs while the BQ is filling"
    );
    assert!(!q.block_queue_has_height(1));
    assert!(!q.block_queue_has_height(10));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn far_thin_wave_holds_under_min_inputs_when_more_remain() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=20u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
            .unwrap();
        prev = b.block_hash();
    }
    for h in 1..=10u32 {
        q.block_queue_mark_resolve_complete(h).unwrap();
    }
    let _ = q.block_queue_update_soft_pressure(Some(3.0));
    let st = resolve_wave(&q, &params, Milestone::NONE, &[15]).stats;
    assert_eq!(
        st.heights, 0,
        "a far 1-block layer must hold under 8000 inputs while more remain"
    );
    assert_eq!(st.decode_ns, 0);
    assert_eq!(st.precompute_ns, 0);
    assert!(q.block_queue_has_height(15));
    assert!(
        q.lookup_started_hi().is_none(),
        "hold_partial must not bump started_hi; got {:?}",
        q.lookup_started_hi()
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn resolve_wave_emits_a_promoted_height() {
    use rbitcoin_query::{ResolvedWire, TxPrecompute};
    use std::sync::Arc;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    let pres: Arc<[TxPrecompute]> = b1
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let wire = ResolvedWire::new(Arc::new(b1), pres);
    q.block_queue_promote_wave(vec![(1, wire, 64)]).unwrap();
    let wave = resolve_wave(&q, &params, Milestone::NONE, &[1]);
    assert_eq!(
        wave.stats.heights, 1,
        "a promoted row is still part of the wave"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn bq_resolve_wave_skips_claimed_height() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    let b2 = mine_with_txs(
        b1.block_hash(),
        b1.header.time + 600,
        2,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(48_0000_0000))],
    );
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
        .unwrap();
    // Caller skipped height 2 (claimed / inflight) — only resolve 1.
    let st = resolve_and_take(&q, &params, &[1]);
    assert_eq!(st.heights, 1);
    assert!(!q.block_queue_has_height(1), "emitted height is dequeued");
    assert!(q.block_queue_has_height(2));
    let _ = std::fs::remove_dir_all(&path);
}

/// Head occupied may already cover the parent fk; prune until the parent
/// height is confirmed so stamp does not MissingPrevout (931147 / 933474).
#[test]
fn stamp_uses_inflight_until_tip_covers_parent_height() {
    use rbitcoin_query::InFlight;
    use rbitcoin_store::{OutputRecord, TxRecord};
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let parent_txid = [0x22u8; 32];
    let parent_fk = rbitcoin_primitives::Fk(99);
    let pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: parent_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let mut log = InFlight::new();
    log.note_pins([(parent_fk, &pin)], Some(1));
    // Production: a wave that snapshotted drain+fence at genesis keeps height 1.
    log.prune_below_height(Some(0));
    assert!(
        log.get_create_fk(&parent_txid).is_some(),
        "in-flight must survive drain while parent height is unconfirmed"
    );
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(
            Txid::from_byte_array(parent_txid),
            0,
            Amount::from_sat(49_0000_0000),
        )],
    );
    let stamped = {
        let pipe = rbitcoin_query::WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start: q.tx_body_count().saturating_add(1).max(1),
            in_flight: &log,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        let items = [(Height(1), std::sync::Arc::new(b1), None)];
        rbitcoin_query::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
            .expect("in-flight parent must stamp until tip covers the parent height")
    };
    let plan = stamped.plan.expect("plan");
    let inp = plan
        .edges
        .values()
        .flatten()
        .find(|e| e.vout != u32::MAX)
        .expect("spend");
    assert_eq!(inp.create_fk, parent_fk);
    log.prune_below_height(Some(2));
    assert!(
        log.get_create_fk(&parent_txid).is_none(),
        "after a later wave snapshots drain+fence past the pack, TipOnly owns it"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Simulated torn publish (`confirmed.set` ahead of the fence). Confirm now
/// extends before `set_many`; this still pins that prune-on-confirmed-tip
/// would drop the parent (mainnet 945952 leftover_n=3546 hit=2811).
#[test]
fn stamp_uses_inflight_when_confirmed_tip_leads_fence() {
    use rbitcoin_query::InFlight;
    use rbitcoin_store::{OutputRecord, TxRecord};
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();

    q.store()
        .confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            Height(1),
            rbitcoin_primitives::Fk(2),
        )
        .unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(
        q.fence_tip_height(),
        Some(0),
        "production torn publish: tip leads fence"
    );

    let parent_txid = [0x33u8; 32];
    let parent_fk = rbitcoin_primitives::Fk(99);
    let pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: parent_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let mut log = InFlight::new();
    log.note_pins([(parent_fk, &pin)], Some(1));
    log.prune_below_height(q.drain_and_fence_hi());
    assert!(
        log.get_create_fk(&parent_txid).is_some(),
        "in-flight stays until a wave snapshots drain+fence covering the pack, not confirmed HWM"
    );
    // Dummy height-1 confirmed row was only to tear tip vs fence; stamp
    // still connects at tip+1 from genesis.
    q.store()
        .confirmed
        .disconnect_tip(&rbitcoin_store::ClassCWrite::for_test(), Height(1))
        .unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));

    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(
            Txid::from_byte_array(parent_txid),
            0,
            Amount::from_sat(49_0000_0000),
        )],
    );
    let stamped = {
        let pipe = rbitcoin_query::WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start: q.tx_body_count().saturating_add(1).max(1),
            in_flight: &log,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        let items = [(Height(1), std::sync::Arc::new(b1), None)];
        rbitcoin_query::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
            .expect("in-flight parent must stamp while confirmed tip leads the fence")
    };
    let plan = stamped.plan.expect("plan");
    let inp = plan
        .edges
        .values()
        .flatten()
        .find(|e| e.vout != u32::MAX)
        .expect("spend");
    assert_eq!(inp.create_fk, parent_fk);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn taken_hi_tracks_sent_load_batches_not_unsent_wave() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut heights = Vec::new();
    for h in 1..=4u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        prev = b.block_hash();
        q.block_queue_enqueue(h, prev.to_byte_array(), 1, &serialize(&b))
            .unwrap();
        heights.push(h);
    }
    let df_before = q.drain_and_fence_hi();
    let wave = resolve_wave(&q, &params, Milestone::NONE, &heights);
    assert_eq!(wave.items.len(), 4);
    assert_eq!(
        wave.drain_fence_hi, df_before,
        "wave must snapshot drain+fence before TipOnly"
    );
    assert!(
        q.lookup_taken_hi().is_none(),
        "resolve must not bump taken_hi before load-batch send; got {:?}",
        q.lookup_taken_hi()
    );
    assert_eq!(
        q.lookup_started_hi(),
        Some(4),
        "resolve wave must bump started_hi at start of TipOnly"
    );
    assert!(
        q.block_queue_has_height(4),
        "unsent wave tail must stay on the BQ"
    );
    assert!(
        q.block_queue_resolved(4).is_some(),
        "unsent tail is parked decoded (no re-decode)"
    );
    q.block_queue_dequeue_height(1).unwrap();
    q.set_lookup_taken_hi(Some(1));
    assert_eq!(q.lookup_taken_hi(), Some(1));
    assert_eq!(
        q.lookup_started_hi(),
        Some(4),
        "take must not rewind started_hi"
    );
    assert!(!q.block_queue_has_height(1));
    assert!(q.block_queue_has_height(4));
    let _ = std::fs::remove_dir_all(&path);
}

/// A re-arm between selection and take wins: the take reports it lost,
/// leaves its rows on the queue for lookup to select again, and does not
/// move the mark. A take at the live generation consumes the rows.
#[test]
fn take_after_a_rearm_leaves_its_rows_queued() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=2u32 {
        time += 600;
        let b = mine_empty_regtest(prev, time, h);
        prev = b.block_hash();
        q.block_queue_enqueue(h, prev.to_byte_array(), 1, &serialize(&b))
            .unwrap();
    }
    let wave = resolve_wave(&q, &params, Milestone::NONE, &[1, 2]);
    assert_eq!(wave.items.len(), 2);
    let gen = q.lookup_taken_gen();
    q.set_lookup_taken_hi(Some(0));
    assert!(!take_wave_items_for_load(&q, &wave.items, gen).unwrap());
    assert_eq!(q.lookup_taken_hi(), Some(0));
    assert!(q.block_queue_has_height(1) && q.block_queue_has_height(2));

    assert!(take_wave_items_for_load(&q, &wave.items, q.lookup_taken_gen()).unwrap());
    assert_eq!(q.lookup_taken_hi(), Some(2));
    assert!(!q.block_queue_has_height(1) && !q.block_queue_has_height(2));
    let _ = std::fs::remove_dir_all(&path);
}

/// IBD teardown sets the confirm cancel, then joins the lookup thread. A wave
/// under that flag returns cancelled instead of resolving its TipOnly need: a
/// full wave is up to 64k cold reads, most of an hour on a busy HDD.
#[test]
fn wave_under_confirm_cancel_returns_cancelled() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let g_cb = genesis.txdata[0].compute_txid();
    let b1 = mine_with_txs(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
    );
    q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
        .unwrap();
    q.request_confirm_cancel();
    let err = match confirm_bq_resolve_wave_capped(
        &q,
        &params,
        Milestone::NONE,
        &[1],
        BQ_RESOLVE_WAVE_MAX_BLOCKS,
        BQ_RESOLVE_WAVE_MAX_INPUTS,
    ) {
        Ok(_) => panic!("a wave under the confirm cancel must not resolve"),
        Err(e) => e,
    };
    assert!(err.is_cancelled(), "want cancelled, got {err:?}");
    // Promote and dequeue sit after the `?`, so a cancelled wave leaves the
    // height queued for the next session.
    assert!(q.block_queue_has_height(1));
    let _ = std::fs::remove_dir_all(&path);
}

/// The cancellable batch is one resolve of the whole need. Uncancelled it
/// returns the rows the one-shot batch does. The cancel is asked before the
/// resolve and before each identity shot, so a flag set on the first ask
/// returns cancelled and never resolves.
#[test]
fn txid_batch_asks_cancel_before_the_identity_shot() {
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let mut txids = vec![genesis.txdata[0].compute_txid().to_byte_array()];
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=2u32 {
        time += 600;
        let b = mine_with_txs(prev, time, h, vec![]);
        accept_and_connect_block(&q, &params, Height(h), &b, Milestone::NONE).unwrap();
        txids.push(b.txdata[0].compute_txid().to_byte_array());
        prev = b.block_hash();
    }
    let whole = q.store().get_fk_by_txid_batch(&txids).unwrap();
    assert!(
        whole.iter().all(|(_, row)| row.is_some()),
        "connected coinbases resolve"
    );
    let once = q
        .store()
        .get_fk_by_txid_batch_cancellable(&txids, &|| false)
        .unwrap();
    assert_eq!(once, whole, "one resolve returns the one-shot rows");

    let asked = std::cell::Cell::new(0u32);
    let err = q
        .store()
        .get_fk_by_txid_batch_cancellable(&txids, &|| {
            asked.set(asked.get() + 1);
            true
        })
        .unwrap_err();
    assert!(
        matches!(err, rbitcoin_store::StoreError::Cancelled(_)),
        "{err:?}"
    );
    assert_eq!(asked.get(), 1, "the resolve asks before any identity shot");
    let _ = std::fs::remove_dir_all(&path);
}
