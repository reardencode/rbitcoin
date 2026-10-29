//! BIP68 checks that read a confirmed median from the store.
#![cfg(test)]
use bitcoin::absolute::LockTime;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use rbitcoin_consensus::ValidationContext;

fn bare_tx(version: i32, lock_time: LockTime, sequence: Sequence) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn bip68_height_zero_time_lock_uses_the_median() {
    let type_flag = 1u32 << 22;
    let mtp = 1_231_006_505u32;
    // The median comes from the confirmed genesis header through
    // `structural_bip68`, not from a caller-supplied MTP slice.
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("bip68-h0");
    let header_fk = query
        .store()
        .put_header(&rbitcoin_store::HeaderRecord {
            timestamp: mtp,
            hash: [0x11; 32],
            ..Default::default()
        })
        .unwrap();
    query
        .store()
        .confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(0),
            header_fk,
        )
        .unwrap();
    query.store().rebuild_height_fence().unwrap();
    let params = Box::leak(Box::new(rbitcoin_consensus::ChainParams::regtest()));
    let ctx = ValidationContext::at(
        params,
        rbitcoin_primitives::Height(1),
        rbitcoin_consensus::Milestone::NONE,
    );
    let create = rbitcoin_primitives::Fk(1);
    let mut create_heights = rbitcoin_query::FkMap::default();
    create_heights.insert(create, 0);
    let spends = [([0u8; 32], 0u32, rbitcoin_primitives::Fk::NULL, create, 0u32)];
    let block = height_zero_timelock_block(type_flag);
    rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &block,
        &ctx,
        &spends,
        &create_heights,
        &mut rbitcoin_query::U32Map::default(),
    )
    .expect("height 0 time lock uses the genesis median");
    let too_far = height_zero_timelock_block(type_flag | 1);
    let err = rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &too_far,
        &ctx,
        &spends,
        &create_heights,
        &mut rbitcoin_query::U32Map::default(),
    )
    .expect_err("512s relative to the genesis median is not final at height 1");
    assert!(
        format!("{err}").contains("nonfinal"),
        "structural path must apply the median, got {err}"
    );
}

fn height_zero_timelock_block(sequence: u32) -> bitcoin::Block {
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
    let spend = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(sequence));
    let coinbase = bare_tx(1, LockTime::ZERO, Sequence::MAX);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1_231_006_505,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, spend],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

fn seq_tx(seqs: &[u32]) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: seqs
            .iter()
            .map(|seq| TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(*seq),
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn csv_block(txs: Vec<Transaction>) -> bitcoin::Block {
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1_231_006_505,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
        },
        txdata: txs,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

/// Three two-input txs must connect. `si * n_in` false-rejects the third.
#[test]
fn structural_bip68_multi_input_block_connects() {
    let params = Box::leak(Box::new(rbitcoin_consensus::ChainParams::regtest()));
    let ctx = ValidationContext::at(
        params,
        rbitcoin_primitives::Height(1),
        rbitcoin_consensus::Milestone::NONE,
    );
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("bip68-multi");
    let coinbase = bare_tx(1, LockTime::ZERO, Sequence::MAX);
    let spend = |seq: u32| seq_tx(&[seq, seq]);
    let block = csv_block(vec![
        coinbase,
        spend(u32::MAX),
        spend(u32::MAX),
        spend(u32::MAX),
    ]);
    let spends = vec![
        (
            [0u8; 32],
            0u32,
            rbitcoin_primitives::Fk::NULL,
            rbitcoin_primitives::Fk::NULL,
            0u32
        );
        6
    ];
    let mut cache = rbitcoin_query::U32Map::default();
    cache.insert(0, 1_000);
    rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &block,
        &ctx,
        &spends,
        &rbitcoin_query::FkMap::default(),
        &mut cache,
    )
    .expect("a well-formed multi-input block passes the spend cursor");
}

/// Height-type CSV does not prefetch a median. A missing parent header must
/// still pass when the block's own previous median is already cached.
#[test]
fn structural_bip68_height_lock_skips_missing_coin_mtp() {
    let params = Box::leak(Box::new(rbitcoin_consensus::ChainParams::regtest()));
    let ctx = ValidationContext::at(
        params,
        rbitcoin_primitives::Height(6),
        rbitcoin_consensus::Milestone::NONE,
    );
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("bip68-height-mtp");
    let create = rbitcoin_primitives::Fk(3);
    let mut create_heights = rbitcoin_query::FkMap::default();
    create_heights.insert(create, 5);
    let block = csv_block(vec![
        bare_tx(1, LockTime::ZERO, Sequence::MAX),
        seq_tx(&[0]),
    ]);
    let spends = [([0u8; 32], 0u32, rbitcoin_primitives::Fk::NULL, create, 0u32)];
    let mut cache = rbitcoin_query::U32Map::default();
    cache.insert(5, 1_500_000);
    rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &block,
        &ctx,
        &spends,
        &create_heights,
        &mut cache,
    )
    .expect("height-type lock must not read the coin median");
}

/// BIP68 walks `txdata[1..]`. A coinbase whose relative lock would fail still connects.
#[test]
fn bip68_skips_a_coinbase_whose_relative_lock_would_fail() {
    use rbitcoin_consensus::{
        mine_empty_regtest, prepare_regtest_candidate, ConsensusError, Milestone,
    };
    use rbitcoin_primitives::Height;

    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("bip68-coinbase");
    let params = rbitcoin_consensus::ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    rbitcoin_query::accept_and_connect_block(
        &q,
        &params,
        Height::GENESIS,
        &genesis,
        Milestone::NONE,
    )
    .unwrap();
    let mut block = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    block.txdata[0].version = bitcoin::transaction::Version::TWO;
    block.txdata[0].input[0].sequence = Sequence::from_consensus(200);
    prepare_regtest_candidate(&mut block, genesis.block_hash(), genesis.header.time + 600);
    rbitcoin_query::accept_and_connect_block(&q, &params, Height(1), &block, Milestone::NONE)
        .expect("coinbase sequence is not a BIP68 input");
    assert_eq!(q.tip_height(), Some(Height(1)));

    let params = Box::leak(Box::new(rbitcoin_consensus::ChainParams::regtest()));
    let ctx = ValidationContext::at(params, Height(6), Milestone::NONE);
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("bip68-noncb");
    let create = rbitcoin_primitives::Fk(3);
    let mut create_heights = rbitcoin_query::FkMap::default();
    create_heights.insert(create, 5);
    let block = csv_block(vec![
        bare_tx(1, LockTime::ZERO, Sequence::MAX),
        bare_tx(2, LockTime::ZERO, Sequence::from_consensus(200)),
    ]);
    let spends = [([0u8; 32], 0u32, rbitcoin_primitives::Fk::NULL, create, 0u32)];
    let mut cache = rbitcoin_query::U32Map::default();
    cache.insert(5, 1_500_000);
    let err = rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &block,
        &ctx,
        &spends,
        &create_heights,
        &mut cache,
    )
    .expect_err("the same lock rejects a non-coinbase");
    assert!(
        matches!(
            err,
            rbitcoin_query::ConfirmError::Rules(ConsensusError::BadTx(s)) if s.contains("nonfinal")
        ),
        "{err:?}"
    );
}

#[test]
fn structural_bip68_skips_when_every_sequence_is_disabled() {
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("bip68-disabled");
    let params = Box::leak(Box::new(rbitcoin_consensus::ChainParams::regtest()));
    let ctx = ValidationContext::at(
        params,
        rbitcoin_primitives::Height(1),
        rbitcoin_consensus::Milestone::NONE,
    );
    let rbf = Sequence::from_consensus(0xffff_fffd);
    let block = csv_block(vec![
        bare_tx(1, LockTime::ZERO, Sequence::MAX),
        bare_tx(2, LockTime::ZERO, rbf),
    ]);
    let spends = [(
        [0u8; 32],
        0u32,
        rbitcoin_primitives::Fk::NULL,
        rbitcoin_primitives::Fk(9),
        0u32,
    )];
    rbitcoin_query::block_pipeline::structural_bip68(
        &query,
        &block,
        &ctx,
        &spends,
        &rbitcoin_query::FkMap::default(),
        &mut rbitcoin_query::U32Map::default(),
    )
    .expect("disabled sequences do not read create heights or medians");
}
