use bitcoin::absolute::LockTime;
use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds, ShortId};
use bitcoin::block::Header;
use bitcoin::block::Version;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{Block, BlockHash, Transaction};
use rbitcoin_net::compact::*;
use std::borrow::Borrow;
use std::collections::HashMap;

use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, TxIn, TxMerkleNode, TxOut, Witness};

fn empty_avail() -> HashMap<ShortId, Vec<&'static Transaction>> {
    HashMap::new()
}

fn must_partial<T: Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    avail: &HashMap<ShortId, Vec<T>>,
) -> CmpctPartial {
    match reconstruct(hsi, avail) {
        Reconstruct::Partial(p) => p,
        other => panic!("expected partial, got {other:?}"),
    }
}

fn dummy_header() -> Header {
    Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    }
}

fn sealed_block(txdata: Vec<Transaction>) -> Block {
    let mut header = dummy_header();
    header.merkle_root = Block {
        header,
        txdata: txdata.clone(),
    }
    .compute_merkle_root()
    .expect("non-empty");
    Block { header, txdata }
}

fn coinbase() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend(n: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![n]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn reconstruct_rejects_tx_count_above_weight_ratio() {
    assert_eq!(
        rbitcoin_consensus::MAX_BLOCK_TX_COUNT,
        (rbitcoin_consensus::MAX_BLOCK_WEIGHT / rbitcoin_consensus::MIN_TX_WEIGHT) as usize
    );
    assert_eq!(rbitcoin_consensus::MAX_BLOCK_TX_COUNT, 100_000);
    let block = sealed_block(vec![coinbase()]);
    let mut hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[]).unwrap();
    hsi.short_ids = vec![ShortId::from([0u8; 6]); rbitcoin_consensus::MAX_BLOCK_TX_COUNT];
    assert!(
        matches!(reconstruct(&hsi, &empty_avail()), Reconstruct::Fail),
        "count at the cap plus the prefilled coinbase is over"
    );
    let n_pref = hsi.prefilled_txs.len();
    hsi.short_ids = vec![ShortId::from([0u8; 6]); rbitcoin_consensus::MAX_BLOCK_TX_COUNT - n_pref];
    assert!(
        !matches!(reconstruct(&hsi, &empty_avail()), Reconstruct::Fail),
        "exactly the cap is still a partial, not a count failure"
    );
}

#[test]
fn reconstruct_full_from_mempool_map() {
    let b1 = spend(1);
    let b2 = spend(2);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 0xdead_beef, 2, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1, &b2]);
    let recon = try_reconstruct(&hsi, &avail).expect("full fill");
    assert_eq!(recon.txdata.len(), 3);
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
    assert_eq!(recon.txdata[2].compute_txid(), b2.compute_txid());
}

#[test]
fn reconstruct_fill_keeps_matching_shortid_not_rehash() {
    let b1 = spend(1);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let mut hsi = HeaderAndShortIds::from_block(&block, 0xdead_beef, 2, &[]).unwrap();
    let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
    let hashed = short_id_for_tx(&b1, 2, keys);
    let fake = ShortId::with_siphash_keys(
        &bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
        keys,
    );
    assert_ne!(fake, hashed, "caller key must differ from clone siphash");
    hsi.short_ids[0] = fake;

    let mut owned: HashMap<ShortId, Vec<Transaction>> = HashMap::new();
    owned.insert(fake, vec![b1.clone()]);

    let rehashed = shortid_map_from_txs(&block.header, hsi.nonce, 2, owned.values().flatten());
    assert!(
        try_reconstruct(&hsi, &rehashed).is_err(),
        "rehashing clones must miss a caller short-id"
    );

    let recon = try_reconstruct(&hsi, &owned).expect("matching short-id must place body");
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
}

#[test]
fn missing_indexes_when_mempool_empty() {
    let b1 = spend(3);
    let block = Block {
        header: dummy_header(),
        txdata: vec![coinbase(), b1],
    };
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let missing = try_reconstruct(&hsi, &empty).unwrap_err();
    // coinbase prefilled; one short id missing at abs index 1
    assert_eq!(missing, vec![1]);
}

#[test]
fn repeated_short_id_is_requested_not_duplicated() {
    let b1 = spend(7);
    let block = Block {
        header: dummy_header(),
        txdata: vec![coinbase(), b1.clone(), b1.clone()],
    };
    let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
    let missing = try_reconstruct(&hsi, &avail).expect_err("repeat must not fully fill");
    assert!(
        !missing.is_empty(),
        "second slot of the same short-id must be missing"
    );
    assert!(
        missing.contains(&2) || missing == vec![2] || missing.contains(&1),
        "expected a missing index for the duplicate slot, got {missing:?}"
    );
}

#[test]
fn unique_shortid_wrong_body_is_not_a_block() {
    let b1 = spend(8);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 4, 2, &[]).unwrap();
    let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
    let sid = short_id_for_tx(&b1, 2, keys);
    let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let wrong = spend(9);
    avail.insert(sid, vec![&wrong]);
    let missing = try_reconstruct(&hsi, &avail).expect_err("wrong unique fill");
    assert!(
        missing.is_empty(),
        "merkle-mutated fill must getdata (empty missing), got {missing:?}"
    );
}

/// One txid list matches rust-bitcoin's root. The mutation bit is the
/// duplicate pair only: that body still satisfies `check_merkle_root`.
#[test]
fn store_merkle_matches_check_merkle_root() {
    let only = sealed_block(vec![coinbase()]);
    let (root, mutated) = block_txid_merkle(&only.txdata).expect("coinbase");
    assert!(only.check_merkle_root());
    assert_eq!(root, only.header.merkle_root.to_byte_array());
    assert!(!mutated);

    let cb = coinbase();
    let pair = sealed_block(vec![cb.clone(), cb]);
    let (root, mutated) = block_txid_merkle(&pair.txdata).expect("pair");
    assert!(pair.check_merkle_root());
    assert_eq!(root, pair.header.merkle_root.to_byte_array());
    assert!(mutated);
}

#[test]
fn empty_txdata_is_not_a_block() {
    let header = dummy_header();
    assert_eq!(header.merkle_root.to_byte_array(), [0u8; 32]);
    let err = finish_reconstructed(header, Vec::new()).expect_err("empty body");
    assert!(err.is_empty(), "getdata the hash, got {err:?}");
}

#[test]
fn repeated_pair_with_matching_root_is_not_a_block() {
    let cb = coinbase();
    let block = sealed_block(vec![cb.clone(), cb]);
    assert!(block.check_merkle_root());
    assert!(block_txid_merkle(&block.txdata).expect("pair").1);
    let err = finish_reconstructed(block.header, block.txdata).expect_err("mutated pair");
    assert!(err.is_empty(), "getdata the hash, got {err:?}");
}

#[test]
fn prefilled_64_byte_body_without_coinbase_is_not_a_block() {
    let inner = rbitcoin_net::chain::sixty_four_byte_body(BlockHash::all_zeros(), 1);
    let hsi = HeaderAndShortIds::from_block(&inner, 6, 2, &[]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let missing = try_reconstruct(&hsi, &empty).expect_err("possible inner merkle node");
    assert!(
        missing.is_empty(),
        "a mutated fill must getdata the full block, got {missing:?}"
    );
}

#[test]
fn apply_blocktxn_wrong_body_is_not_a_block() {
    let b1 = spend(10);
    let block = sealed_block(vec![coinbase(), b1]);
    let hsi = HeaderAndShortIds::from_block(&block, 5, 2, &[]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let partial = must_partial(&hsi, &empty);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![spend(11)],
    };
    let err = apply_block_transactions(&hsi, &partial, &txn).expect_err("wrong blocktxn body");
    assert!(
        err.is_empty(),
        "merkle-mutated blocktxn must getdata, got {err:?}"
    );
}

#[test]
fn apply_blocktxn_completes() {
    let b1 = spend(4);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 2, 2, &[]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let partial = must_partial(&hsi, &empty);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b1.clone()],
    };
    let recon = apply_block_transactions(&hsi, &partial, &txn).unwrap();
    assert_eq!(recon.txdata.len(), 2);
}

#[test]
fn missing_request_uses_absolute_indexes() {
    let missing = vec![1u64, 3, 5];
    let req = missing_request(BlockHash::from_byte_array([9; 32]), &missing);
    assert_eq!(req.indexes, missing);
}

#[test]
fn partial_mempool_plus_blocktxn() {
    let b1 = spend(5);
    let b2 = spend(6);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
    let partial = must_partial(&hsi, &avail);
    assert_eq!(partial.missing(), [2]); // abs index of b2
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b2.clone()],
    };
    let recon = apply_block_transactions(&hsi, &partial, &txn).unwrap();
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
    assert_eq!(recon.txdata[2].compute_txid(), b2.compute_txid());
}

#[test]
fn apply_keeps_first_pass_when_mempool_map_gone() {
    let b1 = spend(5);
    let b2 = spend(6);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
    let partial = must_partial(&hsi, &avail);
    assert_eq!(partial.missing(), [2]);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b2.clone()],
    };
    let recon = apply_block_transactions(&hsi, &partial, &txn)
        .expect("blocktxn must complete without a second short-id walk");
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
    assert_eq!(recon.txdata[2].compute_txid(), b2.compute_txid());
}

#[test]
fn apply_collision_slot_from_blocktxn_only() {
    let b1 = spend(9);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 9, 2, &[]).unwrap();
    let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
    let sid = ShortId::with_siphash_keys(&b1.compute_wtxid().to_raw_hash(), keys);
    let b_alt = spend(10);
    let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    avail.insert(sid, vec![&b1, &b_alt]);
    let partial = must_partial(&hsi, &avail);
    assert_eq!(partial.missing(), [1]);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b1.clone()],
    };
    let recon = apply_block_transactions(&hsi, &partial, &txn).unwrap();
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
}

#[test]
fn reconstruct_oob_prefill_is_fail() {
    let oob = HeaderAndShortIds {
        header: dummy_header(),
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![bitcoin::bip152::PrefilledTransaction {
            idx: 1,
            tx: coinbase(),
        }],
    };
    assert!(matches!(
        reconstruct(&oob, &empty_avail()),
        Reconstruct::Fail
    ));
}

#[test]
fn apply_rejects_oob_filled_slot_duplicate_and_leftover_hole() {
    let b1 = spend(1);
    let b2 = spend(2);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
    let txn1 = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b1.clone()],
    };
    let oob = CmpctPartial {
        slots: vec![Some(coinbase()), None, None],
        missing: vec![9],
    };
    assert!(apply_block_transactions(&hsi, &oob, &txn1)
        .unwrap_err()
        .is_empty());
    let already = CmpctPartial {
        slots: vec![Some(coinbase()), Some(b1.clone()), None],
        missing: vec![1],
    };
    assert!(apply_block_transactions(&hsi, &already, &txn1)
        .unwrap_err()
        .is_empty());
    let dup = CmpctPartial {
        slots: vec![Some(coinbase()), Some(b1.clone()), None],
        missing: vec![2],
    };
    assert_eq!(
        apply_block_transactions(&hsi, &dup, &txn1).unwrap_err(),
        vec![2]
    );
    let hole = CmpctPartial {
        slots: vec![Some(coinbase()), None, None],
        missing: vec![1],
    };
    assert_eq!(
        apply_block_transactions(&hsi, &hole, &txn1).unwrap_err(),
        vec![1]
    );
    let empty_slots = CmpctPartial {
        slots: vec![],
        missing: vec![],
    };
    let empty_txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![],
    };
    assert!(apply_block_transactions(&hsi, &empty_slots, &empty_txn)
        .unwrap_err()
        .is_empty());
}

#[test]
fn version1_txid_shortids_fill() {
    let b1 = spend(7);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 4, 1, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 1, [&b1]);
    let recon = try_reconstruct(&hsi, &avail).expect("v1 fill");
    assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
}

#[test]
fn wrong_count_blocktxn_errors() {
    let b1 = spend(8);
    let block = Block {
        header: dummy_header(),
        txdata: vec![coinbase(), b1],
    };
    let hsi = HeaderAndShortIds::from_block(&block, 5, 2, &[]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let partial = must_partial(&hsi, &empty);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![], // wrong count
    };
    assert!(apply_block_transactions(&hsi, &partial, &txn).is_err());
}

#[test]
fn empty_compact_and_ambiguous_shortid() {
    let hsi = HeaderAndShortIds {
        header: dummy_header(),
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![],
    };
    assert!(
        try_reconstruct(&hsi, &HashMap::<ShortId, Vec<&Transaction>>::new())
            .unwrap_err()
            .is_empty()
    );
    assert!(matches!(
        reconstruct(&hsi, &HashMap::<ShortId, Vec<&Transaction>>::new()),
        Reconstruct::Fail
    ));
    let empty_partial = CmpctPartial {
        slots: Vec::new(),
        missing: Vec::new(),
    };
    assert!(apply_block_transactions(
        &hsi,
        &empty_partial,
        &BlockTransactions {
            block_hash: BlockHash::from_byte_array([0; 32]),
            transactions: vec![],
        },
    )
    .unwrap_err()
    .is_empty());

    // Ambiguous short-id collision → missing.
    let b1 = spend(9);
    let block = Block {
        header: dummy_header(),
        txdata: vec![coinbase(), b1.clone()],
    };
    let hsi = HeaderAndShortIds::from_block(&block, 9, 2, &[]).unwrap();
    let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
    let sid = ShortId::with_siphash_keys(&b1.compute_wtxid().to_raw_hash(), keys);
    let b_alt = spend(10);
    let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    avail.insert(sid, vec![&b1, &b_alt]);
    let missing = try_reconstruct(&hsi, &avail).unwrap_err();
    assert_eq!(missing, vec![1]);

    let idxs = prefilled_absolute_indexes(&hsi);
    assert!(!idxs.is_empty());
    assert_eq!(idxs[0].0, 0); // coinbase at abs 0
    assert!(cmpct_init_data_ok(&hsi));

    let oob = HeaderAndShortIds {
        header: dummy_header(),
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![bitcoin::bip152::PrefilledTransaction {
            idx: 1,
            tx: coinbase(),
        }],
    };
    assert!(!cmpct_init_data_ok(&oob));
}

fn mined_h1_two_tx_hsi() -> HeaderAndShortIds {
    use rbitcoin_consensus::{genesis_block, mine_regtest_paying, ChainParams};
    let genesis = genesis_block(&ChainParams::regtest());
    let extra = spend(1);
    let block = mine_regtest_paying(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![extra],
    );
    HeaderAndShortIds::from_block(&block, 0x11, 2, &[]).unwrap()
}

fn cmpct_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn classify_v2_ping_and_empty_other() {
    let ping = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::Ping(7)).unwrap();
    assert_eq!(classify_v2_cmpct_peer(&ping), CmpctPeerFrame::Ping(7));
    let pong = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::Pong(7)).unwrap();
    assert_eq!(classify_v2_cmpct_peer(&pong), CmpctPeerFrame::Pong(7));
    let block_hash = BlockHash::from_byte_array([7; 32]);
    let get = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::GetBlockTxn(
        bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: bitcoin::bip152::BlockTransactionsRequest {
                block_hash,
                indexes: vec![1, 4],
            },
        },
    ))
    .unwrap();
    assert_eq!(
        classify_v2_cmpct_peer(&get),
        CmpctPeerFrame::GetBlockTxn(vec![1, 4])
    );
    assert_eq!(classify_v2_cmpct_peer(&[]), CmpctPeerFrame::Other);
}

#[test]
fn v2_header_hashes_reads_a_headers_payload() {
    use rbitcoin_consensus::{genesis_block, ChainParams};
    let genesis = genesis_block(&ChainParams::regtest());
    let hash = genesis.block_hash();
    let frame = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::Headers(vec![genesis.header]))
        .unwrap();
    assert_eq!(v2_header_hashes(&frame), Some(vec![hash]));
    let ping = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::Ping(1)).unwrap();
    assert_eq!(v2_header_hashes(&ping), None);
}

#[test]
fn try_reconstruct_empty_mempool_two_tx_is_index_1() {
    let hsi = mined_h1_two_tx_hsi();
    assert_eq!(try_reconstruct(&hsi, &empty_avail()).unwrap_err(), vec![1]);
    let raw = bitcoin::consensus::encode::serialize(&hsi);
    assert_eq!(
        try_reconstruct(&decode_cmpct_hsi(&raw).unwrap(), &empty_avail()).unwrap_err(),
        vec![1]
    );
}

#[test]
fn cmpct_h1_two_tx_fixture_matches_mined() {
    let expected = bitcoin::consensus::encode::serialize(&mined_h1_two_tx_hsi());
    let path = cmpct_fixture_path("cmpct_h1_two_tx.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    let hsi = decode_cmpct_hsi(&raw).unwrap();
    assert_eq!(try_reconstruct(&hsi, &empty_avail()).unwrap_err(), vec![1]);
}

/// Compact siphash nonce for `cmpct_wtxid_shortid_collision_*.bin`.
const COLLISION_CMPCT_NONCE: u64 = 0x0C01_115E;
const COLLISION_STALE_TIME: u32 = 1_300_060_000;
const COLLISION_WINNER_TIME: u32 = 1_300_060_001;

fn collision_parents() -> (Block, Block) {
    use rbitcoin_consensus::{genesis_block, mine_empty_regtest, ChainParams};
    let genesis = genesis_block(&ChainParams::regtest());
    let stale = mine_empty_regtest(genesis.block_hash(), COLLISION_STALE_TIME, 1);
    let mut winner = mine_empty_regtest(genesis.block_hash(), COLLISION_WINNER_TIME, 1);
    if winner.block_hash() == stale.block_hash() {
        winner = mine_empty_regtest(genesis.block_hash(), COLLISION_WINNER_TIME + 1, 1);
    }
    assert_ne!(stale.block_hash(), winner.block_hash());
    (stale, winner)
}

fn load_wtxid_shortid_collision() -> (Block, Transaction) {
    let block_raw = std::fs::read(cmpct_fixture_path(
        "cmpct_wtxid_shortid_collision_block.bin",
    ))
    .expect("cmpct_wtxid_shortid_collision_block.bin");
    let collider_raw = std::fs::read(cmpct_fixture_path(
        "cmpct_wtxid_shortid_collision_collider.bin",
    ))
    .expect("cmpct_wtxid_shortid_collision_collider.bin");
    (
        bitcoin::consensus::encode::deserialize(&block_raw).expect("block"),
        bitcoin::consensus::encode::deserialize(&collider_raw).expect("collider"),
    )
}

fn collision_hsi(block: &Block, collider: &Transaction) -> HeaderAndShortIds {
    assert_eq!(block.txdata.len(), 2);
    let block_tx = &block.txdata[1];
    assert_ne!(block_tx.compute_txid(), collider.compute_txid());
    assert_ne!(block_tx.compute_wtxid(), collider.compute_wtxid());
    let keys = ShortId::calculate_siphash_keys(&block.header, COLLISION_CMPCT_NONCE);
    let sid_block = ShortId::with_siphash_keys(&block_tx.compute_wtxid().to_raw_hash(), keys);
    let sid_col = ShortId::with_siphash_keys(&collider.compute_wtxid().to_raw_hash(), keys);
    assert_eq!(
        sid_block, sid_col,
        "fixture must be a v2 short-id collision"
    );
    let hsi = HeaderAndShortIds::from_block(block, COLLISION_CMPCT_NONCE, 2, &[]).unwrap();
    assert_eq!(hsi.short_ids, vec![sid_block]);
    hsi
}

fn assert_collider_fill_getdata<T: std::borrow::Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    avail: &HashMap<ShortId, Vec<T>>,
) {
    let missing = try_reconstruct(hsi, avail).expect_err("collider unique fill");
    assert!(
        missing.is_empty(),
        "48-bit unique fill must getdata, got {missing:?}"
    );
}

fn mutated_collision_body(block: &Block, collider: &Transaction) -> Block {
    let mutated = Block {
        header: block.header,
        txdata: vec![block.txdata[0].clone(), collider.clone()],
    };
    assert_eq!(mutated.block_hash(), block.block_hash());
    assert!(!mutated.check_merkle_root());
    mutated
}

fn assert_mutated_not_block_failed(
    hub: &rbitcoin_net::chain::ChainHub,
    mutated: Block,
    hash: bitcoin::BlockHash,
) {
    use rbitcoin_net::error::NetError;
    let err = hub
        .accept_received_block(mutated)
        .expect_err("v0.6.0 would accept this reconstructed body");
    match &err {
        NetError::Mutated(s) | NetError::Consensus(s) => {
            assert!(
                s.contains("merkle")
                    || s.contains("bad-txnmrklroot")
                    || s.contains("witness commitment"),
                "got {s}"
            );
        }
        NetError::ConnectFailed { msg, hash: h, .. } => {
            assert!(
                msg.contains("merkle")
                    || msg.contains("bad-txnmrklroot")
                    || msg.contains("witness commitment"),
                "got {msg}"
            );
            assert_eq!(*h, hash.to_byte_array());
        }
        other => panic!("expected mutated reject, got {other:?}"),
    }
    assert!(
        !hub.is_block_invalid(&hash),
        "short-id collision reconstruct must not BLOCK_FAILED the header"
    );
}

/// Pre-ground v2 48-bit wtxid short-id collision: orphan unique-match on a held fork.
#[test]
fn cmpct_wtxid_shortid_collision_held_fork_journey() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_net::chain::AcceptOutcome;
    use std::sync::Arc;

    let (block, collider) = load_wtxid_shortid_collision();
    let (stale, winner) = collision_parents();
    assert_eq!(block.header.prev_blockhash, winner.block_hash());
    let hsi = collision_hsi(&block, &collider);
    let sid = hsi.short_ids[0];
    let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    avail.insert(sid, vec![&collider]);
    assert_collider_fill_getdata(&hsi, &avail);
    let mutated = mutated_collision_body(&block, &collider);

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-sid-col");
    hub.ensure_genesis().unwrap();
    hub.accept_block(stale.clone()).unwrap();
    assert!(matches!(
        hub.accept_received_block(winner.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&winner.block_hash()).is_some());

    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    assert!(matches!(
        mp.accept_tx(&collider),
        Err(rbitcoin_net::AcceptError::Orphaned { .. })
    ));
    let owned = mp
        .try_clone_matching_shortids(&hsi.header, hsi.nonce, 2, &hsi.short_ids)
        .expect("mempool read");
    let fill = owned.get(&sid).expect("orphan collider must unique-match");
    assert_eq!(fill.len(), 1);
    assert_eq!(fill[0].compute_wtxid(), collider.compute_wtxid());
    assert_collider_fill_getdata(&hsi, &owned);

    assert_mutated_not_block_failed(&hub, mutated, block.block_hash());
    assert_eq!(hub.tip_hash(), Some(stale.block_hash()));

    let honest = mine_empty_regtest(
        winner.block_hash(),
        winner.header.time.saturating_add(601),
        2,
    );
    assert!(matches!(
        hub.accept_received_block(honest.clone()).unwrap(),
        AcceptOutcome::Accepted { height: 2 }
    ));
    assert_eq!(hub.tip_hash(), Some(honest.block_hash()));
    assert!(!hub.is_block_invalid(&block.block_hash()));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cmpct_reconstruct_stats_first_shot_all_mempool_fetched_zero() {
    let b1 = spend(1);
    let b2 = spend(2);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 0xdead_beef, 2, &[]).unwrap();
    let recon = try_reconstruct(
        &hsi,
        &shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1, &b2]),
    )
    .expect("full fill");
    let fill = CmpctFillSets {
        mempool: [b1.compute_wtxid(), b2.compute_wtxid()]
            .into_iter()
            .collect(),
        extra: Default::default(),
        orphan: Default::default(),
    };
    let stats = reconstruct_stats(&hsi, &recon, &fill, &[]);
    assert_eq!(stats.fetched_n, 0);
    assert_eq!(stats.fetched_bytes, 0);
    assert_eq!(stats.mempool_n, 2);
    assert_eq!(
        stats.mempool_bytes,
        tx_wire_len(&b1) + tx_wire_len(&b2),
        "mempool fill bytes are the sum of the filled transactions"
    );
    assert_eq!(stats.prefill_n, 1);
    assert_eq!(stats.prefill_bytes, tx_wire_len(&block.txdata[0]));
    assert!(!stats.getdata);
    let line = stats.to_string();
    assert!(
        line.starts_with(&format!("cmpct reconstruct {}", recon.block_hash())),
        "{line}"
    );
    assert!(line.contains("fetched=0/0"), "{line}");
    assert!(line.contains("tx=3"), "{line}");
    assert!(!line.contains("ntx="), "{line}");
}

#[test]
fn cmpct_reconstruct_stats_blocktxn_fetched_bytes() {
    let b1 = spend(5);
    let b2 = spend(6);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
    let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
    let partial = must_partial(&hsi, &avail);
    let txn = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![b2.clone()],
    };
    let recon = apply_block_transactions(&hsi, &partial, &txn).unwrap();
    let fill = CmpctFillSets {
        mempool: [b1.compute_wtxid()].into_iter().collect(),
        extra: Default::default(),
        orphan: Default::default(),
    };
    let stats = reconstruct_stats(&hsi, &recon, &fill, partial.missing());
    let fetched_bytes = bitcoin::consensus::encode::serialize(&b2).len();
    assert_eq!(stats.fetched_n, 1);
    assert_eq!(stats.fetched_bytes, fetched_bytes);
    assert_eq!(stats.mempool_n, 1);
    assert_eq!(stats.extra_n, 0);
    let line = stats.to_string();
    assert!(
        line.contains(&format!("fetched=1/{fetched_bytes}")),
        "{line}"
    );
}

#[test]
fn cmpct_reconstruct_stats_redundant_prefill_in_mempool() {
    let b1 = spend(12);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 7, 2, &[0, 1]).unwrap();
    let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    let recon = try_reconstruct(&hsi, &empty).expect("prefilled");
    let fill = CmpctFillSets {
        mempool: [b1.compute_wtxid()].into_iter().collect(),
        extra: Default::default(),
        orphan: Default::default(),
    };
    let stats = reconstruct_stats(&hsi, &recon, &fill, &[]);
    let b1_bytes = bitcoin::consensus::encode::serialize(&b1).len();
    assert_eq!(stats.prefill_n, 2);
    assert_eq!(stats.redundant_prefill_n, 1);
    assert_eq!(stats.redundant_prefill_bytes, b1_bytes);
    assert_eq!(stats.mempool_n, 0);
    assert_eq!(stats.fetched_n, 0);
}

#[test]
fn cmpct_reconstruct_stats_extra_disjoint_from_mempool() {
    let b1 = spend(13);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 8, 2, &[]).unwrap();
    let recon = try_reconstruct(
        &hsi,
        &shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]),
    )
    .expect("extra fill");
    let fill = CmpctFillSets {
        mempool: Default::default(),
        extra: [b1.compute_wtxid()].into_iter().collect(),
        orphan: Default::default(),
    };
    let stats = reconstruct_stats(&hsi, &recon, &fill, &[]);
    assert_eq!(stats.extra_n, 1);
    assert_eq!(stats.extra_bytes, tx_wire_len(&b1));
    assert_eq!(stats.mempool_n, 0);
    assert_eq!(stats.fetched_n, 0);
}

#[test]
fn cmpct_reconstruct_stats_orphan_bytes_sum() {
    let b1 = spend(15);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 8, 2, &[]).unwrap();
    let recon = try_reconstruct(
        &hsi,
        &shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]),
    )
    .expect("orphan fill");
    let fill = CmpctFillSets {
        mempool: Default::default(),
        extra: Default::default(),
        orphan: [b1.compute_wtxid()].into_iter().collect(),
    };
    let stats = reconstruct_stats(&hsi, &recon, &fill, &[]);
    assert_eq!(stats.orphan_n, 1);
    assert_eq!(stats.orphan_bytes, tx_wire_len(&b1));
    assert_eq!(stats.extra_n, 0);
    assert_eq!(stats.mempool_n, 0);
}

#[test]
fn cmpct_reconstruct_stats_getdata_line() {
    let hash = BlockHash::from_byte_array([0xab; 32]);
    let stats = reconstruct_getdata_stats(hash, 3);
    assert!(stats.getdata);
    assert_eq!(stats.fetched_n, 0);
    assert_eq!(
        stats.to_string(),
        format!("cmpct reconstruct {hash} getdata missing=3 fetched=0/0")
    );
}

#[test]
fn cmpct_send_line_counts_prefill_bodies() {
    let b1 = spend(14);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let hsi = HeaderAndShortIds::from_block(&block, 9, 2, &[0, 1]).unwrap();
    let line = cmpct_send_line(block.block_hash(), block.txdata.len(), &hsi);
    let pref_bytes = tx_wire_len(&block.txdata[0]) + tx_wire_len(&b1);
    assert_eq!(
        line,
        format!(
            "cmpct announce {} tx=2 prefill=2/{pref_bytes}",
            block.block_hash()
        )
    );
}

fn spend_padded(n: u8, pad: usize) -> Transaction {
    let mut tx = spend(n);
    tx.input[0].witness = Witness::from_slice(&[vec![n], vec![0u8; pad]]);
    tx
}

#[test]
fn prefill_indexes_omits_mempool_hits() {
    let b1 = spend(21);
    let b2 = spend(22);
    let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
    let fill = CmpctFillSets {
        mempool: [b1.compute_wtxid()].into_iter().collect(),
        extra: Default::default(),
        orphan: Default::default(),
    };
    let idx = prefill_indexes(&block, &fill);
    assert_eq!(idx, vec![0, 2]);
}

#[test]
fn prefill_indexes_all_mempool_is_coinbase_only() {
    let b1 = spend(23);
    let block = sealed_block(vec![coinbase(), b1.clone()]);
    let fill = CmpctFillSets {
        mempool: [b1.compute_wtxid()].into_iter().collect(),
        extra: Default::default(),
        orphan: Default::default(),
    };
    assert_eq!(prefill_indexes(&block, &fill), vec![0]);
}

#[test]
fn prefill_indexes_prefers_primary_over_extra_when_budget_tight() {
    let primary = spend_padded(24, 8_000);
    let extra = spend_padded(25, 8_000);
    let block = sealed_block(vec![coinbase(), primary.clone(), extra.clone()]);
    let fill = CmpctFillSets {
        mempool: Default::default(),
        extra: [extra.compute_wtxid()].into_iter().collect(),
        orphan: Default::default(),
    };
    let idx = prefill_indexes(&block, &fill);
    assert_eq!(idx, vec![0, 1], "extra-pool last; 10 KiB cannot fit both");
    let extra_len = bitcoin::consensus::encode::serialize(&extra).len();
    assert!(extra_len > 8_000);
}

#[test]
fn prefill_indexes_skips_oversize_extra_keeps_later_small() {
    let huge = spend_padded(26, EXTRA_PREFILL_BUDGET + 100);
    let small = spend(27);
    let block = sealed_block(vec![coinbase(), huge.clone(), small.clone()]);
    let fill = CmpctFillSets {
        mempool: Default::default(),
        extra: [huge.compute_wtxid(), small.compute_wtxid()]
            .into_iter()
            .collect(),
        orphan: Default::default(),
    };
    let idx = prefill_indexes(&block, &fill);
    assert_eq!(idx, vec![0, 2]);
}

#[test]
fn prefill_indexes_empty_fill_packs_non_coinbase() {
    let b1 = spend(28);
    let block = sealed_block(vec![coinbase(), b1]);
    assert_eq!(
        prefill_indexes(&block, &CmpctFillSets::default()),
        vec![0, 1],
        "unknown membership must not be fed to remember"
    );
    assert!(
        outbound_prefill_indexes(&block, None).is_none(),
        "missed mempool read is not an empty fill"
    );
}

#[test]
fn prefill_indexes_keeps_a_tx_that_fills_the_budget_exactly() {
    let mut pad = EXTRA_PREFILL_BUDGET;
    let tx = loop {
        let candidate = spend_padded(40, pad);
        let sz = tx_wire_len(&candidate);
        if sz == EXTRA_PREFILL_BUDGET {
            break candidate;
        }
        if sz > EXTRA_PREFILL_BUDGET {
            pad = pad.saturating_sub(sz - EXTRA_PREFILL_BUDGET);
        } else {
            pad += EXTRA_PREFILL_BUDGET - sz;
        }
    };
    assert_eq!(tx_wire_len(&tx), EXTRA_PREFILL_BUDGET);
    let block = sealed_block(vec![coinbase(), tx]);
    assert_eq!(
        prefill_indexes(&block, &CmpctFillSets::default()),
        vec![0, 1],
        "a transaction that lands on the extra-prefill budget is packed"
    );
}
