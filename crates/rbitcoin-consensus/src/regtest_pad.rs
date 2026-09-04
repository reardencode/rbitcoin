//! Fast regtest empty-block pad (maturity) for tests in dependent crates.
//!
//! Prefer this over a local `for h in 1..=100 { mine_pow; connect }` loop.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target, Transaction,
    TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;

use crate::{
    accept_and_connect_block, apply_witness_commitment, bip34_height_script, block_has_witness,
    block_subsidy, ChainParams, Milestone,
};

pub const REGTEST_POW_BITS: u32 = 0x207f_ffff;
pub const REGTEST_BLOCK_SPACING: u32 = 600;

/// Grind `header.nonce` until PoW matches `header.bits`. Does not change version.
pub fn grind_regtest_pow(header: &mut Header) {
    let target = Target::from_compact(header.bits);
    for nonce in 0..u32::MAX {
        header.nonce = nonce;
        if header.validate_pow(target).is_ok() {
            return;
        }
    }
    panic!("regtest pow grind exhausted");
}

/// Fuzzer / tests keep txdata + version. Harness owns prev/bits/time/merkle/nonce.
pub fn prepare_regtest_candidate(block: &mut Block, prev: BlockHash, time: u32) {
    block.header.prev_blockhash = prev;
    block.header.bits = CompactTarget::from_consensus(REGTEST_POW_BITS);
    block.header.time = time;
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or(TxMerkleNode::from_byte_array([0u8; 32]));
    grind_regtest_pow(&mut block.header);
}

/// Mine one empty-ish regtest block (trivial bits).
pub fn mine_empty_regtest(prev: BlockHash, time: u32, height: u32) -> Block {
    mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        Vec::new(),
    )
}

/// Mine one regtest block paying `script_pubkey`, optional extra txs, trivial bits.
///
/// Adds a BIP141 witness commitment when any input carries witness data.
/// Confirm still goes through the normal accept/connect path (caller).
pub fn mine_regtest_paying(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
) -> Block {
    let bits = CompactTarget::from_consensus(REGTEST_POW_BITS);
    // Post-BIP65 (regtest height 1) requires nVersion ≥ 4. Core generate uses
    // VERSIONBITS_TOP_BITS; 4 is the buried minimum and enough for dersig/cltv.
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut txdata = Vec::with_capacity(1 + extra_txs.len());
    txdata.push(coinbase_paying(height, script_pubkey));
    txdata.extend(extra_txs);
    let mut block = Block { header, txdata };
    if block_has_witness(&block) {
        apply_witness_commitment(&mut block);
    } else if let Some(root) = block.compute_merkle_root() {
        block.header.merkle_root = root;
    }
    grind_regtest_pow(&mut block.header);
    block
}

fn coinbase_paying(height: u32, script_pubkey: ScriptBuf) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
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
            value: Amount::from_sat(block_subsidy(height, &ChainParams::regtest()) as u64),
            script_pubkey,
        }],
    }
}

/// Connect empty blocks `from_h..=last`. Returns tip hash/time and coinbase txids
/// for heights `1..=collect_coinbases` (empty if `collect_coinbases == 0`).
pub fn pad_empty_from(
    query: &Query,
    params: &ChainParams,
    mut tip: BlockHash,
    mut tip_time: u32,
    from_h: u32,
    last: u32,
    collect_coinbases: u32,
) -> (BlockHash, u32, Vec<Txid>) {
    let ms = Milestone::NONE;
    let mut cbs = Vec::new();
    for h in from_h..=last {
        let b = mine_empty_regtest(tip, tip_time + 600, h);
        if h >= 1 && h <= collect_coinbases {
            cbs.push(b.txdata[0].compute_txid());
        }
        accept_and_connect_block(query, params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    query.apply_sh_pending().unwrap();
    (tip, tip_time, cbs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn pad_collects_early_coinbases() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbtc-pad-{n}"));
        let q = Query::open_or_create(&dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _t, cbs) = pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            3,
            2,
        );
        assert_eq!(cbs.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mine_regtest_paying_sets_coinbase_script() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let script =
            ScriptBuf::from_bytes(vec![0x00, 0x14].into_iter().chain([0x11u8; 20]).collect());
        let b = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 1,
            1,
            script.clone(),
            vec![],
        );
        assert_eq!(b.txdata[0].output[0].script_pubkey, script);
        assert_eq!(b.header.prev_blockhash, genesis.block_hash());
        let target = Target::from_compact(b.header.bits);
        assert!(b.header.validate_pow(target).is_ok());
    }

    #[test]
    fn mine_empty_regtest_uses_regtest_halving_subsidy() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let prev = genesis.block_hash();
        let t = genesis.header.time + 1;
        let b149 = mine_empty_regtest(prev, t, 149);
        let b150 = mine_empty_regtest(prev, t, 150);
        assert_eq!(
            b149.txdata[0].output[0].value,
            Amount::from_sat(50_0000_0000)
        );
        assert_eq!(
            b150.txdata[0].output[0].value,
            Amount::from_sat(25_0000_0000)
        );
    }

    #[test]
    fn grind_regtest_pow_changes_nonce_only() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut header = genesis.header;
        header.bits = CompactTarget::from_consensus(REGTEST_POW_BITS);
        header.nonce = 0;
        let version = header.version;
        let prev = header.prev_blockhash;
        let merkle = header.merkle_root;
        let time = header.time;
        let bits = header.bits;
        grind_regtest_pow(&mut header);
        assert_eq!(header.version, version);
        assert_eq!(header.prev_blockhash, prev);
        assert_eq!(header.merkle_root, merkle);
        assert_eq!(header.time, time);
        assert_eq!(header.bits, bits);
        let target = Target::from_compact(header.bits);
        assert!(header.validate_pow(target).is_ok());
    }

    #[test]
    fn prepare_regtest_candidate_keeps_version_and_txids() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut block = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 1, 1);
        block.header.version = Version::from_consensus(5);
        let txids: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        let version = block.header.version;
        prepare_regtest_candidate(
            &mut block,
            genesis.block_hash(),
            genesis.header.time + REGTEST_BLOCK_SPACING,
        );
        assert_eq!(block.header.version, version);
        let after: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        assert_eq!(after, txids);
        assert_eq!(block.header.prev_blockhash, genesis.block_hash());
        assert_eq!(
            block.header.bits,
            CompactTarget::from_consensus(REGTEST_POW_BITS)
        );
        assert_eq!(
            block.header.merkle_root,
            block.compute_merkle_root().unwrap()
        );
        let target = Target::from_compact(block.header.bits);
        assert!(block.header.validate_pow(target).is_ok());
    }

    #[test]
    fn regtest_height1_fixture_matches_mine_empty() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let b = mine_empty_regtest(
            genesis.block_hash(),
            genesis.header.time + REGTEST_BLOCK_SPACING,
            1,
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/regtest_height1.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let got: Block = bitcoin::consensus::encode::deserialize(&raw).expect("fixture block");
        assert_eq!(got.header.prev_blockhash, genesis.block_hash());
        assert_eq!(
            got.header.bits,
            CompactTarget::from_consensus(REGTEST_POW_BITS)
        );
        let target = Target::from_compact(got.header.bits);
        assert!(got.header.validate_pow(target).is_ok());
        assert_eq!(
            bitcoin::consensus::encode::serialize(&b),
            raw,
            "regtest_height1.bin must match mine_empty_regtest(genesis, t+600, 1)"
        );
    }
}
