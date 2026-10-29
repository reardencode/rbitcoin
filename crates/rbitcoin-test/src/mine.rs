//! Regtest block construction helpers for high-level consensus scenarios.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};

/// BIP34 height encoding in coinbase scriptSig (Core `CScript << height`).
pub fn bip34_script(height: u32) -> ScriptBuf {
    ScriptBuf::from_bytes(rbitcoin_consensus::bip34_height_script(height))
}

pub fn coinbase_tx(height: u32, value: Amount) -> Transaction {
    rbitcoin_consensus::regtest_coinbase(
        height,
        value,
        ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]),
    )
}

/// Simple P2WPKH-like anyone-can-spend spend of a previous OP_TRUE output is not needed;
/// for connect tests we spend OP_TRUE with empty scriptSig.
pub fn spend_anyone_can_spend(prev_txid: bitcoin::Txid, vout: u32, value: Amount) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]),
        }],
    }
}

/// One-input, multi-output anyone-can-spend create (for multi-vout parent tests).
pub fn split_anyone_can_spend(
    prev_txid: bitcoin::Txid,
    vout: u32,
    values: &[Amount],
) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: values
            .iter()
            .map(|value| TxOut {
                value: *value,
                script_pubkey: ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]),
            })
            .collect(),
    }
}

/// Spend several OP_TRUE prevouts in one tx (one output).
pub fn spend_many_anyone_can_spend(prevs: &[(bitcoin::Txid, u32)], value: Amount) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: prevs
            .iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint {
                    txid: *txid,
                    vout: *vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]),
        }],
    }
}

/// Mine a regtest block on top of `prev_hash` (or genesis prev null).
pub fn mine_regtest_block(
    prev_hash: BlockHash,
    time: u32,
    height: u32,
    extra_txs: Vec<Transaction>,
) -> Block {
    mine_regtest_block_at(
        prev_hash,
        time,
        height,
        CompactTarget::from_consensus(rbitcoin_consensus::REGTEST_POW_BITS),
        extra_txs,
    )
}

/// Mine a regtest block at an explicit `nBits` and timestamp.
///
/// Always pays a fixed 50 BTC `OP_TRUE` coinbase and does not add a BIP141
/// commitment. Callers that want the halving subsidy or a witness commitment
/// use [`rbitcoin_consensus::mine_regtest_paying`].
pub fn mine_regtest_block_at(
    prev_hash: BlockHash,
    time: u32,
    height: u32,
    bits: CompactTarget,
    extra_txs: Vec<Transaction>,
) -> Block {
    let mut txdata = vec![coinbase_tx(height, Amount::from_sat(50_0000_0000))];
    txdata.extend(extra_txs);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev_hash,
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .expect("non-empty block has merkle root");
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

pub fn regtest_genesis() -> Block {
    bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
}
