use bitcoin::absolute::LockTime;
use bitcoin::block::{Block, Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use rbitcoin_consensus::block::validate_block_structure;
use rbitcoin_consensus::{ChainParams, ConsensusError, ValidationContext};

fn ctx() -> ValidationContext<'static> {
    let params = Box::leak(Box::new(ChainParams::regtest()));
    ValidationContext::archive_structure(params)
}

fn block_with(txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1_290_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: txs,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("merkle");
    block
}

fn coinbase() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend(txid_byte: u8, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn tx_with(input: Vec<TxIn>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn assert_dup(err: ConsensusError) {
    match err {
        ConsensusError::BadTx(s) if s.contains("bad-txns-inputs-duplicate") => {}
        other => panic!("expected bad-txns-inputs-duplicate, got {other:?}"),
    }
}

#[test]
fn duplicate_input_is_one_set_for_the_block() {
    validate_block_structure(
        &block_with(vec![coinbase(), tx_with(vec![spend(1, 0)])]),
        &ctx(),
    )
    .expect("one input");

    let dup = tx_with(vec![spend(2, 0), spend(2, 0)]);
    assert_dup(validate_block_structure(&block_with(vec![coinbase(), dup]), &ctx()).unwrap_err());

    let mut cb = coinbase();
    cb.input.push(cb.input[0].clone());
    assert_dup(validate_block_structure(&block_with(vec![cb]), &ctx()).unwrap_err());

    let mut input = Vec::with_capacity(64);
    for i in 0..64u32 {
        let mut tid = [0u8; 32];
        tid[..4].copy_from_slice(&i.to_le_bytes());
        input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(tid),
                vout: i,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
    }
    validate_block_structure(&block_with(vec![coinbase(), tx_with(input)]), &ctx())
        .expect("64 unique inputs");
}
