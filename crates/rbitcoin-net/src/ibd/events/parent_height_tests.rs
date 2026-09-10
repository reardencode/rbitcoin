//! Tests for super:: events helpers (peeled from events.rs).

use super::parent_height;
use crate::chain::ChainHub;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
    Witness,
};
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_query::Query;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        rbitcoin_consensus::bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    let coinbase = Transaction {
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
    };
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut block = Block {
        header,
        txdata: vec![coinbase],
    };
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

/// Competing header attaches to confirmed tip−1 (not tip, not in RAM map).
#[test]
fn parent_height_resolves_confirmed_tip_minus_one() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-parent-h-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let p = mine(gen, 1_600_000_100, 1);
    hub.accept_block(p.clone()).unwrap();
    let lose = mine(p.block_hash(), 1_600_000_200, 2);
    hub.accept_block(lose.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    let tip = hub.tip_hash().unwrap();
    assert_eq!(tip, lose.block_hash());

    // RAM map empty — only store knows P at height 1.
    let empty = HashMap::new();
    assert_eq!(
        parent_height(&empty, &hub, p.block_hash()),
        Some(2),
        "child of confirmed tip−1 must get height tip"
    );
    assert_eq!(
        parent_height(&empty, &hub, tip),
        Some(3),
        "child of tip still tip+1"
    );
    let unknown = BlockHash::from_byte_array([0xab; 32]);
    assert_eq!(parent_height(&empty, &hub, unknown), None);
    let _ = std::fs::remove_dir_all(dir);
}
