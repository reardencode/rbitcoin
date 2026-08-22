//! Mainnet block 866342 + Floresta prevout pack (unit-test only).
//!
//! Pin is scripts + weight + merkle, not header-chain PoW. Prevouts are
//! Floresta's MIT/Apache `spent_utxos.zst` (ordered non-coinbase inputs).

#![cfg(test)]

use super::{
    merkle_root_bytes, validate_block_structure_hashed, ScriptCheckJob, ValidationContext,
};
use crate::error::ConsensusError;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use rbitcoin_primitives::Height;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const HEIGHT: u32 = 866_342;
const BLOCK_HASH: &str = "000000000000000000014ce9ba7c6760053c3c82ce6ab43d60afb101d3c8f1f1";
const HAPPY_WEIGHT_WU: u64 = 3_993_209;
const OVERWEIGHT_WU: u64 = 4_000_001;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/block_866342")
}

fn decode_zstd(path: &Path) -> Vec<u8> {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("missing fixture {path:?}: {e}"));
    let mut decoder =
        ruzstd::decoding::StreamingDecoder::new(f).unwrap_or_else(|e| panic!("zstd {path:?}: {e}"));
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("zstd read {path:?}: {e}"));
    out
}

fn load_block() -> Block {
    let raw = decode_zstd(&fixture_dir().join("raw.zst"));
    deserialize(&raw).expect("block 866342 wire")
}

fn decode_hex(s: &str) -> Vec<u8> {
    let h = s.trim();
    assert!(h.len().is_multiple_of(2), "odd hex");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

fn prevouts_from_json_zst(path: &Path) -> Vec<TxOut> {
    let bytes = decode_zstd(path);
    let v: Value = serde_json::from_slice(&bytes).expect("spent_utxos json");
    let arr = v.as_array().expect("spent_utxos array");
    arr.iter()
        .map(|u| {
            let txout = &u["txout"];
            let sats = txout["value"].as_u64().expect("value sats");
            let spk = decode_hex(txout["script_pubkey"].as_str().expect("spk"));
            TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }
        })
        .collect()
}

fn ctx() -> ValidationContext<'static> {
    let params = Box::leak(Box::new(ChainParams::mainnet()));
    ValidationContext::at(params, Height(HEIGHT), Milestone::NONE)
}

fn patch_witness_commitment(block: &mut Block) {
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let reserved = {
        let w = block.txdata[0].input[0]
            .witness
            .nth(0)
            .expect("coinbase reserved");
        let mut a = [0u8; 32];
        a.copy_from_slice(w);
        a
    };
    let mut leaves = vec![[0u8; 32]];
    for tx in block.txdata.iter().skip(1) {
        leaves.push(tx.compute_wtxid().to_byte_array());
    }
    let witness_root = merkle_root_bytes(&leaves);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    buf[32..].copy_from_slice(&reserved);
    let hash = sha256d::Hash::hash(&buf);
    let pos = block.txdata[0]
        .output
        .iter()
        .rposition(|o| {
            let b = o.script_pubkey.as_bytes();
            b.len() >= 38 && b[..6] == MAGIC
        })
        .expect("witness commitment");
    let mut spk = Vec::with_capacity(38);
    spk.extend_from_slice(&MAGIC);
    spk.extend_from_slice(&hash.to_byte_array());
    block.txdata[0].output[pos].script_pubkey = ScriptBuf::from_bytes(spk);
    block.header.merkle_root = block.compute_merkle_root().expect("merkle");
}

fn oversized_866342() -> Block {
    let mut block = load_block();
    let extra = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x61; 1_636]),
        }],
    };
    block.txdata.insert(1, extra);
    patch_witness_commitment(&mut block);
    block
}

#[test]
fn block_866342_structure_and_scripts() {
    let t0 = Instant::now();
    let block = load_block();
    assert_eq!(
        block.block_hash(),
        BLOCK_HASH.parse::<BlockHash>().expect("hash")
    );
    assert_eq!(block.weight().to_wu(), HAPPY_WEIGHT_WU);

    let ctx = ctx();
    validate_block_structure_hashed(&block, &ctx).expect("structure 866342");

    let prevouts = prevouts_from_json_zst(&fixture_dir().join("spent_utxos.zst"));
    let n_in: usize = block.txdata.iter().skip(1).map(|tx| tx.input.len()).sum();
    assert_eq!(
        prevouts.len(),
        n_in,
        "spent_utxos must map 1:1 onto non-coinbase inputs"
    );

    let n_tx = block.txdata.len();
    let arc = Arc::new(block);
    let mut stxos = prevouts.into_iter();
    for i in 1..n_tx {
        let tx = &arc.txdata[i];
        let mut prevs = Vec::with_capacity(tx.input.len());
        for _ in &tx.input {
            prevs.push(stxos.next().expect("stxos short"));
        }
        let txid = tx.compute_txid().to_byte_array();
        let job = ScriptCheckJob::with_shared_tx(
            txid,
            prevs,
            Arc::clone(&arc),
            i,
            true,
            true,
            true,
            true,
            true,
        );
        crate::script::verify_job_all_inputs(&job).unwrap_or_else(|e| {
            panic!(
                "866342 scripts tx index {i} txid={} {e}",
                arc.txdata[i].compute_txid()
            )
        });
    }
    assert!(stxos.next().is_none(), "leftover spent_utxos");
    eprintln!(
        "block_866342 structure+scripts wall={:.3}s txs={}",
        t0.elapsed().as_secs_f64(),
        n_tx
    );
}

#[test]
fn block_866342_overweight_rejects() {
    let block = oversized_866342();
    assert_eq!(block.weight().to_wu(), OVERWEIGHT_WU);
    let ctx = ctx();
    let err = validate_block_structure_hashed(&block, &ctx).expect_err("overweight");
    match err {
        ConsensusError::BadBlock(s) => assert!(s.contains("weight"), "got {s}"),
        other => panic!("expected weight BadBlock, got {other}"),
    }
}
