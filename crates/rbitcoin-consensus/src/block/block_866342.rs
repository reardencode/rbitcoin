//! Mainnet block 866342 + Floresta prevout pack (unit-test only).
//!
//! Pin is scripts + weight + merkle, not header-chain PoW. Prevouts are
//! Floresta's MIT/Apache `spent_utxos.zst` (ordered non-coinbase inputs).

#![cfg(test)]

use super::{validate_block_structure_hashed, ScriptCheckJob, ValidationContext};
use crate::error::ConsensusError;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use crate::script::core_script::decode_hex;
use crate::witness_commitment_script;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
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
// Floresta packs declare 128 MiB; ruzstd 0.9 default max is 100 MiB.
const FIXTURE_ZSTD_WINDOW: u64 = 128 * 1024 * 1024;

pub(super) fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/block_866342")
}

fn decode_zstd(path: &Path) -> Vec<u8> {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("missing fixture {path:?}: {e}"));
    let mut decoder =
        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(f, FIXTURE_ZSTD_WINDOW)
            .unwrap_or_else(|e| panic!("zstd {path:?}: {e}"));
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("zstd read {path:?}: {e}"));
    out
}

pub(super) fn load_block() -> Block {
    let raw = decode_zstd(&fixture_dir().join("raw.zst"));
    deserialize(&raw).expect("block 866342 wire")
}

pub(super) fn prevouts_from_json_zst(path: &Path) -> Vec<TxOut> {
    prevouts_from_json(&decode_zstd(path))
}

/// Floresta `spent_utxos` shape: `[{"txout": {"value", "script_pubkey"}}, …]`.
pub(super) fn prevouts_from_json(bytes: &[u8]) -> Vec<TxOut> {
    let v: Value = serde_json::from_slice(bytes).expect("spent_utxos json");
    let arr = v.as_array().expect("spent_utxos array");
    arr.iter()
        .map(|u| {
            let txout = &u["txout"];
            let sats = txout["value"].as_u64().expect("value sats");
            let spk = decode_hex(txout["script_pubkey"].as_str().expect("spk")).expect("spk hex");
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

fn oversized_866342(mut block: Block) -> Block {
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
    let reserved = {
        let w = block.txdata[0].input[0]
            .witness
            .nth(0)
            .expect("coinbase reserved");
        let mut a = [0u8; 32];
        a.copy_from_slice(w);
        a
    };
    let wtxids = block
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_wtxid().to_byte_array());
    let spk = witness_commitment_script(wtxids, &reserved);
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let pos = block.txdata[0]
        .output
        .iter()
        .rposition(|o| {
            let b = o.script_pubkey.as_bytes();
            b.len() >= 38 && b[..6] == MAGIC
        })
        .expect("witness commitment");
    block.txdata[0].output[pos].script_pubkey = ScriptBuf::from_bytes(spk);
    block.header.merkle_root = block.compute_merkle_root().expect("merkle");
    block
}

/// One job per non-coinbase tx, prevouts taken in input order.
pub(super) fn script_jobs(block: Block, prevouts: Vec<TxOut>) -> Vec<ScriptCheckJob> {
    let arc = Arc::new(block);
    let mut stxos = prevouts.into_iter();
    let jobs = (1..arc.txdata.len())
        .map(|i| {
            let tx = &arc.txdata[i];
            let prevs = tx
                .input
                .iter()
                .map(|_| stxos.next().expect("stxos short"))
                .collect();
            ScriptCheckJob::from_parts(
                tx.compute_txid().to_byte_array(),
                crate::block::JobPrevouts::owned(prevs),
                crate::block::JobTx::shared(Arc::clone(&arc), i),
                crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
            )
        })
        .collect();
    assert!(stxos.next().is_none(), "leftover spent_utxos");
    jobs
}

#[test]
fn block_866342_structure_scripts_and_overweight() {
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
    let fat = oversized_866342(block.clone());
    for job in script_jobs(block, prevouts) {
        crate::script::verify_job_all_inputs(&job)
            .unwrap_or_else(|e| panic!("866342 scripts txid={} {e}", job.tx.compute_txid()));
    }

    assert_eq!(fat.weight().to_wu(), OVERWEIGHT_WU);
    let err = validate_block_structure_hashed(&fat, &ctx).expect_err("overweight");
    match err {
        ConsensusError::BadBlock(s) => assert!(s.contains("weight"), "got {s}"),
        other => panic!("expected weight BadBlock, got {other}"),
    }

    eprintln!(
        "block_866342 structure+scripts+overweight wall={:.3}s txs={}",
        t0.elapsed().as_secs_f64(),
        n_tx
    );
}
