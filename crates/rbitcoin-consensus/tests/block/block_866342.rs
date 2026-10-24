//! Mainnet block 866342 + Floresta prevout pack (unit-test only).
//!
//! Pin is scripts + weight + merkle, not header-chain PoW. Prevouts are
//! Floresta's MIT/Apache `spent_utxos.zst` (ordered non-coinbase inputs).
#![cfg(test)]
use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, Transaction, TxOut, Witness};
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::milestone::Milestone;
use rbitcoin_consensus::params::ChainParams;
use rbitcoin_primitives::Height;
use std::sync::Arc;
use std::time::Instant;

use rbitcoin_consensus::block::{
    validate_block_structure_hashed, ScriptCheckJob, ValidationContext,
};

use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use rbitcoin_consensus::script::core_script::decode_hex;
use rbitcoin_consensus::witness_commitment_script;

use bitcoin::{BlockHash, OutPoint, Sequence, TxIn};

use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

const HEIGHT: u32 = 866_342;
const BLOCK_HASH: &str = "000000000000000000014ce9ba7c6760053c3c82ce6ab43d60afb101d3c8f1f1";
const HAPPY_WEIGHT_WU: u64 = 3_993_209;
const OVERWEIGHT_WU: u64 = 4_000_001;
// Floresta packs declare 128 MiB; ruzstd 0.9 default max is 100 MiB.
const FIXTURE_ZSTD_WINDOW: u64 = 128 * 1024 * 1024;

fn fixture_dir() -> PathBuf {
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

fn load_block() -> Block {
    let raw = decode_zstd(&fixture_dir().join("raw.zst"));
    deserialize(&raw).expect("block 866342 wire")
}

fn prevouts_from_json_zst(path: &Path) -> Vec<TxOut> {
    let bytes = decode_zstd(path);
    let v: Value = serde_json::from_slice(&bytes).expect("spent_utxos json");
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
    let arc = Arc::new(block);
    let mut stxos = prevouts.into_iter();
    for i in 1..n_tx {
        let tx = &arc.txdata[i];
        let mut prevs = Vec::with_capacity(tx.input.len());
        for _ in &tx.input {
            prevs.push(stxos.next().expect("stxos short"));
        }
        let txid = tx.compute_txid().to_byte_array();
        let job = ScriptCheckJob::try_from_parts(
            txid,
            rbitcoin_consensus::block::JobPrevouts::owned(prevs),
            rbitcoin_consensus::block::JobTx::shared(Arc::clone(&arc), i),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        )
        .expect("prevouts");
        rbitcoin_consensus::script::verify_job_all_inputs(&job).unwrap_or_else(|e| {
            panic!(
                "866342 scripts tx index {i} txid={} {e}",
                arc.txdata[i].compute_txid()
            )
        });
    }
    assert!(stxos.next().is_none(), "leftover spent_utxos");

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
