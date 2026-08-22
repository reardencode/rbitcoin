//! Bitcoin Core `bip341_wallet_vectors.json` harness (unit-test only).
//!
//! Key-path spends (including mixed P2PKH/P2WPKH inputs on the same tx) go
//! through [`crate::script::verify_job_all_inputs`]. Unknown-leaf script-path
//! rows (non-`0xc0`) go through the same job: BIP341 commitment must hold and
//! the leaf is not executed. This Core file has no marked-invalid spends.

#![cfg(test)]

use crate::block::ScriptCheckJob;
use crate::script;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::Value;
use std::fs;

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let h = s.trim();
    if !h.len().is_multiple_of(2) {
        return Err(format!("odd hex len {}", h.len()));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for i in (0..h.len()).step_by(2) {
        out.push(u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn load_root() -> Value {
    let path = super::core_fixture::stage_core_json("bip341_wallet_vectors.json");
    let s = fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path:?}: {e}"));
    serde_json::from_str(&s).expect("bip341_wallet_vectors.json")
}

fn taproot_job(tx: Transaction, prevouts: Vec<TxOut>) -> ScriptCheckJob {
    ScriptCheckJob::new(prevouts, tx, true, true, true, true, true)
}

fn utxos_spent(v: &Value) -> Result<Vec<TxOut>, String> {
    let arr = v.as_array().ok_or("utxosSpent not array")?;
    let mut out = Vec::with_capacity(arr.len());
    for u in arr {
        let spk = decode_hex(u.get("scriptPubKey").and_then(Value::as_str).ok_or("spk")?)?;
        let sats = u
            .get("amountSats")
            .and_then(Value::as_i64)
            .ok_or("amountSats")? as u64;
        out.push(TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(spk),
        });
    }
    Ok(out)
}

fn witness_from_hex_arr(v: &Value) -> Result<Witness, String> {
    let arr = v.as_array().ok_or("witness not array")?;
    let mut items = Vec::with_capacity(arr.len());
    for el in arr {
        items.push(decode_hex(el.as_str().ok_or("witness hex")?)?);
    }
    let refs: Vec<&[u8]> = items.iter().map(|b| b.as_slice()).collect();
    Ok(Witness::from_slice(&refs))
}

fn collect_leaves(node: &Value, out: &mut Vec<(usize, Vec<u8>, u8)>) -> Result<(), String> {
    if node.is_null() {
        return Ok(());
    }
    if let Some(obj) = node.as_object() {
        let id = obj.get("id").and_then(Value::as_i64).ok_or("leaf id")? as usize;
        let script = decode_hex(
            obj.get("script")
                .and_then(Value::as_str)
                .ok_or("leaf script")?,
        )?;
        let lv = obj
            .get("leafVersion")
            .and_then(Value::as_i64)
            .ok_or("leafVersion")? as u8;
        out.push((id, script, lv));
        return Ok(());
    }
    let arr = node.as_array().ok_or("scriptTree node")?;
    if arr.len() != 2 {
        return Err("scriptTree pair".into());
    }
    collect_leaves(&arr[0], out)?;
    collect_leaves(&arr[1], out)?;
    Ok(())
}

fn unknown_leaf_spend(spk_hex: &str, script: &[u8], control_hex: &str) -> Result<(), String> {
    let spk = decode_hex(spk_hex)?;
    let control = decode_hex(control_hex)?;
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[script, control.as_slice()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = taproot_job(tx, vec![prevout]);
    script::verify_job_all_inputs(&job).map_err(|e| e.to_string())
}

#[test]
fn core_bip341_wallet_vectors_all_rows() {
    let root = load_root();
    let mut total = 0u32;
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut failures = Vec::new();

    let key_path = root
        .get("keyPathSpending")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (vi, vec) in key_path.iter().enumerate() {
        let given = &vec["given"];
        let prevouts = match utxos_spent(&given["utxosSpent"]) {
            Ok(p) => p,
            Err(e) => {
                fail += 1;
                failures.push(format!("keyPath#{vi} utxos: {e}"));
                continue;
            }
        };
        let signed_hex = vec["auxiliary"]["fullySignedTx"].as_str().unwrap_or("");
        match decode_hex(signed_hex)
            .and_then(|b| deserialize::<Transaction>(&b).map_err(|e| format!("fullySignedTx: {e}")))
        {
            Ok(tx) => {
                total += 1;
                let job = taproot_job(tx, prevouts.clone());
                match script::verify_job_all_inputs(&job) {
                    Ok(()) => pass += 1,
                    Err(e) => {
                        fail += 1;
                        failures.push(format!("keyPath#{vi} fullySignedTx: {e}"));
                    }
                }
            }
            Err(e) => {
                total += 1;
                fail += 1;
                failures.push(format!("keyPath#{vi} {e}"));
            }
        }

        let unsigned_bytes = match given["rawUnsignedTx"]
            .as_str()
            .ok_or_else(|| "rawUnsignedTx".to_string())
            .and_then(decode_hex)
        {
            Ok(b) => b,
            Err(e) => {
                fail += 1;
                failures.push(format!("keyPath#{vi} unsigned: {e}"));
                continue;
            }
        };
        let unsigned: Transaction = match deserialize(&unsigned_bytes) {
            Ok(t) => t,
            Err(e) => {
                fail += 1;
                failures.push(format!("keyPath#{vi} unsigned deser: {e}"));
                continue;
            }
        };
        let spends = vec["inputSpending"].as_array().cloned().unwrap_or_default();
        for (si, spend) in spends.iter().enumerate() {
            total += 1;
            let idx = spend["given"]["txinIndex"].as_i64().unwrap_or(-1) as usize;
            match witness_from_hex_arr(&spend["expected"]["witness"]) {
                Ok(wit) => {
                    let mut tx = unsigned.clone();
                    if idx >= tx.input.len() {
                        fail += 1;
                        failures.push(format!("keyPath#{vi}.{si} bad txinIndex {idx}"));
                        continue;
                    }
                    tx.input[idx].witness = wit;
                    let job = taproot_job(tx, prevouts.clone());
                    let tx_ref: &Transaction = &*job.tx;
                    match script::verify_input(&job, idx, tx_ref, &mut None, job.pre()) {
                        Ok(()) => pass += 1,
                        Err(e) => {
                            fail += 1;
                            failures.push(format!("keyPath#{vi}.{si} vin={idx}: {e}"));
                        }
                    }
                }
                Err(e) => {
                    fail += 1;
                    failures.push(format!("keyPath#{vi}.{si} witness: {e}"));
                }
            }
        }
    }

    let spks = root
        .get("scriptPubKey")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (si, vec) in spks.iter().enumerate() {
        let tree = &vec["given"]["scriptTree"];
        let mut leaves = Vec::new();
        if let Err(e) = collect_leaves(tree, &mut leaves) {
            fail += 1;
            failures.push(format!("spk#{si} tree: {e}"));
            continue;
        }
        let spk = vec["expected"]["scriptPubKey"].as_str().unwrap_or("");
        let cbs = vec["expected"]["scriptPathControlBlocks"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for (id, script, lv) in leaves {
            if lv == 0xc0 {
                continue;
            }
            total += 1;
            let Some(cb) = cbs.get(id).and_then(Value::as_str) else {
                fail += 1;
                failures.push(format!("spk#{si} leaf {id}: missing control block"));
                continue;
            };
            match unknown_leaf_spend(spk, &script, cb) {
                Ok(()) => pass += 1,
                Err(e) => {
                    fail += 1;
                    failures.push(format!("spk#{si} leaf {id} lv={lv:#x}: {e}"));
                }
            }
        }
    }

    eprintln!("core bip341 wallet: total={total} pass={pass} fail={fail}");
    for f in &failures {
        eprintln!("  FAIL {f}");
    }
    assert!(total > 5, "expected several BIP341 spends, total={total}");
    assert_eq!(fail, 0, "bip341_wallet_vectors.json failures: {fail}");
    assert_eq!(pass, total);
}

#[test]
fn core_bip341_fully_signed_tamper_rejects() {
    let root = load_root();
    let vec = &root["keyPathSpending"][0];
    let prevouts = utxos_spent(&vec["given"]["utxosSpent"]).expect("utxos");
    let mut raw = decode_hex(vec["auxiliary"]["fullySignedTx"].as_str().unwrap()).unwrap();
    // Flip a byte in the first witness stack item (after the compact-size header).
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let tx: Transaction = deserialize(&raw).expect("still a tx");
    let job = taproot_job(tx, prevouts);
    assert!(
        script::verify_job_all_inputs(&job).is_err(),
        "tampered fullySignedTx must reject"
    );
}
