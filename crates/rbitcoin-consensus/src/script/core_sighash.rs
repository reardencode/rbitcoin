//! Bitcoin Core `sighash.json` harness (unit-test only).
//!
//! Each data row is `[raw_tx_hex, script_hex, input_index, hashType, sighash_hex]`.
//! Digests come from [`bitcoin::sighash::SighashCache::legacy_signature_hash`]
//! with the **raw** hashType byte (same as P2PKH / interpreter CHECKSIG).

#![cfg(test)]

use super::core_script::decode_hex;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::sha256d;
use bitcoin::sighash::SighashCache;
use bitcoin::{ScriptBuf, Transaction};
use serde_json::Value;
use std::fs;

fn load_array() -> Vec<Value> {
    let path = super::core_fixture::stage_core_json("sighash.json");
    let s = fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path:?}: {e}"));
    let v: Value = serde_json::from_str(&s).expect("sighash.json");
    v.as_array()
        .cloned()
        .unwrap_or_else(|| panic!("sighash.json: root not array"))
}

fn json_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().map(|n| n as i64))
        .or_else(|| v.as_f64().map(|n| n as i64))
}

fn sighash_row(cells: &[Value]) -> Result<sha256d::Hash, String> {
    let tx_hex = cells[0].as_str().ok_or("tx hex")?;
    let script_hex = cells[1].as_str().ok_or("script hex")?;
    let input_index = json_i64(&cells[2]).ok_or("input_index")? as usize;
    let hash_ty = json_i64(&cells[3]).ok_or("hashType")? as u32;
    let tx_bytes = decode_hex(tx_hex)?;
    let tx: Transaction = deserialize(&tx_bytes).map_err(|e| format!("tx deser: {e}"))?;
    let script_bytes = decode_hex(script_hex)?;
    let stripped = super::interpreter::strip_op_codeseparator(&script_bytes);
    let script = ScriptBuf::from_bytes(stripped);
    let cache = SighashCache::new(&tx);
    let h = cache
        .legacy_signature_hash(input_index, script.as_script(), hash_ty)
        .map_err(|e| format!("sighash: {e}"))?;
    Ok(h.into())
}

#[test]
// btc-lean: SCR-140 SCR-164 SCR-165 SCR-169 SWT-042 SWT-043 SWT-044 SWT-045 SWT-046 SWT-047 SWT-048
// btc-lean: SWT-049 SWT-050 SWT-051 SWT-052 SWT-053 SWT-054 SWT-055 SWT-066
fn core_sighash_all_rows() {
    let rows = load_array();
    let mut total = 0u32;
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut failures = Vec::new();
    for (idx, row) in rows.iter().enumerate() {
        let Value::Array(cells) = row else {
            continue;
        };
        if cells.len() < 5 || !cells[0].is_string() || cells[0].as_str() == Some("") {
            continue;
        }
        if cells[0]
            .as_str()
            .is_some_and(|s| s.starts_with("raw_transaction"))
        {
            continue;
        }
        total += 1;
        let want_hex = cells[4].as_str().unwrap_or("");
        let want: sha256d::Hash = match want_hex.parse() {
            Ok(w) => w,
            Err(e) => {
                fail += 1;
                if failures.len() < 20 {
                    failures.push(format!("#{idx} bad expected hash {e}"));
                }
                continue;
            }
        };
        match sighash_row(cells) {
            Ok(got) if got == want => pass += 1,
            Ok(got) => {
                fail += 1;
                if failures.len() < 20 {
                    failures.push(format!("#{idx} got={got} want={want_hex}"));
                }
            }
            Err(e) => {
                fail += 1;
                if failures.len() < 20 {
                    failures.push(format!("#{idx} {e}"));
                }
            }
        }
    }
    eprintln!("core sighash: total={total} pass={pass} fail={fail}");
    for f in &failures {
        eprintln!("  FAIL {f}");
    }
    assert!(total > 100, "expected many sighash rows, total={total}");
    assert_eq!(fail, 0, "sighash.json failures: {fail}");
    assert_eq!(pass, total);
}
