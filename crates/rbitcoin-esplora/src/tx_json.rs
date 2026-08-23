//! Build Esplora-shaped transaction JSON from store Class A + wire reconstruct.

use crate::script_fields::esplora_script_fields;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use rbitcoin_primitives::hex_encode;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::{Query, QueryError, ScriptHashHistoryItem, ScriptHashUtxo};
use rbitcoin_store::InputRecord;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Esplora `status` object for a Class A tx fk (confirmed or not).
pub fn tx_status_json(query: &Query, tx_fk: Fk) -> Result<Value, QueryError> {
    match query.pin_chain_view()? {
        Some(view) => tx_status_json_in(query, tx_fk, &view),
        None => Ok(json!({ "confirmed": false })),
    }
}

/// Confirmation status as of `view`.
pub fn tx_status_json_in(
    query: &Query,
    tx_fk: Fk,
    view: &rbitcoin_query::ChainView,
) -> Result<Value, QueryError> {
    let confirmed = query
        .store()
        .is_confirmed_strong_at(tx_fk, Some(view.height.0))?;
    if !confirmed {
        return Ok(json!({ "confirmed": false }));
    }
    let height = query.store().tx_height_get(tx_fk)?.unwrap_or(0);
    let mut out = json!({
        "confirmed": true,
        "block_height": height,
    });
    if let Some((_fk, rec)) = query.header_at_height(Height(height))? {
        out["block_hash"] = Value::String(block_hash_hex(&rec.hash));
        out["block_time"] = json!(rec.timestamp);
    }
    Ok(out)
}

#[derive(Serialize)]
struct EsploraUtxoStatus {
    confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_time: Option<u32>,
}

#[derive(Serialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: i64,
    status: EsploraUtxoStatus,
}

/// Unique create-height → `(block_hash, block_time)` for Esplora `/utxo` status.
pub fn utxo_status_by_height(
    query: &Query,
    heights: impl IntoIterator<Item = u32>,
) -> Result<HashMap<u32, (String, u32)>, QueryError> {
    let mut map = HashMap::new();
    for h in heights {
        if map.contains_key(&h) {
            continue;
        }
        if let Some((_fk, rec)) = query.header_at_height(Height(h))? {
            map.insert(h, (block_hash_hex(&rec.hash), rec.timestamp));
        }
    }
    Ok(map)
}

/// Confirmed (and optional mempool) Esplora `/utxo` array.
///
/// Mempool rows (`create_tx_fk` null) are `{ confirmed: false }` with no block_*.
pub fn utxo_list_json(query: &Query, list: &[ScriptHashUtxo]) -> Result<Value, QueryError> {
    let by_h = utxo_status_by_height(
        query,
        list.iter()
            .filter(|u| !u.create_tx_fk.is_null())
            .map(|u| u.height),
    )?;
    let rows: Vec<EsploraUtxo> = list
        .iter()
        .map(|u| {
            if u.create_tx_fk.is_null() {
                return EsploraUtxo {
                    txid: block_hash_hex(&u.tx_hash),
                    vout: u.tx_pos,
                    value: u.value,
                    status: EsploraUtxoStatus {
                        confirmed: false,
                        block_height: None,
                        block_hash: None,
                        block_time: None,
                    },
                };
            }
            let (block_hash, block_time) = match by_h.get(&u.height) {
                Some((h, t)) => (Some(h.clone()), Some(*t)),
                None => (None, None),
            };
            EsploraUtxo {
                txid: block_hash_hex(&u.tx_hash),
                vout: u.tx_pos,
                value: u.value,
                status: EsploraUtxoStatus {
                    confirmed: true,
                    block_height: Some(u.height),
                    block_hash,
                    block_time,
                },
            }
        })
        .collect();
    serde_json::to_value(rows)
        .map_err(|_| rbitcoin_store::StoreError::Corrupt("invariant: utxo json").into())
}

/// Confirmed history rows → Esplora tx JSON using join fks (no `tx.head`).
pub fn history_items_to_tx_json(
    query: &Query,
    items: &[ScriptHashHistoryItem],
    network: Network,
) -> Result<Vec<Value>, QueryError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.tx_fk.is_null() {
            continue;
        }
        out.push(build_tx_json(query, item.tx_fk, network)?);
    }
    Ok(out)
}

/// Full `GET /tx/:txid` body (Esplora API.md transaction format).
pub fn build_tx_json(query: &Query, tx_fk: Fk, network: Network) -> Result<Value, QueryError> {
    let wire = query.reconstruct_tx(tx_fk)?;
    let status = tx_status_json(query, tx_fk)?;
    let (_meta, stored_inputs, _outs) = query.store().get_tx_full(tx_fk)?;

    let mut vin = Vec::with_capacity(wire.input.len());
    let mut fee_in: Option<i64> = Some(0);
    for (i, tin) in wire.input.iter().enumerate() {
        let is_coinbase = tin.previous_output.is_null();
        let mut vin_obj = json!({
            "txid": if is_coinbase {
                "0".repeat(64)
            } else {
                format!("{}", tin.previous_output.txid)
            },
            "vout": if is_coinbase { 0xFFFFFFFFu32 } else { tin.previous_output.vout },
            "is_coinbase": is_coinbase,
            "sequence": tin.sequence.to_consensus_u32(),
        });

        let ss = tin.script_sig.as_bytes();
        let ss_f = esplora_script_fields(ss, network);
        vin_obj["scriptsig"] = Value::String(ss_f.hex);
        vin_obj["scriptsig_asm"] = Value::String(ss_f.asm);

        let wit: Vec<String> = tin.witness.iter().map(hex_encode).collect();
        vin_obj["witness"] = json!(wit);

        if let Some(asm) = inner_redeemscript_asm(ss) {
            vin_obj["inner_redeemscript_asm"] = Value::String(asm);
        }
        if let Some(asm) = inner_witnessscript_asm(&wit) {
            vin_obj["inner_witnessscript_asm"] = Value::String(asm);
        }

        if !is_coinbase {
            if let Some(prev) = prevout_json(query, &stored_inputs, i, tin, network)? {
                if let Some(v) = prev.get("value").and_then(|x| x.as_i64()) {
                    if let Some(acc) = fee_in.as_mut() {
                        *acc = acc.saturating_add(v);
                    }
                } else {
                    fee_in = None;
                }
                vin_obj["prevout"] = prev;
            } else {
                fee_in = None;
            }
        }

        vin.push(vin_obj);
    }

    let mut vout = Vec::with_capacity(wire.output.len());
    let mut out_sum: i64 = 0;
    for tout in &wire.output {
        let val = tout.value.to_sat() as i64;
        out_sum = out_sum.saturating_add(val);
        let spk_f = esplora_script_fields(tout.script_pubkey.as_bytes(), network);
        let mut o = json!({
            "scriptpubkey": spk_f.hex,
            "scriptpubkey_asm": spk_f.asm,
            "scriptpubkey_type": spk_f.script_type,
            "value": val,
        });
        if let Some(addr) = spk_f.address {
            o["scriptpubkey_address"] = Value::String(addr);
        }
        vout.push(o);
    }

    let weight = wire.weight().to_wu();
    let size = wire.total_size();
    // Prefer Class A stored txid so history cursors and /tx routes share identity
    // (reconstructed wire hash matches in production; fixtures may differ).
    let stored_txid = query
        .store()
        .txs
        .body_txid(tx_fk)
        .unwrap_or_else(|_| wire.compute_txid().to_byte_array());
    let mut obj = json!({
        "txid": block_hash_hex(&stored_txid),
        "version": wire.version.0,
        "locktime": wire.lock_time.to_consensus_u32(),
        "size": size,
        "weight": weight,
        "vin": vin,
        "vout": vout,
        "status": status,
    });

    if let Some(ins) = fee_in {
        if wire.is_coinbase() {
            obj["fee"] = json!(0);
        } else {
            obj["fee"] = json!(ins.saturating_sub(out_sum));
        }
    }

    Ok(obj)
}

fn prevout_json(
    query: &Query,
    stored_inputs: &[InputRecord],
    idx: usize,
    tin: &bitcoin::TxIn,
    network: Network,
) -> Result<Option<Value>, QueryError> {
    if let Some(inp) = stored_inputs.get(idx) {
        if !inp.create_fk.is_null() {
            if let Ok(out) = query.tx_output_at_fk(inp.create_fk, inp.prev_index) {
                return Ok(Some(vout_fields(&out.script, out.value, network)));
            }
        }
    }
    let prev_txid = tin.previous_output.txid.to_byte_array();
    if let Some(pfk) = query.tx_fk_by_txid(&prev_txid)? {
        if let Ok(out) = query.tx_output_at_fk(pfk, tin.previous_output.vout) {
            return Ok(Some(vout_fields(&out.script, out.value, network)));
        }
    }
    Ok(None)
}

fn vout_fields(script: &[u8], value: i64, network: Network) -> Value {
    let f = esplora_script_fields(script, network);
    let mut o = json!({
        "scriptpubkey": f.hex,
        "scriptpubkey_asm": f.asm,
        "scriptpubkey_type": f.script_type,
        "value": value,
    });
    if let Some(addr) = f.address {
        o["scriptpubkey_address"] = Value::String(addr);
    }
    o
}

fn block_hash_hex(hash: &[u8; 32]) -> String {
    let mut rev = *hash;
    rev.reverse();
    hex_encode(rev)
}

/// Last push of scriptSig as redeemscript asm (P2SH).
fn inner_redeemscript_asm(script_sig: &[u8]) -> Option<String> {
    let last = last_push_data(script_sig)?;
    if last.is_empty() {
        return None;
    }
    Some(bitcoin::Script::from_bytes(last).to_asm_string())
}

fn is_der_sig_prefix(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x30)
}

/// Witness script: last stack item when it looks like a script (P2WSH / nested).
fn inner_witnessscript_asm(witness_hex: &[String]) -> Option<String> {
    if witness_hex.len() < 2 {
        return None;
    }
    let last = witness_hex.last()?;
    let bytes = rbitcoin_primitives::hex_decode(last).ok()?;
    if bytes.is_empty() || bytes.len() > 10_000 {
        return None;
    }
    if is_der_sig_prefix(&bytes) {
        return None;
    }
    Some(bitcoin::Script::from_bytes(&bytes).to_asm_string())
}

fn last_push_data(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    let mut last: Option<&[u8]> = None;
    while i < script.len() {
        let op = script[i];
        i += 1;
        if op <= 0x4b {
            let n = op as usize;
            if i + n > script.len() {
                break;
            }
            last = Some(&script[i..i + n]);
            i += n;
        } else if op == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            i += 1;
            if i + n > script.len() {
                break;
            }
            last = Some(&script[i..i + n]);
            i += n;
        } else if op == 0x4d {
            if i + 2 > script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            if i + n > script.len() {
                break;
            }
            last = Some(&script[i..i + n]);
            i += n;
        } else {
            last = None;
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_push_data_direct_and_pushdata() {
        // OP_1 (non-push) clears last.
        assert!(last_push_data(&[0x51]).is_none());
        // Direct push of 2 bytes.
        assert_eq!(last_push_data(&[0x02, 0xaa, 0xbb]), Some(&[0xaa, 0xbb][..]));
        // Truncated direct push → break with no complete last from this op.
        assert!(last_push_data(&[0x03, 0xaa]).is_none());
        // OP_PUSHDATA1
        assert_eq!(
            last_push_data(&[0x4c, 0x02, 0x11, 0x22]),
            Some(&[0x11, 0x22][..])
        );
        assert!(last_push_data(&[0x4c]).is_none()); // missing length
        assert!(last_push_data(&[0x4c, 0x05, 0x01]).is_none()); // truncated body
                                                                // OP_PUSHDATA2
        assert_eq!(
            last_push_data(&[0x4d, 0x02, 0x00, 0x33, 0x44]),
            Some(&[0x33, 0x44][..])
        );
        assert!(last_push_data(&[0x4d, 0x01]).is_none()); // short len field
        assert!(last_push_data(&[0x4d, 0x03, 0x00, 0x01]).is_none()); // short body
                                                                      // Non-push after push clears last.
        assert!(last_push_data(&[0x01, 0xaa, 0x51]).is_none());
        // Empty push then real push.
        assert_eq!(last_push_data(&[0x00, 0x01, 0xee]), Some(&[0xee][..]));
    }

    #[test]
    fn redeem_and_witness_script_asm_helpers() {
        assert!(inner_redeemscript_asm(&[]).is_none());
        assert!(inner_redeemscript_asm(&[0x00]).is_none()); // empty push
        let redeem = inner_redeemscript_asm(&[0x01, 0x51]).unwrap();
        assert!(redeem.contains("OP_1") || redeem.contains("1"));

        assert!(inner_witnessscript_asm(&[]).is_none());
        assert!(inner_witnessscript_asm(&[String::from("51")]).is_none()); // len < 2
                                                                           // Two items, last is OP_TRUE script — not a DER sig.
        let asm = inner_witnessscript_asm(&[String::from("00"), String::from("51")]).unwrap();
        assert!(!asm.is_empty());
        // DER-looking last item skipped.
        assert!(inner_witnessscript_asm(&[String::from("00"), String::from("3000")]).is_none());
        // Empty last stack item.
        assert!(inner_witnessscript_asm(&[String::from("00"), String::new()]).is_none());
        // Invalid hex.
        assert!(inner_witnessscript_asm(&[String::from("00"), String::from("zz")]).is_none());
    }

    #[test]
    fn block_hash_hex_reverses_bytes() {
        let mut h = [0u8; 32];
        h[0] = 0xab;
        h[31] = 0xcd;
        let s = block_hash_hex(&h);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("cd"));
        assert!(s.ends_with("ab"));
    }

    #[test]
    fn utxo_list_json_status_from_join_height_without_tx_head() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{script_hash, HeaderRecord, InputRecord, OutputRecord, TxRecord};
        use std::time::{SystemTime, UNIX_EPOCH};

        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-esplora-utxo-json-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();

        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..2u32 {
            let version = 1;
            let timestamp = h + 1;
            let bits = 0x207fffff;
            let nonce = h;
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xab;
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version,
                timestamp,
                bits,
                nonce,
                merkle_root: merkle,
                hash,
            };
            let mut txid = [0u8; 32];
            txid[0..4].copy_from_slice(&h.to_le_bytes());
            txid[31] = 0xcb;
            let outputs = if h == 1 {
                vec![
                    OutputRecord::unspent(50_0000_0000, vec![0x51]),
                    OutputRecord::unspent(1_0000_0000, vec![0x51]),
                ]
            } else {
                vec![OutputRecord::unspent(50_0000_0000, vec![0x51])]
            };
            let ta = TxApply {
                tx: TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: outputs.len() as u32,
                },
                inputs: vec![InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: Fk::NULL,
                    prev_index: u32::MAX,
                    sequence: u32::MAX,
                    script_sig: vec![h as u8],
                    witness: vec![],
                }],
                outputs,
            };
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            parent_hash = Some(hash);
        }

        let sh = script_hash(&[0x51]);
        let list = q.scripthash_listunspent(&sh).unwrap();
        assert_eq!(list.len(), 3);
        let at0 = list.iter().filter(|u| u.height == 0).count();
        let at1 = list.iter().filter(|u| u.height == 1).count();
        assert_eq!(at0, 1);
        assert_eq!(at1, 2);

        let arr = utxo_list_json(&q, &list).unwrap();
        let rows = arr.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for u in &list {
            let row = rows
                .iter()
                .find(|r| {
                    r["vout"] == u.tx_pos
                        && r["status"]["block_height"].as_u64() == Some(u64::from(u.height))
                        && r["value"] == u.value
                })
                .expect("row");
            let (_fk, rec) = q.header_at_height(Height(u.height)).unwrap().unwrap();
            assert_eq!(row["status"]["confirmed"], true);
            assert_eq!(row["status"]["block_hash"], block_hash_hex(&rec.hash));
            assert_eq!(row["status"]["block_time"], rec.timestamp);
            assert_eq!(row["txid"], block_hash_hex(&u.tx_hash));
        }

        // Status comes from join height, not tx.head: a txid that is not in the
        // store still gets block_hash / block_time from header_at_height.
        let orphan = rbitcoin_query::ScriptHashUtxo {
            tx_hash: [0xee; 32],
            tx_pos: 7,
            height: 1,
            value: 42,
            create_tx_fk: Fk(1),
        };
        let miss = utxo_list_json(&q, &[orphan]).unwrap();
        let row = &miss.as_array().unwrap()[0];
        let (_fk, rec1) = q.header_at_height(Height(1)).unwrap().unwrap();
        assert_eq!(row["status"]["confirmed"], true);
        assert_eq!(row["status"]["block_height"], 1);
        assert_eq!(row["status"]["block_hash"], block_hash_hex(&rec1.hash));
        assert_eq!(row["status"]["block_time"], rec1.timestamp);
        assert_eq!(row["txid"], block_hash_hex(&[0xee; 32]));
        assert_eq!(row["vout"], 7);

        let mempool_row = rbitcoin_query::ScriptHashUtxo {
            tx_hash: [0x11; 32],
            tx_pos: 0,
            height: 0,
            value: 99,
            create_tx_fk: Fk::NULL,
        };
        let mem = utxo_list_json(&q, &[mempool_row]).unwrap();
        let mrow = &mem.as_array().unwrap()[0];
        assert_eq!(mrow["status"]["confirmed"], false);
        assert!(mrow["status"].get("block_height").is_none());
        assert!(mrow["status"].get("block_hash").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vout_fields_includes_type_and_value() {
        // P2WPKH: 0x00 0x14 + 20 bytes
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0x11; 20]);
        let v = vout_fields(&spk, 50_000, Network::Bitcoin);
        assert_eq!(v["value"], 50_000);
        assert_eq!(v["scriptpubkey_type"], "v0_p2wpkh");
        assert!(v["scriptpubkey"].as_str().unwrap().len() > 0);
        assert!(v.get("scriptpubkey_address").is_some());
    }

    #[test]
    fn build_tx_json_prevout_is_outs_only_and_txid_from_body() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{
            reset_tx_full_gets, tx_full_gets, HeaderRecord, InputRecord, OutputRecord, TxRecord,
        };
        use std::time::{SystemTime, UNIX_EPOCH};

        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-esplora-prevout-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();

        let mut merkle0 = [0u8; 32];
        merkle0[0] = 0xaa;
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle0,
            hash: merkle0,
        };
        let mut create_txid = [0u8; 32];
        create_txid[31] = 0xcb;
        let ta0 = TxApply {
            tx: TxRecord {
                txid: create_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

        let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let mut spend1_txid = [0u8; 32];
        spend1_txid[0] = 0x11;
        spend1_txid[31] = 0xcd;
        let ta1 = TxApply {
            tx: TxRecord {
                txid: spend1_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x51])],
        };
        let hfk1 = q.connect_block(Height(1), &h1, &[ta1]).unwrap();
        let spend1_fk = q.block_tx_fks(Height(1)).unwrap()[0];

        let hash2 = rbitcoin_store::block_header_hash(1, &h1.hash, &[0x22; 32], 3, 0x207fffff, 2);
        let h2 = HeaderRecord {
            prev_fk: hfk1,
            version: 1,
            timestamp: 3,
            bits: 0x207fffff,
            nonce: 2,
            merkle_root: [0x22; 32],
            hash: hash2,
        };
        let mut spend2_txid = [0u8; 32];
        spend2_txid[0] = 0x22;
        spend2_txid[31] = 0xce;
        let ta2 = TxApply {
            tx: TxRecord {
                txid: spend2_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: spend1_txid,
                create_fk: spend1_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(48_0000_0000, vec![0x00])],
        };
        q.connect_block(Height(2), &h2, &[ta2]).unwrap();
        let spend2_fk = q.block_tx_fks(Height(2)).unwrap()[0];

        reset_tx_full_gets();
        let v = build_tx_json(&q, spend2_fk, Network::Regtest).unwrap();
        let parent_id = spend1_fk.get().unwrap();
        assert!(
            !tx_full_gets().contains(&parent_id),
            "parent prevout must not zip inwit: {:?}",
            tx_full_gets()
        );
        assert_eq!(v["txid"], block_hash_hex(&spend2_txid));
        assert_eq!(v["vin"][0]["prevout"]["value"].as_i64(), Some(49_0000_0000));
        assert_eq!(q.store().txs.body_txid(spend2_fk).unwrap(), spend2_txid);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
