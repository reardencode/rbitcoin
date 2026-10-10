//! Build Esplora-shaped transaction JSON from store Class A + wire reconstruct.

use crate::script_fields::esplora_script_fields;
use bitcoin::hashes::Hash;
use bitcoin::{Network, Transaction};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{display_hash_hex, hex_encode};
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
            .filter_map(|u| u32::try_from(u.height).ok()),
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
            let height = u32::try_from(u.height).unwrap_or(0);
            let (block_hash, block_time) = match by_h.get(&height) {
                Some((h, t)) => (Some(h.clone()), Some(*t)),
                None => (None, None),
            };
            EsploraUtxo {
                txid: block_hash_hex(&u.tx_hash),
                vout: u.tx_pos,
                value: u.value,
                status: EsploraUtxoStatus {
                    confirmed: true,
                    block_height: Some(height),
                    block_hash,
                    block_time,
                },
            }
        })
        .collect();
    serde_json::to_value(rows)
        .map_err(|_| rbitcoin_store::StoreError::Corrupt("invariant: utxo json"))
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
    let wire = match query.reconstruct_tx(tx_fk) {
        Ok(w) => w,
        Err(rbitcoin_store::StoreError::Pruned { .. }) => {
            return build_tx_json_pruned(query, tx_fk, network);
        }
        Err(e) => return Err(e),
    };
    let status = tx_status_json(query, tx_fk)?;
    let (_meta, stored_inputs, _outs) = query.store().get_tx_full(tx_fk)?;
    let stored_txid = query
        .store()
        .txs
        .body_txid(tx_fk)
        .unwrap_or_else(|_| wire.compute_txid().to_byte_array());
    tx_json_from_wire(
        query,
        &wire,
        network,
        status,
        &stored_inputs,
        stored_txid,
        None,
        None,
    )
}

/// Parent txid and vout from `input.body`. No scriptSig, witness, or sequence.
fn pruned_vin(
    query: &Query,
    tx_fk: Fk,
    network: Network,
) -> Result<Option<Vec<Value>>, QueryError> {
    let Some(edges) = query.store().input_edges(tx_fk)? else {
        return Ok(None);
    };
    let mut vin = Vec::with_capacity(edges.len());
    for edge in edges {
        if edge.parent.is_null() {
            vin.push(json!({
                "txid": "0".repeat(64),
                "vout": 0xFFFFFFFFu32,
                "is_coinbase": true,
            }));
            continue;
        }
        let parent_txid = query.store().txs.body_txid(edge.parent)?;
        let mut obj = json!({
            "txid": block_hash_hex(&parent_txid),
            "vout": edge.vout,
            "is_coinbase": false,
        });
        if let Ok((_meta, outs)) = query.store().get_tx_meta_and_outputs(edge.parent) {
            if let Some(o) = outs.get(edge.vout as usize) {
                obj["prevout"] = vout_fields(&o.script, o.value, network);
            }
        }
        vin.push(obj);
    }
    Ok(Some(vin))
}

fn build_tx_json_pruned(query: &Query, tx_fk: Fk, network: Network) -> Result<Value, QueryError> {
    let tx = query.store().get_tx(tx_fk)?;
    let (_meta, outs) = query.store().get_tx_meta_and_outputs(tx_fk)?;
    let txid = query.store().txs.body_txid(tx_fk).unwrap_or(tx.txid);
    let status = tx_status_json(query, tx_fk)?;
    let vout: Vec<Value> = outs
        .iter()
        .map(|o| vout_fields(&o.script, o.value, network))
        .collect();
    let mut obj = json!({
        "txid": block_hash_hex(&txid),
        "version": tx.version,
        "locktime": tx.locktime,
        "vout": vout,
        "status": status,
        "pruned": true,
    });
    if let Some(vin) = pruned_vin(query, tx_fk, network)? {
        obj["vin"] = json!(vin);
    }
    if let Some(row) = query.txstat_row(tx_fk)? {
        if row.base != 0 || row.wit_extra != 0 {
            obj["fee"] = json!(row.fee_sat);
            obj["size"] = json!(row.size());
            obj["weight"] = json!(row.weight());
        }
    }
    Ok(obj)
}

/// Esplora tx JSON from a mempool wire body (not in Class A).
pub fn build_tx_json_from_tx(
    query: &Query,
    tx: &Transaction,
    network: Network,
    fee: Option<i64>,
    mempool: Option<&MempoolHub>,
) -> Result<Value, QueryError> {
    build_tx_json_from_tx_with_status(
        query,
        tx,
        network,
        json!({ "confirmed": false }),
        fee,
        mempool,
    )
}

/// Wire tx JSON with a caller-supplied `status` (archived reconstruct).
pub fn build_tx_json_from_tx_with_status(
    query: &Query,
    tx: &Transaction,
    network: Network,
    status: Value,
    fee: Option<i64>,
    mempool: Option<&MempoolHub>,
) -> Result<Value, QueryError> {
    tx_json_from_wire(
        query,
        tx,
        network,
        status,
        &[],
        tx.compute_txid().to_byte_array(),
        fee,
        mempool,
    )
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn tx_json_from_wire(
    query: &Query,
    wire: &Transaction,
    network: Network,
    status: Value,
    stored_inputs: &[InputRecord],
    txid_bytes: [u8; 32],
    fee_override: Option<i64>,
    mempool: Option<&MempoolHub>,
) -> Result<Value, QueryError> {
    let mut vin = Vec::with_capacity(wire.input.len());
    let mut fee_in: Option<i64> = Some(0);
    let mut prev_spks: Vec<Vec<u8>> = Vec::with_capacity(wire.input.len());
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

        let wit_raw: Vec<Vec<u8>> = tin.witness.iter().map(|w| w.to_vec()).collect();
        if !wit_raw.is_empty() {
            let wit: Vec<String> = wit_raw.iter().map(hex_encode).collect();
            vin_obj["witness"] = json!(wit);
        }

        let mut spk_for_inner: Option<Vec<u8>> = None;
        if is_coinbase {
            prev_spks.push(Vec::new());
        } else if let Some(prev) = prevout_json(query, stored_inputs, i, tin, network, mempool)? {
            if let Some(v) = prev.get("value").and_then(|x| x.as_i64()) {
                if let Some(acc) = fee_in.as_mut() {
                    *acc = acc.saturating_add(v);
                }
            } else {
                fee_in = None;
            }
            let spk = prev
                .get("scriptpubkey")
                .and_then(|x| x.as_str())
                .and_then(|h| rbitcoin_primitives::hex_decode(h).ok())
                .unwrap_or_default();
            spk_for_inner = Some(spk.clone());
            prev_spks.push(spk);
            vin_obj["prevout"] = prev;
        } else {
            fee_in = None;
            prev_spks.push(Vec::new());
        }
        if let Some(spk) = spk_for_inner.as_deref() {
            attach_inner_scripts(&mut vin_obj, spk, ss, &wit_raw);
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

    let mut obj = json!({
        "txid": block_hash_hex(&txid_bytes),
        "version": wire.version.0,
        "locktime": wire.lock_time.to_consensus_u32(),
        "size": wire.total_size(),
        "weight": wire.weight().to_wu(),
        "vin": vin,
        "vout": vout,
        "status": status,
    });
    let spk_refs: Vec<&[u8]> = prev_spks.iter().map(|s| s.as_slice()).collect();
    obj["sigops"] = json!(rbitcoin_consensus::tx_sigop_cost(
        wire, &spk_refs, true, true
    ));

    if let Some(fee) = fee_override {
        obj["fee"] = json!(fee);
    } else if let Some(ins) = fee_in {
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
    mempool: Option<&MempoolHub>,
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
    if let Some(prev) = mempool.and_then(|m| m.get_tx(&tin.previous_output.txid)) {
        if let Some(o) = prev.output.get(tin.previous_output.vout as usize) {
            return Ok(Some(vout_fields(
                o.script_pubkey.as_bytes(),
                o.value.to_sat() as i64,
                network,
            )));
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
    display_hash_hex(hash)
}

/// electrs `get_innerscripts`: redeem only for P2SH; witness script only for
/// P2WSH (or a P2SH redeem that is P2WSH); Taproot leaf is the second-to-last
/// witness item after a trailing annex (`0x50`). Unknown prevout emits neither.
fn attach_inner_scripts(vin_obj: &mut Value, spk: &[u8], script_sig: &[u8], witness: &[Vec<u8>]) {
    let prev = bitcoin::Script::from_bytes(spk);
    let redeem = if prev.is_p2sh() {
        last_push_data(script_sig).filter(|b| !b.is_empty() && b.len() <= 10_000)
    } else {
        None
    };
    if let Some(bytes) = redeem {
        if let Some(asm) = script_asm(bytes) {
            vin_obj["inner_redeemscript_asm"] = Value::String(asm);
        }
    }
    let nested = redeem
        .map(bitcoin::Script::from_bytes)
        .filter(|s| s.is_witness_program());
    let program = nested.unwrap_or(prev);
    let leaf = if program.is_p2wsh() {
        witness.last().map(Vec::as_slice)
    } else if program.is_p2tr() {
        tapscript_leaf(witness)
    } else {
        None
    };
    if let Some(bytes) = leaf {
        if let Some(asm) = script_asm(bytes) {
            vin_obj["inner_witnessscript_asm"] = Value::String(asm);
        }
    }
}

fn script_asm(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 10_000 {
        return None;
    }
    Some(bitcoin::Script::from_bytes(bytes).to_asm_string())
}

/// BIP341: a last witness item starting with `0x50` is the annex. The leaf
/// script is then the item before the control block.
fn tapscript_leaf(witness: &[Vec<u8>]) -> Option<&[u8]> {
    let mut n = witness.len();
    if n == 0 {
        return None;
    }
    if witness[n - 1].first() == Some(&0x50) {
        n -= 1;
    }
    if n < 2 {
        return None;
    }
    Some(witness[n - 2].as_slice())
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

    use rbitcoin_query::testutil::FixtureChain;
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
    fn vin_inner_scripts_follow_prevout_type() {
        use bitcoin::hashes::Hash;
        use bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
            Transaction, TxIn, TxOut, Witness,
        };
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::testutil::FixtureChain;
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let p2pkh = ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x88, 0xac,
        ]);
        let p2sh = ScriptBuf::from_bytes(vec![
            0xa9, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x87,
        ]);
        let p2wpkh = ScriptBuf::from_bytes({
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[0x33; 20]);
            v
        });
        let witness_script = ScriptBuf::from_bytes(vec![0x51]);
        let p2wsh = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let p2tr =
            ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                bitcoin::XOnlyPublicKey::from_slice(&[0x44; 32]).unwrap(),
            ));
        let spks = [p2pkh, p2sh, p2wpkh, p2wsh, p2tr];

        let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("inner-scripts");
        let mut txid = [0u8; 32];
        txid[31] = 0xcb;
        let parent = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: spks.len() as u32,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0x01],
                witness: vec![],
            }],
            outputs: spks
                .iter()
                .map(|s| OutputRecord::unspent(10_000, s.to_bytes()))
                .collect(),
        };
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: [1u8; 32],
            hash: [1u8; 32],
            size: 0,
            weight: 0,
        };
        q.connect_block(Height(0), &header, &[parent]).unwrap();

        let prev = bitcoin::Txid::from_byte_array(txid);
        let mut child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::from_bytes(vec![0x01, 0x51]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 1,
                    },
                    script_sig: ScriptBuf::from_bytes(vec![0x01, 0x51]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 2,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[&[0x30, 0x01][..], &[0x02, 0x55][..]]),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 3,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[&[0x00][..], witness_script.as_bytes()]),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 4,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[
                        &[0x01][..],
                        &[0x51][..],
                        &{
                            let mut c = vec![0xc0];
                            c.extend_from_slice(&[0x44; 32]);
                            c
                        }[..],
                    ]),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let v = build_tx_json_from_tx(&q, &child, Network::Regtest, None, None).unwrap();
        let vin = v["vin"].as_array().unwrap();
        assert!(vin[0].get("witness").is_none(), "p2pkh {}", vin[0]);
        assert!(vin[0].get("inner_redeemscript_asm").is_none(), "{}", vin[0]);
        assert!(
            vin[0].get("inner_witnessscript_asm").is_none(),
            "{}",
            vin[0]
        );
        assert!(
            vin[1]["inner_redeemscript_asm"]
                .as_str()
                .unwrap()
                .contains("OP_1")
                || vin[1]["inner_redeemscript_asm"]
                    .as_str()
                    .unwrap()
                    .contains('1'),
            "p2sh {}",
            vin[1]
        );
        assert!(
            vin[1].get("inner_witnessscript_asm").is_none(),
            "{}",
            vin[1]
        );
        assert!(vin[2].get("witness").is_some(), "{}", vin[2]);
        assert!(
            vin[2].get("inner_witnessscript_asm").is_none(),
            "p2wpkh {}",
            vin[2]
        );
        let wsh = vin[3]["inner_witnessscript_asm"].as_str().unwrap();
        assert!(wsh.contains("OP_1") || wsh.contains('1'), "p2wsh {wsh}");
        let tr = vin[4]["inner_witnessscript_asm"].as_str().unwrap();
        assert!(tr.contains("OP_1") || tr.contains('1'), "tapscript {tr}");
        assert!(
            !tr.contains("OP_UNKNOWN"),
            "control block must not be the leaf: {tr}"
        );

        child.input[4].witness = Witness::from_slice(&[&[0x22; 64][..]]);
        let keypath = build_tx_json_from_tx(&q, &child, Network::Regtest, None, None).unwrap();
        assert!(
            keypath["vin"][4].get("inner_witnessscript_asm").is_none(),
            "key path {}",
            keypath["vin"][4]
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();

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
                size: 0,
                weight: 0,
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
                        && r["status"]["block_height"].as_u64() == Some(u.height as u64)
                        && r["value"] == u.value
                })
                .expect("row");
            let (_fk, rec) = q
                .header_at_height(Height(u.height as u32))
                .unwrap()
                .unwrap();
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
    fn build_tx_json_prevout_is_outs_only_and_txid_from_body() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
        use std::time::{SystemTime, UNIX_EPOCH};

        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-esplora-prevout-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();

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
            size: 0,
            weight: 0,
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
            size: 0,
            weight: 0,
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
            size: 0,
            weight: 0,
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
            outputs: vec![OutputRecord::unspent(48_0000_0000, vec![0xac])],
        };
        q.connect_block(Height(2), &h2, &[ta2]).unwrap();
        let spend2_fk = q.block_tx_fks(Height(2)).unwrap()[0];

        let v = build_tx_json(&q, spend2_fk, Network::Regtest).unwrap();
        assert_eq!(v["txid"], block_hash_hex(&spend2_txid));
        assert_eq!(v["vin"][0]["prevout"]["value"].as_i64(), Some(49_0000_0000));
        assert_eq!(v["sigops"], 4, "OP_CHECKSIG output scaled: {v}");
        assert_eq!(q.store().txs.body_txid(spend2_fk).unwrap(), spend2_txid);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruned_tx_json_has_fee_from_txstat() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord, TxStatRow};

        let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("esplora-pruned-txstat");
        let mut merkle = [0u8; 32];
        merkle[0] = 0xaa;
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle,
            hash: merkle,
            size: 0,
            weight: 0,
        };
        let mut txid = [0u8; 32];
        txid[31] = 0xcb;
        let ta0 = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![0], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let fk = q.block_tx_fks(Height(0)).unwrap()[0];
        q.store()
            .write_txstat_row(
                fk,
                &TxStatRow {
                    fee_sat: 0,
                    base: 81,
                    wit_extra: 0,
                },
            )
            .unwrap();
        let mut spend_txid = [0u8; 32];
        spend_txid[31] = 0xee;
        let h1_hash = rbitcoin_store::block_header_hash(1, &merkle, &spend_txid, 2, 0x207fffff, 0);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: spend_txid,
            hash: h1_hash,
            size: 0,
            weight: 0,
        };
        let spend = TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: txid,
                create_fk: fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![0x51],
                witness: vec![vec![0xab]],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x51])],
        };
        q.connect_block(Height(1), &h1, &[spend]).unwrap();
        let spend_fk = q.block_tx_fks(Height(1)).unwrap()[0];
        q.set_pruneheight(Some(Height(1))).unwrap();
        let v = build_tx_json(&q, fk, Network::Regtest).unwrap();
        assert_eq!(v["pruned"], true);
        assert_eq!(v["vin"][0]["is_coinbase"], true);
        assert!(v["vin"][0].get("witness").is_none(), "{v}");
        assert!(v["vin"][0].get("scriptsig").is_none(), "{v}");
        let sv = build_tx_json(&q, spend_fk, Network::Regtest).unwrap();
        assert_eq!(sv["pruned"], true, "{sv}");
        assert_eq!(sv["vin"][0]["txid"], block_hash_hex(&txid));
        assert_eq!(sv["vin"][0]["vout"], 0);
        assert_eq!(sv["vin"][0]["is_coinbase"], false);
        assert!(sv["vin"][0].get("witness").is_none(), "{sv}");
        assert_eq!(sv["vin"][0]["prevout"]["value"], 5_000_000_000i64);
        q.set_pruneheight(Some(Height(0))).unwrap();
        assert_eq!(v["fee"], 0);
        assert_eq!(v["size"], 81);
        assert_eq!(v["weight"], 324);
        assert!(v.get("sigops").is_none(), "pruned JSON omits sigops: {v}");
        assert_eq!(v["vout"].as_array().unwrap().len(), 1);
        assert_eq!(v["txid"], block_hash_hex(&txid));

        q.store()
            .write_txstat_row(
                fk,
                &TxStatRow {
                    fee_sat: 0,
                    base: 0,
                    wit_extra: 0,
                },
            )
            .unwrap();
        let raw = build_tx_json(&q, fk, Network::Regtest).unwrap();
        assert_eq!(raw["pruned"], true);
        assert_eq!(raw["vin"][0]["is_coinbase"], true, "{raw}");
        assert!(raw.get("fee").is_none(), "unstamped omits fee: {raw}");
        assert!(raw.get("size").is_none(), "{raw}");
        assert!(raw.get("weight").is_none(), "{raw}");
        assert!(raw.get("sigops").is_none(), "{raw}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
