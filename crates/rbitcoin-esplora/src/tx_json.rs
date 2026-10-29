//! Build Esplora-shaped transaction JSON from store Class A + wire reconstruct.

use crate::script_fields::esplora_script_fields;
use bitcoin::hashes::Hash;
use bitcoin::{Network, Transaction};
use rbitcoin_net::MempoolHub;

use rbitcoin_primitives::{Fk, Height};

use rbitcoin_query::{ChainView, Query, QueryError, ScriptHashHistoryItem, ScriptHashUtxo};
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

/// Header at `height` on `view`'s chain.
///
/// A pin that is still `confirmed[view.height]` shares that prefix, so the
/// confirmed index is the ancestor. A pin whose height was replaced must not
/// read that index: the sibling now sits there. Walk `prev_fk` from the pin.
fn header_on_view(
    query: &Query,
    view: &ChainView,
    height: u32,
) -> Result<Option<rbitcoin_store::HeaderRecord>, QueryError> {
    if height > view.height.0 {
        return Ok(None);
    }
    if view.still_live(query)? {
        return Ok(query.header_at_height(Height(height))?.map(|(_, rec)| rec));
    }
    let mut rec = query.store().get_header(view.header_fk)?;
    let mut at = view.height.0;
    while at > height {
        if rec.prev_fk.is_null() {
            return Ok(None);
        }
        rec = query.store().get_header(rec.prev_fk)?;
        at -= 1;
    }
    Ok(Some(rec))
}

/// Confirmation status as of `view`.
pub fn tx_status_json_in(query: &Query, tx_fk: Fk, view: &ChainView) -> Result<Value, QueryError> {
    let confirmed = query
        .store()
        .is_confirmed_strong_at(tx_fk, Some(view.height.0))?;
    if !confirmed {
        return Ok(json!({ "confirmed": false }));
    }
    let Some(height) = query.store().tx_height_get(tx_fk)? else {
        return Ok(json!({ "confirmed": false }));
    };
    let mut out = json!({
        "confirmed": true,
        "block_height": height,
    });
    if let Some(rec) = header_on_view(query, view, height)? {
        out["block_hash"] = Value::String(block_hash_hex(&rec.hash));
        out["block_time"] = json!(rec.timestamp);
    }
    Ok(out)
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct EsploraUtxoStatus {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<u32>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: i64,
    pub status: EsploraUtxoStatus,
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
        out.push(build_tx_json(query, item.tx_fk, network, None)?);
    }
    Ok(out)
}

fn status_for(query: &Query, tx_fk: Fk, view: Option<&ChainView>) -> Result<Value, QueryError> {
    match view {
        Some(view) => tx_status_json_in(query, tx_fk, view),
        None => tx_status_json(query, tx_fk),
    }
}

/// Full `GET /tx/:txid` body (Esplora API.md transaction format).
///
/// `view` is the status pin. `None` uses the live tip. The wire body is the
/// same either way, including a pruned partial.
pub fn build_tx_json(
    query: &Query,
    tx_fk: Fk,
    network: Network,
    view: Option<&ChainView>,
) -> Result<Value, QueryError> {
    let wire = match query.reconstruct_tx(tx_fk) {
        Ok(w) => w,
        Err(rbitcoin_store::StoreError::Pruned { .. }) => {
            return build_tx_json_pruned(query, tx_fk, network, view);
        }
        Err(e) => return Err(e),
    };
    let status = status_for(query, tx_fk, view)?;
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
#[doc(hidden)]
pub fn pruned_vin(
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

#[doc(hidden)]
pub fn build_tx_json_pruned(
    query: &Query,
    tx_fk: Fk,
    network: Network,
    view: Option<&ChainView>,
) -> Result<Value, QueryError> {
    let tx = query.store().get_tx(tx_fk)?;
    let (_meta, outs) = query.store().get_tx_meta_and_outputs(tx_fk)?;
    let txid = query.store().txs.body_txid(tx_fk).unwrap_or(tx.txid);
    let status = status_for(query, tx_fk, view)?;
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
#[doc(hidden)]
pub fn tx_json_from_wire(
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
            let wit: Vec<String> = wit_raw
                .iter()
                .map(rbitcoin_primitives::hex_encode)
                .collect();
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
                .and_then(|h| {
                    rbitcoin_primitives::hex_decode(
                        h.strip_prefix("0x")
                            .or_else(|| h.strip_prefix("0X"))
                            .unwrap_or(h),
                    )
                    .ok()
                })
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

#[doc(hidden)]
pub fn prevout_json(
    query: &Query,
    stored_inputs: &[InputRecord],
    idx: usize,
    tin: &bitcoin::TxIn,
    network: Network,
    mempool: Option<&MempoolHub>,
) -> Result<Option<Value>, QueryError> {
    if let Some(inp) = stored_inputs.get(idx) {
        if !inp.create_fk().is_null() {
            if let Ok(out) = query.tx_output_at_fk(inp.create_fk(), inp.prev_index()) {
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
                o.value.to_sat(),
                network,
            )));
        }
    }
    Ok(None)
}

#[doc(hidden)]
pub fn vout_fields(script: &[u8], value: u64, network: Network) -> Value {
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

#[doc(hidden)]
pub fn block_hash_hex(hash: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(*(hash))
}

/// electrs `get_innerscripts`: redeem only for P2SH; witness script only for
/// P2WSH (or a P2SH redeem that is P2WSH); Taproot leaf is the second-to-last
/// witness item after a trailing annex (`0x50`). Unknown prevout emits neither.
#[doc(hidden)]
pub fn attach_inner_scripts(
    vin_obj: &mut Value,
    spk: &[u8],
    script_sig: &[u8],
    witness: &[Vec<u8>],
) {
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

#[doc(hidden)]
pub fn script_asm(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 10_000 {
        return None;
    }
    Some(bitcoin::Script::from_bytes(bytes).to_asm_string())
}

/// BIP341: a last witness item starting with `0x50` is the annex. The leaf
/// script is then the item before the control block.
#[doc(hidden)]
pub fn tapscript_leaf(witness: &[Vec<u8>]) -> Option<&[u8]> {
    let mut n = witness.len();
    if n == 0 {
        return None;
    }
    if witness[n - 1].first() == Some(&rbitcoin_primitives::OP_RESERVED) {
        n -= 1;
    }
    if n < 2 {
        return None;
    }
    Some(witness[n - 2].as_slice())
}

#[doc(hidden)]
pub fn last_push_data(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    let mut last: Option<&[u8]> = None;
    while i < script.len() {
        let op = script[i];
        i += 1;
        if op <= rbitcoin_primitives::OP_PUSHBYTES_75 {
            let n = op as usize;
            if i + n > script.len() {
                break;
            }
            last = Some(&script[i..i + n]);
            i += n;
        } else if op == rbitcoin_primitives::OP_PUSHDATA1 {
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
        } else if op == rbitcoin_primitives::OP_PUSHDATA2 {
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
