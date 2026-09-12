use super::*;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Txid};
use rbitcoin_primitives::Height;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Instant;

pub(crate) fn getblockcount(ctx: &RpcContext) -> Result<Value, Value> {
    let h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    Ok(json!(h))
}

pub(crate) fn getbestblockhash(ctx: &RpcContext) -> Result<Value, Value> {
    let Some(tip) = ctx.query.tip_height() else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

pub(crate) fn getblockhash(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height"])?;
    let height = params.req_u64(0, "height")? as u32;
    let (_, rec) = ctx
        .query
        .header_at_height(Height(height))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMETER, "Block height out of range"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

pub(crate) fn getblockchaininfo(ctx: &RpcContext) -> Result<Value, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    // Live hub latch, not the tip-follow copy: `feature_maxtipage` asserts
    // immediately after `sync_all`, before the 50ms RPC tick may store.
    let ibd = ctx
        .chain
        .as_ref()
        .map(|c| c.in_ibd())
        .unwrap_or_else(|| ctx.initial_block_download.load(Ordering::Relaxed));
    let headers = ctx
        .chain
        .as_ref()
        .map(|c| c.best_header_height())
        .unwrap_or(tip);
    let verificationprogress = if headers == 0 {
        1.0
    } else {
        (tip as f64 / headers as f64).clamp(0.0, 1.0)
    };
    let (time, mediantime) = if let Some(h) = ctx.query.tip_height() {
        if let Ok(Some((_, rec))) = ctx.query.header_at_height(h) {
            let mtp = rbitcoin_consensus::median_time_past(ctx.query.as_ref(), h)
                .unwrap_or(rec.timestamp);
            (rec.timestamp, mtp)
        } else {
            (0u32, 0u32)
        }
    } else {
        (0u32, 0u32)
    };
    Ok(json!({
        "chain": chain_name(ctx.network),
        "blocks": tip,
        "headers": headers,
        "bestblockhash": best,
        "difficulty": difficulty_at_tip(ctx).unwrap_or(0.0),
        "time": time,
        "mediantime": mediantime,
        "verificationprogress": verificationprogress,
        "initialblockdownload": ibd,
        "chainwork": chainwork_hex(ctx, ctx.query.tip_height()),
        "size_on_disk": ctx.query.store().datadir_bytes(),
        "pruned": false,
        "warnings": rpc_warnings(ctx),
    }))
}

pub(crate) fn rpc_warnings(ctx: &RpcContext) -> Vec<String> {
    let w = rbitcoin_net::warning_strings(ctx.query.as_ref(), ctx.network);
    if !w.is_empty()
        && ctx
            .alert_fired
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        if let Some(cmd) = ctx.alert_notify.as_deref() {
            let msg = w.join(", ");
            // Core ShellEscape: single-quote so `(versionbit N)` is not a subshell.
            let escaped = format!("'{}'", msg.replace('\'', "'\\''"));
            let shell = cmd.replace("%s", &escaped);
            match std::process::Command::new("sh")
                .arg("-c")
                .arg(&shell)
                .status()
            {
                Ok(st) if !st.success() => {
                    rbitcoin_log::warn!("alertnotify exited {st}: {shell}");
                }
                Err(e) => rbitcoin_log::warn!("alertnotify failed: {e}: {shell}"),
                _ => {}
            }
        }
    }
    w
}

pub(crate) fn difficulty_from_bits(bits: u32) -> f64 {
    // Compact target → difficulty relative to max target (same class as Core).
    let n_shift = ((bits >> 24) & 0xff) as i32;
    let mut ddiff = (0x0000_ffff_u64 as f64) / ((bits & 0x00ff_ffff) as f64);
    let mut shift = n_shift - 29;
    while shift < 0 {
        ddiff *= 256.0;
        shift += 1;
    }
    while shift > 0 {
        ddiff /= 256.0;
        shift -= 1;
    }
    ddiff
}

pub(crate) fn difficulty_at_tip(ctx: &RpcContext) -> Result<f64, Value> {
    let tip = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(difficulty_from_bits(rec.bits))
}

pub(crate) fn getdifficulty(ctx: &RpcContext) -> Result<Value, Value> {
    Ok(json!(difficulty_at_tip(ctx)?))
}

pub(crate) fn getblockheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(true);
    let hash = parse_hash32_display(hash_hex)?;
    let height = ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    if !verbose {
        let hdr = ctx
            .query
            .wire_header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        let mut raw = Vec::new();
        hdr.consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "header encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(json!({
        "hash": hash_hex_display(&rec.hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": rec.version,
        "versionHex": format!("{:08x}", rec.version),
        "merkleroot": hash_hex_display(&rec.merkle_root),
        "time": rec.timestamp,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(rec.timestamp),
        "nonce": rec.nonce,
        "bits": format!("{:08x}", rec.bits),
        "difficulty": difficulty_from_bits(rec.bits),
        "chainwork": chainwork_hex(ctx, Some(height)),
        "previousblockhash": prev,
        "nTx": ctx.query.block_tx_fks(height).map(|v| v.len()).unwrap_or(0),
    }))
}

/// 32-byte BE chainwork hex (regtest = 2 per block). Empty store → 64 zeros.
/// 32-byte BE chainwork hex (regtest = 2 per block). Empty store → 64 zeros.
pub(crate) fn chainwork_hex(ctx: &RpcContext, through: Option<Height>) -> String {
    let Some(tip) = through.or_else(|| ctx.query.tip_height()) else {
        return "00".repeat(32);
    };
    if let Some(hub) = ctx.chain.as_ref() {
        if let Ok(w) = hub.work_through_height(tip.0) {
            return hex_encode(w.to_be_bytes());
        }
    }
    let mut works = Vec::new();
    for h in 0..=tip.0 {
        if let Ok(hdr) = ctx.query.wire_header_at_height(Height(h)) {
            works.push(hdr.work());
        }
    }
    hex_encode(rbitcoin_net::sum_work(works.into_iter()).to_be_bytes())
}

pub(crate) fn getblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbosity", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbosity = match params.get(1, "verbosity") {
        Some(_) => opt_verbosity(params, 1, "verbosity")?,
        None => opt_verbosity(params, 1, "verbose")?,
    };
    let hash = parse_hash32_display(hash_hex)?;
    let height = match ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        Some(h) => h,
        None => {
            let typed = BlockHash::from_byte_array(hash);
            if let Some(block) = ctx.chain.as_ref().and_then(|c| c.held_body(&typed)) {
                if verbosity == 0 {
                    let mut raw = Vec::new();
                    block
                        .consensus_encode(&mut raw)
                        .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
                    return Ok(json!(hex_encode(raw)));
                }
                let txids: Vec<String> = block
                    .txdata
                    .iter()
                    .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
                    .collect();
                return Ok(json!({
                    "hash": hash_hex_display(&hash),
                    "confirmations": -1,
                    "version": block.header.version.to_consensus(),
                    "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
                    "time": block.header.time,
                    "nonce": block.header.nonce,
                    "bits": format!("{:08x}", block.header.bits.to_consensus()),
                    "nTx": block.txdata.len(),
                    "tx": txids,
                }));
            }
            let header_only = ctx.chain.as_ref().is_some_and(|c| c.knows_header(&typed))
                || ctx.query.get_header_by_hash(&hash).ok().flatten().is_some();
            if header_only {
                return Err(rpc_error(
                    ERR_MISC,
                    "Block not available (not fully downloaded)",
                ));
            }
            return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"));
        }
    };
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    if verbosity == 1 {
        let (_, rec) = ctx
            .query
            .header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_MISC, "header missing"))?;
        let ids = ctx
            .query
            .block_txids(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        let txids: Vec<String> = ids.iter().map(hash_hex_display).collect();
        return Ok(json!({
            "hash": hash_hex_display(&hash),
            "confirmations": confirmations(ctx, height),
            "height": height.0,
            "version": rec.version,
            "merkleroot": hash_hex_display(&rec.merkle_root),
            "time": rec.timestamp,
            "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
                .unwrap_or(rec.timestamp),
            "nonce": rec.nonce,
            "bits": format!("{:08x}", rec.bits),
            "previousblockhash": prev,
            "nTx": txids.len(),
            "tx": txids,
        }));
    }
    let block = ctx
        .query
        .reconstruct_block_at_height(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    if verbosity == 0 {
        let mut raw = Vec::new();
        block
            .consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
        .collect();
    let mut obj = json!({
        "hash": hash_hex_display(&hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": block.header.version.to_consensus(),
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(block.header.time),
        "nonce": block.header.nonce,
        "bits": format!("{:08x}", block.header.bits.to_consensus()),
        "previousblockhash": prev,
        "nTx": block.txdata.len(),
        "tx": txids,
    });
    if verbosity >= 2 {
        let net = rpc_btc_network(ctx.network);
        let txs: Vec<Value> = block
            .txdata
            .iter()
            .map(|tx| tx_to_json(tx, None, net))
            .collect();
        obj["tx"] = json!(txs);
    }
    Ok(obj)
}

pub(crate) fn confirmations(ctx: &RpcContext, height: Height) -> u32 {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    tip.saturating_sub(height.0).saturating_add(1)
}

/// Enough of Core `scantxoutset` for MiniWallet: `raw(script)` over Class A.
/// Not a coins-DB product (no HD range / combo / addr expansion).
pub(crate) fn scantxoutset(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["action", "scanobjects"])?;
    let action = params.req_str(0, "action")?;
    match action {
        "status" => return Ok(Value::Null),
        "abort" => return Ok(json!(false)),
        "start" => {}
        other => {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!("Invalid action '{other}'"),
            ));
        }
    }
    let objs = params.get_array(1, "scanobjects").ok_or_else(|| {
        rpc_error(
            ERR_MISC,
            "scanobjects argument is required for the start action",
        )
    })?;
    let mut scripts: Vec<Vec<u8>> = Vec::new();
    for o in objs {
        let desc = match o {
            Value::String(s) => s.as_str(),
            Value::Object(m) => m
                .get("desc")
                .and_then(Value::as_str)
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "scanobject desc required"))?,
            _ => {
                return Err(rpc_error(
                    ERR_INVALID_PARAMS,
                    "scanobjects entries must be descriptor strings",
                ));
            }
        };
        let script = if let Some(s) = parse_raw_descriptor(desc) {
            s
        } else if let Some(s) = parse_addr_descriptor(ctx, desc) {
            s
        } else if let Some(s) = parse_wrapped_multi(desc) {
            s
        } else {
            return Err(rpc_error(
                ERR_INVALID_PARAMS,
                format!("unsupported descriptor (got {desc})"),
            ));
        };
        scripts.push(script.to_bytes());
    }

    let tip = ctx.query.tip_height().unwrap_or(Height(0));
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let found = ctx
        .query
        .scan_unspent_scripts(&scripts)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let mut unspents = Vec::with_capacity(found.len());
    let mut total_sat = 0u64;
    for u in found {
        total_sat = total_sat.saturating_add(u.value);
        unspents.push(json!({
            "txid": hash_hex_display(&u.txid),
            "vout": u.vout,
            "scriptPubKey": hex_encode(&u.script),
            "desc": format!("raw({})", hex_encode(&u.script)),
            "amount": sat_btc_json(u.value as i64),
            "coinbase": u.coinbase,
            "height": u.height,
        }));
    }

    Ok(json!({
        "success": true,
        "txouts": unspents.len(),
        "height": tip.0,
        "bestblock": best,
        "unspents": unspents,
        "total_amount": Amount::from_sat(total_sat).to_btc(),
    }))
}

pub(crate) fn gettxout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "n", "include_mempool"])?;
    let hex = params.req_str(0, "txid")?;
    let n = params.req_u64(1, "n")? as u32;
    let include_mempool = params.opt_bool(2, "include_mempool")?.unwrap_or(true);
    let want = parse_hash32_display(hex)?;

    if include_mempool {
        if let Some(mp) = ctx.mempool.as_ref() {
            let tid = Txid::from_byte_array(want);
            if let Some(tx) = mp.get_tx(&tid) {
                if let Some(out) = tx.output.get(n as usize) {
                    return Ok(json!({
                        "bestblock": getbestblockhash(ctx)?,
                        "confirmations": 0,
                        "value": out.value.to_btc(),
                        "scriptPubKey": {
                            "hex": hex_encode(out.script_pubkey.as_bytes()),
                            "asm": out.script_pubkey.to_asm_string(),
                        },
                        "coinbase": false,
                    }));
                }
            }
        }
    }

    let (fk, rec) = match ctx
        .query
        .tx_fk_by_txid_tip(&want)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        Some(fk) => {
            let rec = ctx
                .query
                .get_tx(fk)
                .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
            (fk, rec)
        }
        None => return Ok(Value::Null),
    };
    if ctx
        .query
        .is_outpoint_spent(&want, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        return Ok(Value::Null);
    }
    if include_mempool {
        if let Some(mp) = ctx.mempool.as_ref() {
            let op = bitcoin::OutPoint {
                txid: Txid::from_byte_array(want),
                vout: n,
            };
            if mp.spends_outpoint(&op) {
                return Ok(Value::Null);
            }
        }
    }
    let out = ctx
        .query
        .tx_output_at_fk(fk, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let height = ctx
        .query
        .store()
        .tx_height_get(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .unwrap_or(0);
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let confs = tip.saturating_sub(height).saturating_add(1);
    let coinbase = rec.input_count == 1
        && ctx
            .query
            .tx_input_at_fk(fk, &rec, 0)
            .map(|inp| inp.is_coinbase())
            .unwrap_or(false);
    Ok(json!({
        "bestblock": getbestblockhash(ctx)?,
        "confirmations": confs,
        "value": Amount::from_sat(out.value as u64).to_btc(),
        "scriptPubKey": {
            "hex": hex_encode(&out.script),
            "asm": ScriptBuf::from_bytes(out.script.clone()).to_asm_string(),
        },
        "coinbase": coinbase,
    }))
}

pub(crate) fn getindexinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["index_name"])?;
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let txindex = json!({
        "synced": true,
        "best_block_height": tip,
    });
    match params.get(0, "index_name") {
        None | Some(Value::Null) => Ok(json!({ "txindex": txindex })),
        Some(Value::String(s)) if s == "txindex" => Ok(json!({ "txindex": txindex })),
        Some(Value::String(_)) => Ok(json!({})),
        Some(_) => Err(rpc_error(ERR_INVALID_PARAMS, "index_name must be a string")),
    }
}

pub(crate) fn getchaintips(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    if let Some(chain) = ctx.chain.as_ref() {
        let tips: Vec<Value> = chain
            .chaintips()
            .into_iter()
            .map(|t| {
                json!({
                    "height": t.height,
                    "hash": hash_hex_display(&t.hash.to_byte_array()),
                    "branchlen": t.branchlen,
                    "status": t.status,
                })
            })
            .collect();
        return Ok(json!(tips));
    }
    let Some(h) = ctx.query.tip_height() else {
        return Ok(json!([]));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!([{
        "height": h.0,
        "hash": hash_hex_display(&rec.hash),
        "branchlen": 0,
        "status": "active",
    }]))
}

pub(crate) fn wait_timeout_ms(params: &RpcParams, idx: usize, name: &str) -> Result<u64, Value> {
    Ok(params.opt_u64(idx, name)?.unwrap_or(30_000))
}

pub(crate) fn tip_hash_height(ctx: &RpcContext) -> Result<(String, u32), Value> {
    let h = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok((hash_hex_display(&rec.hash), h.0))
}

pub(crate) fn buried_row(height: u32, at: u32) -> Value {
    // Core `DeploymentActiveAfter`: active for the *next* block after `at`.
    json!({
        "type": "buried",
        "height": height,
        "active": at.saturating_add(1) >= height,
    })
}

/// Buried deployments from the node's `ChainParams` (overlay heights included).
/// No BIP9 / testdummy / versionbits invention.
/// Buried deployments from the node's `ChainParams` (overlay heights included).
/// No BIP9 / testdummy / versionbits invention.
pub(crate) fn buried_deployments(params: &rbitcoin_consensus::ChainParams, at: u32) -> Value {
    json!({
        "bip34": buried_row(params.btc.bip34_height, at),
        "bip66": buried_row(params.btc.bip66_height, at),
        "bip65": buried_row(params.btc.bip65_height, at),
        "csv": buried_row(params.csv_height(), at),
        "segwit": buried_row(params.segwit_height(), at),
        "taproot": buried_row(params.taproot_height(), at),
    })
}

pub(crate) fn getdeploymentinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let cp = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| rbitcoin_consensus::ChainParams::for_network(ctx.network));
    let (hash, height) = if let Some(hex) = params.get(0, "blockhash").and_then(Value::as_str) {
        let want = parse_hash32_display(hex)?;
        let h = ctx
            .query
            .height_of_hash(&want)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
        (hash_hex_display(&want), h.0)
    } else {
        tip_hash_height(ctx)?
    };
    Ok(json!({
        "hash": hash,
        "height": height,
        "deployments": buried_deployments(&cp, height),
    }))
}

pub(crate) fn waitforblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "timeout"])?;
    let want = params.req_str(0, "blockhash")?.to_string();
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash == want)
}

pub(crate) fn waitforblockheight(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height", "timeout"])?;
    let want = params.req_u64(0, "height")? as u32;
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |_hash, height| height >= want)
}

pub(crate) fn waitfornewblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timeout"])?;
    let timeout_ms = wait_timeout_ms(params, 0, "timeout")?;
    let (start_hash, _) = tip_hash_height(ctx)?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash != start_hash)
}

/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
pub(crate) fn wait_for_tip(
    ctx: &RpcContext,
    timeout_ms: u64,
    pred: impl Fn(&str, u32) -> bool,
) -> Result<Value, Value> {
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            let (hash, height) = tip_hash_height(ctx)?;
            return Ok(json!({ "hash": hash, "height": height }));
        }
        let (hash, height) = tip_hash_height(ctx)?;
        if pred(&hash, height) {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub(crate) fn require_chain(ctx: &RpcContext) -> Result<&rbitcoin_net::ChainHub, Value> {
    ctx.chain
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "chain hub not attached"))
}

pub(crate) fn parse_blockhash_param(params: &RpcParams) -> Result<bitcoin::BlockHash, Value> {
    let hex = params.req_str(0, "blockhash")?;
    let b = parse_hash32_display(hex)?;
    Ok(bitcoin::BlockHash::from_byte_array(b))
}

pub(crate) fn invalidateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.invalidate_block(hash).map_err(|e| {
        let s = e.to_string();
        if s.contains("Block not found") {
            rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found")
        } else {
            rpc_error(ERR_MISC, s)
        }
    })?;
    Ok(Value::Null)
}

pub(crate) fn submitheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata"])?;
    let hub = require_chain(ctx)?;
    let hex = params.req_str(0, "hexdata")?;
    let header = decode_header_hex(hex)?;
    hub.process_submitted_header(&header)
        .map_err(|e| rpc_error(ERR_VERIFY_ERROR, e))?;
    Ok(Value::Null)
}

pub(crate) fn decode_header_hex(hex: &str) -> Result<bitcoin::block::Header, Value> {
    let raw = hex_decode(hex)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))?;
    if raw.len() >= 80 {
        if let Ok(h) = deserialize::<bitcoin::block::Header>(&raw[..80]) {
            return Ok(h);
        }
    }
    deserialize::<Block>(&raw)
        .map(|b| b.header)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))
}

pub(crate) fn reconsiderblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.reconsider_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}

pub(crate) fn preciousblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.precious_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}
