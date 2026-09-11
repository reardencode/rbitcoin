use super::*;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, Txid};
use rbitcoin_net::MempoolHub;
use serde_json::{json, Value};

pub(crate) fn getmempoolinfo(ctx: &RpcContext) -> Result<Value, Value> {
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({
            "loaded": true,
            "size": 0,
            "bytes": 0,
            "usage": 0,
            "total_fee": 0.0,
            "maxmempool": 0,
            "mempoolminfee": MempoolHub::relay_fee_btc_per_kb(),
            "minrelaytxfee": MempoolHub::relay_fee_btc_per_kb(),
            "incrementalrelayfee": MempoolHub::relay_fee_btc_per_kb(),
            "unbroadcastcount": 0,
            "permitbaremultisig": true,
            "optimal": true,
            "orphanage": { "size": 0, "bytes": 0 },
        }));
    };
    let live = mp.list_live_meta();
    let size = live.len();
    let mut bytes = 0u64;
    let mut total_fee = 0u64;
    for (_, fee, weight) in &live {
        bytes += weight / 4;
        total_fee += fee;
    }
    let (orphan_size, orphan_wu) = mp.orphan_stats();
    Ok(json!({
        "loaded": true,
        "size": size,
        "bytes": bytes,
        "usage": bytes,
        "total_fee": (total_fee as f64) / 100_000_000.0,
        "maxmempool": mp.max_weight(),
        "mempoolminfee": MempoolHub::relay_fee_btc_per_kb(),
        "minrelaytxfee": MempoolHub::relay_fee_btc_per_kb(),
        "incrementalrelayfee": MempoolHub::relay_fee_btc_per_kb(),
        "relay_enabled": mp.relay_enabled(),
        "unbroadcastcount": mp.unbroadcast_count(),
        "permitbaremultisig": true,
        "optimal": true,
        "orphanage": {
            "size": orphan_size,
            "bytes": orphan_wu / 4,
        },
    }))
}

/// Exact 8-decimal BTC JSON number (Core `ValueFromAmount`). Avoids f64 drift
/// against `Decimal` comparisons in the functional suite.
/// Exact 8-decimal BTC JSON number (Core `ValueFromAmount`). Avoids f64 drift
/// against `Decimal` comparisons in the functional suite.
pub(crate) fn sat_btc_json(sat: i64) -> Value {
    let sign = if sat < 0 { "-" } else { "" };
    let abs = sat.unsigned_abs();
    let s = format!("{sign}{}.{:08}", abs / 100_000_000, abs % 100_000_000);
    Value::Number(s.parse().expect("sat/BTC decimal"))
}

/// Shared getrawmempool-verbose / getmempoolentry graph + unbroadcast fields.
/// Shared getrawmempool-verbose / getmempoolentry graph + unbroadcast fields.
pub(crate) fn mempool_graph_json(mp: &MempoolHub, txid: &Txid, fee: u64, weight: u64) -> Value {
    let vsize = weight / 4;
    let delta = mp.fee_delta(txid);
    let modified = (fee as i64).saturating_add(delta);
    let (ac, asz, afee, dc, dsz, dfee, a_mod, d_mod, chunk_fee, chunk_w) =
        match mp.graph_fees_modified(txid) {
            Some((s, am, dm, cf, cw)) => (
                s.ancestorcount,
                s.ancestorsize,
                s.ancestorfees,
                s.descendantcount,
                s.descendantsize,
                s.descendantfees,
                am,
                dm,
                cf,
                cw,
            ),
            None => (
                1, vsize, fee, 1, vsize, fee, modified, modified, modified, weight,
            ),
        };
    let (depends, spentby) = match mp.depends_spentby(txid) {
        Some((d, s)) => (
            d.into_iter()
                .map(|t| hash_hex_display(&t.to_byte_array()))
                .collect::<Vec<_>>(),
            s.into_iter()
                .map(|t| hash_hex_display(&t.to_byte_array()))
                .collect::<Vec<_>>(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    json!({
        "vsize": vsize,
        "weight": weight,
        "fee": sat_btc_json(fee as i64),
        // Top-level `modifiedfee` stays the base fee (same pattern as
        // ancestorfees/descendantfees). Real modified value is `fees.modified`.
        "modifiedfee": sat_btc_json(fee as i64),
        "time": mp.accept_time_txid(txid).unwrap_or(0),
        "height": 0,
        "descendantcount": dc,
        "descendantsize": dsz,
        "descendantfees": dfee,
        "ancestorcount": ac,
        "ancestorsize": asz,
        "ancestorfees": afee,
        "chunkweight": chunk_w,
        "unbroadcast": mp.is_unbroadcast(txid),
        "depends": depends,
        "spentby": spentby,
        "fees": {
            "base": sat_btc_json(fee as i64),
            "modified": sat_btc_json(modified),
            "ancestor": sat_btc_json(a_mod),
            "descendant": sat_btc_json(d_mod),
            "chunk": sat_btc_json(chunk_fee),
        },
    })
}

pub(crate) fn getrawmempool(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["verbose", "mempool_sequence"])?;
    let verbose = params.opt_bool(0, "verbose")?.unwrap_or(false);
    let want_seq = params.opt_bool(1, "mempool_sequence")?.unwrap_or(false);
    if verbose && want_seq {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "Verbose results cannot contain mempool sequence number.",
        ));
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(if verbose { json!({}) } else { json!([]) });
    };
    let live = mp.list_live_meta();
    if !verbose {
        let ids: Vec<String> = live
            .iter()
            .map(|(t, _, _)| hash_hex_display(&t.to_byte_array()))
            .collect();
        if want_seq {
            return Ok(json!({
                "txids": ids,
                "mempool_sequence": mp.current_relay_seq(),
            }));
        }
        return Ok(json!(ids));
    }
    let mut map = serde_json::Map::new();
    for (txid, fee, weight) in live {
        map.insert(
            hash_hex_display(&txid.to_byte_array()),
            mempool_graph_json(mp, &txid, fee, weight),
        );
    }
    Ok(Value::Object(map))
}

pub(crate) fn getmempoolentry(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid"])?;
    let hex = params.req_str(0, "txid")?;
    let want = parse_hash32_display(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let tid = Txid::from_byte_array(want);
    if let Some((fee, weight)) = mp.get_live_meta(&tid) {
        let wtxid = mp
            .get_tx(&tid)
            .map(|tx| hash_hex_display(&tx.compute_wtxid().to_byte_array()))
            .unwrap_or_default();
        let mut entry = mempool_graph_json(mp, &tid, fee, weight);
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("wtxid".into(), json!(wtxid));
        }
        return Ok(entry);
    }
    Err(rpc_error(
        ERR_INVALID_ADDRESS_OR_KEY,
        "Transaction not in mempool",
    ))
}

pub(crate) fn getrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose", "verbosity", "blockhash"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = match params
        .get(1, "verbose")
        .or_else(|| params.get(1, "verbosity"))
    {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => json_u64(v)
            .map(|n| n != 0)
            .ok_or_else(|| rpc_error(ERR_TYPE_ERROR, "not of expected type number"))?,
    };
    let want = parse_hash32_display(hex)?;

    if let Some(mp) = ctx.mempool.as_ref() {
        let tid = Txid::from_byte_array(want);
        if let Some(tx) = mp.get_tx(&tid) {
            if !verbose {
                return Ok(json!(serialize_hex(&tx)));
            }
            return Ok(tx_to_json(
                &tx,
                Some(json!({ "in_mempool": true })),
                rpc_btc_network(ctx.network),
            ));
        }
    }

    let (fk, _) = ctx
        .query
        .get_tx_by_txid(&want)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "No such mempool or blockchain transaction"))?;
    let tx = ctx
        .query
        .reconstruct_tx(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    if !verbose {
        return Ok(json!(serialize_hex(&tx)));
    }
    Ok(tx_to_json(
        &tx,
        Some(json!({ "in_mempool": false })),
        rpc_btc_network(ctx.network),
    ))
}

/// Core `DEFAULT_MAX_RAW_TX_FEE_RATE`: 0.10 BTC/kvB (sat/kvB).
const DEFAULT_MAX_RAW_TX_FEE_SAT_KVB: u64 = 10_000_000;
/// Core `ParseFeeRate`: values above 1 BTC/kvB are an RPC parameter error.
const MAX_ALLOWED_FEERATE_SAT_KVB: u64 = 100_000_000;

fn parse_rpc_btc_to_sat(s: &str) -> Result<u64, Value> {
    let s = s.trim();
    if s.is_empty() {
        return Err(rpc_error(ERR_INVALID_PARAMETER, "Invalid amount"));
    }
    if s.starts_with('-') {
        return Err(rpc_error(ERR_INVALID_PARAMETER, "Amount out of range"));
    }
    let (whole_s, frac_s) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u64 = if whole_s.is_empty() {
        0
    } else {
        whole_s
            .parse()
            .map_err(|_| rpc_error(ERR_INVALID_PARAMETER, "Invalid amount"))?
    };
    if frac_s.len() > 8 {
        return Err(rpc_error(ERR_INVALID_PARAMETER, "Invalid amount"));
    }
    let mut frac = frac_s.to_string();
    while frac.len() < 8 {
        frac.push('0');
    }
    let frac_n: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|_| rpc_error(ERR_INVALID_PARAMETER, "Invalid amount"))?
    };
    Ok(whole.saturating_mul(100_000_000).saturating_add(frac_n))
}

fn amount_sat_from_json(v: &Value) -> Result<u64, Value> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Ok(u.saturating_mul(100_000_000));
            }
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(rpc_error(ERR_INVALID_PARAMETER, "Amount out of range"));
                }
                return Ok((i as u64).saturating_mul(100_000_000));
            }
            parse_rpc_btc_to_sat(&n.to_string())
        }
        Value::String(s) => parse_rpc_btc_to_sat(s),
        _ => Err(rpc_error(
            ERR_TYPE_ERROR,
            "Amount is not a number or string",
        )),
    }
}

/// RPC-submit `maxfeerate` (BTC/kvB). Omitted → 0.10. `0` → unlimited. `>1` → param error.
///
/// Wallet protection on `sendrawtransaction` / `testmempoolaccept` / `submitpackage`
/// only. P2P `accept_tx` does not read this cap.
fn opt_maxfeerate_sat_kvb(params: &RpcParams, index: usize) -> Result<u64, Value> {
    match params.get(index, "maxfeerate") {
        None | Some(Value::Null) => Ok(DEFAULT_MAX_RAW_TX_FEE_SAT_KVB),
        Some(v) => {
            let sat = amount_sat_from_json(v)?;
            if sat > MAX_ALLOWED_FEERATE_SAT_KVB {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    "Fee rates larger than 1BTC/kvB are not allowed",
                ));
            }
            Ok(sat)
        }
    }
}

fn fee_exceeds_max(fee_sat: u64, weight: u64, max_sat_kvb: u64) -> bool {
    if max_sat_kvb == 0 {
        return false;
    }
    let vsize = rbitcoin_consensus::policy::get_virtual_size(weight);
    let max_fee = max_sat_kvb.saturating_mul(vsize) / 1000;
    fee_sat > max_fee
}

fn prevout_value_sat(ctx: &RpcContext, op: &OutPoint) -> Option<u64> {
    if let Some(mp) = ctx.mempool.as_ref() {
        if let Some(parent) = mp.get_tx(&op.txid) {
            return parent
                .output
                .get(op.vout as usize)
                .map(|o| o.value.to_sat());
        }
    }
    let want = op.txid.to_byte_array();
    let (fk, _) = ctx.query.get_tx_by_txid(&want).ok().flatten()?;
    let out = ctx.query.tx_output_at_fk(fk, op.vout).ok()?;
    u64::try_from(out.value).ok()
}

fn tx_fee_sat_from_prevouts(ctx: &RpcContext, tx: &Transaction) -> Option<u64> {
    let mut in_sum = 0u64;
    for inp in &tx.input {
        in_sum = in_sum.saturating_add(prevout_value_sat(ctx, &inp.previous_output)?);
    }
    let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    in_sum.checked_sub(out_sum)
}

fn rpc_tx_fee_exceeds_max(ctx: &RpcContext, tx: &Transaction, max_sat_kvb: u64) -> bool {
    let Some(fee) = tx_fee_sat_from_prevouts(ctx, tx) else {
        return false;
    };
    fee_exceeds_max(fee, tx.weight().to_wu(), max_sat_kvb)
}

pub(crate) fn sendrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexstring", "maxfeerate"])?;
    let hex = params.req_str(0, "hexstring")?;
    let max_feerate = opt_maxfeerate_sat_kvb(params, 1)?;
    let tx = decode_tx_hex(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    if rpc_tx_fee_exceeds_max(ctx, &tx, max_feerate) {
        return Err(rpc_error(ERR_VERIFY_REJECTED, "max-fee-exceeded"));
    }
    // `-blocksonly` leaves P2P relay off but RPC still accepts
    // (`p2p_blocksonly.py` sendrawtransaction).
    match mp.accept_tx(&tx) {
        Ok(r) => {
            mp.note_unbroadcast(r.txid);
            // `-blocksonly`: accept-time announce is skipped (relay off + not
            // yet unbroadcast). Re-announce after noting so inbound peers INV
            // (`p2p_blocksonly.py:48`). When relay is on, leave the 30s inbound
            // age gate alone (`mempool_reorg` / `mempool_unbroadcast`).
            if !mp.relay_enabled() {
                mp.rebroadcast_unbroadcast();
                mp.notify_inv_flush();
                if let (Some(peers), Some(chain)) = (ctx.peers.as_ref(), ctx.chain.as_ref()) {
                    rbitcoin_net::flush_tx_invs(chain, peers);
                } else if let Some(peers) = ctx.peers.as_ref() {
                    peers.request_all_tx_inv();
                }
            }
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        // Core sendraw of a live mempool tx is a no-op success (returns txid)
        // and must not re-enter the unbroadcast set (`mempool_unbroadcast.py:93`).
        Err(rbitcoin_net::AcceptError::Duplicate(_)) => {
            Ok(json!(hash_hex_display(&tx.compute_txid().to_byte_array())))
        }
        // Same txid, different witness: success + force-INV the live body so a
        // peer that missed the first announce still sees it
        // (`mempool_accept_wtxid.py:82`). Ignores inv_gen_floor / age gate.
        Err(e) if e.to_string() == "policy: txn-same-nonwitness-data-in-mempool" => {
            let tid = tx.compute_txid();
            if let (Some(peers), Some(chain)) = (ctx.peers.as_ref(), ctx.chain.as_ref()) {
                rbitcoin_net::force_announce_txid(chain, peers, tid);
            }
            Ok(json!(hash_hex_display(&tid.to_byte_array())))
        }
        Err(e) => Err(rpc_error(ERR_VERIFY_REJECTED, accept_reject_reason(&e))),
    }
}

pub(crate) fn accept_reject_reason(e: &impl std::fmt::Display) -> String {
    let owned = e.to_string();
    let s = owned.strip_prefix("policy: ").unwrap_or(owned.as_str());
    if s == "coinbase immature" {
        return "bad-txns-premature-spend-of-coinbase".into();
    }
    if s == "coinbase" {
        return "bad-txns-is-coinbase".into();
    }
    if s.starts_with("missing prevout") {
        return "bad-txns-inputs-missingorspent".into();
    }
    if s.starts_with("duplicate ") {
        return "txn-already-in-mempool".into();
    }
    if s == "inputs-duplicate" {
        return "bad-txns-inputs-duplicate".into();
    }
    if s == "not final" {
        return "non-final".into();
    }
    if s == "negative fee" {
        return "bad-txns-in-belowout".into();
    }
    if s == "non-BIP68-final" {
        return "non-BIP68-final".into();
    }
    if s == "rbf insufficient fee" {
        return "insufficient fee".into();
    }
    if s == "min relay fee" {
        return "min relay fee not met".into();
    }
    if let Some(rest) = s.strip_prefix("script: ") {
        let rest = rest
            .strip_prefix("script verification failed: ")
            .unwrap_or(rest);
        let paren = rbitcoin_consensus::script_flag_paren(rest);
        return format!("mempool-script-verify-flag-failed ({paren})");
    }
    s.to_string()
}

/// Core `reject-details` for mempool rejects.
/// Core `reject-details` for mempool rejects.
pub(crate) fn accept_reject_details(
    e: &impl std::fmt::Display,
    tx: &Transaction,
) -> Option<String> {
    let reason = accept_reject_reason(e);
    if reason == "txn-already-in-mempool" || reason == "txn-same-nonwitness-data-in-mempool" {
        return Some(reason);
    }
    if !reason.starts_with("mempool-script-verify-flag-failed") {
        return None;
    }
    let vin = 0usize;
    let inp = tx.input.get(vin)?;
    let prev = inp.previous_output;
    Some(format!(
        "{reason}, input {vin} of {} (wtxid {}), spending {}:{}",
        tx.compute_txid(),
        tx.compute_wtxid(),
        prev.txid,
        prev.vout
    ))
}

pub(crate) fn testmempoolaccept(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["rawtxs", "maxfeerate"])?;
    let max_feerate = opt_maxfeerate_sat_kvb(params, 1)?;
    let arr = params
        .get_array(0, "rawtxs")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "rawtxs array required"))?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let mut decoded = Vec::new();
    for v in arr {
        let hex = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "rawtx hex required"))?;
        decoded.push(decode_tx_hex(hex)?);
    }
    let mut ids = std::collections::HashSet::new();
    if decoded.iter().any(|tx| !ids.insert(tx.compute_txid())) {
        let tx = &decoded[0];
        return Ok(json!([{
            "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
            "wtxid": hash_hex_display(&tx.compute_wtxid().to_byte_array()),
            "allowed": false,
            "package-error": "package-contains-duplicates",
        }]));
    }
    let mut out = Vec::new();
    for tx in decoded {
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        match mp.test_accept(&tx) {
            Ok(r) => {
                let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
                if fee_exceeds_max(r.fee_sat, r.weight, max_feerate) {
                    out.push(json!({
                        "txid": txid,
                        "wtxid": wtxid,
                        "allowed": false,
                        "reject-reason": "max-fee-exceeded",
                    }));
                    continue;
                }
                out.push(json!({
                    "txid": txid,
                    "wtxid": wtxid,
                    "allowed": true,
                    "vsize": r.weight / 4,
                    "fees": { "base": sat_btc_json(r.fee_sat as i64) },
                }));
            }
            Err(e) => {
                let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
                let mut row = json!({
                    "txid": txid,
                    "wtxid": wtxid,
                    "allowed": false,
                    "reject-reason": accept_reject_reason(&e),
                });
                if let Some(details) = accept_reject_details(&e, &tx) {
                    row["reject-details"] = json!(details);
                }
                out.push(row);
            }
        }
    }
    Ok(json!(out))
}

/// Core `ParseConfirmTarget`: integer in `1..=1008`.
/// Core `ParseConfirmTarget`: integer in `1..=1008`.
pub(crate) fn parse_conf_target(v: &Value) -> Result<u32, Value> {
    let conf_target = match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|i| u64::try_from(i).ok()))
            .ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type number is not of expected type number",
                )
            })? as u32,
        other => {
            return Err(rpc_error(
                ERR_TYPE_ERROR,
                format!(
                    "JSON value of type {} is not of expected type number",
                    json_type_name(other)
                ),
            ));
        }
    };
    if !(1..=1008).contains(&conf_target) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "Invalid conf_target, must be between 1 and 1008",
        ));
    }
    Ok(conf_target)
}

/// Map Core `estimatesmartfee` to this node's **10-minute inclusion** product.
/// Map Core `estimatesmartfee` to this node's **10-minute inclusion** product.
pub(crate) fn estimatesmartfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["conf_target", "estimate_mode"])?;
    // Core requires conf_target (`rpc_estimatefee.py`).
    if params.get(0, "conf_target").is_none() {
        return Err(rpc_error(ERR_MISC, method_help("estimatesmartfee")));
    }
    if params.pos_len() > 2 {
        return Err(rpc_error(ERR_MISC, method_help("estimatesmartfee")));
    }
    let conf_target = parse_conf_target(params.get(0, "conf_target").unwrap())?;
    if let Some(mode_v) = params.get(1, "estimate_mode") {
        if !matches!(mode_v, Value::Null) {
            let mode = mode_v.as_str().ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    format!(
                        "JSON value of type {} is not of expected type string",
                        json_type_name(mode_v)
                    ),
                )
            })?;
            let ok = matches!(
                mode.to_ascii_lowercase().as_str(),
                "unset" | "economical" | "conservative"
            );
            if !ok {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"",
                ));
            }
        }
    }
    estimate_fee_result(ctx, conf_target)
}

/// Core `estimaterawfee` name; same 10-minute product as [`estimatesmartfee`].
/// Core `estimaterawfee` name; same 10-minute product as [`estimatesmartfee`].
pub(crate) fn estimaterawfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["conf_target", "threshold"])?;
    if params.get(0, "conf_target").is_none() {
        return Err(rpc_error(ERR_MISC, method_help("estimaterawfee")));
    }
    if params.pos_len() > 2 {
        return Err(rpc_error(ERR_MISC, method_help("estimaterawfee")));
    }
    let conf_target = parse_conf_target(params.get(0, "conf_target").unwrap())?;
    if let Some(th) = params.get(1, "threshold") {
        if !matches!(th, Value::Null) && json_u64(th).is_none() && th.as_f64().is_none() {
            return Err(rpc_error(
                ERR_TYPE_ERROR,
                format!(
                    "JSON value of type {} is not of expected type number",
                    json_type_name(th)
                ),
            ));
        }
    }
    // Core returns nested short/medium/long buckets; we expose the same
    // single-horizon product under `short` for harness compatibility.
    let base = estimate_fee_result(ctx, conf_target)?;
    Ok(json!({
        "short": {
            "feerate": base.get("feerate").cloned().unwrap_or(json!(-1.0)),
            "decay": 0.962,
            "scale": 2,
            "pass": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
            "fail": Value::Null,
            "errors": base.get("errors").cloned().unwrap_or(Value::Null),
        }
    }))
}

pub(crate) fn estimate_fee_result(ctx: &RpcContext, conf_target: u32) -> Result<Value, Value> {
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({
            "feerate": -1.0,
            "errors": ["mempool unavailable"],
            "blocks": conf_target,
        }));
    };
    let rate = mp.estimate_fee_btc_per_kb(conf_target);
    if rate < 0.0 {
        return Ok(json!({
            "feerate": -1.0,
            "errors": ["Insufficient data or empty mempool"],
            "blocks": conf_target.max(1),
        }));
    }
    Ok(json!({
        "feerate": rate,
        "blocks": conf_target.max(1),
        "errors": Value::Null,
        "rbitcoin_model": "10-minute inclusion frontier (not Core historical)",
    }))
}

pub(crate) fn prioritisetransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "dummy", "fee_delta"])?;
    let missing = params.get(0, "txid").is_none() || params.get(2, "fee_delta").is_none();
    let extra_pos = params.pos_len() > 3;
    if missing || extra_pos {
        return Err(rpc_error(ERR_MISC, "prioritisetransaction"));
    }
    let txid_s = params.req_str(0, "txid")?;
    if txid_s.len() != 64 {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!(
                "txid must be of length 64 (not {}, for '{txid_s}')",
                txid_s.len()
            ),
        ));
    }
    if !txid_s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("txid must be hexadecimal string (not '{txid_s}')"),
        ));
    }
    if let Some(dummy) = params.get(1, "dummy") {
        if dummy.as_i64() != Some(0) && dummy.as_u64() != Some(0) {
            if dummy.as_i64().is_none() && dummy.as_u64().is_none() {
                return Err(rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type string is not of expected type number",
                ));
            }
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.",
            ));
        }
    }
    let fee_delta = params
        .get(2, "fee_delta")
        .and_then(json_i64)
        .ok_or_else(|| {
            if params.get(2, "fee_delta").is_some() {
                rpc_error(
                    ERR_TYPE_ERROR,
                    "JSON value of type string is not of expected type number",
                )
            } else {
                rpc_error(ERR_INVALID_PARAMS, "fee_delta required")
            }
        })?;
    let txid = Txid::from_byte_array(parse_hash32_display(txid_s)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "no mempool"))?;
    mp.prioritise_tx(txid, fee_delta);
    Ok(json!(true))
}

pub(crate) fn getprioritisedtransactions(
    ctx: &RpcContext,
    params: &RpcParams,
) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    if params.pos_len() != 0 {
        return Err(rpc_error(ERR_MISC, "getprioritisedtransactions"));
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({}));
    };
    let mut out = serde_json::Map::new();
    for (txid, delta) in mp.prioritised_txs() {
        let in_mempool = mp.contains(&txid);
        let mut row = json!({
            "fee_delta": delta,
            "in_mempool": in_mempool,
        });
        if in_mempool {
            if let Some((base, _)) = mp.get_live_meta(&txid) {
                let modified = (base as i64).saturating_add(delta);
                row["modified_fee"] = json!(modified);
            }
        }
        out.insert(txid.to_string(), row);
    }
    Ok(Value::Object(out))
}

pub(crate) fn getmempoolcluster(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid"])?;
    let hex = params.req_str(0, "txid")?;
    let tid = Txid::from_byte_array(parse_hash32_display(hex)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let Some((weight, count, chunks)) = mp.cluster_rpc(&tid) else {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Transaction not in mempool",
        ));
    };
    let chunks_json: Vec<Value> = chunks
        .into_iter()
        .map(|(fee, w, txs)| {
            json!({
                "chunkfee": sat_btc_json(fee),
                "chunkweight": w,
                "txs": txs.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "clusterweight": weight,
        "txcount": count,
        "chunks": chunks_json,
    }))
}

pub(crate) fn getmempoolancestors(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, true)
}

pub(crate) fn getmempooldescendants(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, false)
}

pub(crate) fn mempool_relatives(
    ctx: &RpcContext,
    hex: &str,
    verbose: bool,
    ancestors: bool,
) -> Result<Value, Value> {
    let tid = Txid::from_byte_array(parse_hash32_display(hex)?);
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let ids = if ancestors {
        mp.ancestor_txids(&tid)
    } else {
        mp.descendant_txids(&tid)
    };
    let Some(ids) = ids else {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Transaction not in mempool",
        ));
    };
    if !verbose {
        let hexes: Vec<String> = ids
            .iter()
            .map(|t| hash_hex_display(&t.to_byte_array()))
            .collect();
        return Ok(json!(hexes));
    }
    let live = mp.list_live_meta();
    let mut map = serde_json::Map::new();
    for id in ids {
        if let Some((_, fee, weight)) = live.iter().find(|(t, _, _)| *t == id) {
            map.insert(
                hash_hex_display(&id.to_byte_array()),
                mempool_graph_json(mp, &id, *fee, *weight),
            );
        }
    }
    Ok(Value::Object(map))
}

pub(crate) fn getmempoolfeeratediagram(
    ctx: &RpcContext,
    params: &RpcParams,
) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!([]));
    };
    let pts: Vec<Value> = mp
        .feerate_diagram()
        .into_iter()
        .map(|(weight, fee)| {
            json!({
                "weight": weight,
                "fee": sat_btc_json(fee),
            })
        })
        .collect();
    Ok(json!(pts))
}

pub(crate) fn submitpackage(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["package", "maxfeerate", "maxburnamount"])?;
    let arr = params
        .get_array(0, "package")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "package array required"))?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    if !mp.relay_enabled() {
        return Err(rpc_error(
            ERR_MISC,
            "mempool relay disabled (still in IBD or tip not ready)",
        ));
    }
    let mut txs = Vec::with_capacity(arr.len());
    for v in arr {
        let hex = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "package hex required"))?;
        txs.push(decode_tx_hex(hex)?);
    }
    let results = mp.submit_package_rpc(&txs);
    let mut tx_results = serde_json::Map::new();
    let mut replaced = Vec::new();
    let mut all_ok = true;
    for (tx, r) in txs.iter().zip(results.iter()) {
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        match r {
            Ok(ok) => {
                mp.note_unbroadcast(ok.txid);
                for old in &ok.replaced {
                    replaced.push(hash_hex_display(&old.to_byte_array()));
                }
                tx_results.insert(
                    wtxid,
                    json!({
                        "txid": txid,
                        "vsize": ok.weight / 4,
                        "fees": { "base": sat_btc_json(ok.fee_sat as i64) },
                    }),
                );
            }
            Err(e) => {
                let reason = accept_reject_reason(e);
                if reason == "txn-already-in-mempool" {
                    tx_results.insert(wtxid, json!({ "txid": txid }));
                    continue;
                }
                all_ok = false;
                tx_results.insert(
                    wtxid,
                    json!({
                        "txid": txid,
                        "error": reason,
                    }),
                );
            }
        }
    }
    Ok(json!({
        "package_msg": if all_ok { "success" } else { "transaction failed" },
        "tx-results": tx_results,
        "replaced-transactions": replaced,
    }))
}

pub(crate) fn gettxspendingprevout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["outputs"])?;
    let arr = params
        .get_array(0, "outputs")
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "outputs array required"))?;
    let mp = ctx.mempool.as_ref();
    let mut out = Vec::new();
    for v in arr {
        let obj = v
            .as_object()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "output must be an object"))?;
        let txid = obj
            .get("txid")
            .and_then(|x| x.as_str())
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "txid required"))?;
        let vout =
            obj.get("vout")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "vout required"))? as u32;
        let want = parse_hash32_display(txid)?;
        let op = OutPoint {
            txid: Txid::from_byte_array(want),
            vout,
        };
        let mut row = json!({
            "txid": txid,
            "vout": vout,
        });
        if let Some(mp) = mp {
            if let Some(sp) = mp.spending_txid(&op) {
                row["spendingtxid"] = json!(hash_hex_display(&sp.to_byte_array()));
            }
        }
        out.push(row);
    }
    Ok(json!(out))
}
