use super::*;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, Txid};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Height;
use serde_json::{json, Value};

#[doc(hidden)]
pub fn mempool_info_limits(ctx: &RpcContext) -> (u32, u64) {
    ctx.mempool
        .as_ref()
        .map(|mp| mp.cluster_limits())
        .unwrap_or_else(MempoolHub::default_cluster_limits)
}

#[doc(hidden)]
pub fn relay_fee_json() -> Value {
    sat_btc_json(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB as i64)
}

pub fn getmempoolinfo(ctx: &RpcContext) -> Result<Value, Value> {
    let (limit_count, limit_vsize) = mempool_info_limits(ctx);
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({
            "loaded": true,
            "size": 0,
            "bytes": 0,
            "usage": 0,
            "total_fee": sat_btc_json(0),
            "maxmempool": 0,
            "mempoolminfee": relay_fee_json(),
            "minrelaytxfee": relay_fee_json(),
            "incrementalrelayfee": relay_fee_json(),
            "unbroadcastcount": 0,
            "fullrbf": true,
            "maxdatacarriersize": Value::Null,
            "limitclustercount": limit_count,
            "limitclustersize": limit_vsize,
            "permitbaremultisig": true,
            "optimal": true,
            "orphanage": { "size": 0, "bytes": 0 },
        }));
    };
    let (size, bytes, total_fee) = mp.live_adjusted_totals();
    let (orphan_size, orphan_wu) = mp.orphan_stats();
    Ok(json!({
        "loaded": true,
        "size": size,
        "bytes": bytes,
        "usage": bytes,
        "total_fee": sat_btc_json(total_fee as i64),
        // Core's field is the virtual-size byte cap, same unit as `bytes`.
        // The hub budget stays weight; the metric reports that weight.
        "maxmempool": mp.max_weight() / 4,
        "mempoolminfee": sat_btc_json(mp.mempool_min_fee_sat_kvb() as i64),
        "minrelaytxfee": sat_btc_json(mp.min_relay_sat_kvb() as i64),
        "incrementalrelayfee": relay_fee_json(),
        "relay_enabled": mp.relay_enabled(),
        "unbroadcastcount": mp.unbroadcast_count(),
        "fullrbf": true,
        "maxdatacarriersize": Value::Null,
        "limitclustercount": limit_count,
        "limitclustersize": limit_vsize,
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
#[doc(hidden)]
pub fn accept_fees_json(fee_sat: u64, weight: u64, wtxid: &str) -> Value {
    accept_fees_parts(fee_sat, fee_sat, weight, &[wtxid.to_string()])
}

#[doc(hidden)]
pub fn accept_fees_parts(base_sat: u64, eff_sat: u64, weight: u64, includes: &[String]) -> Value {
    let vsize = rbitcoin_consensus::policy::vbytes_ceil(weight).max(1);
    let sat_kvb = eff_sat.saturating_mul(1000).checked_div(vsize).unwrap_or(0);
    json!({
        "base": sat_btc_json(base_sat as i64),
        "effective-feerate": sat_btc_json(sat_kvb as i64),
        "effective-includes": includes,
    })
}

/// Own modified feerate, or the package remainder when `fee_with` is set.
#[doc(hidden)]
pub fn submit_fees_json(
    mp: &MempoolHub,
    txid: &Txid,
    base_fee: u64,
    weight: u64,
    wtxid: &str,
    fee_with: Option<&[Txid]>,
) -> Value {
    if let Some(ids) = fee_with.filter(|ids| ids.len() >= 2) {
        let mut eff = 0i128;
        let mut vsize_sum = 0u64;
        let mut inc = Vec::with_capacity(ids.len());
        for id in ids {
            let base = mp.get_live_meta(id).map(|(fee, _)| fee).unwrap_or(0);
            let delta = mp.fee_delta(id);
            eff = eff
                .saturating_add(i128::from(base))
                .saturating_add(i128::from(delta));
            let w = mp.get_live_adjusted_weight(id).unwrap_or(0);
            vsize_sum = vsize_sum.saturating_add(rbitcoin_consensus::policy::vbytes_ceil(w));
            let Some(wt) = mp.wtxid_of(id) else {
                inc.clear();
                break;
            };
            inc.push(hash_hex_display(&wt.to_byte_array()));
        }
        if inc.len() == ids.len() && vsize_sum > 0 {
            return accept_fees_parts(
                base_fee,
                eff.max(0) as u64,
                vsize_sum.saturating_mul(4),
                &inc,
            );
        }
    }
    let modified = i128::from(base_fee)
        .saturating_add(i128::from(mp.fee_delta(txid)))
        .max(0) as u64;
    accept_fees_parts(base_fee, modified, weight, &[wtxid.to_string()])
}

pub fn sat_btc_json(sat: i64) -> Value {
    let sign = if sat < 0 { "-" } else { "" };
    let abs = sat.unsigned_abs();
    let s = format!("{sign}{}.{:08}", abs / 100_000_000, abs % 100_000_000);
    Value::Number(s.parse().expect("sat/BTC decimal"))
}

/// Shared getrawmempool-verbose / getmempoolentry graph + unbroadcast fields.
/// Shared getrawmempool-verbose / getmempoolentry graph + unbroadcast fields.
pub fn mempool_graph_json(mp: &MempoolHub, txid: &Txid, fee: u64, weight: u64) -> Value {
    // Core `vsize` is sigop-adjusted; `weight` stays raw.
    let adj = mp.get_live_adjusted_weight(txid).unwrap_or(weight);
    let vsize = rbitcoin_consensus::policy::vbytes_ceil(adj);
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
                1, vsize, fee, 1, vsize, fee, modified, modified, modified, adj,
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
    let wtxid = mp
        .wtxid_of(txid)
        .map(|w| hash_hex_display(&w.to_byte_array()))
        .unwrap_or_default();
    json!({
        "vsize": vsize,
        "weight": weight,
        "wtxid": wtxid,
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
    let listing = ctx.pool_listing();
    // Core lists this during catch-up. A nonempty catch-up pool may still
    // hold confirmed transactions, so that case stays refused. `-blocksonly`
    // lists what RPC admitted.
    let stale_catch_up = matches!(listing, PoolListing::Downloading) && !catch_up_pool_empty(ctx);
    if stale_catch_up {
        return Err(pool_listing_unavailable(listing));
    }
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
        let mut ids: Vec<String> = live
            .iter()
            .map(|(t, _, _)| hash_hex_display(&t.to_byte_array()))
            .collect();
        ids.sort();
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

pub fn getmempoolentry(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid"])?;
    let hex = params.req_str(0, "txid")?;
    let want = parse_hash32_display(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    let tid = Txid::from_byte_array(want);
    if let Some((fee, weight)) = mp.get_live_meta(&tid) {
        return Ok(mempool_graph_json(mp, &tid, fee, weight));
    }
    Err(rpc_error(
        ERR_INVALID_ADDRESS_OR_KEY,
        "Transaction not in mempool",
    ))
}

pub fn getrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose", "verbosity", "blockhash"])?;
    let hex = params.req_str(0, "txid")?;
    let want = parse_hash32_display(hex)?;
    if want == genesis_coinbase_txid(ctx) {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved",
        ));
    }
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
        .ok_or_else(|| {
            rpc_error(
                ERR_INVALID_ADDRESS_OR_KEY,
                "No such mempool or blockchain transaction",
            )
        })?;
    let tx = ctx
        .query
        .reconstruct_tx(fk)
        .map_err(|e| map_query(e, "Transaction not available (pruned data)"))?;
    if !verbose {
        return Ok(json!(serialize_hex(&tx)));
    }
    // The resolver falls back to an unconnected Class A row (reorg orphan,
    // invalidateblock, never-connected archive). It has no active-chain block,
    // so it gets the plain object, without confirmations or block fields.
    let unconnected = || {
        Ok(tx_to_json(
            &tx,
            Some(json!({ "in_mempool": false })),
            rpc_btc_network(ctx.network),
        ))
    };
    let store_err = |e: rbitcoin_store::StoreError| rpc_error(ERR_MISC, e.to_string());
    let Some(height) = ctx.query.store().tx_height_get(fk).map_err(store_err)? else {
        return unconnected();
    };
    // The fence and confirmed[] do not move together (connect extends the
    // fence before setting confirmed[h]; disconnect clears confirmed[h] before
    // popping the fence), so a reorg can put another block at `height` between
    // these reads. Only report the header whose own Class A run holds `fk`.
    let Some((header_fk, header)) = ctx
        .query
        .header_at_height(Height(height))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    else {
        return unconnected();
    };
    let holds_fk = ctx
        .query
        .store()
        .header_txs
        .get_range(header_fk)
        .map_err(store_err)?
        .is_some_and(|(first, n)| (first.0..first.0.saturating_add(u64::from(n))).contains(&fk.0));
    let tip = ctx.query.tip_height();
    let Some(tip) = tip.filter(|t| holds_fk && t.0 >= height) else {
        return unconnected();
    };
    Ok(tx_to_json(
        &tx,
        Some(json!({
            "in_mempool": false,
            "confirmations": tip.0.saturating_sub(height).saturating_add(1),
            "blockhash": hash_hex_display(&header.hash),
            "blocktime": header.timestamp,
            "time": header.timestamp,
        })),
        rpc_btc_network(ctx.network),
    ))
}

/// Default RPC-submit cap: 10_000 sat/vB. `0` is unlimited.
#[doc(hidden)]
pub const DEFAULT_MAX_RAW_TX_FEE_SAT_VB: u64 = 10_000;
/// Sanity cap on the `maxfeerate` argument (sat/vB).
#[doc(hidden)]
pub const MAX_ALLOWED_FEERATE_SAT_VB: u64 = 100_000;

#[doc(hidden)]
pub fn parse_rpc_btc_to_sat(s: &str) -> Result<u64, Value> {
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

#[doc(hidden)]
pub fn amount_sat_from_json(v: &Value) -> Result<u64, Value> {
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

/// RPC-submit `maxfeerate` (sat/vB). Omitted → 10_000. `0` → unlimited.
/// `>= 100_000` is a parameter error. P2P `accept_tx` does not read this cap.
#[doc(hidden)]
pub fn opt_maxfeerate_sat_vb(params: &RpcParams, index: usize) -> Result<u64, Value> {
    match params.get(index, "maxfeerate") {
        None | Some(Value::Null) => Ok(DEFAULT_MAX_RAW_TX_FEE_SAT_VB),
        Some(v) => {
            let sat_vb = sat_vb_from_json(v)?;
            if sat_vb >= MAX_ALLOWED_FEERATE_SAT_VB {
                return Err(rpc_error(
                    ERR_INVALID_PARAMETER,
                    "feerate >= 100000 sat/vB is not accepted",
                ));
            }
            Ok(sat_vb)
        }
    }
}

#[doc(hidden)]
pub fn sat_vb_from_json(v: &Value) -> Result<u64, Value> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Ok(u);
            }
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(rpc_error(ERR_INVALID_PARAMETER, "Amount out of range"));
                }
                return Ok(i as u64);
            }
            Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "maxfeerate must be an integer sat/vB",
            ))
        }
        Value::String(s) => {
            let t = s.trim();
            if t.starts_with('-') {
                return Err(rpc_error(ERR_INVALID_PARAMETER, "Amount out of range"));
            }
            t.parse::<u64>().map_err(|_| {
                rpc_error(
                    ERR_INVALID_PARAMETER,
                    "maxfeerate must be an integer sat/vB",
                )
            })
        }
        _ => Err(rpc_error(
            ERR_TYPE_ERROR,
            "maxfeerate is not a number or string",
        )),
    }
}

#[doc(hidden)]
pub use rbitcoin_consensus::policy::fee_exceeds_max;

#[doc(hidden)]
pub fn prevout_value_sat(ctx: &RpcContext, op: &OutPoint) -> Option<u64> {
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
    Some(out.value)
}

#[derive(Debug)]
pub enum TxFeeLook {
    Fee(u64),
    MissingPrevout,
    Overflow,
}

#[doc(hidden)]
pub fn fold_tx_fee_sat(
    in_vals: impl IntoIterator<Item = Option<u64>>,
    out_sum: Option<u64>,
) -> TxFeeLook {
    let mut in_sum = 0u64;
    for v in in_vals {
        let Some(v) = v else {
            return TxFeeLook::MissingPrevout;
        };
        in_sum = match in_sum.checked_add(v) {
            Some(s) => s,
            None => return TxFeeLook::Overflow,
        };
    }
    let Some(out_sum) = out_sum else {
        return TxFeeLook::Overflow;
    };
    match in_sum.checked_sub(out_sum) {
        Some(fee) => TxFeeLook::Fee(fee),
        None => TxFeeLook::Overflow,
    }
}

#[doc(hidden)]
pub fn tx_output_sum_sat(tx: &Transaction) -> Option<u64> {
    tx.output
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
}

pub fn tx_fee_sat_from_prevouts(ctx: &RpcContext, tx: &Transaction) -> TxFeeLook {
    fold_tx_fee_sat(
        tx.input
            .iter()
            .map(|inp| prevout_value_sat(ctx, &inp.previous_output)),
        tx_output_sum_sat(tx),
    )
}

#[doc(hidden)]
pub fn package_dialect_from_env(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

#[doc(hidden)]
pub fn rpc_package_dialect() -> bool {
    package_dialect_from_env(
        std::env::var("RBITCOIN_RPC_PACKAGE_DIALECT")
            .ok()
            .as_deref(),
    )
}

#[doc(hidden)]
pub fn submitpackage_topology_disallowed(txs: &[Transaction], dialect: bool) -> bool {
    dialect && txs.len() > 1 && !MempoolHub::package_is_child_with_direct_parents(txs)
}

#[doc(hidden)]
/// RPC submit admits versions 1, 2, and 3.
///
/// P2P still admits any `nVersion`. Version 3 is BIP 431 TRUC, which Bark
/// captaind uses for tree, forfeit, connector, and CPFP transactions. Other
/// versions stay an RPC `"version"` reject.
pub fn rpc_tx_version_nonstandard(tx: &Transaction) -> bool {
    let v = tx.version.0;
    v != 1 && v != 2 && v != 3
}

#[doc(hidden)]
pub fn rpc_tx_fee_exceeds_max(ctx: &RpcContext, tx: &Transaction, max_sat_vb: u64) -> bool {
    match tx_fee_sat_from_prevouts(ctx, tx) {
        TxFeeLook::Fee(fee) => fee_exceeds_max(fee, tx.weight().to_wu(), max_sat_vb),
        TxFeeLook::Overflow => max_sat_vb != 0,
        TxFeeLook::MissingPrevout => false,
    }
}

#[doc(hidden)]
pub fn prevout_value_sat_in_package(
    ctx: &RpcContext,
    op: &OutPoint,
    package: &[Transaction],
) -> Option<u64> {
    for tx in package {
        if tx.compute_txid() == op.txid {
            return tx.output.get(op.vout as usize).map(|o| o.value.to_sat());
        }
    }
    prevout_value_sat(ctx, op)
}

#[doc(hidden)]
pub fn package_tx_fee_exceeds_max(
    ctx: &RpcContext,
    tx: &Transaction,
    package: &[Transaction],
    max_sat_vb: u64,
) -> bool {
    match fold_tx_fee_sat(
        tx.input
            .iter()
            .map(|inp| prevout_value_sat_in_package(ctx, &inp.previous_output, package)),
        tx_output_sum_sat(tx),
    ) {
        TxFeeLook::Fee(fee) => fee_exceeds_max(fee, tx.weight().to_wu(), max_sat_vb),
        TxFeeLook::Overflow => max_sat_vb != 0,
        TxFeeLook::MissingPrevout => false,
    }
}

/// RPC-submit `maxburnamount` (BTC). Omitted → 0. Sum of unspendable output values vs cap.
#[doc(hidden)]
pub fn opt_maxburn_sat(params: &RpcParams, index: usize) -> Result<u64, Value> {
    match params.get(index, "maxburnamount") {
        None | Some(Value::Null) => Ok(0),
        Some(v) => amount_sat_from_json(v),
    }
}

#[doc(hidden)]
pub fn unspendable_output_sat(tx: &Transaction) -> u64 {
    tx.output
        .iter()
        .filter(|o| crate::blockstats::is_unspendable(o.script_pubkey.as_bytes()))
        .map(|o| o.value.to_sat())
        .sum()
}

#[doc(hidden)]
pub fn burn_exceeds_max(tx: &Transaction, max_burn_sat: u64) -> bool {
    unspendable_output_sat(tx) > max_burn_sat
}

#[doc(hidden)]
pub const MAX_BURN_MSG: &str =
    "Unspendable output exceeds maximum configured by user (maxburnamount)";

pub fn sendrawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexstring", "maxfeerate", "maxburnamount"])?;
    let hex = params.req_str(0, "hexstring")?;
    let max_feerate = opt_maxfeerate_sat_vb(params, 1)?;
    let max_burn = opt_maxburn_sat(params, 2)?;
    let tx = decode_tx_hex(hex)?;
    let mp = ctx
        .mempool
        .as_ref()
        .ok_or_else(|| rpc_error(ERR_MISC, "mempool not available"))?;
    if burn_exceeds_max(&tx, max_burn) {
        return Err(rpc_error(ERR_INVALID_PARAMETER, MAX_BURN_MSG));
    }
    if rpc_tx_version_nonstandard(&tx) {
        return Err(rpc_error(ERR_VERIFY_REJECTED, "version"));
    }
    if rpc_tx_fee_exceeds_max(ctx, &tx, max_feerate) {
        return Err(rpc_error(
            ERR_VERIFY_ERROR,
            "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
        ));
    }
    // `-blocksonly` leaves P2P relay off but RPC still accepts
    // (`p2p_blocksonly.py` sendrawtransaction).
    match mp.accept_tx(&tx) {
        Ok(r) => {
            mp.note_unbroadcast(r.txid);
            mp.mark_local_origin(r.txid);
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

pub fn accept_reject_reason(e: &impl std::fmt::Display) -> String {
    let owned = e.to_string();
    let s = owned.strip_prefix("policy: ").unwrap_or(owned.as_str());
    if s == "coinbase immature" {
        return "bad-txns-premature-spend-of-coinbase".into();
    }
    if s == "coinbase" {
        return "bad-txns-is-coinbase".into();
    }
    if s.starts_with("missing prevout") || s.starts_with("orphaned ") {
        return "missing-inputs".into();
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
    if s == "mempool min fee" {
        return "mempool min fee not met".into();
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
pub fn accept_reject_details(e: &impl std::fmt::Display, tx: &Transaction) -> Option<String> {
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

pub fn testmempoolaccept(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["rawtxs", "maxfeerate"])?;
    let max_feerate = opt_maxfeerate_sat_vb(params, 1)?;
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
    if let Some(rows) = testmempoolaccept_package_precheck(mp, &decoded) {
        return Ok(rows);
    }
    if decoded.len() >= 2 {
        return Ok(testmempoolaccept_package_rows(mp, &decoded, max_feerate));
    }
    testmempoolaccept_single_rows(ctx, mp, decoded, max_feerate)
}

#[doc(hidden)]
pub fn testmempoolaccept_package_precheck(
    mp: &MempoolHub,
    decoded: &[Transaction],
) -> Option<Value> {
    let mut ids = std::collections::HashSet::new();
    if decoded.iter().any(|tx| !ids.insert(tx.compute_txid())) {
        return Some(package_error_rows(decoded, "package-contains-duplicates"));
    }
    if decoded.len() < 2 {
        return None;
    }
    if package_has_conflicts(decoded) {
        return Some(package_error_rows(decoded, "conflict-in-package"));
    }
    if let Err(rbitcoin_net::AcceptError::PackageNotTopo) = MempoolHub::check_package_shape(decoded)
    {
        return Some(package_error_rows(decoded, "package-not-sorted"));
    }
    if mp.package_would_exceed_cluster(decoded) {
        return Some(package_error_rows(decoded, "too-large-cluster"));
    }
    None
}

#[doc(hidden)]
pub fn testmempoolaccept_package_rows(
    mp: &MempoolHub,
    decoded: &[Transaction],
    max_feerate: u64,
) -> Value {
    let mut added = Vec::new();
    let mut out = Vec::new();
    for tx in decoded {
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        if rpc_tx_version_nonstandard(tx) {
            out.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": "version",
            }));
            continue;
        }
        if tx
            .input
            .iter()
            .any(|i| mp.spending_txid(&i.previous_output).is_some())
        {
            out.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": "bip125-replacement-disallowed",
                "reject-details": "bip125-replacement-disallowed",
            }));
            continue;
        }
        match mp.accept_tx(tx) {
            Ok(r) => {
                added.push(r.txid);
                if fee_exceeds_max(r.fee_sat, r.weight, max_feerate) {
                    out.push(json!({
                        "txid": txid,
                        "wtxid": wtxid,
                        "allowed": false,
                        "reject-reason": "max-fee-exceeded",
                    }));
                } else {
                    out.push(json!({
                        "txid": txid,
                        "wtxid": wtxid,
                        "allowed": true,
                        "vsize": rbitcoin_consensus::policy::vbytes_ceil(r.weight),
                        "fees": accept_fees_json(r.fee_sat, r.weight, &wtxid),
                    }));
                }
            }
            Err(e) => {
                let mut row = json!({
                    "txid": txid,
                    "wtxid": wtxid,
                    "allowed": false,
                    "reject-reason": accept_reject_reason(&e),
                });
                if let Some(details) = accept_reject_details(&e, tx) {
                    row["reject-details"] = json!(details);
                }
                out.push(row);
            }
        }
    }
    if !added.is_empty() {
        mp.remove_for_block(&added);
    }
    json!(out)
}

#[doc(hidden)]
pub fn testmempoolaccept_single_rows(
    ctx: &RpcContext,
    mp: &MempoolHub,
    decoded: Vec<Transaction>,
    max_feerate: u64,
) -> Result<Value, Value> {
    let mut out = Vec::new();
    for tx in decoded {
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        if tx_confirmed_on_active_chain(ctx, &tx)? {
            out.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": "txn-already-known",
            }));
            continue;
        }
        if rpc_tx_version_nonstandard(&tx) {
            out.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": "version",
            }));
            continue;
        }
        match mp.test_accept(&tx) {
            Ok(r) => {
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
                    "vsize": rbitcoin_consensus::policy::vbytes_ceil(r.weight),
                    "fees": accept_fees_json(r.fee_sat, r.weight, &wtxid),
                }));
            }
            Err(e) => {
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

#[doc(hidden)]
pub fn package_has_conflicts(txs: &[Transaction]) -> bool {
    let mut spent = std::collections::HashSet::new();
    for tx in txs {
        for inp in &tx.input {
            if !spent.insert(inp.previous_output) {
                return true;
            }
        }
    }
    false
}

#[doc(hidden)]
pub fn package_error_rows(txs: &[Transaction], msg: &str) -> Value {
    json!(txs
        .iter()
        .map(|tx| {
            json!({
                "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
                "wtxid": hash_hex_display(&tx.compute_wtxid().to_byte_array()),
                "package-error": msg,
            })
        })
        .collect::<Vec<_>>())
}

#[doc(hidden)]
pub fn tx_confirmed_on_active_chain(ctx: &RpcContext, tx: &Transaction) -> Result<bool, Value> {
    let txid = tx.compute_txid().to_byte_array();
    match ctx.query.tx_fk_by_txid_tip(&txid) {
        Ok(None) => Ok(false),
        Ok(Some(fk)) => ctx
            .query
            .store()
            .is_confirmed_strong(fk)
            .map_err(|e| rpc_error(ERR_MISC, format!("query failed: {e}"))),
        Err(e) => Err(rpc_error(ERR_MISC, format!("query failed: {e}"))),
    }
}

/// Core `ParseConfirmTarget`: integer in `1..=1008`.
/// Core `ParseConfirmTarget`: integer in `1..=1008`.
pub fn parse_conf_target(v: &Value) -> Result<u32, Value> {
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
pub fn estimatesmartfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
    smart_fee_result(ctx, conf_target)
}

/// Core's `estimatesmartfee` result: `feerate` (at least `mempoolminfee`) and
/// `blocks` with an estimate; `errors` and `blocks`, and no `feerate`, without one.
#[doc(hidden)]
pub fn smart_fee_result(ctx: &RpcContext, conf_target: u32) -> Result<Value, Value> {
    let blocks = conf_target.max(1);
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!({ "errors": ["mempool unavailable"], "blocks": blocks }));
    };
    let rate = mp.estimate_fee_btc_per_kb(conf_target);
    Ok(smart_fee_json(blocks, rate, mp.mempool_min_fee_sat_kvb()))
}

/// Core's result for `rate` (BTC/kvB; negative = no estimate): `feerate` and
/// `blocks`, or `errors` and `blocks`. An estimate is at least
/// `mempoolminfee`, which includes `minrelaytxfee`.
#[doc(hidden)]
pub fn smart_fee_json(blocks: u32, rate: f64, mempool_min_fee_sat_kvb: u64) -> Value {
    if rate < 0.0 {
        return json!({
            "errors": ["Insufficient data or no feerate found"],
            "blocks": blocks,
        });
    }
    let sat_kvb = ((rate * 100_000_000.0).round() as u64).max(mempool_min_fee_sat_kvb);
    json!({ "feerate": sat_btc_json(sat_kvb as i64), "blocks": blocks })
}

/// Same 10-minute product as [`estimatesmartfee`] under the Core name.
pub fn estimaterawfee(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
    estimate_fee_result(ctx, conf_target)
}

pub fn estimate_fee_result(ctx: &RpcContext, conf_target: u32) -> Result<Value, Value> {
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

pub fn prioritisetransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn getprioritisedtransactions(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn getmempoolcluster(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn getmempoolancestors(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, true)
}

pub fn getmempooldescendants(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "verbose"])?;
    let hex = params.req_str(0, "txid")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(false);
    mempool_relatives(ctx, hex, verbose, false)
}

pub fn mempool_relatives(
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

pub fn getmempoolfeeratediagram(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn submitpackage(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["package", "maxfeerate", "maxburnamount"])?;
    let max_feerate = opt_maxfeerate_sat_vb(params, 1)?;
    let max_burn = opt_maxburn_sat(params, 2)?;
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
    if arr.is_empty() || arr.len() > MempoolHub::max_package_count() {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!(
                "Array must contain between 1 and {} transactions.",
                MempoolHub::max_package_count()
            ),
        ));
    }
    let mut txs = Vec::with_capacity(arr.len());
    for v in arr {
        let hex = v
            .as_str()
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "package hex required"))?;
        txs.push(decode_tx_hex(hex)?);
    }
    if let Err(e) = MempoolHub::check_package_shape(&txs) {
        return Err(rpc_error(ERR_INVALID_PARAMS, e.to_string()));
    }
    if package_has_conflicts(&txs) {
        return Ok(submitpackage_conflict_result(&txs));
    }
    let dialect = rpc_package_dialect();
    if submitpackage_topology_disallowed(&txs, dialect) {
        return Err(rpc_error(ERR_VERIFY_ERROR, "package topology disallowed"));
    }
    if let Some(failed) = submitpackage_fee_burn_precheck(ctx, &txs, max_feerate, max_burn)? {
        return Ok(failed);
    }
    Ok(submitpackage_admit(ctx, mp, &txs, max_feerate))
}

#[doc(hidden)]
pub fn submitpackage_conflict_result(txs: &[Transaction]) -> Value {
    let mut tx_results = serde_json::Map::new();
    for tx in txs {
        tx_results.insert(
            hash_hex_display(&tx.compute_wtxid().to_byte_array()),
            json!({
                "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
                "error": "package-not-validated",
            }),
        );
    }
    json!({
        "package_msg": "conflict-in-package",
        "tx-results": tx_results,
        "replaced-transactions": [],
    })
}

#[doc(hidden)]
pub fn submitpackage_fee_burn_precheck(
    ctx: &RpcContext,
    txs: &[Transaction],
    max_feerate: u64,
    max_burn: u64,
) -> Result<Option<Value>, Value> {
    let mut tx_results = serde_json::Map::new();
    let mut pre_fail = false;
    for tx in txs {
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
        if burn_exceeds_max(tx, max_burn) {
            return Err(rpc_error(ERR_VERIFY_ERROR, MAX_BURN_MSG));
        }
        if rpc_tx_fee_exceeds_max(ctx, tx, max_feerate) {
            pre_fail = true;
            tx_results.insert(
                wtxid,
                json!({
                    "txid": txid,
                    "error": "max feerate exceeded",
                }),
            );
        }
    }
    if !pre_fail {
        return Ok(None);
    }
    for tx in txs {
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        tx_results.entry(wtxid).or_insert_with(|| {
            json!({
                "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
                "error": "bad-txns-inputs-missingorspent",
            })
        });
    }
    Ok(Some(json!({
        "package_msg": "transaction failed",
        "tx-results": tx_results,
        "replaced-transactions": [],
    })))
}

#[doc(hidden)]
pub fn submitpackage_admit(
    ctx: &RpcContext,
    mp: &MempoolHub,
    txs: &[Transaction],
    max_feerate: u64,
) -> Value {
    let mut tx_results = serde_json::Map::new();
    let mut replaced = Vec::new();
    let mut to_admit = Vec::new();
    let mut any_fail = false;
    for tx in txs {
        let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
        let txid_s = hash_hex_display(&tx.compute_txid().to_byte_array());
        if rpc_tx_version_nonstandard(tx) {
            any_fail = true;
            tx_results.insert(
                wtxid,
                json!({
                    "txid": txid_s,
                    "error": "version",
                }),
            );
            continue;
        }
        if !mp.contains(&tx.compute_txid()) {
            to_admit.push(tx.clone());
            continue;
        }
        if let (Some((fee, _)), Some(weight)) = (
            mp.get_live_meta(&tx.compute_txid()),
            mp.get_live_adjusted_weight(&tx.compute_txid()),
        ) {
            tx_results.insert(
                wtxid,
                json!({
                    "txid": txid_s,
                    "vsize": rbitcoin_consensus::policy::vbytes_ceil(weight),
                    "fees": { "base": sat_btc_json(fee as i64) },
                }),
            );
        } else {
            tx_results.insert(wtxid, json!({ "txid": txid_s }));
        }
    }
    // Core compares each member's own feerate with `maxfeerate` before
    // that member can enter, including a parent that exists only in this
    // package. Such a member is not submitted: package feerate must not
    // rescue it, and it must not rescue the others (`rpc_packages.py`).
    let mut eval_txs = Vec::new();
    let mut over_max = Vec::new();
    for tx in to_admit {
        if package_tx_fee_exceeds_max(ctx, &tx, txs, max_feerate) {
            over_max.push(tx);
        } else {
            eval_txs.push(tx);
        }
    }
    let package_eval = over_max.is_empty();
    for (tx, row) in eval_txs
        .iter()
        .zip(mp.submit_package_rpc_eval(&eval_txs, package_eval))
    {
        match row.result {
            Ok(ok) => {
                mp.note_unbroadcast(ok.txid);
                mp.mark_local_origin(ok.txid);
                for old in &ok.replaced {
                    replaced.push(hash_hex_display(&old.to_byte_array()));
                }
                let wtxid = hash_hex_display(&tx.compute_wtxid().to_byte_array());
                tx_results.insert(
                    wtxid.clone(),
                    json!({
                        "txid": hash_hex_display(&ok.txid.to_byte_array()),
                        "vsize": rbitcoin_consensus::policy::vbytes_ceil(ok.weight),
                        "fees": submit_fees_json(
                            mp,
                            &ok.txid,
                            ok.fee_sat,
                            ok.weight,
                            &wtxid,
                            row.fee_with.as_deref(),
                        ),
                    }),
                );
            }
            Err(e) => {
                any_fail = true;
                tx_results.insert(
                    hash_hex_display(&tx.compute_wtxid().to_byte_array()),
                    json!({
                        "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
                        "error": submitpackage_member_error(&e),
                    }),
                );
            }
        }
    }
    for tx in over_max {
        any_fail = true;
        tx_results.insert(
            hash_hex_display(&tx.compute_wtxid().to_byte_array()),
            json!({
                "txid": hash_hex_display(&tx.compute_txid().to_byte_array()),
                "error": "max feerate exceeded",
            }),
        );
    }
    let package_msg = if any_fail {
        "transaction failed"
    } else {
        "success"
    };
    json!({
        "package_msg": package_msg,
        "tx-results": tx_results,
        "replaced-transactions": replaced,
    })
}

#[doc(hidden)]
pub fn submitpackage_member_error(e: &impl std::fmt::Display) -> String {
    let mapped = accept_reject_reason(e);
    if mapped == "missing-inputs" {
        return "bad-txns-inputs-missingorspent".into();
    }
    mapped
}

pub fn gettxspendingprevout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn getorphantxs(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["verbosity"])?;
    let verbosity = match params.get(0, "verbosity") {
        None | Some(Value::Null) => 0i64,
        Some(Value::Bool(_)) => {
            return Err(rpc_error(
                ERR_TYPE_ERROR,
                "Verbosity was boolean but only integer allowed",
            ));
        }
        Some(v) => json_i64(v)
            .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "verbosity must be an integer"))?,
    };
    if !(0..=2).contains(&verbosity) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Invalid verbosity value {verbosity}"),
        ));
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return Ok(json!([]));
    };
    let snaps = mp.orphan_snapshot();
    if verbosity == 0 {
        let ids: Vec<String> = snaps
            .iter()
            .map(|s| hash_hex_display(&s.tx.compute_txid().to_byte_array()))
            .collect();
        return Ok(json!(ids));
    }
    let mut out = Vec::with_capacity(snaps.len());
    for s in snaps {
        let raw = bitcoin::consensus::encode::serialize(&s.tx);
        let weight = s.tx.weight().to_wu();
        let mut row = json!({
            "txid": hash_hex_display(&s.tx.compute_txid().to_byte_array()),
            "wtxid": hash_hex_display(&s.tx.compute_wtxid().to_byte_array()),
            "bytes": raw.len(),
            "vsize": s.tx.vsize(),
            "weight": weight,
            "from": s.announcers,
        });
        if verbosity == 2 {
            row["hex"] = json!(serialize_hex(&s.tx));
        }
        out.push(row);
    }
    Ok(json!(out))
}
