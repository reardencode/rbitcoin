use super::*;
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::key::PublicKey;
use bitcoin::script::Builder;
use bitcoin::{
    Address, Amount, Block, BlockHash, Network as BtcNetwork, OutPoint, ScriptBuf, Transaction,
    Txid,
};
use rbitcoin_primitives::{Height, Network};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::Ordering;

pub(crate) fn require_regtest(ctx: &RpcContext, method: &str) -> Result<(), Value> {
    if ctx.network != Network::Regtest {
        return Err(rpc_error(ERR_MISC, format!("{method} is regtest only")));
    }
    Ok(())
}

pub(crate) fn require_regtest_miner<'a>(
    ctx: &'a RpcContext,
    method: &str,
) -> Result<&'a dyn RpcRegtest, Value> {
    require_regtest(ctx, method)?;
    ctx.regtest
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, format!("{method} requires a live chain hub")))
}

pub(crate) fn rpc_btc_network(n: Network) -> BtcNetwork {
    match n {
        Network::Mainnet => BtcNetwork::Bitcoin,
        Network::Testnet => BtcNetwork::Testnet,
        Network::Signet => BtcNetwork::Signet,
        Network::Regtest => BtcNetwork::Regtest,
    }
}

pub(crate) fn script_pubkey_json(script: &ScriptBuf, network: BtcNetwork) -> Value {
    let mut obj = json!({
        "hex": hex_encode(script.as_bytes()),
        "asm": script.to_asm_string(),
        "type": script_core_type(script),
    });
    if let Ok(addr) = Address::from_script(script, network) {
        if let Some(m) = obj.as_object_mut() {
            m.insert("address".into(), json!(addr.to_string()));
        }
    }
    obj
}

/// Core `decoderawtransaction` / `decodescript` `type` strings.
pub(crate) fn script_core_type(script: &bitcoin::Script) -> &'static str {
    if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else if is_p2anchor(script) {
        "anchor"
    } else if script.is_witness_program() {
        "witness_unknown"
    } else if script.is_op_return() {
        "nulldata"
    } else if script.is_p2pk() {
        "pubkey"
    } else if script.is_multisig() {
        "multisig"
    } else {
        "nonstandard"
    }
}

fn is_p2anchor(script: &bitcoin::Script) -> bool {
    let b = script.as_bytes();
    b.len() == 4 && b[0] == 0x51 && b[1] == 0x02 && b[2] == 0x4e && b[3] == 0x73
}

pub(crate) fn decode_output_script(ctx: &RpcContext, s: &str) -> Result<ScriptBuf, Value> {
    let btc_net = rpc_btc_network(ctx.network);
    if let Ok(a) = s.parse::<Address<_>>() {
        match a.require_network(btc_net) {
            Ok(addr) => return Ok(addr.script_pubkey()),
            Err(_) => {
                return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Invalid address"));
            }
        }
    }
    let bytes = hex_decode(s).map_err(|e| {
        rpc_error(
            ERR_INVALID_PARAMS,
            format!("output must be an address or hex script: {e}"),
        )
    })?;
    Ok(ScriptBuf::from_bytes(bytes))
}

pub(crate) fn hashes_json(hashes: &[BlockHash]) -> Value {
    json!(hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>())
}

pub(crate) fn mempool_block_txs(ctx: &RpcContext) -> Vec<Transaction> {
    let txs = ctx
        .mempool
        .as_ref()
        .map(|mp| mp.select_block_txs())
        .unwrap_or_default();
    let min = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    filter_block_min_fee(ctx, txs, min)
}

/// Whether modified fee meets `-blockmintxfee` as a true sat/kvB floor
/// (`fee * 1000 >= min * vsize`). Zero min admits free txs.
/// Whether modified fee meets `-blockmintxfee` as a true sat/kvB floor
/// (`fee * 1000 >= min * vsize`). Zero min admits free txs.
pub(crate) fn meets_block_min_feerate(modified_sat: i64, weight_wu: u64, min_sat_kvb: u64) -> bool {
    if min_sat_kvb == 0 {
        return true;
    }
    if modified_sat <= 0 {
        return false;
    }
    let vsize = weight_wu.saturating_add(3) / 4;
    if vsize == 0 {
        return false;
    }
    (modified_sat as u64).saturating_mul(1000) >= min_sat_kvb.saturating_mul(vsize)
}

pub(crate) fn filter_block_min_fee(
    ctx: &RpcContext,
    txs: Vec<Transaction>,
    min_sat_kvb: u64,
) -> Vec<Transaction> {
    if min_sat_kvb == 0 {
        return txs;
    }
    let Some(mp) = ctx.mempool.as_ref() else {
        return txs;
    };
    txs.into_iter()
        .filter(|tx| {
            let tid = tx.compute_txid();
            let fee = mp.get_live_meta(&tid).map(|(f, _)| f).unwrap_or(0);
            let modified = (fee as i64).saturating_add(mp.fee_delta(&tid));
            meets_block_min_feerate(modified, tx.weight().to_wu(), min_sat_kvb)
        })
        .collect()
}

pub(crate) fn drain_mempool(ctx: &RpcContext, txs: &[Transaction]) {
    let Some(mp) = ctx.mempool.as_ref() else {
        return;
    };
    let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
    let _ = mp.remove_for_block(&ids);
}

pub(crate) fn generate_with_mempool(
    ctx: &RpcContext,
    nblocks: u32,
    script: ScriptBuf,
) -> Result<Value, Value> {
    let miner = require_regtest_miner(ctx, "generate")?;
    let extras = mempool_block_txs(ctx);
    let hashes = miner
        .generate_to_script(nblocks, script, extras.clone())
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    drain_mempool(ctx, &extras);
    if let Some(c) = ctx.chain.as_ref() {
        c.note_gbt_assembled();
    }
    Ok(hashes_json(&hashes))
}

pub(crate) fn generatetoaddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "address", "maxtries"])?;
    let _miner = require_regtest_miner(ctx, "generatetoaddress")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let addr = params.req_str(1, "address")?;
    let _maxtries = params.opt_u64(2, "maxtries")?;
    let script = decode_output_script(ctx, addr)?;
    generate_with_mempool(ctx, nblocks, script)
}

pub(crate) fn generateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["output", "transactions", "submit"])?;
    let miner = require_regtest_miner(ctx, "generateblock")?;
    let output = params.req_str(0, "output")?;
    let script = parse_generateblock_output(ctx, output)?;
    let mut extra = Vec::new();
    if let Some(arr) = params.get_array(1, "transactions") {
        let mp = ctx.mempool.as_ref();
        for v in arr {
            let s = v.as_str().ok_or_else(|| {
                rpc_error(
                    ERR_INVALID_PARAMS,
                    "transactions entries must be hex or txid",
                )
            })?;
            // Core: 64-hex → Txid::FromHex first; miss → not in mempool (-5).
            if s.len() == 64 {
                if let Ok(tid) = parse_hash32_display(s) {
                    let txid = Txid::from_byte_array(tid);
                    if let Some(mp) = mp {
                        if let Some(tx) = mp.get_tx(&txid) {
                            extra.push(tx);
                            continue;
                        }
                    }
                    return Err(rpc_error(
                        ERR_INVALID_ADDRESS_OR_KEY,
                        format!("Transaction {s} not in mempool."),
                    ));
                }
            }
            match decode_tx_hex(s) {
                Ok(tx) => extra.push(tx),
                Err(_) => {
                    return Err(rpc_error(
                        ERR_DESERIALIZATION,
                        format!(
                            "Transaction decode failed for {s}. Make sure the tx has at least one input."
                        ),
                    ));
                }
            }
        }
    } else if params.get(1, "transactions").is_some() {
        return Err(rpc_error(
            ERR_INVALID_PARAMS,
            "transactions must be an array",
        ));
    } else {
        return Err(rpc_error(ERR_INVALID_PARAMS, "transactions required"));
    }
    let submit = params.opt_bool(2, "submit")?.unwrap_or(true);
    if !submit {
        let block = miner
            .assemble_block_to_script(script, extra)
            .map_err(|e| generateblock_validity_error(&e))?;
        return Ok(json!({
            "hash": block.block_hash().to_string(),
            "hex": serialize_hex(&block),
        }));
    }
    let hashes = miner
        .generate_to_script(1, script, extra)
        .map_err(|e| generateblock_validity_error(&e))?;
    let hash = hashes
        .first()
        .ok_or_else(|| rpc_error(ERR_MISC, "generateblock produced no block"))?;
    Ok(json!({ "hash": hash.to_string() }))
}

/// Core `generateblock` after `TestBlockValidity`: `-25 TestBlockValidity failed: <reason>`.
/// Core `generateblock` after `TestBlockValidity`: `-25 TestBlockValidity failed: <reason>`.
pub(crate) fn generateblock_validity_error(e: &str) -> Value {
    let s = e.strip_prefix("consensus: ").unwrap_or(e);
    let s = s.strip_prefix("protocol: ").unwrap_or(s);
    for needle in [
        "bad-txns-inputs-missingorspent",
        "bad-txns-duplicate",
        "bad-txns-nonfinal",
        "bad-txns-in-belowout",
        "bad-cb-missing",
        "bad-blk-length",
        "bad-diffbits",
        "time-too-old",
        "time-too-new",
        "bad-txnmrklroot",
    ] {
        if s.contains(needle) {
            return rpc_error(
                ERR_VERIFY_ERROR,
                format!("TestBlockValidity failed: {needle}"),
            );
        }
    }
    rpc_error(ERR_VERIFY_ERROR, format!("TestBlockValidity failed: {s}"))
}

/// Core `generateblock` output: descriptor first, then address (not bare hex).
/// Core `generateblock` output: descriptor first, then address (not bare hex).
pub(crate) fn parse_generateblock_output(
    ctx: &RpcContext,
    output: &str,
) -> Result<ScriptBuf, Value> {
    let invalid = || {
        rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
            "Error: Invalid address or descriptor",
        )
    };
    if output.contains('(') {
        if output.contains("/*") {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?",
            ));
        }
        if let Some(s) = parse_raw_descriptor(output) {
            return Ok(s);
        }
        if let Some(s) = parse_addr_descriptor(ctx, output) {
            return Ok(s);
        }
        if let Some(s) = parse_combo_descriptor(ctx, output) {
            return Ok(s);
        }
        if let Some(s) = parse_wrapped_multi(output) {
            return Ok(s);
        }
        let has_xpub = output.contains("tpub")
            || output.contains("xpub")
            || output.contains("tprv")
            || output.contains("xprv");
        if has_xpub && (output.contains('\'') || output.contains("h/") || output.contains("h)")) {
            return Err(rpc_error(
                ERR_INVALID_ADDRESS_OR_KEY,
                "Cannot derive script without private keys",
            ));
        }
        return Err(invalid());
    }
    let btc_net = rpc_btc_network(ctx.network);
    if let Ok(a) = output.parse::<Address<_>>() {
        if let Ok(addr) = a.require_network(btc_net) {
            return Ok(addr.script_pubkey());
        }
    }
    Err(invalid())
}

const GENERATE_REPLACED: &str =
    "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n";

pub(crate) fn generate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "maxtries"])?;
    if params.get(0, "nblocks").is_none() {
        return Err(rpc_error(ERR_METHOD_NOT_FOUND, GENERATE_REPLACED));
    }
    let _miner = require_regtest_miner(ctx, "generate")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let _maxtries = params.opt_u64(1, "maxtries")?;
    let script = ScriptBuf::from_bytes(vec![0x51]);
    generate_with_mempool(ctx, nblocks, script)
}

pub(crate) fn generatetodescriptor(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["num_blocks", "descriptor", "maxtries"])?;
    let _miner = require_regtest_miner(ctx, "generatetodescriptor")?;
    let nblocks = params.req_u64(0, "num_blocks")? as u32;
    let desc = params.req_str(1, "descriptor")?;
    let _maxtries = params.opt_u64(2, "maxtries")?;
    let script = parse_output_descriptor(ctx, desc)?;
    generate_with_mempool(ctx, nblocks, script)
}

/// MiniWallet uses `raw(HEX)#checksum`. Not a full descriptor language.
/// MiniWallet uses `raw(HEX)#checksum`. Not a full descriptor language.
pub(crate) fn parse_raw_descriptor(desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("raw(")?.strip_suffix(")")?;
    let bytes = hex_decode(inner).ok()?;
    Some(ScriptBuf::from_bytes(bytes))
}

/// `addr(bech32)#checksum` — same script as the bare address.
/// `addr(bech32)#checksum` — same script as the bare address.
pub(crate) fn parse_addr_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("addr(")?.strip_suffix(")")?;
    decode_output_script(ctx, inner).ok()
}

/// Core `combo(pubkey)` for `generateblock`: compressed → P2WPKH, else P2PKH.
/// Core `combo(pubkey)` for `generateblock`: compressed → P2WPKH, else P2PKH.
pub(crate) fn parse_combo_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
    use bitcoin::key::CompressedPublicKey;
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("combo(")?.strip_suffix(")")?;
    let pk = PublicKey::from_str(inner).ok()?;
    let btc_net = rpc_btc_network(ctx.network);
    let spk = if pk.compressed {
        let cpk = CompressedPublicKey(pk.inner);
        Address::p2wpkh(&cpk, btc_net).script_pubkey()
    } else {
        Address::p2pkh(pk, btc_net).script_pubkey()
    };
    Some(spk)
}

/// `sh(multi(...))` / `wsh(multi(...))` / `sh(wsh(multi(...)))` → scriptPubKey.
/// `sh(multi(...))` / `wsh(multi(...))` / `sh(wsh(multi(...)))` → scriptPubKey.
pub(crate) fn parse_wrapped_multi(desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let (wrap_sh, wrap_wsh, inner) = if let Some(rest) = bare.strip_prefix("sh(wsh(") {
        (true, true, rest.strip_suffix("))")?)
    } else if let Some(rest) = bare.strip_prefix("sh(") {
        (true, false, rest.strip_suffix(")")?)
    } else if let Some(rest) = bare.strip_prefix("wsh(") {
        (false, true, rest.strip_suffix(")")?)
    } else {
        return None;
    };
    let multi = inner.strip_prefix("multi(")?.strip_suffix(")")?;
    let mut parts = multi.split(',');
    let nrequired: usize = parts.next()?.parse().ok()?;
    let mut pks = Vec::new();
    for p in parts {
        pks.push(PublicKey::from_str(p).ok()?);
    }
    let mut b = Builder::new().push_int(nrequired as i64);
    for pk in &pks {
        b = b.push_key(pk);
    }
    let redeem = b
        .push_int(pks.len() as i64)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let spk = if wrap_sh && wrap_wsh {
        redeem.as_script().to_p2wsh().as_script().to_p2sh()
    } else if wrap_sh {
        redeem.as_script().to_p2sh()
    } else {
        redeem.as_script().to_p2wsh()
    };
    Some(spk)
}

pub(crate) fn parse_output_descriptor(ctx: &RpcContext, desc: &str) -> Result<ScriptBuf, Value> {
    if let Some(s) = parse_raw_descriptor(desc) {
        return Ok(s);
    }
    if let Some(s) = parse_addr_descriptor(ctx, desc) {
        return Ok(s);
    }
    if let Some(s) = parse_combo_descriptor(ctx, desc) {
        return Ok(s);
    }
    if let Some(s) = parse_wrapped_multi(desc) {
        return Ok(s);
    }
    decode_output_script(ctx, desc)
}

/// Enough of Core `scantxoutset` for MiniWallet: `raw(script)` over Class A.
/// Not a coins-DB product (no HD range / combo / addr expansion).
pub(crate) fn mockscheduler(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["delta_seconds"])?;
    require_regtest(ctx, "mockscheduler")?;
    let delta = params.req_u64(0, "delta_seconds")?;
    if delta > 0 {
        if let Some(mp) = ctx.mempool.as_ref() {
            mp.rebroadcast_unbroadcast();
        }
    }
    Ok(Value::Null)
}

pub(crate) fn setmocktime(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timestamp"])?;
    require_regtest(ctx, "setmocktime")?;
    let miner = require_regtest_miner(ctx, "setmocktime")?;
    let raw = params.req(0, "timestamp")?;
    let ts = mocktime_i64(raw)?;
    miner
        .set_mock_time(ts)
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    if let Some(peers) = ctx.peers.as_ref() {
        peers.set_mock_now(ts as u64);
    }
    if let Some(mp) = ctx.mempool.as_ref() {
        mp.note_mock_now(ts as u64);
    }
    Ok(Value::Null)
}

pub(crate) fn mocktime_i64(v: &Value) -> Result<i64, Value> {
    let n = match v {
        Value::Number(n) => n,
        _ => {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                "timestamp must be an integer",
            ));
        }
    };
    let i = n
        .as_i64()
        .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()));
    let Some(i) = i else {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "timestamp must be an integer",
        ));
    };
    if !(0..=9_223_372_036).contains(&i) {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Mocktime must be in the range [0, 9223372036], not {i}."),
        ));
    }
    Ok(i)
}

/// Core `VERSIONBITS_TOP_BITS`. No testdummy bit.
const GBT_VERSION: i32 = 0x2000_0000;

pub(crate) fn gbt_rules(req: Option<&Value>) -> Result<Vec<String>, Value> {
    let Some(obj) = req.and_then(Value::as_object) else {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        ));
    };
    let rules = obj.get("rules").and_then(Value::as_array).ok_or_else(|| {
        rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        )
    })?;
    let names: Vec<String> = rules
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    if !names.iter().any(|r| r == "segwit") {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            "getblocktemplate must be called with the segwit rule set",
        ));
    }
    Ok(names)
}

pub(crate) fn getblocktemplate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["template_request"])?;
    let req = params.get(0, "template_request");
    let _rules = gbt_rules(req)?;
    let mode = req
        .and_then(Value::as_object)
        .and_then(|o| o.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("template");
    match mode {
        "template" | "" => {
            if let Some(lp) = req
                .and_then(Value::as_object)
                .and_then(|o| o.get("longpollid"))
                .and_then(Value::as_str)
            {
                gbt_longpoll_wait(ctx, lp);
            }
            gbt_template(ctx)
        }
        "proposal" => gbt_proposal(ctx, req),
        other => Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Invalid mode: {other}"),
        )),
    }
}

/// Core GBT longpoll: block while `longpollid` still matches the live tip +
/// mempool update counter. Tip change (P2P / generate) wakes within one poll
/// tick. A new mempool tx or `prioritisetransaction` does too.
/// Core GBT longpoll: block while `longpollid` still matches the live tip +
/// mempool update counter. Tip change (P2P / generate) wakes within one poll
/// tick. A new mempool tx or `prioritisetransaction` does too.
pub(crate) fn gbt_longpoll_wait(ctx: &RpcContext, want: &str) {
    const TICK: std::time::Duration = std::time::Duration::from_millis(50);
    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }
        if gbt_longpoll_id(ctx) != want {
            return;
        }
        std::thread::sleep(TICK);
    }
}

pub(crate) fn gbt_longpoll_id(ctx: &RpcContext) -> String {
    let tip = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let updates = ctx
        .mempool
        .as_ref()
        .map(|m| m.template_updates())
        .unwrap_or(0);
    format!("{tip}{updates}")
}

pub(crate) fn gbt_template(ctx: &RpcContext) -> Result<Value, Value> {
    let tip_h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let next_h = tip_h.saturating_add(1);
    let (prev_hex, tip_time, tip_bits) = if let Some(h) = ctx.query.tip_height() {
        let (_, rec) = ctx
            .query
            .header_at_height(h)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
        (hash_hex_display(&rec.hash), rec.timestamp, rec.bits)
    } else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let params = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| match ctx.network {
            Network::Regtest => rbitcoin_consensus::ChainParams::regtest(),
            Network::Signet => rbitcoin_consensus::ChainParams::signet(),
            Network::Testnet => rbitcoin_consensus::ChainParams::testnet(),
            Network::Mainnet => rbitcoin_consensus::ChainParams::mainnet(),
        });
    let now = ctx
        .chain
        .as_ref()
        .map(|c| c.clock.now_secs() as u32)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        });
    let curtime = tip_time.saturating_add(1).max(now);
    let bits = rbitcoin_consensus::expected_next_bits(
        ctx.query.as_ref(),
        &params,
        Height(next_h),
        curtime,
    )
    .map(|c| c.to_consensus())
    .unwrap_or(tip_bits);
    let mintime = if tip_h == 0 {
        tip_time
    } else {
        rbitcoin_consensus::median_time_past(ctx.query.as_ref(), Height(tip_h)).unwrap_or(tip_time)
    };
    let selected = mempool_block_txs(ctx);
    let mut fees = 0u64;
    let mut tx_json = Vec::with_capacity(selected.len());
    let ids: Vec<Txid> = selected.iter().map(Transaction::compute_txid).collect();
    for (i, tx) in selected.iter().enumerate() {
        let txid = ids[i];
        let fee = ctx
            .mempool
            .as_ref()
            .and_then(|mp| mp.get_live_meta(&txid))
            .map(|(f, _)| f)
            .unwrap_or(0);
        fees = fees.saturating_add(fee);
        let mut depends = Vec::new();
        for inp in &tx.input {
            if let Some(pos) = ids.iter().position(|t| *t == inp.previous_output.txid) {
                depends.push(pos as u64 + 1);
            }
        }
        tx_json.push(json!({
            "data": serialize_hex(tx),
            "txid": txid.to_string(),
            "hash": tx.compute_wtxid().to_string(),
            "depends": depends,
            "fee": fee,
            "sigops": rbitcoin_consensus::tx_gbt_sigops(tx),
            "weight": tx.weight().to_wu(),
        }));
    }
    let subsidy = rbitcoin_consensus::block_subsidy(next_h, &params) as u64;
    let longpollid = gbt_longpoll_id(ctx);
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    if let Some(c) = ctx.chain.as_ref() {
        c.note_gbt_assembled();
    }
    let wtxids: Vec<[u8; 32]> = selected
        .iter()
        .map(|tx| tx.compute_wtxid().to_byte_array())
        .collect();
    let witness_commit = rbitcoin_consensus::witness_commitment_script(wtxids, &[0u8; 32]);
    Ok(json!({
        "capabilities": ["proposal"],
        "version": ctx
            .chain
            .as_ref()
            .map(|c| c.gbt_block_version())
            .unwrap_or(GBT_VERSION | (1 << 28)),
        "previousblockhash": prev_hex,
        "transactions": tx_json,
        "coinbaseaux": { "flags": "" },
        "coinbasevalue": subsidy.saturating_add(fees),
        "longpollid": longpollid,
        "target": format!("{target:064x}"),
        "mintime": mintime,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80_000,
        "sizelimit": 4_000_000,
        "weightlimit": 4_000_000,
        "curtime": curtime,
        "bits": format!("{bits:08x}"),
        "height": next_h,
        "rules": ["segwit"],
        "default_witness_commitment": hex_encode(witness_commit),
    }))
}

pub(crate) fn gbt_proposal(ctx: &RpcContext, req: Option<&Value>) -> Result<Value, Value> {
    let data = req
        .and_then(Value::as_object)
        .and_then(|o| o.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let raw =
        hex_decode(data).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let block: Block =
        deserialize(&raw).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    match gbt_check_proposal(ctx, &block) {
        Ok(()) => Ok(Value::Null),
        Err(s) => Ok(json!(s)),
    }
}

/// Core `TestBlockValidity` for GBT proposal: no PoW, no UTXO write.
/// Core `TestBlockValidity` for GBT proposal: no PoW, no UTXO write.
pub(crate) fn gbt_check_proposal(ctx: &RpcContext, block: &Block) -> Result<(), String> {
    let tip_h = ctx.query.tip_height().ok_or("no tip")?;
    let (_, tip_rec) = ctx
        .query
        .header_at_height(tip_h)
        .map_err(|e| e.to_string())?
        .ok_or("tip header missing")?;
    if block.header.prev_blockhash.to_byte_array() != tip_rec.hash {
        return Err("inconclusive-not-best-prevblk".into());
    }
    let height = tip_h.0.saturating_add(1);
    let params = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| match ctx.network {
            Network::Regtest => rbitcoin_consensus::ChainParams::regtest(),
            Network::Signet => rbitcoin_consensus::ChainParams::signet(),
            Network::Testnet => rbitcoin_consensus::ChainParams::testnet(),
            Network::Mainnet => rbitcoin_consensus::ChainParams::mainnet(),
        });
    let expected = rbitcoin_consensus::expected_next_bits(
        ctx.query.as_ref(),
        &params,
        Height(height),
        block.header.time,
    )
    .map(|c| c.to_consensus())
    .unwrap_or(tip_rec.bits);
    if block.header.bits.to_consensus() != expected {
        return Err("bad-diffbits".into());
    }
    let mtp = rbitcoin_consensus::median_time_past(ctx.query.as_ref(), tip_h)
        .unwrap_or(tip_rec.timestamp);
    // Core is `<=` MTP. Proposal uses `<` so a template stamped at the
    // parent's mediantime+1 still validates after that parent is submitted
    // (new MTP often equals that stamp on an incrementing cache).
    if block.header.time < mtp {
        return Err("time-too-old".into());
    }
    let now = ctx
        .chain
        .as_ref()
        .map(|c| c.clock.now_secs() as u32)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        });
    if u64::from(block.header.time) > u64::from(now).saturating_add(2 * 60 * 60) {
        return Err("time-too-new".into());
    }
    let milestone = ctx
        .chain
        .as_ref()
        .map(|c| c.milestone)
        .unwrap_or(rbitcoin_consensus::Milestone::NONE);
    // Spends before txid-uniqueness: two copies of the same non-coinbase
    // tx are `bad-txns-inputs-missingorspent` (Core CheckBlock order).
    gbt_proposal_connect(ctx, block, height, mtp)?;
    let mut seen = std::collections::HashSet::new();
    for tx in &block.txdata {
        if !seen.insert(tx.compute_txid()) {
            return Err("bad-txns-duplicate".into());
        }
    }
    let vctx = rbitcoin_consensus::ValidationContext::at(&params, Height(height), milestone);
    if let Err(e) = rbitcoin_consensus::validate_block_structure(block, &vctx) {
        return Err(rbitcoin_consensus::block_reject_reason(&e));
    }
    Ok(())
}

pub(crate) fn gbt_proposal_connect(
    ctx: &RpcContext,
    block: &Block,
    height: u32,
    mtp: u32,
) -> Result<(), String> {
    if block.txdata.is_empty() {
        return Err("bad-blk-length".into());
    }
    if !block.txdata[0].is_coinbase() {
        return Err("bad-cb-missing".into());
    }
    let mut created: std::collections::HashMap<OutPoint, bitcoin::TxOut> =
        std::collections::HashMap::new();
    let mut spent: std::collections::HashSet<OutPoint> = std::collections::HashSet::new();
    for tx in block.txdata.iter() {
        if !rbitcoin_consensus::is_final_tx(tx, height, mtp.max(block.header.time)) {
            return Err("bad-txns-nonfinal".into());
        }
        if tx.is_coinbase() {
            let tid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid: tid,
                        vout: vout as u32,
                    },
                    o.clone(),
                );
            }
            continue;
        }
        let mut in_val = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Err("bad-txns-inputs-missingorspent".into());
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else if let Some(o) = gbt_chain_txout(ctx, &op) {
                o
            } else {
                return Err("bad-txns-inputs-missingorspent".into());
            };
            in_val = in_val.saturating_add(txout.value.to_sat());
        }
        let out_val: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_val > in_val {
            return Err("bad-txns-in-belowout".into());
        }
        let tid = tx.compute_txid();
        for (vout, o) in tx.output.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid: tid,
                    vout: vout as u32,
                },
                o.clone(),
            );
        }
    }
    Ok(())
}

pub(crate) fn gbt_chain_txout(ctx: &RpcContext, op: &OutPoint) -> Option<bitcoin::TxOut> {
    let tid = op.txid.to_byte_array();
    if ctx.query.is_outpoint_spent(&tid, op.vout).ok()? {
        return None;
    }
    let (fk, rec) = ctx.query.get_tx_by_txid(&tid).ok().flatten()?;
    let out = ctx
        .query
        .tx_output_at_fk(fk, op.vout)
        .ok()
        .or_else(|| ctx.query.tx_output(&rec, op.vout).ok())?;
    let value = if out.value < 0 {
        Amount::ZERO
    } else {
        Amount::from_sat(out.value as u64)
    };
    Some(bitcoin::TxOut {
        value,
        script_pubkey: ScriptBuf::from_bytes(out.script),
    })
}

/// Tip height, difficulty, pooledtx, and `blockmintxfee` (BTC/kvB, `sat_btc_json`).
pub(crate) fn getmininginfo(ctx: &RpcContext) -> Result<Value, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let pooledtx = ctx
        .mempool
        .as_ref()
        .map(|m| m.list_live_meta().len())
        .unwrap_or(0);
    let bits = tip_bits(ctx).unwrap_or(0x207f_ffff);
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    let difficulty = difficulty_from_bits(bits);
    let mut m = serde_json::Map::new();
    m.insert("blocks".into(), json!(tip));
    if ctx.chain.as_ref().is_some_and(|c| c.gbt_assembled()) {
        m.insert("currentblockweight".into(), json!(8_000));
        m.insert("currentblocktx".into(), json!(0));
    }
    m.insert("difficulty".into(), json!(difficulty));
    m.insert(
        "networkhashps".into(),
        json!(network_hash_ps(ctx, 120, -1).unwrap_or(0.0)),
    );
    m.insert("pooledtx".into(), json!(pooledtx));
    let min_sat = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    m.insert("blockmintxfee".into(), sat_btc_json(min_sat as i64));
    m.insert("chain".into(), json!(chain_name(ctx.network)));
    m.insert("bits".into(), json!(format!("{bits:08x}")));
    m.insert("target".into(), json!(format!("{target:064x}")));
    m.insert(
        "next".into(),
        json!({
            "height": tip.saturating_add(1),
            "bits": format!("{bits:08x}"),
            "target": format!("{target:064x}"),
            "difficulty": difficulty,
        }),
    );
    m.insert("warnings".into(), json!(rpc_warnings(ctx)));
    Ok(Value::Object(m))
}

pub(crate) fn tip_bits(ctx: &RpcContext) -> Option<u32> {
    let tip = ctx.query.tip_height()?;
    let (_, rec) = ctx.query.header_at_height(tip).ok().flatten()?;
    Some(rec.bits)
}

pub(crate) fn getnetworkhashps(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "height"])?;
    let nblocks = params.opt_u64(0, "nblocks")?.unwrap_or(120) as i64;
    let height = match params.get(1, "height") {
        None | Some(Value::Null) => -1,
        Some(v) => {
            json_i64(v).ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "height must be an integer"))?
        }
    };
    Ok(json!(network_hash_ps(ctx, nblocks, height)?))
}

pub(crate) fn network_hash_ps(ctx: &RpcContext, nblocks: i64, height: i64) -> Result<f64, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    if tip == 0 {
        return Ok(0.0);
    }
    let end = if height < 0 || height as u32 > tip {
        tip
    } else {
        height as u32
    };
    let n = if nblocks <= 0 { 120u32 } else { nblocks as u32 };
    let start = end.saturating_sub(n);
    let t0 = header_time(ctx, start).unwrap_or(0);
    let t1 = header_time(ctx, end).unwrap_or(t0);
    let dt = t1.saturating_sub(t0).max(1) as f64;
    let work = f64::from(end.saturating_sub(start).saturating_mul(2));
    Ok(work / dt)
}

pub(crate) fn header_time(ctx: &RpcContext, h: u32) -> Option<u32> {
    let (_, rec) = ctx
        .query
        .header_at_height(rbitcoin_primitives::Height(h))
        .ok()
        .flatten()?;
    Some(rec.timestamp)
}

/// Same receive path as P2P `block` (all networks).
pub fn submit_received_block(hub: &rbitcoin_net::ChainHub, block: Block) -> SubmitBlockOutcome {
    use bitcoin::Target;
    use rbitcoin_net::AcceptOutcome;
    let hash = block.block_hash();
    if hub.is_block_invalid(&hash) {
        return SubmitBlockOutcome::Rejected("duplicate-invalid".into());
    }
    let target = Target::from_compact(block.header.bits);
    if block.header.validate_pow(target).is_err() {
        return SubmitBlockOutcome::Rejected("high-hash".into());
    }
    let prev = block.header.prev_blockhash.to_byte_array();
    let known = hub.query.get_header_by_hash(&prev).ok().flatten().is_some()
        || hub
            .held_body(&bitcoin::BlockHash::from_byte_array(prev))
            .is_some();
    if !known {
        return SubmitBlockOutcome::Rejected("prev-blk-not-found".into());
    }
    if let Some(reason) = cheap_submit_tx_reject(hub.query.as_ref(), &block) {
        return SubmitBlockOutcome::Rejected(reason);
    }
    match hub.accept_received_block(block.clone()) {
        Ok(AcceptOutcome::Accepted { .. }) => SubmitBlockOutcome::Accepted,
        Ok(AcceptOutcome::AlreadyHave) => SubmitBlockOutcome::Duplicate,
        Ok(AcceptOutcome::IgnoredWeaker) => SubmitBlockOutcome::IgnoredWeaker,
        Err(e) => {
            let reason = submit_reject_reason(&e);
            if reason != "bad-txnmrklroot"
                && reason != "high-hash"
                && reason != "prev-blk-not-found"
            {
                hub.note_invalid_block(hash);
                let _ = hub.ensure_header(&block.header);
            }
            SubmitBlockOutcome::Rejected(reason)
        }
    }
}

fn cheap_submit_tx_reject(query: &rbitcoin_query::Query, block: &Block) -> Option<String> {
    use bitcoin::{Amount, OutPoint, TxOut};
    if block.txdata.is_empty() {
        return Some("bad-blk-length".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut spent = std::collections::HashSet::new();
    let mut created: std::collections::HashMap<OutPoint, TxOut> = std::collections::HashMap::new();
    for (i, tx) in block.txdata.iter().enumerate() {
        if !seen.insert(tx.compute_txid()) {
            return Some("bad-txns-duplicate".into());
        }
        if i == 0 {
            if !tx.is_coinbase() {
                return Some("bad-cb-missing".into());
            }
            let tid = tx.compute_txid();
            for (v, o) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid: tid,
                        vout: v as u32,
                    },
                    o.clone(),
                );
            }
            continue;
        }
        let mut in_val = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Some("bad-txns-inputs-missingorspent".into());
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else {
                let tid = op.txid.to_byte_array();
                if query.is_outpoint_spent(&tid, op.vout).ok().unwrap_or(true) {
                    return Some("bad-txns-inputs-missingorspent".into());
                }
                let Some((fk, rec)) = query.get_tx_by_txid(&tid).ok().flatten() else {
                    return Some("bad-txns-inputs-missingorspent".into());
                };
                let Some(out) = query
                    .tx_output_at_fk(fk, op.vout)
                    .ok()
                    .or_else(|| query.tx_output(&rec, op.vout).ok())
                else {
                    return Some("bad-txns-inputs-missingorspent".into());
                };
                let value = if out.value < 0 {
                    Amount::ZERO
                } else {
                    Amount::from_sat(out.value as u64)
                };
                TxOut {
                    value,
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(out.script),
                }
            };
            in_val = in_val.saturating_add(txout.value.to_sat());
        }
        let out_val: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_val > in_val {
            return Some("bad-txns-in-belowout".into());
        }
        let tid = tx.compute_txid();
        for (v, o) in tx.output.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid: tid,
                    vout: v as u32,
                },
                o.clone(),
            );
        }
    }
    None
}

fn submit_reject_reason(e: &rbitcoin_net::NetError) -> String {
    if matches!(e, rbitcoin_net::NetError::UnknownParent) {
        return "prev-blk-not-found".into();
    }
    let s = e.to_string();
    let s = s.strip_prefix("consensus: ").unwrap_or(s.as_str());
    let s = s.strip_prefix("protocol: ").unwrap_or(s);
    if s.contains("unknown parent") || s.contains("BadPrev") || s.contains("unexpected previous") {
        return "prev-blk-not-found".into();
    }
    if s.contains("pow invalid") || s.contains("InvalidPow") || s.contains("high-hash") {
        return "high-hash".into();
    }
    for needle in [
        "bad-txns-nonfinal",
        "bad-txns-duplicate",
        "bad-txns-inputs-missingorspent",
        "bad-txns-in-belowout",
        "bad-cb-missing",
        "bad-blk-length",
        "bad-diffbits",
        "time-too-old",
        "time-too-new",
        "bad-txnmrklroot",
    ] {
        if s.contains(needle) {
            return needle.into();
        }
    }
    s.to_string()
}

pub(crate) fn submitblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata", "dummy"])?;
    let hex = params.req_str(0, "hexdata")?;
    let raw = hex_decode(hex).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let block: Block =
        deserialize(&raw).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let outcome = if let Some(chain) = ctx.chain.as_ref() {
        submit_received_block(chain, block)
    } else if let Some(miner) = ctx.regtest.as_deref() {
        miner.submit_block(block)
    } else {
        return Err(rpc_error(ERR_MISC, "submitblock requires a live chain hub"));
    };
    match outcome {
        SubmitBlockOutcome::Accepted => Ok(Value::Null),
        SubmitBlockOutcome::Duplicate => Ok(json!("duplicate")),
        SubmitBlockOutcome::IgnoredWeaker => Ok(json!("inconclusive")),
        SubmitBlockOutcome::Rejected(reason) => Ok(json!(reason)),
    }
}

pub(crate) fn decode_tx_hex(hex: &str) -> Result<Transaction, Value> {
    let b = hex_decode(hex).map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    deserialize(&b).map_err(|e| rpc_error(ERR_INVALID_PARAMS, format!("tx decode: {e}")))
}

pub(crate) fn tx_to_json(tx: &Transaction, extra: Option<Value>, network: BtcNetwork) -> Value {
    let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
    let mut vin = Vec::new();
    for (i, inp) in tx.input.iter().enumerate() {
        let mut row = json!({
            "txid": hash_hex_display(&inp.previous_output.txid.to_byte_array()),
            "vout": inp.previous_output.vout,
            "scriptSig": {
                "asm": inp.script_sig.to_asm_string(),
                "hex": hex_encode(inp.script_sig.as_bytes()),
            },
            "sequence": inp.sequence.to_consensus_u32(),
            "n": i,
        });
        if !inp.witness.is_empty() {
            let stack: Vec<String> = inp.witness.iter().map(hex_encode).collect();
            if let Some(m) = row.as_object_mut() {
                m.insert("txinwitness".into(), json!(stack));
            }
        }
        vin.push(row);
    }
    let mut vout = Vec::new();
    for (i, out) in tx.output.iter().enumerate() {
        vout.push(json!({
            "value": out.value.to_btc(),
            "n": i,
            "scriptPubKey": script_pubkey_json(&out.script_pubkey, network),
        }));
    }
    let mut obj = json!({
        "txid": txid,
        "hash": hash_hex_display(&tx.compute_wtxid().to_byte_array()),
        "version": tx.version.0,
        "size": tx.total_size(),
        "vsize": tx.vsize(),
        "weight": tx.weight().to_wu(),
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": serialize_hex(tx),
    });
    if let Some(Value::Object(m)) = extra {
        if let Some(o) = obj.as_object_mut() {
            for (k, v) in m {
                o.insert(k, v);
            }
        }
    }
    obj
}
