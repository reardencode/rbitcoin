use super::descriptor::{bare_multisig, infer_descriptor, p2pk_key};
use super::*;
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::key::PublicKey;
use bitcoin::script::Builder;
use bitcoin::{Address, Block, BlockHash, Network as BtcNetwork, ScriptBuf, Transaction, Txid};
use rbitcoin_net::Selected;
use rbitcoin_primitives::{Height, Network};
use rbitcoin_query::ThresholdState;

use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn require_regtest(ctx: &RpcContext, method: &str) -> Result<(), Value> {
    if ctx.network != Network::Regtest {
        return Err(rpc_error(ERR_MISC, format!("{method} is regtest only")));
    }
    Ok(())
}

/// Regtest, or signet whose challenge is exactly `OP_TRUE` (mine-on-demand).
#[doc(hidden)]
pub fn allow_local_miner(ctx: &RpcContext) -> bool {
    if ctx.network == Network::Regtest {
        return true;
    }
    ctx.network == Network::Signet
        && ctx.chain.as_ref().is_some_and(|c| {
            c.params
                .signet_challenge
                .as_ref()
                .is_some_and(|s| s.as_bytes() == [rbitcoin_primitives::OP_TRUE])
        })
}

pub fn require_regtest_miner<'a>(
    ctx: &'a RpcContext,
    method: &str,
) -> Result<&'a dyn RpcRegtest, Value> {
    if !allow_local_miner(ctx) {
        return Err(rpc_error(ERR_MISC, format!("{method} is regtest only")));
    }
    ctx.regtest
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, format!("{method} requires a live chain hub")))
}

pub fn rpc_btc_network(n: Network) -> BtcNetwork {
    match n {
        Network::Mainnet => BtcNetwork::Bitcoin,
        Network::Testnet => BtcNetwork::Testnet,
        Network::Signet => BtcNetwork::Signet,
        Network::Regtest => BtcNetwork::Regtest,
    }
}

pub fn script_pubkey_json(script: &ScriptBuf, network: BtcNetwork) -> Value {
    let mut obj = json!({
        "hex": rbitcoin_primitives::hex_encode(script.as_bytes() ),
        "asm": script.to_asm_string(),
        "type": script_core_type(script),
        "desc": infer_descriptor(script, network),
    });
    if let Ok(addr) = Address::from_script(script, network) {
        if let Some(m) = obj.as_object_mut() {
            m.insert("address".into(), json!(addr.to_string()));
        }
    }
    obj
}

/// Core `decoderawtransaction` / `decodescript` `type` strings.
pub fn script_core_type(script: &bitcoin::Script) -> &'static str {
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
    } else if let Some(version) = script.witness_version() {
        if version == bitcoin::WitnessVersion::V0 {
            "nonstandard"
        } else {
            "witness_unknown"
        }
    } else if script.is_op_return()
        && bitcoin::Script::from_bytes(&script.as_bytes()[1..]).is_push_only()
    {
        "nulldata"
    } else if p2pk_key(script).is_some() {
        "pubkey"
    } else if bare_multisig(script).is_some() {
        "multisig"
    } else {
        "nonstandard"
    }
}

#[doc(hidden)]
pub fn is_p2anchor(script: &bitcoin::Script) -> bool {
    let b = script.as_bytes();
    b == rbitcoin_primitives::P2A_SCRIPT
}

pub fn decode_output_script(ctx: &RpcContext, s: &str) -> Result<ScriptBuf, Value> {
    let btc_net = rpc_btc_network(ctx.network);
    if let Ok(a) = s.parse::<Address<_>>() {
        match a.require_network(btc_net) {
            Ok(addr) => return Ok(addr.script_pubkey()),
            Err(_) => {
                return Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Invalid address"));
            }
        }
    }
    let bytes = rbitcoin_primitives::hex_decode(s).map_err(|e| {
        rpc_error(
            ERR_INVALID_PARAMS,
            format!("output must be an address or hex script: {e}"),
        )
    })?;
    Ok(ScriptBuf::from_bytes(bytes))
}

pub fn hashes_json(hashes: &[BlockHash]) -> Value {
    json!(hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>())
}

pub fn mempool_block_txs(ctx: &RpcContext) -> Vec<(Arc<Transaction>, Selected)> {
    let min = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    ctx.mempool
        .as_ref()
        .map(|mp| mp.select_block_template(mp.template_budget(min)))
        .unwrap_or_default()
}

pub fn generate_with_mempool(
    ctx: &RpcContext,
    nblocks: u32,
    script: ScriptBuf,
) -> Result<Value, Value> {
    let miner = require_regtest_miner(ctx, "generate")?;
    if nblocks == 0 {
        return Ok(hashes_json(&[]));
    }
    let listing = ctx.pool_listing();
    // Catch-up leaves confirmed transactions in the pool, so mine the coinbase
    // only. Any other listing is removed when the block that contains it is
    // accepted, including while relay is off, and before a later block of this
    // call is mined. A refusal before that block leaves the pool as it was.
    let extras = if matches!(listing, PoolListing::Downloading) {
        Vec::new()
    } else {
        let min = ctx
            .chain
            .as_ref()
            .map(|c| c.block_min_tx_fee_sat_kvb())
            .unwrap_or(1);
        ctx.mempool
            .as_ref()
            .map(|mp| mp.select_generate_txs(min))
            .unwrap_or_default()
    };
    let hashes = miner
        .generate_to_script(nblocks, script, extras, true)
        .map_err(|e| rpc_error(ERR_MISC, e))?;
    Ok(hashes_json(&hashes))
}

pub fn generatetoaddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "address", "maxtries"])?;
    let _miner = require_regtest_miner(ctx, "generatetoaddress")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let addr = params.req_str(1, "address")?;
    let _maxtries = params.opt_u64(2, "maxtries")?;
    let script = decode_output_script(ctx, addr)?;
    generate_with_mempool(ctx, nblocks, script)
}

pub fn generateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
    // Core assembles an empty block (`use_mempool = false`) before it adds
    // the given transactions.
    if let Some(c) = ctx.chain.as_ref() {
        c.note_block_assembled(0, 0);
    }
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
        .generate_to_script(1, script, extra.clone(), false)
        .map_err(|e| generateblock_missing_input_error(&e.to_string(), &extra))?;
    let hash = hashes
        .first()
        .ok_or_else(|| rpc_error(ERR_MISC, "generateblock produced no block"))?;
    Ok(json!({ "hash": hash.to_string() }))
}

/// Core `generateblock` after `TestBlockValidity`: `-25 TestBlockValidity failed: <reason>`.
///
/// A single submitted transaction whose inputs are not coins includes Core's
/// `CheckTxInputs` debug text (`feature_block.py`).
#[doc(hidden)]
pub fn generateblock_missing_input_error(e: &str, extra: &[Transaction]) -> Value {
    let s = e.strip_prefix("consensus: ").unwrap_or(e);
    if extra.len() == 1 && s.contains("bad-txns-inputs-missingorspent") {
        let txid = extra[0].compute_txid();
        return rpc_error(
            ERR_VERIFY_ERROR,
            format!(
                "TestBlockValidity failed: bad-txns-inputs-missingorspent, CheckTxInputs: inputs missing/spent in transaction {txid}"
            ),
        );
    }
    generateblock_validity_error(e)
}

/// Core `generateblock` after `TestBlockValidity`: `-25 TestBlockValidity failed: <reason>`.
pub fn generateblock_validity_error(e: &str) -> Value {
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
pub fn parse_generateblock_output(ctx: &RpcContext, output: &str) -> Result<ScriptBuf, Value> {
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

#[doc(hidden)]
pub const GENERATE_REPLACED: &str =
    "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n";

pub fn generate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "maxtries"])?;
    if params.get(0, "nblocks").is_none() {
        return Err(rpc_error(ERR_METHOD_NOT_FOUND, GENERATE_REPLACED));
    }
    let _miner = require_regtest_miner(ctx, "generate")?;
    let nblocks = params.req_u64(0, "nblocks")? as u32;
    let _maxtries = params.opt_u64(1, "maxtries")?;
    let script = ScriptBuf::from_bytes(vec![rbitcoin_primitives::OP_TRUE]);
    generate_with_mempool(ctx, nblocks, script)
}

pub fn generatetodescriptor(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
pub fn parse_raw_descriptor(desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("raw(")?.strip_suffix(")")?;
    let bytes = rbitcoin_primitives::hex_decode(inner).ok()?;
    Some(ScriptBuf::from_bytes(bytes))
}

/// `addr(bech32)#checksum` — same script as the bare address.
/// `addr(bech32)#checksum` — same script as the bare address.
pub fn parse_addr_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
    let bare = desc.split('#').next()?.trim();
    let inner = bare.strip_prefix("addr(")?.strip_suffix(")")?;
    decode_output_script(ctx, inner).ok()
}

/// Core `combo(pubkey)` for `generateblock`: compressed → P2WPKH, else P2PKH.
/// Core `combo(pubkey)` for `generateblock`: compressed → P2WPKH, else P2PKH.
pub fn parse_combo_descriptor(ctx: &RpcContext, desc: &str) -> Option<ScriptBuf> {
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
pub fn parse_wrapped_multi(desc: &str) -> Option<ScriptBuf> {
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

pub fn parse_output_descriptor(ctx: &RpcContext, desc: &str) -> Result<ScriptBuf, Value> {
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

pub fn mockscheduler(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn setmocktime(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn mocktime_i64(v: &Value) -> Result<i64, Value> {
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

const SEGWIT_RULE_REQUIRED: &str =
    r#"getblocktemplate must be called with the segwit rule set (call with {"rules": ["segwit"]})"#;
const SIGNET_RULE_REQUIRED: &str = r#"getblocktemplate must be called with the signet rule set (call with {"rules": ["segwit", "signet"]})"#;

/// Core `setClientRules`: a `rules` array of strings. Anything else is no rules.
fn gbt_client_rules(req: Option<&serde_json::Map<String, Value>>) -> Result<Vec<&str>, Value> {
    let Some(rules) = req.and_then(|o| o.get("rules")).and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    rules
        .iter()
        .map(|v| {
            v.as_str().ok_or_else(|| {
                rpc_error(
                    ERR_TYPE_ERROR,
                    format!(
                        "JSON value of type {} is not of expected type string",
                        json_type_name(v)
                    ),
                )
            })
        })
        .collect()
}

/// A `getblocktemplate` request after Core's checks that come before the
/// longpoll wait.
pub enum GbtRequest<'a> {
    Proposal(Option<&'a serde_json::Map<String, Value>>),
    Template {
        rules: Vec<&'a str>,
        longpoll: Option<LongpollWant>,
    },
}

pub fn gbt_request<'a>(ctx: &RpcContext, params: &'a RpcParams) -> Result<GbtRequest<'a>, Value> {
    refuse_unmaintained_template(ctx)?;
    params.reject_unknown(&["template_request"])?;
    let req = params.get(0, "template_request").and_then(Value::as_object);
    let invalid_mode = || rpc_error(ERR_INVALID_PARAMETER, "Invalid mode");
    let mode = match req.and_then(|o| o.get("mode")) {
        None | Some(Value::Null) => "template",
        Some(Value::String(m)) => m.as_str(),
        Some(_) => return Err(invalid_mode()),
    };
    if mode == "proposal" {
        return Ok(GbtRequest::Proposal(req));
    }
    let rules = gbt_client_rules(req)?;
    if mode != "template" {
        return Err(invalid_mode());
    }
    // An HTTP longpoll passed these before its wait. Core does not check
    // them again after the wait.
    if matches!(ctx.network, Network::Mainnet) && !super::http_wait_satisfied() {
        if super::net::connection_count(ctx) == 0 {
            return Err(rpc_error(
                ERR_CLIENT_NOT_CONNECTED,
                "Bitcoin Core is not connected!",
            ));
        }
        if super::chain::in_ibd(ctx) {
            return Err(rpc_error(
                ERR_CLIENT_IN_INITIAL_DOWNLOAD,
                "Bitcoin Core is in initial sync and waiting for blocks...",
            ));
        }
    }
    let longpoll = match req.and_then(|o| o.get("longpollid")) {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(LongpollWant::parse(id)?),
        // Core: a non-string id waits on the current tip and counter.
        Some(_) => Some(LongpollWant::current(ctx)),
    };
    Ok(GbtRequest::Template { rules, longpoll })
}

pub(crate) fn getblocktemplate(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    let (rules, longpoll) = match gbt_request(ctx, params)? {
        GbtRequest::Proposal(req) => return gbt_proposal(ctx, req),
        GbtRequest::Template { rules, longpoll } => (rules, longpoll),
    };
    if let Some(want) = longpoll {
        gbt_longpoll_wait(ctx, &want);
        if ctx.stop.load(Ordering::Relaxed) {
            return Err(rpc_error(ERR_CLIENT_NOT_CONNECTED, "Shutting down"));
        }
    }
    if gbt_params(ctx).signet_challenge.is_some() && !rules.contains(&"signet") {
        return Err(rpc_error(ERR_INVALID_PARAMETER, SIGNET_RULE_REQUIRED));
    }
    if !rules.contains(&"segwit") {
        return Err(rpc_error(ERR_INVALID_PARAMETER, SEGWIT_RULE_REQUIRED));
    }
    gbt_template(ctx)
}

/// Core BIP22 `longpollid`: the watched tip and mempool update counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongpollWant {
    /// Lowercase display hex. `None` while the template tip is stale.
    tip: Option<String>,
    updates: u32,
}

impl LongpollWant {
    /// Core `ParseHashV` on the first 64 bytes, `LocaleIndependentAtoi` on the rest.
    fn parse(id: &str) -> Result<Self, Value> {
        let bytes = id.as_bytes();
        let (head, rest) = bytes.split_at(bytes.len().min(64));
        let head_text = String::from_utf8_lossy(head);
        if head.len() != 64 {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!(
                    "longpollid must be of length 64 (not {}, for '{head_text}')",
                    head.len()
                ),
            ));
        }
        if !head.iter().all(u8::is_ascii_hexdigit) {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!("longpollid must be hexadecimal string (not '{head_text}')"),
            ));
        }
        Ok(Self {
            tip: Some(head_text.to_ascii_lowercase()),
            updates: locale_independent_atoi(rest) as u32,
        })
    }

    pub fn current(ctx: &RpcContext) -> Self {
        let updates = ctx
            .mempool
            .as_ref()
            .map(|m| m.template_updates() as u32)
            .unwrap_or(0);
        let tip = match gbt_tip(ctx) {
            Ok(GbtTip::Ready(_, hex, _)) => Some(hex),
            _ => None,
        };
        Self { tip, updates }
    }

    pub fn changed(&self, ctx: &RpcContext) -> bool {
        Self::current(ctx) != *self
    }
}

/// Core `LocaleIndependentAtoi<int64_t>`: leading whitespace, one `+` or
/// `-`, then digits up to the first non-digit. Saturates; no digits is 0.
fn locale_independent_atoi(s: &[u8]) -> i64 {
    let s = &s[s
        .iter()
        .take_while(|c| b" \x0c\n\r\t\x0b".contains(c))
        .count()..];
    let s = match s {
        [b'+', b'-', ..] => return 0,
        [b'+', rest @ ..] => rest,
        _ => s,
    };
    let (negative, digits) = match s {
        [b'-', rest @ ..] => (true, rest),
        _ => (false, s),
    };
    let mut v: i64 = 0;
    for d in digits.iter().take_while(|c| c.is_ascii_digit()) {
        let d = i64::from(d - b'0');
        let next = v.checked_mul(10).and_then(|v| {
            if negative {
                v.checked_sub(d)
            } else {
                v.checked_add(d)
            }
        });
        v = match next {
            Some(v) => v,
            None if negative => return i64::MIN,
            None => return i64::MAX,
        };
    }
    v
}

/// Core GBT longpoll: block while the watched tip and mempool update counter
/// still hold. Tip change (P2P / generate) wakes within one poll tick. A new
/// mempool tx or `prioritisetransaction` does too.
fn gbt_longpoll_wait(ctx: &RpcContext, want: &LongpollWant) {
    if super::http_wait_satisfied() {
        return;
    }
    super::block_on_rpc_wait(ctx, super::RPC_WAIT_TIMEOUT_MS, || {
        ctx.stop.load(Ordering::Relaxed) || want.changed(ctx)
    });
}

/// Where a template may build. The stripped tip wins. The query tip is only
/// a stand-in before any strip has been recorded.
enum GbtTip {
    /// `(height, display hash, bits)`.
    Ready(u32, String, u32),
    /// `template_prev` names a block that is not the header at its height.
    Stale,
}

fn anchor_of(height: u32, hash: [u8; 32], bits: u32) -> GbtTip {
    GbtTip::Ready(height, hash_hex_display(&hash), bits)
}

fn gbt_tip(ctx: &RpcContext) -> Result<GbtTip, Value> {
    if let Some(hash) = ctx.mempool.as_ref().and_then(|m| m.template_prev()) {
        let Some(height) = ctx
            .query
            .height_of_hash(&hash)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        else {
            return Ok(GbtTip::Stale);
        };
        let Some((_, rec)) = ctx
            .query
            .header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        else {
            return Ok(GbtTip::Stale);
        };
        if rec.hash != hash {
            return Ok(GbtTip::Stale);
        }
        return Ok(anchor_of(height.0, rec.hash, rec.bits));
    }
    let Some(h) = ctx.query.tip_height() else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(anchor_of(h.0, rec.hash, rec.bits))
}

/// Core `NextEmptyBlockIndex`: the next block's time floor, its `UpdateTime`
/// time, and the work it must meet at that time.
struct NextBlock {
    mintime: u32,
    curtime: u32,
    bits: u32,
}

fn next_block(
    ctx: &RpcContext,
    params: &rbitcoin_consensus::ChainParams,
    tip_h: u32,
    tip_bits: u32,
) -> Result<NextBlock, Value> {
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
    let mintime = rbitcoin_query::next_block_mintime(ctx.query.as_ref(), params, Height(tip_h))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let curtime = mintime.max(now);
    let next_h = Height(tip_h.saturating_add(1));
    let bits = rbitcoin_query::expected_next_bits(ctx.query.as_ref(), params, next_h, curtime)
        .map(|c| c.to_consensus())
        .unwrap_or(tip_bits);
    Ok(NextBlock {
        mintime,
        curtime,
        bits,
    })
}

fn gbt_params(ctx: &RpcContext) -> rbitcoin_consensus::ChainParams {
    ctx.chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| rbitcoin_consensus::ChainParams::for_network(ctx.network))
}

pub fn gbt_template(ctx: &RpcContext) -> Result<Value, Value> {
    refuse_unmaintained_template(ctx)?;
    let GbtTip::Ready(tip_h, prev_hex, tip_bits) = gbt_tip(ctx)? else {
        return Err(rpc_error(ERR_MISC, "template tip is not on the best chain"));
    };
    let updates = ctx
        .mempool
        .as_ref()
        .map(|m| m.template_updates() as u32)
        .unwrap_or(0);
    let next_h = tip_h.saturating_add(1);
    let params = gbt_params(ctx);
    let pre_segwit = next_h < params.segwit_height();
    let legacy_scale = if pre_segwit { 4 } else { 1 };
    let testdummy = ctx
        .query
        .testdummy_state(&params, Height(tip_h))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let NextBlock {
        mintime,
        curtime,
        bits,
    } = next_block(ctx, &params, tip_h, tip_bits)?;
    let selected = mempool_block_txs(ctx);
    let mut fees = 0u64;
    let mut tx_json = Vec::with_capacity(selected.len());
    let ids: Vec<Txid> = selected.iter().map(|(_, s)| s.txid).collect();
    for (tx, sel) in &selected {
        fees = fees.saturating_add(sel.fee_sat);
        let mut depends = Vec::new();
        for inp in &tx.input {
            if let Some(pos) = ids.iter().position(|t| *t == inp.previous_output.txid) {
                depends.push(pos as u64 + 1);
            }
        }
        tx_json.push(json!({
            "data": serialize_hex(tx),
            "txid": sel.txid.to_string(),
            "hash": tx.compute_wtxid().to_string(),
            "depends": depends,
            "fee": sel.fee_sat,
            "sigops": sel.sigop_cost / legacy_scale,
            "weight": tx.weight().to_wu(),
        }));
    }
    let subsidy = rbitcoin_consensus::block_subsidy(next_h, &params) as u64;
    let longpollid = format!("{prev_hex}{updates}");
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    if let Some(c) = ctx.chain.as_ref() {
        let weight = selected.iter().map(|(tx, _)| tx.weight().to_wu()).sum();
        c.note_block_assembled(weight, selected.len());
    }
    let wtxids = selected
        .iter()
        .map(|(tx, _)| tx.compute_wtxid().to_byte_array());
    let witness_commit = rbitcoin_consensus::witness_commitment_script(wtxids, &[0u8; 32]);
    let mut rules = vec!["csv"];
    if !pre_segwit {
        rules.extend(["!segwit", "taproot"]);
    }
    if params.signet_challenge.is_some() {
        rules.push("!signet");
    }
    let mut vbavailable = serde_json::Map::new();
    let mut version = ctx
        .chain
        .as_ref()
        .map(|c| c.gbt_block_version(testdummy))
        .unwrap_or_else(|| rbitcoin_query::compute_block_version(testdummy));
    if let Some(d) = testdummy {
        match d.state {
            ThresholdState::Started => {
                vbavailable.insert("testdummy".into(), json!(d.bit));
            }
            ThresholdState::LockedIn => {
                version |= 1 << d.bit;
                vbavailable.insert("testdummy".into(), json!(d.bit));
            }
            ThresholdState::Active => rules.push("testdummy"),
            ThresholdState::Defined => {}
        }
    }
    let mut template = json!({
        "capabilities": ["proposal"],
        "version": version,
        "rules": rules,
        "vbavailable": vbavailable,
        "vbrequired": 0,
        "previousblockhash": prev_hex,
        "transactions": tx_json,
        "coinbaseaux": {},
        "coinbasevalue": subsidy.saturating_add(fees),
        "longpollid": longpollid,
        "target": format!("{target:064x}"),
        "mintime": mintime,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": rbitcoin_consensus::block::MAX_BLOCK_SIGOPS_COST / legacy_scale,
        "sizelimit": 4_000_000 / legacy_scale,
        "curtime": curtime,
        "bits": format!("{bits:08x}"),
        "height": next_h,
        "default_witness_commitment": rbitcoin_primitives::hex_encode(&witness_commit),
    });
    if !pre_segwit {
        template["weightlimit"] = json!(4_000_000);
    }
    if let Some(challenge) = &params.signet_challenge {
        template["signet_challenge"] = json!(rbitcoin_primitives::hex_encode(challenge.as_bytes()));
    }
    let warnings = rpc_warnings(ctx);
    if !warnings.is_empty() {
        template["warnings"] = json!(warnings);
    }
    Ok(template)
}

pub fn gbt_proposal(
    ctx: &RpcContext,
    req: Option<&serde_json::Map<String, Value>>,
) -> Result<Value, Value> {
    let data = req
        .and_then(|o| o.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_error(ERR_TYPE_ERROR, "Missing data String key for proposal"))?;
    let raw = rbitcoin_primitives::hex_decode(data)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    let block: Block =
        deserialize(&raw).map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
    if let Some(known) = proposal_duplicate(ctx, &block.block_hash())? {
        return Ok(json!(known));
    }
    match gbt_check_proposal(ctx, &block) {
        Ok(()) => Ok(Value::Null),
        Err(s) => Ok(json!(s)),
    }
}

/// Core's block-index lookup before a proposal is checked. A block connected
/// now, or connected and then reorged off by this process, is `duplicate`
/// (Core `BLOCK_VALID_SCRIPTS`). The mark is not kept across a restart, so
/// such a block is then `duplicate-inconclusive`, like any other known header.
fn proposal_duplicate(ctx: &RpcContext, hash: &BlockHash) -> Result<Option<&'static str>, Value> {
    let bytes = hash.to_byte_array();
    let connected = ctx
        .query
        .height_of_hash(&bytes)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .is_some();
    if connected {
        return Ok(Some("duplicate"));
    }
    let Some(chain) = ctx.chain.as_ref() else {
        return Ok(None);
    };
    if chain.is_block_invalid(hash) {
        return Ok(Some("duplicate-invalid"));
    }
    if ctx.query.was_disconnected(&bytes) {
        return Ok(Some("duplicate"));
    }
    let known = chain.stored_header_height(hash).is_some() || chain.held_body(hash).is_some();
    Ok(known.then_some("duplicate-inconclusive"))
}

/// Core `TestBlockValidity` for GBT proposal: no PoW, no UTXO write.
pub fn gbt_check_proposal(ctx: &RpcContext, block: &Block) -> Result<(), String> {
    let priced = match ctx.chain.as_ref() {
        Some(chain) => chain.check_block_proposal(block),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            rbitcoin_net::check_block_proposal_with(
                ctx.query.as_ref(),
                &rbitcoin_consensus::ChainParams::for_network(ctx.network),
                rbitcoin_consensus::Milestone::NONE,
                now,
                block,
            )
        }
    };
    priced.map(|_fees| ())
}

/// Where a [`during_next_mininginfo`] hook runs in each sample.
#[cfg(debug_assertions)]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MininginfoPoint {
    /// After the tip read, before the reads by height.
    BeforeNext,
    /// After the reads by height, before the sample is checked.
    BeforeRecheck,
}

#[cfg(debug_assertions)]
type MininginfoHook = Box<dyn FnMut(&RpcContext, MininginfoPoint)>;

#[cfg(debug_assertions)]
thread_local! {
    static MININGINFO_HOOK: std::cell::RefCell<Option<MininginfoHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` at each [`MininginfoPoint`] of the next `getmininginfo` on this
/// thread.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn during_next_mininginfo(f: impl FnMut(&RpcContext, MininginfoPoint) + 'static) {
    MININGINFO_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

fn tip_header(ctx: &RpcContext) -> Result<(Height, rbitcoin_store::HeaderRecord), Value> {
    let tip = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok((tip, rec))
}

/// Samples before `getmininginfo` gives up on a chain that keeps reorging.
const MININGINFO_SAMPLES: u32 = 8;

/// Core `getmininginfo`. `blocks`, `bestblockhash`, `bits`, `next`, and
/// `networkhashps` describe one tip, as Core's under `cs_main`.
pub fn getmininginfo(ctx: &RpcContext) -> Result<Value, Value> {
    #[cfg(debug_assertions)]
    let mut hook = MININGINFO_HOOK.with(|h| h.borrow_mut().take());
    #[cfg(debug_assertions)]
    let mut at = |point| {
        if let Some(f) = hook.as_mut() {
            f(ctx, point);
        }
    };
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    let mut sample = || -> Result<_, Value> {
        let (tip, rec) = tip_header(ctx)?;
        #[cfg(debug_assertions)]
        at(MininginfoPoint::BeforeNext);
        let next = next_block(ctx, &gbt_params(ctx), tip.0, rec.bits)?;
        let hashps = network_hash_ps(ctx, 120, i64::from(tip.0)).unwrap_or(0.0);
        #[cfg(debug_assertions)]
        at(MininginfoPoint::BeforeRecheck);
        Ok((tip, rec, next, hashps))
    };
    let disconnects = || ctx.query.disconnect_gen.load(Ordering::Acquire);
    let mut samples = 0;
    let (tip, rec, next, hashps) = loop {
        let gen = disconnects();
        let sampled = sample();
        // Every read is at or below the sampled tip, so a connect above it
        // changes none of them and a syncing node keeps its first sample. A
        // disconnect can change them, and one that was undone leaves the slot as
        // it was. The generation moves after the slot is popped, so read the
        // slot first.
        let held = sampled.as_ref().is_ok_and(|(tip, rec, ..)| {
            matches!(ctx.query.header_at_height(*tip), Ok(Some((_, now))) if now.hash == rec.hash)
                && disconnects() == gen
        });
        samples += 1;
        match sampled {
            Ok(sampled) if held => break sampled,
            Err(e) if samples == MININGINFO_SAMPLES => return Err(e),
            Ok(_) if samples == MININGINFO_SAMPLES => {
                return Err(rpc_error(ERR_MISC, "the chain kept reorging"));
            }
            // A failed read is what a disconnect below the sample looks like.
            _ => {}
        }
        // Every disconnect runs as a tip job, so this paces the samples. An
        // idle lane means nothing is reorging, and the next sample can start.
        wait_chain_tip(ctx);
    };
    let pooledtx = ctx
        .mempool
        .as_ref()
        .map(|m| m.list_live_meta().len())
        .unwrap_or(0);
    let work = |bits: u32| {
        let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
        (
            format!("{bits:08x}"),
            format!("{target:064x}"),
            core_f64_json(difficulty_from_bits(bits)),
        )
    };
    let (bits, target, difficulty) = work(rec.bits);
    let (next_bits, next_target, next_difficulty) = work(next.bits);
    let mut m = serde_json::Map::new();
    m.insert("blocks".into(), json!(tip.0));
    m.insert("bestblockhash".into(), json!(hash_hex_display(&rec.hash)));
    if let Some((weight, txs)) = ctx.chain.as_ref().and_then(|c| c.last_block_assembled()) {
        m.insert("currentblockweight".into(), json!(weight));
        m.insert("currentblocktx".into(), json!(txs));
    }
    m.insert("difficulty".into(), difficulty);
    m.insert("networkhashps".into(), core_f64_json(hashps));
    m.insert("pooledtx".into(), json!(pooledtx));
    let min_sat = ctx
        .chain
        .as_ref()
        .map(|c| c.block_min_tx_fee_sat_kvb())
        .unwrap_or(1);
    m.insert("blockmintxfee".into(), sat_btc_json(min_sat as i64));
    m.insert("chain".into(), json!(chain_name(ctx.network)));
    if let Some(challenge) = super::chain::signet_challenge_hex(ctx) {
        m.insert("signet_challenge".into(), json!(challenge));
    }
    m.insert("bits".into(), json!(bits));
    m.insert("target".into(), json!(target));
    m.insert(
        "next".into(),
        json!({
            "height": tip.0.saturating_add(1),
            "bits": next_bits,
            "target": next_target,
            "difficulty": next_difficulty,
        }),
    );
    m.insert("warnings".into(), json!(rpc_warnings(ctx)));
    Ok(Value::Object(m))
}

pub fn getnetworkhashps(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["nblocks", "height"])?;
    let nblocks = params.opt_i64(0, "nblocks")?.unwrap_or(120);
    let height = match params.get(1, "height") {
        None | Some(Value::Null) => -1,
        Some(v) => {
            json_i64(v).ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "height must be an integer"))?
        }
    };
    Ok(json!(network_hash_ps(ctx, nblocks, height)?))
}

#[doc(hidden)]
pub fn work_to_f64(w: bitcoin::Work) -> f64 {
    w.to_be_bytes()
        .iter()
        .fold(0.0, |a, b| a * 256.0 + f64::from(*b))
}

#[doc(hidden)]
pub fn work_through(ctx: &RpcContext, height: u32) -> bitcoin::Work {
    if let Some(hub) = ctx.chain.as_ref() {
        if let Ok(w) = hub.work_through_height(height) {
            return w;
        }
    }
    let mut works = Vec::new();
    for h in 0..=height {
        if let Ok(hdr) = ctx
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(h))
        {
            works.push(hdr.work());
        }
    }
    rbitcoin_net::sum_work(works.into_iter()).unwrap_or(bitcoin::Work::from_be_bytes([0xff; 32]))
}

pub fn network_hash_ps(ctx: &RpcContext, nblocks: i64, height: i64) -> Result<f64, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    if tip == 0 {
        return Ok(0.0);
    }
    let end = if height < 0 || (height as u32) > tip {
        tip
    } else {
        height as u32
    };
    if end == 0 {
        return Ok(0.0);
    }
    let interval = ctx
        .chain
        .as_ref()
        .map(|c| c.params.difficulty_adjustment_interval())
        .unwrap_or_else(|| {
            rbitcoin_consensus::ChainParams::for_network(ctx.network)
                .difficulty_adjustment_interval()
        });
    let mut lookup = if nblocks <= 0 {
        end % interval + 1
    } else {
        nblocks as u32
    };
    if lookup > end {
        lookup = end;
    }
    // A positive `nblocks` whose low 32 bits are 0 is not a window.
    if lookup == 0 {
        return Ok(0.0);
    }
    let start = end - lookup;
    let mut min_time = u32::MAX;
    let mut max_time = 0u32;
    for h in start..=end {
        let Some(t) = header_time(ctx, h) else {
            continue;
        };
        min_time = min_time.min(t);
        max_time = max_time.max(t);
    }
    if min_time == u32::MAX || min_time == max_time {
        return Ok(0.0);
    }
    let work = work_to_f64(work_through(ctx, end)) - work_to_f64(work_through(ctx, start));
    let dt = f64::from(max_time - min_time);
    Ok(work / dt)
}

pub fn header_time(ctx: &RpcContext, h: u32) -> Option<u32> {
    let (_, rec) = ctx
        .query
        .header_at_height(rbitcoin_primitives::Height(h))
        .ok()
        .flatten()?;
    Some(rec.timestamp)
}

/// Core `UpdateUncommittedBlockStructures`: a coinbase that commits to
/// witnesses but carries no witness gets the 32 zero bytes, once segwit is
/// active for this block. Mining software may leave it out.
#[doc(hidden)]
pub fn fill_witness_reserved_value(hub: &rbitcoin_net::ChainHub, block: &mut Block) {
    let segwit = hub
        .stored_header_height(&block.header.prev_blockhash)
        .is_some_and(|h| hub.params.segwit_active_at(h.saturating_add(1)));
    let Some(coinbase) = block.txdata.first_mut() else {
        return;
    };
    if !segwit
        || rbitcoin_consensus::witness_commitment_vout_index(coinbase).is_none()
        || coinbase.input.iter().any(|i| !i.witness.is_empty())
    {
        return;
    }
    if let Some(input) = coinbase.input.first_mut() {
        input.witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
    }
}

/// Same receive path as P2P `block` (all networks).
pub fn submit_received_block(hub: &rbitcoin_net::ChainHub, mut block: Block) -> SubmitBlockOutcome {
    use bitcoin::Target;
    use rbitcoin_net::AcceptOutcome;
    let hash = block.block_hash();
    if hub.is_block_invalid(&hash) {
        return SubmitBlockOutcome::Rejected("duplicate-invalid".into());
    }
    // Read before accept parks a first-time side block. A block we already
    // hold, and that still does not beat the tip, is Core's `duplicate`.
    let already_held = hub.held_body(&hash).is_some();
    let target = Target::from_compact(block.header.bits);
    if block.header.validate_pow(target).is_err() {
        return SubmitBlockOutcome::Rejected("high-hash".into());
    }
    let prev = block.header.prev_blockhash.to_byte_array();
    let prev_header = match hub.query.get_header_by_hash(&prev) {
        Ok(h) => h.is_some(),
        Err(rbitcoin_store::StoreError::NotFound) => false,
        Err(e) => return SubmitBlockOutcome::Error(format!("store: {e}")),
    };
    let known = prev_header
        || hub
            .held_body(&bitcoin::BlockHash::from_byte_array(prev))
            .is_some();
    if !known {
        return SubmitBlockOutcome::Rejected("prev-blk-not-found".into());
    }
    fill_witness_reserved_value(hub, &mut block);
    match cheap_submit_tx_reject(
        hub.query.as_ref(),
        &block,
        hub.params.coinbase_maturity(),
        &hub.params,
        hub.milestone,
    ) {
        Err(e) => return SubmitBlockOutcome::Error(format!("store: {e}")),
        Ok(Some(reason)) => {
            // Merkle and witness bytes are not the block hash. A coinbase-less
            // 64-byte body can be the header's inner nodes. Those reasons must
            // not stick, so a second submit of the honest body is not
            // `duplicate-invalid`. A warn-and-apply fault stays retryable for
            // the trusted session. Every other cheap consensus reason sticks.
            if submit_reason_sticks(hub, &block, &reason) {
                hub.note_invalid_block(hash);
                let _ = hub.ensure_header(&block.header);
            }
            return SubmitBlockOutcome::Rejected(reason);
        }
        Ok(None) => {}
    }
    match hub.accept_received_block(block.clone()) {
        Ok(AcceptOutcome::Accepted { .. }) => SubmitBlockOutcome::Accepted,
        Ok(AcceptOutcome::AlreadyHave) => SubmitBlockOutcome::Duplicate,
        Ok(AcceptOutcome::IgnoredWeaker) if already_held => SubmitBlockOutcome::Duplicate,
        Ok(AcceptOutcome::IgnoredWeaker) => SubmitBlockOutcome::IgnoredWeaker,
        // Core: an interrupted ProcessNewBlock never fires BlockChecked.
        Err(rbitcoin_net::NetError::Cancelled) => SubmitBlockOutcome::IgnoredWeaker,
        Err(e) if e.is_local_fault() => SubmitBlockOutcome::Error(e.to_string()),
        Err(e) => {
            let reason = submit_reject_reason(&e);
            if submit_reason_sticks(hub, &block, &reason)
                && !(hub.query.trust_peer()
                    && rbitcoin_net::chain::accept_err_is_warn_and_apply(&e))
            {
                hub.note_invalid_block(hash);
                let _ = hub.ensure_header(&block.header);
            }
            SubmitBlockOutcome::Rejected(reason)
        }
    }
}

/// True when `block`'s parent header is the active tip. A known ancestor that
/// is not the tip is a competing block; tip spentness does not apply.
#[doc(hidden)]
pub fn parent_extends_tip(
    query: &rbitcoin_query::Query,
    block: &Block,
) -> Result<bool, rbitcoin_store::StoreError> {
    use rbitcoin_store::StoreError;
    let prev = block.header.prev_blockhash.to_byte_array();
    let parent_fk = match query.get_header_by_hash(&prev) {
        Ok(Some((fk, _))) => fk,
        Ok(None) | Err(StoreError::NotFound) => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(query.tip_header_fk()? == Some(parent_fk))
}

/// Spend height of `block` when its parent is confirmed. The tip parent is a
/// header-fk compare. Any other parent uses the best-chain hash index.
#[doc(hidden)]
pub fn cheap_spend_height(
    query: &rbitcoin_query::Query,
    block: &Block,
) -> Result<Option<u32>, rbitcoin_store::StoreError> {
    use rbitcoin_store::StoreError;
    let prev = block.header.prev_blockhash.to_byte_array();
    let parent_fk = match query.get_header_by_hash(&prev) {
        Ok(Some((fk, _))) => fk,
        Ok(None) | Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    if query.tip_header_fk()? == Some(parent_fk) {
        return Ok(query.tip_height().map(|h| h.0.saturating_add(1)));
    }
    Ok(query.height_of_hash(&prev)?.map(|h| h.0.saturating_add(1)))
}

/// Core `CheckTxInputs`: a coinbase spend inside the maturity window is
/// `bad-txns-premature-spend-of-coinbase` before the value check.
#[doc(hidden)]
pub fn cheap_immature_coinbase(
    query: &rbitcoin_query::Query,
    create_fk: rbitcoin_primitives::Fk,
    spend_height: u32,
    maturity: u32,
) -> Result<bool, rbitcoin_store::StoreError> {
    use rbitcoin_store::StoreError;
    let created_h = match query.store().tx_height_get(create_fk) {
        Ok(Some(h)) => h,
        Ok(None) | Err(StoreError::NotFound) => return Ok(false),
        Err(e) => return Err(e),
    };
    if spend_height >= created_h.saturating_add(maturity) {
        return Ok(false);
    }
    let coinbases = query.store().coinbase_fk_at_heights(&[created_h])?;
    Ok(coinbases.get(&created_h).copied() == Some(create_fk))
}

/// Confirmed unspent output at `op`, with the creating tx's fk. `Ok(None)` is
/// a real miss or spend. `Err` is a store read fault, not a verdict on the
/// spending block.
///
/// `vout` is peer-chosen. It is checked against the parent's output count
/// before the spender read, which treats a slot past that count as corrupt.
#[doc(hidden)]
pub fn read_confirmed_prevout(
    query: &rbitcoin_query::Query,
    op: bitcoin::OutPoint,
    at_tip: bool,
) -> Result<Option<(rbitcoin_primitives::Fk, bitcoin::TxOut)>, rbitcoin_store::StoreError> {
    use rbitcoin_store::StoreError;
    let tid = op.txid.to_byte_array();
    let Some((fk, rec)) = (match query.get_tx_by_txid(&tid) {
        Ok(v) => v,
        Err(StoreError::NotFound) => None,
        Err(e) => return Err(e),
    }) else {
        return Ok(None);
    };
    if op.vout >= rec.output_count {
        return Ok(None);
    }
    // Tip spentness is the parent chain only when this block extends the tip.
    // A sibling can spend a coin the current tip also spent; caching that as
    // invalid drops the competing block for the rest of the process.
    if at_tip && query.is_outpoint_spent(&tid, op.vout)? {
        return Ok(None);
    }
    let out = match query
        .tx_output_at_fk(fk, op.vout)
        .or_else(|_| query.tx_output(&rec, op.vout))
    {
        Ok(out) => out,
        Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let value = bitcoin::Amount::from_sat(out.value);
    Ok(Some((
        fk,
        bitcoin::TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(out.script),
        },
    )))
}

/// Hard consensus rejects stick. A mutated body, a missing parent, a block
/// that is only too far in the future, and a block older than median time
/// stay retryable. A warn-and-apply fault stays retryable while
/// `--trust-peer` is on. `bad-diffbits` sticks.
fn submit_reason_sticks(hub: &rbitcoin_net::ChainHub, block: &Block, reason: &str) -> bool {
    !submit_reason_is_mutated(block, reason)
        && reason != "high-hash"
        && reason != "prev-blk-not-found"
        && reason != "time-too-new"
        && reason != "time-too-old"
        && !(hub.query.trust_peer() && rbitcoin_consensus::reason_is_warn_and_apply(reason))
}

/// Witness and merkle bytes are not the block hash. Caching them drops the
/// honest body for the rest of the process.
#[doc(hidden)]
pub fn submit_reason_is_mutated(block: &Block, reason: &str) -> bool {
    reason == "bad-txns-duplicate"
        || reason == "bad-txnmrklroot"
        || reason.contains("witness")
        || rbitcoin_consensus::block_mutated_without_coinbase(block)
}

#[doc(hidden)]
pub fn cheap_submit_tx_reject(
    query: &rbitcoin_query::Query,
    block: &Block,
    maturity: u32,
    params: &rbitcoin_consensus::ChainParams,
    milestone: rbitcoin_consensus::Milestone,
) -> Result<Option<String>, rbitcoin_store::StoreError> {
    use bitcoin::{OutPoint, TxOut};
    let spend_height = cheap_spend_height(query, block)?;
    let parent_is_tip = parent_extends_tip(query, block)?;
    // Core CheckMerkleRoot runs before every body rule. A repeat that keeps
    // the root (CVE-2012-2459) is the only bad-txns-duplicate. Any other
    // repeat spends a coin its first copy spent.
    let txids: Vec<Txid> = block.txdata.iter().map(Transaction::compute_txid).collect();
    let leaves: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
    let (root, mutated) = rbitcoin_store::merkle_root_mutated(&leaves);
    if root != block.header.merkle_root.to_byte_array() {
        return Ok(Some("bad-txnmrklroot".into()));
    }
    if mutated {
        return Ok(Some("bad-txns-duplicate".into()));
    }
    // CheckBlock before inputs. connect_at is the other caller, and an
    // equal-work sibling never reaches it.
    if let Some(reason) = submit_checkblock_reason(block, spend_height, params, milestone)? {
        return Ok(Some(reason));
    }
    // A parent off the best chain can create the coins this block spends.
    // Only the branch connect sees them (Core checks inputs in ConnectBlock).
    if spend_height.is_none() {
        return Ok(None);
    }
    let mut spent = std::collections::HashSet::new();
    let mut created: std::collections::HashMap<OutPoint, TxOut> = std::collections::HashMap::new();
    for (i, (tx, &tid)) in block.txdata.iter().zip(&txids).enumerate() {
        if i == 0 {
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
        // CheckTransaction rejects an empty vin or vout before ConnectBlock
        // compares values or coinbase maturity.
        if tx.input.is_empty() {
            return Ok(Some("bad-txns-vin-empty".into()));
        }
        if tx.output.is_empty() {
            return Ok(Some("bad-txns-vout-empty".into()));
        }
        let mut in_val = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Ok(Some("bad-txns-inputs-missingorspent".into()));
            }
            // Same-block coinbase is immature. Core reports that before
            // `bad-txns-in-belowout`.
            if op.txid == txids[0] && created.contains_key(&op) {
                return Ok(Some("bad-txns-premature-spend-of-coinbase".into()));
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else {
                let Some((fk, out)) = read_confirmed_prevout(query, op, parent_is_tip)? else {
                    return Ok(Some("bad-txns-inputs-missingorspent".into()));
                };
                if let Some(h) = spend_height {
                    if cheap_immature_coinbase(query, fk, h, maturity)? {
                        return Ok(Some("bad-txns-premature-spend-of-coinbase".into()));
                    }
                }
                out
            };
            in_val = in_val.saturating_add(txout.value.to_sat());
        }
        let out_val: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_val > in_val {
            return Ok(Some("bad-txns-in-belowout".into()));
        }
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
    Ok(None)
}

/// Context-free CheckBlock for a known parent. A best-chain parent has a
/// height, so BIP34 applies. A held-only parent has no height yet.
#[doc(hidden)]
pub fn submit_checkblock_reason(
    block: &Block,
    spend_height: Option<u32>,
    params: &rbitcoin_consensus::ChainParams,
    milestone: rbitcoin_consensus::Milestone,
) -> Result<Option<String>, rbitcoin_store::StoreError> {
    let vctx = match spend_height {
        Some(h) => rbitcoin_consensus::ValidationContext::at(params, Height(h), milestone),
        None => rbitcoin_consensus::ValidationContext::archive_structure(params),
    };
    match rbitcoin_consensus::validate_block_structure(block, &vctx) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(rbitcoin_consensus::block_reject_reason(&e))),
    }
}

#[doc(hidden)]
pub fn submit_reject_reason(e: &rbitcoin_net::NetError) -> String {
    if matches!(e, rbitcoin_net::NetError::UnknownParent) {
        return "prev-blk-not-found".into();
    }
    if let Some(rules) = e.consensus_rules() {
        return rbitcoin_consensus::block_reject_reason(rules);
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

pub fn submitblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata", "dummy"])?;
    let hex = params.req_str(0, "hexdata")?;
    let raw = rbitcoin_primitives::hex_decode(hex)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block decode failed"))?;
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
        SubmitBlockOutcome::Error(msg) => Err(rpc_error(ERR_VERIFY_ERROR, msg)),
    }
}

pub fn decode_tx_hex(hex: &str) -> Result<Transaction, Value> {
    let b = rbitcoin_primitives::hex_decode(hex)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "TX decode failed:"))?;
    deserialize(&b).map_err(|_| rpc_error(ERR_DESERIALIZATION, "TX decode failed:"))
}

pub fn tx_to_json(tx: &Transaction, extra: Option<Value>, network: BtcNetwork) -> Value {
    let txid = hash_hex_display(&tx.compute_txid().to_byte_array());
    let mut vin = Vec::new();
    for (i, inp) in tx.input.iter().enumerate() {
        let mut row = if tx.is_coinbase() {
            json!({
                "coinbase": rbitcoin_primitives::hex_encode(inp.script_sig.as_bytes() ),
                "sequence": inp.sequence.to_consensus_u32(),
                "n": i,
            })
        } else {
            json!({
                "txid": hash_hex_display(&inp.previous_output.txid.to_byte_array()),
                "vout": inp.previous_output.vout,
                "scriptSig": {
                    "asm": inp.script_sig.to_asm_string(),
                    "hex": rbitcoin_primitives::hex_encode(inp.script_sig.as_bytes() ),
                },
                "sequence": inp.sequence.to_consensus_u32(),
                "n": i,
            })
        };
        // Core keeps a segwit coinbase's witness reserved value here too.
        if !inp.witness.is_empty() {
            let stack: Vec<String> = inp
                .witness
                .iter()
                .map(rbitcoin_primitives::hex_encode)
                .collect();
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
