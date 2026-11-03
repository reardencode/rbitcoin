use super::*;
use bitcoin::address::{AddressType, NetworkUnchecked};
use bitcoin::{Address, ScriptBuf};

pub fn decoderawtransaction(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexstring", "iswitness"])?;
    let hex = params.req_str(0, "hexstring")?;
    let iswitness = params.opt_bool(1, "iswitness")?;
    let tx = rbitcoin_primitives::hex_decode(hex)
        .ok()
        .and_then(|raw| {
            rbitcoin_consensus::wire::decode_tx(
                &raw,
                iswitness != Some(true),
                iswitness != Some(false),
            )
        })
        .ok_or_else(|| rpc_error(ERR_DESERIALIZATION, "TX decode failed"))?;
    Ok(tx_to_json(&tx, None, rpc_btc_network(ctx.network)))
}

pub fn decodescript(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexstring"])?;
    let hex = params.req_str(0, "hexstring")?;
    let raw = rbitcoin_primitives::hex_decode(hex)
        .map_err(|e| rpc_error(ERR_INVALID_PARAMS, e.to_string()))?;
    Ok(script_pubkey_json(
        &ScriptBuf::from_bytes(raw),
        rpc_btc_network(ctx.network),
    ))
}

/// Core `DecodeDestination`. Core `DecodeBase58` skips leading and trailing
/// whitespace (`IsSpace`), so a base58 address may carry it. Bech32 may not.
pub fn parse_address(s: &str) -> Option<Address<NetworkUnchecked>> {
    let base58 = s.trim_matches([' ', '\x0c', '\n', '\r', '\t', '\x0b']);
    if base58.len() != s.len() && bitcoin::base58::decode_check(base58).is_ok() {
        return base58.parse().ok();
    }
    s.parse().ok()
}

pub fn validateaddress(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["address"])?;
    let s = params.req_str(0, "address")?;
    let Some(parsed) = parse_address(s) else {
        return Ok(json!({ "isvalid": false }));
    };
    let addr = match parsed.require_network(rpc_btc_network(ctx.network)) {
        Ok(a) => a,
        Err(_) => return Ok(json!({ "isvalid": false })),
    };
    let spk = addr.script_pubkey();
    let (isscript, iswitness) = match addr.address_type() {
        Some(AddressType::P2pkh) => (false, false),
        Some(AddressType::P2sh) => (true, false),
        Some(AddressType::P2wpkh) => (false, true),
        Some(AddressType::P2wsh | AddressType::P2tr | AddressType::P2a) => (true, true),
        Some(_) | None => (false, addr.witness_program().is_some()),
    };
    let mut obj = json!({
        "isvalid": true,
        "address": addr.to_string(),
        "scriptPubKey": rbitcoin_primitives::hex_encode(spk.as_bytes() ),
        "isscript": isscript,
        "iswitness": iswitness,
    });
    // Core omits witness_version / witness_program for pay-to-anchor.
    if addr.address_type() != Some(AddressType::P2a) {
        if let Some(wp) = addr.witness_program() {
            if let Some(m) = obj.as_object_mut() {
                m.insert("witness_version".into(), json!(wp.version().to_num()));
                m.insert(
                    "witness_program".into(),
                    json!(rbitcoin_primitives::hex_encode(wp.program().as_bytes())),
                );
            }
        }
    }
    Ok(obj)
}
