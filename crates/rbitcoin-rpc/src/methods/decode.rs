use super::descriptor::{bare_multisig, p2pk_key, wsh_multi_descriptor};
use super::*;
use bitcoin::address::{AddressType, NetworkUnchecked};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_NOP10;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
use bitcoin::{Address, Network as BtcNetwork, Script, ScriptBuf, WPubkeyHash};
use rbitcoin_consensus::policy::is_unspendable;
use rbitcoin_consensus::script::interpreter::{is_op_success, MAX_SCRIPT_ELEMENT_SIZE};
use rbitcoin_primitives::{P2PKH_PREFIX, P2PKH_SUFFIX};

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
    let script = ScriptBuf::from_bytes(raw);
    let network = rpc_btc_network(ctx.network);
    let mut obj = script_json(&script, network);
    let ty = TxoutType::of(&script);
    if !p2sh_wrappable(&script, ty) {
        return Ok(obj);
    }
    obj["p2sh"] = json!(p2sh_address(&script, network));
    if let Some(segwit) = segwit_json(&script, ty, network) {
        obj["segwit"] = segwit;
    }
    Ok(obj)
}

/// Core `decodescript` `can_wrap`: a type P2SH may carry, with valid
/// opcodes, spendable, and no `OP_CHECKSIGADD` or `OP_SUCCESSx`.
fn p2sh_wrappable(script: &Script, ty: TxoutType) -> bool {
    let wrappable_type = matches!(
        ty,
        TxoutType::Multisig
            | TxoutType::NonStandard
            | TxoutType::PubKey
            | TxoutType::PubKeyHash
            | TxoutType::WitnessV0KeyHash
            | TxoutType::WitnessV0ScriptHash
    );
    wrappable_type
        && !is_unspendable(script.as_bytes())
        && script.instructions().all(|ins| match ins {
            Ok(Instruction::PushBytes(push)) => push.len() <= MAX_SCRIPT_ELEMENT_SIZE,
            Ok(Instruction::Op(op)) => op.to_u8() <= OP_NOP10.to_u8() && !is_op_success(op.to_u8()),
            Err(_) => false,
        })
}

fn p2sh_address(script: &Script, network: BtcNetwork) -> String {
    Address::p2sh_from_hash(script.script_hash(), network).to_string()
}

/// Core `decodescript` `segwit`: the P2WPKH output for a key or key hash,
/// else the P2WSH output for the script. A script with an uncompressed key
/// has none, since segwit refuses those keys.
fn segwit_json(script: &Script, ty: TxoutType, network: BtcNetwork) -> Option<Value> {
    let (program, known_desc) = match ty {
        TxoutType::PubKey => {
            let key = p2pk_key(script).filter(|key| is_compressed(key))?;
            (ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(key)), None)
        }
        TxoutType::PubKeyHash => {
            let b = script.as_bytes();
            let hash = &b[P2PKH_PREFIX.len()..b.len() - P2PKH_SUFFIX.len()];
            let hash = WPubkeyHash::from_slice(hash).ok()?;
            (ScriptBuf::new_p2wpkh(&hash), None)
        }
        TxoutType::Multisig => {
            let (required, keys) = bare_multisig(script)?;
            if !keys.iter().all(|key| is_compressed(key)) {
                return None;
            }
            let desc = wsh_multi_descriptor(required, &keys);
            (ScriptBuf::new_p2wsh(&script.wscript_hash()), Some(desc))
        }
        TxoutType::NonStandard => (ScriptBuf::new_p2wsh(&script.wscript_hash()), None),
        _ => return None,
    };
    let mut obj = script_pubkey_json(&program, network);
    if let Some(desc) = known_desc {
        obj["desc"] = json!(desc);
    }
    obj["p2sh-segwit"] = json!(p2sh_address(&program, network));
    Some(obj)
}

fn is_compressed(key: &[u8]) -> bool {
    key.len() == PUBLIC_KEY_SIZE
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
