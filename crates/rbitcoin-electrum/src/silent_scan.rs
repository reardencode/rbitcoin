//! Frigate `blockchain.silentpayments.subscribe` (session-only scan key).

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Network;
use rbitcoin_consensus::silent_payments::labeled_spend_key;
use rbitcoin_consensus::{taproot_matches_scan, ChainParams};
use rbitcoin_primitives::Height;
use rbitcoin_query::tweaks_for_height;
use rbitcoin_query::Query;
use serde_json::{json, Value};

#[doc(hidden)]
pub fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    crate::server::decode_hex_bytes(s)
}

/// Heights scanned when the client omits a start or passes 0.
pub const SP_HISTORY_WINDOW: u32 = 256;
/// Heights held under one scan permit before the next chunk.
pub const SP_SCAN_CHUNK: u32 = 256;
/// Process-wide historical scans. Not a knob.
pub const SP_SCAN_PERMITS: usize = 3;

#[derive(Clone)]
pub struct SpSub {
    pub scan: SecretKey,
    pub start: u32,
    pub labels: Vec<u32>,
    spend_keys: Vec<PublicKey>,
    pub address: String,
}

pub fn parse_sub(params: &Value, network: Network, tip: Option<u32>) -> Result<SpSub, String> {
    let scan_hex = param_str(params, 0)?;
    let spend_hex = param_str(params, 1)?;
    let scan_bytes = decode_hex_bytes(scan_hex)?;
    if scan_bytes.len() != 32 {
        return Err("scan_private_key must be 32 bytes".into());
    }
    let scan = SecretKey::from_slice(&scan_bytes).map_err(|e| e.to_string())?;
    let spend_bytes = decode_hex_bytes(spend_hex)?;
    let spend = PublicKey::from_slice(&spend_bytes).map_err(|e| e.to_string())?;
    let start = match params.as_array().and_then(|a| a.get(2)) {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) as u32,
        Some(Value::String(s)) if s.contains('-') => s
            .split('-')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    if start > 500_000_000 {
        return Err("timestamp start not supported".into());
    }
    let mut labels = vec![0u32];
    if let Some(arr) = params
        .as_array()
        .and_then(|a| a.get(3))
        .and_then(|v| v.as_array())
    {
        for v in arr {
            if let Some(n) = v.as_u64() {
                let n = n as u32;
                if !labels.contains(&n) {
                    labels.push(n);
                }
            }
        }
    }
    if labels.len() > 10 {
        return Err("too many silent payment labels".into());
    }
    let mut spend_keys = labels
        .iter()
        .map(|&label| labeled_spend_key(&scan, &spend, label))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid silent payment label key: {e}"))?;
    spend_keys.insert(0, spend);
    let start = start.min(tip.unwrap_or(start));
    // Any start, including a nonzero one, stays inside the recent window.
    let start = match tip {
        Some(tip_h) => start.max(tip_h.saturating_sub(SP_HISTORY_WINDOW)),
        None => start,
    };
    let address = encode_sp_address(network, &scan, &spend);
    Ok(SpSub {
        scan,
        start,
        labels,
        spend_keys,
        address,
    })
}

pub fn subscribe_result(sub: &SpSub) -> Value {
    json!({
        "address": sub.address,
        "labels": sub.labels,
        "start_height": sub.start,
    })
}

pub fn scan_hits(
    query: &Query,
    chain: &ChainParams,
    sub: &SpSub,
    from: u32,
    to: u32,
) -> Result<Vec<Value>, String> {
    let mut hits = Vec::new();
    for h in from..=to {
        let map = tweaks_for_height(query, chain, Height(h)).map_err(|e| e.to_string())?;
        for (txid, tw) in map {
            if tx_matches(sub, &tw) {
                hits.push(json!({
                    "height": h,
                    "tx_hash": rbitcoin_primitives::display_hash_hex(txid),
                    "tweak_key": rbitcoin_primitives::hex_encode(tw.tweak),
                }));
            }
        }
    }
    Ok(hits)
}

#[doc(hidden)]
pub fn tx_matches(sub: &SpSub, tw: &rbitcoin_consensus::TxTweak) -> bool {
    taproot_matches_scan(&tw.tweak, &tw.output_pubkeys, &sub.scan, &sub.spend_keys)
}

#[doc(hidden)]
pub fn encode_sp_address(network: Network, scan_sk: &SecretKey, spend: &PublicKey) -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let scan_pk = PublicKey::from_secret_key(&secp, scan_sk);
    let hrp = match network {
        Network::Bitcoin => "sp",
        Network::Regtest => "sprt",
        Network::Signet | Network::Testnet | Network::Testnet4 => "tsp",
    };
    let mut data = Vec::with_capacity(66);
    data.extend_from_slice(&scan_pk.serialize());
    data.extend_from_slice(&spend.serialize());
    match bitcoin::bech32::encode::<bitcoin::bech32::Bech32m>(
        bitcoin::bech32::Hrp::parse_unchecked(hrp),
        &data,
    ) {
        Ok(s) => s,
        Err(_) => format!("{hrp}1{}", rbitcoin_primitives::hex_encode(&data)),
    }
}

#[doc(hidden)]
pub fn param_str(params: &Value, i: usize) -> Result<&str, String> {
    crate::server::param_str(params, i)
}
