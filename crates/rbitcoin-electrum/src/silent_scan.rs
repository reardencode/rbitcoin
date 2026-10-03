//! Frigate `blockchain.silentpayments.subscribe` (session-only scan key).

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Network;
use rbitcoin_consensus::{taproot_matches_scan, tweaks_for_height, ChainParams};
use rbitcoin_primitives::{hex_decode, Height};
use rbitcoin_query::Query;
use serde_json::{json, Value};

/// Heights scanned when the client omits a start or passes 0.
pub const SP_HISTORY_WINDOW: u32 = 256;
/// Heights held under one scan permit before the next chunk.
pub const SP_SCAN_CHUNK: u32 = 256;
/// Process-wide historical scans. Not a knob.
pub const SP_SCAN_PERMITS: usize = 3;

#[derive(Clone)]
pub struct SpSub {
    pub scan: SecretKey,
    pub spend: PublicKey,
    pub start: u32,
    pub labels: Vec<u32>,
    pub address: String,
}

pub fn parse_sub(params: &Value, network: Network, tip: Option<u32>) -> Result<SpSub, String> {
    let scan_hex = param_str(params, 0)?;
    let spend_hex = param_str(params, 1)?;
    let scan_bytes = hex_decode(scan_hex).map_err(|e| e.to_string())?;
    if scan_bytes.len() != 32 {
        return Err("scan_private_key must be 32 bytes".into());
    }
    let scan = SecretKey::from_slice(&scan_bytes).map_err(|e| e.to_string())?;
    let spend_bytes = hex_decode(spend_hex).map_err(|e| e.to_string())?;
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
    let start = start.min(tip.unwrap_or(start));
    // Any start, including a nonzero one, stays inside the recent window.
    let start = match tip {
        Some(tip_h) => start.max(tip_h.saturating_sub(SP_HISTORY_WINDOW)),
        None => start,
    };
    let address = encode_sp_address(network, &scan, &spend);
    Ok(SpSub {
        scan,
        spend,
        start,
        labels,
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
                    "tx_hash": rbitcoin_primitives::display_hash_hex(&txid),
                    "tweak_key": rbitcoin_primitives::hex_encode(tw.tweak),
                }));
            }
        }
    }
    Ok(hits)
}

fn tx_matches(sub: &SpSub, tw: &rbitcoin_consensus::TxTweak) -> bool {
    for o in &tw.output_pubkeys {
        for k in 0u32..8 {
            if taproot_matches_scan(&tw.tweak, &o.xonly, &sub.scan, &sub.spend, k) {
                return true;
            }
        }
        for &lab in &sub.labels {
            if lab > 0 && taproot_matches_scan(&tw.tweak, &o.xonly, &sub.scan, &sub.spend, lab) {
                return true;
            }
        }
    }
    false
}

fn encode_sp_address(network: Network, scan_sk: &SecretKey, spend: &PublicKey) -> String {
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

fn param_str(params: &Value, i: usize) -> Result<&str, String> {
    params
        .as_array()
        .and_then(|a| a.get(i))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "expected string".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use serde_json::json;

    #[test]
    fn parse_sub_rejects_short_scan_key() {
        let err = match parse_sub(&json!(["00", "02".repeat(33)]), Network::Regtest, Some(0)) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(err.contains("32 bytes"), "{err}");
        let _ = Secp256k1::new();
    }

    #[test]
    fn parse_sub_labels_start_and_networks() {
        let scan = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
        let spend = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
        let sub = parse_sub(
            &json!([scan, spend, "12-20", [0, 1, 1]]),
            Network::Bitcoin,
            Some(100),
        )
        .unwrap();
        assert_eq!(sub.start, 12);
        assert_eq!(sub.labels, vec![0, 1]);
        assert!(sub.address.starts_with("sp1"), "{}", sub.address);
        let tsp = parse_sub(&json!([scan, spend]), Network::Signet, Some(3)).unwrap();
        assert!(tsp.address.starts_with("tsp1"), "{}", tsp.address);
        let t4 = parse_sub(&json!([scan, spend]), Network::Testnet4, Some(3)).unwrap();
        assert!(t4.address.starts_with("tsp"), "{}", t4.address);
        let tn = parse_sub(&json!([scan, spend]), Network::Testnet, Some(3)).unwrap();
        assert!(tn.address.starts_with("tsp"), "{}", tn.address);
        let no_tip = parse_sub(&json!([scan, spend, 50]), Network::Regtest, None).unwrap();
        assert_eq!(no_tip.start, 50);
        let null_start = parse_sub(&json!([scan, spend, null]), Network::Regtest, Some(3)).unwrap();
        assert_eq!(null_start.start, 0);
        let bounded = parse_sub(&json!([scan, spend, 0]), Network::Regtest, Some(1_000)).unwrap();
        assert_eq!(bounded.start, 1_000 - SP_HISTORY_WINDOW);
        let wide = parse_sub(&json!([scan, spend, 1]), Network::Regtest, Some(10_000)).unwrap();
        assert_eq!(wide.start, 10_000 - SP_HISTORY_WINDOW);
        assert!(10_000 - wide.start <= SP_HISTORY_WINDOW);
        let bad_spend = match parse_sub(&json!([scan, "02"]), Network::Regtest, Some(0)) {
            Err(e) => e,
            Ok(_) => panic!("spend"),
        };
        assert!(!bad_spend.is_empty(), "{bad_spend}");
        let ts = match parse_sub(
            &json!([scan, spend, 600_000_000]),
            Network::Regtest,
            Some(0),
        ) {
            Err(e) => e,
            Ok(_) => panic!("timestamp"),
        };
        assert!(ts.contains("timestamp"), "{ts}");
        let many = json!([scan, spend, 0, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]);
        let too = match parse_sub(&many, Network::Regtest, Some(0)) {
            Err(e) => e,
            Ok(_) => panic!("labels"),
        };
        assert!(too.contains("too many"), "{too}");
        let r = subscribe_result(&sub);
        assert_eq!(r["start_height"], 12);
        let plain = parse_sub(
            &json!([scan, spend, "12", ["x", 2]]),
            Network::Regtest,
            Some(20),
        )
        .unwrap();
        assert_eq!(plain.start, 12);
        assert_eq!(plain.labels, vec![0, 2]);
        let clamp = parse_sub(&json!([scan, spend, 100]), Network::Regtest, Some(3)).unwrap();
        assert_eq!(clamp.start, 3);
        let bool_start = parse_sub(&json!([scan, spend, true]), Network::Regtest, Some(0)).unwrap();
        assert_eq!(bool_start.start, 0);
    }

    #[test]
    fn tx_matches_bip352_simple_send() {
        let scan = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
        let spend = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
        let sub = parse_sub(&json!([scan, spend, 0, [0, 1]]), Network::Regtest, Some(0)).unwrap();
        let tweak =
            hex_decode("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004")
                .unwrap();
        let xonly =
            hex_decode("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1").unwrap();
        let mut tw33 = [0u8; 33];
        tw33.copy_from_slice(&tweak);
        let mut x32 = [0u8; 32];
        x32.copy_from_slice(&xonly);
        let hit = rbitcoin_consensus::TxTweak {
            tweak: tw33,
            output_pubkeys: vec![rbitcoin_consensus::TaprootOut {
                vout: 0,
                xonly: x32,
                value: 1,
            }],
        };
        assert!(tx_matches(&sub, &hit));
        let miss = rbitcoin_consensus::TxTweak {
            tweak: tw33,
            output_pubkeys: vec![rbitcoin_consensus::TaprootOut {
                vout: 0,
                xonly: [0u8; 32],
                value: 1,
            }],
        };
        assert!(!tx_matches(&sub, &miss));
    }
}
