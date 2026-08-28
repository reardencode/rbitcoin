//! `blockchain.tweaks.subscribe` (naive, uncached).
//!
//! Stream: JSON-RPC result is the first height; remaining heights are
//! notifications; `{"message":"done"}` ends the run. Cake Wallet and
//! kiss-bdk scan locally from tweak + txid + taproot outs. Pre-taproot empty
//! maps collapse into one notify (≤1024 keys). `historicalMode=false` omits
//! confirmed-spent P2TR outs.

use rbitcoin_consensus::{tweaks_for_height, ChainParams, TxTweak};
#[cfg(test)]
use rbitcoin_primitives::hex_encode;
use rbitcoin_primitives::Height;
use rbitcoin_query::{Query, ThinTweakRangeLimits, ThinTweakRow};
#[cfg(test)]
use serde_json::Map;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Instant;

/// Parsed `blockchain.tweaks.subscribe` window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TweakReq {
    pub start: u32,
    /// Requested height count (scan sends tip − restore). Served through tip.
    pub count: u32,
    /// Cake `historicalMode`. `false` → cut-through spent P2TR outs.
    pub historical: bool,
}

pub fn parse_req(params: &Value) -> Result<TweakReq, String> {
    let start = param_u32(params, 0)?;
    let count = param_u32(params, 1).unwrap_or(1).max(1);
    let historical = param_bool(params, 2).unwrap_or(false);
    Ok(TweakReq {
        start,
        count,
        historical,
    })
}

/// Inclusive last height to serve (`start` if `count==1`), not past tip.
pub fn last_height(start: u32, count: u32, tip: Option<u32>) -> Option<u32> {
    let tip = tip?;
    if start > tip {
        return None;
    }
    Some(start.saturating_add(count.saturating_sub(1)).min(tip))
}

/// One height key → txs. Cake `fromJson` uses the **last** map key as `block`.
pub fn height_map(
    query: &Query,
    chain: &ChainParams,
    h: u32,
    cut_through: bool,
) -> Result<Value, String> {
    let s = height_map_json(query, chain, h, cut_through)?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

/// Cake height map as JSON text (no `serde_json::Value` tree).
pub fn height_map_json(
    query: &Query,
    chain: &ChainParams,
    h: u32,
    cut_through: bool,
) -> Result<String, String> {
    let tip = query.tip_height().map(|t| t.0);
    if tip.is_none_or(|t| h > t) || !chain.taproot_active_at(h) {
        return Ok(empty_height_json(h));
    }
    let limits = ThinTweakRangeLimits {
        max_heights: 1,
        max_eligible: usize::MAX,
        cut_through,
    };
    match query.load_thin_tweaks_range(Height(h), limits) {
        Ok(mut batch) if !batch.is_empty() => {
            let rows = batch.pop().map(|(_, r)| r).unwrap_or_default();
            Ok(encode_thin_height_json(h, &rows))
        }
        Ok(_) => {
            let mut tweaks =
                tweaks_for_height(query, chain, Height(h)).map_err(|e| e.to_string())?;
            if cut_through {
                retain_unspent_taproot(query, Height(h), &mut tweaks)?;
            }
            let mut s = String::new();
            s.push('{');
            push_quoted_u32(&mut s, h);
            s.push(':');
            push_height_object_json(&mut s, &tweaks);
            s.push('}');
            Ok(s)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Electrum notify line for one height (json-rpc wrapper + newline not included).
pub fn height_notify_json(
    query: &Query,
    chain: &ChainParams,
    h: u32,
    cut_through: bool,
) -> Result<String, String> {
    let map = height_map_json(query, chain, h, cut_through)?;
    Ok(wrap_height_notify(&map))
}

fn wrap_height_notify(map_json: &str) -> String {
    let mut s = String::with_capacity(map_json.len() + 80);
    s.push_str("{\"jsonrpc\":\"2.0\",\"method\":\"blockchain.tweaks.subscribe\",\"params\":[");
    s.push_str(map_json);
    s.push_str("]}");
    s
}

/// Spawn wave N+1 before writing wave N. `spawn_load(h)` must start work
/// immediately (e.g. `spawn_blocking`), not when the wait future is polled.
#[cfg(test)]
pub async fn overlap_wave_writes<E, Spawn, H, Wait, WF, Write, WR>(
    mut start: u32,
    last: u32,
    mut spawn_load: Spawn,
    mut wait_load: Wait,
    mut write: Write,
) -> Result<(), E>
where
    Spawn: FnMut(u32) -> H,
    Wait: FnMut(H) -> WF,
    WF: std::future::Future<Output = Result<Option<Vec<String>>, E>>,
    Write: FnMut(Vec<String>) -> WR,
    WR: std::future::Future<Output = Result<(), E>>,
{
    if start > last {
        return Ok(());
    }
    let mut pending = Some(spawn_load(start));
    while let Some(job) = pending.take() {
        let Some(batch) = wait_load(job).await? else {
            return Ok(());
        };
        let n = batch.len() as u32;
        let next = start.saturating_add(n.max(1));
        if next <= last {
            pending = Some(spawn_load(next));
        }
        write(batch).await?;
        start = next;
    }
    Ok(())
}

/// Default multi-height load budgets for subscribe (max 128 heights, 16384 eligible).
pub fn subscribe_range_limits() -> ThinTweakRangeLimits {
    ThinTweakRangeLimits::default()
}

/// Serve budgets plus Cake cut-through when `historical` is false.
pub fn subscribe_serve_limits(historical: bool) -> ThinTweakRangeLimits {
    ThinTweakRangeLimits {
        cut_through: !historical,
        ..ThinTweakRangeLimits::default()
    }
}

/// First JSON-RPC height plus remaining notifies of the same thin wave.
pub struct FirstWave {
    pub result_json: String,
    pub rest_notifies: Vec<String>,
    pub consumed: u32,
}

/// One remaining-wave write: `consumed` heights, possibly fewer JSON lines
/// (pre-taproot empty maps collapse into one notify).
pub struct NotifyWave {
    pub lines: Vec<String>,
    pub consumed: u32,
}

/// Indexed: one thin batch starting at `start`. Pre-taproot / hole: first
/// height only (`consumed == 1`).
pub fn first_subscribe_wave(
    query: &Query,
    chain: &ChainParams,
    start: u32,
    last: u32,
    limits: ThinTweakRangeLimits,
) -> Result<FirstWave, String> {
    if start > last {
        return Ok(FirstWave {
            result_json: empty_height_json(start),
            rest_notifies: Vec::new(),
            consumed: 1,
        });
    }
    if !chain.taproot_active_at(start) {
        return Ok(FirstWave {
            result_json: empty_height_json(start),
            rest_notifies: Vec::new(),
            consumed: 1,
        });
    }
    let thin = load_thin_batch(query, start, last, limits)?;
    if thin.is_empty() {
        return Ok(FirstWave {
            result_json: height_map_json(query, chain, start, limits.cut_through)?,
            rest_notifies: Vec::new(),
            consumed: 1,
        });
    }
    let (h0, rows0) = &thin[0];
    debug_assert_eq!(*h0, start);
    let rest_notifies = thin[1..]
        .iter()
        .map(|(h, rows)| thin_height_notify_json(*h, rows))
        .collect();
    Ok(FirstWave {
        result_json: encode_thin_height_json(*h0, rows0),
        rest_notifies,
        consumed: thin.len() as u32,
    })
}

/// Pre-taproot empty notifies per write (no store). Mainnet genesis→origin
/// is ~700k heights; one flush per height is the 10/s-class path. One notify
/// carries up to this many empty height keys (Cake `fromJson` last key = progress).
pub const EMPTY_WAVE_HEIGHTS: u32 = 1024;

/// Inclusive last height of a pre-taproot empty wave, if `start` is below
/// taproot. `None` when taproot is already active at `start` (incl. regtest).
pub fn pre_taproot_wave_last(start: u32, last: u32, taproot_h: u32) -> Option<u32> {
    if start >= taproot_h {
        return None;
    }
    let cap = start.saturating_add(EMPTY_WAVE_HEIGHTS.saturating_sub(1));
    Some(last.min(taproot_h.saturating_sub(1)).min(cap))
}

/// One subscribe wave of notify lines starting at `start`.
///
/// Pre-taproot: one notify whose params map has every empty height in the
/// wave (Cake last-key progress). Indexed: thin batch, one line per height.
/// Hole: one naive/thin height.
pub fn remaining_notify_lines(
    query: &Query,
    chain: &ChainParams,
    start: u32,
    last: u32,
    limits: ThinTweakRangeLimits,
) -> Result<NotifyWave, String> {
    if start > last {
        return Ok(NotifyWave {
            lines: Vec::new(),
            consumed: 0,
        });
    }
    if let Some(end) = pre_taproot_wave_last(start, last, chain.taproot_height()) {
        let consumed = end.saturating_sub(start).saturating_add(1);
        return Ok(NotifyWave {
            lines: vec![wrap_height_notify(&empty_heights_json(start, end))],
            consumed,
        });
    }
    let thin = load_thin_batch(query, start, last, limits)?;
    if thin.is_empty() {
        return Ok(NotifyWave {
            lines: vec![height_notify_json(query, chain, start, limits.cut_through)?],
            consumed: 1,
        });
    }
    let consumed = thin.len() as u32;
    Ok(NotifyWave {
        lines: thin
            .into_iter()
            .map(|(h, rows)| thin_height_notify_json(h, &rows))
            .collect(),
        consumed,
    })
}

/// Load a budgeted contiguous thin-index batch starting at `start`.
///
/// Empty → first height not indexed (caller uses per-height naive/thin).
/// Otherwise each entry is an indexed height (possibly zero eligible rows).
pub fn load_thin_batch(
    query: &Query,
    start: u32,
    last: u32,
    limits: ThinTweakRangeLimits,
) -> Result<Vec<(u32, Vec<ThinTweakRow>)>, String> {
    if start > last {
        return Ok(Vec::new());
    }
    let max_h = last.saturating_sub(start).saturating_add(1);
    let limits = ThinTweakRangeLimits {
        max_heights: limits.max_heights.min(max_h),
        ..limits
    };
    let batch = query
        .load_thin_tweaks_range(Height(start), limits)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_iter().map(|(h, rows)| (h.0, rows)).collect())
}

/// Notify JSON for one thin-index height map.
pub fn thin_height_notify_json(h: u32, rows: &[ThinTweakRow]) -> String {
    wrap_height_notify(&encode_thin_height_json(h, rows))
}

fn empty_height_json(h: u32) -> String {
    empty_heights_json(h, h)
}

fn empty_heights_json(first: u32, last: u32) -> String {
    let n = last.saturating_sub(first).saturating_add(1) as usize;
    let mut s = String::with_capacity(n.saturating_mul(12).saturating_add(2));
    s.push('{');
    for h in first..=last {
        if h > first {
            s.push(',');
        }
        push_quoted_u32(&mut s, h);
        s.push_str(":{}");
    }
    s.push('}');
    s
}

fn retain_unspent_taproot(
    query: &Query,
    height: Height,
    tweaks: &mut BTreeMap<[u8; 32], TxTweak>,
) -> Result<(), String> {
    let fks = query.block_tx_fks(height).map_err(|e| e.to_string())?;
    for fk in fks {
        let txid = query.store().txs.body_txid(fk).map_err(|e| e.to_string())?;
        let Some(t) = tweaks.get_mut(&txid) else {
            continue;
        };
        if t.output_pubkeys.is_empty() {
            continue;
        }
        let vouts: Vec<u32> = t.output_pubkeys.iter().map(|o| o.vout).collect();
        let live = query
            .unspent_create_vouts(fk, &vouts)
            .map_err(|e| e.to_string())?;
        t.output_pubkeys
            .retain(|o| live.iter().any(|v| *v == o.vout));
    }
    tweaks.retain(|_, t| !t.output_pubkeys.is_empty());
    Ok(())
}

pub(crate) fn encode_thin_height_json(h: u32, rows: &[rbitcoin_query::ThinTweakRow]) -> String {
    let mut s = String::with_capacity(64 + rows.len() * 192);
    s.push('{');
    push_quoted_u32(&mut s, h);
    s.push_str(":{");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        push_txid_display_hex(&mut s, &r.txid);
        s.push_str("\":{\"tweak\":\"");
        push_hex(&mut s, &r.tweak);
        s.push_str("\",\"output_pubkeys\":{");
        for (j, (vout, xonly, value)) in r.p2tr.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push('"');
            let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{vout}"));
            s.push_str("\":[\"");
            push_hex(&mut s, xonly);
            s.push_str("\",");
            let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{value}"));
            s.push(']');
        }
        s.push_str("}}");
    }
    s.push_str("}}");
    s
}

fn push_height_object_json(s: &mut String, tweaks: &std::collections::BTreeMap<[u8; 32], TxTweak>) {
    s.push('{');
    for (i, (txid, t)) in tweaks.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        push_txid_display_hex(s, txid);
        s.push_str("\":{\"tweak\":\"");
        push_hex(s, &t.tweak);
        s.push_str("\",\"output_pubkeys\":{");
        for (j, o) in t.output_pubkeys.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push('"');
            let _ = core::fmt::Write::write_fmt(s, format_args!("{}", o.vout));
            s.push_str("\":[\"");
            push_hex(s, &o.xonly);
            s.push_str("\",");
            let _ = core::fmt::Write::write_fmt(s, format_args!("{}", o.value));
            s.push(']');
        }
        s.push_str("}}");
    }
    s.push('}');
}

fn push_quoted_u32(s: &mut String, n: u32) {
    s.push('"');
    let _ = core::fmt::Write::write_fmt(s, format_args!("{n}"));
    s.push('"');
}

fn push_hex(s: &mut String, data: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    s.reserve(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
}

fn push_txid_display_hex(s: &mut String, txid: &[u8; 32]) {
    let mut r = *txid;
    r.reverse();
    push_hex(s, &r);
}

/// Cake `noData` / resubscribe signal (`fromJson` catch path reads `message`).
pub fn done_notify() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "blockchain.tweaks.subscribe",
        "params": [{"message": "done"}],
    })
}

/// JSON-RPC **result** is the **first** height only. Further heights are
/// notifications from the server loop.
pub fn subscribe(query: &Query, params: &Value, chain: &ChainParams) -> Result<Value, String> {
    let req = parse_req(params)?;
    let t0 = Instant::now();
    let map = height_map(query, chain, req.start, !req.historical)?;
    rbitcoin_log::trace!(
        "electrum: tweaks h={} count={} result_keys={} wall_ms={}",
        req.start,
        req.count,
        map.as_object().map(|o| o.len()).unwrap_or(0),
        t0.elapsed().as_millis()
    );
    Ok(map)
}

#[cfg(test)]
pub fn height_object(tweaks: &std::collections::BTreeMap<[u8; 32], TxTweak>) -> Value {
    let mut txs = Map::new();
    for (txid, t) in tweaks {
        txs.insert(txid_display_hex(txid), encode_tx_tweak(t));
    }
    Value::Object(txs)
}

#[cfg(test)]
pub fn encode_tx_tweak(t: &TxTweak) -> Value {
    let mut outs = Map::new();
    for o in &t.output_pubkeys {
        outs.insert(o.vout.to_string(), json!([hex_encode(o.xonly), o.value]));
    }
    json!({
        "tweak": hex_encode(t.tweak),
        "output_pubkeys": Value::Object(outs),
    })
}

#[cfg(test)]
fn txid_display_hex(txid: &[u8; 32]) -> String {
    let mut r = *txid;
    r.reverse();
    hex_encode(r)
}

fn param_u32(params: &Value, idx: usize) -> Result<u32, String> {
    params
        .as_array()
        .and_then(|a| a.get(idx))
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u32)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| format!("param {idx} expected number"))
}

fn param_bool(params: &Value, idx: usize) -> Option<bool> {
    params.as_array().and_then(|a| a.get(idx)).and_then(|v| {
        v.as_bool()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cake_probe_fixture_is_empty_height_map() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tweaks_cake_probe.json"
        ));
        let v: Value = serde_json::from_str(raw).unwrap();
        assert!(v.get("0").unwrap().as_object().unwrap().is_empty());
    }

    #[test]
    fn cake_850000_sample_encoding() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tweaks_cake_850000_sample.json"
        ));
        let v: Value = serde_json::from_str(raw).unwrap();
        let tx = &v["850000"]["0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078"];
        let tweak = tx["tweak"].as_str().unwrap();
        assert_eq!(tweak.len(), 66);
        assert!(tweak.starts_with("02") || tweak.starts_with("03"));
        let pk = tx["output_pubkeys"]["1"][0].as_str().unwrap();
        assert_eq!(pk.len(), 64);
        assert_eq!(tx["output_pubkeys"]["1"][1], 5410);
    }

    #[test]
    fn subscribe_range_limits_matches_query_default() {
        assert_eq!(subscribe_range_limits(), ThinTweakRangeLimits::default());
        assert_eq!(subscribe_range_limits().max_eligible, 16384);
        assert_eq!(subscribe_range_limits().max_heights, 128);
        assert!(!subscribe_range_limits().cut_through);
        assert!(subscribe_serve_limits(false).cut_through);
        assert!(!subscribe_serve_limits(true).cut_through);
    }

    #[test]
    fn parse_req_historical_defaults_false() {
        let r = parse_req(&json!([10, 3])).unwrap();
        assert_eq!(
            r,
            TweakReq {
                start: 10,
                count: 3,
                historical: false
            }
        );
        let h = parse_req(&json!([10, 3, true])).unwrap();
        assert!(h.historical);
        let c = parse_req(&json!([0, 1, false])).unwrap();
        assert!(!c.historical);
    }

    #[test]
    fn last_height_stops_at_tip() {
        assert_eq!(last_height(880_791, 81_427, Some(962_217)), Some(962_217));
        assert_eq!(last_height(10, 3, Some(11)), Some(11));
        assert_eq!(last_height(10, 1, Some(100)), Some(10));
        assert_eq!(last_height(50, 1, Some(10)), None);
        assert_eq!(last_height(0, 1, None), None);
    }

    #[test]
    fn pre_taproot_wave_covers_1024_then_stops_at_activation() {
        assert_eq!(pre_taproot_wave_last(0, 10, 709_632), Some(10));
        assert_eq!(pre_taproot_wave_last(0, 2_000, 709_632), Some(1023));
        assert_eq!(
            pre_taproot_wave_last(709_000, 800_000, 709_632),
            Some(709_631)
        );
        assert_eq!(pre_taproot_wave_last(709_632, 800_000, 709_632), None);
        assert_eq!(pre_taproot_wave_last(0, 100, 0), None);
    }

    #[test]
    fn first_subscribe_wave_indexed_shares_batch_and_pre_taproot_is_empty() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::{Query, TxApply};
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-electrum-first-wave-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..4u32 {
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version: 1,
                timestamp: h + 1,
                bits: 0x207fffff,
                nonce: h,
                merkle_root: merkle,
                hash,
            };
            let mut txid = [0u8; 32];
            txid[0..4].copy_from_slice(&h.to_le_bytes());
            txid[31] = 0xcb;
            let ta = TxApply {
                tx: TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            parent_hash = Some(hash);
            q.put_sp_tweaks_block(Height(h), prev, &[None]).unwrap();
        }

        let chain = ChainParams::regtest();
        let wave = first_subscribe_wave(&q, &chain, 1, 3, subscribe_range_limits()).unwrap();
        let result: Value = serde_json::from_str(&wave.result_json).unwrap();
        assert_eq!(result.as_object().unwrap().len(), 1);
        assert!(result.get("1").unwrap().as_object().unwrap().is_empty());
        assert_eq!(wave.consumed, 3);
        assert_eq!(wave.rest_notifies.len(), 2);
        for (i, line) in wave.rest_notifies.iter().enumerate() {
            let v: Value = serde_json::from_str(line).unwrap();
            let h = (i + 2).to_string();
            assert_eq!(v["method"], "blockchain.tweaks.subscribe");
            assert!(v["params"][0][&h].as_object().unwrap().is_empty(), "{v}");
        }
        let thin1 = q.load_thin_tweaks(Height(1)).unwrap().expect("indexed");
        assert_eq!(encode_thin_height_json(1, &thin1), wave.result_json);

        let main = ChainParams::mainnet();
        let pre = first_subscribe_wave(&q, &main, 0, 10, subscribe_range_limits()).unwrap();
        assert_eq!(pre.consumed, 1);
        assert!(pre.rest_notifies.is_empty());
        let pre_v: Value = serde_json::from_str(&pre.result_json).unwrap();
        assert!(pre_v["0"].as_object().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_lines_pre_taproot_are_one_empty_wave() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::{Query, TxApply};
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-electrum-empty-wave-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        q.set_sptweaks_enabled(true, Height(10_000)).unwrap();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..8u32 {
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version: 1,
                timestamp: h + 1,
                bits: 0x207fffff,
                nonce: h,
                merkle_root: merkle,
                hash,
            };
            let mut txid = [0u8; 32];
            txid[0..4].copy_from_slice(&h.to_le_bytes());
            txid[31] = 0xcb;
            let ta = TxApply {
                tx: TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            parent_hash = Some(hash);
        }
        let chain = ChainParams::mainnet();
        let wave = remaining_notify_lines(&q, &chain, 1, 7, subscribe_range_limits()).unwrap();
        assert_eq!(wave.consumed, 7);
        assert_eq!(wave.lines.len(), 1);
        let v: Value = serde_json::from_str(&wave.lines[0]).unwrap();
        assert_eq!(v["method"], "blockchain.tweaks.subscribe");
        let map = v["params"][0].as_object().expect("collapsed empty map");
        assert_eq!(map.len(), 7, "{v}");
        for h in 1u32..=7 {
            assert!(
                map.get(&h.to_string())
                    .and_then(|x| x.as_object())
                    .is_some_and(|o| o.is_empty()),
                "{v}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn height_map_cut_through_omits_spent_p2tr() {
        use bitcoin::hashes::{hash160, Hash};
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-electrum-cut-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let mut merkle0 = [0u8; 32];
        merkle0[5] = 0xec;
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle0,
            hash: merkle0,
        };
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
                }],
            )
            .unwrap();
        q.put_sp_tweaks_block(Height(0), fk0, &[None]).unwrap();
        let create0 = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: fk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let fk1 = q
            .connect_block(
                Height(1),
                &h1,
                &[TxApply {
                    tx: TxRecord {
                        txid: spend_txid,
                        version: 2,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord {
                        prev_txid: genesis_txid,
                        create_fk: create0,
                        prev_index: 0,
                        sequence: u32::MAX,
                        script_sig: vec![],
                        witness: vec![vec![0u8; 64], ser.to_vec()],
                    }],
                    outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr)],
                }],
            )
            .unwrap();
        let mut tw = [0x02; 33];
        tw[0] = 0x02;
        q.put_sp_tweaks_block(Height(1), fk1, &[Some(tw)]).unwrap();
        let chain = ChainParams::regtest();
        let live = height_map_json(&q, &chain, 1, true).unwrap();
        let live_v: Value = serde_json::from_str(&live).unwrap();
        assert_eq!(live_v["1"].as_object().unwrap().len(), 1);

        let elig_fk = q.block_tx_fks(Height(1)).unwrap()[0];
        let mut spend2 = [0u8; 32];
        spend2[0] = 0x22;
        let hash2 = rbitcoin_store::block_header_hash(1, &h1.hash, &[0x22; 32], 3, 0x207fffff, 2);
        let h2 = HeaderRecord {
            prev_fk: fk1,
            version: 1,
            timestamp: 3,
            bits: 0x207fffff,
            nonce: 2,
            merkle_root: [0x22; 32],
            hash: hash2,
        };
        q.connect_block(
            Height(2),
            &h2,
            &[TxApply {
                tx: TxRecord {
                    txid: spend2,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: spend_txid,
                    create_fk: elig_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![vec![0u8; 64]],
                }],
                outputs: vec![OutputRecord::unspent(48_0000_0000, p2wpkh)],
            }],
        )
        .unwrap();

        let cut = height_map_json(&q, &chain, 1, true).unwrap();
        let cut_v: Value = serde_json::from_str(&cut).unwrap();
        assert!(
            cut_v["1"].as_object().unwrap().is_empty(),
            "cut-through must omit spent p2tr, got {cut}"
        );
        let hist = height_map_json(&q, &chain, 1, false).unwrap();
        let hist_v: Value = serde_json::from_str(&hist).unwrap();
        assert_eq!(hist_v["1"].as_object().unwrap().len(), 1, "{hist}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn done_notify_is_cake_message() {
        let v = done_notify();
        assert_eq!(v["method"], "blockchain.tweaks.subscribe");
        assert_eq!(v["params"][0]["message"], "done");
    }

    #[test]
    fn thin_json_matches_value_encoder() {
        let mut tweak = [0u8; 33];
        tweak[0] = 0x02;
        tweak[1] = 0xaa;
        let mut txid = [0u8; 32];
        txid[0] = 0x11;
        let row = rbitcoin_query::ThinTweakRow {
            txid,
            tweak,
            p2tr: vec![(1, [0x5f; 32], 5410)],
        };
        let s = encode_thin_height_json(850_000, &[row]);
        let v: Value = serde_json::from_str(&s).unwrap();
        let t = TxTweak {
            tweak,
            output_pubkeys: vec![rbitcoin_consensus::TaprootOut {
                vout: 1,
                xonly: [0x5f; 32],
                value: 5410,
            }],
        };
        let mut map = std::collections::BTreeMap::new();
        map.insert(txid, t);
        let expect = json!({ "850000": height_object(&map) });
        assert_eq!(v, expect);
    }

    #[test]
    fn encode_tx_tweak_xonly_and_33_byte() {
        let t = TxTweak {
            tweak: {
                let mut a = [0u8; 33];
                a[0] = 0x02;
                a[1] = 0xaa;
                a
            },
            output_pubkeys: vec![rbitcoin_consensus::TaprootOut {
                vout: 1,
                xonly: [0x5f; 32],
                value: 5410,
            }],
        };
        let v = encode_tx_tweak(&t);
        assert_eq!(v["tweak"].as_str().unwrap().len(), 66);
        assert!(v["tweak"].as_str().unwrap().starts_with("02"));
        assert_eq!(v["output_pubkeys"]["1"][0].as_str().unwrap().len(), 64);
        assert_eq!(v["output_pubkeys"]["1"][1], 5410);
    }

    #[tokio::test]
    async fn overlap_wave_writes_starts_next_load_before_write_returns() {
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        let load_starts = Arc::new(Mutex::new(Vec::<Instant>::new()));
        let write_ends = Arc::new(Mutex::new(Vec::<Instant>::new()));
        let ls = Arc::clone(&load_starts);
        let we = Arc::clone(&write_ends);

        overlap_wave_writes(
            0,
            1,
            move |h| {
                let ls = Arc::clone(&ls);
                tokio::spawn(async move {
                    ls.lock().unwrap().push(Instant::now());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok::<_, String>(vec![h.to_string()])
                })
            },
            |join| async move { join.await.unwrap().map(Some) },
            move |batch| {
                let we = Arc::clone(&we);
                async move {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    we.lock().unwrap().push(Instant::now());
                    let _ = batch;
                    Ok::<_, String>(())
                }
            },
        )
        .await
        .unwrap();

        let starts = load_starts.lock().unwrap();
        let ends = write_ends.lock().unwrap();
        assert_eq!(starts.len(), 2);
        assert_eq!(ends.len(), 2);
        assert!(
            starts[1] < ends[0],
            "wave 1 load must start before wave 0 write returns"
        );
    }
}
