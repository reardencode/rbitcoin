//! Esplora route handlers beyond tip/header/basic tx.

use crate::server::{
    block_hash_hex, json_reply_here, json_reply_shared, maybe_attach_view, mempool_wire, not_found,
    parse_hash32, pin_or_reject, plain_ok, store_err, AppState, AsOf, GbtCache, JoinClient,
};
use crate::tx_json::{
    build_tx_json, build_tx_json_from_tx, history_items_to_tx_json, tx_status_json_in,
    utxo_list_json, vout_fields,
};
use axum::body::Bytes;
use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bitcoin::address::Address;
use bitcoin::consensus::{deserialize, encode::serialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{MerkleBlock, Network, OutPoint, Txid};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{Fk, Height};

use rbitcoin_query::{
    ChainView, ChainViewKind, HistoryFilter, Query, ScriptHashChainStats, ScriptHashTxSummary,
    ShJoinSlot,
};
use rbitcoin_store::{script_hash, StoreError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[doc(hidden)]
pub const MULTI_ADDRESS_LIMIT: usize = 300;
/// Esplora mempool history on `/txs` and `/txs/mempool`.
#[doc(hidden)]
pub const MEMPOOL_TX_PAGE: usize = 50;

#[doc(hidden)]
pub type JoinBag = HashMap<[u8; 32], Arc<ShJoinSlot>>;

/// Best-chain wire block for Esplora (archived reconstruct; no extra PoW rehash gate).
#[doc(hidden)]
pub fn best_chain_block(
    query: &Query,
    hash: &[u8; 32],
) -> Result<(Height, bitcoin::Block), rbitcoin_query::QueryError> {
    let Some(height) = query.height_of_hash(hash)? else {
        return Err(rbitcoin_store::StoreError::NotFound);
    };
    // Prefer archived path: does not re-require stored.hash == wire block_hash
    // (synthetic fixture headers use lab hashes; production hashes match).
    let block = query
        .reconstruct_archived_block(hash)?
        .ok_or(rbitcoin_store::StoreError::NotFound)?;
    Ok((height, block))
}

/// Esplora `GET /block/:hash` JSON for a **best-chain** header hash.
pub fn block_summary_json(
    query: &Query,
    hash: &[u8; 32],
) -> Result<Value, rbitcoin_query::QueryError> {
    let Some(height) = query.height_of_hash(hash)? else {
        return Err(rbitcoin_store::StoreError::NotFound);
    };
    let (header_fk, rec) = query
        .header_at_height(height)?
        .ok_or(rbitcoin_store::StoreError::NotFound)?;
    let prev_hash = if rec.prev_fk.is_null() {
        [0u8; 32]
    } else {
        query.store().get_header(rec.prev_fk)?.hash
    };
    let tx_count = query
        .store()
        .header_txs
        .get_range(header_fk)?
        .map(|(_, n)| n)
        .unwrap_or(0);
    let (size, weight) = query
        .block_size_weight(header_fk)?
        .ok_or(rbitcoin_store::StoreError::NotFound)?;
    let difficulty =
        Target::from_compact(CompactTarget::from_consensus(rec.bits)).difficulty_float();
    let mediantime = block_median_time(query, height)?;
    Ok(json!({
        "id": block_hash_hex(hash),
        "height": height.0,
        "version": rec.version,
        "timestamp": rec.timestamp,
        "tx_count": tx_count,
        "size": size,
        "weight": weight,
        "merkle_root": block_hash_hex(&rec.merkle_root),
        "previousblockhash": if height.0 == 0 {
            Value::Null
        } else {
            json!(block_hash_hex(&prev_hash))
        },
        "mediantime": mediantime,
        "nonce": rec.nonce,
        "bits": rec.bits,
        "difficulty": difficulty,
    }))
}

/// Block-summary median time.
///
/// [`rbitcoin_query::median_time_past`] owns the window, including an MTP-cache
/// hit. A missing best-chain header in that window stays [`StoreError::NotFound`]:
/// a confirm-parent plan or a warm cache must not fill a hole the old walk
/// reported missing. `BadPrev` on that gap is the same 404, not HTTP 500.
#[doc(hidden)]
pub fn block_median_time(query: &Query, height: Height) -> Result<u32, StoreError> {
    if best_chain_window_has_a_hole(query, height)? {
        return Err(StoreError::NotFound);
    }
    match rbitcoin_query::median_time_past(query, height) {
        Ok(t) => Ok(t),
        Err(rbitcoin_query::ConfirmError::Store(StoreError::Corrupt(
            "confirm: load incomplete (parent header plan missing above tip)",
        ))) => Err(StoreError::NotFound),
        Err(rbitcoin_query::ConfirmError::Store(e)) => Err(e),
        Err(rbitcoin_query::ConfirmError::Rules(rbitcoin_consensus::ConsensusError::BadPrev)) => {
            Err(StoreError::NotFound)
        }
        Err(rbitcoin_query::ConfirmError::Rules(_)) => {
            Err(StoreError::Corrupt("invariant: empty median time"))
        }
    }
}

/// Any missing header in the 11-block window is a hole. The query median
/// would otherwise read a confirm-parent plan or the MTP ring.
fn best_chain_window_has_a_hole(query: &Query, height: Height) -> Result<bool, StoreError> {
    let start = height.0.saturating_sub(10);
    for h in start..=height.0 {
        if query.header_at_height(Height(h))?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn block_json(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    let q = std::sync::Arc::clone(&st.query);
    spawn_join(move || match block_summary_json(&q, &hash) {
        Ok(v) => json_reply_here(v),
        Err(e) => store_err(e),
    })
    .await
}

pub async fn block_raw(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    let q = std::sync::Arc::clone(&st.query);
    spawn_join(move || match best_chain_block(&q, &hash) {
        Ok((_h, block)) => {
            let raw = serialize(&block);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                raw,
            )
                .into_response()
        }
        Err(e) => store_err(e),
    })
    .await
}

pub async fn block_status(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    let q = std::sync::Arc::clone(&st.query);
    spawn_join(move || {
        if q.get_header_by_hash(&hash).ok().flatten().is_none() {
            return not_found();
        }
        match q.height_of_hash(&hash) {
            Ok(None) => json_reply_here(json!({
                "in_best_chain": false,
                "height": null,
                "next_best": null,
            })),
            Ok(Some(h)) => {
                let next_best = if let Some(tip) = st.query.tip_height() {
                    if h.0 < tip.0 {
                        match st.query.header_at_height(Height(h.0 + 1)) {
                            Ok(Some((_fk, rec))) => json!(block_hash_hex(&rec.hash)),
                            _ => Value::Null,
                        }
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                };
                json_reply_here(json!({
                    "in_best_chain": true,
                    "height": h.0,
                    "next_best": next_best,
                }))
            }
            Err(e) => store_err(e),
        }
    })
    .await
}

pub(crate) async fn store_blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let store_permit = rbitcoin_net::acquire_armed_store_budget().await;
    tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::BlockingRegion::enter();
        let _store = store_permit;
        f()
    })
    .await
}

pub async fn block_txid_at(
    State(st): State<AppState>,
    Path((hash_hex, index)): Path<(String, u32)>,
) -> Response {
    spawn_join(move || {
        let Ok(hash) = parse_hash32(&hash_hex) else {
            return not_found();
        };
        let Some(height) = (match st.query.height_of_hash(&hash) {
            Ok(h) => h,
            Err(e) => return store_err(e),
        }) else {
            return not_found();
        };
        match st.query.block_txid_at(height, index as usize) {
            Ok(txid) => plain_ok(block_hash_hex(&txid)),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /blocks` — 10 newest from tip.
pub async fn blocks_tip(State(st): State<AppState>) -> Response {
    spawn_join(move || blocks_from(&st, None)).await
}

/// `GET /blocks/:start_height` — 10 blocks starting at `start_height` downward.
pub async fn blocks_from_height(State(st): State<AppState>, Path(start): Path<u32>) -> Response {
    spawn_join(move || blocks_from(&st, Some(start))).await
}

#[doc(hidden)]
pub fn blocks_from(st: &AppState, start: Option<u32>) -> Response {
    let Some(tip) = st.query.tip_height() else {
        return json_reply_here(json!([]));
    };
    let mut h = start.unwrap_or(tip.0);
    if h > tip.0 {
        h = tip.0;
    }
    let mut out = Vec::new();
    for _ in 0..10 {
        let height = Height(h);
        let Ok(Some((_fk, rec))) = st.query.header_at_height(height) else {
            break;
        };
        match block_summary_json(&st.query, &rec.hash) {
            Ok(v) => out.push(v),
            Err(e) => return store_err(e),
        }
        if h == 0 {
            break;
        }
        h -= 1;
    }
    json_reply_here(out)
}

pub async fn block_txids(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    spawn_join(move || {
        let Ok(hash) = parse_hash32(&hash_hex) else {
            return not_found();
        };
        let Some(h) = (match st.query.height_of_hash(&hash) {
            Ok(h) => h,
            Err(e) => return store_err(e),
        }) else {
            return not_found();
        };
        match st.query.block_txids(h) {
            Ok(ids) => json_reply_here(ids.iter().map(block_hash_hex).collect::<Vec<_>>()),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// Optional start index via path: `/block/:hash/txs` or `/block/:hash/txs/:start`.
pub async fn block_txs_start(
    State(st): State<AppState>,
    Path((hash_hex, start)): Path<(String, u32)>,
) -> Response {
    spawn_join(move || block_txs_impl(st, &hash_hex, start)).await
}

pub async fn block_txs_0(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    spawn_join(move || block_txs_impl(st, &hash_hex, 0)).await
}

#[doc(hidden)]
pub fn block_txs_impl(st: AppState, hash_hex: &str, start: u32) -> Response {
    if !start.is_multiple_of(25) {
        return (
            StatusCode::BAD_REQUEST,
            "start_index must be a multiple of 25",
        )
            .into_response();
    }
    let Ok(hash) = parse_hash32(hash_hex) else {
        return not_found();
    };
    let Some(h) = (match st.query.height_of_hash(&hash) {
        Ok(h) => h,
        Err(e) => return store_err(e),
    }) else {
        return not_found();
    };
    match st.query.block_tx_fks(h) {
        Ok(fks) => {
            if (start as usize) >= fks.len() {
                return (StatusCode::NOT_FOUND, "start index out of range").into_response();
            }
            let page: Vec<_> = fks.into_iter().skip(start as usize).take(25).collect();
            let mut out = Vec::with_capacity(page.len());
            for fk in page {
                match build_tx_json(&st.query, fk, st.network, None) {
                    Ok(v) => out.push(v),
                    Err(e) => return store_err(e),
                }
            }
            json_reply_here(out)
        }
        Err(e) => store_err(e),
    }
}

pub async fn tx_merkle_proof(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    spawn_join(move || tx_merkle_proof_sync(st, txid_hex)).await
}

#[doc(hidden)]
pub fn tx_merkle_proof_sync(st: AppState, txid_hex: String) -> Response {
    let Ok(txid) = parse_hash32(&txid_hex) else {
        return not_found();
    };
    let Ok(Some(fk)) = st.query.tx_fk_by_txid(&txid) else {
        return not_found();
    };
    let height = match st.query.store().tx_height_get(fk) {
        Ok(Some(h)) => h,
        Ok(None) => return not_found(),
        Err(e) => return store_err(e),
    };
    if !matches!(st.query.store().is_confirmed_strong(fk), Ok(true)) {
        return not_found();
    }
    match st.query.merkle_proof(Height(height), &txid) {
        Ok(proof) => {
            let merkle: Vec<String> = proof.merkle.iter().map(block_hash_hex).collect();
            json_reply_here(json!({
                "block_height": proof.block_height,
                "merkle": merkle,
                "pos": proof.pos,
            }))
        }
        Err(e) => store_err(e),
    }
}

/// `GET /tx/:txid/raw` — consensus-encoded transaction bytes.
pub async fn tx_raw(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match st.query.tx_wire_bytes(fk) {
                Ok(raw) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    raw,
                )
                    .into_response(),
                Err(e) => store_err(e),
            },
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    bitcoin::consensus::serialize(&tx),
                )
                    .into_response(),
                None => not_found(),
            },
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/merkleblock-proof` — BIP37 merkleblock as hex (Blockstream shape).
pub async fn tx_merkleblock_proof(
    State(st): State<AppState>,
    Path(txid_hex): Path<String>,
) -> Response {
    spawn_join(move || tx_merkleblock_proof_sync(st, txid_hex)).await
}

#[doc(hidden)]
pub fn tx_merkleblock_proof_sync(st: AppState, txid_hex: String) -> Response {
    let Ok(txid) = parse_hash32(&txid_hex) else {
        return not_found();
    };
    let Ok(Some(fk)) = st.query.tx_fk_by_txid(&txid) else {
        return not_found();
    };
    let height = match st.query.store().tx_height_get(fk) {
        Ok(Some(h)) => h,
        Ok(None) => return not_found(),
        Err(e) => return store_err(e),
    };
    if !matches!(st.query.store().is_confirmed_strong(fk), Ok(true)) {
        return not_found();
    }
    let proof = match st.query.merkle_proof(Height(height), &txid) {
        Ok(p) => p,
        Err(e) => return store_err(e),
    };
    let ids = match st.query.block_txids(Height(height)) {
        Ok(v) => v,
        Err(e) => return store_err(e),
    };
    let pos = proof.pos as usize;
    if pos >= ids.len() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "merkle pos out of range").into_response();
    }
    let mut header = match st.query.wire_header_at_height(Height(height)) {
        Ok(h) => h,
        Err(e) => return store_err(e),
    };
    header.merkle_root =
        bitcoin::TxMerkleNode::from_byte_array(rbitcoin_store::merkle_root_from_txids(&ids));
    let txids: Vec<bitcoin::Txid> = ids
        .iter()
        .copied()
        .map(bitcoin::Txid::from_byte_array)
        .collect();
    let want = bitcoin::Txid::from_byte_array(txid);
    let mb = MerkleBlock::from_header_txids_with_predicate(&header, &txids, |t| *t == want);
    let mut raw = Vec::new();
    if mb.consensus_encode(&mut raw).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "merkleblock encode").into_response();
    }
    plain_ok(rbitcoin_primitives::hex_encode(&(raw)))
}

/// One confirmed output: script, value, boolean `spent`, creating-tx `status`.
fn output_at_view(
    query: &Query,
    network: Network,
    fk: Fk,
    txid: &[u8; 32],
    vout: u32,
    view: &ChainView,
) -> Result<Value, StoreError> {
    let out = query.tx_output_at_fk(fk, vout)?;
    let spent = query.is_outpoint_spent_at(txid, vout, Some(view.height.0))?;
    let mut obj = vout_fields(&out.script, out.value, network);
    obj["spent"] = json!(spent);
    obj["status"] = tx_status_json_in(query, fk, view)?;
    Ok(obj)
}

fn genesis_coinbase(query: &Query, fk: Fk) -> Result<bool, StoreError> {
    let Some(0) = query.store().tx_height_get(fk)? else {
        return Ok(false);
    };
    query.is_coinbase_create(fk, 0)
}

#[allow(clippy::result_large_err)] // axum Response, same as pin_or_reject
fn pinned_tip(query: &Query, asof: Option<[u8; 32]>) -> Result<ChainView, Response> {
    match pin_or_reject(query, ChainViewKind::Tip, asof)? {
        Some(view) => Ok(view),
        None => Err(not_found()),
    }
}

/// Position lookup shared by the single GET and every batch slot.
/// `Ok(None)` is a missing slot (404 on a GET, `null` in a batch).
fn output_at_height(
    st: &AppState,
    view: &ChainView,
    height: u32,
    index: u32,
    vout: u32,
) -> Result<Option<Value>, StoreError> {
    if height > view.height.0 || (height == 0 && index == 0) {
        return Ok(None);
    }
    let fk = match st.query.tx_fk_at_height(Height(height), index) {
        Ok(fk) => fk,
        Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let txid = st.query.store().txs.body_txid(fk)?;
    match output_at_view(&st.query, st.network, fk, &txid, vout, view) {
        Ok(v) => Ok(Some(v)),
        Err(StoreError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

fn json_u32(v: &Value) -> Option<u32> {
    u32::try_from(v.as_u64()?).ok()
}

/// `GET /block-height/{height}/tx/{index}`. Same document as `GET /tx/{txid}`.
pub async fn block_height_tx(
    State(st): State<AppState>,
    Path((height, index)): Path<(u32, u32)>,
    AsOf(asof): AsOf,
) -> Response {
    spawn_join(move || {
        let view = match pinned_tip(&st.query, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if height > view.height.0 {
            return not_found();
        }
        let fk = match st.query.tx_fk_at_height(Height(height), index) {
            Ok(fk) => fk,
            Err(StoreError::NotFound) => return not_found(),
            Err(e) => return store_err(e),
        };
        match build_tx_json(&st.query, fk, st.network, Some(&view)) {
            Ok(v) => maybe_attach_view(json_reply_here(v), Some(view)),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /block-height/{height}/tx/{index}/out/{vout}`.
pub async fn block_height_tx_out(
    State(st): State<AppState>,
    Path((height, index, vout)): Path<(u32, u32, u32)>,
    AsOf(asof): AsOf,
) -> Response {
    spawn_join(move || {
        let view = match pinned_tip(&st.query, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        match output_at_height(&st, &view, height, index, vout) {
            Ok(Some(v)) => maybe_attach_view(json_reply_here(v), Some(view)),
            Ok(None) => not_found(),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `POST /block-heights/txs/outs`. One pin for every slot.
pub async fn post_block_height_outs(
    State(st): State<AppState>,
    AsOf(asof): AsOf,
    body: Bytes,
) -> Response {
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    spawn_join(move || {
        let parsed: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
        };
        let Some(arr) = parsed.as_array() else {
            return (StatusCode::BAD_REQUEST, "body must be a JSON array").into_response();
        };
        if arr.len() > MULTI_ADDRESS_LIMIT {
            return body_too_long();
        }
        let mut slots = Vec::with_capacity(arr.len());
        for el in arr {
            let Some(triple) = el.as_array().filter(|t| t.len() == 3) else {
                return (StatusCode::BAD_REQUEST, "bad element").into_response();
            };
            let Some(height) = json_u32(&triple[0]) else {
                return (StatusCode::BAD_REQUEST, "bad element").into_response();
            };
            let Some(index) = json_u32(&triple[1]) else {
                return (StatusCode::BAD_REQUEST, "bad element").into_response();
            };
            let Some(vout) = json_u32(&triple[2]) else {
                return (StatusCode::BAD_REQUEST, "bad element").into_response();
            };
            slots.push((height, index, vout));
        }
        let view = match pinned_tip(&st.query, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut out = Vec::with_capacity(slots.len());
        for (height, index, vout) in slots {
            match output_at_height(&st, &view, height, index, vout) {
                Ok(v) => out.push(v.map_or(Value::Null, |row| row)),
                Err(e) => return store_err(e),
            }
        }
        maybe_attach_view(json_reply_here(Value::Array(out)), Some(view))
    })
    .await
}

/// `GET /tx/{txid}/out/{vout}`. Confirmed create only. Mempool spends stay unspent.
pub async fn tx_out(
    State(st): State<AppState>,
    Path((txid_hex, vout)): Path<(String, u32)>,
    AsOf(asof): AsOf,
) -> Response {
    spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        let fk = match st.query.tx_fk_by_txid(&txid) {
            Ok(Some(fk)) => fk,
            Ok(None) => return not_found(),
            Err(e) => return store_err(e),
        };
        let view = match pinned_tip(&st.query, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        match st
            .query
            .store()
            .is_confirmed_strong_at(fk, Some(view.height.0))
        {
            Ok(true) => {}
            Ok(false) => return not_found(),
            Err(e) => return store_err(e),
        }
        match genesis_coinbase(&st.query, fk) {
            Ok(true) => return not_found(),
            Ok(false) => {}
            Err(e) => return store_err(e),
        }
        match output_at_view(&st.query, st.network, fk, &txid, vout, &view) {
            Ok(v) => maybe_attach_view(json_reply_here(v), Some(view)),
            Err(e) => store_err(e),
        }
    })
    .await
}

pub async fn tx_outspend(
    State(st): State<AppState>,
    Path((txid_hex, vout)): Path<(String, u32)>,
    AsOf(asof): AsOf,
) -> Response {
    spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        let in_class_a = match st.query.tx_fk_by_txid(&txid) {
            Ok(v) => v.is_some(),
            Err(e) => return store_err(e),
        };
        let tid = Txid::from_byte_array(txid);
        let in_mempool = st.mempool.as_ref().is_some_and(|m| m.contains(&tid));
        if !in_class_a && (asof.is_some() || !in_mempool) {
            return not_found();
        }
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mp = if asof.is_none() {
            st.mempool.as_deref()
        } else {
            None
        };
        match outspend_json(&st.query, mp, &txid, vout, view.as_ref()) {
            Ok(v) => maybe_attach_view(json_reply_here(v), view),
            Err(e) => store_err(e),
        }
    })
    .await
}

pub async fn tx_outspends(
    State(st): State<AppState>,
    Path(txid_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        let fk = match st.query.tx_fk_by_txid(&txid) {
            Ok(v) => v,
            Err(e) => return store_err(e),
        };
        let nout = if let Some(fk) = fk {
            match st.query.store().get_tx_meta_and_outputs(fk) {
                Ok((meta, _)) => meta.output_count,
                Err(e) => return store_err(e),
            }
        } else {
            if asof.is_some() {
                return not_found();
            }
            let Some(mp) = st.mempool.as_ref() else {
                return not_found();
            };
            let tid = Txid::from_byte_array(txid);
            let Some(tx) = mp.get_tx(&tid) else {
                return not_found();
            };
            tx.output.len() as u32
        };
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mp = if asof.is_none() {
            st.mempool.as_deref()
        } else {
            None
        };
        let mut arr = Vec::with_capacity(nout as usize);
        for vout in 0..nout {
            match outspend_json(&st.query, mp, &txid, vout, view.as_ref()) {
                Ok(v) => arr.push(v),
                Err(e) => return store_err(e),
            }
        }
        maybe_attach_view(json_reply_here(arr), view)
    })
    .await
}

pub fn outspend_json(
    query: &Query,
    mempool: Option<&MempoolHub>,
    txid: &[u8; 32],
    vout: u32,
    view: Option<&rbitcoin_query::ChainView>,
) -> Result<Value, rbitcoin_query::QueryError> {
    if let Some(view) = view {
        let spenders = query.spenders_at(txid, vout, Some(view.height.0))?;
        if !spenders.is_empty() {
            let p = &spenders[0];
            let spend_txid = query.store().txs.body_txid(p.spending_tx_fk)?;
            let status = tx_status_json_in(query, p.spending_tx_fk, view)?;
            return Ok(json!({
                "spent": true,
                "txid": block_hash_hex(&spend_txid),
                "vin": p.spending_vin,
                "status": status,
            }));
        }
    }
    if let Some(mp) = mempool {
        let op = OutPoint {
            txid: Txid::from_byte_array(*txid),
            vout,
        };
        if let Some(spend) = mp.spending_txid(&op) {
            let vin = mp.get_tx(&spend).and_then(|tx| {
                tx.input
                    .iter()
                    .position(|i| i.previous_output == op)
                    .map(|i| i as u32)
            });
            return Ok(json!({
                "spent": true,
                "txid": block_hash_hex(&spend.to_byte_array()),
                "vin": vin.unwrap_or(0),
                "status": { "confirmed": false },
            }));
        }
    }
    Ok(json!({ "spent": false }))
}

pub async fn block_template(State(st): State<AppState>) -> Response {
    if st.block_template.is_none() {
        return not_found();
    }
    spawn_join(move || block_template_sync(&st)).await
}

#[doc(hidden)]
pub fn block_template_sync(st: &AppState) -> Response {
    let Some(fun) = st.block_template.as_ref() else {
        return not_found();
    };
    let Some(h) = st.query.tip_height() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no tip").into_response();
    };
    let tip = match st.query.header_at_height(h) {
        Ok(Some((_, rec))) => rec.hash,
        Ok(None) => return (StatusCode::SERVICE_UNAVAILABLE, "no tip").into_response(),
        Err(e) => return store_err(e),
    };
    let updates = st
        .mempool
        .as_ref()
        .map(|m| m.template_updates())
        .unwrap_or(0);
    let mut cache = st.gbt_cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(c) = cache.as_ref() {
        if c.tip == tip && c.updates == updates && c.at.elapsed() < Duration::from_secs(15) {
            return gbt_json(&c.body);
        }
    }
    match (fun.0)() {
        Ok(body) => {
            let body = Arc::new(body);
            *cache = Some(GbtCache {
                at: Instant::now(),
                tip,
                updates,
                body: Arc::clone(&body),
            });
            gbt_json(&body)
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    }
}

#[doc(hidden)]
pub fn gbt_json(body: &Arc<Value>) -> Response {
    let mut resp = json_reply_shared(Arc::clone(body));
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub async fn spawn_join(f: impl FnOnce() -> Response + Send + 'static) -> Response {
    let store_permit = rbitcoin_net::acquire_armed_store_budget().await;
    match tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::BlockingRegion::enter();
        let _store = store_permit;
        f()
    })
    .await
    {
        Ok(r) => crate::server::ensure_json(r).await,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[allow(clippy::result_large_err)] // public error enum
#[doc(hidden)]
pub fn sh_pin(
    st: &AppState,
    asof: Option<[u8; 32]>,
) -> Result<Option<rbitcoin_query::ChainView>, Response> {
    pin_or_reject(&st.query, ChainViewKind::ScriptHash, asof)
}

#[allow(clippy::result_large_err)] // public error enum
#[allow(clippy::too_many_arguments)] // asof vs live join plus last-1 / last-bulk
#[doc(hidden)]
pub fn sh_at_view<T>(
    st: &AppState,
    sh: &[u8; 32],
    asof: Option<[u8; 32]>,
    asof_fn: impl Fn(&Query, &rbitcoin_query::ChainView) -> Result<T, rbitcoin_query::QueryError>,
    live_fn: impl Fn(
        &Query,
        &mut Option<Arc<rbitcoin_query::ShJoinSlot>>,
        &rbitcoin_query::ChainView,
    ) -> Result<T, rbitcoin_query::QueryError>,
    missing: T,
    client: Option<&str>,
    mut bag: Option<&mut JoinBag>,
) -> Result<(T, Option<rbitcoin_query::ChainView>), Response> {
    if asof.is_some() {
        let view = sh_pin(st, asof)?;
        let Some(v) = view.as_ref() else {
            return Err(not_found());
        };
        match asof_fn(&st.query, v) {
            Ok(t) => Ok((t, view)),
            Err(e) => Err(store_err(e)),
        }
    } else {
        let mut slot = bag.as_mut().and_then(|m| m.remove(sh));
        let used_bag = bag.is_some();
        let ran = if used_bag {
            st.query.run_at_view(ChainViewKind::ScriptHash, |view| {
                live_fn(&st.query, &mut slot, view)
            })
        } else {
            st.query.run_at_view(ChainViewKind::ScriptHash, |view| {
                st.with_sh_join(client, sh, |s| live_fn(&st.query, s, view))
            })
        };
        if let Some(map) = bag {
            if let Some(s) = slot {
                map.insert(*sh, s);
            }
        }
        match ran {
            Ok((view, t)) => Ok((t, Some(view))),
            Err(StoreError::NotFound) => Ok((missing, None)),
            Err(e) => Err(store_err(e)),
        }
    }
}

pub async fn address_info(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => {
            spawn_join(move || {
                match sh_stats_json(
                    &st,
                    &sh,
                    Some(addr_s.as_str()),
                    None,
                    asof,
                    client.as_deref(),
                ) {
                    Ok((v, view)) => maybe_attach_view(json_reply_here(v), view),
                    Err(r) => r,
                }
            })
            .await
        }
        Err(_) => not_found(),
    }
}

pub async fn scripthash_info(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(move || {
        match sh_stats_json(
            &st,
            &sh,
            None,
            Some(sh_hex.as_str()),
            asof,
            client.as_deref(),
        ) {
            Ok((v, view)) => maybe_attach_view(json_reply_here(v), view),
            Err(r) => r,
        }
    })
    .await
}

pub async fn address_utxo(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || utxo_response(&st, &sh, asof, client.as_deref())).await,
        Err(_) => not_found(),
    }
}

pub async fn scripthash_utxo(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(move || utxo_response(&st, &sh, asof, client.as_deref())).await
}

#[doc(hidden)]
pub fn utxo_response(
    st: &AppState,
    sh: &[u8; 32],
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    let (list, view) = match sh_at_view(
        st,
        sh,
        asof,
        |q, view| q.scripthash_listunspent_in(sh, view),
        |q, slot, view| {
            rbitcoin_electrum::scripthash_utxos_with_mempool_slot_in(
                q,
                st.mempool.as_deref(),
                sh,
                slot,
                view,
            )
        },
        Vec::new(),
        client,
        None,
    ) {
        Ok(x) => x,
        Err(r) => return r,
    };
    maybe_attach_view(
        match utxo_list_json(&st.query, &list) {
            Ok(v) => json_reply_here(v),
            Err(e) => store_err(e),
        },
        view,
    )
}

#[allow(clippy::result_unit_err)] // a bad address is (); the handler maps it to not found
pub fn resolve_address_sh(addr_s: &str, network: Network) -> Result<[u8; 32], ()> {
    let addr = Address::from_str(addr_s).map_err(|_| ())?;
    let addr = addr.require_network(network).map_err(|_| ())?;
    Ok(script_hash(addr.script_pubkey().as_bytes()))
}

#[doc(hidden)]
#[allow(clippy::result_large_err)] // axum Response, same as the other handlers
pub fn sh_stats_json(
    st: &AppState,
    sh: &[u8; 32],
    address: Option<&str>,
    scripthash_hex: Option<&str>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Result<(Value, Option<rbitcoin_query::ChainView>), Response> {
    let (chain, view) = sh_at_view(
        st,
        sh,
        asof,
        |q, view| q.scripthash_chain_stats_in(sh, view),
        |q, slot, view| q.scripthash_chain_stats_slot_in(sh, slot, view),
        ScriptHashChainStats::default(),
        client,
        None,
    )?;
    let chain_stats = json!({
        "tx_count": chain.tx_count,
        "funded_txo_count": chain.funded_txo_count,
        "funded_txo_sum": chain.funded_txo_sum,
        "spent_txo_count": chain.spent_txo_count,
        "spent_txo_sum": chain.spent_txo_sum,
    });
    let zeros = json!({
        "tx_count": 0,
        "funded_txo_count": 0,
        "funded_txo_sum": 0,
        "spent_txo_count": 0,
        "spent_txo_sum": 0,
    });
    let mempool_stats = if asof.is_some() {
        zeros
    } else if let Some(mp) = st.mempool.as_ref() {
        st.with_sh_join(client, sh, |slot| {
            rbitcoin_electrum::scripthash_mempool_stats_slot(&st.query, mp, sh, slot).map(|s| {
                json!({
                    "tx_count": s.tx_count,
                    "funded_txo_count": s.funded_txo_count,
                    "funded_txo_sum": s.funded_txo_sum,
                    "spent_txo_count": s.spent_txo_count,
                    "spent_txo_sum": s.spent_txo_sum,
                })
            })
        })
        .map_err(store_err)?
    } else {
        zeros
    };
    let mut obj = json!({
        "chain_stats": chain_stats,
        "mempool_stats": mempool_stats,
    });
    if let Some(a) = address {
        obj["address"] = Value::String(a.to_string());
    }
    if let Some(h) = scripthash_hex {
        obj["scripthash"] = Value::String(h.to_string());
    }
    Ok((obj, view))
}

pub async fn scripthash_txs_chain(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    spawn_join(move || chain_page(&st, &sh_hex, None, asof, client.as_deref())).await
}

pub async fn scripthash_txs_chain_cursor(
    State(st): State<AppState>,
    Path((sh_hex, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    spawn_join(move || chain_page(&st, &sh_hex, Some(after), asof, client.as_deref())).await
}

pub async fn address_txs_chain(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || chain_page_sh(&st, &sh, None, asof, client.as_deref())).await,
        Err(_) => not_found(),
    }
}

pub async fn address_txs_chain_cursor(
    State(st): State<AppState>,
    Path((addr_s, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => {
            spawn_join(move || chain_page_sh(&st, &sh, Some(after), asof, client.as_deref())).await
        }
        Err(_) => not_found(),
    }
}

/// Combined `/scripthash/:h/txs` = mempool (cap 50) + first chain page.
pub async fn scripthash_txs(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    let after = match parse_after_txid_query(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    spawn_join(move || combined_txs(&st, &sh, asof, after, client.as_deref())).await
}

pub async fn address_txs(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    JoinClient(client): JoinClient,
) -> Response {
    let after = match parse_after_txid_query(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || combined_txs(&st, &sh, asof, after, client.as_deref())).await,
        Err(_) => not_found(),
    }
}

#[doc(hidden)]
pub fn chain_page(
    st: &AppState,
    sh_hex: &str,
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    let Ok(sh) = parse_hash32(sh_hex) else {
        return not_found();
    };
    chain_page_sh(st, &sh, after, asof, client)
}

pub async fn scripthash_txs_summary(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    JoinClient(client): JoinClient,
) -> Response {
    let after = match parse_after_txid_query(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    spawn_join(move || summary_page(&st, &sh_hex, after, asof, client.as_deref())).await
}

pub async fn scripthash_txs_summary_cursor(
    State(st): State<AppState>,
    Path((sh_hex, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    spawn_join(move || summary_page(&st, &sh_hex, Some(after), asof, client.as_deref())).await
}

pub async fn address_txs_summary(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    JoinClient(client): JoinClient,
) -> Response {
    let after = match parse_after_txid_query(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => {
            spawn_join(move || summary_page_sh(&st, &sh, after, asof, client.as_deref())).await
        }
        Err(_) => not_found(),
    }
}

pub async fn address_txs_summary_cursor(
    State(st): State<AppState>,
    Path((addr_s, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
    JoinClient(client): JoinClient,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => {
            spawn_join(move || summary_page_sh(&st, &sh, Some(after), asof, client.as_deref()))
                .await
        }
        Err(_) => not_found(),
    }
}

#[doc(hidden)]
pub fn summary_page(
    st: &AppState,
    sh_hex: &str,
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    let Ok(sh) = parse_hash32(sh_hex) else {
        return not_found();
    };
    summary_page_sh(st, &sh, after, asof, client)
}

#[doc(hidden)]
pub fn summary_page_sh(
    st: &AppState,
    sh: &[u8; 32],
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    if let Some(id) = after {
        if !txid_is_known(st, &id) {
            return after_txid_not_found();
        }
    }
    let filter = HistoryFilter::esplora_chain_page(after);
    let (page, view) = match sh_at_view(
        st,
        sh,
        asof,
        |q, view| q.scripthash_history_summary_filtered_in(sh, &filter, view),
        |q, slot, view| q.scripthash_history_summary_filtered_slot_in(sh, &filter, slot, view),
        cursor_page(after),
        client,
        None,
    ) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(items) = rows_or_cursor_missing(page) else {
        return after_txid_not_found();
    };
    maybe_attach_view(
        match summaries_json(&st.query, &items) {
            Ok(v) => json_reply_here(v),
            Err(e) => store_err(e),
        },
        view,
    )
}

#[doc(hidden)]
pub fn summaries_json(
    query: &Query,
    items: &[ScriptHashTxSummary],
) -> Result<Value, rbitcoin_query::QueryError> {
    let mut spans: HashMap<u32, (rbitcoin_primitives::Fk, u32)> = HashMap::new();
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let time = if it.height >= 0 {
            query
                .header_at_height(Height(it.height as u32))?
                .map(|(_, rec)| rec.timestamp)
                .unwrap_or(0)
        } else {
            0
        };
        let mut row = json!({
            "txid": block_hash_hex(&it.txid),
            "value": it.value,
            "height": it.height,
            "time": time,
        });
        if it.height >= 0 && !it.tx_fk.is_null() {
            let h = it.height as u32;
            let span = match spans.entry(h) {
                std::collections::hash_map::Entry::Occupied(e) => *e.get(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    *e.insert(query.tx_fk_span_at_height(Height(h))?)
                }
            };
            if let Some(pos) =
                rbitcoin_store::HeaderTxsTable::index_in_span(span.0, span.1, it.tx_fk)
            {
                row["tx_position"] = json!(pos);
            }
        }
        out.push(row);
    }
    Ok(Value::Array(out))
}

#[doc(hidden)]
pub fn chain_page_sh(
    st: &AppState,
    sh: &[u8; 32],
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    let filter = HistoryFilter::esplora_chain_page(after);
    let (page, view) = match sh_at_view(
        st,
        sh,
        asof,
        |q, view| q.scripthash_history_filtered_in(sh, &filter, view),
        |q, slot, view| q.scripthash_history_filtered_slot_in(sh, &filter, slot, view),
        cursor_page(after),
        client,
        None,
    ) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(items) = rows_or_cursor_missing(page) else {
        return after_txid_not_found();
    };
    maybe_attach_view(
        match history_items_to_tx_json(&st.query, &items, st.network) {
            Ok(v) => json_reply_here(v),
            Err(e) => store_err(e),
        },
        view,
    )
}

#[doc(hidden)]
pub fn combined_txs(
    st: &AppState,
    sh: &[u8; 32],
    asof: Option<[u8; 32]>,
    after: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    if let Some(id) = after {
        if !txid_is_known(st, &id) {
            return after_txid_not_found();
        }
    }
    // A confirmed cursor is absent from this script's mempool index, so the
    // chain page is read without mempool tx bodies. A cursor inside the first
    // mempool page keeps only the rows after it. A mempool-only cursor past
    // that page is not a chain cursor. A tx in the pool for some other script
    // must not restart this script's first page.
    let mempool = if asof.is_none() {
        mempool_page_json(st, sh, after)
    } else {
        MempoolPage::Absent
    };
    let mut out = Vec::new();
    let chain_after = match mempool {
        MempoolPage::OnPage(rows) => {
            out.extend(rows);
            None
        }
        MempoolPage::PastPage => match after {
            Some(id) if !txid_on_chain(st, &id) => None,
            other => other,
        },
        MempoolPage::Absent => after,
    };
    let filter = HistoryFilter::esplora_chain_page(chain_after);
    let (page, view) = match sh_at_view(
        st,
        sh,
        asof,
        |q, view| q.scripthash_history_filtered_in(sh, &filter, view),
        |q, slot, view| q.scripthash_history_filtered_slot_in(sh, &filter, slot, view),
        cursor_page(chain_after),
        client,
        None,
    ) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(items) = rows_or_cursor_missing(page) else {
        return after_txid_not_found();
    };
    maybe_attach_view(
        match history_items_to_tx_json(&st.query, &items, st.network) {
            Ok(chain) => {
                out.extend(chain);
                json_reply_here(out)
            }
            Err(e) => store_err(e),
        },
        view,
    )
}

#[doc(hidden)]
pub enum MultiKind {
    Address,
    Scripthash,
}

#[doc(hidden)]
pub fn body_too_long() -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, "body too long").into_response()
}

#[allow(clippy::result_large_err)]
#[doc(hidden)]
pub fn parse_multi_scripts(
    network: Network,
    kind: MultiKind,
    body: &[u8],
) -> Result<Vec<[u8; 32]>, Response> {
    let parsed: Vec<String> = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, format!("invalid json: {e}")).into_response());
        }
    };
    if parsed.len() > MULTI_ADDRESS_LIMIT {
        return Err(body_too_long());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in parsed {
        let sh = match kind {
            MultiKind::Address => resolve_address_sh(&s, network).ok(),
            MultiKind::Scripthash => parse_hash32(&s).ok(),
        };
        if let Some(sh) = sh {
            if seen.insert(sh) {
                out.push(sh);
            }
        }
    }
    Ok(out)
}

#[doc(hidden)]
pub fn tx_row_txid(v: &Value) -> Option<&str> {
    v["txid"].as_str()
}

#[doc(hidden)]
pub fn sort_txs_newest_first(rows: &mut [Value]) {
    rows.sort_by(|a, b| {
        let ca = a["status"]["confirmed"].as_bool() == Some(true);
        let cb = b["status"]["confirmed"].as_bool() == Some(true);
        match (ca, cb) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            _ => {
                let ha = a["status"]["block_height"].as_u64().unwrap_or(0);
                let hb = b["status"]["block_height"].as_u64().unwrap_or(0);
                hb.cmp(&ha).then_with(|| {
                    let ta = a["txid"].as_str().unwrap_or("");
                    let tb = b["txid"].as_str().unwrap_or("");
                    tb.cmp(ta)
                })
            }
        }
    });
}

/// `None`: `after` was set and is not in `rows`. The first page is not a
/// stand-in for a cursor this response does not contain.
#[doc(hidden)]
pub fn skip_rows_after(rows: Vec<Value>, after: Option<[u8; 32]>) -> Option<Vec<Value>> {
    let Some(id) = after else {
        return Some(rows);
    };
    let hex = block_hash_hex(&id);
    let i = rows.iter().position(|v| v["txid"] == hex)?;
    Some(rows[i.saturating_add(1)..].to_vec())
}

#[doc(hidden)]
pub fn cursor_page<T>(after: Option<[u8; 32]>) -> rbitcoin_query::FilteredHistory<T> {
    rbitcoin_query::FilteredHistory {
        rows: Vec::new(),
        cursor_missing: after.is_some(),
    }
}

#[doc(hidden)]
pub fn rows_or_cursor_missing<T>(page: rbitcoin_query::FilteredHistory<T>) -> Option<Vec<T>> {
    if page.cursor_missing {
        None
    } else {
        Some(page.rows)
    }
}

#[doc(hidden)]
pub fn dedup_txid(rows: Vec<Value>) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(rows.len());
    for v in rows {
        let Some(id) = tx_row_txid(&v).map(str::to_owned) else {
            continue;
        };
        if seen.insert(id) {
            out.push(v);
        }
    }
    out
}

/// One newest window per script. More than one script keeps a cursor that
/// is absent from some of them. One script stays the single-address rule:
/// a foreign cursor is 422.
#[doc(hidden)]
pub fn multi_page_filter(after: Option<[u8; 32]>, script_count: usize) -> HistoryFilter {
    let mut filter = HistoryFilter::esplora_chain_page(after);
    filter.after_absent_keeps_older = after.is_some() && script_count > 1;
    filter
}

#[allow(clippy::result_large_err)] // public error enum
#[doc(hidden)]
pub fn accept_script_page<T>(
    page: rbitcoin_query::FilteredHistory<T>,
    keep_absent: bool,
    saw_cursor: &mut bool,
) -> Result<Vec<T>, Response> {
    if page.cursor_missing && !keep_absent {
        return Err(after_txid_not_found());
    }
    if !page.cursor_missing {
        *saw_cursor = true;
    }
    Ok(page.rows)
}

#[doc(hidden)]
pub fn truncate_page(rows: &mut Vec<Value>, limit: usize) {
    if rows.len() > limit {
        rows.truncate(limit);
    }
}

/// Higher block first, then the larger internal txid. The next page cuts
/// on that key. Display hex is the byte reverse, so it would pick a
/// different last row at the same height.
#[doc(hidden)]
pub fn newer_internal_txid(left_hex: &str, right_hex: &str) -> std::cmp::Ordering {
    let left = parse_hash32(left_hex).unwrap_or([0u8; 32]);
    let right = parse_hash32(right_hex).unwrap_or([0u8; 32]);
    right.cmp(&left)
}

#[doc(hidden)]
pub fn sort_confirmed_txs(rows: &mut [Value]) {
    rows.sort_by(|a, b| {
        let ha = a["status"]["block_height"].as_u64().unwrap_or(0);
        let hb = b["status"]["block_height"].as_u64().unwrap_or(0);
        hb.cmp(&ha).then_with(|| {
            newer_internal_txid(
                a["txid"].as_str().unwrap_or(""),
                b["txid"].as_str().unwrap_or(""),
            )
        })
    });
}

#[doc(hidden)]
pub fn sort_summaries_newest(rows: &mut [Value]) {
    rows.sort_by(|a, b| {
        let ha = a["height"].as_i64().unwrap_or(0);
        let hb = b["height"].as_i64().unwrap_or(0);
        hb.cmp(&ha).then_with(|| {
            newer_internal_txid(
                a["txid"].as_str().unwrap_or(""),
                b["txid"].as_str().unwrap_or(""),
            )
        })
    });
}

#[doc(hidden)]
pub fn multi_txs(
    st: &AppState,
    scripts: Vec<[u8; 32]>,
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    if let Some(id) = after {
        if !txid_is_known(st, &id) {
            return after_txid_not_found();
        }
    }
    let mut bag = JoinBag::new();
    st.seed_bulk(client, &mut bag);
    let mut mempool_rows = Vec::new();
    if asof.is_none() {
        for sh in &scripts {
            mempool_rows.extend(mempool_txs_json(st, sh));
        }
        mempool_rows = dedup_txid(mempool_rows);
        sort_txs_newest_first(&mut mempool_rows);
    }
    let after_in_mempool = after.is_some_and(|id| {
        let hex = block_hash_hex(&id);
        mempool_rows.iter().any(|v| v["txid"] == hex)
    });
    let past_unconfirmed = after.is_some_and(|id| {
        !after_in_mempool
            && scripts.iter().any(|sh| mempool_indexes(st, sh, &id))
            && !txid_on_chain(st, &id)
    });
    let chain_after = if after_in_mempool || past_unconfirmed {
        None
    } else {
        after
    };
    if after.is_some() && !after_in_mempool {
        mempool_rows.clear();
    } else if let Some(id) = after {
        mempool_rows = skip_rows_after(mempool_rows, Some(id)).unwrap_or_default();
    }
    let filter = multi_page_filter(chain_after, scripts.len());
    let limit = filter.limit.unwrap_or(25);
    let mut saw_cursor = chain_after.is_none();
    let mut chain = Vec::new();
    for sh in &scripts {
        let (page, _) = match sh_at_view(
            st,
            sh,
            asof,
            |q, view| q.scripthash_history_filtered_in(sh, &filter, view),
            |q, slot, view| q.scripthash_history_filtered_slot_in(sh, &filter, slot, view),
            cursor_page(chain_after),
            client,
            Some(&mut bag),
        ) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let items = match accept_script_page(page, filter.after_absent_keeps_older, &mut saw_cursor)
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        match history_items_to_tx_json(&st.query, &items, st.network) {
            Ok(part) => chain.extend(part),
            Err(e) => return store_err(e),
        }
    }
    st.promote_bulk(client, bag);
    if !saw_cursor {
        return after_txid_not_found();
    }
    let mut chain = dedup_txid(chain);
    sort_confirmed_txs(&mut chain);
    truncate_page(&mut chain, limit);
    mempool_rows.extend(chain);
    json_reply_here(mempool_rows)
}

#[doc(hidden)]
pub fn multi_summary(
    st: &AppState,
    scripts: Vec<[u8; 32]>,
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
    client: Option<&str>,
) -> Response {
    if let Some(id) = after {
        if !txid_is_known(st, &id) {
            return after_txid_not_found();
        }
    }
    let mut bag = JoinBag::new();
    st.seed_bulk(client, &mut bag);
    let filter = multi_page_filter(after, scripts.len());
    let limit = filter.limit.unwrap_or(25);
    let mut saw_cursor = after.is_none();
    let mut rows = Vec::new();
    for sh in &scripts {
        let (page, _) = match sh_at_view(
            st,
            sh,
            asof,
            |q, view| q.scripthash_history_summary_filtered_in(sh, &filter, view),
            |q, slot, view| q.scripthash_history_summary_filtered_slot_in(sh, &filter, slot, view),
            cursor_page(after),
            client,
            Some(&mut bag),
        ) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let items = match accept_script_page(page, filter.after_absent_keeps_older, &mut saw_cursor)
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        match summaries_json(&st.query, &items) {
            Ok(Value::Array(v)) => rows.extend(v),
            Ok(_) => {}
            Err(e) => return store_err(e),
        }
    }
    st.promote_bulk(client, bag);
    if !saw_cursor {
        return after_txid_not_found();
    }
    let mut rows = dedup_txid(rows);
    sort_summaries_newest(&mut rows);
    truncate_page(&mut rows, limit);
    json_reply_here(rows)
}

#[doc(hidden)]
pub fn post_multi_body(
    st: AppState,
    kind: MultiKind,
    q: AfterTxidQuery,
    body: Bytes,
    summary: bool,
    client: Option<String>,
) -> Response {
    let after = match parse_after_txid_query(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    let scripts = match parse_multi_scripts(st.network, kind, &body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client = client.as_deref();
    if summary {
        multi_summary(&st, scripts, after, None, client)
    } else {
        multi_txs(&st, scripts, after, None, client)
    }
}

pub async fn post_addresses_txs(
    State(st): State<AppState>,
    JoinClient(client): JoinClient,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    body: Bytes,
) -> Response {
    spawn_join(move || post_multi_body(st, MultiKind::Address, q, body, false, client)).await
}

pub async fn post_scripthashes_txs(
    State(st): State<AppState>,
    JoinClient(client): JoinClient,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    body: Bytes,
) -> Response {
    spawn_join(move || post_multi_body(st, MultiKind::Scripthash, q, body, false, client)).await
}

pub async fn post_addresses_txs_summary(
    State(st): State<AppState>,
    JoinClient(client): JoinClient,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    body: Bytes,
) -> Response {
    spawn_join(move || post_multi_body(st, MultiKind::Address, q, body, true, client)).await
}

pub async fn post_scripthashes_txs_summary(
    State(st): State<AppState>,
    JoinClient(client): JoinClient,
    AxumQuery(q): AxumQuery<AfterTxidQuery>,
    body: Bytes,
) -> Response {
    spawn_join(move || post_multi_body(st, MultiKind::Scripthash, q, body, true, client)).await
}

pub async fn mempool_info(State(st): State<AppState>) -> Response {
    spawn_join(move || mempool_info_sync(&st)).await
}

#[doc(hidden)]
pub fn mempool_info_sync(st: &AppState) -> Response {
    json_reply_here(mempool_info_json(st.mempool.as_deref()))
}

/// `GET /mempool` body. Request path loads published fee-snapshot totals.
pub fn mempool_info_json(mp: Option<&MempoolHub>) -> Value {
    let Some(mp) = mp else {
        return json!({
            "count": 0,
            "vsize": 0,
            "total_fee": 0,
            "fee_histogram": [],
        });
    };
    let (count, vsize, total_fee) = mp.mempool_live_totals();
    let hist: Vec<Value> = mp
        .fee_histogram()
        .into_iter()
        .map(|(rate_kvb, vs)| {
            let rate_sat_per_vb = (rate_kvb as f64) / 1000.0;
            json!([rate_sat_per_vb, vs])
        })
        .collect();
    json!({
        "count": count,
        "vsize": vsize,
        "total_fee": total_fee,
        "fee_histogram": hist,
    })
}

pub async fn fee_estimates(State(st): State<AppState>) -> Response {
    spawn_join(move || fee_estimates_sync(&st)).await
}

/// sat/vB from the estimator's BTC/kvB, keeping its 1 sat/kvB (0.001 sat/vB)
/// resolution. `None` when the estimator has no answer (negative).
#[doc(hidden)]
pub fn sat_vb(btc_kb: f64) -> Option<f64> {
    (btc_kb >= 0.0).then(|| (btc_kb * 100_000_000.0).round() / 1_000.0)
}

/// Esplora `/fee-estimates`: confirm target → sat/vB. Targets without an
/// estimate are left out (electrs); `None` when no target has one.
#[doc(hidden)]
pub fn fee_estimates_from(pairs: &[(u32, f64)]) -> Option<Value> {
    let map: serde_json::Map<String, Value> = pairs
        .iter()
        .filter_map(|(t, btc_kb)| sat_vb(*btc_kb).map(|v| (t.to_string(), json!(v))))
        .collect();
    (!map.is_empty()).then_some(Value::Object(map))
}

#[doc(hidden)]
pub fn fee_estimates_sync(st: &AppState) -> Response {
    let pairs = st
        .mempool
        .as_ref()
        .map(|m| m.fee_estimates_btc_per_kb())
        .unwrap_or_default();
    match fee_estimates_from(&pairs) {
        Some(v) => json_reply_here(v),
        // LDK aborts startup on a failed fee update and must not be handed an invented rate.
        None if st.network != Network::Bitcoin => json_reply_here(json!({})),
        None => (StatusCode::SERVICE_UNAVAILABLE, "fee estimates unavailable").into_response(),
    }
}

pub async fn mempool_txids(State(st): State<AppState>) -> Response {
    spawn_join(move || mempool_txids_sync(&st)).await
}

#[doc(hidden)]
pub fn mempool_txids_sync(st: &AppState) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return json_reply_here(json!([]));
    };
    let ids: Vec<String> = mp
        .list_live_meta()
        .into_iter()
        .map(|(txid, _, _)| block_hash_hex(&txid.to_byte_array()))
        .collect();
    json_reply_here(ids)
}

pub async fn mempool_recent(State(st): State<AppState>) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return json_reply_here(json!([]));
    };
    let rows: Vec<Value> = mp
        .recent_accepts()
        .into_iter()
        .map(|r| {
            json!({
                "txid": block_hash_hex(&r.txid.to_byte_array()),
                "fee": r.fee_sat,
                "vsize": r.weight.saturating_add(3) / 4,
                "value": r.value_sat,
            })
        })
        .collect();
    json_reply_here(rows)
}

/// Mempool-only history (up to 50), dedicated Esplora path.
pub async fn scripthash_txs_mempool(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(move || mempool_txs_for_sh(&st, &sh)).await
}

pub async fn address_txs_mempool(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || mempool_txs_for_sh(&st, &sh)).await,
        Err(_) => not_found(),
    }
}

#[doc(hidden)]
pub fn mempool_txs_json(st: &AppState, sh: &[u8; 32]) -> Vec<Value> {
    match mempool_page_json(st, sh, None) {
        MempoolPage::OnPage(rows) => rows,
        MempoolPage::Absent | MempoolPage::PastPage => Vec::new(),
    }
}

/// Where `after` sits in this script's mempool index.
#[doc(hidden)]
pub enum MempoolPage {
    /// Not in the index. The caller keeps `after` as a chain cursor.
    Absent,
    /// Rows that stay on the page. A cursor on the page is already dropped.
    OnPage(Vec<Value>),
    /// In the index, past the first [`MEMPOOL_TX_PAGE`] rows. No body loaded.
    PastPage,
}

#[doc(hidden)]
pub fn mempool_indexes(st: &AppState, sh: &[u8; 32], id: &[u8; 32]) -> bool {
    let Some(mp) = st.mempool.as_ref() else {
        return false;
    };
    mp.scripthash_indexes_tx(sh, &Txid::from_byte_array(*id))
}

#[doc(hidden)]
pub fn txid_on_chain(st: &AppState, id: &[u8; 32]) -> bool {
    st.query.get_tx_by_txid(id).ok().flatten().is_some()
}

/// Mempool JSON that stays on this `/txs` page.
///
/// A cursor outside the index loads nothing. A cursor on the first page
/// keeps the tail. A cursor past that page loads nothing and is [`MempoolPage::PastPage`],
/// so a mempool-only tx is not mistaken for a chain cursor.
#[doc(hidden)]
pub fn mempool_page_json(st: &AppState, sh: &[u8; 32], after: Option<[u8; 32]>) -> MempoolPage {
    let Some(mp) = st.mempool.as_ref() else {
        return MempoolPage::Absent;
    };
    if let Some(id) = after {
        if !mempool_indexes(st, sh, &id) {
            return MempoolPage::Absent;
        }
    }
    let mut rows = mp.scripthash_mempool_fees(sh);
    rows.truncate(MEMPOOL_TX_PAGE);
    if let Some(id) = after {
        let Some(i) = rows.iter().position(|(txid, _)| *txid == id) else {
            return MempoolPage::PastPage;
        };
        rows.drain(..=i);
    }
    let mut out = Vec::new();
    for (txid, fee) in rows {
        push_mempool_tx_json(st, mp, txid, fee, &mut out);
    }
    MempoolPage::OnPage(out)
}

#[doc(hidden)]
pub fn push_mempool_tx_json(
    st: &AppState,
    mp: &MempoolHub,
    txid: [u8; 32],
    fee: i64,
    out: &mut Vec<Value>,
) {
    if let Ok(Some((fk, _))) = st.query.get_tx_by_txid(&txid) {
        if let Ok(v) = build_tx_json(&st.query, fk, st.network, None) {
            out.push(v);
            return;
        }
    }
    let id = Txid::from_byte_array(txid);
    let Some(tx) = mp.get_tx(&id) else {
        return;
    };
    if let Ok(v) = build_tx_json_from_tx(&st.query, &tx, st.network, Some(fee), Some(mp)) {
        out.push(v);
    }
}

#[doc(hidden)]
pub fn mempool_txs_for_sh(st: &AppState, sh: &[u8; 32]) -> Response {
    json_reply_here(mempool_txs_json(st, sh))
}

#[derive(Deserialize, Default)]
pub struct AfterTxidQuery {
    pub after_txid: Option<String>,
}

#[doc(hidden)]
pub fn after_txid_not_found() -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, "after_txid not found").into_response()
}

#[allow(clippy::result_large_err)] // public error enum
#[doc(hidden)]
pub fn parse_after_txid_query(q: AfterTxidQuery) -> Result<Option<[u8; 32]>, Response> {
    match q.after_txid {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => parse_hash32(&s)
            .map(Some)
            .map_err(|_| after_txid_not_found()),
    }
}

#[doc(hidden)]
pub fn txid_is_known(st: &AppState, id: &[u8; 32]) -> bool {
    let tid = Txid::from_byte_array(*id);
    st.mempool.as_ref().is_some_and(|m| m.contains(&tid))
        || st.query.get_tx_by_txid(id).ok().flatten().is_some()
}

#[derive(Deserialize)]
pub struct TxidsQuery {
    pub txids: Option<String>,
}

pub async fn get_txs_outspends(
    State(st): State<AppState>,
    AxumQuery(q): AxumQuery<TxidsQuery>,
) -> Response {
    let Some(raw) = q.txids.filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "No txids specified").into_response();
    };
    spawn_join(move || {
        let parts: Vec<&str> = raw.split(',').collect();
        if parts.len() > 50 {
            return (StatusCode::BAD_REQUEST, "Too many txids requested").into_response();
        }
        let ids: Vec<Option<[u8; 32]>> = parts.iter().map(|p| parse_hash32(p).ok()).collect();
        crate::internal::outspends_for_txid_opts(&st, ids)
    })
    .await
}

#[allow(clippy::result_large_err)] // public error enum
#[doc(hidden)]
pub fn decode_tx_hex_str(hex: &str) -> Result<bitcoin::Transaction, Response> {
    let hex = hex.trim().trim_matches('"');
    let raw = match rbitcoin_primitives::hex_decode(hex) {
        Ok(r) => r,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, format!("invalid hex: {e}")).into_response());
        }
    };
    match deserialize(&raw) {
        Ok(t) => Ok(t),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("invalid tx: {e}")).into_response()),
    }
}

pub async fn admit_broadcast(st: AppState, tx: bitcoin::Transaction) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    };
    let budget = st.query.api_read_budget();
    match rbitcoin_net::with_store_budget(budget, mp.accept_tx_async(tx)).await {
        Ok(r) => {
            let marked = Arc::clone(mp);
            let tid = r.txid;
            rbitcoin_net::off_pool(move || marked.mark_local_origin(tid)).await;
            plain_ok(block_hash_hex(&tid.to_byte_array()))
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_tx(State(st): State<AppState>, body: Bytes) -> Response {
    if st.mempool.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    }
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    let hex = std::str::from_utf8(&body).unwrap_or("");
    let tx = match decode_tx_hex_str(hex) {
        Ok(t) => t,
        Err(r) => return r,
    };
    admit_broadcast(st, tx).await
}

#[derive(Deserialize, Default)]
pub struct MaxFeeQuery {
    pub maxfeerate: Option<String>,
}

/// BTC/kvB → sat/kvB, rounded up to a whole sat/vB (at least 1).
#[allow(clippy::result_large_err)] // public error enum
#[doc(hidden)]
pub fn parse_maxfeerate_btc_kvb(q: MaxFeeQuery) -> Result<u64, Response> {
    let Some(s) = q.maxfeerate.filter(|s| !s.is_empty()) else {
        return Ok(10_000_000);
    };
    let v: f64 = s
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid maxfeerate").into_response())?;
    if !v.is_finite() || v < 0.0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid maxfeerate").into_response());
    }
    if v == 0.0 {
        return Ok(0);
    }
    let sat_vb = (v * 100_000.0).ceil() as u64;
    Ok(sat_vb.max(1).saturating_mul(1000))
}

pub async fn post_txs_test(
    State(st): State<AppState>,
    AxumQuery(q): AxumQuery<MaxFeeQuery>,
    body: Bytes,
) -> Response {
    let max_sat_kvb = match parse_maxfeerate_btc_kvb(q) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    let Some(mp) = st.mempool.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    };
    {
        let hexes: Vec<String> = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("invalid json: {e}")).into_response();
            }
        };
        if hexes.len() > 25 {
            return (
                StatusCode::BAD_REQUEST,
                "Exceeded maximum of 25 transactions",
            )
                .into_response();
        }
        for (i, hex) in hexes.iter().enumerate() {
            if !(120..800_000).contains(&hex.len()) {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid transaction size for item {i}"),
                )
                    .into_response();
            }
        }
        let mut decoded = Vec::with_capacity(hexes.len());
        for (i, hex) in hexes.iter().enumerate() {
            match decode_tx_hex_str(hex) {
                Ok(tx) => decoded.push(tx),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid transaction hex for item {i}"),
                    )
                        .into_response();
                }
            }
        }
        let mut ids = HashSet::new();
        if decoded.iter().any(|tx| !ids.insert(tx.compute_txid())) {
            let tx = &decoded[0];
            return json_reply_here(json!([{
                "txid": format!("{}", tx.compute_txid()),
                "wtxid": format!("{}", tx.compute_wtxid()),
                "allowed": false,
                "package-error": "package-contains-duplicates",
            }]));
        }
        let mut out = Vec::new();
        for tx in decoded {
            let txid = format!("{}", tx.compute_txid());
            let wtxid = format!("{}", tx.compute_wtxid());
            match rbitcoin_net::with_store_budget(
                st.query.api_read_budget(),
                mp.test_accept_async(tx.clone()),
            )
            .await
            {
                Ok(r) => {
                    if rbitcoin_consensus::policy::fee_exceeds_max(r.fee_sat, r.weight, max_sat_kvb)
                    {
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
                        "fees": { "base": r.fee_sat as f64 / 100_000_000.0 },
                    }));
                }
                Err(e) => {
                    out.push(json!({
                        "txid": txid,
                        "wtxid": wtxid,
                        "allowed": false,
                        "reject-reason": e.to_string(),
                    }));
                }
            }
        }
        json_reply_here(out)
    }
}

/// `POST /txs/package` — JSON array of hex txs → `MempoolHub::accept_package`.
pub async fn post_tx_package(State(st): State<AppState>, body: Bytes) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    };
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid json: {e}")).into_response();
        }
    };
    let Some(arr) = parsed.as_array() else {
        return (
            StatusCode::BAD_REQUEST,
            "body must be a JSON array of tx hex strings",
        )
            .into_response();
    };
    // Soft cap before mempool internal limits (DoS).
    if arr.len() > 25 {
        return (
            StatusCode::BAD_REQUEST,
            "package too large (max 25 transactions)",
        )
            .into_response();
    }
    let mut txs = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let Some(hex) = v.as_str() else {
            return (
                StatusCode::BAD_REQUEST,
                format!("package[{i}] must be a hex string"),
            )
                .into_response();
        };
        let raw = match rbitcoin_primitives::hex_decode(hex.trim()) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("package[{i}] invalid hex: {e}"),
                )
                    .into_response();
            }
        };
        match deserialize::<bitcoin::Transaction>(&raw) {
            Ok(t) => txs.push(t),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("package[{i}] invalid tx: {e}"),
                )
                    .into_response();
            }
        }
    }
    match rbitcoin_net::with_store_budget(st.query.api_read_budget(), mp.accept_package_async(txs))
        .await
    {
        Ok(results) => {
            let marked = Arc::clone(mp);
            let ids: Vec<_> = results.iter().map(|r| r.txid).collect();
            rbitcoin_net::off_pool(move || {
                for tid in ids {
                    marked.mark_local_origin(tid);
                }
            })
            .await;
            let txids: Vec<String> = results
                .iter()
                .map(|r| block_hash_hex(&r.txid.to_byte_array()))
                .collect();
            json_reply_here(json!({ "txids": txids }))
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
