//! Esplora route handlers beyond tip/header/basic tx.

use crate::server::{
    block_hash_hex, maybe_attach_view, mempool_wire, not_found, parse_hash32, pin_or_reject,
    plain_ok, store_err, AppState, AsOf,
};
use crate::tx_json::{
    build_tx_json, build_tx_json_from_tx, history_items_to_tx_json, tx_status_json_in,
    utxo_list_json,
};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bitcoin::address::Address;
use bitcoin::consensus::{deserialize, encode::serialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{MerkleBlock, Network, Txid};
use rbitcoin_primitives::{median_time_past_times, Height};
use rbitcoin_query::{ChainViewKind, HistoryFilter, Query, ScriptHashChainStats};
use rbitcoin_store::{script_hash, StoreError};
use serde_json::{json, Value};
use std::str::FromStr;

/// Best-chain wire block for Esplora (archived reconstruct; no extra PoW rehash gate).
fn best_chain_block(
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
pub(crate) fn block_summary_json(
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
    let block = query
        .reconstruct_archived_block(hash)?
        .ok_or(rbitcoin_store::StoreError::NotFound)?;
    let size = block.total_size() as u64;
    let weight = block.weight().to_wu();
    let difficulty =
        Target::from_compact(CompactTarget::from_consensus(rec.bits)).difficulty_float();
    let mediantime = median_time_past(query, height)?;
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

/// Median timestamp of the last up to 11 best-chain headers ending at `height` (BIP113 MTP).
fn median_time_past(query: &Query, height: Height) -> Result<u32, rbitcoin_query::QueryError> {
    let n = 11u32.min(height.0.saturating_add(1));
    let start = height.0.saturating_sub(n.saturating_sub(1));
    let mut times = Vec::with_capacity(n as usize);
    for h in start..=height.0 {
        let (_fk, rec) = query
            .header_at_height(Height(h))?
            .ok_or(rbitcoin_store::StoreError::NotFound)?;
        times.push(rec.timestamp);
    }
    Ok(median_time_past_times(&times))
}

pub async fn block_json(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    let q = std::sync::Arc::clone(&st.query);
    match tokio::task::spawn_blocking(move || block_summary_json(&q, &hash)).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => store_err(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn block_raw(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    let q = std::sync::Arc::clone(&st.query);
    match tokio::task::spawn_blocking(move || best_chain_block(&q, &hash)).await {
        Ok(Ok((_h, block))) => {
            let raw = serialize(&block);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                raw,
            )
                .into_response()
        }
        Ok(Err(e)) => store_err(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn block_status(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    if st.query.get_header_by_hash(&hash).ok().flatten().is_none() {
        return not_found();
    }
    match st.query.height_of_hash(&hash) {
        Ok(None) => Json(json!({
            "in_best_chain": false,
            "height": null,
            "next_best": null,
        }))
        .into_response(),
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
            Json(json!({
                "in_best_chain": true,
                "height": h.0,
                "next_best": next_best,
            }))
            .into_response()
        }
        Err(e) => store_err(e),
    }
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
    tokio::task::spawn_blocking(move || blocks_from(&st, None))
        .await
        .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

/// `GET /blocks/:start_height` — 10 blocks starting at `start_height` downward.
pub async fn blocks_from_height(State(st): State<AppState>, Path(start): Path<u32>) -> Response {
    tokio::task::spawn_blocking(move || blocks_from(&st, Some(start)))
        .await
        .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

fn blocks_from(st: &AppState, start: Option<u32>) -> Response {
    let Some(tip) = st.query.tip_height() else {
        return Json(json!([])).into_response();
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
    Json(out).into_response()
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
            Ok(ids) => Json(ids.iter().map(block_hash_hex).collect::<Vec<_>>()).into_response(),
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

fn block_txs_impl(st: AppState, hash_hex: &str, start: u32) -> Response {
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
            let page: Vec<_> = fks.into_iter().skip(start as usize).take(25).collect();
            let mut out = Vec::with_capacity(page.len());
            for fk in page {
                match build_tx_json(&st.query, fk, st.network) {
                    Ok(v) => out.push(v),
                    Err(e) => return store_err(e),
                }
            }
            Json(out).into_response()
        }
        Err(e) => store_err(e),
    }
}

pub async fn tx_merkle_proof(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    spawn_join(move || tx_merkle_proof_sync(st, txid_hex)).await
}

fn tx_merkle_proof_sync(st: AppState, txid_hex: String) -> Response {
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
            Json(json!({
                "block_height": proof.block_height,
                "merkle": merkle,
                "pos": proof.pos,
            }))
            .into_response()
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

fn tx_merkleblock_proof_sync(st: AppState, txid_hex: String) -> Response {
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
    plain_ok(rbitcoin_primitives::hex_encode(raw))
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
        if st.query.tx_fk_by_txid(&txid).ok().flatten().is_none() {
            return not_found();
        }
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        match outspend_json(&st.query, &txid, vout, view.as_ref()) {
            Ok(v) => maybe_attach_view(Json(v).into_response(), view),
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
        let Some(fk) = (match st.query.tx_fk_by_txid(&txid) {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }) else {
            return not_found();
        };
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let (meta, _) = match st.query.store().get_tx_meta_and_outputs(fk) {
            Ok(v) => v,
            Err(e) => return store_err(e),
        };
        let mut arr = Vec::with_capacity(meta.output_count as usize);
        for vout in 0..meta.output_count {
            match outspend_json(&st.query, &txid, vout, view.as_ref()) {
                Ok(v) => arr.push(v),
                Err(e) => return store_err(e),
            }
        }
        maybe_attach_view(Json(arr).into_response(), view)
    })
    .await
}

fn outspend_json(
    query: &Query,
    txid: &[u8; 32],
    vout: u32,
    view: Option<&rbitcoin_query::ChainView>,
) -> Result<Value, rbitcoin_query::QueryError> {
    let Some(view) = view else {
        return Ok(json!({ "spent": false }));
    };
    let spenders = query.spenders_at(txid, vout, Some(view.height.0))?;
    if spenders.is_empty() {
        return Ok(json!({ "spent": false }));
    }
    let p = &spenders[0];
    let spend_txid = query.store().txs.body_txid(p.spending_tx_fk)?;
    let status = tx_status_json_in(query, p.spending_tx_fk, view)?;
    Ok(json!({
        "spent": true,
        "txid": block_hash_hex(&spend_txid),
        "vin": p.spending_input_index,
        "status": status,
    }))
}

pub(crate) async fn spawn_join(f: impl FnOnce() -> Response + Send + 'static) -> Response {
    match tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::BlockingRegion::enter();
        f()
    })
    .await
    {
        Ok(r) => r,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn sh_pin(
    st: &AppState,
    asof: Option<[u8; 32]>,
) -> Result<Option<rbitcoin_query::ChainView>, Response> {
    pin_or_reject(&st.query, ChainViewKind::ScriptHash, asof)
}

pub async fn address_info(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => {
            spawn_join(
                move || match sh_stats_json(&st, &sh, Some(addr_s.as_str()), None, asof) {
                    Ok((v, view)) => maybe_attach_view(Json(v).into_response(), view),
                    Err(e) => store_err(e),
                },
            )
            .await
        }
        Err(_) => not_found(),
    }
}

pub async fn scripthash_info(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(
        move || match sh_stats_json(&st, &sh, None, Some(sh_hex.as_str()), asof) {
            Ok((v, view)) => maybe_attach_view(Json(v).into_response(), view),
            Err(e) => store_err(e),
        },
    )
    .await
}

pub async fn address_utxo(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || utxo_response(&st, &sh, asof)).await,
        Err(_) => not_found(),
    }
}

pub async fn scripthash_utxo(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(move || utxo_response(&st, &sh, asof)).await
}

fn utxo_response(st: &AppState, sh: &[u8; 32], asof: Option<[u8; 32]>) -> Response {
    let view = match sh_pin(st, asof) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let resp = if asof.is_some() {
        let Some(view) = view.as_ref() else {
            return not_found();
        };
        match st.query.scripthash_listunspent_in(sh, view) {
            Ok(list) => match utxo_list_json(&st.query, &list) {
                Ok(v) => Json(v).into_response(),
                Err(e) => store_err(e),
            },
            Err(e) => store_err(e),
        }
    } else {
        match st.query.run_at_view(ChainViewKind::ScriptHash, |view| {
            st.with_sh_join(|slot| {
                rbitcoin_electrum::scripthash_utxos_with_mempool_slot_in(
                    &st.query,
                    st.mempool.as_deref(),
                    sh,
                    slot,
                    view,
                )
            })
        }) {
            Ok((view, list)) => {
                return maybe_attach_view(
                    match utxo_list_json(&st.query, &list) {
                        Ok(v) => Json(v).into_response(),
                        Err(e) => store_err(e),
                    },
                    Some(view),
                );
            }
            Err(StoreError::NotFound) => match utxo_list_json(&st.query, &[]) {
                Ok(v) => Json(v).into_response(),
                Err(e) => store_err(e),
            },
            Err(e) => store_err(e),
        }
    };
    maybe_attach_view(resp, view)
}

pub(crate) fn resolve_address_sh(addr_s: &str, network: Network) -> Result<[u8; 32], ()> {
    let addr = Address::from_str(addr_s).map_err(|_| ())?;
    let addr = addr.require_network(network).map_err(|_| ())?;
    Ok(script_hash(addr.script_pubkey().as_bytes()))
}

fn sh_stats_json(
    st: &AppState,
    sh: &[u8; 32],
    address: Option<&str>,
    scripthash_hex: Option<&str>,
    asof: Option<[u8; 32]>,
) -> Result<(Value, Option<rbitcoin_query::ChainView>), rbitcoin_query::QueryError> {
    let (chain, view) = if asof.is_some() {
        let view = st
            .query
            .pin_view(ChainViewKind::ScriptHash, asof.as_ref())?;
        if view.is_none() {
            return Err(StoreError::NotFound);
        }
        let v = view.as_ref().unwrap();
        (st.query.scripthash_chain_stats_in(sh, v)?, view)
    } else {
        match st.query.run_at_view(ChainViewKind::ScriptHash, |v| {
            st.with_sh_join(|slot| st.query.scripthash_chain_stats_slot_in(sh, slot, v))
        }) {
            Ok((view, chain)) => (chain, Some(view)),
            Err(StoreError::NotFound) => (ScriptHashChainStats::default(), None),
            Err(e) => return Err(e),
        }
    };
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
        st.with_sh_join(|slot| {
            rbitcoin_electrum::scripthash_mempool_stats_slot(&st.query, mp, sh, slot).map(|s| {
                json!({
                    "tx_count": s.tx_count,
                    "funded_txo_count": s.funded_txo_count,
                    "funded_txo_sum": s.funded_txo_sum,
                    "spent_txo_count": s.spent_txo_count,
                    "spent_txo_sum": s.spent_txo_sum,
                })
            })
        })?
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
) -> Response {
    spawn_join(move || chain_page(&st, &sh_hex, None, asof)).await
}

pub async fn scripthash_txs_chain_cursor(
    State(st): State<AppState>,
    Path((sh_hex, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    spawn_join(move || chain_page(&st, &sh_hex, Some(after), asof)).await
}

pub async fn address_txs_chain(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || chain_page_sh(&st, &sh, None, asof)).await,
        Err(_) => not_found(),
    }
}

pub async fn address_txs_chain_cursor(
    State(st): State<AppState>,
    Path((addr_s, last)): Path<(String, String)>,
    AsOf(asof): AsOf,
) -> Response {
    let Ok(after) = parse_hash32(&last) else {
        return not_found();
    };
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || chain_page_sh(&st, &sh, Some(after), asof)).await,
        Err(_) => not_found(),
    }
}

/// Combined `/scripthash/:h/txs` = mempool (cap 50) + first chain page.
pub async fn scripthash_txs(
    State(st): State<AppState>,
    Path(sh_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    let Ok(sh) = parse_hash32(&sh_hex) else {
        return not_found();
    };
    spawn_join(move || combined_txs(&st, &sh, asof)).await
}

pub async fn address_txs(
    State(st): State<AppState>,
    Path(addr_s): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    match resolve_address_sh(&addr_s, st.network) {
        Ok(sh) => spawn_join(move || combined_txs(&st, &sh, asof)).await,
        Err(_) => not_found(),
    }
}

fn chain_page(
    st: &AppState,
    sh_hex: &str,
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
) -> Response {
    let Ok(sh) = parse_hash32(sh_hex) else {
        return not_found();
    };
    chain_page_sh(st, &sh, after, asof)
}

fn chain_page_sh(
    st: &AppState,
    sh: &[u8; 32],
    after: Option<[u8; 32]>,
    asof: Option<[u8; 32]>,
) -> Response {
    let view = match sh_pin(st, asof) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let filter = HistoryFilter::esplora_chain_page(after);
    let resp = if asof.is_some() {
        let Some(view) = view.as_ref() else {
            return not_found();
        };
        match st.query.scripthash_history_filtered_in(sh, &filter, view) {
            Ok(items) => match history_items_to_tx_json(&st.query, &items, st.network) {
                Ok(v) => Json(v).into_response(),
                Err(e) => store_err(e),
            },
            Err(e) => store_err(e),
        }
    } else {
        match st.query.run_at_view(ChainViewKind::ScriptHash, |view| {
            st.with_sh_join(|slot| {
                st.query
                    .scripthash_history_filtered_slot_in(sh, &filter, slot, view)
            })
        }) {
            Ok((view, items)) => {
                return maybe_attach_view(
                    match history_items_to_tx_json(&st.query, &items, st.network) {
                        Ok(v) => Json(v).into_response(),
                        Err(e) => store_err(e),
                    },
                    Some(view),
                );
            }
            Err(StoreError::NotFound) => Json(Vec::<Value>::new()).into_response(),
            Err(e) => store_err(e),
        }
    };
    maybe_attach_view(resp, view)
}

fn combined_txs(st: &AppState, sh: &[u8; 32], asof: Option<[u8; 32]>) -> Response {
    let view = match sh_pin(st, asof) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut out = Vec::new();
    if asof.is_none() {
        out.extend(mempool_txs_json(st, sh));
    }
    let filter = HistoryFilter::esplora_chain_page(None);
    let resp = if asof.is_some() {
        let Some(view) = view.as_ref() else {
            return not_found();
        };
        match st.query.scripthash_history_filtered_in(sh, &filter, view) {
            Ok(items) => match history_items_to_tx_json(&st.query, &items, st.network) {
                Ok(chain) => {
                    out.extend(chain);
                    Json(out).into_response()
                }
                Err(e) => store_err(e),
            },
            Err(e) => store_err(e),
        }
    } else {
        match st.query.run_at_view(ChainViewKind::ScriptHash, |view| {
            st.with_sh_join(|slot| {
                st.query
                    .scripthash_history_filtered_slot_in(sh, &filter, slot, view)
            })
        }) {
            Ok((view, items)) => {
                return maybe_attach_view(
                    match history_items_to_tx_json(&st.query, &items, st.network) {
                        Ok(chain) => {
                            out.extend(chain);
                            Json(out).into_response()
                        }
                        Err(e) => store_err(e),
                    },
                    Some(view),
                );
            }
            Err(StoreError::NotFound) => Json(out).into_response(),
            Err(e) => store_err(e),
        }
    };
    maybe_attach_view(resp, view)
}

pub async fn mempool_info(State(st): State<AppState>) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return Json(json!({
            "count": 0,
            "vsize": 0,
            "total_fee": 0,
            "fee_histogram": [],
        }))
        .into_response();
    };
    let live = mp.list_live_meta();
    let count = live.len();
    let mut vsize = 0u64;
    let mut total_fee = 0u64;
    for (_txid, fee, weight) in &live {
        total_fee = total_fee.saturating_add(*fee);
        vsize = vsize.saturating_add(weight.saturating_add(3) / 4);
    }
    let hist: Vec<Value> = mp
        .fee_histogram()
        .into_iter()
        .map(|(rate_kvb, vs)| {
            let rate_sat_per_vb = (rate_kvb as f64) / 1000.0;
            json!([rate_sat_per_vb, vs])
        })
        .collect();
    Json(json!({
        "count": count,
        "vsize": vsize,
        "total_fee": total_fee,
        "fee_histogram": hist,
    }))
    .into_response()
}

pub async fn fee_estimates(State(st): State<AppState>) -> Response {
    let mut obj = serde_json::Map::new();
    // One snapshot refresh + Arc load (not 11× independent graph walks).
    let pairs: Vec<(u32, f64)> = st
        .mempool
        .as_ref()
        .map(|m| m.fee_estimates_btc_per_kb())
        .unwrap_or_default();
    if pairs.is_empty() {
        for t in [1u32, 2, 3, 4, 5, 6, 10, 20, 144, 504, 1008] {
            obj.insert(t.to_string(), json!(1.0));
        }
    } else {
        for (t, btc_kb) in pairs {
            let sat_vb = if btc_kb < 0.0 {
                1.0
            } else {
                btc_kb * 100_000.0
            };
            obj.insert(t.to_string(), json!(sat_vb));
        }
    }
    Json(Value::Object(obj)).into_response()
}

pub async fn mempool_txids(State(st): State<AppState>) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return Json(json!([])).into_response();
    };
    let ids: Vec<String> = mp
        .list_live_meta()
        .into_iter()
        .map(|(txid, _, _)| block_hash_hex(&txid.to_byte_array()))
        .collect();
    Json(ids).into_response()
}

pub async fn mempool_recent(State(st): State<AppState>) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return Json(json!([])).into_response();
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
    Json(rows).into_response()
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

fn mempool_txs_json(st: &AppState, sh: &[u8; 32]) -> Vec<Value> {
    let Some(mp) = st.mempool.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in mp.scripthash_mempool(sh).into_iter().take(50) {
        if let Ok(Some((fk, _))) = st.query.get_tx_by_txid(&item.txid) {
            if let Ok(v) = build_tx_json(&st.query, fk, st.network) {
                out.push(v);
                continue;
            }
        }
        let txid = Txid::from_byte_array(item.txid);
        let Some(tx) = mp.get_tx(&txid) else {
            continue;
        };
        if let Ok(v) = build_tx_json_from_tx(
            &st.query,
            &tx,
            st.network,
            Some(item.fee),
            Some(mp.as_ref()),
        ) {
            out.push(v);
        }
    }
    out
}

fn mempool_txs_for_sh(st: &AppState, sh: &[u8; 32]) -> Response {
    Json(mempool_txs_json(st, sh)).into_response()
}

pub async fn post_tx(State(st): State<AppState>, body: Bytes) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    };
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    let hex = std::str::from_utf8(&body)
        .unwrap_or("")
        .trim()
        .trim_matches('"');
    let raw = match rbitcoin_primitives::hex_decode(hex) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")).into_response();
        }
    };
    let tx: bitcoin::Transaction = match deserialize(&raw) {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid tx: {e}")).into_response();
        }
    };
    match mp.accept_tx_async(tx).await {
        Ok(r) => {
            let tid = r.txid.to_byte_array();
            plain_ok(block_hash_hex(&tid))
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
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
    match mp.accept_package_async(txs).await {
        Ok(results) => {
            let txids: Vec<String> = results
                .iter()
                .map(|r| block_hash_hex(&r.txid.to_byte_array()))
                .collect();
            Json(json!({ "txids": txids })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod pure_helper_tests {
    use super::{block_summary_json, resolve_address_sh};
    use bitcoin::Network;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{Query, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_query() -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-esplora-pure-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (dir, q)
    }

    fn seed_genesis(q: &Query) -> [u8; 32] {
        let merkle = [0xab; 32];
        let hash = rbitcoin_store::block_header_hash(1, &[0u8; 32], &merkle, 1, 0x207f_ffff, 0);
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207f_ffff,
            nonce: 0,
            merkle_root: merkle,
            hash,
        };
        let ta = TxApply {
            tx: TxRecord {
                txid: [0xcb; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![0x00],
                witness: vec![vec![0u8; 32]],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        let _ = q.connect_block(Height(0), &header, &[ta]).unwrap();
        hash
    }

    #[test]
    fn block_summary_bits_u32_and_witness_size_weight() {
        let (dir, q) = temp_query();
        let hash = seed_genesis(&q);
        let summary = block_summary_json(&q, &hash).expect("summary");
        assert!(
            summary["bits"].is_u64(),
            "Esplora bits is u32, not hex: {}",
            summary["bits"]
        );
        assert_eq!(summary["bits"], 0x207f_ffff);
        let block = q.reconstruct_archived_block(&hash).unwrap().unwrap();
        assert_eq!(summary["size"], block.total_size() as u64);
        assert_eq!(summary["weight"], block.weight().to_wu());
        assert_ne!(
            summary["weight"].as_u64().unwrap(),
            summary["size"].as_u64().unwrap().saturating_mul(4),
            "witness block weight is not 4×stripped size"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_address_sh_and_block_summary_surface() {
        // Invalid / wrong-network addresses.
        assert!(resolve_address_sh("not-an-address", Network::Bitcoin).is_err());
        assert!(resolve_address_sh(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Regtest
        )
        .is_err());
        // Well-known mainnet P2WPKH.
        let sh = resolve_address_sh(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Bitcoin,
        )
        .expect("mainnet p2wpkh");
        assert_ne!(sh, [0u8; 32]);

        let (dir, q) = temp_query();
        let hash = seed_genesis(&q);
        let summary = block_summary_json(&q, &hash).expect("genesis summary");
        assert_eq!(summary["height"], 0);
        assert_eq!(summary["tx_count"], 1);
        assert!(summary["previousblockhash"].is_null());
        assert!(summary["id"].as_str().unwrap().len() == 64);
        assert!(summary["difficulty"].as_f64().unwrap() > 0.0);
        assert!(summary["size"].as_u64().unwrap() > 80);
        assert!(summary["weight"].as_u64().unwrap() > 0);
        // Unknown hash → NotFound class error.
        assert!(block_summary_json(&q, &[0x11; 32]).is_err());
        let _ = q.sample_reset_reconstruct_archived();
        let _ = block_summary_json(&q, &hash).expect("summary again");
        assert!(
            q.sample_reset_reconstruct_archived() >= 1,
            "block JSON reconstructs for consensus size/weight"
        );
        assert!(q.reconstruct_archived_block(&hash).unwrap().is_some());
        assert!(q.sample_reset_reconstruct_archived() >= 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn casa_sh_routes_reuse_last_join_slot() {
        use crate::server::AppState;
        use rbitcoin_query::{body_ok_reads, reset_body_ok_reads};
        use rbitcoin_store::script_hash;
        use std::sync::{Arc, Mutex};

        let (dir, q) = temp_query();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..3u32 {
            let merkle = {
                let mut m = [0xab; 32];
                m[0] = h as u8;
                m
            };
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207f_ffff, h)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version: 1,
                timestamp: h + 1,
                bits: 0x207f_ffff,
                nonce: h,
                merkle_root: merkle,
                hash,
            };
            let mut txid = [0xcb; 32];
            txid[0] = h as u8;
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
                inputs: vec![InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: Fk::NULL,
                    prev_index: u32::MAX,
                    sequence: u32::MAX,
                    script_sig: vec![h as u8],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let st = AppState {
            query: Arc::new(q),
            network: Network::Regtest,
            mempool: None,
            max_body: 1 << 20,
            tip_tx: None,
            ws_sem: None,
            max_ws_message_bytes: 64 * 1024,
            max_track_addresses: 64,
            max_track_txs: 64,
            sh_join: Arc::new(Mutex::new(None)),
        };
        let sh = script_hash(&[0x51]);
        reset_body_ok_reads();
        let (info, _) = super::sh_stats_json(&st, &sh, None, None, None).unwrap();
        assert_eq!(info["chain_stats"]["tx_count"], 3);
        let after_info = body_ok_reads();
        assert_eq!(after_info, 3);

        let _ = super::utxo_response(&st, &sh, None);
        assert_eq!(
            body_ok_reads(),
            after_info,
            "/utxo must reuse the last SH join"
        );
        let _ = super::chain_page_sh(&st, &sh, None, None);
        assert_eq!(
            body_ok_reads(),
            after_info,
            "/txs must reuse the last SH join"
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
