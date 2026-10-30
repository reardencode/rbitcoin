//! BlindBit oracle v1 read routes under `/blindbit/v1/` (#1119).
//!
//! The contract is the v1 client in Dana's `spdk` (`backends/blindbit-v1`),
//! not BlindBit's own server where they differ: `spent-index` is always an
//! object, and `info.network` is a Core arg name. Served only while
//! `--sp-tweaks` is on, and only through the thin index's next height.
//!
//! `dustLimit` keeps a tx whose largest P2TR output is `>= dustLimit`
//! (BlindBit's edge). It is not `--sp-tweaks-dust`. `tweaks` is cut-through:
//! confirmed-spent outputs are dropped first. `tweak-index` is every
//! eligible tx.

use crate::handlers::spawn_join;
use crate::server::{block_hash_hex, json_reply_here, AppState};
use axum::extract::{Extension, Path, Query as UrlQuery, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::hashes::{sha256, Hash};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::{Query, QueryError, ThinTweakRangeLimits, ThinTweakRow};
use rbitcoin_store::StoreError;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Mount point of the v1 surface on the Esplora listener.
pub const BLINDBIT_V1_PREFIX: &str = "/blindbit/v1";

/// Default for requests in flight across every `/blindbit/v1/` route: half
/// the node's blocking pool (`available_parallelism`, at least 4), since each
/// read runs there and keeps its permit until it returns. spdk keeps about
/// 200 asks open per scan; they queue here, before they take a listener slot.
pub fn default_max_inflight() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .max(4)
        / 2
}

/// One permit of the `/blindbit/v1/` semaphore, carried by the request.
/// Handlers move it into the blocking read, so a request that times out or
/// whose client goes away still holds it until the read returns.
#[derive(Clone)]
pub struct BlindbitPermit(#[allow(dead_code)] Arc<OwnedSemaphorePermit>);

/// Wait for a `/blindbit/v1/` permit. Mounted outside the listener's own
/// limit, so a queued request does not hold a listener slot.
pub async fn blindbit_permit_mw(
    State(sem): State<Arc<Semaphore>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Ok(permit) = sem.acquire_owned().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "shutting down");
    };
    req.extensions_mut()
        .insert(BlindbitPermit(Arc::new(permit)));
    next.run(req).await
}

/// [`spawn_join`] that holds `permit` until `f` returns.
async fn held(permit: BlindbitPermit, f: impl FnOnce() -> Response + Send + 'static) -> Response {
    spawn_join(move || {
        let _permit = permit;
        f()
    })
    .await
}

/// The v1 routes, nested under [`BLINDBIT_V1_PREFIX`]. Each needs a
/// [`BlindbitPermit`] from [`blindbit_permit_mw`].
pub fn blindbit_routes() -> Router<AppState> {
    Router::new().nest(
        BLINDBIT_V1_PREFIX,
        Router::new()
            .route("/info", get(info))
            .route("/block-height", get(block_height))
            .route("/block-hash/{height}", get(block_hash))
            .route("/tweaks/{height}", get(tweaks))
            .route("/tweak-index/{height}", get(tweak_index))
            .route("/utxos/{height}", get(utxos))
            .route("/spent-index/{height}", get(spent_index))
            .route("/filter/new-utxos/{height}", get(filter_new_utxos))
            .route("/filter/spent/{height}", get(filter_spent))
            .route("/forward-tx", post(forward_tx)),
    )
}

#[derive(Deserialize)]
pub struct DustParam {
    #[serde(rename = "dustLimit")]
    dust_limit: Option<String>,
}

/// Last height every v1 route can answer: the confirmed tip, capped by the
/// thin tweak index. `None` while the index is off or holds no height.
pub fn served_height(query: &Query) -> Option<u32> {
    if !query.sptweaks_enabled() {
        return None;
    }
    let next = query.sptweaks_next_height()?.0;
    let indexed = next.checked_sub(1)?;
    if next <= query.sptweaks_origin().0 {
        return None;
    }
    Some(indexed.min(query.tip_height()?.0))
}

/// BlindBit `HighestValue >= dustLimit` over the P2TR outputs a row still has.
pub fn keeps_dust(row: &ThinTweakRow, dust_limit: u64) -> bool {
    row.p2tr
        .iter()
        .map(|&(_, _, value)| value)
        .max()
        .unwrap_or(0)
        >= dust_limit
}

/// First 8 bytes of `sha256(txid ‖ vout_le ‖ block_hash)`, all in internal
/// byte order: BlindBit v1 `BuildSpentUTXOIndex`, salted by the spending block.
pub fn spent_short_hash(prev_txid: &[u8; 32], vout: u32, block_hash: &[u8; 32]) -> [u8; 8] {
    let mut buf = [0u8; 68];
    buf[..32].copy_from_slice(prev_txid);
    buf[32..36].copy_from_slice(&vout.to_le_bytes());
    buf[36..].copy_from_slice(block_hash);
    let digest = sha256::Hash::hash(&buf).to_byte_array();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// The listener's `store_err` statuses, with this surface's `{"error"}` body.
fn store_error(e: QueryError) -> Response {
    match e {
        StoreError::NotFound => error(StatusCode::NOT_FOUND, "not found"),
        StoreError::Pruned { .. } => error(StatusCode::NOT_FOUND, "pruned"),
        StoreError::Stale(m) | StoreError::Rejected(m) => error(StatusCode::SERVICE_UNAVAILABLE, m),
        e @ StoreError::ShCreatesCap { .. } => {
            error(StatusCode::SERVICE_UNAVAILABLE, &e.to_string())
        }
        e => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `confirmed[h]` moved between the reads one answer is built from.
pub const CHAIN_MOVED: &str = "chain view moved";

fn not_indexed() -> Response {
    error(StatusCode::NOT_FOUND, "height not indexed")
}

#[allow(clippy::result_large_err)] // axum Response, as in handlers
fn parse_height(s: &str) -> Result<u32, Response> {
    s.parse()
        .map_err(|_| error(StatusCode::BAD_REQUEST, "could not parse block height"))
}

#[allow(clippy::result_large_err)] // axum Response, as in handlers
fn parse_dust(p: &DustParam) -> Result<u64, Response> {
    match p.dust_limit.as_deref() {
        None => Ok(0),
        Some(s) => s
            .parse()
            .map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid dustLimit parameter")),
    }
}

/// A served height and the confirmed header every read for it must match.
#[derive(Clone, Copy, Debug)]
pub struct ServedBlock {
    pub height: u32,
    pub header_fk: Fk,
    /// Internal byte order.
    pub hash: [u8; 32],
    pub time: u32,
}

#[allow(clippy::result_large_err)] // axum Response, as in handlers
fn served_block(query: &Query, raw: &str) -> Result<ServedBlock, Response> {
    let h = parse_height(raw)?;
    if served_height(query).is_none_or(|top| h > top) {
        return Err(not_indexed());
    }
    match query.header_at_height(Height(h)) {
        Ok(Some((header_fk, rec))) => Ok(ServedBlock {
            height: h,
            header_fk,
            hash: rec.hash,
            time: rec.timestamp,
        }),
        Ok(None) => Err(not_indexed()),
        Err(e) => Err(store_error(e)),
    }
}

/// `confirmed[h]` is still `block`. A reorg between two reads of one
/// answer is [`CHAIN_MOVED`], never data keyed by the other block's hash.
pub fn still_confirmed(query: &Query, block: &ServedBlock) -> Result<(), QueryError> {
    match query.header_at_height(Height(block.height))? {
        Some((fk, _)) if fk == block.header_fk => Ok(()),
        _ => Err(StoreError::Stale(CHAIN_MOVED)),
    }
}

/// Thin rows at a served height. The index starts at Taproot activation,
/// so an earlier height is not indexed.
#[allow(clippy::result_large_err)] // axum Response, as in handlers
pub fn thin_rows(
    query: &Query,
    block: &ServedBlock,
    cut_through: bool,
) -> Result<Vec<ThinTweakRow>, Response> {
    let limits = ThinTweakRangeLimits {
        max_heights: 1,
        max_eligible: usize::MAX,
        cut_through,
    };
    // The plan reads `confirmed[h]` and the tweak row together under the
    // `sp_tweaks` lock, so its header fk names the block the rows belong to,
    // and the txout join reads that header's own txs. A reorg that commits
    // during the join is a moved view, not a 200 for a replaced height.
    match query.load_thin_tweaks_range_with_header(Height(block.height), limits) {
        Ok(mut batch) => match batch.pop() {
            Some((_, fk, rows)) if fk == block.header_fk => {
                still_confirmed(query, block).map_err(store_error)?;
                Ok(rows)
            }
            Some(_) => Err(store_error(StoreError::Stale(CHAIN_MOVED))),
            None => {
                // The replacement block may not be indexed yet.
                still_confirmed(query, block).map_err(store_error)?;
                Err(not_indexed())
            }
        },
        Err(e) => Err(store_error(e)),
    }
}

pub async fn info(State(st): State<AppState>, Extension(p): Extension<BlindbitPermit>) -> Response {
    held(p, move || {
        // spdk reads `height` as a block height, so 0 would be genesis.
        let Some(height) = served_height(&st.query) else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "no height indexed");
        };
        json_reply_here(json!({
            // `spdk` parses this with `Network::from_core_arg`.
            "network": st.network.to_core_arg(),
            "height": height,
            "tweaks_only": false,
            "tweaks_full_basic": true,
            "tweaks_full_with_dust_filter": true,
            "tweaks_cut_through_with_dust_filter": true,
        }))
    })
    .await
}

pub async fn block_height(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
) -> Response {
    held(p, move || match served_height(&st.query) {
        Some(h) => json_reply_here(json!({ "block_height": h })),
        None => error(StatusCode::SERVICE_UNAVAILABLE, "no height indexed"),
    })
    .await
}

pub async fn block_hash(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
) -> Response {
    held(p, move || match served_block(&st.query, &raw) {
        Ok(b) => json_reply_here(json!({ "block_hash": block_hash_hex(&b.hash) })),
        Err(r) => r,
    })
    .await
}

fn tweak_list(st: &AppState, raw: &str, dust: &DustParam, cut_through: bool) -> Response {
    let dust_limit = match parse_dust(dust) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let block = match served_block(&st.query, raw) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match thin_rows(&st.query, &block, cut_through) {
        Ok(rows) => {
            let list: Vec<String> = rows
                .iter()
                .filter(|r| keeps_dust(r, dust_limit))
                .map(|r| rbitcoin_primitives::hex_encode(r.tweak))
                .collect();
            json_reply_here(list)
        }
        Err(r) => r,
    }
}

pub async fn tweaks(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
    UrlQuery(dust): UrlQuery<DustParam>,
) -> Response {
    held(p, move || tweak_list(&st, &raw, &dust, true)).await
}

pub async fn tweak_index(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
    UrlQuery(dust): UrlQuery<DustParam>,
) -> Response {
    held(p, move || tweak_list(&st, &raw, &dust, false)).await
}

/// Every P2TR output of every eligible tx, with `spent` from the
/// cut-through view of the same height.
fn utxos_json(st: &AppState, raw: &str) -> Response {
    let block = match served_block(&st.query, raw) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (h, hash, time) = (block.height, block.hash, block.time);
    let full = match thin_rows(&st.query, &block, false) {
        Ok(rows) => rows,
        Err(r) => return r,
    };
    let live: HashSet<([u8; 32], u32)> = match thin_rows(&st.query, &block, true) {
        Ok(rows) => rows
            .iter()
            .flat_map(|r| r.p2tr.iter().map(move |&(vout, _, _)| (r.txid, vout)))
            .collect(),
        Err(r) => return r,
    };
    let block_hash = block_hash_hex(&hash);
    let mut out: Vec<Value> = Vec::new();
    for r in &full {
        let txid = block_hash_hex(&r.txid);
        for &(vout, xonly, value) in &r.p2tr {
            let mut spk = String::with_capacity(68);
            spk.push_str("5120");
            spk.push_str(&rbitcoin_primitives::hex_encode(xonly));
            out.push(json!({
                "txid": txid,
                "vout": vout,
                "value": value,
                "scriptpubkey": spk,
                "block_height": h,
                "block_hash": block_hash,
                "timestamp": time,
                "spent": !live.contains(&(r.txid, vout)),
            }));
        }
    }
    json_reply_here(out)
}

pub async fn utxos(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
) -> Response {
    held(p, move || utxos_json(&st, &raw)).await
}

/// What the spdk scan reads from one block: the x-only key of every P2TR
/// output, and the short hash of every spent outpoint.
#[derive(Default)]
pub struct BlockSpElements {
    pub new_keys: Vec<[u8; 32]>,
    pub spent: Vec<[u8; 8]>,
}

/// The filter elements of `block`, from its own txs only: one `txout` span
/// for the keys, input edges and the txid sidefile for the spends. No
/// parent txout is read, so a spend's script is unknown and every spent
/// outpoint is hashed, not only P2TR ones as BlindBit does. spdk tests its
/// own outpoints for membership, which a superset still answers. Below the
/// tweak index origin (Taproot activation on mainnet) no output can be a
/// silent payment, so both sets are empty and nothing is read.
pub fn block_sp_elements(
    query: &Query,
    block: &ServedBlock,
    keys: bool,
    spent: bool,
) -> Result<BlockSpElements, QueryError> {
    if block.height < query.sptweaks_origin().0 {
        return Ok(BlockSpElements::default());
    }
    // Read through the header, so the elements belong to the hash that salts
    // them; then a moved view is 503, never the other block's data.
    let read = query.block_sp_outpoints(block.header_fk, keys, spent)?;
    still_confirmed(query, block)?;
    Ok(BlockSpElements {
        new_keys: read.p2tr_keys,
        spent: read
            .spent
            .iter()
            .map(|(txid, vout)| spent_short_hash(txid, *vout, &block.hash))
            .collect(),
    })
}

/// BIP158 GCS (P=19, M=784931) keyed by the block hash, as BlindBit v1
/// builds both filters. Clients test membership; a repeated element is
/// written once here and twice by BlindBit, which does not change a match.
pub fn sp_filter_bytes<'a>(
    block_hash: &[u8; 32],
    elements: impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, QueryError> {
    Ok(rbitcoin_query::block_filter::encode_basic_filter(block_hash, elements)?.content)
}

#[allow(clippy::result_large_err)] // axum Response, as in handlers
fn sp_elements_at(
    st: &AppState,
    raw: &str,
    keys: bool,
    spent: bool,
) -> Result<(u32, [u8; 32], BlockSpElements), Response> {
    let block = served_block(&st.query, raw)?;
    let elements = block_sp_elements(&st.query, &block, keys, spent).map_err(store_error)?;
    Ok((block.height, block.hash, elements))
}

fn spent_index_json(st: &AppState, raw: &str) -> Response {
    let (_, hash, elements) = match sp_elements_at(st, raw, false, true) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data: Vec<String> = elements
        .spent
        .iter()
        .map(rbitcoin_primitives::hex_encode)
        .collect();
    json_reply_here(json!({ "block_hash": block_hash_hex(&hash), "data": data }))
}

pub async fn spent_index(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
) -> Response {
    held(p, move || spent_index_json(&st, &raw)).await
}

/// BlindBit v1 `filter_type` for both filters.
pub const SP_FILTER_TYPE: u8 = 4;

fn filter_json(st: &AppState, raw: &str, spent: bool) -> Response {
    let (h, hash, elements) = match sp_elements_at(st, raw, !spent, spent) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let bytes = if spent {
        sp_filter_bytes(&hash, elements.spent.iter().map(|s| s.as_slice()))
    } else {
        sp_filter_bytes(&hash, elements.new_keys.iter().map(|k| k.as_slice()))
    };
    match bytes {
        Ok(data) => json_reply_here(json!({
            "filter_type": SP_FILTER_TYPE,
            "block_height": h,
            "block_hash": block_hash_hex(&hash),
            "data": rbitcoin_primitives::hex_encode(&data),
        })),
        Err(e) => store_error(e),
    }
}

pub async fn filter_new_utxos(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
) -> Response {
    held(p, move || filter_json(&st, &raw, false)).await
}

pub async fn filter_spent(
    State(st): State<AppState>,
    Extension(p): Extension<BlindbitPermit>,
    Path(raw): Path<String>,
) -> Response {
    held(p, move || filter_json(&st, &raw, true)).await
}

#[derive(Deserialize)]
pub struct ForwardTx {
    data: String,
}

/// Broadcast `{"data": "<hex>"}`. The answer is the txid as a JSON string:
/// spdk parses the body as a `Txid`, so BlindBit's empty 200 reads as an error.
pub async fn forward_tx(
    State(st): State<AppState>,
    // Extracted before the body, which drops the request's extensions.
    Extension(permit): Extension<BlindbitPermit>,
    body: axum::body::Bytes,
) -> Response {
    let Some(mp) = st.mempool.clone() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "mempool not available");
    };
    let req: ForwardTx = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "could not parse request"),
    };
    let raw = match rbitcoin_primitives::hex_decode(req.data.trim()) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid hex"),
    };
    let tx: bitcoin::Transaction = match bitcoin::consensus::deserialize(&raw) {
        Ok(t) => t,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid tx"),
    };
    // The admit runs inside `held`, so a timeout or disconnect that drops
    // this handler does not free the permit while it is still running.
    held(permit, move || {
        match mp.accept_tx_from(&tx, rbitcoin_net::TxOrigin::Local) {
            Ok(r) => json_reply_here(block_hash_hex(&r.txid.to_byte_array())),
            Err(e) => error(StatusCode::BAD_REQUEST, &e.to_string()),
        }
    })
    .await
}
