use super::*;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Txid};
use rbitcoin_primitives::{median_time_past_times, Height};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Instant;

fn wait_chain_tip(ctx: &RpcContext) {
    if let Some(c) = ctx.chain.as_ref() {
        c.wait_tip_stable_for_rpc();
    }
}

pub(crate) fn getblockcount(ctx: &RpcContext) -> Result<Value, Value> {
    wait_chain_tip(ctx);
    let h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    Ok(json!(h))
}

pub(crate) fn getbestblockhash(ctx: &RpcContext) -> Result<Value, Value> {
    wait_chain_tip(ctx);
    let Some(tip) = ctx.query.tip_height() else {
        return Err(rpc_error(ERR_MISC, "no tip"));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

pub(crate) fn getblockhash(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height"])?;
    let height = params.req_u64(0, "height")? as u32;
    let (_, rec) = ctx
        .query
        .header_at_height(Height(height))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMETER, "Block height out of range"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

pub(crate) fn getblockchaininfo(ctx: &RpcContext) -> Result<Value, Value> {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    // Live hub latch, not the tip-follow copy: `feature_maxtipage` asserts
    // immediately after `sync_all`, before the 50ms RPC tick may store.
    let ibd = ctx
        .chain
        .as_ref()
        .map(|c| c.in_ibd())
        .unwrap_or_else(|| ctx.initial_block_download.load(Ordering::Relaxed));
    let headers = ctx
        .chain
        .as_ref()
        .map(|c| c.best_header_height())
        .unwrap_or(tip);
    let verificationprogress = if headers == 0 {
        1.0
    } else {
        (tip as f64 / headers as f64).clamp(0.0, 1.0)
    };
    let (time, mediantime) = if let Some(h) = ctx.query.tip_height() {
        if let Ok(Some((_, rec))) = ctx.query.header_at_height(h) {
            let mtp = rbitcoin_consensus::median_time_past(ctx.query.as_ref(), h)
                .unwrap_or(rec.timestamp);
            (rec.timestamp, mtp)
        } else {
            (0u32, 0u32)
        }
    } else {
        (0u32, 0u32)
    };
    let mut info = json!({
        "chain": chain_name(ctx.network),
        "blocks": tip,
        "headers": headers,
        "bestblockhash": best,
        "difficulty": core_f64_json(difficulty_at_tip(ctx).unwrap_or(0.0)),
        "time": time,
        "mediantime": mediantime,
        "verificationprogress": verificationprogress,
        "initialblockdownload": ibd,
        "chainwork": chainwork_hex(ctx, ctx.query.tip_height()),
        "size_on_disk": ctx.query.store().datadir_bytes(),
        "pruned": ctx.query.prune_seqsigwit(),
        "warnings": rpc_warnings(ctx),
    });
    if let Some(h) = ctx.query.pruneheight() {
        info["pruneheight"] = json!(h.0);
    }
    if let Some(h) = ctx.query.tip_height() {
        if let Ok(Some((_, rec))) = ctx.query.header_at_height(h) {
            info["bits"] = json!(format!("{:08x}", rec.bits));
            info["target"] = json!(target_hex(rec.bits));
        }
    }
    Ok(info)
}

pub(crate) fn rpc_warnings(ctx: &RpcContext) -> Vec<String> {
    let w = rbitcoin_net::warning_strings(ctx.query.as_ref(), ctx.network);
    if !w.is_empty()
        && ctx
            .alert_fired
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        if let Some(cmd) = ctx.alert_notify.as_deref() {
            let msg = w.join(", ");
            // Core ShellEscape: single-quote so `(versionbit N)` is not a subshell.
            let escaped = format!("'{}'", msg.replace('\'', "'\\''"));
            let shell = cmd.replace("%s", &escaped);
            match std::process::Command::new("sh")
                .arg("-c")
                .arg(&shell)
                .status()
            {
                Ok(st) if !st.success() => {
                    rbitcoin_log::warn!("alertnotify exited {st}: {shell}");
                }
                Err(e) => rbitcoin_log::warn!("alertnotify failed: {e}: {shell}"),
                _ => {}
            }
        }
    }
    w
}

pub(crate) use rbitcoin_consensus::difficulty_from_bits;

/// Compact-target bytes as Core `target` (64 hex chars).
pub(crate) fn target_hex(bits: u32) -> String {
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    format!("{target:064x}")
}

/// Core `UniValue` `setprecision(16)` defaultfloat. Keeps the 16th significant
/// digit (`132757073449487.52` prints `132757073449487.5`).
pub(crate) fn format_core_double(v: f64) -> String {
    if !v.is_finite() || v == 0.0 {
        return "0".to_string();
    }
    let neg = v.is_sign_negative();
    let v = v.abs();
    let mut exp = v.log10().floor() as i32;
    let mut scaled = (v / 10f64.powi(exp - 15)).round();
    if scaled >= 1e16 {
        scaled /= 10.0;
        exp += 1;
    }
    let digits = format!("{scaled:.0}");
    let pos = exp + 1;
    let body = if pos <= 0 {
        format!(
            "0.{}{}",
            "0".repeat((-pos) as usize),
            digits.trim_end_matches('0')
        )
    } else if (pos as usize) >= digits.len() {
        format!("{}{}", digits, "0".repeat(pos as usize - digits.len()))
    } else {
        let (a, b) = digits.split_at(pos as usize);
        let b = b.trim_end_matches('0');
        if b.is_empty() {
            a.to_string()
        } else {
            format!("{a}.{b}")
        }
    };
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

pub(crate) fn core_f64_json(v: f64) -> Value {
    let s = format_core_double(v);
    Value::Number(s.parse().expect("core double decimal"))
}

/// `getblockchaininfo.difficulty`: [`difficulty_from_bits`] at 16 significant digits.
pub fn difficulty_rpc_f64(bits: u32) -> f64 {
    core_f64_json(difficulty_from_bits(bits))
        .as_f64()
        .expect("core difficulty decimal")
}

pub(crate) fn difficulty_at_tip(ctx: &RpcContext) -> Result<f64, Value> {
    let tip = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(tip)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(difficulty_from_bits(rec.bits))
}

pub(crate) fn getdifficulty(ctx: &RpcContext) -> Result<Value, Value> {
    Ok(core_f64_json(difficulty_at_tip(ctx)?))
}

pub(crate) fn getblockheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbose = params.opt_bool(1, "verbose")?.unwrap_or(true);
    let hash = parse_hash32_display(hash_hex)?;
    if let Some(height) = ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        return active_block_header(ctx, height, verbose);
    }
    if let Some(loc) = off_chain_header(ctx, &hash)? {
        return off_chain_header_value(ctx, &loc, verbose);
    }
    let typed = BlockHash::from_byte_array(hash);
    if let Some(block) = ctx.chain.as_ref().and_then(|c| c.held_body(&typed)) {
        return held_header_value(ctx, &block, verbose);
    }
    Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))
}

fn active_block_header(ctx: &RpcContext, height: Height, verbose: bool) -> Result<Value, Value> {
    let (_, rec) = ctx
        .query
        .header_at_height(height)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    if !verbose {
        let hdr = ctx
            .query
            .wire_header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        return Ok(json!(header_hex(&hdr)?));
    }
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let mut obj = json!({
        "hash": hash_hex_display(&rec.hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": rec.version,
        "versionHex": format!("{:08x}", rec.version),
        "merkleroot": hash_hex_display(&rec.merkle_root),
        "time": rec.timestamp,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(rec.timestamp),
        "nonce": rec.nonce,
        "bits": format!("{:08x}", rec.bits),
        "difficulty": core_f64_json(difficulty_from_bits(rec.bits)),
        "chainwork": chainwork_hex(ctx, Some(height)),
        "nTx": ctx.query.block_tx_fks(height).map(|v| v.len()).unwrap_or(0),
        "target": target_hex(rec.bits),
    });
    insert_previousblockhash(&mut obj, &prev);
    if let Some(n) = nextblockhash_at(ctx, height) {
        obj["nextblockhash"] = json!(n);
    }
    Ok(obj)
}

fn header_hex(hdr: &bitcoin::block::Header) -> Result<String, Value> {
    let mut raw = Vec::new();
    hdr.consensus_encode(&mut raw)
        .map_err(|_| rpc_error(ERR_MISC, "header encode"))?;
    Ok(hex_encode(raw))
}

fn insert_previousblockhash(obj: &mut Value, prev: &str) {
    if prev.is_empty() {
        return;
    }
    if let Some(o) = obj.as_object_mut() {
        o.insert("previousblockhash".into(), json!(prev));
    }
}

struct OffChainHeader {
    rec: rbitcoin_store::HeaderRecord,
    header_fk: rbitcoin_primitives::Fk,
    height: u32,
    prev_hash: Option<[u8; 32]>,
    chainwork: String,
    /// Median of this header and up to 10 ancestors (Core `GetMedianTimePast`).
    mediantime: u32,
}

/// Header-sync ancestry cap (`stored_header_height`). One `prev_fk` read per
/// step; active membership is the height index. A longer stale branch errors
/// instead of scanning the rest of the branch.
const OFF_CHAIN_WALK_MAX: u32 = 10_000;

/// Header that is stored but not on the active chain. Height and chainwork
/// walk `prev_fk` until an active ancestor (or genesis).
fn off_chain_header(ctx: &RpcContext, hash: &[u8; 32]) -> Result<Option<OffChainHeader>, Value> {
    let Some((header_fk, rec)) = ctx
        .query
        .get_header_by_hash(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    else {
        return Ok(None);
    };
    let mut cur = rec.clone();
    let mut works = Vec::new();
    let mut times = Vec::with_capacity(11);
    let mut immediate_prev: Option<[u8; 32]> = None;
    for step in 0..OFF_CHAIN_WALK_MAX {
        works.push(work_from_bits(cur.bits));
        if times.len() < 11 {
            times.push(cur.timestamp);
        }
        if cur.prev_fk.is_null() {
            return Ok(Some(off_chain_done(
                rec,
                header_fk,
                (works.len() as u32).saturating_sub(1),
                None,
                hex_encode(sum_header_work(works).to_be_bytes()),
                &times,
            )));
        }
        let parent = ctx
            .query
            .get_header(cur.prev_fk)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        if step == 0 {
            immediate_prev = Some(parent.hash);
        }
        if let Some(h) = ctx
            .query
            .confirmed_height_of_hash(&parent.hash)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        {
            if times.len() < 11 {
                times.push(parent.timestamp);
            }
            fill_mtp_below(ctx, &mut times, h.0)?;
            let height = h.0.saturating_add(works.len() as u32);
            let extra = sum_header_work(works);
            let cw = match ctx.chain.as_ref() {
                Some(hub) => hub
                    .work_through_height(h.0)
                    .map(|w| w + extra)
                    .unwrap_or(extra),
                None => extra,
            };
            return Ok(Some(off_chain_done(
                rec,
                header_fk,
                height,
                immediate_prev,
                hex_encode(cw.to_be_bytes()),
                &times,
            )));
        }
        cur = parent;
    }
    Err(rpc_error(ERR_MISC, "side header walk exceeded"))
}

fn off_chain_done(
    rec: rbitcoin_store::HeaderRecord,
    header_fk: rbitcoin_primitives::Fk,
    height: u32,
    prev_hash: Option<[u8; 32]>,
    chainwork: String,
    times: &[u32],
) -> OffChainHeader {
    OffChainHeader {
        rec,
        header_fk,
        height,
        prev_hash,
        chainwork,
        mediantime: median_time_past_times(times),
    }
}

/// Ancestors strictly below an active parent, until the 11-timestamp window is full.
fn fill_mtp_below(ctx: &RpcContext, times: &mut Vec<u32>, parent_height: u32) -> Result<(), Value> {
    let mut h = parent_height;
    while times.len() < 11 && h > 0 {
        h -= 1;
        let Some((_, rec)) = ctx
            .query
            .header_at_height(Height(h))
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        else {
            break;
        };
        times.push(rec.timestamp);
    }
    Ok(())
}

/// MTP when the block is not a stored header row: at most 10 parent reads.
fn median_time_from_wire(ctx: &RpcContext, time: u32, prev_hash: [u8; 32]) -> Result<u32, Value> {
    let mut times = vec![time];
    if prev_hash != [0u8; 32] {
        if let Some((_, rec)) = ctx
            .query
            .get_header_by_hash(&prev_hash)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        {
            times.push(rec.timestamp);
            let mut fk = rec.prev_fk;
            while times.len() < 11 && !fk.is_null() {
                let parent = ctx
                    .query
                    .get_header(fk)
                    .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
                times.push(parent.timestamp);
                fk = parent.prev_fk;
            }
        }
    }
    Ok(median_time_past_times(&times))
}

fn work_from_bits(bits: u32) -> bitcoin::Work {
    bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(0),
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce: 0,
    }
    .work()
}

fn sum_header_work(works: Vec<bitcoin::Work>) -> bitcoin::Work {
    rbitcoin_net::sum_work(works.into_iter()).unwrap_or(bitcoin::Work::from_be_bytes([0xff; 32]))
}

fn wire_header_from_record(
    rec: &rbitcoin_store::HeaderRecord,
    prev: [u8; 32],
) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(rec.version),
        prev_blockhash: BlockHash::from_byte_array(prev),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(rec.merkle_root),
        time: rec.timestamp,
        bits: bitcoin::CompactTarget::from_consensus(rec.bits),
        nonce: rec.nonce,
    }
}

fn off_chain_header_value(
    ctx: &RpcContext,
    loc: &OffChainHeader,
    verbose: bool,
) -> Result<Value, Value> {
    let prev = loc.prev_hash.unwrap_or([0u8; 32]);
    if !verbose {
        return Ok(json!(header_hex(&wire_header_from_record(&loc.rec, prev))?));
    }
    let n_tx = ctx
        .query
        .header_tx_fks(loc.header_fk, Some(&loc.rec.hash))
        .ok()
        .flatten()
        .map(|v| v.len())
        .unwrap_or(0);
    let mut obj = json!({
        "hash": hash_hex_display(&loc.rec.hash),
        "confirmations": -1,
        "height": loc.height,
        "version": loc.rec.version,
        "versionHex": format!("{:08x}", loc.rec.version),
        "merkleroot": hash_hex_display(&loc.rec.merkle_root),
        "time": loc.rec.timestamp,
        "mediantime": loc.mediantime,
        "nonce": loc.rec.nonce,
        "bits": format!("{:08x}", loc.rec.bits),
        "difficulty": core_f64_json(difficulty_from_bits(loc.rec.bits)),
        "chainwork": loc.chainwork,
        "nTx": n_tx,
        "target": target_hex(loc.rec.bits),
    });
    if let Some(p) = loc.prev_hash {
        insert_previousblockhash(&mut obj, &hash_hex_display(&p));
    }
    Ok(obj)
}

fn held_header_value(ctx: &RpcContext, block: &Block, verbose: bool) -> Result<Value, Value> {
    if !verbose {
        return Ok(json!(header_hex(&block.header)?));
    }
    let bits = block.header.bits.to_consensus();
    let version = block.header.version.to_consensus();
    let prev = block.header.prev_blockhash.to_byte_array();
    let mediantime = median_time_from_wire(ctx, block.header.time, prev)?;
    let mut obj = json!({
        "hash": hash_hex_display(&block.block_hash().to_byte_array()),
        "confirmations": -1,
        "version": version,
        "versionHex": format!("{:08x}", version),
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": mediantime,
        "nonce": block.header.nonce,
        "bits": format!("{:08x}", bits),
        "difficulty": core_f64_json(difficulty_from_bits(bits)),
        "chainwork": hex_encode(block.header.work().to_be_bytes()),
        "nTx": block.txdata.len(),
        "target": target_hex(bits),
    });
    if prev != [0u8; 32] {
        insert_previousblockhash(&mut obj, &hash_hex_display(&prev));
    }
    Ok(obj)
}

/// 32-byte BE chainwork hex (regtest = 2 per block). Empty store → 64 zeros.
pub(crate) fn chainwork_hex(ctx: &RpcContext, through: Option<Height>) -> String {
    let Some(tip) = through.or_else(|| ctx.query.tip_height()) else {
        return "00".repeat(32);
    };
    if let Some(hub) = ctx.chain.as_ref() {
        if let Ok(w) = hub.work_through_height(tip.0) {
            return hex_encode(w.to_be_bytes());
        }
    }
    let mut works = Vec::new();
    for h in 0..=tip.0 {
        if let Ok(hdr) = ctx.query.wire_header_at_height(Height(h)) {
            works.push(hdr.work());
        }
    }
    hex_encode(
        rbitcoin_net::sum_work(works.into_iter())
            .unwrap_or(bitcoin::Work::from_be_bytes([0xff; 32]))
            .to_be_bytes(),
    )
}

fn version_hex(version: i32) -> String {
    format!("{:08x}", version as u32)
}

fn nextblockhash_at(ctx: &RpcContext, height: Height) -> Option<String> {
    ctx.query
        .header_at_height(Height(height.0 + 1))
        .ok()
        .flatten()
        .map(|(_, r)| hash_hex_display(&r.hash))
}

fn enrich_block_header_json(
    obj: &mut Value,
    ctx: &RpcContext,
    version: i32,
    bits: u32,
    height: Option<Height>,
    held_chainwork: Option<String>,
) {
    let Some(o) = obj.as_object_mut() else {
        return;
    };
    o.insert("versionHex".into(), json!(version_hex(version)));
    o.insert(
        "difficulty".into(),
        core_f64_json(difficulty_from_bits(bits)),
    );
    o.insert("target".into(), json!(target_hex(bits)));
    match height {
        Some(h) => {
            o.insert("chainwork".into(), json!(chainwork_hex(ctx, Some(h))));
            if let Some(n) = nextblockhash_at(ctx, h) {
                o.insert("nextblockhash".into(), json!(n));
            }
        }
        None => {
            if let Some(cw) = held_chainwork {
                o.insert("chainwork".into(), json!(cw));
            }
        }
    }
}

fn held_chainwork_hex(ctx: &RpcContext, block: &Block) -> String {
    let prev = block.header.prev_blockhash.to_byte_array();
    if let Ok(Some(h)) = ctx.query.height_of_hash(&prev) {
        if let Some(hub) = ctx.chain.as_ref() {
            if let Ok(w) = hub.work_through_height(h.0) {
                return hex_encode((w + block.header.work()).to_be_bytes());
            }
        }
    }
    hex_encode(block.header.work().to_be_bytes())
}

fn insert_block_size_fields(obj: &mut Value, block: &Block) {
    insert_size_weight(obj, block.total_size() as u64, block.weight().to_wu());
}

/// Core `size` / `strippedsize` / `weight` (strippedsize = (weight - size) / 3).
fn insert_size_weight(obj: &mut Value, size: u64, weight: u64) {
    let Some(o) = obj.as_object_mut() else {
        return;
    };
    o.insert("size".into(), json!(size));
    o.insert("weight".into(), json!(weight));
    o.insert(
        "strippedsize".into(),
        json!(weight.saturating_sub(size) / 3),
    );
}

fn getblock_v2_tx_json(ctx: &RpcContext, block: &Block) -> Vec<Value> {
    let net = rpc_btc_network(ctx.network);
    block
        .txdata
        .iter()
        .map(|tx| {
            let extra = if tx.is_coinbase() {
                None
            } else {
                match tx_fee_sat_from_prevouts(ctx, tx) {
                    TxFeeLook::Fee(fee) => Some(json!({ "fee": sat_btc_json(fee as i64) })),
                    TxFeeLook::MissingPrevout | TxFeeLook::Overflow => None,
                }
            };
            tx_to_json(tx, extra, net)
        })
        .collect()
}

pub(crate) fn getblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "verbosity", "verbose"])?;
    let hash_hex = params.req_str(0, "blockhash")?;
    let verbosity = match params.get(1, "verbosity") {
        Some(_) => opt_verbosity(params, 1, "verbosity")?,
        None => opt_verbosity(params, 1, "verbose")?,
    };
    let hash = parse_hash32_display(hash_hex)?;
    let height = match ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        Some(h) => h,
        None => return getblock_unknown_hash(ctx, hash, verbosity),
    };
    let prev = if height.0 > 0 {
        ctx.query
            .header_at_height(Height(height.0 - 1))
            .ok()
            .flatten()
            .map(|(_, r)| hash_hex_display(&r.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };
    if verbosity == 1 {
        let (header_fk, rec) = ctx
            .query
            .header_at_height(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_MISC, "header missing"))?;
        let ids = ctx
            .query
            .block_txids(height)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
        let txids: Vec<String> = ids.iter().map(hash_hex_display).collect();
        let mut obj = json!({
            "hash": hash_hex_display(&hash),
            "confirmations": confirmations(ctx, height),
            "height": height.0,
            "version": rec.version,
            "merkleroot": hash_hex_display(&rec.merkle_root),
            "time": rec.timestamp,
            "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
                .unwrap_or(rec.timestamp),
            "nonce": rec.nonce,
            "bits": format!("{:08x}", rec.bits),
            "nTx": txids.len(),
            "tx": txids,
        });
        insert_previousblockhash(&mut obj, &prev);
        enrich_block_header_json(&mut obj, ctx, rec.version, rec.bits, Some(height), None);
        // Core verbosity 1 carries size/strippedsize/weight (mempool's block
        // indexer stores them NOT NULL). txstat answers without a reconstruct;
        // if the body is gone the fields are left out rather than failing.
        if let Ok(Some((size, weight))) = ctx.query.block_size_weight(header_fk) {
            insert_size_weight(&mut obj, u64::from(size), u64::from(weight));
        }
        return Ok(obj);
    }
    let block = ctx
        .query
        .reconstruct_block_at_height(height)
        .map_err(|e| map_query(e, "Block not available (pruned data)"))?;
    if verbosity == 0 {
        let mut raw = Vec::new();
        block
            .consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
        .collect();
    let mut obj = json!({
        "hash": hash_hex_display(&hash),
        "confirmations": confirmations(ctx, height),
        "height": height.0,
        "version": block.header.version.to_consensus(),
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": rbitcoin_consensus::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(block.header.time),
        "nonce": block.header.nonce,
        "bits": format!("{:08x}", block.header.bits.to_consensus()),
        "nTx": block.txdata.len(),
        "tx": txids,
    });
    insert_previousblockhash(&mut obj, &prev);
    enrich_block_header_json(
        &mut obj,
        ctx,
        block.header.version.to_consensus(),
        block.header.bits.to_consensus(),
        Some(height),
        None,
    );
    if verbosity >= 2 {
        insert_block_size_fields(&mut obj, &block);
        obj["tx"] = json!(getblock_v2_tx_json(ctx, &block));
    }
    Ok(obj)
}

fn disconnected_block_value(
    ctx: &RpcContext,
    hash: &[u8; 32],
    block: &Block,
    verbosity: u32,
) -> Result<Value, Value> {
    if verbosity == 0 {
        let mut raw = Vec::new();
        block
            .consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
        return Ok(json!(hex_encode(raw)));
    }
    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
        .collect();
    let bits = block.header.bits.to_consensus();
    let version = block.header.version.to_consensus();
    let prev = block.header.prev_blockhash.to_byte_array();
    let loc = off_chain_header(ctx, hash)?;
    let chainwork = loc
        .as_ref()
        .map(|l| l.chainwork.clone())
        .unwrap_or_else(|| held_chainwork_hex(ctx, block));
    let mediantime = match &loc {
        Some(loc) => loc.mediantime,
        None => median_time_from_wire(ctx, block.header.time, prev)?,
    };
    let mut obj = json!({
        "hash": hash_hex_display(hash),
        "confirmations": -1,
        "version": version,
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": mediantime,
        "nonce": block.header.nonce,
        "bits": format!("{:08x}", bits),
        "nTx": block.txdata.len(),
        "tx": txids,
    });
    if let Some(loc) = loc {
        obj["height"] = json!(loc.height);
    }
    if prev != [0u8; 32] {
        insert_previousblockhash(&mut obj, &hash_hex_display(&prev));
    }
    enrich_block_header_json(&mut obj, ctx, version, bits, None, Some(chainwork));
    if verbosity >= 2 {
        insert_block_size_fields(&mut obj, block);
        obj["tx"] = json!(getblock_v2_tx_json(ctx, block));
    }
    Ok(obj)
}

fn getblock_unknown_hash(ctx: &RpcContext, hash: [u8; 32], verbosity: u32) -> Result<Value, Value> {
    if let Ok(Some(block)) = ctx.query.reconstruct_archived_block(&hash) {
        return disconnected_block_value(ctx, &hash, &block, verbosity);
    }
    let typed = BlockHash::from_byte_array(hash);
    if let Some(block) = ctx.chain.as_ref().and_then(|c| c.held_body(&typed)) {
        return disconnected_block_value(ctx, &hash, &block, verbosity);
    }
    let header_only = ctx.chain.as_ref().is_some_and(|c| c.knows_header(&typed))
        || ctx.query.get_header_by_hash(&hash).ok().flatten().is_some();
    if header_only {
        return Err(rpc_error(
            ERR_MISC,
            "Block not available (not fully downloaded)",
        ));
    }
    Err(rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))
}

pub(crate) fn confirmations(ctx: &RpcContext, height: Height) -> u32 {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    tip.saturating_sub(height.0).saturating_add(1)
}

/// Descriptor scan over the scripthash index. `txouts` is always `-1`.
pub(crate) fn scantxoutset(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["action", "scanobjects"])?;
    let Some(action_v) = params.get(0, "action") else {
        return Err(rpc_error(
            ERR_MISC,
            "scantxoutset \"action\" ( [scanobjects,...] )",
        ));
    };
    let action = action_v
        .as_str()
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMS, "action must be a string"))?;
    match action {
        "status" => return Ok(Value::Null),
        "abort" => return Ok(json!(false)),
        "start" => {}
        other => {
            return Err(rpc_error(
                ERR_INVALID_PARAMETER,
                format!("Invalid action '{other}'"),
            ));
        }
    }
    let objs = params.get_array(1, "scanobjects").ok_or_else(|| {
        rpc_error(
            ERR_MISC,
            "scanobjects argument is required for the start action",
        )
    })?;
    if !ctx.query.sh_index_enabled() {
        return Err(rpc_error(ERR_MISC, "scripthash index disabled"));
    }
    let expanded = super::descriptor_scan::expand_scan_objects(ctx, objs)?;
    let scripts: Vec<Vec<u8>> = expanded.iter().map(|s| s.script.clone()).collect();
    let desc_for_script: Vec<(Vec<u8>, String)> =
        expanded.into_iter().map(|s| (s.script, s.desc)).collect();

    let tip = ctx.query.tip_height().unwrap_or(Height(0));
    let best = if let Some(h) = ctx.query.tip_height() {
        ctx.query
            .header_at_height(h)
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let found = ctx
        .query
        .scan_unspent_scripts(&scripts)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let genesis_txid = genesis_coinbase_txid(ctx);
    let mut unspents = Vec::with_capacity(found.len());
    let mut total_sat = 0u64;
    for u in found.into_iter().filter(|u| u.txid != genesis_txid) {
        total_sat = total_sat.saturating_add(u.value);
        let blockhash = ctx
            .query
            .header_at_height(Height(u.height))
            .ok()
            .flatten()
            .map(|(_, rec)| hash_hex_display(&rec.hash))
            .unwrap_or_default();
        unspents.push(json!({
            "txid": hash_hex_display(&u.txid),
            "vout": u.vout,
            "scriptPubKey": hex_encode(&u.script),
            "desc": desc_for_script
                .iter()
                .find(|(spk, _)| spk == &u.script)
                .map(|(_, d)| d.clone())
                .unwrap_or_else(|| format!("raw({})", hex_encode(&u.script))),
            "amount": sat_btc_json(u.value as i64),
            "coinbase": u.coinbase,
            "height": u.height,
            "blockhash": blockhash,
            "confirmations": confirmations(ctx, Height(u.height)),
        }));
    }

    Ok(json!({
        "success": true,
        "txouts": -1,
        "height": tip.0,
        "bestblock": best,
        "unspents": unspents,
        "total_amount": sat_btc_json(total_sat as i64),
    }))
}

pub(crate) fn getblockfilter(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "filtertype"])?;
    let hex = params.req_str(0, "blockhash")?;
    let filtertype = params.opt_str(1, "filtertype")?.unwrap_or("basic");
    if filtertype != "basic" {
        return Err(rpc_error(
            ERR_INVALID_PARAMETER,
            format!("Unknown filtertype {filtertype}"),
        ));
    }
    if !ctx.query.block_filter_enabled() {
        return Err(rpc_error(
            ERR_MISC,
            "Index is not enabled for filtertype basic",
        ));
    }
    let hash = parse_hash32_display(hex)?;
    let height = ctx
        .query
        .height_of_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    let (body, header) = ctx
        .query
        .basic_filter_at(height.0)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| {
            rpc_error(
                ERR_MISC,
                "Filter not found. Block filters are still in the process of being indexed.",
            )
        })?;
    use bitcoin::hashes::Hash;
    Ok(json!({
        "filter": hex_encode(&body),
        "header": hex_encode(header.as_byte_array()),
    }))
}

pub(crate) fn gettxout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["txid", "n", "include_mempool"])?;
    let hex = params.req_str(0, "txid")?;
    let n = params.req_u64(1, "n")? as u32;
    let include_mempool = params.opt_bool(2, "include_mempool")?.unwrap_or(true);
    let want = parse_hash32_display(hex)?;
    if want == genesis_coinbase_txid(ctx) {
        return Ok(Value::Null);
    }
    let connected = ctx
        .query
        .tx_fk_by_txid_tip(&want)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;

    if include_mempool && connected.is_none() {
        if let Some(mp) = ctx.mempool.as_ref() {
            let tid = Txid::from_byte_array(want);
            if let Some(tx) = mp.get_tx(&tid) {
                if let Some(out) = tx.output.get(n as usize) {
                    return Ok(json!({
                        "bestblock": getbestblockhash(ctx)?,
                        "confirmations": 0,
                        "value": out.value.to_btc(),
                        "scriptPubKey": {
                            "hex": hex_encode(out.script_pubkey.as_bytes()),
                            "asm": out.script_pubkey.to_asm_string(),
                        },
                        "coinbase": false,
                    }));
                }
            }
        }
    }

    let Some(fk) = connected else {
        return Ok(Value::Null);
    };
    let rec = ctx
        .query
        .get_tx(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    if ctx
        .query
        .is_outpoint_spent(&want, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
    {
        return Ok(Value::Null);
    }
    if include_mempool {
        if let Some(mp) = ctx.mempool.as_ref() {
            let op = bitcoin::OutPoint {
                txid: Txid::from_byte_array(want),
                vout: n,
            };
            if mp.spends_outpoint(&op) {
                return Ok(Value::Null);
            }
        }
    }
    let out = ctx
        .query
        .tx_output_at_fk(fk, n)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    let height = ctx
        .query
        .store()
        .tx_height_get(fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .unwrap_or(0);
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let confs = tip.saturating_sub(height).saturating_add(1);
    let coinbase = rec.input_count == 1
        && ctx
            .query
            .tx_input_at_fk(fk, &rec, 0)
            .map(|inp| inp.is_coinbase())
            .unwrap_or(false);
    Ok(json!({
        "bestblock": getbestblockhash(ctx)?,
        "confirmations": confs,
        "value": Amount::from_sat(out.value as u64).to_btc(),
        "scriptPubKey": {
            "hex": hex_encode(&out.script),
            "asm": ScriptBuf::from_bytes(out.script.clone()).to_asm_string(),
        },
        "coinbase": coinbase,
    }))
}

pub(crate) fn getindexinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["index_name"])?;
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    let txindex = json!({
        "synced": true,
        "best_block_height": tip,
    });
    match params.get(0, "index_name") {
        None | Some(Value::Null) => Ok(json!({ "txindex": txindex })),
        Some(Value::String(s)) if s == "txindex" => Ok(json!({ "txindex": txindex })),
        Some(Value::String(_)) => Ok(json!({})),
        Some(_) => Err(rpc_error(ERR_INVALID_PARAMS, "index_name must be a string")),
    }
}

pub(crate) fn getchaintips(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&[])?;
    if let Some(chain) = ctx.chain.as_ref() {
        let tips: Vec<Value> = chain
            .chaintips()
            .into_iter()
            .map(|t| {
                json!({
                    "height": t.height,
                    "hash": hash_hex_display(&t.hash.to_byte_array()),
                    "branchlen": t.branchlen,
                    "status": t.status,
                })
            })
            .collect();
        return Ok(json!(tips));
    }
    let Some(h) = ctx.query.tip_height() else {
        return Ok(json!([]));
    };
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok(json!([{
        "height": h.0,
        "hash": hash_hex_display(&rec.hash),
        "branchlen": 0,
        "status": "active",
    }]))
}

pub(crate) fn wait_timeout_ms(params: &RpcParams, idx: usize, name: &str) -> Result<u64, Value> {
    let ms = params.opt_u64(idx, name)?.unwrap_or(30_000);
    Ok(ms.min(super::RPC_WAIT_TIMEOUT_MS))
}

pub(crate) fn tip_hash_height(ctx: &RpcContext) -> Result<(String, u32), Value> {
    let h = ctx
        .query
        .tip_height()
        .ok_or_else(|| rpc_error(ERR_MISC, "no tip"))?;
    let (_, rec) = ctx
        .query
        .header_at_height(h)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_MISC, "tip header missing"))?;
    Ok((hash_hex_display(&rec.hash), h.0))
}

pub(crate) fn buried_row(height: u32, at: u32) -> Value {
    // Core `DeploymentActiveAfter`: active for the *next* block after `at`.
    json!({
        "type": "buried",
        "height": height,
        "active": at.saturating_add(1) >= height,
    })
}

/// Buried deployments from the node's `ChainParams` (overlay heights included).
/// No BIP9 / testdummy / versionbits invention.
/// Buried deployments from the node's `ChainParams` (overlay heights included).
/// No BIP9 / testdummy / versionbits invention.
pub(crate) fn buried_deployments(params: &rbitcoin_consensus::ChainParams, at: u32) -> Value {
    json!({
        "bip34": buried_row(params.btc.bip34_height, at),
        "bip66": buried_row(params.btc.bip66_height, at),
        "bip65": buried_row(params.btc.bip65_height, at),
        "csv": buried_row(params.csv_height(), at),
        "segwit": buried_row(params.segwit_height(), at),
        "taproot": buried_row(params.taproot_height(), at),
    })
}

pub(crate) fn getdeploymentinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let cp = ctx
        .chain
        .as_ref()
        .map(|c| c.params.clone())
        .unwrap_or_else(|| rbitcoin_consensus::ChainParams::for_network(ctx.network));
    let (hash, height) = if let Some(hex) = params.get(0, "blockhash").and_then(Value::as_str) {
        let want = parse_hash32_display(hex)?;
        let h = ctx
            .query
            .height_of_hash(&want)
            .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
            .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
        (hash_hex_display(&want), h.0)
    } else {
        tip_hash_height(ctx)?
    };
    Ok(json!({
        "hash": hash,
        "height": height,
        "deployments": buried_deployments(&cp, height),
    }))
}

pub(crate) fn waitforblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "timeout"])?;
    let want = params.req_str(0, "blockhash")?.to_string();
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash == want)
}

pub(crate) fn waitforblockheight(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height", "timeout"])?;
    let want = params.req_u64(0, "height")? as u32;
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |_hash, height| height >= want)
}

pub(crate) fn waitfornewblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timeout"])?;
    let timeout_ms = wait_timeout_ms(params, 0, "timeout")?;
    let (start_hash, _) = tip_hash_height(ctx)?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash != start_hash)
}

/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
pub(crate) fn wait_for_tip(
    ctx: &RpcContext,
    timeout_ms: u64,
    pred: impl Fn(&str, u32) -> bool,
) -> Result<Value, Value> {
    if super::http_wait_satisfied() {
        let (hash, height) = tip_hash_height(ctx)?;
        return Ok(json!({ "hash": hash, "height": height }));
    }
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            let (hash, height) = tip_hash_height(ctx)?;
            return Ok(json!({ "hash": hash, "height": height }));
        }
        let (hash, height) = tip_hash_height(ctx)?;
        if pred(&hash, height) {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({ "hash": hash, "height": height }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub(crate) fn require_chain(ctx: &RpcContext) -> Result<&rbitcoin_net::ChainHub, Value> {
    ctx.chain
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "chain hub not attached"))
}

pub(crate) fn parse_blockhash_param(params: &RpcParams) -> Result<bitcoin::BlockHash, Value> {
    let hex = params.req_str(0, "blockhash")?;
    let b = parse_hash32_display(hex)?;
    Ok(bitcoin::BlockHash::from_byte_array(b))
}

pub(crate) fn invalidateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.invalidate_block(hash).map_err(|e| {
        let s = e.to_string();
        if s.contains("Block not found") {
            rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found")
        } else {
            rpc_error(ERR_MISC, s)
        }
    })?;
    Ok(Value::Null)
}

pub(crate) fn submitheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata"])?;
    let hub = require_chain(ctx)?;
    let hex = params.req_str(0, "hexdata")?;
    let header = decode_header_hex(hex)?;
    hub.process_submitted_header(&header)
        .map_err(|e| rpc_error(ERR_VERIFY_ERROR, e))?;
    Ok(Value::Null)
}

pub(crate) fn decode_header_hex(hex: &str) -> Result<bitcoin::block::Header, Value> {
    let raw = hex_decode(hex)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))?;
    if raw.len() >= 80 {
        if let Ok(h) = deserialize::<bitcoin::block::Header>(&raw[..80]) {
            return Ok(h);
        }
    }
    deserialize::<Block>(&raw)
        .map(|b| b.header)
        .map_err(|_| rpc_error(ERR_DESERIALIZATION, "Block header decode failed"))
}

pub(crate) fn reconsiderblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.reconsider_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}

pub(crate) fn preciousblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.precious_block(hash).map_err(|e| {
        let s = e.to_string();
        if s.contains("Block not found") {
            rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found")
        } else {
            rpc_error(ERR_MISC, s)
        }
    })?;
    Ok(Value::Null)
}

#[cfg(test)]
mod core_double_tests {
    use super::format_core_double;

    #[test]
    fn sixteen_significant_digits() {
        assert_eq!(format_core_double(1.0), "1");
        assert_eq!(format_core_double(0.0), "0");
        assert_eq!(format_core_double(132757073449487.52), "132757073449487.5");
    }
}

#[cfg(test)]
mod wait_tests {
    use super::*;

    #[test]
    fn wait_timeout_ms_caps_at_two_minutes() {
        let huge = RpcParams::positional(vec![json!(500_000)]);
        assert_eq!(wait_timeout_ms(&huge, 0, "timeout").unwrap(), 120_000);
        let absent = RpcParams::positional(vec![]);
        assert_eq!(wait_timeout_ms(&absent, 0, "timeout").unwrap(), 30_000);
        let short = RpcParams::positional(vec![json!(50)]);
        assert_eq!(wait_timeout_ms(&short, 0, "timeout").unwrap(), 50);
    }
}
