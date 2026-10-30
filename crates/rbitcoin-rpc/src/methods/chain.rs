use super::*;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Txid};
use rbitcoin_primitives::{median_time_past_times, Fk, Height, MedianWindow};

use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Instant;

#[doc(hidden)]
pub fn wait_chain_tip(ctx: &RpcContext) {
    if let Some(c) = ctx.chain.as_ref() {
        c.wait_tip_stable_for_rpc();
    }
}

pub fn getblockcount(ctx: &RpcContext) -> Result<Value, Value> {
    wait_chain_tip(ctx);
    let h = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    Ok(json!(h))
}

pub fn getbestblockhash(ctx: &RpcContext) -> Result<Value, Value> {
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

pub fn getblockhash(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height"])?;
    let height = params.req_u64(0, "height")? as u32;
    let (_, rec) = ctx
        .query
        .header_at_height(Height(height))
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_PARAMETER, "Block height out of range"))?;
    Ok(json!(hash_hex_display(&rec.hash)))
}

/// Live hub latch, not the tip-follow copy: `feature_maxtipage` asserts
/// immediately after `sync_all`, before the 50ms RPC tick may store.
pub(crate) fn in_ibd(ctx: &RpcContext) -> bool {
    ctx.chain
        .as_ref()
        .map(|c| c.in_ibd())
        .unwrap_or_else(|| ctx.initial_block_download.load(Ordering::Relaxed))
}

pub fn getblockchaininfo(ctx: &RpcContext) -> Result<Value, Value> {
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
    let ibd = in_ibd(ctx);
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
            let mtp =
                rbitcoin_query::median_time_past(ctx.query.as_ref(), h).unwrap_or(rec.timestamp);
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
    if let Some(challenge) = signet_challenge_hex(ctx) {
        info["signet_challenge"] = json!(challenge);
    }
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

/// Bitcoin Core includes `signet_challenge` only on signet.
pub fn signet_challenge_hex(ctx: &RpcContext) -> Option<String> {
    if ctx.network != Network::Signet {
        return None;
    }
    let script = ctx
        .chain
        .as_ref()
        .and_then(|c| c.params.signet_challenge.clone())
        .unwrap_or_else(rbitcoin_consensus::default_signet_challenge);
    Some(rbitcoin_primitives::hex_encode(script.as_bytes()))
}

pub fn rpc_warnings(ctx: &RpcContext) -> Vec<String> {
    let who = ctx.peers.as_ref().and_then(|p| p.trust_peer_label());
    let mut w = rbitcoin_net::versionbit_warning_strings(ctx.query.as_ref(), ctx.network);
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
    if let Some(line) = rbitcoin_net::trust_warning_line(ctx.query.as_ref(), who.as_deref()) {
        w.push(line);
    }
    w
}

/// Difficulty relative to the max target.
///
/// Matches Core `GetDifficulty` when every mantissa bit lands inside the
/// 256-bit target. The mantissa is at most `0x7fffff`. Size `3..=32`
/// qualifies. Size `33` qualifies at a mantissa of at most `0xffff`, and
/// size `34` at most `0xff`. A smaller size qualifies when the shifted-off
/// low bits are clear. Network pow limits are in that set, so a header
/// that meets the limit matches too.
///
/// A zero target makes this function `+inf` and the old loop a finite
/// ratio. That is the sign bit, size `0`, and a size of `1` or `2` that
/// shifts every remaining bit off (`0x0100ffff` was `2^224`). A partial
/// drop stays finite and larger than the old loop: `0x0200ffff` leaves
/// target `255`, at `257/256` of the old `2^216`. Size `33` or `34` past
/// the limits above drops high bits. Size `35` or more masks the shift
/// with `0xff`. Size `35` is a shift of `0`, so the mantissa stays and
/// the difficulty is huge where the old loop is small.
///
/// `format_core_double` prints a non-finite result as `0`. Block and chain
/// RPCs use that. `getmininginfo` puts this float straight into JSON, which
/// is `null` when it is non-finite. A connected tip cannot have a zero
/// target.
pub fn difficulty_from_bits(bits: u32) -> f64 {
    bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits)).difficulty_float()
}

/// Compact-target bytes as Core `target` (64 hex chars).
pub fn target_hex(bits: u32) -> String {
    let target = bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(bits));
    format!("{target:064x}")
}

/// Core `UniValue` `setprecision(16)` defaultfloat. Keeps the 16th significant
/// digit (`132757073449487.52` prints `132757073449487.5`).
pub fn format_core_double(v: f64) -> String {
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

pub fn core_f64_json(v: f64) -> Value {
    let s = format_core_double(v);
    Value::Number(s.parse().expect("core double decimal"))
}

/// `getblockchaininfo.difficulty`: [`difficulty_from_bits`] at 16 significant digits.
pub fn difficulty_rpc_f64(bits: u32) -> f64 {
    core_f64_json(difficulty_from_bits(bits))
        .as_f64()
        .expect("core difficulty decimal")
}

pub fn difficulty_at_tip(ctx: &RpcContext) -> Result<f64, Value> {
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

pub fn getdifficulty(ctx: &RpcContext) -> Result<Value, Value> {
    Ok(core_f64_json(difficulty_at_tip(ctx)?))
}

pub fn getblockheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

/// Where `height` is inserted. Held puts it after `target`. Active and
/// off-chain put it after `confirmations`. `serde_json::Map` sorts keys, so
/// both slots serialize the same way until `preserve_order` is on.
enum HeaderHeightSlot {
    AfterConfirmations,
    AfterTarget,
}

struct VerboseHeader<'a> {
    hash: &'a str,
    confirmations: Value,
    height: Option<u32>,
    height_slot: HeaderHeightSlot,
    version: i32,
    merkle_root: &'a str,
    time: u32,
    mediantime: u32,
    nonce: u32,
    bits: u32,
    chainwork: &'a str,
    n_tx: usize,
    previousblockhash: Option<&'a str>,
    nextblockhash: Option<&'a str>,
}

fn insert_header_height(obj: &mut Value, height: Option<u32>) {
    if let Some(h) = height {
        obj["height"] = json!(h);
    }
}

/// Verbose `getblockheader` object. Callers still choose confirmations,
/// height, `nTx`, chainwork, median time, and whether `nextblockhash` is set.
fn verbose_header_object(f: VerboseHeader<'_>) -> Value {
    let mut obj = json!({
        "hash": f.hash,
        "confirmations": f.confirmations,
    });
    if matches!(f.height_slot, HeaderHeightSlot::AfterConfirmations) {
        insert_header_height(&mut obj, f.height);
    }
    obj["version"] = json!(f.version);
    obj["versionHex"] = json!(format!("{:08x}", f.version));
    obj["merkleroot"] = json!(f.merkle_root);
    obj["time"] = json!(f.time);
    obj["mediantime"] = json!(f.mediantime);
    obj["nonce"] = json!(f.nonce);
    obj["bits"] = json!(format!("{:08x}", f.bits));
    obj["difficulty"] = core_f64_json(difficulty_from_bits(f.bits));
    obj["chainwork"] = json!(f.chainwork);
    obj["nTx"] = json!(f.n_tx);
    obj["target"] = json!(target_hex(f.bits));
    if matches!(f.height_slot, HeaderHeightSlot::AfterTarget) {
        insert_header_height(&mut obj, f.height);
    }
    if let Some(prev) = f.previousblockhash {
        insert_previousblockhash(&mut obj, prev);
    }
    if let Some(next) = f.nextblockhash {
        obj["nextblockhash"] = json!(next);
    }
    obj
}

#[doc(hidden)]
pub fn active_block_header(
    ctx: &RpcContext,
    height: Height,
    verbose: bool,
) -> Result<Value, Value> {
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
    let hash = hash_hex_display(&rec.hash);
    let merkle = hash_hex_display(&rec.merkle_root);
    let chainwork = chainwork_hex(ctx, Some(height));
    let next = nextblockhash_at(ctx, height);
    Ok(verbose_header_object(VerboseHeader {
        hash: &hash,
        confirmations: json!(confirmations(ctx, height)),
        height: Some(height.0),
        height_slot: HeaderHeightSlot::AfterConfirmations,
        version: rec.version,
        merkle_root: &merkle,
        time: rec.timestamp,
        mediantime: rbitcoin_query::median_time_past(ctx.query.as_ref(), height)
            .unwrap_or(rec.timestamp),
        nonce: rec.nonce,
        bits: rec.bits,
        chainwork: &chainwork,
        n_tx: ctx.query.block_tx_fks(height).map(|v| v.len()).unwrap_or(0),
        previousblockhash: Some(&prev),
        nextblockhash: next.as_deref(),
    }))
}

#[doc(hidden)]
pub fn header_hex(hdr: &bitcoin::block::Header) -> Result<String, Value> {
    let mut raw = Vec::new();
    hdr.consensus_encode(&mut raw)
        .map_err(|_| rpc_error(ERR_MISC, "header encode"))?;
    Ok(rbitcoin_primitives::hex_encode(&(raw)))
}

#[doc(hidden)]
pub fn insert_previousblockhash(obj: &mut Value, prev: &str) {
    if prev.is_empty() {
        return;
    }
    if let Some(o) = obj.as_object_mut() {
        o.insert("previousblockhash".into(), json!(prev));
    }
}

#[doc(hidden)]
pub struct OffChainHeader {
    pub rec: rbitcoin_store::HeaderRecord,
    pub header_fk: rbitcoin_primitives::Fk,
    pub height: u32,
    pub prev_hash: Option<[u8; 32]>,
    pub chainwork: String,
    /// Median of this header and up to 10 ancestors (Core `GetMedianTimePast`).
    pub mediantime: u32,
}

/// Header-sync ancestry cap (`stored_header_height`). One `prev_fk` read per
/// step; active membership is the height index. A longer stale branch errors
/// instead of scanning the rest of the branch.
#[doc(hidden)]
pub const OFF_CHAIN_WALK_MAX: u32 = 10_000;

/// Header that is stored but not on the active chain. Height and chainwork
/// walk `prev_fk` until an active ancestor (or genesis).
#[doc(hidden)]
pub fn off_chain_header(
    ctx: &RpcContext,
    hash: &[u8; 32],
) -> Result<Option<OffChainHeader>, Value> {
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
                rbitcoin_primitives::hex_encode(sum_header_work(works).to_be_bytes()),
                &times,
            )?));
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
                rbitcoin_primitives::hex_encode(cw.to_be_bytes()),
                &times,
            )?));
        }
        cur = parent;
    }
    Err(rpc_error(ERR_MISC, "side header walk exceeded"))
}

#[doc(hidden)]
pub fn off_chain_done(
    rec: rbitcoin_store::HeaderRecord,
    header_fk: rbitcoin_primitives::Fk,
    height: u32,
    prev_hash: Option<[u8; 32]>,
    chainwork: String,
    times: &[u32],
) -> Result<OffChainHeader, Value> {
    Ok(OffChainHeader {
        rec,
        header_fk,
        height,
        prev_hash,
        chainwork,
        mediantime: median_time_past_times(
            MedianWindow::new(times).map_err(|e| rpc_error(ERR_MISC, e))?,
        ),
    })
}

/// Ancestors strictly below an active parent, until the 11-timestamp window is full.
#[doc(hidden)]
pub fn fill_mtp_below(
    ctx: &RpcContext,
    times: &mut Vec<u32>,
    parent_height: u32,
) -> Result<(), Value> {
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
#[doc(hidden)]
pub fn median_time_from_wire(
    ctx: &RpcContext,
    time: u32,
    prev_hash: [u8; 32],
) -> Result<u32, Value> {
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
    Ok(median_time_past_times(
        MedianWindow::new(&times).map_err(|e| rpc_error(ERR_MISC, e))?,
    ))
}

#[doc(hidden)]
pub fn work_from_bits(bits: u32) -> bitcoin::Work {
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

#[doc(hidden)]
pub fn sum_header_work(works: Vec<bitcoin::Work>) -> bitcoin::Work {
    rbitcoin_net::sum_work(works.into_iter()).unwrap_or(bitcoin::Work::from_be_bytes([0xff; 32]))
}

#[doc(hidden)]
pub fn wire_header_from_record(
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

#[doc(hidden)]
pub fn off_chain_header_value(
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
    let hash = hash_hex_display(&loc.rec.hash);
    let merkle = hash_hex_display(&loc.rec.merkle_root);
    let previous = loc.prev_hash.map(|p| hash_hex_display(&p));
    Ok(verbose_header_object(VerboseHeader {
        hash: &hash,
        confirmations: json!(-1),
        height: Some(loc.height),
        height_slot: HeaderHeightSlot::AfterConfirmations,
        version: loc.rec.version,
        merkle_root: &merkle,
        time: loc.rec.timestamp,
        mediantime: loc.mediantime,
        nonce: loc.rec.nonce,
        bits: loc.rec.bits,
        chainwork: &loc.chainwork,
        n_tx,
        previousblockhash: previous.as_deref(),
        nextblockhash: None,
    }))
}

#[doc(hidden)]
pub fn held_header_value(ctx: &RpcContext, block: &Block, verbose: bool) -> Result<Value, Value> {
    if !verbose {
        return Ok(json!(header_hex(&block.header)?));
    }
    let bits = block.header.bits.to_consensus();
    let version = block.header.version.to_consensus();
    let prev = block.header.prev_blockhash.to_byte_array();
    let mediantime = median_time_from_wire(ctx, block.header.time, prev)?;
    let (height, chainwork) = held_height_and_work_hex(ctx, block);
    let hash = hash_hex_display(&block.block_hash().to_byte_array());
    let merkle = hash_hex_display(&block.header.merkle_root.to_byte_array());
    let previous = (prev != [0u8; 32]).then(|| hash_hex_display(&prev));
    Ok(verbose_header_object(VerboseHeader {
        hash: &hash,
        confirmations: json!(-1),
        height,
        height_slot: HeaderHeightSlot::AfterTarget,
        version,
        merkle_root: &merkle,
        time: block.header.time,
        mediantime,
        nonce: block.header.nonce,
        bits,
        chainwork: &chainwork,
        n_tx: block.txdata.len(),
        previousblockhash: previous.as_deref(),
        nextblockhash: None,
    }))
}

/// 32-byte BE chainwork hex (regtest = 2 per block). Empty store → 64 zeros.
pub fn chainwork_hex(ctx: &RpcContext, through: Option<Height>) -> String {
    let Some(tip) = through.or_else(|| ctx.query.tip_height()) else {
        return "00".repeat(32);
    };
    if let Some(hub) = ctx.chain.as_ref() {
        if let Ok(w) = hub.work_through_height(tip.0) {
            return rbitcoin_primitives::hex_encode(w.to_be_bytes());
        }
    }
    let mut works = Vec::new();
    for h in 0..=tip.0 {
        if let Ok(hdr) = ctx.query.wire_header_at_height(Height(h)) {
            works.push(hdr.work());
        }
    }
    rbitcoin_primitives::hex_encode(
        rbitcoin_net::sum_work(works.into_iter())
            .unwrap_or(bitcoin::Work::from_be_bytes([0xff; 32]))
            .to_be_bytes(),
    )
}

#[doc(hidden)]
pub fn version_hex(version: i32) -> String {
    format!("{:08x}", version as u32)
}

#[doc(hidden)]
pub fn nextblockhash_at(ctx: &RpcContext, height: Height) -> Option<String> {
    ctx.query
        .header_at_height(Height(height.0 + 1))
        .ok()
        .flatten()
        .map(|(_, r)| hash_hex_display(&r.hash))
}

#[doc(hidden)]
pub fn enrich_block_header_json(
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

/// Height and chain work of a held body: its parent's plus this block. The
/// parent is on the active chain, a stored header, or another held body.
#[doc(hidden)]
pub fn held_height_and_work(ctx: &RpcContext, block: &Block) -> Option<(u32, bitcoin::Work)> {
    let hub = ctx.chain.as_ref()?;
    let mut works = vec![block.header.work()];
    let mut prev = block.header.prev_blockhash;
    for depth in 1..=OFF_CHAIN_WALK_MAX {
        let p = prev.to_byte_array();
        let (height, base) = if let Ok(Some(h)) = ctx.query.height_of_hash(&p) {
            (h.0, hub.work_through_height(h.0).ok()?)
        } else if let Some(loc) = off_chain_header(ctx, &p).ok()? {
            let base: [u8; 32] = rbitcoin_primitives::hex_decode(&loc.chainwork)
                .ok()?
                .try_into()
                .ok()?;
            (loc.height, bitcoin::Work::from_be_bytes(base))
        } else {
            let parent = hub.held_body(&prev)?;
            works.push(parent.header.work());
            prev = parent.header.prev_blockhash;
            continue;
        };
        let work = rbitcoin_net::sum_work(std::iter::once(base).chain(works)).ok()?;
        return Some((height.checked_add(depth)?, work));
    }
    None
}

/// [`held_height_and_work`] for JSON. Without a known ancestry, only this
/// block's work and no height.
fn held_height_and_work_hex(ctx: &RpcContext, block: &Block) -> (Option<u32>, String) {
    let (height, work) = match held_height_and_work(ctx, block) {
        Some((h, w)) => (Some(h), w),
        None => (None, block.header.work()),
    };
    (height, rbitcoin_primitives::hex_encode(work.to_be_bytes()))
}

#[doc(hidden)]
pub fn insert_block_size_fields(obj: &mut Value, block: &Block) {
    insert_size_weight(obj, block.total_size() as u64, block.weight().to_wu());
}

/// Core `size` / `strippedsize` / `weight` (strippedsize = (weight - size) / 3).
#[doc(hidden)]
pub fn insert_size_weight(obj: &mut Value, size: u64, weight: u64) {
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

/// Core `coinbase_tx` (verbosity >= 1): the coinbase's version and locktime,
/// and its one input's sequence, script, and first witness item.
#[doc(hidden)]
pub fn coinbase_tx_json(cb: &Transaction) -> Value {
    let Some(vin) = cb.input.first() else {
        return Value::Null;
    };
    let mut obj = json!({
        // Core prints the version as uint32_t.
        "version": cb.version.0 as u32,
        "locktime": cb.lock_time.to_consensus_u32(),
        "sequence": vin.sequence.0,
        "coinbase": rbitcoin_primitives::hex_encode(vin.script_sig.as_bytes()),
    });
    if let Some(w) = vin.witness.iter().next() {
        obj["witness"] = json!(rbitcoin_primitives::hex_encode(w));
    }
    obj
}

/// Header fk and Class A tx fks of the stored body for `hash`, active or
/// disconnected. Their prevout edges are Core's undo data. A held body has
/// none.
fn stored_block_fks(ctx: &RpcContext, hash: &[u8; 32]) -> Option<BlockUndo> {
    let (header_fk, rec) = ctx.query.get_header_by_hash(hash).ok().flatten()?;
    if rec.hash != *hash {
        return None;
    }
    let fks = ctx
        .query
        .header_tx_fks(header_fk, Some(hash))
        .ok()
        .flatten()?;
    Some(BlockUndo { header_fk, fks })
}

/// A stored body's header fk and its tx fks, in block order.
#[doc(hidden)]
pub struct BlockUndo {
    pub header_fk: Fk,
    pub fks: Vec<Fk>,
}

/// Verbosity >= 2 `tx` rows. With undo (`fks`), a non-coinbase carries `fee`,
/// and at verbosity >= 3 each input carries `prevout`. Undo that is present
/// but unreadable is an error, as Core.
#[doc(hidden)]
pub fn getblock_tx_json(
    ctx: &RpcContext,
    block: &Block,
    undo: Option<&BlockUndo>,
    verbosity: u32,
) -> Result<Vec<Value>, Value> {
    let net = rpc_btc_network(ctx.network);
    let undo = undo.filter(|u| u.fks.len() == block.txdata.len());
    block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let read = if verbosity >= 3 {
                UndoRead::Prevouts
            } else {
                UndoRead::Fee
            };
            let row = match undo {
                Some(u) => raw_tx_prevouts(ctx, tx, u.fks[i], Some(u.header_fk), read)?,
                None => None,
            };
            let Some((fee, prevouts)) = row else {
                return Ok(tx_to_json(tx, None, net));
            };
            let mut obj = tx_to_json(tx, Some(json!({ "fee": sat_btc_json(fee) })), net);
            if verbosity >= 3 {
                insert_vin_prevouts(&mut obj, &prevouts);
            }
            Ok(obj)
        })
        .collect()
}

pub fn getblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
    // Every read below goes through this hash's own header fk, so a reorg
    // after the height lookup cannot mix this block with another. The block
    // is reported as active only while `confirmed[height]` still holds it.
    let (header_fk, rec) = ctx
        .query
        .get_header_by_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .filter(|(_, r)| r.hash == hash)
        .ok_or_else(|| rpc_error(ERR_MISC, "header missing"))?;
    let at = ActiveAt {
        hash,
        height,
        header_fk,
    };
    if verbosity == 1 {
        return getblock_v1(ctx, &at, rec);
    }
    getblock_body(ctx, &at, rec, verbosity)
}

#[cfg(debug_assertions)]
type GetblockHook = Box<dyn FnOnce(&RpcContext)>;

#[cfg(debug_assertions)]
thread_local! {
    static BEFORE_GETBLOCK_FINISH: std::cell::RefCell<Option<GetblockHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` once in the next `getblock` on this thread, after the body and
/// before the reads `ActiveAt::finish` makes last.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn before_next_getblock_finish(f: impl FnOnce(&RpcContext) + 'static) {
    BEFORE_GETBLOCK_FINISH.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// A block `height_of_hash` placed on the active chain, and its header fk.
/// The fields read by height are this block's only if `confirmed[height]`
/// still holds it after they are read: a disconnect clears that slot before
/// it pops the fence, and a lower slot is cleared only after this one.
struct ActiveAt {
    hash: [u8; 32],
    height: Height,
    header_fk: Fk,
}

impl ActiveAt {
    /// The reads made after every other field. `confirmations`,
    /// `nextblockhash`, and membership come from one sample of the tip, this
    /// slot, and the one above it. `false` when `confirmed[height]` no longer
    /// holds this block or the next block is not its child, as Core checks.
    /// A read that fails is Core's `-32603`, not a disconnected block.
    fn finish(&self, ctx: &RpcContext, obj: &mut Value) -> Result<bool, Value> {
        #[cfg(debug_assertions)]
        if let Some(f) = BEFORE_GETBLOCK_FINISH.with(|h| h.borrow_mut().take()) {
            f(ctx);
        }
        let slots = ctx
            .query
            .slots_around(self.height)
            .map_err(|e| rpc_error(ERR_INTERNAL, e.to_string()))?;
        let child = slots
            .next
            .as_ref()
            .is_none_or(|next| next.prev_fk == self.header_fk);
        if slots.at != Some(self.header_fk) || !child {
            return Ok(false);
        }
        let Some(o) = obj.as_object_mut() else {
            return Ok(true);
        };
        let tip = slots.tip.map_or(0, |h| h.0);
        o.insert(
            "confirmations".into(),
            json!(tip.saturating_sub(self.height.0).saturating_add(1)),
        );
        match slots.next {
            Some(next) => o.insert("nextblockhash".into(), json!(hash_hex_display(&next.hash))),
            None => o.remove("nextblockhash"),
        };
        Ok(true)
    }
}

/// `previousblockhash` from the header's own `prev_fk`, not the live height.
fn prev_hash_of(ctx: &RpcContext, rec: &rbitcoin_store::HeaderRecord) -> Result<String, Value> {
    if rec.prev_fk.is_null() {
        return Ok(String::new());
    }
    let prev = ctx
        .query
        .get_header(rec.prev_fk)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(hash_hex_display(&prev.hash))
}

/// Verbosity 1: txids without a body reconstruct, so it still answers below
/// `pruneheight`; that body has no coinbase to show.
fn getblock_v1(
    ctx: &RpcContext,
    at: &ActiveAt,
    rec: rbitcoin_store::HeaderRecord,
) -> Result<Value, Value> {
    let misc = |e: rbitcoin_query::QueryError| rpc_error(ERR_MISC, e.to_string());
    let ids = ctx.query.header_txids(at.header_fk).map_err(misc)?;
    let txids: Vec<String> = ids.iter().map(hash_hex_display).collect();
    let mut obj = json!({
        "hash": hash_hex_display(&at.hash),
        "confirmations": confirmations(ctx, at.height),
        "height": at.height.0,
        "version": rec.version,
        "merkleroot": hash_hex_display(&rec.merkle_root),
        "time": rec.timestamp,
        "mediantime": rbitcoin_query::median_time_past(ctx.query.as_ref(), at.height)
            .unwrap_or(rec.timestamp),
        "nonce": rec.nonce,
        "bits": format!("{:08x}", rec.bits),
        "nTx": txids.len(),
        "tx": txids,
    });
    insert_previousblockhash(&mut obj, &prev_hash_of(ctx, &rec)?);
    enrich_block_header_json(&mut obj, ctx, rec.version, rec.bits, Some(at.height), None);
    // Core verbosity 1 carries size/strippedsize/weight (mempool's block
    // indexer stores them NOT NULL). txstat answers without a reconstruct;
    // if the body is gone the fields are left out rather than failing.
    if let Ok(Some((size, weight))) = ctx.query.block_size_weight(at.header_fk) {
        insert_size_weight(&mut obj, u64::from(size), u64::from(weight));
    }
    let cb_fk = ctx
        .query
        .header_tx_fks(at.header_fk, Some(&at.hash))
        .map_err(misc)?
        .and_then(|fks| fks.first().copied());
    if let Some(fk) = cb_fk {
        match ctx.query.reconstruct_tx(fk) {
            Ok(cb) => obj["coinbase_tx"] = coinbase_tx_json(&cb),
            Err(rbitcoin_store::StoreError::Pruned { .. }) => {}
            Err(e) => return Err(misc(e)),
        }
    }
    if !at.finish(ctx, &mut obj)? {
        return getblock_unknown_hash(ctx, at.hash, 1);
    }
    Ok(obj)
}

/// Verbosity 0 and >= 2: the body and its prevout edges from one header fk.
fn getblock_body(
    ctx: &RpcContext,
    at: &ActiveAt,
    rec: rbitcoin_store::HeaderRecord,
    verbosity: u32,
) -> Result<Value, Value> {
    let misc = |e: rbitcoin_query::QueryError| rpc_error(ERR_MISC, e.to_string());
    let pruned = |e| map_query(e, "Block not available (pruned data)");
    ctx.query.require_seqsigwit_at(at.height).map_err(pruned)?;
    let prev = prev_hash_of(ctx, &rec)?;
    let fks = ctx
        .query
        .header_tx_fks(at.header_fk, Some(&at.hash))
        .map_err(misc)?
        .ok_or_else(|| {
            misc(rbitcoin_store::StoreError::Corrupt(
                "confirmed header missing body list",
            ))
        })?;
    let block = ctx
        .query
        .reconstruct_archived_block_from_parts(rec, fks.clone())
        .map_err(pruned)?;
    if block.block_hash().to_byte_array() != at.hash {
        return Err(misc(rbitcoin_store::StoreError::Corrupt(
            "reconstruct hash mismatch",
        )));
    }
    if verbosity == 0 {
        let mut raw = Vec::new();
        block
            .consensus_encode(&mut raw)
            .map_err(|_| rpc_error(ERR_MISC, "block encode"))?;
        return Ok(json!(rbitcoin_primitives::hex_encode(&(raw))));
    }
    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| hash_hex_display(&tx.compute_txid().to_byte_array()))
        .collect();
    let mut obj = json!({
        "hash": hash_hex_display(&at.hash),
        "confirmations": confirmations(ctx, at.height),
        "height": at.height.0,
        "version": block.header.version.to_consensus(),
        "merkleroot": hash_hex_display(&block.header.merkle_root.to_byte_array()),
        "time": block.header.time,
        "mediantime": rbitcoin_query::median_time_past(ctx.query.as_ref(), at.height)
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
        Some(at.height),
        None,
    );
    if let Some(cb) = block.txdata.first() {
        obj["coinbase_tx"] = coinbase_tx_json(cb);
    }
    if verbosity >= 2 {
        insert_block_size_fields(&mut obj, &block);
        let undo = BlockUndo {
            header_fk: at.header_fk,
            fks,
        };
        obj["tx"] = json!(getblock_tx_json(ctx, &block, Some(&undo), verbosity)?);
    }
    if !at.finish(ctx, &mut obj)? {
        return disconnected_block_value(ctx, &at.hash, &block, verbosity);
    }
    Ok(obj)
}

#[doc(hidden)]
pub fn disconnected_block_value(
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
        return Ok(json!(rbitcoin_primitives::hex_encode(&(raw))));
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
    let (height, chainwork) = match &loc {
        Some(l) => (Some(l.height), l.chainwork.clone()),
        None => held_height_and_work_hex(ctx, block),
    };
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
    if let Some(h) = height {
        obj["height"] = json!(h);
    }
    if prev != [0u8; 32] {
        insert_previousblockhash(&mut obj, &hash_hex_display(&prev));
    }
    enrich_block_header_json(&mut obj, ctx, version, bits, None, Some(chainwork));
    if let Some(cb) = block.txdata.first() {
        obj["coinbase_tx"] = coinbase_tx_json(cb);
    }
    if verbosity >= 2 {
        insert_block_size_fields(&mut obj, block);
        let undo = stored_block_fks(ctx, hash);
        obj["tx"] = json!(getblock_tx_json(ctx, block, undo.as_ref(), verbosity)?);
    }
    Ok(obj)
}

#[doc(hidden)]
pub fn getblock_unknown_hash(
    ctx: &RpcContext,
    hash: [u8; 32],
    verbosity: u32,
) -> Result<Value, Value> {
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

pub fn confirmations(ctx: &RpcContext, height: Height) -> u32 {
    let tip = ctx.query.tip_height().map(|h| h.0).unwrap_or(0);
    tip.saturating_sub(height.0).saturating_add(1)
}

pub fn getblockfilter(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "filtertype"])?;
    let hex = params.req_str(0, "blockhash")?;
    let filtertype = params.opt_str(1, "filtertype")?.unwrap_or("basic");
    if filtertype != "basic" {
        return Err(rpc_error(
            ERR_INVALID_ADDRESS_OR_KEY,
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
    let (body, header) = ctx
        .query
        .basic_filter_for_hash(&hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?
        .ok_or_else(|| rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
    use bitcoin::hashes::Hash;
    Ok(json!({
        "filter": rbitcoin_primitives::hex_encode(&body),
        "header": rbitcoin_primitives::hex_encode(header.as_byte_array() ),
    }))
}

pub fn gettxout(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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
                // Another mempool tx spending this output takes it out of the
                // coins view, as the confirmed path does below.
                if mp.spends_outpoint(&bitcoin::OutPoint { txid: tid, vout: n }) {
                    return Ok(Value::Null);
                }
                if let Some(out) = tx.output.get(n as usize) {
                    return Ok(json!({
                        "bestblock": getbestblockhash(ctx)?,
                        "confirmations": 0,
                        "value": out.value.to_btc(),
                        "scriptPubKey": script_pubkey_json(&out.script_pubkey, rpc_btc_network(ctx.network)),
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
    // Spender read treats a slot past `output_count` as corrupt. The vout is absent.
    if n >= rec.output_count {
        return Ok(Value::Null);
    }
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
    // Core never adds an unspendable output to the coins view.
    if rbitcoin_consensus::policy::is_unspendable(&out.script) {
        return Ok(Value::Null);
    }
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
        "value": Amount::from_sat(out.value).to_btc(),
        "scriptPubKey": script_pubkey_json(&ScriptBuf::from_bytes(out.script), rpc_btc_network(ctx.network)),
        "coinbase": coinbase,
    }))
}

pub fn getindexinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn getchaintips(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn wait_timeout_ms(params: &RpcParams, idx: usize, name: &str) -> Result<u64, Value> {
    let ms = params.opt_u64(idx, name)?.unwrap_or(30_000);
    Ok(ms.min(super::RPC_WAIT_TIMEOUT_MS))
}

pub fn tip_hash_height(ctx: &RpcContext) -> Result<(String, u32), Value> {
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

pub fn buried_row(height: u32, at: u32) -> Value {
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
pub fn buried_deployments(params: &rbitcoin_consensus::ChainParams, at: u32) -> Value {
    json!({
        "bip34": buried_row(params.btc.bip34_height, at),
        "bip66": buried_row(params.btc.bip66_height, at),
        "bip65": buried_row(params.btc.bip65_height, at),
        "csv": buried_row(params.csv_height(), at),
        "segwit": buried_row(params.segwit_height(), at),
        "taproot": buried_row(params.taproot_height(), at),
    })
}

pub fn getdeploymentinfo(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
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

pub fn waitforblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash", "timeout"])?;
    let want = params.req_str(0, "blockhash")?.to_string();
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash == want)
}

pub fn waitforblockheight(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["height", "timeout"])?;
    let want = params.req_u64(0, "height")? as u32;
    let timeout_ms = wait_timeout_ms(params, 1, "timeout")?;
    wait_for_tip(ctx, timeout_ms, |_hash, height| height >= want)
}

pub fn waitfornewblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["timeout"])?;
    let timeout_ms = wait_timeout_ms(params, 0, "timeout")?;
    let (start_hash, _) = tip_hash_height(ctx)?;
    wait_for_tip(ctx, timeout_ms, |hash, _height| hash != start_hash)
}

/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
/// `feature_shutdown.py`: stop must wake waiters so in-flight wait RPCs
/// return the current tip instead of hanging until the connection drops.
pub fn wait_for_tip(
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

fn block_missing_or_misc(e: impl std::fmt::Display) -> Value {
    let s = e.to_string();
    if s.contains("Block not found") {
        rpc_error(ERR_INVALID_ADDRESS_OR_KEY, "Block not found")
    } else {
        rpc_error(ERR_MISC, s)
    }
}

pub fn require_chain(ctx: &RpcContext) -> Result<&rbitcoin_net::ChainHub, Value> {
    ctx.chain
        .as_deref()
        .ok_or_else(|| rpc_error(ERR_MISC, "chain hub not attached"))
}

pub fn parse_blockhash_param(params: &RpcParams) -> Result<bitcoin::BlockHash, Value> {
    let hex = params.req_str(0, "blockhash")?;
    let b = parse_hash32_display(hex)?;
    Ok(bitcoin::BlockHash::from_byte_array(b))
}

pub fn invalidateblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.invalidate_block(hash).map_err(block_missing_or_misc)?;
    Ok(Value::Null)
}

pub fn submitheader(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["hexdata"])?;
    let hub = require_chain(ctx)?;
    let hex = params.req_str(0, "hexdata")?;
    let header = decode_header_hex(hex)?;
    hub.process_submitted_header(&header)
        .map_err(|e| rpc_error(ERR_VERIFY_ERROR, e))?;
    Ok(Value::Null)
}

pub fn decode_header_hex(hex: &str) -> Result<bitcoin::block::Header, Value> {
    let raw = rbitcoin_primitives::hex_decode(hex)
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

pub fn reconsiderblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.reconsider_block(hash)
        .map_err(|e| rpc_error(ERR_MISC, e.to_string()))?;
    Ok(Value::Null)
}

pub fn preciousblock(ctx: &RpcContext, params: &RpcParams) -> Result<Value, Value> {
    params.reject_unknown(&["blockhash"])?;
    let hub = require_chain(ctx)?;
    let hash = parse_blockhash_param(params)?;
    hub.precious_block(hash).map_err(block_missing_or_misc)?;
    Ok(Value::Null)
}
