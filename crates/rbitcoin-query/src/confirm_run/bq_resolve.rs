//! BQ-ahead TipOnly parent resolve (lookup wave).
//!
//! Pack/hold uses enqueue-stamped Σ inputs (no `Block` decode). Emit resolves
//! the selected heights with `Store::get_fk_by_txid_batch_cancellable`
//! (TipOnly, pieces of 4096 under one fence snapshot; soft **64000** inputs /
//! hard **1080** blocks). Hits ride the wave as
//! [`crate::BatchParentIds`] (fk + body_range + spent_range). Does not
//! claim, structure, or stamp. Same-wave creates are omitted from TipOnly need.

use super::*;
use crate::{BatchParentIds, IdMap, ResolvedWire, TxPrecompute, TxidHasher, U32Map, U64Map};
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use std::sync::Arc;

/// Hard cap on BQ heights in one TipOnly wave (~1 week of 10-minute blocks).
///
/// Load packs **8000** inputs / **144** blocks. Lookup stays at least 4× the
/// block cap so early-IBD waves are fat enough that one skeleton covers many
/// heights. Soft stop is Σ `tx.input`
/// ([`BQ_RESOLVE_WAVE_MAX_INPUTS`]), include-overshoot, same shape as load.
/// Fat-era 64 k inputs is ~16 blocks → ~20 layers at `ready≈330`.
pub const BQ_RESOLVE_WAVE_MAX_BLOCKS: usize = 1080;
/// Soft max Σ `tx.input` per lookup wave (8× load's 8000; overshoot included).
pub const BQ_RESOLVE_WAVE_MAX_INPUTS: u32 = 64_000;
/// TipOnly need resolved per piece; the confirm cancel is asked between
/// pieces, so IBD teardown waits for one piece rather than a whole wave.
const BQ_RESOLVE_CANCEL_PIECE_TXIDS: usize = 4096;
/// Hard min Σ `tx.input` per lookup wave (same number as load's pack).
///
/// Hold a thinner collect when more unresolved BQ heights can still join —
/// including `ready=0` / load-frontier / unknown window. Last available
/// thin wave still emits (tip / empty BQ).
pub const BQ_RESOLVE_WAVE_MIN_INPUTS: u32 = 8000;
/// Safety cap so one megablock run cannot stall the wave.
pub const BQ_RESOLVE_WAVE_MAX_KEYS: usize = 256_000;

/// Stop before another height once the key cap is hit and this wave already
/// has a height. An empty `done` still emits the height that filled the cap.
#[doc(hidden)]
pub fn stop_for_key_cap(n_keys: usize, done: usize) -> bool {
    n_keys >= BQ_RESOLVE_WAVE_MAX_KEYS && done > 0
}

/// Soft window at least one day of blocks, and the queue has not filled it.
#[doc(hidden)]
pub fn wave_queue_still_filling(win: u32, queued: u32) -> bool {
    win >= 144 && queued < win
}

/// More BQ heights than this wave, or the queue is still filling that window.
#[doc(hidden)]
pub fn wave_more_remain(selected: usize, requested: usize, filling: bool) -> bool {
    selected < requested || filling
}

/// Same include-overshoot rule as load `pack_stop_after`: stop after the
/// block that crosses the soft input budget or hits the hard height cap.
#[inline]
pub fn bq_resolve_wave_stop_after(
    sum_inputs: u32,
    n_blocks: usize,
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> bool {
    n_blocks >= hard_max_blocks || sum_inputs > soft_max_inputs
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Hold a short wave while the BQ is fat so lookup does not mint one layer
/// per newly fetched block.
///
/// `ready` is BQ depth. `soft_win` is the 1-min confirm window (`bq soft=n/win`).
/// `path_lo` is the load frontier (store tip+1). `first_unresolved` is the
/// lowest collected height (already sorted by `BlockQueue::unresolved_heights`).
///
/// Never hold (above the input floor) when the first unresolved height sits
/// in the load-facing half of the window (`first - path_lo ≤ win/2`) — that
/// is the block load is about to claim. O(1): two subtracts, no extra queue
/// walk. `soft_win == 0` (rate unknown) skips only the fat-BQ short hold.
///
/// `more_remain`: more unresolved BQ heights can still join this layer.
/// [`BQ_RESOLVE_WAVE_MIN_INPUTS`] holds a thin far wave; it does **not**
/// hold when `first_unresolved == path_lo` (load's next tip block).
#[inline]
pub fn bq_resolve_wave_hold_partial(
    ready: u32,
    soft_win: u32,
    sum_inputs: u32,
    n_blocks: usize,
    path_lo: u32,
    first_unresolved: u32,
    more_remain: bool,
    max_inputs: u32,
    max_blocks: usize,
) -> bool {
    if n_blocks == 0 {
        return false;
    }
    let at_max = bq_resolve_wave_stop_after(sum_inputs, n_blocks, max_inputs, max_blocks);
    if at_max {
        return false;
    }
    if sum_inputs < BQ_RESOLVE_WAVE_MIN_INPUTS && more_remain && first_unresolved != path_lo {
        return true;
    }
    if soft_win == 0 {
        return false;
    }
    if first_unresolved.saturating_sub(path_lo) <= soft_win / 2 {
        return false;
    }
    ready > soft_win / 2
}

/// Decoded heights from one lookup wave (BQ rows parked as resolved until take).
pub struct BqResolveWave {
    pub stats: BqResolveWaveStats,
    pub items: Vec<(u32, [u8; 32], ResolvedWire)>,
    /// [`Query::drain_and_fence_hi`] immediately before this wave's TipOnly read.
    pub drain_fence_hi: Option<u32>,
    /// TipOnly hits for this wave (`need_vouts` filled per load chunk at send).
    pub parent_ids: BatchParentIds,
    /// `(height, hash)` of a raw row that did not decode. The wave stops
    /// there and the row is already off the body queue; the caller rejects
    /// the hash as soft wire so another peer can serve it.
    pub undecodable: Option<(u32, [u8; 32])>,
}

/// Outcome of one TipOnly wave over BQ-ready heights.
#[derive(Debug, Default, Clone, Copy)]
pub struct BqResolveWaveStats {
    pub heights: u32,
    pub keys: u32,
    pub hits: u32,
    pub work_ns: u64,
    /// `consensus_decode` of still-raw BQ payloads (this wave).
    pub decode_ns: u64,
    /// `from_tx_wire` on payload slices (`precompute=`).
    pub precompute_ns: u64,
    /// `push_resolve_keys` (this wave).
    pub collect_ns: u64,
    /// TipOnly `get_fk_by_txid_batch_cancellable` (this wave).
    pub head_ns: u64,
    /// TipOnly `create.loc` fill is inside [`Self::head_ns`] (`idx_ns`): one
    /// batch after identity waves, not on the held probe ring.
    pub spent_ns: u64,
}

/// Push external prev_txids (+ pre-BIP34 create txids) into the wave TipOnly set.
///
/// Spend keys record every non-coinbase prev (including same-wave creates) so
/// a later load chunk can bind in-flight. TipOnly `keys` still omit `skip`.
#[doc(hidden)]
pub fn push_resolve_keys(
    params: &ChainParams,
    height: u32,
    block: &Block,
    pres: &[TxPrecompute],
    skip: &HashSet<[u8; 32], BuildHasherDefault<TxidHasher>>,
    keys: &mut HashSet<[u8; 32], BuildHasherDefault<TxidHasher>>,
    n_inputs: u32,
) -> Vec<([u8; 32], u32)> {
    let bip34 = params.bip34_active_at(height);
    let mut spends = Vec::with_capacity(n_inputs as usize);
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        for inp in &tx.input {
            if inp.previous_output.is_null() {
                continue;
            }
            let prev = inp.previous_output.txid.to_byte_array();
            if prev == [0u8; 32] {
                continue;
            }
            spends.push((prev, inp.previous_output.vout));
            if !skip.contains(&prev) {
                keys.insert(prev);
            }
        }
        if !bip34 && !skip.contains(&p.txid) {
            keys.insert(p.txid);
        }
    }
    spends
}

/// TipOnly-resolve external parents for `heights` still on the BQ.
///
/// Skips missing / already-complete heights. Stops at the first raw row
/// that does not decode, dequeues it, and names it in
/// [`BqResolveWave::undecodable`]. Marks each
/// processed height resolve-complete even when some keys miss (same-batch /
/// in-flight remainder is load's job). Connected-only (fence) resolve.
/// `max_blocks` / `max_inputs` cap emit (remaining loadq).
pub fn confirm_bq_resolve_wave_capped(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    heights: &[u32],
    max_blocks: usize,
    max_inputs: u32,
) -> Result<BqResolveWave, ConfirmError> {
    let t0 = Instant::now();
    let mut stats = BqResolveWaveStats::default();
    let mut done: Vec<u32> = Vec::new();
    let mut all_keys: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    let mut wave_creates: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
        HashSet::with_hasher(BuildHasherDefault::default());
    let mut wires: Vec<(u32, [u8; 32], ResolvedWire)> = Vec::new();

    let intake = query.block_queue_wave_intake(heights);
    let mut n_inputs_at: U32Map<u32> = U32Map::default();
    let mut header_fk_at: U32Map<u64> = U32Map::default();
    let mut sender_at: U32Map<u64> = U32Map::default();
    let raw_h: HashSet<u32> = intake
        .raw
        .into_iter()
        .map(|(h, n, fk, sender)| {
            n_inputs_at.insert(h, n);
            header_fk_at.insert(h, fk);
            if let Some(s) = sender {
                sender_at.insert(h, s);
            }
            h
        })
        .collect();
    let mut resolved_by_h: HashMap<u32, ResolvedWire> = HashMap::new();
    for (h, wire) in intake.resolved {
        n_inputs_at.insert(h, wire.n_inputs);
        resolved_by_h.insert(h, wire);
    }

    let mut selected: Vec<u32> = Vec::new();
    let mut sum_inputs = 0u32;
    for &h in heights {
        if !raw_h.contains(&h) && !resolved_by_h.contains_key(&h) {
            continue;
        }
        let n = n_inputs_at.get(&h).copied().unwrap_or(0);
        selected.push(h);
        sum_inputs = sum_inputs.saturating_add(n);
        if bq_resolve_wave_stop_after(sum_inputs, selected.len(), max_inputs, max_blocks) {
            break;
        }
    }

    if let Some(&first) = selected.first() {
        let path_lo = query
            .tip_height()
            .map(|h| h.0.saturating_add(1))
            .unwrap_or(0);
        let win = query.soft_confirm_window();
        let filling = wave_queue_still_filling(win, query.block_queue_count() as u32);
        let more_remain = wave_more_remain(selected.len(), heights.len(), filling);
        if bq_resolve_wave_hold_partial(
            query.block_queue_count() as u32,
            query.soft_confirm_window(),
            sum_inputs,
            selected.len(),
            path_lo,
            first,
            more_remain,
            max_inputs,
            max_blocks,
        ) {
            stats.work_ns = t0.elapsed().as_nanos() as u64;
            query.confirm_stats().note_wave_decode(
                stats.decode_ns,
                stats.precompute_ns,
                stats.collect_ns,
                stats.head_ns,
                stats.spent_ns,
            );
            return Ok(BqResolveWave {
                stats,
                items: Vec::new(),
                drain_fence_hi: None,
                parent_ids: BatchParentIds::default(),
                undecodable: None,
            });
        }
    }

    let mut undecodable = None;
    for &h in &selected {
        if stop_for_key_cap(all_keys.len(), done.len()) {
            break;
        }
        let hash = query.block_queue_hash_at_height(h).unwrap_or([0u8; 32]);
        let (block, pres) = if let Some(wire) = resolved_by_h.remove(&h) {
            wires.push((h, hash, wire.clone()));
            (Arc::clone(&wire.block), Arc::clone(&wire.pres))
        } else if raw_h.contains(&h) {
            let Ok(Some(payload)) = query.block_queue_raw_payload(h) else {
                continue;
            };
            let t_dec = Instant::now();
            let decoded = crate::decode_block_precomputes(
                &payload[..],
                !crate::milestone_gate::skips_on_query(milestone, query, h, &hash),
            );
            let wall = t_dec.elapsed().as_nanos() as u64;
            let Some((block, pres_vec, pre_ns)) = decoded else {
                // A row that never decodes would hold this height in hand
                // forever: drop it so the hash is fetched again.
                stats.decode_ns = stats.decode_ns.saturating_add(wall);
                query.block_queue_dequeue_height(h)?;
                undecodable = Some((h, hash));
                break;
            };
            stats.decode_ns = stats.decode_ns.saturating_add(wall.saturating_sub(pre_ns));
            stats.precompute_ns = stats.precompute_ns.saturating_add(pre_ns);
            let pres = Arc::<[TxPrecompute]>::from(pres_vec);
            let block = Arc::new(block);
            wires.push((
                h,
                hash,
                ResolvedWire {
                    block: Arc::clone(&block),
                    pres: Arc::clone(&pres),
                    n_inputs: n_inputs_at.get(&h).copied().unwrap_or(0),
                    header_fk: header_fk_at.get(&h).copied().unwrap_or(0),
                    spend_keys: Arc::from([]),
                    sender: sender_at.get(&h).copied(),
                },
            ));
            (block, pres)
        } else {
            continue;
        };
        let t_col = Instant::now();
        for p in pres.iter() {
            wave_creates.insert(p.txid);
        }
        let spends = push_resolve_keys(
            params,
            h,
            block.as_ref(),
            pres.as_ref(),
            &wave_creates,
            &mut all_keys,
            n_inputs_at.get(&h).copied().unwrap_or(0),
        );
        if let Some((_, _, w)) = wires.last_mut() {
            w.spend_keys = Arc::from(spends);
        }
        stats.collect_ns = stats
            .collect_ns
            .saturating_add(t_col.elapsed().as_nanos() as u64);
        done.push(h);
    }

    stats.keys = all_keys.len() as u32;
    let mut layer = IdMap::default();
    let mut spent = U64Map::default();
    let mut n_out = U64Map::default();
    let need: Vec<[u8; 32]> = all_keys.into_iter().collect();
    let t_head = Instant::now();

    let drain_fence_hi = query.drain_and_fence_hi();
    if let Some(&hi) = selected.last() {
        query.note_lookup_tiponly_start(hi);
    }

    if !need.is_empty() {
        let rows = query
            .store()
            .get_fk_by_txid_batch_cancellable(&need, BQ_RESOLVE_CANCEL_PIECE_TXIDS, &|| {
                query.confirm_cancelled()
            })
            .map_err(ConfirmError::from)?;
        for (txid, row) in rows {
            if let Some((fk, pair)) = row {
                layer.insert(txid, (fk, pair.txout));
                if let Some(id) = fk.get() {
                    spent.insert(id, pair.spent);
                    n_out.insert(id, pair.n_out);
                }
            }
        }
    }
    stats.head_ns = t_head.elapsed().as_nanos() as u64;
    stats.hits = layer.len() as u32;
    stats.spent_ns = 0;
    let parent_ids = BatchParentIds {
        ids: Arc::new(layer),
        spent: Arc::new(spent),
        n_out: Arc::new(n_out),
        need_vouts: U64Map::default(),
    };

    let mut items = Vec::with_capacity(wires.len());
    let mut promote = Vec::with_capacity(wires.len());
    for (h, hash, wire) in wires {
        let charge = wire.block.total_size() as u64;
        promote.push((h, wire.clone(), charge));
        items.push((h, hash, wire));
    }
    if !promote.is_empty() {
        query
            .block_queue_promote_wave(promote)
            .map_err(ConfirmError::from)?;
    }
    stats.heights = items.len() as u32;
    stats.work_ns = t0.elapsed().as_nanos() as u64;
    query.confirm_stats().note_wave_decode(
        stats.decode_ns,
        stats.precompute_ns,
        stats.collect_ns,
        stats.head_ns,
        stats.spent_ns,
    );
    Ok(BqResolveWave {
        stats,
        items,
        drain_fence_hi,
        parent_ids,
        undecodable,
    })
}

/// Take one load batch: move `lookup_taken_hi` to its last height, then
/// dequeue its BQ rows. `gen` is [`Query::lookup_taken_gen`] when the wave
/// was selected. After a re-arm the mark stays at the re-arm and this
/// returns `false` with the rows still queued, so the caller must not send
/// the batch: lookup selects those rows again.
pub fn take_wave_items_for_load(
    query: &Query,
    items: &[(u32, [u8; 32], ResolvedWire)],
    gen: u32,
) -> Result<bool, ConfirmError> {
    let Some(&(last, _, _)) = items.last() else {
        return Ok(true);
    };
    if !query.advance_lookup_taken_hi(gen, last) {
        return Ok(false);
    }
    for (h, _, _) in items {
        query
            .block_queue_dequeue_height(*h)
            .map_err(ConfirmError::from)?;
    }
    Ok(true)
}
