//! BQ-ahead TipOnly parent resolve (lookup wave).
//!
//! One [`Store::get_fk_by_txid_batch`] (TipOnly) across a ready-height wave
//! (soft **64000** inputs / hard **1080** blocks). Hits publish as one
//! [`rbitcoin_query::IdLayer`] on the live union. Does not claim, structure, or stamp.

use super::*;
use bitcoin::consensus::Decodable;
use rbitcoin_query::{ResolvedWire, TxPrecompute};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::Arc;

/// Hard cap on BQ heights in one TipOnly wave (~1 week of 10-minute blocks).
///
/// Load packs **8000** inputs / **144** blocks. Lookup stays at least 4× the
/// block cap so early-IBD waves are fat enough that one published identity
/// layer covers many heights. Soft stop is Σ `tx.input`
/// ([`BQ_RESOLVE_WAVE_MAX_INPUTS`]), include-overshoot, same shape as load.
/// Fat-era 64 k inputs is ~16 blocks → ~20 layers at `ready≈330`.
pub const BQ_RESOLVE_WAVE_MAX_BLOCKS: usize = 1080;
/// Soft max Σ `tx.input` per lookup wave (8× load's 8000; overshoot included).
pub const BQ_RESOLVE_WAVE_MAX_INPUTS: u32 = 64_000;
/// Safety cap so one megablock run cannot stall the wave.
pub const BQ_RESOLVE_WAVE_MAX_KEYS: usize = 256_000;

/// Same include-overshoot rule as load [`pack_stop_after`]: stop after the
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

/// Hold a short wave while the BQ is fat so lookup does not mint one layer
/// per newly fetched block.
///
/// `ready` is BQ depth. `soft_win` is the 1-min confirm window (`bq soft=n/win`).
/// `path_lo` is the load frontier (store tip+1). `first_unresolved` is the
/// lowest collected height (already sorted by [`BlockQueue::unresolved_heights`]).
///
/// Never hold when the first unresolved height sits in the load-facing half
/// of the window (`first - path_lo ≤ win/2`) — that is the block load is
/// about to claim. O(1): two subtracts, no extra queue walk.
/// `soft_win == 0` (rate unknown) never holds.
#[inline]
pub fn bq_resolve_wave_hold_partial(
    ready: u32,
    soft_win: u32,
    sum_inputs: u32,
    n_blocks: usize,
    path_lo: u32,
    first_unresolved: u32,
) -> bool {
    if soft_win == 0 || n_blocks == 0 {
        return false;
    }
    if first_unresolved.saturating_sub(path_lo) <= soft_win / 2 {
        return false;
    }
    ready > soft_win / 2
        && !bq_resolve_wave_stop_after(
            sum_inputs,
            n_blocks,
            BQ_RESOLVE_WAVE_MAX_INPUTS,
            BQ_RESOLVE_WAVE_MAX_BLOCKS,
        )
}

/// Outcome of one TipOnly wave over BQ-ready heights.
#[derive(Debug, Default, Clone, Copy)]
pub struct BqResolveWaveStats {
    pub heights: u32,
    pub keys: u32,
    pub hits: u32,
    /// Keys already in [`rbitcoin_query::LiveUnion`] — no TipOnly this wave.
    pub skipped: u32,
    pub work_ns: u64,
}

/// Collect unique external prev_txids (+ pre-BIP34 create txids) from a wire block.
fn collect_resolve_keys(
    params: &ChainParams,
    height: u32,
    block: &Block,
    pres: &[TxPrecompute],
) -> Vec<[u8; 32]> {
    let same_block: HashSet<[u8; 32]> = pres.iter().map(|p| p.txid).collect();
    let mut need: Vec<[u8; 32]> = Vec::new();
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        for inp in &tx.input {
            if inp.previous_output.is_null() {
                continue;
            }
            let prev = inp.previous_output.txid.to_byte_array();
            if prev == [0u8; 32] || same_block.contains(&prev) {
                continue;
            }
            need.push(prev);
        }
        if !params.bip34_active_at(height) {
            need.push(p.txid);
        }
    }
    need.sort_unstable();
    need.dedup();
    need
}

fn decoded_charge(payload_len: u64, n_tx: usize) -> u64 {
    let approx = payload_len
        .saturating_add(256)
        .saturating_add((n_tx as u64).saturating_mul(256))
        .saturating_add((n_tx as u64).saturating_mul(std::mem::size_of::<TxPrecompute>() as u64));
    payload_len.max(approx)
}

fn decode_bq_block(payload: &[u8]) -> Option<Block> {
    let mut cur = Cursor::new(payload);
    Block::consensus_decode(&mut cur).ok()
}

/// TipOnly-resolve external parents for `heights` still on the BQ.
///
/// Skips missing / already-complete / undecodable heights. Marks each
/// processed height resolve-complete even when some keys miss (same-batch /
/// in-flight remainder is load's job). Connected-only (fence) resolve.
///
/// When `ids` is `Some`, skip TipOnly for keys already in the live union and
/// publish **one** layer for the whole wave (`lo..=hi`). The layer stays until
/// no height in that span is still on the body queue.
pub fn confirm_bq_resolve_wave(
    query: &Query,
    params: &ChainParams,
    heights: &[u32],
) -> Result<BqResolveWaveStats, ConsensusError> {
    confirm_bq_resolve_wave_with_ids(query, params, heights, None)
}

/// [`confirm_bq_resolve_wave`] with a lookup-owned live union.
pub fn confirm_bq_resolve_wave_with_ids(
    query: &Query,
    params: &ChainParams,
    heights: &[u32],
    mut ids: Option<(
        &mut rbitcoin_query::LiveUnion,
        &rbitcoin_query::PublishedIds,
    )>,
) -> Result<BqResolveWaveStats, ConsensusError> {
    let t0 = Instant::now();
    let mut stats = BqResolveWaveStats::default();
    let mut per_height: Vec<(u32, Vec<[u8; 32]>)> = Vec::new();
    let mut all_keys: HashSet<[u8; 32]> = HashSet::new();
    let mut sum_inputs = 0u32;
    let mut promote: Vec<(u32, ResolvedWire, u64)> = Vec::new();

    let intake = query.block_queue_wave_intake(heights);
    let mut by_h: HashMap<u32, (Option<Vec<u8>>, Option<ResolvedWire>)> = HashMap::new();
    for (h, payload) in intake.raw {
        by_h.entry(h).or_default().0 = Some(payload);
    }
    for (h, wire) in intake.resolved {
        by_h.entry(h).or_default().1 = Some(wire);
    }

    for &h in heights {
        let Some(slot) = by_h.remove(&h) else {
            continue;
        };
        let (block, pres) = if let Some(wire) = slot.1 {
            (Arc::clone(&wire.block), Arc::clone(&wire.pres))
        } else {
            let Some(payload) = slot.0 else {
                continue;
            };
            let Some(block) = decode_bq_block(&payload) else {
                continue;
            };
            let pres: Vec<TxPrecompute> = block.txdata.iter().map(TxPrecompute::from_tx).collect();
            let charge = decoded_charge(payload.len() as u64, pres.len());
            let pres = Arc::<[TxPrecompute]>::from(pres);
            let block = Arc::new(block);
            promote.push((
                h,
                ResolvedWire {
                    block: Arc::clone(&block),
                    pres: Arc::clone(&pres),
                },
                charge,
            ));
            (block, pres)
        };
        let need = collect_resolve_keys(params, h, block.as_ref(), pres.as_ref());
        if all_keys.len().saturating_add(need.len()) > BQ_RESOLVE_WAVE_MAX_KEYS
            && !per_height.is_empty()
        {
            break;
        }
        let block_inputs = block
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        for k in &need {
            all_keys.insert(*k);
        }
        per_height.push((h, need));
        sum_inputs = sum_inputs.saturating_add(block_inputs);
        if bq_resolve_wave_stop_after(
            sum_inputs,
            per_height.len(),
            BQ_RESOLVE_WAVE_MAX_INPUTS,
            BQ_RESOLVE_WAVE_MAX_BLOCKS,
        ) {
            break;
        }
    }

    if !promote.is_empty() {
        query
            .block_queue_promote_wave(promote)
            .map_err(ConsensusError::from)?;
    }

    if let Some(&(first, _)) = per_height.first() {
        let path_lo = query
            .tip_height()
            .map(|h| h.0.saturating_add(1))
            .unwrap_or(0);
        if bq_resolve_wave_hold_partial(
            query.block_queue_count() as u32,
            query.soft_confirm_window(),
            sum_inputs,
            per_height.len(),
            path_lo,
            first,
        ) {
            stats.work_ns = t0.elapsed().as_nanos() as u64;
            return Ok(stats);
        }
    }

    let keys: Vec<[u8; 32]> = all_keys.into_iter().collect();
    stats.keys = keys.len() as u32;
    let (mut hit_map, need): (
        HashMap<[u8; 32], (rbitcoin_primitives::Fk, (u64, u64))>,
        Vec<[u8; 32]>,
    ) = match ids.as_mut() {
        Some((live, _)) => {
            let (known, need) = live.partition(keys.iter());
            stats.skipped = known.len() as u32;
            (known.into_iter().collect(), need)
        }
        None => (HashMap::new(), keys),
    };
    let mut need = need;
    need.sort_unstable_by_key(|txid| query.store().txs.head_primary_slot(txid));

    if !need.is_empty() {
        let rows = query
            .store()
            .get_fk_by_txid_batch(&need)
            .map_err(ConsensusError::from)?;
        for (txid, row) in rows {
            if let Some((fk, range)) = row {
                hit_map.insert(txid, (fk, range));
            }
        }
    }
    stats.hits = hit_map.len() as u32;
    if let Some((live, published)) = ids.as_mut() {
        let mut hits = rbitcoin_query::IdMap::default();
        for (_h, need) in &per_height {
            for t in need {
                if let Some(&v) = hit_map.get(t) {
                    hits.insert(*t, v);
                }
            }
        }
        if let (Some(&(lo, _)), Some(&(hi, _))) = (per_height.first(), per_height.last()) {
            live.note_span(lo, hi, &hits);
        }
        let t_keep = Instant::now();
        let queued = query.block_queue_queued_heights();
        live.keep_queued_heights(&queued);
        live.publish(published);
        crate::confirm_phase_stats::LOOKUP_KEEP_NS
            .fetch_add(t_keep.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    let done: Vec<u32> = per_height.iter().map(|(h, _)| *h).collect();
    query
        .block_queue_mark_resolve_complete_wave(&done)
        .map_err(ConsensusError::from)?;
    stats.heights = done.len() as u32;
    stats.work_ns = t0.elapsed().as_nanos() as u64;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept_and_connect_block;
    use crate::regtest_pad::mine_empty_regtest;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use std::sync::Once;

    fn head_tiny() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
                std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
            }
        });
    }

    fn tmp_query() -> (std::path::PathBuf, Query) {
        head_tiny();
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-bq-resolve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let q = Query::open_or_create(&path).unwrap();
        (path, q)
    }

    fn spend_op_true(prev: Txid, vout: u32, value: Amount) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value,
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn coinbase_tx(height: u32) -> Transaction {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            crate::bip34_height_script(height)
        };
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn mine_with_txs(prev: BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
        };
        let mut txdata = vec![coinbase_tx(height)];
        txdata.extend(extra);
        let mut block = Block { header, txdata };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    }

    #[test]
    fn bq_resolve_wave_attaches_tiponly_hits_multi_height() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let g_cb = genesis.txdata[0].compute_txid();
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
        );
        let b2 = mine_with_txs(
            b1.block_hash(),
            b1.header.time + 600,
            2,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(48_0000_0000))],
        );
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
            .unwrap();

        let mut live = rbitcoin_query::LiveUnion::new();
        let st = confirm_bq_resolve_wave_with_ids(
            &q,
            &params,
            &[1, 2],
            Some((&mut live, q.published_ids().as_ref())),
        )
        .unwrap();
        assert_eq!(st.heights, 2);
        assert!(st.keys >= 1);
        assert!(st.hits >= 1);
        assert!(
            q.published_ids().get(&g_cb.to_byte_array()).is_some(),
            "genesis coinbase must be a TipOnly hit in the published union"
        );
        let head = q.published_ids().load().expect("published");
        assert!(
            head.older.is_none(),
            "one lookup wave is one published layer, not one layer per height"
        );
        assert_eq!((head.lo, head.hi), (1, 2));
        assert!(q.block_queue_is_resolve_complete(1));
        assert!(q.block_queue_is_resolve_complete(2));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn resolve_wave_takes_nine_tiny_heights() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let mut prev = genesis.block_hash();
        let mut time = genesis.header.time;
        let mut heights = Vec::new();
        for h in 1..=9u32 {
            time += 600;
            let b = mine_empty_regtest(prev, time, h);
            q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
                .unwrap();
            prev = b.block_hash();
            heights.push(h);
        }
        let st = confirm_bq_resolve_wave(&q, &params, &heights).unwrap();
        assert_eq!(
            st.heights, 9,
            "lookup wave must outgrow the old 8-height cap (soft 64000 inputs / hard 1080 blocks)"
        );
        assert!(
            q.block_queue_raw_payload(1).unwrap().is_none(),
            "lookup must drop raw after first decode"
        );
        let w = q.block_queue_resolved(1).expect("promoted");
        assert_eq!(w.pres.len(), w.block.txdata.len());
        assert_eq!(
            w.pres[0].txid,
            w.block.txdata[0].compute_txid().to_byte_array()
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn resolve_wave_pack_limits_are_4x_load_class() {
        assert_eq!(BQ_RESOLVE_WAVE_MAX_BLOCKS, 1080);
        assert_eq!(BQ_RESOLVE_WAVE_MAX_INPUTS, 64_000);
        assert_eq!(BQ_RESOLVE_WAVE_MAX_KEYS, 256_000);
        assert!(BQ_RESOLVE_WAVE_MAX_BLOCKS >= 144 * 4);
        assert!(BQ_RESOLVE_WAVE_MAX_INPUTS >= 8000 * 8);
        // Include-overshoot: take the crossing block, then stop.
        assert!(!bq_resolve_wave_stop_after(63_900, 1, 64_000, 1080));
        assert!(bq_resolve_wave_stop_after(64_100, 2, 64_000, 1080));
        assert!(bq_resolve_wave_stop_after(1, 1080, 64_000, 1080));
        assert!(!bq_resolve_wave_stop_after(64_000, 1079, 64_000, 1080));
    }

    #[test]
    fn hold_partial_table() {
        // far unresolved (beyond first half of win) + fat + short → hold
        assert!(bq_resolve_wave_hold_partial(330, 180, 4_000, 1, 100, 191));
        // same, but gap is in the first half of the window → emit (load needs it)
        assert!(!bq_resolve_wave_hold_partial(330, 180, 4_000, 1, 100, 190));
        assert!(!bq_resolve_wave_hold_partial(330, 180, 4_000, 1, 100, 100));
        // fat BQ + full input wave → emit
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 64_100, 16, 100, 250
        ));
        // fat BQ + full block cap → emit
        assert!(!bq_resolve_wave_hold_partial(330, 180, 1, 1080, 100, 250));
        // thin BQ + short wave → emit (load catching up)
        assert!(!bq_resolve_wave_hold_partial(50, 180, 4_000, 1, 100, 250));
        // rate unknown (win=0) → never hold
        assert!(!bq_resolve_wave_hold_partial(330, 0, 4_000, 1, 100, 250));
        // nothing collected
        assert!(!bq_resolve_wave_hold_partial(330, 180, 0, 0, 100, 100));
    }

    #[test]
    fn fat_bq_holds_short_unresolved_tail() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let mut prev = genesis.block_hash();
        let mut time = genesis.header.time;
        for h in 1..=8u32 {
            time += 600;
            let b = mine_empty_regtest(prev, time, h);
            q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
                .unwrap();
            prev = b.block_hash();
        }
        for h in 1..=7u32 {
            q.block_queue_mark_resolve_complete(h).unwrap();
        }
        // win = 0.2 * 60 = 12; ready=8 > 6 → hold the 1-block tail
        let _ = q.block_queue_update_soft_pressure(Some(0.2));
        let st = confirm_bq_resolve_wave(&q, &params, &[8]).unwrap();
        assert_eq!(st.heights, 0, "fat BQ must not mint a 1-block layer");
        assert!(!q.block_queue_is_resolve_complete(8));
        assert!(
            q.block_queue_raw_payload(8).unwrap().is_none(),
            "first decode must drop raw even when the wave holds"
        );
        let held = q.block_queue_resolved(8).expect("promoted on hold");
        assert_eq!(held.pres.len(), held.block.txdata.len());
        assert_eq!(
            held.pres[0].txid,
            held.block.txdata[0].compute_txid().to_byte_array()
        );

        let _ = q.block_queue_update_soft_pressure(None);
        let st = confirm_bq_resolve_wave(&q, &params, &[8]).unwrap();
        assert_eq!(st.heights, 1, "unknown window must allow a short wave");
        assert!(q.block_queue_is_resolve_complete(8));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn fat_bq_emits_short_wave_when_gap_is_at_load_frontier() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let mut prev = genesis.block_hash();
        let mut time = genesis.header.time;
        for h in 1..=20u32 {
            time += 600;
            let b = mine_empty_regtest(prev, time, h);
            q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
                .unwrap();
            prev = b.block_hash();
        }
        for h in 2..=20u32 {
            q.block_queue_mark_resolve_complete(h).unwrap();
        }
        // win=12; ready=20 > 6 (fat) but height 1 is path_lo — load is waiting on it.
        let _ = q.block_queue_update_soft_pressure(Some(0.2));
        let st = confirm_bq_resolve_wave(&q, &params, &[1]).unwrap();
        assert_eq!(
            st.heights, 1,
            "unresolved height in the first half of the soft window must emit"
        );
        assert!(q.block_queue_is_resolve_complete(1));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn second_wave_skips_live_union_parent() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let g_cb = genesis.txdata[0].compute_txid();
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
        );
        let b2 = mine_with_txs(
            b1.block_hash(),
            b1.header.time + 600,
            2,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(48_0000_0000))],
        );
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
            .unwrap();
        let mut live = rbitcoin_query::LiveUnion::new();
        let published = rbitcoin_query::PublishedIds::new();
        let st1 =
            confirm_bq_resolve_wave_with_ids(&q, &params, &[1], Some((&mut live, &published)))
                .unwrap();
        assert_eq!(st1.skipped, 0);
        assert!(st1.hits >= 1);
        assert!(published.get(&g_cb.to_byte_array()).is_some());
        let st2 =
            confirm_bq_resolve_wave_with_ids(&q, &params, &[2], Some((&mut live, &published)))
                .unwrap();
        assert!(
            st2.skipped >= 1,
            "second wave must skip genesis parent already in live_union"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn bq_resolve_wave_skips_claimed_height() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let g_cb = genesis.txdata[0].compute_txid();
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
        );
        let b2 = mine_with_txs(
            b1.block_hash(),
            b1.header.time + 600,
            2,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(48_0000_0000))],
        );
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
            .unwrap();
        // Caller skipped height 2 (claimed / inflight) — only resolve 1.
        let st = confirm_bq_resolve_wave(&q, &params, &[1]).unwrap();
        assert_eq!(st.heights, 1);
        assert!(q.block_queue_is_resolve_complete(1));
        assert!(!q.block_queue_is_resolve_complete(2));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn bq_resolve_wave_tiponly_after_disconnect() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        let cb1 = b1.txdata[0].compute_txid();
        let child = mine_with_txs(
            b1.block_hash(),
            b1.header.time + 600,
            2,
            vec![spend_op_true(cb1, 0, Amount::from_sat(49_0000_0000))],
        );
        q.block_queue_enqueue(2, child.block_hash().to_byte_array(), 2, &serialize(&child))
            .unwrap();

        q.disconnect_tip().unwrap();
        assert_eq!(q.tip_height().map(|h| h.0), Some(0));

        let mut live = rbitcoin_query::LiveUnion::new();
        let st = confirm_bq_resolve_wave_with_ids(
            &q,
            &params,
            &[2],
            Some((&mut live, q.published_ids().as_ref())),
        )
        .unwrap();
        assert_eq!(st.heights, 1);
        assert!(
            q.published_ids().get(&cb1.to_byte_array()).is_none(),
            "abandoned-fork coinbase must not be a TipOnly hit (TipThenAny would attach it)"
        );
        assert!(q.block_queue_is_resolve_complete(2));
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Head occupied may already cover the parent fk; prune until the parent
    /// height is confirmed so stamp does not MissingPrevout (931147 / 933474).
    #[test]
    fn stamp_uses_inflight_until_tip_covers_parent_height() {
        use rbitcoin_query::{InFlightLayer, InFlightLog};
        use rbitcoin_store::{OutputRecord, TxRecord};
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let parent_txid = [0x22u8; 32];
        let parent_fk = rbitcoin_primitives::Fk(99);
        let pin = std::sync::Arc::new((
            TxRecord {
                txid: parent_txid,
                version: 1,
                locktime: 0,
                input_start_fk: rbitcoin_primitives::Fk::NULL,
                input_count: 1,
                output_start_fk: rbitcoin_primitives::Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
        let mut log = InFlightLog::new();
        log.note_layer(InFlightLayer::from_plan_pins([(parent_fk, &pin)]).with_max_height(1));
        // Production prune_committed: tip still genesis; occupied already 99.
        log.prune_through_tip(Some(0));
        let view = log.snapshot();
        assert!(
            view.get_create_fk(&parent_txid).is_some(),
            "in-flight must survive drain while parent height is unconfirmed"
        );
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(
                Txid::from_byte_array(parent_txid),
                0,
                Amount::from_sat(49_0000_0000),
            )],
        );
        let pipe = crate::WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start: q.tx_body_count().saturating_add(1).max(1),
            in_flight: view,
            parent_store: std::sync::Arc::new(rbitcoin_query::PipelineParentStore::new()),
            published: std::sync::Arc::new(rbitcoin_query::PublishedIds::new()),
        };
        let items = [(Height(1), std::sync::Arc::new(b1))];
        let stamped =
            crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
                .expect("in-flight parent must stamp until tip covers the parent height");
        let plan = stamped.plan.expect("plan");
        let spend = plan
            .packed
            .iter()
            .find(|(_, ins)| ins.iter().any(|i| !i.is_coinbase()))
            .expect("spend");
        let inp = spend.1.iter().find(|i| !i.is_coinbase()).expect("in");
        assert_eq!(inp.create_fk, parent_fk);
        log.prune_through_tip(Some(1));
        assert!(
            log.snapshot().get_create_fk(&parent_txid).is_none(),
            "confirmed height is leftover TipOnly's job"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Simulated torn publish (`confirmed.set` ahead of the fence). Confirm now
    /// extends before `set_many`; this still pins that prune-on-confirmed-tip
    /// would drop the parent (mainnet 945952 leftover_n=3546 hit=2811).
    #[test]
    fn stamp_uses_inflight_when_confirmed_tip_leads_fence() {
        use rbitcoin_query::{InFlightLayer, InFlightLog};
        use rbitcoin_store::{OutputRecord, TxRecord};
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();

        q.store()
            .confirmed
            .set(Height(1), rbitcoin_primitives::Fk(2))
            .unwrap();
        assert_eq!(q.tip_height(), Some(Height(1)));
        assert_eq!(
            q.fence_tip_height(),
            Some(0),
            "production torn publish: tip leads fence"
        );

        let parent_txid = [0x33u8; 32];
        let parent_fk = rbitcoin_primitives::Fk(99);
        let pin = std::sync::Arc::new((
            TxRecord {
                txid: parent_txid,
                version: 1,
                locktime: 0,
                input_start_fk: rbitcoin_primitives::Fk::NULL,
                input_count: 1,
                output_start_fk: rbitcoin_primitives::Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
        let mut log = InFlightLog::new();
        log.note_layer(InFlightLayer::from_plan_pins([(parent_fk, &pin)]).with_max_height(1));
        let mut dropped = log.clone();
        dropped.prune_through_tip(q.tip_height().map(|h| h.0));
        assert!(
            dropped.snapshot().get_create_fk(&parent_txid).is_none(),
            "prune-on-confirmed-HWM is the 945952 race"
        );
        // Same cutoff production prune_committed must use.
        log.prune_through_tip(q.fence_tip_height());
        assert!(
            log.snapshot().get_create_fk(&parent_txid).is_some(),
            "in-flight stays until the fence covers the pack, not confirmed HWM"
        );
        // Dummy height-1 confirmed row was only to tear tip vs fence; stamp
        // still connects at tip+1 from genesis.
        q.store().confirmed.disconnect_tip(Height(1)).unwrap();
        assert_eq!(q.tip_height(), Some(Height(0)));

        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(
                Txid::from_byte_array(parent_txid),
                0,
                Amount::from_sat(49_0000_0000),
            )],
        );
        let pipe = crate::WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start: q.tx_body_count().saturating_add(1).max(1),
            in_flight: log.snapshot(),
            parent_store: std::sync::Arc::new(rbitcoin_query::PipelineParentStore::new()),
            published: std::sync::Arc::new(rbitcoin_query::PublishedIds::new()),
        };
        let items = [(Height(1), std::sync::Arc::new(b1))];
        let stamped =
            crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
                .expect("in-flight parent must stamp while confirmed tip leads the fence");
        let plan = stamped.plan.expect("plan");
        let spend = plan
            .packed
            .iter()
            .find(|(_, ins)| ins.iter().any(|i| !i.is_coinbase()))
            .expect("spend");
        let inp = spend.1.iter().find(|i| !i.is_coinbase()).expect("in");
        assert_eq!(inp.create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Wave may miss a parent that is already connected in `tx.head`.
    /// Load stamp must TipOnly-head the leftover — not Corrupt-as-invariant.
    #[test]
    fn load_stamp_leftover_parent_via_tiponly_head() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let g_cb = genesis.txdata[0].compute_txid();
        let expect_fk = q
            .store()
            .get_fk_by_txid_tip(&g_cb.to_byte_array())
            .unwrap()
            .expect("genesis coinbase is connected");
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
        );
        let items = [(Height(1), std::sync::Arc::new(b1))];
        let stamped = crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
            .expect("leftover connected parent must TipOnly-head, not invariant");
        let plan = stamped.plan.expect("new body needs a plan");
        let spend = plan
            .packed
            .iter()
            .find(|(_, ins)| ins.iter().any(|i| !i.is_coinbase()))
            .expect("spend tx");
        let inp = spend
            .1
            .iter()
            .find(|i| !i.is_coinbase())
            .expect("spend input");
        assert_eq!(inp.prev_txid, g_cb.to_byte_array());
        assert_eq!(inp.create_fk, expect_fk);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Leftover TipOnly must not resurrect an abandoned (disconnected) Class A row.
    #[test]
    fn load_leftover_disconnected_parent_is_not_tipthenany() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        let cb1 = b1.txdata[0].compute_txid().to_byte_array();
        q.disconnect_tip().unwrap();
        let _ = params;
        let child = TxApply {
            tx: TxRecord {
                txid: [0x22; 32],
                version: 1,
                locktime: 0,
                input_start_fk: rbitcoin_primitives::Fk::NULL,
                input_count: 1,
                output_start_fk: rbitcoin_primitives::Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: cb1,
                create_fk: rbitcoin_primitives::Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need = vec![(rbitcoin_primitives::Fk(1), vec![child])];
        let err = q
            .archive_plan_batch_from_store(
                &mut need,
                1,
                &rbitcoin_query::InFlightView::empty(),
                None,
            )
            .expect_err("disconnected leftover must not TipThenAny-fill");
        let msg = err.to_string();
        assert!(msg.contains("parent create_fk unresolved"), "got: {msg}");
        assert!(
            !msg.contains("invariant: external parent missing BQ TipOnly hit"),
            "leftover miss is unresolved, not the old forbid-head invariant: {msg}"
        );
        let miss = rbitcoin_query::archive_phase_stats::last_union_miss();
        assert_eq!(
            miss.miss_on,
            Some("fence"),
            "disconnected leftover is identity-without-fence, not a head miss: {miss:?}"
        );
        let last = rbitcoin_query::archive_phase_stats::last_plan_batch();
        assert!(
            last.head_need > 0,
            "fail pack leftover_n must be metered before stamp: {last:?}"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn bq_wave_then_stamp_confirms_empty_block() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        confirm_bq_resolve_wave(&q, &params, &[1]).unwrap();
        assert!(q.block_queue_is_resolve_complete(1));
        let items = [(Height(1), std::sync::Arc::new(b1))];
        let stamped = crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
            .expect("coinbase-only block needs no external head");
        let mat = crate::confirm_wire_load_from_plan(
            &q,
            &params,
            Milestone::NONE,
            stamped,
            None,
            &ScriptPreverified::new(),
        )
        .expect("load");
        let ok = crate::confirm_scripts_phase(mat.batch).expect("scripts");
        crate::confirm_write_phase(&q, &params, Milestone::NONE, ok.batch).expect("write");
        assert_eq!(q.tip_height().map(|h| h.0), Some(1));
        let _ = std::fs::remove_dir_all(&path);
    }
}
