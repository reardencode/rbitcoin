//! BQ-ahead TipOnly parent resolve (lookup wave).
//!
//! Pack/hold uses enqueue-stamped Σ inputs (no `Block` decode). Emit runs one
//! [`Store::get_fk_by_txid_batch`] (TipOnly) across the selected heights
//! (soft **64000** inputs / hard **1080** blocks). Hits ride the wave as
//! [`rbitcoin_query::BatchParentIds`] (fk + body_range + spent_range). Does not
//! claim, structure, or stamp. Same-wave creates are omitted from TipOnly need.

use super::*;
use crate::milestone::Milestone;
use bitcoin::consensus::Decodable;
use rbitcoin_query::{
    BatchParentIds, IdMap, ResolvedWire, TxPrecompute, TxidHasher, U32Map, U64Map,
};
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use std::io::Cursor;
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
/// Hard min Σ `tx.input` per lookup wave (same number as load's pack).
///
/// Hold a thinner collect when more unresolved BQ heights can still join —
/// including `ready=0` / load-frontier / unknown window. Last available
/// thin wave still emits (tip / empty BQ).
pub const BQ_RESOLVE_WAVE_MIN_INPUTS: u32 = 8000;
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

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Hold a short wave while the BQ is fat so lookup does not mint one layer
/// per newly fetched block.
///
/// `ready` is BQ depth. `soft_win` is the 1-min confirm window (`bq soft=n/win`).
/// `path_lo` is the load frontier (store tip+1). `first_unresolved` is the
/// lowest collected height (already sorted by [`BlockQueue::unresolved_heights`]).
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
    /// `TxPrecompute::from_tx` / `from_tx_connect` after decode (this wave).
    pub precompute_ns: u64,
    /// `push_resolve_keys` (this wave).
    pub collect_ns: u64,
    /// TipOnly `get_fk_by_txid_batch` + slot sort (this wave).
    pub head_ns: u64,
    /// `tx_spent_range_batch` for TipOnly hits (this wave).
    pub spent_ns: u64,
}

/// Push external prev_txids (+ pre-BIP34 create txids) into the wave set.
fn push_resolve_keys(
    params: &ChainParams,
    height: u32,
    block: &Block,
    pres: &[TxPrecompute],
    skip: &HashSet<[u8; 32], BuildHasherDefault<TxidHasher>>,
    keys: &mut HashSet<[u8; 32], BuildHasherDefault<TxidHasher>>,
) {
    let bip34 = params.bip34_active_at(height);
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        for inp in &tx.input {
            if inp.previous_output.is_null() {
                continue;
            }
            let prev = inp.previous_output.txid.to_byte_array();
            if prev == [0u8; 32] || skip.contains(&prev) {
                continue;
            }
            keys.insert(prev);
        }
        if !bip34 && !skip.contains(&p.txid) {
            keys.insert(p.txid);
        }
    }
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
/// `max_blocks` / `max_inputs` cap emit (remaining loadq).
pub fn confirm_bq_resolve_wave_capped(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    heights: &[u32],
    max_blocks: usize,
    max_inputs: u32,
) -> Result<BqResolveWave, ConsensusError> {
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
    let raw_h: HashSet<u32> = intake
        .raw
        .into_iter()
        .map(|(h, n, fk)| {
            n_inputs_at.insert(h, n);
            header_fk_at.insert(h, fk);
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
        let filling = win >= 144 && (query.block_queue_count() as u32) < win;
        let more_remain = selected.len() < heights.len() || filling;
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
            });
        }
    }

    for &h in &selected {
        if all_keys.len() >= BQ_RESOLVE_WAVE_MAX_KEYS && !done.is_empty() {
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
            let Some(block) = decode_bq_block(&payload) else {
                continue;
            };
            stats.decode_ns = stats
                .decode_ns
                .saturating_add(t_dec.elapsed().as_nanos() as u64);
            let t_pre = Instant::now();
            let pres: Vec<TxPrecompute> = if milestone.skips_scripts_at(h) {
                block
                    .txdata
                    .iter()
                    .map(TxPrecompute::from_tx_connect)
                    .collect()
            } else {
                block.txdata.iter().map(TxPrecompute::from_tx).collect()
            };
            stats.precompute_ns = stats
                .precompute_ns
                .saturating_add(t_pre.elapsed().as_nanos() as u64);
            let pres = Arc::<[TxPrecompute]>::from(pres);
            let block = Arc::new(block);
            wires.push((
                h,
                hash,
                ResolvedWire {
                    block: Arc::clone(&block),
                    pres: Arc::clone(&pres),
                    n_inputs: n_inputs_at.get(&h).copied().unwrap_or(0),
                    header_fk: header_fk_at.get(&h).copied().unwrap_or(0),
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
        push_resolve_keys(
            params,
            h,
            block.as_ref(),
            pres.as_ref(),
            &wave_creates,
            &mut all_keys,
        );
        stats.collect_ns = stats
            .collect_ns
            .saturating_add(t_col.elapsed().as_nanos() as u64);
        done.push(h);
    }

    stats.keys = all_keys.len() as u32;
    let mut layer = IdMap::default();
    let mut need: Vec<[u8; 32]> = all_keys.into_iter().collect();
    let t_head = Instant::now();
    need.sort_by_cached_key(|txid| query.store().txs.head_primary_slot(txid));

    let drain_fence_hi = query.drain_and_fence_hi();
    if let Some(&hi) = selected.last() {
        query.note_lookup_tiponly_start(hi);
    }

    if !need.is_empty() {
        let rows = query
            .store()
            .get_fk_by_txid_batch(&need)
            .map_err(ConsensusError::from)?;
        for (txid, row) in rows {
            if let Some((fk, range)) = row {
                layer.insert(txid, (fk, range));
            }
        }
    }
    stats.head_ns = t_head.elapsed().as_nanos() as u64;
    stats.hits = layer.len() as u32;

    let t_spent = Instant::now();
    let hit_fks: Vec<rbitcoin_primitives::Fk> = layer.values().map(|(fk, _)| *fk).collect();
    let mut spent = U64Map::default();
    if !hit_fks.is_empty() {
        let rows = query
            .store()
            .tx_spent_range_batch(&hit_fks)
            .map_err(ConsensusError::from)?;
        for (fk, row) in hit_fks.iter().zip(rows) {
            if let (Some(id), Some(sr)) = (fk.get(), row) {
                spent.insert(id, sr);
            }
        }
    }
    stats.spent_ns = t_spent.elapsed().as_nanos() as u64;
    let parent_ids = BatchParentIds {
        ids: Arc::new(layer),
        spent: Arc::new(spent),
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
            .map_err(ConsensusError::from)?;
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
    })
}

/// Dequeue BQ rows and bump `lookup_taken_hi` after a successful loadq send.
pub fn take_wave_items_for_load(
    query: &Query,
    items: &[(u32, [u8; 32], ResolvedWire)],
) -> Result<(), ConsensusError> {
    for (h, _, _) in items {
        query
            .block_queue_dequeue_height(*h)
            .map_err(ConsensusError::from)?;
        query.set_lookup_taken_hi(Some(*h));
    }
    Ok(())
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
    fn tmp_query() -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled("bq-resolve")
    }

    fn take_emitted(q: &Query, wave: &BqResolveWave) {
        take_wave_items_for_load(q, &wave.items).unwrap();
    }

    fn resolve_wave(
        q: &Query,
        params: &ChainParams,
        milestone: Milestone,
        heights: &[u32],
    ) -> BqResolveWave {
        confirm_bq_resolve_wave_capped(
            q,
            params,
            milestone,
            heights,
            BQ_RESOLVE_WAVE_MAX_BLOCKS,
            BQ_RESOLVE_WAVE_MAX_INPUTS,
        )
        .unwrap()
    }

    fn resolve_and_take(q: &Query, params: &ChainParams, heights: &[u32]) -> BqResolveWaveStats {
        let wave = resolve_wave(q, params, Milestone::NONE, heights);
        take_emitted(q, &wave);
        wave.stats
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
    fn wire_input_count_matches_serialized_block() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let n: u32 = genesis
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        assert_eq!(
            rbitcoin_store::block_wire_input_count(&serialize(&genesis)),
            n
        );
        let g_cb = genesis.txdata[0].compute_txid();
        let b1 = mine_with_txs(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            vec![spend_op_true(g_cb, 0, Amount::from_sat(49_0000_0000))],
        );
        let n1: u32 = b1
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        assert_eq!(rbitcoin_store::block_wire_input_count(&serialize(&b1)), n1);
        assert!(n1 >= 2, "coinbase + spend");
    }

    #[test]
    fn push_resolve_keys_dedups_same_prev_txid() {
        let params = ChainParams::regtest();
        let prev = Txid::from_byte_array([0x11u8; 32]);
        let spend = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: prev,
                        vout: 1,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let height = params.btc.bip34_height;
        let block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: 0,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx(height), spend],
        };
        let pres: Vec<TxPrecompute> = block.txdata.iter().map(TxPrecompute::from_tx).collect();
        let mut keys: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>> =
            HashSet::with_hasher(BuildHasherDefault::default());
        let skip = HashSet::with_hasher(BuildHasherDefault::default());
        push_resolve_keys(&params, height, &block, &pres, &skip, &mut keys);
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&prev.to_byte_array()));
    }

    #[test]
    fn same_wave_create_is_not_tiponly_need() {
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
        let h1_create = b1.txdata[1].compute_txid();
        let b2 = mine_with_txs(
            b1.block_hash(),
            b1.header.time + 600,
            2,
            vec![spend_op_true(h1_create, 0, Amount::from_sat(48_0000_0000))],
        );
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        q.block_queue_enqueue(2, b2.block_hash().to_byte_array(), 2, &serialize(&b2))
            .unwrap();
        let wave = resolve_wave(&q, &params, Milestone::NONE, &[1, 2]);
        assert_eq!(wave.items.len(), 2);
        assert_eq!(
            wave.stats.keys, 1,
            "same-wave h=1 create must not be TipOnly need; archived genesis still is"
        );
        assert!(
            wave.stats.hits >= 1,
            "archived genesis parent must still TipOnly-hit"
        );
        let _ = std::fs::remove_dir_all(&path);
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

        let wave = resolve_wave(&q, &params, Milestone::NONE, &[1, 2]);
        let st = wave.stats;
        assert_eq!(st.heights, 2);
        assert_eq!(wave.items.len(), 2);
        assert!(st.keys >= 1);
        assert!(st.hits >= 1);
        assert!(
            st.decode_ns > 0 && st.precompute_ns > 0 && st.collect_ns > 0 && st.head_ns > 0,
            "raw-payload wave must meter decode=/precompute=/collect=/head= (decode={} pre={} collect={} head={})",
            st.decode_ns,
            st.precompute_ns,
            st.collect_ns,
            st.head_ns
        );
        let g = g_cb.to_byte_array();
        let (fk, _body, spent) = wave
            .parent_ids
            .get(&g)
            .expect("genesis coinbase must be a TipOnly skeleton hit");
        assert!(!fk.is_null());
        assert!(
            spent.is_some(),
            "archived parent must carry spent.idx on the skeleton"
        );
        take_emitted(&q, &wave);
        assert!(!q.block_queue_has_height(1));
        assert!(!q.block_queue_has_height(2));
        let spend_pre = &wave.items[0].2.pres[1];
        assert!(
            spend_pre.sha_prevouts.is_some(),
            "Milestone::NONE must from_tx (sighash midstates present)"
        );
        assert_eq!(spend_pre.txid, b1.txdata[1].compute_txid().to_byte_array());
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn bq_resolve_wave_connect_precompute_omits_midstates() {
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
        let expect_txid = TxPrecompute::from_tx(&b1.txdata[1]).txid;
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        let wave = resolve_wave(&q, &params, Milestone { height: 100 }, &[1]);
        assert_eq!(wave.items.len(), 1);
        let spend_pre = &wave.items[0].2.pres[1];
        assert_eq!(spend_pre.txid, expect_txid);
        assert_eq!(spend_pre.sha_prevouts, None);
        assert_eq!(spend_pre.sha_sequences, None);
        assert_eq!(spend_pre.sha_outputs, None);
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
        let wave = resolve_wave(&q, &params, Milestone::NONE, &heights);
        assert_eq!(
            wave.stats.heights, 9,
            "lookup wave must outgrow the old 8-height cap (soft 64000 inputs / hard 1080 blocks)"
        );
        take_emitted(&q, &wave);
        assert!(
            !q.block_queue_has_height(1),
            "take after send dequeues the BQ row"
        );
        assert!(q.block_queue_resolved(1).is_none());
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn resolve_wave_pack_limits_are_4x_load_class() {
        assert_eq!(BQ_RESOLVE_WAVE_MAX_BLOCKS, 1080);
        assert_eq!(BQ_RESOLVE_WAVE_MAX_INPUTS, 64_000);
        assert_eq!(BQ_RESOLVE_WAVE_MIN_INPUTS, 8000);
        assert_eq!(BQ_RESOLVE_WAVE_MAX_KEYS, 256_000);
        const {
            assert!(BQ_RESOLVE_WAVE_MAX_BLOCKS >= 144 * 4);
            assert!(BQ_RESOLVE_WAVE_MAX_INPUTS >= BQ_RESOLVE_WAVE_MIN_INPUTS * 8);
        }
        // Include-overshoot: take the crossing block, then stop.
        assert!(!bq_resolve_wave_stop_after(63_900, 1, 64_000, 1080));
        assert!(bq_resolve_wave_stop_after(64_100, 2, 64_000, 1080));
        assert!(bq_resolve_wave_stop_after(1, 1080, 64_000, 1080));
        assert!(!bq_resolve_wave_stop_after(64_000, 1079, 64_000, 1080));
    }

    #[test]
    fn hold_partial_table() {
        const MAX_IN: u32 = BQ_RESOLVE_WAVE_MAX_INPUTS;
        const MAX_BL: usize = BQ_RESOLVE_WAVE_MAX_BLOCKS;
        // far unresolved (beyond first half of win) + fat + short → hold
        assert!(bq_resolve_wave_hold_partial(
            330, 180, 4_000, 1, 100, 191, false, MAX_IN, MAX_BL
        ));
        // above min, gap in the first half of the window → emit (load needs it)
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 9_000, 2, 100, 190, true, MAX_IN, MAX_BL
        ));
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 9_000, 2, 100, 100, true, MAX_IN, MAX_BL
        ));
        // fat BQ + full input wave → emit
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 64_100, 16, 100, 250, true, MAX_IN, MAX_BL
        ));
        // fat BQ + full block cap → emit
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 1, 1080, 100, 250, true, MAX_IN, MAX_BL
        ));
        // thin BQ + short wave, nothing more to join → emit
        assert!(!bq_resolve_wave_hold_partial(
            50, 180, 4_000, 1, 100, 250, false, MAX_IN, MAX_BL
        ));
        // rate unknown (win=0), nothing more to join → emit
        assert!(!bq_resolve_wave_hold_partial(
            330, 0, 4_000, 1, 100, 250, false, MAX_IN, MAX_BL
        ));
        // nothing collected
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 0, 0, 100, 100, true, MAX_IN, MAX_BL
        ));
        // Hard min 8000: hold a thin *far* layer when more BQ heights can
        // still join. A single block at the load frontier (tip+1) must emit.
        assert!(
            bq_resolve_wave_hold_partial(0, 180, 4_000, 1, 100, 150, true, MAX_IN, MAX_BL),
            "ready=0 must still hold a far <8000-input layer when more remain"
        );
        assert!(
            !bq_resolve_wave_hold_partial(330, 180, 4_000, 1, 100, 100, true, MAX_IN, MAX_BL),
            "one tip+1 block must emit even under the 8000-input floor"
        );
        assert!(
            bq_resolve_wave_hold_partial(0, 0, 4_000, 1, 100, 150, true, MAX_IN, MAX_BL),
            "unknown window must still hold a far <8000 layer when more remain"
        );
        assert!(
            !bq_resolve_wave_hold_partial(0, 180, 4_000, 1, 100, 100, false, MAX_IN, MAX_BL),
            "last available thin wave must emit (tip / empty BQ)"
        );
        assert!(!bq_resolve_wave_hold_partial(
            0, 180, 8_000, 2, 100, 100, true, MAX_IN, MAX_BL
        ));
        // remaining-loadq cap counts as at_max so a packed remaining=1 wave emits
        assert!(!bq_resolve_wave_hold_partial(
            330, 180, 8_001, 2, 100, 250, true, 8_000, 144
        ));
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
        let _ = q.block_queue_take_raw_clone_n();
        let st = resolve_wave(&q, &params, Milestone::NONE, &[8]).stats;
        assert_eq!(st.heights, 0, "fat BQ must not mint a 1-block layer");
        assert_eq!(
            st.decode_ns, 0,
            "hold must not consensus_decode; n_inputs is stamped at enqueue"
        );
        assert_eq!(st.precompute_ns, 0, "hold must not TxPrecompute::from_tx");
        assert_eq!(
            q.block_queue_take_raw_clone_n(),
            0,
            "hold must not clone raw payload"
        );
        assert!(!q.block_queue_is_resolve_complete(8));
        assert!(
            q.block_queue_has_height(8),
            "hold leaves raw on BQ until the wave emits"
        );
        assert!(q.block_queue_raw_payload(8).unwrap().is_some());
        assert!(q.block_queue_resolved(8).is_none());

        let _ = q.block_queue_update_soft_pressure(None);
        let st = resolve_and_take(&q, &params, &[8]);
        assert_eq!(st.heights, 1, "unknown window must allow a short wave");
        assert!(!q.block_queue_has_height(8));
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
        let st = resolve_and_take(&q, &params, &[1]);
        assert_eq!(
            st.heights, 1,
            "unresolved height in the first half of the soft window must emit"
        );
        assert!(!q.block_queue_has_height(1));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn tip_block_emits_under_min_inputs_while_bq_filling() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let mut prev = genesis.block_hash();
        let mut time = genesis.header.time;
        for h in 1..=10u32 {
            time += 600;
            let b = mine_empty_regtest(prev, time, h);
            q.block_queue_enqueue(h, b.block_hash().to_byte_array(), 1, &serialize(&b))
                .unwrap();
            prev = b.block_hash();
        }
        // IBD-sized window, BQ still filling (10 < 180). Height 1 is tip+1.
        let _ = q.block_queue_update_soft_pressure(Some(3.0));
        let all: Vec<u32> = (1..=10).collect();
        let st = resolve_and_take(&q, &params, &all);
        assert_eq!(
            st.heights, 10,
            "tip+1 must emit even under 8000 inputs while the BQ is filling"
        );
        assert!(!q.block_queue_has_height(1));
        assert!(!q.block_queue_has_height(10));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn far_thin_wave_holds_under_min_inputs_when_more_remain() {
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
        for h in 1..=10u32 {
            q.block_queue_mark_resolve_complete(h).unwrap();
        }
        let _ = q.block_queue_update_soft_pressure(Some(3.0));
        let _ = q.block_queue_take_raw_clone_n();
        let st = resolve_wave(&q, &params, Milestone::NONE, &[15]).stats;
        assert_eq!(
            st.heights, 0,
            "a far 1-block layer must hold under 8000 inputs while more remain"
        );
        assert_eq!(st.decode_ns, 0);
        assert_eq!(st.precompute_ns, 0);
        assert_eq!(q.block_queue_take_raw_clone_n(), 0);
        assert!(q.block_queue_has_height(15));
        assert!(
            q.lookup_started_hi().is_none(),
            "hold_partial must not bump started_hi; got {:?}",
            q.lookup_started_hi()
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn second_wave_tiponly_archived_parent_again() {
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
        let w1 = resolve_wave(&q, &params, Milestone::NONE, &[1]);
        assert!(w1.stats.hits >= 1);
        assert!(w1.parent_ids.get(&g_cb.to_byte_array()).is_some());
        take_emitted(&q, &w1);
        let w2 = resolve_wave(&q, &params, Milestone::NONE, &[2]);
        assert!(
            w2.stats.keys >= 1 && w2.stats.hits >= 1,
            "second wave still TipOnlys the archived genesis parent (no live_union skip)"
        );
        assert!(w2.parent_ids.get(&g_cb.to_byte_array()).is_some());
        let _ = std::fs::remove_dir_all(&path);
    }

    /// After a lookup wave publishes parent P, load stamp of a child spending P
    /// must not TipOnly-head P again (`HEAD_NEED=0`). Occupancy go/no-go for
    /// moving `plan_batch` onto lookup: leftover-0 means pack on load is fine.
    #[test]
    fn load_stamp_after_wave_has_zero_leftover_head() {
        use rbitcoin_primitives::Height;
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
        q.block_queue_enqueue(1, b1.block_hash().to_byte_array(), 1, &serialize(&b1))
            .unwrap();
        let wave = resolve_wave(&q, &params, Milestone::NONE, &[1]);
        assert!(wave.stats.hits >= 1);
        let g = g_cb.to_byte_array();
        assert!(
            wave.parent_ids.get(&g).is_some(),
            "wave skeleton must carry the archived genesis parent"
        );
        let ext = rbitcoin_query::stamp_external_parents(
            q.store(),
            &[g],
            &rbitcoin_query::InFlight::new(),
            Some(&wave.parent_ids),
            q.confirm_stats(),
        )
        .expect("stamp helper after wave");
        assert_eq!(
            ext.head_need_n, 0,
            "skeleton path must not leftover-probe tx.head"
        );
        let inflight = rbitcoin_query::InFlight::new();
        let pipe = crate::WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start: q.tx_body_count().saturating_add(1).max(1),
            in_flight: &inflight,
            skeleton: Some(wave.parent_ids.clone()),
        };
        let items = [(Height(1), std::sync::Arc::new(b1), None)];
        let stamped =
            crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
                .expect("stamp after wave");
        let plan = stamped.plan.expect("new body needs a plan");
        let inp = plan
            .edges
            .values()
            .flatten()
            .find(|e| e.vout != u32::MAX)
            .expect("spend");
        assert_eq!(inp.prev_txid, g_cb.to_byte_array());
        assert!(!inp.create_fk.is_null());
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
        let st = resolve_and_take(&q, &params, &[1]);
        assert_eq!(st.heights, 1);
        assert!(!q.block_queue_has_height(1), "emitted height is dequeued");
        assert!(q.block_queue_has_height(2));
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

        let wave = resolve_wave(&q, &params, Milestone::NONE, &[2]);
        assert_eq!(wave.stats.heights, 1);
        take_emitted(&q, &wave);
        assert!(
            wave.parent_ids.get(&cb1.to_byte_array()).is_none(),
            "abandoned-fork coinbase must not be a TipOnly hit (TipThenAny would attach it)"
        );
        assert!(!q.block_queue_has_height(2));
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Head occupied may already cover the parent fk; prune until the parent
    /// height is confirmed so stamp does not MissingPrevout (931147 / 933474).
    #[test]
    fn stamp_uses_inflight_until_tip_covers_parent_height() {
        use rbitcoin_query::InFlight;
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
        let mut log = InFlight::new();
        log.note_pins([(parent_fk, &pin)], Some(1));
        // Production: a wave that snapshotted drain+fence at genesis keeps height 1.
        log.prune_below_height(Some(0));
        assert!(
            log.get_create_fk(&parent_txid).is_some(),
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
        let stamped = {
            let pipe = crate::WireLoadPipeline {
                path_lo: 1,
                parent_hash: None,
                next_tx_start: q.tx_body_count().saturating_add(1).max(1),
                in_flight: &log,
                skeleton: None,
            };
            let items = [(Height(1), std::sync::Arc::new(b1), None)];
            crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
                .expect("in-flight parent must stamp until tip covers the parent height")
        };
        let plan = stamped.plan.expect("plan");
        let inp = plan
            .edges
            .values()
            .flatten()
            .find(|e| e.vout != u32::MAX)
            .expect("spend");
        assert_eq!(inp.create_fk, parent_fk);
        log.prune_below_height(Some(2));
        assert!(
            log.get_create_fk(&parent_txid).is_none(),
            "after a later wave snapshots drain+fence past the pack, TipOnly owns it"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Simulated torn publish (`confirmed.set` ahead of the fence). Confirm now
    /// extends before `set_many`; this still pins that prune-on-confirmed-tip
    /// would drop the parent (mainnet 945952 leftover_n=3546 hit=2811).
    #[test]
    fn stamp_uses_inflight_when_confirmed_tip_leads_fence() {
        use rbitcoin_query::InFlight;
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
        let mut log = InFlight::new();
        log.note_pins([(parent_fk, &pin)], Some(1));
        log.prune_below_height(q.drain_and_fence_hi());
        assert!(
            log.get_create_fk(&parent_txid).is_some(),
            "in-flight stays until a wave snapshots drain+fence covering the pack, not confirmed HWM"
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
        let stamped = {
            let pipe = crate::WireLoadPipeline {
                path_lo: 1,
                parent_hash: None,
                next_tx_start: q.tx_body_count().saturating_add(1).max(1),
                in_flight: &log,
                skeleton: None,
            };
            let items = [(Height(1), std::sync::Arc::new(b1), None)];
            crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
                .expect("in-flight parent must stamp while confirmed tip leads the fence")
        };
        let plan = stamped.plan.expect("plan");
        let inp = plan
            .edges
            .values()
            .flatten()
            .find(|e| e.vout != u32::MAX)
            .expect("spend");
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
        let items = [(Height(1), std::sync::Arc::new(b1), None)];
        let stamped = crate::confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
            .expect("leftover connected parent must TipOnly-head, not invariant");
        let plan = stamped.plan.expect("new body needs a plan");
        let inp = plan
            .edges
            .values()
            .flatten()
            .find(|e| e.vout != u32::MAX)
            .expect("spend tx");
        assert_eq!(inp.prev_txid, g_cb.to_byte_array());
        assert_eq!(inp.create_fk, expect_fk);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Leftover TipOnly must not resurrect an abandoned (disconnected) Class A row.
    #[test]
    fn load_leftover_disconnected_parent_is_not_tipthenany() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        let cb1 = b1.txdata[0].compute_txid();
        q.disconnect_tip().unwrap();
        let _ = params;
        let child = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint { txid: cb1, vout: 0 },
                script_sig: bitcoin::script::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::script::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txids = vec![child.compute_txid().to_byte_array()];
        let block = bitcoin::Block {
            header: b1.header,
            txdata: vec![child],
        };
        let err = q
            .archive_plan_batch_from_wire(
                &[(rbitcoin_primitives::Fk(1), &block, txids.as_slice())],
                1,
                &rbitcoin_query::InFlight::new(),
                None,
            )
            .expect_err("disconnected leftover must not TipThenAny-fill");
        let msg = err.to_string();
        assert!(msg.contains("parent create_fk unresolved"), "got: {msg}");
        assert!(
            !msg.contains("invariant: external parent missing BQ TipOnly hit"),
            "leftover miss is unresolved, not the old forbid-head invariant: {msg}"
        );
        // Do not read process-global last_union_miss / last_plan_batch here:
        // cargo test --workspace races those atomics (CI flake on #130).
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
        resolve_and_take(&q, &params, &[1]);
        assert!(!q.block_queue_has_height(1));
        let items = [(Height(1), std::sync::Arc::new(b1), None)];
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

    #[test]
    fn taken_hi_tracks_sent_load_batches_not_unsent_wave() {
        let (path, q) = tmp_query();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let mut prev = genesis.block_hash();
        let mut time = genesis.header.time;
        let mut heights = Vec::new();
        for h in 1..=4u32 {
            time += 600;
            let b = mine_empty_regtest(prev, time, h);
            prev = b.block_hash();
            q.block_queue_enqueue(h, prev.to_byte_array(), 1, &serialize(&b))
                .unwrap();
            heights.push(h);
        }
        let df_before = q.drain_and_fence_hi();
        let wave = resolve_wave(&q, &params, Milestone::NONE, &heights);
        assert_eq!(wave.items.len(), 4);
        assert_eq!(
            wave.drain_fence_hi, df_before,
            "wave must snapshot drain+fence before TipOnly"
        );
        assert!(
            q.lookup_taken_hi().is_none(),
            "resolve must not bump taken_hi before load-batch send; got {:?}",
            q.lookup_taken_hi()
        );
        assert_eq!(
            q.lookup_started_hi(),
            Some(4),
            "resolve wave must bump started_hi at start of TipOnly"
        );
        assert!(
            q.block_queue_has_height(4),
            "unsent wave tail must stay on the BQ"
        );
        assert!(
            q.block_queue_resolved(4).is_some(),
            "unsent tail is parked decoded (no re-decode)"
        );
        q.block_queue_dequeue_height(1).unwrap();
        q.set_lookup_taken_hi(Some(1));
        assert_eq!(q.lookup_taken_hi(), Some(1));
        assert_eq!(
            q.lookup_started_hi(),
            Some(4),
            "take must not rewind started_hi"
        );
        assert!(!q.block_queue_has_height(1));
        assert!(q.block_queue_has_height(4));
        let _ = std::fs::remove_dir_all(&path);
    }
}
