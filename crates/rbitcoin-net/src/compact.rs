//! BIP152 compact block reconstruction from mempool short-ids.
//!
//! Version 2 (witness) short-ids are preferred; callers pass a short-id map
//! built from live mempool (and optional extra txs). On incomplete fill,
//! returns missing absolute indexes for `getblocktxn`.

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::{Block, BlockHash, Transaction, Wtxid};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Build siphash short-id → transaction map for compact fill (version 1 = txid, 2 = wtxid).
pub fn shortid_map_from_txs<'a>(
    header: &Header,
    nonce: u64,
    version: u32,
    txs: impl IntoIterator<Item = &'a Transaction>,
) -> HashMap<ShortId, Vec<&'a Transaction>> {
    let keys = ShortId::calculate_siphash_keys(header, nonce);
    let mut map: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
    for tx in txs {
        let id = short_id_for_tx(tx, version, keys);
        map.entry(id).or_default().push(tx);
    }
    map
}

#[doc(hidden)]
pub fn short_id_for_tx(tx: &Transaction, version: u32, keys: (u64, u64)) -> ShortId {
    match version {
        1 => ShortId::with_siphash_keys(&tx.compute_txid().to_raw_hash(), keys),
        _ => ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys),
    }
}

/// Consensus-decode BIP152 `HeaderAndShortIds`.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn decode_cmpct_hsi(raw: &[u8]) -> Option<HeaderAndShortIds> {
    bitcoin::consensus::encode::deserialize(raw).ok()
}

/// Core v2 frame after we send `cmpctblock`.
#[derive(Debug, PartialEq, Eq)]
pub enum CmpctPeerFrame {
    GetBlockTxn(Vec<u64>),
    Ping(u64),
    Pong(u64),
    Other,
}

/// Classify decrypted application contents (regtest magic).
pub fn classify_v2_cmpct_peer(contents: &[u8]) -> CmpctPeerFrame {
    match crate::v2::parse_v2_contents(Magic::REGTEST, contents) {
        Ok(frame) => match frame.decode().payload() {
            NetworkMessage::GetBlockTxn(r) => {
                CmpctPeerFrame::GetBlockTxn(r.txs_request.indexes.clone())
            }
            NetworkMessage::Ping(n) => CmpctPeerFrame::Ping(*n),
            NetworkMessage::Pong(n) => CmpctPeerFrame::Pong(*n),
            _ => CmpctPeerFrame::Other,
        },
        Err(_) => CmpctPeerFrame::Other,
    }
}

/// Header hashes from a decrypted `headers` payload. Other messages are `None`.
pub fn v2_header_hashes(contents: &[u8]) -> Option<Vec<BlockHash>> {
    let frame = crate::v2::parse_v2_contents(Magic::REGTEST, contents).ok()?;
    match frame.decode().payload() {
        NetworkMessage::Headers(headers) => Some(headers.iter().map(|h| h.block_hash()).collect()),
        _ => None,
    }
}

/// Core `PartiallyDownloadedBlock::InitData` shape. A failure is a malformed
/// `cmpctblock`: no txs, more than [`rbitcoin_consensus::MAX_BLOCK_TX_COUNT`],
/// or a prefilled index that is out of range, not increasing, or past 16 bits.
pub fn cmpct_init_data_ok(hsi: &HeaderAndShortIds) -> bool {
    let total = hsi.short_ids.len().saturating_add(hsi.prefilled_txs.len());
    if total == 0 || total > rbitcoin_consensus::MAX_BLOCK_TX_COUNT {
        return false;
    }
    let mut last: Option<usize> = None;
    for (abs, _) in prefilled_absolute_indexes(hsi) {
        if abs >= total || abs > usize::from(u16::MAX) {
            return false;
        }
        if last.is_some_and(|p| abs <= p) {
            return false;
        }
        last = Some(abs);
    }
    true
}

/// Absolute block indexes of prefilled txs (decode differential encoding).
pub fn prefilled_absolute_indexes(hsi: &HeaderAndShortIds) -> Vec<(usize, &Transaction)> {
    let mut out = Vec::with_capacity(hsi.prefilled_txs.len());
    let mut abs: usize = 0;
    for p in &hsi.prefilled_txs {
        abs = abs.saturating_add(p.idx as usize);
        out.push((abs, &p.tx));
        abs = abs.saturating_add(1);
    }
    out
}

/// First-pass compact fill still waiting on `blocktxn` for `missing` slots.
///
/// Matched mempool / extra / orphan bodies are owned here. Apply overlays
/// the peer response onto those holes and must not re-walk a live short-id
/// map (a later `try_read` miss or eviction would drop first-pass hits).
#[derive(Clone, Debug)]
pub struct CmpctPartial {
    pub slots: Vec<Option<Transaction>>,
    pub missing: Vec<u64>,
}

impl CmpctPartial {
    pub fn missing(&self) -> &[u64] {
        &self.missing
    }
}

#[derive(Debug)]
pub enum Reconstruct {
    Block(Block),
    Partial(CmpctPartial),
    Fail,
}

/// Attempt to reconstruct a full block from compact data + available txs.
///
/// On success the txs merkle to `hsi.header`. Incomplete fill returns the
/// remaining absolute indexes (`getblocktxn`). A complete fill that does not
/// merkle (wrong unique short-id body) returns an empty vec (`getdata`).
pub fn try_reconstruct<T: Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    available: &HashMap<ShortId, Vec<T>>,
) -> Result<Block, Vec<u64>> {
    match reconstruct(hsi, available) {
        Reconstruct::Block(b) => Ok(b),
        Reconstruct::Partial(p) => Err(p.missing),
        Reconstruct::Fail => Err(Vec::new()),
    }
}

pub fn reconstruct<T: Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    available: &HashMap<ShortId, Vec<T>>,
) -> Reconstruct {
    if !cmpct_init_data_ok(hsi) {
        return Reconstruct::Fail;
    }
    let total = hsi.short_ids.len() + hsi.prefilled_txs.len();

    let mut slots: Vec<Option<Transaction>> = vec![None; total];
    let mut prefilled_set = std::collections::HashSet::new();
    let mut placed: std::collections::HashSet<bitcoin::Txid> = std::collections::HashSet::new();
    for (abs, tx) in prefilled_absolute_indexes(hsi) {
        placed.insert(tx.compute_txid());
        slots[abs] = Some(tx.clone());
        prefilled_set.insert(abs);
    }

    let mut short_i = 0usize;
    let mut missing = Vec::new();
    for (abs, slot) in slots.iter_mut().enumerate() {
        if prefilled_set.contains(&abs) {
            continue;
        }
        if short_i >= hsi.short_ids.len() {
            missing.push(abs as u64);
            continue;
        }
        let sid = hsi.short_ids[short_i];
        short_i += 1;
        match available.get(&sid) {
            Some(cands) if cands.len() == 1 => {
                let txid = cands[0].borrow().compute_txid();
                // Repeat short-id / same candidate in two slots → duplicate
                // txid block. Mark missing so getblocktxn / getdata can recover.
                if !placed.insert(txid) {
                    missing.push(abs as u64);
                    continue;
                }
                *slot = Some(cands[0].borrow().clone());
            }
            // One candidate fills the slot. Every other count, including a
            // short-id collision, is missing for getblocktxn.
            _ => missing.push(abs as u64),
        }
    }

    if !missing.is_empty() {
        return Reconstruct::Partial(CmpctPartial { slots, missing });
    }

    let mut txdata = Vec::with_capacity(total);
    for slot in slots {
        match slot {
            Some(tx) => txdata.push(tx),
            None => return Reconstruct::Fail,
        }
    }

    match finish_reconstructed(hsi.header, txdata) {
        Ok(block) => Reconstruct::Block(block),
        Err(_) => Reconstruct::Fail,
    }
}

/// Build a `getblocktxn` request for missing absolute indexes.
pub fn missing_request(block_hash: BlockHash, missing: &[u64]) -> BlockTransactionsRequest {
    BlockTransactionsRequest {
        block_hash,
        indexes: missing.to_vec(),
    }
}

/// Overlay `blocktxn` onto a first-pass [`CmpctPartial`].
///
/// `txn.transactions` is 1:1 with `partial.missing` (absolute indexes, request
/// order). Already-filled slots are kept; the live short-id map is not consulted.
/// Completes only when the filled txs merkle to `hsi.header`.
pub fn apply_block_transactions(
    hsi: &HeaderAndShortIds,
    partial: &CmpctPartial,
    txn: &BlockTransactions,
) -> Result<Block, Vec<u64>> {
    if txn.transactions.len() != partial.missing.len() {
        return Err(partial.missing.clone());
    }
    if partial.slots.is_empty() {
        return Err(Vec::new());
    }

    let mut slots = partial.slots.clone();
    let mut placed: std::collections::HashSet<bitcoin::Txid> = slots
        .iter()
        .flatten()
        .map(Transaction::compute_txid)
        .collect();
    for (i, abs) in partial.missing.iter().enumerate() {
        let abs = *abs as usize;
        if abs >= slots.len() || slots[abs].is_some() {
            return Err(Vec::new());
        }
        let tx = &txn.transactions[i];
        if !placed.insert(tx.compute_txid()) {
            return Err(partial.missing.clone());
        }
        slots[abs] = Some(tx.clone());
    }
    let mut txdata = Vec::with_capacity(slots.len());
    for slot in slots {
        let Some(tx) = slot else {
            return Err(partial.missing.clone());
        };
        txdata.push(tx);
    }
    finish_reconstructed(hsi.header, txdata)
}

/// Header merkle root and the CVE-2012-2459 mutation bit from one txid list.
///
/// `None` when `txdata` is empty. That list has no root, including when the
/// header root is all zeros. Equal adjacent txids still match a root after
/// odd-node duplication. That pair is the mutation bit.
pub fn block_txid_merkle(txdata: &[Transaction]) -> Option<([u8; 32], bool)> {
    if txdata.is_empty() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    Some(rbitcoin_store::merkle_root_mutated(&leaves))
}

/// BIP152: filled slots must merkle to the compact header and not be a
/// Core `IsBlockMutated` body (empty → getdata).
#[doc(hidden)]
pub fn finish_reconstructed(header: Header, txdata: Vec<Transaction>) -> Result<Block, Vec<u64>> {
    let Some((root, mutated)) = block_txid_merkle(&txdata) else {
        return Err(Vec::new());
    };
    let block = Block { header, txdata };
    if root != block.header.merkle_root.to_byte_array()
        || mutated
        || rbitcoin_consensus::block_mutated_without_coinbase(&block)
    {
        return Err(Vec::new());
    }
    Ok(block)
}

/// Wtxid membership at reconstruct time (live graph / extra-compact / orphanage).
#[derive(Clone, Debug, Default)]
pub struct CmpctFillSets {
    pub mempool: HashSet<Wtxid>,
    pub extra: HashSet<Wtxid>,
    pub orphan: HashSet<Wtxid>,
}

/// One compact reconstruct outcome for the operator INFO line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmpctReconstructStats {
    pub hash: BlockHash,
    pub tx_count: usize,
    pub getdata: bool,
    pub missing_n: usize,
    pub prefill_n: usize,
    pub prefill_bytes: usize,
    pub mempool_n: usize,
    pub mempool_bytes: usize,
    pub extra_n: usize,
    pub extra_bytes: usize,
    pub orphan_n: usize,
    pub orphan_bytes: usize,
    pub redundant_prefill_n: usize,
    pub redundant_prefill_bytes: usize,
    pub fetched_n: usize,
    pub fetched_bytes: usize,
}

impl Default for CmpctReconstructStats {
    fn default() -> Self {
        Self {
            hash: BlockHash::from_byte_array([0; 32]),
            tx_count: 0,
            getdata: false,
            missing_n: 0,
            prefill_n: 0,
            prefill_bytes: 0,
            mempool_n: 0,
            mempool_bytes: 0,
            extra_n: 0,
            extra_bytes: 0,
            orphan_n: 0,
            orphan_bytes: 0,
            redundant_prefill_n: 0,
            redundant_prefill_bytes: 0,
            fetched_n: 0,
            fetched_bytes: 0,
        }
    }
}

impl fmt::Display for CmpctReconstructStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.getdata {
            write!(
                f,
                "cmpct reconstruct {} getdata missing={} fetched=0/0",
                self.hash, self.missing_n
            )
        } else {
            write!(
                f,
                "cmpct reconstruct {} tx={} prefill={}/{} mempool={}/{} extra={}/{} orphan={}/{} redundant_prefill={}/{} fetched={}/{}",
                self.hash,
                self.tx_count,
                self.prefill_n,
                self.prefill_bytes,
                self.mempool_n,
                self.mempool_bytes,
                self.extra_n,
                self.extra_bytes,
                self.orphan_n,
                self.orphan_bytes,
                self.redundant_prefill_n,
                self.redundant_prefill_bytes,
                self.fetched_n,
                self.fetched_bytes,
            )
        }
    }
}

#[doc(hidden)]
pub fn tx_wire_len(tx: &Transaction) -> usize {
    tx.total_size()
}

/// Operator line for an outbound `cmpctblock` (announce or getdata serve).
pub fn cmpct_send_line(hash: BlockHash, tx_count: usize, hsi: &HeaderAndShortIds) -> String {
    let prefill_n = hsi.prefilled_txs.len();
    let prefill_bytes: usize = hsi.prefilled_txs.iter().map(|p| tx_wire_len(&p.tx)).sum();
    format!("cmpct announce {hash} tx={tx_count} prefill={prefill_n}/{prefill_bytes}")
}

/// Fallback to full `getdata` after compact reconstruct failed.
pub fn reconstruct_getdata_stats(hash: BlockHash, missing_n: usize) -> CmpctReconstructStats {
    CmpctReconstructStats {
        hash,
        getdata: true,
        missing_n,
        ..CmpctReconstructStats::default()
    }
}

/// Classify a completed reconstruct: fill sources plus `blocktxn` fetch size.
pub fn reconstruct_stats(
    hsi: &HeaderAndShortIds,
    block: &Block,
    fill: &CmpctFillSets,
    fetched_indexes: &[u64],
) -> CmpctReconstructStats {
    let prefilled: HashSet<usize> = prefilled_absolute_indexes(hsi)
        .into_iter()
        .map(|(i, _)| i)
        .collect();
    let fetched: HashSet<usize> = fetched_indexes.iter().map(|i| *i as usize).collect();
    let mut stats = CmpctReconstructStats {
        hash: block.block_hash(),
        tx_count: block.txdata.len(),
        ..CmpctReconstructStats::default()
    };
    for (abs, tx) in block.txdata.iter().enumerate() {
        let bytes = tx_wire_len(tx);
        let wtxid = tx.compute_wtxid();
        if prefilled.contains(&abs) {
            stats.prefill_n += 1;
            stats.prefill_bytes += bytes;
            if fill.mempool.contains(&wtxid) {
                stats.redundant_prefill_n += 1;
                stats.redundant_prefill_bytes += bytes;
            }
            continue;
        }
        if fetched.contains(&abs) {
            stats.fetched_n += 1;
            stats.fetched_bytes += bytes;
            continue;
        }
        if fill.mempool.contains(&wtxid) {
            stats.mempool_n += 1;
            stats.mempool_bytes += bytes;
        } else if fill.extra.contains(&wtxid) {
            stats.extra_n += 1;
            stats.extra_bytes += bytes;
        } else if fill.orphan.contains(&wtxid) {
            stats.orphan_n += 1;
            stats.orphan_bytes += bytes;
        }
    }
    stats
}

/// Additional prefill (beyond coinbase) packed into outbound `cmpctblock`.
pub const EXTRA_PREFILL_BUDGET: usize = 10 * 1024;

/// Sorted prefill indexes: coinbase, then non-mempool primary, then extra-pool.
///
/// Packs greedily up to [`EXTRA_PREFILL_BUDGET`] additional witness bytes.
pub fn prefill_indexes(block: &Block, fill: &CmpctFillSets) -> Vec<usize> {
    let mut primary = Vec::new();
    let mut extra = Vec::new();
    for (i, tx) in block.txdata.iter().enumerate().skip(1) {
        let w = tx.compute_wtxid();
        if fill.mempool.contains(&w) {
            continue;
        }
        if fill.extra.contains(&w) {
            extra.push(i);
        } else {
            primary.push(i);
        }
    }
    let mut out = vec![0];
    let mut used = 0usize;
    for i in primary.into_iter().chain(extra) {
        let sz = tx_wire_len(&block.txdata[i]);
        if used.saturating_add(sz) > EXTRA_PREFILL_BUDGET {
            continue;
        }
        used += sz;
        out.push(i);
    }
    out.sort_unstable();
    out
}

/// `None` when membership was not observed (mempool `try_read` missed).
pub fn outbound_prefill_indexes(block: &Block, fill: Option<&CmpctFillSets>) -> Option<Vec<usize>> {
    Some(prefill_indexes(block, fill?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefillPlan {
    pub hash: BlockHash,
    pub indexes: Vec<usize>,
}
