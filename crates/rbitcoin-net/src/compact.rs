//! BIP152 compact block reconstruction from mempool short-ids.
//!
//! Version 2 (witness) short-ids are preferred; callers pass a short-id map
//! built from live mempool (and optional extra txs). On incomplete fill,
//! returns missing absolute indexes for `getblocktxn`.

use bitcoin::absolute::LockTime;
use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_compact_blocks::{CmpctBlock, SendCmpct};
use bitcoin::p2p::Magic;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Target, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use rbitcoin_consensus::{
    genesis_block, grind_regtest_pow, mine_regtest_paying, ChainParams, REGTEST_BLOCK_SPACING,
};
use std::collections::{HashMap, HashSet};

use crate::error::NetError;
use crate::v2::encode_v2_contents;

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

fn short_id_for_tx(tx: &Transaction, version: u32, keys: (u64, u64)) -> ShortId {
    match version {
        1 => ShortId::with_siphash_keys(&tx.compute_txid().to_raw_hash(), keys),
        _ => ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys),
    }
}

/// Empty-mempool missing indexes for a compact announcement.
///
/// `None` if prefilled indexes are malformed (Core disconnects; not a split).
pub fn cmpct_missing_empty_mempool(hsi: &HeaderAndShortIds) -> Option<Vec<u64>> {
    if !prefilled_indexes_ok(hsi) {
        return None;
    }
    match try_reconstruct(hsi, &HashMap::new(), 2) {
        Ok(_) => Some(Vec::new()),
        Err(idx) => Some(idx),
    }
}

/// Consensus-decode BIP152 `HeaderAndShortIds`.
pub fn decode_cmpct_hsi(raw: &[u8]) -> Option<HeaderAndShortIds> {
    deserialize(raw).ok()
}

/// BIP324 application contents for `cmpctblock`.
pub fn encode_cmpctblock_v2(hsi: &HeaderAndShortIds) -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: hsi.clone(),
    }))
}

/// High-bandwidth BIP152 v2 `sendcmpct(1, 2)`.
pub fn encode_sendcmpct_hb_v2() -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::SendCmpct(SendCmpct {
        send_compact: true,
        version: 2,
    }))
}

/// BIP324 `ping`.
pub fn encode_ping_v2(nonce: u64) -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::Ping(nonce))
}

/// BIP324 `pong`.
pub fn encode_pong_v2(nonce: u64) -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::Pong(nonce))
}

/// BIP324 `verack`.
pub fn encode_verack_v2() -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::Verack)
}

/// BIP324 `getheaders` with empty locator (Core stays connected).
pub fn encode_getheaders_empty_v2() -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::GetHeaders(GetHeadersMessage::new(
        Vec::new(),
        BlockHash::from_byte_array([0; 32]),
    )))
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

/// Height-1 compact: prev is regtest genesis and header meets its own bits.
pub fn cmpct_hsi_regtest_connectable(hsi: &HeaderAndShortIds) -> bool {
    let genesis = genesis_block(&ChainParams::regtest());
    if hsi.header.prev_blockhash != genesis.block_hash() {
        return false;
    }
    hsi.header
        .validate_pow(Target::from_compact(hsi.header.bits))
        .is_ok()
}

/// Decode a compact announcement and restamp a unique grinded height-1 header.
pub fn prepare_cmpct_fuzz_hsi(data: &[u8]) -> Option<HeaderAndShortIds> {
    let mut hsi = decode_cmpct_hsi(data)?;
    let genesis = genesis_block(&ChainParams::regtest());
    hsi.header.prev_blockhash = genesis.block_hash();
    hsi.header.bits = genesis.header.bits;
    let mix = sha256::Hash::hash(data);
    let extra = u32::from_le_bytes(mix.to_byte_array()[..4].try_into().ok()?);
    hsi.header.time = genesis
        .header
        .time
        .saturating_add(REGTEST_BLOCK_SPACING)
        .saturating_add(extra % 10_000);
    grind_regtest_pow(&mut hsi.header);
    cmpct_hsi_regtest_connectable(&hsi).then_some(hsi)
}

const CMPCT_FUZZ_RAW_REM: u8 = 7;
const CMPCT_FUZZ_FLAG_FILL: u8 = 0x01;
const CMPCT_FUZZ_FLAG_DUP: u8 = 0x02;
const CMPCT_FUZZ_FLAG_CORRUPT: u8 = 0x04;

/// Height-1 compact plus optional txs to offer Core before `cmpctblock`.
pub struct CmpctFuzzCase {
    pub hsi: HeaderAndShortIds,
    pub fill_txs: Vec<Transaction>,
}

/// Structured recipe, or raw BIP152 bytes when `data[0] % 8 == 7`.
pub fn prepare_cmpct_fuzz_case(data: &[u8]) -> Option<CmpctFuzzCase> {
    if data.first().is_some_and(|b| b % 8 == CMPCT_FUZZ_RAW_REM) {
        let hsi = prepare_cmpct_fuzz_hsi(data.get(1..).unwrap_or(&[]))?;
        return Some(CmpctFuzzCase {
            hsi,
            fill_txs: Vec::new(),
        });
    }
    Some(structured_cmpct_case(data))
}

/// Missing indexes using the case fill set (empty = mempool-cold).
pub fn cmpct_missing_for_case(case: &CmpctFuzzCase) -> Option<Vec<u64>> {
    if !prefilled_indexes_ok(&case.hsi) {
        return None;
    }
    let avail = shortid_map_from_txs(&case.hsi.header, case.hsi.nonce, 2, &case.fill_txs);
    match try_reconstruct(&case.hsi, &avail, 2) {
        Ok(_) => Some(Vec::new()),
        Err(idx) => Some(idx),
    }
}

/// BIP324 application contents for `tx`.
pub fn encode_tx_v2(tx: &Transaction) -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::Tx(tx.clone()))
}

fn cmpct_fuzz_dummy_tx(mix: sha256::Hash, i: usize) -> Transaction {
    let mut preimage = [0u8; 40];
    preimage[..32].copy_from_slice(mix.as_byte_array());
    preimage[32..].copy_from_slice(&(i as u64).to_le_bytes());
    let id = sha256::Hash::hash(&preimage).to_byte_array();
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(id),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[id.to_vec()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn xor_first_short_id(hsi: &mut HeaderAndShortIds) {
    let Some(sid) = hsi.short_ids.first_mut() else {
        return;
    };
    let mut raw = [0u8; 6];
    raw.copy_from_slice(sid.as_ref());
    raw[0] ^= 0xff;
    *sid = ShortId::from(raw);
}

fn structured_cmpct_case(data: &[u8]) -> CmpctFuzzCase {
    let n_extra = usize::from(data.get(1).copied().unwrap_or(1) % 4);
    let prefill_mask = data.get(2).copied().unwrap_or(0);
    let flags = data.get(3).copied().unwrap_or(0);
    let nonce = if data.len() >= 12 {
        u64::from_le_bytes(data[4..12].try_into().expect("len >= 12"))
    } else {
        0x11
    };
    let mix = sha256::Hash::hash(data);
    let mut extras: Vec<Transaction> = (0..n_extra).map(|i| cmpct_fuzz_dummy_tx(mix, i)).collect();
    if flags & CMPCT_FUZZ_FLAG_DUP != 0 {
        if let Some(last) = extras.last().cloned() {
            extras.push(last);
        }
    }
    let mut prefill = Vec::new();
    for i in 0..n_extra {
        if prefill_mask & (1 << i) != 0 {
            prefill.push(i + 1);
        }
    }
    let fill_txs = if flags & CMPCT_FUZZ_FLAG_FILL != 0 {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (i, tx) in extras.iter().enumerate() {
            let prefilled = i < n_extra && (prefill_mask & (1 << i)) != 0;
            if !prefilled && seen.insert(tx.compute_txid()) {
                out.push(tx.clone());
            }
        }
        out
    } else {
        Vec::new()
    };
    let genesis = genesis_block(&ChainParams::regtest());
    let extra_time = u32::from_le_bytes(mix.to_byte_array()[..4].try_into().unwrap_or([0; 4]));
    let time = genesis
        .header
        .time
        .saturating_add(REGTEST_BLOCK_SPACING)
        .saturating_add(extra_time % 10_000);
    let block = mine_regtest_paying(
        genesis.block_hash(),
        time,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        extras,
    );
    let mut hsi = HeaderAndShortIds::from_block(&block, nonce, 2, &prefill)
        .expect("prefill indexes in range");
    if flags & CMPCT_FUZZ_FLAG_CORRUPT != 0 {
        xor_first_short_id(&mut hsi);
    }
    CmpctFuzzCase { hsi, fill_txs }
}

/// Core: prefilled indexes must decode in-range. Out-of-range is a
/// malformed `cmpctblock` (`p2p_compactblocks` `test_invalid_cmpctblock_message`).
pub fn prefilled_indexes_ok(hsi: &HeaderAndShortIds) -> bool {
    let total = hsi.short_ids.len().saturating_add(hsi.prefilled_txs.len());
    let mut last: Option<usize> = None;
    for (abs, _) in prefilled_absolute_indexes(hsi) {
        if abs >= total {
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

/// Attempt to reconstruct a full block from compact data + available txs.
///
/// On success the txs merkle to `hsi.header`. Incomplete fill returns the
/// remaining absolute indexes (`getblocktxn`). A complete fill that does not
/// merkle (wrong unique short-id body) returns an empty vec (`getdata`).
pub fn try_reconstruct(
    hsi: &HeaderAndShortIds,
    available: &HashMap<ShortId, Vec<&Transaction>>,
    version: u32,
) -> Result<Block, Vec<u64>> {
    let n_short = hsi.short_ids.len();
    let n_pref = hsi.prefilled_txs.len();
    let total = n_short.saturating_add(n_pref);
    if total == 0 {
        return Err(Vec::new());
    }

    let mut slots: Vec<Option<Transaction>> = vec![None; total];
    let mut prefilled_set = std::collections::HashSet::new();
    let mut placed: std::collections::HashSet<bitcoin::Txid> = std::collections::HashSet::new();
    for (abs, tx) in prefilled_absolute_indexes(hsi) {
        if abs >= total {
            return Err(Vec::new());
        }
        placed.insert(tx.compute_txid());
        slots[abs] = Some(tx.clone());
        prefilled_set.insert(abs);
    }

    let mut short_i = 0usize;
    let mut missing = Vec::new();
    for abs in 0..total {
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
                let txid = cands[0].compute_txid();
                // Repeat short-id / same candidate in two slots → duplicate
                // txid block. Mark missing so getblocktxn / getdata can recover.
                if !placed.insert(txid) {
                    missing.push(abs as u64);
                    continue;
                }
                slots[abs] = Some(cands[0].clone());
            }
            Some(cands) if cands.len() > 1 => {
                // Ambiguous short-id collision — request from peer.
                missing.push(abs as u64);
            }
            _ => missing.push(abs as u64),
        }
    }

    if !missing.is_empty() {
        return Err(missing);
    }

    let mut txdata = Vec::with_capacity(total);
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(tx) => txdata.push(tx),
            None => return Err(vec![i as u64]),
        }
    }

    // Version 1 strips witness from prefilled; we may need peer to send full blocks
    // for validation. Prefer version 2. If coinbase has no witness but block needs
    // it, accept_block will fail structure — caller falls back to getdata.
    let _ = version;
    finish_reconstructed(hsi.header, txdata)
}

/// Build a `getblocktxn` request for missing absolute indexes.
pub fn missing_request(block_hash: BlockHash, missing: &[u64]) -> BlockTransactionsRequest {
    BlockTransactionsRequest {
        block_hash,
        indexes: missing.to_vec(),
    }
}

/// Apply `blocktxn` payload into a slot list previously missing those indexes.
///
/// `missing` must match the order of indexes we requested (absolute indexes).
/// `txn.transactions` holds the txs in the same order as the request indexes.
/// Provided txs are placed by absolute index (not re-matched by short-id alone),
/// so collisions cannot undo a successful `getblocktxn` response.
/// Completes only when the filled txs merkle to `hsi.header`.
pub fn apply_block_transactions(
    hsi: &HeaderAndShortIds,
    missing: &[u64],
    txn: &BlockTransactions,
    available: &HashMap<ShortId, Vec<&Transaction>>,
    version: u32,
) -> Result<Block, Vec<u64>> {
    if txn.transactions.len() != missing.len() {
        return Err(missing.to_vec());
    }

    let n_short = hsi.short_ids.len();
    let n_pref = hsi.prefilled_txs.len();
    let total = n_short.saturating_add(n_pref);
    if total == 0 {
        return Err(Vec::new());
    }

    let mut forced: HashMap<usize, &Transaction> = HashMap::with_capacity(missing.len());
    for (i, abs) in missing.iter().enumerate() {
        forced.insert(*abs as usize, &txn.transactions[i]);
    }

    let mut slots: Vec<Option<Transaction>> = vec![None; total];
    let mut prefilled_set = std::collections::HashSet::new();
    let mut placed: std::collections::HashSet<bitcoin::Txid> = std::collections::HashSet::new();
    for (abs, tx) in prefilled_absolute_indexes(hsi) {
        if abs >= total {
            return Err(Vec::new());
        }
        placed.insert(tx.compute_txid());
        slots[abs] = Some(tx.clone());
        prefilled_set.insert(abs);
    }

    let mut short_i = 0usize;
    let mut still_missing = Vec::new();
    for abs in 0..total {
        if prefilled_set.contains(&abs) {
            continue;
        }
        if let Some(tx) = forced.get(&abs) {
            let txid = tx.compute_txid();
            if !placed.insert(txid) {
                return Err(missing.to_vec());
            }
            slots[abs] = Some((*tx).clone());
            // Still consume the corresponding short_id slot.
            if short_i < hsi.short_ids.len() {
                short_i += 1;
            }
            continue;
        }
        if short_i >= hsi.short_ids.len() {
            still_missing.push(abs as u64);
            continue;
        }
        let sid = hsi.short_ids[short_i];
        short_i += 1;
        match available.get(&sid) {
            Some(cands) if cands.len() == 1 => {
                let txid = cands[0].compute_txid();
                if !placed.insert(txid) {
                    still_missing.push(abs as u64);
                    continue;
                }
                slots[abs] = Some(cands[0].clone());
            }
            _ => still_missing.push(abs as u64),
        }
    }

    if !still_missing.is_empty() {
        return Err(still_missing);
    }

    let mut txdata = Vec::with_capacity(total);
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(tx) => txdata.push(tx),
            None => return Err(vec![i as u64]),
        }
    }
    let _ = version;
    finish_reconstructed(hsi.header, txdata)
}

/// BIP152: filled slots must merkle to the compact header (empty → getdata).
fn finish_reconstructed(header: Header, txdata: Vec<Transaction>) -> Result<Block, Vec<u64>> {
    let block = Block { header, txdata };
    if !block.check_merkle_root() {
        return Err(Vec::new());
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, Sequence, TxIn, TxMerkleNode, TxOut, Witness,
    };

    fn dummy_header() -> Header {
        Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        }
    }

    fn sealed_block(txdata: Vec<Transaction>) -> Block {
        let mut header = dummy_header();
        header.merkle_root = Block {
            header,
            txdata: txdata.clone(),
        }
        .compute_merkle_root()
        .expect("non-empty");
        Block { header, txdata }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn spend(n: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([n; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![n]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn reconstruct_full_from_mempool_map() {
        let b1 = spend(1);
        let b2 = spend(2);
        let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
        let hsi = HeaderAndShortIds::from_block(&block, 0xdead_beef, 2, &[]).unwrap();
        // Available: both non-coinbase from "mempool"
        let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1, &b2]);
        let recon = try_reconstruct(&hsi, &avail, 2).expect("full fill");
        assert_eq!(recon.txdata.len(), 3);
        assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
        assert_eq!(recon.txdata[2].compute_txid(), b2.compute_txid());
    }

    #[test]
    fn missing_indexes_when_mempool_empty() {
        let b1 = spend(3);
        let block = Block {
            header: dummy_header(),
            txdata: vec![coinbase(), b1],
        };
        let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[]).unwrap();
        let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        let missing = try_reconstruct(&hsi, &empty, 2).unwrap_err();
        // coinbase prefilled; one short id missing at abs index 1
        assert_eq!(missing, vec![1]);
    }

    #[test]
    fn repeated_short_id_is_requested_not_duplicated() {
        let b1 = spend(7);
        let block = Block {
            header: dummy_header(),
            txdata: vec![coinbase(), b1.clone(), b1.clone()],
        };
        let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
        let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
        let missing = try_reconstruct(&hsi, &avail, 2).expect_err("repeat must not fully fill");
        assert!(
            !missing.is_empty(),
            "second slot of the same short-id must be missing"
        );
        assert!(
            missing.contains(&2) || missing == vec![2] || missing.contains(&1),
            "expected a missing index for the duplicate slot, got {missing:?}"
        );
    }

    #[test]
    fn unique_shortid_wrong_body_is_not_a_block() {
        let b1 = spend(8);
        let block = sealed_block(vec![coinbase(), b1.clone()]);
        let hsi = HeaderAndShortIds::from_block(&block, 4, 2, &[]).unwrap();
        let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
        let sid = short_id_for_tx(&b1, 2, keys);
        let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        let wrong = spend(9);
        avail.insert(sid, vec![&wrong]);
        let missing = try_reconstruct(&hsi, &avail, 2).expect_err("wrong unique fill");
        assert!(
            missing.is_empty(),
            "merkle-mutated fill must getdata (empty missing), got {missing:?}"
        );
    }

    #[test]
    fn apply_blocktxn_wrong_body_is_not_a_block() {
        let b1 = spend(10);
        let block = sealed_block(vec![coinbase(), b1]);
        let hsi = HeaderAndShortIds::from_block(&block, 5, 2, &[]).unwrap();
        let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        let missing = try_reconstruct(&hsi, &empty, 2).unwrap_err();
        let txn = BlockTransactions {
            block_hash: block.block_hash(),
            transactions: vec![spend(11)],
        };
        let err = apply_block_transactions(&hsi, &missing, &txn, &empty, 2)
            .expect_err("wrong blocktxn body");
        assert!(
            err.is_empty(),
            "merkle-mutated blocktxn must getdata, got {err:?}"
        );
    }

    #[test]
    fn apply_blocktxn_completes() {
        let b1 = spend(4);
        let block = sealed_block(vec![coinbase(), b1.clone()]);
        let hsi = HeaderAndShortIds::from_block(&block, 2, 2, &[]).unwrap();
        let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        let missing = try_reconstruct(&hsi, &empty, 2).unwrap_err();
        let txn = BlockTransactions {
            block_hash: block.block_hash(),
            transactions: vec![b1.clone()],
        };
        let recon = apply_block_transactions(&hsi, &missing, &txn, &empty, 2).unwrap();
        assert_eq!(recon.txdata.len(), 2);
    }

    #[test]
    fn missing_request_uses_absolute_indexes() {
        let missing = vec![1u64, 3, 5];
        let req = missing_request(BlockHash::from_byte_array([9; 32]), &missing);
        assert_eq!(req.indexes, missing);
    }

    #[test]
    fn partial_mempool_plus_blocktxn() {
        let b1 = spend(5);
        let b2 = spend(6);
        let block = sealed_block(vec![coinbase(), b1.clone(), b2.clone()]);
        let hsi = HeaderAndShortIds::from_block(&block, 3, 2, &[]).unwrap();
        // Only b1 in "mempool"
        let avail = shortid_map_from_txs(&block.header, hsi.nonce, 2, [&b1]);
        let missing = try_reconstruct(&hsi, &avail, 2).unwrap_err();
        assert_eq!(missing, vec![2]); // abs index of b2
        let txn = BlockTransactions {
            block_hash: block.block_hash(),
            transactions: vec![b2.clone()],
        };
        let recon = apply_block_transactions(&hsi, &missing, &txn, &avail, 2).unwrap();
        assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
        assert_eq!(recon.txdata[2].compute_txid(), b2.compute_txid());
    }

    #[test]
    fn version1_txid_shortids_fill() {
        let b1 = spend(7);
        let block = sealed_block(vec![coinbase(), b1.clone()]);
        let hsi = HeaderAndShortIds::from_block(&block, 4, 1, &[]).unwrap();
        let avail = shortid_map_from_txs(&block.header, hsi.nonce, 1, [&b1]);
        let recon = try_reconstruct(&hsi, &avail, 1).expect("v1 fill");
        assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
    }

    #[test]
    fn wrong_count_blocktxn_errors() {
        let b1 = spend(8);
        let block = Block {
            header: dummy_header(),
            txdata: vec![coinbase(), b1],
        };
        let hsi = HeaderAndShortIds::from_block(&block, 5, 2, &[]).unwrap();
        let empty: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        let missing = try_reconstruct(&hsi, &empty, 2).unwrap_err();
        let txn = BlockTransactions {
            block_hash: block.block_hash(),
            transactions: vec![], // wrong count
        };
        assert!(apply_block_transactions(&hsi, &missing, &txn, &empty, 2).is_err());
    }

    #[test]
    fn empty_compact_and_ambiguous_shortid() {
        // total=0 → empty error.
        let hsi = HeaderAndShortIds {
            header: dummy_header(),
            nonce: 0,
            short_ids: vec![],
            prefilled_txs: vec![],
        };
        assert!(try_reconstruct(&hsi, &HashMap::new(), 2)
            .unwrap_err()
            .is_empty());
        assert!(apply_block_transactions(
            &hsi,
            &[],
            &BlockTransactions {
                block_hash: BlockHash::from_byte_array([0; 32]),
                transactions: vec![],
            },
            &HashMap::new(),
            2
        )
        .unwrap_err()
        .is_empty());

        // Ambiguous short-id collision → missing.
        let b1 = spend(9);
        let block = Block {
            header: dummy_header(),
            txdata: vec![coinbase(), b1.clone()],
        };
        let hsi = HeaderAndShortIds::from_block(&block, 9, 2, &[]).unwrap();
        let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
        let sid = ShortId::with_siphash_keys(&b1.compute_wtxid().to_raw_hash(), keys);
        let b_alt = spend(10);
        let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        avail.insert(sid, vec![&b1, &b_alt]);
        let missing = try_reconstruct(&hsi, &avail, 2).unwrap_err();
        assert_eq!(missing, vec![1]);

        // prefilled absolute indexes differential walk.
        let idxs = prefilled_absolute_indexes(&hsi);
        assert!(!idxs.is_empty());
        assert_eq!(idxs[0].0, 0); // coinbase at abs 0
        assert!(prefilled_indexes_ok(&hsi));

        let oob = HeaderAndShortIds {
            header: dummy_header(),
            nonce: 0,
            short_ids: vec![],
            prefilled_txs: vec![bitcoin::bip152::PrefilledTransaction {
                idx: 1,
                tx: coinbase(),
            }],
        };
        assert!(!prefilled_indexes_ok(&oob));
        assert!(cmpct_missing_empty_mempool(&oob).is_none());
    }

    fn mined_h1_two_tx_hsi() -> HeaderAndShortIds {
        use rbitcoin_consensus::{genesis_block, mine_regtest_paying, ChainParams};
        let genesis = genesis_block(&ChainParams::regtest());
        let extra = spend(1);
        let block = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![extra],
        );
        HeaderAndShortIds::from_block(&block, 0x11, 2, &[]).unwrap()
    }

    fn cmpct_fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn classify_v2_ping_and_sendcmpct_encode() {
        let ping = crate::v2::encode_v2_contents(NetworkMessage::Ping(7)).unwrap();
        assert_eq!(classify_v2_cmpct_peer(&ping), CmpctPeerFrame::Ping(7));
        let ping2 = encode_ping_v2(7).unwrap();
        assert_eq!(ping, ping2);
        let pong = encode_pong_v2(7).unwrap();
        assert_eq!(classify_v2_cmpct_peer(&pong), CmpctPeerFrame::Pong(7));
        encode_sendcmpct_hb_v2().unwrap();
        encode_verack_v2().unwrap();
        encode_getheaders_empty_v2().unwrap();
        encode_tx_v2(&spend(1)).unwrap();
        assert_eq!(classify_v2_cmpct_peer(&[]), CmpctPeerFrame::Other);
    }

    #[test]
    fn cmpct_missing_empty_mempool_two_tx_is_index_1() {
        let hsi = mined_h1_two_tx_hsi();
        assert!(cmpct_hsi_regtest_connectable(&hsi));
        assert_eq!(
            cmpct_missing_empty_mempool(&hsi).as_deref(),
            Some(&[1u64][..])
        );
        let raw = bitcoin::consensus::encode::serialize(&hsi);
        assert_eq!(
            cmpct_missing_empty_mempool(&decode_cmpct_hsi(&raw).unwrap()).as_deref(),
            Some(&[1u64][..])
        );
        encode_cmpctblock_v2(&hsi).unwrap();
    }

    #[test]
    fn prepare_cmpct_fuzz_hsi_unique_connectable_headers() {
        let mut hsi = mined_h1_two_tx_hsi();
        let raw_a = bitcoin::consensus::encode::serialize(&hsi);
        hsi.nonce = 0x22;
        let raw_b = bitcoin::consensus::encode::serialize(&hsi);
        let a = prepare_cmpct_fuzz_hsi(&raw_a).unwrap();
        let b = prepare_cmpct_fuzz_hsi(&raw_b).unwrap();
        assert!(cmpct_hsi_regtest_connectable(&a));
        assert!(cmpct_hsi_regtest_connectable(&b));
        let genesis = genesis_block(&ChainParams::regtest());
        assert_eq!(a.header.prev_blockhash, genesis.block_hash());
        assert_eq!(b.header.prev_blockhash, genesis.block_hash());
        assert_ne!(a.header.block_hash(), b.header.block_hash());
        assert_eq!(
            cmpct_missing_empty_mempool(&a).as_deref(),
            Some(&[1u64][..])
        );
    }

    #[test]
    fn cmpct_h1_two_tx_fixture_matches_mined() {
        let expected = bitcoin::consensus::encode::serialize(&mined_h1_two_tx_hsi());
        let path = cmpct_fixture_path("cmpct_h1_two_tx.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        let hsi = decode_cmpct_hsi(&raw).unwrap();
        assert!(cmpct_hsi_regtest_connectable(&hsi));
        assert_eq!(
            cmpct_missing_empty_mempool(&hsi).as_deref(),
            Some(&[1u64][..])
        );
    }

    #[test]
    fn prepare_cmpct_fuzz_case_random_bytes_are_connectable() {
        let a = prepare_cmpct_fuzz_case(&[0, 1, 0, 0, 9]).unwrap();
        let b = prepare_cmpct_fuzz_case(&[0, 1, 0, 0, 10]).unwrap();
        assert!(cmpct_hsi_regtest_connectable(&a.hsi));
        assert!(cmpct_hsi_regtest_connectable(&b.hsi));
        assert_ne!(a.hsi.header.block_hash(), b.hsi.header.block_hash());
        assert!(a.fill_txs.is_empty());
        assert_eq!(cmpct_missing_for_case(&a).as_deref(), Some(&[1u64][..]));
        let two = prepare_cmpct_fuzz_case(&[0, 2, 0, 0]).unwrap();
        assert_eq!(
            cmpct_missing_for_case(&two).as_deref(),
            Some(&[1u64, 2][..])
        );
        assert_ne!(two.hsi.short_ids[0], two.hsi.short_ids[1]);
    }

    #[test]
    fn prepare_cmpct_fuzz_case_coinbase_only_has_no_missing() {
        let case = prepare_cmpct_fuzz_case(&[0, 0, 0, 0]).unwrap();
        assert!(case.hsi.short_ids.is_empty());
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[][..]));
        assert!(case.fill_txs.is_empty());
    }

    #[test]
    fn prepare_cmpct_fuzz_case_fill_clears_short_id_slot() {
        let case = prepare_cmpct_fuzz_case(&[0, 1, 0, 1]).unwrap();
        assert_eq!(case.fill_txs.len(), 1);
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[][..]));
        assert_eq!(
            cmpct_missing_empty_mempool(&case.hsi).as_deref(),
            Some(&[1u64][..])
        );
    }

    #[test]
    fn prepare_cmpct_fuzz_case_duplicate_short_id_requests_second_slot() {
        let case = prepare_cmpct_fuzz_case(&[0, 1, 0, 3]).unwrap();
        assert_eq!(case.fill_txs.len(), 1);
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[2u64][..]));
    }

    #[test]
    fn prepare_cmpct_fuzz_case_corrupt_short_id_stays_missing_with_fill() {
        let case = prepare_cmpct_fuzz_case(&[0, 1, 0, 5]).unwrap();
        assert_eq!(case.fill_txs.len(), 1);
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[1u64][..]));
    }

    #[test]
    fn prepare_cmpct_fuzz_case_raw_arm_uses_fixture() {
        let mut raw = vec![7u8];
        raw.extend_from_slice(&std::fs::read(cmpct_fixture_path("cmpct_h1_two_tx.bin")).unwrap());
        let case = prepare_cmpct_fuzz_case(&raw).unwrap();
        assert!(case.fill_txs.is_empty());
        assert!(cmpct_hsi_regtest_connectable(&case.hsi));
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[1u64][..]));
    }

    #[test]
    fn prepare_cmpct_fuzz_case_raw_garbage_is_skip() {
        assert!(prepare_cmpct_fuzz_case(&[7, 1, 2, 3]).is_none());
    }

    #[test]
    fn cmpct_fuzz_recipe_fixtures_match_layout() {
        assert_eq!(
            std::fs::read(cmpct_fixture_path("cmpct_fuzz_two_tx.bin")).unwrap(),
            [0, 1, 0, 0]
        );
        assert_eq!(
            std::fs::read(cmpct_fixture_path("cmpct_fuzz_all_prefilled.bin")).unwrap(),
            [0, 0, 0, 0]
        );
        assert_eq!(
            std::fs::read(cmpct_fixture_path("cmpct_fuzz_fill.bin")).unwrap(),
            [0, 1, 0, 1]
        );
        assert_eq!(
            std::fs::read(cmpct_fixture_path("cmpct_fuzz_dup.bin")).unwrap(),
            [0, 1, 0, 3]
        );
        let mut raw = vec![7u8];
        raw.extend_from_slice(&std::fs::read(cmpct_fixture_path("cmpct_h1_two_tx.bin")).unwrap());
        assert_eq!(
            std::fs::read(cmpct_fixture_path("cmpct_fuzz_raw.bin")).unwrap(),
            raw
        );
    }
}
