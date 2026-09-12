//! BIP152 compact block reconstruction from mempool short-ids.
//!
//! Version 2 (witness) short-ids are preferred; callers pass a short-id map
//! built from live mempool (and optional extra txs). On incomplete fill,
//! returns missing absolute indexes for `getblocktxn`.

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::{Block, BlockHash, Transaction};
use std::borrow::Borrow;
use std::collections::HashMap;

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

/// Consensus-decode BIP152 `HeaderAndShortIds`.
#[cfg(test)]
fn decode_cmpct_hsi(raw: &[u8]) -> Option<HeaderAndShortIds> {
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
pub fn try_reconstruct<T: Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    available: &HashMap<ShortId, Vec<T>>,
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
pub fn apply_block_transactions<T: Borrow<Transaction>>(
    hsi: &HeaderAndShortIds,
    missing: &[u64],
    txn: &BlockTransactions,
    available: &HashMap<ShortId, Vec<T>>,
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
    for (abs, slot) in slots.iter_mut().enumerate() {
        if prefilled_set.contains(&abs) {
            continue;
        }
        if let Some(tx) = forced.get(&abs) {
            let txid = tx.compute_txid();
            if !placed.insert(txid) {
                return Err(missing.to_vec());
            }
            *slot = Some((*tx).clone());
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
                let txid = cands[0].borrow().compute_txid();
                if !placed.insert(txid) {
                    still_missing.push(abs as u64);
                    continue;
                }
                *slot = Some(cands[0].borrow().clone());
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

    fn empty_avail() -> HashMap<ShortId, Vec<&'static Transaction>> {
        HashMap::new()
    }

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
    fn reconstruct_fill_keeps_matching_shortid_not_rehash() {
        let b1 = spend(1);
        let block = sealed_block(vec![coinbase(), b1.clone()]);
        let mut hsi = HeaderAndShortIds::from_block(&block, 0xdead_beef, 2, &[]).unwrap();
        let keys = ShortId::calculate_siphash_keys(&block.header, hsi.nonce);
        let hashed = short_id_for_tx(&b1, 2, keys);
        let fake = ShortId::with_siphash_keys(
            &bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
            keys,
        );
        assert_ne!(fake, hashed, "caller key must differ from clone siphash");
        hsi.short_ids[0] = fake;

        let mut owned: HashMap<ShortId, Vec<Transaction>> = HashMap::new();
        owned.insert(fake, vec![b1.clone()]);

        let rehashed = shortid_map_from_txs(&block.header, hsi.nonce, 2, owned.values().flatten());
        assert!(
            try_reconstruct(&hsi, &rehashed, 2).is_err(),
            "rehashing clones must miss a caller short-id"
        );

        let recon = try_reconstruct(&hsi, &owned, 2).expect("matching short-id must place body");
        assert_eq!(recon.txdata[1].compute_txid(), b1.compute_txid());
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
        assert!(
            try_reconstruct(&hsi, &HashMap::<ShortId, Vec<&Transaction>>::new(), 2)
                .unwrap_err()
                .is_empty()
        );
        assert!(apply_block_transactions(
            &hsi,
            &[],
            &BlockTransactions {
                block_hash: BlockHash::from_byte_array([0; 32]),
                transactions: vec![],
            },
            &HashMap::<ShortId, Vec<&Transaction>>::new(),
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
    fn classify_v2_ping_and_empty_other() {
        let ping = crate::v2::encode_v2_contents(NetworkMessage::Ping(7)).unwrap();
        assert_eq!(classify_v2_cmpct_peer(&ping), CmpctPeerFrame::Ping(7));
        let pong = crate::v2::encode_v2_contents(NetworkMessage::Pong(7)).unwrap();
        assert_eq!(classify_v2_cmpct_peer(&pong), CmpctPeerFrame::Pong(7));
        assert_eq!(classify_v2_cmpct_peer(&[]), CmpctPeerFrame::Other);
    }

    #[test]
    fn try_reconstruct_empty_mempool_two_tx_is_index_1() {
        let hsi = mined_h1_two_tx_hsi();
        assert_eq!(
            try_reconstruct(&hsi, &empty_avail(), 2).unwrap_err(),
            vec![1]
        );
        let raw = bitcoin::consensus::encode::serialize(&hsi);
        assert_eq!(
            try_reconstruct(&decode_cmpct_hsi(&raw).unwrap(), &empty_avail(), 2).unwrap_err(),
            vec![1]
        );
    }

    #[test]
    fn cmpct_h1_two_tx_fixture_matches_mined() {
        let expected = bitcoin::consensus::encode::serialize(&mined_h1_two_tx_hsi());
        let path = cmpct_fixture_path("cmpct_h1_two_tx.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        let hsi = decode_cmpct_hsi(&raw).unwrap();
        assert_eq!(
            try_reconstruct(&hsi, &empty_avail(), 2).unwrap_err(),
            vec![1]
        );
    }

    /// Compact siphash nonce for `cmpct_wtxid_shortid_collision_*.bin`.
    const COLLISION_CMPCT_NONCE: u64 = 0x0C01_115E;
    const COLLISION_STALE_TIME: u32 = 1_300_060_000;
    const COLLISION_WINNER_TIME: u32 = 1_300_060_001;

    fn collision_parents() -> (Block, Block) {
        use rbitcoin_consensus::{genesis_block, mine_empty_regtest, ChainParams};
        let genesis = genesis_block(&ChainParams::regtest());
        let stale = mine_empty_regtest(genesis.block_hash(), COLLISION_STALE_TIME, 1);
        let mut winner = mine_empty_regtest(genesis.block_hash(), COLLISION_WINNER_TIME, 1);
        if winner.block_hash() == stale.block_hash() {
            winner = mine_empty_regtest(genesis.block_hash(), COLLISION_WINNER_TIME + 1, 1);
        }
        assert_ne!(stale.block_hash(), winner.block_hash());
        (stale, winner)
    }

    fn load_wtxid_shortid_collision() -> (Block, Transaction) {
        let block_raw = std::fs::read(cmpct_fixture_path(
            "cmpct_wtxid_shortid_collision_block.bin",
        ))
        .expect("cmpct_wtxid_shortid_collision_block.bin");
        let collider_raw = std::fs::read(cmpct_fixture_path(
            "cmpct_wtxid_shortid_collision_collider.bin",
        ))
        .expect("cmpct_wtxid_shortid_collision_collider.bin");
        (
            bitcoin::consensus::encode::deserialize(&block_raw).expect("block"),
            bitcoin::consensus::encode::deserialize(&collider_raw).expect("collider"),
        )
    }

    fn collision_hsi(block: &Block, collider: &Transaction) -> HeaderAndShortIds {
        assert_eq!(block.txdata.len(), 2);
        let block_tx = &block.txdata[1];
        assert_ne!(block_tx.compute_txid(), collider.compute_txid());
        assert_ne!(block_tx.compute_wtxid(), collider.compute_wtxid());
        let keys = ShortId::calculate_siphash_keys(&block.header, COLLISION_CMPCT_NONCE);
        let sid_block = ShortId::with_siphash_keys(&block_tx.compute_wtxid().to_raw_hash(), keys);
        let sid_col = ShortId::with_siphash_keys(&collider.compute_wtxid().to_raw_hash(), keys);
        assert_eq!(
            sid_block, sid_col,
            "fixture must be a v2 short-id collision"
        );
        let hsi = HeaderAndShortIds::from_block(block, COLLISION_CMPCT_NONCE, 2, &[]).unwrap();
        assert_eq!(hsi.short_ids, vec![sid_block]);
        hsi
    }

    fn assert_collider_fill_getdata<T: std::borrow::Borrow<Transaction>>(
        hsi: &HeaderAndShortIds,
        avail: &HashMap<ShortId, Vec<T>>,
    ) {
        let missing = try_reconstruct(hsi, avail, 2).expect_err("collider unique fill");
        assert!(
            missing.is_empty(),
            "48-bit unique fill must getdata, got {missing:?}"
        );
    }

    fn mutated_collision_body(block: &Block, collider: &Transaction) -> Block {
        let mutated = Block {
            header: block.header,
            txdata: vec![block.txdata[0].clone(), collider.clone()],
        };
        assert_eq!(mutated.block_hash(), block.block_hash());
        assert!(!mutated.check_merkle_root());
        mutated
    }

    fn assert_mutated_not_block_failed(
        hub: &crate::chain::ChainHub,
        mutated: Block,
        hash: bitcoin::BlockHash,
    ) {
        use crate::error::NetError;
        let err = hub
            .accept_received_block(mutated)
            .expect_err("v0.6.0 would accept this reconstructed body");
        match &err {
            NetError::Mutated(s) | NetError::Consensus(s) => {
                assert!(
                    s.contains("merkle") || s.contains("bad-txnmrklroot"),
                    "got {s}"
                );
            }
            NetError::ConnectFailed { msg, hash: h } => {
                assert!(
                    msg.contains("merkle") || msg.contains("bad-txnmrklroot"),
                    "got {msg}"
                );
                assert_eq!(*h, hash.to_byte_array());
            }
            other => panic!("expected mutated reject, got {other:?}"),
        }
        assert!(
            !hub.is_block_invalid(&hash),
            "short-id collision reconstruct must not BLOCK_FAILED the header"
        );
    }

    /// Pre-ground v2 48-bit wtxid short-id collision: orphan unique-match on a held fork.
    #[test]
    fn cmpct_wtxid_shortid_collision_held_fork_journey() {
        use crate::chain::AcceptOutcome;
        use rbitcoin_consensus::mine_empty_regtest;
        use std::sync::Arc;

        let (block, collider) = load_wtxid_shortid_collision();
        let (stale, winner) = collision_parents();
        assert_eq!(block.header.prev_blockhash, winner.block_hash());
        let hsi = collision_hsi(&block, &collider);
        let sid = hsi.short_ids[0];
        let mut avail: HashMap<ShortId, Vec<&Transaction>> = HashMap::new();
        avail.insert(sid, vec![&collider]);
        assert_collider_fill_getdata(&hsi, &avail);
        let mutated = mutated_collision_body(&block, &collider);

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("cmpct-sid-col");
        hub.ensure_genesis().unwrap();
        hub.accept_block(stale.clone()).unwrap();
        assert!(matches!(
            hub.accept_received_block(winner.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&winner.block_hash()).is_some());

        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
        assert!(matches!(
            mp.accept_tx(&collider),
            Err(crate::AcceptError::Orphaned { .. })
        ));
        let owned = mp
            .try_clone_matching_shortids(&hsi.header, hsi.nonce, 2, &hsi.short_ids)
            .expect("mempool read");
        let fill = owned.get(&sid).expect("orphan collider must unique-match");
        assert_eq!(fill.len(), 1);
        assert_eq!(fill[0].compute_wtxid(), collider.compute_wtxid());
        assert_collider_fill_getdata(&hsi, &owned);

        assert_mutated_not_block_failed(&hub, mutated, block.block_hash());
        assert_eq!(hub.tip_hash(), Some(stale.block_hash()));

        let honest = mine_empty_regtest(
            winner.block_hash(),
            winner.header.time.saturating_add(601),
            2,
        );
        assert!(matches!(
            hub.accept_received_block(honest.clone()).unwrap(),
            AcceptOutcome::Accepted { height: 2 }
        ));
        assert_eq!(hub.tip_hash(), Some(honest.block_hash()));
        assert!(!hub.is_block_invalid(&block.block_hash()));

        let _ = std::fs::remove_dir_all(dir);
    }
}
