//! Fuzz-only BIP152 recipe + v2 encode helpers. Not compiled into the node.

use bitcoin::absolute::LockTime;
use bitcoin::bip152::{HeaderAndShortIds, ShortId};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_compact_blocks::{CmpctBlock, SendCmpct};
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Target, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use rbitcoin_consensus::{
    genesis_block, grind_regtest_pow, mine_regtest_paying, ChainParams, REGTEST_BLOCK_SPACING,
};
use rbitcoin_net::{encode_v2_contents, shortid_map_from_txs, try_reconstruct, NetError};
use std::collections::HashSet;

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

fn decode_cmpct_hsi(raw: &[u8]) -> Option<HeaderAndShortIds> {
    deserialize(raw).ok()
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
    if !rbitcoin_net::prefilled_indexes_ok(&case.hsi) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn prepare_cmpct_fuzz_case_coinbase_only_has_no_missing() {
        let case = prepare_cmpct_fuzz_case(&[0, 0, 0, 0]).unwrap();
        assert!(case.hsi.short_ids.is_empty());
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[][..]));
        assert!(case.fill_txs.is_empty());
    }

    #[test]
    fn prepare_cmpct_fuzz_case_raw_garbage_is_skip() {
        assert!(prepare_cmpct_fuzz_case(&[7, 1, 2, 3]).is_none());
    }

    #[test]
    fn prepare_cmpct_fuzz_case_two_tx_missing_index_1() {
        let case = prepare_cmpct_fuzz_case(&[0, 1, 0, 0, 9]).unwrap();
        assert!(cmpct_hsi_regtest_connectable(&case.hsi));
        assert_eq!(cmpct_missing_for_case(&case).as_deref(), Some(&[1u64][..]));
        assert_eq!(
            try_reconstruct(&case.hsi, &HashMap::new(), 2).unwrap_err(),
            vec![1]
        );
    }

    #[test]
    fn recipe_fixtures_match_layout() {
        assert_eq!(
            std::fs::read(fixture("cmpct_fuzz_two_tx.bin")).unwrap(),
            [0, 1, 0, 0]
        );
        assert_eq!(
            std::fs::read(fixture("cmpct_fuzz_all_prefilled.bin")).unwrap(),
            [0, 0, 0, 0]
        );
        let mut raw = vec![7u8];
        raw.extend_from_slice(&std::fs::read(fixture("cmpct_h1_two_tx.bin")).unwrap());
        assert_eq!(std::fs::read(fixture("cmpct_fuzz_raw.bin")).unwrap(), raw);
    }
}
