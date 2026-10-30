//! Fuzz-only BIP152 recipe + v2 encode helpers. Not compiled into the node.

use bitcoin::absolute::LockTime;
use bitcoin::bip152::{HeaderAndShortIds, ShortId};
use bitcoin::consensus::encode::{deserialize, serialize};
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
use rbitcoin_net::{
    drain_pending_now, encode_v2_contents, shortid_map_from_txs, try_reconstruct, ChainHub,
    NetError, PendingBlocks,
};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;

use crate::block_diff::{
    same_hash_merkle_mutant, verdict_from_core_reply, BlockOracle, BlockStanding, CompareOne,
    DiffVerdict, OracleReply,
};

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
    encode_getheaders_v2(Vec::new(), BlockHash::from_byte_array([0; 32]))
}

/// BIP324 `feefilter` when `payload` is an 8-byte little-endian fee.
pub fn encode_feefilter_payload(payload: &[u8]) -> Option<Vec<u8>> {
    let bytes: [u8; 8] = payload.try_into().ok()?;
    let amt = i64::from_le_bytes(bytes);
    encode_v2_contents(NetworkMessage::FeeFilter(amt)).ok()
}

/// BIP324 `inv` when `payload` is a consensus-encoded inventory vector.
pub fn encode_inv_payload(payload: &[u8]) -> Option<Vec<u8>> {
    let inv = deserialize::<Vec<bitcoin::p2p::message_blockdata::Inventory>>(payload).ok()?;
    encode_v2_contents(NetworkMessage::Inv(inv)).ok()
}

/// BIP324 `getheaders` for a locator and stop hash.
pub fn encode_getheaders_v2(locator: Vec<BlockHash>, stop: BlockHash) -> Result<Vec<u8>, NetError> {
    encode_v2_contents(NetworkMessage::GetHeaders(GetHeadersMessage::new(
        locator, stop,
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

/// Core's compact job sets mocktime to regtest genesis and rejects a header
/// more than two hours later (`time-too-new`). Fold the mix into
/// genesis + one regtest interval through that cap so stamps stay unique.
fn cmpct_header_time(genesis_time: u32, extra: u32) -> u32 {
    const MAX_FUTURE: u32 = 2 * 60 * 60;
    let earliest = genesis_time.saturating_add(REGTEST_BLOCK_SPACING);
    let latest = genesis_time.saturating_add(MAX_FUTURE);
    let span = latest.saturating_sub(earliest).saturating_add(1);
    earliest.saturating_add(extra % span)
}

/// Hub accept uses this clock. Wall time would accept a 2011 stamp Core's
/// mocktime calls `time-too-new`.
fn pin_cmpct_hub_clock(hub: &ChainHub) {
    let t = genesis_block(&ChainParams::regtest()).header.time;
    hub.clock.set_mock(i64::from(t));
}

/// Decode a compact announcement and restamp a unique grinded height-1 header.
pub fn prepare_cmpct_fuzz_hsi(data: &[u8]) -> Option<HeaderAndShortIds> {
    let mut hsi = decode_cmpct_hsi(data)?;
    let genesis = genesis_block(&ChainParams::regtest());
    hsi.header.prev_blockhash = genesis.block_hash();
    hsi.header.bits = genesis.header.bits;
    let mix = sha256::Hash::hash(data);
    let extra = u32::from_le_bytes(mix.to_byte_array()[..4].try_into().ok()?);
    hsi.header.time = cmpct_header_time(genesis.header.time, extra);
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

/// Core extra-txn may fill a duplicate-txid slot we still `getblocktxn`
/// (018). Agree when every Core index is one of ours. Extra ours is that
/// missing ring, not a split. Omitting a Core index disagrees.
pub fn cmpct_getblocktxn_agrees(ours: &[u64], core: &[u64]) -> bool {
    core.iter().all(|i| ours.contains(i))
}

/// A drain error that drops the peer. That is a disagreement, not a skip.
pub fn cmpct_drain_disconnects(err: &NetError) -> bool {
    matches!(
        err,
        NetError::Disconnected
            | NetError::Protocol(_)
            | NetError::V1Peer
            | NetError::Bip324(_)
            | NetError::MessageTooLarge(_)
    )
}

fn cmpct_drain_harness(err: &NetError) -> bool {
    matches!(
        err,
        NetError::Io(_)
            | NetError::Timeout
            | NetError::Store(_)
            | NetError::Cancelled
            | NetError::Encode(_)
    )
}

/// Full local reconstruct, when the compact case has one.
pub fn reconstructed_cmpct_block(case: &CmpctFuzzCase) -> Option<bitcoin::Block> {
    if !rbitcoin_net::cmpct_init_data_ok(&case.hsi) {
        return None;
    }
    let avail = shortid_map_from_txs(&case.hsi.header, case.hsi.nonce, 2, &case.fill_txs);
    try_reconstruct(&case.hsi, &avail).ok()
}

fn drain_one(hub: &ChainHub, block: bitcoin::Block) -> Result<(), NetError> {
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut pending = PendingBlocks::new();
    pending.insert(block.block_hash(), block);
    let mut headers = HashMap::new();
    let mut requested = HashSet::new();
    drain_pending_now(hub, &tx, &mut pending, &mut headers, &mut requested, true)
}

/// `invalidateblock` sticks for the life of this `bitcoind`. The next
/// `submitblock` of that header is `duplicate-invalid` or
/// `duplicate-inconclusive` until `reconsiderblock`.
fn submit_clearing_invalidate(
    oracle: &dyn BlockOracle,
    hex: &str,
    hash: &str,
) -> Result<OracleReply, CompareOne> {
    let reply = oracle.submitblock_hex(hex);
    let sticky = matches!(
        &reply,
        OracleReply::Reason(reason)
            if reason == "duplicate-invalid" || reason == "duplicate-inconclusive"
    );
    if !sticky {
        return Ok(reply);
    }
    oracle
        .core_reconsider_block(hash)
        .map_err(|_| CompareOne::Harness("reconsider"))?;
    Ok(oracle.submitblock_hex(hex))
}

fn follow_core_verdict(
    oracle: &dyn BlockOracle,
    hex: &str,
    hash: &str,
) -> Result<(DiffVerdict, String), CompareOne> {
    let reply = submit_clearing_invalidate(oracle, hex, hash)?;
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        return Err(CompareOne::Harness("oracle dead"));
    }
    let reason = match &reply {
        OracleReply::Reason(s) => s.clone(),
        _ => String::new(),
    };
    if matches!(reply, OracleReply::NullAccept) {
        return Ok((DiffVerdict::Accept, String::new()));
    }
    // `submitblock` returns "duplicate" on `!new_block && accepted` before the
    // state catcher. After `reconsiderblock` clears `BLOCK_FAILED_VALID`, a
    // heavier tip leaves the body stored and `getchaintips` says
    // `valid-headers`. Accept that reply only for an active chain or a valid
    // fork.
    if reason == "duplicate" {
        return match oracle.block_standing(hash) {
            Ok(BlockStanding::Active | BlockStanding::ValidFork) => {
                Ok((DiffVerdict::Accept, String::new()))
            }
            Ok(BlockStanding::NotConnected | BlockStanding::Invalid) => {
                Ok((DiffVerdict::Reject, reason))
            }
            Err(_) => Err(CompareOne::Harness("duplicate standing")),
        };
    }
    if reason == "duplicate-invalid" || reason == "duplicate-inconclusive" {
        return Ok((DiffVerdict::Reject, reason));
    }
    Ok((verdict_from_core_reply(&reply), reason))
}

/// Mutated compact body, then the honest block for that header, both through
/// `drain_pending_now`. Core sees the honest body only. A tip that stays put
/// is a hub reject, scored against Core's `submitblock` of that body.
pub fn follow_invalid_cmpct(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    mutated: bitcoin::Block,
    successor: bitcoin::Block,
) -> CompareOne {
    pin_cmpct_hub_clock(hub);
    let succ_hash = successor.block_hash();
    if let Err(e) = drain_one(hub, mutated) {
        return if cmpct_drain_harness(&e) {
            CompareOne::Harness("drain")
        } else {
            CompareOne::Disagreed {
                ours: false,
                core: true,
                hex: String::new(),
                reason: String::new(),
            }
        };
    }
    if let Err(e) = drain_one(hub, successor.clone()) {
        if cmpct_drain_harness(&e) {
            return CompareOne::Harness("drain successor");
        }
        if cmpct_drain_disconnects(&e) {
            return CompareOne::Disagreed {
                ours: false,
                core: true,
                hex: String::new(),
                reason: String::new(),
            };
        }
    }
    let hash = succ_hash.to_string();
    let hex = rbitcoin_primitives::hex_encode(&(serialize(&successor)));
    let (core, reason) = match follow_core_verdict(oracle, &hex, &hash) {
        Ok(v) => v,
        Err(fate) => return fate,
    };
    let hub_accept = hub.tip_hash() == Some(succ_hash) && !hub.is_block_invalid(&succ_hash);
    match (hub_accept, core) {
        (true, DiffVerdict::Accept) => CompareOne::Agreed { accept: true },
        (false, DiffVerdict::Reject) => CompareOne::Agreed { accept: false },
        (true, DiffVerdict::Reject) => CompareOne::Disagreed {
            ours: true,
            core: false,
            hex,
            reason,
        },
        (false, DiffVerdict::Accept) => CompareOne::Disagreed {
            ours: false,
            core: true,
            hex,
            reason,
        },
        (_, DiffVerdict::Skip) => CompareOne::Skipped,
    }
}

/// When this compact case reconstructs locally, drain a same-hash mutant and
/// then the honest body. `None` means there is no local body to replay.
pub fn follow_reconstructed_cmpct(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    case: &CmpctFuzzCase,
) -> Option<CompareOne> {
    let block = reconstructed_cmpct_block(case)?;
    let mutated = same_hash_merkle_mutant(&block)?;
    Some(follow_invalid_cmpct(hub, oracle, mutated, block))
}

/// Missing indexes using the case fill set (empty = mempool-cold).
pub fn cmpct_missing_for_case(case: &CmpctFuzzCase) -> Option<Vec<u64>> {
    if !rbitcoin_net::cmpct_init_data_ok(&case.hsi) {
        return None;
    }
    let avail = shortid_map_from_txs(&case.hsi.header, case.hsi.nonce, 2, &case.fill_txs);
    match try_reconstruct(&case.hsi, &avail) {
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
    let time = cmpct_header_time(genesis.header.time, extra_time);
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
    fn drain_disconnect_is_a_disagreement() {
        let err = NetError::Disconnected;
        assert!(cmpct_drain_disconnects(&err));
        assert!(!cmpct_drain_disconnects(&NetError::Timeout));
    }

    #[test]
    fn invalid_compact_then_honest_body_advances_the_tip() {
        use std::cell::Cell;

        use rbitcoin_consensus::{genesis_block, mine_regtest_paying, Milestone};
        use rbitcoin_net::ChainHub;

        struct Accepts {
            n: Cell<u32>,
        }
        impl BlockOracle for Accepts {
            fn submitblock_hex(&self, _hex: &str) -> OracleReply {
                self.n.set(self.n.get() + 1);
                OracleReply::NullAccept
            }
        }

        let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("cmpct-follow");
        let params = crate::block_diff::diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let genesis = genesis_block(&params);
        let honest = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![],
        );
        let mutated = same_hash_merkle_mutant(&honest).expect("mutant");
        let oracle = Accepts { n: Cell::new(0) };
        let fate = follow_invalid_cmpct(&hub, &oracle, mutated, honest.clone());
        assert!(
            matches!(fate, CompareOne::Agreed { accept: true }),
            "{fate:?}"
        );
        assert_eq!(hub.tip_hash(), Some(honest.block_hash()));
        assert!(!hub.is_block_invalid(&honest.block_hash()));
        assert_eq!(oracle.n.get(), 1);
    }

    #[test]
    fn honest_body_both_reject_is_not_a_core_accept() {
        use std::cell::Cell;

        use rbitcoin_consensus::{genesis_block, mine_regtest_paying, Milestone};
        use rbitcoin_net::ChainHub;

        struct Rejects {
            n: Cell<u32>,
        }
        impl BlockOracle for Rejects {
            fn submitblock_hex(&self, _hex: &str) -> OracleReply {
                self.n.set(self.n.get() + 1);
                OracleReply::Reason("bad-txns-inputs-missingorspent".into())
            }
        }

        let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("cmpct-follow-reject");
        let params = crate::block_diff::diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let genesis = genesis_block(&params);
        let mix = sha256::Hash::hash(b"no-connect");
        let honest = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![cmpct_fuzz_dummy_tx(mix, 0)],
        );
        let mutated = same_hash_merkle_mutant(&honest).expect("mutant");
        let oracle = Rejects { n: Cell::new(0) };
        let fate = follow_invalid_cmpct(&hub, &oracle, mutated, honest.clone());
        assert!(
            matches!(fate, CompareOne::Agreed { accept: false }),
            "{fate:?}"
        );
        assert_ne!(hub.tip_hash(), Some(honest.block_hash()));
        assert_eq!(oracle.n.get(), 1);
    }

    /// Core keeps `invalidateblock` on the header. The next honest submit of
    /// that header is `duplicate-invalid` until `reconsiderblock`.
    struct StickyInvalidate {
        reconsidered: std::cell::Cell<bool>,
        submits: std::cell::Cell<u32>,
        before: &'static str,
        after: OracleReply,
    }

    impl BlockOracle for StickyInvalidate {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            self.submits.set(self.submits.get() + 1);
            if self.reconsidered.get() {
                self.after.clone()
            } else {
                OracleReply::Reason(self.before.into())
            }
        }
        fn core_reconsider_block(&self, hash: &str) -> Result<(), &'static str> {
            assert_eq!(hash.len(), 64);
            self.reconsidered.set(true);
            Ok(())
        }
        fn block_standing(
            &self,
            hash: &str,
        ) -> Result<crate::block_diff::BlockStanding, &'static str> {
            assert_eq!(hash.len(), 64);
            Ok(crate::block_diff::BlockStanding::Active)
        }
    }

    fn follow_coinbase_only(label: &str, oracle: &dyn BlockOracle) -> CompareOne {
        use rbitcoin_consensus::{genesis_block, mine_regtest_paying, Milestone};
        use rbitcoin_net::ChainHub;

        let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
        let params = crate::block_diff::diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let genesis = genesis_block(&params);
        let honest = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 600,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![],
        );
        let mutated = same_hash_merkle_mutant(&honest).expect("mutant");
        follow_invalid_cmpct(&hub, oracle, mutated, honest)
    }

    /// `submitblock` answers BIP22 `duplicate` and reports chain standing.
    struct DuplicateStanding {
        standing: crate::block_diff::BlockStanding,
        submits: std::cell::Cell<u32>,
    }

    impl BlockOracle for DuplicateStanding {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            self.submits.set(self.submits.get() + 1);
            OracleReply::Reason("duplicate".into())
        }
        fn block_standing(
            &self,
            hash: &str,
        ) -> Result<crate::block_diff::BlockStanding, &'static str> {
            assert_eq!(hash.len(), 64);
            Ok(self.standing)
        }
    }

    /// v31.1, block already stored and `BLOCK_FAILED_VALID`, tip heavier than
    /// this header. After the compact announcement, `follow_reconstructed_cmpct`
    /// sees `duplicate-invalid`, `reconsiderblock`, then `duplicate`.
    /// `getchaintips` status is `valid-headers` (`NotConnected`).
    ///
    /// `ca87380a3` scored that `duplicate` as an accept with an empty reason:
    /// hub reject, Core accept. Standing makes it a reject.
    struct HeavierTipDuplicate {
        log: std::cell::RefCell<Vec<&'static str>>,
        scored: std::cell::RefCell<Option<OracleReply>>,
    }

    /// `ca87380a3` `follow_core_verdict`: JSON null or exact `duplicate` is an
    /// accept with an empty reason. `duplicate-invalid` is a reject.
    fn master_follow_accept(reply: &OracleReply) -> bool {
        let reason = match reply {
            OracleReply::Reason(s) => s.as_str(),
            _ => "",
        };
        matches!(reply, OracleReply::NullAccept) || reason == "duplicate"
    }

    impl BlockOracle for HeavierTipDuplicate {
        fn submitblock_hex(&self, hex: &str) -> OracleReply {
            assert!(hex.len() > 160, "honest body");
            let reply = if self.log.borrow().contains(&"reconsider") {
                self.log.borrow_mut().push("submit-duplicate");
                OracleReply::Reason("duplicate".into())
            } else {
                self.log.borrow_mut().push("submit-duplicate-invalid");
                OracleReply::Reason("duplicate-invalid".into())
            };
            *self.scored.borrow_mut() = Some(reply.clone());
            reply
        }
        fn core_reconsider_block(&self, hash: &str) -> Result<(), &'static str> {
            assert_eq!(
                hash,
                "65cf78f7756e9040065276fbbfc42c8c7fd07636edfde1eb703aa735bd274ca5"
            );
            self.log.borrow_mut().push("reconsider");
            Ok(())
        }
        fn block_standing(
            &self,
            hash: &str,
        ) -> Result<crate::block_diff::BlockStanding, &'static str> {
            assert_eq!(
                hash,
                "65cf78f7756e9040065276fbbfc42c8c7fd07636edfde1eb703aa735bd274ca5"
            );
            self.log.borrow_mut().push("standing-valid-headers");
            Ok(crate::block_diff::BlockStanding::NotConnected)
        }
    }

    /// Run 38145491136 input `[1, 221, 181]` through the shipped follow.
    #[test]
    fn seen_invalid_duplicate_is_not_a_core_accept() {
        use rbitcoin_consensus::Milestone;
        use rbitcoin_net::ChainHub;

        let data = [1u8, 221, 181];
        let case = prepare_cmpct_fuzz_case(&data).expect("recipe");
        let block = reconstructed_cmpct_block(&case).expect("reconstruct");
        assert_eq!(
            block.block_hash().to_string(),
            "65cf78f7756e9040065276fbbfc42c8c7fd07636edfde1eb703aa735bd274ca5"
        );
        assert_eq!(
            rbitcoin_primitives::hex_encode(
                &block.txdata[1].input[0]
                    .previous_output
                    .txid
                    .as_byte_array(),
            ),
            "9213e78bc5a99212e9a1ebf1ac29f173742cc203dde8f53447c390b78e209684"
        );
        assert_eq!(block.txdata[1].input[0].previous_output.vout, 0);

        let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("cmpct-seen-invalid");
        let params = crate::block_diff::diff_regtest_params();
        let hub = ChainHub::new(q, params, Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let oracle = HeavierTipDuplicate {
            log: std::cell::RefCell::new(Vec::new()),
            scored: std::cell::RefCell::new(None),
        };
        let fate = follow_reconstructed_cmpct(&hub, &oracle, &case).expect("follow");
        assert_eq!(
            oracle.log.borrow().as_slice(),
            [
                "submit-duplicate-invalid",
                "reconsider",
                "submit-duplicate",
                "standing-valid-headers",
            ]
        );
        let scored = oracle.scored.borrow().clone().expect("scored reply");
        assert!(
            master_follow_accept(&scored),
            "master would not have accepted {scored:?}"
        );
        assert_ne!(hub.tip_hash(), Some(block.block_hash()));
        assert!(
            matches!(fate, CompareOne::Agreed { accept: false }),
            "{fate:?}"
        );
    }

    #[test]
    fn active_coinbase_duplicate_stays_accept() {
        let oracle = DuplicateStanding {
            standing: crate::block_diff::BlockStanding::Active,
            submits: std::cell::Cell::new(0),
        };
        let fate = follow_coinbase_only("cmpct-dup-active", &oracle);
        assert!(
            matches!(fate, CompareOne::Agreed { accept: true }),
            "{fate:?}"
        );
        assert_eq!(oracle.submits.get(), 1);
    }

    #[test]
    fn duplicate_invalid_after_reconsider_agrees() {
        let oracle = StickyInvalidate {
            reconsidered: std::cell::Cell::new(false),
            submits: std::cell::Cell::new(0),
            before: "duplicate-invalid",
            after: OracleReply::Reason("duplicate".into()),
        };
        let fate = follow_coinbase_only("cmpct-follow-poison", &oracle);
        assert!(
            matches!(fate, CompareOne::Agreed { accept: true }),
            "{fate:?}"
        );
        assert!(oracle.reconsidered.get());
        assert_eq!(oracle.submits.get(), 2);
    }

    #[test]
    fn real_reject_after_reconsider_stays_a_split() {
        let oracle = StickyInvalidate {
            reconsidered: std::cell::Cell::new(false),
            submits: std::cell::Cell::new(0),
            before: "duplicate-invalid",
            after: OracleReply::Reason("bad-txnmrklroot".into()),
        };
        let fate = follow_coinbase_only("cmpct-follow-still-bad", &oracle);
        assert!(
            matches!(
                fate,
                CompareOne::Disagreed {
                    ours: true,
                    core: false,
                    ..
                }
            ),
            "{fate:?}"
        );
        assert!(format!("{fate:?}").contains("bad-txnmrklroot"), "{fate:?}");
        assert!(oracle.reconsidered.get());
        assert_eq!(oracle.submits.get(), 2);
    }

    /// `[1, 0, 0, 0]` and the overnight crasher `[253, 16]` both hash to a
    /// stamp past genesis + 2h. Core's mocktime is genesis.
    #[test]
    fn prepare_cmpct_stamp_stays_inside_core_mock_window() {
        let genesis = genesis_block(&ChainParams::regtest());
        let cap = genesis.header.time + 2 * 60 * 60;
        for data in [&[1u8, 0, 0, 0][..], &[253, 16][..]] {
            let case = prepare_cmpct_fuzz_case(data).expect("case");
            assert!(case.hsi.header.time > genesis.header.time, "{data:?}");
            assert!(
                case.hsi.header.time <= cap,
                "{data:?} time {} past cap {cap}",
                case.hsi.header.time
            );
        }
    }

    #[test]
    fn follow_past_mock_window_rejects_with_core() {
        use rbitcoin_consensus::{genesis_block, mine_regtest_paying, Milestone};
        use rbitcoin_net::ChainHub;

        let oracle = StickyInvalidate {
            reconsidered: std::cell::Cell::new(false),
            submits: std::cell::Cell::new(0),
            before: "time-too-new",
            after: OracleReply::Reason("time-too-new".into()),
        };
        let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("cmpct-follow-future");
        let params = crate::block_diff::diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let genesis = genesis_block(&params);
        let honest = mine_regtest_paying(
            genesis.block_hash(),
            genesis.header.time + 2 * 60 * 60 + 60,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![],
        );
        let mutated = same_hash_merkle_mutant(&honest).expect("mutant");
        let fate = follow_invalid_cmpct(&hub, &oracle, mutated, honest);
        assert!(
            matches!(fate, CompareOne::Agreed { accept: false }),
            "{fate:?}"
        );
    }

    #[test]
    fn duplicate_inconclusive_after_reconsider_agrees() {
        let oracle = StickyInvalidate {
            reconsidered: std::cell::Cell::new(false),
            submits: std::cell::Cell::new(0),
            before: "duplicate-inconclusive",
            after: OracleReply::NullAccept,
        };
        let fate = follow_coinbase_only("cmpct-follow-inconclusive", &oracle);
        assert!(
            matches!(fate, CompareOne::Agreed { accept: true }),
            "{fate:?}"
        );
        assert!(oracle.reconsidered.get());
        assert_eq!(oracle.submits.get(), 2);
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
            try_reconstruct(&case.hsi, &HashMap::<ShortId, Vec<&Transaction>>::new()).unwrap_err(),
            vec![1]
        );
    }

    #[test]
    fn overnight_dup_prefill_corrupt_missing_is_1_and_4() {
        // fuzz.yml 34852819510: `[2, 203, 4, 63]` → FLAG_FILL|DUP|CORRUPT,
        // 3 extras, prefill abs 3. Ours requests [1, 4]; Core extra-txn
        // filled the duplicate and only `getblocktxn` [1].
        let case = prepare_cmpct_fuzz_case(&[2, 203, 4, 63]).unwrap();
        assert!(cmpct_hsi_regtest_connectable(&case.hsi));
        assert_eq!(
            cmpct_missing_for_case(&case).as_deref(),
            Some(&[1u64, 4][..])
        );
        assert!(
            cmpct_getblocktxn_agrees(&[1, 4], &[1]),
            "018 extra missing vs Core extra-txn fill must not panic"
        );
        assert!(cmpct_getblocktxn_agrees(&[1], &[1]));
        assert!(
            cmpct_getblocktxn_agrees(&[1, 2], &[1]),
            "extra ours is the missing extra-txn ring"
        );
        assert!(cmpct_getblocktxn_agrees(&[2, 4], &[2]));
        assert!(!cmpct_getblocktxn_agrees(&[1], &[1, 4]));
        assert!(!cmpct_getblocktxn_agrees(&[], &[1]));
    }

    #[test]
    fn overnight_fill_dup_requests_2_and_4() {
        // fuzz.yml 35728126468: `[0, 251, 229, 55, 51, 13, 10]`
        // ours [2, 4], Core getblocktxn [2].
        let case = prepare_cmpct_fuzz_case(&[0, 251, 229, 55, 51, 13, 10]).unwrap();
        assert_eq!(
            cmpct_missing_for_case(&case).as_deref(),
            Some(&[2u64, 4][..])
        );
        assert!(cmpct_getblocktxn_agrees(&[2, 4], &[2]));
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
        assert_eq!(
            std::fs::read(fixture("cmpct_fuzz_dup_prefill_corrupt.bin")).unwrap(),
            [2, 203, 4, 63]
        );
        let mut raw = vec![7u8];
        raw.extend_from_slice(&std::fs::read(fixture("cmpct_h1_two_tx.bin")).unwrap());
        assert_eq!(std::fs::read(fixture("cmpct_fuzz_raw.bin")).unwrap(), raw);
    }
}
