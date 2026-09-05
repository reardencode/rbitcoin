//! Verdict-only block differential vs Core `submitblock`. Not a node RPC.

use crate::chain::{AcceptOutcome, ChainHub};
use crate::error::NetError;
use crate::peer::{drain_pending_now, PendingBlocks};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use rbitcoin_consensus::{
    genesis_block, mine_empty_regtest, mine_regtest_paying, prepare_regtest_candidate, ChainParams,
    REGTEST_BLOCK_SPACING,
};
use rbitcoin_primitives::hex_encode;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const CORE_SKIP: &[&str] = &[
    "bad-prevblk",
    "prev-blk-not-found",
    "inconclusive",
    "duplicate",
    "duplicate-invalid",
    "duplicate-inconclusive",
];

const CORE_DESYNC_SKIP: &[&str] = &["inconclusive", "bad-prevblk", "prev-blk-not-found"];
const CORE_DUPLICATE_SKIP: &[&str] = &["duplicate", "duplicate-invalid", "duplicate-inconclusive"];
/// Equal-work sibling is parked on Core (`inconclusive`) or already known.
const CORE_SIDE_STORED: &[&str] = &[
    "inconclusive",
    "duplicate",
    "duplicate-invalid",
    "duplicate-inconclusive",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffVerdict {
    Accept,
    Reject,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleReply {
    NullAccept,
    Reason(String),
    RpcError,
    Dead,
}

pub trait BlockOracle {
    fn submitblock_hex(&self, hex: &str) -> OracleReply;
    fn liveness_ok(&self) -> bool;
    fn core_rewind_to_height(&self, keep: u32) -> Result<(), &'static str>;
    /// Undo `invalidateblock` (sticky). Unknown hash may error; callers ignore.
    fn core_reconsider_block(&self, hash: &str) -> Result<(), &'static str>;
    fn core_invalidate_hash(&self, hash: &str) -> Result<(), &'static str>;
    fn core_precious_block(&self, hash: &str) -> Result<(), &'static str>;
    /// Core `testmempoolaccept` on one hex tx. Default unused.
    fn testmempoolaccept_hex(&self, hex: &str) -> OracleReply {
        let _ = hex;
        OracleReply::RpcError
    }
}

pub const DIFF_TEST_PAD_HEIGHT: u32 = 3;
pub const DIFF_MATURE_PAD_HEIGHT: u32 = 100;
/// Side-chain length vs a 1-block stem (deeper than the 2-block fork target).
pub const DIFF_REORG_N: u32 = 3;
/// Core `MAX_SCRIPT_SIZE` — truncate fuzzer scriptPubKey, do not skip.
pub const SCRIPT_FUZZ_MAX: usize = 10_000;
pub const DIFF_MUT_VERSION: u8 = 0x01;
pub const DIFF_MUT_LOCKTIME: u8 = 0x02;
pub const DIFF_MUT_SEQUENCE: u8 = 0x04;
pub const DIFF_MUT_SCRIPT_SIG: u8 = 0x08;
pub const DIFF_MUT_WITNESS: u8 = 0x10;
pub const DIFF_MUT_ANNEX: u8 = 0x20;
pub const DIFF_MUT_SHUFFLE: u8 = 0x40;
/// `prepare_script_candidate` prefix: version + witness then scriptPubKey.
pub const SCRIPT_FUZZ_CTRL: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffTip {
    pub hash: BlockHash,
    pub time: u32,
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct DiffPad {
    pub tip: DiffTip,
    pub fork_parent: DiffTip,
    pub mature: OutPoint,
    pub bodies: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOne {
    NotABlock,
    Skipped,
    Agreed { accept: bool },
    Disagreed { ours: bool, core: bool, hex: String },
    Harness(&'static str),
}

pub fn diff_regtest_params() -> ChainParams {
    let mut params = ChainParams::regtest();
    params
        .apply_test_activation_height("bip34", 1)
        .expect("regtest overlay");
    params
}

pub fn genesis_diff_tip(params: &ChainParams) -> DiffTip {
    let g = genesis_block(params);
    DiffTip {
        hash: g.block_hash(),
        time: g.header.time,
        height: 0,
    }
}

pub fn mine_diff_pad(hub: &ChainHub, last: u32) -> Result<DiffPad, &'static str> {
    if last < 1 {
        return Err("pad last");
    }
    let params = diff_regtest_params();
    let g = genesis_block(&params);
    let mut hash = g.block_hash();
    let mut time = g.header.time;
    let mut bodies = Vec::with_capacity(last as usize);
    let mut mature = None;
    for h in 1..=last {
        let b = mine_empty_regtest(hash, time.saturating_add(REGTEST_BLOCK_SPACING), h);
        match hub.accept_received_block(b.clone()) {
            Ok(AcceptOutcome::Accepted { height }) if height == h => {}
            _ => return Err("pad accept"),
        }
        if h == 1 {
            mature = Some(OutPoint {
                txid: b.txdata[0].compute_txid(),
                vout: 0,
            });
        }
        hash = b.block_hash();
        time = b.header.time;
        bodies.push(b);
    }
    let tip = DiffTip {
        hash,
        time,
        height: last,
    };
    Ok(DiffPad {
        fork_parent: tip.clone(),
        tip,
        mature: mature.ok_or("pad mature")?,
        bodies,
    })
}

pub fn mine_diff_stem(hub: &ChainHub, pad: DiffPad) -> Result<DiffPad, &'static str> {
    let h = pad.tip.height.saturating_add(1);
    let b = mine_empty_regtest(
        pad.tip.hash,
        pad.tip.time.saturating_add(REGTEST_BLOCK_SPACING),
        h,
    );
    match hub.accept_received_block(b.clone()) {
        Ok(AcceptOutcome::Accepted { height }) if height == h => {}
        _ => return Err("stem accept"),
    }
    let mut bodies = pad.bodies;
    bodies.push(b.clone());
    Ok(DiffPad {
        fork_parent: pad.tip,
        tip: DiffTip {
            hash: b.block_hash(),
            time: b.header.time,
            height: h,
        },
        mature: pad.mature,
        bodies,
    })
}

fn submit_known_block(
    oracle: &dyn BlockOracle,
    block: &Block,
    stored: &[&str],
    err: &'static str,
    uninvalidate: bool,
) -> Result<(), &'static str> {
    let hash = block.block_hash().to_string();
    if uninvalidate {
        let _ = oracle.core_reconsider_block(&hash);
    }
    let hex = hex_encode(serialize(block));
    match oracle.submitblock_hex(&hex) {
        OracleReply::NullAccept => Ok(()),
        OracleReply::Reason(r) if stored.contains(&r.as_str()) => {
            if uninvalidate && (r == "duplicate-invalid" || r == "duplicate-inconclusive") {
                oracle.core_reconsider_block(&hash)?;
            }
            Ok(())
        }
        _ => Err(err),
    }
}

pub fn setup_side_block(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    block: &Block,
) -> Result<(), &'static str> {
    match hub.accept_received_block(block.clone()) {
        Ok(AcceptOutcome::IgnoredWeaker | AcceptOutcome::AlreadyHave) => {}
        Ok(AcceptOutcome::Accepted { .. }) => return Err("side became tip"),
        Err(_) => return Err("side reject"),
    }
    submit_known_block(oracle, block, CORE_SIDE_STORED, "side submit", false)
}

/// Core-only side submit. Hub must not `accept_received_block` the sibling
/// before child-first `drain_pending` (014 / 020).
pub fn submit_side_to_oracle(oracle: &dyn BlockOracle, block: &Block) -> Result<(), &'static str> {
    submit_known_block(oracle, block, CORE_SIDE_STORED, "side submit", false)
}

pub fn submit_pad_to_oracle(
    oracle: &dyn BlockOracle,
    bodies: &[Block],
) -> Result<(), &'static str> {
    for b in bodies {
        let hex = hex_encode(serialize(b));
        match oracle.submitblock_hex(&hex) {
            OracleReply::NullAccept => {}
            _ => return Err("pad submit"),
        }
    }
    Ok(())
}

fn default_spend_in(mature: OutPoint) -> TxIn {
    TxIn {
        previous_output: mature,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn default_op_true_spend(mature: OutPoint, uniq: u32) -> Transaction {
    let mut spk = vec![0x51];
    if uniq != 0 {
        spk.extend_from_slice(&uniq.to_le_bytes());
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![default_spend_in(mature)],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    }
}

fn next_diff_cb_uniq() -> u32 {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// BIP34 extra-nonce. Same-height coinbase txid + new create_fk fills one OA page.
fn stamp_diff_coinbase(block: &mut Block, uniq: u32) {
    if uniq == 0 || block.txdata.is_empty() || block.txdata[0].input.is_empty() {
        return;
    }
    let extra = uniq.to_le_bytes();
    let ss = block.txdata[0].input[0].script_sig.as_bytes();
    if ss.len() + extra.len() <= 100 {
        let mut v = ss.to_vec();
        v.extend_from_slice(&extra);
        block.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(v);
    } else if let Some(out) = block.txdata[0].output.first_mut() {
        let mut spk = out.script_pubkey.to_bytes();
        spk.extend_from_slice(&extra);
        out.script_pubkey = ScriptBuf::from_bytes(spk);
    }
}

fn remine_diff_header(block: &mut Block) {
    let prev = block.header.prev_blockhash;
    let time = block.header.time;
    prepare_regtest_candidate(block, prev, time);
}

fn stamp_diff_out(tx: &mut Transaction, uniq: u32) {
    if uniq == 0 || tx.output.is_empty() {
        return;
    }
    let extra = uniq.to_le_bytes();
    let mut spk = tx.output[0].script_pubkey.to_bytes();
    spk.extend_from_slice(&extra);
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(spk);
}

fn ctrl_take<'a>(ctrl: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if ctrl.len() < n {
        return None;
    }
    let (h, t) = ctrl.split_at(n);
    *ctrl = t;
    Some(h)
}

fn ctrl_u8(ctrl: &mut &[u8]) -> Option<u8> {
    let b = ctrl_take(ctrl, 1)?;
    Some(b[0])
}

fn ctrl_u32_le(ctrl: &mut &[u8]) -> Option<u32> {
    let b = ctrl_take(ctrl, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Overlay consensus fields on extra txs from fuzzer control bytes.
pub fn apply_diff_field_mutations(txs: &mut [Transaction], mut ctrl: &[u8]) {
    if txs.is_empty() {
        return;
    }
    let Some(flags) = ctrl_u8(&mut ctrl) else {
        return;
    };
    if flags & DIFF_MUT_VERSION != 0 {
        if let Some(v) = ctrl_u32_le(&mut ctrl) {
            let ver = TxVersion::non_standard(v as i32);
            for tx in txs.iter_mut() {
                tx.version = ver;
            }
        }
    }
    if flags & DIFF_MUT_LOCKTIME != 0 {
        if let Some(n) = ctrl_u32_le(&mut ctrl) {
            let lt = LockTime::from_consensus(n);
            for tx in txs.iter_mut() {
                tx.lock_time = lt;
            }
        }
    }
    if flags & DIFF_MUT_SEQUENCE != 0 {
        if let Some(n) = ctrl_u32_le(&mut ctrl) {
            let seq = Sequence::from_consensus(n);
            for tx in txs.iter_mut() {
                if let Some(i) = tx.input.first_mut() {
                    i.sequence = seq;
                }
            }
        }
    }
    if flags & DIFF_MUT_SCRIPT_SIG != 0 {
        if let Some(n) = ctrl_u8(&mut ctrl) {
            if let Some(bytes) = ctrl_take(&mut ctrl, n as usize) {
                let ss = ScriptBuf::from_bytes(bytes.to_vec());
                for tx in txs.iter_mut() {
                    if let Some(i) = tx.input.first_mut() {
                        i.script_sig = ss.clone();
                    }
                }
            }
        }
    }
    if flags & DIFF_MUT_WITNESS != 0 {
        if let Some(n_items) = ctrl_u8(&mut ctrl) {
            let mut items = Vec::new();
            let mut ok = true;
            for _ in 0..n_items {
                let Some(n) = ctrl_u8(&mut ctrl) else {
                    ok = false;
                    break;
                };
                let Some(bytes) = ctrl_take(&mut ctrl, n as usize) else {
                    ok = false;
                    break;
                };
                items.push(bytes.to_vec());
            }
            if ok {
                let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
                let w = Witness::from_slice(&refs);
                for tx in txs.iter_mut() {
                    if let Some(i) = tx.input.first_mut() {
                        i.witness = w.clone();
                    }
                }
            }
        }
    }
    if flags & DIFF_MUT_ANNEX != 0 {
        if let Some(n) = ctrl_u8(&mut ctrl) {
            if let Some(bytes) = ctrl_take(&mut ctrl, n as usize) {
                let mut annex = vec![0x50];
                annex.extend_from_slice(bytes);
                for tx in txs.iter_mut() {
                    if let Some(i) = tx.input.first_mut() {
                        i.witness.push(annex.clone());
                    }
                }
            }
        }
    }
    if flags & DIFF_MUT_SHUFFLE != 0 {
        if let Some(rot) = ctrl_u8(&mut ctrl) {
            let n = txs.len();
            if n > 1 {
                let k = (rot as usize) % n;
                txs.rotate_left(k);
            }
        }
    }
}

fn mutation_ctrl(data: &[u8]) -> &[u8] {
    const N: usize = 16;
    if data.len() > N {
        &data[data.len() - N..]
    } else {
        data
    }
}

pub fn parse_script_fuzz_ctrl(data: &[u8]) -> (TxVersion, Witness, &[u8]) {
    if data.first() != Some(&SCRIPT_FUZZ_CTRL) || data.len() < 7 {
        return (TxVersion::ONE, Witness::new(), data);
    }
    let ver = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let mut rest = &data[5..];
    let Some(n_items) = ctrl_u8(&mut rest) else {
        return (TxVersion::ONE, Witness::new(), data);
    };
    let mut items = Vec::new();
    for _ in 0..n_items {
        let Some(n) = ctrl_u8(&mut rest) else {
            return (TxVersion::ONE, Witness::new(), data);
        };
        let Some(bytes) = ctrl_take(&mut rest, n as usize) else {
            return (TxVersion::ONE, Witness::new(), data);
        };
        items.push(bytes.to_vec());
    }
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    (
        TxVersion::non_standard(ver),
        Witness::from_slice(&refs),
        rest,
    )
}

fn mine_diff_paying(
    prev: BlockHash,
    time: u32,
    height: u32,
    script_pubkey: ScriptBuf,
    extra_txs: Vec<Transaction>,
) -> Block {
    let mut b = mine_regtest_paying(prev, time, height, script_pubkey, extra_txs);
    stamp_diff_coinbase(&mut b, next_diff_cb_uniq());
    remine_diff_header(&mut b);
    b
}

pub fn prepare_spend_candidate(tip: &DiffTip, mature: OutPoint, data: &[u8]) -> Option<Block> {
    let parsed: Block = deserialize(data).ok()?;
    if parsed.txdata.is_empty() {
        return None;
    }
    let height = tip.height.saturating_add(1);
    let mut spend = parsed
        .txdata
        .get(1)
        .cloned()
        .unwrap_or_else(|| default_op_true_spend(mature, 0));
    if spend.input.is_empty() {
        spend.input.push(default_spend_in(mature));
    } else {
        spend.input[0].previous_output = mature;
    }
    let mut extra: Vec<Transaction> = parsed.txdata.into_iter().skip(2).collect();
    apply_diff_field_mutations(&mut extra, mutation_ctrl(data));
    let uniq = next_diff_cb_uniq();
    stamp_diff_out(&mut spend, uniq);
    for tx in extra.iter_mut() {
        stamp_diff_out(tx, uniq);
    }
    let mut txs = Vec::with_capacity(1 + extra.len());
    txs.push(spend);
    txs.extend(extra);
    Some(mine_diff_paying(
        tip.hash,
        tip.time.saturating_add(REGTEST_BLOCK_SPACING),
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        txs,
    ))
}

/// Height-n+1 block: spend mature OP_TRUE into `data` as scriptPubKey, then spend that.
pub fn prepare_script_candidate(tip: &DiffTip, mature: OutPoint, data: &[u8]) -> Option<Block> {
    if data.is_empty() {
        return None;
    }
    let (version, witness, rest) = parse_script_fuzz_ctrl(data);
    if rest.is_empty() {
        return None;
    }
    let script = if rest.len() > SCRIPT_FUZZ_MAX {
        &rest[..SCRIPT_FUZZ_MAX]
    } else {
        rest
    };
    let tx1 = Transaction {
        version,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: mature,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
        }],
    };
    let mut tx2 = Transaction {
        version,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx1.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(48_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    stamp_diff_out(&mut tx2, next_diff_cb_uniq());
    Some(mine_diff_paying(
        tip.hash,
        tip.time.saturating_add(REGTEST_BLOCK_SPACING),
        tip.height.saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![tx1, tx2],
    ))
}

/// Spend `mature` with BIP68 relative-height `nSequence` (tx version 2).
pub fn prepare_csv_age_candidate(tip: &DiffTip, mature: OutPoint, data: &[u8]) -> Option<Block> {
    if data.is_empty() {
        return None;
    }
    let rel = if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]])
    } else {
        u16::from(data[0])
    };
    let mut spend = default_op_true_spend(mature, next_diff_cb_uniq());
    spend.version = TxVersion::TWO;
    spend.input[0].sequence = Sequence::from_consensus(u32::from(rel));
    Some(mine_diff_paying(
        tip.hash,
        tip.time.saturating_add(REGTEST_BLOCK_SPACING),
        tip.height.saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    ))
}

pub fn compare_csv_age_one(
    hub: &ChainHub,
    tip: &mut DiffTip,
    oracle: &dyn BlockOracle,
    mature: OutPoint,
    data: &[u8],
) -> CompareOne {
    let Some(block) = prepare_csv_age_candidate(tip, mature, data) else {
        return CompareOne::NotABlock;
    };
    compare_prepared(hub, tip, oracle, block)
}

/// Libre policy vs Core is COMPAT, not a finding. Only consensus-class splits.
pub fn is_core_mempool_policy_skip(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("min relay")
        || r.contains("minrelay")
        || r.contains("dust")
        || r.contains("insufficient fee")
        || r.contains("too-long-mempool")
        || r.contains("too-many-unconfirmed")
        || r.contains("mempool-conflict")
        || r.contains("replacement")
        || r.contains("max-fee")
        || r.contains("absurdly-high-fee")
        || r.contains("policy")
}

fn mempool_ours_consensus(
    r: Result<rbitcoin_mempool::AcceptResult, rbitcoin_mempool::AcceptError>,
) -> Result<DiffVerdict, &'static str> {
    use rbitcoin_mempool::AcceptError;
    match r {
        Ok(_) => Ok(DiffVerdict::Accept),
        Err(
            AcceptError::Policy(_)
            | AcceptError::ClusterTooLarge { .. }
            | AcceptError::PackageTooLarge { .. }
            | AcceptError::PackageEmpty
            | AcceptError::PackageNotTopo
            | AcceptError::RbfInsufficient
            | AcceptError::Orphaned(_)
            | AcceptError::Duplicate(_),
        ) => Ok(DiffVerdict::Skip),
        Err(AcceptError::Durable(_)) => Err("harness"),
        Err(_) => Ok(DiffVerdict::Reject),
    }
}

pub fn parse_testmempoolaccept_json(body: &str) -> Result<OracleReply, &'static str> {
    let body = body.trim();
    if json_field_is_error_object(body) {
        return Err("rpc error");
    }
    if body.contains("\"allowed\": true") || body.contains("\"allowed\":true") {
        return Ok(OracleReply::NullAccept);
    }
    if body.contains("\"allowed\": false") || body.contains("\"allowed\":false") {
        if let Some(r) = after_key(body, "reject-reason") {
            if r.starts_with('"') {
                if let Some(s) = json_quoted(r) {
                    return Ok(OracleReply::Reason(s));
                }
            }
        }
        return Ok(OracleReply::Reason("rejected".into()));
    }
    Err("malformed")
}

pub fn compare_mempool_one(
    hub: &ChainHub,
    tip: &DiffTip,
    oracle: &dyn BlockOracle,
    mature: OutPoint,
    data: &[u8],
) -> CompareOne {
    let Some(mp) = hub.mempool() else {
        return CompareOne::Harness("no mempool");
    };
    let Some(block) = prepare_spend_candidate(tip, mature, data) else {
        return CompareOne::NotABlock;
    };
    let Some(tx) = block.txdata.get(1).cloned() else {
        return CompareOne::NotABlock;
    };
    let ours = match mempool_ours_consensus(mp.test_accept(&tx)) {
        Ok(v) => v,
        Err(msg) => return CompareOne::Harness(msg),
    };
    let hex = hex_encode(serialize(&tx));
    let reply = oracle.testmempoolaccept_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        return CompareOne::Harness("oracle dead");
    }
    let core = match &reply {
        OracleReply::NullAccept => DiffVerdict::Accept,
        OracleReply::Reason(r) if is_core_mempool_policy_skip(r) => DiffVerdict::Skip,
        OracleReply::Reason(_) => DiffVerdict::Reject,
        OracleReply::RpcError | OracleReply::Dead => DiffVerdict::Skip,
    };
    match (ours, core) {
        (DiffVerdict::Accept, DiffVerdict::Accept) => CompareOne::Agreed { accept: true },
        (DiffVerdict::Reject, DiffVerdict::Reject) => CompareOne::Agreed { accept: false },
        (DiffVerdict::Skip, _) | (_, DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Accept, DiffVerdict::Reject) | (DiffVerdict::Reject, DiffVerdict::Accept) => {
            CompareOne::Disagreed {
                ours: ours == DiffVerdict::Accept,
                core: core == DiffVerdict::Accept,
                hex,
            }
        }
    }
}

pub fn is_core_connectivity_skip(reason: &str) -> bool {
    CORE_SKIP.contains(&reason)
}

pub fn verdict_from_core_reply(reply: &OracleReply) -> DiffVerdict {
    match reply {
        OracleReply::NullAccept => DiffVerdict::Accept,
        OracleReply::Reason(r) if is_core_connectivity_skip(r) => DiffVerdict::Skip,
        OracleReply::Reason(_) => DiffVerdict::Reject,
        OracleReply::RpcError => DiffVerdict::Skip,
        OracleReply::Dead => DiffVerdict::Skip,
    }
}

pub fn verdict_from_accept(
    r: Result<AcceptOutcome, NetError>,
) -> Result<DiffVerdict, &'static str> {
    match r {
        Ok(AcceptOutcome::Accepted { .. }) => Ok(DiffVerdict::Accept),
        Ok(AcceptOutcome::AlreadyHave | AcceptOutcome::IgnoredWeaker) => Ok(DiffVerdict::Skip),
        Err(NetError::Protocol(_) | NetError::Consensus(_)) => Ok(DiffVerdict::Reject),
        Err(NetError::Io(_) | NetError::Timeout | NetError::Disconnected) => Err("harness"),
        Err(_) => Err("harness"),
    }
}

/// Invalidate the current tip until `height == keep`.
///
/// Core keeps every `submitblock` body. Invalidating the tip can activate
/// another already-submitted sibling at the **same** height, so progress is a
/// **hash** change, not a height drop. Stop if one invalidate leaves the same
/// tip hash (stuck). No 128-step cap.
pub fn rewind_oracle_until(
    keep: u32,
    mut tip: impl FnMut() -> Result<(u32, String), &'static str>,
    mut invalidate: impl FnMut(&str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    loop {
        let (n, hash) = tip()?;
        if n == keep {
            return Ok(());
        }
        if n < keep {
            return Err("core below pad");
        }
        invalidate(&hash)?;
        let (_, hash2) = tip()?;
        if hash2 == hash {
            return Err("invalidate no progress");
        }
    }
}

pub fn parse_submitblock_json(body: &str) -> Result<Option<String>, &'static str> {
    let body = body.trim();
    if json_field_is_error_object(body) {
        return Err("rpc error");
    }
    match json_result_token(body) {
        Some(JsonTok::Null) => Ok(None),
        Some(JsonTok::String(s)) => Ok(Some(s)),
        _ => Err("malformed"),
    }
}

enum JsonTok {
    Null,
    String(String),
}

fn json_result_token(body: &str) -> Option<JsonTok> {
    let rest = after_key(body, "result")?;
    if rest.starts_with("null") {
        return Some(JsonTok::Null);
    }
    if rest.starts_with('"') {
        return Some(JsonTok::String(json_quoted(rest)?));
    }
    None
}

fn json_field_is_error_object(body: &str) -> bool {
    match after_key(body, "error") {
        Some(rest) => rest.starts_with('{'),
        None => false,
    }
}

fn after_key<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let i = body.find(&needle)?;
    let rest = body[i + needle.len()..].trim_start();
    rest.strip_prefix(':').map(str::trim_start)
}

fn json_quoted(rest: &str) -> Option<String> {
    let b = rest.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some(out),
            b'\\' if i + 1 < b.len() => {
                out.push(b[i + 1] as char);
                i += 2;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    None
}

pub fn check_diff_env(head: Option<&str>, io: Option<&str>) -> Result<(), &'static str> {
    match head {
        Some("tiny" | "test" | "small") => {}
        Some(_) => return Err("RBITCOIN_HEAD_SCALE"),
        None => return Err("RBITCOIN_HEAD_SCALE"),
    }
    match io {
        Some("fd" | "pread" | "libc" | "pwrite") => Ok(()),
        _ => Err("RBITCOIN_IO"),
    }
}

pub fn wait_for_file(path: &Path, deadline: Instant) -> Result<(), &'static str> {
    while Instant::now() < deadline {
        if path.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if path.is_file() {
        Ok(())
    } else {
        Err("timeout")
    }
}

pub fn split_http_body(raw: &[u8]) -> Result<&[u8], &'static str> {
    const SEP: &[u8] = b"\r\n\r\n";
    let Some(i) = raw.windows(SEP.len()).position(|w| w == SEP) else {
        return Err("no header separator");
    };
    Ok(&raw[i + SEP.len()..])
}

pub fn basic_auth_b64(user: &str, pass: &str) -> String {
    base64_encode(format!("{user}:{pass}").as_bytes())
}

pub fn build_jsonrpc_http_request(
    host: &str,
    auth_b64: &str,
    method: &str,
    params_json: &str,
) -> Vec<u8> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params_json}}}"#);
    let mut out = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth_b64}\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(T[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn compare_one(
    hub: &ChainHub,
    tip: &mut DiffTip,
    oracle: &dyn BlockOracle,
    data: &[u8],
) -> CompareOne {
    let Ok(mut block) = deserialize::<Block>(data) else {
        return CompareOne::NotABlock;
    };
    if block.txdata.is_empty() {
        return CompareOne::NotABlock;
    }
    if block.txdata.len() > 1 {
        let n = block.txdata.len();
        apply_diff_field_mutations(&mut block.txdata[1..n], mutation_ctrl(data));
    }
    let uniq = next_diff_cb_uniq();
    for tx in block.txdata.iter_mut().skip(1) {
        stamp_diff_out(tx, uniq);
    }
    prepare_regtest_candidate(
        &mut block,
        tip.hash,
        tip.time.saturating_add(REGTEST_BLOCK_SPACING),
    );
    stamp_diff_coinbase(&mut block, uniq);
    remine_diff_header(&mut block);
    compare_prepared(hub, tip, oracle, block)
}

pub fn compare_spend_one(
    hub: &ChainHub,
    tip: &mut DiffTip,
    oracle: &dyn BlockOracle,
    mature: OutPoint,
    data: &[u8],
) -> CompareOne {
    let Some(block) = prepare_spend_candidate(tip, mature, data) else {
        return CompareOne::NotABlock;
    };
    compare_prepared(hub, tip, oracle, block)
}

pub fn compare_script_one(
    hub: &ChainHub,
    tip: &mut DiffTip,
    oracle: &dyn BlockOracle,
    mature: OutPoint,
    data: &[u8],
) -> CompareOne {
    let Some(block) = prepare_script_candidate(tip, mature, data) else {
        return CompareOne::NotABlock;
    };
    compare_prepared(hub, tip, oracle, block)
}

fn restore_stem(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    stem: &Block,
) -> Result<(), &'static str> {
    match hub.accept_received_block(stem.clone()) {
        Ok(AcceptOutcome::Accepted { .. } | AcceptOutcome::AlreadyHave) => {}
        _ => return Err("stem restore"),
    }
    submit_known_block(
        oracle,
        stem,
        CORE_DUPLICATE_SKIP,
        "stem restore submit",
        true,
    )
}

pub fn compare_fork_one(
    hub: &ChainHub,
    base: &DiffPad,
    oracle: &dyn BlockOracle,
    data: &[u8],
) -> CompareOne {
    let Ok(parsed) = deserialize::<Block>(data) else {
        return CompareOne::NotABlock;
    };
    if parsed.txdata.is_empty() {
        return CompareOne::NotABlock;
    }
    let Some(stem) = base.bodies.last() else {
        return CompareOne::Harness("no stem");
    };
    let side = mine_regtest_paying(
        base.fork_parent.hash,
        base.fork_parent.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51, 0x51]),
        Vec::new(),
    );
    if let Err(e) = setup_side_block(hub, oracle, &side) {
        return CompareOne::Harness(e);
    }
    let mut extra: Vec<Transaction> = parsed.txdata.into_iter().skip(1).collect();
    apply_diff_field_mutations(&mut extra, mutation_ctrl(data));
    let uniq = next_diff_cb_uniq();
    for tx in extra.iter_mut() {
        stamp_diff_out(tx, uniq);
    }
    let child = mine_diff_paying(
        side.block_hash(),
        side.header.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(2),
        ScriptBuf::from_bytes(vec![0x51]),
        extra,
    );
    let ours = match verdict_from_accept(hub.accept_received_block(child.clone())) {
        Ok(v) => v,
        Err(msg) => return CompareOne::Harness(msg),
    };
    let hex = hex_encode(serialize(&child));
    let reply = oracle.submitblock_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        if ours == DiffVerdict::Accept {
            let _ = hub.rewind_to_height(base.fork_parent.height);
        }
        let _ = core_park_child(oracle, &child, stem);
        let _ = restore_stem(hub, oracle, stem);
        return CompareOne::Harness("oracle dead");
    }
    finish_reorg_compare(
        hub,
        oracle,
        base.fork_parent.height,
        stem,
        &child,
        ours,
        &reply,
    )
}

pub fn compare_fork_n_one(
    hub: &ChainHub,
    base: &DiffPad,
    oracle: &dyn BlockOracle,
    data: &[u8],
    n: u32,
) -> CompareOne {
    let n = n.max(DIFF_REORG_N);
    let Ok(parsed) = deserialize::<Block>(data) else {
        return CompareOne::NotABlock;
    };
    if parsed.txdata.is_empty() {
        return CompareOne::NotABlock;
    }
    let Some(stem) = base.bodies.last() else {
        return CompareOne::Harness("no stem");
    };
    let mut side = mine_regtest_paying(
        base.fork_parent.hash,
        base.fork_parent.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51, 0x51]),
        Vec::new(),
    );
    if let Err(e) = setup_side_block(hub, oracle, &side) {
        return CompareOne::Harness(e);
    }
    for i in 2..n {
        let h = base.fork_parent.height.saturating_add(i);
        let nxt = mine_empty_regtest(
            side.block_hash(),
            side.header.time.saturating_add(REGTEST_BLOCK_SPACING),
            h,
        );
        match hub.accept_received_block(nxt.clone()) {
            Ok(AcceptOutcome::Accepted { .. } | AcceptOutcome::AlreadyHave) => {}
            _ => return CompareOne::Harness("side extend"),
        }
        if submit_known_block(
            oracle,
            &nxt,
            CORE_DUPLICATE_SKIP,
            "side extend submit",
            false,
        )
        .is_err()
        {
            return CompareOne::Harness("side extend submit");
        }
        side = nxt;
    }
    let mut extra: Vec<Transaction> = parsed.txdata.into_iter().skip(1).collect();
    apply_diff_field_mutations(&mut extra, mutation_ctrl(data));
    let uniq = next_diff_cb_uniq();
    for tx in extra.iter_mut() {
        stamp_diff_out(tx, uniq);
    }
    let child = mine_diff_paying(
        side.block_hash(),
        side.header.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(n),
        ScriptBuf::from_bytes(vec![0x51]),
        extra,
    );
    let ours = match verdict_from_accept(hub.accept_received_block(child.clone())) {
        Ok(v) => v,
        Err(msg) => return CompareOne::Harness(msg),
    };
    let hex = hex_encode(serialize(&child));
    let reply = oracle.submitblock_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        if ours == DiffVerdict::Accept {
            let _ = hub.rewind_to_height(base.fork_parent.height);
        }
        let _ = oracle.core_rewind_to_height(base.fork_parent.height);
        let _ = restore_stem(hub, oracle, stem);
        return CompareOne::Harness("oracle dead");
    }
    finish_reorg_compare(
        hub,
        oracle,
        base.fork_parent.height,
        stem,
        &child,
        ours,
        &reply,
    )
}

pub fn compare_cmpct_reorg_one(
    hub: &ChainHub,
    base: &DiffPad,
    oracle: &dyn BlockOracle,
    data: &[u8],
) -> CompareOne {
    let Ok(parsed) = deserialize::<Block>(data) else {
        return CompareOne::NotABlock;
    };
    if parsed.txdata.is_empty() {
        return CompareOne::NotABlock;
    }
    let Some(stem) = base.bodies.last() else {
        return CompareOne::Harness("no stem");
    };
    let side = mine_regtest_paying(
        base.fork_parent.hash,
        base.fork_parent.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51, 0x51]),
        Vec::new(),
    );
    if let Err(e) = submit_side_to_oracle(oracle, &side) {
        return CompareOne::Harness(e);
    }
    let mut extra: Vec<Transaction> = parsed.txdata.into_iter().skip(1).collect();
    apply_diff_field_mutations(&mut extra, mutation_ctrl(data));
    let uniq = next_diff_cb_uniq();
    for tx in extra.iter_mut() {
        stamp_diff_out(tx, uniq);
    }
    let child = mine_diff_paying(
        side.block_hash(),
        side.header.time.saturating_add(REGTEST_BLOCK_SPACING),
        base.fork_parent.height.saturating_add(2),
        ScriptBuf::from_bytes(vec![0x51]),
        extra,
    );
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut pending = PendingBlocks::new();
    pending.insert(child.block_hash(), child.clone());
    pending.insert(side.block_hash(), side);
    let mut headers = HashMap::new();
    let mut requested = HashSet::new();
    if drain_pending_now(hub, &tx, &mut pending, &mut headers, &mut requested, true).is_err() {
        return CompareOne::Harness("drain");
    }
    let ours = if hub.tip_hash() == Some(child.block_hash()) {
        DiffVerdict::Accept
    } else {
        DiffVerdict::Reject
    };
    let hex = hex_encode(serialize(&child));
    let reply = oracle.submitblock_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        if ours == DiffVerdict::Accept {
            let _ = hub.rewind_to_height(base.fork_parent.height);
        }
        let _ = core_park_child(oracle, &child, stem);
        let _ = restore_stem(hub, oracle, stem);
        return CompareOne::Harness("oracle dead");
    }
    finish_reorg_compare(
        hub,
        oracle,
        base.fork_parent.height,
        stem,
        &child,
        ours,
        &reply,
    )
}

fn core_desync_msg(reason: &str) -> &'static str {
    match reason {
        "inconclusive" => "core inconclusive (not new tip)",
        "bad-prevblk" => "core bad-prevblk",
        "prev-blk-not-found" => "core prev-blk-not-found",
        _ => "core not at pad tip",
    }
}

fn core_park_child(
    oracle: &dyn BlockOracle,
    child: &Block,
    stem: &Block,
) -> Result<(), &'static str> {
    let _ = oracle.core_invalidate_hash(&child.block_hash().to_string());
    oracle.core_precious_block(&stem.block_hash().to_string())
}

fn finish_reorg_compare(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    pad_height: u32,
    stem: &Block,
    child: &Block,
    ours: DiffVerdict,
    reply: &OracleReply,
) -> CompareOne {
    let hex = hex_encode(serialize(child));
    let reason = match reply {
        OracleReply::Reason(s) => s.as_str(),
        _ => "",
    };
    let core = verdict_from_core_reply(reply);
    let rewind = |accepted: bool| -> Result<(), &'static str> {
        if accepted {
            hub.rewind_to_height(pad_height)
                .map_err(|_| "rewind failed")?;
        }
        if accepted || core == DiffVerdict::Accept {
            core_park_child(oracle, child, stem)?;
        }
        if hub.tip_height() == Some(pad_height) {
            restore_stem(hub, oracle, stem)?;
        }
        Ok(())
    };
    match (ours, core) {
        (DiffVerdict::Accept, DiffVerdict::Accept) => {
            if let Err(e) = rewind(true) {
                return CompareOne::Harness(e);
            }
            CompareOne::Agreed { accept: true }
        }
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DUPLICATE_SKIP.contains(&reason) => {
            if let Err(e) = rewind(true) {
                return CompareOne::Harness(e);
            }
            CompareOne::Agreed { accept: true }
        }
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DESYNC_SKIP.contains(&reason) => {
            let _ = rewind(true);
            CompareOne::Harness(core_desync_msg(reason))
        }
        (DiffVerdict::Accept, DiffVerdict::Reject) => CompareOne::Disagreed {
            ours: true,
            core: false,
            hex,
        },
        (DiffVerdict::Reject, DiffVerdict::Reject) => CompareOne::Agreed { accept: false },
        (DiffVerdict::Reject, DiffVerdict::Accept) => {
            let _ = core_park_child(oracle, child, stem);
            CompareOne::Disagreed {
                ours: false,
                core: true,
                hex,
            }
        }
        (DiffVerdict::Reject, DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Skip, DiffVerdict::Accept) => {
            let _ = core_park_child(oracle, child, stem);
            CompareOne::Harness("skip+accept")
        }
        (DiffVerdict::Skip, DiffVerdict::Reject | DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Accept, DiffVerdict::Skip) => {
            let _ = rewind(true);
            CompareOne::Skipped
        }
    }
}

fn compare_prepared(
    hub: &ChainHub,
    tip: &DiffTip,
    oracle: &dyn BlockOracle,
    block: Block,
) -> CompareOne {
    let keep = tip.height;
    let hex = hex_encode(serialize(&block));
    let ours_res = hub.accept_received_block(block);
    let ours = match verdict_from_accept(ours_res) {
        Ok(v) => v,
        Err(msg) => return CompareOne::Harness(msg),
    };
    let reply = oracle.submitblock_hex(&hex);
    if matches!(reply, OracleReply::Dead)
        || (matches!(reply, OracleReply::RpcError) && !oracle.liveness_ok())
    {
        if ours == DiffVerdict::Accept {
            let _ = hub.rewind_to_height(keep);
        }
        let _ = oracle.core_rewind_to_height(keep);
        return CompareOne::Harness("oracle dead");
    }
    let core = verdict_from_core_reply(&reply);
    combine(hub, oracle, keep, ours, core, &reply, &hex)
}

fn combine(
    hub: &ChainHub,
    oracle: &dyn BlockOracle,
    keep: u32,
    ours: DiffVerdict,
    core: DiffVerdict,
    reply: &OracleReply,
    hex: &str,
) -> CompareOne {
    let reason = match reply {
        OracleReply::Reason(s) => s.as_str(),
        _ => "",
    };
    match (ours, core) {
        (DiffVerdict::Accept, DiffVerdict::Accept) => rewind_agreed(hub, oracle, keep, true),
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DUPLICATE_SKIP.contains(&reason) => {
            rewind_agreed(hub, oracle, keep, true)
        }
        (DiffVerdict::Accept, DiffVerdict::Skip) if CORE_DESYNC_SKIP.contains(&reason) => {
            let _ = hub.rewind_to_height(keep);
            let _ = oracle.core_rewind_to_height(keep);
            CompareOne::Harness("core not at pad tip")
        }
        (DiffVerdict::Accept, DiffVerdict::Reject) => CompareOne::Disagreed {
            ours: true,
            core: false,
            hex: hex.to_string(),
        },
        (DiffVerdict::Reject, DiffVerdict::Reject) => CompareOne::Agreed { accept: false },
        (DiffVerdict::Reject, DiffVerdict::Accept) => CompareOne::Disagreed {
            ours: false,
            core: true,
            hex: hex.to_string(),
        },
        (DiffVerdict::Reject, DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Skip, DiffVerdict::Accept) => {
            let _ = oracle.core_rewind_to_height(keep);
            CompareOne::Harness("skip+accept")
        }
        (DiffVerdict::Skip, DiffVerdict::Reject | DiffVerdict::Skip) => CompareOne::Skipped,
        (DiffVerdict::Accept, DiffVerdict::Skip) => {
            let _ = hub.rewind_to_height(keep);
            CompareOne::Skipped
        }
    }
}

fn rewind_agreed(hub: &ChainHub, oracle: &dyn BlockOracle, keep: u32, accept: bool) -> CompareOne {
    if hub.rewind_to_height(keep).is_err() {
        return CompareOne::Harness("rewind failed");
    }
    if let Err(e) = oracle.core_rewind_to_height(keep) {
        return CompareOne::Harness(e);
    }
    CompareOne::Agreed { accept }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence};
    use rbitcoin_consensus::{mine_empty_regtest, mine_regtest_paying, Milestone};
    use rbitcoin_query::Query;
    use std::cell::Cell;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockOracle {
        reply: OracleReply,
        later: Option<OracleReply>,
        rewind: Cell<u32>,
        last_keep: Cell<u32>,
        submits: Cell<u32>,
        reconsider: Cell<u32>,
        invalidate: Cell<u32>,
        precious: Cell<u32>,
        live: bool,
    }

    impl MockOracle {
        fn new(reply: OracleReply) -> Self {
            Self {
                reply,
                later: None,
                rewind: Cell::new(0),
                last_keep: Cell::new(u32::MAX),
                submits: Cell::new(0),
                reconsider: Cell::new(0),
                invalidate: Cell::new(0),
                precious: Cell::new(0),
                live: true,
            }
        }

        fn then(mut self, later: OracleReply) -> Self {
            self.later = Some(later);
            self
        }
    }

    impl BlockOracle for MockOracle {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            let n = self.submits.get();
            self.submits.set(n + 1);
            if n == 0 {
                self.reply.clone()
            } else {
                self.later.clone().unwrap_or_else(|| self.reply.clone())
            }
        }
        fn liveness_ok(&self) -> bool {
            self.live
        }
        fn core_rewind_to_height(&self, keep: u32) -> Result<(), &'static str> {
            self.rewind.set(self.rewind.get() + 1);
            self.last_keep.set(keep);
            Ok(())
        }
        fn core_reconsider_block(&self, _hash: &str) -> Result<(), &'static str> {
            self.reconsider.set(self.reconsider.get() + 1);
            Ok(())
        }
        fn core_invalidate_hash(&self, _hash: &str) -> Result<(), &'static str> {
            self.invalidate.set(self.invalidate.get() + 1);
            Ok(())
        }
        fn core_precious_block(&self, _hash: &str) -> Result<(), &'static str> {
            self.precious.set(self.precious.get() + 1);
            Ok(())
        }
        fn testmempoolaccept_hex(&self, hex: &str) -> OracleReply {
            self.submitblock_hex(hex)
        }
    }

    fn tmp_diff_hub() -> (std::path::PathBuf, ChainHub, DiffTip) {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "rbtc-diff-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).expect("open");
        let params = diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let tip = genesis_diff_tip(&params);
        (dir, hub, tip)
    }

    fn height1_bytes() -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rbitcoin-consensus/tests/fixtures/regtest_height1.bin");
        fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    fn different_height1() -> Vec<u8> {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let spk = ScriptBuf::from_bytes(vec![0x51, 0x51]);
        let b = mine_regtest_paying(
            g.block_hash(),
            g.header.time + REGTEST_BLOCK_SPACING,
            1,
            spk,
            vec![],
        );
        serialize(&b)
    }

    #[test]
    fn parse_submitblock_json_table() {
        assert_eq!(
            parse_submitblock_json(r#"{"result":null,"error":null,"id":1}"#).unwrap(),
            None
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"inconclusive","error":null,"id":1}"#)
                .unwrap()
                .as_deref(),
            Some("inconclusive")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"duplicate","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("duplicate")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"duplicate-invalid","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("duplicate-invalid")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":"bad-txnmrklroot","error":null}"#)
                .unwrap()
                .as_deref(),
            Some("bad-txnmrklroot")
        );
        assert_eq!(
            parse_submitblock_json(r#"{"result":null,"error":{"code":-1,"message":"x"}}"#)
                .unwrap_err(),
            "rpc error"
        );
        assert_eq!(parse_submitblock_json("not json").unwrap_err(), "malformed");
    }

    #[test]
    fn parse_testmempoolaccept_json_allowed_and_policy() {
        assert!(matches!(
            parse_testmempoolaccept_json(
                r#"{"result":[{"txid":"ab","allowed":true}],"error":null,"id":1}"#
            )
            .unwrap(),
            OracleReply::NullAccept
        ));
        match parse_testmempoolaccept_json(
            r#"{"result":[{"allowed":false,"reject-reason":"dust"}],"error":null}"#,
        )
        .unwrap()
        {
            OracleReply::Reason(r) => assert_eq!(r, "dust"),
            other => panic!("{other:?}"),
        }
        assert!(is_core_mempool_policy_skip("dust"));
        assert!(is_core_mempool_policy_skip("min relay fee not met"));
        assert!(!is_core_mempool_policy_skip(
            "mandatory-script-verify-flag-failed"
        ));
    }

    #[test]
    fn compare_mempool_one_skips_core_policy_and_agrees_consensus() {
        let (dir, hub, _) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_MATURE_PAD_HEIGHT).unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        hub.attach_mempool(mp).ok();
        let seed = serialize(&spend_seed_block());
        let mock = MockOracle::new(OracleReply::Reason("dust".into()));
        match compare_mempool_one(&hub, &pad.tip, &mock, pad.mature, &seed) {
            CompareOne::Skipped => {}
            other => panic!("policy skip: {other:?}"),
        }
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_mempool_one(&hub, &pad.tip, &mock, pad.mature, &seed) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("mempool accept: {other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn is_core_connectivity_skip_exact() {
        assert!(is_core_connectivity_skip("duplicate"));
        assert!(is_core_connectivity_skip("duplicate-invalid"));
        assert!(!is_core_connectivity_skip("duplicated"));
        assert!(!is_core_connectivity_skip("bad-txnmrklroot"));
        assert_eq!(
            verdict_from_core_reply(&OracleReply::NullAccept),
            DiffVerdict::Accept
        );
        assert_eq!(
            verdict_from_core_reply(&OracleReply::Reason("inconclusive".into())),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_core_reply(&OracleReply::Reason("bad-txnmrklroot".into())),
            DiffVerdict::Reject
        );
    }

    #[test]
    fn verdict_from_accept_table() {
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::Accepted { height: 1 })).unwrap(),
            DiffVerdict::Accept
        );
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::AlreadyHave)).unwrap(),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_accept(Ok(AcceptOutcome::IgnoredWeaker)).unwrap(),
            DiffVerdict::Skip
        );
        assert_eq!(
            verdict_from_accept(Err(NetError::Protocol("non-genesis without tip"))).unwrap(),
            DiffVerdict::Reject
        );
        assert_eq!(
            verdict_from_accept(Err(NetError::Consensus("bad-txnmrklroot".into()))).unwrap(),
            DiffVerdict::Reject
        );
        assert!(verdict_from_accept(Err(NetError::Io(std::io::Error::other("x")))).is_err());
    }

    #[test]
    fn accept_received_block_random_prev_is_skip() {
        let (dir, hub, _tip) = tmp_diff_hub();
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mut b = mine_empty_regtest(g.block_hash(), g.header.time + 600, 1);
        b.header.prev_blockhash = BlockHash::from_byte_array([0x11; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        let r = hub.accept_received_block(b);
        assert!(matches!(r, Ok(AcceptOutcome::IgnoredWeaker)));
        assert_eq!(verdict_from_accept(r).unwrap(), DiffVerdict::Skip);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compare_one_height1_journey() {
        let (dir, hub, mut tip) = tmp_diff_hub();
        let raw = height1_bytes();

        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("expected agreed accept, got {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));
        assert!(mock.rewind.get() >= 1);
        assert_eq!(mock.last_keep.get(), 0);

        let mock = MockOracle::new(OracleReply::Reason("inconclusive".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Harness(_) => {}
            other => panic!("expected harness, got {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));
        assert!(mock.rewind.get() >= 1);

        for s in ["bad-prevblk", "prev-blk-not-found"] {
            let mock = MockOracle::new(OracleReply::Reason(s.into()));
            match compare_one(&hub, &mut tip, &mock, &raw) {
                CompareOne::Harness(_) => {}
                other => panic!("{s}: {other:?}"),
            }
        }

        let mock = MockOracle::new(OracleReply::Reason("duplicate".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("duplicate: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        assert!(matches!(
            compare_one(&hub, &mut tip, &mock, b"junk"),
            CompareOne::NotABlock
        ));

        let mock = MockOracle::new(OracleReply::Reason("bad-txnmrklroot".into()));
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Disagreed {
                ours: true,
                core: false,
                ..
            } => {}
            other => panic!("disagree: {other:?}"),
        }
        hub.rewind_to_height(0).unwrap();

        let mut bad: Block = deserialize(&raw).unwrap();
        bad.txdata[0].input[0].previous_output = OutPoint {
            txid: bitcoin::Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let mock = MockOracle::new(OracleReply::Reason("bad-cb-missing".into()));
        match compare_one(&hub, &mut tip, &mock, &serialize(&bad)) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("non-coinbase: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        let mock = MockOracle {
            reply: OracleReply::Dead,
            later: None,
            rewind: Cell::new(0),
            last_keep: Cell::new(u32::MAX),
            submits: Cell::new(0),
            reconsider: Cell::new(0),
            invalidate: Cell::new(0),
            precious: Cell::new(0),
            live: false,
        };
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Harness(_) => {}
            other => panic!("dead: {other:?}"),
        }

        let first: Block = deserialize(&raw).unwrap();
        hub.accept_received_block(first).unwrap();
        assert_eq!(hub.tip_height(), Some(1));
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &different_height1()) {
            CompareOne::Harness(_) => {}
            other => panic!("skip+accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(1));
        assert!(mock.rewind.get() >= 1);
        let _ = fs::remove_dir_all(dir);

        let (dir, hub, mut tip) = tmp_diff_hub();
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mut held = mine_empty_regtest(g.block_hash(), g.header.time + 600, 1);
        held.header.prev_blockhash = BlockHash::from_byte_array([0x22; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut held.header);
        let _ = hub.accept_received_block(held);
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &raw) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("hold then accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(0));

        let mut no_bip34: Block = deserialize(&raw).unwrap();
        no_bip34.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
        let mock = MockOracle::new(OracleReply::Reason("bad-cb-height".into()));
        match compare_one(&hub, &mut tip, &mock, &serialize(&no_bip34)) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("bip34: {other:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wait_for_file_ok_and_timeout() {
        let dir = std::env::temp_dir().join(format!(
            "rbtc-wait-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cookie");
        let p2 = p.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            fs::write(p2, b"x").unwrap();
        });
        wait_for_file(&p, Instant::now() + Duration::from_secs(2)).unwrap();
        let missing = dir.join("nope");
        assert_eq!(
            wait_for_file(&missing, Instant::now() + Duration::from_millis(20)).unwrap_err(),
            "timeout"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn split_http_body_and_request() {
        let req = build_jsonrpc_http_request("127.0.0.1:1", "abc", "submitblock", r#"["00"]"#);
        let s = String::from_utf8(req.clone()).unwrap();
        assert!(s.contains("POST / HTTP/1.1"));
        assert!(s.contains("Authorization: Basic abc"));
        assert!(s.contains("Connection: keep-alive"));
        assert!(s.contains(r#""method":"submitblock""#));
        let body = split_http_body(&req).unwrap();
        assert!(std::str::from_utf8(body).unwrap().contains("submitblock"));
        assert!(split_http_body(b"nope").is_err());
    }

    #[test]
    fn check_diff_env_table() {
        assert!(check_diff_env(None, Some("fd")).is_err());
        assert!(check_diff_env(Some("mainnet"), Some("fd")).is_err());
        assert!(check_diff_env(Some("tiny"), Some("uring")).is_err());
        assert!(check_diff_env(Some("tiny"), Some("fd")).is_ok());
        assert!(check_diff_env(Some("test"), Some("pread")).is_ok());
        assert!(check_diff_env(Some("small"), Some("libc")).is_ok());
        assert!(check_diff_env(Some("tiny"), Some("pwrite")).is_ok());
    }

    #[test]
    fn basic_auth_b64_known() {
        assert_eq!(basic_auth_b64("user", "pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn rewind_oracle_until_drains_same_height_siblings() {
        use std::cell::Cell;
        let seq = Cell::new(0u32);
        let tips = [(1u32, "aa"), (1u32, "bb"), (1u32, "cc"), (0u32, "gg")];
        rewind_oracle_until(
            0,
            || {
                let (h, hash) = tips[seq.get() as usize];
                Ok((h, hash.into()))
            },
            |_| {
                seq.set(seq.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seq.get(), 3);
    }

    #[test]
    fn rewind_oracle_until_stuck_same_hash() {
        let err = rewind_oracle_until(0, || Ok((1, "aa".into())), |_| Ok(())).unwrap_err();
        assert_eq!(err, "invalidate no progress");
    }

    #[test]
    fn rewind_oracle_until_below_keep() {
        let err = rewind_oracle_until(5, || Ok((3, "aa".into())), |_| Ok(())).unwrap_err();
        assert_eq!(err, "core below pad");
    }

    #[test]
    fn default_spend_without_tx1_gets_unique_txid() {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mature = height1_mature_out();
        let dummy = DiffTip {
            hash: g.block_hash(),
            time: g.header.time,
            height: DIFF_MATURE_PAD_HEIGHT,
        };
        let raw = serialize(&mine_empty_regtest(
            g.block_hash(),
            g.header.time + REGTEST_BLOCK_SPACING,
            1,
        ));
        let a = prepare_spend_candidate(&dummy, mature, &raw).unwrap();
        let b = prepare_spend_candidate(&dummy, mature, &raw).unwrap();
        assert_ne!(
            a.txdata[1].compute_txid(),
            b.txdata[1].compute_txid(),
            "default spend must not reuse one txid (BIP30 fills one OA probe chain)"
        );
        assert_ne!(
            a.txdata[0].compute_txid(),
            b.txdata[0].compute_txid(),
            "same-height coinbase must not reuse one txid (BIP30 fills one OA probe chain)"
        );
    }

    #[test]
    fn stamp_diff_coinbase_changes_txid_and_keeps_scriptsig_bound() {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mut a = mine_empty_regtest(g.block_hash(), g.header.time + REGTEST_BLOCK_SPACING, 1);
        let mut b = a.clone();
        super::stamp_diff_coinbase(&mut a, 1);
        super::stamp_diff_coinbase(&mut b, 2);
        assert_ne!(a.txdata[0].compute_txid(), b.txdata[0].compute_txid());
        assert!(a.txdata[0].input[0].script_sig.len() <= 100);
        assert!(b.txdata[0].input[0].script_sig.len() <= 100);
        let mut long = a.clone();
        long.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x51; 98]);
        let before = long.txdata[0].output[0].script_pubkey.clone();
        super::stamp_diff_coinbase(&mut long, 3);
        assert!(long.txdata[0].input[0].script_sig.len() <= 100);
        assert_ne!(
            long.txdata[0].output[0].script_pubkey.as_bytes(),
            before.as_bytes()
        );
    }

    fn height1_mature_out() -> OutPoint {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let h1 = mine_empty_regtest(g.block_hash(), g.header.time + REGTEST_BLOCK_SPACING, 1);
        OutPoint {
            txid: h1.txdata[0].compute_txid(),
            vout: 0,
        }
    }

    fn spend_seed_block() -> Block {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let spend = super::default_op_true_spend(height1_mature_out(), 0);
        mine_regtest_paying(
            g.block_hash(),
            g.header.time + REGTEST_BLOCK_SPACING,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend],
        )
    }

    #[test]
    fn diff_pad_spend_journey() {
        let (dir, hub, _genesis_tip) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_TEST_PAD_HEIGHT).unwrap();
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT));
        assert_eq!(pad.tip.height, DIFF_TEST_PAD_HEIGHT);
        assert_eq!(pad.bodies.len(), DIFF_TEST_PAD_HEIGHT as usize);
        assert_eq!(pad.mature.vout, 0);
        let h1 = &pad.bodies[0];
        assert_eq!(h1.txdata[0].output[0].value, Amount::from_sat(50_0000_0000));
        assert_eq!(h1.txdata[0].output[0].script_pubkey.as_bytes(), &[0x51]);
        assert_eq!(h1.txdata[0].compute_txid(), pad.mature.txid);

        let mock = MockOracle::new(OracleReply::NullAccept);
        submit_pad_to_oracle(&mock, &pad.bodies).unwrap();
        assert_eq!(mock.submits.get(), DIFF_TEST_PAD_HEIGHT);

        let mock_rej = MockOracle::new(OracleReply::Reason("bad-txnmrklroot".into()));
        assert!(submit_pad_to_oracle(&mock_rej, &pad.bodies).is_err());
        assert_eq!(mock_rej.submits.get(), 1);

        let mut tip = pad.tip.clone();
        let empty = serialize(&mine_empty_regtest(
            tip.hash,
            tip.time + REGTEST_BLOCK_SPACING,
            DIFF_TEST_PAD_HEIGHT + 1,
        ));
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_one(&hub, &mut tip, &mock, &empty) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("pad empty accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT));
        assert_eq!(mock.last_keep.get(), DIFF_TEST_PAD_HEIGHT);

        let seed = serialize(&spend_seed_block());
        let mock = MockOracle::new(OracleReply::Reason(
            "bad-txns-premature-spend-of-coinbase".into(),
        ));
        match compare_spend_one(&hub, &mut tip, &mock, pad.mature, &seed) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("immature spend: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prepare_spend_candidate_forces_prevout() {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mature = height1_mature_out();
        let dummy = DiffTip {
            hash: BlockHash::from_byte_array([0x33; 32]),
            time: 1,
            height: DIFF_MATURE_PAD_HEIGHT,
        };
        let mut spend = super::default_op_true_spend(
            OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                vout: 7,
            },
            0,
        );
        spend.version = TxVersion::TWO;
        spend.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        spend.input[0].sequence = Sequence::from_consensus(0xffff_fffe);
        let raw = serialize(&mine_regtest_paying(
            g.block_hash(),
            g.header.time + REGTEST_BLOCK_SPACING,
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend],
        ));
        let got = prepare_spend_candidate(&dummy, mature, &raw).unwrap();
        assert_eq!(got.header.prev_blockhash, dummy.hash);
        assert_eq!(got.txdata.len(), 2);
        assert_eq!(got.txdata[1].input[0].previous_output, mature);
        assert_eq!(got.txdata[1].version, TxVersion::TWO);
        assert_eq!(got.txdata[1].input[0].script_sig.as_bytes(), &[0x51]);
        assert_eq!(
            got.txdata[1].input[0].sequence,
            Sequence::from_consensus(0xffff_fffe)
        );
        let target = bitcoin::Target::from_compact(got.header.bits);
        assert!(got.header.validate_pow(target).is_ok());
        assert!(prepare_spend_candidate(&dummy, mature, b"junk").is_none());
    }

    #[test]
    fn prepare_spend_with_tx1_gets_unique_txid() {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        let mature = height1_mature_out();
        let dummy = DiffTip {
            hash: g.block_hash(),
            time: g.header.time,
            height: DIFF_MATURE_PAD_HEIGHT,
        };
        let raw = serialize(&spend_seed_block());
        let a = prepare_spend_candidate(&dummy, mature, &raw).unwrap();
        let b = prepare_spend_candidate(&dummy, mature, &raw).unwrap();
        assert_ne!(
            a.txdata[1].compute_txid(),
            b.txdata[1].compute_txid(),
            "corpus tx[1] must not reuse one txid (BIP30 fills one OA probe chain)"
        );
    }

    #[test]
    fn regtest_height101_spend_fixture() {
        let expected = serialize(&spend_seed_block());
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rbitcoin-consensus/tests/fixtures/regtest_height101_spend.bin");
        let raw = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        let b: Block = deserialize(&raw).unwrap();
        assert!(b.txdata.len() >= 2);
        assert_eq!(b.txdata[1].input[0].previous_output, height1_mature_out());
    }

    fn fork_child_seed_block() -> Block {
        let params = diff_regtest_params();
        let g = genesis_block(&params);
        mine_empty_regtest(g.block_hash(), g.header.time + REGTEST_BLOCK_SPACING, 1)
    }

    #[test]
    fn setup_side_block_holds_sibling_of_stem() {
        let (dir, hub, _g) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_TEST_PAD_HEIGHT).unwrap();
        let base = mine_diff_stem(&hub, pad).unwrap();
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT + 1));
        assert_eq!(base.tip.height, DIFF_TEST_PAD_HEIGHT + 1);
        assert_eq!(base.fork_parent.height, DIFF_TEST_PAD_HEIGHT);

        let side = mine_regtest_paying(
            base.fork_parent.hash,
            base.fork_parent.time + REGTEST_BLOCK_SPACING,
            DIFF_TEST_PAD_HEIGHT + 1,
            ScriptBuf::from_bytes(vec![0x51, 0x51]),
            Vec::new(),
        );
        let mock = MockOracle::new(OracleReply::NullAccept);
        setup_side_block(&hub, &mock, &side).unwrap();
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT + 1));
        assert_eq!(mock.submits.get(), 1);
        assert_eq!(
            mock.reconsider.get(),
            0,
            "reconsider(side) revives invalidated unique children"
        );

        let mock_inc = MockOracle::new(OracleReply::Reason("inconclusive".into()));
        setup_side_block(&hub, &mock_inc, &side)
            .expect("Core inconclusive is stored equal-work sibling");
        assert_eq!(submit_side_to_oracle(&mock_inc, &side), Ok(()));

        let mock_rej = MockOracle::new(OracleReply::Reason("bad-txnmrklroot".into()));
        assert!(setup_side_block(&hub, &mock_rej, &side).is_err());
        assert_eq!(
            submit_side_to_oracle(&mock_rej, &side).unwrap_err(),
            "side submit"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compare_fork_one_rewinds_to_stem() {
        let (dir, hub, _g) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_TEST_PAD_HEIGHT).unwrap();
        let base = mine_diff_stem(&hub, pad).unwrap();
        let mock = MockOracle::new(OracleReply::NullAccept);
        submit_pad_to_oracle(&mock, &base.bodies).unwrap();

        let seed = serialize(&fork_child_seed_block());
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_fork_one(&hub, &base, &mock, &seed) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("fork child accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT + 1));
        assert_eq!(hub.tip_hash(), Some(base.tip.hash));
        assert!(
            mock.invalidate.get() >= 1 && mock.precious.get() >= 1,
            "Core rewind is invalidate(child)+precious(stem), not pad-walk"
        );

        assert!(matches!(
            compare_fork_one(&hub, &base, &mock, b"junk"),
            CompareOne::NotABlock
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compare_fork_n_one_is_deeper_than_two_and_rewinds_stem() {
        let (dir, hub, _g) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_TEST_PAD_HEIGHT).unwrap();
        let base = mine_diff_stem(&hub, pad).unwrap();
        let seed = serialize(&fork_child_seed_block());
        let mock = MockOracle::new(OracleReply::NullAccept);
        submit_pad_to_oracle(&mock, &base.bodies).unwrap();
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_fork_n_one(&hub, &base, &mock, &seed, DIFF_REORG_N) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("n-reorg accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT + 1));
        assert_eq!(hub.tip_hash(), Some(base.tip.hash));
        assert!(DIFF_REORG_N > 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prepare_csv_age_candidate_version_two_relative_sequence() {
        let dummy = DiffTip {
            hash: BlockHash::from_byte_array([0x33; 32]),
            time: 1,
            height: DIFF_TEST_PAD_HEIGHT,
        };
        let mature = height1_mature_out();
        let got = prepare_csv_age_candidate(&dummy, mature, &[5, 0]).unwrap();
        assert_eq!(got.txdata[1].version, TxVersion::TWO);
        assert_eq!(got.txdata[1].input[0].sequence, Sequence::from_consensus(5));
        assert_eq!(got.txdata[1].input[0].previous_output, mature);
        assert_eq!(got.header.prev_blockhash, dummy.hash);
        assert!(prepare_csv_age_candidate(&dummy, mature, b"").is_none());
    }

    #[test]
    fn compare_csv_age_one_short_lock_accepts_long_lock_rejects() {
        let (dir, hub, _) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_MATURE_PAD_HEIGHT).unwrap();
        let mut tip = pad.tip.clone();
        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_csv_age_one(&hub, &mut tip, &mock, pad.mature, &[1, 0]) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("csv rel=1: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_MATURE_PAD_HEIGHT));
        let mock = MockOracle::new(OracleReply::Reason("non-BIP68-final".into()));
        match compare_csv_age_one(&hub, &mut tip, &mock, pad.mature, &[200, 0]) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("csv rel=200: {other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compare_cmpct_reorg_one_child_first_drain() {
        let (dir, hub, _g) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_TEST_PAD_HEIGHT).unwrap();
        let base = mine_diff_stem(&hub, pad).unwrap();
        let stem = base.tip.hash;
        let seed = serialize(&fork_child_seed_block());

        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_cmpct_reorg_one(&hub, &base, &mock, &seed) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("cmpct reorg accept: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_TEST_PAD_HEIGHT + 1));
        assert_eq!(hub.tip_hash(), Some(stem));
        assert!(
            mock.invalidate.get() >= 1 && mock.precious.get() >= 1,
            "Core rewind is invalidate(child)+precious(stem), not pad-walk"
        );

        let bad_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let bad = serialize(&Block {
            header: fork_child_seed_block().header,
            txdata: vec![fork_child_seed_block().txdata[0].clone(), bad_tx],
        });
        let mock = MockOracle::new(OracleReply::NullAccept)
            .then(OracleReply::Reason("bad-txns-vin-empty".into()));
        match compare_cmpct_reorg_one(&hub, &base, &mock, &bad) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("cmpct reorg reject: {other:?}"),
        }
        assert_eq!(hub.tip_hash(), Some(stem));
        assert!(matches!(
            compare_cmpct_reorg_one(&hub, &base, &mock, b"junk"),
            CompareOne::NotABlock
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn regtest_fork_child_fixture() {
        let expected = serialize(&fork_child_seed_block());
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rbitcoin-consensus/tests/fixtures/regtest_fork_child.bin");
        let raw = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        let b: Block = deserialize(&raw).unwrap();
        assert!(!b.txdata.is_empty());
    }

    #[test]
    fn prepare_script_candidate_wires_same_block_script() {
        let dummy = DiffTip {
            hash: BlockHash::from_byte_array([0x33; 32]),
            time: 1,
            height: DIFF_MATURE_PAD_HEIGHT,
        };
        let mature = height1_mature_out();
        let script = [0x51u8];
        let got = prepare_script_candidate(&dummy, mature, &script).unwrap();
        assert_eq!(got.header.prev_blockhash, dummy.hash);
        assert_eq!(got.txdata.len(), 3);
        assert_eq!(got.txdata[1].input[0].previous_output, mature);
        assert_eq!(got.txdata[1].output[0].script_pubkey.as_bytes(), &script);
        assert_eq!(
            got.txdata[2].input[0].previous_output,
            OutPoint {
                txid: got.txdata[1].compute_txid(),
                vout: 0,
            }
        );
        assert!(got.txdata[2].input[0].script_sig.is_empty());
        let long = vec![0x51; SCRIPT_FUZZ_MAX + 8];
        let trunc = prepare_script_candidate(&dummy, mature, &long).unwrap();
        assert_eq!(
            trunc.txdata[1].output[0].script_pubkey.len(),
            SCRIPT_FUZZ_MAX
        );
        assert!(prepare_script_candidate(&dummy, mature, b"").is_none());
    }

    #[test]
    fn apply_diff_field_mutations_sets_consensus_fields() {
        let mut a = default_op_true_spend(height1_mature_out(), 0);
        let mut b = default_op_true_spend(height1_mature_out(), 1);
        a.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        b.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52]);
        let mut txs = vec![a, b];
        let mut ctrl = vec![
            DIFF_MUT_VERSION
                | DIFF_MUT_LOCKTIME
                | DIFF_MUT_SEQUENCE
                | DIFF_MUT_SCRIPT_SIG
                | DIFF_MUT_WITNESS
                | DIFF_MUT_ANNEX
                | DIFF_MUT_SHUFFLE,
        ];
        ctrl.extend_from_slice(&2i32.to_le_bytes());
        ctrl.extend_from_slice(&7u32.to_le_bytes());
        ctrl.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        ctrl.push(1);
        ctrl.push(0xae);
        ctrl.push(1);
        ctrl.push(3);
        ctrl.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        ctrl.push(2);
        ctrl.extend_from_slice(&[0x11, 0x22]);
        ctrl.push(1);
        apply_diff_field_mutations(&mut txs, &ctrl);
        assert_eq!(txs[0].output[0].script_pubkey.as_bytes(), &[0x52]);
        assert_eq!(txs[1].output[0].script_pubkey.as_bytes(), &[0x51]);
        assert_eq!(txs[0].version, TxVersion::TWO);
        assert_eq!(txs[0].lock_time, LockTime::from_consensus(7));
        assert_eq!(
            txs[0].input[0].sequence,
            Sequence::from_consensus(0x0000_0001)
        );
        assert_eq!(txs[0].input[0].script_sig.as_bytes(), &[0xae]);
        let w: Vec<Vec<u8>> = txs[0].input[0].witness.iter().map(|s| s.to_vec()).collect();
        assert_eq!(w[0], vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(w.last().unwrap()[0], 0x50);
    }

    #[test]
    fn prepare_script_candidate_reads_version_and_witness_prefix() {
        let dummy = DiffTip {
            hash: BlockHash::from_byte_array([0x33; 32]),
            time: 1,
            height: DIFF_MATURE_PAD_HEIGHT,
        };
        let mature = height1_mature_out();
        let mut data = vec![SCRIPT_FUZZ_CTRL];
        data.extend_from_slice(&2i32.to_le_bytes());
        data.push(1);
        data.push(2);
        data.extend_from_slice(&[0xde, 0xad]);
        data.push(0x51);
        let got = prepare_script_candidate(&dummy, mature, &data).unwrap();
        assert_eq!(got.txdata[1].version, TxVersion::TWO);
        assert_eq!(got.txdata[1].output[0].script_pubkey.as_bytes(), &[0x51]);
        let wit: Vec<Vec<u8>> = got.txdata[2].input[0]
            .witness
            .iter()
            .map(|s| s.to_vec())
            .collect();
        assert_eq!(wit, vec![vec![0xde, 0xad]]);
        let plain = prepare_script_candidate(&dummy, mature, &[0x51]).unwrap();
        assert_eq!(plain.txdata[1].version, TxVersion::ONE);
        assert!(plain.txdata[2].input[0].witness.is_empty());
    }

    #[test]
    fn compare_script_one_true_accepts_return_rejects() {
        let (dir, hub, _) = tmp_diff_hub();
        let pad = mine_diff_pad(&hub, DIFF_MATURE_PAD_HEIGHT).unwrap();
        let mut tip = pad.tip.clone();

        let mock = MockOracle::new(OracleReply::NullAccept);
        match compare_script_one(&hub, &mut tip, &mock, pad.mature, &[0x51]) {
            CompareOne::Agreed { accept: true } => {}
            other => panic!("OP_TRUE: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_MATURE_PAD_HEIGHT));
        assert_eq!(mock.last_keep.get(), DIFF_MATURE_PAD_HEIGHT);

        let mock = MockOracle::new(OracleReply::Reason("script-error".into()));
        match compare_script_one(&hub, &mut tip, &mock, pad.mature, &[0x6a]) {
            CompareOne::Agreed { accept: false } => {}
            other => panic!("OP_RETURN: {other:?}"),
        }
        assert_eq!(hub.tip_height(), Some(DIFF_MATURE_PAD_HEIGHT));
        assert!(matches!(
            compare_script_one(&hub, &mut tip, &mock, pad.mature, b""),
            CompareOne::NotABlock
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
