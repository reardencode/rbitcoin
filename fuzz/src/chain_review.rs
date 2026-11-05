//! Hub-level chain differentials for the review discriminators.
//!
//! Each shape runs on a real [`ChainHub`]. The caller supplies Core's reply
//! (a live `submitblock` oracle, or a test double). A different fate is a
//! disagreement. These shapes do not skip.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};
use rbitcoin_consensus::{
    block_subsidy, genesis_block, grind_regtest_pow, mine_empty_regtest, mine_regtest_paying,
    ChainParams, Milestone, REGTEST_BLOCK_SPACING, REGTEST_POW_BITS,
};
use rbitcoin_net::{AcceptOutcome, ChainHub, NetError};
use rbitcoin_primitives::Height;
use rbitcoin_query::confirm_scripts_phase;
use std::sync::Arc;

use crate::block_diff::{BlockOracle, BlockStanding, OracleReply};

const SHAPE_MILESTONE: u8 = 0;
const SHAPE_GENESIS: u8 = 1;
const SHAPE_BIP30: u8 = 2;
const SHAPE_IMMATURE: u8 = 3;
const SHAPE_CSV: u8 = 4;
const SHAPE_MUTATION: u8 = 5;
const SHAPE_REORG: u8 = 6;
pub const CHAIN_REVIEW_SHAPES: u8 = 7;

/// High enough that regtest BIP34 stays off, matching a bitcoind started with
/// `-testactivationheight=bip34@100000000`. Coinbase scriptSigs may still push
/// a height; they just are not required to.
const BIP34_OFF: u32 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fate {
    Accept,
    /// Rejected as mutated and not cached as consensus-invalid.
    Mutated,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedSubmit {
    pub hex: String,
    /// `None` for blocks that only advance the chain. Compared submits carry a fate.
    pub(crate) fate: Option<Fate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReview {
    Agree {
        accept: bool,
    },
    Disagree {
        ours: bool,
        core: bool,
        /// Raw `submitblock` reason and, for `"duplicate"`, the chain standing.
        detail: String,
    },
}

fn params_bip34_off() -> ChainParams {
    let mut params = ChainParams::regtest();
    params
        .apply_test_activation_height("bip34", BIP34_OFF)
        .expect("regtest overlay");
    params
}

fn hex_block(block: &Block) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let raw = serialize(block);
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn subsidy(params: &ChainParams, height: u32) -> Amount {
    Amount::from_sat(block_subsidy(height, params) as u64)
}

fn spend_tx(prev: OutPoint, value: Amount, sequence: Sequence) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: op_true(),
        }],
    }
}

fn hub_fate(hub: &ChainHub, block: Block) -> Result<Fate, String> {
    Ok(hub_verdict(hub, block)?.0)
}

/// Fate plus the hub's reject text. Genesis and CSV shapes use the text so an
/// immature or missing-prevout result is not stored as the compared fate.
fn hub_verdict(hub: &ChainHub, block: Block) -> Result<(Fate, String), String> {
    let hash = block.block_hash();
    match hub.accept_received_block(block) {
        Ok(_) => Ok((Fate::Accept, String::new())),
        Err(NetError::Mutated(s)) => {
            if hub.is_block_invalid(&hash) {
                Ok((Fate::Reject, s))
            } else {
                Ok((Fate::Mutated, s))
            }
        }
        Err(NetError::Rules(e)) => Ok((Fate::Reject, rbitcoin_consensus::block_reject_reason(&e))),
        Err(NetError::Consensus(s)) => Ok((Fate::Reject, s)),
        Err(NetError::ConnectFailed { msg, .. }) => Ok((Fate::Reject, msg)),
        Err(e @ (NetError::BadPrev | NetError::SideBlock | NetError::UnknownParent)) => {
            Ok((Fate::Reject, e.to_string()))
        }
        Err(e) => Err(format!("hub: {e}")),
    }
}

fn detail_has(detail: &str, needle: &str) -> bool {
    detail.to_ascii_lowercase().contains(needle)
}

fn is_immature(detail: &str) -> bool {
    detail_has(detail, "immature")
}

fn is_missing_prevout(detail: &str) -> bool {
    detail_has(detail, "missing prevout") || detail_has(detail, "missingorspent")
}

fn push_setup(out: &mut Vec<PlannedSubmit>, block: &Block) {
    out.push(PlannedSubmit {
        hex: hex_block(block),
        fate: None,
    });
}

fn push_check(out: &mut Vec<PlannedSubmit>, block: &Block, fate: Fate) {
    out.push(PlannedSubmit {
        hex: hex_block(block),
        fate: Some(fate),
    });
}

struct HubSession {
    dir: rbitcoin_query::testutil::TempDir,
    hub: ChainHub,
}

impl Drop for HubSession {
    fn drop(&mut self) {
        let _keep = &self.dir;
    }
}

impl HubSession {
    fn open(label: &str, params: ChainParams, milestone: Milestone) -> Result<Self, String> {
        let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
        let hub = ChainHub::new(q, params.clone(), milestone);
        hub.ensure_genesis().map_err(|e| format!("genesis: {e}"))?;
        Ok(Self { dir, hub })
    }
}

fn genesis_tip(params: &ChainParams) -> (bitcoin::BlockHash, u32) {
    let g = genesis_block(params);
    (g.block_hash(), g.header.time)
}

/// Run one review shape on a fresh hub. `shape` is wrapped into the seven discriminators.
pub fn plan_chain_shape(shape: u8) -> Result<Vec<PlannedSubmit>, String> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    match shape % CHAIN_REVIEW_SHAPES {
        SHAPE_MILESTONE => plan_milestone(),
        SHAPE_GENESIS => plan_genesis_spend(),
        SHAPE_BIP30 => plan_bip30(),
        SHAPE_IMMATURE => plan_immature_batch(),
        SHAPE_CSV => plan_height0_csv(),
        SHAPE_MUTATION => plan_mutation(),
        SHAPE_REORG => plan_reorg_respend(),
        _ => unreachable!(),
    }
}

fn plan_milestone() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    // Height-only milestone (no anchor). The spend is under that height and
    // after coinbase maturity, so immaturity is not what decides the block.
    // The script is OP_TRUE: Core submitblock has no milestone skip, and an
    // OP_0 scriptPubKey would be accepted here and rejected there.
    let maturity = params.coinbase_maturity();
    let spend_h = maturity + 1;
    let session = HubSession::open("chain-ms", params.clone(), Milestone::height(spend_h + 50))?;
    let (mut tip, mut time) = genesis_tip(&params);
    time += REGTEST_BLOCK_SPACING;
    let coin = mine_regtest_paying(tip, time, 1, op_true(), Vec::new());
    let fate_coin = hub_fate(&session.hub, coin.clone())?;
    if fate_coin != Fate::Accept {
        return Err(format!("milestone coinbase rejected: {fate_coin:?}"));
    }
    let value = coin.txdata[0].output[0].value;
    let prev = OutPoint {
        txid: coin.txdata[0].compute_txid(),
        vout: 0,
    };
    let mut out = Vec::new();
    push_setup(&mut out, &coin);
    tip = coin.block_hash();
    time = coin.header.time;
    for h in 2..spend_h {
        time += REGTEST_BLOCK_SPACING;
        let b = mine_empty_regtest(tip, time, h);
        let fate = hub_fate(&session.hub, b.clone())?;
        if fate != Fate::Accept {
            return Err(format!("milestone pad {h}: {fate:?}"));
        }
        push_setup(&mut out, &b);
        tip = b.block_hash();
        time = b.header.time;
    }
    time += REGTEST_BLOCK_SPACING;
    let spend = mine_regtest_paying(
        tip,
        time,
        spend_h,
        op_true(),
        vec![spend_tx(prev, value, Sequence::MAX)],
    );
    let fate = hub_fate(&session.hub, spend.clone())?;
    if fate != Fate::Accept {
        return Err(format!(
            "milestone OP_TRUE spend was not accepted: {fate:?}"
        ));
    }
    push_check(&mut out, &spend, fate);
    drop(session);
    Ok(out)
}

fn connect_empty(
    session: &HubSession,
    out: &mut Vec<PlannedSubmit>,
    tip: &mut bitcoin::BlockHash,
    time: &mut u32,
    heights: impl Iterator<Item = u32>,
    label: &str,
) -> Result<(), String> {
    for h in heights {
        *time += REGTEST_BLOCK_SPACING;
        let b = mine_empty_regtest(*tip, *time, h);
        let fate = hub_fate(&session.hub, b.clone())?;
        if fate != Fate::Accept {
            return Err(format!("{label} pad {h}: {fate:?}"));
        }
        push_setup(out, &b);
        *tip = b.block_hash();
        *time = b.header.time;
    }
    Ok(())
}

fn plan_genesis_spend() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-gen", params.clone(), Milestone::NONE)?;
    let g = genesis_block(&params);
    let prev = OutPoint {
        txid: g.txdata[0].compute_txid(),
        vout: 0,
    };
    let value = g.txdata[0].output[0].value;
    // Height 1 is inside the maturity window, so a node that treats the
    // genesis coinbase as a coin still rejects before it can accept. Spend
    // only after `coinbase_maturity` empty blocks.
    let maturity = params.coinbase_maturity();
    let spend_h = maturity + 1;
    let (mut tip, mut time) = genesis_tip(&params);
    let mut out = Vec::new();
    connect_empty(
        &session,
        &mut out,
        &mut tip,
        &mut time,
        1..=maturity,
        "genesis",
    )?;
    time += REGTEST_BLOCK_SPACING;
    let b = mine_regtest_paying(
        tip,
        time,
        spend_h,
        op_true(),
        vec![spend_tx(prev, value, Sequence::MAX)],
    );
    let (fate, detail) = hub_verdict(&session.hub, b.clone())?;
    if is_immature(&detail) {
        return Err(format!("genesis spend is an immature reject: {detail}"));
    }
    push_check(&mut out, &b, fate);
    drop(session);
    Ok(out)
}

fn plan_bip30() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-bip30", params.clone(), Milestone::NONE)?;
    let (tip, time) = genesis_tip(&params);
    let value = subsidy(&params, 1);
    let cb = duplicate_coinbase(value);
    let b1 = mine_single(&cb, tip, time + REGTEST_BLOCK_SPACING);
    let fate1 = hub_fate(&session.hub, b1.clone())?;
    if fate1 != Fate::Accept {
        return Err(format!("bip30 first block: {fate1:?}"));
    }
    let b2 = mine_single(&cb, b1.block_hash(), b1.header.time + REGTEST_BLOCK_SPACING);
    let fate2 = hub_fate(&session.hub, b2.clone())?;
    let mut out = Vec::new();
    push_setup(&mut out, &b1);
    push_check(&mut out, &b2, fate2);
    drop(session);
    Ok(out)
}

fn duplicate_coinbase(value: Amount) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x04]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }],
    }
}

fn mine_single(tx: &Transaction, prev: bitcoin::BlockHash, time: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array()),
            time,
            bits: CompactTarget::from_consensus(REGTEST_POW_BITS),
            nonce: 0,
        },
        txdata: vec![tx.clone()],
    };
    grind_regtest_pow(&mut block.header);
    block
}

fn plan_immature_batch() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-imm", params.clone(), Milestone::NONE)?;
    let (tip, time) = genesis_tip(&params);
    let b1 = mine_regtest_paying(tip, time + REGTEST_BLOCK_SPACING, 1, op_true(), Vec::new());
    let value = b1.txdata[0].output[0].value;
    let prev = OutPoint {
        txid: b1.txdata[0].compute_txid(),
        vout: 0,
    };
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        b1.header.time + REGTEST_BLOCK_SPACING,
        2,
        op_true(),
        vec![spend_tx(prev, value, Sequence::MAX)],
    );
    let accepted = batch_accept(
        &session.hub,
        &[(Height(1), b1.clone()), (Height(2), b2.clone())],
    )?;
    let fate = if accepted { Fate::Accept } else { Fate::Reject };
    let mut out = Vec::new();
    push_setup(&mut out, &b1);
    push_check(&mut out, &b2, fate);
    drop(session);
    Ok(out)
}

fn batch_accept(hub: &ChainHub, blocks: &[(Height, Block)]) -> Result<bool, String> {
    match hub.confirm_wire_load_phase(blocks) {
        Ok(None) => Ok(false),
        Ok(Some(loaded)) => match confirm_scripts_phase(loaded.batch) {
            Ok(scripts) => match hub.confirm_write(scripts.batch) {
                Ok(_) => Ok(true),
                Err(NetError::Consensus(_) | NetError::Rules(_) | NetError::Mutated(_)) => {
                    Ok(false)
                }
                Err(e) => Err(format!("batch write: {e}")),
            },
            Err(_) => Ok(false),
        },
        Err(NetError::Consensus(_) | NetError::Rules(_) | NetError::Mutated(_)) => Ok(false),
        Err(e) => Err(format!("batch load: {e}")),
    }
}

/// Height-1 coinbase with two `OP_TRUE` outputs. The ancestor median for both
/// is height 0 (`max(h - 1, 0)`).
fn coinbase_two_outputs(prev: bitcoin::BlockHash, time: u32, height: u32) -> Result<Block, String> {
    let mut coin = mine_regtest_paying(prev, time, height, op_true(), Vec::new());
    let subsidy = coin.txdata[0].output[0].value;
    let half = Amount::from_sat(subsidy.to_sat() / 2);
    let rest = subsidy
        .checked_sub(half)
        .ok_or_else(|| format!("subsidy {subsidy}"))?;
    coin.txdata[0].output = vec![
        TxOut {
            value: half,
            script_pubkey: op_true(),
        },
        TxOut {
            value: rest,
            script_pubkey: op_true(),
        },
    ];
    coin.header.merkle_root = coin
        .compute_merkle_root()
        .ok_or_else(|| "csv coinbase merkle".to_string())?;
    coin.header.nonce = 0;
    grind_regtest_pow(&mut coin.header);
    Ok(coin)
}

fn plan_height0_csv() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-csv", params.clone(), Milestone::NONE)?;
    // The genesis coinbase is not a coin: spending it returns MissingPrevout
    // in assemble, before structural_bip68. The first real coin is the
    // height-1 coinbase. Its BIP68 ancestor is height 0 (`max(h - 1, 0)`).
    // A panic on that median-time lookup propagates.
    let maturity = params.coinbase_maturity();
    let spend_h = maturity + 1;
    let (mut tip, mut time) = genesis_tip(&params);
    time += REGTEST_BLOCK_SPACING;
    let coin = coinbase_two_outputs(tip, time, 1)?;
    let fate_coin = hub_fate(&session.hub, coin.clone())?;
    if fate_coin != Fate::Accept {
        return Err(format!("csv coinbase: {fate_coin:?}"));
    }
    let txid = coin.txdata[0].compute_txid();
    let short_value = coin.txdata[0].output[0].value;
    let long_value = coin.txdata[0].output[1].value;
    let mut out = Vec::new();
    push_setup(&mut out, &coin);
    tip = coin.block_hash();
    time = coin.header.time;
    connect_empty(&session, &mut out, &mut tip, &mut time, 2..=maturity, "csv")?;
    // 512s is inside `maturity` blocks of regtest spacing, so the height-0
    // median satisfies it. Fail-closed on create height 0, or on a zero MTP,
    // rejects it. The max time lock is not satisfied by that same median. A
    // BIP68 skip accepts it. The pair is the lock's decision.
    let short_seq = Sequence::from_consensus((1 << 22) | 1);
    let long_seq = Sequence::from_consensus((1 << 22) | 0xffff);
    time += REGTEST_BLOCK_SPACING;
    let short = mine_regtest_paying(
        tip,
        time,
        spend_h,
        op_true(),
        vec![spend_tx(OutPoint { txid, vout: 0 }, short_value, short_seq)],
    );
    let (short_fate, short_detail) = hub_verdict(&session.hub, short.clone())?;
    if is_missing_prevout(&short_detail) || is_immature(&short_detail) {
        return Err(format!(
            "csv short lock stopped before BIP68: {short_fate:?} {short_detail}"
        ));
    }
    if short_fate != Fate::Accept {
        return Err(format!(
            "csv short lock was not satisfied by the height-0 median: {short_fate:?} {short_detail}"
        ));
    }
    push_check(&mut out, &short, short_fate);
    tip = short.block_hash();
    time = short.header.time + REGTEST_BLOCK_SPACING;
    let long = mine_regtest_paying(
        tip,
        time,
        spend_h + 1,
        op_true(),
        vec![spend_tx(OutPoint { txid, vout: 1 }, long_value, long_seq)],
    );
    let (fate, detail) = hub_verdict(&session.hub, long.clone())?;
    if is_missing_prevout(&detail) || is_immature(&detail) {
        return Err(format!(
            "csv long lock stopped before BIP68: {fate:?} {detail}"
        ));
    }
    if fate != Fate::Reject || !detail_has(&detail, "nonfinal") {
        return Err(format!(
            "csv long lock was not decided by the BIP68 time lock: {fate:?} {detail}"
        ));
    }
    push_check(&mut out, &long, fate);
    drop(session);
    Ok(out)
}

fn plan_mutation() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-mut", params.clone(), Milestone::NONE)?;
    let (tip, time) = genesis_tip(&params);
    let honest = mine_regtest_paying(tip, time + REGTEST_BLOCK_SPACING, 1, op_true(), Vec::new());
    let mut bad = honest.clone();
    bad.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x00]);
    let fate_bad = hub_fate(&session.hub, bad.clone())?;
    let fate_honest = hub_fate(&session.hub, honest.clone())?;
    let mut out = Vec::new();
    push_check(&mut out, &bad, fate_bad);
    push_check(&mut out, &honest, fate_honest);
    drop(session);
    Ok(out)
}

fn plan_reorg_respend() -> Result<Vec<PlannedSubmit>, String> {
    let params = params_bip34_off();
    let session = HubSession::open("chain-reorg", params.clone(), Milestone::NONE)?;
    let (mut tip, mut time) = genesis_tip(&params);
    let mut h1_out: Option<(OutPoint, Amount)> = None;
    let mut at_100: Option<(bitcoin::BlockHash, u32)> = None;
    let mut out = Vec::new();
    for h in 1..=100 {
        time += REGTEST_BLOCK_SPACING;
        let b = mine_empty_regtest(tip, time, h);
        if h == 1 {
            h1_out = Some((
                OutPoint {
                    txid: b.txdata[0].compute_txid(),
                    vout: 0,
                },
                b.txdata[0].output[0].value,
            ));
        }
        let fate = hub_fate(&session.hub, b.clone())?;
        if fate != Fate::Accept {
            return Err(format!("pad {h}: {fate:?}"));
        }
        push_setup(&mut out, &b);
        if h == 100 {
            at_100 = Some((b.block_hash(), b.header.time));
        }
        tip = b.block_hash();
        time = b.header.time;
    }
    let (prev, value) = h1_out.ok_or("missing height-1 coin")?;
    time += REGTEST_BLOCK_SPACING;
    let spend = mine_regtest_paying(
        tip,
        time,
        101,
        op_true(),
        vec![spend_tx(prev, value, Sequence::MAX)],
    );
    let fate_spend = hub_fate(&session.hub, spend.clone())?;
    if fate_spend != Fate::Accept {
        return Err(format!("mature spend: {fate_spend:?}"));
    }
    push_setup(&mut out, &spend);
    let (parent, parent_time) = at_100.ok_or("missing height 100")?;
    let fork_a = mine_empty_regtest(parent, parent_time + REGTEST_BLOCK_SPACING, 101);
    let fork_b = mine_empty_regtest(
        fork_a.block_hash(),
        fork_a.header.time + REGTEST_BLOCK_SPACING,
        102,
    );
    match session
        .hub
        .accept_branch(&[Arc::new(fork_a.clone()), Arc::new(fork_b.clone())])
    {
        Ok(AcceptOutcome::Accepted { .. }) => {}
        Ok(other) => return Err(format!("reorg did not connect: {other:?}")),
        Err(e) => return Err(format!("reorg: {e}")),
    }
    push_setup(&mut out, &fork_a);
    push_setup(&mut out, &fork_b);
    let respend = mine_regtest_paying(
        fork_b.block_hash(),
        fork_b.header.time + REGTEST_BLOCK_SPACING,
        103,
        op_true(),
        vec![spend_tx(prev, value, Sequence::MAX)],
    );
    let fate = hub_fate(&session.hub, respend.clone())?;
    push_check(&mut out, &respend, fate);
    drop(session);
    Ok(out)
}

/// One `submitblock` result.
///
/// JSON `null` means Core connected the block. The exact string `duplicate`
/// means the body is already stored and `ProcessNewBlock` returned true.
/// Core returns that string for a block that is merely `valid-headers` while
/// a heavier tip stays active, so `duplicate` is an accept only when
/// `standing` is [`BlockStanding::Active`] or [`BlockStanding::ValidFork`].
/// `duplicate-invalid` stays a reject.
fn core_fate(reply: OracleReply, standing: Option<BlockStanding>) -> Result<Fate, String> {
    match reply {
        OracleReply::NullAccept => Ok(Fate::Accept),
        OracleReply::Reason(reason) if reason == "duplicate" => match standing {
            Some(BlockStanding::Active | BlockStanding::ValidFork) => Ok(Fate::Accept),
            Some(BlockStanding::NotConnected | BlockStanding::Invalid) => Ok(Fate::Reject),
            None => Err("oracle rpc".into()),
        },
        OracleReply::Reason(reason) => {
            if mutated_reason(&reason) {
                Ok(Fate::Mutated)
            } else {
                Ok(Fate::Reject)
            }
        }
        OracleReply::RpcError => Err("oracle rpc".into()),
        OracleReply::Dead => Err("oracle dead".into()),
    }
}

fn standing_label(standing: BlockStanding) -> &'static str {
    match standing {
        BlockStanding::Active => "active",
        BlockStanding::ValidFork => "valid-fork",
        BlockStanding::NotConnected => "not-connected",
        BlockStanding::Invalid => "invalid",
    }
}

fn reply_note(reply: &OracleReply, standing: Option<BlockStanding>) -> String {
    let base = match reply {
        OracleReply::NullAccept => "submitblock=null".to_string(),
        OracleReply::Reason(reason) => format!("submitblock={reason}"),
        OracleReply::RpcError => "submitblock=rpc-error".to_string(),
        OracleReply::Dead => "submitblock=dead".to_string(),
    };
    match standing {
        Some(standing) => format!("{base} standing={}", standing_label(standing)),
        None => base,
    }
}

fn block_hash_from_hex(hex: &str) -> Result<String, String> {
    fn nybble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("block hex".into()),
        }
    }
    if !hex.len().is_multiple_of(2) {
        return Err("block hex".into());
    }
    let bytes = hex.as_bytes();
    let mut raw = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        raw.push((nybble(bytes[i])? << 4) | nybble(bytes[i + 1])?);
        i += 2;
    }
    let block: Block =
        bitcoin::consensus::encode::deserialize(&raw).map_err(|_| "block hex".to_string())?;
    Ok(block.block_hash().to_string())
}

/// `invalidateblock` sticks. A later submit of a block this process already
/// gave Core is `duplicate-invalid` until `reconsiderblock` clears the flag.
/// Setup blocks (no compared fate) still need that clear, or the child is
/// `bad-prevblk`.
fn submit_fate(oracle: &dyn BlockOracle, hex: &str) -> Result<(Fate, String), String> {
    let reply = match oracle.submitblock_hex(hex) {
        OracleReply::Reason(reason)
            if reason == "duplicate-invalid" || reason == "duplicate-inconclusive" =>
        {
            let hash = block_hash_from_hex(hex)?;
            oracle
                .core_reconsider_block(&hash)
                .map_err(|_| "oracle rpc".to_string())?;
            oracle.submitblock_hex(hex)
        }
        other => other,
    };
    let standing = match &reply {
        OracleReply::Reason(reason) if reason == "duplicate" => {
            let hash = block_hash_from_hex(hex)?;
            Some(
                oracle
                    .block_standing(&hash)
                    .map_err(|_| "oracle rpc".to_string())?,
            )
        }
        _ => None,
    };
    let note = reply_note(&reply, standing);
    let fate = core_fate(reply, standing)?;
    Ok((fate, note))
}

/// `reconsiderblock` activates the most-work descendant of that block,
/// including a chain this plan did not submit. When `hash` lies on the
/// active chain, invalidate the tip until `hash` itself is the tip so the
/// next child is most-work and Core connects it.
fn park_active_tip_at(oracle: &dyn BlockOracle, hash: &str) -> Result<(), String> {
    loop {
        let best = match oracle.best_block_hash() {
            Ok(best) => best,
            Err("no chain") => return Ok(()),
            Err(_) => return Err("oracle rpc".into()),
        };
        if best == hash {
            return Ok(());
        }
        match oracle.block_standing(hash) {
            Ok(BlockStanding::Active) => {
                oracle
                    .core_invalidate_hash(&best)
                    .map_err(|_| "oracle rpc".to_string())?;
                let next = oracle.best_block_hash().map_err(|_| "oracle rpc")?;
                if next == best {
                    return Err("invalidate no progress".into());
                }
            }
            Ok(_) => return Ok(()),
            Err("no chain") => return Ok(()),
            Err(_) => return Err("oracle rpc".into()),
        }
    }
}

fn mutated_reason(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("bad-txnmrklroot")
        || r.contains("bad-txns-duplicate")
        || r.contains("mutated")
        || r.contains("bad-witness-merkle-match")
        || r.contains("bad-witness-nonce-size")
        || r.contains("bad-seen-with-witness")
}

/// Submit the planned blocks. Agree when every compared fate matches Core.
pub fn compare_chain_plan(
    plan: &[PlannedSubmit],
    oracle: &dyn BlockOracle,
) -> Result<ChainReview, String> {
    if !oracle.liveness_ok() {
        return Err("oracle dead".into());
    }
    oracle.core_rewind_to_height(0)?;
    let mut saw = false;
    let mut all_accept = true;
    let mut mismatch: Option<(bool, bool, String)> = None;
    for step in plan {
        let (core, note) = submit_fate(oracle, &step.hex)?;
        if step.fate.is_none() {
            let hash = block_hash_from_hex(&step.hex)?;
            park_active_tip_at(oracle, &hash)?;
        }
        let Some(ours) = step.fate else {
            continue;
        };
        saw = true;
        if ours != Fate::Accept {
            all_accept = false;
        }
        if mismatch.is_none() && ours != core {
            mismatch = Some((ours == Fate::Accept, core == Fate::Accept, note));
        }
    }
    if !saw {
        return Err("shape produced no comparison".into());
    }
    if let Some((ours, core, detail)) = mismatch {
        Ok(ChainReview::Disagree { ours, core, detail })
    } else {
        Ok(ChainReview::Agree { accept: all_accept })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct QueueOracle {
        replies: Vec<OracleReply>,
        n: Cell<usize>,
    }

    impl QueueOracle {
        fn new(replies: Vec<OracleReply>) -> Self {
            Self {
                replies,
                n: Cell::new(0),
            }
        }
    }

    impl BlockOracle for QueueOracle {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            let i = self.n.get();
            self.n.set(i + 1);
            self.replies
                .get(i)
                .cloned()
                .unwrap_or(OracleReply::RpcError)
        }
    }

    fn reply_for(fate: Fate) -> OracleReply {
        match fate {
            Fate::Accept => OracleReply::NullAccept,
            Fate::Mutated => OracleReply::Reason("bad-txnmrklroot".into()),
            Fate::Reject => OracleReply::Reason("consensus".into()),
        }
    }

    fn flip(fate: Fate) -> Fate {
        match fate {
            Fate::Accept => Fate::Reject,
            Fate::Reject | Fate::Mutated => Fate::Accept,
        }
    }

    fn scripted(plan: &[PlannedSubmit], flip_checks: bool) -> Vec<OracleReply> {
        let mut flipped = false;
        plan.iter()
            .map(|step| match step.fate {
                None => OracleReply::NullAccept,
                Some(fate) => {
                    let use_fate = if flip_checks && !flipped {
                        flipped = true;
                        flip(fate)
                    } else {
                        fate
                    };
                    reply_for(use_fate)
                }
            })
            .collect()
    }

    #[test]
    fn each_chain_shape_classifies_against_the_hub() {
        for shape in 0..CHAIN_REVIEW_SHAPES {
            let plan = plan_chain_shape(shape).unwrap_or_else(|e| panic!("shape {shape}: {e}"));
            assert!(
                plan.iter().any(|s| s.fate.is_some()),
                "shape {shape} skipped the comparison"
            );
            if shape == SHAPE_MILESTONE {
                let checked: Vec<Fate> = plan.iter().filter_map(|s| s.fate).collect();
                assert_eq!(
                    checked,
                    vec![Fate::Accept],
                    "milestone comparison is the OP_TRUE spend, which Core accepts"
                );
            }
            let matched = compare_chain_plan(&plan, &QueueOracle::new(scripted(&plan, false)))
                .unwrap_or_else(|e| panic!("shape {shape}: {e}"));
            assert!(
                matches!(matched, ChainReview::Agree { .. }),
                "shape {shape} did not agree with its hub fate: {matched:?}"
            );
            let flipped = compare_chain_plan(&plan, &QueueOracle::new(scripted(&plan, true)))
                .unwrap_or_else(|e| panic!("shape {shape}: {e}"));
            assert!(
                matches!(flipped, ChainReview::Disagree { .. }),
                "shape {shape} did not disagree with the opposite reply: {flipped:?}"
            );
        }
    }

    /// After `invalidateblock`, Core answers `duplicate-invalid` for a block it
    /// already accepted. The checked block is a child: without
    /// `reconsiderblock` on the setup parent, Core reports `bad-prevblk`.
    #[test]
    fn invalidated_replay_is_not_a_consensus_split() {
        let params = params_bip34_off();
        let genesis = genesis_block(&params);
        let parent = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        let child = mine_empty_regtest(parent.block_hash(), parent.header.time + 600, 2);
        let parent_hash = parent.block_hash().to_string();
        let plan = vec![
            PlannedSubmit {
                hex: hex_block(&parent),
                fate: None,
            },
            PlannedSubmit {
                hex: hex_block(&child),
                fate: Some(Fate::Accept),
            },
        ];
        let oracle = ReplayOracle {
            setup_hex: plan[0].hex.clone(),
            setup_hash: parent_hash,
            reconsidered: Cell::new(false),
            stay_invalid: false,
        };
        let got = compare_chain_plan(&plan, &oracle).expect("compare");
        assert_eq!(got, ChainReview::Agree { accept: true });
        assert!(oracle.reconsidered.get(), "parent was not reconsidered");
    }

    #[test]
    fn sticky_invalid_block_stays_a_reject() {
        let params = params_bip34_off();
        let genesis = genesis_block(&params);
        let parent = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        let plan = vec![PlannedSubmit {
            hex: hex_block(&parent),
            fate: Some(Fate::Accept),
        }];
        let oracle = ReplayOracle {
            setup_hex: plan[0].hex.clone(),
            setup_hash: parent.block_hash().to_string(),
            reconsidered: Cell::new(false),
            stay_invalid: true,
        };
        let got = compare_chain_plan(&plan, &oracle).expect("compare");
        assert_eq!(
            got,
            ChainReview::Disagree {
                ours: true,
                core: false,
                detail: "submitblock=duplicate-invalid".into(),
            }
        );
    }

    /// BIP22 `duplicate` on a body Core has only stored (`valid-headers`) is
    /// the immature-spend failure: the hub rejects, and the block is not on a
    /// chain Core treats as valid.
    #[test]
    fn duplicate_of_an_unconnected_block_is_a_reject() {
        let block = one_block();
        let plan = vec![PlannedSubmit {
            hex: hex_block(&block),
            fate: Some(Fate::Reject),
        }];
        let oracle = FixedStanding {
            reply: OracleReply::Reason("duplicate".into()),
            standing: BlockStanding::NotConnected,
        };
        let got = compare_chain_plan(&plan, &oracle).expect("compare");
        assert_eq!(got, ChainReview::Agree { accept: false });
    }

    /// The same string on the active chain is still an accept. A reconsidered
    /// valid block comes back `duplicate` and must not become a split.
    #[test]
    fn duplicate_of_the_active_chain_is_an_accept() {
        let block = one_block();
        let plan = vec![PlannedSubmit {
            hex: hex_block(&block),
            fate: Some(Fate::Accept),
        }];
        let oracle = FixedStanding {
            reply: OracleReply::Reason("duplicate".into()),
            standing: BlockStanding::Active,
        };
        let got = compare_chain_plan(&plan, &oracle).expect("compare");
        assert_eq!(got, ChainReview::Agree { accept: true });
    }

    /// `reconsiderblock` on a shared parent revives heavier descendants.
    /// The child is judged only after those descendants are invalidated and
    /// the parent is the tip.
    #[test]
    fn reconsidered_parent_is_parked_before_the_child() {
        let params = params_bip34_off();
        let genesis = genesis_block(&params);
        let parent = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        let child = mine_empty_regtest(parent.block_hash(), parent.header.time + 600, 2);
        let parent_hash = parent.block_hash().to_string();
        let heavy = "11".repeat(32);
        let plan = vec![
            PlannedSubmit {
                hex: hex_block(&parent),
                fate: None,
            },
            PlannedSubmit {
                hex: hex_block(&child),
                fate: Some(Fate::Reject),
            },
        ];
        let oracle = HeavyTipOracle {
            parent_hex: plan[0].hex.clone(),
            parent_hash: parent_hash.clone(),
            heavy: heavy.clone(),
            tip: std::cell::RefCell::new("00".repeat(32)),
            parent_n: Cell::new(0),
            invalidated: std::cell::RefCell::new(Vec::new()),
        };
        let got = compare_chain_plan(&plan, &oracle).expect("compare");
        assert_eq!(got, ChainReview::Agree { accept: false });
        assert_eq!(oracle.invalidated.borrow().as_slice(), &[heavy]);
        assert_eq!(oracle.tip.borrow().as_str(), parent_hash);
    }

    fn one_block() -> Block {
        let params = params_bip34_off();
        let genesis = genesis_block(&params);
        mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1)
    }

    struct FixedStanding {
        reply: OracleReply,
        standing: BlockStanding,
    }

    impl BlockOracle for FixedStanding {
        fn submitblock_hex(&self, _hex: &str) -> OracleReply {
            self.reply.clone()
        }
        fn block_standing(&self, _hash: &str) -> Result<BlockStanding, &'static str> {
            Ok(self.standing)
        }
    }

    struct HeavyTipOracle {
        parent_hex: String,
        parent_hash: String,
        heavy: String,
        tip: std::cell::RefCell<String>,
        parent_n: Cell<u32>,
        invalidated: std::cell::RefCell<Vec<String>>,
    }

    impl BlockOracle for HeavyTipOracle {
        fn submitblock_hex(&self, hex: &str) -> OracleReply {
            if hex == self.parent_hex {
                let n = self.parent_n.get();
                self.parent_n.set(n + 1);
                if n == 0 {
                    return OracleReply::Reason("duplicate-invalid".into());
                }
                return OracleReply::Reason("duplicate".into());
            }
            if self.tip.borrow().as_str() == self.parent_hash {
                OracleReply::Reason("bad-txns-premature-spend-of-coinbase".into())
            } else {
                OracleReply::Reason("duplicate".into())
            }
        }
        fn core_reconsider_block(&self, hash: &str) -> Result<(), &'static str> {
            if hash == self.parent_hash {
                *self.tip.borrow_mut() = self.heavy.clone();
            }
            Ok(())
        }
        fn core_invalidate_hash(&self, hash: &str) -> Result<(), &'static str> {
            self.invalidated.borrow_mut().push(hash.to_string());
            if hash == self.heavy {
                *self.tip.borrow_mut() = self.parent_hash.clone();
            }
            Ok(())
        }
        fn best_block_hash(&self) -> Result<String, &'static str> {
            Ok(self.tip.borrow().clone())
        }
        fn block_standing(&self, hash: &str) -> Result<BlockStanding, &'static str> {
            let tip = self.tip.borrow().clone();
            if hash == self.parent_hash && (tip == self.parent_hash || tip == self.heavy) {
                Ok(BlockStanding::Active)
            } else {
                Ok(BlockStanding::NotConnected)
            }
        }
    }

    struct ReplayOracle {
        setup_hex: String,
        setup_hash: String,
        reconsidered: Cell<bool>,
        stay_invalid: bool,
    }

    impl BlockOracle for ReplayOracle {
        fn submitblock_hex(&self, hex: &str) -> OracleReply {
            if hex == self.setup_hex {
                if !self.reconsidered.get() || self.stay_invalid {
                    return OracleReply::Reason("duplicate-invalid".into());
                }
                return OracleReply::Reason("duplicate".into());
            }
            if self.reconsidered.get() {
                OracleReply::NullAccept
            } else {
                OracleReply::Reason("bad-prevblk".into())
            }
        }
        fn core_reconsider_block(&self, hash: &str) -> Result<(), &'static str> {
            if hash == self.setup_hash {
                self.reconsidered.set(true);
            }
            Ok(())
        }
        fn block_standing(&self, hash: &str) -> Result<BlockStanding, &'static str> {
            if hash == self.setup_hash && self.reconsidered.get() && !self.stay_invalid {
                Ok(BlockStanding::Active)
            } else {
                Ok(BlockStanding::NotConnected)
            }
        }
        fn best_block_hash(&self) -> Result<String, &'static str> {
            if self.reconsidered.get() && !self.stay_invalid {
                Ok(self.setup_hash.clone())
            } else {
                Ok("00".repeat(32))
            }
        }
    }
}
