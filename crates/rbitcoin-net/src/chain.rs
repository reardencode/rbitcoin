//! Shared chain accept path for P2P: tip extension and most-work reorg.
//!
//! Lock order: `connect_lock` then inner maps (`held_bodies`, `invalidated`,
//! `header_tips`, …). Never acquire `connect_lock` while holding an inner guard.

use crate::cache::BlockCache;
use crate::error::NetError;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Target, Transaction, TxOut, Txid,
    Work,
};
use rbitcoin_consensus::{
    accept_and_connect_block_preverified, confirm_wire_load_from_plan as consensus_load_from_plan,
    confirm_wire_load_phase_pipelined, confirm_write_phase, genesis_block, header_to_record,
    mine_op_true_signet_paying, mine_regtest_paying, validate_header, validate_header_on_parent,
    ChainParams, Milestone, PlanStampOutcome, ScriptOkBatch, ScriptPreverified, WireLoadPipeline,
};
use rbitcoin_log::{debug, info};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::{broadcast, Notify};

/// Emitted when the best-chain tip advances (extension or reorg).
#[derive(Debug, Clone)]
pub struct TipEvent {
    pub height: u32,
    pub hash: BlockHash,
    pub header: Header,
    /// New-branch length when this tip came from `accept_branch` (0 = tip-extend).
    /// `p2p_sendheaders`: >8 → announce inv and pause headers.
    pub reorg_branch_len: u32,
}

struct HeaderSyncNode {
    fk: Fk,
    header: Header,
    /// Resolved height. `None` means the ancestor walk hit the cap; children
    /// of that node must not walk again.
    height: Option<u32>,
}

/// Never-confirmed side-branch bodies plus first-seen seq (equal-work FIFO).
struct HeldBodies {
    by_hash: HashMap<BlockHash, (Arc<Block>, u64)>,
    next_seq: u64,
}

impl HeldBodies {
    const CAP: usize = 320;
    const STALE_BELOW: u32 = 288;
    /// One honest max block. A larger body is not held.
    const MAX_BLOCK_SERIALIZED: usize = 4_000_000;

    fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            next_seq: 1,
        }
    }

    fn wire_len(block: &Block) -> usize {
        block.total_size()
    }

    fn get(&self, hash: &BlockHash) -> Option<&Block> {
        self.by_hash.get(hash).map(|(b, _)| b.as_ref())
    }

    fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn contains(&self, hash: &BlockHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    fn keys(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.keys().copied()
    }

    fn blocks(&self) -> impl Iterator<Item = &Block> + '_ {
        self.by_hash.values().map(|(b, _)| b.as_ref())
    }

    fn entries(&self) -> impl Iterator<Item = (BlockHash, &Block)> + '_ {
        self.by_hash.iter().map(|(h, (b, _))| (*h, b.as_ref()))
    }

    fn seq(&self, hash: BlockHash) -> u64 {
        self.by_hash.get(&hash).map(|(_, s)| *s).unwrap_or(u64::MAX)
    }

    fn insert(&mut self, block: Arc<Block>, keep: &HashSet<BlockHash>) {
        let hash = block.block_hash();
        if self.by_hash.contains_key(&hash) {
            return;
        }
        let nbytes = Self::wire_len(&block);
        if nbytes > Self::MAX_BLOCK_SERIALIZED {
            return;
        }
        while self.by_hash.len() >= Self::CAP {
            let victim = self
                .by_hash
                .iter()
                .filter(|(h, _)| !keep.contains(*h))
                .min_by_key(|(_, (_, s))| *s)
                .map(|(h, _)| *h)
                .or_else(|| {
                    self.by_hash
                        .iter()
                        .min_by_key(|(_, (_, s))| *s)
                        .map(|(h, _)| *h)
                });
            if let Some(k) = victim {
                self.by_hash.remove(&k);
            } else {
                break;
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.by_hash.insert(hash, (block, seq));
    }

    fn remove(&mut self, hash: &BlockHash) {
        self.by_hash.remove(hash);
    }
}

/// Operator-invalidated hashes and best-chain paths (hashes only, height order).
struct Invalidated {
    set: RwLock<HashSet<BlockHash>>,
    paths: RwLock<Vec<Vec<BlockHash>>>,
}

impl Invalidated {
    fn new() -> Self {
        Self {
            set: RwLock::new(HashSet::new()),
            paths: RwLock::new(Vec::new()),
        }
    }
}

/// Header-only tips (`submitheader` / P2P headers): hash → (prev, height).
struct HeaderTips {
    by_hash: HashMap<BlockHash, (BlockHash, u32)>,
}

impl HeaderTips {
    fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
        }
    }

    fn get(&self, hash: &BlockHash) -> Option<(BlockHash, u32)> {
        self.by_hash.get(hash).copied()
    }

    fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.get(hash).map(|(_, h)| h)
    }

    fn contains(&self, hash: &BlockHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn insert(&mut self, hash: BlockHash, prev: BlockHash, height: u32) {
        self.by_hash.insert(hash, (prev, height));
    }

    fn remove(&mut self, hash: &BlockHash) {
        self.by_hash.remove(hash);
    }

    fn evict_one(&mut self) {
        if let Some(k) = self.by_hash.keys().next().copied() {
            self.by_hash.remove(&k);
        }
    }

    fn hashes(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.keys().copied()
    }

    fn prevs(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.values().map(|(prev, _)| *prev)
    }

    fn entries(&self) -> impl Iterator<Item = (BlockHash, u32)> + '_ {
        self.by_hash.iter().map(|(hash, (_, h))| (*hash, *h))
    }
}

/// Mining / GBT knobs. Atomics so façade getters stay lock-free.
struct MiningKnobs {
    block_version: AtomicI32,
    gbt_assembled: AtomicBool,
    block_min_tx_fee_sat_kvb: AtomicU64,
}

impl MiningKnobs {
    fn new() -> Self {
        Self {
            block_version: AtomicI32::new(0),
            gbt_assembled: AtomicBool::new(false),
            block_min_tx_fee_sat_kvb: AtomicU64::new(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// New best tip.
    Accepted { height: u32 },
    /// Already in store / cache.
    AlreadyHave,
    /// Same height competing tip with less or equal work — ignored.
    IgnoredWeaker,
}

/// Reconstructed compact/body does not match the header, or witness bytes
/// that are not committed in the hash. Do not cache the hash as permanently
/// failed. Weight after a matching commitment is the block's own fault.
pub(crate) fn reject_is_mutated(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("merkle")
        || reason.contains("bad-txnmrklroot")
        || reason.contains("bad-txns-duplicate")
        || reason.contains("witness commitment")
        || reason.contains("bad-witness-nonce")
        || reason.contains("missing witness commitment")
        || reason.contains("wtxid count")
        || reason.contains("unexpected witness")
}

/// Core logs a contextual header reject (`bad-version`, `time-too-new`) with
/// its reason. The returned error keeps the store-facing Display string.
/// A consensus header failure names the block so it can be marked invalid.
/// A store fault stays a store fault: it must not be cached as `BLOCK_FAILED`.
fn connect_failed_for_header(hash: [u8; 32], e: NetError) -> NetError {
    match e {
        NetError::Consensus(msg) => NetError::ConnectFailed { hash, msg },
        other => other,
    }
}

fn header_reject(header: &Header, e: &rbitcoin_consensus::ConsensusError) -> NetError {
    if let rbitcoin_consensus::ConsensusError::Store(se) = e {
        return NetError::store(se);
    }
    let reason = rbitcoin_consensus::block_reject_reason(e);
    rbitcoin_log::info!(
        "{}",
        rbitcoin_consensus::block_reject_log_line(header.block_hash(), &reason)
    );
    NetError::Consensus(e.to_string())
}

pub(crate) fn accept_err_is_temporary_time(e: &NetError) -> bool {
    match e {
        NetError::Consensus(s) | NetError::ConnectFailed { msg: s, .. } => {
            let s = s.to_ascii_lowercase();
            s.contains("time-too-new")
                || s.contains("time-too-old")
                || s.contains("timestamp too far in future")
                || s.contains("median-time-past")
        }
        _ => false,
    }
}

/// Default tip recency window (24h).
pub const DEFAULT_MAX_TIP_AGE_SECS: u64 = 24 * 60 * 60;

/// IBD fee filter (`p2p_ibd_txrelay.py` `MAX_FEE_FILTER`).
pub const IBD_FEEFILTER_SAT_KVB: u64 = 9_936_506;

/// Stale blocks older than this vs the best header are not served (`p2p_fingerprint`).
pub const STALE_RELAY_AGE_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;

/// Thread-safe chain façade used by peer sessions.
pub struct ChainHub {
    pub query: Arc<Query>,
    pub cache: Arc<BlockCache>,
    pub params: ChainParams,
    pub milestone: Milestone,
    pub notify: Arc<Notify>,
    tip_tx: broadcast::Sender<TipEvent>,
    /// Best-chain confirmed block hashes (O(1) `has_block` for IBD hot path).
    confirmed: Arc<RwLock<HashSet<BlockHash>>>,
    /// Serializes tip connect / reorg so multi-peer accept cannot double Class A+C.
    connect_lock: std::sync::Mutex<()>,
    /// Serializes regtest generate so concurrent generateblock cannot race one tip.
    generate_lock: std::sync::Mutex<()>,
    /// Optional cluster mempool (tip-mode tx relay + confirm remove).
    ///
    /// Attached once via [`Self::attach_mempool`] after the hub is in an `Arc`.
    mempool: std::sync::OnceLock<Arc<crate::tx_relay::MempoolHub>>,
    /// Filled by [`Self::into_arc`]. Async tip jobs clone it.
    self_weak: std::sync::OnceLock<std::sync::Weak<ChainHub>>,
    /// Regtest `setmocktime` / generate timestamps. Default is wall clock.
    pub clock: Arc<rbitcoin_consensus::NodeClock>,
    invalidated: Invalidated,
    /// Never-confirmed side-branch bodies, keyed by hash. Small cap.
    /// Not a block index: once-confirmed losers stay in Class A.
    held_bodies: RwLock<HeldBodies>,
    precious: RwLock<Option<BlockHash>>,
    /// Losing tips after a most-work reorg (hashes only). Bodies via archive.
    fork_tips: RwLock<HashSet<BlockHash>>,
    /// Header-only tips (`submitheader` / P2P headers): hash → (prev, height).
    header_tips: RwLock<HeaderTips>,
    /// Set around `accept_branch` connect so each `TipEvent` carries branch length.
    announce_reorg_len: AtomicU32,
    /// Min-chain-work floor (32-byte BE). `None` = no extra floor.
    minimum_chain_work: RwLock<Option<[u8; 32]>>,
    mining: MiningKnobs,
    /// Tip recency seconds. Default 24h.
    max_tip_age_secs: AtomicU64,
    prefill_compact: AtomicBool,
    prefill_plan: std::sync::Mutex<Option<crate::compact::PrefillPlan>>,
    /// Block hashes we already issued getdata for (any peer).
    asked_blocks: RwLock<HashSet<BlockHash>>,
    /// `prefix[h] = work through height h` on the best chain. Process cache;
    /// rebuilt from wire headers when short, truncated on disconnect.
    chain_work_prefix: RwLock<Vec<Work>>,
    /// Once the relay-inhibited latch clears, stay out.
    finished_ibd: AtomicBool,
    #[cfg(test)]
    block_at_height_calls: AtomicU64,
    #[cfg(test)]
    header_contextual_checks: AtomicU64,
    #[cfg(test)]
    stored_height_walk_steps: AtomicU64,
    /// Test stand-in for the 10_000-step ancestor cap. Production uses 10_000.
    #[cfg(test)]
    stored_height_walk_cap: AtomicU32,
}

/// One `getchaintips` row. Status is a Core-shaped string (`active`,
/// `valid-fork`, `valid-headers`, `headers-only`, `invalid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTipInfo {
    pub height: u32,
    pub hash: BlockHash,
    pub branchlen: u32,
    pub status: &'static str,
}

/// Equal total work prefers the precious tip, then the earlier held tip.
/// A precious hash missing from the hold map has sequence `u64::MAX`; the
/// precious bit wins before that comparison.
fn held_branch_beats(
    candidate: Work,
    candidate_precious: bool,
    candidate_seq: u64,
    incumbent: Work,
    incumbent_precious: bool,
    incumbent_seq: u64,
) -> bool {
    let tie = !work_better(incumbent, candidate);
    work_better(candidate, incumbent)
        || (tie && !incumbent_precious && (candidate_precious || candidate_seq < incumbent_seq))
}

impl ChainHub {
    pub fn new(query: Query, params: ChainParams, milestone: Milestone) -> Self {
        let (tip_tx, _) = broadcast::channel(64);
        let query = Arc::new(query);
        let confirmed = Arc::new(RwLock::new(seed_confirmed_tip(&query)));
        // Full confirmed-set fill in background (mainnet-scale tips make a
        // synchronous walk multi-minute). Tip/genesis are seeded immediately.
        spawn_confirmed_seed(query.clone(), confirmed.clone());
        Self {
            query,
            cache: Arc::new(BlockCache::new()),
            params,
            milestone,
            notify: Arc::new(Notify::new()),
            tip_tx,
            confirmed,
            connect_lock: std::sync::Mutex::new(()),
            generate_lock: std::sync::Mutex::new(()),
            mempool: std::sync::OnceLock::new(),
            self_weak: std::sync::OnceLock::new(),
            clock: rbitcoin_consensus::NodeClock::new(),
            invalidated: Invalidated::new(),
            held_bodies: RwLock::new(HeldBodies::new()),
            precious: RwLock::new(None),
            fork_tips: RwLock::new(HashSet::new()),
            header_tips: RwLock::new(HeaderTips::new()),
            announce_reorg_len: AtomicU32::new(0),
            minimum_chain_work: RwLock::new(None),
            mining: MiningKnobs::new(),
            max_tip_age_secs: AtomicU64::new(DEFAULT_MAX_TIP_AGE_SECS),
            prefill_compact: AtomicBool::new(false),
            prefill_plan: std::sync::Mutex::new(None),
            asked_blocks: RwLock::new(HashSet::new()),
            chain_work_prefix: RwLock::new(Vec::new()),
            finished_ibd: AtomicBool::new(false),
            #[cfg(test)]
            block_at_height_calls: AtomicU64::new(0),
            #[cfg(test)]
            header_contextual_checks: AtomicU64::new(0),
            #[cfg(test)]
            stored_height_walk_steps: AtomicU64::new(0),
            #[cfg(test)]
            stored_height_walk_cap: AtomicU32::new(10_000),
        }
    }

    pub fn note_asked_block(&self, hash: BlockHash) {
        let mut g = self.asked_blocks.write().unwrap();
        if g.len() >= 4096 {
            g.clear();
        }
        g.insert(hash);
    }

    pub fn forget_asked_block(&self, hash: &BlockHash) {
        self.asked_blocks.write().unwrap().remove(hash);
    }

    pub fn already_have_or_asked_block(&self, hash: &BlockHash) -> bool {
        self.is_connected(hash)
            || self.held_body(hash).is_some()
            || self.asked_blocks.read().unwrap().contains(hash)
    }

    pub fn note_gbt_assembled(&self) {
        self.mining.gbt_assembled.store(true, Ordering::Relaxed);
    }

    pub fn gbt_assembled(&self) -> bool {
        self.mining.gbt_assembled.load(Ordering::Relaxed)
    }

    /// Non-zero overrides GBT `version`.
    pub fn set_block_version(&self, v: i32) {
        self.mining.block_version.store(v, Ordering::Relaxed);
    }

    /// GBT `version`: override or versionbits TOP_BITS | testdummy (bit 28).
    pub fn gbt_block_version(&self) -> i32 {
        let v = self.mining.block_version.load(Ordering::Relaxed);
        if v != 0 {
            v
        } else {
            0x2000_0000 | (1 << 28)
        }
    }

    /// Block min tx fee (sat/kvB). Default 1.
    pub fn set_block_min_tx_fee_sat_kvb(&self, sat_kvb: u64) {
        self.mining
            .block_min_tx_fee_sat_kvb
            .store(sat_kvb, Ordering::Relaxed);
    }

    pub fn block_min_tx_fee_sat_kvb(&self) -> u64 {
        self.mining.block_min_tx_fee_sat_kvb.load(Ordering::Relaxed)
    }

    /// Tip recency (seconds). Default [`DEFAULT_MAX_TIP_AGE_SECS`].
    pub fn set_max_tip_age_secs(&self, secs: u64) {
        self.max_tip_age_secs.store(secs, Ordering::Relaxed);
    }

    pub fn max_tip_age_secs(&self) -> u64 {
        self.max_tip_age_secs.load(Ordering::Relaxed)
    }

    pub fn set_prefill_compact(&self, on: bool) {
        self.prefill_compact.store(on, Ordering::Relaxed);
    }

    pub fn prefill_compact(&self) -> bool {
        self.prefill_compact.load(Ordering::Relaxed)
    }

    pub fn remember_cmpct_prefill(&self, hash: BlockHash, prev: BlockHash, indexes: Vec<usize>) {
        if !self.prefill_compact() {
            return;
        }
        if self.tip_hash() != Some(prev) {
            return;
        }
        *self.prefill_plan.lock().expect("prefill plan") =
            Some(crate::compact::PrefillPlan { hash, indexes });
    }

    pub fn remember_cmpct_prefill_from_block(&self, block: &Block) {
        if !self.prefill_compact() {
            return;
        }
        if self.tip_hash() != Some(block.header.prev_blockhash) {
            return;
        }
        let hash = block.block_hash();
        {
            let g = self.prefill_plan.lock().expect("prefill plan");
            if g.as_ref().is_some_and(|p| p.hash == hash) {
                return;
            }
        }
        let Some(fill) = self
            .mempool()
            .and_then(|mp| mp.try_cmpct_fill_sets(&block.txdata))
        else {
            return;
        };
        self.remember_cmpct_prefill(
            hash,
            block.header.prev_blockhash,
            crate::compact::prefill_indexes(block, &fill),
        );
    }

    pub fn cmpct_prefill_indexes(&self, hash: &BlockHash) -> Option<Vec<usize>> {
        if !self.prefill_compact() {
            return None;
        }
        let g = self.prefill_plan.lock().expect("prefill plan");
        g.as_ref()
            .filter(|p| p.hash == *hash)
            .map(|p| p.indexes.clone())
    }

    /// Min-chain-work floor. Below the floor: no getheaders serve, no tip relay.
    pub fn set_minimum_chain_work(&self, w: Option<[u8; 32]>) {
        *self.minimum_chain_work.write().unwrap() = w;
    }

    /// Claimed nBits meet `pow_limit` and the hash meets that target.
    pub(crate) fn header_claimed_pow_ok(&self, header: &Header) -> bool {
        let target = Target::from_compact(header.bits);
        target <= self.params.pow_limit && header.validate_pow(target).is_ok()
    }

    /// Work of `header` hanging off a known parent (tip-extend, header-only
    /// chain, or side), else just the header's own work.
    pub fn work_with_header(&self, header: &Header) -> Work {
        let mut extra = Vec::new();
        if self.header_claimed_pow_ok(header) {
            if let Ok(w) = crate::most_work::header_work_checked(header) {
                extra.push(w);
            }
        }
        let mut prev = header.prev_blockhash;
        for _ in 0..10_000 {
            if prev.to_byte_array() == [0u8; 32] {
                return crate::most_work::sum_work(extra.into_iter())
                    .unwrap_or(Work::from_be_bytes([0xff; 32]));
            }
            if let Some(h) = self
                .query
                .height_of_hash(&prev.to_byte_array())
                .ok()
                .flatten()
            {
                let base = self
                    .work_through_height(h.0)
                    .unwrap_or(Work::from_be_bytes([0u8; 32]));
                extra.push(base);
                return crate::most_work::sum_work(extra.into_iter())
                    .unwrap_or(Work::from_be_bytes([0xff; 32]));
            }
            let Some(hdr) = self.header_of(&prev) else {
                return crate::most_work::sum_work(extra.into_iter())
                    .unwrap_or(Work::from_be_bytes([0xff; 32]));
            };
            if self.header_claimed_pow_ok(&hdr) {
                if let Ok(w) = crate::most_work::header_work_checked(&hdr) {
                    extra.push(w);
                }
            }
            prev = hdr.prev_blockhash;
        }
        crate::most_work::sum_work(extra.into_iter()).unwrap_or(Work::from_be_bytes([0xff; 32]))
    }

    /// Unrequested body more than 288 heights above the validated tip.
    pub fn unrequested_too_far_ahead(&self, header: &Header) -> bool {
        let tip = self.tip_height().unwrap_or(0);
        let prev = header.prev_blockhash;
        let parent_h = self
            .query
            .height_of_hash(&prev.to_byte_array())
            .ok()
            .flatten()
            .map(|h| h.0)
            .or_else(|| self.header_tips.read().unwrap().height_of(&prev));
        let Some(parent_h) = parent_h else {
            return false;
        };
        parent_h.saturating_add(1) > tip.saturating_add(HeldBodies::STALE_BELOW)
    }

    /// True when connecting `header` would still be below `-minimumchainwork`.
    pub fn header_below_minwork(&self, header: &Header) -> bool {
        let Some(min) = self.min_chain_work_floor() else {
            return false;
        };
        self.work_with_header(header).to_be_bytes() < min
    }

    /// Core `GetAntiDoSWorkThreshold`: `max(tip_work - 144*tip_proof, minchainwork)`.
    pub(crate) fn anti_dos_work_threshold(&self) -> Work {
        let zero = Work::from_be_bytes([0u8; 32]);
        let tip_work = self.chain_work().unwrap_or(zero);
        let one = self.tip_header().map(|h| h.work()).unwrap_or(zero);
        let mut window = zero;
        for _ in 0..144 {
            let next = window + one;
            if next > tip_work {
                window = tip_work;
                break;
            }
            window = next;
        }
        let near = tip_work - window;
        match self.min_chain_work_floor() {
            Some(min) => {
                let floor = Work::from_be_bytes(min);
                if near > floor {
                    near
                } else {
                    floor
                }
            }
            None => near,
        }
    }

    /// Compact/header whose claimed work is below the anti-DoS threshold.
    /// Unknown prev is not low-work (Core sends getheaders instead).
    pub(crate) fn header_below_anti_dos(&self, header: &Header) -> bool {
        let prev = header.prev_blockhash;
        if self
            .query
            .height_of_hash(&prev.to_byte_array())
            .ok()
            .flatten()
            .is_none()
        {
            return false;
        }
        self.work_with_header(header) < self.anti_dos_work_threshold()
    }

    /// True when tip work meets `-minimumchainwork` (or the flag is unset).
    pub fn meets_minimum_chain_work(&self) -> bool {
        let min = *self.minimum_chain_work.read().unwrap();
        match min {
            None => true,
            Some(min) => match self.chain_work() {
                Ok(w) => w.to_be_bytes() >= min,
                Err(_) => false,
            },
        }
    }

    /// Min-chain-work floor (32-byte BE), if set.
    pub fn min_chain_work_floor(&self) -> Option<[u8; 32]> {
        *self.minimum_chain_work.read().unwrap()
    }

    /// Sum wire-header work from genesis through `height` (inclusive) on the tip chain.
    pub fn work_through_height(&self, height: u32) -> Result<Work, NetError> {
        let Some(tip) = self.tip_height() else {
            return Ok(Work::from_be_bytes([0u8; 32]));
        };
        self.ensure_chain_work_prefix()?;
        let p = self.chain_work_prefix.read().unwrap();
        let i = height.min(tip) as usize;
        Ok(p.get(i)
            .copied()
            .unwrap_or_else(|| Work::from_be_bytes([0u8; 32])))
    }

    /// Tip recency vs [`Self::clock`] (default 24h).
    pub fn tip_is_stale_for_ibd(&self) -> bool {
        let Some(h) = self.tip_header() else {
            return true;
        };
        self.clock.now_secs().saturating_sub(u64::from(h.time)) > self.max_tip_age_secs()
    }

    /// Relay-inhibited: tip too old **or** work below the min-chain-work floor.
    /// Latches false after the first leave.
    pub fn in_ibd(&self) -> bool {
        if self.finished_ibd.load(Ordering::Acquire) {
            return false;
        }
        let ibd = !self.meets_minimum_chain_work() || self.tip_is_stale_for_ibd();
        if !ibd {
            self.finished_ibd.store(true, Ordering::Release);
        }
        ibd
    }

    /// Active-chain always; stale only if best-header time minus block time
    /// is under one month.
    pub fn stale_relay_allowed(&self, hash: &BlockHash) -> bool {
        if self.is_connected(hash) {
            return true;
        }
        let Some(hdr) = self.header_of(hash) else {
            return false;
        };
        let Some(best) = self.tip_header() else {
            return false;
        };
        u64::from(best.time).saturating_sub(u64::from(hdr.time)) < STALE_RELAY_AGE_LIMIT_SECS
    }

    /// BIP133 feefilter we advertise: rounded MAX_MONEY while IBD, else the
    /// published admission floor (configured min, near-full bump, or rolling
    /// eviction). The floor is an atomic so this stays off `inner`.
    pub fn feefilter_sat_kvb(&self) -> u64 {
        if self.in_ibd() {
            return IBD_FEEFILTER_SAT_KVB;
        }
        self.mempool()
            .map(|m| m.fee_floor_sat_kvb())
            .unwrap_or(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB)
    }

    /// Attach mempool once (same Query Arc as this hub).
    pub fn attach_mempool(
        &self,
        mp: Arc<crate::tx_relay::MempoolHub>,
    ) -> Result<(), Arc<crate::tx_relay::MempoolHub>> {
        self.mempool.set(mp)
    }

    pub fn mempool(&self) -> Option<&Arc<crate::tx_relay::MempoolHub>> {
        self.mempool.get()
    }

    pub fn subscribe_tips(&self) -> broadcast::Receiver<TipEvent> {
        self.tip_tx.subscribe()
    }

    /// Ensure the genesis block is in the store (required before IBD getheaders).
    ///
    /// Peers never re-serve genesis via `getheaders` after the common ancestor;
    /// an empty store must start with height 0 locally.
    pub fn ensure_genesis(&self) -> Result<(), NetError> {
        if self.tip_height().is_some() {
            return Ok(());
        }
        crate::tip_accept::run_on_tip_accept(|| self.ensure_genesis_inner())
    }

    fn ensure_genesis_inner(&self) -> Result<(), NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.tip_height().is_some() {
            return Ok(());
        }
        let genesis = genesis_block(&self.params);
        if genesis.block_hash() != self.params.genesis_hash {
            return Err(NetError::Protocol("genesis hash mismatch with params"));
        }
        self.connect_at(0, Arc::new(genesis))?;
        Ok(())
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.query
            .tip_height()
            .map(|h| h.0)
            .or_else(|| self.cache.tip_height())
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.try_tip_hash().ok().flatten()
    }

    /// [`Self::tip_hash`] that keeps a store read fault as [`NetError::Store`].
    fn try_tip_hash(&self) -> Result<Option<BlockHash>, NetError> {
        // Store tip is authoritative after IBD/archive-confirm (cache may only
        // hold genesis or a short tip window while Class C is far ahead). Prefer
        // query when its height is at least the cache tip; otherwise fall back
        // to the in-memory cache chain (pre-store / regtest cache-only paths).
        let q_h = self.query.tip_height().map(|h| h.0);
        let c_h = self.cache.tip_height();
        Ok(match (q_h, c_h) {
            (Some(qh), Some(ch)) if ch > qh => self.cache.tip_hash(),
            (Some(qh), _) => self
                .query
                .header_at_height(rbitcoin_primitives::Height(qh))
                .map_err(NetError::store)?
                .map(|(_, rec)| BlockHash::from_byte_array(rec.hash)),
            (None, Some(_)) => self.cache.tip_hash(),
            (None, None) => None,
        })
    }

    pub fn tip_header(&self) -> Option<Header> {
        let h = self.tip_height()?;
        self.query.wire_header_at_height(Height(h)).ok()
    }

    /// True if `hash` is on the confirmed best chain (or in the RAM tip cache).
    ///
    /// Uses an in-memory set (tip seeded immediately; full chain filled in the
    /// background on connect). Must **not** fall back to `height_of_hash` here —
    /// header-only archive rows would force multi-thousand-height scans per call.
    pub fn has_block(&self, hash: &BlockHash) -> bool {
        if self.cache.get_block(hash).is_some() {
            return true;
        }
        self.confirmed.read().unwrap().contains(hash)
    }

    /// True if `hash` is connected on the best chain (has a height).
    ///
    /// Download / fork-start decisions must use this, not [`Self::has_block`]:
    /// the RAM body cache can evict, and `confirmed` is insert-only across
    /// reorgs. A stale "we have it" would permanently suppress getdata.
    pub fn is_connected(&self, hash: &BlockHash) -> bool {
        self.query
            .height_of_hash(&hash.to_byte_array())
            .ok()
            .flatten()
            .is_some()
    }

    /// Active tip plus known side tips (held / archive losers / invalidate).
    ///
    /// Losing tips are hashes only; bodies come from hold or
    /// [`Query::reconstruct_archived_block`]. Not a Core block index.
    pub fn chaintips(&self) -> Vec<ChainTipInfo> {
        let mut out: HashMap<BlockHash, ChainTipInfo> = HashMap::new();
        if let (Some(height), Some(hash)) = (self.tip_height(), self.tip_hash()) {
            out.insert(
                hash,
                ChainTipInfo {
                    height,
                    hash,
                    branchlen: 0,
                    status: "active",
                },
            );
        }

        let record =
            |map: &mut HashMap<BlockHash, ChainTipInfo>, hash: BlockHash, status: &'static str| {
                if map.get(&hash).map(|t| t.status) == Some("active") {
                    return;
                }
                if self.is_connected(&hash) {
                    return;
                }
                let Some((height, branchlen)) = self.side_height_and_branchlen(hash) else {
                    return;
                };
                let rank = |s: &str| match s {
                    "invalid" => 3,
                    "valid-fork" => 2,
                    "valid-headers" => 1,
                    "headers-only" => 0,
                    _ => 0,
                };
                match map.get(&hash) {
                    Some(prev) if rank(prev.status) >= rank(status) => {}
                    _ => {
                        map.insert(
                            hash,
                            ChainTipInfo {
                                height,
                                hash,
                                branchlen,
                                status,
                            },
                        );
                    }
                }
            };

        for h in self.fork_tips.read().unwrap().iter().copied() {
            record(&mut out, h, "valid-fork");
        }
        // The header and held walks below re-read `header_tips` and
        // `held_bodies` (`prev_of`, `load_side_body`), so each set is copied
        // out and its guard dropped first; see `best_header_height`.
        {
            let (covered, hashes): (HashSet<BlockHash>, Vec<BlockHash>) = {
                let headers = self.header_tips.read().unwrap();
                (headers.prevs().collect(), headers.hashes().collect())
            };
            // Only header *tips* (a later submitblock of an ancestor must not
            // re-list that ancestor alongside its descendant).
            for hash in hashes {
                if covered.contains(&hash) {
                    continue;
                }
                let status = if self.header_ancestry_invalid(hash) {
                    "invalid"
                } else {
                    "headers-only"
                };
                record(&mut out, hash, status);
            }
        }
        {
            let (parents, hashes): (HashSet<BlockHash>, Vec<BlockHash>) = {
                let held = self.held_bodies.read().unwrap();
                (
                    held.blocks().map(|b| b.header.prev_blockhash).collect(),
                    held.keys().collect(),
                )
            };
            for hash in hashes {
                if parents.contains(&hash) {
                    continue;
                }
                let status = if self.held_path_has_body_gap(hash) {
                    "headers-only"
                } else {
                    "valid-headers"
                };
                record(&mut out, hash, status);
            }
        }
        for path in self.invalidated.paths.read().unwrap().iter() {
            if let Some(h) = path.last().copied() {
                record(&mut out, h, "invalid");
            }
        }

        let mut tips: Vec<ChainTipInfo> = out.into_values().collect();
        tips.sort_by(|a, b| {
            b.height
                .cmp(&a.height)
                .then_with(|| a.hash.to_byte_array().cmp(&b.hash.to_byte_array()))
        });
        tips
    }

    fn held_path_has_body_gap(&self, tip: BlockHash) -> bool {
        let mut h = tip;
        for _ in 0..10_000 {
            if self.is_connected(&h) {
                return false;
            }
            if self.load_side_body(&h).is_none() {
                return true;
            }
            let Some(prev) = self.prev_of(&h) else {
                return true;
            };
            if prev.to_byte_array() == [0u8; 32] {
                return false;
            }
            h = prev;
        }
        true
    }

    /// Prev hash from a held/archive body, header-only tip, or the header store.
    pub(crate) fn prev_of(&self, hash: &BlockHash) -> Option<BlockHash> {
        if let Some(b) = self.load_side_body(hash) {
            return Some(b.header.prev_blockhash);
        }
        if let Some((prev, _)) = self.header_tips.read().unwrap().get(hash) {
            return Some(prev);
        }
        let (_, rec) = self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()?;
        if rec.prev_fk.is_null() {
            return Some(BlockHash::from_byte_array([0u8; 32]));
        }
        self.query
            .get_header(rec.prev_fk)
            .ok()
            .map(|p| BlockHash::from_byte_array(p.hash))
    }

    fn header_ancestry_invalid(&self, tip: BlockHash) -> bool {
        let inv = self.invalidated.set.read().unwrap();
        if inv.contains(&tip) {
            return true;
        }
        let mut h = tip;
        for _ in 0..10_000 {
            let Some(prev) = self.prev_of(&h) else {
                return false;
            };
            if prev.to_byte_array() == [0u8; 32] || self.is_connected(&prev) {
                return false;
            }
            if inv.contains(&prev) {
                return true;
            }
            h = prev;
        }
        false
    }

    /// Height of a non-active tip and the length of the branch to the best chain.
    fn side_height_and_branchlen(&self, tip: BlockHash) -> Option<(u32, u32)> {
        let mut h = tip;
        let mut branchlen = 0u32;
        for _ in 0..10_000 {
            let prev = self.prev_of(&h)?;
            branchlen = branchlen.saturating_add(1);
            if prev.to_byte_array() == [0u8; 32] {
                return Some((branchlen.saturating_sub(1), branchlen));
            }
            if self.is_connected(&prev) {
                let parent_h = self
                    .query
                    .height_of_hash(&prev.to_byte_array())
                    .ok()
                    .flatten()?
                    .0;
                return Some((parent_h.saturating_add(branchlen), branchlen));
            }
            h = prev;
        }
        None
    }

    /// Best known header height (may lead `blocks` after `submitheader`).
    ///
    /// Copies the tips out before walking: `prev_of` read-locks `header_tips`
    /// again, and std's `RwLock` refuses a new reader while a writer waits, so
    /// a walk under the guard deadlocks against `note_header_tip`.
    pub fn best_header_height(&self) -> u32 {
        let mut best = self.tip_height().unwrap_or(0);
        let tips: Vec<(BlockHash, u32)> = self.header_tips.read().unwrap().entries().collect();
        for (hash, h) in tips {
            if !self.header_ancestry_invalid(hash) {
                best = best.max(h);
            }
        }
        best
    }

    fn note_header_tip(&self, header: &Header) {
        let hash = header.block_hash();
        if self.is_connected(&hash) {
            self.header_tips.write().unwrap().remove(&hash);
            return;
        }
        let prev = header.prev_blockhash;
        let height = if self.is_connected(&prev) {
            self.query
                .height_of_hash(&prev.to_byte_array())
                .ok()
                .flatten()
                .map(|h| h.0.saturating_add(1))
        } else {
            self.header_tips
                .read()
                .unwrap()
                .get(&prev)
                .map(|(_, h)| h.saturating_add(1))
        };
        let Some(height) = height else {
            return;
        };
        let mut tips = self.header_tips.write().unwrap();
        tips.remove(&prev);
        if tips.len() >= 128 && !tips.contains(&hash) {
            tips.evict_one();
        }
        tips.insert(hash, prev, height);
    }

    /// Persist a header row only (for header-sync → out-of-order body archive).
    pub fn ensure_header(&self, header: &Header) -> Result<(), NetError> {
        let _ = self.ensure_header_fk(header)?;
        Ok(())
    }

    /// Best-chain or header-only height of `hash`.
    pub fn header_height(&self, hash: &BlockHash) -> Option<u32> {
        if let Some(h) = self
            .query
            .height_of_hash(&hash.to_byte_array())
            .ok()
            .flatten()
        {
            return Some(h.0);
        }
        self.header_tips.read().unwrap().height_of(hash)
    }

    /// Whether `hash` is marked invalid (`invalidateblock` or rejected `submitblock`).
    pub fn is_block_invalid(&self, hash: &BlockHash) -> bool {
        self.invalidated.set.read().unwrap().contains(hash) || self.header_ancestry_invalid(*hash)
    }

    /// Remember a consensus-invalid block (not a mutated merkle).
    pub fn note_invalid_block(&self, hash: BlockHash) {
        self.invalidated.set.write().unwrap().insert(hash);
        self.drop_held(hash);
    }

    /// A reconstructed compact with the right header hash and wrong txs must
    /// not poison later getdata of that hash.
    fn remember_failed_accept(&self, offered: BlockHash, e: &NetError) {
        let hash = e
            .failing_block_hash()
            .map(BlockHash::from_byte_array)
            .unwrap_or(offered);
        if e.is_mutated() || accept_err_is_temporary_time(e) {
            self.drop_held(hash);
            self.forget_asked_block(&hash);
            return;
        }
        if e.failing_block_hash().is_some() {
            self.note_invalid_block(hash);
            return;
        }
        if let NetError::Consensus(s) = e {
            if !s.to_ascii_lowercase().contains("not found") {
                self.note_invalid_block(hash);
            }
        }
    }

    /// True if we have a header row (best chain, header-only tip, or held body).
    /// Used so we never `getdata` a block inv whose header we have not seen.
    pub fn knows_header(&self, hash: &BlockHash) -> bool {
        self.is_connected(hash)
            || self.header_tips.read().unwrap().contains(hash)
            || self
                .query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .is_some()
            || self.held_body(hash).is_some()
    }

    /// `ancestor` is `descendant` or lies on its prev walk (disconnected ok).
    pub(crate) fn is_header_ancestor(&self, ancestor: BlockHash, descendant: BlockHash) -> bool {
        if ancestor == descendant {
            return true;
        }
        if ancestor.to_byte_array() == [0u8; 32] {
            return true;
        }
        let mut h = descendant;
        for _ in 0..64 {
            let Some(prev) = self.prev_of(&h) else {
                return false;
            };
            if prev == ancestor {
                return true;
            }
            if prev.to_byte_array() == [0u8; 32] {
                return false;
            }
            h = prev;
        }
        false
    }

    /// Header for a connected, held, archived, or header-only hash.
    pub(crate) fn header_of(&self, hash: &BlockHash) -> Option<bitcoin::block::Header> {
        if let Some(b) = self.load_side_body(hash) {
            return Some(b.header);
        }
        if let Some(h) = self
            .query
            .height_of_hash(&hash.to_byte_array())
            .ok()
            .flatten()
        {
            if let Ok(Some(b)) = self.block_at_height(h.0) {
                if b.block_hash() == *hash {
                    return Some(b.header);
                }
            }
        }
        if let Some(b) = self
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .ok()
            .flatten()
        {
            return Some(b.header);
        }
        let (_, rec) = self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()?;
        let prev = if rec.prev_fk.is_null() {
            BlockHash::from_byte_array([0u8; 32])
        } else {
            BlockHash::from_byte_array(self.query.get_header(rec.prev_fk).ok()?.hash)
        };
        Some(bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(rec.version),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(rec.merkle_root),
            time: rec.timestamp,
            bits: bitcoin::CompactTarget::from_consensus(rec.bits),
            nonce: rec.nonce,
        })
    }

    /// `submitheader`: decode already succeeded. Missing parent, invalid
    /// parent, and MTP are reject strings (`RPC_VERIFY_ERROR` / `-25`).
    pub fn process_submitted_header(&self, header: &Header) -> Result<(), String> {
        let hash = header.block_hash();
        if self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()
            .is_some()
            || self.header_tips.read().unwrap().contains(&hash)
            || self.is_connected(&hash)
        {
            return Ok(());
        }
        let prev = header.prev_blockhash;
        let prev_bytes = prev.to_byte_array();
        let prev_known = prev_bytes == [0u8; 32]
            || self
                .query
                .get_header_by_hash(&prev_bytes)
                .ok()
                .flatten()
                .is_some()
            || self.header_tips.read().unwrap().contains(&prev)
            || self.is_connected(&prev)
            || self.held_body(&prev).is_some();
        if !prev_known {
            return Err("Must submit previous header".into());
        }
        if self.is_block_invalid(&prev) {
            return Err("bad-prevblk".into());
        }
        if let Some(ph) = self.query.height_of_hash(&prev_bytes).ok().flatten() {
            if let Ok(mtp) = rbitcoin_consensus::median_time_past(self.query.as_ref(), ph) {
                if header.time <= mtp {
                    return Err("time-too-old".into());
                }
            }
        }
        self.ensure_header(header).map_err(|e| e.to_string())
    }

    /// Like [`ensure_header`], but returns the header fk for the archive writer
    /// (avoids a second hash-head probe on the hot write path).
    ///
    /// **Fail closed:** non-genesis headers require the parent row to already
    /// exist. Never write `prev_fk = NULL` for a missing parent (that created
    /// millions of orphan rows and false resume edges on mainnet).
    pub fn ensure_header_fk(&self, header: &Header) -> Result<Fk, NetError> {
        let prev_fk = self.header_sync_prev_fk(header, &HashMap::new())?;
        let rec = header_to_record(prev_fk, header, header.block_hash().to_byte_array());
        let fk = self.query.ensure_header(&rec).map_err(NetError::store)?;
        self.note_header_tip(header);
        Ok(fk)
    }

    /// Persist a headers-message batch (one store `ensure_batch`).
    ///
    /// Fail closed: missing parent is the same error as [`Self::ensure_header_fk`].
    /// Output fks align with `headers`.
    pub fn ensure_headers_batch(&self, headers: &[Header]) -> Result<Vec<Fk>, NetError> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }
        if headers.len() == 1 {
            return Ok(vec![self.ensure_header_fk(&headers[0])?]);
        }
        let mut out = vec![Fk::NULL; headers.len()];
        let mut recs: Vec<(usize, rbitcoin_store::HeaderRecord)> = Vec::new();
        let mut in_batch: HashMap<[u8; 32], HeaderSyncNode> = HashMap::new();
        let mut next = self.query.store().header_count();
        for (i, header) in headers.iter().enumerate() {
            let hash = header.block_hash().to_byte_array();
            if let Some((fk, _)) = self
                .query
                .get_header_by_hash(&hash)
                .map_err(NetError::store)?
            {
                out[i] = fk;
                let prev = header.prev_blockhash.to_byte_array();
                // A walk that returns `None` is still recorded. Omitting it
                // made every later header in the run walk to the cap again.
                let height = if let Some(parent) = in_batch.get(&prev) {
                    parent.height.map(|h| h.saturating_add(1))
                } else {
                    self.stored_header_height(&header.block_hash())
                };
                in_batch.insert(
                    hash,
                    HeaderSyncNode {
                        fk,
                        header: *header,
                        height,
                    },
                );
                continue;
            }
            let prev_fk = self.header_sync_prev_fk(header, &in_batch)?;
            let height = self
                .sync_parent_height(&header.prev_blockhash, &in_batch)
                .map(|p| p.saturating_add(1))
                .unwrap_or(0);
            next = next.saturating_add(1);
            let fk = Fk(next);
            in_batch.insert(
                hash,
                HeaderSyncNode {
                    fk,
                    header: *header,
                    height: Some(height),
                },
            );
            recs.push((i, header_to_record(prev_fk, header, hash)));
            out[i] = fk;
        }
        if !recs.is_empty() {
            let only: Vec<_> = recs.iter().map(|(_, r)| r.clone()).collect();
            let got = self.query.ensure_headers(&only).map_err(NetError::store)?;
            for ((i, _), fk) in recs.iter().zip(got) {
                out[*i] = fk;
            }
        }
        for header in headers {
            self.note_header_tip(header);
        }
        Ok(out)
    }

    fn header_sync_prev_fk(
        &self,
        header: &Header,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Result<Fk, NetError> {
        let prev_bytes = header.prev_blockhash.to_byte_array();
        let prev_fk = if prev_bytes == [0u8; 32] {
            Fk::NULL
        } else if let Some(n) = in_batch.get(&prev_bytes) {
            n.fk
        } else {
            match self
                .query
                .get_header_by_hash(&prev_bytes)
                .map_err(NetError::store)?
            {
                Some((fk, _)) => fk,
                None => {
                    return Err(NetError::Consensus(
                        "header parent unknown — ensure parent before child".into(),
                    ));
                }
            }
        };
        if prev_bytes != [0u8; 32] {
            self.header_sync_contextual(header, in_batch)?;
        }
        Ok(prev_fk)
    }

    fn header_sync_contextual(
        &self,
        header: &Header,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Result<(), NetError> {
        #[cfg(test)]
        self.header_contextual_checks
            .fetch_add(1, Ordering::Relaxed);
        let parent_hash = header.prev_blockhash;
        let parent_bytes = parent_hash.to_byte_array();
        if let Some(ph) = self.query.height_of_hash(&parent_bytes).ok().flatten() {
            return validate_header(
                self.query.as_ref(),
                &self.params,
                Height(ph.0.saturating_add(1)),
                header,
            )
            .map_err(|e| header_reject(header, &e));
        }
        let parent = self
            .sync_parent_header(&parent_hash, in_batch)
            .ok_or_else(|| {
                NetError::Consensus("header parent unknown — ensure parent before child".into())
            })?;
        let parent_height = self
            .sync_parent_height(&parent_hash, in_batch)
            .ok_or_else(|| NetError::Consensus("header parent height unknown".into()))?;
        let mtp = self.mtp_off_tip(&parent, in_batch);
        let expected = self.expected_bits_off_tip(header, &parent, parent_height, in_batch)?;
        validate_header_on_parent(
            &self.params,
            Height(parent_height.saturating_add(1)),
            header,
            mtp,
            expected,
        )
        .map_err(|e| header_reject(header, &e))
    }

    fn sync_parent_header(
        &self,
        hash: &BlockHash,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<Header> {
        if let Some(n) = in_batch.get(&hash.to_byte_array()) {
            return Some(n.header);
        }
        self.header_of(hash)
    }

    fn sync_parent_height(
        &self,
        hash: &BlockHash,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<u32> {
        if let Some(n) = in_batch.get(&hash.to_byte_array()) {
            return n.height;
        }
        self.stored_header_height(hash)
    }

    fn stored_header_height(&self, hash: &BlockHash) -> Option<u32> {
        if let Some(h) = self.header_height(hash) {
            return Some(h);
        }
        let mut cur = *hash;
        let mut delta = 0u32;
        #[cfg(test)]
        let cap = self.stored_height_walk_cap.load(Ordering::Relaxed);
        #[cfg(not(test))]
        let cap = 10_000u32;
        for _ in 0..cap {
            #[cfg(test)]
            self.stored_height_walk_steps
                .fetch_add(1, Ordering::Relaxed);
            let hdr = self.header_of(&cur)?;
            let prev = hdr.prev_blockhash;
            if prev.to_byte_array() == [0u8; 32] {
                return Some(delta);
            }
            if let Some(ph) = self.header_height(&prev) {
                return Some(ph.saturating_add(1).saturating_add(delta));
            }
            cur = prev;
            delta = delta.saturating_add(1);
        }
        None
    }

    fn mtp_off_tip(&self, parent: &Header, in_batch: &HashMap<[u8; 32], HeaderSyncNode>) -> u32 {
        let mut times = Vec::with_capacity(11);
        let mut hdr = *parent;
        loop {
            times.push(hdr.time);
            if times.len() == 11 {
                break;
            }
            if hdr.prev_blockhash.to_byte_array() == [0u8; 32] {
                break;
            }
            match self.sync_parent_header(&hdr.prev_blockhash, in_batch) {
                Some(p) => hdr = p,
                None => break,
            }
        }
        rbitcoin_primitives::median_time_past_times(&times).unwrap_or(parent.time)
    }

    fn expected_bits_off_tip(
        &self,
        header: &Header,
        parent: &Header,
        parent_height: u32,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Result<CompactTarget, NetError> {
        let height = parent_height.saturating_add(1);
        let interval = self.params.difficulty_adjustment_interval();
        if height == 0 {
            return Ok(genesis_block(&self.params).header.bits);
        }
        if !height.is_multiple_of(interval) {
            return Ok(self.min_diff_off_tip(header, parent, parent_height, in_batch));
        }
        if self.params.no_pow_retargeting() {
            return Ok(parent.bits);
        }
        let first_h = height.saturating_sub(interval);
        let first = self
            .header_along_off_tip(parent, parent_height, first_h, in_batch)
            .ok_or_else(|| NetError::Consensus("missing retarget first header".into()))?;
        let timespan = u64::from(parent.time.saturating_sub(first.time));
        Ok(CompactTarget::from_next_work_required(
            parent.bits,
            timespan,
            &self.params.btc,
        ))
    }

    fn min_diff_off_tip(
        &self,
        header: &Header,
        parent: &Header,
        parent_height: u32,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> CompactTarget {
        if !self.params.allow_min_difficulty_blocks() {
            return parent.bits;
        }
        let limit = self.params.pow_limit.to_compact_lossy();
        let spacing = self.params.btc.pow_target_spacing;
        if u64::from(header.time) > u64::from(parent.time).saturating_add(spacing.saturating_mul(2))
        {
            return limit;
        }
        let interval = self.params.difficulty_adjustment_interval();
        let mut h = parent_height;
        let mut bits = parent.bits;
        let mut hdr = *parent;
        while !h.is_multiple_of(interval) && bits == limit {
            if h == 0 {
                break;
            }
            let Some(p) = self.sync_parent_header(&hdr.prev_blockhash, in_batch) else {
                break;
            };
            hdr = p;
            h = h.saturating_sub(1);
            bits = hdr.bits;
        }
        bits
    }

    fn header_along_off_tip(
        &self,
        parent: &Header,
        parent_height: u32,
        want: u32,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<Header> {
        if want == parent_height {
            return Some(*parent);
        }
        if want > parent_height {
            return None;
        }
        let mut hdr = *parent;
        let mut h = parent_height;
        while h > want {
            hdr = self.sync_parent_header(&hdr.prev_blockhash, in_batch)?;
            h = h.saturating_sub(1);
        }
        Some(hdr)
    }

    /// Contiguous tip-extension slice for one-shot load (owned Block).
    fn confirm_wire_contig(
        &self,
        blocks: &[(Height, Block)],
        pipeline: Option<&WireLoadPipeline>,
    ) -> Option<Vec<(Height, Block)>> {
        if blocks.is_empty() {
            return None;
        }
        let store_path_lo = match self.tip_height() {
            None => 0u32,
            Some(t) => t.saturating_add(1),
        };
        let path_lo = pipeline.map(|p| p.path_lo).unwrap_or(store_path_lo);
        let need: Vec<(Height, Block)> = blocks
            .iter()
            .filter(|(h, b)| {
                let hash = b.block_hash();
                !self.has_block(&hash) && h.0 >= path_lo
            })
            .cloned()
            .collect();
        let mut contig = Vec::new();
        for (h, b) in need {
            if h.0 != path_lo.saturating_add(contig.len() as u32) {
                break;
            }
            contig.push((h, b));
        }
        if contig.is_empty() {
            None
        } else {
            Some(contig)
        }
    }

    /// IBD **load** after lookup stamp: pin + assemble (does not re-lookup).
    ///
    /// Single path: denserels by body range from lookup stamp (`ParentPinStamp` /
    /// plan ranges). No cold denserels dual path.
    pub fn confirm_wire_load_from_plan(
        &self,
        stamped: PlanStampOutcome,
        pipeline: Option<&WireLoadPipeline>,
    ) -> Result<rbitcoin_consensus::ConfirmLoadOutcome, NetError> {
        consensus_load_from_plan(
            &self.query,
            &self.params,
            self.milestone,
            stamped,
            pipeline,
            &ScriptPreverified::new(),
        )
        .map_err(NetError::from_consensus)
    }

    /// Unified lookup+load from raw wire blocks (no Class-A wire rebuild).
    /// Skips heights already confirmed. Does **not** require prior archive.
    ///
    /// When `pipeline` is `None`, first height must be store tip+1 (legacy).
    /// When `Some`, first height is `pipeline.path_lo` so lookup(N+1) can run
    /// while write(N) has not advanced tip.
    ///
    /// One-shot path (tests / tip-follow): stamp + pin denserels by range + assemble.
    /// IBD load uses [`Self::confirm_wire_load_from_plan`] after BQ TipOnly stamp.
    pub fn confirm_wire_load_phase(
        &self,
        blocks: &[(Height, Block)],
    ) -> Result<Option<rbitcoin_consensus::ConfirmLoadOutcome>, NetError> {
        self.confirm_wire_load_phase_pipelined(blocks, None)
    }

    /// Load with optional pipeline caches (reserved create fks + in-flight creates).
    ///
    /// One-shot or pipelined load: lookup stamps then pin denserels by range.
    pub fn confirm_wire_load_phase_pipelined(
        &self,
        blocks: &[(Height, Block)],
        pipeline: Option<&WireLoadPipeline>,
    ) -> Result<Option<rbitcoin_consensus::ConfirmLoadOutcome>, NetError> {
        let Some(contig) = self.confirm_wire_contig(blocks, pipeline) else {
            return Ok(None);
        };
        let ok = confirm_wire_load_phase_pipelined(
            &self.query,
            &self.params,
            self.milestone,
            &contig,
            &ScriptPreverified::new(),
            pipeline,
        )
        .map_err(NetError::from_consensus)?;
        Ok(Some(ok))
    }

    /// WRITE stage: structural + Class C + spend annotate (ordered).
    pub fn confirm_write(&self, batch: ScriptOkBatch) -> Result<Vec<AcceptOutcome>, NetError> {
        let headers = batch.wire_headers().map_err(NetError::from_consensus)?;
        let meta: Vec<(u32, BlockHash)> = batch
            .heights_hashes()
            .into_iter()
            .map(|(h, raw)| (h, BlockHash::from_byte_array(raw)))
            .collect();
        confirm_write_phase(&self.query, &self.params, self.milestone, batch)
            .map_err(NetError::from_consensus)?;
        self.note_confirmed_tip(&meta, &headers)?;
        Ok(meta
            .iter()
            .map(|&(height, _)| AcceptOutcome::Accepted { height })
            .collect())
    }

    pub(crate) fn note_confirmed_tip(
        &self,
        need_meta: &[(u32, BlockHash)],
        headers: &[Header],
    ) -> Result<(), NetError> {
        if headers.len() != need_meta.len() {
            return Err(NetError::from_consensus(
                rbitcoin_consensus::ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                    "invariant: wire headers length",
                )),
            ));
        }
        if let Some(mp) = self.mempool() {
            mp.clear_recent_rejects();
            if mp.relay_enabled() {
                for &(height, hash) in need_meta {
                    mp.note_block_fee_history(Height(height));
                    if let Ok(Some(block)) =
                        self.query.reconstruct_block_by_hash(&hash.to_byte_array())
                    {
                        mp.note_recent_confirmed(&block.txdata);
                        let ids: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
                        let spent: Vec<_> = block
                            .txdata
                            .iter()
                            .filter(|t| !t.is_coinbase())
                            .flat_map(|t| t.input.iter().map(|i| i.previous_output))
                            .collect();
                        let n = mp.remove_for_block_spent(&ids, &spent);
                        if n > 0 {
                            rbitcoin_log::debug!("mempool: removed {n} confirmed tx(s) @ {hash}");
                        }
                    }
                }
            }
        }
        let mut confirmed = self.confirmed.write().unwrap();
        for (&(height, hash), header) in need_meta.iter().zip(headers.iter()) {
            confirmed.insert(hash);
            let _ = self.tip_tx.send(TipEvent {
                height,
                hash,
                header: *header,
                reorg_branch_len: 0,
            });
        }
        drop(confirmed);
        self.notify.notify_waiters();
        if let Some(&(height, _)) = need_meta.last() {
            self.query.release_index_writebehind(Height(height));
        }
        Ok(())
    }

    /// Block time is `max(MTP+1, now)`.
    fn generate_block_time(&self, tip_h: u32, tip_time: u32) -> u32 {
        let now = self.clock.now_secs() as u32;
        let mtp = rbitcoin_consensus::median_time_past(self.query.as_ref(), Height(tip_h))
            .unwrap_or(tip_time);
        now.max(mtp.saturating_add(1))
    }

    /// Mine one block paying `script_pubkey` without connecting it.
    ///
    /// `generateblock` with `submit=false` returns the hex for `submitheader`.
    pub fn assemble_block_to_script(
        &self,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<bitcoin::Block, NetError> {
        self.ensure_genesis()?;
        let tip_h = self
            .tip_height()
            .ok_or(NetError::Protocol("generate: no tip"))?;
        let prev = self
            .tip_hash()
            .ok_or(NetError::Protocol("generate: no tip hash"))?;
        let tip_time = self.tip_header().map(|h| h.time).unwrap_or(0);
        let time = self.generate_block_time(tip_h, tip_time);
        self.mine_paying_block(
            prev,
            time,
            tip_h.saturating_add(1),
            script_pubkey,
            extra_txs,
        )
    }

    /// Core `TestBlockValidity` for a `getblocktemplate` proposal: no PoW, no
    /// UTXO write. `Ok` is the block fees in sat; `Err` is Core's reject
    /// string.
    pub fn check_block_proposal(&self, block: &Block) -> Result<u64, String> {
        check_block_proposal_with(
            &self.query,
            &self.params,
            self.milestone,
            self.clock.now_secs() as u32,
            block,
        )
    }

    /// Regtest uses the trivial-bits miner. An `OP_TRUE` signet uses signet
    /// bits and an empty BIP325 solution so `generatetoaddress` can extend
    /// that challenge the way Bitcoin Core's miner does.
    fn mine_paying_block(
        &self,
        prev: BlockHash,
        time: u32,
        height: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<bitcoin::Block, NetError> {
        let op_true = self
            .params
            .signet_challenge
            .as_ref()
            .is_some_and(|s| s.as_bytes() == [0x51]);
        if !op_true {
            return Ok(mine_regtest_paying(
                prev,
                time,
                height,
                script_pubkey,
                extra_txs,
            ));
        }
        let bits = self
            .tip_header()
            .map(|h| h.bits)
            .ok_or(NetError::Protocol("generate: no tip header"))?;
        Ok(mine_op_true_signet_paying(
            &self.params,
            prev,
            time,
            height,
            bits,
            script_pubkey,
            extra_txs,
        ))
    }

    /// Mine `nblocks` paying `script_pubkey` and accept each via [`Self::accept_block`].
    ///
    /// Regtest harness only. Extra txs go in the first block. Ensures genesis.
    ///
    /// PoW runs on the caller, not on `tip-accept`, so an `OP_TRUE` signet
    /// grind can use extra cores. Accept stays on the lane. A peer block that
    /// wins the tip during the grind is mined again.
    pub fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, NetError> {
        if nblocks == 0 {
            return Ok(Vec::new());
        }
        if nblocks > 10_000 {
            return Err(NetError::Consensus("nblocks too large (max 10000)".into()));
        }
        self.ensure_genesis()?;
        // Serialize tip-read + mine + accept so concurrent generateblock
        // (rpc_generate.py parallel) cannot race the same tip into AlreadyHave.
        let _guard = self.generate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut hashes = Vec::with_capacity(nblocks as usize);
        let mut extras = extra_txs;
        for i in 0..nblocks {
            let txs = if i == 0 {
                std::mem::take(&mut extras)
            } else {
                Vec::new()
            };
            hashes.push(self.mine_and_accept_paying(script_pubkey.clone(), txs)?);
        }
        if let Err(e) = self.query.apply_sh_pending() {
            rbitcoin_log::warn!("generate: SH write-behind drain: {e}");
        }
        if let Err(e) = rbitcoin_consensus::build_indexes_released(&self.query) {
            rbitcoin_log::warn!("generate: index write-behind drain: {e}");
        }
        Ok(hashes)
    }

    /// Mine one block on this thread, then accept it on `tip-accept`.
    fn mine_and_accept_paying(
        &self,
        script_pubkey: ScriptBuf,
        txs: Vec<Transaction>,
    ) -> Result<BlockHash, NetError> {
        for _attempt in 0..4 {
            let tip_h = self
                .tip_height()
                .ok_or(NetError::Protocol("generate: no tip"))?;
            let prev = self
                .tip_hash()
                .ok_or(NetError::Protocol("generate: no tip hash"))?;
            let tip_time = self.tip_header().map(|h| h.time).unwrap_or(0);
            let time = self.generate_block_time(tip_h, tip_time);
            let block = self.mine_paying_block(
                prev,
                time,
                tip_h.saturating_add(1),
                script_pubkey.clone(),
                txs.clone(),
            )?;
            let hash = block.block_hash();
            let accepted = crate::tip_accept::run_on_tip_accept(|| {
                if self.tip_hash() != Some(prev) {
                    return Ok(false);
                }
                match self.accept_block_inner(std::sync::Arc::new(block))? {
                    AcceptOutcome::Accepted { .. } => Ok(true),
                    other => Err(NetError::Consensus(format!(
                        "generate did not extend tip: {other:?}"
                    ))),
                }
            })?;
            if accepted {
                return Ok(hash);
            }
        }
        Err(NetError::Consensus(
            "generate lost the tip during proof-of-work".into(),
        ))
    }

    /// Disconnect `hash` and descendants from the tip. Remember hashes only;
    /// [`Self::reconsider_block`] reconstructs from Class A. Then apply the
    /// next most-work non-invalid fork (production: invalidate is not "stay
    /// on the stump").
    pub fn invalidate_block(&self, hash: BlockHash) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.invalidate_block_inner(hash))
    }

    fn invalidate_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        let tip = self.tip_height().unwrap_or(0);
        let on_tip = self
            .query
            .height_of_hash(&hash.to_byte_array())
            .map_err(NetError::store)?
            .filter(|h| h.0 <= tip);
        if let Some(h) = on_tip {
            let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
            let mut path = Vec::new();
            for ht in h.0..=tip {
                if let Some(b) = self.block_at_height(ht)? {
                    let bh = b.block_hash();
                    self.invalidated.set.write().unwrap().insert(bh);
                    self.drop_held(bh);
                    path.push(bh);
                }
            }
            if !path.is_empty() {
                self.invalidated.paths.write().unwrap().push(path);
            }
            let keep = h.0.saturating_sub(1);
            self.disconnect_to(keep)?;
            drop(_guard);
        } else if self.knows_header(&hash) || self.held_body(&hash).is_some() {
            // Side-branch / held header (feature_chain_tiebreaks B10): mark
            // invalid without a tip disconnect.
            self.invalidated.set.write().unwrap().insert(hash);
            self.drop_held(hash);
            self.invalidated.paths.write().unwrap().push(vec![hash]);
        } else {
            return Err(NetError::Consensus("Block not found".into()));
        }
        let _ = self.try_apply_after_invalidate()?;
        if let Some(mp) = self.mempool() {
            mp.evict_after_reorg();
        }
        Ok(())
    }

    /// After invalidate, activate the remaining fork (held or archive) with
    /// the most total chain work. Equal work prefers precious, then the
    /// first-seen held tip.
    fn try_apply_after_invalidate(&self) -> Result<Option<AcceptOutcome>, NetError> {
        let inv = self.invalidated.set.read().unwrap().clone();
        let precious = *self.precious.read().unwrap();
        let mut starts: Vec<BlockHash> = self.fork_tips.read().unwrap().iter().copied().collect();
        starts.extend(self.held_bodies.read().unwrap().keys());
        if let Some(p) = precious {
            if !starts.contains(&p) {
                starts.push(p);
            }
        }
        let mut best: Option<(bitcoin::Work, bool, u64, Vec<Block>)> = None;
        for start in starts {
            if inv.contains(&start) {
                continue;
            }
            let Some(branch) = self.assemble_side_branch(start) else {
                continue;
            };
            if branch.iter().any(|b| inv.contains(&b.block_hash())) {
                continue;
            }
            let tip = branch.last().map(|b| b.block_hash()).unwrap_or(start);
            let Ok(w) = self.branch_chain_work(&branch) else {
                continue;
            };
            let is_p = Some(tip) == precious;
            let seq = self.held_bodies.read().unwrap().seq(tip);
            let take = match &best {
                None => true,
                Some((bw, was_p, bseq, _)) => held_branch_beats(w, is_p, seq, *bw, *was_p, *bseq),
            };
            if take {
                best = Some((w, is_p, seq, branch));
            }
        }
        let Some((_, _, _, branch)) = best else {
            return Ok(None);
        };
        match self.accept_branch_inner(&branch) {
            Ok(AcceptOutcome::Accepted { height }) => Ok(Some(AcceptOutcome::Accepted { height })),
            Ok(AcceptOutcome::IgnoredWeaker) => Ok(None),
            Ok(other) => Ok(Some(other)),
            Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Clear the invalid mark on `hash`, its invalidated path, and ancestors;
    /// re-apply bodies from archive. Header-only descendants stay header tips.
    pub fn reconsider_block(&self, hash: BlockHash) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.reconsider_block_inner(hash))
    }

    fn reconsider_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        let known = self.is_connected(&hash)
            || self.load_side_body(&hash).is_some()
            || self.header_tips.read().unwrap().contains(&hash)
            || self
                .query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .is_some()
            || self
                .invalidated
                .paths
                .read()
                .unwrap()
                .iter()
                .any(|p| p.contains(&hash));
        if !known {
            return Err(NetError::Consensus("Block not found".into()));
        }

        let mut related: HashSet<BlockHash> = HashSet::new();
        related.insert(hash);
        let mut walk = hash;
        for _ in 0..10_000 {
            let Some(prev) = self.prev_of(&walk) else {
                break;
            };
            if prev.to_byte_array() == [0u8; 32] {
                break;
            }
            related.insert(prev);
            if self.is_connected(&prev) {
                break;
            }
            walk = prev;
        }

        self.invalidated.set.write().unwrap().remove(&hash);
        let paths = self.take_related_invalidated_paths(hash, &related);
        {
            let mut inv = self.invalidated.set.write().unwrap();
            for path in &paths {
                for h in path {
                    inv.remove(h);
                }
            }
            for h in &related {
                inv.remove(h);
            }
        }

        for path in paths {
            let mut branch = Vec::new();
            for h in &path {
                if self.is_connected(h) {
                    continue;
                }
                let Some(b) = self.load_side_body(h) else {
                    break;
                };
                branch.push(b);
            }
            if !branch.is_empty() {
                match self.accept_branch_inner(&branch) {
                    Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => {}
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
            }
        }
        if !self.is_connected(&hash) {
            if let Some(branch) = self.assemble_side_branch(hash) {
                match self.accept_branch_inner(&branch) {
                    Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => {}
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
            }
        }
        Ok(())
    }

    fn take_related_invalidated_paths(
        &self,
        hash: BlockHash,
        related: &HashSet<BlockHash>,
    ) -> Vec<Vec<BlockHash>> {
        let mut g = self.invalidated.paths.write().unwrap();
        let mut taken = Vec::new();
        let mut seeds = related.clone();
        seeds.insert(hash);
        loop {
            let before = taken.len();
            g.retain(|p| {
                let hit = p.iter().any(|h| seeds.contains(h))
                    || p.first()
                        .is_some_and(|h| self.prev_of(h).is_some_and(|prev| seeds.contains(&prev)));
                if hit {
                    for h in p {
                        seeds.insert(*h);
                    }
                    taken.push(p.clone());
                    false
                } else {
                    true
                }
            });
            if taken.len() == before {
                break;
            }
        }
        taken
    }

    /// Prefer this hash among equal-work competing tips.
    pub fn precious_block(&self, hash: BlockHash) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.precious_block_inner(hash))
    }

    fn precious_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        if self.is_block_invalid(&hash) {
            return Ok(());
        }
        let branch = self.assemble_side_branch(hash);
        if branch.is_none() && !self.is_connected(&hash) {
            return Err(NetError::Consensus("Block not found".into()));
        }
        let prev = *self.precious.read().unwrap();
        *self.precious.write().unwrap() = Some(hash);
        let result = if let Some(branch) = branch {
            match self.accept_branch_inner(&branch) {
                Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => Ok(()),
                other => other.map(|_| ()),
            }
        } else {
            self.try_apply_held(None).map(|_| ())
        };
        if let Err(e) = result {
            *self.precious.write().unwrap() = prev;
            return Err(e);
        }
        Ok(())
    }

    /// Accept a block that extends the tip, or reorg to a stronger competing tip / branch.
    pub fn accept_block(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.accept_incoming(Arc::new(block), false))
    }

    fn accept_block_inner(&self, block: Arc<Block>) -> Result<AcceptOutcome, NetError> {
        self.accept_incoming(block, false)
    }

    fn accept_incoming(
        &self,
        block: Arc<Block>,
        hold_unconnected: bool,
    ) -> Result<AcceptOutcome, NetError> {
        let hash = block.block_hash();
        if self.tip_hash() == Some(hash) || self.has_block(&hash) {
            return Ok(AcceptOutcome::AlreadyHave);
        }
        if self.invalidated.set.read().unwrap().contains(&hash) {
            return Err(NetError::Consensus("block is invalidated".into()));
        }
        if rbitcoin_consensus::block_mutated_without_coinbase(&block) {
            return Err(NetError::Mutated(
                "bad-cb-missing, 64-byte transaction".into(),
            ));
        }

        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Same hash already tip/confirmed (or won a concurrent accept): drop —
        // do not plan Class A or assign create fks a second time (I4).
        if self.tip_hash() == Some(hash) || self.has_block(&hash) {
            return Ok(AcceptOutcome::AlreadyHave);
        }

        let prev = block.header.prev_blockhash;
        match self.tip_height() {
            None => {
                if prev.to_byte_array() != [0u8; 32] {
                    return Err(NetError::Protocol("non-genesis without tip"));
                }
                self.connect_at(0, block)?;
                Ok(AcceptOutcome::Accepted { height: 0 })
            }
            Some(tip_h) => {
                if prev.to_byte_array() == [0u8; 32] {
                    return Err(NetError::Protocol("non-genesis prev is zero"));
                }
                let tip_hash = self
                    .try_tip_hash()?
                    .ok_or(NetError::Protocol("missing tip hash"))?;
                if prev == tip_hash {
                    let height = tip_h.saturating_add(1);
                    self.remember_cmpct_prefill_from_block(block.as_ref());
                    self.connect_at(height, block)?;
                    return Ok(AcceptOutcome::Accepted { height });
                }

                let Some(parent_h) = self
                    .query
                    .height_of_hash(&prev.to_byte_array())
                    .map_err(NetError::store)?
                else {
                    if hold_unconnected {
                        self.hold_body(block);
                    }
                    return Err(NetError::UnknownParent);
                };

                let new_height = parent_h.0.saturating_add(1);
                validate_header(
                    self.query.as_ref(),
                    &self.params,
                    Height(new_height),
                    &block.header,
                )
                .map_err(|e| header_reject(&block.header, &e))?;

                if new_height == tip_h {
                    let out = self.accept_branch_locked(std::slice::from_ref(block.as_ref()))?;
                    if matches!(out, AcceptOutcome::IgnoredWeaker) && hold_unconnected {
                        self.hold_body(block);
                    }
                    return Ok(out);
                }

                if hold_unconnected {
                    self.hold_body(block);
                }
                Err(NetError::SideBlock)
            }
        }
    }

    /// Connect a contiguous branch `[blocks[0]…blocks[n]]` where `blocks[0].prev` is on our chain.
    /// Reorgs if the new path has strictly more work than our path from the fork.
    pub fn accept_branch(&self, blocks: &[Block]) -> Result<AcceptOutcome, NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.accept_branch_inner(blocks))
    }

    fn accept_branch_inner(&self, blocks: &[Block]) -> Result<AcceptOutcome, NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.accept_branch_locked(blocks)
    }

    /// Err when any block of `blocks` fails connect, even when a heavier
    /// valid prefix stays the tip.
    fn accept_branch_locked(&self, blocks: &[Block]) -> Result<AcceptOutcome, NetError> {
        let (out, failed) = self.accept_branch_prefix(blocks)?;
        failed.map_or(Ok(out), Err)
    }

    /// [`Self::accept_branch_locked`] that also reports a kept prefix: when a
    /// block fails after a heavier valid prefix connected, that prefix stays
    /// the tip and the failure is returned beside `Accepted`.
    fn accept_branch_prefix(
        &self,
        blocks: &[Block],
    ) -> Result<(AcceptOutcome, Option<NetError>), NetError> {
        self.accept_branch_precheck(blocks)?;
        if let Some(out) = self.accept_branch_genesis_fill(blocks)? {
            return Ok((out, None));
        }
        let fork_height = self.accept_branch_fork_height(blocks)?;
        let old_work = self.work_from_fork_to_tip(fork_height)?;
        if self.accept_branch_weaker(blocks, old_work)? {
            return Ok((AcceptOutcome::IgnoredWeaker, None));
        }
        self.accept_branch_check_headers(blocks, fork_height)?;
        let old_path = self.accept_branch_collect_old(fork_height)?;
        self.accept_branch_disconnect(fork_height)?;
        let base = fork_height.map(|h| h + 1).unwrap_or(0);
        let (connected, failed) =
            self.accept_branch_connect(blocks, fork_height, old_work, &old_path)?;
        self.announce_reorg_len.store(0, Ordering::Relaxed);
        let height = base + (connected.len() as u32) - 1;
        {
            let mut held = self.held_bodies.write().unwrap();
            for b in connected {
                held.remove(&b.block_hash());
            }
        }
        {
            let mut forks = self.fork_tips.write().unwrap();
            if let Some(old) = old_path.last() {
                forks.insert(old.block_hash());
            }
            for b in connected {
                forks.remove(&b.block_hash());
            }
        }
        Ok((AcceptOutcome::Accepted { height }, failed))
    }

    fn accept_branch_precheck(&self, blocks: &[Block]) -> Result<(), NetError> {
        if blocks.is_empty() {
            return Err(NetError::Protocol("empty branch"));
        }
        if blocks
            .iter()
            .any(|b| self.is_block_invalid(&b.block_hash()))
        {
            return Err(NetError::Consensus("block is invalidated".into()));
        }
        for w in blocks.windows(2) {
            if w[1].header.prev_blockhash != w[0].block_hash() {
                return Err(NetError::Protocol("branch not linked"));
            }
        }
        Ok(())
    }

    fn accept_branch_genesis_fill(
        &self,
        blocks: &[Block],
    ) -> Result<Option<AcceptOutcome>, NetError> {
        if blocks[0].header.prev_blockhash.to_byte_array() != [0u8; 32] {
            return Ok(None);
        }
        if self.tip_height().is_some() {
            return Ok(None);
        }
        for (i, b) in blocks.iter().enumerate() {
            self.connect_at(i as u32, Arc::new(b.clone()))?;
        }
        let h = (blocks.len() - 1) as u32;
        Ok(Some(AcceptOutcome::Accepted { height: h }))
    }

    fn accept_branch_fork_height(&self, blocks: &[Block]) -> Result<Option<u32>, NetError> {
        let fork_prev = blocks[0].header.prev_blockhash;
        if fork_prev.to_byte_array() == [0u8; 32] {
            if self.tip_height().is_some() {
                return Err(NetError::Protocol("non-genesis prev is zero"));
            }
            return Ok(None);
        }
        Ok(Some(
            self.query
                .height_of_hash(&fork_prev.to_byte_array())
                .map_err(NetError::store)?
                .ok_or(NetError::Protocol("branch parent not on chain"))?
                .0,
        ))
    }

    fn branch_header_work(&self, blocks: &[Block]) -> Result<Work, NetError> {
        if self.tip_height().is_some()
            && blocks
                .iter()
                .any(|b| b.header.prev_blockhash.to_byte_array() == [0u8; 32])
        {
            return Err(NetError::Protocol("non-genesis prev is zero"));
        }
        let mut works = Vec::with_capacity(blocks.len());
        for b in blocks {
            works.push(
                crate::most_work::header_work_checked(&b.header)
                    .map_err(|_| NetError::Consensus("zero target".into()))?,
            );
        }
        crate::most_work::sum_work(works.into_iter())
            .map_err(|_| NetError::Consensus("work overflow".into()))
    }

    /// Total chain work of `blocks` connected on their fork point.
    fn branch_chain_work(&self, blocks: &[Block]) -> Result<Work, NetError> {
        let branch = self.branch_header_work(blocks)?;
        let Some(fork_height) = self.accept_branch_fork_height(blocks)? else {
            return Ok(branch);
        };
        self.ensure_chain_work_prefix()?;
        let base = self
            .chain_work_prefix
            .read()
            .unwrap()
            .get(fork_height as usize)
            .copied()
            .ok_or_else(|| {
                NetError::Store(format!(
                    "invariant: no chain work at fork height {fork_height}"
                ))
            })?;
        Ok(base + branch)
    }

    fn accept_branch_weaker(&self, blocks: &[Block], old_work: Work) -> Result<bool, NetError> {
        let new_work = self.branch_header_work(blocks)?;
        let branch_tip = blocks.last().map(Block::block_hash);
        let precious = *self.precious.read().unwrap() == branch_tip;
        let equal_work = !work_better(new_work, old_work) && !work_better(old_work, new_work);
        Ok(self.tip_height().is_some()
            && !work_better(new_work, old_work)
            && !(precious && equal_work))
    }

    fn accept_branch_collect_old(&self, fork_height: Option<u32>) -> Result<Vec<Block>, NetError> {
        let tip_h = self.tip_height().unwrap_or(0);
        let Some(fh) = fork_height.filter(|fh| tip_h > *fh) else {
            return Ok(Vec::new());
        };
        let mut old_path = Vec::with_capacity((tip_h - fh) as usize);
        for h in (fh + 1)..=tip_h {
            let b = self.block_at_height(h)?.ok_or_else(|| {
                NetError::Store(format!("invariant: no body at connected height {h}"))
            })?;
            old_path.push(b);
        }
        Ok(old_path)
    }

    /// Hash and bits for every header before any `disconnect_to`. The first
    /// block's parent is on the best chain. Later parents are this branch.
    fn accept_branch_check_headers(
        &self,
        blocks: &[Block],
        fork_height: Option<u32>,
    ) -> Result<(), NetError> {
        let Some(fork_h) = fork_height else {
            return Ok(());
        };
        let mut batch = HashMap::with_capacity(blocks.len());
        for (i, b) in blocks.iter().enumerate() {
            let height = fork_h.saturating_add(1).saturating_add(i as u32);
            let checked = if i == 0 {
                validate_header(self.query.as_ref(), &self.params, Height(height), &b.header)
                    .map_err(|e| header_reject(&b.header, &e))
            } else {
                let parent = &blocks[i - 1].header;
                let mtp = self.mtp_off_tip(parent, &batch);
                let expected = self.expected_bits_off_tip(
                    &b.header,
                    parent,
                    height.saturating_sub(1),
                    &batch,
                )?;
                validate_header_on_parent(&self.params, Height(height), &b.header, mtp, expected)
                    .map_err(|e| header_reject(&b.header, &e))
            };
            if let Err(e) = checked {
                return Err(connect_failed_for_header(b.block_hash().to_byte_array(), e));
            }
            batch.insert(
                b.block_hash().to_byte_array(),
                HeaderSyncNode {
                    fk: Fk(0),
                    header: b.header,
                    height: Some(height),
                },
            );
        }
        Ok(())
    }

    fn accept_branch_disconnect(&self, fork_height: Option<u32>) -> Result<(), NetError> {
        if let Some(fh) = fork_height {
            self.disconnect_to(fh)?;
        } else {
            while self.query.tip_height().is_some() {
                if let Some(th) = self.tip_hash() {
                    self.confirmed.write().unwrap().remove(&th);
                }
                self.query.disconnect_tip().map_err(NetError::store)?;
            }
            self.cache.clear();
            self.confirmed.write().unwrap().clear();
        }
        Ok(())
    }

    /// Connect `blocks` on the fork point and return the connected prefix,
    /// with the connect failure that stopped it short.
    ///
    /// On a consensus failure the failing block is remembered as invalid and
    /// the most-work valid chain wins, as in Core's `InvalidChainFound`: the
    /// connected prefix stays if it has strictly more work than the old
    /// branch, else the old branch is restored. A local fault always restores.
    /// Each tip event carries the branch length connected so far, because a
    /// later failure can leave that block the tip.
    fn accept_branch_connect<'b>(
        &self,
        blocks: &'b [Block],
        fork_height: Option<u32>,
        old_work: Work,
        old_path: &[Block],
    ) -> Result<(&'b [Block], Option<NetError>), NetError> {
        let base = fork_height.map(|h| h + 1).unwrap_or(0);
        for (i, b) in blocks.iter().enumerate() {
            self.announce_reorg_len
                .store(i as u32 + 1, Ordering::Relaxed);
            let Err(e) = self.connect_at(base + i as u32, Arc::new(b.clone())) else {
                continue;
            };
            self.announce_reorg_len.store(0, Ordering::Relaxed);
            if e.is_local_fault() {
                self.accept_branch_restore(fork_height, old_path, &e)?;
                return Err(e);
            }
            let failed = NetError::ConnectFailed {
                hash: b.block_hash().to_byte_array(),
                msg: e.to_string(),
            };
            let prefix = &blocks[..i];
            if !prefix.is_empty() && work_better(self.branch_header_work(prefix)?, old_work) {
                self.remember_failed_accept(b.block_hash(), &failed);
                return Ok((prefix, Some(failed)));
            }
            self.accept_branch_restore(fork_height, old_path, &e)?;
            return Err(failed);
        }
        Ok((blocks, None))
    }

    /// Put the old branch back after a failed connect. A restore that does
    /// not finish leaves a torn tip: that is a local fault whatever `e` was,
    /// so no caller marks a block invalid or tries another branch on it.
    fn accept_branch_restore(
        &self,
        fork_height: Option<u32>,
        old_path: &[Block],
        e: &NetError,
    ) -> Result<(), NetError> {
        let Some(fh) = fork_height else {
            return Ok(());
        };
        if let Err(disc) = self.disconnect_to(fh) {
            return Err(NetError::Store(format!(
                "reorg connect failed ({e}); disconnect for restore failed: {disc}"
            )));
        }
        for (j, ob) in old_path.iter().enumerate() {
            if let Err(re) = self.connect_at(fh + 1 + j as u32, Arc::new(ob.clone())) {
                return Err(NetError::Store(format!(
                    "reorg connect failed ({e}); tip restore failed: {re}"
                )));
            }
        }
        Ok(())
    }

    /// Disconnect the best chain down to `keep_height` (inclusive). Losing
    /// bodies stay in Class A. Does not connect a replacement — IBD then
    /// confirms the heavier header path as a linear extension.
    pub fn rewind_to_height(&self, keep_height: u32) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.rewind_to_height_inner(keep_height))
    }

    fn rewind_to_height_inner(&self, keep_height: u32) -> Result<(), NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        let tip = self.tip_height().unwrap_or(0);
        if keep_height > tip {
            return Err(NetError::Protocol("rewind above tip"));
        }
        self.disconnect_to(keep_height)
    }

    /// Production "we received a full block" (P2P `block` / compact, RPC
    /// `submitblock`). Runs on the process-wide `tip-accept` thread (lookup →
    /// load → `rbtc-scripts-*` steal → write). Peer sessions should
    /// [`Self::accept_received_block_async`].
    ///
    /// Tip-extend via [`Self::accept_block`]; otherwise hold the body by hash
    /// and [`Self::accept_branch`] when a held (or archived) path has more
    /// work — or is precious at equal work. Not the IBD body-queue pipeline.
    pub fn accept_received_block(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.accept_received_block_inner(block))
    }

    fn accept_received_block_inner(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        let hash = block.block_hash();
        let block = Arc::new(block);
        match self.accept_incoming(block, true) {
            Ok(AcceptOutcome::Accepted { height }) => {
                self.held_bodies.write().unwrap().remove(&hash);
                match self.apply_held_for(hash)? {
                    Some(o @ AcceptOutcome::Accepted { .. }) => Ok(o),
                    _ => Ok(AcceptOutcome::Accepted { height }),
                }
            }
            Ok(AcceptOutcome::AlreadyHave) => {
                self.held_bodies.write().unwrap().remove(&hash);
                Ok(AcceptOutcome::AlreadyHave)
            }
            Ok(AcceptOutcome::IgnoredWeaker)
            | Err(NetError::SideBlock)
            | Err(NetError::UnknownParent) => Ok(self
                .apply_held_for(hash)?
                .unwrap_or(AcceptOutcome::IgnoredWeaker)),
            Err(e) => {
                self.remember_failed_accept(hash, &e);
                Err(e)
            }
        }
    }

    /// [`Self::try_apply_held`] on behalf of `offered`. A held block that
    /// fails connect is that block's verdict, already remembered. It is not
    /// an error for the offered block.
    fn apply_held_for(&self, offered: BlockHash) -> Result<Option<AcceptOutcome>, NetError> {
        match self.try_apply_held(Some(offered)) {
            Err(e)
                if e.failing_block_hash()
                    .is_some_and(|h| h != offered.to_byte_array()) =>
            {
                Ok(None)
            }
            other => other,
        }
    }

    /// Put this hub in an `Arc` and remember a weak handle for async tip jobs.
    pub(crate) fn into_arc(self) -> Arc<Self> {
        let arc = Arc::new(self);
        let _ = arc.self_weak.set(Arc::downgrade(&arc));
        arc
    }

    /// `Some` after [`Self::into_arc`]. The clone keeps the hub alive for a
    /// tip job whose session future was dropped.
    pub(crate) fn shared_arc(&self) -> Option<Arc<Self>> {
        self.self_weak.get().and_then(|w| w.upgrade())
    }

    /// Block until the tip-accept thread has no job running.
    pub fn wait_tip_accept_idle(&self) {
        crate::tip_accept::wait_idle();
    }

    /// Peer-session accept: same work as [`Self::accept_received_block`], awaited
    /// so the tokio worker is not parked across confirm. The job holds this
    /// `Arc`.
    pub async fn accept_received_block_async(
        self: &Arc<Self>,
        block: Block,
    ) -> Result<AcceptOutcome, NetError> {
        let hub = Arc::clone(self);
        crate::tip_accept::run_on_tip_accept_async(move || hub.accept_received_block_inner(block))
            .await
    }

    pub(crate) fn accept_received_on_lane(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        self.accept_received_block_inner(block)
    }

    /// Wait until the current tip-accept job finishes (including BIP152 HB select).
    ///
    /// Default is bounded to that job: a queued follow-on accept may still be
    /// in flight so wallet `getblockcount` cannot stall across a catch-up burst.
    /// `RBITCOIN_RPC_WAIT_TIP_IDLE=1` waits until the lane is empty (Core
    /// functional `sync_blocks`; not a production default).
    pub fn wait_tip_stable_for_rpc(&self) {
        crate::tip_accept::wait_for_rpc();
    }

    fn held_body_height(&self, block: &Block) -> Option<u32> {
        let prev = block.header.prev_blockhash;
        if prev.to_byte_array() == [0u8; 32] {
            return Some(0);
        }
        self.query
            .height_of_hash(&prev.to_byte_array())
            .ok()
            .flatten()
            .map(|h| h.0.saturating_add(1))
            .or_else(|| {
                self.header_tips
                    .read()
                    .unwrap()
                    .get(&prev)
                    .map(|(_, h)| h.saturating_add(1))
            })
    }

    fn trim_held_bodies(&self, tip: u32) {
        let drop: Vec<BlockHash> = {
            let held = self.held_bodies.read().unwrap();
            held.entries()
                .filter_map(|(hash, b)| {
                    let h = self.held_body_height(b)?;
                    (tip.saturating_sub(h) > HeldBodies::STALE_BELOW).then_some(hash)
                })
                .collect()
        };
        if drop.is_empty() {
            return;
        }
        let mut held = self.held_bodies.write().unwrap();
        for h in drop {
            held.remove(&h);
        }
    }

    fn drop_held(&self, hash: BlockHash) {
        self.held_bodies.write().unwrap().remove(&hash);
    }

    /// Park a disconnected body without running [`Self::try_apply_held`].
    pub fn hold_unconnected_body(&self, block: Block) {
        self.hold_body(Arc::new(block));
    }

    fn hold_body(&self, block: Arc<Block>) {
        let hash = block.block_hash();
        if self.is_connected(&hash) {
            return;
        }
        if let Some(h) = self.held_body_height(block.as_ref()) {
            if let Some(tip) = self.tip_height() {
                if tip.saturating_sub(h) > HeldBodies::STALE_BELOW {
                    return;
                }
            }
        }
        let keep = self.asked_blocks.read().unwrap().clone();
        self.held_bodies.write().unwrap().insert(block, &keep);
    }

    /// Never-confirmed side-branch body in RAM. Once-confirmed disconnected
    /// blocks are reconstructed from Class A — they are not held here.
    pub fn held_body(&self, hash: &BlockHash) -> Option<Block> {
        self.held_bodies.read().unwrap().get(hash).cloned()
    }

    pub fn cache_body_count(&self) -> usize {
        self.cache.body_count()
    }

    pub fn held_body_count(&self) -> usize {
        self.held_bodies.read().unwrap().len()
    }

    /// Parents of held bodies that are neither on the best chain nor held
    /// (nor reconstructable from archive). Peer download window uses this.
    pub fn held_missing_parents(&self) -> Vec<BlockHash> {
        let held = self.held_bodies.read().unwrap();
        let mut missing = Vec::new();
        for b in held.blocks() {
            let prev = b.header.prev_blockhash;
            if prev.to_byte_array() == [0u8; 32] {
                continue;
            }
            if self.is_connected(&prev) || held.contains(&prev) {
                continue;
            }
            if self
                .query
                .reconstruct_archived_block(&prev.to_byte_array())
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            if !missing.contains(&prev) {
                missing.push(prev);
            }
        }
        missing
    }

    fn load_side_body(&self, hash: &BlockHash) -> Option<Block> {
        if let Some(b) = self.held_body(hash) {
            return Some(b);
        }
        self.query
            .reconstruct_archived_block(&hash.to_byte_array())
            .ok()
            .flatten()
    }

    /// Walk hold + archive from `tip` back to a best-chain parent.
    fn assemble_side_branch(&self, tip: BlockHash) -> Option<Vec<Block>> {
        if self.is_connected(&tip) {
            return None;
        }
        let mut rev = Vec::new();
        let mut h = tip;
        for _ in 0..10_000 {
            let b = self.load_side_body(&h)?;
            let prev = b.header.prev_blockhash;
            rev.push(b);
            if prev.to_byte_array() == [0u8; 32] {
                rev.reverse();
                return Some(rev);
            }
            if self.is_connected(&prev) {
                rev.reverse();
                return Some(rev);
            }
            h = prev;
        }
        None
    }

    /// The held (or archived) branch with the most total chain work, as in
    /// Core's `CBlockIndexWorkComparator`. Equal work prefers the precious
    /// tip, then the first-seen held tip.
    fn best_held_branch(&self) -> Option<Vec<Block>> {
        let mut starts: Vec<BlockHash> = self.held_bodies.read().unwrap().keys().collect();
        let precious = *self.precious.read().unwrap();
        if let Some(p) = precious {
            if !starts.contains(&p) {
                starts.push(p);
            }
        }
        let mut best: Option<(Work, bool, u64, Vec<Block>)> = None;
        for start in starts {
            if self.is_block_invalid(&start) {
                continue;
            }
            let Some(branch) = self.assemble_side_branch(start) else {
                continue;
            };
            if branch
                .iter()
                .any(|b| self.is_block_invalid(&b.block_hash()))
            {
                continue;
            }
            let Ok(w) = self.branch_chain_work(&branch) else {
                continue;
            };
            let tip = branch[branch.len() - 1].block_hash();
            let is_p = Some(tip) == precious;
            let seq = self.held_bodies.read().unwrap().seq(tip);
            let take = match &best {
                None => true,
                Some((bw, was_p, bseq, _)) => held_branch_beats(w, is_p, seq, *bw, *was_p, *bseq),
            };
            if take {
                best = Some((w, is_p, seq, branch));
            }
        }
        best.map(|(_, _, _, branch)| branch)
    }

    /// Activate the most-work held branch. A branch that fails connect is
    /// remembered as invalid and the next best is tried, so a failed heavier
    /// branch does not hide a valid one. When `offered` is the block that
    /// failed, its error is the result even if a kept prefix or another
    /// branch became the tip. A local fault stops at once.
    fn try_apply_held(
        &self,
        offered: Option<BlockHash>,
    ) -> Result<Option<AcceptOutcome>, NetError> {
        let mut applied = None;
        let mut failed = None;
        let mut offered_failed = None;
        for _ in 0..=self.held_body_count() {
            let Some(branch) = self.best_held_branch() else {
                break;
            };
            let branch_tip = branch[branch.len() - 1].block_hash();
            let attempt = {
                let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
                self.accept_branch_prefix(&branch)
            };
            let e = match attempt {
                Ok((o @ AcceptOutcome::Accepted { .. }, None)) => {
                    applied = Some(o);
                    break;
                }
                Ok((o @ AcceptOutcome::Accepted { .. }, Some(e))) => {
                    applied = Some(o);
                    e
                }
                Ok((AcceptOutcome::IgnoredWeaker, _)) => break,
                Ok((other, _)) => return Ok(Some(other)),
                Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => break,
                Err(e) if e.is_local_fault() => return Err(e),
                Err(e) => {
                    self.remember_failed_accept(branch_tip, &e);
                    e
                }
            };
            if offered.is_some_and(|h| e.failing_block_hash() == Some(h.to_byte_array())) {
                offered_failed.get_or_insert(e);
            } else {
                failed.get_or_insert(e);
            }
        }
        match (offered_failed, applied, failed) {
            (Some(e), _, _) => Err(e),
            (None, Some(o), _) => Ok(Some(o)),
            (None, None, Some(e)) => Err(e),
            (None, None, None) => Ok(None),
        }
    }

    fn strip_txids_from_pres(pres: &[rbitcoin_query::TxPrecompute]) -> Vec<Txid> {
        pres.iter().map(|p| Txid::from_byte_array(p.txid)).collect()
    }

    fn connect_at(&self, height: u32, block: Arc<Block>) -> Result<(), NetError> {
        debug_assert!(
            crate::tip_accept::on_tip_accept_thread(),
            "connect_at must run on tip-accept"
        );
        let hash = block.block_hash();
        let header = block.header;
        tip_accept_stats_reset(&self.query);
        let t_wall = std::time::Instant::now();
        let t_pres = std::time::Instant::now();
        let (pres, preverified) = match self.mempool() {
            Some(mp) => mp.tip_script_pres(&block.txdata),
            None => rbitcoin_query::pres_for_tip(&block.txdata, true, |_| false),
        };
        let pres_ns = t_pres.elapsed().as_nanos() as u64;
        debug_assert_eq!(pres.len(), block.txdata.len());
        let _ = self
            .clock
            .with_frozen(|| loop {
                match accept_and_connect_block_preverified(
                    &self.query,
                    &self.params,
                    Height(height),
                    Arc::clone(&block),
                    self.milestone,
                    &preverified,
                    Some(std::sync::Arc::clone(&pres)),
                ) {
                    Ok(fk) => return Ok(fk),
                    Err(e) if e.is_uring_session_fault() => {
                        self.query.uring_recover_or_abort("tip-connect");
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            })
            .map_err(|e| match e {
                rbitcoin_consensus::ConsensusError::Cancelled => NetError::Cancelled,
                rbitcoin_consensus::ConsensusError::Store(se) => {
                    rbitcoin_log::warn!("tip connect {hash} @ {height}: store fault: {se}");
                    NetError::store(se)
                }
                e => {
                    let reason = rbitcoin_consensus::block_reject_reason(&e);
                    rbitcoin_log::info!(
                        "{}",
                        rbitcoin_consensus::block_reject_log_line(hash, &reason)
                    );
                    if reject_is_mutated(&reason) {
                        NetError::Mutated(reason)
                    } else {
                        NetError::Consensus(reason)
                    }
                }
            })?;
        self.header_tips.write().unwrap().remove(&hash);
        let t_mp = std::time::Instant::now();
        if let Some(mp) = self.mempool() {
            mp.clear_recent_rejects();
            if mp.relay_enabled() {
                mp.note_recent_confirmed(&block.txdata);
            }
            let ids = Self::strip_txids_from_pres(&pres);
            let spent: Vec<_> = block
                .txdata
                .iter()
                .filter(|t| !t.is_coinbase())
                .flat_map(|t| t.input.iter().map(|i| i.previous_output))
                .collect();
            let n = mp.remove_for_block_spent(&ids, &spent);
            if n > 0 {
                rbitcoin_log::debug!("mempool: removed {n} confirmed tx(s) @ height {height}");
            }
            if mp.relay_enabled() {
                mp.note_block_fee_history(Height(height));
            }
        }
        let mp_strip_ns = t_mp.elapsed().as_nanos() as u64;
        let wall_ns = t_wall.elapsed().as_nanos() as u64;
        self.confirmed.write().unwrap().insert(hash);
        let tx_count = block.txdata.len();
        let owned = Arc::try_unwrap(block).unwrap_or_else(|a| (*a).clone());
        let _ = self.cache.push_best(owned);
        // Tip-follow / wire accept: one info line per height. IBD bulk confirm
        // uses note_confirmed_tip without this line; IBD retains periodic status.
        info!("{}", log_update_tip_line(height, &hash, &header, tx_count));
        log_tip_accept_sh(&self.query, height, tx_count, wall_ns, mp_strip_ns, pres_ns);
        let event = TipEvent {
            height,
            hash,
            header,
            reorg_branch_len: self.announce_reorg_len.load(Ordering::Relaxed),
        };
        let _ = self.tip_tx.send(event);
        self.notify.notify_waiters();
        self.query.release_index_writebehind(Height(height));
        self.trim_held_bodies(height);
        Ok(())
    }

    fn disconnect_to(&self, keep_height: u32) -> Result<(), NetError> {
        let mp = self.mempool().cloned();
        let mut disconnected_txs: Vec<Transaction> = Vec::new();
        while let Some(h) = self.query.tip_height() {
            let tip = h.0;
            if tip <= keep_height {
                break;
            }
            if mp.is_some() {
                if let Ok(Some(b)) = self.block_at_height(tip) {
                    for tx in b.txdata.iter().skip(1) {
                        disconnected_txs.push(tx.clone());
                    }
                }
            }
            if let Some(th) = self.tip_hash() {
                self.confirmed.write().unwrap().remove(&th);
            }
            self.query
                .disconnect_tip_keep_pending()
                .map_err(NetError::store)?;
        }
        self.cache.truncate_to_height(keep_height);
        if let Some(mp) = mp {
            mp.clear_recent_confirmed();
            if !disconnected_txs.is_empty() {
                let n = mp.reorg_reaccept(&disconnected_txs);
                if n > 0 {
                    rbitcoin_log::debug!(
                        "mempool: re-accepted {n}/{} tx(s) after reorg disconnect to {keep_height}",
                        disconnected_txs.len()
                    );
                }
            }
            mp.evict_after_reorg();
        }
        self.query
            .drop_sh_pending_from(Height(keep_height.saturating_add(1)));
        self.chain_work_prefix
            .write()
            .unwrap()
            .truncate(keep_height as usize + 1);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_chain_work_prefix_len(&self) -> usize {
        self.chain_work_prefix.read().unwrap().len()
    }

    #[cfg(test)]
    pub(crate) fn reset_block_at_height_calls(&self) {
        self.block_at_height_calls.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn block_at_height_calls(&self) -> u64 {
        self.block_at_height_calls.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn take_header_contextual_checks(&self) -> u64 {
        self.header_contextual_checks.swap(0, Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn take_stored_height_walk_steps(&self) -> u64 {
        self.stored_height_walk_steps.swap(0, Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn set_stored_height_walk_cap(&self, cap: u32) {
        self.stored_height_walk_cap.store(cap, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn test_clear_chain_work_prefix(&self) {
        self.chain_work_prefix.write().unwrap().clear();
    }

    fn block_at_height(&self, height: u32) -> Result<Option<Block>, NetError> {
        #[cfg(test)]
        self.block_at_height_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(h) = self.cache.hash_at_height(height) {
            if let Some(b) = self.cache.get_block(&h) {
                return Ok(Some(b));
            }
        }
        match self.query.reconstruct_block_at_height(Height(height)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.to_string().contains("not found") || e.to_string().contains("NotFound") => {
                Ok(None)
            }
            Err(e) => Err(NetError::store(e)),
        }
    }

    /// Total chain work from genesis through tip (best effort from headers).
    pub fn chain_work(&self) -> Result<Work, NetError> {
        self.work_from_fork_to_tip(None)
    }

    /// Sum wire-header work on the best chain from `fork_height+1` through tip.
    ///
    /// `fork_height = None` means from genesis (height 0) through tip.
    /// Empty tip → zero work.
    fn work_from_fork_to_tip(&self, fork_height: Option<u32>) -> Result<Work, NetError> {
        let Some(tip) = self.tip_height() else {
            return Ok(Work::from_be_bytes([0u8; 32]));
        };
        let start = fork_height.map(|h| h + 1).unwrap_or(0);
        if start > tip {
            return Ok(Work::from_be_bytes([0u8; 32]));
        }
        self.ensure_chain_work_prefix()?;
        let p = self.chain_work_prefix.read().unwrap();
        let end = p
            .get(tip as usize)
            .copied()
            .unwrap_or_else(|| Work::from_be_bytes([0u8; 32]));
        if start == 0 {
            return Ok(end);
        }
        let base = p
            .get((start - 1) as usize)
            .copied()
            .unwrap_or_else(|| Work::from_be_bytes([0u8; 32]));
        Ok(end - base)
    }

    fn ensure_chain_work_prefix(&self) -> Result<(), NetError> {
        let Some(tip) = self.tip_height() else {
            self.chain_work_prefix.write().unwrap().clear();
            return Ok(());
        };
        let want = tip as usize + 1;
        let mut p = self.chain_work_prefix.write().unwrap();
        if p.len() > want {
            p.truncate(want);
            return Ok(());
        }
        if p.is_empty() {
            self.fill_chain_work_from_header_body(&mut p, want)?;
            return Ok(());
        }
        while p.len() < want {
            let h = p.len() as u32;
            let w = self.header_work_at_height(h)?;
            let acc = match p.last() {
                None => w,
                Some(&prev) => prev + w,
            };
            p.push(acc);
        }
        Ok(())
    }

    /// First fill after process start. `nBits` is the whole work input, so
    /// this is one sequential read of `header.body` plus the in-memory
    /// confirmed fk array. Later heights append one record at a time.
    fn fill_chain_work_from_header_body(
        &self,
        p: &mut Vec<Work>,
        want: usize,
    ) -> Result<(), NetError> {
        let bits = self
            .query
            .store()
            .headers
            .bits_in_fk_order()
            .map_err(NetError::store)?;
        let mut built = Vec::with_capacity(want);
        for h in 0..want as u32 {
            let fk = self
                .query
                .store()
                .confirmed
                .get(Height(h))
                .map_err(NetError::store)?
                .ok_or_else(|| NetError::store(rbitcoin_store::StoreError::NotFound))?;
            let id = fk
                .get()
                .ok_or_else(|| NetError::store(rbitcoin_store::StoreError::InvalidFk))?;
            let nbits = bits.get((id - 1) as usize).copied().ok_or_else(|| {
                NetError::store(rbitcoin_store::StoreError::Corrupt("chain work header fk"))
            })?;
            let w = header_work_bits(nbits);
            let acc = match built.last() {
                None => w,
                Some(&prev) => prev + w,
            };
            built.push(acc);
        }
        *p = built;
        Ok(())
    }

    fn header_work_at_height(&self, h: u32) -> Result<Work, NetError> {
        let (_, rec) = self
            .query
            .header_at_height(Height(h))
            .map_err(NetError::store)?
            .ok_or_else(|| NetError::store(rbitcoin_store::StoreError::NotFound))?;
        Ok(header_work_bits(rec.bits))
    }
}

fn header_work_bits(bits: u32) -> Work {
    Target::from_compact(CompactTarget::from_consensus(bits)).to_work()
}

/// [`ChainHub::check_block_proposal`] on explicit inputs, for a caller that
/// holds a [`Query`] but no live hub.
pub fn check_block_proposal_with(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    now: u32,
    block: &Block,
) -> Result<u64, String> {
    let tip_h = query.tip_height().ok_or("no tip")?;
    let (_, tip_rec) = query
        .header_at_height(tip_h)
        .map_err(|e| e.to_string())?
        .ok_or("tip header missing")?;
    if block.header.prev_blockhash.to_byte_array() != tip_rec.hash {
        return Err("inconclusive-not-best-prevblk".into());
    }
    let height = tip_h.0.saturating_add(1);
    let expected =
        rbitcoin_consensus::expected_next_bits(query, params, Height(height), block.header.time)
            .map(|c| c.to_consensus())
            .unwrap_or(tip_rec.bits);
    if block.header.bits.to_consensus() != expected {
        return Err("bad-diffbits".into());
    }
    let mtp = rbitcoin_consensus::median_time_past(query, tip_h).unwrap_or(tip_rec.timestamp);
    // Core is `<=` MTP. Proposal uses `<` so a template stamped at the
    // parent's mediantime+1 still validates after that parent is submitted
    // (new MTP often equals that stamp on an incrementing cache).
    if block.header.time < mtp {
        return Err("time-too-old".into());
    }
    if u64::from(block.header.time) > u64::from(now).saturating_add(2 * 60 * 60) {
        return Err("time-too-new".into());
    }
    let vctx = rbitcoin_consensus::ValidationContext::at(params, Height(height), milestone);
    if let Err(e) = rbitcoin_consensus::validate_block_structure(block, &vctx) {
        return Err(rbitcoin_consensus::block_reject_reason(&e));
    }
    let (fees, prevouts) = proposal_connect(query, block, height, mtp, params.coinbase_maturity())?;
    let subsidy = rbitcoin_consensus::block_subsidy(height, params) as u64;
    let mut coinbase_out = 0u64;
    for o in &block.txdata[0].output {
        coinbase_out = coinbase_out
            .checked_add(o.value.to_sat())
            .ok_or("bad-txns-txouttotal-toolarge")?;
    }
    let allowed = subsidy.checked_add(fees).ok_or("bad-txns-fee-outofrange")?;
    if coinbase_out > allowed {
        return Err("bad-cb-amount".into());
    }
    let flags = rbitcoin_consensus::ScriptVerifyFlags::for_block(
        params,
        height,
        &block.block_hash().to_byte_array(),
        mtp,
    );
    // Structure counts legacy sigops only. Prevouts are already in hand, so
    // P2SH and witness sigops count here (BIP141 limit, 80_000).
    const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
    let mut sigops = rbitcoin_consensus::tx_sigop_cost(
        &block.txdata[0],
        &[],
        flags.bip16_active,
        flags.witness_active,
    );
    for (tx, ins) in block.txdata.iter().skip(1).zip(prevouts) {
        let prev_spks: Vec<&[u8]> = ins.iter().map(|o| o.script_pubkey.as_bytes()).collect();
        sigops = sigops.saturating_add(rbitcoin_consensus::tx_sigop_cost(
            tx,
            &prev_spks,
            flags.bip16_active,
            flags.witness_active,
        ));
        if sigops > MAX_BLOCK_SIGOPS_COST {
            return Err("bad-blk-sigops".into());
        }
        rbitcoin_consensus::verify_tx_scripts_with_flags(ins, tx.clone(), flags)
            .map_err(|e| rbitcoin_consensus::block_reject_reason(&e))?;
    }
    Ok(fees)
}

/// Resolves every spend against the block and the confirmed chain. `Ok` is
/// the fee total and the prevouts already resolved for each non-coinbase tx.
/// Caller has already passed [`rbitcoin_consensus::validate_block_structure`].
///
/// RAM: `created` holds this block's outputs and [`confirmed_parent_outputs`]
/// only the parent outputs this block spends with their parent's fk and
/// height, O(block outputs + block inputs), dropped at return; the returned
/// prevouts are those spent outputs in block order. CPU: each distinct
/// parent's packed body is decoded once. The pre-pass reads the fence once
/// to cache the create height; each confirmed spend reads that fence again,
/// and a missing or moved height is `bad-txns-inputs-missingorspent`.
/// Spentness is still probed per input, never served from that map.
fn proposal_connect(
    query: &Query,
    block: &Block,
    height: u32,
    mtp: u32,
    maturity: u32,
) -> Result<(u64, Vec<Vec<TxOut>>), String> {
    if block.txdata.is_empty() {
        return Err("bad-blk-length".into());
    }
    if !block.txdata[0].is_coinbase() {
        return Err("bad-cb-missing".into());
    }
    let txids: Vec<Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
    let parents = confirmed_parent_outputs(query, block, &txids);
    let cb_txid = txids[0];
    let mut created: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut spent: HashSet<OutPoint> = HashSet::new();
    let mut fees = 0u64;
    let mut prevouts = Vec::with_capacity(block.txdata.len().saturating_sub(1));
    for (i, (tx, &txid)) in block.txdata.iter().zip(&txids).enumerate() {
        if !rbitcoin_consensus::is_final_tx(tx, height, mtp.max(block.header.time)) {
            return Err("bad-txns-nonfinal".into());
        }
        if i == 0 {
            for (vout, o) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    o.clone(),
                );
            }
            continue;
        }
        let mut in_val = 0u64;
        let mut tx_prevouts = Vec::with_capacity(tx.input.len());
        for inp in &tx.input {
            let op = inp.previous_output;
            if !spent.insert(op) {
                return Err("bad-txns-inputs-missingorspent".into());
            }
            // Same-block coinbase outputs are not spendable yet. Counting
            // them would inflate `fees` and hide `bad-cb-amount`.
            if op.txid == cb_txid && created.contains_key(&op) {
                return Err("bad-txns-premature-spend-of-coinbase".into());
            }
            let txout = if let Some(o) = created.get(&op) {
                o.clone()
            } else if let Some((fk, created_h, o)) = chain_txout(query, &parents, &op) {
                if coinbase_spend_is_immature(query, *fk, *created_h, height, maturity)? {
                    return Err("bad-txns-premature-spend-of-coinbase".into());
                }
                o.clone()
            } else {
                return Err("bad-txns-inputs-missingorspent".into());
            };
            in_val = in_val
                .checked_add(txout.value.to_sat())
                .ok_or("bad-txns-inputvalues-outofrange")?;
            tx_prevouts.push(txout);
        }
        let mut out_val = 0u64;
        for o in &tx.output {
            out_val = out_val
                .checked_add(o.value.to_sat())
                .ok_or("bad-txns-txouttotal-toolarge")?;
        }
        if out_val > in_val {
            return Err("bad-txns-in-belowout".into());
        }
        fees = fees
            .checked_add(in_val - out_val)
            .ok_or("bad-txns-fee-outofrange")?;
        prevouts.push(tx_prevouts);
        for (vout, o) in tx.output.iter().enumerate() {
            created.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                o.clone(),
            );
        }
    }
    Ok((fees, prevouts))
}

/// `op`'s unspent confirmed output: a per-input spentness probe, then the
/// pre-decoded entry in `parents`.
fn chain_txout<'a>(
    query: &Query,
    parents: &'a HashMap<OutPoint, (Fk, u32, TxOut)>,
    op: &OutPoint,
) -> Option<&'a (Fk, u32, TxOut)> {
    if query
        .is_outpoint_spent(&op.txid.to_byte_array(), op.vout)
        .ok()?
    {
        return None;
    }
    parents.get(op)
}

/// The confirmed-parent outputs `block` spends: one tip-only fk resolve and
/// one packed body decode per distinct parent
/// ([`Query::connected_tx_outputs`]), keeping only the spent vouts with the
/// parent's fk and create height. A row that exists only in a reorged-out
/// block resolves to nothing, as in Core. Spends of `txids` (created in the
/// block) are left to the connect loop; a parent that does not resolve
/// contributes nothing, so its spends reject in block order.
fn confirmed_parent_outputs(
    query: &Query,
    block: &Block,
    txids: &[Txid],
) -> HashMap<OutPoint, (Fk, u32, TxOut)> {
    let in_block: HashSet<&Txid> = txids.iter().collect();
    let mut vouts_by_parent: HashMap<Txid, Vec<u32>> = HashMap::new();
    for inp in block.txdata.iter().skip(1).flat_map(|tx| &tx.input) {
        let op = inp.previous_output;
        if !in_block.contains(&op.txid) {
            vouts_by_parent.entry(op.txid).or_default().push(op.vout);
        }
    }
    let mut outs = HashMap::new();
    for (txid, vouts) in vouts_by_parent {
        let Some((fk, created_h, all)) = query
            .connected_tx_outputs(&txid.to_byte_array())
            .ok()
            .flatten()
        else {
            continue;
        };
        for vout in vouts {
            if let Some(out) = all.get(vout as usize) {
                let txout = TxOut {
                    value: Amount::from_sat(u64::try_from(out.value).unwrap_or(0)),
                    script_pubkey: ScriptBuf::from_bytes(out.script.clone()),
                };
                outs.insert(OutPoint { txid, vout }, (fk, created_h, txout));
            }
        }
    }
    outs
}

/// Core `CheckTxInputs`: the creating tx is the coinbase at its height and
/// `spend_height` is still inside the maturity window.
///
/// `created_h` is the height the parent memo cached. The fence is read again
/// here: a disconnect after that cache leaves no height, and that spend is
/// `bad-txns-inputs-missingorspent` even when the cached height is already
/// past maturity.
fn coinbase_spend_is_immature(
    query: &Query,
    create_fk: Fk,
    created_h: u32,
    spend_height: u32,
    maturity: u32,
) -> Result<bool, String> {
    match query.store().tx_height_get(create_fk) {
        Ok(Some(h)) if h == created_h => {}
        Ok(_) => return Err("bad-txns-inputs-missingorspent".into()),
        Err(e) => return Err(e.to_string()),
    }
    if spend_height >= created_h.saturating_add(maturity) {
        return Ok(false);
    }
    query
        .is_coinbase_create(create_fk, created_h)
        .map_err(|e| e.to_string())
}

pub fn accept_block_header_nodos_log(hash: impl std::fmt::Display) -> String {
    format!("p2p: header {hash} missing pow proof — not stored")
}

pub fn accept_prev_not_found_log(hash: impl std::fmt::Display) -> String {
    format!("p2p: accept dropped {hash} (prev not found)")
}

pub fn ignoring_low_work_chain_log(height: u32) -> String {
    format!("p2p: ignore low-work headers height={height}")
}

pub fn synchronizing_blockheaders_log(height: u32) -> String {
    format!("p2p: headers sync height={height}")
}

pub fn initial_getheaders_log(locator_height: u32, peer: u64) -> String {
    format!("p2p: initial getheaders height={locator_height} peer={peer}")
}

/// Headers-sync timeout: 15 min + 1 ms per header-interval.
pub fn headers_download_timeout_secs(now: u64, best_header_time: u64) -> u64 {
    let since = now.saturating_sub(best_header_time);
    // ceil(1ms * since / 600s) in seconds == ceil(since / 600_000).
    let variable = since.div_ceil(600_000);
    now.saturating_add(15 * 60).saturating_add(variable)
}

pub fn headers_timeout_disconnect_log(peer: u64) -> String {
    format!("p2p: headers sync timeout, disconnect peer={peer}")
}

pub fn headers_timeout_noban_log(peer: u64) -> String {
    format!("p2p: headers sync timeout, keep peer={peer}")
}

pub fn received_getdata_wtx_log(wtxid: impl std::fmt::Display, peer: u64) -> String {
    format!("p2p: getdata wtx {wtxid} peer={peer}")
}

pub fn received_tx_log() -> &'static str {
    "p2p: received tx"
}

/// Tip-follow / wire accept (`connect_at`). IBD bulk confirm does not emit this.
pub fn log_update_tip_line(
    height: u32,
    hash: &BlockHash,
    header: &Header,
    tx_count: usize,
) -> String {
    let time = header.time;
    let ver = header.version.to_consensus();
    format!("tip: best={hash} height={height} version={ver} tx={tx_count} date={time}")
}

/// Clear confirm + Class C SH meters before a tip-follow accept sample window.
fn tip_accept_stats_reset(query: &Query) {
    let _ = query.confirm_stats().take_window();
}

/// Inputs for pure tip-accept SH line (unit-tested).
#[derive(Clone, Debug)]
pub struct TipAcceptShInput {
    pub height: u32,
    pub tx_count: usize,
    pub wall_ns: u64,
    /// Load assemble wall (confirm CONNECT_NS).
    pub load_ns: u64,
    pub script_ns: u64,
    pub class_a_ns: u64,
    pub class_c_ns: u64,
    pub spend_ns: u64,
    pub strong_ns: u64,
    pub tip_ns: u64,
    /// Lookup stamp (`ConfirmWindow::lookup_total_ns`).
    pub lookup_ns: u64,
    /// Write structural (spentness / maturity / BIP68).
    pub structural_ns: u64,
    /// Residual wait on `tx.head` drain after structural/Class C overlap.
    pub drain_ns: u64,
    /// `remove_for_block_spent` after confirm (not inside confirm_write).
    pub mp_strip_ns: u64,
    /// Tip `TxPrecompute` / mempool intersect before confirm.
    pub pres_ns: u64,
    /// Block filter appender (`rbtc-bf-wb`) since the last take. Off the
    /// accept wall, so not in `other`.
    pub bf_ns: u64,
    /// Heights between the tip and the committed filter watermark.
    pub bf_lag: u32,
    pub sh_lag: u32,
    pub sh: rbitcoin_query::TipShSnap,
}

/// JSON body for DEBUG `tip: accept` (no log prefix). `ts` is unix milliseconds.
/// Fields are the raw counters; a reader derives milliseconds.
pub fn format_tip_accept_sh_line(i: &TipAcceptShInput) -> String {
    let sh = &i.sh;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    serde_json::json!({
        "ts": ts,
        "height": i.height,
        "tx_count": i.tx_count,
        "wall_ns": i.wall_ns,
        "load_ns": i.load_ns,
        "script_ns": i.script_ns,
        "class_a_ns": i.class_a_ns,
        "class_c_ns": i.class_c_ns,
        "spend_ns": i.spend_ns,
        "strong_ns": i.strong_ns,
        "tip_ns": i.tip_ns,
        "lookup_ns": i.lookup_ns,
        "structural_ns": i.structural_ns,
        "drain_ns": i.drain_ns,
        "mp_strip_ns": i.mp_strip_ns,
        "pres_ns": i.pres_ns,
        "bf_ns": i.bf_ns,
        "bf_lag": i.bf_lag,
        "sh_lag": i.sh_lag,
        "sh": {
            "collect_ns": sh.collect_ns,
            "sort_ns": sh.sort_ns,
            "seed_ns": sh.seed_ns,
            "body_ns": sh.body_ns,
            "head_ns": sh.head_ns,
            "sync_ns": sh.sync_ns,
            "pin": sh.pin,
            "cold": sh.cold,
            "creates": sh.creates,
            "unique": sh.unique,
            "written": sh.written
        }
    })
    .to_string()
}

/// Sample meters after tip accept and emit DEBUG `tip: accept {json}`.
fn log_tip_accept_sh(
    query: &Query,
    height: u32,
    tx_count: usize,
    wall_ns: u64,
    mp_strip_ns: u64,
    pres_ns: u64,
) {
    let w = query.confirm_stats().take_window();
    let connect_ns = w.connect_ns;
    let script_ns = w.script_ns;
    let strong_ns = w.strong_ns;
    let tip_ns = w.tip_ns;
    let spend_ns = w.utxo_apply_ns;
    let load_ns = w.load_ns;
    let structural_ns = w.structural_ns;
    let lookup_ns = w.lookup_total_ns;
    let drain_ns = w.write_drain_join_ns;
    let sh = rbitcoin_query::TipShSnap {
        collect_ns: w.sh_collect_ns,
        sort_ns: w.sh_sort_ns,
        seed_ns: w.sh_seed_ns,
        body_ns: w.sh_body_ns,
        head_ns: w.sh_head_ns,
        sync_ns: w.sh_sync_ns,
        pin: w.sh_collect_pin,
        cold: w.sh_collect_cold,
        creates: w.sh_create_n,
        unique: w.sh_unique_n,
        written: w.sh_written_n,
    };
    // class_c = strong + tip only (parallel SH is not Class C table time).
    let class_c_tables_ns = strong_ns.saturating_add(tip_ns);
    let line = format_tip_accept_sh_line(&TipAcceptShInput {
        height,
        tx_count,
        wall_ns,
        load_ns: load_ns.saturating_add(connect_ns),
        script_ns,
        class_a_ns: w.arch_write_total_ns,
        class_c_ns: class_c_tables_ns,
        spend_ns,
        strong_ns,
        tip_ns,
        lookup_ns,
        structural_ns,
        drain_ns,
        mp_strip_ns,
        pres_ns,
        bf_ns: w.blockfilter_ns,
        bf_lag: query.block_filter_lag_heights(),
        sh_lag: query.sh_lag_heights(),
        sh,
    });
    debug!("tip: accept {line}");
}

/// Immediate seed: genesis + tip (and tip-1) so open is O(1) at mainnet scale.
fn seed_confirmed_tip(query: &Query) -> HashSet<BlockHash> {
    let mut set = HashSet::new();
    let Some(tip) = query.tip_height() else {
        return set;
    };
    for h in [0u32, tip.0.saturating_sub(1), tip.0] {
        if let Ok(Some((_, rec))) = query.header_at_height(Height(h)) {
            set.insert(BlockHash::from_byte_array(rec.hash));
        }
    }
    set
}

/// Fill the rest of the confirmed set without blocking P2P start.
fn spawn_confirmed_seed(query: Arc<Query>, confirmed: Arc<RwLock<HashSet<BlockHash>>>) {
    let Some(tip) = query.tip_height() else {
        return;
    };
    if tip.0 <= 2 {
        return;
    }
    let run = move || {
        let t0 = std::time::Instant::now();
        let mut batch = Vec::with_capacity(4096);
        for h in 0..=tip.0 {
            if let Ok(Some((_, rec))) = query.header_at_height(Height(h)) {
                batch.push(BlockHash::from_byte_array(rec.hash));
            }
            if batch.len() >= 4096 || h == tip.0 {
                let mut g = confirmed.write().unwrap();
                for hash in batch.drain(..) {
                    g.insert(hash);
                }
            }
        }
        info!(
            "ibd: confirmed-set seed complete tip={} in {:?}",
            tip.0,
            t0.elapsed()
        );
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(run);
    } else {
        std::thread::Builder::new()
            .name("confirmed-seed".into())
            .spawn(run)
            .ok();
    }
}

use crate::most_work::work_better;

/// Tiny-head regtest [`ChainHub`] for tests. Not an operator API.
#[cfg(test)]
pub(crate) fn tiny_regtest_hub_labeled(
    label: &str,
) -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    (dir, hub)
}

/// The body a merkle-ambiguity attacker sends: one 64-byte non-coinbase tx
/// whose txid is the header's merkle root. With a ground block `[cb, t1]`
/// those 64 bytes are `txid(cb) || txid(t1)` and the header is the real one.
#[cfg(test)]
pub(crate) fn sixty_four_byte_body(prev: BlockHash, time: u32) -> Block {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut};
    let inner_node = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x64; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 4]),
        }],
    };
    assert_eq!(bitcoin::consensus::serialize(&inner_node).len(), 64);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![inner_node],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    assert!(block.check_merkle_root());
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::most_work::sum_work;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };
    use rbitcoin_consensus::{confirm_scripts_phase, ChainParams, Milestone};
    use rbitcoin_mempool::UtxoProvider;

    fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
        super::tiny_regtest_hub_labeled("chain")
    }

    #[test]
    fn into_arc_shares_one_hub() {
        let (_dir, hub) = tmp_hub();
        assert!(hub.shared_arc().is_none());
        let hub = ChainHub::into_arc(hub);
        let again = hub.shared_arc().expect("weak upgrades");
        assert!(std::sync::Arc::ptr_eq(&hub, &again));
    }

    #[test]
    fn wait_tip_accept_idle_blocks_until_the_job_finishes() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (_dir, hub) = tmp_hub();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            crate::tip_accept::run_on_tip_accept(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        started_rx.recv().unwrap();
        let waiter = thread::spawn(move || hub.wait_tip_accept_idle());
        thread::sleep(Duration::from_millis(30));
        assert!(
            !waiter.is_finished(),
            "wait_tip_accept_idle returned while a tip-accept job was running"
        );
        release_tx.send(()).unwrap();
        waiter.join().expect("wait");
        worker.join().expect("job");
    }

    fn attach_mp(dir: &std::path::Path, hub: &ChainHub) -> Arc<crate::tx_relay::MempoolHub> {
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
        mp
    }

    /// A tx spending the coinbase at `height`.
    fn mature_spend_tx(hub: &ChainHub, height: u32) -> Transaction {
        let cb = hub
            .query
            .reconstruct_block_at_height(Height(height))
            .unwrap()
            .txdata[0]
            .compute_txid();
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// One regtest hub with DERSIG at 102 and CLTV at 111, mined forward:
    /// the compact prefill knob, a mock clock behind the tip, the SH index
    /// after generate, the version floors, and which txs a generated or
    /// submitted block prefills.
    #[test]
    fn chain_hub_prefill_and_version() {
        use bitcoin::block::Version;
        use rbitcoin_consensus::mine_regtest_paying;
        use rbitcoin_store::script_hash;

        let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("prefill-version");
        let mut params = ChainParams::regtest();
        params.apply_test_activation_height("dersig", 102).unwrap();
        params.apply_test_activation_height("cltv", 111).unwrap();
        let hub = ChainHub::new(q, params, Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let op_true = || ScriptBuf::from_bytes(vec![0x51]);

        // A prefill plan is kept only with the knob on and only for a tip
        // child, and the knob off neither shows nor overwrites it.
        let tip = hub.tip_hash().expect("genesis");
        let child = BlockHash::from_byte_array([2; 32]);
        hub.remember_cmpct_prefill(child, tip, vec![0, 1]);
        assert!(
            hub.cmpct_prefill_indexes(&child).is_none(),
            "default knob off"
        );
        hub.set_prefill_compact(true);
        hub.remember_cmpct_prefill(child, tip, vec![0, 1]);
        assert_eq!(hub.cmpct_prefill_indexes(&child), Some(vec![0, 1]));
        hub.remember_cmpct_prefill(child, BlockHash::from_byte_array([3; 32]), vec![0, 2]);
        assert_eq!(
            hub.cmpct_prefill_indexes(&child),
            Some(vec![0, 1]),
            "non tip-child must not replace"
        );
        hub.set_prefill_compact(false);
        hub.remember_cmpct_prefill(child, tip, vec![0, 9]);
        assert!(
            hub.cmpct_prefill_indexes(&child).is_none(),
            "knob off hides the plan"
        );
        hub.set_prefill_compact(true);
        assert_eq!(
            hub.cmpct_prefill_indexes(&child),
            Some(vec![0, 1]),
            "off remember must not overwrite"
        );
        hub.set_prefill_compact(false);

        // Two blocks put the tip 10,000 s past the median time. A mock clock
        // between them still mines, stamped from the mock (Core UpdateTime).
        let mid = 1_300_000_000u32;
        let tip_time = mid + 10_000;
        let h1 = mine(tip, mid, 1);
        hub.accept_block(h1.clone()).unwrap();
        hub.accept_block(mine(h1.block_hash(), tip_time, 2))
            .unwrap();
        let mock = i64::from(tip_time) - 3_000;
        assert!(mock as u32 > mid, "mock must sit above MTP");
        hub.clock.set_mock(mock);
        assert_eq!(
            hub.generate_to_script(1, op_true(), vec![]).unwrap().len(),
            1
        );
        let t = hub.tip_header().unwrap().time;
        assert!(
            t >= mock as u32 && t < tip_time,
            "expected mock-based stamp, got {t} tip={tip_time} mock={mock}"
        );
        hub.clock.set_mock(0);

        // Generate drains the SH write-behind, so its coinbase is indexed.
        let sh_script = ScriptBuf::from_bytes(vec![0x52]);
        let sh = script_hash(sh_script.as_bytes());
        hub.generate_to_script(1, sh_script, vec![]).unwrap();
        let hist = hub.query.scripthash_history(&sh).unwrap();
        assert!(
            hist.iter().any(|row| row.height == 4),
            "generate must drain SH so the height-4 coinbase is indexed, got {hist:?}"
        );

        // `feature_dersig.py`: from 102 a version-2 block is `bad-version`.
        hub.generate_to_script(97, op_true(), vec![]).unwrap();
        assert_eq!(hub.tip_height(), Some(101));
        let bad_version = |height: u32, version: i32| {
            let prev = hub.tip_hash().unwrap();
            let time = hub.tip_header().unwrap().time + 1;
            let mut block = mine_regtest_paying(prev, time, height, op_true(), vec![]);
            block.header.version = Version::from_consensus(version);
            rbitcoin_consensus::grind_regtest_pow(&mut block.header);
            let hash = block.block_hash();
            let err = hub
                .accept_block(block)
                .expect_err("bad version")
                .to_string();
            let needle = format!("bad-version(0x{version:08x})");
            assert!(err.contains(&needle), "shipped reject: {err}");
            assert_eq!(
                rbitcoin_consensus::block_reject_log_line(hash, &needle),
                format!("{hash}, {needle}")
            );
        };
        bad_version(102, 2);

        // With the knob on and a mempool attached, a generated block
        // prefills a tx the mempool lacks, not one it already has; a
        // submitted block prefills one the mempool lacks.
        let mp = attach_mp(dir.path(), &hub);
        hub.set_prefill_compact(true);
        let hashes = hub
            .generate_to_script(1, op_true(), vec![mature_spend_tx(&hub, 1)])
            .unwrap();
        assert_eq!(
            hub.cmpct_prefill_indexes(&hashes[0]),
            Some(vec![0, 1]),
            "tx absent from mempool rides the generate announce"
        );
        let live = mature_spend_tx(&hub, 2);
        mp.accept_tx(&live).expect("in mempool");
        let hashes = hub.generate_to_script(1, op_true(), vec![live]).unwrap();
        assert_eq!(
            hub.cmpct_prefill_indexes(&hashes[0]),
            Some(vec![0]),
            "live mempool hit stays coinbase-only after strip"
        );
        let block = mine_regtest_paying(
            hub.tip_hash().unwrap(),
            hub.tip_header().unwrap().time + 600,
            104,
            op_true(),
            vec![mature_spend_tx(&hub, 3)],
        );
        let hash = block.block_hash();
        match hub.accept_received_block(block) {
            Ok(AcceptOutcome::Accepted { .. }) => {}
            other => panic!("submit must connect: {other:?}"),
        }
        assert_eq!(hub.cmpct_prefill_indexes(&hash), Some(vec![0, 1]));

        // `feature_cltv.py`: from 111 a version-3 block is `bad-version`.
        hub.generate_to_script(6, op_true(), vec![]).unwrap();
        assert_eq!(hub.tip_height(), Some(110));
        bad_version(111, 3);

        let _ = std::fs::remove_dir_all(dir);
    }

    fn coinbase(height: u32) -> Transaction {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            rbitcoin_consensus::bip34_height_script(height)
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

    #[test]
    fn strip_txids_from_pres_match_compute_txid() {
        let a = coinbase(1);
        let b = coinbase(2);
        let pres: Vec<_> = [&a, &b]
            .into_iter()
            .map(rbitcoin_query::TxPrecompute::from_tx)
            .collect();
        let got = ChainHub::strip_txids_from_pres(&pres);
        assert_eq!(got, vec![a.compute_txid(), b.compute_txid()]);
    }

    fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
        };
        let mut block = Block {
            header,
            txdata: vec![coinbase(height)],
        };
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

    fn mine_distinct(prev: BlockHash, time: u32, height: u32, avoid: &[BlockHash]) -> Block {
        let mut b = mine(prev, time, height);
        if !avoid.iter().any(|h| *h == b.block_hash()) {
            return b;
        }
        let target = Target::from_compact(b.header.bits);
        for nonce in 0..u32::MAX {
            b.header.nonce = nonce;
            if b.header.validate_pow(target).is_ok() && !avoid.iter().any(|h| *h == b.block_hash())
            {
                return b;
            }
        }
        panic!("no distinct pow sibling");
    }
    fn block_with_wire_len(n: usize) -> Block {
        let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut len = n;
        for _ in 0..6 {
            b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; len]);
            let got = b.total_size();
            if got == n {
                return b;
            }
            if got > n {
                len = len.saturating_sub(got - n);
            } else {
                len = len.saturating_add(n - got);
            }
        }
        panic!("wire len {n} landed on {}", b.total_size());
    }

    #[test]
    fn hold_body_caps_fifo() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut exact = block_with_wire_len(HeldBodies::MAX_BLOCK_SERIALIZED);
        exact.header.nonce = 1;
        let exact_h = exact.block_hash();
        hub.hold_unconnected_body(exact);
        assert!(hub.held_body(&exact_h).is_some());
        let mut over = block_with_wire_len(HeldBodies::MAX_BLOCK_SERIALIZED);
        over.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; 4_000_001]);
        over.header.nonce = 2;
        let over_h = over.block_hash();
        hub.hold_unconnected_body(over);
        assert!(hub.held_body(&over_h).is_none());
        hub.drop_held(exact_h);
        let gen = hub.tip_hash().unwrap();
        let n = HeldBodies::CAP.saturating_add(1);
        let mut hashes = Vec::with_capacity(n);
        let mut avoid = Vec::new();
        for i in 0..n as u32 {
            let b = mine_distinct(gen, 1_300_000_000 + i, 1, &avoid);
            let h = b.block_hash();
            avoid.push(h);
            hashes.push(h);
            hub.hold_unconnected_body(b);
        }
        assert_eq!(hub.held_body_count(), HeldBodies::CAP);
        assert!(
            hub.held_body(&hashes[0]).is_none(),
            "lowest-seq (first held) must be FIFO-evicted at cap"
        );
        assert!(hub.held_body(&hashes[HeldBodies::CAP]).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hold_body_spares_asked_getdata_from_fifo() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let asked = mine_distinct(gen, 1_400_000_000, 1, &[]);
        let asked_h = asked.block_hash();
        hub.note_asked_block(asked_h);
        hub.hold_unconnected_body(asked);
        let mut avoid = vec![asked_h];
        for i in 0..HeldBodies::CAP as u32 {
            let b = mine_distinct(gen, 1_400_000_100 + i, 1, &avoid);
            avoid.push(b.block_hash());
            hub.hold_unconnected_body(b);
        }
        assert!(
            hub.held_body(&asked_h).is_some(),
            "in-flight getdata body must not FIFO-evict at cap"
        );
        assert_eq!(hub.held_body_count(), HeldBodies::CAP);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn held_missing_parents_skips_connected_and_held() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let orphan_prev = BlockHash::from_byte_array([0x09; 32]);
        let b = mine(orphan_prev, 1_300_000_500, 1);
        hub.hold_unconnected_body(b);
        let missing = hub.held_missing_parents();
        assert!(missing.contains(&orphan_prev));
        assert!(!missing.contains(&gen));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn core_log_helpers_match_step21_needles() {
        let h = BlockHash::from_byte_array([0x11; 32]);
        assert_eq!(
            accept_block_header_nodos_log(h),
            format!("p2p: header {h} missing pow proof — not stored")
        );
        assert_eq!(
            accept_prev_not_found_log(h),
            format!("p2p: accept dropped {h} (prev not found)")
        );
        assert_eq!(
            ignoring_low_work_chain_log(14),
            "p2p: ignore low-work headers height=14"
        );
        assert_eq!(
            synchronizing_blockheaders_log(14),
            "p2p: headers sync height=14"
        );
        assert_eq!(
            initial_getheaders_log(0, 0),
            "p2p: initial getheaders height=0 peer=0"
        );
        assert_eq!(
            headers_timeout_disconnect_log(0),
            "p2p: headers sync timeout, disconnect peer=0"
        );
        assert_eq!(
            headers_timeout_noban_log(0),
            "p2p: headers sync timeout, keep peer=0"
        );
        assert_eq!(
            received_getdata_wtx_log("aabbccdd", 3),
            "p2p: getdata wtx aabbccdd peer=3"
        );
        assert_eq!(received_tx_log(), "p2p: received tx");
        // Test formula: now=1_000_000, genesis=0 → variable = ceil(1e6/6e5)=2.
        assert_eq!(
            headers_download_timeout_secs(1_000_000, 0),
            1_000_000 + 900 + 2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generate_to_script_from_tokio_connects_off_worker() {
        let (dir, hub) = tmp_hub();
        let task = tokio::task::spawn_blocking(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            let hashes = hub
                .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
                .expect("generate");
            (hashes, hub.tip_height())
        });
        let (hashes, tip) = task.await.expect("join blocking");
        assert_eq!(hashes.len(), 1);
        assert_eq!(tip, Some(1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_received_block_async_connects_off_worker() {
        let (dir, hub) = tmp_hub();
        let hub = ChainHub::into_arc(hub);
        let task = tokio::spawn(async move {
            {
                let _g = crate::reactor::BlockingRegion::enter();
                hub.ensure_genesis().unwrap();
            }
            let genesis = hub.tip_hash().unwrap();
            let b = mine(genesis, 1_300_000_000, 1);
            let out = hub.accept_received_block_async(b).await.unwrap();
            (out, hub.tip_height())
        });
        let (out, tip) = task.await.expect("join worker task");
        assert_eq!(out, AcceptOutcome::Accepted { height: 1 });
        assert_eq!(tip, Some(1));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn linux_thread_comms() -> Vec<String> {
        let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
            return Vec::new();
        };
        dir.filter_map(|e| {
            let p = e.ok()?.path().join("comm");
            std::fs::read_to_string(p).ok()
        })
        .map(|s| s.trim().to_string())
        .collect()
    }

    /// Two real script jobs in one tip block must publish to `rbtc-scripts-*`
    /// (same steal pool as IBD). Single-item waves still run inline on the
    /// publisher — this pin needs N≥2.
    #[test]
    fn tip_accept_script_jobs_use_steal_pool() {
        let (dir, hub) = tmp_hub();
        hub.generate_to_script(101, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("mature coinbases");
        let cb1 = hub.block_at_height(1).unwrap().unwrap().txdata[0].compute_txid();
        let cb2 = hub.block_at_height(2).unwrap().unwrap().txdata[0].compute_txid();
        let spend = |txid, value| Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        hub.generate_to_script(
            1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend(cb1, 49_9999_0000), spend(cb2, 49_9999_0000)],
        )
        .expect("spend block");
        assert_eq!(hub.tip_height(), Some(102));
        let comms = linux_thread_comms();
        if comms.is_empty() {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        assert!(
            comms.iter().any(|c| c.starts_with("rbtc-scripts-")),
            "tip connect must publish script jobs to steal workers, comms={comms:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_is_stale_respects_configured_max_tip_age() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let tip_time = 1_700_000_000u32;
        hub.accept_block(mine(gen, tip_time, 1)).unwrap();

        hub.set_max_tip_age_secs(3600);
        hub.clock.set_mock(i64::from(tip_time) + 3601);
        assert!(
            hub.tip_is_stale_for_ibd(),
            "tip older than configured max must be stale for IBD"
        );

        hub.clock.set_mock(i64::from(tip_time) + 3600);
        assert!(
            !hub.tip_is_stale_for_ibd(),
            "tip at exactly max age must leave IBD"
        );
        assert!(!hub.in_ibd(), "leaving IBD latches");
        hub.clock.set_mock(i64::from(tip_time) + 3600 * 48);
        assert!(
            hub.tip_is_stale_for_ibd(),
            "stale helper still follows clock"
        );
        assert!(
            !hub.in_ibd(),
            "Core m_cached_finished_ibd stays false after leave"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn feefilter_sat_kvb_is_rounded_max_during_ibd() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        assert!(hub.in_ibd(), "regtest genesis is older than 24h");
        assert_eq!(hub.feefilter_sat_kvb(), IBD_FEEFILTER_SAT_KVB);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ibd_accept_does_not_fill_recent_confirmed_wtxid() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
        assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
        assert!(hub.in_ibd(), "regtest genesis is older than 24h");
        assert!(!mp.relay_enabled());
        let gen = hub.tip_hash().unwrap();
        let old = hub.clock.now_secs() as u32 - 2 * 24 * 3600;
        let block = mine(gen, old, 1);
        let wtxid = block.txdata[0].compute_wtxid();
        hub.accept_block(block).unwrap();
        assert!(hub.in_ibd());
        assert!(
            !mp.try_contains_wtxid(&wtxid),
            "txs confirmed during IBD must not be in the recently-confirmed filter"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn feefilter_sat_kvb_is_min_relay_once_tip_is_fresh() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let now = 1_700_000_000u32;
        hub.clock.set_mock(i64::from(now));
        hub.accept_block(mine(gen, now, 1)).unwrap();
        assert!(!hub.in_ibd());
        assert_eq!(
            hub.feefilter_sat_kvb(),
            rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn feefilter_sat_kvb_tracks_enforced_floor() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let now = 1_700_000_000u32;
        hub.clock.set_mock(i64::from(now));
        hub.accept_block(mine(gen, now, 1)).unwrap();
        assert!(!hub.in_ibd());
        let mp = crate::tx_relay::MempoolHub::open_with_weight(
            dir.path().join("mp"),
            Arc::clone(&hub.query),
            0,
        )
        .unwrap();
        assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
        let min = rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
        // A zero weight cap is within one standard tx of full, so the floor
        // is min relay plus one incremental step.
        assert_eq!(hub.feefilter_sat_kvb(), min + min);
        mp.set_min_relay_sat_kvb(1_000);
        assert_eq!(hub.feefilter_sat_kvb(), 1_100);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_relay_allowed_withholds_month_old_side_block() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let t0 = 1_700_000_000u32;
        hub.clock.set_mock(i64::from(t0));
        let a = mine(gen, t0, 1);
        hub.accept_block(a.clone()).unwrap();
        let a_hash = a.block_hash();
        hub.invalidate_block(a_hash).unwrap();
        let t1 = t0 + STALE_RELAY_AGE_LIMIT_SECS as u32 + 1;
        hub.clock.set_mock(i64::from(t1));
        let c1 = mine(gen, t1, 1);
        hub.accept_block(c1).unwrap();
        assert!(!hub.is_connected(&a_hash));
        assert!(
            !hub.stale_relay_allowed(&a_hash),
            "stale more than a month behind best header must not be served"
        );
        assert!(hub.stale_relay_allowed(&hub.tip_hash().unwrap()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unrequested_header_below_minwork_is_anti_dos() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut min = [0u8; 32];
        min[31] = 0x10;
        hub.set_minimum_chain_work(Some(min));
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        assert!(
            hub.header_below_minwork(&b1.header),
            "genesis+1 must stay below 0x10"
        );
        hub.set_minimum_chain_work(None);
        hub.accept_block(b1.clone()).unwrap();
        let b2 = mine(b1.block_hash(), 1_300_000_100, 2);
        hub.accept_block(b2.clone()).unwrap();
        let fork = mine(gen, 1_300_000_200, 1);
        assert!(
            crate::most_work::work_better(
                hub.chain_work().unwrap(),
                hub.work_with_header(&fork.header)
            ),
            "genesis-fork at height 1 is weaker than tip 2"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disconnect_to_without_mempool_skips_block_at_height() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_040_000, 1);
        hub.accept_block(b1).unwrap();
        assert!(hub.mempool().is_none());
        hub.reset_block_at_height_calls();
        hub.rewind_to_height(0).unwrap();
        assert_eq!(
            hub.block_at_height_calls(),
            0,
            "IBD disconnect must not reconstruct the losing branch"
        );
        assert_eq!(hub.tip_height(), Some(0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disconnect_to_with_mempool_still_harvests() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_040_100, 1);
        hub.accept_block(b1).unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        assert!(hub.attach_mempool(mp).is_ok());
        hub.reset_block_at_height_calls();
        hub.rewind_to_height(0).unwrap();
        assert!(
            hub.block_at_height_calls() >= 1,
            "tip-mode reorg still reconstructs for reorg_reaccept"
        );
        assert_eq!(hub.tip_height(), Some(0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ensure_header_rejects_claimed_hard_bits_without_pow() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let mut bad = mine(gen, 1_300_031_000, 1).header;
        bad.bits = CompactTarget::from_consensus(0x1d00ffff);
        bad.nonce = 0;
        assert!(
            hub.ensure_header(&bad).is_err(),
            "persist must not accept nBits/POW that confirm would reject"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ensure_header_fork_child_rejects_old_time_and_wrong_bits() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        hub.ensure_header(&b1.header).unwrap();
        let before = hub.query.store().header_count();

        let mut old = b1.header;
        old.prev_blockhash = b1.block_hash();
        old.time = b1.header.time;
        old.merkle_root = bitcoin::TxMerkleNode::from_byte_array([1u8; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut old);
        let err = hub.ensure_header(&old).unwrap_err();
        assert!(
            err.to_string().contains("median-time-past"),
            "fork child with time==parent must fail MTP: {err}"
        );
        assert_eq!(hub.query.store().header_count(), before);

        let mut wrong_bits = b1.header;
        wrong_bits.prev_blockhash = b1.block_hash();
        wrong_bits.time = b1.header.time.saturating_add(600);
        wrong_bits.bits = CompactTarget::from_consensus(0x207f_fffe);
        wrong_bits.merkle_root = bitcoin::TxMerkleNode::from_byte_array([2u8; 32]);
        let target = Target::from_compact(wrong_bits.bits);
        for nonce in 0..u32::MAX {
            wrong_bits.nonce = nonce;
            if wrong_bits.validate_pow(target).is_ok() {
                break;
            }
        }
        let err = hub.ensure_header(&wrong_bits).unwrap_err();
        assert!(
            err.to_string().contains("proof of work bits"),
            "fork child with nBits != parent continuation must fail: {err}"
        );
        assert_eq!(hub.query.store().header_count(), before);

        let mut low_ver = b1.header;
        low_ver.prev_blockhash = b1.block_hash();
        low_ver.time = b1.header.time.saturating_add(600);
        low_ver.version = Version::from_consensus(1);
        low_ver.merkle_root = bitcoin::TxMerkleNode::from_byte_array([3u8; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut low_ver);
        let err = hub.ensure_header(&low_ver).unwrap_err();
        assert!(
            err.to_string().contains("bad-version"),
            "fork child below BIP65 nVersion: {err}"
        );
        assert_eq!(hub.query.store().header_count(), before);

        let mut h2 = b1.header;
        h2.prev_blockhash = b1.block_hash();
        h2.time = b1.header.time.saturating_add(600);
        h2.merkle_root = bitcoin::TxMerkleNode::from_byte_array([4u8; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut h2);
        let n = hub
            .ensure_headers_batch(&[b1.header, h2])
            .expect("in-batch parent of a valid fork child")
            .len();
        assert_eq!(n, 2);
        assert!(hub.query.store().header_count() > before);

        let mut far = h2;
        far.prev_blockhash = h2.block_hash();
        far.time = h2.time.saturating_add(1_201);
        far.merkle_root = bitcoin::TxMerkleNode::from_byte_array([5u8; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut far);
        hub.ensure_header(&far)
            .expect("regtest min-diff after 2×spacing must persist pow_limit bits");

        let mut batch_old = h2;
        batch_old.prev_blockhash = h2.block_hash();
        batch_old.time = b1.header.time;
        batch_old.merkle_root = bitcoin::TxMerkleNode::from_byte_array([6u8; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut batch_old);
        let after_far = hub.query.store().header_count();
        let err = hub
            .ensure_headers_batch(&[h2, batch_old])
            .expect_err("batch must fail closed on MTP");
        assert!(
            err.to_string().contains("median-time-past"),
            "in-batch MTP fail: {err}"
        );
        assert_eq!(hub.query.store().header_count(), after_far);

        let empty = HashMap::new();
        assert_eq!(hub.stored_header_height(&b1.block_hash()), Some(1));
        assert!(hub
            .stored_header_height(&BlockHash::from_byte_array([0xab; 32]))
            .is_none());
        let mtp = hub.mtp_off_tip(&b1.header, &empty);
        assert!(mtp <= b1.header.time);
        let child_bits = hub
            .expected_bits_off_tip(&h2, &b1.header, 1, &empty)
            .unwrap();
        assert_eq!(child_bits, b1.header.bits);
        let mut far_bits = h2;
        far_bits.time = b1.header.time.saturating_add(10_000);
        let md = hub.min_diff_off_tip(&far_bits, &b1.header, 1, &empty);
        assert_eq!(md, hub.params.pow_limit.to_compact_lossy());
        let genesis_hdr = hub.header_of(&gen).expect("genesis header");
        assert!(hub.header_along_off_tip(&b1.header, 1, 0, &empty).is_some());
        assert!(hub.header_along_off_tip(&b1.header, 1, 2, &empty).is_none());
        let _ = genesis_hdr;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_follow_accept_logs_update_tip_per_block() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        let h = b1.header;
        let hash = b1.block_hash();
        let line_probe = log_update_tip_line(1, &hash, &h, b1.txdata.len());
        assert_eq!(
            line_probe,
            format!(
                "tip: best={hash} height=1 version={} tx={} date={}",
                h.version.to_consensus(),
                b1.txdata.len(),
                h.time
            )
        );
        assert!(!line_probe.contains("UpdateTip"), "{line_probe}");
        assert!(matches!(
            hub.accept_block(b1).unwrap(),
            AcceptOutcome::Accepted { height: 1 }
        ));
        assert_eq!(hub.tip_height(), Some(1));
        // Second block also accepted (one log per height on real path).
        let b2 = mine(hash, 1_300_000_600, 2);
        assert!(matches!(
            hub.accept_block(b2).unwrap(),
            AcceptOutcome::Accepted { height: 2 }
        ));
        assert_eq!(hub.tip_height(), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_headers_batch_chain_and_missing_parent() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        let b2 = mine(b1.block_hash(), 1_300_000_600, 2);
        let b3 = mine(b2.block_hash(), 1_300_001_200, 3);
        let before = hub.query.store().header_count();
        let fks = hub
            .ensure_headers_batch(&[b1.header, b2.header, b3.header])
            .unwrap();
        assert_eq!(fks.len(), 3);
        assert_eq!(hub.query.store().header_count(), before + 3);
        assert_eq!(
            hub.query
                .get_header_by_hash(&b2.header.block_hash().to_byte_array())
                .unwrap()
                .unwrap()
                .0,
            fks[1]
        );
        let mut orphan = b1.header;
        orphan.prev_blockhash = BlockHash::from_byte_array([0x9e; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut orphan);
        let err = hub.ensure_headers_batch(&[orphan]).unwrap_err();
        assert!(err.to_string().contains("header parent unknown"), "{err}");
        let b4 = mine(b3.block_hash(), 1_300_001_800, 4);
        let mut bad = b4.header;
        bad.prev_blockhash = BlockHash::from_byte_array([0x9e; 32]);
        rbitcoin_consensus::grind_regtest_pow(&mut bad);
        let after_ok = hub.query.store().header_count();
        assert!(hub
            .ensure_headers_batch(&[b4.header, bad])
            .unwrap_err()
            .to_string()
            .contains("header parent unknown"));
        assert_eq!(hub.query.store().header_count(), after_ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_accept_line_is_timestamped_json() {
        let line = format_tip_accept_sh_line(&TipAcceptShInput {
            height: 961_445,
            tx_count: 4,
            wall_ns: 2_500_000_000,
            load_ns: 100_000_000,
            script_ns: 0,
            class_a_ns: 0,
            class_c_ns: 0,
            spend_ns: 0,
            strong_ns: 0,
            tip_ns: 0,
            lookup_ns: 0,
            structural_ns: 0,
            drain_ns: 0,
            mp_strip_ns: 0,
            pres_ns: 0,
            bf_ns: 0,
            bf_lag: 0,
            sh_lag: 0,
            sh: rbitcoin_query::TipShSnap::default(),
        });
        assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
        assert!(line.contains("\"height\":961445"), "{line}");
        assert!(line.contains("\"ts\":"), "{line}");
        assert!(line.contains("\"wall_ns\":2500000000"), "{line}");
    }

    #[test]
    fn ensure_genesis_accept_extend_and_already_have() {
        let (dir, hub) = tmp_hub();
        assert!(hub.tip_height().is_none());
        hub.ensure_genesis().unwrap();
        assert_eq!(hub.tip_height(), Some(0));
        // Second call is a no-op once tip exists.
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        assert!(hub.has_block(&gen));
        assert!(hub.query.is_block_archived(&gen.to_byte_array()).unwrap());

        let b1 = mine(gen, 1_300_000_000, 1);
        assert!(matches!(
            hub.accept_block(b1.clone()).unwrap(),
            AcceptOutcome::Accepted { height: 1 }
        ));
        assert_eq!(hub.tip_height(), Some(1));
        // AlreadyHave on re-accept.
        assert!(matches!(
            hub.accept_block(b1.clone()).unwrap(),
            AcceptOutcome::AlreadyHave
        ));

        // Non-genesis without tip rejected on empty hub.
        let (dir2, empty) = tmp_hub();
        let err = empty.accept_block(b1.clone()).unwrap_err();
        assert!(matches!(err, NetError::Protocol(_)));

        // Chain work is non-zero after tip.
        assert!(hub.chain_work().unwrap().to_be_bytes() != [0u8; 32]);
        assert!(hub.tip_header().is_some());
        let gwork = hub.work_through_height(0).unwrap();
        assert_eq!(gwork, hub.tip_header().unwrap().work());
        let b2 = mine(hub.tip_hash().unwrap(), 1_300_000_100, 2);
        assert!(matches!(
            hub.accept_block(b2.clone()).unwrap(),
            AcceptOutcome::Accepted { height: 2 }
        ));
        let tip_w = hub.chain_work().unwrap();
        assert_eq!(tip_w, hub.work_through_height(2).unwrap());
        assert_eq!(hub.work_through_height(0).unwrap(), gwork);
        assert_eq!(tip_w - gwork, b1.header.work() + b2.header.work());
        hub.test_clear_chain_work_prefix();
        assert_eq!(hub.chain_work().unwrap(), tip_w);
        let extra = mine(b2.block_hash(), 1_300_000_200, 3);
        assert_eq!(
            hub.work_with_header(&extra.header),
            tip_w + extra.header.work()
        );
        assert!(hub.mempool().is_none());
        let _ = hub.subscribe_tips();

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    /// A failed rebuild must not leave a prefix the next call will extend.
    #[test]
    fn chain_work_error_leaves_prefix_empty() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let b1 = mine(hub.tip_hash().unwrap(), 1_300_000_000, 1);
        hub.accept_block(b1).unwrap();
        hub.test_clear_chain_work_prefix();
        hub.query
            .store()
            .confirmed
            .set(rbitcoin_primitives::Height(1), Fk(9_000))
            .unwrap();
        assert!(hub.chain_work().is_err());
        assert_eq!(
            hub.test_chain_work_prefix_len(),
            0,
            "a failed chain-work fill does not keep the heights already summed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Shifted `nBits` must not still sum, so the three headers use different targets.
    #[test]
    fn chain_work_sums_distinct_header_bits() {
        use rbitcoin_query::testutil::FixtureChain;
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, hub) = tmp_hub();
        let targets = [0x207f_ffffu32, 0x1e0f_ffff, 0x1d00_ffff];
        let works: Vec<_> = targets.iter().copied().map(header_work_bits).collect();
        assert_ne!(works[0], works[1]);
        assert_ne!(works[1], works[2]);
        let mut prev_fk = Fk::NULL;
        let mut parent = [0u8; 32];
        let mut sum = Work::from_be_bytes([0u8; 32]);
        for (h, &bits) in targets.iter().enumerate() {
            sum = sum + works[h];
            let label = h as u32;
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&label.to_le_bytes());
            let hash = if h == 0 {
                merkle
            } else {
                rbitcoin_store::block_header_hash(1, &parent, &merkle, label + 1, bits, label)
            };
            let rec = HeaderRecord {
                prev_fk,
                version: 1,
                timestamp: label + 1,
                bits,
                nonce: label,
                merkle_root: merkle,
                hash,
                ..HeaderRecord::default()
            };
            let mut txid = [0u8; 32];
            txid[31] = label as u8;
            prev_fk = hub
                .query
                .connect_block(
                    Height(label),
                    &rec,
                    &[TxApply {
                        tx: TxRecord {
                            txid,
                            version: 1,
                            locktime: 0,
                            input_start_fk: Fk::NULL,
                            input_count: 1,
                            output_start_fk: Fk::NULL,
                            output_count: 1,
                        },
                        inputs: vec![InputRecord::coinbase(u32::MAX, vec![label as u8], vec![])],
                        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
                    }],
                )
                .unwrap();
            parent = hash;
        }
        hub.test_clear_chain_work_prefix();
        assert_eq!(hub.chain_work().unwrap(), sum);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Multi-peer concurrent accept of the same tip block: exactly one Accepted,
    /// rest AlreadyHave; single tip height; no orphan Class C outside tip body.
    #[test]
    fn concurrent_same_block_accept_no_orphan_class_c() {
        use std::sync::Arc;
        let (dir, hub) = tmp_hub();
        let hub = Arc::new(hub);
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        let n = 8usize;
        let mut handles = Vec::new();
        for _ in 0..n {
            let h = Arc::clone(&hub);
            let b = b1.clone();
            handles.push(std::thread::spawn(move || h.accept_block(b)));
        }
        let mut accepted = 0u32;
        let mut already = 0u32;
        for h in handles {
            match h.join().unwrap().unwrap() {
                AcceptOutcome::Accepted { height: 1 } => accepted += 1,
                AcceptOutcome::AlreadyHave => already += 1,
                other => panic!("unexpected outcome {other:?}"),
            }
        }
        assert_eq!(accepted, 1, "exactly one Accepted");
        assert_eq!(already, (n as u32) - 1);
        assert_eq!(hub.tip_height(), Some(1));
        // Tip body membership: every strong+height tx at tip is in header_txs.
        let tip_fks = hub
            .query
            .block_tx_fks(rbitcoin_primitives::Height(1))
            .unwrap();
        let tip_set: std::collections::HashSet<u64> =
            tip_fks.iter().filter_map(|f| f.get()).collect();
        for &fk in &tip_fks {
            let id = fk.get().unwrap();
            assert!(
                tip_set.contains(&id),
                "orphan Class C fk={id} at tip height not in header_txs"
            );
            assert!(hub.query.store().is_confirmed_strong(fk).unwrap());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Load batch N+1 must succeed while N is only loaded (not committed).
    /// Regression: hub used store tip+1 only → Ok(None) "empty outcome" thrash.
    #[test]
    fn wire_prep_ahead_of_store_tip_with_pipeline() {
        use rbitcoin_consensus::WireLoadPipeline;

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        hub.query.enter_direct_index_mode().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_200, 1);
        let b2 = mine(b1.block_hash(), 1_300_000_800, 2);
        let h1 = b1.block_hash();
        let h2 = b2.block_hash();

        // Batch 1 at store tip+1 (path_lo=1).
        let batch1 = [(rbitcoin_primitives::Height(1), b1.clone())];
        let mut inflight = rbitcoin_query::InFlight::new();
        let mut next_tx_start = hub.query.tx_body_count().saturating_add(1).max(1);
        let mat1 = {
            let pipe = WireLoadPipeline {
                path_lo: 1,
                parent_hash: None,
                next_tx_start,
                in_flight: &inflight,
                skeleton: None,
                carried_need: Vec::new(),
                carried_header_fks: Vec::new(),
                carried_header_hashes: Vec::new(),
            };
            hub.confirm_wire_load_phase_pipelined(&batch1, Some(&pipe))
                .expect("prep1")
                .expect("prep1 some")
        };
        assert_eq!(mat1.batch.len(), 1);
        assert!(mat1.batch.archive_plan.is_some());
        assert_eq!(
            hub.tip_height(),
            Some(0),
            "tip must not advance on load alone"
        );

        // Update pipeline caches from plan (load-thread note_lookup_ok).
        let plan = mat1.batch.archive_plan.as_ref().unwrap();
        if plan.batch_pin.len() == plan.planned_fks.len() {
            inflight.note_pins(
                plan.planned_fks
                    .iter()
                    .zip(plan.batch_pin.iter())
                    .map(|(fk, pin)| (*fk, pin)),
                None,
            );
        } else {
            inflight.note_pins(
                plan.packed
                    .iter()
                    .zip(plan.planned_fks.iter())
                    .map(|((pin, _), fk)| (*fk, pin)),
                None,
            );
        }
        if let Some(last) = plan.planned_fks.last().and_then(|f| f.get()) {
            next_tx_start = last.saturating_add(1).max(1);
        }

        // Batch 2 while tip still 0 — must NOT Ok(None).
        let batch2 = [(rbitcoin_primitives::Height(2), b2.clone())];
        let mat2 = {
            let pipe = WireLoadPipeline {
                path_lo: 2,
                parent_hash: Some(h1.to_byte_array()),
                next_tx_start,
                in_flight: &inflight,
                skeleton: None,
                carried_need: Vec::new(),
                carried_header_fks: Vec::new(),
                carried_header_hashes: Vec::new(),
            };
            hub.confirm_wire_load_phase_pipelined(&batch2, Some(&pipe))
                .expect("prep2 err")
                .expect("prep2 must Some — pipeline path_lo=2 with tip=0")
        };
        assert_eq!(mat2.batch.len(), 1);
        assert!(mat2.batch.archive_plan.is_some());
        // Reserved fks for batch2 start after batch1's plan.
        let p1_last = plan.planned_fks.last().unwrap().get().unwrap();
        let p2_first = mat2
            .batch
            .archive_plan
            .as_ref()
            .unwrap()
            .planned_fks
            .first()
            .unwrap()
            .get()
            .unwrap();
        assert!(
            p2_first > p1_last,
            "batch2 fks must not collide with batch1 reserved fks ({p2_first} <= {p1_last})"
        );
        assert_eq!(hub.tip_height(), Some(0));
        let _ = (h2,);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn archive_then_confirm_run_and_empty_paths() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_100, 1);
        let h1 = b1.block_hash();

        // Header then accept (confirm is sole Class A).
        hub.ensure_header(&b1.header).unwrap();
        hub.ensure_header_fk(&b1.header).unwrap();
        assert!(hub.confirm_wire_load_phase(&[]).unwrap().is_none());
        let acc = hub.accept_block(b1.clone()).unwrap();
        assert!(matches!(acc, AcceptOutcome::Accepted { height: 1 }));
        assert!(hub.has_block(&h1));
        assert_eq!(hub.tip_height(), Some(1));
        // Already confirmed → AlreadyHave.
        assert!(matches!(
            hub.accept_block(b1.clone()).unwrap(),
            AcceptOutcome::AlreadyHave
        ));
        // Wire load on already-confirmed → None.
        assert!(hub
            .confirm_wire_load_phase(&[(Height(1), b1.clone())])
            .unwrap()
            .is_none());

        // Unknown parent.
        let orphan = mine(BlockHash::from_byte_array([9u8; 32]), 1_300_000_200, 99);
        assert!(matches!(
            hub.accept_block(orphan).unwrap_err(),
            NetError::UnknownParent
        ));

        // accept_branch empty / unlinked.
        assert!(hub.accept_branch(&[]).is_err());
        let b2 = mine(h1, 1_300_000_300, 2);
        let b3_bad = mine(BlockHash::from_byte_array([1u8; 32]), 1_300_000_400, 3);
        assert!(hub.accept_branch(&[b2.clone(), b3_bad]).is_err());
        // Linked tip extension via branch.
        assert!(matches!(
            hub.accept_branch(std::slice::from_ref(&b2)).unwrap(),
            AcceptOutcome::Accepted { height: 2 }
        ));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn accept_unknown_parent_errors() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let orphan = mine(BlockHash::from_byte_array([9u8; 32]), 1_300_000_500, 99);
        assert!(matches!(
            hub.accept_block(orphan).unwrap_err(),
            NetError::UnknownParent
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn submit_header_child_is_headers_only_tip() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_020_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        let child = mine(b1.block_hash(), 1_300_020_100, 2);
        hub.ensure_header(&child.header).unwrap();
        let tips = hub.chaintips();
        let ho = tips
            .iter()
            .find(|t| t.status == "headers-only")
            .expect("headers-only child");
        assert_eq!(ho.hash, child.block_hash());
        assert_eq!(ho.height, 2);
        assert_eq!(ho.branchlen, 1);
        assert_eq!(hub.best_header_height(), 2);
        assert_eq!(hub.tip_height(), Some(1));
        let shorter = mine(gen, 1_300_020_200, 9);
        hub.ensure_header(&shorter.header).unwrap();
        assert_eq!(
            hub.best_header_height(),
            2,
            "a shorter valid header cannot lower the best header height"
        );
        hub.invalidate_block(child.block_hash()).unwrap();
        assert_eq!(
            hub.best_header_height(),
            1,
            "an invalidated taller header does not count"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `best_header_height` and `chaintips` walk ancestry through `prev_of`,
    /// which read-locks `header_tips` and (via `load_side_body`)
    /// `held_bodies`. std's `RwLock` refuses a new reader while a writer
    /// waits, so a walk that holds one of those guards deadlocks against a
    /// writer: the writer waits for the held read, and the walk's second read
    /// waits for the writer.
    #[test]
    fn ancestry_walks_never_reread_a_held_chain_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::thread;
        use std::time::{Duration, Instant};

        let (_dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_030_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        // A header-only tip (`header_tips`) and a parked side body (`held_bodies`).
        let child = mine(b1.block_hash(), 1_300_030_100, 2);
        hub.ensure_header(&child.header).unwrap();
        let side = mine(gen, 1_300_030_200, 1);
        hub.hold_unconnected_body(side.clone());
        assert!(hub.held_body(&side.block_hash()).is_some());
        let tip = child.block_hash();

        let hub = ChainHub::into_arc(hub);
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (hub, stop) = (hub.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    drop(hub.header_tips.write().unwrap());
                    drop(hub.held_bodies.write().unwrap());
                }
            })
        };
        let (done_tx, done_rx) = mpsc::channel();
        {
            let hub = hub.clone();
            thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(2);
                while Instant::now() < until {
                    assert_eq!(hub.best_header_height(), 2);
                    assert!(hub.chaintips().iter().any(|t| t.hash == tip));
                }
                let _ = done_tx.send(());
            });
        }
        let outcome = done_rx.recv_timeout(Duration::from_secs(20));
        stop.store(true, Ordering::Relaxed);
        match outcome {
            Ok(()) => writer.join().unwrap(),
            Err(RecvTimeoutError::Timeout) => {
                panic!("an ancestry walk deadlocked against a chain-lock writer")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the walk thread panicked"),
        }
    }

    #[test]
    fn accept_competing_tip_and_block_at_height_paths() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_001_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(1));
        assert_eq!(
            hub.tip_header().expect("tip header").work(),
            b1.header.work(),
            "equal-height compare uses header work, not a body reconstruct"
        );

        // Competing tip at same height with more work reorgs (or IgnoredWeaker if equal).
        // Mine many nonces for a sibling of b1 with higher work is hard on regtest
        // equal-bits; exercise IgnoredWeaker via accept of a different equal-work sibling.
        let mut sibling = mine(gen, 1_300_001_001, 1);
        // Ensure different hash than b1.
        if sibling.block_hash() == b1.block_hash() {
            sibling.header.nonce = sibling.header.nonce.wrapping_add(1);
            // re-mine pow
            let target = Target::from_compact(sibling.header.bits);
            for nonce in sibling.header.nonce..u32::MAX {
                sibling.header.nonce = nonce;
                if sibling.header.validate_pow(target).is_ok()
                    && sibling.block_hash() != b1.block_hash()
                {
                    break;
                }
            }
        }
        let out = hub.accept_block(sibling).unwrap();
        assert!(matches!(
            out,
            AcceptOutcome::IgnoredWeaker | AcceptOutcome::Accepted { .. }
        ));

        // block_at_height via reconstruct after tip extend.
        let b2 = mine(hub.tip_hash().unwrap(), 1_300_001_100, 2);
        hub.accept_block(b2.clone()).unwrap();
        let got = hub.block_at_height(2).unwrap().unwrap();
        assert_eq!(got.block_hash(), b2.block_hash());
        // Far height → None.
        assert!(hub.block_at_height(9_999).unwrap().is_none());

        // attach_mempool + accept_block removes confirmed txs (empty mempool).
        let mp_dir = dir.join("mp");
        let mp = crate::tx_relay::MempoolHub::open(&mp_dir, Arc::clone(&hub.query)).unwrap();
        assert!(hub.attach_mempool(mp).is_ok());
        assert!(hub.mempool().is_some());
        let tip = hub.tip_hash().unwrap();
        let tip_h = hub.tip_height().unwrap();
        let b_next = mine(tip, 1_300_001_200, tip_h + 1);
        hub.accept_block(b_next).unwrap();

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_at_releases_sh_after_tip_event() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let genesis = hub
            .block_at_height(0)
            .unwrap()
            .expect("genesis after ensure");
        rbitcoin_consensus::pad_empty_from(
            hub.query.as_ref(),
            &hub.params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            2,
            0,
        );
        assert_eq!(hub.query.sh_indexed_through_height(), Some(2));
        let mut tip_rx = hub.subscribe_tips();
        let block = hub
            .assemble_block_to_script(ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("assemble");
        match hub.accept_block(block).expect("connect") {
            AcceptOutcome::Accepted { height } => assert_eq!(height, 3),
            other => panic!("expected Accepted, got {other:?}"),
        }
        let ev = tip_rx.try_recv().expect("tip event after accept");
        assert_eq!(ev.height, 3);
        assert_eq!(hub.query.index_released_through_height(), Some(3));
        assert_eq!(
            hub.query.sh_indexed_through_height(),
            Some(2),
            "release must not seed; worker/apply does that"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn note_confirmed_tip_sends_the_wire_header() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let block = hub
            .assemble_block_to_script(ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("assemble");
        let wire = block.header;
        let hash = block.block_hash();
        match hub.accept_block(block).expect("connect") {
            AcceptOutcome::Accepted { height } => assert_eq!(height, 1),
            other => panic!("expected Accepted, got {other:?}"),
        }
        let stored = hub
            .query
            .wire_header_at_height(Height(1))
            .expect("stored header");
        assert_eq!(stored.nonce, wire.nonce);
        let mut claimed = wire;
        claimed.nonce = wire.nonce.wrapping_add(1);
        let mut tip_rx = hub.subscribe_tips();
        hub.note_confirmed_tip(&[(1, hash)], &[claimed])
            .expect("note");
        let ev = tip_rx.try_recv().expect("tip event");
        assert_eq!(ev.header, claimed);
        assert_eq!(
            hub.query
                .wire_header_at_height(Height(1))
                .expect("store")
                .nonce,
            stored.nonce
        );
        let err = hub
            .note_confirmed_tip(&[(1, hash)], &[])
            .expect_err("header count");
        assert!(
            err.to_string().contains("invariant: wire headers length"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn exclusive_sh_handoff_mempool_to_pending() {
        use rbitcoin_store::script_hash;

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let genesis = hub
            .block_at_height(0)
            .unwrap()
            .expect("genesis after ensure");
        let (_tip, _time, cbs) = rbitcoin_consensus::pad_empty_from(
            hub.query.as_ref(),
            &hub.params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            100,
            1,
        );
        assert_eq!(hub.tip_height(), Some(100));
        let through = hub.query.sh_indexed_through_height();
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let sh = script_hash(spk.as_bytes());
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());

        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cbs[0],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: spk.clone(),
            }],
        };
        let spend_id = spend.compute_txid().to_byte_array();
        mp.accept_tx(&spend).expect("accept spend");
        let in_mp = |mp: &crate::tx_relay::MempoolHub| {
            mp.scripthash_mempool(&sh)
                .iter()
                .any(|r| r.txid == spend_id)
        };
        let in_hist = || {
            hub.query
                .scripthash_history(&sh)
                .unwrap()
                .iter()
                .any(|r| r.txid == spend_id)
        };
        assert!(in_mp(&mp), "pre-connect: tx must be in mempool overlay");
        assert!(!in_hist(), "pre-connect: tx must not be confirmed history");

        let cold0 = hub
            .query
            .confirm_stats()
            .sh_collect_cold
            .load(std::sync::atomic::Ordering::Relaxed);
        let block = hub
            .assemble_block_to_script(spk, vec![spend])
            .expect("assemble");
        match hub.accept_block(block).expect("connect spend block") {
            AcceptOutcome::Accepted { height } => assert_eq!(height, 101),
            other => panic!("expected Accepted, got {other:?}"),
        }
        let cold1 = hub
            .query
            .confirm_stats()
            .sh_collect_cold
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            cold1, cold0,
            "mempool-origin creates must collect from pins, not cold Class A"
        );
        assert_eq!(
            hub.query.sh_indexed_through_height(),
            through,
            "accept must not drain durable SH"
        );
        assert!(
            !in_mp(&mp),
            "post-connect: mempool overlay must not keep the confirmed tx"
        );
        assert!(
            in_hist(),
            "post-connect: pending SH must show the confirmed tx before durable apply"
        );
        let hist_hits = hub
            .query
            .scripthash_history(&sh)
            .unwrap()
            .iter()
            .filter(|r| r.txid == spend_id)
            .count();
        let mp_hits = mp
            .scripthash_mempool(&sh)
            .iter()
            .filter(|r| r.txid == spend_id)
            .count();
        assert_eq!(
            hist_hits + mp_hits,
            1,
            "tx must not vanish or duplicate across overlay and history"
        );

        let h101 = hub.tip_hash().expect("spend block");
        hub.invalidate_block(h101).expect("reorg spend block");
        assert_eq!(hub.tip_height(), Some(100));
        assert!(
            in_mp(&mp),
            "reorg must restore mempool overlay before dropping RAM SH head"
        );
        assert!(
            !in_hist(),
            "disconnected spend must not remain confirmed history"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// `mempool_reorg.py`: invalidate below coinbase maturity must empty the spend.
    #[test]
    fn invalidate_evicts_immature_coinbase_spend() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let hashes = hub
            .generate_to_script(103, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad to mature coinbase");
        assert_eq!(hashes.len(), 103);
        assert_eq!(hub.tip_height(), Some(103));
        let b1 = hub.block_at_height(1).unwrap().expect("height 1");
        let cb = b1.txdata[0].compute_txid();

        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp.clone()).is_ok());

        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        mp.accept_tx(&spend).expect("mature coinbase spend");
        let child = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: spend.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9998_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        mp.accept_tx(&child).expect("child of coinbase spend");
        assert_eq!(mp.live_count(), 2);

        // QueryUtxoProvider must see a coinbase at height 1 (same path evict uses).
        let coin = crate::tx_relay::QueryUtxoProvider::new(hub.query.as_ref())
            .get_coin(&OutPoint { txid: cb, vout: 0 })
            .expect("coinbase still a chain coin");
        assert!(coin.is_coinbase, "shipped get_coin must mark coinbase");
        assert_eq!(coin.create_height, 1);

        let h10 = hub.block_at_height(10).unwrap().expect("height 10");
        hub.invalidate_block(h10.block_hash())
            .expect("invalidate height 10");
        assert_eq!(hub.tip_height(), Some(9));
        assert_eq!(
            mp.live_count(),
            0,
            "invalidate below maturity must evict the coinbase spend and its child"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn work_better_and_sum_work_helpers() {
        let z = Work::from_be_bytes([0u8; 32]);
        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            Work::from_be_bytes(b)
        };
        assert!(work_better(one, z));
        assert!(!work_better(z, one));
        assert_eq!(sum_work(std::iter::empty()).unwrap(), z);
        assert_eq!(sum_work([one].into_iter()).unwrap(), one);
    }

    #[test]
    fn confirm_wire_script_split() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_004_000, 1);
        let cb_txid = b1.txdata[0].compute_txid();
        let cb_wtxid = b1.txdata[0].compute_wtxid();
        let loaded = hub.confirm_wire_load_phase(&[(Height(1), b1)]).unwrap();
        assert!(loaded.is_some());
        let batch = loaded.unwrap();
        let script_out = confirm_scripts_phase(batch.batch).unwrap();
        let mp = attach_mp(dir.path(), &hub);
        let write_out = hub.confirm_write(script_out.batch).unwrap();
        assert_eq!(write_out.len(), 1);
        assert!(matches!(
            write_out[0],
            AcceptOutcome::Accepted { height: 1 }
        ));
        assert_eq!(hub.tip_height(), Some(1));
        assert!(
            mp.try_contains_wtxid(&cb_wtxid),
            "IBD confirm_write must fill recent-confirmed wtxid"
        );
        assert!(mp.try_contains(&cb_txid));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Mine a coinbase-only block with optional extra txs (for invalid mid-branch).
    fn mine_with_extra(prev: BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
        };
        let mut txdata = vec![coinbase(height)];
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

    /// Journey: deep most-work reorg (≥16), weaker ignored, mid-branch invalid
    /// restores pre-attempt tip (shipped `accept_branch`).
    #[test]
    fn most_work_reorg_depth16_and_invalid_mid_branch_restores_tip() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let mut tip = gen;
        let time = 1_400_000_000u32;
        // Best chain height 0..=8. Fork at height 2: main continues to 8.
        for h in 1..=8u32 {
            let b = mine(tip, time + h * 600, h);
            tip = b.block_hash();
            hub.accept_block(b).unwrap();
        }
        assert_eq!(hub.tip_height(), Some(8));
        let main_tip = hub.tip_hash().unwrap();

        // Fork parent at height 2.
        let fork_parent = hub
            .query
            .header_at_height(Height(2))
            .unwrap()
            .unwrap()
            .1
            .hash;
        let fork_prev = BlockHash::from_byte_array(fork_parent);
        let fork_time = hub
            .query
            .header_at_height(Height(2))
            .unwrap()
            .unwrap()
            .1
            .timestamp;

        // Competing branch depth 16 from height 3..=18 (16 blocks) → more work.
        let mut branch = Vec::new();
        let mut p = fork_prev;
        let mut t = fork_time;
        for (i, h) in (3..=18u32).enumerate() {
            let b = mine(p, t + 601 + i as u32, h);
            p = b.block_hash();
            t = b.header.time;
            branch.push(b);
        }
        assert_eq!(branch.len(), 16);
        let out = hub.accept_branch(&branch).unwrap();
        assert!(
            matches!(out, AcceptOutcome::Accepted { height: 18 }),
            "depth-16 reorg must accept, got {out:?}"
        );
        assert_eq!(hub.tip_height(), Some(18));
        assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());
        assert_ne!(hub.tip_hash().unwrap(), main_tip);

        // Weaker shorter branch from height 17 → IgnoredWeaker.
        let weak = mine(hub.tip_hash().unwrap(), t + 10, 19); // extends tip — Accepted
        let _ = weak;
        let weak_side = mine(fork_prev, t + 9000, 3);
        let weak_out = hub.accept_branch(&[weak_side]).unwrap();
        assert!(
            matches!(weak_out, AcceptOutcome::IgnoredWeaker),
            "short side from old LCA must be weaker: {weak_out:?}"
        );
        assert_eq!(hub.tip_height(), Some(18));

        // Mid-branch invalid: longer path from height 10 with a bad spend in the middle.
        let pre_tip = hub.tip_hash().unwrap();
        let pre_h = hub.tip_height().unwrap();
        let fork2 = hub
            .query
            .header_at_height(Height(10))
            .unwrap()
            .unwrap()
            .1
            .hash;
        let fork2_prev = BlockHash::from_byte_array(fork2);
        let fork2_time = hub
            .query
            .header_at_height(Height(10))
            .unwrap()
            .unwrap()
            .1
            .timestamp;

        // Path length 10 (> remaining 8 on main from 11..=18) so work_better.
        let mut bad_branch = Vec::new();
        let mut p = fork2_prev;
        let mut t = fork2_time;
        for (i, h) in (11..=20u32).enumerate() {
            let b = if i == 2 {
                // Height 13: spend a non-existent prevout → connect fails.
                let bad_tx = Transaction {
                    version: TxVersion::ONE,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid: bitcoin::Txid::from_byte_array([0xee; 32]),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(1),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    }],
                };
                mine_with_extra(p, t + 701 + i as u32, h, vec![bad_tx])
            } else {
                mine(p, t + 701 + i as u32, h)
            };
            p = b.block_hash();
            t = b.header.time;
            bad_branch.push(b);
        }
        assert_eq!(bad_branch.len(), 10);
        let err = hub
            .accept_branch(&bad_branch)
            .expect_err("invalid mid-branch must fail connect");
        assert!(
            matches!(err, NetError::Consensus(_) | NetError::ConnectFailed { .. }),
            "expected consensus fail, got {err}"
        );
        // The two-block valid prefix does not out-work the eight-block old
        // branch, so the old tip is restored.
        assert_eq!(
            hub.tip_height(),
            Some(pre_h),
            "tip height must restore after failed reorg"
        );
        assert_eq!(
            hub.tip_hash().unwrap(),
            pre_tip,
            "tip hash must equal pre-attempt tip after mid-branch invalid"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tip-follow capacity: 99-block competing branch via shipped `accept_branch`.
    #[test]
    fn most_work_reorg_depth99_tip_follow_capacity() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let mut tip = gen;
        let time = 1_600_000_000u32;
        // Main chain tip at height 10.
        for h in 1..=10u32 {
            let b = mine(tip, time + h * 600, h);
            tip = b.block_hash();
            hub.accept_block(b).unwrap();
        }
        assert_eq!(hub.tip_height(), Some(10));
        let fork_parent = hub
            .query
            .header_at_height(Height(1))
            .unwrap()
            .unwrap()
            .1
            .hash;
        let fork_prev = BlockHash::from_byte_array(fork_parent);
        let fork_time = hub
            .query
            .header_at_height(Height(1))
            .unwrap()
            .unwrap()
            .1
            .timestamp;
        // 99 blocks after height 1 → tip height 100.
        let mut branch = Vec::with_capacity(99);
        let mut p = fork_prev;
        let mut t = fork_time;
        for (i, h) in (2..=100u32).enumerate() {
            let b = mine(p, t + 601 + i as u32, h);
            p = b.block_hash();
            t = b.header.time;
            branch.push(b);
        }
        assert_eq!(branch.len(), 99);
        const {
            assert!(crate::peer::MAX_PENDING_BLOCKS_FOR_TEST >= 99);
        }
        let out = hub.accept_branch(&branch).unwrap();
        assert!(
            matches!(out, AcceptOutcome::Accepted { height: 100 }),
            "99-block reorg must accept, got {out:?}"
        );
        assert_eq!(hub.tip_height(), Some(100));
        assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn held_bodies_trim_stale_below_unrequested_window() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_040_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        let stale = mine_distinct(gen, 1_300_040_001, 1, &[b1.block_hash()]);
        assert!(matches!(
            hub.accept_received_block(stale.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&stale.block_hash()).is_some());

        rbitcoin_consensus::pad_empty_from(
            hub.query.as_ref(),
            &hub.params,
            b1.block_hash(),
            b1.header.time,
            2,
            289,
            0,
        );
        assert_eq!(hub.tip_height(), Some(289));
        let tip_hash = hub.tip_hash().unwrap();
        let tip_block = hub
            .block_at_height(289)
            .unwrap()
            .expect("padded tip reconstructable");
        let mut near = rbitcoin_consensus::mine_empty_regtest(
            tip_block.header.prev_blockhash,
            tip_block.header.time.saturating_add(1),
            289,
        );
        if near.block_hash() == tip_hash {
            let target = Target::from_compact(near.header.bits);
            for nonce in 0..u32::MAX {
                near.header.nonce = nonce;
                if near.header.validate_pow(target).is_ok() && near.block_hash() != tip_hash {
                    break;
                }
            }
        }
        assert!(matches!(
            hub.accept_received_block(near.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&near.block_hash()).is_some());

        let next = rbitcoin_consensus::mine_empty_regtest(
            tip_hash,
            tip_block.header.time.saturating_add(600),
            290,
        );
        hub.accept_block(next).unwrap();
        assert_eq!(hub.tip_height(), Some(290));
        assert!(
            hub.held_body(&stale.block_hash()).is_none(),
            "held body 289 heights behind tip must trim"
        );
        assert!(
            hub.held_body(&near.block_hash()).is_some(),
            "sibling at previous tip height must stay held"
        );

        let far = mine_distinct(
            gen,
            1_300_040_002,
            1,
            &[b1.block_hash(), stale.block_hash()],
        );
        assert!(matches!(
            hub.accept_received_block(far.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(
            hub.held_body(&far.block_hash()).is_none(),
            "must not hold IgnoredWeaker already >288 below tip"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    fn missing_prevout_child(prev: BlockHash, time: u32, height: u32) -> Block {
        let spend = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x29; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        mine_regtest_paying(
            prev,
            time,
            height,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend],
        )
    }

    #[test]
    fn invalid_held_child_does_not_poison_later_apply() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_050_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        let side = mine_distinct(gen, 1_300_050_001, 1, &[b1.block_hash()]);
        assert!(matches!(
            hub.accept_received_block(side.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&side.block_hash()).is_some());

        let bad = missing_prevout_child(side.block_hash(), side.header.time.saturating_add(600), 2);
        let err = hub
            .accept_received_block(bad.clone())
            .expect_err("missing prevout must reject");
        match err {
            NetError::Consensus(s) => {
                assert!(s.contains("bad-txns-inputs-missingorspent"), "got {s}");
            }
            NetError::ConnectFailed { msg, hash } => {
                assert!(msg.contains("bad-txns-inputs-missingorspent"), "got {msg}");
                assert_eq!(hash, bad.block_hash().to_byte_array());
            }
            other => panic!("expected consensus reject, got {other:?}"),
        }
        assert_eq!(hub.tip_hash(), Some(b1.block_hash()));
        assert!(
            hub.held_body(&bad.block_hash()).is_none(),
            "consensus-invalid child must leave held_bodies"
        );
        assert!(
            hub.is_block_invalid(&bad.block_hash()),
            "missingorspent child is BLOCK_FAILED"
        );

        assert!(matches!(
            hub.accept_received_block(side.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker | AcceptOutcome::AlreadyHave
        ));
        assert_eq!(
            hub.tip_hash(),
            Some(b1.block_hash()),
            "retrying the sibling must not fail or reorg onto the invalid child"
        );

        let good = mine(side.block_hash(), side.header.time.saturating_add(601), 2);
        assert!(matches!(
            hub.accept_received_block(good.clone()).unwrap(),
            AcceptOutcome::Accepted { height: 2 }
        ));
        assert_eq!(hub.tip_hash(), Some(good.block_hash()));

        hub.note_invalid_block(good.block_hash());
        let err = hub
            .accept_branch(&[side.clone(), good.clone()])
            .expect_err("invalidated tip must not apply");
        match err {
            NetError::Consensus(s) => {
                assert!(s.contains("invalidat"), "got {s}");
            }
            other => panic!("expected invalidated refuse, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    fn mine_chain(hub: &ChainHub, len: u32, time: u32) -> Vec<Block> {
        let mut prev = hub.tip_hash().unwrap();
        let base = hub.tip_height().unwrap();
        let mut out = Vec::new();
        for h in base + 1..=base + len {
            let b = mine(prev, time + h * 600, h);
            prev = b.block_hash();
            hub.accept_block(b.clone()).unwrap();
            out.push(b);
        }
        out
    }

    #[test]
    fn sibling_claiming_more_work_with_wrong_bits_keeps_the_tip() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 5, 1_300_060_000);
        let tip = main[4].block_hash();
        for h in (2..=5u32).rev() {
            let parent = &main[h as usize - 2];
            let mut bogus = mine(parent.block_hash(), parent.header.time + 1, h);
            bogus.header.bits = CompactTarget::from_consensus(0x1700_ffff);
            let err = hub
                .accept_received_block(bogus)
                .expect_err("a sibling with wrong nBits must be rejected");
            assert!(err.to_string().contains("bits"), "height {h}: {err}");
            assert_eq!(
                hub.tip_hash(),
                Some(tip),
                "a rejected sibling at height {h} must not move the tip"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Side branch `w2, w3, w4` off `main[0]`, where `w4` has a wrong BIP34
    /// height. `w2` and `w4` arrive first; returns `w3`'s outcome.
    fn side_branch_with_bad_tip(
        hub: &ChainHub,
        main: &[Block],
    ) -> (Result<AcceptOutcome, NetError>, [Block; 3]) {
        let x1 = &main[0];
        let w2 = mine_distinct(
            x1.block_hash(),
            x1.header.time + 1,
            2,
            &[main[1].block_hash()],
        );
        let w3 = mine(w2.block_hash(), w2.header.time + 600, 3);
        let w4 = mine(w3.block_hash(), w3.header.time + 600, 9);
        for early in [&w2, &w4] {
            assert!(matches!(
                hub.accept_received_block(early.clone()).unwrap(),
                AcceptOutcome::IgnoredWeaker
            ));
        }
        let out = hub.accept_received_block(w3.clone());
        (out, [w2, w3, w4])
    }

    #[test]
    fn failed_branch_tip_keeps_the_heavier_valid_prefix() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 2, 1_300_070_000);
        let (out, [_, w3, w4]) = side_branch_with_bad_tip(&hub, &main);
        assert!(
            matches!(out, Ok(AcceptOutcome::Accepted { height: 3 })),
            "valid w3 out-works x2: {out:?}"
        );
        assert_eq!(hub.tip_hash(), Some(w3.block_hash()));
        assert!(hub.is_block_invalid(&w4.block_hash()));
        assert!(!hub.is_block_invalid(&w3.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `w2, w3` are held and out-work `x2`; the offered `w4` fails connect.
    /// The prefix stays the tip, and the call that delivered `w4` fails.
    #[test]
    fn failed_offered_block_is_rejected_when_its_held_prefix_stays() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 2, 1_300_074_000);
        let x1 = &main[0];
        let w2 = mine_distinct(
            x1.block_hash(),
            x1.header.time + 1,
            2,
            &[main[1].block_hash()],
        );
        let w3 = mine(w2.block_hash(), w2.header.time + 600, 3);
        let w4 = mine(w3.block_hash(), w3.header.time + 600, 9);
        hub.hold_unconnected_body(w2);
        hub.hold_unconnected_body(w3.clone());
        let err = hub
            .accept_received_block(w4.clone())
            .expect_err("w4 has a wrong BIP34 height");
        assert_eq!(
            err.failing_block_hash(),
            Some(w4.block_hash().to_byte_array())
        );
        assert_eq!(hub.tip_hash(), Some(w3.block_hash()));
        assert!(hub.is_block_invalid(&w4.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_branch_tip_does_not_reject_the_offered_parent() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 3, 1_300_071_000);
        let (out, [_, w3, w4]) = side_branch_with_bad_tip(&hub, &main);
        assert!(
            matches!(out, Ok(AcceptOutcome::IgnoredWeaker)),
            "w3 only ties x3, and w4's failure is not w3's: {out:?}"
        );
        assert_eq!(hub.tip_hash(), Some(main[2].block_hash()));
        assert!(hub.is_block_invalid(&w4.block_hash()));
        assert!(!hub.is_block_invalid(&w3.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two held branches score the same work from their own fork points.
    /// The later one forks higher, so it has more total chain work.
    #[test]
    fn held_branch_with_more_total_work_beats_an_earlier_local_tie() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 3, 1_300_072_000);
        let [x1, x2, x3] = [&main[0], &main[1], &main[2]];
        let y2 = mine_distinct(x1.block_hash(), x1.header.time + 1, 2, &[x2.block_hash()]);
        let y3 = mine(y2.block_hash(), y2.header.time + 600, 3);
        let z3 = mine_distinct(x2.block_hash(), x2.header.time + 1, 3, &[x3.block_hash()]);
        let z4 = mine(z3.block_hash(), z3.header.time + 600, 4);
        for b in [&y2, &y3, &z3] {
            assert!(matches!(
                hub.accept_received_block(b.clone()).unwrap(),
                AcceptOutcome::IgnoredWeaker
            ));
        }
        let out = hub.accept_received_block(z4.clone()).unwrap();
        assert!(
            matches!(out, AcceptOutcome::Accepted { height: 4 }),
            "z4 has the most total work: {out:?}"
        );
        assert_eq!(hub.tip_hash(), Some(z4.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `p2` completes two held branches. The heavier one fails at `m3`; the
    /// lighter `n3` is still heavier than the tip and must win.
    #[test]
    fn failed_heavier_held_branch_does_not_hide_a_valid_one() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let main = mine_chain(&hub, 2, 1_300_073_000);
        let x1 = &main[0];
        let p2 = mine_distinct(
            x1.block_hash(),
            x1.header.time + 1,
            2,
            &[main[1].block_hash()],
        );
        let m3 = mine(p2.block_hash(), p2.header.time + 600, 9);
        let m4 = mine(m3.block_hash(), m3.header.time + 600, 4);
        let n3 = mine_distinct(p2.block_hash(), p2.header.time + 601, 3, &[m3.block_hash()]);
        for b in [&m3, &m4, &n3] {
            assert!(matches!(
                hub.accept_received_block(b.clone()).unwrap(),
                AcceptOutcome::IgnoredWeaker
            ));
        }
        let out = hub.accept_received_block(p2.clone()).unwrap();
        assert!(
            matches!(out, AcceptOutcome::Accepted { height: 3 }),
            "n3 is the most-work valid tip: {out:?}"
        );
        assert_eq!(hub.tip_hash(), Some(n3.block_hash()));
        assert!(hub.is_block_invalid(&m3.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn find_store_file(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
        for e in std::fs::read_dir(root).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(hit) = find_store_file(&p, name) {
                    return Some(hit);
                }
            } else if p.file_name().is_some_and(|n| n == name) {
                return Some(p);
            }
        }
        None
    }

    fn spend_block(prev: BlockHash, time: u32, height: u32, outpoint: OutPoint) -> Block {
        let spend = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        mine_regtest_paying(
            prev,
            time,
            height,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend],
        )
    }

    /// Hub at `t2` on `b1` with `txout.body` cut to zero bytes: any later
    /// read of a confirmed out is a local IO fault, not a block verdict.
    fn hub_with_truncated_body() -> (rbitcoin_query::testutil::TempDir, ChainHub, Block, Block) {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_080_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        let t2 = mine(b1.block_hash(), b1.header.time + 600, 2);
        hub.accept_block(t2.clone()).unwrap();
        let body = find_store_file(dir.path(), "txout.body").expect("txout.body");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&body)
            .unwrap()
            .set_len(0)
            .unwrap();
        (dir, hub, b1, t2)
    }

    fn coinbase_out(b: &Block) -> OutPoint {
        OutPoint {
            txid: b.txdata[0].compute_txid(),
            vout: 0,
        }
    }

    /// Core treats a local read fault as fatal, never `BLOCK_FAILED_VALID`.
    /// The spend is also immature, so a missed fault would cache the hash.
    #[test]
    fn store_fault_on_tip_connect_does_not_cache_block_invalid() {
        let (dir, hub, b1, t2) = hub_with_truncated_body();

        let b3 = spend_block(t2.block_hash(), t2.header.time + 600, 3, coinbase_out(&b1));
        let err = hub
            .accept_received_block(b3.clone())
            .expect_err("parent body read past EOF must fail");
        assert!(matches!(err, NetError::Store(_)), "tip extend: {err:?}");
        assert!(
            !hub.is_block_invalid(&b3.block_hash()),
            "a store fault on tip extend is not a block verdict"
        );
        assert_eq!(hub.tip_hash(), Some(t2.block_hash()));

        let s2 = mine_distinct(b1.block_hash(), t2.header.time + 1, 2, &[t2.block_hash()]);
        assert!(matches!(
            hub.accept_received_block(s2.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        let s3 = spend_block(s2.block_hash(), s2.header.time + 600, 3, coinbase_out(&b1));
        let err = hub
            .accept_received_block(s3.clone())
            .expect_err("reorg must hit the same read fault");
        assert!(matches!(err, NetError::Store(_)), "reorg: {err:?}");
        assert!(
            !hub.is_block_invalid(&s3.block_hash()),
            "a store fault during reorg is not a block verdict"
        );
        assert_eq!(hub.tip_hash(), Some(t2.block_hash()));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn store_fault_applying_held_child_does_not_cache_block_invalid() {
        let (dir, hub, b1, t2) = hub_with_truncated_body();

        let b3 = mine(t2.block_hash(), t2.header.time + 600, 3);
        let c4 = spend_block(b3.block_hash(), b3.header.time + 600, 4, coinbase_out(&b1));
        assert!(matches!(
            hub.accept_received_block(c4.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&c4.block_hash()).is_some());

        let err = hub
            .accept_received_block(b3.clone())
            .expect_err("held child connect must hit the read fault");
        assert!(matches!(err, NetError::Store(_)), "held apply: {err:?}");
        assert_eq!(hub.tip_hash(), Some(b3.block_hash()));
        assert!(
            !hub.is_block_invalid(&c4.block_hash()),
            "a store fault applying a held child is not a block verdict"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[allow(clippy::cognitive_complexity)] // one hub: tip rejects, 64-byte body, in-block duplicates
    #[test]
    fn hostile_peer_session() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let tip = hub.tip_hash().unwrap();

        let mut zero = mine(tip, 1_300_000_100, 1);
        zero.header.prev_blockhash = BlockHash::from_byte_array([0u8; 32]);
        let err = hub.accept_received_block(zero).expect_err("zero prev");
        assert!(
            err.to_string().contains("non-genesis prev is zero"),
            "{err}"
        );
        assert_eq!(hub.tip_hash(), Some(tip));
        assert_eq!(hub.held_body_count(), 0);

        let honest = mine(tip, 1_300_070_000, 1);
        let mut padded = honest.clone();
        let mut wit = Witness::new();
        wit.push(vec![0u8; 4_000_000]);
        padded.txdata[0].input[0].witness = wit;
        assert_eq!(padded.block_hash(), honest.block_hash());
        hub.note_asked_block(honest.block_hash());
        let _err = hub
            .accept_received_block(padded)
            .expect_err("witness padding past the weight limit must reject");
        assert!(
            !hub.is_block_invalid(&honest.block_hash()),
            "witness padding must not cache the block hash"
        );
        let mut short_cb = honest.clone();
        short_cb.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        assert_eq!(short_cb.block_hash(), honest.block_hash());
        let err = hub
            .accept_received_block(short_cb)
            .expect_err("a coinbase the header does not commit to must reject");
        assert!(matches!(&err, NetError::Mutated(_)), "{err:?}");
        assert!(
            !hub.is_block_invalid(&honest.block_hash()),
            "a swapped coinbase scriptSig must not cache the block hash"
        );
        assert!(matches!(
            hub.accept_received_block(honest.clone()).unwrap(),
            AcceptOutcome::Accepted { height: 1 }
        ));

        let inner = super::sixty_four_byte_body(honest.block_hash(), honest.header.time + 1);
        hub.note_asked_block(inner.block_hash());
        let err = hub
            .accept_received_block(inner.clone())
            .expect_err("a body with no coinbase must reject");
        assert!(matches!(err, NetError::Mutated(_)), "got {err:?}");
        assert!(
            !hub.is_block_invalid(&inner.block_hash()),
            "a 64-byte tx without a coinbase may be an inner merkle node: \
             the header's real body must stay acceptable"
        );
        assert!(
            !hub.already_have_or_asked_block(&inner.block_hash()),
            "a mutated reject forgets the ask so the real body can be fetched"
        );
        assert_eq!(hub.tip_hash(), Some(honest.block_hash()));

        // The header commits to these txs, so the hash itself is invalid
        // (Core bad-cb-multiple; a repeat that leaves the tree unmutated is
        // bad-txns-inputs-missingorspent at connect).
        let spend = |n: u8| Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([n; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let t2 = honest.header.time + 600;
        for (extra, want) in [
            (vec![coinbase(3)], "bad-cb-multiple"),
            (
                vec![spend(1), spend(2), spend(1)],
                "bad-txns-inputs-missingorspent",
            ),
        ] {
            let bad = mine_with_extra(honest.block_hash(), t2, 2, extra);
            hub.note_asked_block(bad.block_hash());
            let err = hub.accept_received_block(bad.clone()).expect_err(want);
            assert!(
                matches!(&err, NetError::Consensus(s) if s.contains(want)),
                "{want}: {err:?}"
            );
            assert!(hub.is_block_invalid(&bad.block_hash()), "{want} cached");
        }

        let now = honest.header.time;
        hub.clock.set_mock(i64::from(now));
        let far = now + 2 * 3600 + 1;
        let future = mine(honest.block_hash(), far, 2);
        hub.note_asked_block(future.block_hash());
        let err = hub
            .accept_received_block(future.clone())
            .expect_err("header more than two hours ahead of mock");
        let msg = match &err {
            NetError::Consensus(s) => s.as_str(),
            other => panic!("expected Consensus time-too-new, got {other:?}"),
        };
        assert!(
            msg.contains("time-too-new") || msg.contains("future"),
            "got {msg}"
        );
        assert!(
            !hub.is_block_invalid(&future.block_hash()),
            "time-too-new must not cache BLOCK_FAILED"
        );
        assert!(
            !hub.already_have_or_asked_block(&future.block_hash()),
            "time-too-new must forget asked_blocks so a later getdata can retry"
        );
        assert_eq!(hub.tip_hash(), Some(honest.block_hash()));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A cached create height is not spendable once the fence drops that fk.
    /// The maturity short-circuit must not run on a height the best chain no
    /// longer has: a disconnect between the parent memo and this check is
    /// `bad-txns-inputs-missingorspent`.
    #[test]
    fn coinbase_spend_rejects_cached_height_after_disconnect() {
        let (dir, hub) = tmp_hub();
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(1, op_true, vec![]).unwrap();
        let fk = hub.query.block_tx_fks(Height(1)).unwrap()[0];
        let created_h = hub.query.store().tx_height_get(fk).unwrap().unwrap();
        assert_eq!(created_h, 1);
        hub.invalidate_block(hub.tip_hash().unwrap()).unwrap();
        assert_eq!(
            hub.query.store().tx_height_get(fk).unwrap(),
            None,
            "invalidate drops the create off the fence"
        );
        let err = coinbase_spend_is_immature(
            hub.query.as_ref(),
            fk,
            created_h,
            created_h.saturating_add(100),
            100,
        )
        .expect_err("a disconnected create is not a mature input");
        assert_eq!(err, "bad-txns-inputs-missingorspent");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// One regtest node at height 101 checking block proposals, the Core
    /// `TestBlockValidity` path behind `getblocktemplate` proposal mode.
    /// Regtest coinbase maturity is 100, so a mature spend needs a 101-block
    /// chain and no smaller N reaches one; that one boot is what runs this
    /// test past the two-second budget, and it serves every beat. The
    /// tip-child, coinbase-amount, immature-coinbase, and mature-spend beats
    /// do not observe each other; they ride this hub rather than a shared
    /// fixture because they only read the 101-block tip the mutating beats
    /// then build on (the parent mined at 102, its child confirmed at 103,
    /// that block invalidated), so a second setup would add store copies and
    /// test names without a new observation.
    /// A tip child passes; a block on any other
    /// parent is `inconclusive-not-best-prevblk`. Core prices the coinbase
    /// in ConnectBlock, after CheckBlock: a coinbase over subsidy + fees is
    /// `bad-cb-amount` once the structure checks pass, and a structure
    /// reject on the same block still wins. An immature coinbase is not a
    /// fee source: spending this block's coinbase, or one still inside the
    /// maturity window, is `bad-txns-premature-spend-of-coinbase` before
    /// fees are summed, even when that spend would cover an overpaying
    /// coinbase. `Ok` carries the block fees, so a template provider can
    /// price the coinbase at exactly subsidy + fees. A fan-out parent is
    /// decoded once per check, not once per child
    /// (`TxTable::sample_reset_body_decodes`); output `i` carries a distinct
    /// value so the fee total also pins vout indexing. Spentness is probed
    /// per input: with vout 0 confirmed spent, a proposal whose first sight
    /// of the parent is the unspent vout 1 still rejects a fresh spend of
    /// vout 0 (a fresh tx, so Core's answer is the same reject and not
    /// `bad-txns-BIP30`).
    /// Parents resolve on the connected chain only: after the block that
    /// confirmed `child(0)` is invalidated, a spend of its output is
    /// `bad-txns-inputs-missingorspent` and the stale row is not decoded.
    #[test]
    fn check_block_proposal_prices_fees_and_rejects_on_one_chain() {
        let (dir, hub) = tmp_hub();
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(101, op_true.clone(), vec![])
            .unwrap();

        let block = hub
            .assemble_block_to_script(op_true.clone(), vec![])
            .unwrap();
        assert_eq!(
            hub.check_block_proposal(&block),
            Ok(0),
            "no fees in a coinbase-only block"
        );
        let mut off_tip = block.clone();
        off_tip.header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
        assert_eq!(
            hub.check_block_proposal(&off_tip).unwrap_err(),
            "inconclusive-not-best-prevblk"
        );

        let mut fat_cb = block;
        let cb = &mut fat_cb.txdata[0].output[0].value;
        *cb = Amount::from_sat(cb.to_sat() + 1);
        let root_for_fat_cb = fat_cb.compute_merkle_root().unwrap();
        assert_eq!(
            hub.check_block_proposal(&fat_cb).unwrap_err(),
            "bad-txnmrklroot",
            "structure checks run before the coinbase is priced"
        );
        fat_cb.header.merkle_root = root_for_fat_cb;
        assert_eq!(
            hub.check_block_proposal(&fat_cb).unwrap_err(),
            "bad-cb-amount"
        );

        let cb_txid = fat_cb.txdata[0].compute_txid();
        fat_cb.txdata.push(spend_out(cb_txid, 0));
        assert_eq!(
            hub.check_block_proposal(&fat_cb).unwrap_err(),
            "bad-txnmrklroot",
            "structure checks run before the immature spend"
        );
        fat_cb.header.merkle_root = fat_cb.compute_merkle_root().unwrap();
        assert_eq!(
            hub.check_block_proposal(&fat_cb).unwrap_err(),
            "bad-txns-premature-spend-of-coinbase",
            "a same-block coinbase spend must not inflate fees"
        );
        let tip_cb = hub
            .query
            .reconstruct_block_at_height(Height(101))
            .unwrap()
            .txdata[0]
            .clone();
        let tip_cb_value = tip_cb.output[0].value.to_sat();
        let immature = spend_out(tip_cb.compute_txid(), tip_cb_value - 1_000);
        let block = hub
            .assemble_block_to_script(op_true.clone(), vec![immature])
            .unwrap();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-txns-premature-spend-of-coinbase"
        );
        let over = spend_out(tip_cb.compute_txid(), tip_cb_value + 1);
        let block = hub
            .assemble_block_to_script(op_true.clone(), vec![over])
            .unwrap();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-txns-premature-spend-of-coinbase",
            "maturity is reported before bad-txns-in-belowout"
        );

        let spend = mature_spend_tx(&hub, 1);
        let mut block = hub
            .assemble_block_to_script(op_true.clone(), vec![spend])
            .unwrap();
        assert_eq!(hub.check_block_proposal(&block), Ok(10_000));
        let subsidy = rbitcoin_consensus::block_subsidy(102, &hub.params) as u64;
        block.txdata[0].output[0].value = Amount::from_sat(subsidy + 10_000);
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert_eq!(hub.check_block_proposal(&block), Ok(10_000));

        let payout = 98_000_000u64;
        let parent_value = |vout: u32| payout + 1_000 * u64::from(vout + 1);
        let mut parent = mature_spend_tx(&hub, 1);
        parent.output = (0..50)
            .map(|vout| TxOut {
                value: Amount::from_sat(parent_value(vout)),
                script_pubkey: op_true.clone(),
            })
            .collect();
        let parent_txid = parent.compute_txid();
        hub.generate_to_script(1, op_true.clone(), vec![parent])
            .unwrap();
        let child_paying = |vout: u32, value: u64| Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: op_true.clone(),
            }],
        };
        let child = |vout: u32| child_paying(vout, payout);
        let block = hub
            .assemble_block_to_script(op_true.clone(), (0..50).map(child).collect())
            .unwrap();
        let fees: u64 = (0..50).map(|vout| parent_value(vout) - payout).sum();
        let store = hub.query.store();
        let _ = store.txs.sample_reset_body_decodes();
        assert_eq!(hub.check_block_proposal(&block), Ok(fees));
        assert_eq!(
            store.txs.sample_reset_body_decodes(),
            1,
            "one packed body decode per distinct parent; the spentness probes and the fk resolve decode nothing"
        );

        hub.generate_to_script(1, op_true.clone(), vec![child(0)])
            .unwrap();
        let respend = child_paying(0, payout - 1_000);
        let block = hub
            .assemble_block_to_script(op_true.clone(), vec![child(1), respend])
            .unwrap();
        let _ = store.txs.sample_reset_body_decodes();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-txns-inputs-missingorspent",
            "spentness is probed per input; the parent seen first through unspent vout 1 does not vouch for vout 0"
        );
        assert_eq!(store.txs.sample_reset_body_decodes(), 1);

        let stale = hub.tip_hash().unwrap();
        hub.invalidate_block(stale).unwrap();
        assert_eq!(hub.tip_height(), Some(102));
        let grandchild = spend_out(child(0).compute_txid(), payout - 1_000);
        let block = hub
            .assemble_block_to_script(op_true, vec![grandchild])
            .unwrap();
        let _ = store.txs.sample_reset_body_decodes();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-txns-inputs-missingorspent",
            "an output that exists only in a reorged-out block is not spendable"
        );
        assert_eq!(
            store.txs.sample_reset_body_decodes(),
            0,
            "a row with no fence height is not decoded"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn store_fault_during_header_check_is_not_a_failed_block() {
        let hash = [0x11; 32];
        let store = connect_failed_for_header(hash, NetError::Store("budget full: SQ".into()));
        assert!(
            matches!(store, NetError::Store(_)),
            "a store fault must not name a block, got {store}"
        );
        let bad = connect_failed_for_header(hash, NetError::Consensus("bad-diffbits".into()));
        match bad {
            NetError::ConnectFailed { hash: h, msg } => {
                assert_eq!(h, hash);
                assert!(msg.contains("bad-diffbits"), "{msg}");
            }
            other => panic!("consensus header failure must name the block, got {other}"),
        }
    }

    /// Witness sigops are not in the structure walk. Nine P2WSH inputs of
    /// 10_000 `OP_CHECKSIG` each are over the 80_000 block limit.
    #[test]
    fn check_block_proposal_rejects_witness_sigops_over_the_limit() {
        let (dir, hub) = tmp_hub();
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(101, op_true.clone(), vec![])
            .unwrap();
        let ws = ScriptBuf::from_bytes(vec![0xac; 10_000]);
        let p2wsh = ScriptBuf::new_p2wsh(&ws.wscript_hash());
        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let per = (50_0000_0000u64 - 1_000) / 9;
        let fan = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: (0..9)
                .map(|_| TxOut {
                    value: Amount::from_sat(per),
                    script_pubkey: p2wsh.clone(),
                })
                .collect(),
        };
        let fan_id = fan.compute_txid();
        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: (0..9u32)
                .map(|vout| TxIn {
                    previous_output: OutPoint { txid: fan_id, vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::from_slice(&[ws.as_bytes()]),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(per * 9 - 1_000),
                script_pubkey: op_true.clone(),
            }],
        };
        let block = hub
            .assemble_block_to_script(op_true, vec![fan, spend])
            .unwrap();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-blk-sigops"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn spend_out(txid: bitcoin::Txid, value: u64) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }
}
