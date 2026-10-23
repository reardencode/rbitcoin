//! Shared chain accept path for P2P: tip extension and most-work reorg.
//!
//! Lock order: `connect_lock` then inner maps (`held_bodies`, `confirmed`,
//! `invalidated`, `header_tips`, …). Never acquire `connect_lock` while holding
//! an inner guard.

use crate::cache::BlockCache;
use crate::error::NetError;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Target, Transaction, TxOut, Txid,
    Work,
};
use rbitcoin_consensus::{
    genesis_block, mine_op_true_signet_paying, mine_regtest_paying, validate_header_on_parent,
    ChainParams, Milestone,
};
use rbitcoin_log::{debug, info, warn};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use rbitcoin_query::{
    accept_and_connect_block_preverified, confirm_wire_load_from_plan as consensus_load_from_plan,
    confirm_wire_load_phase_pipelined, confirm_write_phase, header_to_record, validate_header,
    PlanStampOutcome, ScriptOkBatch, ScriptPreverified, WireLoadPipeline,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

thread_local! {
    static ENSURE_HEADERS_BATCH_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static ENSURE_HEADER_FK_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static HEADER_OF_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static CHAIN_WORK_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(debug_assertions)]
pub fn reset_header_store_counts() {
    ENSURE_HEADERS_BATCH_N.with(|c| c.set(0));
    HEADER_OF_N.with(|c| c.set(0));
    CHAIN_WORK_N.with(|c| c.set(0));
}

#[cfg(debug_assertions)]
pub fn reset_ensure_header_fk_count() {
    ENSURE_HEADER_FK_N.with(|c| c.set(0));
}

#[cfg(debug_assertions)]
pub fn ensure_header_fk_count() -> u64 {
    ENSURE_HEADER_FK_N.with(|c| c.get())
}

#[cfg(debug_assertions)]
pub fn header_store_counts() -> (u64, u64, u64) {
    (
        ENSURE_HEADERS_BATCH_N.with(|c| c.get()),
        HEADER_OF_N.with(|c| c.get()),
        CHAIN_WORK_N.with(|c| c.get()),
    )
}
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

#[doc(hidden)]
pub struct HeaderSyncNode {
    pub fk: Fk,
    pub header: Header,
    /// Resolved height. `None` means the ancestor walk hit the cap; children
    /// of that node must not walk again.
    pub height: Option<u32>,
}

/// One parked body. `waive` is the session bit from the accept that first
/// held it. A later hold of the same hash does not change it.
#[doc(hidden)]
pub struct HeldRow {
    pub block: Arc<Block>,
    pub seq: u64,
    pub waive: bool,
}

/// Never-confirmed side-branch bodies plus first-seen seq (equal-work FIFO).
#[doc(hidden)]
pub struct HeldBodies {
    pub by_hash: HashMap<BlockHash, HeldRow>,
    pub next_seq: u64,
}

impl HeldBodies {
    #[doc(hidden)]
    pub const CAP: usize = 320;
    #[doc(hidden)]
    pub const STALE_BELOW: u32 = 288;
    /// One honest max block. A larger body is not held.
    #[doc(hidden)]
    pub const MAX_BLOCK_SERIALIZED: usize = 4_000_000;

    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            next_seq: 1,
        }
    }

    #[doc(hidden)]
    pub fn wire_len(block: &Block) -> usize {
        block.total_size()
    }

    #[doc(hidden)]
    pub fn get(&self, hash: &BlockHash) -> Option<&Block> {
        self.by_hash.get(hash).map(|row| row.block.as_ref())
    }

    /// Session waive bit recorded with the first hold. Absent is strict.
    #[doc(hidden)]
    pub fn waive(&self, hash: &BlockHash) -> bool {
        self.hold_waive(hash).unwrap_or(false)
    }

    /// `Some` when this hash is held. The bool is that hold's waive bit.
    #[doc(hidden)]
    pub fn hold_waive(&self, hash: &BlockHash) -> Option<bool> {
        self.by_hash.get(hash).map(|row| row.waive)
    }

    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    #[doc(hidden)]
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    #[doc(hidden)]
    pub fn keys(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.keys().copied()
    }

    #[doc(hidden)]
    pub fn blocks(&self) -> impl Iterator<Item = &Block> + '_ {
        self.by_hash.values().map(|row| row.block.as_ref())
    }

    #[doc(hidden)]
    pub fn entries(&self) -> impl Iterator<Item = (BlockHash, &Block)> + '_ {
        self.by_hash.iter().map(|(h, row)| (*h, row.block.as_ref()))
    }

    #[doc(hidden)]
    pub fn seq(&self, hash: BlockHash) -> u64 {
        self.by_hash
            .get(&hash)
            .map(|row| row.seq)
            .unwrap_or(u64::MAX)
    }

    #[doc(hidden)]
    pub fn insert(&mut self, block: Arc<Block>, keep: &HashSet<BlockHash>, waive: bool) {
        let hash = block.block_hash();
        if let Some(row) = self.by_hash.get_mut(&hash) {
            // A later trusted-session hold may waive. A local hold does not clear it.
            if waive {
                row.waive = true;
            }
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
                .min_by_key(|(_, row)| row.seq)
                .map(|(h, _)| *h)
                .or_else(|| {
                    self.by_hash
                        .iter()
                        .min_by_key(|(_, row)| row.seq)
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
        self.by_hash.insert(hash, HeldRow { block, seq, waive });
    }

    #[doc(hidden)]
    pub fn remove(&mut self, hash: &BlockHash) {
        self.by_hash.remove(hash);
    }
}

/// Dial and reconsider hints. Not a validity set: the oldest drops at the cap.
#[doc(hidden)]
pub const FORK_TIP_CAP: usize = 64;

#[doc(hidden)]
pub struct ForkTips {
    pub tips: VecDeque<BlockHash>,
}

impl ForkTips {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            tips: VecDeque::new(),
        }
    }

    #[doc(hidden)]
    pub fn insert(&mut self, hash: BlockHash) {
        if self.tips.contains(&hash) {
            return;
        }
        if self.tips.len() == FORK_TIP_CAP {
            self.tips.pop_front();
        }
        self.tips.push_back(hash);
    }

    #[doc(hidden)]
    pub fn remove(&mut self, hash: &BlockHash) {
        self.tips.retain(|h| h != hash);
    }

    #[doc(hidden)]
    pub fn iter(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.tips.iter().copied()
    }
}

/// Operator-invalidated hashes and best-chain paths (hashes only, height order).
///
/// Uncapped. Forgetting an invalid hash would make that block acceptable again.
#[doc(hidden)]
pub struct Invalidated {
    pub set: RwLock<HashSet<BlockHash>>,
    pub paths: RwLock<Vec<InvalidPath>>,
    /// Connect failures kept across restart in [`INVALID_FILE`], oldest first.
    /// Operator invalidations are not: their paths are in-process only.
    pub failed: RwLock<Vec<BlockHash>>,
    pub file: std::path::PathBuf,
    /// `failed` holds a mark the last write did not put on disk.
    pub pending: std::sync::atomic::AtomicBool,
}

/// Refusal of a hash already marked invalid. Not a fresh validation result.
const BLOCK_IS_INVALIDATED: &str = "block is invalidated";

/// Sidecar of connect failures next to `header.adopt`. Not a schema bump.
const INVALID_FILE: &str = "block.invalid";
const INVALID_MAGIC: &[u8; 8] = b"rbtcinv1";
/// Past the cap the oldest kept failure gives way, so the newest survives restart.
const INVALID_FILE_CAP: usize = 4_096;

fn parse_invalid_file(bytes: &[u8]) -> Option<Vec<BlockHash>> {
    let rest = bytes.strip_prefix(INVALID_MAGIC)?;
    let (count, rest) = rest.split_first_chunk::<4>()?;
    let n = u32::from_le_bytes(*count) as usize;
    if n > INVALID_FILE_CAP || rest.len() != n.checked_mul(32)? {
        return None;
    }
    Some(
        rest.chunks_exact(32)
            .map(|c| {
                let mut raw = [0u8; 32];
                raw.copy_from_slice(c);
                BlockHash::from_byte_array(raw)
            })
            .collect(),
    )
}

fn write_invalid_file(path: &std::path::Path, hashes: &[BlockHash]) -> bool {
    let mut buf = Vec::with_capacity(12 + 32 * hashes.len());
    buf.extend_from_slice(INVALID_MAGIC);
    buf.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        buf.extend_from_slice(h.as_byte_array());
    }
    let wrote = rbitcoin_store::file::write_synced_tmp_file(path, |f| {
        std::io::Write::write_all(f, &buf).map_err(|e| rbitcoin_store::StoreError::io(path, e))
    });
    if let Err(e) = &wrote {
        warn!("chain: write {}: {e}", path.display());
    }
    wrote.is_ok()
}

/// The hashes one `invalidateblock` marked, in height order. `connected` when
/// they came off the active chain, so every one passed full validation.
#[derive(Clone)]
#[doc(hidden)]
pub struct InvalidPath {
    pub hashes: Vec<BlockHash>,
    pub connected: bool,
}

impl Invalidated {
    /// Load the connect failures in `store/block.invalid`. A missing file is
    /// none; one that does not parse is none and is replaced on the next write.
    #[doc(hidden)]
    pub fn open(store: &std::path::Path) -> Self {
        let file = store.join(INVALID_FILE);
        let failed = match std::fs::read(&file) {
            Ok(bytes) => parse_invalid_file(&bytes).unwrap_or_else(|| {
                warn!(
                    "chain: {} does not parse; no stored invalid blocks",
                    file.display()
                );
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };
        Self {
            set: RwLock::new(failed.iter().copied().collect()),
            paths: RwLock::new(Vec::new()),
            failed: RwLock::new(failed),
            file,
            pending: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// True once `hash`, and every mark before it, is in the file on disk. A
    /// write that failed before is tried again.
    fn keep_failed(&self, hash: BlockHash) -> bool {
        use std::sync::atomic::Ordering;
        let mut failed = self.failed.write().unwrap();
        if !failed.contains(&hash) {
            if failed.len() >= INVALID_FILE_CAP {
                failed.remove(0);
            }
            failed.push(hash);
        } else if !self.pending.load(Ordering::Acquire) {
            return true;
        }
        let wrote = write_invalid_file(&self.file, &failed);
        self.pending.store(!wrote, Ordering::Release);
        wrote
    }

    /// Drop kept failures that are no longer marked invalid.
    fn prune_failed(&self) {
        let set = self.set.read().unwrap();
        let mut failed = self.failed.write().unwrap();
        let before = failed.len();
        failed.retain(|h| set.contains(h));
        let pending = self.pending.load(std::sync::atomic::Ordering::Acquire);
        if failed.len() != before || pending {
            let wrote = write_invalid_file(&self.file, &failed);
            self.pending
                .store(!wrote, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Header-only tips (`submitheader` / P2P headers): hash → (prev, height).
#[doc(hidden)]
pub struct HeaderTips {
    pub by_hash: HashMap<BlockHash, (BlockHash, u32)>,
}

impl HeaderTips {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
        }
    }

    #[doc(hidden)]
    pub fn get(&self, hash: &BlockHash) -> Option<(BlockHash, u32)> {
        self.by_hash.get(hash).copied()
    }

    #[doc(hidden)]
    pub fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.get(hash).map(|(_, h)| h)
    }

    #[doc(hidden)]
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    #[doc(hidden)]
    pub fn insert(&mut self, hash: BlockHash, prev: BlockHash, height: u32) {
        self.by_hash.insert(hash, (prev, height));
    }

    #[doc(hidden)]
    pub fn remove(&mut self, hash: &BlockHash) {
        self.by_hash.remove(hash);
    }

    #[doc(hidden)]
    pub fn evict_one(&mut self) {
        if let Some(k) = self.by_hash.keys().next().copied() {
            self.by_hash.remove(&k);
        }
    }

    #[doc(hidden)]
    pub fn hashes(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.keys().copied()
    }

    #[doc(hidden)]
    pub fn prevs(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.by_hash.values().map(|(prev, _)| *prev)
    }

    #[doc(hidden)]
    pub fn entries(&self) -> impl Iterator<Item = (BlockHash, u32)> + '_ {
        self.by_hash.iter().map(|(hash, (_, h))| (*hash, *h))
    }
}

/// Mining / GBT knobs. Atomics so façade getters stay lock-free.
#[doc(hidden)]
pub struct MiningKnobs {
    pub block_version: AtomicI32,
    pub gbt_assembled: AtomicBool,
    pub block_min_tx_fee_sat_kvb: AtomicU64,
}

impl MiningKnobs {
    #[doc(hidden)]
    pub fn new() -> Self {
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
pub fn reject_is_mutated(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("merkle")
        || reason.contains("bad-txnmrklroot")
        || reason.contains("bad-txns-duplicate")
        || reason.contains("witness commitment")
        || reason.contains("bad-witness-nonce")
        || reason.contains("unexpected witness")
}

/// Core logs a contextual header reject (`bad-version`, `time-too-new`) with
/// its reason. The returned error keeps the store-facing Display string.
/// A consensus header failure names the block so it can be marked invalid.
/// A store fault stays a store fault: it must not be cached as `BLOCK_FAILED`.
#[doc(hidden)]
pub fn connect_failed_for_header(hash: [u8; 32], e: NetError) -> NetError {
    match e {
        NetError::Consensus(msg) => NetError::ConnectFailed { hash, msg },
        other => other,
    }
}

#[doc(hidden)]
pub fn header_reject(header: &Header, e: &rbitcoin_query::ConfirmError) -> NetError {
    if e.is_cancelled() {
        return NetError::Cancelled;
    }
    let rules = match e {
        rbitcoin_query::ConfirmError::Store(se) => return NetError::store(se),
        rbitcoin_query::ConfirmError::Rules(rbitcoin_consensus::ConsensusError::Internal(m)) => {
            return NetError::store(m);
        }
        rbitcoin_query::ConfirmError::Rules(r) => r,
    };
    let reason = rbitcoin_consensus::block_reject_reason(rules);
    rbitcoin_log::info!(
        "{}",
        rbitcoin_consensus::block_reject_log_line(header.block_hash(), &reason)
    );
    NetError::Consensus(rules.to_string())
}

/// Inputs a connected block spends, excluding the coinbase null prevout.
#[doc(hidden)]
pub fn spent_outpoints(txdata: &[Transaction]) -> Vec<OutPoint> {
    txdata
        .iter()
        .filter(|t| !t.is_coinbase())
        .flat_map(|t| t.input.iter().map(|i| i.previous_output))
        .collect()
}

/// Run a header check that does not open its own collector. The waive bit is
/// the thread cell. The caller set it for this batch, or left it off.
fn soften_parent_header(
    query: &rbitcoin_query::Query,
    header: &Header,
    height: u32,
    check: impl FnOnce() -> Result<(), rbitcoin_consensus::ConsensusError>,
) -> Result<(), rbitcoin_consensus::ConsensusError> {
    let own =
        rbitcoin_query::confirm_run::confirm_waive(query) && !rbitcoin_consensus::collecting();
    let guard = own.then(rbitcoin_consensus::TrustCollect::enter);
    let result = check();
    if own {
        let hash = header.block_hash().to_byte_array();
        let applied = result.is_ok();
        let stopped = result.as_ref().err();
        rbitcoin_query::confirm_run::log_collected_header(hash, height, applied, stopped);
        drop(guard);
    }
    result
}

pub fn accept_err_is_temporary_time(e: &NetError) -> bool {
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

/// Warn-and-apply faults stay retryable so the trusted session can deliver
/// the same block. Hard rejects still stick.
pub fn accept_err_is_warn_and_apply(e: &NetError) -> bool {
    let Some(reason) = (match e {
        NetError::Consensus(s) | NetError::Mutated(s) | NetError::ConnectFailed { msg: s, .. } => {
            Some(s.as_str())
        }
        _ => None,
    }) else {
        return false;
    };
    rbitcoin_consensus::reason_is_warn_and_apply(reason)
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
    pub tip_tx: broadcast::Sender<TipEvent>,
    /// Best-chain confirmed block hashes (O(1) `has_block` for IBD hot path).
    pub confirmed: Arc<RwLock<HashSet<BlockHash>>>,
    /// Serializes tip connect / reorg so multi-peer accept cannot double Class A+C.
    pub connect_lock: std::sync::Mutex<()>,
    /// Serializes regtest generate so concurrent generateblock cannot race one tip.
    pub generate_lock: std::sync::Mutex<()>,
    /// Tests stop one `generate` before this 0-based block index. `0` mines
    /// the whole call. Production never sets it.
    #[doc(hidden)]
    pub generate_fail_before: AtomicU32,
    /// Optional cluster mempool (tip-mode tx relay + confirm remove).
    ///
    /// Attached once via [`Self::attach_mempool`] after the hub is in an `Arc`.
    pub mempool: std::sync::OnceLock<Arc<crate::tx_relay::MempoolHub>>,
    /// Filled by [`Self::into_arc`]. Async tip jobs clone it.
    pub self_weak: std::sync::OnceLock<std::sync::Weak<ChainHub>>,
    /// Regtest `setmocktime` / generate timestamps. Default is wall clock.
    pub clock: Arc<rbitcoin_consensus::NodeClock>,
    pub invalidated: Invalidated,
    /// Never-confirmed side-branch bodies, keyed by hash. Small cap.
    /// Not a block index: once-confirmed losers stay in Class A.
    pub held_bodies: RwLock<HeldBodies>,
    pub precious: RwLock<Option<BlockHash>>,
    /// Losing tips after a most-work reorg (hashes only). Bodies via archive.
    pub fork_tips: RwLock<ForkTips>,
    /// Header-only tips (`submitheader` / P2P headers): hash → (prev, height).
    pub header_tips: RwLock<HeaderTips>,
    /// Set around `accept_branch` connect so each `TipEvent` carries branch length.
    pub announce_reorg_len: AtomicU32,
    /// Min-chain-work floor (32-byte BE). `None` = no extra floor.
    pub minimum_chain_work: RwLock<Option<[u8; 32]>>,
    pub mining: MiningKnobs,
    /// Tip recency seconds. Default 24h.
    pub max_tip_age_secs: AtomicU64,
    pub prefill_compact: AtomicBool,
    pub prefill_plan: std::sync::Mutex<Option<crate::compact::PrefillPlan>>,
    /// Block hashes we already issued getdata for (any peer).
    pub asked_blocks: RwLock<HashSet<BlockHash>>,
    /// `prefix[h] = work through height h` on the best chain. Process cache;
    /// rebuilt from wire headers when short, truncated on disconnect.
    pub chain_work_prefix: RwLock<Vec<Work>>,
    /// Once the relay-inhibited latch clears, stay out.
    pub finished_ibd: AtomicBool,
    /// Initial `getheaders` queued by follow sessions since process start.
    pub initial_getheaders_sent: AtomicU64,
    /// `headers` messages applied since process start (including empty).
    pub headers_replies: AtomicU64,
    /// A follow-session block inv during IBD. The walk asks its header peer.
    pub header_inv_challenge: AtomicBool,
    #[cfg(debug_assertions)]
    pub block_at_height_calls: AtomicU64,
    #[cfg(debug_assertions)]
    pub header_contextual_checks: AtomicU64,
    #[cfg(debug_assertions)]
    pub stored_height_walk_steps: AtomicU64,
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
#[doc(hidden)]
pub fn held_branch_beats(
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

/// Walk `start`'s parents until a known height, a zero previous hash, or
/// `cap` steps. `cap` steps with no known parent returns `None`.
#[doc(hidden)]
pub fn ancestor_walk(
    start: &BlockHash,
    cap: u32,
    mut header_of: impl FnMut(&BlockHash) -> Option<Header>,
    mut known_height: impl FnMut(&BlockHash) -> Option<u32>,
) -> Option<u32> {
    let mut cur = *start;
    let mut delta = 0u32;
    for _ in 0..cap {
        let hdr = header_of(&cur)?;
        let prev = hdr.prev_blockhash;
        if prev.to_byte_array() == [0u8; 32] {
            return Some(delta);
        }
        if let Some(ph) = known_height(&prev) {
            return Some(ph.saturating_add(1).saturating_add(delta));
        }
        cur = prev;
        delta = delta.saturating_add(1);
    }
    None
}

/// Record an already-stored header, including a walk that returned `None`.
///
/// Omitting that row made every later header in the run walk to the cap again.
#[doc(hidden)]
pub fn remember_stored_header(
    in_batch: &mut HashMap<[u8; 32], HeaderSyncNode>,
    hash: [u8; 32],
    prev: [u8; 32],
    fk: Fk,
    header: Header,
    walk: impl FnOnce() -> Option<u32>,
) {
    let parent_height = in_batch.get(&prev).map(|parent| parent.height);
    let height = match parent_height {
        Some(parent) => parent.map(|h| h.saturating_add(1)),
        None => walk(),
    };
    in_batch.insert(hash, HeaderSyncNode { fk, header, height });
}

impl ChainHub {
    pub fn new(query: Query, params: ChainParams, milestone: Milestone) -> Self {
        let (tip_tx, _) = broadcast::channel(64);
        let query = Arc::new(query);
        let confirmed = Arc::new(RwLock::new(seed_confirmed_tip(&query)));
        // Full confirmed-set fill in background (mainnet-scale tips make a
        // synchronous walk multi-minute). Tip/genesis are seeded immediately.
        spawn_confirmed_seed(query.clone(), confirmed.clone());
        let invalidated = Invalidated::open(query.store().path());
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
            generate_fail_before: AtomicU32::new(0),
            mempool: std::sync::OnceLock::new(),
            self_weak: std::sync::OnceLock::new(),
            clock: rbitcoin_consensus::NodeClock::new(),
            invalidated,
            held_bodies: RwLock::new(HeldBodies::new()),
            precious: RwLock::new(None),
            fork_tips: RwLock::new(ForkTips::new()),
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
            initial_getheaders_sent: AtomicU64::new(0),
            headers_replies: AtomicU64::new(0),
            header_inv_challenge: AtomicBool::new(false),
            #[cfg(debug_assertions)]
            block_at_height_calls: AtomicU64::new(0),
            #[cfg(debug_assertions)]
            header_contextual_checks: AtomicU64::new(0),
            #[cfg(debug_assertions)]
            stored_height_walk_steps: AtomicU64::new(0),
        }
    }

    pub fn note_asked_block(&self, hash: BlockHash) {
        let mut g = self.asked_blocks.write().unwrap();
        if g.len() >= 4096 {
            g.clear();
        }
        g.insert(hash);
    }

    /// One in-flight body ask. Connected and held bodies are not claims.
    /// A hash already asked is not claimed again. The set clears at 4096,
    /// the same cap as [`Self::note_asked_block`].
    #[doc(hidden)]
    pub fn claim_block_ask(&self, hash: &BlockHash) -> bool {
        if self.is_connected(hash) || self.held_body(hash).is_some() {
            return false;
        }
        let mut g = self.asked_blocks.write().unwrap();
        if g.contains(hash) {
            return false;
        }
        if g.len() >= 4096 {
            g.clear();
        }
        g.insert(*hash)
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

    /// GBT `version`: override, or versionbits top bits with testdummy (`0x30000000`).
    pub fn gbt_block_version(&self) -> i32 {
        let v = self.mining.block_version.load(Ordering::Relaxed);
        if v != 0 {
            v
        } else {
            0x3000_0000
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
        // Wtxid membership walks every transaction. Callers on a Tokio worker
        // enter a blocking region first.
        crate::reactor::assert_not_reactor("cmpct prefill");
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
    pub fn header_claimed_pow_ok(&self, header: &Header) -> bool {
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
    pub fn anti_dos_work_threshold(&self) -> Work {
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
            Some(min) => std::cmp::max(near, Work::from_be_bytes(min)),
            None => near,
        }
    }

    /// Compact/header whose claimed work is below the anti-DoS threshold.
    /// Unknown prev is not low-work (Core sends getheaders instead).
    pub fn header_below_anti_dos(&self, header: &Header) -> bool {
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
            Some(min) => {
                let work = match self.cached_chain_work() {
                    Some(w) => Ok(w),
                    None => self.chain_work(),
                };
                match work {
                    Ok(w) => w.to_be_bytes() >= min,
                    Err(_) => false,
                }
            }
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

    /// A follow session saw a block it does not have, while still in IBD.
    pub fn note_header_inv_challenge(&self) {
        self.header_inv_challenge.store(true, Ordering::Release);
    }

    /// Whether a follow-session block inv is waiting for the header walk.
    pub fn header_inv_challenge_pending(&self) -> bool {
        self.header_inv_challenge.load(Ordering::Acquire)
    }

    /// Clear a follow-session block inv once the walk has taken it.
    pub fn clear_header_inv_challenge(&self) {
        self.header_inv_challenge.store(false, Ordering::Release);
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

    #[doc(hidden)]
    pub fn ensure_genesis_inner(&self) -> Result<(), NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.tip_height().is_some() {
            return Ok(());
        }
        let genesis = genesis_block(&self.params);
        if genesis.block_hash() != self.params.genesis_hash {
            return Err(NetError::Protocol("genesis hash mismatch with params"));
        }
        self.connect_at(0, Arc::new(genesis), false)?;
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
    #[doc(hidden)]
    pub fn try_tip_hash(&self) -> Result<Option<BlockHash>, NetError> {
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
                .published_tip()
                .and_then(|p| (p.height == qh).then_some(BlockHash::from_byte_array(p.hash))),
            (None, Some(_)) => self.cache.tip_hash(),
            (None, None) => None,
        })
    }

    pub fn tip_header(&self) -> Option<Header> {
        let h = self.tip_height()?;
        self.query.wire_header_at_height(Height(h)).ok()
    }

    /// Tip, confirmed set, or the recent body cache already has `hash`.
    #[doc(hidden)]
    pub fn already_have(&self, hash: BlockHash) -> bool {
        self.tip_hash() == Some(hash) || self.has_block(&hash)
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
    /// The check is the published height index only. A lagging index is a
    /// miss, not a header-store walk.
    pub fn is_connected(&self, hash: &BlockHash) -> bool {
        self.query
            .published_height_of_hash(&hash.to_byte_array())
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
                    // `headers-only` and any other label share rank 0.
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

        for h in self.fork_tips.read().unwrap().iter() {
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
            if let Some(h) = path.hashes.last().copied() {
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

    #[doc(hidden)]
    pub fn held_path_has_body_gap(&self, tip: BlockHash) -> bool {
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
    pub fn prev_of(&self, hash: &BlockHash) -> Option<BlockHash> {
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

    #[doc(hidden)]
    pub fn header_ancestry_invalid(&self, tip: BlockHash) -> bool {
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
    #[doc(hidden)]
    pub fn side_height_and_branchlen(&self, tip: BlockHash) -> Option<(u32, u32)> {
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

    pub fn note_initial_getheaders_sent(&self) {
        self.initial_getheaders_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn initial_getheaders_sent(&self) -> u64 {
        self.initial_getheaders_sent.load(Ordering::Relaxed)
    }

    pub fn note_headers_reply(&self) {
        self.headers_replies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn headers_reply_count(&self) -> u64 {
        self.headers_replies.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn note_header_tip(&self, header: &Header) {
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
        if tips.contains(&hash) {
            tips.insert(hash, prev, height);
            return;
        }
        if tips.len() >= 128 {
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
        if let Some(h) = self.query.published_height_of_hash(&hash.to_byte_array()) {
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

    /// A block failed connect on a consensus rule. Unlike
    /// [`Self::note_invalid_block`], the mark survives restart; mutated bodies,
    /// a future timestamp, and store faults are not this.
    /// True when the mark is on disk.
    pub fn note_failed_connect(&self, hash: BlockHash) -> bool {
        self.note_invalid_block(hash);
        self.invalidated.keep_failed(hash)
    }

    /// Every kept connect failure is in `block.invalid` on disk.
    pub fn invalid_marks_on_disk(&self) -> bool {
        !self
            .invalidated
            .pending
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Every hash marked invalid, for a header scan that must not count them.
    pub fn invalid_blocks(&self) -> Vec<BlockHash> {
        self.invalidated
            .set
            .read()
            .unwrap()
            .iter()
            .copied()
            .collect()
    }

    /// A reconstructed compact with the right header hash and wrong txs must
    /// not poison later getdata of that hash.
    #[doc(hidden)]
    pub fn remember_failed_accept(&self, offered: BlockHash, e: &NetError) {
        if matches!(e, NetError::Consensus(m) if m == BLOCK_IS_INVALIDATED) {
            return;
        }
        let hash = e
            .failing_block_hash()
            .map(BlockHash::from_byte_array)
            .unwrap_or(offered);
        if e.is_mutated()
            || accept_err_is_temporary_time(e)
            || (self.query.trust_peer() && accept_err_is_warn_and_apply(e))
        {
            self.drop_held(hash);
            self.forget_asked_block(&hash);
            return;
        }
        if e.failing_block_hash().is_some() {
            let _ = self.note_failed_connect(hash);
            return;
        }
        if let NetError::Consensus(s) = e {
            if !s.to_ascii_lowercase().contains("not found") {
                let _ = self.note_failed_connect(hash);
            }
        }
    }

    /// True if we have a header row (best chain, header-only tip, or held body).
    /// Used so we never `getdata` a block inv whose header we have not seen.
    pub fn knows_header(&self, hash: &BlockHash) -> bool {
        // A header tip is written only after its header row, so the row covers it.
        self.is_connected(hash)
            || self
                .query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .is_some()
            || self.held_body(hash).is_some()
    }

    /// `ancestor` is `descendant` or lies on its prev walk (disconnected ok).
    pub fn is_header_ancestor(&self, ancestor: BlockHash, descendant: BlockHash) -> bool {
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

    /// Header for a cached, held, archived, or header-only hash.
    ///
    /// A cache hit is the stored body header. It does not rebuild the block.
    /// A miss builds the wire header from the header row, and only that row.
    pub fn header_of(&self, hash: &BlockHash) -> Option<bitcoin::block::Header> {
        HEADER_OF_N.with(|c| c.set(c.get().saturating_add(1)));
        if let Some(header) = self.cache.get_header(hash) {
            return Some(header);
        }
        if let Some(b) = self.load_side_body(hash) {
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
        // A header tip and a connected block both have a header row. The row
        // is the duplicate check.
        if self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(());
        }
        let prev = header.prev_blockhash;
        let prev_bytes = prev.to_byte_array();
        // Same for the parent, plus a body parked with no header row yet.
        // An all-zero parent is known only to genesis.
        let prev_known = (prev_bytes == [0u8; 32] && hash == self.params.genesis_hash)
            || self
                .query
                .get_header_by_hash(&prev_bytes)
                .ok()
                .flatten()
                .is_some()
            || self.held_body(&prev).is_some();
        if !prev_known {
            return Err("Must submit previous header".into());
        }
        if self.is_block_invalid(&prev) {
            return Err("bad-prevblk".into());
        }
        if let Some(ph) = self.query.height_of_hash(&prev_bytes).ok().flatten() {
            if let Ok(mtp) = rbitcoin_query::median_time_past(self.query.as_ref(), ph) {
                if header.time <= mtp {
                    return Err("time-too-old".into());
                }
            }
        }
        // A submitted header is local. The cell stays off, so the mode does not soften it.
        self.ensure_header(header).map_err(|e| e.to_string())
    }

    /// Like `ensure_header`, but returns the header fk for the archive writer
    /// (avoids a second hash-head probe on the hot write path).
    ///
    /// **Fail closed:** non-genesis headers require the parent row to already
    /// exist. Never write `prev_fk = NULL` for a missing parent (that created
    /// millions of orphan rows and false resume edges on mainnet).
    pub fn ensure_header_fk(&self, header: &Header) -> Result<Fk, NetError> {
        ENSURE_HEADER_FK_N.with(|c| c.set(c.get().saturating_add(1)));
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
        crate::reactor::assert_not_reactor("header persist");
        // Headers from the network. Flag-off does not write the cell.
        // A caller that already opted in (the recursive call) falls through.
        if self.query.trust_peer()
            && !rbitcoin_query::confirm_run::confirm_waive(self.query.as_ref())
        {
            return rbitcoin_query::confirm_run::waive_batch(true, || {
                self.ensure_headers_batch(headers)
            });
        }
        ENSURE_HEADERS_BATCH_N.with(|c| c.set(c.get().saturating_add(1)));
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
                remember_stored_header(&mut in_batch, hash, prev, fk, *header, || {
                    self.stored_header_height(&header.block_hash())
                });
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

    #[doc(hidden)]
    pub fn header_sync_prev_fk(
        &self,
        header: &Header,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Result<Fk, NetError> {
        let prev_bytes = header.prev_blockhash.to_byte_array();
        let prev_fk = if prev_bytes == [0u8; 32] {
            // Only genesis has no parent. Any other all-zero parent is
            // missing, as in Core, and gets no row.
            if header.block_hash() != self.params.genesis_hash {
                return Err(NetError::Consensus(
                    "header parent unknown — ensure parent before child".into(),
                ));
            }
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

    /// Off-tip header checks. `validate_header` is only for a confirmed parent,
    /// and that is the call which opens [`rbitcoin_consensus::TrustCollect`].
    #[allow(clippy::too_many_arguments)] // call-site args stay unbundled
    fn apply_off_tip_header(
        query: &rbitcoin_query::Query,
        params: &ChainParams,
        header: &Header,
        height: u32,
        mtp: u32,
        parent_time: u32,
        period_open_time: Option<u32>,
        expected: CompactTarget,
    ) -> Result<(), NetError> {
        soften_parent_header(query, header, height, || {
            validate_header_on_parent(
                params,
                Height(height),
                header,
                mtp,
                parent_time,
                period_open_time,
                expected,
            )
        })
        .map_err(|e| header_reject(header, &rbitcoin_query::ConfirmError::from(e)))
    }

    #[doc(hidden)]
    pub fn header_sync_contextual(
        &self,
        header: &Header,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Result<(), NetError> {
        #[cfg(debug_assertions)]
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
        let height = parent_height.saturating_add(1);
        let period_open = self.bip54_open_off_tip(&parent, parent_height, height, in_batch);
        // `validate_header` opens the collector, and it only runs for a confirmed parent.
        Self::apply_off_tip_header(
            self.query.as_ref(),
            &self.params,
            header,
            height,
            mtp,
            parent.time,
            period_open,
            expected,
        )
    }

    #[doc(hidden)]
    pub fn sync_parent_header(
        &self,
        hash: &BlockHash,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<Header> {
        if let Some(n) = in_batch.get(&hash.to_byte_array()) {
            return Some(n.header);
        }
        self.header_of(hash)
    }

    #[doc(hidden)]
    pub fn sync_parent_height(
        &self,
        hash: &BlockHash,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<u32> {
        if let Some(n) = in_batch.get(&hash.to_byte_array()) {
            return n.height;
        }
        self.stored_header_height(hash)
    }

    /// Height of a stored header, connected or not. Walks back to a known
    /// height (at most 10_000 headers).
    pub fn stored_header_height(&self, hash: &BlockHash) -> Option<u32> {
        if let Some(h) = self.header_height(hash) {
            return Some(h);
        }
        ancestor_walk(
            hash,
            10_000,
            |cur| {
                #[cfg(debug_assertions)]
                self.stored_height_walk_steps
                    .fetch_add(1, Ordering::Relaxed);
                self.header_of(cur)
            },
            |prev| self.header_height(prev),
        )
    }

    #[doc(hidden)]
    pub fn mtp_off_tip(
        &self,
        parent: &Header,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> u32 {
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

    #[doc(hidden)]
    pub fn expected_bits_off_tip(
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

    #[doc(hidden)]
    pub fn min_diff_off_tip(
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
            // Height 0 has no parent. Missing parent ends the walk below.
            let Some(p) = self.sync_parent_header(&hdr.prev_blockhash, in_batch) else {
                break;
            };
            hdr = p;
            h = h.saturating_sub(1);
            bits = hdr.bits;
        }
        bits
    }

    /// Timestamp of the period-open header when BIP 54 compares the last
    /// block of a difficulty period. `None` when that check is off.
    #[doc(hidden)]
    pub fn bip54_open_off_tip(
        &self,
        parent: &Header,
        parent_height: u32,
        height: u32,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<u32> {
        let open_h = self.params.bip54_period_open_height(height)?;
        self.header_along_off_tip(parent, parent_height, open_h, in_batch)
            .map(|header| header.time)
    }

    #[doc(hidden)]
    pub fn header_along_off_tip(
        &self,
        parent: &Header,
        parent_height: u32,
        want: u32,
        in_batch: &HashMap<[u8; 32], HeaderSyncNode>,
    ) -> Option<Header> {
        if want > parent_height {
            return None;
        }
        if want < parent_height {
            let mut hdr = *parent;
            let mut h = parent_height;
            while h > want {
                hdr = self.sync_parent_header(&hdr.prev_blockhash, in_batch)?;
                h = h.saturating_sub(1);
            }
            return Some(hdr);
        }
        Some(*parent)
    }

    /// Contiguous tip-extension slice for one-shot load (owned Block).
    #[doc(hidden)]
    pub fn confirm_wire_contig(
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
    ) -> Result<rbitcoin_query::ConfirmLoadOutcome, NetError> {
        consensus_load_from_plan(
            &self.query,
            &self.params,
            self.milestone,
            stamped,
            pipeline,
            &ScriptPreverified::new(),
        )
        .map_err(NetError::from_confirm)
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
    ) -> Result<Option<rbitcoin_query::ConfirmLoadOutcome>, NetError> {
        self.confirm_wire_load_phase_pipelined(blocks, None)
    }

    /// Load with optional pipeline caches (reserved create fks + in-flight creates).
    ///
    /// One-shot or pipelined load: lookup stamps then pin denserels by range.
    pub fn confirm_wire_load_phase_pipelined(
        &self,
        blocks: &[(Height, Block)],
        pipeline: Option<&WireLoadPipeline>,
    ) -> Result<Option<rbitcoin_query::ConfirmLoadOutcome>, NetError> {
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
        .map_err(NetError::from_confirm)?;
        Ok(Some(ok))
    }

    /// WRITE stage: structural + Class C + spend annotate (ordered).
    pub fn confirm_write(&self, batch: ScriptOkBatch) -> Result<Vec<AcceptOutcome>, NetError> {
        let headers = batch.wire_headers().map_err(NetError::from_confirm)?;
        let meta: Vec<(u32, BlockHash)> = batch
            .heights_hashes()
            .into_iter()
            .map(|(h, raw)| (h, BlockHash::from_byte_array(raw)))
            .collect();
        // Held across the write so the chain tip cannot move while the
        // relay-on purge is deciding which tip it stripped.
        let mp_hold = self.mempool().cloned();
        let mut template_hold = mp_hold.as_ref().map(|mp| mp.template_hold());
        confirm_write_phase(&self.query, &self.params, self.milestone, batch)
            .map_err(NetError::from_confirm)?;
        self.note_confirmed_tip_while(&meta, &headers, template_hold.as_mut())?;
        Ok(meta
            .iter()
            .map(|&(height, _)| AcceptOutcome::Accepted { height })
            .collect())
    }

    #[doc(hidden)]
    pub fn note_confirmed_tip(
        &self,
        need_meta: &[(u32, BlockHash)],
        headers: &[Header],
    ) -> Result<(), NetError> {
        self.note_confirmed_tip_while(need_meta, headers, None)
    }

    #[doc(hidden)]
    pub fn note_confirmed_tip_while(
        &self,
        need_meta: &[(u32, BlockHash)],
        headers: &[Header],
        mut hold: Option<&mut crate::tx_relay::TemplateHold<'_>>,
    ) -> Result<(), NetError> {
        if headers.len() != need_meta.len() {
            return Err(NetError::store(rbitcoin_store::StoreError::Corrupt(
                "invariant: wire headers length",
            )));
        }
        if let Some(mp) = self.mempool() {
            mp.clear_recent_rejects();
            let mut stripped: Option<[u8; 32]> = None;
            if mp.relay_enabled() {
                for &(height, hash) in need_meta {
                    mp.note_block_fee_history(Height(height));
                    let Ok(Some(block)) =
                        self.query.reconstruct_block_by_hash(&hash.to_byte_array())
                    else {
                        break;
                    };
                    mp.note_recent_confirmed(&block.txdata);
                    let ids: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
                    let spent = spent_outpoints(&block.txdata);
                    let n = mp.remove_for_block_spent(&ids, &spent);
                    rbitcoin_log::debug!("mempool: removed {n} confirmed tx(s) @ {hash}");
                    stripped = Some(hash.to_byte_array());
                }
            }
            if let Some(hash) = stripped {
                if let Some(hold) = hold.as_mut() {
                    hold.commit(hash);
                } else {
                    mp.note_template_prev(hash);
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
    #[doc(hidden)]
    pub fn generate_block_time(&self, tip_h: u32, tip_time: u32) -> u32 {
        let now = self.clock.now_secs() as u32;
        let mtp = rbitcoin_query::median_time_past(self.query.as_ref(), Height(tip_h))
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
    #[doc(hidden)]
    pub fn mine_paying_block(
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

    /// One `generate` call refuses more than this many blocks.
    #[doc(hidden)]
    pub const GENERATE_MAX_BLOCKS: u32 = 10_000;

    /// Mine `nblocks` paying `script_pubkey` and accept each via [`Self::accept_block`].
    ///
    /// Regtest harness only. Extra txs go in the first block. Ensures genesis.
    /// More than [`Self::GENERATE_MAX_BLOCKS`] is refused before any block is mined.
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
        self.generate_paying(
            nblocks,
            script_pubkey,
            extra_txs,
            Self::GENERATE_MAX_BLOCKS,
            false,
        )
    }

    /// RPC `generate` / `generateblock`. Same mine as [`Self::generate_to_script`],
    /// and the pool txids in an accepted block are removed before the next
    /// block of this call is mined. A relay-off connect does not remove them.
    #[doc(hidden)]
    pub fn generate_to_script_for_rpc(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, NetError> {
        self.generate_paying(
            nblocks,
            script_pubkey,
            extra_txs,
            Self::GENERATE_MAX_BLOCKS,
            true,
        )
    }

    /// [`Self::generate_to_script`] with an explicit cap. Production passes
    /// [`Self::GENERATE_MAX_BLOCKS`]. Tests pass a small cap so the same
    /// comparison is pinned without mining ten thousand blocks.
    #[doc(hidden)]
    pub fn generate_to_script_limited(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
        limit: u32,
    ) -> Result<Vec<BlockHash>, NetError> {
        self.generate_paying(nblocks, script_pubkey, extra_txs, limit, false)
    }

    fn generate_paying(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
        limit: u32,
        commit_on_accept: bool,
    ) -> Result<Vec<BlockHash>, NetError> {
        if nblocks == 0 {
            return Ok(Vec::new());
        }
        if nblocks > limit {
            return Err(NetError::Consensus(format!(
                "nblocks too large (max {limit})"
            )));
        }
        self.ensure_genesis()?;
        // Serialize tip-read + mine + accept so concurrent generateblock
        // (rpc_generate.py parallel) cannot race the same tip into AlreadyHave.
        let _guard = self.generate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut hashes = Vec::with_capacity(nblocks as usize);
        let mut extras = extra_txs;
        for i in 0..nblocks {
            let stop = self.generate_fail_before.load(Ordering::Relaxed);
            if stop > 0 && i == stop {
                return Err(NetError::Consensus(
                    "generate lost the tip during proof-of-work".into(),
                ));
            }
            let txs = if i == 0 {
                std::mem::take(&mut extras)
            } else {
                Vec::new()
            };
            let ids = commit_on_accept.then(|| {
                txs.iter()
                    .map(|tx| tx.compute_txid())
                    .collect::<Vec<Txid>>()
            });
            hashes.push(self.mine_and_accept_paying(script_pubkey.clone(), txs)?);
            if let Some(ids) = ids.filter(|ids| !ids.is_empty()) {
                let Some(mp) = self.mempool() else {
                    continue;
                };
                mp.commit_generated_txids(&ids)
                    .map_err(|e| NetError::Consensus(e.to_string()))?;
            }
        }
        if let Err(e) = self.query.apply_sh_pending() {
            rbitcoin_log::warn!("generate: SH write-behind drain: {e}");
        }
        if let Err(e) = rbitcoin_query::build_indexes_released(&self.query) {
            rbitcoin_log::warn!("generate: index write-behind drain: {e}");
        }
        Ok(hashes)
    }

    /// Mine one block on this thread, then accept it on `tip-accept`.
    #[doc(hidden)]
    pub fn mine_and_accept_paying(
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

    #[doc(hidden)]
    pub fn invalidate_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
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
                self.invalidated.paths.write().unwrap().push(InvalidPath {
                    hashes: path,
                    connected: true,
                });
            }
            let keep = h.0.saturating_sub(1);
            self.disconnect_to(keep)?;
            drop(_guard);
        } else if self.knows_header(&hash) || self.held_body(&hash).is_some() {
            // Side-branch / held header (feature_chain_tiebreaks B10): mark
            // invalid without a tip disconnect.
            self.invalidated.set.write().unwrap().insert(hash);
            self.drop_held(hash);
            self.invalidated.paths.write().unwrap().push(InvalidPath {
                hashes: vec![hash],
                connected: false,
            });
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
    #[doc(hidden)]
    pub fn try_apply_after_invalidate(&self) -> Result<Option<AcceptOutcome>, NetError> {
        let none = HashSet::new();
        let Some(branch) = self.most_work_branch(self.side_branches(&[], &none, &none), &mut None)
        else {
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

    /// Clear the invalid mark on `hash`, its invalidated paths, and ancestors,
    /// then activate the most-work chain. Header-only descendants stay header
    /// tips.
    pub fn reconsider_block(&self, hash: BlockHash) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.reconsider_block_inner(hash))
    }

    #[doc(hidden)]
    pub fn reconsider_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        // Connected, header-only, and invalidated blocks have a header row.
        // A parked body may not.
        let known = self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()
            .is_some()
            || self.load_side_body(&hash).is_some();
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
            // The zero parent has no header row. The next `prev_of` ends the walk.
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
                for h in &path.hashes {
                    inv.remove(h);
                }
            }
            for h in &related {
                inv.remove(h);
            }
        }
        self.invalidated.prune_failed();

        let restored: HashSet<BlockHash> = paths
            .iter()
            .flat_map(|p| p.hashes.iter().copied())
            .collect();
        let validated: HashSet<BlockHash> = paths
            .iter()
            .filter(|p| p.connected)
            .flat_map(|p| p.hashes.iter().copied())
            .collect();
        let mut leaves: Vec<BlockHash> = paths
            .iter()
            .filter_map(|p| p.hashes.last().copied())
            .collect();
        leaves.push(hash);
        self.apply_after_reconsider(&leaves, &restored, &validated)
    }

    /// Core `ActivateBestChain` after `reconsiderblock`: connect the most-work
    /// side branch, and try the next one when a block fails. Then keep the
    /// restored leaves that lost as fork tips.
    fn apply_after_reconsider(
        &self,
        leaves: &[BlockHash],
        restored: &HashSet<BlockHash>,
        validated: &HashSet<BlockHash>,
    ) -> Result<(), NetError> {
        // A failed tip may stay a candidate (a time reject is not a mark), so
        // each tip is tried once.
        let mut tried = HashSet::new();
        let mut fault = None;
        loop {
            let untried = self.side_branches(leaves, restored, &tried);
            let Some(branch) = self.most_work_branch(untried, &mut fault) else {
                break;
            };
            let branch_tip = branch[branch.len() - 1].block_hash();
            tried.insert(branch_tip);
            let attempt = {
                let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
                self.accept_branch_prefix(&branch)
            };
            match attempt {
                Ok((AcceptOutcome::Accepted { .. }, Some(_))) => {}
                Ok(_) => break,
                Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => {}
                Err(e) if e.is_local_fault() => {
                    fault.get_or_insert(e);
                    break;
                }
                Err(e) => self.remember_failed_accept(branch_tip, &e),
            }
        }
        // The paths that named these leaves are gone, so park before a fault
        // is returned.
        self.park_restored_leaves(leaves, restored, validated);
        fault.map_or(Ok(()), Err)
    }

    /// Keep each restored leaf that is still a side tip as a fork tip, so a
    /// later `invalidateblock` can return to it. Every block to it must have
    /// been connected before: it came off the active chain, or it is at or
    /// under a fork tip. A leaf under a fork tip or another kept leaf is not a
    /// tip. A held child that never connected does not hide it.
    fn park_restored_leaves(
        &self,
        leaves: &[BlockHash],
        restored: &HashSet<BlockHash>,
        validated: &HashSet<BlockHash>,
    ) {
        let forks: HashSet<BlockHash> = self.fork_tips.read().unwrap().iter().collect();
        let mut under_valid = HashSet::new();
        let mut kept = Vec::new();
        for branch in self.side_branches(leaves, restored, &HashSet::new()) {
            let hashes: Vec<BlockHash> = branch.iter().map(Block::block_hash).collect();
            let (tip, below) = hashes.split_last().expect("a side branch is not empty");
            let was_connected = hashes
                .iter()
                .rev()
                .take_while(|h| !forks.contains(*h))
                .all(|h| validated.contains(h));
            let keep = leaves.contains(tip) && was_connected;
            if keep {
                kept.push(*tip);
            }
            if keep || forks.contains(tip) {
                under_valid.extend(below.iter().copied());
            }
        }
        let mut forks = self.fork_tips.write().unwrap();
        for tip in kept {
            if !under_valid.contains(&tip) {
                forks.insert(tip);
            }
        }
    }

    /// Side branches to fork tips, held bodies, precious, and `leaves`, built
    /// one at a time. A branch through an invalid block is left out, and so
    /// is a tip in `skip`.
    fn side_branches<'a>(
        &'a self,
        leaves: &[BlockHash],
        restored: &'a HashSet<BlockHash>,
        skip: &HashSet<BlockHash>,
    ) -> impl Iterator<Item = Vec<Block>> + 'a {
        let inv = self.invalidated.set.read().unwrap().clone();
        let mut starts: Vec<BlockHash> = self.fork_tips.read().unwrap().iter().collect();
        starts.extend(self.held_bodies.read().unwrap().keys());
        starts.extend(*self.precious.read().unwrap());
        starts.extend(leaves.iter().copied());
        let mut seen = HashSet::new();
        starts.retain(|s| seen.insert(*s) && !inv.contains(s) && !skip.contains(s));
        starts
            .into_iter()
            .filter_map(move |s| self.assemble_side_branch(s, restored))
            .filter(move |br| !br.iter().any(|b| inv.contains(&b.block_hash())))
    }

    /// The branch with the most total chain work, as in Core's
    /// `CBlockIndexWorkComparator`. Equal work prefers the precious tip, then
    /// the first-seen held tip. A branch whose work cannot be summed is
    /// skipped. The first store fault among those is kept in `fault`.
    fn most_work_branch(
        &self,
        branches: impl Iterator<Item = Vec<Block>>,
        fault: &mut Option<NetError>,
    ) -> Option<Vec<Block>> {
        let precious = *self.precious.read().unwrap();
        let mut best: Option<(Work, bool, u64, Vec<Block>)> = None;
        for branch in branches {
            let w = match self.branch_chain_work(&branch) {
                Ok(w) => w,
                Err(e) => {
                    if e.is_local_fault() && fault.is_none() {
                        *fault = Some(e);
                    }
                    continue;
                }
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

    #[doc(hidden)]
    pub fn take_related_invalidated_paths(
        &self,
        hash: BlockHash,
        related: &HashSet<BlockHash>,
    ) -> Vec<InvalidPath> {
        let mut g = self.invalidated.paths.write().unwrap();
        let mut taken = Vec::new();
        let mut seeds = related.clone();
        seeds.insert(hash);
        loop {
            let before = taken.len();
            g.retain(|p| {
                let hit = p.hashes.iter().any(|h| seeds.contains(h))
                    || p.hashes
                        .first()
                        .is_some_and(|h| self.prev_of(h).is_some_and(|prev| seeds.contains(&prev)));
                if hit {
                    for h in &p.hashes {
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

    #[doc(hidden)]
    pub fn precious_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        if self.is_block_invalid(&hash) {
            return Ok(());
        }
        let branch = self.assemble_side_branch(hash, &HashSet::new());
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
        crate::tip_accept::run_on_tip_accept(|| self.accept_incoming(Arc::new(block), false, false))
    }

    #[doc(hidden)]
    pub fn accept_block_inner(&self, block: Arc<Block>) -> Result<AcceptOutcome, NetError> {
        self.accept_incoming(block, false, false)
    }

    #[doc(hidden)]
    pub fn accept_incoming(
        &self,
        block: Arc<Block>,
        hold_unconnected: bool,
        waive: bool,
    ) -> Result<AcceptOutcome, NetError> {
        let hash = block.block_hash();
        if self.already_have(hash) {
            return Ok(AcceptOutcome::AlreadyHave);
        }
        if self.invalidated.set.read().unwrap().contains(&hash) {
            return Err(NetError::Consensus(BLOCK_IS_INVALIDATED.into()));
        }
        if rbitcoin_consensus::block_mutated_without_coinbase(&block) {
            return Err(NetError::Mutated(
                "bad-cb-missing, 64-byte transaction".into(),
            ));
        }

        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Same hash already tip/confirmed (or won a concurrent accept): drop —
        // do not plan Class A or assign create fks a second time (I4).
        if self.already_have(hash) {
            return Ok(AcceptOutcome::AlreadyHave);
        }

        let prev = block.header.prev_blockhash;
        match self.tip_height() {
            None => {
                if prev.to_byte_array() != [0u8; 32] {
                    return Err(NetError::Protocol("non-genesis without tip"));
                }
                self.connect_at(0, block, waive)?;
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
                    self.connect_at(height, block, waive)?;
                    return Ok(AcceptOutcome::Accepted { height });
                }

                let Some(parent_h) = self
                    .query
                    .height_of_hash(&prev.to_byte_array())
                    .map_err(NetError::store)?
                else {
                    if hold_unconnected {
                        self.hold_body(block, waive);
                    }
                    return Err(NetError::UnknownParent);
                };

                let new_height = parent_h.0.saturating_add(1);
                // The tip path waives inside `connect_at`. This is the side
                // block, and it uses the same session bit. Proof-of-work and
                // bad nBits stay errors because they are not on the warn list.
                rbitcoin_query::confirm_run::waive_batch(waive, || {
                    validate_header(
                        self.query.as_ref(),
                        &self.params,
                        Height(new_height),
                        &block.header,
                    )
                })
                .map_err(|e| header_reject(&block.header, &e))?;

                if new_height == tip_h {
                    // Park before the branch attempt so connect reads this
                    // session bit. Only an equal-work loser stays parked.
                    let hash = block.block_hash();
                    let already =
                        hold_unconnected && self.held_bodies.read().unwrap().contains(&hash);
                    if hold_unconnected {
                        // Re-hold so a trusted session can set the waive bit.
                        self.hold_body(Arc::clone(&block), waive);
                    }
                    let out = self.accept_branch_locked(std::slice::from_ref(block.as_ref()));
                    if hold_unconnected
                        && !already
                        && !matches!(out, Ok(AcceptOutcome::IgnoredWeaker))
                    {
                        self.drop_held(hash);
                    }
                    return out;
                }

                if hold_unconnected {
                    self.hold_body(block, waive);
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

    #[doc(hidden)]
    pub fn accept_branch_inner(&self, blocks: &[Block]) -> Result<AcceptOutcome, NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.accept_branch_locked(blocks)
    }

    /// Err when any block of `blocks` fails connect, even when a heavier
    /// valid prefix stays the tip.
    #[doc(hidden)]
    pub fn accept_branch_locked(&self, blocks: &[Block]) -> Result<AcceptOutcome, NetError> {
        let (out, failed) = self.accept_branch_prefix(blocks)?;
        failed.map_or(Ok(out), Err)
    }

    /// [`Self::accept_branch_locked`] that also reports a kept prefix: when a
    /// block fails after a heavier valid prefix connected, that prefix stays
    /// the tip and the failure is returned beside `Accepted`.
    #[doc(hidden)]
    pub fn accept_branch_prefix(
        &self,
        blocks: &[Block],
    ) -> Result<(AcceptOutcome, Option<NetError>), NetError> {
        self.accept_branch_precheck(blocks)?;
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

    #[doc(hidden)]
    pub fn accept_branch_precheck(&self, blocks: &[Block]) -> Result<(), NetError> {
        if blocks.is_empty() {
            return Err(NetError::Protocol("empty branch"));
        }
        if blocks
            .iter()
            .any(|b| self.is_block_invalid(&b.block_hash()))
        {
            return Err(NetError::Consensus(BLOCK_IS_INVALIDATED.into()));
        }
        for w in blocks.windows(2) {
            if w[1].header.prev_blockhash != w[0].block_hash() {
                return Err(NetError::Protocol("branch not linked"));
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn accept_branch_fork_height(&self, blocks: &[Block]) -> Result<Option<u32>, NetError> {
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

    #[doc(hidden)]
    pub fn branch_header_work(&self, blocks: &[Block]) -> Result<Work, NetError> {
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
    #[doc(hidden)]
    pub fn branch_chain_work(&self, blocks: &[Block]) -> Result<Work, NetError> {
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

    #[doc(hidden)]
    pub fn accept_branch_weaker(&self, blocks: &[Block], old_work: Work) -> Result<bool, NetError> {
        let new_work = self.branch_header_work(blocks)?;
        let branch_tip = blocks.last().map(Block::block_hash);
        let precious = *self.precious.read().unwrap() == branch_tip;
        let equal_work = !work_better(new_work, old_work) && !work_better(old_work, new_work);
        Ok(self.tip_height().is_some()
            && !work_better(new_work, old_work)
            && !(precious && equal_work))
    }

    #[doc(hidden)]
    pub fn accept_branch_collect_old(
        &self,
        fork_height: Option<u32>,
    ) -> Result<Vec<Block>, NetError> {
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
    #[doc(hidden)]
    pub fn accept_branch_check_headers(
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
            let hash = b.block_hash();
            let checked =
                rbitcoin_query::confirm_run::waive_batch(self.waive_for_connect(&hash), || {
                    if i == 0 {
                        validate_header(
                            self.query.as_ref(),
                            &self.params,
                            Height(height),
                            &b.header,
                        )
                        .map_err(|e| header_reject(&b.header, &e))
                    } else {
                        let parent = &blocks[i - 1].header;
                        let parent_height = height.saturating_sub(1);
                        let mtp = self.mtp_off_tip(parent, &batch);
                        let expected =
                            self.expected_bits_off_tip(&b.header, parent, parent_height, &batch)?;
                        let period_open =
                            self.bip54_open_off_tip(parent, parent_height, height, &batch);
                        soften_parent_header(self.query.as_ref(), &b.header, height, || {
                            validate_header_on_parent(
                                &self.params,
                                Height(height),
                                &b.header,
                                mtp,
                                parent.time,
                                period_open,
                                expected,
                            )
                        })
                        .map_err(|e| {
                            header_reject(&b.header, &rbitcoin_query::ConfirmError::from(e))
                        })
                    }
                });
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

    #[doc(hidden)]
    pub fn accept_branch_disconnect(&self, fork_height: Option<u32>) -> Result<(), NetError> {
        if let Some(fh) = fork_height {
            self.disconnect_to(fh)?;
        } else {
            let _commit = self
                .query
                .lock_tip_commit()
                .map_err(|e| NetError::Store(e.to_string()))?;
            while self.query.tip_height().is_some() {
                if let Some(th) = self.tip_hash() {
                    self.confirmed.write().unwrap().remove(&th);
                }
                self.query
                    .disconnect_tip_in_commit()
                    .map_err(NetError::store)?;
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
    #[doc(hidden)]
    pub fn accept_branch_connect<'b>(
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
            let Err(e) = self.connect_at(
                base + i as u32,
                Arc::new(b.clone()),
                self.waive_for_connect(&b.block_hash()),
            ) else {
                continue;
            };
            self.announce_reorg_len.store(0, Ordering::Relaxed);
            if e.is_local_fault() {
                self.accept_branch_restore(fork_height, old_path, &e)?;
                return Err(e);
            }
            // `ConnectFailed` displays its own "consensus: " prefix.
            let msg = match &e {
                NetError::Consensus(m) | NetError::Mutated(m) => m.clone(),
                other => other.to_string(),
            };
            let failed = NetError::ConnectFailed {
                hash: b.block_hash().to_byte_array(),
                msg,
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
    #[doc(hidden)]
    pub fn accept_branch_restore(
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
            // These blocks were our chain. Disconnect already dropped them
            // from `confirmed`, so the mode bit is the restore waive.
            // Flag-off stays strict. No second set.
            if let Err(re) = self.connect_at(
                fh + 1 + j as u32,
                Arc::new(ob.clone()),
                self.query.trust_peer(),
            ) {
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
        crate::tip_accept::run_on_tip_accept(|| self.rewind_to_height_inner(keep_height, true))
            .map(|_| ())
    }

    /// Disconnect down to `keep_height`, or return `Ok(false)` when a tip
    /// flush already holds the commit. The caller retries; this does not wait
    /// on that disk.
    pub fn try_rewind_to_height(&self, keep_height: u32) -> Result<bool, NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.rewind_to_height_inner(keep_height, false))
    }

    #[doc(hidden)]
    pub fn rewind_to_height_inner(&self, keep_height: u32, wait: bool) -> Result<bool, NetError> {
        let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
        let tip = self.tip_height().unwrap_or(0);
        if keep_height > tip {
            return Err(NetError::Protocol("rewind above tip"));
        }
        // Before the commit lock, same order as `disconnect_to`. This rewind
        // already holds that lock, so it cannot call `disconnect_to`, and the
        // mark would stay on the block that was just disconnected.
        let mp_hold = self.mempool().cloned();
        let mut template_hold = mp_hold.as_ref().map(|mp| mp.template_hold());
        let _commit = if wait {
            self.query
                .lock_tip_commit()
                .map_err(|e| NetError::Store(e.to_string()))?
        } else if let Some(g) = self.query.try_lock_tip_commit() {
            g
        } else {
            return Ok(false);
        };
        self.disconnect_to_in_commit(keep_height)?;
        if let Some(hold) = template_hold.as_mut() {
            if let Ok(Some((_, rec))) = self.query.header_at_height(Height(keep_height)) {
                hold.commit(rec.hash);
            }
        }
        drop(template_hold);
        Ok(true)
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
        crate::tip_accept::run_on_tip_accept(|| self.accept_received_block_inner(block, false))
    }

    #[doc(hidden)]
    pub fn accept_received_block_inner(
        &self,
        block: Block,
        waive: bool,
    ) -> Result<AcceptOutcome, NetError> {
        let hash = block.block_hash();
        let block = Arc::new(block);
        match self.accept_incoming(block, true, waive) {
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
    #[doc(hidden)]
    pub fn apply_held_for(&self, offered: BlockHash) -> Result<Option<AcceptOutcome>, NetError> {
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
    pub fn into_arc(self) -> Arc<Self> {
        let arc = Arc::new(self);
        let _ = arc.self_weak.set(Arc::downgrade(&arc));
        arc
    }

    /// `Some` after [`Self::into_arc`]. The clone keeps the hub alive for a
    /// tip job whose session future was dropped.
    pub fn shared_arc(&self) -> Option<Arc<Self>> {
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
        crate::tip_accept::run_on_tip_accept_async(move || {
            hub.accept_received_block_inner(block, false)
        })
        .await
    }

    pub fn accept_received_on_lane(
        &self,
        block: Block,
        waive: bool,
    ) -> Result<AcceptOutcome, NetError> {
        self.accept_received_block_inner(block, waive)
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

    #[doc(hidden)]
    pub fn held_body_height(&self, block: &Block) -> Option<u32> {
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

    #[doc(hidden)]
    pub fn trim_held_bodies(&self, tip: u32) {
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

    #[doc(hidden)]
    pub fn drop_held(&self, hash: BlockHash) {
        self.held_bodies.write().unwrap().remove(&hash);
    }

    /// Park a disconnected body without running [`Self::try_apply_held`].
    /// Reorg and reconsider callers revalidate strictly.
    pub fn hold_unconnected_body(&self, block: Block) {
        self.hold_body(Arc::new(block), false);
    }

    #[doc(hidden)]
    pub fn hold_body(&self, block: Arc<Block>, waive: bool) {
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
        self.held_bodies
            .write()
            .unwrap()
            .insert(block, &keep, waive);
    }

    /// Waive only a body this session held. Flag-off returns before any lock.
    /// Restoring our own chain uses the mode bit at the restore call.
    #[doc(hidden)]
    pub fn waive_for_connect(&self, hash: &BlockHash) -> bool {
        if !self.query.trust_peer() {
            return false;
        }
        self.held_bodies.read().unwrap().waive(hash)
    }

    /// Never-confirmed side-branch body in RAM. Once-confirmed disconnected
    /// blocks are reconstructed from Class A — they are not held here.
    pub fn held_body(&self, hash: &BlockHash) -> Option<Block> {
        self.held_bodies.read().unwrap().get(hash).cloned()
    }

    pub fn cache_body_count(&self) -> usize {
        self.cache.stored_bodies()
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

    #[doc(hidden)]
    pub fn load_side_body(&self, hash: &BlockHash) -> Option<Block> {
        if let Some(b) = self.held_body(hash) {
            return Some(b);
        }
        self.query
            .reconstruct_archived_block(&hash.to_byte_array())
            .ok()
            .flatten()
    }

    /// Walk hold + archive from `tip` back to a best-chain parent. The walk
    /// gives up after 10,000 blocks outside `restored`. `invalidateblock`
    /// recorded the restored ones, so any number of those is walked.
    #[doc(hidden)]
    pub fn assemble_side_branch(
        &self,
        tip: BlockHash,
        restored: &HashSet<BlockHash>,
    ) -> Option<Vec<Block>> {
        if self.is_connected(&tip) {
            return None;
        }
        let mut rev = Vec::new();
        let mut h = tip;
        let mut unrecorded = 0u32;
        loop {
            if !restored.contains(&h) {
                unrecorded += 1;
                if unrecorded > 10_000 {
                    return None;
                }
            }
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
    }

    /// The held (or archived) branch with the most total chain work, as in
    /// Core's `CBlockIndexWorkComparator`. Equal work prefers the precious
    /// tip, then the first-seen held tip.
    #[doc(hidden)]
    pub fn best_held_branch(&self) -> Option<Vec<Block>> {
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
            let Some(branch) = self.assemble_side_branch(start, &HashSet::new()) else {
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
    #[doc(hidden)]
    pub fn try_apply_held(
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

    #[doc(hidden)]
    pub fn strip_txids_from_pres(pres: &[rbitcoin_query::TxPrecompute]) -> Vec<Txid> {
        pres.iter().map(|p| Txid::from_byte_array(p.txid)).collect()
    }

    #[doc(hidden)]
    pub fn connect_at(&self, height: u32, block: Arc<Block>, waive: bool) -> Result<(), NetError> {
        debug_assert!(
            crate::tip_accept::on_tip_accept_thread(),
            "connect_at must run on tip-accept"
        );
        // Held until this connect returns, so a template cannot observe the
        // new query tip before the pool strip is recorded.
        let mp_hold = self.mempool().cloned();
        let mut template_hold = mp_hold.as_ref().map(|mp| mp.template_hold());
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
                match rbitcoin_query::confirm_run::waive_batch(waive, || {
                    accept_and_connect_block_preverified(
                        &self.query,
                        &self.params,
                        Height(height),
                        Arc::clone(&block),
                        self.milestone,
                        &preverified,
                        Some(std::sync::Arc::clone(&pres)),
                    )
                }) {
                    Ok(fk) => return Ok(fk),
                    Err(e) if e.is_uring_session_fault() => {
                        self.query.uring_recover_or_abort("tip-connect");
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            })
            .map_err(|e| match e {
                e if e.is_cancelled() => NetError::Cancelled,
                rbitcoin_query::ConfirmError::Rules(
                    rbitcoin_consensus::ConsensusError::Internal(m),
                ) => {
                    rbitcoin_log::warn!("tip connect {hash} @ {height}: pipeline fault: {m}");
                    NetError::store(m)
                }
                rbitcoin_query::ConfirmError::Rules(e) => {
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
                rbitcoin_query::ConfirmError::Store(se) => {
                    rbitcoin_log::warn!("tip connect {hash} @ {height}: store fault: {se}");
                    NetError::store(se)
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
            let spent = spent_outpoints(&block.txdata);
            let n = mp.remove_for_block_spent(&ids, &spent);
            rbitcoin_log::debug!("mempool: removed {n} confirmed tx(s) @ height {height}");
            if mp.relay_enabled() {
                mp.note_block_fee_history(Height(height));
                if let Some(hold) = template_hold.as_mut() {
                    hold.commit(hash.to_byte_array());
                }
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
        // Record the stripped tip before the announcement, so a builder that
        // wakes on this event already sees the new mark.
        drop(template_hold);
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

    #[doc(hidden)]
    pub fn disconnect_to(&self, keep_height: u32) -> Result<(), NetError> {
        // Before the commit lock: the relay-on purge takes this same mutex
        // and then reads the query. The pool matches `keep_height` once the
        // disconnected transactions are back in it.
        let mp_hold = self.mempool().cloned();
        let mut template_hold = mp_hold.as_ref().map(|mp| mp.template_hold());
        let _commit = self
            .query
            .lock_tip_commit()
            .map_err(|e| NetError::Store(e.to_string()))?;
        self.disconnect_to_in_commit(keep_height)?;
        if let Some(hold) = template_hold.as_mut() {
            if let Ok(Some((_, rec))) = self.query.header_at_height(Height(keep_height)) {
                hold.commit(rec.hash);
            }
        }
        drop(template_hold);
        Ok(())
    }

    #[doc(hidden)]
    pub fn disconnect_to_in_commit(&self, keep_height: u32) -> Result<(), NetError> {
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
                .disconnect_tip_keep_pending_in_commit()
                .map_err(NetError::store)?;
        }
        self.cache.truncate_to_height(keep_height);
        if let Some(mp) = mp {
            mp.clear_recent_confirmed();
            if !disconnected_txs.is_empty() {
                let n = mp.reorg_reaccept(&disconnected_txs);
                rbitcoin_log::debug!(
                    "mempool: re-accepted {n}/{} tx(s) after reorg disconnect to {keep_height}",
                    disconnected_txs.len()
                );
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

    #[cfg(debug_assertions)]
    pub fn test_chain_work_prefix_len(&self) -> usize {
        self.chain_work_prefix.read().unwrap().len()
    }

    #[cfg(debug_assertions)]
    pub fn reset_block_at_height_calls(&self) {
        self.block_at_height_calls.store(0, Ordering::Relaxed);
    }

    #[cfg(debug_assertions)]
    pub fn block_at_height_calls(&self) -> u64 {
        self.block_at_height_calls.load(Ordering::Relaxed)
    }

    #[cfg(debug_assertions)]
    pub fn take_header_contextual_checks(&self) -> u64 {
        self.header_contextual_checks.swap(0, Ordering::Relaxed)
    }

    #[cfg(debug_assertions)]
    pub fn take_stored_height_walk_steps(&self) -> u64 {
        self.stored_height_walk_steps.swap(0, Ordering::Relaxed)
    }

    #[cfg(debug_assertions)]
    pub fn test_clear_chain_work_prefix(&self) {
        self.chain_work_prefix.write().unwrap().clear();
    }

    #[doc(hidden)]
    pub fn block_at_height(&self, height: u32) -> Result<Option<Block>, NetError> {
        #[cfg(debug_assertions)]
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
        CHAIN_WORK_N.with(|c| c.set(c.get().saturating_add(1)));
        self.work_from_fork_to_tip(None)
    }

    /// Tip work when the in-memory prefix already covers the tip.
    ///
    /// `None` means the prefix is cold. Callers that must not touch the header
    /// store use this instead of [`Self::chain_work`].
    pub fn cached_chain_work(&self) -> Option<Work> {
        let Some(tip) = self.tip_height() else {
            return Some(Work::from_be_bytes([0u8; 32]));
        };
        let prefix = self.chain_work_prefix.read().unwrap();
        if prefix.len() == tip as usize + 1 {
            prefix.last().copied()
        } else {
            None
        }
    }

    /// Sum wire-header work on the best chain from `fork_height+1` through tip.
    ///
    /// `fork_height = None` means from genesis (height 0) through tip.
    /// Empty tip → zero work.
    #[doc(hidden)]
    pub fn work_from_fork_to_tip(&self, fork_height: Option<u32>) -> Result<Work, NetError> {
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

    #[doc(hidden)]
    pub fn ensure_chain_work_prefix(&self) -> Result<(), NetError> {
        let Some(tip) = self.tip_height() else {
            self.chain_work_prefix.write().unwrap().clear();
            return Ok(());
        };
        let want = tip as usize + 1;
        let mut p = self.chain_work_prefix.write().unwrap();
        p.truncate(want);
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
    #[doc(hidden)]
    pub fn fill_chain_work_from_header_body(
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

    #[doc(hidden)]
    pub fn header_work_at_height(&self, h: u32) -> Result<Work, NetError> {
        let (_, rec) = self
            .query
            .header_at_height(Height(h))
            .map_err(NetError::store)?
            .ok_or_else(|| NetError::store(rbitcoin_store::StoreError::NotFound))?;
        Ok(header_work_bits(rec.bits))
    }
}

#[doc(hidden)]
pub fn header_work_bits(bits: u32) -> Work {
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
        rbitcoin_query::expected_next_bits(query, params, Height(height), block.header.time)
            .map(|c| c.to_consensus())
            .unwrap_or(tip_rec.bits);
    let mtp = rbitcoin_query::median_time_past_store(query, tip_h).map_err(|e| e.to_string())?;
    let header = ProposalHeader {
        block,
        height,
        expected_bits: expected,
        mtp,
        now,
    };
    proposal_header_checks(params, header)?;
    let vctx = rbitcoin_consensus::ValidationContext::at(params, Height(height), milestone);
    if let Err(e) = rbitcoin_consensus::validate_block_structure(block, &vctx) {
        return Err(rbitcoin_consensus::block_reject_reason(&e));
    }
    let lock_time_cutoff = rbitcoin_query::assemble_lock_time_cutoff(&vctx, block, mtp);
    let (fees, prevouts) = proposal_connect(query, params, block, height, mtp, lock_time_cutoff)?;
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
        if sigops > rbitcoin_consensus::block::MAX_BLOCK_SIGOPS_COST {
            return Err("bad-blk-sigops".into());
        }
        if let Err(e) = rbitcoin_consensus::verify_tx_scripts_with_flags(ins, tx.clone(), flags) {
            return Err(rbitcoin_consensus::block_reject_reason(&e));
        }
    }
    Ok(fees)
}

struct ProposalHeader<'a> {
    block: &'a Block,
    height: u32,
    expected_bits: u32,
    mtp: u32,
    now: u32,
}

fn proposal_header_checks(params: &ChainParams, header: ProposalHeader<'_>) -> Result<(), String> {
    let ProposalHeader {
        block,
        height,
        expected_bits,
        mtp,
        now,
    } = header;
    if block.header.bits.to_consensus() != expected_bits {
        return Err("bad-diffbits".into());
    }
    // Core is `<=` MTP. Proposal uses `<` so a template stamped at the
    // parent's mediantime+1 still validates after that parent is submitted
    // (new MTP often equals that stamp on an incrementing cache).
    if block.header.time < mtp {
        return Err("time-too-old".into());
    }
    if let Err(e) = rbitcoin_consensus::with_now(u64::from(now), || {
        rbitcoin_consensus::header::check_header_version_and_future_time(
            params,
            Height(height),
            &block.header,
        )
    }) {
        return Err(rbitcoin_consensus::block_reject_reason(&e));
    }
    Ok(())
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
///
/// `mtp` is the parent's median time; `lock_time_cutoff` is the connect
/// path's BIP113 cutoff for this block.
#[doc(hidden)]
pub fn proposal_connect(
    query: &Query,
    params: &ChainParams,
    block: &Block,
    height: u32,
    mtp: u32,
    lock_time_cutoff: u32,
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
        if !rbitcoin_consensus::is_final_tx(tx, height, lock_time_cutoff) {
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
        let mut coin_heights = Vec::with_capacity(tx.input.len());
        let coins = ProposalCoins {
            cb_txid,
            created: &created,
            parents: &parents,
        };
        for inp in &tx.input {
            let mut acc = ProposalInAccum {
                spent: &mut spent,
                in_val: &mut in_val,
            };
            let (txout, coin_h) = proposal_one_input(
                query,
                params,
                height,
                &coins,
                &mut acc,
                &inp.previous_output,
            )?;
            tx_prevouts.push(txout);
            coin_heights.push(coin_h);
        }
        let mut out_val = 0u64;
        for o in &tx.output {
            out_val = out_val
                .checked_add(o.value.to_sat())
                .ok_or("bad-txns-txouttotal-toolarge")?;
        }
        let fee = proposal_tx_fee(in_val, out_val)?;
        fees = fees.checked_add(fee).ok_or("bad-txns-fee-outofrange")?;
        if params.csv_active_at(height) {
            proposal_sequence_locks(query, tx, &coin_heights, height, mtp)?;
        }
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

struct ProposalCoins<'a> {
    cb_txid: Txid,
    created: &'a HashMap<OutPoint, TxOut>,
    parents: &'a HashMap<OutPoint, (Fk, u32, TxOut)>,
}

struct ProposalInAccum<'a> {
    spent: &'a mut HashSet<OutPoint>,
    in_val: &'a mut u64,
}

/// One proposal input. Duplicate, missing, unspendable, same-block
/// coinbase, and immature coinbase spends are errors.
fn proposal_one_input(
    query: &Query,
    params: &ChainParams,
    height: u32,
    coins: &ProposalCoins<'_>,
    acc: &mut ProposalInAccum<'_>,
    op: &OutPoint,
) -> Result<(TxOut, u32), String> {
    if !acc.spent.insert(*op) {
        return Err("bad-txns-inputs-missingorspent".into());
    }
    // Same-block coinbase outputs are not spendable yet.
    if op.txid == coins.cb_txid && coins.created.contains_key(op) {
        return Err("bad-txns-premature-spend-of-coinbase".into());
    }
    let (txout, coin_h) = if let Some(o) = coins.created.get(op) {
        (o.clone(), height)
    } else if let Some((fk, created_h, o)) = chain_txout(query, coins.parents, op) {
        if coinbase_spend_is_immature(query, *fk, *created_h, height, params.coinbase_maturity())? {
            return Err("bad-txns-premature-spend-of-coinbase".into());
        }
        (o.clone(), *created_h)
    } else {
        return Err("bad-txns-inputs-missingorspent".into());
    };
    // Core never stores this script as a coin. Reject before fee math,
    // ahead of the script check.
    if rbitcoin_consensus::policy::is_unspendable(txout.script_pubkey.as_bytes()) {
        return Err("bad-txns-inputs-missingorspent".into());
    }
    *acc.in_val = acc
        .in_val
        .checked_add(txout.value.to_sat())
        .ok_or("bad-txns-inputvalues-outofrange")?;
    Ok((txout, coin_h))
}

fn proposal_tx_fee(paid: u64, out_val: u64) -> Result<u64, String> {
    let paid_i = i64::try_from(paid).map_err(|_| "bad-txns-inputvalues-outofrange".to_string())?;
    let out_i = i64::try_from(out_val).map_err(|_| "bad-txns-txouttotal-toolarge".to_string())?;
    let fee = rbitcoin_consensus::block::fee_from_values(paid_i, out_i).map_err(|e| match e {
        rbitcoin_consensus::ConsensusError::BadTx("in < out") => "bad-txns-in-belowout".to_string(),
        _ => "bad-txns-fee-outofrange".to_string(),
    })?;
    u64::try_from(fee).map_err(|_| "bad-txns-fee-outofrange".to_string())
}

/// BIP68 on a proposal, as at connect: a coin's time is the median time of
/// the block before the one that created it, from confirmed headers only.
/// A store fault reading it is the store error, not a reject.
fn proposal_sequence_locks(
    query: &Query,
    tx: &Transaction,
    coin_heights: &[u32],
    height: u32,
    mtp: u32,
) -> Result<(), String> {
    if !rbitcoin_consensus::block::bip68_active_for_tx(tx) {
        return Ok(());
    }
    let mut coin_mtps = Vec::with_capacity(coin_heights.len());
    for (inp, &h) in tx.input.iter().zip(coin_heights) {
        let coin_mtp = if inp.sequence.is_time_locked() {
            rbitcoin_query::median_time_past_store(query, Height(h.saturating_sub(1)))
                .map_err(|e| e.to_string())?
        } else {
            0
        };
        coin_mtps.push(coin_mtp);
    }
    rbitcoin_consensus::block::reject_sequence_locks(tx, coin_heights, &coin_mtps, height, mtp)
        .map_err(|e| rbitcoin_consensus::block_reject_reason(&e))
}

/// `op`'s unspent confirmed output: a per-input spentness probe, then the
/// pre-decoded entry in `parents`.
#[doc(hidden)]
pub fn chain_txout<'a>(
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
#[doc(hidden)]
pub fn confirmed_parent_outputs(
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
                    value: Amount::from_sat(out.value),
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
#[doc(hidden)]
pub fn coinbase_spend_is_immature(
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
#[doc(hidden)]
pub fn tip_accept_stats_reset(query: &Query) {
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
#[doc(hidden)]
pub fn log_tip_accept_sh(
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
#[doc(hidden)]
pub fn seed_confirmed_tip(query: &Query) -> HashSet<BlockHash> {
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

/// Publish the best chain into `confirmed` from the height index.
///
/// Open already read each header to build that index. The copy holds the tip
/// commit, which a disconnect also holds while it drops hashes above the new
/// tip, so a block removed before the copy is not inserted again.
#[doc(hidden)]
pub fn publish_confirmed_heights(query: &Query, confirmed: &RwLock<HashSet<BlockHash>>) -> bool {
    let Ok(_commit) = query.lock_tip_commit() else {
        warn!("ibd: confirmed-set seed skipped; tip flush failed");
        return false;
    };
    let Some(hashes) = query.indexed_chain_hashes() else {
        warn!("ibd: confirmed-set seed skipped; height index does not match the tip");
        return false;
    };
    let mut g = confirmed.write().unwrap();
    g.reserve(hashes.len());
    for hash in hashes {
        g.insert(BlockHash::from_byte_array(hash));
    }
    true
}

/// Fill the rest of the confirmed set without blocking P2P start.
#[doc(hidden)]
pub fn spawn_confirmed_seed(query: Arc<Query>, confirmed: Arc<RwLock<HashSet<BlockHash>>>) {
    let Some(tip) = query.tip_height() else {
        return;
    };
    if tip.0 <= 2 {
        return;
    }
    let run = move || {
        let t0 = std::time::Instant::now();
        if publish_confirmed_heights(&query, &confirmed) {
            info!(
                "ibd: confirmed-set seed complete tip={} in {:?}",
                tip.0,
                t0.elapsed()
            );
        }
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
#[cfg(debug_assertions)]
pub fn tiny_regtest_hub_labeled(label: &str) -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    (dir, hub)
}

/// The body a merkle-ambiguity attacker sends: one 64-byte non-coinbase tx
/// whose txid is the header's merkle root. With a ground block `[cb, t1]`
/// those 64 bytes are `txid(cb) || txid(t1)` and the header is the real one.
#[cfg(debug_assertions)]
pub fn sixty_four_byte_body(prev: BlockHash, time: u32) -> Block {
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
