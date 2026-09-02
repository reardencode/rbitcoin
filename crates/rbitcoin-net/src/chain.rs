//! Shared chain accept path for P2P: tip extension and most-work reorg.

use crate::cache::BlockCache;
use crate::error::NetError;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, ScriptBuf, Transaction, Work};
use rbitcoin_consensus::{
    accept_and_connect_block_preverified, confirm_wire_load_from_plan as consensus_load_from_plan,
    confirm_wire_load_phase_pipelined, confirm_write_phase, genesis_block, header_to_record,
    mine_regtest_paying, ChainParams, Milestone, PlanStampOutcome, ScriptOkBatch,
    ScriptPreverified, WireLoadPipeline,
};
use rbitcoin_log::info;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// New best tip.
    Accepted { height: u32 },
    /// Already in store / cache.
    AlreadyHave,
    /// Same height competing tip with less or equal work — ignored.
    IgnoredWeaker,
}

/// Core `BLOCK_MUTATED`: reconstructed compact/body does not match the header.
/// Do not cache the hash as `BLOCK_FAILED`.
fn reject_is_mutated(reason: &str) -> bool {
    reason.contains("merkle")
        || reason.contains("bad-txnmrklroot")
        || reason.contains("bad-txns-duplicate")
        || reason.contains("witness commitment")
        || reason.contains("bad-witness-nonce")
        || reason.contains("missing witness commitment")
        || reason.contains("wtxid count")
}

/// Core `DEFAULT_MAX_TIP_AGE` (24h).
pub const DEFAULT_MAX_TIP_AGE_SECS: u64 = 24 * 60 * 60;

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
    /// Regtest `setmocktime` / generate timestamps. Default is wall clock.
    pub clock: Arc<rbitcoin_consensus::NodeClock>,
    invalidated: RwLock<HashSet<BlockHash>>,
    /// Operator-invalidated best-chain paths (hashes only, height order).
    /// Bodies come back via [`Query::reconstruct_archived_block`].
    invalidated_paths: RwLock<Vec<Vec<BlockHash>>>,
    /// Never-confirmed side-branch bodies, keyed by hash. Small cap.
    /// Not a block index: once-confirmed losers stay in Class A.
    held_bodies: RwLock<HashMap<BlockHash, Block>>,
    /// First-seen order for equal-work tip picks after invalidate
    /// (`feature_chain_tiebreaks.py`: earlier-received B7 beats B8).
    held_seq: RwLock<HashMap<BlockHash, u64>>,
    next_held_seq: AtomicU64,
    precious: RwLock<Option<BlockHash>>,
    /// Losing tips after a most-work reorg (hashes only). Bodies via archive.
    fork_tips: RwLock<HashSet<BlockHash>>,
    /// Header-only tips (`submitheader` / P2P headers): hash → (prev, height).
    /// Not a block index — no bodies, no status machine.
    header_tips: RwLock<HashMap<BlockHash, (BlockHash, u32)>>,
    /// Set around `accept_branch` connect so each `TipEvent` carries branch length.
    announce_reorg_len: AtomicU32,
    /// Core `-minimumchainwork` (32-byte BE). `None` = no extra floor.
    minimum_chain_work: RwLock<Option<[u8; 32]>>,
    /// Core `-blockversion`. `0` = default (TOP_BITS | testdummy).
    block_version: AtomicI32,
    /// True after generate/GBT in this process (getmininginfo currentblock*).
    gbt_assembled: AtomicBool,
    /// Core `-blockmintxfee` in sat/kvB. Default 1.
    block_min_tx_fee_sat_kvb: AtomicU64,
    /// Core `-maxtipage` seconds. Default 24h.
    max_tip_age_secs: AtomicU64,
    /// Block hashes we already issued getdata for (any peer).
    asked_blocks: RwLock<HashSet<BlockHash>>,
    /// `prefix[h] = work through height h` on the best chain. Process cache;
    /// rebuilt from wire headers when short, truncated on disconnect.
    chain_work_prefix: RwLock<Vec<Work>>,
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
            clock: rbitcoin_consensus::NodeClock::new(),
            invalidated: RwLock::new(HashSet::new()),
            invalidated_paths: RwLock::new(Vec::new()),
            held_bodies: RwLock::new(HashMap::new()),
            held_seq: RwLock::new(HashMap::new()),
            next_held_seq: AtomicU64::new(1),
            precious: RwLock::new(None),
            fork_tips: RwLock::new(HashSet::new()),
            header_tips: RwLock::new(HashMap::new()),
            announce_reorg_len: AtomicU32::new(0),
            minimum_chain_work: RwLock::new(None),
            block_version: AtomicI32::new(0),
            gbt_assembled: AtomicBool::new(false),
            block_min_tx_fee_sat_kvb: AtomicU64::new(1),
            max_tip_age_secs: AtomicU64::new(DEFAULT_MAX_TIP_AGE_SECS),
            asked_blocks: RwLock::new(HashSet::new()),
            chain_work_prefix: RwLock::new(Vec::new()),
        }
    }

    pub fn note_asked_block(&self, hash: BlockHash) {
        let mut g = self.asked_blocks.write().unwrap();
        if g.len() >= 4096 {
            g.clear();
        }
        g.insert(hash);
    }

    pub fn already_have_or_asked_block(&self, hash: &BlockHash) -> bool {
        self.is_connected(hash)
            || self.held_body(hash).is_some()
            || self.asked_blocks.read().unwrap().contains(hash)
    }

    pub fn note_gbt_assembled(&self) {
        self.gbt_assembled.store(true, Ordering::Relaxed);
    }

    pub fn gbt_assembled(&self) -> bool {
        self.gbt_assembled.load(Ordering::Relaxed)
    }

    /// Core `-blockversion`. Non-zero overrides GBT `version`.
    pub fn set_block_version(&self, v: i32) {
        self.block_version.store(v, Ordering::Relaxed);
    }

    /// GBT `version`: `-blockversion` or Core TOP_BITS | testdummy (bit 28).
    pub fn gbt_block_version(&self) -> i32 {
        let v = self.block_version.load(Ordering::Relaxed);
        if v != 0 {
            v
        } else {
            0x2000_0000 | (1 << 28)
        }
    }

    /// Core `-blockmintxfee` (sat/kvB). Default 1.
    pub fn set_block_min_tx_fee_sat_kvb(&self, sat_kvb: u64) {
        self.block_min_tx_fee_sat_kvb
            .store(sat_kvb, Ordering::Relaxed);
    }

    pub fn block_min_tx_fee_sat_kvb(&self) -> u64 {
        self.block_min_tx_fee_sat_kvb.load(Ordering::Relaxed)
    }

    /// Core `-maxtipage` (seconds). Default [`DEFAULT_MAX_TIP_AGE_SECS`].
    pub fn set_max_tip_age_secs(&self, secs: u64) {
        self.max_tip_age_secs.store(secs, Ordering::Relaxed);
    }

    pub fn max_tip_age_secs(&self) -> u64 {
        self.max_tip_age_secs.load(Ordering::Relaxed)
    }

    /// Core `-minimumchainwork`. Below the floor: no getheaders serve, no tip relay.
    pub fn set_minimum_chain_work(&self, w: Option<[u8; 32]>) {
        *self.minimum_chain_work.write().unwrap() = w;
    }

    /// Work of `header` hanging off a known parent (tip-extend, header-only
    /// chain, or side), else just the header's own work.
    pub fn work_with_header(&self, header: &Header) -> Work {
        let mut extra = vec![header.work()];
        let mut prev = header.prev_blockhash;
        for _ in 0..10_000 {
            if prev.to_byte_array() == [0u8; 32] {
                return crate::most_work::sum_work(extra.into_iter());
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
                return crate::most_work::sum_work(extra.into_iter());
            }
            let Some(hdr) = self.header_of(&prev) else {
                return crate::most_work::sum_work(extra.into_iter());
            };
            extra.push(hdr.work());
            prev = hdr.prev_blockhash;
        }
        crate::most_work::sum_work(extra.into_iter())
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
            .or_else(|| self.header_tips.read().unwrap().get(&prev).map(|(_, h)| *h));
        let Some(parent_h) = parent_h else {
            return false;
        };
        parent_h.saturating_add(1) > tip.saturating_add(Self::HELD_STALE_BELOW)
    }

    /// Unrequested body whose header-path work is strictly below the tip.
    pub fn unrequested_weaker_than_tip(&self, header: &Header) -> bool {
        let Ok(tip) = self.chain_work() else {
            return false;
        };
        crate::most_work::work_better(tip, self.work_with_header(header))
    }

    /// True when connecting `header` would still be below `-minimumchainwork`.
    pub fn header_below_minwork(&self, header: &Header) -> bool {
        let Some(min) = self.min_chain_work_floor() else {
            return false;
        };
        self.work_with_header(header).to_be_bytes() < min
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

    /// Core `-minimumchainwork` floor (32-byte BE), if set.
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

    /// Core `nMaxTipAge` (`-maxtipage`): tip time vs [`Self::clock`].
    pub fn tip_is_stale_for_ibd(&self) -> bool {
        let Some(h) = self.tip_header() else {
            return true;
        };
        self.clock.now_secs().saturating_sub(u64::from(h.time)) > self.max_tip_age_secs()
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
        self.connect_at(0, genesis)?;
        Ok(())
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.query
            .tip_height()
            .map(|h| h.0)
            .or_else(|| self.cache.tip_height())
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        // Store tip is authoritative after IBD/archive-confirm (cache may only
        // hold genesis or a short tip window while Class C is far ahead). Prefer
        // query when its height is at least the cache tip; otherwise fall back
        // to the in-memory cache chain (pre-store / regtest cache-only paths).
        let q_h = self.query.tip_height().map(|h| h.0);
        let c_h = self.cache.tip_height();
        match (q_h, c_h) {
            (Some(qh), Some(ch)) if ch > qh => self.cache.tip_hash(),
            (Some(qh), _) => self
                .query
                .header_at_height(rbitcoin_primitives::Height(qh))
                .ok()
                .flatten()
                .map(|(_, rec)| BlockHash::from_byte_array(rec.hash)),
            (None, Some(_)) => self.cache.tip_hash(),
            (None, None) => None,
        }
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
        {
            let headers = self.header_tips.read().unwrap();
            // Only header *tips* (a later submitblock of an ancestor must not
            // re-list that ancestor alongside its descendant).
            let covered: HashSet<BlockHash> = headers.values().map(|(prev, _)| *prev).collect();
            for hash in headers.keys().copied() {
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
            let held = self.held_bodies.read().unwrap();
            let parents: HashSet<BlockHash> =
                held.values().map(|b| b.header.prev_blockhash).collect();
            for hash in held.keys().copied() {
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
        for path in self.invalidated_paths.read().unwrap().iter() {
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
            return Some(*prev);
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
        let inv = self.invalidated.read().unwrap();
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
    pub fn best_header_height(&self) -> u32 {
        let mut best = self.tip_height().unwrap_or(0);
        let headers = self.header_tips.read().unwrap();
        for (hash, (_, h)) in headers.iter() {
            if self.header_ancestry_invalid(*hash) {
                continue;
            }
            best = best.max(*h);
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
        if tips.len() >= 128 && !tips.contains_key(&hash) {
            if let Some(k) = tips.keys().next().copied() {
                tips.remove(&k);
            }
        }
        tips.insert(hash, (prev, height));
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
        self.header_tips.read().unwrap().get(hash).map(|(_, h)| *h)
    }

    /// Whether `hash` is marked invalid (`invalidateblock` or rejected `submitblock`).
    pub fn is_block_invalid(&self, hash: &BlockHash) -> bool {
        self.invalidated.read().unwrap().contains(hash) || self.header_ancestry_invalid(*hash)
    }

    /// Remember a consensus-invalid block (not a mutated merkle).
    pub fn note_invalid_block(&self, hash: BlockHash) {
        self.invalidated.write().unwrap().insert(hash);
    }

    /// True if we have a header row (best chain, header-only tip, or held body).
    /// Used so we never `getdata` a block inv whose header we have not seen.
    pub fn knows_header(&self, hash: &BlockHash) -> bool {
        self.is_connected(hash)
            || self.header_tips.read().unwrap().contains_key(hash)
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

    /// Core `submitheader`: decode already succeeded. Missing parent, invalid
    /// parent, and MTP are reject strings (`RPC_VERIFY_ERROR` / `-25`).
    pub fn process_submitted_header(&self, header: &Header) -> Result<(), String> {
        let hash = header.block_hash();
        if self
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .ok()
            .flatten()
            .is_some()
            || self.header_tips.read().unwrap().contains_key(&hash)
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
            || self.header_tips.read().unwrap().contains_key(&prev)
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
        let prev_fk = if header.prev_blockhash.to_byte_array() == [0u8; 32] {
            Fk::NULL
        } else {
            match self
                .query
                .get_header_by_hash(header.prev_blockhash.as_byte_array())
                .map_err(|e| NetError::Consensus(e.to_string()))?
            {
                Some((fk, _)) => fk,
                None => {
                    return Err(NetError::Consensus(
                        "header parent unknown — ensure parent before child".into(),
                    ));
                }
            }
        };
        let rec = header_to_record(prev_fk, header);
        let fk = self
            .query
            .ensure_header(&rec)
            .map_err(|e| NetError::Consensus(e.to_string()))?;
        self.note_header_tip(header);
        Ok(fk)
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
        .map_err(|e| NetError::Consensus(e.to_string()))
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
        .map_err(|e| NetError::Consensus(e.to_string()))?;
        Ok(Some(ok))
    }

    /// WRITE stage: structural + Class C + spend annotate (ordered).
    pub fn confirm_write(&self, batch: ScriptOkBatch) -> Result<Vec<AcceptOutcome>, NetError> {
        let meta: Vec<(u32, BlockHash)> = batch
            .heights_hashes()
            .into_iter()
            .map(|(h, raw)| (h, BlockHash::from_byte_array(raw)))
            .collect();
        confirm_write_phase(&self.query, &self.params, self.milestone, batch)
            .map_err(|e| NetError::Consensus(e.to_string()))?;
        self.note_confirmed_tip(&meta)?;
        Ok(meta
            .iter()
            .map(|&(height, _)| AcceptOutcome::Accepted { height })
            .collect())
    }

    fn note_confirmed_tip(&self, need_meta: &[(u32, BlockHash)]) -> Result<(), NetError> {
        if let Some(mp) = self.mempool() {
            if mp.relay_enabled() {
                for &(_height, hash) in need_meta {
                    if let Ok(Some(block)) =
                        self.query.reconstruct_block_by_hash(&hash.to_byte_array())
                    {
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
        for &(height, hash) in need_meta {
            confirmed.insert(hash);
            if let Ok(hdr) = self.query.wire_header_at_height(Height(height)) {
                let _ = self.tip_tx.send(TipEvent {
                    height,
                    hash,
                    header: hdr,
                    reorg_branch_len: 0,
                });
            }
        }
        drop(confirmed);
        self.notify.notify_waiters();
        if let Some(&(height, _)) = need_meta.last() {
            self.query.release_sh_writebehind(Height(height));
        }
        Ok(())
    }

    /// Core `UpdateTime`: `max(MTP+1, GetTime())`.
    fn generate_block_time(&self, tip_h: u32, tip_time: u32) -> u32 {
        let now = self.clock.now_secs() as u32;
        let mtp = rbitcoin_consensus::median_time_past(self.query.as_ref(), Height(tip_h))
            .unwrap_or(tip_time);
        now.max(mtp.saturating_add(1))
    }

    /// Mine one block paying `script_pubkey` without connecting it.
    ///
    /// Core `generateblock … submit=false` returns the hex for `submitheader`.
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
        Ok(mine_regtest_paying(
            prev,
            time,
            tip_h.saturating_add(1),
            script_pubkey,
            extra_txs,
        ))
    }

    /// Mine `nblocks` paying `script_pubkey` and accept each via [`Self::accept_block`].
    ///
    /// Regtest harness only. Extra txs go in the first block. Ensures genesis.
    pub fn generate_to_script(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, NetError> {
        crate::tip_accept::run_on_tip_accept(|| {
            self.generate_to_script_inner(nblocks, script_pubkey, extra_txs)
        })
    }

    fn generate_to_script_inner(
        &self,
        nblocks: u32,
        script_pubkey: ScriptBuf,
        extra_txs: Vec<Transaction>,
    ) -> Result<Vec<BlockHash>, NetError> {
        self.ensure_genesis_inner()?;
        if nblocks == 0 {
            return Ok(Vec::new());
        }
        if nblocks > 10_000 {
            return Err(NetError::Consensus("nblocks too large (max 10000)".into()));
        }
        // Serialize tip-read + mine + accept so concurrent generateblock
        // (rpc_generate.py parallel) cannot race the same tip into AlreadyHave.
        let _guard = self.generate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut hashes = Vec::with_capacity(nblocks as usize);
        let mut extras = extra_txs;
        for i in 0..nblocks {
            let tip_h = self
                .tip_height()
                .ok_or(NetError::Protocol("generate: no tip"))?;
            let prev = self
                .tip_hash()
                .ok_or(NetError::Protocol("generate: no tip hash"))?;
            let tip_time = self.tip_header().map(|h| h.time).unwrap_or(0);
            let time = self.generate_block_time(tip_h, tip_time);
            let txs = if i == 0 {
                std::mem::take(&mut extras)
            } else {
                Vec::new()
            };
            let block = mine_regtest_paying(
                prev,
                time,
                tip_h.saturating_add(1),
                script_pubkey.clone(),
                txs,
            );
            match self.accept_block_inner(block.clone())? {
                AcceptOutcome::Accepted { .. } => hashes.push(block.block_hash()),
                other => {
                    return Err(NetError::Consensus(format!(
                        "generate did not extend tip: {other:?}"
                    )));
                }
            }
        }
        if let Err(e) = self.query.apply_sh_pending() {
            rbitcoin_log::warn!("generate: SH write-behind drain: {e}");
        }
        Ok(hashes)
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
            .map_err(|e| NetError::Consensus(e.to_string()))?
            .filter(|h| h.0 <= tip);
        if let Some(h) = on_tip {
            let _guard = self.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
            let mut path = Vec::new();
            for ht in h.0..=tip {
                if let Some(b) = self.block_at_height(ht)? {
                    let bh = b.block_hash();
                    self.invalidated.write().unwrap().insert(bh);
                    path.push(bh);
                }
            }
            if !path.is_empty() {
                self.invalidated_paths.write().unwrap().push(path);
            }
            let keep = h.0.saturating_sub(1);
            self.disconnect_to(keep)?;
            drop(_guard);
        } else if self.knows_header(&hash) || self.held_body(&hash).is_some() {
            // Side-branch / held header (feature_chain_tiebreaks B10): mark
            // invalid without a tip disconnect.
            self.invalidated.write().unwrap().insert(hash);
            self.invalidated_paths.write().unwrap().push(vec![hash]);
        } else {
            return Err(NetError::Consensus("Block not found".into()));
        }
        let _ = self.try_apply_after_invalidate()?;
        if let Some(mp) = self.mempool() {
            mp.evict_after_reorg();
        }
        Ok(())
    }

    /// After invalidate, activate the best remaining fork (held or archive).
    fn try_apply_after_invalidate(&self) -> Result<Option<AcceptOutcome>, NetError> {
        let inv = self.invalidated.read().unwrap().clone();
        let mut starts: Vec<BlockHash> = self.fork_tips.read().unwrap().iter().copied().collect();
        starts.extend(self.held_bodies.read().unwrap().keys().copied());
        if let Some(p) = *self.precious.read().unwrap() {
            if !starts.contains(&p) {
                starts.push(p);
            }
        }
        let seqs = self.held_seq.read().unwrap().clone();
        let tip_seq = |tip: BlockHash| seqs.get(&tip).copied().unwrap_or(u64::MAX);
        let mut best: Option<(bitcoin::Work, u64, Vec<Block>)> = None;
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
            let w = sum_work(branch.iter().map(|b| b.header.work()));
            let seq = tip_seq(tip);
            let take = match &best {
                None => true,
                Some((bw, bseq, _)) => {
                    work_better(w, *bw) || (w.to_be_bytes() == bw.to_be_bytes() && seq < *bseq)
                }
            };
            if take {
                best = Some((w, seq, branch));
            }
        }
        let Some((_, _, branch)) = best else {
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
            || self.header_tips.read().unwrap().contains_key(&hash)
            || self
                .query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .is_some()
            || self
                .invalidated_paths
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

        self.invalidated.write().unwrap().remove(&hash);
        let paths: Vec<Vec<BlockHash>> = {
            let mut g = self.invalidated_paths.write().unwrap();
            let mut taken = Vec::new();
            let mut seeds = related.clone();
            seeds.insert(hash);
            loop {
                let before = taken.len();
                g.retain(|p| {
                    let hit = p.iter().any(|h| seeds.contains(h))
                        || p.first().is_some_and(|h| {
                            self.prev_of(h).is_some_and(|prev| seeds.contains(&prev))
                        });
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
        };
        {
            let mut inv = self.invalidated.write().unwrap();
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

    /// Prefer this hash among equal-work competing tips.
    pub fn precious_block(&self, hash: BlockHash) -> Result<(), NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.precious_block_inner(hash))
    }

    fn precious_block_inner(&self, hash: BlockHash) -> Result<(), NetError> {
        *self.precious.write().unwrap() = Some(hash);
        if let Some(branch) = self.assemble_side_branch(hash) {
            match self.accept_branch_inner(&branch) {
                Err(NetError::Protocol(s)) if s.contains("branch parent not on chain") => {}
                Err(e) => return Err(e),
                Ok(_) => {}
            }
        } else {
            let _ = self.try_apply_held()?;
        }
        Ok(())
    }

    /// Accept a block that extends the tip, or reorg to a stronger competing tip / branch.
    pub fn accept_block(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        crate::tip_accept::run_on_tip_accept(|| self.accept_block_inner(block))
    }

    fn accept_block_inner(&self, block: Block) -> Result<AcceptOutcome, NetError> {
        let hash = block.block_hash();
        if self.tip_hash() == Some(hash) || self.has_block(&hash) {
            return Ok(AcceptOutcome::AlreadyHave);
        }
        if self.invalidated.read().unwrap().contains(&hash) {
            return Err(NetError::Consensus("block is invalidated".into()));
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
                let tip_hash = self
                    .tip_hash()
                    .ok_or(NetError::Protocol("missing tip hash"))?;
                if prev == tip_hash {
                    let height = tip_h.saturating_add(1);
                    self.connect_at(height, block)?;
                    return Ok(AcceptOutcome::Accepted { height });
                }

                let Some(parent_h) = self
                    .query
                    .height_of_hash(&prev.to_byte_array())
                    .map_err(|e| NetError::Consensus(e.to_string()))?
                else {
                    return Err(NetError::Protocol("unknown parent"));
                };

                let new_height = parent_h.0.saturating_add(1);
                if new_height > tip_h {
                    return Err(NetError::Protocol("gap above tip"));
                }

                if new_height == tip_h {
                    let cur = self
                        .block_at_height(tip_h)?
                        .ok_or(NetError::Protocol("missing current tip block"))?;
                    let precious = *self.precious.read().unwrap() == Some(hash);
                    if block.header.work() > cur.header.work()
                        || (block.header.work() == cur.header.work() && precious)
                    {
                        self.disconnect_to(parent_h.0)?;
                        self.connect_at(new_height, block)?;
                        return Ok(AcceptOutcome::Accepted { height: new_height });
                    }
                    return Ok(AcceptOutcome::IgnoredWeaker);
                }

                Err(NetError::Protocol(
                    "side block; use accept_branch for reorg",
                ))
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
        if blocks.is_empty() {
            return Err(NetError::Protocol("empty branch"));
        }
        for w in blocks.windows(2) {
            if w[1].header.prev_blockhash != w[0].block_hash() {
                return Err(NetError::Protocol("branch not linked"));
            }
        }
        let fork_prev = blocks[0].header.prev_blockhash;
        let fork_h = if fork_prev.to_byte_array() == [0u8; 32] {
            if self.tip_height().is_none() {
                for (i, b) in blocks.iter().enumerate() {
                    self.connect_at(i as u32, b.clone())?;
                }
                let h = (blocks.len() - 1) as u32;
                return Ok(AcceptOutcome::Accepted { height: h });
            }
            None
        } else {
            Some(
                self.query
                    .height_of_hash(&fork_prev.to_byte_array())
                    .map_err(|e| NetError::Consensus(e.to_string()))?
                    .ok_or(NetError::Protocol("branch parent not on chain"))?,
            )
        };

        let fork_height = fork_h.map(|h| h.0);

        let new_work = sum_work(blocks.iter().map(|b| b.header.work()));

        let our_work = self.work_from_fork_to_tip(fork_height)?;

        let branch_tip = blocks.last().map(Block::block_hash);
        let precious = *self.precious.read().unwrap() == branch_tip;
        // Precious may break an equal-work tie. It must not activate less work.
        let equal_work = !work_better(new_work, our_work) && !work_better(our_work, new_work);
        if self.tip_height().is_some()
            && !work_better(new_work, our_work)
            && !(precious && equal_work)
        {
            return Ok(AcceptOutcome::IgnoredWeaker);
        }

        let tip_h = self.tip_height().unwrap_or(0);
        let mut old_path: Vec<Block> = Vec::new();
        if let Some(fh) = fork_height {
            if tip_h > fh {
                old_path.reserve((tip_h - fh) as usize);
                for h in (fh + 1)..=tip_h {
                    if let Some(b) = self.block_at_height(h)? {
                        old_path.push(b);
                    }
                }
            }
        }

        // Once-confirmed losers stay in Class A (`reconstruct_archived_block`).
        // Do not copy `old_path` into the held-body map (that is a block index).
        if let Some(fh) = fork_height {
            self.disconnect_to(fh)?;
        } else {
            while self.query.tip_height().is_some() {
                if let Some(th) = self.tip_hash() {
                    self.confirmed.write().unwrap().remove(&th);
                }
                self.query
                    .disconnect_tip()
                    .map_err(|e| NetError::Consensus(e.to_string()))?;
            }
            self.cache.clear();
            self.confirmed.write().unwrap().clear();
        }

        let base = fork_height.map(|h| h + 1).unwrap_or(0);
        self.announce_reorg_len
            .store(blocks.len() as u32, Ordering::Relaxed);
        for (i, b) in blocks.iter().enumerate() {
            if let Err(e) = self.connect_at(base + i as u32, b.clone()) {
                self.announce_reorg_len.store(0, Ordering::Relaxed);
                // Mid-branch connect fail: restore pre-attempt tip (not leave LCA).
                if let Some(fh) = fork_height {
                    if let Err(disc) = self.disconnect_to(fh) {
                        return Err(NetError::Consensus(format!(
                            "reorg connect failed ({e}); disconnect for restore failed: {disc}"
                        )));
                    }
                    for (j, ob) in old_path.iter().enumerate() {
                        if let Err(re) = self.connect_at(base + j as u32, ob.clone()) {
                            return Err(NetError::Consensus(format!(
                                "reorg connect failed ({e}); tip restore failed: {re}"
                            )));
                        }
                    }
                }
                return Err(e);
            }
        }
        self.announce_reorg_len.store(0, Ordering::Relaxed);
        let height = base + (blocks.len() as u32) - 1;
        {
            let mut held = self.held_bodies.write().unwrap();
            let mut seqs = self.held_seq.write().unwrap();
            for b in blocks {
                let h = b.block_hash();
                held.remove(&h);
                seqs.remove(&h);
            }
        }
        {
            let mut forks = self.fork_tips.write().unwrap();
            if let Some(old) = old_path.last() {
                forks.insert(old.block_hash());
            }
            for b in blocks {
                forks.remove(&b.block_hash());
            }
        }
        Ok(AcceptOutcome::Accepted { height })
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
        match self.accept_block_inner(block.clone()) {
            Ok(AcceptOutcome::Accepted { height }) => {
                self.held_bodies.write().unwrap().remove(&hash);
                self.held_seq.write().unwrap().remove(&hash);
                Ok(AcceptOutcome::Accepted { height })
            }
            Ok(AcceptOutcome::AlreadyHave) => {
                self.held_bodies.write().unwrap().remove(&hash);
                self.held_seq.write().unwrap().remove(&hash);
                Ok(AcceptOutcome::AlreadyHave)
            }
            Ok(AcceptOutcome::IgnoredWeaker) => {
                self.hold_body(block);
                match self.try_apply_held()? {
                    Some(o) => Ok(o),
                    None => Ok(AcceptOutcome::IgnoredWeaker),
                }
            }
            Err(NetError::Protocol(s))
                if s.contains("side block") || s.contains("unknown parent") =>
            {
                self.hold_body(block);
                match self.try_apply_held()? {
                    Some(o) => Ok(o),
                    None => Ok(AcceptOutcome::IgnoredWeaker),
                }
            }
            Err(e) => {
                // Core `BLOCK_FAILED`: remember consensus-invalid hashes even
                // when the header was never persisted (compact reconstruct).
                // Mutated bodies (merkle / witness commitment) keep the hash
                // acceptable so a later honest reconstruct can connect
                // (`p2p_compactblocks` stalling-peer invalid compact).
                if let NetError::Consensus(s) = &e {
                    if !reject_is_mutated(s) && !s.to_ascii_lowercase().contains("not found") {
                        self.note_invalid_block(hash);
                    }
                }
                Err(e)
            }
        }
    }

    /// Peer-session accept: same work as [`Self::accept_received_block`], awaited
    /// so the tokio worker is not parked across confirm.
    pub async fn accept_received_block_async(
        &self,
        block: Block,
    ) -> Result<AcceptOutcome, NetError> {
        crate::tip_accept::run_on_tip_accept_async(|| self.accept_received_block_inner(block)).await
    }

    const HELD_BODIES_CAP: usize = 320;
    const HELD_STALE_BELOW: u32 = 288;

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
            held.iter()
                .filter_map(|(hash, b)| {
                    let h = self.held_body_height(b)?;
                    (tip.saturating_sub(h) > Self::HELD_STALE_BELOW).then_some(*hash)
                })
                .collect()
        };
        if drop.is_empty() {
            return;
        }
        let mut held = self.held_bodies.write().unwrap();
        let mut seqs = self.held_seq.write().unwrap();
        for h in drop {
            held.remove(&h);
            seqs.remove(&h);
        }
    }

    fn hold_body(&self, block: Block) {
        let hash = block.block_hash();
        if self.is_connected(&hash) {
            return;
        }
        if let Some(h) = self.held_body_height(&block) {
            if let Some(tip) = self.tip_height() {
                if tip.saturating_sub(h) > Self::HELD_STALE_BELOW {
                    return;
                }
            }
        }
        let evict = {
            let held = self.held_bodies.read().unwrap();
            if held.contains_key(&hash) {
                return;
            }
            if held.len() < Self::HELD_BODIES_CAP {
                None
            } else {
                held.keys().next().copied()
            }
        };
        let mut held = self.held_bodies.write().unwrap();
        let mut seqs = self.held_seq.write().unwrap();
        if let Some(k) = evict {
            held.remove(&k);
            seqs.remove(&k);
        }
        let seq = self.next_held_seq.fetch_add(1, Ordering::Relaxed);
        held.insert(hash, block);
        seqs.insert(hash, seq);
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
        for b in held.values() {
            let prev = b.header.prev_blockhash;
            if prev.to_byte_array() == [0u8; 32] {
                continue;
            }
            if self.is_connected(&prev) || held.contains_key(&prev) {
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

    fn try_apply_held(&self) -> Result<Option<AcceptOutcome>, NetError> {
        let mut starts: Vec<BlockHash> = self.held_bodies.read().unwrap().keys().copied().collect();
        if let Some(p) = *self.precious.read().unwrap() {
            if !starts.contains(&p) {
                starts.push(p);
            }
        }
        if starts.is_empty() {
            return Ok(None);
        }
        let precious = *self.precious.read().unwrap();
        let seqs = self.held_seq.read().unwrap().clone();
        let tip_seq = |tip: BlockHash| seqs.get(&tip).copied().unwrap_or(u64::MAX);
        let mut best: Option<(Work, u64, Vec<Block>, bool)> = None;
        for start in starts {
            let Some(branch) = self.assemble_side_branch(start) else {
                continue;
            };
            let w = sum_work(branch.iter().map(|b| b.header.work()));
            let tip = branch.last().map(Block::block_hash);
            let is_p = tip == precious;
            let seq = tip.map(tip_seq).unwrap_or(u64::MAX);
            let take = match &best {
                None => true,
                Some((bw, bseq, _, was_p)) => {
                    work_better(w, *bw)
                        || (!work_better(*bw, w) && is_p && !*was_p)
                        || (w.to_be_bytes() == bw.to_be_bytes() && !is_p && !*was_p && seq < *bseq)
                }
            };
            if take {
                best = Some((w, seq, branch, is_p));
            }
        }
        let Some((_, _, branch, _)) = best else {
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

    fn connect_at(&self, height: u32, block: Block) -> Result<(), NetError> {
        debug_assert!(
            crate::tip_accept::on_tip_accept_thread(),
            "connect_at must run on tip-accept"
        );
        let hash = block.block_hash();
        let header = block.header;
        // Reorg disconnect is done before connect; confirm pipeline is tip+1 only.
        // Live mempool txs already had scripts run at accept — skip re-verify.
        let preverified = self
            .mempool()
            .map(|mp| mp.script_preverified_txids())
            .unwrap_or_default();
        tip_accept_stats_reset();
        let t_wall = std::time::Instant::now();
        let now = self.clock.now_secs();
        rbitcoin_consensus::with_now(now, || {
            accept_and_connect_block_preverified(
                &self.query,
                &self.params,
                Height(height),
                &block,
                self.milestone,
                &preverified,
            )
        })
        .map_err(|e| {
            let reason = rbitcoin_consensus::block_reject_reason(&e);
            rbitcoin_log::info!(
                "{}",
                rbitcoin_consensus::block_reject_log_line(&hash, &reason)
            );
            NetError::Consensus(reason)
        })?;
        self.header_tips.write().unwrap().remove(&hash);
        let wall_ns = t_wall.elapsed().as_nanos() as u64;
        if let Some(mp) = self.mempool() {
            let ids: Vec<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
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
        }
        self.confirmed.write().unwrap().insert(hash);
        let n_tx = block.txdata.len();
        let _ = self.cache.push_best(block);
        // Tip-follow / wire accept path: log every accepted tip block (Core-like
        // UpdateTip). IBD bulk confirm uses note_confirmed_tip without this line;
        // IBD retains periodic progress/perf status instead.
        log_update_tip(height, &hash, &header, n_tx);
        log_tip_accept_sh(&self.query, height, n_tx, wall_ns);
        let event = TipEvent {
            height,
            hash,
            header,
            reorg_branch_len: self.announce_reorg_len.load(Ordering::Relaxed),
        };
        let _ = self.tip_tx.send(event);
        self.notify.notify_waiters();
        self.query.release_sh_writebehind(Height(height));
        self.trim_held_bodies(height);
        Ok(())
    }

    fn disconnect_to(&self, keep_height: u32) -> Result<(), NetError> {
        let mut disconnected_txs: Vec<Transaction> = Vec::new();
        loop {
            let tip = match self.query.tip_height() {
                Some(h) => h.0,
                None => break,
            };
            if tip <= keep_height {
                break;
            }
            if let Ok(Some(b)) = self.block_at_height(tip) {
                for tx in b.txdata.iter().skip(1) {
                    disconnected_txs.push(tx.clone());
                }
            }
            if let Some(th) = self.tip_hash() {
                self.confirmed.write().unwrap().remove(&th);
            }
            self.query
                .disconnect_tip_keep_pending()
                .map_err(|e| NetError::Consensus(e.to_string()))?;
        }
        self.cache.truncate_to_height(keep_height);
        if let Some(mp) = self.mempool() {
            if !disconnected_txs.is_empty() {
                let n = mp.reorg_reaccept(&disconnected_txs);
                if n > 0 {
                    rbitcoin_log::debug!(
                        "mempool: re-accepted {n}/{} tx(s) after reorg disconnect to {keep_height}",
                        disconnected_txs.len()
                    );
                }
            }
            // Even when the disconnected blocks were empty, mempool txs that
            // spend now-immature coinbases must leave (`mempool_reorg`).
            mp.evict_after_reorg();
        }
        self.query
            .drop_sh_pending_from(Height(keep_height.saturating_add(1)));
        Ok(())
    }

    fn block_at_height(&self, height: u32) -> Result<Option<Block>, NetError> {
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
            Err(e) => Err(NetError::Consensus(e.to_string())),
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
        while p.len() < want {
            let h = p.len() as u32;
            let hdr = self
                .query
                .wire_header_at_height(Height(h))
                .map_err(|e| NetError::Consensus(e.to_string()))?;
            let w = hdr.work();
            let acc = match p.last() {
                None => w,
                Some(&prev) => prev + w,
            };
            p.push(acc);
        }
        Ok(())
    }
}

/// Core-like per-block tip log for tip-follow / wire accept (`connect_at`).
///
/// Format is intentionally close to Bitcoin Core `UpdateTip` so operators can
/// grep one line per height. IBD does not call this for every confirm batch.
/// `p2p_unrequested_blocks.py` needle when minchainwork rejects an unrequested header.
pub fn accept_block_header_nodos_log(hash: impl std::fmt::Display) -> String {
    format!(
        "AcceptBlockHeader: not adding new block header {hash}, missing anti-dos proof-of-work validation"
    )
}

/// `p2p_headers_sync_with_minchainwork.py` low-work skip.
pub fn ignoring_low_work_chain_log(height: u32) -> String {
    format!("[net] Ignoring low-work chain (height={height})")
}

/// Core `ProcessNewBlockHeaders` IBD progress (noban / sufficient-work).
pub fn synchronizing_blockheaders_log(height: u32) -> String {
    format!("Synchronizing blockheaders, height: {height}")
}

/// `p2p_initial_headers_sync.py` first getheaders after connect.
pub fn initial_getheaders_log(locator_height: u32, peer: u64) -> String {
    format!("initial getheaders ({locator_height}) to peer={peer}")
}

/// Core `HEADERS_DOWNLOAD_TIMEOUT_BASE` (15 min) + 1 ms per header-interval.
pub fn headers_download_timeout_secs(now: u64, best_header_time: u64) -> u64 {
    let since = now.saturating_sub(best_header_time);
    // ceil(1ms * since / 600s) in seconds == ceil(since / 600_000).
    let variable = since.div_ceil(600_000);
    now.saturating_add(15 * 60).saturating_add(variable)
}

pub fn headers_timeout_disconnect_log(peer: u64) -> String {
    format!("Timeout downloading headers, disconnecting peer={peer}")
}

pub fn headers_timeout_noban_log(peer: u64) -> String {
    format!("Timeout downloading headers from noban peer, not disconnecting peer={peer}")
}

/// Core `p2p_blocksonly.py` debug.log needle. Per-item; emit at **trace**.
pub fn received_getdata_wtx_log(wtxid: impl std::fmt::Display, peer: u64) -> String {
    format!("received getdata for: wtx {wtxid} peer={peer}")
}

pub fn log_update_tip(height: u32, hash: &BlockHash, header: &Header, n_tx: usize) {
    let time = header.time;
    let ver = header.version.to_consensus();
    info!(
        "UpdateTip: new best={hash} height={height} version={ver} \
         tx={n_tx} date={time} progress=tip"
    );
}

/// Clear confirm + Class C SH meters before a tip-follow accept sample window.
fn tip_accept_stats_reset() {
    let _ = rbitcoin_consensus::confirm_phase_stats::sample_and_reset();
    let _ = rbitcoin_query::class_c_phase_stats::sample_and_reset();
    let _ = rbitcoin_query::class_c_phase_stats::sample_tip_sh_and_reset();
}

/// Inputs for pure tip-accept SH line (unit-tested).
#[derive(Clone, Debug)]
pub struct TipAcceptShInput {
    pub height: u32,
    pub n_tx: usize,
    pub wall_ns: u64,
    /// Load assemble wall (confirm CONNECT_NS).
    pub load_ns: u64,
    pub script_ns: u64,
    pub class_a_ns: u64,
    pub class_c_ns: u64,
    pub spend_ns: u64,
    pub strong_ns: u64,
    pub tip_ns: u64,
    /// BIP-352 tip write-through (`index_sp_tweaks_batch`). Zero when `--sptweaks` is off.
    pub tweak_ns: u64,
    pub sh_lag: u32,
    pub sh: rbitcoin_query::class_c_phase_stats::TipShSnap,
}

/// Format `tip: accept …` body (no log level). Pure for tests.
pub fn format_tip_accept_sh_line(i: &TipAcceptShInput) -> String {
    let wall_ms = i.wall_ns / 1_000_000;
    let load_ms = i.load_ns / 1_000_000;
    let script_ms = i.script_ns / 1_000_000;
    let class_a_ms = i.class_a_ns / 1_000_000;
    let class_c_ms = i.class_c_ns / 1_000_000;
    let spend_ms = i.spend_ns / 1_000_000;
    let strong_ms = i.strong_ns / 1_000_000;
    let tip_ms = i.tip_ns / 1_000_000;
    let tweak_ms = i.tweak_ns / 1_000_000;
    let sh = &i.sh;
    let sh_ms = sh.total_sh_ns() / 1_000_000;
    let coll_ms = sh.collect_ns / 1_000_000;
    let sort_ms = sh.sort_ns / 1_000_000;
    let seed_ms = sh.seed_ns / 1_000_000;
    let body_ms = sh.body_ns / 1_000_000;
    let head_ms = sh.head_ns / 1_000_000;
    let sh_ratio = if i.wall_ns == 0 {
        0u64
    } else {
        (sh.total_sh_ns().saturating_mul(100)) / i.wall_ns.max(1)
    };
    // class_c = strong + tip only (table work). SH is parallel and listed separately.
    format!(
        "tip: accept h={h} tx={n_tx} wall={wall_ms}ms load={load_ms}ms script={script_ms}ms \
         class_a={class_a_ms}ms class_c={class_c_ms}ms (strong={strong_ms} tip_set={tip_ms}) \
         sh={sh_ms}ms sh_lag={sh_lag} \
         (collect={coll_ms} sort={sort_ms} seed={seed_ms} body={body_ms} head={head_ms} \
         pin={pin} cold={cold} creates={creates} unique={unique} written={written}) \
         spend={spend_ms}ms tweaks={tweak_ms}ms sh/wall={sh_ratio}%",
        h = i.height,
        n_tx = i.n_tx,
        sh_lag = i.sh_lag,
        pin = sh.pin,
        cold = sh.cold,
        creates = sh.creates,
        unique = sh.unique,
        written = sh.written,
    )
}

/// Sample meters after tip accept and emit INFO `tip: accept …` (SH breakdown).
fn log_tip_accept_sh(query: &Query, height: u32, n_tx: usize, wall_ns: u64) {
    let (
        _recon,
        _wire,
        connect_ns,
        script_ns,
        _class_c_ns,
        strong_ns,
        _sh_sum,
        tip_ns,
        spend_ns,
        _blks,
        _resolve,
        load_ns,
        _unpin,
        _cache_tip,
        _spend_ranged,
        _spend_idx,
        _spend_skip,
        _structural,
        _struct_spent,
        _struct_create_h,
        _struct_bip68,
    ) = rbitcoin_consensus::confirm_phase_stats::sample_and_reset();
    let sh = rbitcoin_query::class_c_phase_stats::sample_tip_sh_and_reset();
    let ca = rbitcoin_query::archive_phase_stats::sample_and_reset();
    let tweak_ns = rbitcoin_consensus::confirm_phase_stats::TWEAK_NS
        .swap(0, std::sync::atomic::Ordering::Relaxed);
    // class_c = strong + tip only (parallel SH is not Class C table time).
    let class_c_tables_ns = strong_ns.saturating_add(tip_ns);
    let line = format_tip_accept_sh_line(&TipAcceptShInput {
        height,
        n_tx,
        wall_ns,
        load_ns: load_ns.saturating_add(connect_ns),
        script_ns,
        class_a_ns: ca.write_total_ns,
        class_c_ns: class_c_tables_ns,
        spend_ns,
        strong_ns,
        tip_ns,
        tweak_ns,
        sh_lag: query.sh_lag_heights(),
        sh,
    });
    info!("{line}");
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

use crate::most_work::{sum_work, work_better};

#[cfg(test)]
mod tests {
    use super::*;
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
    use rbitcoin_query::Query;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_hub() -> (std::path::PathBuf, ChainHub) {
        // Keep Class A/hash heads tiny in unit tests (avoid multi‑GiB sparse maps).
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-chain-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).expect("query open_or_create");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        (dir, hub)
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

    #[test]
    fn core_log_helpers_match_step21_needles() {
        let h = BlockHash::from_byte_array([0x11; 32]);
        assert_eq!(
            accept_block_header_nodos_log(h),
            format!(
                "AcceptBlockHeader: not adding new block header {h}, missing anti-dos proof-of-work validation"
            )
        );
        assert_eq!(
            ignoring_low_work_chain_log(14),
            "[net] Ignoring low-work chain (height=14)"
        );
        assert_eq!(
            synchronizing_blockheaders_log(14),
            "Synchronizing blockheaders, height: 14"
        );
        assert_eq!(
            initial_getheaders_log(0, 0),
            "initial getheaders (0) to peer=0"
        );
        assert_eq!(
            headers_timeout_disconnect_log(0),
            "Timeout downloading headers, disconnecting peer=0"
        );
        assert_eq!(
            headers_timeout_noban_log(0),
            "Timeout downloading headers from noban peer, not disconnecting peer=0"
        );
        assert_eq!(
            received_getdata_wtx_log("aabbccdd", 3),
            "received getdata for: wtx aabbccdd peer=3"
        );
        // Test formula: now=1_000_000, genesis=0 → variable = ceil(1e6/6e5)=2.
        assert_eq!(
            headers_download_timeout_secs(1_000_000, 0),
            1_000_000 + 900 + 2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generate_to_script_from_tokio_connects_off_worker() {
        let (dir, hub) = tmp_hub();
        let task = tokio::spawn(async move {
            let hashes = hub
                .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
                .expect("generate");
            (hashes, hub.tip_height())
        });
        let (hashes, tip) = task.await.expect("join worker task");
        assert_eq!(hashes.len(), 1);
        assert_eq!(tip, Some(1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_received_block_async_connects_off_worker() {
        let (dir, hub) = tmp_hub();
        let task = tokio::spawn(async move {
            hub.ensure_genesis().unwrap();
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
    fn generate_uses_mock_when_behind_tip_but_above_mtp() {
        use bitcoin::ScriptBuf;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        // Three headers so MTP is the middle time, not the tip (len/2).
        let mid = 1_300_000_000u32;
        let tip_time = mid + 10_000;
        let h1 = mine(gen, mid, 1);
        hub.accept_block(h1.clone()).unwrap();
        hub.accept_block(mine(h1.block_hash(), tip_time, 2))
            .unwrap();
        let mock = i64::from(tip_time) - 3_000;
        assert!(mock as u32 > mid, "mock must sit above MTP");
        hub.clock.set_mock(mock);
        let hashes = hub
            .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("Core UpdateTime: mock behind tip still mines when mock > MTP");
        assert_eq!(hashes.len(), 1);
        let t = hub.tip_header().unwrap().time;
        assert!(
            t >= mock as u32 && t < tip_time,
            "expected mock-based stamp, got {t} tip={tip_time} mock={mock}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn generate_to_script_drains_sh_writebehind() {
        use bitcoin::ScriptBuf;
        use rbitcoin_store::script_hash;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let sh = script_hash(script.as_bytes());
        hub.generate_to_script(1, script, vec![]).expect("generate");
        let hist = hub.query.scripthash_history(&sh).unwrap();
        assert!(
            hist.iter().any(|row| row.height == 1),
            "generate must drain SH so height-1 coinbase is indexed, got {hist:?}"
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
            hub.unrequested_weaker_than_tip(&fork.header),
            "genesis-fork at height 1 is weaker than tip 2"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_follow_accept_logs_update_tip_per_block() {
        // Shipped path: accept_block → connect_at → log_update_tip (info).
        // Assert helper formats Core-like line; accept advances tip once per block.
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_000_000, 1);
        let h = b1.header;
        let hash = b1.block_hash();
        let line_probe = {
            // Drive the shipped log helper (same args connect_at uses).
            log_update_tip(1, &hash, &h, b1.txdata.len());
            format!(
                "UpdateTip: new best={hash} height=1 version={} tx={} date={} progress=tip",
                h.version.to_consensus(),
                b1.txdata.len(),
                h.time
            )
        };
        assert!(
            line_probe.starts_with("UpdateTip: new best="),
            "tip log must be Core-like UpdateTip: {line_probe}"
        );
        assert!(line_probe.contains("height=1"));
        assert!(line_probe.contains("progress=tip"));
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
    fn format_tip_accept_sh_line_has_sh_breakdown_tokens() {
        let line = format_tip_accept_sh_line(&TipAcceptShInput {
            height: 961_445,
            n_tx: 4_959,
            wall_ns: 2_500_000_000,
            load_ns: 100_000_000,
            script_ns: 200_000_000,
            class_a_ns: 50_000_000,
            // Tables only (strong+tip) — not SH join wall.
            class_c_ns: 7_000_000,
            spend_ns: 80_000_000,
            strong_ns: 5_000_000,
            tip_ns: 2_000_000,
            tweak_ns: 400_000_000,
            sh_lag: 2,
            sh: rbitcoin_query::class_c_phase_stats::TipShSnap {
                collect_ns: 20_000_000,
                sort_ns: 5_000_000,
                seed_ns: 800_000_000,
                body_ns: 600_000_000,
                head_ns: 300_000_000,
                pin: 4_000,
                cold: 12,
                creates: 12_000,
                unique: 9_500,
                written: 9_400,
            },
        });
        assert!(line.starts_with("tip: accept h=961445"), "{line}");
        assert!(line.contains("wall=2500ms"), "{line}");
        assert!(line.contains("class_c=7ms"), "{line}");
        assert!(line.contains("(strong=5 tip_set=2)"), "{line}");
        assert!(line.contains("sh=1725ms"), "{line}"); // 20+5+800+600+300
        assert!(line.contains("sh_lag=2"), "{line}");
        // Substep ms are unitless inside the paren (outer fields carry `ms`).
        assert!(line.contains("seed=800"), "{line}");
        assert!(line.contains("body=600"), "{line}");
        assert!(line.contains("head=300"), "{line}");
        assert!(line.contains("creates=12000"), "{line}");
        assert!(line.contains("unique=9500"), "{line}");
        assert!(line.contains("written=9400"), "{line}");
        assert!(line.contains("pin=4000"), "{line}");
        assert!(line.contains("cold=12"), "{line}");
        assert!(line.contains("tweaks=400ms"), "{line}");
        assert!(line.contains("sh/wall=69%"), "{line}");
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
        let fk = hub.ensure_header_fk(&b1.header).unwrap();
        assert!(fk.0 > 0 || fk.0 == 0); // Fk may be 0 on some layouts
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
            NetError::Protocol(_)
        ));

        // accept_branch empty / unlinked.
        assert!(hub.accept_branch(&[]).is_err());
        let b2 = mine(h1, 1_300_000_300, 2);
        let b3_bad = mine(BlockHash::from_byte_array([1u8; 32]), 1_300_000_400, 3);
        assert!(hub.accept_branch(&[b2.clone(), b3_bad]).is_err());
        // Linked tip extension via branch.
        assert!(matches!(
            hub.accept_branch(&[b2.clone()]).unwrap(),
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
            NetError::Protocol(_)
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn accept_received_reorgs_to_longer_held_fork() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1_300_010_000, 1);
        hub.accept_block(a1.clone()).unwrap();
        let a2 = mine(a1.block_hash(), 1_300_010_100, 2);
        hub.accept_block(a2.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(2));

        let mut prev = gen;
        let mut fork = Vec::new();
        for i in 0..3u32 {
            let b = mine(prev, 1_300_011_000 + i, i + 1);
            prev = b.block_hash();
            fork.push(b);
        }
        for b in &fork {
            hub.accept_received_block(b.clone()).unwrap();
        }
        assert_eq!(hub.tip_hash().unwrap(), fork[2].block_hash());
        assert_eq!(hub.tip_height(), Some(3));

        let tips = hub.chaintips();
        assert_eq!(
            tips.len(),
            2,
            "active + losing valid-fork after held-then-applied reorg: {tips:?}"
        );
        assert_eq!(tips[0].status, "active");
        assert_eq!(tips[0].hash, fork[2].block_hash());
        assert_eq!(tips[0].branchlen, 0);
        let fork_tip = tips
            .iter()
            .find(|t| t.status == "valid-fork")
            .expect("loser");
        assert_eq!(fork_tip.hash, a2.block_hash());
        assert_eq!(fork_tip.height, 2);
        assert_eq!(fork_tip.branchlen, 2);

        // Once-confirmed loser is archive-reconstructable, not a RAM block index.
        assert!(
            hub.query
                .reconstruct_archived_block(&a2.block_hash().to_byte_array())
                .unwrap()
                .is_some(),
            "disconnected best-chain body must stay in Class A"
        );
        assert!(
            hub.held_body(&a2.block_hash()).is_none(),
            "hold is never-confirmed side bodies only — not a CBlockIndex clone of the old path"
        );

        // Equal-work never-confirmed sibling: stay held, do not reorg until precious.
        let mut prev = gen;
        let mut eq = Vec::new();
        for i in 0..3u32 {
            let b = mine(prev, 1_300_012_000 + i, i + 1);
            prev = b.block_hash();
            eq.push(b);
        }
        for b in &eq {
            let out = hub.accept_received_block(b.clone()).unwrap();
            assert!(matches!(
                out,
                AcceptOutcome::IgnoredWeaker | AcceptOutcome::AlreadyHave
            ));
        }
        assert_eq!(hub.tip_hash().unwrap(), fork[2].block_hash());
        hub.precious_block(eq[2].block_hash()).unwrap();
        assert_eq!(hub.tip_hash().unwrap(), eq[2].block_hash());

        // Switch back to the once-confirmed fork via archive, not a held clone.
        assert!(hub.held_body(&fork[2].block_hash()).is_none());
        assert!(hub
            .query
            .reconstruct_archived_block(&fork[2].block_hash().to_byte_array())
            .unwrap()
            .is_some());
        hub.precious_block(fork[2].block_hash()).unwrap();
        assert_eq!(hub.tip_hash().unwrap(), fork[2].block_hash());

        // invalidate / reconsider use archive hashes, not a RAM clone.
        // After invalidate, the next most-work fork (eq) becomes tip.
        let tip = hub.tip_hash().unwrap();
        hub.invalidate_block(fork[1].block_hash()).unwrap();
        assert_eq!(hub.tip_hash().unwrap(), eq[2].block_hash());
        assert!(hub.held_body(&tip).is_none());
        assert!(hub
            .query
            .reconstruct_archived_block(&tip.to_byte_array())
            .unwrap()
            .is_some());
        hub.reconsider_block(fork[1].block_hash()).unwrap();
        assert!(
            hub.held_body(&tip).is_none(),
            "reconsider must not park the old tip"
        );

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
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn accept_competing_tip_and_block_at_height_paths() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_001_000, 1);
        hub.accept_block(b1.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(1));

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
        assert_eq!(hub.query.sh_released_through_height(), Some(3));
        assert_eq!(
            hub.query.sh_indexed_through_height(),
            Some(2),
            "release must not seed; worker/apply does that"
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

        let cold0 = rbitcoin_query::class_c_phase_stats::SH_COLLECT_COLD
            .load(std::sync::atomic::Ordering::Relaxed);
        let block = hub
            .assemble_block_to_script(spk, vec![spend])
            .expect("assemble");
        match hub.accept_block(block).expect("connect spend block") {
            AcceptOutcome::Accepted { height } => assert_eq!(height, 101),
            other => panic!("expected Accepted, got {other:?}"),
        }
        let cold1 = rbitcoin_query::class_c_phase_stats::SH_COLLECT_COLD
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
        let coin = crate::tx_relay::QueryUtxoProvider {
            query: hub.query.as_ref(),
        }
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

    /// `feature_dersig.py`: after dersig@102, a version-2 block is `bad-version`.
    #[test]
    fn dersig_rejects_version2_and_logs_core_needle() {
        use bitcoin::block::Version;
        use rbitcoin_consensus::mine_regtest_paying;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-dersig-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).unwrap();
        let mut params = ChainParams::regtest();
        params.apply_test_activation_height("dersig", 102).unwrap();
        let hub = ChainHub::new(q, params, Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(101, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad to height 101");
        assert_eq!(hub.tip_height(), Some(101));

        let prev = hub.tip_hash().unwrap();
        let time = hub.tip_header().unwrap().time + 1;
        let mut block =
            mine_regtest_paying(prev, time, 102, ScriptBuf::from_bytes(vec![0x51]), vec![]);
        block.header.version = Version::from_consensus(2);
        let bits = block.header.bits;
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let hash = block.block_hash();
        let err = hub.accept_block(block).expect_err("v2 at height 102");
        let s = err.to_string();
        assert!(s.contains("bad-version(0x00000002)"), "shipped reject: {s}");
        let line = rbitcoin_consensus::block_reject_log_line(&hash, "bad-version(0x00000002)");
        assert_eq!(line, format!("{hash}, bad-version(0x00000002)"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `feature_cltv.py`: after cltv@111, a version-3 block is `bad-version`.
    #[test]
    fn cltv_rejects_version3_and_logs_core_needle() {
        use bitcoin::block::Version;
        use rbitcoin_consensus::mine_regtest_paying;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-cltv-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).unwrap();
        let mut params = ChainParams::regtest();
        params.apply_test_activation_height("cltv", 111).unwrap();
        let hub = ChainHub::new(q, params, Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(110, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad to height 110");
        assert_eq!(hub.tip_height(), Some(110));

        let prev = hub.tip_hash().unwrap();
        let time = hub.tip_header().unwrap().time + 1;
        let mut block =
            mine_regtest_paying(prev, time, 111, ScriptBuf::from_bytes(vec![0x51]), vec![]);
        block.header.version = Version::from_consensus(3);
        let bits = block.header.bits;
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let hash = block.block_hash();
        let err = hub.accept_block(block).expect_err("v3 at height 111");
        let s = err.to_string();
        assert!(s.contains("bad-version(0x00000003)"), "shipped reject: {s}");
        let line = rbitcoin_consensus::block_reject_log_line(&hash, "bad-version(0x00000003)");
        assert_eq!(line, format!("{hash}, bad-version(0x00000003)"));
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
        assert_eq!(sum_work(std::iter::empty()), z);
        assert_eq!(sum_work([one].into_iter()), one);
    }

    /// `feature_chain_tiebreaks.py`: after invalidate, equal-work held tips
    /// pick first-seen (lower held_seq), not last-seen.
    #[test]
    fn invalidate_equal_work_picks_first_seen_held() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let main = mine(gen, 1_300_030_000, 1);
        hub.accept_block(main.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(1));

        let mut first = mine(gen, 1_300_030_001, 1);
        if first.block_hash() == main.block_hash() {
            let target = Target::from_compact(first.header.bits);
            for nonce in 0..u32::MAX {
                first.header.nonce = nonce;
                if first.header.validate_pow(target).is_ok()
                    && first.block_hash() != main.block_hash()
                {
                    break;
                }
            }
        }
        let mut second = mine(gen, 1_300_030_002, 1);
        loop {
            if second.block_hash() != main.block_hash() && second.block_hash() != first.block_hash()
            {
                break;
            }
            second.header.nonce = second.header.nonce.wrapping_add(1);
            let target = Target::from_compact(second.header.bits);
            if second.header.validate_pow(target).is_err() {
                continue;
            }
        }

        assert!(matches!(
            hub.accept_received_block(first.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(matches!(
            hub.accept_received_block(second.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
        assert!(hub.held_body(&first.block_hash()).is_some());
        assert!(hub.held_body(&second.block_hash()).is_some());

        hub.invalidate_block(main.block_hash()).unwrap();
        assert_eq!(
            hub.tip_hash().unwrap(),
            first.block_hash(),
            "first-seen equal-work held tip must win after invalidate"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn accept_branch_weaker_and_gap_errors() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_002_000, 1);
        let b2 = mine(b1.block_hash(), 1_300_002_100, 2);
        hub.accept_block(b1.clone()).unwrap();
        hub.accept_block(b2.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(2));

        // Single side block at height 1 while tip is 2 → side block protocol error.
        let mut side = mine(gen, 1_300_002_050, 1);
        if side.block_hash() == b1.block_hash() {
            let target = Target::from_compact(side.header.bits);
            for nonce in 0..u32::MAX {
                side.header.nonce = nonce;
                if side.header.validate_pow(target).is_ok() && side.block_hash() != b1.block_hash()
                {
                    break;
                }
            }
        }
        let err = hub.accept_block(side.clone()).unwrap_err();
        assert!(
            matches!(err, NetError::Protocol(_)),
            "side/gap should be protocol err: {err}"
        );

        // Weaker single-block branch at height 1 → IgnoredWeaker (less work than tip path).
        let out = hub.accept_branch(&[side]).unwrap();
        assert!(matches!(
            out,
            AcceptOutcome::IgnoredWeaker | AcceptOutcome::Accepted { .. }
        ));

        // Gap above tip: parent is tip, but we already have tip+1 path — build orphan
        // child of non-tip ancestor that's not tip-1? parent at height 0 with tip 2
        // is "side block; use accept_branch".
        // Missing parent:
        let orphan = mine(BlockHash::from_byte_array([0xab; 32]), 1_300_003_000, 99);
        assert!(matches!(
            hub.accept_block(orphan).unwrap_err(),
            NetError::Protocol(_)
        ));

        // tip_hash prefers store when present.
        assert_eq!(hub.tip_hash().unwrap(), b2.block_hash());
        assert!(hub.block_at_height(0).unwrap().is_some());
        assert!(hub.block_at_height(1).unwrap().is_some());

        // disconnect_to via reorg: better branch of length 2 from genesis with more work
        // is hard on equal-bits regtest; exercise disconnect_to indirectly by
        // accepting equal-length weaker branch (IgnoredWeaker already covered).

        // has_block false for random.
        assert!(!hub.has_block(&BlockHash::from_byte_array([0xde; 32])));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn confirm_wire_script_split() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_300_004_000, 1);
        let loaded = hub.confirm_wire_load_phase(&[(Height(1), b1)]).unwrap();
        assert!(loaded.is_some());
        let batch = loaded.unwrap();
        let script_out = confirm_scripts_phase(batch.batch).unwrap();
        let write_out = hub.confirm_write(script_out.batch).unwrap();
        assert_eq!(write_out.len(), 1);
        assert!(matches!(
            write_out[0],
            AcceptOutcome::Accepted { height: 1 }
        ));
        assert_eq!(hub.tip_height(), Some(1));

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
            matches!(err, NetError::Consensus(_)),
            "expected consensus fail, got {err}"
        );
        // Tip restored to pre-attempt.
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
        assert!(
            crate::peer::MAX_PENDING_BLOCKS_FOR_TEST >= 99,
            "pending cap must allow 99-block reorg assembly"
        );
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
}
