//! Dedicated confirm engine (Class C tip walk) for IBD.

use super::body::BodyPresence;
use super::status::LoopStats;
use crate::chain::ChainHub;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_consensus::WireLoadPipeline;
use rbitcoin_log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Load-thread pipeline caches so load(N+1) can run while write(N) has not advanced tip.
///
/// In-flight creates are one [`rbitcoin_query::InFlight`] map this thread owns:
/// stamp/pin borrow it, then [`rbitcoin_query::InFlight::note_pins`] inserts the
/// current pack.
struct LoadAheadState {
    next_tx_start: u64,
    in_flight: rbitcoin_query::InFlight,
    /// Last height successfully loaded (still in pipeline or already committed).
    last_loaded: Option<(u32, [u8; 32])>,
    /// Last applied [`Query::take_disconnect`] generation.
    disconnect_gen_seen: u64,
}

impl LoadAheadState {
    fn new(hub: &ChainHub) -> Self {
        let next = hub.query.tx_body_count().saturating_add(1).max(1);
        Self {
            next_tx_start: next,
            in_flight: rbitcoin_query::InFlight::new(),
            last_loaded: None,
            disconnect_gen_seen: 0,
        }
    }

    /// Drop reorged packs **before** bind so disconnected creates cannot stamp.
    fn apply_disconnect(&mut self, hub: &ChainHub) {
        if let Some(h) = hub.query.take_disconnect(&mut self.disconnect_gen_seen) {
            self.in_flight.drop_from_height(h);
            self.publish_mem_stats();
        }
    }

    /// Drop packs whose height is below a lookup-wave drain+fence snapshot.
    ///
    /// Call after this load batch has finished its in-flight read (stamp).
    fn drop_inflight_below(&mut self, hi: Option<u32>) {
        self.in_flight.prune_below_height(hi);
        self.publish_mem_stats();
    }

    /// Advance create-fk HWM from published body; clear last_loaded once on tip.
    fn sync_body_hwm(&mut self, hub: &ChainHub) {
        let body_n = hub.query.tx_body_count();
        self.next_tx_start = self.next_tx_start.max(body_n.saturating_add(1).max(1));
        if let Some((h, _)) = self.last_loaded {
            let tip = hub.tip_height().unwrap_or(0);
            if h <= tip {
                self.last_loaded = None;
            }
        }
    }

    /// Publish InFlight occupancy for `ibd: sizes`.
    fn publish_mem_stats(&self) {
        let (layers, pins, if_bytes) = self.in_flight.size_snapshot();
        rbitcoin_query::process_mem_stats::note(layers, pins, if_bytes);
    }

    fn pipeline_for(
        &self,
        path_lo: u32,
        store_path_lo: u32,
        skeleton: Option<rbitcoin_query::BatchParentIds>,
    ) -> WireLoadPipeline<'_> {
        let parent_hash = if path_lo == store_path_lo {
            None
        } else {
            self.last_loaded
                .filter(|(h, _)| *h + 1 == path_lo)
                .map(|(_, hash)| hash)
        };
        WireLoadPipeline {
            path_lo,
            parent_hash,
            next_tx_start: self.next_tx_start,
            in_flight: &self.in_flight,
            skeleton,
        }
    }

    fn note_lookup_ok(
        &mut self,
        plan: &rbitcoin_query::ArchiveWritePlan,
        last_height: u32,
        last_hash: [u8; 32],
    ) {
        if plan.batch_pin.len() == plan.planned_fks.len() {
            self.in_flight.note_pins(
                plan.planned_fks
                    .iter()
                    .zip(plan.batch_pin.iter())
                    .map(|(fk, pin)| (*fk, pin)),
                Some(last_height),
            );
        } else {
            self.in_flight.note_pins(
                plan.packed
                    .iter()
                    .zip(plan.planned_fks.iter())
                    .map(|((pin, _), fk)| (*fk, pin)),
                Some(last_height),
            );
        }
        if let Some(last) = plan.planned_fks.last().and_then(|f| f.get()) {
            self.next_tx_start = last.saturating_add(1).max(1);
        }
        self.last_loaded = Some((last_height, last_hash));
        self.publish_mem_stats();
    }

    /// Publish already-archived create txid→fk for tip-ahead stamp (plan=None packs).
    ///
    /// Without this, lookup(N+k) cannot resolve parents in N..N+k-1 that already
    /// have Class A body but are mid-head-insert / not yet head-probeable, and
    /// stamp fails with `parent create_fk unresolved` (permanent tip blacklist).
    fn note_archived_creates(&mut self, hub: &ChainHub, heights_hashes: &[(u32, BlockHash)]) {
        let mut pairs: Vec<([u8; 32], rbitcoin_primitives::Fk)> = Vec::new();
        let mut max_fk = 0u64;
        for &(h, hash) in heights_hashes {
            let Ok(Some((hfk, _))) = hub.query.get_header_by_hash(&hash.to_byte_array()) else {
                continue;
            };
            let Ok(Some(fks)) = hub.query.store().header_txs.get_list(hfk) else {
                continue;
            };
            for fk in fks {
                let Some(id) = fk.get() else { continue };
                max_fk = max_fk.max(id);
                let Ok(tid) = hub.query.store().txs.body_txid(fk) else {
                    continue;
                };
                if tid != [0u8; 32] {
                    pairs.push((tid, fk));
                }
            }
            let _ = h;
        }
        if pairs.is_empty() {
            return;
        }
        if let Some((_, last_id)) = pairs
            .iter()
            .filter_map(|(_, f)| f.get().map(|id| ((), id)))
            .max_by_key(|(_, id)| *id)
        {
            self.next_tx_start = last_id.saturating_add(1).max(1);
        }
        let _ = max_fk;
        let max_height = heights_hashes.iter().map(|(h, _)| *h).max();
        self.in_flight.note_creates(pairs, max_height);
        if let Some(&(h, hash)) = heights_hashes.last() {
            self.last_loaded = Some((h, hash.to_byte_array()));
        }
        self.publish_mem_stats();
    }

    fn clear_all(&mut self, hub: &ChainHub) {
        self.in_flight.clear();
        self.publish_mem_stats();
        self.last_loaded = None;
        self.next_tx_start = hub.query.tx_body_count().saturating_add(1).max(1);
    }
}

/// Shared feed of tip-extension **readiness** for the dedicated confirm engine.
///
/// **Sole intake:** peer/rehydrate enqueues wire into the **body queue**, then
/// notes height/hash here. Lookup/load reload wire from the body queue — the feed
/// does **not** retain `Block`s. Class A alone is never enough (no hash-only
/// confirm). Tip-follow reorgs use peer wire via `ChainHub::accept_block`.
///
/// Optional wire slots remain for rare in-process requeue; production requeues
/// strip wire so RAM stays in the body queue + pipeline stage batches only.
///
/// **In-flight tracking:** once lookup claims a contiguous run, those heights sit
/// in `inflight` until write finishes (or re-queue). `note` will not re-insert
/// them — otherwise offer re-notes tip+1 every main-loop tick and lookup
/// re-claims the same batch (duplicate work).
pub(crate) struct ConfirmFeed {
    pub(crate) inner: std::sync::Mutex<ConfirmFeedInner>,
    pub(crate) cv: std::sync::Condvar,
    stop: AtomicBool,
    /// Bumped by [`Self::clear`] so in-channel batches claimed earlier are dropped.
    epoch: AtomicU64,
    /// Next lookup wave claims one height (isolate a multi-block consensus fail).
    force_single: AtomicBool,
}

pub(crate) struct ConfirmFeedInner {
    /// height → (hash, optional wire — normally `None`; body queue holds payloads)
    pub(crate) ready: std::collections::BTreeMap<u32, (BlockHash, Option<bitcoin::Block>)>,
    /// Claimed by load; not yet written or released. Offer must not re-note.
    pub(crate) inflight: std::collections::HashSet<u32>,
    /// Height → lookup epoch when load claimed it (survives [`Self::clear`]).
    claimed_epoch: HashMap<u32, u64>,
}

impl ConfirmFeed {
    pub(crate) fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(ConfirmFeedInner {
                ready: std::collections::BTreeMap::new(),
                inflight: std::collections::HashSet::new(),
                claimed_epoch: HashMap::new(),
            }),
            cv: std::sync::Condvar::new(),
            stop: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            force_single: AtomicBool::new(false),
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// True when a claimed plan's lookup epoch is behind a later [`Self::clear`].
    pub(crate) fn plan_epoch_stale(&self, first_h: u32) -> bool {
        let live = self.epoch();
        let g = self.inner.lock().unwrap();
        g.claimed_epoch.get(&first_h).is_some_and(|&e| e != live)
    }

    pub(crate) fn request_single_block(&self) {
        self.force_single.store(true, Ordering::Release);
    }

    pub(crate) fn single_block(&self) -> bool {
        self.force_single.load(Ordering::Acquire)
    }

    /// Note readiness (wire lives in the body queue — denserels reloads it).
    pub(crate) fn note(&self, height: u32, hash: BlockHash) {
        self.note_wire(height, hash, None);
    }

    /// Note readiness; optional wire is only for tests / rare in-process paths.
    /// Production peer path uses [`Self::note`] (wire lives in the body queue).
    pub(crate) fn note_wire(&self, height: u32, hash: BlockHash, block: Option<bitcoin::Block>) {
        let mut g = self.inner.lock().unwrap();
        if g.inflight.contains(&height) {
            return;
        }
        match g.ready.get_mut(&height) {
            Some(e) => {
                if e.1.is_none() && block.is_some() {
                    e.1 = block;
                }
            }
            None => {
                g.ready.insert(height, (hash, block));
            }
        }
        self.cv.notify_one();
    }

    pub(crate) fn notify(&self) {
        self.cv.notify_all();
    }

    /// Return heights to the ready map (optionally with wire bodies).
    pub(crate) fn requeue_wire(&self, batch: &[(u32, BlockHash, Option<bitcoin::Block>)]) {
        if batch.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        for &(h, hash, ref block) in batch {
            g.inflight.remove(&h);
            let b = block.clone();
            match g.ready.get_mut(&h) {
                Some(e) => {
                    if e.1.is_none() {
                        e.1 = b;
                    }
                }
                None => {
                    g.ready.insert(h, (hash, b));
                }
            }
        }
        self.cv.notify_one();
    }

    /// Write (or permanent reject) finished — height may be re-offered only after
    /// tip moves past it (or a future requeue path).
    pub(crate) fn finish(&self, heights: impl IntoIterator<Item = u32>) {
        let mut g = self.inner.lock().unwrap();
        for h in heights {
            g.inflight.remove(&h);
            g.claimed_epoch.remove(&h);
        }
        drop(g);
        self.cv.notify_one();
    }

    /// Drop ready + inflight so a rewind cannot commit a stale plan.
    ///
    /// Bumps [`Self::epoch`] so load/scripts/write still holding a pre-rewind
    /// batch (not in `ready`/`inflight`) will drop it. `claimed_epoch` is kept
    /// so those in-channel batches can see they are stale.
    pub(crate) fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.ready.clear();
        g.inflight.clear();
        drop(g);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.force_single.store(false, Ordering::Release);
        self.cv.notify_all();
    }

    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// `(ready_heights, inflight_heights)` — O(1) under feed mutex.
    pub(crate) fn size_snap(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.ready.len(), g.inflight.len())
    }
}

/// How IBD treats a confirm-engine reject (computed at the sender).
///
/// Only [`Self::ConsensusInvalid`] blacklists a hash. Weaker header chains
/// are never a reject class — they are `IgnoreWeaker` at selection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmRejectClass {
    /// Block failed a consensus rule against its intended parent.
    ConsensusInvalid,
    /// Wire / reconstruct mismatch: merkle, witness, BadPrev, retarget context.
    SoftWire,
    /// Stale plan after tip moved (`fk mismatch`, height not tip+1).
    Cascade,
    /// Store/pipeline invariant (not a block rule). Requeue once, then halt.
    EngineFault,
    /// Cooperative abort — not a block reject.
    Cancelled,
}

impl ConfirmRejectClass {
    /// Substring map for legacy reject strings. Unknown → [`Self::Cascade`]
    /// (requeue, never blacklist).
    pub(crate) fn from_err_str(err: &str) -> Self {
        let s = err.to_ascii_lowercase();
        if s.contains("confirm cancelled") || s.contains("cancelled:") {
            return Self::Cancelled;
        }
        if super::reorg::is_bad_prev_err(err) {
            return Self::SoftWire;
        }
        if s.contains("merkle root mismatch")
            || s.contains("bad-txnmrklroot")
            || s.contains("witness commitment")
        {
            return Self::SoftWire;
        }
        if s.contains("missing retarget first header") {
            return Self::SoftWire;
        }
        if s.contains("fk mismatch")
            || s.contains("plan not committed in order")
            || s.contains("connect height not tip+1")
        {
            return Self::Cascade;
        }
        if rbitcoin_store::StoreError::is_uring_session_fault_msg(&s) {
            return Self::EngineFault;
        }
        if s.contains("parent create_fk unresolved")
            || s.contains("spend annotate missing pin denserels")
            || s.contains("corrupt record")
            || s.contains("io error")
        {
            return Self::EngineFault;
        }
        if s.contains("script verification")
            || s.contains("prevout already spent")
            || s.contains("pow invalid")
            || s.contains("bad-version")
            || s.contains("bad transaction")
            || s.contains("bad block")
            || s.contains("bad header")
            || s.contains("missing prevout")
        {
            return Self::ConsensusInvalid;
        }
        Self::Cascade
    }

    pub(crate) fn from_consensus(err: &rbitcoin_consensus::ConsensusError) -> Self {
        use rbitcoin_consensus::ConsensusError;
        use rbitcoin_store::StoreError;
        match err {
            ConsensusError::Cancelled => Self::Cancelled,
            ConsensusError::BadPrev => Self::SoftWire,
            ConsensusError::BadBlock("merkle root mismatch") => Self::SoftWire,
            ConsensusError::BadHeader("missing retarget first header") => Self::SoftWire,
            ConsensusError::BadBlock(_)
            | ConsensusError::BadTx(_)
            | ConsensusError::Script(_)
            | ConsensusError::PrevoutSpent
            | ConsensusError::InvalidPow
            | ConsensusError::BadVersion(_)
            | ConsensusError::BadHeader(_)
            | ConsensusError::MissingPrevout => Self::ConsensusInvalid,
            ConsensusError::Store(StoreError::Cancelled(_)) => Self::Cancelled,
            ConsensusError::Store(e) if e.is_uring_session_fault() => Self::EngineFault,
            ConsensusError::Store(StoreError::Io { .. }) => Self::EngineFault,
            ConsensusError::Store(StoreError::Corrupt(m)) => Self::from_err_str(m),
            ConsensusError::Store(_) => Self::EngineFault,
        }
    }

    pub(crate) fn from_net(err: &crate::error::NetError) -> Self {
        match err {
            crate::error::NetError::Cancelled => Self::Cancelled,
            crate::error::NetError::Mutated(_) => Self::SoftWire,
            crate::error::NetError::BadPrev => Self::SoftWire,
            crate::error::NetError::ConnectFailed { msg, .. } => Self::from_err_str(msg),
            crate::error::NetError::Consensus(s) => Self::from_err_str(s),
            other => Self::from_err_str(&other.to_string()),
        }
    }

    pub(crate) fn is_soft(self) -> bool {
        matches!(self, Self::SoftWire)
    }

    /// Consensus verdict is only trusted when the connect ran against the
    /// intended parent (`tip == header.prev`). Otherwise this is a cascade.
    pub(crate) fn trust_consensus(self, hub: &ChainHub, hash: BlockHash) -> Self {
        if self != Self::ConsensusInvalid {
            return self;
        }
        match super::reorg::parent_hash_of(hub, hash) {
            Ok(Some(prev)) if hub.tip_hash() == Some(prev) => Self::ConsensusInvalid,
            Ok(Some(_)) => Self::Cascade,
            // Unknown header: tests use dummy hashes; production bodies have a
            // header row. Keep the typed consensus class.
            Ok(None) => Self::ConsensusInvalid,
            // Store / IO looking up the parent is not a block rule.
            Err(_) => Self::Cascade,
        }
    }

    /// Multi-block waves attribute rejects to the first hash. Do not blacklist
    /// that hash — isolate by retrying one block at a time.
    pub(crate) fn isolate_if_batched(self, batch_len: usize) -> Self {
        if self == Self::ConsensusInvalid && batch_len > 1 {
            Self::Cascade
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteStoreFault {
    Requeue,
    Abort,
    Reject(ConfirmRejectClass),
}

pub(crate) fn classify_write_store_fault(
    e: &rbitcoin_consensus::ConsensusError,
    recover: Option<rbitcoin_query::UringRecover>,
) -> WriteStoreFault {
    match recover {
        Some(rbitcoin_query::UringRecover::Recovered) => WriteStoreFault::Requeue,
        Some(rbitcoin_query::UringRecover::Exhausted) => WriteStoreFault::Abort,
        None => WriteStoreFault::Reject(ConfirmRejectClass::from_consensus(e)),
    }
}

pub(crate) fn apply_write_store_fault(
    feed: &ConfirmFeed,
    heights: &[(u32, [u8; 32])],
    action: WriteStoreFault,
    load_ahead_reset: &AtomicBool,
) {
    match action {
        WriteStoreFault::Requeue => {
            load_ahead_reset.store(true, Ordering::Release);
            let batch: Vec<_> = heights
                .iter()
                .map(|(h, raw)| (*h, BlockHash::from_byte_array(*raw), None))
                .collect();
            feed.requeue_wire(&batch);
        }
        WriteStoreFault::Abort => {}
        WriteStoreFault::Reject(_) => {
            load_ahead_reset.store(true, Ordering::Release);
            feed.finish(heights.iter().map(|(h, _)| *h));
        }
    }
}

fn try_uring_recover(
    query: &rbitcoin_query::Query,
    e: &rbitcoin_consensus::ConsensusError,
    reason: &'static str,
) -> Option<rbitcoin_query::UringRecover> {
    if !e.is_uring_session_fault() {
        return None;
    }
    Some(query.uring_recover(reason))
}

fn try_uring_recover_msg(
    query: &rbitcoin_query::Query,
    msg: &str,
    reason: &'static str,
) -> Option<rbitcoin_query::UringRecover> {
    if !rbitcoin_store::StoreError::is_uring_session_fault_msg(msg) {
        return None;
    }
    Some(query.uring_recover(reason))
}

pub(crate) fn lookup_ready_hash(feed: &ConfirmFeed, height: u32) -> Option<BlockHash> {
    feed.inner
        .lock()
        .ok()
        .and_then(|g| g.ready.get(&height).map(|(h, _)| *h))
}

const LOOKUP_FAULT_HALT_AFTER: u32 = 8;

#[derive(Debug, Default)]
pub(crate) struct LookupFaultPolicy {
    consecutive: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LookupFaultAction {
    Ignore,
    RecoverContinue,
    Abort,
    Warn,
    RejectEngineFault,
}

impl LookupFaultPolicy {
    pub(crate) fn on_success(&mut self) {
        self.consecutive = 0;
    }

    pub(crate) fn on_err(
        &mut self,
        e: &rbitcoin_consensus::ConsensusError,
        recover: Option<rbitcoin_query::UringRecover>,
    ) -> LookupFaultAction {
        use rbitcoin_consensus::ConsensusError;
        let backpressure = matches!(e, ConsensusError::Store(se) if se.is_io_backpressure());
        if backpressure {
            return LookupFaultAction::Ignore;
        }
        match recover {
            Some(rbitcoin_query::UringRecover::Recovered) => {
                self.consecutive = 0;
                LookupFaultAction::RecoverContinue
            }
            Some(rbitcoin_query::UringRecover::Exhausted) => LookupFaultAction::Abort,
            None => {
                self.consecutive = self.consecutive.saturating_add(1);
                if self.consecutive >= LOOKUP_FAULT_HALT_AFTER {
                    LookupFaultAction::RejectEngineFault
                } else {
                    LookupFaultAction::Warn
                }
            }
        }
    }
}

static LOOKUP_WAVE_FAULTS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn take_lookup_wave_faults() -> u64 {
    LOOKUP_WAVE_FAULTS.swap(0, Ordering::Relaxed)
}

pub(crate) enum ConfirmEvent {
    /// Tip advanced; hash is the confirmed block.
    Accepted { hash: BlockHash },
    /// Height is the attempted confirm height (for operator logs).
    Reject {
        height: u32,
        hash: BlockHash,
        class: ConfirmRejectClass,
        err: String,
        /// Heights in the failing wave. `> 1` means the hash is the batch
        /// first, not necessarily the failing block.
        batch_len: usize,
    },
}

fn emit_confirm_reject(
    tx: &std::sync::mpsc::Sender<ConfirmEvent>,
    feed: &ConfirmFeed,
    height: u32,
    hash: BlockHash,
    class: ConfirmRejectClass,
    err: String,
    batch_len: usize,
) -> Result<(), std::sync::mpsc::SendError<ConfirmEvent>> {
    let class = class.isolate_if_batched(batch_len);
    if class == ConfirmRejectClass::Cascade && batch_len > 1 {
        feed.request_single_block();
    }
    tx.send(ConfirmEvent::Reject {
        height,
        hash,
        class,
        err,
        batch_len,
    })
}

/// Hard cap on consecutive ready heights in one confirm wave.
///
/// Primary bound is soft **input** budget ([`confirm_batch_max_inputs`]); this
/// caps how many thin early-chain blocks pack into one lookup/load/script wave.
pub(crate) const CONFIRM_RUN_MAX_BLOCKS: usize = 144;

/// Default soft max Σ `tx.input` over a packed confirm run.
pub(crate) const CONFIRM_BATCH_INPUTS_DEFAULT: u32 = 8000;

/// How far ahead of tip to pre-note ready bodies into the feed.
/// ≥ [`CONFIRM_RUN_MAX_BLOCKS`] so the engine can fill a full hard-cap wave.
const OFFER_AHEAD: u32 = 192;

/// Soft max inputs per confirm batch (hardcoded production default).
#[inline]
pub(crate) fn confirm_batch_max_inputs() -> u32 {
    CONFIRM_BATCH_INPUTS_DEFAULT
}

/// Σ `tx.input.len()` over a decoded block (confirm pack work meter).
pub(crate) fn block_input_count(block: &bitcoin::Block) -> u32 {
    block
        .txdata
        .iter()
        .map(|tx| tx.input.len() as u32)
        .fold(0u32, u32::saturating_add)
}

/// Whether the packed run should stop **after** accepting a block that left
/// `sum_inputs` / `n_blocks` in this state (soft overshoot + hard block cap).
#[inline]
pub(crate) fn pack_stop_after(
    sum_inputs: u32,
    n_blocks: usize,
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> bool {
    n_blocks >= hard_max_blocks || sum_inputs > soft_max_inputs
}

/// Default lookup→load depth (`loadq`): prefetch of load-sized batches.
pub(crate) const LOAD_QUEUE_CAP_DEFAULT: usize = 14;
/// Default load→scripts depth (`scriptq`): script is the long pole; modest buffer.
pub(crate) const SCRIPT_QUEUE_CAP_DEFAULT: usize = 4;
/// Default scripts→write depth: write is bursty (class_a head / tip flush); buffer
/// script output so script thr does not stall on a full writeq.
pub(crate) const WRITE_QUEUE_CAP_DEFAULT: usize = 14;

/// One load-sized run produced by lookup (decoded wire + pres, height-ordered).
pub(crate) struct LoadBatch {
    pub items: Vec<(u32, [u8; 32], rbitcoin_query::ResolvedWire)>,
    pub parent_ids: Option<rbitcoin_query::BatchParentIds>,
    /// Drain+fence height snapshotted before this lookup wave's TipOnly.
    /// `Some` only on the last sent batch of the wave; load drops in-flight
    /// layers with `max_height` below this after the in-flight read.
    pub drop_inflight_below: Option<u32>,
    /// [`ConfirmFeed::epoch`] when lookup built this batch.
    pub epoch: u64,
}

/// Stamp inputs for one loadq run. Lookup `pres` must ride through (`Some`);
/// load must not drop it and `from_tx` again.
pub(crate) fn load_stamp_items(
    items: impl IntoIterator<
        Item = (
            u32,
            std::sync::Arc<bitcoin::Block>,
            std::sync::Arc<[rbitcoin_query::TxPrecompute]>,
        ),
    >,
) -> Vec<(
    rbitcoin_primitives::Height,
    std::sync::Arc<bitcoin::Block>,
    Option<std::sync::Arc<[rbitcoin_query::TxPrecompute]>>,
)> {
    items
        .into_iter()
        .map(|(h, block, pres)| (rbitcoin_primitives::Height(h), block, Some(pres)))
        .collect()
}

/// Split a lookup-wave into load-sized batch lengths.
///
/// Stops on [`pack_stop_after`] (soft 8000 / hard 144) and when `has_body` flips.
/// `has_body` is per height, same order as `input_counts`. Empty skips the kind split.
pub(crate) fn split_wave_into_load_batches_kind(
    input_counts: &[u32],
    has_body: &[bool],
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> Vec<usize> {
    debug_assert!(has_body.is_empty() || has_body.len() == input_counts.len());
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < input_counts.len() {
        let rest = &input_counts[i..];
        let kind0 = has_body.get(i).copied();
        let mut sum = 0u32;
        let mut n = 0usize;
        for (j, &c) in rest.iter().enumerate() {
            if j > 0 {
                if let (Some(k0), Some(&k)) = (kind0, has_body.get(i + j)) {
                    if k != k0 {
                        break;
                    }
                }
            }
            sum = sum.saturating_add(c);
            n += 1;
            if pack_stop_after(sum, n, soft_max_inputs, hard_max_blocks) {
                break;
            }
        }
        if n == 0 {
            break;
        }
        out.push(n);
        i += n;
    }
    out
}

/// Per-chunk need-vouts for a load batch (shared wave ids/spent).
pub(crate) fn chunk_parent_ids(
    wave: &rbitcoin_query::BatchParentIds,
    items: &[(u32, [u8; 32], rbitcoin_query::ResolvedWire)],
) -> rbitcoin_query::BatchParentIds {
    let mut need_vouts: rbitcoin_query::U64Map<Vec<u32>> = rbitcoin_query::U64Map::default();
    for (_, _, w) in items {
        for tx in &w.block.txdata {
            for inp in &tx.input {
                if inp.previous_output.is_null() {
                    continue;
                }
                let prev = inp.previous_output.txid.to_byte_array();
                if let Some((fk, _)) = wave.ids.get(&prev) {
                    if let Some(id) = fk.get() {
                        need_vouts
                            .entry(id)
                            .or_default()
                            .push(inp.previous_output.vout);
                    }
                }
            }
        }
    }
    for vouts in need_vouts.values_mut() {
        vouts.sort_unstable();
        vouts.dedup();
    }
    rbitcoin_query::BatchParentIds {
        ids: std::sync::Arc::clone(&wave.ids),
        spent: std::sync::Arc::clone(&wave.spent),
        need_vouts,
    }
}

/// Chunk a lookup wave into loadq batches; mark the last sent with `drop_below`.
pub(crate) fn load_batches_from_wave(
    items: &[(u32, [u8; 32], rbitcoin_query::ResolvedWire)],
    parts: &[usize],
    remaining: usize,
    wave_ids: &rbitcoin_query::BatchParentIds,
    drop_below: Option<u32>,
) -> Vec<LoadBatch> {
    let mut out = Vec::new();
    let mut i = 0usize;
    for &n in parts {
        if out.len() >= remaining {
            break;
        }
        let end = i.saturating_add(n).min(items.len());
        if i >= end {
            break;
        }
        let chunk = &items[i..end];
        out.push(LoadBatch {
            items: chunk.to_vec(),
            parent_ids: Some(chunk_parent_ids(wave_ids, chunk)),
            drop_inflight_below: None,
            epoch: 0,
        });
        i = end;
    }
    if let Some(last) = out.last_mut() {
        last.drop_inflight_below = drop_below;
    }
    out
}

/// Resolved lookup→load / script / write queue capacities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConfirmQueueCaps {
    /// lookup→load (`loadq`)
    pub load: usize,
    /// load→scripts (`scriptq`)
    pub script: usize,
    /// scripts→write (`writeq`)
    pub write: usize,
}

/// Per-stage confirm pipeline queue capacities (hardcoded production defaults).
///
/// | Queue | Default |
/// |-------|---------|
/// | lookup→load (`loadq`) | **14** |
/// | load→scripts (`scriptq`) | **4** |
/// | scripts→write (`writeq`) | **14** |
///
/// Env overrides removed (Q-04): change defaults in code if needed.
#[inline]
pub(crate) fn confirm_queue_caps() -> ConfirmQueueCaps {
    ConfirmQueueCaps {
        load: LOAD_QUEUE_CAP_DEFAULT,
        script: SCRIPT_QUEUE_CAP_DEFAULT,
        write: WRITE_QUEUE_CAP_DEFAULT,
    }
}

/// Lookup→load (`loadq`) capacity.
pub(crate) fn load_queue_cap() -> usize {
    confirm_queue_caps().load
}
/// Load→scripts (`scriptq`) capacity.
pub(crate) fn script_queue_cap() -> usize {
    confirm_queue_caps().script
}
/// Scripts→write (`writeq`) capacity.
pub(crate) fn write_queue_cap() -> usize {
    confirm_queue_caps().write
}

/// How many script-ok parts write may merge in one `confirm_write_phase`.
///
/// Snapshot-drain: take everything already in `writeq` before work starts
/// so one `flush_class_c_tip` covers the queued run and scripts see an empty
/// queue while write runs. Does not pull more parts mid-write.
#[inline]
pub(crate) fn write_drain_max_parts(writeq_cap: usize) -> usize {
    writeq_cap.max(1)
}

/// Max heights claimable ahead of tip+1 (pipeline depth).
///
/// Lookup may start the next run while load/scripts/write hold earlier ones,
/// but must **not** skip a stuck tip+1 and claim thousands of far heights.
/// Depth units = sum of stage caps (write is usually largest).
#[cfg(test)]
fn max_claim_ahead() -> u32 {
    let c = confirm_queue_caps();
    let q = c.load.saturating_add(c.script).saturating_add(c.write);
    (q.saturating_mul(3).saturating_add(1) as u32).saturating_mul(CONFIRM_RUN_MAX_BLOCKS as u32)
}

/// BQ heights ≥ `path_lo` with resolve-complete and not load-inflight.
pub(crate) fn confirm_ready_count(
    query: &rbitcoin_query::Query,
    path_lo: u32,
    inflight: &std::collections::HashSet<u32>,
) -> usize {
    query
        .block_queue_list_meta()
        .into_iter()
        .filter(|m| m.height >= path_lo && !inflight.contains(&m.height) && m.resolve_complete)
        .count()
}

/// Live depths **and contents** of the bounded confirm pipeline queues.
///
/// Updated on successful send/recv so the status loop can log pressure and
/// process-owned retain without peeking into the OS channels.
///
/// High-water marks (`*_hwm`) track max depth since the last
/// [`ConfirmQueueDepths::sample_hwm_and_reset`] (≈5s status tick). Point
/// samples alone almost always show 0 under a lookup-limited pipeline.
#[derive(Debug, Default)]
pub(crate) struct ConfirmQueueDepths {
    /// lookup → load (`loadq`; capacity [`load_queue_cap`]).
    lookup_to_load: AtomicUsize,
    /// Max loadq depth since last HWM sample.
    load_hwm: AtomicUsize,
    /// Sum of `batch.len()` sitting in loadq.
    load_blocks: AtomicUsize,
    /// Approx decoded wire bytes sitting in loadq.
    load_wire_bytes: AtomicUsize,
    /// load → scripts (`scriptq`; capacity [`script_queue_cap`]).
    load_to_scripts: AtomicUsize,
    /// scripts → write (`writeq`; capacity [`write_queue_cap`]).
    scripts_to_write: AtomicUsize,
    /// Max load→scripts depth since last HWM sample.
    script_hwm: AtomicUsize,
    /// Max scripts→write depth since last HWM sample.
    write_hwm: AtomicUsize,
    /// Sum of `batch.len()` sitting in load→scripts.
    script_blocks: AtomicUsize,
    /// Sum of approx wire bytes of load→scripts batches.
    script_wire_bytes: AtomicUsize,
    /// Sum of `BatchParents` entries riding load→scripts batches.
    script_parents: AtomicUsize,
    /// Sum of `batch.len()` sitting in scripts→write.
    write_blocks: AtomicUsize,
    write_wire_bytes: AtomicUsize,
    /// Sum of `BatchParents` entries in scripts→write (entry count, not unique Arc).
    write_parents: AtomicUsize,
}

/// Snapshot of confirm pipeline retain (queue depths + batch contents + feed).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConfirmPipelineSizes {
    /// lookup→load batches (`loadq`).
    pub load_batches: usize,
    pub load_blocks: usize,
    pub load_wire_bytes: usize,
    /// BQ resolve-complete leftover (not a queue; unused after loadq).
    pub ready: usize,
    pub script_batches: usize,
    pub script_blocks: usize,
    pub script_wire_bytes: usize,
    pub script_parents: usize,
    pub write_batches: usize,
    pub write_blocks: usize,
    pub write_wire_bytes: usize,
    pub write_parents: usize,
    pub feed_ready: usize,
    pub feed_inflight: usize,
}

impl ConfirmPipelineSizes {
    /// Parent entries sitting in scriptq + writeq (pipeline-wide, no budget).
    #[inline]
    pub fn parents_total(&self) -> usize {
        self.script_parents.saturating_add(self.write_parents)
    }
}

/// Format one confirm pipeline queue slot for logs.
///
/// Depth 0 uses `name<0/cap` (next worker waiting on an empty queue);
/// otherwise `name=n/cap`.
#[inline]
pub(crate) fn format_queue_depth(name: &str, depth: usize, cap: usize) -> String {
    if depth == 0 {
        format!("{name}<0/{cap}")
    } else {
        format!("{name}={depth}/{cap}")
    }
}

/// Confirm pipeline: real `loadq` / `scriptq` / `writeq`.
///
/// Depth 0 uses `name<0/cap` (consumer waiting on empty queue).
#[inline]
pub(crate) fn format_conf_q(
    load: usize,
    script: usize,
    write: usize,
    load_cap: usize,
    script_cap: usize,
    write_cap: usize,
) -> String {
    format!(
        "{} {} {}",
        format_queue_depth("loadq", load, load_cap),
        format_queue_depth("scriptq", script, script_cap),
        format_queue_depth("writeq", write, write_cap),
    )
}

impl ConfirmQueueDepths {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `(lookup→load, load→scripts, scripts→write)`.
    pub(crate) fn snap(&self) -> (usize, usize, usize) {
        (
            self.lookup_to_load.load(Ordering::Relaxed),
            self.load_to_scripts.load(Ordering::Relaxed),
            self.scripts_to_write.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn load_depth(&self) -> usize {
        self.lookup_to_load.load(Ordering::Relaxed)
    }

    /// Max queue depths since last call; resets HWMs to 0.
    pub(crate) fn sample_hwm_and_reset(&self) -> (usize, usize, usize) {
        (
            self.load_hwm.swap(0, Ordering::Relaxed),
            self.script_hwm.swap(0, Ordering::Relaxed),
            self.write_hwm.swap(0, Ordering::Relaxed),
        )
    }

    /// Full content snapshot (depths + blocks/wire/parents in each queue).
    pub(crate) fn content_snap(&self) -> ConfirmPipelineSizes {
        ConfirmPipelineSizes {
            load_batches: self.lookup_to_load.load(Ordering::Relaxed),
            load_blocks: self.load_blocks.load(Ordering::Relaxed),
            load_wire_bytes: self.load_wire_bytes.load(Ordering::Relaxed),
            ready: 0,
            script_batches: self.load_to_scripts.load(Ordering::Relaxed),
            script_blocks: self.script_blocks.load(Ordering::Relaxed),
            script_wire_bytes: self.script_wire_bytes.load(Ordering::Relaxed),
            script_parents: self.script_parents.load(Ordering::Relaxed),
            write_batches: self.scripts_to_write.load(Ordering::Relaxed),
            write_blocks: self.write_blocks.load(Ordering::Relaxed),
            write_wire_bytes: self.write_wire_bytes.load(Ordering::Relaxed),
            write_parents: self.write_parents.load(Ordering::Relaxed),
            feed_ready: 0,
            feed_inflight: 0,
        }
    }

    #[inline]
    fn note_depth_hwm(hwm: &AtomicUsize, depth_after: usize) {
        let _ = hwm.fetch_max(depth_after, Ordering::Relaxed);
    }

    /// Batch depth: saturating so a double-recv under teardown cannot wrap to
    /// usize::MAX and panic debug overflow on the next send (`fetch_add + 1`).
    #[inline]
    fn note_batch_depth_send(depth: &AtomicUsize, hwm: &AtomicUsize) {
        let prev = depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or(0);
        Self::note_depth_hwm(hwm, prev.saturating_add(1));
    }

    #[inline]
    fn note_batch_depth_recv(depth: &AtomicUsize) {
        let _ = depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_sub(1))
        });
    }

    fn note_load_send(&self, blocks: usize, wire_bytes: usize) {
        Self::note_batch_depth_send(&self.lookup_to_load, &self.load_hwm);
        self.load_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(blocks))
            })
            .ok();
        self.load_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(wire_bytes))
            })
            .ok();
    }
    fn note_load_recv(&self, blocks: usize, wire_bytes: usize) {
        Self::note_batch_depth_recv(&self.lookup_to_load);
        self.load_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(blocks))
            })
            .ok();
        self.load_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(wire_bytes))
            })
            .ok();
    }

    fn note_script_send(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_send(&self.load_to_scripts, &self.script_hwm);
        // Saturating: concurrent note_script_send under parallel load can race past
        // usize::MAX on wire_bytes/parents counters in debug overflow checks.
        self.script_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(blocks))
            })
            .ok();
        self.script_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(wire_bytes))
            })
            .ok();
        self.script_parents
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(parents))
            })
            .ok();
    }
    fn note_script_recv(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_recv(&self.load_to_scripts);
        self.script_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(blocks))
            })
            .ok();
        self.script_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(wire_bytes))
            })
            .ok();
        self.script_parents
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(parents))
            })
            .ok();
    }

    fn note_write_send(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_send(&self.scripts_to_write, &self.write_hwm);
        self.write_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(blocks))
            })
            .ok();
        self.write_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(wire_bytes))
            })
            .ok();
        self.write_parents
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(parents))
            })
            .ok();
    }
    fn note_write_recv(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_recv(&self.scripts_to_write);
        self.write_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(blocks))
            })
            .ok();
        self.write_wire_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(wire_bytes))
            })
            .ok();
        self.write_parents
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(parents))
            })
            .ok();
    }
}

/// Operator line for load stamp reject. Stamp-stage `missing prevout` is the
/// leftover TipOnly miss remapped from `parent create_fk unresolved` — name
/// that so a race is not logged as a bare invalid-block.
pub(crate) fn format_stamp_reject_missing_prevout(
    leftover_n: u64,
    leftover_hit: u64,
    miss_n: u64,
    miss_txid: Option<[u8; 32]>,
    pending: bool,
    miss_on: Option<&str>,
    miss_cands: u64,
    diag: bool,
) -> String {
    let mut s = format!(
        "missing prevout (leftover parent create_fk unresolved leftover_n={leftover_n} leftover_hit={leftover_hit}"
    );
    if miss_n > 0 {
        s.push_str(&format!(" miss_n={miss_n}"));
        if let Some(raw) = miss_txid {
            s.push_str(&format!(
                " miss_txid={}",
                bitcoin::Txid::from_byte_array(raw)
            ));
        }
        s.push_str(&format!(" pending={}", u8::from(pending)));
        if let Some(on) = miss_on {
            s.push_str(&format!(" miss_on={on} miss_cands={miss_cands}"));
        }
        if diag {
            s.push_str(" diag=1");
        }
    }
    s.push(')');
    s
}

pub(crate) fn stamp_reject_operator_msg(err: &str, stats: &rbitcoin_query::ConfirmStats) -> String {
    if err == "missing prevout" {
        let last = stats.last_plan_batch();
        let miss = stats.last_union_miss();
        format_stamp_reject_missing_prevout(
            last.head_need,
            last.head_hit,
            miss.n,
            miss.txid,
            miss.pending,
            miss.miss_on,
            miss.miss_cands,
            rbitcoin_store::leftover_probe_diag_ready(),
        )
    } else {
        err.to_string()
    }
}

/// Drain scripts→write after `first` is already dequeued (and accounted):
/// non-blocking `try_recv` until empty, merge contiguous into one batch.
///
/// `on_extra` runs only for additionally drained parts (queue depth). Non-contig
/// leftover is returned for the next write iteration (ordered scripts should
/// never hit that path).
fn drain_script_ok_write_queue(
    first: rbitcoin_consensus::ScriptOkBatch,
    rx: &std::sync::mpsc::Receiver<rbitcoin_consensus::ScriptOkBatch>,
    max_parts: usize,
    mut on_extra: impl FnMut(&rbitcoin_consensus::ScriptOkBatch),
) -> (
    rbitcoin_consensus::ScriptOkBatch,
    usize,
    Option<rbitcoin_consensus::ScriptOkBatch>,
) {
    let mut batch = first;
    let mut parts = 1usize;
    let max_parts = max_parts.max(1);
    loop {
        if parts >= max_parts {
            break;
        }
        match rx.try_recv() {
            Ok(more) => {
                on_extra(&more);
                match batch.append_contiguous(more) {
                    Ok(()) => {
                        parts = parts.saturating_add(1);
                    }
                    Err(leftover) => {
                        let polarity =
                            batch.archive_plan.is_some() != leftover.archive_plan.is_some();
                        if polarity {
                            warn!(
                                "ibd: write batch drain plan polarity after parts={parts} leftover_blks={}",
                                leftover.len()
                            );
                        } else {
                            warn!(
                                "ibd: write batch drain gap after parts={parts} leftover_blks={}",
                                leftover.len()
                            );
                        }
                        return (batch, parts, Some(leftover));
                    }
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
        }
    }
    (batch, parts, None)
}

/// OS-thread occupancy for the confirm pipeline (lookup / load / scripts / write).
///
/// Stage `plan_ms` / `script_ms` / … are **work** sums and mis-rank the long
/// pole when scriptq is empty. These timers include **wait** (claim, recv, send
/// block) so a 5s window can show who is busy vs idle.
pub(crate) mod confirm_thr_stats {
    use std::time::Duration;

    #[inline]
    pub fn add_lookup_claim(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_lookup_claim_ns, d);
    }
    #[inline]
    pub fn add_lookup_stamp(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_lookup_stamp_ns, d);
    }
    #[inline]
    pub fn add_lookup_other(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_lookup_other_ns, d);
    }
    #[inline]
    pub fn add_lookup_send_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_lookup_send_wait_ns, d);
    }

    #[inline]
    pub fn add_load_recv_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_recv_wait_ns, d);
    }
    #[inline]
    pub fn add_load_pack(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_pack_ns, d);
    }
    #[inline]
    pub fn add_load_clone(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_clone_ns, d);
    }
    #[inline]
    pub fn add_load_stamp(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_stamp_ns, d);
    }
    #[inline]
    pub fn add_load_pin(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_pin_ns, d);
    }
    #[inline]
    pub fn add_load_asm(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_asm_ns, d);
    }
    #[inline]
    pub fn add_load_prune(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_prune_ns, d);
    }
    #[inline]
    pub fn add_load_send_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_send_wait_ns, d);
    }

    /// Script occupancy is per-batch wave wall on `ibd-confirm`, not steal-pool join.
    #[inline]
    pub fn script_work_from_verify_ns(work_ns: u64) -> Duration {
        Duration::from_nanos(work_ns)
    }

    #[inline]
    pub fn add_script_recv_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_script_recv_wait_ns, d);
    }
    #[inline]
    pub fn add_script_work(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_script_work_ns, d);
    }
    #[inline]
    pub fn add_script_send_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_script_send_wait_ns, d);
    }

    #[inline]
    pub fn add_write_recv_wait(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_write_recv_wait_ns, d);
    }
    #[inline]
    pub fn add_write_work(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_write_work_ns, d);
    }
}

/// True when a write batch's first height is no longer tip+1 (rewind raced).
pub(crate) fn write_batch_is_stale(hub: &ChainHub, first_h: u32) -> bool {
    let expect = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    first_h != expect
}

/// Height-stale **or** claimed before a later [`ConfirmFeed::clear`] (sibling
/// at the new tip+1 would still pass the height check).
pub(crate) fn write_batch_is_stale_plan(hub: &ChainHub, feed: &ConfirmFeed, first_h: u32) -> bool {
    write_batch_is_stale(hub, first_h) || feed.plan_epoch_stale(first_h)
}

/// Spawn confirm **lookup** + **load** + **scripts** + **write** OS threads.
///
/// Lookup (BQ-ahead TipOnly `head_fk`) ∥ load (claim resolve-complete + stamp
/// from in-flight + skeleton + pin + assemble) → scriptq →
/// scripts → writeq → write.
/// Returns the lookup-thread join handle and shared queue-depth counters.
pub(crate) fn spawn_confirm_engine(
    hub: Arc<ChainHub>,
    feed: Arc<ConfirmFeed>,
    event_tx: std::sync::mpsc::Sender<ConfirmEvent>,
    accepted: Arc<AtomicU32>,
    loop_stats: Arc<LoopStats>,
) -> (std::thread::JoinHandle<()>, Arc<ConfirmQueueDepths>) {
    let queues = ConfirmQueueDepths::new();
    let caps = confirm_queue_caps();
    type ScriptsIn = (rbitcoin_consensus::LoadedBatch, u64);
    let (mat_tx, mat_rx) = std::sync::mpsc::sync_channel::<ScriptsIn>(caps.script);
    let (write_tx, write_rx) =
        std::sync::mpsc::sync_channel::<rbitcoin_consensus::ScriptOkBatch>(caps.write);
    let (load_tx, load_rx) = std::sync::mpsc::sync_channel::<LoadBatch>(caps.load);
    // Write reject: plan drops reserved fks + last_loaded so re-lookup after
    // Class A partial commit does not drift next_tx_start.
    let load_ahead_reset = Arc::new(AtomicBool::new(false));

    let hub_wb = Arc::clone(&hub);
    let feed_wb = Arc::clone(&feed);
    let event_tx_wb = event_tx.clone();
    let accepted_wb = Arc::clone(&accepted);
    let loop_stats_wb = Arc::clone(&loop_stats);
    let q_wb = Arc::clone(&queues);
    let load_ahead_reset_wb = Arc::clone(&load_ahead_reset);
    let write_thr = std::thread::Builder::new()
        .name("ibd-confirm-write".into())
        .spawn(move || {
            info!("ibd: confirm write on dedicated OS thread");
            let stats = hub_wb.query.confirm_stats_arc();
            // Non-contig leftover already note_write_recv'd; write it next iter.
            let mut leftover: Option<rbitcoin_consensus::ScriptOkBatch> = None;
            loop {
                let t_recv = Instant::now();
                let first = match leftover.take() {
                    Some(b) => b,
                    None => match write_rx.recv() {
                        Ok(b) => {
                            let n = b.len();
                            let wire = b.approx_wire_bytes();
                            let parents = b.parent_count();
                            q_wb.note_write_recv(n, wire, parents);
                            b
                        }
                        Err(_) => break,
                    },
                };
                let (batch, parts, next_left) = drain_script_ok_write_queue(
                    first,
                    &write_rx,
                    write_drain_max_parts(write_queue_cap()),
                    |b| {
                        let n = b.len();
                        let wire = b.approx_wire_bytes();
                        let parents = b.parent_count();
                        q_wb.note_write_recv(n, wire, parents);
                    },
                );
                leftover = next_left;
                confirm_thr_stats::add_write_recv_wait(&stats, t_recv.elapsed());
                if feed_wb.stopped() || hub_wb.query.confirm_cancelled() {
                    break;
                }
                let n = batch.len();
                let first_h = batch.heights_hashes().first().map(|(h, _)| *h).unwrap_or(0);
                let t0 = Instant::now();
                let heights_hashes = batch.heights_hashes();
                if write_batch_is_stale_plan(&hub_wb, &feed_wb, first_h) {
                    debug!(
                        "ibd: confirm write drop stale batch first={first_h} (tip moved)"
                    );
                    feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                    continue;
                }
                let meta: Vec<(u32, BlockHash)> = heights_hashes
                    .iter()
                    .map(|&(h, raw)| (h, BlockHash::from_byte_array(raw)))
                    .collect();
                match rbitcoin_consensus::confirm_write_phase(
                    &hub_wb.query,
                    &hub_wb.params,
                    hub_wb.milestone,
                    batch,
                ) {
                    Ok(_fks) => {
                        if let Err(e) = hub_wb.note_confirmed_tip(&meta) {
                            warn!("ibd: confirm write note tip: {e}");
                        }
                        let t_deq = Instant::now();
                        for (height, raw) in &heights_hashes {
                            let hash = BlockHash::from_byte_array(*raw);
                            if let Err(e) = hub_wb.query.block_queue_dequeue_height(*height) {
                                rbitcoin_log::debug!(
                                    "ibd: block_queue dequeue h={height}: {e}"
                                );
                            }
                            loop_stats_wb
                                .confirm_blocks
                                .fetch_add(1, Ordering::Relaxed);
                            accepted_wb.fetch_add(1, Ordering::SeqCst);
                            if event_tx_wb
                                .send(ConfirmEvent::Accepted { hash })
                                .is_err()
                            {
                                feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                                return;
                            }
                        }
                        feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                        let deq_ns = t_deq.elapsed().as_nanos() as u64;
                        if deq_ns > 0 {
                            rbitcoin_query::note_confirm(&stats.write_dequeue_ns, deq_ns);
                        }
                        let elapsed = t0.elapsed();
                        confirm_thr_stats::add_write_work(&stats, elapsed);
                        if elapsed.as_millis() > 2_000 {
                            let p = stats.last_write_phases();
                            let ms = rbitcoin_query::LastWritePhases::ms;
                            info!(
                                "ibd: confirm write slow batch={n} parts={parts} first={first_h} wall={:?} \
                                 class_a={}ms ensure={}ms struct={}ms spent={}ms create_h={}ms \
                                 bip68={}ms class_c={}ms spend_ann={}ms tweaks={}ms",
                                elapsed,
                                ms(p.class_a_ns),
                                ms(p.ensure_ns),
                                ms(p.structural_ns),
                                ms(p.spent_ns),
                                ms(p.create_h_ns),
                                ms(p.bip68_ns),
                                ms(p.class_c_ns),
                                ms(p.spend_ann_ns),
                                ms(p.tweak_ns),
                            );
                        }
                    }
                    Err(e) => {
                        confirm_thr_stats::add_write_work(&stats, t0.elapsed());
                        let msg = e.to_string();
                        if matches!(e, rbitcoin_consensus::ConsensusError::Cancelled)
                            || feed_wb.stopped()
                        {
                            info!("ibd: confirm write aborted: {msg}");
                            break;
                        }
                        let (height, hash) = heights_hashes
                            .first()
                            .map(|(h, raw)| (*h, BlockHash::from_byte_array(*raw)))
                            .unwrap_or((first_h, BlockHash::from_byte_array([0u8; 32])));
                        if write_batch_is_stale_plan(&hub_wb, &feed_wb, height) {
                            debug!(
                                "ibd: confirm write drop stale batch first={height} (tip moved)"
                            );
                            feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                            continue;
                        }
                        if hub_wb.has_block(&hash)
                            || (msg.contains("prevout already spent")
                                && heights_hashes.iter().all(|(_, raw)| {
                                    hub_wb.has_block(&BlockHash::from_byte_array(*raw))
                                }))
                        {
                            debug!(
                                "ibd: confirm write skip already-committed @{height} ({msg})"
                            );
                            for (_, raw) in &heights_hashes {
                                let h = BlockHash::from_byte_array(*raw);
                                if hub_wb.has_block(&h) {
                                    loop_stats_wb
                                        .confirm_blocks
                                        .fetch_add(1, Ordering::Relaxed);
                                    accepted_wb.fetch_add(1, Ordering::SeqCst);
                                    let _ = event_tx_wb.send(ConfirmEvent::Accepted { hash: h });
                                }
                            }
                            feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                            continue;
                        }
                        let recover = try_uring_recover(&hub_wb.query, &e, "ibd-confirm-write");
                        let action = classify_write_store_fault(&e, recover);
                        apply_write_store_fault(
                            &feed_wb,
                            &heights_hashes,
                            action,
                            &load_ahead_reset_wb,
                        );
                        match action {
                            WriteStoreFault::Requeue => {
                                warn!(
                                    "ibd: confirm write uring recover @ {height} batch_parts={parts}: {e}"
                                );
                                continue;
                            }
                            WriteStoreFault::Abort => {
                                rbitcoin_store::abort_uring_unusable(
                                    "recover credit exhausted on ibd-confirm-write",
                                );
                            }
                            WriteStoreFault::Reject(class) => {
                                loop_stats_wb
                                    .confirm_reject_stops
                                    .fetch_add(1, Ordering::Relaxed);
                                warn!(
                                    "ibd: confirm write reject @ {height} batch_parts={parts}: {e}"
                                );
                                let _ = emit_confirm_reject(
                                    &event_tx_wb,
                                    &feed_wb,
                                    height,
                                    hash,
                                    class,
                                    msg,
                                    heights_hashes.len(),
                                );
                            }
                        }
                    }
                }
            }
            info!("ibd: confirm write exit");
        })
        .expect("spawn ibd-confirm-write");

    let hub_sc = Arc::clone(&hub);
    let feed_sc = Arc::clone(&feed);
    let event_tx_sc = event_tx.clone();
    let loop_stats_sc = Arc::clone(&loop_stats);
    let q_sc = Arc::clone(&queues);
    let scripts = std::thread::Builder::new()
        .name("ibd-confirm".into())
        .spawn(move || {
            info!("ibd: confirm scripts on dedicated OS thread (publish waves; steal pool verifies)");
            let stats = hub_sc.query.confirm_stats_arc();
            rbitcoin_consensus::drive_script_waves_with(
                &mat_rx,
                |batch, wait| {
                    confirm_thr_stats::add_script_recv_wait(&stats, wait);
                    q_sc.note_script_recv(
                        batch.len(),
                        batch.approx_wire_bytes(),
                        batch.parent_count(),
                    );
                },
                |outcome, meta| {
                    loop_stats_sc
                        .confirm_ns
                        .fetch_add(outcome.work_ns, Ordering::Relaxed);
                    confirm_thr_stats::add_script_work(
                        &stats,
                        confirm_thr_stats::script_work_from_verify_ns(outcome.work_ns),
                    );
                    let script_ms = outcome.work_ns / 1_000_000;
                    let mat_ms = meta.mat_ns / 1_000_000;
                    let wb = outcome.batch.len();
                    let ww = outcome.batch.approx_wire_bytes();
                    let parents = outcome.batch.parent_count();
                    let t_send = Instant::now();
                    if write_tx.send(outcome.batch).is_err() {
                        info!("ibd: confirm write channel closed");
                        return false;
                    }
                    confirm_thr_stats::add_script_send_wait(&stats, t_send.elapsed());
                    q_sc.note_write_send(wb, ww, parents);
                    if script_ms > 2_000 || mat_ms > 2_000 {
                        info!(
                            "ibd: confirm scripts slow batch={} first={} load_ms={mat_ms} script_ms={script_ms} wall_ms={}",
                            meta.n,
                            meta.first_h,
                            meta.t0.elapsed().as_millis()
                        );
                    }
                    !feed_sc.stopped() && !hub_sc.query.confirm_cancelled()
                },
                |e, meta, dropped| {
                    confirm_thr_stats::add_script_work(&stats, Duration::ZERO);
                    let msg = e.to_string();
                    if matches!(e, rbitcoin_consensus::ConsensusError::Cancelled)
                        || feed_sc.stopped()
                    {
                        info!("ibd: confirm scripts aborted: {msg}");
                        return false;
                    }
                    if let Some(r) = try_uring_recover(&hub_sc.query, &e, "ibd-confirm-scripts") {
                        match r {
                            rbitcoin_query::UringRecover::Recovered => {
                                let req: Vec<(u32, BlockHash, Option<bitcoin::Block>)> = meta
                                    .heights_hashes
                                    .iter()
                                    .map(|(h, raw)| {
                                        (*h, BlockHash::from_byte_array(*raw), None)
                                    })
                                    .collect();
                                feed_sc.requeue_wire(&req);
                                warn!("ibd: confirm scripts uring recover @ {}: {e}", meta.first_h);
                                return true;
                            }
                            rbitcoin_query::UringRecover::Exhausted => {
                                rbitcoin_store::abort_uring_unusable(
                                    "recover credit exhausted on ibd-confirm-scripts",
                                );
                            }
                        }
                    }
                    let (height, hash) = meta
                        .heights_hashes
                        .first()
                        .map(|(h, raw)| (*h, BlockHash::from_byte_array(*raw)))
                        .unwrap_or((meta.first_h, BlockHash::from_byte_array([0u8; 32])));
                    feed_sc.finish(meta.heights_hashes.iter().map(|(h, _)| *h));
                    for d in dropped {
                        feed_sc.finish(d.heights_hashes.iter().map(|(h, _)| *h));
                    }
                    loop_stats_sc
                        .confirm_reject_stops
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("ibd: confirm scripts reject @ {height} (batch first {hash}): {e}");
                    let _ = emit_confirm_reject(
                        &event_tx_sc,
                        &feed_sc,
                        height,
                        hash,
                        ConfirmRejectClass::from_consensus(&e),
                        msg,
                        meta.heights_hashes.len(),
                    );
                    true
                },
                || feed_sc.stopped() || hub_sc.query.confirm_cancelled(),
            );
            drop(write_tx);
            let _ = write_thr.join();
            info!("ibd: confirm scripts exit");
        })
        .expect("spawn ibd-confirm");

    let hub_load = Arc::clone(&hub);
    let feed_load = Arc::clone(&feed);
    let event_tx_load = event_tx.clone();
    let loop_stats_load = Arc::clone(&loop_stats);
    let queues_load = Arc::clone(&queues);
    let load_ahead_reset_load = Arc::clone(&load_ahead_reset);
    let load_join = std::thread::Builder::new()
        .name("ibd-confirm-load".into())
        .spawn(move || {
            info!(
                "ibd: confirm load on dedicated OS thread (claim resolve-complete → stamp+pin)"
            );
            let mut lookup_ahead = LoadAheadState::new(&hub_load);
            let stats = hub_load.query.confirm_stats_arc();
            loop {
                if feed_load.stopped() || hub_load.query.confirm_cancelled() {
                    break;
                }
                let t_hygiene = Instant::now();
                if load_ahead_reset_load.swap(false, Ordering::AcqRel) {
                    lookup_ahead.clear_all(&hub_load);
                }
                lookup_ahead.apply_disconnect(&hub_load);
                confirm_thr_stats::add_load_prune(&stats, t_hygiene.elapsed());
                if feed_load.stopped() {
                    drop(mat_tx);
                    rbitcoin_consensus::unpark_script_publisher();
                    let _ = scripts.join();
                    return;
                }
                let t_recv = Instant::now();
                let lb = match load_rx.recv_timeout(Duration::from_millis(20)) {
                    Ok(b) => b,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        confirm_thr_stats::add_load_recv_wait(&stats, t_recv.elapsed());
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                };
                confirm_thr_stats::add_load_pack(&stats, t_recv.elapsed());
                let drop_below = lb.drop_inflight_below;
                let n = lb.items.len();
                let wire: usize = lb.items.iter().map(|(_, _, w)| w.block.total_size()).sum();
                queues_load.note_load_recv(n, wire);
                let parent_ids = lb.parent_ids;
                let claim_epoch = lb.epoch;
                if claim_epoch != feed_load.epoch() {
                    debug!(
                        "ibd: confirm load drop stale plan epoch={claim_epoch} live={}",
                        feed_load.epoch()
                    );
                    feed_load.finish(lb.items.iter().map(|(h, _, _)| *h));
                    continue;
                }
                let batch: Vec<(u32, BlockHash, rbitcoin_query::ResolvedWire)> = {
                    let mut g = feed_load.inner.lock().unwrap();
                    let mut run = Vec::with_capacity(lb.items.len());
                    for (h, raw, wire) in lb.items {
                        let hash = BlockHash::from_byte_array(raw);
                        if hub_load.has_block(&hash) {
                            g.ready.remove(&h);
                            continue;
                        }
                        if g.inflight.contains(&h) {
                            continue;
                        }
                        g.ready.remove(&h);
                        g.inflight.insert(h);
                        g.claimed_epoch.insert(h, claim_epoch);
                        run.push((h, hash, wire));
                    }
                    run
                };
                let batch = (batch, 0u32);

                let (batch, _batch_inputs) = batch;
                if batch.is_empty() {
                    if drop_below.is_some() {
                        let t_prune = Instant::now();
                        lookup_ahead.drop_inflight_below(drop_below);
                        confirm_thr_stats::add_load_prune(&stats, t_prune.elapsed());
                    }
                    continue;
                }
                let expect_h = batch[0].0;
                if feed_load.stopped() || hub_load.query.confirm_cancelled() {
                    let req: Vec<(u32, BlockHash, Option<bitcoin::Block>)> = batch
                        .iter()
                        .map(|(h, ha, w)| (*h, *ha, Some((*w.block).clone())))
                        .collect();
                    feed_load.requeue_wire(&req);
                    drop(mat_tx);
                    rbitcoin_consensus::unpark_script_publisher();
                    let _ = scripts.join();
                    return;
                }

                let store_path_lo = match hub_load.tip_height() {
                    None => 0u32,
                    Some(t) => t.saturating_add(1),
                };
                let use_pipe = expect_h >= store_path_lo;
                let wire_batch = batch;
                let t_clone = Instant::now();
                let plan_items = load_stamp_items(wire_batch.iter().map(|(h, _, w)| {
                    (
                        *h,
                        Arc::clone(&w.block),
                        Arc::clone(&w.pres),
                    )
                }));
                confirm_thr_stats::add_load_clone(&stats, t_clone.elapsed());
                let t_stamp = Instant::now();
                let plan_res = {
                    let pipe =
                        lookup_ahead.pipeline_for(expect_h, store_path_lo, parent_ids.clone());
                    rbitcoin_consensus::confirm_wire_lookup_stamp(
                        &hub_load.query,
                        &hub_load.params,
                        hub_load.milestone,
                        &plan_items,
                        if use_pipe { Some(&pipe) } else { None },
                    )
                };
                confirm_thr_stats::add_load_stamp(&stats, t_stamp.elapsed());
                let stamped = match plan_res {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = e.to_string();
                        if matches!(e, rbitcoin_consensus::ConsensusError::Cancelled)
                            || feed_load.stopped()
                        {
                            drop(mat_tx);
                            rbitcoin_consensus::unpark_script_publisher();
                            let _ = scripts.join();
                            return;
                        }
                        if let Some(r) =
                            try_uring_recover(&hub_load.query, &e, "ibd-confirm-load")
                        {
                            match r {
                                rbitcoin_query::UringRecover::Recovered => {
                                    let req: Vec<(u32, BlockHash, Option<bitcoin::Block>)> =
                                        wire_batch
                                            .iter()
                                            .map(|(h, ha, _)| (*h, *ha, None))
                                            .collect();
                                    feed_load.requeue_wire(&req);
                                    warn!(
                                        "ibd: confirm load stamp uring recover {first} @ {expect_h}: {e}",
                                        first = wire_batch[0].1
                                    );
                                    continue;
                                }
                                rbitcoin_query::UringRecover::Exhausted => {
                                    rbitcoin_store::abort_uring_unusable(
                                        "recover credit exhausted on ibd-confirm-load",
                                    );
                                }
                            }
                        }
                        let first_hash = wire_batch[0].1;
                        if wire_batch.len() > 1 {
                            let tail: Vec<(u32, BlockHash, Option<bitcoin::Block>)> =
                                wire_batch
                                    .iter()
                                    .skip(1)
                                    .filter(|(_, ha, _)| !hub_load.has_block(ha))
                                    .map(|(h, ha, _)| (*h, *ha, None))
                                    .collect();
                            feed_load.requeue_wire(&tail);
                        }
                        feed_load.finish(std::iter::once(expect_h));
                        lookup_ahead.clear_all(&hub_load);
                        loop_stats_load
                            .confirm_reject_stops
                            .fetch_add(1, Ordering::Relaxed);
                        let log_msg = stamp_reject_operator_msg(&msg, &stats);
                        let (if_l, if_n, _) = lookup_ahead.in_flight.size_snapshot();
                        let drain_fk = hub_load.query.head_drain_fk();
                        let fence_h = hub_load.query.fence_tip_height();
                        warn!(
                            "ibd: confirm load stamp reject {first_hash} @ {expect_h}: {log_msg} \
                             iflight={if_l}L/{if_n} drain_fk={drain_fk} fence_h={fence_h:?}"
                        );
                        let _ = emit_confirm_reject(
                            &event_tx_load,
                            &feed_load,
                            expect_h,
                            first_hash,
                            ConfirmRejectClass::from_consensus(&e),
                            log_msg,
                            wire_batch.len(),
                        );
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                if let Some(ref p) = stamped.plan {
                    if let Some((lh, raw)) = wire_batch
                        .iter()
                        .map(|(h, ha, _)| (*h, ha.to_byte_array()))
                        .max_by_key(|(h, _)| *h)
                    {
                        lookup_ahead.note_lookup_ok(p, lh, raw);
                    }
                } else {
                    let hh: Vec<(u32, BlockHash)> = wire_batch
                        .iter()
                        .map(|(h, ha, _)| (*h, *ha))
                        .collect();
                    lookup_ahead.note_archived_creates(&hub_load, &hh);
                }
                if drop_below.is_some() {
                    let t_prune = Instant::now();
                    lookup_ahead.drop_inflight_below(drop_below);
                    confirm_thr_stats::add_load_prune(&stats, t_prune.elapsed());
                }
                let pipe = lookup_ahead.pipeline_for(expect_h, store_path_lo, parent_ids);
                let plan_ns = stamped.work_ns;
                let heights_hashes: Vec<(u32, BlockHash)> = wire_batch
                    .iter()
                    .map(|(h, ha, _)| (*h, *ha))
                    .collect();
                let first_hash = heights_hashes[0].1;
                let _ = wire_batch;

                struct LiveGuard<'a> {
                    stats: &'a LoopStats,
                }
                impl Drop for LiveGuard<'_> {
                    fn drop(&mut self) {
                        self.stats.confirm_end();
                    }
                }
                loop_stats_load.confirm_begin(expect_h, heights_hashes.len() as u32, 0);
                let _live_guard = LiveGuard {
                    stats: &loop_stats_load,
                };

                let pin0 = stats.load_ns.load(std::sync::atomic::Ordering::Relaxed);
                let asm0 = stats.connect_ns.load(std::sync::atomic::Ordering::Relaxed);
                let mat_res = hub_load.confirm_wire_load_from_plan(stamped, Some(&pipe));
                let pin_d = stats
                    .load_ns
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .saturating_sub(pin0);
                let asm_d = stats
                    .connect_ns
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .saturating_sub(asm0);
                confirm_thr_stats::add_load_pin(&stats, Duration::from_nanos(pin_d));
                confirm_thr_stats::add_load_asm(&stats, Duration::from_nanos(asm_d));
                drop(_live_guard);

                if feed_load.stopped() || hub_load.query.confirm_cancelled() {
                    drop(mat_tx);
                    rbitcoin_consensus::unpark_script_publisher();
                    let _ = scripts.join();
                    return;
                }

                match mat_res {
                    Ok(outcome) => {
                        let work_ms = outcome.work_ns / 1_000_000;
                        let prepared_n = outcome.batch.len();
                        let wire = outcome.batch.approx_wire_bytes();
                        let parents = outcome.batch.parent_count();
                        let t_send = Instant::now();
                        if mat_tx
                            .send((outcome.batch, outcome.work_ns))
                            .is_err()
                        {
                            info!("ibd: confirm scripts channel closed");
                            rbitcoin_consensus::unpark_script_publisher();
                            let _ = scripts.join();
                            return;
                        }
                        rbitcoin_consensus::unpark_script_publisher();
                        confirm_thr_stats::add_load_send_wait(&stats, t_send.elapsed());
                        queues_load.note_script_send(prepared_n, wire, parents);
                        if work_ms > 2_000 {
                            let pin = stats.last_pin_phases();
                            info!(
                                "ibd: confirm load slow batch={prepared_n} claim={} first={expect_h} \
                                 work_ms={work_ms} plan_stamp_ms={} \
                                 {} parents={}",
                                heights_hashes.len(),
                                plan_ns / 1_000_000,
                                pin.format_slow_pin(),
                                parents,
                            );
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if matches!(e, crate::error::NetError::Cancelled) {
                            info!("ibd: confirm load cancelled @ {expect_h}");
                            drop(mat_tx);
                            rbitcoin_consensus::unpark_script_publisher();
                            let _ = scripts.join();
                            return;
                        }
                        if let Some(r) = try_uring_recover_msg(
                            &hub_load.query,
                            &msg,
                            "ibd-confirm-load",
                        ) {
                            match r {
                                rbitcoin_query::UringRecover::Recovered => {
                                    let req: Vec<(u32, BlockHash, Option<bitcoin::Block>)> =
                                        heights_hashes
                                            .iter()
                                            .map(|(h, ha)| (*h, *ha, None))
                                            .collect();
                                    feed_load.requeue_wire(&req);
                                    warn!(
                                        "ibd: confirm load uring recover {first_hash} @ {expect_h}: {e}"
                                    );
                                    continue;
                                }
                                rbitcoin_query::UringRecover::Exhausted => {
                                    rbitcoin_store::abort_uring_unusable(
                                        "recover credit exhausted on ibd-confirm-load",
                                    );
                                }
                            }
                        }
                        if heights_hashes.len() > 1 {
                            let tail: Vec<(u32, BlockHash, Option<bitcoin::Block>)> =
                                heights_hashes
                                    .iter()
                                    .skip(1)
                                    .filter(|(_, ha)| !hub_load.has_block(ha))
                                    .map(|(h, ha)| (*h, *ha, None))
                                    .collect();
                            feed_load.requeue_wire(&tail);
                        }
                        feed_load.finish(std::iter::once(expect_h));
                        loop_stats_load
                            .confirm_reject_stops
                            .fetch_add(1, Ordering::Relaxed);
                        warn!("ibd: confirm load reject {first_hash} @ {expect_h}: {e}");
                        if emit_confirm_reject(
                            &event_tx_load,
                            &feed_load,
                            expect_h,
                            first_hash,
                            ConfirmRejectClass::from_net(&e),
                            msg,
                            heights_hashes.len(),
                        )
                        .is_err()
                        {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                // Body HWM only — in-flight drop is the marked last-batch path above.
                lookup_ahead.sync_body_hwm(&hub_load);
            }
            drop(mat_tx);
            rbitcoin_consensus::unpark_script_publisher();
            let _ = scripts.join();
            info!("ibd: confirm load exit");
        })
        .expect("spawn ibd-confirm-load");

    let queues_lookup = Arc::clone(&queues);
    let event_tx_lookup = event_tx.clone();
    let lookup_join = std::thread::Builder::new()
        .name("ibd-confirm-lookup".into())
        .spawn(move || {
            info!("ibd: confirm lookup on dedicated OS thread (in-order BQ take → loadq)");
            let queues_lookup = queues_lookup;
            let stats = hub.query.confirm_stats_arc();
            let mut disco_seen = 0u64;
            let mut lookup_faults = LookupFaultPolicy::default();
            loop {
                if feed.stopped() {
                    break;
                }
                if hub.query.take_disconnect(&mut disco_seen).is_some() {
                    hub.query.set_lookup_taken_hi(None);
                }
                let t_sel = Instant::now();
                let skip: std::collections::HashSet<u32> = {
                    let g = feed.inner.lock().unwrap();
                    g.inflight.iter().copied().collect()
                };
                let tip = hub.tip_height();
                let path_lo = if tip.is_none() {
                    0u32
                } else {
                    tip.unwrap_or(0).saturating_add(1)
                };
                let remaining = load_queue_cap().saturating_sub(queues_lookup.load_depth());
                if remaining == 0 {
                    let t_wait = Instant::now();
                    let g = feed.inner.lock().unwrap();
                    if feed.stopped() {
                        break;
                    }
                    let (_gg, _) = feed.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
                    confirm_thr_stats::add_lookup_send_wait(&stats, t_wait.elapsed());
                    confirm_thr_stats::add_lookup_claim(&stats, t_wait.elapsed());
                    continue;
                }
                let run_max = if feed.single_block() {
                    1usize
                } else {
                    CONFIRM_RUN_MAX_BLOCKS
                };
                let max_blocks = remaining
                    .saturating_mul(run_max)
                    .min(rbitcoin_consensus::BQ_RESOLVE_WAVE_MAX_BLOCKS);
                let max_inputs = (remaining as u32)
                    .saturating_mul(confirm_batch_max_inputs())
                    .min(rbitcoin_consensus::BQ_RESOLVE_WAVE_MAX_INPUTS);
                let wave_h = hub
                    .query
                    .block_queue_unresolved_heights(path_lo, &skip, max_blocks);
                confirm_thr_stats::add_lookup_other(&stats, t_sel.elapsed());
                let mut did = false;
                if !wave_h.is_empty() {
                    let t_wave = Instant::now();
                    match rbitcoin_consensus::confirm_bq_resolve_wave_capped(
                        &hub.query,
                        &hub.params,
                        hub.milestone,
                        &wave_h,
                        max_blocks,
                        max_inputs,
                    ) {
                        Ok(wave) if !wave.items.is_empty() => {
                            lookup_faults.on_success();
                            did = true;
                            let counts: Vec<u32> = wave
                                .items
                                .iter()
                                .map(|(_, _, w)| block_input_count(w.block.as_ref()))
                                .collect();
                            let t_kind = Instant::now();
                            let kinds: Vec<bool> = match wave
                                .items
                                .iter()
                                .map(|(_, hash, _)| hub.query.is_block_archived(hash))
                                .collect::<Result<Vec<_>, _>>()
                            {
                                Ok(k) => k,
                                Err(e) => {
                                    warn!("ibd: load-batch has_body probe: {e}");
                                    confirm_thr_stats::add_lookup_other(&stats, t_kind.elapsed());
                                    continue;
                                }
                            };
                            confirm_thr_stats::add_lookup_other(&stats, t_kind.elapsed());
                            let parts = split_wave_into_load_batches_kind(
                                &counts,
                                &kinds,
                                confirm_batch_max_inputs(),
                                run_max,
                            );
                            let mut batches = load_batches_from_wave(
                                &wave.items,
                                &parts,
                                remaining,
                                &wave.parent_ids,
                                wave.drain_fence_hi,
                            );
                            let epoch = feed.epoch();
                            for batch in &mut batches {
                                batch.epoch = epoch;
                            }
                            for batch in batches {
                                let t_send = Instant::now();
                                let n = batch.items.len();
                                let wire: usize = batch
                                    .items
                                    .iter()
                                    .map(|(_, _, w)| w.block.total_size())
                                    .sum();
                                let chunk = batch.items.clone();
                                if load_tx.send(batch).is_err() {
                                    break;
                                }
                                if rbitcoin_consensus::take_wave_items_for_load(&hub.query, &chunk)
                                    .is_err()
                                {
                                    break;
                                }
                                queues_lookup.note_load_send(n, wire);
                                confirm_thr_stats::add_lookup_send_wait(&stats, t_send.elapsed());
                            }
                            feed.notify();
                        }
                        Ok(_) => {
                            lookup_faults.on_success();
                        }
                        Err(e) => {
                            let recover =
                                try_uring_recover(&hub.query, &e, "ibd-confirm-lookup");
                            match lookup_faults.on_err(&e, recover) {
                                LookupFaultAction::Ignore => {
                                    debug!("ibd: bq resolve wave: {e}");
                                }
                                LookupFaultAction::RecoverContinue => {
                                    warn!("ibd: bq resolve wave uring recover: {e}");
                                }
                                LookupFaultAction::Abort => {
                                    rbitcoin_store::abort_uring_unusable(
                                        "recover credit exhausted on ibd-confirm-lookup",
                                    );
                                }
                                LookupFaultAction::Warn => {
                                    LOOKUP_WAVE_FAULTS.fetch_add(1, Ordering::Relaxed);
                                    warn!("ibd: bq resolve wave: {e}");
                                }
                                LookupFaultAction::RejectEngineFault => {
                                    LOOKUP_WAVE_FAULTS.fetch_add(1, Ordering::Relaxed);
                                    warn!("ibd: bq resolve wave halt: {e}");
                                    let height = wave_h.first().copied().unwrap_or(path_lo);
                                    match lookup_ready_hash(&feed, height) {
                                        Some(hash) => {
                                            let _ = emit_confirm_reject(
                                                &event_tx_lookup,
                                                &feed,
                                                height,
                                                hash,
                                                ConfirmRejectClass::EngineFault,
                                                e.to_string(),
                                                1,
                                            );
                                        }
                                        None => {
                                            warn!(
                                                "ibd: bq resolve wave halt skip emit @{height} (no ready hash)"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    confirm_thr_stats::add_lookup_stamp(&stats, t_wave.elapsed());
                }
                if !did {
                    let t_wait = Instant::now();
                    let g = feed.inner.lock().unwrap();
                    if feed.stopped() {
                        break;
                    }
                    let (_gg, _) = feed.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
                    confirm_thr_stats::add_lookup_send_wait(&stats, t_wait.elapsed());
                    confirm_thr_stats::add_lookup_claim(&stats, t_wait.elapsed());
                }
            }
            feed.notify();
            let _ = load_join.join();
            info!("ibd: confirm lookup exit");
        })
        .expect("spawn ibd-confirm-lookup");
    (lookup_join, queues)
}

/// Offer a run of claim-ready heights starting at tip+1 into the confirm feed.
///
/// Pre-noting ahead of tip lets the engine batch multi-block waves when the
/// **body queue** leads tip. Caps at [`OFFER_AHEAD`].
///
/// Claim-ready = body-queue wire only (not Class A alone, not zombie pending).
///
/// Uses `height_to_hash` for **O(OFFER_AHEAD)** work — never scans the full
/// ordered path (that pegged a core at ~130k headers with tip frozen).
pub(crate) fn offer_confirm_ready(
    feed: &ConfirmFeed,
    height_to_hash: &HashMap<u32, BlockHash>,
    body: &mut BodyPresence,
    hub: &ChainHub,
    max_ready_height: &mut u32,
    max_ready_shared: &AtomicU32,
) -> u32 {
    let expect = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let limit = expect.saturating_add(OFFER_AHEAD);
    let mut noted = 0u32;
    for ht in expect..=limit {
        let Some(&hash) = height_to_hash.get(&ht) else {
            break;
        };
        if hub.has_block(&hash) {
            continue;
        }
        if ht == expect {
            if let Ok(Some(prev)) = super::reorg::parent_hash_of(hub, hash) {
                if hub.tip_hash() != Some(prev) {
                    break;
                }
            }
        }
        if body.is_rejected(&hash) {
            // Tip is frozen on a consensus-invalid tip+1. Densify must not
            // keep fetching above this height (download gate).
            if ht == expect {
                static REJECT_STUCK: AtomicU32 = AtomicU32::new(0);
                let n = REJECT_STUCK.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 3 || n.is_multiple_of(100) {
                    warn!(
                        "ibd: confirm stuck: tip+1={ht} {hash} is consensus-invalid; \
                         download gate closed until a valid heavier fork is planted (n={n})"
                    );
                }
            }
            break;
        }
        if !super::progress::claim_ready(hub, body, ht, &hash) {
            break;
        }
        *max_ready_height = (*max_ready_height).max(ht);
        max_ready_shared.store(*max_ready_height, Ordering::Relaxed);
        feed.note(ht, hash);
        noted += 1;
    }
    noted
}

#[cfg(test)]
mod tests;
