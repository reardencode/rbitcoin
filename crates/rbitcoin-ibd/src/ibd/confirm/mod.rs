//! Dedicated confirm engine (Class C tip walk) for IBD.

use super::body::BodyPresence;
use super::status::LoopStats;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_log::{debug, info, warn};
use rbitcoin_net::chain::ChainHub;
use rbitcoin_query::WireLoadPipeline;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Load-thread pipeline caches so load(N+1) can run while write(N) has not advanced tip.
///
/// In-flight creates are one [`rbitcoin_query::InFlight`] map this thread owns:
/// stamp/pin borrow it, then [`rbitcoin_query::InFlight::note_pins`] inserts the
/// current pack.
#[doc(hidden)]
pub struct LoadAheadState {
    pub next_tx_start: u64,
    pub in_flight: rbitcoin_query::InFlight,
    /// Last height successfully loaded (still in pipeline or already committed).
    pub last_loaded: Option<(u32, [u8; 32])>,
    /// Last applied [`Query::take_disconnect`] generation.
    pub disconnect_gen_seen: u64,
    /// Blocks kept below the drain+fence snapshot around a 1 GiB accounted heap.
    pub retain: InflightRetain,
}

impl LoadAheadState {
    #[doc(hidden)]
    pub fn new(hub: &ChainHub) -> Self {
        let next = hub.query.tx_body_count().saturating_add(1).max(1);
        Self {
            next_tx_start: next,
            in_flight: rbitcoin_query::InFlight::new(),
            last_loaded: None,
            disconnect_gen_seen: 0,
            retain: InflightRetain::default(),
        }
    }

    /// Drop reorged packs **before** bind so disconnected creates cannot stamp.
    #[doc(hidden)]
    pub fn apply_disconnect(&mut self, hub: &ChainHub) {
        if let Some(h) = hub.query.take_disconnect(&mut self.disconnect_gen_seen) {
            self.in_flight.drop_from_height(h);
            self.publish_mem_stats();
        }
    }

    /// Drop packs below the lookup wave's drain+fence snapshot, after that
    /// batch's in-flight read. [`InflightRetain`] may keep a band under it.
    #[doc(hidden)]
    pub fn drop_inflight_below(
        &mut self,
        hi: Option<u32>,
        hub: &ChainHub,
        queues: &ConfirmQueueDepths,
    ) {
        let (.., inflight_bytes) = self.in_flight.size_snapshot();
        let pipe = queues.content_snap();
        let wire = (pipe.load_wire_bytes as u64)
            .saturating_add(pipe.script_wire_bytes as u64)
            .saturating_add(pipe.write_wire_bytes as u64);
        let accounted = AccountedHeap::from_hub(hub, inflight_bytes, wire).bytes();
        let would_drop = self
            .in_flight
            .has_tagged_below(inflight_prune_height(hi, self.retain.extra()));
        let extra = self.retain.observe(accounted, would_drop);
        self.in_flight
            .prune_below_height(inflight_prune_height(hi, extra));
        self.publish_mem_stats();
    }

    /// Advance create-fk HWM from published body; clear last_loaded once on tip.
    #[doc(hidden)]
    pub fn sync_body_hwm(&mut self, hub: &ChainHub) {
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
    #[doc(hidden)]
    pub fn publish_mem_stats(&self) {
        let (layers, pins, if_bytes) = self.in_flight.size_snapshot();
        rbitcoin_query::process_mem_stats::note(layers, pins, if_bytes);
    }

    #[doc(hidden)]
    pub fn pipeline_for(
        &self,
        path_lo: u32,
        store_path_lo: u32,
        skeleton: Option<rbitcoin_query::BatchParentIds>,
        carried_need: Vec<[u8; 32]>,
        carried_header_fks: Vec<rbitcoin_primitives::Fk>,
        carried_header_hashes: Vec<[u8; 32]>,
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
            carried_need,
            carried_header_fks,
            carried_header_hashes,
        }
    }

    #[doc(hidden)]
    pub fn note_lookup_ok(
        &mut self,
        plan: &rbitcoin_query::ArchiveWritePlan,
        last_height: u32,
        last_hash: [u8; 32],
    ) {
        self.in_flight.note_pins(
            plan.planned_fks
                .iter()
                .zip(plan.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            Some(last_height),
        );
        if let Some(last) = plan.planned_fks.last().and_then(|f| f.get()) {
            self.next_tx_start = last.saturating_add(1).max(1);
        }
        self.last_loaded = Some((last_height, last_hash));
        self.publish_mem_stats();
    }

    #[doc(hidden)]
    pub fn note_archived_creates(
        &mut self,
        pairs: Vec<([u8; 32], rbitcoin_primitives::Fk)>,
        last: Option<(u32, [u8; 32])>,
    ) {
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
        let max_height = last.map(|(h, _)| h);
        self.in_flight.note_creates(pairs, max_height);
        if let Some((h, hash)) = last {
            self.last_loaded = Some((h, hash));
        }
        self.publish_mem_stats();
    }

    #[doc(hidden)]
    pub fn clear_all(&mut self, hub: &ChainHub) {
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
/// stores hashes only. Class A alone is never enough (no hash-only
/// confirm). Tip-follow reorgs use peer wire via `ChainHub::accept_block`.
///
/// **In-flight tracking:** once lookup claims a contiguous run, those heights sit
/// in `inflight` until write finishes (or re-queue). `note` will not re-insert
/// them — otherwise offer re-notes tip+1 every main-loop tick and lookup
/// re-claims the same batch (duplicate work).
pub struct ConfirmFeed {
    pub inner: std::sync::Mutex<ConfirmFeedInner>,
    pub cv: std::sync::Condvar,
    pub stop: AtomicBool,
    /// Bumped by [`Self::clear`] so in-channel batches claimed earlier are dropped.
    pub epoch: AtomicU64,
    /// Isolate until confirmed tip reaches this height (`u32::MAX` = off).
    pub force_single_until: AtomicU32,
    /// Lookup selects nothing until this IBD mono ms (0: no hold): a block
    /// was too far ahead of the clock to connect.
    pub hold_until_ms: AtomicU64,
}

pub struct ConfirmFeedInner {
    /// height → hash. Wire lives in the body queue.
    pub ready: std::collections::BTreeMap<u32, BlockHash>,
    /// Claimed by load; not yet written or released. Offer must not re-note.
    pub inflight: std::collections::HashSet<u32>,
    /// Height → lookup epoch when load claimed it (survives `Self::clear`).
    pub claimed_epoch: HashMap<u32, u64>,
}

impl Default for ConfirmFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfirmFeed {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(ConfirmFeedInner {
                ready: std::collections::BTreeMap::new(),
                inflight: std::collections::HashSet::new(),
                claimed_epoch: HashMap::new(),
            }),
            cv: std::sync::Condvar::new(),
            stop: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            force_single_until: AtomicU32::new(u32::MAX),
            hold_until_ms: AtomicU64::new(0),
        }
    }

    /// Lookup waits `for_` before it selects a body again.
    pub fn hold_for(&self, for_: Duration) {
        let until = super::peer_io::ibd_mono_ms().saturating_add(for_.as_millis() as u64);
        self.hold_until_ms.store(until, Ordering::Release);
    }

    /// A hold from [`Self::hold_for`] has not passed.
    pub fn held(&self) -> bool {
        super::peer_io::ibd_mono_ms() < self.hold_until_ms.load(Ordering::Acquire)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// True when a claimed plan's lookup epoch is behind a later [`Self::clear`].
    pub fn plan_epoch_stale(&self, first_h: u32) -> bool {
        let live = self.epoch();
        let g = self.inner.lock().unwrap();
        g.claimed_epoch.get(&first_h).is_some_and(|&e| e != live)
    }

    pub fn request_single_block(&self, until: u32) {
        self.force_single_until.store(until, Ordering::Release);
    }

    pub fn isolate_until(&self) -> u32 {
        self.force_single_until.load(Ordering::Acquire)
    }

    pub fn single_block(&self) -> bool {
        self.isolate_until() != u32::MAX
    }

    pub fn release_isolate_if_tip(&self, tip: u32) {
        let until = self.isolate_until();
        if until != u32::MAX && tip >= until {
            self.force_single_until.store(u32::MAX, Ordering::Release);
        }
    }

    /// Load claimed `height` and write has not finished it.
    pub fn holds(&self, height: u32) -> bool {
        self.inner.lock().unwrap().inflight.contains(&height)
    }

    /// Note readiness (wire lives in the body queue — denserels reloads it).
    pub fn note(&self, height: u32, hash: BlockHash) {
        self.note_wire(height, hash);
    }

    /// Note readiness. The feed stores the hash only.
    pub fn note_wire(&self, height: u32, hash: BlockHash) {
        let mut g = self.inner.lock().unwrap();
        if g.inflight.contains(&height) {
            return;
        }
        g.ready.entry(height).or_insert(hash);
        self.cv.notify_one();
    }

    pub fn notify(&self) {
        self.cv.notify_all();
    }

    /// Return heights to the ready map. Hashes only; wire stays in the body queue.
    pub fn requeue_wire(&self, batch: &[(u32, BlockHash)]) {
        if batch.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        for &(h, hash) in batch {
            g.inflight.remove(&h);
            g.ready.entry(h).or_insert(hash);
        }
        self.cv.notify_one();
    }

    /// Write (or permanent reject) finished — height may be re-offered only after
    /// tip moves past it (or a future requeue path).
    pub fn finish(&self, heights: impl IntoIterator<Item = u32>) {
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
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.ready.clear();
        g.inflight.clear();
        drop(g);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.force_single_until.store(u32::MAX, Ordering::Release);
        self.cv.notify_all();
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// `(ready_heights, inflight_heights)` — O(1) under feed mutex.
    pub fn size_snap(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.ready.len(), g.inflight.len())
    }
}

/// How IBD treats a confirm-engine reject (computed at the sender).
///
/// Only [`Self::ConsensusInvalid`] blacklists a hash. Weaker header chains
/// are never a reject class — they are `IgnoreWeaker` at selection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmRejectClass {
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
    pub fn from_err_str(err: &str) -> Self {
        let s = err.to_ascii_lowercase();
        if s.contains("confirm cancelled") || s.contains("cancelled:") {
            return Self::Cancelled;
        }
        if super::reorg::is_bad_prev_err(err) {
            return Self::SoftWire;
        }
        if rbitcoin_net::chain::reject_is_mutated(&s) {
            return Self::SoftWire;
        }
        if s.contains("missing retarget first header") {
            return Self::SoftWire;
        }
        if s.contains("timestamp too far in future") {
            return Self::Cascade;
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
            || s.contains("create.loc hole after count")
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

    pub fn from_consensus(err: &rbitcoin_consensus::ConsensusError) -> Self {
        use rbitcoin_consensus::ConsensusError;
        match err {
            ConsensusError::Cancelled => Self::Cancelled,
            ConsensusError::BadPrev => Self::SoftWire,
            ConsensusError::BadBlock(r) if rbitcoin_net::chain::reject_is_mutated(r) => {
                Self::SoftWire
            }
            ConsensusError::BadHeader("missing retarget first header") => Self::SoftWire,
            ConsensusError::BadHeader("timestamp too far in future") => Self::Cascade,
            ConsensusError::Internal(m) => Self::from_err_str(m),
            ConsensusError::BadBlock(_)
            | ConsensusError::BadTx(_)
            | ConsensusError::Script(_)
            | ConsensusError::PrevoutSpent
            | ConsensusError::InvalidPow
            | ConsensusError::BadVersion(_)
            | ConsensusError::BadHeader(_)
            | ConsensusError::MissingPrevout => Self::ConsensusInvalid,
        }
    }

    pub fn from_confirm(err: &rbitcoin_query::ConfirmError) -> Self {
        use rbitcoin_query::ConfirmError;
        use rbitcoin_store::StoreError;
        match err {
            ConfirmError::Rules(e) => Self::from_consensus(e),
            ConfirmError::Store(StoreError::Cancelled(_)) => Self::Cancelled,
            ConfirmError::Store(e) if e.is_uring_session_fault() => Self::EngineFault,
            ConfirmError::Store(StoreError::Io { .. }) => Self::EngineFault,
            ConfirmError::Store(StoreError::Corrupt(m)) => Self::from_err_str(m),
            ConfirmError::Store(_) => Self::EngineFault,
        }
    }

    pub fn from_net(err: &rbitcoin_net::error::NetError) -> Self {
        match err {
            rbitcoin_net::error::NetError::Cancelled => Self::Cancelled,
            rbitcoin_net::error::NetError::Mutated(_) => Self::SoftWire,
            rbitcoin_net::error::NetError::BadPrev => Self::SoftWire,
            rbitcoin_net::error::NetError::Rules(e) => Self::from_consensus(e),
            rbitcoin_net::error::NetError::ConnectFailed { rules: Some(e), .. } => {
                Self::from_consensus(e)
            }
            rbitcoin_net::error::NetError::ConnectFailed { msg, .. } => Self::from_err_str(msg),
            rbitcoin_net::error::NetError::Consensus(s) => Self::from_err_str(s),
            other => Self::from_err_str(&other.to_string()),
        }
    }

    pub fn is_soft(self) -> bool {
        matches!(self, Self::SoftWire)
    }

    /// Consensus verdict is trusted only when the connect ran against the tip
    /// (`tip == header.prev`). A stored parent that is not the tip, or a
    /// lookup error, is a cascade. A missing header row is an engine fault:
    /// `hash: None` with `unreadable: false`.
    pub fn trust_consensus(self, parent: RejectParent, tip: Option<BlockHash>) -> Self {
        if self != Self::ConsensusInvalid {
            return self;
        }
        if parent.unreadable {
            return Self::Cascade;
        }
        match parent.hash {
            Some(prev) if tip == Some(prev) => Self::ConsensusInvalid,
            Some(_) => Self::Cascade,
            None => Self::EngineFault,
        }
    }

    /// Multi-block waves attribute rejects to the first hash. Do not blacklist
    /// or re-get that hash — isolate by retrying one block at a time.
    pub fn isolate_if_batched(self, batch_len: usize) -> Self {
        if matches!(self, Self::ConsensusInvalid | Self::SoftWire) && batch_len > 1 {
            Self::Cascade
        } else {
            self
        }
    }
}

/// Class C already committed: finish annotate + head drain here.
/// Requeue through lookup/load cannot work — those heights are stale vs tip.
#[doc(hidden)]
pub fn finish_connected_write_after_session_fault(
    query: &rbitcoin_query::Query,
    items: &[(u32, [u8; 32])],
) -> Result<(), rbitcoin_query::ConfirmError> {
    query.uring_recover_or_abort("ibd-confirm-write");
    loop {
        match rbitcoin_query::finish_post_commit_hashes(query, items) {
            Ok(()) => return Ok(()),
            Err(e) if e.is_uring_session_fault() => {
                query.uring_recover_or_abort("ibd-confirm-write");
            }
            Err(e) => return Err(e),
        }
    }
}

/// A scripts or write session fault: take recover credit, then requeue
/// the wave as an engine fault. Lookup took its bodies off the body queue,
/// so the wave goes back there under a re-arm.
#[doc(hidden)]
pub fn requeue_on_uring_recover(
    hub: &ChainHub,
    feed: &ConfirmFeed,
    reason: &'static str,
    wave: &[(u32, BlockHash, &bitcoin::Block)],
) {
    hub.query.uring_recover_or_abort(reason);
    feed.finish(wave.iter().map(|&(h, _, _)| h));
    rearm_after_reject(hub, feed, ConfirmRejectClass::EngineFault, wave);
}

/// A body to offer back, with the BQ sender id it was enqueued with.
#[doc(hidden)]
pub type OfferBack<'a> = (u32, BlockHash, &'a bitcoin::Block, Option<u64>);

/// A body serialized for the queue, ready to insert.
#[doc(hidden)]
pub struct PreparedOffer {
    pub height: u32,
    pub hash: [u8; 32],
    pub header_fk: u64,
    pub payload: Vec<u8>,
    pub sender: Option<u64>,
}

/// Serialize and look up the header row for each body not yet connected.
/// RAM: the wave's serialized bodies are held together until the insert,
/// which moves them into the queue.
#[doc(hidden)]
pub fn prepare_offer_back<'a>(
    hub: &ChainHub,
    items: impl IntoIterator<Item = OfferBack<'a>>,
) -> Vec<PreparedOffer> {
    use bitcoin::consensus::encode::serialize;
    items
        .into_iter()
        .filter(|(_, hash, _, _)| !hub.has_block(hash))
        .map(|(height, hash, block, sender)| PreparedOffer {
            height,
            hash: hash.to_byte_array(),
            header_fk: hub
                .query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .map(|(fk, _)| fk.0)
                .unwrap_or(0),
            payload: serialize(block),
            sender,
        })
        .collect()
}

#[doc(hidden)]
pub fn offer_back(hub: &ChainHub, prepared: Vec<PreparedOffer>) {
    for p in prepared {
        let _ = hub
            .query
            .block_queue_offer_vec(p.height, p.hash, p.header_fk, p.payload, p.sender);
    }
}

#[doc(hidden)]
pub fn reoffer_blocks_to_body_queue<'a>(
    hub: &ChainHub,
    items: impl IntoIterator<Item = OfferBack<'a>>,
) {
    offer_back(hub, prepare_offer_back(hub, items));
}

/// The script wave that goes back on the body queue. A one-block verdict
/// drops its block. A retry, an engine fault, or a session fault keeps it.
#[doc(hidden)]
pub fn script_reject_wave<T>(
    retried: bool,
    session_fault: bool,
    class: ConfirmRejectClass,
    wave: &[T],
) -> &[T] {
    if retried || session_fault || class == ConfirmRejectClass::EngineFault {
        wave
    } else {
        &[]
    }
}

#[doc(hidden)]
pub fn rearm_script_reject(
    hub: &ChainHub,
    feed: &ConfirmFeed,
    retried: bool,
    session_fault: bool,
    class: ConfirmRejectClass,
    wave: &[(u32, BlockHash, &bitcoin::Block)],
) {
    let rearm = if retried {
        ConfirmRejectClass::Cascade
    } else {
        class
    };
    rearm_after_reject(
        hub,
        feed,
        rearm,
        script_reject_wave(retried, session_fault, class, wave),
    );
}

/// A write or scripts reject: lookup took the wave's bodies off the body
/// queue. Re-arm lookup at the tip, which bumps the generation so load
/// drops its look-ahead plan before the next wave. When the wave is retried
/// (a cascade, or a batched reject being isolated), turn on isolation
/// before the re-arm and offer its bodies back after it, so lookup cannot
/// rebuild the same wave from them. An engine fault's wave goes back the
/// same way without isolation: the fault is no block's. Write and scripts
/// re-offer without a sender: load already checked these bodies for
/// mutation. Returns false when the class does not re-arm (cancel).
///
/// Order: serialize, isolate, re-arm, insert. The insert must follow the
/// re-arm: a body queued first could be selected by a lookup pass that read
/// the old generation and isolation off, and its take would still match.
/// Between the re-arm and the insert assign sees these heights neither
/// taken nor queued and may fetch them again, so the serialize runs first
/// and only the queue inserts are left in that window.
#[doc(hidden)]
pub fn rearm_after_reject(
    hub: &ChainHub,
    feed: &ConfirmFeed,
    class: ConfirmRejectClass,
    wave: &[(u32, BlockHash, &bitcoin::Block)],
) -> bool {
    if class == ConfirmRejectClass::Cancelled {
        return false;
    }
    let retried = class.isolate_if_batched(wave.len()) == ConfirmRejectClass::Cascade;
    let requeue = retried || class == ConfirmRejectClass::EngineFault;
    let prepared = if requeue {
        prepare_offer_back(hub, wave.iter().map(|&(h, ha, b)| (h, ha, b, None)))
    } else {
        Vec::new()
    };
    if let Some(&(first_h, _, _)) = wave.first() {
        if retried && wave.len() > 1 {
            feed.request_single_block(first_h.saturating_add(wave.len() as u32 - 1));
        }
    }
    hub.query.set_lookup_taken_hi(hub.tip_height());
    hub.query.set_lookup_started_hi(hub.tip_height());
    if requeue {
        offer_back(hub, prepared);
        feed.notify();
    }
    true
}

/// A cancelled write does not re-arm. Load then drops the plan it stamped
/// for that wave. Every other class re-arms, which already bumps the generation.
#[doc(hidden)]
pub fn apply_write_reject(
    hub: &ChainHub,
    feed: &ConfirmFeed,
    class: ConfirmRejectClass,
    wave: &[(u32, BlockHash, &bitcoin::Block)],
    reset_lookahead: &AtomicBool,
) {
    if !rearm_after_reject(hub, feed, class, wave) {
        reset_lookahead.store(true, Ordering::Release);
    }
}

/// The class a load reject of `wave` is rewound and sent with. A lone
/// block's verdict holds only while its parent is the tip; otherwise it is
/// a cascade. This is load's one tip sample: the rewind and the event both
/// use it, so a lone `ConsensusInvalid` event always means load dropped the
/// body.
#[doc(hidden)]
pub fn load_reject_class(
    hub: &ChainHub,
    class: ConfirmRejectClass,
    wave: &[OfferBack<'_>],
) -> ConfirmRejectClass {
    match wave {
        [(_, hash, _, _)] => {
            let parent = RejectParent::from_lookup(hub, *hash);
            class.trust_consensus(parent, hub.tip_hash())
        }
        _ => class,
    }
}

/// Stamp/pin fail: drop speculative fks, bump the feed epoch, re-offer to BQ.
/// A one-block verdict drops its failing block; a one-block cascade (a stale
/// plan, or a consensus reject against a parent that is not the tip, see
/// [`load_reject_class`]) goes back for a retry. A batched reject names the
/// first hash but may be any block's fault, so every block goes back and
/// the retry runs one block at a time. An engine fault is no block's fault:
/// every block goes back and the retry is not isolated. Same order as
/// [`rearm_after_reject`]: serialize, isolate, re-arm, insert.
#[doc(hidden)]
pub fn load_fail_rewind_wave(
    feed: &ConfirmFeed,
    hub: &ChainHub,
    lookup_ahead: &mut LoadAheadState,
    first_h: u32,
    class: ConfirmRejectClass,
    wave: &[OfferBack<'_>],
) {
    let fault = class == ConfirmRejectClass::EngineFault;
    let drop_head = wave.len() == 1 && !fault && class != ConfirmRejectClass::Cascade;
    let prepared = prepare_offer_back(hub, wave[usize::from(drop_head)..].iter().copied());
    lookup_ahead.clear_all(hub);
    feed.finish(std::iter::once(first_h));
    feed.clear();
    // After `clear` (which drops isolation) and before the re-offer, so
    // lookup cannot rebuild the same wave.
    if wave.len() > 1 && !fault {
        feed.request_single_block(first_h.saturating_add(wave.len() as u32 - 1));
    }
    hub.query.set_lookup_taken_hi(hub.tip_height());
    hub.query.set_lookup_started_hi(hub.tip_height());
    offer_back(hub, prepared);
    feed.notify();
}

/// A pin-stage engine fault that is not a uring session fault is a stale
/// plan and rewinds as a cascade. A session fault keeps the engine class.
#[doc(hidden)]
pub fn rewind_after_load_reject(
    feed: &ConfirmFeed,
    hub: &ChainHub,
    lookup_ahead: &mut LoadAheadState,
    first_h: u32,
    class: ConfirmRejectClass,
    session_fault: bool,
    wave: &[OfferBack<'_>],
) {
    let rewind = if class == ConfirmRejectClass::EngineFault && !session_fault {
        ConfirmRejectClass::Cascade
    } else {
        class
    };
    load_fail_rewind_wave(feed, hub, lookup_ahead, first_h, rewind, wave);
}

/// Peer id the wire was enqueued with: `sender` on [`ConfirmEvent::Reject`].
#[doc(hidden)]
pub fn wire_sender(wire: &rbitcoin_query::ResolvedWire) -> Option<usize> {
    wire.sender.and_then(|s| usize::try_from(s).ok())
}

pub fn lookup_ready_hash(feed: &ConfirmFeed, height: u32) -> Option<BlockHash> {
    feed.inner
        .lock()
        .ok()
        .and_then(|g| g.ready.get(&height).copied())
}

#[doc(hidden)]
pub const LOOKUP_FAULT_HALT_AFTER: u32 = 8;

#[derive(Debug, Default)]
pub struct LookupFaultPolicy {
    pub consecutive: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupFaultAction {
    Ignore,
    Warn,
    RejectEngineFault,
    /// The wave saw the confirm cancel (IBD teardown): leave the lookup loop.
    Stop,
}

impl LookupFaultPolicy {
    pub fn on_success(&mut self) {
        self.consecutive = 0;
    }

    pub fn on_err(&mut self, e: &rbitcoin_query::ConfirmError) -> LookupFaultAction {
        if e.is_cancelled() {
            return LookupFaultAction::Stop;
        }
        let backpressure = matches!(
            e,
            rbitcoin_query::ConfirmError::Store(se) if se.is_io_backpressure()
        );
        if backpressure {
            return LookupFaultAction::Ignore;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive >= LOOKUP_FAULT_HALT_AFTER {
            LookupFaultAction::RejectEngineFault
        } else {
            LookupFaultAction::Warn
        }
    }
}

#[doc(hidden)]
pub static LOOKUP_WAVE_FAULTS: AtomicU64 = AtomicU64::new(0);

pub fn take_lookup_wave_faults() -> u64 {
    LOOKUP_WAVE_FAULTS.swap(0, Ordering::Relaxed)
}

/// Parent hash already resolved for a confirm reject.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectParent {
    pub hash: Option<BlockHash>,
    pub unreadable: bool,
}

impl RejectParent {
    pub fn from_lookup(hub: &ChainHub, hash: BlockHash) -> Self {
        match super::reorg::parent_hash_of(hub, hash) {
            Ok(Some(hash)) => Self {
                hash: Some(hash),
                unreadable: false,
            },
            // No header row. Distinct from a store error so the reject is an
            // engine fault, not a cascade and not a blacklist.
            Ok(None) => Self {
                hash: None,
                unreadable: false,
            },
            Err(_) => Self {
                hash: None,
                unreadable: true,
            },
        }
    }
}

pub enum ConfirmEvent {
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
        /// Peer that sent the copy of `hash` that failed, read from the wire
        /// the confirm thread held. IBD's own record may by now name the
        /// sender of a replacement copy.
        sender: Option<usize>,
        parent: RejectParent,
    },
}

thread_local! {
    static CONFIRM_PROGRESS_LAST: Cell<Option<Instant>> = const { Cell::new(None) };
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn clear_confirm_progress_clock() {
    CONFIRM_PROGRESS_LAST.with(|cell| cell.set(None));
}

/// Publish operator snapshots when `now` is at least 5s after the last publish.
#[doc(hidden)]
pub fn publish_confirm_progress_at(query: &rbitcoin_query::Query, now: Instant) {
    let due = CONFIRM_PROGRESS_LAST.with(|cell| match cell.get() {
        Some(t) if now.saturating_duration_since(t) < Duration::from_secs(5) => false,
        _ => {
            cell.set(Some(now));
            true
        }
    });
    if due {
        query.publish_progress_snapshots();
    }
}

#[doc(hidden)]
pub fn publish_confirm_progress(query: &rbitcoin_query::Query) {
    publish_confirm_progress_at(query, Instant::now());
}

/// Pause before a block too far ahead of the clock is tried again.
pub const TIME_TOO_NEW_HOLD: Duration = Duration::from_secs(1);

/// A reject for a block more than 2 hours ahead of the clock: it is valid
/// once the clock catches up.
pub fn is_time_too_new(err: &str) -> bool {
    let s = err.to_ascii_lowercase();
    s.contains("timestamp too far in future") || s.contains("time-too-new")
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[doc(hidden)]
pub fn emit_confirm_reject(
    tx: &std::sync::mpsc::Sender<ConfirmEvent>,
    feed: &ConfirmFeed,
    height: u32,
    hash: BlockHash,
    class: ConfirmRejectClass,
    err: String,
    batch_len: usize,
    sender: Option<usize>,
    parent: RejectParent,
) -> Result<(), std::sync::mpsc::SendError<ConfirmEvent>> {
    let class = class.isolate_if_batched(batch_len);
    // A clock stepped back can leave a stored header more than 2 hours
    // ahead. Try it again after a pause, not at once.
    if is_time_too_new(&err) {
        feed.hold_for(TIME_TOO_NEW_HOLD);
    }
    if class == ConfirmRejectClass::Cascade && batch_len > 1 {
        let until = height.saturating_add(batch_len as u32).saturating_sub(1);
        feed.request_single_block(until);
    }
    tx.send(ConfirmEvent::Reject {
        height,
        hash,
        class,
        err,
        batch_len,
        sender,
        parent,
    })
}

/// Hard cap on consecutive ready heights in one confirm wave.
///
/// Primary bound is soft **input** budget ([`confirm_batch_max_inputs`]); this
/// caps how many thin early-chain blocks pack into one lookup/load/script wave.
pub const CONFIRM_RUN_MAX_BLOCKS: usize = 144;

/// Default soft max Σ `tx.input` over a packed confirm run.
pub const CONFIRM_BATCH_INPUTS_DEFAULT: u32 = 8000;

/// How far ahead of tip to pre-note ready bodies into the feed.
/// ≥ [`CONFIRM_RUN_MAX_BLOCKS`] so the engine can fill a full hard-cap wave.
#[doc(hidden)]
pub const OFFER_AHEAD: u32 = 192;

/// Soft max inputs per confirm batch (hardcoded production default).
#[inline]
pub fn confirm_batch_max_inputs() -> u32 {
    CONFIRM_BATCH_INPUTS_DEFAULT
}

/// Whether the packed run should stop **after** accepting a block that left
/// `sum_inputs` / `n_blocks` in this state (soft overshoot + hard block cap).
#[inline]
pub fn pack_stop_after(
    sum_inputs: u32,
    n_blocks: usize,
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> bool {
    n_blocks >= hard_max_blocks || sum_inputs > soft_max_inputs
}

/// Default lookup→load depth (`loadq`): prefetch of load-sized batches.
pub const LOAD_QUEUE_CAP_DEFAULT: usize = 14;
/// Default load→scripts depth (`scriptq`): script is the long pole; modest buffer.
pub const SCRIPT_QUEUE_CAP_DEFAULT: usize = 4;
/// Default scripts→write depth: write is bursty (class_a head / tip flush); buffer
/// script output so script thr does not stall on a full writeq.
pub const WRITE_QUEUE_CAP_DEFAULT: usize = 14;

/// Blocks added to or removed from the extra in-flight window per wave.
pub const INFLIGHT_RETAIN_STEP: u32 = 64;
/// Accounted-heap line (1 GiB). Under it the window can grow; over it the window shrinks.
pub const INFLIGHT_RETAIN_OWNED_LIMIT: u64 = 1 << 30;
/// `height_by_hash` entry estimate from the old `ibd: sizes` accounted total.
#[doc(hidden)]
pub const H2H_ENTRY_BYTES: u64 = 48;
/// Height-fence run estimate from that same total.
#[doc(hidden)]
pub const FENCE_RUN_BYTES: u64 = 16;

/// Process heap the old `ibd: sizes` line called `accounted`.
///
/// Body queue, in-flight CreatePins, write-loc packs, the hash→height map,
/// the height fence, confirm-queue wire, and the heap parts of fuse / MPHF /
/// Class C. Mapped tables and allocator residue are not in this sum.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccountedHeap {
    pub bq_bytes: u64,
    pub inflight_bytes: u64,
    pub wloc_bytes: u64,
    pub h2h_keys: u64,
    pub fence_runs: u64,
    pub wire_bytes: u64,
    pub fuse8_bytes: u64,
    pub mphf_g_bytes: u64,
    pub mphf_occ_bytes: u64,
    pub class_c_l2_bytes: u64,
}

impl AccountedHeap {
    pub fn bytes(self) -> u64 {
        self.bq_bytes
            .saturating_add(self.inflight_bytes)
            .saturating_add(self.wloc_bytes)
            .saturating_add(self.h2h_keys.saturating_mul(H2H_ENTRY_BYTES))
            .saturating_add(self.fence_runs.saturating_mul(FENCE_RUN_BYTES))
            .saturating_add(self.wire_bytes)
            .saturating_add(self.fuse8_bytes)
            .saturating_add(self.mphf_g_bytes)
            .saturating_add(self.mphf_occ_bytes)
            .saturating_add(self.class_c_l2_bytes)
    }

    #[doc(hidden)]
    pub fn from_hub(hub: &ChainHub, inflight_bytes: u64, wire_bytes: u64) -> Self {
        let owned = hub.query.process_owned_size_snapshot();
        let (bq_bytes, _count) = hub.query.block_queue_stats();
        let head = owned.head;
        Self {
            bq_bytes,
            inflight_bytes,
            wloc_bytes: owned.wloc_bytes,
            h2h_keys: owned.h2h_keys as u64,
            fence_runs: owned.fence_runs as u64,
            wire_bytes,
            fuse8_bytes: head.fuse8_bytes,
            mphf_g_bytes: head.mphf_g_bytes,
            mphf_occ_bytes: head.mphf_occ_bytes,
            class_c_l2_bytes: head.class_c_l2_bytes,
        }
    }
}

/// Extra blocks kept below the drain+fence snapshot.
///
/// Under [`INFLIGHT_RETAIN_OWNED_LIMIT`], a wave that would drop packs keeps
/// [`INFLIGHT_RETAIN_STEP`] more. Over the limit, each wave gives that many
/// back. Exactly on the limit, the window holds.
#[derive(Debug, Default)]
pub struct InflightRetain {
    pub extra: u32,
}

impl InflightRetain {
    pub fn extra(&self) -> u32 {
        self.extra
    }

    /// Record one wave. `would_drop` is the current window, before this step.
    /// Returns the extra blocks to keep below the drain+fence snapshot.
    pub fn observe(&mut self, accounted_bytes: u64, would_drop: bool) -> u32 {
        if accounted_bytes > INFLIGHT_RETAIN_OWNED_LIMIT {
            self.extra = self.extra.saturating_sub(INFLIGHT_RETAIN_STEP);
        } else if accounted_bytes < INFLIGHT_RETAIN_OWNED_LIMIT && would_drop {
            self.extra = self.extra.saturating_add(INFLIGHT_RETAIN_STEP);
        }
        self.extra
    }
}

/// Drain+fence snapshot lowered by `extra` blocks. `None` still keeps every pack.
pub fn inflight_prune_height(drain_hi: Option<u32>, extra: u32) -> Option<u32> {
    drain_hi.map(|h| h.saturating_sub(extra))
}

/// One load-sized run produced by lookup (decoded wire + pres, height-ordered).
pub struct LoadBatch {
    pub items: Vec<(u32, [u8; 32], rbitcoin_query::ResolvedWire)>,
    pub parent_ids: Option<rbitcoin_query::BatchParentIds>,
    /// Drain+fence height snapshotted before this lookup wave's TipOnly.
    /// `Some` only on the last sent batch of the wave; load drops in-flight
    /// layers with `max_height` below this after the in-flight read.
    pub drop_inflight_below: Option<u32>,
    /// [`ConfirmFeed::epoch`] when lookup built this batch.
    pub epoch: u64,
    /// [`rbitcoin_query::Query::lookup_taken_gen`] when lookup selected the
    /// wave. Load drops its look-ahead plan when this changes.
    pub gen: u32,
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Stamp inputs for one loadq run. Lookup `pres` must ride through (`Some`);
/// load must not drop it and `from_tx` again.
pub fn load_stamp_items(
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
/// `has_body` is per height from BQ `header_fk` + Class A range (not hash-head).
/// Empty skips the kind split.
pub fn split_wave_into_load_batches_kind(
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

/// Per-chunk need-vouts from carried spend keys ∩ wave ids (no wire input walk).
pub fn chunk_parent_ids(
    wave: &rbitcoin_query::BatchParentIds,
    items: &[(u32, [u8; 32], rbitcoin_query::ResolvedWire)],
) -> rbitcoin_query::BatchParentIds {
    let mut need_vouts: rbitcoin_query::U64Map<Vec<u32>> = rbitcoin_query::U64Map::default();
    for (_, _, w) in items {
        for &(prev, vout) in w.spend_keys.iter() {
            if let Some((fk, _)) = wave.ids.get(&prev) {
                if let Some(id) = fk.get() {
                    need_vouts.entry(id).or_default().push(vout);
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
        n_out: std::sync::Arc::clone(&wave.n_out),
        need_vouts,
    }
}

/// Chunk a lookup wave into loadq batches; mark the last sent with `drop_below`.
pub fn load_batches_from_wave(
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
            gen: 0,
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
pub struct ConfirmQueueCaps {
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
pub fn confirm_queue_caps() -> ConfirmQueueCaps {
    ConfirmQueueCaps {
        load: LOAD_QUEUE_CAP_DEFAULT,
        script: SCRIPT_QUEUE_CAP_DEFAULT,
        write: WRITE_QUEUE_CAP_DEFAULT,
    }
}

/// Lookup→load (`loadq`) capacity.
pub fn load_queue_cap() -> usize {
    confirm_queue_caps().load
}
/// Load→scripts (`scriptq`) capacity.
pub fn script_queue_cap() -> usize {
    confirm_queue_caps().script
}
/// Scripts→write (`writeq`) capacity.
pub fn write_queue_cap() -> usize {
    confirm_queue_caps().write
}

/// How many script-ok parts write may merge in one `confirm_write_phase`.
///
/// Snapshot-drain: take everything already in `writeq` before work starts
/// so one `flush_class_c_tip` covers the queued run and scripts see an empty
/// queue while write runs. Does not pull more parts mid-write.
#[inline]
pub fn write_drain_max_parts(writeq_cap: usize) -> usize {
    writeq_cap.max(1)
}

/// BQ heights ≥ `path_lo` with resolve-complete and not load-inflight.
pub fn confirm_ready_count(
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
pub struct ConfirmQueueDepths {
    /// lookup → load (`loadq`; capacity [`load_queue_cap`]).
    pub lookup_to_load: AtomicUsize,
    /// Sum of `batch.len()` sitting in loadq.
    pub load_blocks: AtomicUsize,
    /// Approx decoded wire bytes sitting in loadq.
    pub load_wire_bytes: AtomicUsize,
    /// load → scripts (`scriptq`; capacity [`script_queue_cap`]).
    pub load_to_scripts: AtomicUsize,
    /// scripts → write (`writeq`; capacity [`write_queue_cap`]).
    pub scripts_to_write: AtomicUsize,
    /// Max load→scripts depth since last HWM sample.
    pub script_hwm: AtomicUsize,
    /// Max scripts→write depth since last HWM sample.
    pub write_hwm: AtomicUsize,
    /// Sum of `batch.len()` sitting in load→scripts.
    pub script_blocks: AtomicUsize,
    /// Sum of approx wire bytes of load→scripts batches.
    pub script_wire_bytes: AtomicUsize,
    /// Sum of `BatchParents` entries riding load→scripts batches.
    pub script_parents: AtomicUsize,
    /// Sum of `batch.len()` sitting in scripts→write.
    pub write_blocks: AtomicUsize,
    pub write_wire_bytes: AtomicUsize,
    /// Sum of `BatchParents` entries in scripts→write (entry count, not unique Arc).
    pub write_parents: AtomicUsize,
}

/// Snapshot of confirm pipeline retain (queue depths + batch contents + feed).
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct ConfirmPipelineSizes {
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
    #[cfg(debug_assertions)]
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
pub fn format_queue_depth(name: &str, depth: usize, cap: usize) -> String {
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
pub fn format_conf_q(
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
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `(lookup→load, load→scripts, scripts→write)`.
    pub fn snap(&self) -> (usize, usize, usize) {
        (
            self.lookup_to_load.load(Ordering::Relaxed),
            self.load_to_scripts.load(Ordering::Relaxed),
            self.scripts_to_write.load(Ordering::Relaxed),
        )
    }

    pub fn load_depth(&self) -> usize {
        self.lookup_to_load.load(Ordering::Relaxed)
    }

    /// Max scriptq and writeq depths since last call; resets those HWMs to 0.
    pub fn sample_hwm_and_reset(&self) -> (usize, usize) {
        (
            self.script_hwm.swap(0, Ordering::Relaxed),
            self.write_hwm.swap(0, Ordering::Relaxed),
        )
    }

    /// Full content snapshot (depths + blocks/wire/parents in each queue).
    pub fn content_snap(&self) -> ConfirmPipelineSizes {
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
    #[doc(hidden)]
    pub fn note_depth_hwm(hwm: &AtomicUsize, depth_after: usize) {
        let _ = hwm.fetch_max(depth_after, Ordering::Relaxed);
    }

    /// Batch depth: saturating so a double-recv under teardown cannot wrap to
    /// usize::MAX and panic debug overflow on the next send (`fetch_add + 1`).
    #[inline]
    #[doc(hidden)]
    pub fn note_batch_depth_send(depth: &AtomicUsize, hwm: &AtomicUsize) {
        let prev = depth
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or(0);
        Self::note_depth_hwm(hwm, prev.saturating_add(1));
    }

    #[inline]
    #[doc(hidden)]
    pub fn note_batch_depth_recv(depth: &AtomicUsize) {
        let _ = depth.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_sub(1))
        });
    }

    #[doc(hidden)]
    pub fn note_load_send(&self, blocks: usize, wire_bytes: usize) {
        let _ = self
            .lookup_to_load
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        self.load_blocks
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(blocks))
            })
            .ok();
        self.load_wire_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(wire_bytes))
            })
            .ok();
    }
    #[doc(hidden)]
    pub fn note_load_recv(&self, blocks: usize, wire_bytes: usize) {
        Self::note_batch_depth_recv(&self.lookup_to_load);
        self.load_blocks
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(blocks))
            })
            .ok();
        self.load_wire_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(wire_bytes))
            })
            .ok();
    }

    #[doc(hidden)]
    pub fn note_script_send(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_send(&self.load_to_scripts, &self.script_hwm);
        Self::add_stage(
            &self.script_blocks,
            &self.script_wire_bytes,
            &self.script_parents,
            blocks,
            wire_bytes,
            parents,
        );
    }
    #[doc(hidden)]
    pub fn note_script_recv(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_recv(&self.load_to_scripts);
        Self::sub_stage(
            &self.script_blocks,
            &self.script_wire_bytes,
            &self.script_parents,
            blocks,
            wire_bytes,
            parents,
        );
    }

    #[doc(hidden)]
    pub fn note_write_send(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_send(&self.scripts_to_write, &self.write_hwm);
        Self::add_stage(
            &self.write_blocks,
            &self.write_wire_bytes,
            &self.write_parents,
            blocks,
            wire_bytes,
            parents,
        );
    }
    #[doc(hidden)]
    pub fn note_write_recv(&self, blocks: usize, wire_bytes: usize, parents: usize) {
        Self::note_batch_depth_recv(&self.scripts_to_write);
        Self::sub_stage(
            &self.write_blocks,
            &self.write_wire_bytes,
            &self.write_parents,
            blocks,
            wire_bytes,
            parents,
        );
    }

    // Saturating: concurrent sends under parallel load can race past
    // usize::MAX on wire_bytes/parents counters in debug overflow checks.
    #[doc(hidden)]
    pub fn add_stage(
        blocks: &AtomicUsize,
        wire_bytes: &AtomicUsize,
        parents: &AtomicUsize,
        n_blocks: usize,
        n_wire: usize,
        n_parents: usize,
    ) {
        Self::update_stage(
            blocks,
            wire_bytes,
            parents,
            n_blocks,
            n_wire,
            n_parents,
            usize::saturating_add,
        );
    }

    #[doc(hidden)]
    pub fn sub_stage(
        blocks: &AtomicUsize,
        wire_bytes: &AtomicUsize,
        parents: &AtomicUsize,
        n_blocks: usize,
        n_wire: usize,
        n_parents: usize,
    ) {
        Self::update_stage(
            blocks,
            wire_bytes,
            parents,
            n_blocks,
            n_wire,
            n_parents,
            usize::saturating_sub,
        );
    }

    #[doc(hidden)]
    pub fn update_stage(
        blocks: &AtomicUsize,
        wire_bytes: &AtomicUsize,
        parents: &AtomicUsize,
        n_blocks: usize,
        n_wire: usize,
        n_parents: usize,
        op: fn(usize, usize) -> usize,
    ) {
        for (slot, n) in [
            (blocks, n_blocks),
            (wire_bytes, n_wire),
            (parents, n_parents),
        ] {
            slot.try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| Some(op(cur, n)))
                .ok();
        }
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Operator line for load stamp reject. Stamp-stage `missing prevout` is the
/// leftover TipOnly miss remapped from `parent create_fk unresolved` — name
/// that so a race is not logged as a bare invalid-block.
pub fn format_stamp_reject_missing_prevout(
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

/// Longest a stamp miss waits for its block's parent to be the tip, with
/// `tx.head` holding every connected create. The parent was stamped just
/// before, and scripts and write never wait on load.
#[doc(hidden)]
pub const PARENT_CHECK_WAIT: Duration = Duration::from_secs(10);

thread_local! {
    /// `Some` advances the parent-check deadline without sleeping. Unset uses
    /// [`Instant::now`] and a 2ms sleep, which is the confirm thread.
    static PARENT_CHECK_CLOCK: Cell<Option<Instant>> = const { Cell::new(None) };
}

#[doc(hidden)]
pub fn parent_now() -> Instant {
    PARENT_CHECK_CLOCK.with(|cell| cell.get().unwrap_or_else(Instant::now))
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn set_parent_check_clock(now: Option<Instant>) {
    PARENT_CHECK_CLOCK.with(|cell| cell.set(now));
}

#[doc(hidden)]
pub fn parent_check_wait_slice() {
    let advanced = PARENT_CHECK_CLOCK.with(|cell| {
        if let Some(t) = cell.get() {
            cell.set(Some(t + Duration::from_millis(500)));
            true
        } else {
            false
        }
    });
    if !advanced {
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A fresh read of a lone block's parents after its load stamp missed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ParentCheck {
    /// The connected chain does not hold this parent: the block's verdict.
    Missing([u8; 32]),
    /// The block's parent is not the tip, the chain moved during the read,
    /// or confirm is stopping: retry the block.
    OffTip,
    /// The chain holds every parent, or the read could not be trusted: the
    /// pipeline missed it.
    Engine,
}

/// The stamp reads the pipeline's own view (in-flight and load-batch
/// skeleton), and a miss there has blacklisted valid blocks before. A
/// verdict needs the tip path's read: the block extends the tip, `tx.head`
/// holds every connected create, a fresh TipOnly read still misses, and no
/// disconnect ran from the wait through the read.
#[doc(hidden)]
pub fn check_missing_parent(
    hub: &ChainHub,
    feed: &ConfirmFeed,
    block: &bitcoin::Block,
) -> ParentCheck {
    let prev = block.header.prev_blockhash;
    let mut disconnects = 0u64;
    let _ = hub.query.take_disconnect(&mut disconnects);
    let on_tip = || hub.tip_hash() == Some(prev);
    let ready = || on_tip() && hub.query.head_covers_fence();
    let stop = || feed.stopped() || hub.query.confirm_cancelled();
    let deadline = parent_now() + PARENT_CHECK_WAIT;
    while !ready() {
        if stop() || parent_now() >= deadline {
            return if on_tip() && !feed.stopped() {
                ParentCheck::Engine
            } else {
                ParentCheck::OffTip
            };
        }
        parent_check_wait_slice();
    }
    // Same HDD gate as lookup and load: this read scans `tx.head`.
    hub.query.store().spindle_wait();
    let read = rbitcoin_query::parent_missing_from_chain(&hub.query, block, stop);
    if stop() || !ready() || hub.query.take_disconnect(&mut disconnects).is_some() {
        return ParentCheck::OffTip;
    }
    match read {
        Ok(Some(txid)) => ParentCheck::Missing(txid),
        Ok(None) => ParentCheck::Engine,
        Err(e) => {
            warn!("ibd: missing-parent read for {}: {e}", block.block_hash());
            ParentCheck::Engine
        }
    }
}

/// A batched stamp miss keeps its consensus class, which isolates the retry
/// to one block at a time. A lone block's miss takes the class of its
/// [`ParentCheck`]; an engine fault goes back once, and a repeat halts IBD.
#[doc(hidden)]
pub fn stamp_reject_class(
    e: &rbitcoin_query::ConfirmError,
    check: Option<ParentCheck>,
) -> ConfirmRejectClass {
    match check {
        Some(ParentCheck::Missing(_)) => ConfirmRejectClass::ConsensusInvalid,
        Some(ParentCheck::OffTip) => ConfirmRejectClass::Cascade,
        Some(ParentCheck::Engine) => ConfirmRejectClass::EngineFault,
        None => ConfirmRejectClass::from_confirm(e),
    }
}

pub fn stamp_reject_operator_msg(err: &str, stats: &rbitcoin_query::ConfirmStats) -> String {
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
/// Archived-body clear waiting on the write thread. Not pushed back onto the
/// channel: `std` mpsc has no unread.
#[doc(hidden)]
pub struct ArchivedBodyClear {
    pub hash: [u8; 32],
    pub reply: std::sync::mpsc::Sender<Result<bool, rbitcoin_store::StoreError>>,
}

#[doc(hidden)]
pub fn drain_script_ok_write_queue(
    first: rbitcoin_query::ScriptOkBatch,
    rx: &std::sync::mpsc::Receiver<rbitcoin_query::ConfirmWriteMsg>,
    max_parts: usize,
    mut on_extra: impl FnMut(&rbitcoin_query::ScriptOkBatch),
) -> (
    rbitcoin_query::ScriptOkBatch,
    usize,
    Option<rbitcoin_query::ScriptOkBatch>,
    Option<ArchivedBodyClear>,
) {
    let mut batch = first;
    let mut parts = 1usize;
    let max_parts = max_parts.max(1);
    loop {
        if parts >= max_parts {
            break;
        }
        match rx.try_recv() {
            Ok(rbitcoin_query::ConfirmWriteMsg::ClearArchived { hash, reply }) => {
                return (batch, parts, None, Some(ArchivedBodyClear { hash, reply }));
            }
            Ok(rbitcoin_query::ConfirmWriteMsg::Batch(more)) => {
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
                        return (batch, parts, Some(leftover), None);
                    }
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
        }
    }
    (batch, parts, None, None)
}

fn finish_archived_clear(query: &rbitcoin_query::Query, clear: ArchivedBodyClear) {
    let result = (|| {
        let _commit = query.lock_tip_commit()?;
        query.clear_archived_body_here(&clear.hash)
    })();
    let _ = clear.reply.send(result);
}

struct ConfirmWriteDetach<'a>(&'a rbitcoin_query::Query);

impl Drop for ConfirmWriteDetach<'_> {
    fn drop(&mut self) {
        self.0.detach_confirm_write();
    }
}

/// OS-thread occupancy for the confirm pipeline (lookup / load / scripts / write).
///
/// Stage `plan_ms` / `script_ms` / … are **work** sums and mis-rank the long
/// pole when scriptq is empty. These timers include **wait** (claim, recv, send
/// block) so a 5s window can show who is busy vs idle.
#[doc(hidden)]
pub mod confirm_thr_stats {
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
    pub fn add_load_reject(stats: &rbitcoin_query::ConfirmStats, d: Duration) {
        rbitcoin_query::note_confirm_dur(&stats.thr_load_reject_ns, d);
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

    /// Time from batch start until both the script wave and the index wave
    /// have finished. Both arguments are completion offsets from that start.
    /// The sum double-counts when the waves overlap.
    #[inline]
    pub fn stage_wall_ns(script_done: u64, index_done: u64) -> u64 {
        script_done.max(index_done)
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
pub fn write_batch_is_stale(hub: &ChainHub, first_h: u32) -> bool {
    let expect = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    first_h != expect
}

/// Height-stale **or** claimed before a later [`ConfirmFeed::clear`] (sibling
/// at the new tip+1 would still pass the height check).
pub fn write_batch_is_stale_plan(hub: &ChainHub, feed: &ConfirmFeed, first_h: u32) -> bool {
    write_batch_is_stale(hub, first_h) || feed.plan_epoch_stale(first_h)
}

/// Spawn confirm **lookup** + **load** + **scripts** + **write** OS threads.
///
/// Lookup (BQ-ahead TipOnly `head_fk`) ∥ load (claim resolve-complete + stamp
/// from in-flight + skeleton + pin + assemble) → scriptq →
/// scripts → writeq → write.
/// Returns the lookup-thread join handle and shared queue-depth counters.
#[allow(clippy::cognitive_complexity)] // lookup also drops undecodable wire before the load batch
pub fn spawn_confirm_engine(
    hub: Arc<ChainHub>,
    feed: Arc<ConfirmFeed>,
    event_tx: std::sync::mpsc::Sender<ConfirmEvent>,
    accepted: Arc<AtomicU32>,
    loop_stats: Arc<LoopStats>,
) -> (std::thread::JoinHandle<()>, Arc<ConfirmQueueDepths>) {
    let queues = ConfirmQueueDepths::new();
    let caps = confirm_queue_caps();
    type ScriptsIn = (rbitcoin_query::LoadedBatch, u64);
    let (mat_tx, mat_rx) = std::sync::mpsc::sync_channel::<ScriptsIn>(caps.script);
    let (write_tx, write_rx) =
        std::sync::mpsc::sync_channel::<rbitcoin_query::ConfirmWriteMsg>(caps.write);
    hub.query.attach_confirm_write(write_tx.clone());
    let (load_tx, load_rx) = std::sync::mpsc::sync_channel::<LoadBatch>(caps.load);
    // A write fault that does not re-arm lookup: plan drops reserved fks +
    // last_loaded so re-lookup after Class A partial commit does not drift
    // next_tx_start. A re-arm resets load through the lookup generation.
    let load_ahead_reset = Arc::new(AtomicBool::new(false));
    hub.query.ensure_tip_flush_worker();

    let hub_wb = Arc::clone(&hub);
    let feed_wb = Arc::clone(&feed);
    let event_tx_wb = event_tx.clone();
    let accepted_wb = Arc::clone(&accepted);
    let loop_stats_wb = Arc::clone(&loop_stats);
    let q_wb = Arc::clone(&queues);
    let load_ahead_reset_wb = Arc::clone(&load_ahead_reset);
    let write_thr = std::thread::Builder::new()
        .name("ibd-confirm-write".into())
        .spawn(
            #[allow(clippy::cognitive_complexity)] // confirm write OS pipeline
            move || {
            info!("ibd: confirm write on dedicated OS thread");
            let stats = hub_wb.query.confirm_stats_arc();
            let _detach = ConfirmWriteDetach(&hub_wb.query);
            // Non-contig leftover already note_write_recv'd; write it next iter.
            let mut leftover: Option<rbitcoin_query::ScriptOkBatch> = None;
            let mut pending_clear: Option<ArchivedBodyClear> = None;
            loop {
                if let Some(clear) = pending_clear.take() {
                    finish_archived_clear(&hub_wb.query, clear);
                    continue;
                }
                let t_recv = Instant::now();
                let first = match leftover.take() {
                    Some(b) => b,
                    None => match write_rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(rbitcoin_query::ConfirmWriteMsg::Batch(b)) => {
                            let n = b.len();
                            let wire = b.approx_wire_bytes();
                            let parents = b.parent_count();
                            q_wb.note_write_recv(n, wire, parents);
                            b
                        }
                        Ok(rbitcoin_query::ConfirmWriteMsg::ClearArchived { hash, reply }) => {
                            finish_archived_clear(
                                &hub_wb.query,
                                ArchivedBodyClear { hash, reply },
                            );
                            continue;
                        }
                        // Query keeps a sender so clear can arrive. That sender
                        // also keeps `recv` from seeing disconnect at shutdown.
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if feed_wb.stopped() || hub_wb.query.confirm_cancelled() {
                                break;
                            }
                            continue;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    },
                };
                let (batch, parts, next_left, clear) = drain_script_ok_write_queue(
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
                pending_clear = clear;
                confirm_thr_stats::add_write_recv_wait(&stats, t_recv.elapsed());
                if feed_wb.stopped() || hub_wb.query.confirm_cancelled() {
                    break;
                }
                publish_confirm_progress(&hub_wb.query);
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
                let headers = match batch.wire_headers() {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("ibd: confirm write {e}");
                        feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                        break;
                    }
                };
                let meta: Vec<(u32, BlockHash)> = heights_hashes
                    .iter()
                    .map(|&(h, raw)| (h, BlockHash::from_byte_array(raw)))
                    .collect();
                // Same lock as a block connect. The chain tip must not move
                // while the relay-on purge is choosing the tip it stripped.
                let mp_hold = hub_wb.mempool().cloned();
                let mut template_hold = mp_hold.as_ref().map(|mp| mp.template_hold());
                match write_batch_trusted(&hub_wb, batch) {
                    Ok(_fks) => {
                        if let Err(e) =
                            hub_wb.note_confirmed_tip_while(&meta, &headers, template_hold.as_mut())
                        {
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
                                 bip68={}ms class_c={}ms spend_ann={}ms",
                                elapsed,
                                ms(p.class_a_ns),
                                ms(p.ensure_ns),
                                ms(p.structural_ns),
                                ms(p.spent_ns),
                                ms(p.create_h_ns),
                                ms(p.bip68_ns),
                                ms(p.class_c_ns),
                                ms(p.spend_ann_ns),
                            );
                        }
                    }
                    Err((e, failed)) => {
                        confirm_thr_stats::add_write_work(&stats, t0.elapsed());
                        let mut err = e;
                        let msg = err.to_string();
                        if err.is_cancelled() || feed_wb.stopped()
                        {
                            info!("ibd: confirm write aborted: {msg}");
                            break;
                        }
                        let (height, hash) = heights_hashes
                            .first()
                            .map(|(h, raw)| (*h, BlockHash::from_byte_array(*raw)))
                            .unwrap_or((first_h, BlockHash::from_byte_array([0u8; 32])));
                        let mut skip_stale = false;
                        if err.is_uring_session_fault() {
                            let all_connected = heights_hashes.iter().all(|(_, raw)| {
                                hub_wb.is_connected(&BlockHash::from_byte_array(*raw))
                            });
                            if all_connected {
                                match finish_connected_write_after_session_fault(
                                    &hub_wb.query,
                                    &heights_hashes,
                                ) {
                                    Ok(()) => {
                                        if let Err(e) = hub_wb.note_confirmed_tip_while(
                                            &meta,
                                            &headers,
                                            template_hold.as_mut(),
                                        ) {
                                            warn!("ibd: confirm write note tip: {e}");
                                        }
                                        for (h, raw) in &heights_hashes {
                                            let ha = BlockHash::from_byte_array(*raw);
                                            if let Err(e) =
                                                hub_wb.query.block_queue_dequeue_height(*h)
                                            {
                                                rbitcoin_log::debug!(
                                                    "ibd: block_queue dequeue h={h}: {e}"
                                                );
                                            }
                                            loop_stats_wb
                                                .confirm_blocks
                                                .fetch_add(1, Ordering::Relaxed);
                                            accepted_wb.fetch_add(1, Ordering::SeqCst);
                                            if event_tx_wb
                                                .send(ConfirmEvent::Accepted { hash: ha })
                                                .is_err()
                                            {
                                                feed_wb.finish(
                                                    heights_hashes.iter().map(|(hh, _)| *hh),
                                                );
                                                return;
                                            }
                                        }
                                        feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                                        continue;
                                    }
                                    Err(e2) => {
                                        err = e2;
                                        skip_stale = true;
                                    }
                                }
                            } else {
                                let t_rearm = Instant::now();
                                let wave: Vec<(u32, BlockHash, &bitcoin::Block)> = meta
                                    .iter()
                                    .zip(failed.wire_blocks())
                                    .map(|(&(h, ha), b)| (h, ha, b.as_ref()))
                                    .collect();
                                requeue_on_uring_recover(
                                    &hub_wb,
                                    &feed_wb,
                                    "ibd-confirm-write",
                                    &wave,
                                );
                                confirm_thr_stats::add_write_work(&stats, t_rearm.elapsed());
                                warn!(
                                    "ibd: confirm write uring recover @ {height} batch_parts={parts}: {err}"
                                );
                                continue;
                            }
                        }
                        let msg = err.to_string();
                        if !skip_stale && write_batch_is_stale_plan(&hub_wb, &feed_wb, height) {
                            debug!(
                                "ibd: confirm write drop stale batch first={height} ({msg})"
                            );
                            feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                            continue;
                        }
                        if !skip_stale
                            && (hub_wb.has_block(&hash)
                                || (msg.contains("prevout already spent")
                                    && heights_hashes.iter().all(|(_, raw)| {
                                        hub_wb.has_block(&BlockHash::from_byte_array(*raw))
                                    })))
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
                        feed_wb.finish(heights_hashes.iter().map(|(h, _)| *h));
                        loop_stats_wb
                            .confirm_reject_stops
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "ibd: confirm write reject @ {height} batch_parts={parts}: {err}"
                        );
                        let class = ConfirmRejectClass::from_confirm(&err);
                        let t_rearm = Instant::now();
                        let wave: Vec<(u32, BlockHash, &bitcoin::Block)> = meta
                            .iter()
                            .zip(failed.wire_blocks())
                            .map(|(&(h, ha), b)| (h, ha, b.as_ref()))
                            .collect();
                        apply_write_reject(&hub_wb, &feed_wb, class, &wave, &load_ahead_reset_wb);
                        confirm_thr_stats::add_write_work(&stats, t_rearm.elapsed());
                        let _ = emit_confirm_reject(
                            &event_tx_wb,
                            &feed_wb,
                            height,
                            hash,
                            class,
                            msg,
                            heights_hashes.len(),
                            None,
                            RejectParent::from_lookup(&hub_wb, hash),
                        );
                    }
                }
            }
            info!("ibd: confirm write exit");
        })
        .unwrap_or_else(|e| {
            hub.query.detach_confirm_write();
            panic!("spawn ibd-confirm-write: {e}");
        });

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
            rbitcoin_query::drive_script_waves_with(
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
                    let stage_ns = confirm_thr_stats::stage_wall_ns(
                        outcome.work_ns,
                        outcome.index_done_ns,
                    );
                    loop_stats_sc
                        .confirm_ns
                        .fetch_add(stage_ns, Ordering::Relaxed);
                    confirm_thr_stats::add_script_work(
                        &stats,
                        confirm_thr_stats::script_work_from_verify_ns(stage_ns),
                    );
                    let script_ms = outcome.work_ns / 1_000_000;
                    let mat_ms = meta.mat_ns / 1_000_000;
                    let wb = outcome.batch.len();
                    let ww = outcome.batch.approx_wire_bytes();
                    let parents = outcome.batch.parent_count();
                    let t_send = Instant::now();
                    if write_tx
                        .send(rbitcoin_query::ConfirmWriteMsg::Batch(outcome.batch))
                        .is_err()
                    {
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
                    if e.is_cancelled() || feed_sc.stopped()
                    {
                        info!("ibd: confirm scripts aborted: {msg}");
                        return false;
                    }
                    let session_fault = e.is_uring_session_fault();
                    let class = ConfirmRejectClass::from_confirm(&e);
                    // A retried, engine-faulted, or session-faulted wave goes
                    // back with the batches dropped behind it; a one-block
                    // verdict drops its block.
                    let retried = class.isolate_if_batched(meta.heights_hashes.len())
                        == ConfirmRejectClass::Cascade;
                    let t_rearm = Instant::now();
                    let full: Vec<(u32, BlockHash, &bitcoin::Block)> = std::iter::once(&meta)
                        .chain(dropped)
                        .flat_map(|m| m.heights_hashes.iter().zip(&m.wire_blocks))
                        .map(|(&(h, raw), b)| (h, BlockHash::from_byte_array(raw), b.as_ref()))
                        .collect();
                    if session_fault {
                        requeue_on_uring_recover(
                            &hub_sc,
                            &feed_sc,
                            "ibd-confirm-scripts",
                            script_reject_wave(retried, session_fault, class, &full),
                        );
                        confirm_thr_stats::add_script_work(&stats, t_rearm.elapsed());
                        warn!("ibd: confirm scripts uring recover @ {}: {e}", meta.first_h);
                        return true;
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
                    rearm_script_reject(&hub_sc, &feed_sc, retried, session_fault, class, &full);
                    confirm_thr_stats::add_script_work(&stats, t_rearm.elapsed());
                    let _ = emit_confirm_reject(
                        &event_tx_sc,
                        &feed_sc,
                        height,
                        hash,
                        class,
                        msg,
                        meta.heights_hashes.len(),
                        None,
                        RejectParent::from_lookup(&hub_sc, hash),
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
        .spawn(
            #[allow(clippy::cognitive_complexity)] // confirm load OS pipeline
            move || {
            info!(
                "ibd: confirm load on dedicated OS thread (claim resolve-complete → stamp+pin)"
            );
            let mut lookup_ahead = LoadAheadState::new(&hub_load);
            let mut stamped_gen: Option<u32> = None;
            let stats = hub_load.query.confirm_stats_arc();
            loop {
                if feed_load.stopped() || hub_load.query.confirm_cancelled() {
                    break;
                }
                let t_hygiene = Instant::now();
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
                let wire: usize = lb
                    .items
                    .iter()
                    .map(|(_, _, w)| {
                        rbitcoin_query::block_wire_len_from_pres(
                            w.block.txdata.len(),
                            w.pres.as_ref(),
                        )
                    })
                    .sum();
                queues_load.note_load_recv(n, wire);
                let parent_ids = lb.parent_ids;
                let claim_epoch = lb.epoch;
                let wave_gen = lb.gen;
                if claim_epoch != feed_load.epoch() {
                    debug!(
                        "ibd: confirm load drop stale plan epoch={claim_epoch} live={}",
                        feed_load.epoch()
                    );
                    reoffer_blocks_to_body_queue(
                        &hub_load,
                        lb.items.iter().map(|(h, raw, w)| {
                            let hash = BlockHash::from_byte_array(*raw);
                            (*h, hash, w.block.as_ref(), w.sender)
                        }),
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
                // After the recv: a rejected wave's bodies are offered back
                // and retaken at once, so a reset seen only before the recv
                // lets the retake stamp from the plan it just failed with.
                let t_reset = Instant::now();
                if load_ahead_reset_load.swap(false, Ordering::AcqRel)
                    || stamped_gen != Some(wave_gen)
                {
                    lookup_ahead.clear_all(&hub_load);
                }
                stamped_gen = Some(wave_gen);
                confirm_thr_stats::add_load_prune(&stats, t_reset.elapsed());
                if batch.is_empty() {
                    if drop_below.is_some() {
                        let t_prune = Instant::now();
                        lookup_ahead.drop_inflight_below(drop_below, &hub_load, &queues_load);
                        confirm_thr_stats::add_load_prune(&stats, t_prune.elapsed());
                    }
                    continue;
                }
                let expect_h = batch[0].0;
                if feed_load.stopped() || hub_load.query.confirm_cancelled() {
                    let req: Vec<(u32, BlockHash)> =
                        batch.iter().map(|(h, ha, _)| (*h, *ha)).collect();
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
                let mut carried_need = Vec::new();
                let mut carried_header_fks = Vec::with_capacity(wire_batch.len());
                let mut carried_header_hashes = Vec::with_capacity(wire_batch.len());
                for (_, ha, w) in &wire_batch {
                    for &(txid, _) in w.spend_keys.iter() {
                        if txid != [0u8; 32] {
                            carried_need.push(txid);
                        }
                    }
                    carried_header_fks.push(rbitcoin_primitives::Fk(w.header_fk));
                    carried_header_hashes.push(ha.to_byte_array());
                }
                let t_stamp = Instant::now();
                let plan_res = {
                    let pipe = lookup_ahead.pipeline_for(
                        expect_h,
                        store_path_lo,
                        parent_ids.clone(),
                        carried_need,
                        carried_header_fks,
                        carried_header_hashes,
                    );
                    load_bulk_stamp(
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
                        if e.is_cancelled() || feed_load.stopped()
                        {
                            drop(mat_tx);
                            rbitcoin_consensus::unpark_script_publisher();
                            let _ = scripts.join();
                            return;
                        }
                        let session_fault = e.is_uring_session_fault();
                        let parent_check = match (&e, wire_batch.as_slice()) {
                            (
                                rbitcoin_query::ConfirmError::Rules(
                                    rbitcoin_consensus::ConsensusError::MissingPrevout,
                                ),
                                [(_, _, w)],
                            ) => {
                                let t_check = Instant::now();
                                let check = check_missing_parent(&hub_load, &feed_load, &w.block);
                                confirm_thr_stats::add_load_reject(&stats, t_check.elapsed());
                                Some(check)
                            }
                            _ => None,
                        };
                        let t_rewind = Instant::now();
                        if session_fault {
                            hub_load.query.uring_recover_or_abort("ibd-confirm-load");
                        }
                        let first_hash = wire_batch[0].1;
                        let sender = wire_sender(&wire_batch[0].2);
                        let wave = wire_batch
                            .iter()
                            .map(|(h, ha, w)| (*h, *ha, w.block.as_ref(), w.sender))
                            .collect::<Vec<_>>();
                        let class = if session_fault {
                            ConfirmRejectClass::EngineFault
                        } else {
                            load_reject_class(&hub_load, stamp_reject_class(&e, parent_check), &wave)
                        };
                        load_fail_rewind_wave(
                            &feed_load,
                            &hub_load,
                            &mut lookup_ahead,
                            expect_h,
                            class,
                            &wave,
                        );
                        confirm_thr_stats::add_load_prune(&stats, t_rewind.elapsed());
                        if session_fault {
                            warn!(
                                "ibd: confirm load stamp uring recover {first_hash} @ {expect_h}: {e}"
                            );
                            continue;
                        }
                        loop_stats_load
                            .confirm_reject_stops
                            .fetch_add(1, Ordering::Relaxed);
                        let log_msg = match parent_check {
                            Some(ParentCheck::Missing(txid)) => format!(
                                "missing prevout: parent {} is not on the connected chain",
                                bitcoin::Txid::from_byte_array(txid)
                            ),
                            Some(ParentCheck::OffTip) => {
                                "missing prevout before its parent block is the tip (retry)".into()
                            }
                            Some(ParentCheck::Engine) | None => {
                                stamp_reject_operator_msg(&msg, &stats)
                            }
                        };
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
                            class,
                            log_msg,
                            wire_batch.len(),
                            sender,
                            RejectParent::from_lookup(&hub_load, first_hash),
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
                    lookup_ahead.note_archived_creates(
                        stamped.archived_create_pairs(),
                        stamped.last_height_hash(),
                    );
                }
                if drop_below.is_some() {
                    let t_prune = Instant::now();
                    lookup_ahead.drop_inflight_below(drop_below, &hub_load, &queues_load);
                    confirm_thr_stats::add_load_prune(&stats, t_prune.elapsed());
                }
                let pipe = lookup_ahead.pipeline_for(
                    expect_h,
                    store_path_lo,
                    parent_ids,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
                let plan_ns = stamped.work_ns;
                let heights_hashes: Vec<(u32, BlockHash)> = wire_batch
                    .iter()
                    .map(|(h, ha, _)| (*h, *ha))
                    .collect();
                let first_hash = heights_hashes[0].1;

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
                let mat_res = rbitcoin_query::confirm_run::waive_batch(hub_load.query.trust_peer(), || {
                    hub_load.confirm_wire_load_from_plan(stamped, Some(&pipe))
                });
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
                        if matches!(e, rbitcoin_net::error::NetError::Cancelled) {
                            info!("ibd: confirm load cancelled @ {expect_h}");
                            drop(mat_tx);
                            rbitcoin_consensus::unpark_script_publisher();
                            let _ = scripts.join();
                            return;
                        }
                        let session_fault =
                            rbitcoin_store::StoreError::is_uring_session_fault_msg(&msg);
                        let t_rewind = Instant::now();
                        if session_fault {
                            hub_load.query.uring_recover_or_abort("ibd-confirm-load");
                        }
                        let wave = wire_batch
                            .iter()
                            .map(|(h, ha, w)| (*h, *ha, w.block.as_ref(), w.sender))
                            .collect::<Vec<_>>();
                        let class = if session_fault {
                            ConfirmRejectClass::EngineFault
                        } else {
                            load_reject_class(&hub_load, ConfirmRejectClass::from_net(&e), &wave)
                        };
                        let sender = wire_sender(&wire_batch[0].2);
                        // A pin-stage invariant miss can be a stale-fk plan
                        // race, not a store fault: retry it one block at a
                        // time, as a cascade. A session fault is not a race.
                        rewind_after_load_reject(
                            &feed_load,
                            &hub_load,
                            &mut lookup_ahead,
                            expect_h,
                            class,
                            session_fault,
                            &wave,
                        );
                        confirm_thr_stats::add_load_prune(&stats, t_rewind.elapsed());
                        if session_fault {
                            warn!(
                                "ibd: confirm load uring recover {first_hash} @ {expect_h}: {e}"
                            );
                            continue;
                        }
                        loop_stats_load
                            .confirm_reject_stops
                            .fetch_add(1, Ordering::Relaxed);
                        warn!("ibd: confirm load reject {first_hash} @ {expect_h}: {e}");
                        if emit_confirm_reject(
                            &event_tx_load,
                            &feed_load,
                            expect_h,
                            first_hash,
                            class,
                            msg,
                            heights_hashes.len(),
                            sender,
                            RejectParent::from_lookup(&hub_load, first_hash),
                        )
                        .is_err()
                        {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
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
                if feed.held() {
                    let g = feed.inner.lock().unwrap_or_else(|err| err.into_inner());
                    let _ = feed
                        .cv
                        .wait_timeout(g, Duration::from_millis(20))
                        .unwrap_or_else(|err| err.into_inner());
                    continue;
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
                // Isolation retries one block through the whole pipeline. A
                // reject while an earlier block is still in write would
                // rewind under it and stamp the next plan from stale fks.
                // A re-arm isolates, bumps the generation, then offers bodies
                // back: read the generation first and re-check it after the
                // selection, so a wave never mixes the two sides of a re-arm.
                let taken_gen = hub.query.lookup_taken_gen();
                let single = feed.single_block();
                if single && (!skip.is_empty() || hub.query.lookup_taken_hi() > tip) {
                    let t_wait = Instant::now();
                    confirm_thr_stats::add_lookup_other(&stats, t_wait.duration_since(t_sel));
                    let g = feed.inner.lock().unwrap();
                    if feed.stopped() {
                        break;
                    }
                    let _ = feed.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
                    confirm_thr_stats::add_lookup_claim(&stats, t_wait.elapsed());
                    continue;
                }
                let run_max = if single { 1 } else { CONFIRM_RUN_MAX_BLOCKS };
                let max_blocks = if single {
                    1
                } else {
                    remaining
                        .saturating_mul(run_max)
                        .min(rbitcoin_query::BQ_RESOLVE_WAVE_MAX_BLOCKS)
                };
                let max_inputs = (remaining as u32)
                    .saturating_mul(confirm_batch_max_inputs())
                    .min(rbitcoin_query::BQ_RESOLVE_WAVE_MAX_INPUTS);
                let wave_h = hub
                    .query
                    .block_queue_unresolved_heights(path_lo, &skip, max_blocks);
                confirm_thr_stats::add_lookup_other(&stats, t_sel.elapsed());
                if hub.query.lookup_taken_gen() != taken_gen {
                    continue;
                }
                let mut did = false;
                if !wave_h.is_empty() {
                    let t_wave = Instant::now();
                    match lookup_bulk_wave(
                        &hub.query,
                        &hub.params,
                        hub.milestone,
                        &wave_h,
                        max_blocks,
                        max_inputs,
                    ) {
                        Ok(wave) if wave.items.is_empty() && wave.undecodable.is_none() => {
                            lookup_faults.on_success();
                        }
                        Ok(wave) => {
                            lookup_faults.on_success();
                            did = true;
                            if let Some((h, hash)) = wave.undecodable {
                                warn!("ibd: body queue wire @{h} does not decode; dropped");
                                if emit_confirm_reject(
                                    &event_tx_lookup,
                                    &feed,
                                    h,
                                    BlockHash::from_byte_array(hash),
                                    ConfirmRejectClass::SoftWire,
                                    "body queue wire does not decode".into(),
                                    1,
                                    None,
                                    RejectParent::from_lookup(
                                        &hub,
                                        BlockHash::from_byte_array(hash),
                                    ),
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                            let counts: Vec<u32> = wave
                                .items
                                .iter()
                                .map(|(_, _, w)| w.n_inputs)
                                .collect();
                            let t_kind = Instant::now();
                            let kinds: Vec<bool> = match wave
                                .items
                                .iter()
                                .map(|(_, _, w)| hub.query.header_has_class_a_body(w.header_fk))
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
                                batch.gen = taken_gen;
                            }
                            for batch in batches {
                                let t_send = Instant::now();
                                let n = batch.items.len();
                                let wire: usize = batch
                                    .items
                                    .iter()
                                    .map(|(_, _, w)| {
                                        rbitcoin_query::block_wire_len_from_pres(
                                            w.block.txdata.len(),
                                            w.pres.as_ref(),
                                        )
                                    })
                                    .sum();
                                // Take before the send: a take that loses to a
                                // re-arm leaves its rows queued and is not sent.
                                if !matches!(
                                    rbitcoin_query::take_wave_items_for_load(
                                        &hub.query,
                                        &batch.items,
                                        taken_gen,
                                    ),
                                    Ok(true)
                                ) {
                                    break;
                                }
                                if load_tx.send(batch).is_err() {
                                    break;
                                }
                                queues_lookup.note_load_send(n, wire);
                                confirm_thr_stats::add_lookup_send_wait(&stats, t_send.elapsed());
                            }
                            feed.notify();
                        }
                        Err(e) => {
                            if e.is_uring_session_fault() {
                                hub.query.uring_recover_or_abort("ibd-confirm-lookup");
                                lookup_faults.on_success();
                                warn!("ibd: bq resolve wave uring recover: {e}");
                            } else {
                                match lookup_faults.on_err(&e) {
                                    LookupFaultAction::Stop => {
                                        info!("ibd: confirm lookup cancelled mid-wave");
                                        break;
                                    }
                                    LookupFaultAction::Ignore => {
                                        debug!("ibd: bq resolve wave: {e}");
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
                                                    None,
                                                    RejectParent::from_lookup(&hub, hash),
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
            hub.query.stop_tip_flush_worker();
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
pub fn offer_confirm_ready(
    feed: &ConfirmFeed,
    height_to_hash: &HashMap<u32, BlockHash>,
    prev_of: &HashMap<BlockHash, BlockHash>,
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
            match prev_of.get(&hash) {
                Some(prev) if hub.tip_hash() == Some(*prev) => {}
                _ => break,
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

#[cfg(debug_assertions)]
thread_local! {
    static BULK_READ_NOTE: std::cell::Cell<Option<std::sync::mpsc::Sender<()>>> =
        const { std::cell::Cell::new(None) };
}

/// The calling thread's bulk-read signal. Other confirm tests share this process.
#[cfg(debug_assertions)]
pub fn set_bulk_read_note(tx: Option<std::sync::mpsc::Sender<()>>) {
    BULK_READ_NOTE.with(|slot| slot.set(tx));
}

#[doc(hidden)]
pub fn note_confirm_bulk_read() {
    #[cfg(debug_assertions)]
    BULK_READ_NOTE.with(|slot| {
        let tx = slot.take();
        if let Some(ref tx) = tx {
            let _ = tx.send(());
        }
        slot.set(tx);
    });
}

/// The write batch's error carries the batch so the caller can offer it back.
#[allow(clippy::result_large_err)]
fn write_batch_trusted(
    hub: &rbitcoin_net::ChainHub,
    batch: rbitcoin_query::ScriptOkBatch,
) -> Result<
    Vec<rbitcoin_primitives::Fk>,
    (rbitcoin_query::ConfirmError, rbitcoin_query::ScriptOkBatch),
> {
    rbitcoin_query::confirm_run::waive_batch(hub.query.trust_peer(), || {
        rbitcoin_query::confirm_write_phase_or_return(&hub.query, &hub.params, hub.milestone, batch)
    })
}

/// One lookup batch: wait out a rotating-media write burst, then identity / `create.loc`.
pub fn lookup_bulk_wave(
    query: &rbitcoin_query::Query,
    params: &rbitcoin_consensus::ChainParams,
    milestone: rbitcoin_consensus::Milestone,
    heights: &[u32],
    max_blocks: usize,
    max_inputs: u32,
) -> Result<rbitcoin_query::BqResolveWave, rbitcoin_query::ConfirmError> {
    note_confirm_bulk_read();
    query.store().spindle_wait();
    note_confirm_bulk_read();
    rbitcoin_query::confirm_bq_resolve_wave_capped(
        query, params, milestone, heights, max_blocks, max_inputs,
    )
}

/// One load batch: wait out a rotating-media write burst, then pin / stamp IO.
pub fn load_bulk_stamp(
    query: &rbitcoin_query::Query,
    params: &rbitcoin_consensus::ChainParams,
    milestone: rbitcoin_consensus::Milestone,
    blocks: &[rbitcoin_query::WireBlockIn],
    pipeline: Option<&rbitcoin_query::WireLoadPipeline>,
) -> Result<rbitcoin_query::PlanStampOutcome, rbitcoin_query::ConfirmError> {
    if query.trust_peer() && !rbitcoin_query::confirm_run::confirm_waive(query) {
        return rbitcoin_query::confirm_run::waive_batch(true, || {
            load_bulk_stamp(query, params, milestone, blocks, pipeline)
        });
    }
    note_confirm_bulk_read();
    query.store().spindle_wait();
    note_confirm_bulk_read();
    rbitcoin_query::confirm_wire_lookup_stamp(query, params, milestone, blocks, pipeline)
}
