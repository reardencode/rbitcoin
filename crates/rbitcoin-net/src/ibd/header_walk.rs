//! One headers ask during IBD.
//!
//! The ordered queue is a window over headers already written. One peer, the
//! lowest time to a first block byte among peers that have not failed the
//! walk, is asked for the next header that is not already stored. While the
//! queue has room the locator starts at the stored tip, then the candidate,
//! then a lighter fork, then earlier checkpoints, so the reply can be
//! enqueued. A full queue asks from the candidate. Headers already written
//! are appended locally while the queue is under [`ORDERED_HEADERS_SOFT_CAP`].
//! An accepted batch is written and recorded as a checkpoint.
//! Above the work floor, one short reply that leaves the candidate
//! unextended retires that peer and the reservation moves. A full
//! 2,000-header window does not, so a lighter fork can still catch up. A
//! block inv is one challenge ask when that peer is not already the walk's
//! next ask: a reply that beats the candidate takes the reservation, and any
//! other reply leaves it where it was. One competing chain is kept until it
//! loses or replaces the candidate. Work for a stored header between
//! checkpoints is the previous checkpoint plus those stored headers. That
//! replay runs only when a competing headers batch forks there.

use super::state::{ConfirmedLocatorTail, IbdWorkState};
use super::ORDERED_HEADERS_SOFT_CAP;
use crate::chain::ChainHub;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::Work;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Difficulty state after a header, so a fork or rewind can retarget without
/// the abandoned tip's period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DiffSnap {
    /// Header that opened the current difficulty period.
    period_header: Option<Header>,
    period_height: u32,
    /// Last header in this period whose `nBits` are not the min-difficulty limit.
    full_diff_bits: Option<CompactTarget>,
    full_diff_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    hash: BlockHash,
    height: u32,
    work: [u8; 32],
    /// Last header of this reply. Lets the next batch check `nBits` and time
    /// without a row in `header.body`.
    header: Option<Header>,
    /// Up to 11 timestamps ending at `header`, oldest first.
    times: Vec<u32>,
    /// Difficulty after this reply. A later fork from this hash retargets
    /// from here, not from the walk tip.
    diff: DiffSnap,
}

/// Fork point, the chain built from it, and one checkpoint per reply.
/// Replaced when a different fork has more work, or when it beats the candidate.
#[derive(Clone, Debug)]
struct Challenger {
    fork_hash: BlockHash,
    fork_height: u32,
    tip: WalkTip,
    checkpoints: Vec<Checkpoint>,
}

#[derive(Debug, Default)]
pub(crate) struct HeaderWalk {
    checkpoints: Vec<Checkpoint>,
    /// Confirmed tip, or the stored path tip, before any look-ahead checkpoint.
    base_hash: Option<BlockHash>,
    base_height: u32,
    base_work: [u8; 32],
    /// Moving candidate. Hash stays empty until the origin is known.
    tip: WalkTip,
    origin: bool,
    /// Look-ahead tips that every peer left empty before the work floor.
    dead_ends: HashSet<BlockHash>,
    /// Peers that have answered empty at the current tip.
    emptied: HashSet<usize>,
    /// Checkpoint work has reached the milestone floor.
    proven: bool,
    /// Stored header hashes from this peer that are not on the download path.
    off_path: std::collections::HashMap<usize, HashSet<BlockHash>>,
    /// The caught-up line has already been logged. The status thread keeps
    /// its own latch; this one exists so header-walk tests can see it.
    #[cfg(test)]
    announced_done: bool,
    /// Peers retired from the walk after a short reply that did not extend
    /// the candidate. A block inv or a redial clears the bit. Not written
    /// to `header.adopt`.
    walk_quiet: HashSet<usize>,
    /// Peer that serves the one headers ask. Not written to `header.adopt`.
    reserved: Option<usize>,
    /// One ask owed after a block inv.
    challenge: Option<usize>,
    /// The challenge came from a session that has no header slot. A reply
    /// that does not beat the candidate must not retire the reserved peer.
    challenge_external: bool,
    /// Challenge ask already sent. Judged when that peer replies or times out.
    challenge_open: Option<usize>,
    /// The one in-flight headers ask. Not written to `header.adopt`.
    walk: Lane,
    /// Expired asks. Not written to `header.adopt`.
    header_misses: HashMap<usize, u8>,
    /// Difficulty at `base_hash`, restored when every checkpoint is rewound.
    base_diff: DiffSnap,
    /// Heavier-so-far alternate that has not yet passed the candidate.
    challenger: Option<Challenger>,
    /// Confirmed chain already proved the anchor; stop stat'ing the sidecar.
    adopt_retired: bool,
}

/// One in-flight header ask on one lane. Not written to `header.adopt`.
#[derive(Debug, Default)]
struct Lane {
    peer: Option<usize>,
    at: Option<Instant>,
    /// The peer asked before this one. A late reply can still count.
    prev_peer: Option<usize>,
}

/// How long one header reply may take before another peer is asked.
/// Each lane has its own request. A miss skips that peer on that lane when
/// someone else can be asked. A second miss on the same lane disconnects them.
/// Shorter than a stall cooldown: one headers reply, not a silent peer.
const LOOKAHEAD_ASK: Duration = Duration::from_secs(5);
/// Missed header asks before the peer is disconnected, same as a block stall.
const HEADER_MISS_DISCONNECT: u8 = 2;
const DEAD_END_CAP: usize = 1024;

impl HeaderWalk {
    pub(crate) fn tip_height(&self) -> u32 {
        self.tip.height
    }

    /// The walk has met the work floor and is not past `tip_h`.
    pub(crate) fn proved_at_or_below(&self, tip_h: u32) -> bool {
        self.proven && self.tip.height <= tip_h
    }

    pub(crate) fn tip_hash(&self) -> Option<BlockHash> {
        self.tip.hash
    }

    fn tip_work(&self) -> [u8; 32] {
        self.tip.work.to_be_bytes()
    }

    fn tip_header(&self) -> Option<Header> {
        self.tip.header
    }

    fn milestone_hash(&self) -> Option<BlockHash> {
        self.tip.milestone_hash
    }

    pub(crate) fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    pub(crate) fn has_checkpoints(&self) -> bool {
        !self.checkpoints.is_empty()
    }

    /// Candidate tip, then a lighter fork, then earlier checkpoints.
    pub(crate) fn locator_hashes(&self) -> Vec<BlockHash> {
        let mut out = Vec::new();
        if let Some(h) = self.tip.hash {
            out.push(h);
        }
        if let Some(ch) = &self.challenger {
            if let Some(h) = ch.tip.hash {
                if !out.contains(&h) {
                    out.push(h);
                }
            }
        }
        let mut step = 1usize;
        let mut i = self.checkpoints.len();
        while i > 0 && out.len() < 8 {
            i = i.saturating_sub(step);
            let h = self.checkpoints[i].hash;
            if !out.contains(&h) {
                out.push(h);
            }
            step = step.saturating_mul(2);
        }
        out
    }

    /// Height of the header after the candidate, when the walk has a tip.
    ///
    /// Callers run after the origin is installed, so a missing tip hash is the
    /// only stop. A height of zero is the parent, not a later header.
    pub(crate) fn next_height(&self) -> Option<u32> {
        self.tip.hash?;
        Some(self.tip.height.saturating_add(1))
    }

    /// `height` is on the candidate and past the queue, so hygiene keeps it.
    ///
    /// The origin and the tip hash are installed together. Hygiene then only
    /// needs the height to sit on that tip, above the genesis parent.
    pub(crate) fn indexes_through(&self, height: u32) -> bool {
        if self.tip.hash.is_none() || !self.origin || height == 0 {
            return false;
        }
        height <= self.tip.height
    }

    /// Test stand-in for a walk that already proved the confirmed tip.
    #[cfg(test)]
    pub(crate) fn prove_through(&mut self, height: u32) {
        self.origin = true;
        self.proven = true;
        self.tip.height = height;
    }
}

pub(crate) struct OriginInput {
    pub already: bool,
    pub height: u32,
    pub hash: Option<BlockHash>,
    pub ordered_empty: bool,
    pub queue_tail: Option<u32>,
    pub next_hashes: Vec<(u32, BlockHash)>,
    pub milestone_height: u32,
    pub milestone_hash: Option<BlockHash>,
    pub milestone_prev: BlockHash,
    pub milestone_header: Option<Header>,
}

pub(crate) struct OriginLoaded {
    pub height: u32,
    pub hash: Option<BlockHash>,
    pub work: Work,
    pub milestone_hash: Option<BlockHash>,
    pub milestone_prev: BlockHash,
    pub milestone_header: Option<Header>,
    pub tip_header: Option<Header>,
}

pub(crate) fn origin_input(st: &IbdWorkState, hub: &ChainHub) -> OriginInput {
    let height = hub.tip_height().unwrap_or(0);
    let queue_tail = st
        .ordered
        .back()
        .and_then(|h| st.hash_height.get(h).copied());
    let mut next_hashes = Vec::new();
    if !st.ordered.is_empty() {
        let mut next_h = height.saturating_add(1);
        while queue_tail.is_none_or(|tail| next_h <= tail) {
            let Some(next) = st.height_to_hash.get(&next_h).copied() else {
                break;
            };
            next_hashes.push((next_h, next));
            next_h = next_h.saturating_add(1);
        }
    }
    OriginInput {
        already: st.header_walk.origin,
        height,
        hash: hub.tip_hash(),
        ordered_empty: st.ordered.is_empty(),
        queue_tail,
        next_hashes,
        milestone_height: hub.milestone.height,
        milestone_hash: st.header_walk.tip.milestone_hash,
        milestone_prev: st.header_walk.tip.milestone_prev,
        milestone_header: st.header_walk.tip.milestone_header,
    }
}

/// Header-store reads for the walk origin. No `IbdWorkState` borrow.
pub(crate) fn load_origin(hub: &ChainHub, input: &OriginInput) -> OriginLoaded {
    let mut height = input.height;
    let mut hash = input.hash;
    let mut work = hub
        .chain_work()
        .unwrap_or_else(|_| Work::from_be_bytes([0u8; 32]));
    let mut milestone_hash = input.milestone_hash;
    let mut milestone_prev = input.milestone_prev;
    let mut milestone_header = input.milestone_header;
    if !input.ordered_empty {
        for (next_h, next) in &input.next_hashes {
            if input.queue_tail.is_some_and(|tail| *next_h > tail) {
                break;
            }
            let Some(hdr) = hub.header_of(next) else {
                break;
            };
            if hash.is_some_and(|h| hdr.prev_blockhash != h) {
                break;
            }
            work = work + hdr.work();
            if input.milestone_height == *next_h {
                let mut latch = WalkTip {
                    height: *next_h,
                    hash: Some(*next),
                    ..WalkTip::default()
                };
                remember_milestone(&mut latch, hub, hdr.prev_blockhash, &hdr);
                milestone_hash = latch.milestone_hash;
                milestone_prev = latch.milestone_prev;
                milestone_header = latch.milestone_header;
            }
            height = *next_h;
            hash = Some(*next);
        }
    }
    let tip_header = hash.and_then(|h| hub.header_of(&h));
    OriginLoaded {
        height,
        hash,
        work,
        milestone_hash,
        milestone_prev,
        milestone_header,
        tip_header,
    }
}

pub(crate) fn install_origin(st: &mut IbdWorkState, hub: &ChainHub, loaded: OriginLoaded) {
    if st.header_walk.origin {
        return;
    }
    let OriginLoaded {
        height,
        hash,
        work,
        milestone_hash,
        milestone_prev,
        milestone_header,
        tip_header,
    } = loaded;
    st.header_walk.tip = WalkTip {
        hash,
        height,
        work,
        milestone_hash,
        milestone_prev,
        milestone_header,
        ..WalkTip::default()
    };
    st.header_walk.base_hash = hash;
    st.header_walk.base_height = height;
    st.header_walk.base_work = work.to_be_bytes();
    st.header_walk.origin = true;
    if let Some(h) = tip_header {
        seed_tip_times(st, hub, h);
        note_period_snap(&mut st.header_walk.tip.diff, hub, h, height);
        note_full_diff_snap(&mut st.header_walk.tip.diff, hub, &h, height);
    }
    st.header_walk.base_diff = st.header_walk.tip.diff;
    publish_work(st, hub);
}

fn ensure_origin(st: &mut IbdWorkState, hub: &ChainHub) {
    if st.header_walk.origin {
        return;
    }
    let input = origin_input(st, hub);
    let loaded = load_origin(hub, &input);
    install_origin(st, hub, loaded);
}

fn below_floor(hub: &ChainHub, work: &[u8; 32]) -> bool {
    match hub.milestone.anchor {
        Some(anchor) => work < &anchor.min_work_be,
        None => false,
    }
}

/// Header fields for the status thread. No store read.
pub(crate) struct HeaderStatusView {
    pub origin: bool,
    pub height: u32,
    pub stored: u32,
    pub queue: usize,
    pub work_ok: bool,
    pub walk: bool,
    pub quiet: bool,
    pub horizon: u32,
}

pub(crate) fn header_status_view(st: &IbdWorkState, hub: &ChainHub) -> HeaderStatusView {
    let walk = wants_lookahead(st);
    // Proven is set only after the origin is installed, so origin is not a
    // second input to the caught-up line.
    let quiet = st.header_walk.proven && !walk;
    HeaderStatusView {
        origin: st.header_walk.origin,
        height: st.header_walk.tip_height(),
        stored: path_top(st, hub).map(|(_, h)| h).unwrap_or(0),
        queue: st.ordered.len(),
        work_ok: st.header_walk.proven,
        walk,
        quiet,
        horizon: peer_horizon(st),
    }
}

/// Operator line for the header walk. Production logs this from the status
/// thread. Tests call this to observe the once-only caught-up latch.
#[cfg(test)]
pub(crate) fn log_status(st: &mut IbdWorkState, hub: &ChainHub, horizon: u32) {
    if !st.header_walk.origin {
        return;
    }
    let looking = wants_lookahead(st);
    if st.header_walk.announced_done && !looking {
        return;
    }
    st.header_walk.announced_done = false;
    let height = st.header_walk.tip_height();
    let pct = super::progress::ibd_pct(height, horizon.max(height));
    let stored = path_top(st, hub).map(|(_, h)| h).unwrap_or(0);
    let queue = st.ordered.len();
    let work = if st.header_walk.proven { "ok" } else { "below" };
    let phase = if looking { "walk" } else { "write" };
    rbitcoin_log::info!(
        "ibd: headers height={height} ({pct}%) horizon={horizon} stored={stored} queue={queue} work={work} phase={phase}"
    );
    if st.header_walk.proven && !wants_lookahead(st) {
        st.header_walk.announced_done = true;
        rbitcoin_log::info!("ibd: headers done height={height} horizon={horizon}");
    }
}

/// A connected peer is still ahead of the walk and has not been retired from it.
///
/// The advertised high-water mark is not a second signal. A disconnected
/// peer leaves that mark behind, and the ask goes out only when someone
/// still connected can serve the next header.
pub(crate) fn wants_lookahead(st: &IbdWorkState) -> bool {
    let tip = st.header_walk.tip_height();
    st.slots
        .iter()
        .any(|s| s.alive && s.peer_height > tip && !st.header_walk.walk_quiet.contains(&s.id))
}

/// The proven walk is at or below the confirmed tip, and every connected
/// peer that advertised more has failed to extend it.
pub(crate) fn headers_complete(st: &IbdWorkState, tip_h: u32) -> bool {
    st.header_walk.origin
        && st.header_walk.proven
        && st.header_walk.tip_height() <= tip_h
        && !wants_lookahead(st)
}

/// Height the progress line counts toward. Before the walk has an origin,
/// the advertised high-water mark. After that, the walk tip or the tallest
/// connected peer still on the walk: a peer that disconnected or failed to
/// extend the walk no longer sets it. Exit still uses `max_peer_height`.
pub(crate) fn peer_horizon(st: &IbdWorkState) -> u32 {
    if !st.header_walk.origin {
        return st.max_peer_height;
    }
    st.slots
        .iter()
        .filter(|s| s.alive && !st.header_walk.walk_quiet.contains(&s.id))
        .map(|s| s.peer_height)
        .fold(st.header_walk.tip_height(), u32::max)
}

/// Candidate hash before a headers reply is applied.
pub(crate) fn candidate_tip(st: &IbdWorkState) -> Option<BlockHash> {
    st.header_walk.tip_hash()
}

/// Retire `peer` from the walk when this reply did not extend the candidate.
///
/// A full [`crate::codec::MAX_HEADERS_RESULTS`] window stays, so a lighter
/// fork can grow across more than one locator. Below the work floor the
/// empty-reply rewind still owns the peer. An extension, a block inv, or
/// peer death clears a previous retirement.
pub(crate) fn settle_walk_peer(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    tip_before: Option<BlockHash>,
    queued_before: usize,
    batch_len: usize,
) {
    // A stored continuation of the download path is not a failed walk.
    let extended = st.header_walk.tip_hash() != tip_before || st.ordered.len() > queued_before;
    if extended {
        st.header_walk.walk_quiet.remove(&peer);
    }
    if batch_len >= crate::codec::MAX_HEADERS_RESULTS || !st.header_walk.origin {
        return;
    }
    if below_floor(hub, &st.header_walk.tip_work()) || extended {
        return;
    }
    // This reply is the walk's answer to someone else's block inv.
    if st.header_walk.challenge_open == Some(peer) && st.header_walk.challenge_external {
        return;
    }
    st.header_walk.walk_quiet.insert(peer);
}

/// A block announcement may be a header this peer has and we do not.
///
/// The reserved peer is already the walk's ask while some peer is still
/// above the walk and this peer can serve it. Once that stops, their inv
/// is the challenge: connect-time height does not move when a new block
/// is found.
pub(crate) fn note_block_inv(st: &mut IbdWorkState, peer: usize) {
    st.header_walk.challenge_external = false;
    st.header_walk.walk_quiet.remove(&peer);
    let above = st.header_walk.tip_height();
    let walk_will_ask = st.header_walk.reserved == Some(peer)
        && wants_lookahead(st)
        && peer_can_head(st, peer, above);
    if !walk_will_ask {
        st.header_walk.challenge = Some(peer);
    }
}

/// A follow-session block inv has no IBD slot. Poke one live header peer
/// the same way [`note_block_inv`] does. Returns false when nobody is live
/// yet, so the caller keeps the flag.
pub(crate) fn note_external_block_inv(st: &mut IbdWorkState) -> bool {
    let Some(peer) = st.slots.iter().find(|slot| slot.alive).map(|slot| slot.id) else {
        return false;
    };
    note_block_inv(st, peer);
    if st.header_walk.challenge == Some(peer) {
        st.header_walk.challenge_external = true;
        // The ask already in flight is the answer. Waiting for the lane to
        // clear lets this reply retire the peer, and a quiet peer then drops
        // the challenge.
        if st.header_walk.walk.peer == Some(peer) {
            st.header_walk.challenge = None;
            st.header_walk.challenge_open = Some(peer);
        }
    }
    true
}

/// A redialed slot can reuse this id. Do not inherit the previous walk retirement.
pub(crate) fn forget_walk_peer(st: &mut IbdWorkState, peer: usize) {
    st.header_walk.walk_quiet.remove(&peer);
    if st.header_walk.reserved == Some(peer) {
        st.header_walk.reserved = None;
    }
    if st.header_walk.challenge == Some(peer) {
        st.header_walk.challenge = None;
        st.header_walk.challenge_external = false;
    }
    if st.header_walk.challenge_open == Some(peer) {
        st.header_walk.challenge_open = None;
        st.header_walk.challenge_external = false;
    }
}

/// Chainwork of the candidate, for judging a challenge reply.
pub(crate) fn candidate_work(st: &IbdWorkState) -> [u8; 32] {
    st.header_walk.tip_work()
}

/// Move the reservation when this reply beat the candidate, or retire a
/// challenge that did not. A reserved peer who was just retired loses it.
pub(crate) fn note_reservation(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    tip_before: Option<BlockHash>,
    work_before: [u8; 32],
) {
    let beat = st.header_walk.tip_hash() != tip_before && st.header_walk.tip_work() > work_before;
    if st.header_walk.challenge_open == Some(peer) {
        let external = st.header_walk.challenge_external;
        st.header_walk.challenge_open = None;
        st.header_walk.challenge_external = false;
        if beat {
            st.header_walk.reserved = Some(peer);
            st.header_walk.walk_quiet.remove(&peer);
        } else if !external && !below_floor(hub, &st.header_walk.tip_work()) {
            st.header_walk.walk_quiet.insert(peer);
            if st.header_walk.reserved == Some(peer) {
                st.header_walk.reserved = None;
            }
        }
        return;
    }
    if st.header_walk.walk_quiet.contains(&peer) && st.header_walk.reserved == Some(peer) {
        st.header_walk.reserved = None;
    }
}

/// Peers that may receive block getdata. The reserved header peer is left
/// out while another peer is connected. A single peer still does both.
pub(crate) fn peers_for_blocks(st: &IbdWorkState) -> Vec<usize> {
    let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
    let Some(reserved) = st.header_walk.reserved else {
        return alive;
    };
    if alive.len() <= 1 {
        return alive;
    }
    let rest: Vec<usize> = alive.iter().copied().filter(|&id| id != reserved).collect();
    if rest.is_empty() {
        alive
    } else {
        rest
    }
}

/// Inputs for one main-loop header poll. The loop owns the cadence clock.
pub(crate) struct HeaderPollIn {
    pub live: usize,
    pub need_ready_headroom: bool,
    pub lag: u32,
    pub min_cache: usize,
    pub fan: usize,
}

/// What the header poll should do with `headers_done` and `send_getheaders`.
pub(crate) enum HeaderPoll {
    /// Send getheaders.
    Ask,
    /// Empty path and peers are not ahead: latch `headers_done`.
    LatchDone,
    /// Leave header sync alone this turn.
    Wait,
}

/// A block inv is waiting, and the walk lane is not already in flight.
///
/// An in-flight ask keeps the challenge until the lane clears. The poll
/// must not call `send_getheaders` on every block event during that window.
pub(crate) fn inv_challenge_due(st: &IbdWorkState) -> bool {
    st.header_walk.challenge.is_some() && !lane_fresh(&st.header_walk.walk)
}

/// The queue still has room, or a gap / look-ahead still needs headers.
fn header_sync_open(st: &IbdWorkState, poll: &HeaderPollIn) -> bool {
    poll.live < ORDERED_HEADERS_SOFT_CAP
        || poll.need_ready_headroom
        || wants_lookahead(st)
        || walk_ahead_of_stored(st)
}

/// Something other than a full quiet queue is waiting on the next header.
fn header_ask_due(st: &IbdWorkState, poll: &HeaderPollIn) -> bool {
    poll.live < poll.min_cache
        || poll.lag > 0
        || poll.need_ready_headroom
        || wants_lookahead(st)
        || walk_ahead_of_stored(st)
}

/// Decide the main-loop header poll.
///
/// A pending block-inv challenge is an ask even when the queue is at the
/// soft cap, `headers_done` is latched, or no peer's connect-time height
/// is past the walk.
pub(crate) fn header_poll(st: &IbdWorkState, poll: HeaderPollIn) -> HeaderPoll {
    if inv_challenge_due(st) {
        return HeaderPoll::Ask;
    }
    if st.headers_done || poll.live >= super::MAX_ORDERED_HEADERS {
        return HeaderPoll::Wait;
    }
    if !header_sync_open(st, &poll) {
        return HeaderPoll::Wait;
    }
    if poll.live == 0 {
        return if poll.fan == 0 && !walk_ahead_of_stored(st) {
            HeaderPoll::LatchDone
        } else {
            HeaderPoll::Ask
        };
    }
    if header_ask_due(st, &poll) {
        return HeaderPoll::Ask;
    }
    HeaderPoll::Wait
}

/// A proven-chain reply that must not be written.
///
/// A heavier chain replaces the checkpoints, including one that forks from a
/// confirmed ancestor while that ancestor is still below `-minimumchainwork`.
/// The queue drops hashes that are not on it. A lighter chain is not stored.
/// Returns true when the reply was consumed. A heavier chain whose queue has
/// room is not consumed: the caller stores it because those blocks will be
/// fetched.
pub(crate) fn suppress_competing_chain(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    headers: &[Header],
) -> bool {
    if headers.is_empty() || !pow_linked(headers) {
        return false;
    }
    let below = below_floor(hub, &st.header_walk.tip_work());
    if !st.header_walk.proven && !below {
        return false;
    }
    if !st.header_walk.origin {
        return false;
    }
    let prev = headers[0].prev_blockhash;
    if st.header_walk.tip_hash() == Some(prev) || batch_ends_on_checkpoint(st, headers) {
        return false;
    }
    // A short queue whose batch continues the stored tip is a refill. Classify
    // returns that before this function runs, so the length comparison is not
    // a second gate.
    if challenger_extends(st, prev) {
        return extend_challenger(st, hub, Some(peer), headers);
    }
    // A batch that has not met the next checkpoint is not a competing chain.
    // Treating it as one would evict a real fork that has less work so far.
    // `!proven && !below` already returned, so `proven` is not a second gate.
    if !below && candidate_prev(st, prev) {
        if let Some(start_h) = height_of(st, hub, prev) {
            if matches!(path_agree(st, start_h, headers, true), PathAgree::Short) {
                return true;
            }
        }
    }
    // The first header of a real chain is below `-minimumchainwork` for most
    // of IBD. Compare the batch when the parent work is known; only an
    // uncomparable low-work header is dropped here.
    if work_at(st, hub, prev).is_none() && headers.iter().any(|h| hub.header_below_anti_dos(h)) {
        return true;
    }
    // `Some(false)`: adopted, and the queue has room so the caller stores it.
    offer_alternate(st, hub, Some(peer), headers).unwrap_or_default()
}

fn clear_off_path(st: &mut IbdWorkState) {
    st.header_walk.off_path.clear();
}

fn note_dead(st: &mut IbdWorkState, hash: BlockHash) {
    if st.header_walk.dead_ends.len() >= DEAD_END_CAP {
        st.header_walk.dead_ends.clear();
    }
    st.header_walk.dead_ends.insert(hash);
}

fn rewind_above(st: &mut IbdWorkState, hub: &ChainHub, height: u32) {
    rewind_to(st, hub, height, None);
}

/// Pop checkpoints above `height`, or the current tip when `dead` is set.
/// `dead` is the hash that every peer left empty.
fn rewind_to(st: &mut IbdWorkState, hub: &ChainHub, height: u32, dead: Option<BlockHash>) {
    let dead_height = st.header_walk.tip_height();
    if let Some(dead) = dead {
        note_dead(st, dead);
        st.header_walk.checkpoints.pop();
    } else {
        while st
            .header_walk
            .checkpoints
            .last()
            .is_some_and(|c| c.height > height)
        {
            st.header_walk.checkpoints.pop();
        }
    }
    let milestone_hash = st.header_walk.tip.milestone_hash;
    let milestone_prev = st.header_walk.tip.milestone_prev;
    let milestone_header = st.header_walk.tip.milestone_header;
    st.header_walk.tip = match st.header_walk.checkpoints.last() {
        Some(prev) => tip_from_checkpoint(prev),
        None => tip_from_base(st),
    };
    st.header_walk.tip.milestone_hash = milestone_hash;
    st.header_walk.tip.milestone_prev = milestone_prev;
    st.header_walk.tip.milestone_header = milestone_header;
    let keep = st.header_walk.tip_height();
    st.clear_path_above(keep);
    forget_milestone_below(st, hub, keep);
    restore_tip_header(st, hub);
    retain_challenger(st);
    let keep_hashes: HashSet<BlockHash> = st
        .ordered
        .iter()
        .copied()
        .filter(|h| match st.hash_height.get(h) {
            Some(ht) => *ht <= keep,
            None => dead != Some(*h),
        })
        .collect();
    // `clear_path_above` already dropped path slots above `keep`. An ordered
    // hash with no height stays unless it is the abandoned tip.
    drop_queue_above(st, keep, &keep_hashes);
    if dead.is_some() {
        st.header_walk.emptied.clear();
        if let Some(dead) = dead {
            rbitcoin_log::warn!(
                "ibd: headers dead-end hash={dead} height={dead_height} rewind={keep}"
            );
        }
    }
    clear_off_path(st);
    save_adopt(st, hub);
}

fn batch_ends_on_checkpoint(st: &IbdWorkState, headers: &[Header]) -> bool {
    let mut hash = headers[0].prev_blockhash;
    for hdr in headers {
        if hdr.prev_blockhash != hash {
            break;
        }
        hash = hdr.block_hash();
    }
    st.header_walk.tip_hash() == Some(hash)
        || st.header_walk.checkpoints.iter().any(|c| c.hash == hash)
}

fn challenger_extends(st: &IbdWorkState, prev: BlockHash) -> bool {
    st.header_walk
        .challenger
        .as_ref()
        .is_some_and(|ch| ch.tip.hash == Some(prev))
}

/// `None` when this reply is not a chain we can compare. `Some(true)` when the
/// caller must not write it. `Some(false)` when it was adopted and the queue
/// has room for those headers.
fn offer_alternate(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: Option<usize>,
    headers: &[Header],
) -> Option<bool> {
    // Callers reject an empty batch. An unlinked batch is not a chain we can
    // compare: judging its first header would open a challenger for a reply
    // that does not connect.
    if !pow_linked(headers) {
        return None;
    }
    let prev = headers[0].prev_blockhash;
    let parent = work_at(st, hub, prev)?;
    let fork_height = height_of(st, hub, prev)?;
    if parent_header(st, hub, prev).is_none() {
        return Some(true);
    }
    let diff = diff_at(st, hub, prev);
    if !batch_context_ok(st, hub, headers, &diff) {
        if let Some(peer) = peer {
            punish_header_peer(st, peer);
        }
        return Some(true);
    }
    let work = chain_work_after(parent, headers);
    if work > Work::from_be_bytes(st.header_walk.tip_work()) {
        adopt_heavier(st, hub, prev, headers, work);
        return Some(st.ordered.len() >= ORDERED_HEADERS_SOFT_CAP);
    }
    note_challenger(st, hub, prev, fork_height, parent, headers);
    Some(true)
}

fn chain_work_after(parent: Work, headers: &[Header]) -> Work {
    let mut work = parent;
    let mut link = headers[0].prev_blockhash;
    for hdr in headers {
        if hdr.prev_blockhash != link {
            break;
        }
        work = work + hdr.work();
        link = hdr.block_hash();
    }
    work
}

#[derive(Clone, Debug)]
struct WalkTip {
    hash: Option<BlockHash>,
    height: u32,
    work: Work,
    header: Option<Header>,
    times: Vec<u32>,
    diff: DiffSnap,
    milestone_hash: Option<BlockHash>,
    milestone_prev: BlockHash,
    milestone_header: Option<Header>,
}

impl Default for WalkTip {
    fn default() -> Self {
        Self {
            hash: None,
            height: 0,
            work: Work::from_be_bytes([0; 32]),
            header: None,
            times: Vec::new(),
            diff: DiffSnap::default(),
            milestone_hash: None,
            milestone_prev: BlockHash::from_byte_array([0; 32]),
            milestone_header: None,
        }
    }
}

/// One header onto the tip. Milestone latch and the query note stay with the caller.
fn push_header(tip: &mut WalkTip, hub: &ChainHub, hdr: &Header) -> bool {
    let Some(cur) = tip.hash else {
        return false;
    };
    if hdr.prev_blockhash != cur {
        return false;
    }
    tip.work = tip.work + hdr.work();
    tip.height = tip.height.saturating_add(1);
    tip.hash = Some(hdr.block_hash());
    push_times(&mut tip.times, *hdr);
    note_period_snap(&mut tip.diff, hub, *hdr, tip.height);
    note_full_diff_snap(&mut tip.diff, hub, hdr, tip.height);
    tip.header = Some(*hdr);
    true
}

fn advance_tip(tip: &mut WalkTip, hub: &ChainHub, headers: &[Header]) {
    for hdr in headers {
        let Some(prev) = tip.hash else {
            break;
        };
        if !push_header(tip, hub, hdr) {
            break;
        }
        if hub.milestone.height > 0 && tip.height == hub.milestone.height {
            // A challenger tip starts with no milestone, and height only
            // increases, so this assignment runs at most once per tip.
            tip.milestone_hash = tip.hash;
            tip.milestone_prev = prev;
            tip.milestone_header = Some(*hdr);
        }
    }
}

fn latch_milestone(tip: &WalkTip, hub: &ChainHub) {
    let (Some(hash), Some(hdr)) = (tip.milestone_hash, tip.milestone_header) else {
        return;
    };
    // Milestone fields are set only at `milestone.height`, then the tip
    // only grows, so the latched tip is already at or above that height.
    hub.query.note_milestone_header(
        hub.milestone.height,
        hash.to_byte_array(),
        tip.milestone_prev.to_byte_array(),
        hdr.work(),
        None,
    );
}

fn push_times(times: &mut Vec<u32>, header: Header) {
    times.push(header.time);
    if times.len() > 11 {
        times.remove(0);
    }
}

fn checkpoint_at(tip: &WalkTip) -> Checkpoint {
    Checkpoint {
        hash: tip
            .hash
            .unwrap_or_else(|| BlockHash::from_byte_array([0; 32])),
        height: tip.height,
        work: tip.work.to_be_bytes(),
        header: tip.header,
        times: tip.times.clone(),
        diff: tip.diff,
    }
}

fn tip_from_checkpoint(c: &Checkpoint) -> WalkTip {
    WalkTip {
        hash: Some(c.hash),
        height: c.height,
        work: Work::from_be_bytes(c.work),
        ..WalkTip::default()
    }
}

fn tip_from_base(st: &IbdWorkState) -> WalkTip {
    WalkTip {
        hash: st.header_walk.base_hash,
        height: st.header_walk.base_height,
        work: Work::from_be_bytes(st.header_walk.base_work),
        ..WalkTip::default()
    }
}

fn note_challenger(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    fork_hash: BlockHash,
    fork_height: u32,
    parent_work: Work,
    headers: &[Header],
) {
    let end = chain_work_after(parent_work, headers);
    if st
        .header_walk
        .challenger
        .as_ref()
        .is_some_and(|ch| end <= ch.tip.work)
    {
        return;
    }
    let mut tip = WalkTip {
        hash: Some(fork_hash),
        height: fork_height,
        work: parent_work,
        times: times_ending_at(st, hub, fork_hash),
        diff: diff_at(st, hub, fork_hash),
        ..WalkTip::default()
    };
    advance_tip(&mut tip, hub, headers);
    st.header_walk.challenger = Some(Challenger {
        fork_hash,
        fork_height,
        checkpoints: vec![checkpoint_at(&tip)],
        tip,
    });
}

fn extend_challenger(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: Option<usize>,
    headers: &[Header],
) -> bool {
    let Some(ch) = st.header_walk.challenger.as_ref() else {
        return false;
    };
    let diff = ch.tip.diff;
    if !batch_context_ok(st, hub, headers, &diff) {
        if let Some(peer) = peer {
            punish_header_peer(st, peer);
        }
        return true;
    }
    let Some(ch) = st.header_walk.challenger.as_ref() else {
        return true;
    };
    let mut tip = ch.tip.clone();
    advance_tip(&mut tip, hub, headers);
    let beat = tip.work > st.header_walk.tip.work;
    let Some(ch) = st.header_walk.challenger.as_mut() else {
        return true;
    };
    ch.checkpoints.push(checkpoint_at(&tip));
    ch.tip = tip;
    if beat {
        promote_challenger(st, hub);
    }
    true
}

fn promote_challenger(st: &mut IbdWorkState, hub: &ChainHub) {
    let Some(ch) = st.header_walk.challenger.take() else {
        return;
    };
    forget_milestone_below(st, hub, ch.fork_height);
    st.header_walk
        .checkpoints
        .retain(|c| c.height <= ch.fork_height);
    st.header_walk.checkpoints.extend(ch.checkpoints);
    let kept = st.header_walk.tip.milestone_hash;
    let kept_prev = st.header_walk.tip.milestone_prev;
    let kept_header = st.header_walk.tip.milestone_header;
    st.header_walk.tip = ch.tip;
    if kept.is_some() {
        st.header_walk.tip.milestone_hash = kept;
        st.header_walk.tip.milestone_prev = kept_prev;
        st.header_walk.tip.milestone_header = kept_header;
    } else {
        latch_milestone(&st.header_walk.tip, hub);
    }
    publish_work(st, hub);
    st.header_walk.emptied.clear();
    st.header_walk.dead_ends.clear();
    clear_off_path(st);
    save_adopt(st, hub);
    drop_queue_above(st, ch.fork_height, &HashSet::new());
}

/// Drop queued hashes above `height`, and any path slot above it that is not
/// in `keep`. A queued hash with no height is not known to be at or below the
/// cut, so it leaves unless `keep` names it.
fn drop_queue_above(st: &mut IbdWorkState, height: u32, keep: &HashSet<BlockHash>) {
    let mut drop: HashSet<BlockHash> = st
        .ordered
        .iter()
        .copied()
        .filter(|h| {
            if keep.contains(h) {
                return false;
            }
            !matches!(st.hash_height.get(h), Some(ht) if *ht <= height)
        })
        .collect();
    for (ht, hash) in &st.height_to_hash {
        if *ht > height && !keep.contains(hash) {
            drop.insert(*hash);
        }
    }
    let drop: Vec<BlockHash> = drop.into_iter().collect();
    forget_queue_hashes(st, &drop);
}

/// One header the walk already knows, before the store fallback.
struct Known {
    height: Option<u32>,
    work: Option<Work>,
    header: Option<Header>,
    diff: Option<DiffSnap>,
    times: Option<Vec<u32>>,
}

fn consider_tip(found: &mut Known, tip: &WalkTip, hash: BlockHash) {
    if tip.hash != Some(hash) {
        return;
    }
    found.height.get_or_insert(tip.height);
    found.work.get_or_insert(tip.work);
    if found.header.is_none() {
        found.header = tip.header;
    }
    if found.diff.is_none() {
        found.diff = Some(tip.diff);
    }
    if found.times.is_none() && !tip.times.is_empty() {
        found.times = Some(tip.times.clone());
    }
}

fn consider_checkpoint(found: &mut Known, c: &Checkpoint) {
    found.height.get_or_insert(c.height);
    found.work.get_or_insert(Work::from_be_bytes(c.work));
    if found.header.is_none() {
        found.header = c.header;
    }
    if found.diff.is_none() {
        found.diff = Some(c.diff);
    }
    if found.times.is_none() && !c.times.is_empty() {
        found.times = Some(c.times.clone());
    }
}

/// Tip, then checkpoints, then the challenger, then the base.
fn known(st: &IbdWorkState, hash: BlockHash) -> Known {
    let mut found = Known {
        height: None,
        work: None,
        header: None,
        diff: None,
        times: None,
    };
    consider_tip(&mut found, &st.header_walk.tip, hash);
    if let Some(c) = st
        .header_walk
        .checkpoints
        .iter()
        .rev()
        .find(|c| c.hash == hash)
    {
        consider_checkpoint(&mut found, c);
    }
    if let Some(ch) = &st.header_walk.challenger {
        consider_tip(&mut found, &ch.tip, hash);
        if ch.fork_hash == hash {
            found.height.get_or_insert(ch.fork_height);
        }
        if let Some(c) = ch.checkpoints.iter().rev().find(|c| c.hash == hash) {
            consider_checkpoint(&mut found, c);
        }
    }
    if st.header_walk.base_hash == Some(hash) {
        found.height.get_or_insert(st.header_walk.base_height);
        found
            .work
            .get_or_insert(Work::from_be_bytes(st.header_walk.base_work));
        if found.diff.is_none() {
            found.diff = Some(st.header_walk.base_diff);
        }
    }
    found
}

/// Difficulty to use for a batch that builds on `hash`.
///
/// The walk tip's latch is only for the tip. A fork from an earlier checkpoint
/// retargets from that checkpoint's period, never from the chain being left.
fn diff_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> DiffSnap {
    known(st, hash).diff.unwrap_or_else(|| {
        stored_path_state(st, hub, hash)
            .map(|(_, diff)| diff)
            .unwrap_or_default()
    })
}

fn note_period_snap(diff: &mut DiffSnap, hub: &ChainHub, header: Header, height: u32) {
    let interval = hub.params.difficulty_adjustment_interval();
    if interval > 0 && height.is_multiple_of(interval) {
        diff.period_header = Some(header);
        diff.period_height = height;
    }
}

fn note_full_diff_snap(diff: &mut DiffSnap, hub: &ChainHub, header: &Header, height: u32) {
    let limit = hub.params.pow_limit.to_compact_lossy();
    if header.bits != limit {
        diff.full_diff_bits = Some(header.bits);
        diff.full_diff_height = height;
    }
}

fn times_ending_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Vec<u32> {
    if let Some(times) = known(st, hash).times {
        return times;
    }
    let Some(parent) = parent_header(st, hub, hash) else {
        return Vec::new();
    };
    let mut times = vec![parent.time];
    let mut prev_hash = parent.prev_blockhash;
    for _ in 0..10 {
        let Some(prev) = parent_header(st, hub, prev_hash) else {
            break;
        };
        times.push(prev.time);
        prev_hash = prev.prev_blockhash;
    }
    times.reverse();
    times
}

/// Drop a competing chain whose fork is no longer on the candidate.
fn retain_challenger(st: &mut IbdWorkState) {
    let keep = st.header_walk.challenger.as_ref().is_some_and(|ch| {
        let fork = ch.fork_hash;
        // `rewind_to` has already set the tip from the last checkpoint, or
        // from the base when no checkpoint remains. The tip hash is one of
        // those, so it is not a third keep.
        st.header_walk.base_hash == Some(fork)
            || st.header_walk.checkpoints.iter().any(|c| c.hash == fork)
    });
    if !keep {
        st.header_walk.challenger = None;
    }
}

fn work_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<Work> {
    if let Some(work) = known(st, hash).work {
        return Some(work);
    }
    if hub.tip_hash() == Some(hash) {
        return hub.chain_work().ok();
    }
    if let Some(found) = stored_path_state(st, hub, hash) {
        return Some(found.0);
    }
    // Not the tip, and not on the download path. A confirmed ancestor still
    // has work, so a heavier chain can fork below the tip.
    confirmed_ancestor_work(hub, hash)
}

fn confirmed_ancestor_work(hub: &ChainHub, hash: BlockHash) -> Option<Work> {
    let height = hub
        .query
        .height_of_hash(hash.as_byte_array())
        .ok()
        .flatten()?;
    hub.work_through_height(height.0).ok()
}

/// Work and difficulty at a header the download path has stored.
///
/// A checkpoint knows both. A header between checkpoints does not, so a
/// heavier chain that forks there cannot be compared. Replay from the
/// nearest earlier checkpoint, the walk base, or the confirmed tip.
fn stored_path_state(
    st: &IbdWorkState,
    hub: &ChainHub,
    hash: BlockHash,
) -> Option<(Work, DiffSnap)> {
    let height = *st.hash_height.get(&hash)?;
    if st.height_to_hash.get(&height) != Some(&hash) {
        return None;
    }
    for c in st.header_walk.checkpoints.iter().rev() {
        if let Some(found) = fold_stored_anchor(
            st,
            hub,
            StoredAnchor {
                height: c.height,
                hash: c.hash,
                work: Work::from_be_bytes(c.work),
                diff: c.diff,
            },
            height,
            hash,
        ) {
            return Some(found);
        }
    }
    if let Some(base) = st.header_walk.base_hash {
        if let Some(found) = fold_stored_anchor(
            st,
            hub,
            StoredAnchor {
                height: st.header_walk.base_height,
                hash: base,
                work: Work::from_be_bytes(st.header_walk.base_work),
                diff: st.header_walk.base_diff,
            },
            height,
            hash,
        ) {
            return Some(found);
        }
    }
    // Confirmed tip, when the walk base does not link through to this header.
    let tip_h = hub.tip_height()?;
    let tip = hub.tip_hash()?;
    fold_stored_anchor(
        st,
        hub,
        StoredAnchor {
            height: tip_h,
            hash: tip,
            work: hub.chain_work().ok()?,
            diff: DiffSnap::default(),
        },
        height,
        hash,
    )
}

struct StoredAnchor {
    height: u32,
    hash: BlockHash,
    work: Work,
    diff: DiffSnap,
}

fn fold_stored_anchor(
    st: &IbdWorkState,
    hub: &ChainHub,
    anchor: StoredAnchor,
    height: u32,
    hash: BlockHash,
) -> Option<(Work, DiffSnap)> {
    let StoredAnchor {
        height: anchor_h,
        hash: anchor_hash,
        mut work,
        mut diff,
    } = anchor;
    let mut prev = anchor_hash;
    for h in anchor_h.saturating_add(1)..=height {
        let next = *st.height_to_hash.get(&h)?;
        let hdr = hub.header_of(&next)?;
        if hdr.prev_blockhash != prev {
            return None;
        }
        work = work + hdr.work();
        note_period_snap(&mut diff, hub, hdr, h);
        note_full_diff_snap(&mut diff, hub, &hdr, h);
        prev = next;
    }
    (prev == hash).then_some((work, diff))
}

fn adopt_heavier(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    prev: BlockHash,
    headers: &[Header],
    work: Work,
) {
    let Some(fork_height) = height_of(st, hub, prev) else {
        return;
    };
    // Capture the fork's period and timestamps before the challenger is dropped.
    let mut tip = WalkTip {
        hash: Some(prev),
        height: fork_height,
        work: work_at(st, hub, prev).unwrap_or(Work::from_be_bytes([0; 32])),
        header: parent_header(st, hub, prev),
        times: times_ending_at(st, hub, prev),
        diff: diff_at(st, hub, prev),
        milestone_hash: st.header_walk.tip.milestone_hash,
        milestone_prev: st.header_walk.tip.milestone_prev,
        milestone_header: st.header_walk.tip.milestone_header,
    };
    st.header_walk.challenger = None;
    forget_milestone_below(st, hub, fork_height);
    if fork_height < hub.milestone.height {
        tip.milestone_hash = None;
        tip.milestone_header = None;
    }
    st.header_walk
        .checkpoints
        .retain(|c| c.height <= fork_height);
    let mut link = prev;
    for hdr in headers {
        if !push_header(&mut tip, hub, hdr) {
            break;
        }
        remember_milestone(&mut tip, hub, link, hdr);
        link = tip.hash.unwrap_or(link);
    }
    // `work` already includes every header that linked. An early break in
    // `push_header` must not leave the parent work in its place.
    if link != prev {
        tip.work = work;
    }
    st.header_walk.tip = tip;
    st.header_walk
        .checkpoints
        .push(checkpoint_at(&st.header_walk.tip));
    publish_work(st, hub);
    st.header_walk.emptied.clear();
    st.header_walk.dead_ends.clear();
    clear_off_path(st);
    save_adopt(st, hub);
    let keep: HashSet<BlockHash> = headers.iter().map(|h| h.block_hash()).collect();
    drop_queue_above(st, fork_height, &keep);
}

fn forget_queue_hashes(st: &mut IbdWorkState, drop: &[BlockHash]) {
    if drop.is_empty() {
        return;
    }
    let gone: HashSet<BlockHash> = drop.iter().copied().collect();
    st.ordered.retain(|h| !gone.contains(h));
    for h in &gone {
        st.ordered_set.remove(h);
        st.known_headers.remove(h);
        if let Some(ht) = st.hash_height.remove(h) {
            if st.height_to_hash.get(&ht) == Some(h) {
                st.height_to_hash.remove(&ht);
            }
        }
    }
}

/// Queue tail, or the confirmed tip when the queue is empty.
fn path_top(st: &IbdWorkState, hub: &ChainHub) -> Option<(BlockHash, u32)> {
    if let Some(tail) = st.ordered.back().copied() {
        return st.hash_height.get(&tail).copied().map(|h| (tail, h));
    }
    Some((hub.tip_hash()?, hub.tip_height()?))
}

/// The walk tip is past the stored path, so a further reply is not a refill.
fn walk_ahead_of_queue(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let Some((_, top_h)) = path_top(st, hub) else {
        return false;
    };
    st.header_walk.origin && st.header_walk.tip_height() > top_h
}

/// The walk tip is past the highest header recorded on the work path.
fn walk_ahead_of_stored(st: &IbdWorkState) -> bool {
    st.header_walk.origin && st.header_walk.tip_height() > st.max_ordered_height
}

/// Queue tail, or the confirmed tip when the queue is empty.
fn stored_top_hash(st: &IbdWorkState, hub: &ChainHub) -> Option<BlockHash> {
    st.ordered.back().copied().or_else(|| hub.tip_hash())
}

/// What a headers batch is, from the hash it builds on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderClass {
    /// Checkpoint. The batch is not a header row.
    WalkAbsorb,
    /// Continues the walk at the stored top. Write it and advance the walk.
    WalkStore,
    /// Continues the stored top while the walk is ahead.
    Refill,
    /// A competing chain, or a batch from before the walk has a tip.
    Fork,
    /// Below the work floor, and parent of neither the walk nor the stored top.
    Stray,
}

/// One class per batch. The lane only says whether the peer was asked.
pub(crate) fn classify(
    st: &IbdWorkState,
    hub: &ChainHub,
    ask: HeaderAsk,
    headers: &[Header],
) -> HeaderClass {
    if headers.is_empty() || !pow_linked(headers) {
        return HeaderClass::Fork;
    }
    if !st.header_walk.origin {
        if st.ordered.len() >= ORDERED_HEADERS_SOFT_CAP {
            return HeaderClass::WalkAbsorb;
        }
        if stored_top_hash(st, hub) == Some(headers[0].prev_blockhash) {
            return HeaderClass::Refill;
        }
        return HeaderClass::Fork;
    }
    let prev = headers[0].prev_blockhash;
    let on_walk = st.header_walk.tip_hash() == Some(prev);
    let on_top = stored_top_hash(st, hub) == Some(prev);
    let under = st.ordered.len() < ORDERED_HEADERS_SOFT_CAP;
    let solicited = ask != HeaderAsk::Unsolicited;
    // Full queue, a solicited reply while the walk is ahead, or the first
    // solicited continuation of the stored tip. That first checkpoint is what
    // puts the walk ahead. A later caught-up continuation is stored.
    let checkpoint = !under
        || (solicited && walk_ahead_of_queue(st, hub))
        || (solicited && on_walk && st.header_walk.checkpoints.is_empty());
    if st
        .header_walk
        .tip
        .hash
        .is_some_and(|tip| st.header_walk.dead_ends.contains(&tip))
        && checkpoint
    {
        return HeaderClass::WalkAbsorb;
    }
    if on_walk && checkpoint {
        return HeaderClass::WalkAbsorb;
    }
    if on_walk && under {
        return HeaderClass::WalkStore;
    }
    if on_top && under {
        return HeaderClass::Refill;
    }
    if ignore_below_floor(st, hub, headers) {
        return HeaderClass::Stray;
    }
    HeaderClass::Fork
}

/// Record a look-ahead batch as a checkpoint. True when the batch was consumed
/// and must not be written. The caller has already decided this is a walk
/// checkpoint: queue length does not choose again.
pub(crate) fn absorb_lookahead(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    ask: HeaderAsk,
    headers: &[Header],
) -> bool {
    if headers.is_empty() {
        return false;
    }
    ensure_origin(st, hub);
    let Some(tip) = st.header_walk.tip_hash() else {
        return false;
    };
    if st.header_walk.dead_ends.contains(&tip) {
        return true;
    }
    if headers[0].prev_blockhash != tip {
        return false;
    }
    if ask == HeaderAsk::Unsolicited {
        return true;
    }
    if !batch_context_ok(st, hub, headers, &st.header_walk.tip.diff) {
        punish_header_peer(st, peer);
        clear_peer_ask(st, peer);
        return true;
    }
    let extended = extend_tip(st, hub, headers);
    clear_peer_ask(st, peer);
    if extended && ask == HeaderAsk::Late {
        rbitcoin_log::info!(
            "ibd: headers late peer={peer} height={}",
            st.header_walk.tip_height()
        );
    }
    extended
}

/// A batch that does not extend the live candidate below the work floor.
///
/// Building on a dead end, or on an earlier checkpoint while the candidate is
/// still live, must not be written.
pub(crate) fn ignore_below_floor(st: &IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
    if headers.is_empty() || !st.header_walk.origin || !below_floor(hub, &st.header_walk.tip_work())
    {
        return false;
    }
    let prev = headers[0].prev_blockhash;
    if st.header_walk.dead_ends.contains(&prev) {
        return true;
    }
    let Some(tip) = st.header_walk.tip_hash() else {
        return false;
    };
    if prev == tip {
        return false;
    }
    if st.ordered.len() < ORDERED_HEADERS_SOFT_CAP && stored_top_hash(st, hub) == Some(prev) {
        return false;
    }
    true
}

/// A queue refill below or above the floor that does not land on the next
/// checkpoint. True when the reply was consumed and must not be written.
pub(crate) fn reject_refill_miss(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    headers: &[Header],
) -> bool {
    if headers.is_empty()
        || !st.header_walk.origin
        || st.header_walk.checkpoints.is_empty()
        || st.ordered.len() >= ORDERED_HEADERS_SOFT_CAP
    {
        return false;
    }
    let prev = headers[0].prev_blockhash;
    // A proven walk is the most-work header chain so far. A refill that
    // disagrees with its next checkpoint is not the download path. A short
    // refill that has not reached that checkpoint still is: refusing it
    // leaves the block queue empty. A later batch from the same anchor that
    // does meet the checkpoint replaces that unproved queue.
    if let Some(tail) = st.ordered.back().copied() {
        if prev != tail {
            return replace_unproved_queue(st, hub, prev, headers);
        }
        let Some(&tail_h) = st.hash_height.get(&tail) else {
            return false;
        };
        return judge_refill(st, hub, tail_h, headers);
    }
    if !proved_above_floor(st, hub) || hub.tip_hash() != Some(prev) {
        return false;
    }
    let Some(tip_h) = hub.tip_height() else {
        return false;
    };
    judge_refill(st, hub, tip_h, headers)
}

fn proved_above_floor(st: &IbdWorkState, hub: &ChainHub) -> bool {
    st.header_walk.proven && !below_floor(hub, &st.header_walk.tip_work())
}

fn judge_refill(st: &mut IbdWorkState, hub: &ChainHub, start_h: u32, headers: &[Header]) -> bool {
    if proved_above_floor(st, hub) {
        return match path_agree(st, start_h, headers, true) {
            PathAgree::Diverges => offer_alternate(st, hub, None, headers).unwrap_or(true),
            PathAgree::Short | PathAgree::Checkpoint(_) => false,
        };
    }
    if !refill_misses_checkpoint(st, start_h, headers) {
        return false;
    }
    rewind_above(st, hub, start_h);
    false
}

/// Queue that continues the stored tip but has not met the next checkpoint.
/// The hash is the proved parent those headers extend.
fn unproved_anchor(st: &IbdWorkState, hub: &ChainHub) -> Option<(BlockHash, u32)> {
    let front = st.ordered.front().copied()?;
    let front_h = st.hash_height.get(&front).copied()?;
    // The highest checkpoint under the queue front is the anchor. A covered
    // checkpoint at or above the front means the queue is already proved.
    let mut reached = false;
    let mut below: Option<&Checkpoint> = None;
    for c in &st.header_walk.checkpoints {
        if c.height >= front_h {
            let covered = st
                .ordered
                .iter()
                .any(|hash| st.hash_height.get(hash).is_some_and(|ht| *ht >= c.height));
            if covered {
                reached = true;
            }
        } else {
            let replace = match below {
                Some(best) => c.height > best.height,
                None => true,
            };
            if replace {
                below = Some(c);
            }
        }
    }
    if reached {
        return None;
    }
    if let Some(cp) = below {
        return Some((cp.hash, cp.height));
    }
    let tip_h = hub.tip_height()?;
    if front_h == tip_h.saturating_add(1) {
        return Some((hub.tip_hash()?, tip_h));
    }
    None
}

/// A batch from the proved anchor under an unproved queue.
///
/// True when the reply was consumed. A batch that meets the next checkpoint
/// clears that queue so the caller can write it. A short guess does not
/// replace the one already queued. A checkpoint miss is a competing chain.
fn replace_unproved_queue(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    prev: BlockHash,
    headers: &[Header],
) -> bool {
    if !proved_above_floor(st, hub) {
        return false;
    }
    let Some((anchor, anchor_h)) = unproved_anchor(st, hub) else {
        return false;
    };
    if prev != anchor {
        return false;
    }
    match path_agree(st, anchor_h, headers, false) {
        PathAgree::Checkpoint(_) => {
            drop_queue_above(st, anchor_h, &HashSet::new());
            false
        }
        PathAgree::Diverges => offer_alternate(st, hub, None, headers).unwrap_or(true),
        PathAgree::Short => true,
    }
}

/// A checkpoint this batch meets is an ancestor of the milestone walk.
/// Headers past that checkpoint, or a batch that never meets one, are not.
enum PathAgree {
    Checkpoint(u32),
    Short,
    Diverges,
}

fn candidate_prev(st: &IbdWorkState, prev: BlockHash) -> bool {
    st.ordered.back().copied() == Some(prev)
        || st.header_walk.base_hash == Some(prev)
        || st.header_walk.tip_hash() == Some(prev)
        || st.header_walk.checkpoints.iter().any(|c| c.hash == prev)
        || st
            .hash_height
            .get(&prev)
            .is_some_and(|h| st.height_to_hash.get(h) == Some(&prev))
}

/// `slots` is false when an unproved queue already occupies `height_to_hash`.
/// The next checkpoint is the proof, not that guess.
fn path_agree(st: &IbdWorkState, start_h: u32, headers: &[Header], slots: bool) -> PathAgree {
    let Some(first) = headers.first() else {
        return PathAgree::Short;
    };
    let mut height = start_h;
    let mut prev = first.prev_blockhash;
    let mut agreed: Option<u32> = None;
    let mut any = false;
    for hdr in headers {
        if hdr.prev_blockhash != prev {
            break;
        }
        any = true;
        height = height.saturating_add(1);
        let hash = hdr.block_hash();
        if let Some(c) = st
            .header_walk
            .checkpoints
            .iter()
            .find(|c| c.height == height)
        {
            if c.hash != hash {
                return PathAgree::Diverges;
            }
            agreed = Some(height);
        } else if slots {
            if let Some(want) = st.height_to_hash.get(&height) {
                if *want != hash {
                    return PathAgree::Diverges;
                }
            } else if agreed.is_some() {
                break;
            }
        }
        prev = hash;
    }
    if !any {
        return PathAgree::Short;
    }
    match agreed {
        Some(h) => PathAgree::Checkpoint(h),
        None => PathAgree::Short,
    }
}

/// How many headers of a proven-chain reply may be written.
///
/// The whole reply stays writable below the work floor, and when it does not
/// build on the candidate. On a proven candidate, only the prefix through the
/// checkpoint the reply actually met is on the chain toward the milestone.
pub(crate) fn proven_header_prefix(st: &IbdWorkState, hub: &ChainHub, headers: &[Header]) -> usize {
    if headers.is_empty()
        || !st.header_walk.proven
        || below_floor(hub, &st.header_walk.tip_work())
        || !st.header_walk.origin
        || st.header_walk.checkpoints.is_empty()
    {
        return headers.len();
    }
    let prev = headers[0].prev_blockhash;
    if !candidate_prev(st, prev) {
        return headers.len();
    }
    let Some(start_h) = height_of(st, hub, prev) else {
        return headers.len();
    };
    let stop = match path_agree(st, start_h, headers, true) {
        PathAgree::Checkpoint(stop) => stop,
        // Continues the stored tip and has not missed a checkpoint. The
        // block queue needs these headers even when the next checkpoint is
        // further than this reply.
        PathAgree::Short => {
            if stored_top_hash(st, hub) == Some(prev) {
                return headers.len();
            }
            return 0;
        }
        // A fork that is not the queue-tail refill stays in the header store.
        // The proven tail path already consumed its own divergent refill.
        PathAgree::Diverges => return headers.len(),
    };
    let mut height = start_h;
    let mut link = prev;
    let mut n = 0usize;
    for hdr in headers {
        if hdr.prev_blockhash != link {
            break;
        }
        height = height.saturating_add(1);
        if height > stop {
            break;
        }
        n += 1;
        link = hdr.block_hash();
    }
    n
}

fn refill_misses_checkpoint(st: &IbdWorkState, tail_h: u32, headers: &[Header]) -> bool {
    let checkpoints = st.header_walk.checkpoints();
    let Some(mut next_i) = checkpoints.iter().position(|c| c.height > tail_h) else {
        return false;
    };
    let mut height = tail_h;
    let mut prev = headers[0].prev_blockhash;
    for hdr in headers {
        if hdr.prev_blockhash != prev {
            break;
        }
        height = height.saturating_add(1);
        if height == checkpoints[next_i].height {
            if hdr.block_hash() != checkpoints[next_i].hash {
                return true;
            }
            next_i += 1;
            if next_i >= checkpoints.len() {
                return false;
            }
        }
        prev = hdr.block_hash();
    }
    // A linked prefix that has not reached the next checkpoint is the same
    // chain, still short of the proof. Only a hash at a checkpoint height
    // that is not the checkpoint is a miss.
    false
}

/// Every alive peer answered empty before the work floor. True when the walk
/// consumed the reply.
pub(crate) fn note_empty(st: &mut IbdWorkState, hub: &ChainHub, peer: usize) -> bool {
    if !st.header_walk.origin || !below_floor(hub, &st.header_walk.tip_work()) {
        return false;
    }
    st.header_walk.emptied.insert(peer);
    let tall: Vec<usize> = st
        .slots
        .iter()
        .filter(|s| s.alive && s.peer_height > st.header_walk.tip_height())
        .map(|s| s.id)
        .collect();
    let alive: Vec<usize> = if tall.is_empty() {
        st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect()
    } else {
        tall
    };
    if alive.is_empty() || alive.iter().any(|id| !st.header_walk.emptied.contains(id)) {
        let _ = send_getheaders(st, hub);
        return true;
    }
    rewind(st, hub);
    let _ = send_getheaders(st, hub);
    true
}

/// Checkpoint at the batch end when these stored headers extend the candidate.
///
/// Context was already checked by [`ChainHub::ensure_headers_batch`]. A batch
/// the walk absorbed is written on that same path; this only records the
/// checkpoint when the tip has not already moved.
pub(crate) fn note_stored_candidate(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header]) {
    if !st.header_walk.origin || headers.is_empty() || !pow_linked(headers) {
        return;
    }
    let Some(tip) = st.header_walk.tip_hash() else {
        return;
    };
    if headers[0].prev_blockhash != tip || st.header_walk.dead_ends.contains(&tip) {
        return;
    }
    let _ = extend_tip(st, hub, headers);
}

fn extend_tip(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
    let Some(start) = st.header_walk.tip.hash else {
        return false;
    };
    let mut prev = start;
    for hdr in headers {
        if !push_header(&mut st.header_walk.tip, hub, hdr) {
            break;
        }
        remember_milestone(&mut st.header_walk.tip, hub, prev, hdr);
        prev = st.header_walk.tip.hash.unwrap_or(prev);
    }
    if st.header_walk.tip.hash == Some(start) {
        return false;
    }
    st.header_walk
        .checkpoints
        .push(checkpoint_at(&st.header_walk.tip));
    st.header_walk.emptied.clear();
    publish_work(st, hub);
    save_adopt(st, hub);
    true
}

fn remember_milestone(tip: &mut WalkTip, hub: &ChainHub, prev: BlockHash, hdr: &Header) {
    if hub.milestone.height == 0 || tip.height != hub.milestone.height {
        return;
    }
    let Some(hash) = tip.hash else {
        return;
    };
    if let Some(existing) = tip.milestone_hash {
        if existing != hash {
            rbitcoin_log::warn!(
                "ibd: headers anchor mismatch height={} hash={hash} previous={existing}",
                tip.height
            );
            return;
        }
    }
    tip.milestone_hash = Some(hash);
    tip.milestone_prev = prev;
    tip.milestone_header = Some(*hdr);
    hub.query.note_milestone_header(
        tip.height,
        hash.to_byte_array(),
        prev.to_byte_array(),
        hdr.work(),
        None,
    );
}

fn publish_work(st: &mut IbdWorkState, hub: &ChainHub) {
    if below_floor(hub, &st.header_walk.tip_work()) {
        return;
    }
    let opened = !st.header_walk.proven;
    st.header_walk.proven = true;
    let Some(anchor) = hub.milestone.anchor else {
        return;
    };
    let Some(hash) = st.header_walk.milestone_hash() else {
        return;
    };
    if hash != anchor.hash {
        if opened {
            rbitcoin_log::warn!(
                "ibd: headers anchor mismatch height={} hash={hash} anchor={}",
                hub.milestone.height,
                anchor.hash
            );
        }
        return;
    }
    hub.query
        .note_milestone_checkpoint_work(st.header_walk.tip_height(), st.header_walk.tip_work());
    if !opened {
        return;
    }
    rbitcoin_log::info!(
        "ibd: headers milestone height={} hash={hash} work=ok",
        hub.milestone.height
    );
}

fn rewind(st: &mut IbdWorkState, hub: &ChainHub) {
    let Some(dead) = st.header_walk.tip_hash() else {
        return;
    };
    rewind_to(st, hub, 0, Some(dead));
}

fn forget_milestone_below(st: &mut IbdWorkState, hub: &ChainHub, height: u32) {
    if hub.milestone.height == 0 || height >= hub.milestone.height {
        return;
    }
    st.header_walk.tip.milestone_hash = None;
    st.header_walk.tip.milestone_header = None;
    hub.query.clear_milestone_path_above(height);
}

fn lane_fresh(lane: &Lane) -> bool {
    lane.peer.is_some() && lane.at.is_some_and(|t| t.elapsed() <= LOOKAHEAD_ASK)
}

/// Lanes still inside their ask window when a reply arrives. Time spent
/// handling that reply is not part of the window: a slow store must not
/// rotate a peer who has not missed.
pub(crate) struct InFlight {
    walk: Option<(usize, Instant)>,
    started: Instant,
    held: bool,
}

impl InFlight {
    pub(crate) fn capture(st: &IbdWorkState) -> Self {
        Self {
            walk: fresh_mark(&st.header_walk.walk),
            started: Instant::now(),
            held: false,
        }
    }

    /// Move a still-waiting ask's start forward by the time since [`capture`].
    pub(crate) fn hold(&mut self, st: &mut IbdWorkState) {
        if self.held {
            return;
        }
        self.held = true;
        let paused = self.started.elapsed();
        hold_mark(&mut st.header_walk.walk, self.walk, paused);
    }
}

fn fresh_mark(lane: &Lane) -> Option<(usize, Instant)> {
    if !lane_fresh(lane) {
        return None;
    }
    Some((lane.peer?, lane.at?))
}

fn hold_mark(lane: &mut Lane, saved: Option<(usize, Instant)>, paused: Duration) {
    let Some((peer, at)) = saved else {
        return;
    };
    if lane.peer == Some(peer) && lane.at == Some(at) {
        lane.at = at.checked_add(paused);
    }
}

fn release_lane(lane: &mut Lane) {
    if let Some(peer) = lane.peer.take() {
        lane.prev_peer = Some(peer);
    }
    lane.at = None;
}

/// Drop this peer's in-flight ask on every lane. A late reply still matches
/// `prev_peer`.
fn clear_peer_ask(st: &mut IbdWorkState, peer: usize) {
    let lane = &mut st.header_walk.walk;
    if lane.peer == Some(peer) {
        lane.peer = None;
        lane.at = None;
    }
}

/// Whether a headers reply is the one we asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderAsk {
    /// This peer was not asked.
    Unsolicited,
    /// Reply inside the window.
    InWindow,
    /// The window expired. The tip has not moved, so the reply can still extend it.
    Late,
}

/// The peer answered. A late reply from the peer we asked, or from the peer
/// we skipped after one miss, is [`HeaderAsk::Late`].
pub(crate) fn take_header_ask(st: &mut IbdWorkState, peer: usize) -> HeaderAsk {
    let lane = &mut st.header_walk.walk;
    let current = lane.peer == Some(peer);
    let previous = lane.prev_peer == Some(peer);
    if !current && !previous {
        return HeaderAsk::Unsolicited;
    }
    let fresh = current && lane_fresh(lane);
    if current {
        lane.peer = None;
        lane.at = None;
    }
    if previous {
        lane.prev_peer = None;
    }
    st.header_walk
        .header_misses
        .retain(|&asked, _| asked != peer);
    if fresh {
        HeaderAsk::InWindow
    } else {
        HeaderAsk::Late
    }
}

/// Count an expired ask on this lane. The peer is skipped on this pick. A
/// second expiry disconnects them and is not skipped: they are no longer alive.
fn expire_header_ask(st: &mut IbdWorkState) -> Option<usize> {
    let peer = {
        let lane = &mut st.header_walk.walk;
        let peer = lane.peer?;
        lane.prev_peer = Some(peer);
        lane.peer = None;
        lane.at = None;
        peer
    };
    let n = {
        let e = st.header_walk.header_misses.entry(peer).or_insert(0);
        *e = e.saturating_add(1);
        *e
    };
    if st.header_walk.challenge_open == Some(peer) {
        st.header_walk.challenge_open = None;
        st.header_walk.challenge_external = false;
        if n >= HEADER_MISS_DISCONNECT {
            st.header_walk.header_misses.remove(&peer);
            punish_header_peer(st, peer);
        } else {
            st.header_walk.walk_quiet.insert(peer);
        }
        return None;
    }
    if st.header_walk.reserved == Some(peer) {
        st.header_walk.reserved = None;
    }
    if n >= HEADER_MISS_DISCONNECT {
        st.header_walk.header_misses.remove(&peer);
        punish_header_peer(st, peer);
        return None;
    }
    Some(peer)
}

fn note_lane(st: &mut IbdWorkState, peer: usize) {
    let lane = &mut st.header_walk.walk;
    if let Some(prev) = lane.peer {
        if prev != peer {
            lane.prev_peer = Some(prev);
        }
    }
    lane.peer = Some(peer);
    lane.at = Some(Instant::now());
}

fn punish_header_peer(st: &mut IbdWorkState, peer: usize) {
    super::dial::disconnect_peer(st, peer);
}

/// Ask for the next header when it is not already stored. The locator is the
/// stored path tip. A request still inside its window stays in flight. One
/// miss moves the reservation when another peer can take it. A second miss
/// disconnects. A block-inv challenge is one ask to that peer and does not
/// replace the reservation until the reply beats the candidate.
pub(crate) fn send_getheaders(
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, crate::error::NetError> {
    ensure_origin(st, hub);
    super::path::append_stored_headers(st, hub);
    if st.header_walk.challenge.is_none() && super::path::walk_successor_indexed(st, hub) {
        release_lane(&mut st.header_walk.walk);
        return Ok(false);
    }
    let want =
        st.header_walk.challenge.is_some() || wants_lookahead(st) || walk_ahead_of_queue(st, hub);
    if !want {
        release_lane(&mut st.header_walk.walk);
        return Ok(false);
    }
    arm_header_ask(st, hub)
}

/// Locator for one headers ask.
///
/// Bitcoin answers after the first locator hash the peer knows. While the
/// queue can take headers, that hash is the stored tip. An unproved queue
/// also names the proved anchor under it, so a peer that does not have the
/// guess still sends the gap. The candidate and its checkpoints follow. A
/// full queue is look-ahead and starts at the candidate.
fn header_ask_locator(st: &IbdWorkState, hub: &ChainHub) -> Vec<BlockHash> {
    let mut tips = Vec::new();
    if st.ordered.len() < ORDERED_HEADERS_SOFT_CAP {
        if let Some(stored) = stored_top_hash(st, hub) {
            tips.push(stored);
        }
        if let Some((anchor, _)) = unproved_anchor(st, hub) {
            if !tips.contains(&anchor) {
                tips.push(anchor);
            }
        }
    }
    for hash in st.header_walk.locator_hashes() {
        if !tips.contains(&hash) {
            tips.push(hash);
        }
    }
    if tips.is_empty() {
        tips = super::path::work_path_tips(st);
    }
    tips
}

fn arm_header_ask(st: &mut IbdWorkState, hub: &ChainHub) -> Result<bool, crate::error::NetError> {
    if lane_fresh(&st.header_walk.walk) {
        return Ok(true);
    }
    let skip = expire_header_ask(st);
    let tips = header_ask_locator(st, hub);
    let above = path_top(st, hub).map(|(_, height)| height).unwrap_or(0);
    if let Some(peer) = take_challenge(st) {
        if ask_header_peer(st, hub, peer, &tips)? {
            st.header_walk.challenge_open = Some(peer);
            return Ok(true);
        }
        st.header_walk.challenge_external = false;
    }
    ensure_reserved(st, above, skip);
    if st.header_walk.reserved.is_none() {
        // Connect-time start height can sit on the stored tip, so no peer
        // looks taller than a header this node already holds.
        st.header_walk.reserved = pick_any_header_peer(st, skip);
    }
    let Some(peer) = st.header_walk.reserved else {
        return Ok(false);
    };
    ask_header_peer(st, hub, peer, &tips)
}

/// Time from connect to the first block body. `None` until a body arrives.
fn header_ttfb(slot: &super::peer_io::PeerSlot) -> Option<u64> {
    if slot.first_data_ms == 0 {
        None
    } else {
        Some(slot.first_data_ms.saturating_sub(slot.connected_ms))
    }
}

fn peer_can_head(st: &IbdWorkState, id: usize, above: u32) -> bool {
    st.slots.iter().any(|s| {
        s.alive && s.id == id && s.peer_height > above && !st.header_walk.walk_quiet.contains(&id)
    })
}

/// A live peer when nobody's connect-time height is above the stored path.
/// Peers still on the walk come first.
fn pick_any_header_peer(st: &IbdWorkState, skip: Option<usize>) -> Option<usize> {
    fn rank(st: &IbdWorkState, skip: Option<usize>, quiet_ok: bool) -> Option<usize> {
        let mut best: Option<(u8, u64, usize)> = None;
        for slot in &st.slots {
            if !slot.alive || skip == Some(slot.id) {
                continue;
            }
            if !quiet_ok && st.header_walk.walk_quiet.contains(&slot.id) {
                continue;
            }
            let key = match header_ttfb(slot) {
                Some(ttfb) => (0u8, ttfb, slot.id),
                None => (1u8, 0, slot.id),
            };
            if best.is_none_or(|cur| key < cur) {
                best = Some(key);
            }
        }
        if let Some((_, _, id)) = best {
            return Some(id);
        }
        skip.filter(|&id| {
            st.slots.iter().any(|s| {
                s.alive && s.id == id && (quiet_ok || !st.header_walk.walk_quiet.contains(&id))
            })
        })
    }
    rank(st, skip, false).or_else(|| rank(st, skip, true))
}

/// Lowest time-to-first-byte among peers still on the walk. A peer with no
/// body yet sorts after one who has delivered. `skip` is the peer whose ask
/// just expired, unless they are the only one left.
fn pick_header_peer(st: &IbdWorkState, above: u32, skip: Option<usize>) -> Option<usize> {
    let mut best: Option<(u8, u64, usize)> = None;
    for slot in &st.slots {
        if !peer_can_head(st, slot.id, above) || skip == Some(slot.id) {
            continue;
        }
        let key = match header_ttfb(slot) {
            Some(ttfb) => (0u8, ttfb, slot.id),
            None => (1u8, 0, slot.id),
        };
        if best.is_none_or(|cur| key < cur) {
            best = Some(key);
        }
    }
    if let Some((_, _, id)) = best {
        return Some(id);
    }
    skip.filter(|&id| peer_can_head(st, id, above))
}

fn ensure_reserved(st: &mut IbdWorkState, above: u32, skip: Option<usize>) {
    if let Some(id) = st.header_walk.reserved {
        // An empty reply asks again before that challenge is judged. Moving
        // the reservation here would drop the header peer for an inv that
        // did not come from them.
        let unjudged_external =
            st.header_walk.challenge_open == Some(id) && st.header_walk.challenge_external;
        if unjudged_external || (peer_can_head(st, id, above) && skip != Some(id)) {
            return;
        }
    }
    st.header_walk.reserved = pick_header_peer(st, above, skip);
}

/// A challenge peer who is still connected and not retired.
fn take_challenge(st: &mut IbdWorkState) -> Option<usize> {
    let peer = st.header_walk.challenge.take()?;
    let usable = st
        .slots
        .iter()
        .any(|s| s.alive && s.id == peer && !st.header_walk.walk_quiet.contains(&peer));
    if usable {
        Some(peer)
    } else {
        None
    }
}

fn ask_header_peer(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    tips: &[BlockHash],
) -> Result<bool, crate::error::NetError> {
    let tail = confirmed_chain_tail(st, hub)?;
    let locator = super::dial::ibd_header_locator(hub, tips, &tail);
    if !super::dial::request_headers_from(&st.slots, peer, &mut st.header_req_seq, locator)? {
        return Ok(false);
    }
    note_lane(st, peer);
    Ok(true)
}

/// Confirmed-chain tail for `getheaders`.
///
/// Rebuilt when `published_tip` height or hash changes. The work-path prefix
/// is not part of this vec.
fn confirmed_chain_tail(
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Result<Vec<BlockHash>, crate::error::NetError> {
    let published = hub.query.published_tip();
    let height = published.map(|tip| tip.height);
    let hash = published.map(|tip| tip.hash);
    if let Some(cached) = &st.confirmed_locator_tail {
        if cached.height == height && cached.hash == hash {
            return Ok(cached.hashes.clone());
        }
    }
    let tail = hub
        .query
        .locator_hashes()
        .map_err(|e| crate::error::NetError::Consensus(e.to_string()))?;
    st.confirmed_locator_tail = Some(ConfirmedLocatorTail {
        height,
        hash,
        hashes: tail.clone(),
    });
    Ok(tail)
}

fn parent_header(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<Header> {
    known(st, hash).header.or_else(|| hub.header_of(&hash))
}

fn height_of(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<u32> {
    known(st, hash).height.or_else(|| {
        st.hash_height.get(&hash).copied().or_else(|| {
            hub.query
                .height_of_hash(hash.as_byte_array())
                .ok()
                .flatten()
                .map(|h| h.0)
        })
    })
}

fn seed_tip_times(st: &mut IbdWorkState, hub: &ChainHub, header: Header) {
    let mut times = vec![header.time];
    let mut prev_hash = header.prev_blockhash;
    for _ in 0..10 {
        let Some(prev) = parent_header(st, hub, prev_hash) else {
            break;
        };
        times.push(prev.time);
        prev_hash = prev.prev_blockhash;
    }
    times.reverse();
    st.header_walk.tip.header = Some(header);
    st.header_walk.tip.times = times;
}

fn restore_tip_header(st: &mut IbdWorkState, hub: &ChainHub) {
    let saved = st.header_walk.checkpoints.last().cloned();
    if let Some(c) = saved {
        st.header_walk.tip.diff = c.diff;
        if let Some(header) = c.header {
            st.header_walk.tip.header = Some(header);
            st.header_walk.tip.times = c.times;
            return;
        }
        if let Some(header) = hub.header_of(&c.hash) {
            seed_tip_times(st, hub, header);
            return;
        }
    } else {
        st.header_walk.tip.diff = st.header_walk.base_diff;
        if let Some(header) = st.header_walk.base_hash.and_then(|h| hub.header_of(&h)) {
            seed_tip_times(st, hub, header);
            return;
        }
    }
    st.header_walk.tip.header = None;
    st.header_walk.tip.times.clear();
}

fn batch_context_ok(
    st: &IbdWorkState,
    hub: &ChainHub,
    headers: &[Header],
    diff: &DiffSnap,
) -> bool {
    if headers.is_empty() {
        return false;
    }
    let Some(mut parent) = parent_header(st, hub, headers[0].prev_blockhash) else {
        return false;
    };
    let Some(mut height) = height_of(st, hub, parent.block_hash()) else {
        return false;
    };
    let mut times = times_ending_at(st, hub, parent.block_hash());
    let mut parent_hash = parent.block_hash();
    // The min-difficulty walk-back can land on a header earlier in this
    // reply, so the snapshot advances with the batch.
    let mut diff = *diff;
    for hdr in headers {
        let hash = hdr.block_hash();
        if hdr.prev_blockhash != parent_hash {
            return false;
        }
        height = height.saturating_add(1);
        let mtp = if times.len() < 11 {
            0
        } else {
            match rbitcoin_primitives::median_time_past_times(&times) {
                Ok(mtp) => mtp,
                Err(_) => return false,
            }
        };
        parent_hash = hash;
        let Some(bits) = expected_lookahead_bits(hub, height, &parent, hdr.time, st, &diff) else {
            return false;
        };
        if rbitcoin_consensus::validate_header_on_parent(
            &hub.params,
            rbitcoin_primitives::Height(height),
            hdr,
            mtp,
            bits,
        )
        .is_err()
        {
            return false;
        }
        if times.len() == 11 {
            times.remove(0);
        }
        times.push(hdr.time);
        note_period_snap(&mut diff, hub, *hdr, height);
        note_full_diff_snap(&mut diff, hub, hdr, height);
        parent = *hdr;
    }
    true
}

fn expected_lookahead_bits(
    hub: &ChainHub,
    height: u32,
    parent: &Header,
    header_time: u32,
    st: &IbdWorkState,
    diff: &DiffSnap,
) -> Option<CompactTarget> {
    rbitcoin_consensus::next_work_bits(
        &hub.params,
        height,
        parent.bits,
        parent.time,
        header_time,
        period_first_time(hub, height, st, diff),
        |h| lookahead_bits_at(diff, st, hub, h),
    )
}

fn period_first_time(
    hub: &ChainHub,
    height: u32,
    st: &IbdWorkState,
    diff: &DiffSnap,
) -> Option<u32> {
    let params = &hub.params;
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.is_multiple_of(interval) || params.no_pow_retargeting() {
        return None;
    }
    let start_h = height - interval;
    let first = if diff.period_height == start_h {
        diff.period_header
    } else {
        None
    };
    first
        .or_else(|| header_on_store(st, hub, start_h))
        .map(|h| h.time)
}

fn lookahead_bits_at(
    diff: &DiffSnap,
    st: &IbdWorkState,
    hub: &ChainHub,
    height: u32,
) -> Option<CompactTarget> {
    let limit = hub.params.pow_limit.to_compact_lossy();
    if let Some(bits) = diff.full_diff_bits {
        if height == diff.full_diff_height {
            return Some(bits);
        }
        if height > diff.full_diff_height && bits != limit {
            return Some(limit);
        }
    }
    if let Some(hdr) = header_on_store(st, hub, height) {
        return Some(hdr.bits);
    }
    if hub.params.allow_min_difficulty_blocks() && diff.full_diff_bits.is_none() {
        return Some(limit);
    }
    None
}

fn header_on_store(st: &IbdWorkState, hub: &ChainHub, height: u32) -> Option<Header> {
    if st.header_walk.tip_height() == height {
        if let Some(hdr) = st.header_walk.tip_header() {
            return Some(hdr);
        }
    }
    if st.header_walk.base_height == height {
        if let Some(hdr) = st.header_walk.base_hash.and_then(|h| hub.header_of(&h)) {
            return Some(hdr);
        }
    }
    if let Some(hdr) = st
        .height_to_hash
        .get(&height)
        .and_then(|h| hub.header_of(h))
    {
        return Some(hdr);
    }
    let hash = hub
        .query
        .header_at_height(rbitcoin_primitives::Height(height))
        .ok()
        .flatten()?
        .1
        .hash;
    hub.header_of(&BlockHash::from_byte_array(hash))
}

fn pow_linked(headers: &[Header]) -> bool {
    for (i, hdr) in headers.iter().enumerate() {
        if hdr.validate_pow(hdr.target()).is_err() {
            return false;
        }
        if i > 0 && hdr.prev_blockhash != headers[i - 1].block_hash() {
            return false;
        }
    }
    true
}

const ADOPT_MAGIC: &[u8; 8] = b"rbtchdr1";
/// period height u32 ‖ period header 80 ‖ full-diff height u32 ‖ full-diff bits u32.
const DIFF_SNAP_LEN: usize = 4 + 80 + 4 + 4;

fn adopt_path(hub: &ChainHub) -> std::path::PathBuf {
    hub.query.store().path().join("header.adopt")
}

fn write_header(buf: &mut Vec<u8>, header: Option<Header>) {
    let mut raw = [0u8; 80];
    if let Some(header) = header {
        let enc = bitcoin::consensus::serialize(&header);
        if enc.len() == raw.len() {
            raw.copy_from_slice(&enc);
        }
    }
    buf.extend_from_slice(&raw);
}

fn read_header(raw: &[u8]) -> Option<Header> {
    if raw.iter().all(|b| *b == 0) {
        return None;
    }
    bitcoin::consensus::deserialize(raw).ok()
}

fn write_diff(buf: &mut Vec<u8>, diff: &DiffSnap) {
    buf.extend_from_slice(&diff.period_height.to_le_bytes());
    write_header(buf, diff.period_header);
    buf.extend_from_slice(&diff.full_diff_height.to_le_bytes());
    let bits = diff.full_diff_bits.map(|b| b.to_consensus()).unwrap_or(0);
    buf.extend_from_slice(&bits.to_le_bytes());
}

fn read_diff(bytes: &[u8]) -> Option<DiffSnap> {
    if bytes.len() < DIFF_SNAP_LEN {
        return None;
    }
    let period_height = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let period_header = read_header(&bytes[4..84]);
    let full_diff_height = u32::from_le_bytes(bytes[84..88].try_into().ok()?);
    let full_bits = u32::from_le_bytes(bytes[88..92].try_into().ok()?);
    let full_diff_bits = (full_bits != 0).then_some(CompactTarget::from_consensus(full_bits));
    Some(DiffSnap {
        period_header,
        period_height,
        full_diff_bits,
        full_diff_height,
    })
}

fn base_conflicts(st: &IbdWorkState, hub: &ChainHub, walk: &HeaderWalk) -> bool {
    let Some(base) = walk.base_hash else {
        return false;
    };
    if st
        .height_to_hash
        .get(&walk.base_height)
        .is_some_and(|h| *h != base)
    {
        return true;
    }
    match hub
        .query
        .header_at_height(rbitcoin_primitives::Height(walk.base_height))
    {
        Ok(Some((_, rec))) => rec.hash != *base.as_byte_array(),
        _ => false,
    }
}

/// A confirmed reorg under the walk's base drops `header.adopt`. The file must
/// not bring back a hash from the chain that was disconnected. A reorg under
/// the milestone height drops the latched hash. Putting that hash back is
/// unsafe: the walk above the fork can still be the chain that was
/// disconnected, while the base is still the confirmed block. Script checks
/// stay on until this chain records the milestone block. A reorg that stays
/// above the milestone puts that hash back after the path clear.
pub(crate) fn on_confirmed_rewind(st: &mut IbdWorkState, hub: &ChainHub, lca_h: u32) {
    if st.header_walk.base_hash.is_some() && lca_h < st.header_walk.base_height {
        st.header_walk = HeaderWalk::default();
        let _ = std::fs::remove_file(adopt_path(hub));
        return;
    }
    if hub.milestone.height == 0 || !st.header_walk.origin {
        return;
    }
    if lca_h < hub.milestone.height {
        if st.header_walk.tip.milestone_hash.take().is_some() {
            rbitcoin_log::warn!(
                "ibd: headers milestone dropped lca={lca_h} milestone={} script checks stay on until this chain records that block",
                hub.milestone.height
            );
            save_adopt(st, hub);
        }
        return;
    }
    let Some(hash) = st.header_walk.milestone_hash() else {
        return;
    };
    // An empty path means the confirmed chain is the source. Inserting only
    // this hash would hide every earlier block on that chain.
    if !hub.query.has_milestone_path() {
        return;
    }
    hub.query.note_milestone_header(
        hub.milestone.height,
        hash.to_byte_array(),
        [0u8; 32],
        Work::from_be_bytes([0u8; 32]),
        None,
    );
}

fn save_adopt(st: &IbdWorkState, hub: &ChainHub) {
    if !st.header_walk.origin {
        return;
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(ADOPT_MAGIC);
    let n = st.header_walk.checkpoints.len() as u32;
    buf.extend_from_slice(&n.to_le_bytes());
    for c in st.header_walk.checkpoints() {
        buf.extend_from_slice(c.hash.as_byte_array());
        buf.extend_from_slice(&c.height.to_le_bytes());
        buf.extend_from_slice(&c.work);
        write_header(&mut buf, c.header);
        write_times(&mut buf, &c.times);
        write_diff(&mut buf, &c.diff);
    }
    let milestone = st
        .header_walk
        .tip
        .milestone_hash
        .map(|h| *h.as_byte_array())
        .unwrap_or([0u8; 32]);
    buf.extend_from_slice(&milestone);
    let base = st
        .header_walk
        .base_hash
        .map(|h| *h.as_byte_array())
        .unwrap_or([0u8; 32]);
    buf.extend_from_slice(&base);
    buf.extend_from_slice(&st.header_walk.base_height.to_le_bytes());
    buf.extend_from_slice(&st.header_walk.base_work);
    write_header(&mut buf, st.header_walk.tip.header);
    buf.extend_from_slice(&st.header_walk.tip.diff.period_height.to_le_bytes());
    write_header(&mut buf, st.header_walk.tip.diff.period_header);
    buf.extend_from_slice(&st.header_walk.tip.diff.full_diff_height.to_le_bytes());
    let full_bits = st
        .header_walk
        .tip
        .diff
        .full_diff_bits
        .map(|b| b.to_consensus())
        .unwrap_or(0);
    buf.extend_from_slice(&full_bits.to_le_bytes());
    write_diff(&mut buf, &st.header_walk.base_diff);
    let path = adopt_path(hub);
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &buf).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Drop `header.adopt` once the confirmed chain itself proves the anchor.
/// Until then the file is how a restart turns the script skip back on.
pub(crate) fn retire_adopt_if_confirmed(st: &mut IbdWorkState, hub: &ChainHub) {
    if st.header_walk.adopt_retired {
        return;
    }
    let Some(anchor) = hub.milestone.anchor else {
        return;
    };
    if hub.milestone.height == 0 {
        return;
    }
    let tip_h = hub.tip_height().unwrap_or(0);
    if tip_h < hub.milestone.height {
        return;
    }
    let Ok(Some((_, rec))) = hub
        .query
        .header_at_height(rbitcoin_primitives::Height(hub.milestone.height))
    else {
        return;
    };
    if rec.hash != *anchor.hash.as_byte_array() {
        return;
    }
    let Ok(work) = hub.chain_work() else {
        return;
    };
    if work.to_be_bytes() < anchor.min_work_be {
        return;
    }
    st.header_walk.adopt_retired = true;
    // The confirmed chain already contains the anchor. Noting only that hash
    // into an empty path would hide the confirmed ancestors.
    if hub.query.has_milestone_path() {
        hub.query.note_milestone_header(
            hub.milestone.height,
            rec.hash,
            [0u8; 32],
            Work::from_be_bytes([0u8; 32]),
            None,
        );
    }
    hub.query
        .note_milestone_checkpoint_work(tip_h, work.to_be_bytes());
    let _ = std::fs::remove_file(adopt_path(hub));
}

/// Read `header.adopt`. A file that does not parse does not restore
/// checkpoints. Headers already queued and linked from the confirmed tip are
/// still noted on the milestone path.
pub(crate) fn restore_adopt(st: &mut IbdWorkState, hub: &ChainHub) -> bool {
    retire_adopt_if_confirmed(st, hub);
    let started = std::time::Instant::now();
    let path = adopt_path(hub);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            renote_stored_path(st, hub);
            return false;
        }
        Err(_) => {
            rbitcoin_log::info!("ibd: headers resume failed took={:?}", started.elapsed());
            renote_stored_path(st, hub);
            return false;
        }
    };
    let took = started.elapsed();
    let Some(parsed) = parse_adopt(&bytes) else {
        rbitcoin_log::info!("ibd: headers resume failed took={took:?}");
        renote_stored_path(st, hub);
        return false;
    };
    if base_conflicts(st, hub, &parsed) {
        rbitcoin_log::info!(
            "ibd: headers resume refused height={} took={took:?}",
            parsed.base_height
        );
        renote_stored_path(st, hub);
        return false;
    }
    st.header_walk = parsed;
    restore_tip_header(st, hub);
    renote_stored_path(st, hub);
    if let Some(hash) = st.header_walk.milestone_hash() {
        if hub.milestone.height > 0 {
            hub.query.note_milestone_header(
                hub.milestone.height,
                hash.to_byte_array(),
                [0u8; 32],
                Work::from_be_bytes([0u8; 32]),
                None,
            );
        }
    }
    publish_work(st, hub);
    let work = if st.header_walk.proven { "ok" } else { "below" };
    rbitcoin_log::info!(
        "ibd: headers resume height={} work={work} took={took:?}",
        st.header_walk.tip_height()
    );
    true
}

fn parse_adopt(bytes: &[u8]) -> Option<HeaderWalk> {
    if bytes.len() < 8 + 4 + 32 || &bytes[..8] != ADOPT_MAGIC {
        return None;
    }
    let n = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
    const CKPT: usize = 32 + 4 + 32 + 80 + 1 + 11 * 4 + DIFF_SNAP_LEN;
    let body = 12 + n * CKPT;
    const TAIL: usize = 32 + 32 + 4 + 32 + 80 + 4 + 80 + 4 + 4 + DIFF_SNAP_LEN;
    if bytes.len() != body + TAIL {
        return None;
    }
    let mut checkpoints = Vec::with_capacity(n);
    let mut off = 12;
    for _ in 0..n {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let height = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
        off += 4;
        let mut work = [0u8; 32];
        work.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let header = read_header(&bytes[off..off + 80]);
        off += 80;
        let times = read_times(&bytes[off..off + 1 + 11 * 4])?;
        off += 1 + 11 * 4;
        let diff = read_diff(&bytes[off..off + DIFF_SNAP_LEN])?;
        off += DIFF_SNAP_LEN;
        checkpoints.push(Checkpoint {
            hash: BlockHash::from_byte_array(hash),
            height,
            work,
            header,
            times,
            diff,
        });
    }
    let mut milestone = [0u8; 32];
    milestone.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let milestone_hash = (milestone != [0u8; 32]).then_some(BlockHash::from_byte_array(milestone));
    let mut base = [0u8; 32];
    base.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let base_height = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
    off += 4;
    let mut base_work = [0u8; 32];
    base_work.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let tip_header = read_header(&bytes[off..off + 80]);
    off += 80;
    let period_height = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
    off += 4;
    let period_header = read_header(&bytes[off..off + 80]);
    off += 80;
    let full_diff_height = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
    off += 4;
    let full_bits = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
    off += 4;
    let full_diff_bits = (full_bits != 0).then_some(CompactTarget::from_consensus(full_bits));
    let base_diff = read_diff(&bytes[off..off + DIFF_SNAP_LEN])?;
    let (hash, height, work) = match checkpoints.last() {
        Some(c) => (Some(c.hash), c.height, c.work),
        None => (None, 0, [0u8; 32]),
    };
    Some(HeaderWalk {
        checkpoints,
        base_hash: (base != [0u8; 32]).then_some(BlockHash::from_byte_array(base)),
        base_height,
        base_work,
        tip: WalkTip {
            hash,
            height,
            work: Work::from_be_bytes(work),
            header: tip_header,
            times: Vec::new(),
            diff: DiffSnap {
                period_header,
                period_height,
                full_diff_bits,
                full_diff_height,
            },
            milestone_hash,
            milestone_prev: BlockHash::from_byte_array([0; 32]),
            milestone_header: None,
        },
        origin: true,
        dead_ends: HashSet::new(),
        emptied: HashSet::new(),
        proven: false,
        off_path: std::collections::HashMap::new(),
        #[cfg(test)]
        announced_done: false,
        walk_quiet: HashSet::new(),
        reserved: None,
        challenge: None,
        challenge_external: false,
        challenge_open: None,
        walk: Lane::default(),
        header_misses: HashMap::new(),
        base_diff,
        challenger: None,
        adopt_retired: false,
    })
}

const TIMES_SLOTS: usize = 11;

fn write_times(buf: &mut Vec<u8>, times: &[u32]) {
    let n = times.len().min(TIMES_SLOTS);
    let start = times.len().saturating_sub(TIMES_SLOTS);
    buf.push(n as u8);
    for i in 0..TIMES_SLOTS {
        let t = times.get(start + i).copied().unwrap_or(0);
        buf.extend_from_slice(&t.to_le_bytes());
    }
}

fn read_times(bytes: &[u8]) -> Option<Vec<u32>> {
    if bytes.len() < 1 + TIMES_SLOTS * 4 {
        return None;
    }
    let n = bytes[0] as usize;
    if n > TIMES_SLOTS {
        return None;
    }
    let mut times = Vec::with_capacity(n);
    for i in 0..n {
        let off = 1 + i * 4;
        times.push(u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?));
    }
    Some(times)
}

/// Below the milestone work floor, more than this many stored headers that are
/// not on the download path disconnects the peer.
const OFF_PATH_HEADER_BUDGET: u32 = 4_000;

/// Count one stored header that is not on the download path. True when the
/// peer is over the budget and still below the work floor.
pub(crate) fn note_off_path(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    hash: BlockHash,
) -> bool {
    if hub.milestone.anchor.is_none() {
        return false;
    }
    if st.header_walk.proven && !below_floor(hub, &st.header_walk.tip_work()) {
        return false;
    }
    let seen = st.header_walk.off_path.entry(peer).or_default();
    if seen.len() > OFF_PATH_HEADER_BUDGET as usize {
        return true;
    }
    if !seen.insert(hash) {
        return false;
    }
    seen.len() > OFF_PATH_HEADER_BUDGET as usize
}

/// Note stored work-path headers on the milestone map.
///
/// Restart restores the anchor before the resume seed fills this map, so
/// the seed calls this again. A height that links from the confirmed tip is
/// on the path that reached the anchor.
pub(crate) fn renote_stored_path(st: &IbdWorkState, hub: &ChainHub) {
    let mut height = hub.tip_height().unwrap_or(0);
    let mut prev = hub.tip_hash();
    while let Some(next_h) = height.checked_add(1) {
        let Some(next) = st.height_to_hash.get(&next_h).copied() else {
            break;
        };
        let Some(hdr) = hub.header_of(&next) else {
            break;
        };
        if prev.is_some_and(|p| hdr.prev_blockhash != p) {
            break;
        }
        let base = if hub.tip_hash() == prev {
            hub.chain_work().ok()
        } else {
            None
        };
        hub.query.note_milestone_header(
            next_h,
            next.to_byte_array(),
            hdr.prev_blockhash.to_byte_array(),
            hdr.work(),
            base,
        );
        height = next_h;
        prev = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibd::events::apply_peer_event;
    use crate::ibd::peer_io::{solicit_track, PeerCmd, PeerEvent, PeerSlot};
    use crate::ibd::state::IbdWorkState;
    use crate::seeds::AddrMan;
    use bitcoin::block::Header;
    use bitcoin::CompactTarget;
    use bitcoin::TxMerkleNode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, AtomicU64};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn mine(prev: BlockHash, n: u32) -> Header {
        let mut h = Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
            time: 1_600_000_000 + n,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    }

    fn slot(id: usize) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
        let (cmd_tx, rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, id as u8)), 8333);
        (
            PeerSlot {
                id,
                addr,
                net: crate::NetAddr::from_socket(addr),
                cmd_tx,
                in_flight: Default::default(),
                requested: solicit_track().0,
                solicited_bytes: solicit_track().1,
                solicited_ms: solicit_track().2,
                any_rx_ms: Arc::new(AtomicU64::new(0)),
                getdata_wire: crate::ibd::peer_io::GetdataWire::new(),
                peer_height: 50_000,
                connected_ms: 1,
                first_data_ms: 0,
                bytes_rx_total: Arc::new(AtomicU64::new(0)),
                rate: Default::default(),
                alive: true,
                task,
            },
            rx,
        )
    }

    fn fill_queue(st: &mut IbdWorkState) {
        for i in 0..ORDERED_HEADERS_SOFT_CAP {
            let mut b = [0u8; 32];
            b[28..32].copy_from_slice(&(i as u32).to_le_bytes());
            let h = BlockHash::from_byte_array(b);
            st.ordered.push_back(h);
            st.ordered_set.insert(h);
        }
    }

    #[test]
    fn follow_session_inv_pokes_a_live_header_peer() {
        let (s0, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], None, None);
        assert!(note_external_block_inv(&mut st));
        assert_eq!(st.header_walk.challenge, Some(0));
        st.slots[0].alive = false;
        st.header_walk.challenge = None;
        assert!(!note_external_block_inv(&mut st));
    }

    fn apply(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, headers: Vec<Header>) {
        apply_peer_event(
            st,
            hub,
            PeerEvent::Headers { peer, headers },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
    }

    fn blocks_inv(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, hashes: Vec<BlockHash>) {
        apply_peer_event(
            st,
            hub,
            PeerEvent::BlocksInv { peer, hashes },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
    }

    fn plant_on_queue(st: &mut IbdWorkState, hash: BlockHash, height: u32) {
        let old = st.ordered.pop_back().unwrap();
        st.ordered_set.remove(&old);
        st.ordered.push_back(hash);
        st.ordered_set.insert(hash);
        st.hash_height.insert(hash, height);
    }

    #[test]
    fn full_queue_checkpoints_lookahead_and_refill_stores_the_successor() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-1");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(
            !st.header_walk.has_checkpoints(),
            "a walk with no replies has no checkpoints"
        );
        let before = hub.query.store().header_count();
        log_status(&mut st, &hub, 50_000);
        assert!(
            !st.header_walk.announced_done,
            "the status line stays quiet until the walk has a candidate"
        );

        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![good]);
        assert_eq!(
            hub.query.store().header_count(),
            before + 1,
            "an accepted batch is written even when the queue is full"
        );
        assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);
        assert_eq!(st.header_walk.checkpoints().len(), 1);
        assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
        assert!(wants_lookahead(&st));
        log_status(&mut st, &hub, 50_000);
        assert!(
            !st.header_walk.announced_done,
            "peers still advertise headers past the candidate"
        );
        let tip = st.header_walk.tip_height();
        st.max_peer_height = tip;
        log_status(&mut st, &hub, tip);
        assert!(
            !st.header_walk.announced_done,
            "advertised height alone does not end the walk"
        );
        st.slots[0].peer_height = tip;
        log_status(&mut st, &hub, tip);
        assert!(
            st.header_walk.announced_done,
            "the done line fires once no connected peer is ahead of the walk"
        );
        log_status(&mut st, &hub, tip);
        assert!(st.header_walk.announced_done);
    }

    #[test]
    fn a_taller_peer_that_cannot_extend_the_candidate_leaves_the_walk() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-quiet");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (mut tall, mut rx) = slot(0);
        tall.peer_height = 100_000;
        let mut st = IbdWorkState::new(vec![tall], Some(gen), Some(0));
        // A full queue still asks while a peer is ahead and the next header
        // is not indexed.
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![good]);
        assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
        assert!(
            wants_lookahead(&st),
            "an advertisement past the walk keeps the lane on"
        );

        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![]);
        assert!(
            !wants_lookahead(&st),
            "one empty reply from a taller peer ends the walk"
        );
        assert!(
            rx.try_recv().is_err(),
            "the walk does not ask that peer again"
        );
        log_status(&mut st, &hub, 100_000);
        assert!(st.header_walk.announced_done);

        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 0,
                hashes: vec![good.block_hash()],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert!(
            wants_lookahead(&st),
            "a later block announcement puts the peer back on the walk"
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })));

        apply(&mut st, &hub, 0, vec![]);
        assert!(!wants_lookahead(&st));
        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::Dead {
                peer: 0,
                reason: "drop".into(),
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        st.slots[0].alive = true;
        assert!(
            wants_lookahead(&st),
            "a redialed peer is a candidate until they fail once"
        );
    }

    #[test]
    fn a_short_lighter_fork_does_not_keep_the_walk_asking() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-light");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let fork = mine(gen, 2);
        let (mut tall, mut rx) = slot(0);
        tall.peer_height = 100_000;
        let mut st = IbdWorkState::new(vec![tall], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![good]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![fork]);
        assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
        assert!(
            !wants_lookahead(&st),
            "a short fork that does not beat the candidate ends the walk"
        );
        assert!(rx.try_recv().is_err());
    }

    /// One peer advertised a height no chain has. Once the walk is at the
    /// confirmed tip and that peer cannot extend it, IBD is caught up.
    #[test]
    fn a_false_peer_height_does_not_hold_ibd_at_the_tip() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-exit");
        hub.ensure_genesis().unwrap();
        let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(2, op_true.clone(), vec![]).unwrap();
        let time = hub.tip_header().unwrap().time + 1;
        let third = rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            3,
            op_true.clone(),
            vec![],
        );
        let third_hash = third.block_hash();
        let fourth =
            rbitcoin_consensus::mine_regtest_paying(third_hash, time + 1, 4, op_true, vec![]);
        let (mut liar, mut liar_rx) = slot(0);
        liar.peer_height = 100_000;
        let (mut honest, mut honest_rx) = slot(1);
        honest.peer_height = 2;
        let mut st = IbdWorkState::new(vec![liar, honest], hub.tip_hash(), Some(2));
        assert_eq!(st.max_peer_height, 100_000);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut liar_rx), 1);
        assert_eq!(
            peer_horizon(&st),
            100_000,
            "a peer still on the walk sets the progress horizon"
        );
        apply(&mut st, &hub, 0, vec![third.header]);
        assert_eq!(st.header_walk.tip_height(), 3);
        hub.accept_block(third).unwrap();
        assert_eq!(hub.tip_height(), Some(3));
        assert!(
            !crate::ibd::exit::ibd_caught_up(&st, 3),
            "the advertised height is still a candidate"
        );

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut liar_rx), 1);
        apply(&mut st, &hub, 0, vec![]);
        assert!(!wants_lookahead(&st));
        st.ordered.clear();
        st.ordered_set.clear();
        assert!(
            crate::ibd::exit::ibd_caught_up(&st, 3),
            "no peer can extend the walk past the confirmed tip"
        );
        assert_eq!(st.max_peer_height, 100_000);
        assert_eq!(
            peer_horizon(&st),
            3,
            "a retired peer's advertised height leaves the progress horizon"
        );

        // The honest peer's start height is below the walk. A block inv is
        // still a header it has and we do not.
        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 1,
                hashes: vec![fourth.block_hash()],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        match honest_rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert_eq!(locator[0], third_hash, "the ask starts at the walk tip");
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("the announcing peer was not asked for headers"),
        }
        assert_eq!(drain_getheaders(&mut liar_rx), 0);
        apply(&mut st, &hub, 1, vec![fourth.header]);
        assert_eq!(st.header_walk.tip_height(), 4);
        assert_eq!(peer_horizon(&st), 4);
        assert!(st.ordered_set.contains(&fourth.block_hash()));
        assert!(
            !crate::ibd::exit::ibd_caught_up(&st, 3),
            "the announced block is still owed"
        );
    }

    /// Restart on a validated tip. No new checkpoint has been built, and one
    /// peer advertises a height no chain has. IBD is caught up once that
    /// peer fails to extend the stored tip.
    #[test]
    fn a_restarted_tip_exits_once_the_false_height_fails() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-restart-tip");
        hub.ensure_genesis().unwrap();
        let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(2, op_true, vec![]).unwrap();
        let tip = hub.tip_height().unwrap();
        let (mut liar, mut liar_rx) = slot(0);
        liar.peer_height = 100_000;
        let (mut honest, _honest_rx) = slot(1);
        honest.peer_height = tip;
        let mut st = IbdWorkState::new(vec![liar, honest], hub.tip_hash(), Some(tip));
        assert_eq!(st.max_peer_height, 100_000);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut liar_rx), 1);
        assert!(
            !crate::ibd::exit::ibd_caught_up(&st, tip),
            "the advertised height is still a candidate"
        );
        apply(&mut st, &hub, 0, vec![]);
        assert!(!wants_lookahead(&st));
        assert!(st.ordered.is_empty());
        assert!(
            crate::ibd::exit::ibd_caught_up(&st, tip),
            "the stored tip is caught up once no peer can extend it"
        );
        assert_eq!(st.max_peer_height, 100_000);
    }

    /// A block found after connect is written from the announcing peer.
    /// That peer's `version.start_height` is still the old tip, so nobody
    /// looks taller than the stored path. The one ask still goes to them.
    #[test]
    fn block_inv_writes_the_next_header_from_the_stored_tip() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-refill-at-tip");
        hub.ensure_genesis().unwrap();
        let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(2, op_true.clone(), vec![]).unwrap();
        let tip = hub.tip_height().unwrap();
        let tip_hash = hub.tip_hash().unwrap();
        let time = hub.tip_header().unwrap().time + 1;
        let next = rbitcoin_consensus::mine_regtest_paying(tip_hash, time, 3, op_true, vec![]);
        let (mut liar, mut liar_rx) = slot(0);
        liar.peer_height = 100_000;
        let (mut honest, mut honest_rx) = slot(1);
        honest.peer_height = tip;
        let mut st = IbdWorkState::new(vec![liar, honest], Some(tip_hash), Some(tip));

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut liar_rx), 1);
        apply(&mut st, &hub, 0, vec![]);
        assert!(!wants_lookahead(&st));

        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 1,
                hashes: vec![next.block_hash()],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        match honest_rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert_eq!(locator[0], tip_hash, "the ask starts at the stored tip");
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("the peer at the stored tip was not asked"),
        }
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 1, vec![next.header]);
        assert_eq!(st.header_walk.tip_height(), tip + 1);
        assert!(st.ordered_set.contains(&next.block_hash()));
        assert!(hub.query.store().header_count() > before);
        assert_eq!(drain_getheaders(&mut liar_rx), 0);
        assert!(
            !send_getheaders(&mut st, &hub).unwrap(),
            "the written header is not asked for again"
        );
        assert!(!crate::ibd::exit::ibd_caught_up(&st, tip));
    }

    /// The header peer's connect-time height is the walk tip and the queue
    /// is full. Their block inv is still a getheaders, on this poll.
    #[test]
    fn a_reserved_peer_block_inv_is_asked_with_a_full_queue() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-reserved-inv");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (mut peer, mut rx) = slot(0);
        peer.peer_height = 100;
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut rx), 1);
        let _ = take_header_ask(&mut st, 0);
        assert_eq!(st.header_walk.reserved, Some(0));
        st.header_walk.tip.height = 100;
        assert!(
            !wants_lookahead(&st),
            "connect-time height is not past the walk"
        );
        assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);

        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 0,
                hashes: vec![BlockHash::from_byte_array([7u8; 32])],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert_eq!(
            st.header_walk.challenge,
            Some(0),
            "the reserved header peer's inv is still a challenge"
        );
        assert!(
            matches!(
                header_poll(
                    &st,
                    HeaderPollIn {
                        live: st.ordered_set.len(),
                        need_ready_headroom: false,
                        lag: 0,
                        min_cache: 8192,
                        fan: 0,
                    },
                ),
                HeaderPoll::Ask
            ),
            "a full queue does not hold the announced header"
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(
            matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })),
            "the announcing peer was asked for headers"
        );
    }

    /// One ask from the stored tip. An accepted batch is written and
    /// checkpointed. A header already indexed is appended and not asked for.
    /// On that same hub, a second ask at one confirmed tip reuses the
    /// confirmed-chain tail. A same-height tip hash, then a taller tip, each
    /// rebuild it.
    #[test]
    fn a_seeded_header_walk_stores_drains_and_refills() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-seeded");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let first = mine(gen, 1);
        let second = mine(first.block_hash(), 2);

        let (s0, mut rx0) = slot(0);
        let (s1, mut rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(
            st.header_walk.origin,
            "the first ask starts the walk at the stored tip"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        rbitcoin_log::capture_logs(true);
        log_status(&mut st, &hub, 50_000);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            logs.iter()
                .any(|(_, line)| line.contains("ibd: headers height=")),
            "the status line starts with the stored tip"
        );
        let asked = st.header_walk.walk.peer.expect("walk lane");
        let front = if asked == 0 {
            locator_front(&mut rx0)
        } else {
            locator_front(&mut rx1)
        };
        assert_eq!(front, Some(gen), "the first locator is the stored tip");
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, asked, vec![first, second]);
        assert!(
            hub.query.store().header_count() > before,
            "an accepted batch is written"
        );
        assert!(st.ordered_set.contains(&second.block_hash()));
        assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));

        st.ordered.clear();
        st.ordered_set.clear();
        st.ordered.push_back(gen);
        st.ordered_set.insert(gen);
        st.hash_height.insert(gen, 0);
        st.height_to_hash.remove(&1);
        st.height_to_hash.remove(&2);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let ask = st.header_walk.walk.peer.expect("one ask");
        let front = if ask == 0 {
            locator_front(&mut rx0)
        } else {
            locator_front(&mut rx1)
        };
        assert_eq!(
            front,
            Some(gen),
            "a missing next header is asked from the stored tip, not the walk"
        );
        let other = if ask == 0 {
            rx1.try_recv()
        } else {
            rx0.try_recv()
        };
        assert!(other.is_err(), "a second peer is not asked in parallel");

        let _ = take_header_ask(&mut st, ask);
        let stored = BlockHash::from_byte_array([0x44; 32]);
        st.height_to_hash.insert(1, stored);
        st.hash_height.insert(stored, 1);
        st.height_to_hash.insert(2, second.block_hash());
        st.hash_height.insert(second.block_hash(), 2);
        st.slots[0].peer_height = st.header_walk.tip_height();
        st.slots[1].peer_height = st.header_walk.tip_height();
        assert!(!send_getheaders(&mut st, &hub).unwrap());
        assert!(st.ordered_set.contains(&stored));
        assert!(st.ordered_set.contains(&second.block_hash()));
        assert!(rx0.try_recv().is_err());
        assert!(rx1.try_recv().is_err());
        confirmed_tail_follows_the_published_tip(&hub);
    }

    /// Same hub as the seeded walk. Two asks share one confirmed tail. A
    /// same-height hash, then a taller tip, each rebuild it.
    fn confirmed_tail_follows_the_published_tip(hub: &ChainHub) {
        let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(2, script.clone(), vec![]).unwrap();
        let tip = hub.tip_hash().unwrap();
        let tip_h = hub.tip_height().unwrap();
        let genesis = hub.params.genesis_hash;
        let ancestor = hub
            .query
            .locator_hashes()
            .unwrap()
            .into_iter()
            .find(|hash| *hash != tip && *hash != genesis)
            .expect("the confirmed chain locator has an ancestor between tip and genesis");
        let (peer, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(tip), Some(tip_h));
        let ahead = BlockHash::from_byte_array([0xab; 32]);
        st.ordered.push_back(ahead);
        st.ordered_set.insert(ahead);
        st.hash_height.insert(ahead, tip_h.saturating_add(100));
        assert!(st.ordered.len() < ORDERED_HEADERS_SOFT_CAP);
        assert!(send_getheaders(&mut st, hub).unwrap());
        let first = take_locator(&mut rx);
        assert_eq!(
            first.first().copied(),
            Some(ahead),
            "a queue with room asks from the stored path tip"
        );
        assert!(
            first.contains(&ancestor),
            "the confirmed ancestor stays in the locator"
        );
        assert!(first.contains(&tip));
        same_tip_reuses_the_tail(&mut st, hub, &mut rx, &first);
        let same_h_tip = same_height_rebuilds_the_tail(&mut st, hub, &mut rx, tip, tip_h, ahead);
        taller_tip_rebuilds_the_tail(&mut st, hub, &mut rx, &script, same_h_tip, ahead);
    }

    fn same_tip_reuses_the_tail(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
        first: &[BlockHash],
    ) {
        assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
        let before = rbitcoin_query::header_lookup_count();
        assert!(send_getheaders(st, hub).unwrap());
        let second_ask = take_locator(rx);
        assert_eq!(
            rbitcoin_query::header_lookup_count().saturating_sub(before),
            0,
            "a second ask at the same confirmed tip does not walk the header store"
        );
        assert_eq!(second_ask, first);
    }

    fn same_height_rebuilds_the_tail(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
        tip: BlockHash,
        tip_h: u32,
        ahead: BlockHash,
    ) -> BlockHash {
        hub.invalidate_block(tip).unwrap();
        assert_eq!(hub.tip_height(), Some(tip_h - 1));
        let alt_script = bitcoin::ScriptBuf::from_bytes(vec![0x52]);
        hub.generate_to_script(1, alt_script, vec![]).unwrap();
        let same_h_tip = hub.tip_hash().unwrap();
        let published = hub.query.published_tip().expect("published tip");
        assert_eq!(hub.tip_height(), Some(tip_h));
        assert_eq!(published.height, tip_h);
        assert_eq!(published.hash, same_h_tip.to_byte_array());
        assert_ne!(same_h_tip, tip);
        assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
        let before = rbitcoin_query::header_lookup_count();
        assert!(send_getheaders(st, hub).unwrap());
        let reorged = take_locator(rx);
        assert!(
            rbitcoin_query::header_lookup_count() > before,
            "a same-height tip hash rebuilds the tail"
        );
        assert_eq!(reorged.first().copied(), Some(ahead));
        assert!(
            reorged.contains(&same_h_tip),
            "the rebuilt tail names the replacement tip"
        );
        let tail = st
            .confirmed_locator_tail
            .as_ref()
            .expect("the same-height ask stored a tail");
        assert_eq!(tail.height, Some(tip_h));
        assert_eq!(tail.hash, Some(*same_h_tip.as_byte_array()));
        assert!(tail.hashes.contains(&same_h_tip));
        assert!(
            !tail.hashes.contains(&tip),
            "the replaced tip hash leaves the confirmed tail"
        );
        same_h_tip
    }

    fn taller_tip_rebuilds_the_tail(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
        script: &bitcoin::ScriptBuf,
        same_h_tip: BlockHash,
        ahead: BlockHash,
    ) {
        hub.generate_to_script(1, script.clone(), vec![]).unwrap();
        let new_tip = hub.tip_hash().unwrap();
        assert_ne!(new_tip, same_h_tip);
        assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
        let before = rbitcoin_query::header_lookup_count();
        assert!(send_getheaders(st, hub).unwrap());
        let taller = take_locator(rx);
        assert!(
            rbitcoin_query::header_lookup_count() > before,
            "a changed confirmed tip rebuilds the tail"
        );
        assert_eq!(taller.first().copied(), Some(ahead));
        assert!(
            taller.contains(&new_tip),
            "the rebuilt tail names the new confirmed tip"
        );
    }

    fn locator_front(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Option<BlockHash> {
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => locator.first().copied(),
            _ => None,
        }
    }

    fn shrink_queue(st: &mut IbdWorkState, keep: usize) {
        while st.ordered.len() > keep {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
    }

    fn take_locator(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Vec<BlockHash> {
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => locator,
            _ => panic!("expected one getheaders"),
        }
    }

    /// Walk tip is `first` (height 1). Queue tail height is 0, so the walk is ahead.
    fn walk_ahead_of_a_short_queue(
        label: &str,
        keep: usize,
        peers: usize,
    ) -> (
        rbitcoin_query::testutil::TempDir,
        ChainHub,
        IbdWorkState,
        Vec<mpsc::UnboundedReceiver<PeerCmd>>,
        Header,
        BlockHash,
    ) {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled(label);
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let first = mine(gen, 1);
        let mut rxs = Vec::new();
        let mut slots = Vec::new();
        for id in 0..peers {
            let (slot_i, rx) = slot(id);
            slots.push(slot_i);
            rxs.push(rx);
        }
        let mut st = IbdWorkState::new(slots, Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        for rx in &mut rxs {
            let _ = rx.try_recv();
        }
        apply(&mut st, &hub, 0, vec![first]);
        shrink_queue(&mut st, keep);
        let tail = st.ordered.back().copied().unwrap();
        st.hash_height.insert(tail, 0);
        (dir, hub, st, rxs, first, tail)
    }

    #[test]
    fn empty_queue_reseeds_stored_path_before_the_tip() {
        let (_dir, hub, mut st, mut rxs, first, _tail) =
            walk_ahead_of_a_short_queue("header-walk-reseed", 1, 2);
        let second = mine(first.block_hash(), 2);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        for rx in &mut rxs {
            let _ = rx.try_recv();
        }
        apply(&mut st, &hub, 0, vec![second]);
        assert_eq!(st.header_walk.tip_height(), 2);
        st.ordered.clear();
        st.ordered_set.clear();
        let stored = BlockHash::from_byte_array([0x44; 32]);
        st.height_to_hash.insert(1, stored);
        st.hash_height.insert(stored, 1);
        st.height_to_hash.remove(&2);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(
            st.ordered_set.contains(&stored),
            "headers still on the work path go back on the queue"
        );
        let mut fronts = Vec::new();
        for rx in &mut rxs {
            if let Some(h) = locator_front(rx) {
                fronts.push(h);
            }
        }
        assert!(
            fronts.contains(&stored),
            "the ask starts at the stored tip so the missing header can be queued: {fronts:?}"
        );
    }

    #[test]
    fn missing_next_header_asks_from_the_stored_tip() {
        let (_dir, hub, mut st, mut rxs, first, tail) =
            walk_ahead_of_a_short_queue("header-walk-missing", 20_000, 1);
        st.height_to_hash.remove(&1);
        assert_ne!(tail, first.block_hash());
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(
            locator_front(&mut rxs[0]),
            Some(tail),
            "a missing next header is asked from the stored tip, not the walk"
        );
    }

    #[test]
    fn indexed_next_header_is_appended_without_an_ask() {
        let (_dir, hub, mut st, mut rxs, first, _tail) =
            walk_ahead_of_a_short_queue("header-walk-indexed", 100, 1);
        st.slots[0].peer_height = st.header_walk.tip_height();
        assert!(!send_getheaders(&mut st, &hub).unwrap());
        assert!(st.ordered_set.contains(&first.block_hash()));
        assert!(rxs[0].try_recv().is_err());
    }

    #[test]
    fn caught_up_walk_reply_is_stored() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-caught");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let first = mine(gen, 1);
        let second = mine(first.block_hash(), 2);
        let (slot0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![slot0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![first]);
        assert_eq!(st.header_walk.tip_hash(), Some(first.block_hash()));

        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        let before = hub.query.store().header_count();
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let queued = st.ordered.len();
        apply(&mut st, &hub, 0, vec![second]);
        assert!(
            hub.query.store().header_count() > before,
            "a reply that continues the stored walk tip is written"
        );
        assert!(st.ordered.len() > queued);
        assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));
    }

    #[test]
    fn status_line_names_the_stored_height_and_the_queue() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-status");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let first = mine(gen, 1);
        let (slot0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![slot0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![first]);
        let tail = st.ordered.back().copied().unwrap();
        st.hash_height.insert(tail, 76_000);
        rbitcoin_log::capture_logs(true);
        log_status(&mut st, &hub, 200_000);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let line = logs
            .iter()
            .find_map(|(_, line)| line.contains("ibd: headers height=").then_some(line))
            .expect("status line");
        assert!(
            line.contains("stored=76000"),
            "the stored path is on the status line: {line}"
        );
        assert!(
            line.contains(&format!("queue={}", ORDERED_HEADERS_SOFT_CAP)),
            "the queue length is on the status line: {line}"
        );
        assert!(line.contains("phase=walk"), "{line}");
    }

    #[test]
    fn short_chain_rewinds_and_the_next_peer_is_followed() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-2");
        hub.ensure_genesis().unwrap();
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 840_000,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: BlockHash::from_byte_array([0xab; 32]),
                min_work_be: [0xff; 32],
            }),
        };
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let b1 = mine(gen, 11);
        let b2 = mine(b1.block_hash(), 12);
        let b3 = mine(b2.block_hash(), 13);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        let before = hub.query.store().header_count();

        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1, a2]);
        assert_eq!(hub.query.store().header_count(), before + 2);
        log_status(&mut st, &hub, 50_000);
        assert!(!st.header_walk.proven, "work is still below the floor");
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        plant_on_queue(&mut st, a1.block_hash(), 1);
        plant_on_queue(&mut st, a2.block_hash(), 2);

        apply(&mut st, &hub, 0, vec![]);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(a2.block_hash()),
            "one peer's empty does not abandon the candidate"
        );
        apply(&mut st, &hub, 1, vec![]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        log_status(&mut st, &hub, 50_000);
        assert!(!st.header_walk.announced_done);
        assert!(!st.ordered_set.contains(&a1.block_hash()));
        assert!(!st.ordered_set.contains(&a2.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(a1.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert!(hub
            .query
            .get_header_by_hash(a2.block_hash().as_byte_array())
            .unwrap()
            .is_some());

        while st.ordered.len() > 10 {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
        apply(&mut st, &hub, 1, vec![b1, b2, b3]);
        assert_eq!(st.header_walk.tip_hash(), Some(b3.block_hash()));
        assert!(st.ordered_set.contains(&b3.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(a2.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert_eq!(hub.query.store().header_count(), before + 5);
    }

    fn skips(hub: &ChainHub, height: u32, hash: &[u8; 32]) -> bool {
        hub.milestone
            .skips_scripts(height, hash, |h| hub.query.milestone_header_at(h))
    }

    fn fill_to_cap(st: &mut IbdWorkState) {
        let mut i = st.ordered.len();
        while st.ordered.len() < ORDERED_HEADERS_SOFT_CAP {
            let mut b = [0xee; 32];
            b[28..32].copy_from_slice(&(i as u32).to_le_bytes());
            let h = BlockHash::from_byte_array(b);
            st.ordered.push_back(h);
            st.ordered_set.insert(h);
            i += 1;
        }
    }

    #[test]
    fn milestone_checkpoint_opens_script_skip_without_the_lookahead_headers() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-3");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![h1]);
        let after_queue = hub.query.store().header_count();
        fill_to_cap(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h2, h3]);

        assert_eq!(
            hub.query.store().header_count(),
            after_queue + 2,
            "an accepted batch is written"
        );
        assert!(hub
            .query
            .get_header_by_hash(h2.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert!(st.ordered_set.contains(&h1.block_hash()));
        assert!(
            skips(&hub, 1, h1.block_hash().as_byte_array()),
            "the queued block skips when the checkpoint hash is the anchor"
        );
        assert!(!skips(&hub, 1, &[0x44; 32]));
        assert!(
            !skips(&hub, 2, &[0x55; 32]),
            "a different hash at the milestone height does not skip"
        );
    }

    #[test]
    // btc-lean: INV-147
    fn heavier_chain_replaces_checkpoints_and_a_cheap_fork_is_not_stored() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-4");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let c2 = mine(a1.block_hash(), 21);
        let c3 = mine(c2.block_hash(), 22);
        let c4 = mine(c3.block_hash(), 23);
        let c5 = mine(c4.block_hash(), 24);
        let light = mine(gen, 31);
        let less = mine(a1.block_hash(), 41);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: a2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![a1]);
        fill_to_cap(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        plant_on_queue(&mut st, a2.block_hash(), 2);
        let before = hub.query.store().header_count();
        hub.set_minimum_chain_work(Some([0xff; 32]));

        apply(&mut st, &hub, 0, vec![c2, c3, c4, c5]);
        assert_eq!(st.header_walk.tip_hash(), Some(c5.block_hash()));
        assert!(!st.ordered_set.contains(&a2.block_hash()));
        assert_eq!(hub.query.store().header_count(), before + 4);
        assert!(st.ordered_set.contains(&c5.block_hash()));

        let after_heavy = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![light]);
        apply(&mut st, &hub, 0, vec![less]);
        assert_eq!(hub.query.store().header_count(), after_heavy);
        assert_eq!(st.header_walk.tip_hash(), Some(c5.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(light.block_hash().as_byte_array())
            .unwrap()
            .is_none());
        assert!(hub
            .query
            .get_header_by_hash(less.block_hash().as_byte_array())
            .unwrap()
            .is_none());
        assert!(hub
            .query
            .get_header_by_hash(a2.block_hash().as_byte_array())
            .unwrap()
            .is_some());
    }

    #[test]
    fn queue_stores_a_reply_that_ends_on_the_checkpoint() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-5");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let later = mine(good.block_hash(), 2);
        let miss = mine(gen, 9);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        let before = hub.query.store().header_count();
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![good, later]);
        assert_eq!(hub.query.store().header_count(), before + 2);
        assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

        st.ordered.clear();
        st.ordered_set.clear();
        st.height_to_hash.remove(&1);
        st.height_to_hash.remove(&2);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert_eq!(
                    locator[0], gen,
                    "an empty queue asks for the headers after the stored tip"
                );
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("peer was not asked for headers"),
        }
        apply(&mut st, &hub, 0, vec![good]);
        assert!(
            st.ordered_set.contains(&good.block_hash()),
            "a header short of the next checkpoint still fills the queue"
        );
        assert_eq!(hub.query.store().header_count(), before + 2);

        let after = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![miss]);
        assert_eq!(hub.query.store().header_count(), after);
        assert!(
            !st.header_walk.dead_ends.contains(&miss.block_hash()),
            "a lighter valid chain stays available for a later heavier extension"
        );
        assert!(st.slots[0].alive);
        assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(miss.block_hash().as_byte_array())
            .unwrap()
            .is_none());
    }

    /// A connected peer's start height is not a hole once the walk is proved
    /// at the confirmed tip. A proved walk that is still above that tip is.
    #[test]
    fn proved_walk_at_the_tip_ignores_a_tall_peer() {
        let (s0, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], None, Some(100));
        st.max_peer_height = 50_000;
        st.headers_done = true;
        st.header_walk.prove_through(100);
        assert!(
            !super::super::exit::should_unlatch_headers_done(&st, 100),
            "a proved walk at the confirmed tip does not chase a connected peer"
        );
        st.header_walk.prove_through(150);
        assert!(
            super::super::exit::should_unlatch_headers_done(&st, 100),
            "a proved walk above the confirmed tip still opens an empty queue"
        );
    }

    /// A batch that misses the checkpoint must not occupy the gap, and a
    /// later batch that meets it must replace a short unproved queue.
    #[test]
    fn an_unproved_queue_does_not_hide_the_checkpoint() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-unproved");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let later = mine(good.block_hash(), 2);
        let miss = mine(gen, 9);
        let miss2 = mine(miss.block_hash(), 8);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![good, later]);
        assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

        st.ordered.clear();
        st.ordered_set.clear();
        st.height_to_hash.remove(&1);
        st.height_to_hash.remove(&2);

        apply(&mut st, &hub, 0, vec![miss, miss2]);
        assert!(
            !st.ordered_set.contains(&miss.block_hash()),
            "a window that misses the checkpoint must not occupy the gap"
        );
        assert!(!st.ordered_set.contains(&miss2.block_hash()));
        assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

        apply(&mut st, &hub, 0, vec![miss]);
        assert!(
            st.ordered_set.contains(&miss.block_hash()),
            "a short refill still fills the queue before the next checkpoint"
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert!(
                    locator.contains(&gen),
                    "a peer that lacks the unproved tail must still be asked from the stored tip"
                );
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("peer was not asked for headers"),
        }
        apply(&mut st, &hub, 0, vec![good, later]);
        assert!(
            st.ordered_set.contains(&good.block_hash()),
            "a batch that meets the checkpoint replaces the unproved queue"
        );
        assert!(!st.ordered_set.contains(&miss.block_hash()));
        assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));
    }

    #[test]
    fn restart_restores_the_checkpoint_skip_and_garbage_does_not() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-6");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![h1]);
        fill_to_cap(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h2, h3]);
        assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));
        assert!(hub
            .query
            .get_header_by_hash(h2.block_hash().as_byte_array())
            .unwrap()
            .is_some());

        st.header_walk = HeaderWalk::default();
        hub.query.clear_milestone_path_above(0);
        assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
        assert!(restore_adopt(&mut st, &hub));
        assert!(
            skips(&hub, 1, h1.block_hash().as_byte_array()),
            "the skip is on again from header.adopt without the look-ahead rows"
        );
        assert_eq!(
            st.header_walk.tip_header().map(|h| h.block_hash()),
            Some(h3.block_hash()),
            "restart keeps the tip header for the next look-ahead"
        );

        let base_h = st.header_walk.base_height;
        st.header_walk = HeaderWalk::default();
        hub.query.clear_milestone_path_above(0);
        st.height_to_hash
            .insert(base_h, BlockHash::from_byte_array([0x11; 32]));
        assert!(
            !restore_adopt(&mut st, &hub),
            "a base hash that is not on this chain is not restored"
        );
        assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));

        st.height_to_hash.remove(&base_h);
        assert!(restore_adopt(&mut st, &hub));
        assert!(st.header_walk.base_height > 0);
        let path = hub.query.store().path().join("header.adopt");
        on_confirmed_rewind(&mut st, &hub, 0);
        assert!(
            !path.exists(),
            "a reorg under the base deletes header.adopt"
        );
        hub.query.clear_milestone_path_above(0);
        assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
        assert!(!restore_adopt(&mut st, &hub));

        st.header_walk = HeaderWalk::default();
        hub.query.clear_milestone_path_above(0);
        let path = hub.query.store().path().join("header.adopt");
        std::fs::write(&path, b"not-a-checkpoint-file").unwrap();
        assert!(!restore_adopt(&mut st, &hub));
        assert!(
            !skips(&hub, 1, h1.block_hash().as_byte_array()),
            "a file that does not parse does not skip scripts by height"
        );
    }

    #[test]
    fn a_failed_adopt_still_notes_the_queued_path() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-renote");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![h1, h2]);
        assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));

        hub.query.clear_milestone_path_above(0);
        st.header_walk = HeaderWalk::default();
        assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
        let path = hub.query.store().path().join("header.adopt");
        std::fs::write(&path, b"not-a-checkpoint-file").unwrap();
        assert!(!restore_adopt(&mut st, &hub));
        assert_eq!(
            hub.query.milestone_header_at(1),
            Some(h1.block_hash().to_byte_array()),
            "a queued header stays on the milestone path when header.adopt does not parse"
        );
        assert_eq!(
            hub.query.milestone_header_at(2),
            Some(h2.block_hash().to_byte_array())
        );
        assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));

        hub.query.clear_milestone_path_above(0);
        std::fs::remove_file(&path).unwrap();
        assert!(!restore_adopt(&mut st, &hub));
        assert_eq!(
            hub.query.milestone_header_at(1),
            Some(h1.block_hash().to_byte_array()),
            "a missing header.adopt still notes the queued path"
        );

        hub.query.clear_milestone_path_above(0);
        st.height_to_hash
            .insert(2, BlockHash::from_byte_array([0x22; 32]));
        assert!(!restore_adopt(&mut st, &hub));
        assert_eq!(
            hub.query.milestone_header_at(1),
            Some(h1.block_hash().to_byte_array())
        );
        assert_eq!(
            hub.query.milestone_header_at(2),
            None,
            "a height that does not link to the previous header is not the milestone chain"
        );
        assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
    }

    /// Two peers, one walk. The fast peer keeps headers until a short miss,
    /// a heavier inv takes the reservation back, a lighter inv restores it,
    /// and a low queue refills from that same peer. A miss that disconnects
    /// needs both peers still eligible, which a retired challenger is not,
    /// so that arc is a second chapter on this hub. One peer alone is a
    /// third: nobody else can take the reservation.
    #[test]
    #[allow(clippy::cognitive_complexity)] // one hub, many reservation arms
    fn two_peers_reserve_the_header_walk() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-reserve");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (mut slow, mut slow_rx) = slot(0);
        let (mut fast, mut fast_rx) = slot(1);
        slow.first_data_ms = 5_000;
        fast.first_data_ms = 50;
        let mut st = IbdWorkState::new(vec![slow, fast], Some(gen), Some(0));

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(slow_rx.try_recv().is_err(), "the slower peer is not asked");
        assert!(
            matches!(fast_rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })),
            "the lowest time-to-first-byte peer takes the walk"
        );
        assert_eq!(st.header_walk.reserved, Some(1));

        let hash = {
            let mut b = [0u8; 32];
            b[0..4].copy_from_slice(&1u32.to_le_bytes());
            BlockHash::from_byte_array(b)
        };
        st.record_height(hash, 1);
        st.height_to_hash.insert(1, hash);
        st.ordered_set.insert(hash);
        st.ordered.push_back(hash);
        st.max_ordered_height = 1;
        st.body.mark_missing(hash);
        let cfg = crate::ibd::IbdConfig::for_test();
        let stats = crate::ibd::status::LoopStats::default();
        crate::ibd::assign::assign_work_ordered(
            &mut st,
            &hub,
            &cfg,
            &stats,
            crate::ibd::assign::AssignDepth::Full,
            None,
        );
        assert!(
            st.slots[0].in_flight.contains(&hash),
            "block getdata goes to the peer who is not walking headers"
        );
        assert!(
            !st.slots[1].in_flight.contains(&hash),
            "the reserved header peer is not given a block"
        );
        assert!(matches!(slow_rx.try_recv(), Ok(PeerCmd::GetData { .. })));
        assert!(fast_rx.try_recv().is_err());

        st.ordered.clear();
        st.ordered_set.clear();
        st.height_to_hash.remove(&1);
        st.hash_height.remove(&hash);
        fill_queue(&mut st);
        let _ = take_header_ask(&mut st, 1);

        let good = mine(gen, 1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        assert_eq!(drain_getheaders(&mut slow_rx), 0);
        apply(&mut st, &hub, 1, vec![good]);
        assert_eq!(st.header_walk.reserved, Some(1));

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        apply(&mut st, &hub, 1, vec![]);
        assert!(st.slots[1].alive, "less work does not disconnect");
        assert_eq!(drain_getheaders(&mut fast_rx), 0);
        assert_eq!(drain_getheaders(&mut slow_rx), 1);
        assert_eq!(st.header_walk.reserved, Some(0));

        let _ = take_header_ask(&mut st, 0);
        let fork_a = mine(gen, 2);
        let fork_b = mine(fork_a.block_hash(), 3);
        blocks_inv(&mut st, &hub, 1, vec![fork_b.block_hash()]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut slow_rx), 0);
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        apply(&mut st, &hub, 1, vec![fork_a, fork_b]);
        assert_eq!(st.header_walk.tip_hash(), Some(fork_b.block_hash()));
        assert_eq!(st.header_walk.reserved, Some(1));
        assert!(st.slots[0].alive);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut slow_rx), 0);
        assert_eq!(drain_getheaders(&mut fast_rx), 1);

        let _ = take_header_ask(&mut st, 1);
        let fork = mine(gen, 4);
        blocks_inv(&mut st, &hub, 0, vec![fork.block_hash()]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut slow_rx), 1);
        apply(&mut st, &hub, 0, vec![fork]);
        assert_eq!(st.header_walk.tip_hash(), Some(fork_b.block_hash()));
        assert_eq!(st.header_walk.reserved, Some(1));
        assert!(st.header_walk.walk_quiet.contains(&0));
        assert!(st.slots[0].alive);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        assert_eq!(drain_getheaders(&mut slow_rx), 0);
        let _ = take_header_ask(&mut st, 1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        assert_eq!(drain_getheaders(&mut slow_rx), 0);

        let _ = take_header_ask(&mut st, 1);
        shrink_queue(&mut st, 100);
        let tail = st.ordered.back().copied().unwrap();
        st.hash_height.insert(tail, st.header_walk.tip_height());
        assert!(walk_ahead_of_queue(&st, &hub) || wants_lookahead(&st));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut fast_rx), 1);
        assert_eq!(drain_getheaders(&mut slow_rx), 0);
        assert_eq!(st.header_walk.reserved, Some(1));
        assert_eq!(st.header_walk.walk.peer, Some(1));

        // Both peers have to be eligible. The lighter challenger is retired.
        let (quiet, mut quiet_rx) = slot(2);
        let (mut busy, mut busy_rx) = slot(3);
        busy.in_flight.insert(BlockHash::from_byte_array([9u8; 32]));
        let quiet_addr = quiet.addr;
        let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut quiet_rx), 1);
        assert_eq!(drain_getheaders(&mut busy_rx), 0);
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(
            drain_getheaders(&mut quiet_rx),
            0,
            "one missed header ask skips that peer while another tall peer is up"
        );
        assert_eq!(drain_getheaders(&mut busy_rx), 1);
        assert!(st.slots.iter().any(|s| s.id == 2 && s.alive));
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(
            drain_getheaders(&mut quiet_rx),
            1,
            "the next miss moves the reservation back"
        );
        assert_eq!(drain_getheaders(&mut busy_rx), 0);
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(
            st.slots.iter().any(|s| s.id == 2 && !s.alive),
            "a second missed header ask disconnects that peer"
        );
        assert!(st.addr_cooldown.contains_key(&quiet_addr));
        assert!(matches!(quiet_rx.try_recv(), Ok(PeerCmd::Shutdown)));
        assert_eq!(drain_getheaders(&mut busy_rx), 1);

        // The survivor already has a miss, so a fresh sole peer is required.
        let (only, mut rx) = slot(4);
        let addr = only.addr;
        let mut st = IbdWorkState::new(vec![only], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut rx), 1);
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(
            drain_getheaders(&mut rx),
            1,
            "the only tall peer is asked again after one miss"
        );
        assert!(st.slots[0].alive);
        age_header_ask(&mut st);
        assert!(!send_getheaders(&mut st, &hub).unwrap());
        assert!(!st.slots[0].alive);
        assert!(st.addr_cooldown.contains_key(&addr));
        assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));
    }

    #[test]
    fn idle_header_requests_rotate_and_skip_a_short_peer() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-rotate");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (a, mut rx_a) = slot(0);
        let (b, mut rx_b) = slot(1);
        let (mut short, mut rx_short) = slot(2);
        short.peer_height = 10;
        let mut st = IbdWorkState::new(vec![a, b, short], Some(gen), Some(0));
        st.header_walk.origin = true;
        st.header_walk.tip.height = 100;
        st.ordered.clear();
        for _ in 0..ORDERED_HEADERS_SOFT_CAP {
            push_dummy(&mut st, 0);
        }
        let mut got = [0u32; 3];
        for _ in 0..6 {
            assert!(send_getheaders(&mut st, &hub).unwrap());
            if rx_a.try_recv().is_ok() {
                got[0] += 1;
            }
            if rx_b.try_recv().is_ok() {
                got[1] += 1;
            }
            if rx_short.try_recv().is_ok() {
                got[2] += 1;
            }
            if let Some(peer) = st.header_walk.walk.peer {
                let _ = take_header_ask(&mut st, peer);
            }
        }
        assert_eq!(got[2], 0, "a peer at or below the walk tip is not asked");
        assert_eq!(got[0], 6, "one peer keeps the walk until they miss");
        assert_eq!(got[1], 0, "a second tall peer is not asked in parallel");
    }

    #[test]
    fn a_challenger_can_extend_past_the_current_tip() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-challenger-extend");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let common = mine(gen, 1);
        let current = mine(common.block_hash(), 2);
        let current_tip = mine(current.block_hash(), 3);
        let side = mine(common.block_hash(), 12);
        let side_tip = mine(side.block_hash(), 13);
        let heavier = mine(side_tip.block_hash(), 14);
        hub.milestone.height = 4;
        let (first, mut first_rx) = slot(0);
        let (second, mut second_rx) = slot(1);
        let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
        fill_queue(&mut st);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = drain_getheaders(&mut first_rx);
        apply(&mut st, &hub, 0, vec![common]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = drain_getheaders(&mut first_rx);
        apply(&mut st, &hub, 0, vec![current, current_tip]);
        assert_eq!(st.header_walk.tip_hash(), Some(current_tip.block_hash()));

        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 1,
                hashes: vec![side_tip.block_hash()],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut second_rx), 1);
        apply(&mut st, &hub, 1, vec![side, side_tip]);
        assert_eq!(st.header_walk.tip_hash(), Some(current_tip.block_hash()));
        assert!(st.header_walk.challenger.is_some());

        apply(&mut st, &hub, 1, vec![heavier]);
        assert_eq!(st.header_walk.tip_hash(), Some(heavier.block_hash()));
        assert_eq!(st.header_walk.tip_height(), 4);
        assert!(st.header_walk.challenger.is_none());
        assert_eq!(
            hub.query.milestone_header_at(4),
            Some(heavier.block_hash().to_byte_array())
        );
    }

    /// Median time while the tip is still genesis, then that same hub confirms
    /// a stale ancestor and rewinds onto it. Retarget is a second hub: its
    /// period length is not regtest difficulty, and each checkpoint layout
    /// replaces the candidate the previous layout measured.
    #[test]
    #[allow(clippy::cognitive_complexity)] // one chain story, many context arms
    fn a_heavier_header_chain_keeps_its_context() {
        {
            let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-heavier-chain");
            hub.ensure_genesis().unwrap();

            // Eleven ancestors on a genesis tip. A confirmed block would hide this median.
            let gen = hub.tip_hash().unwrap();
            let chain = (1..=12).fold((Vec::new(), gen), |(mut headers, prev), n| {
                let header = mine(prev, n);
                headers.push(header);
                (headers, header.block_hash())
            });
            let main = chain.0;
            let side12 = mine(main[10].block_hash(), 32);
            let (first, mut first_rx) = slot(0);
            let (second, mut second_rx) = slot(1);
            let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
            fill_queue(&mut st);

            assert!(send_getheaders(&mut st, &hub).unwrap());
            let _ = drain_getheaders(&mut first_rx);
            apply(&mut st, &hub, 0, main[..11].to_vec());
            assert!(send_getheaders(&mut st, &hub).unwrap());
            let _ = drain_getheaders(&mut first_rx);
            apply(&mut st, &hub, 0, main[11..].to_vec());
            let current_tip = main[11].block_hash();

            apply_peer_event(
                &mut st,
                &hub,
                PeerEvent::BlocksInv {
                    peer: 1,
                    hashes: vec![side12.block_hash()],
                },
                &AtomicU32::new(0),
                &mut AddrMan::new(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                None,
            );
            assert!(send_getheaders(&mut st, &hub).unwrap());
            assert_eq!(drain_getheaders(&mut second_rx), 1);
            apply(&mut st, &hub, 1, vec![side12]);
            assert!(st.header_walk.challenger.is_some());

            let side_times = st
                .header_walk
                .challenger
                .as_ref()
                .unwrap()
                .tip
                .times
                .clone();
            let mtp = rbitcoin_primitives::median_time_past_times(&side_times).unwrap();
            let invalid = mine_at(side12.block_hash(), 40, mtp);
            apply(&mut st, &hub, 1, vec![invalid]);
            assert_eq!(st.header_walk.tip_hash(), Some(current_tip));
            assert_eq!(
                st.header_walk.challenger.as_ref().unwrap().tip.hash,
                Some(side12.block_hash())
            );

            let valid = mine_at(side12.block_hash(), 41, mtp + 1);
            apply(&mut st, &hub, 1, vec![valid]);
            assert_eq!(st.header_walk.tip_hash(), Some(valid.block_hash()));
            {
                // A stale height-1 anchor on this hub. The median-time walk left the confirmed tip at genesis.
                let gen = hub.tip_hash().unwrap();
                let stale = mine_block(gen, 1);
                hub.accept_block(stale.clone()).unwrap();
                assert_eq!(hub.tip_height(), Some(1));
                let stale_hash = stale.block_hash();
                let stale_next = mine(stale_hash, 2);
                let mut floor = [0u8; 32];
                floor[31] = 1;
                hub.milestone = rbitcoin_consensus::Milestone {
                    height: 2,
                    anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                        hash: stale_next.block_hash(),
                        min_work_be: floor,
                    }),
                };
                // Mainnet sets this above the confirmed tip for most of IBD. One
                // header on that tip is below the threshold; the chain is not.
                hub.set_minimum_chain_work(Some([0xff; 32]));
                let (s0, _rx0) = slot(0);
                let mut st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
                fill_queue(&mut st);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, vec![stale_next]);
                assert!(st.header_walk.proven);
                assert!(
                    skips(&hub, 2, stale_next.block_hash().as_byte_array()),
                    "the first chain through the anchor may skip until a heavier one wins"
                );

                let mut prev = gen;
                let mut honest = Vec::new();
                for n in 10..16 {
                    let hdr = mine(prev, n);
                    prev = hdr.block_hash();
                    honest.push(hdr);
                }
                let heavy = prev;
                apply(&mut st, &hub, 0, honest);
                assert!(
                    st.slots[0].alive,
                    "a heavier chain forking below the confirmed tip does not disconnect"
                );
                assert_eq!(st.header_walk.tip_hash(), Some(heavy));
                assert_eq!(st.header_walk.tip_height(), 6);
                assert!(
                    !skips(&hub, 2, stale_next.block_hash().as_byte_array()),
                    "script skip does not stay on the chain that lost"
                );
            }
            {
                // Rewind onto the confirmed chain this hub just grew past the stale block.
                let have = hub.tip_height().unwrap();
                hub.generate_to_script(
                    5 - have,
                    bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                    vec![],
                )
                .unwrap();
                let base_height = hub.tip_height().unwrap();
                let base_hash = hub.tip_hash().unwrap();
                let base_header = hub.tip_header().unwrap();
                floor_unreachable(&mut hub);
                let (s0, _rx0) = slot(0);
                let mut st = IbdWorkState::new(vec![s0], Some(base_hash), Some(base_height));
                fill_queue(&mut st);
                let first = mine_at(base_hash, 50, base_header.time + 1);
                let second = mine_at(first.block_hash(), 51, base_header.time + 2);

                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, vec![first, second]);
                apply(&mut st, &hub, 0, vec![]);
                assert_eq!(st.header_walk.tip_hash(), Some(base_hash));
                assert_eq!(st.header_walk.tip_height(), base_height);
                assert_eq!(
                    st.header_walk.tip.work,
                    Work::from_be_bytes(st.header_walk.base_work)
                );
                assert!(
                    st.header_walk.tip.work > Work::from_be_bytes([0; 32]),
                    "an empty rewind keeps the confirmed chain's work"
                );

                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, vec![first, second]);
                assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));
                assert_eq!(st.header_walk.tip_height(), base_height + 2);

                let parent = hub
                    .query
                    .wire_header_at_height(rbitcoin_primitives::Height(base_height - 1))
                    .unwrap();
                let side = mine_at(parent.block_hash(), 52, parent.time + 1);
                apply(&mut st, &hub, 0, vec![side]);
                assert_eq!(
                    st.header_walk.tip_hash(),
                    Some(second.block_hash()),
                    "one less-work header from the confirmed parent does not replace the walk"
                );
            }
        }
        {
            // Retarget every 20 blocks. The walks above leave regtest difficulty in place.
            let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-heavier-retarget");
            hub.ensure_genesis().unwrap();
            arm_retarget(&mut hub);
            {
                let gen_hash = hub.tip_hash().unwrap();
                let genesis = hub.header_of(&gen_hash).unwrap();
                floor_unreachable(&mut hub);
                let (s0, _rx0) = slot(0);
                let mut st = IbdWorkState::new(vec![s0], Some(gen_hash), Some(0));
                fill_queue(&mut st);
                assert_eq!(hub.params.difficulty_adjustment_interval(), 20);
                let chain = extend_chain(&hub, &genesis, &[], 45, 1);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[..20].to_vec());
                assert!(st.slots[0].alive, "the first period is valid");
                assert_eq!(st.header_walk.tip_height(), 20);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[20..40].to_vec());
                assert!(
                    st.slots[0].alive,
                    "the retarget at the period start is valid"
                );
                assert_eq!(st.header_walk.tip_height(), 40);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[40..].to_vec());
                assert!(st.slots[0].alive, "the walk continues past that retarget");
                assert_eq!(st.header_walk.tip_height(), 45);

                let fork = extend_chain(&hub, &genesis, &chain[..20], 30, 2);
                let fork_tip = fork.last().unwrap().block_hash();
                apply(&mut st, &hub, 0, fork);
                assert!(
                    st.slots[0].alive,
                    "a heavier fork whose period start is only on the fork checkpoint is valid"
                );
                assert_eq!(st.header_walk.tip_height(), 50);
                assert_eq!(st.header_walk.tip_hash(), Some(fork_tip));
            }
            {
                // The gap fork replaces the candidate, so this rewind keeps its own checkpoints.
                let gen_hash = hub.tip_hash().unwrap();
                let genesis = hub.header_of(&gen_hash).unwrap();
                floor_unreachable(&mut hub);
                let (s0, _rx0) = slot(0);
                let mut st = IbdWorkState::new(vec![s0], Some(gen_hash), Some(0));
                fill_queue(&mut st);
                assert_eq!(hub.params.difficulty_adjustment_interval(), 20);
                let chain = extend_chain(&hub, &genesis, &[], 46, 1);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[..16].to_vec());
                assert!(st.slots[0].alive);
                assert_eq!(st.header_walk.tip_height(), 16);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[16..36].to_vec());
                assert!(
                    st.slots[0].alive,
                    "the retarget inside the second reply is valid"
                );
                assert_eq!(st.header_walk.tip_height(), 36);
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, chain[36..].to_vec());
                assert!(st.slots[0].alive);
                assert_eq!(st.header_walk.tip_height(), 46);

                apply(&mut st, &hub, 0, vec![]);
                assert_eq!(
                    st.header_walk.tip_height(),
                    36,
                    "an empty reply below the floor steps back one checkpoint"
                );
                let checkpoint = st.header_walk.checkpoints.last().unwrap();
                assert_eq!(
                    st.header_walk.tip_hash(),
                    Some(checkpoint.hash),
                    "an empty rewind lands on that checkpoint"
                );
                let checkpoint_work = Work::from_be_bytes(checkpoint.work);
                assert_eq!(st.header_walk.tip.work, checkpoint_work);
                assert!(
                    checkpoint_work > Work::from_be_bytes([0; 32]),
                    "an empty rewind keeps that checkpoint's work"
                );
                let next = extend_chain(&hub, &genesis, &chain[..36], 20, 3);
                let tip = next.last().unwrap().block_hash();
                assert!(send_getheaders(&mut st, &hub).unwrap());
                apply(&mut st, &hub, 0, next);
                assert!(
                    st.slots[0].alive,
                    "the period start on the checkpoint we rewound to still checks nBits"
                );
                assert_eq!(st.header_walk.tip_height(), 56);
                assert_eq!(st.header_walk.tip_hash(), Some(tip));

                let lighter = extend_chain(&hub, &genesis, &[], 55, 4);
                apply(&mut st, &hub, 0, lighter);
                assert_eq!(
                st.header_walk.tip_hash(),
                Some(tip),
                "work before the restored checkpoint still counts when comparing a lighter fork"
            );
            }
            {
                // A second peer's snapshot. The rewind chain has no challenger and a different tip.
                let gen = hub.tip_hash().unwrap();
                let genesis = hub.header_of(&gen).unwrap();
                let main = extend_chain(&hub, &genesis, &[], 22, 1);
                let side = extend_chain(&hub, &genesis, &main[..20], 21, 2);
                floor_unreachable(&mut hub);
                hub.milestone.height = 41;
                let (first, mut first_rx) = slot(0);
                let (second, mut second_rx) = slot(1);
                let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
                fill_queue(&mut st);

                assert!(send_getheaders(&mut st, &hub).unwrap());
                let _ = drain_getheaders(&mut first_rx);
                apply(&mut st, &hub, 0, main[..20].to_vec());
                assert!(send_getheaders(&mut st, &hub).unwrap());
                let _ = drain_getheaders(&mut first_rx);
                apply(&mut st, &hub, 0, main[20..].to_vec());
                assert_eq!(st.header_walk.tip_height(), 22);

                apply_peer_event(
                    &mut st,
                    &hub,
                    PeerEvent::BlocksInv {
                        peer: 1,
                        hashes: vec![side[0].block_hash()],
                    },
                    &AtomicU32::new(0),
                    &mut AddrMan::new(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                    None,
                );
                assert!(send_getheaders(&mut st, &hub).unwrap());
                assert_eq!(drain_getheaders(&mut second_rx), 1);
                apply(&mut st, &hub, 1, vec![side[0]]);
                assert_eq!(st.header_walk.tip_hash(), Some(main[21].block_hash()));
                assert!(st.header_walk.challenger.is_some());

                apply(&mut st, &hub, 1, side[1..].to_vec());
                assert_eq!(st.header_walk.tip_height(), 41);
                assert_eq!(st.header_walk.tip_hash(), Some(side[20].block_hash()));
                assert!(st.header_walk.challenger.is_none());
                assert_eq!(
                    hub.query.milestone_header_at(41),
                    Some(side[20].block_hash().to_byte_array())
                );
            }
        }
    }

    fn drain_getheaders(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> usize {
        let mut n = 0usize;
        loop {
            match rx.try_recv() {
                Ok(PeerCmd::GetHeaders { .. }) => n += 1,
                Ok(_) => {}
                Err(_) => return n,
            }
        }
    }

    fn age_header_ask(st: &mut IbdWorkState) {
        let old = Instant::now().checked_sub(Duration::from_secs(6));
        if st.header_walk.walk.peer.is_some() {
            st.header_walk.walk.at = old;
        }
    }

    #[test]
    fn a_refill_ask_waits_then_skips_the_peer_that_missed() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-refill-miss");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (quiet, mut quiet_rx) = slot(0);
        let (mut busy, mut busy_rx) = slot(1);
        busy.in_flight.insert(BlockHash::from_byte_array([8u8; 32]));
        let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut quiet_rx), 1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(
            drain_getheaders(&mut quiet_rx),
            0,
            "a refill still inside the window is not sent again"
        );
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut quiet_rx), 0);
        assert_eq!(drain_getheaders(&mut busy_rx), 1);
    }

    #[test]
    fn a_late_lookahead_from_the_asked_peer_still_extends_the_tip() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-late");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (quiet, mut quiet_rx) = slot(0);
        let (mut busy, mut busy_rx) = slot(1);
        busy.in_flight.insert(BlockHash::from_byte_array([7u8; 32]));
        let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));
        fill_queue(&mut st);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut quiet_rx), 1);
        age_header_ask(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut quiet_rx), 0);
        assert_eq!(drain_getheaders(&mut busy_rx), 1);

        rbitcoin_log::capture_logs(true);
        apply(&mut st, &hub, 0, vec![good]);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(good.block_hash()),
            "a late look-ahead from the peer that was asked still extends the tip"
        );
        assert!(
            logs.iter()
                .any(|(level, line)| *level == rbitcoin_log::Level::Info
                    && line.contains("ibd: headers late")),
            "a late look-ahead is logged"
        );
        assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));

        let next = mine(good.block_hash(), 2);
        let tip = st.header_walk.tip_hash();
        apply(&mut st, &hub, 2, vec![next]);
        assert_eq!(
            st.header_walk.tip_hash(),
            tip,
            "a look-ahead from a peer that was not asked is ignored"
        );
    }

    #[test]
    fn off_path_headers_disconnect_the_peer_and_path_headers_do_not() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-8");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        floor_unreachable(&mut hub);
        let owed = BlockHash::from_byte_array([0x5a; 32]);
        let (path_peer, _rx0) = slot(0);
        let (mut side_peer, _rx1) = slot(1);
        let path_addr = path_peer.addr;
        let side_addr = side_peer.addr;
        side_peer.track_insert(owed);
        let mut st = IbdWorkState::new(vec![path_peer, side_peer], Some(gen), Some(0));
        super::super::assign::inflight_add_peer(&mut st.inflight, owed, 1);
        apply(&mut st, &hub, 0, vec![h1, h2]);
        assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));
        assert!(!st.addr_cooldown.contains_key(&path_addr));
        assert!(
            st.inflight.contains_key(&owed),
            "the side peer still owes the block while it is connected"
        );

        let mut prev = gen;
        let mut side = Vec::with_capacity(4_001);
        for n in 0..4_001 {
            let hdr = mine(prev, 10_000 + n);
            prev = hdr.block_hash();
            side.push(hdr);
        }
        apply(&mut st, &hub, 1, side);
        assert!(
            st.slots.iter().any(|s| s.id == 1 && !s.alive),
            "a peer over the off-path budget is disconnected"
        );
        assert!(st.addr_cooldown.contains_key(&side_addr));
        assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));
        assert!(
            !st.inflight.contains_key(&owed),
            "the disconnected peer's block getdata is free to ask another peer"
        );
    }

    fn push_dummy(st: &mut IbdWorkState, n: u32) {
        let mut b = [0x11; 32];
        b[28..32].copy_from_slice(&n.to_le_bytes());
        let h = BlockHash::from_byte_array(b);
        st.ordered.push_back(h);
        st.ordered_set.insert(h);
    }

    /// The work floor is above anything a regtest header can reach.
    fn floor_unreachable(hub: &mut ChainHub) {
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 840_000,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: BlockHash::from_byte_array([0xab; 32]),
                min_work_be: [0xff; 32],
            }),
        };
    }

    fn queue_at_cap_ending_on(st: &mut IbdWorkState, hub: &ChainHub, tail: Header) {
        let mut n = 0u32;
        while st.ordered.len() + 1 < ORDERED_HEADERS_SOFT_CAP {
            push_dummy(st, n);
            n += 1;
        }
        apply(st, hub, 0, vec![tail]);
    }

    #[test]
    fn queue_refill_below_the_floor_stores_the_successor() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-refill");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let a3 = mine(a2.block_hash(), 3);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert_eq!(st.ordered.back().copied(), Some(a1.block_hash()));
        let before = hub.query.store().header_count();
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert_eq!(hub.query.store().header_count(), before + 1);
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));

        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        apply(&mut st, &hub, 0, vec![a2, a3]);
        assert_eq!(
            hub.query.store().header_count(),
            before + 2,
            "the queue stores the successor of its tail below the work floor"
        );
        assert!(st.ordered_set.contains(&a2.block_hash()));
        assert!(st.ordered_set.contains(&a3.block_hash()));
    }

    #[test]
    fn easy_bits_lookahead_does_not_capture_the_walk() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-easy");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let honest = mine(gen, 1);
        let mut easy = honest;
        easy.bits = CompactTarget::from_consensus(0x2100ffff);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let bad_addr = s0.addr;
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        let before = hub.query.store().header_count();
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![easy]);
        assert_eq!(hub.query.store().header_count(), before);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(st.header_walk.checkpoints().is_empty());
        assert!(
            !st.slots[0].alive,
            "the peer that sent the easy header is down"
        );
        assert!(st.addr_cooldown.contains_key(&bad_addr));
        assert!(st.slots[1].alive);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 1, vec![honest]);
        assert_eq!(st.header_walk.tip_hash(), Some(honest.block_hash()));
        assert_eq!(hub.query.store().header_count(), before + 1);
        assert!(st.slots[1].alive);
    }

    #[test]
    fn unsolicited_lookahead_from_another_peer_is_ignored() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-unasked");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 1, vec![good]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(st.header_walk.checkpoints().is_empty());
        assert!(st.slots[1].alive, "an unasked peer is not disconnected");
        apply(&mut st, &hub, 0, vec![good]);
        assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
        assert!(st.slots[1].alive);
    }

    #[test]
    fn rewind_clears_a_milestone_hash_from_the_abandoned_chain() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-milestone");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let b1 = mine(gen, 11);
        let b2 = mine(b1.block_hash(), 12);
        floor_unreachable(&mut hub);
        hub.milestone.height = 2;
        hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
            hash: b2.block_hash(),
            min_work_be: [0xff; 32],
        });
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1, a2]);
        assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));
        let side = BlockHash::from_byte_array([0x42; 32]);
        assert!(!note_off_path(&mut st, &hub, 0, side));
        assert!(!note_off_path(&mut st, &hub, 0, side));
        assert_eq!(st.header_walk.off_path.get(&0).map(|s| s.len()), Some(1));
        plant_on_queue(&mut st, a1.block_hash(), 1);
        plant_on_queue(&mut st, a2.block_hash(), 2);

        apply(&mut st, &hub, 0, vec![]);
        apply(&mut st, &hub, 1, vec![]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(
            st.header_walk.off_path.is_empty(),
            "a rewind forgets side headers from the abandoned chain"
        );
        assert!(
            st.header_walk.milestone_hash().is_none(),
            "rewinding under the milestone drops the abandoned hash"
        );

        apply(&mut st, &hub, 1, vec![b1, b2]);
        assert_eq!(st.header_walk.milestone_hash(), Some(b2.block_hash()));
    }

    #[test]
    fn confirmed_reorg_drops_a_milestone_hash_below_the_fork() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-reorg-ms");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        floor_unreachable(&mut hub);
        hub.milestone.height = 2;
        hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
            hash: a2.block_hash(),
            min_work_be: [0xff; 32],
        });
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1, a2]);
        assert_eq!(st.header_walk.base_height, 0);
        assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));

        rbitcoin_log::capture_logs(true);
        hub.query.clear_milestone_path_above(2);
        on_confirmed_rewind(&mut st, &hub, 2);
        let above = rbitcoin_log::take_logs();
        assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));
        assert_eq!(
            hub.query.milestone_header_at(2),
            Some(a2.block_hash().to_byte_array())
        );
        assert!(
            above
                .iter()
                .all(|(_, line)| !line.contains("milestone dropped")),
            "a reorg that stays above the milestone keeps the latched hash"
        );

        hub.query.clear_milestone_path_above(0);
        on_confirmed_rewind(&mut st, &hub, 0);
        let below = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            st.header_walk.milestone_hash().is_none(),
            "a fork under the milestone drops the latched hash and does not put it back"
        );
        assert!(
            below.iter().any(|(level, line)| {
                *level == rbitcoin_log::Level::Warn
                    && line.contains("ibd: headers milestone dropped")
            }),
            "dropping the latch is logged so script checks staying on is visible"
        );
        st.header_walk = HeaderWalk::default();
        assert!(restore_adopt(&mut st, &hub));
        assert!(
            st.header_walk.milestone_hash().is_none(),
            "header.adopt does not restore a hash from below the fork"
        );
    }

    #[test]
    fn origin_stops_at_the_queue_tail() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-origin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let next = mine(h2.block_hash(), 4);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![h1, h2, h3]);
        fill_to_cap(&mut st);
        plant_on_queue(&mut st, h2.block_hash(), 2);
        st.height_to_hash.remove(&3);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![next]);
        assert_eq!(st.header_walk.tip_hash(), Some(next.block_hash()));
        assert_eq!(st.header_walk.base_height, 2);
    }

    fn mine_at(prev: BlockHash, n: u32, time: u32) -> Header {
        let mut h = Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
            time,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    }

    #[test]
    fn refill_matching_the_first_of_two_checkpoints_is_stored() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-two-ckpt");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let a3 = mine(a2.block_hash(), 3);
        let a4 = mine(a3.block_hash(), 4);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2, a3]);
        while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
            let Some(dropped) = st.ordered.pop_front() else {
                break;
            };
            st.ordered_set.remove(&dropped);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a4]);
        assert!(
            st.slots[0].alive,
            "the peer that extended the walk stays up"
        );
        assert_eq!(st.header_walk.checkpoints().len(), 2);
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![a2, a3]);
        assert_eq!(
            hub.query.store().header_count(),
            before,
            "a refill that matches a checkpoint already written is not stored again"
        );
        assert!(hub
            .query
            .get_header_by_hash(a3.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert_eq!(st.header_walk.checkpoints().len(), 2);
    }

    #[test]
    fn refill_that_contradicts_a_checkpoint_rewinds_and_stores() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-rewind-miss");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let honest = mine(a1.block_hash(), 9);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![honest]);
        assert_eq!(hub.query.store().header_count(), before + 1);
        assert_eq!(st.header_walk.tip_hash(), Some(honest.block_hash()));
        assert!(st
            .header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != a2.block_hash()));
        assert!(!st.header_walk.dead_ends.contains(&honest.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(honest.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert!(st.slots[0].alive);
    }

    #[test]
    fn a_second_lookahead_ask_waits_for_the_reply() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-latch");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert!(
            rx.try_recv().is_err(),
            "a look-ahead ask still inside the window is not sent again"
        );
        apply(&mut st, &hub, 0, vec![good]);
        assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
        assert!(st.slots[0].alive);
    }

    #[test]
    fn heavier_chain_below_the_floor_is_adopted_without_an_empty_reply() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-heavy-floor");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let stale = mine(gen, 1);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![stale]);
        assert_eq!(st.header_walk.tip_hash(), Some(stale.block_hash()));
        let mut prev = gen;
        let mut honest = Vec::new();
        for n in 10..14 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            honest.push(hdr);
        }
        let tip = honest.last().unwrap().block_hash();
        apply(&mut st, &hub, 0, honest);
        assert_eq!(st.header_walk.tip_hash(), Some(tip));
        assert!(st.slots[0].alive);
        assert!(st
            .header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != stale.block_hash()));
    }

    #[test]
    fn a_short_peer_does_not_block_an_empty_rewind() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-short-empty");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        floor_unreachable(&mut hub);
        let (tall, _rx0) = slot(0);
        let (mut short, _rx1) = slot(1);
        short.peer_height = 1;
        let mut st = IbdWorkState::new(vec![tall, short], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1, a2]);
        assert_eq!(st.header_walk.tip_height(), 2);
        plant_on_queue(&mut st, a1.block_hash(), 1);
        plant_on_queue(&mut st, a2.block_hash(), 2);
        apply(&mut st, &hub, 0, vec![]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(st.slots.iter().any(|s| s.id == 1 && s.alive));
    }

    #[test]
    fn a_queued_hash_between_checkpoints_is_not_stored_while_the_queue_is_full() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-between");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        let tip = st.header_walk.tip_hash();
        let before = hub.query.store().header_count();
        let mid = st.ordered[st.ordered.len() / 2];
        let side = mine(mid, 40);
        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(hub.query.store().header_count(), before);
        assert_eq!(st.header_walk.tip_hash(), tip);
        assert!(!st.ordered_set.contains(&side.block_hash()));
    }

    #[test]
    fn restored_checkpoint_times_accept_a_header_under_the_tip_time() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-mtp");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let mut prev = gen;
        let mut chain = Vec::new();
        for n in 1..=12 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            chain.push(hdr);
        }
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, chain.clone());
        assert_eq!(st.header_walk.tip.times.len(), 11);
        let tip = chain[11];
        st.header_walk = HeaderWalk::default();
        assert!(restore_adopt(&mut st, &hub));
        assert_eq!(st.header_walk.tip.times.len(), 11);
        assert_eq!(
            st.header_walk.tip_header().map(|h| h.block_hash()),
            Some(tip.block_hash())
        );
        let soft = mine_at(tip.block_hash(), 13, tip.time - 2);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![soft]);
        assert_eq!(st.header_walk.tip_hash(), Some(soft.block_hash()));
        assert!(st.slots[0].alive);

        apply(&mut st, &hub, 0, vec![]);
        assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
        let mtp = rbitcoin_primitives::median_time_past_times(&st.header_walk.tip.times).unwrap();
        let invalid = mine_at(tip.block_hash(), 14, mtp);
        apply(&mut st, &hub, 0, vec![invalid]);
        assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
    }

    #[test]
    fn a_missing_parent_header_is_consumed_without_a_disconnect() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-no-parent");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let stale = mine(gen, 1);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![stale]);
        st.header_walk.tip.header = None;
        st.header_walk.tip.times.clear();
        if let Some(c) = st.header_walk.checkpoints.last_mut() {
            c.header = None;
            c.times.clear();
        }
        let mut prev = stale.block_hash();
        let mut heavier = Vec::new();
        for n in 20..24 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            heavier.push(hdr);
        }
        let before = st.header_walk.tip_hash();
        apply(&mut st, &hub, 0, heavier);
        assert_eq!(st.header_walk.tip_hash(), before);
        assert!(st.slots[0].alive);
    }

    #[test]
    fn min_difficulty_walk_back_rejects_a_limit_header() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-mindiff");
        hub.ensure_genesis().unwrap();
        hub.params.btc.allow_min_difficulty_blocks = true;
        let gen = hub.tip_hash().unwrap();
        let tip = mine(gen, 1);
        let (s0, _rx0) = slot(0);
        let addr = s0.addr;
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![tip]);
        assert!(st.slots[0].alive);
        st.header_walk.tip.diff.full_diff_bits = Some(CompactTarget::from_consensus(0x1d00ffff));
        st.header_walk.tip.diff.full_diff_height = st.header_walk.tip_height().saturating_sub(1);
        let next = mine_at(tip.block_hash(), 2, tip.time + 1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![next]);
        assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
        assert!(!st.slots[0].alive);
        assert!(st.addr_cooldown.contains_key(&addr));
    }

    /// Core `GetNextWorkRequired`: a header within 20 minutes of a
    /// min-difficulty parent takes the last non-limit `nBits`, even when that
    /// header is earlier in the same reply.
    #[test]
    fn min_difficulty_walk_back_finds_a_retarget_in_the_same_batch() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-mindiff-batch");
        hub.ensure_genesis().unwrap();
        arm_retarget(&mut hub);
        let gen = hub.tip_hash().unwrap();
        let genesis = hub.header_of(&gen).unwrap();
        let mut chain = extend_chain(&hub, &genesis, &[], 20, 1);
        hub.params.btc.allow_min_difficulty_blocks = true;
        let limit = hub.params.pow_limit.to_compact_lossy();
        let retarget = chain[19];
        assert_ne!(retarget.bits, limit, "height 20 retargets above the limit");
        let spacing = hub.params.btc.pow_target_spacing as u32;
        let min_diff = mine_bits(
            retarget.block_hash(),
            21,
            retarget.time + 2 * spacing + 1,
            limit,
            1,
        );
        let next = mine_bits(
            min_diff.block_hash(),
            22,
            min_diff.time + 1,
            retarget.bits,
            1,
        );
        chain.extend([min_diff, next]);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, chain);
        assert!(st.slots[0].alive);
        assert_eq!(st.header_walk.tip_hash(), Some(next.block_hash()));
    }

    #[test]
    fn a_restored_checkpoint_header_adopts_a_heavier_fork() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-restore-fork");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let fork = mine(gen, 1);
        let tip = mine(fork.block_hash(), 2);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![fork]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![tip]);
        assert_eq!(st.header_walk.checkpoints().len(), 2);
        st.header_walk = HeaderWalk::default();
        assert!(restore_adopt(&mut st, &hub));
        let mut prev = fork.block_hash();
        let mut heavier = Vec::new();
        for n in 30..34 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            heavier.push(hdr);
        }
        let heavy_tip = heavier.last().unwrap().block_hash();
        apply(&mut st, &hub, 0, heavier);
        assert_eq!(st.header_walk.tip_hash(), Some(heavy_tip));
        assert!(st.slots[0].alive);
    }

    fn arm_retarget(hub: &mut crate::chain::ChainHub) {
        hub.params.btc.no_pow_retargeting = false;
        hub.params.btc.allow_min_difficulty_blocks = false;
        let spacing = hub.params.btc.pow_target_spacing;
        hub.params.btc.pow_target_timespan = spacing.saturating_mul(20);
    }

    fn chain_time(genesis_time: u32, spacing: u32, height: u32) -> u32 {
        genesis_time.saturating_add(spacing.saturating_mul(height))
    }

    fn bits_for(
        hub: &crate::chain::ChainHub,
        genesis: &Header,
        prior: &[Header],
        height: u32,
        time: u32,
        parent: &Header,
    ) -> CompactTarget {
        let interval = hub.params.difficulty_adjustment_interval();
        let period_first = if interval > 0 && height.is_multiple_of(interval) {
            let start = height - interval;
            if start == 0 {
                Some(genesis.time)
            } else {
                prior.get((start as usize) - 1).map(|h| h.time)
            }
        } else {
            None
        };
        rbitcoin_consensus::next_work_bits(
            &hub.params,
            height,
            parent.bits,
            parent.time,
            time,
            period_first,
            |_| None,
        )
        .expect("difficulty bits")
    }

    fn mine_bits(prev: BlockHash, n: u32, time: u32, bits: CompactTarget, salt: u8) -> Header {
        let mut merkle = [salt; 32];
        merkle[28..32].copy_from_slice(&n.to_le_bytes());
        let mut h = Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time,
            bits,
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    }

    /// Headers at heights `prior.len()+1` onward. `prior` is the shared prefix
    /// (height 1 first). Difficulty matches `hub.params`.
    fn extend_chain(
        hub: &crate::chain::ChainHub,
        genesis: &Header,
        prior: &[Header],
        extra: u32,
        salt: u8,
    ) -> Vec<Header> {
        let spacing = hub.params.btc.pow_target_spacing as u32;
        let mut all = prior.to_vec();
        let mut parent = prior.last().copied().unwrap_or(*genesis);
        let start = prior.len() as u32;
        let mut out = Vec::with_capacity(extra as usize);
        for n in 1..=extra {
            let height = start + n;
            let time = chain_time(genesis.time, spacing, height);
            let bits = bits_for(hub, genesis, &all, height, time, &parent);
            let hdr = mine_bits(parent.block_hash(), height, time, bits, salt);
            all.push(hdr);
            out.push(hdr);
            parent = hdr;
        }
        out
    }

    #[test]
    fn a_full_queue_next_ask_starts_at_the_walk_tip() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-ask-past-cap");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        floor_unreachable(&mut hub);
        let (mut peer, mut rx) = slot(0);
        peer.peer_height = 100_000;
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![a2]);
        assert!(
            !st.ordered_set.contains(&a2.block_hash()),
            "the soft cap keeps the new header off the queue"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        st.hygiene();
        assert!(
            st.height_to_hash
                .values()
                .any(|hash| *hash == a2.block_hash()),
            "a header written past the queue stays indexed until the queue takes it"
        );
        assert!(
            send_getheaders(&mut st, &hub).unwrap(),
            "the walk still needs the header after the one it just stored"
        );
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert_eq!(
                    locator[0],
                    a2.block_hash(),
                    "the ask starts at the stored walk tip, not the queue tail"
                );
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("peer was not asked for the next header"),
        }
    }

    #[test]
    fn new_lookahead_batch_does_not_skip_stored_queue_successors() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-no-queue-gap");
        hub.ensure_genesis().unwrap();
        let genesis = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(genesis), Some(0));
        let tail = mine(genesis, 1);
        queue_at_cap_ending_on(&mut st, &hub, tail);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let next = mine(tail.block_hash(), 2);
        let third = mine(next.block_hash(), 3);
        apply(&mut st, &hub, 0, vec![next, third]);
        for _ in 0..2 {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
        let fourth = mine(third.block_hash(), 4);
        apply(&mut st, &hub, 0, vec![fourth]);
        super::super::path::append_stored_headers(&mut st, &hub);
        let queued: Vec<_> = st.ordered.iter().rev().take(2).copied().collect();
        assert_eq!(
            queued,
            vec![third.block_hash(), next.block_hash()],
            "new lookahead must leave the free queue slots for already stored successors"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(fourth.block_hash()));
    }

    #[test]
    fn drained_queue_refills_stored_headers_after_known_header_pruning() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-pruned-refill");
        hub.ensure_genesis().unwrap();
        let genesis = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(genesis), Some(0));
        let tail = mine(genesis, 1);
        queue_at_cap_ending_on(&mut st, &hub, tail);
        st.known_headers.extend(st.ordered.iter().copied());
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let next = mine(tail.block_hash(), 2);
        let last = mine(next.block_hash(), 3);
        apply(&mut st, &hub, 0, vec![next, last]);
        assert_eq!(st.header_walk.tip_hash(), Some(last.block_hash()));
        while st.ordered.len() > 1 {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
        assert_eq!(st.ordered.back(), Some(&tail.block_hash()));
        st.hygiene();
        assert_eq!(
            super::super::path::append_stored_headers(&mut st, &hub),
            2,
            "both stored successors must remain available to the download queue after pruning"
        );
        assert_eq!(path_top(&st, &hub), Some((last.block_hash(), 3)));
    }

    #[test]
    fn a_heavier_fork_below_the_floor_is_written_when_the_queue_has_room() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-stray-write");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        let mut prev = gen;
        let mut candidate = Vec::new();
        for n in 1..=2 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            candidate.push(hdr);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, candidate);
        let before = hub.query.store().header_count();
        let mut prev = gen;
        let mut fork = Vec::new();
        for n in 20..26 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            fork.push(hdr);
        }
        let heavy = prev;
        apply(&mut st, &hub, 0, fork);
        assert_eq!(st.header_walk.tip_hash(), Some(heavy));
        assert!(
            hub.query.store().header_count() > before,
            "a heavier fork is written when the queue can hold it"
        );
    }

    #[test]
    fn an_external_block_inv_does_not_retire_the_header_peer() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-external-inv");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
            hash: gen,
            min_work_be: [0; 32],
        });
        let (mut peer, mut rx) = slot(0);
        peer.peer_height = 1;
        let (mut tall, _tall_rx) = slot(1);
        tall.peer_height = 50;
        let mut st = IbdWorkState::new(vec![peer, tall], Some(gen), Some(0));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![mine(gen, 1)]);
        assert_eq!(st.header_walk.reserved, Some(0));
        assert_eq!(st.header_walk.tip_height(), 1);
        assert!(note_external_block_inv(&mut st));
        assert_eq!(st.header_walk.challenge, Some(0));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, vec![]);
        assert_eq!(
            st.header_walk.reserved,
            Some(0),
            "an inv from a peer with no header slot does not drop the reservation"
        );
        assert!(
            !st.header_walk.walk_quiet.contains(&0),
            "that empty reply does not retire the header peer"
        );
    }

    #[test]
    fn an_inflight_external_inv_does_not_retire_on_empty() {
        let (_dir, mut hub) =
            crate::chain::tiny_regtest_hub_labeled("header-walk-external-inflight");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
            hash: gen,
            min_work_be: [0; 32],
        });
        let (mut peer, mut rx) = slot(0);
        peer.peer_height = 1;
        let (mut tall, _tall_rx) = slot(1);
        tall.peer_height = 50;
        let mut st = IbdWorkState::new(vec![peer, tall], Some(gen), Some(0));
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        assert_eq!(st.header_walk.reserved, Some(0));
        assert_eq!(st.header_walk.walk.peer, Some(0));
        // The walk caught this peer's advertised height while their ask is
        // still out, so the inv is a challenge rather than the next walk ask.
        st.header_walk.tip.height = st.slots[0].peer_height;
        assert!(note_external_block_inv(&mut st));
        assert_eq!(
            st.header_walk.challenge_open,
            Some(0),
            "the ask already in flight is the challenge answer"
        );
        apply(&mut st, &hub, 0, vec![]);
        assert_eq!(
            st.header_walk.reserved,
            Some(0),
            "an inv from a peer with no header slot does not drop the reservation"
        );
        assert!(
            !st.header_walk.walk_quiet.contains(&0),
            "the in-flight empty reply does not retire the header peer"
        );
    }

    #[test]
    fn a_heavier_chain_arriving_in_two_batches_replaces_the_candidate() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-two-batch");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let (s0, mut rx) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        let mut prev = gen;
        let mut candidate = Vec::new();
        for n in 1..=4 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            candidate.push(hdr);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = rx.try_recv();
        apply(&mut st, &hub, 0, candidate);
        let candidate_tip = st.header_walk.tip_hash();
        assert_eq!(st.header_walk.tip_height(), 4);
        let before = hub.query.store().header_count();

        let mut prev = gen;
        let mut first = Vec::new();
        for n in 20..22 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            first.push(hdr);
        }
        apply(&mut st, &hub, 0, first);
        assert_eq!(
            st.header_walk.tip_hash(),
            candidate_tip,
            "a short valid batch does not replace a heavier candidate"
        );
        assert_eq!(hub.query.store().header_count(), before);
        assert!(st.slots[0].alive);
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => {
                assert!(
                    locator.contains(&prev),
                    "the ask names the lighter fork so that peer can send the next window"
                );
            }
            Ok(_) => panic!("expected getheaders"),
            Err(_) => panic!("peer was not asked for headers"),
        }

        let mut second = Vec::new();
        for n in 22..26 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            second.push(hdr);
        }
        let heavy = prev;
        apply(&mut st, &hub, 0, second);
        assert!(
            st.slots[0].alive,
            "feeding the heavier chain does not disconnect"
        );
        assert_eq!(st.header_walk.tip_height(), 6);
        assert_eq!(st.header_walk.tip_hash(), Some(heavy));
        assert_eq!(
            hub.query.store().header_count(),
            before,
            "headers past the full queue stay off header.body"
        );
    }

    #[test]
    fn a_fork_from_the_confirmed_tip_keeps_that_height() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-fork-height");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        floor_unreachable(&mut hub);
        hub.milestone.height = 2;
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        apply(&mut st, &hub, 0, vec![h1, h2]);
        fill_to_cap(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h3]);
        assert_eq!(st.header_walk.base_height, 2);
        assert_eq!(st.header_walk.tip_height(), 3);
        assert_eq!(st.header_walk.milestone_hash(), Some(h2.block_hash()));

        let mut prev = gen;
        let mut fork = Vec::new();
        for n in 30..35 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            fork.push(hdr);
        }
        let on_milestone = fork[1].block_hash();
        hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
            hash: on_milestone,
            min_work_be: [0xff; 32],
        });
        apply(&mut st, &hub, 0, fork);
        assert!(st.slots[0].alive);
        assert_eq!(
            st.header_walk.tip_height(),
            5,
            "the fork height is the confirmed tip, not the queue tail"
        );
        assert_eq!(
            st.header_walk.milestone_hash(),
            Some(on_milestone),
            "a fork under the milestone drops the abandoned hash"
        );
        assert!(!st.ordered_set.contains(&h2.block_hash()));
    }

    #[test]
    fn a_short_refill_keeps_the_lookahead() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-short-refill");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let a3 = mine(a2.block_hash(), 3);
        let a4 = mine(a3.block_hash(), 4);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2, a3]);
        while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
            let Some(dropped) = st.ordered.pop_front() else {
                break;
            };
            st.ordered_set.remove(&dropped);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a4]);
        assert_eq!(st.header_walk.checkpoints().len(), 2);
        let tip = st.header_walk.tip_hash();
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![a2]);
        assert_eq!(hub.query.store().header_count(), before);
        assert!(st.ordered_set.contains(&a2.block_hash()));
        assert_eq!(st.header_walk.checkpoints().len(), 2);
        assert_eq!(
            st.header_walk.tip_hash(),
            tip,
            "a prefix that has not reached the next checkpoint is not a contradiction"
        );
    }

    #[test]
    fn a_divergent_refill_does_not_drop_a_proven_lookahead() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-proven-refill");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let sibling = mine(a1.block_hash(), 9);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: a2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert!(st.header_walk.proven);
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![sibling]);
        assert_eq!(hub.query.store().header_count(), before);
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        assert!(st
            .header_walk
            .checkpoints()
            .iter()
            .any(|c| c.hash == a2.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(sibling.block_hash().as_byte_array())
            .unwrap()
            .is_none());
        assert!(st.slots[0].alive);
    }

    #[test]
    fn a_header_between_checkpoints_does_not_skip_scripts() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-between-skip");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let h4 = mine(h3.block_hash(), 4);
        let side = mine(h1.block_hash(), 9);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 4,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h4.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, h1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h2, h3, h4]);
        assert!(st.header_walk.proven);
        assert!(
            skips(&hub, 1, h1.block_hash().as_byte_array()),
            "the queued ancestor of the milestone skips"
        );
        let before = hub.query.store().header_count();

        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(hub.query.store().header_count(), before);
        assert_eq!(
            hub.query.milestone_header_at(2),
            Some(h2.block_hash().to_byte_array())
        );
        assert!(!skips(&hub, 2, side.block_hash().as_byte_array()));
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(h4.block_hash()),
            "a one-block fork does not replace the candidate"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(h4.block_hash()));
        assert!(st.slots[0].alive);

        for _ in 0..3 {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(
            hub.query.store().header_count(),
            before,
            "a refill that has not reached the next checkpoint is not stored"
        );
        assert!(!st.ordered_set.contains(&side.block_hash()));
        assert!(!st.is_on_path(&side.block_hash(), 2));
        assert!(!skips(&hub, 2, side.block_hash().as_byte_array()));
        assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));
        assert_eq!(st.header_walk.tip_hash(), Some(h4.block_hash()));
        assert!(st.slots[0].alive);

        apply(&mut st, &hub, 0, vec![h2, h3, h4]);
        assert!(st.ordered_set.contains(&h2.block_hash()));
        assert!(
            skips(&hub, 2, h2.block_hash().as_byte_array()),
            "a refill that meets the milestone checkpoint skips"
        );
        assert!(skips(&hub, 4, h4.block_hash().as_byte_array()));
    }

    #[test]
    fn a_refill_stops_at_the_agreed_checkpoint() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-stop-at-ckpt");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let h4 = mine(h3.block_hash(), 4);
        let h5 = mine(h4.block_hash(), 5);
        let h6 = mine(h5.block_hash(), 6);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 6,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h6.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, h1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h2, h3]);
        while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
            let Some(dropped) = st.ordered.pop_front() else {
                break;
            };
            st.ordered_set.remove(&dropped);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h4, h5, h6]);
        assert!(st.header_walk.proven);
        assert_eq!(st.header_walk.tip_hash(), Some(h6.block_hash()));

        for _ in 0..3 {
            let dropped = st.ordered.pop_front().unwrap();
            st.ordered_set.remove(&dropped);
        }
        apply(&mut st, &hub, 0, vec![h2, h3, h4]);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(h6.block_hash()),
            "a prefix of the written chain is not a contradiction"
        );
        assert!(hub
            .query
            .get_header_by_hash(h3.block_hash().as_byte_array())
            .unwrap()
            .is_some());
        assert!(
            hub.query
                .get_header_by_hash(h4.block_hash().as_byte_array())
                .unwrap()
                .is_some(),
            "headers the walk already accepted stay written"
        );
        assert!(skips(&hub, 4, h4.block_hash().as_byte_array()));
        assert!(skips(&hub, 3, h3.block_hash().as_byte_array()));

        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let mut prev = h3.block_hash();
        let mut fork = Vec::new();
        for n in 40..44 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            fork.push(hdr);
        }
        let heavy = prev;
        apply(&mut st, &hub, 0, fork);
        assert!(
            st.slots[0].alive,
            "a heavier fork from the agreed checkpoint does not disconnect"
        );
        assert_eq!(st.header_walk.tip_height(), 7);
        assert_eq!(st.header_walk.tip_hash(), Some(heavy));
        assert!(st
            .header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != h6.block_hash()));
    }

    #[test]
    fn a_heavier_fork_from_a_stored_gap_header_is_adopted() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-gap-fork");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let h1 = mine(gen, 1);
        let h2 = mine(h1.block_hash(), 2);
        let h3 = mine(h2.block_hash(), 3);
        let h4 = mine(h3.block_hash(), 4);
        let h5 = mine(h4.block_hash(), 5);
        let h6 = mine(h5.block_hash(), 6);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 6,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: h6.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, h1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h2, h3]);
        while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
            let Some(dropped) = st.ordered.pop_front() else {
                break;
            };
            st.ordered_set.remove(&dropped);
        }
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![h4, h5, h6]);
        assert!(st.header_walk.proven);
        assert_eq!(st.header_walk.tip_hash(), Some(h6.block_hash()));

        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        apply(&mut st, &hub, 0, vec![h2, h3, h4]);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(h6.block_hash()),
            "a stored prefix between checkpoints does not replace the candidate"
        );
        assert!(st
            .header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != h2.block_hash()));
        assert!(hub
            .query
            .get_header_by_hash(h2.block_hash().as_byte_array())
            .unwrap()
            .is_some());

        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let mut prev = h2.block_hash();
        let mut fork = Vec::new();
        for n in 40..45 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            fork.push(hdr);
        }
        let heavy = prev;
        let fork_child = fork[0].block_hash();
        apply(&mut st, &hub, 0, fork);
        assert!(
            st.slots[0].alive,
            "a heavier fork from a stored header between checkpoints does not disconnect"
        );
        assert_eq!(st.header_walk.tip_height(), 7);
        assert_eq!(st.header_walk.tip_hash(), Some(heavy));
        assert!(
            st.is_on_path(&fork_child, 3),
            "the adopted fork becomes the download path"
        );
        assert!(!skips(&hub, 6, h6.block_hash().as_byte_array()));
    }

    /// Block that extends `prev` at `height`, with a real coinbase.
    fn mine_block(prev: BlockHash, height: u32) -> bitcoin::Block {
        use bitcoin::absolute::LockTime;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        let coinbase = Transaction {
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
        };
        let mut block = bitcoin::Block {
            header: mine(prev, height),
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        block
    }

    /// A block inv asks only once the header lane is idle. A fresh ask keeps
    /// the challenge until that reply lands.
    #[test]
    fn a_stale_announcement_asks_while_headers_are_done() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-inv-stale");
        hub.ensure_genesis().unwrap();
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
        st.headers_done = true;
        st.header_walk.challenge = Some(0);
        let poll = || HeaderPollIn {
            live: ORDERED_HEADERS_SOFT_CAP,
            need_ready_headroom: false,
            lag: 0,
            min_cache: 1,
            fan: 0,
        };
        assert!(
            matches!(header_poll(&st, poll()), HeaderPoll::Ask),
            "a block announcement with no header ask in flight still asks"
        );
        st.header_walk.walk.peer = Some(0);
        st.header_walk.walk.at = Some(std::time::Instant::now());
        assert!(
            matches!(header_poll(&st, poll()), HeaderPoll::Wait),
            "an announcement does not ask again while that header ask is in flight"
        );
    }

    /// Checkpoint timestamps are the median-time window when the tip has not
    /// copied them yet. The tip's own window wins once it has one.
    #[test]
    fn checkpoint_times_stand_in_for_an_empty_tip() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-times");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        floor_unreachable(&mut hub);
        let mut prev = gen;
        let mut chain = Vec::new();
        for n in 1..=12 {
            let hdr = mine(prev, n);
            prev = hdr.block_hash();
            chain.push(hdr);
        }
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, chain.clone());
        let tip = chain[11];
        let real = st.header_walk.tip.times.clone();
        assert_eq!(real.len(), 11);
        let raised: Vec<u32> = real.iter().map(|t| t.saturating_add(10_000)).collect();
        st.header_walk.checkpoints.last_mut().unwrap().times = raised.clone();
        st.header_walk.tip.times.clear();
        let from_checkpoint = times_ending_at(&st, &hub, tip.block_hash());
        assert_eq!(
            from_checkpoint, raised,
            "an empty tip takes the checkpoint median-time window"
        );
        st.header_walk.tip.times = real.clone();
        let from_tip = times_ending_at(&st, &hub, tip.block_hash());
        assert_eq!(
            from_tip, real,
            "the tip's own window is kept when a checkpoint disagrees"
        );
    }

    /// Two empty replies abandon the candidate. The previous dead tip stays
    /// dead, and a queued hash with no height is not the abandoned one.
    #[test]
    fn two_abandoned_candidates_both_stay_dead() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-two-dead");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let b1 = mine(gen, 11);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        let kept = BlockHash::from_byte_array([0x44; 32]);
        st.ordered.push_back(kept);
        st.ordered_set.insert(kept);
        apply(&mut st, &hub, 0, vec![]);
        apply(&mut st, &hub, 1, vec![]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(
            st.header_walk.dead_ends.contains(&a1.block_hash()),
            "the first abandoned tip stays dead"
        );
        assert!(
            st.ordered_set.contains(&kept),
            "a queued hash with no height is not the dead tip"
        );

        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![b1]);
        apply(&mut st, &hub, 0, vec![]);
        apply(&mut st, &hub, 1, vec![]);
        assert!(st.header_walk.dead_ends.contains(&a1.block_hash()));
        assert!(
            st.header_walk.dead_ends.contains(&b1.block_hash()),
            "a second abandoned tip does not forget the first"
        );
    }

    /// Equal work is a challenger, not a new tip. One more header promotes
    /// it and drops checkpoints above the fork.
    #[test]
    fn a_tied_challenger_stays_off_the_tip_until_it_is_heavier() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-tie");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let a3 = mine(a2.block_hash(), 3);
        let s2 = mine(a1.block_hash(), 12);
        let s3 = mine(s2.block_hash(), 13);
        let s4 = mine(s3.block_hash(), 14);
        let weak = mine(a1.block_hash(), 21);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a3]);
        assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .any(|c| c.hash == a1.block_hash()),
            "the first lookahead is a checkpoint below the tip"
        );

        let replay = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![a1]);
        assert_eq!(
            hub.query.store().header_count(),
            replay,
            "a batch that ends on an earlier checkpoint is not a new chain"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
        assert!(
            st.header_walk.challenger.is_none(),
            "replaying a checkpoint does not open a challenger"
        );
        assert!(st.slots[0].alive);

        apply(&mut st, &hub, 0, vec![s2]);
        assert_eq!(
            st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
            Some(s2.block_hash()),
            "a lighter fork is remembered"
        );
        assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
        apply(&mut st, &hub, 0, vec![weak]);
        assert_eq!(
            st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
            Some(s2.block_hash()),
            "a lighter fork does not replace the challenger"
        );
        apply(&mut st, &hub, 0, vec![s3]);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(a3.block_hash()),
            "matching work does not promote the challenger"
        );
        assert_eq!(
            st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
            Some(s3.block_hash()),
            "the tied extension is still the challenger"
        );

        apply(&mut st, &hub, 0, vec![s4]);
        assert_eq!(
            st.header_walk.tip_hash(),
            Some(s4.block_hash()),
            "one header past the tie replaces the candidate"
        );
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .any(|c| c.hash == a1.block_hash()),
            "checkpoints at or below the fork stay"
        );
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .all(|c| c.hash != a3.block_hash()),
            "checkpoints above the fork are dropped"
        );
    }

    /// A rewind to the fork height keeps that checkpoint and the challenger.
    /// Dropping every checkpoint above the base drops the challenger too.
    #[test]
    fn rewind_keeps_a_challenger_forked_at_a_live_checkpoint() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-retain");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let side = mine(a1.block_hash(), 12);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(
            st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
            Some(a1.block_hash()),
            "the side header forks at the first checkpoint"
        );
        rewind_above(&mut st, &hub, 1);
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .any(|c| c.hash == a1.block_hash()),
            "the checkpoint at the rewind height stays"
        );
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .all(|c| c.hash != a2.block_hash()),
            "a checkpoint above the rewind is popped"
        );
        assert!(
            st.header_walk
                .challenger
                .as_ref()
                .is_some_and(|c| c.fork_hash == a1.block_hash()),
            "the challenger stays while its fork checkpoint is on the walk"
        );
        rewind_above(&mut st, &hub, 0);
        assert!(
            st.header_walk.challenger.is_none(),
            "rewinding under the fork drops the challenger"
        );
    }

    /// The fork is the walk base, and the tip is a later checkpoint. Rewinding
    /// onto that checkpoint must keep the challenger: the base is still on the
    /// candidate even though the tip hash is not the fork.
    #[test]
    fn rewind_keeps_a_challenger_forked_at_the_base() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-retain-base");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let side = mine(gen, 12);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(
            st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
            Some(gen),
            "the side header forks at the confirmed base"
        );
        rewind_above(&mut st, &hub, 1);
        assert_eq!(st.header_walk.tip_hash(), Some(a1.block_hash()));
        assert!(
            st.header_walk
                .challenger
                .as_ref()
                .is_some_and(|c| c.fork_hash == gen),
            "the challenger stays while the walk base is its fork"
        );
    }

    /// Popping the fork's checkpoint, while an earlier checkpoint remains,
    /// drops the challenger. The fork is neither the base nor the new tip.
    #[test]
    fn rewind_drops_a_challenger_when_its_fork_checkpoint_is_gone() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-retain-drop");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let a3 = mine(a2.block_hash(), 3);
        let side = mine(a2.block_hash(), 12);
        floor_unreachable(&mut hub);
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        fill_queue(&mut st);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a1]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a3]);
        apply(&mut st, &hub, 0, vec![side]);
        assert_eq!(
            st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
            Some(a2.block_hash()),
            "the side header forks at the middle checkpoint"
        );
        rewind_above(&mut st, &hub, 1);
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .any(|c| c.hash == a1.block_hash()),
            "the checkpoint under the cut stays"
        );
        assert!(
            st.header_walk
                .checkpoints()
                .iter()
                .all(|c| c.hash != a2.block_hash()),
            "the fork checkpoint above the cut is popped"
        );
        assert!(
            st.header_walk.challenger.is_none(),
            "a fork that is no longer a base, tip, or checkpoint is dropped"
        );
    }

    /// A diverging refill whose headers do not link is not a chain. Comparing
    /// its first header would remember a challenger for a reply that breaks.
    #[test]
    fn an_unlinked_divergent_refill_is_not_a_challenger() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-unlinked");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let a1 = mine(gen, 1);
        let a2 = mine(a1.block_hash(), 2);
        let sibling = mine(a1.block_hash(), 9);
        let broken = mine(gen, 11);
        let mut floor = [0u8; 32];
        floor[31] = 1;
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 2,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: a2.block_hash(),
                min_work_be: floor,
            }),
        };
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        queue_at_cap_ending_on(&mut st, &hub, a1);
        assert!(send_getheaders(&mut st, &hub).unwrap());
        apply(&mut st, &hub, 0, vec![a2]);
        assert!(st.header_walk.proven);
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        let before = hub.query.store().header_count();
        apply(&mut st, &hub, 0, vec![sibling, broken]);
        assert_eq!(hub.query.store().header_count(), before);
        assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
        assert!(
            st.header_walk.challenger.is_none(),
            "a batch that does not link is not a competing chain"
        );
        assert!(st.slots[0].alive);
    }

    /// The walk base is genesis and the download path has a hole under the
    /// confirmed tip, so only the confirmed tip can price the next header.
    #[test]
    fn stored_work_uses_the_confirmed_tip_when_the_base_does_not_link() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-walk-stored-tip");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let gen_work = hub.chain_work().unwrap();
        hub.generate_to_script(2, bitcoin::ScriptBuf::from_bytes(vec![0x51]), Vec::new())
            .unwrap();
        let tip = hub.tip_hash().unwrap();
        let tip_h = hub.tip_height().unwrap();
        let mut next = mine(tip, 40);
        next.time = hub.tip_header().unwrap().time.saturating_add(60);
        rbitcoin_consensus::grind_regtest_pow(&mut next);
        hub.ensure_header(&next).unwrap();
        let (s0, _rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        st.header_walk.base_hash = Some(gen);
        st.header_walk.base_height = 0;
        st.header_walk.base_work = gen_work.to_be_bytes();
        st.header_walk.checkpoints.push(Checkpoint {
            hash: BlockHash::from_byte_array([0xab; 32]),
            height: tip_h + 10,
            work: [0u8; 32],
            header: None,
            times: Vec::new(),
            diff: DiffSnap::default(),
        });
        st.record_height(next.block_hash(), tip_h + 1);
        let (work, _) = stored_path_state(&st, &hub, next.block_hash())
            .expect("the confirmed tip prices a header the base cannot reach");
        assert_eq!(work, hub.chain_work().unwrap() + next.work());
    }

    fn byte_hash(n: u8) -> BlockHash {
        let mut raw = [0u8; 32];
        raw[31] = n;
        BlockHash::from_byte_array(raw)
    }

    fn mark_checkpoint(hash: BlockHash, height: u32) -> Checkpoint {
        Checkpoint {
            hash,
            height,
            work: [0; 32],
            header: None,
            times: Vec::new(),
            diff: DiffSnap::default(),
        }
    }

    fn fresh_walk() -> IbdWorkState {
        let (peer, _rx) = slot(0);
        IbdWorkState::new(vec![peer], None, None)
    }

    fn plant_challenger(st: &mut IbdWorkState, fork: BlockHash) {
        st.header_walk.challenger = Some(Challenger {
            fork_hash: fork,
            fork_height: 1,
            tip: WalkTip::default(),
            checkpoints: Vec::new(),
        });
    }

    #[test]
    fn retain_challenger_keeps_a_fork_that_is_still_on_the_candidate() {
        let fork = byte_hash(1);
        let other = byte_hash(2);
        let mut st = fresh_walk();
        st.header_walk.base_hash = Some(fork);
        plant_challenger(&mut st, fork);
        retain_challenger(&mut st);
        assert!(
            st.header_walk.challenger.is_some(),
            "the walk base still holds the fork"
        );

        st.header_walk.base_hash = Some(other);
        st.header_walk.checkpoints.push(mark_checkpoint(fork, 4));
        retain_challenger(&mut st);
        assert!(
            st.header_walk.challenger.is_some(),
            "a checkpoint still holds the fork"
        );

        st.header_walk.checkpoints.clear();
        retain_challenger(&mut st);
        assert!(
            st.header_walk.challenger.is_none(),
            "a fork off the candidate is dropped"
        );
    }

    #[test]
    fn adopt_heavier_keeps_the_milestone_at_the_fork_height() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("hdr-adopt-pin");
        hub.ensure_genesis().unwrap();
        let prev = byte_hash(3);
        let header = Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([4; 32]),
            time: 1_600_000_100,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 1,
        };
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), hub.tip_height());
        st.hash_height.insert(prev, 5);
        hub.milestone.height = 5;
        let marker = byte_hash(9);
        st.header_walk.tip.milestone_hash = Some(marker);
        let mut raw = [0u8; 32];
        raw[31] = 9;
        let passed = Work::from_be_bytes(raw);
        adopt_heavier(&mut st, &hub, prev, &[header], passed);
        assert_eq!(st.header_walk.tip.milestone_hash, Some(marker));
        assert_eq!(st.header_walk.tip.work, passed);
    }

    #[test]
    fn walk_ahead_of_stored_is_strictly_above_the_recorded_height() {
        let mut st = fresh_walk();
        st.header_walk.origin = true;
        st.header_walk.tip.height = 4;
        st.max_ordered_height = 4;
        assert!(!walk_ahead_of_stored(&st));
        st.header_walk.tip.height = 5;
        assert!(walk_ahead_of_stored(&st));
    }

    #[test]
    fn classify_pins_an_unlinked_batch_a_refill_and_the_first_checkpoint() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-classify-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let mut broken = mine(good.block_hash(), 2);
        broken.prev_blockhash = byte_hash(8);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        assert_eq!(
            classify(&st, &hub, HeaderAsk::InWindow, &[good, broken]),
            HeaderClass::Fork,
            "an unlinked batch is not a refill of the stored tip"
        );
        assert_eq!(
            classify(&st, &hub, HeaderAsk::InWindow, &[good]),
            HeaderClass::Refill
        );

        st.header_walk.origin = true;
        st.header_walk.tip.hash = Some(gen);
        st.header_walk.tip.height = 0;
        assert_eq!(
            classify(&st, &hub, HeaderAsk::InWindow, &[good]),
            HeaderClass::WalkAbsorb,
            "the first solicited continuation is a checkpoint"
        );
    }

    #[test]
    fn headers_late_is_logged_only_for_a_late_extension() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-late-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 7);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        st.header_walk.origin = true;
        st.header_walk.tip.hash = Some(gen);
        st.header_walk.tip.height = 0;
        st.header_walk.tip.header = hub.tip_header();
        rbitcoin_log::capture_logs(true);
        assert!(absorb_lookahead(
            &mut st,
            &hub,
            0,
            HeaderAsk::InWindow,
            &[good]
        ));
        let on_time = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            on_time
                .iter()
                .all(|(_, line)| !line.contains("ibd: headers late")),
            "an in-window extension is not late: {on_time:?}"
        );

        let next = mine(good.block_hash(), 8);
        rbitcoin_log::capture_logs(true);
        assert!(absorb_lookahead(&mut st, &hub, 0, HeaderAsk::Late, &[next]));
        let late = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            late.iter()
                .any(|(_, line)| line.contains("ibd: headers late")),
            "a late extension names itself: {late:?}"
        );
    }

    fn floor_above(hub: &mut ChainHub) {
        hub.milestone = rbitcoin_consensus::Milestone {
            height: 100,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: byte_hash(1),
                min_work_be: [0xff; 32],
            }),
        };
    }

    #[test]
    fn ignore_below_floor_pins_the_floor_gate_and_the_queue_cap() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("hdr-floor-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        st.header_walk.origin = true;
        st.header_walk.tip.hash = Some(byte_hash(3));
        st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
        st.header_walk.dead_ends.insert(gen);
        assert!(
            !ignore_below_floor(&st, &hub, &[good]),
            "above the floor a dead-end parent is not ignored"
        );

        floor_above(&mut hub);
        st.header_walk.origin = false;
        assert!(
            !ignore_below_floor(&st, &hub, &[good]),
            "below the floor a walk that has not started is not ignored"
        );
        st.header_walk.origin = true;
        st.header_walk.dead_ends.clear();
        assert!(
            !ignore_below_floor(&st, &hub, &[good]),
            "under the cap the stored tip's child is still the download path"
        );
        fill_queue(&mut st);
        plant_on_queue(&mut st, gen, 0);
        assert!(
            ignore_below_floor(&st, &hub, &[good]),
            "a full queue does not keep writing that child"
        );
    }

    fn heavy_proved(st: &mut IbdWorkState, hub: &ChainHub) {
        st.header_walk.origin = true;
        st.header_walk.proven = true;
        st.header_walk.tip.hash = hub.tip_hash();
        st.header_walk.tip.height = hub.tip_height().unwrap_or(0);
        st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
    }

    #[test]
    fn reject_refill_miss_pins_each_reason_it_returns() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-refill-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 3);
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        heavy_proved(&mut st, &hub);
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(9), 1));
        st.header_walk.origin = false;
        assert!(
            !reject_refill_miss(&mut st, &hub, &[good]),
            "a walk with no origin does not judge the refill"
        );

        heavy_proved(&mut st, &hub);
        st.header_walk.checkpoints.clear();
        let queued = byte_hash(8);
        st.ordered.push_back(queued);
        st.ordered_set.insert(queued);
        st.hash_height.insert(queued, 1);
        assert!(
            !reject_refill_miss(&mut st, &hub, &[good]),
            "no checkpoint means there is nothing to miss"
        );
        st.ordered.clear();
        st.ordered_set.clear();
        st.hash_height.remove(&queued);

        heavy_proved(&mut st, &hub);
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(9), 1));
        fill_queue(&mut st);
        plant_on_queue(&mut st, gen, 0);
        assert!(
            !reject_refill_miss(&mut st, &hub, &[good]),
            "a full queue is not a refill"
        );

        let stray = mine(byte_hash(7), 4);
        let (peer, _rx) = slot(1);
        let mut open = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        heavy_proved(&mut open, &hub);
        open.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(9), 1));
        open.header_walk.tip.hash = Some(byte_hash(6));
        assert!(
            !reject_refill_miss(&mut open, &hub, &[stray]),
            "a batch that does not build on the confirmed tip is not a refill miss"
        );
    }

    #[test]
    fn proved_above_floor_requires_both() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-proved-pin");
        hub.ensure_genesis().unwrap();
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), Some(0));
        st.header_walk.proven = false;
        st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
        assert!(!proved_above_floor(&st, &hub));
        st.header_walk.proven = true;
        assert!(proved_above_floor(&st, &hub));
    }

    #[test]
    fn unproved_anchor_stops_at_a_met_checkpoint_and_keeps_the_one_below() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-anchor-pin");
        hub.ensure_genesis().unwrap();
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), Some(0));
        let front = byte_hash(5);
        st.ordered.push_back(front);
        st.ordered_set.insert(front);
        st.hash_height.insert(front, 5);
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(3), 3));
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(4), 5));
        assert!(unproved_anchor(&st, &hub).is_none());

        st.header_walk.checkpoints.pop();
        assert_eq!(unproved_anchor(&st, &hub), Some((byte_hash(3), 3)));

        st.header_walk.checkpoints.clear();
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(3), 3));
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(6), 3));
        assert_eq!(
            unproved_anchor(&st, &hub),
            Some((byte_hash(3), 3)),
            "two checkpoints at one height keep the earlier hash"
        );
    }

    #[test]
    fn candidate_prev_accepts_base_tip_and_checkpoint() {
        let prev = byte_hash(1);
        let mut st = fresh_walk();
        st.header_walk.base_hash = Some(prev);
        assert!(candidate_prev(&st, prev));
        st.header_walk.base_hash = None;
        st.header_walk.tip.hash = Some(prev);
        assert!(candidate_prev(&st, prev));
        st.header_walk.tip.hash = None;
        st.header_walk.checkpoints.push(mark_checkpoint(prev, 2));
        assert!(candidate_prev(&st, prev));
        st.header_walk.checkpoints.clear();
        assert!(!candidate_prev(&st, prev));
    }

    fn prefix_body(st: &mut IbdWorkState, _hub: &ChainHub, prev: BlockHash) -> Vec<Header> {
        st.header_walk.proven = true;
        st.header_walk.origin = true;
        st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
        st.header_walk.base_hash = Some(prev);
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(9), 50));
        vec![mine(prev, 11)]
    }

    #[test]
    fn proven_header_prefix_writes_the_whole_reply_until_the_candidate_is_proved() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("hdr-prefix-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        let prev = byte_hash(4);
        let headers = prefix_body(&mut st, &hub, prev);
        st.header_walk.proven = false;
        assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
        st.header_walk.proven = true;
        st.header_walk.origin = false;
        assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
        st.header_walk.origin = true;
        floor_above(&mut hub);
        st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
        assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
        hub.milestone.anchor = None;
        st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
        assert_eq!(
            proven_header_prefix(&st, &hub, &headers),
            0,
            "a proved candidate writes no header that misses the checkpoint"
        );
    }

    #[test]
    fn refill_misses_checkpoint_only_above_the_queue_tail() {
        let tail = byte_hash(1);
        let first = mine(tail, 21);
        let second = mine(first.block_hash(), 22);
        let mut st = fresh_walk();
        st.header_walk.checkpoints.push(mark_checkpoint(tail, 5));
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(first.block_hash(), 6));
        st.header_walk
            .checkpoints
            .push(mark_checkpoint(byte_hash(8), 7));
        assert!(refill_misses_checkpoint(&st, 5, &[first, second]));
        st.header_walk.checkpoints.clear();
        st.header_walk.checkpoints.push(mark_checkpoint(tail, 5));
        assert!(!refill_misses_checkpoint(&st, 5, &[first]));
    }

    #[test]
    fn note_empty_rewinds_only_when_every_taller_peer_is_empty() {
        let (_dir, mut hub) = crate::chain::tiny_regtest_hub_labeled("hdr-empty-pin");
        hub.ensure_genesis().unwrap();
        floor_above(&mut hub);
        let gen = hub.tip_hash().unwrap();
        let (mut tall, _rx0) = slot(0);
        tall.peer_height = 10;
        let (mut level, _rx1) = slot(1);
        level.peer_height = 3;
        let mut st = IbdWorkState::new(vec![tall, level], Some(gen), Some(0));
        st.header_walk.origin = true;
        st.header_walk.base_hash = Some(gen);
        st.header_walk.base_height = 0;
        st.header_walk.tip.hash = Some(byte_hash(4));
        st.header_walk.tip.height = 3;
        st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
        assert!(note_empty(&mut st, &hub, 0));
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
    }

    #[test]
    fn note_stored_candidate_ignores_a_dead_end_tip() {
        let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("hdr-stored-pin");
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let (peer, _rx) = slot(0);
        let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
        st.header_walk.origin = true;
        st.header_walk.tip.hash = Some(gen);
        st.header_walk.tip.height = 0;
        st.header_walk.dead_ends.insert(gen);
        note_stored_candidate(&mut st, &hub, &[mine(gen, 30)]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(st.header_walk.checkpoints.is_empty());

        st.header_walk.dead_ends.clear();
        let mut broken = mine(gen, 31);
        broken.bits = CompactTarget::from_consensus(0x1d00ffff);
        note_stored_candidate(&mut st, &hub, &[broken]);
        assert_eq!(st.header_walk.tip_hash(), Some(gen));
        assert!(st.header_walk.checkpoints.is_empty());
    }
}
