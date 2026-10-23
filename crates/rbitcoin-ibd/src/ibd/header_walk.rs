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
//! 2,000-header window that advances a lighter fork stays eligible. A
//! block inv is one challenge ask when that peer is not already the walk's
//! next ask: a reply that beats the candidate takes the reservation, and any
//! other reply leaves it where it was. One competing chain is kept until it
//! loses or replaces the candidate. Work for a stored header between
//! checkpoints is the previous checkpoint plus those stored headers. That
//! replay runs only when a competing headers batch forks there.

use super::state::{ConfirmedLocatorTail, IbdWorkState};
use super::ORDERED_HEADERS_SOFT_CAP;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::Work;
use rbitcoin_net::chain::ChainHub;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Difficulty state after a header, so a fork or rewind can retarget without
/// the abandoned tip's period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct DiffSnap {
    /// Header that opened the current difficulty period.
    pub period_header: Option<Header>,
    pub period_height: u32,
    /// Last header in this period whose `nBits` are not the min-difficulty limit.
    pub full_diff_bits: Option<CompactTarget>,
    pub full_diff_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub hash: BlockHash,
    pub height: u32,
    pub work: [u8; 32],
    /// Last header of this reply. Lets the next batch check `nBits` and time
    /// without a row in `header.body`.
    pub header: Option<Header>,
    /// Up to 11 timestamps ending at `header`, oldest first.
    pub times: Vec<u32>,
    /// Difficulty after this reply. A later fork from this hash retargets
    /// from here, not from the walk tip.
    pub diff: DiffSnap,
}

/// Fork point, the chain built from it, and one checkpoint per reply.
/// Replaced when a different fork has more work, or when it beats the candidate.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct Challenger {
    pub fork_hash: BlockHash,
    pub fork_height: u32,
    pub tip: WalkTip,
    pub checkpoints: Vec<Checkpoint>,
}

#[derive(Debug, Default)]
pub struct HeaderWalk {
    pub checkpoints: Vec<Checkpoint>,
    /// Confirmed tip, or the stored path tip, before any look-ahead checkpoint.
    pub base_hash: Option<BlockHash>,
    pub base_height: u32,
    pub base_work: [u8; 32],
    /// Moving candidate. Hash stays empty until the origin is known.
    pub tip: WalkTip,
    pub origin: bool,
    /// Look-ahead tips that every peer left empty before the work floor.
    pub dead_ends: HashSet<BlockHash>,
    /// The last header of each refused batch that built on a rejected block.
    /// A batch that builds on one is refused too.
    pub invalid_tips: HashSet<BlockHash>,
    /// `invalid_tips` in insertion order, so the cap drops the oldest.
    pub invalid_tip_order: std::collections::VecDeque<BlockHash>,
    /// Peers that have answered empty at the current tip.
    pub emptied: HashSet<usize>,
    /// Checkpoint work has reached the milestone floor.
    pub proven: bool,
    /// Stored header hashes from this peer that are not on the download path.
    pub off_path: std::collections::HashMap<usize, HashSet<BlockHash>>,
    /// The caught-up line has already been logged. The status thread keeps
    /// its own latch; this one exists so header-walk tests can see it.
    #[cfg(debug_assertions)]
    pub announced_done: bool,
    /// Peers retired from the walk after a reply made no useful progress.
    /// A block inv or a redial clears the bit. Not written to `header.adopt`.
    pub walk_quiet: HashSet<usize>,
    /// Peer that serves the one headers ask. Not written to `header.adopt`.
    pub reserved: Option<usize>,
    /// One ask owed after a block inv.
    pub challenge: Option<usize>,
    /// The challenge came from a session that has no header slot. A reply
    /// that does not beat the candidate must not retire the reserved peer.
    pub challenge_external: bool,
    /// Challenge ask already sent. Judged when that peer replies or times out.
    pub challenge_open: Option<usize>,
    /// Block peer owed one chain probe: a headers ask from the confirmed tip.
    /// Not a walk ask. Not written to `header.adopt`.
    pub probe: Option<usize>,
    /// Probe ask already sent. Its reply is read into that peer's chain
    /// record, not by the walk.
    pub probe_open: Option<usize>,
    /// The path top the open probe asked headers after; none when it asked
    /// from the confirmed tip.
    pub probe_top: Option<(u32, BlockHash)>,
    /// The one in-flight headers ask. Not written to `header.adopt`.
    pub walk: Lane,
    /// Expired asks. Not written to `header.adopt`.
    pub header_misses: HashMap<usize, u8>,
    /// Difficulty at `base_hash`, restored when every checkpoint is rewound.
    pub base_diff: DiffSnap,
    /// Heavier-so-far alternate that has not yet passed the candidate.
    pub challenger: Option<Challenger>,
    /// Confirmed chain already proved the anchor; stop stat'ing the sidecar.
    pub adopt_retired: bool,
}

/// One in-flight header ask on one lane. Not written to `header.adopt`.
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct Lane {
    pub peer: Option<usize>,
    pub at: Option<Instant>,
    /// The peer asked before this one. A late reply can still count.
    pub prev_peer: Option<usize>,
}

/// How long one header reply may take before another peer is asked.
/// Each lane has its own request. A miss skips that peer on that lane when
/// someone else can be asked. A second miss on the same lane disconnects them.
/// Shorter than a stall cooldown: one headers reply, not a silent peer.
#[doc(hidden)]
pub const LOOKAHEAD_ASK: Duration = Duration::from_secs(5);
/// Missed header asks before the peer is disconnected, same as a block stall.
#[doc(hidden)]
pub const HEADER_MISS_DISCONNECT: u8 = 2;
#[doc(hidden)]
pub const DEAD_END_CAP: usize = 1024;
/// Past the cap the oldest refused tip gives way, so the newest is kept: the
/// next batch of a long invalid chain links to it.
const INVALID_TIP_CAP: usize = 1024;

impl HeaderWalk {
    pub fn tip_height(&self) -> u32 {
        self.tip.height
    }

    /// The walk has met the work floor and is not past `tip_h`.
    pub fn proved_at_or_below(&self, tip_h: u32) -> bool {
        self.proven && self.tip.height <= tip_h
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.tip.hash
    }

    #[doc(hidden)]
    pub fn tip_work(&self) -> [u8; 32] {
        self.tip.work.to_be_bytes()
    }

    #[doc(hidden)]
    pub fn tip_header(&self) -> Option<Header> {
        self.tip.header
    }

    #[doc(hidden)]
    pub fn milestone_hash(&self) -> Option<BlockHash> {
        self.tip.milestone_hash
    }

    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    pub fn has_checkpoints(&self) -> bool {
        !self.checkpoints.is_empty()
    }

    /// Candidate tip, then a lighter fork, then earlier checkpoints.
    pub fn locator_hashes(&self) -> Vec<BlockHash> {
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
    pub fn next_height(&self) -> Option<u32> {
        self.tip.hash?;
        Some(self.tip.height.saturating_add(1))
    }

    /// `height` is on the candidate and past the queue, so hygiene keeps it.
    ///
    /// The origin and the tip hash are installed together. Hygiene then only
    /// needs the height to sit on that tip, above the genesis parent.
    pub fn indexes_through(&self, height: u32) -> bool {
        if self.tip.hash.is_none() || !self.origin || height == 0 {
            return false;
        }
        height <= self.tip.height
    }

    /// Test stand-in for a walk that already proved the confirmed tip.
    #[cfg(debug_assertions)]
    pub fn prove_through(&mut self, height: u32) {
        self.origin = true;
        self.proven = true;
        self.tip.height = height;
    }
}

pub struct OriginInput {
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

pub struct OriginLoaded {
    pub height: u32,
    pub hash: Option<BlockHash>,
    pub work: Work,
    pub milestone_hash: Option<BlockHash>,
    pub milestone_prev: BlockHash,
    pub milestone_header: Option<Header>,
    pub tip_header: Option<Header>,
}

pub fn origin_input(st: &IbdWorkState, hub: &ChainHub) -> OriginInput {
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
pub fn load_origin(hub: &ChainHub, input: &OriginInput) -> OriginLoaded {
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

pub fn install_origin(st: &mut IbdWorkState, hub: &ChainHub, loaded: OriginLoaded) {
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

#[doc(hidden)]
pub fn ensure_origin(st: &mut IbdWorkState, hub: &ChainHub) {
    if st.header_walk.origin {
        return;
    }
    let input = origin_input(st, hub);
    let loaded = load_origin(hub, &input);
    install_origin(st, hub, loaded);
}

#[doc(hidden)]
pub fn below_floor(hub: &ChainHub, work: &[u8; 32]) -> bool {
    match hub.milestone.anchor {
        Some(anchor) => work < &anchor.min_work_be,
        None => false,
    }
}

/// Header fields for the status thread. No store read.
pub struct HeaderStatusView {
    pub origin: bool,
    pub height: u32,
    pub stored: u32,
    pub queue: usize,
    pub work_ok: bool,
    pub walk: bool,
    pub quiet: bool,
    pub horizon: u32,
}

pub fn header_status_view(st: &IbdWorkState, hub: &ChainHub) -> HeaderStatusView {
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
#[cfg(debug_assertions)]
pub fn log_status(st: &mut IbdWorkState, hub: &ChainHub, horizon: u32) {
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
pub fn wants_lookahead(st: &IbdWorkState) -> bool {
    let tip = st.header_walk.tip_height();
    st.slots
        .iter()
        .any(|s| s.alive && s.peer_height > tip && !st.header_walk.walk_quiet.contains(&s.id))
}

/// The proven walk is at or below the confirmed tip, and every connected
/// peer that advertised more has failed to extend it.
pub fn headers_complete(st: &IbdWorkState, tip_h: u32) -> bool {
    st.header_walk.origin
        && st.header_walk.proven
        && st.header_walk.tip_height() <= tip_h
        && !wants_lookahead(st)
}

/// Height the progress line counts toward. Before the walk has an origin,
/// the advertised high-water mark. After that, the walk tip or the tallest
/// connected peer still on the walk: a peer that disconnected or failed to
/// extend the walk no longer sets it. Exit still uses `max_peer_height`.
pub fn peer_horizon(st: &IbdWorkState) -> u32 {
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
pub fn candidate_tip(st: &IbdWorkState) -> Option<BlockHash> {
    st.header_walk.tip_hash()
}

/// Retire `peer` from the walk when this reply did not extend the candidate.
///
/// A full [`rbitcoin_net::codec::MAX_HEADERS_RESULTS`] window stays only when
/// it advances a lighter fork, so that fork can grow across locators without
/// repeated batches holding IBD open. Below the work floor the empty-reply
/// rewind still owns the peer. An extension, a block inv, or peer death
/// clears a previous retirement.
pub fn settle_walk_peer(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    tip_before: Option<BlockHash>,
    queued_before: usize,
    challenger_work_before: Option<Work>,
    batch_len: usize,
) {
    let fork_advanced = batch_len >= rbitcoin_net::codec::MAX_HEADERS_RESULTS
        && st
            .header_walk
            .challenger
            .as_ref()
            .is_some_and(|ch| challenger_work_before.is_none_or(|before| ch.tip.work > before));
    let extended = st.header_walk.tip_hash() != tip_before
        || st.ordered.len() > queued_before
        || fork_advanced;
    if extended {
        st.header_walk.walk_quiet.remove(&peer);
    }
    if !st.header_walk.origin {
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
pub fn note_block_inv(st: &mut IbdWorkState, peer: usize) {
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

/// Heights above the confirmed tip a peer's record should decide before it
/// is probed again.
const PROBE_AHEAD: u32 = 4_096;

/// Ask one block peer for headers, so block getdata follows what it holds:
/// one that has not announced a chain (Core starts header sync with each
/// peer), or one whose record no longer decides the next blocks. One probe
/// at a time, never the reserved header peer, and not a peer with a walk ask
/// open.
pub fn probe_unprobed_peer(st: &mut IbdWorkState, hub: &ChainHub) {
    use super::peer_io::PeerSlot;
    let walk = &st.header_walk;
    // A record only chooses among peers. With one live peer it would only
    // take the header lane, and its reply would not reach the walk.
    if walk.probe.is_some()
        || walk.probe_open.is_some()
        || st.slots.iter().filter(|s| s.alive).count() < 2
    {
        return;
    }
    let tip = hub.tip_height().unwrap_or(0);
    let ahead = tip.saturating_add(PROBE_AHEAD).min(st.max_ordered_height);
    let now = Instant::now();
    let due = |s: &PeerSlot| {
        !s.chain.probed() || (ahead > tip && s.chain.needs_refresh(&st.height_to_hash, ahead, now))
    };
    let Some(slot) = st
        .slots
        .iter()
        .find(|s| s.alive && !walk_busy(walk, s.id) && due(s))
    else {
        return;
    };
    st.header_walk.probe = Some(slot.id);
}

/// The header peer, or a peer with a walk ask open or expired and not yet
/// answered, whose late reply could be read as a probe's.
fn walk_busy(walk: &HeaderWalk, peer: usize) -> bool {
    [
        walk.reserved,
        walk.challenge_open,
        walk.walk.peer,
        walk.walk.prev_peer,
    ]
    .contains(&Some(peer))
        || walk.header_misses.contains_key(&peer)
}

/// A follow-session block inv has no IBD slot. Poke one live header peer
/// the same way [`note_block_inv`] does. Returns false when nobody is live
/// yet, so the caller keeps the flag.
pub fn note_external_block_inv(st: &mut IbdWorkState) -> bool {
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
pub fn forget_walk_peer(st: &mut IbdWorkState, peer: usize) {
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
    if st.header_walk.probe == Some(peer) {
        st.header_walk.probe = None;
    }
    if st.header_walk.probe_open == Some(peer) {
        st.header_walk.probe_open = None;
        st.header_walk.probe_top = None;
    }
}

/// Chainwork of the candidate, for judging a challenge reply.
pub fn candidate_work(st: &IbdWorkState) -> [u8; 32] {
    st.header_walk.tip_work()
}

/// Move the reservation when this reply beat the candidate, or retire a
/// challenge that did not. A reserved peer who was just retired loses it.
pub fn note_reservation(
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

/// Whether block `hash` may be asked of `peer`. As in Core, a peer is asked
/// only for a block its chain showed (`PeerChain::shows`), and not for one it
/// answered `notfound`. The reserved header peer is asked only when no other
/// peer shows the block. A single peer still does both.
pub fn may_serve(st: &IbdWorkState, peer: usize, hash: &BlockHash) -> bool {
    use super::peer_io::PeerSlot;
    let height = st.hash_height.get(hash).copied();
    let now = super::peer_io::ibd_mono_ms();
    let path = &st.height_to_hash;
    let askable = |s: &PeerSlot| s.alive && !s.chain.lacks(hash, now);
    let shows = |s: &PeerSlot| askable(s) && height.is_some_and(|ht| s.chain.shows(path, ht));
    let open =
        |s: &PeerSlot| askable(s) && !height.is_some_and(|ht| s.chain.left_path_by(path, ht));
    let Some(slot) = st.slots.iter().find(|s| s.id == peer) else {
        return false;
    };
    // With no peer that shows the block, a record can be stale: a peer whose
    // chain has not left the path is asked, else any peer that did not answer
    // `notfound`, the header peer too. Otherwise the header peer stays on
    // headers while another peer can fetch the block.
    let tier: &dyn Fn(&PeerSlot) -> bool = if st.slots.iter().any(&shows) {
        &shows
    } else if st.slots.iter().any(&open) {
        &open
    } else {
        return askable(slot);
    };
    tier(slot)
        && (st.header_walk.reserved != Some(peer)
            || !st.slots.iter().any(|s| s.id != peer && tier(s)))
}

/// Heights whose recorded split has left the download path.
pub fn split_heights_off_path(st: &IbdWorkState) -> Vec<u32> {
    let mut heights = Vec::new();
    for slot in &st.slots {
        if let Some(at) = slot.chain.off_path_split_height(&st.height_to_hash) {
            heights.push(at);
        }
    }
    heights.sort_unstable();
    heights.dedup();
    heights
}

/// Apply confirms already read for off-path splits. A height missing from
/// `confirmed` appeared while the coordinator lock was down and waits.
pub fn apply_split_confirms(st: &mut IbdWorkState, confirmed: &HashMap<u32, Option<BlockHash>>) {
    let path = &st.height_to_hash;
    for slot in &mut st.slots {
        let Some(at) = slot.chain.off_path_split_height(path) else {
            continue;
        };
        if !confirmed.contains_key(&at) {
            continue;
        }
        slot.chain
            .settle_split(path, |ht| confirmed.get(&ht).copied().flatten());
    }
}

/// Inputs for one main-loop header poll. The loop owns the cadence clock.
pub struct HeaderPollIn {
    pub live: usize,
    pub need_ready_headroom: bool,
    pub lag: u32,
    pub min_cache: usize,
    pub fan: usize,
}

/// What the header poll should do with `headers_done` and `send_getheaders`.
pub enum HeaderPoll {
    /// Send getheaders.
    Ask,
    /// Empty path and peers are not ahead: latch `headers_done`.
    LatchDone,
    /// Leave header sync alone this turn.
    Wait,
}

/// A block inv or a probe is waiting, or an open probe is past its window,
/// and the walk lane is not already in flight.
///
/// An in-flight ask keeps the challenge until the lane clears. The poll
/// must not call `send_getheaders` on every block event during that window.
pub fn inv_challenge_due(st: &IbdWorkState) -> bool {
    probe_or_challenge_owed(st) && !lane_fresh(&st.header_walk.walk)
}

/// A challenge or probe waits to be sent, or a probe waits to be answered
/// or expire. Either keeps the lane.
fn probe_or_challenge_owed(st: &IbdWorkState) -> bool {
    let walk = &st.header_walk;
    walk.challenge.is_some() || walk.probe.is_some() || walk.probe_open.is_some()
}

/// The queue still has room, or a gap / look-ahead still needs headers.
#[doc(hidden)]
pub fn header_sync_open(st: &IbdWorkState, poll: &HeaderPollIn) -> bool {
    poll.live < ORDERED_HEADERS_SOFT_CAP
        || poll.need_ready_headroom
        || wants_lookahead(st)
        || walk_ahead_of_stored(st)
}

/// Something other than a full quiet queue is waiting on the next header.
#[doc(hidden)]
pub fn header_ask_due(st: &IbdWorkState, poll: &HeaderPollIn) -> bool {
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
pub fn header_poll(st: &IbdWorkState, poll: HeaderPollIn) -> HeaderPoll {
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
pub fn suppress_competing_chain(
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

#[doc(hidden)]
pub fn clear_off_path(st: &mut IbdWorkState) {
    st.header_walk.off_path.clear();
}

#[doc(hidden)]
pub fn note_dead(st: &mut IbdWorkState, hash: BlockHash) {
    if st.header_walk.dead_ends.len() >= DEAD_END_CAP {
        st.header_walk.dead_ends.clear();
    }
    st.header_walk.dead_ends.insert(hash);
}

#[doc(hidden)]
fn note_invalid_tip(st: &mut IbdWorkState, hash: BlockHash) {
    let walk = &mut st.header_walk;
    if !walk.invalid_tips.insert(hash) {
        return;
    }
    walk.invalid_tip_order.push_back(hash);
    if walk.invalid_tip_order.len() > INVALID_TIP_CAP {
        if let Some(oldest) = walk.invalid_tip_order.pop_front() {
            walk.invalid_tips.remove(&oldest);
        }
    }
}

/// Refuse a linked batch that holds or builds on a rejected block, and
/// retire `peer` from the walk. The batch's last header is remembered, so
/// the next batch of that chain is refused too.
pub fn refuse_invalid_batch(st: &mut IbdWorkState, peer: usize, headers: &[Header]) -> bool {
    let Some(first) = headers.first() else {
        return false;
    };
    // An unlinked batch does not build on what it names, so its last
    // header is not remembered. The usual checks drop it.
    if !pow_linked(headers) {
        return false;
    }
    let rejected = |hash: &BlockHash| {
        st.header_walk.invalid_tips.contains(hash)
            || st.reorg.invalid.contains(hash.to_byte_array())
    };
    if !rejected(&first.prev_blockhash) && !headers.iter().any(|h| rejected(&h.block_hash())) {
        return false;
    }
    if let Some(last) = headers.last() {
        note_invalid_tip(st, last.block_hash());
    }
    st.header_walk.walk_quiet.insert(peer);
    if st.header_walk.reserved == Some(peer) {
        st.header_walk.reserved = None;
    }
    true
}

/// The block at `height` failed consensus. When the download path holds it,
/// the path above its parent is dropped and every peer may be asked for
/// headers again. A candidate built on it falls back to that parent.
pub fn retire_invalid(st: &mut IbdWorkState, hub: &ChainHub, hash: BlockHash, height: u32) {
    if !st.is_on_path(&hash, height) {
        return;
    }
    let Some(parent) = hub.header_of(&hash).map(|h| h.prev_blockhash) else {
        return;
    };
    let parent_h = height.saturating_sub(1);
    drop_dead_path(st, Some(hub.query.as_ref()), parent_h);
    if !st.header_walk.origin || st.header_walk.tip_height() < height {
        return;
    }
    let tip = cut_back_to(st, hub, parent, parent_h);
    if st.header_walk.base_height > parent_h {
        st.header_walk.base_hash = tip.hash;
        st.header_walk.base_height = parent_h;
        st.header_walk.base_work = tip.work.to_be_bytes();
        st.header_walk.base_diff = tip.diff;
    }
    st.header_walk.tip = tip;
    // `header.adopt` restores the tip from the last checkpoint.
    if st
        .header_walk
        .checkpoints
        .last()
        .is_none_or(|c| c.height < parent_h)
    {
        let at_parent = checkpoint_at(&st.header_walk.tip);
        st.header_walk.checkpoints.push(at_parent);
    }
    // A challenger's headers are not stored, and its fork can sit below the
    // confirmed tip. Peers are asked again from the parent, and a heavier
    // chain comes back as headers that are stored and can be rewound onto.
    st.header_walk.challenger = None;
    rbitcoin_log::warn!(
        "ibd: header candidate retired at {hash} height={height}; walk back to {parent} height={parent_h}"
    );
    publish_work(st, hub);
    save_adopt(st, hub);
}

/// Forget the download path above `keep`: queued hashes, bodies waiting in
/// the body queue, the confirm plan, and the densify cursor. Every peer may
/// be asked for headers again. The queue drop runs before the path clear so
/// a hash popped off the front of `ordered` is still forgotten from
/// `hash_height`.
pub(crate) fn drop_dead_path(
    st: &mut IbdWorkState,
    query: Option<&rbitcoin_query::Query>,
    keep: u32,
) {
    drop_queue_above(st, keep, &HashSet::new());
    st.clear_path_above(keep);
    if let Some(query) = query {
        for queued in query.block_queue_queued_heights() {
            if queued > keep {
                let _ = query.block_queue_dequeue_height(queued);
            }
        }
    }
    st.confirm_quiesce = true;
    st.max_ready_height = st.max_ready_height.min(keep);
    let next = keep.saturating_add(1);
    st.densify_scan_lo = st.densify_scan_lo.min(next);
    st.densify_ready_through = st.densify_ready_through.min(next);
    st.header_walk.reserved = None;
    st.header_walk.walk_quiet.clear();
    st.header_walk.emptied.clear();
    clear_off_path(st);
}

/// A walk tip at stored `hash`, `height` on the candidate. Checkpoints and a
/// milestone above it are dropped.
fn cut_back_to(st: &mut IbdWorkState, hub: &ChainHub, hash: BlockHash, height: u32) -> WalkTip {
    let mut tip = WalkTip {
        hash: Some(hash),
        height,
        work: work_at(st, hub, hash).unwrap_or(Work::from_be_bytes([0; 32])),
        header: parent_header(st, hub, hash),
        times: times_ending_at(st, hub, hash),
        diff: diff_at(st, hub, hash),
        milestone_hash: st.header_walk.tip.milestone_hash,
        milestone_prev: st.header_walk.tip.milestone_prev,
        milestone_header: st.header_walk.tip.milestone_header,
    };
    forget_milestone_below(st, hub, height);
    if height < hub.milestone.height {
        tip.milestone_hash = None;
        tip.milestone_header = None;
    }
    st.header_walk.checkpoints.retain(|c| c.height <= height);
    tip
}

pub fn rewind_above(st: &mut IbdWorkState, hub: &ChainHub, height: u32) {
    rewind_to(st, hub, height, None);
}

/// Pop checkpoints above `height`, or the current tip when `dead` is set.
/// `dead` is the hash that every peer left empty.
#[doc(hidden)]
pub fn rewind_to(st: &mut IbdWorkState, hub: &ChainHub, height: u32, dead: Option<BlockHash>) {
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

#[doc(hidden)]
pub fn batch_ends_on_checkpoint(st: &IbdWorkState, headers: &[Header]) -> bool {
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

#[doc(hidden)]
pub fn challenger_extends(st: &IbdWorkState, prev: BlockHash) -> bool {
    st.header_walk
        .challenger
        .as_ref()
        .is_some_and(|ch| ch.tip.hash == Some(prev))
}

/// `None` when this reply is not a chain we can compare. `Some(true)` when the
/// caller must not write it. `Some(false)` when it was adopted and the queue
/// has room for those headers.
#[doc(hidden)]
pub fn offer_alternate(
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

#[doc(hidden)]
pub fn chain_work_after(parent: Work, headers: &[Header]) -> Work {
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
#[doc(hidden)]
pub struct WalkTip {
    pub hash: Option<BlockHash>,
    pub height: u32,
    pub work: Work,
    pub header: Option<Header>,
    pub times: Vec<u32>,
    pub diff: DiffSnap,
    pub milestone_hash: Option<BlockHash>,
    pub milestone_prev: BlockHash,
    pub milestone_header: Option<Header>,
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
#[doc(hidden)]
pub fn push_header(tip: &mut WalkTip, hub: &ChainHub, hdr: &Header) -> bool {
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

#[doc(hidden)]
pub fn advance_tip(tip: &mut WalkTip, hub: &ChainHub, headers: &[Header]) {
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

#[doc(hidden)]
pub fn latch_milestone(tip: &WalkTip, hub: &ChainHub) {
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

#[doc(hidden)]
pub fn push_times(times: &mut Vec<u32>, header: Header) {
    times.push(header.time);
    if times.len() > 11 {
        times.remove(0);
    }
}

#[doc(hidden)]
pub fn checkpoint_at(tip: &WalkTip) -> Checkpoint {
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

#[doc(hidden)]
pub fn tip_from_checkpoint(c: &Checkpoint) -> WalkTip {
    WalkTip {
        hash: Some(c.hash),
        height: c.height,
        work: Work::from_be_bytes(c.work),
        ..WalkTip::default()
    }
}

#[doc(hidden)]
pub fn tip_from_base(st: &IbdWorkState) -> WalkTip {
    WalkTip {
        hash: st.header_walk.base_hash,
        height: st.header_walk.base_height,
        work: Work::from_be_bytes(st.header_walk.base_work),
        ..WalkTip::default()
    }
}

#[doc(hidden)]
pub fn note_challenger(
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

#[doc(hidden)]
pub fn extend_challenger(
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

#[doc(hidden)]
pub fn promote_challenger(st: &mut IbdWorkState, hub: &ChainHub) {
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
#[doc(hidden)]
pub fn drop_queue_above(st: &mut IbdWorkState, height: u32, keep: &HashSet<BlockHash>) {
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
#[doc(hidden)]
pub struct Known {
    pub height: Option<u32>,
    pub work: Option<Work>,
    pub header: Option<Header>,
    pub diff: Option<DiffSnap>,
    pub times: Option<Vec<u32>>,
}

#[doc(hidden)]
pub fn consider_tip(found: &mut Known, tip: &WalkTip, hash: BlockHash) {
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

#[doc(hidden)]
pub fn consider_checkpoint(found: &mut Known, c: &Checkpoint) {
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
#[doc(hidden)]
pub fn known(st: &IbdWorkState, hash: BlockHash) -> Known {
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
#[doc(hidden)]
pub fn diff_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> DiffSnap {
    known(st, hash).diff.unwrap_or_else(|| {
        stored_path_state(st, hub, hash)
            .map(|(_, diff)| diff)
            .unwrap_or_default()
    })
}

#[doc(hidden)]
pub fn note_period_snap(diff: &mut DiffSnap, hub: &ChainHub, header: Header, height: u32) {
    let interval = hub.params.difficulty_adjustment_interval();
    if interval > 0 && height.is_multiple_of(interval) {
        diff.period_header = Some(header);
        diff.period_height = height;
    }
}

#[doc(hidden)]
pub fn note_full_diff_snap(diff: &mut DiffSnap, hub: &ChainHub, header: &Header, height: u32) {
    let limit = hub.params.pow_limit.to_compact_lossy();
    if header.bits != limit {
        diff.full_diff_bits = Some(header.bits);
        diff.full_diff_height = height;
    }
}

#[doc(hidden)]
pub fn times_ending_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Vec<u32> {
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
#[doc(hidden)]
pub fn retain_challenger(st: &mut IbdWorkState) {
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

#[doc(hidden)]
pub fn work_at(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<Work> {
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

#[doc(hidden)]
pub fn confirmed_ancestor_work(hub: &ChainHub, hash: BlockHash) -> Option<Work> {
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
#[doc(hidden)]
pub fn stored_path_state(
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

#[doc(hidden)]
pub struct StoredAnchor {
    pub height: u32,
    pub hash: BlockHash,
    pub work: Work,
    pub diff: DiffSnap,
}

#[doc(hidden)]
pub fn fold_stored_anchor(
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

#[doc(hidden)]
pub fn adopt_heavier(
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
    let mut tip = cut_back_to(st, hub, prev, fork_height);
    st.header_walk.challenger = None;
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

#[doc(hidden)]
pub fn forget_queue_hashes(st: &mut IbdWorkState, drop: &[BlockHash]) {
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
#[doc(hidden)]
pub fn path_top(st: &IbdWorkState, hub: &ChainHub) -> Option<(BlockHash, u32)> {
    if let Some(tail) = st.ordered.back().copied() {
        return st.hash_height.get(&tail).copied().map(|h| (tail, h));
    }
    Some((hub.tip_hash()?, hub.tip_height()?))
}

/// The walk tip is past the stored path, so a further reply is not a refill.
#[doc(hidden)]
pub fn walk_ahead_of_queue(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let Some((_, top_h)) = path_top(st, hub) else {
        return false;
    };
    st.header_walk.origin && st.header_walk.tip_height() > top_h
}

/// The walk tip is past the highest header recorded on the work path.
#[doc(hidden)]
pub fn walk_ahead_of_stored(st: &IbdWorkState) -> bool {
    st.header_walk.origin && st.header_walk.tip_height() > st.max_ordered_height
}

/// Queue tail, or the confirmed tip when the queue is empty.
#[doc(hidden)]
pub fn stored_top_hash(st: &IbdWorkState, hub: &ChainHub) -> Option<BlockHash> {
    st.ordered.back().copied().or_else(|| hub.tip_hash())
}

/// What a headers batch is, from the hash it builds on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderClass {
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
pub fn classify(
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
pub fn absorb_lookahead(
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
pub fn ignore_below_floor(st: &IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
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
pub fn reject_refill_miss(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
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

#[doc(hidden)]
pub fn proved_above_floor(st: &IbdWorkState, hub: &ChainHub) -> bool {
    st.header_walk.proven && !below_floor(hub, &st.header_walk.tip_work())
}

#[doc(hidden)]
pub fn judge_refill(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    start_h: u32,
    headers: &[Header],
) -> bool {
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
#[doc(hidden)]
pub fn unproved_anchor(st: &IbdWorkState, hub: &ChainHub) -> Option<(BlockHash, u32)> {
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
#[doc(hidden)]
pub fn replace_unproved_queue(
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
#[doc(hidden)]
pub enum PathAgree {
    Checkpoint(u32),
    Short,
    Diverges,
}

#[doc(hidden)]
pub fn candidate_prev(st: &IbdWorkState, prev: BlockHash) -> bool {
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
#[doc(hidden)]
pub fn path_agree(st: &IbdWorkState, start_h: u32, headers: &[Header], slots: bool) -> PathAgree {
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
pub fn proven_header_prefix(st: &IbdWorkState, hub: &ChainHub, headers: &[Header]) -> usize {
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

#[doc(hidden)]
pub fn refill_misses_checkpoint(st: &IbdWorkState, tail_h: u32, headers: &[Header]) -> bool {
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
pub fn note_empty(st: &mut IbdWorkState, hub: &ChainHub, peer: usize) -> bool {
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
pub fn note_stored_candidate(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header]) {
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

#[doc(hidden)]
pub fn extend_tip(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
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

#[doc(hidden)]
pub fn remember_milestone(tip: &mut WalkTip, hub: &ChainHub, prev: BlockHash, hdr: &Header) {
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

#[doc(hidden)]
pub fn publish_work(st: &mut IbdWorkState, hub: &ChainHub) {
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

#[doc(hidden)]
pub fn rewind(st: &mut IbdWorkState, hub: &ChainHub) {
    let Some(dead) = st.header_walk.tip_hash() else {
        return;
    };
    rewind_to(st, hub, 0, Some(dead));
}

#[doc(hidden)]
pub fn forget_milestone_below(st: &mut IbdWorkState, hub: &ChainHub, height: u32) {
    if hub.milestone.height == 0 || height >= hub.milestone.height {
        return;
    }
    st.header_walk.tip.milestone_hash = None;
    st.header_walk.tip.milestone_header = None;
    hub.query.clear_milestone_path_above(height);
}

#[doc(hidden)]
pub fn lane_fresh(lane: &Lane) -> bool {
    lane.peer.is_some() && lane.at.is_some_and(|t| t.elapsed() <= LOOKAHEAD_ASK)
}

/// Lanes still inside their ask window when a reply arrives. Time spent
/// handling that reply is not part of the window: a slow store must not
/// rotate a peer who has not missed.
pub struct InFlight {
    pub walk: Option<(usize, Instant)>,
    pub started: Instant,
    pub held: bool,
}

impl InFlight {
    pub fn capture(st: &IbdWorkState) -> Self {
        Self {
            walk: fresh_mark(&st.header_walk.walk),
            started: Instant::now(),
            held: false,
        }
    }

    /// Move a still-waiting ask's start forward by the time since [`capture`].
    pub fn hold(&mut self, st: &mut IbdWorkState) {
        if self.held {
            return;
        }
        self.held = true;
        let paused = self.started.elapsed();
        hold_mark(&mut st.header_walk.walk, self.walk, paused);
    }
}

#[doc(hidden)]
pub fn fresh_mark(lane: &Lane) -> Option<(usize, Instant)> {
    if !lane_fresh(lane) {
        return None;
    }
    Some((lane.peer?, lane.at?))
}

#[doc(hidden)]
pub fn hold_mark(lane: &mut Lane, saved: Option<(usize, Instant)>, paused: Duration) {
    let Some((peer, at)) = saved else {
        return;
    };
    if lane.peer == Some(peer) && lane.at == Some(at) {
        lane.at = at.checked_add(paused);
    }
}

#[doc(hidden)]
pub fn release_lane(lane: &mut Lane) {
    if let Some(peer) = lane.peer.take() {
        lane.prev_peer = Some(peer);
    }
    lane.at = None;
}

/// Drop this peer's in-flight ask on every lane. A late reply still matches
/// `prev_peer`.
#[doc(hidden)]
pub fn clear_peer_ask(st: &mut IbdWorkState, peer: usize) {
    let lane = &mut st.header_walk.walk;
    if lane.peer == Some(peer) {
        lane.peer = None;
        lane.at = None;
    }
}

/// Whether a headers reply is the one we asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderAsk {
    /// This peer was not asked.
    Unsolicited,
    /// Reply inside the window.
    InWindow,
    /// The window expired. The tip has not moved, so the reply can still extend it.
    Late,
}

/// The peer answered. A late reply from the peer we asked, or from the peer
/// we skipped after one miss, is [`HeaderAsk::Late`].
pub fn take_header_ask(st: &mut IbdWorkState, peer: usize) -> HeaderAsk {
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
#[doc(hidden)]
pub fn expire_header_ask(st: &mut IbdWorkState) -> Option<usize> {
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
    if st.header_walk.probe_open == Some(peer) {
        st.header_walk.probe_open = None;
        st.header_walk.probe_top = None;
        if n >= HEADER_MISS_DISCONNECT {
            st.header_walk.header_misses.remove(&peer);
            punish_header_peer(st, peer);
        }
        return None;
    }
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

#[doc(hidden)]
pub fn note_lane(st: &mut IbdWorkState, peer: usize) {
    let lane = &mut st.header_walk.walk;
    if let Some(prev) = lane.peer {
        if prev != peer {
            lane.prev_peer = Some(prev);
        }
    }
    lane.peer = Some(peer);
    lane.at = Some(Instant::now());
}

#[doc(hidden)]
pub fn punish_header_peer(st: &mut IbdWorkState, peer: usize) {
    super::dial::disconnect_peer(st, peer);
}

/// Ask for the next header when it is not already stored. The locator is the
/// stored path tip. A request still inside its window stays in flight. One
/// miss moves the reservation when another peer can take it. A second miss
/// disconnects. A block-inv challenge is one ask to that peer and does not
/// replace the reservation until the reply beats the candidate.
pub fn send_getheaders(
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, rbitcoin_net::error::NetError> {
    ensure_origin(st, hub);
    super::path::append_stored_headers(st, hub);
    let owed = probe_or_challenge_owed(st);
    if !owed && super::path::walk_successor_indexed(st, hub) {
        release_lane(&mut st.header_walk.walk);
        return Ok(false);
    }
    let want = owed || wants_lookahead(st) || walk_ahead_of_queue(st, hub);
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
#[doc(hidden)]
pub fn header_ask_locator(st: &IbdWorkState, hub: &ChainHub) -> Vec<BlockHash> {
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

#[doc(hidden)]
pub fn arm_header_ask(
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, rbitcoin_net::error::NetError> {
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
    if let Some(peer) = take_probe(st) {
        // After the path top alone: a reply that builds on it shows the
        // whole path. A peer that did not show it is asked with the
        // confirmed chain only, whose first hash it has is at or below the
        // tip, so the reply is what it has above it.
        let tip_h = hub.tip_height().unwrap_or(0);
        let from_tip = st
            .slots
            .iter()
            .any(|s| s.id == peer && s.chain.probe_from_tip());
        let top = path_top(st, hub).filter(|&(_, h)| h > tip_h && !from_tip);
        let sent = match top {
            Some((hash, height)) => {
                let sent = super::dial::request_headers_from(
                    &st.slots,
                    peer,
                    &mut st.header_req_seq,
                    vec![hash],
                )?;
                if sent {
                    note_lane(st, peer);
                }
                st.header_walk.probe_top = sent.then_some((height, hash));
                sent
            }
            None => {
                st.header_walk.probe_top = None;
                ask_header_peer(st, hub, peer, &[])?
            }
        };
        if sent {
            st.header_walk.probe_open = Some(peer);
            let now = Instant::now();
            if let Some(slot) = st.slots.iter_mut().find(|s| s.id == peer) {
                slot.chain.note_probe_sent(now, top.is_none());
            }
            return Ok(true);
        }
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
#[doc(hidden)]
pub fn header_ttfb(slot: &super::peer_io::PeerSlot) -> Option<u64> {
    if slot.first_data_ms == 0 {
        None
    } else {
        Some(slot.first_data_ms.saturating_sub(slot.connected_ms))
    }
}

#[doc(hidden)]
pub fn peer_can_head(st: &IbdWorkState, id: usize, above: u32) -> bool {
    st.slots.iter().any(|s| {
        s.alive && s.id == id && s.peer_height > above && !st.header_walk.walk_quiet.contains(&id)
    })
}

/// A live peer when nobody's connect-time height is above the stored path.
/// Peers still on the walk come first.
#[doc(hidden)]
pub fn pick_any_header_peer(st: &IbdWorkState, skip: Option<usize>) -> Option<usize> {
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
#[doc(hidden)]
pub fn pick_header_peer(st: &IbdWorkState, above: u32, skip: Option<usize>) -> Option<usize> {
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

#[doc(hidden)]
pub fn ensure_reserved(st: &mut IbdWorkState, above: u32, skip: Option<usize>) {
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

/// A probe peer who is still connected and not [`walk_busy`]. A busy peer
/// is dropped unprobed, so it is picked again later.
fn take_probe(st: &mut IbdWorkState) -> Option<usize> {
    let peer = st.header_walk.probe.take()?;
    let alive = st.slots.iter().any(|s| s.alive && s.id == peer);
    (alive && !walk_busy(&st.header_walk, peer)).then_some(peer)
}

/// A challenge peer who is still connected and not retired.
#[doc(hidden)]
pub fn take_challenge(st: &mut IbdWorkState) -> Option<usize> {
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

#[doc(hidden)]
pub fn ask_header_peer(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    tips: &[BlockHash],
) -> Result<bool, rbitcoin_net::error::NetError> {
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
#[doc(hidden)]
pub fn confirmed_chain_tail(
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Result<Vec<BlockHash>, rbitcoin_net::error::NetError> {
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
        .map_err(|e| rbitcoin_net::error::NetError::Consensus(e.to_string()))?;
    st.confirmed_locator_tail = Some(ConfirmedLocatorTail {
        height,
        hash,
        hashes: tail.clone(),
    });
    Ok(tail)
}

#[doc(hidden)]
pub fn parent_header(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<Header> {
    known(st, hash).header.or_else(|| hub.header_of(&hash))
}

#[doc(hidden)]
pub fn height_of(st: &IbdWorkState, hub: &ChainHub, hash: BlockHash) -> Option<u32> {
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

#[doc(hidden)]
pub fn seed_tip_times(st: &mut IbdWorkState, hub: &ChainHub, header: Header) {
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

#[doc(hidden)]
pub fn restore_tip_header(st: &mut IbdWorkState, hub: &ChainHub) {
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

#[doc(hidden)]
pub fn batch_context_ok(
    st: &IbdWorkState,
    hub: &ChainHub,
    headers: &[Header],
    diff: &DiffSnap,
) -> bool {
    if headers.is_empty() {
        return false;
    }
    // The header batch opts in while the mode is on. Flag-off does not write the cell.
    // The recursive call already holds the cell, so it does not opt in again.
    if hub.query.trust_peer() && !rbitcoin_query::confirm_run::confirm_waive(hub.query.as_ref()) {
        return rbitcoin_query::confirm_run::waive_batch(true, || {
            batch_context_ok(st, hub, headers, diff)
        });
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
    let own_guard = rbitcoin_query::confirm_run::confirm_waive(hub.query.as_ref())
        && !rbitcoin_consensus::collecting();
    let guard = own_guard.then(rbitcoin_consensus::TrustCollect::enter);
    let mut stopped: Option<(u32, [u8; 32], rbitcoin_consensus::ConsensusError)> = None;
    let mut seen: Vec<(u32, [u8; 32])> = Vec::with_capacity(headers.len());
    let mut accepted = true;
    for hdr in headers {
        let hash = hdr.block_hash();
        if hdr.prev_blockhash != parent_hash {
            stopped = Some((
                height.saturating_add(1),
                hash.to_byte_array(),
                rbitcoin_consensus::ConsensusError::BadPrev,
            ));
            accepted = false;
            break;
        }
        height = height.saturating_add(1);
        seen.push((height, hash.to_byte_array()));
        let mtp = if times.len() < 11 {
            0
        } else {
            match rbitcoin_primitives::median_time_past_times(&times) {
                Ok(mtp) => mtp,
                Err(_) => {
                    stopped = Some((
                        height,
                        hash.to_byte_array(),
                        rbitcoin_consensus::ConsensusError::BadHeader("empty median time"),
                    ));
                    accepted = false;
                    break;
                }
            }
        };
        parent_hash = hash;
        let Some(bits) = expected_lookahead_bits(hub, height, &parent, hdr.time, st, &diff) else {
            stopped = Some((
                height,
                hash.to_byte_array(),
                rbitcoin_consensus::ConsensusError::BadHeader("missing retarget first header"),
            ));
            accepted = false;
            break;
        };
        let period_open = period_open_time(hub, height, st, &diff);
        if let Err(e) = rbitcoin_consensus::validate_header_on_parent(
            &hub.params,
            rbitcoin_primitives::Height(height),
            hdr,
            mtp,
            parent.time,
            period_open,
            bits,
        ) {
            stopped = Some((height, hash.to_byte_array(), e));
            accepted = false;
            break;
        }
        if times.len() == 11 {
            times.remove(0);
        }
        times.push(hdr.time);
        note_period_snap(&mut diff, hub, *hdr, height);
        note_full_diff_snap(&mut diff, hub, hdr, height);
        parent = *hdr;
    }
    let warns = if own_guard {
        rbitcoin_consensus::drain_warnings()
    } else {
        Vec::new()
    };
    drop(guard);
    if own_guard {
        for (h, err) in warns {
            let hh = h.unwrap_or(height);
            let hash = seen
                .iter()
                .find(|(y, _)| *y == hh)
                .map(|(_, hash)| *hash)
                .unwrap_or([0; 32]);
            rbitcoin_query::confirm_run::warn_trust_block(accepted, hash, hh, &err);
        }
        if let Some((h, hash, err)) = stopped {
            rbitcoin_query::confirm_run::warn_trust_block(false, hash, h, &err);
        }
    }
    accepted
}

#[doc(hidden)]
pub fn expected_lookahead_bits(
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

/// Timestamp of the period-open header when BIP 54's negative-interval
/// check applies. `None` when the check is off, or when that header is not
/// in the snap or the header store (the caller then fails closed).
#[doc(hidden)]
pub fn period_open_time(
    hub: &ChainHub,
    height: u32,
    st: &IbdWorkState,
    diff: &DiffSnap,
) -> Option<u32> {
    let open_h = hub.params.bip54_period_open_height(height)?;
    if diff.period_height == open_h {
        if let Some(header) = diff.period_header {
            return Some(header.time);
        }
    }
    header_on_store(st, hub, open_h).map(|header| header.time)
}

#[doc(hidden)]
pub fn period_first_time(
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

#[doc(hidden)]
pub fn lookahead_bits_at(
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

#[doc(hidden)]
pub fn header_on_store(st: &IbdWorkState, hub: &ChainHub, height: u32) -> Option<Header> {
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

#[doc(hidden)]
pub fn pow_linked(headers: &[Header]) -> bool {
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

#[doc(hidden)]
pub const ADOPT_MAGIC: &[u8; 8] = b"rbtchdr1";
/// period height u32 ‖ period header 80 ‖ full-diff height u32 ‖ full-diff bits u32.
#[doc(hidden)]
pub const DIFF_SNAP_LEN: usize = 4 + 80 + 4 + 4;

#[doc(hidden)]
/// Drop `header.adopt`; the next start walks again from the confirmed tip.
pub fn forget_adopt(hub: &ChainHub) {
    let path = adopt_path(hub);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                let _ = rbitcoin_store::file::fsync_parent_dir(dir);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => rbitcoin_log::warn!("ibd: remove {}: {e}", path.display()),
    }
}

pub fn adopt_path(hub: &ChainHub) -> std::path::PathBuf {
    hub.query.store().path().join("header.adopt")
}

#[doc(hidden)]
pub fn write_header(buf: &mut Vec<u8>, header: Option<Header>) {
    let mut raw = [0u8; 80];
    if let Some(header) = header {
        let enc = bitcoin::consensus::serialize(&header);
        if enc.len() == raw.len() {
            raw.copy_from_slice(&enc);
        }
    }
    buf.extend_from_slice(&raw);
}

#[doc(hidden)]
pub fn read_header(raw: &[u8]) -> Option<Header> {
    if raw.iter().all(|b| *b == 0) {
        return None;
    }
    bitcoin::consensus::deserialize(raw).ok()
}

#[doc(hidden)]
pub fn write_diff(buf: &mut Vec<u8>, diff: &DiffSnap) {
    buf.extend_from_slice(&diff.period_height.to_le_bytes());
    write_header(buf, diff.period_header);
    buf.extend_from_slice(&diff.full_diff_height.to_le_bytes());
    let bits = diff.full_diff_bits.map(|b| b.to_consensus()).unwrap_or(0);
    buf.extend_from_slice(&bits.to_le_bytes());
}

#[doc(hidden)]
pub fn read_diff(bytes: &[u8]) -> Option<DiffSnap> {
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

#[doc(hidden)]
pub fn base_conflicts(st: &IbdWorkState, hub: &ChainHub, walk: &HeaderWalk) -> bool {
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
pub fn on_confirmed_rewind(st: &mut IbdWorkState, hub: &ChainHub, lca_h: u32) {
    if st.header_walk.base_hash.is_some() && lca_h < st.header_walk.base_height {
        st.header_walk = HeaderWalk::default();
        forget_adopt(hub);
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

#[doc(hidden)]
pub fn save_adopt(st: &IbdWorkState, hub: &ChainHub) {
    if !st.header_walk.origin {
        return;
    }
    // A walk saved while a failure is not on disk could resume onto the
    // invalid chain. No walk is the resume point until the mark is.
    if !hub.invalid_marks_on_disk() {
        forget_adopt(hub);
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
pub fn retire_adopt_if_confirmed(st: &mut IbdWorkState, hub: &ChainHub) {
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
    forget_adopt(hub);
}

/// Read `header.adopt`. A file that does not parse does not restore
/// checkpoints. Headers already queued and linked from the confirmed tip are
/// still noted on the milestone path.
/// Ancestors walked to find a stored failure's height.
const FAILURE_HEIGHT_WALK: usize = 64;

/// A stored failure that a walk saved from `base_height` may build on: one
/// above that base, or one whose height is not found within a few headers
/// of the best chain. The chain at or below the base is the confirmed one.
fn failure_above(hub: &ChainHub, base_height: u32) -> bool {
    hub.invalid_blocks()
        .into_iter()
        .any(|hash| failure_height(hub, hash).is_none_or(|h| h > base_height))
}

fn failure_height(hub: &ChainHub, hash: BlockHash) -> Option<u32> {
    let path =
        super::reorg::header_hashes_to_best_ancestor_n(hub, hash, FAILURE_HEIGHT_WALK).ok()?;
    let join = super::reorg::parent_hash_of(hub, *path.first()?).ok()??;
    if !hub.is_connected(&join) {
        return None;
    }
    let join_h = hub.query.height_of_hash(&join.to_byte_array()).ok()??.0;
    Some(join_h.saturating_add(path.len() as u32))
}

pub fn restore_adopt(st: &mut IbdWorkState, hub: &ChainHub) -> bool {
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
    // A saved candidate above the confirmed tip may build on a block marked
    // invalid after it was saved. The walk starts again from the tip.
    if parsed.tip.height > hub.tip_height().unwrap_or(0) && failure_above(hub, parsed.base_height) {
        rbitcoin_log::info!(
            "ibd: headers resume refused height={}: invalid blocks are stored",
            parsed.tip.height
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

#[doc(hidden)]
pub fn parse_adopt(bytes: &[u8]) -> Option<HeaderWalk> {
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
        invalid_tips: HashSet::new(),
        invalid_tip_order: std::collections::VecDeque::new(),
        emptied: HashSet::new(),
        proven: false,
        off_path: std::collections::HashMap::new(),
        #[cfg(debug_assertions)]
        announced_done: false,
        walk_quiet: HashSet::new(),
        reserved: None,
        challenge: None,
        challenge_external: false,
        challenge_open: None,
        probe: None,
        probe_open: None,
        probe_top: None,
        walk: Lane::default(),
        header_misses: HashMap::new(),
        base_diff,
        challenger: None,
        adopt_retired: false,
    })
}

#[doc(hidden)]
pub const TIMES_SLOTS: usize = 11;

#[doc(hidden)]
pub fn write_times(buf: &mut Vec<u8>, times: &[u32]) {
    let n = times.len().min(TIMES_SLOTS);
    let start = times.len().saturating_sub(TIMES_SLOTS);
    buf.push(n as u8);
    for i in 0..TIMES_SLOTS {
        let t = times.get(start + i).copied().unwrap_or(0);
        buf.extend_from_slice(&t.to_le_bytes());
    }
}

#[doc(hidden)]
pub fn read_times(bytes: &[u8]) -> Option<Vec<u32>> {
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
#[doc(hidden)]
pub const OFF_PATH_HEADER_BUDGET: u32 = 4_000;

/// Count one stored header that is not on the download path. True when the
/// peer is over the budget and still below the work floor.
pub fn note_off_path(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, hash: BlockHash) -> bool {
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
pub fn renote_stored_path(st: &IbdWorkState, hub: &ChainHub) {
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
