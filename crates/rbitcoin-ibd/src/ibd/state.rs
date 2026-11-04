//! Mutable IBD work-path state (peers, ordered queue, body cache, inflight).
//!
//! ## Ordered path memory
//!
//! - `ordered` + `ordered_set` track headers after the local tip for getdata.
//! - Middle completions leave **ghost** deque entries (see [`super::assign_plan::remove_from_ordered`]);
//!   `Self::hygiene` compacts when the deque bloats.
//! - `hash_height` / `header_fks` / `path_prev` / `known_headers` hold the
//!   header chain (a re-getheaders must re-resolve height without a store
//!   walk). `Self::deep_hygiene` drops side-branch rows; `Self::hygiene` is
//!   O(live) and runs every second.

use super::assign_plan::compact_ordered;
use super::body::{BodyPresence, BodyPresenceSizes};
use super::reorg::IbdReorgState;
use bitcoin::BlockHash;
use rbitcoin_net::NetAddr;
use rbitcoin_primitives::Fk;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::peer_io::PeerSlot;

/// O(1) occupancy of [`IbdWorkState`] retain structures (for `ibd: sizes`).
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct WorkStructureSizes {
    pub ordered: usize,
    pub ordered_set: usize,
    pub hash_height: usize,
    pub height_to_hash: usize,
    pub header_fks: usize,
    pub known_headers: usize,
    pub inflight: usize,
    /// Sum of per-peer `in_flight` sets (may exceed unique `inflight` on tip races).
    pub peer_inflight: usize,
    pub addr_cooldown: usize,
    pub body: BodyPresenceSizes,
}

/// Outstanding getdata for one block hash (one or more peers).
///
/// Near/far densify use a single peer. Tip-hole hashes race up to
/// [`super::TIP_HOLE_MAX_PEERS`] once the body queue is a quarter of the
/// confirm window or the configured assign-stop, or holds
/// [`rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS`] bodies. Below that, the gap
/// is the frontier.
///
/// Getdata cannot be cancelled. A peer dropped from the race moves to
/// `retired`: it no longer counts as a racer, but it still holds the request,
/// so the hash stays requested. Except for the racerless re-ask after
/// [`super::assign::TIP_HOLE_RX_STALE`], a retired peer is not asked for it again.
/// Retired peers count toward the ask cap once a racer is live. A retired-only
/// set is not coverage: cover still places a racer when holders are already
/// at the cap.
#[derive(Debug, Clone)]
pub struct InflightReq {
    /// Racing owners.
    pub peers: HashSet<usize>,
    /// When each racing owner was asked.
    pub asked_at: HashMap<usize, Instant>,
    /// Dropped from the race; still holding the getdata.
    pub retired: HashSet<usize>,
    /// When this hash first entered global inflight (stale tip-hole re-get).
    pub started_at: Instant,
}

impl Default for InflightReq {
    fn default() -> Self {
        Self {
            peers: HashSet::new(),
            asked_at: HashMap::new(),
            retired: HashSet::new(),
            started_at: Instant::now(),
        }
    }
}

impl InflightReq {
    pub fn new(peer: usize) -> Self {
        let mut r = Self::default();
        r.add_peer(peer);
        r
    }

    /// Racing or retired: `peer` has been sent this getdata and not answered.
    pub fn holds(&self, peer: usize) -> bool {
        self.peers.contains(&peer) || self.retired.contains(&peer)
    }

    /// Racing owners only.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Racing and retired: every peer already sent this getdata.
    pub fn holders(&self) -> usize {
        self.peers.len() + self.retired.len()
    }

    /// Returns true if `peer` was newly added.
    pub fn add_peer(&mut self, peer: usize) -> bool {
        self.retired.remove(&peer);
        let added = self.peers.insert(peer);
        if added {
            self.asked_at.insert(peer, Instant::now());
        }
        added
    }

    /// When racing or retired owner `peer` was asked.
    pub fn owner_asked_at(&self, peer: usize) -> Option<Instant> {
        self.asked_at.get(&peer).copied()
    }

    /// Stop counting `peer` as a racer. It keeps the request and its ask time,
    /// so a racerless hash can re-ask it once the hold has aged out.
    pub fn retire_peer(&mut self, peer: usize) {
        if self.peers.remove(&peer) {
            self.retired.insert(peer);
        }
    }

    /// `peer` no longer holds the request (answered, notfound, or gone).
    /// Returns true if no holder remains (caller should drop the hash).
    pub fn remove_peer(&mut self, peer: usize) -> bool {
        self.peers.remove(&peer);
        self.asked_at.remove(&peer);
        self.retired.remove(&peer);
        self.peers.is_empty() && self.retired.is_empty()
    }
}

/// Confirmed-chain `getheaders` tail for one published tip.
///
/// Absent until the first catch-up ask. The next ask reuses `entries` while
/// both `height` and `hash` still match `published_tip`. The work-path
/// prefix is not stored here.
pub struct ConfirmedLocatorTail {
    pub height: Option<u32>,
    pub hash: Option<[u8; 32]>,
    /// Each locator hash with its height.
    pub entries: Vec<(u32, BlockHash)>,
}

/// Core mutable state for the IBD event loop.
pub struct IbdWorkState {
    pub slots: Vec<PeerSlot>,
    /// Unique hashes with outstanding getdata (1 peer normally; tip-hole races ≤4).
    pub inflight: HashMap<BlockHash, InflightReq>,
    /// Chain-order download path after local tip (front ≈ next to confirm).
    pub ordered: VecDeque<BlockHash>,
    pub ordered_set: HashSet<BlockHash>,
    pub hash_height: HashMap<BlockHash, u32>,
    /// Inverse of [`Self::hash_height`] for O(1) tip+1‥ confirm offers.
    pub height_to_hash: HashMap<u32, BlockHash>,
    /// Parent hash recorded when the header was admitted. The orchestration
    /// loop uses this instead of reading the header store.
    pub path_prev: HashMap<BlockHash, BlockHash>,
    pub known_headers: HashSet<BlockHash>,
    pub body: BodyPresence,
    /// header hash → Class A header fk (from getheaders; Block path skips store).
    pub header_fks: HashMap<BlockHash, Fk>,
    /// Best peer-advertised tip (version.start_height + learned header heights).
    pub max_peer_height: u32,
    /// Highest claim-ready / offered body height on the work path (body queue
    /// densify + confirm offer bookkeeping; not a dual-track Class A HWM).
    pub max_ready_height: u32,
    /// Highest header height currently on the ordered work path.
    pub max_ordered_height: u32,
    pub headers_done: bool,
    pub empty_header_streak: u32,
    pub header_req_seq: u32,
    /// Rotates which peer is offered work first.
    pub assign_rot: usize,
    /// Stall-disconnect cooldowns (addr → until).
    pub addr_cooldown: HashMap<NetAddr, Instant>,
    /// Per-peer addr token buckets (peer id → bucket), as on tip-follow
    /// sessions. Dropped when the peer dies.
    pub addr_buckets: HashMap<usize, rbitcoin_net::peer::AddrTokenBucket>,
    /// Process-local kick counts for addresses in addrman or still cooling.
    pub addr_strikes: HashMap<NetAddr, u8>,
    /// Relative-slow hysteresis: peer id + first Gate B fail ms.
    pub relative_slow_suspect: Option<(usize, u64)>,
    /// Mono ms of last relative-slow disconnect (`0` = never).
    pub relative_slow_last_kick_ms: u64,
    /// Process-local invalid apply marks for most-work reorg (IBD run only).
    pub reorg: IbdReorgState,
    /// First height ≥ path_lo densify should walk (filled prefix skip).
    pub densify_scan_lo: u32,
    /// Last Full-assign `path_lo`; drop watermark when the tip shrinks.
    pub assign_path_lo: u32,
    /// Hashes that already produced one [`super::confirm::ConfirmRejectClass::EngineFault`].
    pub engine_fault_seen: HashSet<BlockHash>,
    /// Set when a second engine-fault hits the same hash — IBD must halt.
    pub halt: Option<String>,
    /// First time confirm rejected without tip progress (download gate timer).
    pub confirm_stuck_since: Option<Instant>,
    /// Set by header-work rewind/plant so the main loop can drop in-channel plans.
    pub confirm_quiesce: bool,
    /// Repeated Cascade at the same tip for the same hash → escalate to halt.
    pub cascade_at: Option<(BlockHash, [u8; 32], u8)>,
    /// Tip-child BadPrev retries. Another block's soft reject does not clear this.
    pub tip_child_bad_prev: Option<(BlockHash, [u8; 32], u8)>,
    /// Assign-stop byte budget, snapshotted when assign runs (`u64::MAX` = off).
    pub intake_stop: u64,
    /// Body-queue bytes snapshotted with [`Self::intake_stop`].
    pub intake_queued: u64,
    /// Recent block payload lengths, oldest first. Per-peer byte cap only.
    pub block_lens: VecDeque<u32>,
    /// Checkpoints for headers past the download queue.
    pub header_walk: super::header_walk::HeaderWalk,
    /// `-whitelist` / operator noban grants. `None`: no peer is noban.
    pub perms: Option<std::sync::Arc<rbitcoin_net::peers::PeerHub>>,
    /// Confirm engine feed: assign does not demote a body load still holds.
    pub confirm_feed: Option<std::sync::Arc<super::confirm::ConfirmFeed>>,
    /// Set while a header thread owns store IO. Peer reads only enqueue.
    pub header_cmd: Option<HeaderCmdTx>,
    /// Heights below this are already claim-ready. Rewind starts here.
    pub densify_ready_through: u32,
    /// Confirmed-chain `getheaders` tail for one published tip.
    pub confirmed_locator_tail: Option<ConfirmedLocatorTail>,
}

pub enum HeaderCmd {
    Batch {
        peer: usize,
        headers: Vec<bitcoin::block::Header>,
    },
    Ask,
    Reseed,
    Report,
}

/// Header batches waiting on the header thread. Past this, the coordination
/// loop stops pulling header events so the queue cannot grow without bound.
pub const HEADER_CMD_BOUND: usize = 64;

pub type HeaderCmdTx = tokio::sync::mpsc::Sender<HeaderCmd>;

/// Send `cmd` to the header thread. A full channel leaves the event on the
/// peer queue; the coordination loop stops pulling header events until there
/// is room.
pub fn enqueue_header_cmd(st: &mut IbdWorkState, cmd: HeaderCmd) {
    let Some(tx) = st.header_cmd.clone() else {
        return;
    };
    let _ = tx.try_send(cmd);
}

impl IbdWorkState {
    pub fn new(slots: Vec<PeerSlot>, tip_hash: Option<BlockHash>, tip_height: Option<u32>) -> Self {
        let mut known_headers = HashSet::new();
        let mut hash_height = HashMap::new();
        let mut max_peer_height = tip_height.unwrap_or(0);
        if let Some(h) = tip_hash {
            known_headers.insert(h);
            if let Some(th) = tip_height {
                hash_height.insert(h, th);
            }
        }
        for s in &slots {
            max_peer_height = max_peer_height.max(s.peer_height);
        }
        let start_tip = tip_height.unwrap_or(0);
        Self {
            slots,
            inflight: HashMap::new(),
            ordered: VecDeque::new(),
            ordered_set: HashSet::new(),
            hash_height,
            path_prev: HashMap::new(),
            height_to_hash: {
                let mut m = HashMap::new();
                if let (Some(h), Some(th)) = (tip_hash, tip_height) {
                    m.insert(th, h);
                }
                m
            },
            known_headers,
            body: BodyPresence::new(),
            header_fks: HashMap::new(),
            max_peer_height,
            max_ready_height: start_tip,
            max_ordered_height: start_tip,
            headers_done: false,
            empty_header_streak: 0,
            header_req_seq: 0,
            assign_rot: 0,
            addr_cooldown: HashMap::new(),
            addr_buckets: HashMap::new(),
            addr_strikes: HashMap::new(),
            relative_slow_suspect: None,
            relative_slow_last_kick_ms: 0,
            reorg: IbdReorgState::new(),
            densify_scan_lo: 0,
            assign_path_lo: 0,
            engine_fault_seen: HashSet::new(),
            halt: None,
            confirm_stuck_since: None,
            confirm_quiesce: false,
            cascade_at: None,
            tip_child_bad_prev: None,
            intake_stop: u64::MAX,
            intake_queued: 0,
            block_lens: VecDeque::new(),
            header_walk: super::header_walk::HeaderWalk::default(),
            perms: None,
            confirm_feed: None,
            header_cmd: None,
            densify_ready_through: 0,
            confirmed_locator_tail: None,
        }
    }

    /// Record `hash` at chain height `ht` (keeps inverse map in sync).
    ///
    /// Tests / reorg gather may plant a slot. Header intake uses
    /// [`Self::try_set_path_slot`] (first-wins, prev-anchored).
    /// Hashes that left `inflight` without arriving. Densify skips forward past
    /// requested heights and never walks below `densify_scan_lo`, so move the
    /// cursor back to the lowest of them or densify will not request them again.
    pub fn reopen_for_densify(&mut self, freed: &[BlockHash]) {
        let lowest = freed
            .iter()
            .filter_map(|h| self.hash_height.get(h).copied())
            .min();
        if let Some(lo) = lowest {
            self.densify_scan_lo = self.densify_scan_lo.min(lo);
            self.densify_ready_through = self.densify_ready_through.min(lo);
        }
    }

    pub fn record_height(&mut self, hash: BlockHash, ht: u32) {
        if let Some(old) = self.hash_height.insert(hash, ht) {
            if old != ht && self.height_to_hash.get(&old) == Some(&hash) {
                self.height_to_hash.remove(&old);
            }
        }
        self.height_to_hash.insert(ht, hash);
    }

    /// Admit `hash` to the work-path slot `ht` only if it chains onto the
    /// occupant of `ht-1` (or onto the store tip for tip+1). First-wins:
    /// a competing header never displaces a connected occupant.
    ///
    /// Always records `hash_height`. Returns whether the path slot was set
    /// to `hash`.
    pub fn note_path_prev(&mut self, hash: BlockHash, prev: BlockHash) {
        self.path_prev.insert(hash, prev);
    }

    pub fn try_set_path_slot(
        &mut self,
        hash: BlockHash,
        ht: u32,
        prev: BlockHash,
        tip: Option<(u32, BlockHash)>,
    ) -> bool {
        self.path_prev.insert(hash, prev);
        if let Some(old) = self.hash_height.insert(hash, ht) {
            if old != ht && self.height_to_hash.get(&old) == Some(&hash) {
                self.height_to_hash.remove(&old);
            }
        }
        let anchored = match tip {
            Some((tip_h, tip_hash)) if ht == tip_h.saturating_add(1) => prev == tip_hash,
            _ => self.height_to_hash.get(&ht.wrapping_sub(1)) == Some(&prev),
        };
        if !anchored {
            return false;
        }
        if let Some(cur) = self.height_to_hash.get(&ht) {
            return *cur == hash;
        }
        self.height_to_hash.insert(ht, hash);
        true
    }

    pub fn is_on_path(&self, hash: &BlockHash, ht: u32) -> bool {
        self.height_to_hash.get(&ht) == Some(hash)
    }

    /// Drop work-path slots strictly above `ht` (reorg apply suffix).
    pub fn clear_path_above(&mut self, ht: u32) {
        let drop: Vec<BlockHash> = self
            .height_to_hash
            .iter()
            .filter(|(h, _)| **h > ht)
            .map(|(_, hash)| *hash)
            .collect();
        self.height_to_hash.retain(|h, _| *h <= ht);
        for hash in drop {
            self.ordered_set.remove(&hash);
        }
        while let Some(front) = self.ordered.front().copied() {
            if self.ordered_set.contains(&front) {
                break;
            }
            self.ordered.pop_front();
        }
    }

    /// Cheap occupancy of work-path maps/deques (for `ibd: sizes`; all O(1) lens).
    pub fn structure_sizes(&self) -> WorkStructureSizes {
        let peer_inflight: usize = self.slots.iter().map(|s| s.in_flight.len()).sum();
        WorkStructureSizes {
            ordered: self.ordered.len(),
            ordered_set: self.ordered_set.len(),
            hash_height: self.hash_height.len(),
            height_to_hash: self.height_to_hash.len(),
            header_fks: self.header_fks.len(),
            known_headers: self.known_headers.len(),
            inflight: self.inflight.len(),
            peer_inflight,
            addr_cooldown: self.addr_cooldown.len(),
            body: self.body.size_snapshot(),
        }
    }

    /// True when `ordered` has piled up ghost entries (completed hashes left
    /// in the deque). Caller cadences retain; bloat skips the wait.
    pub fn ordered_bloated(&self) -> bool {
        self.ordered.len() > self.ordered_set.len().saturating_mul(4).max(128)
    }

    /// Per-second work-path hygiene: **O(live)**.
    ///
    /// Compacts `ordered` ghosts, drops `height_to_hash` rows that no longer
    /// name the occupant of their height, and bounds the body cache to live
    /// work. Chain-sized maps are [`Self::deep_hygiene`]; sweeping them here
    /// cost ~0.8 s of every second at a mainnet tip.
    pub fn hygiene(&mut self) {
        compact_ordered(&mut self.ordered, &self.ordered_set);
        let live = &self.ordered_set;
        let inflight = &self.inflight;
        // Retain chained occupants. Do not clear+rebuild (HashMap order is
        // last-write and would remix two hashes at one height).
        let queue_tail = self
            .ordered
            .iter()
            .rev()
            .find(|hash| live.contains(*hash))
            .and_then(|hash| self.hash_height.get(hash).copied())
            .unwrap_or(0);
        self.height_to_hash.retain(|ht, hash| {
            self.hash_height.get(hash) == Some(ht)
                && (live.contains(hash)
                    || inflight.contains_key(hash)
                    || (*ht > queue_tail && self.header_walk.indexes_through(*ht)))
        });
        // Bound body presence cache to live work (rejected
        // never hygiene-pruned — see BodyPresence::hygiene_retain).
        self.body
            .hygiene_retain(|h| live.contains(h) || inflight.contains_key(h));
    }

    /// Chain-sized prune of the work-path maps: **O(known headers)**.
    ///
    /// `known_headers` keeps the whole header chain by design: when tip drains
    /// `ordered`, re-getheaders must re-resolve height and re-admit without a
    /// full store walk. Wiping them left known_hdr=N with hash_h=0 and freeze.
    /// This drops only headers that are not the occupant of their height (side
    /// branches), plus the `header_fks` / `hash_height` / `path_prev` rows that
    /// followed them. Caller owns cadence: main loop every
    /// `cadence::DEEP_HYGIENE_PERIOD`, never per turn.
    pub fn deep_hygiene(&mut self) {
        let live = &self.ordered_set;
        let inflight = &self.inflight;
        if self.known_headers.len() <= live.len().saturating_add(4096) {
            return;
        }
        self.known_headers.retain(|h| {
            live.contains(h)
                || inflight.contains_key(h)
                || self
                    .hash_height
                    .get(h)
                    .is_some_and(|ht| self.height_to_hash.get(ht) == Some(h))
        });
        self.header_fks.retain(|h, _| {
            live.contains(h) || inflight.contains_key(h) || self.known_headers.contains(h)
        });
        self.hash_height.retain(|h, _| {
            live.contains(h) || inflight.contains_key(h) || self.known_headers.contains(h)
        });
        self.path_prev.retain(|h, _| {
            live.contains(h) || inflight.contains_key(h) || self.known_headers.contains(h)
        });
    }
}
