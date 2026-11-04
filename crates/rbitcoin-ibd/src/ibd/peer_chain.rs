//! What one IBD peer has shown of its chain.
//!
//! Core asks a peer only for blocks on that peer's best known chain
//! (`pindexBestKnownBlock`). A peer whose announced headers leave the
//! download path is not asked for blocks above that point, and a peer that
//! answered `notfound` for a block is not asked for it again for a while.

use super::state::HeightOccupants;
use bitcoin::block::Header;
use bitcoin::BlockHash;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// `notfound` hashes kept per peer. Past the cap a peer may be asked again.
const LACKS_CAP: usize = 1024;
/// How long a `notfound` keeps a peer off that block: one stall window. A
/// peer that answered `notfound` everywhere is asked again after it.
const LACKS_TTL_MS: u64 = 30_000;

/// Announced hashes kept per peer: one full `headers` reply.
const ANNOUNCED_CAP: usize = rbitcoin_net::codec::MAX_HEADERS_RESULTS;

/// How often a peer whose record no longer decides the next blocks is
/// probed again.
const PROBE_REFRESH: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
pub struct PeerChain {
    /// `notfound` hashes, with the mono ms they were answered.
    lacks: HashMap<BlockHash, u64>,
    /// This peer's announced chain above the confirmed tip, oldest first.
    announced: VecDeque<BlockHash>,
    /// Height of `announced[0]`.
    from: u32,
    /// Top of this peer's chain: the last reply was shorter than a full
    /// `headers` batch and ended here, or a probe found nothing above the
    /// confirmed tip. The peer has no block above it.
    ends: Option<u32>,
    /// The peer's header at the first height where its announced chain
    /// differed from this node's chain (path or confirmed) when announced.
    split: Option<(u32, BlockHash)>,
    /// That height has left the path and this node's confirmed block there
    /// is a different one.
    split_confirmed: bool,
    /// A rewind replaced this node's chain from this height, and the record
    /// took the old blocks as the peer's chain. The peer is not taken to hold
    /// a block at or above it until it answers again.
    stale_from: Option<u32>,
    /// The highest path block this peer showed through a probe that asked
    /// for headers after it. It holds every path block at or below it while
    /// the path still holds that block there.
    reaches: Option<(u32, BlockHash)>,
    /// The last probe asked after the path top and the reply did not show
    /// it, so the next probe asks from the confirmed tip.
    probe_from_tip: bool,
    /// The peer announced headers, or was asked for them.
    probed: bool,
    /// When the last probe was sent.
    probed_at: Option<Instant>,
}

impl PeerChain {
    pub fn note_notfound(&mut self, hash: BlockHash, now_ms: u64) {
        if self.lacks.len() >= LACKS_CAP {
            self.lacks
                .retain(|_, at| now_ms.saturating_sub(*at) < LACKS_TTL_MS);
        }
        if self.lacks.len() < LACKS_CAP {
            self.lacks.insert(hash, now_ms);
        }
    }

    pub fn lacks(&self, hash: &BlockHash, now_ms: u64) -> bool {
        self.lacks
            .get(hash)
            .is_some_and(|at| now_ms.saturating_sub(*at) < LACKS_TTL_MS)
    }

    /// A headers message or a block inv: the peer may have those blocks now.
    pub fn note_announcement(&mut self) {
        self.lacks.clear();
    }

    pub fn probed(&self) -> bool {
        self.probed
    }

    /// Whether the next probe asks from the confirmed tip.
    pub fn probe_from_tip(&self) -> bool {
        self.probe_from_tip
    }

    /// A probe was sent `at`, from the tip or after the path top.
    pub fn note_probe_sent(&mut self, at: Instant, from_tip: bool) {
        self.probed = true;
        self.probed_at = Some(at);
        if from_tip {
            self.probe_from_tip = false;
        }
    }

    /// The peer's chain holds the path block `hash` at `height`.
    pub fn note_reaches(&mut self, height: u32, hash: BlockHash) {
        self.reaches = Some((height, hash));
    }

    /// The reply to a probe after the path top did not show it: ask from
    /// the confirmed tip next.
    pub fn note_lacks_top(&mut self) {
        self.probe_from_tip = true;
        self.probed = false;
    }

    /// The record no longer says whether the peer holds the path block at
    /// `height`, and no probe was sent within one refresh.
    pub fn needs_refresh(&self, path: &impl HeightOccupants, height: u32, now: Instant) -> bool {
        self.probed
            && self
                .probed_at
                .is_none_or(|at| now.saturating_duration_since(at) >= PROBE_REFRESH)
            && !self.shows(path, height)
            && !self.left_path_by(path, height)
    }

    /// An empty reply to a walk ask: the peer is at one of several locator
    /// hashes, the path top or the confirmed tip. Ask it once more from the
    /// tip.
    pub fn forget_probe(&mut self) {
        self.probed = false;
    }

    /// An empty reply to a probe from the confirmed `tip`: this peer has
    /// nothing above it.
    pub fn note_ends_at(&mut self, tip: u32) {
        self.probed = true;
        self.announced.clear();
        self.from = tip.saturating_add(1);
        self.ends = Some(tip);
    }

    /// Keep announced `headers`, the first at `height`, against this node's
    /// chain: the `path`, or a `confirmed` block at or below `tip`. The first
    /// height where they differ is where the peer leaves this chain; a later
    /// reply that agrees there clears it. Only heights above `tip` are kept,
    /// newest last: a reply that continues the kept run extends it, any other
    /// replaces it, and the oldest hashes past one full reply give way. A
    /// short reply is where the peer's chain ends, also at or below the tip.
    pub fn note_headers(
        &mut self,
        path: &impl HeightOccupants,
        confirmed: impl Fn(u32) -> Option<BlockHash>,
        tip: u32,
        height: u32,
        headers: &[Header],
    ) {
        self.probed = true;
        let hashes: Vec<BlockHash> = headers.iter().map(|h| h.block_hash()).collect();
        let mut split_moved = false;
        let ours = |ht: u32| {
            path.occupant(ht)
                .or_else(|| (ht <= tip).then(|| confirmed(ht)).flatten())
        };
        // A reply on this node's block proves this chain below it, so a split
        // at or below that block is gone. Every chain shares genesis.
        if let Some(first) = headers.first() {
            if height > 1
                && ours(height - 1) == Some(first.prev_blockhash)
                && self.split.is_some_and(|(at, _)| at < height)
            {
                self.split = None;
            }
        }
        for (ht, hash) in (height..).zip(&hashes) {
            let on_path = path.occupant(ht);
            let Some(our) = ours(ht) else {
                continue;
            };
            if our == *hash {
                if self.split.is_some_and(|(at, _)| at == ht) {
                    self.split = None;
                }
                continue;
            }
            if self.split.is_none_or(|(at, _)| ht <= at) {
                self.split = Some((ht, *hash));
                self.split_confirmed = on_path.is_none();
                split_moved = true;
            }
            break;
        }
        let short = headers.len() < ANNOUNCED_CAP;
        let top = height.saturating_add(hashes.len() as u32).saturating_sub(1);
        // A stale record is answered by a reply that reaches its fork. One
        // that ends below the fork says nothing there: ask again.
        if let Some(stale) = self.stale_from {
            if top >= stale {
                self.stale_from = None;
            } else {
                self.probed = false;
            }
        }
        self.ends = short.then_some(top);
        let drop = tip.saturating_add(1).saturating_sub(self.from) as usize;
        self.announced.drain(..drop.min(self.announced.len()));
        self.from = self.from.max(tip.saturating_add(1));
        let skip = tip.saturating_add(1).saturating_sub(height) as usize;
        let Some(fresh) = hashes.get(skip..).filter(|h| !h.is_empty()) else {
            // Nothing above the tip. A short reply ended the peer's chain at
            // or below it; a split that moved leaves the kept run on the
            // chain the peer left.
            if split_moved || short {
                self.announced.clear();
            }
            return;
        };
        let start = height.saturating_add(skip as u32);
        let end = self.from.saturating_add(self.announced.len() as u32);
        // The kept run continues only from the parent of `start`.
        let parent = match skip {
            0 => headers[0].prev_blockhash,
            k => hashes[k - 1],
        };
        let keep = (start > self.from && start <= end)
            .then(|| (start - self.from) as usize)
            .filter(|&k| self.announced[k - 1] == parent);
        match keep {
            Some(k) => self.announced.truncate(k),
            None => {
                self.announced.clear();
                self.from = start;
            }
        }
        self.announced.extend(fresh.iter().copied());
        let over = self.announced.len().saturating_sub(ANNOUNCED_CAP);
        self.announced.drain(..over);
        self.from = self.from.saturating_add(over as u32);
    }

    /// This node's confirmed chain above `lca` was rewound away, and `path`
    /// is the chain planted in its place. A record that starts past the fork
    /// took the old blocks as the peer's chain, so it is stale from the fork
    /// up until the peer answers again, and the peer is probed. A split the
    /// peer showed at or below the fork already says where it left, and an
    /// announced hash on the new path says it is on the new chain.
    pub fn note_rewind(&mut self, path: &impl HeightOccupants, lca: u32) {
        let at = lca.saturating_add(1);
        if self.from <= at || self.split.is_some_and(|(h, _)| h <= at) {
            return;
        }
        if (self.from..)
            .zip(&self.announced)
            .any(|(h, hash)| path.occupant(h).as_ref() == Some(hash))
        {
            return;
        }
        self.stale_from = Some(self.stale_from.map_or(at, |s| s.min(at)));
        self.probed = false;
    }

    /// Split height that is no longer on `path`, if this peer has one.
    pub fn off_path_split_height(&self, path: &impl HeightOccupants) -> Option<u32> {
        let (at, _) = self.split?;
        if path.occupant(at).is_some() {
            return None;
        }
        Some(at)
    }

    /// The recorded split's height has left the path: compare it with this
    /// node's `confirmed` block there. The same block means this node took
    /// the peer's chain, so the split is gone.
    pub fn settle_split(
        &mut self,
        path: &impl HeightOccupants,
        confirmed: impl Fn(u32) -> Option<BlockHash>,
    ) {
        let Some((at, hash)) = self.split else {
            return;
        };
        if path.occupant(at).is_some() {
            return;
        }
        match confirmed(at) {
            Some(ours) if ours == hash => self.split = None,
            ours => self.split_confirmed = ours.is_some(),
        }
    }

    /// This peer's announced chain holds the path block at `height`: it
    /// announced that block, or a path block above it, and has not left the
    /// path at or below it.
    pub fn shows(&self, path: &impl HeightOccupants, height: u32) -> bool {
        if self.left_path_by(path, height) {
            return false;
        }
        // A path block the peer holds, from a probe or from where its chain
        // left this one before this node took its chain.
        let holds = |at: Option<(u32, BlockHash)>| {
            at.is_some_and(|(h, hash)| height <= h && path.occupant(h) == Some(hash))
        };
        if holds(self.reaches) || holds(self.split) {
            return true;
        }
        let Some(len) = (self.announced.len() as u32).checked_sub(1) else {
            return false;
        };
        if height > self.from.saturating_add(len) {
            return false;
        }
        let at = height.max(self.from);
        path.occupant(at)
            .is_some_and(|p| p == self.announced[(at - self.from) as usize])
    }

    /// The peer does not have the path block at `height`: its chain left this
    /// node's chain at or below it, it holds a different block there, its
    /// whole chain ends below it, or a rewind left its record stale there. Two
    /// chains that differ at one height differ above it.
    pub fn left_path_by(&self, path: &impl HeightOccupants, height: u32) -> bool {
        if self.stale_from.is_some_and(|from| height >= from) {
            return true;
        }
        if let Some((at, hash)) = self.split {
            let differs = match path.occupant(at) {
                Some(p) => p != hash,
                None => self.split_confirmed,
            };
            if at <= height && differs {
                return true;
            }
        }
        if self.ends.is_some_and(|top| height > top) {
            return true;
        }
        let Some(len) = (self.announced.len() as u32).checked_sub(1) else {
            return false;
        };
        if height < self.from {
            return false;
        }
        let top = self.from.saturating_add(len);
        let at = height.min(top);
        let peer = self.announced[(at - self.from) as usize];
        path.occupant(at).is_some_and(|p| p != peer)
    }
}

/// This node's confirmed block at `height`.
pub fn confirmed_at(hub: &rbitcoin_net::chain::ChainHub, height: u32) -> Option<BlockHash> {
    use bitcoin::hashes::Hash;
    let (_, rec) = hub
        .query
        .header_at_height(rbitcoin_primitives::Height(height))
        .ok()
        .flatten()?;
    Some(BlockHash::from_byte_array(rec.hash))
}
