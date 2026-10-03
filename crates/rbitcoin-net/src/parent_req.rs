//! Missing-parent GETDATA tracker.
//!
//! One mutex owns the hash map and a per-peer time index. A heartbeat walks
//! only that peer's due entries. Caps are announcements, not a new knob.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{GETDATA_TX_INTERVAL_SECS, MAX_PARENTS_PER_PARK};

/// Announcements one peer may add. Past this the map does not grow.
pub(super) const MAX_PARENT_ANN_PER_PEER: usize = 5_000;
/// Process-wide announcements. A few hundred thousand, not tens of millions.
pub(super) const MAX_PARENT_ANN_GLOBAL: usize = 200_000;

/// One parent GETDATA the sweep should send.
pub(crate) struct DueParent {
    pub hash: [u8; 32],
    pub wtxid: bool,
}

struct ParentAnn {
    peer: u64,
    preferred: bool,
    reqtime: u64,
    /// Bucket in `due_by_peer` while this ann is waiting to be selected.
    due_at: Option<u64>,
    requested_until: Option<u64>,
    failed: bool,
}

struct ParentSlot {
    anns: Vec<ParentAnn>,
    /// The hash arrived as a wtxid inv. Orphan parents are txids.
    wtxid: bool,
}

/// Hash map plus per-peer due and in-flight indexes. The indexes are one
/// entry per announcement and stop at the same caps (extra RAM, not a scan
/// of every peer on the heartbeat).
pub(super) struct ParentTracker {
    by_hash: HashMap<[u8; 32], ParentSlot>,
    due_by_peer: HashMap<u64, BTreeMap<u64, Vec<[u8; 32]>>>,
    inflight_by_peer: HashMap<u64, BTreeMap<u64, Vec<[u8; 32]>>>,
    hashes_by_peer: HashMap<u64, HashSet<[u8; 32]>>,
    ann_per_peer: HashMap<u64, usize>,
    announcements: usize,
}

impl ParentTracker {
    pub(super) fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            due_by_peer: HashMap::new(),
            inflight_by_peer: HashMap::new(),
            hashes_by_peer: HashMap::new(),
            ann_per_peer: HashMap::new(),
            announcements: 0,
        }
    }

    fn at_cap(&self, peer: u64) -> bool {
        self.announcements >= MAX_PARENT_ANN_GLOBAL
            || self.ann_per_peer.get(&peer).copied().unwrap_or(0) >= MAX_PARENT_ANN_PER_PEER
    }

    pub(super) fn note_inv(
        &mut self,
        peer: u64,
        hash: [u8; 32],
        inbound: bool,
        now: u64,
        wtxid: bool,
    ) -> bool {
        if self.rearm_existing(peer, hash, now, wtxid) {
            return true;
        }
        if self.at_cap(peer) {
            return false;
        }
        let exp = now.saturating_add(GETDATA_TX_INTERVAL_SECS);
        self.add_ann(
            hash,
            ParentAnn {
                peer,
                preferred: !inbound,
                reqtime: now,
                due_at: None,
                requested_until: Some(exp),
                failed: false,
            },
            wtxid,
        );
        true
    }

    pub(super) fn schedule(&mut self, hash: [u8; 32], peer: u64, preferred: bool, reqtime: u64) {
        if self
            .by_hash
            .get(&hash)
            .is_some_and(|slot| slot.anns.iter().any(|a| a.peer == peer))
        {
            return;
        }
        if self.at_cap(peer) {
            return;
        }
        self.add_ann(
            hash,
            ParentAnn {
                peer,
                preferred,
                reqtime,
                due_at: Some(reqtime),
                requested_until: None,
                failed: false,
            },
            false,
        );
    }

    /// True when this peer already had an announcement for `hash`.
    fn rearm_existing(&mut self, peer: u64, hash: [u8; 32], now: u64, wtxid: bool) -> bool {
        let Some(slot) = self.by_hash.get_mut(&hash) else {
            return false;
        };
        if wtxid {
            slot.wtxid = true;
        }
        let Some(pos) = slot.anns.iter().position(|a| a.peer == peer) else {
            return false;
        };
        let due_at = {
            if slot.anns[pos].requested_until.is_some() || slot.anns[pos].failed {
                return true;
            }
            let exp = now.saturating_add(GETDATA_TX_INTERVAL_SECS);
            let due_at = slot.anns[pos].due_at;
            slot.anns[pos].requested_until = Some(exp);
            slot.anns[pos].due_at = None;
            (due_at, exp)
        };
        if let Some(t) = due_at.0 {
            unindex(&mut self.due_by_peer, peer, t, &hash);
        }
        index_at(&mut self.inflight_by_peer, peer, due_at.1, hash);
        true
    }

    fn add_ann(&mut self, hash: [u8; 32], ann: ParentAnn, wtxid: bool) {
        let peer = ann.peer;
        let due_at = ann.due_at;
        let exp = ann.requested_until;
        let slot = self.by_hash.entry(hash).or_insert_with(|| ParentSlot {
            anns: Vec::new(),
            wtxid: false,
        });
        if wtxid {
            slot.wtxid = true;
        }
        slot.anns.push(ann);
        *self.ann_per_peer.entry(peer).or_default() += 1;
        self.announcements += 1;
        self.hashes_by_peer.entry(peer).or_default().insert(hash);
        if let Some(exp) = exp {
            index_at(&mut self.inflight_by_peer, peer, exp, hash);
        } else if let Some(t) = due_at {
            index_at(&mut self.due_by_peer, peer, t, hash);
        }
    }

    pub(super) fn forget_peer(&mut self, peer: u64) {
        self.due_by_peer.remove(&peer);
        self.inflight_by_peer.remove(&peer);
        let Some(hashes) = self.hashes_by_peer.remove(&peer) else {
            return;
        };
        for hash in hashes {
            self.remove_peer_ann(&hash, peer);
        }
    }

    pub(super) fn announcer_peers(&self, hashes: [[u8; 32]; 2]) -> Vec<u64> {
        let mut peers = Vec::new();
        for hash in hashes {
            let Some(slot) = self.by_hash.get(&hash) else {
                continue;
            };
            for a in &slot.anns {
                if !a.failed && !peers.contains(&a.peer) {
                    peers.push(a.peer);
                }
            }
        }
        peers
    }

    pub(super) fn resolve(&mut self, hashes: [[u8; 32]; 2], admitted: bool) {
        for hash in hashes {
            if admitted {
                self.remove_hash(&hash);
                continue;
            }
            let inflight = self.inflight_peers(&hash);
            for (peer, exp) in inflight {
                self.fail_inflight(&hash, peer, exp);
            }
            if self.slot_all_failed(&hash) {
                self.remove_hash(&hash);
            }
        }
    }

    pub(super) fn take_due(
        &mut self,
        peer: u64,
        now: u64,
        mut already_have: impl FnMut(&[u8; 32], bool) -> bool,
    ) -> Vec<DueParent> {
        self.expire_peer_inflight(peer, now);
        let due_hashes = self.due_hashes(peer, now);
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for hash in due_hashes {
            if out.len() >= MAX_PARENTS_PER_PARK {
                break;
            }
            if !seen.insert(hash) {
                continue;
            }
            self.expire_hash_inflight(&hash, now);
            if !self.by_hash.contains_key(&hash) {
                continue;
            }
            if self.slot_all_failed(&hash) {
                self.remove_hash(&hash);
                continue;
            }
            let wtxid = self.by_hash.get(&hash).is_some_and(|s| s.wtxid);
            if already_have(&hash, wtxid) {
                self.remove_hash(&hash);
                continue;
            }
            if self.earliest_inflight(&hash).is_some() {
                continue;
            }
            if self.select(peer, now, &hash).is_none() {
                continue;
            }
            out.push(DueParent { hash, wtxid });
        }
        out
    }

    fn due_hashes(&self, peer: u64, now: u64) -> Vec<[u8; 32]> {
        let Some(tree) = self.due_by_peer.get(&peer) else {
            return Vec::new();
        };
        tree.range(..=now)
            .flat_map(|(_, v)| v.iter().copied())
            .collect()
    }

    fn select(&mut self, peer: u64, now: u64, hash: &[u8; 32]) -> Option<()> {
        let exp = now.saturating_add(GETDATA_TX_INTERVAL_SECS);
        let due_at = {
            let slot = self.by_hash.get_mut(hash)?;
            let has_pref = slot
                .anns
                .iter()
                .any(|a| a.preferred && !a.failed && a.reqtime <= now);
            let pos = slot.anns.iter().position(|a| {
                !a.failed && a.reqtime <= now && a.peer == peer && (!has_pref || a.preferred)
            })?;
            let ann = &mut slot.anns[pos];
            let due_at = ann.due_at.unwrap_or(ann.reqtime);
            ann.requested_until = Some(exp);
            ann.due_at = None;
            due_at
        };
        unindex(&mut self.due_by_peer, peer, due_at, hash);
        index_at(&mut self.inflight_by_peer, peer, exp, *hash);
        Some(())
    }

    fn expire_peer_inflight(&mut self, peer: u64, now: u64) {
        let expired = self
            .inflight_by_peer
            .get(&peer)
            .map(|tree| {
                tree.range(..=now)
                    .flat_map(|(t, v)| v.iter().map(|h| (*t, *h)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (exp, hash) in expired {
            self.fail_inflight(&hash, peer, exp);
            if self.slot_all_failed(&hash) {
                self.remove_hash(&hash);
            }
        }
    }

    fn expire_hash_inflight(&mut self, hash: &[u8; 32], now: u64) {
        let expired = self.inflight_peers(hash);
        for (peer, exp) in expired {
            if exp <= now {
                self.fail_inflight(hash, peer, exp);
            }
        }
        if self.slot_all_failed(hash) {
            self.remove_hash(hash);
        }
    }

    fn inflight_peers(&self, hash: &[u8; 32]) -> Vec<(u64, u64)> {
        self.by_hash
            .get(hash)
            .map(|slot| {
                slot.anns
                    .iter()
                    .filter_map(|a| a.requested_until.map(|exp| (a.peer, exp)))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn earliest_inflight(&self, hash: &[u8; 32]) -> Option<u64> {
        self.inflight_peers(hash).into_iter().map(|(_, e)| e).min()
    }

    fn fail_inflight(&mut self, hash: &[u8; 32], peer: u64, exp: u64) {
        let unindex_it = match self.by_hash.get_mut(hash) {
            None => true,
            Some(slot) => match slot.anns.iter_mut().find(|a| a.peer == peer) {
                None => true,
                Some(ann) if ann.requested_until == Some(exp) => {
                    ann.requested_until = None;
                    ann.failed = true;
                    true
                }
                Some(_) => false,
            },
        };
        if unindex_it {
            unindex(&mut self.inflight_by_peer, peer, exp, hash);
        }
    }

    fn slot_all_failed(&self, hash: &[u8; 32]) -> bool {
        self.by_hash
            .get(hash)
            .is_some_and(|slot| !slot.anns.is_empty() && slot.anns.iter().all(|a| a.failed))
    }

    fn remove_hash(&mut self, hash: &[u8; 32]) {
        let Some(slot) = self.by_hash.remove(hash) else {
            return;
        };
        for ann in slot.anns {
            self.note_removed_ann(&ann, hash);
        }
    }

    fn remove_peer_ann(&mut self, hash: &[u8; 32], peer: u64) {
        let Some(ann) = self.by_hash.get_mut(hash).and_then(|slot| {
            let pos = slot.anns.iter().position(|a| a.peer == peer)?;
            Some(slot.anns.swap_remove(pos))
        }) else {
            return;
        };
        if self
            .by_hash
            .get(hash)
            .is_some_and(|slot| slot.anns.is_empty())
        {
            self.by_hash.remove(hash);
        }
        self.note_removed_ann(&ann, hash);
    }

    fn note_removed_ann(&mut self, ann: &ParentAnn, hash: &[u8; 32]) {
        self.announcements = self.announcements.saturating_sub(1);
        if let Some(c) = self.ann_per_peer.get_mut(&ann.peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.ann_per_peer.remove(&ann.peer);
            }
        }
        if let Some(set) = self.hashes_by_peer.get_mut(&ann.peer) {
            let still = self
                .by_hash
                .get(hash)
                .is_some_and(|slot| slot.anns.iter().any(|a| a.peer == ann.peer));
            if !still {
                set.remove(hash);
                if set.is_empty() {
                    self.hashes_by_peer.remove(&ann.peer);
                }
            }
        }
        if let Some(exp) = ann.requested_until {
            unindex(&mut self.inflight_by_peer, ann.peer, exp, hash);
        }
        if let Some(t) = ann.due_at {
            unindex(&mut self.due_by_peer, ann.peer, t, hash);
        }
    }
}

fn index_at(
    tree: &mut HashMap<u64, BTreeMap<u64, Vec<[u8; 32]>>>,
    peer: u64,
    time: u64,
    hash: [u8; 32],
) {
    tree.entry(peer)
        .or_default()
        .entry(time)
        .or_default()
        .push(hash);
}

fn unindex(
    tree: &mut HashMap<u64, BTreeMap<u64, Vec<[u8; 32]>>>,
    peer: u64,
    time: u64,
    hash: &[u8; 32],
) {
    let Some(by_time) = tree.get_mut(&peer) else {
        return;
    };
    let Some(v) = by_time.get_mut(&time) else {
        return;
    };
    if let Some(i) = v.iter().position(|h| h == hash) {
        v.swap_remove(i);
    }
    if v.is_empty() {
        by_time.remove(&time);
    }
    if by_time.is_empty() {
        tree.remove(&peer);
    }
}
