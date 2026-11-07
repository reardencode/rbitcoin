//! IBD most-work reorg: classify BadPrev, rank candidates, rewind + linear confirm.
//!
//! See `docs/architecture.md` (most-work chain selection). Orchestration-thread only.

use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, CompactTarget, Target};
use rbitcoin_log::{info, warn};
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::error::NetError;
use rbitcoin_net::most_work::{sum_work, work_better, InvalidHashSet};
use rbitcoin_primitives::{Fk, Height};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::thread::ThreadId;

/// Whether a confirm reject string is the soft BadPrev class.
pub fn is_bad_prev_err(err: &str) -> bool {
    err.contains("unexpected previous header") || err.contains("unexpected previous")
}

/// Process-local reorg state for one IBD run.
///
/// Side-branch **presence** is held by hash here: the body queue is
/// height-keyed first-wins, so a same-height competitor of the tip cannot
/// live in BQ while the tip path occupies that height. Production only
/// needs presence (`contains`); bodies are in Class A / BQ.
#[derive(Debug, Default)]
pub struct IbdReorgState {
    pub invalid: InvalidHashSet,
    /// Side-branch / reorg-candidate hashes we have already seen.
    pub held_bodies: HashSet<BlockHash>,
    /// Proactive exploration: hashes densify should pull (same-height winner +
    /// extensions).
    pub explore_need: Vec<BlockHash>,
    /// Candidate tips on an exploration path (for proactive most-work apply).
    pub explore_tips: Vec<BlockHash>,
}

impl IbdReorgState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap on held side bodies (DoS / process RAM). Sized for multi-hop BadPrev
    /// paths (mainnet-class LCA walks) without thrashing; still small enough
    /// that unit tests can exercise eviction without huge chains.
    pub const HELD_CAP: usize = 32;

    pub fn hold_body(&mut self, block: Block) {
        let h = block.block_hash();
        if self.held_bodies.len() >= Self::HELD_CAP && !self.held_bodies.contains(&h) {
            if let Some(k) = self.held_bodies.iter().next().copied() {
                self.held_bodies.remove(&k);
            }
        }
        self.held_bodies.insert(h);
        self.explore_need.retain(|x| *x != h);
    }

    /// Cap on each explore list. Small enough that membership stays a scan.
    pub const EXPLORE_CAP: usize = 64;

    /// Register hashes (and optional path tip) for exploration densify / apply.
    ///
    /// Each list keeps at most [`Self::EXPLORE_CAP`] hashes. A new hash past
    /// the cap drops the oldest. The two lists are capped independently.
    pub fn register_explore(
        &mut self,
        need: impl IntoIterator<Item = BlockHash>,
        tip: Option<BlockHash>,
    ) {
        for h in need {
            if self.explore_need.contains(&h) {
                continue;
            }
            if self.explore_need.len() >= Self::EXPLORE_CAP {
                self.explore_need.remove(0);
            }
            self.explore_need.push(h);
        }
        if let Some(t) = tip {
            if !self.explore_tips.contains(&t) {
                if self.explore_tips.len() >= Self::EXPLORE_CAP {
                    self.explore_tips.remove(0);
                }
                self.explore_tips.push(t);
            }
        }
    }

    pub fn explore_tips(&self) -> &[BlockHash] {
        &self.explore_tips
    }

    /// Registered exploration densify hashes (same-height winner + extensions).
    #[cfg(debug_assertions)]
    pub fn explore_need_hashes(&self) -> &[BlockHash] {
        &self.explore_need
    }

    pub fn clear_explore(&mut self) {
        self.explore_need.clear();
        self.explore_tips.clear();
    }

    /// Hashes densify/getdata should still pull for incomplete exploration.
    pub fn need_getdata(&self) -> Vec<BlockHash> {
        self.explore_need
            .iter()
            .copied()
            .filter(|h| !self.held_bodies.contains(h))
            .collect()
    }
}

/// Cap on prev-walks from a header-horizon candidate. Early IBD can have
/// hundreds of thousands of headers above a low confirmed tip; walking the
/// whole gap is CPU + RAM for no reorg.
#[doc(hidden)]
pub const ANCESTOR_WALK_MAX: usize = 10_000;

/// Max confirmed blocks disconnected in one header-driven rewind.
#[doc(hidden)]
pub const REWIND_MAX_DEPTH: u32 = 1_024;

/// Header hashes from `tip` back to (not including) a best-chain / confirmed
/// ancestor, **oldest-first**. Used so BadPrev densify requests every mid-path
/// body to the LCA (mainnet: d1e0 + 02022e + tip+1, not wire_prev alone).
///
/// Stops on [`ChainHub::is_connected`] — [`ChainHub::has_block`] stays true for
/// disconnected once-confirmed losers (`confirmed` is insert-only).
#[cfg(debug_assertions)]
pub fn header_hashes_to_best_ancestor(
    hub: &ChainHub,
    tip: BlockHash,
) -> Result<Vec<BlockHash>, NetError> {
    header_hashes_to_best_ancestor_n(hub, tip, ANCESTOR_WALK_MAX)
}

#[doc(hidden)]
pub fn header_hashes_to_best_ancestor_n(
    hub: &ChainHub,
    tip: BlockHash,
    walk_max: usize,
) -> Result<Vec<BlockHash>, NetError> {
    use bitcoin::hashes::Hash as _;
    let mut rev = Vec::new();
    let mut cur = tip;
    for _ in 0..walk_max {
        if hub.is_connected(&cur) {
            break;
        }
        rev.push(cur);
        let Some((_fk, rec)) = hub
            .query
            .get_header_by_hash(&cur.to_byte_array())
            .map_err(NetError::store)?
        else {
            break;
        };
        let Some(pfk) = rec.prev_fk.get() else {
            break;
        };
        let parent = hub
            .query
            .get_header(rbitcoin_primitives::Fk(pfk))
            .map_err(NetError::store)?;
        cur = BlockHash::from_byte_array(parent.hash);
    }
    rev.reverse();
    Ok(rev)
}

thread_local! {
    static PARENT_HASH_OF_N: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(debug_assertions)]
pub fn reset_parent_hash_of_count() {
    PARENT_HASH_OF_N.with(|c| c.set(0));
}

#[cfg(debug_assertions)]
pub fn parent_hash_of_count() -> u64 {
    PARENT_HASH_OF_N.with(|c| c.get())
}

pub fn parent_hash_of(hub: &ChainHub, hash: BlockHash) -> Result<Option<BlockHash>, NetError> {
    #[cfg(debug_assertions)]
    PARENT_HASH_OF_N.with(|c| c.set(c.get().saturating_add(1)));
    let Some((_, rec)) = hub
        .query
        .get_header_by_hash(&hash.to_byte_array())
        .map_err(NetError::store)?
    else {
        return Ok(None);
    };
    if rec.prev_fk.is_null() {
        return Ok(Some(BlockHash::from_byte_array([0u8; 32])));
    }
    let parent = hub.query.get_header(rec.prev_fk).map_err(NetError::store)?;
    Ok(Some(BlockHash::from_byte_array(parent.hash)))
}

#[doc(hidden)]
pub fn header_work_of(hub: &ChainHub, hash: BlockHash) -> Result<Option<bitcoin::Work>, NetError> {
    let Some((_, rec)) = hub
        .query
        .get_header_by_hash(&hash.to_byte_array())
        .map_err(NetError::store)?
    else {
        return Ok(None);
    };
    Ok(Some(
        Target::from_compact(CompactTarget::from_consensus(rec.bits)).to_work(),
    ))
}

#[doc(hidden)]
pub fn our_work_from_lca(hub: &ChainHub, lca_height: u32) -> Result<bitcoin::Work, NetError> {
    let tip_h = hub.tip_height().unwrap_or(0);
    let mut our = Vec::new();
    if tip_h > lca_height {
        for h in (lca_height + 1)..=tip_h {
            let hdr = hub
                .query
                .wire_header_at_height(Height(h))
                .map_err(NetError::store)?;
            our.push(hdr.work());
        }
    }
    sum_work(our.into_iter()).map_err(|_| NetError::Consensus("work overflow".into()))
}

/// Index of the last hash in the shortest prefix of `path` (oldest-first)
/// whose header work strictly beats our tip from the same LCA.
pub fn shortest_heavier_header_prefix(
    hub: &ChainHub,
    path: &[BlockHash],
) -> Result<Option<usize>, NetError> {
    if path.is_empty() {
        return Ok(None);
    }
    let Some(parent) = parent_hash_of(hub, path[0])? else {
        return Ok(None);
    };
    let lca_h = hub
        .query
        .height_of_hash(&parent.to_byte_array())
        .map_err(NetError::store)?
        .map(|h| h.0)
        .unwrap_or(0);
    let ours = our_work_from_lca(hub, lca_h)?;
    let mut acc = bitcoin::Work::from_be_bytes([0u8; 32]);
    for (i, h) in path.iter().enumerate() {
        let Some(w) = header_work_of(hub, *h)? else {
            return Ok(None);
        };
        acc = acc + w;
        if work_better(acc, ours) {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Unconfirmed hashes from after the best-chain LCA to `candidate` (oldest-first)
/// when that header path does not connect to the current tip and is strictly
/// heavier than our tip from the same LCA.
///
/// Callers getdata these **connecting** hashes instead of waiting for a child
/// of the losing tip (most-work: we followed a lighter fork; a heavier header
/// path is already known).
///
/// A walk that does not reach a **connected** LCA is not a fork: early IBD
/// headers sit tens of thousands above tip, the walk hits [`ANCESTOR_WALK_MAX`],
/// and the join is header-only. Treating that as connecting-search getdata
/// storms `ibd: heavier chain does not connect at tip` on a linear chain.
pub fn connecting_hashes_heavier_disconnected(
    hub: &ChainHub,
    candidate: BlockHash,
) -> Result<Option<Vec<BlockHash>>, NetError> {
    connecting_hashes_heavier_disconnected_n(hub, candidate, ANCESTOR_WALK_MAX)
}

#[doc(hidden)]
pub fn connecting_hashes_heavier_disconnected_n(
    hub: &ChainHub,
    candidate: BlockHash,
    walk_max: usize,
) -> Result<Option<Vec<BlockHash>>, NetError> {
    let Some(tip) = hub.tip_hash() else {
        return Ok(None);
    };
    if candidate == tip || hub.is_connected(&candidate) {
        return Ok(None);
    }
    let path = header_hashes_to_best_ancestor_n(hub, candidate, walk_max)?;
    if path.is_empty() {
        return Ok(None);
    }
    let Some(join) = parent_hash_of(hub, path[0])? else {
        return Ok(Some(path));
    };
    if join == tip || path.contains(&tip) {
        return Ok(None);
    }
    // `has_block` can lag the published tip. If join is on the best chain and
    // path[0] is the next best-chain header, this is a linear extension.
    if let Some(jh) = hub
        .query
        .height_of_hash(&join.to_byte_array())
        .map_err(NetError::store)?
    {
        if let Ok(next) = hub
            .query
            .wire_header_at_height(Height(jh.0.saturating_add(1)))
        {
            if next.block_hash() == path[0] {
                return Ok(None);
            }
        }
    }
    // Join must be a connected LCA. `!has_block(join)` used to return Some
    // here so a mid-path hole still densified — but a capped walk from a far
    // *linear* header horizon also lands on a header-only mid. That is early
    // IBD, not a competing fork. Fork-start uses `is_connected`, not `has_block`.
    if !hub.is_connected(&join) && join.to_byte_array() != [0u8; 32] {
        return Ok(None);
    }
    if shortest_heavier_header_prefix(hub, &path)?.is_none() {
        return Ok(None);
    }
    Ok(Some(path))
}

/// Work-path hashes that may start a connecting search.
///
/// Only tip+1 when it is a **competing** child (parent ≠ current tip). A
/// linear extension or a far `max_ordered` header is not a fork signal —
/// walking the horizon is a multi-second assign tax on ordinary IBD.
pub fn connecting_search_candidates(
    st: &super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<Vec<BlockHash>, NetError> {
    let Some(tip) = hub.tip_hash() else {
        return Ok(Vec::new());
    };
    let tip_h = hub.tip_height().unwrap_or(0);
    let Some(&h) = st.height_to_hash.get(&tip_h.saturating_add(1)) else {
        return Ok(Vec::new());
    };
    // Parent was stored when the header was admitted. A missing parent is not
    // a fork signal — reading the header store here stalls the orchestration
    // loop behind confirm's disk.
    match st.path_prev.get(&h) {
        Some(p) if *p != tip => Ok(vec![h]),
        _ => Ok(Vec::new()),
    }
}

/// Competing tip+1, or the walk candidate while nothing is planted above the
/// confirmed tip. Collecting these does not read the header store.
#[doc(hidden)]
pub fn heavier_fork_candidates(
    st: &super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<(Vec<BlockHash>, HashSet<[u8; 32]>), NetError> {
    let mut cands = connecting_search_candidates(st, hub)?;
    if cands.is_empty() {
        cands.extend(unplanted_walk_tip(st, hub));
    }
    let invalid: HashSet<[u8; 32]> = st.reorg.invalid.iter().collect();
    Ok((cands, invalid))
}

/// Scan a competing work-path tip+1 for a heavier disconnected fork and
/// rewind the confirmed tip to the LCA so the normal pipeline confirms it.
///
/// The caller does not hold `shared`. Candidates are collected under that
/// lock, then the rewind runs with the lock down. One exclusion covers the
/// select, the disconnect, and the commit. The commit is skipped when the
/// tip is no longer the block the prepare disconnected to.
pub fn consider_disconnected_heavier(
    shared: &Mutex<super::state::IbdWorkState>,
    hub: &ChainHub,
) -> Result<bool, NetError> {
    let (cands, invalid) = {
        let st = shared.lock().unwrap_or_else(|err| err.into_inner());
        heavier_fork_candidates(&st, hub)?
    };
    Ok(apply_off_lock_rewind(shared, hub, &cands, &invalid)?.is_some())
}

/// The walk's candidate while nothing is planted above the confirmed tip. A
/// retire walks back to the parent, and a heavier chain that forked under
/// the tip then takes no path slots, so tip+1 names no fork. The main loop
/// rewinds to it; the header thread's rewind does not see it. A candidate
/// that is not stored has no parent, so no rewind is prepared for it.
fn unplanted_walk_tip(st: &super::state::IbdWorkState, hub: &ChainHub) -> Option<BlockHash> {
    let tip_h = hub.tip_height()?;
    let planted =
        !st.ordered.is_empty() || st.height_to_hash.contains_key(&tip_h.saturating_add(1));
    if planted || st.header_walk.tip_height() <= tip_h {
        return None;
    }
    st.header_walk.tip_hash()
}

/// Header tips on known competing forks that do not contain an invalid hash.
///
/// After a consensus-invalid reject the planted path may be a dead-end while a
/// previously-weaker fork is now the best *valid* chain. Scan is only useful
/// when `reorg.invalid` is non-empty (callers register the result as explore).
pub fn competing_valid_header_tips(
    st: &super::state::IbdWorkState,
    hub: &ChainHub,
) -> Vec<BlockHash> {
    if st.reorg.invalid.is_empty() {
        return Vec::new();
    }
    let mut by_h: HashMap<u32, Vec<BlockHash>> = HashMap::new();
    for (&h, &ht) in &st.hash_height {
        if st.reorg.invalid.contains(h.to_byte_array()) || st.body.is_rejected(&h) {
            continue;
        }
        by_h.entry(ht).or_default().push(h);
    }
    let tip = hub.tip_hash();
    let tip_h = hub.tip_height().unwrap_or(0);
    let mut starts: Vec<(BlockHash, u32)> = Vec::new();
    let push_start = |h: BlockHash, ht: u32, starts: &mut Vec<(BlockHash, u32)>| {
        if Some(h) == tip {
            return;
        }
        if !starts.iter().any(|(x, _)| *x == h) {
            starts.push((h, ht));
        }
    };
    if let Some(hashes) = by_h.get(&tip_h) {
        for &h in hashes {
            push_start(h, tip_h, &mut starts);
        }
    }
    for (&ht, hashes) in &by_h {
        if hashes.len() > 1 {
            for &h in hashes {
                push_start(h, ht, &mut starts);
            }
        }
    }
    const MAX_TIPS: usize = 8;
    let mut tips = Vec::new();
    for (h, ht) in starts {
        let tip_hsh = extend_valid_header_tip(st, hub, &by_h, h, ht);
        if !tips.contains(&tip_hsh) {
            tips.push(tip_hsh);
        }
        if tips.len() >= MAX_TIPS {
            break;
        }
    }
    tips
}

#[doc(hidden)]
pub fn extend_valid_header_tip(
    st: &super::state::IbdWorkState,
    hub: &ChainHub,
    by_h: &HashMap<u32, Vec<BlockHash>>,
    start: BlockHash,
    start_h: u32,
) -> BlockHash {
    let mut cur = start;
    let mut ht = start_h;
    for _ in 0..64 {
        let next_ht = ht.saturating_add(1);
        let Some(cands) = by_h.get(&next_ht) else {
            break;
        };
        let mut child = None;
        for &c in cands {
            if st.reorg.invalid.contains(c.to_byte_array()) || st.body.is_rejected(&c) {
                continue;
            }
            match parent_hash_of(hub, c) {
                Ok(Some(p)) if p == cur => {
                    child = Some(c);
                    break;
                }
                _ => {}
            }
        }
        match child {
            Some(c) => {
                cur = c;
                ht = next_ht;
            }
            None => break,
        }
    }
    cur
}

/// If a strictly heavier header branch is known, disconnect to its LCA and
/// plant that branch as the linear work path. No side-channel body gather.
pub fn maybe_rewind_to_best_work(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, NetError> {
    let cands = rewind_candidate_hashes(st, hub)?;
    let invalid: HashSet<[u8; 32]> = st.reorg.invalid.iter().collect();
    let Some(path) = select_heavier_path(hub, &cands, &invalid)? else {
        return Ok(false);
    };
    apply_header_rewind(st, hub, &path)
}

#[doc(hidden)]
pub fn rewind_candidate_hashes(
    st: &super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<Vec<BlockHash>, NetError> {
    let mut seen = HashSet::new();
    let mut cands = Vec::new();
    for t in st.reorg.explore_tips() {
        if seen.insert(*t) {
            cands.push(*t);
        }
    }
    for h in connecting_search_candidates(st, hub)? {
        if seen.insert(h) {
            cands.push(h);
        }
    }
    Ok(cands)
}

#[doc(hidden)]
pub fn select_heavier_path(
    hub: &ChainHub,
    cands: &[BlockHash],
    invalid: &HashSet<[u8; 32]>,
) -> Result<Option<Vec<BlockHash>>, NetError> {
    for cand in cands {
        if invalid.contains(&cand.to_byte_array()) {
            continue;
        }
        if let Some(path) = connecting_hashes_heavier_disconnected(hub, *cand)? {
            if path.iter().any(|h| invalid.contains(&h.to_byte_array())) {
                continue;
            }
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Disconnect to the path's LCA and re-point height slots at `path`
/// (oldest-first, unconfirmed hashes after the LCA).
#[doc(hidden)]
pub struct RewindPrep {
    pub lca: BlockHash,
    pub lca_h: u32,
    pub archived: Vec<bool>,
    pub connected: Vec<bool>,
    pub fks: Vec<Option<Fk>>,
    /// The confirmed tip was above the LCA, so blocks were disconnected.
    pub rewound: bool,
}

/// Store side of a rewind: parent lookup and the confirmed-tip disconnect.
/// No `IbdWorkState` borrow, so the coordination lock is not held.
#[doc(hidden)]
pub fn prepare_header_rewind(
    hub: &ChainHub,
    path: &[BlockHash],
    max_depth: u32,
) -> Result<Option<RewindPrep>, NetError> {
    if path.is_empty() {
        return Ok(None);
    }
    let Some(lca) = parent_hash_of(hub, path[0])? else {
        return Ok(None);
    };
    let Some(lca_h) = hub
        .query
        .height_of_hash(&lca.to_byte_array())
        .map_err(NetError::store)?
        .map(|h| h.0)
    else {
        return Ok(None);
    };
    let tip_h = hub.tip_height().unwrap_or(0);
    let rewound = tip_h > lca_h;
    if tip_h.saturating_sub(lca_h) > max_depth {
        warn!(
            "ibd: heavier fork rewind depth {} exceeds cap {max_depth} (lca={lca_h} tip={tip_h})",
            tip_h.saturating_sub(lca_h)
        );
        return Ok(None);
    }
    if tip_h > lca_h {
        if !hub.try_rewind_to_height(lca_h)? {
            return Ok(None);
        }
        info!(
            "ibd: most-work header rewind tip {tip_h} → {lca_h} (winning path {} header(s))",
            path.len()
        );
    } else {
        info!(
            "ibd: most-work header plant at lca={lca_h} (winning path {} header(s))",
            path.len()
        );
    }
    let archived = path
        .iter()
        .map(|hash| {
            hub.query
                .is_block_archived(&hash.to_byte_array())
                .unwrap_or(false)
        })
        .collect();
    let connected = path.iter().map(|hash| hub.is_connected(hash)).collect();
    let fks = path
        .iter()
        .map(|hash| {
            hub.query
                .get_header_by_hash(&hash.to_byte_array())
                .ok()
                .flatten()
                .map(|(fk, _)| fk)
        })
        .collect();
    Ok(Some(RewindPrep {
        lca,
        lca_h,
        archived,
        connected,
        fks,
        rewound,
    }))
}

#[doc(hidden)]
pub fn commit_header_rewind(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
    path: &[BlockHash],
    prep: &RewindPrep,
) {
    st.clear_path_above(prep.lca_h);
    hub.query.clear_milestone_path_above(prep.lca_h);
    super::header_walk::on_confirmed_rewind(st, hub, prep.lca_h);
    hub.query.set_lookup_taken_hi(Some(prep.lca_h));
    st.headers_done = false;
    let tip = hub.tip_height().zip(hub.tip_hash());
    let mut prev = prep.lca;
    for (i, hash) in path.iter().enumerate() {
        let ht = prep.lca_h.saturating_add(1).saturating_add(i as u32);
        let _ = st.try_set_path_slot(*hash, ht, prev, tip);
        st.known_headers.insert(*hash);
        if let Some(fk) = prep.fks.get(i).copied().flatten() {
            st.header_fks.insert(*hash, fk);
        }
        st.max_ordered_height = st.max_ordered_height.max(ht);
        if !prep.connected[i] && st.ordered_set.insert(*hash) {
            st.ordered.push_back(*hash);
        }
        if prep.archived[i] {
            st.body.mark_archived(*hash);
        }
        prev = *hash;
    }
    if prep.rewound {
        for slot in &mut st.slots {
            slot.chain.note_rewind(&st.height_to_hash, prep.lca_h);
        }
    }
    for h in hub.query.block_queue_queued_heights() {
        if h > prep.lca_h {
            let _ = hub.query.block_queue_dequeue_height(h);
        }
    }
    st.reorg.clear_explore();
    st.confirm_quiesce = true;
}

pub fn apply_header_rewind(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
    path: &[BlockHash],
) -> Result<bool, NetError> {
    let cap = super::header_walk::rewind_depth_cap(st, hub);
    let Some(prep) = prepare_header_rewind(hub, path, cap)? else {
        return Ok(false);
    };
    commit_header_rewind(st, hub, path, &prep);
    Ok(true)
}

/// Off-lock rewinds take this, then `shared`. Reject and explore still
/// disconnect through `maybe_rewind_to_best_work` → `apply_header_rewind`
/// while the caller holds `shared`, so that path does not take this gate.
fn rewind_exclusion() -> &'static Mutex<()> {
    static GATE: Mutex<()> = Mutex::new(());
    &GATE
}

fn tip_pair(hub: &ChainHub) -> (Option<u32>, Option<BlockHash>) {
    (hub.tip_height(), hub.tip_hash())
}

/// `prepare_header_rewind` already disconnected when `prep.rewound`. The
/// commit is for that tip, not whatever tip is current after a later rewind.
fn rewind_tip_still(
    hub: &ChainHub,
    prep: &RewindPrep,
    tip_before: (Option<u32>, Option<BlockHash>),
) -> bool {
    let now = tip_pair(hub);
    if prep.rewound {
        now == (Some(prep.lca_h), Some(prep.lca))
    } else {
        now == tip_before
    }
}

struct PreparedHook {
    thread: ThreadId,
    hook: fn(),
}

static AFTER_PREPARE: Mutex<Option<PreparedHook>> = Mutex::new(None);

/// Runs on this thread after a rewind is prepared and before it is committed.
/// The header-thread stand-in in the stale-commit pin uses this. An empty
/// hook is production.
#[doc(hidden)]
pub fn arm_after_header_rewind_prepare_for_test(hook: Option<fn()>) {
    let mut slot = AFTER_PREPARE.lock().unwrap_or_else(|err| err.into_inner());
    *slot = hook.map(|hook| PreparedHook {
        thread: std::thread::current().id(),
        hook,
    });
}

fn fire_after_prepare() {
    let hook = {
        let mut slot = AFTER_PREPARE.lock().unwrap_or_else(|err| err.into_inner());
        match slot.as_ref() {
            Some(armed) if armed.thread == std::thread::current().id() => {
                let hook = armed.hook;
                *slot = None;
                Some(hook)
            }
            _ => None,
        }
    };
    if let Some(hook) = hook {
        hook();
    }
}

/// Select, disconnect, and commit one heavier path. Caller does not hold
/// `shared`. One exclusion covers the select, the disconnect, and the
/// commit. A moved tip or a hash marked invalid skips the commit, so
/// `clear_path_above` and `set_lookup_taken_hi` stay off that stale height.
pub(crate) fn apply_off_lock_rewind(
    shared: &Mutex<super::state::IbdWorkState>,
    hub: &ChainHub,
    cands: &[BlockHash],
    invalid: &HashSet<[u8; 32]>,
) -> Result<Option<Vec<(BlockHash, Fk)>>, NetError> {
    let _gate = rewind_exclusion()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let Some(path) = select_heavier_path(hub, cands, invalid)? else {
        return Ok(None);
    };
    let tip_before = tip_pair(hub);
    let cap = {
        let st = shared.lock().unwrap_or_else(|err| err.into_inner());
        super::header_walk::rewind_depth_cap(&st, hub)
    };
    let Some(prep) = prepare_header_rewind(hub, &path, cap)? else {
        return Ok(None);
    };
    // Re-selecting here would see the LCA we just rewound to and return
    // none. The fresh select is the one above, after the other rewind has
    // either committed or is waiting on this gate.
    fire_after_prepare();
    let mut st = shared.lock().unwrap_or_else(|err| err.into_inner());
    if path
        .iter()
        .any(|hash| st.reorg.invalid.contains(hash.to_byte_array()))
    {
        return Ok(None);
    }
    if !rewind_tip_still(hub, &prep, tip_before) {
        return Ok(None);
    }
    commit_header_rewind(&mut st, hub, &path, &prep);
    let pairs = path
        .iter()
        .zip(prep.fks.iter())
        .filter_map(|(hash, fk)| fk.map(|fk| (*hash, fk)))
        .collect();
    Ok(Some(pairs))
}

/// Most-work rewind with the store reads outside `shared`.
///
/// `bus` receives the path's header fks after the lock drops. Those fks are
/// also in `header_fks`, so a body that arrives before the publish still
/// resolves.
pub fn rewind_off_coord_lock(
    shared: &Mutex<super::state::IbdWorkState>,
    hub: &ChainHub,
    bus: Option<&super::peer_io::HeaderFkBus>,
) -> Result<bool, NetError> {
    let (cands, invalid) = {
        let st = shared.lock().unwrap_or_else(|err| err.into_inner());
        let cands = rewind_candidate_hashes(&st, hub)?;
        let invalid: HashSet<[u8; 32]> = st.reorg.invalid.iter().collect();
        (cands, invalid)
    };
    let Some(pairs) = apply_off_lock_rewind(shared, hub, &cands, &invalid)? else {
        return Ok(false);
    };
    if let Some(bus) = bus {
        super::peer_io::publish_header_fks(bus, &pairs);
    }
    Ok(true)
}
