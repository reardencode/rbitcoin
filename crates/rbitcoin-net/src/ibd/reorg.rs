//! IBD most-work reorg: classify BadPrev, rank candidates, rewind + linear confirm.
//!
//! See `docs/architecture.md` (most-work chain selection). Orchestration-thread only.

use crate::chain::ChainHub;
use crate::error::NetError;
use crate::most_work::{sum_work, work_better, InvalidHashSet};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, CompactTarget, Target};
use rbitcoin_log::{info, warn};
use rbitcoin_primitives::Height;
use std::collections::HashMap;

/// Classification of tip+1 `unexpected previous header` (BadPrev).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadPrevClass {
    /// Wire prev is not a known header — soft re-get only.
    CorruptWire { wire_prev: BlockHash },
    /// Wire prev is a known header that is not the current tip (competing path).
    CompetingPath {
        /// Parent of the rejected tip+1 body (winning sibling / branch tip).
        winning_prev: BlockHash,
        /// Current best tip (losing fork when this is the mainnet class stall).
        losing_tip: BlockHash,
    },
}

/// Classify a BadPrev / unexpected-previous reject at confirm tip+1.
///
/// `wire_prev` is the previous-block hash from the rejected block header.
/// `tip_hash` is the current best tip hash.
#[cfg(test)]
pub fn classify_bad_prev(
    hub: &ChainHub,
    wire_prev: BlockHash,
    tip_hash: BlockHash,
) -> BadPrevClass {
    if wire_prev == tip_hash {
        // Same as tip — not a competing reorg signal (should not be BadPrev).
        return BadPrevClass::CorruptWire { wire_prev };
    }
    let known = hub
        .query
        .get_header_by_hash(&wire_prev.to_byte_array())
        .ok()
        .flatten()
        .is_some()
        || hub.has_block(&wire_prev);
    if known {
        BadPrevClass::CompetingPath {
            winning_prev: wire_prev,
            losing_tip: tip_hash,
        }
    } else {
        BadPrevClass::CorruptWire { wire_prev }
    }
}

/// Whether a confirm reject string is the soft BadPrev class.
pub fn is_bad_prev_err(err: &str) -> bool {
    err.contains("unexpected previous header") || err.contains("unexpected previous")
}

/// Awaiting a missing body (e.g. winning sibling) before apply can run.
#[derive(Debug, Clone)]
pub struct AwaitingBodies {
    /// Block we already hold (typically tip+1 on the winning path).
    pub held_tip: Block,
    /// Hashes still needed (e.g. winning sibling at tip height).
    pub need: Vec<BlockHash>,
}

/// Process-local reorg state for one IBD run.
///
/// Bodies for **side branches** are held by hash here: the body queue is
/// height-keyed first-wins, so a same-height competitor of the tip cannot
/// live in BQ while the tip path occupies that height.
#[derive(Debug, Default)]
pub struct IbdReorgState {
    pub invalid: InvalidHashSet,
    /// Side-branch / reorg-candidate bodies keyed by block hash.
    held_bodies: HashMap<BlockHash, Block>,
    /// Incomplete gather: need `need` hashes before applying `held_tip` path.
    awaiting: Option<AwaitingBodies>,
    /// Proactive exploration: hashes densify should pull (same-height winner +
    /// extensions) without waiting for BadPrev awaiting.
    explore_need: Vec<BlockHash>,
    /// Candidate tips on an exploration path (for proactive most-work apply).
    explore_tips: Vec<BlockHash>,
}

impl IbdReorgState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap on held side bodies (DoS / process RAM). Sized for multi-hop BadPrev
    /// paths (mainnet-class LCA walks) without thrashing; still small enough
    /// that unit tests can exercise eviction without huge chains.
    pub(crate) const HELD_CAP: usize = 32;

    pub fn hold_body(&mut self, block: Block) {
        let h = block.block_hash();
        if self.held_bodies.len() >= Self::HELD_CAP && !self.held_bodies.contains_key(&h) {
            // Drop an arbitrary older entry (HashMap iter order is arbitrary).
            if let Some(k) = self.held_bodies.keys().next().copied() {
                self.held_bodies.remove(&k);
            }
        }
        self.held_bodies.insert(h, block);
        self.explore_need.retain(|x| *x != h);
    }

    pub fn clear_awaiting(&mut self) {
        self.awaiting = None;
    }

    pub fn awaiting(&self) -> Option<&AwaitingBodies> {
        self.awaiting.as_ref()
    }

    /// True if `hash` is the held tip+1 of an incomplete reorg gather (do not
    /// soft re-getdata / tip-hole race it — densify **mids** instead).
    pub fn is_awaiting_held_tip(&self, hash: &BlockHash) -> bool {
        self.awaiting
            .as_ref()
            .is_some_and(|a| a.held_tip.block_hash() == *hash)
    }

    /// Register hashes (and optional path tip) for exploration densify / apply.
    pub fn register_explore(
        &mut self,
        need: impl IntoIterator<Item = BlockHash>,
        tip: Option<BlockHash>,
    ) {
        for h in need {
            if !self.explore_need.contains(&h) {
                self.explore_need.push(h);
            }
        }
        if let Some(t) = tip {
            if !self.explore_tips.contains(&t) {
                self.explore_tips.push(t);
            }
        }
    }

    pub fn explore_tips(&self) -> &[BlockHash] {
        &self.explore_tips
    }

    /// Registered exploration densify hashes (same-height winner + extensions).
    #[cfg(test)]
    pub fn explore_need_hashes(&self) -> &[BlockHash] {
        &self.explore_need
    }

    pub fn clear_explore(&mut self) {
        self.explore_need.clear();
        self.explore_tips.clear();
    }

    /// Hashes still needed for an incomplete **awaiting** gather (not explore).
    pub fn awaiting_need_getdata(&self) -> Vec<BlockHash> {
        self.awaiting
            .as_ref()
            .map(|a| {
                a.need
                    .iter()
                    .filter(|h| !self.held_bodies.contains_key(*h))
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Hashes densify/getdata should still pull for an incomplete reorg
    /// (awaiting gather **or** proactive exploration).
    pub fn need_getdata(&self) -> Vec<BlockHash> {
        let mut out = self.awaiting_need_getdata();
        for h in &self.explore_need {
            if !self.held_bodies.contains_key(h) && !out.contains(h) {
                out.push(*h);
            }
        }
        out
    }
}

/// Cap on prev-walks from a header-horizon candidate. Early IBD can have
/// hundreds of thousands of headers above a low confirmed tip; walking the
/// whole gap is CPU + RAM for no reorg.
const ANCESTOR_WALK_MAX: usize = 10_000;

/// Max confirmed blocks disconnected in one header-driven rewind.
const REWIND_MAX_DEPTH: u32 = 1_024;

/// Header hashes from `tip` back to (not including) a best-chain / confirmed
/// ancestor, **oldest-first**. Used so BadPrev densify requests every mid-path
/// body to the LCA (mainnet: d1e0 + 02022e + tip+1, not wire_prev alone).
///
/// Stops on [`ChainHub::is_connected`] — [`ChainHub::has_block`] stays true for
/// disconnected once-confirmed losers (`confirmed` is insert-only).
#[cfg(test)]
pub fn header_hashes_to_best_ancestor(
    hub: &ChainHub,
    tip: BlockHash,
) -> Result<Vec<BlockHash>, NetError> {
    header_hashes_to_best_ancestor_n(hub, tip, ANCESTOR_WALK_MAX)
}

fn header_hashes_to_best_ancestor_n(
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
            .map_err(|e| NetError::Consensus(e.to_string()))?
        else {
            break;
        };
        let Some(pfk) = rec.prev_fk.get() else {
            break;
        };
        let parent = hub
            .query
            .get_header(rbitcoin_primitives::Fk(pfk))
            .map_err(|e| NetError::Consensus(e.to_string()))?;
        cur = BlockHash::from_byte_array(parent.hash);
    }
    rev.reverse();
    Ok(rev)
}

pub(crate) fn parent_hash_of(
    hub: &ChainHub,
    hash: BlockHash,
) -> Result<Option<BlockHash>, NetError> {
    let Some((_, rec)) = hub
        .query
        .get_header_by_hash(&hash.to_byte_array())
        .map_err(|e| NetError::Consensus(e.to_string()))?
    else {
        return Ok(None);
    };
    if rec.prev_fk.is_null() {
        return Ok(Some(BlockHash::from_byte_array([0u8; 32])));
    }
    let parent = hub
        .query
        .get_header(rec.prev_fk)
        .map_err(|e| NetError::Consensus(e.to_string()))?;
    Ok(Some(BlockHash::from_byte_array(parent.hash)))
}

fn header_work_of(hub: &ChainHub, hash: BlockHash) -> Result<Option<bitcoin::Work>, NetError> {
    let Some((_, rec)) = hub
        .query
        .get_header_by_hash(&hash.to_byte_array())
        .map_err(|e| NetError::Consensus(e.to_string()))?
    else {
        return Ok(None);
    };
    Ok(Some(
        Target::from_compact(CompactTarget::from_consensus(rec.bits)).to_work(),
    ))
}

fn our_work_from_lca(hub: &ChainHub, lca_height: u32) -> Result<bitcoin::Work, NetError> {
    let tip_h = hub.tip_height().unwrap_or(0);
    let mut our = Vec::new();
    if tip_h > lca_height {
        for h in (lca_height + 1)..=tip_h {
            let hdr = hub
                .query
                .wire_header_at_height(Height(h))
                .map_err(|e| NetError::Consensus(e.to_string()))?;
            our.push(hdr.work());
        }
    }
    Ok(sum_work(our.into_iter()))
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
        .map_err(|e| NetError::Consensus(e.to_string()))?
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

fn connecting_hashes_heavier_disconnected_n(
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
    if join == tip || path.iter().any(|h| *h == tip) {
        return Ok(None);
    }
    // `has_block` can lag the published tip. If join is on the best chain and
    // path[0] is the next best-chain header, this is a linear extension.
    if let Some(jh) = hub
        .query
        .height_of_hash(&join.to_byte_array())
        .map_err(|e| NetError::Consensus(e.to_string()))?
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

/// Register a connecting-hash search for a heavier header path that does not
/// meet the current tip. Explore tip is the **shortest** prefix that beats
/// current tip work — not the header horizon.
#[cfg(test)]
pub fn note_disconnected_heavier(
    reorg: &mut IbdReorgState,
    hub: &ChainHub,
    candidate: BlockHash,
) -> Result<bool, NetError> {
    let Some(path) = connecting_hashes_heavier_disconnected(hub, candidate)? else {
        return Ok(false);
    };
    let tip_idx = shortest_heavier_header_prefix(hub, &path)?.unwrap_or(path.len() - 1);
    let end = (tip_idx + 1).min(path.len()).min(IbdReorgState::HELD_CAP);
    if end == 0 {
        return Ok(false);
    }
    let prefix = &path[..end];
    let explore_tip = prefix[prefix.len() - 1];
    reorg.register_explore(prefix.iter().copied(), Some(explore_tip));
    info!(
        "ibd: heavier chain does not connect at tip — search {} connecting block(s) to {explore_tip} (candidate {candidate})",
        prefix.len()
    );
    Ok(true)
}

/// Work-path hashes that may start a connecting search.
///
/// Only tip+1 when it is a **competing** child (parent ≠ current tip). A
/// linear extension or a far `max_ordered` header is not a fork signal —
/// walking the horizon is a multi-second assign tax on ordinary IBD.
pub(crate) fn connecting_search_candidates(
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
    match parent_hash_of(hub, h)? {
        Some(p) if p != tip => Ok(vec![h]),
        _ => Ok(Vec::new()),
    }
}

/// Scan a competing work-path tip+1 for a heavier disconnected fork and
/// rewind the confirmed tip to the LCA so the normal pipeline confirms it.
pub fn consider_disconnected_heavier(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, NetError> {
    for h in connecting_search_candidates(st, hub)? {
        if st.reorg.invalid.contains(h.to_byte_array()) {
            continue;
        }
        if let Some(path) = connecting_hashes_heavier_disconnected(hub, h)? {
            if path
                .iter()
                .any(|p| st.reorg.invalid.contains(p.to_byte_array()))
            {
                continue;
            }
            return apply_header_rewind(st, hub, &path);
        }
    }
    Ok(false)
}

/// Header tips on known competing forks that do not contain an invalid hash.
///
/// After a consensus-invalid reject the planted path may be a dead-end while a
/// previously-weaker fork is now the best *valid* chain. Scan is only useful
/// when `reorg.invalid` is non-empty (callers register the result as explore).
pub(crate) fn competing_valid_header_tips(
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

fn extend_valid_header_tip(
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
pub(crate) fn maybe_rewind_to_best_work(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
) -> Result<bool, NetError> {
    let mut seen = std::collections::HashSet::new();
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
    if let Some(a) = st.reorg.awaiting() {
        let h = a.held_tip.block_hash();
        if seen.insert(h) {
            cands.push(h);
        }
    }
    for cand in cands {
        if st.reorg.invalid.contains(cand.to_byte_array()) {
            continue;
        }
        if let Some(path) = connecting_hashes_heavier_disconnected(hub, cand)? {
            if path
                .iter()
                .any(|h| st.reorg.invalid.contains(h.to_byte_array()))
            {
                continue;
            }
            return apply_header_rewind(st, hub, &path);
        }
    }
    Ok(false)
}

/// Disconnect to the path's LCA and re-point height slots at `path`
/// (oldest-first, unconfirmed hashes after the LCA).
pub(crate) fn apply_header_rewind(
    st: &mut super::state::IbdWorkState,
    hub: &ChainHub,
    path: &[BlockHash],
) -> Result<bool, NetError> {
    if path.is_empty() {
        return Ok(false);
    }
    let Some(lca) = parent_hash_of(hub, path[0])? else {
        return Ok(false);
    };
    let Some(lca_h) = hub
        .query
        .height_of_hash(&lca.to_byte_array())
        .map_err(|e| NetError::Consensus(e.to_string()))?
        .map(|h| h.0)
    else {
        return Ok(false);
    };
    let tip_h = hub.tip_height().unwrap_or(0);
    if tip_h.saturating_sub(lca_h) > REWIND_MAX_DEPTH {
        warn!(
            "ibd: heavier fork rewind depth {} exceeds cap {REWIND_MAX_DEPTH} (lca={lca_h} tip={tip_h})",
            tip_h.saturating_sub(lca_h)
        );
        return Ok(false);
    }
    if tip_h > lca_h {
        hub.rewind_to_height(lca_h)?;
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
    st.clear_path_above(lca_h);
    hub.query.set_lookup_taken_hi(Some(lca_h));
    st.headers_done = false;
    let tip = hub.tip_height().zip(hub.tip_hash());
    let mut prev = lca;
    for (i, hash) in path.iter().enumerate() {
        let ht = lca_h.saturating_add(1).saturating_add(i as u32);
        let _ = st.try_set_path_slot(*hash, ht, prev, tip);
        st.known_headers.insert(*hash);
        st.max_ordered_height = st.max_ordered_height.max(ht);
        if !hub.is_connected(hash) && st.ordered_set.insert(*hash) {
            st.ordered.push_back(*hash);
        }
        if hub
            .query
            .is_block_archived(&hash.to_byte_array())
            .unwrap_or(false)
        {
            st.body.mark_archived(*hash);
        }
        prev = *hash;
    }
    for h in hub.query.block_queue_queued_heights() {
        if h > lca_h {
            let _ = hub.query.block_queue_dequeue_height(h);
        }
    }
    st.reorg.clear_awaiting();
    st.reorg.clear_explore();
    st.confirm_quiesce = true;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::Query;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_hub() -> (std::path::PathBuf, ChainHub) {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-ibd-reorg-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create_tiny(dir.join("store")).expect("query");
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

    #[test]
    fn classify_corrupt_vs_competing() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let lose = mine(gen, 1_500_000_100, 1);
        let win = {
            let mut b = mine(gen, 1_500_000_101, 1);
            if b.block_hash() == lose.block_hash() {
                let target = Target::from_compact(b.header.bits);
                for nonce in 0..u32::MAX {
                    b.header.nonce = nonce;
                    if b.header.validate_pow(target).is_ok() && b.block_hash() != lose.block_hash()
                    {
                        break;
                    }
                }
            }
            b
        };
        hub.accept_block(lose.clone()).unwrap();
        // Winning sibling header known but not tip.
        hub.ensure_header(&win.header).unwrap();
        let tip = hub.tip_hash().unwrap();
        assert_eq!(tip, lose.block_hash());

        match classify_bad_prev(&hub, win.block_hash(), tip) {
            BadPrevClass::CompetingPath {
                winning_prev,
                losing_tip,
            } => {
                assert_eq!(winning_prev, win.block_hash());
                assert_eq!(losing_tip, lose.block_hash());
            }
            other => panic!("expected CompetingPath, got {other:?}"),
        }
        let unknown = BlockHash::from_byte_array([0xde; 32]);
        match classify_bad_prev(&hub, unknown, tip) {
            BadPrevClass::CorruptWire { wire_prev } => assert_eq!(wire_prev, unknown),
            other => panic!("expected CorruptWire, got {other:?}"),
        }
        assert!(is_bad_prev_err("consensus: unexpected previous header"));
        assert!(!is_bad_prev_err("script verification failed"));
        // Same-as-tip wire prev → CorruptWire class (not CompetingPath).
        match classify_bad_prev(&hub, tip, tip) {
            BadPrevClass::CorruptWire { wire_prev } => assert_eq!(wire_prev, tip),
            other => panic!("expected CorruptWire for tip==prev, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn header_hashes_to_best_ancestor_walks_mid_path() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_060_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        // Side path not confirmed: w1 → w2
        let mut w1 = mine(gen, 1_500_060_101, 1);
        if w1.block_hash() == l1.block_hash() {
            let target = Target::from_compact(w1.header.bits);
            for nonce in 0..u32::MAX {
                w1.header.nonce = nonce;
                if w1.header.validate_pow(target).is_ok() && w1.block_hash() != l1.block_hash() {
                    break;
                }
            }
        }
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_060_200, 2);
        hub.ensure_header(&w2.header).unwrap();
        let path = header_hashes_to_best_ancestor(&hub, w2.block_hash()).unwrap();
        assert_eq!(
            path,
            vec![w1.block_hash(), w2.block_hash()],
            "oldest-first mid path to LCA"
        );
        // Already on best chain → empty.
        assert!(header_hashes_to_best_ancestor(&hub, l1.block_hash())
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reorg_state_held_awaiting_need_getdata() {
        let mut st = IbdReorgState::new();
        assert!(st.need_getdata().is_empty());
        assert!(st.awaiting().is_none());
        let gen = BlockHash::from_byte_array([0x11; 32]);
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let held = mine(gen, 1_300_000_000, 1);
        let mut need_h = mine(gen, 1_300_000_001, 1);
        if need_h.block_hash() == held.block_hash() {
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                need_h.header.nonce = nonce;
                if need_h.header.validate_pow(target).is_ok()
                    && need_h.block_hash() != held.block_hash()
                {
                    break;
                }
            }
        }
        let need = need_h.block_hash();
        st.register_explore([need], None);
        assert_eq!(st.need_getdata(), vec![need]);
        st.hold_body(need_h);
        assert!(st.need_getdata().is_empty(), "held satisfies need");
        let explore = mine(gen, 1_300_000_050, 1);
        let eh = explore.block_hash();
        st.register_explore([eh], Some(eh));
        assert_eq!(st.need_getdata(), vec![eh]);
        st.hold_body(explore);
        assert!(st.need_getdata().is_empty());
        st.clear_awaiting();
        assert!(st.awaiting().is_none());
        assert!(st.need_getdata().is_empty());
        let mut st_cap = IbdReorgState::new();
        let mut held_keys = Vec::new();
        let mut prev = gen;
        for i in 0u32..(IbdReorgState::HELD_CAP as u32 + 4) {
            let b = mine(prev, 1_300_001_000 + i, 1);
            prev = b.block_hash();
            held_keys.push(b.block_hash());
            st_cap.hold_body(b);
        }
        for k in &held_keys {
            st_cap.register_explore([*k], None);
        }
        let still = held_keys
            .iter()
            .filter(|k| !st_cap.need_getdata().contains(k))
            .count();
        assert_eq!(
            still,
            IbdReorgState::HELD_CAP,
            "held map must stay exactly HELD_CAP after overflow inserts"
        );
        let _ = held;
    }

    fn distinct_sib(mut b: Block, avoid: BlockHash) -> Block {
        if b.block_hash() == avoid {
            let target = Target::from_compact(b.header.bits);
            for nonce in 0..u32::MAX {
                b.header.nonce = nonce;
                if b.header.validate_pow(target).is_ok() && b.block_hash() != avoid {
                    break;
                }
            }
        }
        b
    }

    /// Tip on a 2-block loser; heavier winner headers do not connect at
    /// tip+1. Name the connecting hashes (not a dead-tip child).
    #[test]
    fn heavier_disconnected_path_names_connecting_hashes() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_060_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        let l2 = mine(l1.block_hash(), 1_500_060_200, 2);
        hub.accept_block(l2.clone()).unwrap();
        assert_eq!(hub.tip_hash().unwrap(), l2.block_hash());

        let w1 = distinct_sib(mine(gen, 1_500_060_101, 1), l1.block_hash());
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_060_201, 2);
        hub.ensure_header(&w2.header).unwrap();
        let w3 = mine(w2.block_hash(), 1_500_060_301, 3);
        hub.ensure_header(&w3.header).unwrap();
        let w4 = mine(w3.block_hash(), 1_500_060_401, 4);
        hub.ensure_header(&w4.header).unwrap();

        // Connected loser child is not a disconnected heavier path.
        let l3 = mine(l2.block_hash(), 1_500_060_300, 3);
        hub.ensure_header(&l3.header).unwrap();
        assert!(
            connecting_hashes_heavier_disconnected(&hub, l3.block_hash())
                .unwrap()
                .is_none(),
            "child of current tip is a normal extension, not a connecting search"
        );

        let path = connecting_hashes_heavier_disconnected(&hub, w4.block_hash())
            .unwrap()
            .expect("heavier winner that does not connect at tip must name a path");
        assert_eq!(
            path,
            vec![
                w1.block_hash(),
                w2.block_hash(),
                w3.block_hash(),
                w4.block_hash()
            ],
            "path must be winner mids from LCA, not the loser tip+1"
        );
        assert!(!path.contains(&l3.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Register only the shortest prefix that beats tip work; apply it once
    /// those connecting bodies are held — no BadPrev, no full-horizon gather.
    #[test]
    fn note_disconnected_heavier_fetches_connecting_prefix_and_reorgs() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_061_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        let l2 = mine(l1.block_hash(), 1_500_061_200, 2);
        hub.accept_block(l2.clone()).unwrap();

        let w1 = distinct_sib(mine(gen, 1_500_061_101, 1), l1.block_hash());
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_061_201, 2);
        hub.ensure_header(&w2.header).unwrap();
        let w3 = mine(w2.block_hash(), 1_500_061_301, 3);
        hub.ensure_header(&w3.header).unwrap();
        let w4 = mine(w3.block_hash(), 1_500_061_401, 4);
        hub.ensure_header(&w4.header).unwrap();
        let w5 = mine(w4.block_hash(), 1_500_061_501, 5);
        hub.ensure_header(&w5.header).unwrap();

        let mut reorg = IbdReorgState::new();
        assert!(
            note_disconnected_heavier(&mut reorg, &hub, w5.block_hash()).unwrap(),
            "must register a connecting search for the heavier disconnected path"
        );
        let need = reorg.need_getdata();
        assert!(
            need.contains(&w1.block_hash())
                && need.contains(&w2.block_hash())
                && need.contains(&w3.block_hash()),
            "must search for connecting mids; need={need:?}"
        );
        assert!(
            !need.contains(&w5.block_hash()),
            "must not wait to gather the whole heavier horizon; need={need:?}"
        );
        assert_eq!(
            reorg.explore_tips(),
            &[w3.block_hash()],
            "explore tip is the shortest prefix that beats loser work"
        );

        reorg.hold_body(w1.clone());
        reorg.hold_body(w2.clone());
        reorg.hold_body(w3.clone());
        assert!(
            reorg.need_getdata().is_empty(),
            "held connecting prefix satisfies explore need"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Work-path tip+1 / far header (no resume seed) still registers the
    /// connecting prefix — the live IBD hook, not BadPrev.
    #[test]
    fn consider_disconnected_from_work_path_without_resume_seed() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_062_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        let l2 = mine(l1.block_hash(), 1_500_062_200, 2);
        hub.accept_block(l2.clone()).unwrap();
        let w1 = distinct_sib(mine(gen, 1_500_062_101, 1), l1.block_hash());
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_062_201, 2);
        hub.ensure_header(&w2.header).unwrap();
        let w3 = mine(w2.block_hash(), 1_500_062_301, 3);
        hub.ensure_header(&w3.header).unwrap();
        let w4 = mine(w3.block_hash(), 1_500_062_401, 4);
        hub.ensure_header(&w4.header).unwrap();

        let mut st =
            super::super::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        st.record_height(w3.block_hash(), 3);
        st.record_height(w4.block_hash(), 4);
        st.max_ordered_height = 4;
        assert!(consider_disconnected_heavier(&mut st, &hub).unwrap());
        assert_eq!(
            hub.tip_height(),
            Some(0),
            "competing tip+1 must rewind to the LCA"
        );
        assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
        assert_eq!(st.height_to_hash.get(&2), Some(&w2.block_hash()));
        assert!(
            st.reorg.need_getdata().is_empty(),
            "winner is a linear extension after rewind; need={:?}",
            st.reorg.need_getdata()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Linear headers ahead of tip are a normal extension, not a fork search.
    /// (CI: two_node IBD hung at tip=1 after consider treated h=8 as disconnected.)
    #[test]
    fn linear_ahead_headers_are_not_a_disconnected_fork() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_500_070_100, 1);
        hub.accept_block(b1.clone()).unwrap();
        let mut prev = b1.block_hash();
        let mut time = 1_500_070_200u32;
        let mut ahead = Vec::new();
        for h in 2..=8u32 {
            let b = mine(prev, time, h);
            hub.ensure_header(&b.header).unwrap();
            prev = b.block_hash();
            time += 100;
            ahead.push((h, prev));
        }
        let last = ahead.last().unwrap().1;
        assert!(
            connecting_hashes_heavier_disconnected(&hub, last)
                .unwrap()
                .is_none(),
            "far header on the same chain as tip is not a disconnected fork"
        );
        let mut st =
            super::super::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        for (h, hash) in &ahead {
            st.record_height(*hash, *h);
        }
        st.max_ordered_height = 8;
        assert!(
            !consider_disconnected_heavier(&mut st, &hub).unwrap(),
            "linear work-path must not register connecting search; need={:?}",
            st.reorg.need_getdata()
        );
        assert!(st.reorg.need_getdata().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Early IBD: headers sit far above a low tip. The ancestor walk hits its
    /// cap on a header-only mid, so join is not a confirmed LCA. That is still
    /// a linear extension, not a connecting search.
    ///
    /// Production walk is 10_000; a smaller cap plus ~20 headers hits the same
    /// branch without mining a mainnet-scale horizon.
    #[test]
    fn capped_walk_on_linear_headers_is_not_a_disconnected_fork() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let b1 = mine(gen, 1_500_080_100, 1);
        hub.accept_block(b1.clone()).unwrap();
        let mut prev = b1.block_hash();
        let mut time = 1_500_080_200u32;
        let mut last = prev;
        for h in 2..=20u32 {
            let b = mine(prev, time, h);
            hub.ensure_header(&b.header).unwrap();
            prev = b.block_hash();
            last = prev;
            time += 100;
        }
        let path = connecting_hashes_heavier_disconnected_n(&hub, last, 8).unwrap();
        assert!(
            path.is_none(),
            "capped walk whose join is header-only must not start connecting search; got {path:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connecting_search_skips_linear_tip_plus_one() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let mut prev = gen;
        let mut time = 1_500_090_100u32;
        let b1 = mine(prev, time, 1);
        hub.accept_block(b1.clone()).unwrap();
        prev = b1.block_hash();
        time += 100;
        let b2 = mine(prev, time, 2);
        hub.accept_block(b2.clone()).unwrap();
        prev = b2.block_hash();
        time += 100;
        let mut st =
            super::super::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        let mut last = prev;
        for h in 3..=20u32 {
            let b = mine(prev, time, h);
            hub.ensure_header(&b.header).unwrap();
            prev = b.block_hash();
            last = prev;
            time += 100;
            st.record_height(prev, h);
        }
        st.max_ordered_height = 20;
        assert!(
            connecting_search_candidates(&st, &hub).unwrap().is_empty(),
            "linear tip+1 must not be a connecting-search candidate (avoids a 10k max_ordered walk)"
        );
        assert!(
            !consider_disconnected_heavier(&mut st, &hub).unwrap(),
            "linear tip+1 + far headers must not register; last={last} need={:?}",
            st.reorg.need_getdata()
        );
        assert!(st.reorg.need_getdata().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connecting_search_candidates_is_tip_plus_one_when_competing() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_091_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        let l2 = mine(l1.block_hash(), 1_500_091_200, 2);
        hub.accept_block(l2.clone()).unwrap();
        let w1 = distinct_sib(mine(gen, 1_500_091_101, 1), l1.block_hash());
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_091_201, 2);
        hub.ensure_header(&w2.header).unwrap();
        let w3 = mine(w2.block_hash(), 1_500_091_301, 3);
        hub.ensure_header(&w3.header).unwrap();
        let w4 = mine(w3.block_hash(), 1_500_091_401, 4);
        hub.ensure_header(&w4.header).unwrap();
        let mut st =
            super::super::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        st.record_height(w3.block_hash(), 3);
        st.record_height(w4.block_hash(), 4);
        st.max_ordered_height = 4;
        assert_eq!(
            connecting_search_candidates(&st, &hub).unwrap(),
            vec![w3.block_hash()],
            "competing tip+1 is the only candidate; far header is the same fork"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connecting_search_skips_when_tip_plus_one_is_own_child() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let l1 = mine(gen, 1_500_092_100, 1);
        hub.accept_block(l1.clone()).unwrap();
        let l2 = mine(l1.block_hash(), 1_500_092_200, 2);
        hub.accept_block(l2.clone()).unwrap();
        let l3 = mine(l2.block_hash(), 1_500_092_300, 3);
        hub.ensure_header(&l3.header).unwrap();
        let w1 = distinct_sib(mine(gen, 1_500_092_101, 1), l1.block_hash());
        hub.ensure_header(&w1.header).unwrap();
        let w2 = mine(w1.block_hash(), 1_500_092_201, 2);
        hub.ensure_header(&w2.header).unwrap();
        let w3 = mine(w2.block_hash(), 1_500_092_301, 3);
        hub.ensure_header(&w3.header).unwrap();
        let w4 = mine(w3.block_hash(), 1_500_092_401, 4);
        hub.ensure_header(&w4.header).unwrap();
        let mut st =
            super::super::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        st.record_height(l3.block_hash(), 3);
        st.record_height(w4.block_hash(), 4);
        st.max_ordered_height = 4;
        assert!(
            connecting_search_candidates(&st, &hub).unwrap().is_empty(),
            "own-child tip+1 is linear; heavier far header is not a consider candidate"
        );
        assert!(
            !consider_disconnected_heavier(&mut st, &hub).unwrap(),
            "accepted miss: heavier fork only at max_ordered while tip+1 is our child"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
