//! Peer / body event drain and apply (IBD main loop).

use super::assign::clear_hash_inflight;
use super::assign_plan::{
    remove_from_ordered, should_enqueue_header, want_headers_beyond_soft_cap,
};
use super::dial::{
    note_dead_without_block_bytes, release_peer_block_work, request_headers, request_headers_from,
};
use super::exit::{
    header_lag_behind_peers, should_advance_locator_after_known_batch,
    should_log_empty_headers_lag, should_rerequest_headers_on_empty_lag,
    should_reseed_work_path_on_empty_lag,
};
use super::path::work_path_tips;
use super::peer_io::{note_block_progress, note_block_rx, PeerCmd, PeerEvent};
use super::state::IbdWorkState;
use super::status::LoopStats;
use super::{CONTIG_DENSIFY_AHEAD, MAX_ORDERED_HEADERS, MAX_PEER_POOL, ORDERED_HEADERS_SOFT_CAP};
use crate::chain::ChainHub;
use crate::codec::MAX_HEADERS_RESULTS;
use crate::error::NetError;
use crate::seeds::AddrMan;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_log::{info, trace, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Immediately stop getdata and disconnect every peer (SIGINT / IBD exit).
pub(crate) fn disconnect_all_peers(st: &mut IbdWorkState) {
    let n = st.slots.len();
    if n == 0 {
        return;
    }
    for s in &st.slots {
        let _ = s.cmd_tx.send(PeerCmd::Shutdown);
        s.task.abort();
    }
    st.inflight.clear();
    for s in &mut st.slots {
        s.in_flight.clear();
        s.alive = false;
    }
    st.slots.clear();
    info!("ibd: disconnected {n} peer(s)");
}

/// First 80 bytes of a consensus-serialized block → header (no full block decode).
fn decode_block_header_prefix(payload: &[u8]) -> Option<bitcoin::block::Header> {
    use bitcoin::consensus::Decodable;
    if payload.len() < 80 {
        return None;
    }
    let mut cur = std::io::Cursor::new(&payload[..80]);
    bitcoin::block::Header::consensus_decode(&mut cur).ok()
}

/// Header/control events per turn (anti-livelock under multi-peer header spam).
const CTRL_DRAIN_EVENT_BUDGET: u64 = 512;
const CTRL_DRAIN_TIME_BUDGET: Duration = Duration::from_millis(5);
/// Body path (framed/decoded blocks): process as much as possible so delivered
/// bytes are not stranded behind headers. Soft wall so cancel/assign still run.
const BODY_DRAIN_TIME_BUDGET: Duration = Duration::from_millis(40);

/// Non-blocking drain of archive results + peer events.
///
/// **Priority:** body (`BlockFramed`/…) → headers.
/// Delivered block bytes must not wait on header floods (single-FIFO waste).
/// Headers remain budgeted so apply cannot livelock.
///
/// Archive-job dual-track is gone: sole Class A path is body queue → confirm.
pub(crate) fn drain_ready_peer_and_body_events(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    body_rx: &mut mpsc::UnboundedReceiver<PeerEvent>,
    ctrl_rx: &mut mpsc::UnboundedReceiver<PeerEvent>,
    archive_write_next: &AtomicU32,
    loop_stats: &LoopStats,
    peer_book: &mut AddrMan,
    local_addr: SocketAddr,
    confirm_feed: Option<&super::confirm::ConfirmFeed>,
) -> Result<bool, NetError> {
    let t0 = Instant::now();
    let mut events = 0u64;

    let body_t0 = Instant::now();
    loop {
        if body_t0.elapsed() >= BODY_DRAIN_TIME_BUDGET {
            break;
        }
        match body_rx.try_recv() {
            Ok(ev) => {
                events += 1;
                apply_peer_event(
                    st,
                    hub,
                    ev,
                    archive_write_next,
                    peer_book,
                    local_addr,
                    confirm_feed,
                );
            }
            Err(_) => break,
        }
    }

    let ctrl_t0 = Instant::now();
    let mut ctrl_n = 0u64;
    while ctrl_n < CTRL_DRAIN_EVENT_BUDGET && ctrl_t0.elapsed() < CTRL_DRAIN_TIME_BUDGET {
        match ctrl_rx.try_recv() {
            Ok(ev) => {
                events += 1;
                ctrl_n += 1;
                apply_peer_event(
                    st,
                    hub,
                    ev,
                    archive_write_next,
                    peer_book,
                    local_addr,
                    confirm_feed,
                );
            }
            Err(_) => break,
        }
    }

    loop_stats
        .drain_ns
        .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    loop_stats.drain_events.fetch_add(events, Ordering::Relaxed);
    Ok(true)
}

fn batch_header_height(
    st: &IbdWorkState,
    hub: &ChainHub,
    prev: BlockHash,
    batch_prev: Option<(BlockHash, u32)>,
) -> Option<u32> {
    parent_height(&st.hash_height, hub, prev)
        .or_else(|| batch_prev.and_then(|(ph, pht)| (ph == prev).then_some(pht.saturating_add(1))))
}

fn note_header_path(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    hash: BlockHash,
    height: u32,
    prev: BlockHash,
) {
    let tip = hub.tip_height().zip(hub.tip_hash());
    if st.try_set_path_slot(hash, height, prev, tip) {
        st.max_peer_height = st.max_peer_height.max(height);
        st.max_ordered_height = st.max_ordered_height.max(height);
        return;
    }
    if let Some(&cur) = st.height_to_hash.get(&height) {
        if cur != hash {
            st.reorg.register_explore(std::iter::once(hash), Some(hash));
        }
    }
}

fn try_enqueue_ordered_header(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    hash: BlockHash,
    prev: BlockHash,
) -> bool {
    if hub.has_block(&hash) {
        st.known_headers.insert(hash);
        return false;
    }
    if st.body.is_rejected(&hash) || st.reorg.invalid.contains(hash.to_byte_array()) {
        return false;
    }
    let prev_ok = st.known_headers.contains(&prev)
        || hub.has_block(&prev)
        || prev.to_byte_array() == [0u8; 32]
        || hub.tip_hash() == Some(prev);
    if !prev_ok && hub.tip_height().is_some() && !st.known_headers.is_empty() {
        return false;
    }
    st.known_headers.insert(hash);
    let Some(ht) = st.hash_height.get(&hash).copied() else {
        return false;
    };
    if !st.is_on_path(&hash, ht) || st.ordered.len() >= MAX_ORDERED_HEADERS {
        return false;
    }
    if !should_enqueue_header(
        st.ordered_set.contains(&hash),
        st.inflight.contains_key(&hash),
        st.body.is_pending(&hash),
        st.body.is_rejected(&hash),
        hub.has_block(&hash),
        Some(ht),
        hub.tip_height(),
    ) {
        return false;
    }
    if st.ordered_set.insert(hash) {
        st.ordered.push_back(hash);
        return true;
    }
    false
}

fn on_headers_batch(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    headers: Vec<bitcoin::block::Header>,
) -> usize {
    let mut added = 0usize;
    let mut batch_prev: Option<(BlockHash, u32)> = None;
    for hdr in headers {
        let hash = hdr.block_hash();
        let prev = hdr.prev_blockhash;
        let already_known = st.known_headers.contains(&hash) && st.header_fks.contains_key(&hash);
        if let Some(h) = batch_header_height(st, hub, prev, batch_prev) {
            note_header_path(st, hub, hash, h, prev);
            batch_prev = Some((hash, h));
        }
        if !already_known && !st.header_fks.contains_key(&hash) {
            if let Ok(fk) = hub.ensure_header_fk(&hdr) {
                st.header_fks.insert(hash, fk);
            }
        }
        if try_enqueue_ordered_header(st, hub, hash, prev) {
            added += 1;
        }
    }
    added
}

fn on_empty_headers(st: &mut IbdWorkState, hub: &ChainHub) {
    st.empty_header_streak = st.empty_header_streak.saturating_add(1);
    let tip_h = hub.tip_height().unwrap_or(0);
    let lag = header_lag_behind_peers(st, tip_h);
    let path_idle = st.ordered.is_empty() && st.inflight.is_empty();
    let peers_n = st.slots.iter().filter(|s| s.alive).count() as u32;
    if st.empty_header_streak >= peers_n.max(2) && path_idle {
        st.headers_done = true;
    } else if lag > 2 {
        if should_log_empty_headers_lag(st.empty_header_streak) {
            let known = st
                .max_ready_height
                .max(st.hash_height.values().copied().max().unwrap_or(0));
            if st.ordered_set.is_empty() {
                warn!(
                    "ibd: empty headers but lag={lag} behind max_peer_height={} (known≈{known}, tip={tip_h}) — keep header sync",
                    st.max_peer_height,
                );
            } else {
                trace!(
                    "ibd: empty headers but lag={lag} behind max_peer_height={} (known≈{known}, tip={tip_h}) — keep header sync",
                    st.max_peer_height,
                );
            }
        }
        st.headers_done = false;
        if should_rerequest_headers_on_empty_lag(st.empty_header_streak) {
            if should_reseed_work_path_on_empty_lag(
                st.empty_header_streak,
                st.ordered_set.is_empty(),
            ) {
                super::path::seed_work_path_from_store(st, hub);
            }
            let tips = work_path_tips(st);
            let _ = request_headers(&st.slots, hub, &mut st.header_req_seq, &tips);
        }
    } else if st.empty_header_streak < 8 && st.ordered_set.len() < ORDERED_HEADERS_SOFT_CAP {
        let tips = work_path_tips(st);
        let _ = request_headers(&st.slots, hub, &mut st.header_req_seq, &tips);
    } else if st.empty_header_streak >= 8 && lag <= 2 {
        st.headers_done = true;
    }
}

fn on_known_headers_batch(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, batch_len: usize) {
    let live = st.ordered_set.len();
    let need_ready_headroom = want_headers_beyond_soft_cap(
        live,
        st.body.known_len(),
        st.max_ordered_height.saturating_sub(st.max_ready_height),
        4096,
    );
    let lag = header_lag_behind_peers(st, hub.tip_height().unwrap_or(0));
    if live < MAX_ORDERED_HEADERS
        && (live < ORDERED_HEADERS_SOFT_CAP || need_ready_headroom)
        && should_advance_locator_after_known_batch(
            live,
            lag,
            batch_len >= MAX_HEADERS_RESULTS,
            need_ready_headroom,
        )
    {
        let tips = work_path_tips(st);
        let _ = request_headers_from(&st.slots, peer, hub, &mut st.header_req_seq, &tips);
    }
}

pub(crate) fn apply_peer_event(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    ev: PeerEvent,
    archive_write_next: &AtomicU32,
    peer_book: &mut AddrMan,
    local_addr: SocketAddr,
    confirm_feed: Option<&super::confirm::ConfirmFeed>,
) {
    match ev {
        PeerEvent::Headers { peer, headers } => {
            let batch_len = headers.len();
            let added = on_headers_batch(st, hub, headers);
            if added > 0 {
                if super::reorg::consider_disconnected_heavier(st, hub).unwrap_or(false) {
                    let _ = try_complete_awaiting_reorg(st, hub);
                }
                st.empty_header_streak = 0;
                st.headers_done = false;
                let live = st.ordered_set.len();
                let need_ready_headroom = want_headers_beyond_soft_cap(
                    live,
                    st.body.known_len(),
                    st.max_ordered_height.saturating_sub(st.max_ready_height),
                    4096,
                );
                if batch_len >= MAX_HEADERS_RESULTS
                    && live < MAX_ORDERED_HEADERS
                    && (live < ORDERED_HEADERS_SOFT_CAP || need_ready_headroom)
                {
                    let tips = work_path_tips(st);
                    let _ =
                        request_headers_from(&st.slots, peer, hub, &mut st.header_req_seq, &tips);
                }
            } else if batch_len == 0 {
                on_empty_headers(st, hub);
            } else {
                on_known_headers_batch(st, hub, peer, batch_len);
            }
        }
        PeerEvent::BlockFramed {
            peer,
            hash,
            payload,
        } => {
            let wire_bytes = payload.len();
            note_block_rx(&mut st.slots, peer, wire_bytes);
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            // Class A `is_known_archived` is not claim-ready (needs BQ wire).
            if st.body.is_rejected(&hash) || hub.has_block(&hash) {
                return;
            }
            let header_fk = if let Some(&fk) = st.header_fks.get(&hash) {
                fk
            } else {
                let header = match decode_block_header_prefix(&payload) {
                    Some(h) => h,
                    None => {
                        st.body.mark_missing(hash);
                        return;
                    }
                };
                match hub.ensure_header_fk(&header) {
                    Ok(fk) => {
                        st.header_fks.insert(hash, fk);
                        fk
                    }
                    Err(e) => {
                        warn!("ibd: ensure_header {hash}: {e}");
                        st.body.mark_missing(hash);
                        return;
                    }
                }
            };
            let tip_h = hub.tip_height().unwrap_or(0);
            let height = st.hash_height.get(&hash).copied();
            let Some(height) = height else {
                st.body.mark_missing(hash);
                return;
            };
            let write_next = archive_write_next.load(Ordering::Relaxed);
            let tip_hi = tip_h.saturating_add(CONTIG_DENSIFY_AHEAD);
            let densify_hi = write_next.saturating_add(CONTIG_DENSIFY_AHEAD);
            if height > tip_hi && height > densify_hi {
                st.body.mark_missing(hash);
                return;
            }
            // Side-branch body at tip height (or any competing hash): hold by
            // hash for most-work reorg. BQ is height first-wins and cannot store
            // a same-height sibling of the confirmed tip.
            let tip_hash = hub.tip_hash();
            if height <= tip_h && tip_hash != Some(hash) {
                if let Ok(block) = bitcoin::consensus::deserialize::<bitcoin::Block>(&payload) {
                    st.reorg.hold_body(block);
                    st.body.mark_pending(hash);
                    if try_complete_awaiting_reorg(st, hub) {
                        return;
                    }
                }
            }
            if super::progress::claim_ready(hub, &mut st.body, height, &hash) {
                return;
            }
            let raw = hash.to_byte_array();
            match hub
                .query
                .block_queue_offer(height, raw, header_fk.0, &payload)
            {
                Ok(_offer) => {
                    let _ = try_complete_awaiting_reorg(st, hub);
                }
                Err(e) => {
                    rbitcoin_log::warn!("ibd: body queue offer failed ({e}) h={height}");
                    st.body.mark_missing(hash);
                    return;
                }
            }
            st.body.mark_pending(hash);
            if let Some(feed) = confirm_feed {
                feed.note(height, hash);
            }
        }
        PeerEvent::BlockDecodeFailed { peer, hash } => {
            note_block_progress(&mut st.slots, peer);
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            if st.body.is_pending(&hash) {
                st.body.mark_missing(hash);
            }
        }
        PeerEvent::NotFound { peer, hashes } => {
            note_block_progress(&mut st.slots, peer);
            if let Some(s) = st.slots.iter_mut().find(|s| s.id == peer) {
                for h in &hashes {
                    s.in_flight.remove(h);
                    let empty = st
                        .inflight
                        .get_mut(h)
                        .map(|e| e.remove_peer(peer))
                        .unwrap_or(false);
                    if empty {
                        st.inflight.remove(h);
                    }
                }
            }
        }
        PeerEvent::Addrs { peer, addrs } => {
            inject_learned_addrs(peer_book, &addrs, local_addr, peer);
        }
        PeerEvent::Dead { peer, reason } => {
            warn!("ibd: peer[{peer}] dead: {reason}");
            if let Some(s) = st.slots.iter().find(|s| s.id == peer) {
                note_dead_without_block_bytes(
                    peer_book,
                    &mut st.addr_cooldown,
                    s.addr,
                    s.first_data_ms,
                    Instant::now(),
                );
                if let Some(bps) = s.rate.bps() {
                    let first = s.first_data_ms;
                    let lat = first.saturating_sub(s.connected_ms);
                    peer_book.note_speed(s.addr, lat, bps);
                }
            }
            release_peer_block_work(&mut st.slots, &mut st.inflight, peer);
        }
    }
}

/// Grow the IBD dial book from peer-advertised addresses (getaddr responses).
pub(crate) fn inject_learned_addrs(
    book: &mut AddrMan,
    addrs: &[SocketAddr],
    local_addr: SocketAddr,
    from_peer: usize,
) {
    if addrs.is_empty() {
        return;
    }
    let mut added = 0usize;
    for &a in addrs {
        if a == local_addr || a.ip().is_unspecified() || a.port() == 0 {
            continue;
        }
        if book.add_learned(a, MAX_PEER_POOL) {
            added += 1;
        }
    }
    if added > 0 {
        rbitcoin_log::debug!(
            "ibd: peer[{from_peer}] taught {added} addr(s); book={}",
            book.len()
        );
    }
}

/// Permanent confirm failure: drop from the work path and never re-offer.
///
/// Without this, `offer_confirm_ready` re-noted ghost/re-queued hashes and the
/// confirm engine spun on the same BadPrev / missing-prevout tip+1 (signet log:
/// same hash every ~30s with tip frozen).
pub(crate) fn update_confirm_lag(lag: &AtomicU32, tip: Option<u32>, max_ready: u32) {
    let t = tip.unwrap_or(0);
    lag.store(max_ready.saturating_sub(t), Ordering::Relaxed);
}

pub(crate) fn apply_confirm_events(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    rx: &std::sync::mpsc::Receiver<super::confirm::ConfirmEvent>,
    archive_write_next: &AtomicU32,
    max_ready_shared: &AtomicU32,
    last_progress: &mut Instant,
    feed: Option<&super::confirm::ConfirmFeed>,
) {
    while let Ok(ev) = rx.try_recv() {
        match ev {
            super::confirm::ConfirmEvent::Accepted { hash } => {
                *last_progress = Instant::now();
                st.confirm_stuck_since = None;
                remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
                st.body.mark_archived(hash);
                let tip = hub.tip_height().unwrap_or(0);
                archive_write_next.store(tip.saturating_add(1), Ordering::Relaxed);
                st.max_ready_height = st.max_ready_height.max(tip);
                max_ready_shared.store(st.max_ready_height, Ordering::Relaxed);
            }
            super::confirm::ConfirmEvent::Reject {
                height,
                hash,
                class,
                err,
                batch_len,
            } => {
                apply_confirm_reject(
                    st,
                    height,
                    hash,
                    class,
                    &err,
                    Some(hub.query.as_ref()),
                    Some(hub),
                    batch_len,
                    feed,
                );
            }
        }
    }
    if st.confirm_quiesce {
        if let Some(f) = feed {
            f.clear();
        }
        st.confirm_quiesce = false;
    }
}

pub(crate) fn apply_confirm_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    class: super::confirm::ConfirmRejectClass,
    err: &str,
    query: Option<&rbitcoin_query::Query>,
    hub: Option<&crate::chain::ChainHub>,
    batch_len: usize,
    feed: Option<&super::confirm::ConfirmFeed>,
) {
    // Never blacklist the all-zero sentinel (write used to emit this on
    // mis-attributed rejects).
    use super::confirm::ConfirmRejectClass;
    use bitcoin::hashes::Hash;
    if hash.to_byte_array() == [0u8; 32] {
        warn!("ibd: confirm reject ignored zero-hash @{height}: {err}");
        return;
    }
    let class = if err.contains("parent create_fk unresolved")
        || err.contains("spend annotate missing pin denserels")
    {
        ConfirmRejectClass::EngineFault
    } else if class == ConfirmRejectClass::ConsensusInvalid {
        if let Some(h) = hub {
            class.trust_consensus(h, hash)
        } else {
            class
        }
    } else {
        class
    };
    let class = class.isolate_if_batched(batch_len);
    if class == ConfirmRejectClass::Cascade && batch_len > 1 {
        if let Some(f) = feed {
            f.request_single_block();
        }
    }
    if class.is_soft() {
        apply_soft_wire_reject(st, height, hash, err, query, hub);
        return;
    }
    match class {
        ConfirmRejectClass::Cancelled => {
            warn!("ibd: confirm reject cancelled @{height} {hash}: {err}");
        }
        ConfirmRejectClass::SoftWire => {}
        ConfirmRejectClass::Cascade => {
            apply_cascade_reject(st, height, hash, err, hub);
        }
        ConfirmRejectClass::EngineFault => {
            apply_engine_fault_reject(st, height, hash, err, query);
        }
        ConfirmRejectClass::ConsensusInvalid => {
            apply_consensus_invalid_reject(st, height, hash, err, query, hub);
        }
    }
}

fn apply_soft_wire_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    query: Option<&rbitcoin_query::Query>,
    hub: Option<&crate::chain::ChainHub>,
) {
    let bad_prev = super::reorg::is_bad_prev_err(err);
    if bad_prev {
        if let Some(q) = query {
            q.set_lookup_taken_hi(hub.and_then(|h| h.tip_height()));
        }
        st.headers_done = false;
    }
    if bad_prev {
        if let Some(h) = hub {
            st.reorg
                .register_explore(std::iter::empty::<bitcoin::BlockHash>(), Some(hash));
            let rewound = super::reorg::maybe_rewind_to_best_work(st, h).unwrap_or(false);
            if rewound {
                return;
            }
            if st.height_to_hash.get(&height) == Some(&hash) {
                st.height_to_hash.remove(&height);
                remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
            }
        } else if st.height_to_hash.get(&height) == Some(&hash) {
            st.height_to_hash.remove(&height);
            remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
        }
    }
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    if let Some(q) = query {
        let _ = q.block_queue_dequeue_height(height);
        if err.contains("merkle root mismatch")
            || err.contains("bad-txnmrklroot")
            || err.contains("witness commitment")
        {
            match q.clear_archived_body(hash.as_byte_array()) {
                Ok(true) => warn!(
                    "ibd: cleared corrupt Class A body for {hash} @{height} (merkle mismatch)"
                ),
                Ok(false) => {}
                Err(e) => warn!("ibd: clear Class A body {hash} @{height}: {e}"),
            }
        }
    }
    if !bad_prev {
        st.body.mark_missing(hash);
        st.body.demote_known(hash);
        warn!("ibd: confirm reject soft @{height} {hash}: {err} (re-getdata, not blacklisted)");
    } else {
        warn!(
            "ibd: confirm reject BadPrev @{height} {hash}: {err} (slot evicted, not re-get same hash)"
        );
    }
}

fn apply_cascade_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    hub: Option<&crate::chain::ChainHub>,
) {
    // Leave the body queue: the plan was stale, the wire is still good.
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    const CASCADE_HALT_AFTER: u8 = 3;
    let tip = hub
        .and_then(|h| h.tip_hash())
        .map(|t| t.to_byte_array())
        .unwrap_or([0u8; 32]);
    let n = match st.cascade_at {
        Some((h, t, c)) if h == hash && t == tip => c.saturating_add(1),
        _ => 1u8,
    };
    st.cascade_at = Some((hash, tip, n));
    if n >= CASCADE_HALT_AFTER {
        st.halt = Some(format!(
            "cascade repeated {n}× @{height} {hash} (tip unchanged): {err}"
        ));
        warn!(
            "ibd: confirm reject cascade halt @{height} {hash}: {err} ({n} at same tip, not blacklisted)"
        );
        return;
    }
    note_confirm_stuck(st);
    warn!("ibd: confirm reject cascade @{height} {hash}: {err} (requeue, not blacklisted)");
}

fn apply_engine_fault_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    query: Option<&rbitcoin_query::Query>,
) {
    if let Some(q) = query {
        let _ = q.block_queue_dequeue_height(height);
    }
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    if st.engine_fault_seen.contains(&hash) {
        st.halt = Some(format!("engine fault repeated @{height} {hash}: {err}"));
        warn!(
            "ibd: engine fault halt @{height} {hash}: {err} (second occurrence, not blacklisted)"
        );
        return;
    }
    st.engine_fault_seen.insert(hash);
    note_confirm_stuck(st);
    warn!(
        "ibd: confirm reject engine-fault @{height} {hash}: {err} (requeue once, not blacklisted)"
    );
}

fn apply_consensus_invalid_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    query: Option<&rbitcoin_query::Query>,
    hub: Option<&crate::chain::ChainHub>,
) {
    if let Some(q) = query {
        let _ = q.block_queue_dequeue_height(height);
    }
    st.body.mark_rejected(hash);
    st.reorg.invalid.mark(hash.to_byte_array());
    if st.height_to_hash.get(&height) == Some(&hash) {
        st.height_to_hash.remove(&height);
    }
    remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n.is_multiple_of(50) {
        warn!("ibd: confirm reject applied {hash} @{height}: {err} (consensus-invalid, count={n})");
    }
    if let Some(h) = hub {
        for t in super::reorg::competing_valid_header_tips(st, h) {
            st.reorg
                .register_explore(std::iter::empty::<bitcoin::BlockHash>(), Some(t));
        }
        let rewound = super::reorg::maybe_rewind_to_best_work(st, h).unwrap_or(false);
        if !rewound {
            super::path::seed_work_path_from_store(st, h);
        }
        super::path::plant_valid_tip_child(st, h);
        let expect = if h.tip_height().is_none() {
            0u32
        } else {
            h.tip_height().unwrap_or(0).saturating_add(1)
        };
        let next_ok = st.height_to_hash.get(&expect).is_some_and(|nh| {
            !st.reorg.invalid.contains(nh.to_byte_array()) && !st.body.is_rejected(nh)
        });
        if rewound || next_ok {
            st.confirm_stuck_since = None;
            return;
        }
    }
    note_confirm_stuck(st);
}

fn note_confirm_stuck(st: &mut IbdWorkState) {
    if st.confirm_stuck_since.is_none() {
        st.confirm_stuck_since = Some(Instant::now());
    }
}

/// Proactive most-work apply: header-work rewind only (no gathered `accept_branch`).
fn try_apply_exploration(st: &mut IbdWorkState, hub: &crate::chain::ChainHub) -> bool {
    if st.reorg.explore_tips().is_empty() {
        return false;
    }
    match super::reorg::maybe_rewind_to_best_work(st, hub) {
        Ok(true) => {
            rbitcoin_log::info!(
                "ibd: most-work header rewind after exploration (no accept_branch)"
            );
            true
        }
        Ok(false) => {
            st.reorg.clear_explore();
            false
        }
        Err(e) => {
            warn!("ibd: exploration rewind failed: {e}");
            false
        }
    }
}

/// After a side-branch body is held (or BQ has mids), try to finish an awaiting reorg
/// by header-work rewind (never `accept_branch` of gathered bodies).
pub(crate) fn try_complete_awaiting_reorg(
    st: &mut IbdWorkState,
    hub: &crate::chain::ChainHub,
) -> bool {
    try_apply_exploration(st, hub)
}

pub(crate) fn parent_height(
    hash_height: &HashMap<BlockHash, u32>,
    hub: &ChainHub,
    prev: BlockHash,
) -> Option<u32> {
    if prev.to_byte_array() == [0u8; 32] {
        return Some(0);
    }
    if let Some(&ph) = hash_height.get(&prev) {
        return Some(ph.saturating_add(1));
    }
    if hub.tip_hash() == Some(prev) {
        return Some(hub.tip_height().unwrap_or(0).saturating_add(1));
    }
    // Confirmed ancestor (tip−1 / deeper): competing headers often attach to a
    // non-tip parent that is not yet in the RAM height map. height_of_hash is
    // best-chain only — orphan prevs stay None (peer batch_prev can fill).
    if let Ok(Some(h)) = hub.query.height_of_hash(&prev.to_byte_array()) {
        return Some(h.0.saturating_add(1));
    }
    None
}

#[cfg(test)]
mod confirm_reject_tests;
#[cfg(test)]
mod decode_header_prefix_tests;
#[cfg(test)]
mod parent_height_tests;
