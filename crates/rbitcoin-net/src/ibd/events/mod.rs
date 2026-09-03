//! Peer / archive event drain and apply (IBD main loop).

use super::assign::clear_hash_inflight;
use super::assign_plan::{
    remove_from_ordered, should_enqueue_header, want_headers_beyond_soft_cap,
};
use super::dial::{release_peer_block_work, request_headers, request_headers_from};
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
pub(crate) fn drain_ready_peer_and_archive_events(
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
            let mut added = 0usize;
            // Mid-batch parents are often only the previous header in this message.
            let mut batch_prev: Option<(BlockHash, u32)> = None;
            for hdr in headers {
                let hash = hdr.block_hash();
                let prev = hdr.prev_blockhash;
                // Multi-peer overlap re-sends the same 2000-header windows. Full
                // ensure_header_fk (hash-head lookup + maybe put) on every repeat
                // made drain cost climb from ~µs to ~ms per event and froze the
                // main loop for tens of seconds with no status lines.
                let already_known =
                    st.known_headers.contains(&hash) && st.header_fks.contains_key(&hash);
                let height = parent_height(&st.hash_height, hub, prev).or_else(|| {
                    batch_prev.and_then(|(ph, pht)| {
                        if ph == prev {
                            Some(pht.saturating_add(1))
                        } else {
                            None
                        }
                    })
                });
                if let Some(h) = height {
                    let tip = hub.tip_height().zip(hub.tip_hash());
                    let on_path = st.try_set_path_slot(hash, h, prev, tip);
                    if !on_path {
                        if let Some(&cur) = st.height_to_hash.get(&h) {
                            if cur != hash {
                                st.reorg.register_explore(std::iter::once(hash), Some(hash));
                            }
                        }
                    }
                    st.max_peer_height = st.max_peer_height.max(h);
                    st.max_ordered_height = st.max_ordered_height.max(h);
                    batch_prev = Some((hash, h));
                }
                if !already_known {
                    if !st.header_fks.contains_key(&hash) {
                        if let Ok(fk) = hub.ensure_header_fk(&hdr) {
                            st.header_fks.insert(hash, fk);
                        }
                    }
                }
                if hub.has_block(&hash) {
                    st.known_headers.insert(hash);
                    continue;
                }
                if st.body.is_rejected(&hash) {
                    continue;
                }
                let prev_ok = st.known_headers.contains(&prev)
                    || hub.has_block(&prev)
                    || prev.to_byte_array() == [0u8; 32]
                    || hub.tip_hash() == Some(prev);
                if !prev_ok && hub.tip_height().is_some() && !st.known_headers.is_empty() {
                    continue;
                }
                st.known_headers.insert(hash);
                // Offer needs a height (ht==tip+1); unknown-height used to stall tip silently.
                if !st.hash_height.contains_key(&hash) {
                    continue;
                }
                let Some(ht) = st.hash_height.get(&hash).copied() else {
                    continue;
                };
                if !st.is_on_path(&hash, ht) {
                    continue;
                }
                if st.ordered.len() >= MAX_ORDERED_HEADERS {
                    continue;
                }
                if !should_enqueue_header(
                    st.ordered_set.contains(&hash),
                    st.inflight.contains_key(&hash),
                    st.body.is_pending(&hash),
                    st.body.is_rejected(&hash),
                    hub.has_block(&hash),
                    st.hash_height.get(&hash).copied(),
                    hub.tip_height(),
                ) {
                    continue;
                }
                if st.ordered_set.insert(hash) {
                    st.ordered.push_back(hash);
                    added += 1;
                }
            }
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
                st.empty_header_streak = st.empty_header_streak.saturating_add(1);
                let tip_h = hub.tip_height().unwrap_or(0);
                let lag = header_lag_behind_peers(st, tip_h);
                let path_idle = st.ordered.is_empty() && st.inflight.is_empty();
                let peers_n = st.slots.iter().filter(|s| s.alive).count() as u32;
                if st.empty_header_streak >= peers_n.max(2) && path_idle && lag <= 2 {
                    st.headers_done = true;
                } else if lag > 2 {
                    // Peers advertise a higher tip than our work path — empty is a
                    // false EOF (locator stuck / peer-horizon skew). Keep syncing;
                    // never mark headers_done.
                    //
                    // **Do not reset** `empty_header_streak` here: a prior reset every
                    // 8 empties re-triggered `streak == 1` WARNs and re-getheaders
                    // storms (mainnet: thousands of "empty headers but lag=…" lines).
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
                } else if st.empty_header_streak < 8
                    && st.ordered_set.len() < ORDERED_HEADERS_SOFT_CAP
                {
                    let tips = work_path_tips(st);
                    let _ = request_headers(&st.slots, hub, &mut st.header_req_seq, &tips);
                } else if st.empty_header_streak >= 8 && lag <= 2 {
                    st.headers_done = true;
                }
            } else {
                // Non-empty but all already known: advance locator off the work path
                // (do **not** count toward headers_done — multi-peer overlap was
                // marking done after one 2000-header window).
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
                    let _ =
                        request_headers_from(&st.slots, peer, hub, &mut st.header_req_seq, &tips);
                }
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
    if addrs.is_empty() || book.len() >= MAX_PEER_POOL {
        return;
    }
    let mut added = 0usize;
    for &a in addrs {
        if book.len() >= MAX_PEER_POOL {
            break;
        }
        if a == local_addr || a.ip().is_unspecified() || a.port() == 0 {
            continue;
        }
        let before = book.len();
        book.add(a);
        if book.len() > before {
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

pub(crate) fn apply_confirm_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    // When set, drop bad body-queue payload so densify can re-getdata a good block.
    query: Option<&rbitcoin_query::Query>,
    // When set, BadPrev may trigger most-work reorg onto a competing path.
    hub: Option<&crate::chain::ChainHub>,
    _wire: Option<std::sync::Arc<bitcoin::Block>>,
) {
    // Never blacklist the all-zero sentinel (write used to emit this on
    // mis-attributed rejects).
    use bitcoin::hashes::Hash;
    if hash.to_byte_array() == [0u8; 32] {
        warn!("ibd: confirm reject ignored zero-hash @{height}: {err}");
        return;
    }
    // Soft re-get only for bad wire / missing header window / merkle reconstruct.
    // Never soft-requeue "parent unresolved" / "fk mismatch" (hides store bugs).
    let soft_wire = err.contains("unexpected previous header")
        || err.contains("unexpected previous")
        || err.contains("missing retarget first header")
        || err.contains("merkle root mismatch");
    let bad_prev = super::reorg::is_bad_prev_err(err);
    if bad_prev {
        if let Some(q) = query {
            q.set_lookup_taken_hi(hub.and_then(|h| h.tip_height()));
        }
        st.headers_done = false;
    }
    if soft_wire {
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
            if err.contains("merkle root mismatch") {
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
        return;
    }
    if let Some(q) = query {
        let _ = q.block_queue_dequeue_height(height);
    }
    st.body.mark_rejected(hash);
    remove_from_ordered(&mut st.ordered, &mut st.ordered_set, hash);
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n.is_multiple_of(50) {
        warn!("ibd: confirm reject applied {hash} @{height}: {err} (blacklisted, count={n})");
    }
}

/// True if reorg gather can obtain `hash` without a Class A reconstruct probe.
///
/// Hot path gate for exploration: do **not** call `reconstruct_block_by_hash`
/// here (store IO on hundreds of ordered hashes pegged one core on mainnet).
/// BQ readiness is **by hash** only — height first-wins of a different body is
/// not ready (same contract as `claim_ready` / densify `need_hash_at`).
fn reorg_body_ready_cheap(
    st: &IbdWorkState,
    hub: &crate::chain::ChainHub,
    hash: BlockHash,
) -> bool {
    use bitcoin::hashes::Hash as _;
    if st.reorg.get_held(&hash).is_some() {
        return true;
    }
    if hub.has_block(&hash) {
        return true;
    }
    hub.query.block_queue_has_hash(&hash.to_byte_array()) || st.body.is_known_archived(&hash)
}

/// Load a full block for `hash` from reorg held map, BQ-by-hash, or Class A.
///
/// Order: held → BQ (cheap RAM) → Class A reconstruct (store IO last).
fn load_reorg_body(
    st: &IbdWorkState,
    hub: &crate::chain::ChainHub,
    hash: BlockHash,
) -> Option<bitcoin::Block> {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash as _;
    if let Some(b) = st.reorg.get_held(&hash) {
        return Some(b);
    }
    if let Ok(Some(wire)) = hub.query.block_queue_payload_by_hash(&hash.to_byte_array()) {
        if !wire.is_empty() {
            if let Ok(b) = deserialize::<bitcoin::Block>(&wire) {
                return Some(b);
            }
        }
    }
    if let Ok(Some(b)) = hub.query.reconstruct_block_by_hash(&hash.to_byte_array()) {
        return Some(b);
    }
    None
}

/// Proactive most-work apply for exploration tips (seeded sibling fork) when
/// bodies are available via held map, Class A, or BQ-by-hash — not held-only.
/// Tip+1 extensions never enter held on BlockFramed (only height≤tip siblings),
/// so apply must load BQ/Class A the same way BadPrev gather does.
///
/// **Hot path:** called from every mid `BlockFramed`. Must **not** probe Class A
/// / `load_reorg_body` for the full ordered path (mainnet ~180 hashes → multi-
/// second drain, 1-core peg, status delayed ~minute). Gate on explore_need
/// cheap readiness, then load only need + tip→LCA walks.
fn try_apply_exploration(st: &mut IbdWorkState, hub: &crate::chain::ChainHub) -> bool {
    use super::reorg::try_apply_best_candidate;
    use crate::chain::AcceptOutcome;
    use rbitcoin_log::info;
    use std::collections::HashMap;

    let tips: Vec<BlockHash> = st.reorg.explore_tips().to_vec();
    if tips.is_empty() {
        return false;
    }

    let need: Vec<BlockHash> = st.reorg.explore_need_hashes().to_vec();
    for &h in &need {
        if !reorg_body_ready_cheap(st, hub, h) {
            return false;
        }
    }

    let mut bodies: HashMap<BlockHash, bitcoin::Block> = HashMap::new();
    for &h in &need {
        let Some(b) = load_reorg_body(st, hub, h) else {
            return false;
        };
        st.reorg.hold_body(b.clone());
        bodies.insert(h, b);
    }

    for &tip in &tips {
        let mut cur = tip;
        for _ in 0..10_000 {
            if hub.has_block(&cur) {
                break;
            }
            if !bodies.contains_key(&cur) {
                let Some(b) = load_reorg_body(st, hub, cur) else {
                    break;
                };
                st.reorg.hold_body(b.clone());
                let prev = b.header.prev_blockhash;
                bodies.insert(cur, b);
                if hub.has_block(&prev) || prev.to_byte_array() == [0u8; 32] {
                    break;
                }
                cur = prev;
                continue;
            }
            let prev = bodies[&cur].header.prev_blockhash;
            if hub.has_block(&prev) || prev.to_byte_array() == [0u8; 32] {
                break;
            }
            cur = prev;
        }
    }

    if bodies.is_empty() {
        return false;
    }
    let losing = hub.tip_hash();
    let apply_tip = tips.first().copied();
    match try_apply_best_candidate(hub, &bodies, &tips, &mut st.reorg) {
        Ok(Some(AcceptOutcome::Accepted { height: new_h })) => {
            info!("ibd: most-work reorg after exploration gather → tip_h={new_h}");
            let tip = hub.tip_hash().or(apply_tip);
            if let Some(tip) = tip {
                on_reorg_accepted(st, hub, tip, bodies.keys().copied(), losing);
            } else {
                for h in bodies.keys() {
                    st.body.mark_archived(*h);
                }
                st.reorg.clear_awaiting();
                st.reorg.clear_explore();
            }
            true
        }
        Ok(_) => false,
        Err(e) => {
            warn!("ibd: exploration reorg failed: {e}");
            false
        }
    }
}

/// Scrub IBD state after a successful most-work reorg apply (awaiting or explore).
fn on_reorg_accepted(
    st: &mut IbdWorkState,
    hub: &crate::chain::ChainHub,
    applied_tip: BlockHash,
    body_hashes: impl IntoIterator<Item = BlockHash>,
    losing_tip: Option<BlockHash>,
) {
    if let Some(ht) = st.hash_height.get(&applied_tip).copied() {
        let _ = hub.query.block_queue_dequeue_height(ht);
    }
    clear_hash_inflight(&mut st.slots, &mut st.inflight, applied_tip);
    for h in body_hashes {
        st.body.mark_archived(h);
    }
    if let Some(l) = losing_tip {
        remove_from_ordered(&mut st.ordered, &mut st.ordered_set, l);
    }
    if let Some(h) = hub.tip_height() {
        st.clear_path_above(h);
    }
    st.reorg.clear_awaiting();
    st.reorg.clear_explore();
}

/// After a side-branch body is held (or BQ has mids), try to finish an awaiting reorg.
pub(crate) fn try_complete_awaiting_reorg(
    st: &mut IbdWorkState,
    hub: &crate::chain::ChainHub,
) -> bool {
    use super::reorg::{header_hashes_to_best_ancestor, try_apply_best_candidate};
    use crate::chain::AcceptOutcome;
    use rbitcoin_log::info;
    use std::collections::HashMap;

    if try_apply_exploration(st, hub) {
        return true;
    }

    let Some(awaiting) = st.reorg.awaiting().cloned() else {
        return false;
    };
    let tip_hash = awaiting.held_tip.block_hash();
    let held_tip = awaiting.held_tip.clone();
    let mut bodies: HashMap<BlockHash, bitcoin::Block> = HashMap::new();
    st.reorg.hold_body(held_tip.clone());
    bodies.insert(tip_hash, held_tip.clone());

    let mut missing = Vec::new();
    let mut load = |h: BlockHash| {
        if bodies.contains_key(&h) {
            return;
        }
        if let Some(b) = load_reorg_body(st, hub, h) {
            st.reorg.hold_body(b.clone());
            bodies.insert(h, b);
        } else {
            if !missing.contains(&h) {
                missing.push(h);
            }
            st.body.mark_missing(h);
        }
    };
    if let Ok(path) = header_hashes_to_best_ancestor(hub, tip_hash) {
        for h in path {
            if h != tip_hash {
                load(h);
            }
        }
    }
    for h in &awaiting.need {
        load(*h);
    }
    if !missing.is_empty() {
        st.reorg.set_awaiting(held_tip, missing);
        return false;
    }
    let losing = hub.tip_hash();
    match try_apply_best_candidate(hub, &bodies, &[tip_hash], &mut st.reorg) {
        Ok(Some(AcceptOutcome::Accepted { height: new_h })) => {
            info!("ibd: most-work reorg completed after body gather → tip_h={new_h}");
            on_reorg_accepted(st, hub, tip_hash, bodies.keys().copied(), losing);
            true
        }
        Ok(None) => {
            warn!(
                "ibd: awaiting reorg not applied (no candidate; bodies={})",
                bodies.len()
            );
            false
        }
        Ok(other) => {
            warn!("ibd: awaiting reorg not applied: {other:?}");
            false
        }
        Err(e) => {
            warn!("ibd: awaiting reorg failed: {e}");
            false
        }
    }
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
