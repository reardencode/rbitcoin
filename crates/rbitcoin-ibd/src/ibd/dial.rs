//! Peer dial, header request, stall disconnect / cooldown.

use super::peer_io::{ibd_mono_ms, spawn_peer, PeerCmd, PeerEventSinks, PeerSlot};
use super::rate::{PROGRESS_STEP, RELSLOW_ACTIVE_MS};
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::BlockHash;
use rbitcoin_log::{debug, error, info, warn};
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::error::NetError;
use rbitcoin_net::peers::{trying_connection_log, PeerConnType};
use rbitcoin_net::seeds::AddrMan;
use rbitcoin_net::NetAddr;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long to avoid redialing an address after a stall disconnect.
pub const STALL_ADDR_COOLDOWN: Duration = Duration::from_secs(10 * 60);
/// Second stall/relative-slow kick of the same addr this process.
pub const STALL_ADDR_COOLDOWN_2: Duration = Duration::from_secs(30 * 60);
/// Third and later kicks this process.
pub const STALL_ADDR_COOLDOWN_3: Duration = Duration::from_secs(2 * 60 * 60);
/// Core `MANUAL_PEER_BLOCK_DOWNLOAD_COOLDOWN`: a manual peer that stalls block
/// download is sent no block getdata for this long on the node clock.
pub const MANUAL_PEER_BLOCK_DOWNLOAD_COOLDOWN: Duration = Duration::from_secs(2 * 60);

/// Bulk cluster: `median <= min * this` → tight pack, never relative-disconnect.
/// Uses median/min (not max/min) so one fast peer does not open the gate.
pub const RELATIVE_SLOW_CLUSTER_SPREAD: u64 = 2;
/// Disconnect only if peer bps ≤ median / this (4 → quarter median).
pub const RELATIVE_SLOW_OUTLIER_RATIO: u64 = 4;
/// Same peer must fail Gate B for this long before disconnect (ms).
pub const RELATIVE_SLOW_HYSTERESIS_MS: u64 = 2_000;
/// Minimum gap between relative-slow disconnects (ms).
pub const RELATIVE_SLOW_MIN_KICK_GAP_MS: u64 = 5_000;
/// Target mature peers before relative rule runs (full IBD peer set).
pub const RELATIVE_SLOW_MIN_SAMPLES: usize = 8;
/// Floor when fewer than 16 alive peers.
pub const RELATIVE_SLOW_MIN_SAMPLES_FLOOR: usize = 6;
/// Global IBD download age before any relative disconnect (ms).
pub const RELATIVE_SLOW_GLOBAL_WARMUP_MS: u64 = 60_000;

/// One mature speed sample for relative-slow classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelativeSlowSample {
    pub peer_id: usize,
    pub bps: u64,
    pub has_inflight: bool,
}

/// Minimum mature samples required given how many peers are alive.
pub fn relative_slow_min_samples(alive: usize) -> usize {
    if alive == 0 {
        return RELATIVE_SLOW_MIN_SAMPLES;
    }
    if alive >= 16 {
        RELATIVE_SLOW_MIN_SAMPLES
    } else {
        let half = alive.div_ceil(2);
        half.max(RELATIVE_SLOW_MIN_SAMPLES_FLOOR).min(alive)
    }
}

/// Median of a non-empty sorted slice (average of two middle when even).
pub fn median_u64(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        let a = sorted[n / 2 - 1];
        let b = sorted[n / 2];
        a.saturating_add(b) / 2
    }
}

/// Pure relative-slow pick: at most one peer id that is a clear quarter-median
/// outlier with inflight work. Empty when pack is tight, thin, or no outlier.
///
/// `bps == 0` with inflight work is a peer that has not delivered block bytes.
/// It can be the outlier next to peers that have. An all-zero set returns
/// none; the stall pass owns that set.
/// Gate A: `median <= min * CLUSTER_SPREAD` on the samples → none.
/// Gate B: `bps * OUTLIER_RATIO <= median` and `has_inflight` → worst bps.
pub fn relative_slow_pick(samples: &[RelativeSlowSample], min_samples: usize) -> Option<usize> {
    if samples.len() < min_samples {
        return None;
    }
    let mut bps: Vec<u64> = samples.iter().map(|s| s.bps).collect();
    bps.sort_unstable();
    let lo = bps[0];
    let med = median_u64(&bps);
    if med == 0 {
        return None;
    }
    if med <= lo.saturating_mul(RELATIVE_SLOW_CLUSTER_SPREAD) {
        return None;
    }
    let mut worst: Option<(usize, u64)> = None;
    for s in samples {
        if !s.has_inflight {
            continue;
        }
        if s.bps.saturating_mul(RELATIVE_SLOW_OUTLIER_RATIO) > med {
            continue;
        }
        match worst {
            None => worst = Some((s.peer_id, s.bps)),
            Some((_, wb)) if s.bps < wb => worst = Some((s.peer_id, s.bps)),
            Some((wid, wb)) if s.bps == wb && s.peer_id < wid => {
                worst = Some((s.peer_id, s.bps));
            }
            _ => {}
        }
    }
    worst.map(|(id, _)| id)
}

/// Wall-clock hysteresis: same id must fail Gate B for [`RELATIVE_SLOW_HYSTERESIS_MS`]
/// and [`RELATIVE_SLOW_MIN_KICK_GAP_MS`] must have elapsed since the last kick.
/// Different pick resets the suspect clock. `last_kick_ms == 0` means never kicked.
pub fn relative_slow_with_hysteresis(
    samples: &[RelativeSlowSample],
    min_samples: usize,
    now_ms: u64,
    prev_suspect: Option<(usize, u64)>,
    last_kick_ms: u64,
) -> (Option<usize>, Option<(usize, u64)>) {
    let Some(id) = relative_slow_pick(samples, min_samples) else {
        return (None, None);
    };
    let since = match prev_suspect {
        Some((pid, t)) if pid == id => t,
        _ => now_ms,
    };
    let suspect = Some((id, since));
    let held = now_ms.saturating_sub(since) >= RELATIVE_SLOW_HYSTERESIS_MS;
    let gap_ok =
        last_kick_ms == 0 || now_ms.saturating_sub(last_kick_ms) >= RELATIVE_SLOW_MIN_KICK_GAP_MS;
    if held && gap_ok {
        (Some(id), None)
    } else {
        (None, suspect)
    }
}

/// Build mature relative-slow samples from live slots (`active_ms` floor).
pub fn mature_relative_slow_samples(slots: &[PeerSlot], now_ms: u64) -> Vec<RelativeSlowSample> {
    let mut out = Vec::new();
    for s in slots {
        if !s.alive {
            continue;
        }
        if s.rate.active_ms < RELSLOW_ACTIVE_MS {
            continue;
        }
        let Some(bps) = s.rate.eviction_bps(now_ms) else {
            continue;
        };
        if bps == 0 {
            // Chat with getdata outstanding is a real zero. A body still
            // arriving, or a peer with nothing assigned, is not.
            let streaming = s
                .bytes_rx_total
                .load(Ordering::Relaxed)
                .saturating_sub(s.rate.bytes_at_progress);
            if s.in_flight.is_empty() || streaming >= PROGRESS_STEP {
                continue;
            }
        }
        out.push(RelativeSlowSample {
            peer_id: s.id,
            bps,
            has_inflight: !s.in_flight.is_empty(),
        });
    }
    out
}

/// Earliest first-data mono ms among alive peers (0 = no download yet).
pub fn global_first_block_ms(slots: &[PeerSlot]) -> u64 {
    let mut min_first = 0u64;
    for s in slots {
        if !s.alive {
            continue;
        }
        let first = s.first_data_ms;
        if first == 0 {
            continue;
        }
        if min_first == 0 || first < min_first {
            min_first = first;
        }
    }
    min_first
}

/// True when IBD has been receiving block bytes long enough for relative rule.
pub fn relative_slow_global_warmup_at(slots: &[PeerSlot], now_ms: u64) -> bool {
    let first = global_first_block_ms(slots);
    if first == 0 {
        return false;
    }
    now_ms.saturating_sub(first) >= RELATIVE_SLOW_GLOBAL_WARMUP_MS
}

/// Classified dial failure for [`AddrMan`] flag updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailKind {
    /// TCP/timeout/IO — `FAILED_LAST_CONNECT`.
    Network,
    /// No BIP324 v2 — `INCOMPATIBLE`.
    Incompatible,
}

#[doc(hidden)]
pub fn classify_dial_err(e: &NetError) -> DialFailKind {
    match e {
        NetError::V1Peer | NetError::Bip324(_) => DialFailKind::Incompatible,
        NetError::Protocol(s)
            if s.contains("v2") || s.contains("verack") || s.contains("version") =>
        {
            DialFailKind::Incompatible
        }
        _ => DialFailKind::Network,
    }
}

/// Result of a dial batch: live slots + failures for the peer book.
pub struct DialBatchResult {
    pub slots: Vec<PeerSlot>,
    pub failed: Vec<(rbitcoin_net::NetAddr, DialFailKind)>,
    pub attempted: Vec<rbitcoin_net::NetAddr>,
}

/// Process-wide, not per IBD run: a body queue row outlives the run that
/// queued it and names its sender by this id.
#[doc(hidden)]
pub static NEXT_PEER_ID: AtomicUsize = AtomicUsize::new(0);

/// A peer id no other connection in this process has had.
pub fn next_peer_id() -> usize {
    NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Core dials `-connect` as a manual connection. Every other IBD dial is
/// outbound full relay.
fn ibd_conn_type(connect: &[NetAddr], addr: NetAddr) -> PeerConnType {
    if connect.contains(&addr) {
        PeerConnType::Manual
    } else {
        PeerConnType::OutboundFullRelay
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Dial up to `count` ranked candidates from `book`. `already` is exclude
/// (slots + cooldown). `occupied` is live addrs whose netgroups are skipped
/// while unused-group candidates remain. A `connect` target is dialled as
/// [`PeerConnType::Manual`].
pub async fn dial_batch(
    book: &AddrMan,
    count: usize,
    mut already: HashSet<rbitcoin_net::NetAddr>,
    occupied: &[SocketAddr],
    magic: Magic,
    local_addr: SocketAddr,
    tip_h: Option<u32>,
    sinks: PeerEventSinks,
    connect_timeout: Duration,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    dialer: rbitcoin_net::socks::Dialer,
    clock: &rbitcoin_consensus::NodeClock,
    perms: Option<Arc<rbitcoin_net::peers::PeerHub>>,
    connect: &[NetAddr],
) -> DialBatchResult {
    let mut out = DialBatchResult {
        slots: Vec::new(),
        failed: Vec::new(),
        attempted: Vec::new(),
    };
    if count == 0 || book.is_empty() {
        return out;
    }
    let cancelled = || {
        cancel
            .as_ref()
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(false)
    };

    let candidates = book.take_dial_candidates_net(count, &already, occupied);
    out.attempted = candidates.clone();
    let mut handles = Vec::new();
    for addr in candidates {
        if cancelled() {
            break;
        }
        if handles.len() >= count {
            break;
        }
        if !already.insert(addr) {
            continue;
        }
        let id = next_peer_id();
        let sinks = sinks.clone();
        clock.note_connection_attempt();
        let conn_type = ibd_conn_type(connect, addr);
        debug!("{}", trying_connection_log(conn_type, addr));
        let dialer = dialer.clone();
        let to = dialer.connect_timeout(addr, connect_timeout);
        let dial_perms = perms.clone();
        handles.push(tokio::spawn(async move {
            let fut = spawn_peer(
                id, addr, magic, local_addr, tip_h, sinks, dialer, dial_perms, conn_type,
            );
            match tokio::time::timeout(to, fut).await {
                Ok(Ok(slot)) => Ok(slot),
                Ok(Err(e)) => {
                    let kind = classify_dial_err(&e);
                    Err((id, addr, kind, e.to_string()))
                }
                Err(_) => Err((
                    id,
                    addr,
                    DialFailKind::Network,
                    format!("connect timeout ({to:?})"),
                )),
            }
        }));
    }
    for h in handles {
        if cancelled() {
            h.abort();
            continue;
        }
        match h.await {
            Ok(Ok(slot)) => out.slots.push(slot),
            Ok(Err((id, addr, kind, reason))) => {
                warn!("ibd: peer[{id}] {addr} failed: {reason}");
                out.failed.push((addr, kind));
            }
            Err(e) => {
                error!("ibd: peer connect task panicked: {e}");
            }
        }
    }
    out.slots.sort_by_key(|s| s.id);
    out
}

/// How many new dials to start when below `target` live peers.
///
/// At least 2 so a single lemon cannot occupy the only spare slot forever;
/// at most 8 to bound burst. 0 when already at/above target.
pub fn redial_want(alive: usize, target: usize) -> usize {
    let target = target.max(1);
    if alive >= target {
        0
    } else {
        (target - alive).clamp(2, 8)
    }
}

/// Apply dial successes / failures to the peer book.
///
/// A network failure (EOF, timeout) takes the same strike cooldown as a
/// stall kick. Incompatible peers stay last-resort without that ban.
/// A later successful connect clears the cooldown, but keeps its strike history.
pub fn apply_dial_result(
    book: &mut AddrMan,
    result: &DialBatchResult,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr_strikes: &mut HashMap<NetAddr, u8>,
    now: Instant,
) {
    for &addr in &result.attempted {
        book.note_attempt_addr(addr);
    }
    for s in &result.slots {
        book.note_connected_addr(s.net);
        addr_cooldown.remove(&s.net);
    }
    for &(addr, kind) in &result.failed {
        let incompatible = kind == DialFailKind::Incompatible;
        book.note_connect_failed_addr(addr, incompatible);
        if incompatible {
            continue;
        }
        record_stall_kick(addr_cooldown, addr_strikes, addr, now);
    }
}

/// True when some dialable address is neither live nor cooling and did not
/// fail its last connect. Relative-slow must not drop a peer when this is
/// false: the only redials would be dead seeds or addresses already banned.
pub fn replacement_available(
    book: &AddrMan,
    slots: &[PeerSlot],
    cooldown: &HashMap<NetAddr, Instant>,
    now: Instant,
) -> bool {
    let live: HashSet<rbitcoin_net::NetAddr> =
        slots.iter().filter(|s| s.alive).map(|s| s.net).collect();
    book.dial_order().iter().copied().any(|addr| {
        if !book.is_dialable(addr) || live.contains(&addr) {
            return false;
        }
        let cooling = cooldown.get(&addr).is_some_and(|until| *until > now);
        !cooling && !book.connect_failed(addr)
    })
}

pub fn request_headers_from(
    slots: &[PeerSlot],
    peer: usize,
    _seq: &mut u32,
    locator: Vec<BlockHash>,
) -> Result<bool, NetError> {
    let Some(s) = slots.iter().find(|s| s.id == peer && s.alive) else {
        return Ok(false);
    };
    Ok(s.cmd_tx.send(PeerCmd::GetHeaders { locator }).is_ok())
}

/// Locator for IBD getheaders: prefer the **work-path tip** (highest ordered /
/// archived hash) ahead of the confirmed store tip.
///
/// Signet bug: with only `query.locator_hashes()` (confirmed tip), when archive
/// led tip by a full headers window (~2000), peers re-served that same window
/// forever; we marked `headers_done` and exited IBD at height 2000 while
/// `max_peer_height` was still ~313k.
pub fn ibd_header_locator(
    hub: &ChainHub,
    work_tips: &[BlockHash],
    confirmed_tail: &[BlockHash],
) -> Vec<BlockHash> {
    let mut locator = Vec::with_capacity(32);
    // Eight hashes is the walk's own stop. This only enforces the protocol
    // maximum, so a stored tip prepended in front does not drop the oldest
    // checkpoint.
    for h in work_tips {
        if locator.len() >= rbitcoin_net::codec::MAX_LOCATOR_SZ {
            break;
        }
        if !locator.contains(h) {
            locator.push(*h);
        }
    }
    // In-memory snapshot. Not a header-store walk.
    if let Some(t) = hub.tip_hash() {
        if locator.len() < rbitcoin_net::codec::MAX_LOCATOR_SZ && !locator.contains(&t) {
            locator.push(t);
        }
    }
    for h in confirmed_tail {
        if locator.len() >= rbitcoin_net::codec::MAX_LOCATOR_SZ {
            break;
        }
        if !locator.contains(h) {
            locator.push(*h);
        }
    }
    if locator.is_empty() {
        locator.push(BlockHash::from_byte_array([0u8; 32]));
    }
    locator
}

/// Mark `peer` dead and drop it from every hash it holds. Returns the hashes
/// no other peer still holds: they are no longer requested and need
/// [`super::state::IbdWorkState::reopen_for_densify`].
pub fn release_peer_block_work(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    peer: usize,
) -> Vec<bitcoin::BlockHash> {
    let Some(s) = slots.iter_mut().find(|s| s.id == peer) else {
        return Vec::new();
    };
    s.alive = false;
    let owed = s.track_drain();
    release_block_requests(inflight, body, peer, owed)
}

/// Drop `peer` from each of `owed`. A disconnect and a manual-peer pause
/// both release through here.
fn release_block_requests(
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    peer: usize,
    owed: Vec<bitcoin::BlockHash>,
) -> Vec<bitcoin::BlockHash> {
    let mut freed = Vec::new();
    for h in owed {
        let empty = inflight
            .get_mut(&h)
            .map(|e| e.remove_peer(peer))
            .unwrap_or(false);
        if empty {
            inflight.remove(&h);
            if body.is_pending(&h) {
                body.mark_missing(h);
            }
            freed.push(h);
        }
    }
    freed
}

/// When every dialable address is live or cooling, drop the cooling address
/// we tried least recently from `exclude` so one redial can proceed.
/// Never-attempted sorts first. A free candidate suppresses this.
pub fn admit_cooldown_fallback(
    book: &AddrMan,
    exclude: &mut HashSet<rbitcoin_net::NetAddr>,
    occupied: &[SocketAddr],
    cooldown: &HashMap<NetAddr, Instant>,
    now: Instant,
    live: &HashSet<rbitcoin_net::NetAddr>,
) -> Option<rbitcoin_net::NetAddr> {
    if !book
        .take_dial_candidates_net(1, exclude, occupied)
        .is_empty()
    {
        return None;
    }
    let cooling: Vec<rbitcoin_net::NetAddr> = book
        .dial_order()
        .iter()
        .copied()
        .filter(|a| book.is_dialable(*a) && !live.contains(a))
        .filter(|a| cooldown.get(a).is_some_and(|until| *until > now))
        .collect();
    let pick = cooling
        .iter()
        .copied()
        .enumerate()
        .min_by_key(|(i, a)| {
            (
                book.last_attempt_of(*a).is_some(),
                book.last_attempt_of(*a).unwrap_or(now),
                *i,
            )
        })
        .map(|(_, a)| a)?;
    exclude.remove(&pick);
    Some(pick)
}

/// Addrs we must not dial: currently connected/slot-held + still-cooling stall bans.
pub fn dial_blocked_addrs(
    slots: &[PeerSlot],
    cooldown: &HashMap<NetAddr, Instant>,
    now: Instant,
) -> HashSet<rbitcoin_net::NetAddr> {
    let mut blocked: HashSet<rbitcoin_net::NetAddr> = slots.iter().map(|s| s.net).collect();
    for (&addr, &until) in cooldown {
        if until > now {
            blocked.insert(addr);
        }
    }
    blocked
}

/// Live slot addrs whose netgroups occupy outbound diversity (cooldown is exclude-only).
pub fn alive_dial_addrs(slots: &[PeerSlot]) -> Vec<SocketAddr> {
    slots
        .iter()
        .filter(|s| s.alive)
        .filter_map(|s| s.net.socket_addr())
        .collect()
}

pub fn expire_addr_cooldown(
    cooldown: &mut HashMap<NetAddr, Instant>,
    strikes: &mut HashMap<NetAddr, u8>,
    book: &AddrMan,
    now: Instant,
) {
    cooldown.retain(|_, until| *until > now);
    strikes.retain(|addr, _| cooldown.contains_key(addr) || book.entry_of(addr).is_some());
}

/// Cooldown after the Nth stall/relative-slow kick of this addr this process.
pub fn kick_cooldown_for(strikes: u8) -> Duration {
    match strikes {
        0 | 1 => STALL_ADDR_COOLDOWN,
        2 => STALL_ADDR_COOLDOWN_2,
        _ => STALL_ADDR_COOLDOWN_3,
    }
}

/// Drop one live peer, cool down its address, and hand its block getdata
/// back to densify. The main loop drops dead slots before `PeerDead`
/// arrives, so the release cannot wait for that event.
pub fn disconnect_peer(st: &mut super::state::IbdWorkState, peer: usize) {
    let Some(idx) = st.slots.iter().position(|s| s.id == peer && s.alive) else {
        return;
    };
    let net = st.slots[idx].net;
    let _ = st.slots[idx].cmd_tx.send(PeerCmd::Shutdown);
    if !net.socket_addr().is_some_and(|s| s.ip().is_unspecified()) {
        record_stall_kick(
            &mut st.addr_cooldown,
            &mut st.addr_strikes,
            net,
            Instant::now(),
        );
    }
    let freed = release_peer_block_work(&mut st.slots, &mut st.inflight, &mut st.body, peer);
    st.reopen_for_densify(&freed);
}

/// Bump the process-local strike count and set `addr_cooldown`.
pub fn record_stall_kick(
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    strikes: &mut HashMap<NetAddr, u8>,
    addr: NetAddr,
    now: Instant,
) -> Duration {
    let n = {
        let e = strikes.entry(addr).or_insert(0);
        *e = e.saturating_add(1);
        *e
    };
    let d = kick_cooldown_for(n);
    addr_cooldown.insert(addr, now + d);
    d
}

/// Handshake with no block bytes: last-resort + stall cooldown (not a stall disconnect).
pub fn note_dead_without_block_bytes(
    book: &mut AddrMan,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr: rbitcoin_net::NetAddr,
    first_data_ms: u64,
    now: Instant,
) {
    if first_data_ms != 0 {
        return;
    }
    book.note_connect_failed_addr(addr, false);
    if !addr.socket_addr().is_some_and(|s| s.ip().is_unspecified()) {
        addr_cooldown.insert(addr, now + STALL_ADDR_COOLDOWN);
    }
}

/// Misbehavior-threshold death. Cools the dial even after a block body was counted.
pub fn note_misbehavior_dead(
    book: &mut AddrMan,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr: rbitcoin_net::NetAddr,
    now: Instant,
) {
    book.note_connect_failed_addr(addr, false);
    if !addr.socket_addr().is_some_and(|s| s.ip().is_unspecified()) {
        addr_cooldown.insert(addr, now + STALL_ADDR_COOLDOWN);
    }
}

/// Disconnect at most one peer that has block getdata already on the socket
/// and is not delivering.
///
/// Quiet means no socket bytes at all for `stall`. A peer with nothing
/// assigned is not quiet. One quiet peer is disconnected even when every
/// on-wire peer is quiet, so a silent set cannot hold the slots forever.
///
/// A peer that keeps sending but has no block progress, and has not moved
/// a body-sized chunk of the stream since that progress, is withholding.
/// That peer is left alone while anyone else is delivering blocks. When
/// every on-wire peer is withholding, one is disconnected.
///
/// The window opens when the first getdata of an empty window is written.
/// Hashes still queued in the writer do not start it. Idle time before that
/// write does not count. A later getdata write while any of those hashes
/// are still outstanding does not refresh the window. Draining the last
/// outstanding hash disarms it. Headers and pings are socket bytes, not
/// block progress.
///
/// Stalled addresses enter a cooldown so redial does not immediately re-open
/// the same host under a new peer id (log spam + wasted slots).
///
/// A manual (`--connect`) peer is kept, as in Core (bitcoin/bitcoin#34743).
/// Its block requests are released and it is sent no block getdata for
/// [`MANUAL_PEER_BLOCK_DOWNLOAD_COOLDOWN`] on the node clock.
///
/// The status thread sends that shutdown without this lock. The coordination
/// loop records the kick and releases in-flight blocks when the task ends.
/// This lock-holding form is what the stall tests drive.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn disconnect_stalled_block_peers(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr_strikes: &mut HashMap<NetAddr, u8>,
    now: Instant,
    stall: Duration,
    clock: &rbitcoin_consensus::NodeClock,
) -> Vec<bitcoin::BlockHash> {
    disconnect_stalled_block_peers_at(
        slots,
        inflight,
        body,
        addr_cooldown,
        addr_strikes,
        now,
        stall,
        ibd_mono_ms(),
        clock.now_secs(),
    )
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn disconnect_stalled_block_peers_at(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr_strikes: &mut HashMap<NetAddr, u8>,
    now: Instant,
    stall: Duration,
    now_ms: u64,
    now_secs: u64,
) -> Vec<bitcoin::BlockHash> {
    let stall = stall.max(Duration::from_secs(30));
    let stall_ms = stall.as_millis() as u64;
    let mut on_wire = 0usize;
    let mut quiet: Vec<(usize, usize, NetAddr, u64)> = Vec::new();
    let mut withholding: Vec<(usize, usize, NetAddr, u64)> = Vec::new();
    for s in slots.iter() {
        if !s.alive || s.in_flight.is_empty() {
            continue;
        }
        if s.getdata_wire.unwritten() >= s.in_flight.len() {
            continue;
        }
        on_wire += 1;
        let row = (
            s.id,
            s.in_flight.len(),
            s.net,
            s.bytes_rx_total.load(Ordering::Relaxed),
        );
        if super::peer_io::getdata_on_wire_quiet(s, now_ms, stall_ms) {
            quiet.push(row);
        } else if withholding_blocks(s, now_ms, stall_ms) {
            withholding.push(row);
        }
    }
    let picked = if !quiet.is_empty() {
        Some(("quiet", quiet.remove(0)))
    } else if on_wire > 0 && withholding.len() == on_wire {
        Some(("no block bytes", withholding.remove(0)))
    } else {
        None
    };
    let Some((why, (id, n_work, addr, stream))) = picked else {
        return Vec::new();
    };
    if let Some(s) = slots
        .iter_mut()
        .find(|s| s.id == id && s.conn_type == PeerConnType::Manual)
    {
        let cool = MANUAL_PEER_BLOCK_DOWNLOAD_COOLDOWN.as_secs();
        info!(
            "ibd: Pausing block downloads from stalling manual peer={id} for {cool} seconds ({addr} {why}, {stall:?}, {n_work} in-flight, stream={stream})"
        );
        let owed = s.pause_block_download(now_secs.saturating_add(cool));
        return release_block_requests(inflight, body, id, owed);
    }
    let mut freed = Vec::new();
    let cool = record_stall_kick(addr_cooldown, addr_strikes, addr, now);
    warn!(
        "ibd: peer[{id}] {addr} {why} ({stall:?}, {n_work} in-flight, stream={stream}) — disconnect + reassign (cooldown {cool:?})"
    );
    if let Some(s) = slots.iter_mut().find(|s| s.id == id) {
        let _ = s.cmd_tx.send(PeerCmd::Shutdown);
        s.task.abort();
    }
    freed.extend(release_peer_block_work(slots, inflight, body, id));
    freed
}

/// Getdata is on the wire, block progress is stale, and the stream has not
/// moved a body-sized chunk since that progress.
#[doc(hidden)]
pub fn withholding_blocks(slot: &PeerSlot, now_ms: u64, stall_ms: u64) -> bool {
    if !super::peer_io::getdata_on_wire_stalled(slot, now_ms, stall_ms) {
        return false;
    }
    let streamed = slot
        .bytes_rx_total
        .load(Ordering::Relaxed)
        .saturating_sub(slot.rate.bytes_at_progress);
    streamed < PROGRESS_STEP
}

/// Disconnect at most one **clear quarter-median outlier** (warm-up + cluster gate
/// + wall-clock hysteresis + kick gap). Updates `suspect` / `last_kick_ms`.
///
/// Absolute stall ([`disconnect_stalled_block_peers`]) remains the zero-progress
/// floor; this only cuts peers that keep making slow progress while the bulk
/// is dramatically faster.
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn disconnect_relative_slow_block_peers(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr_strikes: &mut HashMap<NetAddr, u8>,
    now: Instant,
    book: &AddrMan,
    suspect: &mut Option<(usize, u64)>,
    last_kick_ms: &mut u64,
) -> Vec<bitcoin::BlockHash> {
    disconnect_relative_slow_block_peers_at(
        slots,
        inflight,
        body,
        addr_cooldown,
        addr_strikes,
        now,
        book,
        suspect,
        last_kick_ms,
        ibd_mono_ms(),
    )
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn disconnect_relative_slow_block_peers_at(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    body: &mut super::body::BodyPresence,
    addr_cooldown: &mut HashMap<NetAddr, Instant>,
    addr_strikes: &mut HashMap<NetAddr, u8>,
    now: Instant,
    book: &AddrMan,
    suspect: &mut Option<(usize, u64)>,
    last_kick_ms: &mut u64,
    now_ms: u64,
) -> Vec<bitcoin::BlockHash> {
    if !relative_slow_global_warmup_at(slots, now_ms) {
        *suspect = None;
        return Vec::new();
    }
    if !replacement_available(book, slots, addr_cooldown, now) {
        *suspect = None;
        return Vec::new();
    }
    let alive = slots.iter().filter(|s| s.alive).count();
    let min_samples = relative_slow_min_samples(alive);
    let samples = mature_relative_slow_samples(slots, now_ms);
    if samples.len() < min_samples {
        *suspect = None;
        return Vec::new();
    }
    let (kick, next_suspect) =
        relative_slow_with_hysteresis(&samples, min_samples, now_ms, *suspect, *last_kick_ms);
    *suspect = next_suspect;
    let Some(id) = kick else {
        return Vec::new();
    };
    let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
        *suspect = None;
        return Vec::new();
    };
    let addr = slot.net;
    let n_work = slot.in_flight.len();
    let bps = samples
        .iter()
        .find(|s| s.peer_id == id)
        .map(|s| s.bps)
        .unwrap_or(0);
    let mut bps_list: Vec<u64> = samples
        .iter()
        .filter(|s| s.bps > 0)
        .map(|s| s.bps)
        .collect();
    bps_list.sort_unstable();
    let med = median_u64(&bps_list);
    let lo = bps_list.first().copied().unwrap_or(0);
    let hi = bps_list.last().copied().unwrap_or(0);
    let cool = record_stall_kick(addr_cooldown, addr_strikes, addr, now);
    warn!(
        "ibd: peer[{id}] {addr} relative-slow (bps={bps} med={med} spread={lo}..{hi}, {n_work} in-flight) — disconnect + reassign (cooldown {cool:?})"
    );
    if let Some(s) = slots.iter_mut().find(|s| s.id == id) {
        let _ = s.cmd_tx.send(PeerCmd::Shutdown);
        s.task.abort();
    }
    let freed = release_peer_block_work(slots, inflight, body, id);
    *suspect = None;
    *last_kick_ms = now_ms;
    freed
}
