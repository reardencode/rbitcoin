//! Peer dial, header request, stall disconnect / cooldown.

use super::peer_io::{ibd_mono_ms, spawn_peer, PeerCmd, PeerEventSinks, PeerSlot};
use super::rate::RELSLOW_ACTIVE_MS;
use crate::chain::ChainHub;
use crate::error::NetError;
use crate::peers::{trying_connection_log, PeerConnType};
use crate::seeds::AddrMan;
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::BlockHash;
use rbitcoin_log::{debug, error, warn};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long to avoid redialing an address after a stall disconnect.
pub(crate) const STALL_ADDR_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// max/min bps within this factor → tight pack, never relative-disconnect.
pub(crate) const RELATIVE_SLOW_CLUSTER_SPREAD: u64 = 2;
/// Disconnect only if peer bps ≤ median / this (default 2 → half median).
pub(crate) const RELATIVE_SLOW_OUTLIER_RATIO: u64 = 2;
/// Target mature peers before relative rule runs (full IBD peer set).
pub(crate) const RELATIVE_SLOW_MIN_SAMPLES: usize = 8;
/// Floor when fewer than 16 alive peers.
pub(crate) const RELATIVE_SLOW_MIN_SAMPLES_FLOOR: usize = 6;
/// Global IBD download age before any relative disconnect (ms).
pub(crate) const RELATIVE_SLOW_GLOBAL_WARMUP_MS: u64 = 60_000;

/// One mature speed sample for relative-slow classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelativeSlowSample {
    pub peer_id: usize,
    pub bps: u64,
    pub has_inflight: bool,
}

/// Minimum mature samples required given how many peers are alive.
pub(crate) fn relative_slow_min_samples(alive: usize) -> usize {
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
pub(crate) fn median_u64(sorted: &[u64]) -> u64 {
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

/// Pure relative-slow pick: at most one peer id that is a clear half-median
/// outlier with inflight work. Empty when pack is tight, thin, or no outlier.
///
/// Gate A: `max_bps <= min_bps * CLUSTER_SPREAD` → none.
/// Gate B: `bps * OUTLIER_RATIO <= median` and `has_inflight` → worst bps.
pub(crate) fn relative_slow_pick(
    samples: &[RelativeSlowSample],
    min_samples: usize,
) -> Option<usize> {
    if samples.len() < min_samples {
        return None;
    }
    let mut bps: Vec<u64> = samples.iter().map(|s| s.bps).collect();
    bps.sort_unstable();
    let lo = bps[0];
    let hi = bps[bps.len() - 1];
    if lo == 0 {
        if hi == 0 {
            return None;
        }
        // Zero bps with positive hi is extreme spread; allow Gate B.
    } else if hi <= lo.saturating_mul(RELATIVE_SLOW_CLUSTER_SPREAD) {
        return None;
    }
    let med = median_u64(&bps);
    if med == 0 {
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

/// Two-tick hysteresis: first fail marks suspect; second consecutive same id
/// returns disconnect. Different pick resets mark to the new id.
pub(crate) fn relative_slow_with_hysteresis(
    samples: &[RelativeSlowSample],
    min_samples: usize,
    prev_suspect: Option<usize>,
) -> (Option<usize>, Option<usize>) {
    match relative_slow_pick(samples, min_samples) {
        Some(id) if prev_suspect == Some(id) => (Some(id), None),
        Some(id) => (None, Some(id)),
        None => (None, None),
    }
}

/// Build mature relative-slow samples from live slots (`active_ms` floor).
pub(crate) fn mature_relative_slow_samples(slots: &[PeerSlot]) -> Vec<RelativeSlowSample> {
    let mut out = Vec::new();
    for s in slots {
        if !s.alive {
            continue;
        }
        if s.rate.active_ms < RELSLOW_ACTIVE_MS {
            continue;
        }
        let Some(bps) = s.rate.bps() else {
            continue;
        };
        out.push(RelativeSlowSample {
            peer_id: s.id,
            bps,
            has_inflight: !s.in_flight.is_empty(),
        });
    }
    out
}

/// Earliest first-data mono ms among alive peers (0 = no download yet).
pub(crate) fn global_first_block_ms(slots: &[PeerSlot]) -> u64 {
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
pub(crate) fn relative_slow_global_warmup_ok(slots: &[PeerSlot]) -> bool {
    let first = global_first_block_ms(slots);
    if first == 0 {
        return false;
    }
    ibd_mono_ms().saturating_sub(first) >= RELATIVE_SLOW_GLOBAL_WARMUP_MS
}

/// Classified dial failure for [`AddrMan`] flag updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialFailKind {
    /// TCP/timeout/IO — `FAILED_LAST_CONNECT`.
    Network,
    /// No BIP324 v2 — `INCOMPATIBLE`.
    Incompatible,
}

fn classify_dial_err(e: &NetError) -> DialFailKind {
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
pub(crate) struct DialBatchResult {
    pub slots: Vec<PeerSlot>,
    pub failed: Vec<(SocketAddr, DialFailKind)>,
}

/// Dial up to `count` ranked candidates from `book` (excludes `already` + cooldown).
pub(crate) async fn dial_batch(
    book: &AddrMan,
    next_id: &AtomicUsize,
    count: usize,
    mut already: HashSet<SocketAddr>,
    magic: Magic,
    local_addr: SocketAddr,
    tip_h: Option<u32>,
    sinks: PeerEventSinks,
    connect_timeout: Duration,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> DialBatchResult {
    let mut out = DialBatchResult {
        slots: Vec::new(),
        failed: Vec::new(),
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

    let candidates = book.take_dial_candidates(book.len().max(count), &already);
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
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let sinks = sinks.clone();
        debug!(
            "{}",
            trying_connection_log(PeerConnType::OutboundFullRelay, addr)
        );
        handles.push(tokio::spawn(async move {
            let fut = spawn_peer(id, addr, magic, local_addr, tip_h, sinks);
            match tokio::time::timeout(connect_timeout, fut).await {
                Ok(Ok(slot)) => Ok(slot),
                Ok(Err(e)) => {
                    let kind = classify_dial_err(&e);
                    Err((id, addr, kind, e.to_string()))
                }
                Err(_) => Err((
                    id,
                    addr,
                    DialFailKind::Network,
                    format!("connect timeout ({connect_timeout:?})"),
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

/// Apply dial successes / failures to the peer book.
pub(crate) fn apply_dial_result(book: &mut AddrMan, result: &DialBatchResult) {
    for s in &result.slots {
        book.note_connected(s.addr);
    }
    for &(addr, kind) in &result.failed {
        book.note_connect_failed(addr, kind == DialFailKind::Incompatible);
    }
}

pub(crate) fn request_headers(
    slots: &[PeerSlot],
    hub: &ChainHub,
    seq: &mut u32,
    // Best hashes on the IBD work path (newest first preferred). When tip
    // lags archive, store locators alone re-fetch the same 2000-header window.
    work_tips: &[BlockHash],
) -> Result<bool, NetError> {
    let alive: Vec<usize> = slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
    if alive.is_empty() {
        return Ok(false);
    }
    let peer = alive[(*seq as usize) % alive.len()];
    *seq = seq.saturating_add(1);
    request_headers_from(slots, peer, hub, seq, work_tips)
}

pub(crate) fn request_headers_from(
    slots: &[PeerSlot],
    peer: usize,
    hub: &ChainHub,
    _seq: &mut u32,
    work_tips: &[BlockHash],
) -> Result<bool, NetError> {
    let Some(s) = slots.iter().find(|s| s.id == peer && s.alive) else {
        return Ok(false);
    };
    let locator = ibd_header_locator(hub, work_tips)?;
    Ok(s.cmd_tx.send(PeerCmd::GetHeaders { locator }).is_ok())
}

/// Locator for IBD getheaders: prefer the **work-path tip** (highest ordered /
/// archived hash) ahead of the confirmed store tip.
///
/// Signet bug: with only `query.locator_hashes()` (confirmed tip), when archive
/// led tip by a full headers window (~2000), peers re-served that same window
/// forever; we marked `headers_done` and exited IBD at height 2000 while
/// `max_peer_height` was still ~313k.
pub(crate) fn ibd_header_locator(
    hub: &ChainHub,
    work_tips: &[BlockHash],
) -> Result<Vec<BlockHash>, NetError> {
    let mut locator = Vec::with_capacity(32);
    for h in work_tips {
        if !locator.contains(h) {
            locator.push(*h);
        }
        if locator.len() >= 8 {
            break;
        }
    }
    if let Some(t) = hub.tip_hash() {
        if !locator.contains(&t) {
            locator.push(t);
        }
    }
    let rest = hub
        .query
        .locator_hashes()
        .map_err(|e| NetError::Consensus(e.to_string()))?;
    for h in rest {
        if !locator.contains(&h) {
            locator.push(h);
        }
        if locator.len() >= crate::codec::MAX_LOCATOR_SZ {
            break;
        }
    }
    if locator.is_empty() {
        locator.push(BlockHash::from_byte_array([0u8; 32]));
    }
    Ok(locator)
}

pub(crate) fn release_peer_block_work(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    peer: usize,
) {
    if let Some(s) = slots.iter_mut().find(|s| s.id == peer) {
        s.alive = false;
        for h in s.in_flight.drain() {
            let empty = inflight
                .get_mut(&h)
                .map(|e| e.remove_peer(peer))
                .unwrap_or(false);
            if empty {
                inflight.remove(&h);
            }
        }
    }
}

/// Addrs we must not dial: currently connected/slot-held + still-cooling stall bans.
pub(crate) fn dial_blocked_addrs(
    slots: &[PeerSlot],
    cooldown: &HashMap<SocketAddr, Instant>,
    now: Instant,
) -> HashSet<SocketAddr> {
    let mut blocked: HashSet<SocketAddr> = slots.iter().map(|s| s.addr).collect();
    for (&addr, &until) in cooldown {
        if until > now {
            blocked.insert(addr);
        }
    }
    blocked
}

pub(crate) fn expire_addr_cooldown(cooldown: &mut HashMap<SocketAddr, Instant>, now: Instant) {
    cooldown.retain(|_, until| *until > now);
}

/// One stall rule: if a peer has outstanding block getdata and no **block**
/// progress for `stall`, disconnect it and free its work for reassignment.
///
/// Progress = payload bytes (atomic), complete `block`, or `notfound`.
/// Headers/pings do not count. Clock resets when we issue new getdata.
///
/// Stalled addresses enter a cooldown so redial does not immediately re-open
/// the same host under a new peer id (log spam + wasted slots).
pub(crate) fn disconnect_stalled_block_peers(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    addr_cooldown: &mut HashMap<SocketAddr, Instant>,
    now: Instant,
    stall: Duration,
) {
    disconnect_stalled_block_peers_at(slots, inflight, addr_cooldown, now, stall, ibd_mono_ms());
}

pub(crate) fn disconnect_stalled_block_peers_at(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    addr_cooldown: &mut HashMap<SocketAddr, Instant>,
    now: Instant,
    stall: Duration,
    now_ms: u64,
) {
    let stall = stall.max(Duration::from_secs(30));
    let stall_ms = stall.as_millis() as u64;
    let stalled_peers: Vec<(usize, usize, SocketAddr)> = slots
        .iter()
        .filter(|s| s.alive && !s.in_flight.is_empty())
        .filter(|s| s.rate.stalled(now_ms, stall_ms, true))
        .map(|s| (s.id, s.in_flight.len(), s.addr))
        .collect();
    for (id, n_work, addr) in stalled_peers {
        warn!(
            "ibd: peer[{id}] {addr} stalled (no block progress for {stall:?}, {n_work} in-flight) — disconnect + reassign (cooldown {STALL_ADDR_COOLDOWN:?})"
        );
        addr_cooldown.insert(addr, now + STALL_ADDR_COOLDOWN);
        if let Some(s) = slots.iter_mut().find(|s| s.id == id) {
            let _ = s.cmd_tx.send(PeerCmd::Shutdown);
            s.task.abort();
        }
        release_peer_block_work(slots, inflight, id);
    }
}

/// Disconnect at most one **clear half-median outlier** (warm-up + cluster gate
/// + two-tick hysteresis). Updates `suspect` for hysteresis across ticks.
///
/// Absolute stall ([`disconnect_stalled_block_peers`]) remains the zero-progress
/// floor; this only cuts peers that keep making slow progress while the pack is
/// dramatically faster.
pub(crate) fn disconnect_relative_slow_block_peers(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<bitcoin::BlockHash, super::state::InflightReq>,
    addr_cooldown: &mut HashMap<SocketAddr, Instant>,
    now: Instant,
    suspect: &mut Option<usize>,
) {
    if !relative_slow_global_warmup_ok(slots) {
        *suspect = None;
        return;
    }
    let alive = slots.iter().filter(|s| s.alive).count();
    let min_samples = relative_slow_min_samples(alive);
    let samples = mature_relative_slow_samples(slots);
    if samples.len() < min_samples {
        *suspect = None;
        return;
    }
    let (kick, next_suspect) = relative_slow_with_hysteresis(&samples, min_samples, *suspect);
    *suspect = next_suspect;
    let Some(id) = kick else {
        return;
    };
    let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
        *suspect = None;
        return;
    };
    let addr = slot.addr;
    let n_work = slot.in_flight.len();
    let bps = samples
        .iter()
        .find(|s| s.peer_id == id)
        .map(|s| s.bps)
        .unwrap_or(0);
    let mut bps_list: Vec<u64> = samples.iter().map(|s| s.bps).collect();
    bps_list.sort_unstable();
    let med = median_u64(&bps_list);
    let lo = bps_list.first().copied().unwrap_or(0);
    let hi = bps_list.last().copied().unwrap_or(0);
    warn!(
        "ibd: peer[{id}] {addr} relative-slow (bps={bps} med={med} spread={lo}..{hi}, {n_work} in-flight) — disconnect + reassign (cooldown {STALL_ADDR_COOLDOWN:?})"
    );
    addr_cooldown.insert(addr, now + STALL_ADDR_COOLDOWN);
    if let Some(s) = slots.iter_mut().find(|s| s.id == id) {
        let _ = s.cmd_tx.send(PeerCmd::Shutdown);
        s.task.abort();
    }
    release_peer_block_work(slots, inflight, id);
    *suspect = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;

    fn addr(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, o)), 8333)
    }

    fn dummy_slot(id: usize, a: SocketAddr, alive: bool) -> PeerSlot {
        let (cmd_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        // JoinHandle without a running runtime: abort on Drop is still safe.
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: a,
            cmd_tx,
            in_flight: HashSet::new(),
            peer_height: 0,
            connected_ms: 0,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            alive,
            task,
        }
    }

    #[test]
    fn classify_dial_err_network_vs_incompatible() {
        assert_eq!(
            classify_dial_err(&NetError::V1Peer),
            DialFailKind::Incompatible
        );
        assert_eq!(
            classify_dial_err(&NetError::Bip324("x".into())),
            DialFailKind::Incompatible
        );
        assert_eq!(
            classify_dial_err(&NetError::Protocol("no v2 support")),
            DialFailKind::Incompatible
        );
        assert_eq!(
            classify_dial_err(&NetError::Protocol("missing verack")),
            DialFailKind::Incompatible
        );
        assert_eq!(
            classify_dial_err(&NetError::Protocol("version too old")),
            DialFailKind::Incompatible
        );
        assert_eq!(classify_dial_err(&NetError::Timeout), DialFailKind::Network);
        assert_eq!(
            classify_dial_err(&NetError::Disconnected),
            DialFailKind::Network
        );
        assert_eq!(
            classify_dial_err(&NetError::Protocol("ban score")),
            DialFailKind::Network
        );
    }

    #[test]
    fn dial_blocked_and_cooldown_expiry() {
        let now = Instant::now();
        let s = dummy_slot(1, addr(1), true);
        let mut cooldown = HashMap::new();
        cooldown.insert(addr(2), now + Duration::from_secs(60));
        cooldown.insert(addr(3), now - Duration::from_secs(1)); // expired
        let blocked = dial_blocked_addrs(&[s], &cooldown, now);
        assert!(blocked.contains(&addr(1)));
        assert!(blocked.contains(&addr(2)));
        assert!(!blocked.contains(&addr(3)));

        expire_addr_cooldown(&mut cooldown, now);
        assert!(cooldown.contains_key(&addr(2)));
        assert!(!cooldown.contains_key(&addr(3)));
    }

    fn samp(id: usize, bps: u64, inflight: bool) -> RelativeSlowSample {
        RelativeSlowSample {
            peer_id: id,
            bps,
            has_inflight: inflight,
        }
    }

    #[test]
    fn relative_slow_pick_respects_cluster_and_outlier() {
        // Thin samples
        assert_eq!(relative_slow_pick(&[samp(0, 1_000_000, true)], 8), None);
        // Tight pack — slowest is still in-cluster
        let tight = [
            samp(0, 1_000_000, true),
            samp(1, 1_100_000, true),
            samp(2, 1_200_000, true),
            samp(3, 900_000, true),
            samp(4, 1_050_000, true),
            samp(5, 1_000_000, true),
            samp(6, 1_080_000, true),
            samp(7, 950_000, true),
        ];
        assert_eq!(relative_slow_pick(&tight, 8), None);

        // Mild spread, slowest > median/2
        let mild = [
            samp(0, 2_000_000, true),
            samp(1, 1_500_000, true),
            samp(2, 1_400_000, true),
            samp(3, 1_100_000, true),
            samp(4, 1_600_000, true),
            samp(5, 1_550_000, true),
            samp(6, 1_450_000, true),
            samp(7, 1_300_000, true),
        ];
        assert_eq!(relative_slow_pick(&mild, 8), None);

        // Clear half-median outlier
        let outlier = [
            samp(0, 2_000_000, true),
            samp(1, 1_900_000, true),
            samp(2, 1_800_000, true),
            samp(3, 800_000, true), // ≤ med/2
            samp(4, 1_850_000, true),
            samp(5, 1_950_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        assert_eq!(relative_slow_pick(&outlier, 8), Some(3));

        // Outlier without inflight is not kicked
        let no_work = [
            samp(0, 2_000_000, true),
            samp(1, 1_900_000, true),
            samp(2, 1_800_000, true),
            samp(3, 800_000, false),
            samp(4, 1_850_000, true),
            samp(5, 1_950_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        assert_eq!(relative_slow_pick(&no_work, 8), None);

        // Two outliers → worst (lowest bps)
        let two = [
            samp(0, 2_000_000, true),
            samp(1, 1_900_000, true),
            samp(2, 1_800_000, true),
            samp(3, 800_000, true),
            samp(4, 400_000, true),
            samp(5, 1_950_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        assert_eq!(relative_slow_pick(&two, 8), Some(4));
    }

    #[test]
    fn relative_slow_hysteresis_two_ticks() {
        let outlier = [
            samp(0, 2_000_000, true),
            samp(1, 1_900_000, true),
            samp(2, 1_800_000, true),
            samp(3, 800_000, true),
            samp(4, 1_850_000, true),
            samp(5, 1_950_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        let (kick0, sus0) = relative_slow_with_hysteresis(&outlier, 8, None);
        assert_eq!(kick0, None);
        assert_eq!(sus0, Some(3));
        let (kick1, sus1) = relative_slow_with_hysteresis(&outlier, 8, sus0);
        assert_eq!(kick1, Some(3));
        assert_eq!(sus1, None);
        // Clear when pack tightens
        let tight = [
            samp(0, 1_000_000, true),
            samp(1, 1_100_000, true),
            samp(2, 1_200_000, true),
            samp(3, 900_000, true),
            samp(4, 1_050_000, true),
            samp(5, 1_000_000, true),
            samp(6, 1_080_000, true),
            samp(7, 950_000, true),
        ];
        let (kick2, sus2) = relative_slow_with_hysteresis(&tight, 8, Some(3));
        assert_eq!(kick2, None);
        assert_eq!(sus2, None);
    }

    #[test]
    fn relative_slow_min_samples_scales() {
        assert_eq!(relative_slow_min_samples(16), 8);
        assert_eq!(relative_slow_min_samples(10), 6); // max(6, 5)=6
        assert_eq!(relative_slow_min_samples(4), 4); // min(alive)
        assert_eq!(relative_slow_min_samples(8), 6);
    }

    #[test]
    fn apply_dial_result_updates_book() {
        let mut book = AddrMan::new();
        let good = addr(5);
        let bad = addr(6);
        let inc = addr(7);
        let slot = dummy_slot(0, good, true);
        let result = DialBatchResult {
            slots: vec![slot],
            failed: vec![
                (bad, DialFailKind::Network),
                (inc, DialFailKind::Incompatible),
            ],
        };
        apply_dial_result(&mut book, &result);
        assert!(book.flags(&good).has_connected());
        assert!(book.flags(&bad).failed_last_connect());
        assert!(book.flags(&inc).is_incompatible());
    }

    #[test]
    fn release_peer_block_work_clears_inflight() {
        let a = addr(9);
        let mut slot = dummy_slot(3, a, true);
        let h = BlockHash::from_byte_array([7u8; 32]);
        slot.in_flight.insert(h);
        let mut inflight = HashMap::new();
        inflight.insert(h, super::super::state::InflightReq::new(3));
        release_peer_block_work(&mut [slot], &mut inflight, 3);
        assert!(inflight.is_empty());
    }

    #[test]
    fn dial_batch_empty_count_or_book() {
        let book = AddrMan::new();
        let next = AtomicUsize::new(0);
        let (body_tx, _body_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::unbounded_channel();
        let sinks = PeerEventSinks {
            body: body_tx,
            ctrl: ctrl_tx,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(dial_batch(
            &book,
            &next,
            0,
            HashSet::new(),
            Magic::REGTEST,
            addr(1),
            Some(0),
            sinks.clone(),
            Duration::from_millis(50),
            None,
        ));
        assert!(r.slots.is_empty() && r.failed.is_empty());
        let r2 = rt.block_on(dial_batch(
            &book,
            &next,
            4,
            HashSet::new(),
            Magic::REGTEST,
            addr(1),
            None,
            sinks,
            Duration::from_millis(50),
            None,
        ));
        assert!(r2.slots.is_empty() && r2.failed.is_empty());
    }

    #[test]
    fn disconnect_stalled_after_30s_without_rx() {
        let a = addr(11);
        let mut slot = dummy_slot(5, a, true);
        let h = BlockHash::from_byte_array([0xee; 32]);
        slot.in_flight.insert(h);
        slot.rate.note_work_started(0);
        let mut inflight = HashMap::new();
        inflight.insert(h, super::super::state::InflightReq::new(5));
        let mut cooldown = HashMap::new();
        disconnect_stalled_block_peers_at(
            std::slice::from_mut(&mut slot),
            &mut inflight,
            &mut cooldown,
            Instant::now(),
            Duration::from_secs(30),
            30_001,
        );
        assert!(cooldown.contains_key(&a));
        assert!(inflight.is_empty());
    }

    #[test]
    fn disconnect_stalled_not_when_rx_recent() {
        let a = addr(12);
        let mut slot = dummy_slot(6, a, true);
        let h = BlockHash::from_byte_array([0xee; 32]);
        slot.in_flight.insert(h);
        slot.rate.note_work_started(0);
        slot.rate.note_rx(25_000);
        let mut inflight = HashMap::new();
        inflight.insert(h, super::super::state::InflightReq::new(6));
        let mut cooldown = HashMap::new();
        disconnect_stalled_block_peers_at(
            std::slice::from_mut(&mut slot),
            &mut inflight,
            &mut cooldown,
            Instant::now(),
            Duration::from_secs(30),
            45_000,
        );
        assert!(cooldown.get(&a).is_none());
        assert!(inflight.contains_key(&h));
    }

    #[test]
    fn disconnect_stalled_releases_and_cools_addr() {
        let now = Instant::now();
        let mut cooldown = HashMap::new();
        disconnect_stalled_block_peers(
            &mut [dummy_slot(7, addr(13), true)],
            &mut HashMap::new(),
            &mut cooldown,
            now,
            Duration::from_secs(30),
        );
        assert!(cooldown.get(&addr(13)).is_none());
    }

    #[test]
    fn request_headers_no_alive_returns_false() {
        use rbitcoin_consensus::{ChainParams, Milestone};
        use rbitcoin_query::Query;
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-dial-hdr-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let q = Query::open_or_create(dir.join("store")).unwrap();
        let hub = crate::chain::ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        let mut seq = 0u32;
        assert!(!request_headers(&[], &hub, &mut seq, &[]).unwrap());
        let mut dead = dummy_slot(1, addr(1), false);
        dead.alive = false;
        assert!(!request_headers_from(&[dead], 1, &hub, &mut seq, &[]).unwrap());
        // Locator alone (empty work tips + no tip) still returns genesis zero.
        let loc = ibd_header_locator(&hub, &[]).unwrap();
        assert!(!loc.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// median / pick edge matrix + mature-sample early exits + relative-slow early exits.
    #[test]
    fn relative_slow_pure_edges_and_mature_sample_filters() {
        assert_eq!(median_u64(&[]), 0);
        assert_eq!(median_u64(&[7]), 7);
        assert_eq!(median_u64(&[2, 8]), 5);
        assert_eq!(median_u64(&[1, 2, 3]), 2);
        assert_eq!(relative_slow_min_samples(0), RELATIVE_SLOW_MIN_SAMPLES);

        // All-zero bps → Gate A none.
        let zeros: Vec<_> = (0..8).map(|i| samp(i, 0, true)).collect();
        assert_eq!(relative_slow_pick(&zeros, 8), None);
        // Zero lo with positive hi: allow Gate B; pick lowest inflight outlier.
        let zero_and_fast = [
            samp(0, 0, true),
            samp(1, 2_000_000, true),
            samp(2, 1_900_000, true),
            samp(3, 1_800_000, true),
            samp(4, 1_850_000, true),
            samp(5, 1_950_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        assert_eq!(relative_slow_pick(&zero_and_fast, 8), Some(0));

        // Equal worst bps → lower peer_id wins.
        let tie = [
            samp(5, 400_000, true),
            samp(2, 400_000, true),
            samp(0, 2_000_000, true),
            samp(1, 1_900_000, true),
            samp(3, 1_800_000, true),
            samp(4, 1_850_000, true),
            samp(6, 1_880_000, true),
            samp(7, 1_920_000, true),
        ];
        assert_eq!(relative_slow_pick(&tie, 8), Some(2));

        // Mature filters: dead / young active_ms / no sample.
        let dead = {
            let mut s = dummy_slot(0, addr(20), false);
            s.rate.sample(0, 0, true);
            s.rate
                .sample(RELSLOW_ACTIVE_MS, RELSLOW_ACTIVE_MS * 1_000, true);
            s
        };
        let young = {
            let mut s = dummy_slot(2, addr(22), true);
            s.rate.sample(0, 0, true);
            s.rate.sample(5_000, 50_000_000, true);
            s
        };
        let samples = mature_relative_slow_samples(&[dead, young]);
        assert!(samples.iter().all(|s| s.peer_id != 0 && s.peer_id != 2));

        assert_eq!(global_first_block_ms(&[]), 0);
        let a_empty = dummy_slot(10, addr(30), true);
        assert_eq!(global_first_block_ms(std::slice::from_ref(&a_empty)), 0);
        let b_dead = {
            let mut s = dummy_slot(11, addr(31), true);
            s.alive = false;
            s.first_data_ms = 5;
            s
        };
        assert_eq!(global_first_block_ms(std::slice::from_ref(&b_dead)), 0);
        let a = {
            let mut s = dummy_slot(10, addr(30), true);
            s.first_data_ms = 42;
            s
        };
        let c = {
            let mut s = dummy_slot(12, addr(32), true);
            s.first_data_ms = 10;
            s
        };
        assert_eq!(global_first_block_ms(&[a, c]), 10);
        // Warmup fails when age since global first < 60s (typical unit-test process).
        let a2 = {
            let mut s = dummy_slot(10, addr(30), true);
            s.first_data_ms = 10;
            s
        };
        let warm = relative_slow_global_warmup_ok(std::slice::from_ref(&a2));
        if ibd_mono_ms().saturating_sub(10) < RELATIVE_SLOW_GLOBAL_WARMUP_MS {
            assert!(!warm);
        }

        // disconnect_relative_slow: fail warmup → clear suspect; thin samples → clear.
        let mut slots = [dummy_slot(1, addr(40), true)];
        let mut inflight = HashMap::new();
        let mut cooldown = HashMap::new();
        let mut suspect = Some(1usize);
        disconnect_relative_slow_block_peers(
            &mut slots,
            &mut inflight,
            &mut cooldown,
            Instant::now(),
            &mut suspect,
        );
        assert!(suspect.is_none());
        assert!(cooldown.is_empty());
    }

    #[test]
    fn mature_relative_slow_samples_uses_ewma_active_ms() {
        let h = BlockHash::from_byte_array([9u8; 32]);
        let mut young = dummy_slot(0, addr(50), true);
        young.rate.sample(0, 0, true);
        young.rate.sample(5_000, 50_000_000, true);
        young.in_flight.insert(h);
        assert!(young.rate.bps().is_some());
        assert!(young.rate.active_ms < RELSLOW_ACTIVE_MS);

        let mut mature = dummy_slot(1, addr(51), true);
        mature.rate.sample(0, 0, true);
        mature
            .rate
            .sample(RELSLOW_ACTIVE_MS, RELSLOW_ACTIVE_MS * 10_000, true);
        mature.in_flight.insert(h);

        let samples = mature_relative_slow_samples(&[young, mature]);
        assert!(samples.iter().all(|s| s.peer_id != 0));
        assert!(samples.iter().any(|s| s.peer_id == 1));
    }
}
