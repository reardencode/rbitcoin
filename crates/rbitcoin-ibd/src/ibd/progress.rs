//! Work-chain progress snapshot, percent helpers, and rate/ETA for IBD logs.
//!
//! The operator `ibd: progress` line reports tip pace and in-RAM block-queue
//! occupancy. It does **not** print a retired dual-track Class A high-water or
//! "archive lead" (`arch_hwm` / `lead=`).

use super::body::BodyPresence;
use super::state::HeightOccupants;
use bitcoin::BlockHash;
use rbitcoin_net::chain::ChainHub;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cap status-tick hole walk so a huge missing header band cannot burn the loop.
#[doc(hidden)]
pub const TIP_HOLE_SCAN_MAX: u32 = 8192;

/// Work-chain progress for status / progress logs.
///
/// - `tip`: confirmed best-chain height
/// - `ready_hwm`: highest claim-ready / offered body height on the work path
///   (body queue densify bookkeeping; **not** printed on the progress line)
/// - `headers`: max peer-advertised / learned header height
/// - `tip_hole`: count of heights from tip+1 until the next **claim-ready**
///   body (body queue / pending wire only) — the fetch gap operators care about
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkChainProgress {
    pub tip: u32,
    pub ready_hwm: u32,
    pub headers: u32,
    pub tip_hole: usize,
}

/// Inputs for the pure `ibd: progress` line formatter (unit-tested).
#[derive(Clone, Debug)]
pub struct ProgressLineInput {
    pub pct: u32,
    pub tip: u32,
    /// Tip advance rate over the last sample window (blocks/s).
    pub tip_rate: f64,
    pub tip_hole: usize,
    pub peers: usize,
    /// Confirm pipeline depths already formatted (`ready=… scriptq… writeq…`).
    pub conf_q: String,
    pub txs: u64,
    pub horizon: u32,
    /// From [`TipRateTracker::eta_string`] (`eta=…` or `done`).
    pub eta: String,
    /// In-RAM block queue bytes / entry count (process heap wire payloads).
    pub bq_bytes: u64,
    pub bq_count: usize,
    /// Soft densify confirm-window target (block count for ~1 min at tip rate).
    pub bq_soft_stop: u32,
}

/// Build the `ibd: progress …` message body (no log level prefix).
///
/// Tip percent/rate, **fetch hole** (tip→next claim-ready body), peers, confirm
/// queues, txs, header horizon, tip-rate ETA, in-RAM block-queue occupancy.
/// `bq soft=n/win` is count vs 1-min confirm window at tip rate; `RAM=` is queue heap MiB.
/// Count is only in `soft=` (no redundant `n=`).
pub fn format_progress_line(i: &ProgressLineInput) -> String {
    let bq_mib = i.bq_bytes / (1024 * 1024);
    format!(
        "ibd: progress {}% tip={} ({}/s) hole={} peers={} {} txs={} horizon={} {} bq soft={}/{} RAM={}MiB",
        i.pct,
        i.tip,
        format_rate(i.tip_rate),
        i.tip_hole,
        i.peers,
        i.conf_q,
        i.txs,
        i.horizon,
        i.eta,
        i.bq_count,
        i.bq_soft_stop,
        bq_mib,
    )
}

/// True if this height does not need another getdata.
///
/// In hand: confirmed, matching BQ hash, or already taken onto loadq
/// (`H ≤ lookup_taken_hi`). Class A alone is not enough. Pending without
/// BQ is not in hand (zombie). Rejected is never in hand.
pub fn claim_ready(hub: &ChainHub, body: &mut BodyPresence, height: u32, hash: &BlockHash) -> bool {
    use bitcoin::hashes::Hash as _;
    if hub.has_block(hash) {
        return true;
    }
    if body.is_rejected(hash) {
        return false;
    }
    if hub.query.lookup_already_taken(height) {
        return true;
    }
    // Must be **this** hash at the height — first-wins BQ of a different block
    // is not claim-ready (mainnet tip+1 wrong-wire thrash / permanent hole).
    hub.query
        .block_queue_hash_at_height(height)
        .is_some_and(|h| h == hash.to_byte_array())
}

/// Count heights from tip+1 until the next in-hand body (fetch gap).
///
/// - Missing header on the work path → stop (cannot request further).
/// - Rejected tip+1 → stop (not a download gap; confirm is blacklisted).
/// - In hand (confirmed / BQ hash / taken onto loadq) → stop.
/// - Otherwise increment hole (needs getdata).
#[cfg(debug_assertions)]
pub fn tip_fetch_hole(
    hub: &ChainHub,
    height_to_hash: &impl HeightOccupants,
    body: &mut BodyPresence,
) -> usize {
    tip_fetch_hole_at(hub, hub.tip_height(), height_to_hash, body)
}

pub fn tip_fetch_hole_at(
    hub: &ChainHub,
    tip: Option<u32>,
    height_to_hash: &impl HeightOccupants,
    body: &mut BodyPresence,
) -> usize {
    let path_lo = match tip {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let limit = path_lo.saturating_add(TIP_HOLE_SCAN_MAX);
    let mut flags = Vec::new();
    for ht in path_lo..=limit {
        let Some(hash) = height_to_hash.occupant(ht) else {
            break;
        };
        if body.is_rejected(&hash) {
            break;
        }
        flags.push(claim_ready(hub, body, ht, &hash));
    }
    tip_hole_from_claim_ready(&flags)
}

/// Build a status snapshot for the ~5s operator tick.
#[cfg(debug_assertions)]
pub fn work_chain_progress(
    hub: &ChainHub,
    height_to_hash: &impl HeightOccupants,
    body: &mut BodyPresence,
    horizon: u32,
    max_ready_height: u32,
) -> WorkChainProgress {
    work_chain_progress_at(
        hub,
        hub.tip_height(),
        height_to_hash,
        body,
        horizon,
        max_ready_height,
    )
}

pub fn work_chain_progress_at(
    hub: &ChainHub,
    tip: Option<u32>,
    height_to_hash: &impl HeightOccupants,
    body: &mut BodyPresence,
    horizon: u32,
    max_ready_height: u32,
) -> WorkChainProgress {
    let tip_n = tip.unwrap_or(0);
    let tip_hole = tip_fetch_hole_at(hub, tip, height_to_hash, body);
    WorkChainProgress {
        tip: tip_n,
        ready_hwm: tip_n.max(max_ready_height),
        headers: tip_n.max(horizon),
        tip_hole,
    }
}

/// Numbers the 5s tick reads. No directory listing and no height-index lock.
pub struct ProgressPublished {
    pub tip: Option<u32>,
    pub txs: u64,
    pub sh_runs: usize,
    pub owned: rbitcoin_query::ProcessOwnedSizes,
}

pub fn read_progress_published(query: &rbitcoin_query::Query) -> ProgressPublished {
    ProgressPublished {
        tip: query.published_tip().map(|p| p.height),
        txs: query.tx_body_count(),
        sh_runs: query.published_scripthash_run_count(),
        owned: query.published_owned_sizes(),
    }
}

/// Confirmed tip as a percent of network/header horizon (0–100).
/// Denominator is max(our known headers, best peer-advertised tip).
pub fn ibd_pct(tip: u32, horizon: u32) -> u32 {
    let denom = horizon.max(tip).max(1);
    ((u64::from(tip) * 100) / u64::from(denom)) as u32
}

/// Half-life for the tip-rate EWMA used by ETA (seconds).
///
/// ~90s: recent IBD pace dominates (not the last hour of early empty blocks).
/// A single 5s spike only moves the estimate a few percent; a sustained regime
/// change is mostly reflected within ~5–6 minutes.
#[doc(hidden)]
pub const ETA_RATE_HALF_LIFE_SECS: f64 = 90.0;

/// Need at least this much wall time of samples before publishing an ETA.
#[doc(hidden)]
pub const ETA_MIN_ELAPSED_SECS: f64 = 20.0;

/// Present-biased smoothed tip rate for IBD ETA logs.
///
/// Samples are pushed on the centralized ~5s status tick. ETA uses an EWMA of
/// inter-sample rates (half-life [`ETA_RATE_HALF_LIFE_SECS`]): recent pace
/// dominates, but a single 5s spike only moves the estimate a few percent.
pub struct TipRateTracker {
    /// EWMA of tip advance rate (blocks/s).
    pub rate_ema: Option<f64>,
    /// Previous sample used to form the next instantaneous interval rate.
    pub last: Option<(Instant, u32)>,
    /// First sample time (gate ETA until we have a few ticks of history).
    pub first_at: Option<Instant>,
}

impl Default for TipRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TipRateTracker {
    pub fn new() -> Self {
        Self {
            rate_ema: None,
            last: None,
            first_at: None,
        }
    }

    /// Record a sample (call once per centralized status tick).
    pub fn push(&mut self, now: Instant, tip: u32) {
        if self.first_at.is_none() {
            self.first_at = Some(now);
        }
        if let Some((t0, tip0)) = self.last {
            let dt = now.duration_since(t0).as_secs_f64();
            // Ignore zero/negative clock skew; tiny dt would explode inst rate.
            if dt >= 0.5 {
                let inst = tip.saturating_sub(tip0) as f64 / dt;
                let inst = if inst.is_finite() && inst >= 0.0 {
                    inst
                } else {
                    0.0
                };
                self.rate_ema = Some(match self.rate_ema {
                    None => inst,
                    Some(prev) => {
                        let alpha =
                            1.0 - (-std::f64::consts::LN_2 * dt / ETA_RATE_HALF_LIFE_SECS).exp();
                        let alpha = alpha.clamp(0.02, 0.5);
                        alpha * inst + (1.0 - alpha) * prev
                    }
                });
            }
        }
        self.last = Some((now, tip));
    }

    /// Smoothed tip rate (blocks/s) for ETA: present-biased EWMA.
    pub fn eta_rate(&self, now: Instant) -> Option<f64> {
        let first = self.first_at?;
        let elapsed = now.duration_since(first).as_secs_f64();
        if elapsed < ETA_MIN_ELAPSED_SECS {
            return None;
        }
        let ema = self.rate_ema.filter(|r| r.is_finite() && *r > 1e-6)?;
        Some(ema)
    }

    /// Human ETA from tip→horizon using smoothed present-biased tip rate.
    pub fn eta_string(&self, now: Instant, tip: u32, horizon: u32) -> String {
        let remain = horizon.saturating_sub(tip);
        if remain == 0 {
            return "done".into();
        }
        let Some(rate) = self.eta_rate(now) else {
            return "eta=?".into();
        };
        let secs = (remain as f64 / rate).ceil() as u64;
        format!("eta={}", format_duration_short(secs))
    }
}

/// Compact duration for logs: `45s`, `12m`, `3.2h`, `2d5h`.
pub fn format_duration_short(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    if secs < 3600 {
        return format!("{}m", (secs + 30) / 60);
    }
    if secs < 86400 {
        let h = secs as f64 / 3600.0;
        if h < 10.0 {
            return format!("{h:.1}h");
        }
        return format!("{}h", (secs + 1800) / 3600);
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    if h == 0 {
        format!("{d}d")
    } else {
        format!("{d}d{h}h")
    }
}

/// Format a per-second rate for progress logs (`0`, `2.4`, `31`).
pub fn format_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return "0".into();
    }
    if rate < 10.0 {
        format!("{rate:.1}")
    } else {
        format!("{rate:.0}")
    }
}

/// Numbers the status thread prints. The coordination loop publishes a new
/// copy when it runs. A stuck loop leaves this snapshot in place.
#[derive(Clone, Default)]
pub struct StatusSnap {
    pub peers: usize,
    pub horizon: u32,
    pub hole: usize,
    pub header_origin: bool,
    pub header_height: u32,
    pub header_stored: u32,
    pub header_queue: usize,
    pub header_work_ok: bool,
    pub header_walk: bool,
    pub header_quiet: bool,
}

/// Confirm-tip rate for the status line. Peer disconnects do not read it.
pub struct StatusClock {
    pub last_sample_tip: u32,
    pub last_sample_at: Instant,
    pub saw_quiet: bool,
    pub rate: TipRateTracker,
}

impl StatusClock {
    pub fn new(tip: u32, now: Instant) -> Self {
        let mut rate = TipRateTracker::new();
        rate.push(now, tip);
        Self {
            last_sample_tip: tip,
            last_sample_at: now,
            saw_quiet: false,
            rate,
        }
    }
}

/// One progress line from published counters and the last coordination snapshot.
pub fn log_progress_tick(
    clock: &mut StatusClock,
    snap: &StatusSnap,
    published: &ProgressPublished,
    queues: (usize, usize, usize),
    bq_count: usize,
    bq_bytes: u64,
    now: Instant,
) {
    let tip = published.tip.unwrap_or(0);
    clock.rate.push(now, tip);
    let horizon = snap.horizon.max(tip);
    let pct = ibd_pct(tip, horizon);
    let window = now
        .saturating_duration_since(clock.last_sample_at)
        .as_secs_f64()
        .max(0.001);
    let tip_rate = tip.saturating_sub(clock.last_sample_tip) as f64 / window;
    clock.last_sample_tip = tip;
    clock.last_sample_at = now;
    let eta_rate = clock.rate.eta_rate(now);
    let eta = clock.rate.eta_string(now, tip, horizon);
    let conf_q = super::confirm::format_conf_q(
        queues.0,
        queues.1,
        queues.2,
        super::confirm::load_queue_cap(),
        super::confirm::script_queue_cap(),
        super::confirm::write_queue_cap(),
    );
    let line = format_progress_line(&ProgressLineInput {
        pct,
        tip,
        tip_rate,
        tip_hole: snap.hole,
        peers: snap.peers,
        conf_q,
        txs: published.txs,
        horizon,
        eta,
        bq_bytes,
        bq_count,
        bq_soft_stop: rbitcoin_query::soft_confirm_window_n(eta_rate),
    });
    rbitcoin_log::info_bold!("{line}");
    if !snap.header_origin || snap.header_quiet {
        if snap.header_quiet && !clock.saw_quiet {
            rbitcoin_log::info!(
                "ibd: headers done height={} horizon={horizon}",
                snap.header_height
            );
        }
        clock.saw_quiet = snap.header_quiet;
        return;
    }
    clock.saw_quiet = false;
    let pct_h = ibd_pct(snap.header_height, horizon.max(snap.header_height));
    let work = if snap.header_work_ok { "ok" } else { "below" };
    let phase = if snap.header_walk { "walk" } else { "write" };
    rbitcoin_log::info!(
        "ibd: headers height={} ({pct_h}%) horizon={horizon} stored={} queue={} work={work} phase={phase}",
        snap.header_height,
        snap.header_stored,
        snap.header_queue
    );
}

/// Snapshot the coordination loop publishes for the status line.
pub struct StatusBoard {
    pub snap: std::sync::Mutex<StatusSnap>,
    pub hole: std::sync::atomic::AtomicUsize,
}

impl Default for StatusBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusBoard {
    pub fn new() -> Self {
        Self {
            snap: std::sync::Mutex::new(StatusSnap::default()),
            hole: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn publish(&self, snap: StatusSnap) {
        *self.snap.lock().unwrap_or_else(|e| e.into_inner()) = snap;
    }

    pub fn set_hole(&self, hole: usize) {
        self.hole.store(hole, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn spawn_status_thread(
    board: Arc<StatusBoard>,
    query: Arc<rbitcoin_query::Query>,
    queues: Arc<super::confirm::ConfirmQueueDepths>,
    start_tip: u32,
    stop: std::sync::mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ibd-status".into())
        .spawn(move || {
            let mut clock = StatusClock::new(start_tip, Instant::now());
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                stop.recv_timeout(Duration::from_secs(5))
            {
                let mut snap = board.snap.lock().unwrap_or_else(|e| e.into_inner()).clone();
                snap.hole = board.hole.load(std::sync::atomic::Ordering::Relaxed);
                let published = read_progress_published(&query);
                let (bq_bytes, bq_count) = query.block_queue_stats();
                let now = Instant::now();
                log_progress_tick(
                    &mut clock,
                    &snap,
                    &published,
                    queues.snap(),
                    bq_count,
                    bq_bytes,
                    now,
                );
            }
        })
        .expect("ibd-status thread")
}

/// Pure tip-hole count over tip+1.. using claim-ready flags.
///
/// `claim_ready[i]` corresponds to height path_lo+i. Production
/// [`tip_fetch_hole`] walks heights and builds the same sequential hole count.
pub fn tip_hole_from_claim_ready(claim_ready_flags: &[bool]) -> usize {
    let mut tip_hole = 0usize;
    for &ready in claim_ready_flags {
        if ready {
            break;
        }
        tip_hole += 1;
    }
    tip_hole
}
