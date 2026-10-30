//! Per-peer IBD byte-rate EWMA, accrued only while block getdata is in flight.

/// EWMA time constant (ms).
pub const TAU_MS: u64 = 15_000;
/// Minimum dt to fold a sample (ms).
pub const MIN_SAMPLE_MS: u64 = 250;
/// `bps()` becomes `Some` after this much inflight-accrued time (ms).
pub const RANK_MATURE_MS: u64 = 5_000;
/// Relative-slow sample maturity (ms of inflight-accrued EWMA).
pub const RELSLOW_ACTIVE_MS: u64 = 30_000;
/// Qualifying stream delta for rx progress.
pub const PROGRESS_STEP: u64 = 64 * 1024;

/// Integer EWMA of received block bytes, sampled on the IBD main thread.
///
/// Accrues only while the peer has block getdata in flight. Idle time rebaselines
/// the byte cursor so it does not dilute the rate. `progress_ms` is the last
/// solicited block progress. `any_rx_ms` is the last socket byte of any kind.
/// Quiet disconnect uses `any_rx_ms`. Block clocks (`progress_ms`, eviction,
/// recent-rx) ignore pings, addr, and headers.
/// `bytes_at_progress` is the stream total when block progress last moved, so
/// a body still arriving is not scored as chat.
/// `work_started_ms` records the last getdata write and is not a stall input.
/// A quiet in-flight gap does not rewrite the EWMA. Ranking, densify caps,
/// and AddrMan FAST/SLOW read [`Self::bps`].
/// Eviction reads [`Self::eviction_bps`], which folds missing block bytes in
/// as zero throughput.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerRate {
    pub ewma: u64,
    pub active_ms: u64,
    pub progress_ms: u64,
    pub work_started_ms: u64,
    pub any_rx_ms: u64,
    pub bytes_at_progress: u64,
    pub last_bytes: u64,
    pub last_ms: Option<u64>,
}

impl PeerRate {
    /// Fold `bytes_total` at `now_ms`. `inflight` false freezes the EWMA.
    pub fn sample(&mut self, now_ms: u64, bytes_total: u64, inflight: bool) {
        if !inflight {
            self.last_bytes = bytes_total;
            self.last_ms = Some(now_ms);
            return;
        }
        let Some(prev_ms) = self.last_ms else {
            self.last_bytes = bytes_total;
            self.last_ms = Some(now_ms);
            return;
        };
        if now_ms < prev_ms {
            self.last_bytes = bytes_total;
            self.last_ms = Some(now_ms);
            return;
        }
        let dt = now_ms.saturating_sub(prev_ms);
        if dt < MIN_SAMPLE_MS {
            return;
        }
        let delta = bytes_total.saturating_sub(self.last_bytes);
        if delta == 0 {
            // Silence is not a new transfer rate. Eviction applies the age.
            self.active_ms = self.active_ms.saturating_add(dt);
            self.last_bytes = bytes_total;
            self.last_ms = Some(now_ms);
            return;
        }
        let inst = delta.saturating_mul(1000) / dt;
        let den = TAU_MS.saturating_add(dt);
        self.ewma = self
            .ewma
            .saturating_mul(TAU_MS)
            .saturating_add(inst.saturating_mul(dt))
            / den.max(1);
        self.active_ms = self.active_ms.saturating_add(dt);
        if delta >= PROGRESS_STEP {
            self.progress_ms = now_ms;
        }
        self.last_bytes = bytes_total;
        self.last_ms = Some(now_ms);
    }

    /// First silence window starts when the peer connects, not at process epoch
    /// and not when we later write getdata.
    pub fn note_connected(&mut self, now_ms: u64) {
        self.progress_ms = now_ms;
        self.any_rx_ms = now_ms;
    }

    #[cfg(debug_assertions)]
    pub fn note_work_started(&mut self, now_ms: u64) {
        self.work_started_ms = now_ms;
    }

    /// Solicited block progress. Also counts as socket bytes.
    pub fn note_rx(&mut self, now_ms: u64) {
        self.progress_ms = now_ms;
        self.any_rx_ms = now_ms;
    }

    /// Ping, addr, headers, or any other socket bytes. Not block progress.
    /// Production writes the reader atomic; this is the test seam.
    #[cfg(debug_assertions)]
    pub fn note_any_rx(&mut self, now_ms: u64) {
        self.any_rx_ms = now_ms;
    }

    /// Stream total at the latest block-progress mark.
    pub fn note_bytes_at_progress(&mut self, bytes_rx: u64) {
        self.bytes_at_progress = bytes_rx;
    }

    pub fn bps(&self) -> Option<u64> {
        if self.active_ms >= RANK_MATURE_MS {
            Some(self.ewma)
        } else {
            None
        }
    }

    /// Speed for an eviction decision.
    ///
    /// [`Self::bps`] stays at the last real transfer rate, including while the
    /// peer is idle, so a frozen high sample is not proof the peer is fast
    /// now. Silence since the last qualifying rx counts as zero throughput:
    /// `ewma * TAU / (TAU + age)`.
    pub fn eviction_bps(&self, now_ms: u64) -> Option<u64> {
        let bps = self.bps()?;
        let last = self.progress_ms;
        if last == 0 || now_ms <= last {
            return Some(bps);
        }
        let age = now_ms - last;
        Some(bps.saturating_mul(TAU_MS) / TAU_MS.saturating_add(age))
    }

    /// No solicited block progress inside `stall_ms`.
    ///
    /// The on-wire window decides whether a getdata is outstanding.
    /// This is only the clock.
    pub fn stalled(&self, now_ms: u64, stall_ms: u64) -> bool {
        now_ms.saturating_sub(self.progress_ms) > stall_ms
    }

    /// No socket bytes at all inside `stall_ms`.
    ///
    /// The on-wire window decides whether a getdata is outstanding.
    /// This is only the clock.
    pub fn quiet(&self, now_ms: u64, stall_ms: u64) -> bool {
        now_ms.saturating_sub(self.any_rx_ms) > stall_ms
    }

    pub fn has_recent_rx(&self, now_ms: u64, stale_ms: u64) -> bool {
        self.progress_ms != 0 && now_ms.saturating_sub(self.progress_ms) <= stale_ms
    }
}
