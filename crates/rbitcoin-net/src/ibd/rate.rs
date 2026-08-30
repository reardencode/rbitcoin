//! Per-peer IBD byte-rate EWMA, accrued only while block getdata is in flight.

/// EWMA time constant (ms).
pub(crate) const TAU_MS: u64 = 15_000;
/// Minimum dt to fold a sample (ms).
pub(crate) const MIN_SAMPLE_MS: u64 = 250;
/// `bps()` becomes `Some` after this much inflight-accrued time (ms).
pub(crate) const RANK_MATURE_MS: u64 = 5_000;
/// Relative-slow sample maturity (ms of inflight-accrued EWMA).
pub(crate) const RELSLOW_ACTIVE_MS: u64 = 30_000;
/// Qualifying stream delta for rx progress.
pub(crate) const PROGRESS_STEP: u64 = 64 * 1024;

/// Integer EWMA of received bytes, sampled on the IBD main thread.
///
/// Accrues only while the peer has block getdata in flight. Idle time rebaselines
/// the byte cursor so it does not dilute the rate. `progress_ms` is last qualifying
/// rx (stream ≥ [`PROGRESS_STEP`] or event-path `note_rx`); `work_started_ms` is the
/// last empty→nonempty getdata. Stall is `now - max(progress, work_started) > stall`
/// while inflight.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PeerRate {
    ewma: u64,
    pub(crate) active_ms: u64,
    pub(crate) progress_ms: u64,
    pub(crate) work_started_ms: u64,
    last_bytes: u64,
    last_ms: Option<u64>,
}

impl PeerRate {
    /// Fold `bytes_total` at `now_ms`. `inflight` false freezes the EWMA.
    pub(crate) fn sample(&mut self, now_ms: u64, bytes_total: u64, inflight: bool) {
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

    pub(crate) fn note_work_started(&mut self, now_ms: u64) {
        self.work_started_ms = now_ms;
    }

    pub(crate) fn note_rx(&mut self, now_ms: u64) {
        self.progress_ms = now_ms;
    }

    pub(crate) fn bps(&self) -> Option<u64> {
        if self.active_ms >= RANK_MATURE_MS {
            Some(self.ewma)
        } else {
            None
        }
    }

    pub(crate) fn stalled(&self, now_ms: u64, stall_ms: u64, inflight: bool) -> bool {
        if !inflight {
            return false;
        }
        let last = self.progress_ms.max(self.work_started_ms);
        now_ms.saturating_sub(last) > stall_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relslow_active_is_longer_than_rank() {
        let mut r = PeerRate::default();
        r.sample(0, 0, true);
        r.sample(RANK_MATURE_MS, RANK_MATURE_MS * 1_000, true);
        assert!(r.bps().is_some());
        assert!(r.active_ms < RELSLOW_ACTIVE_MS);
    }

    #[test]
    fn idle_rebaseline_freezes_ewma() {
        let mut r = PeerRate::default();
        r.sample(0, 0, true);
        r.sample(5_000, 5_000_000, true);
        let frozen = r.bps().expect("mature after 5s");
        r.sample(15_000, 5_000_000 + 50_000_000, false);
        assert_eq!(r.bps(), Some(frozen));
    }

    #[test]
    fn active_zero_delta_decays_ewma() {
        let mut r = PeerRate::default();
        r.sample(0, 0, true);
        r.sample(5_000, 5_000_000, true);
        let high = r.bps().expect("mature");
        r.sample(10_000, 5_000_000, true);
        r.sample(15_000, 5_000_000, true);
        assert!(r.bps().unwrap() < high);
    }

    #[test]
    fn bps_none_until_rank_mature() {
        let mut r = PeerRate::default();
        r.sample(0, 0, true);
        r.sample(4_000, 4_000_000, true);
        assert!(r.bps().is_none());
        r.sample(5_000, 5_000_000, true);
        assert!(r.bps().is_some());
    }

    #[test]
    fn progress_marks_on_64k_not_on_small_delta() {
        let mut r = PeerRate::default();
        r.sample(0, 0, true);
        r.sample(1_000, 1_000, true);
        assert_eq!(r.progress_ms, 0);
        r.sample(2_000, 1_000 + PROGRESS_STEP, true);
        assert_eq!(r.progress_ms, 2_000);
    }

    #[test]
    fn stalled_uses_work_started_when_no_rx() {
        let mut r = PeerRate::default();
        r.note_work_started(0);
        assert!(!r.stalled(29_999, 30_000, true));
        assert!(r.stalled(30_001, 30_000, true));
    }

    #[test]
    fn stalled_false_when_idle_inflight_empty() {
        let mut r = PeerRate::default();
        r.note_work_started(0);
        assert!(!r.stalled(40_000, 30_000, false));
    }

    #[test]
    fn stalled_false_when_rx_within_grace() {
        let mut r = PeerRate::default();
        r.note_work_started(0);
        r.note_rx(20_000);
        assert!(!r.stalled(45_000, 30_000, true));
        assert!(r.stalled(50_001, 30_000, true));
    }
}
