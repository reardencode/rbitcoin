//! Process-local fee flow meter (EMA of admit WU/s per bucket).

use crate::fee_est::{bucket_count, bucket_index};
use std::time::Instant;

/// Admit EMA half-life (seconds).
pub const ADMIT_HALF_LIFE_SECS: f64 = 150.0;
/// Warm after this many wall seconds.
pub const WARM_AFTER_SECS: f64 = 60.0;
/// Warm after this many admit events.
pub const WARM_AFTER_ADMITS: u64 = 32;

/// EMA flow state for fee Engine v2.
#[derive(Debug, Clone)]
pub struct FeeFlowMeter {
    admit_wu_s: Vec<f64>,
    last: Instant,
    start: Instant,
    admit_events: u64,
}

impl Default for FeeFlowMeter {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl FeeFlowMeter {
    pub fn new(now: Instant) -> Self {
        let n = bucket_count();
        Self {
            admit_wu_s: vec![0.0; n],
            last: now,
            start: now,
            admit_events: 0,
        }
    }

    pub fn is_warm(&self, now: Instant) -> bool {
        let age = now.duration_since(self.start).as_secs_f64();
        age >= WARM_AFTER_SECS && self.admit_events >= WARM_AFTER_ADMITS
    }

    pub fn admit_events(&self) -> u64 {
        self.admit_events
    }

    /// Snapshot of admit λ (WU/s) per bucket after decaying to `now`.
    pub fn admit_rates_wu_s(&mut self, now: Instant) -> Vec<u64> {
        self.decay_to(now);
        self.admit_wu_s
            .iter()
            .map(|x| x.max(0.0).round() as u64)
            .collect()
    }

    pub fn note_admit(&mut self, weight_wu: u64, rate_sat_per_kvb: u64, now: Instant) {
        let dt = now.duration_since(self.last).as_secs_f64().max(1e-3);
        self.decay_to(now);
        let i = bucket_index(rate_sat_per_kvb).min(self.admit_wu_s.len().saturating_sub(1));
        let sample = weight_wu as f64 / dt;
        let alpha = 1.0 - (-std::f64::consts::LN_2 * dt / ADMIT_HALF_LIFE_SECS).exp();
        self.admit_wu_s[i] = self.admit_wu_s[i] * (1.0 - alpha) + sample * alpha;
        self.admit_events = self.admit_events.saturating_add(1);
    }

    fn decay_to(&mut self, now: Instant) {
        let dt = now.duration_since(self.last).as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        let factor_a = (-std::f64::consts::LN_2 * dt / ADMIT_HALF_LIFE_SECS).exp();
        for v in &mut self.admit_wu_s {
            *v *= factor_a;
        }
        self.last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn admit_stream_raises_ema() {
        let t0 = Instant::now();
        let mut m = FeeFlowMeter::new(t0);
        for i in 0..40 {
            let t = t0 + Duration::from_secs(i + 1);
            m.note_admit(10_000, 1_000, t);
        }
        let rates = m.admit_rates_wu_s(t0 + Duration::from_secs(41));
        let bi = bucket_index(1_000);
        assert!(rates[bi] > 0, "ema should be warm, got {rates:?}");
        assert!(m.is_warm(t0 + Duration::from_secs(70)));
    }

    #[test]
    fn idle_decays() {
        let t0 = Instant::now();
        let mut m = FeeFlowMeter::new(t0);
        m.note_admit(100_000, 500, t0 + Duration::from_secs(1));
        let hot = m.admit_rates_wu_s(t0 + Duration::from_secs(2));
        let cold = m.admit_rates_wu_s(t0 + Duration::from_secs(600));
        let bi = bucket_index(500);
        assert!(cold[bi] < hot[bi], "hot={} cold={}", hot[bi], cold[bi]);
    }
}
