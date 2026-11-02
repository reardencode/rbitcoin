//! Process-local fee flow meter (EMA of admit WU/s per bucket).

use crate::fee_est::{bucket_count, bucket_index, BLOCK_WEIGHT_WU, SECONDS_PER_BLOCK};
use std::time::Instant;

/// Admit EMA half-life (seconds). The fullness scalar uses the same half-life.
pub const ADMIT_HALF_LIFE_SECS: f64 = 150.0;

/// Weight a full block every 10 minutes leaves in the half-life memory.
pub fn flow_full_wu() -> f64 {
    (BLOCK_WEIGHT_WU as f64 / SECONDS_PER_BLOCK as f64)
        * (ADMIT_HALF_LIFE_SECS / std::f64::consts::LN_2)
}

/// EMA flow state for fee Engine v2.
#[derive(Debug, Clone)]
pub struct FeeFlowMeter {
    pub admit_wu_s: Vec<f64>,
    /// Decayed admitted weight (WU). Not the per-bucket time-gap alpha.
    pub admitted_wu: f64,
    /// Decay clock. Reads move it too.
    pub last: Instant,
    /// Previous admit. The sample is weight over the gap since this one.
    last_admit: Instant,
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
            admitted_wu: 0.0,
            last: now,
            last_admit: now,
        }
    }

    /// Fullness in `0..=1` after decaying to `now`. Starts at 0.
    pub fn fullness(&mut self, now: Instant) -> f64 {
        self.decay_to(now);
        let full = flow_full_wu();
        if full <= 0.0 {
            return 0.0;
        }
        (self.admitted_wu / full).clamp(0.0, 1.0)
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
        let dt = now.duration_since(self.last_admit).as_secs_f64().max(1e-3);
        // Every bucket has decayed by `1 - alpha` since `last_admit`, reads included.
        self.decay_to(now);
        let i = bucket_index(rate_sat_per_kvb).min(self.admit_wu_s.len().saturating_sub(1));
        let sample = weight_wu as f64 / dt;
        let alpha = 1.0 - (-std::f64::consts::LN_2 * dt / ADMIT_HALF_LIFE_SECS).exp();
        self.admit_wu_s[i] += sample * alpha;
        self.admitted_wu += weight_wu as f64;
        self.last_admit = now;
    }

    #[doc(hidden)]
    pub fn decay_to(&mut self, now: Instant) {
        let dt = now.duration_since(self.last).as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        let factor_a = (-std::f64::consts::LN_2 * dt / ADMIT_HALF_LIFE_SECS).exp();
        for v in &mut self.admit_wu_s {
            *v *= factor_a;
        }
        self.admitted_wu *= factor_a;
        self.last = now;
    }
}
