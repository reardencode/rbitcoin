//! Historical fee hurdles from windows that looked like now.
//!
//! Each block with a hurdle (its vsize-weighted p10 feerate) is one
//! observation; blocks without one (coinbase-only, or every tx below min
//! relay) are skipped, so a window of N is N blocks that carried
//! transactions. For target N, the pair at position `t` is the median hurdle
//! of the [`analog_lookback`] blocks before `t` and the lowest hurdle of the N
//! blocks from `t` (a tx at that rate would have beaten some block's p10).
//! An estimate keeps pairs whose lookback median is within [`ANALOG_BAND`]
//! of the current lookback median, or the [`ANALOG_MIN_NEIGHBORS`] nearest,
//! and takes the requested quantile of their outcomes. Windows that started
//! inside a spike stop steering calm-market estimates, and the reverse.

use std::collections::VecDeque;

/// Lookback medians within this ratio of now count as "looked like now".
pub const ANALOG_BAND: f64 = 1.25;
/// Fewest neighbors an estimate uses; below it, the nearest by lookback.
pub const ANALOG_MIN_NEIGHBORS: usize = 200;
/// Pairs a target needs before it answers.
pub const ANALOG_READY_PAIRS: usize = 2_000;

/// Lookback length for target N: `clamp(N/4, 3, 144)` hurdle blocks. On a
/// mainnet backtest a 3-block floor tracked the current level closer than 6
/// at N=2–6 (99.1–99.3% coverage at 99% vs 98.6–98.8%, and lower rates).
pub fn analog_lookback(n_blocks: u32) -> usize {
    (n_blocks as usize / 4).clamp(3, 144)
}

#[derive(Debug)]
struct Depth {
    n: usize,
    lookback: usize,
    /// `(ln lookback median, window hurdle)` by window start, oldest first.
    pairs: VecDeque<(f64, u64)>,
}

/// Hurdle sequence plus per-target analog pairs, kept in step as blocks are
/// added or dropped at either end.
///
/// RAM: 16 B per pair per target plus 8 B per hurdle; ~5.5 MiB for 31k
/// mainnet blocks (1 GiB of txstat) at 11 targets. CPU: an end push or pop
/// costs `O(lookback·log + N)` per target; [`Self::rate_sat_kvb`] scans every
/// pair of one target (~0.2 ms at 31k).
#[derive(Debug)]
pub struct AnalogHistory {
    hurdles: VecDeque<u64>,
    depths: Vec<Depth>,
}

fn lower_median(values: impl Iterator<Item = u64>) -> u64 {
    let mut v: Vec<u64> = values.collect();
    let mid = (v.len() - 1) / 2;
    *v.select_nth_unstable(mid).1
}

fn ln_rate(rate: u64) -> f64 {
    (rate.max(1) as f64).ln()
}

impl AnalogHistory {
    pub fn new(targets: &[u32]) -> Self {
        Self {
            hurdles: VecDeque::new(),
            depths: targets
                .iter()
                .map(|&n| Depth {
                    n: n.max(1) as usize,
                    lookback: analog_lookback(n),
                    pairs: VecDeque::new(),
                })
                .collect(),
        }
    }

    /// Pair whose window starts at hurdle index `t`.
    fn pair(hurdles: &VecDeque<u64>, d: &Depth, t: usize) -> (f64, u64) {
        let before = lower_median(hurdles.range(t - d.lookback..t).copied());
        let ahead = hurdles
            .range(t..t + d.n)
            .copied()
            .min()
            .expect("window is not empty");
        (ln_rate(before), ahead)
    }

    /// Append the newest block's hurdle.
    pub fn push_back(&mut self, hurdle: u64) {
        self.hurdles.push_back(hurdle);
        let k = self.hurdles.len();
        for d in &mut self.depths {
            if k >= d.lookback + d.n {
                let pair = Self::pair(&self.hurdles, d, k - d.n);
                d.pairs.push_back(pair);
            }
        }
    }

    /// Drop the newest block's hurdle (its windows end with it).
    pub fn pop_back(&mut self) {
        if self.hurdles.pop_back().is_some() {
            for d in &mut self.depths {
                d.pairs.pop_back();
            }
        }
    }

    /// Prepend an older block's hurdle.
    pub fn push_front(&mut self, hurdle: u64) {
        self.hurdles.push_front(hurdle);
        let k = self.hurdles.len();
        for d in &mut self.depths {
            if k >= d.lookback + d.n {
                let pair = Self::pair(&self.hurdles, d, d.lookback);
                d.pairs.push_front(pair);
            }
        }
    }

    /// Drop the oldest block's hurdle (its lookbacks start with it).
    pub fn pop_front(&mut self) {
        if self.hurdles.pop_front().is_some() {
            for d in &mut self.depths {
                d.pairs.pop_front();
            }
        }
    }

    /// Replace the sequence (oldest first).
    pub fn rebuild(&mut self, hurdles: impl IntoIterator<Item = u64>) {
        self.hurdles.clear();
        for d in &mut self.depths {
            d.pairs.clear();
        }
        for hurdle in hurdles {
            self.push_back(hurdle);
        }
    }

    /// Pairs held for target `n_blocks` (0 for a target not tracked).
    pub fn pairs(&self, n_blocks: u32) -> usize {
        self.depths
            .iter()
            .find(|d| d.n == n_blocks.max(1) as usize)
            .map_or(0, |d| d.pairs.len())
    }

    /// Lowest rate (sat/kvB) at or above the window hurdle in a `confidence`
    /// share of the windows that looked like now. None before the target
    /// holds [`ANALOG_READY_PAIRS`] pairs.
    pub fn rate_sat_kvb(&self, n_blocks: u32, confidence: f64) -> Option<u64> {
        let d = self
            .depths
            .iter()
            .find(|d| d.n == n_blocks.max(1) as usize)?;
        if d.pairs.len() < ANALOG_READY_PAIRS || !(0.0..=1.0).contains(&confidence) {
            return None;
        }
        let k = self.hurdles.len();
        let now = ln_rate(lower_median(self.hurdles.range(k - d.lookback..).copied()));
        let band = ANALOG_BAND.ln();
        let mut outcomes: Vec<u64> = d
            .pairs
            .iter()
            .filter(|(before, _)| (before - now).abs() <= band)
            .map(|&(_, ahead)| ahead)
            .collect();
        // Out-of-band distances sit past the band, so a full in-band set is
        // already the nearest floor. Borrow only while some neighbors are missing.
        let missing = ANALOG_MIN_NEIGHBORS.saturating_sub(outcomes.len());
        if missing > 0 {
            let mut nearest: Vec<(f64, u64)> = d
                .pairs
                .iter()
                .map(|&(before, ahead)| ((before - now).abs(), ahead))
                .collect();
            nearest.select_nth_unstable_by(ANALOG_MIN_NEIGHBORS.saturating_sub(1), |a, b| {
                a.0.total_cmp(&b.0)
            });
            outcomes = nearest[..ANALOG_MIN_NEIGHBORS]
                .iter()
                .map(|&(_, ahead)| ahead)
                .collect();
        }
        let i = ((confidence * outcomes.len() as f64).ceil() as usize).saturating_sub(1);
        Some(*outcomes.select_nth_unstable(i).1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Calm hurdles near 1000 sat/kvB with a deterministic wobble.
    fn calm(i: usize) -> u64 {
        1_000 + (i as u64 * 7_919) % 200
    }

    fn history(targets: &[u32], hurdles: impl IntoIterator<Item = u64>) -> AnalogHistory {
        let mut h = AnalogHistory::new(targets);
        h.rebuild(hurdles);
        h
    }

    fn paired_history(now: u64, pairs: impl IntoIterator<Item = (f64, u64)>) -> AnalogHistory {
        let mut h = AnalogHistory::new(&[1]);
        h.hurdles = VecDeque::from([now, now, now]);
        h.depths[0].pairs = pairs.into_iter().collect();
        h
    }

    #[test]
    fn a_past_spike_does_not_steer_a_calm_market() {
        // 4000 calm blocks with a 400-block spike at 50000 in the middle
        let hurdles = (0..4_000).map(|i| {
            if (1_800..2_200).contains(&i) {
                50_000
            } else {
                calm(i)
            }
        });
        let h = history(&[2, 20], hurdles);
        for n in [2, 20] {
            let rate = h.rate_sat_kvb(n, 0.99).unwrap();
            assert!(rate < 1_200, "N={n}: calm now, got {rate}");
        }
    }

    #[test]
    fn a_spike_in_progress_finds_the_spike_windows() {
        let hurdles = (0..4_000).map(|i| {
            if (1_800..2_200).contains(&i) || i >= 3_900 {
                50_000 + (i as u64 % 7) * 100
            } else {
                calm(i)
            }
        });
        let h = history(&[2], hurdles);
        let rate = h.rate_sat_kvb(2, 0.99).unwrap();
        assert!(rate >= 50_000, "spike now, got {rate}");
    }

    #[test]
    fn a_spike_that_ended_stops_counting_once_the_lookback_is_calm() {
        let hurdles = (0..4_000).map(|i| {
            if (1_800..2_200).contains(&i) || (3_700..3_990).contains(&i) {
                50_000
            } else {
                calm(i)
            }
        });
        let h = history(&[2], hurdles);
        let rate = h.rate_sat_kvb(2, 0.99).unwrap();
        assert!(rate < 1_200, "spike ended 10 blocks ago, got {rate}");
    }

    #[test]
    fn a_target_answers_only_once_it_holds_enough_pairs() {
        let lookback = analog_lookback(2);
        let needed = ANALOG_READY_PAIRS + lookback + 2 - 1;
        let mut h = history(&[2], (0..needed - 1).map(calm));
        assert_eq!(h.pairs(2), ANALOG_READY_PAIRS - 1);
        assert_eq!(h.rate_sat_kvb(2, 0.99), None);
        h.push_back(calm(needed));
        assert_eq!(h.pairs(2), ANALOG_READY_PAIRS);
        assert!(h.rate_sat_kvb(2, 0.99).is_some());
        assert_eq!(h.rate_sat_kvb(3, 0.99), None, "untracked target");
        assert_eq!(h.rate_sat_kvb(2, 1.5), None, "confidence out of range");
    }

    #[test]
    fn an_unmatched_level_uses_the_nearest_neighbors() {
        // now sits at 20000, far outside every past lookback band
        let hurdles = (0..3_000).map(|i| if i >= 2_990 { 20_000 } else { calm(i) });
        let h = history(&[2], hurdles);
        let rate = h.rate_sat_kvb(2, 0.5).unwrap();
        assert!(rate >= 1_000, "{rate}");
    }

    #[test]
    fn analog_selector_keeps_each_boundary_rate() {
        let now = 10_000u64;
        let center = (now as f64).ln();
        let band = std::iter::repeat_n((center, 1_000), ANALOG_MIN_NEIGHBORS + 50)
            .chain(std::iter::repeat_n((center + 0.1, 50_000), 50))
            .chain(std::iter::repeat_n(
                (center + 1.0, 90_000),
                ANALOG_READY_PAIRS - ANALOG_MIN_NEIGHBORS - 100,
            ));
        let quantile = std::iter::repeat_n((center + 0.3, 50_000), ANALOG_MIN_NEIGHBORS - 1).chain(
            std::iter::repeat_n(
                (center - 0.4, 1_000),
                ANALOG_READY_PAIRS - ANALOG_MIN_NEIGHBORS + 1,
            ),
        );
        let mut nearest = std::iter::repeat_n((center + 0.3, 1_000), ANALOG_MIN_NEIGHBORS - 1)
            .chain([(center + 0.31, 50_000), (center + 0.32, 1_000)])
            .chain(std::iter::repeat_n(
                (center + 0.4, 1_000),
                ANALOG_READY_PAIRS - ANALOG_MIN_NEIGHBORS - 1,
            ))
            .collect::<Vec<_>>();
        let mut seed = 341usize;
        for i in (1..nearest.len()).rev() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            nearest.swap(i, seed % (i + 1));
        }
        let upper = std::iter::repeat_n((0.0, 1_000), ANALOG_READY_PAIRS - 1)
            .chain([(ANALOG_BAND.ln(), 50_000)]);

        let cases = [
            (
                "exact upper boundary",
                paired_history(1, upper),
                1.0,
                50_000,
            ),
            (
                "absolute log distance",
                paired_history(now, band),
                0.9,
                50_000,
            ),
            (
                "absolute log distance quantile",
                paired_history(now, quantile),
                0.99,
                50_000,
            ),
            (
                "two hundredth window",
                paired_history(now, nearest),
                1.0,
                50_000,
            ),
        ];
        for (name, history, confidence, want) in cases {
            assert_eq!(history.rate_sat_kvb(1, confidence), Some(want), "{name}");
        }
    }

    #[test]
    fn end_updates_match_a_rebuild() {
        // deterministic LCG drives pushes and pops at both ends
        let mut seed = 42u64;
        let mut next = || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            seed >> 33
        };
        let targets = [1, 2, 6, 20];
        let mut h = AnalogHistory::new(&targets);
        let mut seq: VecDeque<u64> = VecDeque::new();
        for _ in 0..3_000 {
            let r = next();
            let hurdle = 100 + next() % 5_000;
            match r % 10 {
                0..=4 => {
                    h.push_back(hurdle);
                    seq.push_back(hurdle);
                }
                5..=6 => {
                    h.push_front(hurdle);
                    seq.push_front(hurdle);
                }
                7 => {
                    h.pop_back();
                    seq.pop_back();
                }
                _ => {
                    h.pop_front();
                    seq.pop_front();
                }
            }
        }
        let rebuilt = history(&targets, seq.iter().copied());
        assert_eq!(h.hurdles, rebuilt.hurdles);
        for (a, b) in h.depths.iter().zip(&rebuilt.depths) {
            assert_eq!(a.pairs, b.pairs, "N={}", a.n);
        }
    }
}
