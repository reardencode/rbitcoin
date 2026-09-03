//! Head resolve sub-timers (probe / idx / body) + winner locality metrics.
//!
//! Reset by the IBD ~5s sampler. Used to split archive prep `head_fk` cost into
//! open-address probes vs `tx.idx` range vs `txid.body` identity peeks, and to
//! measure **winning candidate rank** plus **winner sealed-age** for hot-window sizing.
//!
//! # Winner age histogram
//!
//! On each resolved parent (`create_fk` winner), we record
//! `sealed_age = n_segs - 1 - si` (0 = open/tip). Ages ≥ [`AGE_CAP`]−1 share the
//! last bucket. Sample CDFs:
//!
//! - `age_cdf(3)` ≈ fraction of hits inside today's wave1 window (ages ≤ 3)
//! - `age_cdf(K)` → how far to grow the hot set for locality
//!
//! No separate wave1/wave2 counters: under current policy, winners at age ≤ 3 are
//! wave1 hits; age ≥ 4 are wave2. Hist is over **resolved** keys only (`hit_n`).

use crate::head_resolve_pick::LeftoverMissOn;
use std::sync::atomic::{AtomicU64, Ordering};

/// Histogram buckets for winner sealed-age (last bucket is ages ≥ CAP−1).
pub const AGE_CAP: usize = 48;

static PROBE_NS: AtomicU64 = AtomicU64::new(0);
static IDX_NS: AtomicU64 = AtomicU64::new(0);
static BODY_NS: AtomicU64 = AtomicU64::new(0);
/// Keys that entered a head probe (batch or single).
static KEYS: AtomicU64 = AtomicU64::new(0);
/// Candidate fks collected from probes (before body dedupe).
static CANDS: AtomicU64 = AtomicU64::new(0);
/// Unique fks that paid idx+body_txid (one per body peek attempt).
static BODY_LOOKUPS: AtomicU64 = AtomicU64::new(0);
/// Sum of 1-based ranks of the matching cand in probe order (resolved keys only).
static HIT_RANK_SUM: AtomicU64 = AtomicU64::new(0);
/// Number of keys that resolved (contributed to HIT_RANK_SUM).
static HIT_RANK_N: AtomicU64 = AtomicU64::new(0);
/// Body peeks that did **not** match the wanted txid (wrong cand).
static MISS_PEEKS: AtomicU64 = AtomicU64::new(0);
/// Keys resolved from the unflushed head-insert map (write-behind).
static PENDING_HITS: AtomicU64 = AtomicU64::new(0);

/// First TipOnly leftover miss in the last resolve batch (`0` = none).
/// 1=head 2=body 3=idx 4=fence — see [`LeftoverMissOn`].
static LAST_MISS_ON: AtomicU64 = AtomicU64::new(0);
static LAST_MISS_CANDS: AtomicU64 = AtomicU64::new(0);

fn miss_on_code(on: LeftoverMissOn) -> u64 {
    match on {
        LeftoverMissOn::Head => 1,
        LeftoverMissOn::Body => 2,
        LeftoverMissOn::Idx => 3,
        LeftoverMissOn::Fence => 4,
    }
}

fn miss_on_from_code(code: u64) -> Option<LeftoverMissOn> {
    match code {
        1 => Some(LeftoverMissOn::Head),
        2 => Some(LeftoverMissOn::Body),
        3 => Some(LeftoverMissOn::Idx),
        4 => Some(LeftoverMissOn::Fence),
        _ => None,
    }
}

/// Clear leftover-miss classification (start of a resolve batch).
///
/// Does **not** drop the leftover hop-dump: every TipOnly/leftover resolve
/// starts a batch. Wiping the dump here raced parallel tests
/// (`leftover_miss_dumps_probe_diag`) and could clear `diag=1` on the
/// operator reject line before it was read.
pub fn clear_leftover_miss() {
    LAST_MISS_ON.store(0, Ordering::Relaxed);
    LAST_MISS_CANDS.store(0, Ordering::Relaxed);
}

/// Record the first leftover miss in this batch (later calls ignored).
pub fn note_leftover_miss(on: LeftoverMissOn, n_cands: u64) {
    if LAST_MISS_ON
        .compare_exchange(0, miss_on_code(on), Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        LAST_MISS_CANDS.store(n_cands, Ordering::Relaxed);
    }
}

/// Last leftover miss table + probe cand count (`None` if the batch hit every key).
pub fn take_leftover_miss() -> Option<(LeftoverMissOn, u64)> {
    let code = LAST_MISS_ON.swap(0, Ordering::Relaxed);
    let cands = LAST_MISS_CANDS.swap(0, Ordering::Relaxed);
    miss_on_from_code(code).map(|on| (on, cands))
}

/// One hop cand on the leftover-miss dump (shipped resolve path).
#[derive(Debug, Clone)]
pub struct LeftoverProbeCand {
    pub depth: u32,
    pub local: u64,
    pub rel: u64,
    pub abs_fk: u64,
    pub body_prefix: [u8; 8],
    pub body_match: bool,
}

/// Failure-time hop + identity dump for the first leftover miss.
#[derive(Debug, Clone)]
pub struct LeftoverProbeDiag {
    pub txid: [u8; 32],
    pub mixed_prefix: [u8; 8],
    pub page_base: u64,
    pub bits: u32,
    pub file_id: u32,
    pub first_fk: u64,
    pub sealed_age: Option<u32>,
    pub hit_empty: bool,
    pub depth_end: u32,
    pub empty_local: u64,
    pub page_occupied: u32,
    pub hop_equal_second: bool,
    pub cands: Vec<LeftoverProbeCand>,
}

static LAST_PROBE_DIAG: std::sync::Mutex<Option<LeftoverProbeDiag>> = std::sync::Mutex::new(None);
static LAST_PROBE_DIAG_SET: AtomicU64 = AtomicU64::new(0);
/// Recent leftover hop-dump txids (cap 16). Survives `take` / next resolve
/// `clear_leftover_miss` so tests can pin **this** parent, not a process flag.
static RECORDED_PROBE_TXIDS: std::sync::Mutex<Vec<[u8; 32]>> = std::sync::Mutex::new(Vec::new());

/// True when leftover (not lookup) recorded a probe dump (`diag=1` on the reject line).
pub fn leftover_probe_diag_ready() -> bool {
    LAST_PROBE_DIAG_SET.load(Ordering::Relaxed) != 0
}

/// True when a leftover hop-dump for `txid` was recorded this process.
pub fn leftover_probe_diag_recorded(txid: &[u8; 32]) -> bool {
    RECORDED_PROBE_TXIDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|t| t == txid)
}

pub fn take_leftover_probe_diag() -> Option<LeftoverProbeDiag> {
    LAST_PROBE_DIAG_SET.store(0, Ordering::Relaxed);
    LAST_PROBE_DIAG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

pub(crate) fn note_leftover_probe_diag(diag: LeftoverProbeDiag) {
    LAST_PROBE_DIAG_SET.store(1, Ordering::Relaxed);
    {
        let mut rec = RECORDED_PROBE_TXIDS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if rec.len() >= 16 {
            rec.remove(0);
        }
        rec.push(diag.txid);
    }
    *LAST_PROBE_DIAG.lock().unwrap_or_else(|e| e.into_inner()) = Some(diag);
}

/// Winner sealed-age histogram (index = age from tip; last bucket is tail).
static AGE_HIT: [AtomicU64; AGE_CAP] = [const { AtomicU64::new(0) }; AGE_CAP];

#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub probe_ns: u64,
    pub idx_ns: u64,
    pub body_ns: u64,
    pub keys: u64,
    pub cands: u64,
    pub body_lookups: u64,
    /// Sum of hit ranks (use with [`Self::hit_rank_n`] for mean).
    pub hit_rank_sum: u64,
    pub hit_rank_n: u64,
    pub miss_peeks: u64,
    /// Unflushed write-behind map hits.
    pub pending_hits: u64,
    /// Hits by sealed-age from tip (`age_hit[AGE_CAP-1]` = ages ≥ CAP−1).
    pub age_hit: [u64; AGE_CAP],
}

impl Default for Sample {
    fn default() -> Self {
        Self {
            probe_ns: 0,
            idx_ns: 0,
            body_ns: 0,
            keys: 0,
            cands: 0,
            body_lookups: 0,
            hit_rank_sum: 0,
            hit_rank_n: 0,
            miss_peeks: 0,
            pending_hits: 0,
            age_hit: [0; AGE_CAP],
        }
    }
}

impl Sample {
    pub fn sum_ns(&self) -> u64 {
        self.probe_ns
            .saturating_add(self.idx_ns)
            .saturating_add(self.body_ns)
    }

    /// Mean 1-based rank of winning cand (0 if no hits).
    pub fn hit_rank_avg(&self) -> f64 {
        if self.hit_rank_n == 0 {
            0.0
        } else {
            self.hit_rank_sum as f64 / self.hit_rank_n as f64
        }
    }

    /// Total histogram counts (should match resolved hits when fully instrumented).
    pub fn age_hit_n(&self) -> u64 {
        self.age_hit.iter().copied().sum()
    }

    /// Fraction of winner hits with sealed_age ≤ `k` (0.0 if no hits).
    ///
    /// Under ages≤3 hot policy, `age_cdf(3)` ≈ wave1 hit fraction among resolved keys.
    pub fn age_cdf(&self, k: u32) -> f64 {
        let n = self.age_hit_n();
        if n == 0 {
            return 0.0;
        }
        let mut sum = 0u64;
        let last = (k as usize).min(AGE_CAP - 1);
        for i in 0..=last {
            sum = sum.saturating_add(self.age_hit[i]);
        }
        sum as f64 / n as f64
    }

    /// Integer percent for logs: `round(100 * age_cdf(k))`.
    pub fn age_cdf_pct(&self, k: u32) -> u64 {
        (self.age_cdf(k) * 100.0).round() as u64
    }

    /// Compact `h0:h1:…:h7+tail` (first 8 ages + sum of the rest).
    pub fn age_hit_compact(&self) -> String {
        let mut parts = Vec::with_capacity(9);
        for i in 0..8.min(AGE_CAP) {
            parts.push(self.age_hit[i].to_string());
        }
        let mut tail = 0u64;
        for i in 8..AGE_CAP {
            tail = tail.saturating_add(self.age_hit[i]);
        }
        parts.push(tail.to_string());
        parts.join(":")
    }
}

/// Sealed age from tip for segment index `si` in a vec of `n_segs` (last = tip).
///
/// Used by the two-wave probe split and winner-age stats.
#[inline]
pub fn sealed_age_from_index(si: usize, n_segs: usize) -> u32 {
    n_segs.saturating_sub(1).saturating_sub(si) as u32
}

/// Map `create_fk` → sealed-age from tip using segment `first_fk` boundaries.
///
/// `first_fks[si]` is the inclusive start of segment `si` (last = open/tip).
/// Returns `None` if `fk` is zero or below the first segment.
#[inline]
pub fn sealed_age_for_fk(first_fks: &[u64], fk: u64) -> Option<u32> {
    if first_fks.is_empty() || fk == 0 {
        return None;
    }
    let mut lo = 0usize;
    let mut hi = first_fks.len();
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if first_fks[mid] <= fk {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    if first_fks[lo] > fk {
        return None;
    }
    Some(sealed_age_from_index(lo, first_fks.len()))
}

/// Bucket index for a sealed-age (ages ≥ CAP−1 share the last bucket).
#[inline]
pub fn age_bucket(age: u32) -> usize {
    (age as usize).min(AGE_CAP - 1)
}

#[inline]
pub fn add_probe(ns: u64) {
    if ns > 0 {
        PROBE_NS.fetch_add(ns, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_idx(ns: u64) {
    if ns > 0 {
        IDX_NS.fetch_add(ns, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_body(ns: u64) {
    if ns > 0 {
        BODY_NS.fetch_add(ns, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_keys(n: u64) {
    if n > 0 {
        KEYS.fetch_add(n, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_cands(n: u64) {
    if n > 0 {
        CANDS.fetch_add(n, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_body_lookups(n: u64) {
    if n > 0 {
        BODY_LOOKUPS.fetch_add(n, Ordering::Relaxed);
    }
}

/// Record a resolved key: `rank` is 1-based index in probe/body order of the match.
#[inline]
pub fn add_hit_rank(rank: u64) {
    if rank > 0 {
        HIT_RANK_SUM.fetch_add(rank, Ordering::Relaxed);
        HIT_RANK_N.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record one winner at sealed-age `age` (tip-relative).
#[inline]
pub fn add_hit_age(age: u32) {
    AGE_HIT[age_bucket(age)].fetch_add(1, Ordering::Relaxed);
}

/// Flush a batch-local age histogram into process counters.
#[inline]
pub fn add_hit_ages(local: &[u64; AGE_CAP]) {
    for (i, &n) in local.iter().enumerate() {
        if n > 0 {
            AGE_HIT[i].fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Note winner age into a batch-local hist (no atomics until [`add_hit_ages`]).
#[inline]
pub fn note_local_hit_age(local: &mut [u64; AGE_CAP], first_fks: &[u64], fk: u64) {
    if let Some(age) = sealed_age_for_fk(first_fks, fk) {
        local[age_bucket(age)] = local[age_bucket(age)].saturating_add(1);
    }
}

#[inline]
pub fn add_miss_peeks(n: u64) {
    if n > 0 {
        MISS_PEEKS.fetch_add(n, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_pending_hit(n: u64) {
    if n > 0 {
        PENDING_HITS.fetch_add(n, Ordering::Relaxed);
    }
}

pub fn sample_and_reset() -> Sample {
    let mut age_hit = [0u64; AGE_CAP];
    for (i, slot) in AGE_HIT.iter().enumerate() {
        age_hit[i] = slot.swap(0, Ordering::Relaxed);
    }
    Sample {
        probe_ns: PROBE_NS.swap(0, Ordering::Relaxed),
        idx_ns: IDX_NS.swap(0, Ordering::Relaxed),
        body_ns: BODY_NS.swap(0, Ordering::Relaxed),
        keys: KEYS.swap(0, Ordering::Relaxed),
        cands: CANDS.swap(0, Ordering::Relaxed),
        body_lookups: BODY_LOOKUPS.swap(0, Ordering::Relaxed),
        hit_rank_sum: HIT_RANK_SUM.swap(0, Ordering::Relaxed),
        hit_rank_n: HIT_RANK_N.swap(0, Ordering::Relaxed),
        miss_peeks: MISS_PEEKS.swap(0, Ordering::Relaxed),
        pending_hits: PENDING_HITS.swap(0, Ordering::Relaxed),
        age_hit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure Sample math (no process atomics — safe under parallel cargo test).
    #[test]
    fn sample_age_cdf_and_compact() {
        let mut s = Sample::default();
        s.age_hit[0] = 2;
        s.age_hit[3] = 1;
        s.age_hit[AGE_CAP - 1] = 1;
        assert_eq!(s.age_hit_n(), 4);
        assert!((s.age_cdf(0) - 0.5).abs() < 1e-9);
        assert!((s.age_cdf(3) - 0.75).abs() < 1e-9);
        assert!((s.age_cdf(47) - 1.0).abs() < 1e-9);
        assert_eq!(s.age_cdf_pct(3), 75);
        assert!(s.age_hit_compact().starts_with("2:0:0:1:"));
        s.hit_rank_sum = 4;
        s.hit_rank_n = 2;
        assert!((s.hit_rank_avg() - 2.0).abs() < 1e-9);
        s.probe_ns = 10;
        s.idx_ns = 20;
        s.body_ns = 30;
        assert_eq!(s.sum_ns(), 60);
        let empty = Sample::default();
        assert_eq!(empty.age_cdf(3), 0.0);
        assert_eq!(empty.age_hit_n(), 0);
    }

    #[test]
    fn sealed_age_for_fk_binary_search() {
        // segs: [1, 100, 200] → ages from tip: si0 age2, si1 age1, si2 age0
        let first = [1u64, 100, 200];
        assert_eq!(sealed_age_for_fk(&first, 0), None);
        assert_eq!(sealed_age_for_fk(&first, 1), Some(2));
        assert_eq!(sealed_age_for_fk(&first, 99), Some(2));
        assert_eq!(sealed_age_for_fk(&first, 100), Some(1));
        assert_eq!(sealed_age_for_fk(&first, 199), Some(1));
        assert_eq!(sealed_age_for_fk(&first, 200), Some(0));
        assert_eq!(sealed_age_for_fk(&first, 999_999), Some(0));
        assert_eq!(sealed_age_for_fk(&[], 1), None);
        assert_eq!(sealed_age_from_index(5, 6), 0);
        assert_eq!(sealed_age_from_index(0, 6), 5);
        assert_eq!(sealed_age_from_index(2, 6), 3);
        assert_eq!(sealed_age_from_index(0, 0), 0);
        assert_eq!(age_bucket(0), 0);
        assert_eq!(age_bucket(3), 3);
        assert_eq!(age_bucket(100), AGE_CAP - 1);
    }

    #[test]
    fn note_local_hit_age_buckets() {
        let first = [1u64, 50, 100];
        let mut local = [0u64; AGE_CAP];
        note_local_hit_age(&mut local, &first, 10); // age 2
        note_local_hit_age(&mut local, &first, 60); // age 1
        note_local_hit_age(&mut local, &first, 100); // age 0
        note_local_hit_age(&mut local, &first, 100); // age 0
        note_local_hit_age(&mut local, &first, 0); // ignore
        assert_eq!(local[0], 2);
        assert_eq!(local[1], 1);
        assert_eq!(local[2], 1);
        assert_eq!(local.iter().sum::<u64>(), 4);
        // Flush path is best-effort under parallel tests; still exercise the API.
        add_hit_ages(&local);
        add_hit_age(7);
        let _ = sample_and_reset();
    }

    fn dummy_probe_diag(txid: [u8; 32]) -> LeftoverProbeDiag {
        LeftoverProbeDiag {
            txid,
            mixed_prefix: [0; 8],
            page_base: 0,
            bits: 16,
            file_id: 0,
            first_fk: 1,
            sealed_age: None,
            hit_empty: true,
            depth_end: 0,
            empty_local: 0,
            page_occupied: 0,
            hop_equal_second: true,
            cands: Vec::new(),
        }
    }

    /// Next resolve batch (`clear_leftover_miss`) must not drop a leftover hop-dump.
    /// Parallel `get_fk_by_txid_batch` used to wipe `diag=1` before the pin.
    #[test]
    fn clear_leftover_miss_keeps_probe_diag() {
        let ghost = [0xEEu8; 32];
        note_leftover_probe_diag(dummy_probe_diag(ghost));
        note_leftover_miss(LeftoverMissOn::Head, 3);
        clear_leftover_miss();
        assert!(
            take_leftover_miss().is_none(),
            "miss class is per resolve batch"
        );
        assert!(
            leftover_probe_diag_recorded(&ghost),
            "hop-dump txid must survive the next resolve clear"
        );
    }
}
