//! Body-queue soft densify assign policy (IBD getdata window).

/// Soft assign free floor (~100 MiB). Under this payload size, densify uses the
/// usual ahead horizon (net-side densify cap). Over it, densify is limited to
/// the confirm-time window ([`BQ_SOFT_CONFIRM_SECS`]).
///
/// Tunable constant — no hysteresis band (single threshold).
pub const BQ_SOFT_FREE_BYTES: u64 = 100 * 1024 * 1024;

/// When body-queue payload is over [`BQ_SOFT_FREE_BYTES`], only assign getdata
/// for heights confirm will consume in this many seconds at the current tip
/// rate. Tunable constant — no hysteresis band.
pub const BQ_SOFT_CONFIRM_SECS: f64 = 60.0;

/// Default densify assign-stop (1 GiB). At/over this, densify only holes within
/// the ~1 min tip-rate confirm window **and** not past `fetched_hi` (do not grow
/// past fetched; do not densify far holes outside the window). Override with
/// `RBITCOIN_BLOCK_QUEUE_BYTES` / `_GB` (`0` = unlimited).
pub const BQ_ASSIGN_STOP_BYTES: u64 = 1024 * 1024 * 1024;

/// Blocks confirm can take in one soft confirm window at `rate` (ceil).
///
/// Rate unknown / non-positive → `0` (no densify ahead when restricted).
pub fn soft_confirm_window_n(rate_blocks_per_s: Option<f64>) -> u32 {
    let rate = rate_blocks_per_s
        .filter(|r| r.is_finite() && *r > 1e-9)
        .unwrap_or(0.0);
    (rate * BQ_SOFT_CONFIRM_SECS).ceil() as u32
}

/// True when BQ payload is over the free-byte floor (densify uses confirm window).
#[inline]
pub fn soft_assign_restricted(depth_bytes: u64) -> bool {
    depth_bytes > BQ_SOFT_FREE_BYTES
}

/// True when BQ payload is at/over the densify assign-stop (`0` / `u64::MAX` = off).
#[inline]
pub fn soft_assign_stopped(depth_bytes: u64, stop_bytes: u64) -> bool {
    stop_bytes != 0 && stop_bytes != u64::MAX && depth_bytes >= stop_bytes
}

/// Assign-stop from env, or [`BQ_ASSIGN_STOP_BYTES`]. `_BYTES` wins over `_GB`.
/// `0` means unlimited (`u64::MAX`). Invalid parse falls through.
pub fn bq_assign_stop_bytes() -> u64 {
    if let Ok(s) = std::env::var("RBITCOIN_BLOCK_QUEUE_BYTES") {
        if let Ok(n) = s.parse::<u64>() {
            return if n == 0 { u64::MAX } else { n };
        }
    }
    if let Ok(s) = std::env::var("RBITCOIN_BLOCK_QUEUE_GB") {
        if let Ok(n) = s.parse::<u64>() {
            return if n == 0 {
                u64::MAX
            } else {
                n.saturating_mul(1024 * 1024 * 1024)
            };
        }
    }
    BQ_ASSIGN_STOP_BYTES
}

/// Inclusive densify band high height for getdata assign.
///
/// - **At/over** `assign_stop_bytes`: holes only within the ~1 min tip-rate
///   confirm window **and** not past `fetched_hi` (do not grow past fetched;
///   do not densify far holes outside the window). No usable fetched range →
///   empty band.
/// - **Under** [`BQ_SOFT_FREE_BYTES`]: full `densify_hi` (usual densify ahead).
/// - **Over** free bytes (and under assign-stop): only heights confirm will
///   pick up within [`BQ_SOFT_CONFIRM_SECS`] at current rate —
///   `path_lo .. path_lo+window-1` (clamped to `densify_hi`). Rate cold →
///   only `path_lo` (tip-adjacent).
///
/// **Never** gates peer TCP reads or [`Query::block_queue_offer`].
pub fn soft_densify_band_hi(
    path_lo: u32,
    densify_hi: u32,
    depth_bytes: u64,
    rate_blocks_per_s: Option<f64>,
    assign_stop_bytes: u64,
    fetched_hi: Option<u32>,
) -> u32 {
    if densify_hi < path_lo {
        return densify_hi;
    }
    if soft_assign_stopped(depth_bytes, assign_stop_bytes) {
        let n = soft_confirm_window_n(rate_blocks_per_s);
        let window_hi = if n == 0 {
            path_lo.min(densify_hi)
        } else {
            path_lo.saturating_add(n.saturating_sub(1)).min(densify_hi)
        };
        return match fetched_hi {
            Some(h) if h >= path_lo => window_hi.min(h),
            _ => path_lo.saturating_sub(1),
        };
    }
    if !soft_assign_restricted(depth_bytes) {
        return densify_hi;
    }
    let n = soft_confirm_window_n(rate_blocks_per_s);
    if n == 0 {
        return path_lo.min(densify_hi);
    }
    path_lo.saturating_add(n.saturating_sub(1)).min(densify_hi)
}

/// True when over free bytes and the queue already holds at least one confirm
/// window of blocks (assign densify has little/no room left in the window).
///
/// Used for Critical assign (tip race only) when inflight is low.
pub fn soft_confirm_window_covered(
    depth_n: u32,
    depth_bytes: u64,
    rate_blocks_per_s: Option<f64>,
) -> bool {
    if !soft_assign_restricted(depth_bytes) {
        return false;
    }
    let w = soft_confirm_window_n(rate_blocks_per_s);
    if w == 0 {
        // Over free, rate unknown: treat as covered (no densify ahead).
        return true;
    }
    depth_n >= w
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_assign_stop_is_1gib() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_b = std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES");
        let prev_g = std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        assert_eq!(bq_assign_stop_bytes(), BQ_ASSIGN_STOP_BYTES);
        assert_eq!(BQ_ASSIGN_STOP_BYTES, 1024 * 1024 * 1024);
        match prev_b {
            Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", v),
            None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES"),
        }
        match prev_g {
            Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", v),
            None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB"),
        }
    }

    #[test]
    fn assign_stop_env_bytes_wins_zero_unlimited() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_b = std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES");
        let prev_g = std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", "2");
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "4096");
        assert_eq!(bq_assign_stop_bytes(), 4096);
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        assert_eq!(bq_assign_stop_bytes(), 2u64 * 1024 * 1024 * 1024);
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", "0");
        assert_eq!(bq_assign_stop_bytes(), u64::MAX);
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "0");
        assert_eq!(bq_assign_stop_bytes(), u64::MAX);
        match prev_b {
            Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", v),
            None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES"),
        }
        match prev_g {
            Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", v),
            None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB"),
        }
    }

    #[test]
    fn assign_stop_clamps_to_confirm_window_and_fetched() {
        let stop = 2048u64;
        let over = 4096u64;
        let free = BQ_SOFT_FREE_BYTES;
        assert_eq!(
            soft_densify_band_hi(1, 1000, 100, Some(5.0), stop, Some(80)),
            1000,
            "under assign-stop: full densify_hi"
        );
        assert_eq!(
            soft_densify_band_hi(1, 1000, free + 1, Some(0.1), BQ_ASSIGN_STOP_BYTES, Some(80)),
            6,
            "over free / under 1 GiB still uses confirm window"
        );
        // Over stop: min(confirm_window_hi, fetched_hi, densify_hi); rate 5 → window 300.
        assert_eq!(
            soft_densify_band_hi(1, 1000, over, Some(5.0), stop, Some(80)),
            80,
            "fetched_hi below window → fetched_hi"
        );
        assert_eq!(
            soft_densify_band_hi(1, 1000, over, Some(5.0), stop, Some(500)),
            300,
            "fetched_hi above window → confirm window, not fetched_hi"
        );
        assert_eq!(
            soft_densify_band_hi(1, 50, over, Some(5.0), stop, Some(80)),
            50,
            "densify_hi below fetched and window → densify_hi"
        );
        assert_eq!(
            soft_densify_band_hi(1, 1000, over, None, stop, Some(80)),
            1,
            "rate cold → path_lo only, not full fetched"
        );
        assert_eq!(
            soft_densify_band_hi(1, 1000, over, Some(5.0), stop, None),
            0,
            "no fetched range → empty densify band"
        );
        assert!(!soft_assign_stopped(over, 0));
        assert!(!soft_assign_stopped(over, u64::MAX));
        assert!(soft_assign_stopped(over, stop));
    }
}
