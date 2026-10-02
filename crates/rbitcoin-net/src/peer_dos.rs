//! Per-peer DoS controls: message/byte rate windows and inbound connection caps.
//!
//! These are **not** Bitcoin Core banlist parity — they bound cheap resource abuse
//! (flooding messages or multi-MB frames) with disconnect when thresholds trip.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Default max concurrent **inbound** P2P sessions (post-handshake work).
pub const DEFAULT_MAX_INBOUND: usize = 125;
/// One-second rate window (current second plus the previous second).
pub const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Max application messages per peer per window (after decrypt/frame).
///
/// Tip mempool sync and compact-block reconstruction can burst many small inv /
/// getdata / tx messages; 200/s was disconnecting useful peers. 4k/s matches a
/// healthy peer under load without inviting pure message-spam (byte budget
/// still bounds bulk).
pub const DEFAULT_MAX_MSGS_PER_SEC: u32 = 4_000;
/// Max framed payload bytes per peer per window (BIP324 contents size).
/// ~16 MiB/s: enough for concurrent block + tx relay; still caps multi-peer floods.
pub const DEFAULT_MAX_BYTES_PER_SEC: u64 = 16_000_000;
/// Disconnect score added when a peer exceeds rate limits (disconnect at 100).
pub const RATE_LIMIT_BAN_SCORE: u32 = 50;
/// Disconnect score for oversized protocol messages already rejected as MessageTooLarge.
pub const OVERSIZE_BAN_SCORE: u32 = 100;

/// Process-wide inbound session slots.
pub fn inbound_semaphore(max: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max.max(1)))
}

/// Per-session message and byte counters.
///
/// Two buckets (the current second and the previous one). A note weighs the
/// previous bucket by how much of it is still inside the one-second window.
/// No per-message allocation. A tumbling reset granted a second full budget
/// at the boundary.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    current_start: Instant,
    cur_msgs: u32,
    cur_bytes: u64,
    prev_msgs: u32,
    prev_bytes: u64,
    max_msgs: u32,
    max_bytes: u64,
}

impl PeerRateLimiter {
    pub fn new(max_msgs: u32, max_bytes: u64) -> Self {
        Self {
            current_start: Instant::now(),
            cur_msgs: 0,
            cur_bytes: 0,
            prev_msgs: 0,
            prev_bytes: 0,
            max_msgs: max_msgs.max(1),
            max_bytes: max_bytes.max(1),
        }
    }

    pub fn default_limits() -> Self {
        Self::new(DEFAULT_MAX_MSGS_PER_SEC, DEFAULT_MAX_BYTES_PER_SEC)
    }

    /// Record one framed message of `payload_len` bytes.
    /// Returns `false` if this message would exceed the window budget.
    pub fn note(&mut self, payload_len: usize) -> bool {
        self.note_at(payload_len, Instant::now())
    }

    /// Same as [`Self::note`] at a chosen instant. Tests pin the window edge.
    pub fn note_at(&mut self, payload_len: usize, now: Instant) -> bool {
        self.roll(now);
        let elapsed_ms = now
            .saturating_duration_since(self.current_start)
            .as_millis()
            .min(1_000) as u64;
        let prev_weight = 1_000 - elapsed_ms;
        let eff_msgs = u64::from(self.cur_msgs)
            + (u64::from(self.prev_msgs) * prev_weight) / 1_000;
        let eff_bytes = self.cur_bytes + (self.prev_bytes * prev_weight) / 1_000;
        let next_msgs = eff_msgs.saturating_add(1);
        let next_bytes = eff_bytes.saturating_add(payload_len as u64);
        if next_msgs > u64::from(self.max_msgs) || next_bytes > self.max_bytes {
            return false;
        }
        self.cur_msgs = self.cur_msgs.saturating_add(1);
        self.cur_bytes = self.cur_bytes.saturating_add(payload_len as u64);
        true
    }

    fn roll(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.current_start);
        if elapsed < RATE_WINDOW {
            return;
        }
        if elapsed >= RATE_WINDOW + RATE_WINDOW {
            self.prev_msgs = 0;
            self.prev_bytes = 0;
            self.cur_msgs = 0;
            self.cur_bytes = 0;
            self.current_start = now;
            return;
        }
        self.prev_msgs = self.cur_msgs;
        self.prev_bytes = self.cur_bytes;
        self.cur_msgs = 0;
        self.cur_bytes = 0;
        self.current_start += RATE_WINDOW;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_under_budget() {
        let mut r = PeerRateLimiter::new(10, 1000);
        for _ in 0..10 {
            assert!(r.note(50));
        }
        assert!(!r.note(1), "11th message must trip msg limit");
    }

    #[test]
    fn rate_limiter_bytes_cap() {
        let mut r = PeerRateLimiter::new(1000, 100);
        assert!(r.note(100));
        assert!(!r.note(1));
    }

    #[test]
    fn rate_limiter_boundary_does_not_grant_a_second_budget() {
        let mut r = PeerRateLimiter::new(2, 10_000);
        let t0 = Instant::now();
        assert!(r.note_at(1, t0));
        assert!(r.note_at(1, t0));
        assert!(!r.note_at(1, t0));
        let boundary = t0 + RATE_WINDOW;
        assert!(
            !r.note_at(1, boundary),
            "a full previous second must not grant another budget at the boundary"
        );
        let cleared = t0 + RATE_WINDOW + RATE_WINDOW + Duration::from_millis(1);
        assert!(r.note_at(1, cleared));
        assert!(r.note_at(1, cleared));
        assert!(!r.note_at(1, cleared));
    }

    #[test]
    fn rate_limiter_window_resets() {
        let mut r = PeerRateLimiter::new(2, 10_000);
        let t0 = Instant::now();
        assert!(r.note_at(1, t0));
        assert!(r.note_at(1, t0));
        assert!(!r.note_at(1, t0));
        let cleared = t0 + RATE_WINDOW + RATE_WINDOW + Duration::from_millis(1);
        assert!(r.note_at(1, cleared));
    }

    #[test]
    fn max_inbound_env_default() {
        // Do not mutate env in parallel tests; just check parse of default path.
        const {
            assert!(DEFAULT_MAX_INBOUND >= 1);
        }
        assert_eq!(RATE_LIMIT_BAN_SCORE, 50);
        assert_eq!(OVERSIZE_BAN_SCORE, 100);
    }
}
