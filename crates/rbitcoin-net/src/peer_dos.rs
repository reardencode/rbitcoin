//! Per-peer DoS controls: message/byte rate windows and inbound connection caps.
//!
//! These are **not** Bitcoin Core banlist parity — they bound cheap resource abuse
//! (flooding messages or multi-MB frames) with disconnect when thresholds trip.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Default max concurrent **inbound** P2P sessions (post-handshake work).
pub const DEFAULT_MAX_INBOUND: usize = 125;
/// Sliding window for rate accounting.
pub const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Max application messages per peer per window (after decrypt/frame).
///
/// Tip mempool sync and compact-block reconstruction can burst many small inv /
/// getdata / tx messages; 200/s was disconnecting useful peers (log: rate limit
/// ban_score 50→100). 4k/s matches a healthy Core peer under load without
/// inviting pure message-spam (byte budget still bounds bulk).
pub const DEFAULT_MAX_MSGS_PER_SEC: u32 = 4_000;
/// Max framed payload bytes per peer per window (BIP324 contents size).
/// ~16 MiB/s: enough for concurrent block + tx relay; still caps multi-peer floods.
pub const DEFAULT_MAX_BYTES_PER_SEC: u64 = 16_000_000;
/// Ban score added when a peer exceeds rate limits (disconnect at 100).
pub const RATE_LIMIT_BAN_SCORE: u32 = 50;
/// Ban score for oversized protocol messages already rejected as MessageTooLarge.
pub const OVERSIZE_BAN_SCORE: u32 = 100;

/// Process-wide inbound session slots.
pub fn inbound_semaphore(max: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max.max(1)))
}

/// Per-session sliding-window message and byte counters.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    window_start: Instant,
    msgs: u32,
    bytes: u64,
    max_msgs: u32,
    max_bytes: u64,
}

impl PeerRateLimiter {
    pub fn new(max_msgs: u32, max_bytes: u64) -> Self {
        Self {
            window_start: Instant::now(),
            msgs: 0,
            bytes: 0,
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
        let now = Instant::now();
        if now.duration_since(self.window_start) >= RATE_WINDOW {
            self.window_start = now;
            self.msgs = 0;
            self.bytes = 0;
        }
        let next_msgs = self.msgs.saturating_add(1);
        let next_bytes = self.bytes.saturating_add(payload_len as u64);
        if next_msgs > self.max_msgs || next_bytes > self.max_bytes {
            return false;
        }
        self.msgs = next_msgs;
        self.bytes = next_bytes;
        true
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
    fn rate_limiter_window_resets() {
        let mut r = PeerRateLimiter::new(2, 10_000);
        assert!(r.note(1));
        assert!(r.note(1));
        assert!(!r.note(1));
        // Simulate window expiry.
        r.window_start = Instant::now() - RATE_WINDOW - Duration::from_millis(1);
        assert!(r.note(1));
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
