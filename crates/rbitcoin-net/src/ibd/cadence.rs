//! Wall-clock cadence for IBD main-loop housekeeping.
//!
//! Peer frames (and the idle 50 ms keepalive) used to run **assign**,
//! peer-slow, work-path hygiene, and `getheaders` locator walks on every
//! turn. During IBD that is event-rate, not 20 Hz — densify scans and
//! `locator_hashes` store IO competed with confirm.
//!
//! Drain / confirm-offer stay event-driven. Housekeeping below is “good
//! enough” at these periods.

use std::time::{Duration, Instant};

/// Full/Critical getdata assign (densify walk, inflight prune).
pub(crate) const ASSIGN_PERIOD: Duration = Duration::from_millis(50);
/// Stall + relative-slow disconnect + addr-cooldown expire.
pub(crate) const PEER_SLOW_PERIOD: Duration = Duration::from_secs(1);
/// Compact `ordered` ghosts and retain work-path maps.
pub(crate) const HYGIENE_PERIOD: Duration = Duration::from_secs(1);
/// Main-loop `getheaders` poll (`locator_hashes` store walk).
/// Empty work path bypasses this (header sync must not wait).
pub(crate) const HEADERS_PERIOD: Duration = Duration::from_millis(500);

/// Last-run stamps for the IBD orchestration task.
#[derive(Debug, Default)]
pub(crate) struct IbdLoopCadence {
    last_assign: Option<Instant>,
    last_peer_slow: Option<Instant>,
    last_hygiene: Option<Instant>,
    last_headers: Option<Instant>,
}

impl IbdLoopCadence {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn due(last: Option<Instant>, now: Instant, period: Duration) -> bool {
        last.is_none_or(|t| now.saturating_duration_since(t) >= period)
    }

    /// Assign on the first turn, every [`ASSIGN_PERIOD`], or immediately when
    /// inflight is empty (do not wait 50 ms to start getdata after headers).
    pub(crate) fn assign_due(&self, now: Instant, inflight_empty: bool) -> bool {
        inflight_empty || Self::due(self.last_assign, now, ASSIGN_PERIOD)
    }

    pub(crate) fn mark_assign(&mut self, now: Instant) {
        self.last_assign = Some(now);
    }

    pub(crate) fn peer_slow_due(&self, now: Instant) -> bool {
        Self::due(self.last_peer_slow, now, PEER_SLOW_PERIOD)
    }

    pub(crate) fn mark_peer_slow(&mut self, now: Instant) {
        self.last_peer_slow = Some(now);
    }

    /// Hygiene every [`HYGIENE_PERIOD`], or immediately when the ordered deque
    /// is bloated with ghosts.
    pub(crate) fn hygiene_due(&self, now: Instant, bloated: bool) -> bool {
        bloated || Self::due(self.last_hygiene, now, HYGIENE_PERIOD)
    }

    pub(crate) fn mark_hygiene(&mut self, now: Instant) {
        self.last_hygiene = Some(now);
    }

    /// Header poll every [`HEADERS_PERIOD`], or immediately when the work path
    /// is empty (continuation of a live path stays event-driven in apply).
    pub(crate) fn headers_due(&self, now: Instant, path_empty: bool) -> bool {
        path_empty || Self::due(self.last_headers, now, HEADERS_PERIOD)
    }

    pub(crate) fn mark_headers(&mut self, now: Instant) {
        self.last_headers = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_due_first_then_period_unless_inflight_empty() {
        let mut c = IbdLoopCadence::new();
        let t0 = Instant::now();
        assert!(c.assign_due(t0, false), "first turn is due");
        c.mark_assign(t0);
        assert!(
            !c.assign_due(t0 + Duration::from_millis(49), false),
            "event-rate assign is the waste"
        );
        assert!(c.assign_due(t0 + ASSIGN_PERIOD, false));
        assert!(
            c.assign_due(t0 + Duration::from_millis(1), true),
            "empty inflight must not wait the period"
        );
    }

    #[test]
    fn peer_slow_is_one_second_not_every_turn() {
        let mut c = IbdLoopCadence::new();
        let t0 = Instant::now();
        assert!(c.peer_slow_due(t0));
        c.mark_peer_slow(t0);
        assert!(!c.peer_slow_due(t0 + Duration::from_millis(50)));
        assert!(!c.peer_slow_due(t0 + Duration::from_millis(999)));
        assert!(c.peer_slow_due(t0 + PEER_SLOW_PERIOD));
    }

    #[test]
    fn hygiene_period_or_bloated() {
        let mut c = IbdLoopCadence::new();
        let t0 = Instant::now();
        assert!(c.hygiene_due(t0, false));
        c.mark_hygiene(t0);
        assert!(!c.hygiene_due(t0 + Duration::from_millis(50), false));
        assert!(
            c.hygiene_due(t0 + Duration::from_millis(1), true),
            "ghost-bloated deque skips the wait"
        );
        assert!(c.hygiene_due(t0 + HYGIENE_PERIOD, false));
    }

    #[test]
    fn headers_period_or_empty_path() {
        let mut c = IbdLoopCadence::new();
        let t0 = Instant::now();
        assert!(c.headers_due(t0, false));
        c.mark_headers(t0);
        assert!(
            !c.headers_due(t0 + Duration::from_millis(50), false),
            "locator_hashes must not run on every frame"
        );
        assert!(
            c.headers_due(t0 + Duration::from_millis(1), true),
            "empty path header fan is immediate"
        );
        assert!(c.headers_due(t0 + HEADERS_PERIOD, false));
    }
}
