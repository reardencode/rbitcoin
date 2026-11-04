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
pub const ASSIGN_PERIOD: Duration = Duration::from_millis(50);
/// Stall + relative-slow disconnect + addr-cooldown expire.
pub const PEER_SLOW_PERIOD: Duration = Duration::from_secs(1);
/// Compact `ordered` ghosts and drop `height_to_hash` occupants at or below
/// the queue tail. The indexed header walk above the tail is not visited.
pub const HYGIENE_PERIOD: Duration = Duration::from_secs(1);
/// Chain-sized work-path prune (`IbdWorkState::deep_hygiene`). A minute apart.
/// The sweep itself runs only when a map is past its keep set.
pub const DEEP_HYGIENE_PERIOD: Duration = Duration::from_secs(60);
/// Main-loop `getheaders` poll (`locator_hashes` store walk).
/// Empty work path bypasses this (header sync must not wait).
pub const HEADERS_PERIOD: Duration = Duration::from_millis(500);

/// Last-run stamps for the IBD orchestration task.
#[derive(Debug, Default)]
pub struct IbdLoopCadence {
    pub last_assign: Option<Instant>,
    pub last_peer_slow: Option<Instant>,
    pub last_hygiene: Option<Instant>,
    pub last_deep_hygiene: Option<Instant>,
    pub last_headers: Option<Instant>,
}

impl IbdLoopCadence {
    pub fn new() -> Self {
        Self::default()
    }

    #[doc(hidden)]
    pub fn due(last: Option<Instant>, now: Instant, period: Duration) -> bool {
        last.is_none_or(|t| now.saturating_duration_since(t) >= period)
    }

    /// Assign on the first turn, every [`ASSIGN_PERIOD`], or immediately when
    /// inflight is empty (do not wait 50 ms to start getdata after headers).
    pub fn assign_due(&self, now: Instant, inflight_empty: bool) -> bool {
        inflight_empty || Self::due(self.last_assign, now, ASSIGN_PERIOD)
    }

    pub fn mark_assign(&mut self, now: Instant) {
        self.last_assign = Some(now);
    }

    pub fn peer_slow_due(&self, now: Instant) -> bool {
        Self::due(self.last_peer_slow, now, PEER_SLOW_PERIOD)
    }

    pub fn mark_peer_slow(&mut self, now: Instant) {
        self.last_peer_slow = Some(now);
    }

    /// Hygiene every [`HYGIENE_PERIOD`], or immediately when the ordered deque
    /// is bloated with ghosts.
    pub fn hygiene_due(&self, now: Instant, bloated: bool) -> bool {
        bloated || Self::due(self.last_hygiene, now, HYGIENE_PERIOD)
    }

    pub fn mark_hygiene(&mut self, now: Instant) {
        self.last_hygiene = Some(now);
    }

    /// Due every [`DEEP_HYGIENE_PERIOD`]. The sweep walks a map only when
    /// that map is past its keep set. Never per turn.
    pub fn deep_hygiene_due(&self, now: Instant) -> bool {
        Self::due(self.last_deep_hygiene, now, DEEP_HYGIENE_PERIOD)
    }

    pub fn mark_deep_hygiene(&mut self, now: Instant) {
        self.last_deep_hygiene = Some(now);
    }

    /// Header poll every [`HEADERS_PERIOD`], or immediately when the work path
    /// is empty or a block inv is waiting on headers.
    pub fn headers_due(&self, now: Instant, path_empty: bool, challenge_due: bool) -> bool {
        path_empty || challenge_due || Self::due(self.last_headers, now, HEADERS_PERIOD)
    }

    pub fn mark_headers(&mut self, now: Instant) {
        self.last_headers = Some(now);
    }
}
