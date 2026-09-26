//! Node clock for consensus / generate. Mock time is **not** a process `time()` hook.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since epoch. `mock == 0` means wall clock.
#[derive(Debug)]
pub struct NodeClock {
    mock: AtomicI64,
}

impl NodeClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mock: AtomicI64::new(0),
        })
    }

    pub fn now_secs(&self) -> u64 {
        let m = self.mock.load(Ordering::Relaxed);
        if m > 0 {
            m as u64
        } else {
            wall_now()
        }
    }

    /// `0` restores wall clock. Negative is rejected by RPC.
    pub fn set_mock(&self, t: i64) {
        self.mock.store(t.max(0), Ordering::SeqCst);
    }
}

pub fn wall_now() -> u64 {
    unix_secs(SystemTime::now())
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

thread_local! {
    static NOW_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Scoped override for consensus header/time checks (does not affect log stamps).
pub fn with_now<T>(now: u64, f: impl FnOnce() -> T) -> T {
    NOW_OVERRIDE.with(|c| {
        let prev = c.replace(Some(now));
        let out = f();
        c.set(prev);
        out
    })
}

pub fn current_now() -> u64 {
    NOW_OVERRIDE.with(|c| c.get()).unwrap_or_else(wall_now)
}

impl NodeClock {
    /// Freeze wall time to a consistent value for the duration of `f`.
    /// All `now_secs()` calls inside `f` return the same instant.
    /// Restored when `f` exits — synchronous only, does not persist across .await.
    pub fn with_frozen<R>(&self, f: impl FnOnce() -> R) -> R {
        let frozen = self.now_secs();
        with_now(frozen, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_then_wall() {
        let c = NodeClock::new();
        c.set_mock(1_700_000_000);
        assert_eq!(c.now_secs(), 1_700_000_000);
        c.set_mock(0);
        assert!(c.now_secs() >= 1_700_000_000 || c.now_secs() > 1_600_000_000);
    }

    #[test]
    fn with_now_scopes() {
        assert!(current_now() > 0);
        with_now(42, || assert_eq!(current_now(), 42));
        assert_ne!(current_now(), 42);
    }

    #[test]
    fn unix_secs_epoch_is_zero() {
        assert_eq!(unix_secs(UNIX_EPOCH), 0);
    }

    #[test]
    #[should_panic(expected = "system clock before Unix epoch")]
    fn unix_secs_panics_before_epoch() {
        unix_secs(UNIX_EPOCH - std::time::Duration::from_secs(1));
    }

    #[test]
    fn with_frozen_uses_current_now_restores_prior() {
        let c = NodeClock::new();
        c.set_mock(1_000_000_000);

        c.set_mock(2_000_000_000);
        c.with_frozen(|| {
            assert_eq!(
                current_now(),
                2_000_000_000,
                "frozen value visible via current_now() inside closure"
            );
        });

        assert_eq!(
            c.now_secs(),
            2_000_000_000,
            "outer mock value unchanged after scope"
        );
    }
}
