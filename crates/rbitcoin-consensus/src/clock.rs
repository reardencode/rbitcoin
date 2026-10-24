//! Node clock for consensus / generate. Mock time is **not** a process `time()` hook.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since epoch. `mock == 0` means wall clock.
#[derive(Debug)]
pub struct NodeClock {
    pub mock: AtomicI64,
    /// Outbound dial this clock is measuring. `0` means none since startup
    /// or since [`Self::forget_connection_attempt`].
    /// A later [`Self::set_mock`] does not move it.
    pub attempt_at: AtomicU64,
}

impl NodeClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mock: AtomicI64::new(0),
            attempt_at: AtomicU64::new(0),
        })
    }

    /// Remember an outbound dial when none is stored. Later calls keep that
    /// sample, so a `setmocktime` afterwards still measures from the dial.
    /// [`Self::forget_connection_attempt`] lets the next call record again.
    pub fn note_connection_attempt(&self) {
        let now = self.now_secs().max(1);
        let _ = self
            .attempt_at
            .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Drop the stored dial so the next [`Self::note_connection_attempt`]
    /// records again.
    pub fn forget_connection_attempt(&self) {
        self.attempt_at.store(0, Ordering::SeqCst);
    }

    /// `0` until [`Self::note_connection_attempt`].
    pub fn connection_attempt_at(&self) -> u64 {
        self.attempt_at.load(Ordering::SeqCst)
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

    /// Run `f` with [`current_now`] pinned to one sample of this clock
    /// (see [`with_now`]). [`Self::now_secs`] is not pinned. The prior
    /// override returns when `f` exits; the scope is synchronous and does not
    /// span an `.await`.
    pub fn with_frozen<R>(&self, f: impl FnOnce() -> R) -> R {
        with_now(self.now_secs(), f)
    }
}

pub fn wall_now() -> u64 {
    unix_secs(SystemTime::now())
}

#[doc(hidden)]
pub fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

/// Wall clock in milliseconds. A clock before the epoch is 0.
#[doc(hidden)]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
