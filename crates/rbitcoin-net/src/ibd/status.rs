//! IBD main-loop timers and sample (status / perf_log).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Main-loop hot-path timers (atomics; reset every status sample).
///
/// Used to see whether the pegged core is Class C confirm, getdata assign,
/// event drain, or the status scan itself.
///
/// **Live confirm:** `confirm_ns` accrues when a **script** batch finishes.
/// It is **script-stage work only** (not lookup stamp, not load pin/assemble, not write).
/// Lookup/load/write walls live on `Query::confirm_stats` (sampled by `perf_log`).
/// During lookup/load claim, [`Self::confirm_live`] shows in-progress stage wall.
pub(crate) struct LoopStats {
    /// Pure script-stage wall for completed script batches (excludes lookup/load/write).
    pub(crate) confirm_ns: AtomicU64,
    /// Successful tip accepts this window.
    pub(crate) confirm_blocks: AtomicU64,
    /// Times confirm stopped on a non-skippable reject.
    pub(crate) confirm_reject_stops: AtomicU64,
    /// Wall time in `assign_work_ordered`.
    pub(crate) assign_ns: AtomicU64,
    /// Unique hashes put into getdata this window.
    pub(crate) assign_issued: AtomicU64,
    /// Wall time draining peer/archive channels.
    pub(crate) drain_ns: AtomicU64,
    /// Peer + archive events applied this window.
    pub(crate) drain_events: AtomicU64,
    /// Wall time building the status `work_chain_progress` snapshot.
    pub(crate) status_scan_ns: AtomicU64,
    /// Class A bodies published this run (any height; cumulative).
    /// Includes gap-fills below the archive high-water mark — not just HWM rises.
    pub(crate) archived_bodies: AtomicU64,
    /// In-flight confirm batch (set by confirm OS thread; status only).
    confirm_live: Mutex<Option<ConfirmLive>>,
}

#[derive(Clone, Copy, Debug)]
struct ConfirmLive {
    first_height: u32,
    batch_n: u32,
    /// Σ tx.input count over the packed batch (confirm-side pack).
    batch_inputs: u32,
    started: Instant,
}

impl Default for LoopStats {
    fn default() -> Self {
        Self {
            confirm_ns: AtomicU64::new(0),
            confirm_blocks: AtomicU64::new(0),
            confirm_reject_stops: AtomicU64::new(0),
            assign_ns: AtomicU64::new(0),
            assign_issued: AtomicU64::new(0),
            drain_ns: AtomicU64::new(0),
            drain_events: AtomicU64::new(0),
            status_scan_ns: AtomicU64::new(0),
            archived_bodies: AtomicU64::new(0),
            confirm_live: Mutex::new(None),
        }
    }
}

impl LoopStats {
    pub(crate) fn confirm_begin(&self, first_height: u32, batch_n: u32, batch_inputs: u32) {
        *self.confirm_live.lock().unwrap() = Some(ConfirmLive {
            first_height,
            batch_n,
            batch_inputs,
            started: Instant::now(),
        });
    }

    pub(crate) fn confirm_end(&self) {
        *self.confirm_live.lock().unwrap() = None;
    }

    /// `(first_height, batch_n, batch_inputs, elapsed_ms)` if a confirm batch is running.
    pub(crate) fn confirm_live_snap(&self) -> Option<(u32, u32, u32, u64)> {
        self.confirm_live.lock().unwrap().as_ref().map(|l| {
            (
                l.first_height,
                l.batch_n,
                l.batch_inputs,
                l.started.elapsed().as_millis() as u64,
            )
        })
    }

    pub(crate) fn sample_and_reset(&self) -> LoopSample {
        LoopSample {
            confirm_ns: self.confirm_ns.swap(0, Ordering::Relaxed),
            confirm_blocks: self.confirm_blocks.swap(0, Ordering::Relaxed),
            confirm_reject_stops: self.confirm_reject_stops.swap(0, Ordering::Relaxed),
            assign_ns: self.assign_ns.swap(0, Ordering::Relaxed),
            assign_issued: self.assign_issued.swap(0, Ordering::Relaxed),
            drain_ns: self.drain_ns.swap(0, Ordering::Relaxed),
            drain_events: self.drain_events.swap(0, Ordering::Relaxed),
            status_scan_ns: self.status_scan_ns.swap(0, Ordering::Relaxed),
            confirm_live: self.confirm_live_snap(),
        }
    }
}

pub(crate) struct LoopSample {
    pub(crate) confirm_ns: u64,
    pub(crate) confirm_blocks: u64,
    pub(crate) confirm_reject_stops: u64,
    pub(crate) assign_ns: u64,
    pub(crate) assign_issued: u64,
    pub(crate) drain_ns: u64,
    pub(crate) drain_events: u64,
    pub(crate) status_scan_ns: u64,
    /// Live batch if confirm engine is mid-`confirm_run`:
    /// `(first_height, batch_n, batch_inputs, elapsed_ms)`.
    pub(crate) confirm_live: Option<(u32, u32, u32, u64)>,
}

impl LoopSample {
    fn ms(ns: u64) -> u64 {
        ns / 1_000_000
    }
    pub(crate) fn confirm_ms(&self) -> u64 {
        Self::ms(self.confirm_ns)
    }
    pub(crate) fn assign_ms(&self) -> u64 {
        Self::ms(self.assign_ns)
    }
    pub(crate) fn drain_ms(&self) -> u64 {
        Self::ms(self.drain_ns)
    }
    pub(crate) fn status_scan_ms(&self) -> u64 {
        Self::ms(self.status_scan_ns)
    }
    pub(crate) fn confirm_us_per_block(&self) -> u64 {
        self.confirm_ns
            .checked_div(self.confirm_blocks)
            .unwrap_or(0)
            / 1000
    }
    /// Which phase dominated wall time this window (for one-glance diagnosis).
    pub(crate) fn dominant(&self) -> &'static str {
        // Completed-batch timer is 0 while a batch is still running — treat live as confirm.
        if self.confirm_live.is_some() && self.confirm_ns == 0 {
            return "confirm";
        }
        let c = self.confirm_ns;
        let a = self.assign_ns;
        let d = self.drain_ns;
        let s = self.status_scan_ns;
        let m = c.max(a).max(d).max(s);
        if m == 0 {
            "idle"
        } else if m == c {
            "confirm"
        } else if m == a {
            "assign"
        } else if m == d {
            "drain"
        } else {
            "status_scan"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn loop_stats_sample_dominant_and_live() {
        let s = LoopStats::default();
        assert!(s.confirm_live_snap().is_none());
        s.confirm_begin(10, 4, 100);
        let live = s.confirm_live_snap().unwrap();
        assert_eq!(live.0, 10);
        assert_eq!(live.1, 4);
        assert_eq!(live.2, 100);
        std::thread::sleep(Duration::from_millis(2));
        let sample = s.sample_and_reset();
        assert!(sample.confirm_live.is_some());
        assert_eq!(sample.dominant(), "confirm"); // live with 0 ns → confirm
        s.confirm_end();
        assert!(s.confirm_live_snap().is_none());

        s.confirm_ns.store(5_000_000, Ordering::Relaxed);
        s.confirm_blocks.store(2, Ordering::Relaxed);
        s.assign_ns.store(1_000_000, Ordering::Relaxed);
        s.assign_issued.store(3, Ordering::Relaxed);
        s.drain_ns.store(500_000, Ordering::Relaxed);
        s.drain_events.store(9, Ordering::Relaxed);
        s.status_scan_ns.store(100_000, Ordering::Relaxed);
        s.confirm_reject_stops.store(1, Ordering::Relaxed);
        let sample = s.sample_and_reset();
        assert_eq!(sample.confirm_blocks, 2);
        assert_eq!(sample.confirm_ms(), 5);
        assert_eq!(sample.assign_ms(), 1);
        assert!(sample.drain_ms() <= 1);
        assert_eq!(sample.status_scan_ms(), 0);
        assert_eq!(sample.confirm_us_per_block(), 2500);
        assert_eq!(sample.dominant(), "confirm");
        assert_eq!(sample.confirm_reject_stops, 1);
        // Reset clears counters.
        let z = s.sample_and_reset();
        assert_eq!(z.confirm_ns, 0);
        assert_eq!(z.dominant(), "idle");

        s.assign_ns.store(9_000_000, Ordering::Relaxed);
        assert_eq!(s.sample_and_reset().dominant(), "assign");
        s.drain_ns.store(9_000_000, Ordering::Relaxed);
        assert_eq!(s.sample_and_reset().dominant(), "drain");
        s.status_scan_ns.store(9_000_000, Ordering::Relaxed);
        assert_eq!(s.sample_and_reset().dominant(), "status_scan");
    }
}
