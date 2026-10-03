//! Live progress of long-running stages (index build, rebuild, backfill),
//! readable at any log level.
//!
//! The stages already compute `done/total` for their INFO lines; this keeps the
//! same numbers where the health listener (`GET /progress`, `/metrics`) can
//! read them, so an operator running at `warn` still sees where a multi-hour
//! build is. [`begin`] registers a stage and returns its guard; workers report
//! through the guard, and dropping it (done, error, cancel, or panic)
//! unregisters the stage and records its final numbers, which [`view`] reports
//! as the last finished stage. Stages that overlap keep separate counts. The
//! registry is per process: nodes sharing one process (tests) see each other's
//! stages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

struct Entry {
    stage: &'static str,
    total: u64,
    base: u64,
    started: Instant,
    started_at: SystemTime,
    done: AtomicU64,
}

impl Entry {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            stage: self.stage,
            done: self.done.load(Ordering::Relaxed),
            total: self.total,
            base: self.base,
            elapsed: self.started.elapsed(),
            started_at: self.started_at,
        }
    }
}

/// Running stages, oldest first, and the last one to end. One lock, so a
/// reader never sees a stage in neither place.
struct Registry {
    active: Vec<Arc<Entry>>,
    last_finished: Option<Snapshot>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    active: Vec::new(),
    last_finished: None,
});

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    static CAPTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CAPTURED: std::cell::RefCell<Vec<Snapshot>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Record the final numbers of stages that end on this thread, for
/// [`take_finished`]. Either call drops anything recorded before it. Off in
/// production; tests use it because the registry is process-global and other
/// tests run stages concurrently.
pub fn capture_finished(on: bool) {
    CAPTURE.with(|c| c.set(on));
    let _ = take_finished();
}

/// Drain stages recorded after [`capture_finished`]`(true)`, oldest first.
pub fn take_finished() -> Vec<Snapshot> {
    CAPTURED.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// A point-in-time view of one stage.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub stage: &'static str,
    pub done: u64,
    pub total: u64,
    /// `done` when the stage began: work finished before a restart.
    pub base: u64,
    pub elapsed: Duration,
    /// Wall-clock time the stage began, read once at [`begin_at`].
    pub started_at: SystemTime,
}

impl Snapshot {
    /// `done / total` as a percentage rounded down to hundredths (so 100.0
    /// only when done), or `None` when the total is unknown (0). Integer
    /// math: a float floor would turn 57/100 into 56.99.
    pub fn percent(&self) -> Option<f64> {
        (self.total > 0).then(|| {
            let hundredths =
                u128::from(self.done.min(self.total)) * 10_000 / u128::from(self.total);
            hundredths as f64 / 100.0
        })
    }

    /// Time left at the rate of this run (`done - base` in `elapsed`), once
    /// this run has done some work and while short of `total`.
    pub fn eta(&self) -> Option<Duration> {
        let done = self.done.min(self.total);
        let ran = done.checked_sub(self.base).filter(|&r| r > 0)?;
        let left = self.total.checked_sub(done).filter(|&l| l > 0)?;
        Duration::try_from_secs_f64(self.elapsed.as_secs_f64() * left as f64 / ran as f64).ok()
    }
}

/// A registered stage. Share `&Stage` with worker threads to report; the
/// stage unregisters when this drops.
#[must_use = "the stage ends when this guard is dropped"]
pub struct Stage(Arc<Entry>);

impl Stage {
    /// Record cumulative progress. Never moves backwards, so concurrent
    /// workers may report out of order.
    pub fn set_done(&self, done: u64) {
        self.0.done.fetch_max(done, Ordering::Relaxed);
    }

    /// Record `n` more units of progress.
    pub fn add_done(&self, n: u64) {
        self.0.done.fetch_add(n, Ordering::Relaxed);
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let fin = self.0.snapshot();
        if CAPTURE.with(|c| c.get()) {
            CAPTURED.with(|c| c.borrow_mut().push(fin.clone()));
        }
        let mut reg = registry();
        reg.active.retain(|e| !Arc::ptr_eq(e, &self.0));
        reg.last_finished = Some(fin);
    }
}

/// Register `stage` with `total` units of work (0 = unknown).
pub fn begin(stage: &'static str, total: u64) -> Stage {
    begin_at(stage, total, 0)
}

/// [`begin`] for a resumed stage: `done` starts at `base`, the units finished
/// before a restart, and [`Snapshot::eta`] counts only this run's rate.
pub fn begin_at(stage: &'static str, total: u64, base: u64) -> Stage {
    let entry = Arc::new(Entry {
        stage,
        total,
        base,
        started: Instant::now(),
        started_at: SystemTime::now(),
        done: AtomicU64::new(base),
    });
    registry().active.push(Arc::clone(&entry));
    Stage(entry)
}

/// Every running stage, oldest first.
pub fn snapshots() -> Vec<Snapshot> {
    registry().active.iter().map(|e| e.snapshot()).collect()
}

/// The most recently begun stage still running (the innermost when stages
/// nest, the one an operator is waiting on) and the stage that ended most
/// recently, with its numbers at the end (`done < total` when it stopped
/// early). One lock, so a stage that ends meanwhile is never reported as
/// both.
pub fn view() -> (Option<Snapshot>, Option<Snapshot>) {
    let reg = registry();
    (
        reg.active.last().map(|e| e.snapshot()),
        reg.last_finished.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(stage: &'static str) -> Option<Snapshot> {
        snapshots().into_iter().find(|s| s.stage == stage)
    }

    #[test]
    fn stage_reports_and_unregisters_on_drop() {
        capture_finished(true);
        {
            let s = begin("progress unit a", 200);
            s.set_done(50);
            s.set_done(20); // out of order: never moves back
            let snap = running("progress unit a").expect("registered");
            assert_eq!((snap.done, snap.total), (50, 200));
            assert_eq!(snap.percent(), Some(25.0));
            s.add_done(50);
            assert_eq!(running("progress unit a").unwrap().done, 100);
        }
        assert!(running("progress unit a").is_none(), "drop unregisters");
        let fin: Vec<_> = take_finished()
            .into_iter()
            .map(|s| (s.stage, s.done, s.total))
            .collect();
        capture_finished(false);
        assert_eq!(fin, [("progress unit a", 100, 200)]);
    }

    #[test]
    fn overlapping_stages_keep_their_own_counts() {
        let outer = begin("progress unit outer", 10);
        let inner = begin("progress unit inner", 20);
        outer.add_done(3);
        inner.add_done(7);
        assert_eq!(running("progress unit outer").unwrap().done, 3);
        assert_eq!(running("progress unit inner").unwrap().done, 7);
        let all = snapshots();
        let pos = |n| all.iter().position(|s| s.stage == n).unwrap();
        assert!(pos("progress unit outer") < pos("progress unit inner"));
        drop(outer);
        assert!(running("progress unit outer").is_none());
        assert_eq!(running("progress unit inner").unwrap().done, 7);
        drop(inner);
        assert!(running("progress unit inner").is_none());
    }

    #[test]
    fn capture_is_per_thread_and_off_by_default() {
        let other = std::thread::spawn(|| {
            drop(begin("progress unit other thread", 1));
            take_finished()
        });
        assert!(other.join().unwrap().is_empty(), "off unless turned on");
        capture_finished(true);
        std::thread::spawn(|| drop(begin("progress unit elsewhere", 1)))
            .join()
            .unwrap();
        let here = take_finished();
        capture_finished(false);
        assert!(here.is_empty(), "{here:?}");
    }

    #[test]
    fn eta_only_between_zero_and_full() {
        let s = Snapshot {
            stage: "x",
            done: 5,
            total: 0,
            base: 0,
            elapsed: Duration::from_secs(10),
            started_at: SystemTime::UNIX_EPOCH,
        };
        assert_eq!(s.percent(), None);
        assert_eq!(s.eta(), None);
        let half = Snapshot { total: 10, ..s };
        assert_eq!(half.eta(), Some(Duration::from_secs(10)));
        let none_yet = Snapshot {
            done: 0,
            ..half.clone()
        };
        assert_eq!(none_yet.percent(), Some(0.0));
        assert_eq!(none_yet.eta(), None);
        let full = Snapshot { done: 10, ..half };
        assert_eq!(full.eta(), None);
    }

    #[test]
    fn percent_rounds_down_exactly() {
        let at = |done, total| Snapshot {
            stage: "x",
            done,
            total,
            base: 0,
            elapsed: Duration::ZERO,
            started_at: SystemTime::UNIX_EPOCH,
        };
        // Each of these is a hundredth low under a float floor.
        assert_eq!(at(57, 100).percent(), Some(57.0));
        assert_eq!(at(69, 100).percent(), Some(69.0));
        assert_eq!(at(43, 1000).percent(), Some(4.3));
        assert_eq!(at(1, 3).percent(), Some(33.33));
        assert_eq!(at(99_999, 100_000).percent(), Some(99.99));
        assert_eq!(at(100, 100).percent(), Some(100.0));
        assert_eq!(at(5, 0).percent(), None);
        // Exhaustive for small totals: never above the true value, never a
        // whole hundredth below it.
        for total in 1..=300u64 {
            for done in 0..=total {
                let p = at(done, total).percent().unwrap();
                let exact = done as f64 * 100.0 / total as f64;
                assert!(p <= exact + 1e-9 && exact - p < 0.01, "{done}/{total}: {p}");
            }
        }
    }

    #[test]
    fn resumed_stage_eta_counts_only_this_run() {
        let s = begin_at("progress unit resumed", 100, 50);
        let snap = running("progress unit resumed").unwrap();
        assert_eq!((snap.done, snap.base), (50, 50));
        assert_eq!(snap.percent(), Some(50.0));
        assert_eq!(snap.eta(), None, "nothing done this run yet");
        drop(s);
        let after = Snapshot {
            stage: "x",
            done: 60,
            total: 100,
            base: 50,
            elapsed: Duration::from_secs(10),
            started_at: SystemTime::UNIX_EPOCH,
        };
        // 10 units in 10s this run, 40 left.
        assert_eq!(after.eta(), Some(Duration::from_secs(40)));
    }
}
