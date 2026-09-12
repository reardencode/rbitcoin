//! Lightweight parallel script-check pool (replaces rayon on the hot path).
//!
//! Production: (1) [`start_for_each_owned`] steals **chunks** of jobs on
//! the process-wide `rbtc-scripts-*` workers; (2) [`spawn_detached`] /
//! [`run_detached_join`] for mempool accept; (3) [`try_for_each_parallel_idle`]
//! publishes a **background** wave claimed only when no foreground wave and no
//! detached job are waiting (sptweak CPU). IBD confirm scripts publish waves
//! from the stage thread — steal workers must not `wait_done` on this pool.
//!
//! Idle steal workers [`thread::park`]. A new wave or detached job bumps an
//! epoch and [`Thread::unpark`]s every worker (unpark-before-park leaves a
//! permit, so a worker cannot miss work by parking after the wake). The jobs
//! mutex is only the detached-job queue, never the steal wake path.
//!
//! No rayon / crossbeam.

use arc_swap::ArcSwap;
use std::cell::Cell;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

/// Jobs claimed per steal. Amortizes `next` / `in_wave` / `Arc<Wave>` traffic
/// without a megachunk on mixed P2WPKH/P2WSH waves.
const STEAL_CHUNK: usize = 32;

use crate::error::ConsensusError;

thread_local! {
    static ON_STEAL_WORKER: Cell<bool> = const { Cell::new(false) };
}

fn on_steal_worker() -> bool {
    ON_STEAL_WORKER.with(|c| c.get())
}

/// Type-erased `f(&items[i])`. `ctx` is valid until the publisher drops the
/// owning [`OwnedWave`] (after [`Wave::is_complete`]).
struct Apply {
    f: unsafe fn(*const (), usize) -> Result<(), ConsensusError>,
    ctx: *const (),
}

// Workers only dereference `ctx` while `in_wave > 0`; the publisher waits
// for `in_wave == 0` before returning, so the stack `ctx` is still live.
unsafe impl Send for Apply {}
unsafe impl Sync for Apply {}

struct Wave {
    n: usize,
    next: AtomicUsize,
    in_wave: AtomicUsize,
    failed: AtomicBool,
    first_err: Mutex<Option<ConsensusError>>,
    apply: Apply,
    done: Mutex<bool>,
    done_cv: Condvar,
}

impl Wave {
    fn notify_if_complete(&self) {
        if !self.is_complete() {
            return;
        }
        *self.done.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.done_cv.notify_all();
        unpark_script_publisher();
    }

    fn claim_chunk(&self) -> Option<Range<usize>> {
        if self.failed.load(Ordering::Acquire) {
            return None;
        }
        // `in_wave` before `next`: a last-chunk claimer is visible to
        // `is_complete` before `next >= n`, so the publisher cannot free ctx
        // under a worker about to `apply`.
        self.in_wave.fetch_add(1, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            self.in_wave.fetch_sub(1, Ordering::AcqRel);
            self.notify_if_complete();
            return None;
        }
        let i = self.next.fetch_add(STEAL_CHUNK, Ordering::Relaxed);
        if i >= self.n {
            self.in_wave.fetch_sub(1, Ordering::AcqRel);
            self.notify_if_complete();
            return None;
        }
        #[cfg(test)]
        maybe_delay_claim();
        #[cfg(test)]
        if STEAL_CLAIMS_ON.load(Ordering::Relaxed) {
            STEAL_CLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        Some(i..self.n.min(i.saturating_add(STEAL_CHUNK)))
    }

    fn is_complete(&self) -> bool {
        let claimed_out =
            self.next.load(Ordering::Relaxed) >= self.n || self.failed.load(Ordering::Acquire);
        claimed_out && self.in_wave.load(Ordering::Acquire) == 0
    }

    fn run_chunk(&self, range: Range<usize>) {
        // SAFETY: `in_wave` was incremented before `next`; publisher keeps
        // `ctx` live until `is_complete` (then `OwnedWave` Drop unpublished).
        for i in range {
            if self.failed.load(Ordering::Acquire) {
                break;
            }
            let r = unsafe { (self.apply.f)(self.apply.ctx, i) };
            if let Err(e) = r {
                self.failed.store(true, Ordering::Release);
                let mut g = self.first_err.lock().unwrap_or_else(|p| p.into_inner());
                if g.is_none() {
                    *g = Some(e);
                }
                break;
            }
        }
        self.in_wave.fetch_sub(1, Ordering::AcqRel);
        self.notify_if_complete();
    }

    fn has_unclaimed(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self.next.load(Ordering::Relaxed) < self.n
    }

    fn wait_done(&self) {
        let mut g = self.done.lock().unwrap_or_else(|p| p.into_inner());
        while !self.is_complete() {
            g = self.done_cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

static PUBLISHER: Mutex<Option<thread::Thread>> = Mutex::new(None);

pub(crate) fn set_script_publisher(t: Option<thread::Thread>) {
    *PUBLISHER.lock().unwrap_or_else(|p| p.into_inner()) = t;
}

/// Wake the scripts stage thread (wave complete, `scriptq` send, or shutdown).
pub fn unpark_script_publisher() {
    let t = PUBLISHER.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(t) = t {
        t.unpark();
    }
}

static WAVES: Mutex<Vec<Arc<Wave>>> = Mutex::new(Vec::new());
static WAVES_SNAP: OnceLock<ArcSwap<Vec<Arc<Wave>>>> = OnceLock::new();
static WAVES_BG: Mutex<Vec<Arc<Wave>>> = Mutex::new(Vec::new());
static WAVES_BG_SNAP: OnceLock<ArcSwap<Vec<Arc<Wave>>>> = OnceLock::new();

#[cfg(test)]
static STEAL_WAVES_LOCKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static STEAL_CLAIMS: AtomicUsize = AtomicUsize::new(0);
/// When true, [`Wave::claim_chunk`] increments [`STEAL_CLAIMS`]. Off by default
/// so parallel idle-wave tests do not inflate the counter.
#[cfg(test)]
static STEAL_CLAIMS_ON: AtomicBool = AtomicBool::new(false);
/// Serialize the two 256-job steal tests so they do not share [`STEAL_CLAIMS`].
#[cfg(test)]
static STEAL_TEST: Mutex<()> = Mutex::new(());

fn waves_snap() -> &'static ArcSwap<Vec<Arc<Wave>>> {
    WAVES_SNAP.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

fn waves_bg_snap() -> &'static ArcSwap<Vec<Arc<Wave>>> {
    WAVES_BG_SNAP.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

fn publish_waves(waves: &[Arc<Wave>]) {
    waves_snap().store(Arc::new(waves.to_vec()));
}

fn publish_waves_bg(waves: &[Arc<Wave>]) {
    waves_bg_snap().store(Arc::new(waves.to_vec()));
}

/// Lock-free claim: load the published wave list. Must not lock [`WAVES`].
/// [`STEAL_WAVES_LOCKS`] counts steal-path mutex takes only.
fn steal_from(snap: &[Arc<Wave>]) -> Option<(Arc<Wave>, Range<usize>)> {
    for w in snap {
        if let Some(range) = w.claim_chunk() {
            return Some((Arc::clone(w), range));
        }
    }
    None
}

fn steal_chunk() -> Option<(Arc<Wave>, Range<usize>)> {
    steal_from(&waves_snap().load())
}

fn steal_bg_chunk() -> Option<(Arc<Wave>, Range<usize>)> {
    steal_from(&waves_bg_snap().load())
}

/// True when steal workers can still claim a foreground job.
pub(crate) fn fg_has_unclaimed() -> bool {
    waves_snap().load().iter().any(|w| w.has_unclaimed())
}

/// Run one steal chunk on the caller (not a steal worker). Used by the
/// scripts stage thread to finish a wave tail instead of parking.
pub(crate) fn help_steal() -> bool {
    if on_steal_worker() {
        return false;
    }
    let Some((w, range)) = steal_chunk() else {
        return false;
    };
    w.run_chunk(range);
    true
}

struct ApplyCtx<T> {
    items: *const T,
    f: fn(&T) -> Result<(), ConsensusError>,
}

unsafe impl<T: Sync> Send for ApplyCtx<T> {}
unsafe impl<T: Sync> Sync for ApplyCtx<T> {}

/// Publisher-owned job list + live wave. Safe to move; heap allocation is stable.
pub(crate) struct OwnedWave<T: Sync> {
    _items: Box<[T]>,
    _ctx: Box<ApplyCtx<T>>,
    wave: Arc<Wave>,
}

impl<T: Sync> OwnedWave<T> {
    pub(crate) fn is_complete(&self) -> bool {
        self.wave.is_complete()
    }

    #[cfg(test)]
    pub(crate) fn has_unclaimed(&self) -> bool {
        self.wave.has_unclaimed()
    }

    pub(crate) fn finish(self) -> Result<(), ConsensusError> {
        self.wave.wait_done();
        match self
            .wave
            .first_err
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<T: Sync> Drop for OwnedWave<T> {
    fn drop(&mut self) {
        self.wave.wait_done();
        unpublish_fg(&self.wave);
    }
}

fn unpublish_fg(wave: &Arc<Wave>) {
    let mut g = WAVES.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|w| !Arc::ptr_eq(w, wave));
    publish_waves(&g);
}

/// Publish `items` for steal workers without waiting. `None` = already done
/// (empty or single-item ran inline).
pub(crate) fn start_for_each_owned<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    if on_steal_worker() {
        return Err(ConsensusError::BadBlock(
            "try_for_each from a script worker",
        ));
    }
    if items.is_empty() {
        return Ok(None);
    }
    if items.len() == 1 {
        f(&items[0])?;
        return Ok(None);
    }
    let items = items.into_boxed_slice();
    let ctx = Box::new(ApplyCtx {
        items: items.as_ptr(),
        f,
    });
    unsafe fn apply<T>(ptr: *const (), i: usize) -> Result<(), ConsensusError> {
        let ctx = unsafe { &*(ptr as *const ApplyCtx<T>) };
        (ctx.f)(unsafe { &*ctx.items.add(i) })
    }
    let wave = Arc::new(Wave {
        n: items.len(),
        next: AtomicUsize::new(0),
        in_wave: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        first_err: Mutex::new(None),
        apply: Apply {
            f: apply::<T>,
            ctx: (&*ctx as *const ApplyCtx<T>).cast(),
        },
        done: Mutex::new(false),
        done_cv: Condvar::new(),
    });
    {
        let mut g = WAVES.lock().unwrap_or_else(|p| p.into_inner());
        g.push(Arc::clone(&wave));
        publish_waves(&g);
    }
    wake_steal_workers();
    Ok(Some(OwnedWave {
        _items: items,
        _ctx: ctx,
        wave,
    }))
}

/// Parallel map over `items` until the first error (or all succeed).
///
/// Workers claim only when no foreground wave and no detached job are waiting
/// (mempool / block scripts win). Must not be called from a steal worker
/// (hard refuse — same-pool wait would deadlock). On first error, workers stop
/// claiming; in-flight units may still finish.
pub(crate) fn try_for_each_parallel_idle<T, F>(items: &[T], f: F) -> Result<(), ConsensusError>
where
    T: Sync,
    F: Fn(&T) -> Result<(), ConsensusError> + Sync,
{
    run_wave(items, f)
}

fn run_wave<T, F>(items: &[T], f: F) -> Result<(), ConsensusError>
where
    T: Sync,
    F: Fn(&T) -> Result<(), ConsensusError> + Sync,
{
    if on_steal_worker() {
        return Err(ConsensusError::BadBlock(
            "try_for_each from a script worker",
        ));
    }
    if items.is_empty() {
        return Ok(());
    }
    if items.len() == 1 {
        return f(&items[0]);
    }

    struct Ctx<'a, T, F> {
        items: &'a [T],
        f: &'a F,
    }
    unsafe fn apply<T, F>(ptr: *const (), i: usize) -> Result<(), ConsensusError>
    where
        F: Fn(&T) -> Result<(), ConsensusError>,
    {
        let ctx = unsafe { &*(ptr as *const Ctx<T, F>) };
        (ctx.f)(&ctx.items[i])
    }

    let ctx = Ctx { items, f: &f };
    let wave = Arc::new(Wave {
        n: items.len(),
        next: AtomicUsize::new(0),
        in_wave: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        first_err: Mutex::new(None),
        apply: Apply {
            f: apply::<T, F>,
            ctx: (&ctx as *const Ctx<T, F>).cast(),
        },
        done: Mutex::new(false),
        done_cv: Condvar::new(),
    });
    {
        let mut g = WAVES_BG.lock().unwrap_or_else(|p| p.into_inner());
        g.push(Arc::clone(&wave));
        publish_waves_bg(&g);
    }
    wake_steal_workers();
    wave.wait_done();

    {
        let mut g = WAVES_BG.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|w| !Arc::ptr_eq(w, &wave));
        publish_waves_bg(&g);
    }

    let err = wave
        .first_err
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take();
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct ScriptWorkers {
    jobs: Mutex<VecDeque<Job>>,
    epoch: AtomicUsize,
}

static WORKERS: OnceLock<ScriptWorkers> = OnceLock::new();
static WORKER_THREADS: OnceLock<Box<[thread::Thread]>> = OnceLock::new();
static WORKER_HANDLES: OnceLock<Vec<thread::JoinHandle<()>>> = OnceLock::new();
static WORKER_SPAWNS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static IDLE_WAITERS: AtomicUsize = AtomicUsize::new(0);

fn take_detached_job(pool: &ScriptWorkers) -> Option<Job> {
    pool.jobs
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .pop_front()
}

fn steal_or_job(pool: &ScriptWorkers) -> bool {
    if let Some((w, range)) = steal_chunk() {
        w.run_chunk(range);
        return true;
    }
    if let Some(job) = take_detached_job(pool) {
        job();
        return true;
    }
    if let Some((w, range)) = steal_chunk() {
        w.run_chunk(range);
        return true;
    }
    if let Some((w, range)) = steal_bg_chunk() {
        w.run_chunk(range);
        return true;
    }
    false
}

fn wake_steal_workers() {
    let pool = workers();
    pool.epoch.fetch_add(1, Ordering::Release);
    if let Some(threads) = WORKER_THREADS.get() {
        for t in threads.iter() {
            t.unpark();
        }
    }
}

fn workers() -> &'static ScriptWorkers {
    static SPAWN: OnceLock<()> = OnceLock::new();
    let pool = WORKERS.get_or_init(|| ScriptWorkers {
        jobs: Mutex::new(VecDeque::new()),
        epoch: AtomicUsize::new(0),
    });
    SPAWN.get_or_init(|| {
        let n = thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
            .max(1);
        let mut threads = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let Ok(h) = thread::Builder::new()
                .name(format!("rbtc-scripts-{i}"))
                .spawn(move || {
                    ON_STEAL_WORKER.with(|c| c.set(true));
                    loop {
                        if steal_or_job(pool) {
                            continue;
                        }
                        let epoch = pool.epoch.load(Ordering::Acquire);
                        if steal_or_job(pool) {
                            continue;
                        }
                        if pool.epoch.load(Ordering::Acquire) != epoch {
                            continue;
                        }
                        #[cfg(test)]
                        maybe_delay_park();
                        #[cfg(test)]
                        IDLE_WAITERS.fetch_add(1, Ordering::SeqCst);
                        thread::park();
                        #[cfg(test)]
                        IDLE_WAITERS.fetch_sub(1, Ordering::SeqCst);
                    }
                })
            else {
                continue;
            };
            threads.push(h.thread().clone());
            handles.push(h);
            WORKER_SPAWNS.fetch_add(1, Ordering::Relaxed);
        }
        let _ = WORKER_THREADS.set(threads.into_boxed_slice());
        let _ = WORKER_HANDLES.set(handles);
    });
    pool
}

/// How many OS worker threads the process pool has started (tests).
#[cfg(test)]
pub(crate) fn worker_spawn_count() -> usize {
    let _ = workers();
    WORKER_SPAWNS.load(Ordering::Relaxed)
}

/// Workers currently blocked in [`thread::park`], not in a job or steal.
#[cfg(test)]
fn idle_waiter_count() -> usize {
    IDLE_WAITERS.load(Ordering::SeqCst)
}

#[cfg(test)]
static DELAY_CLAIM: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static DELAY_CLAIM_GO: AtomicBool = AtomicBool::new(true);
#[cfg(test)]
static DELAY_CLAIM_ENTERED: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static DELAY_CLAIM_MU: Mutex<()> = Mutex::new(());
#[cfg(test)]
static DELAY_CLAIM_CV: Condvar = Condvar::new();

#[cfg(test)]
fn maybe_delay_claim() {
    if !DELAY_CLAIM.load(Ordering::SeqCst) {
        return;
    }
    DELAY_CLAIM_ENTERED.fetch_add(1, Ordering::SeqCst);
    let mut g = DELAY_CLAIM_MU.lock().unwrap_or_else(|p| p.into_inner());
    while !DELAY_CLAIM_GO.load(Ordering::SeqCst) {
        g = DELAY_CLAIM_CV.wait(g).unwrap_or_else(|p| p.into_inner());
    }
}

#[cfg(test)]
static DELAY_PARK: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static DELAY_PARK_GO: AtomicBool = AtomicBool::new(true);
#[cfg(test)]
static DELAY_PARK_ENTERED: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static DELAY_PARK_MU: Mutex<()> = Mutex::new(());
#[cfg(test)]
static DELAY_PARK_CV: Condvar = Condvar::new();

#[cfg(test)]
fn maybe_delay_park() {
    if !DELAY_PARK.load(Ordering::SeqCst) {
        return;
    }
    DELAY_PARK_ENTERED.fetch_add(1, Ordering::SeqCst);
    let mut g = DELAY_PARK_MU.lock().unwrap_or_else(|p| p.into_inner());
    while !DELAY_PARK_GO.load(Ordering::SeqCst) {
        g = DELAY_PARK_CV.wait(g).unwrap_or_else(|p| p.into_inner());
    }
}

/// Submit `work` to the process-wide `rbtc-scripts` pool (IBD feed-ahead).
pub(crate) fn spawn_detached<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    let pool = workers();
    {
        let mut q = pool.jobs.lock().unwrap_or_else(|p| p.into_inner());
        q.push_back(Box::new(work));
    }
    wake_steal_workers();
}

/// Run `work` on the shared `rbtc-scripts` pool and join the result.
///
/// Used by mempool accept so the peer/tokio stack never runs the interpreter
/// (even for a single input). Returns `None` if the pool is gone.
pub(crate) fn run_detached_join<T, F>(work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    spawn_detached(move || {
        let _ = tx.send(work());
    });
    rx.recv().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    static OCCUPY: Mutex<()> = Mutex::new(());

    struct OccupyGate {
        gate: Arc<(Mutex<bool>, Condvar)>,
        _occupy: MutexGuard<'static, ()>,
    }

    impl OccupyGate {
        fn occupy_all() -> Self {
            Self::occupy_n(worker_spawn_count())
        }

        fn occupy_n(k: usize) -> Self {
            let occupy = OCCUPY.lock().unwrap_or_else(|p| p.into_inner());
            let n = worker_spawn_count();
            assert!(n >= 1);
            let k = k.min(n);
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let me = Self {
                gate: Arc::clone(&gate),
                _occupy: occupy,
            };
            let entered = Arc::new(AtomicUsize::new(0));
            for _ in 0..k {
                let entered = Arc::clone(&entered);
                let gate = Arc::clone(&gate);
                spawn_detached(move || {
                    entered.fetch_add(1, Ordering::SeqCst);
                    let (lock, cv) = &*gate;
                    let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
                    while !*g {
                        g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
                    }
                });
            }
            let start = Instant::now();
            while entered.load(Ordering::SeqCst) < k {
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "failed to occupy steal workers"
                );
                thread::sleep(Duration::from_millis(1));
            }
            me
        }

        fn release(&self) {
            let (lock, cv) = &*self.gate;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cv.notify_all();
        }
    }

    impl Drop for OccupyGate {
        fn drop(&mut self) {
            self.release();
        }
    }

    #[test]
    fn parallel_all_ok_and_counts() {
        let items: Vec<u32> = (0..64).collect();
        let hits = AtomicUsize::new(0);
        try_for_each_parallel_idle(&items, |_| {
            hits.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        assert_eq!(hits.load(Ordering::Relaxed), 64);
    }

    #[test]
    fn parallel_first_error_surfaces() {
        let items: Vec<u32> = (0..32).collect();
        let err = try_for_each_parallel_idle(&items, |&i| {
            if i == 7 {
                Err(ConsensusError::BadBlock("boom"))
            } else {
                Ok(())
            }
        })
        .expect_err("must fail");
        assert!(format!("{err}").contains("boom"));
    }

    fn boom_at_seven(i: &u32) -> Result<(), ConsensusError> {
        if *i == 7 {
            Err(ConsensusError::BadBlock("boom"))
        } else {
            Ok(())
        }
    }

    #[test]
    fn owned_wave_first_error_surfaces() {
        let _gate = STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner());
        let err = match start_for_each_owned((0..32u32).collect(), boom_at_seven) {
            Ok(Some(w)) => w.finish().expect_err("owned wave must fail"),
            Ok(None) => panic!("expected a published owned wave"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("boom"));
    }

    #[test]
    fn empty_and_single() {
        let empty: Vec<u32> = vec![];
        try_for_each_parallel_idle(&empty, |_| Ok(())).unwrap();
        try_for_each_parallel_idle(&[1u32], |_| Ok(())).unwrap();
    }

    #[test]
    fn spawn_detached_runs_work() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::sync_channel(1);
        spawn_detached(move || {
            let _ = tx.send(42u32);
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(),
            42
        );
    }

    #[test]
    fn join_many_does_not_spawn_per_job() {
        let before = worker_spawn_count();
        assert!(before >= 1);
        for i in 0..32u32 {
            let v = run_detached_join(move || i).expect("join");
            assert_eq!(v, i);
        }
        assert_eq!(
            worker_spawn_count(),
            before,
            "pool must not spawn a thread per mempool-style join"
        );
    }

    /// All `rbtc-scripts-*` workers must be able to sit in [`thread::park`] at
    /// once (no jobs-mutex held across the idle wait).
    #[test]
    fn pool_waiters_run_concurrently() {
        let n = worker_spawn_count();
        assert!(n >= 1);
        let start = Instant::now();
        while idle_waiter_count() < n {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "only {} of {n} workers idle-waiting",
                idle_waiter_count()
            );
            thread::sleep(Duration::from_millis(1));
        }
        let occupy = OccupyGate::occupy_all();
        occupy.release();
        let start = Instant::now();
        while idle_waiter_count() < n {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "workers did not finish after release"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    struct DelayParkArm;

    impl DelayParkArm {
        fn arm() -> Self {
            DELAY_PARK_ENTERED.store(0, Ordering::SeqCst);
            DELAY_PARK_GO.store(false, Ordering::SeqCst);
            DELAY_PARK.store(true, Ordering::SeqCst);
            Self
        }

        fn go(&self) {
            let _g = DELAY_PARK_MU.lock().unwrap_or_else(|p| p.into_inner());
            DELAY_PARK_GO.store(true, Ordering::SeqCst);
            DELAY_PARK_CV.notify_all();
        }
    }

    impl Drop for DelayParkArm {
        fn drop(&mut self) {
            DELAY_PARK.store(false, Ordering::SeqCst);
            let _g = DELAY_PARK_MU.lock().unwrap_or_else(|p| p.into_inner());
            DELAY_PARK_GO.store(true, Ordering::SeqCst);
            DELAY_PARK_CV.notify_all();
        }
    }

    /// Publish a wave after the last free worker has missed steal and before
    /// it parks. Condvar notify-without-mutex lost that wake; park permits
    /// must still run the wave.
    #[test]
    fn wave_published_before_park_is_not_missed() {
        let n = worker_spawn_count();
        let occupy = OccupyGate::occupy_n(n.saturating_sub(1));
        let start = Instant::now();
        while idle_waiter_count() == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "free worker did not park"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let arm = DelayParkArm::arm();
        wake_steal_workers();
        let start = Instant::now();
        while DELAY_PARK_ENTERED.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "free worker did not reach park gate"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = Arc::clone(&hits);
        let wave = thread::spawn(move || {
            let items: Vec<u32> = (0..64).collect();
            try_for_each_parallel_idle(&items, |_| {
                hits2.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        });
        let start = Instant::now();
        while waves_bg_snap().load().is_empty() {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "wave was not published"
            );
            thread::sleep(Duration::from_millis(1));
        }
        arm.go();
        wave.join().expect("wave thread").expect("wave ok");
        assert_eq!(hits.load(Ordering::Relaxed), 64);
        occupy.release();
    }

    #[test]
    fn try_for_each_runs_on_script_workers() {
        let before = worker_spawn_count();
        let items: Vec<u32> = (0..32).collect();
        let names = Mutex::new(Vec::new());
        try_for_each_parallel_idle(&items, |_| {
            names
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(thread::current().name().unwrap_or("").to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(worker_spawn_count(), before);
        let names = names.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(names.len(), 32);
        for n in names.iter() {
            assert!(n.starts_with("rbtc-scripts-"), "item ran on {n:?}");
        }
    }

    #[test]
    fn overlapping_try_for_each_both_complete() {
        let a_hits = Arc::new(AtomicUsize::new(0));
        let b_hits = Arc::new(AtomicUsize::new(0));
        let a = {
            let hits = Arc::clone(&a_hits);
            thread::spawn(move || {
                let items: Vec<u32> = (0..16).collect();
                try_for_each_parallel_idle(&items, |_| {
                    hits.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
            })
        };
        let b = {
            let hits = Arc::clone(&b_hits);
            thread::spawn(move || {
                let items: Vec<u32> = (0..16).collect();
                try_for_each_parallel_idle(&items, |_| {
                    hits.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
            })
        };
        a.join().expect("a").expect("a ok");
        b.join().expect("b").expect("b ok");
        assert_eq!(a_hits.load(Ordering::Relaxed), 16);
        assert_eq!(b_hits.load(Ordering::Relaxed), 16);
    }

    #[test]
    fn steal_chunk_amortizes_claims() {
        // 256 items → 8 chunks of 32. Not 256 fetch_adds on `next`.
        let _gate = STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner());
        workers();
        STEAL_CLAIMS.store(0, Ordering::Relaxed);
        STEAL_CLAIMS_ON.store(true, Ordering::Relaxed);
        let items: Vec<u32> = (0..256).collect();
        let hits: Vec<AtomicUsize> = (0..256).map(|_| AtomicUsize::new(0)).collect();
        try_for_each_parallel_idle(&items, |&i| {
            hits[i as usize].fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        STEAL_CLAIMS_ON.store(false, Ordering::Relaxed);
        for (i, h) in hits.iter().enumerate() {
            assert_eq!(h.load(Ordering::Relaxed), 1, "index {i} not run once");
        }
        let claims = STEAL_CLAIMS.load(Ordering::Relaxed);
        assert!(
            (8..32).contains(&claims),
            "expected ~8 chunks of 32 for 256 jobs, got {claims}"
        );
    }

    #[test]
    fn steal_index_does_not_lock_waves_per_job() {
        // Claim must not take WAVES: a 256-job wave is tens of thousands of
        // short P2WPKH jobs on IBD. Today's steal_index locks per claim.
        let _gate = STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner());
        workers();
        STEAL_WAVES_LOCKS.store(0, Ordering::Relaxed);
        let items: Vec<u32> = (0..256).collect();
        let hits = AtomicUsize::new(0);
        try_for_each_parallel_idle(&items, |_| {
            hits.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        assert_eq!(hits.load(Ordering::Relaxed), 256);
        let locks = STEAL_WAVES_LOCKS.load(Ordering::Relaxed);
        assert_eq!(
            locks, 0,
            "steal_index took WAVES {locks} times (must be snapshot load only)"
        );
    }

    #[test]
    fn try_for_each_from_script_worker_is_refused() {
        let got =
            run_detached_join(|| try_for_each_parallel_idle(&[1u32, 2], |_| Ok(()))).expect("join");
        let err = got.expect_err("must refuse nested wait");
        assert!(
            format!("{err}").contains("try_for_each from a script worker"),
            "{err}"
        );
    }

    /// Occupy every steal worker in a detached job, publish an idle wave whose
    /// items wait on a later job, queue that job, then release. If idle stole
    /// like a foreground wave, the job never runs (items wait on it).
    #[test]
    fn idle_wave_does_not_starve_detached_job() {
        let occupy = OccupyGate::occupy_all();

        let job2 = Arc::new(AtomicBool::new(false));
        let idle_hits = Arc::new(AtomicUsize::new(0));
        let items: Vec<u32> = (0..64).collect();
        let idle_hits2 = Arc::clone(&idle_hits);
        let job2_wait = Arc::clone(&job2);
        let idle = thread::spawn(move || {
            try_for_each_parallel_idle(&items, |_| {
                let t0 = Instant::now();
                while !job2_wait.load(Ordering::SeqCst) {
                    assert!(
                        t0.elapsed() < Duration::from_secs(2),
                        "idle item waited for a starved detached job"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                idle_hits2.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        });
        thread::sleep(Duration::from_millis(20));
        let job2_flag = Arc::clone(&job2);
        spawn_detached(move || {
            job2_flag.store(true, Ordering::SeqCst);
        });
        occupy.release();
        let start = Instant::now();
        while !job2.load(Ordering::SeqCst) {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "idle wave starved the detached job"
            );
            thread::sleep(Duration::from_millis(1));
        }
        idle.join().expect("idle thread").expect("idle ok");
        assert_eq!(idle_hits.load(Ordering::Relaxed), 64);
    }

    static FG_HITS: AtomicUsize = AtomicUsize::new(0);
    fn count_fg(_: &u32) -> Result<(), ConsensusError> {
        FG_HITS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn idle_wave_does_not_starve_foreground_wave() {
        let occupy = OccupyGate::occupy_all();

        FG_HITS.store(0, Ordering::Relaxed);
        let fg_done = Arc::new(AtomicBool::new(false));
        let items: Vec<u32> = (0..64).collect();
        let fg_wait = Arc::clone(&fg_done);
        let idle = thread::spawn(move || {
            try_for_each_parallel_idle(&items, |_| {
                let t0 = Instant::now();
                while !fg_wait.load(Ordering::SeqCst) {
                    assert!(
                        t0.elapsed() < Duration::from_secs(2),
                        "idle item waited for a starved foreground wave"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(())
            })
        });
        thread::sleep(Duration::from_millis(20));
        let fg_flag = Arc::clone(&fg_done);
        let fg = thread::spawn(move || {
            let r = match start_for_each_owned((0..32u32).collect(), count_fg) {
                Ok(Some(w)) => w.finish(),
                Ok(None) => Ok(()),
                Err(e) => Err(e),
            };
            fg_flag.store(true, Ordering::SeqCst);
            r
        });
        occupy.release();
        fg.join().expect("fg thread").expect("fg ok");
        assert_eq!(FG_HITS.load(Ordering::Relaxed), 32);
        idle.join().expect("idle thread").expect("idle ok");
    }

    #[test]
    fn panic_while_workers_occupied_does_not_deadlock_pool() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _gate = OccupyGate::occupy_all();
            panic!("occupy test boom");
        }));
        std::panic::set_hook(prev);
        assert!(panicked.is_err());
        try_for_each_parallel_idle(&[1u32, 2, 3, 4], |_| Ok(())).unwrap();
    }

    static HOLD_JOBS: AtomicBool = AtomicBool::new(false);
    static HOLD_IN: AtomicUsize = AtomicUsize::new(0);

    fn hold_job(_: &u32) -> Result<(), ConsensusError> {
        HOLD_IN.fetch_add(1, Ordering::SeqCst);
        let t0 = Instant::now();
        while HOLD_JOBS.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(3) {
            thread::park_timeout(Duration::from_millis(1));
        }
        Ok(())
    }

    struct HoldJobs;
    impl HoldJobs {
        fn arm() -> Self {
            HOLD_IN.store(0, Ordering::SeqCst);
            HOLD_JOBS.store(true, Ordering::SeqCst);
            Self
        }
    }
    impl Drop for HoldJobs {
        fn drop(&mut self) {
            HOLD_JOBS.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn second_wave_publishes_when_first_is_claimed() {
        let _steal = STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner());
        let _occupy = OCCUPY.lock().unwrap_or_else(|p| p.into_inner());
        let hold = HoldJobs::arm();
        let a = start_for_each_owned((0..64u32).collect(), hold_job)
            .unwrap()
            .expect("wave a");
        let start = Instant::now();
        while a.has_unclaimed() {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "first wave not fully claimed"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!fg_has_unclaimed());
        let b = start_for_each_owned((0..64u32).collect(), hold_job)
            .unwrap()
            .expect("wave b");
        assert!(
            !a.is_complete(),
            "first wave still in_wave when second is published"
        );
        assert!(b.has_unclaimed() || fg_has_unclaimed() || !a.is_complete());
        drop(hold);
        a.finish().unwrap();
        b.finish().unwrap();
        assert!(!fg_has_unclaimed());
    }

    fn ok_u32(_: &u32) -> Result<(), ConsensusError> {
        Ok(())
    }

    struct DelayClaimArm;
    impl DelayClaimArm {
        fn arm() -> Self {
            DELAY_CLAIM_ENTERED.store(0, Ordering::SeqCst);
            DELAY_CLAIM_GO.store(false, Ordering::SeqCst);
            DELAY_CLAIM.store(true, Ordering::SeqCst);
            Self
        }
        fn go(&self) {
            let _g = DELAY_CLAIM_MU.lock().unwrap_or_else(|p| p.into_inner());
            DELAY_CLAIM_GO.store(true, Ordering::SeqCst);
            DELAY_CLAIM_CV.notify_all();
        }
    }
    impl Drop for DelayClaimArm {
        fn drop(&mut self) {
            DELAY_CLAIM.store(false, Ordering::SeqCst);
            let _g = DELAY_CLAIM_MU.lock().unwrap_or_else(|p| p.into_inner());
            DELAY_CLAIM_GO.store(true, Ordering::SeqCst);
            DELAY_CLAIM_CV.notify_all();
        }
    }

    /// After `in_wave++` and before `next += chunk`, `is_complete` must be
    /// false (publisher must not free ctx under the claimer).
    #[test]
    fn last_claim_holds_in_wave_before_next() {
        let _gate = STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner());
        let n = worker_spawn_count();
        let occupy = OccupyGate::occupy_n(n.saturating_sub(1));
        let arm = DelayClaimArm::arm();
        let wave = thread::spawn(|| {
            start_for_each_owned((0..2u32).collect(), ok_u32)
                .unwrap()
                .expect("wave")
                .finish()
        });
        let start = Instant::now();
        while DELAY_CLAIM_ENTERED.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "claimer did not enter in_wave delay"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let snap = waves_snap().load();
        assert!(!snap.is_empty(), "wave not published");
        assert!(
            !snap[0].is_complete(),
            "is_complete during in_wave-before-next window"
        );
        arm.go();
        wave.join().expect("join").expect("wave ok");
        occupy.release();
    }
}
