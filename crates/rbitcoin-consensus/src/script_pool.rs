//! Lightweight parallel script-check pool (replaces rayon on the hot path).
//!
//! Production: (1) [`start_for_each_owned`] steals **chunks** of jobs on
//! the process-wide `rbtc-scripts-*` workers; (2) [`spawn_detached`] /
//! [`run_detached_join`] for mempool accept. IBD confirm scripts publish waves
//! from the stage thread — steal workers must not `wait_done` on this pool.
//!
//! Idle steal workers [`thread::park`]. A new wave or detached job bumps an
//! epoch and unparks one parked worker per queued chunk or detached job
//! (capped by how many are parked). Unpark-before-park leaves a permit, so a
//! worker that already decided to park still sees the wave. The jobs mutex is
//! only the detached-job queue, never the steal wake path.
//!
//! No rayon / crossbeam.

use crate::sync::atomic::Ordering as ModelOrdering;
use arc_swap::ArcSwap;
use std::collections::VecDeque;
use std::future::Future;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;

/// Jobs claimed per steal. Amortizes `next` / `in_wave` / `Arc<Wave>` traffic
/// without a megachunk on mixed P2WPKH/P2WSH waves.
pub const STEAL_CHUNK: usize = 32;

use crate::error::ConsensusError;

#[doc(hidden)]
pub fn on_steal_worker() -> bool {
    rbitcoin_primitives::on_script_worker()
}

/// Type-erased `f(&items[i])`. `ctx` is valid until the publisher drops the
/// owning [`OwnedWave`] (after [`Wave::is_complete`]).
#[doc(hidden)]
pub struct Apply {
    pub f: unsafe fn(*const (), usize) -> Result<(), ConsensusError>,
    pub ctx: *const (),
}

// SAFETY: workers dereference `ctx` only while `in_wave > 0`. `ctx` points
// at `OwnedWave`'s box. `Drop` and `finish` wait until `in_wave == 0`
// before that box is freed.
unsafe impl Send for Apply {}
// SAFETY: same lifetime as `Send`: `ctx` stays live until `in_wave` hits 0.
unsafe impl Sync for Apply {}

#[doc(hidden)]
pub struct Wave {
    pub n: usize,
    /// Jobs taken per successful steal. Script verify uses [`STEAL_CHUNK`].
    /// An index window claims one height.
    pub chunk: usize,
    pub next: crate::sync::atomic::AtomicUsize,
    pub in_wave: crate::sync::atomic::AtomicUsize,
    pub failed: AtomicBool,
    pub first_err: Mutex<Option<ConsensusError>>,
    /// When set, warn-and-apply script faults are kept and the rest of the
    /// wave still runs. Flag-off leaves this false and stops at the first error.
    pub keep_faults: AtomicBool,
    pub faults: Mutex<Vec<(usize, ConsensusError)>>,
    pub apply: Apply,
    pub done: Mutex<bool>,
    pub done_cv: Condvar,
}

impl Wave {
    #[doc(hidden)]
    pub fn notify_if_complete(&self) {
        if !self.is_complete() {
            return;
        }
        *self.done.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.done_cv.notify_all();
        unpark_script_publisher();
    }

    #[doc(hidden)]
    pub fn claim_chunk(wave: &Arc<Wave>) -> Option<(Range<usize>, InWave)> {
        if wave.failed.load(Ordering::Acquire) {
            return None;
        }
        // `in_wave` before `next`. `next` is the release, and `is_complete`
        // acquire-loads it, so that load sees this increment. A relaxed
        // `next` can become visible first and look like the claim finished.
        wave.in_wave.fetch_add(1, ModelOrdering::AcqRel);
        let hold = InWave {
            wave: Arc::clone(wave),
        };
        if wave.failed.load(Ordering::Acquire) {
            return None;
        }
        let chunk = wave.chunk.max(1);
        let i = wave.next.fetch_add(chunk, ModelOrdering::Release);
        if i >= wave.n {
            return None;
        }
        #[cfg(debug_assertions)]
        if STEAL_CLAIMS_ON.load(Ordering::Relaxed) {
            STEAL_CLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        Some((i..wave.n.min(i.saturating_add(chunk)), hold))
    }

    #[doc(hidden)]
    pub fn is_complete(&self) -> bool {
        let claimed_out =
            self.next.load(ModelOrdering::Acquire) >= self.n || self.failed.load(Ordering::Acquire);
        claimed_out && self.in_wave.load(ModelOrdering::Acquire) == 0
    }

    #[doc(hidden)]
    pub fn run_chunk(&self, range: Range<usize>) {
        for i in range {
            if self.failed.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: `in_wave` was incremented before `next`. The publisher
            // keeps `ctx` live until `is_complete` (then `OwnedWave` drops it).
            let r = unsafe { (self.apply.f)(self.apply.ctx, i) };
            if let Err(e) = r {
                if self.keep_faults.load(Ordering::Relaxed) && crate::is_warn_and_apply(&e) {
                    self.faults
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push((i, e));
                    continue;
                }
                self.failed.store(true, Ordering::Release);
                let mut g = self.first_err.lock().unwrap_or_else(|p| p.into_inner());
                if g.is_none() {
                    *g = Some(e);
                }
                break;
            }
        }
    }

    #[doc(hidden)]
    pub fn has_unclaimed(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self.next.load(ModelOrdering::Relaxed) < self.n
    }

    fn unclaimed_chunks(&self) -> usize {
        if !self.has_unclaimed() {
            return 0;
        }
        let next = self.next.load(ModelOrdering::Relaxed);
        let chunk = self.chunk.max(1);
        self.n.saturating_sub(next).div_ceil(chunk)
    }

    #[doc(hidden)]
    pub fn wait_done(&self) {
        let mut g = self.done.lock().unwrap_or_else(|p| p.into_inner());
        while !self.is_complete() {
            g = self.done_cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

#[doc(hidden)]
pub static PUBLISHERS: Mutex<Vec<thread::Thread>> = Mutex::new(Vec::new());

/// Register the scripts stage that should be woken, or clear the caller.
///
/// `None` removes the calling thread. Two stages in one process each
/// register; a single slot dropped the first stage's wakes.
pub fn set_script_publisher(t: Option<thread::Thread>) {
    let mut g = PUBLISHERS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(t) = t {
        g.retain(|p| p.id() != t.id());
        g.push(t);
    } else {
        let id = thread::current().id();
        g.retain(|p| p.id() != id);
    }
}

/// Wake every registered scripts stage (wave complete, `scriptq` send, or shutdown).
pub fn unpark_script_publisher() {
    // Drop the guard before unpark: a woken stage may register or clear.
    let threads = PUBLISHERS.lock().unwrap_or_else(|p| p.into_inner()).clone();
    for t in threads {
        t.unpark();
    }
}

#[doc(hidden)]
pub static WAVES: Mutex<Vec<Arc<Wave>>> = Mutex::new(Vec::new());
#[doc(hidden)]
pub static WAVES_SNAP: OnceLock<ArcSwap<Vec<Arc<Wave>>>> = OnceLock::new();

#[cfg(debug_assertions)]
#[doc(hidden)]
pub static STEAL_CLAIMS: AtomicUsize = AtomicUsize::new(0);
/// When true, [`Wave::claim_chunk`] increments [`STEAL_CLAIMS`]. Off by default
/// so parallel wave tests do not inflate the counter.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static STEAL_CLAIMS_ON: AtomicBool = AtomicBool::new(false);
/// Serialize steal-wave tests so they do not interleave. Lives outside
/// `cfg(test)` because query tests link this crate without that cfg.
#[doc(hidden)]
pub static STEAL_TEST: Mutex<()> = Mutex::new(());

/// Hold across a test that publishes a steal wave, so pool tests do not
/// interleave waves.
#[doc(hidden)]
pub fn steal_test_gate() -> std::sync::MutexGuard<'static, ()> {
    STEAL_TEST.lock().unwrap_or_else(|p| p.into_inner())
}

#[doc(hidden)]
pub fn waves_snap() -> &'static ArcSwap<Vec<Arc<Wave>>> {
    WAVES_SNAP.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

#[doc(hidden)]
pub fn publish_waves(waves: &[Arc<Wave>]) {
    waves_snap().store(Arc::new(waves.to_vec()));
    #[cfg(debug_assertions)]
    note_script_progress();
}

/// Drops `in_wave` on the success path and on a panic inside the chunk.
#[doc(hidden)]
pub struct InWave {
    pub wave: Arc<Wave>,
}

impl Drop for InWave {
    fn drop(&mut self) {
        self.wave.in_wave.fetch_sub(1, ModelOrdering::AcqRel);
        self.wave.notify_if_complete();
    }
}

/// Lock-free claim: load the published wave list. Must not lock [`WAVES`].
#[doc(hidden)]
pub fn steal_chunk() -> Option<(Range<usize>, InWave)> {
    let claimed = waves_snap().load().iter().find_map(Wave::claim_chunk);
    #[cfg(debug_assertions)]
    if claimed.is_some() {
        maybe_delay_claim();
    }
    claimed
}

#[doc(hidden)]
pub fn run_held(range: Range<usize>, hold: InWave) {
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hold.wave.run_chunk(range);
    }));
    if panicked.is_err() {
        hold.wave.failed.store(true, Ordering::Release);
        let mut g = hold
            .wave
            .first_err
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(ConsensusError::Internal("script worker panic"));
        }
    }
}

/// True when steal workers can still claim a foreground job.
pub fn fg_has_unclaimed() -> bool {
    waves_snap().load().iter().any(|w| w.has_unclaimed())
}

/// Run one steal chunk on the caller (not a steal worker). Used by the
/// scripts stage thread to finish a wave tail instead of parking.
///
/// A one-job index claim can run on `ibd-confirm` when the workers are busy.
pub fn help_steal() -> bool {
    if on_steal_worker() {
        return false;
    }
    let Some((range, hold)) = steal_chunk() else {
        return false;
    };
    run_held(range, hold);
    true
}

#[doc(hidden)]
pub struct ApplyCtx<T> {
    pub items: *const T,
    pub f: fn(&T) -> Result<(), ConsensusError>,
}

// SAFETY: `items` points at `OwnedWave`'s box. `T: Sync` so workers may share it.
unsafe impl<T: Sync> Send for ApplyCtx<T> {}
// SAFETY: same as `Send`: the box outlives every worker that reads `items`.
unsafe impl<T: Sync> Sync for ApplyCtx<T> {}

/// Publisher-owned job list + live wave. Safe to move; heap allocation is stable.
pub struct OwnedWave<T: Sync> {
    pub _items: Box<[T]>,
    pub _ctx: Box<ApplyCtx<T>>,
    pub wave: Arc<Wave>,
}

impl<T: Sync> OwnedWave<T> {
    pub fn is_complete(&self) -> bool {
        self.wave.is_complete()
    }

    /// Block until every claimed chunk has finished. Call this before
    /// [`Self::take_faults`]: workers record faults only as they run.
    pub fn wait(&self) {
        self.wave.wait_done();
    }

    #[cfg(debug_assertions)]
    pub fn has_unclaimed(&self) -> bool {
        self.wave.has_unclaimed()
    }

    pub fn finish(self) -> Result<(), ConsensusError> {
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

    /// Warn-and-apply faults recorded while [`Wave::keep_faults`] is set.
    /// Indexes match the published job list. Empty when the wave stopped early.
    pub fn take_faults(&self) -> Vec<(usize, ConsensusError)> {
        std::mem::take(&mut *self.wave.faults.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl<T: Sync> Drop for OwnedWave<T> {
    fn drop(&mut self) {
        self.wave.wait_done();
        unpublish_fg(&self.wave);
    }
}

#[doc(hidden)]
pub fn unpublish_fg(wave: &Arc<Wave>) {
    let mut g = WAVES.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|w| !Arc::ptr_eq(w, wave));
    publish_waves(&g);
}

/// Publish `items` for steal workers without waiting. `None` = already done
/// (empty or single-item ran inline). Claims [`STEAL_CHUNK`] jobs at a time.
pub fn start_for_each_owned<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    start_for_each_owned_chunk(items, f, STEAL_CHUNK)
}

/// [`start_for_each_owned`] that records every warn-and-apply fault and
/// finishes the remaining jobs. Stop-class errors still end the wave.
pub fn start_for_each_owned_keep<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    start_wave(items, f, STEAL_CHUNK, true, true)
}

/// Same as [`start_for_each_owned`] with an explicit claim size. `chunk` of 0
/// is treated as 1. Empty and single-item lists still run inline.
pub fn start_for_each_owned_chunk<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
    chunk: usize,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    start_wave(items, f, chunk, true, false)
}

/// Like [`start_for_each_owned`], but a single job is still published.
///
/// [`start_for_each_owned`] runs a single item on the caller. The index wave
/// must not do that: one filter would block `ibd-confirm` inside `start`.
/// `chunk` of 0 is treated as 1.
pub fn start_for_each_pooled<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
    chunk: usize,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    start_wave(items, f, chunk, false, false)
}

#[doc(hidden)]
pub fn start_wave<T: Sync>(
    items: Vec<T>,
    f: fn(&T) -> Result<(), ConsensusError>,
    chunk: usize,
    inline_single: bool,
    keep_faults: bool,
) -> Result<Option<OwnedWave<T>>, ConsensusError> {
    if on_steal_worker() {
        return Err(ConsensusError::BadBlock(
            "try_for_each from a script worker",
        ));
    }
    if items.is_empty() {
        return Ok(None);
    }
    if inline_single && items.len() == 1 {
        f(&items[0])?;
        return Ok(None);
    }
    let items = items.into_boxed_slice();
    let ctx = Box::new(ApplyCtx {
        items: items.as_ptr(),
        f,
    });
    pub unsafe fn apply<T>(ptr: *const (), i: usize) -> Result<(), ConsensusError> {
        // SAFETY: `ptr` is the `ApplyCtx` published for this wave, live until
        // `in_wave` returns to 0. `i` is inside `0..n`.
        let ctx = unsafe { &*(ptr as *const ApplyCtx<T>) };
        // SAFETY: `items` has `n` elements and `i < n` (the wave claims that range).
        (ctx.f)(unsafe { &*ctx.items.add(i) })
    }
    let wave = Arc::new(Wave {
        n: items.len(),
        chunk,
        next: crate::sync::atomic::AtomicUsize::new(0),
        in_wave: crate::sync::atomic::AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        first_err: Mutex::new(None),
        keep_faults: AtomicBool::new(keep_faults),
        faults: Mutex::new(Vec::new()),
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

#[doc(hidden)]
pub type Job = Box<dyn FnOnce() + Send + 'static>;

#[doc(hidden)]
pub struct ScriptWorkers {
    pub jobs: crate::sync::Mutex<VecDeque<Job>>,
    pub epoch: crate::sync::atomic::AtomicUsize,
}

#[doc(hidden)]
pub static WORKERS: OnceLock<ScriptWorkers> = OnceLock::new();
#[doc(hidden)]
pub static WORKER_THREADS: OnceLock<Box<[thread::Thread]>> = OnceLock::new();
#[doc(hidden)]
pub static WORKER_HANDLES: OnceLock<Vec<thread::JoinHandle<()>>> = OnceLock::new();
#[doc(hidden)]
pub static WORKER_SPAWNS: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static IDLE_WAITERS: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static STEAL_UNPARKS: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub fn take_detached_job(pool: &ScriptWorkers) -> Option<Job> {
    crate::sync::lock(&pool.jobs).pop_front()
}

#[doc(hidden)]
pub fn steal_or_job(pool: &ScriptWorkers) -> bool {
    if let Some((range, hold)) = steal_chunk() {
        run_held(range, hold);
        return true;
    }
    if let Some(job) = take_detached_job(pool) {
        job();
        return true;
    }
    if let Some((range, hold)) = steal_chunk() {
        run_held(range, hold);
        return true;
    }
    false
}

#[doc(hidden)]
pub fn wake_steal_workers() {
    let pool = workers();
    pool.epoch.fetch_add(1, ModelOrdering::Release);
    unpark_idle(queued_wake_count(pool));
}

fn work_pending(pool: &ScriptWorkers) -> bool {
    if fg_has_unclaimed() {
        return true;
    }
    !crate::sync::lock(&pool.jobs).is_empty()
}

fn queued_wake_count(pool: &ScriptWorkers) -> usize {
    let mut n = 0usize;
    for wave in waves_snap().load().iter() {
        n = n.saturating_add(wave.unclaimed_chunks());
    }
    let jobs = crate::sync::lock(&pool.jobs).len();
    n.saturating_add(jobs)
}

static IDLE_THREADS: std::sync::LazyLock<crate::sync::Mutex<Vec<crate::sync::thread::Thread>>> =
    std::sync::LazyLock::new(|| crate::sync::Mutex::new(Vec::new()));

#[doc(hidden)]
pub fn register_idle(idle: &crate::sync::Mutex<Vec<crate::sync::thread::Thread>>) {
    let current = crate::sync::thread::current();
    let mut idle = crate::sync::lock(idle);
    if idle.iter().all(|parked| parked.id() != current.id()) {
        idle.push(current);
    }
}

#[doc(hidden)]
pub fn unregister_idle(idle: &crate::sync::Mutex<Vec<crate::sync::thread::Thread>>) {
    let id = crate::sync::thread::current().id();
    crate::sync::lock(idle).retain(|parked| parked.id() != id);
}

fn unpark_idle(n: usize) {
    unpark_idle_from(&IDLE_THREADS, n);
}

/// Wake up to `n` threads on this idle list. The OS pool uses [`IDLE_THREADS`].
#[doc(hidden)]
pub fn unpark_idle_from(idle: &crate::sync::Mutex<Vec<crate::sync::thread::Thread>>, n: usize) {
    if n == 0 {
        return;
    }
    let taken = {
        let mut idle = crate::sync::lock(idle);
        let n = n.min(idle.len());
        idle.drain(..n).collect::<Vec<_>>()
    };
    for thread in taken {
        thread.unpark();
        #[cfg(debug_assertions)]
        {
            STEAL_UNPARKS.fetch_add(1, Ordering::Relaxed);
            note_script_progress();
        }
    }
}

/// Register, recheck, then park. Returns false when work or a newer epoch
/// arrived before park, and true after a park that was woken.
///
/// The second check is the lost-wakeup close: a publisher that bumps the
/// epoch after the first check must either be seen here or find this thread
/// already on `idle` so its unpark is a park permit.
#[doc(hidden)]
pub fn park_if_still_idle(
    pool: &ScriptWorkers,
    epoch: usize,
    idle: &crate::sync::Mutex<Vec<crate::sync::thread::Thread>>,
) -> bool {
    register_idle(idle);
    let missed = work_pending(pool) || pool.epoch.load(ModelOrdering::Acquire) != epoch;
    if missed {
        unregister_idle(idle);
        return false;
    }
    #[cfg(debug_assertions)]
    maybe_delay_park();
    let missed = work_pending(pool) || pool.epoch.load(ModelOrdering::Acquire) != epoch;
    if missed {
        unregister_idle(idle);
        return false;
    }
    #[cfg(debug_assertions)]
    {
        IDLE_WAITERS.fetch_add(1, Ordering::SeqCst);
        note_script_progress();
    }
    crate::sync::thread::park();
    #[cfg(debug_assertions)]
    {
        IDLE_WAITERS.fetch_sub(1, Ordering::SeqCst);
        note_script_progress();
    }
    unregister_idle(idle);
    true
}

#[doc(hidden)]
pub fn workers() -> &'static ScriptWorkers {
    static SPAWN: OnceLock<()> = OnceLock::new();
    let pool = WORKERS.get_or_init(|| ScriptWorkers {
        jobs: crate::sync::Mutex::new(VecDeque::new()),
        epoch: crate::sync::atomic::AtomicUsize::new(0),
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
                    rbitcoin_primitives::set_script_worker(true);
                    loop {
                        if steal_or_job(pool) {
                            continue;
                        }
                        let epoch = pool.epoch.load(ModelOrdering::Acquire);
                        if steal_or_job(pool) {
                            continue;
                        }
                        if pool.epoch.load(ModelOrdering::Acquire) != epoch {
                            continue;
                        }
                        // Do not run a job while registered. A busy worker on
                        // the idle list would take a wake meant for one that
                        // is actually parked.
                        let _ = park_if_still_idle(pool, epoch, &IDLE_THREADS);
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
#[cfg(debug_assertions)]
pub fn worker_spawn_count() -> usize {
    let _ = workers();
    WORKER_SPAWNS.load(Ordering::Relaxed)
}

/// Workers currently blocked in [`thread::park`], not in a job or steal.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn idle_waiter_count() -> usize {
    IDLE_WAITERS.load(Ordering::SeqCst)
}

/// Test waits for idle, claim, and publish. Not a permit: the waiter holds
/// [`SCRIPT_PROGRESS_MU`] across the check.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static SCRIPT_PROGRESS_MU: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static SCRIPT_PROGRESS_CV: Condvar = Condvar::new();

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn note_script_progress() {
    let _g = SCRIPT_PROGRESS_MU.lock().unwrap_or_else(|p| p.into_inner());
    SCRIPT_PROGRESS_CV.notify_all();
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_CLAIM: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_CLAIM_GO: AtomicBool = AtomicBool::new(true);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_CLAIM_ENTERED: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_CLAIM_MU: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_CLAIM_CV: Condvar = Condvar::new();

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn maybe_delay_claim() {
    if !DELAY_CLAIM.load(Ordering::SeqCst) {
        return;
    }
    DELAY_CLAIM_ENTERED.fetch_add(1, Ordering::SeqCst);
    note_script_progress();
    let mut g = DELAY_CLAIM_MU.lock().unwrap_or_else(|p| p.into_inner());
    while !DELAY_CLAIM_GO.load(Ordering::SeqCst) {
        g = DELAY_CLAIM_CV.wait(g).unwrap_or_else(|p| p.into_inner());
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_PARK: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_PARK_GO: AtomicBool = AtomicBool::new(true);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_PARK_ENTERED: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_PARK_MU: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static DELAY_PARK_CV: Condvar = Condvar::new();

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn maybe_delay_park() {
    if !DELAY_PARK.load(Ordering::SeqCst) {
        return;
    }
    DELAY_PARK_ENTERED.fetch_add(1, Ordering::SeqCst);
    note_script_progress();
    let mut g = DELAY_PARK_MU.lock().unwrap_or_else(|p| p.into_inner());
    while !DELAY_PARK_GO.load(Ordering::SeqCst) {
        g = DELAY_PARK_CV.wait(g).unwrap_or_else(|p| p.into_inner());
    }
}

/// Submit `work` to the process-wide `rbtc-scripts` pool (IBD feed-ahead).
pub fn spawn_detached<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    let pool = workers();
    {
        let mut q = crate::sync::lock(&pool.jobs);
        q.push_back(Box::new(work));
    }
    wake_steal_workers();
}

struct CpuState<T> {
    value: Option<T>,
    waker: Option<Waker>,
    done: bool,
}

struct CpuFinish<T> {
    state: Arc<Mutex<CpuState<T>>>,
    value: Option<T>,
}

impl<T> Drop for CpuFinish<T> {
    fn drop(&mut self) {
        let waker = {
            let mut slot = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(value) = self.value.take() {
                slot.value = Some(value);
            }
            slot.done = true;
            slot.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A [`run_cpu`] join. `None` means the worker dropped the reply.
#[doc(hidden)]
pub struct CpuJob<T> {
    state: Arc<Mutex<CpuState<T>>>,
}

impl<T> Future for CpuJob<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut slot = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(value) = slot.value.take() {
            return Poll::Ready(Some(value));
        }
        if slot.done {
            return Poll::Ready(None);
        }
        slot.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Run `work` on `rbtc-scripts-*` and await it.
///
/// The caller parks. It does not hold a blocking-pool thread. A published
/// steal chunk is claimed before this job. `None` means the guest panicked
/// and the worker dropped the reply. The worker stays in the pool.
pub fn run_cpu<T, F>(work: F) -> CpuJob<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let state = Arc::new(Mutex::new(CpuState {
        value: None,
        waker: None,
        done: false,
    }));
    let finish = CpuFinish {
        state: Arc::clone(&state),
        value: None,
    };
    spawn_detached(move || {
        let mut finish = finish;
        if let Ok(value) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
            finish.value = Some(value);
        }
    });
    CpuJob { state }
}

/// Run `work` on the shared `rbtc-scripts` pool and join the result.
///
/// Used by mempool accept so the peer/tokio stack never runs the interpreter
/// (even for a single input). Returns `None` if the pool is gone. Callers
/// that can await should use [`run_cpu`] so they do not hold a blocking thread.
pub fn run_detached_join<T, F>(work: F) -> Option<T>
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
