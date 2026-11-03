//! Process-wide `tip-accept` thread: P2P/RPC connect off tokio workers.
//!
//! Jobs are 1-block (or one `accept_branch` run). Confirm still uses
//! [`rbitcoin_query::confirm_wire_run_preverified`] (lookup → load →
//! `rbtc-scripts-*` steal → write). Not the IBD body-queue pipeline.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
#[cfg(debug_assertions)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;

pub const TIP_ACCEPT_THREAD_NAME: &str = "tip-accept";

#[doc(hidden)]
pub const QUEUE_CAP: usize = 8;

/// Sync senders blocked in the permit mutex. An async poll must not join them.
#[doc(hidden)]
pub static LANE_SEND_GUARD_WAITERS: AtomicUsize = AtomicUsize::new(0);

/// Callers inside [`hold_lane_mutex_for_tests`] after the lock is taken.
/// Condvar waiters do not increment this.
#[doc(hidden)]
pub static LANE_MUTEX_HOLDERS: AtomicUsize = AtomicUsize::new(0);

/// Failed async `try_send`s on a full tip-accept queue. A parked sender
/// records a handful. A yield loop keeps adding.
#[doc(hidden)]
pub static FULL_QUEUE_SPINS: AtomicUsize = AtomicUsize::new(0);

/// Successful `try_send`s from [`run_on_tip_accept_async`].
#[doc(hidden)]
pub static TIP_ASYNC_ENQUEUED: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub type Job = Box<dyn FnOnce() + Send>;

#[doc(hidden)]
pub struct Inflight {
    pub n: AtomicU32,
    pub gen: AtomicU64,
    pub mu: Mutex<()>,
    pub cv: Condvar,
}

#[doc(hidden)]
pub fn inflight() -> &'static Inflight {
    static I: OnceLock<Inflight> = OnceLock::new();
    I.get_or_init(|| Inflight {
        n: AtomicU32::new(0),
        gen: AtomicU64::new(0),
        mu: Mutex::new(()),
        cv: Condvar::new(),
    })
}

#[doc(hidden)]
pub fn begin_job() {
    let i = inflight();
    i.gen.fetch_add(1, Ordering::SeqCst);
    i.n.fetch_add(1, Ordering::SeqCst);
}

#[doc(hidden)]
pub fn end_job() {
    let i = inflight();
    let prev = i.n.fetch_sub(1, Ordering::SeqCst);
    if prev == 1 {
        let _g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
        i.cv.notify_all();
    }
}

#[doc(hidden)]
pub struct InflightEnd;
impl Drop for InflightEnd {
    fn drop(&mut self) {
        end_job();
    }
}

/// Block until no tip-accept job is running. No-op on the lane itself
/// (nested generate/RPC must not deadlock). A job still sitting in the
/// queue has not called [`begin_job`]; this wait does not see it.
/// [`quiet_drain_for_tests`] does.
pub fn wait_idle() {
    if on_tip_accept_thread() {
        return;
    }
    let i = inflight();
    let mut g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
    while i.n.load(Ordering::SeqCst) > 0 {
        note_wait_seen();
        g = i.cv.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// Drain every job that has been handed to the lane, including ones that
/// have not called [`begin_job`]. Does not publish [`note_wait_seen`].
#[doc(hidden)]
pub fn quiet_drain_for_tests() {
    if on_tip_accept_thread() {
        return;
    }
    #[cfg(debug_assertions)]
    {
        let q = lane_queued();
        let mut g = q.mu.lock().unwrap_or_else(|e| e.into_inner());
        while q.n.load(Ordering::SeqCst) > 0 {
            // Before the condvar wait, so a subscriber unblocks only once
            // this thread has observed a queued job. Not `note_wait_seen`.
            note_quiet_drain();
            g = q.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Wait until the tip-accept job that was running when this call started
/// finishes. A queued follow-on accept may still be in flight.
pub fn wait_current_job() {
    if on_tip_accept_thread() {
        return;
    }
    let i = inflight();
    let mut g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
    let snapshot = i.gen.load(Ordering::SeqCst);
    while i.n.load(Ordering::SeqCst) > 0 && i.gen.load(Ordering::SeqCst) == snapshot {
        note_wait_seen();
        g = i.cv.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

#[doc(hidden)]
pub fn sender() -> SyncSender<Job> {
    static TX: OnceLock<SyncSender<Job>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE_CAP);
        thread::Builder::new()
            .name(TIP_ACCEPT_THREAD_NAME.into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    // The recv freed a queue slot. Wake one async sender that
                    // found the channel full. A permit with no waiter is kept
                    // for the next `Notified::enable`.
                    slot_freed().notify_one();
                    let _ = panic::catch_unwind(AssertUnwindSafe(job));
                    // After the job returns, including fillers that never
                    // call `begin_job`. `quiet_drain_for_tests` waits on this.
                    note_dequeued();
                }
            })
            .expect("spawn tip-accept");
        tx
    })
    .clone()
}

pub fn on_tip_accept_thread() -> bool {
    thread::current().name() == Some(TIP_ACCEPT_THREAD_NAME)
}

/// Process-wide exclusion for tests that fill or inspect the lane.
///
/// Debug builds take [`LANE_EXCLUSIVE_MU`] across each enqueue only after
/// [`enable_lane_test_gate`]. Release accepts do not. A test holds
/// [`LanePermit`] for its whole body. Other enqueues wait until that permit
/// drops, unless the caller is the task that took it (or the plain thread,
/// when `take` was not inside a task) or armed [`arm_lane_oneshot`] for this
/// entry. A later task on that same worker is not exempt. Production never
/// sets the flag, so the accept path does not take the lock.
#[cfg(debug_assertions)]
static LANE_GATE_ON: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE_MU: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE_CV: Condvar = Condvar::new();

#[cfg(debug_assertions)]
#[derive(Clone, Copy)]
enum LaneOwner {
    Empty,
    /// `take` ran outside a tokio task. That thread is the holder.
    PlainThread,
    Task(tokio::task::Id),
}

#[cfg(debug_assertions)]
thread_local! {
    static LANE_HELD: Cell<u32> = const { Cell::new(0) };
    static LANE_ONESHOT: Cell<bool> = const { Cell::new(false) };
    static LANE_OWNER: Cell<LaneOwner> = const { Cell::new(LaneOwner::Empty) };
}

#[cfg(debug_assertions)]
use std::cell::Cell;

/// Opt in for the process. The net suite calls this before any test. A node
/// never does, and then [`lane_send_guard`] does not lock. This does not
/// exempt a thread; that is [`arm_lane_oneshot`].
#[doc(hidden)]
pub fn enable_lane_test_gate() {
    #[cfg(debug_assertions)]
    LANE_GATE_ON.store(true, Ordering::Release);
}

/// The suite initializer ran. [`LanePermit::take`] does not set this.
#[doc(hidden)]
pub fn lane_test_gate_enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        LANE_GATE_ON.load(Ordering::Acquire)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Let the next [`run_on_tip_accept`] or [`run_on_tip_accept_async`] on this
/// thread enter while a [`LanePermit`] is held. Consumed at that entry, before
/// any `.await`, so a tokio worker does not stay exempt for the next task.
#[doc(hidden)]
pub fn arm_lane_oneshot() {
    #[cfg(debug_assertions)]
    LANE_ONESHOT.with(|c| c.set(true));
}

/// True for this whole entry. The oneshot is consumed once so a retry loop
/// does not lose it, and a tokio worker is not left exempt after the poll.
#[cfg(debug_assertions)]
fn take_lane_exemption() -> bool {
    if on_tip_accept_thread() {
        return true;
    }
    let oneshot = LANE_ONESHOT.with(|c| c.replace(false));
    if oneshot {
        return true;
    }
    if lane_held_after_revoke() == 0 {
        return false;
    }
    // `LANE_HELD` is the worker thread. Another task polled there is not
    // the holder. A plain-thread take has no task id to compare.
    match LANE_OWNER.with(|c| c.get()) {
        LaneOwner::Empty => false,
        // A task polled on this thread is not the plain-thread holder.
        LaneOwner::PlainThread => tokio::task::try_id().is_none(),
        LaneOwner::Task(id) => tokio::task::try_id() == Some(id),
    }
}

#[cfg(not(debug_assertions))]
fn take_lane_exemption() -> bool {
    true
}

/// Held across `send` / `try_send` so [`LanePermit::take`] cannot miss a
/// caller that already decided the lane was free. `None` when this entry is
/// exempt (the permit holder, or release builds).
#[cfg(debug_assertions)]
fn lane_send_guard(exempt: bool) -> Option<std::sync::MutexGuard<'static, ()>> {
    if exempt || !LANE_GATE_ON.load(Ordering::Acquire) {
        return None;
    }
    let mut g = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
    while LANE_EXCLUSIVE.load(Ordering::Acquire) {
        LANE_SEND_GUARD_WAITERS.fetch_add(1, Ordering::SeqCst);
        g = LANE_EXCLUSIVE_CV.wait(g).unwrap_or_else(|p| p.into_inner());
        LANE_SEND_GUARD_WAITERS.fetch_sub(1, Ordering::SeqCst);
    }
    Some(g)
}

#[cfg(not(debug_assertions))]
fn lane_send_guard(_exempt: bool) -> Option<std::sync::MutexGuard<'static, ()>> {
    None
}

#[cfg(debug_assertions)]
enum LaneGate {
    /// `Some` holds the exclusive mutex across the send. `None` is exempt
    /// or the suite gate is off, so the send does not lock.
    Clear(Option<std::sync::MutexGuard<'static, ()>>),
    Busy,
}

#[cfg(debug_assertions)]
fn lane_poll_gate(exempt: bool) -> LaneGate {
    if exempt || !LANE_GATE_ON.load(Ordering::Acquire) {
        return LaneGate::Clear(None);
    }
    // `try_lock`: `hold_lane_mutex_for_tests` keeps this mutex. `lock` here
    // would park the worker inside `timeout`'s future. `send` does not.
    let g = match LANE_EXCLUSIVE_MU.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return LaneGate::Busy,
    };
    if LANE_EXCLUSIVE.load(Ordering::Acquire) {
        LaneGate::Busy
    } else {
        LaneGate::Clear(Some(g))
    }
}

#[cfg(debug_assertions)]
fn lane_exclusive_notify() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// The permit flag is set. Yield so a tokio timeout can fire. The sleep
/// covers `notify_waiters`, which does not leave a permit for a later waiter.
#[cfg(debug_assertions)]
async fn wait_lane_permit() {
    let notified = lane_exclusive_notify().notified();
    tokio::pin!(notified);
    let still_blocked = match LANE_EXCLUSIVE_MU.try_lock() {
        Ok(g) => {
            let busy = LANE_EXCLUSIVE.load(Ordering::Acquire);
            drop(g);
            busy
        }
        Err(std::sync::TryLockError::Poisoned(p)) => {
            let g = p.into_inner();
            let busy = LANE_EXCLUSIVE.load(Ordering::Acquire);
            drop(g);
            busy
        }
        // The sync sender still holds the mutex across `send`. Sleep.
        Err(std::sync::TryLockError::WouldBlock) => true,
    };
    if !still_blocked {
        return;
    }
    tokio::select! {
        _ = notified => {}
        _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
    }
}

/// Jobs accepted onto the lane and not yet finished. Includes fillers that
/// never call [`begin_job`], and jobs still sitting in the sync channel.
#[cfg(debug_assertions)]
struct LaneQueued {
    n: AtomicUsize,
    mu: Mutex<()>,
    cv: Condvar,
}

#[cfg(debug_assertions)]
fn lane_queued() -> &'static LaneQueued {
    static Q: OnceLock<LaneQueued> = OnceLock::new();
    Q.get_or_init(|| LaneQueued {
        n: AtomicUsize::new(0),
        mu: Mutex::new(()),
        cv: Condvar::new(),
    })
}

fn note_queued() {
    #[cfg(debug_assertions)]
    lane_queued().n.fetch_add(1, Ordering::SeqCst);
}

fn note_dequeued() {
    #[cfg(debug_assertions)]
    {
        let q = lane_queued();
        let prev = q.n.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            let _g = q.mu.lock().unwrap_or_else(|e| e.into_inner());
            q.cv.notify_all();
        }
    }
}

enum PollEnqueue {
    Sent,
    Full(Job),
    #[cfg(debug_assertions)]
    Busy(Job),
}

/// Count the job, then `try_send`. A failed send drops the count. Callers
/// that must not race [`LanePermit::take`] hold the exclusive mutex across
/// this call. Fillers do not: they run while a permit is already held.
#[doc(hidden)]
pub fn try_enqueue(job: Job) -> Result<(), TrySendError<Job>> {
    note_queued();
    match sender().try_send(job) {
        Ok(()) => Ok(()),
        Err(e) => {
            note_dequeued();
            Err(e)
        }
    }
}

/// Hold the permit mutex without releasing it on the exclusive condvar.
/// Async polls use `try_lock` and must time out while this runs.
#[doc(hidden)]
pub fn hold_lane_mutex_for_tests(release: &std::sync::Arc<(Mutex<bool>, Condvar)>) {
    #[cfg(debug_assertions)]
    let _gate = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
    LANE_MUTEX_HOLDERS.fetch_add(1, Ordering::SeqCst);
    let (lock, cv) = &**release;
    let mut w = lock.lock().unwrap_or_else(|p| p.into_inner());
    while !*w {
        w = cv.wait(w).unwrap_or_else(|p| p.into_inner());
    }
    LANE_MUTEX_HOLDERS.fetch_sub(1, Ordering::SeqCst);
}

fn poll_try_enqueue(exempt: bool, job: Job) -> PollEnqueue {
    #[cfg(debug_assertions)]
    {
        match lane_poll_gate(exempt) {
            LaneGate::Busy => PollEnqueue::Busy(job),
            LaneGate::Clear(gate) => {
                let out = match try_enqueue(job) {
                    Ok(()) => PollEnqueue::Sent,
                    Err(TrySendError::Full(j)) => PollEnqueue::Full(j),
                    Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
                };
                drop(gate);
                out
            }
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = exempt;
        match try_enqueue(job) {
            Ok(()) => PollEnqueue::Sent,
            Err(TrySendError::Full(j)) => PollEnqueue::Full(j),
            Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
        }
    }
}

/// Hold for a test that uses the process-wide tip-accept lane. Other lane
/// entries in this process wait until the guard drops.
#[doc(hidden)]
pub struct LanePermit {
    /// Thread that incremented the permit hold. Drop on any other thread must
    /// not leave that increment behind.
    #[cfg(debug_assertions)]
    owner: thread::ThreadId,
}

impl LanePermit {
    pub fn take() -> Self {
        #[cfg(debug_assertions)]
        {
            let mut g = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
            while LANE_EXCLUSIVE.load(Ordering::Acquire) {
                g = LANE_EXCLUSIVE_CV.wait(g).unwrap_or_else(|p| p.into_inner());
            }
            LANE_EXCLUSIVE.store(true, Ordering::Release);
            drop(g);
            // A permit dropped on another thread left a revoke for us.
            // Clear it before this take adds its own hold.
            let _ = lane_held_after_revoke();
            hold_lane();
            // Same drain the waiter test calls. It does not publish
            // `note_wait_seen`.
            quiet_drain_for_tests();
        }
        Self {
            #[cfg(debug_assertions)]
            owner: thread::current().id(),
        }
    }
}

impl Drop for LanePermit {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            if thread::current().id() == self.owner {
                release_lane_hold();
            } else {
                revoke_lane_held(self.owner);
            }
            let _g = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
            LANE_EXCLUSIVE.store(false, Ordering::Release);
            LANE_EXCLUSIVE_CV.notify_all();
            // While the flag is still held, so a waiter that checks after
            // this unlock sees it clear. `notify_waiters` does not store a
            // permit; the async wait also sleeps.
            lane_exclusive_notify().notify_waiters();
        }
    }
}

#[cfg(debug_assertions)]
static LANE_HELD_REVOKES: Mutex<Vec<thread::ThreadId>> = Mutex::new(Vec::new());

#[cfg(debug_assertions)]
fn revoke_lane_held(owner: thread::ThreadId) {
    LANE_HELD_REVOKES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(owner);
}

#[cfg(debug_assertions)]
fn apply_lane_held_revoke() {
    let id = thread::current().id();
    let mut revoked = LANE_HELD_REVOKES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = revoked.iter().position(|held| *held == id) {
        revoked.swap_remove(i);
        release_lane_hold();
    }
}

#[cfg(debug_assertions)]
fn hold_lane() {
    let n = LANE_HELD.with(|c| {
        let n = c.get().saturating_add(1);
        c.set(n);
        n
    });
    if n != 1 {
        return;
    }
    let owner = match tokio::task::try_id() {
        Some(id) => LaneOwner::Task(id),
        None => LaneOwner::PlainThread,
    };
    LANE_OWNER.with(|c| c.set(owner));
}

#[cfg(debug_assertions)]
fn release_lane_hold() {
    let n = LANE_HELD.with(|c| {
        let n = c.get().saturating_sub(1);
        c.set(n);
        n
    });
    if n == 0 {
        LANE_OWNER.with(|c| c.set(LaneOwner::Empty));
    }
}

/// Holds still charged to this thread. Applies a cross-thread drop first.
#[cfg(debug_assertions)]
fn lane_held_after_revoke() -> u32 {
    if LANE_GATE_ON.load(Ordering::Acquire) {
        apply_lane_held_revoke();
    }
    LANE_HELD.with(|c| c.get())
}

/// Test read of the permit hold on this thread.
#[doc(hidden)]
pub fn lane_held_for_tests() -> u32 {
    #[cfg(debug_assertions)]
    {
        lane_held_after_revoke()
    }
    #[cfg(not(debug_assertions))]
    {
        0
    }
}

fn slot_freed() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

fn wait_seen_subs() -> &'static Mutex<Vec<mpsc::Sender<thread::ThreadId>>> {
    static S: OnceLock<Mutex<Vec<mpsc::Sender<thread::ThreadId>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// One message per observation, carrying the waiter thread. Callers keep the
/// id they spawned and ignore every other waiter.
#[doc(hidden)]
pub fn subscribe_wait_seen() -> mpsc::Receiver<thread::ThreadId> {
    let (tx, rx) = mpsc::channel();
    wait_seen_subs()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(tx);
    rx
}

/// True when `id` itself has observed a running job and is about to wait.
#[doc(hidden)]
pub fn wait_seen_from(
    rx: &mpsc::Receiver<thread::ThreadId>,
    id: thread::ThreadId,
    timeout: std::time::Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(noted) if noted == id => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    false
}

fn note_wait_seen() {
    let id = thread::current().id();
    let mut subs = wait_seen_subs().lock().unwrap_or_else(|e| e.into_inner());
    subs.retain(|tx| tx.send(id).is_ok());
}

fn quiet_drain_subs() -> &'static Mutex<Vec<mpsc::Sender<thread::ThreadId>>> {
    static S: OnceLock<Mutex<Vec<mpsc::Sender<thread::ThreadId>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// One message when [`quiet_drain_for_tests`] has observed a running job.
#[doc(hidden)]
pub fn subscribe_quiet_drain() -> mpsc::Receiver<thread::ThreadId> {
    let (tx, rx) = mpsc::channel();
    quiet_drain_subs()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(tx);
    rx
}

#[cfg(debug_assertions)]
fn note_quiet_drain() {
    let id = thread::current().id();
    let mut subs = quiet_drain_subs().lock().unwrap_or_else(|e| e.into_inner());
    subs.retain(|tx| tx.send(id).is_ok());
}

fn send_parked() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// The async sender is inside its `slot_freed` wait.
#[doc(hidden)]
pub fn send_parked_notify() -> &'static tokio::sync::Notify {
    send_parked()
}

fn note_send_parked() {
    send_parked().notify_one();
}

fn note_async_enqueued() {
    TIP_ASYNC_ENQUEUED.fetch_add(1, Ordering::Relaxed);
    // The recv that opened this slot may have coalesced with an earlier
    // `notify_one`. Wake one parked sender so it observes the free slot.
    slot_freed().notify_one();
}

/// Test gate between "queue was full" and `Notified::enable`. A burst of
/// `notify_one` in that window stores one permit. The pin holds senders there
/// while the lane drains.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static TIP_PARK_DELAY: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static TIP_PARK_ENTERED: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
#[doc(hidden)]
pub static TIP_PARK_GO: AtomicBool = AtomicBool::new(false);

#[cfg(debug_assertions)]
fn tip_park_notify() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn tip_park_gate_notify() {
    tip_park_notify().notify_waiters();
}

#[cfg(debug_assertions)]
async fn wait_park_gate() {
    if !TIP_PARK_DELAY.load(Ordering::SeqCst) || TIP_PARK_GO.load(Ordering::SeqCst) {
        return;
    }
    let notified = tip_park_notify().notified();
    tokio::pin!(notified);
    if TIP_PARK_GO.load(Ordering::SeqCst) || !TIP_PARK_DELAY.load(Ordering::SeqCst) {
        return;
    }
    TIP_PARK_ENTERED.fetch_add(1, Ordering::SeqCst);
    if !notified.as_mut().enable() {
        if TIP_PARK_GO.load(Ordering::SeqCst) || !TIP_PARK_DELAY.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

#[doc(hidden)]
pub fn erase_lifetime(job: Box<dyn FnOnce() + Send + '_>) -> Job {
    // SAFETY: `run_on_tip_accept` blocks on the result channel until `f`
    // returns, so captured borrows outlive the job. The async path is
    // `'static` and does not call this.
    unsafe { std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, Job>(job) }
}

/// Run `f` on `tip-accept`. Always enqueues (nested connect uses inner methods).
pub fn run_on_tip_accept<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let exempt = take_lane_exemption();
    crate::reactor::assert_not_reactor("tip-accept wait");
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let job = erase_lifetime(Box::new(move || {
        begin_job();
        let _end = InflightEnd;
        let r = panic::catch_unwind(AssertUnwindSafe(f));
        let _ = tx.send(r);
    }));
    {
        // Count under the mutex, then drop it before `send`. A full queue
        // blocks, and the async poll must still be able to `try_lock`.
        let gate = lane_send_guard(exempt);
        note_queued();
        drop(gate);
        let sent = sender().send(job);
        if sent.is_err() {
            note_dequeued();
            panic!("tip-accept thread");
        }
    }
    match rx.recv().expect("tip-accept job") {
        Ok(v) => v,
        Err(p) => panic::resume_unwind(p),
    }
}

#[doc(hidden)]
pub struct JobCell<R> {
    pub result: Mutex<Option<thread::Result<R>>>,
    pub waker: Mutex<Option<Waker>>,
}

#[doc(hidden)]
pub struct JoinOnDrop<R> {
    pub cell: Arc<JobCell<R>>,
}

impl<R> Future for JoinOnDrop<R> {
    type Output = thread::Result<R>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut g = this.cell.result.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = g.take() {
            return Poll::Ready(r);
        }
        *this.cell.waker.lock().unwrap_or_else(|p| p.into_inner()) = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[doc(hidden)]
pub fn finish_cell<R>(cell: &JobCell<R>, r: thread::Result<R>) {
    *cell.result.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
    if let Some(w) = cell.waker.lock().unwrap_or_else(|p| p.into_inner()).take() {
        w.wake();
    }
}

/// Same as [`run_on_tip_accept`] but the caller `.await`s (peer session).
///
/// `f` is `'static`: dropping the session future does not join, so the job
/// must not borrow the caller's stack.
pub async fn run_on_tip_accept_async<R: Send + 'static>(
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    // Before the first `.await`, so [`arm_lane_oneshot`] is consumed on this poll.
    let exempt = take_lane_exemption();
    let cell = Arc::new(JobCell {
        result: Mutex::new(None),
        waker: Mutex::new(None),
    });
    let cell_w = Arc::clone(&cell);
    let job: Job = Box::new(move || {
        begin_job();
        let _end = InflightEnd;
        let r = panic::catch_unwind(AssertUnwindSafe(f));
        finish_cell(&cell_w, r);
    });
    let mut job = job;
    loop {
        match poll_try_enqueue(exempt, job) {
            PollEnqueue::Sent => {
                note_async_enqueued();
                break;
            }
            #[cfg(debug_assertions)]
            PollEnqueue::Busy(j) => {
                job = j;
                wait_lane_permit().await;
                continue;
            }
            PollEnqueue::Full(j) => job = j,
        }
        FULL_QUEUE_SPINS.fetch_add(1, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        wait_park_gate().await;
        let notified = slot_freed().notified();
        tokio::pin!(notified);
        // `notify_one` keeps a single permit when no waiter is
        // registered. `enable` consumes that permit for one sender.
        // Every other sender that already saw Full must try again
        // before it sleeps, or a free slot stays empty.
        if notified.as_mut().enable() {
            continue;
        }
        match poll_try_enqueue(exempt, job) {
            PollEnqueue::Sent => {
                note_async_enqueued();
                break;
            }
            #[cfg(debug_assertions)]
            PollEnqueue::Busy(j) => {
                job = j;
                wait_lane_permit().await;
                continue;
            }
            PollEnqueue::Full(j) => job = j,
        }
        FULL_QUEUE_SPINS.fetch_add(1, Ordering::Relaxed);
        note_send_parked();
        notified.await;
    }
    match (JoinOnDrop { cell }).await {
        Ok(v) => v,
        Err(p) => panic::resume_unwind(p),
    }
}
