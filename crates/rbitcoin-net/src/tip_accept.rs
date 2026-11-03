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
/// (nested generate/RPC must not deadlock).
pub fn wait_idle() {
    park_until_idle(true);
}

/// `announce` publishes [`note_wait_seen`] for the waiter tests. The permit
/// drain passes `false`: that wait is not one of those waiters.
fn park_until_idle(announce: bool) {
    if on_tip_accept_thread() {
        return;
    }
    let i = inflight();
    let mut g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
    while i.n.load(Ordering::SeqCst) > 0 {
        if announce {
            note_wait_seen();
        } else {
            // Before the condvar wait, so a subscriber unblocks only once
            // this thread has observed `n > 0`. This arm does not call
            // `note_wait_seen`.
            note_quiet_drain();
        }
        g = i.cv.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// Drain a running tip-accept job without publishing [`note_wait_seen`].
/// [`LanePermit::take`] uses this. The permit is already held by the caller
/// when a test uses it directly, so the drain does not enqueue.
#[doc(hidden)]
pub fn quiet_drain_for_tests() {
    park_until_idle(false);
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
/// drops, unless the caller is the permit thread or armed
/// [`arm_lane_oneshot`] for this entry. Production never sets the flag, so
/// the accept path does not take the lock.
#[cfg(debug_assertions)]
static LANE_GATE_ON: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE_MU: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
static LANE_EXCLUSIVE_CV: Condvar = Condvar::new();

#[cfg(debug_assertions)]
thread_local! {
    static LANE_HELD: Cell<u32> = const { Cell::new(0) };
    static LANE_ONESHOT: Cell<bool> = const { Cell::new(false) };
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
    if oneshot || lane_held_after_revoke() > 0 {
        return true;
    }
    LANE_TASK_EXEMPT.try_with(|_| ()).is_ok()
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
        g = LANE_EXCLUSIVE_CV.wait(g).unwrap_or_else(|p| p.into_inner());
    }
    Some(g)
}

#[cfg(not(debug_assertions))]
fn lane_send_guard(_exempt: bool) -> Option<std::sync::MutexGuard<'static, ()>> {
    None
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
            LANE_HELD.with(|c| c.set(c.get().saturating_add(1)));
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
                LANE_HELD.with(|c| c.set(c.get().saturating_sub(1)));
            } else {
                revoke_lane_held(self.owner);
            }
            let _g = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
            LANE_EXCLUSIVE.store(false, Ordering::Release);
            LANE_EXCLUSIVE_CV.notify_all();
            // Async senders wait on this. A condvar would park the worker
            // inside the poll, so the caller's timeout would not run.
            lane_exclusive_notify().notify_waiters();
        }
    }
}

tokio::task_local! {
    static LANE_TASK_EXEMPT: ();
}

/// The spawning thread holds a [`LanePermit`]. `spawn_with_store_budget`
/// copies that into the child so an async accept does not wait on its own
/// caller's permit.
#[doc(hidden)]
pub fn spawn_inherits_lane_permit() -> bool {
    #[cfg(debug_assertions)]
    {
        lane_test_gate_enabled() && lane_held_after_revoke() > 0
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

#[doc(hidden)]
pub async fn enter_lane_task_exemption<F: Future>(fut: F) -> F::Output {
    LANE_TASK_EXEMPT.scope((), fut).await
}

#[cfg(debug_assertions)]
fn lane_exclusive_notify() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
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
        LANE_HELD.with(|c| c.set(c.get().saturating_sub(1)));
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

/// `Err(job)` when the queue is full. A held permit is awaited here, not
/// inside a worker-blocking condvar.
async fn send_or_full(exempt: bool, job: Job) -> Result<(), Job> {
    #[cfg(debug_assertions)]
    if !exempt && lane_test_gate_enabled() {
        return send_or_full_gated(job).await;
    }
    match sender().try_send(job) {
        Ok(()) => {
            note_async_enqueued();
            Ok(())
        }
        Err(TrySendError::Full(j)) => Err(j),
        Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
    }
}

#[cfg(debug_assertions)]
async fn send_or_full_gated(job: Job) -> Result<(), Job> {
    loop {
        let notified = lane_exclusive_notify().notified();
        tokio::pin!(notified);
        {
            let _gate = LANE_EXCLUSIVE_MU.lock().unwrap_or_else(|p| p.into_inner());
            if !LANE_EXCLUSIVE.load(Ordering::Acquire) {
                return match sender().try_send(job) {
                    Ok(()) => {
                        note_async_enqueued();
                        Ok(())
                    }
                    Err(TrySendError::Full(j)) => Err(j),
                    Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
                };
            }
            notified.as_mut().enable();
        }
        notified.await;
    }
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
        let _gate = lane_send_guard(exempt);
        sender().send(job).expect("tip-accept thread");
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
        match send_or_full(exempt, job).await {
            Ok(()) => break,
            Err(j) => job = j,
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
        match send_or_full(exempt, job).await {
            Ok(()) => break,
            Err(j) => job = j,
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
