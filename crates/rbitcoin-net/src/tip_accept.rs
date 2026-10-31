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

fn slot_freed() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

fn wait_seen_subs() -> &'static Mutex<Vec<mpsc::Sender<()>>> {
    static S: OnceLock<Mutex<Vec<mpsc::Sender<()>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// One message when a waiter has observed a running job and is about to wait.
#[doc(hidden)]
pub fn subscribe_wait_seen() -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    wait_seen_subs()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(tx);
    rx
}

fn note_wait_seen() {
    let mut subs = wait_seen_subs().lock().unwrap_or_else(|e| e.into_inner());
    subs.retain(|tx| tx.send(()).is_ok());
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
    crate::reactor::assert_not_reactor("tip-accept wait");
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let job = erase_lifetime(Box::new(move || {
        begin_job();
        let _end = InflightEnd;
        let r = panic::catch_unwind(AssertUnwindSafe(f));
        let _ = tx.send(r);
    }));
    sender().send(job).expect("tip-accept thread");
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
        match sender().try_send(job) {
            Ok(()) => {
                note_async_enqueued();
                break;
            }
            Err(TrySendError::Full(j)) => {
                job = j;
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
                match sender().try_send(job) {
                    Ok(()) => {
                        note_async_enqueued();
                        break;
                    }
                    Err(TrySendError::Full(j)) => {
                        job = j;
                        FULL_QUEUE_SPINS.fetch_add(1, Ordering::Relaxed);
                        note_send_parked();
                        notified.await;
                    }
                    Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
                }
            }
            Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
        }
    }
    match (JoinOnDrop { cell }).await {
        Ok(v) => v,
        Err(p) => panic::resume_unwind(p),
    }
}
