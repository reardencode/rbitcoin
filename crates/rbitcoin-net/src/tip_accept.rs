//! Process-wide `tip-accept` thread: P2P/RPC connect off tokio workers.
//!
//! Jobs are 1-block (or one `accept_branch` run). Confirm still uses
//! [`rbitcoin_consensus::confirm_wire_run_preverified`] (lookup → load →
//! `rbtc-scripts-*` steal → write). Not the IBD body-queue pipeline.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;

pub(crate) const TIP_ACCEPT_THREAD_NAME: &str = "tip-accept";

const QUEUE_CAP: usize = 8;

type Job = Box<dyn FnOnce() + Send>;

struct Inflight {
    n: AtomicU32,
    gen: AtomicU64,
    mu: Mutex<()>,
    cv: Condvar,
}

fn inflight() -> &'static Inflight {
    static I: OnceLock<Inflight> = OnceLock::new();
    I.get_or_init(|| Inflight {
        n: AtomicU32::new(0),
        gen: AtomicU64::new(0),
        mu: Mutex::new(()),
        cv: Condvar::new(),
    })
}

fn begin_job() {
    let i = inflight();
    i.gen.fetch_add(1, Ordering::SeqCst);
    i.n.fetch_add(1, Ordering::SeqCst);
}

fn end_job() {
    let i = inflight();
    let prev = i.n.fetch_sub(1, Ordering::SeqCst);
    if prev == 1 {
        let _g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
        i.cv.notify_all();
    }
}

struct InflightEnd;
impl Drop for InflightEnd {
    fn drop(&mut self) {
        end_job();
    }
}

/// Block until no tip-accept job is running. No-op on the lane itself
/// (nested generate/RPC must not deadlock).
pub(crate) fn wait_idle() {
    if on_tip_accept_thread() {
        return;
    }
    let i = inflight();
    let mut g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
    while i.n.load(Ordering::SeqCst) > 0 {
        g = i.cv.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

fn wait_tip_idle_from_env(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

/// Wait until the tip-accept job that was running when this call started
/// finishes. A queued follow-on accept may still be in flight.
pub(crate) fn wait_current_job() {
    if on_tip_accept_thread() {
        return;
    }
    let i = inflight();
    let mut g = i.mu.lock().unwrap_or_else(|e| e.into_inner());
    let snapshot = i.gen.load(Ordering::SeqCst);
    while i.n.load(Ordering::SeqCst) > 0 && i.gen.load(Ordering::SeqCst) == snapshot {
        g = i.cv.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// RPC / `wait_height` tip latch. Default is [`wait_current_job`].
/// `RBITCOIN_RPC_WAIT_TIP_IDLE=1` restores [`wait_idle`] (Core `sync_blocks`).
pub(crate) fn wait_for_rpc() {
    if wait_tip_idle_from_env(std::env::var("RBITCOIN_RPC_WAIT_TIP_IDLE").ok().as_deref()) {
        wait_idle();
    } else {
        wait_current_job();
    }
}

fn sender() -> SyncSender<Job> {
    static TX: OnceLock<SyncSender<Job>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE_CAP);
        thread::Builder::new()
            .name(TIP_ACCEPT_THREAD_NAME.into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let _ = panic::catch_unwind(AssertUnwindSafe(job));
                }
            })
            .expect("spawn tip-accept");
        tx
    })
    .clone()
}

pub(crate) fn on_tip_accept_thread() -> bool {
    thread::current().name() == Some(TIP_ACCEPT_THREAD_NAME)
}

fn erase_lifetime(job: Box<dyn FnOnce() + Send + '_>) -> Job {
    // SAFETY: `run_on_tip_accept` blocks on the result channel until `f`
    // returns, so captured borrows outlive the job. The async path is
    // `'static` and does not call this.
    unsafe { std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, Job>(job) }
}

/// Run `f` on `tip-accept`. Always enqueues (nested connect uses inner methods).
pub(crate) fn run_on_tip_accept<R: Send>(f: impl FnOnce() -> R + Send) -> R {
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

struct JobCell<R> {
    result: Mutex<Option<thread::Result<R>>>,
    waker: Mutex<Option<Waker>>,
}

struct JoinOnDrop<R> {
    cell: Arc<JobCell<R>>,
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

fn finish_cell<R>(cell: &JobCell<R>, r: thread::Result<R>) {
    *cell.result.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
    if let Some(w) = cell.waker.lock().unwrap_or_else(|p| p.into_inner()).take() {
        w.wake();
    }
}

/// Same as [`run_on_tip_accept`] but the caller `.await`s (peer session).
///
/// `f` is `'static`: dropping the session future does not join, so the job
/// must not borrow the caller's stack.
pub(crate) async fn run_on_tip_accept_async<R: Send + 'static>(
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
            Ok(()) => break,
            Err(TrySendError::Full(j)) => {
                job = j;
                tokio::task::yield_now().await;
            }
            Err(TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
        }
    }
    match (JoinOnDrop { cell }).await {
        Ok(v) => v,
        Err(p) => panic::resume_unwind(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_runs_on_named_thread() {
        let name = run_on_tip_accept(|| thread::current().name().map(str::to_string));
        assert_eq!(name.as_deref(), Some(TIP_ACCEPT_THREAD_NAME));
    }

    #[test]
    fn wait_idle_blocks_until_job_finishes() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            run_on_tip_accept(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        started_rx.recv().unwrap();
        let waiter = thread::spawn(wait_idle);
        thread::sleep(Duration::from_millis(20));
        assert!(
            !waiter.is_finished(),
            "wait_idle must not return while a tip-accept job is running"
        );
        release_tx.send(()).unwrap();
        waiter.join().expect("wait_idle");
        worker.join().expect("job");
        wait_idle();
    }

    #[test]
    fn wait_current_job_returns_while_second_job_queued() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (started1_tx, started1_rx) = mpsc::sync_channel(1);
        let (release1_tx, release1_rx) = mpsc::sync_channel(1);
        let (started2_tx, started2_rx) = mpsc::sync_channel(1);
        let (release2_tx, release2_rx) = mpsc::sync_channel(1);
        let first = thread::spawn(move || {
            run_on_tip_accept(move || {
                started1_tx.send(()).unwrap();
                release1_rx.recv().unwrap();
            });
        });
        started1_rx.recv().unwrap();
        let second = thread::spawn(move || {
            run_on_tip_accept(move || {
                started2_tx.send(()).unwrap();
                release2_rx.recv().unwrap();
            });
        });
        thread::sleep(Duration::from_millis(20));
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            wait_current_job();
            done_tx.send(()).ok();
        });
        thread::sleep(Duration::from_millis(20));
        assert!(
            done_rx.try_recv().is_err(),
            "wait_current_job must not return while the snapshotted job is running"
        );
        release1_tx.send(()).unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wait_current_job must return when job 1 ends");
        waiter.join().expect("wait_current_job thread");
        assert!(
            started2_rx.try_recv().is_err() || !second.is_finished(),
            "second job must still be queued or running after wait_current_job returns"
        );
        release2_tx.send(()).unwrap();
        first.join().expect("job1");
        second.join().expect("job2");
    }

    #[test]
    fn wait_tip_idle_from_env_only_one_and_true() {
        assert!(!wait_tip_idle_from_env(None));
        assert!(!wait_tip_idle_from_env(Some("")));
        assert!(!wait_tip_idle_from_env(Some("0")));
        assert!(!wait_tip_idle_from_env(Some("false")));
        assert!(wait_tip_idle_from_env(Some("1")));
        assert!(wait_tip_idle_from_env(Some("true")));
        assert!(wait_tip_idle_from_env(Some("TRUE")));
    }

    #[tokio::test]
    async fn lane_sync_from_current_thread_runtime() {
        assert_eq!(run_on_tip_accept(|| 7), 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lane_async_is_not_tokio_worker() {
        let task = tokio::spawn(async {
            let caller = thread::current().name().map(str::to_string);
            let name =
                run_on_tip_accept_async(|| thread::current().name().map(str::to_string)).await;
            (caller, name)
        });
        let (caller, name) = task.await.expect("join worker task");
        assert!(
            caller
                .as_deref()
                .is_some_and(|n| n.starts_with("tokio-rt-worker")),
            "spawned task must run on a tokio worker, got {caller:?}"
        );
        assert_eq!(name.as_deref(), Some(TIP_ACCEPT_THREAD_NAME));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn drop_join_does_not_park_worker() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Condvar;
        use std::time::{Duration, Instant};

        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
        // A failed assert must still wake the job. The tip-accept thread is
        // process-wide, and leaving it parked hangs every later test.
        let _wake = ReleaseOnDrop(Arc::clone(&release));
        let s2 = Arc::clone(&started);
        let r2 = Arc::clone(&release);
        let waiter = tokio::spawn(async move {
            run_on_tip_accept_async(move || {
                s2.store(true, Ordering::Release);
                let (lock, cv) = &*r2;
                let mut g = lock.lock().unwrap();
                while !*g {
                    g = cv.wait(g).unwrap();
                }
                1u8
            })
            .await
        });
        // The lane is shared by every test in this binary. A journey that
        // mines 100+ blocks is one job and can hold it for seconds under load.
        let t0 = Instant::now();
        while !started.load(Ordering::Acquire) {
            assert!(t0.elapsed() < Duration::from_secs(60), "job never started");
            tokio::task::yield_now().await;
        }
        waiter.abort();
        let progressed = tokio::time::timeout(Duration::from_millis(200), async {
            tokio::task::yield_now().await;
            1u8
        })
        .await;
        assert!(
            progressed.is_ok(),
            "JoinOnDrop must not park the tokio worker"
        );
        drop(_wake);
    }

    struct ReleaseOnDrop(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, cv) = &*self.0;
            *lock.lock().unwrap() = true;
            cv.notify_one();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_job_finishes_after_waiter_abort() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let saw = Arc::new(AtomicU8::new(0));
        let saw_job = Arc::clone(&saw);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let waiter = tokio::spawn(async move {
            run_on_tip_accept_async(move || {
                saw_job.fetch_add(1, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                let _ = release_rx.recv();
                saw_job.fetch_add(1, Ordering::SeqCst);
            })
            .await;
        });
        started_rx.recv().expect("job started");
        waiter.abort();
        release_tx.send(()).unwrap();
        let t0 = Instant::now();
        while saw.load(Ordering::SeqCst) < 2 {
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "aborted waiter left the tip-accept job unfinished"
            );
            tokio::task::yield_now().await;
        }
        wait_idle();
    }
}
