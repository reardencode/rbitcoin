//! Process-wide `tip-accept` thread: P2P/RPC connect off tokio workers.
//!
//! Jobs are 1-block (or one `accept_branch` run). Confirm still uses
//! [`rbitcoin_consensus::confirm_wire_run_preverified`] (lookup → load →
//! `rbtc-scripts-*` steal → write). Not the IBD body-queue pipeline.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;

pub(crate) const TIP_ACCEPT_THREAD_NAME: &str = "tip-accept";

const QUEUE_CAP: usize = 8;

type Job = Box<dyn FnOnce() + Send>;

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
    // returns. `run_on_tip_accept_async` waits on a condvar in Drop of the
    // future, which still holds the caller's borrows (`&self` on ChainHub).
    unsafe { std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, Job>(job) }
}

/// Run `f` on `tip-accept`. Always enqueues (nested connect uses inner methods).
pub(crate) fn run_on_tip_accept<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let job = erase_lifetime(Box::new(move || {
        let _ = tx.send(panic::catch_unwind(AssertUnwindSafe(f)));
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
    cv: Condvar,
}

struct JoinOnDrop<R> {
    cell: Arc<JobCell<R>>,
    taken: bool,
}

impl<R> Future for JoinOnDrop<R> {
    type Output = thread::Result<R>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut g = this.cell.result.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = g.take() {
            this.taken = true;
            return Poll::Ready(r);
        }
        *this.cell.waker.lock().unwrap_or_else(|p| p.into_inner()) = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl<R> Drop for JoinOnDrop<R> {
    fn drop(&mut self) {
        if self.taken {
            return;
        }
        let mut g = self.cell.result.lock().unwrap_or_else(|p| p.into_inner());
        while g.is_none() {
            g = self.cell.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

fn finish_cell<R>(cell: &JobCell<R>, r: thread::Result<R>) {
    *cell.result.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
    cell.cv.notify_one();
    if let Some(w) = cell.waker.lock().unwrap_or_else(|p| p.into_inner()).take() {
        w.wake();
    }
}

/// Same as [`run_on_tip_accept`] but the caller `.await`s (peer session).
pub(crate) async fn run_on_tip_accept_async<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let cell = Arc::new(JobCell {
        result: Mutex::new(None),
        waker: Mutex::new(None),
        cv: Condvar::new(),
    });
    let cell_w = Arc::clone(&cell);
    let job = erase_lifetime(Box::new(move || {
        finish_cell(&cell_w, panic::catch_unwind(AssertUnwindSafe(f)));
    }));
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
    match (JoinOnDrop { cell, taken: false }).await {
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
    fn lane_survives_job_panic() {
        let panicked = panic::catch_unwind(|| {
            run_on_tip_accept(|| panic!("tip-accept test panic"));
        });
        assert!(panicked.is_err());
        assert_eq!(run_on_tip_accept(|| 2 + 2), 4);
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
}
