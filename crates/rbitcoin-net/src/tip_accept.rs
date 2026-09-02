//! Process-wide `tip-accept` thread: P2P/RPC connect off tokio workers.
//!
//! Jobs are 1-block (or one `accept_branch` run). Confirm still uses
//! [`rbitcoin_consensus::confirm_wire_run_preverified`] (lookup → load →
//! `rbtc-scripts-*` steal → write). Not the IBD body-queue pipeline.

use std::future::{poll_fn, Future};
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::OnceLock;
use std::thread;
use tokio::sync::mpsc::Sender;

pub(crate) const TIP_ACCEPT_THREAD_NAME: &str = "tip-accept";

const QUEUE_CAP: usize = 8;

type Job = Box<dyn FnOnce() + Send>;

fn sender() -> Sender<Job> {
    static TX: OnceLock<Sender<Job>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Job>(QUEUE_CAP);
        thread::Builder::new()
            .name(TIP_ACCEPT_THREAD_NAME.into())
            .spawn(move || {
                while let Some(job) = rx.blocking_recv() {
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

pub(crate) fn is_tokio_runtime_worker() -> bool {
    thread::current()
        .name()
        .is_some_and(|n| n.starts_with("tokio-rt-worker") || n.starts_with("tokio-runtime-worker"))
}

fn erase_lifetime(job: Box<dyn FnOnce() + Send + '_>) -> Job {
    // SAFETY: `run_on_tip_accept` blocks until the job returns.
    // `run_on_tip_accept_async` joins the oneshot on Drop of the future,
    // which still holds the caller's borrows (`&self` on ChainHub).
    unsafe { std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, Job>(job) }
}

fn run_on_tip_accept_blocking<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let job = erase_lifetime(Box::new(move || {
        let _ = tx.send(panic::catch_unwind(AssertUnwindSafe(f)));
    }));
    sender().blocking_send(job).expect("tip-accept thread");
    match rx.recv().expect("tip-accept job") {
        Ok(v) => v,
        Err(p) => panic::resume_unwind(p),
    }
}

/// Run `f` on `tip-accept`. Re-entrant (already on that thread → inline).
pub(crate) fn run_on_tip_accept<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    if on_tip_accept_thread() {
        return f();
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| run_on_tip_accept_blocking(f));
        }
    }
    run_on_tip_accept_blocking(f)
}

struct JoinOnDrop<R> {
    rx: Option<tokio::sync::oneshot::Receiver<thread::Result<R>>>,
}

impl<R> Drop for JoinOnDrop<R> {
    fn drop(&mut self) {
        if let Some(rx) = self.rx.take() {
            let _ = rx.blocking_recv();
        }
    }
}

/// Same as [`run_on_tip_accept`] but the caller `.await`s (peer session).
pub(crate) async fn run_on_tip_accept_async<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    if on_tip_accept_thread() {
        return f();
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut guard = JoinOnDrop { rx: Some(rx) };
    let job = erase_lifetime(Box::new(move || {
        let _ = tx.send(panic::catch_unwind(AssertUnwindSafe(f)));
    }));
    sender().send(job).await.expect("tip-accept thread");
    let r = poll_fn(|cx| {
        let rx = guard.rx.as_mut().expect("tip-accept poll after take");
        Pin::new(rx).poll(cx)
    })
    .await
    .expect("tip-accept job");
    guard.rx = None;
    match r {
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
    fn lane_reentrant_stays_on_named_thread() {
        let name = run_on_tip_accept(|| {
            run_on_tip_accept(|| thread::current().name().map(str::to_string))
        });
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lane_async_is_not_tokio_worker() {
        let task = tokio::spawn(async {
            let caller = is_tokio_runtime_worker();
            let (name, ran_on_tokio) = run_on_tip_accept_async(|| {
                (
                    thread::current().name().map(str::to_string),
                    is_tokio_runtime_worker(),
                )
            })
            .await;
            (caller, name, ran_on_tokio)
        });
        let (caller, name, ran_on_tokio) = task.await.expect("join worker task");
        assert!(
            caller,
            "spawned task must run on a tokio worker so the pin is meaningful"
        );
        assert_eq!(name.as_deref(), Some(TIP_ACCEPT_THREAD_NAME));
        assert!(!ran_on_tokio, "job ran on {name:?}");
    }
}
