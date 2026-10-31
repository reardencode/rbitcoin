//! Tokio **reactor** threads must not wait on std locks, store IO, or scripts.
//!
//! Tokio names both multi-thread workers and `spawn_blocking` threads
//! `tokio-rt-worker`. Blocking-pool work must enter [`BlockingRegion`].

use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::thread;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

tokio::task_local! {
    static API_STORE_BUDGET: Arc<Semaphore>;
}

thread_local! {
    static BLOCKING_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Guard: this OS thread may take std locks / store IO (blocking pool or tests).
pub struct BlockingRegion(());

impl BlockingRegion {
    pub fn enter() -> Self {
        BLOCKING_DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self(())
    }
}

impl Drop for BlockingRegion {
    fn drop(&mut self) {
        BLOCKING_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

pub fn on_tokio_worker() -> bool {
    thread::current()
        .name()
        .is_some_and(|n| n.starts_with("tokio-rt-worker"))
}

pub fn in_blocking_region() -> bool {
    BLOCKING_DEPTH.with(|d| d.get() > 0)
}

/// Run `f` on a fresh OS thread and await it. Not the Tokio blocking pool.
///
/// A parked pool must still finish a connect or a mempool admit. The thread
/// is held only for `f`. Script verify is awaited on the caller via
/// `run_cpu`, not inside `f`.
pub async fn off_pool<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = tokio::sync::oneshot::channel();
    thread::Builder::new()
        .name("rbtc-off-pool".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .expect("rbtc-off-pool");
    rx.await.expect("rbtc-off-pool dropped")
}

/// Run `fut` with the API store-read budget armed. Prepare takes one permit
/// and drops it before script verify. The commit coin re-read takes one
/// again. A task that never calls this does not take the budget (P2P decode,
/// and admits that are not an API read).
pub async fn with_store_budget<R>(budget: Arc<Semaphore>, fut: impl Future<Output = R>) -> R {
    API_STORE_BUDGET.scope(budget, fut).await
}

/// `tokio::spawn` does not keep the task-local budget. Copy it into the
/// child so a detached admit still waits for a store permit.
pub fn spawn_with_store_budget<T: Send + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let budget = API_STORE_BUDGET.try_with(Arc::clone).ok();
    tokio::spawn(async move {
        if let Some(budget) = budget {
            with_store_budget(budget, fut).await
        } else {
            fut.await
        }
    })
}

/// One permit of the armed budget, or `None` when this task has no budget.
/// The wait is async. The caller moves the permit into the read so a dropped
/// request does not release it while the read still runs.
pub async fn acquire_armed_store_budget() -> Option<OwnedSemaphorePermit> {
    let Ok(sem) = API_STORE_BUDGET.try_with(Arc::clone) else {
        return None;
    };
    Some(sem.acquire_owned().await.expect("store budget"))
}

/// [`off_pool`] that holds one armed store-read permit for `f` only.
pub async fn off_pool_budgeted<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let permit = acquire_armed_store_budget().await;
    off_pool(move || {
        let _permit = permit;
        f()
    })
    .await
}

pub fn assert_not_reactor(what: &'static str) {
    assert!(
        !on_tokio_worker() || in_blocking_region(),
        "{what} on tokio-rt-worker"
    );
}

pub use rbitcoin_primitives::assert_not_script_worker;
