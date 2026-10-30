//! Tokio **reactor** threads must not wait on std locks, store IO, or scripts.
//!
//! Tokio names both multi-thread workers and `spawn_blocking` threads
//! `tokio-rt-worker`. Blocking-pool work must enter [`BlockingRegion`].

use std::cell::Cell;
use std::thread;

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

pub fn assert_not_reactor(what: &'static str) {
    assert!(
        !on_tokio_worker() || in_blocking_region(),
        "{what} on tokio-rt-worker"
    );
}

pub use rbitcoin_primitives::assert_not_script_worker;
