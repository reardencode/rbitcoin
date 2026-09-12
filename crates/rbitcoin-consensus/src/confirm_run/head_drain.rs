//! Process-wide `ibd-confirm-head` thread: write-behind `tx.head` insert.
//!
//! Confirm write overlaps this insert with structural + Class C. One inserter;
//! the thread stays up so each batch does not `thread::scope` spawn/teardown.

use rbitcoin_store::StoreError;
use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
#[cfg(test)]
use std::thread::ThreadId;

pub(crate) const HEAD_DRAIN_THREAD_NAME: &str = "ibd-confirm-head";

type Job = Box<dyn FnOnce() + Send>;

struct DrainWorkers {
    jobs: Mutex<VecDeque<Job>>,
    cv: Condvar,
}

fn pool() -> &'static DrainWorkers {
    static POOL: OnceLock<DrainWorkers> = OnceLock::new();
    static SPAWN: OnceLock<()> = OnceLock::new();
    let pool = POOL.get_or_init(|| DrainWorkers {
        jobs: Mutex::new(VecDeque::new()),
        cv: Condvar::new(),
    });
    SPAWN.get_or_init(|| {
        let jobs = &pool.jobs;
        let cv = &pool.cv;
        thread::Builder::new()
            .name(HEAD_DRAIN_THREAD_NAME.into())
            .spawn(move || loop {
                let f = recv_job(jobs, cv);
                f();
            })
            .expect("spawn ibd-confirm-head");
    });
    pool
}

fn recv_job(jobs: &Mutex<VecDeque<Job>>, cv: &Condvar) -> Job {
    let mut g = jobs.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        if let Some(job) = g.pop_front() {
            return job;
        }
        g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
    }
}

pub(crate) struct HeadDrainHandle {
    rx: Option<Receiver<Result<u64, StoreError>>>,
    restore: Option<Arc<Mutex<Option<Vec<([u8; 32], rbitcoin_primitives::Fk)>>>>>,
    #[cfg(test)]
    named: Arc<Mutex<Option<(ThreadId, String)>>>,
}

impl HeadDrainHandle {
    /// Join and, on insert failure, return the batch so the write thread can
    /// put it back on pending-head (no clone on the success path).
    pub(crate) fn join_restore(
        mut self,
    ) -> (
        Result<u64, StoreError>,
        Vec<([u8; 32], rbitcoin_primitives::Fk)>,
    ) {
        let r = self.recv_result();
        let queued = self
            .restore
            .take()
            .and_then(|a| a.lock().unwrap_or_else(|p| p.into_inner()).take())
            .unwrap_or_default();
        (r, queued)
    }

    fn recv_result(&mut self) -> Result<u64, StoreError> {
        let rx = self
            .rx
            .take()
            .ok_or(StoreError::Corrupt("tx.head drain handle joined twice"))?;
        rx.recv().unwrap_or(Err(StoreError::Corrupt(
            "tx.head write-behind drain thread gone",
        )))
    }

    #[cfg(test)]
    pub(crate) fn join_named(mut self) -> (Result<u64, StoreError>, ThreadId, String) {
        let r = self.recv_result();
        let (id, name) = self
            .named
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .unwrap_or_else(|| (thread::current().id(), String::new()));
        (r, id, name)
    }
}

impl Drop for HeadDrainHandle {
    fn drop(&mut self) {
        if self.rx.is_some() {
            let _ = self.recv_result();
        }
    }
}

/// Run `work` on [`HEAD_DRAIN_THREAD_NAME`]. Caller must join before captured
/// store pointers go out of scope.
pub(crate) fn submit_head_drain<F>(work: F) -> HeadDrainHandle
where
    F: FnOnce() -> Result<u64, StoreError> + Send + 'static,
{
    let pool = pool();
    let (tx, rx) = mpsc::sync_channel(1);
    #[cfg(test)]
    let named = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let named_job = Arc::clone(&named);
    {
        let mut q = pool.jobs.lock().unwrap_or_else(|p| p.into_inner());
        q.push_back(Box::new(move || {
            #[cfg(test)]
            {
                *named_job.lock().unwrap_or_else(|p| p.into_inner()) = Some((
                    thread::current().id(),
                    thread::current().name().unwrap_or("").to_string(),
                ));
            }
            let r = panic::catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| {
                Err(StoreError::Corrupt(
                    "tx.head write-behind drain thread panicked",
                ))
            });
            let _ = tx.send(r);
        }));
    }
    pool.cv.notify_one();
    HeadDrainHandle {
        rx: Some(rx),
        restore: None,
        #[cfg(test)]
        named,
    }
}

struct SendStorePtr(usize);
impl SendStorePtr {
    fn from_store(store: &rbitcoin_store::Store) -> Self {
        Self(store as *const rbitcoin_store::Store as usize)
    }
    fn insert(self, batch: &[([u8; 32], rbitcoin_primitives::Fk)]) -> Result<u64, StoreError> {
        // SAFETY: confirm write still borrows `Store` until the drain handle joins.
        unsafe {
            (*(self.0 as *const rbitcoin_store::Store))
                .txs
                .head_insert_queued(batch)
        }
    }
}

/// Insert a taken pending-head batch on [`HEAD_DRAIN_THREAD_NAME`].
pub(crate) fn submit_head_insert(
    store: &rbitcoin_store::Store,
    batch: Vec<([u8; 32], rbitcoin_primitives::Fk)>,
) -> HeadDrainHandle {
    let ptr = SendStorePtr::from_store(store);
    let restore = Arc::new(Mutex::new(None));
    let restore_job = Arc::clone(&restore);
    let mut handle = submit_head_drain(move || match ptr.insert(&batch) {
        Ok(n) => Ok(n),
        Err(e) => {
            *restore_job.lock().unwrap_or_else(|p| p.into_inner()) = Some(batch);
            Err(e)
        }
    });
    handle.restore = Some(restore);
    handle
}
