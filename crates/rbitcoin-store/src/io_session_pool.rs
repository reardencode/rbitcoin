//! Completion-ring facade over a bounded worker pool.
//!
//! Same harvest contract as io_uring (`user_data`, drain, in-flight cap).
//! Darwin's file AIO is a thread pool; this is the honest session there and
//! the Linux CI pin (`RBITCOIN_IO=pool`).
//!
//! Workers are **process-shared**. Each [`PoolEngine`] is a session handle
//! with its own CQE queue so harvest does not steal another thread's
//! completions.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

static SPAWNED_WORKERS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_POOL: OnceLock<Arc<SharedPool>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn spawned_workers() -> usize {
    SPAWNED_WORKERS.load(Ordering::Relaxed)
}

struct Job {
    handle: IoHandle,
    offset: u64,
    ptr: *mut u8,
    len: usize,
    user_data: u64,
    write: bool,
    cq: Arc<SessionCq>,
}

// SAFETY: the machine thread keeps `ptr` live until the matching CQE is harvested.
unsafe impl Send for Job {}

struct SessionCq {
    cqes: Mutex<VecDeque<(u64, i32)>>,
    cqe_cv: Condvar,
    inflight: AtomicUsize,
}

struct SharedPool {
    jobs: Mutex<VecDeque<Job>>,
    job_cv: Condvar,
    shutdown: AtomicBool,
}

fn global_pool(n_workers: usize) -> Arc<SharedPool> {
    GLOBAL_POOL
        .get_or_init(|| {
            let n = n_workers.clamp(1, 16);
            let pool = Arc::new(SharedPool {
                jobs: Mutex::new(VecDeque::new()),
                job_cv: Condvar::new(),
                shutdown: AtomicBool::new(false),
            });
            for _ in 0..n {
                let sh = Arc::clone(&pool);
                thread::Builder::new()
                    .name("rbtc-io-pool".into())
                    .spawn(move || worker_loop(sh))
                    .expect("spawn io pool worker");
                SPAWNED_WORKERS.fetch_add(1, Ordering::Relaxed);
            }
            pool
        })
        .clone()
}

pub(crate) struct PoolEngine {
    pool: Arc<SharedPool>,
    cq: Arc<SessionCq>,
}

impl PoolEngine {
    pub(crate) fn open(n_workers: usize) -> Self {
        Self {
            pool: global_pool(n_workers),
            cq: Arc::new(SessionCq {
                cqes: Mutex::new(VecDeque::new()),
                cqe_cv: Condvar::new(),
                inflight: AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn inflight(&self) -> usize {
        self.cq.inflight.load(Ordering::Acquire)
    }

    pub(crate) fn push_pread(
        &self,
        handle: IoHandle,
        offset: u64,
        buf: &mut [u8],
        user_data: u64,
    ) -> Result<(), StoreError> {
        self.push(
            handle,
            offset,
            buf.as_mut_ptr(),
            buf.len(),
            user_data,
            false,
        )
    }

    pub(crate) fn push_pwrite(
        &self,
        handle: IoHandle,
        offset: u64,
        buf: &[u8],
        user_data: u64,
    ) -> Result<(), StoreError> {
        self.push(
            handle,
            offset,
            buf.as_ptr() as *mut u8,
            buf.len(),
            user_data,
            true,
        )
    }

    fn push(
        &self,
        handle: IoHandle,
        offset: u64,
        ptr: *mut u8,
        len: usize,
        user_data: u64,
        write: bool,
    ) -> Result<(), StoreError> {
        if len == 0 {
            return Ok(());
        }
        self.cq.inflight.fetch_add(1, Ordering::AcqRel);
        {
            let mut q = self.pool.jobs.lock().unwrap_or_else(|e| e.into_inner());
            q.push_back(Job {
                handle,
                offset,
                ptr,
                len,
                user_data,
                write,
                cq: Arc::clone(&self.cq),
            });
        }
        self.pool.job_cv.notify_one();
        Ok(())
    }

    pub(crate) fn harvest_ready(&self) -> Vec<(u64, i32)> {
        let mut q = self.cq.cqes.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    /// Wait until a CQE is ready or `timeout`. Returns false on timeout with
    /// nothing in the CQ (lost SQE / phantom pending).
    pub(crate) fn wait_one_cqe_timeout(&self, timeout: std::time::Duration) -> bool {
        let mut q = self.cq.cqes.lock().unwrap_or_else(|e| e.into_inner());
        if !q.is_empty() {
            return true;
        }
        if self.cq.inflight.load(Ordering::Acquire) == 0 {
            return false;
        }
        let deadline = std::time::Instant::now() + timeout;
        while q.is_empty() && self.cq.inflight.load(Ordering::Acquire) != 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (qq, wr) = self
                .cq
                .cqe_cv
                .wait_timeout(q, deadline.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner());
            q = qq;
            if wr.timed_out() && q.is_empty() {
                return false;
            }
        }
        !q.is_empty()
    }
}

fn worker_loop(shared: Arc<SharedPool>) {
    loop {
        if shared.shutdown.load(Ordering::Acquire) {
            return;
        }
        let job = {
            let mut q = shared.jobs.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if shared.shutdown.load(Ordering::Acquire) {
                    return;
                }
                if let Some(j) = q.pop_front() {
                    break j;
                }
                q = shared.job_cv.wait(q).unwrap_or_else(|e| e.into_inner());
            }
        };
        let buf = unsafe { std::slice::from_raw_parts_mut(job.ptr, job.len) };
        let res = if job.write {
            job.handle.pwrite(job.offset, buf)
        } else {
            job.handle.pread(job.offset, buf)
        };
        {
            let mut cq = job.cq.cqes.lock().unwrap_or_else(|e| e.into_inner());
            cq.push_back((job.user_data, res));
            job.cq.inflight.fetch_sub(1, Ordering::AcqRel);
        }
        job.cq.cqe_cv.notify_all();
    }
}
