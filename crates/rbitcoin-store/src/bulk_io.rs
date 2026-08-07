//! Bulk table IO via **io_uring** (Linux): pipelined preads and pwrites so the
//! kernel can keep many independent ops in flight.
//!
//! All io_uring work is driven by [`crate::uring_session::UringSession`] (same
//! type as archive streaming head-resolve). Hot-path
//! `pread_batch` / `pwrite_batch` / page-RMW reuse a **thread-local** ring so
//! confirm-load and archive-prep waves do not `io_uring_setup`/`exit` per batch.
//! Nested bulk_io on the same thread (re-entrant) opens a temporary ring.
//! Falls back to libc `pread`/`pwrite` when uring is off.
//!
//! Used by archive head-resolve body prefixes, confirm load body batches, and
//! Class C bulk slots. Completions are unordered within a submit batch.
//!
//! # Controls
//!
//! - `RBITCOIN_IO_URING=0` — force libc `pread`/`pwrite` fallback.
//! - `RBITCOIN_BULK_IO_WORKERS` — parallel pread workers when uring is off
//!   (default `min(CPUs, 16)`; `1` = serial). Writes fall back to serial pwrite.
//!
//! Ring entries: [`crate::uring_session::DEFAULT_ENTRIES`] (128). Large waves
//! keep the ring full: submit up to depth outstanding ops, then refill as CQEs
//! complete (pipelined, not stop-and-wait chunks).
//!
//! # Non-Linux
//!
//! Windows/macOS use the same `pread_batch` / `pwrite_batch` API surface with
//! libc (or equivalent) positional IO and optional worker threads. A native
//! IOCP/kqueue backend is intentionally **not** wired: it would not unify
//! execution with Linux's completion-driven ring and would add a second code
//! path without a measured Linux-safe win. See `docs/concurrency.md`.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// SQ/CQ depth for bulk batch sessions.
#[cfg(target_os = "linux")]
const RING_ENTRIES: u32 = crate::uring_session::DEFAULT_ENTRIES;

/// One independent pread. Caller owns `buf` for the full submit/wait.
pub struct ReadOp<'a> {
    pub fd: RawFd,
    pub offset: u64,
    pub buf: &'a mut [u8],
    /// Filled: bytes read (≥0) or negated errno on failure.
    pub result: i32,
    /// When true, SQE uses [`crate::uring_session::RWF_DONTCACHE`].
    // Only read on the Linux io_uring submit path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub dontcache: bool,
}

/// One independent pwrite. Caller owns `buf` for the full submit/wait.
pub struct WriteOp<'a> {
    pub fd: RawFd,
    pub offset: u64,
    pub buf: &'a [u8],
    /// Filled: bytes written (≥0) or negated errno on failure.
    pub result: i32,
    /// When true, SQE uses [`crate::uring_session::RWF_DONTCACHE`].
    // Only read on the Linux io_uring submit path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub dontcache: bool,
}

/// One page RMW slot for [`page_rmw_pipelined`]: pread into `buf`, apply, pwrite.
#[allow(dead_code)]
pub struct PageRmw<'a> {
    pub fd: RawFd,
    pub offset: u64,
    pub buf: &'a mut [u8],
}

static URING_MODE: AtomicU8 = AtomicU8::new(0); // 0 unknown, 1 on, 2 off
static WORKERS: AtomicUsize = AtomicUsize::new(0);
static URING_FAIL_LOGGED: AtomicBool = AtomicBool::new(false);
/// 0 unknown, 1 ok, 2 unsupported (ENOTSUP) — probed once on first use.
static RWF_DONTCACHE_MODE: AtomicU8 = AtomicU8::new(0);

/// Whether RWF_DONTCACHE is **capable** of being set on SQEs.
///
/// Default true until a CQE returns ENOTSUP / EOPNOTSUPP (then permanently demoted
/// for this process). Policy of *which* ops set the flag is permanent
/// spend-annotate body pwrites only — see [`crate::dontcache_policy`].
pub fn rwf_dontcache_ok() -> bool {
    match RWF_DONTCACHE_MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            RWF_DONTCACHE_MODE.store(1, Ordering::Relaxed);
            true
        }
    }
}

/// Mark RWF_DONTCACHE as unsupported after ENOTSUP / EOPNOTSUPP.
pub fn note_rwf_dontcache_unsupported() {
    RWF_DONTCACHE_MODE.store(2, Ordering::Relaxed);
}

/// Whether io_uring bulk reads are enabled (env + successful ring setup).
pub fn io_uring_enabled() -> bool {
    match URING_MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let want = std::env::var("RBITCOIN_IO_URING")
                .map(|s| s != "0" && s != "false" && s != "off")
                .unwrap_or(true);
            if !want {
                URING_MODE.store(2, Ordering::Relaxed);
                return false;
            }
            let ok = probe_uring();
            URING_MODE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            if !ok && !URING_FAIL_LOGGED.swap(true, Ordering::Relaxed) {
                rbitcoin_log::warn!(
                    "store: io_uring unavailable — bulk reads use pread fallback \
                     (set RBITCOIN_IO_URING=0 to silence)"
                );
            }
            ok
        }
    }
}

fn probe_uring() -> bool {
    crate::uring_session::UringSession::try_open(32).is_ok()
}

/// Worker count for pread fallback (cached).
pub fn bulk_io_workers() -> usize {
    let cached = WORKERS.load(Ordering::Relaxed);
    if cached > 0 {
        return cached;
    }
    let n = std::env::var("RBITCOIN_BULK_IO_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
                .clamp(1, 16)
        })
        .max(1);
    WORKERS.store(n, Ordering::Relaxed);
    n
}

/// Submit all ops; fill [`ReadOp::result`]. Prefers io_uring; else parallel pread.
pub fn pread_batch(ops: &mut [ReadOp<'_>]) {
    if ops.is_empty() {
        return;
    }
    #[cfg(test)]
    test_note_read_dontcache(ops);
    if io_uring_enabled() && pread_batch_uring(ops) {
        return;
    }
    pread_batch_fallback(ops);
}

/// One pread with optional schema-13 [`ReadOp::dontcache`] (uring when available).
///
/// Returns bytes read (≥0) or negated errno. Used by serial Class A paths that
/// must still honor RWF_DONTCACHE policy (`tx.idx` pages, sidefile get, body get).
#[inline]
pub fn pread_single(fd: RawFd, offset: u64, buf: &mut [u8], dontcache: bool) -> i32 {
    if buf.is_empty() {
        return 0;
    }
    let mut ops = [ReadOp {
        fd,
        offset,
        buf,
        result: i32::MIN,
        dontcache,
    }];
    pread_batch(&mut ops);
    ops[0].result
}

/// Bulk pread with an explicit backend (`mmap` is not handled here — callers
/// use map pins). `Uring` demotes to libc pread when the ring is unavailable.
pub fn pread_batch_backend(ops: &mut [ReadOp<'_>], backend: crate::io_backend::ReadIoBackend) {
    use crate::io_backend::ReadIoBackend;
    if ops.is_empty() {
        return;
    }
    #[cfg(test)]
    test_note_read_dontcache(ops);
    match backend {
        ReadIoBackend::Uring => {
            if io_uring_enabled() && pread_batch_uring(ops) {
                return;
            }
            pread_batch_fallback(ops);
        }
        ReadIoBackend::Pread => pread_batch_fallback(ops),
    }
}

/// Submit all ops; fill [`WriteOp::result`]. Prefers io_uring; else serial pwrite.
///
/// Public counterpart of [`pread_batch`]. Page RMW uses the mixed pipeline
/// ([`page_rmw_pipelined`]); this remains for bulk write-only call sites/tests.
#[allow(dead_code)]
pub fn pwrite_batch(ops: &mut [WriteOp<'_>]) {
    if ops.is_empty() {
        return;
    }
    #[cfg(test)]
    test_note_write_dontcache(ops);
    if io_uring_enabled() && pwrite_batch_uring(ops) {
        return;
    }
    pwrite_batch_fallback(ops);
}

// Test hook: last ReadOp/WriteOp.dontcache flags seen by pread/pwrite_batch.
#[cfg(test)]
thread_local! {
    static LAST_READ_DONTCACHE: std::cell::RefCell<Vec<bool>> =
        std::cell::RefCell::new(Vec::new());
    static LAST_WRITE_DONTCACHE: std::cell::RefCell<Vec<bool>> =
        std::cell::RefCell::new(Vec::new());
}

#[cfg(test)]
fn test_note_read_dontcache(ops: &[ReadOp<'_>]) {
    LAST_READ_DONTCACHE.with(|c| {
        c.borrow_mut().extend(ops.iter().map(|o| o.dontcache));
    });
}

#[cfg(test)]
fn test_note_write_dontcache(ops: &[WriteOp<'_>]) {
    LAST_WRITE_DONTCACHE.with(|c| {
        c.borrow_mut().extend(ops.iter().map(|o| o.dontcache));
    });
}

/// Drain and return recorded read-op DONTCACHE flags (tests only).
#[cfg(test)]
pub fn test_take_last_read_dontcache() -> Vec<bool> {
    LAST_READ_DONTCACHE.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Drain and return recorded write-op DONTCACHE flags (tests only).
#[cfg(test)]
pub fn test_take_last_write_dontcache() -> Vec<bool> {
    LAST_WRITE_DONTCACHE.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Pipelined page RMW on the thread-local ring:
///
/// 1. Submit page preads (fill ring up to DEFAULT_ENTRIES).
/// 2. On each read CQE: run `apply(page_index, buf)` — mutate in place; return
///    `true` if the page is dirty and needs write-back.
/// 3. Immediately submit dirty pages for pwrite; keep free slots filled with
///    more reads when work remains.
///
/// Returns `false` if io_uring is unavailable or the ring path fails (caller
/// should fall back). `apply` is only invoked after a successful full-page read.
/// When `apply` returns `false` (clean / abort), that page is not written.
///
/// On non-Linux or `RBITCOIN_IO_URING=0`, returns `false` immediately.
///
/// Kept as a reusable primitive (tests); `tx.head` insert is per-txid mmap path.
#[allow(dead_code)]
pub fn page_rmw_pipelined(
    pages: &mut [PageRmw<'_>],
    apply: impl FnMut(usize, &mut [u8]) -> bool,
) -> bool {
    if pages.is_empty() {
        return true;
    }
    if !io_uring_enabled() {
        return false;
    }
    page_rmw_pipelined_uring(pages, apply)
}

/// Thread-local bulk ring via [`crate::uring_session::with_thread_local`].
///
/// **Must not** be called while another `with_thread_local` is active on this
/// OS thread (nested TLS uring panics). Plan head-resolve streams probe/id/idx
/// SQEs on its own held session instead.
#[cfg(target_os = "linux")]
fn with_bulk_session<R>(f: impl FnOnce(&mut crate::uring_session::UringSession) -> R) -> Option<R> {
    match crate::uring_session::with_thread_local(RING_ENTRIES, f) {
        Ok(r) => Some(r),
        Err(_) => {
            // Permanent disable only on setup failure (same as prior TL open path).
            URING_MODE.store(2, Ordering::Relaxed);
            None
        }
    }
}

/// Pipelined bulk pread via thread-local [`crate::uring_session::UringSession`].
/// `user_data = op index`. Returns false → caller uses pread fallback.
#[cfg(target_os = "linux")]
fn pread_batch_uring(ops: &mut [ReadOp<'_>]) -> bool {
    for op in ops.iter_mut() {
        op.result = if op.buf.is_empty() { 0 } else { i32::MIN };
    }
    let total_nonempty = ops.iter().filter(|o| !o.buf.is_empty()).count();
    if total_nonempty == 0 {
        return true;
    }

    // Mid-wave false (push/submit/wait fail) → fall back for *this* batch only.
    // Permanently disable uring only when the ring cannot be opened (None);
    // with_bulk_session already stores mode 2 on try_open Err for the TL path.
    match with_bulk_session(|session| {
        #[cfg(test)]
        if test_force_session_false() {
            session.drain_all();
            return false;
        }
        pread_batch_on_session(session, ops, total_nonempty)
    }) {
        Some(true) => true,
        Some(false) => false,
        None => false,
    }
}

// Test-only fault inject: force mid-wave `Some(false)` from `pread_batch_uring`
// so we prove that path does not permanently disable process-wide io_uring.
// Kept: no production API can inject a partial-session failure without this.
#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_FORCE_SESSION_FALSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, target_os = "linux"))]
fn test_force_session_false() -> bool {
    TEST_FORCE_SESSION_FALSE.with(|c| c.get())
}

#[cfg(target_os = "linux")]
fn pread_batch_on_session(
    session: &mut crate::uring_session::UringSession,
    ops: &mut [ReadOp<'_>],
    total_nonempty: usize,
) -> bool {
    let n = ops.len();
    let mut next = 0usize;
    let mut completed = 0usize;

    while completed < total_nonempty {
        while next < n && session.free_sq() > 0 {
            if ops[next].buf.is_empty() {
                next += 1;
                continue;
            }
            let fd = ops[next].fd;
            let offset = ops[next].offset;
            let ud = next as u64;
            // Prefer DONTCACHE when requested; may be unsupported on some FS/kernels.
            let flags = if ops[next].dontcache && rwf_dontcache_ok() {
                crate::uring_session::RWF_DONTCACHE
            } else {
                0
            };
            // SAFETY: caller owns each `buf` until `pread_batch` returns.
            if session
                .push_pread_flags(fd, offset, ops[next].buf, ud, flags)
                .is_err()
            {
                if session.in_flight() == 0 {
                    session.drain_all();
                    return false;
                }
                break;
            }
            next += 1;
        }
        session.sync_submission();

        if session.in_flight() == 0 {
            break;
        }

        let mut cqes = session.harvest_ready();
        if cqes.is_empty() {
            if session.submit_and_wait_one().is_err() {
                session.drain_all();
                return false;
            }
            cqes = session.harvest_ready();
            if cqes.is_empty() {
                session.drain_all();
                return false;
            }
        } else if session.submit().is_err() {
            session.drain_all();
            return false;
        }

        for (ud, res) in cqes {
            let i = ud as usize;
            if i < ops.len() {
                ops[i].result = res;
                // ENOTSUP / EOPNOTSUPP (95) often means RWF_DONTCACHE unsupported.
                if res == -95 || res == -95i32 {
                    note_rwf_dontcache_unsupported();
                }
            }
            completed += 1;
        }
    }

    let mut any_fail = false;
    for op in ops.iter_mut() {
        if !op.buf.is_empty() && op.result == i32::MIN {
            op.result = -5; // EIO
            any_fail = true;
        }
        if op.result < 0 {
            any_fail = true;
        }
    }
    session.drain_all();
    // Signal caller to fall back to pread if any SQE failed (e.g. DONTCACHE).
    !any_fail
}

/// Pipelined bulk pwrite — same fill/harvest shape as [`pread_batch_uring`].
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn pwrite_batch_uring(ops: &mut [WriteOp<'_>]) -> bool {
    for op in ops.iter_mut() {
        op.result = if op.buf.is_empty() { 0 } else { i32::MIN };
    }
    let total_nonempty = ops.iter().filter(|o| !o.buf.is_empty()).count();
    if total_nonempty == 0 {
        return true;
    }

    // Same policy as pread_batch_uring: mid-wave fail does not disable uring.
    match with_bulk_session(|session| pwrite_batch_on_session(session, ops, total_nonempty)) {
        Some(true) => true,
        Some(false) => false,
        None => false,
    }
}

#[cfg(target_os = "linux")]
fn pwrite_batch_on_session(
    session: &mut crate::uring_session::UringSession,
    ops: &mut [WriteOp<'_>],
    total_nonempty: usize,
) -> bool {
    let n = ops.len();
    let mut next = 0usize;
    let mut completed = 0usize;

    while completed < total_nonempty {
        while next < n && session.free_sq() > 0 {
            if ops[next].buf.is_empty() {
                next += 1;
                continue;
            }
            let fd = ops[next].fd;
            let offset = ops[next].offset;
            let ud = next as u64;
            let flags = if ops[next].dontcache && rwf_dontcache_ok() {
                crate::uring_session::RWF_DONTCACHE
            } else {
                0
            };
            if session
                .push_pwrite_flags(fd, offset, ops[next].buf, ud, flags)
                .is_err()
            {
                if session.in_flight() == 0 {
                    session.drain_all();
                    return false;
                }
                break;
            }
            next += 1;
        }
        session.sync_submission();

        if session.in_flight() == 0 {
            break;
        }

        let mut cqes = session.harvest_ready();
        if cqes.is_empty() {
            if session.submit_and_wait_one().is_err() {
                session.drain_all();
                return false;
            }
            cqes = session.harvest_ready();
            if cqes.is_empty() {
                session.drain_all();
                return false;
            }
        } else if session.submit().is_err() {
            session.drain_all();
            return false;
        }

        for (ud, res) in cqes {
            let i = ud as usize;
            if i < ops.len() {
                ops[i].result = res;
                // ENOTSUP / EOPNOTSUPP (95): RWF_DONTCACHE unsupported (writes).
                if res == -95 || res == -95i32 {
                    note_rwf_dontcache_unsupported();
                }
            }
            completed += 1;
        }
    }

    for op in ops.iter_mut() {
        if !op.buf.is_empty() && op.result == i32::MIN {
            op.result = -5;
        }
    }
    session.drain_all();
    true
}

/// user_data: low 63 bits = page index; bit 63 set ⇒ write completion.
#[cfg(target_os = "linux")]
const RMW_WRITE_BIT: u64 = 1u64 << 63;

#[cfg(target_os = "linux")]
fn page_rmw_pipelined_uring(
    pages: &mut [PageRmw<'_>],
    mut apply: impl FnMut(usize, &mut [u8]) -> bool,
) -> bool {
    with_bulk_session(|session| page_rmw_on_session(session, pages, &mut apply)).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn page_rmw_on_session(
    session: &mut crate::uring_session::UringSession,
    pages: &mut [PageRmw<'_>],
    apply: &mut dyn FnMut(usize, &mut [u8]) -> bool,
) -> bool {
    let n = pages.len();
    // 0 = need read, 1 = read in flight, 2 = need write, 3 = write in flight, 4 = done
    let mut state = vec![0u8; n];
    let mut need_read = n;
    let mut need_write = 0usize;
    let mut done = 0usize;
    let mut next_read = 0usize;

    while done < n {
        let mut submitted = false;

        if need_write > 0 && session.free_sq() > 0 {
            for i in 0..n {
                if session.free_sq() == 0 {
                    break;
                }
                if state[i] != 2 {
                    continue;
                }
                if pages[i].buf.is_empty() {
                    state[i] = 4;
                    need_write -= 1;
                    done += 1;
                    continue;
                }
                let fd = pages[i].fd;
                let offset = pages[i].offset;
                if session
                    .push_pwrite(fd, offset, pages[i].buf, (i as u64) | RMW_WRITE_BIT)
                    .is_err()
                {
                    break;
                }
                state[i] = 3;
                need_write -= 1;
                submitted = true;
            }
        }

        while need_read > 0 && session.free_sq() > 0 && next_read < n {
            while next_read < n && state[next_read] != 0 {
                next_read += 1;
            }
            if next_read >= n {
                break;
            }
            let i = next_read;
            if pages[i].buf.is_empty() {
                state[i] = 4;
                need_read -= 1;
                done += 1;
                next_read += 1;
                continue;
            }
            let fd = pages[i].fd;
            let offset = pages[i].offset;
            if session
                .push_pread(fd, offset, pages[i].buf, i as u64)
                .is_err()
            {
                break;
            }
            state[i] = 1;
            need_read -= 1;
            next_read += 1;
            submitted = true;
        }

        if submitted {
            session.sync_submission();
        }

        if session.in_flight() == 0 {
            break;
        }

        let mut events = session.harvest_ready();
        if events.is_empty() {
            if session.submit_and_wait_one().is_err() {
                session.drain_all();
                return false;
            }
            events = session.harvest_ready();
            if events.is_empty() {
                continue;
            }
        } else if session.submit().is_err() {
            session.drain_all();
            return false;
        }

        for (ud, res) in events {
            let i = (ud & !RMW_WRITE_BIT) as usize;
            if i >= n {
                continue;
            }
            if ud & RMW_WRITE_BIT != 0 {
                if res < 0 || res as usize != pages[i].buf.len() {
                    session.drain_all();
                    return false;
                }
                state[i] = 4;
                done += 1;
            } else {
                if res < 0 || res as usize != pages[i].buf.len() {
                    session.drain_all();
                    return false;
                }
                let dirty = apply(i, pages[i].buf);
                if dirty {
                    state[i] = 2;
                    need_write += 1;
                } else {
                    state[i] = 4;
                    done += 1;
                }
            }
        }
    }

    session.drain_all();
    done == n && need_read == 0 && need_write == 0
}

#[cfg(not(target_os = "linux"))]
fn pread_batch_uring(_ops: &mut [ReadOp<'_>]) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn pwrite_batch_uring(_ops: &mut [WriteOp<'_>]) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn page_rmw_pipelined_uring(
    _pages: &mut [PageRmw<'_>],
    _apply: impl FnMut(usize, &mut [u8]) -> bool,
) -> bool {
    false
}

fn pread_batch_fallback(ops: &mut [ReadOp<'_>]) {
    for op in ops.iter_mut() {
        op.result = i32::MIN;
    }
    let n = ops.len();
    let workers = bulk_io_workers();
    if n == 1 || workers <= 1 || n < 8 {
        for op in ops.iter_mut() {
            pread_one(op);
        }
        return;
    }
    let threads = workers.min(n);
    let chunk = n.div_ceil(threads);
    std::thread::scope(|scope| {
        for piece in ops.chunks_mut(chunk) {
            scope.spawn(|| {
                for op in piece.iter_mut() {
                    pread_one(op);
                }
            });
        }
    });
}

fn pread_one(op: &mut ReadOp<'_>) {
    if op.buf.is_empty() {
        op.result = 0;
        return;
    }
    let mut got = 0usize;
    while got < op.buf.len() {
        let n = unsafe {
            libc::pread(
                op.fd,
                op.buf[got..].as_mut_ptr() as *mut libc::c_void,
                op.buf.len() - got,
                (op.offset + got as u64) as i64,
            )
        };
        if n < 0 {
            op.result = -std::io::Error::last_os_error().raw_os_error().unwrap_or(5) as i32;
            return;
        }
        if n == 0 {
            op.result = got as i32;
            return;
        }
        got += n as usize;
    }
    op.result = got as i32;
}

#[allow(dead_code)]
fn pwrite_batch_fallback(ops: &mut [WriteOp<'_>]) {
    for op in ops.iter_mut() {
        pwrite_one(op);
    }
}

fn pwrite_one(op: &mut WriteOp<'_>) {
    if op.buf.is_empty() {
        op.result = 0;
        return;
    }
    let mut got = 0usize;
    while got < op.buf.len() {
        let n = unsafe {
            libc::pwrite(
                op.fd,
                op.buf[got..].as_ptr() as *const libc::c_void,
                op.buf.len() - got,
                (op.offset + got as u64) as i64,
            )
        };
        if n < 0 {
            op.result = -std::io::Error::last_os_error().raw_os_error().unwrap_or(5) as i32;
            return;
        }
        if n == 0 {
            op.result = got as i32;
            return;
        }
        got += n as usize;
    }
    op.result = got as i32;
}

/// Sequential page RMW (pread → apply → pwrite). Used when io_uring is off.
#[allow(dead_code)]
pub fn page_rmw_serial(
    pages: &mut [PageRmw<'_>],
    mut apply: impl FnMut(usize, &mut [u8]) -> bool,
) -> bool {
    for (i, page) in pages.iter_mut().enumerate() {
        if page.buf.is_empty() {
            continue;
        }
        let fd = page.fd;
        let offset = page.offset;
        let len = page.buf.len();
        let read_ok = {
            let mut ro = ReadOp {
                fd,
                offset,
                buf: page.buf,
                result: i32::MIN,
                dontcache: false,
            };
            pread_one(&mut ro);
            ro.result >= 0 && ro.result as usize == len
        };
        if !read_ok {
            return false;
        }
        let dirty = apply(i, page.buf);
        if !dirty {
            continue;
        }
        let write_ok = {
            let mut wo = WriteOp {
                fd,
                offset,
                buf: page.buf,
                result: i32::MIN,
                dontcache: false,
            };
            pwrite_one(&mut wo);
            wo.result >= 0 && wo.result as usize == len
        };
        if !write_ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    /// Dense surface: empty ops, empty bufs, serial RMW, multi-worker fallback,
    /// workers/io_uring helpers (without racing env with parallel tests for mode).
    #[test]
    fn bulk_io_edges_empty_serial_rmw_workers() {
        let _ = io_uring_enabled(); // may probe once
        let w = bulk_io_workers();
        assert!(w >= 1);

        // Empty batches
        pread_batch(&mut []);
        pwrite_batch(&mut []);
        assert!(page_rmw_pipelined(&mut [], |_, _| true));
        assert!(page_rmw_serial(&mut [], |_, _| true));

        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-bulk-edge-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        let mut f = std::fs::File::create(&path).unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        // Read+write so serial page RMW pwrite succeeds.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let fd = f.as_raw_fd();

        // Empty bufs
        let mut empty = [];
        let mut ops = [ReadOp {
            fd,
            offset: 0,
            buf: &mut empty[..],
            result: i32::MIN,
            dontcache: false,
        }];
        pread_batch(&mut ops);
        assert_eq!(ops[0].result, 0);

        let mut wops = [WriteOp {
            fd,
            offset: 0,
            buf: &[],
            result: i32::MIN,
            dontcache: false,
        }];
        pwrite_batch(&mut wops);
        assert_eq!(wops[0].result, 0);

        // Force fallback multi-worker path: many preads (≥8)
        let mut bufs: Vec<[u8; 64]> = vec![[0u8; 64]; 16];
        let mut read_ops: Vec<ReadOp<'_>> = Vec::new();
        for (i, b) in bufs.iter_mut().enumerate() {
            read_ops.push(ReadOp {
                fd,
                offset: (i * 64) as u64,
                buf: b.as_mut_slice(),
                result: i32::MIN,
                dontcache: false,
            });
        }
        pread_batch_fallback(&mut read_ops);
        for op in &read_ops {
            assert_eq!(op.result, 64, "result={}", op.result);
        }
        assert_eq!(&bufs[0][..], &data[0..64]);

        // Serial page RMW with clean (apply false) + dirty pages
        let mut p0 = vec![0u8; 32];
        let mut p1 = vec![0u8; 32];
        let mut p_empty: Vec<u8> = vec![];
        let mut pages = [
            PageRmw {
                fd,
                offset: 0,
                buf: &mut p0,
            },
            PageRmw {
                fd,
                offset: 32,
                buf: &mut p1,
            },
            PageRmw {
                fd,
                offset: 64,
                buf: &mut p_empty,
            },
        ];
        assert!(page_rmw_serial(&mut pages, |i, buf| {
            if i == 0 {
                buf[0] ^= 0xff;
                true
            } else {
                false // clean — no write
            }
        }));
        // Verify dirty page written
        let mut check = [0u8; 1];
        let mut ro = ReadOp {
            fd,
            offset: 0,
            buf: &mut check,
            result: i32::MIN,
            dontcache: false,
        };
        pread_one(&mut ro);
        assert_eq!(check[0], data[0] ^ 0xff);

        // pread_one short read past EOF
        let mut past = [0u8; 16];
        let mut ro = ReadOp {
            fd,
            offset: 10_000,
            buf: &mut past,
            result: i32::MIN,
            dontcache: false,
        };
        pread_one(&mut ro);
        assert_eq!(ro.result, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pread_batch_roundtrip_tmpfile() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-uring-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        let mut f = std::fs::File::create(&path).unwrap();
        let data: Vec<u8> = (0u8..200).collect();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.as_raw_fd();

        let mut b0 = [0u8; 50];
        let mut b1 = [0u8; 50];
        let mut b2 = [0u8; 50];
        let mut ops = [
            ReadOp {
                fd,
                offset: 0,
                buf: &mut b0[..],
                result: i32::MIN,
                dontcache: false,
            },
            ReadOp {
                fd,
                offset: 50,
                buf: &mut b1[..],
                result: i32::MIN,
                dontcache: false,
            },
            ReadOp {
                fd,
                offset: 100,
                buf: &mut b2[..],
                result: i32::MIN,
                dontcache: false,
            },
        ];
        pread_batch(&mut ops);
        for op in &ops {
            assert!(op.result >= 50, "result={}", op.result);
        }
        drop(ops);
        assert_eq!(&b0[..], &data[0..50]);
        assert_eq!(&b1[..], &data[50..100]);
        assert_eq!(&b2[..], &data[100..150]);

        // Many small reads (stress completion mapping).
        let mut bufs: Vec<[u8; 1]> = (0..120).map(|_| [0u8; 1]).collect();
        let mut ops: Vec<ReadOp<'_>> = Vec::new();
        // Build via raw pointers after collecting mut refs carefully.
        let mut slices: Vec<&mut [u8]> = bufs.iter_mut().map(|b| &mut b[..]).collect();
        for (i, sl) in slices.iter_mut().enumerate() {
            ops.push(ReadOp {
                fd,
                offset: i as u64,
                buf: *sl,
                result: i32::MIN,
                dontcache: false,
            });
        }
        pread_batch(&mut ops);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(op.result, 1, "i={i}");
        }
        drop(ops);
        for (i, b) in bufs.iter().enumerate() {
            assert_eq!(b[0], data[i], "i={i}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pread_batch_fallback_matches() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-pread-fb-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hello-fallback-path!!").unwrap();
        f.flush().unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.as_raw_fd();
        let mut b = [0u8; 5];
        let mut ops = [ReadOp {
            fd,
            offset: 0,
            buf: &mut b[..],
            result: i32::MIN,
            dontcache: false,
        }];
        pread_batch_fallback(&mut ops);
        drop(ops);
        assert_eq!(&b, b"hello");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pwrite_batch_roundtrip_tmpfile() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-pwrite-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            f.set_len(300).unwrap();
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let fd = f.as_raw_fd();
        let d0 = [1u8; 50];
        let d1 = [2u8; 50];
        let d2 = [3u8; 50];
        let mut ops = [
            WriteOp {
                fd,
                offset: 0,
                buf: &d0[..],
                result: i32::MIN,
                dontcache: false,
            },
            WriteOp {
                fd,
                offset: 50,
                buf: &d1[..],
                result: i32::MIN,
                dontcache: false,
            },
            WriteOp {
                fd,
                offset: 100,
                buf: &d2[..],
                result: i32::MIN,
                dontcache: false,
            },
        ];
        pwrite_batch(&mut ops);
        for op in &ops {
            assert!(op.result >= 50, "result={}", op.result);
        }
        let mut got = vec![0u8; 150];
        let n = unsafe { libc::pread(fd, got.as_mut_ptr() as *mut libc::c_void, 150, 0) };
        assert_eq!(n, 150);
        assert_eq!(&got[0..50], &d0[..]);
        assert_eq!(&got[50..100], &d1[..]);
        assert_eq!(&got[100..150], &d2[..]);

        // Page RMW pipeline: read → flip byte → write-back.
        let mut pages_data: Vec<Vec<u8>> = (0..3).map(|_| vec![0u8; 50]).collect();
        let mut pages: Vec<PageRmw<'_>> = pages_data
            .iter_mut()
            .enumerate()
            .map(|(i, b)| PageRmw {
                fd,
                offset: (i * 50) as u64,
                buf: b.as_mut_slice(),
            })
            .collect();
        let rmw_ok = if io_uring_enabled() {
            page_rmw_pipelined(&mut pages, |_i, buf| {
                for b in buf.iter_mut() {
                    *b = b.wrapping_add(10);
                }
                true
            })
        } else {
            page_rmw_serial(&mut pages, |_i, buf| {
                for b in buf.iter_mut() {
                    *b = b.wrapping_add(10);
                }
                true
            })
        };
        assert!(rmw_ok);
        drop(pages);
        let mut got2 = vec![0u8; 150];
        let n2 = unsafe { libc::pread(fd, got2.as_mut_ptr() as *mut libc::c_void, 150, 0) };
        assert_eq!(n2, 150);
        assert_eq!(got2[0], 11);
        assert_eq!(got2[50], 12);
        assert_eq!(got2[100], 13);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mid-wave uring failure must fall back for that batch only — not flip
    /// `URING_MODE` off for the rest of the process (regression for TL-ring
    /// rewrite that wrongly stored mode 2 on `Some(false)`).
    #[cfg(target_os = "linux")]
    #[test]
    fn mid_wave_false_does_not_disable_uring() {
        if !io_uring_enabled() {
            return;
        }
        assert_eq!(
            URING_MODE.load(Ordering::Relaxed),
            1,
            "expected uring mode on after probe"
        );

        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-uring-mode-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"abcdefghij").unwrap();
            f.flush().unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.as_raw_fd();

        // Inject Some(false) through the real pread_batch_uring match.
        TEST_FORCE_SESSION_FALSE.with(|c| c.set(true));
        let mut b = [0u8; 4];
        let mut ops = [ReadOp {
            fd,
            offset: 0,
            buf: &mut b[..],
            result: i32::MIN,
            dontcache: false,
        }];
        pread_batch(&mut ops); // uring false → fallback still fills
        TEST_FORCE_SESSION_FALSE.with(|c| c.set(false));
        drop(ops);
        assert_eq!(
            &b, b"abcd",
            "fallback must still serve the forced-false wave"
        );
        assert_eq!(
            URING_MODE.load(Ordering::Relaxed),
            1,
            "mid-wave false must not permanently disable io_uring"
        );

        // Next wave must still use uring (mode still 1) and read correctly.
        let mut b2 = [0u8; 4];
        let mut ops2 = [ReadOp {
            fd,
            offset: 4,
            buf: &mut b2[..],
            result: i32::MIN,
            dontcache: false,
        }];
        assert!(
            pread_batch_uring(&mut ops2),
            "uring path must still succeed after mid-wave false"
        );
        drop(ops2);
        assert_eq!(&b2, b"efgh");
        assert_eq!(URING_MODE.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Multiple sequential waves on one thread reuse the TL ring and match
    /// libc pread for identical ranges (batch identity under reuse).
    #[test]
    fn pread_batch_thread_local_reuse_matches_fallback() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-uring-tl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        let data: Vec<u8> = (0u16..512).map(|i| (i % 251) as u8).collect();
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.as_raw_fd();

        // Three waves — first opens TL ring; later waves must reuse it correctly.
        for wave in 0..3u64 {
            let base = (wave * 64) as usize;
            let mut b0 = [0u8; 32];
            let mut b1 = [0u8; 32];
            let mut ops = [
                ReadOp {
                    fd,
                    offset: base as u64,
                    buf: &mut b0[..],
                    result: i32::MIN,
                    dontcache: false,
                },
                ReadOp {
                    fd,
                    offset: (base + 32) as u64,
                    buf: &mut b1[..],
                    result: i32::MIN,
                    dontcache: false,
                },
            ];
            pread_batch(&mut ops);
            assert_eq!(ops[0].result, 32, "wave={wave}");
            assert_eq!(ops[1].result, 32, "wave={wave}");
            drop(ops);
            assert_eq!(&b0[..], &data[base..base + 32], "wave={wave}");
            assert_eq!(&b1[..], &data[base + 32..base + 64], "wave={wave}");

            // Fallback path must agree (same bytes, independent of ring).
            let mut c0 = [0u8; 32];
            let mut c1 = [0u8; 32];
            let mut fops = [
                ReadOp {
                    fd,
                    offset: base as u64,
                    buf: &mut c0[..],
                    result: i32::MIN,
                    dontcache: false,
                },
                ReadOp {
                    fd,
                    offset: (base + 32) as u64,
                    buf: &mut c1[..],
                    result: i32::MIN,
                    dontcache: false,
                },
            ];
            pread_batch_fallback(&mut fops);
            assert_eq!(&c0[..], &b0[..]);
            assert_eq!(&c1[..], &b1[..]);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Forces multi-fill of the ring (N > RING_ENTRIES) and checks every byte —
    /// exercises pipelined refill, not just a single wave.
    #[test]
    fn pread_batch_pipeline_over_ring_depth() {
        const N: usize = 200;
        assert!(N > RING_ENTRIES as usize);

        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-uring-pipe-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        let data: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
            f.flush().unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.as_raw_fd();

        let mut bufs: Vec<[u8; 1]> = (0..N).map(|_| [0u8; 1]).collect();
        let mut slices: Vec<&mut [u8]> = bufs.iter_mut().map(|b| &mut b[..]).collect();
        let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(N);
        for (i, sl) in slices.iter_mut().enumerate() {
            ops.push(ReadOp {
                fd,
                offset: i as u64,
                buf: *sl,
                result: i32::MIN,
                dontcache: false,
            });
        }
        pread_batch(&mut ops);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(op.result, 1, "i={i} result={}", op.result);
        }
        drop(ops);
        for (i, b) in bufs.iter().enumerate() {
            assert_eq!(b[0], data[i], "i={i}");
        }

        // Empty buffer interleaved — must not be submitted; index mapping intact.
        let mut b0 = [0u8; 1];
        let mut empty: [u8; 0] = [];
        let mut b1 = [0u8; 1];
        let mut ops2 = [
            ReadOp {
                fd,
                offset: 0,
                buf: &mut b0[..],
                result: i32::MIN,
                dontcache: false,
            },
            ReadOp {
                fd,
                offset: 0,
                buf: &mut empty[..],
                result: i32::MIN,
                dontcache: false,
            },
            ReadOp {
                fd,
                offset: 1,
                buf: &mut b1[..],
                result: i32::MIN,
                dontcache: false,
            },
        ];
        pread_batch(&mut ops2);
        assert_eq!(ops2[0].result, 1);
        assert_eq!(ops2[1].result, 0);
        assert_eq!(ops2[2].result, 1);
        drop(ops2);
        assert_eq!(b0[0], data[0]);
        assert_eq!(b1[0], data[1]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
