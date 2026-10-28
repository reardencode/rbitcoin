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
//! - `RBITCOIN_IO=pread` — force libc `pread`/`pwrite` fallback (see `io_backend`).
//! - `RBITCOIN_BULK_IO_WORKERS` — parallel pread workers when uring is off
//!   (default `min(CPUs, 16)`; `1` = serial). Writes fall back to serial pwrite.
//!
//! Ring entries: [`crate::uring_session::DEFAULT_ENTRIES`] (128). Large waves
//! keep the ring full: submit up to depth outstanding ops, then refill as CQEs
//! complete (pipelined, not stop-and-wait chunks).
//!
//! # Non-Linux
//!
//! Darwin default is libc **pread** (kqueue is not a regular-file backend,
//! and the pool session's per-read handoff cost more than the reads in IBD);
//! `RBITCOIN_IO=pool` opens the pool session there. Windows uses IOCP.
//! Machines stay staged; they do not flatten to one-shot `pread`. See
//! `docs/io-modality.md` and `docs/concurrency.md`.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// SQ/CQ depth for bulk batch sessions.
#[doc(hidden)]
pub const RING_ENTRIES: u32 = crate::uring_session::DEFAULT_ENTRIES;

/// One independent pread. Caller owns `buf` for the full submit/wait.
pub struct ReadOp<'a> {
    pub fd: IoHandle,
    pub offset: u64,
    pub buf: &'a mut [u8],
    /// Filled: bytes read (≥0) or negated errno on failure.
    pub result: i32,
}

/// One independent pwrite. Caller owns `buf` for the full submit/wait.
pub struct WriteOp<'a> {
    pub fd: IoHandle,
    pub offset: u64,
    pub buf: &'a [u8],
    /// Filled: bytes written (≥0) or negated errno on failure.
    pub result: i32,
}

#[doc(hidden)]
pub static URING_MODE: AtomicU8 = AtomicU8::new(0); // 0 unknown, 1 on, 2 off
#[doc(hidden)]
pub static WORKERS: AtomicUsize = AtomicUsize::new(0);
#[doc(hidden)]
pub static URING_FAIL_LOGGED: AtomicBool = AtomicBool::new(false);

/// Whether a completion session is available (uring / pool / iocp).
///
/// `RBITCOIN_IO=pread` (and aliases) disables the session. The name is
/// historical; machines run on any session backend.
pub fn io_uring_enabled() -> bool {
    match URING_MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            if !session_wanted(parse_io_token()) {
                URING_MODE.store(2, Ordering::Relaxed);
                return false;
            }
            let ok = crate::uring_session::UringSession::try_open(32).is_ok();
            URING_MODE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            if !ok && !URING_FAIL_LOGGED.swap(true, Ordering::Relaxed) {
                rbitcoin_log::warn!(
                    "store: completion session unavailable — bulk reads use pread fallback \
                     (set RBITCOIN_IO=pread to silence)"
                );
            }
            ok
        }
    }
}

#[doc(hidden)]
pub fn session_wanted(token: Option<IoToken>) -> bool {
    match token {
        Some(IoToken::Pread) => false,
        Some(_) => true,
        // Darwin's only session is the worker pool. Its per-read handoff cost
        // more than the read in signet IBD (about 20% slower, warm or cold).
        None => !cfg!(target_os = "macos"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoToken {
    Uring,
    Pool,
    Iocp,
    Pread,
}

pub fn parse_io_token_str(s: &str) -> Option<IoToken> {
    match s.trim().to_ascii_lowercase().as_str() {
        "uring" | "io_uring" => Some(IoToken::Uring),
        "pool" => Some(IoToken::Pool),
        "iocp" => Some(IoToken::Iocp),
        "pread" | "fd" | "libc" | "pwrite" => Some(IoToken::Pread),
        _ => None,
    }
}

#[doc(hidden)]
pub fn parse_io_token() -> Option<IoToken> {
    std::env::var("RBITCOIN_IO")
        .ok()
        .and_then(|s| parse_io_token_str(&s))
}

/// Backend [`crate::uring_session::UringSession::try_open`] should open.
pub fn resolved_session_kind() -> crate::uring_session::SessionKind {
    use crate::uring_session::SessionKind;
    match parse_io_token() {
        Some(IoToken::Pool) => SessionKind::Pool,
        Some(IoToken::Iocp) => SessionKind::Iocp,
        Some(IoToken::Uring) => SessionKind::Uring,
        Some(IoToken::Pread) => SessionKind::Pool, // unused: gate is off
        None => default_session_kind(),
    }
}

#[doc(hidden)]
pub fn default_session_kind() -> crate::uring_session::SessionKind {
    use crate::uring_session::SessionKind;
    #[cfg(target_os = "linux")]
    {
        SessionKind::Uring
    }
    #[cfg(windows)]
    {
        SessionKind::Iocp
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        SessionKind::Pool
    }
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
    if io_uring_enabled() && pread_batch_uring(ops) {
        return;
    }
    pread_batch_fallback(ops);
}

/// One pread (uring when available). Returns bytes read (≥0) or negated errno.
#[inline]
pub fn pread_single(fd: IoHandle, offset: u64, buf: &mut [u8]) -> i32 {
    if buf.is_empty() {
        return 0;
    }
    let mut ops = [ReadOp {
        fd,
        offset,
        buf,
        result: i32::MIN,
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
/// Public counterpart of [`pread_batch`]. Used by production bulk writers
/// (e.g. `var_table`) and tests.
pub fn pwrite_batch(ops: &mut [WriteOp<'_>]) {
    if ops.is_empty() {
        return;
    }
    // The armed fd must hit `IoHandle::pwrite`. A completion submit would
    // report a full write and the partial-append fault would not run.
    #[cfg(debug_assertions)]
    if ops
        .iter()
        .any(|op| crate::io_handle::would_short_pwrite(op.fd, op.buf.len()))
    {
        pwrite_batch_fallback(ops);
        return;
    }
    if io_uring_enabled() && pwrite_batch_uring(ops) {
        return;
    }
    pwrite_batch_fallback(ops);
}

/// Thread-local bulk ring via [`crate::uring_session::with_thread_local`].
///
/// **Must not** be called while another `with_thread_local` is active on this
/// OS thread (nested TLS uring panics). Plan head-resolve streams probe/id/idx
/// SQEs on its own held session instead.
#[doc(hidden)]
pub fn with_bulk_session<R>(
    f: impl FnOnce(&mut crate::uring_session::UringSession) -> R,
) -> Option<R> {
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
#[doc(hidden)]
pub fn pread_batch_uring(ops: &mut [ReadOp<'_>]) -> bool {
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
    match with_bulk_session(|session| pread_batch_on_session_inner(session, ops, total_nonempty)) {
        Some(true) => true,
        Some(false) => false,
        None => false,
    }
}

/// Bulk pread on a shared [`crate::IoCtx`].
///
/// - `Ok(true)`: submitted on the **held** session. Per-op short/errno and
///   live-ring batch fail (empty CQ / submit) stay on those ops; the caller
///   libc-completes them. That is **not** session death and does not consume
///   IBD uring recover credit.
/// - `Ok(false)`: no session — caller may `pread_batch` (standalone TLS, `DEPTH=0`).
/// - `Err`: held session poisoned / leftover. Do **not** open another ring
///   and do **not** libc-complete on a dirty ring.
pub fn pread_batch_on_ctx(
    ctx: &mut crate::IoCtx<'_>,
    ops: &mut [ReadOp<'_>],
) -> Result<bool, StoreError> {
    let Some(session) = ctx.session() else {
        return Ok(false);
    };
    let total_nonempty = ops.iter().filter(|o| !o.buf.is_empty()).count();
    if total_nonempty == 0 {
        for op in ops.iter_mut() {
            if op.buf.is_empty() {
                op.result = 0;
            }
        }
        return Ok(true);
    }
    for op in ops.iter_mut() {
        op.result = if op.buf.is_empty() { 0 } else { i32::MIN };
    }
    held_pread_after_inner(
        pread_batch_on_session_inner(session, ops, total_nonempty),
        session.is_poisoned(),
    )
}

#[doc(hidden)]
pub fn held_pread_after_inner(inner_ok: bool, poisoned: bool) -> Result<bool, StoreError> {
    if inner_ok {
        return Ok(true);
    }
    if poisoned {
        return Err(StoreError::Corrupt("invariant: io_uring session poisoned"));
    }
    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum EmptyHarvest {
    Retry,
    Fail,
}

#[doc(hidden)]
pub fn empty_harvest_next(wait_ok: bool) -> EmptyHarvest {
    if wait_ok {
        EmptyHarvest::Retry
    } else {
        EmptyHarvest::Fail
    }
}

#[doc(hidden)]
pub fn pread_batch_on_session_inner(
    session: &mut crate::uring_session::UringSession,
    ops: &mut [ReadOp<'_>],
    total_nonempty: usize,
) -> bool {
    if session.begin_batch().is_err() {
        return false;
    }
    let epoch = session.epoch();
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
            let ud = crate::uring_session::pack_ud(
                crate::uring_session::KIND_BULK_PREAD,
                epoch,
                next as u32,
            );
            // SAFETY: caller owns each `buf` until `pread_batch` returns.
            if unsafe { session.push_pread(fd, offset, ops[next].buf, ud) }.is_err() {
                if session.in_flight() == 0 {
                    let _ = session.drain_all();
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

        let cqes = match session.harvest_ready() {
            Ok(c) => c,
            Err(_) => {
                let _ = session.drain_all();
                return false;
            }
        };
        if cqes.is_empty() {
            match empty_harvest_next(session.submit_and_wait_one().is_ok()) {
                EmptyHarvest::Retry => continue,
                EmptyHarvest::Fail => {
                    let _ = session.drain_all();
                    return false;
                }
            }
        } else if session.submit().is_err() {
            let _ = session.drain_all();
            return false;
        }

        for (ud, res) in cqes {
            let (kind, ep, slot) = crate::uring_session::unpack_ud(ud);
            if kind != crate::uring_session::KIND_BULK_PREAD || ep != epoch {
                session.poison();
                let _ = session.drain_all();
                return false;
            }
            let i = slot as usize;
            if i < ops.len() {
                ops[i].result = res;
            }
            completed += 1;
        }
    }

    for op in ops.iter_mut() {
        if !op.buf.is_empty() && op.result == i32::MIN {
            op.result = -5; // EIO
        }
    }
    if session.drain_all().is_err() {
        return false;
    }

    true
}

/// Pipelined bulk pwrite — same fill/harvest shape as [`pread_batch_uring`].
#[doc(hidden)]
pub fn pwrite_batch_uring(ops: &mut [WriteOp<'_>]) -> bool {
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

#[doc(hidden)]
pub fn pwrite_batch_on_session(
    session: &mut crate::uring_session::UringSession,
    ops: &mut [WriteOp<'_>],
    total_nonempty: usize,
) -> bool {
    if session.begin_batch().is_err() {
        return false;
    }
    let epoch = session.epoch();
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
            let ud = crate::uring_session::pack_ud(
                crate::uring_session::KIND_BULK_PWRITE,
                epoch,
                next as u32,
            );
            // SAFETY: caller owns each `buf` until `pwrite_batch` returns.
            if unsafe { session.push_pwrite(fd, offset, ops[next].buf, ud) }.is_err() {
                if session.in_flight() == 0 {
                    let _ = session.drain_all();
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

        let cqes = match session.harvest_ready() {
            Ok(c) => c,
            Err(_) => {
                let _ = session.drain_all();
                return false;
            }
        };
        if cqes.is_empty() {
            match empty_harvest_next(session.submit_and_wait_one().is_ok()) {
                EmptyHarvest::Retry => continue,
                EmptyHarvest::Fail => {
                    let _ = session.drain_all();
                    return false;
                }
            }
        } else if session.submit().is_err() {
            let _ = session.drain_all();
            return false;
        }

        for (ud, res) in cqes {
            let (kind, ep, slot) = crate::uring_session::unpack_ud(ud);
            if kind != crate::uring_session::KIND_BULK_PWRITE || ep != epoch {
                session.poison();
                let _ = session.drain_all();
                return false;
            }
            let i = slot as usize;
            if i < ops.len() {
                ops[i].result = res;
            }
            completed += 1;
        }
    }

    let ok = finish_pwrite_wave(ops);
    if session.drain_all().is_err() {
        return false;
    }
    ok
}

/// Unfilled or failed pwrite ops are not success. Caller libc-retries.
#[doc(hidden)]
pub fn finish_pwrite_wave(ops: &mut [WriteOp<'_>]) -> bool {
    let mut any_fail = false;
    for op in ops.iter_mut() {
        if !op.buf.is_empty() && op.result == i32::MIN {
            op.result = -5;
            any_fail = true;
        }
        if op.result < 0 {
            any_fail = true;
        }
    }
    !any_fail
}

#[doc(hidden)]
pub fn pread_batch_fallback(ops: &mut [ReadOp<'_>]) {
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

#[doc(hidden)]
pub fn pread_one(op: &mut ReadOp<'_>) {
    if op.buf.is_empty() {
        op.result = 0;
        return;
    }
    let mut got = 0usize;
    while got < op.buf.len() {
        let n = op.fd.pread(op.offset + got as u64, &mut op.buf[got..]);
        if n < 0 {
            op.result = n;
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

#[doc(hidden)]
pub fn pwrite_batch_fallback(ops: &mut [WriteOp<'_>]) {
    for op in ops.iter_mut() {
        pwrite_one(op);
    }
}

#[doc(hidden)]
pub fn pwrite_one(op: &mut WriteOp<'_>) {
    if op.buf.is_empty() {
        op.result = 0;
        return;
    }
    let mut got = 0usize;
    while got < op.buf.len() {
        let n = op.fd.pwrite(op.offset + got as u64, &op.buf[got..]);
        if n < 0 {
            op.result = n;
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
