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
//! Darwin default is the **pool** completion session (kqueue is not a
//! regular-file backend). Windows uses IOCP.
//! Machines stay staged; they do not flatten to one-shot `pread`. See
//! `docs/io-modality.md` and `docs/concurrency.md`.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// SQ/CQ depth for bulk batch sessions.
const RING_ENTRIES: u32 = crate::uring_session::DEFAULT_ENTRIES;

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

static URING_MODE: AtomicU8 = AtomicU8::new(0); // 0 unknown, 1 on, 2 off
static WORKERS: AtomicUsize = AtomicUsize::new(0);
static URING_FAIL_LOGGED: AtomicBool = AtomicBool::new(false);

/// Whether a completion session is available (uring / pool / iocp).
///
/// `RBITCOIN_IO=pread` (and aliases) disables the session. The name is
/// historical; machines run on any session backend.
pub fn io_uring_enabled() -> bool {
    match URING_MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            if crate::uring_session::forced_session_kind().is_some() {
                return true;
            }
            let want = match parse_io_token() {
                Some(IoToken::Pread) => false,
                Some(_) | None => true,
            };
            if !want {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IoToken {
    Uring,
    Pool,
    Iocp,
    Pread,
}

pub(crate) fn parse_io_token_str(s: &str) -> Option<IoToken> {
    match s.trim().to_ascii_lowercase().as_str() {
        "uring" | "io_uring" => Some(IoToken::Uring),
        "pool" => Some(IoToken::Pool),
        "iocp" => Some(IoToken::Iocp),
        "pread" | "fd" | "libc" | "pwrite" => Some(IoToken::Pread),
        _ => None,
    }
}

fn parse_io_token() -> Option<IoToken> {
    std::env::var("RBITCOIN_IO")
        .ok()
        .and_then(|s| parse_io_token_str(&s))
}

/// Backend [`crate::uring_session::UringSession::try_open`] should open.
pub fn resolved_session_kind() -> crate::uring_session::SessionKind {
    use crate::uring_session::SessionKind;
    if let Some(k) = crate::uring_session::forced_session_kind() {
        return k;
    }
    match parse_io_token() {
        Some(IoToken::Pool) => SessionKind::Pool,
        Some(IoToken::Iocp) => SessionKind::Iocp,
        Some(IoToken::Uring) => SessionKind::Uring,
        Some(IoToken::Pread) => SessionKind::Pool, // unused: gate is off
        None => default_session_kind(),
    }
}

fn default_session_kind() -> crate::uring_session::SessionKind {
    use crate::uring_session::SessionKind;
    #[cfg(target_os = "linux")]
    {
        SessionKind::Uring
    }
    #[cfg(target_os = "macos")]
    {
        SessionKind::Pool
    }
    #[cfg(windows)]
    {
        SessionKind::Iocp
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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
    match with_bulk_session(|session| pread_batch_on_session_inner(session, ops, total_nonempty)) {
        Some(true) => true,
        Some(false) => false,
        None => false,
    }
}

/// Bulk pread on a shared [`crate::IoCtx`].
///
/// - `Ok(true)`: filled on the **held** session.
/// - `Ok(false)`: no session — caller may `pread_batch` (standalone TLS, `DEPTH=0`).
/// - `Err`: held session failed (poison / leftover). Do **not** open another ring.
pub(crate) fn pread_batch_on_ctx(
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
    if pread_batch_on_session_inner(session, ops, total_nonempty) {
        return Ok(true);
    }
    if session.is_poisoned() {
        return Err(StoreError::Corrupt("invariant: io_uring session poisoned"));
    }
    Err(StoreError::Corrupt("invariant: held pread failed"))
}

fn pread_batch_on_session_inner(
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
            if session.push_pread(fd, offset, ops[next].buf, ud).is_err() {
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

        let mut cqes = match session.harvest_ready() {
            Ok(c) => c,
            Err(_) => {
                let _ = session.drain_all();
                return false;
            }
        };
        if cqes.is_empty() {
            if session.submit_and_wait_one().is_err() {
                let _ = session.drain_all();
                return false;
            }
            cqes = match session.harvest_ready() {
                Ok(c) => c,
                Err(_) => {
                    let _ = session.drain_all();
                    return false;
                }
            };
            if cqes.is_empty() {
                let _ = session.drain_all();
                return false;
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
    if session.drain_all().is_err() {
        return false;
    }

    !any_fail
}

/// Pipelined bulk pwrite — same fill/harvest shape as [`pread_batch_uring`].
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

fn pwrite_batch_on_session(
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
            if session.push_pwrite(fd, offset, ops[next].buf, ud).is_err() {
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

        let mut cqes = match session.harvest_ready() {
            Ok(c) => c,
            Err(_) => {
                let _ = session.drain_all();
                return false;
            }
        };
        if cqes.is_empty() {
            if session.submit_and_wait_one().is_err() {
                let _ = session.drain_all();
                return false;
            }
            cqes = match session.harvest_ready() {
                Ok(c) => c,
                Err(_) => {
                    let _ = session.drain_all();
                    return false;
                }
            };
            if cqes.is_empty() {
                let _ = session.drain_all();
                return false;
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
fn finish_pwrite_wave(ops: &mut [WriteOp<'_>]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dummy_handle() -> IoHandle {
        #[cfg(unix)]
        {
            IoHandle::from_raw_fd(0)
        }
        #[cfg(windows)]
        {
            IoHandle::from_raw_handle(0)
        }
    }

    #[test]
    fn pwrite_batch_fail_unfilled_is_not_success() {
        let buf = [1u8; 4];
        let mut ops = [WriteOp {
            fd: dummy_handle(),
            offset: 0,
            buf: &buf,
            result: i32::MIN,
        }];
        assert!(!finish_pwrite_wave(&mut ops));
        assert_eq!(ops[0].result, -5);
        ops[0].result = 4;
        assert!(finish_pwrite_wave(&mut ops));
    }

    /// Dense surface: empty ops, empty bufs, multi-worker fallback,
    /// workers/io_uring helpers (without racing env with parallel tests for mode).
    #[test]
    fn bulk_io_edges_empty_serial_rmw_workers() {
        let _ = io_uring_enabled(); // may probe once
        let w = bulk_io_workers();
        assert!(w >= 1);

        // Empty batches
        pread_batch(&mut []);
        pwrite_batch(&mut []);

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
        let f = std::fs::File::open(&path).unwrap();
        let fd = crate::io_handle::IoHandle::from_file(&f);

        // Empty bufs
        let mut empty = [];
        let mut ops = [ReadOp {
            fd,
            offset: 0,
            buf: &mut empty[..],
            result: i32::MIN,
        }];
        pread_batch(&mut ops);
        assert_eq!(ops[0].result, 0);

        let mut wops = [WriteOp {
            fd,
            offset: 0,
            buf: &[],
            result: i32::MIN,
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
            });
        }
        pread_batch_fallback(&mut read_ops);
        for op in &read_ops {
            assert_eq!(op.result, 64, "result={}", op.result);
        }
        assert_eq!(&bufs[0][..], &data[0..64]);

        // pread_one short read past EOF
        let mut past = [0u8; 16];
        let mut ro = ReadOp {
            fd,
            offset: 10_000,
            buf: &mut past,
            result: i32::MIN,
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
        let fd = crate::io_handle::IoHandle::from_file(&f);

        let mut b0 = [0u8; 50];
        let mut b1 = [0u8; 50];
        let mut b2 = [0u8; 50];
        {
            let mut ops = [
                ReadOp {
                    fd,
                    offset: 0,
                    buf: &mut b0[..],
                    result: i32::MIN,
                },
                ReadOp {
                    fd,
                    offset: 50,
                    buf: &mut b1[..],
                    result: i32::MIN,
                },
                ReadOp {
                    fd,
                    offset: 100,
                    buf: &mut b2[..],
                    result: i32::MIN,
                },
            ];
            pread_batch(&mut ops);
            for op in &ops {
                assert!(op.result >= 50, "result={}", op.result);
            }
        }
        assert_eq!(&b0[..], &data[0..50]);
        assert_eq!(&b1[..], &data[50..100]);
        assert_eq!(&b2[..], &data[100..150]);

        // Many small reads (stress completion mapping).
        let mut bufs: Vec<[u8; 1]> = (0..120).map(|_| [0u8; 1]).collect();
        {
            let mut slices: Vec<&mut [u8]> = bufs.iter_mut().map(|b| &mut b[..]).collect();
            let mut ops: Vec<ReadOp<'_>> = Vec::new();
            for (i, sl) in slices.iter_mut().enumerate() {
                ops.push(ReadOp {
                    fd,
                    offset: i as u64,
                    buf: sl,
                    result: i32::MIN,
                });
            }
            pread_batch(&mut ops);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(op.result, 1, "i={i}");
            }
        }
        for (i, b) in bufs.iter().enumerate() {
            assert_eq!(b[0], data[i], "i={i}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pread_batch_on_pool_session() {
        use crate::uring_session::{with_forced_session_kind, SessionKind};
        with_forced_session_kind(SessionKind::Pool, || {
            let dir = std::env::temp_dir().join(format!(
                "rbitcoin-pread-pool-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("blob");
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"pool-session-bytes!!").unwrap();
            f.flush().unwrap();
            let f = std::fs::File::open(&path).unwrap();
            let fd = crate::io_handle::IoHandle::from_file(&f);
            let mut b = [0u8; 4];
            let mut ops = [ReadOp {
                fd,
                offset: 0,
                buf: &mut b[..],
                result: i32::MIN,
            }];
            pread_batch(&mut ops);
            assert_eq!(ops[0].result, 4);
            assert_eq!(&b, b"pool");

            // Held-session path (head-resolve ID / idx) must also work on pool.
            let mut sess = crate::uring_session::UringSession::try_open_kind(
                crate::uring_session::SessionKind::Pool,
                32,
            )
            .expect("held pool");
            let mut b2 = [0u8; 4];
            let mut ops2 = [ReadOp {
                fd,
                offset: 5,
                buf: &mut b2[..],
                result: i32::MIN,
            }];
            assert!(
                pread_batch_on_ctx(&mut crate::IoCtx::held(&mut sess), &mut ops2)
                    .expect("held pool pread"),
                "pread_batch_on_ctx(held) must succeed on pool (not a linux-only stub)"
            );
            assert_eq!(ops2[0].result, 4);
            assert_eq!(&b2, b"sess");
            sess.drain_all().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        });
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
        let fd = crate::io_handle::IoHandle::from_file(&f);
        let mut b = [0u8; 5];
        {
            let mut ops = [ReadOp {
                fd,
                offset: 0,
                buf: &mut b[..],
                result: i32::MIN,
            }];
            pread_batch_fallback(&mut ops);
        }
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
        let fd = crate::io_handle::IoHandle::from_file(&f);
        let d0 = [1u8; 50];
        let d1 = [2u8; 50];
        let d2 = [3u8; 50];
        let mut ops = [
            WriteOp {
                fd,
                offset: 0,
                buf: &d0[..],
                result: i32::MIN,
            },
            WriteOp {
                fd,
                offset: 50,
                buf: &d1[..],
                result: i32::MIN,
            },
            WriteOp {
                fd,
                offset: 100,
                buf: &d2[..],
                result: i32::MIN,
            },
        ];
        pwrite_batch(&mut ops);
        for op in &ops {
            assert!(op.result >= 50, "result={}", op.result);
        }
        let mut got = vec![0u8; 150];
        let n = fd.pread(0, &mut got);
        assert_eq!(n, 150);
        assert_eq!(&got[0..50], &d0[..]);
        assert_eq!(&got[50..100], &d1[..]);
        assert_eq!(&got[100..150], &d2[..]);

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
        let fd = crate::io_handle::IoHandle::from_file(&f);

        // Three waves — first opens TL ring; later waves must reuse it correctly.
        for wave in 0..3u64 {
            let base = (wave * 64) as usize;
            let mut b0 = [0u8; 32];
            let mut b1 = [0u8; 32];
            {
                let mut ops = [
                    ReadOp {
                        fd,
                        offset: base as u64,
                        buf: &mut b0[..],
                        result: i32::MIN,
                    },
                    ReadOp {
                        fd,
                        offset: (base + 32) as u64,
                        buf: &mut b1[..],
                        result: i32::MIN,
                    },
                ];
                pread_batch(&mut ops);
                assert_eq!(ops[0].result, 32, "wave={wave}");
                assert_eq!(ops[1].result, 32, "wave={wave}");
            }
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
                },
                ReadOp {
                    fd,
                    offset: (base + 32) as u64,
                    buf: &mut c1[..],
                    result: i32::MIN,
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
        let fd = crate::io_handle::IoHandle::from_file(&f);

        let mut bufs: Vec<[u8; 1]> = (0..N).map(|_| [0u8; 1]).collect();
        {
            let mut slices: Vec<&mut [u8]> = bufs.iter_mut().map(|b| &mut b[..]).collect();
            let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(N);
            for (i, sl) in slices.iter_mut().enumerate() {
                ops.push(ReadOp {
                    fd,
                    offset: i as u64,
                    buf: sl,
                    result: i32::MIN,
                });
            }
            pread_batch(&mut ops);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(op.result, 1, "i={i} result={}", op.result);
            }
        }
        for (i, b) in bufs.iter().enumerate() {
            assert_eq!(b[0], data[i], "i={i}");
        }

        // Empty buffer interleaved — must not be submitted; index mapping intact.
        let mut b0 = [0u8; 1];
        let mut empty: [u8; 0] = [];
        let mut b1 = [0u8; 1];
        {
            let mut ops2 = [
                ReadOp {
                    fd,
                    offset: 0,
                    buf: &mut b0[..],
                    result: i32::MIN,
                },
                ReadOp {
                    fd,
                    offset: 0,
                    buf: &mut empty[..],
                    result: i32::MIN,
                },
                ReadOp {
                    fd,
                    offset: 1,
                    buf: &mut b1[..],
                    result: i32::MIN,
                },
            ];
            pread_batch(&mut ops2);
            assert_eq!(ops2[0].result, 1);
            assert_eq!(ops2[1].result, 0);
            assert_eq!(ops2[2].result, 1);
        }
        assert_eq!(b0[0], data[0]);
        assert_eq!(b1[0], data[1]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
