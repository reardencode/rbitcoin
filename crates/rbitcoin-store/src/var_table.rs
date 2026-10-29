//! Growable variable-length record table (schema v11+ Class A).
//!
//! Layout: `{stem}.body` — file header + append-only **unframed** payloads.
//! Record ranges live on [`crate::create_loc::CreateLoc`] / [`crate::delta_loc::DeltaLoc`].
//! Starts are **8-byte aligned**.
//!
//! # Publish order (lock-free)
//!
//! Single appender: **body bytes → loc append → `(count, body_end)` via seqlock**.
//! Readers load a consistent `(count, published_body_end)` pair (never
//! `(old_count, new_end)`).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::io_handle::IoHandle;
use rbitcoin_primitives::{Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Encoded Class A append waiting for body write + idx + HWM publish.
pub struct PreparedAppend {
    pub start: u64,
    pub body_blob: Vec<u8>,
    pub starts: Vec<u64>,
    pub fks: Vec<Fk>,
    pub base_count: u64,
}

impl PreparedAppend {
    pub fn aligned_lens(&self) -> Vec<u64> {
        let end = self.start.saturating_add(self.body_blob.len() as u64);
        self.starts
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                let nxt = self.starts.get(i + 1).copied().unwrap_or(end);
                nxt.saturating_sub(s)
            })
            .collect()
    }
}

/// Next 8-byte-aligned body start (schema 13+: no body-txid page rule).
#[inline]
#[doc(hidden)]
pub fn next_aligned_tx_start(cursor: u64) -> u64 {
    cursor.saturating_add(7) & !7u64
}

pub struct VarTable {
    pub body: TableFile,
    pub count: AtomicU64,
    /// Body exclusive-end of the last **published** record.
    /// Must not use live `body.logical_len()` for last-record length: the single
    /// appender may extend body for the *next* batch before publishing count.
    pub published_body_end: AtomicU64,
    /// Seqlock for `(count, published_body_end)`: odd = writer critical section,
    /// even = stable. Prevents readers from pairing a stale count with a newer end
    /// (writer stores end then count; naive double-load of count alone is racy).
    pub publish_seq: AtomicU64,
}

impl VarTable {
    pub fn create(dir: &Path, stem: &str, body_kind: TableKind) -> Result<Self, StoreError> {
        Self::create_body_only(dir, stem, body_kind)
    }

    pub fn create_body_only(
        dir: &Path,
        stem: &str,
        body_kind: TableKind,
    ) -> Result<Self, StoreError> {
        let body = TableFile::create(Self::body_path(dir, stem), body_kind)?;
        Ok(Self {
            body,
            count: AtomicU64::new(0),
            published_body_end: AtomicU64::new(FILE_HEADER_LEN as u64),
            publish_seq: AtomicU64::new(0),
        })
    }

    pub fn open_body_only(
        dir: &Path,
        stem: &str,
        body_kind: TableKind,
        count: u64,
    ) -> Result<Self, StoreError> {
        let body = TableFile::open(Self::body_path(dir, stem), body_kind)?;
        let body_end = body.logical_len().max(FILE_HEADER_LEN as u64);
        Ok(Self {
            body,
            count: AtomicU64::new(count),
            published_body_end: AtomicU64::new(body_end),
            publish_seq: AtomicU64::new(0),
        })
    }

    /// Body-only truncate (`spent` has no idx).
    pub fn truncate_body_to(&self, new_count: u64, new_end: u64) -> Result<(), StoreError> {
        self.body.set_logical_len(new_end)?;
        self.publish_begin();
        self.published_body_end.store(new_end, Ordering::Relaxed);
        self.count.store(new_count, Ordering::Relaxed);
        self.publish_end();
        Ok(())
    }

    #[doc(hidden)]
    pub fn body_path(dir: &Path, stem: &str) -> PathBuf {
        dir.join(format!("{stem}.body"))
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    /// Current body logical length (including file header).
    pub fn body_logical_len(&self) -> u64 {
        self.body.logical_len()
    }

    /// Best-effort drop of body page-cache for a byte range (see
    /// [`crate::file::TableFile::advise_dont_need`]).
    pub fn advise_body_dont_need(&self, offset: u64, len: u64) {
        self.body.advise_dont_need(offset, len);
    }

    pub fn pread_span(&self, offset: u64, len: u64) -> Result<Vec<u8>, StoreError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let n = Self::checked_body_read(self.body.logical_len(), offset, len)?;
        let mut buf = vec![0u8; n];
        self.read_body_pread(self.body.logical_len(), offset, &mut buf)?;
        Ok(buf)
    }

    #[inline]
    pub fn body_read_fd(&self) -> IoHandle {
        self.body.read_fd()
    }

    #[inline]
    pub fn body_file_path(&self) -> &Path {
        self.body.path()
    }

    #[inline]
    pub fn body_published_len(&self) -> u64 {
        self.published_meta().1
    }

    /// Inspect body bytes at a known absolute range (no idx read).
    pub fn with_bytes_at<R>(
        &self,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        // File HWM, not the seqlock end. Locator publish can trail the body.
        self.with_bytes_at_published(self.body.logical_len(), offset, len, f)
    }

    /// [`Self::with_bytes_at`] against a published end the caller already took.
    ///
    /// Compares `offset + len` to `published` only. Does not load
    /// `published_body_end` again.
    pub fn with_bytes_at_published<R>(
        &self,
        published: u64,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut buf = Vec::new();
        self.with_bytes_at_into_published(published, offset, len, &mut buf, f)
    }

    /// Like [`Self::with_bytes_at`] into a caller buffer. Pread overwrites
    /// `buf`; it is not zero-filled first.
    pub fn with_bytes_at_into<R>(
        &self,
        offset: u64,
        len: u64,
        buf: &mut Vec<u8>,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        self.with_bytes_at_into_published(self.body.logical_len(), offset, len, buf, f)
    }

    #[doc(hidden)]
    pub fn with_bytes_at_into_published<R>(
        &self,
        published: u64,
        offset: u64,
        len: u64,
        buf: &mut Vec<u8>,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        if len == 0 {
            buf.clear();
            return f(&[]);
        }
        let n = Self::checked_body_read(published, offset, len)?;
        buf.clear();
        buf.reserve(n);
        let dst = {
            let spare = buf.spare_capacity_mut();
            if spare.len() < n {
                return Err(StoreError::Corrupt("body span spare short"));
            }
            // SAFETY: `n` bytes of spare capacity; pread fills them before set_len.
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr().cast::<u8>(), n) }
        };
        self.read_body_bulk(published, offset, dst)?;
        // SAFETY: `read_body_bulk` wrote `n` bytes into spare capacity.
        unsafe {
            buf.set_len(n);
        }
        f(buf)
    }

    /// Like [`Self::with_bytes_at`] but always libc `pread` (no TLS uring).
    pub fn with_bytes_at_pread<R>(
        &self,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        if len == 0 {
            return f(&[]);
        }
        let n = Self::checked_body_read(self.body.logical_len(), offset, len)?;
        let mut buf = vec![0u8; n];
        self.read_body_pread(self.body.logical_len(), offset, &mut buf)?;
        f(&buf)
    }

    /// Absolute write into Class A body via **pwrite** (never mmap).
    ///
    /// Prefer [`Self::write_body_blob_bulk`] for Class A append (bulk pwrite path).
    pub fn write_body_abs(&self, abs_offset: u64, data: &[u8]) -> Result<(), StoreError> {
        self.write_body_blob_bulk(abs_offset, data)
    }

    /// Class A body payload write via bulk `WriteOp`. Falls back to plain pwrite
    /// when uring is unavailable.
    pub fn write_body_blob_bulk(&self, start: u64, body_blob: &[u8]) -> Result<(), StoreError> {
        if body_blob.is_empty() {
            return Ok(());
        }
        let end = start.saturating_add(body_blob.len() as u64);
        self.body.ensure_capacity(end)?;
        use crate::bulk_io::{self, WriteOp};
        let mut ops = [WriteOp {
            fd: self.body.read_fd(),
            offset: start,
            buf: body_blob,
            result: i32::MIN,
        }];
        bulk_io::pwrite_batch(&mut ops);
        if ops[0].result < 0 {
            return self.body.write_at_pwrite(start, body_blob);
        }
        if (ops[0].result as usize) != body_blob.len() {
            return self.body.write_at_pwrite(start, body_blob);
        }
        self.body
            .set_logical_len(end.max(self.body.logical_len()))?;
        Ok(())
    }
}

/// Wave ranges over a non-empty Class A stem list.
///
/// Callers pass stems in append order (`txout`, `seqsigwit` when present,
/// `spent`). `serial` is `--datadir-hdd`: one stem per wave. Otherwise one wave.
pub fn class_a_body_waves(serial: bool, n_stems: usize) -> Vec<std::ops::Range<usize>> {
    if n_stems == 0 {
        return Vec::new();
    }
    if serial {
        return (0..n_stems).map(|i| i..i + 1).collect();
    }
    std::iter::once(0..n_stems).collect()
}

/// Submit prepared Class A body blobs without moving `published_len`.
///
/// `serial` (`--datadir-hdd`) is one `pwrite_batch` per stem. Otherwise every
/// stem is one wave. The caller publishes body ends after locator strides
/// that cover these bytes. Falls back to per-stem `pwrite` if a wave is short
/// or fails.
pub fn write_prepared_bodies_one_wave(
    jobs: &[(&VarTable, &PreparedAppend)],
    serial: bool,
) -> Result<(), StoreError> {
    if jobs.is_empty() {
        return Ok(());
    }
    for (table, prep) in jobs {
        if prep.body_blob.is_empty() {
            continue;
        }
        let end = prep.start.saturating_add(prep.body_blob.len() as u64);
        table.ensure_body_end(end)?;
    }
    use crate::bulk_io::{self, WriteOp};
    let mut ops: Vec<WriteOp<'_>> = Vec::with_capacity(jobs.len());
    for (table, prep) in jobs {
        if prep.body_blob.is_empty() {
            continue;
        }
        ops.push(WriteOp {
            fd: table.body_write_fd(),
            offset: prep.start,
            buf: prep.body_blob.as_slice(),
            result: i32::MIN,
        });
    }
    if !ops.is_empty() {
        let mut all_ok = true;
        for wave in class_a_body_waves(serial, ops.len()) {
            bulk_io::pwrite_batch(&mut ops[wave.start..wave.end]);
            let wave_ok = ops[wave.start..wave.end]
                .iter()
                .all(|op| op.result >= 0 && (op.result as usize) == op.buf.len());
            if !wave_ok {
                all_ok = false;
                break;
            }
        }
        if !all_ok {
            for (table, prep) in jobs {
                table.body.write_uncommitted(prep.start, &prep.body_blob)?;
            }
        }
    }
    Ok(())
}

impl VarTable {
    /// Pre-grow body capacity so a following mega `put_batch` does not remap mid-write.
    pub fn reserve_append(&self, body_bytes: u64, _n_records: u64) -> Result<(), StoreError> {
        let body_need = self.body.logical_len().saturating_add(body_bytes);
        self.body.ensure_capacity(body_need)?;
        Ok(())
    }

    /// Encode records and validate starts. Does **not** write or publish.
    pub fn prepare_batch_encode(
        &self,
        n: usize,
        estimate_bytes: usize,
        mut encode: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<Option<PreparedAppend>, StoreError> {
        if n == 0 {
            return Ok(None);
        }
        let base_count = self.count.load(Ordering::Acquire);
        let start = self.body.logical_len().max(FILE_HEADER_LEN as u64);
        let mut body_blob = Vec::with_capacity(estimate_bytes);
        let mut starts = Vec::with_capacity(n);
        let mut fks = Vec::with_capacity(n);
        let mut cursor = start;
        for i in 0..n {
            fks.push(Fk(base_count + 1 + i as u64));
            let aligned = next_aligned_tx_start(cursor);
            let pad = aligned.saturating_sub(cursor) as usize;
            if pad > 0 {
                body_blob.resize(body_blob.len() + pad, 0);
                cursor = aligned;
            }
            starts.push(cursor);
            let before = body_blob.len();
            encode(i, &mut body_blob);
            // Loc strides must be strictly monotone. Zero-length payloads (empty
            // seqsigwit) get an 8-byte zero pad so the next start advances one stride.
            // Decode treats trailing zeros as pad. Spent `n_out ≥ 1` is 8×n.
            if body_blob.len() == before {
                body_blob.resize(body_blob.len().saturating_add(8), 0);
            }
            cursor += (body_blob.len() - before) as u64;
        }
        let aligned_end = next_aligned_tx_start(cursor);
        let tail = aligned_end.saturating_sub(cursor) as usize;
        if tail > 0 {
            body_blob.resize(body_blob.len() + tail, 0);
        }
        // Single appender: count must still equal base.
        if self.count.load(Ordering::Acquire) != base_count {
            return Err(StoreError::Corrupt("var put_batch_encode race"));
        }
        let (_c, body_end) = self.published_meta();
        // Starts must land at/after the exclusive end of published body — never
        // re-index bytes already owned by an earlier create (double-append class).
        if let Some(&s0) = starts.first() {
            if s0 < body_end {
                return Err(StoreError::Corrupt(
                    "tx body starts inside published body_end \
                     (refusing Class A double-append)",
                ));
            }
        }
        Ok(Some(PreparedAppend {
            start,
            body_blob,
            starts,
            fks,
            base_count,
        }))
    }

    pub fn body_write_fd(&self) -> IoHandle {
        self.body.read_fd()
    }

    pub fn ensure_body_end(&self, end: u64) -> Result<(), StoreError> {
        self.body.ensure_capacity(end)
    }

    /// Body end after locator headers. `durable` is one header pwrite, the
    /// same cost as `write_at`. Otherwise RAM moves and `flush` keeps the
    /// previous header.
    pub fn note_body_end(&self, end: u64, durable: bool) {
        let _ = self.body.publish_end(end, durable);
    }

    /// Count + body-end publish after the body blob is already on disk (and HWM set).
    pub fn finish_prepared(&self, prep: PreparedAppend) -> Result<Vec<Fk>, StoreError> {
        let new_end = prep.start.saturating_add(prep.body_blob.len() as u64);
        let new_count = prep.base_count + prep.fks.len() as u64;
        self.publish_begin();
        self.published_body_end.store(new_end, Ordering::Relaxed);
        self.count.store(new_count, Ordering::Relaxed);
        self.publish_end();
        Ok(prep.fks)
    }

    #[inline]
    #[doc(hidden)]
    pub fn publish_begin(&self) {
        let prev = self.publish_seq.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(prev & 1, 0, "nested/concurrent publish_begin");
        std::sync::atomic::fence(Ordering::Release);
    }

    #[inline]
    #[doc(hidden)]
    pub fn publish_end(&self) {
        let prev = self.publish_seq.fetch_add(1, Ordering::Release);
        debug_assert_eq!(prev & 1, 1, "publish_end without begin");
    }

    /// Consistent `(count, published_body_end)` via seqlock (never torn pair).
    pub fn published_meta(&self) -> (u64, u64) {
        loop {
            let s1 = self.publish_seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let end = self
                .published_body_end
                .load(Ordering::Relaxed)
                .max(FILE_HEADER_LEN as u64);
            let count = self.count.load(Ordering::Relaxed);
            let s2 = self.publish_seq.load(Ordering::Acquire);
            if s1 == s2 {
                return (count, end);
            }
        }
    }

    /// Read only the first `buf.len()` bytes at absolute body `(offset, len)`.
    ///
    /// `published` is the end the caller already paired with the record count.
    /// This does not load `published_body_end` again.
    pub fn read_prefix_at_published(
        &self,
        published: u64,
        offset: u64,
        len: u64,
        buf: &mut [u8],
    ) -> Result<usize, StoreError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = (len as usize).min(buf.len());
        if n == 0 {
            return Ok(0);
        }
        self.read_body_bulk(published, offset, &mut buf[..n])?;
        Ok(n)
    }

    /// One read. A create-loc stride is a `u32` times 8 (~32 GiB). A block is a few mebibytes.
    pub const BODY_READ_MAX: u64 = 64 * 1024 * 1024;

    /// Cap and published end before any buffer is grown.
    #[doc(hidden)]
    pub fn checked_body_read(published: u64, offset: u64, len: u64) -> Result<usize, StoreError> {
        if len > Self::BODY_READ_MAX {
            return Err(StoreError::Rejected("body read too large"));
        }
        Self::require_published_body(published, offset, len)?;
        usize::try_from(len).map_err(|_| StoreError::Corrupt("body span too large"))
    }

    /// Compare `offset + len` to the caller's published-end integer.
    /// No atomic load: a fresh `published_body_end` can disagree with that snapshot.
    #[doc(hidden)]
    pub fn require_published_body(published: u64, offset: u64, len: u64) -> Result<(), StoreError> {
        if published == 0 {
            return Err(StoreError::Corrupt(
                "invariant: body read missing published end",
            ));
        }
        if offset.saturating_add(len) > published {
            return Err(StoreError::Corrupt(
                "invariant: body read past published end",
            ));
        }
        Ok(())
    }

    /// Class A body pread via bulk_io.
    #[doc(hidden)]
    pub fn read_body_bulk(
        &self,
        published: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
        Self::require_published_body(published, offset, buf.len() as u64)?;
        let rc = crate::bulk_io::pread_single(self.body.read_fd(), offset, buf);
        if rc < 0 {
            return Err(StoreError::io(
                self.body.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) != buf.len() {
            self.body.read_at(offset, buf)?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn read_body_pread(
        &self,
        published: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
        Self::require_published_body(published, offset, buf.len() as u64)?;
        use crate::bulk_io::ReadOp;
        use crate::io_backend::ReadIoBackend;
        let mut ops = [ReadOp {
            fd: self.body.read_fd(),
            offset,
            buf,
            result: i32::MIN,
        }];
        crate::bulk_io::pread_batch_backend(&mut ops, ReadIoBackend::Pread);
        let rc = ops[0].result;
        if rc < 0 {
            return Err(StoreError::io(
                self.body.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) != buf.len() {
            self.body.read_at(offset, buf)?;
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        Ok(())
    }

    pub fn sync_data_only(&self) -> Result<(), StoreError> {
        self.body.sync_data_only()
    }

    /// `POSIX_FADV_RANDOM` until drop, then `POSIX_FADV_NORMAL`.
    pub fn advise_random_for_sweep(&self) -> BodyAccessGuard<'_> {
        #[cfg(target_os = "linux")]
        self.body.advise_access(libc::POSIX_FADV_RANDOM);
        BodyAccessGuard { body: &self.body }
    }

    /// HWM + MS_ASYNC (no fdatasync) — host-friendly process exit.
    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        Ok(())
    }
}

pub struct BodyAccessGuard<'a> {
    pub body: &'a crate::file::TableFile,
}

impl Drop for BodyAccessGuard<'_> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.body.advise_access(libc::POSIX_FADV_NORMAL);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self.body;
        }
    }
}
