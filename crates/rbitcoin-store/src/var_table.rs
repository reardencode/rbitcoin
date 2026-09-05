//! Growable variable-length record table (schema v11+ Class A).
//!
//! Layout:
//! - `{stem}.body` — file header + append-only **unframed** payloads
//! - `{stem}.idx.meta` + `{stem}.idx.NNNNNN` — segmented **u32 stride-8**
//!   offsets (see [`crate::tx_idx::TxIdx`])
//!
//! Record length is derived from the index: `len(i) = start(i+1) - start(i)`,
//! and for the last record `logical_body_end - start`. Starts are **8-byte
//! aligned** (and for Class A, txid does not straddle a 4 KiB page).
//!
//! # Publish order (lock-free)
//!
//! Single appender: **body bytes → idx slots → `(count, body_end)` via seqlock**.
//! Readers load a consistent `(count, published_body_end)` pair (never
//! `(old_count, new_end)`).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::io_handle::IoHandle;
use crate::tx_idx::TxIdx;
use rbitcoin_primitives::{Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Encoded Class A append waiting for body write + idx + HWM publish.
pub(crate) struct PreparedAppend {
    pub start: u64,
    pub body_blob: Vec<u8>,
    pub starts: Vec<u64>,
    pub fks: Vec<Fk>,
    pub base_count: u64,
}

/// Next 8-byte-aligned body start (schema 13+: no body-txid page rule).
#[inline]
fn next_aligned_tx_start(cursor: u64) -> u64 {
    cursor.saturating_add(7) & !7u64
}

pub struct VarTable {
    body: TableFile,
    idx: TxIdx,
    count: AtomicU64,
    /// Body exclusive-end of the last **published** record.
    /// Must not use live `body.logical_len()` for last-record length: the single
    /// appender may extend body for the *next* batch before publishing count.
    published_body_end: AtomicU64,
    /// Seqlock for `(count, published_body_end)`: odd = writer critical section,
    /// even = stable. Prevents readers from pairing a stale count with a newer end
    /// (writer stores end then count; naive double-load of count alone is racy).
    publish_seq: AtomicU64,
}

impl VarTable {
    pub fn create(dir: &Path, stem: &str, body_kind: TableKind) -> Result<Self, StoreError> {
        let body = TableFile::create(Self::body_path(dir, stem), body_kind)?;
        let idx = TxIdx::create(dir, stem)?;
        Ok(Self {
            body,
            idx,
            count: AtomicU64::new(0),
            published_body_end: AtomicU64::new(FILE_HEADER_LEN as u64),
            publish_seq: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path, stem: &str, body_kind: TableKind) -> Result<Self, StoreError> {
        let body = TableFile::open(Self::body_path(dir, stem), body_kind)?;
        let idx = TxIdx::open(dir, stem)?;
        let count = idx.slot_count();
        let body_end = body.logical_len().max(FILE_HEADER_LEN as u64);
        Ok(Self {
            body,
            idx,
            count: AtomicU64::new(count),
            published_body_end: AtomicU64::new(body_end),
            publish_seq: AtomicU64::new(0),
        })
    }

    /// Truncate published Class A count to `new_count` (idx + RAM count + body HWM).
    ///
    /// Body bytes past the new end may remain on disk (append-only); HWM rolls
    /// back to the start of the first dropped record so the next append reuses
    /// that region. Call only from sole Class A open/repair path.
    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count.load(Ordering::Acquire);
        if new_count > cur {
            return Err(StoreError::Corrupt("var table truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        // Body exclusive-end for kept prefix = start of first dropped record.
        let new_end = if new_count == 0 {
            FILE_HEADER_LEN as u64
        } else if new_count < cur {
            // record_start uses live idx count; still valid before idx truncate.
            self.idx.record_start(new_count + 1)?
        } else {
            self.body.logical_len().max(FILE_HEADER_LEN as u64)
        };
        self.idx.truncate_to_count(new_count)?;
        self.body.set_logical_len(new_end)?;
        self.publish_begin();
        self.published_body_end.store(new_end, Ordering::Relaxed);
        self.count.store(new_count, Ordering::Relaxed);
        self.publish_end();
        Ok(())
    }

    fn body_path(dir: &Path, stem: &str) -> PathBuf {
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

    pub(crate) fn pread_span(&self, offset: u64, len: u64) -> Result<Vec<u8>, StoreError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let n = usize::try_from(len).map_err(|_| StoreError::Corrupt("body span too large"))?;
        let mut buf = vec![0u8; n];
        self.read_body_pread(offset, &mut buf)?;
        Ok(buf)
    }

    /// Plan body_range idx page IO without reading (plan head-resolve STAGE_IDX).
    ///
    /// Caller submits page preads on an owned uring session and decodes via
    /// [`crate::tx_idx::BodyRangeIdxPlan::decode_range`].
    pub(crate) fn plan_body_range_idx(
        &self,
        fk: Fk,
    ) -> Result<crate::tx_idx::BodyRangeIdxPlan, StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        if id == 0 {
            return Err(StoreError::InvalidFk);
        }
        let (count, body_end) = self.published_meta();
        if id > count {
            return Err(StoreError::NotFound);
        }
        self.idx.plan_body_range(id, count, body_end)
    }

    /// Absolute `(offset, len)` of the unframed payload for `fk`.
    ///
    /// **Interior records (`id < count`):** starts of `id` and `id+1` (may span
    /// idx segments).
    ///
    /// **Last record (`id == count`):** seqlock `(count, body_end)` + start.
    ///
    /// Corrupt idx (`start(id+1) < start(id)`) is a hard `Corrupt` — no live heal.
    pub fn record_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        if id == 0 {
            return Err(StoreError::InvalidFk);
        }
        let count = self.count.load(Ordering::Acquire);
        if id > count {
            return Err(StoreError::NotFound);
        }
        if id < count {
            return self.idx.record_range_interior(id);
        }
        let (count2, body_end) = self.published_meta();
        if id > count2 {
            return Err(StoreError::NotFound);
        }
        if id < count2 {
            return self.idx.record_range_interior(id);
        }
        let start = self.record_start(id, count2)?;
        if body_end < start {
            return Err(StoreError::Corrupt("var record end < start"));
        }
        Ok((start, body_end - start))
    }

    /// Contiguous `(offset, len)` for Class A ids `first..=last` (1-based).
    pub fn record_ranges(&self, first: u64, last: u64) -> Result<Vec<(u64, u64)>, StoreError> {
        let (count, body_end) = self.published_meta();
        self.idx.record_ranges(first, last, count, body_end)
    }

    /// Bulk body ranges for arbitrary fks — **sorted** walk of segmented idx.
    ///
    /// Output order matches `fks`. Null / OOB ids yield `None` (not an error).
    /// Contiguous id runs use page-aligned sequential loads; sparse ids use
    /// OS-page-coalesced bulk pread (`record_starts_batch_bulk`).
    pub fn record_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        if fks.is_empty() {
            return Ok(Vec::new());
        }
        let (count, body_end) = self.published_meta();
        let mut out: Vec<Option<(u64, u64)>> = vec![None; fks.len()];
        let mut jobs: Vec<(usize, u64)> = Vec::with_capacity(fks.len());
        for (i, fk) in fks.iter().enumerate() {
            let Some(id) = fk.get() else {
                continue;
            };
            if id == 0 || id > count {
                continue;
            }
            jobs.push((i, id));
        }
        if jobs.is_empty() {
            return Ok(out);
        }
        jobs.sort_unstable_by_key(|(_, id)| *id);

        let mut start_ids: Vec<u64> = Vec::with_capacity(jobs.len() * 2);
        for &(_, id) in &jobs {
            start_ids.push(id);
            if id < count {
                start_ids.push(id + 1);
            }
        }
        start_ids.sort_unstable();
        start_ids.dedup();

        let starts = self
            .idx
            .record_starts_batch_bulk(&start_ids, crate::io_backend::read_io_backend())?;
        let mut start_map: crate::U64Map<u64> =
            crate::U64Map::with_capacity_and_hasher(start_ids.len(), Default::default());
        for (id, s) in start_ids.iter().zip(starts.iter()) {
            if let Some(abs) = s {
                start_map.insert(*id, *abs);
            }
        }

        for &(orig_i, id) in &jobs {
            let Some(&start) = start_map.get(&id) else {
                continue;
            };
            let end = if id < count {
                match start_map.get(&(id + 1)) {
                    Some(&e) => e,
                    None => continue,
                }
            } else {
                body_end
            };
            if end < start {
                return Err(StoreError::Corrupt("var record end < start"));
            }
            out[orig_i] = Some((start, end - start));
        }
        Ok(out)
    }

    /// Segmented idx: resolve ranges via page-coalesced batch APIs, then body pread.
    #[inline]
    pub(crate) fn body_read_fd(&self) -> IoHandle {
        self.body.read_fd()
    }

    #[inline]
    pub(crate) fn body_file_path(&self) -> &Path {
        self.body.path()
    }

    #[inline]
    pub(crate) fn body_published_len(&self) -> u64 {
        self.published_meta().1
    }

    /// Inspect record bytes without copying into a `Vec`.
    pub fn with_raw<R>(
        &self,
        fk: Fk,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let (off, len) = self.record_range(fk)?;
        self.with_bytes_at(off, len, f)
    }

    /// Inspect body bytes at a known absolute range (no idx read).
    pub fn with_bytes_at<R>(
        &self,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut buf = Vec::new();
        self.with_bytes_at_into(offset, len, &mut buf, f)
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
        if len == 0 {
            buf.clear();
            return f(&[]);
        }
        let n = usize::try_from(len).map_err(|_| StoreError::Corrupt("body span too large"))?;
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
        self.read_body_bulk(offset, dst)?;
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
        let mut buf = vec![0u8; len as usize];
        self.read_body_pread(offset, &mut buf)?;
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
    pub(crate) fn write_body_blob_bulk(
        &self,
        start: u64,
        body_blob: &[u8],
    ) -> Result<(), StoreError> {
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

/// Submit several prepared Class A body blobs as **one** `pwrite_batch` wave.
///
/// Publish order is still body → idx → HWM: callers must [`VarTable::finish_prepared`]
/// after this returns. Falls back to per-stem [`VarTable::write_body_blob_bulk`]
/// if the batched submit is short or fails.
pub(crate) fn write_prepared_bodies_one_wave(
    jobs: &[(&VarTable, &PreparedAppend)],
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
        bulk_io::pwrite_batch(&mut ops);
        let all_ok = ops
            .iter()
            .zip(jobs.iter().filter(|(_, p)| !p.body_blob.is_empty()))
            .all(|(op, (_, prep))| op.result >= 0 && (op.result as usize) == prep.body_blob.len());
        if !all_ok {
            for (table, prep) in jobs {
                table.write_body_blob_bulk(prep.start, &prep.body_blob)?;
            }
            return Ok(());
        }
    }
    for (table, prep) in jobs {
        let end = prep.start.saturating_add(prep.body_blob.len() as u64);
        table.publish_body_hwm(end)?;
    }
    Ok(())
}

impl VarTable {
    /// Next 8-aligned body start for a following append.
    pub fn next_aligned_start(&self) -> u64 {
        let start = self.body.logical_len().max(FILE_HEADER_LEN as u64);
        next_aligned_tx_start(start)
    }

    /// Pre-grow body (+ idx tail) capacity so a following mega `put_batch` does not
    /// remap mid-write.
    pub fn reserve_append(&self, body_bytes: u64, n_records: u64) -> Result<(), StoreError> {
        let body_need = self.body.logical_len().saturating_add(body_bytes);
        self.body.ensure_capacity(body_need)?;
        self.idx.reserve_slots(n_records)?;
        Ok(())
    }

    /// Encode `n` records into one body blob then one write.
    ///
    /// Encoding runs outside any count barrier (single appender role). Publish
    /// order: body → idx → `count` Release. Record starts are always 8-aligned
    /// (stride idx) with the Class A page non-straddle rule.
    pub fn put_batch_encode(
        &self,
        n: usize,
        estimate_bytes: usize,
        encode: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<Vec<Fk>, StoreError> {
        self.put_batch_encode_inner(n, estimate_bytes, encode)
    }

    /// Same as [`put_batch_encode`] (alignment is always on for stride idx).
    pub fn put_batch_encode_aligned(
        &self,
        n: usize,
        estimate_bytes: usize,
        encode: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<Vec<Fk>, StoreError> {
        self.put_batch_encode_inner(n, estimate_bytes, encode)
    }

    fn put_batch_encode_inner(
        &self,
        n: usize,
        estimate_bytes: usize,
        encode: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<Vec<Fk>, StoreError> {
        let Some(prep) = self.prepare_batch_encode(n, estimate_bytes, encode)? else {
            return Ok(Vec::new());
        };
        self.write_body_blob_bulk(prep.start, &prep.body_blob)?;
        self.finish_prepared(prep)
    }

    /// Encode records and validate starts. Does **not** write or publish.
    pub(crate) fn prepare_batch_encode(
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
            // Idx starts must be strictly monotone. Zero-length payloads (empty
            // inwit / zero-out spent) get an 8-byte zero pad so the next start
            // advances one stride. Decode treats trailing zeros as pad.
            if body_blob.len() == before {
                body_blob.resize(body_blob.len().saturating_add(8), 0);
            }
            cursor += (body_blob.len() - before) as u64;
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

    pub(crate) fn body_write_fd(&self) -> IoHandle {
        self.body.read_fd()
    }

    pub(crate) fn ensure_body_end(&self, end: u64) -> Result<(), StoreError> {
        self.body.ensure_capacity(end)
    }

    pub(crate) fn publish_body_hwm(&self, end: u64) -> Result<(), StoreError> {
        self.body.set_logical_len(end.max(self.body.logical_len()))
    }

    /// Idx + count publish after the body blob is already on disk (and HWM set).
    pub(crate) fn finish_prepared(&self, prep: PreparedAppend) -> Result<Vec<Fk>, StoreError> {
        self.idx.append_starts(prep.base_count, &prep.starts)?;
        let new_end = prep.start.saturating_add(prep.body_blob.len() as u64);
        let new_count = prep.base_count + prep.fks.len() as u64;
        self.publish_begin();
        self.published_body_end.store(new_end, Ordering::Relaxed);
        self.count.store(new_count, Ordering::Relaxed);
        self.publish_end();
        Ok(prep.fks)
    }

    /// Absolute start offset of record `fk` in body (for length-from-idx).
    pub(crate) fn record_start(&self, id: u64, count: u64) -> Result<u64, StoreError> {
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        self.idx.record_start(id)
    }

    #[inline]
    fn publish_begin(&self) {
        let prev = self.publish_seq.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(prev & 1, 0, "nested/concurrent publish_begin");
        std::sync::atomic::fence(Ordering::Release);
    }

    #[inline]
    fn publish_end(&self) {
        let prev = self.publish_seq.fetch_add(1, Ordering::Release);
        debug_assert_eq!(prev & 1, 1, "publish_end without begin");
    }

    /// Consistent `(count, published_body_end)` via seqlock (never torn pair).
    pub(crate) fn published_meta(&self) -> (u64, u64) {
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

    /// Exclusive end offset of record `id` given a consistent `(count, body_end)`.
    fn record_end_with(
        &self,
        id: u64,
        count: u64,
        published_body_end: u64,
    ) -> Result<u64, StoreError> {
        if id < count {
            self.record_start(id + 1, count)
        } else if id == count {
            Ok(published_body_end)
        } else {
            Err(StoreError::NotFound)
        }
    }

    /// Raw unframed payload for `fk`.
    pub fn get_raw(&self, fk: Fk) -> Result<Vec<u8>, StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let (count, body_end) = self.published_meta();
        let start = self.record_start(id, count)?;
        let end = self.record_end_with(id, count, body_end)?;
        if end < start {
            return Err(StoreError::Corrupt("var record end < start"));
        }
        let len = (end - start) as usize;
        let mut buf = vec![0u8; len];
        if len > 0 {
            self.read_body_bulk(start, &mut buf)?;
        }
        Ok(buf)
    }

    /// Read only the first `buf.len()` bytes at absolute body `(offset, len)`.
    pub fn read_prefix_at(
        &self,
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
        self.read_body_bulk(offset, &mut buf[..n])?;
        Ok(n)
    }

    /// Class A body pread via bulk_io.
    fn read_body_bulk(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
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

    fn read_body_pread(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
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
        self.idx.flush()?;
        Ok(())
    }

    /// HWM + MS_ASYNC (no fdatasync) — host-friendly process exit.
    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        self.idx.flush_async()?;
        Ok(())
    }

    /// Diagnostics: number of idx segment files.
    pub fn idx_segment_count(&self) -> usize {
        self.idx.segment_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::TableKind;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn put_batch_fd_append_roundtrip() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, AtomicOrdering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-var-fd-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        let fks = t
            .put_batch_encode(3, 64, |i, buf| {
                buf.extend_from_slice(&[i as u8 + 1; 16]);
            })
            .unwrap();
        assert_eq!(fks.len(), 3);
        assert_eq!(t.count(), 3);
        for (i, fk) in fks.iter().enumerate() {
            let body = t.get_raw(*fk).unwrap();
            // May include alignment pad as trailing zeros.
            assert!(body.len() >= 16);
            assert_eq!(&body[..16], &[i as u8 + 1; 16]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_batch_publish_visible_to_concurrent_readers() {
        let _stress = crate::file::TEST_MMAP_STRESS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, AtomicOrdering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-var-pub-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = Arc::new(VarTable::create(&dir, "tx", TableKind::TxOut).unwrap());

        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        {
            let t = Arc::clone(&t);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for batch in 0..200u8 {
                    let payload = vec![batch; 128];
                    t.put_batch_encode(4, 512, |_i, buf| {
                        buf.extend_from_slice(&payload);
                    })
                    .unwrap();
                }
            }));
        }

        for _ in 0..4 {
            let t = Arc::clone(&t);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..20_000 {
                    let c = t.count();
                    if c == 0 {
                        continue;
                    }
                    let (meta_c, meta_end) = t.published_meta();
                    if meta_c == 0 {
                        continue;
                    }
                    let fk = Fk(meta_c);
                    let raw = t.get_raw(fk).unwrap();
                    // 128-byte payloads are 8-aligned; last record has no pad
                    // until the next batch lands.
                    assert!(
                        raw.len() >= 128,
                        "torn publish meta_c={meta_c} meta_end={meta_end} count={c} len={}",
                        raw.len()
                    );
                    assert!(raw[..128].iter().all(|&b| b == raw[0]));
                }
            }));
        }

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                h.join().unwrap();
            }
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("concurrent var_table workers timed out (hang?)");
        assert_eq!(t.count(), 800);
        let raw = t.get_raw(Fk(t.count())).unwrap();
        assert!(raw.len() >= 128);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn published_meta_seqlock_matches_last_record_len() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-seqlock-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = Arc::new(VarTable::create(&dir, "tx", TableKind::TxOut).unwrap());
        let stop = Arc::new(AtomicU64::new(0));
        let t_w = Arc::clone(&t);
        let stop_w = Arc::clone(&stop);
        let writer = thread::spawn(move || {
            let mut batch = 0u8;
            while stop_w.load(AtomicOrdering::Acquire) == 0 {
                let payload = vec![batch; 64];
                t_w.put_batch_encode(8, 512, |_i, buf| {
                    buf.extend_from_slice(&payload);
                })
                .unwrap();
                batch = batch.wrapping_add(1);
            }
        });
        for _ in 0..50_000 {
            let (c, end) = t.published_meta();
            if c == 0 {
                continue;
            }
            let start = t.record_start(c, c).unwrap();
            assert!(end >= start + 64, "end={end} start={start} c={c}");
            // 64-byte aligned records: last length is exactly 64 until next pad.
            assert_eq!(
                end - start,
                64,
                "seqlock pair torn: c={c} end={end} start={start}"
            );
        }
        stop.store(1, AtomicOrdering::Release);
        writer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_range_interior_matches_adjacent_starts() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-interior-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        t.put_batch_encode(5, 256, |i, buf| {
            buf.extend_from_slice(&vec![i as u8; 8 + i * 3]);
        })
        .unwrap();
        assert_eq!(t.count(), 5);
        for id in 1..=5u64 {
            let (off, len) = t.record_range(Fk(id)).unwrap();
            let raw = t.get_raw(Fk(id)).unwrap();
            assert_eq!(raw.len() as u64, len, "id={id}");
            assert_eq!(raw[0], (id - 1) as u8);
            if id < 5 {
                let (next_off, _) = t.record_range(Fk(id + 1)).unwrap();
                assert_eq!(off + len, next_off, "interior abut id={id}");
            }
            assert_eq!(off % 8, 0, "id={id}");
        }
        let bulk = t.record_ranges(1, 5).unwrap();
        for (i, &(off, len)) in bulk.iter().enumerate() {
            assert_eq!(
                (off, len),
                t.record_range(Fk(1 + i as u64)).unwrap(),
                "bulk vs single id={}",
                1 + i
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Idx inversion is corrupt hard-fail — no live heal.
    #[test]
    fn record_range_idx_start_inversion_is_corrupt() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-inv-hard-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        t.put_batch_encode(6, 512, |i, buf| {
            buf.extend_from_slice(&vec![0xA0 + i as u8; 32 + i * 8]);
        })
        .unwrap();
        let idx_path = dir.join("tx.idx").join("000000");
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&idx_path)
            .unwrap();
        // slot 3 → fk 4: force start(4) << start(3)
        let slot_off = FILE_HEADER_LEN as u64 + 3 * 4;
        f.seek(SeekFrom::Start(slot_off)).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let err = t.record_range(Fk(3)).expect_err("inversion must hard-fail");
        assert!(format!("{err}").contains("end < start"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_range_batch_sorted_mmap_matches_serial() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-range-batch-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        t.put_batch_encode(20, 256, |i, buf| {
            buf.extend_from_slice(&vec![i as u8; 10 + (i % 5)]);
        })
        .unwrap();
        assert_eq!(t.count(), 20);

        let fks = vec![
            Fk(15),
            Fk(3),
            Fk(3),
            Fk(1),
            Fk::NULL,
            Fk(20),
            Fk(99),
            Fk(10),
            Fk(11),
            Fk(12),
        ];
        let batch = t.record_range_batch(&fks).unwrap();
        assert_eq!(batch.len(), fks.len());
        assert_eq!(batch[4], None);
        assert_eq!(batch[6], None);
        for (i, fk) in fks.iter().enumerate() {
            if batch[i].is_none() {
                continue;
            }
            let seq = t.record_range(*fk).unwrap();
            assert_eq!(batch[i], Some(seq), "fk={fk:?} i={i}");
        }
        assert_eq!(batch[1], batch[2]);
        let contig = t.record_ranges(10, 12).unwrap();
        assert_eq!(batch[7], Some(contig[0]));
        assert_eq!(batch[8], Some(contig[1]));
        assert_eq!(batch[9], Some(contig[2]));
        assert!(t.record_range_batch(&[]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_ranges_matches_record_range() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-ranges-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        for batch in 0..10u8 {
            let payload = vec![batch; 16 + batch as usize];
            t.put_batch_encode(3, 128, |_i, buf| {
                buf.extend_from_slice(&payload);
            })
            .unwrap();
        }
        assert_eq!(t.count(), 30);
        let bulk = t.record_ranges(5, 12).unwrap();
        assert_eq!(bulk.len(), 8);
        for (i, (off, len)) in bulk.iter().enumerate() {
            let (o, l) = t.record_range(Fk(5 + i as u64)).unwrap();
            assert_eq!((*off, *len), (o, l), "id={}", 5 + i);
        }
        let bulk_end = t.record_ranges(28, 30).unwrap();
        for (i, (off, len)) in bulk_end.iter().enumerate() {
            let (o, l) = t.record_range(Fk(28 + i as u64)).unwrap();
            assert_eq!((*off, *len), (o, l));
        }
        assert!(t.record_ranges(4, 3).unwrap().is_empty());
        assert_eq!(
            t.record_ranges(1, 1).unwrap()[0],
            t.record_range(Fk(1)).unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_segment_via_soft_span() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-multiseg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::tx_idx::test_with_soft_span_bytes(128, || {
            let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
            // Each record ~100 B → soft 128 forces new segment often.
            for i in 0..12u8 {
                t.put_batch_encode(1, 128, |_j, buf| {
                    buf.extend_from_slice(&vec![i; 100]);
                })
                .unwrap();
            }
            assert!(t.idx_segment_count() >= 2, "segs={}", t.idx_segment_count());
            for id in 1..=12u64 {
                let raw = t.get_raw(Fk(id)).unwrap();
                assert_eq!(raw[0], (id - 1) as u8);
                assert!(raw.len() >= 100);
            }
            drop(t);
            let t = VarTable::open(&dir, "tx", TableKind::TxOut).unwrap();
            assert_eq!(t.count(), 12);
            assert_eq!(t.get_raw(Fk(12)).unwrap()[0], 11);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn var_table_surface_helpers_and_errors() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-surface-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        assert_eq!(t.count(), 0);
        assert!(t.body_logical_len() >= FILE_HEADER_LEN as u64);
        t.advise_body_dont_need(0, 0);
        assert_eq!(t.put_batch_encode(0, 0, |_, _| {}).unwrap().len(), 0);
        t.reserve_append(1024, 8).unwrap();
        let fks = t
            .put_batch_encode(3, 64, |i, buf| {
                buf.extend_from_slice(&[i as u8; 16]);
            })
            .unwrap();
        assert_eq!(fks.len(), 3);
        assert_eq!(t.count(), 3);
        let raw = t.get_raw(fks[1]).unwrap();
        assert!(raw.len() >= 16);
        assert_eq!(raw[0], 1);
        let via = t
            .with_raw(fks[1], |b| {
                assert!(b.len() >= 16);
                Ok(b[0])
            })
            .unwrap();
        assert_eq!(via, 1);
        let (off, len) = t.record_range(fks[0]).unwrap();
        assert_eq!(off % 8, 0);
        let mut prefix = [0u8; 4];
        assert_eq!(t.read_prefix_at(off, len, &mut prefix).unwrap(), 4);
        assert_eq!(prefix, [0, 0, 0, 0]);
        assert_eq!(t.read_prefix_at(off, len, &mut []).unwrap(), 0);
        t.with_bytes_at(off, len, |b| {
            assert!(b.len() >= 16);
            Ok(())
        })
        .unwrap();
        t.with_bytes_at_pread(off, len, |b| {
            assert!(b.len() >= 16);
            Ok(())
        })
        .unwrap();
        t.write_body_abs(off, &[0xff]).unwrap();
        assert_eq!(t.get_raw(fks[0]).unwrap()[0], 0xff);
        assert!(matches!(
            t.record_range(Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(t.record_range(Fk(99)), Err(StoreError::NotFound)));
        assert!(matches!(t.record_ranges(0, 1), Err(StoreError::InvalidFk)));
        assert!(matches!(t.record_ranges(1, 99), Err(StoreError::NotFound)));
        assert!(matches!(t.get_raw(Fk::NULL), Err(StoreError::InvalidFk)));
        t.flush().unwrap();
        t.flush_async().unwrap();
        drop(t);
        let t = VarTable::open(&dir, "tx", TableKind::TxOut).unwrap();
        assert_eq!(t.count(), 3);
        assert!(t.get_raw(Fk(2)).unwrap().len() >= 16);
        // Corrupt meta magic.
        {
            let meta = dir.join("tx.idx").join("meta");
            std::fs::write(&meta, b"XXXX").unwrap();
        }
        assert!(matches!(
            VarTable::open(&dir, "tx", TableKind::TxOut),
            Err(StoreError::Corrupt(_)) | Err(StoreError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_bytes_at_into_overwrites_dirty_capacity() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-var-into-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        let fks = t
            .put_batch_encode(2, 64, |i, buf| {
                buf.extend_from_slice(&[(i as u8).saturating_add(0x5a); 16]);
            })
            .unwrap();
        let (off, len) = t.record_range(fks[1]).unwrap();
        let mut buf = vec![0xFFu8; (len as usize).saturating_add(32)];
        buf.clear();
        t.with_bytes_at_into(off, len, &mut buf, |b| {
            assert!(!b.is_empty());
            assert_ne!(b[0], 0xFF);
            assert_eq!(b[0], 0x5b);
            Ok(())
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_and_empty_helpers() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, AtomicOrdering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-var-trunc-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = VarTable::create(&dir, "tx", TableKind::TxOut).unwrap();
        let fks = t
            .put_batch_encode(5, 64, |i, buf| {
                buf.extend_from_slice(&[i as u8; 16]);
            })
            .unwrap();
        assert_eq!(fks.len(), 5);
        assert_eq!(t.count(), 5);
        // No-op truncate to same count.
        t.truncate_to_count(5).unwrap();
        assert_eq!(t.count(), 5);
        // Shorten.
        t.truncate_to_count(2).unwrap();
        assert_eq!(t.count(), 2);
        assert!(t.get_raw(Fk(1)).unwrap().len() >= 16);
        assert!(matches!(t.get_raw(Fk(3)), Err(StoreError::NotFound)));
        // Past count is corrupt.
        assert!(matches!(
            t.truncate_to_count(9),
            Err(StoreError::Corrupt(_))
        ));
        // Empty body helpers.
        t.advise_body_dont_need(0, 0);
        let _ = t.body_logical_len();
        assert!(t.idx_segment_count() >= 1);
        let ranges = t.record_range_batch(&[Fk(1), Fk(99)]).unwrap();
        assert!(ranges[0].is_some());
        assert!(ranges[1].is_none());
        t.with_raw(Fk(1), |b| {
            assert!(b.len() >= 16);
            Ok(())
        })
        .unwrap();
        // Empty batch.
        let empty = t.put_batch_encode(0, 0, |_, _| {}).unwrap();
        assert!(empty.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
