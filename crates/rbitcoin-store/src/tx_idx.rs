//! Segmented Class A body index (`tx.idx.*`): u32 stride-8 offsets from a
//! per-segment `body_base`.
//!
//! Layout (schema 12+ after layout migration):
//! ```text
//! store/
//!   tx.idx/
//!     meta                   # segment map
//!     000000                 # dense u32 LE stride units
//!     000001
//!     …
//! ```
//!
//! Leftover flat `tx.idx.meta` + `tx.idx.NNNNNN` **refuse** on open (place files
//! under `{stem}.idx/` then restart; Class A bodies are kept).
//!
//! ```text
//! abs_start = body_base + (u32_le[i] as u64) * STRIDE
//! i = fk - first_fk   (fk 1-based; first_fk inclusive)
//! ```
//!
//! Hard span per segment: `2^32 * 8` ≈ 32 GiB. Soft rollover earlier (default
//! 16 GiB; override with `RBITCOIN_TX_IDX_SOFT_SPAN` bytes).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{schema_file_openable, TableKind, SCHEMA_VERSION, STORE_MAGIC};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Body offset unit for idx relatives (matches 8-byte-aligned record starts).
pub const IDX_STRIDE: u64 = 8;

/// Default soft body span before opening a new segment (~16 GiB).
pub const DEFAULT_SOFT_SPAN: u64 = 16 << 30;

/// Hard max: `u32::MAX` stride units × 8.
pub const HARD_SPAN: u64 = (u32::MAX as u64) * IDX_STRIDE;

/// Leftover flat `{stem}.idx.meta` beside or instead of `{stem}.idx/`.
pub const INDEX_REFUSE_FLAT_IDX: &str = "index refuses flat *.idx.meta; place files under store/{stem}.idx/ (meta + NNNNNN segments) then restart (Class A kept)";

/// Open-time refuse when published starts are not strictly monotone
/// (already-written double-append / clone window).
pub const IDX_OPEN_DOUBLE_APPEND: &str =
    "tx.idx starts not monotone (double-append class); wipe store/txout.idx \
     (or inwit.idx / spent.idx) or run scripts/repair-idx-double-append.py — \
     do not recreate tx.head";

/// Tail slots checked on open (page-grouped). Joins between segments always.
const OPEN_MONOTONE_TAIL: u64 = 8192;

/// OS page size for idx coalesced reads (Linux default; matches head probe pages).
pub const IDX_OS_PAGE: u64 = 4096;

const META_VERSION: u32 = 1;
/// magic4 + schema2 + kind2 + meta_ver4 + seg_count4 + reserved4
const META_HEADER_LEN: usize = 20;
/// first_fk8 + count8 + body_base8 + file_id4 + reserved4
const SEG_DESC_LEN: usize = 32;

#[derive(Clone)]
struct Segment {
    first_fk: u64,
    count: u64,
    body_base: u64,
    file_id: u32,
    file: Arc<TableFile>,
}

/// Multi-file u32 stride index for one var body stem (`tx`).
pub struct TxIdx {
    dir: PathBuf,
    stem: String,
    /// Published segment list (Arc swap under write lock on roll).
    segments: RwLock<Arc<Vec<Segment>>>,
    /// Next file_id to allocate (monotone).
    next_file_id: std::sync::atomic::AtomicU32,
    /// Soft body span before opening a new segment (captured at open).
    soft_span: u64,
}

/// Resolve idx soft-span: explicit open-time value, else env, else default.
pub fn resolve_soft_span(explicit: Option<u64>) -> u64 {
    if let Some(v) = explicit.filter(|&v| v >= IDX_STRIDE) {
        return v.min(HARD_SPAN);
    }
    if let Some(v) = std::env::var("RBITCOIN_TX_IDX_SOFT_SPAN")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&v: &u64| v >= IDX_STRIDE)
    {
        return v.min(HARD_SPAN);
    }
    DEFAULT_SOFT_SPAN.min(HARD_SPAN)
}

impl TxIdx {
    pub fn create(dir: &Path, stem: &str) -> Result<Self, StoreError> {
        Self::create_with_soft_span(dir, stem, resolve_soft_span(None))
    }

    pub fn create_with_soft_span(
        dir: &Path,
        stem: &str,
        soft_span: u64,
    ) -> Result<Self, StoreError> {
        let dir = dir.to_path_buf();
        let stem = stem.to_string();
        ensure_idx_layout(&dir, &stem)?;
        write_meta(&dir, &stem, &[])?;
        Ok(Self {
            dir,
            stem,
            segments: RwLock::new(Arc::new(Vec::new())),
            next_file_id: std::sync::atomic::AtomicU32::new(0),
            soft_span: resolve_soft_span(Some(soft_span)),
        })
    }

    pub fn open(dir: &Path, stem: &str) -> Result<Self, StoreError> {
        Self::open_with_soft_span(dir, stem, resolve_soft_span(None))
    }

    pub fn open_with_soft_span(dir: &Path, stem: &str, soft_span: u64) -> Result<Self, StoreError> {
        let dir = dir.to_path_buf();
        let stem = stem.to_string();
        ensure_idx_layout(&dir, &stem)?;
        let descs = read_meta(&dir, &stem)?;
        let mut segs = Vec::with_capacity(descs.len());
        let mut max_id = 0u32;
        for d in descs {
            let path = segment_path(&dir, &stem, d.file_id);
            // FdOnly: multi‑GiB idx segments use pread/pwrite (no full MAP_SHARED).
            let file = TableFile::open(&path, TableKind::ArrayLink)?;
            file.set_grow_tight(true);
            let slot_bytes = file.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
            if slot_bytes % 4 != 0 {
                return Err(StoreError::Corrupt("tx.idx segment size"));
            }
            let n_slots = slot_bytes / 4;
            if n_slots != d.count {
                return Err(StoreError::Corrupt("tx.idx segment count mismatch"));
            }
            max_id = max_id.max(d.file_id);
            segs.push(Segment {
                first_fk: d.first_fk,
                count: d.count,
                body_base: d.body_base,
                file_id: d.file_id,
                file: Arc::new(file),
            });
        }
        for w in segs.windows(2) {
            let a = &w[0];
            let b = &w[1];
            let a_end = a.first_fk.saturating_add(a.count);
            if b.first_fk != a_end {
                return Err(StoreError::Corrupt("tx.idx segment fk gap/overlap"));
            }
            if !a.body_base.is_multiple_of(IDX_STRIDE) || !b.body_base.is_multiple_of(IDX_STRIDE) {
                return Err(StoreError::Corrupt("tx.idx body_base unaligned"));
            }
        }
        check_published_starts_monotone(&segs)?;
        Ok(Self {
            dir,
            stem,
            segments: RwLock::new(Arc::new(segs)),
            next_file_id: std::sync::atomic::AtomicU32::new(max_id.saturating_add(1)),
            soft_span: resolve_soft_span(Some(soft_span)),
        })
    }

    /// Total published slots (= Class A count when in sync).
    pub fn slot_count(&self) -> u64 {
        let segs = self.segments_snapshot();
        segs.last()
            .map(|s| s.first_fk.saturating_add(s.count).saturating_sub(1))
            .unwrap_or(0)
    }

    /// Drop trailing slots so published count becomes `new_count` (1-based last fk).
    ///
    /// Used when Class A body/idx led an incomplete `txid.body` append (crash
    /// between idx publish and identity sidefile). Does not punch body bytes.
    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.slot_count();
        if new_count > cur {
            return Err(StoreError::Corrupt("tx.idx truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let mut segs = (*self.segments_snapshot()).clone();
        if new_count == 0 {
            segs.clear();
            {
                let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
                *guard = Arc::new(segs);
            }
            write_meta_from_segs(&self.dir, &self.stem, &[])?;
            return Ok(());
        }
        let mut kept: Vec<Segment> = Vec::new();
        for s in segs.drain(..) {
            let last = s.first_fk.saturating_add(s.count).saturating_sub(1);
            if last <= new_count {
                kept.push(s);
                continue;
            }
            if s.first_fk > new_count {
                break;
            }
            let keep_n = new_count.saturating_sub(s.first_fk).saturating_add(1);
            kept.push(Segment {
                first_fk: s.first_fk,
                count: keep_n,
                body_base: s.body_base,
                file_id: s.file_id,
                file: s.file,
            });
            break;
        }
        {
            let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
            *guard = Arc::new(kept);
        }
        let segs = self.segments_snapshot();
        write_meta_from_segs(&self.dir, &self.stem, &segs)?;
        Ok(())
    }

    fn segments_snapshot(&self) -> Arc<Vec<Segment>> {
        Arc::clone(&self.segments.read().unwrap_or_else(|e| e.into_inner()))
    }

    fn soft_span(&self) -> u64 {
        self.soft_span
    }

    /// Absolute body start for 1-based `id` (must be ≤ published count).
    pub fn record_start(&self, id: u64) -> Result<u64, StoreError> {
        if id == 0 {
            return Err(StoreError::NotFound);
        }
        let segs = self.segments_snapshot();
        let si = find_segment_index(&segs, id).ok_or(StoreError::NotFound)?;
        let seg = &segs[si];
        let i = id - seg.first_fk;
        if i >= seg.count {
            return Err(StoreError::NotFound);
        }
        read_start(seg, i)
    }

    /// `(offset, len)` for interior id (`id < count`); needs start(id+1).
    ///
    /// When both slots share one OS page, uses a **single** page pread.
    pub fn record_range_interior(&self, id: u64) -> Result<(u64, u64), StoreError> {
        if id == 0 {
            return Err(StoreError::NotFound);
        }
        let segs = self.segments_snapshot();
        let si = find_segment_index(&segs, id).ok_or(StoreError::NotFound)?;
        let seg = &segs[si];
        let i = id - seg.first_fk;
        if i + 1 >= seg.count {
            let start = self.record_start(id)?;
            let end = self.record_start(id + 1)?;
            if end < start {
                return Err(StoreError::Corrupt("var record end < start"));
            }
            return Ok((start, end - start));
        }
        let off0 = slot_file_off(i);
        let off1 = slot_file_off(i + 1);
        let page0 = align_down(off0, IDX_OS_PAGE);
        let page1 = align_down(off1, IDX_OS_PAGE);
        if page0 == page1 {
            let mut starts = Vec::with_capacity(2);
            read_starts_page_aligned(seg, i, i + 1, &mut starts)?;
            if starts.len() != 2 {
                return Err(StoreError::Corrupt("tx.idx dual extract"));
            }
            if starts[1] < starts[0] {
                return Err(StoreError::Corrupt("var record end < start"));
            }
            return Ok((starts[0], starts[1] - starts[0]));
        }
        let start = self.record_start(id)?;
        let end = self.record_start(id + 1)?;
        if end < start {
            return Err(StoreError::Corrupt("var record end < start"));
        }
        Ok((start, end - start))
    }

    /// Contiguous ranges `first..=last` (1-based). `body_end` for last published.
    pub fn record_ranges(
        &self,
        first: u64,
        last: u64,
        count: u64,
        body_end: u64,
    ) -> Result<Vec<(u64, u64)>, StoreError> {
        if first == 0 {
            return Err(StoreError::InvalidFk);
        }
        if last < first {
            return Ok(Vec::new());
        }
        if last > count {
            return Err(StoreError::NotFound);
        }
        let n = (last - first + 1) as usize;
        let need_next = last < count;
        let mut starts = Vec::with_capacity(n + usize::from(need_next));
        let end_id = if need_next { last + 1 } else { last };
        self.collect_starts(first, end_id, &mut starts)?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let start = starts[i];
            let end = if i + 1 < starts.len() {
                starts[i + 1]
            } else {
                body_end
            };
            if end < start {
                return Err(StoreError::Corrupt("var record end < start"));
            }
            out.push((start, end - start));
        }
        Ok(out)
    }

    fn collect_starts(&self, first: u64, last: u64, out: &mut Vec<u64>) -> Result<(), StoreError> {
        if last < first {
            return Ok(());
        }
        let segs = self.segments_snapshot();
        let mut id = first;
        while id <= last {
            let si = find_segment_index(&segs, id).ok_or(StoreError::NotFound)?;
            let seg = &segs[si];
            let seg_last_fk = seg.first_fk + seg.count - 1;
            let take_last = last.min(seg_last_fk);
            let i0 = id - seg.first_fk;
            let i1 = take_last - seg.first_fk;
            read_starts_page_aligned(seg, i0, i1, out)?;
            id = take_last + 1;
        }
        Ok(())
    }

    /// Absolute body starts for arbitrary 1-based ids (may be sparse).
    ///
    /// Coalesces to **one pread (or uring SQE) per OS page** touched across the
    /// batch, then extracts the requested slots.
    pub fn record_starts_batch(&self, ids: &[u64]) -> Result<Vec<Option<u64>>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let segs = self.segments_snapshot();
        let mut out: Vec<Option<u64>> = vec![None; ids.len()];
        let mut jobs: Vec<(usize, u32, u64, usize)> = Vec::new();
        for (oi, &id) in ids.iter().enumerate() {
            if id == 0 {
                continue;
            }
            let Some(si) = find_segment_index(&segs, id) else {
                continue;
            };
            let seg = &segs[si];
            let slot = id - seg.first_fk;
            if slot >= seg.count {
                continue;
            }
            jobs.push((oi, seg.file_id, slot, si));
        }
        if jobs.is_empty() {
            return Ok(out);
        }
        jobs.sort_unstable_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| slot_file_off(a.2).cmp(&slot_file_off(b.2)))
        });
        let mut page_buf = vec![0u8; IDX_OS_PAGE as usize];
        let mut p = 0usize;
        while p < jobs.len() {
            let file_id = jobs[p].1;
            let si = jobs[p].3;
            let page_off = align_down(slot_file_off(jobs[p].2), IDX_OS_PAGE);
            let mut q = p + 1;
            while q < jobs.len()
                && jobs[q].1 == file_id
                && align_down(slot_file_off(jobs[q].2), IDX_OS_PAGE) == page_off
            {
                q += 1;
            }
            let seg = &segs[si];
            let file_end = seg.file.logical_len();
            let want = (IDX_OS_PAGE as usize).min(file_end.saturating_sub(page_off) as usize);
            if want < 4 {
                p = q;
                continue;
            }
            page_buf[..want].fill(0);
            let rc =
                crate::bulk_io::pread_single(seg.file.read_fd(), page_off, &mut page_buf[..want]);
            if rc < 0 {
                return Err(StoreError::io(
                    seg.file.path(),
                    std::io::Error::from_raw_os_error(-rc),
                ));
            }
            if (rc as usize) < want {
                seg.file.read_at(page_off, &mut page_buf[..want])?;
            }
            for &(oi, _, slot, _) in &jobs[p..q] {
                let abs_off = slot_file_off(slot);
                let rel_off = (abs_off - page_off) as usize;
                if rel_off + 4 > want {
                    continue;
                }
                let rel = u32::from_le_bytes(page_buf[rel_off..rel_off + 4].try_into().unwrap());
                match decode_abs(seg, rel) {
                    Ok(a) => out[oi] = Some(a),
                    Err(_) => out[oi] = None,
                }
            }
            p = q;
        }
        Ok(out)
    }

    /// Like [`Self::record_starts_batch`] but uses uring/`pread_batch` when many
    /// distinct OS pages are needed (one SQE per unique page).
    pub fn record_starts_batch_bulk(
        &self,
        ids: &[u64],
        backend: crate::io_backend::ReadIoBackend,
    ) -> Result<Vec<Option<u64>>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // Small batches: serial page-coalesced path is enough.
        if ids.len() < 8 {
            return self.record_starts_batch(ids);
        }
        let segs = self.segments_snapshot();
        let mut out: Vec<Option<u64>> = vec![None; ids.len()];
        let mut jobs: Vec<(usize, u32, u64, usize)> = Vec::new();
        for (oi, &id) in ids.iter().enumerate() {
            if id == 0 {
                continue;
            }
            let Some(si) = find_segment_index(&segs, id) else {
                continue;
            };
            let seg = &segs[si];
            let slot = id - seg.first_fk;
            if slot >= seg.count {
                continue;
            }
            jobs.push((oi, seg.file_id, slot, si));
        }
        if jobs.is_empty() {
            return Ok(out);
        }
        jobs.sort_unstable_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| slot_file_off(a.2).cmp(&slot_file_off(b.2)))
        });

        let mut page_keys: Vec<(usize, u64)> = Vec::new();
        let mut page_job_ranges: Vec<(usize, usize)> = Vec::new();
        let mut p = 0usize;
        while p < jobs.len() {
            let si = jobs[p].3;
            let page_off = align_down(slot_file_off(jobs[p].2), IDX_OS_PAGE);
            let mut q = p + 1;
            while q < jobs.len()
                && jobs[q].3 == si
                && align_down(slot_file_off(jobs[q].2), IDX_OS_PAGE) == page_off
            {
                q += 1;
            }
            page_keys.push((si, page_off));
            page_job_ranges.push((p, q));
            p = q;
        }

        let mut pages: Vec<Vec<u8>> = page_keys
            .iter()
            .map(|(si, page_off)| {
                let seg = &segs[*si];
                let file_end = seg.file.logical_len();
                let want = (IDX_OS_PAGE as usize).min(file_end.saturating_sub(*page_off) as usize);
                vec![0u8; want]
            })
            .collect();

        {
            use crate::bulk_io::{self, ReadOp};
            // SAFETY: each pages[i] is a distinct allocation.
            let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(pages.len());
            for (i, (si, page_off)) in page_keys.iter().enumerate() {
                let fd = segs[*si].file.read_fd();
                let len = pages[i].len();
                let ptr = pages[i].as_mut_ptr();
                let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
                ops.push(ReadOp {
                    fd,
                    offset: *page_off,
                    buf: slice,
                    result: i32::MIN,
                });
            }
            bulk_io::pread_batch_backend(&mut ops, backend);
            for (i, op) in ops.iter().enumerate() {
                if op.result < 0 {
                    return Err(StoreError::io(
                        segs[page_keys[i].0].file.path(),
                        std::io::Error::from_raw_os_error(-op.result),
                    ));
                }
            }
        }

        for (page_i, &(jp, jq)) in page_job_ranges.iter().enumerate() {
            let (si, page_off) = page_keys[page_i];
            let seg = &segs[si];
            let want = pages[page_i].len();
            for &(oi, _, slot, _) in &jobs[jp..jq] {
                let abs_off = slot_file_off(slot);
                let rel_off = (abs_off - page_off) as usize;
                if rel_off + 4 > want {
                    continue;
                }
                let rel =
                    u32::from_le_bytes(pages[page_i][rel_off..rel_off + 4].try_into().unwrap());
                if let Ok(a) = decode_abs(seg, rel) {
                    out[oi] = Some(a);
                }
            }
        }
        Ok(out)
    }

    /// Append `n` absolute starts (must be 8-aligned, monotone, published after body).
    ///
    /// `base_count` is published count **before** this batch; starts[i] is for
    /// fk = base_count + 1 + i.
    ///
    /// **Double-append guard:** if `base_count > 0`, `starts[0]` must be strictly
    /// greater than `start(base_count)` (the last published create). Re-appending
    /// a prior starts vector after count advanced (mainnet 3330-slot clone) fails
    /// here instead of pasting idx onto already-owned body.
    pub fn append_starts(&self, base_count: u64, starts: &[u64]) -> Result<(), StoreError> {
        if starts.is_empty() {
            return Ok(());
        }
        for &s in starts {
            if !s.is_multiple_of(IDX_STRIDE) {
                return Err(StoreError::Corrupt("tx.idx start not stride-aligned"));
            }
        }
        for w in starts.windows(2) {
            if w[1] <= w[0] {
                return Err(StoreError::Corrupt(
                    "tx.idx starts not strictly monotone (refusing append)",
                ));
            }
        }
        if base_count > 0 {
            let last_pub = self.record_start(base_count)?;
            if starts[0] <= last_pub {
                return Err(StoreError::Corrupt(
                    "tx.idx starts[0] <= start(last published create) \
                     (refusing double-append of starts into already-indexed body)",
                ));
            }
        }
        let soft = self.soft_span();

        let mut i = 0usize;
        while i < starts.len() {
            self.ensure_tail_for(base_count + 1 + i as u64, starts[i], soft)?;
            let segs = self.segments_snapshot();
            let tail = segs
                .last()
                .ok_or(StoreError::Corrupt("tx.idx no segment"))?;
            let body_base = tail.body_base;
            let mut j = i;
            while j < starts.len() {
                let abs = starts[j];
                if abs < body_base {
                    return Err(StoreError::Corrupt("tx.idx start < body_base"));
                }
                let delta = abs - body_base;
                if !delta.is_multiple_of(IDX_STRIDE) {
                    return Err(StoreError::Corrupt("tx.idx start not on stride"));
                }
                let rel = delta / IDX_STRIDE;
                if rel > u32::MAX as u64 {
                    break;
                }
                // Soft span: allow first slot of segment always; else roll when
                // span from base would exceed soft (except we already placed some).
                if j > i && delta > soft {
                    break;
                }
                if j == i && delta > soft && tail.count > 0 {
                    // Should have rolled in ensure_tail; treat as hard need.
                    break;
                }
                j += 1;
            }
            if j == i {
                self.roll_segment(base_count + 1 + i as u64, starts[i])?;
                continue;
            }
            let n = j - i;
            let mut blob = Vec::with_capacity(n * 4);
            for &abs in &starts[i..j] {
                let rel = ((abs - body_base) / IDX_STRIDE) as u32;
                blob.extend_from_slice(&rel.to_le_bytes());
            }
            let slot_off = FILE_HEADER_LEN as u64 + tail.count * 4;
            let segs = self.segments_snapshot();
            let tail = segs.last().unwrap();
            tail.file.write_at_pwrite(slot_off, &blob)?;
            {
                let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
                let mut new_list = (**guard).clone();
                let t = new_list.last_mut().unwrap();
                t.count += n as u64;
                *guard = Arc::new(new_list);
            }
            i = j;
        }
        let segs = self.segments_snapshot();
        write_meta_from_segs(&self.dir, &self.stem, &segs)?;
        Ok(())
    }

    fn ensure_tail_for(
        &self,
        first_new_fk: u64,
        abs_start: u64,
        soft: u64,
    ) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        if segs.is_empty() {
            return self.roll_segment(first_new_fk, abs_start);
        }
        let tail = segs.last().unwrap();
        if abs_start < tail.body_base {
            return Err(StoreError::Corrupt("tx.idx start < body_base"));
        }
        let delta = abs_start - tail.body_base;
        if !delta.is_multiple_of(IDX_STRIDE) {
            return Err(StoreError::Corrupt("tx.idx start not on stride"));
        }
        let rel = delta / IDX_STRIDE;
        if rel > u32::MAX as u64 || (tail.count > 0 && delta > soft) {
            return self.roll_segment(first_new_fk, abs_start);
        }
        // Empty brand-new segment: body_base should match first write.
        if tail.count == 0 && tail.body_base != abs_start {
            // Reset empty segment base (only possible if we rolled early).
            return self.roll_segment(first_new_fk, abs_start);
        }
        Ok(())
    }

    fn roll_segment(&self, first_fk: u64, body_base: u64) -> Result<(), StoreError> {
        if !body_base.is_multiple_of(IDX_STRIDE) {
            return Err(StoreError::Corrupt("tx.idx body_base unaligned"));
        }
        let file_id = self
            .next_file_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = segment_path(&self.dir, &self.stem, file_id);
        let _ = std::fs::remove_file(&path);
        let file = TableFile::create(&path, TableKind::ArrayLink)?;
        file.set_grow_tight(true);
        let seg = Segment {
            first_fk,
            count: 0,
            body_base,
            file_id,
            file: Arc::new(file),
        };
        {
            let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
            let mut new_list = (**guard).clone();
            if let Some(last) = new_list.last() {
                if last.count == 0 {
                    new_list.pop();
                }
            }
            new_list.push(seg);
            *guard = Arc::new(new_list);
        }
        let segs = self.segments_snapshot();
        write_meta_from_segs(&self.dir, &self.stem, &segs)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        for s in segs.iter() {
            s.file.flush()?;
        }
        // Meta is rewritten on append; fsync via re-write.
        write_meta_from_segs(&self.dir, &self.stem, &segs)?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        for s in segs.iter() {
            s.file.flush_async()?;
        }
        Ok(())
    }

    /// Pre-grow capacity for `n_records` more slots on the tail segment.
    pub fn reserve_slots(&self, n_records: u64) -> Result<(), StoreError> {
        if n_records == 0 {
            return Ok(());
        }
        let segs = self.segments_snapshot();
        if let Some(tail) = segs.last() {
            let need = FILE_HEADER_LEN as u64 + (tail.count + n_records) * 4;
            tail.file.ensure_capacity(need)?;
        }
        Ok(())
    }

    /// Plan body_range idx IO without performing reads (plan head-resolve STAGE_IDX).
    ///
    /// `id` is 1-based Class A fk; `count`/`body_end` from [`crate::var_table::VarTable::published_meta`].
    /// Returns 1–2 OS-page preads plus a decode recipe so the caller can push
    /// SQEs on an owned [`crate::uring_session::UringSession`] (no nested bulk_io).
    pub(crate) fn plan_body_range(
        &self,
        id: u64,
        count: u64,
        body_end: u64,
    ) -> Result<BodyRangeIdxPlan, StoreError> {
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let segs = self.segments_snapshot();

        let (si0, slot0) = locate_slot(&segs, id)?;
        let page0 = plan_page(&segs[si0], slot0)?;

        if id == count {
            let start_rel = (slot_file_off(slot0) - page0.page_off) as u16;
            return Ok(BodyRangeIdxPlan {
                pages: vec![page0],
                decode: BodyRangeIdxDecode::Last {
                    start_rel,
                    start_base: segs[si0].body_base,
                    body_end,
                },
            });
        }

        let (si1, slot1) = locate_slot(&segs, id + 1)?;
        let start_rel = (slot_file_off(slot0) - page0.page_off) as u16;
        let base0 = segs[si0].body_base;
        let base1 = segs[si1].body_base;
        let same_page = si0 == si1
            && align_down(slot_file_off(slot0), IDX_OS_PAGE)
                == align_down(slot_file_off(slot1), IDX_OS_PAGE);

        if same_page {
            let end_rel = (slot_file_off(slot1) - page0.page_off) as u16;
            return Ok(BodyRangeIdxPlan {
                pages: vec![page0],
                decode: BodyRangeIdxDecode::Interior {
                    start_page: 0,
                    start_rel,
                    start_base: base0,
                    end_page: 0,
                    end_rel,
                    end_base: base1,
                },
            });
        }

        let page1 = plan_page(&segs[si1], slot1)?;
        let end_rel = (slot_file_off(slot1) - page1.page_off) as u16;
        Ok(BodyRangeIdxPlan {
            pages: vec![page0, page1],
            decode: BodyRangeIdxDecode::Interior {
                start_page: 0,
                start_rel,
                start_base: base0,
                end_page: 1,
                end_rel,
                end_base: base1,
            },
        })
    }
}

/// One OS-page pread for planned idx range decode (no IO yet).
#[derive(Clone, Debug)]
pub(crate) struct IdxPagePlan {
    pub fd: crate::io_handle::IoHandle,
    pub page_off: u64,
    pub want: usize,
}

/// How to decode `(body_off, body_len)` once page buffers are filled.
#[derive(Clone, Debug)]
pub(crate) enum BodyRangeIdxDecode {
    /// Interior id: starts of id and id+1 (possibly two pages).
    Interior {
        start_page: u8,
        start_rel: u16,
        start_base: u64,
        end_page: u8,
        end_rel: u16,
        end_base: u64,
    },
    /// Last published record: start(id) + published body_end.
    Last {
        start_rel: u16,
        start_base: u64,
        body_end: u64,
    },
}

/// Planned idx IO for one body_range (1–2 page preads + decode).
#[derive(Clone, Debug)]
pub(crate) struct BodyRangeIdxPlan {
    pub pages: Vec<IdxPagePlan>,
    pub decode: BodyRangeIdxDecode,
}

impl BodyRangeIdxPlan {
    /// Decode absolute `(offset, len)` from filled page buffers (same order as `pages`).
    pub(crate) fn decode_range(&self, page_bufs: &[&[u8]]) -> Result<(u64, u64), StoreError> {
        match &self.decode {
            BodyRangeIdxDecode::Last {
                start_rel,
                start_base,
                body_end,
            } => {
                let start = decode_slot_abs(page_bufs[0], *start_rel, *start_base)?;
                if *body_end < start {
                    return Err(StoreError::Corrupt("var record end < start"));
                }
                Ok((start, body_end - start))
            }
            BodyRangeIdxDecode::Interior {
                start_page,
                start_rel,
                start_base,
                end_page,
                end_rel,
                end_base,
            } => {
                let start =
                    decode_slot_abs(page_bufs[*start_page as usize], *start_rel, *start_base)?;
                let end = decode_slot_abs(page_bufs[*end_page as usize], *end_rel, *end_base)?;
                if end < start {
                    return Err(StoreError::Corrupt("var record end < start"));
                }
                Ok((start, end - start))
            }
        }
    }
}

fn locate_slot(segs: &[Segment], id: u64) -> Result<(usize, u64), StoreError> {
    let si = find_segment_index(segs, id).ok_or(StoreError::NotFound)?;
    let seg = &segs[si];
    let slot = id - seg.first_fk;
    if slot >= seg.count {
        return Err(StoreError::NotFound);
    }
    Ok((si, slot))
}

fn plan_page(seg: &Segment, slot: u64) -> Result<IdxPagePlan, StoreError> {
    let page_off = align_down(slot_file_off(slot), IDX_OS_PAGE);
    let file_end = seg.file.logical_len();
    let want = (IDX_OS_PAGE as usize).min(file_end.saturating_sub(page_off) as usize);
    if want < 4 {
        return Err(StoreError::Corrupt(
            "tx.idx page too short for body_range plan",
        ));
    }
    Ok(IdxPagePlan {
        fd: seg.file.read_fd(),
        page_off,
        want,
    })
}

#[inline]
fn decode_slot_abs(page: &[u8], rel: u16, body_base: u64) -> Result<u64, StoreError> {
    let rel_off = rel as usize;
    if rel_off + 4 > page.len() {
        return Err(StoreError::Corrupt("tx.idx STAGE_IDX slot OOB"));
    }
    let rel_u = u32::from_le_bytes(page[rel_off..rel_off + 4].try_into().unwrap());
    body_base
        .checked_add(
            (rel_u as u64)
                .checked_mul(IDX_STRIDE)
                .ok_or(StoreError::Corrupt("tx.idx stride overflow"))?,
        )
        .ok_or(StoreError::Corrupt("tx.idx abs overflow"))
}

/// Segment joins + last [`OPEN_MONOTONE_TAIL`] starts must be strictly increasing.
fn check_published_starts_monotone(segs: &[Segment]) -> Result<(), StoreError> {
    for w in segs.windows(2) {
        let a = &w[0];
        let b = &w[1];
        if a.count == 0 || b.count == 0 {
            continue;
        }
        let last_a = read_start(a, a.count - 1)?;
        let first_b = read_start(b, 0)?;
        if first_b <= last_a {
            return Err(StoreError::Corrupt(IDX_OPEN_DOUBLE_APPEND));
        }
    }
    let total: u64 = segs.iter().map(|s| s.count).sum();
    if total < 2 {
        return Ok(());
    }
    let want = total.min(OPEN_MONOTONE_TAIL);
    let mut starts = Vec::with_capacity(want as usize);
    let mut remain = want;
    for seg in segs.iter().rev() {
        if remain == 0 {
            break;
        }
        let take = remain.min(seg.count);
        if take == 0 {
            continue;
        }
        let i0 = seg.count - take;
        let i1 = seg.count - 1;
        let mut chunk = Vec::with_capacity(take as usize);
        read_starts_page_aligned(seg, i0, i1, &mut chunk)?;
        remain = remain.saturating_sub(chunk.len() as u64);
        starts.extend(chunk.into_iter().rev());
    }
    starts.reverse();
    for w in starts.windows(2) {
        if w[1] <= w[0] {
            return Err(StoreError::Corrupt(IDX_OPEN_DOUBLE_APPEND));
        }
    }
    Ok(())
}

#[inline]
fn slot_file_off(slot_i: u64) -> u64 {
    FILE_HEADER_LEN as u64 + slot_i * 4
}

#[inline]
fn align_down(off: u64, page: u64) -> u64 {
    off / page * page
}

#[inline]
fn decode_abs(seg: &Segment, rel: u32) -> Result<u64, StoreError> {
    seg.body_base
        .checked_add(
            (rel as u64)
                .checked_mul(IDX_STRIDE)
                .ok_or(StoreError::Corrupt("tx.idx stride overflow"))?,
        )
        .ok_or(StoreError::Corrupt("tx.idx abs overflow"))
}

fn read_start(seg: &Segment, i: u64) -> Result<u64, StoreError> {
    // Single slot: still go through page-aligned read (one OS page) so cold
    // probes share the page cache with neighbors.
    let mut out = Vec::with_capacity(1);
    read_starts_page_aligned(seg, i, i, &mut out)?;
    out.into_iter()
        .next()
        .ok_or(StoreError::Corrupt("tx.idx empty page extract"))
}

/// Read slots `[i0..=i1]` via OS-page-aligned preads (one read per page).
fn read_starts_page_aligned(
    seg: &Segment,
    i0: u64,
    i1: u64,
    out: &mut Vec<u64>,
) -> Result<(), StoreError> {
    if i1 < i0 {
        return Ok(());
    }
    let file_end = seg.file.logical_len();
    let mut slot = i0;
    while slot <= i1 {
        let page_off = align_down(slot_file_off(slot), IDX_OS_PAGE);
        let page_end = page_off + IDX_OS_PAGE;
        let want = (IDX_OS_PAGE as usize).min(file_end.saturating_sub(page_off) as usize);
        if want < 4 {
            break;
        }
        let mut page = vec![0u8; want];
        let rc = crate::bulk_io::pread_single(seg.file.read_fd(), page_off, &mut page);
        if rc < 0 {
            return Err(StoreError::io(
                seg.file.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) < want {
            seg.file.read_at(page_off, &mut page)?;
        }
        while slot <= i1 {
            let off = slot_file_off(slot);
            if off >= page_end {
                break;
            }
            if off < page_off {
                slot += 1;
                continue;
            }
            let rel_off = (off - page_off) as usize;
            if rel_off + 4 > want {
                break;
            }
            let rel = u32::from_le_bytes(page[rel_off..rel_off + 4].try_into().unwrap());
            out.push(decode_abs(seg, rel)?);
            slot += 1;
        }
    }
    Ok(())
}

fn find_segment_index(segs: &[Segment], id: u64) -> Option<usize> {
    if segs.is_empty() || id == 0 {
        return None;
    }
    let mut lo = 0usize;
    let mut hi = segs.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let s = &segs[mid];
        let end = s.first_fk + s.count; // exclusive
        if id < s.first_fk {
            hi = mid;
        } else if id >= end {
            lo = mid + 1;
        } else {
            return Some(mid);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct SegDesc {
    first_fk: u64,
    count: u64,
    body_base: u64,
    file_id: u32,
}

/// Directory holding `{stem}.idx` segments + meta (`store/tx.idx/…`).
#[inline]
fn idx_root(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.idx"))
}

fn segment_path(dir: &Path, stem: &str, file_id: u32) -> PathBuf {
    idx_root(dir, stem).join(format!("{file_id:06}"))
}

fn meta_path(dir: &Path, stem: &str) -> PathBuf {
    idx_root(dir, stem).join("meta")
}

fn flat_meta_path(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.idx.meta"))
}

/// Ensure `tx.idx/` exists. Leftover flat `{stem}.idx.meta` refuses.
fn ensure_idx_layout(dir: &Path, stem: &str) -> Result<(), StoreError> {
    let root = idx_root(dir, stem);
    let new_meta = meta_path(dir, stem);
    let flat_meta = flat_meta_path(dir, stem);
    if flat_meta.is_file() {
        return Err(StoreError::Corrupt(INDEX_REFUSE_FLAT_IDX));
    }
    if new_meta.is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(&root).map_err(|e| StoreError::io(&root, e))?;
    Ok(())
}

fn write_meta(dir: &Path, stem: &str, descs: &[SegDesc]) -> Result<(), StoreError> {
    let path = meta_path(dir, stem);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
    }
    let mut buf = Vec::with_capacity(META_HEADER_LEN + descs.len() * SEG_DESC_LEN);
    buf.extend_from_slice(&STORE_MAGIC);
    buf.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&TableKind::ArrayLink.as_u16().to_le_bytes());
    buf.extend_from_slice(&META_VERSION.to_le_bytes());
    buf.extend_from_slice(&(descs.len() as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for d in descs {
        buf.extend_from_slice(&d.first_fk.to_le_bytes());
        buf.extend_from_slice(&d.count.to_le_bytes());
        buf.extend_from_slice(&d.body_base.to_le_bytes());
        buf.extend_from_slice(&d.file_id.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    // Atomic replace: write sibling temp then rename over `meta` (never unlink first).
    // Use an explicit sibling name so we never collide with a segment file named `tmp`.
    let tmp = path.with_file_name("meta.tmp");
    std::fs::write(&tmp, &buf).map_err(|e| StoreError::io(&tmp, e))?;
    // Best-effort durability of temp before rename (crash mid-rename keeps old meta).
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_data();
    }
    std::fs::rename(&tmp, &path).map_err(|e| StoreError::io(&path, e))?;
    Ok(())
}

fn write_meta_from_segs(dir: &Path, stem: &str, segs: &[Segment]) -> Result<(), StoreError> {
    let descs: Vec<SegDesc> = segs
        .iter()
        .map(|s| SegDesc {
            first_fk: s.first_fk,
            count: s.count,
            body_base: s.body_base,
            file_id: s.file_id,
        })
        .collect();
    write_meta(dir, stem, &descs)
}

fn read_meta(dir: &Path, stem: &str) -> Result<Vec<SegDesc>, StoreError> {
    let path = meta_path(dir, stem);
    // One retry on ENOENT: concurrent `write_meta` renames `meta.tmp` → `meta`
    // and a reader can briefly observe a missing path on some FS/schedulers.
    let buf = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::thread::sleep(std::time::Duration::from_millis(1));
            std::fs::read(&path).map_err(|e2| StoreError::io(&path, e2))?
        }
        Err(e) => return Err(StoreError::io(&path, e)),
    };
    read_meta_buf(&buf)
}

fn read_meta_buf(buf: &[u8]) -> Result<Vec<SegDesc>, StoreError> {
    if buf.len() < META_HEADER_LEN {
        return Err(StoreError::Corrupt("tx.idx.meta short"));
    }
    if buf[0..4] != STORE_MAGIC {
        return Err(StoreError::Corrupt("tx.idx.meta magic"));
    }
    let ver = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if !schema_file_openable(ver) {
        return Err(StoreError::Corrupt("tx.idx.meta schema"));
    }
    let meta_ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if meta_ver != META_VERSION {
        return Err(StoreError::Corrupt("tx.idx.meta version"));
    }
    let n = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let need = META_HEADER_LEN + n * SEG_DESC_LEN;
    if buf.len() < need {
        return Err(StoreError::Corrupt("tx.idx.meta truncated"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = META_HEADER_LEN + i * SEG_DESC_LEN;
        let first_fk = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        let count = u64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap());
        let body_base = u64::from_le_bytes(buf[o + 16..o + 24].try_into().unwrap());
        let file_id = u32::from_le_bytes(buf[o + 24..o + 28].try_into().unwrap());
        if first_fk == 0 && count > 0 {
            return Err(StoreError::Corrupt("tx.idx.meta first_fk"));
        }
        if !body_base.is_multiple_of(IDX_STRIDE) {
            return Err(StoreError::Corrupt("tx.idx.meta body_base"));
        }
        out.push(SegDesc {
            first_fk,
            count,
            body_base,
            file_id,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_span_is_per_instance() {
        let dir_a = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-span-a-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir_b = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-span-b-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let a = TxIdx::create_with_soft_span(&dir_a, "tx", 48).unwrap();
        let b = TxIdx::create(&dir_b, "tx").unwrap();
        assert_eq!(a.soft_span(), 48);
        assert_ne!(
            b.soft_span(),
            48,
            "sibling instance must keep default span (got {})",
            b.soft_span()
        );
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// Re-appending the same absolute starts after count advanced must fail
    /// (mainnet double-write of 3330 idx slots).
    #[test]
    fn append_starts_rejects_double_append_into_prior_body() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-dbl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let idx = TxIdx::create(&dir, "tx").unwrap();
        let s1 = [16u64, 24, 32, 40];
        idx.append_starts(0, &s1).unwrap();
        // Same starts again at advanced base — clone pattern.
        let err = idx.append_starts(4, &s1).expect_err("must refuse");
        assert!(
            format!("{err}").contains("double-append")
                || format!("{err}").contains("last published"),
            "got {err}"
        );
        // Legitimate next batch is past last start.
        idx.append_starts(4, &[48u64, 56]).unwrap();
        assert_eq!(idx.slot_count(), 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Already-written clone window must fail `TxIdx::open` (append guard is write-only).
    #[test]
    fn open_refuses_cloned_starts_window() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-open-clone-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let idx = TxIdx::create(&dir, "txout").unwrap();
        idx.append_starts(0, &[16u64, 24, 32, 40]).unwrap();
        idx.append_starts(4, &[48u64, 56, 64, 72]).unwrap();
        drop(idx);

        let seg = segment_path(&dir, "txout", 0);
        let mut raw = std::fs::read(&seg).unwrap();
        // Copy first 4 u32 slots over the last 4 (clone the prior window).
        let hdr = FILE_HEADER_LEN;
        let src = raw[hdr..hdr + 16].to_vec();
        raw[hdr + 16..hdr + 32].copy_from_slice(&src);
        std::fs::write(&seg, &raw).unwrap();

        let err = match TxIdx::open(&dir, "txout") {
            Ok(_) => panic!("clone must refuse on open"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("double-append") || msg.contains("repair-idx-double-append"),
            "operator one-liner missing: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_segment_stride_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let idx = TxIdx::create_with_soft_span(&dir, "tx", 64).unwrap();
            // Three batches that force rolls (span > 64).
            let s1 = [16u64, 24, 32, 40];
            idx.append_starts(0, &s1).unwrap();
            assert_eq!(idx.slot_count(), 4);
            let s2 = [16 + 128, 16 + 128 + 16]; // far → new segment
            idx.append_starts(4, &s2).unwrap();
            assert!(idx.segments_snapshot().len() >= 2);
            assert_eq!(idx.record_start(1).unwrap(), 16);
            assert_eq!(idx.record_start(5).unwrap(), 16 + 128);
            let (off, len) = idx.record_range_interior(4).unwrap();
            assert_eq!(off, 40);
            assert_eq!(len, (16 + 128) - 40);
            // Reopen.
            drop(idx);
            let idx = TxIdx::open_with_soft_span(&dir, "tx", 64).unwrap();
            assert_eq!(idx.slot_count(), 6);
            assert_eq!(idx.record_start(6).unwrap(), 16 + 128 + 16);
            let ranges = idx.record_ranges(1, 6, 6, 16 + 128 + 16 + 8).unwrap();
            assert_eq!(ranges.len(), 6);
            assert_eq!(ranges[0].0, 16);
        }
        // New layout lives under tx.idx/
        assert!(dir.join("tx.idx").join("meta").is_file());
        assert!(!dir.join("tx.idx.meta").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_flat_idx_layout_on_open() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-txidx-migrate-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let idx = TxIdx::create_with_soft_span(&dir, "tx", 64).unwrap();
            idx.append_starts(0, &[16u64, 24, 32, 40]).unwrap();
            idx.append_starts(4, &[16 + 128, 16 + 128 + 16]).unwrap();
            idx.flush().unwrap();
        }
        // Flatten layout back to legacy paths (simulate old datadir).
        let root = dir.join("tx.idx");
        assert!(root.is_dir());
        let meta_new = root.join("meta");
        let meta_flat = dir.join("tx.idx.meta");
        std::fs::rename(&meta_new, &meta_flat).unwrap();
        for ent in std::fs::read_dir(&root).unwrap().flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if s.chars().all(|c| c.is_ascii_digit()) {
                let dst = dir.join(format!("tx.idx.{s}"));
                std::fs::rename(ent.path(), &dst).unwrap();
            }
        }
        let _ = std::fs::remove_dir_all(&root);
        assert!(meta_flat.is_file());
        assert!(!dir.join("tx.idx").join("meta").exists());

        match TxIdx::open(&dir, "tx") {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, INDEX_REFUSE_FLAT_IDX);
                assert!(m.contains("Class A kept"), "{m}");
            }
            Ok(_) => panic!("flat idx must refuse TxIdx::open"),
            Err(other) => panic!("expected INDEX_REFUSE_FLAT_IDX, got {other}"),
        }
        assert!(meta_flat.is_file(), "flat files left for operator to move");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
