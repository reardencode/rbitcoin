//! Shared delta-locator helpers: 1024-create windows, stride-8, overflow rows.
//!
//! [`CreateLoc`](crate::create_loc::CreateLoc) packs txout strides + `n_out`.
//! [`DeltaLoc`] is the single-plane u16 sibling used by `seqsigwit.loc`.

use crate::error::StoreError;
use crate::file::{
    leading_header_bytes, write_synced_tmp_rename, GrowPolicy, TableFile, FILE_HEADER_LEN,
};
use rbitcoin_primitives::{Fk, TableKind, SCHEMA_VERSION};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Body offset unit (8-byte aligned record starts).
pub const IDX_STRIDE: u64 = 8;
/// Creates per loc window / checkpoint grain.
pub const LOC_WINDOW: u64 = 1024;

/// How many creates `off_len` checkpoint bytes can name.
///
/// A short checkpoint file keeps the last create that does not need a
/// missing window. A long or mis-sized file does not open.
pub(crate) fn checkpoint_fit(loc_count: u64, off_len: u64, off_slot: u64) -> Option<u64> {
    if off_slot == 0 || !off_len.is_multiple_of(off_slot) {
        return None;
    }
    let n_off = off_len / off_slot;
    let n_need = loc_count / LOC_WINDOW;
    if n_off > n_need {
        return None;
    }
    if n_off == n_need {
        return Some(loc_count);
    }
    Some(
        n_off
            .saturating_add(1)
            .saturating_mul(LOC_WINDOW)
            .saturating_sub(1),
    )
}

/// Count to keep when the next overflow row was written and its header was not.
///
/// That row sits at the ovf file's published end. A create slot is 16 bytes;
/// a seqsigwit slot is 12. It counts only when the loc slot at its fk is the
/// matching overflow marker. Anything else is spare capacity, not a row.
pub(crate) fn unresolved_ovf_cut(
    loc: &TableFile,
    ovf: &TableFile,
    count: u64,
    last_ovf_fk: u64,
    pair: bool,
) -> Result<Option<u64>, StoreError> {
    if last_ovf_fk >= count {
        return Ok(None);
    }
    let width = if pair { 16 } else { 12 };
    let mut row = [0u8; 16];
    if ovf.pread_all(ovf.logical_len(), &mut row[..width]).is_err() {
        return Ok(None);
    }
    let fk = u64::from_le_bytes(row[0..8].try_into().unwrap());
    if fk == 0 || fk <= last_ovf_fk || fk > count {
        return Ok(None);
    }
    let mut slot = [0u8; 2];
    loc.read_at(loc_file_off(fk, 2), &mut slot)?;
    if !ovf_row_matches_slot(&row, &slot, pair) {
        return Ok(None);
    }
    Ok(Some(fk.saturating_sub(1)))
}

fn ovf_row_matches_slot(row: &[u8], slot: &[u8; 2], pair: bool) -> bool {
    if pair {
        let strides = u32::from_le_bytes(row[8..12].try_into().unwrap());
        let n_out = u32::from_le_bytes(row[12..16].try_into().unwrap());
        if slot[0] != 0 && u32::from(slot[0]) != strides {
            return false;
        }
        if slot[1] != 0 && u32::from(slot[1]) != n_out {
            return false;
        }
        let strides_ovf = slot[0] == 0 && strides >= 256;
        let n_out_ovf = slot[1] == 0 && n_out >= 256;
        return strides_ovf || n_out_ovf;
    }
    if slot[0] != 0 || slot[1] != 0 {
        return false;
    }
    u32::from_le_bytes(row[8..12].try_into().unwrap()) >= 65536
}

#[doc(hidden)]
pub const CREATE_OVF_MISSING: &str = "invariant: create.loc overflow missing";
#[doc(hidden)]
pub const SEQSIGWIT_OVF_MISSING: &str = "invariant: seqsigwit.loc overflow missing";
pub const CREATE_OVF_SLOT: u64 = 16;
#[doc(hidden)]
pub const CREATE_OVF_SLOT_V22: u64 = 12;

#[inline]
pub fn loc_window(id: u64) -> u64 {
    (id - 1) / LOC_WINDOW
}

#[inline]
pub fn loc_within(id: u64) -> usize {
    ((id - 1) % LOC_WINDOW) as usize
}

#[inline]
pub fn loc_file_off(id: u64, slot: u64) -> u64 {
    FILE_HEADER_LEN as u64 + (id - 1) * slot
}

pub fn strides_from_aligned_len(len: u64) -> Result<u32, StoreError> {
    if len == 0 || !len.is_multiple_of(IDX_STRIDE) {
        return Err(StoreError::Corrupt("invariant: loc body length"));
    }
    let s = len / IDX_STRIDE;
    if s > u64::from(u32::MAX) {
        return Err(StoreError::Corrupt("invariant: loc strides"));
    }
    Ok(s as u32)
}

#[doc(hidden)]
pub fn ovf_lookup_pair(
    rows: &[(u64, u32, u32)],
    fk: u64,
    missing: &'static str,
) -> Result<(u32, u32), StoreError> {
    match rows.binary_search_by_key(&fk, |r| r.0) {
        Ok(i) => Ok((rows[i].1, rows[i].2)),
        Err(_) => Err(StoreError::Corrupt(missing)),
    }
}

#[doc(hidden)]
pub fn ovf_lookup_strides(
    rows: &[(u64, u32)],
    fk: u64,
    missing: &'static str,
) -> Result<u32, StoreError> {
    match rows.binary_search_by_key(&fk, |r| r.0) {
        Ok(i) => Ok(rows[i].1),
        Err(_) => Err(StoreError::Corrupt(missing)),
    }
}

#[doc(hidden)]
pub fn open_loc_file(path: &Path, kind: TableKind) -> Result<TableFile, StoreError> {
    let f = TableFile::open(path, kind)?;
    f.set_grow_policy(GrowPolicy::Tight1MiB);
    Ok(f)
}

#[doc(hidden)]
pub fn create_loc_file(path: &Path, kind: TableKind) -> Result<TableFile, StoreError> {
    let f = TableFile::create(path, kind)?;
    f.set_grow_policy(GrowPolicy::Tight1MiB);
    Ok(f)
}

/// One seqsigwit-loc append, encoded and not yet published.
pub(crate) struct StagedDelta {
    base: u64,
    n: u64,
    loc_off: u64,
    loc_bytes: Vec<u8>,
    ovf_at: u64,
    ovf_bytes: Vec<u8>,
    new_ovf: Vec<(u64, u32)>,
    off_at: u64,
    off_bytes: Vec<u8>,
    new_offs: Vec<(u64, u64)>,
}

/// Single-plane u16 delta locator (`seqsigwit.loc`: strides, `0` = overflow).
pub struct DeltaLoc {
    pub loc: TableFile,
    pub ovf: TableFile,
    pub off: TableFile,
    pub checkpoints: RwLock<Vec<u64>>,
    pub ovf_rows: RwLock<Vec<(u64, u32)>>,
    pub count: AtomicU64,
    pub missing: &'static str,
    /// Open dropped a locator prefix. Later truncates do not set this.
    pub(crate) cut_on_open: bool,
}

impl DeltaLoc {
    pub fn create(dir: &Path, stem: &str) -> Result<Self, StoreError> {
        let loc = create_loc_file(&dir.join(format!("{stem}.loc")), TableKind::DeltaLoc)?;
        let ovf = create_loc_file(&dir.join(format!("{stem}.loc.ovf")), TableKind::DeltaLoc)?;
        let off = create_loc_file(&dir.join(format!("{stem}.off")), TableKind::ArrayLink)?;
        Ok(Self {
            loc,
            ovf,
            off,
            checkpoints: RwLock::new(Vec::new()),
            ovf_rows: RwLock::new(Vec::new()),
            count: AtomicU64::new(0),
            missing: if stem == "seqsigwit" {
                SEQSIGWIT_OVF_MISSING
            } else {
                CREATE_OVF_MISSING
            },
            cut_on_open: false,
        })
    }

    pub fn open(dir: &Path, stem: &str) -> Result<Self, StoreError> {
        let loc = open_loc_file(&dir.join(format!("{stem}.loc")), TableKind::DeltaLoc)?;
        let ovf_path = dir.join(format!("{stem}.loc.ovf"));
        let ovf = if ovf_path.exists() {
            open_loc_file(&ovf_path, TableKind::DeltaLoc)?
        } else {
            create_loc_file(&ovf_path, TableKind::DeltaLoc)?
        };
        let off = open_loc_file(&dir.join(format!("{stem}.off")), TableKind::ArrayLink)?;
        let data = loc.data_len();
        if data % 2 != 0 {
            return Err(StoreError::Corrupt("invariant: loc size"));
        }
        let full = data / 2;
        let Some(count) = checkpoint_fit(full, off.data_len(), 8) else {
            return Err(StoreError::Corrupt("invariant: loc checkpoint count"));
        };
        let n_win = count / LOC_WINDOW;
        let mut checkpoints = vec![0u64; n_win as usize];
        if n_win > 0 {
            let mut bytes = vec![0u8; (n_win * 8) as usize];
            off.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
            for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                checkpoints[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        let ovf_rows = load_u16_ovf(&ovf)?;
        let mut opened = Self {
            loc,
            ovf,
            off,
            checkpoints: RwLock::new(checkpoints),
            ovf_rows: RwLock::new(ovf_rows),
            count: AtomicU64::new(full),
            missing: if stem == "seqsigwit" {
                SEQSIGWIT_OVF_MISSING
            } else {
                CREATE_OVF_MISSING
            },
            cut_on_open: false,
        };
        if count < full {
            opened.truncate_to_count(count)?;
            opened.cut_on_open = true;
        }
        // A row past the overflow header belongs to a create this file does not name.
        let last_ovf = opened
            .ovf_rows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last()
            .map(|row| row.0)
            .unwrap_or(0);
        if let Some(cut) =
            unresolved_ovf_cut(&opened.loc, &opened.ovf, opened.count(), last_ovf, false)?
        {
            opened.truncate_to_count(cut)?;
            opened.cut_on_open = true;
        }
        Ok(opened)
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count.load(Ordering::Acquire);
        if new_count > cur {
            return Err(StoreError::Corrupt("seqsigwit.loc truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let n_win = new_count / LOC_WINDOW;
        let kept = self
            .ovf_rows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.0 <= new_count)
            .count();
        // Kept overflow rows are a prefix.
        self.loc
            .set_logical_len(FILE_HEADER_LEN as u64 + new_count * 2)?;
        self.off
            .set_logical_len(FILE_HEADER_LEN as u64 + n_win * 8)?;
        self.ovf
            .set_logical_len(FILE_HEADER_LEN as u64 + kept as u64 * 12)?;
        self.checkpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .truncate(n_win as usize);
        self.ovf_rows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|r| r.0 <= new_count);
        self.count.store(new_count, Ordering::Release);
        Ok(())
    }

    /// Append `aligned_len` per record (8-aligned, ≥ 8). `starts[i]` is the body abs.
    pub fn append(&self, starts: &[u64], aligned_lens: &[u64]) -> Result<(), StoreError> {
        if starts.len() != aligned_lens.len() {
            return Err(StoreError::Corrupt("invariant: loc append length"));
        }
        if starts.is_empty() {
            return Ok(());
        }
        let staged = self.stage(starts, aligned_lens)?;
        self.write_staged(&staged)?;
        let _ = self.commit_staged(staged, true);
        Ok(())
    }

    pub(crate) fn stage(
        &self,
        starts: &[u64],
        aligned_lens: &[u64],
    ) -> Result<StagedDelta, StoreError> {
        if starts.len() != aligned_lens.len() {
            return Err(StoreError::Corrupt("invariant: loc append length"));
        }
        let base = self.count.load(Ordering::Acquire);
        let mut loc_bytes = Vec::with_capacity(starts.len() * 2);
        let mut ovf_bytes = Vec::new();
        let mut new_ovf: Vec<(u64, u32)> = Vec::new();
        let mut new_offs: Vec<(u64, u64)> = Vec::new();
        for (i, (&start, &len)) in starts.iter().zip(aligned_lens.iter()).enumerate() {
            let fk = base + 1 + i as u64;
            let strides = strides_from_aligned_len(len)?;
            if i + 1 < starts.len() && starts[i + 1] != start.saturating_add(len) {
                return Err(StoreError::Corrupt("invariant: loc starts"));
            }
            let (disk, ovf) = pack_u16_strides_seqsigwit(strides)?;
            loc_bytes.extend_from_slice(&disk.to_le_bytes());
            if let Some(true_s) = ovf {
                let mut row = [0u8; 12];
                row[0..8].copy_from_slice(&fk.to_le_bytes());
                row[8..12].copy_from_slice(&true_s.to_le_bytes());
                ovf_bytes.extend_from_slice(&row);
                new_ovf.push((fk, true_s));
            }
            if fk.is_multiple_of(LOC_WINDOW) {
                let next = start.saturating_add(len);
                new_offs.push((fk / LOC_WINDOW - 1, next));
            }
        }
        let off_at = new_offs
            .first()
            .map(|(w, _)| FILE_HEADER_LEN as u64 + w * 8)
            .unwrap_or(0);
        let mut off_bytes = Vec::with_capacity(new_offs.len() * 8);
        for &(_, abs) in &new_offs {
            off_bytes.extend_from_slice(&abs.to_le_bytes());
        }
        Ok(StagedDelta {
            base,
            n: starts.len() as u64,
            loc_off: loc_file_off(base + 1, 2),
            loc_bytes,
            ovf_at: FILE_HEADER_LEN as u64 + self.ovf.data_len(),
            ovf_bytes,
            new_ovf,
            off_at,
            off_bytes,
            new_offs,
        })
    }

    pub(crate) fn write_staged(&self, staged: &StagedDelta) -> Result<(), StoreError> {
        if let Some(&(fk, _)) = staged.new_ovf.first() {
            let rows = self.ovf_rows.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&(last, _)) = rows.last() {
                if fk <= last {
                    return Err(StoreError::Corrupt("invariant: loc ovf order"));
                }
            }
        }
        if let Some(&(w, _)) = staged.new_offs.first() {
            let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
            if w as usize != cps.len() {
                return Err(StoreError::Corrupt("invariant: loc checkpoint index"));
            }
        }
        self.loc
            .write_uncommitted(staged.loc_off, &staged.loc_bytes)?;
        if !staged.ovf_bytes.is_empty() {
            self.ovf
                .write_uncommitted(staged.ovf_at, &staged.ovf_bytes)?;
        }
        if !staged.off_bytes.is_empty() {
            self.off
                .write_uncommitted(staged.off_at, &staged.off_bytes)?;
        }
        Ok(())
    }

    /// Publish RAM for this append. Header pwrites run only while `durable`
    /// is still true, one per grown file. A file whose header is behind its
    /// RAM end is persisted first, including an overflow file this batch
    /// does not append. A failed header pwrite returns false and skips the
    /// rest. RAM still advances.
    #[must_use]
    pub(crate) fn commit_staged(&self, staged: StagedDelta, mut durable: bool) -> bool {
        if durable && !TableFile::catch_up_locator_headers(&self.loc, &self.ovf, &self.off) {
            durable = false;
        }
        let loc_end = staged.loc_off + staged.loc_bytes.len() as u64;
        durable = self.loc.publish_locator_end(loc_end, durable);
        if !staged.ovf_bytes.is_empty() {
            let ovf_end = staged.ovf_at + staged.ovf_bytes.len() as u64;
            durable = self.ovf.publish_locator_end(ovf_end, durable);
            self.ovf_rows
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(&staged.new_ovf);
        }
        if !staged.off_bytes.is_empty() {
            let off_end = staged.off_at + staged.off_bytes.len() as u64;
            durable = self.off.publish_locator_end(off_end, durable);
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            for &(w, abs) in &staged.new_offs {
                debug_assert_eq!(w as usize, cps.len());
                cps.push(abs);
            }
        }
        self.count.store(staged.base + staged.n, Ordering::Release);
        durable
    }

    pub fn range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        let mut plan = self.plan_range_batch(fks)?;
        for (off, buf) in plan.reads() {
            self.loc.read_at(off, buf)?;
        }
        self.finish_range_batch(&plan)
    }

    /// Window reads that resolve `fks` (offsets from RAM checkpoints; no IO).
    pub fn plan_range_batch(&self, fks: &[Fk]) -> Result<DeltaLocPlan, StoreError> {
        let count = self.count.load(Ordering::Acquire);
        let mut jobs: Vec<(usize, u64)> = Vec::new();
        for (i, fk) in fks.iter().enumerate() {
            let Some(id) = fk.get() else { continue };
            if id == 0 || id > count {
                continue;
            }
            jobs.push((i, id));
        }
        jobs.sort_unstable_by_key(|(_, id)| *id);
        let mut windows = Vec::new();
        let mut w_i = 0usize;
        while w_i < jobs.len() {
            let w = loc_window(jobs[w_i].1);
            let mut w_j = w_i + 1;
            while w_j < jobs.len() && loc_window(jobs[w_j].1) == w {
                w_j += 1;
            }
            let win_first = w * LOC_WINDOW + 1;
            let win_last = ((w + 1) * LOC_WINDOW).min(count);
            let n = (win_last - win_first + 1) as usize;
            let win_start = {
                let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
                if w == 0 {
                    FILE_HEADER_LEN as u64
                } else {
                    *cps.get((w - 1) as usize)
                        .ok_or(StoreError::Corrupt("invariant: loc checkpoint"))?
                }
            };
            windows.push(DeltaWin {
                job_lo: w_i,
                job_hi: w_j,
                win_first,
                n,
                win_start,
                buf: vec![0u8; n * 2],
            });
            w_i = w_j;
        }
        Ok(DeltaLocPlan {
            out_len: fks.len(),
            jobs,
            windows,
        })
    }

    /// Decode the window buffers of a filled [`DeltaLocPlan`].
    pub fn finish_range_batch(
        &self,
        plan: &DeltaLocPlan,
    ) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        let mut out = vec![None; plan.out_len];
        for win in &plan.windows {
            let (buf, n) = (&win.buf, win.n);
            let mut ps = vec![0u64; n + 1];
            ps[0] = win.win_start;
            let any_ovf =
                (0..n).any(|i| u16::from_le_bytes(buf[i * 2..i * 2 + 2].try_into().unwrap()) == 0);
            if any_ovf {
                let ovf = self.ovf_rows.read().unwrap_or_else(|e| e.into_inner());
                for i in 0..n {
                    let disk = u16::from_le_bytes(buf[i * 2..i * 2 + 2].try_into().unwrap());
                    let strides = if disk == 0 {
                        ovf_lookup_strides(&ovf, win.win_first + i as u64, self.missing)?
                    } else {
                        u32::from(disk)
                    };
                    ps[i + 1] = ps[i].saturating_add(u64::from(strides).saturating_mul(IDX_STRIDE));
                }
            } else {
                for i in 0..n {
                    let disk = u16::from_le_bytes(buf[i * 2..i * 2 + 2].try_into().unwrap());
                    ps[i + 1] = ps[i].saturating_add(u64::from(disk).saturating_mul(IDX_STRIDE));
                }
            }
            for &(orig, id) in &plan.jobs[win.job_lo..win.job_hi] {
                let within = loc_within(id);
                out[orig] = Some((ps[within], ps[within + 1] - ps[within]));
            }
        }
        Ok(out)
    }

    /// Locator handle and path for a machine's reads.
    pub fn loc_file(&self) -> (crate::io_handle::IoHandle, &Path) {
        (self.loc.read_fd(), self.loc.path())
    }
}

/// Window reads for one [`DeltaLoc::plan_range_batch`].
pub struct DeltaLocPlan {
    pub out_len: usize,
    pub jobs: Vec<(usize, u64)>,
    pub windows: Vec<DeltaWin>,
}

#[doc(hidden)]
pub struct DeltaWin {
    pub job_lo: usize,
    pub job_hi: usize,
    pub win_first: u64,
    pub n: usize,
    pub win_start: u64,
    pub buf: Vec<u8>,
}

impl DeltaLocPlan {
    /// `(file offset, buffer)` for each window read, in plan order.
    pub fn reads(&mut self) -> impl Iterator<Item = (u64, &mut Vec<u8>)> {
        self.windows
            .iter_mut()
            .map(|w| (loc_file_off(w.win_first, 2), &mut w.buf))
    }
}

#[doc(hidden)]
pub fn pack_u16_strides_seqsigwit(strides: u32) -> Result<(u16, Option<u32>), StoreError> {
    if strides == 0 {
        return Err(StoreError::Corrupt("invariant: loc strides"));
    }
    if strides >= 65536 {
        return Ok((0, Some(strides)));
    }
    Ok((strides as u16, None))
}

#[doc(hidden)]
pub fn load_u16_ovf(ovf: &TableFile) -> Result<Vec<(u64, u32)>, StoreError> {
    let data = ovf.data_len();
    if !data.is_multiple_of(12) {
        return Err(StoreError::Corrupt("invariant: loc ovf size"));
    }
    let n = (data / 12) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0u8; data as usize];
    ovf.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
    let mut rows = Vec::with_capacity(n);
    let mut prev = 0u64;
    for chunk in bytes.chunks_exact(12) {
        let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let strides = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        if fk == 0 || (prev != 0 && fk <= prev) {
            return Err(StoreError::Corrupt("invariant: loc ovf order"));
        }
        prev = fk;
        rows.push((fk, strides));
    }
    Ok(rows)
}

#[doc(hidden)]
pub type PackedCreateSlot = (u8, u8, Option<(u32, u32)>);

pub fn pack_create_pair(txout_strides: u32, n_out: u32) -> Result<PackedCreateSlot, StoreError> {
    if n_out == 0 {
        return Err(StoreError::Corrupt("invariant: create n_out"));
    }
    if txout_strides == 0 {
        return Err(StoreError::Corrupt("invariant: create txout strides"));
    }
    let s8 = if txout_strides >= 256 {
        0u8
    } else {
        txout_strides as u8
    };
    let n8 = if n_out >= 256 { 0u8 } else { n_out as u8 };
    let ovf = if s8 == 0 || n8 == 0 {
        Some((txout_strides, n_out))
    } else {
        None
    };
    Ok((s8, n8, ovf))
}

pub fn decode_create_pair(
    strides_b: u8,
    n_out_b: u8,
    fk: u64,
    ovf: &[(u64, u32, u32)],
) -> Result<(u32, u32), StoreError> {
    if strides_b == 0 || n_out_b == 0 {
        ovf_lookup_pair(ovf, fk, CREATE_OVF_MISSING)
    } else {
        Ok((u32::from(strides_b), u32::from(n_out_b)))
    }
}

pub fn encode_create_ovf_row(fk: u64, strides: u32, n_out: u32) -> [u8; 16] {
    let mut row = [0u8; CREATE_OVF_SLOT as usize];
    row[0..8].copy_from_slice(&fk.to_le_bytes());
    row[8..12].copy_from_slice(&strides.to_le_bytes());
    row[12..16].copy_from_slice(&n_out.to_le_bytes());
    row
}

pub fn load_create_ovf(ovf: &TableFile) -> Result<Vec<(u64, u32, u32)>, StoreError> {
    let data = ovf.data_len();
    if !data.is_multiple_of(CREATE_OVF_SLOT) {
        return Err(StoreError::Corrupt("invariant: create.loc ovf size"));
    }
    let n = (data / CREATE_OVF_SLOT) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0u8; data as usize];
    ovf.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
    let mut rows = Vec::with_capacity(n);
    let mut prev = 0u64;
    for chunk in bytes.chunks_exact(CREATE_OVF_SLOT as usize) {
        let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let strides = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let n_out = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        if fk == 0 || (prev != 0 && fk <= prev) {
            return Err(StoreError::Corrupt("invariant: create.loc ovf order"));
        }
        prev = fk;
        rows.push((fk, strides, n_out));
    }
    Ok(rows)
}

#[doc(hidden)]
pub fn create_ovf_header_ver(ovf: &TableFile) -> Result<u16, StoreError> {
    let mut hdr = [0u8; FILE_HEADER_LEN];
    ovf.pread_at(0, &mut hdr)?;
    Ok(u16::from_le_bytes([hdr[4], hdr[5]]))
}

/// Schema 22 `create.loc.ovf` is 12 B (`fk:u64` + two u16). Schema 23 is 16 B
/// (`fk:u64` + two u32). Rewrite on open so occupied 22 Class A can resume IBD.
pub fn migrate_create_ovf_v22_if_needed(path: &Path) -> Result<(), StoreError> {
    if !path.exists() {
        return Ok(());
    }
    let ovf = open_loc_file(path, TableKind::DeltaLoc)?;
    let ver = create_ovf_header_ver(&ovf)?;
    let data = ovf.data_len();
    if ver >= 23 {
        return Ok(());
    }
    if data == 0 {
        let hdr = leading_header_bytes(TableKind::DeltaLoc, FILE_HEADER_LEN as u64);
        ovf.write_at(0, &hdr)?;
        ovf.flush()?;
        return Ok(());
    }
    if data.is_multiple_of(CREATE_OVF_SLOT) && !data.is_multiple_of(CREATE_OVF_SLOT_V22) {
        let logical = FILE_HEADER_LEN as u64 + data;
        let hdr = leading_header_bytes(TableKind::DeltaLoc, logical);
        ovf.write_at(0, &hdr)?;
        ovf.flush()?;
        return Ok(());
    }
    if !data.is_multiple_of(CREATE_OVF_SLOT_V22) {
        return Err(StoreError::Corrupt("invariant: create.loc ovf size"));
    }
    let mut bytes = vec![0u8; data as usize];
    ovf.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
    drop(ovf);
    let n = (data / CREATE_OVF_SLOT_V22) as usize;
    let mut payload = Vec::with_capacity(n * CREATE_OVF_SLOT as usize);
    let mut prev = 0u64;
    for chunk in bytes.chunks_exact(CREATE_OVF_SLOT_V22 as usize) {
        let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let strides = u16::from_le_bytes(chunk[8..10].try_into().unwrap());
        let n_out = u16::from_le_bytes(chunk[10..12].try_into().unwrap());
        if fk == 0 || (prev != 0 && fk <= prev) {
            return Err(StoreError::Corrupt("invariant: create.loc ovf order"));
        }
        prev = fk;
        payload.extend_from_slice(&encode_create_ovf_row(
            fk,
            u32::from(strides),
            u32::from(n_out),
        ));
    }
    let logical = FILE_HEADER_LEN as u64 + payload.len() as u64;
    let mut blob = leading_header_bytes(TableKind::DeltaLoc, logical).to_vec();
    blob.extend_from_slice(&payload);
    write_synced_tmp_rename(path, &blob)?;
    rbitcoin_log::warn!(
        "store: rewriting create.loc.ovf 12 B rows to 16 B (schema {SCHEMA_VERSION})"
    );
    Ok(())
}

pub fn create_table_file(path: &Path, kind: TableKind) -> Result<TableFile, StoreError> {
    create_loc_file(path, kind)
}

pub fn open_table_file(path: &Path, kind: TableKind) -> Result<TableFile, StoreError> {
    open_loc_file(path, kind)
}
