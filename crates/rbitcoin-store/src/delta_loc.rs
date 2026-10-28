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

/// Locator files and RAM rows before one `append`. The count store is last,
/// so a later disk-full write has already published overflow rows that
/// `truncate_to_count` will not see.
struct DeltaSideSnap {
    loc_len: u64,
    ovf_len: u64,
    off_len: u64,
    ovf_n: usize,
    cp_n: usize,
}

impl DeltaSideSnap {
    fn capture(loc: &DeltaLoc) -> Self {
        Self {
            loc_len: loc.loc.logical_len(),
            ovf_len: loc.ovf.logical_len(),
            off_len: loc.off.logical_len(),
            ovf_n: loc.ovf_rows.read().unwrap_or_else(|e| e.into_inner()).len(),
            cp_n: loc
                .checkpoints
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
        }
    }

    fn restore(self, loc: &DeltaLoc) -> Result<(), StoreError> {
        if loc.loc.logical_len() != self.loc_len {
            loc.loc.set_logical_len(self.loc_len)?;
        }
        if loc.ovf.logical_len() != self.ovf_len {
            loc.ovf.set_logical_len(self.ovf_len)?;
        }
        if loc.off.logical_len() != self.off_len {
            loc.off.set_logical_len(self.off_len)?;
        }
        loc.ovf_rows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .truncate(self.ovf_n);
        loc.checkpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .truncate(self.cp_n);
        Ok(())
    }
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
        let count = data / 2;
        let expect_off = (count / LOC_WINDOW) * 8;
        if off.data_len() != expect_off {
            return Err(StoreError::Corrupt("invariant: loc checkpoint count"));
        }
        let mut checkpoints = vec![0u64; (count / LOC_WINDOW) as usize];
        if !checkpoints.is_empty() {
            let mut bytes = vec![0u8; expect_off as usize];
            off.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
            for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                checkpoints[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        let ovf_rows = load_u16_ovf(&ovf)?;
        Ok(Self {
            loc,
            ovf,
            off,
            checkpoints: RwLock::new(checkpoints),
            ovf_rows: RwLock::new(ovf_rows),
            count: AtomicU64::new(count),
            missing: if stem == "seqsigwit" {
                SEQSIGWIT_OVF_MISSING
            } else {
                CREATE_OVF_MISSING
            },
        })
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
        // Kept overflow rows are a prefix. A rewrite of that prefix is the
        // write that used to fail after the locator file was already short.
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
        let snap = DeltaSideSnap::capture(self);
        let outcome = self.append_writes(starts, aligned_lens);
        if outcome.is_err() {
            snap.restore(self)?;
        }
        outcome
    }

    fn append_writes(&self, starts: &[u64], aligned_lens: &[u64]) -> Result<(), StoreError> {
        if starts.len() != aligned_lens.len() {
            return Err(StoreError::Corrupt("invariant: loc append length"));
        }
        if starts.is_empty() {
            return Ok(());
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
        let loc_off = loc_file_off(base + 1, 2);
        self.loc.write_at(loc_off, &loc_bytes)?;
        if !ovf_bytes.is_empty() {
            let ovf_at = FILE_HEADER_LEN as u64 + self.ovf.data_len();
            self.ovf.write_at(ovf_at, &ovf_bytes)?;
            let mut rows = self.ovf_rows.write().unwrap_or_else(|e| e.into_inner());
            if let Some(&(last, _)) = rows.last() {
                if new_ovf[0].0 <= last {
                    return Err(StoreError::Corrupt("invariant: loc ovf order"));
                }
            }
            rows.extend_from_slice(&new_ovf);
        }
        if !new_offs.is_empty() {
            {
                let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
                if new_offs[0].0 as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: loc checkpoint index"));
                }
            }
            let mut blob = Vec::with_capacity(new_offs.len() * 8);
            for &(_, abs) in &new_offs {
                blob.extend_from_slice(&abs.to_le_bytes());
            }
            let off_at = FILE_HEADER_LEN as u64 + (new_offs[0].0 * 8);
            self.off.write_at(off_at, &blob)?;
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            for &(w, abs) in &new_offs {
                if w as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: loc checkpoint index"));
                }
                cps.push(abs);
            }
        }
        self.count
            .store(base + starts.len() as u64, Ordering::Release);
        Ok(())
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
