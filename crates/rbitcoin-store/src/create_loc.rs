//! Packed create locator: 2 B/create (`txout_strides:u8`, `n_out:u8`).
//!
//! Checkpoints in `create.off` (RAM). Loc and overflow stay FdOnly.

use crate::bulk_io::ReadOp;
use crate::delta_loc::{
    create_table_file, decode_create_pair, encode_create_ovf_row, load_create_ovf, loc_file_off,
    loc_window, loc_within, migrate_create_ovf_v22_if_needed, open_table_file, pack_create_pair,
    strides_from_aligned_len, CREATE_OVF_SLOT, IDX_STRIDE, LOC_WINDOW,
};
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::IoCtx;
use rbitcoin_primitives::{deinterleave_pairs_u8x8, inclusive_u8x8_times_8, Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

const SLOT: u64 = 2;
const OFF_SLOT: u64 = 16;

/// Slots to read and prefix-sum in `[win_first, win_last]` for the highest needed fk.
#[inline]
pub(crate) fn loc_window_need_n(max_id: u64, win_first: u64, win_last: u64) -> usize {
    if max_id < win_first || win_last < win_first {
        return 0;
    }
    (max_id.min(win_last) - win_first + 1) as usize
}

/// One create's txout range, spent range, and true output count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateLocPair {
    pub txout: (u64, u64),
    pub spent: (u64, u64),
    pub n_out: u32,
}

/// Per-create append input (8-aligned body starts and txout length).
#[derive(Clone, Copy, Debug)]
pub struct CreateLocAppend {
    pub txout_start: u64,
    pub txout_len: u64,
    pub spent_start: u64,
    pub n_out: u32,
}

pub struct CreateLoc {
    loc: TableFile,
    ovf: TableFile,
    off: TableFile,
    checkpoints: RwLock<Vec<(u64, u64)>>,
    ovf_rows: RwLock<Vec<(u64, u32, u32)>>,
    count: AtomicU64,
}

impl CreateLoc {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            loc: create_table_file(&dir.join("create.loc"), TableKind::DeltaLoc)?,
            ovf: create_table_file(&dir.join("create.loc.ovf"), TableKind::DeltaLoc)?,
            off: create_table_file(&dir.join("create.off"), TableKind::ArrayLink)?,
            checkpoints: RwLock::new(Vec::new()),
            ovf_rows: RwLock::new(Vec::new()),
            count: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let loc = open_table_file(&dir.join("create.loc"), TableKind::DeltaLoc)?;
        let ovf_path = dir.join("create.loc.ovf");
        if ovf_path.exists() {
            migrate_create_ovf_v22_if_needed(&ovf_path)?;
        }
        let ovf = if ovf_path.exists() {
            open_table_file(&ovf_path, TableKind::DeltaLoc)?
        } else {
            create_table_file(&ovf_path, TableKind::DeltaLoc)?
        };
        let off = open_table_file(&dir.join("create.off"), TableKind::ArrayLink)?;
        let data = loc.data_len();
        if data % SLOT != 0 {
            return Err(StoreError::Corrupt("invariant: create.loc size"));
        }
        let count = data / SLOT;
        let n_win = count / LOC_WINDOW;
        if off.data_len() != n_win * OFF_SLOT {
            return Err(StoreError::Corrupt("invariant: create.off size"));
        }
        let mut checkpoints = vec![(0u64, 0u64); n_win as usize];
        if n_win > 0 {
            let mut bytes = vec![0u8; (n_win * OFF_SLOT) as usize];
            off.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
            for (i, chunk) in bytes.chunks_exact(OFF_SLOT as usize).enumerate() {
                let txout = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                let spent = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
                checkpoints[i] = (txout, spent);
            }
        }
        let ovf_rows = load_create_ovf(&ovf)?;
        Ok(Self {
            loc,
            ovf,
            off,
            checkpoints: RwLock::new(checkpoints),
            ovf_rows: RwLock::new(ovf_rows),
            count: AtomicU64::new(count),
        })
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count.load(Ordering::Acquire);
        if new_count > cur {
            return Err(StoreError::Corrupt("create.loc truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let loc_end = FILE_HEADER_LEN as u64 + new_count * SLOT;
        self.loc.set_logical_len(loc_end)?;
        let n_win = new_count / LOC_WINDOW;
        self.off
            .set_logical_len(FILE_HEADER_LEN as u64 + n_win * OFF_SLOT)?;
        {
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            cps.truncate(n_win as usize);
        }
        {
            let mut rows = self.ovf_rows.write().unwrap_or_else(|e| e.into_inner());
            rows.retain(|r| r.0 <= new_count);
            let mut blob = Vec::with_capacity(rows.len() * CREATE_OVF_SLOT as usize);
            for &(fk, st, n_out) in rows.iter() {
                blob.extend_from_slice(&encode_create_ovf_row(fk, st, n_out));
            }
            self.ovf
                .set_logical_len(FILE_HEADER_LEN as u64 + blob.len() as u64)?;
            if !blob.is_empty() {
                self.ovf.write_at(FILE_HEADER_LEN as u64, &blob)?;
            }
        }
        self.count.store(new_count, Ordering::Release);
        Ok(())
    }

    pub fn append(&self, recs: &[CreateLocAppend]) -> Result<(), StoreError> {
        if recs.is_empty() {
            return Ok(());
        }
        let base = self.count.load(Ordering::Acquire);
        let mut loc_bytes = Vec::with_capacity(recs.len() * 2);
        let mut ovf_bytes = Vec::new();
        let mut new_ovf: Vec<(u64, u32, u32)> = Vec::new();
        let mut new_offs: Vec<(u64, u64, u64)> = Vec::new();
        for (i, rec) in recs.iter().enumerate() {
            let fk = base + 1 + i as u64;
            if rec.n_out == 0 {
                return Err(StoreError::Corrupt("invariant: create n_out"));
            }
            let strides = strides_from_aligned_len(rec.txout_len)?;
            let spent_len = u64::from(rec.n_out).saturating_mul(IDX_STRIDE);
            if i + 1 < recs.len() {
                if recs[i + 1].txout_start != rec.txout_start.saturating_add(rec.txout_len) {
                    return Err(StoreError::Corrupt("invariant: create.loc txout starts"));
                }
                if recs[i + 1].spent_start != rec.spent_start.saturating_add(spent_len) {
                    return Err(StoreError::Corrupt("invariant: create.loc spent starts"));
                }
            }
            let (s8, n8, ovf) = pack_create_pair(strides, rec.n_out)?;
            loc_bytes.push(s8);
            loc_bytes.push(n8);
            if let Some((os, on)) = ovf {
                ovf_bytes.extend_from_slice(&encode_create_ovf_row(fk, os, on));
                new_ovf.push((fk, os, on));
            }
            if fk.is_multiple_of(LOC_WINDOW) {
                new_offs.push((
                    fk / LOC_WINDOW - 1,
                    rec.txout_start.saturating_add(rec.txout_len),
                    rec.spent_start.saturating_add(spent_len),
                ));
            }
        }
        self.loc
            .write_at(loc_file_off(base + 1, SLOT), &loc_bytes)?;
        if !ovf_bytes.is_empty() {
            let ovf_at = FILE_HEADER_LEN as u64 + self.ovf.data_len();
            self.ovf.write_at(ovf_at, &ovf_bytes)?;
            let mut rows = self.ovf_rows.write().unwrap_or_else(|e| e.into_inner());
            if let Some(&(last, _, _)) = rows.last() {
                if new_ovf[0].0 <= last {
                    return Err(StoreError::Corrupt("invariant: create.loc ovf order"));
                }
            }
            rows.extend_from_slice(&new_ovf);
        }
        if !new_offs.is_empty() {
            {
                let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
                if new_offs[0].0 as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: create.off index"));
                }
            }
            let mut blob = Vec::with_capacity(new_offs.len() * OFF_SLOT as usize);
            for &(_, txout_abs, spent_abs) in &new_offs {
                blob.extend_from_slice(&txout_abs.to_le_bytes());
                blob.extend_from_slice(&spent_abs.to_le_bytes());
            }
            let off_at = FILE_HEADER_LEN as u64 + new_offs[0].0 * OFF_SLOT;
            self.off.write_at(off_at, &blob)?;
            let mut cps = self.checkpoints.write().unwrap_or_else(|e| e.into_inner());
            for &(w, txout_abs, spent_abs) in &new_offs {
                if w as usize != cps.len() {
                    return Err(StoreError::Corrupt("invariant: create.off index"));
                }
                cps.push((txout_abs, spent_abs));
            }
        }
        self.count
            .store(base + recs.len() as u64, Ordering::Release);
        Ok(())
    }

    pub fn range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<CreateLocPair>>, StoreError> {
        self.range_batch_ctx(fks, &mut IoCtx::none())
    }

    /// Same as [`Self::range_batch`] on a caller-held completion session.
    ///
    /// Poisoned held session fails closed (no libc-complete). Live unpoisoned
    /// batch fail libc-completes shorts and does not consume recover credit.
    /// Head resolve does **not** pass its probe ring here — it uses
    /// [`Self::range_batch`] after TLS drops.
    pub(crate) fn range_batch_ctx(
        &self,
        fks: &[Fk],
        ctx: &mut IoCtx<'_>,
    ) -> Result<Vec<Option<CreateLocPair>>, StoreError> {
        let mut plan = self.plan_range_batch(fks)?;
        self.pread_windows(ctx, &mut plan)?;
        self.finish_range_batch(&plan)
    }

    /// Window reads that resolve `fks` (offsets from RAM checkpoints; no IO).
    ///
    /// A completion machine pushes [`LocPlan::reads`] on its own session,
    /// then calls [`Self::finish_range_batch`].
    pub(crate) fn plan_range_batch(&self, fks: &[Fk]) -> Result<LocPlan, StoreError> {
        // Pair `count` with one published-end load. Window preads compare
        // that integer and do not load `logical_len` again.
        let count = self.count.load(Ordering::Acquire);
        let published = self.loc.logical_len();
        let mut jobs: Vec<(usize, u64)> = Vec::new();
        for (i, fk) in fks.iter().enumerate() {
            let Some(id) = fk.get() else { continue };
            if id == 0 || id > count {
                continue;
            }
            jobs.push((i, id));
        }
        jobs.sort_unstable_by_key(|(_, id)| *id);
        let mut windows: Vec<LocWinRead> = Vec::new();
        let mut w_i = 0usize;
        while w_i < jobs.len() {
            let w = loc_window(jobs[w_i].1);
            let mut w_j = w_i + 1;
            while w_j < jobs.len() && loc_window(jobs[w_j].1) == w {
                w_j += 1;
            }
            let win_first = w * LOC_WINDOW + 1;
            let win_last = ((w + 1) * LOC_WINDOW).min(count);
            let max_id = jobs[w_j - 1].1;
            let n = loc_window_need_n(max_id, win_first, win_last);
            if n == 0 {
                w_i = w_j;
                continue;
            }
            let (tx0, sp0) = {
                let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
                if w == 0 {
                    (FILE_HEADER_LEN as u64, FILE_HEADER_LEN as u64)
                } else {
                    *cps.get((w - 1) as usize)
                        .ok_or(StoreError::Corrupt("invariant: create.off checkpoint"))?
                }
            };
            windows.push(LocWinRead {
                job_lo: w_i,
                job_hi: w_j,
                win_first,
                n,
                tx0,
                sp0,
                buf: vec![0u8; n * 2],
            });
            w_i = w_j;
        }
        Ok(LocPlan {
            out_len: fks.len(),
            jobs,
            windows,
            published,
        })
    }

    /// Decode the window buffers of a filled [`LocPlan`].
    pub(crate) fn finish_range_batch(
        &self,
        plan: &LocPlan,
    ) -> Result<Vec<Option<CreateLocPair>>, StoreError> {
        let mut out = vec![None; plan.out_len];
        for win in &plan.windows {
            self.extract_win_pairs(win, &plan.jobs, &mut out)?;
        }
        Ok(out)
    }

    /// `create.loc` handle and path for a machine's reads.
    pub(crate) fn loc_file(&self) -> (crate::io_handle::IoHandle, &Path) {
        (self.loc.read_fd(), self.loc.path())
    }

    fn extract_win_pairs(
        &self,
        win: &LocWinRead,
        jobs: &[(usize, u64)],
        out: &mut [Option<CreateLocPair>],
    ) -> Result<(), StoreError> {
        let win_jobs = &jobs[win.job_lo..win.job_hi];
        match extract_pairs_no_ovf(win, win_jobs, out) {
            Ok(()) => Ok(()),
            Err(ExtractFail::NeedOvf) => {
                let ovf = self.ovf_rows.read().unwrap_or_else(|e| e.into_inner());
                extract_pairs_ovf(win, &ovf, win_jobs, out)
            }
        }
    }

    fn pread_windows(&self, ctx: &mut IoCtx<'_>, plan: &mut LocPlan) -> Result<(), StoreError> {
        let windows = &mut plan.windows;
        if windows.is_empty() {
            return Ok(());
        }
        // The end `plan_range_batch` paired with `count`. Not a fresh load.
        let published = plan.published;
        if published == 0 {
            return Err(StoreError::Corrupt(
                "invariant: body read missing published end",
            ));
        }
        for w in windows.iter() {
            let end = loc_file_off(w.win_first, SLOT).saturating_add(w.buf.len() as u64);
            if end > published {
                return Err(StoreError::Corrupt(
                    "invariant: body read past published end",
                ));
            }
        }
        let fd = self.loc.read_fd();
        let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(windows.len());
        for w in windows.iter_mut() {
            let off = loc_file_off(w.win_first, SLOT);
            let ptr = w.buf.as_mut_ptr();
            let len = w.buf.len();
            // SAFETY: each window owns a distinct `buf` until this function returns.
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            ops.push(ReadOp {
                fd,
                offset: off,
                buf: slice,
                result: i32::MIN,
            });
        }
        let held = ctx.session().is_some();
        if held {
            match crate::bulk_io::pread_batch_on_ctx(ctx, &mut ops) {
                Ok(true) => {}
                Ok(false) => {
                    drop(ops);
                    for w in windows.iter_mut() {
                        self.loc
                            .pread_at(loc_file_off(w.win_first, SLOT), &mut w.buf)?;
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        } else {
            crate::bulk_io::pread_batch(&mut ops);
        }
        let mut shorts = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            if op.result < 0 || (op.result as usize) != windows[i].buf.len() {
                shorts.push(i);
            }
        }
        drop(ops);
        for i in shorts {
            self.loc.pread_at(
                loc_file_off(windows[i].win_first, SLOT),
                &mut windows[i].buf,
            )?;
        }
        Ok(())
    }
}

/// Window reads for one [`CreateLoc::plan_range_batch`].
pub(crate) struct LocPlan {
    out_len: usize,
    jobs: Vec<(usize, u64)>,
    windows: Vec<LocWinRead>,
    /// `create.loc` published end paired with the count this plan resolved.
    published: u64,
}

impl LocPlan {
    /// `(file offset, buffer)` for each window read, in plan order.
    pub(crate) fn reads(&mut self) -> impl Iterator<Item = (u64, &mut Vec<u8>)> {
        self.windows
            .iter_mut()
            .map(|w| (loc_file_off(w.win_first, SLOT), &mut w.buf))
    }
}

struct LocWinRead {
    job_lo: usize,
    job_hi: usize,
    win_first: u64,
    n: usize,
    tx0: u64,
    sp0: u64,
    buf: Vec<u8>,
}

enum ExtractFail {
    NeedOvf,
}

fn emit_pair(
    orig: usize,
    tx: u64,
    tlen: u64,
    sp: u64,
    slen: u64,
    n_out: u32,
    out: &mut [Option<CreateLocPair>],
) {
    out[orig] = Some(CreateLocPair {
        txout: (tx, tlen),
        spent: (sp, slen),
        n_out,
    });
}

fn extract_pairs_ovf(
    win: &LocWinRead,
    ovf: &[(u64, u32, u32)],
    jobs: &[(usize, u64)],
    out: &mut [Option<CreateLocPair>],
) -> Result<(), StoreError> {
    let buf = &win.buf;
    let n = win.n;
    let win_first = win.win_first;
    let last_fk = win_first.saturating_add(n as u64).saturating_sub(1);
    let lo = ovf.partition_point(|&(fk, _, _)| fk < win_first);
    let hi = ovf.partition_point(|&(fk, _, _)| fk <= last_fk);
    let win_ovf = &ovf[lo..hi];
    let mut tx = win.tx0;
    let mut sp = win.sp0;
    let mut j = 0usize;
    for i in 0..n {
        let fk = win_first + i as u64;
        let (st, n_out) = decode_create_pair(buf[i * 2], buf[i * 2 + 1], fk, win_ovf)?;
        let tlen = u64::from(st).saturating_mul(IDX_STRIDE);
        let slen = u64::from(n_out).saturating_mul(IDX_STRIDE);
        while j < jobs.len() && loc_within(jobs[j].1) == i {
            emit_pair(jobs[j].0, tx, tlen, sp, slen, n_out, out);
            j += 1;
        }
        tx = tx.saturating_add(tlen);
        sp = sp.saturating_add(slen);
    }
    Ok(())
}

fn extract_pairs_no_ovf(
    win: &LocWinRead,
    jobs: &[(usize, u64)],
    out: &mut [Option<CreateLocPair>],
) -> Result<(), ExtractFail> {
    let buf = &win.buf;
    let n = win.n;
    let mut tx = win.tx0;
    let mut sp = win.sp0;
    let mut i = 0usize;
    let mut j = 0usize;
    while i + 8 <= n {
        let base = i * 2;
        let mut chunk = [0u8; 16];
        chunk.copy_from_slice(&buf[base..base + 16]);
        let (st, no, has_zero) = deinterleave_pairs_u8x8(chunk);
        if has_zero {
            return Err(ExtractFail::NeedOvf);
        }
        let (tx_inc, sp_inc) = inclusive_u8x8_times_8(&st, &no);
        while j < jobs.len() {
            let within = loc_within(jobs[j].1);
            if within < i {
                j += 1;
                continue;
            }
            if within >= i + 8 {
                break;
            }
            let k = within - i;
            let tprev = if k == 0 { 0 } else { u64::from(tx_inc[k - 1]) };
            let sprev = if k == 0 { 0 } else { u64::from(sp_inc[k - 1]) };
            let tlen = u64::from(tx_inc[k]).saturating_sub(tprev);
            let slen = u64::from(sp_inc[k]).saturating_sub(sprev);
            emit_pair(
                jobs[j].0,
                tx.saturating_add(tprev),
                tlen,
                sp.saturating_add(sprev),
                slen,
                u32::from(no[k]),
                out,
            );
            j += 1;
        }
        tx = tx.saturating_add(u64::from(tx_inc[7]));
        sp = sp.saturating_add(u64::from(sp_inc[7]));
        i += 8;
    }
    while i < n {
        let st = buf[i * 2];
        let no = buf[i * 2 + 1];
        if st == 0 || no == 0 {
            return Err(ExtractFail::NeedOvf);
        }
        let tlen = u64::from(st).saturating_mul(IDX_STRIDE);
        let slen = u64::from(no).saturating_mul(IDX_STRIDE);
        while j < jobs.len() && loc_within(jobs[j].1) == i {
            emit_pair(jobs[j].0, tx, tlen, sp, slen, u32::from(no), out);
            j += 1;
        }
        tx = tx.saturating_add(tlen);
        sp = sp.saturating_add(slen);
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FILE_HEADER_LEN;
    use crate::testutil::TempDir;

    fn rec(txout_start: u64, txout_len: u64, spent_start: u64, n_out: u32) -> CreateLocAppend {
        CreateLocAppend {
            txout_start,
            txout_len,
            spent_start,
            n_out,
        }
    }

    fn chain(n_out: &[u32], txout_len: &[u64]) -> Vec<CreateLocAppend> {
        assert_eq!(n_out.len(), txout_len.len());
        let mut tx = FILE_HEADER_LEN as u64;
        let mut sp = FILE_HEADER_LEN as u64;
        let mut out = Vec::with_capacity(n_out.len());
        for (&n, &tlen) in n_out.iter().zip(txout_len.iter()) {
            out.push(rec(tx, tlen, sp, n));
            tx += tlen;
            sp += u64::from(n) * IDX_STRIDE;
        }
        out
    }

    fn ovf_data_len(dir: &Path) -> u64 {
        let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
        let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        logical - FILE_HEADER_LEN as u64
    }

    fn write_legacy_create_ovf_v22(dir: &Path, rows: &[(u64, u16, u16)]) {
        use rbitcoin_primitives::{TableKind, STORE_MAGIC};
        let mut payload = Vec::new();
        for &(fk, st, n) in rows {
            payload.extend_from_slice(&fk.to_le_bytes());
            payload.extend_from_slice(&st.to_le_bytes());
            payload.extend_from_slice(&n.to_le_bytes());
        }
        let logical = FILE_HEADER_LEN as u64 + payload.len() as u64;
        let mut blob = vec![0u8; FILE_HEADER_LEN];
        blob[0..4].copy_from_slice(&STORE_MAGIC);
        blob[4..6].copy_from_slice(&22u16.to_le_bytes());
        blob[6..8].copy_from_slice(&TableKind::DeltaLoc.as_u16().to_le_bytes());
        blob[8..16].copy_from_slice(&logical.to_le_bytes());
        blob.extend_from_slice(&payload);
        std::fs::write(dir.join("create.loc.ovf"), blob).unwrap();
    }

    #[test]
    fn create_loc_read_past_published_end_is_corrupt() {
        let dir = TempDir::labeled("create-loc-pub").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1], &[16])).unwrap();
        loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
        match loc.range_batch(&[Fk(1)]) {
            Err(StoreError::Corrupt(msg)) => assert!(msg.contains("published"), "{msg}"),
            Ok(v) => panic!("read past published end returned {v:?}"),
            Err(other) => panic!("{other}"),
        }
    }

    /// The window pread compares the end `plan_range_batch` paired with
    /// `count`. A later publish must not change that integer.
    #[test]
    fn create_loc_window_read_uses_the_planned_published_end() {
        let dir = TempDir::labeled("create-loc-snap").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1], &[16])).unwrap();
        let full = loc.loc.logical_len();
        let mut plan = loc.plan_range_batch(&[Fk(1)]).unwrap();
        loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
        loc.pread_windows(&mut IoCtx::none(), &mut plan)
            .expect("in-snapshot window stays readable after a shrink");
        let got = loc.finish_range_batch(&plan).unwrap();
        assert_eq!(
            got[0],
            Some(CreateLocPair {
                txout: (FILE_HEADER_LEN as u64, 16),
                spent: (FILE_HEADER_LEN as u64, 8),
                n_out: 1,
            })
        );

        loc.loc.set_logical_len(FILE_HEADER_LEN as u64).unwrap();
        let mut short = loc.plan_range_batch(&[Fk(1)]).unwrap();
        loc.loc.set_logical_len(full).unwrap();
        match loc.pread_windows(&mut IoCtx::none(), &mut short) {
            Err(StoreError::Corrupt(msg)) => assert!(msg.contains("published"), "{msg}"),
            Ok(()) => panic!("a later grow widened the planned published end"),
            Err(other) => panic!("{other}"),
        }
    }

    #[test]
    fn create_loc_n_out_1_and_3() {
        let dir = TempDir::labeled("create-loc-13").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1, 3], &[16, 32])).unwrap();
        let got = loc.range_batch(&[Fk(1), Fk(2)]).unwrap();
        assert_eq!(
            got[0],
            Some(CreateLocPair {
                txout: (FILE_HEADER_LEN as u64, 16),
                spent: (FILE_HEADER_LEN as u64, 8),
                n_out: 1,
            })
        );
        assert_eq!(
            got[1],
            Some(CreateLocPair {
                txout: (FILE_HEADER_LEN as u64 + 16, 32),
                spent: (FILE_HEADER_LEN as u64 + 8, 24),
                n_out: 3,
            })
        );
        let last = got[1].unwrap();
        assert_eq!(last.txout.0 + last.txout.1, FILE_HEADER_LEN as u64 + 48);
        assert_eq!(last.spent.0 + last.spent.1, FILE_HEADER_LEN as u64 + 32);
    }

    #[test]
    fn create_loc_batch_preserves_caller_order() {
        let dir = TempDir::labeled("create-loc-order").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1, 1, 1], &[8, 8, 8])).unwrap();
        let got = loc
            .range_batch(&[Fk(3), Fk(1), Fk(2), Fk::NULL, Fk(9)])
            .unwrap();
        assert_eq!(got[0].unwrap().txout.0, FILE_HEADER_LEN as u64 + 16);
        assert_eq!(got[1].unwrap().txout.0, FILE_HEADER_LEN as u64);
        assert_eq!(got[2].unwrap().txout.0, FILE_HEADER_LEN as u64 + 8);
        assert_eq!(got[3], None);
        assert_eq!(got[4], None);
    }

    #[test]
    fn create_loc_window_1024_and_1025() {
        let dir = TempDir::labeled("create-loc-win").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        let n_out = vec![1u32; 1025];
        let lens = vec![8u64; 1025];
        loc.append(&chain(&n_out, &lens)).unwrap();
        assert_eq!(loc.count(), 1025);
        let got = loc.range_batch(&[Fk(1), Fk(1024), Fk(1025)]).unwrap();
        assert_eq!(got[0].unwrap().txout, (FILE_HEADER_LEN as u64, 8));
        assert_eq!(
            got[1].unwrap().txout,
            (FILE_HEADER_LEN as u64 + 1023 * 8, 8)
        );
        assert_eq!(
            got[2].unwrap().txout,
            (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
        );
        assert_eq!(
            got[2].unwrap().spent,
            (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
        );
        drop(loc);
        let loc = CreateLoc::open(dir.path()).unwrap();
        let got = loc.range_batch(&[Fk(1024), Fk(1025)]).unwrap();
        assert_eq!(
            got[0].unwrap().txout,
            (FILE_HEADER_LEN as u64 + 1023 * 8, 8)
        );
        assert_eq!(
            got[1].unwrap().txout,
            (FILE_HEADER_LEN as u64 + 1024 * 8, 8)
        );
    }

    #[test]
    fn create_loc_n_out_zero_append_corrupt() {
        let dir = TempDir::labeled("create-loc-zero").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        match loc.append(&[rec(FILE_HEADER_LEN as u64, 8, FILE_HEADER_LEN as u64, 0)]) {
            Err(StoreError::Corrupt(m)) => assert!(m.contains("create n_out"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_loc_n_out_256_overflow() {
        let dir = TempDir::labeled("create-loc-256").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[256], &[8])).unwrap();
        let got = loc.range_batch(&[Fk(1)]).unwrap();
        assert_eq!(got[0].unwrap().n_out, 256);
        assert_eq!(got[0].unwrap().spent.1, 256 * 8);
        assert!(dir.path().join("create.loc.ovf").exists());
        drop(loc);
        let loc = CreateLoc::open(dir.path()).unwrap();
        assert_eq!(loc.range_batch(&[Fk(1)]).unwrap()[0].unwrap().n_out, 256);
    }

    #[test]
    fn create_loc_fat_txout_overflow() {
        let dir = TempDir::labeled("create-loc-fat").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1], &[2048])).unwrap();
        let got = loc.range_batch(&[Fk(1)]).unwrap();
        assert_eq!(got[0].unwrap().txout.1, 2048);
        assert_eq!(got[0].unwrap().n_out, 1);
    }

    #[test]
    fn create_loc_txout_past_u16_strides() {
        let dir = TempDir::labeled("create-loc-u16-strides").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        let len = 65536 * IDX_STRIDE;
        loc.append(&chain(&[1], &[len])).unwrap();
        let got = loc.range_batch(&[Fk(1)]).unwrap();
        assert_eq!(got[0].unwrap().txout.1, len);
        assert_eq!(got[0].unwrap().n_out, 1);
        drop(loc);
        let loc = CreateLoc::open(dir.path()).unwrap();
        let got = loc.range_batch(&[Fk(1)]).unwrap();
        assert_eq!(got[0].unwrap().txout.1, len);
        assert_eq!(got[0].unwrap().n_out, 1);
        assert_eq!(ovf_data_len(dir.path()), 16);
    }

    #[test]
    fn create_loc_n_out_past_u16() {
        let dir = TempDir::labeled("create-loc-u16-nout").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[65536], &[8])).unwrap();
        let got = loc.range_batch(&[Fk(1)]).unwrap();
        assert_eq!(got[0].unwrap().n_out, 65536);
        assert_eq!(got[0].unwrap().spent.1, 65536 * IDX_STRIDE);
        drop(loc);
        let loc = CreateLoc::open(dir.path()).unwrap();
        assert_eq!(loc.range_batch(&[Fk(1)]).unwrap()[0].unwrap().n_out, 65536);
        assert_eq!(ovf_data_len(dir.path()), 16);
    }

    #[test]
    fn create_loc_opens_legacy_12b_ovf() {
        let dir = TempDir::labeled("create-loc-ovf12").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[256, 256, 256, 256], &[8, 8, 8, 8]))
            .unwrap();
        drop(loc);
        write_legacy_create_ovf_v22(
            dir.path(),
            &[(1, 1, 256), (2, 1, 256), (3, 1, 256), (4, 1, 256)],
        );
        assert_eq!(ovf_data_len(dir.path()), 48);
        let loc = CreateLoc::open(dir.path()).unwrap();
        let got = loc.range_batch(&[Fk(1), Fk(2), Fk(3), Fk(4)]).unwrap();
        for g in &got {
            assert_eq!(g.unwrap().n_out, 256);
            assert_eq!(g.unwrap().spent.1, 256 * IDX_STRIDE);
        }
        assert_eq!(ovf_data_len(dir.path()), 64);
    }

    #[test]
    fn create_loc_mixed_window_overflow() {
        let dir = TempDir::labeled("create-loc-mix").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        let mut n_out = vec![1u32; 16];
        n_out[7] = 256;
        let lens = vec![8u64; 16];
        loc.append(&chain(&n_out, &lens)).unwrap();
        let got = loc.range_batch(&[Fk(8), Fk(1), Fk(16)]).unwrap();
        assert_eq!(got[0].unwrap().n_out, 256);
        assert_eq!(got[0].unwrap().spent.1, 256 * 8);
        assert_eq!(got[1].unwrap().n_out, 1);
        assert_eq!(got[2].unwrap().n_out, 1);
        assert_eq!(got[0].unwrap().spent.0, FILE_HEADER_LEN as u64 + 7 * 8);
        assert_eq!(
            got[2].unwrap().spent.0,
            FILE_HEADER_LEN as u64 + 7 * 8 + 256 * 8 + 7 * 8
        );
        if let Ok(mut sess) =
            crate::uring_session::UringSession::try_open(crate::uring_session::DEFAULT_ENTRIES)
        {
            let held = loc
                .range_batch_ctx(&[Fk(8), Fk(1), Fk(16)], &mut crate::IoCtx::held(&mut sess))
                .unwrap();
            assert_eq!(held, got);
        }
    }

    #[test]
    fn create_loc_mixed_window_u32_strides() {
        let dir = TempDir::labeled("create-loc-mix-u32").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        let n_out = vec![1u32; 8];
        let mut lens = vec![8u64; 8];
        lens[3] = 65536 * IDX_STRIDE;
        loc.append(&chain(&n_out, &lens)).unwrap();
        let got = loc.range_batch(&[Fk(4), Fk(1), Fk(8)]).unwrap();
        assert_eq!(got[0].unwrap().txout.1, 65536 * IDX_STRIDE);
        assert_eq!(got[1].unwrap().txout.1, 8);
        assert_eq!(
            got[2].unwrap().txout.0,
            FILE_HEADER_LEN as u64 + 3 * 8 + 65536 * IDX_STRIDE + 3 * 8
        );
    }

    #[test]
    fn create_loc_missing_ovf_is_corrupt() {
        let dir = TempDir::labeled("create-loc-missing-ovf").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[256], &[8])).unwrap();
        drop(loc);
        std::fs::remove_file(dir.path().join("create.loc.ovf")).unwrap();
        let loc = CreateLoc::open(dir.path()).unwrap();
        match loc.range_batch(&[Fk(1)]) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("overflow missing"), "{m}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn spent_len_is_8_times_n_out() {
        assert_eq!(IDX_STRIDE, 8);
        assert_eq!(3u64.saturating_mul(IDX_STRIDE), 24);
        assert_eq!(256u64.saturating_mul(IDX_STRIDE), 2048);
    }

    #[test]
    fn loc_window_need_n_stops_at_max_id() {
        assert_eq!(loc_window_need_n(3, 1, 1024), 3);
        assert_eq!(loc_window_need_n(1024, 1, 1024), 1024);
        assert_eq!(loc_window_need_n(1025, 1025, 2048), 1);
        assert_eq!(loc_window_need_n(1100, 1025, 2048), 76);
        assert_eq!(loc_window_need_n(1, 1025, 2048), 0);
    }

    #[test]
    fn range_batch_multi_window_matches_serial_and_held() {
        let dir = TempDir::labeled("create-loc-batch-win").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&vec![1u32; 2000], &vec![8u64; 2000]))
            .unwrap();
        let fks = [Fk(3), Fk(50), Fk(1024), Fk(1025), Fk(2000), Fk::NULL];
        let batch = loc.range_batch(&fks).unwrap();
        for (i, fk) in fks.iter().enumerate() {
            let one = loc.range_batch(&[*fk]).unwrap();
            assert_eq!(batch[i], one[0], "fk={}", fk.0);
        }
        if let Ok(mut sess) =
            crate::uring_session::UringSession::try_open(crate::uring_session::DEFAULT_ENTRIES)
        {
            let held = loc
                .range_batch_ctx(&fks, &mut crate::IoCtx::held(&mut sess))
                .unwrap();
            assert_eq!(held, batch);
        }
    }
}
