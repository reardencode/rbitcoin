//! Packed create locator: 2 B/create (`txout_strides:u8`, `n_out:u8`).
//!
//! Checkpoints in `create.off` (RAM). Loc and overflow stay FdOnly.

use crate::bulk_io::ReadOp;
use crate::delta_loc::{
    checkpoint_fit, create_table_file, decode_create_pair, encode_create_ovf_row, load_create_ovf,
    loc_file_off, loc_window, loc_within, migrate_create_ovf_v22_if_needed, open_table_file,
    pack_create_pair, strides_from_aligned_len, unresolved_ovf_cut, CREATE_OVF_SLOT, IDX_STRIDE,
    LOC_WINDOW,
};
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::IoCtx;
use rbitcoin_primitives::{deinterleave_pairs_u8x8, inclusive_u8x8_times_8, Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[doc(hidden)]
pub const SLOT: u64 = 2;
#[doc(hidden)]
pub const OFF_SLOT: u64 = 16;

/// Slots to read and prefix-sum in `[win_first, win_last]` for the highest needed fk.
#[inline]
pub fn loc_window_need_n(max_id: u64, win_first: u64, win_last: u64) -> usize {
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

/// One create-loc append, encoded and not yet published.
pub(crate) struct StagedCreate {
    base: u64,
    n: u64,
    loc_off: u64,
    loc_bytes: Vec<u8>,
    ovf_at: u64,
    ovf_bytes: Vec<u8>,
    new_ovf: Vec<(u64, u32, u32)>,
    off_at: u64,
    off_bytes: Vec<u8>,
    new_offs: Vec<(u64, u64, u64)>,
}

pub struct CreateLoc {
    pub loc: TableFile,
    pub ovf: TableFile,
    pub off: TableFile,
    pub checkpoints: RwLock<Vec<(u64, u64)>>,
    pub ovf_rows: RwLock<Vec<(u64, u32, u32)>>,
    pub count: AtomicU64,
    /// Open dropped a locator prefix. Later truncates do not set this.
    pub(crate) cut_on_open: bool,
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
            cut_on_open: false,
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
        let full = data / SLOT;
        let Some(count) = checkpoint_fit(full, off.data_len(), OFF_SLOT) else {
            return Err(StoreError::Corrupt("invariant: create.off size"));
        };
        let n_win = count / LOC_WINDOW;
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
        let mut opened = Self {
            loc,
            ovf,
            off,
            checkpoints: RwLock::new(checkpoints),
            ovf_rows: RwLock::new(ovf_rows),
            count: AtomicU64::new(full),
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
            unresolved_ovf_cut(&opened.loc, &opened.ovf, opened.count(), last_ovf, true)?
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
            return Err(StoreError::Corrupt("create.loc truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let loc_end = FILE_HEADER_LEN as u64 + new_count * SLOT;
        let n_win = new_count / LOC_WINDOW;
        let kept = self
            .ovf_rows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.0 <= new_count)
            .count();
        // Kept overflow rows are a prefix.
        self.loc.set_logical_len(loc_end)?;
        self.off
            .set_logical_len(FILE_HEADER_LEN as u64 + n_win * OFF_SLOT)?;
        self.ovf
            .set_logical_len(FILE_HEADER_LEN as u64 + kept as u64 * CREATE_OVF_SLOT)?;
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

    pub fn append(&self, recs: &[CreateLocAppend]) -> Result<(), StoreError> {
        if recs.is_empty() {
            return Ok(());
        }
        let staged = self.stage(recs)?;
        self.write_staged(&staged)?;
        let _ = self.commit_staged(staged, true);
        Ok(())
    }

    pub(crate) fn stage(&self, recs: &[CreateLocAppend]) -> Result<StagedCreate, StoreError> {
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
        let off_at = new_offs
            .first()
            .map(|(w, _, _)| FILE_HEADER_LEN as u64 + w * OFF_SLOT)
            .unwrap_or(0);
        let mut off_bytes = Vec::with_capacity(new_offs.len() * OFF_SLOT as usize);
        for &(_, txout_abs, spent_abs) in &new_offs {
            off_bytes.extend_from_slice(&txout_abs.to_le_bytes());
            off_bytes.extend_from_slice(&spent_abs.to_le_bytes());
        }
        Ok(StagedCreate {
            base,
            n: recs.len() as u64,
            loc_off: loc_file_off(base + 1, SLOT),
            loc_bytes,
            ovf_at: FILE_HEADER_LEN as u64 + self.ovf.data_len(),
            ovf_bytes,
            new_ovf,
            off_at,
            off_bytes,
            new_offs,
        })
    }

    pub(crate) fn write_staged(&self, staged: &StagedCreate) -> Result<(), StoreError> {
        if let Some(&(fk, _, _)) = staged.new_ovf.first() {
            let rows = self.ovf_rows.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&(last, _, _)) = rows.last() {
                if fk <= last {
                    return Err(StoreError::Corrupt("invariant: create.loc ovf order"));
                }
            }
        }
        if let Some(&(w, _, _)) = staged.new_offs.first() {
            let cps = self.checkpoints.read().unwrap_or_else(|e| e.into_inner());
            if w as usize != cps.len() {
                return Err(StoreError::Corrupt("invariant: create.off index"));
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
    pub(crate) fn commit_staged(&self, staged: StagedCreate, mut durable: bool) -> bool {
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
            for &(w, txout_abs, spent_abs) in &staged.new_offs {
                debug_assert_eq!(w as usize, cps.len());
                cps.push((txout_abs, spent_abs));
            }
        }
        self.count.store(staged.base + staged.n, Ordering::Release);
        durable
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
    pub fn range_batch_ctx(
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
    pub fn plan_range_batch(&self, fks: &[Fk]) -> Result<LocPlan, StoreError> {
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
            let buf_len = n * 2;
            let end = loc_file_off(win_first, SLOT).saturating_add(buf_len as u64);
            if end > published {
                return Err(StoreError::Corrupt(
                    "invariant: body read past published end",
                ));
            }
            windows.push(LocWinRead {
                job_lo: w_i,
                job_hi: w_j,
                win_first,
                n,
                tx0,
                sp0,
                buf: vec![0u8; buf_len],
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
    pub fn finish_range_batch(
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
    pub fn loc_file(&self) -> (crate::io_handle::IoHandle, &Path) {
        (self.loc.read_fd(), self.loc.path())
    }

    #[doc(hidden)]
    pub fn extract_win_pairs(
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

    #[doc(hidden)]
    pub fn pread_windows(&self, ctx: &mut IoCtx<'_>, plan: &mut LocPlan) -> Result<(), StoreError> {
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
                    self.read_planned_windows(windows)?;
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
            self.read_one_planned_window(&mut windows[i])?;
        }
        Ok(())
    }

    /// Fill windows whose planned end was already checked. No second HWM load.
    #[doc(hidden)]
    pub fn read_planned_windows(&self, windows: &mut [LocWinRead]) -> Result<(), StoreError> {
        for w in windows {
            self.read_one_planned_window(w)?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn read_one_planned_window(&self, w: &mut LocWinRead) -> Result<(), StoreError> {
        self.loc
            .pread_exact(loc_file_off(w.win_first, SLOT), &mut w.buf)
    }
}

/// Window reads for one [`CreateLoc::plan_range_batch`].
pub struct LocPlan {
    pub out_len: usize,
    pub jobs: Vec<(usize, u64)>,
    pub windows: Vec<LocWinRead>,
    /// `create.loc` published end paired with the count this plan resolved.
    pub published: u64,
}

impl LocPlan {
    /// `(file offset, buffer)` for each window read, in plan order.
    pub fn reads(&mut self) -> impl Iterator<Item = (u64, &mut Vec<u8>)> {
        self.windows
            .iter_mut()
            .map(|w| (loc_file_off(w.win_first, SLOT), &mut w.buf))
    }
}

#[doc(hidden)]
pub struct LocWinRead {
    pub job_lo: usize,
    pub job_hi: usize,
    pub win_first: u64,
    pub n: usize,
    pub tx0: u64,
    pub sp0: u64,
    pub buf: Vec<u8>,
}

#[doc(hidden)]
pub enum ExtractFail {
    NeedOvf,
}

#[doc(hidden)]
pub fn emit_pair(
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

#[doc(hidden)]
pub fn extract_pairs_ovf(
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

#[doc(hidden)]
pub fn extract_pairs_no_ovf(
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
