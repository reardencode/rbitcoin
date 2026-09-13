//! Packed create locator: 2 B/create (`txout_strides:u8`, `n_out:u8`).
//!
//! Checkpoints in `create.off` (RAM). Loc and overflow stay FdOnly.
//! Last 2²⁰ decoded pairs stay in process RAM after append so leftover
//! lookup can stamp without preading the live tail.

use crate::bulk_io::ReadOp;
use crate::delta_loc::{
    create_table_file, decode_create_pair, load_create_ovf, loc_file_off, loc_window, loc_within,
    open_table_file, pack_create_pair, strides_from_aligned_len, IDX_STRIDE, LOC_WINDOW,
};
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::IoCtx;
use arc_swap::ArcSwap;
use rbitcoin_primitives::{Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const SLOT: u64 = 2;
const OFF_SLOT: u64 = 16;
const OVF_SLOT: u64 = 12;
/// Sliding window of decoded loc pairs after Class A append (write + lookup).
const LOC_RAM_KEEP: usize = 1 << 20;

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

/// Immutable loc-pair window. Chunked so append publishes without copying KEEP.
#[derive(Clone, Default)]
struct LocRamSnap {
    base: u64,
    len: usize,
    chunks: Vec<Arc<Vec<CreateLocPair>>>,
}

impl LocRamSnap {
    const CHUNK: usize = 1024;

    fn get(&self, id: u64) -> Option<CreateLocPair> {
        let off = id.checked_sub(self.base)? as usize;
        if off >= self.len {
            return None;
        }
        let first_n = self.chunks.first()?.len();
        if off < first_n {
            return self.chunks[0].get(off).copied();
        }
        let rest = off - first_n;
        let ci = 1 + rest / Self::CHUNK;
        let wi = rest % Self::CHUNK;
        self.chunks.get(ci)?.get(wi).copied()
    }

    fn extend(&self, start: u64, loc: &[CreateLocPair]) -> Self {
        self.extend_capped(start, loc, LOC_RAM_KEEP)
    }

    fn extend_capped(&self, start: u64, loc: &[CreateLocPair], keep: usize) -> Self {
        if loc.is_empty() {
            return self.clone();
        }
        let next = self.base.saturating_add(self.len as u64);
        let mut out = if self.len == 0 || start != next {
            Self::from_pairs(start, loc)
        } else {
            self.append_pairs(loc)
        };
        out.trim_keep(keep);
        out
    }

    fn from_pairs(start: u64, loc: &[CreateLocPair]) -> Self {
        let mut chunks = Vec::new();
        let mut rest = loc;
        while rest.len() >= Self::CHUNK {
            chunks.push(Arc::new(rest[..Self::CHUNK].to_vec()));
            rest = &rest[Self::CHUNK..];
        }
        if !rest.is_empty() {
            chunks.push(Arc::new(rest.to_vec()));
        }
        Self {
            base: start,
            len: loc.len(),
            chunks,
        }
    }

    fn append_pairs(&self, loc: &[CreateLocPair]) -> Self {
        let mut chunks = self.chunks.clone();
        let mut rest = loc;
        if let Some(last) = chunks.last() {
            if last.len() < Self::CHUNK {
                let mut v = last.as_ref().clone();
                let take = (Self::CHUNK - v.len()).min(rest.len());
                v.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                *chunks.last_mut().unwrap() = Arc::new(v);
            }
        }
        while rest.len() >= Self::CHUNK {
            chunks.push(Arc::new(rest[..Self::CHUNK].to_vec()));
            rest = &rest[Self::CHUNK..];
        }
        if !rest.is_empty() {
            chunks.push(Arc::new(rest.to_vec()));
        }
        Self {
            base: self.base,
            len: self.len + loc.len(),
            chunks,
        }
    }

    fn trim_keep(&mut self, keep: usize) {
        if keep == 0 {
            *self = Self::default();
            return;
        }
        while self.len > keep {
            let extra = self.len - keep;
            let Some(first) = self.chunks.first() else {
                break;
            };
            if extra >= first.len() {
                let n = first.len();
                self.base = self.base.saturating_add(n as u64);
                self.len -= n;
                self.chunks.remove(0);
            } else {
                let v = first[extra..].to_vec();
                self.base = self.base.saturating_add(extra as u64);
                self.len = keep;
                self.chunks[0] = Arc::new(v);
            }
        }
    }

    fn truncate_to(&self, new_count: u64) -> Self {
        if self.len == 0 {
            return Self::default();
        }
        let last_id = self.base + self.len as u64 - 1;
        if new_count >= last_id {
            return self.clone();
        }
        if new_count < self.base {
            return Self::default();
        }
        let keep_n = (new_count - self.base + 1) as usize;
        let mut pairs = Vec::with_capacity(keep_n);
        for i in 0..keep_n {
            let id = self.base + i as u64;
            let Some(p) = self.get(id) else {
                return Self::default();
            };
            pairs.push(p);
        }
        Self::from_pairs(self.base, &pairs)
    }
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
    ram: ArcSwap<LocRamSnap>,
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
            ram: ArcSwap::from_pointee(LocRamSnap::default()),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let loc = open_table_file(&dir.join("create.loc"), TableKind::DeltaLoc)?;
        let ovf_path = dir.join("create.loc.ovf");
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
            ram: ArcSwap::from_pointee(LocRamSnap::default()),
        })
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    pub(crate) fn ram_get(&self, fk: Fk) -> Option<CreateLocPair> {
        let id = fk.get()?;
        self.ram.load().get(id)
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
            let mut blob = Vec::with_capacity(rows.len() * OVF_SLOT as usize);
            for &(fk, st, n_out) in rows.iter() {
                blob.extend_from_slice(&fk.to_le_bytes());
                blob.extend_from_slice(&(st as u16).to_le_bytes());
                blob.extend_from_slice(&(n_out as u16).to_le_bytes());
            }
            self.ovf
                .set_logical_len(FILE_HEADER_LEN as u64 + blob.len() as u64)?;
            if !blob.is_empty() {
                self.ovf.write_at(FILE_HEADER_LEN as u64, &blob)?;
            }
        }
        self.count.store(new_count, Ordering::Release);
        self.ram
            .store(Arc::new(self.ram.load().truncate_to(new_count)));
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
                let mut row = [0u8; OVF_SLOT as usize];
                row[0..8].copy_from_slice(&fk.to_le_bytes());
                row[8..10].copy_from_slice(&os.to_le_bytes());
                row[10..12].copy_from_slice(&on.to_le_bytes());
                ovf_bytes.extend_from_slice(&row);
                new_ovf.push((fk, u32::from(os), u32::from(on)));
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
        let start = base + 1;
        let pairs: Vec<CreateLocPair> = recs
            .iter()
            .map(|rec| CreateLocPair {
                txout: (rec.txout_start, rec.txout_len),
                spent: (
                    rec.spent_start,
                    u64::from(rec.n_out).saturating_mul(IDX_STRIDE),
                ),
                n_out: rec.n_out,
            })
            .collect();
        self.ram
            .store(Arc::new(self.ram.load().extend(start, &pairs)));
        Ok(())
    }

    pub fn range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<CreateLocPair>>, StoreError> {
        self.range_batch_ctx(fks, &mut IoCtx::none())
    }

    /// Same as [`Self::range_batch`] on a held completion session (head-resolve TLS).
    pub(crate) fn range_batch_ctx(
        &self,
        fks: &[Fk],
        ctx: &mut IoCtx<'_>,
    ) -> Result<Vec<Option<CreateLocPair>>, StoreError> {
        if fks.is_empty() {
            return Ok(Vec::new());
        }
        let count = self.count.load(Ordering::Acquire);
        let mut out = vec![None; fks.len()];
        let snap = self.ram.load();
        let mut jobs: Vec<(usize, u64)> = Vec::new();
        let mut ram_n = 0u64;
        for (i, fk) in fks.iter().enumerate() {
            let Some(id) = fk.get() else { continue };
            if id == 0 || id > count {
                continue;
            }
            if let Some(p) = snap.get(id) {
                out[i] = Some(p);
                ram_n = ram_n.saturating_add(1);
                continue;
            }
            jobs.push((i, id));
        }
        crate::head_resolve_stats::add_loc_ram(ram_n);
        crate::head_resolve_stats::add_loc_disk(jobs.len() as u64);
        if jobs.is_empty() {
            return Ok(out);
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
        self.pread_windows(ctx, &mut windows)?;
        for win in &windows {
            let (tx_ps, sp_ps, n_outs) = self.prefix_sum_win(win)?;
            for &(orig, id) in &jobs[win.job_lo..win.job_hi] {
                let within = loc_within(id);
                out[orig] = Some(CreateLocPair {
                    txout: (tx_ps[within], tx_ps[within + 1] - tx_ps[within]),
                    spent: (sp_ps[within], sp_ps[within + 1] - sp_ps[within]),
                    n_out: n_outs[within],
                });
            }
        }
        Ok(out)
    }

    fn prefix_sum_win(&self, win: &LocWinRead) -> Result<LocPrefix, StoreError> {
        let mut any_sentinel = false;
        for i in 0..win.n {
            if win.buf[i * 2] == 0 || win.buf[i * 2 + 1] == 0 {
                any_sentinel = true;
                break;
            }
        }
        if any_sentinel {
            let ovf = self.ovf_rows.read().unwrap_or_else(|e| e.into_inner());
            prefix_sum_create_ovf(&win.buf, win.n, win.tx0, win.sp0, win.win_first, &ovf)
        } else {
            Ok(prefix_sum_create_no_ovf(&win.buf, win.n, win.tx0, win.sp0))
        }
    }

    fn pread_windows(
        &self,
        ctx: &mut IoCtx<'_>,
        windows: &mut [LocWinRead],
    ) -> Result<(), StoreError> {
        if windows.is_empty() {
            return Ok(());
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

struct LocWinRead {
    job_lo: usize,
    job_hi: usize,
    win_first: u64,
    n: usize,
    tx0: u64,
    sp0: u64,
    buf: Vec<u8>,
}

type LocPrefix = (Vec<u64>, Vec<u64>, Vec<u32>);

fn prefix_sum_create_ovf(
    buf: &[u8],
    n: usize,
    tx0: u64,
    sp0: u64,
    win_first: u64,
    ovf: &[(u64, u32, u32)],
) -> Result<LocPrefix, StoreError> {
    let mut tx_ps = vec![0u64; n + 1];
    let mut sp_ps = vec![0u64; n + 1];
    let mut n_outs = vec![0u32; n];
    tx_ps[0] = tx0;
    sp_ps[0] = sp0;
    for i in 0..n {
        let fk = win_first + i as u64;
        let (st, n_out) = decode_create_pair(buf[i * 2], buf[i * 2 + 1], fk, ovf)?;
        n_outs[i] = n_out;
        tx_ps[i + 1] = tx_ps[i].saturating_add(u64::from(st).saturating_mul(IDX_STRIDE));
        sp_ps[i + 1] = sp_ps[i].saturating_add(u64::from(n_out).saturating_mul(IDX_STRIDE));
    }
    Ok((tx_ps, sp_ps, n_outs))
}

/// Non-overflow window: SIMD prefix when the arch provides it, else scalar.
pub(crate) fn prefix_sum_create_no_ovf(buf: &[u8], n: usize, tx0: u64, sp0: u64) -> LocPrefix {
    let mut tx_ps = vec![0u64; n + 1];
    let mut sp_ps = vec![0u64; n + 1];
    let mut n_outs = vec![0u32; n];
    prefix_sum_create_no_ovf_into(buf, n, tx0, sp0, &mut tx_ps, &mut sp_ps, &mut n_outs);
    (tx_ps, sp_ps, n_outs)
}

/// Independent scalar prefix: test golden, and the production path off x86_64/aarch64.
/// Test binaries on those arches still run [`prefix_sum_create_no_ovf`] through SIMD.
#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub(crate) fn prefix_sum_create_no_ovf_scalar(
    buf: &[u8],
    n: usize,
    tx0: u64,
    sp0: u64,
) -> LocPrefix {
    let mut tx_ps = vec![0u64; n + 1];
    let mut sp_ps = vec![0u64; n + 1];
    let mut n_outs = vec![0u32; n];
    prefix_sum_create_no_ovf_scalar_into(buf, n, tx0, sp0, &mut tx_ps, &mut sp_ps, &mut n_outs);
    (tx_ps, sp_ps, n_outs)
}

fn prefix_sum_create_no_ovf_into(
    buf: &[u8],
    n: usize,
    tx0: u64,
    sp0: u64,
    tx_ps: &mut [u64],
    sp_ps: &mut [u64],
    n_outs: &mut [u32],
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    prefix_sum_create_u8x8(buf, n, tx0, sp0, tx_ps, sp_ps, n_outs);
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    prefix_sum_create_no_ovf_scalar_into(buf, n, tx0, sp0, tx_ps, sp_ps, n_outs);
}

#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn prefix_sum_create_no_ovf_scalar_into(
    buf: &[u8],
    n: usize,
    tx0: u64,
    sp0: u64,
    tx_ps: &mut [u64],
    sp_ps: &mut [u64],
    n_outs: &mut [u32],
) {
    tx_ps[0] = tx0;
    sp_ps[0] = sp0;
    for i in 0..n {
        let st = u32::from(buf[i * 2]);
        let n_out = u32::from(buf[i * 2 + 1]);
        n_outs[i] = n_out;
        tx_ps[i + 1] = tx_ps[i].saturating_add(u64::from(st).saturating_mul(IDX_STRIDE));
        sp_ps[i + 1] = sp_ps[i].saturating_add(u64::from(n_out).saturating_mul(IDX_STRIDE));
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn prefix_sum_create_u8x8(
    buf: &[u8],
    n: usize,
    tx0: u64,
    sp0: u64,
    tx_ps: &mut [u64],
    sp_ps: &mut [u64],
    n_outs: &mut [u32],
) {
    tx_ps[0] = tx0;
    sp_ps[0] = sp0;
    let mut i = 0usize;
    let mut tx = tx0;
    let mut sp = sp0;
    while i + 8 <= n {
        let mut st = [0u8; 8];
        let mut no = [0u8; 8];
        let base = i * 2;
        for k in 0..8 {
            st[k] = buf[base + k * 2];
            no[k] = buf[base + k * 2 + 1];
            n_outs[i + k] = u32::from(no[k]);
        }
        // SAFETY: `st`/`no` are 8-byte stack arrays; SSE2 movq / NEON vld1
        // 8-byte loads are defined unaligned.
        #[cfg(target_arch = "x86_64")]
        let (tx_inc, sp_inc) = unsafe {
            (
                sse2_u8x8_times_8_inclusive(st.as_ptr()),
                sse2_u8x8_times_8_inclusive(no.as_ptr()),
            )
        };
        #[cfg(target_arch = "aarch64")]
        let (tx_inc, sp_inc) = unsafe {
            (
                neon_u8x8_times_8_inclusive(st.as_ptr()),
                neon_u8x8_times_8_inclusive(no.as_ptr()),
            )
        };
        let tx_start = tx;
        let sp_start = sp;
        for k in 0..8 {
            tx_ps[i + k + 1] = tx_start.saturating_add(u64::from(tx_inc[k]));
            sp_ps[i + k + 1] = sp_start.saturating_add(u64::from(sp_inc[k]));
        }
        tx = tx_ps[i + 8];
        sp = sp_ps[i + 8];
        i += 8;
    }
    for j in i..n {
        let st = u32::from(buf[j * 2]);
        let n_out = u32::from(buf[j * 2 + 1]);
        n_outs[j] = n_out;
        tx = tx.saturating_add(u64::from(st).saturating_mul(IDX_STRIDE));
        sp = sp.saturating_add(u64::from(n_out).saturating_mul(IDX_STRIDE));
        tx_ps[j + 1] = tx;
        sp_ps[j + 1] = sp;
    }
}

/// Inclusive scan of eight `u8 << 3` values (fits u32 for a 1024-create window).
///
/// # Safety
/// `p` must be readable for 8 bytes.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn sse2_u8x8_times_8_inclusive(p: *const u8) -> [u32; 8] {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_cvtepu8_epi32, _mm_extract_epi32, _mm_loadl_epi64,
        _mm_set1_epi32, _mm_slli_epi32, _mm_slli_si128, _mm_srli_si128, _mm_storeu_si128,
    };
    let prefix4 = |v: __m128i| {
        let s = _mm_add_epi32(v, _mm_slli_si128(v, 4));
        _mm_add_epi32(s, _mm_slli_si128(s, 8))
    };
    let v = _mm_loadl_epi64(p as *const __m128i);
    let lo = prefix4(_mm_slli_epi32(_mm_cvtepu8_epi32(v), 3));
    let hi = prefix4(_mm_slli_epi32(_mm_cvtepu8_epi32(_mm_srli_si128(v, 4)), 3));
    let lo_sum = _mm_extract_epi32(lo, 3);
    let hi = _mm_add_epi32(hi, _mm_set1_epi32(lo_sum));
    let mut out = [0u32; 8];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, lo);
    _mm_storeu_si128(out.as_mut_ptr().add(4) as *mut __m128i, hi);
    out
}

/// Inclusive scan of eight `u8 << 3` values (fits u32 for a 1024-create window).
///
/// # Safety
/// `p` must be readable for 8 bytes.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn neon_u8x8_times_8_inclusive(p: *const u8) -> [u32; 8] {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vdupq_n_u32, vextq_u32, vget_high_u16, vget_low_u16, vgetq_lane_u32,
        vld1_u8, vmovl_u16, vmovl_u8, vshlq_n_u32, vst1q_u32,
    };
    let prefix4 = |v: uint32x4_t| {
        let z = vdupq_n_u32(0);
        let s = vaddq_u32(v, vextq_u32(z, v, 3));
        vaddq_u32(s, vextq_u32(z, s, 2))
    };
    let v = vld1_u8(p);
    let v16 = vmovl_u8(v);
    let lo = prefix4(vshlq_n_u32(vmovl_u16(vget_low_u16(v16)), 3));
    let hi = prefix4(vshlq_n_u32(vmovl_u16(vget_high_u16(v16)), 3));
    let hi = vaddq_u32(hi, vdupq_n_u32(vgetq_lane_u32(lo, 3)));
    let mut out = [0u32; 8];
    vst1q_u32(out.as_mut_ptr(), lo);
    vst1q_u32(out.as_mut_ptr().add(4), hi);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FILE_HEADER_LEN;
    use crate::testutil::TempDir;
    use std::path::Path;

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
    fn prefix_sum_fast_matches_scalar() {
        let mut buf = Vec::new();
        for i in 0..1024 {
            buf.push(((i % 254) + 1) as u8);
            buf.push(((i % 200) + 1) as u8);
        }
        let fat = vec![255u8; 1024 * 2];
        for n in [1usize, 7, 8, 9, 16, 63, 64, 1024] {
            assert_eq!(
                prefix_sum_create_no_ovf(&buf, n, 64, 80),
                prefix_sum_create_no_ovf_scalar(&buf, n, 64, 80),
                "n={n}"
            );
            assert_eq!(
                prefix_sum_create_no_ovf(&fat, n, 0, 64),
                prefix_sum_create_no_ovf_scalar(&fat, n, 0, 64),
                "fat n={n}"
            );
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn prefix_sum_u8x8_scan_matches_scalar() {
        let p = [255u8, 1, 0, 8, 255, 9, 2, 3];
        let mut expect = [0u32; 8];
        let mut acc = 0u32;
        for (i, b) in p.iter().enumerate() {
            acc += u32::from(*b) << 3;
            expect[i] = acc;
        }
        let got = unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                sse2_u8x8_times_8_inclusive(p.as_ptr())
            }
            #[cfg(target_arch = "aarch64")]
            {
                neon_u8x8_times_8_inclusive(p.as_ptr())
            }
        };
        assert_eq!(got, expect);
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

    fn smash_loc_payload(dir: &Path, n: usize) {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("create.loc"))
            .unwrap();
        f.seek(SeekFrom::Start(FILE_HEADER_LEN as u64)).unwrap();
        f.write_all(&vec![0xffu8; n * 2]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn range_batch_after_append_ignores_smashed_loc_bytes() {
        let dir = TempDir::labeled("create-loc-ram").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1, 3, 2], &[16, 32, 24])).unwrap();
        let fks = [Fk(2), Fk(1), Fk(3), Fk::NULL];
        let want = loc.range_batch(&fks).unwrap();
        assert!(want[0].is_some() && want[1].is_some() && want[2].is_some());
        smash_loc_payload(dir.path(), 3);
        let got = loc.range_batch(&fks).unwrap();
        assert_eq!(
            got, want,
            "append RAM must stamp loc without reading smashed bytes"
        );
        let disk = CreateLoc::open(dir.path()).unwrap();
        let from_disk = disk.range_batch(&fks).unwrap();
        assert_ne!(
            from_disk, want,
            "reopen has empty RAM and must see smashed loc bytes"
        );
    }

    #[test]
    fn loc_ram_snap_evicts_oldest_over_keep() {
        let p = CreateLocPair {
            txout: (8, 8),
            spent: (8, 8),
            n_out: 1,
        };
        let snap = LocRamSnap::default().extend_capped(1, &[p, p, p, p, p, p], 4);
        assert_eq!(snap.get(1), None);
        assert_eq!(snap.get(2), None);
        assert_eq!(snap.get(3), Some(p));
        assert_eq!(snap.get(6), Some(p));
        assert_eq!(snap.get(7), None);
    }

    #[test]
    fn range_batch_after_truncate_keeps_ram_for_remaining() {
        let dir = TempDir::labeled("create-loc-ram-trunc").unwrap();
        let loc = CreateLoc::create(dir.path()).unwrap();
        loc.append(&chain(&[1, 1, 1, 1], &[8, 8, 8, 8])).unwrap();
        loc.truncate_to_count(2).unwrap();
        smash_loc_payload(dir.path(), 2);
        let got = loc.range_batch(&[Fk(1), Fk(2), Fk(3)]).unwrap();
        assert_eq!(
            got[0],
            Some(CreateLocPair {
                txout: (FILE_HEADER_LEN as u64, 8),
                spent: (FILE_HEADER_LEN as u64, 8),
                n_out: 1,
            })
        );
        assert_eq!(got[1].unwrap().n_out, 1);
        assert_eq!(got[2], None);
        assert!(loc.ram_get(Fk(1)).is_some());
        assert!(loc.ram_get(Fk(3)).is_none());
    }
}
