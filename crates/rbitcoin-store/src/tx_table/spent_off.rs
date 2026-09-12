//! Sparse `spent.body` starts: prefix of `spent_record_len(n_out)` from txout.

use super::packed::spent_record_len;
use super::TxRecord;
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::var_table::VarTable;
use rbitcoin_primitives::{Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Checkpoint every N creates (fk 1, 1025, …). Between them, sum `n_out` from txout meta.
const SPENT_OFF_STRIDE: u64 = 1024;
const META_PEEK: u64 = 32;

pub(super) struct SpentOff {
    path: PathBuf,
    ckpts: Mutex<Vec<u64>>,
}

pub(crate) fn unlink_leftover_spent_idx(dir: &Path) -> Result<bool, StoreError> {
    let mut dropped = false;
    let root = dir.join("spent.idx");
    if root.exists() {
        if root.is_dir() {
            std::fs::remove_dir_all(&root).map_err(|e| StoreError::io(&root, e))?;
        } else {
            std::fs::remove_file(&root).map_err(|e| StoreError::io(&root, e))?;
        }
        dropped = true;
    }
    let flat_meta = dir.join("spent.idx.meta");
    if flat_meta.is_file() {
        std::fs::remove_file(&flat_meta).map_err(|e| StoreError::io(&flat_meta, e))?;
        dropped = true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("spent.idx.") {
                let p = e.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                } else {
                    let _ = std::fs::remove_file(&p);
                }
                dropped = true;
            }
        }
    }
    if dropped {
        rbitcoin_log::warn!(
            "store: dropping leftover spent.idx (spent ranges are n_out prefix of txout)"
        );
    }
    Ok(dropped)
}

impl SpentOff {
    pub(super) fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("spent.off"),
            ckpts: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn load(dir: &Path) -> Result<Self, StoreError> {
        let me = Self::new(dir);
        if !me.path.exists() {
            return Ok(me);
        }
        let f = TableFile::open(&me.path, TableKind::ArrayLink)?;
        let payload = f.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if payload % 8 != 0 {
            return Err(StoreError::Corrupt("spent.off size"));
        }
        let n = payload as usize;
        let mut buf = vec![0u8; n];
        if n > 0 {
            f.read_at(FILE_HEADER_LEN as u64, &mut buf)?;
        }
        let mut ckpts = Vec::with_capacity(n / 8);
        for c in buf.chunks_exact(8) {
            ckpts.push(u64::from_le_bytes(c.try_into().unwrap()));
        }
        *me.ckpts.lock().unwrap_or_else(|e| e.into_inner()) = ckpts;
        Ok(me)
    }

    pub(super) fn note_starts(&self, base_count: u64, starts: &[u64]) {
        if starts.is_empty() {
            return;
        }
        let mut g = self.ckpts.lock().unwrap_or_else(|e| e.into_inner());
        for (i, &start) in starts.iter().enumerate() {
            let fk = base_count.saturating_add(1).saturating_add(i as u64);
            if !fk.saturating_sub(1).is_multiple_of(SPENT_OFF_STRIDE) {
                continue;
            }
            let idx = ((fk - 1) / SPENT_OFF_STRIDE) as usize;
            if g.len() <= idx {
                g.resize(idx + 1, 0);
            }
            g[idx] = start;
        }
    }

    pub(super) fn truncate_to_count(&self, new_count: u64) {
        let mut g = self.ckpts.lock().unwrap_or_else(|e| e.into_inner());
        if new_count == 0 {
            g.clear();
            return;
        }
        let keep = 1 + (new_count - 1) / SPENT_OFF_STRIDE;
        g.truncate(keep as usize);
    }

    pub(super) fn ensure_covering(&self, body: &VarTable, count: u64) -> Result<(), StoreError> {
        if count == 0 {
            self.ckpts.lock().unwrap_or_else(|e| e.into_inner()).clear();
            return Ok(());
        }
        let need = 1 + (count - 1) / SPENT_OFF_STRIDE;
        {
            let g = self.ckpts.lock().unwrap_or_else(|e| e.into_inner());
            if g.len() as u64 >= need && g.first().copied() == Some(FILE_HEADER_LEN as u64) {
                return Ok(());
            }
        }
        let rebuilt = rebuild_from_txout(body, count)?;
        *self.ckpts.lock().unwrap_or_else(|e| e.into_inner()) = rebuilt;
        Ok(())
    }

    pub(super) fn flush(&self) -> Result<(), StoreError> {
        let ckpts = self.ckpts.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let f = if self.path.exists() {
            TableFile::open(&self.path, TableKind::ArrayLink)?
        } else {
            TableFile::create(&self.path, TableKind::ArrayLink)?
        };
        let mut blob = Vec::with_capacity(ckpts.len() * 8);
        for c in &ckpts {
            blob.extend_from_slice(&c.to_le_bytes());
        }
        let end = (FILE_HEADER_LEN as u64).saturating_add(blob.len() as u64);
        f.ensure_capacity(end)?;
        if !blob.is_empty() {
            f.write_at_pwrite(FILE_HEADER_LEN as u64, &blob)?;
        }
        f.set_logical_len(end)?;
        f.flush()
    }

    fn base_for(&self, fk: u64) -> Result<(u64, u64), StoreError> {
        if fk == 0 {
            return Err(StoreError::InvalidFk);
        }
        let i = (fk - 1) / SPENT_OFF_STRIDE;
        let g = self.ckpts.lock().unwrap_or_else(|e| e.into_inner());
        let Some(&off) = g.get(i as usize) else {
            return Err(StoreError::Corrupt(
                "invariant: spent off checkpoint missing",
            ));
        };
        if off < FILE_HEADER_LEN as u64 {
            return Err(StoreError::Corrupt("invariant: spent off checkpoint"));
        }
        Ok((i * SPENT_OFF_STRIDE + 1, off))
    }

    pub(super) fn range_for(
        &self,
        body: &VarTable,
        fk: Fk,
        count: u64,
    ) -> Result<(u64, u64), StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        if id == 0 {
            return Err(StoreError::InvalidFk);
        }
        if id > count {
            return Err(StoreError::NotFound);
        }
        let (base_fk, mut off) = self.base_for(id)?;
        if base_fk > id {
            return Err(StoreError::Corrupt("invariant: spent off base"));
        }
        let last_sum = id; // inclusive n_out through this fk
        let n_outs = peek_output_counts(body, base_fk, last_sum)?;
        if n_outs.len() as u64 != last_sum.saturating_sub(base_fk).saturating_add(1) {
            return Err(StoreError::Corrupt("invariant: spent n_out walk"));
        }
        for (i, n_out) in n_outs.iter().enumerate() {
            let cur = base_fk + i as u64;
            let len = spent_record_len(*n_out);
            if cur == id {
                return Ok((off, len));
            }
            off = off.saturating_add(len);
        }
        Err(StoreError::Corrupt("invariant: spent range walk"))
    }

    pub(super) fn ranges_batch(
        &self,
        body: &VarTable,
        fks: &[Fk],
        count: u64,
    ) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        let mut out = vec![None; fks.len()];
        if fks.is_empty() {
            return Ok(out);
        }
        let mut jobs: Vec<(usize, u64)> = Vec::new();
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
        let mut w = 0usize;
        while w < jobs.len() {
            let window = (jobs[w].1 - 1) / SPENT_OFF_STRIDE;
            let mut e = w + 1;
            while e < jobs.len() && (jobs[e].1 - 1) / SPENT_OFF_STRIDE == window {
                e += 1;
            }
            let lo = jobs[w].1;
            let hi = jobs[e - 1].1;
            let (base_fk, mut off) = self.base_for(lo)?;
            let n_outs = peek_output_counts(body, base_fk, hi)?;
            let mut want = w;
            for (i, n_out) in n_outs.iter().enumerate() {
                let cur = base_fk + i as u64;
                let len = spent_record_len(*n_out);
                while want < e && jobs[want].1 == cur {
                    out[jobs[want].0] = Some((off, len));
                    want += 1;
                }
                if cur == hi {
                    break;
                }
                off = off.saturating_add(len);
            }
            w = e;
        }
        Ok(out)
    }

    pub(super) fn end_for(&self, body: &VarTable, count: u64) -> Result<u64, StoreError> {
        if count == 0 {
            return Ok(FILE_HEADER_LEN as u64);
        }
        let (off, len) = self.range_for(body, Fk(count), count)?;
        Ok(off.saturating_add(len))
    }
}

fn peek_output_counts(body: &VarTable, first: u64, last: u64) -> Result<Vec<u32>, StoreError> {
    if first == 0 || last < first {
        return Err(StoreError::InvalidFk);
    }
    let ranges = body.record_ranges(first, last)?;
    let expect = last.saturating_sub(first).saturating_add(1) as usize;
    if ranges.len() != expect {
        return Err(StoreError::Corrupt("invariant: txout n_out range"));
    }
    let span_lo = ranges[0].0;
    let mut span_hi = span_lo;
    for &(off, rlen) in &ranges {
        span_hi = span_hi.max(off.saturating_add(rlen.min(META_PEEK)));
    }
    let span_len = span_hi.saturating_sub(span_lo);
    let buf = body.pread_span(span_lo, span_len)?;
    let mut out = Vec::with_capacity(ranges.len());
    for &(off, rlen) in &ranges {
        let rel = (off.saturating_sub(span_lo)) as usize;
        let take = (rlen.min(META_PEEK) as usize).min(buf.len().saturating_sub(rel));
        let (rec, _) = TxRecord::decode_body_meta(
            buf.get(rel..rel + take)
                .ok_or(StoreError::Corrupt("txout meta span short"))?,
        )?;
        out.push(rec.output_count);
    }
    Ok(out)
}

fn rebuild_from_txout(body: &VarTable, count: u64) -> Result<Vec<u64>, StoreError> {
    let mut ckpts = Vec::new();
    let mut off = FILE_HEADER_LEN as u64;
    let mut first = 1u64;
    while first <= count {
        let last = first.saturating_add(SPENT_OFF_STRIDE - 1).min(count);
        let n_outs = peek_output_counts(body, first, last)?;
        for (i, n_out) in n_outs.iter().enumerate() {
            let fk = first + i as u64;
            if (fk - 1).is_multiple_of(SPENT_OFF_STRIDE) {
                ckpts.push(off);
            }
            off = off.saturating_add(spent_record_len(*n_out));
        }
        first = last.saturating_add(1);
    }
    Ok(ckpts)
}
