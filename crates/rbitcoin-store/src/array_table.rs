//! Growable dense array of little-endian `u64` values.
//!
//! 0-based indexing. Used for Class C: `confirmed[height]`, `header_txs` arrays, etc.
//!
//! # L2 write-behind (phase 6)
//!
//! Compact **array** tables (`confirmed`, `header_txs_*`; body ≤
//! [`class_c_inram_max_bytes`]) load fully into process RAM on open.
//! `strong_tx` is always L2 (see [`crate::chain::StrongTxTable`]).
//! Mutates update the `Vec` only and mark dirty. Disk is updated on
//! `Self::flush` / barrier:
//!
//! - **Append-only** (dirty only at indices ≥ last flushed len): write the new
//!   **suffix** only, then extend HWM — never overwrites published prefix bytes.
//! - **Truncate**: shrink the HWM only when nothing below the new length is
//!   dirty; otherwise rewrite from the lowest dirty index, then shrink.
//! - **In-prefix mutate** (rare for tip Class C): full body rewrite (residual
//!   mid-pwrite tear risk on same-size published range — mitigated by tip-last
//!   barrier so `confirmed` is not advanced until strong/height are durable).
//!
//! Tables over the cap stay pure fd L0 (per-slot write-through).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(loom, shuttle))]
use crate::sync::TryUpdate as _;
use crate::sync::{Mutex, RwLock};
use rbitcoin_primitives::TableKind;
use std::path::Path;

/// Packed dirty generation: `0` is clean. `set` bumps; flush CASes back to `0`.
pub fn dirty_epoch_bump(epoch: &AtomicU64) {
    let _ = epoch.try_update(Ordering::Release, Ordering::Relaxed, |e| {
        Some(e.wrapping_add(1).max(1))
    });
}

/// Mark clean after a persist that sampled generation `e0`. `lo` resets
/// first: a `set` that lands here bumps the generation, the clean fails, and
/// its index survives for the next flush.
pub fn dirty_try_clean(epoch: &AtomicU64, lo: &AtomicU64, e0: u64, between: impl FnOnce()) {
    let prev = lo.swap(u64::MAX, Ordering::AcqRel);
    between();
    if epoch
        .compare_exchange(e0, 0, Ordering::Release, Ordering::Relaxed)
        .is_err()
    {
        lo.fetch_min(prev, Ordering::AcqRel);
    }
}

#[doc(hidden)]
pub const ELEM: u64 = 8;

/// Where a flush calls its test hook: after the snapshot, before the write;
/// or inside the clean step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum FlushStep {
    Write,
    Clean,
}

/// Default max body size for L2 InRam (256 MiB). Over → pure FdOnly L0.
pub const DEFAULT_CLASS_C_INRAM_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Cap for loading Class C arrays into process RAM.
///
/// Env: `RBITCOIN_CLASS_C_INRAM_MAX_MB` (integer MiB). Unset → 256 MiB.
pub fn class_c_inram_max_bytes() -> u64 {
    match std::env::var("RBITCOIN_CLASS_C_INRAM_MAX_MB") {
        Ok(s) => {
            let mb: u64 = s.trim().parse().unwrap_or(256);
            mb.saturating_mul(1024 * 1024)
        }
        Err(_) => DEFAULT_CLASS_C_INRAM_MAX_BYTES,
    }
}

/// Positional file an [`ArrayTable`] persists through: [`TableFile`] in
/// production; the model suite substitutes an in-memory file.
#[doc(hidden)]
pub trait ArrayFile {
    fn logical_len(&self) -> u64;
    /// Fails [`StoreError::Corrupt`] only when the read passes the logical end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError>;
    fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError>;
    fn set_logical_len(&self, logical: u64) -> Result<(), StoreError>;
    fn flush(&self) -> Result<(), StoreError>;
    fn flush_async(&self) -> Result<(), StoreError>;
}

impl ArrayFile for TableFile {
    fn logical_len(&self) -> u64 {
        TableFile::logical_len(self)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        TableFile::read_at(self, offset, buf)
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        TableFile::write_at(self, offset, bytes)
    }

    fn set_logical_len(&self, logical: u64) -> Result<(), StoreError> {
        TableFile::set_logical_len(self, logical)
    }

    fn flush(&self) -> Result<(), StoreError> {
        TableFile::flush(self)
    }

    fn flush_async(&self) -> Result<(), StoreError> {
        TableFile::flush_async(self)
    }
}

pub struct ArrayTable<F: ArrayFile = TableFile> {
    pub file: F,
    pub len: AtomicU64,
    /// `Some` = L2 authoritative image; `None` = L0 fd-only path.
    pub data: RwLock<Option<Vec<u64>>>,
    /// `0` = clean. Nonzero generation: a `set` raced persist if CAS fails.
    pub dirty_epoch: AtomicU64,
    /// Min index mutated since last flush (`u64::MAX` = none).
    pub dirty_lo: AtomicU64,
    /// Element count last successfully flushed to disk (L2).
    pub disk_len: AtomicU64,
    /// One flusher at a time: a second snapshot never lands under an older one.
    pub flush_lock: Mutex<()>,
}

impl ArrayTable {
    pub fn create(path: impl AsRef<Path>, kind: TableKind) -> Result<Self, StoreError> {
        Ok(Self::new(TableFile::create(path.as_ref(), kind)?))
    }

    pub fn open(path: impl AsRef<Path>, kind: TableKind) -> Result<Self, StoreError> {
        Self::load(
            TableFile::open(path.as_ref(), kind)?,
            class_c_inram_max_bytes(),
        )
    }
}

impl<F: ArrayFile> ArrayTable<F> {
    /// Empty table over a file with no body.
    #[doc(hidden)]
    pub fn new(file: F) -> Self {
        Self {
            file,
            len: AtomicU64::new(0),
            data: RwLock::new(Some(Vec::new())),
            dirty_epoch: AtomicU64::new(0),
            dirty_lo: AtomicU64::new(u64::MAX),
            disk_len: AtomicU64::new(0),
            flush_lock: Mutex::new(()),
        }
    }

    /// Table over an existing body. A body up to `inram_max_bytes` loads into
    /// RAM (L2); a larger one stays fd-only (L0).
    #[doc(hidden)]
    pub fn load(file: F, inram_max_bytes: u64) -> Result<Self, StoreError> {
        let body = file.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if !body.is_multiple_of(ELEM) {
            return Err(StoreError::Corrupt("array table size"));
        }
        let n = body / ELEM;
        let data = if body <= inram_max_bytes {
            let mut v = vec![0u64; n as usize];
            if n > 0 {
                let mut bytes = vec![0u8; body as usize];
                file.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
                for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                    v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
                }
            }
            Some(v)
        } else {
            None
        };
        Ok(Self {
            file,
            len: AtomicU64::new(n),
            data: RwLock::new(data),
            dirty_epoch: AtomicU64::new(0),
            dirty_lo: AtomicU64::new(u64::MAX),
            disk_len: AtomicU64::new(n),
            flush_lock: Mutex::new(()),
        })
    }

    pub fn len(&self) -> u64 {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[doc(hidden)]
    pub fn offset(index: u64) -> u64 {
        FILE_HEADER_LEN as u64 + index * ELEM
    }

    #[doc(hidden)]
    pub fn mark_dirty_index(&self, index: u64) {
        dirty_epoch_bump(&self.dirty_epoch);
        let mut cur = self.dirty_lo.load(Ordering::Relaxed);
        while index < cur {
            match self.dirty_lo.compare_exchange_weak(
                cur,
                index,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    pub fn get(&self, index: u64) -> Result<u64, StoreError> {
        let len = self.len.load(Ordering::Acquire);
        if index >= len {
            return Ok(0);
        }
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref v) = *guard {
            // `len` was read before the lock; a truncate may have landed since.
            return Ok(v.get(index as usize).copied().unwrap_or(0));
        }
        drop(guard);
        let mut buf = [0u8; 8];
        self.file.read_at(Self::offset(index), &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn set(&self, index: u64, value: u64) -> Result<(), StoreError> {
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            let need = index as usize + 1;
            if v.len() < need {
                v.resize(need, 0);
            }
            v[index as usize] = value;
            self.len.store(v.len() as u64, Ordering::Release);
            self.mark_dirty_index(index);
            return Ok(());
        }
        drop(guard);
        let len = self.len.load(Ordering::Acquire);
        if index >= len {
            for i in len..index {
                self.file.write_at(Self::offset(i), &0u64.to_le_bytes())?;
            }
            self.file
                .write_at(Self::offset(index), &value.to_le_bytes())?;
            self.len.store(index + 1, Ordering::Release);
        } else {
            self.file
                .write_at(Self::offset(index), &value.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn set_many(&self, pairs: &[(u64, u64)]) -> Result<(), StoreError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let max_idx = pairs.iter().map(|(i, _)| *i).max().unwrap();
        let min_idx = pairs.iter().map(|(i, _)| *i).min().unwrap();
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            let need = max_idx as usize + 1;
            if v.len() < need {
                v.resize(need, 0);
            }
            for &(index, value) in pairs {
                v[index as usize] = value;
            }
            self.len.store(v.len() as u64, Ordering::Release);
            self.mark_dirty_index(min_idx);
            return Ok(());
        }
        drop(guard);
        let len = self.len.load(Ordering::Acquire);
        if max_idx >= len {
            let new_len = max_idx + 1;
            let gap = new_len - len;
            const CHUNK: usize = 1024 * 1024;
            let mut offset = Self::offset(len);
            let mut remaining = gap * ELEM;
            let zeros = vec![0u8; CHUNK];
            while remaining > 0 {
                let n = remaining.min(zeros.len() as u64) as usize;
                self.file.write_at(offset, &zeros[..n])?;
                offset += n as u64;
                remaining -= n as u64;
            }
            self.len.store(new_len, Ordering::Release);
        }
        for &(index, value) in pairs {
            self.file
                .write_at(Self::offset(index), &value.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn truncate(&self, new_len: u64) -> Result<(), StoreError> {
        let len = self.len.load(Ordering::Acquire);
        if new_len > len {
            return Err(StoreError::Corrupt("array truncate grows"));
        }
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            v.truncate(new_len as usize);
            self.len.store(new_len, Ordering::Release);
            // A plain shrink needs no byte write; a later set below `new_len`
            // lowers the mark itself.
            self.mark_dirty_index(new_len);
            return Ok(());
        }
        drop(guard);
        self.len.store(new_len, Ordering::Release);
        let logical = FILE_HEADER_LEN as u64 + new_len * ELEM;
        self.file.set_logical_len(logical)?;
        Ok(())
    }

    /// Persist dirty L2 image. Prefers append-only suffix writes so published
    /// prefix bytes are never overwritten mid-barrier.
    /// In-RAM L2 image bytes (0 when FdOnly).
    pub fn l2_resident_bytes(&self) -> u64 {
        let g = self.data.read().unwrap_or_else(|e| e.into_inner());
        g.as_ref()
            .map(|v| (v.len() as u64).saturating_mul(ELEM))
            .unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn note_flush_clean(&self, e0: u64, between: &mut impl FnMut(&Self, FlushStep)) {
        dirty_try_clean(&self.dirty_epoch, &self.dirty_lo, e0, || {
            between(self, FlushStep::Clean)
        });
    }

    pub fn flush_dirty(&self) -> Result<(), StoreError> {
        self.flush_dirty_between(|_, _| {})
    }

    #[doc(hidden)]
    pub fn flush_dirty_between(
        &self,
        mut between: impl FnMut(&Self, FlushStep),
    ) -> Result<(), StoreError> {
        let _one = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref v) = *guard else {
            return Ok(());
        };
        let e0 = self.dirty_epoch.load(Ordering::Acquire);
        if e0 == 0 {
            return Ok(());
        }
        let n = v.len() as u64;
        let disk = self.disk_len.load(Ordering::Acquire);
        let dirty_lo = self.dirty_lo.load(Ordering::Acquire);

        if n < disk && dirty_lo >= n {
            drop(guard);
            between(self, FlushStep::Write);
            let logical = FILE_HEADER_LEN as u64 + n * ELEM;
            self.file.set_logical_len(logical)?;
            self.disk_len.store(n, Ordering::Release);
            self.note_flush_clean(e0, &mut between);
            return Ok(());
        }

        if n == disk && dirty_lo >= disk {
            drop(guard);
            between(self, FlushStep::Write);
            self.note_flush_clean(e0, &mut between);
            return Ok(());
        }

        if dirty_lo >= disk && n > disk {
            let start = disk as usize;
            let mut bytes = vec![0u8; ((n - disk) as usize) * 8];
            for (i, &val) in v[start..].iter().enumerate() {
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
            }
            drop(guard);
            between(self, FlushStep::Write);
            self.file.write_at(Self::offset(disk), &bytes)?;
            let logical = FILE_HEADER_LEN as u64 + n * ELEM;
            debug_assert_eq!(self.file.logical_len(), logical);
            let _ = logical;
            self.disk_len.store(n, Ordering::Release);
            self.note_flush_clean(e0, &mut between);
            return Ok(());
        }

        let from = dirty_lo.min(n);
        let mut bytes = vec![0u8; ((n - from) as usize) * 8];
        for (i, &val) in v[from as usize..].iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }
        drop(guard);
        between(self, FlushStep::Write);
        if !bytes.is_empty() {
            self.file.write_at(Self::offset(from), &bytes)?;
        }
        if n != disk {
            let logical = FILE_HEADER_LEN as u64 + n * ELEM;
            self.file.set_logical_len(logical)?;
        }
        self.disk_len.store(n, Ordering::Release);
        self.note_flush_clean(e0, &mut between);
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.file.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.file.flush_async()
    }
}
