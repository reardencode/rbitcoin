//! Class C tip/confirmation tables and Class A header→tx ranges.

use crate::array_table::ArrayTable;
use crate::error::StoreError;
use crate::sync::atomic::AtomicU64;
use rbitcoin_primitives::{Fk, Height, TableKind};
use std::path::Path;

/// Best-chain height → header fk. Length = tip_height + 1 when non-empty.
pub struct ConfirmedTable {
    pub arr: ArrayTable,
}

impl ConfirmedTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            arr: ArrayTable::create(dir.join("confirmed.body"), TableKind::Confirmed)?,
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            arr: ArrayTable::open(dir.join("confirmed.body"), TableKind::Confirmed)?,
        })
    }

    pub fn l2_resident_bytes(&self) -> u64 {
        self.arr.l2_resident_bytes()
    }

    pub fn tip_height(&self) -> Option<Height> {
        let n = self.arr.len();
        if n == 0 {
            None
        } else {
            Some(Height((n - 1) as u32))
        }
    }

    pub fn get(&self, height: Height) -> Result<Option<Fk>, StoreError> {
        let v = self.arr.get(u64::from(height.0))?;
        Ok(Fk::new(v))
    }

    /// Batch height → header_fk (0-based height indices). Missing/unset → `None`.
    pub fn get_many(&self, heights: &[Height]) -> Result<Vec<Option<Fk>>, StoreError> {
        let mut out = Vec::with_capacity(heights.len());
        for &h in heights {
            out.push(self.get(h)?);
        }
        Ok(out)
    }

    /// Write a raw slot, including 0. For tests that need a tip length with
    /// no header fk. Production `set` refuses 0.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn set_raw_for_test(&self, height: Height, value: u64) -> Result<(), StoreError> {
        self.arr.set(u64::from(height.0), value)
    }

    pub fn set(&self, height: Height, header_fk: Fk) -> Result<(), StoreError> {
        if header_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        self.arr.set(u64::from(height.0), header_fk.0)
    }

    /// Set many height→header_fk pairs (one grow for max height, then bulk writes).
    ///
    /// Used by multi-block Class C confirm so tip extension is not N separate grows.
    pub fn set_many(&self, pairs: &[(Height, Fk)]) -> Result<(), StoreError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut raw = Vec::with_capacity(pairs.len());
        for &(h, fk) in pairs {
            if fk.is_null() {
                return Err(StoreError::InvalidFk);
            }
            raw.push((u64::from(h.0), fk.0));
        }
        self.arr.set_many(&raw)
    }

    /// Drop a trailing run of null header fks (HWM ahead of last real tip).
    ///
    /// Returns how many slots were removed. Mid-array holes are left for
    /// [`Store::revalidate_tip_window_n`] to shrink to last good.
    pub fn trim_trailing_nulls(&self) -> Result<u64, StoreError> {
        let n = self.arr.len();
        if n == 0 {
            return Ok(0);
        }
        let mut keep = n;
        while keep > 0 {
            let v = self.arr.get(keep - 1)?;
            if Fk::new(v).is_some() {
                break;
            }
            keep -= 1;
        }
        let trimmed = n - keep;
        if trimmed > 0 {
            self.arr.truncate(keep)?;
        }
        Ok(trimmed)
    }

    /// Disconnect tip: height must be current tip.
    pub fn disconnect_tip(&self, height: Height) -> Result<(), StoreError> {
        match self.tip_height() {
            Some(t) if t == height => {
                self.arr.truncate(u64::from(height.0))?;
                Ok(())
            }
            Some(_) => Err(StoreError::Corrupt("disconnect not at tip")),
            None => Err(StoreError::Corrupt("disconnect empty chain")),
        }
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.arr.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.arr.flush_async()
    }
}

/// Per-tx strong bit (schema v3): bit `(tx_fk - 1)` set ⇒ strong on best chain.
///
/// ~64× smaller than u64-per-tx; call sites only need `is_strong`. Header fk is
/// not stored (derived from confirmed range when needed).
///
/// Always L2 write-behind (unlike [`crate::array_table::class_c_inram_max_bytes`],
/// which still caps `confirmed` / `header_txs_*`). 1 bit/tx stays in RAM.
pub struct StrongTxTable {
    pub bits: crate::file::TableFile,
    /// Number of bits allocated (covers tx fks 1..=n_bits).
    pub n_bits: AtomicU64,
    /// L2 byte image. `strong_tx` stays in this `Vec`; open and create never go FdOnly.
    pub data: std::sync::RwLock<Vec<u8>>,
    /// `0` = clean. Nonzero generation: a bit `set` raced persist if CAS fails.
    pub dirty_epoch: AtomicU64,
    /// Min bit index mutated since last flush (`u64::MAX` = none).
    pub dirty_lo_bit: AtomicU64,
    /// Body byte length last flushed to disk (L2).
    pub disk_bytes: AtomicU64,
}

impl StrongTxTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            bits: crate::file::TableFile::create(dir.join("strong_tx.body"), TableKind::StrongTx)?,
            n_bits: AtomicU64::new(0),
            data: std::sync::RwLock::new(Vec::new()),
            dirty_epoch: AtomicU64::new(0),
            dirty_lo_bit: AtomicU64::new(u64::MAX),
            disk_bytes: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let bits = crate::file::TableFile::open(dir.join("strong_tx.body"), TableKind::StrongTx)?;
        let body = bits
            .logical_len()
            .saturating_sub(crate::file::FILE_HEADER_LEN as u64);
        let n_bits = body.saturating_mul(8);
        let mut v = vec![0u8; body as usize];
        if body > 0 {
            bits.read_at(crate::file::FILE_HEADER_LEN as u64, &mut v)?;
        }
        Ok(Self {
            bits,
            n_bits: AtomicU64::new(n_bits),
            data: std::sync::RwLock::new(v),
            dirty_epoch: AtomicU64::new(0),
            dirty_lo_bit: AtomicU64::new(u64::MAX),
            disk_bytes: AtomicU64::new(body),
        })
    }

    #[doc(hidden)]
    pub fn mark_dirty_bit(&self, bit: u64) {
        use std::sync::atomic::Ordering;
        crate::array_table::dirty_epoch_bump(&self.dirty_epoch);
        let mut cur = self.dirty_lo_bit.load(Ordering::Relaxed);
        while bit < cur {
            match self.dirty_lo_bit.compare_exchange_weak(
                cur,
                bit,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    #[doc(hidden)]
    pub fn ensure_bits(&self, need_bits: u64) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let n = self.n_bits.load(Ordering::Acquire);
        if need_bits <= n {
            return Ok(());
        }
        let need_bytes = need_bits.div_ceil(8);
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if need_bytes as usize > guard.len() {
            guard.resize(need_bytes as usize, 0);
        }
        self.n_bits.store(need_bits, Ordering::Release);
        // Growth alone is not a bit mutate; callers set_bit mark dirty.
        Ok(())
    }

    #[doc(hidden)]
    pub fn get_bit(&self, bit: u64) -> Result<bool, StoreError> {
        use std::sync::atomic::Ordering;
        let n = self.n_bits.load(Ordering::Acquire);
        if bit >= n {
            return Ok(false);
        }
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let bi = (bit / 8) as usize;
        Ok((guard[bi] >> (bit % 8)) & 1 != 0)
    }

    #[doc(hidden)]
    pub fn set_bit(&self, bit: u64, on: bool) -> Result<(), StoreError> {
        self.ensure_bits(bit + 1)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        let bi = (bit / 8) as usize;
        if on {
            guard[bi] |= 1 << (bit % 8);
        } else {
            guard[bi] &= !(1 << (bit % 8));
        }
        self.mark_dirty_bit(bit);
        Ok(())
    }

    /// Compatibility: Some(dummy nonzero) if strong, else None.
    pub fn get(&self, tx_fk: Fk) -> Result<Option<Fk>, StoreError> {
        if self.is_strong(tx_fk)? {
            Ok(Some(Fk(1)))
        } else {
            Ok(None)
        }
    }

    /// In-RAM L2 bit-image bytes.
    pub fn l2_resident_bytes(&self) -> u64 {
        let g = self.data.read().unwrap_or_else(|e| e.into_inner());
        g.len() as u64
    }

    pub fn set_strong(&self, tx_fk: Fk, header_fk: Fk) -> Result<(), StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if header_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        self.set_bit(id - 1, true)
    }

    /// Mark many consecutive tx fks strong (one ensure + bulk byte writes).
    pub fn set_strong_range(
        &self,
        first_tx_fk: Fk,
        count: u32,
        header_fk: Fk,
    ) -> Result<(), StoreError> {
        let id = first_tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if header_fk.is_null() || count == 0 {
            return if count == 0 {
                Ok(())
            } else {
                Err(StoreError::InvalidFk)
            };
        }
        let start = id - 1;
        let end = start + u64::from(count);
        self.set_bits_range(start, end, true)
    }

    /// Set bits in half-open `[start, end)` (bit indices).
    #[doc(hidden)]
    pub fn set_bits_range(&self, start: u64, end: u64, on: bool) -> Result<(), StoreError> {
        if end <= start {
            return Ok(());
        }
        self.ensure_bits(end)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        let mut bit = start;
        while bit < end {
            let bi = (bit / 8) as usize;
            if on {
                guard[bi] |= 1 << (bit % 8);
            } else {
                guard[bi] &= !(1 << (bit % 8));
            }
            bit += 1;
        }
        self.mark_dirty_bit(start);
        Ok(())
    }

    pub fn set_unstrong(&self, tx_fk: Fk) -> Result<(), StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        let n = self.n_bits.load(std::sync::atomic::Ordering::Acquire);
        if id > n {
            return Ok(());
        }
        self.set_bit(id - 1, false)
    }

    /// Clear many consecutive strong bits (Class C repair / disconnect ranges).
    pub fn set_unstrong_range(&self, first_tx_fk: Fk, count: u32) -> Result<(), StoreError> {
        let id = first_tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if count == 0 {
            return Ok(());
        }
        let start = id - 1;
        let end = start + u64::from(count);
        let n = self.n_bits.load(std::sync::atomic::Ordering::Acquire);
        if start >= n {
            return Ok(());
        }
        let end = end.min(n);
        self.set_bits_range(start, end, false)
    }

    pub fn is_strong(&self, tx_fk: Fk) -> Result<bool, StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        self.get_bit(id - 1)
    }

    /// Allocated bit count (covers create fks `1..=n`).
    pub fn allocated_bits(&self) -> u64 {
        self.n_bits.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Count set bits for create fks in half-open `[start_fk, end_fk)`.
    pub fn count_strong_in_fk_range(&self, start_fk: u64, end_fk: u64) -> Result<u64, StoreError> {
        if start_fk == 0 || end_fk <= start_fk {
            return Ok(0);
        }
        let n = self.allocated_bits();
        if start_fk > n {
            return Ok(0);
        }
        let start_bit = start_fk - 1;
        let end_bit = (end_fk - 1).min(n);
        self.count_ones_bits(start_bit, end_bit)
    }

    #[doc(hidden)]
    pub fn count_ones_bits(&self, start_bit: u64, end_bit: u64) -> Result<u64, StoreError> {
        if end_bit <= start_bit {
            return Ok(0);
        }
        let mut ones = 0u64;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let mut bit = start_bit;
        while bit < end_bit {
            let bi = (bit / 8) as usize;
            let b = guard[bi];
            if b == 0 {
                bit = (bit + 8) & !7;
                continue;
            }
            let off = (bit % 8) as u32;
            if (b >> off) & 1 != 0 {
                ones += 1;
            }
            bit += 1;
        }
        Ok(ones)
    }

    /// Read `dst.len()` bit-image bytes starting at payload byte `byte_off`.
    pub fn read_bit_bytes(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), StoreError> {
        if dst.is_empty() {
            return Ok(());
        }
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let start = byte_off as usize;
        let end = start.saturating_add(dst.len()).min(guard.len());
        if start >= guard.len() {
            dst.fill(0);
            return Ok(());
        }
        let n = end - start;
        dst[..n].copy_from_slice(&guard[start..end]);
        dst[n..].fill(0);
        Ok(())
    }

    /// True when every fk in `[first, first+count)` is strong.
    pub fn all_strong_range(&self, first_tx_fk: Fk, count: u32) -> Result<bool, StoreError> {
        let id = first_tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if count == 0 {
            return Ok(true);
        }
        let ones = self.count_strong_in_fk_range(id, id.saturating_add(u64::from(count)))?;
        Ok(ones == u64::from(count))
    }

    /// Persist dirty L2 bit image. Prefers append-only byte suffix writes.
    pub fn flush_dirty(&self) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let v = &*guard;
        let e0 = self.dirty_epoch.load(Ordering::Acquire);
        if e0 == 0 {
            return Ok(());
        }
        let body_len = v.len() as u64;
        let disk = self.disk_bytes.load(Ordering::Acquire);
        let dirty_lo = self.dirty_lo_bit.load(Ordering::Acquire);

        let dirty_byte = if dirty_lo == u64::MAX {
            body_len
        } else {
            dirty_lo / 8
        };

        if body_len > disk && dirty_byte >= disk {
            let suffix = v[disk as usize..].to_vec();
            drop(guard);
            if !suffix.is_empty() {
                self.bits
                    .write_at(crate::file::FILE_HEADER_LEN as u64 + disk, &suffix)?;
            }
            self.disk_bytes.store(body_len, Ordering::Release);
            crate::array_table::dirty_try_clean(&self.dirty_epoch, &self.dirty_lo_bit, e0, || {});
            return Ok(());
        }

        let from = dirty_byte.min(body_len);
        let suffix = v[from as usize..].to_vec();
        drop(guard);
        if !suffix.is_empty() {
            self.bits
                .write_at(crate::file::FILE_HEADER_LEN as u64 + from, &suffix)?;
        }
        if body_len != disk {
            let logical = crate::file::FILE_HEADER_LEN as u64 + body_len;
            self.bits.set_logical_len(logical)?;
        }
        self.disk_bytes.store(body_len, Ordering::Release);
        crate::array_table::dirty_try_clean(&self.dirty_epoch, &self.dirty_lo_bit, e0, || {});
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.bits.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.bits.flush_async()
    }
}

/// Per-header **contiguous** tx_fk range (Class A archive body association).
///
/// Schema v2 stores `(first_tx_fk, count)` only — not a u64 fk vector.
/// Writer must assign contiguous FKs per block (archive plan does).
///
/// - `first.body[header_fk-1]` = first_tx_fk (0 = no body)
/// - `count.body[header_fk-1]` = n txs (0 = no body)
pub struct HeaderTxsTable {
    pub first: ArrayTable,
    pub count: ArrayTable,
}

impl HeaderTxsTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            first: ArrayTable::create(dir.join("header_txs_first.body"), TableKind::ArrayLink)?,
            count: ArrayTable::create(dir.join("header_txs_count.body"), TableKind::ArrayLink)?,
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            first: ArrayTable::open(dir.join("header_txs_first.body"), TableKind::ArrayLink)?,
            count: ArrayTable::open(dir.join("header_txs_count.body"), TableKind::ArrayLink)?,
        })
    }

    pub fn l2_resident_bytes(&self) -> u64 {
        self.first
            .l2_resident_bytes()
            .saturating_add(self.count.l2_resident_bytes())
    }

    /// Store a contiguous range. `tx_fks` must be non-empty and contiguous.
    pub fn put_list(&self, header_fk: Fk, tx_fks: &[Fk]) -> Result<(), StoreError> {
        if tx_fks.is_empty() {
            return Err(StoreError::Corrupt("empty header tx list"));
        }
        debug_assert!(
            tx_fks
                .windows(2)
                .all(|w| w[1].0 == w[0].0.saturating_add(1)),
            "header_txs must be contiguous"
        );
        if !tx_fks
            .windows(2)
            .all(|w| w[1].0 == w[0].0.saturating_add(1))
        {
            return Err(StoreError::Corrupt("header_txs not contiguous"));
        }
        self.put_range(header_fk, tx_fks[0], tx_fks.len() as u32)
    }

    pub fn put_range(&self, header_fk: Fk, first_tx_fk: Fk, n: u32) -> Result<(), StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        if first_tx_fk.is_null() || n == 0 {
            return Err(StoreError::InvalidFk);
        }
        self.first.set(id - 1, first_tx_fk.0)?;
        self.count.set(id - 1, u64::from(n))?;
        Ok(())
    }

    /// Batch-append many header→tx ranges.
    pub fn put_lists_batch(&self, items: &[(Fk, &[Fk])]) -> Result<(), StoreError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut first_pairs = Vec::with_capacity(items.len());
        let mut count_pairs = Vec::with_capacity(items.len());
        for (header_fk, tx_fks) in items {
            if tx_fks.is_empty() {
                return Err(StoreError::Corrupt("empty header tx list"));
            }
            if !tx_fks
                .windows(2)
                .all(|w| w[1].0 == w[0].0.saturating_add(1))
            {
                return Err(StoreError::Corrupt("header_txs not contiguous"));
            }
            let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
            first_pairs.push((id - 1, tx_fks[0].0));
            count_pairs.push((id - 1, tx_fks.len() as u64));
        }
        self.first.set_many(&first_pairs)?;
        self.count.set_many(&count_pairs)?;
        Ok(())
    }

    /// Batch store ranges without expanding fk vectors.
    pub fn put_ranges_batch(&self, items: &[(Fk, Fk, u32)]) -> Result<(), StoreError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut first_pairs = Vec::with_capacity(items.len());
        let mut count_pairs = Vec::with_capacity(items.len());
        for &(header_fk, first_tx_fk, n) in items {
            let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
            if first_tx_fk.is_null() || n == 0 {
                return Err(StoreError::InvalidFk);
            }
            first_pairs.push((id - 1, first_tx_fk.0));
            count_pairs.push((id - 1, u64::from(n)));
        }
        self.first.set_many(&first_pairs)?;
        self.count.set_many(&count_pairs)?;
        Ok(())
    }

    pub fn get_range(&self, header_fk: Fk) -> Result<Option<(Fk, u32)>, StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        if id > self.first.len() {
            return Ok(None);
        }
        let first_raw = self.first.get(id - 1)?;
        let Some(first) = Fk::new(first_raw) else {
            return Ok(None);
        };
        let n = self.count.get(id - 1)?;
        if n == 0 || n > u64::from(u32::MAX) {
            return Ok(None);
        }
        Ok(Some((first, n as u32)))
    }

    /// Expand range to a vec of fks (convenience for existing call sites).
    pub fn get_list(&self, header_fk: Fk) -> Result<Option<Vec<Fk>>, StoreError> {
        let Some((first, n)) = self.get_range(header_fk)? else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(n as usize);
        for i in 0..n {
            out.push(Fk(first.0 + u64::from(i)));
        }
        Ok(Some(out))
    }

    pub fn has_body(&self, header_fk: Fk) -> Result<bool, StoreError> {
        Ok(self.get_range(header_fk)?.is_some())
    }

    /// Index of `tx_fk` inside a contiguous `(first, count)` span.
    pub fn index_in_span(first: Fk, n: u32, tx_fk: Fk) -> Option<u32> {
        let tid = tx_fk.get()?;
        let lo = first.get()?;
        if n == 0 {
            return None;
        }
        let end = lo.saturating_add(u64::from(n));
        if tid < lo || tid >= end {
            return None;
        }
        u32::try_from(tid - lo).ok()
    }

    /// True if `tx_fk` is in this header's contiguous Class A body range.
    pub fn contains_tx(&self, header_fk: Fk, tx_fk: Fk) -> Result<bool, StoreError> {
        Ok(self.tx_index(header_fk, tx_fk)?.is_some())
    }

    /// Index of `tx_fk` in this header's contiguous Class A range.
    ///
    /// One `(first, count)` read. Does not expand the block's fk list.
    pub fn tx_index(&self, header_fk: Fk, tx_fk: Fk) -> Result<Option<u32>, StoreError> {
        let Some((first, n)) = self.get_range(header_fk)? else {
            return Ok(None);
        };
        Ok(Self::index_in_span(first, n, tx_fk))
    }

    /// Drop Class A body association for `header_fk` (does not free tx rows).
    ///
    /// Used when reconstruct produces a block that fails header checks (e.g.
    /// merkle root mismatch) — the header hash is fine; the association is bad.
    pub fn clear_body(&self, header_fk: Fk) -> Result<bool, StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        if id == 0 {
            return Err(StoreError::InvalidFk);
        }
        let had = self.has_body(header_fk)?;
        if !had {
            return Ok(false);
        }
        // Ensure array slots exist then zero (0 = no body).
        let idx = id - 1;
        if idx >= self.first.len() {
            return Ok(false);
        }
        self.first.set(idx, 0)?;
        self.count.set(idx, 0)?;
        Ok(true)
    }

    /// Number of headers that currently have a Class A body (`count > 0`).
    ///
    /// Full-array scan — use only for rare status/startup (`archived_block_count`).
    /// **Not** on the plan hot path: Class A never leads tip, so plan must not
    /// call this for “archive far ahead” heuristics.
    pub fn count_bodies(&self) -> Result<u64, StoreError> {
        let n = self.count.len();
        let mut total = 0u64;
        for i in 0..n {
            let c = self.count.get(i)?;
            if c > 0 {
                total += 1;
            }
        }
        Ok(total)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.first.flush()?;
        self.count.flush()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.first.flush_async()?;
        self.count.flush_async()?;
        Ok(())
    }
}
