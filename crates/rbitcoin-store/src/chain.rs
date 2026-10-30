//! Class C tip/confirmation tables and Class A header→tx ranges.

use crate::array_table::{copy_bit_bytes, seq_odd, seq_read, ArrayTable, ClassCWrite, FlushStep};
use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::sync::atomic::{AtomicU64, Ordering};
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
        (n != 0).then(|| Height((n - 1) as u32))
    }

    pub fn get(&self, height: Height) -> Result<Option<Fk>, StoreError> {
        let v = self.arr.get(u64::from(height.0))?;
        Ok(Fk::new(v))
    }

    /// `confirmed[height]`, `confirmed[height + 1]`, and the tip, from one
    /// sample.
    pub fn get_pair_with_tip(
        &self,
        height: Height,
    ) -> Result<([Option<Fk>; 2], Option<Height>), StoreError> {
        let ([at, next], n) = self.arr.get_pair_sample(u64::from(height.0))?;
        let tip = (n != 0).then(|| Height((n - 1) as u32));
        Ok(([Fk::new(at), Fk::new(next)], tip))
    }

    /// Batch height → header_fk (0-based height indices). Missing/unset → `None`.
    pub fn get_many(&self, heights: &[Height]) -> Result<Vec<Option<Fk>>, StoreError> {
        heights.iter().map(|&h| self.get(h)).collect()
    }

    /// Write a raw slot, including 0. For tests that need a tip length with
    /// no header fk. Production `set` refuses 0.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn set_raw_for_test(
        &self,
        write: &ClassCWrite,
        height: Height,
        value: u64,
    ) -> Result<(), StoreError> {
        self.arr.set(write, u64::from(height.0), value)
    }

    pub fn set(
        &self,
        write: &ClassCWrite,
        height: Height,
        header_fk: Fk,
    ) -> Result<(), StoreError> {
        if header_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        self.arr.set(write, u64::from(height.0), header_fk.0)
    }

    /// Set many height→header_fk pairs (one grow for max height, then bulk writes).
    ///
    /// Used by multi-block Class C confirm so tip extension is not N separate grows.
    pub fn set_many(&self, write: &ClassCWrite, pairs: &[(Height, Fk)]) -> Result<(), StoreError> {
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
        self.arr.set_many(write, &raw)
    }

    /// Drop a trailing run of null header fks (HWM ahead of last real tip).
    ///
    /// Returns how many slots were removed. Mid-array holes are left for
    /// [`Store::revalidate_tip_window_n`] to shrink to last good.
    pub fn trim_trailing_nulls(&self, write: &ClassCWrite) -> Result<u64, StoreError> {
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
            self.arr.truncate(write, keep)?;
        }
        Ok(trimmed)
    }

    /// Disconnect tip: height must be current tip.
    pub fn disconnect_tip(&self, write: &ClassCWrite, height: Height) -> Result<(), StoreError> {
        match self.tip_height() {
            Some(t) if t == height => {
                self.arr.truncate(write, u64::from(height.0))?;
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
/// ~64× smaller than a `u64` per tx; the header fk comes from the confirmed range.
/// Always in RAM, ignoring [`crate::array_table::class_c_inram_max_bytes`].
/// The words are [`ArrayTable`]'s slot buffer. Its length is body bytes, not
/// rounded up to a word. Flush is that table's flush.
pub struct StrongTxTable {
    pub table: ArrayTable,
    /// Number of bits allocated (covers tx fks 1..=n_bits).
    pub n_bits: AtomicU64,
}

impl StrongTxTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        let file = TableFile::create(dir.join("strong_tx.body"), TableKind::StrongTx)?;
        Ok(Self {
            table: ArrayTable::bit_image(file, 0)?,
            n_bits: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let bits = TableFile::open(dir.join("strong_tx.body"), TableKind::StrongTx)?;
        let body = bits.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        let mut bytes = vec![0u8; body as usize];
        if body > 0 {
            bits.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
        }
        let table = ArrayTable::bit_image(bits, body)?;
        if body > 0 {
            table.slots.grow((body as usize).div_ceil(8))?;
            Self::copy_bytes_in(table.slots.slots(Ordering::Relaxed), &bytes);
        }
        Ok(Self {
            table,
            n_bits: AtomicU64::new(body.saturating_mul(8)),
        })
    }

    fn ensure_held(&self, need_bits: u64) -> Result<(), StoreError> {
        if need_bits <= self.n_bits.load(Ordering::Relaxed) {
            return Ok(());
        }
        let need_bytes = need_bits.div_ceil(8) as usize;
        self.table.slots.grow(need_bytes.div_ceil(8))?;
        self.table.len.store(need_bytes as u64, Ordering::Relaxed);
        self.n_bits.store(need_bits, Ordering::Relaxed);
        Ok(())
    }

    fn for_each_mask(start: u64, end: u64, mut f: impl FnMut(usize, u64)) {
        let mut bit = start;
        while bit < end {
            let wi = (bit / 64) as usize;
            let word_lo = (wi as u64) * 64;
            let lo = bit - word_lo;
            let hi = end.min(word_lo + 64) - word_lo;
            // `u64::MAX << lo` is `MAX ^ ((1 << lo) - 1)`. A short word stops at `hi`.
            let hi_bits = if hi == 64 { u64::MAX } else { (1u64 << hi) - 1 };
            let mask = hi_bits ^ ((1u64 << lo) - 1);
            f(wi, mask);
            bit = word_lo + hi;
        }
    }

    fn apply_bits(&self, start: u64, end: u64, on: bool) {
        let words = self.table.slots.slots(Ordering::Relaxed);
        Self::for_each_mask(start, end, |wi, mask| {
            if on {
                words[wi].fetch_or(mask, Ordering::Relaxed);
            } else {
                words[wi].fetch_and(!mask, Ordering::Relaxed);
            }
        });
    }

    fn count_word_ones(words: &[AtomicU64], start: u64, end: u64) -> u64 {
        let mut ones = 0u64;
        Self::for_each_mask(start, end, |wi, mask| {
            ones += (words[wi].load(Ordering::Relaxed) & mask).count_ones() as u64;
        });
        ones
    }

    fn store_byte(words: &[AtomicU64], index: usize, value: u8) {
        let w = &words[index / 8];
        let shift = (index % 8) * 8;
        let update = |cur: u64| Some((cur & !(0xffu64 << shift)) | (u64::from(value) << shift));
        // loom 0.7 still names this `fetch_update`. std renamed it `try_update`.
        #[cfg(loom)]
        let _ = w.fetch_update(Ordering::Relaxed, Ordering::Relaxed, update);
        #[cfg(not(loom))]
        let _ = w.try_update(Ordering::Relaxed, Ordering::Relaxed, update);
    }

    fn copy_bytes_in(words: &[AtomicU64], src: &[u8]) {
        for (i, chunk) in src.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            words[i].store(u64::from_le_bytes(buf), Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn mark_dirty_bit(&self, bit: u64) {
        let _ = self.table.unstored_from.fetch_min(bit, Ordering::AcqRel);
    }

    #[doc(hidden)]
    pub fn ensure_bits(&self, _write: &ClassCWrite, need_bits: u64) -> Result<(), StoreError> {
        if need_bits <= self.n_bits.load(Ordering::Acquire) {
            return Ok(());
        }
        let _odd = self.table.begin_store()?;
        self.ensure_held(need_bits)?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn get_bit(&self, bit: u64) -> Result<bool, StoreError> {
        Ok(seq_read(&self.table.seq, || {
            let n = self.n_bits.load(Ordering::Relaxed);
            if bit >= n {
                return Some(false);
            }
            let words = self.table.slots.try_slots((bit / 64) as usize + 1)?;
            let word = words[(bit / 64) as usize].load(Ordering::Relaxed);
            Some((word >> (bit % 64)) & 1 == 1)
        }))
    }

    #[doc(hidden)]
    pub fn set_bit(&self, write: &ClassCWrite, bit: u64, on: bool) -> Result<(), StoreError> {
        self.set_bits_range(write, bit, bit + 1, on)
    }

    /// Compatibility: Some(dummy nonzero) if strong, else None.
    pub fn get(&self, tx_fk: Fk) -> Result<Option<Fk>, StoreError> {
        Ok(self.is_strong(tx_fk)?.then_some(Fk(1)))
    }

    /// In-RAM L2 bit-image bytes.
    pub fn l2_resident_bytes(&self) -> u64 {
        self.table.l2_resident_bytes()
    }

    /// Bytes committed for the bit image. The logical body can be shorter.
    #[doc(hidden)]
    pub fn committed_bytes(&self) -> u64 {
        self.table.slots.committed_bytes()
    }

    /// Set one live body byte without the sequence counter. Flush tests use
    /// this to show the persist reads the image the writer would read.
    #[doc(hidden)]
    pub fn poke_live_byte(&self, index: usize, value: u8) {
        Self::store_byte(self.table.slots.slots(Ordering::Acquire), index, value);
    }

    pub fn set_strong(
        &self,
        write: &ClassCWrite,
        tx_fk: Fk,
        header_fk: Fk,
    ) -> Result<(), StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if header_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        self.set_bit(write, id - 1, true)
    }

    /// Mark many consecutive tx fks strong (one ensure + bulk byte writes).
    pub fn set_strong_range(
        &self,
        write: &ClassCWrite,
        first_tx_fk: Fk,
        count: u32,
        header_fk: Fk,
    ) -> Result<(), StoreError> {
        if count == 0 {
            return Ok(());
        }
        if header_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        let id = first_tx_fk.get().ok_or(StoreError::InvalidFk)?;
        let start = id - 1;
        let end = start + u64::from(count);
        self.set_bits_range(write, start, end, true)
    }

    /// Set bits in half-open `[start, end)` (bit indices).
    #[doc(hidden)]
    pub fn set_bits_range(
        &self,
        _write: &ClassCWrite,
        start: u64,
        end: u64,
        on: bool,
    ) -> Result<(), StoreError> {
        if end <= start {
            return Ok(());
        }
        let _odd = self.table.begin_store()?;
        self.ensure_held(end)?;
        self.apply_bits(start, end, on);
        self.mark_dirty_bit(start);
        Ok(())
    }

    pub fn set_unstrong(&self, write: &ClassCWrite, tx_fk: Fk) -> Result<(), StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        let n = self.n_bits.load(Ordering::Acquire);
        if id > n {
            return Ok(());
        }
        self.set_bit(write, id - 1, false)
    }

    /// Clear many consecutive strong bits (Class C repair / disconnect ranges).
    pub fn set_unstrong_range(
        &self,
        write: &ClassCWrite,
        first_tx_fk: Fk,
        count: u32,
    ) -> Result<(), StoreError> {
        let id = first_tx_fk.get().ok_or(StoreError::InvalidFk)?;
        if count == 0 {
            return Ok(());
        }
        let start = id - 1;
        let end = start + u64::from(count);
        let n = self.n_bits.load(Ordering::Acquire);
        if start >= n {
            return Ok(());
        }
        let end = end.min(n);
        self.set_bits_range(write, start, end, false)
    }

    pub fn is_strong(&self, tx_fk: Fk) -> Result<bool, StoreError> {
        let id = tx_fk.get().ok_or(StoreError::InvalidFk)?;
        self.get_bit(id - 1)
    }

    /// Allocated bit count (covers create fks `1..=n`).
    pub fn allocated_bits(&self) -> u64 {
        self.n_bits.load(Ordering::Acquire)
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
        Ok(seq_read(&self.table.seq, || {
            let n = self.n_bits.load(Ordering::Relaxed);
            let end = end_bit.min(n);
            if end <= start_bit {
                return Some(0);
            }
            let words = self.table.slots.try_slots(((end - 1) / 64) as usize + 1)?;
            Some(Self::count_word_ones(words, start_bit, end))
        }))
    }

    /// Read `dst.len()` bit-image bytes starting at payload byte `byte_off`.
    pub fn read_bit_bytes(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), StoreError> {
        if dst.is_empty() {
            return Ok(());
        }
        seq_read(&self.table.seq, || {
            let n = self.table.len.load(Ordering::Relaxed) as usize;
            let start = byte_off as usize;
            if start >= n {
                dst.fill(0);
                return Some(());
            }
            let take = dst.len().min(n - start);
            let last = start + take - 1;
            let words = self.table.slots.try_slots(last / 8 + 1)?;
            copy_bit_bytes(words, start, &mut dst[..take]);
            dst[take..].fill(0);
            Some(())
        });
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

    /// Persist dirty L2 bit image by reading live bytes. The unstored mark
    /// clears only after the length publish succeeds.
    pub fn flush_dirty(&self) -> Result<(), StoreError> {
        self.table.flush_dirty()
    }

    /// Same flush as [`ArrayTable::flush_dirty_between`]. The hook sees this
    /// table so a test can store during admit or the write.
    #[doc(hidden)]
    pub fn flush_observing(
        &self,
        mut between: impl FnMut(&Self, FlushStep),
    ) -> Result<(), StoreError> {
        let this = self as *const Self;
        // SAFETY: `this` is `self`, and the hook runs before this method
        // returns. Both uses are shared.
        self.table
            .flush_dirty_between(|_, step| between(unsafe { &*this }, step))
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.table.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.table.flush_async()
    }
}

/// Per-header contiguous tx_fk range (Class A). Schema v2 stores `(first, count)`
/// only, and the writer assigns contiguous fks per block.
/// `first.body[header_fk-1]` is the first tx fk (0 = no body).
/// `count.body[header_fk-1]` is the tx count (0 = no body).
///
/// `put_range`, `put_lists_batch`, `put_ranges_batch`, and `clear_body` store
/// the first column, then the count, under one pair counter. If the count
/// store returns an error, `get_range` can accept the new first with the
/// previous count once the call returns.
pub struct HeaderTxsTable {
    pub first: ArrayTable,
    pub count: ArrayTable,
    /// One counter for a header's `(first, count)` pair.
    seq: AtomicU64,
}

impl HeaderTxsTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            first: ArrayTable::create(dir.join("header_txs_first.body"), TableKind::ArrayLink)?,
            count: ArrayTable::create(dir.join("header_txs_count.body"), TableKind::ArrayLink)?,
            seq: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            first: ArrayTable::open(dir.join("header_txs_first.body"), TableKind::ArrayLink)?,
            count: ArrayTable::open(dir.join("header_txs_count.body"), TableKind::ArrayLink)?,
            seq: AtomicU64::new(0),
        })
    }

    pub fn l2_resident_bytes(&self) -> u64 {
        self.first
            .l2_resident_bytes()
            .saturating_add(self.count.l2_resident_bytes())
    }

    /// Store a contiguous range. `tx_fks` must be non-empty and contiguous.
    pub fn put_list(
        &self,
        write: &ClassCWrite,
        header_fk: Fk,
        tx_fks: &[Fk],
    ) -> Result<(), StoreError> {
        let (first, n) = Self::list_span(tx_fks)?;
        self.put_range(write, header_fk, first, n)
    }

    fn list_span(tx_fks: &[Fk]) -> Result<(Fk, u32), StoreError> {
        if tx_fks.is_empty() {
            return Err(StoreError::Corrupt("empty header tx list"));
        }
        if !tx_fks
            .windows(2)
            .all(|w| w[1].0 == w[0].0.saturating_add(1))
        {
            return Err(StoreError::Corrupt("header_txs not contiguous"));
        }
        Ok((tx_fks[0], tx_fks.len() as u32))
    }

    pub fn put_range(
        &self,
        write: &ClassCWrite,
        header_fk: Fk,
        first_tx_fk: Fk,
        n: u32,
    ) -> Result<(), StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        if first_tx_fk.is_null() || n == 0 {
            return Err(StoreError::InvalidFk);
        }
        let _pair = seq_odd(&self.seq);
        self.first.set_zero_gap(write, id - 1, first_tx_fk.0)?;
        self.count.set_zero_gap(write, id - 1, u64::from(n))?;
        Ok(())
    }

    /// Batch-append many header→tx ranges.
    pub fn put_lists_batch(
        &self,
        write: &ClassCWrite,
        items: &[(Fk, &[Fk])],
    ) -> Result<(), StoreError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut first_pairs = Vec::with_capacity(items.len());
        let mut count_pairs = Vec::with_capacity(items.len());
        for (header_fk, tx_fks) in items {
            let (first, n) = Self::list_span(tx_fks)?;
            let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
            first_pairs.push((id - 1, first.0));
            count_pairs.push((id - 1, u64::from(n)));
        }
        let _pair = seq_odd(&self.seq);
        self.first.set_many_zero_gap(write, &first_pairs)?;
        self.count.set_many_zero_gap(write, &count_pairs)?;
        Ok(())
    }

    /// Batch store ranges without expanding fk vectors.
    pub fn put_ranges_batch(
        &self,
        write: &ClassCWrite,
        items: &[(Fk, Fk, u32)],
    ) -> Result<(), StoreError> {
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
        let _pair = seq_odd(&self.seq);
        self.first.set_many_zero_gap(write, &first_pairs)?;
        self.count.set_many_zero_gap(write, &count_pairs)?;
        Ok(())
    }

    pub fn get_range(&self, header_fk: Fk) -> Result<Option<(Fk, u32)>, StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        let mut failed = None;
        let pair = seq_read(&self.seq, || {
            failed = None;
            if id > self.first.len() {
                return Some(None);
            }
            // Column loads acquire the stores. `seq_read` rechecks behind its
            // acquire fence. `Ok(None)` retries; `Err` returns once that generation holds.
            let mut raw = [0u64; 2];
            for (i, col) in [&self.first, &self.count].into_iter().enumerate() {
                match col.peek_slot(id - 1) {
                    Ok(Some(v)) => raw[i] = v,
                    Ok(None) => return None,
                    Err(e) => {
                        failed = Some(e);
                        return Some(None);
                    }
                }
            }
            let count = u32::try_from(raw[1]).ok().filter(|&n| n > 0);
            Some(Fk::new(raw[0]).zip(count))
        });
        failed.map_or(Ok(pair), Err)
    }

    /// Expand range to a vec of fks (convenience for existing call sites).
    pub fn get_list(&self, header_fk: Fk) -> Result<Option<Vec<Fk>>, StoreError> {
        let Some((first, n)) = self.get_range(header_fk)? else {
            return Ok(None);
        };
        Ok(Some((0..n).map(|i| Fk(first.0 + u64::from(i))).collect()))
    }

    pub fn has_body(&self, header_fk: Fk) -> Result<bool, StoreError> {
        Ok(self.get_range(header_fk)?.is_some())
    }

    /// Index of `tx_fk` inside a contiguous `(first, count)` span.
    pub fn index_in_span(first: Fk, n: u32, tx_fk: Fk) -> Option<u32> {
        let tid = tx_fk.get()?;
        let lo = first.get()?;
        let end = lo.saturating_add(u64::from(n));
        (n != 0 && (lo..end).contains(&tid))
            .then(|| u32::try_from(tid - lo).ok())
            .flatten()
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

    /// Drop the Class A body association for `header_fk` (tx rows stay).
    /// Reconstruct uses this when a block fails a header check such as merkle.
    pub fn clear_body(&self, write: &ClassCWrite, header_fk: Fk) -> Result<bool, StoreError> {
        let id = header_fk.get().ok_or(StoreError::InvalidFk)?;
        if id == 0 {
            return Err(StoreError::InvalidFk);
        }
        if !self.has_body(header_fk)? {
            return Ok(false);
        }
        // Ensure array slots exist then zero (0 = no body).
        let idx = id - 1;
        if idx >= self.first.len() {
            return Ok(false);
        }
        let _pair = seq_odd(&self.seq);
        self.first.set(write, idx, 0)?;
        self.count.set(write, idx, 0)?;
        Ok(true)
    }

    /// Headers with a Class A body (`count > 0`). Full scan for status and startup
    /// (`archived_block_count`) only. Not a plan hot path: Class A never leads tip.
    pub fn count_bodies(&self) -> Result<u64, StoreError> {
        (0..self.count.len()).try_fold(0u64, |total, i| {
            Ok(total + u64::from(self.count.get(i)? > 0))
        })
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
