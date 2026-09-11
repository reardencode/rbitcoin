//! Class C tip/confirmation tables and Class A header→tx ranges.

use crate::array_table::ArrayTable;
use crate::error::StoreError;
use rbitcoin_primitives::{Fk, Height, TableKind};
use std::path::Path;

/// Best-chain height → header fk. Length = tip_height + 1 when non-empty.
pub struct ConfirmedTable {
    arr: ArrayTable,
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
    /// [`Store::revalidate_tip_window`] to shrink to last good.
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
    bits: crate::file::TableFile,
    /// Number of bits allocated (covers tx fks 1..=n_bits).
    n_bits: std::sync::atomic::AtomicU64,
    /// L2 byte image (`None` = pure L0).
    data: std::sync::RwLock<Option<Vec<u8>>>,
    dirty: std::sync::atomic::AtomicBool,
    /// Min bit index mutated since last flush (`u64::MAX` = none).
    dirty_lo_bit: std::sync::atomic::AtomicU64,
    /// Body byte length last flushed to disk (L2).
    disk_bytes: std::sync::atomic::AtomicU64,
    /// Payload bytes written by the last [`Self::flush_dirty`].
    last_flush_bytes: std::sync::atomic::AtomicU64,
}

impl StrongTxTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            bits: crate::file::TableFile::create(dir.join("strong_tx.body"), TableKind::StrongTx)?,
            n_bits: std::sync::atomic::AtomicU64::new(0),
            data: std::sync::RwLock::new(Some(Vec::new())),
            dirty: std::sync::atomic::AtomicBool::new(false),
            dirty_lo_bit: std::sync::atomic::AtomicU64::new(u64::MAX),
            disk_bytes: std::sync::atomic::AtomicU64::new(0),
            last_flush_bytes: std::sync::atomic::AtomicU64::new(0),
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
        let data = Some(v);
        Ok(Self {
            bits,
            n_bits: std::sync::atomic::AtomicU64::new(n_bits),
            data: std::sync::RwLock::new(data),
            dirty: std::sync::atomic::AtomicBool::new(false),
            dirty_lo_bit: std::sync::atomic::AtomicU64::new(u64::MAX),
            disk_bytes: std::sync::atomic::AtomicU64::new(body),
            last_flush_bytes: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn mark_dirty_bit(&self, bit: u64) {
        use std::sync::atomic::Ordering;
        self.dirty.store(true, Ordering::Release);
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

    fn byte_off(bit: u64) -> u64 {
        crate::file::FILE_HEADER_LEN as u64 + bit / 8
    }

    fn ensure_bits(&self, need_bits: u64) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let n = self.n_bits.load(Ordering::Acquire);
        if need_bits <= n {
            return Ok(());
        }
        let need_bytes = need_bits.div_ceil(8);
        let cur_bytes = n.div_ceil(8);
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            if need_bytes as usize > v.len() {
                v.resize(need_bytes as usize, 0);
            }
            self.n_bits.store(need_bits, Ordering::Release);
            // Growth alone is not a bit mutate; callers set_bit mark dirty.
            return Ok(());
        }
        drop(guard);
        if need_bytes > cur_bytes {
            let zeros = vec![0u8; (need_bytes - cur_bytes) as usize];
            self.bits
                .write_at(crate::file::FILE_HEADER_LEN as u64 + cur_bytes, &zeros)?;
        }
        self.n_bits.store(need_bits, Ordering::Release);
        Ok(())
    }

    fn get_bit(&self, bit: u64) -> Result<bool, StoreError> {
        use std::sync::atomic::Ordering;
        let n = self.n_bits.load(Ordering::Acquire);
        if bit >= n {
            return Ok(false);
        }
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref v) = *guard {
            let bi = (bit / 8) as usize;
            return Ok((v[bi] >> (bit % 8)) & 1 != 0);
        }
        drop(guard);
        let mut b = [0u8; 1];
        self.bits.read_at(Self::byte_off(bit), &mut b)?;
        Ok((b[0] >> (bit % 8)) & 1 != 0)
    }

    fn set_bit(&self, bit: u64, on: bool) -> Result<(), StoreError> {
        self.ensure_bits(bit + 1)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            let bi = (bit / 8) as usize;
            if on {
                v[bi] |= 1 << (bit % 8);
            } else {
                v[bi] &= !(1 << (bit % 8));
            }
            self.mark_dirty_bit(bit);
            return Ok(());
        }
        drop(guard);
        let mut b = [0u8; 1];
        self.bits.read_at(Self::byte_off(bit), &mut b)?;
        if on {
            b[0] |= 1 << (bit % 8);
        } else {
            b[0] &= !(1 << (bit % 8));
        }
        self.bits.write_at(Self::byte_off(bit), &b)
    }

    /// Compatibility: Some(dummy nonzero) if strong, else None.
    pub fn get(&self, tx_fk: Fk) -> Result<Option<Fk>, StoreError> {
        if self.is_strong(tx_fk)? {
            Ok(Some(Fk(1)))
        } else {
            Ok(None)
        }
    }

    /// In-RAM L2 bit-image bytes (0 when FdOnly).
    pub fn l2_resident_bytes(&self) -> u64 {
        let g = self.data.read().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|v| v.len() as u64).unwrap_or(0)
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
    fn set_bits_range(&self, start: u64, end: u64, on: bool) -> Result<(), StoreError> {
        if end <= start {
            return Ok(());
        }
        self.ensure_bits(end)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut v) = *guard {
            let mut bit = start;
            while bit < end {
                let bi = (bit / 8) as usize;
                if on {
                    v[bi] |= 1 << (bit % 8);
                } else {
                    v[bi] &= !(1 << (bit % 8));
                }
                bit += 1;
            }
            self.mark_dirty_bit(start);
            return Ok(());
        }
        drop(guard);

        let mut bit = start;
        if !bit.is_multiple_of(8) {
            let byte_end = (bit + 8) & !7;
            let stop = end.min(byte_end);
            while bit < stop {
                let mut b = [0u8; 1];
                self.bits.read_at(Self::byte_off(bit), &mut b)?;
                if on {
                    b[0] |= 1 << (bit % 8);
                } else {
                    b[0] &= !(1 << (bit % 8));
                }
                self.bits.write_at(Self::byte_off(bit), &b)?;
                bit += 1;
            }
        }
        if bit + 8 <= end {
            let full_start = bit / 8;
            let full_end = end / 8;
            if full_end > full_start {
                let n = (full_end - full_start) as usize;
                let fill = if on { 0xffu8 } else { 0u8 };
                let blob = vec![fill; n];
                self.bits
                    .write_at(crate::file::FILE_HEADER_LEN as u64 + full_start, &blob)?;
                bit = full_end * 8;
            }
        }
        while bit < end {
            let mut b = [0u8; 1];
            self.bits.read_at(Self::byte_off(bit), &mut b)?;
            if on {
                b[0] |= 1 << (bit % 8);
            } else {
                b[0] &= !(1 << (bit % 8));
            }
            self.bits.write_at(Self::byte_off(bit), &b)?;
            bit += 1;
        }
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

    fn count_ones_bits(&self, start_bit: u64, end_bit: u64) -> Result<u64, StoreError> {
        if end_bit <= start_bit {
            return Ok(0);
        }
        let mut ones = 0u64;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref v) = *guard {
            let mut bit = start_bit;
            while bit < end_bit {
                let bi = (bit / 8) as usize;
                let b = v[bi];
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
            return Ok(ones);
        }
        drop(guard);
        const CHUNK: usize = 8192;
        let mut buf = vec![0u8; CHUNK];
        let mut bit = start_bit;
        while bit < end_bit {
            let byte_off = bit / 8;
            let nbytes = end_bit.div_ceil(8).saturating_sub(byte_off);
            let take = (nbytes as usize).min(CHUNK);
            self.bits.read_at(
                crate::file::FILE_HEADER_LEN as u64 + byte_off,
                &mut buf[..take],
            )?;
            let base_bit = byte_off * 8;
            for (i, &b) in buf[..take].iter().enumerate() {
                if b == 0 {
                    continue;
                }
                for k in 0..8u32 {
                    let idx = base_bit + (i as u64) * 8 + u64::from(k);
                    if idx >= start_bit && idx < end_bit && (b >> k) & 1 != 0 {
                        ones += 1;
                    }
                }
            }
            bit = base_bit + (take as u64) * 8;
        }
        Ok(ones)
    }

    /// Read `dst.len()` bit-image bytes starting at payload byte `byte_off`.
    pub(crate) fn read_bit_bytes(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), StoreError> {
        if dst.is_empty() {
            return Ok(());
        }
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref v) = *guard {
            let start = byte_off as usize;
            let end = start.saturating_add(dst.len()).min(v.len());
            if start >= v.len() {
                dst.fill(0);
                return Ok(());
            }
            let n = end - start;
            dst[..n].copy_from_slice(&v[start..end]);
            dst[n..].fill(0);
            return Ok(());
        }
        drop(guard);
        self.bits
            .read_at(crate::file::FILE_HEADER_LEN as u64 + byte_off, dst)
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

    /// Bytes written by the last [`Self::flush_dirty`].
    #[cfg(test)]
    pub(crate) fn last_flush_write_bytes(&self) -> u64 {
        self.last_flush_bytes
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Persist dirty L2 bit image. Prefers append-only byte suffix writes.
    pub fn flush_dirty(&self) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref v) = *guard else {
            return Ok(());
        };
        if !self.dirty.load(Ordering::Acquire) {
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
            let n = suffix.len() as u64;
            if !suffix.is_empty() {
                self.bits
                    .write_at(crate::file::FILE_HEADER_LEN as u64 + disk, &suffix)?;
            }
            self.disk_bytes.store(body_len, Ordering::Release);
            self.dirty.store(false, Ordering::Release);
            self.dirty_lo_bit.store(u64::MAX, Ordering::Release);
            self.last_flush_bytes.store(n, Ordering::Release);
            return Ok(());
        }

        // In-prefix bit mutate: write from first dirty byte through end only.
        // Tip Class C almost always dirties only the high bits (new creates);
        // rewriting the full ~40 MiB image every batch was wasteful. Same-size
        // mid-file tear risk is limited to the dirty suffix; tip-last barrier
        // still keeps tip unadvanced until this flush completes.
        let from = dirty_byte.min(body_len);
        let suffix = v[from as usize..].to_vec();
        drop(guard);
        let n = suffix.len() as u64;
        if !suffix.is_empty() {
            self.bits
                .write_at(crate::file::FILE_HEADER_LEN as u64 + from, &suffix)?;
        }
        if body_len != disk {
            let logical = crate::file::FILE_HEADER_LEN as u64 + body_len;
            self.bits.set_logical_len(logical)?;
        }
        self.disk_bytes.store(body_len, Ordering::Release);
        self.dirty.store(false, Ordering::Release);
        self.dirty_lo_bit.store(u64::MAX, Ordering::Release);
        self.last_flush_bytes.store(n, Ordering::Release);
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

#[cfg(test)]
mod strong_tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-strong-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn strong_bitset_range_and_clear() {
        let dir = tmp();
        let t = StrongTxTable::create(&dir).unwrap();
        t.set_strong_range(Fk(1), 10, Fk(99)).unwrap();
        for i in 1..=10 {
            assert!(t.is_strong(Fk(i)).unwrap());
        }
        assert!(!t.is_strong(Fk(11)).unwrap());
        t.set_unstrong(Fk(5)).unwrap();
        assert!(!t.is_strong(Fk(5)).unwrap());
        assert!(t.is_strong(Fk(4)).unwrap());
        assert!(t.get(Fk(1)).unwrap().is_some());
        assert!(t.get(Fk(5)).unwrap().is_none());
        t.flush().unwrap();
        drop(t);
        let t = StrongTxTable::open(&dir).unwrap();
        assert!(t.is_strong(Fk(1)).unwrap());
        assert!(!t.is_strong(Fk(5)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `strong_tx` stays L2 even when the Class C array cap would demote it.
    #[test]
    fn strong_tx_always_l2_above_class_c_cap() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("RBITCOIN_CLASS_C_INRAM_MAX_MB");
        std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", "1");
        let dir = tmp();
        // 1 MiB + 1 byte of bits → body > class_c_inram_max_bytes() (1 MiB).
        let fk = Fk(8_388_608 + 8);
        {
            let t = StrongTxTable::create(&dir).unwrap();
            t.set_strong(fk, Fk(1)).unwrap();
            t.flush().unwrap();
            assert!(
                t.l2_resident_bytes() > 1024 * 1024,
                "create path L2={}",
                t.l2_resident_bytes()
            );
        }
        let t = StrongTxTable::open(&dir).unwrap();
        assert!(
            t.l2_resident_bytes() > 1024 * 1024,
            "reopen must keep L2 under a 1 MiB Class C cap; got {}",
            t.l2_resident_bytes()
        );
        assert!(t.is_strong(fk).unwrap());
        match prev {
            Some(v) => std::env::set_var("RBITCOIN_CLASS_C_INRAM_MAX_MB", v),
            None => std::env::remove_var("RBITCOIN_CLASS_C_INRAM_MAX_MB"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strong_write_behind_no_flush_keeps_old() {
        let dir = tmp();
        {
            let t = StrongTxTable::create(&dir).unwrap();
            t.set_strong_range(Fk(1), 8, Fk(1)).unwrap();
            t.flush().unwrap();
            t.set_strong(Fk(9), Fk(1)).unwrap();
            // Drop without flush.
        }
        let t = StrongTxTable::open(&dir).unwrap();
        assert!(t.is_strong(Fk(1)).unwrap());
        assert!(
            !t.is_strong(Fk(9)).unwrap(),
            "unflushed strong must not survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// High-fk-only dirties must write a suffix, not the full L2 image.
    #[test]
    fn strong_high_fk_flush_writes_suffix_not_full_image() {
        let dir = tmp();
        let t = StrongTxTable::create(&dir).unwrap();
        // 80_000 bits = 10_000 payload bytes.
        t.set_strong_range(Fk(1), 80_000, Fk(1)).unwrap();
        t.flush_dirty().unwrap();
        let first = t.last_flush_write_bytes();
        assert!(
            first >= 10_000,
            "first flush should persist the full image, got {first}"
        );

        // Flip only the last allocated bit — dirty_lo is near the end.
        t.set_unstrong(Fk(80_000)).unwrap();
        t.flush_dirty().unwrap();
        let second = t.last_flush_write_bytes();
        assert!(
            second > 0 && second < first / 4,
            "high-bit dirty must write a suffix, not the full image (first={first} second={second})"
        );
        assert!(t.is_strong(Fk(1)).unwrap());
        assert!(!t.is_strong(Fk(80_000)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// In-prefix high-bit dirties must flush without losing low bits (suffix write).
    #[test]
    fn strong_suffix_dirty_flush_preserves_prefix() {
        let dir = tmp();
        {
            let s = StrongTxTable::create(&dir).unwrap();
            // Allocate a wide bit image then flush so disk_bytes covers it.
            s.set_strong_range(Fk(1), 10_000, Fk(1)).unwrap();
            s.flush().unwrap();
            // Flip only high bits (still within disk image) — suffix dirty path.
            s.set_strong_range(Fk(9000), 100, Fk(1)).unwrap();
            s.flush().unwrap();
        }
        let s = StrongTxTable::open(&dir).unwrap();
        assert!(s.is_strong(Fk(1)).unwrap());
        assert!(s.is_strong(Fk(5000)).unwrap());
        assert!(s.is_strong(Fk(9000)).unwrap());
        assert!(s.is_strong(Fk(9099)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strong_write_behind_flush_reopen() {
        let dir = tmp();
        {
            let t = StrongTxTable::create(&dir).unwrap();
            t.set_strong_range(Fk(1), 16, Fk(1)).unwrap();
            t.flush().unwrap();
            t.set_unstrong_range(Fk(5), 4).unwrap();
            t.flush().unwrap();
        }
        let t = StrongTxTable::open(&dir).unwrap();
        assert!(t.is_strong(Fk(1)).unwrap());
        assert!(!t.is_strong(Fk(5)).unwrap());
        assert!(!t.is_strong(Fk(8)).unwrap());
        assert!(t.is_strong(Fk(9)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strong_partial_bytes_unstrong_range_and_errors() {
        let dir = tmp();
        let t = StrongTxTable::create(&dir).unwrap();
        // Unaligned start so partial-first-byte path runs.
        t.set_strong_range(Fk(3), 20, Fk(1)).unwrap();
        for i in 3..23 {
            assert!(t.is_strong(Fk(i)).unwrap(), "i={i}");
        }
        assert!(!t.is_strong(Fk(2)).unwrap());
        // count==0 no-op
        t.set_strong_range(Fk(1), 0, Fk(1)).unwrap();
        t.set_unstrong_range(Fk(1), 0).unwrap();
        // Clear a mid-range with partial ends.
        t.set_unstrong_range(Fk(5), 10).unwrap();
        for i in 5..15 {
            assert!(!t.is_strong(Fk(i)).unwrap());
        }
        assert!(t.is_strong(Fk(4)).unwrap());
        assert!(t.is_strong(Fk(15)).unwrap());
        // past allocated → no-op
        t.set_unstrong(Fk(9999)).unwrap();
        t.set_unstrong_range(Fk(9000), 10).unwrap();
        assert!(matches!(
            t.set_strong(Fk::NULL, Fk(1)),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            t.set_strong(Fk(1), Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            t.set_strong_range(Fk::NULL, 1, Fk(1)),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            t.set_strong_range(Fk(1), 1, Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(t.is_strong(Fk::NULL), Err(StoreError::InvalidFk)));
        t.flush_async().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod chain_table_tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-chain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn confirmed_tx_height_header_txs_surface() {
        let dir = tmp();
        // Confirmed
        let c = ConfirmedTable::create(&dir).unwrap();
        assert!(c.tip_height().is_none());
        c.set(Height(0), Fk(1)).unwrap();
        c.set(Height(1), Fk(2)).unwrap();
        assert_eq!(c.tip_height(), Some(Height(1)));
        assert_eq!(c.get(Height(0)).unwrap(), Some(Fk(1)));
        c.set_many(&[]).unwrap();
        c.set_many(&[(Height(2), Fk(3)), (Height(3), Fk(4))])
            .unwrap();
        assert_eq!(c.tip_height(), Some(Height(3)));
        assert!(matches!(
            c.set(Height(4), Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            c.set_many(&[(Height(5), Fk::NULL)]),
            Err(StoreError::InvalidFk)
        ));
        c.disconnect_tip(Height(3)).unwrap();
        assert_eq!(c.tip_height(), Some(Height(2)));
        assert!(matches!(
            c.disconnect_tip(Height(0)),
            Err(StoreError::Corrupt(_))
        ));
        c.disconnect_tip(Height(2)).unwrap();
        c.disconnect_tip(Height(1)).unwrap();
        c.disconnect_tip(Height(0)).unwrap();
        assert!(c.tip_height().is_none());
        assert!(matches!(
            c.disconnect_tip(Height(0)),
            Err(StoreError::Corrupt(_))
        ));
        c.flush().unwrap();
        c.flush_async().unwrap();

        // HeaderTxs
        let ht = HeaderTxsTable::create(&dir).unwrap();
        assert!(ht.get_range(Fk(1)).unwrap().is_none());
        ht.put_range(Fk(1), Fk(100), 3).unwrap();
        assert_eq!(ht.get_range(Fk(1)).unwrap(), Some((Fk(100), 3)));
        assert_eq!(
            ht.get_list(Fk(1)).unwrap().unwrap(),
            vec![Fk(100), Fk(101), Fk(102)]
        );
        assert!(ht.has_body(Fk(1)).unwrap());
        assert!(!ht.has_body(Fk(2)).unwrap());
        ht.put_list(Fk(2), &[Fk(200), Fk(201)]).unwrap();
        assert!(matches!(
            ht.put_list(Fk(3), &[]),
            Err(StoreError::Corrupt(_))
        ));
        // Non-contiguous triggers debug_assert in debug builds; only empty is a
        // stable Err path under RUSTFLAGS=-Dwarnings debug tests.
        assert!(matches!(
            ht.put_range(Fk::NULL, Fk(1), 1),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            ht.put_range(Fk(3), Fk::NULL, 1),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            ht.put_range(Fk(3), Fk(1), 0),
            Err(StoreError::InvalidFk)
        ));
        ht.put_lists_batch(&[]).unwrap();
        ht.put_lists_batch(&[(Fk(3), &[Fk(300)] as &[_]), (Fk(4), &[Fk(400), Fk(401)])])
            .unwrap();
        assert!(matches!(
            ht.put_lists_batch(&[(Fk(5), &[] as &[_])]),
            Err(StoreError::Corrupt(_))
        ));
        ht.put_ranges_batch(&[]).unwrap();
        ht.put_ranges_batch(&[(Fk(5), Fk(500), 2)]).unwrap();
        assert!(matches!(
            ht.put_ranges_batch(&[(Fk::NULL, Fk(1), 1)]),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(
            ht.put_ranges_batch(&[(Fk(6), Fk::NULL, 1)]),
            Err(StoreError::InvalidFk)
        ));
        assert_eq!(ht.count_bodies().unwrap(), 5);
        assert!(matches!(ht.get_range(Fk::NULL), Err(StoreError::InvalidFk)));

        // clear_body: drop association without freeing tx rows (merkle soft-reget path).
        assert!(matches!(
            ht.clear_body(Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(!ht.clear_body(Fk(99)).unwrap(), "no body → false");
        assert!(ht.clear_body(Fk(1)).unwrap(), "had body → true");
        assert!(!ht.has_body(Fk(1)).unwrap());
        assert!(!ht.clear_body(Fk(1)).unwrap(), "already clear → false");
        assert_eq!(ht.count_bodies().unwrap(), 4);

        ht.flush().unwrap();
        ht.flush_async().unwrap();
        drop(ht);
        let ht = HeaderTxsTable::open(&dir).unwrap();
        assert_eq!(ht.get_range(Fk(5)).unwrap(), Some((Fk(500), 2)));
        assert!(
            !ht.has_body(Fk(1)).unwrap(),
            "clear_body durable after reopen"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_txs_contains_tx_range_edges() {
        let dir = tmp();
        let ht = HeaderTxsTable::create(&dir).unwrap();
        assert!(!ht.contains_tx(Fk(1), Fk::NULL).unwrap());
        assert!(!ht.contains_tx(Fk(1), Fk(1)).unwrap(), "no body");
        ht.put_range(Fk(1), Fk(10), 3).unwrap();
        assert!(ht.contains_tx(Fk(1), Fk(10)).unwrap());
        assert!(ht.contains_tx(Fk(1), Fk(12)).unwrap());
        assert!(!ht.contains_tx(Fk(1), Fk(9)).unwrap());
        assert!(!ht.contains_tx(Fk(1), Fk(13)).unwrap());
        assert!(!ht.contains_tx(Fk(2), Fk(10)).unwrap(), "other header");
        let _ = std::fs::remove_dir_all(&dir);
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
    first: ArrayTable,
    count: ArrayTable,
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

    /// True if `tx_fk` is in this header's contiguous Class A body range.
    pub fn contains_tx(&self, header_fk: Fk, tx_fk: Fk) -> Result<bool, StoreError> {
        let Some(tid) = tx_fk.get() else {
            return Ok(false);
        };
        let Some((first, n)) = self.get_range(header_fk)? else {
            return Ok(false);
        };
        let Some(lo) = first.get() else {
            return Ok(false);
        };
        Ok(tid >= lo && tid < lo.saturating_add(u64::from(n)))
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
