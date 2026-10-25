//! In-memory [`ArrayFile`] with leading-header `TableFile` semantics: the
//! published logical end, the 8-byte HWM at header offset 8 that a reopen
//! reads, and `needs_sync`. Faults are injected per call.

use rbitcoin_store::array_table::ArrayFile;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::sync::atomic::{AtomicU64, Ordering};
use rbitcoin_store::sync::Mutex;
use std::sync::atomic::AtomicBool;

const HEADER: u64 = FILE_HEADER_LEN as u64;
const HWM: std::ops::Range<usize> = 8..16;

/// Where an armed fault fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailAt {
    /// `write_at` fails and touches nothing.
    Write,
    /// `write_at` lands the first half of its elements (rounded down), then
    /// fails: `handle_pwrite_all` returning after a short `pwrite`.
    TornWrite,
    /// `set_logical_len` fails before it moves the published end
    /// (`ensure_capacity`).
    SetLenBeforeStore,
    /// `set_logical_len` moves the published end, then its HWM persist fails.
    SetLenAfterStore,
}

impl FailAt {
    fn on_write(self) -> bool {
        matches!(self, FailAt::Write | FailAt::TornWrite)
    }
}

pub struct MemFile {
    /// Page cache, header included. A pread or pwrite is one critical
    /// section, and a pread that sees a pwrite's bytes is ordered after it
    /// (the kernel's page-cache locks), so the model's lock.
    bytes: Mutex<Vec<u8>>,
    /// `TableFile::published_len`: readers never read past it.
    published_len: AtomicU64,
    /// `TableFile::needs_sync`. Read only by the quiescent `flush`.
    needs_sync: AtomicBool,
    /// Lowest offset any `write_at` touched (`u64::MAX` = none).
    min_write_offset: std::sync::atomic::AtomicU64,
    /// The next `.1` calls of kind `.0` fail. Test control, not file
    /// state: a std lock with no model op inside.
    fault: std::sync::Mutex<Option<(FailAt, usize)>>,
}

impl MemFile {
    pub fn with_body(body: &[u64]) -> Self {
        let mut bytes = vec![0u8; FILE_HEADER_LEN];
        bytes.extend(body.iter().flat_map(|v| v.to_le_bytes()));
        let logical = bytes.len() as u64;
        bytes[HWM].copy_from_slice(&logical.to_le_bytes());
        Self::over(bytes, logical)
    }

    fn over(bytes: Vec<u8>, logical: u64) -> Self {
        Self {
            published_len: AtomicU64::new(logical),
            bytes: Mutex::new(bytes),
            needs_sync: AtomicBool::new(false),
            min_write_offset: std::sync::atomic::AtomicU64::new(u64::MAX),
            fault: std::sync::Mutex::new(None),
        }
    }

    /// The file a process restart opens over the same page cache: logical
    /// length from the persisted HWM, clamped like `TableFile::open`.
    pub fn reopen(&self) -> Self {
        let bytes = self.bytes.lock().unwrap().clone();
        let hwm = u64::from_le_bytes(bytes[HWM].try_into().unwrap());
        let logical = hwm.clamp(HEADER, bytes.len() as u64);
        Self::over(bytes, logical)
    }

    /// Body up to the published end, as `u64`s.
    pub fn image(&self) -> Vec<u64> {
        let end = self.published_len.load(Ordering::Acquire) as usize;
        let bytes = self.bytes.lock().unwrap();
        bytes[FILE_HEADER_LEN..end]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    pub fn min_write_offset(&self) -> u64 {
        self.min_write_offset.load(Ordering::SeqCst)
    }

    /// The next `times` calls that `at` names fail.
    pub fn arm(&self, at: FailAt, times: usize) {
        *self.fault.lock().unwrap() = (times > 0).then_some((at, times));
    }

    pub fn disarm(&self) {
        *self.fault.lock().unwrap() = None;
    }

    /// Consumes one armed fault when `fires` accepts its kind.
    fn take_fault(&self, fires: impl Fn(FailAt) -> bool) -> Option<FailAt> {
        let mut armed = self.fault.lock().unwrap();
        let (at, left) = (*armed).filter(|&(at, _)| fires(at))?;
        *armed = (left > 1).then_some((at, left - 1));
        Some(at)
    }

    /// The page cache, zero-extended to cover `end` (`ensure_capacity`).
    fn cache_to(&self, end: u64, f: impl FnOnce(&mut [u8])) {
        let mut cache = self.bytes.lock().unwrap();
        if cache.len() < end as usize {
            cache.resize(end as usize, 0);
        }
        f(&mut cache)
    }

    fn land(&self, offset: u64, bytes: &[u8]) {
        let end = offset + bytes.len() as u64;
        self.cache_to(end, |cache| {
            cache[offset as usize..end as usize].copy_from_slice(bytes);
        });
        self.min_write_offset.fetch_min(offset, Ordering::SeqCst);
    }

    fn persist_hwm(&self, logical: u64) {
        self.bytes.lock().unwrap()[HWM].copy_from_slice(&logical.to_le_bytes());
    }

    /// `TableFile::publish_logical_end`.
    fn publish_logical_end(&self, end: u64) {
        let mut cur = self.published_len.load(Ordering::Relaxed);
        while end > cur {
            match self.published_len.compare_exchange_weak(
                cur,
                end,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.persist_hwm(end);
                    break;
                }
                Err(c) => cur = c,
            }
        }
    }
}

fn injected(what: &str) -> StoreError {
    StoreError::io("mem", std::io::Error::other(format!("injected {what}")))
}

impl ArrayFile for MemFile {
    fn logical_len(&self) -> u64 {
        self.published_len.load(Ordering::Acquire)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset + buf.len() as u64;
        if end > self.published_len.load(Ordering::Acquire) {
            return Err(StoreError::Corrupt("pread past logical end"));
        }
        buf.copy_from_slice(&self.bytes.lock().unwrap()[offset as usize..end as usize]);
        Ok(())
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.is_empty() {
            return Ok(());
        }
        match self.take_fault(FailAt::on_write) {
            Some(FailAt::TornWrite) => {
                let landed = &bytes[..bytes.len() / 16 * 8];
                if !landed.is_empty() {
                    self.land(offset, landed);
                }
                return Err(injected("torn write"));
            }
            Some(_) => return Err(injected("write failure")),
            None => {}
        }
        self.land(offset, bytes);
        self.publish_logical_end(offset + bytes.len() as u64);
        self.needs_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn set_logical_len(&self, logical: u64) -> Result<(), StoreError> {
        if logical < HEADER {
            return Err(StoreError::Corrupt("logical length below header"));
        }
        if self
            .take_fault(|at| at == FailAt::SetLenBeforeStore)
            .is_some()
        {
            return Err(injected("capacity failure"));
        }
        self.cache_to(logical, |_| {});
        self.published_len.store(logical, Ordering::Release);
        if self
            .take_fault(|at| at == FailAt::SetLenAfterStore)
            .is_some()
        {
            return Err(injected("HWM persist failure"));
        }
        self.persist_hwm(logical);
        self.needs_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        if self
            .needs_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.persist_hwm(self.published_len.load(Ordering::Acquire));
        }
        Ok(())
    }

    fn flush_async(&self) -> Result<(), StoreError> {
        self.persist_hwm(self.published_len.load(Ordering::Acquire));
        Ok(())
    }
}
