//! Growable table files with a common header — **fd-only** pread/pwrite transport.
//!
//! See [`docs/io-modality.md`](../../../../docs/io-modality.md) for the bulk-IO vs
//! table-transport split and the L0/L1/L2 RAM tiers.
//!
//! # Transport
//!
//! All payload IO uses **pread/pwrite** on a file descriptor. The process never
//! maps multi‑GiB table images (`memmap2` / `MmapMut` removed). Hot pages live in
//! the kernel page cache. Capacity grows via fallocate / `SetFileInformationByHandle`
//! (Windows) / `set_len` (Unix). Windows table handles are `FILE_FLAG_OVERLAPPED`;
//! create/open/grow never use std `Read`/`Write`/`Seek`.
//!
//! # Publish order (complete-or-fail units)
//!
//! 1. Ensure capacity (fallocate).
//! 2. Write full payload bytes (`pwrite` loop until complete or error).
//! 3. Publish `published_len` (Release) only after payload is fully written.
//! 4. Persist HWM (8-byte logical length in header/trailer) via complete pwrite.
//!
//! Readers never consume past `published_len`. A crash mid-payload leaves HWM
//! at the previous value; re-drive rebuilds from body queue / re-append.
//!
//! # Concurrency
//!
//! - **Published logical length** is an `AtomicU64` (Acquire/Release).
//! - `File` is locked only for grow (fallocate / Windows EOF / `set_len`), fsync, and fadvise.
//! - Roles (see `docs/concurrency.md`): at most one appender and
//!   one annotator; N concurrent readers of published ranges.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use rbitcoin_primitives::{schema_file_openable, TableKind, SCHEMA_VERSION, STORE_MAGIC};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

// needs_sync: set on durable-payload writes; cleared after sync_data.

pub const FILE_HEADER_LEN: usize = 16;

/// Trailing-header tables (`tx.head`): 16-byte store identity + 16-byte layout
/// extension (bits / entry_bytes / generation). Slots still start at file offset 0
/// so probe pages stay OS-page-aligned.
pub const TRAILING_FOOTER_LEN: usize = 32;

pub struct TableFile {
    path: PathBuf,
    /// Grow / fsync / fadvise only — not on the pread/pwrite hot path.
    file: Mutex<File>,
    /// Cloned FD for lock-free [`pread`](Self::pread_at) / io_uring bulk reads.
    read_file: File,
    /// Logical length including header/trailer (published HWM).
    published_len: AtomicU64,
    /// File capacity. Always ≥ published; grown via fallocate without mapping.
    file_cap: AtomicU64,
    /// When true: [`TRAILING_FOOTER_LEN`]-byte magic+HWM+layout trailer is at
    /// **end** of published range; data starts at offset 0 (page-aligned probes).
    trailing_header: bool,
    /// Layout extension for trailing footers (address-head bits/gen).
    trailing_ext: [u8; 16],
    kind: TableKind,
    /// Payload/HWM written since last successful `sync_data` (Class C barrier skip).
    needs_sync: AtomicBool,
    /// [`GrowPolicy`] as u8. Idx uses 1 MiB; SH body uses 64 KiB; Class A slabs.
    grow_policy: AtomicU8,
}

/// File capacity growth. SH body must not inherit Class A 64–256 MiB slabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GrowPolicy {
    /// Double until 64 MiB, then 256 MiB headroom / 64 MiB steps.
    Slab = 0,
    /// `need + 1 MiB` (idx / dense u32).
    Tight1MiB = 1,
    /// Round `need` up to 64 KiB (SH shard / ovf body).
    Align64k = 2,
}

fn table_open_opts() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
        o.custom_flags(FILE_FLAG_OVERLAPPED);
    }
    o
}

fn encode_leading_header(kind: TableKind, logical: u64) -> [u8; FILE_HEADER_LEN] {
    let mut header = [0u8; FILE_HEADER_LEN];
    header[0..4].copy_from_slice(&STORE_MAGIC);
    header[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&kind.as_u16().to_le_bytes());
    header[8..16].copy_from_slice(&logical.to_le_bytes());
    header
}

/// Complete positional write. Safe on Windows `FILE_FLAG_OVERLAPPED` handles
/// (std `Write` / `WriteFile` with a NULL `OVERLAPPED` is os error 87).
fn handle_pwrite_all(
    file: &File,
    path: &Path,
    offset: u64,
    bytes: &[u8],
) -> Result<(), StoreError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let handle = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < bytes.len() {
        let rc = handle.pwrite(offset + done as u64, &bytes[done..]);
        if rc < 0 {
            return Err(StoreError::io(path, std::io::Error::from_raw_os_error(-rc)));
        }
        if rc == 0 {
            return Err(StoreError::io(
                path,
                std::io::Error::new(std::io::ErrorKind::WriteZero, "pwrite returned 0"),
            ));
        }
        done += rc as usize;
    }
    Ok(())
}

/// Complete positional read. Safe on Windows `FILE_FLAG_OVERLAPPED` handles
/// (std `Read` / `ReadFile` with a NULL `OVERLAPPED` is os error 87).
fn handle_pread_all(
    file: &File,
    path: &Path,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), StoreError> {
    if buf.is_empty() {
        return Ok(());
    }
    let handle = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < buf.len() {
        let rc = handle.pread(offset + done as u64, &mut buf[done..]);
        if rc < 0 {
            return Err(StoreError::io(path, std::io::Error::from_raw_os_error(-rc)));
        }
        if rc == 0 {
            return Err(StoreError::io(
                path,
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "pread short"),
            ));
        }
        done += rc as usize;
    }
    Ok(())
}

fn set_file_len(file: &File, path: &Path, new_len: u64) -> Result<(), StoreError> {
    #[cfg(windows)]
    {
        crate::io_handle::win_set_eof(file, new_len).map_err(|e| StoreError::io(path, e))
    }
    #[cfg(not(windows))]
    {
        file.set_len(new_len).map_err(|e| StoreError::io(path, e))
    }
}

impl TableFile {
    pub fn create(path: impl Into<PathBuf>, kind: TableKind) -> Result<Self, StoreError> {
        let path = path.into();
        let file = table_open_opts()
            .create_new(true)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;

        let header = encode_leading_header(kind, FILE_HEADER_LEN as u64);
        let initial = FILE_HEADER_LEN as u64 + 64;
        // Capacity first, then header via overlapped-safe pwrite (not std Write).
        set_file_len(&file, &path, initial)?;
        handle_pwrite_all(&file, &path, 0, &header)?;
        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;

        Ok(Self {
            path,
            file: Mutex::new(file),
            read_file,
            published_len: AtomicU64::new(FILE_HEADER_LEN as u64),
            file_cap: AtomicU64::new(initial),
            trailing_header: false,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(false),
            grow_policy: AtomicU8::new(GrowPolicy::Slab as u8),
        })
    }

    /// Create a table whose **data starts at offset 0** and a
    /// [`TRAILING_FOOTER_LEN`]-byte footer sits at the **end** of published length.
    pub fn create_trailing_header(
        path: impl Into<PathBuf>,
        kind: TableKind,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        let file = table_open_opts()
            .create_new(true)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        let initial = TRAILING_FOOTER_LEN as u64;
        set_file_len(&file, &path, initial)?;
        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;
        let s = Self {
            path,
            file: Mutex::new(file),
            read_file,
            published_len: AtomicU64::new(initial),
            file_cap: AtomicU64::new(initial),
            trailing_header: true,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(false),
            grow_policy: AtomicU8::new(GrowPolicy::Slab as u8),
        };
        s.write_trailer(initial)?;
        Ok(s)
    }

    pub fn open_trailing_header(
        path: impl Into<PathBuf>,
        kind: TableKind,
        data_bytes: u64,
    ) -> Result<(Self, [u8; 16]), StoreError> {
        let path = path.into();
        let file = table_open_opts()
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
        let expect = data_bytes.saturating_add(TRAILING_FOOTER_LEN as u64);
        if file_len < expect {
            return Err(StoreError::Corrupt("trailing-header table short"));
        }
        let mut footer = [0u8; TRAILING_FOOTER_LEN];
        handle_pread_all(&file, &path, data_bytes, &mut footer)?;
        if footer[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes([footer[4], footer[5]]);
        if !schema_file_openable(ver) {
            return Err(StoreError::BadSchema(ver));
        }
        let got = u16::from_le_bytes([footer[6], footer[7]]);
        if got != kind.as_u16() {
            return Err(StoreError::BadKind {
                expected: kind.as_u16(),
                got,
            });
        }
        let mut trailing_ext = [0u8; 16];
        trailing_ext.copy_from_slice(&footer[16..32]);
        let logical = expect;
        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;
        Ok((
            Self {
                path,
                file: Mutex::new(file),
                read_file,
                published_len: AtomicU64::new(logical),
                file_cap: AtomicU64::new(file_len.max(logical)),
                trailing_header: true,
                trailing_ext,
                kind,
                needs_sync: AtomicBool::new(false),
                grow_policy: AtomicU8::new(GrowPolicy::Slab as u8),
            },
            trailing_ext,
        ))
    }

    pub fn open_trailing_header_from_end(
        path: impl Into<PathBuf>,
        kind: TableKind,
    ) -> Result<(Self, [u8; 16]), StoreError> {
        let (path, data_bytes) = Self::trailing_footer_data_bytes(path, kind)?;
        Self::open_trailing_header(path, kind, data_bytes)
    }

    fn trailing_footer_data_bytes(
        path: impl Into<PathBuf>,
        kind: TableKind,
    ) -> Result<(PathBuf, u64), StoreError> {
        let path = path.into();
        let file = table_open_opts()
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
        if file_len < TRAILING_FOOTER_LEN as u64 {
            return Err(StoreError::Corrupt("trailing-header table short"));
        }
        let mut footer = [0u8; TRAILING_FOOTER_LEN];
        handle_pread_all(
            &file,
            &path,
            file_len - TRAILING_FOOTER_LEN as u64,
            &mut footer,
        )?;
        if footer[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes([footer[4], footer[5]]);
        if !schema_file_openable(ver) {
            return Err(StoreError::BadSchema(ver));
        }
        let got = u16::from_le_bytes([footer[6], footer[7]]);
        if got != kind.as_u16() {
            return Err(StoreError::BadKind {
                expected: kind.as_u16(),
                got,
            });
        }
        let logical = u64::from_le_bytes(footer[8..16].try_into().unwrap());
        if logical < TRAILING_FOOTER_LEN as u64 || logical > file_len {
            return Err(StoreError::Corrupt("trailing-header logical length"));
        }
        let data_bytes = logical - TRAILING_FOOTER_LEN as u64;
        Ok((path, data_bytes))
    }

    pub fn set_trailing_ext(&mut self, ext: [u8; 16]) -> Result<(), StoreError> {
        if !self.trailing_header {
            return Err(StoreError::Corrupt(
                "set_trailing_ext on leading-header file",
            ));
        }
        self.trailing_ext = ext;
        let logical = self.published_len.load(Ordering::Acquire);
        self.write_trailer(logical)
    }

    fn write_trailer(&self, logical: u64) -> Result<(), StoreError> {
        if logical < TRAILING_FOOTER_LEN as u64 {
            return Err(StoreError::Corrupt("trailing header logical short"));
        }
        let base = logical - TRAILING_FOOTER_LEN as u64;
        let mut footer = [0u8; TRAILING_FOOTER_LEN];
        footer[0..4].copy_from_slice(&STORE_MAGIC);
        footer[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
        footer[6..8].copy_from_slice(&self.kind.as_u16().to_le_bytes());
        footer[8..16].copy_from_slice(&logical.to_le_bytes());
        footer[16..32].copy_from_slice(&self.trailing_ext);
        self.ensure_capacity(logical)?;
        self.pwrite_all(base, &footer)
    }

    pub fn open(path: impl Into<PathBuf>, kind: TableKind) -> Result<Self, StoreError> {
        let path = path.into();
        let file = table_open_opts()
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;

        let mut header = [0u8; FILE_HEADER_LEN];
        handle_pread_all(&file, &path, 0, &mut header)?;
        if header[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes([header[4], header[5]]);
        if !schema_file_openable(ver) {
            return Err(StoreError::BadSchema(ver));
        }
        let got = u16::from_le_bytes([header[6], header[7]]);
        if got != kind.as_u16() {
            return Err(StoreError::BadKind {
                expected: kind.as_u16(),
                got,
            });
        }

        let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
        let mut logical = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if logical < FILE_HEADER_LEN as u64 {
            logical = FILE_HEADER_LEN as u64;
        }
        if logical > file_len {
            logical = file_len;
        }

        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            read_file,
            published_len: AtomicU64::new(logical),
            file_cap: AtomicU64::new(file_len.max(logical)),
            trailing_header: false,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(false),
            grow_policy: AtomicU8::new(GrowPolicy::Slab as u8),
        })
    }

    pub fn logical_len(&self) -> u64 {
        self.published_len.load(Ordering::Acquire)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Portable handle for bulk / session IO (lock-free; do not close).
    #[inline]
    pub fn read_fd(&self) -> crate::io_handle::IoHandle {
        self.io_handle()
    }

    /// Portable handle for the completion session (lock-free; do not close).
    #[inline]
    pub fn io_handle(&self) -> crate::io_handle::IoHandle {
        crate::io_handle::IoHandle::from_file(&self.read_file)
    }

    /// Shrink or set logical length (must be ≥ header/trailer size). Does not zero freed bytes.
    pub fn set_logical_len(&self, logical: u64) -> Result<(), StoreError> {
        let min = if self.trailing_header {
            TRAILING_FOOTER_LEN as u64
        } else {
            FILE_HEADER_LEN as u64
        };
        if logical < min {
            return Err(StoreError::Corrupt("logical length below header"));
        }
        self.ensure_capacity(logical)?;
        if self.trailing_header {
            // Trailer rewrite includes HWM; publish after full trailer write.
            self.write_trailer(logical)?;
            self.published_len.store(logical, Ordering::Release);
        } else {
            self.published_len.store(logical, Ordering::Release);
            self.persist_hwm(logical)?;
        }
        self.needs_sync.store(true, Ordering::Release);
        Ok(())
    }

    /// Slot/data length excluding the header or trailing footer.
    #[inline]
    pub fn data_len(&self) -> u64 {
        let overhead = if self.trailing_header {
            TRAILING_FOOTER_LEN as u64
        } else {
            FILE_HEADER_LEN as u64
        };
        self.published_len
            .load(Ordering::Acquire)
            .saturating_sub(overhead)
    }

    /// Complete pread of `buf.len()` bytes or error (no partial success).
    fn pread_all(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        handle_pread_all(&self.read_file, &self.path, offset, buf)
    }

    /// Complete pwrite of all bytes or error (no partial success returned).
    fn pwrite_all(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        handle_pwrite_all(&self.read_file, &self.path, offset, bytes)
    }

    /// Positional pread (page cache / disk). Preferred for Class A `tx.body`.
    pub fn pread_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset.saturating_add(buf.len() as u64);
        let len = self.published_len.load(Ordering::Acquire);
        if end > len {
            return Err(StoreError::Corrupt("pread past logical end"));
        }
        self.pread_all(offset, buf)
    }

    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        self.pread_at(offset, buf)
    }

    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        self.write_at_pwrite(offset, bytes)
    }

    /// Write `bytes` at `offset` via complete **`pwrite`**, then publish HWM.
    ///
    /// Complete-or-fail: either all bytes are written and HWM advances to cover
    /// `offset+len`, or an error is returned and HWM is left unchanged for this
    /// write (prior published range remains valid).
    pub fn write_at_pwrite(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = offset.saturating_add(bytes.len() as u64);
        self.ensure_capacity(end)?;
        self.pwrite_all(offset, bytes)?;
        self.publish_logical_end(end);
        self.needs_sync.store(true, Ordering::Release);
        Ok(())
    }

    /// Extend published HWM to at least `end` (Release) and persist on-disk HWM.
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
                    // Best-effort HWM persist on steady path; `flush` hardens it.
                    let _ = self.persist_hwm(end);
                    break;
                }
                Err(c) => cur = c,
            }
        }
    }

    /// Atomic little-endian `u32` load via pread (tests / diagnostics).
    #[cfg(test)]
    pub fn load_u32_le(&self, offset: u64) -> Result<u32, StoreError> {
        if !offset.is_multiple_of(4) {
            return Err(StoreError::Corrupt("load_u32 unaligned"));
        }
        let mut buf = [0u8; 4];
        self.pread_at(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Atomic little-endian `u64` load via pread (tests / diagnostics).
    #[cfg(test)]
    pub fn load_u64_le(&self, offset: u64) -> Result<u64, StoreError> {
        if !offset.is_multiple_of(8) {
            return Err(StoreError::Corrupt("load_u64 unaligned"));
        }
        let mut buf = [0u8; 8];
        self.pread_at(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Ensure the file covers at least `need` bytes (fallocate / set_len only).
    /// Idx / dense u32 tables: grow in ~1 MiB steps, not 256 MiB slabs.
    pub fn set_grow_tight(&self, tight: bool) {
        self.set_grow_policy(if tight {
            GrowPolicy::Tight1MiB
        } else {
            GrowPolicy::Slab
        });
    }

    pub fn set_grow_policy(&self, policy: GrowPolicy) {
        self.grow_policy.store(policy as u8, Ordering::Release);
    }

    pub fn ensure_capacity(&self, need: u64) -> Result<(), StoreError> {
        if need <= self.file_cap.load(Ordering::Acquire) {
            return Ok(());
        }
        self.ensure_capacity_grow(need)
    }

    fn ensure_capacity_grow(&self, need: u64) -> Result<(), StoreError> {
        const DOUBLE_UNTIL: u64 = 64 * 1024 * 1024;
        let cur = self.file_cap.load(Ordering::Acquire);
        if need <= cur {
            return Ok(());
        }
        let policy = self.grow_policy.load(Ordering::Acquire);
        if policy == GrowPolicy::Tight1MiB as u8 {
            let target = need.saturating_add(1 << 20).max(need);
            return self.grow_to(target);
        }
        if policy == GrowPolicy::Align64k as u8 {
            const STEP: u64 = 64 * 1024;
            let target = need.div_ceil(STEP).saturating_mul(STEP).max(need);
            return self.grow_to(target);
        }
        let (headroom, step) = if cur >= 8 * 1024 * 1024 * 1024 {
            (1024 * 1024 * 1024u64, 512 * 1024 * 1024u64)
        } else if cur >= 1024 * 1024 * 1024 {
            (512 * 1024 * 1024u64, 256 * 1024 * 1024u64)
        } else {
            (256 * 1024 * 1024u64, 64 * 1024 * 1024u64)
        };
        let new_cap = if cur < DOUBLE_UNTIL {
            let mut c = cur.max(64);
            while c < need {
                c = c.saturating_mul(2).max(need);
            }
            c
        } else {
            need.saturating_add(headroom)
                .div_ceil(step)
                .saturating_mul(step)
                .max(need)
        };
        self.grow_to(new_cap)
    }

    /// Fallocate/`set_len` to `new_cap` and publish `file_cap`.
    fn grow_to(&self, new_cap: u64) -> Result<(), StoreError> {
        let file = self.file.lock().unwrap();
        if new_cap <= self.file_cap.load(Ordering::Acquire) {
            return Ok(());
        }
        if try_fallocate(&file, new_cap).is_err() {
            set_file_len(&file, &self.path, new_cap)?;
        } else if file.metadata().map(|m| m.len()).unwrap_or(0) < new_cap {
            set_file_len(&file, &self.path, new_cap)?;
        }
        drop(file);
        self.file_cap.store(new_cap, Ordering::Release);
        Ok(())
    }

    /// Punch a hole over `[offset, offset+len)`.
    pub fn zero_range(&self, offset: u64, len: u64) -> Result<(), StoreError> {
        if len == 0 {
            return Ok(());
        }
        self.ensure_capacity(offset.saturating_add(len))?;
        let file = self.file.lock().unwrap();
        if try_punch_hole(&file, offset, len).is_ok() {
            return Ok(());
        }
        drop(file);
        let zero = vec![0u8; 1024 * 1024];
        let mut written = 0u64;
        while written < len {
            let chunk = ((len - written) as usize).min(zero.len());
            self.write_at(offset + written, &zero[..chunk])?;
            written += chunk as u64;
        }
        Ok(())
    }

    /// Persist 8-byte HWM field (complete pwrite of the unit).
    fn persist_hwm(&self, logical: u64) -> Result<(), StoreError> {
        let bytes = logical.to_le_bytes();
        let hwm_off = if self.trailing_header {
            logical
                .saturating_sub(TRAILING_FOOTER_LEN as u64)
                .saturating_add(8)
        } else {
            8
        };
        self.pwrite_all(hwm_off, &bytes)
    }

    fn persist_logical_len(&self, logical: u64) -> Result<(), StoreError> {
        if self.trailing_header {
            // Full trailer is the durability unit (magic+schema+kind+HWM+ext).
            self.write_trailer(logical)?;
        } else {
            self.persist_hwm(logical)?;
        }
        Ok(())
    }

    /// Persist HWM / trailer and `sync_data`.
    ///
    /// Skips entirely when no payload write has occurred since the last
    /// successful sync (Class C tip barrier: avoid fsyncing multi‑GiB tables
    /// that were not dirtied this batch).
    pub fn flush(&self) -> Result<(), StoreError> {
        if !self.needs_sync.load(Ordering::Acquire) {
            return Ok(());
        }
        let logical = self.published_len.load(Ordering::Acquire);
        self.persist_logical_len(logical)?;
        self.file
            .lock()
            .unwrap()
            .sync_data()
            .map_err(|e| StoreError::io(&self.path, e))?;
        self.needs_sync.store(false, Ordering::Release);
        Ok(())
    }

    /// Persist HWM / trailer without waiting on `sync_data`.
    pub fn flush_async(&self) -> Result<(), StoreError> {
        let logical = self.published_len.load(Ordering::Acquire);
        self.persist_logical_len(logical)?;
        Ok(())
    }

    /// Walk a byte range via pread into a temporary buffer (tests only).
    ///
    /// Production Class A body inspection uses [`crate::var_table::VarTable::with_bytes_at`].
    #[cfg(test)]
    pub fn with_bytes<R>(
        &self,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, StoreError> {
        let end = offset.saturating_add(len);
        let logical = self.published_len.load(Ordering::Acquire);
        if end > logical {
            return Err(StoreError::Corrupt("with_bytes past logical end"));
        }
        let mut buf = vec![0u8; len as usize];
        self.pread_at(offset, &mut buf)?;
        Ok(f(&buf))
    }

    pub fn advise_dont_need(&self, offset: u64, len: u64) {
        #[cfg(target_os = "linux")]
        self.posix_fadvise(offset, len, libc::POSIX_FADV_DONTNEED);
        #[cfg(not(target_os = "linux"))]
        let _ = (offset, len);
    }

    pub fn advise_will_need(&self, offset: u64, len: u64) {
        #[cfg(target_os = "linux")]
        self.posix_fadvise(offset, len, libc::POSIX_FADV_WILLNEED);
        #[cfg(not(target_os = "linux"))]
        let _ = (offset, len);
    }

    pub fn unix_device_id(&self) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&self.path).map(|m| m.dev()).unwrap_or(0)
        }
        #[cfg(not(unix))]
        {
            0
        }
    }

    #[cfg(target_os = "linux")]
    fn posix_fadvise(&self, offset: u64, len: u64, advice: libc::c_int) {
        if len == 0 {
            return;
        }
        use std::os::unix::io::AsRawFd;
        let file = self.file.lock().unwrap();
        let fd = file.as_raw_fd();
        let rc =
            unsafe { libc::posix_fadvise(fd, offset as libc::off_t, len as libc::off_t, advice) };
        if rc != 0 {
            rbitcoin_log::trace!(
                "store: posix_fadvise failed path={} off={offset} len={len}: {}",
                self.path.display(),
                std::io::Error::from_raw_os_error(rc)
            );
        }
    }
}

/// True when both `st_dev` values are known and differ (split NVMe/HDD).
pub(crate) fn distinct_unix_devices(a: u64, b: u64) -> bool {
    a != 0 && b != 0 && a != b
}

#[cfg(test)]
mod advise_tests {
    use super::*;
    use rbitcoin_primitives::TableKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn grow_tight_adds_one_mib_not_slab() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-grow-tight-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::ArrayLink).unwrap();
        f.set_grow_tight(true);
        let payload = vec![0x11u8; 2048];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        let on_disk = std::fs::metadata(&path).unwrap().len();
        // need ≈ 16+2048; tight grow is need+1MiB, never a 64–256 MiB slab.
        assert!(on_disk > 2048);
        assert!(
            on_disk < 2 * 1024 * 1024,
            "tight grow should stay near 1 MiB, got {on_disk}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn grow_align_64k_not_slab() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-grow-64k-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::ArrayLink).unwrap();
        f.set_grow_policy(GrowPolicy::Align64k);
        let payload = vec![0x11u8; 16];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        let need = FILE_HEADER_LEN as u64 + 16;
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert!(on_disk >= need);
        assert!(
            on_disk < need + 128 * 1024,
            "64 KiB grow must stay < 128 KiB above need, got {on_disk}"
        );
        assert!(
            on_disk < 64 * 1024 * 1024,
            "SH-style grow must not punch a 64 MiB slab, got {on_disk}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn distinct_unix_devices_requires_both_nonzero_and_unequal() {
        assert!(!super::distinct_unix_devices(0, 0));
        assert!(!super::distinct_unix_devices(0, 8));
        assert!(!super::distinct_unix_devices(8, 0));
        assert!(!super::distinct_unix_devices(8, 8));
        assert!(super::distinct_unix_devices(8, 9));
    }

    #[test]
    fn advise_will_need_is_best_effort() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-advise-willneed-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        let payload = vec![0xcdu8; 16 * 1024];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        f.advise_will_need(FILE_HEADER_LEN as u64, payload.len() as u64);
        f.advise_will_need(0, 0);
        let mut buf = vec![0u8; payload.len()];
        f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
        assert_eq!(buf, payload);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn advise_dont_need_is_best_effort() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-advise-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        let payload = vec![0xabu8; 16 * 1024];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        f.advise_dont_need(FILE_HEADER_LEN as u64, payload.len() as u64);
        f.advise_dont_need(0, 0);
        let mut buf = vec![0u8; payload.len()];
        f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
        assert_eq!(buf, payload);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn table_file_create_open_roundtrip() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path3 = std::env::temp_dir().join(format!("rbitcoin-access-idx-{id}"));
        let _ = std::fs::remove_file(&path3);
        let idx = TableFile::create(&path3, TableKind::ArrayLink).unwrap();
        let payload = 42u32.to_le_bytes();
        let off = FILE_HEADER_LEN as u64;
        idx.write_at_pwrite(off, &payload).unwrap();
        let mut got = [0u8; 4];
        idx.read_at(off, &mut got).unwrap();
        assert_eq!(got, payload);
        drop(idx);
        let idx2 = TableFile::open(&path3, TableKind::ArrayLink).unwrap();
        let mut got2 = [0u8; 4];
        idx2.read_at(off, &mut got2).unwrap();
        assert_eq!(got2, payload);
        let _ = std::fs::remove_file(&path3);
    }

    /// Tweet pin: first store file is `scripthash.body`. Windows
    /// `FILE_FLAG_OVERLAPPED` + std `WriteFile`/`ReadFile` (NULL OVERLAPPED)
    /// is os error 87. Create, payload pwrite, reopen, and grow must work.
    #[test]
    fn scripthash_body_create_open_roundtrip() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-body-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("scripthash.body");
        let f = TableFile::create(&path, TableKind::ScriptHash).unwrap();
        let payload = [0xABu8; 32];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        f.flush().unwrap();
        drop(f);
        let f2 = TableFile::open(&path, TableKind::ScriptHash).unwrap();
        let mut got = [0u8; 32];
        f2.read_at(FILE_HEADER_LEN as u64, &mut got).unwrap();
        assert_eq!(got, payload);
        f2.ensure_capacity(4096).unwrap();
        f2.write_at(FILE_HEADER_LEN as u64 + 32, &[0xCD; 8])
            .unwrap();
        drop(f2);
        let f3 = TableFile::open(&path, TableKind::ScriptHash).unwrap();
        let mut tail = [0u8; 8];
        f3.read_at(FILE_HEADER_LEN as u64 + 32, &mut tail).unwrap();
        assert_eq!(tail, [0xCD; 8]);
        drop(f3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_readers_during_append_and_grow() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let _stress = TEST_MMAP_STRESS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-epoch-stress-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = Arc::new(TableFile::create(&path, TableKind::TxOut).unwrap());

        let seed = vec![0x11u8; 64];
        f.write_at(FILE_HEADER_LEN as u64, &seed).unwrap();
        assert_eq!(f.logical_len(), FILE_HEADER_LEN as u64 + seed.len() as u64);

        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        {
            let f = Arc::clone(&f);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut off = f.logical_len();
                for i in 0..200u32 {
                    let chunk = vec![(i % 251) as u8; 4096];
                    f.write_at(off, &chunk).unwrap();
                    off += chunk.len() as u64;
                }
            }));
        }

        {
            let f = Arc::clone(&f);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..500u32 {
                    let b = [((i % 200) + 1) as u8; 8];
                    f.write_at(FILE_HEADER_LEN as u64, &b).unwrap();
                }
            }));
        }

        for _ in 0..3 {
            let f = Arc::clone(&f);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..1000 {
                    let len = f.logical_len();
                    if len <= FILE_HEADER_LEN as u64 {
                        continue;
                    }
                    let n = (len - FILE_HEADER_LEN as u64).min(64) as usize;
                    let mut buf = vec![0u8; n];
                    f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
                    let _ = buf[0];
                }
            }));
        }

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                h.join().unwrap();
            }
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("concurrent TableFile workers timed out (hang?)");
        let final_len = f.logical_len();
        assert!(final_len > FILE_HEADER_LEN as u64 + 64);
        let mut head = [0u8; 8];
        f.read_at(FILE_HEADER_LEN as u64, &mut head).unwrap();
        assert_ne!(head, [0u8; 8]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_store_u32_u64_zero_range_trailing_and_open_errors() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-file-atomics-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        let payload = [0u8; 64];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        let off32 = FILE_HEADER_LEN as u64;
        let off64 = FILE_HEADER_LEN as u64 + 8;
        f.write_at(off32, &0x1122_3344u32.to_le_bytes()).unwrap();
        assert_eq!(f.load_u32_le(off32).unwrap(), 0x1122_3344);
        f.write_at(off64, &0x0102_0304_0506_0708u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.load_u64_le(off64).unwrap(), 0x0102_0304_0506_0708);
        assert!(matches!(
            f.load_u32_le(off32 + 1),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(f.load_u32_le(10_000), Err(StoreError::Corrupt(_))));
        f.zero_range(0, 0).unwrap();
        f.zero_range(FILE_HEADER_LEN as u64 + 32, 16).unwrap();
        f.set_logical_len(FILE_HEADER_LEN as u64 + 48).unwrap();
        assert!(matches!(f.set_logical_len(0), Err(StoreError::Corrupt(_))));
        assert!(matches!(
            f.with_bytes(FILE_HEADER_LEN as u64, 10_000, |_| ()),
            Err(StoreError::Corrupt(_))
        ));
        drop(f);

        {
            let bad = std::env::temp_dir().join(format!("rbitcoin-file-bad-{id}"));
            let _ = std::fs::remove_file(&bad);
            std::fs::write(
                &bad,
                b"XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
            .unwrap();
            assert!(matches!(
                TableFile::open(&bad, TableKind::TxOut),
                Err(StoreError::BadMagic)
            ));
            let _ = std::fs::remove_file(&bad);
        }
        {
            let th = std::env::temp_dir().join(format!("rbitcoin-file-trail-{id}"));
            let _ = std::fs::remove_file(&th);
            let f = TableFile::create_trailing_header(&th, TableKind::HashHead).unwrap();
            let data_bytes = 64u64;
            f.set_logical_len(data_bytes + TRAILING_FOOTER_LEN as u64)
                .unwrap();
            f.write_at(0, &[0xABu8; 64]).unwrap();
            f.flush().unwrap();
            drop(f);
            let (f2, _ext) =
                TableFile::open_trailing_header(&th, TableKind::HashHead, data_bytes).unwrap();
            let mut b = [0u8; 4];
            f2.read_at(0, &mut b).unwrap();
            assert_eq!(b, [0xAB; 4]);
            assert!(matches!(
                TableFile::open_trailing_header(&th, TableKind::HashHead, 1_000_000),
                Err(StoreError::Corrupt(_))
            ));
            assert!(matches!(
                TableFile::open_trailing_header(&th, TableKind::TxOut, data_bytes),
                Err(StoreError::BadKind { .. })
            ));
            let (mut f3, _ext) =
                TableFile::open_trailing_header(&th, TableKind::HashHead, data_bytes).unwrap();
            f3.set_trailing_ext([0x11; 16]).unwrap();
            f3.flush().unwrap();
            drop(f3);
            {
                let tight = std::env::temp_dir().join(format!("rbitcoin-file-trail-tight-{id}"));
                let _ = std::fs::remove_file(&tight);
                let data = [0xCDu8; 32];
                let logical = data.len() as u64 + TRAILING_FOOTER_LEN as u64;
                let mut footer = [0u8; TRAILING_FOOTER_LEN];
                footer[0..4].copy_from_slice(&STORE_MAGIC);
                footer[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
                footer[6..8].copy_from_slice(&TableKind::HashHead.as_u16().to_le_bytes());
                footer[8..16].copy_from_slice(&logical.to_le_bytes());
                footer[16..32].copy_from_slice(&[0x22; 16]);
                let mut raw = Vec::with_capacity(logical as usize);
                raw.extend_from_slice(&data);
                raw.extend_from_slice(&footer);
                std::fs::write(&tight, &raw).unwrap();
                let (f4, ext) =
                    TableFile::open_trailing_header_from_end(&tight, TableKind::HashHead).unwrap();
                assert_eq!(ext, [0x22; 16]);
                let mut b = [0u8; 4];
                f4.read_at(0, &mut b).unwrap();
                assert_eq!(b, [0xCD; 4]);
                drop(f4);
                let _ = std::fs::remove_file(&tight);
            }
            let short = std::env::temp_dir().join(format!("rbitcoin-file-trail-short-{id}"));
            let _ = std::fs::remove_file(&short);
            std::fs::write(&short, b"tiny").unwrap();
            assert!(matches!(
                TableFile::open_trailing_header_from_end(&short, TableKind::HashHead),
                Err(StoreError::Corrupt(_))
            ));
            let _ = std::fs::remove_file(&short);
            let badm = std::env::temp_dir().join(format!("rbitcoin-file-trail-badm-{id}"));
            let _ = std::fs::remove_file(&badm);
            let raw = vec![0u8; 64 + TRAILING_FOOTER_LEN];
            std::fs::write(&badm, &raw).unwrap();
            assert!(matches!(
                TableFile::open_trailing_header_from_end(&badm, TableKind::HashHead),
                Err(StoreError::BadMagic)
            ));
            let _ = std::fs::remove_file(&badm);
            let _ = std::fs::remove_file(&th);
        }
        {
            let lead = std::env::temp_dir().join(format!("rbitcoin-file-lead-{id}"));
            let _ = std::fs::remove_file(&lead);
            let mut f = TableFile::create(&lead, TableKind::TxOut).unwrap();
            assert!(matches!(
                f.set_trailing_ext([0; 16]),
                Err(StoreError::Corrupt(_))
            ));
            drop(f);
            let _ = std::fs::remove_file(&lead);
        }
        {
            let p = std::env::temp_dir().join(format!("rbitcoin-file-readpast-{id}"));
            let _ = std::fs::remove_file(&p);
            let f = TableFile::create(&p, TableKind::TxOut).unwrap();
            let mut big = [0u8; 8];
            assert!(matches!(
                f.read_at(FILE_HEADER_LEN as u64 + 1000, &mut big),
                Err(StoreError::Corrupt(_))
            ));
            drop(f);
            let _ = std::fs::remove_file(&p);
        }
        let _ = ensure_nofile_budget();
        let _ = ensure_nofile_budget_at_least(64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trailing_header_open_error_arms() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-trail-err-{id}"));
        let _ = std::fs::create_dir_all(&dir);
        let short = dir.join("short");
        std::fs::write(&short, b"tiny").unwrap();
        assert!(matches!(
            TableFile::open_trailing_header_from_end(&short, TableKind::TxOut),
            Err(StoreError::Corrupt(_))
        ));
        let bad_magic = dir.join("badmag");
        std::fs::write(&bad_magic, vec![0u8; TRAILING_FOOTER_LEN]).unwrap();
        assert!(matches!(
            TableFile::open_trailing_header_from_end(&bad_magic, TableKind::TxOut),
            Err(StoreError::BadMagic)
        ));
        let good = dir.join("good");
        let f = TableFile::create_trailing_header(&good, TableKind::TxOut).unwrap();
        f.ensure_capacity(4096 + TRAILING_FOOTER_LEN as u64)
            .unwrap();
        f.set_logical_len(4096 + TRAILING_FOOTER_LEN as u64)
            .unwrap();
        drop(f);
        let (_f2, _ext) =
            TableFile::open_trailing_header_from_end(&good, TableKind::TxOut).unwrap();
        assert!(matches!(
            TableFile::open_trailing_header_from_end(&good, TableKind::Header),
            Err(StoreError::BadKind { .. })
        ));
        let good2 = dir.join("good2");
        let f = TableFile::create_trailing_header(&good2, TableKind::TxOut).unwrap();
        f.ensure_capacity(1024 + TRAILING_FOOTER_LEN as u64)
            .unwrap();
        f.set_logical_len(1024 + TRAILING_FOOTER_LEN as u64)
            .unwrap();
        drop(f);
        let (_f3, _) = TableFile::open_trailing_header(&good2, TableKind::TxOut, 1024).unwrap();
        assert!(TableFile::open_trailing_header(&good2, TableKind::TxOut, 50_000).is_err());
        let path = dir.join("normal");
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        f.write_at(FILE_HEADER_LEN as u64, &[1, 2, 3, 4, 5, 6, 7, 8])
            .unwrap();
        let u = f.load_u32_le(FILE_HEADER_LEN as u64).unwrap();
        assert_eq!(u, u32::from_le_bytes([1, 2, 3, 4]));
        f.write_at(FILE_HEADER_LEN as u64, &0x1122_3344u32.to_le_bytes())
            .unwrap();
        f.write_at(
            FILE_HEADER_LEN as u64,
            &0x0102_0304_0506_0708u64.to_le_bytes(),
        )
        .unwrap();
        let _ = f.load_u64_le(FILE_HEADER_LEN as u64).unwrap();
        f.zero_range(FILE_HEADER_LEN as u64, 8).unwrap();
        f.set_logical_len(FILE_HEADER_LEN as u64 + 8).unwrap();
        let _ = f.path();
        let _ = f.data_len();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// pwrite payload must be visible via pread (page-cache coherency).
    #[test]
    fn write_at_pwrite_visible_via_pread() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-pwrite-vis-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        let payload = b"fd-append-payload-0123456789abcdef";
        let off = FILE_HEADER_LEN as u64;
        f.write_at_pwrite(off, payload).unwrap();
        assert_eq!(f.logical_len(), off + payload.len() as u64);
        let mut got = vec![0u8; payload.len()];
        f.read_at(off, &mut got).unwrap();
        assert_eq!(&got[..], payload);
        let more = b"MORE";
        let off2 = f.logical_len();
        f.write_at_pwrite(off2, more).unwrap();
        let mut got2 = [0u8; 4];
        f.read_at(off2, &mut got2).unwrap();
        assert_eq!(&got2, more);
        drop(f);
        let _ = std::fs::remove_file(&path);
    }

    /// HWM on disk never exceeds what is fully written (complete-or-fail publish).
    #[test]
    fn hwm_publish_matches_full_payload_after_flush() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-hwm-pub-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        let payload = vec![0x5Au8; 1024];
        f.write_at(FILE_HEADER_LEN as u64, &payload).unwrap();
        f.flush().unwrap();
        let published = f.logical_len();
        drop(f);
        // Raw header HWM must equal published length.
        let raw = std::fs::read(&path).unwrap();
        let hwm = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        assert_eq!(hwm, published);
        assert_eq!(hwm, FILE_HEADER_LEN as u64 + 1024);
        // Reopen sees full payload, nothing past HWM.
        let f2 = TableFile::open(&path, TableKind::TxOut).unwrap();
        assert_eq!(f2.logical_len(), published);
        let mut got = vec![0u8; 1024];
        f2.read_at(FILE_HEADER_LEN as u64, &mut got).unwrap();
        assert_eq!(got, payload);
        let mut past = [0u8; 1];
        assert!(f2.read_at(published, &mut past).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn table_file_surface_and_nofile_budget() {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rbitcoin-file-surface-{id}"));
        let _ = std::fs::remove_file(&path);
        let f = TableFile::create(&path, TableKind::TxOut).unwrap();
        assert!(f.logical_len() >= FILE_HEADER_LEN as u64);
        let payload = b"hello-table";
        f.write_at(FILE_HEADER_LEN as u64, payload).unwrap();
        let mut buf = vec![0u8; payload.len()];
        f.read_at(FILE_HEADER_LEN as u64, &mut buf).unwrap();
        assert_eq!(&buf, payload);
        f.with_bytes(FILE_HEADER_LEN as u64, payload.len() as u64, |b| {
            assert_eq!(b, payload);
        })
        .unwrap();
        f.ensure_capacity(f.logical_len() + 4096).unwrap();
        f.flush().unwrap();
        f.flush_async().unwrap();
        let _ = f.read_fd();
        drop(f);
        let f = TableFile::open(&path, TableKind::TxOut).unwrap();
        let mut buf2 = vec![0u8; payload.len()];
        f.read_at(FILE_HEADER_LEN as u64, &mut buf2).unwrap();
        assert_eq!(&buf2, payload);
        assert!(matches!(
            TableFile::open(&path, TableKind::Header),
            Err(StoreError::BadKind { .. })
        ));
        drop(f);
        let (soft, hard) = ensure_nofile_budget();
        assert!(soft > 0 || hard > 0 || cfg!(not(unix)));
        let (s2, _) = ensure_nofile_budget_at_least(64);
        assert!(s2 >= 64 || cfg!(not(unix)) || soft == 0);
        let _ = std::fs::remove_file(&path);
    }
}

pub const NOFILE_SOFT_TARGET: u64 = 16_384;

/// Process-wide lock for multi-thread table stress tests.
#[cfg(test)]
pub(crate) static TEST_MMAP_STRESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn ensure_nofile_budget() -> (u64, u64) {
    ensure_nofile_budget_at_least(NOFILE_SOFT_TARGET)
}

pub fn ensure_nofile_budget_at_least(want_soft: u64) -> (u64, u64) {
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
            rbitcoin_log::warn!(
                "store: getrlimit(NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            return (0, 0);
        }
        let hard = rlim.rlim_max as u64;
        let soft = rlim.rlim_cur as u64;
        let hard_cap = if hard == u64::MAX || rlim.rlim_max == libc::RLIM_INFINITY {
            want_soft.max(soft)
        } else {
            hard
        };
        let target = want_soft.min(hard_cap).max(soft);
        if target > soft {
            rlim.rlim_cur = target as libc::rlim_t;
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
                rbitcoin_log::warn!(
                    "store: setrlimit(NOFILE) soft {soft}→{target} failed (hard={hard}): {}",
                    std::io::Error::last_os_error()
                );
                return (soft, hard);
            }
            rbitcoin_log::debug!("store: raised RLIMIT_NOFILE soft {soft}→{target} (hard={hard})");
            return (target, hard);
        }
        if soft < want_soft {
            rbitcoin_log::warn!(
                "store: RLIMIT_NOFILE soft={soft} hard={hard} below target {want_soft}; \
                 sharded heads need ~1k+ FDs — raise hard limit (ulimit -n / LimitNOFILE) \
                 if open fails with EMFILE"
            );
        }
        return (soft, hard);
    }
    #[cfg(not(unix))]
    {
        let _ = want_soft;
        (0, 0)
    }
}

fn try_fallocate(file: &File, len: u64) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, len as i64) };
        if rc == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, len);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fallocate unavailable",
        ))
    }
}

fn try_punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        const PUNCH: i32 = 0x02 | 0x01;
        let rc = unsafe { libc::fallocate(file.as_raw_fd(), PUNCH, offset as i64, len as i64) };
        if rc == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, offset, len);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "punch hole unavailable",
        ))
    }
}
