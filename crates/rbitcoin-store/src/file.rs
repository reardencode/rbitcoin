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
//! 4. Persist HWM (one 8-byte pwrite of that length).
//!
//! Readers never consume past `published_len`. A crash mid-payload leaves HWM
//! at the previous value; re-drive rebuilds from body queue / re-append.
//! A multi-file append can advance RAM without that pwrite when an earlier
//! header pwrite failed. `flush` then keeps the previous header. A locator
//! file remembers that previous end and retries it before a later append
//! publishes.
//!
//! # Concurrency
//!
//! - **Published logical length** is an `AtomicU64` (Acquire/Release).
//! - `File` is locked only for grow (fallocate / Windows EOF / `set_len`),
//!   `flush`'s `sync_data`, and fadvise. `sync_data_only` uses the read fd.
//! - Roles (see `docs/concurrency.md`): at most one appender and
//!   one annotator; N concurrent readers of published ranges.

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use rbitcoin_primitives::{schema_file_openable, TableKind, SCHEMA_VERSION, STORE_MAGIC};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

pub const FILE_HEADER_LEN: usize = 16;

/// Bytes [`TableFile::create`] leaves past the header. A longer file is payload.
pub(crate) const CREATE_FILE_SLACK: u64 = 64;

/// Sibling `{filename}.tmp` next to `path` (keeps compound suffixes like `.idx`).
pub fn tmp_sidecar_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("file"))
        .to_os_string();
    name.push(".tmp");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// Write `bytes` to a sibling tmp, then rename over `path`. No `sync_all`.
pub fn write_tmp_rename(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_tmp_file(path, false, |f| {
        f.write_all(bytes).map_err(|e| StoreError::io(path, e))
    })
}

/// Write `bytes` to a sibling tmp, `sync_all`, then rename over `path`.
pub fn write_synced_tmp_rename(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_tmp_file(path, true, |f| {
        f.write_all(bytes).map_err(|e| StoreError::io(path, e))
    })
}

/// Stream `write` into a sibling tmp, `sync_all`, then rename over `path`.
///
/// The durable name is not created or truncated until rename.
pub fn write_synced_tmp_file<F>(path: &Path, write: F) -> Result<(), StoreError>
where
    F: FnOnce(&mut File) -> Result<(), StoreError>,
{
    write_tmp_file(path, true, write)
}

#[doc(hidden)]
pub fn write_tmp_file<F>(path: &Path, sync: bool, write: F) -> Result<(), StoreError>
where
    F: FnOnce(&mut File) -> Result<(), StoreError>,
{
    let tmp = tmp_sidecar_path(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
        }
    }
    {
        let mut f = File::create(&tmp).map_err(|e| StoreError::io(&tmp, e))?;
        write(&mut f)?;
        if sync {
            f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))?;
    if sync {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
            }
        }
    }
    Ok(())
}

/// `fsync` the directory so a renamed dirent survives a crash.
///
/// Windows denies a directory handle (`ERROR_ACCESS_DENIED`), including with
/// backup semantics. The file itself was already `sync_all`'d before rename.
pub fn fsync_parent_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Trailing-header tables (`tx.head`): 16-byte store identity + 16-byte layout
/// extension (bits / entry width / generation). Slots still start at file offset 0
/// so probe pages stay OS-page-aligned.
pub const TRAILING_FOOTER_LEN: usize = 32;

pub struct TableFile {
    pub path: PathBuf,
    /// Grow / fsync / fadvise only — not on the pread/pwrite hot path.
    pub file: Mutex<File>,
    /// Cloned FD for lock-free [`pread`](Self::pread_at) / io_uring bulk reads.
    pub read_file: File,
    /// Logical length including header/trailer (published HWM).
    pub published_len: AtomicU64,
    /// Non-zero: `flush` persists this length instead of `published_len`.
    /// Set when RAM advances without a header write, so a later flush cannot
    /// name bytes whose locator header did not land. Zero follows `published_len`.
    header_cap: AtomicU64,
    /// File capacity. Always ≥ published; grown via fallocate without mapping.
    pub file_cap: AtomicU64,
    /// When true: [`TRAILING_FOOTER_LEN`]-byte magic+HWM+layout trailer is at
    /// **end** of published range; data starts at offset 0 (page-aligned probes).
    pub trailing_header: bool,
    /// Layout extension for trailing footers (address-head bits/gen).
    pub trailing_ext: [u8; 16],
    pub kind: TableKind,
    /// Payload/HWM written since last successful `sync_data` (Class C barrier skip).
    pub needs_sync: AtomicBool,
    /// Header still names a longer end than `published_len`. A grow must store
    /// the short end before it extends the file, or open loads the old end.
    hwm_behind: AtomicBool,
    /// One flusher at a time, so a second never returns before the first's sync.
    pub flush_lock: Mutex<()>,
    /// [`GrowPolicy`] as u8. Idx uses 1 MiB; SH body uses 64 KiB; Class A slabs.
    pub grow_policy: AtomicU8,
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

#[doc(hidden)]
pub fn table_open_opts() -> OpenOptions {
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

pub fn leading_header_bytes(kind: TableKind, logical: u64) -> [u8; FILE_HEADER_LEN] {
    encode_leading_header(kind, logical)
}

#[doc(hidden)]
pub fn encode_leading_header(kind: TableKind, logical: u64) -> [u8; FILE_HEADER_LEN] {
    let mut header = [0u8; FILE_HEADER_LEN];
    header[0..4].copy_from_slice(&STORE_MAGIC);
    header[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&kind.as_u16().to_le_bytes());
    header[8..16].copy_from_slice(&logical.to_le_bytes());
    header
}

/// Complete positional write. Safe on Windows `FILE_FLAG_OVERLAPPED` handles
/// (std `Write` / `WriteFile` with a NULL `OVERLAPPED` is os error 87).
pub fn handle_pwrite_all(
    file: &File,
    path: &Path,
    offset: u64,
    bytes: &[u8],
) -> Result<(), StoreError> {
    if bytes.is_empty() {
        return Ok(());
    }
    rbitcoin_primitives::assert_not_script_worker("store write");
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
pub fn handle_pread_all(
    file: &File,
    path: &Path,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), StoreError> {
    if buf.is_empty() {
        return Ok(());
    }
    rbitcoin_primitives::assert_not_script_worker("store read");
    crate::coord_io::note_store_read();
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

#[doc(hidden)]
pub fn set_file_len(file: &File, path: &Path, new_len: u64) -> Result<(), StoreError> {
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
        let initial = FILE_HEADER_LEN as u64 + CREATE_FILE_SLACK;
        // Capacity first, then header via overlapped-safe pwrite (not std Write).
        set_file_len(&file, &path, initial)?;
        handle_pwrite_all(&file, &path, 0, &header)?;
        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;

        Ok(Self {
            path,
            file: Mutex::new(file),
            read_file,
            published_len: AtomicU64::new(FILE_HEADER_LEN as u64),
            header_cap: AtomicU64::new(0),
            file_cap: AtomicU64::new(initial),
            trailing_header: false,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(false),
            hwm_behind: AtomicBool::new(false),
            flush_lock: Mutex::new(()),
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
            header_cap: AtomicU64::new(0),
            file_cap: AtomicU64::new(initial),
            trailing_header: true,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(false),
            hwm_behind: AtomicBool::new(false),
            flush_lock: Mutex::new(()),
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
                header_cap: AtomicU64::new(0),
                file_cap: AtomicU64::new(file_len.max(logical)),
                trailing_header: true,
                trailing_ext,
                kind,
                needs_sync: AtomicBool::new(false),
                hwm_behind: AtomicBool::new(false),
                flush_lock: Mutex::new(()),
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

    #[doc(hidden)]
    pub fn trailing_footer_data_bytes(
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

    #[doc(hidden)]
    pub fn write_trailer(&self, logical: u64) -> Result<(), StoreError> {
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
        let hwm_behind = logical > file_len;
        if hwm_behind {
            logical = file_len;
        }

        let read_file = file.try_clone().map_err(|e| StoreError::io(&path, e))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            read_file,
            published_len: AtomicU64::new(logical),
            header_cap: AtomicU64::new(0),
            file_cap: AtomicU64::new(file_len.max(logical)),
            trailing_header: false,
            trailing_ext: [0u8; 16],
            kind,
            needs_sync: AtomicBool::new(hwm_behind),
            hwm_behind: AtomicBool::new(hwm_behind),
            flush_lock: Mutex::new(()),
            grow_policy: AtomicU8::new(GrowPolicy::Slab as u8),
        })
    }

    pub fn logical_len(&self) -> u64 {
        self.published_len.load(Ordering::Acquire)
    }

    /// Length a flush will store. A withheld header stays at the last landed end.
    pub(crate) fn header_persist_len(&self) -> u64 {
        self.header_len_to_persist()
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
            let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
            // Trailer rewrite includes HWM; publish after full trailer write.
            self.write_trailer(logical)?;
            self.published_len.store(logical, Ordering::Release);
            self.header_cap.store(0, Ordering::Release);
        } else {
            self.publish_prefixed_len(logical)?;
        }
        self.needs_sync.store(true, Ordering::Release);
        Ok(())
    }

    /// Store `logical` as the prefixed-header length.
    ///
    /// A non-zero `header_cap` is a body end whose locator header did not
    /// land. A slot patch must not persist or extend past that cap. The
    /// flush lock covers the length and the cap so flush cannot observe a
    /// cleared cap with the withheld end.
    fn publish_prefixed_len(&self, logical: u64) -> Result<(), StoreError> {
        let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        let prev = self.published_len.load(Ordering::Relaxed);
        let cap = self.header_cap.load(Ordering::Relaxed);
        if cap != 0 && logical > cap {
            if logical < prev {
                self.published_len.store(logical, Ordering::Release);
            }
            return Ok(());
        }
        // Readers use this length as the next append start. A grow that
        // does not persist must not stay published. A shrink that fails
        // must stay the shorter length: putting the longer value back
        // makes the next flush record bytes the locators do not own.
        self.published_len.store(logical, Ordering::Release);
        let attempts = if logical < prev { 4 } else { 1 };
        let mut persist_err = None;
        for _ in 0..attempts {
            match self.persist_hwm(logical) {
                Ok(()) => {
                    persist_err = None;
                    break;
                }
                Err(e) => persist_err = Some(e),
            }
        }
        if let Some(e) = persist_err {
            if logical > prev {
                self.published_len.store(prev, Ordering::Release);
                return Err(e);
            }
            if logical == prev {
                return Err(e);
            }
            // Readers already append from `logical`. The header still
            // names `prev`. End the file here so open cannot load `prev`.
            self.keep_short_end(logical)?;
        }
        if cap != 0 {
            self.header_cap.store(0, Ordering::Release);
        }
        Ok(())
    }

    /// `logical` is the published shorter end. The 8-byte header write did
    /// not land. Cutting the file makes open's length clamp keep this end
    /// until a grow stores that end.
    fn keep_short_end(&self, logical: u64) -> Result<(), StoreError> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        set_file_len(&file, &self.path, logical)?;
        drop(file);
        self.file_cap.store(logical, Ordering::Release);
        match self.persist_hwm(logical) {
            Ok(()) => self.hwm_behind.store(false, Ordering::Release),
            Err(_) => self.hwm_behind.store(true, Ordering::Release),
        }
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
    #[doc(hidden)]
    pub fn pread_all(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        handle_pread_all(&self.read_file, &self.path, offset, buf)
    }

    /// Complete pwrite of all bytes or error (no partial success returned).
    #[doc(hidden)]
    pub fn pwrite_all(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        handle_pwrite_all(&self.read_file, &self.path, offset, bytes)
    }

    /// Pread `buf` with no logical-end load.
    ///
    /// The caller already compared `offset + len` to a published end. A second
    /// `logical_len` load can disagree with that snapshot.
    pub fn pread_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() {
            return Ok(());
        }
        self.pread_all(offset, buf)
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

    /// Payload past the published end. `published_len` stays put until the
    /// caller commits, so a later failed write does not move readers.
    pub fn write_uncommitted(&self, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = offset.saturating_add(bytes.len() as u64);
        self.ensure_capacity(end)?;
        self.pwrite_all(offset, bytes)?;
        self.needs_sync.store(true, Ordering::Release);
        Ok(())
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
        let _ = self.publish_end(end, true);
        self.needs_sync.store(true, Ordering::Release);
        Ok(())
    }

    /// Advance `published_len` to `end`.
    ///
    /// `durable` persists the header with one 8-byte pwrite, the same cost as
    /// [`Self::write_at`]. Otherwise only RAM moves, and `flush` keeps the
    /// previous header. A failed header pwrite does not roll RAM back.
    /// Returns whether the on-disk header names `end` or already covered it.
    #[must_use]
    pub fn publish_end(&self, end: u64, durable: bool) -> bool {
        if !durable {
            self.publish_ram_only(end);
            return false;
        }
        if !self.advance_published(end) {
            return true;
        }
        if self.header_cap.load(Ordering::Relaxed) != 0 {
            self.header_cap.store(0, Ordering::Release);
        }
        self.persist_hwm(end).is_ok()
    }

    /// Locator publish. Same one header pwrite as [`Self::publish_end`] when
    /// the write lands. A miss keeps the previous durable end so a later
    /// [`Self::catch_up_header`] can store it. The success path does not take
    /// the flush lock.
    #[must_use]
    pub fn publish_locator_end(&self, end: u64, durable: bool) -> bool {
        if !durable {
            self.publish_ram_only(end);
            return false;
        }
        let prior = self.published_len.load(Ordering::Relaxed);
        if !self.advance_published(end) {
            let cap = self.header_cap.load(Ordering::Relaxed);
            return cap == 0 || cap >= end;
        }
        if self.persist_hwm(end).is_ok() {
            self.clear_header_cap();
            return true;
        }
        self.withhold_locator_header(prior)
    }

    /// Persist a locator header that an earlier pwrite missed.
    ///
    /// No IO when the header already matches RAM. A miss leaves the cap in
    /// place and returns false.
    #[must_use]
    pub fn catch_up_header(&self) -> bool {
        let end = self.published_len.load(Ordering::Acquire);
        let cap = self.header_cap.load(Ordering::Acquire);
        if cap == 0 || cap >= end {
            return true;
        }
        let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        let end = self.published_len.load(Ordering::Acquire);
        let cap = self.header_cap.load(Ordering::Relaxed);
        if cap == 0 || cap >= end {
            return true;
        }
        if self.persist_hwm(end).is_err() {
            return false;
        }
        self.header_cap.store(0, Ordering::Release);
        true
    }

    /// Loc, overflow, and checkpoint headers for one locator family.
    #[must_use]
    pub(crate) fn catch_up_locator_headers(loc: &Self, ovf: &Self, off: &Self) -> bool {
        loc.catch_up_header() && ovf.catch_up_header() && off.catch_up_header()
    }

    fn clear_header_cap(&self) {
        if self.header_cap.load(Ordering::Relaxed) == 0 {
            return;
        }
        let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.header_cap.store(0, Ordering::Release);
    }

    /// `prior` is the RAM end from before this publish. The header stays at
    /// the last end that is actually on disk.
    fn withhold_locator_header(&self, prior: u64) -> bool {
        debug_assert!(!self.trailing_header);
        let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        let published = self.published_len.load(Ordering::Acquire);
        let mut buf = [0u8; 8];
        let disk = match self.pread_all(8, &mut buf) {
            Ok(()) => u64::from_le_bytes(buf),
            Err(_) => prior,
        };
        if disk == published {
            self.header_cap.store(0, Ordering::Release);
            return true;
        }
        let durable_end = if disk >= FILE_HEADER_LEN as u64 && disk < published {
            disk
        } else {
            prior
        };
        if durable_end < published {
            let cap = self.header_cap.load(Ordering::Relaxed);
            if cap == 0 || durable_end < cap {
                self.header_cap.store(durable_end, Ordering::Release);
            }
        }
        false
    }

    fn advance_published(&self, end: u64) -> bool {
        let mut cur = self.published_len.load(Ordering::Relaxed);
        while end > cur {
            match self.published_len.compare_exchange_weak(
                cur,
                end,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
        false
    }

    /// RAM length only. Holds the flush lock across the cap store and the
    /// RAM publish so `flush` cannot observe the new end with no cap.
    fn publish_ram_only(&self, end: u64) {
        let _hold = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        let prior = self.published_len.load(Ordering::Acquire);
        if end > prior && self.header_cap.load(Ordering::Relaxed) == 0 {
            self.header_cap.store(prior, Ordering::Release);
        }
        let _ = self.advance_published(end);
    }

    fn header_len_to_persist(&self) -> u64 {
        let published = self.published_len.load(Ordering::Acquire);
        let cap = self.header_cap.load(Ordering::Acquire);
        if cap == 0 {
            published
        } else {
            cap.min(published)
        }
    }

    /// Atomic little-endian `u32` load via pread (tests / diagnostics).
    #[cfg(debug_assertions)]
    pub fn load_u32_le(&self, offset: u64) -> Result<u32, StoreError> {
        if !offset.is_multiple_of(4) {
            return Err(StoreError::Corrupt("load_u32 unaligned"));
        }
        let mut buf = [0u8; 4];
        self.pread_at(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Atomic little-endian `u64` load via pread (tests / diagnostics).
    #[cfg(debug_assertions)]
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

    #[doc(hidden)]
    pub fn ensure_capacity_grow(&self, need: u64) -> Result<(), StoreError> {
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
    #[doc(hidden)]
    pub fn grow_to(&self, new_cap: u64) -> Result<(), StoreError> {
        if new_cap <= self.file_cap.load(Ordering::Acquire) {
            return Ok(());
        }
        // A cut file can still carry the pre-shrink header. Extending it
        // makes that longer value loadable again.
        if self.hwm_behind.load(Ordering::Acquire) {
            let published = self.published_len.load(Ordering::Acquire);
            self.persist_hwm(published)?;
            self.hwm_behind.store(false, Ordering::Release);
        }
        let file = self.file.lock().unwrap();
        if new_cap <= self.file_cap.load(Ordering::Acquire) {
            return Ok(());
        }
        if try_fallocate(&file, new_cap).is_err()
            || file.metadata().map(|m| m.len()).unwrap_or(0) < new_cap
        {
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
    #[doc(hidden)]
    pub fn persist_hwm(&self, logical: u64) -> Result<(), StoreError> {
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

    #[doc(hidden)]
    pub fn persist_logical_len(&self, logical: u64) -> Result<(), StoreError> {
        if self.trailing_header {
            // Full trailer is the durability unit (magic+schema+kind+HWM+ext).
            self.write_trailer(logical)?;
        } else {
            self.persist_hwm(logical)?;
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn pending_sync(&self) -> bool {
        self.needs_sync.load(Ordering::Acquire)
    }

    /// Device barrier for bytes already written on this file.
    ///
    /// Does not publish the high-water mark and does not clear `needs_sync`.
    /// Uses the read fd so the grow lock is not held across the wait.
    pub fn sync_data_only(&self) -> Result<(), StoreError> {
        self.read_file
            .sync_data()
            .map_err(|e| StoreError::io(&self.path, e))
    }

    /// Persist HWM / trailer and `sync_data`.
    ///
    /// Skips entirely when no payload write has occurred since the last
    /// successful sync (Class C tip barrier: avoid fsyncing multi‑GiB tables
    /// that were not dirtied this batch).
    pub fn flush(&self) -> Result<(), StoreError> {
        self.flush_between(|_| {})
    }

    #[doc(hidden)]
    pub fn flush_between(&self, between: impl FnOnce(&Self)) -> Result<(), StoreError> {
        let _one = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Clear before reading the length: a write that lands later sets it again.
        if !self.needs_sync.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let synced = self.persist_and_sync();
        between(self);
        if synced.is_err() {
            self.needs_sync.store(true, Ordering::Release);
        }
        synced
    }

    #[doc(hidden)]
    pub fn persist_and_sync(&self) -> Result<(), StoreError> {
        let logical = self.header_len_to_persist();
        self.persist_logical_len(logical)?;
        self.file
            .lock()
            .unwrap()
            .sync_data()
            .map_err(|e| StoreError::io(&self.path, e))
    }

    /// Persist HWM / trailer without waiting on `sync_data`.
    pub fn flush_async(&self) -> Result<(), StoreError> {
        let _one = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.persist_logical_len(self.header_len_to_persist())?;
        Ok(())
    }

    /// Walk a byte range via pread into a temporary buffer (tests only).
    ///
    /// Production Class A body inspection uses [`crate::var_table::VarTable::with_bytes_at`].
    #[cfg(debug_assertions)]
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

    /// `posix_fadvise` for the whole file. Linux best-effort; other OS no-op.
    /// Whole-file advice. Linux only; other hosts have no `posix_fadvise`.
    #[cfg(target_os = "linux")]
    pub fn advise_access(&self, advice: libc::c_int) {
        use std::os::unix::io::AsRawFd;
        let file = self.file.lock().unwrap();
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is the live file held by `self.file`. Advice is whole-file.
        let rc = unsafe { libc::posix_fadvise(fd, 0, 0, advice) };
        if rc != 0 {
            rbitcoin_log::trace!(
                "store: posix_fadvise failed path={}: {}",
                self.path.display(),
                std::io::Error::from_raw_os_error(rc)
            );
        }
    }

    pub fn advise_dont_need(&self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let file = self.file.lock().unwrap();
            let fd = file.as_raw_fd();
            // SAFETY: `fd` is the live file. `offset` and `len` are the caller's range.
            let rc = unsafe {
                libc::posix_fadvise(
                    fd,
                    offset as libc::off_t,
                    len as libc::off_t,
                    libc::POSIX_FADV_DONTNEED,
                )
            };
            if rc != 0 {
                rbitcoin_log::trace!(
                    "store: posix_fadvise(DONTNEED) failed path={} off={offset} len={len}: {}",
                    self.path.display(),
                    std::io::Error::from_raw_os_error(rc)
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (offset, len);
        }
    }
}

pub const NOFILE_SOFT_TARGET: u64 = 16_384;

/// Process-wide lock for multi-thread table stress tests.
#[cfg(debug_assertions)]
pub static TEST_MMAP_STRESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        // SAFETY: `rlim` is a local `rlimit` the call writes.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
            rbitcoin_log::warn!(
                "store: getrlimit(NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            return (0, 0);
        }
        let hard = rlim.rlim_max;
        let soft = rlim.rlim_cur;
        let hard_cap = if hard == u64::MAX || rlim.rlim_max == libc::RLIM_INFINITY {
            want_soft.max(soft)
        } else {
            hard
        };
        let target = want_soft.min(hard_cap).max(soft);
        if target > soft {
            rlim.rlim_cur = target as libc::rlim_t;
            // SAFETY: `rlim` was filled by `getrlimit` and only `rlim_cur` changed.
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
        (soft, hard)
    }
    #[cfg(not(unix))]
    {
        let _ = want_soft;
        (0, 0)
    }
}

#[doc(hidden)]
pub fn try_fallocate(file: &File, len: u64) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` is open. Mode 0 allocates `[0, len)`.
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

#[doc(hidden)]
pub fn try_punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        const PUNCH: i32 = 0x02 | 0x01;
        // SAFETY: `file` is open. `PUNCH` drops `[offset, offset+len)`.
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
