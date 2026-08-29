//! Leftover sorted-run files (`scripthash.runs`): header parse, list, discard.
//!
//! Historical SH catalog / k-way merge is gone. Tip materialize is unsorted
//! Class A collect. This module still opens leftover `*.run` / `*.run.mat` so
//! schema 17 can refuse `key_len=32` catalogs, and so tip finalize can count
//! and discard residual files (SEAL is kept).
//!
//! # Concurrency invariant (`runs_io`)
//!
//! Callers **must** hold the per-family `runs_io` mutex across list + delete.
//! [`list_runs`] may **delete** uncataloged `*.run` files (orphan cleanup).

use crate::error::StoreError;
use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Magic: `RBSORT02` (v2 header with body CRC).
const MAGIC: [u8; 8] = *b"RBSORT02";
/// Pre-checksum runs (pad was zero). Still readable; body CRC not verified.
const MAGIC_V1: [u8; 8] = *b"RBSORT01";
const HEADER_LEN: usize = 32;
/// header: magic8 | version_u32 | key_len_u32 | rec_len_u32 | count_u64 | body_crc32_u32
const VERSION: u32 = 2;
const VERSION_V1: u32 = 1;

/// Directory catalog: `MANIFEST` (atomic replace).
const MANIFEST_NAME: &str = "MANIFEST";
const MANIFEST_MAGIC: [u8; 8] = *b"RBRUNMF1";
const MANIFEST_VERSION: u32 = 1;
/// entry: seq_u64 | count_u64 | key_len_u32 | rec_len_u32 | body_crc32_u32 = 28
const MANIFEST_ENTRY_LEN: usize = 28;

fn io_err(path: &Path, e: std::io::Error) -> StoreError {
    StoreError::io(path, e)
}

fn crc32_table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    })
}

/// CRC-32 of `data` (init 0xFFFF_FFFF, final xor 0xFFFF_FFFF).
pub fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

fn crc32_file_body(path: &Path, body_len: u64) -> Result<u32, StoreError> {
    let mut f = File::open(path).map_err(|e| io_err(path, e))?;
    f.seek(SeekFrom::Start(HEADER_LEN as u64))
        .map_err(|e| io_err(path, e))?;
    let table = crc32_table();
    let mut c = 0xFFFF_FFFFu32;
    let mut left = body_len;
    let mut buf = [0u8; 64 * 1024];
    while left > 0 {
        let n = (left as usize).min(buf.len());
        f.read_exact(&mut buf[..n]).map_err(|e| io_err(path, e))?;
        for &b in &buf[..n] {
            c = table[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
        }
        left -= n as u64;
    }
    Ok(c ^ 0xFFFF_FFFF)
}

/// One immutable sorted run on disk.
#[derive(Debug, Clone)]
pub struct SortedRunPath {
    pub path: PathBuf,
    pub count: u64,
    pub rec_len: u32,
    pub key_len: u32,
    /// CRC-32 of the body (0 = legacy v1 / unknown).
    pub body_crc32: u32,
}

impl SortedRunPath {
    /// Sequence number from `{seq:06}.run` stem, if parseable.
    pub fn seq(&self) -> Option<u64> {
        seq_from_path(&self.path)
    }
}

fn seq_from_path(path: &Path) -> Option<u64> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Next run path: `{dir}/{seq:06}.run`.
pub fn next_run_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{seq:06}.run"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    seq: u64,
    count: u64,
    key_len: u32,
    rec_len: u32,
    body_crc32: u32,
}

impl ManifestEntry {
    fn from_run(run: &SortedRunPath) -> Option<Self> {
        Some(Self {
            seq: run.seq()?,
            count: run.count,
            key_len: run.key_len,
            rec_len: run.rec_len,
            body_crc32: run.body_crc32,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.key_len.to_le_bytes());
        out.extend_from_slice(&self.rec_len.to_le_bytes());
        out.extend_from_slice(&self.body_crc32.to_le_bytes());
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < MANIFEST_ENTRY_LEN {
            return None;
        }
        Some(Self {
            seq: u64::from_le_bytes(buf[0..8].try_into().ok()?),
            count: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            key_len: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            rec_len: u32::from_le_bytes(buf[20..24].try_into().ok()?),
            body_crc32: u32::from_le_bytes(buf[24..28].try_into().ok()?),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct Manifest {
    entries: Vec<ManifestEntry>,
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_NAME)
}

fn load_manifest(dir: &Path) -> Result<Option<Manifest>, StoreError> {
    let path = manifest_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let mut f = File::open(&path).map_err(|e| io_err(&path, e))?;
    let mut hdr = [0u8; 16];
    if f.read_exact(&mut hdr).is_err() {
        rbitcoin_log::warn!("store: sorted-run MANIFEST truncated at {}", path.display());
        return Ok(None);
    }
    if hdr[0..8] != MANIFEST_MAGIC {
        rbitcoin_log::warn!("store: sorted-run MANIFEST bad magic at {}", path.display());
        return Ok(None);
    }
    let ver = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    if ver != MANIFEST_VERSION {
        rbitcoin_log::warn!(
            "store: sorted-run MANIFEST unsupported version {ver} at {}",
            path.display()
        );
        return Ok(None);
    }
    let n = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    let mut body = vec![0u8; n.saturating_mul(MANIFEST_ENTRY_LEN)];
    if !body.is_empty() {
        f.read_exact(&mut body).map_err(|e| io_err(&path, e))?;
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * MANIFEST_ENTRY_LEN;
        let Some(e) = ManifestEntry::decode(&body[off..off + MANIFEST_ENTRY_LEN]) else {
            return Err(StoreError::Corrupt("sorted run manifest: bad entry"));
        };
        entries.push(e);
    }
    entries.sort_by_key(|e| e.seq);
    Ok(Some(Manifest { entries }))
}

/// Atomically replace `MANIFEST` (tmp + fsync + rename).
fn save_manifest(dir: &Path, mf: &Manifest) -> Result<(), StoreError> {
    fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
    let path = manifest_path(dir);
    let tmp = dir.join(format!("{MANIFEST_NAME}.tmp"));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| io_err(&tmp, e))?;
        let mut buf = Vec::with_capacity(16 + mf.entries.len() * MANIFEST_ENTRY_LEN);
        buf.extend_from_slice(&MANIFEST_MAGIC);
        buf.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        buf.extend_from_slice(&(mf.entries.len() as u32).to_le_bytes());
        for e in &mf.entries {
            e.encode(&mut buf);
        }
        f.write_all(&buf).map_err(|e| io_err(&tmp, e))?;
        f.sync_all().map_err(|e| io_err(&tmp, e))?;
    }
    fs::rename(&tmp, &path).map_err(|e| io_err(&path, e))?;
    // Best-effort directory durability for the new dirent.
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

fn manifest_insert(dir: &Path, run: &SortedRunPath) -> Result<(), StoreError> {
    let Some(entry) = ManifestEntry::from_run(run) else {
        // Non-standard name (tests use `lk.run`) — no catalog entry.
        return Ok(());
    };
    let mut mf = load_manifest(dir)?.unwrap_or_default();
    mf.entries.retain(|e| e.seq != entry.seq);
    mf.entries.push(entry);
    mf.entries.sort_by_key(|e| e.seq);
    save_manifest(dir, &mf)
}

fn rebuild_manifest_from_runs(dir: &Path, runs: &[SortedRunPath]) -> Result<(), StoreError> {
    let mut mf = Manifest::default();
    for r in runs {
        if let Some(e) = ManifestEntry::from_run(r) {
            mf.entries.push(e);
        }
    }
    mf.entries.sort_by_key(|e| e.seq);
    save_manifest(dir, &mf)
}

/// Durable catalog write: fsync + `POSIX_FADV_DONTNEED` after rename.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunWritePolicy {
    /// `fsync` file + parent dir after rename.
    pub durable: bool,
    /// `POSIX_FADV_DONTNEED` after write (long-lived catalog only).
    pub drop_cache: bool,
}

impl RunWritePolicy {
    /// Durable leftover-catalog write; full-speed write + DONTNEED.
    pub const CATALOG: Self = Self {
        durable: true,
        drop_cache: true,
    };
}

/// Write a new sorted run from **already sorted** fixed-width records.
///
/// `records` must be sorted ascending by the first `key_len` bytes of each
/// `rec_len`-byte record. Updates the parent directory [`MANIFEST`] when the
/// file name is `{seq:06}.run`. Uses [`RunWritePolicy::CATALOG`].
pub fn write_sorted_run(
    path: &Path,
    key_len: u32,
    rec_len: u32,
    records: &[u8],
) -> Result<SortedRunPath, StoreError> {
    let run = write_sorted_run_file_with_policy(
        path,
        key_len,
        rec_len,
        records,
        RunWritePolicy::CATALOG,
    )?;
    if let Some(dir) = path.parent() {
        manifest_insert(dir, &run)?;
    }
    Ok(run)
}

/// Insert an already-written `{seq:06}.run` into the parent [`MANIFEST`].
///
/// Pair with [`write_sorted_run_file_with_policy`] so the body write can run
/// without holding the catalog mutex. Callers serialize this against other
/// MANIFEST writers.
pub fn commit_run_to_catalog(run: &SortedRunPath) -> Result<(), StoreError> {
    let Some(dir) = run.path.parent() else {
        return Ok(());
    };
    manifest_insert(dir, run)
}

/// Write run file only (no MANIFEST) with an explicit policy.
pub fn write_sorted_run_file_with_policy(
    path: &Path,
    key_len: u32,
    rec_len: u32,
    records: &[u8],
    policy: RunWritePolicy,
) -> Result<SortedRunPath, StoreError> {
    write_sorted_run_file(path, key_len, rec_len, records, policy)
}

/// Write run file only (no manifest). Used by merge for a single catalog commit.
fn write_sorted_run_file(
    path: &Path,
    key_len: u32,
    rec_len: u32,
    records: &[u8],
    policy: RunWritePolicy,
) -> Result<SortedRunPath, StoreError> {
    if key_len == 0 || rec_len < key_len {
        return Err(StoreError::Corrupt("sorted run: bad key/rec len"));
    }
    if !records.len().is_multiple_of(rec_len as usize) {
        return Err(StoreError::Corrupt(
            "sorted run: body not multiple of rec_len",
        ));
    }
    // Full-record keys (SH: key_len == rec_len == 40) must be unique and ordered.
    // Other families (key_len < rec_len) keep payload-only ties.
    if key_len == rec_len && !records.is_empty() {
        let rl = rec_len as usize;
        let mut prev: Option<&[u8]> = None;
        for rec in records.chunks_exact(rl) {
            if let Some(p) = prev {
                if rec_key_cmp(rec, p, key_len as usize, rec_len) != Ordering::Greater {
                    return Err(StoreError::Corrupt(
                        "sorted run: records not strictly increasing",
                    ));
                }
            }
            prev = Some(rec);
        }
    }
    let count = (records.len() / rec_len as usize) as u64;
    let body_crc32 = crc32(records);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| io_err(&tmp, e))?;
        let mut hdr = [0u8; HEADER_LEN];
        hdr[0..8].copy_from_slice(&MAGIC);
        hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
        hdr[12..16].copy_from_slice(&key_len.to_le_bytes());
        hdr[16..20].copy_from_slice(&rec_len.to_le_bytes());
        hdr[20..28].copy_from_slice(&count.to_le_bytes());
        hdr[28..32].copy_from_slice(&body_crc32.to_le_bytes());
        f.write_all(&hdr).map_err(|e| io_err(&tmp, e))?;
        if !records.is_empty() {
            f.write_all(records).map_err(|e| io_err(&tmp, e))?;
        }
        if policy.durable {
            f.sync_all().map_err(|e| io_err(&tmp, e))?;
        }
    }
    fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    if policy.durable {
        if let Some(parent) = path.parent() {
            if let Ok(dirf) = File::open(parent) {
                let _ = dirf.sync_all();
            }
        }
    }
    // Catalog: drop from page cache so multi‑hundred MiB runs do not crowd
    // tx.body working set.
    if policy.drop_cache {
        advise_file_dont_need(path);
    }
    Ok(SortedRunPath {
        path: path.to_path_buf(),
        count,
        rec_len,
        key_len,
        body_crc32,
    })
}

/// Best-effort whole-file `POSIX_FADV_DONTNEED` (Linux). No-op elsewhere.
fn advise_file_dont_need(path: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let f = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return,
        };
        // offset=0, len=0 ⇒ entire file on Linux.
        let rc = unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if rc != 0 {
            rbitcoin_log::trace!(
                "store: sorted-run fadvise(DONTNEED) failed path={}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(rc)
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
    }
}

/// Open and validate a run header + body length (does not re-hash the body).
///
/// Full body CRC is checked by [`verify_run_body`] / [`read_run_body`].
pub fn open_run(path: &Path) -> Result<SortedRunPath, StoreError> {
    let mut f = File::open(path).map_err(|e| io_err(path, e))?;
    let mut hdr = [0u8; HEADER_LEN];
    f.read_exact(&mut hdr).map_err(|e| io_err(path, e))?;
    let (version, body_crc32) = if hdr[0..8] == MAGIC {
        let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(StoreError::Corrupt("sorted run: unsupported version"));
        }
        let crc = u32::from_le_bytes(hdr[28..32].try_into().unwrap());
        (version, crc)
    } else if hdr[0..8] == MAGIC_V1 {
        let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        if version != VERSION_V1 {
            return Err(StoreError::Corrupt("sorted run: unsupported version"));
        }
        (version, 0)
    } else {
        return Err(StoreError::Corrupt("sorted run: bad magic"));
    };
    let _ = version;
    let key_len = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
    let rec_len = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
    let count = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    if key_len == 0 || rec_len < key_len {
        return Err(StoreError::Corrupt("sorted run: bad lens in header"));
    }
    let meta = f.metadata().map_err(|e| io_err(path, e))?;
    let expect = HEADER_LEN as u64 + count * rec_len as u64;
    if meta.len() < expect {
        return Err(StoreError::Corrupt("sorted run: truncated body"));
    }
    if meta.len() > expect {
        // Trailing garbage is not allowed for v2.
        if body_crc32 != 0 || hdr[0..8] == MAGIC {
            return Err(StoreError::Corrupt("sorted run: trailing garbage"));
        }
    }
    Ok(SortedRunPath {
        path: path.to_path_buf(),
        count,
        rec_len,
        key_len,
        body_crc32,
    })
}

/// Stream the body and check CRC-32 (no-op for legacy v1 with crc=0).
pub fn verify_run_body(run: &SortedRunPath) -> Result<(), StoreError> {
    if run.body_crc32 == 0 {
        return Ok(());
    }
    let body_len = run.count.saturating_mul(u64::from(run.rec_len));
    let got = crc32_file_body(&run.path, body_len)?;
    if got != run.body_crc32 {
        return Err(StoreError::Corrupt("sorted run: body CRC mismatch"));
    }
    Ok(())
}

/// Read all records into a contiguous buffer (count × rec_len). Verifies CRC.
pub fn read_run_body(run: &SortedRunPath) -> Result<Vec<u8>, StoreError> {
    let mut f = File::open(&run.path).map_err(|e| io_err(&run.path, e))?;
    f.seek(SeekFrom::Start(HEADER_LEN as u64))
        .map_err(|e| io_err(&run.path, e))?;
    let mut buf = vec![0u8; (run.count as usize).saturating_mul(run.rec_len as usize)];
    if !buf.is_empty() {
        f.read_exact(&mut buf).map_err(|e| io_err(&run.path, e))?;
    }
    if run.body_crc32 != 0 {
        let got = crc32(&buf);
        if got != run.body_crc32 {
            return Err(StoreError::Corrupt("sorted run: body CRC mismatch"));
        }
    }
    Ok(buf)
}

/// Binary-search a sorted run for `key` (first `key_len` bytes of each record).
///
/// Returns the full record bytes on hit. Equal keys: first match in file order.
/// Does **not** load the whole run into RAM (O(log n) seeks + reads).
pub fn lookup_key(run: &SortedRunPath, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
    if key.len() < run.key_len as usize {
        return Err(StoreError::Corrupt("sorted run: lookup key short"));
    }
    if run.count == 0 {
        return Ok(None);
    }
    let key = &key[..run.key_len as usize];
    let rec_len = run.rec_len as u64;
    let mut f = File::open(&run.path).map_err(|e| io_err(&run.path, e))?;
    let mut lo = 0u64;
    let mut hi = run.count;
    let mut rec = vec![0u8; run.rec_len as usize];
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let off = HEADER_LEN as u64 + mid * rec_len;
        f.seek(SeekFrom::Start(off))
            .map_err(|e| io_err(&run.path, e))?;
        f.read_exact(&mut rec).map_err(|e| io_err(&run.path, e))?;
        match rec[..run.key_len as usize].cmp(key) {
            Ordering::Less => lo = mid + 1,
            Ordering::Greater => hi = mid,
            Ordering::Equal => {
                let mut i = mid;
                while i > 0 {
                    let poff = HEADER_LEN as u64 + (i - 1) * rec_len;
                    f.seek(SeekFrom::Start(poff))
                        .map_err(|e| io_err(&run.path, e))?;
                    let mut prev = vec![0u8; run.rec_len as usize];
                    f.read_exact(&mut prev).map_err(|e| io_err(&run.path, e))?;
                    if &prev[..run.key_len as usize] != key {
                        break;
                    }
                    rec = prev;
                    i -= 1;
                }
                return Ok(Some(rec));
            }
        }
    }
    Ok(None)
}

/// Compare two fixed records for merge / write order.
///
/// SH catalogs (`key_len == rec_len == 40`) sort by scripthash then **numeric**
/// little-endian create_fk — not raw 40-byte memcmp (fk 255 < 256).
fn rec_key_cmp(a: &[u8], b: &[u8], key_len: usize, rec_len: u32) -> Ordering {
    if key_len == 40 && rec_len == 40 && a.len() >= 40 && b.len() >= 40 {
        match a[..32].cmp(&b[..32]) {
            Ordering::Equal => {
                let fa = u64::from_le_bytes(a[32..40].try_into().unwrap());
                let fb = u64::from_le_bytes(b[32..40].try_into().unwrap());
                fa.cmp(&fb)
            }
            o => o,
        }
    } else {
        let n = key_len.min(a.len()).min(b.len());
        a[..n].cmp(&b[..n])
    }
}

/// Remove one run from the catalog and delete its file (after materialize).
pub fn remove_run(run: &SortedRunPath) -> Result<(), StoreError> {
    detach_run(run)?;
    let _ = fs::remove_file(&run.path);
    Ok(())
}

/// Drop a run from the MANIFEST but **leave the file**.
///
/// A bare detach leaves a `.run` file that concurrent [`list_runs`] will
/// **delete as an orphan**.
pub fn detach_run(run: &SortedRunPath) -> Result<(), StoreError> {
    let Some(dir) = run.path.parent() else {
        return Ok(());
    };
    if let Some(seq) = run.seq() {
        let mut mf = load_manifest(dir)?.unwrap_or_default();
        mf.entries.retain(|e| e.seq != seq);
        save_manifest(dir, &mf)?;
    }
    Ok(())
}

/// Open leftover incomplete k-way claims (`*.run.mat`) from older datadirs.
pub fn list_materialize_claims(dir: &Path) -> Result<Vec<SortedRunPath>, StoreError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| io_err(dir, e))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.ends_with(".run.mat"))
        })
        .collect();
    paths.sort();
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        match open_run(&p) {
            Ok(r) => out.push(r),
            Err(e) => {
                rbitcoin_log::warn!("store: skipping bad materialize claim {}: {e}", p.display());
            }
        }
    }
    Ok(out)
}

/// Cap workers at 1 per `per_worker` free bytes (floor 1, clamp 1..=256 vs CPUs).
pub fn workers_for_free_ram(cpus: usize, free_bytes: u64, per_worker: u64) -> usize {
    let cpus = cpus.clamp(1, 256);
    if per_worker == 0 {
        return 1;
    }
    let ram_cap = (free_bytes / per_worker) as usize;
    cpus.min(ram_cap.clamp(1, 256))
}

/// `MemAvailable` from `/proc/meminfo` text (kB → bytes).
#[cfg(any(test, target_os = "linux"))]
fn mem_available_from_meminfo(text: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return Some(kb.saturating_mul(1024));
    }
    None
}

/// Darwin reclaimable pages (`free_count + inactive_count`) × page size.
/// Speculative pages are already inside `free_count`.
#[cfg(any(test, target_os = "macos"))]
fn mem_available_from_darwin_vm(
    page_size: u64,
    free_count: u64,
    inactive_count: u64,
) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    Some(
        free_count
            .saturating_add(inactive_count)
            .saturating_mul(page_size),
    )
}

#[cfg(target_os = "macos")]
fn mem_available_from_darwin_host() -> Option<u64> {
    let page_size = {
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n <= 0 {
            return None;
        }
        n as u64
    };
    let mut vm = unsafe { std::mem::zeroed::<libc::vm_statistics64>() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let kr = unsafe {
        // SAFETY: process host port; HOST_VM_INFO64 writes into this stack vm_statistics64.
        #[allow(deprecated)]
        let host = libc::mach_host_self();
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            &mut vm as *mut _ as libc::host_info64_t,
            &mut count,
        )
    };
    if kr != libc::KERN_SUCCESS {
        return None;
    }
    mem_available_from_darwin_vm(
        page_size,
        u64::from(vm.free_count),
        u64::from(vm.inactive_count),
    )
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct MemoryStatusEx {
    dw_length: u32,
    dw_memory_load: u32,
    ull_total_phys: u64,
    ull_avail_phys: u64,
    ull_total_page_file: u64,
    ull_avail_page_file: u64,
    ull_total_virtual: u64,
    ull_avail_virtual: u64,
    ull_avail_extended_virtual: u64,
}

#[cfg(windows)]
extern "system" {
    fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
}

#[cfg(windows)]
fn mem_available_from_windows_host() -> Option<u64> {
    let mut st = MemoryStatusEx {
        dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
        dw_memory_load: 0,
        ull_total_phys: 0,
        ull_avail_phys: 0,
        ull_total_page_file: 0,
        ull_avail_page_file: 0,
        ull_total_virtual: 0,
        ull_avail_virtual: 0,
        ull_avail_extended_virtual: 0,
    };
    // SAFETY: dw_length is size_of Self; the API fills the remaining fields.
    if unsafe { GlobalMemoryStatusEx(&mut st) } == 0 {
        return None;
    }
    Some(st.ull_avail_phys)
}

/// Host memory available for new allocations.
///
/// Linux: `MemAvailable`. Darwin: free+inactive pages. Windows: `ullAvailPhys`.
/// Other OS: `None` (worker cap falls back to 1).
pub fn host_mem_available_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        return mem_available_from_meminfo(&text);
    }
    #[cfg(target_os = "macos")]
    {
        return mem_available_from_darwin_host();
    }
    #[cfg(windows)]
    {
        return mem_available_from_windows_host();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// `MemAvailable` as a log label (`"12.3"` GiB, or `"?"` when unknown).
pub fn free_gib_label() -> String {
    host_mem_available_bytes()
        .map(|b| format!("{:.1}", b as f64 / (1u64 << 30) as f64))
        .unwrap_or_else(|| "?".into())
}

pub fn logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 256)
}

fn scan_run_paths(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| io_err(dir, e))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("run"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn open_and_check_against_entry(
    path: &Path,
    expect: &ManifestEntry,
) -> Result<SortedRunPath, StoreError> {
    let run = open_run(path)?;
    if run.count != expect.count || run.key_len != expect.key_len || run.rec_len != expect.rec_len {
        return Err(StoreError::Corrupt(
            "sorted run: header does not match MANIFEST",
        ));
    }
    if expect.body_crc32 != 0 && run.body_crc32 != 0 && run.body_crc32 != expect.body_crc32 {
        return Err(StoreError::Corrupt(
            "sorted run: CRC does not match MANIFEST",
        ));
    }
    Ok(run)
}

/// List runs in `dir` (sorted by seq / name).
///
/// When `MANIFEST` exists it is the **authoritative** set: only listed runs are
/// returned; orphans are removed best-effort; missing listed files are warned.
/// Without a manifest, falls back to a directory scan and rebuilds the catalog.
///
/// **Must** be called under the family's `runs_io` lock whenever concurrent
/// writers/mergers/materialize may touch the same directory (see module docs).
pub fn list_runs(dir: &Path) -> Result<Vec<SortedRunPath>, StoreError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    if let Some(mf) = load_manifest(dir)? {
        let mut out = Vec::with_capacity(mf.entries.len());
        let mut listed_seqs = std::collections::HashSet::with_capacity(mf.entries.len());
        for e in &mf.entries {
            listed_seqs.insert(e.seq);
            let path = next_run_path(dir, e.seq);
            match open_and_check_against_entry(&path, e) {
                Ok(r) => out.push(r),
                Err(StoreError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    rbitcoin_log::warn!(
                        "store: MANIFEST lists missing run {} (seq={}) — data may be incomplete",
                        path.display(),
                        e.seq
                    );
                }
                Err(e) => {
                    rbitcoin_log::warn!("store: skipping bad sorted run {}: {e}", path.display());
                }
            }
        }
        // Orphan `*.run` files not in the catalog (e.g. merge inputs left after a
        // successful MANIFEST commit, or a crash between write and catalog).
        // Safe only for true leftovers: claimed materialize files use `*.run.mat`
        // and are not scanned here. Deleting an in-flight claim would drop data.
        for p in scan_run_paths(dir)? {
            let Some(seq) = seq_from_path(&p) else {
                continue;
            };
            if !listed_seqs.contains(&seq) {
                rbitcoin_log::debug!(
                    "store: removing orphan sorted run not in MANIFEST {}",
                    p.display()
                );
                let _ = fs::remove_file(&p);
            }
        }
        return Ok(out);
    }

    // Legacy / empty: scan directory, heal by writing MANIFEST.
    let paths = scan_run_paths(dir)?;
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        match open_run(&p) {
            Ok(r) => out.push(r),
            Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            }
            Err(e) => {
                rbitcoin_log::warn!("store: skipping bad sorted run {}: {e}", p.display());
            }
        }
    }
    if !out.is_empty() {
        if let Err(e) = rebuild_manifest_from_runs(dir, &out) {
            rbitcoin_log::warn!(
                "store: failed to rebuild sorted-run MANIFEST in {}: {e}",
                dir.display()
            );
        }
    }
    Ok(out)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("rbitcoin-sorted-run-{n}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(key: u8, tag: u8) -> [u8; 44] {
        let mut r = [0u8; 44];
        r[0] = key;
        r[32] = tag;
        r
    }

    #[test]
    fn workers_for_free_ram_1gib_head_is_not_sh_1_5gib() {
        const HEAD: u64 = crate::tx_table::TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES;
        assert_eq!(workers_for_free_ram(8, 0, HEAD), 1);
        assert_eq!(workers_for_free_ram(8, HEAD.saturating_sub(1), HEAD), 1);
        assert_eq!(workers_for_free_ram(8, HEAD, HEAD), 1);
        assert_eq!(workers_for_free_ram(8, 2 * HEAD, HEAD), 2);
        assert_eq!(workers_for_free_ram(8, 3 * HEAD, HEAD), 3);
        assert_eq!(workers_for_free_ram(4, 20 * HEAD, HEAD), 4);
        assert_eq!(workers_for_free_ram(8, 3 * (1 << 30) / 2, HEAD), 1);
        assert_eq!(workers_for_free_ram(8, 2 * (1 << 30), HEAD), 2);
    }

    #[test]
    fn mem_available_parses_proc_meminfo() {
        let text = "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    3145728 kB\nBuffers:          200000 kB\n";
        assert_eq!(mem_available_from_meminfo(text), Some(3145728 * 1024));
        assert_eq!(mem_available_from_meminfo("MemTotal: 1 kB\n"), None);
    }

    #[test]
    fn darwin_vm_pages_count_as_free_ram() {
        assert_eq!(mem_available_from_darwin_vm(0, 10, 10), None);
        assert_eq!(mem_available_from_darwin_vm(4096, 0, 0), Some(0));
        assert_eq!(mem_available_from_darwin_vm(4096, 1, 0), Some(4096));
        assert_eq!(mem_available_from_darwin_vm(16384, 2, 2), Some(4 * 16384));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn host_mem_available_bytes_is_some_on_linux_macos_windows() {
        let n =
            host_mem_available_bytes().expect("Linux MemAvailable / Darwin vm / Windows AvailPhys");
        assert!(n >= 1024 * 1024, "probe too small: {n}");
        let w = workers_for_free_ram(logical_cpus(), n, 2 << 30);
        assert!((1..=256).contains(&w));
        assert!(w <= logical_cpus());
        let label = free_gib_label();
        assert!(label == "?" || label.parse::<f64>().is_ok(), "{label}");
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn write_read_roundtrip() {
        let d = tmp_dir();
        let path = d.join("000001.run");
        let mut body = Vec::new();
        body.extend_from_slice(&rec(1, 10));
        body.extend_from_slice(&rec(2, 20));
        write_sorted_run(&path, 32, 44, &body).unwrap();
        let run = open_run(&path).unwrap();
        assert_eq!(run.count, 2);
        assert_ne!(run.body_crc32, 0);
        let b = read_run_body(&run).unwrap();
        assert_eq!(b.len(), 88);
        assert_eq!(b[0], 1);
        assert_eq!(b[32], 10);
        verify_run_body(&run).unwrap();
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn body_crc_detects_corruption() {
        let d = tmp_dir();
        let path = d.join("000001.run");
        let body = rec(1, 10);
        write_sorted_run(&path, 32, 44, &body).unwrap();
        let mut raw = fs::read(&path).unwrap();
        raw[HEADER_LEN] ^= 0xFF;
        fs::write(&path, &raw).unwrap();
        let run = open_run(&path).unwrap();
        assert!(read_run_body(&run).is_err());
        assert!(verify_run_body(&run).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn list_runs_ignores_orphan_not_in_manifest() {
        let d = tmp_dir();
        write_sorted_run(&d.join("000001.run"), 32, 44, &rec(1, 1)).unwrap();
        let orphan = d.join("000099.run");
        write_sorted_run_file(&orphan, 32, 44, &rec(9, 9), RunWritePolicy::CATALOG).unwrap();
        let runs = list_runs(&d).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].seq(), Some(1));
        assert!(!orphan.exists(), "orphan should be removed");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn list_materialize_claims_finds_leftover_mats() {
        let d = tmp_dir();
        let run = write_sorted_run(&d.join("000001.run"), 32, 44, &rec(1, 1)).unwrap();
        let mat = d.join("000001.run.mat");
        std::fs::rename(&run.path, &mat).unwrap();
        detach_run(&run).unwrap();
        assert!(list_runs(&d).unwrap().is_empty());
        let mats = list_materialize_claims(&d).unwrap();
        assert_eq!(mats.len(), 1);
        assert!(mats[0].path.ends_with("000001.run.mat"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn list_runs_skips_non_run() {
        let d = tmp_dir();
        write_sorted_run(&d.join("000001.run"), 32, 44, &rec(1, 1)).unwrap();
        fs::write(d.join("meta"), b"x").unwrap();
        let runs = list_runs(&d).unwrap();
        assert_eq!(runs.len(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn open_run_and_list_error_arms() {
        let d = tmp_dir();
        let bad = d.join("000010.run");
        fs::write(&bad, vec![0u8; 64]).unwrap();
        assert!(matches!(open_run(&bad), Err(StoreError::Corrupt(_))));
        let short = d.join("000011.run");
        fs::write(&short, b"SRUNSORT").unwrap();
        assert!(open_run(&short).is_err());
        let path = d.join("000012.run");
        let run = write_sorted_run(&path, 32, 44, &rec(1, 1)).unwrap();
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"GARBAGE").unwrap();
        }
        assert!(matches!(open_run(&path), Err(StoreError::Corrupt(_))));
        let _ = run;
        let clean = tmp_dir();
        write_sorted_run(&clean.join("000001.run"), 32, 44, &rec(1, 1)).unwrap();
        let listed = list_runs(&clean).unwrap();
        assert_eq!(listed.len(), 1);
        write_sorted_run(&clean.join("000099.run"), 32, 44, &rec(9, 9)).unwrap();
        let again = list_runs(&clean).unwrap();
        assert!(!again.is_empty());
        if let Ok(r) = open_run(&clean.join("000001.run")) {
            assert!(lookup_key(&r, &[0xff; 32]).unwrap().is_none());
            let _ = detach_run(&r);
        }
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&clean);
    }

    #[test]
    fn open_run_v1_and_unsupported_version_and_lookup_short() {
        let d = tmp_dir();
        let bad_ver = d.join("000020.run");
        let mut hdr = vec![0u8; 64];
        hdr[0..8].copy_from_slice(b"RBSORT02");
        hdr[8..12].copy_from_slice(&99u32.to_le_bytes());
        fs::write(&bad_ver, &hdr).unwrap();
        assert!(matches!(open_run(&bad_ver), Err(StoreError::Corrupt(_))));
        let bad_v1 = d.join("000021.run");
        let mut h2 = vec![0u8; 64];
        h2[0..8].copy_from_slice(b"RBSORT01");
        h2[8..12].copy_from_slice(&99u32.to_le_bytes());
        fs::write(&bad_v1, &h2).unwrap();
        assert!(matches!(open_run(&bad_v1), Err(StoreError::Corrupt(_))));
        let path = d.join("000022.run");
        let run = write_sorted_run(&path, 32, 44, &rec(1, 1)).unwrap();
        assert!(matches!(
            lookup_key(&run, &[0u8; 8]),
            Err(StoreError::Corrupt(_))
        ));
        let empty_path = d.join("000023.run");
        if let Ok(empty) = write_sorted_run(&empty_path, 32, 44, &[]) {
            assert!(lookup_key(&empty, &[0u8; 32]).unwrap().is_none());
            let _ = read_run_body(&empty);
        }
        let _ = run;
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lookup_key_finds_record() {
        let d = tmp_dir();
        let path = d.join("lk.run");
        let mut body = Vec::new();
        for i in [1u8, 3, 5, 7, 9] {
            body.extend_from_slice(&rec(i, i.wrapping_mul(10)));
        }
        let run = write_sorted_run(&path, 32, 44, &body).unwrap();
        let hit = lookup_key(&run, &rec(5, 0)[..32]).unwrap().unwrap();
        assert_eq!(hit[32], 50);
        assert!(lookup_key(&run, &rec(4, 0)[..32]).unwrap().is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn clear_style_dir_drops_manifest() {
        let d = tmp_dir();
        write_sorted_run(&d.join("000001.run"), 32, 44, &rec(1, 1)).unwrap();
        assert!(manifest_path(&d).exists());
        for e in fs::read_dir(&d).unwrap().flatten() {
            let _ = fs::remove_file(e.path());
        }
        assert!(!manifest_path(&d).exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn manifest_bad_magic_and_truncated() {
        let d = tmp_dir();
        fs::write(manifest_path(&d), b"short").unwrap();
        assert!(load_manifest(&d).unwrap().is_none());
        let mut bad = MANIFEST_MAGIC.to_vec();
        bad[0] ^= 0xff;
        bad.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        bad.extend_from_slice(&0u32.to_le_bytes());
        fs::write(manifest_path(&d), &bad).unwrap();
        assert!(load_manifest(&d).unwrap().is_none());
        let mut badv = MANIFEST_MAGIC.to_vec();
        badv.extend_from_slice(&99u32.to_le_bytes());
        badv.extend_from_slice(&0u32.to_le_bytes());
        fs::write(manifest_path(&d), &badv).unwrap();
        assert!(load_manifest(&d).unwrap().is_none());

        let pbad = d.join("bad.run");
        fs::write(&pbad, b"notasortrunfile!!!!!!!!!!!!!").unwrap();
        assert!(open_run(&pbad).is_err());
        assert!(list_materialize_claims(&d.join("nope")).unwrap().is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn list_runs_manifest_missing_bad_and_legacy_heal() {
        let d = tmp_dir();
        write_sorted_run(&next_run_path(&d, 1), 32, 44, &rec(1, 1)).unwrap();
        write_sorted_run(&next_run_path(&d, 2), 32, 44, &rec(2, 2)).unwrap();
        fs::remove_file(next_run_path(&d, 2)).unwrap();
        let listed = list_runs(&d).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].seq(), Some(1));

        let mut mf = load_manifest(&d).unwrap().unwrap();
        mf.entries.push(ManifestEntry {
            seq: 3,
            key_len: 32,
            rec_len: 44,
            count: 1,
            body_crc32: 0xdead_beef,
        });
        save_manifest(&d, &mf).unwrap();
        fs::write(next_run_path(&d, 3), b"notasortrunfile!!!!!!!!!!!!!").unwrap();
        let listed2 = list_runs(&d).unwrap();
        assert_eq!(listed2.len(), 1);

        write_sorted_run(&next_run_path(&d, 4), 32, 44, &rec(4, 4)).unwrap();
        let run4 = open_run(&next_run_path(&d, 4)).unwrap();
        let mut mf = load_manifest(&d).unwrap().unwrap();
        if let Some(e) = mf.entries.iter_mut().find(|e| e.seq == 4) {
            e.body_crc32 = run4.body_crc32 ^ 0xffff_ffff;
        }
        save_manifest(&d, &mf).unwrap();
        let expect = ManifestEntry {
            seq: 4,
            key_len: 32,
            rec_len: 44,
            count: 1,
            body_crc32: run4.body_crc32 ^ 0xffff_ffff,
        };
        assert!(open_and_check_against_entry(&next_run_path(&d, 4), &expect).is_err());
        let listed3 = list_runs(&d).unwrap();
        assert!(!listed3.iter().any(|r| r.seq() == Some(4)));

        let d2 = tmp_dir();
        write_sorted_run_file(
            &next_run_path(&d2, 7),
            32,
            44,
            &rec(7, 7),
            RunWritePolicy::CATALOG,
        )
        .unwrap();
        assert!(!manifest_path(&d2).exists());
        let listed_legacy = list_runs(&d2).unwrap();
        assert_eq!(listed_legacy.len(), 1);
        assert!(manifest_path(&d2).exists());

        assert!(
            write_sorted_run_file(&d.join("x.run"), 0, 44, &[], RunWritePolicy::CATALOG).is_err()
        );
        assert!(
            write_sorted_run_file(&d.join("y.run"), 32, 16, &[], RunWritePolicy::CATALOG).is_err()
        );
        assert!(write_sorted_run_file(
            &d.join("z.run"),
            32,
            44,
            &[1, 2, 3],
            RunWritePolicy::CATALOG
        )
        .is_err());

        assert!(list_runs(&d.join("nope")).unwrap().is_empty());

        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn detach_remove_next_path_and_opts() {
        let d = tmp_dir();
        assert_eq!(next_run_path(&d, 1).file_name().unwrap(), "000001.run");
        let p1 = next_run_path(&d, 1);
        let mut body = Vec::new();
        body.extend_from_slice(&rec(1, 10));
        body.extend_from_slice(&rec(2, 20));
        body.extend_from_slice(&rec(3, 30));
        write_sorted_run(&p1, 32, 44, &body).unwrap();
        assert_eq!(list_runs(&d).unwrap().len(), 1);

        let p_empty = next_run_path(&d, 2);
        write_sorted_run(&p_empty, 32, 44, &[]).unwrap();
        let empty = open_run(&p_empty).unwrap();
        assert_eq!(empty.count, 0);
        assert!(read_run_body(&empty).unwrap().is_empty());
        verify_run_body(&empty).unwrap();

        let run = open_run(&p1).unwrap();
        detach_run(&run).unwrap();
        assert!(p1.exists());
        remove_run(&run).unwrap();
        assert!(!p1.exists());

        assert!(matches!(
            write_sorted_run(&d.join("bad.run"), 0, 44, &[]),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            write_sorted_run(&d.join("bad2.run"), 32, 44, &[1, 2, 3]),
            Err(StoreError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn write_sorted_run_rejects_unsorted_when_key_len_eq_rec() {
        let d = tmp_dir();
        let mut rec_hi = [0u8; 40];
        rec_hi[31] = 2;
        rec_hi[32..40].copy_from_slice(&2u64.to_le_bytes());
        let mut rec_lo = [0u8; 40];
        rec_lo[31] = 1;
        rec_lo[32..40].copy_from_slice(&1u64.to_le_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&rec_hi);
        body.extend_from_slice(&rec_lo);
        match write_sorted_run(&d.join("desc.run"), 40, 40, &body) {
            Err(StoreError::Corrupt(m)) => {
                assert!(
                    m.contains("not strictly increasing"),
                    "expected order error, got {m}"
                );
            }
            other => panic!("expected Corrupt unsorted, got {other:?}"),
        }
        let mut ok = Vec::new();
        ok.extend_from_slice(&rec_lo);
        ok.extend_from_slice(&rec_hi);
        let run = write_sorted_run(&d.join("000001.run"), 40, 40, &ok).unwrap();
        assert_eq!(run.key_len, 40);
        assert_eq!(run.rec_len, 40);
        assert_eq!(run.count, 2);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn catalog_policy_is_durable() {
        assert!(RunWritePolicy::CATALOG.durable);
        assert!(RunWritePolicy::CATALOG.drop_cache);
    }

    #[test]
    fn commit_run_to_catalog_inserts_file_only_write() {
        let d = tmp_dir();
        let path = next_run_path(&d, 1);
        let mut rec = [0u8; 40];
        rec[0] = 1;
        rec[32..40].copy_from_slice(&1u64.to_le_bytes());
        let run = write_sorted_run_file_with_policy(&path, 40, 40, &rec, RunWritePolicy::CATALOG)
            .unwrap();
        commit_run_to_catalog(&run).unwrap();
        let listed = list_runs(&d).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].seq(), Some(1));
        assert_eq!(listed[0].count, 1);
        let _ = fs::remove_dir_all(&d);
    }
}
