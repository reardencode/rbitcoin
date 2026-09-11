//! Dense **create_fk-ordered** txid sidefile (`txid.body`).
//!
//! Layout (schema 13+):
//! ```text
//! offset 0..32   — 32-byte file header (standard 16-byte TableFile header + 16 pad)
//! offset 32+i*32 — txid for create_fk = i+1
//! ```
//!
//! Append-published with Class A body/idx on the sole Class A write path.
//! Identity peeks use fixed `off = 32 + (fk-1)*32` — no `tx.idx` / body prefix.
//! Multi-fk peeks **page-group** (one bulk pread per OS page of entries).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{Fk, TableKind};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Bytes before first txid entry (TableFile header 16 + pad to 32).
pub const TXID_BODY_HEADER: u64 = 32;
/// One create identity.
pub const TXID_ENTRY_LEN: u64 = 32;
/// OS page size used for multi-fk sidefile coalesce.
pub const TXID_OS_PAGE: u64 = 4096;
/// Entries per OS page (`TXID_OS_PAGE / TXID_ENTRY_LEN` = 128).
pub const TXID_ENTRIES_PER_PAGE: u64 = TXID_OS_PAGE / TXID_ENTRY_LEN;

/// Dense create_fk → txid table.
pub struct TxidBody {
    file: TableFile,
    /// Published entry count (matches Class A body count when consistent).
    count: std::sync::atomic::AtomicU64,
}

impl TxidBody {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        let path = Self::path(dir);
        let file = TableFile::create(path, TableKind::TxidBody)?;
        // Pad header region to 32 so entries start page-friendly / plan layout.
        let pad = vec![0u8; (TXID_BODY_HEADER as usize).saturating_sub(FILE_HEADER_LEN)];
        if !pad.is_empty() {
            file.write_at_pwrite(FILE_HEADER_LEN as u64, &pad)?;
            // Logical end already advanced by write_at_pwrite HWM.
        }
        Ok(Self {
            file,
            count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let path = Self::path(dir);
        let file = TableFile::open(path, TableKind::TxidBody)?;
        let len = file.logical_len();
        let count = if len <= TXID_BODY_HEADER {
            0
        } else {
            (len - TXID_BODY_HEADER) / TXID_ENTRY_LEN
        };
        Ok(Self {
            file,
            count: std::sync::atomic::AtomicU64::new(count),
        })
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join("txid.body")
    }

    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Roll published identity count back to `new_count` (and HWM).
    ///
    /// Used when `txid.body` led body/idx (should be rare) so open can align.
    pub fn truncate_to_count(&self, new_count: u64) -> Result<(), StoreError> {
        let cur = self.count();
        if new_count > cur {
            return Err(StoreError::Corrupt("txid.body truncate past count"));
        }
        if new_count == cur {
            return Ok(());
        }
        let new_len = TXID_BODY_HEADER + new_count * TXID_ENTRY_LEN;
        self.file.set_logical_len(new_len)?;
        self.count
            .store(new_count, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Absolute file offset of the 32-byte entry for `fk` (1-based).
    #[inline]
    pub fn entry_offset(fk: u64) -> Result<u64, StoreError> {
        if fk == 0 {
            return Err(StoreError::InvalidFk);
        }
        Ok(TXID_BODY_HEADER + (fk - 1) * TXID_ENTRY_LEN)
    }

    /// OS page index that holds the entry for `fk` (1-based).
    #[inline]
    pub fn entry_page(fk: u64) -> Result<u64, StoreError> {
        Ok(Self::entry_offset(fk)? / TXID_OS_PAGE)
    }

    pub fn body_read_fd(&self) -> crate::io_handle::IoHandle {
        self.file.read_fd()
    }

    pub fn file_path(&self) -> &Path {
        self.file.path()
    }

    pub fn logical_len(&self) -> u64 {
        self.file.logical_len()
    }

    /// Append `txids` for consecutive create_fks starting at `base_count+1`.
    ///
    /// Must be called once per Class A body batch with the same length; order
    /// matches create_fk order. Publishes count after durable write.
    pub fn append_batch(&self, base_count: u64, txids: &[[u8; 32]]) -> Result<(), StoreError> {
        if txids.is_empty() {
            return Ok(());
        }
        let cur = self.count.load(std::sync::atomic::Ordering::Acquire);
        if cur != base_count {
            return Err(StoreError::Corrupt("txid.body count mismatch on append"));
        }
        let start = TXID_BODY_HEADER + base_count * TXID_ENTRY_LEN;
        let mut blob = Vec::with_capacity(txids.len() * 32);
        for t in txids {
            blob.extend_from_slice(t);
        }
        self.file.write_at_pwrite(start, &blob)?;
        let new = base_count + txids.len() as u64;
        self.count.store(new, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// `txid.body` peek via libc `pread` (safe under a held TLS ring).
    pub fn get_read_at(&self, fk: Fk) -> Result<[u8; 32], StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let n = self.count();
        if id > n {
            return Err(StoreError::NotFound);
        }
        let off = Self::entry_offset(id)?;
        let mut buf = [0u8; 32];
        self.file.read_at(off, &mut buf)?;
        Ok(buf)
    }

    /// Read txid for create_fk (bulk pread).
    pub fn get(&self, fk: Fk) -> Result<[u8; 32], StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let n = self.count();
        if id > n {
            return Err(StoreError::NotFound);
        }
        let off = Self::entry_offset(id)?;
        let mut buf = [0u8; 32];
        let rc = crate::bulk_io::pread_single(self.file.read_fd(), off, &mut buf);
        if rc < 0 {
            return Err(StoreError::io(
                self.file.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) != 32 {
            self.file.pread_at(off, &mut buf)?;
        }
        Ok(buf)
    }

    /// Bulk read txids for consecutive fks `first..=last` (1-based).
    pub fn get_range(&self, first: u64, last: u64) -> Result<Vec<[u8; 32]>, StoreError> {
        if last < first {
            return Ok(Vec::new());
        }
        let n = self.count();
        if first == 0 || last > n {
            return Err(StoreError::NotFound);
        }
        let count = (last - first + 1) as usize;
        let off = Self::entry_offset(first)?;
        let mut blob = vec![0u8; count * 32];
        let rc = crate::bulk_io::pread_single(self.file.read_fd(), off, &mut blob);
        if rc < 0 {
            return Err(StoreError::io(
                self.file.path(),
                std::io::Error::from_raw_os_error(-rc),
            ));
        }
        if (rc as usize) != blob.len() {
            self.file.pread_at(off, &mut blob)?;
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let s = i * 32;
            out.push(blob[s..s + 32].try_into().unwrap());
        }
        Ok(out)
    }

    /// Fill `out[i]` with txid for `fks[i]` (scattered fks).
    ///
    /// Uses [`Self::get_many_page_grouped`] so fks that share a 4 KiB sidefile
    /// page pay **one** bulk pread for that page.
    pub fn get_many(&self, fks: &[Fk]) -> Result<Vec<Option<[u8; 32]>>, StoreError> {
        if fks.is_empty() {
            return Ok(Vec::new());
        }
        let (by_fk, _pages) = self.get_many_page_grouped(fks)?;
        let mut out = vec![None; fks.len()];
        for (i, fk) in fks.iter().enumerate() {
            if let Some(id) = fk.get() {
                if let Some(t) = by_fk.get(&id) {
                    out[i] = Some(*t);
                }
            }
        }
        Ok(out)
    }

    /// Page-grouped multi-get: unique valid fks → one bulk pread per OS page.
    ///
    /// Uses **libc pread only** (never TLS bulk uring) so it is safe both
    /// outside and while another path might hold a ring. Prefer
    /// [`Self::get_many_page_grouped_on_session`] when a plan session is already
    /// held so page preads ride the outer ring.
    ///
    /// Returns `(map create_fk → txid, pages_read)`.
    pub fn get_many_page_grouped(
        &self,
        fks: &[Fk],
    ) -> Result<(HashMap<u64, [u8; 32]>, u64), StoreError> {
        self.get_many_page_grouped_ctx(fks, &mut crate::IoCtx::none())
    }

    /// Same as [`Self::get_many_page_grouped`] but page preads use the
    /// **already-held** plan TLS session (no nested `with_thread_local`).
    pub fn get_many_page_grouped_on_session(
        &self,
        fks: &[Fk],
        session: &mut crate::uring_session::UringSession,
    ) -> Result<(HashMap<u64, [u8; 32]>, u64), StoreError> {
        self.get_many_page_grouped_ctx(fks, &mut crate::IoCtx::held(session))
    }

    /// Page-grouped identity fill with a shared [`crate::IoCtx`].
    pub(crate) fn get_many_page_grouped_ctx(
        &self,
        fks: &[Fk],
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<(HashMap<u64, [u8; 32]>, u64), StoreError> {
        self.get_many_page_grouped_inner(fks, ctx)
    }

    fn get_many_page_grouped_inner(
        &self,
        fks: &[Fk],
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<(HashMap<u64, [u8; 32]>, u64), StoreError> {
        let n = self.count();
        let mut unique: Vec<u64> = Vec::with_capacity(fks.len());
        {
            let mut seen = std::collections::HashSet::with_capacity(fks.len());
            for fk in fks {
                let Some(id) = fk.get() else {
                    continue;
                };
                if id == 0 || id > n {
                    continue;
                }
                if seen.insert(id) {
                    unique.push(id);
                }
            }
        }
        if unique.is_empty() {
            return Ok((HashMap::new(), 0));
        }
        unique.sort_unstable();

        let mut groups: Vec<(u64, Vec<u64>)> = Vec::new();
        for id in unique {
            let page = Self::entry_page(id)?;
            match groups.last_mut() {
                Some((p, v)) if *p == page => v.push(id),
                _ => groups.push((page, vec![id])),
            }
        }

        let mut jobs: Vec<(u64, Vec<u8>, Vec<u64>)> = Vec::with_capacity(groups.len());
        for (_page, group) in groups {
            debug_assert!(
                (group.last().unwrap() - group.first().unwrap() + 1) <= TXID_ENTRIES_PER_PAGE,
                "page group wider than entries-per-page geometry"
            );
            let first = *group.first().unwrap();
            let last = *group.last().unwrap();
            let bytes = ((last - first + 1) as usize) * (TXID_ENTRY_LEN as usize);
            jobs.push((first, vec![0u8; bytes], group));
        }

        let fd = self.file.read_fd();
        let pages_read = jobs.len() as u64;

        // Prefer held-session bulk pread; else libc pread (never nested TLS).
        let mut used_session = false;
        if ctx.session().is_some() {
            use crate::bulk_io::ReadOp;
            // SAFETY: each jobs[i].1 is a distinct Vec owned until after pread_batch_on_ctx.
            let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(jobs.len());
            for (first, blob, _) in jobs.iter_mut() {
                let off = Self::entry_offset(*first)?;
                let ptr = blob.as_mut_ptr();
                let len = blob.len();
                let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
                ops.push(ReadOp {
                    fd,
                    offset: off,
                    buf: slice,
                    result: i32::MIN,
                });
            }
            used_session = crate::bulk_io::pread_batch_on_ctx(ctx, &mut ops).unwrap_or(false);
            if used_session {
                for (op, (first, blob, _)) in ops.iter().zip(jobs.iter_mut()) {
                    if op.result < 0 || (op.result as usize) != blob.len() {
                        // Complete short / failed page via libc pread.
                        self.file.pread_at(Self::entry_offset(*first)?, blob)?;
                    }
                }
            }
        }
        if !used_session {
            for (first, blob, _) in jobs.iter_mut() {
                let off = Self::entry_offset(*first)?;
                self.file.pread_at(off, blob)?;
            }
        }

        let mut out: HashMap<u64, [u8; 32]> = HashMap::with_capacity(fks.len());
        for (first, blob, group) in jobs {
            for id in group {
                let rel = ((id - first) as usize) * (TXID_ENTRY_LEN as usize);
                let mut tid = [0u8; 32];
                tid.copy_from_slice(&blob[rel..rel + 32]);
                out.insert(id, tid);
            }
        }
        Ok((out, pages_read))
    }

    /// Serial per-fk `get` map for the same keys (A/B / golden). Not page-grouped.
    pub fn get_many_serial(&self, fks: &[Fk]) -> Result<HashMap<u64, [u8; 32]>, StoreError> {
        let mut out = HashMap::new();
        for fk in fks {
            match self.get(*fk) {
                Ok(t) => {
                    if let Some(id) = fk.get() {
                        out.insert(id, t);
                    }
                }
                Err(StoreError::NotFound) | Err(StoreError::InvalidFk) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-txid-body-{n}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn append_and_get_roundtrip() {
        let dir = tmp();
        let t = TxidBody::create(&dir).unwrap();
        assert_eq!(t.count(), 0);
        let a = [1u8; 32];
        let b = [2u8; 32];
        t.append_batch(0, &[a, b]).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(Fk(1)).unwrap(), a);
        assert_eq!(t.get(Fk(2)).unwrap(), b);
        assert_eq!(t.get_range(1, 2).unwrap(), vec![a, b]);
        // reopen
        drop(t);
        let t2 = TxidBody::open(&dir).unwrap();
        assert_eq!(t2.count(), 2);
        assert_eq!(t2.get(Fk(2)).unwrap(), b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Held pool session must fill identity pages via `pread_batch_on_session`
    /// (not one-shot `pread_at`). SQE lens prove the session path ran.
    #[test]
    fn page_grouped_on_pool_session_pushes_sqes() {
        use crate::uring_session::{SessionKind, UringSession};
        let dir = tmp();
        let t = TxidBody::create(&dir).unwrap();
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        t.append_batch(0, &[a, b]).unwrap();
        let mut session = UringSession::try_open_kind(SessionKind::Pool, 32).expect("pool");
        let _ = session.take_sqe_n();
        let (map, pages) = t
            .get_many_page_grouped_on_session(&[Fk(1), Fk(2)], &mut session)
            .expect("session identity");
        session.drain_all().unwrap();
        assert_eq!(pages, 1);
        assert_eq!(map.get(&1), Some(&a));
        assert_eq!(map.get(&2), Some(&b));
        assert!(
            session.take_sqe_n() > 0,
            "get_many_page_grouped_on_session must submit on the held session"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_offset_layout() {
        assert_eq!(TxidBody::entry_offset(1).unwrap(), 32);
        assert_eq!(TxidBody::entry_offset(2).unwrap(), 64);
        assert!(TxidBody::entry_offset(0).is_err());
        assert_eq!(TXID_ENTRIES_PER_PAGE, 128);
        assert_eq!(TxidBody::entry_page(1).unwrap(), 0);
        assert_eq!(TxidBody::entry_page(TXID_ENTRIES_PER_PAGE + 1).unwrap(), 1);
    }

    #[test]
    fn truncate_get_many_logical_and_errors() {
        let dir = tmp();
        let t = TxidBody::create(&dir).unwrap();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let c = [0xCCu8; 32];
        t.append_batch(0, &[a, b, c]).unwrap();
        assert!(t.logical_len() >= 32 * 3);
        // get_many: empty + mix of present / past-end.
        assert!(t.get_many(&[]).unwrap().is_empty());
        let many = t.get_many(&[Fk(1), Fk(2), Fk(99), Fk(3)]).unwrap();
        assert_eq!(many[0], Some(a));
        assert_eq!(many[1], Some(b));
        assert_eq!(many[2], None);
        assert_eq!(many[3], Some(c));
        // NotFound on single get past end.
        assert!(matches!(t.get(Fk(99)), Err(StoreError::NotFound)));
        // Truncate to shorter prefix.
        t.truncate_to_count(2).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(Fk(2)).unwrap(), b);
        assert!(matches!(t.get(Fk(3)), Err(StoreError::NotFound)));
        // No-op truncate to same count.
        t.truncate_to_count(2).unwrap();
        // Past-count truncate is corrupt.
        assert!(matches!(
            t.truncate_to_count(5),
            Err(StoreError::Corrupt(_))
        ));
        // Append at wrong expected count.
        assert!(matches!(
            t.append_batch(0, &[[0u8; 32]]),
            Err(StoreError::Corrupt(_))
        ));
        // Empty append is fine.
        t.append_batch(2, &[]).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Page-grouped multi-get matches serial `get` for dense + sparse fks and
    /// issues ≤1 bulk read per OS page touched.
    #[test]
    fn get_many_page_grouped_matches_serial_and_caps_pages() {
        let dir = tmp();
        let t = TxidBody::create(&dir).unwrap();
        // 300 entries → spans multiple 128-entry pages.
        let mut all = Vec::with_capacity(300);
        for i in 0..300u32 {
            let mut x = [0u8; 32];
            x[0..4].copy_from_slice(&i.to_le_bytes());
            all.push(x);
        }
        t.append_batch(0, &all).unwrap();

        // Dense run within page 0 (fks 1..10).
        let dense: Vec<Fk> = (1u64..=10).map(Fk).collect();
        let (map_d, pages_d) = t.get_many_page_grouped(&dense).unwrap();
        let serial_d = t.get_many_serial(&dense).unwrap();
        assert_eq!(map_d, serial_d);
        assert_eq!(pages_d, 1, "dense same-page fks must be one bulk read");

        // Sparse across pages: fk 1 (page0), 129 (page1), 257 (page2).
        let sparse = vec![Fk(1), Fk(129), Fk(257), Fk(1)]; // dup ok
        let (map_s, pages_s) = t.get_many_page_grouped(&sparse).unwrap();
        let serial_s = t.get_many_serial(&sparse).unwrap();
        assert_eq!(map_s, serial_s);
        assert_eq!(pages_s, 3, "three distinct pages → three bulk reads");
        // get_many order scatter
        let many = t.get_many(&sparse).unwrap();
        assert_eq!(many[0], Some(all[0]));
        assert_eq!(many[1], Some(all[128]));
        assert_eq!(many[2], Some(all[256]));
        assert_eq!(many[3], Some(all[0]));

        // Cluster within page 1: fks 130, 140, 150 → one page.
        let cluster: Vec<Fk> = [130u64, 140, 150].into_iter().map(Fk).collect();
        let (_m, pages_c) = t.get_many_page_grouped(&cluster).unwrap();
        assert_eq!(pages_c, 1);

        // Out-of-range ignored.
        let (empty_map, p0) = t.get_many_page_grouped(&[Fk(9999), Fk(0)]).unwrap();
        assert!(empty_map.is_empty());
        assert_eq!(p0, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
