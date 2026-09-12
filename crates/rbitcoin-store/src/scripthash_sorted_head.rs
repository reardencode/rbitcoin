//! Sealed sorted Class B head: packed `(key16 ‖ pack8)` + `.idx`.
//!
//! Record count is immutable after seal. Existing keys update pack8 in
//! place. A key that is not on this file is **not inserted** (caller uses ovf).
//!
//! **Main shards** are idx-only (misses pay one 4 KiB data pread). **Sealed
//! ovf** still writes BF8R so a miss walk can skip the page.

use crate::error::StoreError;
use crate::fuse8_filter::{fuse_key_from_mixed, SealedFuse8};
use crate::io_handle::IoHandle;
use crate::scripthash_layout::{
    pack8_bytes, unpack8_bytes, ShHeadKey, ShHeadValue, SH_HEAD_KEY_LEN, SH_HEAD_SLOT_SIZE,
    SH_HEAD_VALUE_LEN,
};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Records per data page (170 × 24 B = 4080 B).
pub const SH_SORTED_RECS_PER_PAGE: usize = 170;
const DATA_MAGIC: &[u8; 4] = b"SHSR";
const IDX_MAGIC: &[u8; 4] = b"SHIX";
const FORMAT_VER: u16 = 2;
const DATA_HEADER_LEN: u64 = 32;
const IDX_HEADER_LEN: usize = 16;
const IDX_ENT_LEN: usize = SH_HEAD_KEY_LEN + 8;

/// Sealed sorted head file (one shard or one global ovf segment).
pub struct SortedHead {
    path: PathBuf,
    file: File,
    count: u64,
    /// First key of each 4 KiB data page + file offset of that page.
    idx: Vec<(ShHeadKey, u64)>,
    fuse: Option<SealedFuse8>,
    preads: AtomicU64,
}

impl SortedHead {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Durability barrier (shutdown / SH flush). Data already pwrite'd.
    pub fn flush(&self) -> Result<(), StoreError> {
        self.file
            .sync_data()
            .map_err(|e| StoreError::io(&self.path, e))
    }

    /// Write a sealed sorted head. `recs` must be unique and sorted by key16.
    pub fn write(
        path: impl AsRef<Path>,
        recs: &[(ShHeadKey, [u8; SH_HEAD_VALUE_LEN])],
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        for w in recs.windows(2) {
            if w[1].0 <= w[0].0 {
                return Err(StoreError::Corrupt(
                    "scripthash sorted head: recs not strictly increasing",
                ));
            }
        }
        let count = recs.len() as u64;
        let mut header = [0u8; DATA_HEADER_LEN as usize];
        header[0..4].copy_from_slice(DATA_MAGIC);
        header[4..6].copy_from_slice(&FORMAT_VER.to_le_bytes());
        header[6..14].copy_from_slice(&count.to_le_bytes());
        header[14..16].copy_from_slice(&(SH_SORTED_RECS_PER_PAGE as u16).to_le_bytes());

        {
            let mut f = File::create(path).map_err(|e| StoreError::io(path, e))?;
            f.write_all(&header).map_err(|e| StoreError::io(path, e))?;
            for (k, v) in recs {
                f.write_all(k).map_err(|e| StoreError::io(path, e))?;
                f.write_all(v).map_err(|e| StoreError::io(path, e))?;
            }
            f.sync_all().map_err(|e| StoreError::io(path, e))?;
        }

        let mut idx: Vec<(ShHeadKey, u64)> = Vec::new();
        let mut i = 0usize;
        while i < recs.len() {
            let off = DATA_HEADER_LEN + (i as u64) * SH_HEAD_SLOT_SIZE as u64;
            idx.push((recs[i].0, off));
            i += SH_SORTED_RECS_PER_PAGE;
        }
        write_idx(&idx_path(path), &idx)?;

        let mut fuse_keys: Vec<u64> = recs.iter().map(|(k, _)| fuse_key16(k)).collect();
        fuse_keys.sort_unstable();
        fuse_keys.dedup();
        let fuse = SealedFuse8::build(&fuse_keys)?;
        fuse.write_to(&fuse_path(path))?;

        Self::open(path)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        let mut header = [0u8; DATA_HEADER_LEN as usize];
        let _ = pread_file(&file, 0, &mut header).map_err(|e| StoreError::io(&path, e))?;
        if header[0..4] != *DATA_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let ver = u16::from_le_bytes(header[4..6].try_into().unwrap());
        if ver != FORMAT_VER {
            return Err(StoreError::Corrupt(
                "scripthash sorted head: unsupported version",
            ));
        }
        let count = u64::from_le_bytes(header[6..14].try_into().unwrap());
        let idx = read_idx(&idx_path(&path))?;
        let fuse = Some(SealedFuse8::read_from(&fuse_path(&path))?);
        Ok(Self {
            path,
            file,
            count,
            idx,
            fuse,
            preads: AtomicU64::new(0),
        })
    }

    pub fn get(&self, key: &ShHeadKey) -> Result<Option<ShHeadValue>, StoreError> {
        if let Some(ref fuse) = self.fuse {
            if !fuse.contains(fuse_key16(key)) {
                return Ok(None);
            }
        }
        let Some((_slot, rec)) = self.locate_rec(key)? else {
            return Ok(None);
        };
        let mut val = [0u8; SH_HEAD_VALUE_LEN];
        val.copy_from_slice(&rec[SH_HEAD_KEY_LEN..]);
        Ok(Some(unpack8_bytes(&val)?))
    }

    /// In-place `value16` update. `Ok(false)` if the key is not on this file.
    pub fn update_value(&self, key: &ShHeadKey, value: &ShHeadValue) -> Result<bool, StoreError> {
        if let Some(ref fuse) = self.fuse {
            if !fuse.contains(fuse_key16(key)) {
                return Ok(false);
            }
        }
        let Some(slot) = self.locate_rec(key)?.map(|(s, _)| s) else {
            return Ok(false);
        };
        let enc = pack8_bytes(value)?;
        let off = DATA_HEADER_LEN + slot * SH_HEAD_SLOT_SIZE as u64 + SH_HEAD_KEY_LEN as u64;
        pwrite_file(&self.file, off, &enc).map_err(|e| StoreError::io(&self.path, e))?;
        Ok(true)
    }

    /// Visit every record (cold walks / seal-merge). Sequential reads, not the get path.
    pub fn for_each_occupied(
        &self,
        mut f: impl FnMut(ShHeadKey, ShHeadValue) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut rec = [0u8; SH_HEAD_SLOT_SIZE];
        for slot in 0..self.count {
            let off = DATA_HEADER_LEN + slot * SH_HEAD_SLOT_SIZE as u64;
            pread_file_exact(&self.file, off, &mut rec)
                .map_err(|e| StoreError::io(&self.path, e))?;
            let k: ShHeadKey = rec[0..SH_HEAD_KEY_LEN].try_into().unwrap();
            let val = unpack8_bytes(&rec[SH_HEAD_KEY_LEN..].try_into().unwrap())?;
            if !val.is_empty() {
                f(k, val)?;
            }
        }
        Ok(())
    }

    fn locate_rec(
        &self,
        key: &ShHeadKey,
    ) -> Result<Option<(u64, [u8; SH_HEAD_SLOT_SIZE])>, StoreError> {
        if self.count == 0 || self.idx.is_empty() {
            return Ok(None);
        }
        let i = match self.idx.binary_search_by(|probe| probe.0.cmp(key)) {
            Ok(exact) => exact,
            Err(0) => return Ok(None),
            Err(ins) => ins - 1,
        };
        let page_off = self.idx[i].1;
        let page_slot0 = (page_off - DATA_HEADER_LEN) / SH_HEAD_SLOT_SIZE as u64;
        let remain = self.count.saturating_sub(page_slot0);
        let n = remain.min(SH_SORTED_RECS_PER_PAGE as u64) as usize;
        let mut page = vec![0u8; n * SH_HEAD_SLOT_SIZE];
        self.preads.fetch_add(1, Ordering::Relaxed);
        pread_file_exact(&self.file, page_off, &mut page)
            .map_err(|e| StoreError::io(&self.path, e))?;
        for s in 0..n {
            let rec = &page[s * SH_HEAD_SLOT_SIZE..(s + 1) * SH_HEAD_SLOT_SIZE];
            let k: ShHeadKey = rec[0..SH_HEAD_KEY_LEN].try_into().unwrap();
            match k.cmp(key) {
                std::cmp::Ordering::Equal => {
                    let mut out = [0u8; SH_HEAD_SLOT_SIZE];
                    out.copy_from_slice(rec);
                    return Ok(Some((page_slot0 + s as u64, out)));
                }
                std::cmp::Ordering::Greater => return Ok(None),
                std::cmp::Ordering::Less => {}
            }
        }
        Ok(None)
    }
}

fn pread_file(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = IoHandle::from_file(file).pread(offset, buf);
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn pread_file_exact(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let h = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < buf.len() {
        let n = h.pread(offset + done as u64, &mut buf[done..]);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "pread short",
            ));
        }
        done += n as usize;
    }
    Ok(())
}

fn pwrite_file(file: &File, offset: u64, buf: &[u8]) -> std::io::Result<()> {
    let h = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < buf.len() {
        let n = h.pwrite(offset + done as u64, &buf[done..]);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "pwrite returned 0",
            ));
        }
        done += n as usize;
    }
    Ok(())
}

fn fuse_key16(key: &ShHeadKey) -> u64 {
    let mut pad = [0u8; 32];
    pad[..SH_HEAD_KEY_LEN].copy_from_slice(key);
    fuse_key_from_mixed(&pad)
}

fn idx_path(data: &Path) -> PathBuf {
    let mut s = data.as_os_str().to_os_string();
    s.push(".idx");
    PathBuf::from(s)
}

fn fuse_path(data: &Path) -> PathBuf {
    let mut s = data.as_os_str().to_os_string();
    s.push(".fuse8");
    PathBuf::from(s)
}

fn write_idx(path: &Path, idx: &[(ShHeadKey, u64)]) -> Result<(), StoreError> {
    let mut buf = vec![0u8; IDX_HEADER_LEN + idx.len() * IDX_ENT_LEN];
    buf[0..4].copy_from_slice(IDX_MAGIC);
    buf[4..6].copy_from_slice(&FORMAT_VER.to_le_bytes());
    buf[6..10].copy_from_slice(&(idx.len() as u32).to_le_bytes());
    let mut off = IDX_HEADER_LEN;
    for (k, rec_off) in idx {
        buf[off..off + SH_HEAD_KEY_LEN].copy_from_slice(k);
        off += SH_HEAD_KEY_LEN;
        buf[off..off + 8].copy_from_slice(&rec_off.to_le_bytes());
        off += 8;
    }
    crate::file::write_synced_tmp_rename(path, &buf)?;
    Ok(())
}

fn read_idx(path: &Path) -> Result<Vec<(ShHeadKey, u64)>, StoreError> {
    let buf = std::fs::read(path).map_err(|e| StoreError::io(path, e))?;
    if buf.len() < IDX_HEADER_LEN || buf[0..4] != *IDX_MAGIC {
        return Err(StoreError::Corrupt("scripthash sorted head: bad idx"));
    }
    let n = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
    if buf.len() < IDX_HEADER_LEN + n * IDX_ENT_LEN {
        return Err(StoreError::Corrupt("scripthash sorted head: short idx"));
    }
    let mut out = Vec::with_capacity(n);
    let mut off = IDX_HEADER_LEN;
    for _ in 0..n {
        let k: ShHeadKey = buf[off..off + SH_HEAD_KEY_LEN].try_into().unwrap();
        off += SH_HEAD_KEY_LEN;
        let rec_off = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        off += 8;
        out.push((k, rec_off));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::Fk;
    use std::sync::atomic::Ordering;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-shsort-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&p);
        p.join("head")
    }

    fn key_of(i: u32) -> ShHeadKey {
        let mut k = [0u8; 16];
        k[0..4].copy_from_slice(&i.to_be_bytes());
        k
    }

    fn recs(n: u32) -> Vec<(ShHeadKey, [u8; SH_HEAD_VALUE_LEN])> {
        (0..n)
            .map(|i| {
                let v = ShHeadValue::inline_one(Fk(u64::from(i) + 1));
                (key_of(i), pack8_bytes(&v).unwrap())
            })
            .collect()
    }

    #[test]
    fn sorted_head_hit_miss_update() {
        let path = tmp();
        let n = 10_000u32;
        let recs = recs(n);
        let h = SortedHead::write(&path, &recs).unwrap();
        assert_eq!(h.count, u64::from(n));
        assert!(h.fuse.is_some());
        assert_eq!(h.path(), path.as_path());
        assert!(path.is_file());
        assert!(idx_path(&path).is_file());
        assert!(fuse_path(&path).is_file());

        h.preads.store(0, Ordering::Relaxed);
        let got = h.get(&key_of(1234)).unwrap().unwrap();
        assert_eq!(got.inline_fks(), vec![Fk(1235)]);
        assert!(
            h.preads.load(Ordering::Relaxed) <= 2,
            "hit must be ≤2 preads, got {}",
            h.preads.load(Ordering::Relaxed)
        );

        h.preads.store(0, Ordering::Relaxed);
        assert!(h.get(&key_of(n + 10_000)).unwrap().is_none());

        let new_val = ShHeadValue::slab(0, 2, 4096);
        assert!(h.update_value(&key_of(7), &new_val).unwrap());
        assert_eq!(h.get(&key_of(7)).unwrap().unwrap(), new_val);
        assert!(!h.update_value(&key_of(n + 1), &new_val).unwrap());

        let h2 = SortedHead::open(&path).unwrap();
        assert!(h2.fuse.is_some());
        assert_eq!(h2.get(&key_of(7)).unwrap().unwrap(), new_val);

        let unsorted = vec![(key_of(2), recs[0].1), (key_of(1), recs[0].1)];
        assert!(SortedHead::write(path.with_extension("bad"), &unsorted).is_err());
        let junk = path.with_extension("junk");
        std::fs::write(&junk, b"XXXX").unwrap();
        assert!(matches!(SortedHead::open(&junk), Err(StoreError::BadMagic)));
        let mut bad_ver = std::fs::read(&path).unwrap();
        bad_ver[4..6].copy_from_slice(&99u16.to_le_bytes());
        let verp = path.with_extension("ver");
        std::fs::write(&verp, &bad_ver).unwrap();
        std::fs::copy(idx_path(&path), idx_path(&verp)).unwrap();
        std::fs::copy(fuse_path(&path), fuse_path(&verp)).unwrap();
        assert!(SortedHead::open(&verp).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(idx_path(&path));
        let _ = std::fs::remove_file(fuse_path(&path));
        let _ = std::fs::remove_file(&junk);
        let _ = std::fs::remove_file(&verp);
        let _ = std::fs::remove_file(idx_path(&verp));
        let _ = std::fs::remove_file(fuse_path(&verp));
    }

    #[test]
    fn sorted_ovf_fuse_skips_pread_on_miss() {
        let path = tmp();
        let n = 10_000u32;
        let recs = recs(n);
        let h = SortedHead::write(&path, &recs).unwrap();
        assert!(h.fuse.is_some());
        assert!(fuse_path(&path).is_file());

        h.preads.store(0, Ordering::Relaxed);
        assert!(h.get(&key_of(1234)).unwrap().is_some());
        assert!(h.preads.load(Ordering::Relaxed) <= 2);

        let mut saw_fuse_miss = false;
        for extra in 0..2000u32 {
            let k = key_of(n + 10_000 + extra);
            h.preads.store(0, Ordering::Relaxed);
            let got = h.get(&k).unwrap();
            if got.is_none() && h.preads.load(Ordering::Relaxed) == 0 {
                saw_fuse_miss = true;
                break;
            }
            assert!(got.is_none(), "absent key must not decode as present");
        }
        assert!(
            saw_fuse_miss,
            "ovf fuse must skip data/idx IO on a true miss"
        );

        assert!(SortedHead::open(&path).unwrap().fuse.is_some());
        let _ = std::fs::remove_file(fuse_path(&path));
        assert!(SortedHead::open(&path).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(idx_path(&path));
    }
}
