//! Sealed SH shard: compact BDZ MPHF + dense 8 B pack8 locators.
//!
//! `base.mphf` is BDZ3 (2-bit `g` + occupancy) then `n` mix64(key16) tags
//! (not loaded into RAM). `base.val` is `n × 8` pack8. A key not in the set
//! fails the tag check.

use crate::bdz::BdzMphf;
use crate::error::StoreError;
use crate::fuse8_filter::fuse_key_from_mixed;
use crate::io_handle::IoHandle;
use crate::scripthash_layout::{pack8, unpack8, ShHeadKey, ShHeadValue, SH_HEAD_KEY_LEN};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MphfHead {
    base: PathBuf,
    mphf_file: File,
    val_file: File,
    mphf: BdzMphf,
    tags_off: u64,
    preads: AtomicU64,
}

pub fn mphf_path(base: &Path) -> PathBuf {
    sidecar(base, ".mphf")
}

pub fn val_path(base: &Path) -> PathBuf {
    sidecar(base, ".val")
}

fn sidecar(base: &Path, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(ext);
    PathBuf::from(s)
}

pub fn mix_key16(key: &ShHeadKey) -> u64 {
    let mut pad = [0u8; 32];
    pad[..SH_HEAD_KEY_LEN].copy_from_slice(key);
    fuse_key_from_mixed(&pad)
}

fn mix64_keys_unique(recs: &[(ShHeadKey, u64)]) -> Result<Vec<u64>, StoreError> {
    let keys: Vec<u64> = recs.iter().map(|(k, _)| mix_key16(k)).collect();
    if keys.len() >= 2 {
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(StoreError::Corrupt("sh mphf: mix64 collision"));
        }
    }
    Ok(keys)
}

impl MphfHead {
    pub fn exists(base: &Path) -> bool {
        mphf_path(base).is_file() && val_path(base).is_file()
    }

    pub fn is_empty(&self) -> bool {
        self.mphf.n() == 0
    }

    pub fn g_bytes_resident(&self) -> usize {
        self.mphf.g_bytes_resident()
    }

    #[cfg(test)]
    pub fn pread_count(&self) -> u64 {
        self.preads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn reset_pread_count(&self) {
        self.preads.store(0, Ordering::Relaxed)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.val_file
            .sync_data()
            .map_err(|e| StoreError::io(&val_path(&self.base), e))?;
        self.mphf_file
            .sync_data()
            .map_err(|e| StoreError::io(&mphf_path(&self.base), e))
    }

    pub fn write_pack8(
        base: impl AsRef<Path>,
        recs: &[(ShHeadKey, u64)],
    ) -> Result<Self, StoreError> {
        let base = base.as_ref();
        if let Some(parent) = base.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let keys = mix64_keys_unique(recs)?;
        let mphf = BdzMphf::build_compact(&keys)?;
        let n = recs.len();
        let mut val = vec![0u8; n.saturating_mul(8)];
        let mut tags = vec![0u8; n.saturating_mul(8)];
        for (i, (_k, w)) in recs.iter().enumerate() {
            let ku = keys[i];
            let slot = mphf.index(ku)? as usize;
            tags[slot * 8..slot * 8 + 8].copy_from_slice(&ku.to_le_bytes());
            val[slot * 8..slot * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let mp = mphf_path(base);
        mphf.write_compact_to(&mp)?;
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&mp)
                .map_err(|e| StoreError::io(&mp, e))?;
            f.write_all(&tags).map_err(|e| StoreError::io(&mp, e))?;
            f.sync_all().map_err(|e| StoreError::io(&mp, e))?;
        }
        let vp = val_path(base);
        std::fs::write(&vp, &val).map_err(|e| StoreError::io(&vp, e))?;
        {
            let f = OpenOptions::new()
                .write(true)
                .open(&vp)
                .map_err(|e| StoreError::io(&vp, e))?;
            f.sync_all().map_err(|e| StoreError::io(&vp, e))?;
        }
        Self::open(base)
    }

    pub fn open(base: impl AsRef<Path>) -> Result<Self, StoreError> {
        let base = base.as_ref().to_path_buf();
        let mp = mphf_path(&base);
        let vp = val_path(&base);
        let mphf = BdzMphf::read_compact_from(&mp)?;
        let tags_off = mphf.trailer_off();
        let mphf_file = File::open(&mp).map_err(|e| StoreError::io(&mp, e))?;
        let val_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vp)
            .map_err(|e| StoreError::io(&vp, e))?;
        let n = mphf.n() as u64;
        let meta = val_file.metadata().map_err(|e| StoreError::io(&vp, e))?;
        if meta.len() != n.saturating_mul(8) {
            return Err(StoreError::Corrupt("sh mphf: val length"));
        }
        let mphf_len = mphf_file
            .metadata()
            .map_err(|e| StoreError::io(&mp, e))?
            .len();
        if mphf_len != tags_off + n.saturating_mul(8) {
            return Err(StoreError::Corrupt("sh mphf: tag length"));
        }
        Ok(Self {
            base,
            mphf_file,
            val_file,
            mphf,
            tags_off,
            preads: AtomicU64::new(0),
        })
    }

    pub fn get(&self, key: &ShHeadKey) -> Result<Option<ShHeadValue>, StoreError> {
        let Some(slot) = self.slot_if_present(key)? else {
            return Ok(None);
        };
        Ok(Some(self.read_val(slot)?))
    }

    pub fn update_value(&self, key: &ShHeadKey, value: &ShHeadValue) -> Result<bool, StoreError> {
        let Some(slot) = self.slot_if_present(key)? else {
            return Ok(false);
        };
        let w = pack8(value)?;
        let off = slot.saturating_mul(8);
        pwrite_file(&self.val_file, off, &w.to_le_bytes())
            .map_err(|e| StoreError::io(&val_path(&self.base), e))?;
        Ok(true)
    }

    pub fn for_each_occupied(
        &self,
        mut f: impl FnMut(ShHeadKey, ShHeadValue) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let n = self.mphf.n() as u64;
        let dummy = [0u8; SH_HEAD_KEY_LEN];
        for slot in 0..n {
            let v = self.read_val(slot)?;
            if !v.is_empty() {
                f(dummy, v)?;
            }
        }
        Ok(())
    }

    fn slot_if_present(&self, key: &ShHeadKey) -> Result<Option<u64>, StoreError> {
        if self.mphf.n() == 0 {
            return Ok(None);
        }
        let ku = mix_key16(key);
        let slot = u64::from(self.mphf.index(ku)?);
        let mut tag = [0u8; 8];
        self.preads.fetch_add(1, Ordering::Relaxed);
        pread_file_exact(&self.mphf_file, self.tags_off + slot * 8, &mut tag)
            .map_err(|e| StoreError::io(&mphf_path(&self.base), e))?;
        if u64::from_le_bytes(tag) != ku {
            return Ok(None);
        }
        Ok(Some(slot))
    }

    fn read_val(&self, slot: u64) -> Result<ShHeadValue, StoreError> {
        let mut buf = [0u8; 8];
        self.preads.fetch_add(1, Ordering::Relaxed);
        pread_file_exact(&self.val_file, slot * 8, &mut buf)
            .map_err(|e| StoreError::io(&val_path(&self.base), e))?;
        unpack8(u64::from_le_bytes(buf))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripthash_layout::pack8;
    use rbitcoin_primitives::Fk;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-sh-mphf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn key(tag: u8) -> ShHeadKey {
        let mut k = [0u8; SH_HEAD_KEY_LEN];
        k[0] = tag;
        k[1] = tag.wrapping_add(1);
        k
    }

    #[test]
    fn sh_mphf_two_keys_get_and_miss() {
        let dir = tmp();
        let base = dir.join("00");
        let a = ShHeadValue::inline_one(Fk(11));
        let b = ShHeadValue::inline_one(Fk(22));
        let recs = [(key(1), pack8(&a).unwrap()), (key(2), pack8(&b).unwrap())];
        let h = MphfHead::write_pack8(&base, &recs).unwrap();
        let raw = std::fs::read(mphf_path(&base)).unwrap();
        assert_eq!(&raw[0..4], b"BDZ3");
        let compact = BdzMphf::read_compact_from(&mphf_path(&base)).unwrap();
        assert_eq!(
            raw.len() as u64,
            compact.trailer_off() + (recs.len() as u64) * 8
        );
        assert_eq!(h.get(&key(1)).unwrap().unwrap(), a);
        assert_eq!(h.get(&key(2)).unwrap().unwrap(), b);
        assert!(h.get(&key(9)).unwrap().is_none());
        assert!(MphfHead::exists(&base));
        assert!(mphf_path(&base).is_file());
        assert!(val_path(&base).is_file());
        assert_eq!(std::fs::metadata(val_path(&base)).unwrap().len(), 16);
        let h2 = MphfHead::open(&base).unwrap();
        assert_eq!(h2.g_bytes_resident(), 0);
        assert_eq!(h2.get(&key(1)).unwrap().unwrap(), a);
        assert!(h2.get(&key(7)).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_update_inline_to_slab() {
        let dir = tmp();
        let base = dir.join("00");
        let one = ShHeadValue::inline_one(Fk(3));
        let h = MphfHead::write_pack8(&base, &[(key(4), pack8(&one).unwrap())]).unwrap();
        let slab = ShHeadValue::slab(0, 2, 4096);
        assert!(h.update_value(&key(4), &slab).unwrap());
        assert!(!h.update_value(&key(5), &slab).unwrap());
        match h.get(&key(4)).unwrap().unwrap() {
            ShHeadValue::Slab {
                class: 0,
                used: 2,
                off: 4096,
            } => {}
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_empty_and_paged_last_only() {
        let dir = tmp();
        let base = dir.join("00");
        let h = MphfHead::write_pack8(&base, &[]).unwrap();
        assert!(h.is_empty());
        assert!(h.get(&key(1)).unwrap().is_none());
        let paged = ShHeadValue::paged(4096, 8192);
        let h = MphfHead::write_pack8(&base, &[(key(1), pack8(&paged).unwrap())]).unwrap();
        match h.get(&key(1)).unwrap().unwrap() {
            ShHeadValue::Paged {
                first_page: 0,
                last_page: 8192,
            } => {}
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_duplicate_key16_is_mix64_collision() {
        let dir = tmp();
        let base = dir.join("00");
        let a = ShHeadValue::inline_one(Fk(11));
        let recs = [(key(1), pack8(&a).unwrap()), (key(1), pack8(&a).unwrap())];
        match MphfHead::write_pack8(&base, &recs) {
            Err(StoreError::Corrupt(m)) if m.contains("mix64 collision") => {}
            Err(e) => panic!("expected mix64 collision, got {e}"),
            Ok(_) => panic!("expected mix64 collision"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
