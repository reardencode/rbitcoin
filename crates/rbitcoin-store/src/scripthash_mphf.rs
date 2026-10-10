//! Sealed SH shard: compact BDZ MPHF + dense 8 B pack8 locators.
//!
//! `base.mphf` is BDZ3 (2-bit `g` + occupancy) then `n` mix64(key16) tags
//! (not loaded into RAM). `base.val` is `n × 8` pack8. A key not in the set
//! fails the tag check.

use crate::bdz::BdzMphf;
use crate::error::StoreError;
use crate::io_handle::IoHandle;
use crate::scripthash_layout::{pack8, unpack8, ShHeadKey, ShHeadValue, SH_HEAD_KEY_LEN};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct MphfHead {
    base: PathBuf,
    mphf_file: File,
    val_file: File,
    mphf: BdzMphf,
    tags_off: u64,
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
    u64::from_le_bytes(key[0..8].try_into().expect("key16 half"))
        ^ u64::from_le_bytes(key[8..16].try_into().expect("key16 half"))
}

pub(crate) fn mix64_keys(recs: &[(ShHeadKey, u64)]) -> Vec<u64> {
    recs.iter().map(|(k, _)| mix_key16(k)).collect()
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

    pub fn occ_bytes_resident(&self) -> usize {
        self.mphf.occ_bytes_resident()
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.val_file
            .sync_data()
            .map_err(|e| StoreError::io(val_path(&self.base), e))
    }

    pub fn write_pack8(
        base: impl AsRef<Path>,
        recs: &[(ShHeadKey, u64)],
    ) -> Result<Self, StoreError> {
        let keys = mix64_keys(recs);
        Self::write_pack8_mixed(base, recs, &keys)
    }

    pub(crate) fn write_pack8_mixed(
        base: impl AsRef<Path>,
        recs: &[(ShHeadKey, u64)],
        keys: &[u64],
    ) -> Result<Self, StoreError> {
        let base = base.as_ref();
        if let Some(parent) = base.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mphf = BdzMphf::build_compact(keys)?;
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
        let staging = crate::file::tmp_sidecar_path(&mp);
        mphf.write_compact_to(&staging)?;
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&staging)
                .map_err(|e| StoreError::io(&staging, e))?;
            f.write_all(&tags)
                .map_err(|e| StoreError::io(&staging, e))?;
            f.sync_all().map_err(|e| StoreError::io(&staging, e))?;
        }
        std::fs::rename(&staging, &mp).map_err(|e| StoreError::io(&mp, e))?;
        let vp = val_path(base);
        crate::file::write_synced_tmp_rename(&vp, &val)?;
        Self::open(base)
    }

    /// MPHF slot for a key known to be in the set (no tag pread).
    pub fn slot_for_key16(&self, key: &ShHeadKey) -> Result<u32, StoreError> {
        if self.mphf.n() == 0 {
            return Err(StoreError::Corrupt("sh mphf: empty shard has key"));
        }
        self.mphf.index(mix_key16(key))
    }

    /// Overwrite pack8 words by MPHF slot (pass-2 pack; does not rebuild BDZ).
    ///
    /// Every slot is checked before any write. `.val` up to 512 MiB is patched
    /// as one image; larger files use 1 MiB windows.
    pub fn rewrite_val_slots(&self, words: &[(u32, u64)]) -> Result<(), StoreError> {
        let n = self.mphf.n();
        for &(slot, _) in words {
            if slot >= n {
                return Err(StoreError::Corrupt("sh mphf: slot OOB"));
            }
        }
        let len = u64::from(n).saturating_mul(8);
        let path = val_path(&self.base);
        if words.is_empty() || len == 0 {
            self.val_file
                .sync_data()
                .map_err(|e| StoreError::io(&path, e))?;
            return Ok(());
        }
        if len <= VAL_REWRITE_FULL_MAX {
            let mut buf = vec![0u8; len as usize];
            pread_file_exact(&self.val_file, 0, &mut buf).map_err(|e| StoreError::io(&path, e))?;
            patch_val_image(&mut buf, 0, words);
            pwrite_file(&self.val_file, 0, &buf).map_err(|e| StoreError::io(&path, e))?;
        } else {
            rewrite_val_windows(&self.val_file, words, VAL_REWRITE_WINDOW)
                .map_err(|e| StoreError::io(&path, e))?;
        }
        self.val_file
            .sync_data()
            .map_err(|e| StoreError::io(&path, e))?;
        Ok(())
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
            .map_err(|e| StoreError::io(val_path(&self.base), e))?;
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
        pread_file_exact(&self.mphf_file, self.tags_off + slot * 8, &mut tag)
            .map_err(|e| StoreError::io(mphf_path(&self.base), e))?;
        if u64::from_le_bytes(tag) != ku {
            return Ok(None);
        }
        Ok(Some(slot))
    }

    fn read_val(&self, slot: u64) -> Result<ShHeadValue, StoreError> {
        let mut buf = [0u8; 8];
        pread_file_exact(&self.val_file, slot * 8, &mut buf)
            .map_err(|e| StoreError::io(val_path(&self.base), e))?;
        unpack8(u64::from_le_bytes(buf))
    }
}

/// Patch a whole `.val` in RAM up to this size. Above it, windowed RMW.
const VAL_REWRITE_FULL_MAX: u64 = 512 << 20;
/// Byte cap of one read-modify-write span on a large `.val`.
const VAL_REWRITE_WINDOW: u64 = 1 << 20;

fn patch_val_image(buf: &mut [u8], base_slot: u32, words: &[(u32, u64)]) {
    for &(slot, w) in words {
        let rel = (slot - base_slot) as usize * 8;
        buf[rel..rel + 8].copy_from_slice(&w.to_le_bytes());
    }
}

/// Inclusive slot spans whose byte width is at most `window_bytes`.
/// `words` must be sorted by slot. Later duplicates of a slot stay in the
/// same span so the caller applies them in order.
fn val_window_spans(words: &[(u32, u64)], window_bytes: u64) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < words.len() {
        let start = words[i].0;
        let mut end = start;
        let mut j = i + 1;
        while j < words.len() {
            let slot = words[j].0;
            let span = (u64::from(slot) - u64::from(start) + 1).saturating_mul(8);
            if span > window_bytes.max(8) {
                break;
            }
            end = slot;
            j += 1;
        }
        out.push((start, end));
        i = j;
    }
    out
}

fn rewrite_val_windows(
    file: &File,
    words: &[(u32, u64)],
    window_bytes: u64,
) -> std::io::Result<()> {
    let mut order: Vec<usize> = (0..words.len()).collect();
    order.sort_by_key(|&i| (words[i].0, i));
    let sorted: Vec<(u32, u64)> = order.iter().map(|&i| words[i]).collect();
    let mut at = 0usize;
    for (start, end) in val_window_spans(&sorted, window_bytes) {
        let mut next = at;
        while next < sorted.len() && sorted[next].0 <= end {
            next += 1;
        }
        let span = ((end - start) as usize + 1) * 8;
        let off = u64::from(start) * 8;
        let mut buf = vec![0u8; span];
        pread_file_exact(file, off, &mut buf)?;
        patch_val_image(&mut buf, start, &sorted[at..next]);
        pwrite_file(file, off, &buf)?;
        at = next;
    }
    Ok(())
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
        h.flush().unwrap();
        assert!(MphfHead::exists(&base));
        assert!(mphf_path(&base).is_file());
        assert!(val_path(&base).is_file());
        assert_eq!(std::fs::metadata(val_path(&base)).unwrap().len(), 16);
        let h2 = MphfHead::open(&base).unwrap();
        assert_eq!(h2.g_bytes_resident(), 0);
        assert!(
            h2.occ_bytes_resident() > 0 && h2.occ_bytes_resident() < 64,
            "open must keep supers, not copy occ"
        );
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
    fn sh_mphf_empty_and_extent_last_only() {
        let dir = tmp();
        let base = dir.join("00");
        let h = MphfHead::write_pack8(&base, &[]).unwrap();
        assert!(h.is_empty());
        assert!(h.get(&key(1)).unwrap().is_none());
        let extent = ShHeadValue::extent(8192);
        let h = MphfHead::write_pack8(&base, &[(key(1), pack8(&extent).unwrap())]).unwrap();
        match h.get(&key(1)).unwrap().unwrap() {
            ShHeadValue::Extent { last_page: 8192 } => {}
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_write_keys_zero_val_then_rewrite_slots() {
        let dir = tmp();
        let base = dir.join("00");
        let k1 = key(1);
        let k2 = key(2);
        let h = MphfHead::write_pack8(&base, &[(k1, 0), (k2, 0)]).unwrap();
        assert!(h.get(&k1).unwrap().unwrap().is_empty());
        let s1 = h.slot_for_key16(&k1).unwrap();
        let s2 = h.slot_for_key16(&k2).unwrap();
        let a = pack8(&ShHeadValue::inline_one(Fk(11))).unwrap();
        let b = pack8(&ShHeadValue::inline_one(Fk(22))).unwrap();
        h.rewrite_val_slots(&[(s1, a), (s2, b)]).unwrap();
        assert_eq!(
            h.get(&k1).unwrap().unwrap(),
            ShHeadValue::inline_one(Fk(11))
        );
        assert_eq!(
            h.get(&k2).unwrap().unwrap(),
            ShHeadValue::inline_one(Fk(22))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_rewrite_val_edges_keep_middle_and_length() {
        let dir = tmp();
        let base = dir.join("00");
        let keys: Vec<ShHeadKey> = (1..=4).map(key).collect();
        let recs: Vec<(ShHeadKey, u64)> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    *k,
                    pack8(&ShHeadValue::inline_one(Fk(100 + i as u64))).unwrap(),
                )
            })
            .collect();
        let h = MphfHead::write_pack8(&base, &recs).unwrap();
        let n = h.mphf.n();
        assert_eq!(n, 4);
        assert_eq!(std::fs::metadata(val_path(&base)).unwrap().len(), 32);
        let mut by_slot = vec![None; n as usize];
        for (i, k) in keys.iter().enumerate() {
            let slot = h.slot_for_key16(k).unwrap() as usize;
            by_slot[slot] = Some((i, *k));
        }
        let (_i0, k0) = by_slot[0].unwrap();
        let (_il, kl) = by_slot[n as usize - 1].unwrap();
        let mid_slot = (1..n as usize - 1).find(|s| by_slot[*s].is_some()).unwrap();
        let (im, km) = by_slot[mid_slot].unwrap();
        let w0 = pack8(&ShHeadValue::inline_one(Fk(7))).unwrap();
        let wl = pack8(&ShHeadValue::inline_one(Fk(9))).unwrap();
        h.rewrite_val_slots(&[(0, w0), (n - 1, wl)]).unwrap();
        assert_eq!(h.get(&k0).unwrap().unwrap(), ShHeadValue::inline_one(Fk(7)));
        assert_eq!(h.get(&kl).unwrap().unwrap(), ShHeadValue::inline_one(Fk(9)));
        assert_eq!(
            h.get(&km).unwrap().unwrap(),
            ShHeadValue::inline_one(Fk(100 + im as u64))
        );
        assert_eq!(std::fs::metadata(val_path(&base)).unwrap().len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_rewrite_val_oob_does_not_tear() {
        let dir = tmp();
        let base = dir.join("00");
        let k1 = key(1);
        let k2 = key(2);
        let a = ShHeadValue::inline_one(Fk(11));
        let b = ShHeadValue::inline_one(Fk(22));
        let h = MphfHead::write_pack8(&base, &[(k1, pack8(&a).unwrap()), (k2, pack8(&b).unwrap())])
            .unwrap();
        let s1 = h.slot_for_key16(&k1).unwrap();
        let before = std::fs::read(val_path(&base)).unwrap();
        let err = h
            .rewrite_val_slots(&[
                (s1, pack8(&ShHeadValue::inline_one(Fk(99))).unwrap()),
                (99, 1),
            ])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(m) if m.contains("slot OOB")));
        assert_eq!(std::fs::read(val_path(&base)).unwrap(), before);
        assert_eq!(h.get(&k1).unwrap().unwrap(), a);
        assert_eq!(h.get(&k2).unwrap().unwrap(), b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn val_window_spans_split_on_gap() {
        let words = [(0u32, 1u64), (1, 2), (10, 3), (10, 4), (11, 5)];
        assert_eq!(val_window_spans(&words, 24), vec![(0, 1), (10, 11)]);
        assert_eq!(
            val_window_spans(&words, 8),
            vec![(0, 0), (1, 1), (10, 10), (11, 11)]
        );
    }

    #[test]
    fn rewrite_val_windows_last_duplicate_wins() {
        let dir = tmp();
        let path = dir.join("val");
        let mut raw = vec![0u8; 16 * 8];
        for slot in 0..16u32 {
            let off = slot as usize * 8;
            raw[off..off + 8].copy_from_slice(&(u64::from(slot) + 1).to_le_bytes());
        }
        std::fs::write(&path, &raw).unwrap();
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        rewrite_val_windows(&f, &[(0, 9), (15, 7), (0, 4), (2, 8)], 16).unwrap();
        let got = std::fs::read(&path).unwrap();
        assert_eq!(u64::from_le_bytes(got[0..8].try_into().unwrap()), 4);
        assert_eq!(u64::from_le_bytes(got[8..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(got[16..24].try_into().unwrap()), 8);
        assert_eq!(u64::from_le_bytes(got[24..32].try_into().unwrap()), 4);
        assert_eq!(
            u64::from_le_bytes(got[15 * 8..16 * 8].try_into().unwrap()),
            7
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sh_mphf_duplicate_key16_does_not_clone_sort_mix64() {
        let dir = tmp();
        let base = dir.join("00");
        let a = ShHeadValue::inline_one(Fk(11));
        let recs = [(key(1), pack8(&a).unwrap()), (key(1), pack8(&a).unwrap())];
        match MphfHead::write_pack8(&base, &recs) {
            Err(StoreError::Corrupt(m)) if m.contains("mix64 collision") => {
                panic!("mix64 clone-sort is not the collision path: {m}")
            }
            Err(StoreError::Corrupt(_)) | Ok(_) => {}
            Err(e) => panic!("unexpected {e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
