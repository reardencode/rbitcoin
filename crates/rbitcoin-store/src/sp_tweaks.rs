//! Thin BIP-352 tweak index (`sp_tweaks.idx/` + `sp_tweaks.body/`).
//!
//! Schema **17** side product. Missing dirs are not [`StoreError::Corrupt`].
//! Persist is **tweaks only** — no txids, outs, or parent scripts.
//!
//! **Tip / strong height only.** Slots are dense from `origin`. A reorg
//! truncates above the new tip and those heights are written again. The idx
//! does not store `header_fk`.
//!
//! **Original body:** `u8 len` then `len` bytes (`0` = none; `33` + compressed
//! `A_tweak`). Each body file stays addressable by `u32` off. When the next
//! record’s **start** would exceed `u32::MAX`, we roll a new `NNNNNN` pair.
//!
//! ```text
//! sp_tweaks.idx/meta      origin:u32 ‖ fmt:u32=3
//! sp_tweaks.idx/NNNNNN    slot[i] = off:u32     // start in that body file
//! sp_tweaks.body/NNNNNN   u8 len ‖ [u8; len]
//! ```
//!
//! Leftover **files** `sp_tweaks.idx` / `sp_tweaks.body` (pre-17 single-file)
//! are unlinked on store open; `--sptweaks` backfill regenerates.

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{Height, TableKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Compressed BIP-352 server tweak (Electrum tweaks wire).
pub const TWEAK_LEN: u8 = 33;
const SLOT: u64 = 4;
/// Schema 17: segmented tip-only idx, original 0/33 body.
const IDX_FMT_SEG_TIP: u32 = 3;

struct Seg {
    file_id: u32,
    first_slot: u64,
    n_slots: u64,
    idx: TableFile,
    body: TableFile,
}

struct Inner {
    segs: Vec<Seg>,
}

/// Height-dense thin tweak table (tip / strong heights only).
pub struct SpTweaksTable {
    dir: PathBuf,
    origin: u32,
    inner: Mutex<Inner>,
}

impl SpTweaksTable {
    pub fn idx_dir(dir: &Path) -> PathBuf {
        dir.join("sp_tweaks.idx")
    }

    pub fn body_dir(dir: &Path) -> PathBuf {
        dir.join("sp_tweaks.body")
    }

    fn meta_path(dir: &Path) -> PathBuf {
        Self::idx_dir(dir).join("meta")
    }

    fn seg_idx_path(dir: &Path, file_id: u32) -> PathBuf {
        Self::idx_dir(dir).join(format!("{file_id:06}"))
    }

    fn seg_body_path(dir: &Path, file_id: u32) -> PathBuf {
        Self::body_dir(dir).join(format!("{file_id:06}"))
    }

    pub fn files_present(dir: &Path) -> bool {
        Self::idx_dir(dir).is_dir()
            && Self::body_dir(dir).is_dir()
            && Self::meta_path(dir).is_file()
    }

    /// Pre-17 single files (not the schema-17 directories).
    pub fn legacy_files_present(dir: &Path) -> bool {
        Self::idx_dir(dir).is_file() || Self::body_dir(dir).is_file()
    }

    /// Unlink leftover single-file idx/body. Returns true if anything was removed.
    pub fn discard_legacy_files(dir: &Path) -> bool {
        let idx = Self::idx_dir(dir);
        let body = Self::body_dir(dir);
        let mut dropped = false;
        if idx.is_file() {
            let _ = std::fs::remove_file(&idx);
            dropped = true;
        }
        if body.is_file() {
            let _ = std::fs::remove_file(&body);
            dropped = true;
        }
        dropped
    }

    pub fn create(dir: impl AsRef<Path>, origin: Height) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(Self::idx_dir(&dir)).map_err(|e| StoreError::io(&dir, e))?;
        std::fs::create_dir_all(Self::body_dir(&dir)).map_err(|e| StoreError::io(&dir, e))?;
        Self::write_meta(&dir, origin.0)?;
        let seg = Self::create_seg(&dir, 0, 0)?;
        Ok(Self {
            dir,
            origin: origin.0,
            inner: Mutex::new(Inner { segs: vec![seg] }),
        })
    }

    fn write_meta(dir: &Path, origin: u32) -> Result<(), StoreError> {
        let meta = TableFile::create(Self::meta_path(dir), TableKind::ArrayLink)?;
        let mut prefix = [0u8; 8];
        prefix[..4].copy_from_slice(&origin.to_le_bytes());
        prefix[4..8].copy_from_slice(&IDX_FMT_SEG_TIP.to_le_bytes());
        meta.write_at_pwrite(FILE_HEADER_LEN as u64, &prefix)
    }

    fn create_seg(dir: &Path, file_id: u32, first_slot: u64) -> Result<Seg, StoreError> {
        let idx = TableFile::create(Self::seg_idx_path(dir, file_id), TableKind::ArrayLink)?;
        idx.set_grow_tight(true);
        let body = TableFile::create(Self::seg_body_path(dir, file_id), TableKind::SpTweaks)?;
        Ok(Seg {
            file_id,
            first_slot,
            n_slots: 0,
            idx,
            body,
        })
    }

    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        if Self::legacy_files_present(&dir) {
            return Err(StoreError::Corrupt(
                "sp_tweaks: leftover single-file idx/body (schema 17 uses dirs)",
            ));
        }
        if !Self::files_present(&dir) {
            return Err(StoreError::Corrupt("sp_tweaks.idx/ missing meta"));
        }
        let meta = TableFile::open(Self::meta_path(&dir), TableKind::ArrayLink)?;
        if meta.logical_len() < FILE_HEADER_LEN as u64 + 8 {
            return Err(StoreError::Corrupt("sp_tweaks.idx/meta short"));
        }
        let mut prefix = [0u8; 8];
        meta.read_at(FILE_HEADER_LEN as u64, &mut prefix)?;
        let origin = u32::from_le_bytes(prefix[..4].try_into().unwrap());
        let fmt = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
        if fmt != IDX_FMT_SEG_TIP {
            return Err(StoreError::Corrupt("sp_tweaks idx format"));
        }
        let mut segs = Vec::new();
        let mut first_slot = 0u64;
        for file_id in 0u32.. {
            let ip = Self::seg_idx_path(&dir, file_id);
            let bp = Self::seg_body_path(&dir, file_id);
            if !ip.exists() && !bp.exists() {
                break;
            }
            if !ip.exists() || !bp.exists() {
                return Err(StoreError::Corrupt("sp_tweaks incomplete segment"));
            }
            let idx = TableFile::open(&ip, TableKind::ArrayLink)?;
            idx.set_grow_tight(true);
            let body = TableFile::open(&bp, TableKind::SpTweaks)?;
            let extra = idx.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
            if !extra.is_multiple_of(SLOT) {
                return Err(StoreError::Corrupt("sp_tweaks.idx size"));
            }
            let n_slots = extra / SLOT;
            segs.push(Seg {
                file_id,
                first_slot,
                n_slots,
                idx,
                body,
            });
            first_slot = first_slot.saturating_add(n_slots);
        }
        if segs.is_empty() {
            return Err(StoreError::Corrupt("sp_tweaks no segments"));
        }
        Ok(Self {
            dir,
            origin,
            inner: Mutex::new(Inner { segs }),
        })
    }

    /// Open existing dirs, or create empty ones. Leftover single files are dropped.
    pub fn open_or_create(dir: impl AsRef<Path>, origin: Height) -> Result<Self, StoreError> {
        let dir = dir.as_ref();
        if Self::discard_legacy_files(dir) {
            rbitcoin_log::warn!(
                "sp_tweaks: dropped leftover single-file idx/body; recreating origin={}",
                origin.0
            );
        }
        let idx_d = Self::idx_dir(dir);
        let body_d = Self::body_dir(dir);
        match (Self::files_present(dir), idx_d.exists() || body_d.exists()) {
            (true, _) => {
                let t = Self::open(dir)?;
                if t.origin != origin.0 {
                    return Err(StoreError::Corrupt("sp_tweaks origin mismatch"));
                }
                Ok(t)
            }
            (false, false) => {
                rbitcoin_log::info!(
                    "sp_tweaks: creating empty index origin={} dir={}",
                    origin.0,
                    dir.display()
                );
                Self::create(dir, origin)
            }
            (false, true) => {
                rbitcoin_log::warn!("sp_tweaks: incomplete dirs; recreating origin={}", origin.0);
                let _ = std::fs::remove_dir_all(&idx_d);
                let _ = std::fs::remove_dir_all(&body_d);
                Self::create(dir, origin)
            }
        }
    }

    pub fn origin_height(&self) -> Height {
        Height(self.origin)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn slot_count(&self) -> u64 {
        self.lock().segs.iter().map(|s| s.n_slots).sum()
    }

    /// Next height this table will accept (`origin` when empty).
    pub fn next_height(&self) -> Height {
        Height(self.origin.saturating_add(self.slot_count() as u32))
    }

    pub fn body_logical_len(&self) -> u64 {
        self.lock()
            .segs
            .last()
            .map(|s| s.body.logical_len())
            .unwrap_or(FILE_HEADER_LEN as u64)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        for s in self.lock().segs.iter() {
            s.body.flush()?;
            s.idx.flush()?;
        }
        Ok(())
    }

    fn read_off(seg: &Seg, local: u64) -> Result<u32, StoreError> {
        let mut buf = [0u8; SLOT as usize];
        seg.idx
            .read_at(FILE_HEADER_LEN as u64 + local * SLOT, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_offs_run(seg: &Seg, local: u64, n: u64) -> Result<(Vec<u32>, u64), StoreError> {
        if n == 0 {
            return Ok((Vec::new(), 0));
        }
        if local.saturating_add(n) > seg.n_slots {
            return Err(StoreError::Corrupt("sp_tweaks run past segment"));
        }
        let need_next = local + n < seg.n_slots;
        let n_offs = n + u64::from(need_next);
        let mut buf = vec![0u8; (n_offs as usize) * SLOT as usize];
        seg.idx
            .read_at(FILE_HEADER_LEN as u64 + local * SLOT, &mut buf)?;
        let mut starts = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let s = i * SLOT as usize;
            starts.push(u32::from_le_bytes(buf[s..s + 4].try_into().unwrap()));
        }
        let end = if need_next {
            let s = n as usize * SLOT as usize;
            u64::from(u32::from_le_bytes(buf[s..s + 4].try_into().unwrap()))
        } else {
            seg.body.logical_len()
        };
        Ok((starts, end))
    }

    fn locate(inner: &Inner, origin: u32, height: Height) -> Option<(usize, u64)> {
        if height.0 < origin {
            return None;
        }
        let g = u64::from(height.0 - origin);
        for (si, s) in inner.segs.iter().enumerate() {
            if g >= s.first_slot && g < s.first_slot.saturating_add(s.n_slots) {
                return Some((si, g - s.first_slot));
            }
        }
        None
    }

    fn roll(dir: &Path, inner: &mut Inner) -> Result<(), StoreError> {
        let first_slot = inner.segs.iter().map(|s| s.n_slots).sum();
        let file_id = u32::try_from(inner.segs.len())
            .map_err(|_| StoreError::Corrupt("sp_tweaks too many segments"))?;
        inner.segs.push(Self::create_seg(dir, file_id, first_slot)?);
        Ok(())
    }

    /// Encode one tx: `0` or `33 ‖ tweak`.
    pub fn encode_records(records: &[Option<[u8; 33]>]) -> Vec<u8> {
        let mut out = Vec::with_capacity(records.len().saturating_mul(2));
        for r in records {
            match r {
                None => out.push(0),
                Some(t) => {
                    out.push(TWEAK_LEN);
                    out.extend_from_slice(t);
                }
            }
        }
        out
    }

    fn decode_records(bytes: &[u8], n_tx: u32) -> Result<Vec<Option<[u8; 33]>>, StoreError> {
        let mut recs = Vec::with_capacity(n_tx as usize);
        let mut i = 0usize;
        for _ in 0..n_tx {
            if i >= bytes.len() {
                return Err(StoreError::Corrupt("sp_tweaks short body"));
            }
            let len = bytes[i];
            i += 1;
            match len {
                0 => recs.push(None),
                TWEAK_LEN => {
                    if i + 33 > bytes.len() {
                        return Err(StoreError::Corrupt("sp_tweaks short tweak"));
                    }
                    let mut t = [0u8; 33];
                    t.copy_from_slice(&bytes[i..i + 33]);
                    recs.push(Some(t));
                    i += 33;
                }
                _ => return Err(StoreError::Corrupt("sp_tweaks bad len (want 0 or 33)")),
            }
        }
        if i != bytes.len() {
            return Err(StoreError::Corrupt("sp_tweaks n_tx/body mismatch"));
        }
        Ok(recs)
    }

    fn decode_eligible(bytes: &[u8], n_tx: u32) -> Result<Vec<(u32, [u8; 33])>, StoreError> {
        let mut elig = Vec::new();
        let mut i = 0usize;
        for tx_i in 0..n_tx {
            if i >= bytes.len() {
                return Err(StoreError::Corrupt("sp_tweaks short body"));
            }
            let len = bytes[i];
            i += 1;
            match len {
                0 => {}
                TWEAK_LEN => {
                    if i + 33 > bytes.len() {
                        return Err(StoreError::Corrupt("sp_tweaks short tweak"));
                    }
                    let mut t = [0u8; 33];
                    t.copy_from_slice(&bytes[i..i + 33]);
                    elig.push((tx_i, t));
                    i += 33;
                }
                _ => return Err(StoreError::Corrupt("sp_tweaks bad len (want 0 or 33)")),
            }
        }
        if i != bytes.len() {
            return Err(StoreError::Corrupt("sp_tweaks n_tx/body mismatch"));
        }
        Ok(elig)
    }

    fn read_height_bytes_range(
        &self,
        start: Height,
        count: u32,
    ) -> Result<Option<Vec<Vec<u8>>>, StoreError> {
        if count == 0 {
            return Ok(Some(Vec::new()));
        }
        let inner = self.lock();
        let Some((mut si, mut local)) = Self::locate(&inner, self.origin, start) else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(count as usize);
        let mut left = u64::from(count);
        while left > 0 {
            if si >= inner.segs.len() {
                break;
            }
            let seg = &inner.segs[si];
            if local >= seg.n_slots {
                break;
            }
            let run = left.min(seg.n_slots - local);
            let (starts, end) = Self::read_offs_run(seg, local, run)?;
            let body_start = u64::from(*starts.first().unwrap_or(&0));
            if end < body_start {
                return Err(StoreError::Corrupt("sp_tweaks off order"));
            }
            if body_start < FILE_HEADER_LEN as u64 {
                return Err(StoreError::Corrupt("sp_tweaks off in header"));
            }
            let mut blob = vec![0u8; (end - body_start) as usize];
            if !blob.is_empty() {
                seg.body.read_at(body_start, &mut blob)?;
            }
            for i in 0..starts.len() {
                let s = u64::from(starts[i]);
                let e = if i + 1 < starts.len() {
                    u64::from(starts[i + 1])
                } else {
                    end
                };
                if e < s {
                    return Err(StoreError::Corrupt("sp_tweaks off order"));
                }
                let rel = (s - body_start) as usize;
                let len = (e - s) as usize;
                let slice = blob
                    .get(rel..rel.saturating_add(len))
                    .ok_or(StoreError::Corrupt("sp_tweaks range body truncated"))?;
                out.push(slice.to_vec());
            }
            left -= run;
            local += run;
            if local >= seg.n_slots {
                si += 1;
                local = 0;
            }
        }
        Ok(Some(out))
    }

    fn read_height_bytes(&self, height: Height) -> Result<Option<Vec<u8>>, StoreError> {
        match self.read_height_bytes_range(height, 1)? {
            None => Ok(None),
            Some(mut v) => Ok(v.pop()),
        }
    }

    /// Append the next **tip** height. `records.len()` is `header_txs` count.
    pub fn put_block(
        &self,
        height: Height,
        records: &[Option<[u8; 33]>],
    ) -> Result<(), StoreError> {
        self.put_blocks(&[(height, records)])
    }

    /// Append consecutive heights. One body pwrite + one idx pwrite per
    /// segment group (not a pwrite per tx). `items[0].0` must be
    /// [`Self::next_height`].
    ///
    /// Idx `off` is the record **start**. A blob may extend past `u32::MAX`;
    /// when the next start would not fit in `u32`, we roll a new segment.
    pub fn put_blocks(&self, items: &[(Height, &[Option<[u8; 33]>])]) -> Result<(), StoreError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut expect = self.next_height();
        for (h, _) in items {
            if h.0 < self.origin {
                return Err(StoreError::Corrupt("sp_tweaks put below origin"));
            }
            if *h != expect {
                return Err(StoreError::Corrupt("sp_tweaks put not next height"));
            }
            expect = Height(expect.0.saturating_add(1));
        }
        let mut inner = self.lock();
        let mut i = 0usize;
        while i < items.len() {
            let start0 = inner
                .segs
                .last()
                .map(|s| s.body.logical_len())
                .unwrap_or(FILE_HEADER_LEN as u64);
            if start0 > u32::MAX as u64 {
                Self::roll(&self.dir, &mut inner)?;
            }
            let tail = inner
                .segs
                .last_mut()
                .ok_or(StoreError::Corrupt("sp_tweaks no segments"))?;
            let start = tail.body.logical_len();
            if start > u32::MAX as u64 {
                return Err(StoreError::Corrupt("sp_tweaks body exceeds u32 off"));
            }
            let mut body = Vec::new();
            let mut offs: Vec<u32> = Vec::new();
            while i < items.len() {
                let rec_start = start.saturating_add(body.len() as u64);
                if rec_start > u32::MAX as u64 {
                    break;
                }
                offs.push(rec_start as u32);
                body.extend_from_slice(&Self::encode_records(items[i].1));
                i += 1;
            }
            if offs.is_empty() {
                return Err(StoreError::Corrupt("sp_tweaks body exceeds u32 off"));
            }
            if !body.is_empty() {
                tail.body.write_at_pwrite(start, &body)?;
            }
            let mut idx_blob = Vec::with_capacity(offs.len() * SLOT as usize);
            for o in &offs {
                idx_blob.extend_from_slice(&o.to_le_bytes());
            }
            let idx_at = FILE_HEADER_LEN as u64 + tail.n_slots * SLOT;
            if !idx_blob.is_empty() {
                tail.idx.write_at_pwrite(idx_at, &idx_blob)?;
            }
            tail.n_slots = tail.n_slots.saturating_add(offs.len() as u64);
        }
        Ok(())
    }

    /// `None` = not indexed (below origin or past next).
    pub fn get_block(
        &self,
        height: Height,
        n_tx: u32,
    ) -> Result<Option<Vec<Option<[u8; 33]>>>, StoreError> {
        let Some(buf) = self.read_height_bytes(height)? else {
            return Ok(None);
        };
        Ok(Some(Self::decode_records(&buf, n_tx)?))
    }

    /// Eligible tweaks only: `(tx_index_in_block, tweak)`. Not indexed → `None`.
    pub fn get_eligible(
        &self,
        height: Height,
        n_tx: u32,
    ) -> Result<Option<Vec<(u32, [u8; 33])>>, StoreError> {
        match self.get_eligible_range(height, &[n_tx])? {
            None => Ok(None),
            Some(mut v) => Ok(v.pop()),
        }
    }

    /// Contiguous eligible tweaks from `start`. `n_tx[i]` is `header_txs` count
    /// at `start + i`. Missing first height → `None`. Index hole → prefix.
    pub fn get_eligible_range(
        &self,
        start: Height,
        n_tx: &[u32],
    ) -> Result<Option<Vec<Vec<(u32, [u8; 33])>>>, StoreError> {
        let Some(bufs) = self.read_height_bytes_range(start, n_tx.len() as u32)? else {
            return Ok(None);
        };
        let n = bufs.len().min(n_tx.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(Self::decode_eligible(&bufs[i], n_tx[i])?);
        }
        Ok(Some(out))
    }

    /// Drop heights **above** `new_tip` (inclusive keep `origin..=new_tip`).
    pub fn truncate_above(&self, new_tip: Height) -> Result<(), StoreError> {
        let keep = if new_tip.0 < self.origin {
            0
        } else {
            u64::from(new_tip.0 - self.origin + 1)
        };
        self.truncate_keep_slots(keep)
    }

    /// `tip == None` drops every slot (empty chain).
    pub fn truncate_through_tip(&self, tip: Option<Height>) -> Result<(), StoreError> {
        match tip {
            None => self.truncate_keep_slots(0),
            Some(h) => self.truncate_above(h),
        }
    }

    fn truncate_keep_slots(&self, keep: u64) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let total: u64 = inner.segs.iter().map(|s| s.n_slots).sum();
        if keep >= total {
            return Ok(());
        }
        if keep == 0 {
            let first = &mut inner.segs[0];
            first.idx.set_logical_len(FILE_HEADER_LEN as u64)?;
            first.body.set_logical_len(FILE_HEADER_LEN as u64)?;
            first.n_slots = 0;
            first.first_slot = 0;
            let drop: Vec<u32> = inner.segs.iter().skip(1).map(|s| s.file_id).collect();
            inner.segs.truncate(1);
            drop_seg_files(&self.dir, &drop);
            return Ok(());
        }
        let last_keep = keep - 1;
        let Some(si) = inner.segs.iter().position(|s| {
            last_keep >= s.first_slot && last_keep < s.first_slot.saturating_add(s.n_slots)
        }) else {
            return Err(StoreError::Corrupt("sp_tweaks truncate locate"));
        };
        let local_keep = last_keep - inner.segs[si].first_slot + 1;
        if local_keep < inner.segs[si].n_slots {
            let new_body = u64::from(Self::read_off(&inner.segs[si], local_keep)?);
            inner.segs[si]
                .idx
                .set_logical_len(FILE_HEADER_LEN as u64 + local_keep * SLOT)?;
            inner.segs[si]
                .body
                .set_logical_len(new_body.max(FILE_HEADER_LEN as u64))?;
            inner.segs[si].n_slots = local_keep;
        }
        let drop: Vec<u32> = inner.segs.iter().skip(si + 1).map(|s| s.file_id).collect();
        inner.segs.truncate(si + 1);
        drop_seg_files(&self.dir, &drop);
        Ok(())
    }
}

fn drop_seg_files(dir: &Path, ids: &[u32]) {
    for &id in ids {
        let _ = std::fs::remove_file(SpTweaksTable::seg_idx_path(dir, id));
        let _ = std::fs::remove_file(SpTweaksTable::seg_body_path(dir, id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn tmp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-sptweaks-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn set_file_hwm(path: &Path, hwm: u64) {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        f.set_len(hwm.max(FILE_HEADER_LEN as u64)).unwrap();
        let mut hdr = [0u8; FILE_HEADER_LEN];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut hdr).unwrap();
        hdr[8..16].copy_from_slice(&hwm.to_le_bytes());
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&hdr).unwrap();
    }

    #[test]
    fn put_get_len_tweak_no_txid() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut tweak = [0u8; 33];
        tweak[0] = 0x02;
        tweak[32] = 0xab;
        t.put_block(Height(0), &[None, Some(tweak), None]).unwrap();

        let got = t.get_block(Height(0), 3).unwrap().expect("present");
        assert_eq!(got, vec![None, Some(tweak), None]);

        let want = SpTweaksTable::encode_records(&[None, Some(tweak), None]);
        assert_eq!(want.len(), 1 + 1 + 33 + 1);
        assert_eq!(want[0], 0);
        assert_eq!(want[1], 33);
        let raw = fs::read(SpTweaksTable::seg_body_path(&dir, 0)).unwrap();
        let pub_len = t.body_logical_len() as usize;
        assert_eq!(pub_len, FILE_HEADER_LEN + want.len());
        assert_eq!(&raw[FILE_HEADER_LEN..pub_len], want.as_slice());

        // Idx slot is u32 off only (no header_fk).
        let idx = fs::read(SpTweaksTable::seg_idx_path(&dir, 0)).unwrap();
        let idx_hwm = u64::from_le_bytes(idx[8..16].try_into().unwrap()) as usize;
        assert_eq!(idx_hwm, FILE_HEADER_LEN + 4);
        assert_eq!(
            u32::from_le_bytes(
                idx[FILE_HEADER_LEN..FILE_HEADER_LEN + 4]
                    .try_into()
                    .unwrap()
            ),
            FILE_HEADER_LEN as u32
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_blocks_concatenates_consecutive_heights() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut a = [0u8; 33];
        a[0] = 0x02;
        a[32] = 0xaa;
        let mut b = [0u8; 33];
        b[0] = 0x03;
        b[32] = 0xbb;
        t.put_blocks(&[
            (Height(0), &[None, Some(a)] as &[Option<[u8; 33]>]),
            (Height(1), &[None]),
            (Height(2), &[Some(b), None]),
        ])
        .unwrap();

        assert_eq!(t.next_height(), Height(3));
        assert_eq!(
            t.get_block(Height(0), 2).unwrap().unwrap(),
            vec![None, Some(a)]
        );
        assert_eq!(t.get_block(Height(1), 1).unwrap().unwrap(), vec![None]);
        assert_eq!(
            t.get_block(Height(2), 2).unwrap().unwrap(),
            vec![Some(b), None]
        );

        let blob0 = SpTweaksTable::encode_records(&[None, Some(a)]);
        let blob1 = SpTweaksTable::encode_records(&[None]);
        let blob2 = SpTweaksTable::encode_records(&[Some(b), None]);
        let mut want = Vec::new();
        want.extend_from_slice(&blob0);
        want.extend_from_slice(&blob1);
        want.extend_from_slice(&blob2);
        let raw = fs::read(SpTweaksTable::seg_body_path(&dir, 0)).unwrap();
        let pub_len = t.body_logical_len() as usize;
        assert_eq!(pub_len, FILE_HEADER_LEN + want.len());
        assert_eq!(&raw[FILE_HEADER_LEN..pub_len], want.as_slice());

        let idx = fs::read(SpTweaksTable::seg_idx_path(&dir, 0)).unwrap();
        let idx_hwm = u64::from_le_bytes(idx[8..16].try_into().unwrap()) as usize;
        assert_eq!(idx_hwm, FILE_HEADER_LEN + 12);
        let off0 = u32::from_le_bytes(
            idx[FILE_HEADER_LEN..FILE_HEADER_LEN + 4]
                .try_into()
                .unwrap(),
        );
        let off1 = u32::from_le_bytes(
            idx[FILE_HEADER_LEN + 4..FILE_HEADER_LEN + 8]
                .try_into()
                .unwrap(),
        );
        let off2 = u32::from_le_bytes(
            idx[FILE_HEADER_LEN + 8..FILE_HEADER_LEN + 12]
                .try_into()
                .unwrap(),
        );
        assert_eq!(off0, FILE_HEADER_LEN as u32);
        assert_eq!(off1, off0 + blob0.len() as u32);
        assert_eq!(off2, off1 + blob1.len() as u32);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rolls_new_segment_when_next_start_exceeds_u32() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        t.put_block(Height(0), &[None]).unwrap();
        t.flush().unwrap();
        drop(t);

        // Last (only) record lives at u32::MAX; HWM is one past so the next start rolls.
        let body = SpTweaksTable::seg_body_path(&dir, 0);
        let idx = SpTweaksTable::seg_idx_path(&dir, 0);
        let start = u32::MAX;
        set_file_hwm(&body, u64::from(start) + 1);
        {
            let mut f = fs::OpenOptions::new().write(true).open(&body).unwrap();
            f.seek(SeekFrom::Start(u64::from(start))).unwrap();
            f.write_all(&[0u8]).unwrap();
        }
        {
            let mut raw = fs::read(&idx).unwrap();
            raw[FILE_HEADER_LEN..FILE_HEADER_LEN + 4].copy_from_slice(&start.to_le_bytes());
            fs::write(&idx, &raw).unwrap();
        }

        let t = SpTweaksTable::open(&dir).unwrap();
        assert_eq!(t.get_block(Height(0), 1).unwrap().unwrap(), vec![None]);
        t.put_block(Height(1), &[None, None])
            .expect("must roll instead of u32-off Corrupt");
        assert!(SpTweaksTable::seg_body_path(&dir, 1).is_file());
        assert_eq!(
            t.get_block(Height(1), 2).unwrap().unwrap(),
            vec![None, None]
        );
        assert_eq!(t.get_block(Height(0), 1).unwrap().unwrap(), vec![None]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_block_body_may_pass_u32_if_start_fits() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        t.put_block(Height(0), &[None]).unwrap();
        t.flush().unwrap();
        drop(t);

        let body = SpTweaksTable::seg_body_path(&dir, 0);
        let near = u32::MAX - 8;
        set_file_hwm(&body, u64::from(near));
        let t = SpTweaksTable::open(&dir).unwrap();
        let fat: Vec<Option<[u8; 33]>> = vec![None; 32];
        t.put_block(Height(1), &fat)
            .expect("start < 2^32 may extend body past u32::MAX");
        assert!(
            t.body_logical_len() > u32::MAX as u64,
            "this height's blob must be allowed to pass 4 GiB"
        );
        assert_eq!(t.get_block(Height(1), 32).unwrap().unwrap(), fat);
        t.put_block(Height(2), &[None])
            .expect("next start > u32::MAX must roll, not Corrupt");
        assert!(SpTweaksTable::seg_body_path(&dir, 1).is_file());
        assert_eq!(t.get_block(Height(2), 1).unwrap().unwrap(), vec![None]);
        assert_eq!(t.get_block(Height(1), 32).unwrap().unwrap(), fat);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_blocks_rolls_mid_batch_when_next_start_exceeds_u32() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        t.put_block(Height(0), &[None]).unwrap();
        t.flush().unwrap();
        drop(t);

        let body = SpTweaksTable::seg_body_path(&dir, 0);
        let near = u32::MAX - 4;
        set_file_hwm(&body, u64::from(near));
        let t = SpTweaksTable::open(&dir).unwrap();
        let fat: Vec<Option<[u8; 33]>> = vec![None; 20];
        t.put_blocks(&[
            (Height(1), fat.as_slice()),
            (Height(2), &[None] as &[Option<[u8; 33]>]),
            (Height(3), &[None, None]),
        ])
        .expect("mid-batch start past u32 must roll, not Corrupt");
        assert!(SpTweaksTable::seg_body_path(&dir, 1).is_file());
        assert_eq!(t.get_block(Height(1), 20).unwrap().unwrap(), fat);
        assert_eq!(t.get_block(Height(2), 1).unwrap().unwrap(), vec![None]);
        assert_eq!(
            t.get_block(Height(3), 2).unwrap().unwrap(),
            vec![None, None]
        );
        assert_eq!(t.next_height(), Height(4));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reorg_truncates_and_regenerates_tip_height() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut a = [0u8; 33];
        a[0] = 0x02;
        let mut b = [0u8; 33];
        b[0] = 0x03;
        t.put_block(Height(0), &[Some(a)]).unwrap();
        t.put_block(Height(1), &[None, Some(a)]).unwrap();
        t.truncate_above(Height(0)).unwrap();
        assert_eq!(t.next_height(), Height(1));
        assert!(t.get_block(Height(1), 2).unwrap().is_none());
        t.put_block(Height(1), &[Some(b)]).unwrap();
        assert_eq!(t.get_block(Height(1), 1).unwrap().unwrap(), vec![Some(b)]);
        assert_eq!(t.get_eligible(Height(1), 1).unwrap().unwrap(), vec![(0, b)]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_eligible_range_matches_singles_and_stops_on_hole() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut a = [0u8; 33];
        a[0] = 0x02;
        let mut b = [0u8; 33];
        b[0] = 0x03;
        t.put_block(Height(0), &[None, Some(a)]).unwrap();
        t.put_block(Height(1), &[None]).unwrap();
        t.put_block(Height(2), &[Some(b), None]).unwrap();

        let got = t
            .get_eligible_range(Height(0), &[2, 1, 2])
            .unwrap()
            .expect("indexed");
        assert_eq!(
            got,
            vec![
                t.get_eligible(Height(0), 2).unwrap().unwrap(),
                t.get_eligible(Height(1), 1).unwrap().unwrap(),
                t.get_eligible(Height(2), 2).unwrap().unwrap(),
            ]
        );

        assert!(t.get_eligible_range(Height(3), &[1]).unwrap().is_none());
        assert!(t
            .get_eligible_range(Height(0), &[])
            .unwrap()
            .unwrap()
            .is_empty());

        let prefix = t
            .get_eligible_range(Height(2), &[2, 1])
            .unwrap()
            .expect("start indexed");
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0], vec![(0, b)]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hole_vs_empty_eligible() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(10)).unwrap();
        t.put_block(Height(10), &[None, None]).unwrap();
        let empty = t.get_block(Height(10), 2).unwrap().expect("present");
        assert_eq!(empty, vec![None, None]);
        assert!(t.get_block(Height(11), 1).unwrap().is_none());
        assert!(t.get_block(Height(9), 1).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_above_and_reopen() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut a = [0u8; 33];
        a[0] = 0x03;
        t.put_block(Height(0), &[Some(a)]).unwrap();
        t.put_block(Height(1), &[None]).unwrap();
        t.put_block(Height(2), &[None, None]).unwrap();
        assert_eq!(t.next_height(), Height(3));
        t.truncate_above(Height(0)).unwrap();
        assert_eq!(t.next_height(), Height(1));
        assert!(t.get_block(Height(1), 1).unwrap().is_none());
        assert_eq!(t.get_block(Height(0), 1).unwrap().unwrap(), vec![Some(a)]);

        t.flush().unwrap();
        drop(t);
        let t = SpTweaksTable::open(&dir).unwrap();
        assert_eq!(t.origin_height(), Height(0));
        assert_eq!(t.next_height(), Height(1));
        assert_eq!(t.get_block(Height(0), 1).unwrap().unwrap(), vec![Some(a)]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_files_open_or_create_not_corrupt() {
        let dir = tmp_dir();
        let t = SpTweaksTable::open_or_create(&dir, Height(5)).unwrap();
        assert_eq!(t.origin_height(), Height(5));
        assert_eq!(t.slot_count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_or_create_discards_legacy_files() {
        let dir = tmp_dir();
        fs::write(SpTweaksTable::idx_dir(&dir), b"old-idx").unwrap();
        fs::write(SpTweaksTable::body_dir(&dir), b"old-body").unwrap();
        assert!(SpTweaksTable::legacy_files_present(&dir));
        let t = SpTweaksTable::open_or_create(&dir, Height(0)).unwrap();
        assert!(!SpTweaksTable::legacy_files_present(&dir));
        assert!(SpTweaksTable::files_present(&dir));
        t.put_block(Height(0), &[None]).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuse_fat_len() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        t.put_block(Height(0), &[None]).unwrap();
        t.flush().unwrap();
        drop(t);
        let mut raw = fs::read(SpTweaksTable::seg_body_path(&dir, 0)).unwrap();
        raw[FILE_HEADER_LEN] = 32;
        fs::write(SpTweaksTable::seg_body_path(&dir, 0), &raw).unwrap();
        let t = SpTweaksTable::open(&dir).unwrap();
        let err = t.get_block(Height(0), 1).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(m) if m.contains("bad len")),
            "got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_not_next_height_errors() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let err = t.put_block(Height(2), &[None]).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_or_create_repairs_incomplete_and_checks_origin() {
        let dir = tmp_dir();
        fs::create_dir_all(SpTweaksTable::idx_dir(&dir)).unwrap();
        fs::write(SpTweaksTable::idx_dir(&dir).join("partial"), b"x").unwrap();
        let t = SpTweaksTable::open_or_create(&dir, Height(3)).unwrap();
        assert_eq!(t.origin_height(), Height(3));
        drop(t);
        let Err(err) = SpTweaksTable::open_or_create(&dir, Height(9)) else {
            panic!("expected origin mismatch");
        };
        assert!(
            matches!(err, StoreError::Corrupt(m) if m.contains("origin")),
            "{err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_below_origin_and_n_tx_mismatch() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(5)).unwrap();
        assert!(matches!(
            t.put_block(Height(4), &[None]),
            Err(StoreError::Corrupt(_))
        ));
        t.put_block(Height(5), &[None]).unwrap();
        let err = t.get_block(Height(5), 2).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        t.truncate_through_tip(None).unwrap();
        assert_eq!(t.slot_count(), 0);
        t.truncate_above(Height(99)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_short_tweak_and_n_tx_mismatch() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        let mut tw = [0u8; 33];
        tw[0] = 0x02;
        t.put_block(Height(0), &[Some(tw)]).unwrap();
        t.flush().unwrap();
        drop(t);
        let p = SpTweaksTable::seg_body_path(&dir, 0);
        let mut raw = fs::read(&p).unwrap();
        raw.truncate(FILE_HEADER_LEN + 1 + 8);
        fs::write(&p, &raw).unwrap();
        let t = SpTweaksTable::open(&dir).unwrap();
        let err = t.get_block(Height(0), 1).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_two_heights_uses_next_slot_off() {
        let dir = tmp_dir();
        let t = SpTweaksTable::create(&dir, Height(0)).unwrap();
        t.put_block(Height(0), &[None]).unwrap();
        t.put_block(Height(1), &[None, None]).unwrap();
        assert_eq!(t.get_block(Height(0), 1).unwrap().unwrap(), vec![None]);
        assert_eq!(
            t.get_block(Height(1), 2).unwrap().unwrap(),
            vec![None, None]
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
