use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::hashhead::{initial_slots_for, HashHead, HeadScale};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use rbitcoin_primitives::{Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

pub const HEADER_HEAD_DIR_REFUSE: &str =
    "header.head is a shard directory; wipe header.head and header.body and reindex";

pub const HEADER_HEAD_EMPTY_REFUSE: &str =
    "header.head is empty at target slots; wipe header.head, header.head.mlt, and header.body and reindex";

/// Fixed-size header body record (88 bytes). See SCHEMA.md.
pub const HEADER_RECORD_LEN: usize = 88;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRecord {
    pub prev_fk: Fk,
    pub version: i32,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    pub merkle_root: [u8; 32],
    pub hash: [u8; 32],
}

impl HeaderRecord {
    pub fn encode(&self) -> [u8; HEADER_RECORD_LEN] {
        let mut out = [0u8; HEADER_RECORD_LEN];
        out[0..8].copy_from_slice(&self.prev_fk.0.to_le_bytes());
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..20].copy_from_slice(&self.bits.to_le_bytes());
        out[20..24].copy_from_slice(&self.nonce.to_le_bytes());
        out[24..56].copy_from_slice(&self.merkle_root);
        out[56..88].copy_from_slice(&self.hash);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        if buf.len() < HEADER_RECORD_LEN {
            return Err(StoreError::Corrupt("short header record"));
        }
        Ok(Self {
            prev_fk: Fk(u64::from_le_bytes(buf[0..8].try_into().unwrap())),
            version: i32::from_le_bytes(buf[8..12].try_into().unwrap()),
            timestamp: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            bits: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            nonce: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            merkle_root: buf[24..56].try_into().unwrap(),
            hash: buf[56..88].try_into().unwrap(),
        })
    }
}

/// Double-SHA256 of a bitcoin block header (80 bytes), internal byte order.
pub fn block_header_hash(
    version: i32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    nonce: u32,
) -> [u8; 32] {
    let mut ser = [0u8; 80];
    ser[0..4].copy_from_slice(&version.to_le_bytes());
    ser[4..36].copy_from_slice(prev_hash);
    ser[36..68].copy_from_slice(merkle_root);
    ser[68..72].copy_from_slice(&timestamp.to_le_bytes());
    ser[72..76].copy_from_slice(&bits.to_le_bytes());
    ser[76..80].copy_from_slice(&nonce.to_le_bytes());
    let mut eng = sha256::HashEngine::default();
    eng.input(&ser);
    let mid = sha256::Hash::from_engine(eng);
    let mut eng2 = sha256::HashEngine::default();
    eng2.input(mid.as_byte_array());
    sha256::Hash::from_engine(eng2).to_byte_array()
}

/// `header.head` plus overflow gens `header.head.g1`, `header.head.g2`, …
struct HeaderHead {
    base: PathBuf,
    target_slots: u64,
    gens: RwLock<Vec<HashHead>>,
}

fn header_gen_path(base: &Path, i: usize) -> PathBuf {
    if i == 0 {
        return base.to_path_buf();
    }
    let mut p = base.as_os_str().to_os_string();
    p.push(format!(".g{i}"));
    PathBuf::from(p)
}

impl HeaderHead {
    fn create(base: PathBuf, scale: HeadScale) -> Result<Self, StoreError> {
        let target_slots = initial_slots_for(scale);
        let h = HashHead::create_with_slots(&base, target_slots)?;
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(vec![h]),
        })
    }

    fn open(base: PathBuf, body_count: u64, scale: HeadScale) -> Result<Self, StoreError> {
        if base.is_dir() {
            return Err(StoreError::Layout(HEADER_HEAD_DIR_REFUSE.to_string()));
        }
        if !base.is_file() {
            return Err(StoreError::io(
                &base,
                std::io::Error::new(std::io::ErrorKind::NotFound, "header.head missing"),
            ));
        }
        crate::hashhead::discard_grow_part(&base);
        let target_slots = initial_slots_for(scale);
        let mut gens = vec![HashHead::open(&base)?];
        let mut i = 1usize;
        loop {
            let p = header_gen_path(&base, i);
            if !p.is_file() {
                break;
            }
            gens.push(HashHead::open(p)?);
            i += 1;
        }
        if gens.len() == 1 && gens[0].slots() < target_slots {
            let g = gens.remove(0);
            gens.push(g.rewrite_to_slots(target_slots)?);
        } else if gens.len() == 1
            && gens[0].slots() >= target_slots
            && gens[0].occupied() == 0
            && (body_count > 0 || gens[0].multi_count() > 0)
        {
            return Err(StoreError::Layout(HEADER_HEAD_EMPTY_REFUSE.to_string()));
        }
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(gens),
        })
    }

    fn get_all(&self, key: &[u8; 32]) -> Result<Vec<Fk>, StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for h in gens.iter().rev() {
            out.extend(h.get_all(key)?);
        }
        Ok(out)
    }

    fn insert_many(&self, entries: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        let mut rest: Vec<([u8; 32], Fk)> = entries.to_vec();
        while !rest.is_empty() {
            let leftover = {
                let last = {
                    let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                    gens.len().saturating_sub(1)
                };
                let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                gens[last].insert_many_file(&rest, |_| {})?
            };
            if leftover.is_empty() {
                return Ok(());
            }
            self.roll()?;
            rest = leftover;
        }
        Ok(())
    }

    fn roll(&self) -> Result<(), StoreError> {
        let mut gens = self.gens.write().unwrap_or_else(|e| e.into_inner());
        // Another ensure may have rolled while we dropped the read lock.
        if gens.last().is_some_and(|h| !h.at_load_cap()) {
            return Ok(());
        }
        let i = gens.len();
        let p = header_gen_path(&self.base, i);
        gens.push(HashHead::create_with_slots(p, self.target_slots)?);
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush()?;
        }
        Ok(())
    }

    fn flush_async(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush_async()?;
        }
        Ok(())
    }
}

pub struct HeaderTable {
    body: TableFile,
    head: HeaderHead,
    count: std::sync::atomic::AtomicU64,
    /// Serializes check-then-put so two threads cannot both miss and both append
    /// the same full hash (I1 + I4).
    put_lock: Mutex<()>,
}

impl HeaderTable {
    pub fn create(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn create_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Tiny)
    }

    pub fn create_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        let body = TableFile::create(dir.join("header.body"), TableKind::Header)?;
        let head = HeaderHead::create(dir.join("header.head"), scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(0),
            put_lock: Mutex::new(()),
        })
    }

    pub fn open(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn open_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Tiny)
    }

    pub fn open_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        let body = TableFile::open(dir.join("header.body"), TableKind::Header)?;
        let body_len = body.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len % HEADER_RECORD_LEN as u64 != 0 {
            return Err(StoreError::Corrupt("header body size"));
        }
        let count = body_len / HEADER_RECORD_LEN as u64;
        let head = HeaderHead::open(dir.join("header.head"), count, scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(count),
            put_lock: Mutex::new(()),
        })
    }

    pub fn head_target_slots(&self) -> u64 {
        self.head.target_slots
    }

    /// Write gate: at most one body row per full block hash (I1).
    ///
    /// - If `hash` already exists → return that fk (ignore caller's `prev_fk`).
    /// - Else if `prev_fk` is non-null → parent must exist and
    ///   `hash` must equal SHA256D(header fields with parent.hash as prev) (I2/I3).
    /// - Else (`prev_fk` null) → append as-is (genesis / synthetic test rows).
    ///
    /// Lookup + insert hold [`Self::put_lock`] (I4).
    pub fn ensure(&self, rec: &HeaderRecord) -> Result<Fk, StoreError> {
        let mut fks = self.ensure_batch(std::slice::from_ref(rec))?;
        fks.pop().ok_or(StoreError::Corrupt("ensure_batch empty"))
    }

    /// Batch [`Self::ensure`]: one `put_lock`, one `header.body` write, chunked head insert.
    ///
    /// Output fks align with `recs`. Duplicate hashes in the batch share one body row.
    pub fn ensure_batch(&self, recs: &[HeaderRecord]) -> Result<Vec<Fk>, StoreError> {
        use std::sync::atomic::Ordering;
        if recs.is_empty() {
            return Ok(Vec::new());
        }
        let _g = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(recs.len());
        let mut fresh: Vec<(Fk, HeaderRecord)> = Vec::new();
        let mut seen: Vec<([u8; 32], Fk)> = Vec::new();
        let mut next = self.count.load(Ordering::Acquire);
        for rec in recs {
            if let Some((_, fk)) = seen.iter().rev().find(|(h, _)| *h == rec.hash) {
                out.push(*fk);
                continue;
            }
            if let Some((fk, _)) = self.get_by_hash_unlocked(&rec.hash)? {
                seen.push((rec.hash, fk));
                out.push(fk);
                continue;
            }
            if !rec.prev_fk.is_null() {
                let parent = self.parent_for_batch(rec.prev_fk, &fresh)?;
                Self::check_parent_edge(rec, &parent)?;
            }
            next = next.saturating_add(1);
            let fk = Fk(next);
            let mut stored = rec.clone();
            stored.prev_fk = rec.prev_fk;
            fresh.push((fk, stored));
            seen.push((rec.hash, fk));
            out.push(fk);
        }
        if fresh.is_empty() {
            return Ok(out);
        }
        let base = self.count.load(Ordering::Acquire);
        let offset = FILE_HEADER_LEN as u64 + base * HEADER_RECORD_LEN as u64;
        let mut blob = Vec::with_capacity(fresh.len().saturating_mul(HEADER_RECORD_LEN));
        let mut head_entries: Vec<([u8; 32], Fk)> = Vec::with_capacity(fresh.len());
        for (fk, rec) in &fresh {
            blob.extend_from_slice(&rec.encode());
            head_entries.push((rec.hash, *fk));
        }
        self.body.write_at(offset, &blob)?;
        self.count
            .store(base.saturating_add(fresh.len() as u64), Ordering::Release);
        self.head.insert_many(&head_entries)?;
        Ok(out)
    }

    fn parent_for_batch(
        &self,
        prev_fk: Fk,
        fresh: &[(Fk, HeaderRecord)],
    ) -> Result<HeaderRecord, StoreError> {
        if let Some((_, rec)) = fresh.iter().rev().find(|(fk, _)| *fk == prev_fk) {
            return Ok(rec.clone());
        }
        self.get(prev_fk)
    }

    fn check_parent_edge(rec: &HeaderRecord, parent: &HeaderRecord) -> Result<(), StoreError> {
        let expect = block_header_hash(
            rec.version,
            &parent.hash,
            &rec.merkle_root,
            rec.timestamp,
            rec.bits,
            rec.nonce,
        );
        if expect != rec.hash {
            return Err(StoreError::Corrupt(
                "header prev_fk does not match block hash (false parent edge)",
            ));
        }
        Ok(())
    }

    pub fn get(&self, fk: Fk) -> Result<HeaderRecord, StoreError> {
        use std::sync::atomic::Ordering;
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let count = self.count.load(Ordering::Acquire);
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let offset = FILE_HEADER_LEN as u64 + (id - 1) * HEADER_RECORD_LEN as u64;
        let mut buf = [0u8; HEADER_RECORD_LEN];
        self.body.read_at(offset, &mut buf)?;
        HeaderRecord::decode(&buf)
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // Head reads are safe without put_lock (body append-only; head multi-list
        // is append-oriented). Callers that check-then-put must use ensure.
        self.get_by_hash_unlocked(hash)
    }

    fn get_by_hash_unlocked(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // 16-byte head prefix may collide — verify full hash on the body.
        for fk in self.head.get_all(hash)? {
            let rec = self.get(fk)?;
            if rec.hash == *hash {
                return Ok(Some((fk, rec)));
            }
        }
        Ok(None)
    }

    /// Number of header rows currently stored (highest fk = this value).
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        self.head.flush()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        self.head.flush_async()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-header-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample(hash: [u8; 32]) -> HeaderRecord {
        HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 100,
            bits: 0x1d00ffff,
            nonce: 7,
            merkle_root: [2u8; 32],
            hash,
        }
    }

    #[test]
    fn header_put_get_by_hash_open_flush() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let fk1 = t.ensure(&sample(h1)).unwrap();
        let fk2 = t.ensure(&sample(h2)).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(fk1).unwrap().hash, h1);
        assert_eq!(t.get(fk2).unwrap().hash, h2);
        assert_eq!(t.get_by_hash(&h1).unwrap().unwrap().0, fk1);
        assert!(t.get_by_hash(&[9u8; 32]).unwrap().is_none());
        assert!(matches!(t.get(Fk::NULL), Err(StoreError::InvalidFk)));
        assert!(matches!(t.get(Fk(99)), Err(StoreError::NotFound)));
        // short decode
        assert!(matches!(
            HeaderRecord::decode(&[0u8; 10]),
            Err(StoreError::Corrupt(_))
        ));
        t.flush().unwrap();
        t.flush_async().unwrap();
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get_by_hash(&h2).unwrap().unwrap().1.nonce, 7);
        // Shrink OS file below HWM so open clamps logical to a non-record size.
        {
            use crate::file::FILE_HEADER_LEN;
            let body = dir.join("header.body");
            std::fs::OpenOptions::new()
                .write(true)
                .open(&body)
                .unwrap()
                .set_len((FILE_HEADER_LEN + 3) as u64)
                .unwrap();
        }
        assert!(matches!(
            HeaderTable::open_tiny(&dir),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real block-header fields with PoW-style hash committed to a real parent.
    fn linked_child(parent: &HeaderRecord, parent_fk: Fk, salt: u32) -> HeaderRecord {
        let version = 1;
        let timestamp = 1_700_000_000 + salt;
        let bits = 0x207fffff;
        let nonce = salt;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&salt.to_le_bytes());
        let hash = block_header_hash(version, &parent.hash, &merkle, timestamp, bits, nonce);
        HeaderRecord {
            prev_fk: parent_fk,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        }
    }

    #[test]
    fn ensure_batch_linked_headers_roundtrip() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x10; 32]);
        let a = linked_child(&g, Fk(1), 1);
        let b = linked_child(&a, Fk(2), 2);
        let fks = t.ensure_batch(&[g.clone(), a.clone(), b.clone()]).unwrap();
        assert_eq!(fks, vec![Fk(1), Fk(2), Fk(3)]);
        assert_eq!(t.count(), 3);
        assert_eq!(t.get_by_hash(&g.hash).unwrap().unwrap().0, Fk(1));
        assert_eq!(t.get_by_hash(&b.hash).unwrap().unwrap().0, Fk(3));
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), 3);
        assert_eq!(t.get_by_hash(&a.hash).unwrap().unwrap().1.nonce, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_duplicate_hash_is_one_row() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x21; 32]);
        let fks = t.ensure_batch(&[g.clone(), g.clone()]).unwrap();
        assert_eq!(fks[0], fks[1]);
        assert_eq!(t.count(), 1);
        let again = t.ensure_batch(&[g]).unwrap();
        assert_eq!(again[0], fks[0]);
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_false_parent_writes_nothing() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x31; 32]);
        let a = linked_child(&g, Fk(1), 1);
        let honest = linked_child(&a, Fk(2), 2);
        let mut lying = honest.clone();
        lying.prev_fk = Fk(1);
        let err = t.ensure_batch(&[g.clone(), a.clone(), lying]).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(_)),
            "false parent edge must be rejected, got {err}"
        );
        assert_eq!(t.count(), 0, "failed batch must not append");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_parent_in_batch_assigns_prev_fk() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x41; 32]);
        let a = linked_child(&g, Fk(1), 7);
        let fks = t.ensure_batch(&[g, a.clone()]).unwrap();
        assert_eq!(fks, vec![Fk(1), Fk(2)]);
        assert_eq!(t.get(Fk(2)).unwrap().prev_fk, Fk(1));
        assert_eq!(t.get(Fk(2)).unwrap().hash, a.hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Production failure shape: same full hash as an older block, but `prev_fk`
    /// points at a tip-extension header. Without the write gate this plants a
    /// false child edge that resume walks as "headers past tip".
    #[test]
    fn ensure_rejects_duplicate_hash_with_divergent_prev_and_false_parent_edge() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();

        // G (null prev, synthetic hash) → A → B → C (real linked hashes).
        let g = sample([0x11; 32]);
        let g_fk = t.ensure(&g).unwrap();
        let a = linked_child(&g, g_fk, 1);
        let a_fk = t.ensure(&a).unwrap();
        let b = linked_child(&a, a_fk, 2);
        let b_fk = t.ensure(&b).unwrap();
        let c = linked_child(&b, b_fk, 3);
        let c_fk = t.ensure(&c).unwrap();
        assert_eq!(t.count(), 4);

        // Poison: re-insert G's identity with prev_fk = C (false parent).
        let mut poison = g.clone();
        poison.prev_fk = c_fk;
        // Same hash as G; gate must return G's fk and not append.
        let again = t.ensure(&poison).unwrap();
        assert_eq!(again, g_fk, "same hash must not create a second row");
        assert_eq!(t.count(), 4, "duplicate hash must not grow the table");
        assert_eq!(t.get(g_fk).unwrap().prev_fk, Fk::NULL);

        // First-time insert of a header whose hash commits to A as parent, but
        // caller lies with prev_fk = C → corrupt (false parent edge).
        let honest = linked_child(&a, a_fk, 99);
        let mut lying = honest.clone();
        lying.prev_fk = c_fk;
        let err = t.ensure(&lying).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(_)),
            "false parent edge must be rejected at write gate, got {err}"
        );
        assert_eq!(t.count(), 4);

        // Honest insert still works.
        let ok = t.ensure(&honest).unwrap();
        assert_eq!(t.count(), 5);
        assert_eq!(t.get(ok).unwrap().prev_fk, a_fk);

        // Children of C: only what truly points at C (none of the poisons).
        let mut kids_of_c = 0u32;
        for id in 1..=t.count() {
            let rec = t.get(Fk(id)).unwrap();
            if rec.prev_fk == c_fk {
                kids_of_c += 1;
            }
        }
        assert_eq!(
            kids_of_c, 0,
            "C must not gain false children from poison puts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_rolls_generation_when_gen0_is_full() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let mut hashes = Vec::new();
        for i in 0u32..80 {
            let mut hash = [0u8; 32];
            hash[0..4].copy_from_slice(&i.to_le_bytes());
            hash[4] = 0xa5;
            hashes.push(hash);
            t.ensure(&sample(hash)).unwrap();
        }
        assert!(
            dir.join("header.head.g1").is_file(),
            "tiny 64-slot gen0 must roll header.head.g1"
        );
        assert!(dir.join("header.head").is_file());
        let first = t.get_by_hash(&hashes[0]).unwrap().unwrap();
        let last = t.get_by_hash(&hashes[79]).unwrap().unwrap();
        assert_eq!(first.1.hash, hashes[0]);
        assert_eq!(last.1.hash, hashes[79]);
        assert_eq!(t.ensure(&sample(hashes[0])).unwrap(), first.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_rolls_generation_when_gen0_is_full() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let recs: Vec<HeaderRecord> = (0u32..80)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..4].copy_from_slice(&i.to_le_bytes());
                hash[4] = 0xa5;
                sample(hash)
            })
            .collect();
        let fks = t.ensure_batch(&recs).unwrap();
        assert_eq!(fks.len(), 80);
        assert_eq!(t.count(), 80);
        assert!(
            dir.join("header.head.g1").is_file(),
            "tiny 64-slot gen0 must roll header.head.g1"
        );
        assert_eq!(t.get_by_hash(&recs[0].hash).unwrap().unwrap().0, Fk(1));
        assert_eq!(t.get_by_hash(&recs[79].hash).unwrap().unwrap().0, Fk(80));
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(
            t.get_by_hash(&recs[40].hash).unwrap().unwrap().1.hash,
            recs[40].hash
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_open_grows_undersized_single_gen() {
        let dir = tmp();
        let hashes: Vec<[u8; 32]> = (0u32..5)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&i.to_le_bytes());
                h[8] = 0x3c;
                h
            })
            .collect();
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            for (i, hash) in hashes.iter().enumerate() {
                let rec = sample(*hash);
                let off = FILE_HEADER_LEN as u64 + (i as u64) * HEADER_RECORD_LEN as u64;
                body.write_at(off, &rec.encode()).unwrap();
            }
            body.set_logical_len(FILE_HEADER_LEN as u64 + 5 * HEADER_RECORD_LEN as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 32).unwrap();
            for (i, hash) in hashes.iter().enumerate() {
                h.insert(hash, Fk(i as u64 + 1)).unwrap();
            }
            h.flush().unwrap();
            assert_eq!(h.slots(), 32);
        }
        #[cfg(unix)]
        let old = std::fs::File::open(dir.join("header.head")).unwrap();
        #[cfg(unix)]
        let old_ino = {
            use std::os::unix::fs::MetadataExt;
            old.metadata().unwrap().ino()
        };
        let t = HeaderTable::open_tiny(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(dir.join("header.head")).unwrap().ino(),
                old_ino,
                "HeaderTable::open must replace undersized header.head, not punch it"
            );
            drop(old);
        }
        for hash in &hashes {
            assert_eq!(t.get_by_hash(hash).unwrap().unwrap().1.hash, *hash);
        }
        for i in 5u32..40 {
            let mut hash = [0u8; 32];
            hash[0..4].copy_from_slice(&i.to_le_bytes());
            hash[8] = 0x3c;
            t.ensure(&sample(hash)).unwrap();
        }
        assert!(
            !dir.join("header.head.g1").is_file(),
            "open-grow to 64 slots must absorb 40 headers without rolling"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_empty_target_sized_gen0_with_body_is_layout_refuse() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        t.ensure(&sample([0x44; 32])).unwrap();
        t.flush().unwrap();
        drop(t);
        std::fs::remove_file(dir.join("header.head")).unwrap();
        let slots = initial_slots_for(HeadScale::Tiny);
        let staging = tmp();
        let h = HashHead::create_with_slots(staging.join("header.head"), slots).unwrap();
        h.flush().unwrap();
        drop(h);
        std::fs::rename(staging.join("header.head"), dir.join("header.head")).unwrap();
        let _ = std::fs::remove_dir_all(&staging);
        let err = match HeaderTable::open_tiny(&dir) {
            Err(e) => e,
            Ok(_) => panic!("expected Layout refuse for empty target-sized header.head"),
        };
        match err {
            StoreError::Layout(m) => {
                assert!(m.contains("header.head"), "{m}");
                assert!(m.contains("header.body"), "{m}");
                assert!(m.contains("header.head.mlt"), "{m}");
            }
            other => panic!("expected Layout, got {other}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_directory_is_layout_refuse() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        drop(t);
        let head = dir.join("header.head");
        std::fs::remove_file(&head).unwrap();
        std::fs::create_dir(&head).unwrap();
        std::fs::write(head.join("00"), b"x").unwrap();
        std::fs::write(head.join("01"), b"y").unwrap();
        let err = match HeaderTable::open_tiny(&dir) {
            Err(e) => e,
            Ok(_) => panic!("expected Layout refuse for sharded header.head dir"),
        };
        match err {
            StoreError::Layout(m) => {
                assert!(m.contains("header.head"), "{m}");
            }
            other => panic!("expected Layout, got {other}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_same_hash_twice_is_idempotent() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let h = sample([7u8; 32]);
        let fk1 = t.ensure(&h).unwrap();
        let mut h2 = h.clone();
        h2.prev_fk = Fk(999); // divergent prev ignored on hit
        let fk2 = t.ensure(&h2).unwrap();
        assert_eq!(fk1, fk2);
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
