//! Multi-spender overflow (`spent.ovf`, schema 17).
//!
//! Common case stores a sole `spending_tx_fk` on the create output. Only when an
//! outpoint has multiple annotated spenders do we allocate nodes here.
//!
//! Fixed 16 B records (1-based fk): `spending_tx_fk:u64 | next:u64`.

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use rbitcoin_primitives::{Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const SPENDER_RECORD_LEN: usize = 16;
/// Multi-spender overflow next to `spent.body` (schema 17).
pub const SPENT_OVF_NAME: &str = "spent.ovf";
const LEGACY_SPENDERS_BODY: &str = "spenders.body";

pub struct SpenderTable {
    body: TableFile,
    count: AtomicU64,
}

fn spent_ovf_path(dir: &Path) -> Result<std::path::PathBuf, StoreError> {
    let ovf = dir.join(SPENT_OVF_NAME);
    let legacy = dir.join(LEGACY_SPENDERS_BODY);
    match (ovf.exists(), legacy.exists()) {
        (true, true) => {
            eprintln!(
                "store: dropping leftover {LEGACY_SPENDERS_BODY} (schema 17 uses {SPENT_OVF_NAME})"
            );
            let _ = std::fs::remove_file(&legacy);
        }
        (false, true) => {
            eprintln!("store: renaming {LEGACY_SPENDERS_BODY} → {SPENT_OVF_NAME}");
            std::fs::rename(&legacy, &ovf).map_err(|e| StoreError::io(&legacy, e))?;
        }
        _ => {}
    }
    Ok(ovf)
}

impl SpenderTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        let body = TableFile::create(dir.join(SPENT_OVF_NAME), TableKind::Spender)?;
        Ok(Self {
            body,
            count: AtomicU64::new(0),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let path = spent_ovf_path(dir)?;
        if !path.exists() {
            return Self::create(dir);
        }
        let body = TableFile::open(path, TableKind::Spender)?;
        let body_len = body.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len % SPENDER_RECORD_LEN as u64 != 0 {
            return Err(StoreError::Corrupt("spenders body size"));
        }
        let count = body_len / SPENDER_RECORD_LEN as u64;
        Ok(Self {
            body,
            count: AtomicU64::new(count),
        })
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    fn offset(id: u64) -> u64 {
        FILE_HEADER_LEN as u64 + (id - 1) * SPENDER_RECORD_LEN as u64
    }

    /// Append one list node. Returns its fk.
    pub fn append(&self, spending_tx_fk: Fk, next: Fk) -> Result<Fk, StoreError> {
        if spending_tx_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        // Single annotator role: load → write → publish count.
        let id = self.count.load(Ordering::Acquire) + 1;
        let mut buf = [0u8; SPENDER_RECORD_LEN];
        buf[0..8].copy_from_slice(&spending_tx_fk.0.to_le_bytes());
        buf[8..16].copy_from_slice(&next.0.to_le_bytes());
        self.body.write_at(Self::offset(id), &buf)?;
        self.count.store(id, Ordering::Release);
        Ok(Fk(id))
    }

    pub fn get(&self, fk: Fk) -> Result<(Fk, Fk), StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let count = self.count.load(Ordering::Acquire);
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let mut buf = [0u8; SPENDER_RECORD_LEN];
        self.body.read_at(Self::offset(id), &mut buf)?;
        Ok((
            Fk(u64::from_le_bytes(buf[0..8].try_into().unwrap())),
            Fk(u64::from_le_bytes(buf[8..16].try_into().unwrap())),
        ))
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_get_chain() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-spender-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = SpenderTable::create(&dir).unwrap();
        assert!(dir.join("spent.ovf").exists(), "schema 17 name");
        assert!(
            !dir.join("spenders.body").exists(),
            "legacy filename must not be created"
        );
        let a = t.append(Fk(10), Fk::NULL).unwrap();
        let b = t.append(Fk(11), a).unwrap();
        assert_eq!(t.get(a).unwrap(), (Fk(10), Fk::NULL));
        assert_eq!(t.get(b).unwrap(), (Fk(11), a));
        assert_eq!(t.count(), 2);
        assert!(matches!(
            t.append(Fk::NULL, Fk::NULL),
            Err(StoreError::InvalidFk)
        ));
        assert!(matches!(t.get(Fk::NULL), Err(StoreError::InvalidFk)));
        assert!(matches!(t.get(Fk(99)), Err(StoreError::NotFound)));
        t.flush().unwrap();
        t.flush_async().unwrap();
        drop(t);
        // open existing
        let t = SpenderTable::open(&dir).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(a).unwrap(), (Fk(10), Fk::NULL));
        // open creates when body missing
        let dir2 = dir.with_extension("empty");
        let _ = std::fs::remove_dir_all(&dir2);
        std::fs::create_dir_all(&dir2).unwrap();
        let t2 = SpenderTable::open(&dir2).unwrap();
        assert_eq!(t2.count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn open_rejects_bad_body_size() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-spender-bad-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = SpenderTable::create(&dir).unwrap();
        t.append(Fk(1), Fk::NULL).unwrap();
        drop(t);
        // Shrink below HWM so open clamps logical_len to a non-multiple of 16.
        let body = dir.join("spent.ovf");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&body)
            .unwrap()
            .set_len((FILE_HEADER_LEN + 3) as u64)
            .unwrap();
        assert!(matches!(
            SpenderTable::open(&dir),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_renames_leftover_spenders_body_to_spent_ovf() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-spender-legacy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let t = SpenderTable::create(&dir).unwrap();
            t.append(Fk(7), Fk::NULL).unwrap();
            t.flush().unwrap();
        }
        std::fs::rename(dir.join("spent.ovf"), dir.join("spenders.body")).unwrap();
        assert!(!dir.join("spent.ovf").exists());
        let t = SpenderTable::open(&dir).unwrap();
        assert!(dir.join("spent.ovf").exists());
        assert!(!dir.join("spenders.body").exists());
        assert_eq!(t.count(), 1);
        assert_eq!(t.get(Fk(1)).unwrap(), (Fk(7), Fk::NULL));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
