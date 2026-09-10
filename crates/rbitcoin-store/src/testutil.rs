//! Drop-cleaning Tiny fixtures for tests. Not an operator API.
//!
//! Production constructors stay Mainnet (`StoreLayout::single`). Tests that
//! need an on-disk store use [`tiny_store`] / [`TempDir`] instead of rolling
//! `std::env::temp_dir()` + `create_dir_all`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Store;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Unique directory removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> std::io::Result<Self> {
        Self::labeled("tmp")
    }

    pub fn labeled(label: &str) -> std::io::Result<Self> {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let safe: String = label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-{safe}-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for TempDir {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

/// Tiny-head store in a drop-cleaning directory.
pub fn tiny_store() -> (TempDir, Store) {
    tiny_store_labeled("store")
}

pub fn tiny_store_labeled(label: &str) -> (TempDir, Store) {
    let dir = TempDir::labeled(label).expect("create temp dir");
    let store = Store::create_tiny(dir.path()).expect("create tiny store");
    (dir, store)
}
