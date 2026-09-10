//! Leftover schema-14 SH overflow helpers.
//!
//! Production incremental creates use ingest OA (`scripthash.ovf/ingest`) and
//! seal to `SHSR` files. This module keeps wipe of legacy `scripthash.ovf.head`.
//! Open of leftover OA segs is refused by `ScriptHashTable`.

use crate::error::StoreError;
use std::path::Path;

/// Directory under the store root for overflow segment files.
pub const OVERFLOW_DIR: &str = "scripthash.ovf";
/// Legacy interim full-size overflow path (wiped on open).
pub const LEGACY_OVERFLOW_HEAD: &str = "scripthash.ovf.head";
/// Legacy placeholder fuse next to single-file ovf (removed with legacy wipe).
pub const LEGACY_OVERFLOW_FUSE: &str = "scripthash.ovf.head.fuse8";

/// Remove interim full-size `scripthash.ovf.head` (+ fuse) so segmented ovf can start clean.
pub fn wipe_legacy_fullsize_overflow(store_dir: &Path) -> Result<(), StoreError> {
    let legacy = store_dir.join(LEGACY_OVERFLOW_HEAD);
    let legacy_fuse = store_dir.join(LEGACY_OVERFLOW_FUSE);
    if legacy.exists() {
        rbitcoin_log::info!(
            "store: removing legacy full-size {} (leftover under {})",
            LEGACY_OVERFLOW_HEAD,
            OVERFLOW_DIR
        );
        if legacy.is_dir() {
            std::fs::remove_dir_all(&legacy).map_err(|e| StoreError::io(&legacy, e))?;
        } else {
            std::fs::remove_file(&legacy).map_err(|e| StoreError::io(&legacy, e))?;
        }
    }
    if legacy_fuse.exists() {
        let _ = std::fs::remove_file(&legacy_fuse);
    }
    Ok(())
}
