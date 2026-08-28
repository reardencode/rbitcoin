//! Post-IBD scripthash collect: one Class A pass into unsorted per-shard
//! files, then in-place unique-sort + seal.
//!
//! Direct confirm does **not** enqueue SH. A durable head never enters this
//! path (write-behind / `recover_sh_writebehind` instead). Leftover
//! `scripthash.runs` are discarded, never k-way merged.

use super::run_builder_core::{clear_runs_dir, on_disk_run_count, runs_dir_io, RunControl};
use rbitcoin_log::info;
use rbitcoin_store::{materialize_sh_unsorted_from_class_a, ColdProgress, Store, StoreError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// `RBITCOIN_SH_FORCE_REBUILD=1|true` — full Class A collect + unsorted rematerialize.
pub fn sh_force_rebuild() -> bool {
    matches!(
        std::env::var("RBITCOIN_SH_FORCE_REBUILD")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .ok(),
        Some(true)
    )
}

/// Inclusion floor for a durable SH head.
///
/// Prefer `include_hwm` when present. When the HWM file is missing (legacy
/// datadir / cold finished before the feature), fall back to SEAL — never treat
/// missing HWM as `0` for clamp purposes.
pub fn durable_sh_inclusion_floor(include_hwm: u64, seal: u64) -> u64 {
    if include_hwm > 0 {
        include_hwm
    } else {
        seal
    }
}

fn seal_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join("SEAL")
}

/// Load sealed max create_fk (0 if missing/corrupt).
pub fn load_seal(runs_dir: &Path) -> u64 {
    let path = seal_path(runs_dir);
    let Ok(buf) = std::fs::read(&path) else {
        return 0;
    };
    if buf.len() < 8 {
        return 0;
    }
    u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]))
}

/// Write SEAL (max create_fk) — catch-up clamp / force rebuild / tests.
pub fn store_seal(runs_dir: &Path, max_fk: u64) -> Result<(), StoreError> {
    let path = seal_path(runs_dir);
    let tmp = runs_dir.join("SEAL.tmp");
    std::fs::create_dir_all(runs_dir).map_err(|e| StoreError::io(runs_dir, e))?;
    std::fs::write(&tmp, max_fk.to_le_bytes()).map_err(|e| StoreError::io(&tmp, e))?;
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| StoreError::io(&path, e))?;
    Ok(())
}

struct Inner {
    ctrl: RunControl,
}

/// Post-IBD SH SEAL + leftover-run discard; unsorted collect/pack is the materialize.
pub struct ShRunBuilder {
    inner: Arc<Mutex<Inner>>,
    sealed_fk: Arc<AtomicU64>,
    runs_dir: PathBuf,
}

impl ShRunBuilder {
    pub fn new(store_dir: &Path) -> Self {
        let ctrl = RunControl::open(store_dir, "scripthash.runs");
        let runs_dir = ctrl.runs_dir.clone();
        let sealed = load_seal(&runs_dir);
        Self {
            inner: Arc::new(Mutex::new(Inner { ctrl })),
            sealed_fk: Arc::new(AtomicU64::new(sealed)),
            runs_dir,
        }
    }

    /// Historical IBD SH run worker; always off (Direct does not spill catalog runs).
    pub fn is_enabled(&self) -> bool {
        false
    }

    /// Max create_fk watermark (SEAL).
    pub fn sealed_max_create_fk(&self) -> u64 {
        self.sealed_fk.load(Ordering::Acquire)
    }

    pub fn on_disk_run_count(&self) -> usize {
        let g = self.inner.lock().unwrap();
        let (dir, io) = runs_dir_io(&g.ctrl);
        drop(g);
        on_disk_run_count(&dir, &io)
    }

    /// Reload SEAL from disk into process cache.
    pub fn refresh_seal(&self) {
        let s = load_seal(&self.runs_dir);
        self.sealed_fk.store(s, Ordering::Release);
    }

    /// Drop leftover catalog / `.mat` / merge files. **Keeps `SEAL`**.
    pub fn discard_residual_runs(&self) {
        clear_runs_dir(&self.runs_dir);
        let _ = std::fs::create_dir_all(&self.runs_dir);
    }

    /// Wipe leftover catalog runs + SEAL=0 (does not touch durable SH head).
    fn wipe_catalog_and_seal(&self) -> Result<(), StoreError> {
        clear_runs_dir(&self.runs_dir);
        let _ = std::fs::create_dir_all(&self.runs_dir);
        store_seal(&self.runs_dir, 0)?;
        self.sealed_fk.store(0, Ordering::Release);
        Ok(())
    }

    fn clear_cold_progress_and_hwm(store: &Store) {
        ColdProgress::clear(store.path());
        let hwm_path = store.path().join(rbitcoin_store::INCLUDE_HWM_NAME);
        let _ = std::fs::remove_file(&hwm_path);
    }

    /// Wipe SH runs/SEAL/cold progress/include_hwm and empty durable SH tables.
    ///
    /// Used by `RBITCOIN_SH_FORCE_REBUILD=1` so tip collects **all** Class A.
    pub fn prepare_force_full_rebuild(&self, store: &Store) -> Result<(), StoreError> {
        info!("node: scripthash FORCE_REBUILD — clearing runs/SEAL/progress/HWM and reinit head");
        self.wipe_catalog_and_seal()?;
        Self::clear_cold_progress_and_hwm(store);
        store.scripthash.reinit_empty_for_cold_materialize()?;
        Ok(())
    }

    /// Publish SEAL watermark (inclusion floor companion to `include_hwm`).
    pub fn publish_seal_watermark(&self, seal: u64) -> Result<(), StoreError> {
        if seal == 0 {
            return Ok(());
        }
        let cur = self.sealed_max_create_fk();
        if seal <= cur {
            return Ok(());
        }
        store_seal(&self.runs_dir, seal)?;
        self.sealed_fk.store(seal, Ordering::Release);
        Ok(())
    }

    /// One Class A pass into unsorted shard files, then in-place unique-sort + seal.
    pub fn finalize_and_unsorted_materialize_cancellable(
        &self,
        store: &Store,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, StoreError> {
        let n_existing = store.scripthash.entry_count();
        let head_empty = store.scripthash.head_is_empty();
        let n_shards = store.scripthash.head_shard_count();
        let unsealed = store.scripthash.unsealed_main_shards();
        if unsealed.is_empty() && (!head_empty || n_existing > 0) {
            info!(
                "node: scripthash unsorted-shards skip (all {n_shards} shards sealed, entry_count={n_existing})"
            );
            self.discard_residual_runs();
            rbitcoin_store::clear_unsorted_shard_dir(&rbitcoin_store::unsorted_shard_dir(
                store.path(),
            ));
            return Ok(0);
        }

        if head_empty && n_existing == 0 {
            self.wipe_catalog_and_seal()?;
        }

        let collect_workers = rbitcoin_store::unsorted_collect_workers();
        let pack_workers = rbitcoin_store::unsorted_pack_workers();
        let free_gib = rbitcoin_store::free_gib_label();
        let tip_max = store.txs.count();
        info!(
            "node: scripthash unsorted-shards start collect_workers={collect_workers} \
             pack_workers={pack_workers} free_GiB={free_gib} n_shards={n_shards} \
             unsealed={} tip_max_fk={tip_max} head_empty={head_empty}",
            unsealed.len(),
        );
        let t0 = Instant::now();
        let mat = match materialize_sh_unsorted_from_class_a(
            store,
            collect_workers,
            pack_workers,
            cancel,
        ) {
            Ok(m) => m,
            Err(StoreError::Cancelled(msg)) => {
                info!(
                    "node: scripthash unsorted-shards cancelled ({msg}); \
                     complete shards kept — restart resumes from DONE"
                );
                return Err(StoreError::Cancelled(msg));
            }
            Err(e) => return Err(e),
        };
        store.scripthash.flush()?;
        self.discard_residual_runs();
        if mat.max_fk > 0 {
            self.publish_seal_watermark(mat.max_fk)?;
            let _ = store.scripthash.note_include_hwm(mat.max_fk);
        }
        info!(
            "node: scripthash unsorted-shards done creates≈{} keys≈{} shards={n_shards} \
             elapsed={:?}",
            mat.creates,
            mat.keys,
            t0.elapsed(),
        );
        Ok(mat.creates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_store::{next_run_path, write_sorted_run, Store};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn durable_sh_inclusion_floor_prefers_hwm() {
        assert_eq!(durable_sh_inclusion_floor(0, 50), 50);
        assert_eq!(durable_sh_inclusion_floor(99, 50), 99);
    }

    #[test]
    fn force_rebuild_resets_seal_and_clears_runs() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-force-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        store_seal(&runs_dir, 1_400_000_000).unwrap();
        b.refresh_seal();
        assert_eq!(b.sealed_max_create_fk(), 1_400_000_000);
        let mut body = Vec::new();
        let mut rec = [0u8; 40];
        rec[..32].fill(0xab);
        rec[32..].copy_from_slice(&99u64.to_le_bytes());
        body.extend_from_slice(&rec);
        write_sorted_run(&next_run_path(&runs_dir, 1), 40, 40, &body).unwrap();
        assert!(b.on_disk_run_count() > 0);

        b.prepare_force_full_rebuild(&store).unwrap();
        assert_eq!(b.sealed_max_create_fk(), 0);
        assert_eq!(b.on_disk_run_count(), 0);
        assert!(store.scripthash.head_is_empty());
        assert_eq!(store.scripthash.entry_count(), 0);
        assert_eq!(store.scripthash.include_hwm(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
