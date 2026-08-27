//! Shared leftover-run dir helpers (SEAL + discard). Not a catalog spill path.

use rbitcoin_store::{list_materialize_claims, list_runs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Control plane for leftover `scripthash.runs` discard / SEAL.
///
/// **`runs_io` invariant:** list + delete for this family hold `runs_io` for the
/// full critical section.
pub struct RunControl {
    pub runs_dir: PathBuf,
    /// Serializes leftover-run list / delete.
    pub runs_io: Arc<Mutex<()>>,
}

impl RunControl {
    pub fn open(store_dir: &Path, subdir: &str) -> Self {
        let runs_dir = store_dir.join(subdir);
        let _ = std::fs::create_dir_all(&runs_dir);
        Self {
            runs_dir,
            runs_io: Arc::new(Mutex::new(())),
        }
    }
}

/// On-disk leftover run count under `runs_io`.
///
/// Includes incomplete materialize claims (`*.run.mat`) so tip-entry leftover
/// detection sees crash mid-old-k-way state.
pub fn on_disk_run_count(runs_dir: &Path, runs_io: &Mutex<()>) -> usize {
    let _io = runs_io.lock().unwrap();
    let catalog = list_runs(runs_dir).map(|r| r.len()).unwrap_or(0);
    let claims = list_materialize_claims(runs_dir)
        .map(|r| r.len())
        .unwrap_or(0);
    catalog.saturating_add(claims)
}

/// Snapshot `(runs_dir, runs_io)` from a locked catalog control.
pub fn runs_dir_io(ctrl: &RunControl) -> (PathBuf, Arc<Mutex<()>>) {
    (ctrl.runs_dir.clone(), Arc::clone(&ctrl.runs_io))
}

/// Remove run/mat/merge artifacts under `runs_dir`, **preserving `SEAL`**.
pub fn clear_runs_dir(runs_dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(runs_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == "SEAL" || name == "SEAL.tmp" {
                continue;
            }
            if p.is_dir() {
                let _ = std::fs::remove_dir_all(&p);
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_runs_dir_keeps_seal() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-runctrl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let ctrl = RunControl::open(&dir, "sh.runs");

        let runs = ctrl.runs_dir.clone();
        std::fs::write(runs.join("SEAL"), b"keep").unwrap();
        std::fs::write(runs.join("1.run"), b"x").unwrap();
        std::fs::write(runs.join("junk.tmp"), b"y").unwrap();
        let sub = runs.join("nested");
        let _ = std::fs::create_dir_all(&sub);
        std::fs::write(sub.join("z"), b"z").unwrap();
        clear_runs_dir(&runs);
        assert!(runs.join("SEAL").is_file());
        assert!(!runs.join("1.run").exists());
        assert!(!runs.join("junk.tmp").exists());
        assert!(!sub.exists());

        let (rd, io) = runs_dir_io(&ctrl);
        assert_eq!(rd, runs);
        assert_eq!(on_disk_run_count(&rd, &io), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
