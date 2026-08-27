//! Post-IBD scripthash collect: Class A recollect → catalog runs → FullCold / ColdResume.
//!
//! Direct confirm does **not** enqueue SH. A durable head never enters this
//! path (write-behind / `recover_sh_writebehind` instead).
//!
//! 1. Parallel fk chunks spill ~128 MiB catalog runs (`spill_creates_catalog`).
//! 2. `SEAL` is the contiguous create_fk resume floor (`create_fk > SEAL`).
//! 3. Tip finalize claims runs → `ColdResume` | `FullCold`.

use super::run_builder_core::{clear_runs_dir, on_disk_run_count, runs_dir_io, RunControl};
use rbitcoin_log::{debug, info};
use rbitcoin_primitives::Fk;
use rbitcoin_store::{
    claim_run_for_materialize, commit_run_to_catalog, for_each_merged_rec_opts,
    list_materialize_claims, list_runs, materialize_sh_shards, materialize_sh_shards_from_class_a,
    next_run_path, write_sorted_run_file_with_policy, ColdProgress, RunWritePolicy,
    ScriptHashRecord, SortedRunPath, Store, StoreError, SH_RUN_SORT_KEY_LEN,
};

/// How tip finalize applies remaining SH runs (pure decision; no I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShTipMaterializeMode {
    /// Head empty (or force rebuild): wipe + cold stream.
    FullCold,
    /// Resume interrupted cold (progress present). Dir-variant: sealed
    /// `head/NN` stays; `next_shard` is the lowest unsealed hole.
    ColdResume { next_shard: u32 },
    /// Durable head, or empty catalog: do not pack. Leftover runs are discarded.
    Skip,
}

/// Select materialize mode. **Never** returns FullCold when head already holds durable data.
pub fn select_sh_tip_materialize_mode(
    head_empty: bool,
    entry_count: u64,
    progress_next_shard: Option<u32>,
    n_shards: u32,
    stream_run_count: usize,
) -> ShTipMaterializeMode {
    let n_shards = n_shards.max(1);
    if let Some(ns) = progress_next_shard {
        if ns < n_shards {
            return ShTipMaterializeMode::ColdResume { next_shard: ns };
        }
    }
    if !head_empty || entry_count > 0 {
        return ShTipMaterializeMode::Skip;
    }
    if stream_run_count == 0 {
        return ShTipMaterializeMode::Skip;
    }
    ShTipMaterializeMode::FullCold
}

/// `RBITCOIN_SH_FORCE_REBUILD=1|true` — full Class A recollect + cold rematerialize.
pub fn sh_force_rebuild() -> bool {
    matches!(
        std::env::var("RBITCOIN_SH_FORCE_REBUILD")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .ok(),
        Some(true)
    )
}

/// `RBITCOIN_SH_MATERIALIZE=ram-shard` — one Class A pass per prefix shard, sort in RAM.
pub fn parse_sh_materialize_ram_shard(raw: Option<&str>) -> bool {
    raw.is_some_and(|s| s.eq_ignore_ascii_case("ram-shard"))
}

/// True when tip finalize should skip catalog runs and pack from Class A per shard.
pub fn sh_ram_shard_materialize() -> bool {
    parse_sh_materialize_ram_shard(std::env::var("RBITCOIN_SH_MATERIALIZE").ok().as_deref())
}

/// Allowed SEAL lag behind tip create count (recollect cancel window).
pub const SH_SEAL_LAG_OK: u64 = 50_000;

/// True when SEAL is near tip create HWM.
pub fn sh_catalog_seal_covers_tip(seal_max_fk: u64, tip_max_create_fk: u64) -> bool {
    if tip_max_create_fk == 0 {
        return true;
    }
    seal_max_fk.saturating_add(SH_SEAL_LAG_OK) >= tip_max_create_fk
}

/// High SEAL with only a tiny on-disk run mass — catch-up tail, not full IBD spills.
///
/// After a **successful** cold materialize, runs are cleared while SEAL stays high.
/// That success state is **not** a stale tail when the durable head is live; only
/// use this heuristic when the head is empty (or FORCE_REBUILD already wiped it).
pub fn sh_catalog_is_stale_tail(seal_max_fk: u64, total_run_records: u64) -> bool {
    seal_max_fk >= 1_000_000 && total_run_records < seal_max_fk / 50
}

/// True when catalog SEAL / run record mass can cover Class A through `tip_max_create_fk`.
///
/// For **empty-head** FullCold decisions only. Incomplete when SEAL lags tip, or
/// SEAL is huge but on-disk run rows are a tiny tail (catch-up-only rebuild with
/// a stale high SEAL). **Do not** use this alone on a durable head — empty runs
/// after consume are normal (see [`plan_sh_pre_materialize`]).
pub fn sh_catalog_looks_complete(
    seal_max_fk: u64,
    tip_max_create_fk: u64,
    total_run_records: u64,
) -> bool {
    if tip_max_create_fk == 0 {
        return true;
    }
    if !sh_catalog_seal_covers_tip(seal_max_fk, tip_max_create_fk) {
        return false;
    }
    if seal_max_fk == 0 {
        return total_run_records == 0;
    }
    if sh_catalog_is_stale_tail(seal_max_fk, total_run_records) {
        return false;
    }
    true
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

/// Pre-materialize catalog / SEAL action (pure; no I/O).
///
/// Covers catch-up ↔ tip ↔ restart transitions:
/// - **FORCE_REBUILD + empty head + unusable catalog:** wipe head+runs, full Class A.
/// - **FORCE_REBUILD + empty head + usable catalog:** reinit head only (FullCold) —
///   **never** wipe a just-finished multi-hour recollect (sticky env). Gap recollect
///   fills any SEAL↔tip lag after cold load.
/// - **FORCE_REBUILD + durable head:** never wipe; same bootstrap/clamp/Noop as normal
///   durable path (gap recollect + warm residual handle lag).
/// - **Empty head + stale tail / no usable catalog:** reset SEAL+runs, full recollect.
/// - **Durable head:** never wipe; never clamp SEAL to 0 for missing HWM; bootstrap
///   HWM from SEAL; clamp SEAL to HWM only when `0 < hwm < seal`.
///
/// Mainnet regression (2026-08-05): recollect done seal→1.41e9 catalog_recs≈3.7e9,
/// then tip FORCE wiped catalog and recollected from seal=0 — must not recur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShPreMaterializeAction {
    ForceFullRebuild,
    /// FORCE set but catalog usable — reinit head for FullCold only (keep runs/SEAL).
    ForceColdFromExistingCatalog,
    /// Empty head cannot be cold-loaded from current runs — SEAL=0 + clear runs.
    ResetCatalogFullRecollect,
    /// Durable head: write `include_hwm = seal` (legacy missing file).
    BootstrapIncludeHwm {
        seal: u64,
    },
    /// Durable head: lower SEAL to authoritative HWM for gap recollect.
    ClampSealTo {
        floor: u64,
    },
    Noop,
}

/// Plan SEAL/catalog prep before Class A recollect + tip materialize.
pub fn plan_sh_pre_materialize(
    force: bool,
    head_durable: bool,
    seal: u64,
    tip_max_create_fk: u64,
    run_records: u64,
    include_hwm: u64,
) -> ShPreMaterializeAction {
    if force {
        if head_durable {
            // Sticky FORCE must never nuclear-wipe a live durable head. Fall through
            // to durable maintenance (bootstrap HWM / clamp SEAL / Noop). Gap recollect
            // after this plan a durable head uses write-behind, not recollect.
        } else if empty_head_needs_full_class_a_recollect(seal, tip_max_create_fk, run_records) {
            return ShPreMaterializeAction::ForceFullRebuild;
        } else {
            return ShPreMaterializeAction::ForceColdFromExistingCatalog;
        }
    } else if !head_durable {
        if empty_head_needs_full_class_a_recollect(seal, tip_max_create_fk, run_records) {
            return ShPreMaterializeAction::ResetCatalogFullRecollect;
        }
        return ShPreMaterializeAction::Noop;
    }
    let floor = durable_sh_inclusion_floor(include_hwm, seal);
    if include_hwm == 0 && seal > 0 {
        return ShPreMaterializeAction::BootstrapIncludeHwm { seal: floor };
    }
    if include_hwm > 0 && include_hwm < seal {
        // SEAL ahead of HWM is normal after enter_direct recollect or IBD spills:
        // residual runs already hold create_fk in (hwm, seal]. Clamping SEAL back
        // to HWM and re-recollecting re-spills the same creates onto a live
        // head (mainnet 2026-08-25 zero delta). Durable head: skip collect.
        if run_records > 0 {
            return ShPreMaterializeAction::Noop;
        }
        return ShPreMaterializeAction::ClampSealTo { floor };
    }
    ShPreMaterializeAction::Noop
}

/// Empty head: full Class A recollect when catalog cannot seed a complete cold load.
fn empty_head_needs_full_class_a_recollect(seal: u64, tip_max: u64, run_records: u64) -> bool {
    if tip_max == 0 {
        return false;
    }
    if sh_catalog_is_stale_tail(seal, run_records) {
        return true;
    }
    if run_records == 0 && !sh_catalog_seal_covers_tip(seal, tip_max) {
        return true;
    }
    // Runs consumed (empty) while head still empty: prior materialize did not
    // leave a durable index — only full recollect recovers.
    if run_records == 0 && seal > 0 && sh_catalog_seal_covers_tip(seal, tip_max) {
        return true;
    }
    false
}

/// Sum of `count` over catalog + materialize claims under `runs_dir`.
pub fn sh_catalog_total_records(runs_dir: &Path) -> u64 {
    let mut n = 0u64;
    if let Ok(runs) = list_runs(runs_dir) {
        for r in runs {
            n = n.saturating_add(r.count);
        }
    }
    if let Ok(mats) = list_materialize_claims(runs_dir) {
        for r in mats {
            n = n.saturating_add(r.count);
        }
    }
    n
}
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Fixed run record: scripthash[32] | create_tx_fk:u64 = 40 bytes (no vout).
pub const SH_RUN_REC_LEN: u32 = 40;
pub const SH_RUN_KEY_LEN: u32 = SH_RUN_SORT_KEY_LEN;

#[inline]
fn run_body_bytes(run: &SortedRunPath) -> u64 {
    run.count.saturating_mul(u64::from(run.rec_len))
}

fn encode_rec(sh: &[u8; 32], tx_fk: Fk) -> [u8; SH_RUN_REC_LEN as usize] {
    let mut r = [0u8; SH_RUN_REC_LEN as usize];
    r[0..32].copy_from_slice(sh);
    r[32..40].copy_from_slice(&tx_fk.0.to_le_bytes());
    r
}

#[inline(always)]
fn decode_rec_fixed(buf: &[u8]) -> ([u8; 32], Fk) {
    debug_assert!(buf.len() >= SH_RUN_REC_LEN as usize);
    let sh: [u8; 32] = buf[0..32].try_into().unwrap();
    let tx_fk = Fk(u64::from_le_bytes(buf[32..40].try_into().unwrap()));
    (sh, tx_fk)
}

/// Sort + unique `(scripthash, create_fk)` then encode a 40-byte-key run body.
fn encode_sh_run_body_sorted_unique(pairs: &mut [([u8; 32], Fk)]) -> Vec<u8> {
    pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1 .0.cmp(&b.1 .0)));
    let mut body = Vec::with_capacity(pairs.len().saturating_mul(SH_RUN_REC_LEN as usize));
    let mut prev: Option<([u8; 32], u64)> = None;
    for &(sh, fk) in pairs.iter() {
        if fk.is_null() {
            continue;
        }
        if let Some((psh, pfk)) = prev {
            if psh == sh && pfk == fk.0 {
                continue;
            }
        }
        prev = Some((sh, fk.0));
        body.extend_from_slice(&encode_rec(&sh, fk));
    }
    body
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

/// Write SEAL (max create_fk) — tests / catch-up clamp / force rebuild.
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

fn max_fk_in_body(body: &[u8]) -> u64 {
    let rec = SH_RUN_REC_LEN as usize;
    let mut max = 0u64;
    let mut i = 0;
    while i + rec <= body.len() {
        let fk = u64::from_le_bytes(body[i + 32..i + 40].try_into().unwrap());
        if fk > max {
            max = fk;
        }
        i += rec;
    }
    max
}

struct Inner {
    ctrl: RunControl,
}

/// Post-IBD SH catalog builder (Class A recollect spills; no memtable worker).
pub struct ShRunBuilder {
    inner: Arc<Mutex<Inner>>,
    enabled: AtomicBool,
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
            enabled: AtomicBool::new(false),
            sealed_fk: Arc::new(AtomicU64::new(sealed)),
            runs_dir,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Max create_fk present in durable cataloged runs (SEAL).
    pub fn sealed_max_create_fk(&self) -> u64 {
        self.sealed_fk.load(Ordering::Acquire)
    }

    pub fn on_disk_run_count(&self) -> usize {
        let g = self.inner.lock().unwrap();
        let (dir, io) = runs_dir_io(&g.ctrl);
        drop(g);
        on_disk_run_count(&dir, &io)
    }

    /// Reload SEAL from disk into process cache (after worker coalesce / resume).
    pub fn refresh_seal(&self) {
        let s = load_seal(&self.runs_dir);
        self.sealed_fk.store(s, Ordering::Release);
    }

    /// Drop leftover catalog / `.mat` / merge files. **Keeps `SEAL`** (resume
    /// watermark). Used when a durable head exists: residual runs are not merged.
    pub fn discard_residual_runs(&self) {
        clear_runs_dir(&self.runs_dir);
        let _ = std::fs::create_dir_all(&self.runs_dir);
    }

    /// Wipe on-disk catalog runs + SEAL=0 (does not touch durable SH head).
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

    fn rearm_for_recollect(&self) {}

    /// Wipe SH runs/SEAL/cold progress/include_hwm and empty durable SH tables.
    ///
    /// Used by `RBITCOIN_SH_FORCE_REBUILD=1` when catalog is unusable so tip
    /// recollects **all** Class A creates (SEAL=0).
    pub fn prepare_force_full_rebuild(&self, store: &Store) -> Result<(), StoreError> {
        info!("node: scripthash FORCE_REBUILD — clearing runs/SEAL/progress/HWM and reinit head");
        self.wipe_catalog_and_seal()?;
        Self::clear_cold_progress_and_hwm(store);
        store.scripthash.reinit_empty_for_cold_materialize()?;
        self.rearm_for_recollect();
        Ok(())
    }

    /// FORCE with usable catalog: reinit head only — keep runs/SEAL for FullCold.
    pub fn prepare_force_cold_from_catalog(&self, store: &Store) -> Result<(), StoreError> {
        info!(
            "node: scripthash FORCE_REBUILD — catalog usable; reinit head only \
             (not wiping runs/SEAL)"
        );
        Self::clear_cold_progress_and_hwm(store);
        store.scripthash.reinit_empty_for_cold_materialize()?;
        self.rearm_for_recollect();
        Ok(())
    }

    /// Thread-safe: sort `creates` and append one **catalog** run (direct write).
    ///
    /// Used by parallel Class A recollect so each worker can spill ~128 MiB without
    /// going through a process-wide queue. Does **not** advance SEAL —
    /// the recollect coordinator bumps a **contiguous** watermark so resume never
    /// skips unfinished lower fk ranges.
    ///
    /// Returns `(max_create_fk, record_count)`.
    pub fn spill_creates_catalog(
        &self,
        creates: &mut [ScriptHashRecord],
    ) -> Result<(u64, u64), StoreError> {
        if creates.is_empty() {
            return Ok((0, 0));
        }
        let mut pairs: Vec<([u8; 32], Fk)> = creates
            .iter()
            .map(|r| (r.scripthash, r.create_tx_fk))
            .collect();
        let body = encode_sh_run_body_sorted_unique(&mut pairs);
        let n = (body.len() / SH_RUN_REC_LEN as usize) as u64;
        let max_fk = max_fk_in_body(&body);
        if body.is_empty() {
            return Ok((0, 0));
        }
        let (runs_dir, runs_io) = {
            let g = self.inner.lock().unwrap();
            (g.ctrl.runs_dir.clone(), Arc::clone(&g.ctrl.runs_io))
        };
        let mut next_seq = {
            let g = self.inner.lock().unwrap();
            g.ctrl.next_seq
        };
        let path = {
            let mut g = self.inner.lock().unwrap();
            let _io = runs_io.lock().unwrap();
            next_seq = next_seq
                .max(g.ctrl.next_seq)
                .max(next_seq_ceiling(&runs_dir));
            let path = next_run_path(&runs_dir, next_seq);
            next_seq = next_seq.saturating_add(1);
            g.ctrl.next_seq = next_seq.max(g.ctrl.next_seq);
            path
        };
        let part = path.with_extension("run.part");
        let run = write_sorted_run_file_with_policy(
            &part,
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body,
            RunWritePolicy::CATALOG,
        )?;
        debug!(
            "ibd: SH recollect spill records≈{} body≈{:.1}MiB max_fk={max_fk} path={}",
            run.count,
            run_body_bytes(&run) as f64 / (1024.0 * 1024.0),
            path.display()
        );
        {
            let _io = runs_io.lock().unwrap();
            std::fs::rename(&part, &path).map_err(|e| StoreError::io(&path, e))?;
            let run = SortedRunPath {
                path: path.clone(),
                ..run
            };
            commit_run_to_catalog(&run)?;
        }
        Ok((max_fk, n))
    }

    /// Publish contiguous SEAL watermark (recollect resume floor).
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

    /// Drop incomplete/stale run catalog and SEAL so Class A recollect starts at 0.
    ///
    /// Does **not** wipe a durable SH head (use [`Self::prepare_force_full_rebuild`] for that).
    /// Does **not** join the worker (safe mid-IBD); re-enables so recollect can spill.
    pub fn reset_catalog_for_full_recollect(&self) -> Result<(), StoreError> {
        info!(
            "node: scripthash catalog incomplete/stale — resetting SEAL=0 and clearing runs for full Class A recollect"
        );
        self.wipe_catalog_and_seal()?;
        self.rearm_for_recollect();
        Ok(())
    }

    /// Clamp SEAL down to `max_fk` (gap recollect for durable head + warm residual).
    pub fn set_sealed_max_for_recollect(&self, max_fk: u64) -> Result<(), StoreError> {
        store_seal(&self.runs_dir, max_fk)?;
        self.sealed_fk.store(max_fk, Ordering::Release);
        Ok(())
    }

    /// Claim catalog runs and cold bulk-load durable SH (k-way over claimed files).
    pub fn finalize_and_bulk_materialize(&self, store: &Store) -> Result<u64, StoreError> {
        self.finalize_and_bulk_materialize_cancellable(store, None)
    }

    /// Like [`Self::finalize_and_bulk_materialize`] with cooperative cancel (SIGINT).
    ///
    /// Interrupted cold resumes via [`ColdProgress`] shard hole, not a run-reduce
    /// checkpoint. Recollect spills ~128 MiB runs; materialize k-ways them directly.
    pub fn finalize_and_bulk_materialize_cancellable(
        &self,
        store: &Store,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, StoreError> {
        let (runs_dir, runs_io) = {
            let g = self.inner.lock().unwrap();
            (g.ctrl.runs_dir.clone(), Arc::clone(&g.ctrl.runs_io))
        };

        let merge_dir = runs_dir.join("merge");

        let t_claim = Instant::now();
        let mut claimed: Vec<SortedRunPath> = Vec::new();
        {
            let _io = runs_io.lock().unwrap();
            let mut prior = list_materialize_claims(&runs_dir)?;
            let mut runs = list_runs(&runs_dir)?;
            runs.sort_by_key(|r| r.seq().unwrap_or(u64::MAX));
            let _ = std::fs::remove_dir_all(&merge_dir);
            if !prior.is_empty() {
                info!(
                    "node: scripthash resuming {} incomplete materialize claim(s)",
                    prior.len()
                );
            }
            claimed.append(&mut prior);
            for run in runs {
                claimed.push(claim_run_for_materialize(&run)?);
            }
        }
        let claim_ns = t_claim.elapsed().as_nanos() as u64;

        if claimed.is_empty() {
            debug!("node: scripthash bulk materialize: no runs");
            clear_runs_dir(&runs_dir);
            return Ok(0);
        }

        let workers = rbitcoin_store::sh_merge_workers();
        let free_gib = rbitcoin_store::free_gib_label();
        let total_recs: u64 = claimed.iter().map(|r| r.count).sum();
        let claimed_body: u64 = claimed
            .iter()
            .map(|r| r.count.saturating_mul(u64::from(r.rec_len)))
            .sum();
        info!(
            "node: scripthash tip k-way claimed={} workers={workers} \
             free_GiB={free_gib} records≈{total_recs} body≈{:.1}MiB",
            claimed.len(),
            claimed_body as f64 / (1024.0 * 1024.0),
        );
        let n_existing = store.scripthash.entry_count();
        let head_empty = store.scripthash.head_is_empty();
        let n_shards = store.scripthash.head_shard_count();
        let store_dir = store.path();
        let progress = ColdProgress::load(store_dir).ok().flatten();
        let tip_max = store.txs.count();
        let seal_now = self.sealed_max_create_fk();
        // Durable head: empty/tiny residual runs are normal after consume — do not
        // flag mass incompleteness (that is an empty-head / FORCE concern only).
        let head_live = !head_empty || n_existing > 0;
        let catalog_ok = if head_live {
            sh_catalog_seal_covers_tip(seal_now, tip_max)
        } else {
            sh_catalog_looks_complete(seal_now, tip_max, total_recs)
        };
        let mode = select_sh_tip_materialize_mode(
            head_empty,
            n_existing,
            progress.as_ref().map(|p| p.next_shard),
            n_shards as u32,
            claimed.len(),
        );
        info!(
            "node: scripthash tip materialize path={mode:?} entry_count={n_existing} \
             head_empty={head_empty} stream_runs={} records≈{total_recs} \
             catalog_complete={catalog_ok} seal={seal_now} tip_max_fk={tip_max} progress={:?}",
            claimed.len(),
            progress.as_ref().map(|p| p.next_shard),
        );

        if matches!(mode, ShTipMaterializeMode::Skip) {
            info!(
                "node: scripthash skip materialize (durable head or empty stream); \
                 discarding leftover runs={}",
                claimed.len()
            );
            for run in &claimed {
                let _ = std::fs::remove_file(&run.path);
            }
            let _ = std::fs::remove_dir_all(&merge_dir);
            clear_runs_dir(&runs_dir);
            return Ok(0);
        }

        let resume_from = match &mode {
            ShTipMaterializeMode::ColdResume { next_shard } => *next_shard as usize,
            _ => 0,
        };
        let t_reinit = Instant::now();
        match mode {
            ShTipMaterializeMode::ColdResume { .. } => {
                let p = progress.expect("ColdResume requires progress");
                info!(
                    "node: scripthash cold resume next_shard={}/{} keys≈{} creates≈{} bump={} \
                     stream_runs={}",
                    p.next_shard,
                    n_shards,
                    p.keys_written,
                    p.live_count,
                    p.body_bump,
                    claimed.len()
                );
                store.scripthash.prepare_cold_resume(&p)?;
            }
            ShTipMaterializeMode::FullCold => {
                info!(
                    "node: scripthash reinit empty for cold rematerialize \
                     stream_runs={} entry_count={n_existing} head_empty={head_empty} \
                     n_shards={n_shards}",
                    claimed.len()
                );
                store.scripthash.reinit_empty_for_cold_materialize()?;
                debug_assert_eq!(store.scripthash.entry_count(), 0);
                debug_assert!(store.scripthash.head_is_empty());
            }
            ShTipMaterializeMode::Skip => unreachable!("skip handled above"),
        }
        let reinit_ns = t_reinit.elapsed().as_nanos() as u64;
        info!(
            "node: scripthash bulk materialize start runs={} records≈{total_recs} cold=true \
             n_shards={n_shards} resume_from_shard={resume_from} \
             workers={workers} free_GiB={free_gib}",
            claimed.len()
        );
        let t0 = Instant::now();
        let t_stream = Instant::now();
        let mat = match materialize_sh_shards(
            &store.scripthash,
            &claimed,
            resume_from,
            workers,
            cancel,
        ) {
            Ok(m) => m,
            Err(StoreError::Cancelled(msg)) => {
                info!(
                    "node: scripthash materialize cancelled ({msg}); complete shards kept — restart resumes"
                );
                return Err(StoreError::Cancelled(msg));
            }
            Err(e) => return Err(e),
        };
        let unique_in = mat.keys;
        let max_fk_seen = mat.max_fk;
        let stream_ns = t_stream.elapsed().as_nanos() as u64;

        let t_finish = Instant::now();
        let n_total = mat.creates;
        let n_keys = mat.keys;
        let merge_ns = mat.merge_ns;
        let pack_ns = mat.pack_ns;
        let mphf_ns = mat.mphf_ns;
        let body_flush_ns = mat.body_flush_ns;
        let head_fill_ns = mat.head_fill_ns;
        store.scripthash.flush()?;
        let finish_ns = t_finish.elapsed().as_nanos() as u64;

        // Success barrier: drop materialize artifacts.
        for run in &claimed {
            let _ = std::fs::remove_file(&run.path);
        }
        let _ = std::fs::remove_dir_all(&merge_dir);
        ColdProgress::clear(store_dir);

        let leftover = {
            let _io = runs_io.lock().unwrap();
            list_runs(&runs_dir).unwrap_or_default()
        };
        let mut n_deferred = 0u64;
        let mut hwm = max_fk_seen;
        if !leftover.is_empty() {
            for r in &leftover {
                if let Ok(body) = rbitcoin_store::read_run_body(r) {
                    hwm = hwm.max(max_fk_in_body(&body));
                }
            }
            info!(
                "node: scripthash applying {} leftover run(s) after cold materialize",
                leftover.len()
            );
            n_deferred = apply_runs_to_live_sh(store, &leftover, cancel)?;
            for r in &leftover {
                let _ = std::fs::remove_file(&r.path);
            }
        }
        clear_runs_dir(&runs_dir);
        if hwm > 0 {
            let _ = store_seal(&runs_dir, hwm);
            self.sealed_fk.store(hwm, Ordering::Release);
            let _ = store.scripthash.note_include_hwm(hwm);
        }

        info!(
            "node: scripthash bulk materialize done creates≈{n_total} keys≈{n_keys} unique_in≈{unique_in} \
             deferred≈{n_deferred} shards={n_shards} elapsed={:?} \
             stages: claim={:?} reinit={:?} stream={:?} merge={:?} pack={:?} \
             mphf={:?} body_flush={:?} head_fill={:?} finish_flush={:?}",
            t0.elapsed(),
            Duration::from_nanos(claim_ns),
            Duration::from_nanos(reinit_ns),
            Duration::from_nanos(stream_ns),
            Duration::from_nanos(merge_ns),
            Duration::from_nanos(pack_ns),
            Duration::from_nanos(mphf_ns),
            Duration::from_nanos(body_flush_ns),
            Duration::from_nanos(head_fill_ns),
            Duration::from_nanos(finish_ns),
        );
        Ok(n_total.saturating_add(n_deferred))
    }

    /// Class A → one shard in RAM per pass (no catalog runs). SIGINT keeps sealed shards.
    pub fn finalize_and_ram_shard_materialize_cancellable(
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
                "node: scripthash ram-shard skip (all {n_shards} shards sealed, entry_count={n_existing})"
            );
            self.discard_residual_runs();
            let tip_max = store.txs.count();
            if tip_max > 0 {
                self.publish_seal_watermark(tip_max)?;
                let _ = store.scripthash.note_include_hwm(tip_max);
            }
            return Ok(0);
        }

        if head_empty {
            info!(
                "node: scripthash ram-shard reinit empty for cold rematerialize n_shards={n_shards}"
            );
            store.scripthash.reinit_empty_for_cold_materialize()?;
        }

        let workers = rbitcoin_store::sh_merge_workers();
        let free_gib = rbitcoin_store::free_gib_label();
        let tip_max = store.txs.count();
        info!(
            "node: scripthash ram-shard materialize start workers={workers} free_GiB={free_gib} \
             n_shards={n_shards} unsealed={} tip_max_fk={tip_max} head_empty={head_empty}",
            unsealed.len(),
        );
        let t0 = Instant::now();
        let mat = match materialize_sh_shards_from_class_a(store, workers, cancel) {
            Ok(m) => m,
            Err(StoreError::Cancelled(msg)) => {
                info!(
                    "node: scripthash ram-shard cancelled ({msg}); complete shards kept — restart resumes"
                );
                return Err(StoreError::Cancelled(msg));
            }
            Err(e) => return Err(e),
        };
        store.scripthash.flush()?;
        ColdProgress::clear(store.path());
        self.discard_residual_runs();
        let hwm = mat.max_fk.max(tip_max);
        if hwm > 0 {
            self.publish_seal_watermark(hwm)?;
            let _ = store.scripthash.note_include_hwm(hwm);
        }
        info!(
            "node: scripthash ram-shard materialize done creates≈{} keys≈{} shards={n_shards} \
             elapsed={:?}",
            mat.creates,
            mat.keys,
            t0.elapsed(),
        );
        Ok(mat.creates)
    }
}

/// Batch size for warm deferred apply (records per `put_create_batch_append`).
///
/// Avoids per-create `put_create` (head probe + contains walk each time) which
/// pegs one core for hours on a multi‑GiB live head after cold materialize.
/// Sized so each batch finishes in seconds (status + cancel) on a full mainnet head.
const DEFERRED_APPLY_BATCH: usize = 8_000;

/// Stream sorted-run records into the **live** SH table (batched tip-style append).
///
/// Runs are already scripthash-sorted: group into batches and
/// [`ScriptHashTable::put_create_batch_append`] (one head seed + body merge per
/// distinct key per batch). Not the cold live-OA path — head is already full.
///
/// Creates with `create_tx_fk ≤ include_hwm` are skipped (already in the durable
/// head). Logs **after each batch** so a multi-minute head walk cannot go silent.
fn apply_runs_to_live_sh(
    store: &Store,
    runs: &[SortedRunPath],
    cancel: Option<&AtomicBool>,
) -> Result<u64, StoreError> {
    if runs.is_empty() {
        return Ok(0);
    }
    let total_recs: u64 = runs.iter().map(|r| r.count).sum();
    let body_mib: f64 =
        runs.iter().map(|r| run_body_bytes(r) as f64).sum::<f64>() / (1024.0 * 1024.0);
    let include_hwm = store.scripthash.include_hwm();
    info!(
        "node: scripthash deferred warm apply start runs={} records≈{total_recs} body≈{body_mib:.1}MiB \
         batch={DEFERRED_APPLY_BATCH} include_hwm={include_hwm}",
        runs.len()
    );
    let t0 = Instant::now();
    let mut n = 0u64;
    let mut batch: Vec<ScriptHashRecord> = Vec::with_capacity(DEFERRED_APPLY_BATCH);
    // Process-local head cache; cleared each batch (stream is key-sorted, no revisit).
    let mut heads = std::collections::HashMap::new();
    let mut recs_seen = 0u64;
    let mut recs_skipped_hwm = 0u64;
    let mut batch_i = 0u32;

    let flush_batch =
        |batch: &mut Vec<ScriptHashRecord>,
         heads: &mut std::collections::HashMap<[u8; 32], rbitcoin_store::ShHeadValue>,
         n: &mut u64,
         batch_i: &mut u32,
         recs_seen: u64,
         t0: Instant|
         -> Result<(), StoreError> {
            if batch.is_empty() {
                return Ok(());
            }
            *batch_i = batch_i.saturating_add(1);
            let bi = *batch_i;
            let batch_n = batch.len();
            let tb = Instant::now();
            let (w, timing) = store.scripthash.put_create_batch_append(batch, heads)?;
            *n = n.saturating_add(w as u64);
            let pct = if total_recs > 0 {
                (100.0 * recs_seen as f64 / total_recs as f64).clamp(0.0, 99.9)
            } else {
                0.0
            };
            let secs = t0.elapsed().as_secs_f64().max(1e-3);
            info!(
                "node: scripthash deferred warm apply batch={bi} recs={batch_n} written+={w} \
             total_written≈{n} stream≈{recs_seen}/{total_recs} pct≈{pct:.1}% \
             rate≈{:.0}rec/s batch_wall={:?} seed={:?} body={:?} head={:?} elapsed={:?}",
                recs_seen as f64 / secs,
                tb.elapsed(),
                Duration::from_nanos(timing.seed_ns),
                Duration::from_nanos(timing.body_ns),
                Duration::from_nanos(timing.head_ns),
                t0.elapsed()
            );
            batch.clear();
            heads.clear();
            Ok(())
        };

    for_each_merged_rec_opts(runs, false, |rec| {
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash deferred apply"));
        }
        if rec.len() < SH_RUN_REC_LEN as usize {
            return Err(StoreError::Corrupt("sh run short record in deferred apply"));
        }
        let (sh, tx_fk) = decode_rec_fixed(rec);
        if tx_fk.is_null() {
            return Ok(());
        }
        recs_seen = recs_seen.saturating_add(1);
        if include_hwm > 0 && tx_fk.0 <= include_hwm {
            recs_skipped_hwm = recs_skipped_hwm.saturating_add(1);
            return Ok(());
        }
        batch.push(ScriptHashRecord::from_fk(sh, tx_fk));
        if batch.len() >= DEFERRED_APPLY_BATCH {
            flush_batch(&mut batch, &mut heads, &mut n, &mut batch_i, recs_seen, t0)?;
        }
        Ok(())
    })?;
    flush_batch(&mut batch, &mut heads, &mut n, &mut batch_i, recs_seen, t0)?;
    store.scripthash.flush()?;
    info!(
        "node: scripthash deferred warm apply done written≈{n} recs≈{recs_seen} \
         skipped_hwm≈{recs_skipped_hwm} batches={batch_i} elapsed={:?}",
        t0.elapsed()
    );
    Ok(n)
}

/// Next seq id strictly above any cataloged run (and current counter).
fn next_seq_ceiling(runs_dir: &Path) -> u64 {
    list_runs(runs_dir)
        .ok()
        .and_then(|rs| rs.iter().filter_map(|r| r.seq()).max())
        .map(|m| m.saturating_add(1))
        .unwrap_or(1)
}

/// Parallel Class A recollect: spill local buffer at this size (~128 MiB of 40 B recs).
pub const RECOLLECT_THREAD_SPILL_BYTES: u64 = 128 * 1024 * 1024;

/// Floor for catalog compact: do **not** merge intentional recollect spills.
///
/// Slightly below [`RECOLLECT_THREAD_SPILL_BYTES`] so default ~128 MiB spills
/// are never candidates. Live compact uses [`catalog_compact_floor_bytes`] of
/// the resolved spill size.
#[cfg(test)]
const CATALOG_COMPACT_FLOOR_BYTES: u64 = RECOLLECT_THREAD_SPILL_BYTES.saturating_mul(3) / 4;

const RECOLLECT_SPILL_BYTES_MIN: u64 = 16 * 1024 * 1024;
const RECOLLECT_SPILL_BYTES_MAX: u64 = 512 * 1024 * 1024;

/// Parse `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` (16 MiB–512 MiB, default 128 MiB).
pub fn parse_recollect_spill_bytes(raw: Option<&str>) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
        .map(|n| n.clamp(RECOLLECT_SPILL_BYTES_MIN, RECOLLECT_SPILL_BYTES_MAX))
        .unwrap_or(RECOLLECT_THREAD_SPILL_BYTES)
}

/// Resolved recollect spill size (`RBITCOIN_SH_RECOLLECT_SPILL_BYTES` or default).
pub fn recollect_spill_bytes() -> u64 {
    parse_recollect_spill_bytes(
        std::env::var("RBITCOIN_SH_RECOLLECT_SPILL_BYTES")
            .ok()
            .as_deref(),
    )
}

/// Compact floor: 3/4 of the effective recollect spill so intentional spills stay.
#[cfg(test)]
pub fn catalog_compact_floor_bytes(spill_bytes: u64) -> u64 {
    spill_bytes.saturating_mul(3) / 4
}

/// True if a catalog run body should be eligible for undersized compact.
#[cfg(test)]
pub fn catalog_run_is_compact_candidate(body_bytes: u64, target_run_bytes: u64) -> bool {
    if body_bytes == 0 {
        return false;
    }
    let half = target_run_bytes / 2;
    let small_max = half.min(catalog_compact_floor_bytes(recollect_spill_bytes()));
    body_bytes < small_max
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_store::{read_run_body, write_sorted_run, Store};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn materialize_streams_megakey_without_full_chain_vec() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-stream-mega-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut sh = [0u8; 32];
        sh[0] = 0x51;
        let n_fks = 600u64;
        let mut body = Vec::new();
        for i in 1..=n_fks {
            body.extend_from_slice(&encode_rec(&sh, Fk(i)));
        }
        write_sorted_run(
            &next_run_path(&runs_dir, 1),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body,
        )
        .unwrap();
        let written = b.finalize_and_bulk_materialize(&store).unwrap();
        assert_eq!(written, n_fks);
        assert_eq!(store.scripthash.entries(&sh).unwrap().len(), n_fks as usize);
        match store.scripthash.head_value(&sh).unwrap().unwrap() {
            rbitcoin_store::ShHeadValue::Slab { used, class, .. } => {
                assert_eq!(used, n_fks as u16);
                assert!(
                    class <= rbitcoin_store::SH_MAX_SLAB_CLASS,
                    "600 tight deltas stay in a relocating slab, class={class}"
                );
            }
            other => panic!("expected slab (not paged), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_two_run_catalog(runs_dir: &std::path::Path) -> Vec<[u8; 32]> {
        std::fs::create_dir_all(runs_dir).unwrap();
        let mut body_a = Vec::new();
        let mut body_b = Vec::new();
        let mut keys = Vec::new();
        for i in 0..16u32 {
            let mut sh = [0u8; 32];
            sh[0] = (i * 16) as u8;
            keys.push(sh);
            let rec = encode_rec(&sh, Fk(u64::from(i) + 1));
            if i % 2 == 0 {
                body_a.extend_from_slice(&rec);
            } else {
                body_b.extend_from_slice(&rec);
            }
        }
        write_sorted_run(
            &next_run_path(runs_dir, 1),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body_a,
        )
        .unwrap();
        write_sorted_run(
            &next_run_path(runs_dir, 2),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body_b,
        )
        .unwrap();
        keys
    }

    #[test]
    fn materialize_parallel_matches_serial() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-par-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let serial_dir = dir.join("serial");
        std::fs::create_dir_all(&serial_dir).unwrap();
        let keys = write_two_run_catalog(&serial_dir.join("scripthash.runs"));
        std::env::set_var("RBITCOIN_SH_MERGE_WORKERS", "1");
        let store_s = Store::open_or_create(&serial_dir).unwrap();
        let n_s = ShRunBuilder::new(&serial_dir)
            .finalize_and_bulk_materialize(&store_s)
            .unwrap();

        let par_dir = dir.join("par");
        std::fs::create_dir_all(&par_dir).unwrap();
        write_two_run_catalog(&par_dir.join("scripthash.runs"));
        std::env::set_var("RBITCOIN_SH_MERGE_WORKERS", "2");
        let store_p = Store::open_or_create(&par_dir).unwrap();
        let n_p = ShRunBuilder::new(&par_dir)
            .finalize_and_bulk_materialize(&store_p)
            .unwrap();
        std::env::remove_var("RBITCOIN_SH_MERGE_WORKERS");

        assert_eq!(n_s, n_p);
        assert_eq!(
            store_s.scripthash.entry_count(),
            store_p.scripthash.entry_count()
        );
        for sh in &keys {
            assert_eq!(
                store_s.scripthash.entries(sh).unwrap().len(),
                store_p.scripthash.entries(sh).unwrap().len()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_parallel_resume() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-resume-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        ColdProgress {
            next_shard: 1,
            body_bump: 8192,
            live_count: 8,
            keys_written: 8,
        }
        .store(&dir)
        .unwrap();
        let p = ColdProgress::load(&dir).unwrap().unwrap();
        assert_eq!(p.next_shard, 1);
        assert_eq!(p.body_bump, 8192);
        assert_eq!(p.live_count, 8);
        assert_eq!(p.keys_written, 8);
        assert_eq!(
            select_sh_tip_materialize_mode(false, 8, Some(1), 4, 2),
            ShTipMaterializeMode::ColdResume { next_shard: 1 }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_spill_then_materialize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-builder-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let mut creates = Vec::new();
        for i in 0..100u32 {
            let mut sh = [0u8; 32];
            sh[0] = (i % 17) as u8;
            sh[1] = (i / 17) as u8;
            creates.push(ScriptHashRecord::from_fk(sh, Fk(i as u64 + 1)));
        }
        let (max_fk, n_spill) = b.spill_creates_catalog(&mut creates).unwrap();
        assert_eq!(n_spill, 100);
        assert_eq!(max_fk, 100);
        let n = b.finalize_and_bulk_materialize(&store).unwrap();
        assert!(n >= 100, "inserted={n}");
        assert!(store.scripthash.entry_count() >= 100);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spill_creates_catalog_writes_run() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-seal-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let mut creates = Vec::new();
        for i in 1..=50u64 {
            let mut sh = [0u8; 32];
            sh[0] = i as u8;
            creates.push(ScriptHashRecord::from_fk(sh, Fk(i)));
        }
        let (mfk, n) = b.spill_creates_catalog(&mut creates).unwrap();
        assert_eq!(n, 50);
        assert_eq!(mfk, 50);
        let mut more = vec![ScriptHashRecord::from_fk([0xee; 32], Fk(99))];
        let (mfk2, n2) = b.spill_creates_catalog(&mut more).unwrap();
        assert_eq!(n2, 1);
        assert_eq!(mfk2, 99);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spill_creates_catalog_writes_key_len_40_and_dedups() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-spill40-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let sh_a = [0x11u8; 32];
        let sh_b = [0x22u8; 32];
        let mut creates = vec![
            ScriptHashRecord::from_fk(sh_b, Fk(5)),
            ScriptHashRecord::from_fk(sh_a, Fk(3)),
            ScriptHashRecord::from_fk(sh_a, Fk(3)),
            ScriptHashRecord::from_fk(sh_a, Fk(1)),
        ];
        let (mfk, n) = b.spill_creates_catalog(&mut creates).unwrap();
        assert_eq!(n, 3, "dup (sh,fk) dropped; three unique records");
        assert_eq!(mfk, 5);
        let runs = list_runs(&dir.join("scripthash.runs")).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].key_len, 40);
        assert_eq!(runs[0].rec_len, 40);
        let body = read_run_body(&runs[0]).unwrap();
        assert_eq!(body.len(), 3 * SH_RUN_REC_LEN as usize);
        let (_s0, f0) = decode_rec_fixed(&body[0..40]);
        let (_s1, f1) = decode_rec_fixed(&body[40..80]);
        let (_s2, f2) = decode_rec_fixed(&body[80..120]);
        assert!(f0.0 < f1.0 || _s0 < _s1);
        assert_eq!((_s0, f0), (sh_a, Fk(1)));
        assert_eq!((_s1, f1), (sh_a, Fk(3)));
        assert_eq!((_s2, f2), (sh_b, Fk(5)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spill_creates_catalog_concurrent_unique_seqs() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-spill-conc-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        std::thread::scope(|scope| {
            for i in 0..4u8 {
                let b = &b;
                scope.spawn(move || {
                    let mut sh = [0u8; 32];
                    sh[0] = i.saturating_add(1);
                    let mut creates = vec![ScriptHashRecord::from_fk(sh, Fk(u64::from(i) + 1))];
                    b.spill_creates_catalog(&mut creates).unwrap();
                });
            }
        });
        let runs = list_runs(&dir.join("scripthash.runs")).unwrap();
        assert_eq!(runs.len(), 4, "each worker must land a catalog run");
        let mut seqs: Vec<u64> = runs.iter().filter_map(|r| r.seq()).collect();
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), 4, "seqs must be unique: {seqs:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kway_many_runs_materialize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-kway-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        const N_RUNS: u64 = 40;
        const PER_RUN: u64 = 8;
        for seq in 1..=N_RUNS {
            let mut body = Vec::new();
            for j in 0..PER_RUN {
                let mut sh = [0u8; 32];
                sh[0] = seq as u8;
                sh[1] = j as u8;
                body.extend_from_slice(&encode_rec(&sh, Fk(seq * 100 + j + 1)));
            }
            let path = next_run_path(&runs_dir, seq);
            write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();
        }
        let n = b.finalize_and_bulk_materialize(&store).unwrap();
        assert_eq!(n, N_RUNS * PER_RUN);
        assert_eq!(store.scripthash.entry_count(), N_RUNS * PER_RUN);
        let merge = runs_dir.join("merge");
        assert!(
            !merge.join("CHECKPOINT").is_file() && !merge.join("READY").is_file(),
            "k-way must not write a fan-in checkpoint"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_skips_residual_on_nonempty_table() {
        // Durable head + residual runs → discard runs; never FullCold wipe.
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-reinit-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();

        let mut body = Vec::new();
        let mut first_sh = [0u8; 32];
        for i in 0..30u32 {
            let mut sh = [0u8; 32];
            sh[0] = i as u8;
            if i == 0 {
                first_sh = sh;
            }
            body.extend_from_slice(&encode_rec(&sh, Fk(i as u64 + 1)));
        }
        let path = next_run_path(&runs_dir, 1);
        write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();
        let n1 = b.finalize_and_bulk_materialize(&store).unwrap();
        assert!(n1 >= 30);
        let count_before = store.scripthash.entry_count();
        assert!(count_before >= 30);
        assert_eq!(store.scripthash.entries(&first_sh).unwrap().len(), 1);

        let mut body2 = Vec::new();
        let mut residual_sh = [0u8; 32];
        residual_sh[0] = 100;
        for i in 0..40u32 {
            let mut sh = [0u8; 32];
            sh[0] = (i + 100) as u8;
            body2.extend_from_slice(&encode_rec(&sh, Fk(i as u64 + 1000)));
        }
        let path2 = next_run_path(&runs_dir, 2);
        let run2 = write_sorted_run(&path2, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body2).unwrap();
        let _ = claim_run_for_materialize(&run2).unwrap();

        let n2 = b.finalize_and_bulk_materialize(&store).unwrap();
        assert_eq!(n2, 0, "must not WarmOnly residual onto a live head");
        assert_eq!(store.scripthash.entry_count(), count_before);
        assert_eq!(
            store.scripthash.entries(&first_sh).unwrap().len(),
            1,
            "skip must not wipe durable head"
        );
        assert!(
            store.scripthash.entries(&residual_sh).unwrap().is_empty(),
            "leftover run must not be merged"
        );
        assert!(list_materialize_claims(&runs_dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_recovers_claimed_mat_files() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-mat-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut body = Vec::new();
        for i in 0..50u32 {
            let mut sh = [0u8; 32];
            sh[0] = i as u8;
            body.extend_from_slice(&encode_rec(&sh, Fk(i as u64 + 1)));
        }
        let path = next_run_path(&runs_dir, 1);
        let run = write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();
        let claimed = claim_run_for_materialize(&run).unwrap();
        assert!(claimed.path.to_string_lossy().ends_with(".run.mat"));
        assert!(list_runs(&runs_dir).unwrap().is_empty());
        assert_eq!(list_materialize_claims(&runs_dir).unwrap().len(), 1);

        let n = b.finalize_and_bulk_materialize(&store).unwrap();
        assert!(n >= 50, "inserted={n}");
        assert!(store.scripthash.entry_count() >= 50);
        assert!(list_materialize_claims(&runs_dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_key_run_finalize_materialize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-run-same-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let b = ShRunBuilder::new(&dir);
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let sh = [0xabu8; 32];
        let mut body = Vec::new();
        for i in 1..=20u64 {
            body.extend_from_slice(&encode_rec(&sh, Fk(i)));
        }
        let path = next_run_path(&runs_dir, 1);
        write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();
        let n = b.finalize_and_bulk_materialize(&store).unwrap();
        assert_eq!(n, 20);
        assert_eq!(store.scripthash.entries(&sh).unwrap().len(), 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_key_append_preserves_chain() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-sh-append-same-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_or_create(&dir).unwrap();
        let sh = [0xabu8; 32];
        let mut batch = Vec::new();
        for i in 1..=20u64 {
            batch.push(ScriptHashRecord::from_fk(sh, Fk(i)));
        }
        let mut heads = std::collections::HashMap::new();
        let (n, _) = store
            .scripthash
            .put_create_batch_append(&batch, &mut heads)
            .unwrap();
        assert_eq!(n, 20);
        assert_eq!(store.scripthash.entries(&sh).unwrap().len(), 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_mode_never_full_cold_when_head_has_data() {
        assert_eq!(
            select_sh_tip_materialize_mode(false, 3_741_517_546, None, 64, 1),
            ShTipMaterializeMode::Skip
        );
        assert_eq!(
            select_sh_tip_materialize_mode(true, 100, None, 64, 1),
            ShTipMaterializeMode::Skip
        );
        assert_eq!(
            select_sh_tip_materialize_mode(true, 0, None, 64, 10),
            ShTipMaterializeMode::FullCold
        );
        assert_eq!(
            select_sh_tip_materialize_mode(false, 1e9 as u64, Some(40), 64, 32),
            ShTipMaterializeMode::ColdResume { next_shard: 40 }
        );
        assert_eq!(
            select_sh_tip_materialize_mode(false, 1e9 as u64, Some(0), 64, 1),
            ShTipMaterializeMode::ColdResume { next_shard: 0 }
        );
        assert_eq!(
            select_sh_tip_materialize_mode(true, 0, None, 64, 1),
            ShTipMaterializeMode::FullCold
        );
        assert_eq!(
            select_sh_tip_materialize_mode(false, 100, Some(64), 64, 1),
            ShTipMaterializeMode::Skip
        );
    }

    #[test]
    fn catalog_complete_rejects_stale_seal_with_tiny_runs() {
        // Real failure mode: SEAL≈1.4e9 after catch-up but only ~2e5 run rows (tail).
        assert!(!sh_catalog_looks_complete(
            1_411_832_114,
            1_416_000_000,
            222_511
        ));
        assert!(sh_catalog_is_stale_tail(1_411_832_114, 222_511));
        assert!(!sh_catalog_looks_complete(1_000_000, 2_000_000, 10_000));
        // Full IBD-style: seal near tip, huge run mass.
        assert!(sh_catalog_looks_complete(
            1_410_000_000,
            1_410_000_000,
            3_700_000_000
        ));
        assert!(sh_catalog_looks_complete(0, 0, 0));
        // Post-success state: high SEAL, zero runs — incomplete for *empty* head only.
        assert!(sh_catalog_is_stale_tail(1_411_000_000, 0));
        assert!(!sh_catalog_looks_complete(1_411_000_000, 1_411_000_000, 0));
    }

    #[test]
    fn compact_candidate_spares_recollect_scale_runs() {
        // Default tip target 512MiB → half=256MiB; floor=96MiB → small_max=96MiB.
        let target = 512 * 1024 * 1024u64;
        assert!(
            catalog_run_is_compact_candidate(10 * 1024 * 1024, target),
            "tiny crumbs still compact"
        );
        assert!(
            !catalog_run_is_compact_candidate(RECOLLECT_THREAD_SPILL_BYTES, target),
            "128MiB recollect spills must not compact"
        );
        assert!(
            !catalog_run_is_compact_candidate(125 * 1024 * 1024, target),
            "near-spill-size runs stay for tip k-way"
        );
        assert!(
            !catalog_run_is_compact_candidate(CATALOG_COMPACT_FLOOR_BYTES, target),
            "at floor is not a candidate"
        );
        assert!(catalog_run_is_compact_candidate(
            CATALOG_COMPACT_FLOOR_BYTES - 1,
            target
        ));
        // Tiny target: floor still bounds.
        assert!(!catalog_run_is_compact_candidate(
            50 * 1024 * 1024,
            64 * 1024 * 1024
        ));
    }

    #[test]
    fn recollect_spill_bytes_parse_clamps() {
        assert_eq!(
            parse_recollect_spill_bytes(None),
            RECOLLECT_THREAD_SPILL_BYTES
        );
        assert_eq!(
            parse_recollect_spill_bytes(Some("not-a-number")),
            RECOLLECT_THREAD_SPILL_BYTES
        );
        assert_eq!(
            parse_recollect_spill_bytes(Some("1")),
            16 * 1024 * 1024,
            "below 16MiB clamps up"
        );
        assert_eq!(
            parse_recollect_spill_bytes(Some("999999999999")),
            512 * 1024 * 1024,
            "above 512MiB clamps down"
        );
        assert_eq!(
            parse_recollect_spill_bytes(Some("268435456")),
            256 * 1024 * 1024
        );
        assert_eq!(
            catalog_compact_floor_bytes(RECOLLECT_THREAD_SPILL_BYTES),
            CATALOG_COMPACT_FLOOR_BYTES
        );
        assert_eq!(
            catalog_compact_floor_bytes(256 * 1024 * 1024),
            192 * 1024 * 1024
        );
    }

    #[test]
    fn ram_shard_materialize_env_parse() {
        assert!(!parse_sh_materialize_ram_shard(None));
        assert!(!parse_sh_materialize_ram_shard(Some("kway")));
        assert!(!parse_sh_materialize_ram_shard(Some("1")));
        assert!(parse_sh_materialize_ram_shard(Some("ram-shard")));
        assert!(parse_sh_materialize_ram_shard(Some("RAM-SHARD")));
    }

    #[test]
    fn plan_pre_materialize_durable_head_never_clamps_seal_to_zero() {
        // Skeptic regression: high SEAL + empty runs + missing HWM must NOT
        // reset SEAL (old code treated catalog incomplete → clamp to hwm=0).
        let seal = 1_411_000_000u64;
        let tip = 1_411_000_000u64;
        assert_eq!(
            plan_sh_pre_materialize(false, true, seal, tip, 0, 0),
            ShPreMaterializeAction::BootstrapIncludeHwm { seal }
        );
        assert_eq!(
            plan_sh_pre_materialize(false, true, seal, tip, 222_511, 0),
            ShPreMaterializeAction::BootstrapIncludeHwm { seal }
        );
        // Authoritative HWM below SEAL, **no residual runs** → clamp (never to 0).
        assert_eq!(
            plan_sh_pre_materialize(false, true, seal, tip, 0, 1_400_000_000),
            ShPreMaterializeAction::ClampSealTo {
                floor: 1_400_000_000
            }
        );
        // HWM below SEAL but residual runs already hold the gap → warm only (no re-recollect).
        assert_eq!(
            plan_sh_pre_materialize(false, true, seal, tip, 295_466, 1_400_000_000),
            ShPreMaterializeAction::Noop,
            "residual runs must not clamp+recollect (mainnet warm-apply peg)"
        );
        // Healthy: HWM == SEAL, empty residual runs.
        assert_eq!(
            plan_sh_pre_materialize(false, true, seal, tip, 0, seal),
            ShPreMaterializeAction::Noop
        );
        assert_eq!(durable_sh_inclusion_floor(0, seal), seal);
        assert_eq!(durable_sh_inclusion_floor(99, seal), 99);
    }

    #[test]
    fn plan_pre_materialize_empty_head_stale_tail_full_recollect() {
        let seal = 1_411_832_114u64;
        let tip = 1_416_000_000u64;
        assert_eq!(
            plan_sh_pre_materialize(false, false, seal, tip, 222_511, 0),
            ShPreMaterializeAction::ResetCatalogFullRecollect
        );
        // Empty runs + high SEAL + empty head (consumed catalog, no head).
        assert_eq!(
            plan_sh_pre_materialize(false, false, seal, seal, 0, 0),
            ShPreMaterializeAction::ResetCatalogFullRecollect
        );
        // Incomplete catalog + FORCE → nuclear.
        assert_eq!(
            plan_sh_pre_materialize(true, false, seal, tip, 222_511, 0),
            ShPreMaterializeAction::ForceFullRebuild
        );
        // Complete catalog + empty head + FORCE → cold from catalog (no wipe).
        assert_eq!(
            plan_sh_pre_materialize(true, false, tip, tip, 3_700_000_000, 0),
            ShPreMaterializeAction::ForceColdFromExistingCatalog
        );
        // Mainnet wipe regression: seal near tip, huge catalog, tip advanced past
        // SH_SEAL_LAG_OK during recollect — still cold-load, never seal=0 wipe.
        let seal_main = 1_411_839_527u64;
        let tip_main = 1_411_887_545u64;
        let recs_main = 3_741_750_509u64;
        assert_eq!(
            plan_sh_pre_materialize(true, false, seal_main, tip_main, recs_main, 0),
            ShPreMaterializeAction::ForceColdFromExistingCatalog
        );
        // Same with multi-million tip advance past seal — catalog mass still usable.
        assert_eq!(
            plan_sh_pre_materialize(true, false, seal_main, seal_main + 5_000_000, recs_main, 0),
            ShPreMaterializeAction::ForceColdFromExistingCatalog,
            "usable catalog + tip lag must not ForceFullRebuild"
        );
        // Durable head + sticky FORCE even when floor lags tip → Noop (never wipe).
        assert_eq!(
            plan_sh_pre_materialize(true, true, seal, tip, 0, seal),
            ShPreMaterializeAction::Noop
        );
        // Durable + FORCE + missing HWM → bootstrap (not wipe).
        assert_eq!(
            plan_sh_pre_materialize(true, true, seal, tip, 0, 0),
            ShPreMaterializeAction::BootstrapIncludeHwm { seal }
        );
        // Good empty-head catalog without FORCE → Noop (FullCold from runs later).
        assert_eq!(
            plan_sh_pre_materialize(false, false, tip, tip, 3_700_000_000, 0),
            ShPreMaterializeAction::Noop
        );
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
        // Fake high SEAL + tiny run (incomplete catalog).
        store_seal(&runs_dir, 1_400_000_000).unwrap();
        b.refresh_seal();
        assert_eq!(b.sealed_max_create_fk(), 1_400_000_000);
        let mut body = Vec::new();
        body.extend_from_slice(&encode_rec(&[0xab; 32], Fk(99)));
        let path = next_run_path(&runs_dir, 1);
        write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();
        assert!(
            !sh_catalog_looks_complete(1_400_000_000, 1_410_000_000, 1),
            "tiny catalog must be incomplete"
        );

        b.prepare_force_full_rebuild(&store).unwrap();
        assert_eq!(b.sealed_max_create_fk(), 0);
        assert!(list_runs(&runs_dir).unwrap().is_empty());
        assert!(store.scripthash.head_is_empty());
        assert_eq!(store.scripthash.entry_count(), 0);
        assert_eq!(store.scripthash.include_hwm(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
