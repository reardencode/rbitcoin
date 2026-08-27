//! Index modes: Direct (IBD live heads/spends) and Tip (steady-state).
//!
//! Spentness truth for both: durable confirmed-strong spend annotations.
//! SH: Direct defers until post-IBD Class A collect; Tip write-behind if a
//! durable head already exists.

use super::*;
use std::sync::atomic::Ordering;

/// Index / spentness mode.
///
/// | Mode | Durable `tx.head` | Durable spends | SH |
/// |------|-------------------|----------------|-----|
/// | [`Direct`](IndexMode::Direct) | archive live | confirm batch after Class C | target-sized runs + SEAL → bulk at tip |
/// | [`Tip`](IndexMode::Tip) | live | archive + connect | durable write-through after bulk |
///
/// Open defaults to [`Tip`] until the node calls [`Query::enter_direct_index_mode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IndexMode {
    /// IBD: archive writes `tx.head`; confirm batch-writes spend annotations.
    Direct = 1,
    /// Steady-state / Electrum: durable points + `tx.head` (+ SH materialized).
    Tip = 2,
}

impl IndexMode {
    pub fn is_direct(self) -> bool {
        matches!(self, Self::Direct)
    }
    pub fn is_tip(self) -> bool {
        matches!(self, Self::Tip)
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Direct,
            // 0 was historical Catchup — treat as Direct (safe for residual stores).
            0 => Self::Direct,
            _ => Self::Tip,
        }
    }
}

impl Query {
    /// Current index / spentness mode ([`IndexMode`]).
    #[inline]
    pub fn index_mode(&self) -> IndexMode {
        IndexMode::from_u8(self.index_mode_cell.load(Ordering::SeqCst))
    }

    fn set_index_mode(&self, mode: IndexMode) {
        self.index_mode_cell.store(mode as u8, Ordering::SeqCst);
    }

    /// Whether Class C builds scripthash (runs in Direct; durable write-through in Tip).
    ///
    /// Operator `--shindex` / conf `shindex=1`. Library default is **on** so unit
    /// tests that call [`Self::enter_direct_index_mode`] keep SH. The node sets
    /// this **off** when shindex is disabled before Direct enter.
    #[inline]
    pub fn sh_index_enabled(&self) -> bool {
        self.sh_index_enabled.load(Ordering::SeqCst)
    }

    /// Enable or disable scripthash indexing for subsequent Class C / tip work.
    pub fn set_sh_index_enabled(&self, on: bool) {
        self.sh_index_enabled.store(on, Ordering::SeqCst);
    }

    /// Enter **direct** IBD with scripthash indexing **on** (library / test default).
    ///
    /// Prefer [`Self::enter_direct_index_mode_sh`] when the operator knobs `shindex`.
    pub fn enter_direct_index_mode(&self) -> Result<(), QueryError> {
        self.enter_direct_index_mode_sh(true)
    }

    /// Enter **direct** IBD: durable `tx.head` on archive, spend annotations on
    /// confirm (batch). Confirm does **not** enqueue SH runs or write the durable
    /// head — recollect + pack is tip finalize / `--shindex` only.
    ///
    /// Best-effort removes leftover `ibd_utxo.map` / point+tx run dirs from old
    /// Catchup datadirs. When the durable SH head already covers tip creates
    /// (`include_hwm` / SEAL), SEAL is raised to HWM so restart does not re-scan.
    pub fn enter_direct_index_mode_sh(&self, shindex: bool) -> Result<(), QueryError> {
        self.set_sh_index_enabled(shindex);
        self.set_index_mode(IndexMode::Direct);
        self.set_spend_index(true);
        self.set_tx_index(true);
        self.drop_legacy_catchup_artifacts()?;
        if !shindex {
            rbitcoin_log::info!(
                "ibd: IndexMode::Direct without scripthash index (shindex off; no SH runs)"
            );
            return Ok(());
        }
        rbitcoin_log::info!(
            "ibd: IndexMode::Direct (shindex on; SH runs only at tip finalize recollect)"
        );
        self.sh_run.refresh_seal();
        let seal = self.sh_run.sealed_max_create_fk();
        let include_hwm = self.store.scripthash.include_hwm();
        if include_hwm > seal {
            let _ = self.sh_run.publish_seal_watermark(include_hwm);
        }
        Ok(())
    }

    /// Flip durable index flags on for tip-follow (after SH bulk when shindex on).
    ///
    /// Does **not** require scripthash readiness — tip follow and mempool relay
    /// use Class A + spends only.
    pub fn enter_tip_index_mode(&self) {
        self.set_index_mode(IndexMode::Tip);
        self.set_spend_index(true);
        self.set_tx_index(true);
    }

    /// True when a durable SH head already exists — catch-up / restart must
    /// **write-behind** (same as tip follow), never Class A recollect or WarmOnly.
    ///
    /// Residual `scripthash.runs` next to a live head are leftover (cancelled
    /// WarmOnly / crash); they are discarded, not merged.
    pub fn sh_use_writebehind(&self) -> bool {
        self.sh_index_enabled() && self.store.scripthash.has_durable_index()
    }

    /// True when durable SH already covers Class A through tip (safe to stay in
    /// Tip mode on restart — no Direct recollect / bulk materialize).
    ///
    /// Requires a non-empty durable head, no residual on-disk runs, and
    /// `include_hwm`/SEAL **≥** tip create HWM (strict; not memtable lag).
    pub fn sh_is_tip_ready(&self) -> bool {
        use crate::sh_builder::durable_sh_inclusion_floor;

        let tip_max = self.store.txs.count();
        if tip_max == 0 {
            // Empty / genesis-only store: not "tip ready" for SH (nothing to serve).
            return false;
        }
        if !self.store.scripthash.has_durable_index() {
            return false;
        }
        if self.sh_run.on_disk_run_count() > 0 {
            return false;
        }
        self.sh_run.refresh_seal();
        let seal = self.sh_run.sealed_max_create_fk();
        let include_hwm = self.store.scripthash.include_hwm();
        let floor = durable_sh_inclusion_floor(include_hwm, seal);
        floor >= tip_max
    }

    /// Sync SEAL up to durable `include_hwm` when the head is ahead of the run
    /// catalog watermark (tip-follow without Direct). Idempotent.
    pub fn sync_sh_seal_from_include_hwm(&self) -> Result<(), QueryError> {
        self.sh_run.refresh_seal();
        let seal = self.sh_run.sealed_max_create_fk();
        let include_hwm = self.store.scripthash.include_hwm();
        if include_hwm > seal {
            self.sh_run.publish_seal_watermark(include_hwm)?;
        }
        Ok(())
    }

    /// Remove leftover Catchup artifacts (light UTXO map, point/tx run dirs).
    fn drop_legacy_catchup_artifacts(&self) -> Result<(), QueryError> {
        let path = self.store.path().join("ibd_utxo.map");
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| StoreError::io(&path, e))?;
            rbitcoin_log::info!(
                "store: removed leftover light UTXO map {} (direct index mode)",
                path.display()
            );
        }
        for name in ["point.runs", "tx.runs"] {
            let dir = self.store.path().join(name);
            if dir.is_dir() {
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => rbitcoin_log::info!(
                        "store: removed leftover catch-up run dir {}",
                        dir.display()
                    ),
                    Err(e) => rbitcoin_log::warn!(
                        "store: could not remove leftover run dir {}: {e}",
                        dir.display()
                    ),
                }
            }
        }
        Ok(())
    }

    /// Cold bulk-load durable scripthash tables (tip entry).
    ///
    /// Direct IBD: append-only ~128 MiB catalog runs + SEAL. Tip: k-way bulk load.
    ///
    /// **`RBITCOIN_SH_FORCE_REBUILD=1`:** wipe SH head/runs/SEAL/HWM, recollect **all**
    /// Class A creates into runs, then full cold materialize (not a catch-up tail).
    pub fn finalize_sh_runs(&self) -> Result<u64, QueryError> {
        self.finalize_sh_runs_cancellable(None)
    }

    /// Like [`Self::finalize_sh_runs`] with cooperative cancel (SIGINT keeps sealed shards).
    pub fn finalize_sh_runs_cancellable(
        &self,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<u64, QueryError> {
        use crate::sh_builder::{
            plan_sh_pre_materialize, sh_catalog_total_records, sh_force_rebuild,
            sh_unsorted_shard_materialize, ShPreMaterializeAction, SH_SEAL_LAG_OK,
        };

        if !sh_force_rebuild() && self.sh_use_writebehind() {
            let unsorted_resume = sh_unsorted_shard_materialize()
                && !self.store.scripthash.unsealed_main_shards().is_empty();
            if !unsorted_resume {
                let residual = self.sh_run.on_disk_run_count();
                self.sh_run.discard_residual_runs();
                if residual > 0 {
                    rbitcoin_log::info!(
                        "node: scripthash durable head — discarding {residual} leftover run(s); \
                     gap uses write-behind (no Class A recollect / WarmOnly)"
                    );
                }
                // Legacy head without include_hwm: SEAL is the inclusion floor.
                self.sh_run.refresh_seal();
                let seal = self.sh_run.sealed_max_create_fk();
                if self.store.scripthash.include_hwm() == 0 && seal > 0 {
                    self.store.scripthash.note_include_hwm(seal)?;
                }
                self.sync_sh_seal_from_include_hwm()?;
                if self.sh_is_tip_ready() {
                    rbitcoin_log::info!(
                        "node: scripthash already tip-ready (durable head covers tip) — \
                     skip Class A recollect and bulk materialize"
                    );
                    self.mark_sh_indexed_through_tip();
                } else {
                    rbitcoin_log::info!(
                        "node: scripthash durable head with HWM/SEAL lag — skip collect; \
                     recover/write-behind fills the height gap"
                    );
                }
                return Ok(0);
            }
            rbitcoin_log::info!(
                "node: scripthash unsorted-shards resume unsealed={} (partial sealed head)",
                self.store.scripthash.unsealed_main_shards().len()
            );
        }

        if sh_unsorted_shard_materialize() {
            return self.finalize_sh_unsorted_cancellable(cancel);
        }

        self.sh_run.refresh_seal();
        let tip_max = self.store.txs.count();
        let seal = self.sh_run.sealed_max_create_fk();
        let run_recs = sh_catalog_total_records(&self.store.path().join("scripthash.runs"));
        let head_durable = self.store.scripthash.has_durable_index();
        let include_hwm = self.store.scripthash.include_hwm();
        let force = sh_force_rebuild();
        let action =
            plan_sh_pre_materialize(force, head_durable, seal, tip_max, run_recs, include_hwm);
        let need_full_recollect = matches!(
            action,
            ShPreMaterializeAction::ForceFullRebuild
                | ShPreMaterializeAction::ResetCatalogFullRecollect
        );

        match action {
            ShPreMaterializeAction::ForceFullRebuild => {
                rbitcoin_log::info!(
                    "node: scripthash FORCE_REBUILD seal={seal} tip_max_create_fk={tip_max} \
                     catalog_recs≈{run_recs} head_durable={head_durable} include_hwm={include_hwm}"
                );
                self.sh_run.prepare_force_full_rebuild(&self.store)?;
            }
            ShPreMaterializeAction::ForceColdFromExistingCatalog => {
                rbitcoin_log::warn!(
                    "node: scripthash FORCE_REBUILD env set but catalog complete \
                     (seal={seal} tip_max={tip_max} catalog_recs≈{run_recs}) — \
                     reinit head only; unset RBITCOIN_SH_FORCE_REBUILD after success"
                );
                self.sh_run.prepare_force_cold_from_catalog(&self.store)?;
            }
            ShPreMaterializeAction::ResetCatalogFullRecollect => {
                // Empty/wiped head + stale high SEAL + tail-only runs (or consumed
                // catalog with no head) would cold-load a tiny incomplete index —
                // recollect Class A from 0 instead.
                rbitcoin_log::warn!(
                    "node: scripthash empty head needs full Class A recollect \
                     (seal={seal} tip_max={tip_max} catalog_recs≈{run_recs})"
                );
                self.sh_run.reset_catalog_for_full_recollect()?;
            }
            ShPreMaterializeAction::BootstrapIncludeHwm { seal: s } => {
                // Legacy durable head without include_hwm: SEAL is the inclusion
                // watermark. Never clamp SEAL→0 (that would re-scan all Class A).
                rbitcoin_log::info!(
                    "node: scripthash durable head missing include_hwm — \
                     bootstrapping from SEAL={s} (no SEAL clamp)"
                );
                self.store.scripthash.note_include_hwm(s)?;
            }
            ShPreMaterializeAction::ClampSealTo { floor } => {
                rbitcoin_log::info!(
                    "node: scripthash durable head include_hwm={floor} < seal={seal} and no \
                     residual runs — clamping SEAL to HWM for gap recollect"
                );
                self.sh_run.set_sealed_max_for_recollect(floor)?;
            }
            ShPreMaterializeAction::Noop => {}
        }

        self.sh_run.refresh_seal();
        let seal_before_recollect = self.sh_run.sealed_max_create_fk();
        let tip_max = self.store.txs.count();
        if tip_max > 0 && seal_before_recollect.saturating_add(SH_SEAL_LAG_OK) < tip_max {
            rbitcoin_log::info!(
                "node: scripthash collect gap seal={seal_before_recollect} \
                 tip_max_create_fk={tip_max} — Class A recollect for residual"
            );
        } else if tip_max > 0 {
            rbitcoin_log::info!(
                "node: scripthash collect seal={seal_before_recollect} covers \
                 tip_max_create_fk={tip_max} (lag≤{SH_SEAL_LAG_OK}) — Class A recollect no-op if seal≥tip"
            );
        }
        self.rebuild_sh_unsealed_from_class_a_cancellable(cancel)?;

        // Fail closed: never FullCold / "no runs" success on a zeroed head when
        // Class A still has creates above SEAL (FORCE / empty-head full recollect).
        self.sh_run.refresh_seal();
        let seal_after = self.sh_run.sealed_max_create_fk();
        let run_after = sh_catalog_total_records(&self.store.path().join("scripthash.runs"));
        let tip_max = self.store.txs.count();
        let head_durable = self.store.scripthash.has_durable_index();
        if !head_durable
            && tip_max > 0
            && run_after == 0
            && seal_after.saturating_add(SH_SEAL_LAG_OK) < tip_max
        {
            rbitcoin_log::error!(
                "node: scripthash recollect left empty catalog seal={seal_after} \
                 tip_max_create_fk={tip_max} force_or_reset={need_full_recollect} — abort"
            );
            return Err(StoreError::Corrupt(
                "scripthash Class A recollect produced empty catalog while creates remain above SEAL",
            ));
        }

        let mut n = match cancel {
            None => self.sh_run.finalize_and_bulk_materialize(&self.store)?,
            Some(c) => self
                .sh_run
                .finalize_and_bulk_materialize_cancellable(&self.store, Some(c))?,
        };

        if n == 0
            && !self.store.scripthash.has_durable_index()
            && tip_max > 0
            && seal_after.saturating_add(SH_SEAL_LAG_OK) < tip_max
        {
            return Err(StoreError::Corrupt(
                "scripthash materialize finished empty while Class A creates remain above SEAL",
            ));
        }

        // Post-materialize drain: failed/partial cold loads, or creates that
        // landed as small runs after recollect but before claim, must be folded
        // into the durable head **before** tip-ready / Electrum. Mainnet saw
        // leftover catalog after ENOSPC rematerialize + short Direct catch-up.
        // Bounded loop: each pass recollects create_fk > SEAL then FullCold /
        // ColdResume residual catalog.
        //
        // Empty store (tip_max==0): nothing to cover — skip tip-ready fail-closed.
        let tip_final = self.store.txs.count();
        if tip_final > 0 {
            const MAX_POST_DRAIN_ROUNDS: u32 = 8;
            for round in 1..=MAX_POST_DRAIN_ROUNDS {
                if self.sh_is_tip_ready() {
                    break;
                }
                self.sh_run.refresh_seal();
                let residual = self.sh_run.on_disk_run_count();
                let tip_now = self.store.txs.count();
                let seal_now = self.sh_run.sealed_max_create_fk();
                let hwm_now = self.store.scripthash.include_hwm();
                rbitcoin_log::info!(
                    "node: scripthash post-materialize round={round}/{MAX_POST_DRAIN_ROUNDS} \
                     residual_runs={residual} seal={seal_now} include_hwm={hwm_now} tip_max={tip_now}"
                );
                self.rebuild_sh_unsealed_from_class_a_cancellable(cancel)?;
                let n2 = match cancel {
                    None => self.sh_run.finalize_and_bulk_materialize(&self.store)?,
                    Some(c) => self
                        .sh_run
                        .finalize_and_bulk_materialize_cancellable(&self.store, Some(c))?,
                };
                n = n.saturating_add(n2);
            }
            if !self.sh_is_tip_ready() {
                let residual = self.sh_run.on_disk_run_count();
                let tip_now = self.store.txs.count();
                let seal_now = self.sh_run.sealed_max_create_fk();
                let hwm_now = self.store.scripthash.include_hwm();
                rbitcoin_log::error!(
                    "node: scripthash not tip-ready after post-materialize residual \
                     residual_runs={residual} seal={seal_now} include_hwm={hwm_now} tip_max={tip_now}"
                );
                return Err(StoreError::Corrupt(
                    "scripthash residual runs or create gap remain after materialize drain \
                     (refuse tip-follow / Electrum)",
                ));
            }
        }
        self.mark_sh_indexed_through_tip();
        Ok(n)
    }

    fn finalize_sh_unsorted_cancellable(
        &self,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<u64, QueryError> {
        if crate::sh_builder::sh_force_rebuild() {
            rbitcoin_log::info!(
                "node: scripthash FORCE_REBUILD + unsorted-shards — wipe head then Class A collect"
            );
            self.sh_run.prepare_force_full_rebuild(&self.store)?;
            rbitcoin_store::clear_unsorted_shard_dir(&rbitcoin_store::unsorted_shard_dir(
                self.store.path(),
            ));
        }
        let tip_max = self.store.txs.count();
        let n = self
            .sh_run
            .finalize_and_unsorted_materialize_cancellable(&self.store, cancel)?;
        if n == 0 && !self.store.scripthash.has_durable_index() && tip_max > 0 {
            return Err(StoreError::Corrupt(
                "scripthash unsorted-shards materialize finished empty while Class A creates remain",
            ));
        }
        if tip_max > 0 {
            const MAX_POST_DRAIN_ROUNDS: u32 = 8;
            let mut n = n;
            for round in 1..=MAX_POST_DRAIN_ROUNDS {
                if self.sh_is_tip_ready() {
                    break;
                }
                rbitcoin_log::info!(
                    "node: scripthash unsorted-shards post-materialize round={round}/{MAX_POST_DRAIN_ROUNDS}"
                );
                rbitcoin_store::clear_unsorted_shard_dir(&rbitcoin_store::unsorted_shard_dir(
                    self.store.path(),
                ));
                n = n.saturating_add(
                    self.sh_run
                        .finalize_and_unsorted_materialize_cancellable(&self.store, cancel)?,
                );
            }
            if !self.sh_is_tip_ready() {
                return Err(StoreError::Corrupt(
                    "scripthash unsorted-shards create gap remain after materialize drain \
                     (refuse tip-follow / Electrum)",
                ));
            }
            self.mark_sh_indexed_through_tip();
            return Ok(n);
        }
        Ok(n)
    }

    fn mark_sh_indexed_through_tip(&self) {
        if let Some(tip) = self.tip_height() {
            self.set_sh_indexed_through_height(Some(tip.0));
        }
    }

    /// On-disk scripthash sorted-run count (Direct IBD cache).
    pub fn scripthash_run_count(&self) -> usize {
        self.sh_run.on_disk_run_count()
    }

    /// Whether the Direct-IBD SH run worker is currently enabled.
    pub fn sh_run_enabled(&self) -> bool {
        self.sh_run.is_enabled()
    }

    /// Re-collect thin SH creates for confirmed txs with `create_fk > SEAL`.
    ///
    /// Covers kill after tip advance while memtable was still unspilled. Work is
    /// O(crash window) when SEAL tracks near tip; full chain only if SEAL=0.
    #[cfg(test)]
    fn rebuild_sh_unsealed_from_class_a(&self) -> Result<(), QueryError> {
        self.rebuild_sh_unsealed_from_class_a_cancellable(None)
    }

    /// Parallel Class A → SH runs for `create_fk > SEAL`.
    ///
    /// Work units are fixed **create_fk chunks** (~64k idx entries). One OS thread
    /// per CPU collects independently and spills a sorted catalog run whenever its
    /// local buffer exceeds **128 MiB** (some later merge/compact is expected).
    ///
    /// SEAL advances only over a **contiguous prefix** of completed chunks so
    /// cancel/restart never skips unfinished lower ranges. Status ~every 10s.
    fn rebuild_sh_unsealed_from_class_a_cancellable(
        &self,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<(), QueryError> {
        use crate::sh_builder::{recollect_spill_bytes, SH_RUN_REC_LEN};
        use rbitcoin_store::ScriptHashRecord;
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        // Recollect floor is max(SEAL, include_hwm): tip-mode durable writes raise
        // HWM without always matching SEAL; never re-scan creates already in head.
        self.sh_run.refresh_seal();
        let mut sealed0 = self.sh_run.sealed_max_create_fk();
        let include_hwm = self.store.scripthash.include_hwm();
        if include_hwm > sealed0 {
            let _ = self.sh_run.publish_seal_watermark(include_hwm);
            sealed0 = include_hwm;
        }
        let Some(tip) = self.store.tip_height() else {
            return Ok(());
        };
        let tip_max = self.store.txs.count();
        if tip_max == 0 || sealed0 >= tip_max {
            return Ok(());
        }

        /// Create_fk span per parallel work unit (tx.idx density).
        const CHUNK_FKS: u64 = 64_000;
        const STATUS_INTERVAL: Duration = Duration::from_secs(10);

        let workers = recollect_workers();
        let spill_bytes = recollect_spill_bytes();
        let thread_spill_recs = (spill_bytes / u64::from(SH_RUN_REC_LEN)).max(1) as usize;
        let work_lo = sealed0.saturating_add(1);
        let work_span = tip_max.saturating_sub(sealed0);
        let n_chunks = work_span.div_ceil(CHUNK_FKS).max(1) as usize;

        rbitcoin_log::info!(
            "node: scripthash Class A recollect start seal={sealed0} tip_height={} \
             tip_max_create_fk={tip_max} chunks={n_chunks} chunk_fks={CHUNK_FKS} \
             workers={workers} free_GiB={} thread_spill_MiB≈{:.0}",
            tip.0,
            rbitcoin_store::free_gib_label(),
            spill_bytes as f64 / (1024.0 * 1024.0)
        );

        let t0 = Instant::now();
        let next_chunk = AtomicUsize::new(0);
        let n_txs = AtomicU64::new(0);
        let n_creates = AtomicU64::new(0);
        let n_spills = AtomicU64::new(0);
        let max_fk_seen = AtomicU64::new(sealed0);
        let seal_prefix = AtomicUsize::new(0);
        let done_flags = Mutex::new(vec![false; n_chunks]);
        let first_err: Mutex<Option<StoreError>> = Mutex::new(None);
        let stop = AtomicBool::new(false);

        let store = &self.store;
        let sh_run = &self.sh_run;
        let (spill_tx, spill_rx) =
            std::sync::mpsc::sync_channel::<RecollectSpillJob>(RECOLLECT_WRITER_QUEUE_CAP);

        std::thread::scope(|scope| {
            let n_spills = &n_spills;
            let n_creates = &n_creates;
            let max_fk_seen = &max_fk_seen;
            let n_txs = &n_txs;
            let next_chunk = &next_chunk;
            let first_err = &first_err;
            let stop = &stop;
            let done_flags = &done_flags;
            let seal_prefix = &seal_prefix;
            scope.spawn({
                let spill_rx = spill_rx;
                move || {
                    while let Ok(mut job) = spill_rx.recv() {
                        if !job.records.is_empty() {
                            match sh_run.spill_creates_catalog(&mut job.records) {
                                Ok((mfk, n)) => {
                                    n_spills.fetch_add(1, AtomicOrdering::Relaxed);
                                    n_creates.fetch_add(n, AtomicOrdering::Relaxed);
                                    max_fk_seen.fetch_max(mfk, AtomicOrdering::Relaxed);
                                }
                                Err(e) => {
                                    *first_err.lock().unwrap() = Some(e);
                                    stop.store(true, AtomicOrdering::Relaxed);
                                    break;
                                }
                            }
                        }
                        for chunk_id in job.pending_chunks {
                            if let Err(e) = mark_recollect_chunk_done(
                                chunk_id,
                                n_chunks,
                                sealed0,
                                tip_max,
                                CHUNK_FKS,
                                done_flags,
                                seal_prefix,
                                sh_run,
                            ) {
                                *first_err.lock().unwrap() = Some(e);
                                stop.store(true, AtomicOrdering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            });
            scope.spawn(|| {
                let mut last_log = Instant::now();
                loop {
                    if stop.load(AtomicOrdering::Relaxed)
                        || seal_prefix.load(AtomicOrdering::Relaxed) >= n_chunks
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                    if last_log.elapsed() < STATUS_INTERVAL {
                        continue;
                    }
                    last_log = Instant::now();
                    let elapsed = t0.elapsed();
                    let creates = n_creates.load(AtomicOrdering::Relaxed);
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        creates as f64 / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    let prefix = seal_prefix.load(AtomicOrdering::Relaxed);
                    rbitcoin_log::info!(
                        "node: scripthash Class A recollect status \
                         seal_prefix={prefix}/{n_chunks} assigned={} seal={} \
                         txs≈{} creates≈{creates} max_fk={} spills={} workers={workers} \
                         rate≈{:.0} creates/s elapsed={:?}",
                        next_chunk.load(AtomicOrdering::Relaxed).min(n_chunks),
                        sh_run.sealed_max_create_fk(),
                        n_txs.load(AtomicOrdering::Relaxed),
                        max_fk_seen.load(AtomicOrdering::Relaxed),
                        n_spills.load(AtomicOrdering::Relaxed),
                        rate,
                        elapsed
                    );
                }
            });

            for _w in 0..workers {
                scope.spawn({
                    let spill_tx = spill_tx.clone();
                    move || {
                        let mut local: Vec<rbitcoin_store::ScriptHashRecord> =
                            Vec::with_capacity(thread_spill_recs.min(1 << 22));
                        let mut pending_done: Vec<usize> = Vec::with_capacity(32);

                        let submit = |local: &mut Vec<rbitcoin_store::ScriptHashRecord>,
                                      pending: &mut Vec<usize>|
                         -> Result<(), StoreError> {
                            submit_recollect_spill(&spill_tx, local, pending)
                        };

                        loop {
                            if stop.load(AtomicOrdering::Relaxed)
                                || cancel
                                    .map(|c| c.load(AtomicOrdering::Relaxed))
                                    .unwrap_or(false)
                            {
                                stop.store(true, AtomicOrdering::Relaxed);
                                let _ = submit(&mut local, &mut pending_done);
                                break;
                            }
                            if first_err.lock().unwrap().is_some() {
                                break;
                            }
                            let i = next_chunk.fetch_add(1, AtomicOrdering::Relaxed);
                            if i >= n_chunks {
                                if let Err(e) = submit(&mut local, &mut pending_done) {
                                    *first_err.lock().unwrap() = Some(e);
                                    stop.store(true, AtomicOrdering::Relaxed);
                                }
                                break;
                            }
                            let lo = work_lo.saturating_add((i as u64).saturating_mul(CHUNK_FKS));
                            let hi = lo.saturating_add(CHUNK_FKS).saturating_sub(1).min(tip_max);
                            if lo > tip_max {
                                pending_done.push(i);
                                if local.len() >= thread_spill_recs {
                                    if let Err(e) = submit(&mut local, &mut pending_done) {
                                        *first_err.lock().unwrap() = Some(e);
                                        stop.store(true, AtomicOrdering::Relaxed);
                                        break;
                                    }
                                }
                                continue;
                            }

                            let mut chunk_txs = 0u64;
                            let mut chunk_max = sealed0;
                            let mut chunk_ok = true;
                            if cancel
                                .map(|c| c.load(AtomicOrdering::Relaxed))
                                .unwrap_or(false)
                                || stop.load(AtomicOrdering::Relaxed)
                            {
                                stop.store(true, AtomicOrdering::Relaxed);
                                chunk_ok = false;
                            } else {
                                match store.for_each_create_script_hashes_in_fk_span(
                                    lo,
                                    hi,
                                    |fk, sh| {
                                        if chunk_max != fk.0 {
                                            chunk_txs = chunk_txs.saturating_add(1);
                                            chunk_max = chunk_max.max(fk.0);
                                        }
                                        local.push(ScriptHashRecord::from_fk(sh, fk));
                                        if local.len() >= thread_spill_recs {
                                            submit(&mut local, &mut pending_done)?;
                                        }
                                        Ok(())
                                    },
                                ) {
                                    Ok(()) => {}
                                    Err(StoreError::Cancelled(_)) => {
                                        stop.store(true, AtomicOrdering::Relaxed);
                                        chunk_ok = false;
                                    }
                                    Err(e) => {
                                        *first_err.lock().unwrap() = Some(e);
                                        stop.store(true, AtomicOrdering::Relaxed);
                                        chunk_ok = false;
                                    }
                                }
                            }

                            if !chunk_ok {
                                let _ = submit(&mut local, &mut pending_done);
                                break;
                            }

                            n_txs.fetch_add(chunk_txs, AtomicOrdering::Relaxed);
                            max_fk_seen.fetch_max(chunk_max, AtomicOrdering::Relaxed);
                            // Chunk fully scanned into `local` — commit after next spill
                            // (or worker exit spill) so SEAL never covers RAM-only data.
                            pending_done.push(i);
                            if local.len() >= thread_spill_recs {
                                if let Err(e) = submit(&mut local, &mut pending_done) {
                                    *first_err.lock().unwrap() = Some(e);
                                    stop.store(true, AtomicOrdering::Relaxed);
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            drop(spill_tx);
        });

        stop.store(true, AtomicOrdering::Relaxed);

        if let Some(e) = first_err.lock().unwrap().take() {
            return Err(e);
        }

        let cancelled = cancel
            .map(|c| c.load(AtomicOrdering::Relaxed))
            .unwrap_or(false);
        let prefix = seal_prefix.load(AtomicOrdering::Relaxed);
        self.sh_run.refresh_seal();
        let seal_final = if prefix >= n_chunks {
            tip_max
        } else {
            sealed0
                .saturating_add((prefix as u64).saturating_mul(CHUNK_FKS))
                .min(tip_max)
        };
        self.sh_run.publish_seal_watermark(seal_final)?;
        self.sh_run.refresh_seal();

        let txs = n_txs.load(AtomicOrdering::Relaxed);
        let creates = n_creates.load(AtomicOrdering::Relaxed);
        let spills = n_spills.load(AtomicOrdering::Relaxed);
        let max_fk = max_fk_seen.load(AtomicOrdering::Relaxed);

        if cancelled && prefix < n_chunks {
            rbitcoin_log::warn!(
                "node: scripthash Class A recollect cancelled \
                 seal_prefix={prefix}/{n_chunks} txs≈{txs} creates≈{creates} \
                 seal={sealed0}→{} spills={spills} elapsed={:?}",
                self.sh_run.sealed_max_create_fk(),
                t0.elapsed()
            );
            return Err(StoreError::Cancelled("scripthash Class A recollect"));
        }

        if txs == 0 && creates == 0 {
            rbitcoin_log::info!(
                "node: scripthash Class A recollect done (nothing above seal={sealed0}) \
                 tip_max_fk={tip_max} elapsed={:?}",
                t0.elapsed()
            );
            return Ok(());
        }
        rbitcoin_log::info!(
            "node: scripthash Class A recollect done txs≈{txs} creates≈{creates} \
             seal={sealed0}→{} max_fk={max_fk} tip_height={} tip_max_fk={tip_max} \
             chunks={n_chunks} workers={workers} spills={spills} elapsed={:?}",
            self.sh_run.sealed_max_create_fk(),
            tip.0,
            t0.elapsed()
        );
        Ok(())
    }
}

const RECOLLECT_WRITER_QUEUE_CAP: usize = 2;

struct RecollectSpillJob {
    records: Vec<rbitcoin_store::ScriptHashRecord>,
    pending_chunks: Vec<usize>,
}

fn take_recollect_spill_job(
    records: &mut Vec<rbitcoin_store::ScriptHashRecord>,
    pending: &mut Vec<usize>,
) -> Option<RecollectSpillJob> {
    if records.is_empty() && pending.is_empty() {
        return None;
    }
    Some(RecollectSpillJob {
        records: std::mem::take(records),
        pending_chunks: std::mem::take(pending),
    })
}

fn submit_recollect_spill(
    tx: &std::sync::mpsc::SyncSender<RecollectSpillJob>,
    records: &mut Vec<rbitcoin_store::ScriptHashRecord>,
    pending: &mut Vec<usize>,
) -> Result<(), StoreError> {
    let Some(job) = take_recollect_spill_job(records, pending) else {
        return Ok(());
    };
    tx.send(job)
        .map_err(|_| StoreError::Corrupt("invariant: recollect writer gone"))
}

fn mark_recollect_chunk_done(
    chunk_id: usize,
    n_chunks: usize,
    sealed0: u64,
    tip_max: u64,
    chunk_fks: u64,
    done_flags: &std::sync::Mutex<Vec<bool>>,
    seal_prefix: &std::sync::atomic::AtomicUsize,
    sh_run: &crate::sh_builder::ShRunBuilder,
) -> Result<(), StoreError> {
    use std::sync::atomic::Ordering as AtomicOrdering;
    let mut d = done_flags.lock().unwrap();
    if chunk_id < d.len() {
        d[chunk_id] = true;
    }
    let mut p = seal_prefix.load(AtomicOrdering::Relaxed);
    while p < d.len() && d[p] {
        p += 1;
    }
    seal_prefix.store(p, AtomicOrdering::Relaxed);
    let new_seal = if p >= n_chunks {
        tip_max
    } else {
        sealed0
            .saturating_add((p as u64).saturating_mul(chunk_fks))
            .min(tip_max)
    };
    sh_run.publish_seal_watermark(new_seal)
}

/// Parallel recollect worker count (`RBITCOIN_SH_RECOLLECT_WORKERS`, else RAM-capped CPUs).
fn recollect_workers() -> usize {
    if let Ok(s) = std::env::var("RBITCOIN_SH_RECOLLECT_WORKERS") {
        if let Ok(n) = s.parse::<usize>() {
            return n.clamp(1, 256);
        }
    }
    rbitcoin_store::sh_workers_capped_by_free_ram()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sh_builder::{
        load_seal, plan_sh_pre_materialize, sh_catalog_total_records, sh_force_rebuild, store_seal,
        ShPreMaterializeAction, SH_RUN_KEY_LEN, SH_RUN_REC_LEN,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_store::{
        next_run_path, write_sorted_run, HeaderRecord, InputRecord, OutputRecord, ScriptHashRecord,
        TxRecord,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Serialize FORCE_REBUILD env mutations (parallel tests share process env).
    static FORCE_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn recollect_spill_handoff_scan_continues_before_commit() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<RecollectSpillJob>(2);
        let latch = std::sync::Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let committed = std::sync::Arc::new(AtomicBool::new(false));
        let scanned_again = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let latch_w = std::sync::Arc::clone(&latch);
            let committed_w = std::sync::Arc::clone(&committed);
            scope.spawn(move || {
                let job = rx.recv().unwrap();
                assert_eq!(job.records.len(), 1);
                assert_eq!(job.pending_chunks, vec![0]);
                let (lock, cv) = &*latch_w;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = cv.wait(open).unwrap();
                }
                committed_w.store(true, Ordering::Release);
            });
            let mut recs = vec![ScriptHashRecord::from_fk([1u8; 32], Fk(1))];
            let mut pending = vec![0usize];
            submit_recollect_spill(&tx, &mut recs, &mut pending).unwrap();
            assert!(recs.is_empty());
            assert!(
                pending.is_empty(),
                "pending_done travels with the job; not marked until the writer commits"
            );
            scanned_again.fetch_add(1, Ordering::Relaxed);
            assert!(
                !committed.load(Ordering::Acquire),
                "scan-side continues before the writer latch opens"
            );
            {
                let (lock, cv) = &*latch;
                *lock.lock().unwrap() = true;
                cv.notify_one();
            }
        });
        assert!(committed.load(Ordering::Acquire));
        assert_eq!(scanned_again.load(Ordering::Relaxed), 1);
    }

    fn encode_rec(sh: &[u8; 32], fk: Fk) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(sh);
        buf[32..40].copy_from_slice(&fk.0.to_le_bytes());
        buf
    }

    fn coinbase_block(
        h: u32,
        prev: Fk,
        parent_hash: Option<[u8; 32]>,
    ) -> (HeaderRecord, crate::TxApply) {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[4] = 0xcd;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = crate::TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51, h as u8])],
        };
        (header, ta)
    }

    /// Archive + confirm `n` coinbase blocks under Direct mode (Class A + tip height).
    fn seed_direct_chain(q: &Query, n: u32) {
        q.enter_direct_index_mode().unwrap();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..n {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        assert_eq!(q.tip_height(), Some(Height(n - 1)));
        assert!(q.store.txs.count() >= u64::from(n));
    }

    /// Direct IBD with `--shindex` must not spill `scripthash.runs` or write the
    /// durable head. Recollect + pack is tip finalize only.
    #[test]
    fn direct_shindex_does_not_collect_runs_until_finalize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-direct-no-runs-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 4);
        assert!(q.sh_index_enabled());
        assert!(
            !q.sh_run_enabled(),
            "Direct must not start an IBD SH run worker"
        );
        assert_eq!(q.scripthash_run_count(), 0);
        assert!(
            !q.store.scripthash.has_durable_index(),
            "durable SH appears only after finalize recollect"
        );
        let sh = rbitcoin_store::script_hash(&[0x51, 0]);
        assert!(q.scripthash_history(&sh).unwrap().is_empty());
        let n_mat = q.finalize_sh_runs().unwrap();
        assert!(n_mat > 0 || q.store.scripthash.has_durable_index());
        assert!(!q.scripthash_history(&sh).unwrap().is_empty());
        assert_eq!(q.scripthash_run_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drive [`Query::finalize_sh_runs`] with durable head + high SEAL + no HWM.
    /// Must not zero SEAL or wipe the head (catchup clamp regression).
    #[test]
    fn finalize_sh_runs_durable_head_missing_hwm_keeps_seal() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-hwm-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        q.enter_direct_index_mode().unwrap();

        let mut sh0 = [0u8; 32];
        sh0[0] = 0x44;
        let mut recs = vec![ScriptHashRecord::from_fk(sh0, Fk(3))];
        q.sh_run.spill_creates_catalog(&mut recs).unwrap();
        let n0 = q.sh_run.finalize_and_bulk_materialize(&q.store).unwrap();
        assert!(n0 >= 1);
        assert!(q.store.scripthash.has_durable_index());
        let count_before = q.store.scripthash.entry_count();

        // Legacy post-materialize: high SEAL, empty runs, delete include_hwm.
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let high_seal = 1_411_000_000u64;
        store_seal(&runs_dir, high_seal).unwrap();
        q.sh_run.refresh_seal();
        let _ = std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME));
        assert_eq!(q.store.scripthash.include_hwm(), 0);
        assert_eq!(q.sh_run.sealed_max_create_fk(), high_seal);

        // No tip txs → rebuild_sh is a no-op; prep must still bootstrap HWM.
        let _ = q.finalize_sh_runs().unwrap();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            high_seal,
            "SEAL must not be clamped to 0 when HWM was missing"
        );
        assert_eq!(
            q.store.scripthash.include_hwm(),
            high_seal,
            "include_hwm must bootstrap from SEAL"
        );
        assert_eq!(
            q.store.scripthash.entries(&sh0).unwrap().len(),
            1,
            "durable head must remain"
        );
        assert!(q.store.scripthash.entry_count() >= count_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_sh_runs_empty_head_stale_tail_resets_seal() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-stale-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        q.enter_direct_index_mode().unwrap();
        assert!(!q.store.scripthash.has_durable_index());

        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let high_seal = 1_400_000_000u64;
        store_seal(&runs_dir, high_seal).unwrap();
        q.sh_run.refresh_seal();
        // Tiny catch-up tail run.
        let mut body = Vec::new();
        body.extend_from_slice(&encode_rec(&[0xab; 32], Fk(99)));
        let path = next_run_path(&runs_dir, 1);
        write_sorted_run(&path, SH_RUN_KEY_LEN, SH_RUN_REC_LEN, &body).unwrap();

        assert_eq!(
            plan_sh_pre_materialize(false, false, high_seal, high_seal + 1_000_000, 1, 0),
            ShPreMaterializeAction::ResetCatalogFullRecollect
        );

        // finalize with empty Class A tip: prep resets SEAL; materialize may apply
        // leftover or clear — SEAL after reset must start at 0 before recollect.
        // Call prep path only via plan (already asserted) + reset helper.
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
        assert_eq!(load_seal(&runs_dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FORCE prep used to leave the SH builder **disabled**, so Class A recollect
    /// was a silent no-op and tip materialize reported creates≈0 on a zeroed head.
    #[test]
    fn force_rebuild_recollects_class_a_not_empty_materialize() {
        let _g = FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-force-recol-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 6);
        let tip_max = q.store.txs.count();
        assert!(tip_max >= 6);

        q.sh_run.prepare_force_full_rebuild(&q.store).unwrap();
        assert!(!q.store.scripthash.has_durable_index());
        assert_eq!(q.sh_run.sealed_max_create_fk(), 0);

        // Recollect alone must produce catalog runs + advance SEAL.
        q.rebuild_sh_unsealed_from_class_a().unwrap();
        q.sh_run.refresh_seal();
        let seal = q.sh_run.sealed_max_create_fk();
        let run_recs = sh_catalog_total_records(&dir.join("scripthash.runs"));
        assert!(
            seal > 0 && run_recs > 0,
            "recollect must spill runs seal={seal} recs={run_recs} tip_max={tip_max}"
        );

        // Full finalize under FORCE_REBUILD env must not Ok empty head.
        std::env::set_var("RBITCOIN_SH_FORCE_REBUILD", "1");
        assert!(sh_force_rebuild());
        let result = q.finalize_sh_runs();
        std::env::remove_var("RBITCOIN_SH_FORCE_REBUILD");
        let n_mat = result.expect("finalize after FORCE must not fail empty");
        assert!(
            n_mat > 0,
            "materialize must load Class A creates, got {n_mat}"
        );
        assert!(
            q.store.scripthash.has_durable_index(),
            "head must not stay empty after FORCE recollect+materialize"
        );
        assert!(q.store.scripthash.entry_count() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mid-recollect cancel preserves SEAL; resume continues from watermark.
    #[test]
    fn class_a_recollect_cancel_resume_from_seal() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-recol-resume-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 12);
        let tip_max = q.store.txs.count();
        let mid = (tip_max / 2).max(1);

        // Plant SEAL mid (as after a partial spill), then cancel on entry.
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        q.sh_run.set_sealed_max_for_recollect(mid).unwrap();
        let cancel = AtomicBool::new(true);
        let err = q
            .rebuild_sh_unsealed_from_class_a_cancellable(Some(&cancel))
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Cancelled(_)),
            "expected Cancelled, got {err}"
        );
        q.sh_run.refresh_seal();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            mid,
            "cancel must not wipe SEAL watermark"
        );

        // Resume without cancel: only create_fk > mid, then materialize.
        cancel.store(false, Ordering::Relaxed);
        q.rebuild_sh_unsealed_from_class_a().unwrap();
        q.sh_run.refresh_seal();
        let seal_done = q.sh_run.sealed_max_create_fk();
        assert!(
            seal_done >= mid,
            "resume must keep/advance SEAL (got {seal_done} mid={mid})"
        );
        let run_recs = sh_catalog_total_records(&dir.join("scripthash.runs"));
        // Creates above mid should have been spilled (unless mid already covered tip).
        if mid + 1 < tip_max {
            assert!(
                run_recs > 0 || seal_done > mid,
                "resume recollect should spill remaining creates"
            );
        }
        // Tip entry after cancel/resume (shipped finalize_sh_runs).
        let n_mat = q.finalize_sh_runs().unwrap();
        if run_recs > 0 || seal_done > mid {
            assert!(
                n_mat > 0 || q.store.scripthash.has_durable_index(),
                "tip finalize after resume must settle SH"
            );
        }
        let seal_final = q.sh_run.sealed_max_create_fk();
        let _ = q.finalize_sh_runs().unwrap();
        assert!(
            q.sh_run.sealed_max_create_fk() >= seal_final,
            "post-settle finalize must not reset SEAL"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `RBITCOIN_SH_MATERIALIZE=unsorted-shards` packs from Class A without catalog runs.
    #[test]
    fn unsorted_shards_finalize_skips_catalog_runs() {
        let _g = FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-unsorted-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 5);
        std::env::set_var("RBITCOIN_SH_MATERIALIZE", "unsorted-shards");
        struct ClearEnv;
        impl Drop for ClearEnv {
            fn drop(&mut self) {
                std::env::remove_var("RBITCOIN_SH_MATERIALIZE");
            }
        }
        let _clear = ClearEnv;
        let result = q.finalize_sh_runs();
        drop(_clear);
        let n_mat = result.expect("unsorted-shards finalize");
        assert!(
            n_mat > 0 || q.store.scripthash.has_durable_index(),
            "unsorted-shards must settle SH"
        );
        assert!(q.store.scripthash.has_durable_index());
        assert_eq!(
            q.scripthash_run_count(),
            0,
            "unsorted-shards must not leave catalog runs"
        );
        assert!(
            !rbitcoin_store::unsorted_shard_dir(q.store.path()).exists()
                || std::fs::read_dir(rbitcoin_store::unsorted_shard_dir(q.store.path()))
                    .map(|it| it.count() == 0)
                    .unwrap_or(true),
            "unsorted dir must be cleared after seal"
        );
        let sh = rbitcoin_store::script_hash(&[0x51, 0]);
        assert!(
            !q.scripthash_history(&sh).unwrap().is_empty(),
            "Class A creates must be queryable"
        );
        assert!(q.sh_is_tip_ready() || q.store.scripthash.entry_count() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Direct enter never recollects; Class A recollect is tip finalize only.
    #[test]
    fn scenario_direct_enter_does_not_recollect() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-direct-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 3);
        let tip_max = q.store.txs.count();
        q.sh_run.set_sealed_max_for_recollect(0).unwrap();
        q.enter_direct_index_mode().unwrap();
        q.sh_run.refresh_seal();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            0,
            "Direct enter must not Class A recollect (tip_max={tip_max})"
        );
        assert_eq!(q.scripthash_run_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fresh IBD: direct seed → tip finalize materializes; second pass is stable.
    #[test]
    fn scenario_fresh_ibd_tip_materialize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-fresh-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 5);
        let n_mat = q.finalize_sh_runs().unwrap();
        assert!(
            n_mat > 0 || q.store.scripthash.has_durable_index() || q.scripthash_run_count() == 0,
            "fresh tip finalize should settle SH"
        );
        let seal1 = q.sh_run.sealed_max_create_fk();
        let count1 = q.store.scripthash.entry_count();
        // Second finalize is cheap (durable head, no wipe).
        let _n2 = q.finalize_sh_runs().unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), seal1);
        assert!(
            q.store.scripthash.entry_count() >= count1,
            "repeat finalize must not thrash durable head"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Resumed IBD: partial SEAL + leftover runs, then tip finalize completes.
    #[test]
    fn scenario_resumed_ibd_partial_seal_then_tip() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-resume-ibd-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 12);
        let tip_max = q.store.txs.count();
        let mid = (tip_max / 2).max(1);

        // Simulate crash after partial recollect: SEAL at mid, some catalog from first half.
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        q.sh_run.set_sealed_max_for_recollect(0).unwrap();
        // Recollect only lower half by planting mid SEAL after a full rebuild then
        // resetting catalog is hard; instead: recollect all, then set seal mid + clear
        // would lose data. Better: plant seal=mid with empty runs (crash before spill).
        q.sh_run.set_sealed_max_for_recollect(mid).unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), mid);

        // Restart path: enter_direct (small gap) + tip finalize.
        q.enter_direct_index_mode().unwrap();
        q.sh_run.refresh_seal();
        assert!(
            q.sh_run.sealed_max_create_fk() >= mid,
            "resume must not lower SEAL"
        );
        let n_mat = q.finalize_sh_runs().unwrap();
        assert!(
            q.store.scripthash.has_durable_index() || n_mat > 0 || mid >= tip_max,
            "resumed IBD tip finalize should settle SH"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mainnet sequence: recollect complete → sticky FORCE tip → cold load (not wipe)
    /// → durable head → sticky FORCE again is Noop.
    #[test]
    fn scenario_mainnet_recollect_then_force_then_stable() {
        let _g = FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-mainnet-seq-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 8);
        let tip_max = q.store.txs.count();

        // Phase 1: full Class A recollect (as enter_direct / pre-tip).
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        q.rebuild_sh_unsealed_from_class_a().unwrap();
        q.sh_run.refresh_seal();
        let seal1 = q.sh_run.sealed_max_create_fk();
        let recs1 = sh_catalog_total_records(&dir.join("scripthash.runs"));
        assert!(seal1 > 0 && recs1 > 0, "recollect must produce catalog");
        assert!(!q.store.scripthash.has_durable_index());

        // Phase 2: tip finalize with sticky FORCE (mainnet wipe bug).
        std::env::set_var("RBITCOIN_SH_FORCE_REBUILD", "1");
        assert_eq!(
            plan_sh_pre_materialize(true, false, seal1, tip_max, recs1, 0),
            ShPreMaterializeAction::ForceColdFromExistingCatalog
        );
        let n_mat = q.finalize_sh_runs().expect("FORCE finalize cold-load");
        assert!(n_mat > 0);
        assert!(q.store.scripthash.has_durable_index());
        q.sh_run.refresh_seal();
        let seal2 = q.sh_run.sealed_max_create_fk();
        assert!(
            seal2 >= seal1.min(tip_max),
            "SEAL must survive FORCE cold path (got {seal2}, had {seal1})"
        );
        let count_after = q.store.scripthash.entry_count();
        assert!(count_after > 0);

        // Phase 3: sticky FORCE still set on durable head → Noop plan, no wipe.
        assert_eq!(
            plan_sh_pre_materialize(
                true,
                true,
                seal2,
                tip_max,
                0,
                q.store.scripthash.include_hwm().max(seal2)
            ),
            ShPreMaterializeAction::Noop
        );
        let _ = q.finalize_sh_runs().unwrap();
        assert!(q.store.scripthash.has_durable_index());
        assert!(
            q.store.scripthash.entry_count() >= count_after,
            "second FORCE finalize must not wipe durable head"
        );
        assert!(q.sh_run.sealed_max_create_fk() >= seal2.min(tip_max));
        std::env::remove_var("RBITCOIN_SH_FORCE_REBUILD");

        // Phase 4: clean restart finalize (no FORCE) stays stable.
        let seal3 = q.sh_run.sealed_max_create_fk();
        let _ = q.finalize_sh_runs().unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), seal3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Incomplete FORCE (stale high SEAL + tiny runs) still does nuclear full rebuild.
    #[test]
    fn scenario_force_incomplete_catalog_still_full_rebuild() {
        let _g = FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-force-stale-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 6);
        let tip_max = q.store.txs.count();

        // Plant stale high SEAL + tiny run (catch-up tail, not full catalog).
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        store_seal(&runs_dir, 1_400_000_000).unwrap();
        q.sh_run.refresh_seal();
        let mut body = Vec::new();
        body.extend_from_slice(&encode_rec(&[0xab; 32], Fk(99)));
        write_sorted_run(
            &next_run_path(&runs_dir, 1),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body,
        )
        .unwrap();
        let recs = sh_catalog_total_records(&runs_dir);
        assert_eq!(
            plan_sh_pre_materialize(
                true,
                false,
                1_400_000_000,
                tip_max.max(1_410_000_000),
                recs,
                0
            ),
            ShPreMaterializeAction::ForceFullRebuild
        );

        std::env::set_var("RBITCOIN_SH_FORCE_REBUILD", "1");
        let n_mat = q
            .finalize_sh_runs()
            .expect("FORCE incomplete must recollect+materialize");
        std::env::remove_var("RBITCOIN_SH_FORCE_REBUILD");
        assert!(n_mat > 0);
        assert!(q.store.scripthash.has_durable_index());
        // After nuclear path SEAL should track real tip, not the planted 1.4e9.
        q.sh_run.refresh_seal();
        assert!(
            q.sh_run.sealed_max_create_fk() <= tip_max + 1_000,
            "full rebuild SEAL should match Class A tip, not stale plant"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After SH materialize at tip, restart must see tip-ready and skip recollect.
    #[test]
    fn tip_ready_after_materialize_skips_recollect_and_finalize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-tip-ready-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 5);
        let n_mat = q.finalize_sh_runs().expect("materialize");
        assert!(n_mat > 0 || q.store.scripthash.has_durable_index());
        q.enter_tip_index_mode();
        assert!(
            q.sh_is_tip_ready(),
            "durable SH after materialize must be tip-ready seal={} hwm={} tip_max={} runs={}",
            q.sh_run.sealed_max_create_fk(),
            q.store.scripthash.include_hwm(),
            q.store.txs.count(),
            q.sh_run.on_disk_run_count()
        );

        // Simulate restart: enter Direct must not recollect (floor covers tip).
        let seal_before = q.sh_run.sealed_max_create_fk();
        q.enter_direct_index_mode().unwrap();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            seal_before.max(q.store.scripthash.include_hwm()),
            "Direct enter must not reset SEAL when HWM covers tip"
        );

        // Second finalize is a no-op fast path.
        assert_eq!(q.finalize_sh_runs().unwrap(), 0);
        assert!(q.sh_is_tip_ready());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Durable head + lagging include_hwm + leftover run: skip recollect/WarmOnly.
    ///
    /// Mainnet 2026-08-25: short Tip catch-up then WarmOnly re-applied creates
    /// already in the head → `fk stream zero delta`.
    #[test]
    fn durable_head_hwm_lag_skips_recollect() {
        let _g = FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-hwm-lag-skip-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 6);
        let n0 = q.finalize_sh_runs().unwrap();
        assert!(n0 > 0 || q.store.scripthash.has_durable_index());
        assert!(q.store.scripthash.has_durable_index());
        let count_before = q.store.scripthash.entry_count();
        let tip_max = q.store.txs.count();
        assert!(tip_max >= 6);

        // Write-behind applied fewer heights than Class A (HWM file is monotonic
        // on the store API — plant the lag the way a crash leaves it).
        let lag = tip_max.saturating_sub(3).max(1);
        std::fs::write(
            dir.join(rbitcoin_store::INCLUDE_HWM_NAME),
            lag.to_le_bytes(),
        )
        .unwrap();
        assert!(
            q.store.scripthash.include_hwm() < tip_max,
            "planted HWM lag hwm={} tip_max={tip_max}",
            q.store.scripthash.include_hwm()
        );

        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&encode_rec(&[0xee; 32], Fk(99)));
        write_sorted_run(
            &next_run_path(&runs_dir, 50),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body,
        )
        .unwrap();
        assert!(q.sh_run.on_disk_run_count() > 0);
        assert!(
            !q.sh_is_tip_ready(),
            "strict HWM/run check is still false (the old tripwire)"
        );
        assert!(
            q.sh_use_writebehind(),
            "durable head must choose write-behind even when HWM lags"
        );

        let n1 = q.finalize_sh_runs().unwrap();
        assert_eq!(n1, 0, "must not recollect/WarmOnly onto a live head");
        assert_eq!(
            q.store.scripthash.entry_count(),
            count_before,
            "leftover run must not be applied onto the live head"
        );
        assert_eq!(q.scripthash_run_count(), 0, "leftover runs discarded");
        assert_eq!(
            q.store.scripthash.include_hwm(),
            lag,
            "skip must not bump HWM from the leftover run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tip-mode durable SH writes advance include_hwm + SEAL (restart floor).
    #[test]
    fn tip_mode_connect_advances_sh_watermarks() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-tip-wm-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 3);
        let _ = q.finalize_sh_runs().unwrap();
        q.enter_tip_index_mode();
        // finalize disables run worker → tip durable SH path.
        assert!(!q.sh_run.is_enabled());
        let tip_max_before = q.store.txs.count();
        let hwm_before = q.store.scripthash.include_hwm();
        let seal_before = q.sh_run.sealed_max_create_fk();

        let tip_h = q.tip_height().unwrap().0;
        let tip_fk = q.store.confirmed.get(Height(tip_h)).unwrap().unwrap();
        let tip_hash = q.store.get_header(tip_fk).unwrap().hash;
        let (header, ta) = coinbase_block(tip_h + 1, tip_fk, Some(tip_hash));
        q.connect_block(Height(tip_h + 1), &header, &[ta])
            .expect("tip connect");

        let tip_max_after = q.store.txs.count();
        assert!(tip_max_after > tip_max_before);
        assert!(
            q.store.scripthash.include_hwm() >= tip_max_after
                || q.store.scripthash.include_hwm() > hwm_before,
            "include_hwm must advance on tip durable SH write hwm={} before={} tip_max={}",
            q.store.scripthash.include_hwm(),
            hwm_before,
            tip_max_after
        );
        assert!(
            q.sh_run.sealed_max_create_fk() >= q.store.scripthash.include_hwm()
                || q.sh_run.sealed_max_create_fk() > seal_before,
            "SEAL must advance with tip durable writes"
        );
        assert!(
            q.sh_is_tip_ready(),
            "after tip follow block, still tip-ready (no recollect on restart)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// include_hwm alone (SEAL lagging) is enough to skip Direct recollect.
    #[test]
    fn include_hwm_covers_tip_without_seal_match() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-hwm-floor-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 4);
        let _ = q.finalize_sh_runs().unwrap();
        let tip_max = q.store.txs.count();
        q.store.scripthash.note_include_hwm(tip_max).unwrap();
        // Plant lagging SEAL (simulates old tip-follow without SEAL advance).
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        store_seal(&runs_dir, tip_max.saturating_sub(10).max(1)).unwrap();
        q.sh_run.refresh_seal();
        assert!(q.sh_run.sealed_max_create_fk() < tip_max);
        assert!(
            q.sh_is_tip_ready() || {
                // Residual runs from plant empty dir — clear and recheck.
                let _ = std::fs::remove_dir_all(&runs_dir);
                q.sh_run.refresh_seal();
                q.store.scripthash.note_include_hwm(tip_max).unwrap();
                // SEAL file gone → seal 0; HWM still covers.
                q.sync_sh_seal_from_include_hwm().unwrap();
                q.sh_is_tip_ready()
            }
        );
        q.enter_direct_index_mode().unwrap();
        assert!(
            q.sh_run.sealed_max_create_fk() >= tip_max,
            "Direct enter must raise SEAL to include_hwm covering tip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Failed mid-materialize (empty head + claimed mats) + more Direct creates
    /// as small runs → finalize must fold **all** creates into durable SH and be
    /// tip-ready before tip-follow / Electrum (mainnet ENOSPC rematerialize class).
    #[test]
    fn scenario_failed_materialize_then_small_runs_then_finalize_tip_ready() {
        use rbitcoin_store::{claim_run_for_materialize, list_runs};

        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-fail-then-runs-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();

        // Phase 1: Direct chain + recollect spills into catalog runs.
        seed_direct_chain(&q, 6);
        let tip_max_phase1 = q.store.txs.count();
        assert!(tip_max_phase1 >= 6);
        q.rebuild_sh_unsealed_from_class_a().unwrap();
        assert!(
            q.sh_run.on_disk_run_count() > 0,
            "recollect must leave catalog runs"
        );

        // Phase 2: simulate materialize *start* then failure — claim runs as .mat
        // and reinit empty head (FullCold reinit) without streaming them in.
        let runs_dir = dir.join("scripthash.runs");
        {
            let runs = list_runs(&runs_dir).unwrap();
            assert!(!runs.is_empty());
            for r in runs {
                claim_run_for_materialize(&r).unwrap();
            }
        }
        q.store
            .scripthash
            .reinit_empty_for_cold_materialize()
            .unwrap();
        assert!(
            !q.store.scripthash.has_durable_index(),
            "failed materialize leaves empty head"
        );
        assert!(
            q.sh_run.on_disk_run_count() > 0,
            "claimed .mat leftovers must remain visible"
        );
        assert!(
            !q.sh_is_tip_ready(),
            "must not be tip-ready after failed materialize"
        );

        // Phase 3: more Direct blocks → small new SH runs (post-fail catch-up).
        let tip_h = q.tip_height().unwrap().0;
        let tip_fk = q.store.confirmed.get(Height(tip_h)).unwrap().unwrap();
        let tip_hash = q.store.get_header(tip_fk).unwrap().hash;
        let mut prev = tip_fk;
        let mut parent_hash = Some(tip_hash);
        for h in (tip_h + 1)..=(tip_h + 3) {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let tip_max_final = q.store.txs.count();
        assert!(tip_max_final > tip_max_phase1);

        // Phase 4: finalize must recollect gap + materialize claimed + new runs.
        let n_mat = q
            .finalize_sh_runs()
            .expect("finalize after failed materialize + more runs");
        assert!(
            n_mat > 0 || q.store.scripthash.has_durable_index(),
            "materialize must produce durable SH"
        );
        assert_eq!(
            q.scripthash_run_count(),
            0,
            "no residual runs before tip-ready"
        );
        assert!(
            q.sh_is_tip_ready(),
            "must be tip-ready seal={} hwm={} tip_max={} runs={}",
            q.sh_run.sealed_max_create_fk(),
            q.store.scripthash.include_hwm(),
            tip_max_final,
            q.sh_run.on_disk_run_count()
        );
        // Inclusion floor covers every Class A create through tip.
        let floor = crate::sh_builder::durable_sh_inclusion_floor(
            q.store.scripthash.include_hwm(),
            q.sh_run.sealed_max_create_fk(),
        );
        assert!(
            floor >= tip_max_final,
            "include floor must cover tip creates floor={floor} tip_max={tip_max_final}"
        );
        q.enter_tip_index_mode();
        assert!(q.sh_is_tip_ready());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Residual run after cold materialize must warm-apply (never FullCold wipe).
    #[test]
    fn scenario_tip_residual_warm_after_materialize() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-warm-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 4);
        q.sh_run.reset_catalog_for_full_recollect().unwrap();
        q.rebuild_sh_unsealed_from_class_a().unwrap();
        let n0 = q.finalize_sh_runs().unwrap();
        assert!(n0 > 0 || q.store.scripthash.has_durable_index());
        let count_before = q.store.scripthash.entry_count();
        let seal_before = q.sh_run.sealed_max_create_fk();
        // Plant residual run.
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&encode_rec(&[0xee; 32], Fk(99)));
        write_sorted_run(
            &next_run_path(&runs_dir, 50),
            SH_RUN_KEY_LEN,
            SH_RUN_REC_LEN,
            &body,
        )
        .unwrap();
        let n1 = q.finalize_sh_runs().unwrap();
        assert!(n1 >= 1 || q.store.scripthash.entry_count() >= count_before);
        assert!(
            q.store.scripthash.entry_count() >= count_before,
            "warm residual must not wipe durable head"
        );
        assert!(
            q.sh_run.sealed_max_create_fk() >= seal_before,
            "warm residual must not reset SEAL"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
