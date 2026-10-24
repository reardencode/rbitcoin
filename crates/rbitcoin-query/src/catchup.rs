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
/// | [`Direct`](IndexMode::Direct) | archive live | confirm batch after Class C | Class A collect → unsorted shards → seal at tip |
/// | [`Tip`](IndexMode::Tip) | live | confirm batch after Class C | durable write-through after bulk |
///
/// Open defaults to `Tip` until the node calls [`Query::enter_direct_index_mode`].
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

    /// Confirm enqueues SH write-behind in Tip when `--shindex` is on.
    pub fn enqueues_sh_writebehind(self, sh_index: bool) -> bool {
        sh_index && self.is_tip()
    }
    #[doc(hidden)]
    pub fn from_u8(v: u8) -> Result<Self, StoreError> {
        match v {
            1 => Ok(Self::Direct),
            2 => Ok(Self::Tip),
            _ => Err(StoreError::Corrupt("index mode byte")),
        }
    }
}

impl Query {
    /// Current index / spentness mode ([`IndexMode`]).
    ///
    /// The in-memory cell is only Direct (`1`) or Tip (`2`). Any other byte is corrupt.
    #[inline]
    pub fn index_mode(&self) -> Result<IndexMode, QueryError> {
        IndexMode::from_u8(self.index_mode_cell.load(Ordering::SeqCst))
    }

    #[doc(hidden)]
    pub fn set_index_mode(&self, mode: IndexMode) {
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

    /// Confirm SH write-behind enqueue: Tip + shindex on.
    #[inline]
    pub fn enqueues_sh_writebehind(&self) -> bool {
        self.index_mode()
            .expect("index mode cell")
            .enqueues_sh_writebehind(self.sh_index_enabled())
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
    /// head — unsorted Class A collect + pack is tip finalize / `--shindex` only.
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
        rbitcoin_log::info!("ibd: IndexMode::Direct (shindex on; SH collect only at tip finalize)");
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
    /// **write-behind** (same as tip follow), never Class A catalog recollect or WarmOnly.
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
    #[doc(hidden)]
    pub fn drop_legacy_catchup_artifacts(&self) -> Result<(), QueryError> {
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
    /// Direct IBD defers SH. Tip: two Class A scans (identity-map keys, then
    /// fuse-hit postings) into `scripthash.unsorted`, then pack and seal.
    ///
    /// **`RBITCOIN_SH_FORCE_REBUILD=1`:** wipe SH head/runs/SEAL/HWM, then
    /// full unsorted Class A collect + pack (not a catch-up tail).
    pub fn finalize_sh_runs(&self) -> Result<u64, QueryError> {
        self.finalize_sh_runs_cancellable(None)
    }

    /// Like [`Self::finalize_sh_runs`] with cooperative cancel (SIGINT keeps sealed shards).
    pub fn finalize_sh_runs_cancellable(
        &self,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<u64, QueryError> {
        use crate::sh_builder::sh_force_rebuild;

        if !sh_force_rebuild() && self.sh_use_writebehind() {
            if self.store.scripthash.unsealed_main_shards().is_empty() {
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
                } else if self.index_mode()?.is_direct() {
                    rbitcoin_log::info!(
                        "node: scripthash durable head with HWM/SEAL lag while Direct — \
                     Class A tail backfill (write-behind no-ops until Tip)"
                    );
                    self.backfill_until_sh_tip_ready(
                        "scripthash Class A tail backfill left include_hwm short of tip",
                    )?;
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

        self.finalize_sh_unsorted_cancellable(cancel)
    }

    #[doc(hidden)]
    pub fn finalize_sh_unsorted_cancellable(
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
            let mut n = n;
            if !self.sh_is_tip_ready() && self.store.scripthash.has_durable_index() {
                rbitcoin_log::info!(
                    "node: scripthash unsorted-shards post-materialize Class A tail backfill"
                );
                n = n.saturating_add(self.backfill_until_sh_tip_ready(
                    "scripthash unsorted-shards create gap remain after materialize drain \
                     (refuse tip-follow / Electrum)",
                )?);
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

    /// Keep scanning Class A until the inclusion watermark covers the tip.
    ///
    /// A create that lands after one pass is another pass. When the watermark
    /// already covers every create and the tip is still short, `gap` is the
    /// corrupt record.
    fn backfill_until_sh_tip_ready(&self, gap: &'static str) -> Result<u64, QueryError> {
        let mut n = 0u64;
        loop {
            n = n.saturating_add(self.backfill_sh_creates_from_class_a()?);
            if self.sh_is_tip_ready() {
                return Ok(n);
            }
            if self.store.scripthash.include_hwm() >= self.store.txs.count() {
                return Err(StoreError::Corrupt(gap));
            }
        }
    }

    /// Append Class A creates after the durable inclusion floor onto a live SH head.
    ///
    /// Confirm keeps appending while this runs (`submitblock` during
    /// materialize). Each pass samples `txs.count()` and, when that count
    /// grew, scans the new tail before publishing the watermark.
    #[doc(hidden)]
    pub fn backfill_sh_creates_from_class_a(&self) -> Result<u64, QueryError> {
        use crate::sh_builder::durable_sh_inclusion_floor;

        const CHUNK: u64 = 64_000;
        let mut total = 0u64;
        loop {
            let last = self.store.txs.count();
            self.sh_run.refresh_seal();
            let floor = durable_sh_inclusion_floor(
                self.store.scripthash.include_hwm(),
                self.sh_run.sealed_max_create_fk(),
            );
            let first = if floor == 0 {
                1
            } else {
                floor.saturating_add(1)
            };
            // Test seam: a create that lands after this sample must not be left
            // behind the inclusion watermark. Production leaves the cell empty.
            if let Some(hook) = sh_backfill_after_sample_hook() {
                hook(self);
            }
            if last < first {
                if self.store.txs.count() <= last {
                    return Ok(total);
                }
                continue;
            }
            rbitcoin_log::info!("node: scripthash Class A tail backfill first={first} last={last}");
            let mut lo = first;
            let mut heads = self.sh.heads.lock().unwrap();
            while lo <= last {
                let hi = lo.saturating_add(CHUNK.saturating_sub(1)).min(last);
                let mut recs = Vec::new();
                self.store
                    .txs
                    .for_each_script_hashes_in_fk_span(lo, hi, |fk, sh| {
                        recs.push(ScriptHashRecord::from_fk(sh, fk));
                        Ok(())
                    })?;
                if !recs.is_empty() {
                    total = total.saturating_add(recs.len() as u64);
                    self.store
                        .scripthash
                        .put_create_batch_append(&recs, &mut heads)?;
                }
                lo = hi.saturating_add(1);
            }
            drop(heads);
            self.store.scripthash.flush()?;
            self.store.scripthash.note_include_hwm(last)?;
            self.sh_run.publish_seal_watermark(last)?;
            if self.store.txs.count() <= last {
                return Ok(total);
            }
        }
    }

    #[doc(hidden)]
    pub fn mark_sh_indexed_through_tip(&self) {
        if let Some(tip) = self.tip_height() {
            self.set_sh_indexed_through_height(Some(tip.0));
        }
    }

    /// On-disk scripthash sorted-run count (Direct IBD cache).
    pub fn scripthash_run_count(&self) -> usize {
        super::note_scripthash_run_count_call();
        self.sh_run.on_disk_run_count()
    }

    /// Whether the Direct-IBD SH run worker is currently enabled.
    pub fn sh_run_enabled(&self) -> bool {
        self.sh_run.is_enabled()
    }
}

thread_local! {
    static SH_BACKFILL_AFTER_SAMPLE: std::cell::Cell<Option<fn(&Query)>> =
        const { std::cell::Cell::new(None) };
}

fn sh_backfill_after_sample_hook() -> Option<fn(&Query)> {
    SH_BACKFILL_AFTER_SAMPLE.with(|c| c.take())
}

/// One-shot hook invoked after a Class A tail backfill samples `txs.count()`.
/// Tests use it to confirm another create in that window.
#[doc(hidden)]
pub fn set_sh_backfill_after_sample_for_test(hook: Option<fn(&Query)>) {
    SH_BACKFILL_AFTER_SAMPLE.with(|c| c.set(hook));
}
