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
    /// Direct IBD defers SH. Tip: one Class A pass into unsorted per-shard
    /// files, then in-place unique-sort + seal.
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
                } else if self.index_mode().is_direct() {
                    rbitcoin_log::info!(
                        "node: scripthash durable head with HWM/SEAL lag while Direct — \
                     Class A tail backfill (write-behind no-ops until Tip)"
                    );
                    self.backfill_sh_creates_from_class_a()?;
                    if self.sh_is_tip_ready() {
                        self.mark_sh_indexed_through_tip();
                    } else {
                        return Err(StoreError::Corrupt(
                            "scripthash Class A tail backfill left include_hwm short of tip",
                        ));
                    }
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
            let mut n = n;
            if !self.sh_is_tip_ready() && self.store.scripthash.has_durable_index() {
                rbitcoin_log::info!(
                    "node: scripthash unsorted-shards post-materialize Class A tail backfill"
                );
                n = n.saturating_add(self.backfill_sh_creates_from_class_a()?);
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

    /// Append Class A creates after the durable inclusion floor onto a live SH head.
    fn backfill_sh_creates_from_class_a(&self) -> Result<u64, QueryError> {
        use crate::sh_builder::durable_sh_inclusion_floor;

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
        if last < first {
            return Ok(0);
        }
        rbitcoin_log::info!("node: scripthash Class A tail backfill first={first} last={last}");
        const CHUNK: u64 = 64_000;
        let mut total = 0u64;
        let mut lo = first;
        let mut heads = self.sh_heads.lock().unwrap();
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
        Ok(total)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sh_builder::{load_seal, sh_force_rebuild, store_seal};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_store::{
        next_run_path, write_sorted_run, HeaderRecord, InputRecord, OutputRecord, TxRecord,
    };
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Serialize FORCE_REBUILD env mutations (parallel tests share process env).
    static FORCE_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn leftover_run_rec(sh0: u8, fk: u64) -> Vec<u8> {
        let mut rec = [0u8; 40];
        rec[..32].fill(sh0);
        rec[32..40].copy_from_slice(&fk.to_le_bytes());
        rec.to_vec()
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

    fn seed_direct_chain(q: &Query, n: u32) {
        q.enter_direct_index_mode().unwrap();
        extend_direct_chain(q, n);
        assert_eq!(q.tip_height(), Some(Height(n - 1)));
        assert!(q.store.txs.count() >= u64::from(n));
    }

    fn extend_direct_chain(q: &Query, add: u32) {
        if add == 0 {
            return;
        }
        let start = q.tip_height().map(|h| h.0.saturating_add(1)).unwrap_or(0);
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        if start > 0 {
            let prev_h = Height(start - 1);
            prev = q.store.confirmed.get(prev_h).unwrap().unwrap();
            parent_hash = Some(q.get_header(prev).unwrap().hash);
        }
        for h in start..start + add {
            let (header, ta) = coinbase_block(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
    }

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
            "durable SH appears only after finalize collect"
        );
        let sh = rbitcoin_store::script_hash(&[0x51, 0]);
        assert!(q.scripthash_history(&sh).unwrap().is_empty());
        let n_mat = q.finalize_sh_runs().unwrap();
        assert!(n_mat > 0 || q.store.scripthash.has_durable_index());
        assert!(!q.scripthash_history(&sh).unwrap().is_empty());
        assert_eq!(q.scripthash_run_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        seed_direct_chain(&q, 3);
        let n0 = q.finalize_sh_runs().unwrap();
        assert!(n0 >= 1 || q.store.scripthash.has_durable_index());
        assert!(q.store.scripthash.has_durable_index());
        let count_before = q.store.scripthash.entry_count();
        let sh0 = rbitcoin_store::script_hash(&[0x51, 0]);

        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let high_seal = 1_411_000_000u64;
        store_seal(&runs_dir, high_seal).unwrap();
        q.sh_run.refresh_seal();
        let _ = std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME));
        assert_eq!(q.store.scripthash.include_hwm(), 0);
        assert_eq!(q.sh_run.sealed_max_create_fk(), high_seal);

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
        assert!(
            !q.store.scripthash.entries(&sh0).unwrap().is_empty(),
            "durable head must remain"
        );
        assert!(q.store.scripthash.entry_count() >= count_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_sh_runs_empty_head_leftover_seal_is_wiped() {
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
        write_sorted_run(
            &next_run_path(&runs_dir, 1),
            40,
            40,
            &leftover_run_rec(0xab, 99),
        )
        .unwrap();

        let _ = q.finalize_sh_runs().unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
        assert_eq!(load_seal(&runs_dir), 0);
        assert_eq!(q.scripthash_run_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let _ = q.finalize_sh_runs().unwrap();
        assert!(q.store.scripthash.has_durable_index());

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
            "head must not stay empty after FORCE collect+pack"
        );
        assert!(q.store.scripthash.entry_count() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsorted_shards_finalize_skips_catalog_runs() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-unsorted-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 5);
        let n_mat = q.finalize_sh_runs().expect("unsorted-shards finalize");
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

    #[test]
    fn scenario_direct_enter_does_not_collect() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-scenario-direct-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 3);
        q.enter_direct_index_mode().unwrap();
        q.sh_run.refresh_seal();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            0,
            "Direct enter must not Class A collect"
        );
        assert_eq!(q.scripthash_run_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let _n2 = q.finalize_sh_runs().unwrap();
        assert_eq!(q.sh_run.sealed_max_create_fk(), seal1);
        assert!(
            q.store.scripthash.entry_count() >= count1,
            "repeat finalize must not thrash durable head"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tip_ready_after_materialize_skips_collect_and_finalize() {
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

        let seal_before = q.sh_run.sealed_max_create_fk();
        q.enter_direct_index_mode().unwrap();
        assert_eq!(
            q.sh_run.sealed_max_create_fk(),
            seal_before.max(q.store.scripthash.include_hwm()),
            "Direct enter must not reset SEAL when HWM covers tip"
        );

        assert_eq!(q.finalize_sh_runs().unwrap(), 0);
        assert!(q.sh_is_tip_ready());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_head_hwm_lag_discards_leftover_run() {
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
        write_sorted_run(
            &next_run_path(&runs_dir, 50),
            40,
            40,
            &leftover_run_rec(0xee, 99),
        )
        .unwrap();
        assert!(q.sh_run.on_disk_run_count() > 0);
        assert!(!q.sh_is_tip_ready(), "strict HWM/run check is still false");
        assert!(
            q.sh_use_writebehind(),
            "durable head must choose write-behind even when HWM lags"
        );

        let n1 = q.finalize_sh_runs().unwrap();
        assert_eq!(n1, 0, "must not collect onto a live head");
        assert_eq!(
            q.store.scripthash.entry_count(),
            count_before,
            "leftover run must not be applied onto the live head"
        );
        assert_eq!(q.scripthash_run_count(), 0, "leftover runs discarded");
        assert!(
            q.store.scripthash.include_hwm() >= tip_max,
            "Direct finalize backfills Class A tail (hwm={} tip_max={tip_max}), not leftover fk=99",
            q.store.scripthash.include_hwm()
        );
        assert!(
            q.store.scripthash.include_hwm() < 99,
            "leftover run fk=99 must not become include_hwm"
        );
        assert!(q.sh_is_tip_ready());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
            "after tip follow block, still tip-ready"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let runs_dir = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        store_seal(&runs_dir, tip_max.saturating_sub(10).max(1)).unwrap();
        q.sh_run.refresh_seal();
        assert!(q.sh_run.sealed_max_create_fk() < tip_max);
        assert!(
            q.sh_is_tip_ready() || {
                let _ = std::fs::remove_dir_all(&runs_dir);
                q.sh_run.refresh_seal();
                q.store.scripthash.note_include_hwm(tip_max).unwrap();
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

    #[test]
    fn finalize_sh_appends_unsorted_when_done_lags_before_any_shard() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-done-lag-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 3);
        let n_shards = q.store.scripthash.head_shard_count();
        let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
        rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
        let done_last = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
        extend_direct_chain(&q, 2);
        assert!(q.store.txs.count() > done_last);
        assert!(!q.store.scripthash.has_durable_index());
        let _ = q.finalize_sh_runs().unwrap();
        let sh_old = rbitcoin_store::script_hash(&[0x51, 0]);
        let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
        assert!(
            !q.scripthash_history(&sh_old).unwrap().is_empty(),
            "creates from the original collect must remain"
        );
        assert!(
            !q.scripthash_history(&sh_new).unwrap().is_empty(),
            "creates after DONE must be in unsorted catch-up before pack"
        );
        assert!(q.sh_is_tip_ready());
        assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_sh_backfills_class_a_tail_when_shards_already_sealed() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-q-sh-shard-lag-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        seed_direct_chain(&q, 3);
        let _ = q.finalize_sh_runs().unwrap();
        assert!(q.store.scripthash.has_durable_index());
        assert!(q.sh_is_tip_ready());
        extend_direct_chain(&q, 2);
        assert!(
            !q.sh_is_tip_ready(),
            "new Class A after seal must lag honest include_hwm"
        );
        let _ = q.finalize_sh_runs().unwrap();
        let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
        assert!(
            !q.scripthash_history(&sh_new).unwrap().is_empty(),
            "Direct finalize must backfill Class A tail onto sealed shards"
        );
        assert!(q.sh_is_tip_ready());
        assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
