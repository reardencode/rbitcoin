//! Tip confirm / connect / disconnect.

use super::*;
use std::sync::atomic::Ordering;

/// One height of SH creates waiting for the Class B appender.
#[derive(Clone)]
pub(crate) struct ShPendingJob {
    height: Height,
    header_fk: Fk,
    records: Vec<ScriptHashRecord>,
}

fn index_sh_ram_head(head: &mut HashMap<[u8; 32], Vec<Fk>>, job: &ShPendingJob) {
    for r in &job.records {
        head.entry(r.scripthash).or_default().push(r.create_tx_fk);
    }
}

fn unindex_sh_ram_head(head: &mut HashMap<[u8; 32], Vec<Fk>>, job: &ShPendingJob) {
    for r in &job.records {
        let Some(v) = head.get_mut(&r.scripthash) else {
            continue;
        };
        if let Some(i) = v.iter().position(|fk| *fk == r.create_tx_fk) {
            v.swap_remove(i);
        }
        if v.is_empty() {
            head.remove(&r.scripthash);
        }
    }
}

/// One height ready for Class C (header + body already archived).
///
/// Callers that already resolved `header_fk` / `tx_fks` (e.g. multi-block confirm)
/// pass them here to avoid redoing hash lookups.
#[derive(Debug, Clone)]
pub struct ConfirmPrepared {
    pub height: Height,
    pub header_fk: Fk,
    pub tx_fks: Vec<Fk>,
}

impl Query {
    pub fn confirm_block(&self, height: Height, header_hash: &[u8; 32]) -> Result<Fk, QueryError> {
        if let Some(h) = self.height_of_hash(header_hash)? {
            if h == height {
                if let Some((fk, _)) = self.get_header_by_hash(header_hash)? {
                    return Ok(fk);
                }
            }
        }

        let (header_fk, _rec) = self
            .get_header_by_hash(header_hash)?
            .ok_or(StoreError::NotFound)?;
        let tx_fks = self
            .store
            .header_txs
            .get_list(header_fk)?
            .ok_or(StoreError::Corrupt("confirm without archived body"))?;

        let out = self.confirm_blocks_run(&[ConfirmPrepared {
            height,
            header_fk,
            tx_fks,
        }])?;
        Ok(out[0])
    }

    /// Confirm a contiguous tip-extension run of already-archived bodies.
    ///
    /// Skips per-block `height_of_hash` / `get_header_by_hash` (caller supplies fks).
    ///
    /// # Class C write order (crash atomicity)
    ///
    /// Per block we write `strong_tx`, then **last** advance `confirmed[]` for
    /// the whole run. Scripthash creates are enqueued after that commit and
    /// applied by [`Self::apply_sh_pending`]. The confirmed tip is the commit
    /// point: [`rbitcoin_store::Store::spenders`] /
    /// [`rbitcoin_store::Store::is_confirmed_strong`] only treat a spend as
    /// best-chain once the height fence (confirmed + header_txs) contains the
    /// spender. A hard kill after strong bits but before tip advance leaves
    /// recoverable state — open repairs strong not on the fence, and re-confirm
    /// of tip+1 does not see false PrevoutSpent.
    ///
    /// # Spend annotations
    ///
    /// When `spend_index` is on, durable spend annotations land on create outputs
    /// (schema v5+). Under Direct IBD, **confirm** batch-writes those annotations
    /// after Class C (not archive). Tip mode assumes they are already complete.
    pub fn confirm_blocks_run(&self, items: &[ConfirmPrepared]) -> Result<Vec<Fk>, QueryError> {
        self.confirm_blocks_run_with_create_pins(items, None)
    }

    /// Like [`Self::confirm_blocks_run`], with optional write-batch create pins.
    ///
    /// `create_pins` is `create_fk → CreatePin` for creates committed on this write
    /// path. Collect runs after tip (cheap); records sit on the job so queries
    /// join them before durable seed. Enqueue is after the tip commit: a collect
    /// failure can surface after `confirmed[]` advanced; retry is the heal
    /// (re-confirm at the same height is idempotent).
    pub fn confirm_blocks_run_with_create_pins(
        &self,
        items: &[ConfirmPrepared],
        create_pins: Option<&crate::FkMap<CreatePin>>,
    ) -> Result<Vec<Fk>, QueryError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        for w in items.windows(2) {
            if w[1].height.0 != w[0].height.0.saturating_add(1) {
                return Err(StoreError::Corrupt("confirm run not contiguous heights"));
            }
        }

        match self.tip_height() {
            None => {
                if items[0].height != Height::GENESIS {
                    return Err(StoreError::Corrupt("first block must be genesis height"));
                }
            }
            Some(tip) => {
                let expect = tip.next().ok_or(StoreError::Corrupt("height overflow"))?;
                if items[0].height != expect {
                    if items.len() == 1 {
                        if let Some(fk) = self.store.confirmed.get(items[0].height)? {
                            if fk == items[0].header_fk {
                                return Ok(vec![fk]);
                            }
                        }
                    }
                    return Err(StoreError::Corrupt("connect height not tip+1"));
                }
            }
        }

        for item in items {
            if item.header_fk.is_null() {
                return Err(StoreError::InvalidFk);
            }
        }

        let t_strong = std::time::Instant::now();
        let mut confirmed_pairs = Vec::with_capacity(items.len());
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let contiguous = item
                .tx_fks
                .windows(2)
                .all(|w| w[1].0 == w[0].0.saturating_add(1));
            if contiguous {
                if let Some(&first) = item.tx_fks.first() {
                    self.store.strong_tx.set_strong_range(
                        first,
                        item.tx_fks.len() as u32,
                        item.header_fk,
                    )?;
                }
            } else {
                for &tx_fk in &item.tx_fks {
                    self.store.strong_tx.set_strong(tx_fk, item.header_fk)?;
                }
            }
            confirmed_pairs.push((item.height, item.header_fk));
            out.push(item.header_fk);
        }
        crate::note_confirm(
            &self.confirm_stats().strong_ns,
            t_strong.elapsed().as_nanos() as u64,
        );

        // Fence first: missing header_txs is Corrupt. Publishing confirmed[]
        // before extend would leave tip ahead of height_of (leftover TipOnly hole).
        let t_tip = std::time::Instant::now();
        for item in items {
            self.store
                .height_fence_extend(item.height, item.header_fk)?;
        }
        self.store.confirmed.set_many(&confirmed_pairs)?;
        // Do not forget pending here: drain may still be inserting tx.head
        // (67438). Write forgets after drain.join() *and* this extend.
        // L2 write-behind barrier: complete-or-fail Class C image to disk **before**
        // callers dequeue the body queue. Kill after this returns → tip durable;
        // kill before → BQ still holds blocks for re-drive.
        self.store.flush_class_c_tip()?;
        crate::note_confirm(
            &self.confirm_stats().tip_ns,
            t_tip.elapsed().as_nanos() as u64,
        );

        self.enqueue_sh_pending(items, create_pins)?;

        if let Some(tip) = self.tip_height() {
            let _ = self.ensure_height_by_hash_index(tip);
        }

        Ok(out)
    }

    fn enqueue_sh_pending(
        &self,
        items: &[ConfirmPrepared],
        create_pins: Option<&crate::FkMap<CreatePin>>,
    ) -> Result<(), QueryError> {
        if !self.enqueues_sh_writebehind() {
            return Ok(());
        }
        let through = self.sh_indexed_through_height();
        let mut jobs = Vec::new();
        for item in items {
            if through.map(|t| item.height.0 <= t).unwrap_or(false) {
                continue;
            }
            let t_collect = std::time::Instant::now();
            let mut records: Vec<ScriptHashRecord> = Vec::new();
            records.reserve(item.tx_fks.len().saturating_mul(2));
            for &fk in &item.tx_fks {
                let pin = create_pins.and_then(|m| m.get(&fk));
                self.collect_scripthash_creates(fk, &mut records, pin)?;
            }
            self.confirm_stats().add_sh_part(
                &self.confirm_stats().sh_collect_ns,
                t_collect.elapsed().as_nanos() as u64,
            );
            jobs.push(ShPendingJob {
                height: item.height,
                header_fk: item.header_fk,
                records,
            });
        }
        if jobs.is_empty() {
            return Ok(());
        }
        let mut pending = self.sh.pending.lock().unwrap();
        let mut head = self.sh.ram_head.lock().unwrap();
        for job in &jobs {
            index_sh_ram_head(&mut head, job);
        }
        pending.extend(jobs);
        Ok(())
    }

    /// Allow the Class B appender to durable-apply jobs through `through`.
    ///
    /// Enqueue publishes RAM records; seed waits for this so tip connect and
    /// block announce do not share disk with `locate_head`.
    pub fn release_sh_writebehind(&self, through: Height) {
        let v = through.0.saturating_add(1);
        self.sh.released_through.fetch_max(v, Ordering::Release);
        self.sh.pending_cv.notify_one();
    }

    /// Last height durable apply is allowed to run (`None` until first release).
    pub fn sh_released_through_height(&self) -> Option<u32> {
        let v = self.sh.released_through.load(Ordering::Acquire);
        v.checked_sub(1)
    }

    fn release_queued_sh_writebehind(&self) {
        if let Some(h) = self.sh_pending_max_height() {
            self.release_sh_writebehind(Height(h));
        }
    }

    fn clamp_sh_released_before(&self, height: Height) {
        let cap = height.0;
        loop {
            let cur = self.sh.released_through.load(Ordering::Acquire);
            if cur <= cap {
                return;
            }
            if self
                .sh
                .released_through
                .compare_exchange(cur, cap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    fn sh_job_released(&self, job: &ShPendingJob) -> bool {
        let rel = self.sh.released_through.load(Ordering::Acquire);
        rel > 0 && job.height.0.saturating_add(1) <= rel
    }

    pub(crate) fn pending_sh_create_fks(&self, scripthash: &[u8; 32]) -> Vec<Fk> {
        self.sh
            .ram_head
            .lock()
            .unwrap()
            .get(scripthash)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn sh_pending_max_height(&self) -> Option<u32> {
        let queued = self
            .sh
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|j| j.height.0)
            .max();
        let applying = self
            .sh
            .applying
            .lock()
            .unwrap()
            .as_ref()
            .map(|j| j.height.0);
        match (queued, applying) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => Some(a.max(b)),
        }
    }

    /// Durable watermark plus pending jobs (RAM records already collected),
    /// never above the live tip (reorg may leave pending jobs until mempool reaccept).
    pub(crate) fn sh_visible_through_height(&self) -> Option<u32> {
        let vis = self
            .sh_indexed_through_height()
            .max(self.sh_pending_max_height())?;
        self.tip_height().map(|tip| vis.min(tip.0))
    }

    /// Apply queued SH write-behind jobs in height order (one Class B appender).
    ///
    /// Production: the tip-follow worker. Tests / [`Self::connect_block`]: drain
    /// so SH history is visible immediately after the fixture connect.
    pub fn apply_sh_pending(&self) -> Result<(), QueryError> {
        self.release_queued_sh_writebehind();
        loop {
            if let Some(job) = self.take_sh_job_for_apply() {
                let height = job.height;
                let result = self.apply_sh_job(job.clone());
                if result.is_err() {
                    self.requeue_sh_job_front(job);
                }
                self.finish_sh_job(height);
                result?;
                continue;
            }
            let pending = self.sh.pending.lock().unwrap();
            let applying = self.sh.applying.lock().unwrap();
            if pending.is_empty() && applying.is_none() {
                return Ok(());
            }
            drop(applying);
            let _ = self
                .sh
                .pending_cv
                .wait_timeout(pending, std::time::Duration::from_millis(200))
                .unwrap();
        }
    }

    /// Pop queue → `sh.applying` so readers still join pending at live tip.
    pub(crate) fn take_sh_job_for_apply(&self) -> Option<ShPendingJob> {
        let mut pending = self.sh.pending.lock().unwrap();
        let mut applying = self.sh.applying.lock().unwrap();
        if applying.is_some() {
            return None;
        }
        let job = pending.front()?;
        if !self.sh_job_released(job) {
            return None;
        }
        let job = pending.pop_front()?;
        *applying = Some(job.clone());
        Some(job)
    }

    fn requeue_sh_job_front(&self, job: ShPendingJob) {
        self.sh.pending.lock().unwrap().push_front(job);
        self.sh.pending_cv.notify_one();
    }

    pub(crate) fn finish_sh_job(&self, height: Height) {
        let mut applying = self.sh.applying.lock().unwrap();
        if applying.as_ref().is_some_and(|j| j.height == height) {
            *applying = None;
        }
        self.sh.pending_cv.notify_all();
    }

    pub(crate) fn apply_sh_job(&self, job: ShPendingJob) -> Result<(), QueryError> {
        let applied = self.apply_sh_job_inner(&job)?;
        if applied {
            unindex_sh_ram_head(&mut self.sh.ram_head.lock().unwrap(), &job);
        }
        Ok(())
    }

    fn apply_sh_job_inner(&self, job: &ShPendingJob) -> Result<bool, QueryError> {
        let _appender = self.sh.appender.lock().unwrap();
        if !self.enqueues_sh_writebehind() {
            return Ok(false);
        }
        if self
            .sh_indexed_through_height()
            .is_some_and(|t| job.height.0 <= t)
        {
            return Ok(false);
        }
        if self.store.confirmed.get(job.height)? != Some(job.header_fk) {
            return Ok(false);
        }

        let sh_creates = &job.records;

        if !sh_creates.is_empty() {
            crate::note_confirm(&self.confirm_stats().sh_create_n, sh_creates.len() as u64);
            let mut uniq = std::collections::HashSet::with_capacity(sh_creates.len());
            for r in sh_creates {
                uniq.insert(r.scripthash);
            }
            crate::note_confirm(&self.confirm_stats().sh_unique_n, uniq.len() as u64);
        }

        let mut tip_sh_max_fk = 0u64;
        if !sh_creates.is_empty() {
            for r in sh_creates {
                tip_sh_max_fk = tip_sh_max_fk.max(r.create_tx_fk.0);
            }
            let mut heads = self.sh.heads.lock().unwrap();
            let (n, timing) = self
                .store
                .scripthash
                .put_create_batch_append(sh_creates, &mut heads)?;
            crate::note_confirm(&self.confirm_stats().sh_written_n, n as u64);
            let st = self.confirm_stats();
            st.add_sh_part(&st.sh_sort_ns, timing.sort_ns);
            st.add_sh_part(&st.sh_seed_ns, timing.seed_ns);
            st.add_sh_part(&st.sh_body_ns, timing.body_ns);
            st.add_sh_part(&st.sh_head_ns, timing.head_ns);
        }

        self.set_sh_indexed_through_height(Some(job.height.0));
        if tip_sh_max_fk > 0 {
            let _ = self.store.scripthash.note_include_hwm(tip_sh_max_fk);
            let _ = self.sh_run.publish_seal_watermark(tip_sh_max_fk);
        }
        Ok(true)
    }

    pub fn drop_sh_pending_from(&self, height: Height) {
        let mut pending = self.sh.pending.lock().unwrap();
        let dropped: Vec<ShPendingJob> = pending
            .iter()
            .filter(|job| job.height.0 >= height.0)
            .cloned()
            .collect();
        pending.retain(|job| job.height.0 < height.0);
        drop(pending);
        let mut applying = self.sh.applying.lock().unwrap();
        let applying_job = if applying.as_ref().is_some_and(|j| j.height.0 >= height.0) {
            applying.take()
        } else {
            None
        };
        drop(applying);
        {
            let mut head = self.sh.ram_head.lock().unwrap();
            for job in &dropped {
                unindex_sh_ram_head(&mut head, job);
            }
            if let Some(job) = applying_job.as_ref() {
                unindex_sh_ram_head(&mut head, job);
            }
        }
        self.clamp_sh_released_before(height);
    }

    /// Restore SH watermark from durable `include_hwm` and re-queue heights the
    /// RAM write-behind lost on restart.
    pub(crate) fn recover_sh_writebehind(&self) -> Result<(), QueryError> {
        let recovered = self.recover_sh_indexed_through()?;
        self.set_sh_indexed_through_height(recovered);
        if !self.store.scripthash.has_durable_index() {
            return Ok(());
        }
        let Some(tip) = self.tip_height() else {
            return Ok(());
        };
        let from = recovered.map(|h| h.saturating_add(1)).unwrap_or(0);
        if from > tip.0 {
            return Ok(());
        }
        let mut items = Vec::new();
        for h in from..=tip.0 {
            let header_fk = self
                .store
                .confirmed
                .get(Height(h))?
                .ok_or(StoreError::Corrupt(
                    "invariant: confirmed height missing header",
                ))?;
            let tx_fks = match self.store.header_txs.get_list(header_fk)? {
                Some(tx_fks) => tx_fks,
                None if h == tip.0 => break,
                None => {
                    return Err(StoreError::Corrupt(
                        "invariant: confirmed height missing header_txs",
                    ));
                }
            };
            items.push(ConfirmPrepared {
                height: Height(h),
                header_fk,
                tx_fks,
            });
        }
        if !items.is_empty() {
            self.enqueue_sh_pending(&items, None)?;
            if let Some(last) = items.last() {
                self.release_sh_writebehind(last.height);
            }
        }
        Ok(())
    }

    fn recover_sh_indexed_through(&self) -> Result<Option<u32>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(None);
        };
        let hwm = self.store.scripthash.include_hwm();
        if hwm == 0 {
            if self.store.scripthash.has_durable_index() {
                return Ok(Some(tip.0));
            }
            return Ok(None);
        }
        let mut h = tip.0;
        loop {
            let header_fk = self
                .store
                .confirmed
                .get(Height(h))?
                .ok_or(StoreError::Corrupt(
                    "invariant: confirmed height missing header",
                ))?;
            let fks = match self.store.header_txs.get_list(header_fk)? {
                Some(fks) => fks,
                None if h == tip.0 => {
                    if h == 0 {
                        return Ok(None);
                    }
                    h -= 1;
                    continue;
                }
                None => {
                    return Err(StoreError::Corrupt(
                        "invariant: confirmed height missing header_txs",
                    ));
                }
            };
            let max_fk = fks.iter().map(|f| f.0).max().unwrap_or(0);
            if max_fk <= hwm {
                return Ok(Some(h));
            }
            if h == 0 {
                return Ok(None);
            }
            h -= 1;
        }
    }

    /// Collect thin scripthash create pointers for one tx's outputs (no spend marks).
    ///
    /// Source order (first hit wins):
    /// 1. **Write-batch CreatePin** — outs already on the confirm write path
    /// 2. **Cold store** — Class A body pread/decode
    ///
    /// Same-batch creates must hit (1) or SH collect re-reads every body.
    /// `write_pin` is the pin Arc for this `tx_fk` when the write path has it.
    pub(crate) fn collect_scripthash_creates(
        &self,
        tx_fk: Fk,
        out: &mut Vec<ScriptHashRecord>,
        write_pin: Option<&CreatePin>,
    ) -> Result<(), QueryError> {
        if let Some(pin) = write_pin {
            let (_tx, outputs) = pin.as_ref();
            for o in outputs.iter() {
                out.push(ScriptHashRecord::from_fk(script_hash(&o.script), tx_fk));
            }
            crate::note_confirm(&self.confirm_stats().sh_collect_pin, 1);
            return Ok(());
        }
        let tx = self.get_tx(tx_fk)?;
        if tx.output_count == 0 {
            crate::note_confirm(&self.confirm_stats().sh_collect_cold, 1);
            return Ok(());
        }
        let outputs = self.tx_output_run_class_a(tx_fk, &tx)?;
        for o in outputs.iter() {
            out.push(ScriptHashRecord::from_fk(script_hash(&o.script), tx_fk));
        }
        crate::note_confirm(&self.confirm_stats().sh_collect_cold, 1);
        Ok(())
    }

    /// Input run keyed by known create fk (packed body works without `tx.head`).
    pub fn tx_input_run_class_a(
        &self,
        create_fk: Fk,
        tx: &TxRecord,
    ) -> Result<Vec<InputRecord>, QueryError> {
        if tx.input_count == 0 {
            return Ok(Vec::new());
        }
        let (_, inputs, _) = self.store.get_tx_full(create_fk)?;
        if inputs.len() as u32 != tx.input_count {
            return Err(StoreError::Corrupt("packed input count mismatch"));
        }
        Ok(inputs)
    }

    /// Output run from store (keyed by known create fk — no txid lookup).
    ///
    /// Preferred for packed Class A (works with `tx.head` off). Callers that only
    /// have a [`TxRecord`] must resolve create fk first (UTXO / head / scan).
    pub(crate) fn tx_output_run_class_a(
        &self,
        create_fk: Fk,
        tx: &TxRecord,
    ) -> Result<Vec<OutputRecord>, QueryError> {
        if tx.output_count == 0 {
            return Ok(Vec::new());
        }
        let (_, _, outs) = self.store.get_tx_full(create_fk)?;
        if outs.len() as u32 != tx.output_count {
            return Err(StoreError::Corrupt("packed output count mismatch"));
        }
        Ok(outs)
    }

    /// Connect a block at `height` (genesis or tip+1): Class A then confirm Class C.
    ///
    /// Cheap store fixture (HeaderRecord + TxApply). Not `confirm_wire_run`.
    /// Drains SH write-behind so fixture reads see creates immediately.
    pub fn connect_block(
        &self,
        height: Height,
        header: &HeaderRecord,
        txs: &[TxApply],
    ) -> Result<Fk, QueryError> {
        self.commit_class_a_only(header, txs)?;
        let fk = self.confirm_block(height, &header.hash)?;
        self.apply_sh_pending()?;
        Ok(fk)
    }

    /// Disconnect the current tip (Class C + scripthash create unlink; archive remains).
    ///
    /// Durable point edges remain for archive history; strong bits cleared below.
    ///
    /// # Crash order (**tip first** — opposite of connect)
    ///
    /// 1. SH unlink (index only; filtered by strong+tip at query time).
    /// 2. `confirmed` truncate in RAM → **`flush_confirmed_only`** (durable tip shrink).
    /// 3. Then `set_unstrong` for disconnected txs → flush strong.
    ///
    /// Unstrong-before-tip would make tip txs fail `is_confirmed_strong` while
    /// tip is still high (permanent if kill). Mid-kill after tip shrink leaves
    /// strong **not on the new fence** → `repair_class_c_above_tip` heals.
    ///
    /// Every successful tip shrink logs [`format_disconnect_tip_line`] at **warn**.
    pub fn disconnect_tip(&self) -> Result<(), QueryError> {
        self.disconnect_tip_with(true)
    }

    /// Class C disconnect without dropping RAM SH pending (reorg reaccept first).
    pub fn disconnect_tip_keep_pending(&self) -> Result<(), QueryError> {
        self.disconnect_tip_with(false)
    }

    fn disconnect_tip_with(&self, drop_pending: bool) -> Result<(), QueryError> {
        let height = self
            .tip_height()
            .ok_or(StoreError::Corrupt("no tip to disconnect"))?;
        let _appender = self.sh.appender.lock().unwrap();
        if drop_pending {
            self.drop_sh_pending_from(height);
        } else {
            self.clamp_sh_released_before(height);
        }
        let hash = self
            .header_at_height(height)?
            .map(|(_, rec)| rec.hash)
            .unwrap_or([0u8; 32]);
        let tx_fks = self.block_tx_fks(height)?;

        let mut touched_sh: Vec<[u8; 32]> = Vec::new();
        for &tx_fk in &tx_fks {
            let tx = self.store.get_tx(tx_fk)?;
            if tx.output_count > 0 {
                let outputs = self.tx_output_run_class_a(tx_fk, &tx)?;
                for (i, o) in outputs.iter().enumerate() {
                    let sh = script_hash(&o.script);
                    let _ = self.store.scripthash.unlink_create(&sh, tx_fk, i as u32)?;
                    touched_sh.push(sh);
                }
            }
        }
        if !touched_sh.is_empty() {
            let mut heads = self.sh.heads.lock().unwrap();
            for sh in touched_sh {
                match self.store.scripthash.head_value(&sh) {
                    Ok(Some(v)) if !v.is_empty() => {
                        rbitcoin_store::sh_heads_insert_capped(
                            &mut heads,
                            sh,
                            v,
                            rbitcoin_store::SH_HEADS_CAP,
                        );
                    }
                    _ => {
                        heads.remove(&sh);
                    }
                }
            }
        }

        self.store.confirmed.disconnect_tip(height)?;
        self.store.height_fence_pop_tip(height);
        self.note_disconnect_height(height.0);
        let _ = self.on_load_pack();
        self.store.flush_confirmed_only()?;
        log_disconnect_tip(height.0, &hash, tx_fks.len());
        if let Some(new_tip) = self.tip_height() {
            let _ = self.ensure_height_by_hash_index(new_tip);
        } else {
            self.invalidate_height_by_hash_index();
        }

        for &tx_fk in &tx_fks {
            self.store.strong_tx.set_unstrong(tx_fk)?;
        }
        self.store.flush_class_c_after_disconnect_tip()?;

        if self.sh_indexed_through_height() == Some(height.0) {
            self.set_sh_indexed_through_height(self.tip_height().map(|h| h.0));
        }
        self.truncate_sp_tweaks_through_tip(self.tip_height())?;
        Ok(())
    }
}

/// Operator line for one confirmed-block disconnect (reorg / restore).
///
/// Hash is Core display-order hex (`BlockHash` `Display`).
pub fn format_disconnect_tip_line(height: u32, hash: &[u8; 32], n_tx: usize) -> String {
    let hash = BlockHash::from_byte_array(*hash);
    format!("DisconnectTip: hash={hash} height={height} tx={n_tx}")
}

fn log_disconnect_tip(height: u32, hash: &[u8; 32], n_tx: usize) {
    rbitcoin_log::warn!("{}", format_disconnect_tip_line(height, hash, n_tx));
}

pub(crate) fn request_sh_writebehind_halt(
    stop: &std::sync::atomic::AtomicBool,
    h: u32,
    e: &impl std::fmt::Display,
) {
    rbitcoin_log::error!("scripthash write-behind h={h}: {e}");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// One Class B appender for SH write-behind. Tests drain via [`Query::apply_sh_pending`].
///
/// Apply errors request `stop` and `on_fatal` so the process exits instead of
/// leaving a dead worker with a growing pending queue.
pub fn spawn_sh_writebehind(
    query: std::sync::Arc<Query>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    on_fatal: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rbtc-sh-wb".into())
        .spawn(move || {
            let mut on_fatal = Some(on_fatal);
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let job = loop {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    if let Some(job) = query.take_sh_job_for_apply() {
                        break job;
                    }
                    let g = query.sh.pending.lock().unwrap();
                    let (g2, wait) = query
                        .sh
                        .pending_cv
                        .wait_timeout(g, std::time::Duration::from_millis(200))
                        .unwrap();
                    drop(g2);
                    if wait.timed_out() {
                        continue;
                    }
                };
                let t0 = std::time::Instant::now();
                let h = job.height.0;
                let height = job.height;
                let apply_err = query.apply_sh_job(job.clone()).err();
                if let Some(e) = apply_err {
                    query.requeue_sh_job_front(job);
                    query.finish_sh_job(height);
                    request_sh_writebehind_halt(&stop, h, &e);
                    if let Some(f) = on_fatal.take() {
                        f();
                    }
                    return;
                }
                query.finish_sh_job(height);
                let wall_ms = t0.elapsed().as_millis();
                let lag = query.sh_lag_heights();
                rbitcoin_log::info!("sh: apply h={h} wall={wall_ms}ms lag={lag}");
            }
        })
        .expect("spawn sh write-behind")
}
