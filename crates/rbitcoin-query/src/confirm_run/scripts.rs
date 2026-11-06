//! Scripts stage (pure CPU verify, plus live filter and tweak jobs).

use super::index::{self, IndexJob};
use super::*;
use rbitcoin_consensus::block::{verify_one_script_job, ScriptCheckJob};
use rbitcoin_consensus::script_pool::{
    fg_has_unclaimed, set_script_publisher, start_for_each_owned, start_for_each_owned_keep,
    start_for_each_pooled, OwnedWave,
};
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// In-flight waves the stage thread will publish while steal is empty.
/// Matches `scriptq` cap so load→scripts retain stays bounded.
#[doc(hidden)]
pub const SCRIPT_WAVES_MAX: usize = 4;

#[doc(hidden)]
pub fn take_script_jobs(
    prepared: &mut [Prepared],
    preverified: &ScriptPreverified,
    stats: &crate::ConfirmStats,
) -> (Vec<ScriptCheckJob>, Vec<u32>) {
    let mut jobs = Vec::new();
    let mut heights = Vec::new();
    let mut n_skip = 0u64;
    for p in prepared {
        if !p.check_scripts {
            p.jobs.clear();
            p.jobs.shrink_to_fit();
            continue;
        }
        let height = p.height.0;
        for job in p.jobs.drain(..) {
            if preverified.contains(&job.txid) {
                n_skip = n_skip.saturating_add(1);
            } else {
                jobs.push(job);
                heights.push(height);
            }
        }
        p.jobs.shrink_to_fit();
    }
    if n_skip > 0 {
        crate::note_confirm(&stats.script_skip_mempool, n_skip);
    }
    crate::note_confirm(&stats.script_jobs, jobs.len() as u64);
    (jobs, heights)
}

#[doc(hidden)]
pub fn outcome_from(
    batch: LoadedBatch,
    work_ns: u64,
    index_done_ns: u64,
    seal: super::index::IndexSeal,
    idx_asm_ns: u64,
    mut trust_script_warns: Vec<(u32, rbitcoin_consensus::ConsensusError)>,
) -> ConfirmScriptOutcome {
    crate::note_confirm(&batch.stats.script_ns, work_ns);
    let mut held = batch.trust_warns;
    held.append(&mut trust_script_warns);
    let trust_script_warns = held;
    if idx_asm_ns > 0 {
        crate::note_confirm(&batch.stats.idx_asm_ns, idx_asm_ns);
        crate::note_confirm(&batch.stats.blockfilter_ns, idx_asm_ns);
    }
    ConfirmScriptOutcome {
        batch: ScriptOkBatch {
            prepared: batch.prepared,
            wire_blocks: batch.wire_blocks,
            batch_parents: batch.batch_parents,
            archive_plan: batch.archive_plan,
            index_seal: seal,
            trust_script_warns,
        },
        work_ns,
        index_done_ns,
        idx_asm_ns,
    }
}

#[doc(hidden)]
pub fn apply_script(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
    verify_one_script_job(job)
}

#[doc(hidden)]
pub struct Inflight {
    pub batch: LoadedBatch,
    pub t0: Instant,
    /// Older wave. Workers claim it before the index wave.
    pub script_wave: Option<OwnedWave<ScriptCheckJob>>,
    pub index_wave: Option<OwnedWave<IndexJob>>,
    pub script_heights: Vec<u32>,
    pub slots: Vec<index::HeightSlots>,
    pub index_started: Arc<OnceLock<Instant>>,
    pub script_done: OnceLock<u64>,
    pub index_done: OnceLock<u64>,
    pub idx_asm: OnceLock<u64>,
    pub meta: ScriptsBatchMeta,
    /// Warn-and-apply script faults. Moved onto the batch only when this
    /// wave finishes without a hard stop. A later connect failure drops them.
    pub script_warns: Vec<(u32, rbitcoin_consensus::ConsensusError)>,
}

impl Inflight {
    #[doc(hidden)]
    pub fn start(
        mut batch: LoadedBatch,
        mat_ns: u64,
    ) -> Result<Self, (ConfirmError, ScriptsBatchMeta)> {
        let t0 = Instant::now();
        let meta = ScriptsBatchMeta::from_batch(&batch, mat_ns);
        let (scripts, script_heights) =
            take_script_jobs(&mut batch.prepared, &batch.script_preverified, &batch.stats);
        let index_jobs = match index::prepare_index_jobs(&batch) {
            Ok(jobs) => jobs,
            Err(e) => return Err((e, meta)),
        };
        let index_started = index_jobs.started;
        let started = if batch.trust_peer {
            start_for_each_owned_keep(scripts, apply_script)
        } else {
            start_for_each_owned(scripts, apply_script)
        };
        let mut script_warns = Vec::new();
        let script_wave = match started {
            Ok(w) => w,
            Err(e) => {
                // A single job runs on this thread inside `start`. Keep a
                // warn-and-apply fault on the batch. The write stage logs it
                // only after connect. This stage does not enter TrustCollect.
                let height = script_heights.first().copied();
                if batch.trust_peer && rbitcoin_consensus::is_warn_and_apply(&e) {
                    script_warns.push((fault_height(&batch, height), e));
                    None
                } else {
                    let err = ConfirmError::Rules(e);
                    log_batch_stop(&batch, &err);
                    return Err((err, meta));
                }
            }
        };
        let index_wave = match start_for_each_pooled(index_jobs.jobs, index::apply_index_job, 1) {
            Ok(w) => w,
            Err(e) => {
                let err = ConfirmError::from(e);
                log_batch_stop(&batch, &err);
                return Err((err, meta));
            }
        };
        let inf = Self {
            batch,
            t0,
            script_wave,
            index_wave,
            script_heights,
            slots: index_jobs.slots,
            index_started,
            script_done: OnceLock::new(),
            index_done: OnceLock::new(),
            idx_asm: OnceLock::new(),
            meta,
            script_warns,
        };
        inf.note_clocks();
        Ok(inf)
    }

    #[doc(hidden)]
    pub fn note_clocks(&self) {
        let scripts_done = self.script_wave.as_ref().is_none_or(|w| w.is_complete());
        if scripts_done {
            let _ = self.script_done.set(self.t0.elapsed().as_nanos() as u64);
        }
        if self.index_wave.as_ref().is_some_and(|w| w.is_complete()) {
            self.stamp_index();
        }
    }

    #[doc(hidden)]
    pub fn stamp_index(&self) {
        let now = Instant::now();
        let _ = self
            .index_done
            .set(now.saturating_duration_since(self.t0).as_nanos() as u64);
        let asm = self
            .index_started
            .get()
            .map(|start| now.saturating_duration_since(*start).as_nanos() as u64)
            .unwrap_or(0);
        let _ = self.idx_asm.set(asm);
    }

    #[doc(hidden)]
    pub fn is_complete(&self) -> bool {
        self.note_clocks();
        let scripts_done = self.script_wave.as_ref().is_none_or(|w| w.is_complete());
        let index_done = self.index_wave.as_ref().is_none_or(|w| w.is_complete());
        scripts_done && index_done
    }

    #[doc(hidden)]
    pub fn finish(mut self) -> Result<(ConfirmScriptOutcome, ScriptsBatchMeta), ConfirmError> {
        if let Some(w) = self.script_wave.as_ref() {
            w.wait();
        }
        let indexed = self
            .script_wave
            .as_ref()
            .map(|w| w.take_faults())
            .unwrap_or_default();
        let mut kept = Vec::new();
        let mut script_stop = None;
        for (idx, err) in indexed {
            let height = self.script_heights.get(idx).copied();
            if self.batch.trust_peer && rbitcoin_consensus::is_warn_and_apply(&err) {
                kept.push((height, err));
            } else {
                script_stop = Some((height, err));
                break;
            }
        }
        // `ConsensusError` is not `Clone`. A stop already in hand means the
        // wave's `first_err` is the same class; skip `finish` so the owned
        // error is returned once.
        let wave_stop = if script_stop.is_some() {
            None
        } else {
            match self.script_wave.take() {
                Some(w) => w.finish().err(),
                None => None,
            }
        };
        let _ = self.script_done.set(self.t0.elapsed().as_nanos() as u64);
        let had_index = self.index_wave.is_some();
        let index_res = match self.index_wave.take() {
            Some(w) => w.finish(),
            None => Ok(()),
        };
        if had_index {
            self.stamp_index();
        }
        // A hard stop drops the kept script faults. Only the stop is logged,
        // and only as not applied. Connect is what logs a kept fault.
        if script_stop.is_none() && wave_stop.is_none() {
            for (height, err) in kept {
                let h = fault_height(&self.batch, height);
                self.script_warns.push((h, err));
            }
        }
        if let Some((height, err)) = script_stop {
            log_batch_fault(&self.batch, height, &err, false);
            return Err(crate::ConfirmError::Rules(err));
        }
        if let Some(e) = wave_stop {
            let height = self.script_heights.first().copied();
            log_batch_fault(&self.batch, height, &e, false);
            return Err(crate::ConfirmError::Rules(e));
        }
        if let Err(e) = index_res {
            let err = crate::ConfirmError::from(e);
            log_batch_stop(&self.batch, &err);
            return Err(err);
        }
        let seal = if self.slots.is_empty() {
            Ok(index::IndexSeal::default())
        } else {
            index::rows_from_heights(&self.slots)
        };
        let seal = match seal {
            Ok(seal) => seal,
            Err(e) => {
                log_batch_stop(&self.batch, &e);
                return Err(e);
            }
        };
        let work_ns = self.script_done.get().copied().unwrap_or(0);
        let index_done_ns = self.index_done.get().copied().unwrap_or(0);
        let idx_asm_ns = self.idx_asm.get().copied().unwrap_or(0);
        let warns = std::mem::take(&mut self.script_warns);
        Ok((
            outcome_from(self.batch, work_ns, index_done_ns, seal, idx_asm_ns, warns),
            self.meta,
        ))
    }
}

fn fault_height(batch: &LoadedBatch, height: Option<u32>) -> u32 {
    height
        .or_else(|| batch.prepared.first().map(|p| p.height.0))
        .unwrap_or(0)
}

fn log_batch_fault(
    batch: &LoadedBatch,
    height: Option<u32>,
    err: &rbitcoin_consensus::ConsensusError,
    applied: bool,
) {
    if !batch.trust_peer {
        return;
    }
    let fallback = batch.prepared.first().map(|p| (p.height.0, p.hash));
    let h = height.or_else(|| fallback.map(|(h, _)| h)).unwrap_or(0);
    let hash = batch
        .prepared
        .iter()
        .find(|p| p.height.0 == h)
        .map(|p| p.hash)
        .or_else(|| fallback.map(|(_, hash)| hash))
        .unwrap_or([0; 32]);
    super::warn_trust_block(applied, hash, h, err);
}

fn log_batch_stop(batch: &LoadedBatch, err: &ConfirmError) {
    let ConfirmError::Rules(rules) = err else {
        return;
    };
    let height = batch.prepared.first().map(|p| p.height.0);
    log_batch_fault(batch, height, rules, false);
}

pub fn confirm_scripts_phase(batch: LoadedBatch) -> Result<ConfirmScriptOutcome, ConfirmError> {
    match Inflight::start(batch, 0) {
        Ok(inf) => inf.finish().map(|(o, _)| o),
        Err((e, _)) => Err(e),
    }
}

/// IBD scripts stage: a script wave, then an index wave, per batch.
/// The next batch is published when both waves have nothing left to claim.
/// Write handoff stays in height order, after both waves have finished.
///
/// `on_take` receives the recv-wait before this batch was taken (zero when
/// `try_recv` hit a ready item).
pub fn drive_script_waves_with(
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    mut on_take: impl FnMut(&LoadedBatch, Duration),
    mut on_ok: impl FnMut(ConfirmScriptOutcome, ScriptsBatchMeta) -> bool,
    mut on_err: impl FnMut(ConfirmError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
    mut should_stop: impl FnMut() -> bool,
) {
    struct ClearPublisher;
    impl Drop for ClearPublisher {
        fn drop(&mut self) {
            set_script_publisher(None);
        }
    }
    set_script_publisher(Some(thread::current()));
    let _clear = ClearPublisher;
    let mut inflight: VecDeque<Inflight> = VecDeque::new();
    loop {
        if should_stop() {
            break;
        }
        if drive_drain_complete(&mut inflight, &mut on_ok, &mut on_err) {
            return;
        }
        match drive_try_start(&mut inflight, mat_rx, &mut on_take, &mut on_err) {
            DriveStart::Continue => continue,
            DriveStart::Abort => return,
            DriveStart::Stop => break,
            DriveStart::Idle => {}
        }
        if inflight.is_empty() {
            match drive_blocking_start(&mut inflight, mat_rx, &mut on_take, &mut on_err) {
                DriveStart::Continue => continue,
                DriveStart::Abort | DriveStart::Stop | DriveStart::Idle => break,
            }
        }
        thread::park_timeout(Duration::from_millis(1));
    }
}

#[doc(hidden)]
pub enum DriveStart {
    Continue,
    Idle,
    Stop,
    Abort,
}

#[doc(hidden)]
pub fn drop_inflight_tail(inflight: &mut VecDeque<Inflight>) -> Vec<ScriptsBatchMeta> {
    let mut dropped = Vec::with_capacity(inflight.len());
    while let Some(rest) = inflight.pop_front() {
        dropped.push(rest.meta.clone());
        let _ = rest.finish();
    }
    dropped
}

#[doc(hidden)]
pub fn drive_drain_complete(
    inflight: &mut VecDeque<Inflight>,
    on_ok: &mut impl FnMut(ConfirmScriptOutcome, ScriptsBatchMeta) -> bool,
    on_err: &mut impl FnMut(ConfirmError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
) -> bool {
    while inflight.front().is_some_and(Inflight::is_complete) {
        let front = inflight.pop_front().expect("front");
        let meta_err = front.meta.clone();
        match front.finish() {
            Ok((ok, meta)) => {
                if !on_ok(ok, meta) {
                    return true;
                }
            }
            Err(e) => {
                let dropped = drop_inflight_tail(inflight);
                if !on_err(e, meta_err, &dropped) {
                    return true;
                }
            }
        }
    }
    false
}

#[doc(hidden)]
pub fn drive_try_start(
    inflight: &mut VecDeque<Inflight>,
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    on_take: &mut impl FnMut(&LoadedBatch, Duration),
    on_err: &mut impl FnMut(ConfirmError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
) -> DriveStart {
    if fg_has_unclaimed() || inflight.len() >= SCRIPT_WAVES_MAX {
        return DriveStart::Idle;
    }
    let t_recv = Instant::now();
    match mat_rx.try_recv() {
        Ok((batch, mat_ns)) => {
            on_take(&batch, t_recv.elapsed());
            match Inflight::start(batch, mat_ns) {
                Ok(f) => {
                    inflight.push_back(f);
                    DriveStart::Continue
                }
                Err((e, meta)) => {
                    if on_err(e, meta, &[]) {
                        DriveStart::Continue
                    } else {
                        DriveStart::Abort
                    }
                }
            }
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => DriveStart::Idle,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            if inflight.is_empty() {
                DriveStart::Stop
            } else {
                DriveStart::Idle
            }
        }
    }
}

#[doc(hidden)]
pub fn drive_blocking_start(
    inflight: &mut VecDeque<Inflight>,
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    on_take: &mut impl FnMut(&LoadedBatch, Duration),
    on_err: &mut impl FnMut(ConfirmError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
) -> DriveStart {
    let t_recv = Instant::now();
    match mat_rx.recv() {
        Ok((batch, mat_ns)) => {
            on_take(&batch, t_recv.elapsed());
            match Inflight::start(batch, mat_ns) {
                Ok(f) => {
                    inflight.push_back(f);
                    DriveStart::Continue
                }
                Err((e, meta)) => {
                    if on_err(e, meta, &[]) {
                        DriveStart::Continue
                    } else {
                        DriveStart::Stop
                    }
                }
            }
        }
        Err(_) => DriveStart::Stop,
    }
}

/// Metadata retained across wave submit → ordered write handoff.
#[derive(Clone, Debug)]
pub struct ScriptsBatchMeta {
    pub n: usize,
    pub first_h: u32,
    pub heights_hashes: Vec<(u32, [u8; 32])>,
    /// Arc clones of the batch's bodies (no copy), so a rejected wave can be
    /// offered back to the body queue.
    pub wire_blocks: Vec<Arc<Block>>,
    pub mat_ns: u64,
    pub t0: Instant,
}

impl ScriptsBatchMeta {
    pub fn from_batch(batch: &LoadedBatch, mat_ns: u64) -> Self {
        let heights_hashes = batch.heights_hashes();
        let first_h = heights_hashes.first().map(|(h, _)| *h).unwrap_or(0);
        Self {
            n: batch.len(),
            first_h,
            heights_hashes,
            wire_blocks: batch.wire_blocks.clone(),
            mat_ns,
            t0: Instant::now(),
        }
    }
}
