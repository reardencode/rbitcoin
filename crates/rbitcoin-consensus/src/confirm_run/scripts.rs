//! Scripts stage (pure CPU verify).

use super::*;
use crate::block::{verify_one_script_job, ScriptCheckJob};
use crate::script_pool::{
    fg_has_unclaimed, help_steal, set_script_publisher, start_for_each_owned, OwnedWave,
};
use std::cell::Cell;
use std::collections::VecDeque;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// In-flight waves the stage thread will publish while steal is empty.
/// Matches `scriptq` cap so load→scripts retain stays bounded.
const SCRIPT_WAVES_MAX: usize = 4;

fn take_script_jobs(
    prepared: &mut [Prepared],
    preverified: &ScriptPreverified,
    stats: &rbitcoin_query::ConfirmStats,
) -> Vec<ScriptCheckJob> {
    let mut jobs = Vec::new();
    let mut n_skip = 0u64;
    for p in prepared {
        if !p.check_scripts {
            p.jobs.clear();
            p.jobs.shrink_to_fit();
            continue;
        }
        for job in p.jobs.drain(..) {
            if preverified.contains(&job.txid) {
                n_skip = n_skip.saturating_add(1);
            } else {
                jobs.push(job);
            }
        }
        p.jobs.shrink_to_fit();
    }
    if n_skip > 0 {
        rbitcoin_query::note_confirm(&stats.script_skip_mempool, n_skip);
    }
    rbitcoin_query::note_confirm(&stats.script_jobs, jobs.len() as u64);
    jobs
}

fn outcome_from(
    batch: LoadedBatch,
    work_ns: u64,
    seal: super::index::IndexSeal,
    idx_asm_ns: u64,
) -> ConfirmScriptOutcome {
    rbitcoin_query::note_confirm(&batch.stats.script_ns, work_ns);
    if idx_asm_ns > 0 {
        rbitcoin_query::note_confirm(&batch.stats.idx_asm_ns, idx_asm_ns);
        rbitcoin_query::note_confirm(&batch.stats.blockfilter_ns, idx_asm_ns);
    }
    ConfirmScriptOutcome {
        batch: ScriptOkBatch {
            prepared: batch.prepared,
            wire_blocks: batch.wire_blocks,
            batch_parents: batch.batch_parents,
            archive_plan: batch.archive_plan,
            index_seal: seal,
        },
        work_ns,
        idx_asm_ns,
    }
}

struct Inflight {
    batch: LoadedBatch,
    wave: Option<OwnedWave<ScriptCheckJob>>,
    meta: ScriptsBatchMeta,
    t0: Instant,
    done_ns: Cell<Option<u64>>,
}

impl Inflight {
    fn start(
        mut batch: LoadedBatch,
        mat_ns: u64,
    ) -> Result<Self, (ConsensusError, ScriptsBatchMeta)> {
        let t0 = Instant::now();
        let meta = ScriptsBatchMeta::from_batch(&batch, mat_ns);
        let jobs = take_script_jobs(&mut batch.prepared, &batch.script_preverified, &batch.stats);
        let wave = match start_for_each_owned(jobs, verify_one_script_job) {
            Ok(w) => w,
            Err(e) => return Err((e, meta)),
        };
        let inf = Self {
            batch,
            wave,
            meta,
            t0,
            done_ns: Cell::new(None),
        };
        let _ = inf.is_complete();
        Ok(inf)
    }

    fn is_complete(&self) -> bool {
        let done = self.wave.as_ref().is_none_or(|w| w.is_complete());
        if done && self.done_ns.get().is_none() {
            self.done_ns.set(Some(self.t0.elapsed().as_nanos() as u64));
        }
        done
    }

    fn finish(self) -> Result<(ConfirmScriptOutcome, ScriptsBatchMeta), ConsensusError> {
        let work_ns = self
            .done_ns
            .get()
            .unwrap_or_else(|| self.t0.elapsed().as_nanos() as u64);
        if let Some(w) = self.wave {
            w.finish()?;
        }
        let (seal, idx_asm_ns) = super::index::live_index_seal(&self.batch)?;
        Ok((
            outcome_from(self.batch, work_ns, seal, idx_asm_ns),
            self.meta,
        ))
    }
}

pub fn confirm_scripts_phase(batch: LoadedBatch) -> Result<ConfirmScriptOutcome, ConsensusError> {
    match Inflight::start(batch, 0) {
        Ok(inf) => inf.finish().map(|(o, _)| o),
        Err((e, _)) => Err(e),
    }
}

/// IBD scripts stage: publish waves from the stage thread, steal-help, in-order
/// write handoff. Starts another `scriptq` batch when the steal list is empty.
///
/// `on_take` receives the recv-wait before this batch was taken (zero when
/// `try_recv` hit a ready item).
pub fn drive_script_waves_with(
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    mut on_take: impl FnMut(&LoadedBatch, Duration),
    mut on_ok: impl FnMut(ConfirmScriptOutcome, ScriptsBatchMeta) -> bool,
    mut on_err: impl FnMut(ConsensusError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
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
        if help_steal() {
            continue;
        }
        thread::park_timeout(Duration::from_millis(1));
    }
}

enum DriveStart {
    Continue,
    Idle,
    Stop,
    Abort,
}

fn drop_inflight_tail(inflight: &mut VecDeque<Inflight>) -> Vec<ScriptsBatchMeta> {
    let mut dropped = Vec::with_capacity(inflight.len());
    while let Some(rest) = inflight.pop_front() {
        dropped.push(rest.meta.clone());
        let _ = rest.finish();
    }
    dropped
}

fn drive_drain_complete(
    inflight: &mut VecDeque<Inflight>,
    on_ok: &mut impl FnMut(ConfirmScriptOutcome, ScriptsBatchMeta) -> bool,
    on_err: &mut impl FnMut(ConsensusError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
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

fn drive_try_start(
    inflight: &mut VecDeque<Inflight>,
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    on_take: &mut impl FnMut(&LoadedBatch, Duration),
    on_err: &mut impl FnMut(ConsensusError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
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

fn drive_blocking_start(
    inflight: &mut VecDeque<Inflight>,
    mat_rx: &std::sync::mpsc::Receiver<(LoadedBatch, u64)>,
    on_take: &mut impl FnMut(&LoadedBatch, Duration),
    on_err: &mut impl FnMut(ConsensusError, ScriptsBatchMeta, &[ScriptsBatchMeta]) -> bool,
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
