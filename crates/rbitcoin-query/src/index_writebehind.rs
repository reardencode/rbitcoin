//! Block index materialize (`rbtc-idx-wb`): BIP158 basic filters and BIP-352
//! tweaks from one read of Class A when a watermark is behind the tip.
//!
//! [`prepare_live_indexes`] seals a restart gap of at most one IBD write
//! drain before confirm runs. A larger gap stays on this reader. Confirm
//! batches do not call it.
//!
//! The IO thread plans windows of consecutive heights from the lower index
//! watermark up to the released tip and reads each through
//! [`rbitcoin_store::read_index_window`] (one completion session). One CPU
//! worker publishes one job per height to `rbtc-scripts-*` (filter GCS and
//! tweak EC) and commits each index once per window
//! under the index write-behind lock. A commit that finds its watermark or a
//! `confirmed[h]` moved (a reorg) returns 0, and the IO thread re-plans from
//! the watermarks. A wide gap is the materialize; at the tip each release is
//! a one-height window.

use crate::index_rows::{self, IndexHeightOut, IndexRows};
use crate::sp_read::tweak_records_from_window;
use crate::ConfirmError;
use crate::Query;
use rbitcoin_consensus::ConsensusError;
use rbitcoin_log::progress;
use rbitcoin_primitives::Height;
use rbitcoin_store::IndexWindow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Heights per window. Bounds how long a disconnect waits and how far the
/// IO thread reads ahead of commits.
#[doc(hidden)]
pub const WINDOW_HEIGHTS: u32 = 64;
/// Creates per window. RAM trade: a window holds its blocks' outputs, input
/// edges, P2TR-output witnesses, and spent parents (tens of MB at mainnet
/// sizes); at most two windows wait for the CPU worker.
#[doc(hidden)]
pub const WINDOW_TXS: u64 = 50_000;
#[doc(hidden)]
pub const PROGRESS_EVERY: Duration = Duration::from_secs(10);

/// Lowest height either index still needs, if any index is on.
#[doc(hidden)]
pub fn next_needed(query: &Query) -> Option<u32> {
    match (query.filter_index_next(), query.tweak_index_next()) {
        (Some(f), Some(t)) => Some(f.min(t)),
        (f, t) => f.or(t),
    }
}

/// `blockfilter build` and `sp_tweaks build` for the health listener's
/// `/progress`, one stage per index since the two watermarks move apart (an
/// index turned on later, or a tweak origin above 0). Counts heights from
/// where the index starts (0 for filters, the tweak origin for tweaks) through
/// the target, read from the committed watermarks. A stage begins only when
/// its index is a full window behind, so tip following does not register one
/// per block, and ends when the watermark passes the target or the index is
/// turned off.
#[derive(Default)]
#[doc(hidden)]
pub struct IndexStages {
    pub filters: Option<progress::Stage>,
    pub tweaks: Option<progress::Stage>,
}

impl IndexStages {
    /// Refresh from the watermarks. `filters` / `tweaks` false leave that
    /// index untracked (a startup repair that skips it).
    #[doc(hidden)]
    pub fn observe(&mut self, query: &Query, target: Option<u32>, filters: bool, tweaks: bool) {
        if filters {
            track_index(
                &mut self.filters,
                "blockfilter build",
                query.filter_index_next(),
                0,
                target,
            );
        }
        if tweaks {
            track_index(
                &mut self.tweaks,
                "sp_tweaks build",
                query.tweak_index_next(),
                query.sptweaks_origin().0,
                target,
            );
        }
    }
}

#[doc(hidden)]
pub fn track_index(
    slot: &mut Option<progress::Stage>,
    stage: &'static str,
    next: Option<u32>,
    from: u32,
    target: Option<u32>,
) {
    let (Some(next), Some(target)) = (next, target) else {
        *slot = None;
        return;
    };
    let done = u64::from(next.saturating_sub(from));
    let total = u64::from(target.saturating_add(1).saturating_sub(from));
    if next > target {
        if let Some(s) = slot.take() {
            s.set_total(total);
            s.set_done(done);
        }
        return;
    }
    match slot {
        Some(s) => {
            s.set_total(total);
            s.set_done(done);
        }
        None if target - next >= WINDOW_HEIGHTS => {
            *slot = Some(progress::begin_at(stage, total, done));
        }
        None => {}
    }
}

/// Heights one IBD write drain can leave unsealed: write queue (14) times
/// the confirm run cap (144).
pub const INDEX_STARTUP_GAP_HEIGHTS: u32 = 14 * 144;

/// Tip entry: spawn the materialize only while an enabled watermark is still
/// behind the tip and live append is off. Advertise filters immediately when
/// that watermark already covers the tip.
pub struct IndexTipEntry {
    pub spawn: bool,
    pub advertise_filters: bool,
}

pub fn index_tip_entry(query: &Query) -> IndexTipEntry {
    let tip = query.tip_height().map(|h| h.0);
    let behind = |next: Option<u32>| next.is_some_and(|n| tip.is_some_and(|t| n <= t));
    let caught = |next: Option<u32>| next.is_some_and(|n| tip.is_some_and(|t| n > t));
    IndexTipEntry {
        spawn: !query.index_live()
            && (behind(query.filter_index_next()) || behind(query.tweak_index_next())),
        advertise_filters: caught(query.filter_index_next()),
    }
}

/// Before confirm: seal each enabled index whose gap through the tip fits
/// [`INDEX_STARTUP_GAP_HEIGHTS`], then set [`Query::index_live`] when every
/// enabled index is contiguous with the tip.
pub fn prepare_live_indexes(query: &Query) -> Result<(), ConfirmError> {
    prepare_live_indexes_limited(query, INDEX_STARTUP_GAP_HEIGHTS)
}

pub fn prepare_live_indexes_limited(query: &Query, max_heights: u32) -> Result<(), ConfirmError> {
    let tip_h = query.tip_height().map(|h| h.0);
    if let Some(tip) = tip_h {
        let repair_f = repair_from(query.filter_index_next(), tip, max_heights);
        let repair_t = repair_from(query.tweak_index_next(), tip, max_heights);
        if repair_f.is_some() || repair_t.is_some() {
            seal_through(query, repair_f, repair_t, tip)?;
        }
    }
    let tip_h = query.tip_height().map(|h| h.0);
    let any_on = query.filter_index_next().is_some() || query.tweak_index_next().is_some();
    query.set_index_live(
        any_on
            && index_caught_up(query.filter_index_next(), tip_h)
            && index_caught_up(query.tweak_index_next(), tip_h),
    );
    Ok(())
}

#[doc(hidden)]
pub fn repair_from(next: Option<u32>, tip: u32, max_heights: u32) -> Option<u32> {
    let next = next?;
    if next > tip {
        return None;
    }
    let gap = tip.saturating_add(1).saturating_sub(next);
    (gap <= max_heights).then_some(next)
}

#[doc(hidden)]
pub fn index_caught_up(next: Option<u32>, tip: Option<u32>) -> bool {
    match (next, tip) {
        (None, _) => true,
        (Some(_), None) => true,
        (Some(n), Some(t)) => n > t,
    }
}

/// Read and commit `start..=tip` for the indexes in `filter_from` / `tweak_from`.
/// `None` means that index is not part of this repair.
#[doc(hidden)]
pub fn seal_through(
    query: &Query,
    filter_from: Option<u32>,
    tweak_from: Option<u32>,
    tip: u32,
) -> Result<(), ConfirmError> {
    let mut start = match (filter_from, tweak_from) {
        (Some(f), Some(t)) => f.min(t),
        (Some(f), None) => f,
        (None, Some(t)) => t,
        (None, None) => return Ok(()),
    };
    let mut live = IndexStages::default();
    let observe = |live: &mut IndexStages| {
        live.observe(
            query,
            Some(tip),
            filter_from.is_some(),
            tweak_from.is_some(),
        );
    };
    observe(&mut live);
    while start <= tip {
        let end = plan_window(query, start, tip)?;
        let window = Arc::new(read_window_from(query, start, end, tweak_from)?);
        let rows = assemble_window_from(&window, filter_from, tweak_from)?;
        if index_rows::commit_index_rows(query, rows)?.moved {
            return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: startup index repair",
            )));
        }
        observe(&mut live);
        if end >= tip {
            break;
        }
        start = end + 1;
    }
    Ok(())
}

#[doc(hidden)]
pub fn plan_window(query: &Query, start: u32, target: u32) -> Result<u32, ConfirmError> {
    let mut end = start;
    let mut txs = 0u64;
    while end < target && end - start + 1 < WINDOW_HEIGHTS {
        let fk = query.store().confirmed.get(Height(end + 1))?.ok_or(
            rbitcoin_store::StoreError::Corrupt("invariant: index height not confirmed"),
        )?;
        let n = query
            .store()
            .header_txs
            .get_range(fk)?
            .map_or(0, |(_, n)| u64::from(n));
        if txs + n > WINDOW_TXS {
            break;
        }
        txs += n;
        end += 1;
    }
    Ok(end)
}

#[doc(hidden)]
pub fn read_window(query: &Query, start: u32, end: u32) -> Result<IndexWindow, ConfirmError> {
    read_window_from(query, start, end, query.tweak_index_next())
}

#[doc(hidden)]
pub fn read_window_from(
    query: &Query,
    start: u32,
    end: u32,
    tweaks_from: Option<u32>,
) -> Result<IndexWindow, ConfirmError> {
    let heights = query.index_heights(start, end, tweaks_from)?;
    let mut window = query.read_index_window(&heights)?;
    for block in &mut window.blocks {
        block.hash = query.store().get_header(block.header_fk)?.hash;
    }
    Ok(window)
}

#[doc(hidden)]
pub struct IndexHeightJob {
    pub window: Arc<IndexWindow>,
    pub index: usize,
    pub want_filter: bool,
    pub want_tweaks: bool,
    pub out: Arc<Mutex<Option<IndexHeightOut>>>,
}

#[doc(hidden)]
pub fn assemble_index_height_pool(job: &IndexHeightJob) -> Result<(), ConsensusError> {
    assemble_index_height(job).map_err(ConfirmError::into_pool)
}

#[doc(hidden)]
pub fn assemble_index_height(job: &IndexHeightJob) -> Result<(), ConfirmError> {
    let block = &job.window.blocks[job.index];
    let filter = if job.want_filter {
        Some((
            block.height,
            crate::basic_filter_of(&block.hash, &job.window, job.index)?,
            block.header_fk,
        ))
    } else {
        None
    };
    let tweaks = if job.want_tweaks {
        Some((
            block.height,
            block.header_fk,
            tweak_records_from_window(&job.window, job.index)?,
        ))
    } else {
        None
    };
    *job.out.lock().unwrap_or_else(|e| e.into_inner()) = Some(IndexHeightOut { filter, tweaks });
    Ok(())
}

/// One job per height that still needs a filter or tweaks. The wave joins
/// before return, so the `Arc` is only shared for that call.
#[doc(hidden)]
pub fn assemble_window(
    query: &Query,
    window: &Arc<IndexWindow>,
) -> Result<IndexRows, ConfirmError> {
    assemble_window_from(window, query.filter_index_next(), query.tweak_index_next())
}

#[doc(hidden)]
pub fn assemble_window_from(
    window: &Arc<IndexWindow>,
    filter_from: Option<u32>,
    tweak_from: Option<u32>,
) -> Result<IndexRows, ConfirmError> {
    let mut slots = Vec::with_capacity(window.blocks.len());
    let mut jobs = Vec::new();
    for (index, block) in window.blocks.iter().enumerate() {
        let h = block.height.0;
        let want_filter = filter_from.is_some_and(|n| h >= n);
        let want_tweaks = tweak_from.is_some_and(|n| h >= n);
        let out = Arc::new(Mutex::new(None));
        if want_filter || want_tweaks {
            jobs.push(IndexHeightJob {
                window: Arc::clone(window),
                index,
                want_filter,
                want_tweaks,
                out: Arc::clone(&out),
            });
        }
        slots.push(out);
    }
    index_rows::finish_wave(jobs, assemble_index_height_pool)?;
    Ok(index_rows::rows_from_slots(&slots))
}

/// Milliseconds of one interval, or of one tip window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct IndexStageSample {
    pub read_ms: u64,
    pub build_ms: u64,
    pub commit_ms: u64,
}

/// Interval sums for `index: build` / `index: apply`. Not an `ibd: perf` token.
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct IndexStageMs {
    pub read_ns: AtomicU64,
    pub build_ns: AtomicU64,
    pub commit_ns: AtomicU64,
}

impl IndexStageMs {
    #[doc(hidden)]
    pub fn add_ns(slot: &AtomicU64, ns: u64) {
        if ns > 0 {
            slot.fetch_add(ns, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn add_read(&self, ns: u64) {
        Self::add_ns(&self.read_ns, ns);
    }

    #[doc(hidden)]
    pub fn add_build(&self, ns: u64) {
        Self::add_ns(&self.build_ns, ns);
    }

    #[doc(hidden)]
    pub fn add_commit(&self, ns: u64) {
        Self::add_ns(&self.commit_ns, ns);
    }

    /// Take the interval and reset. Sub-millisecond leftovers truncate.
    #[doc(hidden)]
    pub fn take_ms(&self) -> IndexStageSample {
        IndexStageSample {
            read_ms: self.read_ns.swap(0, Ordering::Relaxed) / 1_000_000,
            build_ms: self.build_ns.swap(0, Ordering::Relaxed) / 1_000_000,
            commit_ms: self.commit_ns.swap(0, Ordering::Relaxed) / 1_000_000,
        }
    }
}

#[doc(hidden)]
pub struct IndexBuildProgress {
    pub next: u32,
    pub tip: u32,
    pub from: u32,
    pub elapsed: Duration,
    pub stages: IndexStageSample,
}

#[doc(hidden)]
pub fn format_index_build_progress(p: &IndexBuildProgress) -> String {
    let secs = p.elapsed.as_secs_f64();
    let rate = f64::from(p.next.saturating_sub(p.from)) / secs.max(0.001);
    format!(
        "index: build next={} tip={} rate={:.0}/s remain={} elapsed={:.0}s read={}ms build={}ms commit={}ms",
        p.next,
        p.tip,
        rate,
        p.tip.saturating_add(1).saturating_sub(p.next),
        secs,
        p.stages.read_ms,
        p.stages.build_ms,
        p.stages.commit_ms,
    )
}

#[doc(hidden)]
pub fn format_index_apply(start: u32, end: u32, stages: IndexStageSample) -> String {
    format!(
        "index: apply h={start}..={end} read={}ms build={}ms commit={}ms",
        stages.read_ms, stages.build_ms, stages.commit_ms
    )
}

#[doc(hidden)]
pub struct CommitTimes {
    pub ok: bool,
    pub build_ns: u64,
    pub commit_ns: u64,
}

/// Build and commit what each index still needs from `window`. `ok` is false
/// when a commit found the watermark or a `confirmed[h]` moved.
#[doc(hidden)]
pub fn commit_window(
    query: &Query,
    window: &Arc<IndexWindow>,
    stages: &IndexStageMs,
) -> Result<CommitTimes, ConfirmError> {
    if window.blocks.is_empty() {
        return Ok(CommitTimes {
            ok: true,
            build_ns: 0,
            commit_ns: 0,
        });
    }
    let t_build = Instant::now();
    let assembled = assemble_window(query, window)?;
    let build_ns = t_build.elapsed().as_nanos() as u64;
    let committed = index_rows::commit_index_rows(query, assembled)?;
    let commit_ns = committed.put_ns;
    stages.add_build(build_ns);
    stages.add_commit(commit_ns);
    crate::note_confirm(
        &query.confirm_stats().blockfilter_ns,
        build_ns.saturating_add(commit_ns),
    );
    Ok(CommitTimes {
        ok: !committed.moved,
        build_ns,
        commit_ns,
    })
}

/// Seal every released height on this thread (regtest `generate`, tests).
pub fn build_indexes_released(query: &Query) -> Result<(), ConfirmError> {
    let mut live = IndexStages::default();
    live.observe(query, query.index_target(), true, true);
    while let (Some(start), Some(target)) = (next_needed(query), query.index_target()) {
        if start > target {
            break;
        }
        let end = plan_window(query, start, target)?;
        let stages = IndexStageMs::default();
        let window = Arc::new(read_window(query, start, end)?);
        let ok = commit_window(query, &window, &stages)?.ok;
        live.observe(query, query.index_target(), true, true);
        if !ok {
            break;
        }
    }
    Ok(())
}

#[doc(hidden)]
pub struct ReadyWindow {
    pub window: IndexWindow,
    pub start: u32,
    pub end: u32,
    pub read_ns: u64,
    /// Tip path: one height, logged after commit with this window's times.
    pub log_apply: bool,
}

#[doc(hidden)]
pub fn cpu_worker(
    query: &Query,
    rx: Receiver<ReadyWindow>,
    resync: &AtomicBool,
    stages: &IndexStageMs,
) -> Result<(), ConfirmError> {
    for ready in rx {
        if resync.load(Ordering::Acquire) {
            continue;
        }
        let window = Arc::new(ready.window);
        let times = commit_window(query, &window, stages)?;
        if ready.log_apply {
            rbitcoin_log::info!(
                "{}",
                format_index_apply(
                    ready.start,
                    ready.end,
                    IndexStageSample {
                        read_ms: ready.read_ns / 1_000_000,
                        build_ms: times.build_ns / 1_000_000,
                        commit_ms: times.commit_ns / 1_000_000,
                    },
                )
            );
        }
        if !times.ok {
            resync.store(true, Ordering::Release);
        }
    }
    Ok(())
}

/// Spawn `rbtc-idx-wb` once tip mode is entered. Stop is checked between
/// windows; apply errors request `stop` and `on_fatal`. `on_filters_caught_up`
/// runs once, the first time filters reach the released tip.
pub fn spawn_index_writebehind(
    query: Arc<Query>,
    stop: Arc<AtomicBool>,
    on_fatal: impl FnOnce() + Send + 'static,
    on_filters_caught_up: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rbtc-idx-wb".into())
        .spawn(move || {
            if let Err(e) = run_writebehind(&query, &stop, on_filters_caught_up) {
                rbitcoin_log::error!("index write-behind: {e}");
                stop.store(true, Ordering::SeqCst);
                on_fatal();
            }
        })
        .expect("spawn index write-behind")
}

#[doc(hidden)]
pub fn run_writebehind(
    query: &Query,
    stop: &AtomicBool,
    on_filters_caught_up: impl FnOnce(),
) -> Result<(), ConfirmError> {
    // Spawned after catch-up: the current tip was already announced.
    if let Some(tip) = query.tip_height() {
        query.release_index_writebehind(tip);
    }
    let resync = AtomicBool::new(false);
    let stages = IndexStageMs::default();
    let (tx, rx) = sync_channel::<ReadyWindow>(2);
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("rbtc-idx-cpu".into())
            .spawn_scoped(scope, || cpu_worker(query, rx, &resync, &stages))
            .expect("spawn index cpu worker");
        let io = io_loop(
            query,
            stop,
            &resync,
            &stages,
            &tx,
            PROGRESS_EVERY,
            IoHooks {
                before_send: || {},
                on_filters_caught_up,
            },
        );
        drop(tx);
        let cpu = worker.join().expect("index cpu worker");
        io.and(cpu)
    })
}

#[doc(hidden)]
pub struct Pass {
    pub from: u32,
    pub started: Instant,
    pub last_log: Instant,
}

/// Test and production callbacks for [`io_loop`]. One argument keeps the
/// function under the argument-count lint.
#[doc(hidden)]
pub struct IoHooks<B, F> {
    pub before_send: B,
    pub on_filters_caught_up: F,
}

#[doc(hidden)]
pub fn io_loop(
    query: &Query,
    stop: &AtomicBool,
    resync: &AtomicBool,
    stages: &IndexStageMs,
    tx: &std::sync::mpsc::SyncSender<ReadyWindow>,
    progress_every: Duration,
    mut hooks: IoHooks<impl FnMut(), impl FnOnce()>,
) -> Result<(), ConfirmError> {
    let mut on_filters_caught_up = Some(hooks.on_filters_caught_up);
    let mut cursor: Option<u32> = None;
    let mut pass: Option<Pass> = None;
    let mut live = IndexStages::default();
    while !stop.load(Ordering::Relaxed) {
        if resync.swap(false, Ordering::AcqRel) {
            cursor = None;
        }
        let target = query.index_target();
        live.observe(query, target, true, true);
        if let (Some(t), Some(f)) = (target, query.filter_index_next()) {
            if f > t {
                if let Some(cb) = on_filters_caught_up.take() {
                    rbitcoin_log::info!(
                        "blockfilter: caught up through={}; advertising NODE_COMPACT_FILTERS",
                        f - 1
                    );
                    cb();
                }
            }
        }
        let start = match cursor {
            Some(c) => Some(c),
            None => next_needed(query),
        };
        let (Some(start), Some(target)) = (start, target) else {
            query.wait_index_release(Duration::from_millis(200));
            continue;
        };
        if start > target {
            if let Some(p) = pass.take() {
                rbitcoin_log::info!(
                    "index: build done through={target} heights={} elapsed={:.1}s",
                    target + 1 - p.from,
                    p.started.elapsed().as_secs_f64()
                );
            }
            query.wait_index_release(Duration::from_millis(200));
            continue;
        }
        let now = Instant::now();
        if target - start >= WINDOW_HEIGHTS && pass.is_none() {
            rbitcoin_log::info!(
                "index: build from={start} to={target} filters={:?} tweaks={:?}",
                query.filter_index_next(),
                query.tweak_index_next()
            );
            pass = Some(Pass {
                from: start,
                started: now,
                last_log: now,
            });
        }
        if let Some(p) = pass.as_mut() {
            if p.last_log.elapsed() >= progress_every {
                rbitcoin_log::info!(
                    "{}",
                    format_index_build_progress(&IndexBuildProgress {
                        next: start,
                        tip: target,
                        from: p.from,
                        elapsed: p.started.elapsed(),
                        stages: stages.take_ms(),
                    })
                );
                p.last_log = now;
            }
        }
        let end = plan_window(query, start, target)?;
        let t_read = Instant::now();
        let window = read_window(query, start, end)?;
        let read_ns = t_read.elapsed().as_nanos() as u64;
        stages.add_read(read_ns);
        (hooks.before_send)();
        if tx
            .send(ReadyWindow {
                window,
                start,
                end,
                read_ns,
                log_apply: pass.is_none(),
            })
            .is_err()
        {
            break;
        }
        cursor = Some(end + 1);
    }
    Ok(())
}
