//! Sliced k-way SH tip materialize: one worker per prefix shard.
//!
//! Sharded bodies: each worker packs `body/NN` and seals `head/NN` itself.
//! Shared body: one writer, prefix `SHCOLDP1` HWM.
//!
//! Alternate path: [`materialize_sh_shards_from_class_a`] scans Class A once
//! per unsealed prefix shard, sorts that shard in RAM, and packs it. No catalog
//! runs. `RBITCOIN_SH_MATERIALIZE=ram-shard` selects it at tip finalize.

use crate::error::StoreError;
use crate::file::ensure_nofile_budget_at_least;
use crate::scripthash::{
    ColdProgress, ScriptHashRecord, ScriptHashTable, ShBodyLayout, ShShardPack,
};
use crate::scripthash_head::prefix_shard_of;
use crate::sorted_run::{for_each_merged_rec_shard, SortedRunPath};
use crate::store::Store;
use crate::tx_table::TxTable;
use rbitcoin_primitives::Fk;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Create_fk span per parallel Class A scan unit (same grain as recollect).
const CLASS_A_CHUNK_FKS: u64 = 64_000;

const MATERIALIZE_STATUS_INTERVAL: Duration = Duration::from_secs(10);

fn status_interval_due(last: Option<Instant>, now: Instant, interval: Duration) -> bool {
    match last {
        None => true,
        Some(t) => now.saturating_duration_since(t) >= interval,
    }
}

/// Global pack/publish counters. One observer thread samples these.
struct MaterializeProgress {
    recs_packed: AtomicU64,
    keys_packed: AtomicU64,
    shards_published: AtomicU32,
    creates_published: AtomicU64,
    merge_ns: AtomicU64,
    pack_ns: AtomicU64,
    mphf_ns: AtomicU64,
    body_flush_ns: AtomicU64,
    stop: AtomicBool,
    complete: AtomicBool,
    wake: Condvar,
    wake_mu: Mutex<()>,
}

struct StatusSnapshot {
    keys: u64,
    creates: u64,
    pending: u64,
    shards: u32,
    pct: f64,
}

impl MaterializeProgress {
    fn new() -> Self {
        Self {
            recs_packed: AtomicU64::new(0),
            keys_packed: AtomicU64::new(0),
            shards_published: AtomicU32::new(0),
            creates_published: AtomicU64::new(0),
            merge_ns: AtomicU64::new(0),
            pack_ns: AtomicU64::new(0),
            mphf_ns: AtomicU64::new(0),
            body_flush_ns: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            wake: Condvar::new(),
            wake_mu: Mutex::new(()),
        }
    }

    fn snapshot(&self, total_recs: u64, done: bool) -> StatusSnapshot {
        let creates = self.recs_packed.load(Ordering::Relaxed);
        let published = self.creates_published.load(Ordering::Relaxed);
        let pct = if done {
            100.0
        } else if total_recs > 0 {
            (100.0 * creates as f64 / total_recs as f64).clamp(0.0, 99.9)
        } else {
            0.0
        };
        StatusSnapshot {
            keys: self.keys_packed.load(Ordering::Relaxed),
            creates,
            pending: creates.saturating_sub(published),
            shards: self.shards_published.load(Ordering::Relaxed),
            pct,
        }
    }

    fn stages(&self) -> MaterializeStageNs {
        MaterializeStageNs {
            merge_ns: self.merge_ns.load(Ordering::Relaxed),
            pack_ns: self.pack_ns.load(Ordering::Relaxed),
            mphf_ns: self.mphf_ns.load(Ordering::Relaxed),
            body_flush_ns: self.body_flush_ns.load(Ordering::Relaxed),
        }
    }
}

fn log_materialize_status(
    last_log: &mut Option<Instant>,
    snap: &StatusSnapshot,
    n_shards: usize,
    t0: Instant,
) {
    *last_log = Some(Instant::now());
    let elapsed = t0.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-3);
    let recs_per_s = snap.creates as f64 / secs;
    rbitcoin_log::info!(
        "node: scripthash materialize status keys≈{} creates≈{} pending≈{} \
         pct≈{:.1}% shards={}/{} rate≈{:.0}creates/s elapsed={elapsed:?}",
        snap.keys,
        snap.creates,
        snap.pending,
        snap.pct,
        snap.shards,
        n_shards,
        recs_per_s,
    );
}

struct StopOnDrop<'a>(&'a MaterializeProgress);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::Release);
        self.0.wake.notify_all();
    }
}

/// CPU-summed stage times for [`materialize_sh_shards`] (parallel workers add).
#[derive(Debug, Clone, Copy, Default)]
pub struct MaterializeStageNs {
    pub merge_ns: u64,
    pub pack_ns: u64,
    pub mphf_ns: u64,
    pub body_flush_ns: u64,
}

/// Result of [`materialize_sh_shards`].
#[derive(Debug, Clone, Copy)]
pub struct ShShardMaterialize {
    pub creates: u64,
    pub keys: u64,
    pub max_fk: u64,
    pub merge_ns: u64,
    pub pack_ns: u64,
    pub mphf_ns: u64,
    pub body_flush_ns: u64,
    pub head_fill_ns: u64,
}

impl ShShardMaterialize {
    fn with_stages(mut self, stages: MaterializeStageNs) -> Self {
        self.merge_ns = stages.merge_ns;
        self.pack_ns = stages.pack_ns;
        self.mphf_ns = stages.mphf_ns;
        self.body_flush_ns = stages.body_flush_ns;
        self.head_fill_ns = 0;
        self
    }
}

fn decode_sh_run_rec(rec: &[u8]) -> Result<([u8; 32], Fk), StoreError> {
    if rec.len() < 40 {
        return Err(StoreError::Corrupt("sh run short record in shard merge"));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&rec[..32]);
    let fk = Fk(u64::from_le_bytes(rec[32..40].try_into().unwrap()));
    Ok((sh, fk))
}

fn resolve_workers(
    requested: usize,
    n_shards: usize,
    n_runs: usize,
    layout: ShBodyLayout,
) -> usize {
    let n_shards = n_shards.max(1);
    let mut workers = requested.max(1).min(n_shards);
    let k = n_runs.max(1);
    let want = (workers.saturating_mul(k).saturating_add(64)) as u64;
    let (soft, _) = ensure_nofile_budget_at_least(want);
    if soft > 0 && (soft as usize) < want as usize {
        let clamped = (soft as usize / k).max(1).min(n_shards);
        if clamped < workers {
            rbitcoin_log::warn!(
                "store: scripthash shard workers clamped {workers}→{clamped} \
                 (nofile soft={soft} runs={k} fds≈{})",
                workers.saturating_mul(k)
            );
            workers = clamped;
        }
    }
    if layout == ShBodyLayout::Shared && workers > 1 {
        workers = 1;
    }
    workers
}

fn pack_shard(
    table: &ScriptHashTable,
    inputs: &[SortedRunPath],
    cuts: &[Vec<u64>],
    shard: usize,
    cancel: Option<&AtomicBool>,
    progress: &MaterializeProgress,
) -> Result<ShShardPack, StoreError> {
    let mut session = table.pack_shard_session(shard)?;
    let t_loop = Instant::now();
    for_each_merged_rec_shard(inputs, cuts, shard, false, |rec| {
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash shard pack"));
        }
        let (sh, fk) = decode_sh_run_rec(rec)?;
        if fk.is_null() {
            return Ok(());
        }
        session.push_sorted_fk(sh, fk)?;
        progress.recs_packed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })?;
    let loop_wall = t_loop.elapsed().as_nanos() as u64;
    let pack_during_loop = session.pack_ns;
    progress.merge_ns.fetch_add(
        loop_wall.saturating_sub(pack_during_loop),
        Ordering::Relaxed,
    );
    let pack = session.finish_pack()?;
    progress.pack_ns.fetch_add(pack.pack_ns, Ordering::Relaxed);
    progress
        .body_flush_ns
        .fetch_add(pack.body_flush_ns, Ordering::Relaxed);
    progress.keys_packed.fetch_add(pack.keys, Ordering::Relaxed);
    Ok(pack)
}

fn seal_shard(
    table: &ScriptHashTable,
    shard: usize,
    pack: ShShardPack,
    max_fk: &AtomicU64,
    progress: &MaterializeProgress,
) -> Result<(), StoreError> {
    max_fk.fetch_max(pack.max_fk, Ordering::Relaxed);
    let creates = pack.creates;
    let t_mphf = Instant::now();
    let bump = table.publish_packed_shard(shard, pack)?;
    progress
        .mphf_ns
        .fetch_add(t_mphf.elapsed().as_nanos() as u64, Ordering::Relaxed);
    progress
        .creates_published
        .fetch_add(creates, Ordering::Relaxed);
    progress.shards_published.fetch_add(1, Ordering::Relaxed);
    match table.body_layout() {
        ShBodyLayout::Shared => ColdProgress {
            next_shard: (shard as u32).saturating_add(1),
            body_bump: bump,
            live_count: progress.creates_published.load(Ordering::Relaxed),
            keys_written: progress.keys_packed.load(Ordering::Relaxed),
        }
        .store(table.store_dir())?,
        ShBodyLayout::Sharded => table.store_sharded_cold_progress(
            progress.keys_packed.load(Ordering::Relaxed),
            progress.creates_published.load(Ordering::Relaxed),
        )?,
    }
    Ok(())
}

/// Pack prefix shards in parallel. Sharded: each worker seals its own `head/NN`.
pub fn materialize_sh_shards(
    table: &ScriptHashTable,
    inputs: &[SortedRunPath],
    resume_from: usize,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    let jobs: Vec<usize> = match table.body_layout() {
        ShBodyLayout::Sharded => table.unsealed_main_shards(),
        ShBodyLayout::Shared => {
            if resume_from >= n_shards {
                Vec::new()
            } else {
                (resume_from..n_shards).collect()
            }
        }
    };
    if jobs.is_empty() {
        return Ok(ShShardMaterialize {
            creates: table.entry_count(),
            keys: 0,
            max_fk: 0,
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        });
    }
    let cuts = crate::sorted_run::shard_record_starts_many(inputs, n_shards)?;
    let workers = resolve_workers(workers, jobs.len(), inputs.len(), table.body_layout());
    rbitcoin_log::info!(
        "store: scripthash shard-kway start resume_from={resume_from} n_shards={n_shards} \
         jobs={} workers={workers} runs={} fds≈{}",
        jobs.len(),
        inputs.len(),
        workers.saturating_mul(inputs.len().max(1))
    );
    let t0 = Instant::now();
    let progress = MaterializeProgress::new();
    let already = (n_shards - jobs.len()) as u32;
    progress.shards_published.store(already, Ordering::Relaxed);
    progress
        .recs_packed
        .store(table.entry_count(), Ordering::Relaxed);
    progress
        .creates_published
        .store(table.entry_count(), Ordering::Relaxed);
    if let Some(p) = ColdProgress::load(table.store_dir()).ok().flatten() {
        progress
            .keys_packed
            .store(p.keys_written, Ordering::Relaxed);
    }
    let total_recs: u64 = inputs.iter().map(|r| r.count).sum();
    let max_fk = AtomicU64::new(0);

    let out = std::thread::scope(|scope| {
        let progress = &progress;
        let max_fk = &max_fk;
        let _stop = StopOnDrop(progress);
        scope.spawn(move || {
            let mut last = None;
            loop {
                let stop = progress.stop.load(Ordering::Relaxed);
                if status_interval_due(last, Instant::now(), MATERIALIZE_STATUS_INTERVAL) || stop {
                    log_materialize_status(
                        &mut last,
                        &progress.snapshot(
                            total_recs,
                            stop && progress.complete.load(Ordering::Relaxed),
                        ),
                        n_shards,
                        t0,
                    );
                }
                if stop {
                    break;
                }
                let g = progress.wake_mu.lock().unwrap();
                if progress.stop.load(Ordering::Relaxed) {
                    continue;
                }
                let wait = last
                    .map(|t| MATERIALIZE_STATUS_INTERVAL.saturating_sub(t.elapsed()))
                    .unwrap_or(MATERIALIZE_STATUS_INTERVAL);
                let _ = progress.wake.wait_timeout(g, wait);
            }
        });

        if workers <= 1 {
            for shard in jobs {
                if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                    return Err(StoreError::Cancelled("scripthash shard pack"));
                }
                let pack = pack_shard(table, inputs, &cuts, shard, cancel, progress)?;
                seal_shard(table, shard, pack, max_fk, progress)?;
            }
        } else {
            let shared = Arc::new(ShardPool {
                jobs: Mutex::new(VecDeque::from(jobs)),
                err: Mutex::new(None),
            });
            let mut joins = Vec::with_capacity(workers);
            for _ in 0..workers {
                let shared = Arc::clone(&shared);
                let cuts = &cuts;
                joins.push(scope.spawn(move || loop {
                    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                        let mut g = shared.err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash shard pack"));
                        }
                        break;
                    }
                    if shared.err.lock().unwrap().is_some() {
                        break;
                    }
                    let shard = shared.jobs.lock().unwrap().pop_front();
                    let Some(shard) = shard else {
                        break;
                    };
                    match pack_shard(table, inputs, cuts, shard, cancel, progress)
                        .and_then(|pack| seal_shard(table, shard, pack, max_fk, progress))
                    {
                        Ok(()) => {}
                        Err(e) => {
                            *shared.err.lock().unwrap() = Some(e);
                            break;
                        }
                    }
                }));
            }
            for j in joins {
                if j.join().is_err() {
                    return Err(StoreError::Corrupt("scripthash shard pack worker panicked"));
                }
            }
            let err = shared.err.lock().unwrap().take();
            if let Some(e) = err {
                return Err(e);
            }
        }

        progress.complete.store(true, Ordering::Release);
        Ok(ShShardMaterialize {
            creates: progress.creates_published.load(Ordering::Relaxed),
            keys: progress.keys_packed.load(Ordering::Relaxed),
            max_fk: max_fk.load(Ordering::Relaxed),
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        }
        .with_stages(progress.stages()))
    })?;
    Ok(out)
}

/// Scan Class A `txout` for `create_fk` in `1..=count`, keep rows whose
/// scripthash lands in `shard` of `n_shards`, sort by `(scripthash, create_fk)`.
pub fn collect_class_a_shard_records(
    store: &Store,
    shard: usize,
    n_shards: usize,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<ScriptHashRecord>, StoreError> {
    let last = store.txs.count();
    if last == 0 {
        return Ok(Vec::new());
    }
    collect_class_a_shard_from_txs(&store.txs, shard, n_shards, 1, last, workers, cancel)
}

fn collect_class_a_shard_from_txs(
    txs: &TxTable,
    shard: usize,
    n_shards: usize,
    first: u64,
    last: u64,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<ScriptHashRecord>, StoreError> {
    if last < first {
        return Ok(Vec::new());
    }
    let n_shards = n_shards.max(1);
    let work_span = last.saturating_sub(first.saturating_sub(1));
    let n_chunks = work_span.div_ceil(CLASS_A_CHUNK_FKS).max(1) as usize;
    let workers = workers.max(1).min(n_chunks);
    let next_chunk = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<StoreError>> = Mutex::new(None);
    let parts: Mutex<Vec<Vec<ScriptHashRecord>>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    if stop.load(Ordering::Relaxed)
                        || cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false)
                    {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    if first_err.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next_chunk.fetch_add(1, Ordering::Relaxed);
                    if i >= n_chunks {
                        break;
                    }
                    let lo = first.saturating_add((i as u64).saturating_mul(CLASS_A_CHUNK_FKS));
                    let hi = lo
                        .saturating_add(CLASS_A_CHUNK_FKS)
                        .saturating_sub(1)
                        .min(last);
                    if lo > last {
                        continue;
                    }
                    match txs.for_each_script_hashes_in_fk_span(lo, hi, |fk, sh| {
                        if prefix_shard_of(&sh, n_shards) == shard {
                            local.push(ScriptHashRecord::from_fk(sh, fk));
                        }
                        Ok(())
                    }) {
                        Ok(()) => {}
                        Err(StoreError::Cancelled(_)) => {
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        Err(e) => {
                            *first_err.lock().unwrap() = Some(e);
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                if !local.is_empty() {
                    parts.lock().unwrap().push(local);
                }
            });
        }
    });

    if let Some(e) = first_err.lock().unwrap().take() {
        return Err(e);
    }
    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
        return Err(StoreError::Cancelled("scripthash ram-shard class a scan"));
    }

    let mut recs: Vec<ScriptHashRecord> =
        parts.into_inner().unwrap().into_iter().flatten().collect();
    recs.sort_unstable_by(|a, b| {
        a.scripthash
            .cmp(&b.scripthash)
            .then(a.create_tx_fk.0.cmp(&b.create_tx_fk.0))
    });
    recs.dedup_by(|a, b| a.scripthash == b.scripthash && a.create_tx_fk == b.create_tx_fk);
    Ok(recs)
}

fn pack_sorted_class_a_shard(
    table: &ScriptHashTable,
    shard: usize,
    recs: &[ScriptHashRecord],
    cancel: Option<&AtomicBool>,
    progress: &MaterializeProgress,
) -> Result<ShShardPack, StoreError> {
    let mut session = table.pack_shard_session(shard)?;
    let t_loop = Instant::now();
    for (i, r) in recs.iter().enumerate() {
        if i & 0xfff == 0 && cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash ram-shard pack"));
        }
        if r.create_tx_fk.is_null() {
            continue;
        }
        session.push_sorted_fk(r.scripthash, r.create_tx_fk)?;
        progress.recs_packed.fetch_add(1, Ordering::Relaxed);
    }
    let loop_wall = t_loop.elapsed().as_nanos() as u64;
    let pack_during_loop = session.pack_ns;
    progress.merge_ns.fetch_add(
        loop_wall.saturating_sub(pack_during_loop),
        Ordering::Relaxed,
    );
    let pack = session.finish_pack()?;
    progress.pack_ns.fetch_add(pack.pack_ns, Ordering::Relaxed);
    progress
        .body_flush_ns
        .fetch_add(pack.body_flush_ns, Ordering::Relaxed);
    progress.keys_packed.fetch_add(pack.keys, Ordering::Relaxed);
    Ok(pack)
}

fn ram_shard_jobs(table: &ScriptHashTable, resume_from: usize) -> Vec<usize> {
    let n_shards = table.head_shard_count().max(1);
    match table.body_layout() {
        ShBodyLayout::Sharded => table.unsealed_main_shards(),
        ShBodyLayout::Shared => {
            if resume_from >= n_shards {
                Vec::new()
            } else {
                (resume_from..n_shards).collect()
            }
        }
    }
}

/// One Class A pass per unsealed prefix shard: filter, sort in RAM, pack+seal.
///
/// Does not read or write `scripthash.runs`. Shards run **serially** (one RAM
/// image). `workers` parallelize the `txout` scan inside each pass.
pub fn materialize_sh_shards_from_class_a(
    store: &Store,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    materialize_sh_from_txout(&store.txs, &store.scripthash, workers, cancel)
}

/// Like [`materialize_sh_shards_from_class_a`] packing `table` from `store` Class A.
///
/// `table` may be a different SH layout than `store.scripthash` (tests).
pub fn materialize_sh_from_class_a_into(
    store: &Store,
    table: &ScriptHashTable,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    materialize_sh_from_txout(&store.txs, table, workers, cancel)
}

fn materialize_sh_from_txout(
    txs: &TxTable,
    table: &ScriptHashTable,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    let resume_from = match ColdProgress::load(table.store_dir()).ok().flatten() {
        Some(p) if table.body_layout() == ShBodyLayout::Shared => p.next_shard as usize,
        _ => 0,
    };
    let jobs = ram_shard_jobs(table, resume_from);
    if jobs.is_empty() {
        return Ok(ShShardMaterialize {
            creates: table.entry_count(),
            keys: 0,
            max_fk: 0,
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        });
    }
    let workers = workers.max(1);
    let tip_max = txs.count();
    rbitcoin_log::info!(
        "store: scripthash ram-shard start resume_from={resume_from} n_shards={n_shards} \
         jobs={} workers={workers} tip_max_create_fk={tip_max}",
        jobs.len(),
    );
    let t0 = Instant::now();
    let progress = MaterializeProgress::new();
    let already = (n_shards - jobs.len()) as u32;
    progress.shards_published.store(already, Ordering::Relaxed);
    progress
        .recs_packed
        .store(table.entry_count(), Ordering::Relaxed);
    progress
        .creates_published
        .store(table.entry_count(), Ordering::Relaxed);
    if let Some(p) = ColdProgress::load(table.store_dir()).ok().flatten() {
        progress
            .keys_packed
            .store(p.keys_written, Ordering::Relaxed);
    }
    let max_fk = AtomicU64::new(0);
    let n_jobs = jobs.len();

    for (ji, shard) in jobs.into_iter().enumerate() {
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash ram-shard pack"));
        }
        let t_shard = Instant::now();
        rbitcoin_log::info!(
            "store: scripthash ram-shard pass={}/{n_jobs} shard={shard}/{n_shards} \
             workers={workers} tip_max_create_fk={tip_max}",
            ji + 1,
        );
        let recs =
            collect_class_a_shard_from_txs(txs, shard, n_shards, 1, tip_max, workers, cancel)?;
        let n_recs = recs.len() as u64;
        let pack = pack_sorted_class_a_shard(table, shard, &recs, cancel, &progress)?;
        drop(recs);
        seal_shard(table, shard, pack, &max_fk, &progress)?;
        rbitcoin_log::info!(
            "store: scripthash ram-shard packed shard={shard}/{n_shards} recs={n_recs} \
             shards={}/{} elapsed={:?}",
            progress.shards_published.load(Ordering::Relaxed),
            n_shards,
            t_shard.elapsed(),
        );
    }

    progress.complete.store(true, Ordering::Release);
    rbitcoin_log::info!(
        "store: scripthash ram-shard done shards={n_shards} creates≈{} keys≈{} elapsed={:?}",
        progress.creates_published.load(Ordering::Relaxed),
        progress.keys_packed.load(Ordering::Relaxed),
        t0.elapsed(),
    );
    Ok(ShShardMaterialize {
        creates: progress.creates_published.load(Ordering::Relaxed),
        keys: progress.keys_packed.load(Ordering::Relaxed),
        max_fk: max_fk.load(Ordering::Relaxed),
        merge_ns: 0,
        pack_ns: 0,
        mphf_ns: 0,
        body_flush_ns: 0,
        head_fill_ns: 0,
    }
    .with_stages(progress.stages()))
}

struct ShardPool {
    jobs: Mutex<VecDeque<usize>>,
    err: Mutex<Option<StoreError>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_status_interval_due_is_wall_only() {
        let interval = Duration::from_secs(10);
        let t0 = Instant::now();
        assert!(
            status_interval_due(None, t0, interval),
            "first tick must emit"
        );
        assert!(
            !status_interval_due(Some(t0), t0, interval),
            "must not emit before the wall interval"
        );
        assert!(
            status_interval_due(Some(t0), t0 + interval, interval),
            "emit when the wall interval has elapsed"
        );
    }

    #[test]
    fn materialize_status_snapshot_is_global() {
        let p = MaterializeProgress::new();
        p.recs_packed.store(1_000_000, Ordering::Relaxed);
        p.keys_packed.store(400_000, Ordering::Relaxed);
        p.creates_published.store(250_000, Ordering::Relaxed);
        p.shards_published.store(3, Ordering::Relaxed);
        let s = p.snapshot(10_000_000, false);
        assert_eq!(s.creates, 1_000_000, "creates are all packed recs");
        assert_eq!(s.keys, 400_000, "keys are packed shards, not one worker");
        assert_eq!(s.pending, 750_000, "pending is packed minus published");
        assert_eq!(s.shards, 3);
        assert!(
            (s.pct - 10.0).abs() < 0.01,
            "pct uses global recs/total, got {}",
            s.pct
        );
        let done = p.snapshot(10_000_000, true);
        assert!((done.pct - 100.0).abs() < 0.01);
        let mut last = None;
        log_materialize_status(&mut last, &s, 64, Instant::now());
        assert!(last.is_some());
    }

    #[test]
    fn materialize_stage_ns_are_populated() {
        crate::hashhead::HeadScale::test_with(crate::hashhead::HeadScale::Tiny, || {
            let dir = std::env::temp_dir().join(format!(
                "rbitcoin-sh-stage-ns-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let runs_dir = dir.join("runs");
            std::fs::create_dir_all(&runs_dir).unwrap();
            let rec = |sh0: u8, fk: u64| {
                let mut r = [0u8; 40];
                r[0] = sh0;
                r[32..40].copy_from_slice(&fk.to_le_bytes());
                r
            };
            let mut a = Vec::new();
            let mut b = Vec::new();
            for i in 0..8u64 {
                let sh0 = (i as u8) * 16;
                let body1 = rec(sh0, i * 10 + 1);
                let body2 = rec(sh0, i * 10 + 2);
                if i % 2 == 0 {
                    a.extend_from_slice(&body1);
                    a.extend_from_slice(&body2);
                } else {
                    b.extend_from_slice(&body1);
                    b.extend_from_slice(&body2);
                }
            }
            crate::sorted_run::write_sorted_run(&runs_dir.join("000001.run"), 40, 40, &a).unwrap();
            crate::sorted_run::write_sorted_run(&runs_dir.join("000002.run"), 40, 40, &b).unwrap();
            let inputs = [
                crate::sorted_run::open_run(&runs_dir.join("000001.run")).unwrap(),
                crate::sorted_run::open_run(&runs_dir.join("000002.run")).unwrap(),
            ];
            let table = crate::scripthash::ScriptHashTable::create(&dir).unwrap();
            let mat = materialize_sh_shards(&table, &inputs, 0, 1, None).unwrap();
            assert!(mat.creates >= 16);
            assert!(
                mat.pack_ns > 0 && mat.body_flush_ns > 0 && mat.mphf_ns > 0,
                "stage ns must be real merge={} pack={} mphf={} body={}",
                mat.merge_ns,
                mat.pack_ns,
                mat.mphf_ns,
                mat.body_flush_ns
            );
            assert_eq!(
                mat.head_fill_ns, 0,
                "pack-only materialize must not alias head_fill to mphf"
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}
