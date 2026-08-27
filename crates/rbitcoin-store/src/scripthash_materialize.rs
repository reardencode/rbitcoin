//! Sliced k-way SH tip materialize: one worker per prefix shard.
//!
//! Sharded bodies: each worker packs `body/NN` and seals `head/NN` itself.
//! Shared body: one writer, prefix `SHCOLDP1` HWM.
//!
//! Alternate env path: one Class A pass into unsorted per-shard files, then
//! RAM-sort + pack (`RBITCOIN_SH_MATERIALIZE=unsorted-shards`).

use crate::error::StoreError;
use crate::file::ensure_nofile_budget_at_least;
use crate::io_handle::IoHandle;
use crate::scripthash::{
    ColdProgress, ScriptHashRecord, ScriptHashTable, ShBodyLayout, ShShardPack,
};
use crate::scripthash_head::prefix_shard_of;
use crate::sorted_run::{for_each_merged_rec_shard, SortedRunPath};
use crate::store::Store;
use crate::tx_table::TxTable;
use rbitcoin_primitives::Fk;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

struct ShardPool {
    jobs: Mutex<VecDeque<usize>>,
    err: Mutex<Option<StoreError>>,
}

/// Temp dir for one Class A pass → unsorted per-shard 40-byte records.
pub const UNSORTED_SHARD_DIR: &str = "scripthash.unsorted";
const UNSORTED_DONE_NAME: &str = "DONE";
const UNSORTED_DONE_MAGIC: &[u8; 8] = b"SHUNSRT1";
const UNSORTED_REC_LEN: usize = 40;
const UNSORTED_FLUSH_BYTES: usize = 256 * 1024;
const CLASS_A_CHUNK_FKS: u64 = 64_000;

/// RAM budget per unsorted-shard pack worker (read + sort + pack session).
pub const SH_UNSORTED_PACK_RAM_BYTES: u64 = 2 << 30;

/// Collect / pack result counts for one unsorted-shard cold pass.
#[derive(Clone, Debug, Default)]
pub struct UnsortedShardCollect {
    pub recs: u64,
    pub per_shard: Vec<u64>,
}

pub fn unsorted_shard_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(UNSORTED_SHARD_DIR)
}

pub fn unsorted_shard_path(dir: &Path, shard: usize) -> PathBuf {
    dir.join(format!("{shard:02x}"))
}

/// Collect workers: `RBITCOIN_SH_RECOLLECT_WORKERS` or nCPU (small write buffers).
pub fn unsorted_collect_workers() -> usize {
    if let Ok(s) = std::env::var("RBITCOIN_SH_RECOLLECT_WORKERS") {
        if let Ok(n) = s.parse::<usize>() {
            return n.clamp(1, 256);
        }
    }
    crate::sorted_run::logical_cpus()
}

/// Pack workers: `RBITCOIN_SH_MERGE_WORKERS` or free RAM / 2 GiB.
pub fn unsorted_pack_workers() -> usize {
    if let Ok(s) = std::env::var("RBITCOIN_SH_MERGE_WORKERS") {
        if let Ok(n) = s.parse::<usize>() {
            return n.clamp(1, 256);
        }
    }
    crate::sorted_run::workers_for_free_ram(
        crate::sorted_run::logical_cpus(),
        crate::sorted_run::host_mem_available_bytes().unwrap_or(0),
        SH_UNSORTED_PACK_RAM_BYTES,
    )
}

fn encode_unsorted_rec(sh: &[u8; 32], fk: Fk) -> [u8; UNSORTED_REC_LEN] {
    let mut r = [0u8; UNSORTED_REC_LEN];
    r[..32].copy_from_slice(sh);
    r[32..].copy_from_slice(&fk.0.to_le_bytes());
    r
}

fn pwrite_all(file: &File, path: &Path, offset: u64, bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let handle = IoHandle::from_file(file);
    let mut done = 0usize;
    while done < bytes.len() {
        let rc = handle.pwrite(offset + done as u64, &bytes[done..]);
        if rc < 0 {
            return Err(StoreError::io(path, io::Error::from_raw_os_error(-rc)));
        }
        if rc == 0 {
            return Err(StoreError::io(
                path,
                io::Error::new(io::ErrorKind::WriteZero, "pwrite returned 0"),
            ));
        }
        done += rc as usize;
    }
    Ok(())
}

struct UnsortedShardSink {
    path: PathBuf,
    file: File,
    cursor: AtomicU64,
}

fn flush_unsorted_buf(sink: &UnsortedShardSink, buf: &mut Vec<u8>) -> Result<(), StoreError> {
    if buf.is_empty() {
        return Ok(());
    }
    if !buf.len().is_multiple_of(UNSORTED_REC_LEN) {
        return Err(StoreError::Corrupt(
            "scripthash unsorted shard buffer not a multiple of 40",
        ));
    }
    let n = buf.len() as u64;
    let off = sink.cursor.fetch_add(n, Ordering::Relaxed);
    pwrite_all(&sink.file, &sink.path, off, buf)?;
    buf.clear();
    Ok(())
}

fn write_unsorted_done(dir: &Path, per_shard: &[u64]) -> Result<(), StoreError> {
    let n = per_shard.len() as u32;
    let mut buf = Vec::with_capacity(12 + per_shard.len() * 8);
    buf.extend_from_slice(UNSORTED_DONE_MAGIC);
    buf.extend_from_slice(&n.to_le_bytes());
    for c in per_shard {
        buf.extend_from_slice(&c.to_le_bytes());
    }
    let tmp = dir.join(format!("{UNSORTED_DONE_NAME}.tmp"));
    let dst = dir.join(UNSORTED_DONE_NAME);
    fs::write(&tmp, &buf).map_err(|e| StoreError::io(&tmp, e))?;
    {
        let f = OpenOptions::new()
            .write(true)
            .open(&tmp)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    }
    fs::rename(&tmp, &dst).map_err(|e| StoreError::io(&dst, e))?;
    Ok(())
}

/// True when `DONE` matches `n_shards` and every shard file is `count * 40` bytes.
pub fn unsorted_manifest_ok(dir: &Path, n_shards: usize) -> bool {
    let p = dir.join(UNSORTED_DONE_NAME);
    let Ok(buf) = fs::read(&p) else {
        return false;
    };
    if buf.len() < 12 || buf.len() != 12 + n_shards * 8 || &buf[..8] != UNSORTED_DONE_MAGIC {
        return false;
    }
    let n = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4])) as usize;
    if n != n_shards {
        return false;
    }
    for i in 0..n_shards {
        let off = 12 + i * 8;
        let count = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]));
        let path = unsorted_shard_path(dir, i);
        let Ok(meta) = fs::metadata(&path) else {
            return false;
        };
        if meta.len() != count.saturating_mul(UNSORTED_REC_LEN as u64) {
            return false;
        }
    }
    true
}

pub fn clear_unsorted_shard_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// One Class A pass: n workers scan fk chunks and pwrite 40-byte recs to `n_shards` FDs.
pub fn collect_unsorted_shard_files(
    store: &Store,
    dir: &Path,
    n_shards: usize,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedShardCollect, StoreError> {
    let last = store.txs.count();
    if last == 0 {
        return collect_unsorted_from_txs(&store.txs, dir, n_shards, 1, 0, workers, cancel);
    }
    collect_unsorted_from_txs(&store.txs, dir, n_shards, 1, last, workers, cancel)
}

fn collect_unsorted_from_txs(
    txs: &TxTable,
    dir: &Path,
    n_shards: usize,
    first: u64,
    last: u64,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedShardCollect, StoreError> {
    let n_shards = n_shards.max(1);
    clear_unsorted_shard_dir(dir);
    fs::create_dir_all(dir).map_err(|e| StoreError::io(dir, e))?;
    let mut sinks = Vec::with_capacity(n_shards);
    for shard in 0..n_shards {
        let path = unsorted_shard_path(dir, shard);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        sinks.push(UnsortedShardSink {
            path,
            file,
            cursor: AtomicU64::new(0),
        });
    }

    if last < first {
        let per_shard = vec![0u64; n_shards];
        write_unsorted_done(dir, &per_shard)?;
        return Ok(UnsortedShardCollect { recs: 0, per_shard });
    }

    let work_span = last.saturating_sub(first.saturating_sub(1));
    let workers = workers.max(1).min(256);
    let by_size = work_span.div_ceil(CLASS_A_CHUNK_FKS).max(1) as usize;
    let n_chunks = by_size.max(workers.min(work_span as usize).max(1));
    let chunk_span = work_span.div_ceil(n_chunks as u64).max(1);
    let workers = workers.min(n_chunks);
    let next_chunk = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<StoreError>> = Mutex::new(None);
    let n_recs = AtomicU64::new(0);
    let t0 = Instant::now();

    rbitcoin_log::info!(
        "store: scripthash unsorted collect start n_shards={n_shards} workers={workers} \
         chunks={n_chunks} first={first} last={last}"
    );

    std::thread::scope(|scope| {
        let sinks = &sinks;
        let next_chunk = &next_chunk;
        let stop = &stop;
        let first_err = &first_err;
        let n_recs = &n_recs;
        scope.spawn(|| {
            let mut last_log = Instant::now();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
                if last_log.elapsed() < MATERIALIZE_STATUS_INTERVAL {
                    continue;
                }
                last_log = Instant::now();
                let recs = n_recs.load(Ordering::Relaxed);
                rbitcoin_log::info!(
                    "store: scripthash unsorted collect status recs≈{recs} assigned={} \
                     workers={workers} elapsed={:?}",
                    next_chunk.load(Ordering::Relaxed).min(n_chunks),
                    t0.elapsed()
                );
            }
        });
        let mut joins = Vec::with_capacity(workers);
        for _ in 0..workers {
            joins.push(scope.spawn(|| {
                let mut bufs: Vec<Vec<u8>> = (0..n_shards)
                    .map(|_| Vec::with_capacity(UNSORTED_FLUSH_BYTES))
                    .collect();
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
                    let lo = first.saturating_add((i as u64).saturating_mul(chunk_span));
                    let hi = lo.saturating_add(chunk_span).saturating_sub(1).min(last);
                    if lo > last {
                        continue;
                    }
                    match txs.for_each_script_hashes_in_fk_span(lo, hi, |fk, sh| {
                        let shard = prefix_shard_of(&sh, n_shards);
                        let rec = encode_unsorted_rec(&sh, fk);
                        bufs[shard].extend_from_slice(&rec);
                        n_recs.fetch_add(1, Ordering::Relaxed);
                        if bufs[shard].len() >= UNSORTED_FLUSH_BYTES {
                            flush_unsorted_buf(&sinks[shard], &mut bufs[shard])?;
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
                for (shard, buf) in bufs.iter_mut().enumerate() {
                    if let Err(e) = flush_unsorted_buf(&sinks[shard], buf) {
                        *first_err.lock().unwrap() = Some(e);
                        stop.store(true, Ordering::Relaxed);
                    }
                }
            }));
        }
        for j in joins {
            if j.join().is_err() {
                *first_err.lock().unwrap() = Some(StoreError::Corrupt(
                    "scripthash unsorted collect worker panicked",
                ));
            }
        }
        stop.store(true, Ordering::Relaxed);
    });

    if let Some(e) = first_err.lock().unwrap().take() {
        return Err(e);
    }
    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
        return Err(StoreError::Cancelled("scripthash unsorted class a collect"));
    }

    let mut per_shard = Vec::with_capacity(n_shards);
    for sink in &sinks {
        let bytes = sink.cursor.load(Ordering::Relaxed);
        if !bytes.is_multiple_of(UNSORTED_REC_LEN as u64) {
            return Err(StoreError::Corrupt(
                "scripthash unsorted shard size not a multiple of 40",
            ));
        }
        sink.file
            .set_len(bytes)
            .map_err(|e| StoreError::io(&sink.path, e))?;
        sink.file
            .sync_all()
            .map_err(|e| StoreError::io(&sink.path, e))?;
        per_shard.push(bytes / UNSORTED_REC_LEN as u64);
    }
    write_unsorted_done(dir, &per_shard)?;
    let recs = per_shard.iter().copied().sum();
    rbitcoin_log::info!(
        "store: scripthash unsorted collect done recs={recs} n_shards={n_shards} elapsed={:?}",
        t0.elapsed()
    );
    Ok(UnsortedShardCollect { recs, per_shard })
}

fn load_unsorted_shard_records(path: &Path) -> Result<Vec<ScriptHashRecord>, StoreError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::io(path, e)),
    };
    if !bytes.len().is_multiple_of(UNSORTED_REC_LEN) {
        return Err(StoreError::Corrupt(
            "scripthash unsorted shard file length not a multiple of 40",
        ));
    }
    let mut recs = Vec::with_capacity(bytes.len() / UNSORTED_REC_LEN);
    for chunk in bytes.chunks_exact(UNSORTED_REC_LEN) {
        let (sh, fk) = decode_sh_run_rec(chunk)?;
        if fk.is_null() {
            continue;
        }
        recs.push(ScriptHashRecord::from_fk(sh, fk));
    }
    recs.sort_unstable_by(|a, b| {
        a.scripthash
            .cmp(&b.scripthash)
            .then(a.create_tx_fk.0.cmp(&b.create_tx_fk.0))
    });
    Ok(recs)
}

fn pack_unsorted_shard(
    table: &ScriptHashTable,
    dir: &Path,
    shard: usize,
    cancel: Option<&AtomicBool>,
    progress: &MaterializeProgress,
) -> Result<ShShardPack, StoreError> {
    let path = unsorted_shard_path(dir, shard);
    let recs = load_unsorted_shard_records(&path)?;
    let mut session = table.pack_shard_session(shard)?;
    let t_loop = Instant::now();
    for (i, rec) in recs.iter().enumerate() {
        if i & 0xfff == 0 && cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash unsorted shard pack"));
        }
        session.push_sorted_fk(rec.scripthash, rec.create_tx_fk)?;
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

/// RAM-sort each unsorted shard file and seal `head/NN` for unsealed shards.
pub fn materialize_sh_from_unsorted(
    table: &ScriptHashTable,
    unsorted_dir: &Path,
    pack_workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    let jobs: Vec<usize> = table
        .unsealed_main_shards()
        .into_iter()
        .filter(|s| *s < n_shards)
        .collect();
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
    let workers = pack_workers.max(1).min(jobs.len());
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
    let max_fk = AtomicU64::new(0);
    rbitcoin_log::info!(
        "store: scripthash unsorted pack start unsealed={} n_shards={n_shards} workers={workers}",
        jobs.len()
    );

    let out = std::thread::scope(|scope| {
        let progress = &progress;
        let max_fk = &max_fk;
        let _stop = StopOnDrop(progress);
        if workers <= 1 {
            for shard in jobs {
                if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                    return Err(StoreError::Cancelled("scripthash unsorted shard pack"));
                }
                let pack = pack_unsorted_shard(table, unsorted_dir, shard, cancel, progress)?;
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
                joins.push(scope.spawn(move || loop {
                    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                        let mut g = shared.err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash unsorted shard pack"));
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
                    match pack_unsorted_shard(table, unsorted_dir, shard, cancel, progress)
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
                    return Err(StoreError::Corrupt(
                        "scripthash unsorted pack worker panicked",
                    ));
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
    rbitcoin_log::info!(
        "store: scripthash unsorted pack done creates≈{} keys≈{} elapsed={:?}",
        out.creates,
        out.keys,
        t0.elapsed()
    );
    Ok(out)
}

/// Collect (unless `DONE` is valid) then pack unsealed shards from Class A.
pub fn materialize_sh_unsorted_from_class_a(
    store: &Store,
    collect_workers: usize,
    pack_workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let table = &store.scripthash;
    let n_shards = table.head_shard_count().max(1);
    let dir = unsorted_shard_dir(store.path());
    let collect_workers = if collect_workers == 0 {
        unsorted_collect_workers()
    } else {
        collect_workers
    };
    let pack_workers = if pack_workers == 0 {
        unsorted_pack_workers()
    } else {
        pack_workers
    };

    let unsealed = table.unsealed_main_shards();
    if unsealed.is_empty() && (!table.head_is_empty() || table.entry_count() > 0) {
        clear_unsorted_shard_dir(&dir);
        ColdProgress::clear(store.path());
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

    if table.head_is_empty() {
        table.reinit_empty_for_cold_materialize()?;
    }

    if !unsorted_manifest_ok(&dir, n_shards) {
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(StoreError::Cancelled("scripthash unsorted class a collect"));
        }
        collect_unsorted_shard_files(store, &dir, n_shards, collect_workers, cancel)?;
    }

    let mat = materialize_sh_from_unsorted(table, &dir, pack_workers, cancel)?;
    if table.unsealed_main_shards().is_empty() {
        clear_unsorted_shard_dir(&dir);
        ColdProgress::clear(store.path());
    }
    Ok(mat)
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

    #[test]
    fn unsorted_pack_workers_use_2gib_not_sh_1_5gib() {
        assert_eq!(
            crate::sorted_run::workers_for_free_ram(8, 3 << 30, SH_UNSORTED_PACK_RAM_BYTES),
            1,
            "3 GiB free / 2 GiB per unsorted pack worker"
        );
        assert_eq!(
            crate::sorted_run::sh_workers_for_free_ram(8, 3 << 30),
            2,
            "SH k-way 1.5 GiB: 3 GiB / 1.5 GiB = 2"
        );
        assert_eq!(
            crate::sorted_run::workers_for_free_ram(16, 8 << 30, SH_UNSORTED_PACK_RAM_BYTES),
            4,
            "8 GiB free → 4 unsorted pack workers"
        );
    }
}
