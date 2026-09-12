//! **idx → body** pipeline for confirm load (`txout` / `inwit` / `spent` stems).
//!
//! Idx via sorted [`VarTable::record_range_batch`] (idx segments are
//! fd pread). Body backend from
//! [`crate::io_backend::read_io_backend`] (global
//! `RBITCOIN_IO`): **uring** or **pread**. Class A body is also FdOnly.
//!
//! **Concurrency:** read-only on published ranges; prep + confirm-load may run
//! concurrent waves (each thread's bulk_io TL ring). Caller owns job buffers
//! until the call returns.

use crate::bulk_io::{self, ReadOp};
use crate::error::StoreError;
use crate::io_backend::{self, ReadIoBackend};
use crate::var_table::VarTable;
use rbitcoin_primitives::Fk;

/// What body bytes to fetch after the range is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// Full record (txout or inwit).
    Full,
    /// `txout` first page (outs / pin).
    Outs,
    /// Leading ≤32 body bytes (retired; tests only).
    Prefix33,
}

impl BodyMode {
    #[inline]
    fn body_len(self, range_len: u64) -> u64 {
        match self {
            BodyMode::Full => range_len,
            BodyMode::Outs => range_len.min(4096),
            BodyMode::Prefix33 => range_len.min(32),
        }
    }
}

/// One cold Class A layout + body job.
///
/// **Input:** set `id` (1-based Class A fk) and optionally `range` when known
/// (sticky / FIFO). **Output:** `range`, `body` (on success), `ok`.
#[derive(Debug)]
pub struct IdxBodyJob {
    /// 1-based create id (`Fk.0` when non-null).
    pub id: u64,
    /// Known `(body_off, body_len)` skips idx; filled by pipeline when resolved.
    pub range: Option<(u64, u64)>,
    /// Body bytes (mode-sized) when `ok`.
    pub body: Vec<u8>,
    /// True when body pread completed for the expected length.
    pub ok: bool,
    /// Sparse Outs need (sorted unique). Empty = all outs (SH / ensure).
    pub need_vouts: Vec<u32>,
}

impl IdxBodyJob {
    pub fn new(id: u64, range: Option<(u64, u64)>) -> Self {
        Self {
            id,
            range,
            body: Vec::new(),
            ok: false,
            need_vouts: Vec::new(),
        }
    }

    pub fn from_fk(fk: Fk, range: Option<(u64, u64)>) -> Option<Self> {
        let id = fk.get()?;
        if id == 0 {
            return None;
        }
        Some(Self::new(id, range))
    }
}

/// Body-wave IO counts for `ibd: perf` (extend / page-grouped SQEs).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IdxBodyIoStats {
    /// Second-wave Outs jobs that pread the remainder of the idx span.
    pub extend_n: u64,
    /// Body `ReadOp`s submitted (first wave + extend), after page grouping.
    pub body_sqe_n: u64,
}

const BODY_OS_PAGE: u64 = crate::tx_table::BODY_PAGE_SIZE;
/// Cap a coalesced span at two OS pages (one straddle). Do not chain into SH-sized reads.
const BODY_GROUP_MAX_PAGES: u64 = 2;

/// Offset-sorted `[off, off+len)` windows → `(page_off, span_len, window indices)`.
///
/// Jobs that share an OS page (or a two-page straddle) become one SQE. Adjacent
/// disjoint pages stay split.
fn group_body_peeks(windows: &[(u64, u64)]) -> Vec<(u64, u64, Vec<usize>)> {
    let mut groups = Vec::new();
    if windows.is_empty() {
        return groups;
    }
    let pages = |off: u64, len: u64| -> (u64, u64) {
        let lo = off / BODY_OS_PAGE;
        let hi = if len == 0 {
            lo
        } else {
            off.saturating_add(len).saturating_sub(1) / BODY_OS_PAGE
        };
        (lo, hi)
    };
    let mut start = 0usize;
    let (mut glo, mut ghi) = pages(windows[0].0, windows[0].1);
    let mut min_off = windows[0].0;
    let mut max_end = windows[0].0.saturating_add(windows[0].1);
    for (i, &(off, len)) in windows.iter().enumerate().skip(1) {
        let (plo, phi) = pages(off, len);
        let new_hi = ghi.max(phi);
        if plo <= ghi && new_hi.saturating_sub(glo) < BODY_GROUP_MAX_PAGES {
            ghi = new_hi;
            max_end = max_end.max(off.saturating_add(len));
            continue;
        }
        let page_off = (min_off / BODY_OS_PAGE) * BODY_OS_PAGE;
        groups.push((
            page_off,
            max_end.saturating_sub(page_off),
            (start..i).collect(),
        ));
        start = i;
        glo = plo;
        ghi = phi;
        min_off = off;
        max_end = off.saturating_add(len);
    }
    let page_off = (min_off / BODY_OS_PAGE) * BODY_OS_PAGE;
    groups.push((
        page_off,
        max_end.saturating_sub(page_off),
        (start..windows.len()).collect(),
    ));
    groups
}

struct PeekDest {
    job: usize,
    off: u64,
    dest: usize,
    len: usize,
}

fn pread_grouped_peeks(
    jobs: &mut [IdxBodyJob],
    dests: &[PeekDest],
    body_fd: crate::io_handle::IoHandle,
    body_path: &std::path::Path,
    backend: ReadIoBackend,
    mark_ok: bool,
) -> Result<u64, StoreError> {
    if dests.is_empty() {
        return Ok(0);
    }
    let windows: Vec<(u64, u64)> = dests.iter().map(|d| (d.off, d.len as u64)).collect();
    let groups = group_body_peeks(&windows);
    let mut bufs: Vec<Vec<u8>> = groups
        .iter()
        .map(|(_, len, _)| vec![0u8; *len as usize])
        .collect();
    // SAFETY: each bufs[g] is a distinct allocation owned until after pread.
    let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(groups.len());
    for (g, (page_off, len, _)) in groups.iter().enumerate() {
        let ptr = bufs[g].as_mut_ptr();
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, *len as usize) };
        ops.push(ReadOp {
            fd: body_fd,
            offset: *page_off,
            buf: slice,
            result: i32::MIN,
        });
    }
    bulk_io::pread_batch_backend(&mut ops, backend);
    for (g, ((page_off, _, members), ro)) in groups.iter().zip(ops.iter()).enumerate() {
        if ro.result < 0 {
            return Err(StoreError::io(
                body_path,
                std::io::Error::from_raw_os_error(-ro.result),
            ));
        }
        let got = ro.result as usize;
        let buf = &bufs[g];
        for &wi in members {
            let d = &dests[wi];
            let rel = d.off.saturating_sub(*page_off) as usize;
            let need_end = rel.saturating_add(d.len);
            if got < need_end || rel + d.len > buf.len() {
                if !mark_ok {
                    jobs[d.job].ok = false;
                }
                continue;
            }
            jobs[d.job].body[d.dest..d.dest + d.len].copy_from_slice(&buf[rel..rel + d.len]);
            if mark_ok {
                jobs[d.job].ok = true;
            }
        }
    }
    Ok(groups.len() as u64)
}

/// Resolve idx (FdOnly pread) then body (backend from env). Mutates `jobs` in place.
///
/// Jobs with invalid / OOB ids are left `ok = false` without failing the batch
/// (caller applies confirm hard invariants vs head-resolve skip policy).
pub fn run_idx_body_pipeline(
    table: &VarTable,
    jobs: &mut [IdxBodyJob],
    mode: BodyMode,
) -> Result<IdxBodyIoStats, StoreError> {
    run_idx_body_pipeline_backend(table, jobs, mode, io_backend::read_io_backend())
}

/// Like [`run_idx_body_pipeline`] with an explicit body backend (tests / tools).
pub fn run_idx_body_pipeline_backend(
    table: &VarTable,
    jobs: &mut [IdxBodyJob],
    mode: BodyMode,
    backend: ReadIoBackend,
) -> Result<IdxBodyIoStats, StoreError> {
    if jobs.is_empty() {
        return Ok(IdxBodyIoStats::default());
    }
    let mut need_fk: Vec<Fk> = Vec::new();
    let mut need_slot: Vec<usize> = Vec::new();
    for (i, j) in jobs.iter().enumerate() {
        if j.range.is_none() && j.id > 0 {
            need_fk.push(Fk(j.id));
            need_slot.push(i);
        }
    }
    // Page-coalesced idx (one OS-page / uring SQE per distinct page), then body.
    // Contiguous runs still use record_range_batch (page-aligned collect_starts).
    if !need_fk.is_empty() {
        let ranges = table.record_range_batch(&need_fk)?;
        for (slot, r) in need_slot.into_iter().zip(ranges) {
            jobs[slot].range = r;
        }
    }

    let body_fd = table.body_read_fd();
    let body_pub = table.body_published_len();
    let body_path = table.body_file_path();

    let mut submitted: Vec<usize> = Vec::new();
    for (i, j) in jobs.iter_mut().enumerate() {
        j.ok = false;
        j.body.clear();
        let Some((off, full_len)) = j.range else {
            continue;
        };
        let want = mode.body_len(full_len);
        if want == 0 || off.saturating_add(want) > body_pub {
            continue;
        }
        j.body.resize(want as usize, 0);
        submitted.push(i);
    }
    if submitted.is_empty() {
        return Ok(IdxBodyIoStats::default());
    }

    submitted.sort_unstable_by_key(|&i| jobs[i].range.map(|(o, _)| o).unwrap_or(0));

    let dests: Vec<PeekDest> = submitted
        .iter()
        .map(|&i| PeekDest {
            job: i,
            off: jobs[i].range.unwrap().0,
            dest: 0,
            len: jobs[i].body.len(),
        })
        .collect();
    let mut stats = IdxBodyIoStats {
        body_sqe_n: pread_grouped_peeks(jobs, &dests, body_fd, body_path, backend, true)?,
        ..Default::default()
    };
    if mode == BodyMode::Outs {
        let (extend_n, extend_sqe) = extend_truncated_txout_jobs(table, jobs, backend)?;
        stats.extend_n = extend_n;
        stats.body_sqe_n = stats.body_sqe_n.saturating_add(extend_sqe);
    }
    Ok(stats)
}

/// Second wave: when a 4 KiB Outs read does not cover needed outputs, pread the
/// remainder of the idx span. Empty need walks every out; sparse need skips
/// extend when the first page already contains those vouts.
fn extend_truncated_txout_jobs(
    table: &VarTable,
    jobs: &mut [IdxBodyJob],
    backend: ReadIoBackend,
) -> Result<(u64, u64), StoreError> {
    let mut rest: Vec<(usize, usize)> = Vec::new();
    let body_pub = table.body_published_len();
    for (i, j) in jobs.iter_mut().enumerate() {
        if !j.ok {
            continue;
        }
        let Some((off, full_len)) = j.range else {
            continue;
        };
        if (j.body.len() as u64) >= full_len {
            continue;
        }
        if crate::tx_table::txout_first_page_covers_need(&j.body, &j.need_vouts) {
            continue;
        }
        if off.saturating_add(full_len) > body_pub {
            j.ok = false;
            continue;
        }
        let have = j.body.len();
        j.body.resize(full_len as usize, 0);
        rest.push((i, have));
    }
    if rest.is_empty() {
        return Ok((0, 0));
    }
    let extend_n = rest.len() as u64;
    rest.sort_unstable_by_key(|&(i, have)| {
        jobs[i]
            .range
            .map(|(o, _)| o.saturating_add(have as u64))
            .unwrap_or(0)
    });
    let dests: Vec<PeekDest> = rest
        .iter()
        .map(|&(i, have)| PeekDest {
            job: i,
            off: jobs[i].range.unwrap().0.saturating_add(have as u64),
            dest: have,
            len: jobs[i].body.len().saturating_sub(have),
        })
        .collect();
    let sqe = pread_grouped_peeks(
        jobs,
        &dests,
        table.body_read_fd(),
        table.body_file_path(),
        backend,
        false,
    )?;
    Ok((extend_n, sqe))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_table::{
        decode_packed_tx_outs_with_spender_rels, InputRecord, OutputRecord, TxRecord, TxTable,
    };
    use rbitcoin_primitives::Fk;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_tx() -> (std::path::PathBuf, TxTable) {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-idx-body-pipe-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = TxTable::create_tiny(&dir).unwrap();
        (dir, t)
    }

    fn put_n(t: &TxTable, n: u8) -> Vec<Fk> {
        let mut fks = Vec::new();
        for i in 0..n {
            let mut txid = [0u8; 32];
            txid[0] = i.wrapping_add(1);
            let tx = TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1 + (i % 3) as u32,
            };
            let inputs = vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![i],
                witness: vec![],
            }];
            let mut outs = Vec::new();
            for j in 0..(1 + (i % 3)) {
                outs.push(OutputRecord::unspent(j as i64 + 1, vec![0x51, j]));
            }
            fks.push(
                t.put_full_batch_indexed(&[(tx, inputs, outs)], true)
                    .unwrap()[0],
            );
        }
        fks
    }

    #[test]
    fn from_fk_and_empty_pipeline() {
        assert!(IdxBodyJob::from_fk(Fk::NULL, None).is_none());
        assert!(IdxBodyJob::from_fk(Fk(0), None).is_none());
        let j = IdxBodyJob::from_fk(Fk(7), Some((16, 8))).unwrap();
        assert_eq!(j.id, 7);
        assert_eq!(j.range, Some((16, 8)));
        let (dir, t) = temp_tx();
        run_idx_body_pipeline(&t.body, &mut [], BodyMode::Full).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_body_peeks_same_page_merges() {
        let g = group_body_peeks(&[(0, 91), (91, 91)]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].2, vec![0, 1]);
        assert_eq!(g[0].0, 0);
    }

    #[test]
    fn group_body_peeks_distinct_pages_split() {
        let g = group_body_peeks(&[(0, 91), (8192, 91)]);
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn group_body_peeks_straddle_pulls_same_pages() {
        let g = group_body_peeks(&[(0, 91), (4000, 2000)]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].2, vec![0, 1]);
    }

    #[test]
    fn group_body_peeks_caps_straddle_chain_at_two_pages() {
        let g = group_body_peeks(&[(100, 4096), (4196, 4096)]);
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn pipeline_outs_coalesces_same_page_peeks() {
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 8);
        let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
        assert!(stats.body_sqe_n >= 1);
        assert!(
            stats.body_sqe_n < jobs.len() as u64,
            "sqe={} jobs={}",
            stats.body_sqe_n,
            jobs.len()
        );
        for j in &jobs {
            assert!(j.ok, "id={}", j.id);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_outs_extends_past_first_page() {
        let (dir, t) = temp_tx();
        let tx = TxRecord {
            txid: [0x7eu8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let outs = vec![OutputRecord::unspent(1, vec![0x51; 6000])];
        let fk = t
            .put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap()[0];
        let (_off, full_len) = t.body.record_range(fk).unwrap();
        assert!(full_len > 4096, "fixture must exceed first-page cap");
        let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
        assert!(jobs[0].ok);
        assert_eq!(jobs[0].body.len() as u64, full_len);
        let (meta, decoded, _) =
            crate::tx_table::decode_packed_tx_outs_with_spender_rels(&jobs[0].body).unwrap();
        assert_eq!(meta.output_count, 1);
        assert_eq!(decoded[0].script.len(), 6000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fat_many_outs(n_out: u32) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
        let tx = TxRecord {
            txid: [0x5au8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: n_out,
        };
        let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let mut outs = Vec::with_capacity(n_out as usize);
        outs.push(OutputRecord::unspent(1, vec![0x51]));
        for _ in 1..n_out {
            outs.push(OutputRecord::unspent(1, vec![0x51; 64]));
        }
        (tx, inputs, outs)
    }

    #[test]
    fn pipeline_outs_skips_extend_when_need_fits_first_page() {
        let (dir, t) = temp_tx();
        let (tx, inputs, outs) = fat_many_outs(80);
        let fk = t
            .put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap()[0];
        let (_off, full_len) = t.body.record_range(fk).unwrap();
        assert!(full_len > 4096, "fixture must exceed first-page cap");
        let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
        jobs[0].need_vouts = vec![0];
        let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
        assert!(jobs[0].ok);
        assert_eq!(jobs[0].body.len(), 4096);
        assert_eq!(stats.extend_n, 0);
        let (meta, live, _) = crate::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            &[0],
            None,
        )
        .unwrap();
        assert_eq!(meta.output_count, 80);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_outs_extends_when_need_past_first_page() {
        let (dir, t) = temp_tx();
        let (tx, inputs, outs) = fat_many_outs(80);
        let fk = t
            .put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap()[0];
        let (_off, full_len) = t.body.record_range(fk).unwrap();
        assert!(full_len > 4096, "fixture must exceed first-page cap");
        let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
        jobs[0].need_vouts = vec![79];
        let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
        assert!(jobs[0].ok);
        assert_eq!(jobs[0].body.len() as u64, full_len);
        assert_eq!(stats.extend_n, 1);
        let (_meta, live, _) =
            crate::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
                &jobs[0].body,
                &[79],
                None,
            )
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, 79);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// uring / pread body backends produce identical Full payloads.
    #[test]
    fn pipeline_body_backends_agree() {
        use crate::io_backend::ReadIoBackend;
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 8);
        let mut bodies: Vec<Vec<Vec<u8>>> = Vec::new();
        for backend in [ReadIoBackend::Uring, ReadIoBackend::Pread] {
            let mut jobs: Vec<IdxBodyJob> =
                fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
            run_idx_body_pipeline_backend(&t.body, &mut jobs, BodyMode::Full, backend).unwrap();
            let mut batch = Vec::new();
            for j in &jobs {
                assert!(j.ok, "backend={backend:?} id={}", j.id);
                batch.push(j.body.clone());
            }
            bodies.push(batch);
        }
        assert_eq!(bodies[0], bodies[1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_full_matches_record_range_and_decode() {
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 12);
        // Unsorted + one pre-known range.
        let (known_off, known_len) = t.body.record_range(fks[3]).unwrap();
        let mut jobs: Vec<IdxBodyJob> = fks
            .iter()
            .enumerate()
            .map(|(i, fk)| {
                let range = if i == 3 {
                    Some((known_off, known_len))
                } else {
                    None
                };
                IdxBodyJob::new(fk.0, range)
            })
            .collect();
        // Shuffle order.
        jobs.swap(0, 7);
        jobs.swap(2, 10);
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
        for j in &jobs {
            assert!(j.ok, "id={}", j.id);
            let seq = t.body.record_range(Fk(j.id)).unwrap();
            assert_eq!(j.range, Some(seq));
            let (tx, outs, rels) = decode_packed_tx_outs_with_spender_rels(&j.body).unwrap();
            assert_eq!(outs.len(), rels.len());
            assert_eq!(tx.output_count as usize, outs.len());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_prefix33_and_denserels_modes() {
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 5);
        let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Prefix33).unwrap();
        for j in &jobs {
            assert!(j.ok);
            assert!(j.body.len() <= 32);
            assert!(!j.body.is_empty());
        }
        let mut jobs2: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        run_idx_body_pipeline(&t.body, &mut jobs2, BodyMode::Outs).unwrap();
        for j in &jobs2 {
            assert!(j.ok);
            let (_tx, outs, rels) =
                crate::tx_table::decode_packed_tx_outs_with_spender_rels(&j.body).unwrap();
            assert_eq!(outs.len(), rels.len());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pre-known ranges skip idx; remaining jobs still resolve + body-read.
    /// Identity: pipeline body bytes match sequential `record_range` + decode.
    #[test]
    fn pipeline_preknown_range_skips_idx_identity() {
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 8);
        let mut jobs: Vec<IdxBodyJob> = fks
            .iter()
            .enumerate()
            .map(|(i, fk)| {
                let range = if i % 2 == 0 {
                    Some(t.body.record_range(*fk).unwrap())
                } else {
                    None
                };
                IdxBodyJob::new(fk.0, range)
            })
            .collect();
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
        for j in &jobs {
            assert!(j.ok, "id={}", j.id);
            let seq = t.body.record_range(Fk(j.id)).unwrap();
            assert_eq!(j.range, Some(seq));
            let (tx, outs, rels) = decode_packed_tx_outs_with_spender_rels(&j.body).unwrap();
            assert_eq!(outs.len(), rels.len());
            assert_eq!(tx.output_count as usize, outs.len());
        }
        // Second wave reuses bulk_io TL ring; results stable.
        let mut jobs2: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        run_idx_body_pipeline(&t.body, &mut jobs2, BodyMode::Full).unwrap();
        for (a, b) in jobs.iter().zip(jobs2.iter()) {
            assert_eq!(a.range, b.range);
            assert_eq!(a.body, b.body);
            assert!(b.ok);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oob_and_null_ids_not_ok() {
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 2);
        let mut jobs = vec![
            IdxBodyJob::new(0, None),
            IdxBodyJob::new(fks[0].0, None),
            IdxBodyJob::new(99_999, None),
        ];
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
        assert!(!jobs[0].ok);
        assert!(jobs[1].ok);
        assert!(!jobs[2].ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Synthetic confirm-load-style cold batch: N Class A txs, mixed pre-known
    /// ranges, timed multi-wave idx+body. Prints wall µs for evidence capture.
    #[test]
    fn synthetic_cold_batch_timed_identity() {
        use std::time::Instant;
        let (dir, t) = temp_tx();
        let fks = put_n(&t, 64);
        // Wave 1: cold idx+body for all
        let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        let t0 = Instant::now();
        run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
        let cold_us = t0.elapsed().as_micros();
        assert_eq!(jobs.iter().filter(|j| j.ok).count(), fks.len());
        let bodies: Vec<Vec<u8>> = jobs.iter().map(|j| j.body.clone()).collect();
        let ranges: Vec<_> = jobs.iter().map(|j| j.range).collect();

        // Wave 2: all ranges pre-known (skip idx) — confirm pin_new-ish path
        let mut jobs2: Vec<IdxBodyJob> = fks
            .iter()
            .zip(ranges.iter())
            .map(|(fk, r)| IdxBodyJob::new(fk.0, *r))
            .collect();
        let t1 = Instant::now();
        run_idx_body_pipeline(&t.body, &mut jobs2, BodyMode::Full).unwrap();
        let warm_us = t1.elapsed().as_micros();
        for (i, j) in jobs2.iter().enumerate() {
            assert!(j.ok, "i={i}");
            assert_eq!(j.body, bodies[i]);
            assert_eq!(j.range, ranges[i]);
        }

        // Wave 3: Prefix33 head-resolve style
        let mut jobs3: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        let t2 = Instant::now();
        run_idx_body_pipeline(&t.body, &mut jobs3, BodyMode::Prefix33).unwrap();
        let prefix_us = t2.elapsed().as_micros();
        for j in &jobs3 {
            assert!(j.ok);
            assert!(j.body.len() <= 32 && !j.body.is_empty());
        }

        eprintln!(
            "synthetic_cold_batch: n={} cold_full={}us preknown_full={}us prefix33={}us uring={}",
            fks.len(),
            cold_us,
            warm_us,
            prefix_us,
            crate::bulk_io::io_uring_enabled()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
