//! Completion-session load for BIP-352 tweak backfill.
//!
//! Reads: idx ranges **before** taking the TLS ring (no nested
//! `with_thread_local`), then S1 `txout` → S2 `inwit` / S3 parent `txout` only
//! for P2TR creates.
//!
//! Writes are **not** this machine: consecutive heights go through
//! [`SpTweaksTable::put_blocks`] (one body pwrite + one idx pwrite).

use crate::error::StoreError;
use crate::io_handle::IoHandle;
use crate::tx_table::{
    decode_inwit_secret, decode_packed_tx_outs_with_spender_rels_secret, InputRecord, OutputRecord,
    TxRecord, TxTable,
};
use crate::uring_session::{self, UringSession};
use crate::U64Map;
use rbitcoin_primitives::Fk;
use std::path::Path;

/// One create after the load wave.
pub struct LoadedTweakTx {
    pub fk: Fk,
    pub rec: TxRecord,
    pub outs: Vec<OutputRecord>,
    pub need_inwit: bool,
    pub inputs: Option<Vec<InputRecord>>,
}

/// Wave result: per-fk bodies + parent outs for P2TR spends not in the wave.
pub struct TweakWave {
    pub txs: Vec<LoadedTweakTx>,
    pub parents: U64Map<([u8; 32], Vec<OutputRecord>)>,
}

fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

struct PreadJob {
    off: u64,
    buf: Vec<u8>,
}

fn jobs_from_ranges(ranges: &[Option<(u64, u64)>], cap: Option<usize>) -> Vec<PreadJob> {
    ranges
        .iter()
        .map(|r| match r {
            Some((off, len)) if *len > 0 => {
                let n = match cap {
                    Some(c) => (*len as usize).min(c).max(1),
                    None => (*len as usize).max(1),
                };
                PreadJob {
                    off: *off,
                    buf: vec![0u8; n],
                }
            }
            _ => PreadJob {
                off: 0,
                buf: Vec::new(),
            },
        })
        .collect()
}

fn run_preads_serial(fd: IoHandle, path: &Path, jobs: &mut [PreadJob]) -> Result<(), StoreError> {
    for job in jobs.iter_mut() {
        if job.buf.is_empty() {
            continue;
        }
        let rc = crate::bulk_io::pread_single(fd, job.off, &mut job.buf);
        uring_session::require_full_cqe(rc, job.buf.len(), path)?;
    }
    Ok(())
}

fn run_preads(
    session: &mut UringSession,
    fd: IoHandle,
    path: &Path,
    kind: u8,
    jobs: &mut [PreadJob],
) -> Result<(), StoreError> {
    if jobs.is_empty() {
        return Ok(());
    }
    session.begin_batch()?;
    let epoch = session.epoch();
    let n = jobs.len();
    let mut next = 0usize;
    let mut inflight = 0usize;
    let mut n_done = 0usize;

    loop {
        while inflight < 128 && session.free_sq() > 0 && next < n {
            let i = next;
            next += 1;
            if jobs[i].buf.is_empty() {
                n_done += 1;
                continue;
            }
            let ud = uring_session::pack_ud(kind, epoch, i as u32);
            session.push_pread(fd, jobs[i].off, &mut jobs[i].buf, ud)?;
            inflight += 1;
        }
        if n_done >= n {
            break;
        }
        if inflight == 0 {
            break;
        }
        session.sync_submission();
        let _ = session.submit();
        let mut cqes = session.harvest_ready()?;
        if cqes.is_empty() {
            session.submit_and_wait_one()?;
            cqes = session.harvest_ready()?;
        }
        for (ud, res) in cqes {
            let (k, ep, slot) = uring_session::unpack_ud(ud);
            if k != kind || ep != epoch {
                return Err(StoreError::Corrupt("sp_tweaks load leftover CQE"));
            }
            let i = slot as usize;
            if i >= n {
                return Err(StoreError::Corrupt("sp_tweaks load bad slot"));
            }
            uring_session::require_full_cqe(res, jobs[i].buf.len(), path)?;
            inflight = inflight.saturating_sub(1);
            n_done += 1;
        }
    }
    Ok(())
}

fn run_stage(fd: IoHandle, path: &Path, kind: u8, jobs: &mut [PreadJob]) -> Result<(), StoreError> {
    if jobs.iter().all(|j| j.buf.is_empty()) {
        return Ok(());
    }
    match uring_session::with_thread_local(uring_session::DEFAULT_ENTRIES, |session| {
        let mut session = session.drain_guard();
        run_preads(&mut session, fd, path, kind, jobs)
    }) {
        Ok(r) => r,
        Err(_) => run_preads_serial(fd, path, jobs),
    }
}

fn empty_rec(txid: [u8; 32]) -> TxRecord {
    TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 0,
        output_start_fk: Fk::NULL,
        output_count: 0,
    }
}

/// Load outs for `fks`; inwit + extra parents only for P2TR creates.
///
/// Idx resolve ([`crate::var_table::VarTable::record_range_batch`]) runs
/// **outside** the TLS ring. Body preads are the machine.
pub fn load_tweak_wave(table: &TxTable, fks: &[Fk]) -> Result<TweakWave, StoreError> {
    if fks.is_empty() {
        return Ok(TweakWave {
            txs: Vec::new(),
            parents: U64Map::default(),
        });
    }

    let txout_ranges = table.body.record_range_batch(fks)?;
    let mut txs: Vec<LoadedTweakTx> = Vec::with_capacity(fks.len());
    for &fk in fks {
        let txid = table.body_txid(fk).unwrap_or([0u8; 32]);
        txs.push(LoadedTweakTx {
            fk,
            rec: empty_rec(txid),
            outs: Vec::new(),
            need_inwit: false,
            inputs: None,
        });
    }
    let mut txout_jobs = jobs_from_ranges(&txout_ranges, None);
    run_stage(
        table.body.body_read_fd(),
        table.body.body_file_path(),
        uring_session::KIND_SP_TXOUT,
        &mut txout_jobs,
    )?;

    let mut wave_outs: U64Map<Vec<OutputRecord>> = U64Map::default();
    for (i, job) in txout_jobs.iter().enumerate() {
        if job.buf.is_empty() {
            continue;
        }
        let (mut rec, outs, _) =
            decode_packed_tx_outs_with_spender_rels_secret(&job.buf, Some(&table.secret))?;
        rec.txid = txs[i].rec.txid;
        txs[i].need_inwit = outs.iter().any(|o| is_p2tr(&o.script));
        wave_outs.insert(txs[i].fk.0, outs.clone());
        txs[i].outs = outs;
        txs[i].rec = rec;
    }

    let p2tr_i: Vec<usize> = txs
        .iter()
        .enumerate()
        .filter(|(_, t)| t.need_inwit)
        .map(|(i, _)| i)
        .collect();
    if !p2tr_i.is_empty() {
        let inwit_fks: Vec<Fk> = p2tr_i.iter().map(|&i| txs[i].fk).collect();
        let inwit_ranges = table.inwit.record_range_batch(&inwit_fks)?;
        let mut inwit_jobs = jobs_from_ranges(&inwit_ranges, None);
        run_stage(
            table.inwit.body_read_fd(),
            table.inwit.body_file_path(),
            uring_session::KIND_SP_INWIT,
            &mut inwit_jobs,
        )?;
        for (j, &ti) in p2tr_i.iter().enumerate() {
            if inwit_jobs[j].buf.is_empty() {
                continue;
            }
            let ins = decode_inwit_secret(
                &inwit_jobs[j].buf,
                txs[ti].rec.input_count,
                Some(&table.secret),
            )?;
            txs[ti].inputs = Some(ins);
        }
    }

    let mut missing: Vec<Fk> = Vec::new();
    for t in &txs {
        let Some(ins) = t.inputs.as_ref() else {
            continue;
        };
        for inp in ins {
            if inp.is_coinbase() {
                continue;
            }
            if wave_outs.contains_key(&inp.create_fk.0) {
                continue;
            }
            missing.push(inp.create_fk);
        }
    }
    missing.sort_by_key(|f| f.0);
    missing.dedup();

    let mut parents: U64Map<([u8; 32], Vec<OutputRecord>)> = U64Map::default();
    if !missing.is_empty() {
        let pr = table.body.record_range_batch(&missing)?;
        let mut jobs = jobs_from_ranges(&pr, None);
        run_stage(
            table.body.body_read_fd(),
            table.body.body_file_path(),
            uring_session::KIND_SP_PARENT,
            &mut jobs,
        )?;
        for (i, fk) in missing.iter().enumerate() {
            if jobs[i].buf.is_empty() {
                continue;
            }
            let (mut rec, outs, _) =
                decode_packed_tx_outs_with_spender_rels_secret(&jobs[i].buf, Some(&table.secret))?;
            rec.txid = table.body_txid(*fk).unwrap_or(rec.txid);
            parents.insert(fk.0, (rec.txid, outs));
        }
    }

    Ok(TweakWave { txs, parents })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_head::HeadLayout;
    use crate::tx_table::TxTable;
    use rbitcoin_primitives::Fk;

    fn tmp_dir() -> crate::testutil::TempDir {
        crate::testutil::TempDir::labeled("sp-uring").unwrap()
    }

    fn tiny_table(dir: &std::path::Path) -> TxTable {
        TxTable::create_with_head_layout(
            dir,
            HeadLayout::new(crate::address_head::TINY_BITS).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn filter_marks_only_p2tr_need_inwit() {
        let dir = tmp_dir();
        let t = tiny_table(&dir);
        let p2tr = {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[3u8; 32]);
            s
        };
        let op_true = vec![0x51];
        let a = TxRecord {
            txid: [1u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let b = TxRecord {
            txid: [2u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let fks = t
            .put_full_batch_indexed(
                &[
                    (a, ins.clone(), vec![OutputRecord::unspent(1, op_true)]),
                    (b, ins, vec![OutputRecord::unspent(2, p2tr)]),
                ],
                true,
            )
            .unwrap();
        let wave = load_tweak_wave(&t, &fks).unwrap();
        assert_eq!(wave.txs.len(), 2);
        assert!(!wave.txs[0].need_inwit, "OP_TRUE must not load inwit");
        assert!(wave.txs[0].inputs.is_none());
        assert!(wave.txs[1].need_inwit, "P2TR must need inwit");
        assert!(wave.txs[1].inputs.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
