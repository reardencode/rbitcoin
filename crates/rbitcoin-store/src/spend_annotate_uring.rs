//! Completion-driven io_uring RMW for Class A spender-meta annotation.
//!
//! Hot path: known absolute offset of the 8-byte `(flags:u8, spender_field:u56)`
//! in `spent.body`. Machine:
//!
//! 1. Submit pread of 8 B  
//! 2. On read: decide sole / multi / promote / idempotent  
//!    - multi or promote: **inline** [`SpenderTable::append`] (needs read
//!      result; same-outpoint edges are serialized so list order is stable)  
//! 3. Submit pwrite of updated 8 B  
//! 4. On write: free the slot and arm more work  
//!
//! At most one in-flight RMW per absolute offset (reorg double-annotate on the
//! same outpoint is serialized). Falls back to the caller on uring setup failure.

use crate::compact::output_flags;
use crate::error::StoreError;
use crate::io_handle::IoHandle;
use crate::spender_table::SpenderTable;
use crate::tx_table::{decode_spent_slot_v17, encode_spent_slot_v17, OutputRecord, TxTable};
use crate::uring_session::{self, UringSession};
use crate::{U64Map, U64Set};
use rbitcoin_primitives::Fk;
use std::collections::VecDeque;

const META_LEN: usize = OutputRecord::SPENT_SLOT_LEN;
const MAX_SLOTS: usize = 128;

enum Phase {
    Reading,
    Writing,
}

struct Slot {
    edge_i: usize,
    phase: Phase,
    /// Read buffer / write payload (8-byte spent slot).
    buf: [u8; META_LEN],
}

/// Annotate spends at absolute meta offsets via io_uring RMW.
///
/// `edges`: `(abs_off, create_tx_fk, vout, spending_tx_fk)`.
/// Returns edges that could not be annotated here (OOB abs, IO error deferred
/// as cold — empty when all succeed). On hard errors returns `Err`.
pub fn put_spend_batch_by_abs_meta_uring(
    txs: &TxTable,
    spenders: &SpenderTable,
    edges: &[(u64, Fk, u32, Fk)],
) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
    if edges.is_empty() {
        return Ok(Vec::new());
    }
    for &(_, _, _, sfk) in edges {
        if sfk.is_null() {
            return Err(StoreError::InvalidFk);
        }
    }

    let body_fd: IoHandle = txs.spent.body_read_fd();
    let body_path = txs.spent.body_file_path().to_path_buf();
    let body_pub = txs.spent.body_published_len();

    let mut cold: Vec<(Fk, u32, Fk)> = Vec::new();
    let mut work: Vec<(u64, Fk, u32, Fk)> = Vec::with_capacity(edges.len());
    for &(abs, cfk, vout, sfk) in edges {
        if abs.saturating_add(META_LEN as u64) > body_pub {
            cold.push((cfk, vout, sfk));
        } else {
            work.push((abs, cfk, vout, sfk));
        }
    }
    if work.is_empty() {
        return Ok(cold);
    }

    uring_session::with_thread_local(uring_session::DEFAULT_ENTRIES, |session| {
        session.begin_batch()?;
        let epoch = session.epoch();
        let mut pending: VecDeque<usize> = (0..work.len()).collect();
        let mut abs_busy: U64Set = U64Set::default();
        let mut abs_wait: U64Map<VecDeque<usize>> = U64Map::default();

        let mut free_slots: Vec<usize> = (0..MAX_SLOTS).collect();
        let mut slots: Vec<Option<Slot>> = (0..MAX_SLOTS).map(|_| None).collect();
        let mut session = session.drain_guard();
        let mut in_flight = 0usize;

        let arm = |session: &mut UringSession,
                   free_slots: &mut Vec<usize>,
                   slots: &mut [Option<Slot>],
                   pending: &mut VecDeque<usize>,
                   abs_busy: &mut U64Set,
                   abs_wait: &mut U64Map<VecDeque<usize>>,
                   work: &[(u64, Fk, u32, Fk)],
                   in_flight: &mut usize,
                   body_fd: IoHandle|
         -> Result<(), StoreError> {
            while *in_flight < MAX_SLOTS && session.free_sq() > 0 && !free_slots.is_empty() {
                let edge_i = if let Some(ei) = next_ready(pending, abs_busy, abs_wait, work) {
                    ei
                } else {
                    break;
                };
                let abs = work[edge_i].0;
                abs_busy.insert(abs);
                let slot = free_slots.pop().unwrap();
                slots[slot] = Some(Slot {
                    edge_i,
                    phase: Phase::Reading,
                    buf: [0u8; META_LEN],
                });
                {
                    let s = slots[slot].as_mut().unwrap();
                    let ud = uring_session::pack_ud(
                        uring_session::KIND_SPEND_META_READ,
                        epoch,
                        slot as u32,
                    );
                    session.push_pread_flags(body_fd, abs, &mut s.buf, ud, 0)?;
                }
                *in_flight += 1;
            }
            Ok(())
        };

        arm(
            &mut session,
            &mut free_slots,
            &mut slots,
            &mut pending,
            &mut abs_busy,
            &mut abs_wait,
            &work,
            &mut in_flight,
            body_fd,
        )?;
        session.sync_submission();
        let _ = session.submit();

        while in_flight > 0 {
            let mut cqes = session.harvest_ready()?;
            if cqes.is_empty() {
                session.submit_and_wait_one()?;
                cqes = session.harvest_ready()?;
            }

            for (ud, res) in cqes {
                let (kind, _ep, slot) = uring_session::unpack_ud(ud);
                let slot = slot as usize;
                if slot >= slots.len() {
                    return Err(StoreError::Corrupt("spend annotate bad user_data"));
                }
                let mut st = slots[slot]
                    .take()
                    .ok_or(StoreError::Corrupt("spend annotate empty slot"))?;
                let expect = match st.phase {
                    Phase::Reading => uring_session::KIND_SPEND_META_READ,
                    Phase::Writing => uring_session::KIND_SPEND_META_WRITE,
                };
                if kind != expect {
                    return Err(StoreError::Corrupt("spend annotate bad user_data"));
                }
                in_flight = in_flight.saturating_sub(1);
                let edge_i = st.edge_i;
                let (abs, _create_fk, _vout, spend_fk) = work[edge_i];

                match st.phase {
                    Phase::Reading => {
                        if let Err(e) = uring_session::require_full_cqe(res, META_LEN, &body_path) {
                            free_slots.push(slot);
                            abs_busy.remove(&abs);
                            return Err(e);
                        }

                        let (flags0, field) = decode_spent_slot_v17(&st.buf)?;
                        let multi = flags0 & output_flags::MULTI_SPENDER != 0;

                        let (new_multi, new_field, skip_write) = if !multi && field.is_null() {
                            (false, spend_fk, false)
                        } else if !multi && field == spend_fk {
                            (false, field, true)
                        } else if !multi {
                            let e1 = spenders.append(field, Fk::NULL)?;
                            let e2 = spenders.append(spend_fk, e1)?;
                            (true, e2, false)
                        } else {
                            let e = spenders.append(spend_fk, field)?;
                            (true, e, false)
                        };

                        if skip_write {
                            free_slots.push(slot);
                            abs_busy.remove(&abs);
                            if let Some(q) = abs_wait.get_mut(&abs) {
                                if let Some(next_ei) = q.pop_front() {
                                    pending.push_front(next_ei);
                                }
                                if q.is_empty() {
                                    abs_wait.remove(&abs);
                                }
                            }
                            continue;
                        }

                        let new_flags = if new_multi {
                            flags0 | output_flags::MULTI_SPENDER
                        } else {
                            flags0 & !output_flags::MULTI_SPENDER
                        };
                        st.buf = encode_spent_slot_v17(new_flags, new_field)?;
                        st.phase = Phase::Writing;
                        // Keep slot occupied for write buffer stability.
                        slots[slot] = Some(st);
                        {
                            let s = slots[slot].as_mut().unwrap();
                            let ud = uring_session::pack_ud(
                                uring_session::KIND_SPEND_META_WRITE,
                                epoch,
                                slot as u32,
                            );
                            session.push_pwrite_flags(body_fd, abs, &s.buf, ud, 0)?;
                        }
                        in_flight += 1;
                    }
                    Phase::Writing => {
                        if let Err(e) = uring_session::require_full_cqe(res, META_LEN, &body_path) {
                            free_slots.push(slot);
                            abs_busy.remove(&abs);
                            return Err(e);
                        }
                        free_slots.push(slot);
                        abs_busy.remove(&abs);
                        if let Some(q) = abs_wait.get_mut(&abs) {
                            if let Some(next_ei) = q.pop_front() {
                                pending.push_front(next_ei);
                            }
                            if q.is_empty() {
                                abs_wait.remove(&abs);
                            }
                        }
                    }
                }
            }

            arm(
                &mut session,
                &mut free_slots,
                &mut slots,
                &mut pending,
                &mut abs_busy,
                &mut abs_wait,
                &work,
                &mut in_flight,
                body_fd,
            )?;
            session.sync_submission();
            let _ = session.submit();
        }

        while let Some(ei) = pending.pop_front() {
            let (_, cfk, vout, sfk) = work[ei];
            cold.push((cfk, vout, sfk));
        }
        for q in abs_wait.into_values() {
            for ei in q {
                let (_, cfk, vout, sfk) = work[ei];
                cold.push((cfk, vout, sfk));
            }
        }

        Ok(cold)
    })?
}

/// Pick next edge that can start: abs not busy, or from wait queues.
fn next_ready(
    pending: &mut VecDeque<usize>,
    abs_busy: &U64Set,
    abs_wait: &mut U64Map<VecDeque<usize>>,
    work: &[(u64, Fk, u32, Fk)],
) -> Option<usize> {
    while let Some(ei) = pending.pop_front() {
        let abs = work[ei].0;
        if !abs_busy.contains(&abs) {
            return Some(ei);
        }
        abs_wait.entry(abs).or_default().push_back(ei);
    }
    None
}

/// Annotate backend for pure-write path (Class A body never mmap'd).
///
/// Selected via global `RBITCOIN_IO` (see [`crate::io_backend`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendAnnBackend {
    /// Page-RMW via io_uring (pread page, poke 8 B slots, pwrite page).
    Uring,
    /// Page-RMW via libc pread + pwrite (positional, no ring).
    Pwrite,
}

/// Resolve pure-write annotate backend from env hierarchy.
#[inline]
pub fn spend_ann_backend() -> SpendAnnBackend {
    match crate::io_backend::write_io_backend() {
        crate::io_backend::WriteIoBackend::Uring => SpendAnnBackend::Uring,
        crate::io_backend::WriteIoBackend::Pwrite => SpendAnnBackend::Pwrite,
    }
}

/// Decision from structural snapshot + spend_fk (no body read).
enum AnnotateOp {
    Skip,
    Write([u8; META_LEN]),
}

fn decide_annotate(
    field: Fk,
    flags: u8,
    spend_fk: Fk,
    spenders: &SpenderTable,
) -> Result<AnnotateOp, StoreError> {
    let multi = flags & output_flags::MULTI_SPENDER != 0;
    if !multi && field.is_null() {
        let meta = encode_spent_slot_v17(flags & !output_flags::MULTI_SPENDER, spend_fk)?;
        return Ok(AnnotateOp::Write(meta));
    }
    if !multi && field == spend_fk {
        return Ok(AnnotateOp::Skip);
    }
    if !multi {
        let e1 = spenders.append(field, Fk::NULL)?;
        let e2 = spenders.append(spend_fk, e1)?;
        let meta = encode_spent_slot_v17(flags | output_flags::MULTI_SPENDER, e2)?;
        return Ok(AnnotateOp::Write(meta));
    }
    let e = spenders.append(spend_fk, field)?;
    let meta = encode_spent_slot_v17(flags | output_flags::MULTI_SPENDER, e)?;
    Ok(AnnotateOp::Write(meta))
}

/// One RMW window on `spent.body` (usually one 4 KiB page, clipped to the
/// published range and past the 16-byte file header).
struct SpentPageGroup {
    off: u64,
    len: usize,
    writes: Vec<(u64, Fk, u32, Fk, [u8; META_LEN])>,
}

/// Page span covering the 8-byte slot at `abs` (`[lo, hi)`).
#[inline]
fn spent_meta_page_span(abs: u64) -> (u64, u64) {
    let page = crate::tx_table::BODY_PAGE_SIZE;
    let lo = abs & !(page - 1);
    let last = abs.saturating_add(META_LEN as u64 - 1);
    let hi = (last & !(page - 1)).saturating_add(page);
    (lo, hi)
}

#[inline]
fn clip_spent_page_window(span_lo: u64, span_hi: u64, body_pub: u64) -> Option<(u64, usize)> {
    let off = span_lo.max(crate::file::FILE_HEADER_LEN as u64);
    let end = span_hi.min(body_pub);
    if end <= off {
        return None;
    }
    Some((off, (end - off) as usize))
}

/// Group abs-sorted writes into non-overlapping `spent.body` page spans.
///
/// Same-page slots share one RMW. An 8 B slot that straddles a page boundary
/// extends the span so the next page's writes merge (no overlapping in-flight
/// RMWs). Adjacent pages without a straddle stay separate.
fn group_writes_by_spent_page(
    writes: &[(u64, Fk, u32, Fk, [u8; META_LEN])],
    body_pub: u64,
) -> Vec<SpentPageGroup> {
    let mut groups = Vec::new();
    let mut cur_lo = 0u64;
    let mut cur_hi = 0u64;
    let mut cur: Vec<(u64, Fk, u32, Fk, [u8; META_LEN])> = Vec::new();

    let flush = |groups: &mut Vec<SpentPageGroup>,
                 lo: u64,
                 hi: u64,
                 cur: Vec<(u64, Fk, u32, Fk, [u8; META_LEN])>| {
        if cur.is_empty() {
            return;
        }
        let Some((off, len)) = clip_spent_page_window(lo, hi, body_pub) else {
            return;
        };
        groups.push(SpentPageGroup {
            off,
            len,
            writes: cur,
        });
    };

    for &w in writes {
        let (lo, hi) = spent_meta_page_span(w.0);
        if cur.is_empty() {
            cur_lo = lo;
            cur_hi = hi;
            cur.push(w);
            continue;
        }
        if lo < cur_hi {
            cur_hi = cur_hi.max(hi);
            cur.push(w);
        } else {
            flush(&mut groups, cur_lo, cur_hi, std::mem::take(&mut cur));
            cur_lo = lo;
            cur_hi = hi;
            cur.push(w);
        }
    }
    flush(&mut groups, cur_lo, cur_hi, cur);
    groups
}

fn poke_spent_page(
    buf: &mut [u8],
    off: u64,
    writes: &[(u64, Fk, u32, Fk, [u8; META_LEN])],
) -> Result<(), StoreError> {
    for &(abs, _, _, _, meta) in writes {
        let i = abs.saturating_sub(off) as usize;
        if i.saturating_add(META_LEN) > buf.len() {
            return Err(StoreError::Corrupt(
                "spend annotate poke outside page window",
            ));
        }
        buf[i..i + META_LEN].copy_from_slice(&meta);
    }
    Ok(())
}

fn cold_group_edges(cold: &mut Vec<(Fk, u32, Fk)>, writes: &[(u64, Fk, u32, Fk, [u8; META_LEN])]) {
    for &(_, cfk, vout, sfk, _) in writes {
        cold.push((cfk, vout, sfk));
    }
}

/// Pure-write annotate: `known[i]` is structural `(field, flags)` for `abs_edges[i]`.
///
/// Sorts by abs, then page-RMW on `spent.body` (pread page → poke 8 B slots →
/// pwrite page). Returns OOB edges as cold (caller must hard-fail).
pub fn put_spend_batch_by_abs_meta_known(
    txs: &TxTable,
    spenders: &SpenderTable,
    abs_edges: &[(u64, Fk, u32, Fk)],
    known: &[(Fk, u8)],
    backend: SpendAnnBackend,
) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
    if abs_edges.is_empty() {
        return Ok(Vec::new());
    }
    if abs_edges.len() != known.len() {
        return Err(StoreError::Corrupt("spend annotate known length mismatch"));
    }
    for &(_, _, _, sfk) in abs_edges {
        if sfk.is_null() {
            return Err(StoreError::InvalidFk);
        }
    }

    let mut order: Vec<usize> = (0..abs_edges.len()).collect();
    order.sort_unstable_by_key(|&i| abs_edges[i].0);

    let body_pub = txs.spent.body_published_len();
    let mut cold: Vec<(Fk, u32, Fk)> = Vec::new();
    let mut writes: Vec<(u64, Fk, u32, Fk, [u8; META_LEN])> = Vec::with_capacity(order.len());

    for &i in &order {
        let (abs, cfk, vout, sfk) = abs_edges[i];
        if abs.saturating_add(META_LEN as u64) > body_pub {
            cold.push((cfk, vout, sfk));
            continue;
        }
        let (field, flags) = known[i];
        match decide_annotate(field, flags, sfk, spenders)? {
            AnnotateOp::Skip => {}
            AnnotateOp::Write(meta) => writes.push((abs, cfk, vout, sfk, meta)),
        }
    }

    if writes.is_empty() {
        return Ok(cold);
    }

    match backend {
        SpendAnnBackend::Uring => put_spend_batch_pure_write_uring(txs, &writes, cold),
        SpendAnnBackend::Pwrite => put_spend_batch_pure_write_pwrite(txs, &writes, cold),
    }
}

/// libc page-RMW (pread + pwrite, no ring) for prepared 8-byte metas.
fn put_spend_batch_pure_write_pwrite(
    txs: &TxTable,
    writes: &[(u64, Fk, u32, Fk, [u8; META_LEN])],
    mut cold: Vec<(Fk, u32, Fk)>,
) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
    let body_pub = txs.spent.body_published_len();
    let groups = group_writes_by_spent_page(writes, body_pub);
    for g in &groups {
        let mut buf = vec![0u8; g.len];
        if txs
            .spent
            .read_prefix_at(g.off, g.len as u64, &mut buf)
            .is_err()
        {
            cold_group_edges(&mut cold, &g.writes);
            continue;
        }
        poke_spent_page(&mut buf, g.off, &g.writes)?;
        if txs.spent.write_body_abs(g.off, &buf).is_err() {
            cold_group_edges(&mut cold, &g.writes);
        }
    }
    Ok(cold)
}

/// io_uring page-RMW (pread page → poke → pwrite page) for prepared 8-byte metas.
fn put_spend_batch_pure_write_uring(
    txs: &TxTable,
    writes: &[(u64, Fk, u32, Fk, [u8; META_LEN])],
    cold: Vec<(Fk, u32, Fk)>,
) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
    if writes.is_empty() {
        return Ok(cold);
    }
    let body_pub = txs.spent.body_published_len();
    let groups = group_writes_by_spent_page(writes, body_pub);
    if groups.is_empty() {
        return Ok(cold);
    }
    let body_fd: IoHandle = txs.spent.body_read_fd();
    let body_path = txs.spent.body_file_path().to_path_buf();

    struct PageSlot {
        group_i: usize,
        phase: Phase,
        buf: Vec<u8>,
    }

    let run = uring_session::with_thread_local(uring_session::DEFAULT_ENTRIES, |session| {
        session.begin_batch()?;
        let epoch = session.epoch();
        let mut pending: VecDeque<usize> = (0..groups.len()).collect();
        let nslots = MAX_SLOTS.min(groups.len().max(1));
        let mut free_slots: Vec<usize> = (0..nslots).collect();
        let mut slots: Vec<Option<PageSlot>> = (0..nslots).map(|_| None).collect();
        let mut session = session.drain_guard();
        let mut in_flight = 0usize;
        let mut cold_local = cold.clone();

        let arm = |session: &mut UringSession,
                   free_slots: &mut Vec<usize>,
                   slots: &mut [Option<PageSlot>],
                   pending: &mut VecDeque<usize>,
                   groups: &[SpentPageGroup],
                   in_flight: &mut usize,
                   body_fd: IoHandle|
         -> Result<(), StoreError> {
            while *in_flight < slots.len() && session.free_sq() > 0 && !free_slots.is_empty() {
                let Some(gi) = pending.pop_front() else {
                    break;
                };
                let slot = free_slots.pop().unwrap();
                slots[slot] = Some(PageSlot {
                    group_i: gi,
                    phase: Phase::Reading,
                    buf: vec![0u8; groups[gi].len],
                });
                {
                    let s = slots[slot].as_mut().unwrap();
                    let ud = uring_session::pack_ud(
                        uring_session::KIND_SPEND_PAGE_READ,
                        epoch,
                        slot as u32,
                    );
                    session.push_pread_flags(body_fd, groups[gi].off, &mut s.buf, ud, 0)?;
                }
                *in_flight += 1;
            }
            Ok(())
        };

        arm(
            &mut session,
            &mut free_slots,
            &mut slots,
            &mut pending,
            &groups,
            &mut in_flight,
            body_fd,
        )?;
        session.sync_submission();
        let _ = session.submit();

        while in_flight > 0 {
            let mut cqes = session.harvest_ready()?;
            if cqes.is_empty() {
                session.submit_and_wait_one()?;
                cqes = session.harvest_ready()?;
            }
            for (ud, res) in cqes {
                let (kind, _ep, slot) = uring_session::unpack_ud(ud);
                let slot = slot as usize;
                if slot >= slots.len() {
                    return Err(StoreError::Corrupt("spend pure-write bad user_data"));
                }
                let mut st = slots[slot]
                    .take()
                    .ok_or(StoreError::Corrupt("spend pure-write empty slot"))?;
                let expect = match st.phase {
                    Phase::Reading => uring_session::KIND_SPEND_PAGE_READ,
                    Phase::Writing => uring_session::KIND_SPEND_PAGE_WRITE,
                };
                if kind != expect {
                    return Err(StoreError::Corrupt("spend pure-write bad user_data"));
                }
                in_flight = in_flight.saturating_sub(1);
                let gi = st.group_i;
                match st.phase {
                    Phase::Reading => {
                        let want = st.buf.len();
                        if let Err(e) = uring_session::require_full_cqe(res, want, &body_path) {
                            free_slots.push(slot);
                            return Err(e);
                        }
                        poke_spent_page(&mut st.buf, groups[gi].off, &groups[gi].writes)?;
                        st.phase = Phase::Writing;
                        slots[slot] = Some(st);
                        {
                            let s = slots[slot].as_mut().unwrap();
                            let ud = uring_session::pack_ud(
                                uring_session::KIND_SPEND_PAGE_WRITE,
                                epoch,
                                slot as u32,
                            );
                            session.push_pwrite(body_fd, groups[gi].off, &s.buf, ud)?;
                        }
                        in_flight += 1;
                    }
                    Phase::Writing => {
                        let want = st.buf.len();
                        if let Err(e) = uring_session::require_full_cqe(res, want, &body_path) {
                            free_slots.push(slot);
                            return Err(e);
                        }
                        free_slots.push(slot);
                    }
                }
            }
            arm(
                &mut session,
                &mut free_slots,
                &mut slots,
                &mut pending,
                &groups,
                &mut in_flight,
                body_fd,
            )?;
            session.sync_submission();
            let _ = session.submit();
        }

        while let Some(gi) = pending.pop_front() {
            cold_group_edges(&mut cold_local, &groups[gi].writes);
        }
        Ok(cold_local)
    });
    match run {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => {
            rbitcoin_log::debug!(
                "store: spend annotate pure-write uring error ({e}); pwrite fallback"
            );
            put_spend_batch_pure_write_pwrite(txs, writes, cold)
        }
        Err(e) => {
            rbitcoin_log::debug!(
                "store: spend annotate pure-write uring unavailable ({e}); pwrite fallback"
            );
            put_spend_batch_pure_write_pwrite(txs, writes, cold)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_table() -> (std::path::PathBuf, TxTable, SpenderTable) {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rbitcoin-ann-known-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = TxTable::create(&dir).unwrap();
        let s = SpenderTable::create(&dir).unwrap();
        (dir, t, s)
    }

    fn put_n_outs(t: &TxTable, n_out: u32, txid_byte: u8) -> (Fk, u64, u64) {
        let tx = TxRecord {
            txid: [txid_byte; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: n_out,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![0x01],
            witness: vec![],
        }];
        let outputs = vec![OutputRecord::unspent(50, vec![0x51]); n_out as usize];
        let fk = t
            .put_full_batch_indexed(&[(tx, inputs, outputs)], false)
            .unwrap()[0];
        let (off, len) = t.spent_range_batch(&[fk]).unwrap()[0].unwrap();
        (fk, off, len)
    }

    fn put_one(t: &TxTable) -> (Fk, u64, u64) {
        put_n_outs(t, 1, 0x11)
    }

    #[test]
    fn pure_write_known_null_mmap_and_uring() {
        for backend in [SpendAnnBackend::Uring, SpendAnnBackend::Pwrite] {
            let (dir, t, spenders) = temp_table();
            let (cfk, off, _len) = put_one(&t);
            let abs = crate::tx_table::spent_abs(off, 0);
            let bulk = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
            let (field, flags) = bulk[0].expect("meta");
            assert!(field.is_null());
            let sfk = Fk(99);
            let cold = put_spend_batch_by_abs_meta_known(
                &t,
                &spenders,
                &[(abs, cfk, 0, sfk)],
                &[(field, flags)],
                backend,
            )
            .unwrap();
            assert!(cold.is_empty());
            let bulk2 = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
            let (f2, fl2) = bulk2[0].unwrap();
            assert_eq!(f2, sfk);
            assert_eq!(fl2 & output_flags::MULTI_SPENDER, 0);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Shipped uring spend path must not set RWF_DONTCACHE (`spent.body` is its
    /// own file; evicting those pages does not protect `txout`).
    #[test]
    fn uring_rmw_body_sqe_sets_no_dontcache() {
        if !crate::bulk_io::io_uring_enabled() {
            return;
        }
        let (dir, t, spenders) = temp_table();
        let (cfk, off, len) = put_one(&t);
        let _ = len;
        let abs = crate::tx_table::spent_abs(off, 0);
        let bulk = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
        let (field, flags) = bulk[0].unwrap();
        let _ = uring_session::test_take_last_sqe_rw_flags();
        let cold = put_spend_batch_by_abs_meta_known(
            &t,
            &spenders,
            &[(abs, cfk, 0, Fk(55))],
            &[(field, flags)],
            SpendAnnBackend::Uring,
        )
        .unwrap();
        assert!(cold.is_empty());
        let sqe_flags = uring_session::test_take_last_sqe_rw_flags();
        assert!(
            !sqe_flags.is_empty(),
            "uring spend annotate must push at least one SQE"
        );
        assert!(
            sqe_flags.iter().all(|&f| f == 0),
            "annotate SQEs must not set RWF_DONTCACHE; got {sqe_flags:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shipped RMW machine on the portable pool session (Linux CI pin).
    #[test]
    fn pool_rmw_annotates_sole_spender() {
        crate::uring_session::with_forced_session_kind(
            crate::uring_session::SessionKind::Pool,
            || {
                let (dir, t, spenders) = temp_table();
                let (cfk, off, _len) = put_one(&t);
                let abs = crate::tx_table::spent_abs(off, 0);
                let sfk = Fk(88);
                let cold = put_spend_batch_by_abs_meta_uring(&t, &spenders, &[(abs, cfk, 0, sfk)])
                    .expect("pool rmw");
                assert!(cold.is_empty());
                let bulk = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
                let (field, flags) = bulk[0].unwrap();
                assert_eq!(field, sfk);
                assert_eq!(flags & output_flags::MULTI_SPENDER, 0);
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    #[test]
    fn pure_write_idempotent_skip() {
        let (dir, t, spenders) = temp_table();
        let (cfk, off, len) = put_one(&t);
        let _ = len;
        let abs = crate::tx_table::spent_abs(off, 0);
        let sfk = Fk(77);
        let bulk = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
        let (field, flags) = bulk[0].unwrap();
        put_spend_batch_by_abs_meta_known(
            &t,
            &spenders,
            &[(abs, cfk, 0, sfk)],
            &[(field, flags)],
            SpendAnnBackend::Pwrite,
        )
        .unwrap();
        // Second time with known field==sfk → skip
        put_spend_batch_by_abs_meta_known(
            &t,
            &spenders,
            &[(abs, cfk, 0, sfk)],
            &[(sfk, 0)],
            SpendAnnBackend::Pwrite,
        )
        .unwrap();
        let bulk2 = t.get_spender_meta_at_abs_batch(&[abs]).unwrap();
        assert_eq!(bulk2[0].unwrap().0, sfk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two vouts on one page: both land; a third slot on that page is unchanged.
    #[test]
    fn pure_write_two_vouts_same_page_preserves_neighbor() {
        for backend in [SpendAnnBackend::Uring, SpendAnnBackend::Pwrite] {
            let (dir, t, spenders) = temp_table();
            let (cfk, off, _len) = put_n_outs(&t, 3, 0x22);
            let abs0 = crate::tx_table::spent_abs(off, 0);
            let abs1 = crate::tx_table::spent_abs(off, 1);
            let abs2 = crate::tx_table::spent_abs(off, 2);
            assert_eq!(
                abs0 & !0xfff,
                abs2 & !0xfff,
                "fixture must keep vout 0 and 2 on one 4 KiB page"
            );

            let sentinel = Fk(0x51);
            let known1 = t.get_spender_meta_at_abs_batch(&[abs1]).unwrap()[0].unwrap();
            let cold_s = put_spend_batch_by_abs_meta_known(
                &t,
                &spenders,
                &[(abs1, cfk, 1, sentinel)],
                &[known1],
                backend,
            )
            .unwrap();
            assert!(cold_s.is_empty());

            let known0 = t.get_spender_meta_at_abs_batch(&[abs0]).unwrap()[0].unwrap();
            let known2 = t.get_spender_meta_at_abs_batch(&[abs2]).unwrap()[0].unwrap();
            let mut hdr_before = [0u8; crate::file::FILE_HEADER_LEN];
            t.spent
                .read_prefix_at(0, crate::file::FILE_HEADER_LEN as u64, &mut hdr_before)
                .unwrap();
            let cold = put_spend_batch_by_abs_meta_known(
                &t,
                &spenders,
                &[(abs0, cfk, 0, Fk(10)), (abs2, cfk, 2, Fk(12))],
                &[known0, known2],
                backend,
            )
            .unwrap();
            assert!(cold.is_empty());

            let bulk = t
                .get_spender_meta_at_abs_batch(&[abs0, abs1, abs2])
                .unwrap();
            assert_eq!(bulk[0].unwrap().0, Fk(10));
            assert_eq!(
                bulk[1].unwrap().0,
                sentinel,
                "neighbor slot must be preserved"
            );
            assert_eq!(bulk[2].unwrap().0, Fk(12));

            let mut hdr_after = [0u8; crate::file::FILE_HEADER_LEN];
            t.spent
                .read_prefix_at(0, crate::file::FILE_HEADER_LEN as u64, &mut hdr_after)
                .unwrap();
            assert_eq!(
                hdr_before, hdr_after,
                "page 0 RMW must not rewrite file header"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Vouts whose abs straddle a 4 KiB page both persist.
    #[test]
    fn pure_write_two_pages_both_land() {
        for backend in [SpendAnnBackend::Uring, SpendAnnBackend::Pwrite] {
            let (dir, t, spenders) = temp_table();
            // 512 × 8 B from file offset 16 crosses 4096 (slot 510 starts at 4096).
            let (cfk, off, _len) = put_n_outs(&t, 512, 0x33);
            let abs0 = crate::tx_table::spent_abs(off, 0);
            let abs_last = crate::tx_table::spent_abs(off, 511);
            assert_ne!(
                abs0 & !0xfff,
                abs_last & !0xfff,
                "fixture must straddle a 4 KiB page"
            );
            let k0 = t.get_spender_meta_at_abs_batch(&[abs0]).unwrap()[0].unwrap();
            let k1 = t.get_spender_meta_at_abs_batch(&[abs_last]).unwrap()[0].unwrap();
            let cold = put_spend_batch_by_abs_meta_known(
                &t,
                &spenders,
                &[(abs0, cfk, 0, Fk(1)), (abs_last, cfk, 511, Fk(2))],
                &[k0, k1],
                backend,
            )
            .unwrap();
            assert!(cold.is_empty());
            let bulk = t.get_spender_meta_at_abs_batch(&[abs0, abs_last]).unwrap();
            assert_eq!(bulk[0].unwrap().0, Fk(1));
            assert_eq!(bulk[1].unwrap().0, Fk(2));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Same-page pair is one page-window write, not two 9 B pwrites.
    #[test]
    fn pure_write_same_page_is_one_page_write() {
        if !crate::bulk_io::io_uring_enabled() {
            return;
        }
        let (dir, t, spenders) = temp_table();
        let (cfk, off, _len) = put_n_outs(&t, 3, 0x44);
        let abs0 = crate::tx_table::spent_abs(off, 0);
        let abs2 = crate::tx_table::spent_abs(off, 2);
        let k0 = t.get_spender_meta_at_abs_batch(&[abs0]).unwrap()[0].unwrap();
        let k2 = t.get_spender_meta_at_abs_batch(&[abs2]).unwrap()[0].unwrap();
        let _ = uring_session::test_take_last_sqe_lens();
        let cold = put_spend_batch_by_abs_meta_known(
            &t,
            &spenders,
            &[(abs0, cfk, 0, Fk(3)), (abs2, cfk, 2, Fk(4))],
            &[k0, k2],
            SpendAnnBackend::Uring,
        )
        .unwrap();
        assert!(cold.is_empty());
        let lens = uring_session::test_take_last_sqe_lens();
        assert!(
            !lens.is_empty(),
            "uring spend annotate must push at least one SQE"
        );
        // Page 0 is clipped past the 16 B file header; the write is the published
        // page window (here the whole 3-slot spent record), never one 9 B SQE per vout.
        let writes: Vec<u32> = lens.into_iter().filter(|&n| n != META_LEN as u32).collect();
        assert!(
            writes.iter().any(|&n| n >= 3 * META_LEN as u32),
            "expected a page-window write covering both slots; sqe lens={writes:?} (9 B-only is the old path)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_writes_by_spent_page_merges_same_page() {
        let meta = [1u8; META_LEN];
        let slot = META_LEN as u64;
        let writes = [
            (16u64, Fk(1), 0, Fk(10), meta),
            (16 + 2 * slot, Fk(1), 2, Fk(12), meta),
        ];
        let rec = 3 * slot;
        let g = group_writes_by_spent_page(&writes, 16 + rec);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].off, crate::file::FILE_HEADER_LEN as u64);
        assert_eq!(g[0].len, rec as usize);
        assert_eq!(g[0].writes.len(), 2);
    }

    #[test]
    fn group_writes_by_spent_page_keeps_distinct_pages() {
        let meta = [1u8; META_LEN];
        let writes = [
            (16u64, Fk(1), 0, Fk(10), meta),
            (4096u64 + 16, Fk(2), 0, Fk(12), meta),
        ];
        let g = group_writes_by_spent_page(&writes, 4096 + 16 + META_LEN as u64);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].off, crate::file::FILE_HEADER_LEN as u64);
        assert_eq!(g[1].off, 4096);
    }

    #[test]
    fn group_writes_by_spent_page_merges_straddle() {
        let meta = [1u8; META_LEN];
        let slot = META_LEN as u64;
        // Slot starts 3 bytes before the 4 KiB page end so the RMW straddles.
        let first = 4096u64 - 3;
        let second = first + slot;
        let end = second + slot;
        let writes = [
            (first, Fk(1), 0, Fk(10), meta),
            (second, Fk(1), 1, Fk(11), meta),
        ];
        let g = group_writes_by_spent_page(&writes, end);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].writes.len(), 2);
        assert!(g[0].off <= first);
        assert!(g[0].off + g[0].len as u64 >= end);
    }
}
