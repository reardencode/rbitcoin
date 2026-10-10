//! Plan Shape A head resolve: **txids in → denserels out** (or fk+range short-circuit).
//!
//! Probe+identity (uring when available):
//! 1. **Open** — every unsealed OA (insert tail + in-flight seal), one batch
//! 2. **Sealed** — newest segment first. Fuse + one MPHF (or sealed OA), then
//!    identity, then retire fence-connected keys before the next segment.
//!
//! Each identity: at most two page-grouped `txid.body` shots (first four cands,
//! then the rest if still unfinished) → newest-first walk (`body==want`,
//! fence-connected if a fence is on). Unconnected identity does **not** skip
//! later segments or shot B. TipOnly strips unconnected winners at the end.
//! **One** `create.loc` batch runs **after** the sealed walk, on FdOnly /
//! standalone bulk — not on the held probe ring.
//!
//! [`resolve_fk_and_range_batch`] is the **stamp short-circuit**: stops after
//! loc, returns `(fk, body_range)` so prep denserels-loads by offset.
//!
//! **IO shape:** probe may use one TLS [`UringSession`]; sidefile ID is
//! page-grouped bulk pread (one read per OS page of `txid.body`). Nested TLS
//! uring remains a hard error.
//!
//! Backend: global `RBITCOIN_IO` (`uring` \| `pool` \| `pread`).

use crate::error::StoreError;
use crate::height_fence::HeightFence;
use crate::io_backend::{self, ReadIoBackend};
use crate::segmented_head::HeadProbeWave;
use crate::tx_table::TxTable;
use crate::txid_body::TxidBody;
use crate::uring_session::{self, UringSession};
use rbitcoin_primitives::Fk;
use std::time::Instant;

/// Stamp short-circuit: **txids → (fk, body_range)** via one TLS uring machine.
///
/// Probe (head pages) + identity on the held ring, then **one** loc batch after
/// TLS drops. Prep denserels loads by offset (skip re-idx).
pub fn resolve_fk_and_range_batch(
    table: &TxTable,
    txids: &[[u8; 32]],
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    resolve_fk_and_range_batch_opts(table, txids, None, false)
}

/// Like [`resolve_fk_and_range_batch`], but prefer a **connected** Class A row
/// (height fence hit). An unconnected hit does **not** skip older segments.
///
/// `tip_only`: result is connected-or-None (confirm). Otherwise connected else
/// newest unconnected (RPC).
pub fn resolve_fk_and_range_batch_with_tip(
    table: &TxTable,
    heights: &HeightFence,
    txids: &[[u8; 32]],
    tip_only: bool,
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    resolve_fk_and_range_batch_opts(table, txids, Some(heights), tip_only)
}

fn note_first_leftover_miss(
    tip_only: bool,
    picked: &[Option<Fk>],
    n_cands: &[usize],
    had_id: &[bool],
) {
    crate::head_resolve_stats::clear_leftover_miss();
    if !tip_only {
        return;
    }
    for i in 0..picked.len() {
        if picked[i].is_some() {
            continue;
        }
        let on = crate::head_resolve_pick::classify_leftover_miss(n_cands[i], had_id[i]);
        crate::head_resolve_stats::note_leftover_miss(on, n_cands[i] as u64);
        return;
    }
}

fn hex_bytes(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

fn format_leftover_probe_diag(d: &crate::head_resolve_stats::LeftoverProbeDiag) -> String {
    let age = d
        .sealed_age
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".into());
    let mut s = format!(
        "leftover probe diag txid={} mix={} page_base={} bits={} file_id={} first_fk={} age={} \
         hit_empty={} depth_end={} empty_local={} occ={} hop2eq={} ncand={}",
        hex_bytes(&d.txid),
        hex_bytes(&d.mixed_prefix),
        d.page_base,
        d.bits,
        d.file_id,
        d.first_fk,
        age,
        u8::from(d.hit_empty),
        d.depth_end,
        d.empty_local,
        d.page_occupied,
        u8::from(d.hop_equal_second),
        d.cands.len(),
    );
    for c in &d.cands {
        s.push_str(&format!(
            " | d={} loc={} rel={} abs={} body={} match={}",
            c.depth,
            c.local,
            c.rel,
            c.abs_fk,
            hex_bytes(&c.body_prefix),
            u8::from(c.body_match),
        ));
    }
    s
}

/// Hop + cand dump for a leftover miss only (not lookup / BQ-ahead TipOnly).
pub(crate) fn diagnose_and_note_leftover_probe(table: &TxTable, txid: &[u8; 32]) {
    match diagnose_txid_probe(table, txid) {
        Ok(d) => {
            rbitcoin_log::warn!("store: {}", format_leftover_probe_diag(&d));
            crate::head_resolve_stats::note_leftover_probe_diag(d);
        }
        Err(e) => {
            rbitcoin_log::warn!("store: leftover probe diag failed: {e}");
        }
    }
}

fn diagnose_txid_probe(
    table: &TxTable,
    txid: &[u8; 32],
) -> Result<crate::head_resolve_stats::LeftoverProbeDiag, StoreError> {
    use crate::address_head::{h1_in_page, h2_in_page, page_base_for_txid, PAGE_SLOTS};
    use crate::head_resolve_stats::{LeftoverProbeCand, LeftoverProbeDiag};

    let mixed = table.secret.mix_txid(txid);
    let bits = table.head.bits();
    let page_base = page_base_for_txid(&mixed, bits);
    let first_fks = table.head.first_fks_snapshot();
    let (file_id, first_fk, hop) = table.head.leftover_open_hop(&mixed)?;
    let abs_cands = table.head.probe_candidates(&mixed)?;
    let side = table.txid_sidefile();
    let mask = if bits <= crate::address_head::PAGE_SLOT_BITS {
        (1u64 << bits) - 1
    } else {
        PAGE_SLOTS - 1
    };
    let h1 = h1_in_page(&mixed, bits);
    let h2 = h2_in_page(&mixed, bits);
    let mut rel_meta = std::collections::HashMap::new();
    for &(d, rel) in hop.scan.cands.iter() {
        let local = h1.wrapping_add(u64::from(d).wrapping_mul(h2)) & mask;
        rel_meta.insert(rel, (d, local));
    }
    let mut cands = Vec::with_capacity(abs_cands.len());
    for fk in abs_cands {
        let Some(id) = fk.get() else {
            continue;
        };
        let rel = if id >= first_fk { id - first_fk + 1 } else { 0 };
        let (depth, local) = rel_meta.get(&rel).copied().unwrap_or((u32::MAX, 0));
        let body = side.get_read_at(fk).unwrap_or_default();
        let mut body_prefix = [0u8; 8];
        body_prefix.copy_from_slice(&body[..8]);
        cands.push(LeftoverProbeCand {
            depth,
            local,
            rel,
            abs_fk: id,
            body_prefix,
            body_match: body == *txid,
        });
    }
    let sealed_age = crate::head_resolve_stats::sealed_age_for_fk(&first_fks, first_fk);
    let mut mixed_prefix = [0u8; 8];
    mixed_prefix.copy_from_slice(&mixed[..8]);
    Ok(LeftoverProbeDiag {
        txid: *txid,
        mixed_prefix,
        page_base,
        bits,
        file_id,
        first_fk,
        sealed_age,
        hit_empty: hop.scan.hit_empty,
        depth_end: hop.scan.depth_end,
        empty_local: hop.scan.empty_local,
        page_occupied: hop.occupied,
        hop_equal_second: hop.hop_equal_second,
        cands,
    })
}

fn resolve_fk_and_range_batch_opts(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    if txids.is_empty() {
        crate::head_resolve_stats::clear_leftover_miss();
        return Ok(Vec::new());
    }
    match io_backend::read_io_backend() {
        ReadIoBackend::Uring => map_uring_resolve(
            resolve_fk_and_range_uring(table, txids, heights, tip_only),
            || resolve_fk_and_range_pread(table, txids, heights, tip_only),
        ),
        ReadIoBackend::Pread => resolve_fk_and_range_pread(table, txids, heights, tip_only),
    }
}

/// Fallback to pread only when the ring cannot be opened. Harvest invariants
/// (`Corrupt` / `Io` from a live machine) must not be swallowed.
fn map_uring_resolve<T>(
    uring: Result<T, StoreError>,
    pread: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    match uring {
        Ok(v) => Ok(v),
        Err(e) if is_uring_unavailable(&e) => pread(),
        Err(e) => Err(e),
    }
}

fn is_uring_unavailable(err: &StoreError) -> bool {
    match err {
        StoreError::Unavailable | StoreError::Corrupt("io_uring is Linux-only") => true,
        StoreError::Io { path, .. } if path.as_os_str() == "io_uring" => true,
        _ => false,
    }
}

fn add_wave_cands(n_cands: &mut [usize], cands: &[Vec<Fk>]) -> u64 {
    let mut n = 0u64;
    for (i, c) in cands.iter().enumerate() {
        n_cands[i] = n_cands[i].saturating_add(c.len());
        n = n.saturating_add(c.len() as u64);
    }
    n
}

struct IdentityHits {
    picked: Vec<Option<Fk>>,
}

fn resolve_identity_core(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
    session: Option<&mut UringSession>,
) -> Result<IdentityHits, StoreError> {
    crate::head_resolve_stats::add_keys(txids.len() as u64);

    let mixed: Vec<[u8; 32]> = txids.iter().map(|t| table.secret.mix_txid(t)).collect();
    let side = table.txid_sidefile();
    let first_fks = table.head.first_fks_snapshot();
    let mut local_age = [0u64; crate::head_resolve_stats::AGE_CAP];
    let mut picked: Vec<Option<Fk>> = vec![None; txids.len()];
    let mut connected = vec![false; txids.len()];
    let mut n_cands = vec![0usize; txids.len()];
    let mut had_id = vec![false; txids.len()];
    let mut body_lookups = 0u64;
    let mut miss_peeks = 0u64;
    let mut id_ns = 0u64;
    let mut probe_ns = 0u64;
    let mut cands_total = 0u64;
    let mut ctx = crate::IoCtx::from_opt(session);

    let t_probe = Instant::now();
    let open =
        table
            .head
            .probe_candidates_batch_wave(&mixed, HeadProbeWave::Open, None, &mut ctx)?;
    probe_ns = probe_ns.saturating_add(t_probe.elapsed().as_nanos() as u64);
    cands_total = cands_total.saturating_add(add_wave_cands(&mut n_cands, &open));
    id_idx_wave(
        txids,
        &open,
        side,
        &mut picked,
        &mut connected,
        heights,
        &mut body_lookups,
        &mut miss_peeks,
        &mut id_ns,
        &first_fks,
        &mut local_age,
        &mut ctx,
        &mut had_id,
    )?;

    if any_unfinished(&picked, &connected, heights) {
        let n_segs = table.head.segment_count();
        let mut active = unfinished_mask(&picked, &connected, heights);
        for si in (0..n_segs).rev() {
            if !active.iter().any(|on| *on) {
                break;
            }
            let t_probe = Instant::now();
            let cands = table
                .head
                .probe_sealed_segment(&mixed, si, Some(&active), &mut ctx)?;
            probe_ns = probe_ns.saturating_add(t_probe.elapsed().as_nanos() as u64);
            if cands.iter().all(|c| c.is_empty()) {
                continue;
            }
            cands_total = cands_total.saturating_add(add_wave_cands(&mut n_cands, &cands));
            id_idx_wave(
                txids,
                &cands,
                side,
                &mut picked,
                &mut connected,
                heights,
                &mut body_lookups,
                &mut miss_peeks,
                &mut id_ns,
                &first_fks,
                &mut local_age,
                &mut ctx,
                &mut had_id,
            )?;
            for (i, on) in active.iter_mut().enumerate() {
                *on = !key_finished(i, &picked, &connected, heights);
            }
        }
    }

    if tip_only && heights.is_some() {
        for (i, w) in picked.iter_mut().enumerate() {
            if !connected[i] {
                *w = None;
            }
        }
    }
    note_first_leftover_miss(tip_only, &picked, &n_cands, &had_id);

    crate::head_resolve_stats::add_probe(probe_ns);
    crate::head_resolve_stats::add_cands(cands_total);
    crate::head_resolve_stats::add_body(id_ns);
    crate::head_resolve_stats::add_body_lookups(body_lookups);
    crate::head_resolve_stats::add_miss_peeks(miss_peeks);
    crate::head_resolve_stats::add_hit_ages(&local_age);

    Ok(IdentityHits { picked })
}

fn resolve_fk_and_range_pread(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    let ident = resolve_identity_core(table, txids, heights, tip_only, None)?;
    attach_loc_to_identity(table, txids, ident)
}

fn attach_loc_to_identity(
    table: &TxTable,
    txids: &[[u8; 32]],
    ident: IdentityHits,
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    let IdentityHits { picked } = ident;
    let t_idx = Instant::now();
    let mut need: Vec<Fk> = Vec::new();
    let mut slots: Vec<usize> = Vec::new();
    for (i, fk) in picked.iter().enumerate() {
        if let Some(fk) = *fk {
            need.push(fk);
            slots.push(i);
        }
    }
    let ranges = table.create_loc.range_batch(&need)?;
    crate::head_resolve_stats::add_idx(t_idx.elapsed().as_nanos() as u64);
    let mut winner: Vec<Option<(Fk, crate::create_loc::CreateLocPair)>> = vec![None; picked.len()];
    for (slot, (fk, range)) in slots.into_iter().zip(need.into_iter().zip(ranges)) {
        match range {
            Some(pair) => winner[slot] = Some((fk, pair)),
            None => {
                crate::uring_session::note_uring_invariant(
                    crate::uring_session::UringInvariant::IdxRangeMissing,
                );
                return Err(StoreError::Corrupt(
                    "invariant: loc range missing after identity",
                ));
            }
        }
    }
    Ok(txids
        .iter()
        .enumerate()
        .map(|(i, t)| (*t, winner[i]))
        .collect())
}

/// Connected if a height fence is set, else any winner.
fn key_finished(
    ki: usize,
    picked: &[Option<Fk>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> bool {
    if heights.is_some() {
        connected[ki]
    } else {
        picked[ki].is_some()
    }
}

fn any_unfinished(
    picked: &[Option<Fk>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> bool {
    (0..picked.len()).any(|i| !key_finished(i, picked, connected, heights))
}

fn unfinished_mask(
    picked: &[Option<Fk>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> Vec<bool> {
    (0..picked.len())
        .map(|i| !key_finished(i, picked, connected, heights))
        .collect()
}

#[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
/// Sidefile ID (at most two page-grouped shots) then BIP30 match.
///
/// Shot A is the first four cands of unfinished keys; shot B is the rest only
/// when the key is still unfinished. A fence-connected win skips shot B; an
/// unconnected body match does not. Loc fill is **one** batch after the
/// sealed walk (`attach_loc_to_identity`), never on this held probe ring.
///
/// When `ctx` is held, identity preads ride that **already-held** plan ring.
/// When none, libc pread for ID.
fn id_idx_wave(
    txids: &[[u8; 32]],
    cands_by_key: &[Vec<Fk>],
    side: &TxidBody,
    picked: &mut [Option<Fk>],
    connected: &mut [bool],
    heights: Option<&HeightFence>,
    body_lookups: &mut u64,
    miss_peeks: &mut u64,
    id_ns: &mut u64,
    first_fks: &[u64],
    local_age: &mut [u64; crate::head_resolve_stats::AGE_CAP],
    ctx: &mut crate::IoCtx<'_>,
    had_id: &mut [bool],
) -> Result<(), StoreError> {
    use crate::head_resolve_pick::{next_id_shot, walk_id_prefix, ID_FILL_CHUNK};
    use crate::int_map::{U64Map, U64Set};

    let n = cands_by_key.len();
    let mut filled = vec![0usize; n];
    let mut skip = vec![false; n];
    let mut started = vec![false; n];
    let mut key_miss = vec![0u64; n];
    for ki in 0..n {
        let done = key_finished(ki, picked, connected, heights);
        skip[ki] = done;
        started[ki] = !done;
    }
    let mut id_map: U64Map<[u8; 32]> = U64Map::default();

    for take in [ID_FILL_CHUNK, usize::MAX] {
        let shot = next_id_shot(cands_by_key, &filled, &skip, take);
        let mut need: Vec<Fk> = Vec::new();
        {
            let mut seen = U64Set::default();
            for fk in shot {
                let Some(id) = fk.get() else {
                    continue;
                };
                if id_map.contains_key(&id) {
                    continue;
                }
                if seen.insert(id) {
                    need.push(fk);
                }
            }
        }
        if !need.is_empty() {
            let t_id = Instant::now();
            let (more, _pages) = side.get_many_page_grouped_ctx(&need, ctx)?;
            *id_ns = id_ns.saturating_add(t_id.elapsed().as_nanos() as u64);
            *body_lookups = body_lookups.saturating_add(more.len() as u64);
            id_map.extend(more);
        }
        for ki in 0..n {
            if skip[ki] {
                continue;
            }
            filled[ki] = filled[ki].saturating_add(take).min(cands_by_key[ki].len());
        }
        for ki in 0..n {
            if skip[ki] {
                continue;
            }
            let cands = &cands_by_key[ki];
            let nfill = filled[ki];
            // A prior segment may already hold an unconnected body. Do not
            // replace it unless this prefix connects, or this is the last
            // cand and nothing is picked yet.
            let fallback = heights.is_some() && nfill >= cands.len() && picked[ki].is_none();
            let walked = walk_id_prefix(cands, nfill, &txids[ki], &id_map, heights, fallback);
            if walked.had_body {
                had_id[ki] = true;
            }
            key_miss[ki] = walked.miss;
            if let Some((fk, rank)) = walked.winner {
                crate::head_resolve_stats::add_hit_rank(rank);
                note_identity_pick(ki, fk, picked, connected, heights, first_fks, local_age);
                skip[ki] = true;
            }
        }
    }

    for ki in 0..n {
        if !started[ki] {
            continue;
        }
        *miss_peeks = miss_peeks.saturating_add(key_miss[ki]);
    }
    Ok(())
}

fn note_identity_pick(
    ki: usize,
    fk: Fk,
    picked: &mut [Option<Fk>],
    connected: &mut [bool],
    heights: Option<&HeightFence>,
    first_fks: &[u64],
    local_age: &mut [u64; crate::head_resolve_stats::AGE_CAP],
) {
    picked[ki] = Some(fk);
    if heights.is_some_and(|h| h.height_of(fk).is_some()) {
        connected[ki] = true;
    }
    crate::head_resolve_stats::note_local_hit_age(local_age, first_fks, fk.0);
}

fn resolve_fk_and_range_uring(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
    let ident = uring_session::with_thread_local(uring_session::DEFAULT_ENTRIES, |session| {
        resolve_identity_core(table, txids, heights, tip_only, Some(session))
    })??;
    attach_loc_to_identity(table, txids, ident)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(name: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("rbitcoin-head-res-{name}-{id}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn seed_table(n: u8) -> (PathBuf, TxTable, Vec<[u8; 32]>) {
        let dir = tmp("seed");
        let t = TxTable::create_tiny(&dir).unwrap();
        let mut items = Vec::new();
        let mut txids = Vec::new();
        for i in 0..n {
            let mut tid = [0u8; 32];
            tid[0] = i;
            tid[1] = 0xa5;
            tid[2] = 0x5a;
            txids.push(tid);
            let tx = TxRecord {
                txid: tid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let script: Vec<u8> = (0..((i as usize % 17) + 1)).map(|b| b as u8).collect();
            items.push((
                tx,
                vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
                vec![OutputRecord::unspent(1000 + i as i64, script)],
            ));
        }
        let _fks = t.put_full_batch_indexed(&items, true).unwrap();
        (dir, t, txids)
    }

    /// `n` creates (1-based fks). 4 B idx slots + 16 B file header → ~1020
    /// slots on page 0, so `n ≥ 1100` spans two OS pages.
    fn seed_table_n(n: u32) -> (PathBuf, TxTable, Vec<[u8; 32]>) {
        let dir = tmp("seed-n");
        let t = TxTable::create_tiny(&dir).unwrap();
        let mut items = Vec::new();
        let mut txids = Vec::new();
        for i in 0..n {
            let mut tid = [0u8; 32];
            tid[0] = (i & 0xff) as u8;
            tid[1] = ((i >> 8) & 0xff) as u8;
            tid[2] = 0xa5;
            tid[3] = 0x5a;
            txids.push(tid);
            let tx = TxRecord {
                txid: tid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let script: Vec<u8> = (0..((i as usize % 17) + 1)).map(|b| b as u8).collect();
            items.push((
                tx,
                vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
                vec![OutputRecord::unspent(1000 + i as i64, script)],
            ));
        }
        let _fks = t.put_full_batch_indexed(&items, true).unwrap();
        (dir, t, txids)
    }

    #[test]
    fn resolve_uring_no_swallow_corrupt() {
        let err = StoreError::Corrupt("invariant: io_uring unexpected cqe");
        let mut pread_hits = 0u32;
        match map_uring_resolve(Err(err), || {
            pread_hits += 1;
            Ok(Vec::<crate::tx_table::TxidFkRange>::new())
        }) {
            Err(StoreError::Corrupt("invariant: io_uring unexpected cqe")) => {}
            other => panic!("Corrupt must propagate, got {other:?}"),
        }
        assert_eq!(pread_hits, 0);
    }

    #[test]
    fn resolve_uring_unavailable_falls_back_to_pread() {
        let mut pread_hits = 0u32;
        let out = map_uring_resolve(Err(StoreError::Unavailable), || {
            pread_hits += 1;
            Ok(vec![(
                [0u8; 32],
                None::<(Fk, crate::create_loc::CreateLocPair)>,
            )])
        })
        .unwrap();
        assert_eq!(pread_hits, 1);
        assert_eq!(out.len(), 1);
    }

    /// Uring machine returns same (fk, body_range) as sequential pread path.
    #[test]
    fn uring_fk_and_range_matches_pread() {
        let (dir, t, txids) = seed_table(40);
        let pread = resolve_fk_and_range_pread(&t, &txids, None, false).unwrap();
        // Public entry (uring when available, else pread) must match pure pread.
        let via = resolve_fk_and_range_batch(&t, &txids).unwrap();
        assert_eq!(pread.len(), via.len());
        for (a, b) in pread.iter().zip(via.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1, "txid[0]={}", a.0[0]);
        }
        // Every hit has a non-empty body_range matching record_range.
        for (_tid, row) in &pread {
            if let Some((fk, range)) = row {
                assert_eq!(t.body_range(*fk).unwrap(), range.txout);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After drain, TipOnly hits durable head (write-behind is load-owned).
    #[test]
    fn uring_pending_write_behind_does_not_nest_tls() {
        let dir = tmp("pending-uring");
        let t = TxTable::create_tiny(&dir).unwrap();
        let mut tid = [0u8; 32];
        tid[0] = 0x51;
        let tx = TxRecord {
            txid: tid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let fks = t
            .put_full_batch_indexed(
                &[(
                    tx,
                    vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
                    vec![OutputRecord::unspent(50, vec![0x51])],
                )],
                /*index=*/ false,
            )
            .unwrap();
        t.head_note_pending(&[(tid, fks[0])]);
        t.head_drain_pending().unwrap();
        let via = resolve_fk_and_range_batch(&t, &[tid]).unwrap();
        assert_eq!(via.len(), 1);
        let (got_tid, row) = &via[0];
        assert_eq!(*got_tid, tid);
        let (fk, range) = row.expect("drained head must stamp fk+range");
        assert_eq!(fk, fks[0]);
        assert_eq!(t.body_range(fk).unwrap(), range.txout);
        assert!(range.txout.1 > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Single-segment store: every winner is sealed_age 0 (open/tip).
    ///
    /// Multi-age mapping is covered by `head_resolve_stats::sealed_age_for_fk_*`.
    /// Global AGE_HIT atomics race parallel tests, so we pin mapping on winners
    /// via `first_fks` and only require the process counters moved for age 0.
    #[test]
    fn resolve_records_winner_age_open_segment() {
        let _ = crate::head_resolve_stats::sample_and_reset();
        let (dir, t, txids) = seed_table(16);
        assert_eq!(
            t.head.segment_count(),
            1,
            "unexpected segs={}",
            t.head.segment_count()
        );
        let first = t.head.first_fks_snapshot();
        assert_eq!(first, vec![1]);
        let got = resolve_fk_and_range_batch(&t, &txids).unwrap();
        let hits = got.iter().filter(|(_, r)| r.is_some()).count() as u64;
        assert_eq!(hits, txids.len() as u64);
        for (_tid, row) in &got {
            if let Some((fk, _)) = row {
                assert_eq!(
                    crate::head_resolve_stats::sealed_age_for_fk(&first, fk.0),
                    Some(0),
                    "fk={}",
                    fk.0
                );
            }
        }
        let s = crate::head_resolve_stats::sample_and_reset();
        // Our hits are age 0; concurrent resolve tests may add more age-0 counts.
        assert!(
            s.age_hit[0] >= hits,
            "age0={} hits={hits} age_hit={:?}",
            s.age_hit[0],
            &s.age_hit[..8]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Older fence-connected create wins over a newer unconnected duplicate,
    /// including when they sit in different sealed segments. TipOnly must not
    /// return None after seeing only the newer body.
    #[test]
    fn tip_fence_keeps_older_connected_across_sealed_segments() {
        use crate::address_head::HeadLayout;
        use crate::height_fence::FenceRun;
        let dir = tmp("fence-across-segs");
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        let n = 204u32.saturating_mul(6);
        let mut items = Vec::new();
        let mut txids = Vec::new();
        for i in 0..n {
            let mut tid = [0u8; 32];
            tid[0..4].copy_from_slice(&i.to_le_bytes());
            tid[8] = 0xa5;
            txids.push(tid);
            items.push((
                TxRecord {
                    txid: tid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
                vec![OutputRecord::unspent(1, vec![0x51])],
            ));
        }
        t.put_full_batch_indexed(&items, true).unwrap();
        let dup_tid = txids[0];
        let dup_fk = t
            .put_full_batch_indexed(
                &[(
                    TxRecord {
                        txid: dup_tid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    vec![InputRecord::coinbase(u32::MAX, vec![0x22], vec![])],
                    vec![OutputRecord::unspent(1, vec![0x52])],
                )],
                true,
            )
            .unwrap()[0];
        t.flush_head().unwrap();
        let first = t.head.first_fks_snapshot();
        let oldest = crate::head_resolve_stats::sealed_age_for_fk(&first, 1).unwrap();
        let newest_fk = Fk(u64::from(n));
        let age_new = crate::head_resolve_stats::sealed_age_for_fk(&first, newest_fk.0).unwrap();
        assert!(
            oldest > age_new && age_new >= 1 && t.head.sealed_segment_count() >= 4,
            "oldest age={oldest} newest age={age_new} sealed={}",
            t.head.sealed_segment_count()
        );
        let age_dup = crate::head_resolve_stats::sealed_age_for_fk(&first, dup_fk.0).unwrap();
        assert_eq!(
            age_dup, 0,
            "duplicate must land in the open tail, fk={}",
            dup_fk.0
        );
        assert!(dup_fk.0 > newest_fk.0);
        let fence = HeightFence::from_runs(vec![
            FenceRun {
                first_fk: 1,
                count: 1,
                height: 1,
            },
            FenceRun {
                first_fk: newest_fk.0,
                count: 1,
                height: 2,
            },
        ]);
        assert_eq!(fence.height_of(Fk(1)), Some(1));
        assert_eq!(fence.height_of(newest_fk), Some(2));
        assert_eq!(fence.height_of(dup_fk), None);
        let newest_tid = txids[(n as usize) - 1];
        let tip =
            resolve_fk_and_range_batch_with_tip(&t, &fence, &[dup_tid, newest_tid], true).unwrap();
        assert_eq!(tip[0].1.map(|(f, _)| f), Some(Fk(1)));
        assert_eq!(tip[1].1.map(|(f, _)| f), Some(newest_fk));
        let any = resolve_fk_and_range_batch_with_tip(&t, &fence, &[dup_tid], false).unwrap();
        assert_eq!(any[0].1.map(|(f, _)| f), Some(Fk(1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn miss_and_deepest_create_wins() {
        let dir = tmp("bip30");
        let t = TxTable::create_tiny(&dir).unwrap();
        let txid = [0xcd; 32];
        let mk = |hint: u8| {
            (
                TxRecord {
                    txid,
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                vec![InputRecord {
                    prev_txid: [0u8; 32],
                    create_fk: Fk::NULL,
                    prev_index: u32::MAX,
                    sequence: u32::MAX,
                    script_sig: vec![hint],
                    witness: vec![],
                }],
                vec![OutputRecord::unspent(1, vec![0x51])],
            )
        };
        let _fk1 = t.put_full_batch_indexed(&[mk(1)], true).unwrap()[0];
        let fk2 = t.put_full_batch_indexed(&[mk(2)], true).unwrap()[0];
        let got = resolve_fk_and_range_batch(&t, &[txid, [0xff; 32]]).unwrap();
        assert_eq!(got[0].1.map(|(f, _)| f), Some(fk2));
        assert_eq!(got[1].1, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loc_batch_matches_serial_body_range() {
        let (dir, t, txids) = seed_table_n(1100);
        let first = Fk(1);
        let near = Fk(2);
        let far = Fk(1100);
        let batch = t.create_loc.range_batch(&[first, near, far]).unwrap();
        for (fk, got) in [first, near, far].iter().zip(batch.iter()) {
            let exp = t.body_range(*fk).unwrap();
            assert_eq!(got.map(|p| p.txout), Some(exp), "fk={}", fk.0);
        }
        let got = resolve_fk_and_range_pread(&t, &[txids[0], txids[1], txids[1099]], None, false)
            .unwrap();
        assert_eq!(got[0].1, Some((first, batch[0].unwrap())));
        assert_eq!(got[1].1, Some((near, batch[1].unwrap())));
        assert_eq!(got[2].1, Some((far, batch[2].unwrap())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loc_fill_does_not_use_held_probe_session() {
        let (dir, t, txids) = seed_table(4);
        let mut sess = crate::uring_session::UringSession::try_open(32).unwrap_or_else(|_| {
            crate::uring_session::UringSession::try_open_kind(
                crate::uring_session::SessionKind::Pool,
                32,
            )
            .expect("pool")
        });
        sess.poison();
        let got = t
            .create_loc
            .range_batch(&[Fk(1), Fk(2)])
            .expect("standalone loc must not fail-close on a poisoned probe ring");
        assert_eq!(got[0].unwrap().txout, t.body_range(Fk(1)).unwrap());
        assert_eq!(got[1].unwrap().txout, t.body_range(Fk(2)).unwrap());
        match t
            .create_loc
            .range_batch_ctx(&[Fk(1)], &mut crate::IoCtx::held(&mut sess))
        {
            Err(e) => {
                let m = format!("{e}");
                assert!(m.contains("poisoned") || m.contains("io_uring"), "{m}");
            }
            other => panic!("held loc ctx must stay fail-closed, got {other:?}"),
        }
        let via = resolve_fk_and_range_batch(&t, &[txids[0]]).unwrap();
        assert!(via[0].1.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_loc_missing_after_identity_is_corrupt() {
        let (dir, t, txids) = seed_table(2);
        match attach_loc_to_identity(
            &t,
            &[txids[0]],
            IdentityHits {
                picked: vec![Some(Fk(99))],
            },
        ) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("loc range missing after identity"), "{m}");
            }
            other => panic!("expected loc-range Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
