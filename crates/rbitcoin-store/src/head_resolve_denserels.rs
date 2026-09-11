//! Plan Shape A head resolve: **txids in → denserels out** (or fk+range short-circuit).
//!
//! Three probe+identity waves (uring when available):
//! 1. **Open** — every unsealed OA (insert tail + in-flight seal)
//! 2. **Sealed-hot** — sealed ages 1..=3 (only keys still unfinished)
//! 3. **Cold** — sealed ages ≥4 (only keys still unfinished)
//!
//! Each wave: probe that slice → at most two page-grouped `txid.body` shots
//! (first four cands, then the rest if still unfinished) → newest-first walk
//! (`body==want`, fence-connected if a fence is on) → one `tx.idx` fill for
//! chosen fks. Unconnected identity does **not** skip later waves or shot B.
//! TipOnly strips unconnected winners at the end.
//!
//! [`resolve_fk_and_range_batch`] is the **stamp short-circuit**: stops after
//! idx, returns `(fk, body_range)` so prep denserels-loads by offset.
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
/// Probe (head pages) → depth-first identity → idx body_range. Prep denserels
/// loads by offset (skip re-idx).
pub fn resolve_fk_and_range_batch(
    table: &TxTable,
    txids: &[[u8; 32]],
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
    resolve_fk_and_range_batch_opts(table, txids, None, false)
}

/// Like [`resolve_fk_and_range_batch`], but prefer a **connected** Class A row
/// (height fence hit). Unconnected hot hits do **not** skip the cold wave.
///
/// `tip_only`: result is connected-or-None (confirm). Otherwise connected else
/// newest unconnected (RPC).
pub fn resolve_fk_and_range_batch_with_tip(
    table: &TxTable,
    heights: &HeightFence,
    txids: &[[u8; 32]],
    tip_only: bool,
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
    resolve_fk_and_range_batch_opts(table, txids, Some(heights), tip_only)
}

fn note_first_leftover_miss(
    tip_only: bool,
    winner: &[Option<(Fk, (u64, u64))>],
    connected: &[bool],
    n_cands: &[usize],
    had_id: &[bool],
) {
    crate::head_resolve_stats::clear_leftover_miss();
    if !tip_only {
        return;
    }
    for i in 0..winner.len() {
        if winner[i].is_some() {
            continue;
        }
        let on =
            crate::head_resolve_pick::classify_leftover_miss(n_cands[i], had_id[i], connected[i]);
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
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
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

fn resolve_fk_and_range_core(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
    session: Option<&mut UringSession>,
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
    crate::head_resolve_stats::add_keys(txids.len() as u64);

    let mixed: Vec<[u8; 32]> = txids.iter().map(|t| table.secret.mix_txid(t)).collect();
    let side = table.txid_sidefile();
    let first_fks = table.head.first_fks_snapshot();
    let mut local_age = [0u64; crate::head_resolve_stats::AGE_CAP];
    let mut winner: Vec<Option<(Fk, (u64, u64))>> = vec![None; txids.len()];
    let mut connected = vec![false; txids.len()];
    let mut n_cands = vec![0usize; txids.len()];
    let mut had_id = vec![false; txids.len()];
    let mut body_lookups = 0u64;
    let mut miss_peeks = 0u64;
    let mut id_ns = 0u64;
    let mut idx_ns = 0u64;
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
        table,
        txids,
        &open,
        side,
        &mut winner,
        &mut connected,
        heights,
        &mut body_lookups,
        &mut miss_peeks,
        &mut id_ns,
        &mut idx_ns,
        &first_fks,
        &mut local_age,
        &mut ctx,
        &mut had_id,
    )?;

    if any_unfinished(&winner, &connected, heights) {
        let active = unfinished_mask(&winner, &connected, heights);
        let t_probe = Instant::now();
        let mid = table.head.probe_candidates_batch_wave(
            &mixed,
            HeadProbeWave::SealedHot,
            Some(&active),
            &mut ctx,
        )?;
        probe_ns = probe_ns.saturating_add(t_probe.elapsed().as_nanos() as u64);
        cands_total = cands_total.saturating_add(add_wave_cands(&mut n_cands, &mid));
        id_idx_wave(
            table,
            txids,
            &mid,
            side,
            &mut winner,
            &mut connected,
            heights,
            &mut body_lookups,
            &mut miss_peeks,
            &mut id_ns,
            &mut idx_ns,
            &first_fks,
            &mut local_age,
            &mut ctx,
            &mut had_id,
        )?;
    }

    if any_unfinished(&winner, &connected, heights) {
        let active = unfinished_mask(&winner, &connected, heights);
        let t_probe = Instant::now();
        let cold = table.head.probe_candidates_batch_wave(
            &mixed,
            HeadProbeWave::Cold,
            Some(&active),
            &mut ctx,
        )?;
        probe_ns = probe_ns.saturating_add(t_probe.elapsed().as_nanos() as u64);
        cands_total = cands_total.saturating_add(add_wave_cands(&mut n_cands, &cold));
        id_idx_wave(
            table,
            txids,
            &cold,
            side,
            &mut winner,
            &mut connected,
            heights,
            &mut body_lookups,
            &mut miss_peeks,
            &mut id_ns,
            &mut idx_ns,
            &first_fks,
            &mut local_age,
            &mut ctx,
            &mut had_id,
        )?;
    }

    if tip_only && heights.is_some() {
        for (i, w) in winner.iter_mut().enumerate() {
            if !connected[i] {
                *w = None;
            }
        }
    }
    note_first_leftover_miss(tip_only, &winner, &connected, &n_cands, &had_id);

    crate::head_resolve_stats::add_probe(probe_ns);
    crate::head_resolve_stats::add_cands(cands_total);
    crate::head_resolve_stats::add_body(id_ns);
    crate::head_resolve_stats::add_idx(idx_ns);
    crate::head_resolve_stats::add_body_lookups(body_lookups);
    crate::head_resolve_stats::add_miss_peeks(miss_peeks);
    crate::head_resolve_stats::add_hit_ages(&local_age);

    Ok(txids
        .iter()
        .enumerate()
        .map(|(i, t)| (*t, winner[i]))
        .collect())
}

fn resolve_fk_and_range_pread(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
    resolve_fk_and_range_core(table, txids, heights, tip_only, None)
}

/// Kind tag for idx-page SQEs on the held plan session (`pack_ud` kind byte).
const UD_KIND_IDX: u8 = crate::uring_session::KIND_IDX;

/// Fill idx page buffers via held session. Poison / leftover / undrained is
/// `Err` — do not libc-fallback on this ring (BDZ g-pages share it).
fn fill_idx_pages(
    sess: &mut UringSession,
    pages: &[crate::tx_idx::IdxPagePlan],
    bufs: &mut [Vec<u8>],
) -> Result<(), StoreError> {
    if pages.is_empty() {
        return Ok(());
    }
    sess.begin_batch()?;
    let epoch = sess.epoch();
    let run = (|| -> Result<(), StoreError> {
        let mut results = vec![i32::MIN; pages.len()];
        let need = pages.len();
        let mut done = 0usize;
        let mut next = 0usize;
        let take_cqes = |sess: &mut UringSession,
                         results: &mut [i32],
                         done: &mut usize|
         -> Result<(), StoreError> {
            let mut cqes = sess.harvest_ready()?;
            if cqes.is_empty() {
                sess.submit_and_wait_one()?;
                cqes = sess.harvest_ready()?;
                if cqes.is_empty() {
                    sess.poison();
                    return Err(StoreError::Corrupt("invariant: io_uring wait timeout"));
                }
            } else {
                sess.submit()?;
            }
            for (ud, res) in cqes {
                let (kind, ep, slot) = crate::uring_session::unpack_ud(ud);
                let slot = slot as usize;
                if kind != UD_KIND_IDX
                    || ep != epoch
                    || slot >= results.len()
                    || results[slot] != i32::MIN
                {
                    sess.poison();
                    return Err(StoreError::Corrupt("invariant: io_uring leftover cqe"));
                }
                results[slot] = res;
                *done += 1;
            }
            Ok(())
        };
        while done < need {
            while next < need && sess.free_sq() > 0 {
                let i = next;
                next += 1;
                let ud = crate::uring_session::pack_ud(UD_KIND_IDX, epoch, i as u32);
                sess.push_pread_flags(pages[i].fd, pages[i].page_off, &mut bufs[i], ud, 0)?;
            }
            sess.sync_submission();
            if sess.in_flight() == 0 {
                break;
            }
            take_cqes(sess, &mut results, &mut done)?;
        }
        for (i, &res) in results.iter().enumerate() {
            if res < 0 || (res as usize) < pages[i].want {
                let page = &pages[i];
                let rc = page.fd.pread(page.page_off, &mut bufs[i][..page.want]);
                if rc < 0 || (rc as usize) < page.want {
                    return Err(StoreError::Corrupt("invariant: idx page fill failed"));
                }
            }
        }
        Ok(())
    })();
    sess.drain_all()?;
    run
}

/// Dedup idx OS pages by `(fd, page_off)` so a wave fills each page once.
fn unique_idx_pages<'a, I>(pages: I) -> Vec<crate::tx_idx::IdxPagePlan>
where
    I: IntoIterator<Item = &'a crate::tx_idx::IdxPagePlan>,
{
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in pages {
        if seen.insert((p.fd, p.page_off)) {
            out.push(p.clone());
        }
    }
    out
}

fn fill_idx_pages_libc(pages: &[crate::tx_idx::IdxPagePlan], bufs: &mut [Vec<u8>]) -> bool {
    for (i, page) in pages.iter().enumerate() {
        let rc = page.fd.pread(page.page_off, &mut bufs[i][..page.want]);
        if rc < 0 || (rc as usize) < page.want {
            return false;
        }
    }
    true
}

/// Body ranges for chosen fks: plan each, fill **unique** idx pages once
/// (held session or libc), decode. No nested TLS uring.
fn body_ranges_batched(
    table: &TxTable,
    fks: &[Fk],
    ctx: &mut crate::IoCtx<'_>,
) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
    if fks.is_empty() {
        return Ok(Vec::new());
    }
    let mut plans: Vec<Option<crate::tx_idx::BodyRangeIdxPlan>> = Vec::with_capacity(fks.len());
    for &fk in fks {
        match table.body.plan_body_range_idx(fk) {
            Ok(p) if !p.pages.is_empty() => plans.push(Some(p)),
            Ok(_) => plans.push(None),
            Err(StoreError::NotFound)
            | Err(StoreError::Corrupt(_))
            | Err(StoreError::InvalidFk) => plans.push(None),
            Err(e) => return Err(e),
        }
    }
    let uniq = unique_idx_pages(plans.iter().flatten().flat_map(|p| p.pages.iter()));
    if uniq.is_empty() {
        return Ok(vec![None; fks.len()]);
    }
    let mut bufs: Vec<Vec<u8>> = uniq.iter().map(|p| vec![0u8; p.want]).collect();
    match ctx.session() {
        Some(sess) => fill_idx_pages(sess, &uniq, &mut bufs)?,
        None => {
            if !fill_idx_pages_libc(&uniq, &mut bufs) {
                return Err(StoreError::Corrupt("invariant: idx page fill failed"));
            }
        }
    }
    let mut page_ix = std::collections::HashMap::with_capacity(uniq.len());
    for (i, p) in uniq.iter().enumerate() {
        page_ix.insert((p.fd, p.page_off), i);
    }
    let mut out = Vec::with_capacity(fks.len());
    for plan in &plans {
        let Some(plan) = plan else {
            out.push(None);
            continue;
        };
        let mut page_refs: Vec<&[u8]> = Vec::with_capacity(plan.pages.len());
        let mut ok = true;
        for p in &plan.pages {
            match page_ix.get(&(p.fd, p.page_off)) {
                Some(&i) => page_refs.push(bufs[i].as_slice()),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            out.push(None);
            continue;
        }
        match plan.decode_range(&page_refs) {
            Ok((off, len)) if len > 0 => out.push(Some((off, len))),
            Ok(_) => out.push(None),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Connected if a height fence is set, else any winner.
fn key_finished(
    ki: usize,
    winner: &[Option<(Fk, (u64, u64))>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> bool {
    if heights.is_some() {
        connected[ki]
    } else {
        winner[ki].is_some()
    }
}

fn any_unfinished(
    winner: &[Option<(Fk, (u64, u64))>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> bool {
    (0..winner.len()).any(|i| !key_finished(i, winner, connected, heights))
}

fn unfinished_mask(
    winner: &[Option<(Fk, (u64, u64))>],
    connected: &[bool],
    heights: Option<&HeightFence>,
) -> Vec<bool> {
    (0..winner.len())
        .map(|i| !key_finished(i, winner, connected, heights))
        .collect()
}

/// Sidefile ID (at most two page-grouped shots) then BIP30 match + batched idx.
///
/// Shot A is the first four cands of unfinished keys; shot B is the rest only
/// when the key is still unfinished. A fence-connected win skips shot B; an
/// unconnected body match does not. Chosen fks share **one** idx-page fill
/// (held session or libc).
///
/// When `ctx` is held, ID + IDX page preads ride that **already-held**
/// plan ring. When none, libc pread for ID and unique idx pages.
fn id_idx_wave(
    table: &TxTable,
    txids: &[[u8; 32]],
    cands_by_key: &[Vec<Fk>],
    side: &TxidBody,
    winner: &mut [Option<(Fk, (u64, u64))>],
    connected: &mut [bool],
    heights: Option<&HeightFence>,
    body_lookups: &mut u64,
    miss_peeks: &mut u64,
    id_ns: &mut u64,
    idx_ns: &mut u64,
    first_fks: &[u64],
    local_age: &mut [u64; crate::head_resolve_stats::AGE_CAP],
    ctx: &mut crate::IoCtx<'_>,
    had_id: &mut [bool],
) -> Result<(), StoreError> {
    use crate::head_resolve_pick::{
        miss_peeks_in_prefix, next_id_shot, pick_winner, ID_FILL_CHUNK,
    };
    use std::collections::HashMap;

    let n = cands_by_key.len();
    let mut filled = vec![0usize; n];
    let mut skip = vec![false; n];
    let mut started = vec![false; n];
    for ki in 0..n {
        let done = key_finished(ki, winner, connected, heights);
        skip[ki] = done;
        started[ki] = !done;
    }
    let mut id_map: HashMap<u64, [u8; 32]> = HashMap::new();
    let mut chosen_kis: Vec<usize> = Vec::new();
    let mut chosen_fks: Vec<Fk> = Vec::new();

    for take in [ID_FILL_CHUNK, usize::MAX] {
        let shot = next_id_shot(cands_by_key, &filled, &skip, take);
        let mut need: Vec<Fk> = Vec::new();
        {
            let mut seen = std::collections::HashSet::new();
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
            if pick_winner(cands, nfill, &txids[ki], &id_map, None).is_some() {
                had_id[ki] = true;
            }
            if let Some((fk, rank)) = pick_winner(cands, nfill, &txids[ki], &id_map, heights) {
                crate::head_resolve_stats::add_hit_rank(rank);
                chosen_kis.push(ki);
                chosen_fks.push(fk);
                skip[ki] = true;
                continue;
            }
            if heights.is_none() || nfill < cands.len() || winner[ki].is_some() {
                continue;
            }
            if let Some((fk, rank)) = pick_winner(cands, nfill, &txids[ki], &id_map, None) {
                crate::head_resolve_stats::add_hit_rank(rank);
                chosen_kis.push(ki);
                chosen_fks.push(fk);
                skip[ki] = true;
            }
        }
    }

    for ki in 0..n {
        if !started[ki] {
            continue;
        }
        *miss_peeks = miss_peeks.saturating_add(miss_peeks_in_prefix(
            &cands_by_key[ki],
            filled[ki],
            &txids[ki],
            &id_map,
        ));
    }
    let t_idx = Instant::now();
    let ranges = body_ranges_batched(table, &chosen_fks, ctx)?;
    record_chosen_idx_ranges(
        &chosen_kis,
        &chosen_fks,
        &ranges,
        winner,
        connected,
        heights,
        first_fks,
        local_age,
    )?;
    *idx_ns = idx_ns.saturating_add(t_idx.elapsed().as_nanos() as u64);
    Ok(())
}

/// Apply idx ranges for identity picks. `connected` is set only when a range
/// exists — never before idx. Missing range after a chosen fk is Corrupt.
fn record_chosen_idx_ranges(
    chosen_kis: &[usize],
    chosen_fks: &[Fk],
    ranges: &[Option<(u64, u64)>],
    winner: &mut [Option<(Fk, (u64, u64))>],
    connected: &mut [bool],
    heights: Option<&HeightFence>,
    first_fks: &[u64],
    local_age: &mut [u64; crate::head_resolve_stats::AGE_CAP],
) -> Result<(), StoreError> {
    for ((&ki, &fk), range) in chosen_kis.iter().zip(chosen_fks.iter()).zip(ranges) {
        match range {
            Some(range) => {
                winner[ki] = Some((fk, *range));
                if heights.is_some_and(|h| h.height_of(fk).is_some()) {
                    connected[ki] = true;
                }
                crate::head_resolve_stats::note_local_hit_age(local_age, first_fks, fk.0);
            }
            None => {
                crate::uring_session::note_uring_invariant(
                    crate::uring_session::UringInvariant::IdxRangeMissing,
                );
                return Err(StoreError::Corrupt(
                    "invariant: idx range missing after identity",
                ));
            }
        }
    }
    Ok(())
}

fn resolve_fk_and_range_uring(
    table: &TxTable,
    txids: &[[u8; 32]],
    heights: Option<&HeightFence>,
    tip_only: bool,
) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
    uring_session::with_thread_local(uring_session::DEFAULT_ENTRIES, |session| {
        resolve_fk_and_range_core(table, txids, heights, tip_only, Some(session))
    })?
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
            Ok(Vec::<([u8; 32], Option<(Fk, (u64, u64))>)>::new())
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
            Ok(vec![([0u8; 32], None::<(Fk, (u64, u64))>)])
        })
        .unwrap();
        assert_eq!(pread_hits, 1);
        assert_eq!(out.len(), 1);
    }

    /// Held-session idx fill must not libc-succeed on a poisoned ring (that
    /// leaves leftover CQEs for BDZ g-pages on the same TLS session).
    #[test]
    fn poisoned_held_idx_fill_fails_closed() {
        let (dir, t, _txids) = seed_table(8);
        let mut session = crate::uring_session::UringSession::try_open_kind(
            crate::uring_session::SessionKind::Pool,
            32,
        )
        .expect("pool");
        session.poison();
        let mut ctx = crate::IoCtx::held(&mut session);
        match body_ranges_batched(&t, &[Fk(1)], &mut ctx) {
            Err(StoreError::Corrupt("invariant: io_uring session poisoned")) => {}
            other => panic!("poisoned held idx fill must fail closed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connected_after_idx_missing_range_is_corrupt() {
        let mut winner = vec![None; 1];
        let mut connected = vec![false; 1];
        let fence = HeightFence::from_runs(vec![crate::height_fence::FenceRun {
            first_fk: 1,
            count: 1,
            height: 0,
        }]);
        let mut age = [0u64; crate::head_resolve_stats::AGE_CAP];
        match record_chosen_idx_ranges(
            &[0],
            &[Fk(1)],
            &[None],
            &mut winner,
            &mut connected,
            Some(&fence),
            &[1],
            &mut age,
        ) {
            Err(StoreError::Corrupt("invariant: idx range missing after identity")) => {}
            other => panic!("expected idx-range Corrupt, got {other:?}"),
        }
        assert!(winner[0].is_none());
        assert!(!connected[0], "must not mark connected without a range");
    }

    #[test]
    fn connected_after_idx_sets_winner_and_connected() {
        let mut winner = vec![None; 1];
        let mut connected = vec![false; 1];
        let fence = HeightFence::from_runs(vec![crate::height_fence::FenceRun {
            first_fk: 1,
            count: 1,
            height: 0,
        }]);
        let mut age = [0u64; crate::head_resolve_stats::AGE_CAP];
        record_chosen_idx_ranges(
            &[0],
            &[Fk(1)],
            &[Some((8, 16))],
            &mut winner,
            &mut connected,
            Some(&fence),
            &[1],
            &mut age,
        )
        .unwrap();
        assert_eq!(winner[0], Some((Fk(1), (8, 16))));
        assert!(connected[0]);
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
                assert_eq!(t.body.record_range(*fk).unwrap(), *range);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pool session drives the same staged resolve machine.
    #[test]
    fn pool_fk_and_range_matches_pread() {
        crate::uring_session::with_forced_session_kind(
            crate::uring_session::SessionKind::Pool,
            || {
                let (dir, t, txids) = seed_table(16);
                let _ = crate::uring_session::tls_take_sqe_n();
                let pread = resolve_fk_and_range_pread(&t, &txids, None, false).unwrap();
                let via = resolve_fk_and_range_batch(&t, &txids).unwrap();
                assert_eq!(pread, via);
                assert!(
                    crate::uring_session::tls_take_sqe_n() > 0,
                    "pool resolve must push probe/idx SQEs on the held session"
                );
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
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
        assert_eq!(t.body.record_range(fk).unwrap(), range);
        assert!(range.1 > 0);
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

    fn merge_cands(parts: &[Vec<Vec<Fk>>]) -> Vec<Vec<Fk>> {
        let n = parts[0].len();
        let mut out = vec![Vec::new(); n];
        for part in parts {
            for (i, c) in part.iter().enumerate() {
                out[i].extend(c.iter().copied());
            }
        }
        out
    }

    /// On a small (no cold segs) store, open∪sealed_hot∪cold equals full probe.
    #[test]
    fn three_waves_cands_match_full_probe() {
        let (dir, t, txids) = seed_table(24);
        let mixed: Vec<[u8; 32]> = txids.iter().map(|x| t.secret.mix_txid(x)).collect();
        let full = t.head.probe_candidates_batch(&mixed).unwrap();
        let open = t.head.probe_candidates_batch_open(&mixed).unwrap();
        let mid = t
            .head
            .probe_candidates_batch_sealed_hot(&mixed, &vec![true; mixed.len()])
            .unwrap();
        let active = vec![true; mixed.len()];
        let cold = t.head.probe_candidates_batch_cold(&mixed, &active).unwrap();
        let merged = merge_cands(&[open.clone(), mid.clone(), cold.clone()]);
        assert_eq!(merged, full);
        assert!(
            mid.iter().all(|c| c.is_empty()) && cold.iter().all(|c| c.is_empty()),
            "tiny store is open-only"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Open / sealed-hot (ages 1..=3) / cold (age ≥4); union = full.
    #[test]
    fn three_waves_partition_by_sealed_age() {
        use crate::address_head::HeadLayout;
        use crate::segmented_head::HEAD_PROBE_HOT_MAX_AGE;
        let dir = tmp("hot-open-plus-3");
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let t = TxTable::create_with_head_layout(&dir, layout).unwrap();
        // bits=8 → 256 slots, seal ~204 keys. Six segments ⇒ oldest age ≥4.
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
        t.flush_head().unwrap();
        assert!(
            t.head.sealed_segment_count() >= 4,
            "need a cold sealed age, segs={} sealed={}",
            t.head.segment_count(),
            t.head.sealed_segment_count()
        );
        let first = t.head.first_fks_snapshot();
        let mixed: Vec<[u8; 32]> = txids.iter().map(|x| t.secret.mix_txid(x)).collect();
        let open = t.head.probe_candidates_batch_open(&mixed).unwrap();
        let mid = t
            .head
            .probe_candidates_batch_sealed_hot(&mixed, &vec![true; mixed.len()])
            .unwrap();
        let active = vec![true; mixed.len()];
        let cold = t.head.probe_candidates_batch_cold(&mixed, &active).unwrap();
        let full = t.head.probe_candidates_batch(&mixed).unwrap();
        let merged = merge_cands(&[open.clone(), mid.clone(), cold.clone()]);
        assert_eq!(merged, full, "open∪sealed_hot∪cold must equal full probe");
        let mid_off = t
            .head
            .probe_candidates_batch_sealed_hot(&mixed, &vec![false; mixed.len()])
            .unwrap();
        assert!(
            mid_off.iter().all(|c| c.is_empty()),
            "inactive sealed-hot mask must skip every key"
        );
        let hit = mid
            .iter()
            .position(|c| !c.is_empty())
            .expect("expected sealed-hot cands");
        let mut one = vec![false; mixed.len()];
        one[hit] = true;
        let mid_one = t
            .head
            .probe_candidates_batch_sealed_hot(&mixed, &one)
            .unwrap();
        assert_eq!(mid_one[hit], mid[hit]);
        for (i, c) in mid_one.iter().enumerate() {
            if i != hit {
                assert!(c.is_empty(), "inactive key {i} must not probe sealed-hot");
            }
        }
        let mut saw_cold = false;
        for i in 0..txids.len() {
            for &fk in &open[i] {
                let age = crate::head_resolve_stats::sealed_age_for_fk(&first, fk.0).unwrap();
                assert_eq!(age, 0, "open cand fk={} age={age}", fk.0);
            }
            for &fk in &mid[i] {
                let age = crate::head_resolve_stats::sealed_age_for_fk(&first, fk.0).unwrap();
                assert!(
                    age <= HEAD_PROBE_HOT_MAX_AGE,
                    "sealed-hot cand fk={} age={age}",
                    fk.0
                );
            }
            for &fk in &cold[i] {
                let age = crate::head_resolve_stats::sealed_age_for_fk(&first, fk.0).unwrap();
                assert!(
                    age > HEAD_PROBE_HOT_MAX_AGE,
                    "cold cand fk={} age={age}",
                    fk.0
                );
                saw_cold = true;
            }
        }
        assert!(saw_cold, "expected some keys to have cold-only cands");
        let oldest = crate::head_resolve_stats::sealed_age_for_fk(&first, 1).unwrap();
        assert!(oldest > HEAD_PROBE_HOT_MAX_AGE, "oldest age={oldest}");
        assert!(
            !open[0].iter().any(|f| f.0 == 1) && !mid[0].iter().any(|f| f.0 == 1),
            "oldest create must not be in open or sealed-hot"
        );
        assert!(
            cold[0].iter().any(|f| f.0 == 1),
            "oldest create must be in cold"
        );
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
    fn plan_body_range_idx_matches_record_range() {
        let (dir, t, _txids) = seed_table(20);
        let count = t.body.count();
        for id in 1..=count {
            let fk = Fk(id);
            let expected = t.body.record_range(fk).unwrap();
            let plan = t.body.plan_body_range_idx(fk).unwrap();
            assert!(!plan.pages.is_empty());
            let bufs: Vec<Vec<u8>> = plan
                .pages
                .iter()
                .map(|p| {
                    let mut b = vec![0u8; p.want];
                    let rc = p.fd.pread(p.page_off, &mut b);
                    assert!(rc > 0, "pread idx page");
                    b
                })
                .collect();
            let refs: Vec<&[u8]> = bufs.iter().map(|b| b.as_slice()).collect();
            let got = plan.decode_range(&refs).unwrap();
            assert_eq!(got, expected, "fk={fk:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Batched idx fill: unique pages, decode equals serial `record_range`.
    ///
    /// Distant fks sit on distinct OS pages; adjacent fks share a page so the
    /// helper's unique set is smaller than the per-fk page sum.
    #[test]
    fn id_idx_wave_batches_idx_pages() {
        let (dir, t, txids) = seed_table_n(1100);
        let first = Fk(1);
        let near = Fk(2);
        let far = Fk(1100);
        let p0 = t.body.plan_body_range_idx(first).unwrap();
        let p_near = t.body.plan_body_range_idx(near).unwrap();
        let p_far = t.body.plan_body_range_idx(far).unwrap();
        assert!(!p0.pages.is_empty() && !p_far.pages.is_empty());

        let uniq_far = unique_idx_pages(p0.pages.iter().chain(p_far.pages.iter()));
        let far_offs: std::collections::HashSet<u64> =
            uniq_far.iter().map(|p| p.page_off).collect();
        assert!(
            far_offs.len() >= 2,
            "fk 1 and 1100 must span distinct idx pages, offs={far_offs:?}"
        );

        let sum_near = p0.pages.len() + p_near.pages.len();
        let uniq_near = unique_idx_pages(p0.pages.iter().chain(p_near.pages.iter()));
        assert!(
            uniq_near.len() < sum_near,
            "adjacent fks must share an idx page: uniq={} sum={sum_near}",
            uniq_near.len()
        );

        let batch =
            body_ranges_batched(&t, &[first, near, far], &mut crate::IoCtx::none()).unwrap();
        for (fk, got) in [first, near, far].iter().zip(batch.iter()) {
            let exp = t.body.record_range(*fk).unwrap();
            assert_eq!(*got, Some(exp), "fk={}", fk.0);
        }

        let got = resolve_fk_and_range_pread(&t, &[txids[0], txids[1], txids[1099]], None, false)
            .unwrap();
        assert_eq!(got[0].1, Some((first, batch[0].unwrap())));
        assert_eq!(got[1].1, Some((near, batch[1].unwrap())));
        assert_eq!(got[2].1, Some((far, batch[2].unwrap())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Idx fill must submit/harvest in `free_sq` windows. Pushing every unique
    /// page before any CQE trips `io_session SQ full` on a 1080-high leftover
    /// wave (default-milestone IBD).
    #[test]
    fn fill_idx_pages_windows_past_ring_depth() {
        use std::io::Write;
        let n = 48usize;
        let page = 64usize;
        let path = tmp("idx-sq-window").join("idx.bin");
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let mut blob = vec![0u8; n * page];
        for i in 0..n {
            blob[i * page] = i as u8;
        }
        f.write_all(&blob).unwrap();
        f.sync_all().unwrap();
        let fd = crate::io_handle::IoHandle::from_file(&f);
        let pages: Vec<crate::tx_idx::IdxPagePlan> = (0..n)
            .map(|i| crate::tx_idx::IdxPagePlan {
                fd,
                page_off: (i * page) as u64,
                want: page,
            })
            .collect();
        let mut bufs: Vec<Vec<u8>> = pages.iter().map(|p| vec![0u8; p.want]).collect();
        let mut sess = crate::uring_session::UringSession::try_open(32).expect("session");
        assert!(
            n > sess.entries() as usize,
            "fixture must exceed ring depth"
        );
        fill_idx_pages(&mut sess, &pages, &mut bufs)
            .expect("idx fill must window SQ; SQ full is not store corruption");
        for (i, b) in bufs.iter().enumerate() {
            assert_eq!(b[0], i as u8, "page {i}");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
