//! External parent create_fk stamp: in-flight → published → recent creates → TipOnly.
//!
//! One function for S0 plan (`archive_plan_batch_from_store`) and plan=None
//! rehydrate. Pipeline parent store is outs only — not a create_fk source.

use crate::published_ids::TxidHasher;
use crate::{CreatePin, InFlightView, PublishedIds, QueryError, RecentCreates, U64Map, U64Set};
use rbitcoin_primitives::Fk;
use rbitcoin_store::Store;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::time::Instant;

type TxidFkMap = HashMap<[u8; 32], Fk, BuildHasherDefault<TxidHasher>>;

/// One create's lookup-stamped identity (body / spent / pin optional).
#[derive(Debug, Clone, Default)]
pub struct ParentIdent {
    pub txid: [u8; 32],
    pub body: Option<(u64, u64)>,
    pub spent: Option<(u64, u64)>,
    pub pin: Option<CreatePin>,
}

impl ParentIdent {
    #[inline]
    pub fn new(txid: [u8; 32]) -> Self {
        Self {
            txid,
            body: None,
            spent: None,
            pin: None,
        }
    }

    #[inline]
    pub fn with_body(txid: [u8; 32], body: (u64, u64)) -> Self {
        Self {
            txid,
            body: Some(body),
            spent: None,
            pin: None,
        }
    }
}

/// Lookup-stamped external parent identity (same-batch stays offline at pin).
///
/// `txid → create_fk` plus `create_fk → ParentIdent`. No parallel range/txid/pin maps.
#[derive(Debug, Default, Clone)]
pub struct ExternalParentStamp {
    /// prev_txid → create_fk
    pub resolved: TxidFkMap,
    /// create_fk_id → identity
    pub idents: U64Map<ParentIdent>,
    pub inflight_ns: u64,
    pub pin_txid_n: u64,
    pub pin_txid_ns: u64,
    pub recent_n: u64,
    pub recent_ns: u64,
    pub head_fk_ns: u64,
    pub head_need_n: u64,
    pub head_hit_n: u64,
}

impl ExternalParentStamp {
    fn bind(&mut self, id: u64, txid: [u8; 32]) -> &mut ParentIdent {
        self.idents
            .entry(id)
            .or_insert_with(|| ParentIdent::new(txid))
    }
}

/// Bind `need` txids: in-flight → published `live_union` → recent creates → leftover.
///
/// Then idx range-fill for resolved creates that have no range and no
/// in-flight outs. Same-batch identities are not inputs — callers skip them
/// in `need` and keep them offline at pin.
pub fn stamp_external_parents(
    store: &Store,
    need: &[[u8; 32]],
    in_flight: &InFlightView,
    published: &PublishedIds,
    recent: &RecentCreates,
) -> Result<ExternalParentStamp, QueryError> {
    let pub_head = published.load();
    let recent_snap = recent.snapshot();
    let mut stamp = ExternalParentStamp {
        resolved: TxidFkMap::with_capacity_and_hasher(need.len() / 2, Default::default()),
        idents: U64Map::with_capacity_and_hasher(need.len(), Default::default()),
        ..ExternalParentStamp::default()
    };

    let t_inflight = Instant::now();
    let mut still_need: Vec<&[u8; 32]> = Vec::new();
    for t in need {
        if *t == [0u8; 32] {
            continue;
        }
        if let Some(fk) = in_flight.get_create_fk(t) {
            stamp.resolved.insert(*t, fk);
            if let Some(id) = fk.get() {
                stamp.bind(id, *t);
            }
        } else {
            still_need.push(t);
        }
    }
    stamp.inflight_ns = t_inflight.elapsed().as_nanos() as u64;

    let t_pin_txid = Instant::now();
    let mut after_pub: Vec<&[u8; 32]> = Vec::new();
    for t in still_need {
        if let Some((fk, range)) = pub_head.as_ref().and_then(|h| h.get(t)) {
            stamp.resolved.insert(*t, fk);
            if let Some(id) = fk.get() {
                stamp.bind(id, *t).body = Some(range);
            }
            stamp.pin_txid_n = stamp.pin_txid_n.saturating_add(1);
            continue;
        }
        after_pub.push(t);
    }
    stamp.pin_txid_ns = t_pin_txid.elapsed().as_nanos() as u64;

    let t_recent = Instant::now();
    let mut need_head: Vec<[u8; 32]> = Vec::new();
    for t in after_pub {
        if let Some((fk, range)) = recent_snap.get(t) {
            stamp.resolved.insert(*t, fk);
            if let Some(id) = fk.get() {
                let e = stamp.bind(id, *t);
                e.body = Some(range);
                if let Some(pin) = recent_snap.create_pin(t) {
                    e.pin = Some(pin);
                }
            }
            stamp.recent_n = stamp.recent_n.saturating_add(1);
            continue;
        }
        need_head.push(*t);
    }
    stamp.recent_ns = t_recent.elapsed().as_nanos() as u64;
    stamp.head_need_n = need_head.len() as u64;

    let t_head = Instant::now();
    if !need_head.is_empty() {
        need_head.sort_by_cached_key(|txid| store.txs.head_primary_slot(txid));
        let hits = store.get_fk_by_txid_batch(&need_head)?;
        let first_fks = store.txs.head_first_fks_snapshot();
        let mut age0 = 0u64;
        let mut age3 = 0u64;
        let mut age_n = 0u64;
        for (txid, row) in hits {
            if let Some((fk, range)) = row {
                stamp.resolved.insert(txid, fk);
                stamp.head_hit_n = stamp.head_hit_n.saturating_add(1);
                if let Some(id) = fk.get() {
                    stamp.bind(id, txid).body = Some(range);
                    if let Some(age) =
                        rbitcoin_store::head_resolve_stats::sealed_age_for_fk(&first_fks, id)
                    {
                        age_n = age_n.saturating_add(1);
                        if age == 0 {
                            age0 = age0.saturating_add(1);
                        }
                        if age <= 3 {
                            age3 = age3.saturating_add(1);
                        }
                    }
                }
            }
        }
        crate::archive_phase_stats::note_leftover_mix(0, age0, age3, age_n);
    }
    {
        let mut miss_n = 0u64;
        let mut first_miss = None;
        for t in &need_head {
            if stamp.resolved.contains_key(t) {
                continue;
            }
            miss_n = miss_n.saturating_add(1);
            if first_miss.is_none() {
                first_miss = Some(*t);
            }
        }
        if let Some(tid) = first_miss {
            let pending = store.txs.queued_pending_fk(&tid).is_some();
            let (miss_on, miss_cands) = rbitcoin_store::head_resolve_stats::take_leftover_miss()
                .map(|(on, n)| (Some(on.as_str()), n))
                .unwrap_or((None, 0));
            crate::archive_phase_stats::note_union_miss(tid, miss_n, pending, miss_on, miss_cands);
            store.diagnose_leftover_probe(&tid);
        } else {
            crate::archive_phase_stats::note_union_miss([0u8; 32], 0, false, None, 0);
        }
    }
    stamp.head_fk_ns = t_head.elapsed().as_nanos() as u64;
    crate::archive_phase_stats::note_pin_txid(stamp.pin_txid_n, stamp.pin_txid_ns);
    crate::archive_phase_stats::note_recent(stamp.recent_n, stamp.recent_ns);

    fill_missing_parent_ranges(store, in_flight, &mut stamp.idents)?;
    Ok(stamp)
}

/// Idx body_range and spent_range for stamped create_fks with no in-flight outs.
///
/// Body miss after identity is `Corrupt`. Spent miss after a **store** body fill
/// is `Corrupt`. RAM-only identity (published/recent fake range, no `spent.idx`
/// row) leaves spent unset — write ensure still stamps those holes.
pub fn fill_missing_parent_ranges(
    store: &Store,
    in_flight: &InFlightView,
    idents: &mut U64Map<ParentIdent>,
) -> Result<(), QueryError> {
    crate::archive_phase_stats::note_fill_missing();
    let t_all = Instant::now();
    let inflight_outs = in_flight.out_ids();
    let mut need_body: Vec<Fk> = Vec::new();
    let mut need_spent: Vec<Fk> = Vec::new();
    for (&id, ident) in idents.iter() {
        if inflight_outs.contains(&id) {
            continue;
        }
        let fk = Fk(id);
        if ident.body.is_none() {
            need_body.push(fk);
        }
        if ident.spent.is_none() {
            need_spent.push(fk);
        }
    }
    let t_idx = Instant::now();
    let mut body_filled = U64Set::default();
    if !need_body.is_empty() {
        let filled = store.tx_body_range_batch(&need_body)?;
        for (fk, row) in need_body.into_iter().zip(filled.into_iter()) {
            let Some(id) = fk.get() else {
                continue;
            };
            let Some(range) = row else {
                return Err(rbitcoin_store::StoreError::Corrupt(
                    "archive: external parent body_range missing after create_fk stamp",
                )
                .into());
            };
            if let Some(e) = idents.get_mut(&id) {
                e.body = Some(range);
            }
            body_filled.insert(id);
        }
    }
    if !need_spent.is_empty() {
        let filled = store.tx_spent_range_batch(&need_spent)?;
        for (fk, row) in need_spent.into_iter().zip(filled.into_iter()) {
            let Some(id) = fk.get() else {
                continue;
            };
            match row {
                Some(sr) => {
                    if let Some(e) = idents.get_mut(&id) {
                        e.spent = Some(sr);
                    }
                }
                None if body_filled.contains(&id) => {
                    return Err(rbitcoin_store::StoreError::Corrupt(
                        "archive: external parent spent_range missing after create_fk stamp",
                    )
                    .into());
                }
                None => {}
            }
        }
    }
    let idx_ns = t_idx.elapsed().as_nanos() as u64;
    crate::archive_phase_stats::note_fill_missing_ns(t_all.elapsed().as_nanos() as u64, idx_ns);
    Ok(())
}
