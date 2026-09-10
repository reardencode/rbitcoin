//! External parent create_fk stamp: in-flight → skeleton → leftover TipOnly.
//!
//! IBD load passes a lookup-filled [`BatchParentIds`] and never leftover-probes.
//! plan=None / S0 (`skeleton = None`) is in-flight → leftover TipOnly.
//! One function for S0 plan (`archive_plan_batch_from_store`) and plan=None
//! rehydrate. In-flight holds CreatePins until load drops map rows below a
//! lookup-wave drain+fence snapshot taken before TipOnly.

use crate::id_map::{IdMap, TxidHasher};
use crate::{CreatePin, InFlight, QueryError, U64Map, U64Set};
use rbitcoin_primitives::Fk;
use rbitcoin_store::Store;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::time::Instant;

type TxidFkMap = HashMap<[u8; 32], Fk, BuildHasherDefault<TxidHasher>>;

/// Lookup-filled parent identity for one load chunk (fk + ranges; no outs).
#[derive(Clone, Debug, Default)]
pub struct BatchParentIds {
    /// Wave `txid → (create_fk, body_range)` (shared across chunks).
    pub ids: Arc<IdMap>,
    /// Wave `create_fk_id → spent.idx` range (shared across chunks).
    pub spent: Arc<U64Map<(u64, u64)>>,
    /// Per-chunk `create_fk_id → vouts` spent in this load batch.
    pub need_vouts: U64Map<Vec<u32>>,
}

impl BatchParentIds {
    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64), Option<(u64, u64)>)> {
        let &(fk, body) = self.ids.get(txid)?;
        let spent = fk.get().and_then(|id| self.spent.get(&id).copied());
        Some((fk, body, spent))
    }
}

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

/// Bind `need` txids: in-flight → skeleton → leftover TipOnly.
///
/// `skeleton = Some` is the IBD path: miss of in-flight and skeleton is
/// `Corrupt` with no leftover `tx.head` probe. `skeleton = None` is plan=None
/// / S0 leftover TipOnly. Same-batch identities are not inputs — callers skip
/// them in `need` and keep them offline at pin.
pub fn stamp_external_parents(
    store: &Store,
    need: &[[u8; 32]],
    in_flight: &InFlight,
    skeleton: Option<&BatchParentIds>,
) -> Result<ExternalParentStamp, QueryError> {
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
                let e = stamp.bind(id, *t);
                if let Some(pin) = in_flight.get_out(id) {
                    e.pin = Some(std::sync::Arc::clone(pin));
                }
            }
        } else {
            still_need.push(t);
        }
    }
    stamp.inflight_ns = t_inflight.elapsed().as_nanos() as u64;

    let t_pin_txid = Instant::now();
    let mut after_skel: Vec<&[u8; 32]> = Vec::new();
    if let Some(skel) = skeleton {
        for t in still_need {
            if let Some((fk, range, spent)) = skel.get(t) {
                stamp.resolved.insert(*t, fk);
                if let Some(id) = fk.get() {
                    let e = stamp.bind(id, *t);
                    e.body = Some(range);
                    if let Some(sr) = spent {
                        e.spent = Some(sr);
                    }
                }
                stamp.pin_txid_n = stamp.pin_txid_n.saturating_add(1);
                continue;
            }
            after_skel.push(t);
        }
        stamp.pin_txid_ns = t_pin_txid.elapsed().as_nanos() as u64;
        if !after_skel.is_empty() {
            return Err(rbitcoin_store::StoreError::Corrupt(
                "archive: parent create_fk unresolved (contiguous batch required)",
            )
            .into());
        }
        stamp.head_need_n = 0;
        crate::archive_phase_stats::note_pin_txid(stamp.pin_txid_n, stamp.pin_txid_ns);
        crate::archive_phase_stats::note_recent(stamp.recent_n, stamp.recent_ns);
        return Ok(stamp);
    }
    let mut need_head: Vec<[u8; 32]> = still_need.into_iter().copied().collect();
    stamp.pin_txid_ns = t_pin_txid.elapsed().as_nanos() as u64;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::in_flight::InFlight;
    use rbitcoin_primitives::Fk;

    fn tmp_store() -> (std::path::PathBuf, crate::Query) {
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-stamp-skel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let q = crate::Query::open_or_create_tiny(&path).unwrap();
        (path, q)
    }

    fn pin(id: u64) -> CreatePin {
        use rbitcoin_store::{OutputRecord, TxRecord};
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&id.to_le_bytes());
        Arc::new((
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        ))
    }

    #[test]
    fn skeleton_hit_skips_leftover_head() {
        let (dir, q) = tmp_store();
        let mut txid = [0u8; 32];
        txid[0] = 0x11;
        let mut ids = IdMap::default();
        ids.insert(txid, (Fk(7), (10, 20)));
        let mut spent = U64Map::default();
        spent.insert(7, (30, 40));
        let skel = BatchParentIds {
            ids: Arc::new(ids),
            spent: Arc::new(spent),
            need_vouts: U64Map::default(),
        };
        let empty = InFlight::new();
        let st = stamp_external_parents(q.store(), &[txid], &empty, Some(&skel)).unwrap();
        assert_eq!(st.head_need_n, 0);
        assert_eq!(st.resolved.get(&txid), Some(&Fk(7)));
        assert_eq!(st.idents.get(&7).and_then(|e| e.body), Some((10, 20)));
        assert_eq!(st.idents.get(&7).and_then(|e| e.spent), Some((30, 40)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inflight_hit_without_skeleton() {
        let (dir, q) = tmp_store();
        let p = pin(42);
        let mut inflight = InFlight::new();
        inflight.note_pins([(Fk(42), &p)], Some(1));
        let txid = p.0.txid;
        let st = stamp_external_parents(q.store(), &[txid], &inflight, None).unwrap();
        assert_eq!(st.head_need_n, 0);
        assert_eq!(st.resolved.get(&txid), Some(&Fk(42)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skeleton_miss_is_unresolved_without_head_probe() {
        let (dir, q) = tmp_store();
        let mut txid = [0u8; 32];
        txid[0] = 0x22;
        let skel = BatchParentIds::default();
        let empty = InFlight::new();
        let err = stamp_external_parents(q.store(), &[txid], &empty, Some(&skel)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parent create_fk unresolved"), "got: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Idx body_range and spent_range for stamped create_fks with no in-flight outs.
///
/// Body miss after identity is `Corrupt`. Spent miss after a **store** body fill
/// is `Corrupt`. RAM-only identity (in-flight outs, no `spent.idx` row) leaves
/// spent unset — write ensure still stamps those holes.
pub fn fill_missing_parent_ranges(
    store: &Store,
    in_flight: &InFlight,
    idents: &mut U64Map<ParentIdent>,
) -> Result<(), QueryError> {
    crate::archive_phase_stats::note_fill_missing();
    let mut need_body: Vec<Fk> = Vec::new();
    let mut need_spent: Vec<Fk> = Vec::new();
    for (&id, ident) in idents.iter() {
        if in_flight.get_out(id).is_some() {
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
    Ok(())
}
