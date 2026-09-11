//! Batch-local sparse parent pins for confirm.
//!
//! **Sharing:** one [`SharedParentPin`] per create_fk (refcounted via `Arc`)
//! while the batch needs it. [`BatchParents`] is a cheap handle map of `Arc`s —
//! no process Weak registry.
//!
//! **Immutable publish:** outs and layout are **separate** immutable Arc
//! snapshots. Vacant `insert_owned` stores Frozen halves (no `ArcSwap`). First
//! real compose promotes that half to `ArcSwap` (lock-free load; RCU store).
//! Widening need-vouts composes only the outs half; layout fill composes only
//! denserels/range — never clones script bytes for a layout-only publish.
//! No-op compose keeps Arc identity (no full-body clone on share hits). Never
//! `push`/mutate shared vectors in place.
//!
//! **Assemble sticky:** [`BatchParents`] caches the last outs Arc by create_fk
//! so multi-input same-parent prevout lookup does not re-load on every input.
//!
//! **Sparse:** only spent need-vouts + layout fields write/assemble need (not
//! full parent output sets). Vout merge when a later batch spends more outs.
//!
//! Create heights are not stashed — write re-reads the height fence.

use arc_swap::ArcSwap;
use rbitcoin_primitives::Fk;
use rbitcoin_store::{OutputRecord, StoreError, TxRecord};
use std::cell::RefCell;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

pub use rbitcoin_store::{FkMap, FkSet, U32Map, U64Map, U64Set};

/// Relative offset sentinel: layout unknown for this out.
pub const SPENDER_REL_UNKNOWN: u32 = u32::MAX;

const CB_UNKNOWN: u8 = 0;
const CB_FALSE: u8 = 1;
const CB_TRUE: u8 = 2;

/// Immutable pin outs (compose → publish, never mutate).
#[derive(Debug, Clone)]
enum PinOuts {
    /// Plan / in-flight: share the CreatePin Arc.
    Full {
        pin: crate::CreatePin,
        checked: Vec<u32>,
    },
    /// Range-fill: owned sparse decoded outs.
    Sparse {
        outs: Vec<(u32, OutputRecord)>,
        checked: Vec<u32>,
    },
}

impl PinOuts {
    fn new(live: Vec<(u32, OutputRecord)>, checked: Vec<u32>) -> Self {
        Self::Sparse {
            outs: ensure_outs_sorted(live),
            checked: ensure_checked_sorted(checked),
        }
    }

    fn full(pin: crate::CreatePin, checked: Vec<u32>) -> Self {
        Self::Full {
            pin,
            checked: ensure_checked_sorted(checked),
        }
    }

    fn checked(&self) -> &[u32] {
        match self {
            Self::Full { checked, .. } | Self::Sparse { checked, .. } => checked,
        }
    }

    fn with_checked(&self, checked: Vec<u32>) -> Self {
        let checked = ensure_checked_sorted(checked);
        match self {
            Self::Full { pin, .. } => Self::Full {
                pin: std::sync::Arc::clone(pin),
                checked,
            },
            Self::Sparse { outs, .. } => Self::Sparse {
                outs: outs.clone(),
                checked,
            },
        }
    }

    fn get(&self, vout: u32) -> Option<&OutputRecord> {
        match self {
            Self::Full { pin, .. } => pin.1.get(vout as usize),
            Self::Sparse { outs, .. } => {
                let i = outs.binary_search_by_key(&vout, |(v, _)| *v).ok()?;
                Some(&outs[i].1)
            }
        }
    }

    fn covers_need(&self, need: &[u32]) -> bool {
        if need.is_empty() {
            return true;
        }
        let checked = self.checked();
        if checked.is_empty() {
            return false;
        }
        need.iter().all(|v| checked_contains(checked, *v))
    }

    fn has_all_live(&self, live: &[(u32, OutputRecord)]) -> bool {
        live.iter().all(|(v, _)| self.get(*v).is_some())
    }

    fn already_covers(&self, live: &[(u32, OutputRecord)], checked: &[u32]) -> bool {
        self.covers_need(checked) && (live.is_empty() || self.has_all_live(live))
    }

    #[cfg(test)]
    fn live_len(&self) -> usize {
        match self {
            Self::Full { pin, .. } => pin.1.len(),
            Self::Sparse { outs, .. } => outs.len(),
        }
    }

    fn sparse_live(&self) -> Vec<(u32, OutputRecord)> {
        match self {
            Self::Sparse { outs, .. } => outs.clone(),
            Self::Full { pin, checked, .. } => checked
                .iter()
                .filter_map(|&v| pin.1.get(v as usize).cloned().map(|o| (v, o)))
                .collect(),
        }
    }

    /// Compose wider need coverage (new half; does not mutate `self`).
    fn compose(&self, live: &[(u32, OutputRecord)], checked: &[u32]) -> Self {
        match self {
            Self::Full { pin, checked: ch } => {
                let extra = live.iter().any(|(v, _)| pin.1.get(*v as usize).is_none());
                if extra {
                    let mut outs = self.sparse_live();
                    for (v, o) in live {
                        if outs.binary_search_by_key(v, |(dv, _)| *dv).is_err() {
                            outs.push((*v, o.clone()));
                        }
                    }
                    outs.sort_unstable_by_key(|(v, _)| *v);
                    let mut next_ch = ch.clone();
                    next_ch.extend_from_slice(checked);
                    next_ch.sort_unstable();
                    next_ch.dedup();
                    Self::Sparse {
                        outs,
                        checked: next_ch,
                    }
                } else {
                    let mut next_ch = ch.clone();
                    next_ch.extend_from_slice(checked);
                    next_ch.sort_unstable();
                    next_ch.dedup();
                    Self::Full {
                        pin: std::sync::Arc::clone(pin),
                        checked: next_ch,
                    }
                }
            }
            Self::Sparse { outs, checked: ch } => {
                let mut next_outs = outs.clone();
                for (v, o) in live {
                    if next_outs.binary_search_by_key(v, |(dv, _)| *dv).is_err() {
                        next_outs.push((*v, o.clone()));
                    }
                }
                next_outs.sort_unstable_by_key(|(v, _)| *v);
                let mut next_ch = ch.clone();
                next_ch.extend_from_slice(checked);
                next_ch.sort_unstable();
                next_ch.dedup();
                Self::Sparse {
                    outs: next_outs,
                    checked: next_ch,
                }
            }
        }
    }
}

/// `txout` range + `spent` range. Abs = spent_off + 9×vout (no denserels).
#[derive(Debug, Clone, Default)]
struct ParentLayout {
    body_range: Option<(u64, u64)>,
    spent_range: Option<(u64, u64)>,
    spender_rels: Vec<(u32, u32)>,
}

impl ParentLayout {
    fn new(body_range: Option<(u64, u64)>, spender_rels: Vec<(u32, u32)>) -> Self {
        Self {
            body_range,
            spent_range: None,
            spender_rels,
        }
    }

    fn already_covers(&self, body_range: Option<(u64, u64)>, spender_rels: &[(u32, u32)]) -> bool {
        let range_done = body_range.is_none() || self.body_range.is_some();
        let rels_done = spender_rels.is_empty()
            || spender_rels.iter().all(|(v, r)| {
                self.spender_rels
                    .binary_search_by_key(v, |(dv, _)| *dv)
                    .ok()
                    .is_some_and(|i| self.spender_rels[i].1 == *r)
            });
        range_done && rels_done
    }

    /// Compose layout overlay (new half; does not mutate `self`).
    /// First writer wins for body_range; denserels merge by vout.
    fn compose(&self, body_range: Option<(u64, u64)>, spender_rels: &[(u32, u32)]) -> Self {
        let mut layout = self.clone();
        if layout.body_range.is_none() {
            layout.body_range = body_range;
        }
        merge_spender_rels_into(&mut layout.spender_rels, spender_rels);
        layout
    }

    /// Write-path: force body_range and merge denserels.
    fn compose_write(&self, body_range: (u64, u64), sparse_rels: &[(u32, u32)]) -> Self {
        let mut layout = self.clone();
        layout.body_range = Some(body_range);
        merge_spender_rels_into(&mut layout.spender_rels, sparse_rels);
        layout
    }
}

/// Frozen until the first real compose, then [`ArcSwap`] RCU.
#[derive(Debug)]
struct PinHalf<T> {
    frozen: Arc<T>,
    rcu: OnceLock<ArcSwap<T>>,
}

impl<T> PinHalf<T> {
    fn new(val: T) -> Self {
        Self {
            frozen: Arc::new(val),
            rcu: OnceLock::new(),
        }
    }

    #[inline]
    fn load(&self) -> Arc<T> {
        match self.rcu.get() {
            Some(s) => s.load_full(),
            None => Arc::clone(&self.frozen),
        }
    }

    fn rcu(&self, f: impl Fn(&Arc<T>) -> Arc<T>) {
        loop {
            if let Some(s) = self.rcu.get() {
                s.rcu(|cur| f(cur));
                return;
            }
            let cur = Arc::clone(&self.frozen);
            let next = f(&cur);
            if Arc::ptr_eq(&next, &cur) {
                return;
            }
            if self.rcu.set(ArcSwap::from(next)).is_ok() {
                return;
            }
        }
    }
}

/// One create's sparse pin payload, shared as `Arc` within a batch.
///
/// Outs and layout are independent immutable Arc halves (compose only the half
/// that changes). Vacant insert is Frozen; first real compose promotes to
/// ArcSwap (lock-free load; RCU store).
#[derive(Debug)]
pub struct SharedParentPin {
    tx: TxRecord,
    /// 0 unknown, 1 not coinbase, 2 coinbase.
    coinbase: AtomicU8,
    /// Sparse need outs + checked (prep widen).
    outs: PinHalf<PinOuts>,
    /// Abs layout for spentness/annotate (write fill).
    layout: PinHalf<ParentLayout>,
}

impl SharedParentPin {
    fn new(
        tx: TxRecord,
        live: Vec<(u32, OutputRecord)>,
        checked: Vec<u32>,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: Vec<(u32, u32)>,
    ) -> Self {
        let cb = match coinbase {
            Some(true) => CB_TRUE,
            Some(false) => CB_FALSE,
            None => CB_UNKNOWN,
        };
        Self {
            tx,
            coinbase: AtomicU8::new(cb),
            outs: PinHalf::new(PinOuts::new(live, checked)),
            layout: PinHalf::new(ParentLayout::new(body_range, spender_rels)),
        }
    }

    fn new_full(
        pin: crate::CreatePin,
        checked: Vec<u32>,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: Vec<(u32, u32)>,
    ) -> Self {
        let cb = match coinbase {
            Some(true) => CB_TRUE,
            Some(false) => CB_FALSE,
            None => CB_UNKNOWN,
        };
        let tx = pin.0.clone();
        Self {
            tx,
            coinbase: AtomicU8::new(cb),
            outs: PinHalf::new(PinOuts::full(pin, checked)),
            layout: PinHalf::new(ParentLayout::new(body_range, spender_rels)),
        }
    }

    #[inline]
    fn load_outs(&self) -> Arc<PinOuts> {
        self.outs.load()
    }

    #[inline]
    fn load_layout(&self) -> Arc<ParentLayout> {
        self.layout.load()
    }

    /// Compose outs half: `None` = no-op (keep existing Arc identity).
    ///
    /// Uses RCU so concurrent widens from peer batches merge correctly.
    fn publish_outs(&self, f: impl Fn(&PinOuts) -> Option<PinOuts>) {
        let cur = self.outs.load();
        if f(cur.as_ref()).is_none() {
            return;
        }
        self.outs.rcu(|cur| match f(cur.as_ref()) {
            None => Arc::clone(cur),
            Some(next) => Arc::new(next),
        });
    }

    /// Compose layout half: `None` = no-op (keep existing Arc identity).
    fn publish_layout(&self, f: impl Fn(&ParentLayout) -> Option<ParentLayout>) {
        let cur = self.layout.load();
        if f(cur.as_ref()).is_none() {
            return;
        }
        self.layout.rcu(|cur| match f(cur.as_ref()) {
            None => Arc::clone(cur),
            Some(next) => Arc::new(next),
        });
    }

    /// True when all `need` vouts are already in checked.
    #[inline]
    fn covers_need(&self, need: &[u32]) -> bool {
        self.load_outs().covers_need(need)
    }

    /// No-op (empty / already-covered `checked`+`live`) keeps the outs Arc.
    fn merge_outs(&self, live: Vec<(u32, OutputRecord)>, checked: &[u32]) {
        let snap = self.load_outs();
        if snap.already_covers(&live, checked) {
            return;
        }
        self.outs.rcu(|cur| {
            if cur.already_covers(&live, checked) {
                Arc::clone(cur)
            } else {
                Arc::new(cur.compose(&live, checked))
            }
        });
    }

    fn set_coinbase_if_known(&self, coinbase: Option<bool>) {
        if let Some(b) = coinbase {
            let v = if b { CB_TRUE } else { CB_FALSE };
            let _ =
                self.coinbase
                    .compare_exchange(CB_UNKNOWN, v, Ordering::Relaxed, Ordering::Relaxed);
        }
    }

    fn coinbase_opt(&self) -> Option<bool> {
        match self.coinbase.load(Ordering::Relaxed) {
            CB_TRUE => Some(true),
            CB_FALSE => Some(false),
            _ => None,
        }
    }

    /// Publish layout only when something new is present.
    fn maybe_merge_layout(&self, body_range: Option<(u64, u64)>, spender_rels: &[(u32, u32)]) {
        if body_range.is_none() && spender_rels.is_empty() {
            return;
        }
        let snap = self.load_layout();
        if snap.already_covers(body_range, spender_rels) {
            return;
        }
        self.layout.rcu(|cur| {
            if cur.already_covers(body_range, spender_rels) {
                Arc::clone(cur)
            } else {
                Arc::new(cur.compose(body_range, spender_rels))
            }
        });
    }

    #[allow(clippy::type_complexity)] // packed (fk, range) / span row is the on-disk shape
    /// Single-snap apply for free-pin Occupied path: outs widen and/or layout
    /// merge from one outs load + one layout load (no double compose when no-op).
    fn apply_pin_delta(
        &self,
        live: Option<(Vec<(u32, OutputRecord)>, &[u32])>,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: &[(u32, u32)],
    ) {
        self.set_coinbase_if_known(coinbase);
        if let Some((live, checked)) = live {
            self.merge_outs(live, checked);
        }
        self.maybe_merge_layout(body_range, spender_rels);
    }

    /// Pure share-hit: coinbase + layout only when material present (no outs touch).
    fn apply_meta_only(
        &self,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: &[(u32, u32)],
    ) {
        self.set_coinbase_if_known(coinbase);
        self.maybe_merge_layout(body_range, spender_rels);
    }
}

/// Per-batch handle map: `create_fk → Arc` shared pin (refcount only on clone).
///
/// Assemble sticky (`sticky_outs`) is batch-local and not shared across clones.
#[derive(Debug, Default)]
pub struct BatchParents {
    pins: U64Map<Arc<SharedParentPin>>,
    /// Last outs Arc loaded for assemble (`get_parent_txout_parts`).
    sticky_outs: RefCell<Option<(u64, Arc<PinOuts>)>>,
}

impl Clone for BatchParents {
    fn clone(&self) -> Self {
        Self {
            pins: self.pins.clone(),
            sticky_outs: RefCell::new(None),
        }
    }
}

impl BatchParents {
    pub fn new() -> Self {
        Self {
            pins: U64Map::default(),
            sticky_outs: RefCell::new(None),
        }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            pins: U64Map::with_capacity_and_hasher(n, BuildHasherDefault::default()),
            sticky_outs: RefCell::new(None),
        }
    }

    #[inline]
    fn invalidate_sticky(&self, id: u64) {
        let mut st = self.sticky_outs.borrow_mut();
        if st.as_ref().is_some_and(|(sid, _)| *sid == id) {
            *st = None;
        }
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Layout / coinbase only when outs already cover need (share hit).
    ///
    /// Skips all work when there is no meta material (pure share hit).
    #[inline]
    pub fn refresh_pin_meta(
        &mut self,
        fk: Fk,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: Vec<(u32, u32)>,
    ) {
        if coinbase.is_none() && body_range.is_none() && spender_rels.is_empty() {
            return;
        }
        let Some(id) = fk.get() else {
            return;
        };
        let Some(p) = self.pins.get(&id) else {
            return;
        };
        p.apply_meta_only(coinbase, body_range, &spender_rels);
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    /// Insert / merge one parent (prep pin hot path).
    ///
    /// Pure batch HashMap. Merge only if the same batch already holds a partial
    /// pin. Occupied path uses one snap decision for outs+layout (single-snap).
    #[inline]
    pub fn insert_owned(
        &mut self,
        fk: Fk,
        tx: TxRecord,
        live: Vec<(u32, OutputRecord)>,
        checked: Vec<u32>,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: Vec<(u32, u32)>,
    ) {
        let Some(id) = fk.get() else {
            return;
        };
        match self.pins.entry(id) {
            std::collections::hash_map::Entry::Occupied(o) => {
                let p = o.get();
                let outs = p.load_outs();
                let need_outs = !outs.already_covers(&live, &checked);
                if need_outs {
                    p.apply_pin_delta(
                        Some((live, checked.as_slice())),
                        coinbase,
                        body_range,
                        &spender_rels,
                    );
                    // Drop sticky so assemble does not see a stale narrower snap.
                    drop(outs);
                    self.invalidate_sticky(id);
                } else {
                    let _ = live;
                    p.apply_meta_only(coinbase, body_range, &spender_rels);
                }
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(Arc::new(SharedParentPin::new(
                    tx,
                    live,
                    checked,
                    coinbase,
                    body_range,
                    spender_rels,
                )));
            }
        }
    }

    /// Vacant insert from a plan/in-flight [`crate::CreatePin`] (refcount only).
    pub fn insert_create_pin(
        &mut self,
        fk: Fk,
        pin: crate::CreatePin,
        checked: Vec<u32>,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: Vec<(u32, u32)>,
    ) {
        let Some(id) = fk.get() else {
            return;
        };
        match self.pins.entry(id) {
            std::collections::hash_map::Entry::Occupied(o) => {
                let p = o.get();
                let outs = p.load_outs();
                let need_outs = !outs.covers_need(&checked);
                if need_outs {
                    let live = {
                        let (_tx, rows) = pin.as_ref();
                        checked
                            .iter()
                            .filter_map(|&v| rows.get(v as usize).cloned().map(|o| (v, o)))
                            .collect::<Vec<_>>()
                    };
                    p.apply_pin_delta(
                        Some((live, checked.as_slice())),
                        coinbase,
                        body_range,
                        &spender_rels,
                    );
                    drop(outs);
                    self.invalidate_sticky(id);
                } else {
                    p.apply_meta_only(coinbase, body_range, &spender_rels);
                }
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(Arc::new(SharedParentPin::new_full(
                    pin,
                    checked,
                    coinbase,
                    body_range,
                    spender_rels,
                )));
            }
        }
    }

    /// Test / convenience: clone from slices into the map.
    pub fn put_resolved(
        &mut self,
        fk: Fk,
        tx: TxRecord,
        live: &[(u32, OutputRecord)],
        checked: &[u32],
        coinbase: Option<bool>,
    ) {
        self.insert_owned(
            fk,
            tx,
            live.to_vec(),
            checked.to_vec(),
            coinbase,
            None,
            Vec::new(),
        );
    }

    pub fn get_parent_out(&self, fk: Fk, vout: u32) -> Option<(TxRecord, OutputRecord)> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let outs = e.load_outs();
        let o = outs.get(vout)?;
        Some((e.tx.clone(), o.clone()))
    }

    /// Assemble hot path: value + borrowed script bytes + parent txid.
    ///
    /// Sticky: multi-input spends of the same create reuse one outs Arc without
    /// re-entering the pin slot. The callback runs while that Arc is held.
    #[inline]
    pub fn get_parent_txout_parts<R>(
        &self,
        fk: Fk,
        vout: u32,
        f: impl FnOnce(i64, &[u8], [u8; 32]) -> R,
    ) -> Option<R> {
        self.parent_txout_parts_inner(fk, vout, true, f)
    }

    /// Same as [`get_parent_txout_parts`] but **always** `load_outs` (no sticky).
    /// Used as the fair cold control for sticky benches / tests.
    #[inline]
    pub fn get_parent_txout_parts_no_sticky<R>(
        &self,
        fk: Fk,
        vout: u32,
        f: impl FnOnce(i64, &[u8], [u8; 32]) -> R,
    ) -> Option<R> {
        self.parent_txout_parts_inner(fk, vout, false, f)
    }

    #[inline]
    fn parent_txout_parts_inner<R>(
        &self,
        fk: Fk,
        vout: u32,
        use_sticky: bool,
        f: impl FnOnce(i64, &[u8], [u8; 32]) -> R,
    ) -> Option<R> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let txid = e.tx.txid;
        if use_sticky {
            {
                let st = self.sticky_outs.borrow();
                if let Some((sid, snap)) = st.as_ref() {
                    if *sid == id {
                        let o = snap.get(vout)?;
                        return Some(f(o.value, o.script.as_slice(), txid));
                    }
                }
            }
            let snap = e.load_outs();
            let o = snap.get(vout)?;
            let r = f(o.value, o.script.as_slice(), txid);
            *self.sticky_outs.borrow_mut() = Some((id, Arc::clone(&snap)));
            return Some(r);
        }
        let outs = e.load_outs();
        let o = outs.get(vout)?;
        Some(f(o.value, o.script.as_slice(), txid))
    }

    pub fn get_parent_tx(&self, fk: Fk) -> Option<TxRecord> {
        let id = fk.get()?;
        self.pins.get(&id).map(|e| e.tx.clone())
    }

    pub fn get_parent_coinbase(&self, fk: Fk) -> Option<bool> {
        let id = fk.get()?;
        self.pins.get(&id)?.coinbase_opt()
    }

    pub fn get_body_range(&self, fk: Fk) -> Option<(u64, u64)> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        e.load_layout().body_range
    }

    pub fn set_layout(&mut self, fk: Fk, body_range: (u64, u64), dense_rels: &[u32]) {
        self.set_layout_for_need(fk, body_range, dense_rels, &[]);
    }

    pub fn set_layout_for_need(
        &mut self,
        fk: Fk,
        body_range: (u64, u64),
        dense_rels: &[u32],
        extra_need: &[u32],
    ) {
        let Some(id) = fk.get() else {
            return;
        };
        let Some(e) = self.pins.get(&id) else {
            return;
        };
        // RCU must recompute checked from `cur` (not a stale pre-load snap):
        // concurrent prep merge_outs can add peer need-vouts between load and
        // publish; replacing with a snap-built list clobbered those vouts.
        let mut need_for_sparse: Vec<u32> = e.load_outs().checked().to_vec();
        let may_grow_checked =
            need_for_sparse.is_empty() && extra_need.is_empty() && !dense_rels.is_empty()
                || !extra_need.is_empty();
        if may_grow_checked {
            e.publish_outs(|cur| {
                let mut checked = cur.checked().to_vec();
                if checked.is_empty() && extra_need.is_empty() && !dense_rels.is_empty() {
                    checked = (0..dense_rels.len() as u32).collect();
                }
                if !extra_need.is_empty() {
                    checked.extend_from_slice(extra_need);
                    checked.sort_unstable();
                    checked.dedup();
                }
                if checked == cur.checked() {
                    return None;
                }
                Some(cur.with_checked(checked))
            });
            self.invalidate_sticky(id);
            need_for_sparse = e.load_outs().checked().to_vec();
        }
        let sparse = sparse_spender_rels(dense_rels, &need_for_sparse);
        let lay = e.load_layout();
        if lay.body_range == Some(body_range) && lay.already_covers(Some(body_range), &sparse) {
            return;
        }
        e.publish_layout(|cur| {
            if cur.body_range == Some(body_range) && cur.already_covers(Some(body_range), &sparse) {
                return None;
            }
            Some(cur.compose_write(body_range, &sparse))
        });
    }

    pub fn set_body_range_only(&mut self, fk: Fk, body_range: (u64, u64)) {
        let Some(id) = fk.get() else {
            return;
        };
        if let Some(e) = self.pins.get(&id) {
            e.publish_layout(|cur| {
                if cur.body_range == Some(body_range) {
                    return None;
                }
                let mut next = cur.clone();
                next.body_range = Some(body_range);
                Some(next)
            });
        }
    }

    pub fn set_layout_sparse(
        &mut self,
        fk: Fk,
        body_range: (u64, u64),
        sparse_rels: Vec<(u32, u32)>,
        extra_need: &[u32],
    ) {
        let Some(id) = fk.get() else {
            return;
        };
        let Some(e) = self.pins.get(&id) else {
            return;
        };
        if !extra_need.is_empty() {
            e.publish_outs(|cur| {
                let mut checked = cur.checked().to_vec();
                checked.extend_from_slice(extra_need);
                checked.sort_unstable();
                checked.dedup();
                if checked == cur.checked() {
                    return None;
                }
                Some(cur.with_checked(checked))
            });
            self.invalidate_sticky(id);
        }
        let lay = e.load_layout();
        if lay.body_range == Some(body_range) && lay.already_covers(Some(body_range), &sparse_rels)
        {
            return;
        }
        e.publish_layout(|cur| {
            if cur.body_range == Some(body_range)
                && cur.already_covers(Some(body_range), &sparse_rels)
            {
                return None;
            }
            Some(cur.compose_write(body_range, &sparse_rels))
        });
    }

    #[inline]
    pub fn has_abs_layout(&self, fk: Fk) -> bool {
        let Some(id) = fk.get() else {
            return false;
        };
        let Some(e) = self.pins.get(&id) else {
            return false;
        };
        let lay = e.load_layout();
        lay.spent_range.is_some()
    }

    pub fn fks_missing_layout(&self) -> Vec<Fk> {
        self.pins
            .iter()
            .filter(|(_, e)| {
                let lay = e.load_layout();
                lay.spent_range.is_none()
                    && (lay.body_range.is_none() || lay.spender_rels.is_empty())
            })
            .map(|(&id, _)| Fk(id))
            .collect()
    }

    #[inline]
    pub fn contains(&self, fk: Fk) -> bool {
        fk.get().is_some_and(|id| self.pins.contains_key(&id))
    }

    pub fn get_spender_abs(&self, fk: Fk, vout: u32) -> Option<u64> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let lay = e.load_layout();
        let (off, len) = lay.spent_range?;
        let abs = rbitcoin_store::spent_abs(off, vout);
        if abs.saturating_add(rbitcoin_store::OutputRecord::SPENT_SLOT_LEN as u64)
            > off.saturating_add(len)
        {
            return None;
        }
        Some(abs)
    }

    /// Unique `(create_id, vout, abs, spend_fk)` for spend edges. Missing abs is Corrupt.
    pub fn spend_abs_jobs(
        &self,
        edges: impl IntoIterator<Item = (Fk, u32, Fk)>,
    ) -> Result<Vec<(u64, u32, u64, Fk)>, StoreError> {
        let mut out = Vec::new();
        let mut seen = U64Set::default();
        for (fk, vout, sfk) in edges {
            if fk.is_null() {
                continue;
            }
            let Some(id) = fk.get() else {
                continue;
            };
            let Some(abs) = self.get_spender_abs(fk, vout) else {
                return Err(StoreError::Corrupt(
                    "invariant: structural spentness missing pin denserels/abs (cold forbidden)",
                ));
            };
            if seen.insert(abs) {
                out.push((id, vout, abs, sfk));
            }
        }
        Ok(out)
    }

    pub fn set_spent_range_only(&mut self, fk: Fk, spent_range: (u64, u64)) {
        let Some(id) = fk.get() else {
            return;
        };
        if let Some(e) = self.pins.get(&id) {
            e.publish_layout(|cur| {
                if cur.spent_range == Some(spent_range) {
                    return None;
                }
                let mut next = cur.clone();
                next.spent_range = Some(spent_range);
                Some(next)
            });
        }
    }

    pub fn has_parent_out(&self, fk: Fk, vout: u32) -> bool {
        let Some(id) = fk.get() else {
            return false;
        };
        let Some(e) = self.pins.get(&id) else {
            return false;
        };
        e.load_outs().get(vout).is_some()
    }

    pub fn pin_covered(&self, fk: Fk, vouts: &[u32]) -> bool {
        if vouts.is_empty() {
            return true;
        }
        let Some(id) = fk.get() else {
            return false;
        };
        let Some(e) = self.pins.get(&id) else {
            return false;
        };
        e.covers_need(vouts)
    }

    /// Absorb another batch's handles (write batch). Same create → keep one Arc
    /// (prefer already-present; merge sparse fields from `other` if needed).
    pub fn extend_from(&mut self, other: Self) {
        if other.pins.is_empty() {
            return;
        }
        if self.pins.is_empty() {
            *self = other;
            return;
        }
        self.pins.reserve(other.pins.len());
        for (id, src) in other.pins {
            match self.pins.entry(id) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(src);
                }
                std::collections::hash_map::Entry::Occupied(o) => {
                    if !Arc::ptr_eq(o.get(), &src) {
                        let src_outs = src.load_outs();
                        let src_lay = src.load_layout();
                        o.get()
                            .merge_outs(src_outs.sparse_live(), src_outs.checked());
                        o.get().set_coinbase_if_known(src.coinbase_opt());
                        o.get()
                            .maybe_merge_layout(src_lay.body_range, &src_lay.spender_rels);
                    }
                }
            }
        }
    }

    #[allow(clippy::type_complexity)] // packed (fk, range) / span row is the on-disk shape
    pub fn get_parent_outs_needed(
        &self,
        fk: Fk,
        vouts: &[u32],
    ) -> Option<(TxRecord, Vec<(u32, OutputRecord)>, bool)> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let body = e.load_outs();
        let covered = !body.checked().is_empty()
            && vouts.iter().all(|v| checked_contains(body.checked(), *v));
        if covered {
            let mut live = Vec::with_capacity(vouts.len());
            for &v in vouts {
                if let Some(o) = body.get(v) {
                    live.push((v, o.clone()));
                }
            }
            return Some((e.tx.clone(), live, true));
        }
        if vouts.iter().all(|v| body.get(*v).is_some()) {
            let mut live = Vec::with_capacity(vouts.len());
            for &v in vouts {
                if let Some(o) = body.get(v) {
                    live.push((v, o.clone()));
                }
            }
            return Some((e.tx.clone(), live, false));
        }
        None
    }
}

#[inline]
fn checked_contains(checked: &[u32], v: u32) -> bool {
    checked.binary_search(&v).is_ok()
}

#[inline]
fn ensure_outs_sorted(mut outs: Vec<(u32, OutputRecord)>) -> Vec<(u32, OutputRecord)> {
    if outs.windows(2).any(|w| w[0].0 > w[1].0) {
        outs.sort_unstable_by_key(|(v, _)| *v);
    }
    outs
}

#[inline]
fn ensure_checked_sorted(mut checked: Vec<u32>) -> Vec<u32> {
    if checked.windows(2).any(|w| w[0] > w[1]) {
        checked.sort_unstable();
    }
    // Dedup only when needed (sorted unique from pin path is the common case).
    if checked.windows(2).any(|w| w[0] == w[1]) {
        checked.dedup();
    }
    checked
}

/// Merge sparse denserels by vout (prefer `src` rel when both present).
fn merge_spender_rels_into(dst: &mut Vec<(u32, u32)>, src: &[(u32, u32)]) {
    if src.is_empty() {
        return;
    }
    if dst.is_empty() {
        *dst = src.to_vec();
        return;
    }
    let mut m: U32Map<u32> = dst.iter().copied().collect();
    for &(v, r) in src {
        m.insert(v, r);
    }
    let mut merged: Vec<(u32, u32)> = m.into_iter().collect();
    merged.sort_unstable_by_key(|(v, _)| *v);
    *dst = merged;
}

/// Build sorted `(vout, rel)` for requested vouts from dense pin rels.
pub fn sparse_spender_rels(dense: &[u32], need_vouts: &[u32]) -> Vec<(u32, u32)> {
    let mut out = Vec::with_capacity(need_vouts.len());
    for &v in need_vouts {
        if let Some(&rel) = dense.get(v as usize) {
            if rel != SPENDER_REL_UNKNOWN {
                out.push((v, rel));
            }
        }
    }
    out
}

/// True when pin layout can supply abs spender meta for every `need_vout`.
pub fn layout_covers_need(
    body_range: Option<(u64, u64)>,
    sparse_rels: &[(u32, u32)],
    need_vouts: &[u32],
) -> bool {
    if body_range.is_none() || need_vouts.is_empty() {
        return body_range.is_some() && need_vouts.is_empty();
    }
    if sparse_rels.len() != need_vouts.len() {
        return false;
    }
    for (i, &v) in need_vouts.iter().enumerate() {
        if sparse_rels[i].0 != v || sparse_rels[i].1 == SPENDER_REL_UNKNOWN {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::{OutputRecord, TxRecord, U64IdentityHasher};

    fn tx(id: u8) -> TxRecord {
        let mut txid = [0u8; 32];
        txid[0] = id;
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        }
    }

    fn out(v: i64) -> OutputRecord {
        OutputRecord::unspent(v, vec![0x51])
    }

    /// Vacant CreatePin insert must keep the script allocation (no PinOuts clone).
    #[test]
    fn insert_create_pin_shares_script_bytes() {
        use crate::CreatePin;
        use std::sync::Arc;
        let script = vec![0x51u8; 4096];
        let pin: CreatePin = Arc::new((tx(9), vec![OutputRecord::unspent(50, script)]));
        let expect = pin.1[0].script.as_ptr();
        let mut bp = BatchParents::new();
        bp.insert_create_pin(
            Fk(9),
            Arc::clone(&pin),
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let got = bp
            .get_parent_txout_parts(Fk(9), 0, |v, sc, t| {
                assert_eq!(v, 50);
                assert_eq!(t[0], 9);
                sc.as_ptr()
            })
            .expect("full pin prevout");
        assert_eq!(got, expect, "CreatePin insert must not clone script bytes");
    }

    #[test]
    fn extend_from_merges_disjoint_and_same_fk() {
        let mut a = BatchParents::new();
        a.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(1))],
            vec![0],
            Some(false),
            Some((100, 50)),
            vec![(0, 10)],
        );
        let mut b = BatchParents::new();
        b.insert_owned(
            Fk(2),
            tx(2),
            vec![(0, out(2))],
            vec![0],
            Some(true),
            None,
            Vec::new(),
        );
        b.insert_owned(
            Fk(1),
            tx(1),
            vec![(1, out(3))],
            vec![1],
            None,
            None,
            vec![(1, 20)],
        );
        a.extend_from(b);
        assert_eq!(a.len(), 2);
        assert!(a.has_parent_out(Fk(1), 0));
        assert!(a.has_parent_out(Fk(1), 1));
        assert!(a.has_parent_out(Fk(2), 0));
        a.set_spent_range_only(Fk(1), (1000, 24));
        assert_eq!(a.get_spender_abs(Fk(1), 0), Some(1000));
        assert_eq!(a.get_spender_abs(Fk(1), 1), Some(1008));
        assert_eq!(a.get_parent_coinbase(Fk(1)), Some(false));
        assert_eq!(a.get_parent_coinbase(Fk(2)), Some(true));
    }

    #[test]
    fn insert_layout_coinbase_and_covered() {
        let mut bp = BatchParents::with_capacity(1);
        let live = vec![(0, out(42)), (2, out(99))];
        bp.insert_owned(
            Fk(9),
            tx(9),
            live,
            vec![0, 1, 2],
            Some(true),
            Some((1000, 200)),
            vec![(0, 50), (1, 70), (2, 90)],
        );
        assert_eq!(bp.len(), 1);
        assert!(bp.pin_covered(Fk(9), &[0, 1, 2]));
        assert!(!bp.pin_covered(Fk(9), &[0, 3]));
        assert!(!bp.has_parent_out(Fk(9), 1));
        bp.set_spent_range_only(Fk(9), (2000, 24));
        assert_eq!(bp.get_spender_abs(Fk(9), 2), Some(2016));
        assert_eq!(bp.get_body_range(Fk(9)), Some((1000, 200)));
        assert_eq!(bp.get_parent_coinbase(Fk(9)), Some(true));
        assert!(bp.has_abs_layout(Fk(9)));
        let (_, o) = bp.get_parent_out(Fk(9), 0).unwrap();
        assert_eq!(o.value, 42);
        let (v, script, parent_txid) = bp
            .get_parent_txout_parts(Fk(9), 0, |v, s, t| (v, s.to_vec(), t))
            .unwrap();
        assert_eq!(v, 42);
        assert_eq!(script, &[0x51]);
        assert_eq!(parent_txid[0], 9);
        assert!(bp.get_parent_txout_parts(Fk(9), 1, |_, _, _| ()).is_none());
    }

    #[test]
    fn parent_txout_borrows_pin_script() {
        let mut bp = BatchParents::new();
        let script = vec![0x51, 0x52, 0x53];
        bp.insert_owned(
            Fk(9),
            tx(9),
            vec![(0, OutputRecord::unspent(42, script))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let pin_ptr = {
            let e = bp.pins.get(&9).expect("pin");
            let outs = e.load_outs();
            outs.get(0).expect("vout 0").script.as_ptr()
        };
        let hit = bp
            .get_parent_txout_parts(Fk(9), 0, |value, spk, txid| {
                assert_eq!(value, 42);
                assert_eq!(spk, &[0x51, 0x52, 0x53]);
                assert_eq!(txid[0], 9);
                assert_eq!(
                    spk.as_ptr(),
                    pin_ptr,
                    "must borrow pin script bytes, not clone"
                );
                true
            })
            .expect("hit");
        assert!(hit);
    }

    #[test]
    fn set_body_range_only_completes_layout_when_rels_present() {
        let mut bp = BatchParents::with_capacity(1);
        bp.insert_owned(
            Fk(3),
            tx(3),
            vec![(0, out(1))],
            vec![0],
            None,
            None,
            vec![(0, 40)],
        );
        assert!(!bp.has_abs_layout(Fk(3)));
        bp.set_body_range_only(Fk(3), (500, 80));
        assert!(!bp.has_abs_layout(Fk(3)));
        bp.set_spent_range_only(Fk(3), (500, 16));
        assert!(bp.has_abs_layout(Fk(3)));
        assert_eq!(bp.get_spender_abs(Fk(3), 0), Some(500));
    }

    #[test]
    fn sparse_spender_rels_skips_unknown() {
        let dense = vec![10, SPENDER_REL_UNKNOWN, 30];
        let sparse = sparse_spender_rels(&dense, &[0, 1, 2]);
        assert_eq!(sparse, vec![(0, 10), (2, 30)]);
        assert!(!layout_covers_need(Some((0, 100)), &sparse, &[0, 1, 2]));
        assert!(layout_covers_need(
            Some((0, 100)),
            &[(0, 10), (2, 30)],
            &[0, 2]
        ));
        assert!(!layout_covers_need(None, &[(0, 10)], &[0]));
    }

    #[test]
    fn get_spender_abs_rejects_unknown_rel() {
        let mut bp = BatchParents::with_capacity(1);
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(1))],
            vec![0],
            None,
            Some((100, 50)),
            vec![(0, SPENDER_REL_UNKNOWN)],
        );
        assert!(bp.get_spender_abs(Fk(1), 0).is_none());
        bp.set_spent_range_only(Fk(1), (100, 8));
        assert_eq!(bp.get_spender_abs(Fk(1), 0), Some(100));
        assert!(bp.get_spender_abs(Fk(1), 1).is_none());
    }

    /// Identity hasher for pack-scale u64 keys is the raw key (no SipHash mix).
    /// Write/lookup structural maps depend on this for the measured CPU win.
    #[test]
    fn u64_identity_hasher_is_raw_key_and_map_roundtrips_pack_scale() {
        // Shipped path: store identity hasher via U64Map API.
        use std::hash::Hasher;
        let mut h = U64IdentityHasher::default();
        h.write_u64(0xdead_beef_cafe_u64);
        assert_eq!(h.finish(), 0xdead_beef_cafe_u64);

        // Pack-scale create_fk map: sequential ids must insert + get without loss.
        let n = 8_000u64;
        let mut m: U64Map<u32> = U64Map::with_capacity_and_hasher(n as usize, Default::default());
        for i in 1..=n {
            m.insert(i, (i % 1_000_000) as u32);
        }
        assert_eq!(m.len(), n as usize);
        for i in 1..=n {
            assert_eq!(m.get(&i).copied(), Some((i % 1_000_000) as u32));
        }
        // Collisions / wrong finish would drop keys under open addressing.
        assert_eq!(m.get(&0), None);
        assert_eq!(m.get(&(n + 1)), None);
    }

    #[test]
    fn vacant_insert_does_not_arcswap_until_compose() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let pin = bp.pins.get(&1).expect("vacant pin");
        assert!(
            pin.outs.rcu.get().is_none(),
            "vacant insert must not allocate ArcSwap on outs"
        );
        assert!(
            pin.layout.rcu.get().is_none(),
            "vacant insert must not allocate ArcSwap on layout"
        );
        assert!(pin.load_outs().covers_need(&[0]));
        pin.merge_outs(vec![], &[0]);
        assert!(pin.outs.rcu.get().is_none(), "no-op cover must stay Frozen");
    }

    /// Q-M3: empty checked / already-covered live must not publish a new outs Arc.
    #[test]
    fn merge_outs_empty_checked_keeps_outs_arc() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        assert!(pin.outs.rcu.get().is_none());
        let before = pin.load_outs();
        pin.merge_outs(vec![], &[]);
        assert!(
            Arc::ptr_eq(&before, &pin.load_outs()),
            "empty checked no-op must keep outs Arc"
        );
        assert!(
            pin.outs.rcu.get().is_none(),
            "empty checked no-op must stay Frozen"
        );
        pin.merge_outs(vec![(0, out(10))], &[]);
        assert!(
            Arc::ptr_eq(&before, &pin.load_outs()),
            "redundant live + empty checked must keep outs Arc"
        );
        assert!(pin.outs.rcu.get().is_none());

        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(1, out(20))],
            vec![],
            None,
            None,
            Vec::new(),
        );
        let after = pin.load_outs();
        assert!(
            after.covers_need(&[0]) && after.get(1).is_some(),
            "Occupied empty-checked new live must still widen"
        );
        assert!(!Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn merge_outs_large_script_widens_once() {
        let script = vec![0x51u8; 4096];
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        let rec = OutputRecord::unspent(20, script.clone());
        pin.merge_outs(vec![(1, rec.clone())], &[1]);
        pin.merge_outs(vec![(1, rec)], &[1]);
        let snap = pin.load_outs();
        assert_eq!(snap.live_len(), 2);
        assert_eq!(snap.get(1).expect("vout 1").script.len(), 4096);
        assert_eq!(snap.get(1).unwrap().script, script);
    }

    #[test]
    fn compose_adds_vout_without_mutating_old_snap() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        let old = pin.load_outs();
        pin.merge_outs(vec![(1, out(20))], &[1]);
        assert!(
            pin.outs.rcu.get().is_some(),
            "real compose promotes Frozen to Rcu"
        );
        let new = pin.load_outs();
        assert_eq!(old.live_len(), 1, "old snap must not gain vouts");
        assert_eq!(old.checked(), &[0]);
        assert!(new.covers_need(&[0, 1]));
        assert!(!Arc::ptr_eq(&old, &new));
    }

    /// Prep∥write on one SharedParentPin: write set_layout_for_need must not
    /// clobber checked need-vouts or denserels composed by concurrent prep.
    ///
    /// Bodies are immutable snapshots; concurrent compose publishes new Arcs
    /// under the pin lock so peer need-vouts and denserels survive.
    #[test]
    fn set_layout_merges_not_clobbers_under_concurrent_prep() {
        use std::sync::Barrier;
        use std::thread;

        let mut writer = BatchParents::with_capacity(1);
        writer.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            None,
            vec![(0, 10)],
        );
        let pin = Arc::clone(writer.pins.get(&1).expect("shared pin"));

        let barrier = Arc::new(Barrier::new(2));
        let pin_prep = Arc::clone(&pin);
        let barrier_prep = Arc::clone(&barrier);
        let prep = thread::spawn(move || {
            barrier_prep.wait();
            // Concurrent prep batch spends vout 1 of the same create.
            for _ in 0..200 {
                pin_prep.merge_outs(vec![(1, out(20))], &[1]);
                pin_prep.maybe_merge_layout(None, &[(1, 20)]);
            }
        });

        barrier.wait();
        // Write-side layout fill for this batch's need (vout 0); dense has both outs.
        for _ in 0..200 {
            writer.set_layout_for_need(Fk(1), (100, 80), &[10, 20], &[0]);
        }
        prep.join().expect("prep thread");

        // Peer need-vout must still be covered (not wiped by stale checked replace).
        assert!(
            writer.pin_covered(Fk(1), &[0, 1]),
            "checked must keep prep-merged vout 1 after write set_layout"
        );
        assert!(writer.has_parent_out(Fk(1), 1));
        writer.set_spent_range_only(Fk(1), (1000, 24));
        assert_eq!(writer.get_spender_abs(Fk(1), 0), Some(1000));
        assert_eq!(
            writer.get_spender_abs(Fk(1), 1),
            Some(1008),
            "spent abs covers peer vout after merge"
        );
    }

    /// Timed synthetic: multi-pack insert + layout compose at few-block scale.
    /// Prints ns/op so IBD regressions are visible without a criterion harness.
    ///
    /// **Probe shape matches pre-recovery baseline** (single need-vout insert) so
    /// covered/layout can be compared to `bench-baseline-*.txt`. Extra phases:
    /// - layout2: second ensure (same `set_layout_for_need` API, no-op path)
    /// - assemble: sticky vs `get_parent_txout_parts_no_sticky` (same return path)
    #[test]
    fn pin_compose_multi_pack_timed() {
        let n_parents = 8_000usize; // ~input budget scale
        let t0 = std::time::Instant::now();
        let mut a = BatchParents::with_capacity(n_parents);
        for i in 1..=n_parents as u64 {
            a.insert_owned(
                Fk(i),
                tx((i % 200) as u8),
                vec![(0, out(i as i64))],
                vec![0],
                Some(false),
                None,
                vec![(0, 10)],
            );
        }
        let insert_ns = t0.elapsed().as_nanos();

        // Covered re-insert (Occupied no-op outs).
        let t_cov = std::time::Instant::now();
        for i in 1..=n_parents as u64 {
            a.insert_owned(
                Fk(i),
                tx((i % 200) as u8),
                vec![(0, out(i as i64))],
                vec![0],
                None,
                None,
                vec![(0, 10)],
            );
        }
        let covered_ns = t_cov.elapsed().as_nanos();

        // Layout-only fill (write ensure path) — same denserels shape as baseline.
        let t_lay = std::time::Instant::now();
        for i in 1..=n_parents as u64 {
            a.set_layout_for_need(Fk(i), (i * 100, 50), &[10], &[]);
        }
        let layout_ns = t_lay.elapsed().as_nanos();

        // Second ensure pass — same API; already_covers short-circuit.
        let t_lay2 = std::time::Instant::now();
        for i in 1..=n_parents as u64 {
            a.set_layout_for_need(Fk(i), (i * 100, 50), &[10], &[]);
        }
        let layout2_ns = t_lay2.elapsed().as_nanos();

        let t1 = std::time::Instant::now();
        for i in 1..=n_parents as u64 {
            // Widen need + layout (compose publish on the same pins).
            a.insert_owned(
                Fk(i),
                tx((i % 200) as u8),
                vec![(1, out(i as i64 + 1))],
                vec![1],
                None,
                Some((i * 100, 50)),
                vec![(1, 20)],
            );
        }
        let widen_ns = t1.elapsed().as_nanos();

        // Multi-input same-parent: vouts 0 and 1 after widen.
        // Fair cold = same `parent_txout_parts` path with sticky disabled.
        let reps = 10usize;
        let n_inputs = n_parents * reps * 2;
        let t_cold = std::time::Instant::now();
        let mut sum_c = 0i64;
        for p in 1..=n_parents as u64 {
            for _ in 0..reps {
                for vout in 0u32..2 {
                    if let Some(v) = a.get_parent_txout_parts_no_sticky(Fk(p), vout, |v, _, _| v) {
                        sum_c = sum_c.wrapping_add(v);
                    }
                }
            }
        }
        let assemble_cold_ns = t_cold.elapsed().as_nanos();
        let t_asm = std::time::Instant::now();
        let mut sum = 0i64;
        for p in 1..=n_parents as u64 {
            for _ in 0..reps {
                for vout in 0u32..2 {
                    if let Some(v) = a.get_parent_txout_parts(Fk(p), vout, |v, _, _| v) {
                        sum = sum.wrapping_add(v);
                    }
                }
            }
        }
        let assemble_ns = t_asm.elapsed().as_nanos();
        assert!(sum != 0 || n_inputs == 0);
        assert_eq!(sum, sum_c);

        assert_eq!(a.len(), n_parents);
        assert!(a.pin_covered(Fk(1), &[0, 1]));
        a.set_spent_range_only(Fk(1), (1000, 24));
        assert_eq!(a.get_spender_abs(Fk(1), 1), Some(1008));
        let n = n_parents as f64;
        eprintln!(
            "pin_compose_multi_pack n={n_parents} \
             insert={:.1}ns/op covered={:.1}ns/op layout={:.1}ns/op layout2={:.1}ns/op \
             widen={:.1}ns/op assemble_sticky={:.1}ns/op assemble_nosticky={:.1}ns/op \
             (insert_ns={insert_ns} covered_ns={covered_ns} layout_ns={layout_ns} \
             layout2_ns={layout2_ns} widen_ns={widen_ns} assemble_ns={assemble_ns} \
             assemble_nosticky_ns={assemble_cold_ns} n_in={n_inputs})",
            insert_ns as f64 / n,
            covered_ns as f64 / n,
            layout_ns as f64 / n,
            layout2_ns as f64 / n,
            widen_ns as f64 / n,
            assemble_ns as f64 / n_inputs as f64,
            assemble_cold_ns as f64 / n_inputs as f64,
        );
        // Timing gates only for structural short-circuits (layout no-op, covered
        // vs widen). Sticky vs no-sticky assemble is printed for hosts/benches but
        // not asserted: alternating multi-vout walks often make sticky snap
        // overhead match or exceed cold under debug + parallel load (see
        // sticky_and_nosticky_txout_parts_match for functional equality).
        // Floor avoids inverting layout/covered when both are sub-ms noise.
        const TIMING_FLOOR_NS: u128 = 2_000_000; // 2ms
        if layout_ns > TIMING_FLOOR_NS {
            assert!(
                layout2_ns < layout_ns,
                "layout no-op must beat first ensure: layout={layout_ns} layout2={layout2_ns}"
            );
        }
        // Sanity bound: free-plan insert should stay well under 50µs/op even in debug.
        assert!(
            insert_ns / (n_parents as u128) < 50_000,
            "insert ns/op too high: {}",
            insert_ns / n_parents as u128
        );
        // Covered re-insert should be cheaper than real widen when both are hot.
        if widen_ns > TIMING_FLOOR_NS && covered_ns > TIMING_FLOOR_NS / 4 {
            assert!(
                covered_ns < widen_ns,
                "covered re-insert should beat widen: covered={covered_ns} widen={widen_ns}"
            );
        }
    }

    /// Sticky and no-sticky assemble APIs return identical prevout parts.
    #[test]
    fn sticky_and_nosticky_txout_parts_match() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(3),
            tx(3),
            vec![(0, out(11)), (1, out(22))],
            vec![0, 1],
            Some(false),
            None,
            Vec::new(),
        );
        for vout in [0u32, 1] {
            let s = bp
                .get_parent_txout_parts(Fk(3), vout, |v, sc, t| (v, sc.to_vec(), t))
                .unwrap();
            let c = bp
                .get_parent_txout_parts_no_sticky(Fk(3), vout, |v, sc, t| (v, sc.to_vec(), t))
                .unwrap();
            assert_eq!(s.0, c.0);
            assert_eq!(s.1, c.1);
            assert_eq!(s.2, c.2);
        }
    }

    /// Sticky outs: consecutive same-parent lookups share one Arc (no re-load).
    #[test]
    fn sticky_assemble_reuses_outs_arc() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(7),
            tx(7),
            vec![(0, out(10)), (1, out(20)), (2, out(30))],
            vec![0, 1, 2],
            Some(false),
            None,
            Vec::new(),
        );
        let (v0, s0, t0) = bp
            .get_parent_txout_parts(Fk(7), 0, |v, s, t| (v, s.to_vec(), t))
            .unwrap();
        let (v1, s1, t1) = bp
            .get_parent_txout_parts(Fk(7), 1, |v, s, t| (v, s.to_vec(), t))
            .unwrap();
        let pin = std::sync::Arc::clone(bp.pins.get(&7).unwrap());
        let outs = pin.load_outs();
        let before = std::sync::Arc::strong_count(&outs);
        bp.get_parent_txout_parts(Fk(7), 1, |_, _, _| {
            assert_eq!(
                std::sync::Arc::strong_count(&outs),
                before,
                "sticky hit must borrow, not Arc::clone"
            );
        })
        .unwrap();
        let (v2, s2, t2) = bp
            .get_parent_txout_parts(Fk(7), 2, |v, s, t| (v, s.to_vec(), t))
            .unwrap();
        assert_eq!(v0, 10);
        assert_eq!(v1, 20);
        assert_eq!(v2, 30);
        assert_eq!(s0, vec![0x51]);
        assert_eq!(s1, vec![0x51]);
        assert_eq!(s2, vec![0x51]);
        assert_eq!(t0[0], 7);
        assert_eq!(t1[0], 7);
        assert_eq!(t2[0], 7);
        // Sticky holds parent 7.
        assert_eq!(bp.sticky_outs.borrow().as_ref().map(|(id, _)| *id), Some(7));
        // Switch parent clears sticky to new id.
        bp.insert_owned(
            Fk(8),
            tx(8),
            vec![(0, out(99))],
            vec![0],
            None,
            None,
            Vec::new(),
        );
        bp.get_parent_txout_parts(Fk(8), 0, |_, _, _| ()).unwrap();
        assert_eq!(bp.sticky_outs.borrow().as_ref().map(|(id, _)| *id), Some(8));
    }

    /// Pure share-hit refresh with empty meta is a no-op (no layout store).
    #[test]
    fn refresh_pin_meta_empty_is_noop() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(1))],
            vec![0],
            Some(false),
            Some((100, 50)),
            vec![(0, 10)],
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        let lay_before = pin.load_layout();
        bp.refresh_pin_meta(Fk(1), None, None, Vec::new());
        let lay_after = pin.load_layout();
        assert!(Arc::ptr_eq(&lay_before, &lay_after));
    }

    /// Pure compose helpers: widening need and layout builds new halves without
    /// mutating the source snapshots (AGENTS prefer-immutable).
    #[test]
    fn pin_body_compose_does_not_mutate_source() {
        let pin = SharedParentPin::new(
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            Some((100, 50)),
            vec![(0, 10)],
        );
        let before_outs = pin.load_outs();
        let before_lay = pin.load_layout();
        pin.merge_outs(vec![(1, out(20))], &[1]);
        pin.maybe_merge_layout(None, &[(1, 20)]);
        let after_outs = pin.load_outs();
        let after_lay = pin.load_layout();
        // Source snapshots unchanged.
        assert_eq!(before_outs.live_len(), 1);
        assert_eq!(before_outs.checked(), &[0]);
        assert_eq!(before_lay.spender_rels, vec![(0, 10)]);
        // Published halves have the union.
        assert_eq!(after_outs.live_len(), 2);
        assert!(after_outs.covers_need(&[0, 1]));
        assert_eq!(after_lay.spender_rels, vec![(0, 10), (1, 20)]);
        assert!(
            !Arc::ptr_eq(&before_outs, &after_outs),
            "outs compose must publish new Arc"
        );
        assert!(
            !Arc::ptr_eq(&before_lay, &after_lay),
            "layout compose must publish new Arc"
        );
    }

    /// Covered share hit must not replace outs Arc (no full clone on no-op).
    #[test]
    fn covered_insert_keeps_outs_arc_identity() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            Some(false),
            Some((100, 50)),
            vec![(0, 10)],
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        let outs_before = pin.load_outs();
        let lay_before = pin.load_layout();
        // Same need already covered — free-pin share hit.
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10))],
            vec![0],
            None,
            Some((100, 50)),
            vec![(0, 10)],
        );
        let outs_after = pin.load_outs();
        let lay_after = pin.load_layout();
        assert!(
            Arc::ptr_eq(&outs_before, &outs_after),
            "no-op outs must keep Arc identity (no clone)"
        );
        assert!(
            Arc::ptr_eq(&lay_before, &lay_after),
            "no-op layout must keep Arc identity"
        );
    }

    /// Layout-only write must not replace outs Arc (scripts stay shared).
    #[test]
    fn layout_only_write_keeps_outs_arc() {
        let mut bp = BatchParents::new();
        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10)), (1, out(20))],
            vec![0, 1],
            Some(false),
            None,
            vec![(0, 10)],
        );
        let pin = Arc::clone(bp.pins.get(&1).unwrap());
        let outs_before = pin.load_outs();
        bp.set_layout_for_need(Fk(1), (500, 80), &[10, 20], &[]);
        let outs_after = pin.load_outs();
        let lay = pin.load_layout();
        assert!(
            Arc::ptr_eq(&outs_before, &outs_after),
            "layout fill must not clone outs half"
        );
        assert_eq!(lay.body_range, Some((500, 80)));
        bp.set_spent_range_only(Fk(1), (800, 24));
        assert_eq!(bp.get_spender_abs(Fk(1), 1), Some(808));
    }

    /// `set_layout_sparse` / `set_body_range_only` edges on missing pins.
    #[test]
    fn layout_sparse_and_body_range_only_surface() {
        let mut bp = BatchParents::with_capacity(8);
        // Null / missing pin early-outs (set_layout_sparse + set_body_range_only).
        bp.set_layout_sparse(Fk::NULL, (0, 10), vec![(0, 1)], &[]);
        bp.set_layout_sparse(Fk(99), (0, 10), vec![(0, 1)], &[0]);
        bp.set_body_range_only(Fk::NULL, (1, 2));
        bp.set_body_range_only(Fk(99), (1, 2));
        bp.set_layout(Fk::NULL, (0, 1), &[1]);
        bp.set_layout_for_need(Fk(99), (0, 1), &[1], &[]);

        bp.insert_owned(
            Fk(1),
            tx(1),
            vec![(0, out(10)), (1, out(20))],
            vec![0],
            Some(false),
            None,
            Vec::new(),
        );
        bp.insert_owned(
            Fk(2),
            tx(2),
            vec![(0, out(30))],
            vec![0],
            Some(false),
            Some((100, 40)),
            vec![(0, 5)],
        );

        // Grow checked via extra_need, then fill sparse layout.
        bp.set_layout_sparse(Fk(1), (200, 50), vec![(0, 7), (1, 8)], &[1]);
        assert!(bp.has_parent_out(Fk(1), 0));
        assert_eq!(bp.get_body_range(Fk(1)), Some((200, 50)));
        assert!(!bp.has_abs_layout(Fk(1)));
        bp.set_spent_range_only(Fk(1), (200, 24));
        assert!(bp.has_abs_layout(Fk(1)));
        // No-op when layout already covers same range+rels.
        bp.set_layout_sparse(Fk(1), (200, 50), vec![(0, 7), (1, 8)], &[]);
        assert_eq!(bp.get_spender_abs(Fk(1), 1), Some(208));

        // set_body_range_only updates range; same range is no-op.
        bp.set_body_range_only(Fk(2), (300, 60));
        assert_eq!(bp.get_body_range(Fk(2)), Some((300, 60)));
        bp.set_body_range_only(Fk(2), (300, 60));
        assert_eq!(bp.get_body_range(Fk(2)), Some((300, 60)));
    }

    #[test]
    fn spend_abs_jobs_unique_and_missing_is_corrupt() {
        let mut bp = BatchParents::new();
        bp.insert_owned(Fk(1), tx(1), vec![(0, out(1))], vec![0], None, None, vec![]);
        bp.set_spent_range_only(Fk(1), (1000, 24));
        let jobs = bp
            .spend_abs_jobs([(Fk(1), 0, Fk(9)), (Fk::NULL, 0, Fk(9)), (Fk(1), 0, Fk(9))])
            .expect("abs");
        assert_eq!(
            jobs,
            vec![(1, 0, rbitcoin_store::spent_abs(1000, 0), Fk(9))]
        );
        let err = bp.spend_abs_jobs([(Fk(2), 0, Fk(9))]).unwrap_err();
        assert!(
            err.to_string().contains("missing pin denserels/abs"),
            "got {err}"
        );
    }

    /// has_abs_layout null and missing pins.
    #[test]
    fn has_layout_helpers_null_and_missing() {
        let bp = BatchParents::new();
        assert!(!bp.has_abs_layout(Fk::NULL));
        assert!(!bp.has_abs_layout(Fk(1)));
        assert!(bp.get_parent_tx(Fk::NULL).is_none());
        assert!(bp.get_parent_coinbase(Fk::NULL).is_none());
        assert!(bp.get_body_range(Fk::NULL).is_none());
    }
}
