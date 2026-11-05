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

/// Script bytes a confirm job can hold after the pin map is dropped.
///
/// `Wire` is `(tx_index, vout)` inside the job's wire block. The job already
/// holds that `Arc<Block>`, so the prevout does not clone it. `Pinned` is one
/// vout inside the pin's outs `Arc` (records `Vec` or range-fill
/// `OutputRecord`), not a second copy.
#[derive(Clone, Debug)]
pub enum SharedPrevoutScript {
    Wire { tx_index: u32, vout: u32 },
    Pinned(PinnedOuts),
}

/// One vout of a published pin-outs snapshot.
#[derive(Clone, Debug)]
pub struct PinnedOuts {
    pub outs: Arc<PinOuts>,
    pub vout: u32,
}

impl rbitcoin_consensus::block::PinParts for PinOuts {
    fn parts(&self, vout: u32) -> Option<(u64, &[u8])> {
        self.get_parts(vout)
    }
}

impl SharedPrevoutScript {
    /// Amount and script for a pinned vout. `None` for [`Self::Wire`] (the
    /// block lives on the script job) and when the vout is absent.
    pub fn parts(&self) -> Option<(u64, &[u8])> {
        match self {
            Self::Wire { .. } => None,
            Self::Pinned(p) => p.outs.get_parts(p.vout),
        }
    }

    /// Same allocation the pin published. The script bytes are not copied.
    pub fn into_shared_prevout(self) -> rbitcoin_consensus::block::SharedPrevout {
        use rbitcoin_consensus::block::SharedPrevout;
        match self {
            Self::Wire { tx_index, vout } => SharedPrevout::Wire { tx_index, vout },
            Self::Pinned(p) => SharedPrevout::Pinned {
                outs: p.outs,
                vout: p.vout,
            },
        }
    }
}

#[doc(hidden)]
pub const CB_UNKNOWN: u8 = 0;
#[doc(hidden)]
pub const CB_FALSE: u8 = 1;
#[doc(hidden)]
pub const CB_TRUE: u8 = 2;

/// Immutable pin outs (compose → publish, never mutate).
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum PinOuts {
    /// Plan / in-flight: share the CreatePin Arc.
    ///
    /// `block` is a clone taken while the pin still holds the decoded block.
    /// Script jobs borrow that clone, so Class A can drop the pin's clone
    /// without freeing the bytes under an in-flight `parts` call. After the
    /// pin publishes its output blob, `get_parts` borrows the blob instead.
    Full {
        pin: crate::CreatePin,
        block: Option<Arc<bitcoin::Block>>,
        checked: Vec<u32>,
    },
    /// Range-fill: owned sparse decoded outs.
    Sparse {
        outs: Vec<(u32, OutputRecord)>,
        checked: Vec<u32>,
    },
}

impl PinOuts {
    #[doc(hidden)]
    pub fn new(live: Vec<(u32, OutputRecord)>, checked: Vec<u32>) -> Self {
        Self::Sparse {
            outs: ensure_outs_sorted(live),
            checked: ensure_checked_sorted(checked),
        }
    }

    #[doc(hidden)]
    pub fn full(pin: crate::CreatePin, checked: Vec<u32>) -> Self {
        let block = pin.clone_wire_block();
        Self::Full {
            pin,
            block,
            checked: ensure_checked_sorted(checked),
        }
    }

    #[doc(hidden)]
    pub fn checked(&self) -> &[u32] {
        match self {
            Self::Full { checked, .. } | Self::Sparse { checked, .. } => checked,
        }
    }

    #[doc(hidden)]
    pub fn with_checked(&self, checked: Vec<u32>) -> Self {
        let checked = ensure_checked_sorted(checked);
        match self {
            Self::Full { pin, block, .. } => Self::Full {
                pin: std::sync::Arc::clone(pin),
                block: block.clone(),
                checked,
            },
            Self::Sparse { outs, .. } => Self::Sparse {
                outs: outs.clone(),
                checked,
            },
        }
    }

    #[doc(hidden)]
    pub fn get_parts(&self, vout: u32) -> Option<(u64, &[u8])> {
        match self {
            Self::Full { pin, block, .. } => {
                if let Some(parts) = pin.out_parts(vout) {
                    return Some(parts);
                }
                let block = block.as_ref()?;
                let tx_index = pin.wire_tx_index()?;
                let o = block
                    .txdata
                    .get(tx_index as usize)?
                    .output
                    .get(vout as usize)?;
                Some((o.value.to_sat(), o.script_pubkey.as_bytes()))
            }
            Self::Sparse { outs, .. } => {
                let i = outs.binary_search_by_key(&vout, |(v, _)| *v).ok()?;
                Some((outs[i].1.value, outs[i].1.script.as_slice()))
            }
        }
    }

    #[doc(hidden)]
    pub fn covers_need(&self, need: &[u32]) -> bool {
        if need.is_empty() {
            return true;
        }
        let checked = self.checked();
        if checked.is_empty() {
            return false;
        }
        need.iter().all(|v| checked_contains(checked, *v))
    }

    /// `covers_need` plus a stored script for every vout.
    ///
    /// The checked list can name a vout this pin never stored.
    fn holds_checked_scripts(&self, vouts: &[u32]) -> bool {
        self.covers_need(vouts) && vouts.iter().all(|&v| self.get_parts(v).is_some())
    }

    #[doc(hidden)]
    pub fn has_all_live(&self, live: &[(u32, OutputRecord)]) -> bool {
        live.iter().all(|(v, _)| self.get_parts(*v).is_some())
    }

    #[doc(hidden)]
    pub fn already_covers(&self, live: &[(u32, OutputRecord)], checked: &[u32]) -> bool {
        self.covers_need(checked) && (live.is_empty() || self.has_all_live(live))
    }

    /// Checked-list widen when every `extra` vout already lives in this create.
    ///
    /// `None` for a sparse pin, and for a vout this create does not have.
    fn union_full_checked(&self, extra: &[u32]) -> Option<Self> {
        match self {
            Self::Full {
                pin,
                block,
                checked,
            } if extra.iter().all(|&v| pin.contains_vout(v)) => Some(Self::Full {
                pin: std::sync::Arc::clone(pin),
                block: block.clone(),
                checked: union_vouts(checked, extra),
            }),
            _ => None,
        }
    }

    #[doc(hidden)]
    pub fn sparse_live(&self) -> Vec<(u32, OutputRecord)> {
        match self {
            Self::Sparse { outs, .. } => outs.clone(),
            Self::Full { pin, checked, .. } => checked
                .iter()
                .filter_map(|&v| pin.out_record(v).map(|o| (v, o)))
                .collect(),
        }
    }

    /// Compose wider need coverage (new half; does not mutate `self`).
    #[doc(hidden)]
    pub fn compose(&self, live: &[(u32, OutputRecord)], checked: &[u32]) -> Self {
        match self {
            Self::Full {
                pin,
                block,
                checked: ch,
            } => {
                let extra = live.iter().any(|(v, _)| !pin.contains_vout(*v));
                if extra {
                    let mut outs = self.sparse_live();
                    for (v, o) in live {
                        if outs.binary_search_by_key(v, |(dv, _)| *dv).is_err() {
                            outs.push((*v, o.clone()));
                        }
                    }
                    outs.sort_unstable_by_key(|(v, _)| *v);
                    Self::Sparse {
                        outs,
                        checked: union_vouts(ch, checked),
                    }
                } else {
                    Self::Full {
                        pin: std::sync::Arc::clone(pin),
                        block: block.clone(),
                        checked: union_vouts(ch, checked),
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
                Self::Sparse {
                    outs: next_outs,
                    checked: union_vouts(ch, checked),
                }
            }
        }
    }
}

/// `txout` range + `spent` range. Abs = spent_off + 9×vout (no denserels).
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct ParentLayout {
    pub body_range: Option<(u64, u64)>,
    pub spent_range: Option<(u64, u64)>,
    pub spender_rels: Vec<(u32, u32)>,
}

impl ParentLayout {
    #[doc(hidden)]
    pub fn new(body_range: Option<(u64, u64)>, spender_rels: Vec<(u32, u32)>) -> Self {
        Self {
            body_range,
            spent_range: None,
            spender_rels,
        }
    }

    #[doc(hidden)]
    pub fn already_covers(
        &self,
        body_range: Option<(u64, u64)>,
        spender_rels: &[(u32, u32)],
    ) -> bool {
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
    #[doc(hidden)]
    pub fn compose(&self, body_range: Option<(u64, u64)>, spender_rels: &[(u32, u32)]) -> Self {
        let mut layout = self.clone();
        if layout.body_range.is_none() {
            layout.body_range = body_range;
        }
        merge_spender_rels_into(&mut layout.spender_rels, spender_rels);
        layout
    }

    /// Write-path: force body_range and merge denserels.
    #[doc(hidden)]
    pub fn compose_write(&self, body_range: (u64, u64), sparse_rels: &[(u32, u32)]) -> Self {
        let mut layout = self.clone();
        layout.body_range = Some(body_range);
        merge_spender_rels_into(&mut layout.spender_rels, sparse_rels);
        layout
    }
}

/// Frozen until the first real compose, then [`ArcSwap`] RCU.
#[derive(Debug)]
#[doc(hidden)]
pub struct PinHalf<T> {
    pub frozen: Arc<T>,
    pub rcu: OnceLock<ArcSwap<T>>,
}

impl<T> PinHalf<T> {
    #[doc(hidden)]
    pub fn new(val: T) -> Self {
        Self {
            frozen: Arc::new(val),
            rcu: OnceLock::new(),
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn load(&self) -> Arc<T> {
        match self.rcu.get() {
            Some(s) => s.load_full(),
            None => Arc::clone(&self.frozen),
        }
    }

    #[doc(hidden)]
    pub fn rcu(&self, f: impl Fn(&Arc<T>) -> Arc<T>) {
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
    pub tx: TxRecord,
    /// 0 unknown, 1 not coinbase, 2 coinbase.
    pub coinbase: AtomicU8,
    /// Sparse need outs + checked (prep widen).
    pub outs: PinHalf<PinOuts>,
    /// Abs layout for spentness/annotate (write fill).
    pub layout: PinHalf<ParentLayout>,
}

impl SharedParentPin {
    #[doc(hidden)]
    pub fn new(
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

    #[doc(hidden)]
    pub fn new_full(
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
        let tx = pin.tx().clone();
        Self {
            tx,
            coinbase: AtomicU8::new(cb),
            outs: PinHalf::new(PinOuts::full(pin, checked)),
            layout: PinHalf::new(ParentLayout::new(body_range, spender_rels)),
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn load_outs(&self) -> Arc<PinOuts> {
        self.outs.load()
    }

    #[inline]
    #[doc(hidden)]
    pub fn load_layout(&self) -> Arc<ParentLayout> {
        self.layout.load()
    }

    /// Compose outs half: `None` = no-op (keep existing Arc identity).
    ///
    /// Uses RCU so concurrent widens from peer batches merge correctly.
    #[doc(hidden)]
    pub fn publish_outs(&self, f: impl Fn(&PinOuts) -> Option<PinOuts>) {
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
    #[doc(hidden)]
    pub fn publish_layout(&self, f: impl Fn(&ParentLayout) -> Option<ParentLayout>) {
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
    #[doc(hidden)]
    pub fn covers_need(&self, need: &[u32]) -> bool {
        self.load_outs().covers_need(need)
    }

    /// Union `src` into this pin.
    ///
    /// An in-window pin already holds every output of its create, so a wider
    /// checked list does not copy those scripts. A checked vout with no stored
    /// script still takes the source record.
    fn absorb_outs(&self, src: &PinOuts) {
        let extra = src.checked();
        if self.load_outs().holds_checked_scripts(extra) {
            return;
        }
        self.outs.rcu(|cur| {
            if cur.holds_checked_scripts(extra) {
                Arc::clone(cur)
            } else if let Some(next) = cur.union_full_checked(extra) {
                Arc::new(next)
            } else {
                Arc::new(cur.compose(&src.sparse_live(), extra))
            }
        });
    }

    /// No-op (empty / already-covered `checked`+`live`) keeps the outs Arc.
    #[doc(hidden)]
    pub fn merge_outs(&self, live: Vec<(u32, OutputRecord)>, checked: &[u32]) {
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

    #[doc(hidden)]
    pub fn set_coinbase_if_known(&self, coinbase: Option<bool>) {
        if let Some(b) = coinbase {
            let v = if b { CB_TRUE } else { CB_FALSE };
            let _ =
                self.coinbase
                    .compare_exchange(CB_UNKNOWN, v, Ordering::Relaxed, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn coinbase_opt(&self) -> Option<bool> {
        match self.coinbase.load(Ordering::Relaxed) {
            CB_TRUE => Some(true),
            CB_FALSE => Some(false),
            _ => None,
        }
    }

    /// Publish layout only when something new is present.
    #[doc(hidden)]
    pub fn maybe_merge_layout(&self, body_range: Option<(u64, u64)>, spender_rels: &[(u32, u32)]) {
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
    #[doc(hidden)]
    pub fn apply_pin_delta(
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
    #[doc(hidden)]
    pub fn apply_meta_only(
        &self,
        coinbase: Option<bool>,
        body_range: Option<(u64, u64)>,
        spender_rels: &[(u32, u32)],
    ) {
        self.set_coinbase_if_known(coinbase);
        self.maybe_merge_layout(body_range, spender_rels);
    }
}

/// Pin map shared with script-pool jobs. No sticky cache (`BatchParents` is
/// not `Sync`).
#[derive(Clone, Debug, Default)]
pub struct ParentPinView {
    pub pins: U64Map<Arc<SharedParentPin>>,
}

impl ParentPinView {
    /// Value, script bytes, and parent txid. Always loads the outs `Arc`
    /// (no sticky cache).
    pub fn txout_parts(&self, fk: Fk, vout: u32) -> Option<(u64, Vec<u8>, [u8; 32])> {
        let id = fk.get()?;
        let pin = self.pins.get(&id)?;
        let outs = pin.load_outs();
        let (value, script) = outs.get_parts(vout)?;
        Some((value, script.to_vec(), pin.tx.txid))
    }
}

/// Per-batch handle map: `create_fk → Arc` shared pin (refcount only on clone).
///
/// Assemble sticky (`sticky_outs`) is batch-local and not shared across clones.
#[derive(Debug, Default)]
pub struct BatchParents {
    pub pins: U64Map<Arc<SharedParentPin>>,
    /// Last outs Arc loaded for assemble (`get_parent_txout_parts`).
    pub sticky_outs: RefCell<Option<(u64, Arc<PinOuts>)>>,
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
    #[doc(hidden)]
    pub fn invalidate_sticky(&self, id: u64) {
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
                    let live = checked
                        .iter()
                        .filter_map(|&v| pin.out_record(v).map(|o| (v, o)))
                        .collect::<Vec<_>>();
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
        let (value, script) = outs.get_parts(vout)?;
        Some((e.tx.clone(), OutputRecord::unspent(value, script.to_vec())))
    }

    /// Pin outs `Arc` for `vout`, plus the parent txid.
    ///
    /// Uses the sticky outs cache. The script bytes stay in that snapshot.
    pub fn share_parent_prevout(
        &self,
        fk: Fk,
        vout: u32,
    ) -> Option<(SharedPrevoutScript, [u8; 32])> {
        let (outs, txid) = self.load_parent_outs(fk, vout)?;
        Some((SharedPrevoutScript::Pinned(PinnedOuts { outs, vout }), txid))
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
        f: impl FnOnce(u64, &[u8], [u8; 32]) -> R,
    ) -> Option<R> {
        self.parent_txout_parts_inner(fk, vout, f)
    }

    /// Clone the pin `Arc`s for script-pool jobs. The sticky cache stays here.
    pub fn pin_view(&self) -> ParentPinView {
        ParentPinView {
            pins: self.pins.clone(),
        }
    }

    #[doc(hidden)]
    pub fn load_parent_outs(&self, fk: Fk, vout: u32) -> Option<(Arc<PinOuts>, [u8; 32])> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let txid = e.tx.txid;
        {
            let st = self.sticky_outs.borrow();
            if let Some((sid, snap)) = st.as_ref() {
                if *sid == id && snap.get_parts(vout).is_some() {
                    return Some((Arc::clone(snap), txid));
                }
            }
        }
        let snap = e.load_outs();
        snap.get_parts(vout)?;
        *self.sticky_outs.borrow_mut() = Some((id, Arc::clone(&snap)));
        Some((snap, txid))
    }

    #[doc(hidden)]
    pub fn parent_txout_parts_inner<R>(
        &self,
        fk: Fk,
        vout: u32,
        f: impl FnOnce(u64, &[u8], [u8; 32]) -> R,
    ) -> Option<R> {
        let id = fk.get()?;
        let e = self.pins.get(&id)?;
        let txid = e.tx.txid;
        {
            let st = self.sticky_outs.borrow();
            if let Some((sid, snap)) = st.as_ref() {
                if *sid == id {
                    if let Some((value, script)) = snap.get_parts(vout) {
                        return Some(f(value, script, txid));
                    }
                }
            }
        }
        let snap = e.load_outs();
        let (value, script) = snap.get_parts(vout)?;
        *self.sticky_outs.borrow_mut() = Some((id, Arc::clone(&snap)));
        Some(f(value, script, txid))
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
    #[allow(clippy::type_complexity)] // packed (id, vout, abs, spend_fk, vin)
    pub fn spend_abs_jobs(
        &self,
        edges: impl IntoIterator<Item = (Fk, u32, Fk, u32)>,
    ) -> Result<Vec<(u64, u32, u64, Fk, u32)>, StoreError> {
        let mut out = Vec::new();
        let mut seen = U64Set::default();
        self.spend_abs_jobs_into(edges, &mut out, &mut seen)?;
        Ok(out)
    }

    /// Append into caller buffers. `out` and `seen` must already be cleared for this block.
    #[allow(clippy::type_complexity)]
    pub fn spend_abs_jobs_into(
        &self,
        edges: impl IntoIterator<Item = (Fk, u32, Fk, u32)>,
        out: &mut Vec<(u64, u32, u64, Fk, u32)>,
        seen: &mut U64Set,
    ) -> Result<(), StoreError> {
        for (fk, vout, sfk, vin) in edges {
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
                out.push((id, vout, abs, sfk, vin));
            }
        }
        Ok(())
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
        e.load_outs().get_parts(vout).is_some()
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
                        o.get().absorb_outs(src_outs.as_ref());
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
                if let Some((value, script)) = body.get_parts(v) {
                    live.push((v, OutputRecord::unspent(value, script.to_vec())));
                }
            }
            return Some((e.tx.clone(), live, true));
        }
        if vouts.iter().all(|v| body.get_parts(*v).is_some()) {
            let mut live = Vec::with_capacity(vouts.len());
            for &v in vouts {
                if let Some((value, script)) = body.get_parts(v) {
                    live.push((v, OutputRecord::unspent(value, script.to_vec())));
                }
            }
            return Some((e.tx.clone(), live, false));
        }
        None
    }
}

fn union_vouts(checked: &[u32], extra: &[u32]) -> Vec<u32> {
    let mut next = Vec::with_capacity(checked.len().saturating_add(extra.len()));
    next.extend_from_slice(checked);
    next.extend_from_slice(extra);
    next.sort_unstable();
    next.dedup();
    next
}

#[inline]
#[doc(hidden)]
pub fn checked_contains(checked: &[u32], v: u32) -> bool {
    checked.binary_search(&v).is_ok()
}

#[inline]
#[doc(hidden)]
pub fn ensure_outs_sorted(mut outs: Vec<(u32, OutputRecord)>) -> Vec<(u32, OutputRecord)> {
    if outs.windows(2).any(|w| w[0].0 > w[1].0) {
        outs.sort_unstable_by_key(|(v, _)| *v);
    }
    outs
}

#[inline]
#[doc(hidden)]
pub fn ensure_checked_sorted(mut checked: Vec<u32>) -> Vec<u32> {
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
#[doc(hidden)]
pub fn merge_spender_rels_into(dst: &mut Vec<(u32, u32)>, src: &[(u32, u32)]) {
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
