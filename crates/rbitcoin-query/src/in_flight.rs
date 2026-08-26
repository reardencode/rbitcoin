//! Immutable prep-ahead in-flight create material (confirm pipeline Phase A).
//!
//! **Publish model:** each planned pack becomes an [`InFlightLayer`] (frozen
//! maps of create pins). The plan thread appends layers to an [`InFlightLog`]
//! and hands prep an [`InFlightView`] (Arc slice of layers). Prior layers are
//! never mutated — no `Arc::make_mut` of a shared whole-map while prep holds a
//! snapshot.
//!
//! **Prune:** drop a layer only when **both** drain has inserted its create-fk
//! span (`fk_hi <= drain_fk`) **and** the fence covers that span. TipOnly is
//! fence-connected; drain alone is not a home. Either signal alone keeps the
//! layer (Class C ∥ drain/seal). Call after pin — stamp skips `body_range`
//! when this map still has CreatePin outs.
//!
//! Per-key [`InFlightView::get_out`] / `get_create_fk` is newest→oldest (O(L)).
//! Bulk skip/adopt over many parents must iterate outs (O(pins)), not
//! parents×L — post-milestone unique parents dwarf pipeline CreatePins.

use crate::archive::CreatePin;
use crate::U64Map;
use rbitcoin_primitives::Fk;
use std::collections::HashMap;
use std::sync::Arc;

/// One planned pack's published creates (immutable after construction).
#[derive(Debug, Clone)]
pub struct InFlightLayer {
    creates: HashMap<[u8; 32], Fk>,
    outs: U64Map<CreatePin>,
    /// Highest block height in this pack. [`None`] = untagged (tip prune keeps it).
    max_height: Option<u32>,
    /// Inclusive create-fk span (drain + fence prune).
    fk_lo: Option<u64>,
    fk_hi: Option<u64>,
    /// Occupancy bytes computed at build (no per-pack script walk).
    approx_bytes: u64,
}

impl InFlightLayer {
    /// Build from planned fks + batch_pin (or packed pin half) Arc clones.
    pub fn from_plan_pins<'a>(pins: impl IntoIterator<Item = (Fk, &'a CreatePin)>) -> Self {
        let mut creates = HashMap::new();
        let mut outs = U64Map::default();
        let mut fk_lo: Option<u64> = None;
        let mut fk_hi: Option<u64> = None;
        for (fk, pin) in pins {
            creates.insert(pin.0.txid, fk);
            if let Some(id) = fk.get() {
                outs.insert(id, Arc::clone(pin));
                fk_lo = Some(fk_lo.map_or(id, |l| l.min(id)));
                fk_hi = Some(fk_hi.map_or(id, |h| h.max(id)));
            }
        }
        let approx_bytes = layer_approx_bytes(&creates, &outs);
        Self {
            creates,
            outs,
            max_height: None,
            fk_lo,
            fk_hi,
            approx_bytes,
        }
    }

    /// Tag the pack's highest height so tip prune can drop it after confirm.
    pub fn with_max_height(mut self, height: u32) -> Self {
        self.max_height = Some(height);
        self
    }

    /// Creates-only layer (txid→fk) for already-archived packs without denserels pins.
    ///
    /// Lookup tip-ahead needs parent create_fk resolution while Class A of prior
    /// heights is already on disk but may still be mid-head-insert; publishing
    /// txid→fk here bridges the gap without requiring full CreatePin outs.
    pub fn from_txid_fks(pairs: impl IntoIterator<Item = ([u8; 32], Fk)>) -> Self {
        let mut creates = HashMap::new();
        let mut fk_lo: Option<u64> = None;
        let mut fk_hi: Option<u64> = None;
        for (txid, fk) in pairs {
            creates.insert(txid, fk);
            if let Some(id) = fk.get() {
                fk_lo = Some(fk_lo.map_or(id, |l| l.min(id)));
                fk_hi = Some(fk_hi.map_or(id, |h| h.max(id)));
            }
        }
        let outs = U64Map::default();
        let approx_bytes = layer_approx_bytes(&creates, &outs);
        Self {
            creates,
            outs,
            max_height: None,
            fk_lo,
            fk_hi,
            approx_bytes,
        }
    }

    /// Drain inserted the span **and** TipOnly would accept it (fence).
    fn head_ready(&self, fence: &rbitcoin_store::HeightFence, drain_fk: u64) -> bool {
        let (Some(lo), Some(hi)) = (self.fk_lo, self.fk_hi) else {
            return false;
        };
        drain_fk > 0 && hi <= drain_fk && fence.covers_fk_span(lo, hi)
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.outs.is_empty()
    }

    pub fn outs_len(&self) -> usize {
        self.outs.len()
    }
}

fn layer_approx_bytes(creates: &HashMap<[u8; 32], Fk>, outs: &U64Map<CreatePin>) -> u64 {
    let mut bytes = (creates.len().saturating_add(outs.len()) as u64).saturating_mul(40);
    for pin in outs.values() {
        bytes = bytes.saturating_add(crate::archive::create_pin_approx_bytes(pin) as u64);
    }
    bytes
}

/// Plan-owned append-only log of immutable layers.
#[derive(Debug, Default, Clone)]
pub struct InFlightLog {
    layers: Vec<Arc<InFlightLayer>>,
}

impl InFlightLog {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Publish one pack. Does not mutate existing layers.
    ///
    /// A layer with only `creates` (no outs) is still published — plan=None
    /// archived packs use creates-only for tip-ahead parent resolve.
    pub fn note_layer(&mut self, layer: InFlightLayer) {
        if layer.creates.is_empty() && layer.outs.is_empty() {
            return;
        }
        self.layers.push(Arc::new(layer));
    }

    /// Drop layers at or above a disconnected height (reorg). Untagged stay.
    pub fn drop_from_height(&mut self, height: u32) {
        if self.layers.is_empty() {
            return;
        }
        self.layers.retain(|layer| match layer.max_height {
            Some(h) => h < height,
            None => true,
        });
        self.layers.shrink_to_fit();
    }

    /// Drop layers TipOnly can see: inserted **and** fenced.
    ///
    /// Call **after** pin (scripts handoff) so n−1 still has CreatePin outs.
    /// Stamp skips `body_range` when `get_out` hits. `drain_fk == 0` keeps
    /// every layer. Empty-span layers stay.
    pub fn prune_if_head_ready(&mut self, fence: &rbitcoin_store::HeightFence, drain_fk: u64) {
        if self.layers.is_empty() || drain_fk == 0 {
            return;
        }
        self.layers
            .retain(|layer| !layer.head_ready(fence, drain_fk));
        self.layers.shrink_to_fit();
    }

    /// Drop packs whose heights are already on the fence. `None` keeps all.
    ///
    /// Callers must pass **fence** tip (`Query::fence_tip_height`), not
    /// `confirmed[]` HWM. Untagged layers (`max_height == None`) stay.
    pub fn prune_through_tip(&mut self, tip: Option<u32>) {
        let Some(t) = tip else {
            return;
        };
        if self.layers.is_empty() {
            return;
        }
        self.layers.retain(|layer| match layer.max_height {
            Some(h) => h > t,
            None => true,
        });
        self.layers.shrink_to_fit();
    }

    pub fn clear(&mut self) {
        self.layers.clear();
        self.layers.shrink_to_fit();
    }

    /// Prep-facing snapshot: Arc bumps only (no map clone).
    pub fn snapshot(&self) -> InFlightView {
        let layers: Arc<[Arc<InFlightLayer>]> = self.layers.iter().cloned().collect();
        InFlightView { layers }
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    pub fn entry_count(&self) -> usize {
        self.layers.iter().map(|l| l.outs.len()).sum()
    }

    /// Occupancy for IBD `sizes`: layers, create-pin entries, approx payload bytes.
    pub fn size_snapshot(&self) -> (usize, usize, u64) {
        let mut entries = 0usize;
        let mut bytes = 0u64;
        for layer in &self.layers {
            entries = entries.saturating_add(layer.outs.len());
            bytes = bytes.saturating_add(layer.approx_bytes);
        }
        (self.layers.len(), entries, bytes)
    }
}

/// Immutable prep/plan view over published layers (newest→oldest lookup).
#[derive(Debug, Clone)]
pub struct InFlightView {
    layers: Arc<[Arc<InFlightLayer>]>,
}

impl Default for InFlightView {
    fn default() -> Self {
        Self::empty()
    }
}

impl InFlightView {
    pub fn empty() -> Self {
        Self {
            layers: Arc::from([]),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty() || self.layers.iter().all(|l| l.is_empty())
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Pin material for create fk id (scan newest layer first).
    #[inline]
    pub fn get_out(&self, id: u64) -> Option<&CreatePin> {
        for layer in self.layers.iter().rev() {
            if let Some(p) = layer.outs.get(&id) {
                return Some(p);
            }
        }
        None
    }

    /// Union of CreatePin keys across layers.
    pub fn out_ids(&self) -> crate::U64Set {
        let n: usize = self.layers.iter().map(|l| l.outs.len()).sum();
        let mut ids = crate::U64Set::with_capacity_and_hasher(n, Default::default());
        for layer in self.layers.iter() {
            for id in layer.outs.keys() {
                ids.insert(*id);
            }
        }
        ids
    }

    /// Newest layer first; each id once (same winner as [`Self::get_out`]).
    pub fn for_each_out(&self, mut f: impl FnMut(u64, &CreatePin)) {
        let mut seen = crate::U64Set::default();
        for layer in self.layers.iter().rev() {
            for (id, pin) in &layer.outs {
                if seen.insert(*id) {
                    f(*id, pin);
                }
            }
        }
    }

    /// Create fk for txid from prior uncommitted packs.
    #[inline]
    pub fn get_create_fk(&self, txid: &[u8; 32]) -> Option<Fk> {
        for layer in self.layers.iter().rev() {
            if let Some(fk) = layer.creates.get(txid) {
                return Some(*fk);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_store::{OutputRecord, TxRecord};

    fn pin(id: u64) -> CreatePin {
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
    fn creates_only_layer_resolves_txid() {
        let mut log = InFlightLog::new();
        let mut tid = [0u8; 32];
        tid[0] = 0xab;
        log.note_layer(InFlightLayer::from_txid_fks([(tid, Fk(42))]));
        let v = log.snapshot();
        assert_eq!(v.get_create_fk(&tid), Some(Fk(42)));
        assert!(v.get_out(42).is_none(), "creates-only has no denserels pin");
    }

    #[test]
    fn size_snapshot_counts_layers_and_bytes() {
        let mut log = InFlightLog::new();
        let p1 = pin(1);
        let p2 = pin(2);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(1), &p1)]));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(2), &p2)]));
        let (layers, entries, bytes) = log.size_snapshot();
        assert_eq!(layers, 2);
        assert_eq!(entries, 2);
        assert!(bytes > 0, "expected non-zero approx bytes");
        // Two pins with tiny scripts should stay well under 4 KiB.
        assert!(bytes < 4096, "bytes={bytes}");
        crate::process_mem_stats::note(layers, entries, bytes, 10, 2, 100);
        let s = crate::process_mem_stats::load();
        assert_eq!(s.inflight_layers, 2);
        assert_eq!(s.inflight_pins, 2);
        assert_eq!(s.pstore_weak, 10);
        assert_eq!(s.pstore_live, 2);
        let again = log.size_snapshot();
        assert_eq!(
            (layers, entries, bytes),
            again,
            "size_snapshot must reuse layer-cached bytes (no per-pack pin walk)"
        );
    }

    #[test]
    fn out_ids_unions_layers_and_matches_get_out() {
        let mut log = InFlightLog::new();
        let a = pin(1);
        let b = pin(2);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(1), &a)]));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(2), &b)]));
        let v = log.snapshot();
        let ids = v.out_ids();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert_eq!(ids.len(), 2);
        assert!(v.get_out(1).is_some());
        assert!(v.get_out(99).is_none());
        assert!(!ids.contains(&99));
        let mut newest = None;
        v.for_each_out(|id, _| {
            if newest.is_none() {
                newest = Some(id);
            }
        });
        assert_eq!(newest, Some(2), "newest layer first");
    }

    #[test]
    fn note_does_not_mutate_prior_layer_arcs() {
        let mut log = InFlightLog::new();
        let p1 = pin(1);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(1), &p1)]));
        let snap = log.snapshot();
        let layer0 = Arc::clone(&log.layers[0]);

        let p2 = pin(2);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(2), &p2)]));

        // Prior layer Arc identity unchanged (no make_mut rebuild).
        assert!(
            Arc::ptr_eq(&layer0, &log.layers[0]),
            "prior layer must not be rebuilt when noting a new pack"
        );
        assert_eq!(snap.layer_count(), 1);
        assert!(snap.get_out(1).is_some());
        assert!(snap.get_out(2).is_none(), "snapshot is frozen");
        assert!(log.snapshot().get_out(2).is_some());
    }

    #[test]
    fn prune_drops_whole_old_layers() {
        let mut log = InFlightLog::new();
        let a = pin(10);
        let b = pin(50);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(10), &a)]).with_max_height(1));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(50), &b)]).with_max_height(3));
        assert_eq!(log.layer_count(), 2);
        log.prune_through_tip(Some(1));
        assert_eq!(log.layer_count(), 1);
        assert!(log.snapshot().get_out(50).is_some());
        assert!(log.snapshot().get_out(10).is_none());
    }

    /// In-flight lives until the pack's heights are on the fence — not until
    /// `tx.head` occupied or `confirmed[]` HWM (mainnet 931147 / 945952).
    #[test]
    fn inflight_prune_through_tip() {
        let mut log = InFlightLog::new();
        let confirmed = pin(10);
        let ahead = pin(50);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(10), &confirmed)]).with_max_height(5));
        // Occupied already covers fk=50 (drain done) but height 6 is not confirmed.
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(50), &ahead)]).with_max_height(6));
        log.prune_through_tip(None);
        assert_eq!(log.layer_count(), 2, "no tip: keep every layer");

        log.prune_through_tip(Some(5));
        let v = log.snapshot();
        assert!(
            v.get_create_fk(&confirmed.0.txid).is_none(),
            "tip>=max_height drops the confirmed pack"
        );
        assert!(
            v.get_create_fk(&ahead.0.txid).is_some(),
            "max_fk<=occupied must not drop an unconfirmed height"
        );

        log.prune_through_tip(Some(6));
        assert!(log.snapshot().is_empty());
    }

    fn fence_covering(lo: u64, count: u32, height: u32) -> rbitcoin_store::HeightFence {
        use rbitcoin_store::{FenceRun, HeightFence};
        HeightFence::from_runs(vec![FenceRun {
            first_fk: lo,
            count,
            height,
        }])
    }

    /// TipOnly is fence-connected. Drain or fence alone is not a home
    /// (269204 leftover_n=1121 hit=1120 during first segment seal).
    #[test]
    fn prune_keeps_until_drain_and_fence() {
        let mut log = InFlightLog::new();
        let p = pin(10);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(10), &p)]).with_max_height(2));
        let covered = fence_covering(10, 1, 2);
        let empty = rbitcoin_store::HeightFence::empty();

        log.prune_if_head_ready(&covered, 0);
        assert!(
            log.snapshot().get_create_fk(&p.0.txid).is_some(),
            "drain_fk 0: insert never completed"
        );
        log.prune_if_head_ready(&covered, 9);
        assert!(
            log.snapshot().get_create_fk(&p.0.txid).is_some(),
            "fence covers, drain still mid-seal"
        );
        log.prune_if_head_ready(&empty, 10);
        assert!(
            log.snapshot().get_create_fk(&p.0.txid).is_some(),
            "drain done, fence not connected — TipOnly would drop"
        );
        log.prune_if_head_ready(&covered, 10);
        assert!(
            log.snapshot().get_create_fk(&p.0.txid).is_none(),
            "inserted and fenced"
        );
    }

    #[test]
    fn drop_from_height_keeps_lower_and_untagged() {
        let mut log = InFlightLog::new();
        let a = pin(10);
        let b = pin(20);
        let c = pin(30);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(10), &a)]).with_max_height(1));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(20), &b)]).with_max_height(3));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(30), &c)]));
        log.drop_from_height(3);
        let v = log.snapshot();
        assert!(v.get_create_fk(&a.0.txid).is_some());
        assert!(v.get_create_fk(&b.0.txid).is_none());
        assert!(v.get_create_fk(&c.0.txid).is_some(), "untagged stays");
    }

    #[test]
    fn prune_if_head_ready_keeps_higher_layer() {
        let mut log = InFlightLog::new();
        let a = pin(10);
        let b = pin(50);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(10), &a)]));
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(50), &b)]));
        log.prune_if_head_ready(&fence_covering(1, 50, 2), 10);
        let v = log.snapshot();
        assert!(v.get_create_fk(&a.0.txid).is_none());
        assert!(
            v.get_create_fk(&b.0.txid).is_some(),
            "later pack still mid-insert"
        );
    }

    #[test]
    fn clear_drops_all_layers_and_entries() {
        let mut log = InFlightLog::new();
        for i in 1u64..=5 {
            let p = pin(i);
            log.note_layer(InFlightLayer::from_plan_pins([(Fk(i), &p)]));
        }
        assert_eq!(log.layer_count(), 5);
        assert_eq!(log.entry_count(), 5);
        let held = log.snapshot();
        assert_eq!(held.layer_count(), 5);
        log.clear();
        assert_eq!(log.layer_count(), 0);
        assert_eq!(log.entry_count(), 0);
        // Prior snapshot stays valid (immutable); log is empty for new notes.
        assert_eq!(held.layer_count(), 5);
        assert!(held.get_out(3).is_some());
        assert!(log.snapshot().is_empty());
        let p = pin(99);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(99), &p)]));
        assert_eq!(log.layer_count(), 1);
        assert!(log.snapshot().get_out(99).is_some());
        assert!(log.snapshot().get_out(1).is_none());
    }

    #[test]
    fn snapshot_stable_while_log_notes_more() {
        let mut log = InFlightLog::new();
        let p1 = pin(1);
        log.note_layer(InFlightLayer::from_plan_pins([(Fk(1), &p1)]));
        let held = log.snapshot();
        for i in 2u64..=40 {
            let p = pin(i);
            log.note_layer(InFlightLayer::from_plan_pins([(Fk(i), &p)]));
        }
        // Prep-held view still only sees pack 1.
        assert_eq!(held.layer_count(), 1);
        assert!(held.get_out(1).is_some());
        assert!(held.get_out(40).is_none());
        assert_eq!(log.layer_count(), 40);
    }

    /// Timed multi-pack note while a prep snapshot is held — must stay O(C)
    /// per pack (no O(N) whole-map clone). Guards Phase A performance.
    #[test]
    fn multi_pack_note_under_held_snapshot_is_cheap() {
        use std::time::Instant;

        const PACKS: u64 = 80;
        const PER_PACK: u64 = 2_000;

        let mut log = InFlightLog::new();
        // Seed depth so N is large before the timed region.
        for pack in 0..40u64 {
            let pins: Vec<_> = (0..PER_PACK)
                .map(|i| {
                    let id = pack * PER_PACK + i + 1;
                    let p = pin(id);
                    (Fk(id), p)
                })
                .collect();
            log.note_layer(InFlightLayer::from_plan_pins(
                pins.iter().map(|(f, p)| (*f, p)),
            ));
        }
        let held = log.snapshot();
        assert!(held.layer_count() >= 40);

        let t0 = Instant::now();
        for pack in 40..PACKS {
            let pins: Vec<_> = (0..PER_PACK)
                .map(|i| {
                    let id = pack * PER_PACK + i + 1;
                    let p = pin(id);
                    (Fk(id), p)
                })
                .collect();
            log.note_layer(InFlightLayer::from_plan_pins(
                pins.iter().map(|(f, p)| (*f, p)),
            ));
        }
        let elapsed = t0.elapsed();
        // Held snapshot must remain frozen.
        assert_eq!(held.layer_count(), 40);
        assert!(held.get_out(1).is_some());
        assert!(held.get_out(40 * PER_PACK + 1).is_none());

        // 40 packs × 2000 pins under a held snapshot of 40 prior packs
        // (≈80k live entries when finishing). Old make_mut path cloned O(N)
        // HashMap shells each tick → multi-second; immutable note is O(C).
        eprintln!(
            "inflight_bench: packs={} per_pack={} note_under_hold={:?} final_layers={} final_entries={}",
            PACKS - 40,
            PER_PACK,
            elapsed,
            log.layer_count(),
            log.entry_count()
        );
        assert!(
            elapsed.as_millis() < 2_000,
            "note under held snapshot too slow: {elapsed:?} (possible map-clone regression)"
        );
        assert_eq!(log.layer_count(), PACKS as usize);
        let _ = held;
    }
}
