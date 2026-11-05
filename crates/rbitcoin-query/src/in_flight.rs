//! Load-thread in-flight create material (confirm pipeline).
//!
//! IBD load is sequential: stamp/pin read this map, **then**
//! [`InFlight::note_pins`] / [`InFlight::note_creates`] insert the current pack
//! so that stamp cannot see it. One HashMap for `txid → fk` and one for
//! `fk → CreatePin` (outs for pin adopt). A height index drops keys without
//! scanning the maps. Same-txid overwrite (BIP30) records a count on a
//! side map; prune is the current path when that map is empty.
//!
//! **Prune:** lookup snapshots [`rbitcoin_store::HeightFence::drain_and_fence_hi`]
//! before a wave's TipOnly read and passes it on the last load batch. After
//! that batch finishes its in-flight read, [`InFlight::prune_below_height`]
//! drops tagged packs with pack height **below** that snapshot (equality
//! keeps). Class C tip and `class_a_hi` are not drop gates. Disconnect still
//! [`InFlight::drop_from_height`] on pack height.

use crate::archive::CreatePin;
use crate::TxidHasher;
use crate::U64Map;
use rbitcoin_primitives::Fk;
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasherDefault;
use std::sync::Arc;

#[doc(hidden)]
pub type TxidFkMap = HashMap<[u8; 32], Fk, BuildHasherDefault<TxidHasher>>;
#[doc(hidden)]
pub type TxidEvictMap = HashMap<[u8; 32], u32, BuildHasherDefault<TxidHasher>>;

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct HeightKeys {
    /// `(txid, fk)` as noted by this pack: removal only drops a `creates`
    /// entry this pack still owns (exact fk match), so packs can retire in
    /// any order (ascending prune, descending disconnect drop).
    pub txids: Vec<([u8; 32], Fk)>,
    pub out_ids: Vec<u64>,
    pub approx_bytes: u64,
}

impl HeightKeys {
    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.txids.is_empty() && self.out_ids.is_empty()
    }
}

/// Load-owned map of prior uncommitted creates (O(1) get; drop by pack height).
#[derive(Debug, Default)]
pub struct InFlight {
    pub creates: TxidFkMap,
    pub outs: U64Map<CreatePin>,
    pub by_height: BTreeMap<u32, HeightKeys>,
    pub untagged: HeightKeys,
    /// Count of older packs still listing a txid after a later `creates` clobber.
    /// Empty on the IBD hot path; prune skips the per-key check when empty.
    pub evictions: TxidEvictMap,
    pub approx_bytes: u64,
    /// Lowest create id still in `outs`. Pin does not call [`Self::get_out`] below it.
    min_out: Option<u64>,
}

impl InFlight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert planned fks + CreatePin outs. `height` is the pack's max height
    /// ([`None`] = untagged: disconnect and prune keep it).
    pub fn note_pins<'a>(
        &mut self,
        pins: impl IntoIterator<Item = (Fk, &'a CreatePin)>,
        height: Option<u32>,
    ) {
        let mut keys = HeightKeys::default();
        for (fk, pin) in pins {
            self.note_create_fk(pin.tx().txid, fk);
            keys.txids.push((pin.tx().txid, fk));
            if let Some(id) = fk.get() {
                self.outs.insert(id, Arc::clone(pin));
                keys.out_ids.push(id);
                self.min_out = Some(match self.min_out {
                    Some(min) if min < id => min,
                    _ => id,
                });
                let pin_bytes =
                    40u64.saturating_add(crate::archive::create_pin_approx_bytes(pin) as u64);
                keys.approx_bytes = keys.approx_bytes.saturating_add(pin_bytes);
                self.approx_bytes = self.approx_bytes.saturating_add(pin_bytes);
            }
        }
        self.commit_keys(keys, height);
    }

    /// Creates-only rows (txid→fk, no outs) for already-archived packs.
    pub fn note_creates(
        &mut self,
        pairs: impl IntoIterator<Item = ([u8; 32], Fk)>,
        height: Option<u32>,
    ) {
        let mut keys = HeightKeys::default();
        for (txid, fk) in pairs {
            self.note_create_fk(txid, fk);
            keys.txids.push((txid, fk));
        }
        self.commit_keys(keys, height);
    }

    #[doc(hidden)]
    pub fn commit_keys(&mut self, keys: HeightKeys, height: Option<u32>) {
        if keys.is_empty() {
            return;
        }
        let slot = match height {
            Some(h) => self.by_height.entry(h).or_default(),
            None => &mut self.untagged,
        };
        slot.approx_bytes = slot.approx_bytes.saturating_add(keys.approx_bytes);
        slot.txids.extend(keys.txids);
        slot.out_ids.extend(keys.out_ids);
    }

    #[doc(hidden)]
    pub fn note_create_fk(&mut self, txid: [u8; 32], fk: Fk) {
        match self.creates.insert(txid, fk) {
            None => {
                self.approx_bytes = self.approx_bytes.saturating_add(40);
            }
            Some(old) if old != fk => {
                *self.evictions.entry(txid).or_insert(0) += 1;
            }
            Some(_) => {}
        }
    }

    #[doc(hidden)]
    pub fn consume_eviction(&mut self, tid: &[u8; 32]) -> bool {
        let Some(n) = self.evictions.get_mut(tid) else {
            return false;
        };
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.evictions.remove(tid);
        }
        true
    }

    #[doc(hidden)]
    pub fn remove_keys(&mut self, keys: HeightKeys) {
        if self.evictions.is_empty() {
            for (tid, _) in &keys.txids {
                if self.creates.remove(tid).is_some() {
                    self.approx_bytes = self.approx_bytes.saturating_sub(40);
                }
            }
        } else {
            for (tid, fk) in &keys.txids {
                if self.creates.get(tid) == Some(fk) {
                    self.creates.remove(tid);
                    self.approx_bytes = self.approx_bytes.saturating_sub(40);
                } else {
                    self.consume_eviction(tid);
                }
            }
        }
        for id in &keys.out_ids {
            if let Some(pin) = self.outs.remove(id) {
                self.approx_bytes = self
                    .approx_bytes
                    .saturating_sub(40)
                    .saturating_sub(crate::archive::create_pin_approx_bytes(&pin) as u64);
            }
        }
        if self.min_out.is_some_and(|id| !self.outs.contains_key(&id)) {
            self.recompute_min_out();
        }
    }

    /// Lowest id still listed on a surviving height, including untagged.
    ///
    /// `by_height` is already the kept packs when prune calls this.
    fn recompute_min_out(&mut self) {
        let mut min: Option<u64> = None;
        let mut consider = |ids: &[u64]| {
            for id in ids {
                if self.outs.contains_key(id) {
                    min = Some(min.map_or(*id, |cur| cur.min(*id)));
                }
            }
        };
        for keys in self.by_height.values() {
            consider(&keys.out_ids);
        }
        consider(&self.untagged.out_ids);
        self.min_out = min;
    }

    /// Drop tagged packs at or above a disconnected height. Untagged stay.
    pub fn drop_from_height(&mut self, height: u32) {
        let drop = self.by_height.split_off(&height);
        for keys in drop.into_values() {
            self.remove_keys(keys);
        }
    }

    /// True when a [`Self::prune_below_height`] at `hi` would drop a tagged pack.
    ///
    /// `None` keeps every pack. Equality keeps, matching the prune.
    pub fn has_tagged_below(&self, hi: Option<u32>) -> bool {
        let Some(h) = hi else {
            return false;
        };
        self.by_height.range(..h).any(|(_, keys)| !keys.is_empty())
    }

    /// Drop tagged packs with height below `hi`.
    ///
    /// `None` hi keeps every pack. Untagged stay. Equality keeps
    /// (`hi == pack height`). Load calls this after the last batch of a lookup
    /// wave finishes its in-flight read, with the drain+fence height
    /// snapshotted before that wave's TipOnly.
    pub fn prune_below_height(&mut self, hi: Option<u32>) {
        let Some(h) = hi else {
            return;
        };
        let keep = self.by_height.split_off(&h);
        let drop = std::mem::replace(&mut self.by_height, keep);
        for keys in drop.into_values() {
            self.remove_keys(keys);
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.outs.is_empty()
    }

    pub fn pack_count(&self) -> usize {
        self.by_height.len() + usize::from(!self.untagged.is_empty())
    }

    pub fn entry_count(&self) -> usize {
        self.outs.len()
    }

    /// Occupancy for IBD `sizes`: height buckets, create-pin entries, approx bytes.
    pub fn size_snapshot(&self) -> (usize, usize, u64) {
        (self.pack_count(), self.outs.len(), self.approx_bytes)
    }

    /// Lowest create id in [`Self::outs`], if any.
    #[inline]
    pub fn min_out_id(&self) -> Option<u64> {
        self.min_out
    }

    #[inline]
    pub fn get_out(&self, id: u64) -> Option<&CreatePin> {
        self.outs.get(&id)
    }

    #[inline]
    pub fn get_create_fk(&self, txid: &[u8; 32]) -> Option<Fk> {
        self.creates.get(txid).copied()
    }
}
