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
use crate::id_map::TxidHasher;
use crate::U64Map;
use rbitcoin_primitives::Fk;
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasherDefault;
use std::sync::Arc;

type TxidFkMap = HashMap<[u8; 32], Fk, BuildHasherDefault<TxidHasher>>;
type TxidEvictMap = HashMap<[u8; 32], u32, BuildHasherDefault<TxidHasher>>;

#[derive(Debug, Default)]
struct HeightKeys {
    /// `(txid, fk)` as noted by this pack: removal only drops a `creates`
    /// entry this pack still owns (exact fk match), so packs can retire in
    /// any order (ascending prune, descending disconnect drop).
    txids: Vec<([u8; 32], Fk)>,
    out_ids: Vec<u64>,
    approx_bytes: u64,
}

impl HeightKeys {
    fn is_empty(&self) -> bool {
        self.txids.is_empty() && self.out_ids.is_empty()
    }
}

/// Load-owned map of prior uncommitted creates (O(1) get; drop by pack height).
#[derive(Debug, Default)]
pub struct InFlight {
    creates: TxidFkMap,
    outs: U64Map<CreatePin>,
    by_height: BTreeMap<u32, HeightKeys>,
    untagged: HeightKeys,
    /// Count of older packs still listing a txid after a later `creates` clobber.
    /// Empty on the IBD hot path; prune skips the per-key check when empty.
    evictions: TxidEvictMap,
    approx_bytes: u64,
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
            self.note_create_fk(pin.0.txid, fk);
            keys.txids.push((pin.0.txid, fk));
            if let Some(id) = fk.get() {
                self.outs.insert(id, Arc::clone(pin));
                keys.out_ids.push(id);
                let pin_bytes = 40u64
                    .saturating_add(crate::archive::create_pin_approx_bytes(pin) as u64);
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

    fn commit_keys(&mut self, keys: HeightKeys, height: Option<u32>) {
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

    fn note_create_fk(&mut self, txid: [u8; 32], fk: Fk) {
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

    fn consume_eviction(&mut self, tid: &[u8; 32]) -> bool {
        let Some(n) = self.evictions.get_mut(tid) else {
            return false;
        };
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.evictions.remove(tid);
        }
        true
    }

    fn remove_keys(&mut self, keys: HeightKeys) {
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
    }

    /// Drop tagged packs at or above a disconnected height. Untagged stay.
    pub fn drop_from_height(&mut self, height: u32) {
        let drop = self.by_height.split_off(&height);
        for keys in drop.into_values() {
            self.remove_keys(keys);
        }
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

    #[inline]
    pub fn get_out(&self, id: u64) -> Option<&CreatePin> {
        self.outs.get(&id)
    }

    #[inline]
    pub fn get_create_fk(&self, txid: &[u8; 32]) -> Option<Fk> {
        self.creates.get(txid).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_store::{OutputRecord, TxRecord};

    fn pin(id: u64) -> CreatePin {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&id.to_le_bytes());
        pin_with_txid(txid)
    }

    fn pin_with_txid(txid: [u8; 32]) -> CreatePin {
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
    fn creates_only_resolves_txid() {
        let mut m = InFlight::new();
        let mut tid = [0u8; 32];
        tid[0] = 0xab;
        m.note_creates([(tid, Fk(42))], None);
        assert_eq!(m.get_create_fk(&tid), Some(Fk(42)));
        assert!(m.get_out(42).is_none(), "creates-only has no denserels pin");
    }

    #[test]
    fn size_snapshot_counts_packs_and_bytes() {
        let mut m = InFlight::new();
        let p1 = pin(1);
        let p2 = pin(2);
        m.note_pins([(Fk(1), &p1)], Some(1));
        m.note_pins([(Fk(2), &p2)], Some(2));
        let (packs, entries, bytes) = m.size_snapshot();
        assert_eq!(packs, 2);
        assert_eq!(entries, 2);
        assert!(bytes > 0, "expected non-zero approx bytes");
        assert!(bytes < 4096, "bytes={bytes}");
        crate::process_mem_stats::note(packs, entries, bytes, 10, 2, 100);
        let s = crate::process_mem_stats::load();
        assert_eq!(s.inflight_layers, 2);
        assert_eq!(s.inflight_pins, 2);
        assert_eq!(s.pstore_weak, 10);
        assert_eq!(s.pstore_live, 2);
        let again = m.size_snapshot();
        assert_eq!(
            (packs, entries, bytes),
            again,
            "size_snapshot must reuse cached bytes (no pin walk)"
        );
    }

    #[test]
    fn get_misses_until_note() {
        let mut m = InFlight::new();
        let p = pin(1);
        assert!(m.get_create_fk(&p.0.txid).is_none());
        m.note_pins([(Fk(1), &p)], Some(1));
        assert!(m.get_create_fk(&p.0.txid).is_some());
        assert!(m.get_out(1).is_some());
    }

    #[test]
    fn prune_drops_whole_old_packs() {
        let mut m = InFlight::new();
        let a = pin(10);
        let b = pin(50);
        m.note_pins([(Fk(10), &a)], Some(1));
        m.note_pins([(Fk(50), &b)], Some(3));
        assert_eq!(m.pack_count(), 2);
        m.prune_below_height(Some(2));
        assert_eq!(m.pack_count(), 1);
        assert!(m.get_out(50).is_some());
        assert!(m.get_out(10).is_none());
    }

    /// Drop is pack height vs the wave's pre-TipOnly drain+fence snapshot,
    /// not `tx.head` occupied or `confirmed[]` HWM (mainnet 931147 / 945952).
    #[test]
    fn prune_below_height_drops_strictly_below() {
        let mut m = InFlight::new();
        let confirmed = pin(10);
        let ahead = pin(50);
        m.note_pins([(Fk(10), &confirmed)], Some(5));
        m.note_pins([(Fk(50), &ahead)], Some(6));
        m.prune_below_height(None);
        assert_eq!(m.pack_count(), 2, "no snapshot: keep every pack");

        m.prune_below_height(Some(5));
        assert!(
            m.get_create_fk(&confirmed.0.txid).is_some(),
            "equality keeps (drop is strictly below)"
        );
        assert!(m.get_create_fk(&ahead.0.txid).is_some());

        m.prune_below_height(Some(6));
        assert!(
            m.get_create_fk(&confirmed.0.txid).is_none(),
            "height 5 is below noted 6"
        );
        assert!(
            m.get_create_fk(&ahead.0.txid).is_some(),
            "height == noted keeps"
        );

        m.prune_below_height(Some(7));
        assert!(m.is_empty());
    }

    #[test]
    fn prune_below_height_keeps_untagged() {
        let mut m = InFlight::new();
        let a = pin(10);
        let b = pin(20);
        m.note_pins([(Fk(10), &a)], Some(1));
        m.note_pins([(Fk(20), &b)], None);
        m.prune_below_height(Some(99));
        assert!(m.get_create_fk(&a.0.txid).is_none());
        assert!(m.get_create_fk(&b.0.txid).is_some(), "untagged stays");
    }

    #[test]
    fn prune_below_height_drops_height_index_prefix() {
        let mut m = InFlight::new();
        let pins: Vec<_> = (1u32..=20).map(|h| (h, pin(u64::from(h)))).collect();
        for (h, p) in &pins {
            m.note_pins([(Fk(u64::from(*h)), p)], Some(*h));
        }
        m.prune_below_height(Some(10));
        assert_eq!(m.pack_count(), 11, "heights 10..=20");
        assert!(m.get_out(9).is_none());
        assert!(m.get_out(10).is_some());
        assert!(m.get_out(20).is_some());
        m.drop_from_height(15);
        assert!(m.get_out(14).is_some());
        assert!(m.get_out(15).is_none());
        assert!(m.get_out(20).is_none());
        assert_eq!(m.pack_count(), 5, "heights 10..=14");
    }

    #[test]
    fn drop_from_height_keeps_lower_and_untagged() {
        let mut m = InFlight::new();
        let a = pin(10);
        let b = pin(20);
        let c = pin(30);
        m.note_pins([(Fk(10), &a)], Some(1));
        m.note_pins([(Fk(20), &b)], Some(3));
        m.note_pins([(Fk(30), &c)], None);
        m.drop_from_height(3);
        assert!(m.get_create_fk(&a.0.txid).is_some());
        assert!(m.get_create_fk(&b.0.txid).is_none());
        assert!(m.get_create_fk(&c.0.txid).is_some(), "untagged stays");
    }

    #[test]
    fn clear_drops_all_packs_and_entries() {
        let mut m = InFlight::new();
        for i in 1u64..=5 {
            let p = pin(i);
            m.note_pins([(Fk(i), &p)], Some(i as u32));
        }
        assert_eq!(m.pack_count(), 5);
        assert_eq!(m.entry_count(), 5);
        m.clear();
        assert_eq!(m.pack_count(), 0);
        assert_eq!(m.entry_count(), 0);
        assert!(m.is_empty());
        let p = pin(99);
        m.note_pins([(Fk(99), &p)], Some(9));
        assert_eq!(m.pack_count(), 1);
        assert!(m.get_out(99).is_some());
        assert!(m.get_out(1).is_none());
    }

    /// BIP30 overwrite (91722 then 91880): prune of the older pack must not
    /// drop the last-write fk from `creates`.
    #[test]
    fn prune_older_pack_keeps_newer_same_txid_last_write() {
        let mut m = InFlight::new();
        let mut txid = [0u8; 32];
        txid[0] = 0xe3;
        let old = pin_with_txid(txid);
        let new = pin_with_txid(txid);
        m.note_pins([(Fk(91722), &old)], Some(91722));
        m.note_pins([(Fk(91880), &new)], Some(91880));
        assert_eq!(m.get_create_fk(&txid), Some(Fk(91880)));
        m.prune_below_height(Some(91750));
        assert_eq!(
            m.get_create_fk(&txid),
            Some(Fk(91880)),
            "prune of 91722 must not drop last-write at 91880"
        );
        assert!(m.get_out(91880).is_some());
        assert!(m.get_out(91722).is_none());
    }

    /// Disconnect drops packs newest-first. Dropping the newer of two
    /// same-txid packs must not leave `creates` pointing at the dropped
    /// pack's fk, and the older pack's later prune must still clean up.
    #[test]
    fn drop_newer_same_txid_does_not_strand_creates() {
        let mut m = InFlight::new();
        let mut txid = [0u8; 32];
        txid[0] = 0xe3;
        let old = pin_with_txid(txid);
        let new = pin_with_txid(txid);
        m.note_pins([(Fk(1), &old)], Some(91722));
        m.note_pins([(Fk(2), &new)], Some(91880));
        m.drop_from_height(91880);
        assert_ne!(
            m.get_create_fk(&txid),
            Some(Fk(2)),
            "creates must not point at the dropped pack"
        );
        assert!(m.get_out(2).is_none());
        m.prune_below_height(Some(91723));
        assert_eq!(m.get_create_fk(&txid), None);
        assert!(m.is_empty(), "no leaked entries after both packs retire");
    }

    #[test]
    fn prune_older_creates_only_keeps_newer_same_txid() {
        let mut m = InFlight::new();
        let mut txid = [0u8; 32];
        txid[0] = 0xe3;
        m.note_creates([(txid, Fk(1))], Some(91722));
        m.note_creates([(txid, Fk(2))], Some(91880));
        m.prune_below_height(Some(91750));
        assert_eq!(m.get_create_fk(&txid), Some(Fk(2)));
    }

    #[test]
    fn same_txid_overwrite_does_not_double_count_creates_bytes() {
        let mut m = InFlight::new();
        let mut txid = [0u8; 32];
        txid[0] = 0xe3;
        m.note_creates([(txid, Fk(1))], Some(91722));
        let (_, _, once) = m.size_snapshot();
        m.note_creates([(txid, Fk(2))], Some(91880));
        let (_, _, twice) = m.size_snapshot();
        assert_eq!(
            twice, once,
            "creates map still holds one slot; iflight= must not grow on clobber"
        );
        m.prune_below_height(Some(91750));
        let (_, _, after) = m.size_snapshot();
        assert_eq!(after, once);
    }

    #[test]
    fn empty_note_is_noop() {
        let mut m = InFlight::new();
        m.note_pins(std::iter::empty(), Some(1));
        m.note_creates(std::iter::empty(), Some(1));
        assert!(m.is_empty());
        assert_eq!(m.pack_count(), 0);
    }
}
