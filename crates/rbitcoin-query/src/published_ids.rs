//! Published parent identity (`txid → fk + range`) as a wave-layered chain.
//!
//! Lookup prepends one [`IdLayer`] per resolve wave (a span of BQ heights)
//! and [`publish`](LiveUnion::publish) stores the chain head (`Arc` bump).
//! [`LiveUnion::get`] / [`partition`](LiveUnion::partition) and load
//! [`get`](PublishedIds::get) walk newest → older. A layer stays until
//! **no** height in its span is still on the body queue; drop is splice
//! only (no union rebuild). [`unpublish`](PublishedIds::unpublish) (store
//! `None`) drops visibility for new readers; a reader holding the old
//! `Arc` still sees hits.

use arc_swap::ArcSwapOption;
use rbitcoin_primitives::Fk;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

/// Identity hasher for `[u8; 32]` txids (already uniform). `finish()` is the
/// first 8 bytes; equality still compares the full key.
#[derive(Default, Clone, Copy)]
pub struct TxidHasher(u64);

impl Hasher for TxidHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            self.0 = u64::from_le_bytes(raw);
        } else {
            self.0 = 0;
            for (i, &b) in bytes.iter().enumerate() {
                self.0 |= u64::from(b) << (8 * i);
            }
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Immutable `txid → (create_fk, body_range)` for one resolve wave.
pub type IdMap = HashMap<[u8; 32], (Fk, (u64, u64)), BuildHasherDefault<TxidHasher>>;

/// One lookup wave's hits (`lo..=hi` BQ heights) plus the older chain.
#[derive(Debug)]
pub struct IdLayer {
    pub lo: u32,
    pub hi: u32,
    pub hits: Arc<IdMap>,
    pub older: Option<Arc<IdLayer>>,
}

impl IdLayer {
    /// Newest-first walk. First layer that has `txid` wins.
    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64))> {
        let mut layer = self;
        loop {
            if let Some(&v) = layer.hits.get(txid) {
                return Some(v);
            }
            match layer.older.as_deref() {
                Some(older) => layer = older,
                None => return None,
            }
        }
    }
}

/// Atomic published identity chain. Readers `load` an `Arc`; writers `store`.
#[derive(Debug)]
pub struct PublishedIds {
    inner: ArcSwapOption<IdLayer>,
}

impl Default for PublishedIds {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishedIds {
    pub fn new() -> Self {
        Self {
            inner: ArcSwapOption::empty(),
        }
    }

    /// Replace the chain with a single layer (tests / one-shot stamp).
    pub fn publish(&self, map: Arc<IdMap>) {
        self.inner.store(Some(Arc::new(IdLayer {
            lo: 0,
            hi: 0,
            hits: map,
            older: None,
        })));
    }

    pub(crate) fn publish_head(&self, head: Option<Arc<IdLayer>>) {
        self.inner.store(head);
    }

    /// New [`load`](Self::load) / [`get`](Self::get) miss. Held Arcs still work.
    pub fn unpublish(&self) {
        self.inner.store(None);
    }

    /// Chain head. `None` after [`unpublish`](Self::unpublish).
    pub fn load(&self) -> Option<Arc<IdLayer>> {
        self.inner.load_full()
    }

    /// Point get. Zero txid is never a hit.
    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64))> {
        if *txid == [0u8; 32] {
            return None;
        }
        self.load()?.get(txid)
    }
}

/// Lookup-thread chain of still-queued height layers. Not shared with load.
#[derive(Debug, Default)]
pub struct LiveUnion {
    head: Option<Arc<IdLayer>>,
    next_wave: u32,
}

impl LiveUnion {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, txid: &[u8; 32]) -> Option<(Fk, (u64, u64))> {
        if *txid == [0u8; 32] {
            return None;
        }
        self.head.as_deref()?.get(txid)
    }

    /// Split `keys` into already-known hits vs TipOnly need.
    pub fn partition<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a [u8; 32]>,
    ) -> (IdMap, Vec<[u8; 32]>) {
        let mut known = IdMap::default();
        let mut need = Vec::new();
        for t in keys {
            if *t == [0u8; 32] {
                continue;
            }
            match self.get(t) {
                Some(hit) => {
                    known.insert(*t, hit);
                }
                None => need.push(*t),
            }
        }
        (known, need)
    }

    /// Drop layers whose span has no remaining queued height. Does not swap.
    pub fn keep_heights(&mut self, keep: impl Fn(u32) -> bool) {
        self.head = splice_kept(self.head.take(), keep);
    }

    /// Same as [`Self::keep_heights`] using a queued-height set (`range`, not `lo..=hi`).
    pub fn keep_queued_heights(&mut self, queued: &std::collections::BTreeSet<u32>) {
        self.head = splice_queued(self.head.take(), queued);
    }

    /// Prepend one layer covering `lo..=hi` (inclusive).
    pub fn note_span(&mut self, lo: u32, hi: u32, hits: &IdMap) {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        self.head = splice_kept(self.head.take(), |h| h < lo || h > hi);
        let mut layer_hits = IdMap::default();
        for (t, &v) in hits {
            if *t == [0u8; 32] {
                continue;
            }
            layer_hits.insert(*t, v);
        }
        if !layer_hits.is_empty() {
            self.head = Some(Arc::new(IdLayer {
                lo,
                hi,
                hits: Arc::new(layer_hits),
                older: self.head.take(),
            }));
        }
    }

    /// Prepend a single-height layer (tests / one-shot).
    pub fn note_height(&mut self, height: u32, hits: &IdMap) {
        self.note_span(height, height, hits);
    }

    /// Arc-bump the chain head. Call once after a wave's [`note_span`].
    pub fn publish(&self, published: &PublishedIds) {
        published.publish_head(self.head.clone());
    }

    /// Insert hits under a synthetic single-height wave, publish the chain head.
    pub fn finish_wave(&mut self, hits: &IdMap, published: &PublishedIds) -> u32 {
        let height = self.next_wave;
        self.next_wave = self.next_wave.saturating_add(1);
        self.note_height(height, hits);
        self.publish(published);
        height
    }
}

fn span_kept(lo: u32, hi: u32, keep: &impl Fn(u32) -> bool) -> bool {
    (lo..=hi).any(keep)
}

/// True when any height in `queued` falls in `lo..=hi` (no 1080-wide walk).
pub fn span_overlaps_queued(lo: u32, hi: u32, queued: &std::collections::BTreeSet<u32>) -> bool {
    queued.range(lo..=hi).next().is_some()
}

/// Rebuild the chain keeping nodes that still have a queued height in span.
/// Kept hit maps are `Arc`-cloned; suffix nodes whose `older` is unchanged
/// are reused.
fn splice_kept(head: Option<Arc<IdLayer>>, keep: impl Fn(u32) -> bool) -> Option<Arc<IdLayer>> {
    let mut nodes = Vec::new();
    let mut cur = head;
    while let Some(n) = cur {
        let older = n.older.clone();
        nodes.push(n);
        cur = older;
    }
    let mut new_head: Option<Arc<IdLayer>> = None;
    for n in nodes.into_iter().rev() {
        if !span_kept(n.lo, n.hi, &keep) {
            continue;
        }
        let older_ok = match (n.older.as_ref(), new_head.as_ref()) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if older_ok {
            new_head = Some(n);
        } else {
            new_head = Some(Arc::new(IdLayer {
                lo: n.lo,
                hi: n.hi,
                hits: Arc::clone(&n.hits),
                older: new_head,
            }));
        }
    }
    new_head
}

fn splice_queued(
    head: Option<Arc<IdLayer>>,
    queued: &std::collections::BTreeSet<u32>,
) -> Option<Arc<IdLayer>> {
    let mut nodes = Vec::new();
    let mut cur = head;
    while let Some(n) = cur {
        let older = n.older.clone();
        nodes.push(n);
        cur = older;
    }
    let mut new_head: Option<Arc<IdLayer>> = None;
    for n in nodes.into_iter().rev() {
        if !span_overlaps_queued(n.lo, n.hi, queued) {
            continue;
        }
        let older_ok = match (n.older.as_ref(), new_head.as_ref()) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if older_ok {
            new_head = Some(n);
        } else {
            new_head = Some(Arc::new(IdLayer {
                lo: n.lo,
                hi: n.hi,
                hits: Arc::clone(&n.hits),
                older: new_head,
            }));
        }
    }
    new_head
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_hasher_uses_first_8_bytes() {
        let mut h = TxidHasher::default();
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        t[8] = 0xff;
        h.write(&t);
        assert_eq!(h.finish(), 0x0102_0304_0506_0708);
        let mut other = [0u8; 32];
        other[..8].copy_from_slice(&t[..8]);
        other[31] = 1;
        let mut h2 = TxidHasher::default();
        h2.write(&other);
        assert_eq!(
            h2.finish(),
            h.finish(),
            "same prefix must hash equal; full-key eq still separates them"
        );
        let mut m = IdMap::default();
        m.insert(t, (Fk(1), (0, 1)));
        m.insert(other, (Fk(2), (0, 1)));
        assert_eq!(m.get(&t).map(|v| v.0), Some(Fk(1)));
        assert_eq!(m.get(&other).map(|v| v.0), Some(Fk(2)));
    }

    fn tid(b: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = b;
        t
    }

    fn map_one() -> Arc<IdMap> {
        let mut m = IdMap::default();
        m.insert(tid(1), (Fk(9), (100, 8)));
        Arc::new(m)
    }

    #[test]
    fn publish_makes_get_visible() {
        let p = PublishedIds::new();
        assert!(p.get(&tid(1)).is_none());
        p.publish(map_one());
        assert_eq!(p.get(&tid(1)), Some((Fk(9), (100, 8))));
        assert!(p.get(&tid(2)).is_none());
    }

    #[test]
    fn unpublish_hides_from_new_readers() {
        let p = PublishedIds::new();
        p.publish(map_one());
        p.unpublish();
        assert!(p.get(&tid(1)).is_none());
        assert!(p.load().is_none());
    }

    #[test]
    fn unpublish_keeps_old_arc() {
        let p = PublishedIds::new();
        p.publish(map_one());
        let held = p.load().expect("published");
        p.unpublish();
        assert_eq!(held.get(&tid(1)), Some((Fk(9), (100, 8))));
        assert!(p.get(&tid(1)).is_none());
    }

    #[test]
    fn zero_txid_is_never_a_hit() {
        let p = PublishedIds::new();
        let mut m = IdMap::default();
        m.insert([0u8; 32], (Fk(1), (0, 1)));
        p.publish(Arc::new(m));
        assert!(p.get(&[0u8; 32]).is_none());
    }

    fn hits(pairs: &[([u8; 32], Fk, (u64, u64))]) -> IdMap {
        pairs.iter().map(|(t, f, r)| (*t, (*f, *r))).collect()
    }

    #[test]
    fn finish_wave_publishes_and_second_wave_skips() {
        let published = PublishedIds::new();
        let mut live = LiveUnion::new();
        let t1 = tid(1);
        let t2 = tid(2);
        live.finish_wave(&hits(&[(t1, Fk(10), (1, 2))]), &published);
        assert_eq!(published.get(&t1), Some((Fk(10), (1, 2))));
        let (known, need) = live.partition([&t1, &t2]);
        assert_eq!(known.get(&t1).copied(), Some((Fk(10), (1, 2))));
        assert_eq!(need, vec![t2]);
    }

    #[test]
    fn publish_reuses_layer_arc_when_unchanged() {
        let published = PublishedIds::new();
        let mut live = LiveUnion::new();
        live.finish_wave(&hits(&[(tid(1), Fk(10), (1, 2))]), &published);
        let a = published.load().expect("published");
        live.publish(&published);
        let b = published.load().expect("published");
        assert!(
            Arc::ptr_eq(&a, &b),
            "unchanged union must Arc-bump, not rebuild a HashMap"
        );
    }

    #[test]
    fn forget_only_wave1_drops_unique_keeps_shared() {
        let published = PublishedIds::new();
        let mut live = LiveUnion::new();
        let shared = tid(1);
        let only1 = tid(2);
        let w1 = live.finish_wave(
            &hits(&[(shared, Fk(10), (1, 2)), (only1, Fk(11), (3, 4))]),
            &published,
        );
        let w2 = live.finish_wave(
            &hits(&[(shared, Fk(10), (1, 2)), (tid(3), Fk(12), (5, 6))]),
            &published,
        );
        let kept_hits = Arc::clone(&published.load().expect("head").hits);
        live.keep_heights(|h| h != w1);
        live.publish(&published);
        assert!(published.get(&only1).is_none(), "wave-1-only key must drop");
        assert_eq!(
            published.get(&shared),
            Some((Fk(10), (1, 2))),
            "shared key survives forget of wave 1"
        );
        assert_eq!(published.get(&tid(3)), Some((Fk(12), (5, 6))));
        let head = published.load().expect("w2 remains");
        assert_eq!((head.lo, head.hi), (w2, w2));
        assert!(head.older.is_none(), "dropped layer must leave the chain");
        assert!(
            Arc::ptr_eq(&head.hits, &kept_hits),
            "kept layer hit map must not be cloned"
        );
    }

    #[test]
    fn span_overlaps_queued_does_not_walk_width() {
        let mut q = std::collections::BTreeSet::new();
        q.insert(500);
        assert!(span_overlaps_queued(0, 1079, &q));
        assert!(!span_overlaps_queued(0, 499, &q));
        assert!(!span_overlaps_queued(501, 1079, &q));
    }

    #[test]
    fn keep_span_while_any_height_in_range_queued() {
        let published = PublishedIds::new();
        let mut live = LiveUnion::new();
        live.note_span(3, 5, &hits(&[(tid(1), Fk(10), (1, 2))]));
        live.publish(&published);
        live.keep_heights(|h| h != 3);
        live.publish(&published);
        assert_eq!(
            published.get(&tid(1)),
            Some((Fk(10), (1, 2))),
            "layer 3..=5 must stay while 4 or 5 is still queued"
        );
        live.keep_heights(|h| h > 5);
        live.publish(&published);
        assert!(
            published.get(&tid(1)).is_none(),
            "layer must drop when no height in the span remains"
        );
    }

    #[test]
    fn note_span_and_keep_walk_layers_without_union_rebuild() {
        let mut live = LiveUnion::new();
        live.note_span(1, 1, &hits(&[(tid(1), Fk(10), (1, 2))]));
        live.note_span(2, 2, &hits(&[(tid(2), Fk(11), (3, 4))]));
        live.keep_heights(|h| h == 2);
        assert_eq!(live.get(&tid(2)), Some((Fk(11), (3, 4))));
        assert!(
            live.get(&tid(1)).is_none(),
            "dropped layer must not be rebuilt into a live union map"
        );
        let (known, need) = live.partition([&tid(2), &tid(3)]);
        assert_eq!(known.get(&tid(2)).copied(), Some((Fk(11), (3, 4))));
        assert_eq!(need, vec![tid(3)]);
    }

    #[test]
    fn store_none_hides_until_next_publish() {
        let published = PublishedIds::new();
        let mut live = LiveUnion::new();
        live.finish_wave(&hits(&[(tid(1), Fk(10), (1, 2))]), &published);
        published.unpublish();
        assert!(published.get(&tid(1)).is_none());
        live.finish_wave(&hits(&[(tid(1), Fk(10), (1, 2))]), &published);
        assert_eq!(published.get(&tid(1)), Some((Fk(10), (1, 2))));
    }
}
