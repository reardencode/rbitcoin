//! In-RAM block payload queue for the combined archive/confirm path.
//!
//! **Why RAM (not disk):** peer wire would otherwise be written once to a durable
//! queue and again into Class A on confirm — **double disk write per block**.
//! Keeping the same FIFO / height-index structure in process memory trades
//! **redownload on restart** and peak RAM for a single durable write (Class A).
//!
//! **Lifecycle:** enqueue after peer framing (raw payload + stamped Σ inputs;
//! no full block parse); lookup **takes** raw on emit (`take_raw`);
//! **dequeue only after combined confirm-write** (or permanent reject).
//! Restart does **not** rehydrate payloads (queue starts empty).
//!
//! **Primary capacity** is soft densify assign in the net layer (no hysteresis):
//! under ~100 MiB free densify ahead; over ~100 MiB only the next ~1 min of
//! confirm work at tip rate; at/over the 1 GiB assign-stop (`RBITCOIN_BLOCK_QUEUE_GB`
//! / `_BYTES`) densify holes only within that ~1 min window **and** not past
//! fetched_hi (do not grow past fetched; do not densify far holes outside the
//! window). This type **always** accepts already-requested payloads (OOM aside).

use crate::error::StoreError;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Payload clones from [`BlockQueue::raw_payloads`] / [`BlockQueue::raw_payload`].
/// Debug/test only — wave intake must not bump this for the whole asked set.
/// `cfg(test)` so `--release` `cargo test` (Windows/macOS store smoke) compiles.
#[cfg(any(test, debug_assertions))]
static RAW_CLONE_N: AtomicU64 = AtomicU64::new(0);

/// Take-and-reset raw payload clone count (debug builds / unit tests).
#[cfg(any(test, debug_assertions))]
pub fn take_raw_clone_n() -> u64 {
    RAW_CLONE_N.swap(0, Ordering::Relaxed)
}

#[cfg(any(test, debug_assertions))]
fn note_raw_clone() {
    RAW_CLONE_N.fetch_add(1, Ordering::Relaxed);
}

/// Raw row removed by [`BlockQueue::take_raw`] (lookup consume).
#[derive(Debug, Clone)]
pub struct TakenRaw {
    pub hash: [u8; 32],
    pub header_fk: u64,
    pub payload: Vec<u8>,
}

/// One queued block. `payload` is empty after [`BlockQueue::promote_wave`].
#[derive(Debug, Clone)]
pub struct QueuedBlock {
    pub id: u64,
    pub height: u32,
    pub hash: [u8; 32],
    pub header_fk: u64,
    pub payload: Vec<u8>,
}

/// Wire bytes or a post-lookup charge (decoded `Block` lives on Query).
#[derive(Debug, Clone)]
enum QueuedBody {
    Raw(Vec<u8>),
    Promoted { charge: u64 },
}

impl QueuedBody {
    fn charge(&self) -> u64 {
        match self {
            Self::Raw(v) => v.len() as u64,
            Self::Promoted { charge } => *charge,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Raw(v) => v,
            Self::Promoted { .. } => &[],
        }
    }
}

/// Index-only view of a queue entry (no payload clone).
#[derive(Debug, Clone, Copy)]
pub struct QueuedBlockMeta {
    pub id: u64,
    pub height: u32,
    pub hash: [u8; 32],
    pub header_fk: u64,
    /// Raw wire length, or decoded charge after promote.
    pub payload_len: u64,
    /// Σ `tx.input` from [`crate::block_wire_input_count`] at enqueue (`0` if unreadable).
    pub n_inputs: u32,
    /// Lookup finished TipOnly for this height (load may still leftover-stamp).
    pub resolve_complete: bool,
}

/// Process-local FIFO of block payloads (append + delete-by-id).
///
/// Same shape as the former on-disk queue (`id`, height, hash, header_fk,
/// payload) but **never** writes rec files. `store_dir` is accepted for API
/// compatibility and to optionally ignore/remove a legacy `block_queue/` dir.
pub struct BlockQueue {
    next_id: AtomicU64,
    /// id → entry (payload owned)
    index: BTreeMap<u64, IndexEntry>,
    /// First-wins height → id. Height APIs must not walk `index.values()`.
    height_to_id: HashMap<u32, u64>,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct IndexEntry {
    height: u32,
    hash: [u8; 32],
    header_fk: u64,
    body: QueuedBody,
    n_inputs: u32,
    resolve_complete: bool,
}

impl BlockQueue {
    /// Create an empty in-RAM queue. Legacy on-disk `store_dir/block_queue/` is
    /// not loaded (redownload after restart); best-effort remove stale files.
    pub fn open_or_create(store_dir: &Path) -> Result<Self, StoreError> {
        let legacy = store_dir.join("block_queue");
        if legacy.exists() {
            let _ = std::fs::remove_dir_all(&legacy);
        }
        Ok(Self {
            next_id: AtomicU64::new(1),
            index: BTreeMap::new(),
            height_to_id: HashMap::new(),
            bytes: 0,
        })
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn count(&self) -> usize {
        self.index.len()
    }

    /// Append a block payload in RAM. Returns queue id.
    ///
    /// Always accepts (IBD densify assign-stop is request-limited; never refuse
    /// already-requested bodies here).
    pub fn enqueue(
        &mut self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: &[u8],
    ) -> Result<u64, StoreError> {
        let n_inputs = crate::block_wire_input_count(payload);
        self.enqueue_vec(height, hash, header_fk, payload.to_vec(), n_inputs)
    }

    /// Enqueue an already-owned payload (copy happened outside the BQ lock).
    ///
    /// `n_inputs` is [`crate::block_wire_input_count`] from the caller so the
    /// walk can run off the BQ mutex (peer offer).
    pub fn enqueue_vec(
        &mut self,
        height: u32,
        hash: [u8; 32],
        header_fk: u64,
        payload: Vec<u8>,
        n_inputs: u32,
    ) -> Result<u64, StoreError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.bytes = self.bytes.saturating_add(payload.len() as u64);
        self.index.insert(
            id,
            IndexEntry {
                height,
                hash,
                header_fk,
                body: QueuedBody::Raw(payload),
                n_inputs,
                resolve_complete: false,
            },
        );
        self.height_to_id.entry(height).or_insert(id);
        Ok(id)
    }

    /// Load payload by id.
    pub fn get(&self, id: u64) -> Result<Option<QueuedBlock>, StoreError> {
        let Some(e) = self.index.get(&id) else {
            return Ok(None);
        };
        Ok(Some(QueuedBlock {
            id,
            height: e.height,
            hash: e.hash,
            header_fk: e.header_fk,
            payload: e.body.payload().to_vec(),
        }))
    }

    /// Peek oldest id (FIFO by id).
    pub fn peek_oldest_id(&self) -> Option<u64> {
        self.index.keys().next().copied()
    }

    /// List all ids ascending.
    pub fn ids(&self) -> Vec<u64> {
        self.index.keys().copied().collect()
    }

    /// Remove after confirm-write / permanent reject.
    pub fn dequeue(&mut self, id: u64) -> Result<bool, StoreError> {
        let Some(e) = self.index.remove(&id) else {
            return Ok(false);
        };
        self.bytes = self.bytes.saturating_sub(e.body.charge());
        if self.height_to_id.get(&e.height) == Some(&id) {
            self.height_to_id.remove(&e.height);
            if let Some((&nid, _)) = self.index.iter().find(|(_, x)| x.height == e.height) {
                self.height_to_id.insert(e.height, nid);
            }
        }
        Ok(true)
    }

    /// Take raw payload and remove the row. `None` if missing or already promoted.
    pub fn take_raw(&mut self, height: u32) -> Option<TakenRaw> {
        let id = *self.height_to_id.get(&height)?;
        let e = self.index.get_mut(&id)?;
        let payload = match &mut e.body {
            QueuedBody::Raw(v) => std::mem::take(v),
            QueuedBody::Promoted { .. } => return None,
        };
        let e = self.index.get(&id)?;
        let out = TakenRaw {
            hash: e.hash,
            header_fk: e.header_fk,
            payload,
        };
        self.bytes = self.bytes.saturating_sub(out.payload.len() as u64);
        let _ = self.dequeue(id);
        Some(out)
    }

    /// Dequeue all records for a confirmed height (may be 0 or 1 in normal path).
    pub fn dequeue_height(&mut self, height: u32) -> Result<usize, StoreError> {
        let mut n = 0usize;
        while let Some(&id) = self.height_to_id.get(&height) {
            if !self.dequeue(id)? {
                break;
            }
            n += 1;
        }
        Ok(n)
    }

    /// Contiguous unresolved heights from `path_lo`. Stops at the first height
    /// not on the queue (a hole). Skips resolve-complete and `skip` without
    /// treating those as a gap. Capped at `cap`.
    pub fn unresolved_heights(&self, path_lo: u32, skip: &HashSet<u32>, cap: usize) -> Vec<u32> {
        if cap == 0 {
            return Vec::new();
        }
        let mut out: Vec<u32> = Vec::new();
        let mut h = path_lo;
        while out.len() < cap {
            if !self.contains_height(h) {
                break;
            }
            if !self.is_resolve_complete(h) && !skip.contains(&h) {
                out.push(h);
            }
            h = match h.checked_add(1) {
                Some(n) => n,
                None => break,
            };
        }
        out
    }

    /// Index-only listing (ascending id).
    pub fn list_meta(&self) -> Vec<QueuedBlockMeta> {
        self.index
            .iter()
            .map(|(&id, e)| QueuedBlockMeta {
                id,
                height: e.height,
                hash: e.hash,
                header_fk: e.header_fk,
                payload_len: e.body.charge(),
                n_inputs: e.n_inputs,
                resolve_complete: e.resolve_complete,
            })
            .collect()
    }

    /// Load payload for a height (confirm load intake). First match by height.
    ///
    /// Does **not** dequeue — confirm-write / permanent reject removes the rec.
    pub fn get_by_height(&self, height: u32) -> Result<Option<QueuedBlock>, StoreError> {
        let Some(&id) = self.height_to_id.get(&height) else {
            return Ok(None);
        };
        self.get(id)
    }

    /// True if any rec exists for `height`.
    pub fn contains_height(&self, height: u32) -> bool {
        self.height_to_id.contains_key(&height)
    }

    /// Heights currently on the queue.
    pub fn heights(&self) -> Vec<u32> {
        self.index.values().map(|e| e.height).collect()
    }

    /// Highest height among recs (`None` if empty).
    pub fn max_height(&self) -> Option<u32> {
        self.index.values().map(|e| e.height).max()
    }

    /// Lowest height among recs (`None` if empty).
    pub fn min_height(&self) -> Option<u32> {
        self.index.values().map(|e| e.height).min()
    }

    /// First queue id for `height`, if any.
    pub fn id_for_height(&self, height: u32) -> Option<u64> {
        self.height_to_id.get(&height).copied()
    }

    fn entry_for_height(&self, height: u32) -> Option<&IndexEntry> {
        self.height_to_id
            .get(&height)
            .and_then(|id| self.index.get(id))
    }

    fn entry_mut_for_height(&mut self, height: u32) -> Result<&mut IndexEntry, StoreError> {
        let id = self
            .height_to_id
            .get(&height)
            .copied()
            .ok_or(StoreError::NotFound)?;
        self.index.get_mut(&id).ok_or(StoreError::NotFound)
    }

    /// Lookup finished this height: every external parent has a hit (or none exist).
    pub fn mark_resolve_complete(&mut self, height: u32) -> Result<(), StoreError> {
        self.entry_mut_for_height(height)?.resolve_complete = true;
        Ok(())
    }

    pub fn is_resolve_complete(&self, height: u32) -> bool {
        self.entry_for_height(height)
            .map(|e| e.resolve_complete)
            .unwrap_or(false)
    }

    /// Hash of the first queue entry at `height`, if any (no payload clone).
    pub fn hash_at_height(&self, height: u32) -> Option<[u8; 32]> {
        self.entry_for_height(height).map(|e| e.hash)
    }

    /// Enqueue-stamped Σ inputs (`None` if height missing).
    pub fn input_count_at(&self, height: u32) -> Option<u32> {
        self.entry_for_height(height).map(|e| e.n_inputs)
    }

    /// One-pass height list for a load pack: stored hash + resolve-complete.
    /// Missing heights are omitted (caller treats as body-missing).
    pub fn pack_snapshot(&self, heights: &[u32]) -> Vec<(u32, [u8; 32], bool)> {
        let mut out = Vec::with_capacity(heights.len());
        for &h in heights {
            if let Some(e) = self.entry_for_height(h) {
                out.push((h, e.hash, e.resolve_complete));
            }
        }
        out
    }

    /// True when `height` still holds a raw (unpromoted) payload. No clone.
    pub fn has_raw(&self, height: u32) -> bool {
        matches!(
            self.entry_for_height(height).map(|e| &e.body),
            Some(QueuedBody::Raw(_))
        )
    }

    /// Clone one still-raw payload by height. Promoted / missing → `None`.
    pub fn raw_payload(&self, height: u32) -> Option<Vec<u8>> {
        match self.entry_for_height(height).map(|e| &e.body) {
            Some(QueuedBody::Raw(v)) => {
                #[cfg(any(test, debug_assertions))]
                note_raw_clone();
                Some(v.clone())
            }
            _ => None,
        }
    }

    /// Raw wire for `heights` still holding payload. One pass; skips promoted.
    ///
    /// Lookup wave must not use this for the unresolved cap — clone via
    /// [`Self::raw_payload`] per height that will actually decode.
    pub fn raw_payloads(&self, heights: &[u32]) -> Vec<(u32, Vec<u8>)> {
        let want: HashSet<u32> = heights.iter().copied().collect();
        let mut out = Vec::new();
        for e in self.index.values() {
            if !want.contains(&e.height) {
                continue;
            }
            if let QueuedBody::Raw(v) = &e.body {
                #[cfg(any(test, debug_assertions))]
                note_raw_clone();
                out.push((e.height, v.clone()));
            }
        }
        out
    }

    /// Replace raw with a decoded charge for each height. Returns how many
    /// were still raw. Already-promoted rows keep their charge. One pass.
    pub fn promote_wave(&mut self, items: &[(u32, u64)]) -> Result<usize, StoreError> {
        let mut n = 0usize;
        for &(height, charge) in items {
            let old = {
                let Ok(e) = self.entry_mut_for_height(height) else {
                    continue;
                };
                if matches!(e.body, QueuedBody::Promoted { .. }) {
                    continue;
                }
                let old = e.body.charge();
                e.body = QueuedBody::Promoted { charge };
                old
            };
            self.bytes = self.bytes.saturating_sub(old).saturating_add(charge);
            n += 1;
        }
        Ok(n)
    }

    pub fn promoted_count(&self) -> usize {
        self.index
            .values()
            .filter(|e| matches!(e.body, QueuedBody::Promoted { .. }))
            .count()
    }

    pub fn mark_resolve_complete_wave(&mut self, heights: &[u32]) -> Result<usize, StoreError> {
        let mut n = 0usize;
        for &h in heights {
            if let Ok(e) = self.entry_mut_for_height(h) {
                if !e.resolve_complete {
                    e.resolve_complete = true;
                    n += 1;
                }
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("rbitcoin-bq-ram-{id}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn get_by_height_peek_without_dequeue() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let payload = b"wire-bytes-height-42".to_vec();
        q.enqueue(42, [0x11u8; 32], 3, &payload).unwrap();
        let got = q.get_by_height(42).unwrap().expect("by height");
        assert_eq!(got.payload, payload);
        assert_eq!(got.height, 42);
        assert!(q.contains_height(42));
        assert!(q.get_by_height(99).unwrap().is_none());
        assert_eq!(q.count(), 1, "peek must not dequeue");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_dequeue_no_disk_rehydrate() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let payload = b"fake-block-bytes-for-queue".to_vec();
        let id = q.enqueue(100, [0xABu8; 32], 7, &payload).unwrap();
        assert_eq!(q.count(), 1);
        let got = q.get(id).unwrap().expect("present");
        assert_eq!(got.height, 100);
        assert_eq!(got.hash, [0xABu8; 32]);
        assert_eq!(got.payload, payload);
        assert!(q.dequeue(id).unwrap());
        assert_eq!(q.count(), 0);
        // Restart: RAM queue is empty (by design — no durable rehydrate).
        drop(q);
        let q2 = BlockQueue::open_or_create(&dir).unwrap();
        assert_eq!(q2.count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_accepts_large_payload_and_drops_legacy_dir() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let big = vec![0u8; 65 * 1024 * 1024];
        q.enqueue(1, [9u8; 32], 1, &big)
            .expect("enqueue has no byte ceiling");
        assert_eq!(q.count(), 1);
        let legacy = dir.join("block_queue");
        std::fs::create_dir_all(&legacy).unwrap();
        let _ = BlockQueue::open_or_create(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_height_span() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        assert_eq!(q.max_height(), None);
        q.enqueue(10, [1u8; 32], 1, b"a").unwrap();
        q.enqueue(15, [2u8; 32], 2, b"b").unwrap();
        q.enqueue(12, [3u8; 32], 3, b"c").unwrap();
        assert_eq!(q.max_height(), Some(15));
        assert_eq!(q.min_height(), Some(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fifo_oldest_and_heights() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let id1 = q.enqueue(1, [1u8; 32], 1, b"a").unwrap();
        let id2 = q.enqueue(2, [2u8; 32], 2, b"bb").unwrap();
        assert_eq!(q.peek_oldest_id(), Some(id1));
        let mut hs = q.heights();
        hs.sort_unstable();
        assert_eq!(hs, vec![1, 2]);
        assert_eq!(q.id_for_height(2), Some(id2));
        assert_eq!(q.dequeue_height(1).unwrap(), 1);
        assert_eq!(q.peek_oldest_id(), Some(id2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_meta_matches_payload_len() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(5, [9u8; 32], 1, b"hello").unwrap();
        let m = q.list_meta();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].payload_len, 5);
        assert_eq!(m[0].height, 5);
        assert_eq!(m[0].n_inputs, 0, "junk payload is not a block");
        assert!(!m[0].resolve_complete, "enqueue starts unresolved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_stamps_wire_input_count() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let mut payload = vec![0u8; 80];
        crate::compact::write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&1u32.to_le_bytes());
        crate::compact::write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        crate::compact::write_compact_size(&mut payload, 0);
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        crate::compact::write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&0u64.to_le_bytes());
        crate::compact::write_compact_size(&mut payload, 0);
        payload.extend_from_slice(&0u32.to_le_bytes());
        q.enqueue(1, [1u8; 32], 1, &payload).unwrap();
        assert_eq!(q.input_count_at(1), Some(1));
        assert_eq!(q.list_meta()[0].n_inputs, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_meta_reports_resolve_complete() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(3, [3u8; 32], 1, b"a").unwrap();
        q.enqueue(4, [4u8; 32], 2, b"b").unwrap();
        q.mark_resolve_complete(4).unwrap();
        let m = q.list_meta();
        assert_eq!(m.len(), 2);
        let h3 = m.iter().find(|e| e.height == 3).unwrap();
        let h4 = m.iter().find(|e| e.height == 4).unwrap();
        assert!(!h3.resolve_complete);
        assert!(h4.resolve_complete);
        assert!(q.is_resolve_complete(4));
        assert!(!q.is_resolve_complete(3));
        let id4 = q.id_for_height(4).unwrap();
        assert!(q.dequeue(id4).unwrap());
        let m = q.list_meta();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].height, 3);
        assert!(!m[0].resolve_complete);
        assert!(!q.is_resolve_complete(4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unresolved_heights_skips_complete_and_respects_cap() {
        use std::collections::HashSet;
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        for h in 0..24u32 {
            q.enqueue(h, [h as u8; 32], 1, b"x").unwrap();
        }
        for h in 0..16u32 {
            q.mark_resolve_complete(h).unwrap();
        }
        let skip: HashSet<u32> = [16, 17].into_iter().collect();
        let got = q.unresolved_heights(10, &skip, 8);
        assert_eq!(got, vec![18, 19, 20, 21, 22, 23]);
        assert_eq!(q.unresolved_heights(10, &skip, 3), vec![18, 19, 20]);
        assert!(q.unresolved_heights(10, &skip, 0).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unresolved_heights_stops_at_first_gap() {
        use std::collections::HashSet;
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(12, [12u8; 32], 1, b"a").unwrap();
        q.enqueue(13, [13u8; 32], 1, b"b").unwrap();
        let none = HashSet::new();
        assert!(
            q.unresolved_heights(10, &none, 8).is_empty(),
            "missing path_lo must not skip ahead: {:?}",
            q.unresolved_heights(10, &none, 8)
        );
        q.enqueue(10, [10u8; 32], 1, b"c").unwrap();
        q.enqueue(11, [11u8; 32], 1, b"d").unwrap();
        assert_eq!(q.unresolved_heights(10, &none, 8), vec![10, 11, 12, 13]);
        // Hole at 12 after removing it — prefix only.
        q.dequeue_height(12).unwrap();
        assert_eq!(q.unresolved_heights(10, &none, 8), vec![10, 11]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_never_refuses_on_bytes() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let big = vec![0u8; 32 * 1024 * 1024];
        q.enqueue(1, [1u8; 32], 1, &big).unwrap();
        q.enqueue(2, [2u8; 32], 2, &big).unwrap();
        q.enqueue(3, [3u8; 32], 3, &big)
            .expect("BQ must accept already-requested bodies; densify assign-stop is the cap");
        assert_eq!(q.count(), 3);
        assert!(q.bytes() > 64 * 1024 * 1024);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_and_get_by_height() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        assert!(q.ids().is_empty());
        assert!(!q.contains_height(1));
        let id = q.enqueue(7, [7u8; 32], 1, b"xyz").unwrap();
        let mut ids = q.ids();
        ids.sort_unstable();
        assert_eq!(ids, vec![id]);
        assert!(q.contains_height(7));
        assert!(!q.contains_height(8));
        assert!(q.get_by_height(99).unwrap().is_none());
        let got = q.get_by_height(7).unwrap().unwrap();
        assert_eq!(got.payload, b"xyz");
        assert_eq!(q.get(id).unwrap().unwrap().payload, b"xyz");
        assert!(q.get(999).unwrap().is_none());
        assert_eq!(q.min_height(), Some(7));
        assert_eq!(q.max_height(), Some(7));
        assert!(q.dequeue(id).unwrap());
        assert!(!q.contains_height(7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_complete_clears_with_dequeue() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        let id = q.enqueue(5, [5u8; 32], 1, b"blk").unwrap();
        q.mark_resolve_complete(5).unwrap();
        assert!(q.is_resolve_complete(5));
        assert!(q.dequeue(id).unwrap());
        assert!(!q.is_resolve_complete(5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_complete_clears_with_dequeue_height() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(9, [9u8; 32], 1, b"a").unwrap();
        q.enqueue(10, [10u8; 32], 2, b"b").unwrap();
        q.mark_resolve_complete(10).unwrap();
        assert_eq!(q.dequeue_height(10).unwrap(), 1);
        assert!(!q.is_resolve_complete(10));
        assert!(q.contains_height(9));
        assert!(!q.is_resolve_complete(9));
        assert!(q.mark_resolve_complete(10).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lookup_take_removes_bq_row() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(10, [10u8; 32], 7, b"aaaa").unwrap();
        q.enqueue(11, [11u8; 32], 8, b"bb").unwrap();
        assert_eq!(q.bytes(), 6);
        let got = q.take_raw(10).expect("take 10");
        assert_eq!(got.hash, [10u8; 32]);
        assert_eq!(got.header_fk, 7);
        assert_eq!(got.payload, b"aaaa");
        assert!(!q.contains_height(10));
        assert!(q.contains_height(11));
        assert_eq!(q.bytes(), 2);
        assert!(q.take_raw(10).is_none());
        assert!(q.take_raw(99).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn promote_wave_drops_raw_and_charges_decoded() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(10, [1u8; 32], 1, b"aaaa").unwrap();
        q.enqueue(11, [2u8; 32], 2, b"bb").unwrap();
        q.enqueue(12, [3u8; 32], 3, b"c").unwrap();
        assert_eq!(q.bytes(), 7);
        let raw = q.raw_payloads(&[10, 11, 99]);
        assert_eq!(raw.len(), 2);
        assert_eq!(q.promote_wave(&[(10, 16), (11, 8)]).unwrap(), 2);
        assert_eq!(
            q.bytes(),
            16 + 8 + 1,
            "promoted charge replaces raw; 12 stays raw"
        );
        assert!(q.get_by_height(10).unwrap().unwrap().payload.is_empty());
        assert!(q.get_by_height(11).unwrap().unwrap().payload.is_empty());
        assert_eq!(q.get_by_height(12).unwrap().unwrap().payload, b"c");
        assert_eq!(q.raw_payloads(&[10, 11, 12]), vec![(12, b"c".to_vec())]);
        assert_eq!(q.promoted_count(), 2);
        let meta10 = q.list_meta().into_iter().find(|m| m.height == 10).unwrap();
        assert_eq!(meta10.payload_len, 16);
        assert_eq!(q.dequeue_height(10).unwrap(), 1);
        assert_eq!(q.bytes(), 8 + 1);
        assert_eq!(q.promoted_count(), 1);
        assert!(q.get_by_height(10).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_payload_clones_one_has_raw_does_not() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        for h in 0..8u32 {
            q.enqueue(h, [h as u8; 32], 1, &[h as u8; 8]).unwrap();
        }
        let _ = take_raw_clone_n();
        assert!(q.has_raw(3));
        assert_eq!(take_raw_clone_n(), 0);
        assert_eq!(q.raw_payload(3).unwrap().len(), 8);
        assert_eq!(take_raw_clone_n(), 1);
        let _ = q.promote_wave(&[(3, 16)]).unwrap();
        assert!(!q.has_raw(3));
        assert!(q.raw_payload(3).is_none());
        assert_eq!(take_raw_clone_n(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn height_index_survives_promote_and_dequeue() {
        let dir = temp();
        let mut q = BlockQueue::open_or_create(&dir).unwrap();
        q.enqueue(10, [10u8; 32], 1, b"a").unwrap();
        q.enqueue(11, [11u8; 32], 2, b"b").unwrap();
        q.enqueue(12, [12u8; 32], 3, b"c").unwrap();
        assert_eq!(q.id_for_height(11), Some(2));
        assert!(q.contains_height(11));
        q.mark_resolve_complete(11).unwrap();
        assert!(q.is_resolve_complete(11));
        assert!(!q.is_resolve_complete(10));
        assert_eq!(q.promote_wave(&[(11, 32)]).unwrap(), 1);
        assert_eq!(q.hash_at_height(11), Some([11u8; 32]));
        let snap = q.pack_snapshot(&[10, 11, 12, 99]);
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0], (10, [10u8; 32], false));
        assert_eq!(snap[1], (11, [11u8; 32], true));
        assert_eq!(snap[2], (12, [12u8; 32], false));
        assert_eq!(q.dequeue_height(11).unwrap(), 1);
        assert!(!q.contains_height(11));
        assert!(!q.is_resolve_complete(11));
        assert!(q.contains_height(10));
        assert!(q.contains_height(12));
        assert_eq!(q.id_for_height(10), Some(1));
        assert_eq!(q.id_for_height(12), Some(3));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
