//! Segmented Class A `tx.head`: fixed-bits open-address tables + seal-time fuse8.
//!
//! Layout:
//! ```text
//! store/
//!   tx.head/
//!     meta                       # segment descriptors
//!     000000                     # open OA only (unlinked after seal)
//!     000000.mphf + .fuse8     # sealed: value-assigned MPHF + fuse8
//!     …
//! ```
//!
//! Leftover flat `tx.head.meta` **refuses** (wipe `store/tx.head`; Class A kept).
//!
//! **Relative fks:** slot stores `rel` where `0` = empty and
//! `fk = first_fk + rel - 1` (1-based relative within the segment).
//!
//! **Capacity:** open segment ends at `floor(slots × HEAD_LOAD_START)` (80%);
//! then open a new head and seal the previous OA on a sidecar (MPHF + fuse8).
//! Lookup probes every unsealed OA until publish.
//!
//! **Lookup:** unsealed OAs newest-first; then sealed newest→oldest gated by fuse8;
//! candidates are absolute fks for body-verify by the caller.

use crate::address_head::{AddressHead, HeadLayout, HEAD_LOAD_START, MAINNET_BITS};
use crate::error::StoreError;
use crate::fuse8_filter::{fuse_key_from_mixed, open_file, FuseFileOpen, SealedFuse8};
use crate::tx_head_mphf::TxHeadMphf;
use rbitcoin_primitives::{Fk, SCHEMA_VERSION, STORE_MAGIC};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

const META_VERSION: u32 = 1;
const META_HEADER_LEN: usize = 24;
const SEG_DESC_LEN: usize = 32;
const FLAG_SEALED: u32 = 1;

/// Collect `(fuse_key, rel)` for a sealed range (`first_fk`, `count`).
///
/// Runs on the seal sidecar (or crash-reopen). `'static` so the worker can
/// pread `txid.body` after the write thread has already rolled.
pub(crate) type SealCollect =
    Arc<dyn Fn(u64, u64) -> Result<Vec<(u64, u32)>, StoreError> + Send + Sync>;

/// Product default head width (2²⁵ slots × 4 B = 128 MiB per segment).
pub const SEGMENT_HEAD_BITS: u32 = MAINNET_BITS;

struct Segment {
    first_fk: u64,
    count: AtomicU64,
    file_id: u32,
    sealed: bool,
    head: Option<Arc<AddressHead>>,
    pack: Option<Arc<TxHeadMphf>>,
    fuse: Option<SealedFuse8>,
}

pub(crate) struct SealPublish {
    file_id: u32,
    pack: crate::tx_head_mphf::TxHeadMphf,
}

/// Multi-segment keyless address head with seal-time binary fuse8.
pub struct SegmentedTxHead {
    dir: PathBuf,
    layout: HeadLayout,
    segments: RwLock<Arc<Vec<Arc<Segment>>>>,
    next_file_id: AtomicU32,
    max_keys: u64,
    /// Serializes seal/roll + inserts (sole Class A appender still the rule).
    write: Mutex<()>,
    /// Background seal of the previous open OA (not joined on insert).
    seal_rx: Mutex<Option<Receiver<Result<SealPublish, StoreError>>>>,
}

impl SegmentedTxHead {
    pub fn create(dir: &Path, layout: HeadLayout) -> Result<Self, StoreError> {
        if layout.entry_bytes != 4 {
            return Err(StoreError::Corrupt(
                "segmented tx.head requires 4 B relative entries",
            ));
        }
        let dir = dir.to_path_buf();
        refuse_legacy_mono_head(&dir)?;
        write_meta(&dir, layout.bits, &[])?;
        Ok(Self {
            dir,
            max_keys: max_keys_for_layout(layout),
            layout,
            segments: RwLock::new(Arc::new(Vec::new())),
            next_file_id: AtomicU32::new(0),
            write: Mutex::new(()),
            seal_rx: Mutex::new(None),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let dir = dir.to_path_buf();
        refuse_legacy_mono_head(&dir)?;
        let (bits, descs) = read_meta(&dir)?;
        let layout = HeadLayout::with_entry_bytes(bits, 4)?;
        let max_keys = max_keys_for_layout(layout);
        let mut segs = Vec::with_capacity(descs.len());
        let mut max_id = 0u32;
        for d in descs {
            let path = segment_head_path(&dir, d.file_id);
            let sealed = d.flags & FLAG_SEALED != 0;
            let (head, pack) = if sealed {
                if !TxHeadMphf::exists(&path) {
                    return Err(StoreError::Corrupt("tx.head sealed segment missing mphf"));
                }
                if path.is_file() {
                    // Crash between sealed-meta persist and OA unlink.
                    rbitcoin_log::warn!(
                        "store: tx.head discarding leftover OA for sealed segment file_id={}",
                        d.file_id
                    );
                    let _ = std::fs::remove_file(&path);
                }
                (None, Some(Arc::new(TxHeadMphf::open(&path)?)))
            } else {
                let head = AddressHead::open(&path)?;
                if head.bits() != bits || head.entry_bytes() != 4 {
                    return Err(StoreError::Corrupt("tx.head segment layout mismatch"));
                }
                (Some(Arc::new(head)), None)
            };
            let fuse = if sealed {
                let fp = segment_fuse_path(&dir, d.file_id);
                if !fp.exists() {
                    return Err(StoreError::Corrupt("tx.head sealed segment missing fuse8"));
                }
                match open_file(&fp)? {
                    FuseFileOpen::Ready(f) => Some(f),
                }
            } else {
                None
            };
            max_id = max_id.max(d.file_id);
            segs.push(Arc::new(Segment {
                first_fk: d.first_fk,
                count: AtomicU64::new(d.count),
                file_id: d.file_id,
                sealed,
                head,
                pack,
                fuse,
            }));
        }
        let unsealed_nontail = segs
            .iter()
            .enumerate()
            .filter(|(i, s)| i + 1 != segs.len() && !s.sealed)
            .count();
        if unsealed_nontail > 1 {
            return Err(StoreError::Corrupt(
                "tx.head multiple unsealed non-tail segments",
            ));
        }
        for w in segs.windows(2) {
            let a_end = w[0]
                .first_fk
                .saturating_add(w[0].count.load(Ordering::Relaxed));
            if w[1].first_fk != a_end {
                return Err(StoreError::Corrupt("tx.head segment fk gap/overlap"));
            }
        }
        // One summary for the whole head (not one line per segment).
        // Per-seg detail: `file_id@first_fk:count{s|o}` (s=sealed, o=open tail).
        let sealed_n = segs.iter().filter(|s| s.sealed).count();
        let open_n = segs.len().saturating_sub(sealed_n);
        let creates: u64 = segs.iter().map(|s| s.count.load(Ordering::Relaxed)).sum();
        let detail: String = segs
            .iter()
            .map(|s| {
                let c = s.count.load(Ordering::Relaxed);
                let flag = if s.sealed { 's' } else { 'o' };
                format!("{}@{}:{}{}", s.file_id, s.first_fk, c, flag)
            })
            .collect::<Vec<_>>()
            .join(" ");
        rbitcoin_log::info!(
            "store: tx.head open bits={bits} entry=4B slots={} segs={} sealed={sealed_n} \
             open={open_n} creates≈{creates} [{detail}]",
            layout.slots(),
            segs.len(),
        );
        Ok(Self {
            dir,
            layout,
            segments: RwLock::new(Arc::new(segs)),
            next_file_id: AtomicU32::new(max_id.saturating_add(1)),
            max_keys,
            write: Mutex::new(()),
            seal_rx: Mutex::new(None),
        })
    }

    pub fn bits(&self) -> u32 {
        self.layout.bits
    }

    pub fn slots(&self) -> u64 {
        self.layout.slots()
    }

    pub fn entry_bytes(&self) -> u8 {
        4
    }

    pub fn segment_count(&self) -> usize {
        self.segments_snapshot().len()
    }

    /// Per-segment `first_fk` (index 0 = oldest; last = open/tip).
    ///
    /// Used by head-resolve winner-age stats ([`crate::head_resolve_stats::sealed_age_for_fk`]).
    pub fn first_fks_snapshot(&self) -> Vec<u64> {
        self.segments_snapshot()
            .iter()
            .map(|s| s.first_fk)
            .collect()
    }

    pub fn sealed_segment_count(&self) -> usize {
        self.segments_snapshot().iter().filter(|s| s.sealed).count()
    }

    /// Sum of segment fk spans. Equals the number of indexed creates unless
    /// Class A holds bodies the head never received (those gap fks count too).
    pub fn occupied(&self) -> u64 {
        self.segments_snapshot()
            .iter()
            .map(|s| s.count.load(Ordering::Relaxed))
            .sum()
    }

    /// First fk of the oldest unsealed segment. Probes read every row at or
    /// above it from open-address slot pages, which a power loss can leave
    /// with holes under a synced `meta` count: insert syncs `meta` but not
    /// the pages. A roll syncs the pages it closes, but a hole already in
    /// them stays there until that segment's seal publishes, and the open tail
    /// and the in-flight seal are both unsealed. A seal rebuilds its rows from
    /// `txid.body` and syncs its files before `meta` names it sealed, so rows
    /// below this fk are complete. Never falls: a publish seals the oldest
    /// unsealed segment, and a roll opens past the last create. Past the last
    /// create when every segment is sealed.
    pub fn unsynced_first_fk(&self) -> u64 {
        let segs = self.segments_snapshot();
        match segs.iter().find(|s| !s.sealed) {
            Some(s) => s.first_fk,
            None => self.last_inserted_fk().saturating_add(1),
        }
    }

    /// Highest create_fk present in any segment (0 if empty).
    pub fn last_inserted_fk(&self) -> u64 {
        let segs = self.segments_snapshot();
        for s in segs.iter().rev() {
            let c = s.count.load(Ordering::Relaxed);
            if c > 0 {
                return s.first_fk.saturating_add(c).saturating_sub(1);
            }
        }
        0
    }

    pub fn sealed_mphf_g_resident_bytes(&self) -> u64 {
        self.segments_snapshot()
            .iter()
            .map(|s| s.pack.as_ref().map(|p| p.g_bytes_resident()).unwrap_or(0))
            .sum()
    }

    /// Heap-owned sealed fuse8 fingerprints (**0** when mapped from `.fuse8`).
    pub fn sealed_fuse_resident_bytes(&self) -> u64 {
        self.segments_snapshot()
            .iter()
            .map(|s| {
                s.fuse
                    .as_ref()
                    .map(|f| f.fingerprint_heap_bytes() as u64)
                    .unwrap_or(0)
            })
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn take_open_page_writes(&self) -> u64 {
        self.segments_snapshot()
            .last()
            .and_then(|s| s.head.as_ref().map(|h| h.take_page_writes()))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn take_sealed_g_page_preads(&self) -> u64 {
        self.segments_snapshot()
            .iter()
            .map(|s| s.pack.as_ref().map(|p| p.take_g_page_preads()).unwrap_or(0))
            .sum()
    }

    /// Open-tail page hop dump for leftover-miss diagnostics.
    pub(crate) fn leftover_open_hop(
        &self,
        mixed: &[u8; 32],
    ) -> Result<(u32, u64, crate::address_head::PageHopDump), StoreError> {
        let segs = self.segments_snapshot();
        let Some(last) = segs.last() else {
            return Ok((
                0,
                0,
                crate::address_head::PageHopDump {
                    scan: crate::address_head::ProbeRegionScan {
                        cands: crate::address_head::ProbeCands::default(),
                        hit_empty: true,
                        depth_end: 0,
                        empty_local: 0,
                    },
                    hop_equal_second: true,
                    occupied: 0,
                },
            ));
        };
        let Some(head) = last.head.as_ref() else {
            return Err(StoreError::Corrupt("tx.head leftover hop: tail sealed"));
        };
        let dump = head.dump_page_hop(mixed)?;
        Ok((last.file_id, last.first_fk, dump))
    }

    fn segments_snapshot(&self) -> Arc<Vec<Arc<Segment>>> {
        Arc::clone(&self.segments.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Insert mixed probe keys → absolute create fks (sole writer).
    ///
    /// Relativizes `entries` fks in place (absolute → segment-relative) then
    /// sorts that same buffer in the open HashHead — no extra pair copy.
    ///
    /// Rolls when the open segment's fk span reaches `max_keys` (80% of slots),
    /// or the next fk lies past that span. Publish drains
    /// on the next `insert_many`, [`Self::flush`], or `Drop` — not joined on
    /// the roll that started it. Seal keys are collected on the sidecar from
    /// `txid.body` (crash-reopen stays on the open thread).
    #[cfg(test)]
    pub fn insert_many(&self, entries: &mut [([u8; 32], Fk)]) -> Result<(), StoreError> {
        let snap: Vec<([u8; 32], u64)> = entries.iter().map(|(m, f)| (*m, f.0)).collect();
        let collect: SealCollect = Arc::new(move |first_fk, count| {
            let mut pairs = Vec::with_capacity(count as usize);
            for i in 0..count {
                let fk = first_fk + i;
                let mixed = snap.iter().find(|(_, f)| *f == fk).map(|(m, _)| *m).ok_or(
                    StoreError::Corrupt("tx.head seal collect: fk not in insert batch"),
                )?;
                pairs.push((fuse_key_from_mixed(&mixed), (i as u32) + 1));
            }
            Ok(pairs)
        });
        self.insert_many_with(entries, collect)
    }

    /// Insert; `collect` runs on the seal sidecar at roll (not on this thread).
    pub(crate) fn insert_many_with(
        &self,
        entries: &mut [([u8; 32], Fk)],
        collect: SealCollect,
    ) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let _w = self.write.lock().unwrap_or_else(|e| e.into_inner());

        self.try_publish_seal_locked()?;

        // Callers pass non-decreasing absolute fks. `count` is the span, not the entry count.
        let mut i = 0usize;
        while i < entries.len() {
            self.ensure_open_for(entries[i].1 .0)?;
            let segs = self.segments_snapshot();
            let last = segs
                .last()
                .ok_or(StoreError::Corrupt("tx.head no open segment"))?;
            if last.sealed {
                return Err(StoreError::Corrupt("tx.head tail sealed unexpectedly"));
            }
            let count = last.count.load(Ordering::Relaxed);
            if count >= self.max_keys {
                self.roll_tail_background_locked(collect.clone())?;
                continue;
            }
            let first_fk = last.first_fk;
            let span_end = first_fk.saturating_add(self.max_keys);
            let take = entries[i..]
                .iter()
                .take_while(|(_, fk)| fk.0 < span_end)
                .count();
            if take == 0 {
                // The next fk lies past this segment's span (a gap at its end).
                // An empty segment wholly inside the gap claims its full span,
                // or the roll is a no-op (count == 0) and this loop never ends.
                // A gap of k whole spans costs k serial seals here; on mainnet
                // that needs a gap of max_keys (~26.8M) orphan bodies.
                if count == 0 {
                    last.count.store(self.max_keys, Ordering::Relaxed);
                }
                self.roll_tail_background_locked(collect.clone())?;
                continue;
            }
            let batch = &mut entries[i..i + take];

            let mut max_rel = count;
            for (_mixed, fk) in batch.iter_mut() {
                if fk.0 < first_fk {
                    return Err(StoreError::Corrupt("tx.head insert fk before segment"));
                }
                let rel = fk.0 - first_fk + 1;
                if rel == 0 || rel > u32::MAX as u64 {
                    return Err(StoreError::Corrupt("tx.head relative fk overflow"));
                }
                max_rel = max_rel.max(rel);
                *fk = Fk(rel);
            }
            last.head
                .as_ref()
                .ok_or(StoreError::Corrupt("tx.head insert: open missing OA"))?
                .insert_many_in_place(batch)?;
            last.count.fetch_max(max_rel, Ordering::Relaxed);
            i += take;

            if max_rel >= self.max_keys {
                self.roll_tail_background_locked(collect.clone())?;
            }
        }
        self.persist_meta_locked()?;
        Ok(())
    }
}

/// Which head segments a probe walks. Lookup uses [`HeadProbeWave::All`]
/// for a full probe and [`HeadProbeWave::Open`] for the unsealed tail.
/// Sealed segments are retired one at a time by the resolve machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadProbeWave {
    /// Open + all sealed.
    All,
    /// All unsealed OAs (insert tail + in-flight seal), newest first.
    Open,
}

impl HeadProbeWave {
    #[inline]
    fn includes_open(self) -> bool {
        matches!(self, HeadProbeWave::All | HeadProbeWave::Open)
    }

    /// `age` is unused: every sealed segment is included only on [`Self::All`].
    #[inline]
    fn includes_sealed_age(self, _age: u32) -> bool {
        matches!(self, HeadProbeWave::All)
    }
}

impl SegmentedTxHead {
    /// Probe absolute create_fk candidates for a mixed key (open → sealed new→old).
    ///
    /// Order within each segment: deepest probe first is applied by reversing
    /// the page probe list. Across segments: open first, then sealed newest first.
    /// Caller body-verifies.
    pub fn probe_candidates(&self, mixed: &[u8; 32]) -> Result<Vec<Fk>, StoreError> {
        let mut out = self.probe_candidates_batch(std::slice::from_ref(mixed))?;
        Ok(out.pop().unwrap_or_default())
    }

    /// Batch probe: same order/results as N× [`Self::probe_candidates`], with
    /// **page-coalesced** loads inside each segment ([`AddressHead::probe_fks_batch`]).
    ///
    /// Sealed segments still fuse-gate per key; only keys that pass are batched
    /// for that segment's page loads. Page IO uses TLS bulk_io.
    pub fn probe_candidates_batch(&self, mixed: &[[u8; 32]]) -> Result<Vec<Vec<Fk>>, StoreError> {
        self.probe_candidates_batch_wave(mixed, HeadProbeWave::All, None, &mut crate::IoCtx::none())
    }

    /// One probe walk: `wave` + shared [`crate::IoCtx`] (held session or standalone).
    pub(crate) fn probe_candidates_batch_wave(
        &self,
        mixed: &[[u8; 32]],
        wave: HeadProbeWave,
        active: Option<&[bool]>,
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<Vec<Fk>>, StoreError> {
        let n = mixed.len();
        let mut out = vec![Vec::new(); n];
        if n == 0 {
            return Ok(out);
        }
        let segs = self.segments_snapshot();
        if segs.is_empty() {
            return Ok(out);
        }
        if wave.includes_open() {
            self.probe_unsealed_wave(mixed, active, ctx, &mut out)?;
        }
        self.probe_sealed_wave(mixed, wave, active, ctx, &mut out)?;
        Ok(out)
    }

    /// One sealed segment, newest-first caller order. Unsealed `si` returns
    /// empty lists (the open wave already probed those OAs).
    pub(crate) fn probe_sealed_segment(
        &self,
        mixed: &[[u8; 32]],
        si: usize,
        active: Option<&[bool]>,
        ctx: &mut crate::IoCtx<'_>,
    ) -> Result<Vec<Vec<Fk>>, StoreError> {
        let n = mixed.len();
        let mut out = vec![Vec::new(); n];
        if n == 0 {
            return Ok(out);
        }
        let segs = self.segments_snapshot();
        if si >= segs.len() {
            return Ok(out);
        }
        self.fill_sealed_segment(&segs, si, mixed, active, ctx, &mut out)?;
        Ok(out)
    }

    fn probe_unsealed_wave(
        &self,
        mixed: &[[u8; 32]],
        active: Option<&[bool]>,
        ctx: &mut crate::IoCtx<'_>,
        out: &mut [Vec<Fk>],
    ) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        let key_on = |i: usize| active.map(|a| a[i]).unwrap_or(true);
        for seg in segs.iter().rev() {
            if seg.sealed {
                continue;
            }
            let Some(head) = seg.head.as_ref() else {
                continue;
            };
            let mut pass_i: Vec<usize> = Vec::new();
            let mut pass_keys: Vec<[u8; 32]> = Vec::new();
            for (i, key) in mixed.iter().enumerate() {
                if !key_on(i) {
                    continue;
                }
                pass_i.push(i);
                pass_keys.push(*key);
            }
            if pass_keys.is_empty() {
                continue;
            }
            let rel_lists = head.probe_fks_batch_ctx(&pass_keys, ctx)?;
            for (orig_i, rels) in pass_i.into_iter().zip(rel_lists) {
                for r in rels.into_iter().rev() {
                    if let Some(fk) = rel_to_abs(seg.first_fk, r.0) {
                        out[orig_i].push(fk);
                    }
                }
            }
        }
        Ok(())
    }

    fn probe_sealed_wave(
        &self,
        mixed: &[[u8; 32]],
        wave: HeadProbeWave,
        active: Option<&[bool]>,
        ctx: &mut crate::IoCtx<'_>,
        out: &mut [Vec<Fk>],
    ) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        let n_segs = segs.len();
        for si in (0..n_segs).rev() {
            if !segs[si].sealed {
                continue;
            }
            let age = crate::head_resolve_stats::sealed_age_from_index(si, n_segs);
            if !wave.includes_sealed_age(age) {
                continue;
            }
            self.fill_sealed_segment(&segs, si, mixed, active, ctx, out)?;
        }
        Ok(())
    }

    /// Fuse-filter `active` keys, then one MPHF batch (or the sealed OA).
    fn fill_sealed_segment(
        &self,
        segs: &[Arc<Segment>],
        si: usize,
        mixed: &[[u8; 32]],
        active: Option<&[bool]>,
        ctx: &mut crate::IoCtx<'_>,
        out: &mut [Vec<Fk>],
    ) -> Result<(), StoreError> {
        let seg = &segs[si];
        if !seg.sealed {
            return Ok(());
        }
        let Some(fuse) = seg.fuse.as_ref() else {
            return Err(StoreError::Corrupt("sealed segment missing fuse"));
        };
        let key_on = |i: usize| active.map(|a| a[i]).unwrap_or(true);

        let mut pass_i: Vec<usize> = Vec::new();
        let mut pass_keys: Vec<[u8; 32]> = Vec::new();
        for (i, m) in mixed.iter().enumerate() {
            if !key_on(i) {
                continue;
            }
            let fuse_key = fuse_key_from_mixed(m);
            if !fuse.contains(fuse_key) {
                continue;
            }
            pass_i.push(i);
            pass_keys.push(*m);
        }
        if pass_keys.is_empty() {
            return Ok(());
        }
        if let Some(pack) = seg.pack.as_ref() {
            let mixed_u: Vec<u64> = pass_keys.iter().map(fuse_key_from_mixed).collect();
            let slots = pack.slots_for_ctx(&mixed_u, ctx)?;
            let rel_lists = pack.read_rels_batch(&slots, ctx)?;
            for (orig_i, rels) in pass_i.into_iter().zip(rel_lists) {
                for r in rels {
                    if let Some(fk) = rel_to_abs(seg.first_fk, u64::from(r)) {
                        out[orig_i].push(fk);
                    }
                }
            }
        } else {
            let rel_lists = seg
                .head
                .as_ref()
                .ok_or(StoreError::Corrupt("tx.head sealed probe: missing pack"))?
                .probe_fks_batch_ctx(&pass_keys, ctx)?;
            for (orig_i, rels) in pass_i.into_iter().zip(rel_lists) {
                for r in rels.into_iter().rev() {
                    if let Some(fk) = rel_to_abs(seg.first_fk, r.0) {
                        out[orig_i].push(fk);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        for s in segs.iter() {
            if let Some(h) = s.head.as_ref() {
                h.flush()?;
            }
        }
        let _w = self.write.lock().unwrap_or_else(|e| e.into_inner());
        self.wait_seal_locked()?;
        self.persist_meta_locked()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        for s in segs.iter() {
            if let Some(h) = s.head.as_ref() {
                h.flush_async()?;
            }
        }
        Ok(())
    }

    fn ensure_open_for(&self, first_fk: u64) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        if segs.is_empty() {
            return self.open_new_locked(first_fk);
        }
        let last = segs.last().unwrap();
        if last.sealed {
            return self.open_new_locked(first_fk);
        }
        Ok(())
    }

    fn open_new_locked(&self, first_fk: u64) -> Result<(), StoreError> {
        if first_fk == 0 {
            return Err(StoreError::InvalidFk);
        }
        let file_id = self.next_file_id.fetch_add(1, Ordering::Relaxed);
        let path = segment_head_path(&self.dir, file_id);
        let _ = std::fs::remove_file(&path);
        let head = AddressHead::create_with_layout(&path, self.layout)?;
        let seg = Arc::new(Segment {
            first_fk,
            count: AtomicU64::new(0),
            file_id,
            sealed: false,
            head: Some(Arc::new(head)),
            pack: None,
            fuse: None,
        });
        {
            let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
            let mut new_list = (**guard).clone();

            if let Some(last) = new_list.last() {
                if !last.sealed && last.count.load(Ordering::Relaxed) == 0 {
                    let fid = last.file_id;
                    new_list.pop();
                    let _ = std::fs::remove_file(segment_head_path(&self.dir, fid));
                }
            }
            new_list.push(seg);
            *guard = Arc::new(new_list);
        }

        rbitcoin_log::info!(
            "store: tx.head roll open file_id={file_id} first_fk={first_fk} bits={} slots={}",
            self.layout.bits,
            self.layout.slots(),
        );
        self.persist_meta_locked()?;
        Ok(())
    }

    fn try_publish_seal_locked(&self) -> Result<(), StoreError> {
        let rx = {
            let mut g = self.seal_rx.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        let Some(rx) = rx else {
            return Ok(());
        };
        match rx.try_recv() {
            Ok(Ok(p)) => self.apply_seal_publish_locked(p),
            Ok(Err(e)) => Err(e),
            Err(mpsc::TryRecvError::Empty) => {
                *self.seal_rx.lock().unwrap_or_else(|e| e.into_inner()) = Some(rx);
                Ok(())
            }
            Err(mpsc::TryRecvError::Disconnected) => Err(StoreError::Corrupt(
                "tx.head background seal worker disconnected",
            )),
        }
    }

    fn wait_seal_locked(&self) -> Result<(), StoreError> {
        let rx = {
            let mut g = self.seal_rx.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        let Some(rx) = rx else {
            return Ok(());
        };
        match rx.recv() {
            Ok(Ok(p)) => self.apply_seal_publish_locked(p),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StoreError::Corrupt(
                "tx.head background seal worker disconnected",
            )),
        }
    }

    fn apply_seal_publish_locked(&self, p: SealPublish) -> Result<(), StoreError> {
        let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
        let mut new_list = (**guard).clone();
        let mut found = false;
        for s in &mut new_list {
            if s.file_id != p.file_id {
                continue;
            }
            if s.sealed {
                return Err(StoreError::Corrupt("tx.head seal publish: already sealed"));
            }
            let count = s.count.load(Ordering::Relaxed);
            let first_fk = s.first_fk;
            let file_id = p.file_id;
            *s = Arc::new(Segment {
                first_fk,
                count: AtomicU64::new(count),
                file_id,
                sealed: true,
                head: None,
                pack: Some(Arc::new(p.pack)),
                fuse: Some(map_segment_fuse(&self.dir, file_id)?),
            });
            found = true;
            break;
        }
        if !found {
            return Err(StoreError::Corrupt("tx.head seal publish: file_id missing"));
        }
        *guard = Arc::new(new_list);
        drop(guard);
        // Sealed meta must be durable before the OA is unlinked: a crash after
        // unlink with meta still "open" would force a full head rebuild. A
        // leftover OA after persist is discarded on open.
        self.persist_meta_locked()?;
        let base = segment_head_path(&self.dir, p.file_id);
        let _ = std::fs::remove_file(&base);
        Ok(())
    }

    fn roll_tail_background_locked(&self, collect: SealCollect) -> Result<(), StoreError> {
        self.wait_seal_locked()?;
        let segs = self.segments_snapshot();
        let last = segs
            .last()
            .ok_or(StoreError::Corrupt("tx.head roll empty"))?;
        if last.sealed {
            return Ok(());
        }
        let count = last.count.load(Ordering::Relaxed);
        if count == 0 {
            return Ok(());
        }
        let file_id = last.file_id;
        let first_fk = last.first_fk;
        if let Some(h) = last.head.as_ref() {
            h.flush()?;
        }
        let next_fk = first_fk.saturating_add(count);
        self.open_new_locked(next_fk)?;
        self.persist_meta_locked()?;
        self.spawn_seal(file_id, first_fk, count, collect);
        Ok(())
    }

    fn spawn_seal(&self, file_id: u32, first_fk: u64, count: u64, collect: SealCollect) {
        let dir = self.dir.clone();
        let (tx, rx) = mpsc::channel();
        *self.seal_rx.lock().unwrap_or_else(|e| e.into_inner()) = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(collect_and_seal(&dir, file_id, first_fk, count, collect));
        });
    }

    fn seal_file_sync_locked(
        &self,
        file_id: u32,
        pairs: Vec<(u64, u32)>,
    ) -> Result<(), StoreError> {
        self.wait_seal_locked()?;
        let segs = self.segments_snapshot();
        let Some(seg) = segs.iter().find(|s| s.file_id == file_id) else {
            return Err(StoreError::Corrupt("tx.head seal_file: missing"));
        };
        if seg.sealed {
            return Ok(());
        }
        let count = seg.count.load(Ordering::Relaxed);
        if count == 0 {
            return Ok(());
        }
        if pairs.len() as u64 != count {
            return Err(StoreError::Corrupt(
                "tx.head seal open_keys incomplete (reopen mid-segment without rebuild)",
            ));
        }
        if let Some(h) = seg.head.as_ref() {
            h.flush()?;
        }
        let pubd = build_seal_publish(&self.dir, file_id, seg.first_fk, count, pairs)?;
        self.apply_seal_publish_locked(pubd)
    }

    /// Crash reopen: seal every unsealed non-tail (caller collected keys).
    pub fn seal_file_sync(&self, file_id: u32, pairs: Vec<(u64, u32)>) -> Result<(), StoreError> {
        let _w = self.write.lock().unwrap_or_else(|e| e.into_inner());
        self.seal_file_sync_locked(file_id, pairs)
    }

    /// Unsealed non-tail `(file_id, first_fk, count)` (in-flight seal after crash).
    pub fn unsealed_nontail_ranges(&self) -> Vec<(u32, u64, u64)> {
        let segs = self.segments_snapshot();
        let n = segs.len();
        segs.iter()
            .enumerate()
            .filter(|(i, s)| i + 1 != n && !s.sealed)
            .map(|(_, s)| (s.file_id, s.first_fk, s.count.load(Ordering::Relaxed)))
            .collect()
    }

    /// Unsealed segments `(file_id, first_fk, count)` (insert tail + in-flight seal).
    #[cfg(test)]
    pub fn unsealed_ranges(&self) -> Vec<(u32, u64, u64)> {
        self.segments_snapshot()
            .iter()
            .filter(|s| !s.sealed)
            .map(|s| (s.file_id, s.first_fk, s.count.load(Ordering::Relaxed)))
            .collect()
    }

    pub(crate) fn write_sealed_pairs(
        &self,
        file_id: u32,
        first_fk: u64,
        count: u64,
        pairs: Vec<(u64, u32)>,
    ) -> Result<SealPublish, StoreError> {
        build_seal_publish(&self.dir, file_id, first_fk, count, pairs)
    }

    /// Replace the segment list with sealed MPHF ranges and an empty open tail.
    pub(crate) fn install_rebuild_sealed(
        &self,
        sealed: Vec<(u64, u64, SealPublish)>,
        tail_first_fk: u64,
    ) -> Result<(), StoreError> {
        let _w = self.write.lock().unwrap_or_else(|e| e.into_inner());
        self.wait_seal_locked()?;
        let mut max_id = 0u32;
        let mut list = Vec::with_capacity(sealed.len().saturating_add(1));
        for (first_fk, count, p) in sealed {
            max_id = max_id.max(p.file_id);
            let fuse = map_segment_fuse(&self.dir, p.file_id)?;
            list.push(Arc::new(Segment {
                first_fk,
                count: AtomicU64::new(count),
                file_id: p.file_id,
                sealed: true,
                head: None,
                pack: Some(Arc::new(p.pack)),
                fuse: Some(fuse),
            }));
        }
        {
            let mut guard = self.segments.write().unwrap_or_else(|e| e.into_inner());
            *guard = Arc::new(list);
        }
        self.next_file_id
            .store(max_id.saturating_add(1), Ordering::Relaxed);
        self.open_new_locked(tail_first_fk)?;
        Ok(())
    }

    fn persist_meta_locked(&self) -> Result<(), StoreError> {
        let segs = self.segments_snapshot();
        let descs: Vec<(u64, u64, u32, u32)> = segs
            .iter()
            .map(|s| {
                let flags = if s.sealed { FLAG_SEALED } else { 0 };
                (
                    s.first_fk,
                    s.count.load(Ordering::Relaxed),
                    s.file_id,
                    flags,
                )
            })
            .collect();
        write_meta(&self.dir, self.layout.bits, &descs)
    }
}

impl Drop for SegmentedTxHead {
    fn drop(&mut self) {
        let _w = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.wait_seal_locked();
    }
}

fn collect_and_seal(
    dir: &Path,
    file_id: u32,
    first_fk: u64,
    count: u64,
    collect: SealCollect,
) -> Result<SealPublish, StoreError> {
    let t0 = Instant::now();
    let pairs = collect(first_fk, count)?;
    rbitcoin_log::info!(
        "store: tx.head seal collect file_id={file_id} count={count} duration_ms={}",
        t0.elapsed().as_millis()
    );
    if pairs.len() as u64 != count {
        return Err(StoreError::Corrupt(
            "tx.head seal collect pair count mismatch",
        ));
    }
    build_seal_publish(dir, file_id, first_fk, count, pairs)
}

fn build_seal_publish(
    dir: &Path,
    file_id: u32,
    first_fk: u64,
    count: u64,
    mut pairs: Vec<(u64, u32)>,
) -> Result<SealPublish, StoreError> {
    let raw_n = pairs.len();
    let grouped = crate::tx_head_mphf::group_assigned_pairs(&mut pairs)?;
    drop(pairs);
    let unique_n = grouped.keys.len();
    rbitcoin_log::info!(
        "store: tx.head seal begin file_id={file_id} first_fk={first_fk} count={count} \
         fuse_keys_raw={raw_n} fuse_keys_unique={unique_n}"
    );
    let t0 = Instant::now();
    let fuse = SealedFuse8::build(&grouped.keys)?;
    let fuse_bytes = fuse.fingerprint_bytes();
    fuse.write_to(&segment_fuse_path(dir, file_id))?;
    let pack = TxHeadMphf::write_grouped(segment_head_path(dir, file_id), grouped)?;
    rbitcoin_log::info!(
        "store: tx.head seal done file_id={file_id} count={count} fuse_keys_unique={unique_n} \
         fuse_bytes={fuse_bytes} duration_ms={}",
        t0.elapsed().as_millis()
    );
    Ok(SealPublish { file_id, pack })
}

#[inline]
fn rel_to_abs(first_fk: u64, rel: u64) -> Option<Fk> {
    if rel == 0 {
        return None;
    }
    Some(Fk(first_fk + rel - 1))
}

fn max_keys_for_layout(layout: HeadLayout) -> u64 {
    let slots = layout.slots();
    ((slots as f64) * HEAD_LOAD_START).floor() as u64
}

/// `store/tx.head/` — segment files + meta live here.
#[inline]
fn head_root(dir: &Path) -> PathBuf {
    dir.join("tx.head")
}

fn refuse_legacy_mono_head(dir: &Path) -> Result<(), StoreError> {
    let mono = dir.join("tx.head");
    if mono.is_file() {
        return Err(StoreError::Corrupt(
            "legacy monolithic tx.head present — reindex required (segmented 25-bit heads)",
        ));
    }
    // Directory is the **new** segment home. Reject only non-empty dirs that are
    // not our layout (no `meta`, no pending flat migration).
    if mono.is_dir() {
        let new_meta = mono.join("meta");
        if !new_meta.is_file() && !dir.join("tx.head.meta").is_file() {
            let non_empty = std::fs::read_dir(&mono)
                .map(|rd| rd.filter_map(|e| e.ok()).next().is_some())
                .unwrap_or(false);
            if non_empty {
                return Err(StoreError::Corrupt(
                    "legacy sharded tx.head/ dir — reindex required",
                ));
            }
        }
    }
    for name in [
        "tx.head.new",
        "tx.head.resize",
        "tx.head.bak",
        "tx.head.overflow",
    ] {
        let p = dir.join(name);
        if p.exists() {
            rbitcoin_log::warn!(
                "store: removing obsolete mono-head artifact {}",
                p.display()
            );
            let _ = std::fs::remove_file(&p);
        }
    }
    ensure_head_layout(dir)?;
    Ok(())
}

/// Leftover flat `tx.head.meta` (pre-directory layout).
pub const INDEX_REFUSE_FLAT_HEAD: &str = "index refuses flat tx.head.meta; wipe store/tx.head then restart (Class A kept; tx.head rebuilds)";

/// Leftover **layouts** that must not auto-rebuild (v1 fuse, flat `tx.head.meta`).
/// Torn current-layout files (`bdz mphf:*`, short meta) rebuild from Class A.
pub(crate) fn is_index_open_refuse(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::Corrupt(m)
            if *m == crate::fuse8_filter::INDEX_REFUSE_FUSE8_V1 || *m == INDEX_REFUSE_FLAT_HEAD
    )
}

/// Ensure `tx.head/` exists. Leftover flat `tx.head.meta` refuses.
fn ensure_head_layout(dir: &Path) -> Result<(), StoreError> {
    let root = head_root(dir);
    let new_meta = meta_path(dir);
    let flat_meta = dir.join("tx.head.meta");
    if flat_meta.is_file() {
        return Err(StoreError::Corrupt(INDEX_REFUSE_FLAT_HEAD));
    }
    if new_meta.is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(&root).map_err(|e| StoreError::io(&root, e))?;
    Ok(())
}

fn segment_head_path(dir: &Path, file_id: u32) -> PathBuf {
    head_root(dir).join(format!("{file_id:06}"))
}

fn segment_fuse_path(dir: &Path, file_id: u32) -> PathBuf {
    head_root(dir).join(format!("{file_id:06}.fuse8"))
}

fn map_segment_fuse(dir: &Path, file_id: u32) -> Result<SealedFuse8, StoreError> {
    SealedFuse8::read_from(&segment_fuse_path(dir, file_id))
}

fn meta_path(dir: &Path) -> PathBuf {
    head_root(dir).join("meta")
}

/// True when segmented head meta exists (subdir or pre-migration flat).
pub fn head_meta_exists(dir: &Path) -> bool {
    meta_path(dir).is_file() || dir.join("tx.head.meta").is_file()
}

/// Remove all segmented head files (subdir layout + any leftover flat files).
pub fn wipe_segmented_head_files(dir: &Path) {
    let root = head_root(dir);
    if root.is_dir() {
        let _ = std::fs::remove_dir_all(&root);
    }
    let _ = std::fs::remove_file(dir.join("tx.head.meta"));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let s = ent.file_name().to_string_lossy().into_owned();
            if s.starts_with("tx.head.") {
                let _ = std::fs::remove_file(ent.path());
            }
        }
    }
}

fn write_meta(dir: &Path, bits: u32, segs: &[(u64, u64, u32, u32)]) -> Result<(), StoreError> {
    let path = meta_path(dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
    }
    let mut buf = Vec::with_capacity(META_HEADER_LEN + segs.len() * SEG_DESC_LEN);
    buf.extend_from_slice(&STORE_MAGIC);
    buf.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&META_VERSION.to_le_bytes());
    buf.extend_from_slice(&(segs.len() as u32).to_le_bytes());
    buf.extend_from_slice(&bits.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    for &(first_fk, count, file_id, flags) in segs {
        buf.extend_from_slice(&first_fk.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());
        buf.extend_from_slice(&file_id.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
    }
    crate::file::write_synced_tmp_rename(&path, &buf)?;
    Ok(())
}

struct SegDesc {
    first_fk: u64,
    count: u64,
    file_id: u32,
    flags: u32,
}

fn read_meta(dir: &Path) -> Result<(u32, Vec<SegDesc>), StoreError> {
    let path = meta_path(dir);
    if !path.exists() {
        return Ok((SEGMENT_HEAD_BITS, Vec::new()));
    }
    let buf = std::fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
    read_meta_buf(&buf)
}

fn read_meta_buf(buf: &[u8]) -> Result<(u32, Vec<SegDesc>), StoreError> {
    if buf.len() < META_HEADER_LEN {
        return Err(StoreError::Corrupt("tx.head.meta short"));
    }
    if buf[0..4] != STORE_MAGIC {
        return Err(StoreError::Corrupt("tx.head.meta magic"));
    }
    let meta_ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if meta_ver != META_VERSION {
        return Err(StoreError::Corrupt("tx.head.meta version"));
    }
    let seg_count = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let bits = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let need = META_HEADER_LEN + seg_count * SEG_DESC_LEN;
    if buf.len() < need {
        return Err(StoreError::Corrupt("tx.head.meta truncated"));
    }
    let mut descs = Vec::with_capacity(seg_count);
    for i in 0..seg_count {
        let o = META_HEADER_LEN + i * SEG_DESC_LEN;
        descs.push(SegDesc {
            first_fk: u64::from_le_bytes(buf[o..o + 8].try_into().unwrap()),
            count: u64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap()),
            file_id: u32::from_le_bytes(buf[o + 16..o + 20].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[o + 20..o + 24].try_into().unwrap()),
        });
    }
    Ok((bits, descs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_head::HeadLayout;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-seghead-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mixed(i: u64) -> [u8; 32] {
        let mut m = [0u8; 32];
        m[0..8].copy_from_slice(&i.to_le_bytes());
        m[8] = 0xA5;
        m
    }

    #[test]
    fn probe_candidates_batch_empty_is_empty() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        assert!(h.probe_candidates_batch(&[]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_flat_head_layout_on_open() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let mut entries = Vec::new();
            for i in 0..50u64 {
                entries.push((mixed(i + 1), Fk(i + 1)));
            }
            h.insert_many(&mut entries).unwrap();
            h.flush().unwrap();
        }
        assert!(dir.join("tx.head").join("meta").is_file());
        // Flatten to legacy flat paths.
        let root = dir.join("tx.head");
        std::fs::rename(root.join("meta"), dir.join("tx.head.meta")).unwrap();
        for ent in std::fs::read_dir(&root).unwrap().flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if s == "meta" || s == "meta.tmp" {
                continue;
            }
            let dst = dir.join(format!("tx.head.{s}"));
            std::fs::rename(ent.path(), &dst).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
        assert!(dir.join("tx.head.meta").is_file());
        assert!(!dir.join("tx.head").join("meta").exists());

        match SegmentedTxHead::open(&dir) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, INDEX_REFUSE_FLAT_HEAD);
                assert!(m.contains("Class A kept"), "{m}");
            }
            Ok(_) => panic!("flat tx.head.meta must refuse open"),
            Err(other) => panic!("expected INDEX_REFUSE_FLAT_HEAD, got {other}"),
        }
        assert!(dir.join("tx.head.meta").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Class A can hold bodies the head never gets (a write that appends and
    /// then rejects on the planned-fk check). The inserted fk stream then has
    /// a gap. A segment must still seal exactly the fks it holds: the last
    /// entries before the roll must stay findable after the seal publishes.
    #[test]
    fn fk_gap_before_roll_keeps_entries_findable_after_seal() {
        let dir = tmp();
        // 8-bit head: 256 slots, max_keys = floor(0.8*256) = 204.
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        // Production collect reads txids for the fk range from txid.body,
        // which also holds the orphan bodies the head never saw.
        let collect: SealCollect = std::sync::Arc::new(|first_fk, count| {
            Ok((0..count)
                .map(|i| (fuse_key_from_mixed(&mixed(first_fk + i)), (i as u32) + 1))
                .collect())
        });
        let orphans = 51..=60u64;
        let mut entries: Vec<_> = (1..=300u64)
            .filter(|fk| !orphans.contains(fk))
            .map(|fk| (mixed(fk), Fk(fk)))
            .collect();
        h.insert_many_with(&mut entries, collect.clone()).unwrap();
        h.flush().unwrap();
        // The next insert publishes the finished seal (OA unlinked).
        h.insert_many_with(&mut [(mixed(301), Fk(301))], collect)
            .unwrap();
        assert!(h.sealed_segment_count() >= 1, "segment 0 must have sealed");

        let mut lost = Vec::new();
        for fk in (1..=301u64).filter(|fk| !orphans.contains(fk)) {
            let cands = h.probe_candidates(&mixed(fk)).unwrap();
            if !cands.contains(&Fk(fk)) {
                lost.push(fk);
            }
        }
        assert!(
            lost.is_empty(),
            "head lost {} entries: {lost:?}",
            lost.len()
        );
        assert_eq!(h.last_inserted_fk(), 301, "coverage must reach the last fk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A gap at the very end of a segment's span rolls on the next fk (the
    /// `take == 0` path), and the result still reopens: `open` requires
    /// `first_fk + count` of one segment to equal the next segment's first_fk.
    #[test]
    fn fk_gap_at_segment_end_rolls_and_reopens() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let collect: SealCollect = std::sync::Arc::new(|first_fk, count| {
            Ok((0..count)
                .map(|i| (fuse_key_from_mixed(&mixed(first_fk + i)), (i as u32) + 1))
                .collect())
        });
        // fks 195..=210 are orphans: the span of segment 0 (1..=204) ends
        // inside the gap, and 211 is the first fk past it.
        let orphan = |fk: u64| (195..=210).contains(&fk);
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let mut entries: Vec<_> = (1..=260u64)
                .filter(|fk| !orphan(*fk))
                .map(|fk| (mixed(fk), Fk(fk)))
                .collect();
            h.insert_many_with(&mut entries, collect.clone()).unwrap();
            h.flush().unwrap();
            h.insert_many_with(&mut [(mixed(261), Fk(261))], collect)
                .unwrap();
            h.flush().unwrap();
            assert_eq!(h.first_fks_snapshot(), vec![1, 195]);
            assert_eq!(h.last_inserted_fk(), 261);
        }
        let h = SegmentedTxHead::open(&dir).unwrap();
        for fk in (1..=261u64).filter(|fk| !orphan(*fk)) {
            assert!(
                h.probe_candidates(&mixed(fk)).unwrap().contains(&Fk(fk)),
                "fk={fk} lost after reopen"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A gap longer than a whole segment: the empty segments inside it must
    /// roll (not spin), and entries on both sides stay findable after reopen.
    #[test]
    fn fk_gap_longer_than_a_segment_rolls_empty_spans() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let collect: SealCollect = std::sync::Arc::new(|first_fk, count| {
            Ok((0..count)
                .map(|i| (fuse_key_from_mixed(&mixed(first_fk + i)), (i as u32) + 1))
                .collect())
        });
        // max_keys = 204; orphans 150..=700 cover more than two full spans.
        let orphan = |fk: u64| (150..=700).contains(&fk);
        let live: Vec<u64> = (1..=760u64).filter(|fk| !orphan(*fk)).collect();
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let mut entries: Vec<_> = live.iter().map(|&fk| (mixed(fk), Fk(fk))).collect();
            h.insert_many_with(&mut entries, collect.clone()).unwrap();
            h.flush().unwrap();
            h.insert_many_with(&mut [(mixed(761), Fk(761))], collect)
                .unwrap();
            h.flush().unwrap();
            assert_eq!(h.last_inserted_fk(), 761);
        }
        let h = SegmentedTxHead::open(&dir).unwrap();
        for fk in live.iter().copied().chain([761]) {
            assert!(
                h.probe_candidates(&mixed(fk)).unwrap().contains(&Fk(fk)),
                "fk={fk} lost"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A later fk behind the open segment's `first_fk` is refused. Callers
    /// pass non-decreasing absolute fks; this path does not reorder them.
    #[test]
    fn fk_behind_open_segment_is_corrupt() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        let collect: SealCollect = std::sync::Arc::new(|first_fk, count| {
            Ok((0..count)
                .map(|i| (fuse_key_from_mixed(&mixed(first_fk + i)), (i as u32) + 1))
                .collect())
        });
        // 300 opens the segment; 5 is behind that first_fk. max_keys = 204.
        let mut entries = [(mixed(300), Fk(300)), (mixed(5), Fk(5))];
        let err = h.insert_many_with(&mut entries, collect).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(m) if m == "tx.head insert fk before segment"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_collect_runs_on_sidecar_not_insert_thread() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        let caller = std::thread::current().id();
        let collect_tid = std::sync::Arc::new(std::sync::Mutex::new(None));
        let tid = collect_tid.clone();
        let collect: SealCollect = std::sync::Arc::new(move |first_fk, count| {
            *tid.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::thread::current().id());
            Ok((0..count)
                .map(|i| {
                    let fk = first_fk + i;
                    (fuse_key_from_mixed(&mixed(fk)), (i as u32) + 1)
                })
                .collect())
        });
        let mut entries: Vec<_> = (0..205u64).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
        h.insert_many_with(&mut entries, collect).unwrap();
        h.flush().unwrap();
        let got = collect_tid
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .expect("collect ran on sidecar");
        assert_ne!(got, caller, "collect must run on the seal sidecar");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn insert_roll_seal_lookup_roundtrip() {
        let dir = tmp();
        // 10-bit head: 1024 slots, max_keys = floor(0.8*1024)=819
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        assert_eq!(h.max_keys, 819);

        let n = 820u64; // forces a roll (max_keys=819)
        let mut entries = Vec::with_capacity(n as usize);
        for i in 0..n {
            entries.push((mixed(i + 1), Fk(i + 1)));
        }
        h.insert_many(&mut entries).unwrap();
        assert!(h.segment_count() >= 2, "segs={}", h.segment_count());
        h.flush().unwrap();
        assert!(h.sealed_segment_count() >= 1);
        assert_eq!(
            h.sealed_fuse_resident_bytes(),
            0,
            "seal publish must map fuse, not keep the build Box"
        );

        // Known members resolve (as candidates).
        for i in [1u64, 400, 819, 820] {
            let cands = h.probe_candidates(&mixed(i)).unwrap();
            assert!(
                cands.iter().any(|f| f.0 == i),
                "missing fk={i} cands={cands:?}"
            );
        }
        // Global miss.
        let miss = h.probe_candidates(&mixed(0xDEAD_BEEF)).unwrap();
        assert!(miss.is_empty() || !miss.iter().any(|f| f.0 == 0xDEAD_BEEF));

        h.flush().unwrap();
        drop(h);
        let h2 = SegmentedTxHead::open(&dir).unwrap();
        for i in [1u64, 500, 820] {
            let cands = h2.probe_candidates(&mixed(i)).unwrap();
            assert!(cands.iter().any(|f| f.0 == i), "reopen missing {i}");
        }
        // Sealed fuse never FN on members of first segment.
        let cands = h2.probe_candidates(&mixed(1)).unwrap();
        assert!(cands.iter().any(|f| f.0 == 1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_mphf_one_candidate_bip30_unlinks_oa() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        let n = 820u64;
        let mut entries: Vec<_> = (0..n).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
        h.insert_many(&mut entries).unwrap();
        h.flush().unwrap();
        assert!(h.sealed_segment_count() >= 1);
        let sealed = dir.join("tx.head").join("000000");
        assert!(!sealed.is_file(), "sealed OA file must be unlinked");
        assert!(crate::tx_head_mphf::TxHeadMphf::exists(&sealed));
        assert!(!crate::tx_head_mphf::rel_path(&sealed).is_file());
        assert_eq!(
            &std::fs::read(crate::tx_head_mphf::mphf_path(&sealed)).unwrap()[0..4],
            b"BDZ2"
        );
        assert!(dir.join("tx.head").join("000000.fuse8").is_file());
        let cands = h.probe_candidates(&mixed(1)).unwrap();
        assert_eq!(cands.len(), 1, "cands={cands:?}");
        assert_eq!(cands[0], Fk(1));
        let mut fuse_skip = false;
        for i in 0..32u64 {
            let _ = h.take_sealed_g_page_preads();
            let miss = h.probe_candidates(&mixed(0xDEAD_BEEF + i)).unwrap();
            let g_pages = h.take_sealed_g_page_preads();
            if miss.is_empty() && g_pages == 0 {
                fuse_skip = true;
                break;
            }
        }
        assert!(fuse_skip, "fuse miss must not pread g pages");

        let k = mixed(0xB1B0);
        let collect: SealCollect = Arc::new(move |first_fk, count| {
            Ok((0..count)
                .map(|i| {
                    let fk = first_fk + i;
                    let m = if fk == 821 { k } else { mixed(fk) };
                    (fuse_key_from_mixed(&m), (i as u32) + 1)
                })
                .collect())
        });
        h.insert_many_with(&mut [(k, Fk(821))], collect.clone())
            .unwrap();
        let mut fill: Vec<_> = (822..1639).map(|i| (mixed(i), Fk(i))).collect();
        h.insert_many_with(&mut fill, collect.clone()).unwrap();
        h.insert_many_with(&mut [(k, Fk(1639))], collect).unwrap();
        let cands = h.probe_candidates(&k).unwrap();
        assert_eq!(
            cands.first().copied(),
            Some(Fk(1639)),
            "newest first {cands:?}"
        );
        assert!(cands.iter().any(|f| f.0 == 821), "cands={cands:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Seal publish must persist sealed meta **before** unlinking the open OA.
    /// A meta-persist failure mid-publish (crash model) must leave the OA on
    /// disk so reopen serves the segment unsealed instead of forcing a full
    /// head rebuild.
    #[test]
    fn seal_publish_keeps_oa_when_meta_persist_fails() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let n = 820u64; // max_keys=819 → roll + background seal of file 000000
            let mut entries: Vec<_> = (0..n).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
            h.insert_many(&mut entries).unwrap();
            // Block `meta.tmp` so persist_meta fails inside the publish.
            let block = dir.join("tx.head").join("meta.tmp");
            std::fs::create_dir(&block).unwrap();
            let err = h
                .flush()
                .expect_err("meta persist must fail during publish");
            let _ = err;
            std::fs::remove_dir(&block).unwrap();
        }
        let oa = dir.join("tx.head").join("000000");
        assert!(
            oa.is_file(),
            "OA must not be unlinked before sealed meta is durable"
        );
        let h2 = SegmentedTxHead::open(&dir).expect("reopen without rebuild");
        let cands = h2.probe_candidates(&mixed(1)).unwrap();
        assert!(cands.iter().any(|f| f.0 == 1), "cands={cands:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash between sealed-meta persist and OA unlink leaves a leftover open
    /// OA next to the sealed `.mphf`. Open must discard it (sealed segments
    /// never read the base file).
    #[test]
    fn open_discards_leftover_oa_for_sealed_segment() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let n = 820u64;
            let mut entries: Vec<_> = (0..n).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
            h.insert_many(&mut entries).unwrap();
            h.flush().unwrap();
            assert!(h.sealed_segment_count() >= 1);
        }
        let oa = dir.join("tx.head").join("000000");
        let mphf = dir.join("tx.head").join("000000.mphf");
        assert!(!oa.is_file());
        assert!(mphf.is_file());
        let mphf_before = std::fs::read(&mphf).unwrap();
        std::fs::write(&oa, b"leftover pre-unlink OA").unwrap();
        let h2 = SegmentedTxHead::open(&dir).unwrap();
        assert!(
            !oa.is_file(),
            "leftover sealed-segment OA must be discarded on open"
        );
        assert_eq!(
            std::fs::read(&mphf).unwrap(),
            mphf_before,
            "mphf must be unchanged when discarding leftover OA"
        );
        let cands = h2.probe_candidates(&mixed(1)).unwrap();
        assert!(cands.iter().any(|f| f.0 == 1), "cands={cands:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One seal pad, then a v1 fuse file written the way seal names `.fuse8`.
    #[test]
    fn v1_fuse_and_mono_head_refuse_open() {
        let dir = tmp();
        let layout = HeadLayout::with_entry_bytes(10, 4).unwrap();
        // 0.8 * 1024 = 819 → seal at 820.
        let n = 820u64;
        {
            let h = SegmentedTxHead::create(&dir, layout).unwrap();
            let mut entries: Vec<_> = (0..n).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
            h.insert_many(&mut entries).unwrap();
            h.flush().unwrap();
            assert!(h.sealed_segment_count() >= 1);
            let fuse_path = dir.join("tx.head").join("000000.fuse8");
            assert!(
                fuse_path.is_file(),
                "seal writes 000000.fuse8, got {}",
                fuse_path.display()
            );
        }

        // Same pad: leftover v1 fuse refuses open.
        let fuse_path = dir.join("tx.head").join("000000.fuse8");
        let mut raw = Vec::from(*b"BF8R");
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&fuse_path, &raw).unwrap();
        match SegmentedTxHead::open(&dir) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, crate::fuse8_filter::INDEX_REFUSE_FUSE8_V1);
            }
            Ok(_) => panic!("v1 fuse must refuse SegmentedTxHead::open"),
            Err(other) => panic!("expected INDEX_REFUSE_FUSE8_V1, got {other}"),
        }

        // Same suite budget: count-only roll + mono refuse without extra full pads.
        let dir_roll = tmp();
        let layout_roll = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let h_roll = SegmentedTxHead::create(&dir_roll, layout_roll).unwrap();
        let mut fill: Vec<_> = (0..254u64).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
        h_roll.insert_many(&mut fill).unwrap();
        assert!(h_roll.segment_count() >= 2);
        h_roll.flush().unwrap();
        assert!(h_roll.sealed_segment_count() >= 1);
        assert!(h_roll
            .probe_candidates(&mixed(50))
            .unwrap()
            .iter()
            .any(|f| f.0 == 50));
        assert!(h_roll
            .probe_candidates(&mixed(220))
            .unwrap()
            .iter()
            .any(|f| f.0 == 220));

        let dir_mono = tmp();
        std::fs::write(dir_mono.join("tx.head"), b"legacy").unwrap();
        let layout_mono = HeadLayout::with_entry_bytes(10, 4).unwrap();
        let err = SegmentedTxHead::create(&dir_mono, layout_mono)
            .err()
            .expect("must refuse mono head");
        let s = format!("{err}");
        assert!(s.contains("legacy") || s.contains("reindex"), "{s}");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir_roll);
        let _ = std::fs::remove_dir_all(&dir_mono);
    }

    /// Roll opens the next OA and returns without joining BDZ/fuse. The sealing
    /// OA stays in the Open wave until [`SegmentedTxHead::flush`].
    #[test]
    fn roll_does_not_join_seal_open_probes_sealing_oa() {
        let dir = tmp();
        // 8-bit: 256 slots, max_keys = floor(0.8*256)=204.
        let layout = HeadLayout::with_entry_bytes(8, 4).unwrap();
        let h = SegmentedTxHead::create(&dir, layout).unwrap();
        let n = 205u64;
        let mut entries: Vec<_> = (0..n).map(|i| (mixed(i + 1), Fk(i + 1))).collect();
        h.insert_many(&mut entries).unwrap();
        assert!(h.segment_count() >= 2, "segs={}", h.segment_count());
        assert_eq!(
            h.sealed_segment_count(),
            0,
            "insert_many must not join/publish the sidecar seal"
        );
        let unsealed = h.unsealed_ranges();
        assert!(
            unsealed.len() >= 2,
            "tail + in-flight seal, unsealed={unsealed:?}"
        );
        let oa = dir.join("tx.head").join("000000");
        assert!(oa.is_file(), "sealing OA stays on disk until publish");
        let open = h
            .probe_candidates_batch_wave(
                &[mixed(1)],
                HeadProbeWave::Open,
                None,
                &mut crate::IoCtx::none(),
            )
            .unwrap();
        assert!(
            open[0].iter().any(|f| f.0 == 1),
            "Open wave must probe the sealing OA, cands={:?}",
            open[0]
        );
        assert!(h
            .probe_candidates(&mixed(1))
            .unwrap()
            .iter()
            .any(|f| f.0 == 1));
        assert!(h
            .probe_candidates(&mixed(205))
            .unwrap()
            .iter()
            .any(|f| f.0 == 205));

        h.flush().unwrap();
        assert!(h.sealed_segment_count() >= 1);
        assert!(!oa.is_file(), "flush publishes and unlinks the OA");
        assert!(crate::tx_head_mphf::TxHeadMphf::exists(&oa));
        let open_after = h
            .probe_candidates_batch_wave(
                &[mixed(1)],
                HeadProbeWave::Open,
                None,
                &mut crate::IoCtx::none(),
            )
            .unwrap();
        assert!(
            !open_after[0].iter().any(|f| f.0 == 1),
            "sealed segment leaves the Open wave, cands={:?}",
            open_after[0]
        );
        assert!(h
            .probe_candidates(&mixed(1))
            .unwrap()
            .iter()
            .any(|f| f.0 == 1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
