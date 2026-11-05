//! Keyless addressable `tx.head`: `2^BITS` slots × 4 B create_fk entries.
//!
//! **Layout:** each file entry is LE create_fk (`0` = empty). No key material and
//! **no HAS_NEXT** — probe continues until an empty slot (no Class A deletes).
//! Callers verify identity via Class A body txid on **lookup**. The spare high
//! bits of each slot hold a fingerprint of the mixed key, so a probe skips most
//! foreign occupants before identity. Probes read the slots through a read-only
//! `MAP_SHARED` map (`AddressHead::slots`); the page cache keeps it coherent
//! with the sole writer's `pwrite`s.
//!
//! **Insert (sole writer):** probe until the **same fk** is already present
//! (idempotent) or an **empty** slot — `pwrite` the slot (`0 → fk`; no CAS, no
//! per-slot atomics). **No body_txid** on insert (no BIP30 displacement on write).
//! Foreigners and older same-txid creates are skipped blindly; a second Class A
//! row for the same txid lands at the next empty slot (deeper on the probe chain).
//!
//! **Insert batching:** stable-sort by probe **page** then original index
//! (preserves call order within a page for rare same-batch duplicate txids). One
//! page copy from the map + multi-insert + one `pwrite` per dirty page. Readers
//! see the new slots through the map once the `pwrite` lands.
//!
//! **Concurrency:** at most **one** thread may insert into a given head segment
//! (archive writer in IBD; single tip accept path after). Multi-writer races are
//! not supported. Capacity growth is **segment roll** (seal + new open), not bits-widen.
//!
//! **Lookup:** walk candidates from the **last occupied** probe slot toward the
//! first, body-verify — so the deepest same-txid create wins (newest under
//! append-deeper insert).
//!
//! **Probe (page-local open address):** high bits of the txid select a **page** of
//! [`PAGE_SLOTS`] (2¹⁰) slots; within the page, **double hashing** with the next
//! key bits (`h1` / odd `h2`). Depth is capped at [`MAX_PROBE`] (= page size).
//! Lookup and insert hop the mapped slots; insert then writes **one page** (4 KiB)
//! per dirty page. Foreign occupants with the same fingerprint (or none yet):
//! body mismatch ⇒ continue. Keyless slots cannot Robin-Hood. First insert at depth > [`PROBE_DEPTH_WARN`] requests online
//!
//! **Segment default:** BITS=**25** → **128 MiB** @ 4 B relative create ids per
//! segment (`2^15` pages × 4 KiB). Capacity ends at [`HEAD_LOAD_START`] (0.80);
//! the segmented head seals (fuse8) and opens a new fixed-bits table — no
//! global bits-widen.

use crate::error::StoreError;
use crate::file::{TableFile, TRAILING_FOOTER_LEN};
use crate::hashhead::HeadScale;
use crate::readonly_map::ReadonlyMap;
use rbitcoin_primitives::{Fk, TableKind};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// In-page slot index width (1024 slots / page @ any entry width).
pub const PAGE_SLOT_BITS: u32 = 10;
/// Slots per page (`2^PAGE_SLOT_BITS`).
pub const PAGE_SLOTS: u64 = 1 << PAGE_SLOT_BITS;

/// Hard cap — full in-page exploration (never leave the page).
pub const MAX_PROBE: u32 = 1024;
/// Occupied `(depth, fk)` stored inline in [`ProbeCands`] before a spill `Vec`.
pub const PROBE_CANDS_INLINE: usize = 8;

/// Bytes of one slot in the file (`rel` as LE u32).
pub const ENTRY_BYTES: u64 = 4;
/// Bytes of one head page (1024 × 4 B).
pub const PROBE_REGION_BYTES: usize = (PAGE_SLOTS as usize) * (ENTRY_BYTES as usize);

/// Inserts that needed probe depth **> [`PROBE_DEPTH_WARN`]** (warning band).
/// Cumulative counter for lagging/retry logs; WARN only once at first event.
#[doc(hidden)]
pub static PROBE_INSERT_DEPTH_WARN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Inserts that exhausted [`MAX_PROBE`] (archiver sleeps until resize completes).
/// Counter only — the retry loop owns operator-facing logs.
#[doc(hidden)]
pub static PROBE_INSERT_EXHAUSTED: AtomicU64 = AtomicU64::new(0);

/// Depth threshold above which inserts count as “deep” for ops visibility and
/// trigger an early online resize request (first event only).
pub const PROBE_DEPTH_WARN: u32 = 128;

/// Segment address width (2^25 slots × 4 B = 128 MiB). Fixed per segment; roll to grow.
pub const MAINNET_BITS: u32 = 25;
/// Tiny / unit-test width.
pub const TINY_BITS: u32 = 16;
/// Maximum supported address width: `rel` must fit a 4 B slot.
pub const MAX_BITS: u32 = 32;
/// Minimum supported address width.
pub const MIN_BITS: u32 = 8;

/// Start sequential rebuild when `txs.count() / slots >=` this.
pub const HEAD_LOAD_START: f64 = 0.80;

/// True when `err` is the sole-writer open-address insert failure (table full
/// along the probe chain — should not happen when segment roll respects 80% load).
#[inline]
pub fn is_probe_exhausted_error(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::Corrupt(m) if *m == "address head probe exhausted on insert"
    )
}

/// `NetError::Consensus` display of store `Corrupt` (not a block rule).
pub fn is_store_corrupt_display(s: &str) -> bool {
    const PROBE: &str = "address head probe exhausted on insert";
    let probe = StoreError::Corrupt(PROBE);
    if s == probe.to_string() {
        return is_probe_exhausted_error(&probe);
    }
    s.starts_with("corrupt record:")
}

#[inline]
#[doc(hidden)]
pub fn note_probe_depth_on_insert(depth: u32) {
    if depth <= PROBE_DEPTH_WARN {
        return;
    }
    let n = PROBE_INSERT_DEPTH_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 {
        rbitcoin_log::warn!(
            "store: tx.head insert probe depth>{PROBE_DEPTH_WARN} (first depth={depth}; \
             segment may be overfull — roll policy should prevent this)"
        );
    }
}

#[inline]
#[doc(hidden)]
pub fn note_probe_exhausted() {
    PROBE_INSERT_EXHAUSTED.fetch_add(1, Ordering::Relaxed);
}

#[doc(hidden)]
pub const META_MAGIC: &[u8; 4] = b"THM1";
/// `5` = page-local double-hash; layout (bits/entry/generation) lives in the
/// **trailing footer** next to store magic (no `tx.head.meta` sidecar). Slots at
/// offset 0 remain page-aligned. Older versions refused → open recreates + rebuilds.
#[doc(hidden)]
pub const META_VERSION: u16 = 5;

/// On-disk / in-memory address-head geometry (4 B slots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadLayout {
    pub bits: u32,
}

impl HeadLayout {
    pub fn new(bits: u32) -> Result<Self, StoreError> {
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(StoreError::Corrupt("address head bits out of range"));
        }
        Ok(Self { bits })
    }

    pub fn slots(&self) -> u64 {
        1u64 << self.bits
    }

    pub fn body_bytes(&self) -> u64 {
        self.slots() * ENTRY_BYTES
    }
}

/// Fingerprint of a mixed key for the spare high bits above `rel < 2^bits`:
/// `1..=mask` from bytes no page / h1 / h2 field uses. `0` means unknown (a
/// row written before tags) and matches every key. No spare bits at 32.
#[inline]
pub fn fingerprint(mixed: &[u8; 32], bits: u32) -> u32 {
    if bits >= 32 {
        return 0;
    }
    let mask = (1u32 << (32 - bits)) - 1;
    let w = u64::from_le_bytes(mixed[16..24].try_into().unwrap());
    (w % u64::from(mask)) as u32 + 1
}

/// Slot word `rel | fp << bits`, or `None` when `rel` does not fit in `bits`:
/// a wider rel would fold into the fingerprint and its own probe would skip it.
#[inline]
fn tag_entry(rel: u64, fp: u32, bits: u32) -> Option<u32> {
    if rel >> bits != 0 {
        return None;
    }
    Some((rel | (u64::from(fp) << bits)) as u32)
}

/// First 8 bytes of txid as big-endian u64 (bit stream for page / h1).
#[inline]
#[doc(hidden)]
pub fn key_be_u64(txid: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        txid[0], txid[1], txid[2], txid[3], txid[4], txid[5], txid[6], txid[7],
    ])
}

/// Page index from the **top** `(bits - 10)` bits of the txid (0 if bits ≤ 10).
#[inline]
pub fn page_index(txid: &[u8; 32], bits: u32) -> u64 {
    debug_assert!((MIN_BITS..=MAX_BITS).contains(&bits));
    if bits <= PAGE_SLOT_BITS {
        return 0;
    }
    let page_bits = bits - PAGE_SLOT_BITS;
    key_be_u64(txid) >> (64 - page_bits)
}

/// In-page h1: next 10 bits after the page-select field (mod 2^10).
#[inline]
pub fn h1_in_page(txid: &[u8; 32], bits: u32) -> u64 {
    let v = key_be_u64(txid);
    if bits <= PAGE_SLOT_BITS {
        return (v >> (64 - bits)) & ((1u64 << bits) - 1);
    }
    let page_bits = bits - PAGE_SLOT_BITS;
    (v >> (64 - page_bits - PAGE_SLOT_BITS)) & (PAGE_SLOTS - 1)
}

/// In-page odd step from a second window of the txid (1,3,… within the page).
#[inline]
pub fn h2_in_page(txid: &[u8; 32], bits: u32) -> u64 {
    let v = u64::from_be_bytes([
        txid[4], txid[5], txid[6], txid[7], txid[8], txid[9], txid[10], txid[11],
    ]);
    let mask = if bits <= PAGE_SLOT_BITS {
        (1u64 << bits) - 1
    } else {
        PAGE_SLOTS - 1
    };
    (v | 1) & mask
}

/// Global slot at probe depth `d`: page from high bits, double-hash within page.
///
/// `slot = (page << 10) | ((h1 + d·h2) mod 1024)` when `bits > 10`.
#[inline]
pub fn probe_index(txid: &[u8; 32], d: u32, bits: u32) -> u64 {
    debug_assert!((MIN_BITS..=MAX_BITS).contains(&bits));
    let h1 = h1_in_page(txid, bits);
    let h2 = h2_in_page(txid, bits);
    if bits <= PAGE_SLOT_BITS {
        let mask = (1u64 << bits) - 1;
        return h1.wrapping_add(u64::from(d).wrapping_mul(h2)) & mask;
    }
    let page = page_index(txid, bits);
    let local = h1.wrapping_add(u64::from(d).wrapping_mul(h2)) & (PAGE_SLOTS - 1);
    (page << PAGE_SLOT_BITS) | local
}

/// Number of slots in the probe page for this table width.
#[inline]
pub fn page_slot_count(bits: u32) -> u64 {
    if bits <= PAGE_SLOT_BITS {
        1u64 << bits
    } else {
        PAGE_SLOTS
    }
}

/// Slot file offset: data starts at **0** (trailing magic); page-aligned probes.
#[inline]
pub fn entry_file_off(slot: u64) -> u64 {
    slot * ENTRY_BYTES
}

/// Decode one LE create_fk from a page buffer at local slot index.
#[inline]
pub fn entry_from_page_buf(buf: &[u8], local: u64) -> Option<u64> {
    let off = (local as usize).checked_mul(ENTRY_BYTES as usize)?;
    let bytes = buf.get(off..off + ENTRY_BYTES as usize)?;
    Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)))
}

/// One key's hop plus its page's occupancy (leftover-miss dump).
pub struct PageHopDump {
    pub scan: ProbeRegionScan,
    pub occupied: u32,
}

/// Occupied `(depth, encoded_fk)` from one hop. Inline for the common 1–2
/// cand path; heap only past [`PROBE_CANDS_INLINE`].
#[derive(Debug, Clone)]
pub struct ProbeCands {
    pub inline: [(u32, u64); PROBE_CANDS_INLINE],
    pub n: u8,
    pub spill: Vec<(u32, u64)>,
}

impl Default for ProbeCands {
    fn default() -> Self {
        Self {
            inline: [(0, 0); PROBE_CANDS_INLINE],
            n: 0,
            spill: Vec::new(),
        }
    }
}

impl ProbeCands {
    #[inline]
    pub fn len(&self) -> usize {
        (self.n as usize).saturating_add(self.spill.len())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn push(&mut self, depth: u32, fk: u64) {
        let i = self.n as usize;
        if i < PROBE_CANDS_INLINE {
            self.inline[i] = (depth, fk);
            self.n = (i + 1) as u8;
            return;
        }
        self.spill.push((depth, fk));
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &(u32, u64)> {
        self.inline[..self.n as usize]
            .iter()
            .chain(self.spill.iter())
    }
}

impl PartialEq for ProbeCands {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

/// Result of hopping through one loaded page.
#[derive(Debug, Clone)]
pub struct ProbeRegionScan {
    /// Occupied create_fks with absolute probe depth (home = 0).
    pub cands: ProbeCands,
    /// Saw an empty slot (probe chain ends).
    pub hit_empty: bool,
    /// Depth of empty slot if [`Self::hit_empty`], else depths explored without empty.
    pub depth_end: u32,
    /// Local slot index of empty (valid if hit_empty).
    pub empty_local: u64,
}

/// Double-hash hop through a loaded page buffer.
pub fn hop_scan_page(
    page_buf: &[u8],
    h1: u64,
    h2: u64,
    page_slots: u64,
    max_probe: u32,
) -> ProbeRegionScan {
    let mask = page_slots - 1;
    let max_d = max_probe.min(page_slots as u32);
    let mut cands = ProbeCands::default();
    for d in 0..max_d {
        let local = h1.wrapping_add(u64::from(d).wrapping_mul(h2)) & mask;
        let Some(e) = entry_from_page_buf(page_buf, local) else {
            break;
        };
        if e == 0 {
            return ProbeRegionScan {
                cands,
                hit_empty: true,
                depth_end: d,
                empty_local: local,
            };
        }
        cands.push(d, e);
    }
    ProbeRegionScan {
        cands,
        hit_empty: false,
        depth_end: max_d,
        empty_local: 0,
    }
}

/// Global first slot of the probe page that holds `txid`.
#[inline]
pub fn page_base_for_txid(txid: &[u8; 32], bits: u32) -> u64 {
    if bits <= PAGE_SLOT_BITS {
        0
    } else {
        page_index(txid, bits) << PAGE_SLOT_BITS
    }
}

/// Outcome of [`insert_fk_into_page_buf`] (in-buffer only; no file IO).
#[derive(Debug, Clone, Copy)]
pub struct InsertPageOutcome {
    /// Wrote a new empty→fk slot (false if `new_fk` already on the chain).
    pub wrote_new: bool,
    /// Probe depth of the empty slot written (or 0 if idempotent).
    pub depth: u32,
}

/// Insert `new_fk` into a **loaded** probe page buffer; the new slot carries
/// the key's fingerprint.
///
/// Idempotent if `new_fk` is already present. Does not touch the file or
/// occupied count — caller applies the buffer via pwrite.
pub fn insert_fk_into_page_buf(
    page_buf: &mut [u8],
    bits: u32,
    txid: &[u8; 32],
    new_fk: Fk,
) -> Result<InsertPageOutcome, StoreError> {
    if new_fk.is_null() {
        return Err(StoreError::InvalidFk);
    }
    let new_u = new_fk.0;
    let Some(tagged) = tag_entry(new_u, fingerprint(txid, bits), bits) else {
        return Err(StoreError::InvalidFk);
    };
    let rel_mask = (1u64 << bits) - 1;
    let nslots = (page_buf.len() / ENTRY_BYTES as usize) as u64;
    let h1 = h1_in_page(txid, bits);
    let h2 = h2_in_page(txid, bits);
    let scan = hop_scan_page(page_buf, h1, h2, nslots, MAX_PROBE);
    for &(_d, e) in scan.cands.iter() {
        if e & rel_mask == new_u {
            return Ok(InsertPageOutcome {
                wrote_new: false,
                depth: 0,
            });
        }
    }
    if !scan.hit_empty {
        note_probe_exhausted();
        return Err(StoreError::Corrupt(
            "address head probe exhausted on insert",
        ));
    }
    store_entry_in_page_buf(page_buf, scan.empty_local, tagged)?;
    Ok(InsertPageOutcome {
        wrote_new: true,
        depth: scan.depth_end,
    })
}

/// Write LE create_fk into a page buffer at local slot index.
#[inline]
#[doc(hidden)]
pub fn store_entry_in_page_buf(
    page_buf: &mut [u8],
    local: u64,
    new: u32,
) -> Result<(), StoreError> {
    let es = ENTRY_BYTES as usize;
    let off = (local as usize)
        .checked_mul(es)
        .ok_or(StoreError::Corrupt("page buf slot overflow"))?;
    let slot = page_buf
        .get_mut(off..off + es)
        .ok_or(StoreError::Corrupt("page buf slot out of range"))?;
    slot.copy_from_slice(&new.to_le_bytes());
    Ok(())
}

thread_local! {
    static TEST_TX_HEAD_BITS: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Run `f` with a per-thread `RBITCOIN_TX_HEAD_BITS` value. Other threads keep
/// the process env. The node still reads that variable when this is unset.
pub fn with_tx_head_bits<R>(raw: &str, f: impl FnOnce() -> R) -> R {
    TEST_TX_HEAD_BITS.with(|c| {
        let prev = c.replace(Some(raw.to_owned()));
        let _restore = BitsRestore(c, prev);
        f()
    })
}

struct BitsRestore<'a>(&'a RefCell<Option<String>>, Option<String>);

impl Drop for BitsRestore<'_> {
    fn drop(&mut self) {
        *self.0.borrow_mut() = self.1.take();
    }
}

/// Resolve address width for new creates.
///
/// A thread override wins. Otherwise `RBITCOIN_TX_HEAD_BITS` when it parses
/// inside [`MIN_BITS`]..=[`MAX_BITS`]. Anything else uses the scale default.
pub fn bits_for_scale(scale: HeadScale) -> u32 {
    let from_thread = TEST_TX_HEAD_BITS.with(|c| c.borrow().clone());
    let from_env = if from_thread.is_some() {
        None
    } else {
        std::env::var("RBITCOIN_TX_HEAD_BITS").ok()
    };
    if let Some(s) = from_thread.as_deref().or(from_env.as_deref()) {
        if let Ok(n) = s.parse::<u32>() {
            if (MIN_BITS..=MAX_BITS).contains(&n) {
                return n;
            }
            rbitcoin_log::warn!(
                "store: RBITCOIN_TX_HEAD_BITS={s:?} out of {MIN_BITS}..={MAX_BITS}, using scale default"
            );
        }
    }
    match scale {
        HeadScale::Tiny => TINY_BITS,
        HeadScale::Mainnet => MAINNET_BITS,
    }
}

pub fn default_layout(scale: HeadScale) -> HeadLayout {
    HeadLayout::new(bits_for_scale(scale)).expect("default bits in range")
}

/// Legacy sidecar path (`tx.head.meta`) — only for best-effort cleanup of old datadirs.
#[doc(hidden)]
pub fn meta_path(head_path: &Path) -> PathBuf {
    let mut p = head_path.as_os_str().to_os_string();
    p.push(".meta");
    PathBuf::from(p)
}

/// Drop leftover sidecar meta from pre-v5 layouts (layout is now in the footer).
pub fn remove_legacy_meta_sidecar(head_path: &Path) {
    let _ = std::fs::remove_file(meta_path(head_path));
}

/// Pack layout + generation into the 16-byte trailing-footer extension.
#[inline]
pub fn encode_layout_ext(layout: HeadLayout, generation: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(META_MAGIC);
    buf[4..6].copy_from_slice(&META_VERSION.to_le_bytes());
    buf[6] = layout.bits as u8;
    buf[7] = ENTRY_BYTES as u8;
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    buf
}

/// Decode layout extension from the trailing footer (or fail for rebuild).
pub fn decode_layout_ext(ext: &[u8; 16]) -> Result<(HeadLayout, u64), StoreError> {
    if &ext[0..4] != META_MAGIC {
        return Err(StoreError::Corrupt(
            "tx.head footer layout magic (rebuild tx.head)",
        ));
    }
    let ver = u16::from_le_bytes([ext[4], ext[5]]);
    if ver != META_VERSION {
        return Err(StoreError::Corrupt(
            "tx.head footer layout version (footer-embedded meta; rebuild tx.head)",
        ));
    }
    if u64::from(ext[7]) != ENTRY_BYTES {
        return Err(StoreError::Corrupt(
            "tx.head footer entry width (rebuild tx.head)",
        ));
    }
    let bits = u32::from(ext[6]);
    let generation = u64::from_le_bytes(ext[8..16].try_into().unwrap());
    Ok((HeadLayout::new(bits)?, generation))
}

/// Fixed-width keyless txid → dense create_fk table.
pub struct AddressHead {
    pub file: TableFile,
    pub layout: HeadLayout,
    /// Read-only `MAP_SHARED` view of the slot array. Probes and inserts hop
    /// it; the sole writer `pwrite`s pages through `file` and the page cache
    /// keeps the view coherent. A slot is `rel | fp << bits`.
    map: ReadonlyMap,
}

impl AddressHead {
    pub fn create_with_layout(
        path: impl Into<PathBuf>,
        layout: HeadLayout,
    ) -> Result<Self, StoreError> {
        // Trailing footer: slots at offset 0 so each 4 KiB probe page is OS-aligned.
        // Layout (bits/entry/generation) lives in the footer extension — no sidecar.
        let path = path.into();
        if path.is_dir() {
            return Err(StoreError::Corrupt(
                "tx.head is a directory (legacy shards); wipe datadir for address head",
            ));
        }
        let mut file = TableFile::create_trailing_header(&path, TableKind::HashHead)?;
        let body_bytes = layout.body_bytes();
        let need = body_bytes + TRAILING_FOOTER_LEN as u64;
        file.ensure_capacity(need)?;
        // Layout ext must be set before set_logical_len so the footer at EOF
        // carries bits/generation (no sidecar).
        file.set_trailing_ext(encode_layout_ext(layout, 0))?;
        file.set_logical_len(need)?;
        file.zero_range(0, body_bytes)?;
        remove_legacy_meta_sidecar(&path);
        Self::with_map(file, layout, &path)
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if path.is_dir() {
            return Err(StoreError::Corrupt(
                "tx.head is a directory (legacy shards); wipe datadir for address head",
            ));
        }
        // Layout is in the trailing footer (v5). Sidecar-only or older footers fail
        // here → TxTable recreates + rebuilds from Class A.
        let (file, ext) = TableFile::open_trailing_header_from_end(&path, TableKind::HashHead)?;
        let (layout, _generation) = decode_layout_ext(&ext)?;
        let expect_body = layout.body_bytes();
        let body = file.data_len();
        if body == 0 {
            return Err(StoreError::Corrupt("address head size"));
        }
        if body != expect_body {
            return Err(StoreError::Corrupt(
                "address head size mismatch vs footer layout",
            ));
        }
        remove_legacy_meta_sidecar(&path);
        Self::with_map(file, layout, &path)
    }

    fn with_map(file: TableFile, layout: HeadLayout, path: &Path) -> Result<Self, StoreError> {
        let map = ReadonlyMap::map_prefix(path, layout.body_bytes() as usize)?;
        Ok(Self { file, layout, map })
    }

    /// The mapped slot array. The bytes are not frozen: the sole writer
    /// publishes slots by `pwrite` through `file`, and the page cache changes
    /// them under this view. So every read is an atomic load, and no `&[u8]`
    /// of the map is ever formed (`as_file_bytes` is for sealed files).
    #[inline]
    fn slots(&self) -> &[AtomicU32] {
        // SAFETY: a page-aligned live `MAP_SHARED` mapping of `body_bytes()`
        // bytes (a multiple of 4), held for `self`'s lifetime. Nothing in this
        // process writes through the mapping; concurrent file writes are
        // observed only by atomic loads, never by a plain reference.
        unsafe {
            std::slice::from_raw_parts(
                self.map.as_ptr() as *const AtomicU32,
                self.map.map_len() / 4,
            )
        }
    }

    pub fn bits(&self) -> u32 {
        self.layout.bits
    }

    /// Bytes of the mapped slot array (file-backed, reclaimable; not heap).
    pub fn map_bytes(&self) -> u64 {
        self.map.map_len() as u64
    }

    /// Global slot at probe depth `d` of `mixed`.
    #[inline]
    #[doc(hidden)]
    pub fn slot_at(&self, mixed: &[u8; 32], d: u32) -> usize {
        probe_index(mixed, d, self.layout.bits) as usize
    }

    /// Hop one key's chain through the map. `fp != 0` drops slots whose known
    /// fingerprint differs; `fp == 0` keeps every occupied slot. Cands carry
    /// the plain `rel`.
    fn hop(&self, mixed: &[u8; 32], fp: u32) -> ProbeRegionScan {
        let bits = self.layout.bits;
        let page_slots = page_slot_count(bits);
        let mask = page_slots - 1;
        let base = page_base_for_txid(mixed, bits) as usize;
        let h1 = h1_in_page(mixed, bits);
        let h2 = h2_in_page(mixed, bits);
        let max_d = MAX_PROBE.min(page_slots as u32);
        let rel_mask = (1u64 << bits) - 1;
        let mut cands = ProbeCands::default();
        for d in 0..max_d {
            let local = h1.wrapping_add(u64::from(d).wrapping_mul(h2)) & mask;
            let e = u64::from(self.slots()[base + local as usize].load(Ordering::Acquire));
            if e == 0 {
                return ProbeRegionScan {
                    cands,
                    hit_empty: true,
                    depth_end: d,
                    empty_local: local,
                };
            }
            let efp = (e >> bits) as u32;
            if fp != 0 && efp != 0 && efp != fp {
                continue;
            }
            cands.push(d, e & rel_mask);
        }
        ProbeRegionScan {
            cands,
            hit_empty: false,
            depth_end: max_d,
            empty_local: 0,
        }
    }

    /// Candidates per mixed key through the map, in probe order (callers
    /// reverse for deepest-first). No syscall.
    #[doc(hidden)]
    pub fn probe_fks_batch(&self, mixed: &[[u8; 32]]) -> Vec<Vec<Fk>> {
        let bits = self.layout.bits;
        mixed
            .iter()
            .map(|m| {
                let scan = self.hop(m, fingerprint(m, bits));
                scan.cands.iter().map(|&(_, rel)| Fk(rel)).collect()
            })
            .collect()
    }

    /// Write the fingerprint of rows that predate tags: `(mixed, rel)` whose
    /// rel sits on the key's chain. One 4-byte `pwrite` per row; a rel not on
    /// its chain is left alone. Callers running in parallel must pass
    /// disjoint rels.
    #[doc(hidden)]
    pub fn fill_fingerprints(&self, keys: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        let bits = self.layout.bits;
        for (mixed, rel) in keys {
            let scan = self.hop(mixed, 0);
            let depth = scan
                .cands
                .iter()
                .find(|&&(_, r)| r == rel.0)
                .map(|&(d, _)| d);
            if let Some(d) = depth {
                let v = tag_entry(rel.0, fingerprint(mixed, bits), bits)
                    .ok_or(StoreError::Corrupt("tx.head rel wider than bits"))?;
                let off = entry_file_off(self.slot_at(mixed, d) as u64);
                self.file.write_at(off, &v.to_le_bytes())?;
            }
        }
        Ok(())
    }

    /// Rewrite every occupied slot without its tag, as a meta v1 head wrote it.
    #[cfg(debug_assertions)]
    pub fn strip_tags_for_test(&self) -> Result<(), StoreError> {
        let rel_mask = (1u32 << self.layout.bits) - 1;
        for (i, s) in self.slots().iter().enumerate() {
            let raw = s.load(Ordering::Relaxed);
            if raw != 0 {
                self.file
                    .write_at(entry_file_off(i as u64), &(raw & rel_mask).to_le_bytes())?;
            }
        }
        Ok(())
    }

    /// Hop one key and count its page's occupied slots. Leftover-miss dump only.
    #[doc(hidden)]
    pub fn dump_page_hop(&self, mixed: &[u8; 32]) -> PageHopDump {
        let bits = self.layout.bits;
        let page_slots = page_slot_count(bits) as usize;
        let base = page_base_for_txid(mixed, bits) as usize;
        let occupied = self.slots()[base..base + page_slots]
            .iter()
            .filter(|s| s.load(Ordering::Relaxed) != 0)
            .count() as u32;
        PageHopDump {
            scan: self.hop(mixed, 0),
            occupied,
        }
    }

    /// Sort `entries` in place by probe page and insert. No extra pair copy.
    pub fn insert_many_in_place(&self, entries: &mut [([u8; 32], Fk)]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let bits = self.layout.bits;
        let page_slots = page_slot_count(bits) as usize;
        let n = page_slots * ENTRY_BYTES as usize;

        entries.sort_by_key(|a| page_base_for_txid(&a.0, bits));

        let mut buf = [0u8; PROBE_REGION_BYTES];
        let mut i = 0;
        while i < entries.len() {
            let page_base = page_base_for_txid(&entries[i].0, bits);
            let mut j = i + 1;
            while j < entries.len() && page_base_for_txid(&entries[j].0, bits) == page_base {
                j += 1;
            }

            // The page (tagged slots) comes from the map, not a pread.
            let slots = self.slots();
            for s in 0..page_slots {
                let e = slots[page_base as usize + s].load(Ordering::Relaxed);
                buf[s * 4..s * 4 + 4].copy_from_slice(&e.to_le_bytes());
            }

            let mut dirty = false;
            for &(ref txid, fk) in &entries[i..j] {
                let outcome = insert_fk_into_page_buf(&mut buf[..n], bits, txid, fk)?;
                if outcome.wrote_new {
                    note_probe_depth_on_insert(outcome.depth);
                    dirty = true;
                }
            }
            if dirty {
                self.file.write_at(entry_file_off(page_base), &buf[..n])?;
            }
            i = j;
        }

        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.file.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.file.flush_async()
    }
}
