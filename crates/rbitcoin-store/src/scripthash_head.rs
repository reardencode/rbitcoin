//! Open-addressed head for hybrid scripthash: key[16] → pack8 value (24 B slots).
//!
//! Key is the first 16 bytes of Electrum SHA256(spk). Public APIs take full 32 B
//! hashes and truncate. Values are [`ShHeadValue`] pack8 encodings.
//!
//! # Occupancy (startup)
//!
//! Slot occupancy is process state for load-factor / `is_empty`, **not** needed for
//! probe lookups. Mainnet shards are multi‑GiB — a full slot scan on every open is
//! unacceptable. Durable sidecar `{shard}.occ` holds the count (written on create,
//! reinit, cold install, and inserts). Large shards without a sidecar skip
//! the scan and mark occupancy **unknown** (never treated as empty, never bulk-fill).

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::hashhead::HeadScale;
use crate::scripthash_layout::{
    head_key_from_full, pack8_bytes, unpack8_bytes, ShHeadKey, ShHeadValue, SH_HEAD_KEY_LEN,
    SH_HEAD_SLOT_SIZE, SH_HEAD_VALUE_LEN,
};
use rbitcoin_primitives::TableKind;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::time::Instant;

use crate::open_address::{self, MAX_LOAD_DEN, MAX_LOAD_NUM};

/// Full occupancy scan only for tiny head files (tests / early IBD).
const OCC_SCAN_BYTE_CAP: u64 = 16 * 1024 * 1024;
const OCC_MAGIC: &[u8; 8] = b"SHOCC001";

const SLOTS_PER_CHUNK: u64 = 128;
const CHUNK_CACHE_MAX: usize = 256;

pub(crate) const SH_HEAD_FULL: &str = "invariant: scripthash head full";

/// Default unique-key hint for cold live OA pre-size (mainnet ~2e9).
///
/// Override with `RBITCOIN_SH_UNIQUE_HINT`. Tiny/test scale uses a small default
/// so unit tests do not allocate multi-GiB tables.
pub fn sh_unique_hint_default(scale: HeadScale) -> u64 {
    if let Ok(s) = std::env::var("RBITCOIN_SH_UNIQUE_HINT") {
        if let Ok(n) = s.parse::<u64>() {
            return n.max(1);
        }
    }
    scale.sh_unique_hint()
}

/// Per-shard key capacity from a global unique hint (25% skew margin).
#[inline]
pub fn sh_per_shard_key_budget(unique_hint: u64, n_shards: usize) -> u64 {
    let n = n_shards.max(1) as u64;
    unique_hint
        .max(1)
        .div_ceil(n)
        .saturating_mul(5)
        .div_ceil(4)
        .max(1)
}

/// Shard index from the **high bits** of `scripthash[0]` (power-of-two `n_shards`).
///
/// Unlike `key[0] % n`, this makes lexicographic order of full scripthashes
/// contiguous per shard: for 64 shards, bytes `0x00–0x03` → shard 0,
/// `0x04–0x07` → 1, … So sorted runs already stream one complete shard at a
/// time — cold materialize builds one live OA image per band.
///
/// `n_shards` must be 1 or a power of two ≤ 256 (mainnet SH uses **64**).
#[inline]
pub fn prefix_shard_of(full: &[u8; 32], n_shards: usize) -> usize {
    let n = n_shards.max(1);
    if n == 1 {
        return 0;
    }
    debug_assert!(
        n.is_power_of_two() && n <= 256,
        "scripthash prefix shards must be power-of-two ≤ 256, got {n}"
    );
    let bits = n.trailing_zeros() as usize;
    (full[0] as usize) >> (8 - bits)
}

pub struct ScriptHashHead {
    file: TableFile,
    state: Mutex<HashState>,
}

struct HashState {
    slots: u64,
    occupied: u64,
    /// When false, `occupied` is not authoritative (large open without `.occ`).
    /// Never treat as empty / never bulk-fill from this state.
    occ_known: bool,
}

fn occ_sidecar_path(head_path: &Path) -> PathBuf {
    let mut p = head_path.as_os_str().to_os_string();
    p.push(".occ");
    PathBuf::from(p)
}

fn load_occ_sidecar(head_path: &Path) -> Option<u64> {
    let p = occ_sidecar_path(head_path);
    let Ok(buf) = std::fs::read(&p) else {
        return None;
    };
    if buf.len() < 16 || &buf[0..8] != OCC_MAGIC {
        return None;
    }
    Some(u64::from_le_bytes(buf[8..16].try_into().ok()?))
}

fn store_occ_sidecar(head_path: &Path, occupied: u64) -> Result<(), StoreError> {
    let p = occ_sidecar_path(head_path);
    let tmp = {
        let mut t = p.as_os_str().to_os_string();
        t.push(".tmp");
        PathBuf::from(t)
    };
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(OCC_MAGIC);
    buf[8..16].copy_from_slice(&occupied.to_le_bytes());
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&tmp, buf).map_err(|e| StoreError::io(&tmp, e))?;
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, &p).map_err(|e| StoreError::io(&p, e))?;
    Ok(())
}

fn scan_occupied(file: &TableFile, slots: u64) -> Result<u64, StoreError> {
    let mut occupied = 0u64;
    let mut buf = vec![0u8; SH_HEAD_SLOT_SIZE * 1024];
    let mut slot = 0u64;
    while slot < slots {
        let n = ((slots - slot) as usize).min(1024);
        let off = FILE_HEADER_LEN as u64 + slot * SH_HEAD_SLOT_SIZE as u64;
        let bytes = n * SH_HEAD_SLOT_SIZE;
        file.read_at(off, &mut buf[..bytes])?;
        for i in 0..n {
            let base = i * SH_HEAD_SLOT_SIZE;
            let k: ShHeadKey = buf[base..base + SH_HEAD_KEY_LEN].try_into().unwrap();
            let v: [u8; SH_HEAD_VALUE_LEN] = buf[base + SH_HEAD_KEY_LEN..base + SH_HEAD_SLOT_SIZE]
                .try_into()
                .unwrap();
            if !is_empty_slot(&k, &v) {
                unpack8_bytes(&v)?;
                occupied += 1;
            }
        }
        slot += n as u64;
    }
    Ok(occupied)
}

impl ScriptHashHead {
    /// Occupied/slots before ingest seals to L0 (`SHSR`).
    pub const SH_SEAL_LOAD: f64 = 0.80;

    pub fn create_with_slots(path: impl Into<PathBuf>, slots: u64) -> Result<Self, StoreError> {
        let slots = slots.max(2).next_power_of_two();
        let file = TableFile::create(path, TableKind::HashHead)?;
        let body_bytes = SH_HEAD_SLOT_SIZE as u64 * slots;
        let need = FILE_HEADER_LEN as u64 + body_bytes;
        file.ensure_capacity(need)?;
        file.set_logical_len(need)?;
        file.zero_range(FILE_HEADER_LEN as u64, body_bytes)?;
        let _ = store_occ_sidecar(file.path(), 0);
        Ok(Self {
            file,
            state: Mutex::new(HashState {
                slots,
                occupied: 0,
                occ_known: true,
            }),
        })
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let file = TableFile::open(path, TableKind::HashHead)?;
        Self::from_file(file)
    }

    fn from_file(file: TableFile) -> Result<Self, StoreError> {
        let body = file.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if !body.is_multiple_of(SH_HEAD_SLOT_SIZE as u64) || body == 0 {
            return Err(StoreError::Corrupt("scripthash head size"));
        }
        let slots = body / SH_HEAD_SLOT_SIZE as u64;
        if !slots.is_power_of_two() {
            return Err(StoreError::Corrupt(
                "scripthash head slots not power of two",
            ));
        }
        let (occupied, occ_known) = if body <= OCC_SCAN_BYTE_CAP {
            // Tiny heads: always walk slots so leftover pack8 Paged refuses on open.
            let occ = scan_occupied(&file, slots)?;
            let _ = store_occ_sidecar(file.path(), occ);
            (occ, true)
        } else if let Some(occ) = load_occ_sidecar(file.path()) {
            (occ, true)
        } else {
            // Multi‑GiB mainnet shard without sidecar: do **not** read every slot.
            // Occupancy unknown — never empty, never bulk-fill (see insert path).
            rbitcoin_log::info!(
                "store: scripthash head open skip occupancy scan path={} body_MiB≈{:.0} \
                 (no .occ sidecar; lookups ok, is_empty=false until reinit/install)",
                file.path().display(),
                body as f64 / (1024.0 * 1024.0)
            );
            (0, false)
        };
        Ok(Self {
            file,
            state: Mutex::new(HashState {
                slots,
                occupied,
                occ_known,
            }),
        })
    }

    fn persist_occ(&self, occupied: u64) {
        let _ = store_occ_sidecar(self.file.path(), occupied);
    }

    fn set_occupied_known(&self, occupied: u64) {
        {
            let mut state = self.state.lock().unwrap();
            state.occupied = occupied;
            state.occ_known = true;
        }
        self.persist_occ(occupied);
    }

    fn hash_slot(key: &ShHeadKey, slots: u64) -> u64 {
        open_address::primary_slot(key, slots)
    }

    fn slot_file_off(slot: u64) -> u64 {
        FILE_HEADER_LEN as u64 + slot * SH_HEAD_SLOT_SIZE as u64
    }

    fn to_key(full: &[u8; 32]) -> ShHeadKey {
        head_key_from_full(full)
    }

    pub fn get(&self, full: &[u8; 32]) -> Result<Option<ShHeadValue>, StoreError> {
        Ok(self.get_with_chunk_loads(full)?.0)
    }

    /// Like [`Self::get`], also returns 4 KiB chunk `read_at` count (shared cache size = 1).
    fn get_with_chunk_loads(
        &self,
        full: &[u8; 32],
    ) -> Result<(Option<ShHeadValue>, u64), StoreError> {
        let key = Self::to_key(full);
        let slots = self.state.lock().unwrap().slots;
        let mut cache = SlotPageCache::new(self, slots);
        let mut slot = Self::hash_slot(&key, slots);
        for _ in 0..slots {
            let (k, v) = cache.read_slot(slot)?;
            if is_empty_slot(&k, &v) {
                return Ok((None, cache.chunk_loads));
            }
            if k == key {
                let val = unpack8_bytes(&v)?;
                if val.is_empty() {
                    return Ok((None, cache.chunk_loads));
                }
                return Ok((Some(val), cache.chunk_loads));
            }
            slot = (slot + 1) & (slots - 1);
        }
        Ok((None, cache.chunk_loads))
    }

    pub fn insert(&self, full: &[u8; 32], value: &ShHeadValue) -> Result<(), StoreError> {
        self.insert_many(&[(*full, value.clone())])
    }

    /// Soft-clear value; keeps probe chain.
    pub fn clear_key(&self, full: &[u8; 32]) -> Result<bool, StoreError> {
        let key = Self::to_key(full);
        let slots = self.state.lock().unwrap().slots;
        let mut cache = SlotPageCache::new(self, slots);
        let mut slot = Self::hash_slot(&key, slots);
        for _ in 0..slots {
            let (k, v) = cache.read_slot(slot)?;
            if is_empty_slot(&k, &v) {
                return Ok(false);
            }
            if k == key {
                cache.write_slot(slot, &key, &[0u8; SH_HEAD_VALUE_LEN])?;
                cache.flush()?;
                return Ok(true);
            }
            slot = (slot + 1) & (slots - 1);
        }
        Ok(false)
    }

    pub fn insert_many(&self, entries: &[([u8; 32], ShHeadValue)]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut upserts: Vec<(ShHeadKey, ShHeadValue)> = Vec::with_capacity(entries.len());
        for (full, v) in entries {
            let key = Self::to_key(full);
            if v.is_empty() {
                self.clear_key(full)?;
            } else {
                upserts.push((key, v.clone()));
            }
        }
        if upserts.is_empty() {
            return Ok(());
        }
        // Bulk-fill only when occupancy is known empty — never when open skipped
        // the scan (would overwrite a live multi‑GiB table). Does not grow.
        {
            let state = self.state.lock().unwrap();
            if state.occ_known && state.occupied == 0 {
                drop(state);
                return self.bulk_fill_empty(&upserts);
            }
        }

        let mut work = upserts;
        let slots_now = self.state.lock().unwrap().slots;
        work.sort_unstable_by_key(|(k, _)| Self::hash_slot(k, slots_now));

        let cap = slots_now.saturating_mul(MAX_LOAD_NUM) / MAX_LOAD_DEN;
        let mut i = 0usize;
        let mut cache = SlotPageCache::new(self, slots_now);
        while i < work.len() {
            let (key, ref val) = work[i];
            let at_cap = {
                let st = self.state.lock().unwrap();
                st.occ_known && st.occupied >= cap
            };
            if at_cap {
                let mut full = [0u8; 32];
                full[..SH_HEAD_KEY_LEN].copy_from_slice(&key);
                if self.get(&full)?.is_none() {
                    cache.flush()?;
                    return Err(StoreError::Corrupt(SH_HEAD_FULL));
                }
            }
            let enc = pack8_bytes(val)?;
            match cache.try_insert(&key, &enc, true)? {
                InsertResult::Done(was_empty) => {
                    if was_empty {
                        let mut state = self.state.lock().unwrap();
                        if state.occ_known {
                            if state.occupied >= cap {
                                cache.flush()?;
                                return Err(StoreError::Corrupt(SH_HEAD_FULL));
                            }
                            state.occupied = state.occupied.saturating_add(1);
                        }
                    }
                    i += 1;
                }
                InsertResult::NeedSlot => {
                    cache.flush()?;
                    return Err(StoreError::Corrupt(SH_HEAD_FULL));
                }
            }
        }
        cache.flush()?;
        // Seal sidecar after batch when count is authoritative.
        {
            let state = self.state.lock().unwrap();
            if state.occ_known {
                let occ = state.occupied;
                drop(state);
                self.persist_occ(occ);
            }
        }
        Ok(())
    }

    /// occupied/slots when occupancy is known (`None` if unknown).
    pub fn load_ratio(&self) -> Option<f64> {
        let state = self.state.lock().unwrap();
        if !state.occ_known || state.slots == 0 {
            return None;
        }
        Some(state.occupied as f64 / state.slots as f64)
    }

    /// How many new keys can land before ingest should seal (0 → seal first).
    pub fn room_before_seal(&self) -> u64 {
        let st = self.state.lock().unwrap();
        if !st.occ_known || st.slots == 0 {
            return 0;
        }
        let cap = ((st.slots as f64) * Self::SH_SEAL_LOAD).ceil() as u64;
        cap.saturating_sub(st.occupied)
    }

    fn bulk_fill_empty(&self, entries: &[(ShHeadKey, ShHeadValue)]) -> Result<(), StoreError> {
        debug_assert!(self.is_known_empty());
        let slots = self.state.lock().unwrap().slots;
        let nbytes = (slots as usize).saturating_mul(SH_HEAD_SLOT_SIZE);
        let mut table = vec![0u8; nbytes];
        let mut occupied = 0u64;
        for (key, val) in entries {
            let enc = pack8_bytes(val)?;
            let mut slot = Self::hash_slot(key, slots);
            let mut placed = false;
            for _ in 0..slots {
                let off = (slot as usize) * SH_HEAD_SLOT_SIZE;
                let slot_key: ShHeadKey = table[off..off + SH_HEAD_KEY_LEN].try_into().unwrap();
                let slot_v: [u8; SH_HEAD_VALUE_LEN] = table
                    [off + SH_HEAD_KEY_LEN..off + SH_HEAD_SLOT_SIZE]
                    .try_into()
                    .unwrap();
                if is_empty_slot(&slot_key, &slot_v) {
                    table[off..off + SH_HEAD_KEY_LEN].copy_from_slice(key);
                    table[off + SH_HEAD_KEY_LEN..off + SH_HEAD_SLOT_SIZE].copy_from_slice(&enc);
                    occupied = occupied.saturating_add(1);
                    placed = true;
                    break;
                }
                if &slot_key == key {
                    table[off + SH_HEAD_KEY_LEN..off + SH_HEAD_SLOT_SIZE].copy_from_slice(&enc);
                    placed = true;
                    break;
                }
                slot = (slot + 1) & (slots - 1);
            }
            if !placed {
                return Err(StoreError::Corrupt("scripthash head bulk_fill full"));
            }
        }
        self.file.write_at(FILE_HEADER_LEN as u64, &table)?;
        self.set_occupied_known(occupied);
        Ok(())
    }

    pub fn occupied(&self) -> u64 {
        self.state.lock().unwrap().occupied
    }

    /// True when occupancy is known and zero (safe for cold bulk-fill / install).
    pub fn is_known_empty(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.occ_known && state.occupied == 0
    }

    /// Visit every occupied non-empty head value (key is zero-padded to 32 B for API).
    pub fn for_each_occupied(
        &self,
        mut f: impl FnMut([u8; 32], ShHeadValue) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let slots = self.state.lock().unwrap().slots;
        let mut buf = vec![0u8; SH_HEAD_SLOT_SIZE * 1024];
        let mut slot = 0u64;
        while slot < slots {
            let n = ((slots - slot) as usize).min(1024);
            let off = FILE_HEADER_LEN as u64 + slot * SH_HEAD_SLOT_SIZE as u64;
            let bytes = n * SH_HEAD_SLOT_SIZE;
            self.file.read_at(off, &mut buf[..bytes])?;
            for i in 0..n {
                let base = i * SH_HEAD_SLOT_SIZE;
                let k: ShHeadKey = buf[base..base + SH_HEAD_KEY_LEN].try_into().unwrap();
                let v: [u8; SH_HEAD_VALUE_LEN] = buf
                    [base + SH_HEAD_KEY_LEN..base + SH_HEAD_SLOT_SIZE]
                    .try_into()
                    .unwrap();
                if is_empty_slot(&k, &v) {
                    continue;
                }
                let val = unpack8_bytes(&v)?;
                if !val.is_empty() {
                    let mut full = [0u8; 32];
                    full[0..SH_HEAD_KEY_LEN].copy_from_slice(&k);
                    f(full, val)?;
                }
            }
            slot += n as u64;
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

fn is_empty_slot(k: &ShHeadKey, v: &[u8; SH_HEAD_VALUE_LEN]) -> bool {
    *k == [0u8; SH_HEAD_KEY_LEN] && *v == [0u8; SH_HEAD_VALUE_LEN]
}

enum InsertResult {
    /// Wrote the slot. `true` = filled a previously empty slot (new key).
    Done(bool),
    /// Key is not present and a new slot is required (or `allow_new` is false at
    /// the first empty / end of probe). Caller may rehash or spill to overflow.
    NeedSlot,
}

struct SlotPageCache<'a> {
    head: &'a ScriptHashHead,
    slots: u64,
    chunks: BTreeMap<u64, CachedChunk>,
    /// Number of `read_at` chunk faults (for microbenches / diagnostics).
    chunk_loads: u64,
}

struct CachedChunk {
    base_slot: u64,
    data: Vec<u8>,
    dirty: bool,
}

impl<'a> SlotPageCache<'a> {
    fn new(head: &'a ScriptHashHead, slots: u64) -> Self {
        Self {
            head,
            slots,
            chunks: BTreeMap::new(),
            chunk_loads: 0,
        }
    }

    /// Probe-insert. When `allow_new` is false, only in-place updates of an
    /// existing key succeed; empty slot (key absent under open addressing) or a
    /// full probe without a match returns [`InsertResult::NeedSlot`].
    fn try_insert(
        &mut self,
        key: &ShHeadKey,
        value: &[u8; SH_HEAD_VALUE_LEN],
        allow_new: bool,
    ) -> Result<InsertResult, StoreError> {
        let mut slot = ScriptHashHead::hash_slot(key, self.slots);
        for _ in 0..self.slots {
            let (k, old_v) = self.read_slot(slot)?;
            if is_empty_slot(&k, &old_v) {
                if !allow_new {
                    // Empty ends the open-address probe: key is not present.
                    return Ok(InsertResult::NeedSlot);
                }
                self.write_slot(slot, key, value)?;
                return Ok(InsertResult::Done(true));
            }
            if &k == key {
                self.write_slot(slot, key, value)?;
                return Ok(InsertResult::Done(false));
            }
            slot = (slot + 1) & (self.slots - 1);
        }
        Ok(InsertResult::NeedSlot)
    }

    fn read_slot(&mut self, slot: u64) -> Result<(ShHeadKey, [u8; SH_HEAD_VALUE_LEN]), StoreError> {
        let chunk = self.ensure_chunk(slot)?;
        let rel = ((slot - chunk.base_slot) as usize) * SH_HEAD_SLOT_SIZE;
        let k: ShHeadKey = chunk.data[rel..rel + SH_HEAD_KEY_LEN].try_into().unwrap();
        let v: [u8; SH_HEAD_VALUE_LEN] = chunk.data[rel + SH_HEAD_KEY_LEN..rel + SH_HEAD_SLOT_SIZE]
            .try_into()
            .unwrap();
        Ok((k, v))
    }

    fn write_slot(
        &mut self,
        slot: u64,
        key: &ShHeadKey,
        value: &[u8; SH_HEAD_VALUE_LEN],
    ) -> Result<(), StoreError> {
        let chunk = self.ensure_chunk(slot)?;
        let rel = ((slot - chunk.base_slot) as usize) * SH_HEAD_SLOT_SIZE;
        chunk.data[rel..rel + SH_HEAD_KEY_LEN].copy_from_slice(key);
        chunk.data[rel + SH_HEAD_KEY_LEN..rel + SH_HEAD_SLOT_SIZE].copy_from_slice(value);
        chunk.dirty = true;
        Ok(())
    }

    fn ensure_chunk(&mut self, slot: u64) -> Result<&mut CachedChunk, StoreError> {
        let chunk_idx = slot / SLOTS_PER_CHUNK;
        if !self.chunks.contains_key(&chunk_idx) {
            if self.chunks.len() >= CHUNK_CACHE_MAX {
                self.flush()?;
            }
            let base_slot = chunk_idx * SLOTS_PER_CHUNK;
            let n = ((self.slots - base_slot) as usize).min(SLOTS_PER_CHUNK as usize);
            let off = ScriptHashHead::slot_file_off(base_slot);
            let len = n * SH_HEAD_SLOT_SIZE;
            let mut data = vec![0u8; len];
            self.head.file.read_at(off, &mut data)?;
            self.chunk_loads = self.chunk_loads.saturating_add(1);
            self.chunks.insert(
                chunk_idx,
                CachedChunk {
                    base_slot,
                    data,
                    dirty: false,
                },
            );
        }
        Ok(self.chunks.get_mut(&chunk_idx).unwrap())
    }

    fn flush(&mut self) -> Result<(), StoreError> {
        for (_, chunk) in self.chunks.iter_mut() {
            if chunk.dirty {
                let off = ScriptHashHead::slot_file_off(chunk.base_slot);
                self.head.file.write_at(off, &chunk.data)?;
                chunk.dirty = false;
            }
        }
        self.chunks.clear();
        Ok(())
    }
}

/// Sharded facade (64-way mainnet) over [`ScriptHashHead`].
#[cfg(test)]
pub struct ShardedScriptHashHead {
    shards: Vec<ScriptHashHead>,
}

#[cfg(test)]
impl ShardedScriptHashHead {
    pub fn create_sharded(
        path: impl Into<PathBuf>,
        shard_count: usize,
        slots_each: u64,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        let n = shard_count.max(1);
        let per = slots_each.max(2).next_power_of_two();
        if n == 1 {
            let h = ScriptHashHead::create_with_slots(&path, per)?;
            return Ok(Self { shards: vec![h] });
        }
        if path.exists() {
            return Err(StoreError::io(
                &path,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "sharded scripthash head path exists",
                ),
            ));
        }
        std::fs::create_dir_all(&path).map_err(|e| StoreError::io(&path, e))?;
        let mut shards = Vec::with_capacity(n);
        for i in 0..n {
            let shard_path = path.join(format!("{i:02x}"));
            shards.push(ScriptHashHead::create_with_slots(shard_path, per)?);
        }
        Ok(Self { shards })
    }

    pub fn open_for_role(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if path.is_dir() {
            // Shard files only (`00`..`3f`); ignore `00.occ` sidecars and temps.
            let mut names: Vec<String> = std::fs::read_dir(&path)
                .map_err(|e| StoreError::io(&path, e))?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.len() == 2 && n.chars().all(|c| c.is_ascii_hexdigit()))
                .collect();
            names.sort();
            if names.is_empty() {
                return Err(StoreError::Corrupt("sharded scripthash head empty"));
            }
            let mut shards = Vec::with_capacity(names.len());
            for (i, name) in names.iter().enumerate() {
                let expect = format!("{i:02x}");
                if name != &expect {
                    return Err(StoreError::Corrupt(
                        "sharded scripthash head unexpected shard name",
                    ));
                }
                shards.push(ScriptHashHead::open(path.join(name))?);
            }
            return Ok(Self { shards });
        }
        if path.is_file() {
            return Ok(Self {
                shards: vec![ScriptHashHead::open(path)?],
            });
        }
        Err(StoreError::io(
            &path,
            std::io::Error::new(std::io::ErrorKind::NotFound, "scripthash head missing"),
        ))
    }

    #[inline]
    fn shard_of(&self, full: &[u8; 32]) -> usize {
        prefix_shard_of(full, self.shards.len())
    }

    #[cfg(test)]
    pub fn get(&self, key: &[u8; 32]) -> Result<Option<ShHeadValue>, StoreError> {
        self.shards[self.shard_of(key)].get(key)
    }

    #[cfg(test)]
    pub fn insert(&self, key: &[u8; 32], value: &ShHeadValue) -> Result<(), StoreError> {
        self.shards[self.shard_of(key)].insert(key, value)
    }

    #[cfg(test)]
    pub fn clear_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
        self.shards[self.shard_of(key)].clear_key(key)
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Shard index for a full Electrum scripthash (same as insert routing).
    #[inline]
    pub fn shard_index(&self, full: &[u8; 32]) -> usize {
        self.shard_of(full)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        for s in &self.shards {
            s.flush()?;
        }
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        for s in &self.shards {
            s.flush_async()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::Fk;

    #[test]
    fn prefix_shard_of_high_bits_contiguous() {
        // 16 shards: first nibble of byte 0.
        assert_eq!(prefix_shard_of(&[0x00; 32], 16), 0);
        assert_eq!(prefix_shard_of(&[0x0f; 32], 16), 0);
        let mut k = [0u8; 32];
        k[0] = 0x10;
        assert_eq!(prefix_shard_of(&k, 16), 1);
        k[0] = 0x1f;
        assert_eq!(prefix_shard_of(&k, 16), 1);
        k[0] = 0xf0;
        assert_eq!(prefix_shard_of(&k, 16), 15);
        k[0] = 0xff;
        assert_eq!(prefix_shard_of(&k, 16), 15);
        // Lex order of first byte maps to non-decreasing shard ids.
        let mut prev = 0usize;
        for b in 0u16..=255 {
            k[0] = b as u8;
            let s = prefix_shard_of(&k, 16);
            assert!(s >= prev, "b={b:#x} shard={s} prev={prev}");
            prev = s;
        }
        assert_eq!(prefix_shard_of(&[0xab; 32], 1), 0);
    }

    #[test]
    fn head_insert_get_clear() {
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-shhead-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(occ_sidecar_path(&path));
        let h = ScriptHashHead::create_with_slots(&path, 64).unwrap();
        let mut key = [0u8; 32];
        key[0] = 7;
        let val = ShHeadValue::inline_one(Fk(42));
        h.insert(&key, &val).unwrap();
        assert_eq!(h.get(&key).unwrap().unwrap(), val);
        assert!(h.clear_key(&key).unwrap());
        assert!(h.get(&key).unwrap().is_none());
        // Sidecar tracks occupied; reopen without full scan path for tiny files.
        drop(h);
        let h2 = ScriptHashHead::open(&path).unwrap();
        assert!(h2.is_known_empty() || h2.occupied() >= 1); // soft-clear keeps slot
        assert!(h2.get(&key).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(occ_sidecar_path(&path));
    }

    #[test]
    fn open_large_without_occ_skips_scan_not_empty() {
        // Body just over OCC_SCAN_BYTE_CAP → skip full scan when .occ missing.
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-shhead-large-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(occ_sidecar_path(&path));
        // body = slots * 32 B; need body > 16 MiB ⇒ slots > 16MiB/32 = 524_288.
        let min_slots = (OCC_SCAN_BYTE_CAP / SH_HEAD_SLOT_SIZE as u64) + 1;
        let slots = min_slots.next_power_of_two();
        assert!(slots * SH_HEAD_SLOT_SIZE as u64 > OCC_SCAN_BYTE_CAP);
        let h = ScriptHashHead::create_with_slots(&path, slots).unwrap();
        assert!(h.is_known_empty());
        let mut key = [0u8; 32];
        key[0] = 0xab;
        h.insert(&key, &ShHeadValue::inline_one(Fk(1))).unwrap();
        assert_eq!(h.occupied(), 1);
        drop(h);
        // Drop sidecar only — reopen must not scan body and must not claim empty.
        let _ = std::fs::remove_file(occ_sidecar_path(&path));
        let t0 = Instant::now();
        let h2 = ScriptHashHead::open(&path).unwrap();
        let open_ms = t0.elapsed().as_millis();
        assert!(
            !h2.is_known_empty(),
            "missing .occ on large head must not report empty"
        );
        assert!(
            open_ms < 2_000,
            "open without .occ must skip full scan (took {open_ms}ms)"
        );
        // Lookups still work (probe, not occupancy).
        assert_eq!(h2.get(&key).unwrap().unwrap().inline_fks(), vec![Fk(1)]);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(occ_sidecar_path(&path));
    }

    #[test]
    fn scripthash_head_insert_many_full_without_rehash() {
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-shhead-full-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let h = ScriptHashHead::create_with_slots(&path, 8).unwrap();
        h.insert_many(&[]).unwrap();
        let mut k0 = [0u8; 32];
        k0[0] = 1;
        h.insert(&k0, &ShHeadValue::Empty).unwrap();
        assert!(!h.clear_key(&k0).unwrap());

        let mut n = 0u64;
        loop {
            let mut key = [0u8; 32];
            key[0..8].copy_from_slice(&n.to_le_bytes());
            match h.insert(&key, &ShHeadValue::inline_one(Fk(n + 1))) {
                Ok(()) => n += 1,
                Err(StoreError::Corrupt(SH_HEAD_FULL)) => break,
                Err(e) => panic!("unexpected {e}"),
            }
            assert!(n < 16, "must not grow 8-slot ingest OA");
        }
        let mut seen = 0u64;
        h.for_each_occupied(|_full, val| {
            assert!(!val.is_empty());
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert!(seen >= 1);
        h.flush().unwrap();
        h.flush_async().unwrap();
        drop(h);
        let h2 = ScriptHashHead::open(&path).unwrap();
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&5u64.to_le_bytes());
        assert!(h2.get(&key).unwrap().is_some());
        // corrupt size open
        {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len((FILE_HEADER_LEN + 3) as u64)
                .unwrap();
        }
        assert!(matches!(
            ScriptHashHead::open(&path),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// Multi-shard create/open/insert/reinit/flush + error arms.
    #[test]
    fn sharded_scripthash_head_create_open_and_errors() {
        let base = std::env::temp_dir().join(format!(
            "rbitcoin-sh-sharded-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // n=1 uses single-file path
        let single = base.join("single");
        let h1 = ShardedScriptHashHead::create_sharded(&single, 1, 32).unwrap();
        assert_eq!(h1.shard_count(), 1);
        let mut k = [0u8; 32];
        k[0] = 0xab;
        h1.insert(&k, &ShHeadValue::inline_one(Fk(9))).unwrap();
        assert!(h1.get(&k).unwrap().is_some());
        h1.clear_key(&k).unwrap();
        h1.flush().unwrap();
        h1.flush_async().unwrap();
        drop(h1);

        // Multi-shard directory layout
        let multi = base.join("multi");
        let h = ShardedScriptHashHead::create_sharded(&multi, 4, 16).unwrap();
        assert_eq!(h.shard_count(), 4);
        // route inserts across shards
        for i in 0u8..16 {
            let mut key = [0u8; 32];
            key[0] = i.wrapping_mul(0x40); // spread high bits
            h.insert(&key, &ShHeadValue::inline_one(Fk(i as u64 + 1)))
                .unwrap();
            assert_eq!(h.shard_index(&key), prefix_shard_of(&key, 4));
        }
        h.flush().unwrap();
        drop(h);
        // open_for_role directory
        let h2 = ShardedScriptHashHead::open_for_role(&multi).unwrap();
        assert_eq!(h2.shard_count(), 4);
        let key0 = [0u8; 32];
        assert!(h2.get(&key0).unwrap().is_some());
        assert!(h2.clear_key(&key0).unwrap());
        assert!(h2.get(&key0).unwrap().is_none());
        drop(h2);

        // create on existing path fails
        assert!(ShardedScriptHashHead::create_sharded(&multi, 4, 16).is_err());

        // open empty dir
        let empty = base.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(matches!(
            ShardedScriptHashHead::open_for_role(&empty),
            Err(StoreError::Corrupt(_))
        ));
        // open missing
        assert!(ShardedScriptHashHead::open_for_role(base.join("nope")).is_err());
        // open single file via open_for_role
        let h3 = ShardedScriptHashHead::open_for_role(&single).unwrap();
        assert_eq!(h3.shard_count(), 1);

        // unexpected shard name
        let bad = base.join("badnames");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("zz"), b"x").unwrap();
        assert!(matches!(
            ShardedScriptHashHead::open_for_role(&bad),
            Err(StoreError::Corrupt(_))
        ));

        let _ = std::fs::remove_dir_all(&base);
    }
}
