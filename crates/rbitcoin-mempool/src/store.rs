//! Private mempool durability under `{datadir}/mempool/` (not Class A).
//!
//! # Namespace (important)
//!
//! | Path | Role |
//! |------|------|
//! | `{datadir}/store/tx.body` | **Class A** confirmed archive — confirm commit sole writer |
//! | `{datadir}/mempool/tx.body` | **This file** — unconfirmed live set only |
//!
//! # Transport (phase 5b M2)
//!
//! Process-owned buffers (`meta` fields + `slots` / `body` `Vec`s) are the
//! source of truth. Sidecar files are updated with normal `read`/`write` /
//! `pwrite`-style IO — **no `memmap2`**. Flush bumps generation and `sync_data`.

use crate::error::MempoolError;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// File magic: `rBMP` (rbitcoin mempool).
pub const MEM_MAGIC: [u8; 4] = *b"rBMP";
/// Schema version for the meta header.
pub const MEM_SCHEMA: u16 = 1;

const META_LEN: usize = 64;
/// Initial slot table capacity (records).
///
/// Sized for mainnet tip mempool under a ~300 MvB weight budget: many small
/// txs fit weight-wise long before 4k slots fill (overnight tip stall). Fixed
/// constant — no env. Existing datadirs with smaller caps grow on demand.
const DEFAULT_SLOT_CAP: u32 = 131_072;
/// Hard ceiling when doubling the slot table (DoS / RAM bound).
const MAX_SLOT_CAP: u32 = 1_048_576;
/// Slot record: status(1) + pad(3) + body_off(8) + body_len(4) + txid(32) = 48.
const SLOT_REC: usize = 48;
const SLOTS_HEADER: usize = 16;
const BODY_HEADER: usize = 16;
/// Prefix before each serialized tx in `mempool/tx.body`.
const BODY_TX_PREFIX: usize = 16;

const SLOT_FREE: u8 = 0;
const SLOT_LIVE: u8 = 1;
const SLOT_DEAD: u8 = 2;

/// Snapshot of durable meta fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolMeta {
    /// Last committed generation (bumped on flush).
    pub generation: u64,
    /// Slot table capacity (record count).
    pub slot_cap: u32,
    /// Number of LIVE slots.
    pub live_count: u32,
}

/// Coalesce sidecar writes: flush RAM→disk after this many dirty ops (append/dead).
///
/// Crash may lose fewer than this many admits since the last persist (relay re-fetch).
/// Structural ops (slot grow, compact) and [`Mempool::flush`] always persist.
pub const PERSIST_COALESCE_OPS: u32 = 32;

/// Durable mempool under `dir` (`{datadir}/mempool`) — InRam buffers + file IO.
pub struct Mempool {
    dir: PathBuf,
    meta_file: File,
    slots_file: File,
    body_file: File,
    /// Full slots image (header + records).
    slots: Vec<u8>,
    /// Full body image including header; logical length in `body[8..16]`.
    body: Vec<u8>,
    generation: u64,
    slot_cap: u32,
    live_count: u32,
    /// Append/mark_dead ops since last sidecar persist.
    dirty_ops: u32,
}

impl Mempool {
    /// Create `dir` if needed and open (or initialize) meta/slots/body into RAM.
    pub fn open_or_create(dir: impl Into<PathBuf>) -> Result<Self, MempoolError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| MempoolError::io(&dir, e))?;
        finish_pending_compact(&dir)?;

        let meta_path = dir.join("meta");
        let slots_path = dir.join("slots");
        let body_path = dir.join("tx.body");

        let (meta_file, generation, slot_cap, _meta_live) = open_or_init_meta(&meta_path)?;
        let (slots_file, slots) = open_or_init_slots(&slots_path, slot_cap)?;
        let (body_file, body) = open_or_init_body(&body_path)?;
        let live_count = count_live_slots(&slots, slot_cap);

        Ok(Self {
            dir,
            meta_file,
            slots_file,
            body_file,
            slots,
            body,
            generation,
            slot_cap,
            live_count,
            dirty_ops: 0,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn meta(&self) -> MempoolMeta {
        MempoolMeta {
            generation: self.generation,
            slot_cap: self.slot_cap,
            live_count: self.live_count,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn live_count(&self) -> u32 {
        self.live_count
    }

    /// Test / rebuild helper: set live_count without scanning.
    pub(crate) fn set_live_count(&mut self, n: u32) {
        self.live_count = n;
    }

    /// Persist buffers, bump generation, and fsync sidecar files.
    ///
    /// Accept path coalesces non-fsync writes ([`PERSIST_COALESCE_OPS`]); a crash
    /// may lose admits since the last persist. [`Self::flush`] is the durable
    /// checkpoint (generation + fsync).
    pub fn flush(&mut self) -> Result<(), MempoolError> {
        self.generation = self.generation.saturating_add(1);
        self.persist_all()?;
        self.dirty_ops = 0;
        self.meta_file
            .sync_data()
            .map_err(|e| MempoolError::io(self.dir.join("meta"), e))?;
        self.slots_file
            .sync_data()
            .map_err(|e| MempoolError::io(self.dir.join("slots"), e))?;
        self.body_file
            .sync_data()
            .map_err(|e| MempoolError::io(self.dir.join("tx.body"), e))?;
        Ok(())
    }

    /// Best-effort sidecar write if dirty (no generation bump / no fsync).
    pub fn persist_if_dirty(&mut self) -> Result<(), MempoolError> {
        if self.dirty_ops == 0 {
            return Ok(());
        }
        self.persist_all()?;
        self.dirty_ops = 0;
        Ok(())
    }

    fn note_dirty_op(&mut self) -> Result<(), MempoolError> {
        self.dirty_ops = self.dirty_ops.saturating_add(1);
        if self.dirty_ops >= PERSIST_COALESCE_OPS {
            self.persist_all()?;
            self.dirty_ops = 0;
        }
        Ok(())
    }

    /// Append raw tx bytes + fee/weight prefix; mark a FREE slot LIVE.
    ///
    /// Returns the slot index. Updates `live_count` (not generation — call flush).
    /// RAM is updated immediately; sidecar write is coalesced (see
    /// [`PERSIST_COALESCE_OPS`]) unless this op trips the threshold.
    pub fn append_live_tx(
        &mut self,
        raw_tx: &[u8],
        txid: &Txid,
        fee_sat: u64,
        weight: u64,
    ) -> Result<u32, MempoolError> {
        let payload_len = BODY_TX_PREFIX + raw_tx.len();
        if payload_len > u32::MAX as usize {
            return Err(MempoolError::Corrupt("tx body too large"));
        }
        let body_off = self.reserve_body(payload_len)?;
        let off = body_off as usize;
        self.body[off..off + 8].copy_from_slice(&fee_sat.to_le_bytes());
        self.body[off + 8..off + 16].copy_from_slice(&weight.to_le_bytes());
        self.body[off + BODY_TX_PREFIX..off + payload_len].copy_from_slice(raw_tx);
        let slot = self.alloc_slot()?;
        self.write_slot(slot, SLOT_LIVE, body_off, payload_len as u32, txid)?;
        self.live_count = self.live_count.saturating_add(1);
        self.note_dirty_op()?;
        Ok(slot)
    }

    /// Drop every LIVE slot (Core `-persistmempool=0` start: do not reload).
    pub fn abandon_live(&mut self) -> Result<u32, MempoolError> {
        let mut n = 0u32;
        for slot in 0..self.slot_cap {
            let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
            if self.slots[off] == SLOT_LIVE {
                self.slots[off] = SLOT_DEAD;
                n = n.saturating_add(1);
            }
        }
        if n > 0 {
            self.live_count = 0;
            self.flush()?;
        }
        Ok(n)
    }

    /// Mark slot DEAD and decrement live_count (rollback path).
    pub fn mark_slot_dead(&mut self, slot: u32) -> Result<(), MempoolError> {
        if slot >= self.slot_cap {
            return Err(MempoolError::Corrupt("slot OOB"));
        }
        let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
        if self.slots[off] == SLOT_LIVE {
            self.slots[off] = SLOT_DEAD;
            self.live_count = self.live_count.saturating_sub(1);
            self.note_dirty_op()?;
        }
        Ok(())
    }

    /// Count FREE / LIVE / DEAD slots (for compaction triggers).
    pub fn slot_stats(&self) -> (u32, u32, u32) {
        let mut free = 0u32;
        let mut live = 0u32;
        let mut dead = 0u32;
        for slot in 0..self.slot_cap {
            let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
            match self.slots[off] {
                SLOT_LIVE => live += 1,
                SLOT_DEAD => dead += 1,
                _ => free += 1,
            }
        }
        (free, live, dead)
    }

    /// Logical body length in bytes (includes header).
    pub fn body_logical_len(&self) -> Result<usize, MempoolError> {
        body_logical_len(&self.body)
    }

    /// Rewrite body/slots to contain only LIVE payloads packed from the header.
    ///
    /// Returns `(live_after, body_bytes_after)`. Callers must rebuild RAM indexes
    /// with the new slot numbers from [`load_live_txs`].
    pub fn compact(&mut self) -> Result<(u32, usize), MempoolError> {
        let live = self.load_live_txs()?;

        let mut new_body = vec![0u8; BODY_HEADER];
        new_body[0..4].copy_from_slice(&MEM_MAGIC);
        new_body[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
        let mut new_slots = vec![0u8; SLOTS_HEADER + (self.slot_cap as usize) * SLOT_REC];
        new_slots[0..4].copy_from_slice(&MEM_MAGIC);
        new_slots[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
        new_slots[8..12].copy_from_slice(&self.slot_cap.to_le_bytes());

        let mut next_slot = 0u32;
        for (_old_slot, fee_sat, weight, tx) in &live {
            let raw = bitcoin::consensus::encode::serialize(tx);
            let payload_len = BODY_TX_PREFIX + raw.len();
            let body_off = new_body.len() as u64;
            new_body.extend_from_slice(&fee_sat.to_le_bytes());
            new_body.extend_from_slice(&weight.to_le_bytes());
            new_body.extend_from_slice(&raw);
            let off = SLOTS_HEADER + (next_slot as usize) * SLOT_REC;
            new_slots[off] = SLOT_LIVE;
            new_slots[off + 4..off + 12].copy_from_slice(&body_off.to_le_bytes());
            new_slots[off + 12..off + 16].copy_from_slice(&(payload_len as u32).to_le_bytes());
            new_slots[off + 16..off + 48].copy_from_slice(tx.compute_txid().as_byte_array());
            next_slot += 1;
        }
        let logical = new_body.len();
        new_body[8..16].copy_from_slice(&(logical as u64).to_le_bytes());

        self.body = new_body;
        self.slots = new_slots;
        self.live_count = next_slot;
        self.install_packed_images()?;
        self.dirty_ops = 0;
        Ok((self.live_count, logical))
    }

    /// Load all LIVE txs from slots/body for graph rebuild.
    ///
    /// Returns `(slot, fee_sat, weight, tx)`.
    pub fn load_live_txs(&self) -> Result<Vec<(u32, u64, u64, Transaction)>, MempoolError> {
        let mut out = Vec::new();
        let logical = body_logical_len(&self.body)?;
        for slot in 0..self.slot_cap {
            let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
            if self.slots[off] != SLOT_LIVE {
                continue;
            }
            let body_off = u64::from_le_bytes(self.slots[off + 4..off + 12].try_into().unwrap());
            let body_len =
                u32::from_le_bytes(self.slots[off + 12..off + 16].try_into().unwrap()) as usize;
            if body_off as usize + body_len > logical || body_len < BODY_TX_PREFIX {
                return Err(MempoolError::Corrupt("live slot body range"));
            }
            let start = body_off as usize;
            let fee_sat = u64::from_le_bytes(self.body[start..start + 8].try_into().unwrap());
            let weight = u64::from_le_bytes(self.body[start + 8..start + 16].try_into().unwrap());
            let raw = &self.body[start + BODY_TX_PREFIX..start + body_len];
            let tx: Transaction =
                deserialize(raw).map_err(|_| MempoolError::Corrupt("tx deserialize"))?;
            out.push((slot, fee_sat, weight, tx));
        }
        Ok(out)
    }

    /// True if at least one FREE or DEAD slot can be reused.
    pub fn has_free_slot(&self) -> bool {
        self.find_free_slot().is_some()
    }

    fn find_free_slot(&self) -> Option<u32> {
        for slot in 0..self.slot_cap {
            let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
            if self.slots[off] == SLOT_FREE || self.slots[off] == SLOT_DEAD {
                return Some(slot);
            }
        }
        None
    }

    fn alloc_slot(&mut self) -> Result<u32, MempoolError> {
        if let Some(s) = self.find_free_slot() {
            return Ok(s);
        }
        // Grow once so a full live set under a small legacy cap is not a hard fail.
        self.grow_slots()?;
        self.find_free_slot().ok_or(MempoolError::Full)
    }

    /// Double slot capacity (up to [`MAX_SLOT_CAP`]) and extend the slots image with FREE records.
    pub fn grow_slots(&mut self) -> Result<(), MempoolError> {
        if self.slot_cap >= MAX_SLOT_CAP {
            return Err(MempoolError::Full);
        }
        let new_cap = self
            .slot_cap
            .saturating_mul(2)
            .max(self.slot_cap.saturating_add(DEFAULT_SLOT_CAP.min(16_384)))
            .min(MAX_SLOT_CAP);
        if new_cap <= self.slot_cap {
            return Err(MempoolError::Full);
        }
        let old_cap = self.slot_cap;
        let need = SLOTS_HEADER + (new_cap as usize) * SLOT_REC;
        self.slots.resize(need, 0);
        self.slots[8..12].copy_from_slice(&new_cap.to_le_bytes());
        self.slot_cap = new_cap;
        self.persist_all()?;
        self.dirty_ops = 0;
        rbitcoin_log::info!(
            "mempool: grew slot table {old_cap} → {new_cap} (live={})",
            self.live_count
        );
        Ok(())
    }

    fn write_slot(
        &mut self,
        slot: u32,
        status: u8,
        body_off: u64,
        body_len: u32,
        txid: &Txid,
    ) -> Result<(), MempoolError> {
        let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
        self.slots[off] = status;
        self.slots[off + 1..off + 4].fill(0);
        self.slots[off + 4..off + 12].copy_from_slice(&body_off.to_le_bytes());
        self.slots[off + 12..off + 16].copy_from_slice(&body_len.to_le_bytes());
        self.slots[off + 16..off + 48].copy_from_slice(txid.as_byte_array());
        Ok(())
    }

    /// Ensure body has `need` free bytes; return offset of free region. Updates logical len.
    fn reserve_body(&mut self, need: usize) -> Result<u64, MempoolError> {
        let logical = body_logical_len(&self.body)?;
        let end = logical.saturating_add(need);
        if end > self.body.len() {
            let new_len = (self.body.len().max(4096) * 2).max(end + 4096);
            self.body.resize(new_len, 0);
        }
        self.body[8..16].copy_from_slice(&(end as u64).to_le_bytes());
        Ok(logical as u64)
    }

    /// Write body, then LIVE slots, then meta (no fsync).
    ///
    /// Append-safe: a crash after a grown body and before new slots loses admits;
    /// old LIVE ranges stay a prefix of the new body. Packed compact must not
    /// use this order (see [`Self::install_packed_images`]).
    fn persist_all(&mut self) -> Result<(), MempoolError> {
        let slots_path = self.dir.join("slots");
        let body_path = self.dir.join("tx.body");

        let logical = body_logical_len(&self.body)?;
        self.body_file
            .set_len(logical as u64)
            .map_err(|e| MempoolError::io(&body_path, e))?;
        self.body_file
            .seek(SeekFrom::Start(0))
            .map_err(|e| MempoolError::io(&body_path, e))?;
        self.body_file
            .write_all(&self.body[..logical])
            .map_err(|e| MempoolError::io(&body_path, e))?;

        let slots_need = self.slots.len() as u64;
        self.slots_file
            .set_len(slots_need)
            .map_err(|e| MempoolError::io(&slots_path, e))?;
        self.slots_file
            .seek(SeekFrom::Start(0))
            .map_err(|e| MempoolError::io(&slots_path, e))?;
        self.slots_file
            .write_all(&self.slots)
            .map_err(|e| MempoolError::io(&slots_path, e))?;

        self.persist_meta()
    }

    fn persist_meta(&mut self) -> Result<(), MempoolError> {
        let meta_path = self.dir.join("meta");
        let mut meta = [0u8; META_LEN];
        write_meta_bytes(&mut meta, self.generation, self.slot_cap, self.live_count);
        self.meta_file
            .seek(SeekFrom::Start(0))
            .map_err(|e| MempoolError::io(&meta_path, e))?;
        self.meta_file
            .write_all(&meta)
            .map_err(|e| MempoolError::io(&meta_path, e))?;
        Ok(())
    }

    /// Packed body+slots: both tmps `sync_all`'d, then rename body then slots.
    ///
    /// After rename, persist **meta only** (generation / `live_count` / `slot_cap`).
    /// Do not rewrite body or slots: compact usually shrinks, and `set_len` /
    /// in-place `write_all` would reopen the crash window tmp+rename just closed.
    /// Open finishes a crash after the body rename (`slots.tmp` still present).
    /// Crash after both renames and before meta: packed images + stale
    /// `live_count` still load (`load_live_txs` scans slots; open recounts LIVE).
    fn install_packed_images(&mut self) -> Result<(), MempoolError> {
        let body_path = self.dir.join("tx.body");
        let slots_path = self.dir.join("slots");
        let body_tmp = self.dir.join("tx.body.tmp");
        let slots_tmp = self.dir.join("slots.tmp");
        let logical = body_logical_len(&self.body)?;
        write_file_synced(&body_tmp, &self.body[..logical])?;
        write_file_synced(&slots_tmp, &self.slots)?;
        fs::rename(&body_tmp, &body_path).map_err(|e| MempoolError::io(&body_path, e))?;
        fs::rename(&slots_tmp, &slots_path).map_err(|e| MempoolError::io(&slots_path, e))?;
        self.reopen_body_slots()?;
        self.persist_meta()
    }

    fn reopen_body_slots(&mut self) -> Result<(), MempoolError> {
        let body_path = self.dir.join("tx.body");
        let slots_path = self.dir.join("slots");
        self.body_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&body_path)
            .map_err(|e| MempoolError::io(&body_path, e))?;
        self.slots_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slots_path)
            .map_err(|e| MempoolError::io(&slots_path, e))?;
        Ok(())
    }
}

fn body_logical_len(body: &[u8]) -> Result<usize, MempoolError> {
    if body.len() < BODY_HEADER {
        return Err(MempoolError::Corrupt("body too short"));
    }
    let n = u64::from_le_bytes(body[8..16].try_into().unwrap()) as usize;
    if n < BODY_HEADER || n > body.len() {
        return Err(MempoolError::Corrupt("body logical len"));
    }
    Ok(n)
}

fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<(), MempoolError> {
    let mut f = File::create(path).map_err(|e| MempoolError::io(path, e))?;
    f.write_all(bytes).map_err(|e| MempoolError::io(path, e))?;
    f.sync_all().map_err(|e| MempoolError::io(path, e))?;
    Ok(())
}

/// Finish a compact install interrupted between the two renames.
///
/// Both tmps: neither rename landed — discard. `slots.tmp` only: body rename
/// landed — finish slots. `tx.body.tmp` only: discard (live body is still old).
/// No tmp (crash after both renames, before meta): packed body+slots with stale
/// `live_count` still load; open recounts LIVE from slots.
fn finish_pending_compact(dir: &Path) -> Result<(), MempoolError> {
    let body_tmp = dir.join("tx.body.tmp");
    let slots_tmp = dir.join("slots.tmp");
    match (body_tmp.exists(), slots_tmp.exists()) {
        (true, true) => {
            let _ = fs::remove_file(&body_tmp);
            let _ = fs::remove_file(&slots_tmp);
        }
        (false, true) => {
            fs::rename(&slots_tmp, dir.join("slots")).map_err(|e| MempoolError::io(dir, e))?;
        }
        (true, false) => {
            let _ = fs::remove_file(&body_tmp);
        }
        (false, false) => {}
    }
    Ok(())
}

fn count_live_slots(slots: &[u8], slot_cap: u32) -> u32 {
    let mut n = 0u32;
    for slot in 0..slot_cap {
        let off = SLOTS_HEADER + (slot as usize) * SLOT_REC;
        if slots[off] == SLOT_LIVE {
            n = n.saturating_add(1);
        }
    }
    n
}

fn open_or_init_meta(path: &Path) -> Result<(File, u64, u32, u32), MempoolError> {
    if path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let mut buf = [0u8; META_LEN];
        file.read_exact(&mut buf)
            .map_err(|e| MempoolError::io(path, e))?;
        if buf[0..4] != MEM_MAGIC {
            return Err(MempoolError::BadMagic);
        }
        let schema = u16::from_le_bytes([buf[4], buf[5]]);
        if schema != MEM_SCHEMA {
            return Err(MempoolError::BadSchema(schema));
        }
        let generation = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let slot_cap = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let live_count = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        if slot_cap == 0 {
            return Err(MempoolError::Corrupt("slot_cap zero"));
        }
        Ok((file, generation, slot_cap, live_count))
    } else {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let mut buf = [0u8; META_LEN];
        write_meta_bytes(&mut buf, 0, DEFAULT_SLOT_CAP, 0);
        file.write_all(&buf)
            .map_err(|e| MempoolError::io(path, e))?;
        file.flush().map_err(|e| MempoolError::io(path, e))?;
        Ok((file, 0, DEFAULT_SLOT_CAP, 0))
    }
}

fn write_meta_bytes(buf: &mut [u8; META_LEN], generation: u64, slot_cap: u32, live_count: u32) {
    buf[0..4].copy_from_slice(&MEM_MAGIC);
    buf[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    buf[16..20].copy_from_slice(&slot_cap.to_le_bytes());
    buf[20..24].copy_from_slice(&live_count.to_le_bytes());
}

fn open_or_init_slots(path: &Path, slot_cap: u32) -> Result<(File, Vec<u8>), MempoolError> {
    let need = SLOTS_HEADER + (slot_cap as usize) * SLOT_REC;
    if path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let len = file
            .metadata()
            .map_err(|e| MempoolError::io(path, e))?
            .len() as usize;
        if len < need {
            return Err(MempoolError::Corrupt("slots file short"));
        }
        let mut buf = vec![0u8; need];
        file.read_exact(&mut buf)
            .map_err(|e| MempoolError::io(path, e))?;
        if buf[0..4] != MEM_MAGIC {
            return Err(MempoolError::BadMagic);
        }
        Ok((file, buf))
    } else {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let mut buf = vec![0u8; need];
        buf[0..4].copy_from_slice(&MEM_MAGIC);
        buf[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
        buf[8..12].copy_from_slice(&slot_cap.to_le_bytes());
        file.write_all(&buf)
            .map_err(|e| MempoolError::io(path, e))?;
        file.flush().map_err(|e| MempoolError::io(path, e))?;
        Ok((file, buf))
    }
}

fn open_or_init_body(path: &Path) -> Result<(File, Vec<u8>), MempoolError> {
    let initial = BODY_HEADER + 64;
    if path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let len = file
            .metadata()
            .map_err(|e| MempoolError::io(path, e))?
            .len() as usize;
        if len < BODY_HEADER {
            return Err(MempoolError::Corrupt("body too short"));
        }
        let mut buf = vec![0u8; len];
        file.seek(SeekFrom::Start(0))
            .map_err(|e| MempoolError::io(path, e))?;
        file.read_exact(&mut buf)
            .map_err(|e| MempoolError::io(path, e))?;
        if buf[0..4] != MEM_MAGIC {
            return Err(MempoolError::BadMagic);
        }
        let logical = body_logical_len(&buf)?;
        if logical > len {
            return Err(MempoolError::Corrupt("body logical past file"));
        }
        // Spare capacity in process for appends (not on disk until persist).
        if buf.len() < initial {
            buf.resize(initial, 0);
        }
        Ok((file, buf))
    } else {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| MempoolError::io(path, e))?;
        let mut buf = vec![0u8; initial];
        buf[0..4].copy_from_slice(&MEM_MAGIC);
        buf[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
        buf[8..16].copy_from_slice(&(BODY_HEADER as u64).to_le_bytes());
        file.write_all(&buf[..BODY_HEADER])
            .map_err(|e| MempoolError::io(path, e))?;
        file.flush().map_err(|e| MempoolError::io(path, e))?;
        Ok((file, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> rbitcoin_store::testutil::TempDir {
        rbitcoin_store::testutil::TempDir::labeled("mempool").unwrap()
    }

    fn tiny_raw() -> Vec<u8> {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    #[test]
    fn empty_create_reopen_flush() {
        let dir = tmp_dir();
        {
            let mut mp = Mempool::open_or_create(&dir).expect("create");
            let m = mp.meta();
            assert_eq!(m.generation, 0);
            assert_eq!(m.live_count, 0);
            assert_eq!(m.slot_cap, DEFAULT_SLOT_CAP);
            mp.flush().expect("flush");
            assert_eq!(mp.generation(), 1);
        }
        {
            let mp = Mempool::open_or_create(&dir).expect("reopen");
            assert_eq!(mp.generation(), 1);
            assert_eq!(mp.live_count(), 0);
            assert!(mp.dir().join("meta").exists());
            assert!(mp.dir().join("slots").exists());
            assert!(mp.dir().join("tx.body").exists());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_coalesces_persist_until_threshold() {
        let dir = tmp_dir();
        {
            let mut mp = Mempool::open_or_create(&dir).unwrap();
            let tid = Txid::from_byte_array([0x22; 32]);
            mp.append_live_tx(&[0x01, 0x00, 0x00, 0x00], &tid, 1, 400)
                .unwrap();
            assert_eq!(mp.live_count(), 1);
            // Dirty but under coalesce threshold — drop without flush.
        }
        {
            let mp = Mempool::open_or_create(&dir).unwrap();
            // Unpersisted admit is not durable.
            assert_eq!(mp.live_count(), 0);
        }
        {
            let mut mp = Mempool::open_or_create(&dir).unwrap();
            for i in 0..PERSIST_COALESCE_OPS {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                id[1] = (i >> 8) as u8;
                let tid = Txid::from_byte_array(id);
                mp.append_live_tx(&[0x01, 0x00, 0x00, 0x00], &tid, 1, 400)
                    .unwrap();
            }
            assert_eq!(mp.live_count(), PERSIST_COALESCE_OPS);
            // Threshold trip persisted without flush.
        }
        {
            let mp = Mempool::open_or_create(&dir).unwrap();
            assert_eq!(mp.live_count(), PERSIST_COALESCE_OPS);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_bumps_generation_monotone() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        for i in 1..=5 {
            mp.flush().unwrap();
            assert_eq!(mp.generation(), i);
        }
        drop(mp);
        let mp = Mempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.generation(), 5);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_live_clears_reopen() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let tid = Txid::from_byte_array([0x22; 32]);
        mp.append_live_tx(&[0x01, 0x00, 0x00, 0x00], &tid, 1, 400)
            .unwrap();
        mp.flush().unwrap();
        assert_eq!(mp.live_count(), 1);
        assert_eq!(mp.abandon_live().unwrap(), 1);
        drop(mp);
        let mp = Mempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.live_count(), 0);
        assert!(mp.load_live_txs().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_mark_dead_stats_and_bad_magic() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let txid = Txid::from_byte_array([0x11; 32]);
        let slot = mp
            .append_live_tx(&[0x01, 0x00, 0x00, 0x00], &txid, 10, 400)
            .unwrap();
        assert_eq!(mp.live_count(), 1);
        let (free, live, dead) = mp.slot_stats();
        assert_eq!(live, 1);
        assert!(free + live + dead >= 1);
        // Coalesced persist: force sidecar write before reopen.
        mp.persist_if_dirty().unwrap();
        drop(mp);
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.live_count(), 1);
        let (free2, live2, _dead2) = mp.slot_stats();
        assert_eq!(live2, 1);
        assert!(free2 + live2 >= 1);
        mp.mark_slot_dead(slot).unwrap();
        assert_eq!(mp.live_count(), 0);
        assert!(mp.mark_slot_dead(u32::MAX).is_err());
        drop(mp);

        let dir2 = tmp_dir();
        {
            let _ = Mempool::open_or_create(&dir2).unwrap();
        }
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(dir2.join("meta"))
                .unwrap();
            f.write_all(b"BAD!").unwrap();
        }
        match Mempool::open_or_create(&dir2) {
            Err(MempoolError::BadMagic) => {}
            Ok(_) => panic!("expected BadMagic, got Ok"),
            Err(e) => panic!("expected BadMagic, got {e}"),
        }
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    /// Legacy tiny slot table must grow instead of returning Corrupt("slot table full").
    #[test]
    fn full_live_table_grows_not_corrupt() {
        let dir = tmp_dir();
        // Seed a 4-slot sidecar (legacy mainnet shape).
        fs::create_dir_all(&dir).unwrap();
        let tiny = 4u32;
        {
            let mut meta = [0u8; META_LEN];
            write_meta_bytes(&mut meta, 0, tiny, 0);
            fs::write(dir.join("meta"), meta).unwrap();
            let mut slots = vec![0u8; SLOTS_HEADER + (tiny as usize) * SLOT_REC];
            slots[0..4].copy_from_slice(&MEM_MAGIC);
            slots[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
            slots[8..12].copy_from_slice(&tiny.to_le_bytes());
            fs::write(dir.join("slots"), &slots).unwrap();
            let mut body = vec![0u8; BODY_HEADER];
            body[0..4].copy_from_slice(&MEM_MAGIC);
            body[4..6].copy_from_slice(&MEM_SCHEMA.to_le_bytes());
            body[8..16].copy_from_slice(&(BODY_HEADER as u64).to_le_bytes());
            fs::write(dir.join("tx.body"), &body).unwrap();
        }
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.meta().slot_cap, tiny);
        for i in 0..tiny {
            let mut tid = [0u8; 32];
            tid[0] = i as u8 + 1;
            let txid = Txid::from_byte_array(tid);
            mp.append_live_tx(&[0x01, 0x00, 0x00, 0x00], &txid, 1, 400)
                .unwrap_or_else(|e| panic!("append {i}: {e}"));
        }
        assert!(!mp.has_free_slot());
        // 5th append must grow, not Corrupt.
        let tid5 = Txid::from_byte_array([0x55; 32]);
        let r = mp.append_live_tx(&[0x01, 0x00, 0x00, 0x00], &tid5, 1, 400);
        assert!(
            r.is_ok(),
            "expected grow on full table, got {:?}",
            r.err().map(|e| e.to_string())
        );
        assert!(mp.meta().slot_cap > tiny);
        assert_eq!(mp.live_count(), tiny + 1);
        // Must not be the old Corrupt message.
        assert!(!format!("{:?}", MempoolError::Full).contains("corrupt"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_new_body_old_slots_reopens() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let raw = tiny_raw();
        let t1 = Txid::from_byte_array([0x01; 32]);
        mp.append_live_tx(&raw, &t1, 1, 400).unwrap();
        mp.flush().unwrap();
        let slots_first = fs::read(dir.join("slots")).unwrap();
        let t2 = Txid::from_byte_array([0x02; 32]);
        mp.append_live_tx(&raw, &t2, 1, 400).unwrap();
        mp.flush().unwrap();
        drop(mp);
        fs::write(dir.join("slots"), &slots_first).unwrap();
        let mp = Mempool::open_or_create(&dir).unwrap();
        let live = mp.load_live_txs().expect("new body + old slots must load");
        assert!(live.len() <= 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_slots_old_short_body_is_corrupt() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let raw = tiny_raw();
        let t1 = Txid::from_byte_array([0x01; 32]);
        mp.append_live_tx(&raw, &t1, 1, 400).unwrap();
        mp.flush().unwrap();
        let body_first = fs::read(dir.join("tx.body")).unwrap();
        let t2 = Txid::from_byte_array([0x02; 32]);
        mp.append_live_tx(&raw, &t2, 1, 400).unwrap();
        mp.flush().unwrap();
        drop(mp);
        fs::write(dir.join("tx.body"), body_first).unwrap();
        let mp = Mempool::open_or_create(&dir).unwrap();
        match mp.load_live_txs() {
            Err(MempoolError::Corrupt(m)) => {
                assert!(m.contains("live slot body range"), "{m}");
            }
            other => panic!("expected live slot body range, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_crash_after_body_rename_finishes_slots() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let raw = tiny_raw();
        let t1 = Txid::from_byte_array([0x01; 32]);
        mp.append_live_tx(&raw, &t1, 1, 400).unwrap();
        mp.flush().unwrap();
        let slots_unpacked = fs::read(dir.join("slots")).unwrap();
        mp.mark_slot_dead(0).unwrap();
        let t2 = Txid::from_byte_array([0x02; 32]);
        mp.append_live_tx(&raw, &t2, 1, 400).unwrap();
        mp.flush().unwrap();
        mp.compact().unwrap();
        let slots_packed = fs::read(dir.join("slots")).unwrap();
        drop(mp);
        fs::write(dir.join("slots"), &slots_unpacked).unwrap();
        fs::write(dir.join("slots.tmp"), &slots_packed).unwrap();
        let mp = Mempool::open_or_create(&dir).unwrap();
        assert!(!dir.join("slots.tmp").exists());
        mp.load_live_txs().expect("open must finish slots.tmp");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_both_tmps_discarded_on_open() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        mp.flush().unwrap();
        drop(mp);
        fs::copy(dir.join("tx.body"), dir.join("tx.body.tmp")).unwrap();
        fs::copy(dir.join("slots"), dir.join("slots.tmp")).unwrap();
        let mp = Mempool::open_or_create(&dir).unwrap();
        assert!(!dir.join("tx.body.tmp").exists());
        assert!(!dir.join("slots.tmp").exists());
        mp.load_live_txs().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_crash_after_slots_rename_before_meta_still_loads() {
        let dir = tmp_dir();
        let mut mp = Mempool::open_or_create(&dir).unwrap();
        let raw = tiny_raw();
        let t1 = Txid::from_byte_array([0x01; 32]);
        mp.append_live_tx(&raw, &t1, 1, 400).unwrap();
        let t2 = Txid::from_byte_array([0x02; 32]);
        mp.append_live_tx(&raw, &t2, 1, 400).unwrap();
        mp.flush().unwrap();
        assert_eq!(mp.live_count(), 2);
        let meta_before_compact = fs::read(dir.join("meta")).unwrap();
        mp.mark_slot_dead(0).unwrap();
        mp.compact().unwrap();
        drop(mp);
        fs::write(dir.join("meta"), &meta_before_compact).unwrap();
        let mp = Mempool::open_or_create(&dir).unwrap();
        let live = mp
            .load_live_txs()
            .expect("packed images + stale live_count must load");
        assert_eq!(live.len(), 1, "packed live set");
        assert_eq!(
            mp.live_count() as usize,
            live.len(),
            "open must heal live_count from slots, not stale meta"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
