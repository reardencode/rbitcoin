use crate::address_head::HeadLayout;
use crate::compact::{
    decode_script_kind_v17, encode_script_kind_v17, input_flags, output_flags, read_compact_size,
    read_uleb128, script_kind_v17_disk_used, write_compact_size, write_uleb128,
};
use crate::error::StoreError;
use crate::segmented_head::SegmentedTxHead;
use crate::var_table::VarTable;
use rbitcoin_primitives::{Fk, TableKind};
use std::path::Path;

#[cfg(test)]
thread_local! {
    static TEST_REBUILD_SEAL_BITS: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
    static TEST_REBUILD_WORKERS: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Host RAM budget per parallel `tx.head` rebuild worker (not SH pack's 2 GiB).
/// BDZ peel scratch + keys + g at the default 2²⁵ seal is ≈1 GiB peak.
pub const TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES: u64 = 1024 * 1024 * 1024;

/// Max coalesced `txout.body` pread for SH Class A collect. Sequential libc
/// pread (not TLS uring); 16 MiB matches Class A locality.
pub const SCRIPT_HASH_COLLECT_SPAN: u64 = 16 * 1024 * 1024;

pub(crate) fn parse_rebuild_seal_bits(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .map(|b| b.clamp(6, 26))
        .unwrap_or(25)
}

pub(crate) fn parse_rebuild_workers(raw: Option<&str>) -> Option<usize> {
    raw.and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(1, 256))
}

pub(crate) fn tx_head_rebuild_workers_for_free_ram(cpus: usize, free_bytes: u64) -> usize {
    crate::sorted_run::workers_for_free_ram(cpus, free_bytes, TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES)
}

/// Class A tx row (no wire blob — reconstruct from txout + inwit).
///
/// On-disk `txout.body` (schema **17**): thin LAYOUT17 meta then outputs (no spender).
/// Identity lives in [`crate::txid_body::TxidBody`]. `txid` is filled in-memory
/// from the sidefile (or caller) after decode. `input_start_fk` / `output_start_fk`
/// stay [`Fk::NULL`] in RAM (legacy split-run address unused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecord {
    pub txid: [u8; 32],
    pub version: i32,
    pub locktime: u32,
    /// Always [`Fk::NULL`] for packed Class A (legacy split-run address unused).
    pub input_start_fk: Fk,
    pub input_count: u32,
    /// Always [`Fk::NULL`] for packed Class A (legacy split-run address unused).
    pub output_start_fk: Fk,
    pub output_count: u32,
}

impl TxRecord {
    /// Upper bound for buffer estimates (schema-15 16 B; v17 typical is 3).
    pub const BODY_META_LEN: usize = 4 + 4 + 4 + 4;
    /// Full in-memory encode size (txid + body meta); used for estimates only.
    pub const ENCODED_LEN: usize = 32 + Self::BODY_META_LEN;

    /// Encode full record including txid (tests / soft buffers — **not** Class A body).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.reserve(Self::ENCODED_LEN);
        out.extend_from_slice(&self.txid);
        self.encode_body_meta_into(out);
    }

    /// Encode `txout` body meta (schema 17 thin LAYOUT17).
    pub fn encode_body_meta_into(&self, out: &mut Vec<u8>) {
        encode_body_meta_v17(self, out);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        self.encode_into(&mut out);
        out
    }

    /// Decode full record with leading txid (soft / test buffers).
    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        if buf.len() < 32 {
            return Err(StoreError::Corrupt("short tx record"));
        }
        let (mut rec, _) = Self::decode_body_meta(&buf[32..])?;
        rec.txid = buf[0..32].try_into().unwrap();
        Ok(rec)
    }

    /// Decode schema-17 thin `txout` meta. Returns `(record, bytes consumed)`.
    pub fn decode_body_meta(buf: &[u8]) -> Result<(Self, usize), StoreError> {
        decode_body_meta_v17(buf)
    }
}

/// Schema-17 thin `txout` meta flags (codec only until Class A cutover).
/// Bit 7 must be set so a v1 schema-15 prefix (`01 00 00 00`) cannot decode.
const BODY_META_V17_LAYOUT17: u8 = 1 << 7;
const BODY_META_V17_VER_1: u8 = 1 << 0;
const BODY_META_V17_VER_2: u8 = 1 << 1;
const BODY_META_V17_VER_3: u8 = 1 << 2;
const BODY_META_V17_LOCKTIME_ZERO: u8 = 1 << 3;
const BODY_META_V17_RESERVED: u8 = 0x70;
const BODY_META_V17_VER_MASK: u8 = BODY_META_V17_VER_1 | BODY_META_V17_VER_2 | BODY_META_V17_VER_3;

/// Encode schema-17 thin meta. Production still writes [`TxRecord::encode_body_meta_into`].
pub(crate) fn encode_body_meta_v17(rec: &TxRecord, out: &mut Vec<u8>) {
    let mut flags = BODY_META_V17_LAYOUT17;
    match rec.version {
        1 => flags |= BODY_META_V17_VER_1,
        2 => flags |= BODY_META_V17_VER_2,
        3 => flags |= BODY_META_V17_VER_3,
        _ => {}
    }
    if rec.locktime == 0 {
        flags |= BODY_META_V17_LOCKTIME_ZERO;
    }
    out.push(flags);
    if flags & BODY_META_V17_VER_MASK == 0 {
        out.extend_from_slice(&rec.version.to_le_bytes());
    }
    if rec.locktime != 0 {
        write_uleb128(out, u64::from(rec.locktime));
    }
    write_uleb128(out, u64::from(rec.input_count));
    write_uleb128(out, u64::from(rec.output_count));
}

/// Decode schema-17 thin meta. Rejects schema-15 16-byte prefixes (no LAYOUT17 bit).
pub(crate) fn decode_body_meta_v17(buf: &[u8]) -> Result<(TxRecord, usize), StoreError> {
    if buf.is_empty() {
        return Err(StoreError::Corrupt("short v17 txout meta"));
    }
    let flags = buf[0];
    if flags & BODY_META_V17_LAYOUT17 == 0 {
        return Err(StoreError::Corrupt(
            "legacy txout meta missing LAYOUT17 bit",
        ));
    }
    if flags & BODY_META_V17_RESERVED != 0 {
        return Err(StoreError::Corrupt("v17 txout meta reserved flags"));
    }
    let ver_bits = flags & BODY_META_V17_VER_MASK;
    if ver_bits.count_ones() > 1 {
        return Err(StoreError::Corrupt("v17 txout meta multiple VER bits"));
    }
    let mut off = 1usize;
    let version = if ver_bits == 0 {
        if buf.len() < off + 4 {
            return Err(StoreError::Corrupt("short v17 txout version"));
        }
        let v = i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        v
    } else if ver_bits == BODY_META_V17_VER_1 {
        1
    } else if ver_bits == BODY_META_V17_VER_2 {
        2
    } else {
        3
    };
    let locktime = if flags & BODY_META_V17_LOCKTIME_ZERO != 0 {
        0
    } else {
        let (v, n) = read_uleb128(&buf[off..])?;
        if v > u64::from(u32::MAX) {
            return Err(StoreError::Corrupt("v17 locktime overflow"));
        }
        off += n;
        v as u32
    };
    let (nin, n1) = read_uleb128(&buf[off..])?;
    if nin > u64::from(u32::MAX) {
        return Err(StoreError::Corrupt("v17 input_count overflow"));
    }
    off += n1;
    let (nout, n2) = read_uleb128(&buf[off..])?;
    if nout > u64::from(u32::MAX) {
        return Err(StoreError::Corrupt("v17 output_count overflow"));
    }
    off += n2;
    Ok((
        TxRecord {
            txid: [0u8; 32],
            version,
            locktime,
            input_start_fk: Fk::NULL,
            input_count: nin as u32,
            output_start_fk: Fk::NULL,
            output_count: nout as u32,
        },
        off,
    ))
}

/// Class A output (addressed via `tx.output_start_fk` run + local vout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRecord {
    pub value: i64,
    pub script: Vec<u8>,
    /// Schema v5: sole `spending_tx_fk` if !multi; else head fk into `spent.ovf`.
    pub spender_field: Fk,
    /// When true, `spender_field` is a multi-list head (not a single spending_tx_fk).
    pub multi_spender: bool,
}

impl OutputRecord {
    pub fn unspent(value: i64, script: Vec<u8>) -> Self {
        Self {
            value,
            script,
            spender_field: Fk::NULL,
            multi_spender: false,
        }
    }

    /// Encode `txout` payload (schema 17: kind nibble + template payload; no spender).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let flags_at = out.len();
        out.push(0);
        let v = if self.value < 0 {
            0u64
        } else {
            self.value as u64
        };
        write_uleb128(out, v);
        let kind = encode_script_kind_v17(&self.script, out);
        out[flags_at] = kind;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 10 + 9 + self.script.len());
        self.encode_into(&mut out);
        out
    }

    /// Decode one `txout` output; spender fields are left null (load from `spent.body`).
    pub fn decode_at(buf: &[u8]) -> Result<(Self, usize), StoreError> {
        Self::decode_at_secret(buf, None)
    }

    pub fn decode_at_secret(
        buf: &[u8],
        secret: Option<&crate::store_secret::StoreSecret>,
    ) -> Result<(Self, usize), StoreError> {
        if buf.is_empty() {
            return Err(StoreError::Corrupt("short output record"));
        }
        let flags = buf[0];
        if flags & 0xf0 != 0 {
            return Err(StoreError::Corrupt("v17 txout reserved output flags"));
        }
        let kind = flags & 0x0f;
        let mut off = 1usize;
        let (v, n) = read_uleb128(&buf[off..])?;
        off += n;
        if v > i64::MAX as u64 {
            return Err(StoreError::Corrupt("output value too large"));
        }
        let value = v as i64;
        let used = script_kind_v17_disk_used(kind, &buf[off..])?;
        let script = if let Some(sec) = secret {
            let mut payload = buf[off..off + used].to_vec();
            packed::xor_script_kind_v17_payload(kind, &mut payload, sec);
            decode_script_kind_v17(kind, &payload)?.0
        } else {
            decode_script_kind_v17(kind, &buf[off..])?.0
        };
        off += used;
        Ok((
            Self {
                value,
                script,
                spender_field: Fk::NULL,
                multi_spender: false,
            },
            off,
        ))
    }

    /// Bytes consumed by one `txout` output starting at `buf` (no script alloc).
    pub fn skip_at(buf: &[u8]) -> Result<usize, StoreError> {
        if buf.is_empty() {
            return Err(StoreError::Corrupt("short output record"));
        }
        let flags = buf[0];
        if flags & 0xf0 != 0 {
            return Err(StoreError::Corrupt("v17 txout reserved output flags"));
        }
        let kind = flags & 0x0f;
        let mut off = 1usize;
        let (_v, n) = read_uleb128(&buf[off..])?;
        off += n;
        off += script_kind_v17_disk_used(kind, &buf[off..])?;
        Ok(off)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        let (rec, used) = Self::decode_at(buf)?;
        if used != buf.len() {
            return Err(StoreError::Corrupt("output trailing bytes"));
        }
        Ok(rec)
    }

    /// Capacity upper bound for encode buffers (not byte-exact).
    pub fn encoded_len(&self) -> usize {
        1 + 10 + 9 + self.script.len()
    }

    /// Exact on-wire length matching [`Self::encode_into`].
    #[inline]
    pub fn encoded_len_exact(&self) -> usize {
        use crate::compact::{classify_script, compact_size_len, uleb128_len};
        use crate::compact::{SCRIPT_KIND_V17_OP_RETURN_PUSH, SCRIPT_KIND_V17_RAW};
        let v = if self.value < 0 {
            0u64
        } else {
            self.value as u64
        };
        let (kind, payload) = classify_script(&self.script);
        let payload_len = match kind {
            SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
                compact_size_len(payload.len() as u64) + payload.len()
            }
            _ => payload.len(),
        };
        1 + uleb128_len(v) + payload_len
    }

    /// Sole-spender slot length in `spent.body`.
    pub const SPENT_SLOT_LEN: usize = 8;
}

mod packed;
mod pending_head;
pub use packed::*;
pub(crate) use pending_head::PENDING_HEAD_CAP;

pub struct TxTable {
    /// `txout.body` — meta + outputs (hot).
    pub(crate) body: VarTable,
    /// `inwit.body` — inputs + witness (cold).
    pub(crate) inwit: VarTable,
    /// `spent.body` — 8 B × n_out sole-spender slots.
    pub(crate) spent: VarTable,
    /// Segmented fixed-bits heads + seal-time fuse8.
    pub(crate) head: SegmentedTxHead,
    /// Dense create_fk-ordered txids (schema 13+).
    pub(crate) txids: crate::txid_body::TxidBody,
    /// Datadir secret: keyed head probes + script XOR (schema 12+).
    pub(crate) secret: crate::store_secret::StoreSecret,
    /// Unflushed head inserts (write-behind). Readers see published snapshot.
    pending_head: pending_head::PendingHeadInserts,
}

/// Backend for bulk structural 8-byte spender-meta reads on `tx.body`.
///
/// Selected via global `RBITCOIN_IO` (see [`crate::io_backend`]).
/// Body peeks are never mmap'd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendMetaBackend {
    /// io_uring pread_batch 9B peeks.
    Uring,
    /// libc pread_batch (no ring).
    Pread,
}

/// Structural-meta backend from env hierarchy.
pub fn spend_meta_backend() -> SpendMetaBackend {
    match crate::io_backend::read_io_backend() {
        crate::io_backend::ReadIoBackend::Uring => SpendMetaBackend::Uring,
        crate::io_backend::ReadIoBackend::Pread => SpendMetaBackend::Pread,
    }
}

impl TxTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Self::create_with_head_layout(dir, crate::address_head::default_layout())
    }

    /// Create with an explicit head geometry (tests / recovery).
    pub fn create_with_head_layout(dir: &Path, layout: HeadLayout) -> Result<Self, StoreError> {
        Self::create_with_head_layout_inwit(dir, dir, layout)
    }

    /// Create Class A stems; `inwit` may live in a different directory.
    pub(crate) fn create_with_head_layout_inwit(
        dir: &Path,
        inwit_dir: &Path,
        layout: HeadLayout,
    ) -> Result<Self, StoreError> {
        if inwit_dir != dir {
            std::fs::create_dir_all(inwit_dir).map_err(|e| StoreError::io(inwit_dir, e))?;
        }
        let secret = crate::store_secret::StoreSecret::load_or_create(dir, true)?;
        let layout = HeadLayout::with_entry_bytes(layout.bits, 4)?;
        Ok(Self {
            body: VarTable::create(dir, "txout", TableKind::TxOut)?,
            inwit: VarTable::create(inwit_dir, "inwit", TableKind::Inwit)?,
            spent: VarTable::create(dir, "spent", TableKind::Spent)?,
            head: SegmentedTxHead::create(dir, layout)?,
            txids: crate::txid_body::TxidBody::create(dir)?,
            secret,
            pending_head: pending_head::PendingHeadInserts::new(),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Self::open_inwit(dir, dir)
    }

    /// Open Class A stems; `inwit` may live in a different directory.
    pub(crate) fn open_inwit(dir: &Path, inwit_dir: &Path) -> Result<Self, StoreError> {
        if dir.join("tx.body").exists() && !dir.join("txout.body").exists() {
            let legacy = VarTable::open(dir, "tx", TableKind::TxOut)?;
            if legacy.count() > 0 {
                return Err(StoreError::Corrupt(
                    "schema 15 refuses packed tx.body with creates; wipe datadir and redo IBD",
                ));
            }
        }
        let had_txout = dir.join("txout.body").exists();
        let had_inwit = inwit_dir.join("inwit.body").exists();
        let had_spent = dir.join("spent.body").exists();
        let body = if had_txout {
            VarTable::open(dir, "txout", TableKind::TxOut)?
        } else {
            VarTable::create(dir, "txout", TableKind::TxOut)?
        };
        if had_txout && body.count() > 0 && (!had_inwit || !had_spent) {
            return Err(StoreError::Corrupt(
                "schema 15 Class A missing inwit/spent for existing txout creates; wipe + IBD \
                 (or --datadir-cold if inwit is on a cold volume)",
            ));
        }
        if inwit_dir != dir {
            std::fs::create_dir_all(inwit_dir).map_err(|e| StoreError::io(inwit_dir, e))?;
        }
        let inwit = if had_inwit {
            VarTable::open(inwit_dir, "inwit", TableKind::Inwit)?
        } else {
            VarTable::create(inwit_dir, "inwit", TableKind::Inwit)?
        };
        let spent = if had_spent {
            VarTable::open(dir, "spent", TableKind::Spent)?
        } else {
            VarTable::create(dir, "spent", TableKind::Spent)?
        };
        let txids = if dir.join("txid.body").exists() {
            crate::txid_body::TxidBody::open(dir)?
        } else {
            crate::txid_body::TxidBody::create(dir)?
        };
        let n_bodies = body.count();
        let n_txids = txids.count();
        let n_inwit = inwit.count();
        let n_spent = spent.count();
        if n_txids != n_bodies || n_inwit != n_bodies || n_spent != n_bodies {
            let n = n_bodies.min(n_txids).min(n_inwit).min(n_spent);
            rbitcoin_log::warn!(
                "store: Class A count skew txout={n_bodies} inwit={n_inwit} spent={n_spent} \
                 txid.body={n_txids} — truncating to {n}"
            );
            if n_bodies > n {
                body.truncate_to_count(n)?;
            }
            if n_inwit > n {
                inwit.truncate_to_count(n)?;
            }
            if n_spent > n {
                spent.truncate_to_count(n)?;
            }
            if n_txids > n {
                txids.truncate_to_count(n)?;
            }
            if body.count() != txids.count()
                || body.count() != inwit.count()
                || body.count() != spent.count()
            {
                return Err(StoreError::Corrupt(
                    "Class A stem counts still mismatch after repair (reindex required)",
                ));
            }
        }
        let n_bodies = body.count();
        let mut need_rebuild = false;
        let head = if !crate::segmented_head::head_meta_exists(dir) {
            need_rebuild = n_bodies > 0;
            if need_rebuild {
                rbitcoin_log::info!(
                    "store: tx.head meta missing with {n_bodies} Class A bodies — rebuild segmented head"
                );
            }
            // Wipe legacy mono head if present so create does not refuse after wipe intent.
            let mono = dir.join("tx.head");
            if mono.is_file() {
                let _ = std::fs::remove_file(&mono);
            }
            SegmentedTxHead::create(dir, crate::address_head::default_layout())?
        } else {
            match SegmentedTxHead::open(dir) {
                Ok(h) => {
                    let covered = h.last_inserted_fk();
                    if covered > n_bodies {
                        // Torn Class A truncate: stale head entries past the
                        // bodies would fail a later seal — rebuild instead.
                        rbitcoin_log::warn!(
                            "store: tx.head leads Class A covered={covered} n={n_bodies} \
                             — wipe + rebuild"
                        );
                        drop(h);
                        crate::segmented_head::wipe_segmented_head_files(dir);
                        need_rebuild = n_bodies > 0;
                        SegmentedTxHead::create(dir, crate::address_head::default_layout())?
                    } else {
                        if n_bodies > 0 && h.occupied() == 0 {
                            need_rebuild = true;
                        }
                        h
                    }
                }
                Err(e) => {
                    if n_bodies > 0 {
                        rbitcoin_log::warn!(
                            "store: segmented tx.head unreadable ({e}) with {n_bodies} Class A \
                             bodies — recreate + rebuild"
                        );
                        crate::segmented_head::wipe_segmented_head_files(dir);
                        need_rebuild = true;
                        SegmentedTxHead::create(dir, crate::address_head::default_layout())?
                    } else {
                        return Err(e);
                    }
                }
            }
        };
        let secret = crate::store_secret::StoreSecret::load_or_create(dir, true)?;
        let t = Self {
            body,
            inwit,
            spent,
            head,
            txids,
            secret,
            pending_head: pending_head::PendingHeadInserts::new(),
        };
        if need_rebuild {
            let bits = t.head_bits();
            let slots = t.head_slots();
            rbitcoin_log::info!(
                "store: tx.head rebuild begin n={n_bodies} bits={bits} slots={slots} \
                 seal_bits={} workers={} free_GiB={} (segmented)",
                Self::rebuild_seal_bits(),
                Self::rebuild_workers(),
                crate::free_gib_label(),
            );
            let inserted = t.rebuild_head_from_bodies(|done, total, ins| {
                if done == total || done % 1_000_000 == 0 {
                    rbitcoin_log::info!(
                        "store: tx.head rebuild progress {done}/{total} inserted={ins}"
                    );
                }
            })?;
            t.head.flush()?;
            rbitcoin_log::info!(
                "store: tx.head rebuild complete inserted={inserted} bodies={} bits={} segs={}",
                t.count(),
                t.head_bits(),
                t.head.segment_count()
            );
        } else {
            // Crash before write-behind drain: head occupancy lags Class A.
            let n = t.count();
            let covered = t.head.last_inserted_fk();
            if covered < n {
                rbitcoin_log::info!(
                    "store: tx.head lags Class A covered={covered} n={n} — backfill tail"
                );
                t.backfill_head_from(covered.saturating_add(1))?;
                t.head.flush()?;
            }
            t.rebuild_unsealed_fuse_keys()?;
            t.head.seal_unsealed_nontail()?;
            // Soft-migrate sealed fuse8 v1 (xorf/bincode) → v2 without wiping head.
            t.rewrite_legacy_sealed_fuses()?;
        }
        Ok(t)
    }

    /// Rewrite sealed `.fuse8` files that opened as always-probe (legacy v1).
    ///
    /// Rebuilds fuse keys from Class A `txid.body` for each stale sealed segment and
    /// installs a durable v2 payload. Head OA tables are left intact.
    fn rewrite_legacy_sealed_fuses(&self) -> Result<(), StoreError> {
        let queue = self.head.sealed_fuse_rewrite_queue();
        if queue.is_empty() {
            return Ok(());
        }
        rbitcoin_log::warn!(
            "store: rewriting {} sealed tx.head fuse8 file(s) to v2 (format migration; \
             head data kept)",
            queue.len()
        );
        for (file_id, first_fk, count) in queue {
            if count == 0 {
                continue;
            }
            let last_fk = first_fk.saturating_add(count).saturating_sub(1);
            let n_body = self.count();
            if first_fk == 0 || first_fk > n_body || last_fk > n_body {
                rbitcoin_log::warn!(
                    "store: skip fuse rewrite file_id={file_id} first_fk={first_fk} \
                     count={count} body={n_body} (range past Class A)"
                );
                continue;
            }
            let txids = self.body_txid_range(first_fk, last_fk)?;
            if txids.len() as u64 != count {
                return Err(StoreError::Corrupt(
                    "tx.head fuse rewrite: body range count mismatch",
                ));
            }
            let mut keys: Vec<u64> = txids
                .iter()
                .map(|txid| crate::fuse8_filter::fuse_key_from_mixed(&self.secret.mix_txid(txid)))
                .collect();
            keys.sort_unstable();
            keys.dedup();
            let fuse = crate::fuse8_filter::SealedFuse8::build(&keys)?;
            let path = self.head.fuse_path_for_file_id(file_id);
            fuse.write_to(&path)?;
            self.head.install_sealed_fuse(file_id, fuse)?;
            rbitcoin_log::info!(
                "store: tx.head fuse rewritten v2 file_id={file_id} first_fk={first_fk} \
                 count={count} unique_keys={}",
                keys.len()
            );
        }
        Ok(())
    }

    /// Rebuild fuse keys for every unsealed segment from Class A (crash/restart).
    fn rebuild_unsealed_fuse_keys(&self) -> Result<(), StoreError> {
        let n_body = self.count();
        for (file_id, first_fk, count) in self.head.unsealed_ranges() {
            if count == 0 {
                continue;
            }
            let last_fk = first_fk.saturating_add(count).saturating_sub(1);
            if first_fk == 0 || first_fk > n_body || last_fk > n_body {
                rbitcoin_log::warn!(
                    "store: skip unsealed fuse rebuild file_id={file_id} first={first_fk} \
                     count={count} body={n_body}; head may lead truncated Class A"
                );
                continue;
            }
            let txids = self.body_txid_range(first_fk, last_fk)?;
            if txids.len() as u64 != count {
                return Err(StoreError::Corrupt(
                    "tx.head unsealed body range count mismatch",
                ));
            }
            let keys: Vec<u64> = txids
                .iter()
                .map(|txid| crate::fuse8_filter::fuse_key_from_mixed(&self.secret.mix_txid(txid)))
                .collect();
            self.head.replace_open_keys_for(file_id, keys)?;
            rbitcoin_log::info!(
                "store: tx.head unsealed fuse keys rebuilt file_id={file_id} \
                 first_fk={first_fk} count={count}"
            );
        }
        Ok(())
    }

    pub fn count(&self) -> u64 {
        self.body.count()
    }

    /// Current `tx.body` logical length (including file header).
    pub fn body_logical_len(&self) -> u64 {
        self.body.body_logical_len()
    }

    /// Best-effort: drop `tx.body` page-cache for a written range (archive far lead).
    pub fn advise_body_dont_need(&self, offset: u64, len: u64) {
        self.body.advise_body_dont_need(offset, len);
    }

    /// Absolute `(offset, len)` of packed body for `fk`.
    pub fn body_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.body.record_range(fk)
    }

    /// One sequential `tx.body` pread of `[offset, offset+len)`.
    pub fn with_body_span<R>(
        &self,
        offset: u64,
        len: u64,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut buf = Vec::new();
        self.with_body_span_into(offset, len, &mut buf, f)
    }

    pub fn with_body_span_into<R>(
        &self,
        offset: u64,
        len: u64,
        buf: &mut Vec<u8>,
        f: impl FnOnce(&[u8]) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        self.body.with_bytes_at_into(offset, len, buf, f)
    }

    /// Contiguous Class A body `(offset, len)` for create_fks `first..=last`.
    pub fn body_ranges(&self, first: u64, last: u64) -> Result<Vec<(u64, u64)>, StoreError> {
        self.body.record_ranges(first, last)
    }

    /// P2TR outs from a packed body slice (stack XOR; no `OutputRecord` heap).
    pub fn packed_p2tr_from_raw(
        &self,
        raw: &[u8],
    ) -> Result<Vec<(u32, [u8; 32], u64)>, StoreError> {
        scan_packed_p2tr_outs(raw, Some(&self.secret))
    }

    /// Meta + input prevouts only (no script/witness allocation, no outputs).
    ///
    /// Used by load: discover parents without full parse into RAM.
    pub fn get_meta_and_prevouts(&self, fk: Fk) -> Result<(TxRecord, Vec<(Fk, u32)>), StoreError> {
        let mut tx = self.get(fk)?;
        let inwit = self.inwit.get_raw(fk)?;
        let prevs = scan_inwit_prevouts(&inwit, tx.input_count)?;
        tx.txid = self.txids.get(fk)?;
        Ok((tx, prevs))
    }

    pub fn reserve_append(&self, body_bytes: u64, n_records: u64) -> Result<(), StoreError> {
        self.body.reserve_append(body_bytes, n_records)
    }

    pub fn get(&self, fk: Fk) -> Result<TxRecord, StoreError> {
        let raw = self.body.get_raw(fk)?;
        let (mut tx, _, _, _) =
            decode_packed_tx_with_spender_rels_secret(&raw, Some(&self.secret))?;
        tx.txid = self.txids.get(fk)?;
        Ok(tx)
    }

    /// Read create identity from **`txid.body`** (schema 13+).
    ///
    /// Thin I/O: one 32-byte sidefile pread — no idx / body.
    pub fn body_txid(&self, fk: Fk) -> Result<[u8; 32], StoreError> {
        use std::time::Instant;
        let t = Instant::now();
        let id = self.txids.get(fk)?;
        crate::head_resolve_stats::add_body(t.elapsed().as_nanos() as u64);
        crate::head_resolve_stats::add_body_lookups(1);
        Ok(id)
    }

    /// Bulk consecutive create txids `first..=last` (1-based) from `txid.body`.
    pub fn body_txid_range(&self, first: u64, last: u64) -> Result<Vec<[u8; 32]>, StoreError> {
        let out = self.txids.get_range(first, last)?;
        crate::head_resolve_stats::add_body_lookups(out.len() as u64);
        Ok(out)
    }

    /// Access dense identity sidefile (tests / resolve machines).
    pub fn txid_sidefile(&self) -> &crate::txid_body::TxidBody {
        &self.txids
    }

    /// Primary head probe slot for `txid` (sort key for locality-friendly batches).
    #[inline]
    pub fn head_primary_slot(&self, txid: &[u8; 32]) -> u64 {
        let bits = self.head.bits();
        crate::address_head::probe_index(txid, 0, bits)
    }

    /// Probe segmented address head and verify body **txid only**.
    ///
    /// Open segment first, then sealed newest→oldest (fuse-gated). Body-check
    /// order prefers deeper probe slots (newest BIP30-shaped create).
    pub fn get_fk_by_txid(&self, txid: &[u8; 32]) -> Result<Option<Fk>, StoreError> {
        use std::time::Instant;
        let mixed = self.secret.mix_txid(txid);
        let t_probe = Instant::now();
        let cands = self.head.probe_candidates(&mixed)?;
        crate::head_resolve_stats::add_probe(t_probe.elapsed().as_nanos() as u64);
        crate::head_resolve_stats::add_keys(1);
        crate::head_resolve_stats::add_cands(cands.len() as u64);
        for (i, fk) in cands.into_iter().enumerate() {
            if self.body_txid(fk)? == *txid {
                crate::head_resolve_stats::add_hit_rank((i as u64).saturating_add(1));
                return Ok(Some(fk));
            }
            crate::head_resolve_stats::add_miss_peeks(1);
        }
        Ok(None)
    }

    /// Mix txid for head probe keys (tests / diagnostics).
    pub fn mix_txid_for_head(&self, txid: &[u8; 32]) -> [u8; 32] {
        self.secret.mix_txid(txid)
    }

    /// Store secret (script XOR / head mix).
    pub fn store_secret(&self) -> &crate::store_secret::StoreSecret {
        &self.secret
    }

    /// Batch head resolve for plan stamp: **txid → (create_fk, body_range)**.
    ///
    /// Short-circuit of the Shape A denserels machine
    /// ([`crate::head_resolve_denserels::resolve_fk_and_range_batch`]): probe →
    /// **per-key depth-first** sidefile identity (io_uring when available) → idx
    /// range on hit. **No** cross-key depth-round batching. Prep denserels-loads
    /// via known `body_range` (skip `tx.idx`).
    ///
    /// BIP30: deepest matching create wins (probe order deepest-first).
    /// Timers: [`crate::head_resolve_stats`] probe / idx / body.
    pub fn get_fk_by_txid_batch(
        &self,
        txids: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], Option<(Fk, (u64, u64))>)>, StoreError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        crate::head_resolve_denserels::resolve_fk_and_range_batch(self, txids)
    }

    /// Sparse outs by known `txout` body ranges (prep pin after plan stamp).
    ///
    /// Each job is `(create_fk, body_range, known_txid, need_vouts)`.
    /// - **Skips `tx.idx`** (range known).
    /// - **`known_txid`**: RAM identity (plan reverse map / residency); not sidefile.
    /// - **`need_vouts`**: sorted unique; empty = all outs. Only those scripts are
    ///   allocated (N2.1). Full body is still pread (layout denserels).
    ///
    /// Returns `(rows, body_ns, decode_ns)` where each row is
    /// `Some((tx, live (vout,out), sparse denserels (vout,rel)))` (N2.0 timers).
    pub fn get_outs_by_range_batch(
        &self,
        items: &[(Fk, (u64, u64), [u8; 32], Vec<u32>)],
    ) -> Result<
        (
            Vec<Option<(TxRecord, Vec<(u32, OutputRecord)>, Vec<(u32, u32)>)>>,
            u64, /* body_ns */
            u64, /* decode_ns */
        ),
        StoreError,
    > {
        use crate::idx_body_pipeline::{run_idx_body_pipeline_backend, BodyMode, IdxBodyJob};
        use std::time::Instant;
        if items.is_empty() {
            return Ok((Vec::new(), 0, 0));
        }
        let mut jobs: Vec<IdxBodyJob> = items
            .iter()
            .map(|(fk, range, _txid, _need)| IdxBodyJob::new(fk.get().unwrap_or(0), Some(*range)))
            .collect();
        let t_body = Instant::now();
        run_idx_body_pipeline_backend(
            &self.body,
            &mut jobs,
            BodyMode::Outs,
            crate::io_backend::read_io_backend(),
        )?;
        let body_ns = t_body.elapsed().as_nanos() as u64;
        let secret = self.store_secret();
        let t_dec = Instant::now();
        let mut out = Vec::with_capacity(jobs.len());
        for (job, (fk, _range, known_txid, need)) in jobs.into_iter().zip(items.iter()) {
            let _ = fk;
            if !job.ok || job.body.is_empty() {
                out.push(None);
                continue;
            }
            match decode_packed_tx_need_outs_with_spender_rels_secret(&job.body, need, Some(secret))
            {
                Ok((mut tx, live, sparse)) => {
                    tx.txid = *known_txid;
                    out.push(Some((tx, live, sparse)));
                }
                Err(StoreError::NotFound) | Err(StoreError::Corrupt(_)) => out.push(None),
                Err(e) => return Err(e),
            }
        }
        let decode_ns = t_dec.elapsed().as_nanos() as u64;
        Ok((out, body_ns, decode_ns))
    }

    /// Bulk `body_range` for many fks (confirm load / reconstruct).
    ///
    /// **Sorted** walk of `tx.idx` via [`VarTable::record_range_batch`] (FdOnly
    /// pread segments) —
    /// same modality as archive head-resolve idx (not scatter io_uring/pread).
    pub fn body_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        self.body.record_range_batch(fks)
    }

    /// `spent.body` range for one create.
    pub fn spent_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.spent.record_range(fk)
    }

    /// `spent.body` ranges (same fk order as [`Self::body_range_batch`]).
    pub fn spent_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        self.spent.record_range_batch(fks)
    }

    /// Annotate spends at known absolute spender-meta offsets (confirm write).
    ///
    /// Prefer io_uring RMW ([`crate::spend_annotate_uring`]): pread 8 B → decide
    /// sole / multi / promote → pwrite; `spent.ovf` appends run **inline** on
    /// the read completion. Same abs serialized. Fallback: serial `pwrite` RMW.
    ///
    /// Returns edges that still need a full cold path (OOB abs / deferred).
    /// Multi-list cases are handled here when uring/`pwrite` succeed (not returned).
    pub fn put_spend_batch_by_abs_meta(
        &self,
        spenders: &crate::spender_table::SpenderTable,
        abs_edges: &[(u64, Fk, u32, Fk)],
    ) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
        const META_LEN: u64 = OutputRecord::SPENT_SLOT_LEN as u64;
        if abs_edges.is_empty() {
            return Ok(Vec::new());
        }
        for &(_, _, _, sfk) in abs_edges {
            if sfk.is_null() {
                return Err(StoreError::InvalidFk);
            }
        }
        if crate::bulk_io::io_uring_enabled() {
            match crate::spend_annotate_uring::put_spend_batch_by_abs_meta_uring(
                self, spenders, abs_edges,
            ) {
                Ok(cold) => return Ok(cold),
                Err(e) => {
                    rbitcoin_log::debug!(
                        "store: spend annotate uring unavailable ({e}); pwrite fallback"
                    );
                }
            }
        }

        let body_pub = self.spent.body_published_len();
        let mut cold: Vec<(Fk, u32, Fk)> = Vec::new();
        for &(abs, create_fk, vout, spend_fk) in abs_edges {
            if abs.saturating_add(META_LEN) > body_pub {
                cold.push((create_fk, vout, spend_fk));
                continue;
            }
            let cur = self.spent.with_bytes_at(abs, META_LEN, |raw| {
                let (flags, field) = decode_spent_slot_v17(raw)?;
                Ok((field, flags))
            });
            let Ok((field, flags)) = cur else {
                cold.push((create_fk, vout, spend_fk));
                continue;
            };
            let multi = flags & output_flags::MULTI_SPENDER != 0;
            let (new_multi, new_field) = if !multi && field.is_null() {
                (false, spend_fk)
            } else if !multi && field == spend_fk {
                continue;
            } else if !multi {
                let e1 = spenders.append(field, Fk::NULL)?;
                let e2 = spenders.append(spend_fk, e1)?;
                (true, e2)
            } else {
                let e = spenders.append(spend_fk, field)?;
                (true, e)
            };
            let new_flags = if new_multi {
                flags | output_flags::MULTI_SPENDER
            } else {
                flags & !output_flags::MULTI_SPENDER
            };
            let meta = encode_spent_slot_v17(new_flags, new_field)?;
            if let Err(_) = self.spent.write_body_abs(abs, &meta) {
                cold.push((create_fk, vout, spend_fk));
            }
        }
        Ok(cold)
    }

    /// Bulk 8-byte spender meta reads at absolute `spent.body` file offsets.
    ///
    /// Returns `(spender_field, flags)` — multi = `flags & MULTI_SPENDER`.
    /// Backend from [`spend_meta_backend`] / global `RBITCOIN_IO` /
    /// global `RBITCOIN_IO` (`uring` \| `pread`). Out-of-range / short → `None`.
    pub fn get_spender_meta_at_abs_batch(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<(Fk, u8)>>, StoreError> {
        self.get_spender_meta_at_abs_batch_backend(abs_offs, spend_meta_backend())
    }

    /// Like [`Self::get_spender_meta_at_abs_batch`] with an explicit backend.
    pub fn get_spender_meta_at_abs_batch_backend(
        &self,
        abs_offs: &[u64],
        backend: SpendMetaBackend,
    ) -> Result<Vec<Option<(Fk, u8)>>, StoreError> {
        if abs_offs.is_empty() {
            return Ok(Vec::new());
        }
        match backend {
            SpendMetaBackend::Uring => match self.get_spender_meta_at_abs_batch_uring(abs_offs) {
                Ok(v) => Ok(v),
                Err(e) => {
                    rbitcoin_log::debug!(
                        "store: structural meta uring failed ({e}); pread fallback"
                    );
                    self.get_spender_meta_at_abs_batch_pread(abs_offs)
                }
            },
            SpendMetaBackend::Pread => self.get_spender_meta_at_abs_batch_pread(abs_offs),
        }
    }

    /// io_uring pread_batch 9B peeks.
    fn get_spender_meta_at_abs_batch_uring(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<(Fk, u8)>>, StoreError> {
        self.get_spender_meta_at_abs_batch_fd(abs_offs, crate::io_backend::ReadIoBackend::Uring)
    }

    /// libc pread_batch 9B peeks (no ring).
    fn get_spender_meta_at_abs_batch_pread(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<(Fk, u8)>>, StoreError> {
        self.get_spender_meta_at_abs_batch_fd(abs_offs, crate::io_backend::ReadIoBackend::Pread)
    }

    fn get_spender_meta_at_abs_batch_fd(
        &self,
        abs_offs: &[u64],
        backend: crate::io_backend::ReadIoBackend,
    ) -> Result<Vec<Option<(Fk, u8)>>, StoreError> {
        use crate::bulk_io::{self, ReadOp};
        const META_LEN: usize = OutputRecord::SPENT_SLOT_LEN;
        let body_fd = self.spent.body_read_fd();
        let body_pub = self.spent.body_published_len();
        let body_path = self.spent.body_file_path();

        let mut bufs: Vec<[u8; META_LEN]> = vec![[0u8; META_LEN]; abs_offs.len()];
        let mut submitted: Vec<usize> = Vec::with_capacity(abs_offs.len());
        for (i, &off) in abs_offs.iter().enumerate() {
            let end = off.saturating_add(META_LEN as u64);
            if end > body_pub {
                continue;
            }
            submitted.push(i);
        }
        if submitted.is_empty() {
            return Ok(vec![None; abs_offs.len()]);
        }

        // SAFETY: each bufs[i] is distinct; submitted indices unique.
        let mut ops: Vec<ReadOp<'_>> = Vec::with_capacity(submitted.len());
        for &i in &submitted {
            let ptr = bufs[i].as_mut_ptr();
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, META_LEN) };
            ops.push(ReadOp {
                fd: body_fd,
                offset: abs_offs[i],
                buf: slice,
                result: i32::MIN,
            });
        }
        bulk_io::pread_batch_backend(&mut ops, backend);

        let mut out: Vec<Option<(Fk, u8)>> = vec![None; abs_offs.len()];
        for (ro, &i) in ops.iter().zip(submitted.iter()) {
            if ro.result < 0 {
                return Err(StoreError::io(
                    body_path,
                    std::io::Error::from_raw_os_error(-ro.result),
                ));
            }
            if ro.result as usize != META_LEN {
                continue;
            }
            let b = &bufs[i];
            let Ok((flags, field)) = decode_spent_slot_v17(b) else {
                continue;
            };
            out[i] = Some((field, flags));
        }
        Ok(out)
    }

    /// Pure-write spend annotate using structural-known meta (no body pread).
    ///
    /// `known[i]` is `(field, flags)` at `abs_edges[i].0` from structural spentness.
    /// Backend: `pwrite` or `uring`. Returns cold edges
    /// (OOB) — production callers must treat non-empty as hard error.
    pub fn put_spend_batch_by_abs_meta_known(
        &self,
        spenders: &crate::spender_table::SpenderTable,
        abs_edges: &[(u64, Fk, u32, Fk)],
        known: &[(Fk, u8)],
        backend: crate::spend_annotate_uring::SpendAnnBackend,
    ) -> Result<Vec<(Fk, u32, Fk)>, StoreError> {
        crate::spend_annotate_uring::put_spend_batch_by_abs_meta_known(
            self, spenders, abs_edges, known, backend,
        )
    }

    /// Read multi + spender_field for create tx output (packed Class A body).
    pub fn get_output_spender_meta(
        &self,
        create_tx_fk: Fk,
        vout: u32,
    ) -> Result<(bool, Fk), StoreError> {
        let (off, len) = self.spent.record_range(create_tx_fk)?;
        self.get_output_spender_meta_at(off, len, vout)
    }

    /// Like [`Self::get_output_spender_meta`] but uses a cache-held body range (no idx).
    pub fn get_output_spender_meta_at(
        &self,
        body_off: u64,
        body_len: u64,
        vout: u32,
    ) -> Result<(bool, Fk), StoreError> {
        let abs = spent_abs(body_off, vout);
        let end = body_off.saturating_add(body_len);
        if abs.saturating_add(OutputRecord::SPENT_SLOT_LEN as u64) > end {
            return Err(StoreError::Corrupt("spent slot OOB"));
        }
        self.spent
            .with_bytes_at(abs, OutputRecord::SPENT_SLOT_LEN as u64, |raw| {
                let (flags, field) = decode_spent_slot_v17(raw)?;
                Ok((flags & output_flags::MULTI_SPENDER != 0, field))
            })
    }

    /// One packed body walk: spender meta for many vouts (ascending).
    ///
    /// Returns `(vout, multi, field)` for each found vout. Missing vouts omitted.
    pub fn get_output_spender_metas_at(
        &self,
        body_off: u64,
        body_len: u64,
        vouts: &[u32],
    ) -> Result<Vec<(u32, bool, Fk)>, StoreError> {
        if vouts.is_empty() {
            return Ok(Vec::new());
        }
        let slot = OutputRecord::SPENT_SLOT_LEN;
        self.spent.with_bytes_at(body_off, body_len, |raw| {
            let mut out = Vec::with_capacity(vouts.len());
            for &v in vouts {
                let start = (v as usize).saturating_mul(slot);
                let end = start.saturating_add(slot);
                if end > raw.len() {
                    continue;
                }
                let Ok((flags, field)) = decode_spent_slot_v17(&raw[start..end]) else {
                    continue;
                };
                out.push((v, flags & output_flags::MULTI_SPENDER != 0, field));
            }
            Ok(out)
        })
    }

    /// Patch multi + spender_field on create tx output (packed Class A body).
    pub fn set_output_spender_meta(
        &self,
        create_tx_fk: Fk,
        vout: u32,
        multi: bool,
        field: Fk,
    ) -> Result<(), StoreError> {
        let (off, len) = self.spent.record_range(create_tx_fk)?;
        self.set_output_spender_meta_at(off, len, vout, multi, field)
    }

    /// Patch spender meta using a cache-held body range (no idx read on the hot path).
    pub fn set_output_spender_meta_at(
        &self,
        body_off: u64,
        body_len: u64,
        vout: u32,
        multi: bool,
        field: Fk,
    ) -> Result<(), StoreError> {
        let abs = spent_abs(body_off, vout);
        let end = body_off.saturating_add(body_len);
        if abs.saturating_add(OutputRecord::SPENT_SLOT_LEN as u64) > end {
            return Err(StoreError::Corrupt("spent slot OOB"));
        }
        let flags = if multi {
            output_flags::MULTI_SPENDER
        } else {
            0
        };
        let slot = encode_spent_slot_v17(flags, field)?;
        self.spent.write_body_abs(abs, &slot)?;
        Ok(())
    }

    /// Full tx: `txout` + `inwit` zip.
    pub fn get_full(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>), StoreError> {
        let raw = self.body.get_raw(fk)?;
        let (mut tx, _ins, outs, _) =
            decode_packed_tx_with_spender_rels_secret(&raw, Some(&self.secret))?;
        let inwit = self.inwit.get_raw(fk)?;
        let ins = decode_inwit_secret(&inwit, tx.input_count, Some(&self.secret))?;
        tx.txid = self.txids.get(fk)?;
        Ok((tx, ins, outs))
    }

    /// Meta + outputs only (one body IO; skips input materialization).
    pub fn get_meta_and_outputs(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<OutputRecord>), StoreError> {
        let raw = self.body.get_raw(fk)?;
        let (mut tx, outs, _) =
            decode_packed_tx_outs_with_spender_rels_secret(&raw, Some(&self.secret))?;
        tx.txid = self.txids.get(fk)?;
        Ok((tx, outs))
    }

    /// Walk create_fks `first..=last` from a coalesced `txout.body` span (one idx
    /// walk, sequential body pread), yielding `script_hash` per out.
    ///
    /// Body IO is libc `pread` (not the TLS uring ring). Collect is nCPU workers
    /// each doing one large sequential span — not a completion machine. The ring
    /// 5 s wait is a lost-CQE fence for 4 KiB lookup/g-page waves.
    pub fn for_each_script_hashes_in_fk_span(
        &self,
        first: u64,
        last: u64,
        mut f: impl FnMut(Fk, [u8; 32]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if last < first {
            return Ok(());
        }
        let ranges = match self.body.record_ranges(first, last) {
            Ok(r) => r,
            Err(StoreError::NotFound) | Err(StoreError::InvalidFk) => return Ok(()),
            Err(e) => return Err(e),
        };
        const MAX_SPAN: u64 = SCRIPT_HASH_COLLECT_SPAN;
        let mut i = 0usize;
        while i < ranges.len() {
            let span_lo = ranges[i].0;
            let mut span_hi = ranges[i].0.saturating_add(ranges[i].1);
            let mut j = i + 1;
            while j < ranges.len() {
                let (off, len) = ranges[j];
                if off != span_hi || span_hi.saturating_sub(span_lo).saturating_add(len) > MAX_SPAN
                {
                    break;
                }
                span_hi = span_hi.saturating_add(len);
                j += 1;
            }
            let span_len = span_hi.saturating_sub(span_lo);
            self.body.with_bytes_at_pread(span_lo, span_len, |buf| {
                for k in i..j {
                    let (off, len) = ranges[k];
                    let rel = (off.saturating_sub(span_lo)) as usize;
                    let end = rel.saturating_add(len as usize);
                    if end > buf.len() {
                        return Err(StoreError::Corrupt("txout span short for fk range"));
                    }
                    let fk = Fk(first.saturating_add(k as u64));
                    visit_packed_script_hashes(&buf[rel..end], Some(&self.secret), |sh| f(fk, sh))?;
                }
                Ok(())
            })?;
            i = j;
        }
        Ok(())
    }

    /// Append Class A rows: `txout` + `inwit` + zero `spent` + `txid.body`.
    pub fn put_full_batch_indexed(
        &self,
        items: &[(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)],
        index: bool,
    ) -> Result<Vec<Fk>, StoreError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let est_out: usize = items
            .iter()
            .map(|(_tx, _ins, outs)| {
                16 + TxRecord::BODY_META_LEN + outs.iter().map(|o| o.encoded_len()).sum::<usize>()
            })
            .sum();
        let est_inwit: usize = items
            .iter()
            .map(|(_tx, ins, _outs)| 16 + ins.iter().map(|i| i.encoded_len()).sum::<usize>())
            .sum();
        let est_spent: usize = items
            .iter()
            .map(|(_tx, _ins, outs)| 16 + outs.len() * OutputRecord::SPENT_SLOT_LEN)
            .sum();
        let base = self.body.count();
        if self.inwit.count() != base || self.spent.count() != base {
            return Err(StoreError::Corrupt("Class A stem count mismatch on append"));
        }
        let fks = self.append_stems_one_wave(
            items.len(),
            est_out,
            est_inwit,
            est_spent,
            |i, buf| {
                let (tx, ins, outs) = &items[i];
                encode_packed_tx_with_secret(tx, ins, outs, buf, Some(&self.secret));
            },
            |i, buf| encode_inwit_with_secret(&items[i].1, buf, Some(&self.secret)),
            |i, buf| encode_spent_zeros(items[i].2.len() as u32, buf),
        )?;
        let ids: Vec<[u8; 32]> = items.iter().map(|(tx, _, _)| tx.txid).collect();
        self.txids.append_batch(base, &ids)?;
        if index {
            let heads: Vec<([u8; 32], Fk)> = items
                .iter()
                .zip(fks.iter())
                .map(|((tx, _, _), fk)| (tx.txid, *fk))
                .collect();
            self.head_insert_many(&heads)?;
        }
        Ok(fks)
    }

    /// Like [`Self::put_full_batch_indexed`], but outs live in a shared pin Arc
    /// (tx + outs + denserels). Encode borrows pin fields — no outs deep clone.
    pub fn put_full_batch_from_pins(
        &self,
        items: &[(
            std::sync::Arc<(TxRecord, Vec<OutputRecord>)>,
            Vec<InputRecord>,
        )],
        index: bool,
    ) -> Result<Vec<Fk>, StoreError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let est_out: usize = items
            .iter()
            .map(|(pin, _ins)| {
                let (_tx, outs) = pin.as_ref();
                16 + TxRecord::BODY_META_LEN + outs.iter().map(|o| o.encoded_len()).sum::<usize>()
            })
            .sum();
        let est_inwit: usize = items
            .iter()
            .map(|(_pin, ins)| 16 + ins.iter().map(|i| i.encoded_len()).sum::<usize>())
            .sum();
        let est_spent: usize = items
            .iter()
            .map(|(pin, _ins)| {
                let (_tx, outs) = pin.as_ref();
                16 + outs.len() * OutputRecord::SPENT_SLOT_LEN
            })
            .sum();
        let base = self.body.count();
        if self.inwit.count() != base || self.spent.count() != base {
            return Err(StoreError::Corrupt("Class A stem count mismatch on append"));
        }
        let fks = self.append_stems_one_wave(
            items.len(),
            est_out,
            est_inwit,
            est_spent,
            |i, buf| {
                let (pin, ins) = &items[i];
                let (tx, outs) = pin.as_ref();
                encode_packed_tx_with_secret(tx, ins, outs, buf, Some(&self.secret));
            },
            |i, buf| encode_inwit_with_secret(&items[i].1, buf, Some(&self.secret)),
            |i, buf| {
                let (_tx, outs) = items[i].0.as_ref();
                encode_spent_zeros(outs.len() as u32, buf);
            },
        )?;
        let ids: Vec<[u8; 32]> = items.iter().map(|(pin, _)| pin.0.txid).collect();
        self.txids.append_batch(base, &ids)?;
        if index {
            let heads: Vec<([u8; 32], Fk)> = items
                .iter()
                .zip(fks.iter())
                .map(|((pin, _), fk)| (pin.0.txid, *fk))
                .collect();
            self.head_insert_many(&heads)?;
        }
        Ok(fks)
    }

    /// Encode and write `txout` + `inwit` + `spent` bodies as one pwrite wave.
    ///
    /// Order is still body → idx → HWM per stem. Not the spend-annotate machine.
    fn append_stems_one_wave(
        &self,
        n: usize,
        est_out: usize,
        est_inwit: usize,
        est_spent: usize,
        encode_out: impl FnMut(usize, &mut Vec<u8>),
        encode_in: impl FnMut(usize, &mut Vec<u8>),
        encode_sp: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<Vec<Fk>, StoreError> {
        let Some(p_out) = self.body.prepare_batch_encode(n, est_out, encode_out)? else {
            return Ok(Vec::new());
        };
        let Some(p_in) = self.inwit.prepare_batch_encode(n, est_inwit, encode_in)? else {
            return Err(StoreError::Corrupt("Class A inwit prepare empty"));
        };
        let Some(p_sp) = self.spent.prepare_batch_encode(n, est_spent, encode_sp)? else {
            return Err(StoreError::Corrupt("Class A spent prepare empty"));
        };
        crate::var_table::write_prepared_bodies_one_wave(&[
            (&self.body, &p_out),
            (&self.inwit, &p_in),
            (&self.spent, &p_sp),
        ])?;
        let fks = self.body.finish_prepared(p_out)?;
        let fks_in = self.inwit.finish_prepared(p_in)?;
        let fks_sp = self.spent.finish_prepared(p_sp)?;
        if fks != fks_in || fks != fks_sp {
            return Err(StoreError::Corrupt(
                "Class A append fk mismatch across stems",
            ));
        }
        Ok(fks)
    }

    pub fn get_by_txid(&self, txid: &[u8; 32]) -> Result<Option<(Fk, TxRecord)>, StoreError> {
        let Some(fk) = self.get_fk_by_txid(txid)? else {
            return Ok(None);
        };
        Ok(Some((fk, self.get(fk)?)))
    }

    /// All Class A fks whose body txid equals `txid` (BIP30: more than one).
    ///
    /// Order is **newest-first** (deepest probe match first), matching
    /// [`Self::get_fk_by_txid`].
    pub fn get_all_by_txid(&self, txid: &[u8; 32]) -> Result<Vec<(Fk, TxRecord)>, StoreError> {
        let mut out: Vec<(Fk, TxRecord)> = Vec::new();
        let mixed = self.secret.mix_txid(txid);
        // probe_candidates already open-first then sealed newest→oldest, deep-first within.
        let cands = self.head.probe_candidates(&mixed)?;
        for fk in cands {
            if out.iter().any(|(have, _)| have.0 == fk.0) {
                continue;
            }
            if self.body_txid(fk)? != *txid {
                continue;
            }
            out.push((fk, self.get(fk)?));
        }
        Ok(out)
    }

    /// Annotate many vouts on one create. `spent_off`/`spent_len` are the
    /// `spent.body` range (not `txout`).
    pub fn put_spends_on_create_at(
        &self,
        spenders: &crate::spender_table::SpenderTable,
        spent_off: u64,
        spent_len: u64,
        edges: &[(u32, Fk)],
    ) -> Result<(), StoreError> {
        if edges.is_empty() {
            return Ok(());
        }
        for &(_, sfk) in edges {
            if sfk.is_null() {
                return Err(StoreError::InvalidFk);
            }
        }
        for &(vout, spend_fk) in edges {
            let (multi, field) = self.get_output_spender_meta_at(spent_off, spent_len, vout)?;
            let (new_multi, new_field) = if !multi && field.is_null() {
                (false, spend_fk)
            } else if !multi && field == spend_fk {
                continue;
            } else if !multi {
                let e1 = spenders.append(field, Fk::NULL)?;
                let e2 = spenders.append(spend_fk, e1)?;
                (true, e2)
            } else {
                let e = spenders.append(spend_fk, field)?;
                (true, e)
            };
            self.set_output_spender_meta_at(spent_off, spent_len, vout, new_multi, new_field)?;
        }
        Ok(())
    }

    /// Ensure durable `tx.head` maps `txid → fk` for every Class A body.
    ///
    /// Idempotent: skips fks already present in the probe chain. Prefer
    /// [`Self::rebuild_head_from_bodies`] after a deliberate empty recreate
    /// (skips presence probes — much faster for a full rebuild).
    ///
    /// `on_progress(done_bodies, total_bodies, inserted)` is invoked periodically.
    pub fn backfill_head(&self, on_progress: impl FnMut(u64, u64, u64)) -> Result<u64, StoreError> {
        if self.head.occupied() == 0 && self.count() > 0 {
            return self.rebuild_head_from_bodies(on_progress);
        }
        self.backfill_head_inner(/* force_all */ false, on_progress)
    }

    /// Insert `txid.body` → `tx.head` for creates `first_fk..=count` (no presence probe).
    pub fn backfill_head_from(&self, first_fk: u64) -> Result<u64, StoreError> {
        let n = self.count();
        if first_fk == 0 || first_fk > n {
            return Ok(0);
        }
        let mut inserted = 0u64;
        let read_batch: u64 = 65_536;
        let write_chunk: usize = 65_536;
        let mut batch: Vec<([u8; 32], Fk)> = Vec::with_capacity(write_chunk);
        let mut cur = first_fk;
        while cur <= n {
            let end = (cur + read_batch - 1).min(n);
            let txids = self.body_txid_range(cur, end)?;
            for (i, txid) in txids.into_iter().enumerate() {
                batch.push((txid, Fk(cur + i as u64)));
                if batch.len() >= write_chunk {
                    inserted += batch.len() as u64;
                    self.head_insert_many(&batch)?;
                    batch.clear();
                }
            }
            cur = end + 1;
        }
        if !batch.is_empty() {
            inserted += batch.len() as u64;
            self.head_insert_many(&batch)?;
        }
        Ok(inserted)
    }

    /// Rebuild sealed MPHF+fuse8 from Class A (`txid.body`), no historical OA.
    ///
    /// Range width is [`Self::rebuild_seal_keys`] (default 2²⁵). Remainder is
    /// sealed too; an empty open tail is created for later inserts.
    /// Workers: [`Self::rebuild_workers`] (min of CPUs, free RAM / 1 GiB,
    /// and range count). Distinct from SH pack's 2 GiB cap.
    pub fn rebuild_head_from_bodies(
        &self,
        mut on_progress: impl FnMut(u64, u64, u64),
    ) -> Result<u64, StoreError> {
        let n = self.count();
        if n == 0 {
            return Ok(0);
        }
        let ranges = self.plan_head_rebuild_ranges()?;
        let n_jobs = ranges.len();
        let workers = Self::rebuild_workers().min(n_jobs).max(1);
        let seal_bits = Self::rebuild_seal_bits();
        rbitcoin_log::info!(
            "store: tx.head rebuild mphf n={n} seal_bits={seal_bits} ranges={n_jobs} \
             workers={workers} free_GiB={}",
            crate::free_gib_label()
        );
        let jobs: Vec<(u32, u64, u64)> = ranges
            .into_iter()
            .enumerate()
            .map(|(i, (first, count))| (i as u32, first, count))
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<
            std::sync::Mutex<
                Option<Result<(u64, u64, crate::segmented_head::SealPublish), StoreError>>,
            >,
        > = (0..n_jobs).map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let jobs = &jobs;
                let next = &next;
                let slots = &slots;
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= n_jobs {
                        break;
                    }
                    let (file_id, first, count) = jobs[i];
                    let r = self.seal_rebuild_range(file_id, first, count);
                    *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
                });
            }
        });
        let mut sealed = Vec::with_capacity(n_jobs);
        let mut inserted = 0u64;
        for cell in slots {
            let (first, count, pubd) = cell
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .ok_or(StoreError::Corrupt("tx.head rebuild worker silent"))??;
            inserted += count;
            on_progress(first.saturating_add(count).saturating_sub(1), n, inserted);
            sealed.push((first, count, pubd));
        }
        self.head
            .install_rebuild_sealed(sealed, n.saturating_add(1))?;
        Ok(inserted)
    }

    fn seal_rebuild_range(
        &self,
        file_id: u32,
        first: u64,
        count: u64,
    ) -> Result<(u64, u64, crate::segmented_head::SealPublish), StoreError> {
        if count == 0 {
            return Err(StoreError::Corrupt("tx.head rebuild empty range"));
        }
        const CHUNK: u64 = 65_536;
        let last = first.saturating_add(count).saturating_sub(1);
        let mut pairs = Vec::with_capacity(count as usize);
        let mut rel = 1u32;
        let mut cur = first;
        while cur <= last {
            let end = (cur + CHUNK - 1).min(last);
            let txids = self.body_txid_range(cur, end)?;
            for txid in txids {
                pairs.push((
                    crate::fuse8_filter::fuse_key_from_mixed(&self.secret.mix_txid(&txid)),
                    rel,
                ));
                rel = rel.saturating_add(1);
            }
            cur = end + 1;
        }
        if pairs.len() as u64 != count {
            return Err(StoreError::Corrupt("tx.head rebuild pair count"));
        }
        let pubd = self.head.write_sealed_pairs(file_id, first, count, pairs)?;
        Ok((first, count, pubd))
    }

    /// Parallel wipe-rebuild workers. Env `RBITCOIN_TX_HEAD_REBUILD_WORKERS`;
    /// default min(CPUs, free RAM / 1 GiB). Not SH pack's 2 GiB cap.
    pub fn rebuild_workers() -> usize {
        #[cfg(test)]
        if let Some(n) = TEST_REBUILD_WORKERS.with(std::cell::Cell::get) {
            return n;
        }
        if let Some(n) = parse_rebuild_workers(
            std::env::var("RBITCOIN_TX_HEAD_REBUILD_WORKERS")
                .ok()
                .as_deref(),
        ) {
            return n;
        }
        tx_head_rebuild_workers_for_free_ram(
            crate::sorted_run::logical_cpus(),
            crate::host_mem_available_bytes().unwrap_or(0),
        )
    }

    /// Hold this thread's rebuild worker count for `f`.
    #[cfg(test)]
    pub fn test_with_rebuild_workers<R>(n: usize, f: impl FnOnce() -> R) -> R {
        let n = n.clamp(1, 256);
        let prev = TEST_REBUILD_WORKERS.with(|c| c.replace(Some(n)));
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_REBUILD_WORKERS.with(|c| c.set(self.0));
            }
        }
        let _restore = Restore(prev);
        f()
    }

    /// Rebuild MPHF range width: `2^bits` keys. Default **25**; **26** is wider.
    ///
    /// Env `RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS`. Operator: 25 or 26. Tests may
    /// pin 6..=26 on the calling thread without mutating process env.
    pub fn rebuild_seal_bits() -> u32 {
        #[cfg(test)]
        if let Some(b) = TEST_REBUILD_SEAL_BITS.with(std::cell::Cell::get) {
            return b;
        }
        parse_rebuild_seal_bits(
            std::env::var("RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS")
                .ok()
                .as_deref(),
        )
    }

    /// Hold this thread's rebuild seal bits for `f` (does not mutate process env).
    #[cfg(test)]
    pub fn test_with_rebuild_seal_bits<R>(bits: u32, f: impl FnOnce() -> R) -> R {
        let bits = bits.clamp(6, 26);
        let prev = TEST_REBUILD_SEAL_BITS.with(|c| c.replace(Some(bits)));
        struct Restore(Option<u32>);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_REBUILD_SEAL_BITS.with(|c| c.set(self.0));
            }
        }
        let _restore = Restore(prev);
        f()
    }

    pub fn rebuild_seal_keys() -> u64 {
        1u64 << Self::rebuild_seal_bits()
    }

    /// Class A cuts for a cold MPHF rebuild (`2^bits` keys, last range short).
    ///
    /// Independent of live OA 80% load and of idx body soft-span.
    pub fn plan_head_rebuild_ranges(&self) -> Result<Vec<(u64, u64)>, StoreError> {
        let n = self.count();
        if n == 0 {
            return Ok(Vec::new());
        }
        let t = Self::rebuild_seal_keys().min(u64::from(u32::MAX));
        let mut out = Vec::new();
        let mut first = 1u64;
        while first <= n {
            let count = (n - first + 1).min(t);
            out.push((first, count));
            first += count;
        }
        Ok(out)
    }

    fn backfill_head_inner(
        &self,
        force_all: bool,
        mut on_progress: impl FnMut(u64, u64, u64),
    ) -> Result<u64, StoreError> {
        let n = self.count();
        if n == 0 {
            return Ok(0);
        }
        let mut inserted = 0u64;
        let read_batch: u64 = 65_536;
        let write_chunk: usize = 65_536;
        const PROGRESS_EVERY: u64 = 50_000;
        let mut batch: Vec<([u8; 32], Fk)> = Vec::with_capacity(write_chunk);
        let mut last_progress = 0u64;
        let mut cur = 1u64;
        while cur <= n {
            let end = (cur + read_batch - 1).min(n);
            let txids = self.body_txid_range(cur, end)?;
            for (i, txid) in txids.into_iter().enumerate() {
                let id = cur + i as u64;
                let fk = Fk(id);
                if !force_all {
                    let mixed = self.secret.mix_txid(&txid);
                    let present = self
                        .head
                        .probe_candidates(&mixed)?
                        .iter()
                        .any(|c| c.0 == fk.0);
                    if present {
                        if id - last_progress >= PROGRESS_EVERY || id == n {
                            on_progress(id, n, inserted + batch.len() as u64);
                            last_progress = id;
                        }
                        continue;
                    }
                }
                batch.push((txid, fk));
                if batch.len() >= write_chunk {
                    inserted += batch.len() as u64;
                    self.head_insert_many(&batch)?;
                    batch.clear();
                }
                if id - last_progress >= PROGRESS_EVERY || id == n {
                    on_progress(id, n, inserted + batch.len() as u64);
                    last_progress = id;
                }
            }
            cur = end + 1;
        }
        if !batch.is_empty() {
            inserted += batch.len() as u64;
            self.head_insert_many(&batch)?;
        }
        if last_progress != n {
            on_progress(n, n, inserted);
        }
        Ok(inserted)
    }

    pub fn head_occupied(&self) -> u64 {
        self.head.occupied()
    }

    /// Per-segment first create_fk (winner-age stats).
    pub fn head_first_fks_snapshot(&self) -> Vec<u64> {
        self.head.first_fks_snapshot()
    }

    pub fn head_bits(&self) -> u32 {
        self.head.bits()
    }

    pub fn head_slots(&self) -> u64 {
        self.head.slots()
    }

    pub fn head_entry_bytes(&self) -> u8 {
        self.head.entry_bytes()
    }

    pub fn head_reserve_additional(&self, _additional: u64) -> Result<(), StoreError> {
        Ok(())
    }

    pub fn head_segment_count(&self) -> usize {
        self.head.segment_count()
    }

    /// Queue txid→fk for durable `tx.head` drain (write-local list only).
    pub fn head_note_pending(&self, entries: &[([u8; 32], Fk)]) {
        self.pending_head.note(entries);
    }

    /// Write-local drain list lookup (same-batch spend annotate before insert).
    pub fn queued_pending_fk(&self, txid: &[u8; 32]) -> Option<Fk> {
        self.pending_head.queued_fk(txid)
    }

    /// Take the drain list on the write thread (drain receives an owned Vec).
    pub fn take_pending_queued(&self) -> Vec<([u8; 32], Fk)> {
        self.pending_head.take_queued()
    }

    /// Insert a taken drain list. Leftover identity is load-owned, not here.
    pub fn head_insert_queued(&self, batch: &[([u8; 32], Fk)]) -> Result<u64, StoreError> {
        if batch.is_empty() {
            return Ok(0);
        }
        self.head_insert_many(batch)?;
        Ok(batch.len() as u64)
    }

    /// Drain the pending insert queue via page-grouped [`Self::head_insert_many`].
    pub fn head_drain_pending(&self) -> Result<u64, StoreError> {
        let batch = self.take_pending_queued();
        self.head_insert_queued(&batch)
    }

    pub fn pending_head_len(&self) -> usize {
        self.pending_head.len()
    }

    pub fn pending_head_is_full(&self) -> bool {
        self.pending_head.len() >= PENDING_HEAD_CAP
    }

    /// Bound write-behind: drain if the queue is at/over [`PENDING_HEAD_CAP`].
    pub fn head_drain_pending_if_full(&self) -> Result<(), StoreError> {
        if self.pending_head_is_full() {
            self.head_drain_pending()?;
        }
        Ok(())
    }

    /// Insert txid→fk into the segmented head (mixes keys; may seal/roll).
    ///
    /// Rolls the open OA at 80% slots (`max_keys`). Idx body soft-span does
    /// not cut `tx.head` shards.
    pub fn head_insert_many(&self, entries: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut mixed: Vec<([u8; 32], Fk)> = entries
            .iter()
            .map(|(txid, fk)| (self.secret.mix_txid(txid), *fk))
            .collect();
        self.head.insert_many(&mut mixed)
    }

    pub fn head_resize_size_snapshot(&self) -> HeadResizeSizeSnapshot {
        let n = self.count();
        let bits = self.head.bits();
        let slots = self.head.slots();
        let occ = self.head.occupied();
        let body_bytes = slots.saturating_mul(u64::from(self.head.entry_bytes()));
        HeadResizeSizeSnapshot {
            class_a_n: n,
            primary_bits: bits,
            primary_slots: slots,
            primary_entry_b: self.head.entry_bytes(),
            primary_occupied: occ,
            primary_body_bytes: body_bytes,
            segment_count: self.head.segment_count() as u64,
            sealed_segments: self.head.sealed_segment_count() as u64,
            fuse8_bytes: self.head.sealed_fuse_resident_bytes(),
            mphf_g_bytes: self.head.sealed_mphf_g_resident_bytes(),
            open_keys_bytes: self.head.open_keys_resident_bytes(),
            class_c_l2_bytes: 0,
        }
    }

    /// Flush segmented heads only.
    pub fn flush_head(&self) -> Result<(), StoreError> {
        self.head.flush()
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        self.inwit.flush()?;
        self.spent.flush()?;
        self.head.flush()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        self.inwit.flush_async()?;
        self.spent.flush_async()?;
        self.head.flush_async()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
