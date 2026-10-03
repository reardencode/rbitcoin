use crate::address_head::HeadLayout;
use crate::compact::{
    amount_exp_mantissa, decode_output_amount, decode_script_kind_v17, encode_script_kind_v17,
    input_flags, output_flags, script_kind_v17_disk_used, split_output_flags,
};
use crate::error::StoreError;
use crate::hashhead::HeadOpenOpts;
use crate::segmented_head::SegmentedTxHead;
use crate::var_table::VarTable;
use rbitcoin_primitives::{read_uleb128, write_uleb128, Fk, TableKind};
use std::path::Path;
use std::sync::Arc;

/// Host RAM budget per parallel `tx.head` rebuild worker (not SH extract's 1.5 GiB).
/// BDZ peel scratch + keys + g at the default 2²⁵ seal is ≈1 GiB peak.
pub const TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES: u64 = 1024 * 1024 * 1024;

/// Max coalesced `txout.body` pread for SH Class A collect. Sequential libc
/// pread (not TLS uring); 16 MiB matches Class A locality.
pub const SCRIPT_HASH_COLLECT_SPAN: u64 = 16 * 1024 * 1024;

/// Stamp short-circuit row: txid → optional (create fk, txout body range).
pub(crate) type TxidFkRange = ([u8; 32], Option<(Fk, crate::create_loc::CreateLocPair)>);
/// Sparse denserels-load row: meta + live outs + spender rels.
pub(crate) type SparseOutsRow = (TxRecord, Vec<(u32, OutputRecord)>, Vec<(u32, u32)>);
/// Full Class A body: meta + inputs + outputs.
pub(crate) type PackedTx = (TxRecord, Vec<InputRecord>, Vec<OutputRecord>);
/// Packed txout decode including spender rels.
pub(crate) type PackedTxRels = (TxRecord, Vec<InputRecord>, Vec<OutputRecord>, Vec<u32>);
/// Prep denserels job: create fk, body range, known txid, loc n_out, need-vouts.
pub(crate) type OutsByRangeJob = (Fk, (u64, u64), [u8; 32], u32, Vec<u32>);
/// `(rows, body_ns, decode_ns, extend_n, body_sqe_n, guess_full_n)` from [`TxTable::get_outs_by_range_batch`].
pub(crate) type OutsByRangeOut = (Vec<Option<SparseOutsRow>>, u64, u64, u64, u64, u64);
/// `spent.body` slot: spender fk + flags + vin.
pub(crate) type SpenderSlot = (Fk, u8, u32);

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

/// Class A tx row (no wire blob — reconstruct from txout + seqsigwit).
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
/// `n_in` lives on `txstat.body`; no uleb `input_count` follows locktime.
pub(crate) const BODY_META_V17_N_IN_TXSTAT: u8 = 1 << 4;
const BODY_META_V17_RESERVED: u8 = 0x60;
const BODY_META_V17_VER_MASK: u8 = BODY_META_V17_VER_1 | BODY_META_V17_VER_2 | BODY_META_V17_VER_3;

/// Encode schema-17 thin meta. New writes set [`BODY_META_V17_N_IN_TXSTAT`]
/// and omit the `input_count` uleb (`n_in` is on `txstat.body`).
pub(crate) fn encode_body_meta_v17(rec: &TxRecord, out: &mut Vec<u8>) {
    let mut flags = BODY_META_V17_LAYOUT17 | BODY_META_V17_N_IN_TXSTAT;
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
    let input_count = if flags & BODY_META_V17_N_IN_TXSTAT != 0 {
        0
    } else {
        let (nin, n1) = read_uleb128(&buf[off..])?;
        if nin > u64::from(u32::MAX) {
            return Err(StoreError::Corrupt("v17 input_count overflow"));
        }
        off += n1;
        nin as u32
    };
    Ok((
        TxRecord {
            txid: [0u8; 32],
            version,
            locktime,
            input_start_fk: Fk::NULL,
            input_count,
            output_start_fk: Fk::NULL,
            output_count: 0,
        },
        off,
    ))
}

fn edges_from_seqsigwit_payload(raw: &[u8]) -> Result<Vec<crate::input::InputEdge>, StoreError> {
    let mut off = 0usize;
    let mut edges = Vec::new();
    while off < raw.len() && raw[off..].iter().any(|&b| b != 0) {
        let (create_fk, prev_index, used) = InputRecord::decode_prevout_at(&raw[off..])?;
        off += used;
        if create_fk.is_null() {
            edges.push(crate::input::InputEdge::coinbase());
        } else {
            edges.push(crate::input::InputEdge {
                parent: create_fk,
                vout: prev_index,
            });
        }
    }
    Ok(edges)
}

/// How many creates to locate per input-backfill step.
const INPUT_BACKFILL_FKS: u64 = 16_384;
/// Coalesced `seqsigwit.body` pread. Same bound as [`SCRIPT_HASH_COLLECT_SPAN`].
const INPUT_BACKFILL_SPAN: u64 = SCRIPT_HASH_COLLECT_SPAN;

fn backfill_chunk_end(id: u64, n: u64) -> u64 {
    (id + INPUT_BACKFILL_FKS - 1).min(n)
}

fn backfill_progress_due(end: u64, id: u64) -> bool {
    end / 1_000_000 != (id - 1) / 1_000_000
}

fn unstamped_tail(n_bodies: u64, have: u64) -> u64 {
    n_bodies.saturating_sub(have)
}

#[derive(Debug, PartialEq, Eq)]
enum InputOpenTail {
    Backfill { from: u64 },
    Unstamped { n: u64 },
    Ahead,
    Ready,
}

fn input_open_tail(input_count: u64, n_bodies: u64, seq_count: u64) -> InputOpenTail {
    if n_bodies > 0 && seq_count == n_bodies && input_count < n_bodies {
        InputOpenTail::Backfill {
            from: input_count + 1,
        }
    } else if input_count < n_bodies {
        InputOpenTail::Unstamped {
            n: unstamped_tail(n_bodies, input_count),
        }
    } else if input_count > n_bodies {
        InputOpenTail::Ahead
    } else {
        InputOpenTail::Ready
    }
}

type ReadSeqsigwitSpan<'a> = &'a mut dyn FnMut(u64, u64, &mut Vec<u8>) -> Result<(), StoreError>;

fn edges_from_seqsigwit_ranges(
    read: ReadSeqsigwitSpan<'_>,
    ranges: &[Option<(u64, u64)>],
    span_max: u64,
    buf: &mut Vec<u8>,
) -> Result<Vec<Vec<crate::input::InputEdge>>, StoreError> {
    let mut out = Vec::with_capacity(ranges.len());
    let mut i = 0usize;
    while i < ranges.len() {
        let Some((start, first_len)) = ranges[i] else {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit range missing during input backfill",
            ));
        };
        let mut end = start.saturating_add(first_len);
        let mut j = i + 1;
        if first_len <= span_max {
            while j < ranges.len() {
                let Some((off, len)) = ranges[j] else {
                    return Err(StoreError::Corrupt(
                        "invariant: seqsigwit range missing during input backfill",
                    ));
                };
                if off != end {
                    break;
                }
                let next = end.saturating_add(len);
                if next - start > span_max {
                    break;
                }
                end = next;
                j += 1;
            }
        }
        if j <= i {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit span did not advance",
            ));
        }
        if end > start {
            read(start, end - start, buf)?;
        } else {
            buf.clear();
        }
        if buf.len() as u64 != end.saturating_sub(start) {
            return Err(StoreError::Corrupt(
                "invariant: seqsigwit span short during input backfill",
            ));
        }
        for slot in &ranges[i..j] {
            let (off, len) = slot.ok_or(StoreError::Corrupt(
                "invariant: seqsigwit range missing during input backfill",
            ))?;
            let rel = usize::try_from(off - start)
                .map_err(|_| StoreError::Corrupt("invariant: seqsigwit span offset"))?;
            let n = usize::try_from(len)
                .map_err(|_| StoreError::Corrupt("invariant: seqsigwit span length"))?;
            let at = rel + n;
            if at > buf.len() {
                return Err(StoreError::Corrupt(
                    "invariant: seqsigwit span short during input backfill",
                ));
            }
            out.push(edges_from_seqsigwit_payload(&buf[rel..at])?);
        }
        i = j;
    }
    Ok(out)
}

fn input_edges(ins: &[InputRecord]) -> Vec<crate::input::InputEdge> {
    ins.iter()
        .map(|inp| {
            if inp.is_coinbase() {
                crate::input::InputEdge::coinbase()
            } else {
                crate::input::InputEdge {
                    parent: inp.create_fk,
                    vout: inp.prev_index,
                }
            }
        })
        .collect()
}

fn txstat_placeholder() -> crate::txstat::TxStatRow {
    crate::txstat::TxStatRow {
        fee_sat: 0,
        base: 0,
        wit_extra: 0,
    }
}

fn txstat_placeholders(
    items: &[(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)],
) -> Vec<crate::txstat::TxStatRow> {
    items.iter().map(|_| txstat_placeholder()).collect()
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

    /// Encode `txout` payload (kind nibble + amount exp + ULEB mantissa; no spender).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let _ = self.try_encode_into(out);
    }

    pub fn try_encode_into(&self, out: &mut Vec<u8>) -> Result<(), StoreError> {
        if self.value < 0 {
            return Err(StoreError::Corrupt("txout amount negative"));
        }
        Self::encode_unspent_into(self.value, &self.script, out);
        Ok(())
    }

    /// Same bytes as [`Self::encode_into`] for an unspent `(value, script)` pair.
    ///
    /// `value` must be ≥ 0 (Class A append rejects negatives first).
    pub fn encode_unspent_into(value: i64, script: &[u8], out: &mut Vec<u8>) {
        let flags_at = out.len();
        out.push(0);
        let (exp, mantissa) = amount_exp_mantissa(value as u64);
        write_uleb128(out, mantissa);
        let kind = encode_script_kind_v17(script, out);
        out[flags_at] = kind | (exp << 4);
    }

    /// Capacity upper bound matching [`Self::encoded_len`] without an [`OutputRecord`].
    #[inline]
    pub fn encoded_len_for_script(script_len: usize) -> usize {
        1 + 10 + 9 + script_len
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
        let (kind, exp) = split_output_flags(flags)?;
        let mut off = 1usize;
        let (v, n) = decode_output_amount(exp, &buf[off..])?;
        off += n;
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
        let (kind, exp) = split_output_flags(flags)?;
        let mut off = 1usize;
        let (_v, n) = decode_output_amount(exp, &buf[off..])?;
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
        use crate::compact::{
            classify_script, SCRIPT_KIND_V17_OP_RETURN_PUSH, SCRIPT_KIND_V17_RAW,
        };
        use rbitcoin_primitives::{compact_size_len, uleb128_len};
        if self.value < 0 {
            return 0;
        }
        let (_exp, mantissa) = amount_exp_mantissa(self.value as u64);
        let (kind, payload) = classify_script(&self.script);
        let payload_len = match kind {
            SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
                compact_size_len(payload.len() as u64) + payload.len()
            }
            _ => payload.len(),
        };
        1 + uleb128_len(mantissa) + payload_len
    }

    /// Sole-spender slot length in `spent.body`.
    pub const SPENT_SLOT_LEN: usize = 8;
}

mod packed;
mod pending_head;
pub use packed::*;
pub(crate) use pending_head::PENDING_HEAD_CAP;

fn span_rec(span: &[u8], span_off: u64, rec_off: u64, rec_len: u64) -> Result<&[u8], StoreError> {
    let start = rec_off
        .checked_sub(span_off)
        .ok_or(StoreError::Corrupt("span record before span"))?;
    let start = usize::try_from(start).map_err(|_| StoreError::Corrupt("span start"))?;
    let len = usize::try_from(rec_len).map_err(|_| StoreError::Corrupt("span rec len"))?;
    let end = start
        .checked_add(len)
        .ok_or(StoreError::Corrupt("span rec end"))?;
    span.get(start..end)
        .ok_or(StoreError::Corrupt("span record OOB"))
}

fn pread_two_spans(
    a: &VarTable,
    a_off: u64,
    a_len: u64,
    b: &VarTable,
    b_off: u64,
    b_len: u64,
    parallel: bool,
) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    if !parallel {
        return Ok((a.pread_span(a_off, a_len)?, b.pread_span(b_off, b_len)?));
    }
    std::thread::scope(|s| {
        let ta = s.spawn(|| a.pread_span(a_off, a_len));
        let tb = s.spawn(|| b.pread_span(b_off, b_len));
        let va = ta
            .join()
            .unwrap_or(Err(StoreError::Corrupt("txout span thread")))?;
        let vb = tb
            .join()
            .unwrap_or(Err(StoreError::Corrupt("seqsigwit span thread")))?;
        Ok((va, vb))
    })
}

pub struct TxTable {
    /// `txout.body` — meta + outputs (hot).
    pub(crate) body: VarTable,
    /// `seqsigwit.body` — inputs + witness (cold).
    pub(crate) seqsigwit: VarTable,
    /// `spent.body` — 8 B × n_out sole-spender slots.
    pub(crate) spent: VarTable,
    pub(crate) create_loc: crate::create_loc::CreateLoc,
    pub(crate) seqsigwit_loc: crate::delta_loc::DeltaLoc,
    /// Segmented fixed-bits heads + seal-time fuse8.
    /// Segmented fixed-bits heads + seal-time fuse8.
    pub(crate) head: SegmentedTxHead,
    /// Dense create_fk-ordered txids (schema 13+).
    pub(crate) txids: crate::txid_body::TxidBody,
    /// Dense create_fk-ordered confirm-time econ (schema 25).
    pub(crate) txstat: crate::txstat::TxStat,
    /// Spender → parent edges (`input.loc` / `input.body`).
    pub(crate) input: crate::input::Input,
    /// Datadir secret: keyed head probes + script XOR (schema 12+).
    pub(crate) secret: crate::store_secret::StoreSecret,
    /// Unflushed head inserts (write-behind). Readers see published snapshot.
    pending_head: pending_head::PendingHeadInserts,
    rebuild_seal_bits: u32,
    rebuild_workers: usize,
    prune_seqsigwit_mode: std::sync::atomic::AtomicBool,
}

/// Structural-meta backend from env hierarchy.
pub fn spend_meta_backend() -> crate::io_backend::ReadIoBackend {
    crate::io_backend::read_io_backend()
}

fn class_a_body_occupied(dir: &Path, stem: &str) -> bool {
    let p = dir.join(format!("{stem}.body"));
    match std::fs::metadata(&p) {
        Ok(m) => m.len() > crate::file::FILE_HEADER_LEN as u64,
        Err(_) => false,
    }
}

fn refuse_schema15_packed_tx_body(dir: &Path) -> Result<(), StoreError> {
    if dir.join("tx.body").exists()
        && !dir.join("txout.body").exists()
        && class_a_body_occupied(dir, "tx")
    {
        return Err(StoreError::Corrupt(
            "schema 15 refuses packed tx.body with creates; wipe datadir and redo IBD",
        ));
    }
    Ok(())
}

fn open_or_create_create_loc(dir: &Path) -> Result<crate::create_loc::CreateLoc, StoreError> {
    if dir.join("create.loc").exists() {
        crate::create_loc::CreateLoc::open(dir)
    } else if class_a_body_occupied(dir, "txout") {
        Err(StoreError::Corrupt("invariant: create.loc missing"))
    } else {
        crate::create_loc::CreateLoc::create(dir)
    }
}

fn open_or_create_seqsigwit_loc(
    seqsigwit_dir: &Path,
) -> Result<crate::delta_loc::DeltaLoc, StoreError> {
    if seqsigwit_dir.join("seqsigwit.loc").exists() {
        crate::delta_loc::DeltaLoc::open(seqsigwit_dir, "seqsigwit")
    } else if class_a_body_occupied(seqsigwit_dir, "seqsigwit") {
        Err(StoreError::Corrupt("invariant: seqsigwit.loc missing"))
    } else {
        crate::delta_loc::DeltaLoc::create(seqsigwit_dir, "seqsigwit")
    }
}

fn unlink_leftover_class_a_idx(dir: &Path) -> Result<(), StoreError> {
    for stem in ["txout", "spent", "seqsigwit"] {
        let p = dir.join(format!("{stem}.idx"));
        if p.exists() {
            if p.is_dir() {
                std::fs::remove_dir_all(&p).map_err(|e| StoreError::io(&p, e))?;
            } else {
                std::fs::remove_file(&p).map_err(|e| StoreError::io(&p, e))?;
            }
            rbitcoin_log::warn!(
                "store: dropping leftover {stem}.idx (schema 22 uses create.loc / seqsigwit.loc)"
            );
        }
    }
    Ok(())
}

struct ClassASkewStems<'a> {
    create_loc: &'a crate::create_loc::CreateLoc,
    seqsigwit_loc: &'a crate::delta_loc::DeltaLoc,
    body: &'a VarTable,
    spent: &'a VarTable,
    seqsigwit: &'a VarTable,
    txids: &'a crate::txid_body::TxidBody,
    txstat: &'a crate::txstat::TxStat,
    input: &'a crate::input::Input,
}

fn class_a_skew_target_count(
    n_loc: u64,
    n_txids: u64,
    n_seqsigwit_loc: u64,
    prune_seqsigwit_mode: bool,
) -> Option<u64> {
    if n_txids == n_loc && (prune_seqsigwit_mode || n_seqsigwit_loc == n_loc) {
        return None;
    }
    Some(if prune_seqsigwit_mode {
        n_loc.min(n_txids)
    } else {
        n_loc.min(n_txids).min(n_seqsigwit_loc)
    })
}

fn class_a_skew_stem_ends(
    stems: &ClassASkewStems<'_>,
    n: u64,
    prune_seqsigwit_mode: bool,
) -> Result<(u64, u64, u64), StoreError> {
    if n == 0 {
        let h = crate::file::FILE_HEADER_LEN as u64;
        return Ok((h, h, h));
    }
    let p = stems
        .create_loc
        .range_batch(&[Fk(n)])?
        .into_iter()
        .next()
        .flatten()
        .ok_or(StoreError::Corrupt("invariant: loc range for truncate"))?;
    let in_end = if prune_seqsigwit_mode {
        crate::file::FILE_HEADER_LEN as u64
    } else {
        let ir = stems
            .seqsigwit_loc
            .range_batch(&[Fk(n)])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::Corrupt(
                "invariant: seqsigwit.loc range for truncate",
            ))?;
        ir.0.saturating_add(ir.1)
    };
    Ok((
        p.txout.0.saturating_add(p.txout.1),
        p.spent.0.saturating_add(p.spent.1),
        in_end,
    ))
}

fn class_a_skew_apply_truncate(
    stems: &ClassASkewStems<'_>,
    n: u64,
    n_txids: u64,
    tx_end: u64,
    sp_end: u64,
    in_end: u64,
    prune_seqsigwit_mode: bool,
) -> Result<(), StoreError> {
    stems.create_loc.truncate_to_count(n)?;
    if !prune_seqsigwit_mode {
        stems.seqsigwit_loc.truncate_to_count(n)?;
    }
    stems.body.truncate_body_to(n, tx_end)?;
    stems.spent.truncate_body_to(n, sp_end)?;
    if !prune_seqsigwit_mode {
        stems.seqsigwit.truncate_body_to(n, in_end)?;
    }
    if n_txids > n {
        stems.txids.truncate_to_count(n)?;
    }
    if stems.txstat.count() > n {
        stems.txstat.truncate_to_count(n)?;
    }
    if stems.input.count() > n {
        stems.input.truncate_to_count(n)?;
    }
    Ok(())
}

fn class_a_skew_assert_aligned(
    stems: &ClassASkewStems<'_>,
    prune_seqsigwit_mode: bool,
) -> Result<(), StoreError> {
    if stems.body.count() != stems.txids.count() || stems.create_loc.count() != stems.txids.count()
    {
        return Err(StoreError::Corrupt(
            "Class A stem counts still mismatch after repair (reindex required)",
        ));
    }
    if !prune_seqsigwit_mode && stems.seqsigwit_loc.count() != stems.txids.count() {
        return Err(StoreError::Corrupt(
            "Class A stem counts still mismatch after repair (reindex required)",
        ));
    }
    Ok(())
}

fn repair_class_a_count_skew(
    stems: ClassASkewStems<'_>,
    prune_seqsigwit_mode: bool,
) -> Result<(), StoreError> {
    let n_loc = stems.create_loc.count();
    let n_txids = stems.txids.count();
    let n_seqsigwit_loc = stems.seqsigwit_loc.count();
    let Some(n) = class_a_skew_target_count(n_loc, n_txids, n_seqsigwit_loc, prune_seqsigwit_mode)
    else {
        return Ok(());
    };
    rbitcoin_log::warn!(
        "store: Class A count skew loc={n_loc} seqsigwit.loc={n_seqsigwit_loc} \
         txid.body={n_txids} — truncating to {n}"
    );
    let (tx_end, sp_end, in_end) = class_a_skew_stem_ends(&stems, n, prune_seqsigwit_mode)?;
    class_a_skew_apply_truncate(
        &stems,
        n,
        n_txids,
        tx_end,
        sp_end,
        in_end,
        prune_seqsigwit_mode,
    )?;
    class_a_skew_assert_aligned(&stems, prune_seqsigwit_mode)
}

impl TxTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Self::create_with_opts(dir, HeadOpenOpts::MAINNET)
    }

    pub fn create_tiny(dir: &Path) -> Result<Self, StoreError> {
        Self::create_with_opts(dir, HeadOpenOpts::TINY)
    }

    pub fn create_with_opts(dir: &Path, opts: HeadOpenOpts) -> Result<Self, StoreError> {
        Self::create_with_head_layout_opts(
            dir,
            crate::address_head::default_layout(opts.scale),
            opts,
        )
    }

    /// Create with an explicit head geometry (tests / recovery).
    pub fn create_with_head_layout(dir: &Path, layout: HeadLayout) -> Result<Self, StoreError> {
        Self::create_with_head_layout_opts(dir, layout, HeadOpenOpts::TINY)
    }

    pub fn create_with_head_layout_opts(
        dir: &Path,
        layout: HeadLayout,
        opts: HeadOpenOpts,
    ) -> Result<Self, StoreError> {
        Self::create_with_head_layout_seqsigwit(dir, dir, layout, opts)
    }

    /// Create Class A stems; `seqsigwit` may live in a different directory.
    pub(crate) fn create_with_head_layout_seqsigwit(
        dir: &Path,
        seqsigwit_dir: &Path,
        layout: HeadLayout,
        opts: HeadOpenOpts,
    ) -> Result<Self, StoreError> {
        if seqsigwit_dir != dir {
            std::fs::create_dir_all(seqsigwit_dir).map_err(|e| StoreError::io(seqsigwit_dir, e))?;
        }
        let secret = crate::store_secret::StoreSecret::load_or_create(dir, true)?;
        let layout = HeadLayout::with_entry_bytes(layout.bits, 4)?;
        let (seal_bits, workers) = Self::resolve_open_opts(opts);
        Ok(Self {
            body: VarTable::create(dir, "txout", TableKind::TxOut)?,
            seqsigwit: VarTable::create(seqsigwit_dir, "seqsigwit", TableKind::SeqSigWit)?,
            spent: VarTable::create(dir, "spent", TableKind::Spent)?,
            create_loc: crate::create_loc::CreateLoc::create(dir)?,
            seqsigwit_loc: crate::delta_loc::DeltaLoc::create(seqsigwit_dir, "seqsigwit")?,
            head: SegmentedTxHead::create(dir, layout)?,
            txids: crate::txid_body::TxidBody::create(dir)?,
            txstat: crate::txstat::TxStat::create(seqsigwit_dir)?,
            input: crate::input::Input::create(seqsigwit_dir)?,
            secret,
            pending_head: pending_head::PendingHeadInserts::new(),
            rebuild_seal_bits: seal_bits,
            rebuild_workers: workers,
            prune_seqsigwit_mode: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn resolve_open_opts(opts: HeadOpenOpts) -> (u32, usize) {
        let seal_bits = opts
            .rebuild_seal_bits
            .map(|b| b.clamp(6, 26))
            .unwrap_or_else(|| {
                parse_rebuild_seal_bits(
                    std::env::var("RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS")
                        .ok()
                        .as_deref(),
                )
            });
        let workers = opts
            .rebuild_workers
            .map(|n| n.clamp(1, 256))
            .unwrap_or_else(|| {
                if let Some(n) = parse_rebuild_workers(
                    std::env::var("RBITCOIN_TX_HEAD_REBUILD_WORKERS")
                        .ok()
                        .as_deref(),
                ) {
                    n
                } else {
                    tx_head_rebuild_workers_for_free_ram(
                        crate::sorted_run::logical_cpus(),
                        crate::host_mem_available_bytes().unwrap_or(0),
                    )
                }
            });
        (seal_bits, workers)
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Self::open_with_opts(dir, HeadOpenOpts::MAINNET)
    }

    pub fn open_tiny(dir: &Path) -> Result<Self, StoreError> {
        Self::open_with_opts(dir, HeadOpenOpts::TINY)
    }

    pub fn open_with_opts(dir: &Path, opts: HeadOpenOpts) -> Result<Self, StoreError> {
        Self::open_seqsigwit(dir, dir, opts)
    }

    /// Open Class A stems; `seqsigwit` may live in a different directory.
    pub(crate) fn open_seqsigwit(
        dir: &Path,
        seqsigwit_dir: &Path,
        opts: HeadOpenOpts,
    ) -> Result<Self, StoreError> {
        let prune_seqsigwit_mode = false;
        crate::store::rename_legacy_inwit_files(dir)?;
        crate::store::rename_legacy_input_files(dir)?;
        crate::store::rename_legacy_inwit_files(seqsigwit_dir)?;
        crate::store::rename_legacy_input_files(seqsigwit_dir)?;
        refuse_schema15_packed_tx_body(dir)?;
        let (seal_bits, workers) = Self::resolve_open_opts(opts);
        unlink_leftover_class_a_idx(dir)?;
        if seqsigwit_dir != dir {
            unlink_leftover_class_a_idx(seqsigwit_dir)?;
            std::fs::create_dir_all(seqsigwit_dir).map_err(|e| StoreError::io(seqsigwit_dir, e))?;
        }
        let had_txout = dir.join("txout.body").exists();
        let had_seqsigwit = seqsigwit_dir.join("seqsigwit.body").exists();
        let had_spent = dir.join("spent.body").exists();
        let create_loc = open_or_create_create_loc(dir)?;
        let seqsigwit_loc = open_or_create_seqsigwit_loc(seqsigwit_dir)?;
        let loc_count = create_loc.count();
        if !prune_seqsigwit_mode && seqsigwit_loc.count() != loc_count {
            return Err(StoreError::Corrupt("invariant: seqsigwit.loc count"));
        }
        let body = if had_txout {
            VarTable::open_body_only(dir, "txout", TableKind::TxOut, loc_count)?
        } else {
            VarTable::create_body_only(dir, "txout", TableKind::TxOut)?
        };
        if had_txout && loc_count > 0 && (!had_spent || (!had_seqsigwit && !prune_seqsigwit_mode)) {
            return Err(StoreError::Corrupt(
                "schema 15 Class A missing seqsigwit/spent for existing txout creates; wipe + IBD \
                 (or --datadir-cold if seqsigwit is on a cold volume)",
            ));
        }
        let seqsigwit = if had_seqsigwit {
            let in_count = if prune_seqsigwit_mode {
                seqsigwit_loc.count()
            } else {
                loc_count
            };
            VarTable::open_body_only(seqsigwit_dir, "seqsigwit", TableKind::SeqSigWit, in_count)?
        } else {
            VarTable::create_body_only(seqsigwit_dir, "seqsigwit", TableKind::SeqSigWit)?
        };
        let spent = if had_spent {
            VarTable::open_body_only(dir, "spent", TableKind::Spent, loc_count)?
        } else {
            VarTable::create_body_only(dir, "spent", TableKind::Spent)?
        };
        let txids = if dir.join("txid.body").exists() {
            crate::txid_body::TxidBody::open(dir)?
        } else {
            crate::txid_body::TxidBody::create(dir)?
        };
        if seqsigwit_dir != dir {
            for name in [
                "txstat.body",
                "txstat.ovf",
                "txstat.blk",
                "input.loc",
                "input.off",
                "input.body",
            ] {
                if dir.join(name).exists() && !seqsigwit_dir.join(name).exists() {
                    return Err(StoreError::Layout(format!(
                        "{name} is still in {}; move it next to seqsigwit under {}",
                        dir.display(),
                        seqsigwit_dir.display()
                    )));
                }
            }
        }
        let txstat = crate::txstat::TxStat::open(seqsigwit_dir)?;
        let input = if seqsigwit_dir.join("input.loc").exists() {
            crate::input::Input::open(seqsigwit_dir)?
        } else if seqsigwit_dir.join("input.body").exists()
            || seqsigwit_dir.join("input.off").exists()
        {
            return Err(StoreError::Corrupt("invariant: input stems partial"));
        } else {
            crate::input::Input::create(seqsigwit_dir)?
        };
        repair_class_a_count_skew(
            ClassASkewStems {
                create_loc: &create_loc,
                seqsigwit_loc: &seqsigwit_loc,
                body: &body,
                spent: &spent,
                seqsigwit: &seqsigwit,
                txids: &txids,
                txstat: &txstat,
                input: &input,
            },
            prune_seqsigwit_mode,
        )?;
        let n_bodies = create_loc.count();
        if txstat.count() != n_bodies {
            rbitcoin_log::warn!(
                "store: txstat.body count={} loc={} — aligning to loc",
                txstat.count(),
                n_bodies
            );
            txstat.extend_or_truncate_to(n_bodies)?;
        }
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
            SegmentedTxHead::create(dir, crate::address_head::default_layout(opts.scale))?
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
                        SegmentedTxHead::create(
                            dir,
                            crate::address_head::default_layout(opts.scale),
                        )?
                    } else {
                        if n_bodies > 0 && h.occupied() == 0 {
                            need_rebuild = true;
                        }
                        h
                    }
                }
                Err(e) => {
                    if crate::segmented_head::is_index_open_refuse(&e) {
                        return Err(e);
                    }
                    if n_bodies > 0 {
                        rbitcoin_log::warn!(
                            "store: segmented tx.head unreadable ({e}) with {n_bodies} Class A \
                             bodies — recreate + rebuild"
                        );
                        crate::segmented_head::wipe_segmented_head_files(dir);
                        need_rebuild = true;
                        SegmentedTxHead::create(
                            dir,
                            crate::address_head::default_layout(opts.scale),
                        )?
                    } else {
                        return Err(e);
                    }
                }
            }
        };
        let secret = crate::store_secret::StoreSecret::load_or_create(dir, true)?;
        let t = Self {
            body,
            seqsigwit,
            spent,
            create_loc,
            seqsigwit_loc,
            head,
            txids,
            txstat,
            input,
            secret,
            pending_head: pending_head::PendingHeadInserts::new(),
            rebuild_seal_bits: seal_bits,
            rebuild_workers: workers,
            prune_seqsigwit_mode: std::sync::atomic::AtomicBool::new(prune_seqsigwit_mode),
        };
        match input_open_tail(t.input.count(), n_bodies, t.seqsigwit.count()) {
            InputOpenTail::Backfill { from } => {
                // A missing tail on the new layout has no inline prevout. Stamp
                // those rows empty. A legacy tail (or a fresh backfill) still
                // walks seqsigwit.
                let legacy = from == 1 || t.seqsigwit_has_inline_prevout(Fk(from))?;
                if legacy {
                    t.backfill_inputs_from_seqsigwit(from)?;
                } else {
                    t.input
                        .append_unstamped(unstamped_tail(n_bodies, t.input.count()))?;
                }
            }
            InputOpenTail::Unstamped { n } => t.input.append_unstamped(n)?,
            InputOpenTail::Ahead => {
                return Err(StoreError::Corrupt(
                    "invariant: input.loc ahead of create.loc",
                ));
            }
            InputOpenTail::Ready => {}
        }
        if n_bodies > 0 {
            let _ = t.input.n_in(Fk(1))?;
        }
        if need_rebuild {
            let bits = t.head_bits();
            let slots = t.head_slots();
            rbitcoin_log::info!(
                "store: tx.head rebuild begin n={n_bodies} bits={bits} slots={slots} \
                 seal_bits={} workers={} free_GiB={} (segmented)",
                t.rebuild_seal_bits(),
                t.rebuild_workers(),
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
            t.seal_unsealed_nontail_from_body()?;
        }
        Ok(t)
    }

    pub fn prune_seqsigwit_mode(&self) -> bool {
        self.prune_seqsigwit_mode
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn set_prune_seqsigwit_mode(&self, on: bool) {
        self.prune_seqsigwit_mode
            .store(on, std::sync::atomic::Ordering::Release);
    }

    pub fn clear_durable_seqsigwit(&self) -> Result<(), StoreError> {
        self.seqsigwit_loc.truncate_to_count(0)?;
        self.seqsigwit
            .truncate_body_to(0, crate::file::FILE_HEADER_LEN as u64)
    }

    /// Seal unsealed non-tails from Class A (crash/restart). Keys are not retained.
    fn seal_unsealed_nontail_from_body(&self) -> Result<(), StoreError> {
        let n_body = self.count();
        for (file_id, first_fk, count) in self.head.unsealed_nontail_ranges() {
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
            let pairs = self.fuse_pairs_for_range(first_fk, count)?;
            self.head.seal_file_sync(file_id, pairs)?;
            rbitcoin_log::info!(
                "store: tx.head unsealed fuse keys sealed file_id={file_id} \
                 first_fk={first_fk} count={count}"
            );
        }
        Ok(())
    }

    /// `(fuse_key, rel)` pairs for a create fk range (1-based `first_fk`, `count`).
    fn fuse_pairs_for_range(
        &self,
        first_fk: u64,
        count: u64,
    ) -> Result<Vec<(u64, u32)>, StoreError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        const CHUNK: u64 = 65_536;
        let last = first_fk.saturating_add(count).saturating_sub(1);
        let mut pairs = Vec::with_capacity(count as usize);
        let mut rel = 1u32;
        let mut cur = first_fk;
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
            return Err(StoreError::Corrupt(
                "tx.head unsealed body range count mismatch",
            ));
        }
        Ok(pairs)
    }

    /// Sidecar collect: libc pread of `[first_fk, first_fk+count)` (already
    /// published on `txid.body` before head insert).
    fn fuse_pairs_from_txid_pread(
        fd: crate::io_handle::IoHandle,
        path: &Path,
        secret: &crate::store_secret::StoreSecret,
        first_fk: u64,
        count: u64,
    ) -> Result<Vec<(u64, u32)>, StoreError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        const CHUNK: u64 = 65_536;
        let last = first_fk.saturating_add(count).saturating_sub(1);
        let mut pairs = Vec::with_capacity(count as usize);
        let mut rel = 1u32;
        let mut cur = first_fk;
        while cur <= last {
            let end = (cur + CHUNK - 1).min(last);
            let n = (end - cur + 1) as usize;
            let off = crate::txid_body::TxidBody::entry_offset(cur)?;
            let mut blob = vec![0u8; n * 32];
            let rc = crate::bulk_io::pread_single(fd, off, &mut blob);
            if rc < 0 {
                return Err(StoreError::io(path, std::io::Error::from_raw_os_error(-rc)));
            }
            if (rc as usize) != blob.len() {
                return Err(StoreError::Corrupt("tx.head seal collect txid.body short"));
            }
            for i in 0..n {
                let s = i * 32;
                let txid: [u8; 32] = blob[s..s + 32].try_into().unwrap();
                pairs.push((
                    crate::fuse8_filter::fuse_key_from_mixed(&secret.mix_txid(&txid)),
                    rel,
                ));
                rel = rel.saturating_add(1);
            }
            cur = end + 1;
        }
        if pairs.len() as u64 != count {
            return Err(StoreError::Corrupt(
                "tx.head unsealed body range count mismatch",
            ));
        }
        Ok(pairs)
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
        self.create_loc_range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .map(|p| p.txout)
            .ok_or(StoreError::NotFound)
    }

    pub fn create_loc_range_batch(
        &self,
        fks: &[Fk],
    ) -> Result<Vec<Option<crate::create_loc::CreateLocPair>>, StoreError> {
        self.create_loc.range_batch(fks)
    }

    /// Durable `create.loc` row count (not `tx.body` HWM).
    pub fn create_loc_count(&self) -> u64 {
        self.create_loc.count()
    }

    /// Truncate `create.loc` to `n` rows without touching Class A bodies.
    pub fn create_loc_truncate_to_count(&self, n: u64) -> Result<(), StoreError> {
        self.create_loc.truncate_to_count(n)
    }

    pub(crate) fn fill_txout_job_ranges(
        &self,
        jobs: &mut [crate::IdxBodyJob],
    ) -> Result<(), StoreError> {
        let mut need = Vec::new();
        let mut slots = Vec::new();
        for (i, j) in jobs.iter().enumerate() {
            if j.id > 0 && (j.range.is_none() || j.n_out == 0) {
                need.push(Fk(j.id));
                slots.push(i);
            }
        }
        if need.is_empty() {
            return Ok(());
        }
        let pairs = self.create_loc_range_batch(&need)?;
        for (slot, p) in slots.into_iter().zip(pairs) {
            if let Some(p) = p {
                if jobs[slot].range.is_none() {
                    jobs[slot].range = Some(p.txout);
                }
                if jobs[slot].n_out == 0 {
                    jobs[slot].n_out = p.n_out;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn fill_seqsigwit_job_ranges(
        &self,
        jobs: &mut [crate::IdxBodyJob],
    ) -> Result<(), StoreError> {
        if self.prune_seqsigwit_mode() {
            return Ok(());
        }
        let mut need = Vec::new();
        let mut slots = Vec::new();
        for (i, j) in jobs.iter().enumerate() {
            if j.range.is_none() && j.id > 0 {
                need.push(Fk(j.id));
                slots.push(i);
            }
        }
        if need.is_empty() {
            return Ok(());
        }
        let pairs = self.seqsigwit_loc.range_batch(&need)?;
        for (slot, p) in slots.into_iter().zip(pairs) {
            jobs[slot].range = p;
        }
        Ok(())
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
        if first == 0 || last < first {
            return Ok(Vec::new());
        }
        let fks: Vec<Fk> = (first..=last).map(Fk).collect();
        let pairs = self.create_loc.range_batch(&fks)?;
        let mut out = Vec::with_capacity(pairs.len());
        for p in pairs {
            out.push(p.ok_or(StoreError::NotFound)?.txout);
        }
        Ok(out)
    }

    /// P2TR outs from a packed body slice (stack XOR; no `OutputRecord` heap).
    pub fn packed_p2tr_from_raw(
        &self,
        raw: &[u8],
        n_out: u32,
    ) -> Result<Vec<(u32, [u8; 32], u64)>, StoreError> {
        scan_packed_p2tr_outs(raw, n_out, Some(&self.secret))
    }

    /// Meta + input prevouts only (no script/witness allocation, no outputs).
    ///
    /// Stamped rows read `n_in` and the parent edge from `input`. Leftover
    /// unstamped rows still take the inline prevout out of legacy `seqsigwit`.
    pub fn get_meta_and_prevouts(&self, fk: Fk) -> Result<(TxRecord, Vec<(Fk, u32)>), StoreError> {
        if self.prune_seqsigwit_mode() {
            return Err(StoreError::NotFound);
        }
        let mut tx = if let Some(n_in) = self.input.n_in(fk)? {
            TxRecord {
                txid: [0u8; 32],
                version: 0,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: n_in,
                output_start_fk: Fk::NULL,
                output_count: 0,
            }
        } else {
            self.get(fk)?
        };
        let prevs = if let Some(edges) = self.input.edges(fk)? {
            prevouts_from_edges(&edges)
        } else {
            let ir = self
                .seqsigwit_loc
                .range_batch(&[fk])?
                .into_iter()
                .next()
                .flatten()
                .ok_or(StoreError::NotFound)?;
            let seqsigwit = self
                .seqsigwit
                .with_bytes_at(ir.0, ir.1, |b| Ok(b.to_vec()))?;
            scan_seqsigwit_prevouts(&seqsigwit, tx.input_count)?
        };
        tx.txid = self.txids.get(fk)?;
        Ok((tx, prevs))
    }

    pub(crate) fn overlay_stamped_n_in(&self, fk: Fk, tx: &mut TxRecord) -> Result<(), StoreError> {
        let Some(n_in) = self.input.n_in(fk)? else {
            return Ok(());
        };
        if tx.input_count != 0 && tx.input_count != n_in {
            return Err(StoreError::Corrupt("input n_in mismatch txout"));
        }
        tx.input_count = n_in;
        Ok(())
    }

    pub fn reserve_append(&self, body_bytes: u64, n_records: u64) -> Result<(), StoreError> {
        self.body.reserve_append(body_bytes, n_records)
    }

    pub fn get(&self, fk: Fk) -> Result<TxRecord, StoreError> {
        let pair = self
            .create_loc_range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::NotFound)?;
        let raw = self
            .body
            .with_bytes_at(pair.txout.0, pair.txout.1, |b| Ok(b.to_vec()))?;
        let (mut tx, _, _, _) =
            decode_packed_tx_with_spender_rels_secret(&raw, pair.n_out, Some(&self.secret))?;
        tx.txid = self.txids.get(fk)?;
        self.overlay_stamped_n_in(fk, &mut tx)?;
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
    pub fn probe_body_match_fk(&self, txid: &[u8; 32]) -> Result<Option<Fk>, StoreError> {
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
    /// **per-key depth-first** sidefile identity (io_uring when available) → loc
    /// range on hit. **No** cross-key depth-round batching. Prep denserels-loads
    /// via known `body_range` (skip loc).
    ///
    /// BIP30: deepest matching create wins (probe order deepest-first).
    /// Timers: [`crate::head_resolve_stats`] probe / idx / body.
    pub fn get_fk_by_txid_batch(&self, txids: &[[u8; 32]]) -> Result<Vec<TxidFkRange>, StoreError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        crate::head_resolve_denserels::resolve_fk_and_range_batch(self, txids)
    }

    /// Sparse outs by known `txout` body ranges (prep pin after plan stamp).
    ///
    /// Each job is `(create_fk, body_range, known_txid, n_out, need_vouts)`.
    /// - **Skips loc** (range known).
    /// - **`known_txid`**: RAM identity (plan reverse map / residency); not sidefile.
    /// - **`need_vouts`**: sorted unique; empty = all outs. Only those scripts are
    ///   allocated (N2.1). First-wave Outs peek is the remainder of the starting
    ///   OS page unless `(max_vout+1)*40` (empty need: the loc span) is likely to
    ///   spill onto the next page — then the first wave is the full loc span.
    ///
    /// Returns `(rows, body_ns, decode_ns, extend_n, body_sqe_n, guess_full_n)` where each row is
    /// `Some((tx, live (vout,out), sparse denserels (vout,rel)))` (N2.0 timers).
    pub fn get_outs_by_range_batch(
        &self,
        items: &[OutsByRangeJob],
    ) -> Result<OutsByRangeOut, StoreError> {
        use crate::idx_body_pipeline::{run_idx_body_pipeline_backend, BodyMode, IdxBodyJob};
        use std::time::Instant;
        if items.is_empty() {
            return Ok((Vec::new(), 0, 0, 0, 0, 0));
        }
        let mut jobs: Vec<IdxBodyJob> = items
            .iter()
            .map(|(fk, range, _txid, n_out, need)| {
                let mut job = IdxBodyJob::new(fk.get().unwrap_or(0), Some(*range));
                job.need_vouts = need.clone();
                job.n_out = *n_out;
                job
            })
            .collect();
        let t_body = Instant::now();
        let io = run_idx_body_pipeline_backend(
            &self.body,
            &mut jobs,
            BodyMode::Outs,
            crate::io_backend::read_io_backend(),
        )?;
        let body_ns = t_body.elapsed().as_nanos() as u64;
        let secret = self.store_secret();
        let t_dec = Instant::now();
        let mut out = Vec::with_capacity(jobs.len());
        for (job, (_fk, _range, known_txid, n_out, need)) in jobs.into_iter().zip(items.iter()) {
            if !job.ok || job.body.is_empty() {
                out.push(None);
                continue;
            }
            match decode_packed_tx_need_outs_with_spender_rels_secret(
                &job.body,
                *n_out,
                need,
                Some(secret),
            ) {
                Ok((mut tx, live, sparse)) => {
                    tx.txid = *known_txid;
                    // input_count stays 0. Full get overlays n_in from input.loc.
                    out.push(Some((tx, live, sparse)));
                }
                Err(StoreError::NotFound) | Err(StoreError::Corrupt(_)) => out.push(None),
                Err(e) => return Err(e),
            }
        }
        let decode_ns = t_dec.elapsed().as_nanos() as u64;
        Ok((
            out,
            body_ns,
            decode_ns,
            io.extend_n,
            io.body_sqe_n,
            io.guess_full_n,
        ))
    }

    /// Bulk `body_range` for many fks (confirm load / reconstruct).
    ///
    /// Thin wrapper over [`Self::create_loc_range_batch`] (txout half).
    pub fn body_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        Ok(self
            .create_loc
            .range_batch(fks)?
            .into_iter()
            .map(|p| p.map(|x| x.txout))
            .collect())
    }

    fn seqsigwit_has_inline_prevout(&self, fk: Fk) -> Result<bool, StoreError> {
        let (off, len) = self.seqsigwit_range(fk)?;
        if len == 0 {
            return Ok(false);
        }
        let flags = self.seqsigwit.with_bytes_at(off, 1, |b| Ok(b[0]))?;
        Ok(flags & input_flags::PREV_ON_INPUTS == 0)
    }

    fn backfill_inputs_from_seqsigwit(&self, from: u64) -> Result<(), StoreError> {
        let n = self.create_loc.count();
        let mut id = from.max(1);
        rbitcoin_log::info!("store: input backfill from seqsigwit n={n} start={id}");
        let mut buf = Vec::new();
        while id <= n {
            let end = backfill_chunk_end(id, n);
            let fks: Vec<Fk> = (id..=end).map(Fk).collect();
            let ranges = self.seqsigwit_loc.range_batch(&fks)?;
            let edges = edges_from_seqsigwit_ranges(
                &mut |off, len, buf| self.seqsigwit.with_bytes_at_into(off, len, buf, |_| Ok(())),
                &ranges,
                INPUT_BACKFILL_SPAN,
                &mut buf,
            )?;
            self.input.append(&edges)?;
            if backfill_progress_due(end, id) {
                rbitcoin_log::info!("store: input backfill progress {end}/{n}");
            }
            let next_id = end + 1;
            if next_id <= id {
                return Err(StoreError::Corrupt(
                    "invariant: input backfill did not advance",
                ));
            }
            id = next_id;
        }
        rbitcoin_log::info!("store: input backfill complete n={n}");
        Ok(())
    }

    /// `seqsigwit.body` range for one create.
    pub fn seqsigwit_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        if self.prune_seqsigwit_mode() {
            return Err(StoreError::NotFound);
        }
        self.seqsigwit_loc
            .range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::NotFound)
    }

    pub fn spent_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.create_loc_range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .map(|p| p.spent)
            .ok_or(StoreError::NotFound)
    }

    /// `spent.body` ranges (same fk order as [`Self::body_range_batch`]).
    pub fn spent_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        Ok(self
            .create_loc
            .range_batch(fks)?
            .into_iter()
            .map(|p| p.map(|x| x.spent))
            .collect())
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
        abs_edges: &[(u64, Fk, u32, Fk, u32)],
    ) -> Result<Vec<(Fk, u32, Fk, u32)>, StoreError> {
        const META_LEN: u64 = OutputRecord::SPENT_SLOT_LEN as u64;
        if abs_edges.is_empty() {
            return Ok(Vec::new());
        }
        for &(_, _, _, sfk, _) in abs_edges {
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
        let mut cold: Vec<(Fk, u32, Fk, u32)> = Vec::new();
        for &(abs, create_fk, vout, spend_fk, spend_vin) in abs_edges {
            if abs.saturating_add(META_LEN) > body_pub {
                cold.push((create_fk, vout, spend_fk, spend_vin));
                continue;
            }
            let cur = self
                .spent
                .with_bytes_at_published(body_pub, abs, META_LEN, |raw| {
                    let (flags, field, field_vin) = decode_spent_slot(raw)?;
                    Ok((field, flags, field_vin))
                });
            let Ok((field, flags, field_vin)) = cur else {
                cold.push((create_fk, vout, spend_fk, spend_vin));
                continue;
            };
            let multi = flags & output_flags::MULTI_SPENDER != 0;
            let (new_multi, new_field, new_vin) = if !multi && field.is_null() {
                (false, spend_fk, spend_vin)
            } else if !multi && field == spend_fk && field_vin == spend_vin {
                continue;
            } else if !multi {
                let e1 = spenders.append(field, field_vin, Fk::NULL)?;
                let e2 = spenders.append(spend_fk, spend_vin, e1)?;
                (true, e2, 0)
            } else {
                let e = spenders.append(spend_fk, spend_vin, field)?;
                (true, e, 0)
            };
            let new_flags = if new_multi {
                flags | output_flags::MULTI_SPENDER
            } else {
                flags & !output_flags::MULTI_SPENDER
            };
            let meta = encode_spent_slot(new_flags, new_field, new_vin)?;
            if self.spent.write_body_abs(abs, &meta).is_err() {
                cold.push((create_fk, vout, spend_fk, spend_vin));
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
    ) -> Result<Vec<Option<SpenderSlot>>, StoreError> {
        self.get_spender_meta_at_abs_batch_backend(abs_offs, spend_meta_backend())
    }

    /// Like [`Self::get_spender_meta_at_abs_batch`] with an explicit backend.
    pub fn get_spender_meta_at_abs_batch_backend(
        &self,
        abs_offs: &[u64],
        backend: crate::io_backend::ReadIoBackend,
    ) -> Result<Vec<Option<SpenderSlot>>, StoreError> {
        if abs_offs.is_empty() {
            return Ok(Vec::new());
        }
        match backend {
            crate::io_backend::ReadIoBackend::Uring => {
                match self.get_spender_meta_at_abs_batch_uring(abs_offs) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        rbitcoin_log::debug!(
                            "store: structural meta uring failed ({e}); pread fallback"
                        );
                        self.get_spender_meta_at_abs_batch_pread(abs_offs)
                    }
                }
            }
            crate::io_backend::ReadIoBackend::Pread => {
                self.get_spender_meta_at_abs_batch_pread(abs_offs)
            }
        }
    }

    /// io_uring pread_batch 9B peeks.
    fn get_spender_meta_at_abs_batch_uring(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<SpenderSlot>>, StoreError> {
        self.get_spender_meta_at_abs_batch_fd(abs_offs, crate::io_backend::ReadIoBackend::Uring)
    }

    /// libc pread_batch 9B peeks (no ring).
    fn get_spender_meta_at_abs_batch_pread(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<SpenderSlot>>, StoreError> {
        self.get_spender_meta_at_abs_batch_fd(abs_offs, crate::io_backend::ReadIoBackend::Pread)
    }

    fn get_spender_meta_at_abs_batch_fd(
        &self,
        abs_offs: &[u64],
        backend: crate::io_backend::ReadIoBackend,
    ) -> Result<Vec<Option<SpenderSlot>>, StoreError> {
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

        let mut out: Vec<Option<SpenderSlot>> = vec![None; abs_offs.len()];
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
            let Ok((flags, field, vin)) = decode_spent_slot(b) else {
                continue;
            };
            out[i] = Some((field, flags, vin));
        }
        Ok(out)
    }

    /// Pure-write spend annotate using structural-known meta (no body pread).
    ///
    /// `known[i]` is `(field, flags, vin)` at `abs_edges[i].0` from structural spentness.
    /// Backend: `pwrite` or `uring`. Returns cold edges
    /// (OOB) — production callers must treat non-empty as hard error.
    pub fn put_spend_batch_by_abs_meta_known(
        &self,
        spenders: &crate::spender_table::SpenderTable,
        abs_edges: &[(u64, Fk, u32, Fk, u32)],
        known: &[(Fk, u8, u32)],
        backend: crate::io_backend::WriteIoBackend,
    ) -> Result<Vec<(Fk, u32, Fk, u32)>, StoreError> {
        crate::spend_annotate_uring::put_spend_batch_by_abs_meta_known(
            self, spenders, abs_edges, known, backend,
        )
    }

    /// Read multi + spender_field for create tx output (packed Class A body).
    pub fn get_output_spender_meta(
        &self,
        create_tx_fk: Fk,
        vout: u32,
    ) -> Result<(bool, Fk, u32), StoreError> {
        let (off, len) = self.spent_range(create_tx_fk)?;
        self.get_output_spender_meta_at(off, len, vout)
    }

    /// Like [`Self::get_output_spender_meta`] but uses a cache-held body range (no idx).
    pub fn get_output_spender_meta_at(
        &self,
        body_off: u64,
        body_len: u64,
        vout: u32,
    ) -> Result<(bool, Fk, u32), StoreError> {
        let abs = spent_abs(body_off, vout);
        let end = body_off.saturating_add(body_len);
        if abs.saturating_add(OutputRecord::SPENT_SLOT_LEN as u64) > end {
            return Err(StoreError::Corrupt("spent slot OOB"));
        }
        self.spent
            .with_bytes_at(abs, OutputRecord::SPENT_SLOT_LEN as u64, |raw| {
                let (flags, field, vin) = decode_spent_slot(raw)?;
                Ok((flags & output_flags::MULTI_SPENDER != 0, field, vin))
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
    ) -> Result<Vec<(u32, bool, Fk, u32)>, StoreError> {
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
                let Ok((flags, field, vin)) = decode_spent_slot(&raw[start..end]) else {
                    continue;
                };
                out.push((v, flags & output_flags::MULTI_SPENDER != 0, field, vin));
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
        vin: u32,
    ) -> Result<(), StoreError> {
        let (off, len) = self.spent_range(create_tx_fk)?;
        self.set_output_spender_meta_at(off, len, vout, multi, field, vin)
    }

    /// Patch spender meta using a cache-held body range (no idx read on the hot path).
    pub fn set_output_spender_meta_at(
        &self,
        body_off: u64,
        body_len: u64,
        vout: u32,
        multi: bool,
        field: Fk,
        vin: u32,
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
        let slot_vin = if multi { 0 } else { vin };
        let slot = encode_spent_slot(flags, field, slot_vin)?;
        self.spent.write_body_abs(abs, &slot)?;
        Ok(())
    }

    /// Full tx: `txout` + `seqsigwit` zip.
    pub fn get_full(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>), StoreError> {
        if self.prune_seqsigwit_mode() {
            return Err(StoreError::NotFound);
        }
        let pair = self
            .create_loc_range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::NotFound)?;
        let raw = self
            .body
            .with_bytes_at(pair.txout.0, pair.txout.1, |b| Ok(b.to_vec()))?;
        let (mut tx, _ins, outs, _) =
            decode_packed_tx_with_spender_rels_secret(&raw, pair.n_out, Some(&self.secret))?;
        let ir = self
            .seqsigwit_loc
            .range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::NotFound)?;
        let seqsigwit = self
            .seqsigwit
            .with_bytes_at(ir.0, ir.1, |b| Ok(b.to_vec()))?;
        let mut ins = if tx.input_count == 0 {
            decode_seqsigwit_secret_to_end(&seqsigwit, Some(&self.secret))?
        } else {
            decode_seqsigwit_secret(&seqsigwit, tx.input_count, Some(&self.secret))?
        };
        self.stamp_seqsigwit_prevouts(fk, &mut ins)?;
        tx.input_count = ins.len() as u32;
        tx.txid = self.txids.get(fk)?;
        Ok((tx, ins, outs))
    }

    pub(crate) fn stamp_seqsigwit_prevouts(
        &self,
        fk: Fk,
        ins: &mut [InputRecord],
    ) -> Result<(), StoreError> {
        let Some(edges) = self.input.edges(fk)? else {
            return Ok(());
        };
        apply_input_edges(ins, &edges)
    }

    /// Contiguous create_fks `first..=last`: one libc span each of `txout.body`
    /// and `seqsigwit.body`, plus `txid.body` range. Not the confirm uring pipeline.
    pub fn get_full_span(&self, first: u64, last: u64) -> Result<Vec<PackedTx>, StoreError> {
        if self.prune_seqsigwit_mode() {
            return Err(StoreError::NotFound);
        }
        if first == 0 {
            return Err(StoreError::InvalidFk);
        }
        if last < first {
            return Ok(Vec::new());
        }
        let n = (last - first + 1) as usize;
        let fks: Vec<Fk> = (first..=last).map(Fk).collect();
        let loc_pairs = self.create_loc.range_batch(&fks)?;
        let mut txout_ranges = Vec::with_capacity(n);
        let mut n_outs = Vec::with_capacity(n);
        for p in loc_pairs {
            let p = p.ok_or(StoreError::NotFound)?;
            txout_ranges.push(p.txout);
            n_outs.push(p.n_out);
        }
        let seqsigwit_pairs = self.seqsigwit_loc.range_batch(&fks)?;
        let mut seqsigwit_ranges = Vec::with_capacity(n);
        for p in seqsigwit_pairs {
            seqsigwit_ranges.push(p.ok_or(StoreError::NotFound)?);
        }
        if txout_ranges.len() != n || seqsigwit_ranges.len() != n {
            return Err(StoreError::Corrupt("invariant: full span range count"));
        }
        let (t0, _) = txout_ranges[0];
        let (tn, tln) = txout_ranges[n - 1];
        let tspan = tn
            .checked_add(tln)
            .and_then(|end| end.checked_sub(t0))
            .ok_or(StoreError::Corrupt("txout span"))?;
        let (i0, _) = seqsigwit_ranges[0];
        let (inn, iln) = seqsigwit_ranges[n - 1];
        let ispan = inn
            .checked_add(iln)
            .and_then(|end| end.checked_sub(i0))
            .ok_or(StoreError::Corrupt("seqsigwit span"))?;
        let ids = self.txids.get_range(first, last)?;
        if ids.len() != n {
            return Err(StoreError::Corrupt("invariant: txid.body span length"));
        }
        let (txout_span, seqsigwit_span) =
            pread_two_spans(&self.body, t0, tspan, &self.seqsigwit, i0, ispan, true)?;
        let edge_rows = self.input.edges_span(first, last)?;
        if edge_rows.len() != n {
            return Err(StoreError::Corrupt("invariant: input span length"));
        }
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let (toff, tlen) = txout_ranges[i];
            let (ioff, ilen) = seqsigwit_ranges[i];
            let traw = span_rec(&txout_span, t0, toff, tlen)?;
            let iraw = span_rec(&seqsigwit_span, i0, ioff, ilen)?;
            let (mut tx, _ins, outs, _) =
                decode_packed_tx_with_spender_rels_secret(traw, n_outs[i], Some(&self.secret))?;
            let mut ins = if tx.input_count == 0 {
                decode_seqsigwit_secret_to_end(iraw, Some(&self.secret))?
            } else {
                decode_seqsigwit_secret(iraw, tx.input_count, Some(&self.secret))?
            };
            if let Some(edges) = edge_rows[i].as_ref() {
                apply_input_edges(&mut ins, edges)?;
            }
            tx.input_count = ins.len() as u32;
            tx.txid = ids[i];
            out.push((tx, ins, outs));
        }
        Ok(out)
    }

    /// Meta + outputs only (one body IO; skips input materialization).
    pub fn get_meta_and_outputs(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<OutputRecord>), StoreError> {
        let pair = self
            .create_loc_range_batch(&[fk])?
            .into_iter()
            .next()
            .flatten()
            .ok_or(StoreError::NotFound)?;
        let raw = self
            .body
            .with_bytes_at(pair.txout.0, pair.txout.1, |b| Ok(b.to_vec()))?;
        let (mut tx, outs, _) =
            decode_packed_tx_outs_with_spender_rels_secret(&raw, pair.n_out, Some(&self.secret))?;
        tx.txid = self.txids.get(fk)?;
        self.overlay_stamped_n_in(fk, &mut tx)?;
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
        let fks: Vec<Fk> = (first..=last).map(Fk).collect();
        let loc = match self.create_loc.range_batch(&fks) {
            Ok(r) => r,
            Err(StoreError::NotFound) | Err(StoreError::InvalidFk) => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut ranges = Vec::with_capacity(loc.len());
        let mut n_outs = Vec::with_capacity(loc.len());
        for p in loc {
            let Some(p) = p else {
                return Ok(());
            };
            ranges.push(p.txout);
            n_outs.push(p.n_out);
        }
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
                for (k, &(off, len)) in ranges.iter().enumerate().take(j).skip(i) {
                    let rel = (off.saturating_sub(span_lo)) as usize;
                    let end = rel.saturating_add(len as usize);
                    if end > buf.len() {
                        return Err(StoreError::Corrupt("txout span short for fk range"));
                    }
                    let fk = Fk(first.saturating_add(k as u64));
                    visit_packed_script_hashes(
                        &buf[rel..end],
                        n_outs[k],
                        Some(&self.secret),
                        |sh| f(fk, sh),
                    )?;
                }
                Ok(())
            })?;
            i = j;
        }
        Ok(())
    }

    /// Append Class A rows: `txout` + `seqsigwit` + zero `spent` + `txid.body` + `txstat.body`.
    pub fn put_full_batch_indexed(
        &self,
        items: &[(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)],
        index: bool,
    ) -> Result<Vec<Fk>, StoreError> {
        let rows = txstat_placeholders(items);
        self.put_full_batch_indexed_with_txstat(items, index, &rows)
    }

    pub fn put_full_batch_indexed_with_txstat(
        &self,
        items: &[(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)],
        index: bool,
        txstat: &[crate::txstat::TxStatRow],
    ) -> Result<Vec<Fk>, StoreError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        if txstat.len() != items.len() {
            return Err(StoreError::Corrupt("txstat batch length"));
        }
        let est_out: usize = items
            .iter()
            .map(|(_tx, _ins, outs)| {
                16 + TxRecord::BODY_META_LEN + outs.iter().map(|o| o.encoded_len()).sum::<usize>()
            })
            .sum();
        let est_seqsigwit: usize = items
            .iter()
            .map(|(_tx, ins, _outs)| 16 + ins.iter().map(|i| i.encoded_len()).sum::<usize>())
            .sum();
        let est_spent: usize = items
            .iter()
            .map(|(_tx, _ins, outs)| 16 + outs.len() * OutputRecord::SPENT_SLOT_LEN)
            .sum();
        let base = self.body.count();
        if (!self.prune_seqsigwit_mode() && self.seqsigwit.count() != base)
            || self.spent.count() != base
            || self.txstat.count() != base
            || self.input.count() != base
        {
            return Err(StoreError::Corrupt("Class A stem count mismatch on append"));
        }
        if items.iter().any(|(_, _, outs)| outs.is_empty()) {
            return Err(StoreError::Corrupt("invariant: create n_out"));
        }
        if items
            .iter()
            .any(|(_, _, outs)| outs.iter().any(|o| o.value < 0))
        {
            return Err(StoreError::Corrupt("txout amount negative"));
        }
        let n_outs: Vec<u32> = items.iter().map(|(_, _, o)| o.len() as u32).collect();
        let (fks, _loc) = self.append_stems_one_wave(
            items.len(),
            est_out,
            est_seqsigwit,
            est_spent,
            &n_outs,
            |i, buf| {
                let (tx, ins, outs) = &items[i];
                encode_packed_tx_with_secret(tx, ins, outs, buf, Some(&self.secret));
            },
            |i, buf| encode_seqsigwit_with_secret(&items[i].1, buf, Some(&self.secret)),
            |i, buf| encode_spent_zeros(items[i].2.len() as u32, buf),
        )?;
        let ids: Vec<[u8; 32]> = items.iter().map(|(tx, _, _)| tx.txid).collect();
        self.txids.append_batch(base, &ids)?;
        let tails = self.txstat.append_batch(base, txstat)?;
        if !tails.is_empty() {
            return Err(StoreError::Corrupt("txstat overflow needs header blob"));
        }
        let edges: Vec<Vec<crate::input::InputEdge>> =
            items.iter().map(|(_, ins, _)| input_edges(ins)).collect();
        self.input.append(&edges)?;
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

    /// Like [`Self::put_full_batch_indexed`], but outs live in a shared pin
    /// ([`PackedCreate`]). Encode borrows pin fields — no outs deep clone.
    ///
    /// `spent_overlay` is per-item `(vout, spend_fk, vin)` sole spenders written into
    /// the Class A spent stem. Empty slice = all zeros. Non-empty must be one
    /// inner vec per item.
    pub fn put_full_batch_from_pins<P: PackedCreate>(
        &self,
        items: &[(P, Vec<InputRecord>)],
        index: bool,
        spent_overlay: &[Vec<(u32, Fk, u32)>],
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        let rows: Vec<crate::txstat::TxStatRow> =
            items.iter().map(|_| txstat_placeholder()).collect();
        self.put_full_batch_from_pins_with_txstat(items, index, spent_overlay, &rows, &[])
    }

    pub fn put_full_batch_from_pins_with_txstat<P: PackedCreate>(
        &self,
        items: &[(P, Vec<InputRecord>)],
        index: bool,
        spent_overlay: &[Vec<(u32, Fk, u32)>],
        txstat: &[crate::txstat::TxStatRow],
        header_ranges: &[(Fk, Fk, u32)],
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        if items.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if txstat.len() != items.len() {
            return Err(StoreError::Corrupt("txstat batch length"));
        }
        if !spent_overlay.is_empty() && spent_overlay.len() != items.len() {
            return Err(StoreError::Corrupt("spent overlay length"));
        }
        let est_out: usize = items.iter().map(|(pin, _ins)| pin.packed_outs_est()).sum();
        let est_seqsigwit: usize = items
            .iter()
            .map(|(_pin, ins)| 16 + ins.iter().map(|i| i.encoded_len()).sum::<usize>())
            .sum();
        let est_spent: usize = items
            .iter()
            .map(|(pin, _ins)| 16 + spent_record_len(pin.packed_n_out()) as usize)
            .sum();
        let base = self.body.count();
        if (!self.prune_seqsigwit_mode() && self.seqsigwit.count() != base)
            || self.spent.count() != base
            || self.txstat.count() != base
            || self.input.count() != base
        {
            return Err(StoreError::Corrupt("Class A stem count mismatch on append"));
        }
        for (i, (pin, _)) in items.iter().enumerate() {
            let n_out = pin.packed_n_out();
            if n_out == 0 {
                return Err(StoreError::Corrupt("invariant: create n_out"));
            }
            if pin.packed_has_negative_amount() {
                return Err(StoreError::Corrupt("txout amount negative"));
            }
            let pairs = spent_overlay.get(i).map(|v| v.as_slice()).unwrap_or(&[]);
            for &(vout, fk, vin) in pairs {
                if vout >= n_out {
                    return Err(StoreError::Corrupt("spent overlay vout"));
                }
                encode_spent_slot(0, fk, vin)?;
            }
        }
        let n_outs: Vec<u32> = items.iter().map(|(pin, _)| pin.packed_n_out()).collect();
        let (fks, loc) = self.append_stems_one_wave(
            items.len(),
            est_out,
            est_seqsigwit,
            est_spent,
            &n_outs,
            |i, buf| {
                items[i].0.encode_txout_body(buf, Some(&self.secret));
            },
            |i, buf| encode_seqsigwit_with_secret(&items[i].1, buf, Some(&self.secret)),
            |i, buf| {
                let n_out = items[i].0.packed_n_out();
                let pairs = spent_overlay.get(i).map(|v| v.as_slice()).unwrap_or(&[]);
                encode_spent_slots(n_out, pairs, buf).expect("spent overlay prechecked");
            },
        )?;
        let ids: Vec<[u8; 32]> = items.iter().map(|(pin, _)| pin.packed_txid()).collect();
        self.txids.append_batch(base, &ids)?;
        let tails = self.txstat.append_batch(base, txstat)?;
        self.txstat
            .put_overflows_for_headers(header_ranges, &tails)?;
        let edges: Vec<Vec<crate::input::InputEdge>> =
            items.iter().map(|(_, ins)| input_edges(ins)).collect();
        self.input.append(&edges)?;
        if index {
            let heads: Vec<([u8; 32], Fk)> = items
                .iter()
                .zip(fks.iter())
                .map(|((pin, _), fk)| (pin.packed_txid(), *fk))
                .collect();
            self.head_insert_many(&heads)?;
        }
        Ok((fks, loc))
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    /// Encode and write `txout` + `seqsigwit` + `spent` bodies as one pwrite wave.
    ///
    /// Order is still body → loc → HWM per stem. Not the spend-annotate machine.
    /// Loc pairs are the append starts (write keeps them in RAM; no loc pread).
    fn append_stems_one_wave(
        &self,
        n: usize,
        est_out: usize,
        est_seqsigwit: usize,
        est_spent: usize,
        n_outs: &[u32],
        encode_out: impl FnMut(usize, &mut Vec<u8>),
        encode_in: impl FnMut(usize, &mut Vec<u8>),
        encode_sp: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        if n_outs.len() != n {
            return Err(StoreError::Corrupt("invariant: create n_out"));
        }
        let Some(p_out) = self.body.prepare_batch_encode(n, est_out, encode_out)? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let Some(p_sp) = self.spent.prepare_batch_encode(n, est_spent, encode_sp)? else {
            return Err(StoreError::Corrupt("Class A spent prepare empty"));
        };
        let tx_lens = p_out.aligned_lens();
        let mut recs = Vec::with_capacity(n);
        let mut loc = Vec::with_capacity(n);
        for i in 0..n {
            let spent_len = spent_record_len(n_outs[i]);
            recs.push(crate::create_loc::CreateLocAppend {
                txout_start: p_out.starts[i],
                txout_len: tx_lens[i],
                spent_start: p_sp.starts[i],
                n_out: n_outs[i],
            });
            loc.push(crate::create_loc::CreateLocPair {
                txout: (p_out.starts[i], tx_lens[i]),
                spent: (p_sp.starts[i], spent_len),
                n_out: n_outs[i],
            });
        }

        if self.prune_seqsigwit_mode() {
            crate::var_table::write_prepared_bodies_one_wave(&[
                (&self.body, &p_out),
                (&self.spent, &p_sp),
            ])?;
            self.create_loc.append(&recs)?;
            let fks = self.body.finish_prepared(p_out)?;
            let fks_sp = self.spent.finish_prepared(p_sp)?;
            if fks != fks_sp {
                return Err(StoreError::Corrupt(
                    "Class A append fk mismatch across stems",
                ));
            }
            return Ok((fks, loc));
        }

        let Some(p_in) = self
            .seqsigwit
            .prepare_batch_encode(n, est_seqsigwit, encode_in)?
        else {
            return Err(StoreError::Corrupt("Class A seqsigwit prepare empty"));
        };
        crate::var_table::write_prepared_bodies_one_wave(&[
            (&self.body, &p_out),
            (&self.seqsigwit, &p_in),
            (&self.spent, &p_sp),
        ])?;
        self.create_loc.append(&recs)?;
        self.seqsigwit_loc
            .append(&p_in.starts, &p_in.aligned_lens())?;
        let fks = self.body.finish_prepared(p_out)?;
        let fks_in = self.seqsigwit.finish_prepared(p_in)?;
        let fks_sp = self.spent.finish_prepared(p_sp)?;
        if fks != fks_in || fks != fks_sp {
            return Err(StoreError::Corrupt(
                "Class A append fk mismatch across stems",
            ));
        }
        Ok((fks, loc))
    }

    pub fn get_by_txid(&self, txid: &[u8; 32]) -> Result<Option<(Fk, TxRecord)>, StoreError> {
        let Some(fk) = self.probe_body_match_fk(txid)? else {
            return Ok(None);
        };
        Ok(Some((fk, self.get(fk)?)))
    }

    /// All Class A fks whose body txid equals `txid` (BIP30: more than one).
    ///
    /// Order is **newest-first** (deepest probe match first), matching
    /// [`Self::probe_body_match_fk`].
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
        edges: &[(u32, Fk, u32)],
    ) -> Result<(), StoreError> {
        if edges.is_empty() {
            return Ok(());
        }
        for &(_, sfk, _) in edges {
            if sfk.is_null() {
                return Err(StoreError::InvalidFk);
            }
        }
        for &(vout, spend_fk, spend_vin) in edges {
            let (multi, field, field_vin) =
                self.get_output_spender_meta_at(spent_off, spent_len, vout)?;
            let (new_multi, new_field, new_vin) = if !multi && field.is_null() {
                (false, spend_fk, spend_vin)
            } else if !multi && field == spend_fk && field_vin == spend_vin {
                continue;
            } else if !multi {
                let e1 = spenders.append(field, field_vin, Fk::NULL)?;
                let e2 = spenders.append(spend_fk, spend_vin, e1)?;
                (true, e2, 0)
            } else {
                let e = spenders.append(spend_fk, spend_vin, field)?;
                (true, e, 0)
            };
            self.set_output_spender_meta_at(
                spent_off, spent_len, vout, new_multi, new_field, new_vin,
            )?;
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
    /// and range count). Distinct from SH extract's 1.5 GiB cap.
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
        let workers = self.rebuild_workers().min(n_jobs).max(1);
        let seal_bits = self.rebuild_seal_bits();
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
        type SealSlot = std::sync::Mutex<
            Option<Result<(u64, u64, crate::segmented_head::SealPublish), StoreError>>,
        >;
        let slots: Vec<SealSlot> = (0..n_jobs).map(|_| std::sync::Mutex::new(None)).collect();
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
        let pairs = self.fuse_pairs_for_range(first, count)?;
        let pubd = self.head.write_sealed_pairs(file_id, first, count, pairs)?;
        Ok((first, count, pubd))
    }

    /// Parallel wipe-rebuild workers captured at open (env or explicit opts).
    pub fn rebuild_workers(&self) -> usize {
        self.rebuild_workers
    }

    /// Rebuild MPHF range width captured at open: `2^bits` keys.
    pub fn rebuild_seal_bits(&self) -> u32 {
        self.rebuild_seal_bits
    }

    pub fn rebuild_seal_keys(&self) -> u64 {
        1u64 << self.rebuild_seal_bits()
    }
}

/// Class A cuts for a cold MPHF rebuild (`2^bits` keys, last range short).
pub(crate) fn plan_rebuild_ranges(n: u64, seal_bits: u32) -> Vec<(u64, u64)> {
    if n == 0 {
        return Vec::new();
    }
    let t = (1u64 << seal_bits.clamp(6, 26)).min(u64::from(u32::MAX));
    let mut out = Vec::new();
    let mut first = 1u64;
    while first <= n {
        let count = (n - first + 1).min(t);
        out.push((first, count));
        first += count;
    }
    out
}

impl TxTable {
    /// Class A cuts for a cold MPHF rebuild (`2^bits` keys, last range short).
    ///
    /// Independent of live OA 80% load.
    pub fn plan_head_rebuild_ranges(&self) -> Result<Vec<(u64, u64)>, StoreError> {
        Ok(plan_rebuild_ranges(self.count(), self.rebuild_seal_bits()))
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
    /// Rolls the open OA when its fk span reaches 80% slots (`max_keys`).
    /// Class A loc/body size does not cut `tx.head` shards.
    pub fn head_insert_many(&self, entries: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut mixed: Vec<([u8; 32], Fk)> = entries
            .iter()
            .map(|(txid, fk)| (self.secret.mix_txid(txid), *fk))
            .collect();
        self.head.insert_many_with(
            &mut mixed,
            Arc::new({
                let secret = self.secret.clone();
                let fd = self.txids.body_read_fd();
                let path = self.txids.file_path().to_path_buf();
                move |first_fk, count| {
                    TxTable::fuse_pairs_from_txid_pread(fd, &path, &secret, first_fk, count)
                }
            }),
        )
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
            mphf_occ_bytes: 0,
            class_c_l2_bytes: 0,
        }
    }

    /// Flush segmented heads only.
    pub fn flush_head(&self) -> Result<(), StoreError> {
        self.head.flush()
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.sync_replay_bodies()?;
        self.head.flush()?;
        Ok(())
    }

    /// Bodies the tip-window check and spend replay read. Not `tx.head`.
    pub(crate) fn sync_replay_bodies(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        self.seqsigwit.flush()?;
        self.spent.flush()?;
        self.txids.flush()?;
        self.txstat.flush()?;
        self.input.flush()?;
        Ok(())
    }

    /// Device barrier for those bodies. Does not publish their high-water marks.
    pub(crate) fn sync_replay_data(&self) -> Result<(), StoreError> {
        self.body.sync_data_only()?;
        self.seqsigwit.sync_data_only()?;
        self.spent.sync_data_only()?;
        self.txids.sync_data_only()?;
        self.txstat.sync_data_only()?;
        self.input.sync_data_only()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        self.seqsigwit.flush_async()?;
        self.spent.flush_async()?;
        self.head.flush_async()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
