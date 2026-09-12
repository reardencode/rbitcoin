//! Packed tx body encode/decode (schema Class A payload).

use super::*;

/// Encode a per-tx output run (concat of compact outputs; count lives on TxRecord).
pub(super) fn encode_output_run_secret(
    recs: &[OutputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    for r in recs {
        let start = out.len();
        r.encode_into(out);
        if let Some(sec) = secret {
            // XOR only the scriptPubKey payload bytes (after spender/flags/value/len).
            xor_script_region_in_output(out, start, sec);
        }
    }
}

/// Class A input + BIP141 witness (schema v10).
///
/// On-disk prevout:
/// - coinbase: `NULL_PREV` (no payload)
/// - non-coinbase: **`create_fk:u64` LE** + CompactSize `vout` (not prev_txid)
///
/// [`Self::prev_txid`] is a soft cache for wire rebuild (zeros until filled from
/// the create body or from the wire convert path). Encoding never writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputRecord {
    /// Soft: wire txid of parent create (`[0;32]` if unknown / coinbase).
    pub prev_txid: [u8; 32],
    /// Dense Class A fk of parent create; [`Fk::NULL`] for coinbase.
    pub create_fk: Fk,
    pub prev_index: u32,
    pub sequence: u32,
    pub script_sig: Vec<u8>,
    /// Witness stack items (empty = no witness).
    pub witness: Vec<Vec<u8>>,
}

impl InputRecord {
    pub fn is_coinbase(&self) -> bool {
        self.create_fk.is_null() && self.prev_index == u32::MAX
    }

    /// Coinbase null prevout.
    pub fn coinbase(sequence: u32, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Self {
        Self {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence,
            script_sig,
            witness,
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let null_prev = self.create_fk.is_null() && self.prev_index == u32::MAX;
        let mut flags = 0u8;
        if self.sequence == u32::MAX {
            flags |= input_flags::SEQ_FINAL;
        }
        if self.script_sig.is_empty() {
            flags |= input_flags::EMPTY_SCRIPT;
        }
        if self.witness.is_empty() {
            flags |= input_flags::EMPTY_WITNESS;
        }
        if null_prev {
            flags |= input_flags::NULL_PREV;
        }
        out.push(flags);
        if !null_prev {
            debug_assert!(
                !self.create_fk.is_null(),
                "non-coinbase input requires create_fk before encode"
            );
            out.extend_from_slice(&self.create_fk.0.to_le_bytes());
            write_compact_size(out, u64::from(self.prev_index));
        }
        if flags & input_flags::SEQ_FINAL == 0 {
            out.extend_from_slice(&self.sequence.to_le_bytes());
        }
        if flags & input_flags::EMPTY_SCRIPT == 0 {
            write_compact_size(out, self.script_sig.len() as u64);
            out.extend_from_slice(&self.script_sig);
        }
        if flags & input_flags::EMPTY_WITNESS == 0 {
            write_compact_size(out, self.witness.len() as u64);
            for item in &self.witness {
                write_compact_size(out, item.len() as u64);
                out.extend_from_slice(item);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Skip past one input after reading create_fk + vout (no script/witness alloc).
    ///
    /// Returns `(create_fk, prev_index, bytes_consumed)`. Coinbase → `(NULL, u32::MAX, …)`.
    pub fn decode_prevout_at(buf: &[u8]) -> Result<(Fk, u32, usize), StoreError> {
        if buf.is_empty() {
            return Err(StoreError::Corrupt("short input record"));
        }
        let flags = buf[0];
        let mut off = 1usize;
        check_inwit_flags(flags)?;
        let (create_fk, prev_index) = if flags & input_flags::NULL_PREV != 0 {
            (Fk::NULL, u32::MAX)
        } else {
            if buf.len() < off + 8 {
                return Err(StoreError::Corrupt("input create_fk truncated"));
            }
            let id = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            off += 8;
            if id == 0 {
                return Err(StoreError::Corrupt("non-coinbase create_fk is null"));
            }
            let (vout, n) = read_compact_size(&buf[off..])?;
            off += n;
            if vout > u64::from(u32::MAX) {
                return Err(StoreError::Corrupt("prev_index too large"));
            }
            (Fk(id), vout as u32)
        };
        if flags & input_flags::SEQ_FINAL == 0 {
            if buf.len() < off + 4 {
                return Err(StoreError::Corrupt("input sequence truncated"));
            }
            off += 4;
        }
        if flags & input_flags::EMPTY_SCRIPT == 0 {
            let (slen, n) = read_compact_size(&buf[off..])?;
            off += n;
            let slen = slen as usize;
            if buf.len() < off + slen {
                return Err(StoreError::Corrupt("input script truncated"));
            }
            off += slen;
        }
        if flags & input_flags::EMPTY_WITNESS == 0 {
            let (nw, n) = read_compact_size(&buf[off..])?;
            off += n;
            for _ in 0..nw {
                let (ilen, n) = read_compact_size(&buf[off..])?;
                off += n;
                let ilen = ilen as usize;
                if buf.len() < off + ilen {
                    return Err(StoreError::Corrupt("witness item truncated"));
                }
                off += ilen;
            }
        }
        Ok((create_fk, prev_index, off))
    }

    /// Decode one input; returns (record, bytes_consumed).
    ///
    /// `prev_txid` is left zero; fill from create body when wire needs it.
    pub fn decode_at(buf: &[u8]) -> Result<(Self, usize), StoreError> {
        if buf.is_empty() {
            return Err(StoreError::Corrupt("short input record"));
        }
        let flags = buf[0];
        let mut off = 1usize;
        check_inwit_flags(flags)?;
        let (create_fk, prev_index) = if flags & input_flags::NULL_PREV != 0 {
            (Fk::NULL, u32::MAX)
        } else {
            if buf.len() < off + 8 {
                return Err(StoreError::Corrupt("input create_fk truncated"));
            }
            let id = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            off += 8;
            if id == 0 {
                return Err(StoreError::Corrupt("non-coinbase create_fk is null"));
            }
            let (vout, n) = read_compact_size(&buf[off..])?;
            off += n;
            if vout > u64::from(u32::MAX) {
                return Err(StoreError::Corrupt("prev_index too large"));
            }
            (Fk(id), vout as u32)
        };
        let sequence = if flags & input_flags::SEQ_FINAL != 0 {
            u32::MAX
        } else {
            if buf.len() < off + 4 {
                return Err(StoreError::Corrupt("input sequence truncated"));
            }
            let s = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            off += 4;
            s
        };
        let script_sig = if flags & input_flags::EMPTY_SCRIPT != 0 {
            Vec::new()
        } else {
            let (slen, n) = read_compact_size(&buf[off..])?;
            off += n;
            let slen = slen as usize;
            if buf.len() < off + slen {
                return Err(StoreError::Corrupt("input script truncated"));
            }
            let s = buf[off..off + slen].to_vec();
            off += slen;
            s
        };
        let witness = if flags & input_flags::EMPTY_WITNESS != 0 {
            Vec::new()
        } else {
            let (nw, n) = read_compact_size(&buf[off..])?;
            off += n;
            let mut witness = Vec::with_capacity(nw as usize);
            for _ in 0..nw {
                let (ilen, n) = read_compact_size(&buf[off..])?;
                off += n;
                let ilen = ilen as usize;
                if buf.len() < off + ilen {
                    return Err(StoreError::Corrupt("witness item truncated"));
                }
                witness.push(buf[off..off + ilen].to_vec());
                off += ilen;
            }
            witness
        };
        Ok((
            Self {
                prev_txid: [0u8; 32],
                create_fk,
                prev_index,
                sequence,
                script_sig,
                witness,
            },
            off,
        ))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        let (rec, used) = Self::decode_at(buf)?;
        if used != buf.len() {
            return Err(StoreError::Corrupt("input trailing bytes"));
        }
        Ok(rec)
    }

    /// Capacity upper bound for encode buffers (not byte-exact).
    pub fn encoded_len(&self) -> usize {
        1 + 8
            + 9
            + 4
            + 9
            + self.script_sig.len()
            + 9
            + self.witness.iter().map(|i| 9 + i.len()).sum::<usize>()
    }

    /// Exact on-wire length matching [`Self::encode_into`] (for denserels layout).
    #[inline]
    pub fn encoded_len_exact(&self) -> usize {
        use crate::compact::compact_size_len;
        let null_prev = self.create_fk.is_null() && self.prev_index == u32::MAX;
        let mut n = 1usize;
        if !null_prev {
            n += 8;
            n += compact_size_len(u64::from(self.prev_index));
        }
        if self.sequence != u32::MAX {
            n += 4;
        }
        if !self.script_sig.is_empty() {
            n += compact_size_len(self.script_sig.len() as u64) + self.script_sig.len();
        }
        if !self.witness.is_empty() {
            n += compact_size_len(self.witness.len() as u64);
            for item in &self.witness {
                n += compact_size_len(item.len() as u64) + item.len();
            }
        }
        n
    }
}

/// Encode a per-tx input run (concat of compact inputs; count lives on TxRecord).
pub(super) fn encode_input_run_secret(
    recs: &[InputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    for r in recs {
        let start = out.len();
        r.encode_into(out);
        if let Some(sec) = secret {
            xor_script_regions_in_input(out, start, sec);
        }
    }
}

/// XOR script_sig + witness item bytes inside an already-encoded input record.
pub(super) fn xor_script_regions_in_input(
    buf: &mut [u8],
    start: usize,
    secret: &crate::store_secret::StoreSecret,
) {
    if start >= buf.len() {
        return;
    }
    let flags = buf[start];
    let mut off = start + 1;
    let null_prev = flags & input_flags::NULL_PREV != 0;
    if !null_prev {
        if off + 8 > buf.len() {
            return;
        }
        off += 8;
        let Ok((vout, n)) = read_compact_size(&buf[off..]) else {
            return;
        };
        let _ = vout;
        off += n;
    }
    if flags & input_flags::SEQ_FINAL == 0 {
        off += 4;
    }
    if flags & input_flags::EMPTY_SCRIPT == 0 {
        let Ok((slen, n)) = read_compact_size(&buf[off..]) else {
            return;
        };
        off += n;
        let slen = slen as usize;
        if off + slen > buf.len() {
            return;
        }
        secret.xor_bytes(0, &mut buf[off..off + slen]);
        off += slen;
    }
    if flags & input_flags::EMPTY_WITNESS == 0 {
        let Ok((nw, n)) = read_compact_size(&buf[off..]) else {
            return;
        };
        off += n;
        for wi in 0..nw {
            let Ok((ilen, n)) = read_compact_size(&buf[off..]) else {
                return;
            };
            off += n;
            let ilen = ilen as usize;
            if off + ilen > buf.len() {
                return;
            }
            secret.xor_bytes(
                u64::from(wi as u32).saturating_add(1) << 16,
                &mut buf[off..off + ilen],
            );
            off += ilen;
        }
    }
}

/// XOR scriptPubKey bytes inside an already-encoded `txout` output record.
pub(super) fn xor_script_region_in_output(
    buf: &mut [u8],
    start: usize,
    secret: &crate::store_secret::StoreSecret,
) {
    if start >= buf.len() {
        return;
    }
    let kind = buf[start] & 0x0f;
    let mut off = start + 1;
    loop {
        if off >= buf.len() {
            return;
        }
        let b = buf[off];
        off += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    if off > buf.len() {
        return;
    }
    xor_script_kind_v17_payload(kind, &mut buf[off..], secret);
}

/// XOR the at-rest v17 script payload (hash/data only; CompactSize stays plaintext).
pub(super) fn xor_script_kind_v17_payload(
    kind: u8,
    disk: &mut [u8],
    secret: &crate::store_secret::StoreSecret,
) {
    use crate::compact::{
        read_compact_size, SCRIPT_KIND_V17_EMPTY, SCRIPT_KIND_V17_OP_RETURN_PUSH,
        SCRIPT_KIND_V17_OP_TRUE, SCRIPT_KIND_V17_P2A, SCRIPT_KIND_V17_P2PKH, SCRIPT_KIND_V17_P2SH,
        SCRIPT_KIND_V17_P2TR, SCRIPT_KIND_V17_P2WPKH, SCRIPT_KIND_V17_P2WSH, SCRIPT_KIND_V17_RAW,
    };
    match kind {
        SCRIPT_KIND_V17_EMPTY | SCRIPT_KIND_V17_OP_TRUE | SCRIPT_KIND_V17_P2A => {}
        SCRIPT_KIND_V17_P2PKH | SCRIPT_KIND_V17_P2SH | SCRIPT_KIND_V17_P2WPKH
            if disk.len() >= 20 =>
        {
            secret.xor_bytes(0, &mut disk[..20]);
        }
        SCRIPT_KIND_V17_P2WSH | SCRIPT_KIND_V17_P2TR if disk.len() >= 32 => {
            secret.xor_bytes(0, &mut disk[..32]);
        }
        SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
            if let Ok((slen, n)) = read_compact_size(disk) {
                let slen = slen as usize;
                if n + slen <= disk.len() {
                    secret.xor_bytes(0, &mut disk[n..n + slen]);
                }
            }
        }
        _ => {}
    }
}

/// Decode `count` inputs; returns records + bytes consumed (allows trailing data).
pub fn decode_input_run_prefix(
    buf: &[u8],
    count: u32,
) -> Result<(Vec<InputRecord>, usize), StoreError> {
    let mut out = Vec::with_capacity(count as usize);
    let mut off = 0;
    for _ in 0..count {
        let (rec, used) = InputRecord::decode_at(&buf[off..])?;
        off += used;
        out.push(rec);
    }
    Ok((out, off))
}

/// OS page size (legacy constant; body packing is 8-byte aligned only in schema 13).
pub const BODY_PAGE_SIZE: u64 = 4096;

/// Encode `txout.body` payload (schema **17**): thin meta || output_run.
///
/// Inputs/witness go to [`encode_inwit_with_secret`]. Spender slots go to
/// [`encode_spent_zeros`]. `inputs` is accepted for call-site compatibility
/// (count assert only).
pub fn encode_packed_tx(
    tx: &TxRecord,
    inputs: &[InputRecord],
    outputs: &[OutputRecord],
    out: &mut Vec<u8>,
) {
    encode_packed_tx_with_secret(tx, inputs, outputs, out, None);
}

/// Encode `txout` with optional at-rest XOR of scriptPubKey.
pub fn encode_packed_tx_with_secret(
    tx: &TxRecord,
    inputs: &[InputRecord],
    outputs: &[OutputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    debug_assert_eq!(inputs.len() as u32, tx.input_count);
    debug_assert_eq!(outputs.len() as u32, tx.output_count);
    let mut meta = tx.clone();
    meta.input_start_fk = Fk::NULL;
    meta.output_start_fk = Fk::NULL;
    meta.encode_body_meta_into(out);
    encode_output_run_secret(outputs, out, secret);
}

/// Encode `inwit.body` payload (input-side + witness).
pub fn encode_inwit_with_secret(
    inputs: &[InputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    encode_input_run_secret(inputs, out, secret);
}

/// Encode a `spent.body` run (`8 × n_out` bytes) with optional sole-spender overlays.
///
/// Duplicate `vout` last-wins. `vout >= n_out` or `fk ≥ 2^56` is Corrupt.
pub fn encode_spent_slots(
    n_out: u32,
    pairs: &[(u32, Fk)],
    out: &mut Vec<u8>,
) -> Result<(), StoreError> {
    let n = (n_out as usize).saturating_mul(OutputRecord::SPENT_SLOT_LEN);
    let start = out.len();
    out.resize(start.saturating_add(n), 0);
    for &(vout, fk) in pairs {
        if vout >= n_out {
            return Err(StoreError::Corrupt("spent overlay vout"));
        }
        let slot = encode_spent_slot_v17(0, fk)?;
        let off =
            start.saturating_add((vout as usize).saturating_mul(OutputRecord::SPENT_SLOT_LEN));
        out[off..off + OutputRecord::SPENT_SLOT_LEN].copy_from_slice(&slot);
    }
    Ok(())
}

/// Encode a zeroed `spent.body` run (`8 × n_out` bytes).
pub fn encode_spent_zeros(n_out: u32, out: &mut Vec<u8>) {
    encode_spent_slots(n_out, &[], out).expect("empty spent overlay");
}

/// Published `spent.body` span for one create (zero-out still pays 8 B pad).
#[inline]
pub fn spent_record_len(n_out: u32) -> u64 {
    u64::from(n_out.max(1)).saturating_mul(OutputRecord::SPENT_SLOT_LEN as u64)
}

/// Schema-17 spent slot width (same as [`OutputRecord::SPENT_SLOT_LEN`]).
pub const SPENT_SLOT_V17_LEN: usize = 8;
const SPENT_FIELD_V17_MAX: u64 = (1u64 << 56) - 1;

fn check_inwit_flags(flags: u8) -> Result<(), StoreError> {
    if flags & (input_flags::RESERVED4 | input_flags::RESERVED_HIGH) != 0 {
        return Err(StoreError::Corrupt("inwit reserved flags"));
    }
    Ok(())
}

fn check_spent_flags(flags: u8) -> Result<(), StoreError> {
    if flags & !output_flags::MULTI_SPENDER != 0 {
        return Err(StoreError::Corrupt("v17 spent reserved flags"));
    }
    Ok(())
}

/// Encode flags + u56 spender field. `fk ≥ 2^56` is Corrupt.
pub fn encode_spent_slot_v17(flags: u8, field: Fk) -> Result<[u8; 8], StoreError> {
    check_spent_flags(flags)?;
    if field.0 > SPENT_FIELD_V17_MAX {
        return Err(StoreError::Corrupt("v17 spent field exceeds u56"));
    }
    let mut slot = [0u8; 8];
    slot[0] = flags;
    let le = field.0.to_le_bytes();
    slot[1..8].copy_from_slice(&le[..7]);
    Ok(slot)
}

/// Decode an 8-byte v17 spent slot.
pub fn decode_spent_slot_v17(raw: &[u8]) -> Result<(u8, Fk), StoreError> {
    if raw.len() < SPENT_SLOT_V17_LEN {
        return Err(StoreError::Corrupt("short v17 spent slot"));
    }
    let flags = raw[0];
    check_spent_flags(flags)?;
    let mut le = [0u8; 8];
    le[..7].copy_from_slice(&raw[1..8]);
    Ok((flags, Fk(u64::from_le_bytes(le))))
}

/// Spent abs for `vout` given the create's `spent.body` range start.
#[inline]
pub fn spent_abs(spent_off: u64, vout: u32) -> u64 {
    spent_off.saturating_add(u64::from(vout).saturating_mul(OutputRecord::SPENT_SLOT_LEN as u64))
}

/// Decode `inwit.body` payload into input records (script_sig + witness).
pub fn decode_inwit_secret(
    raw: &[u8],
    in_count: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<Vec<InputRecord>, StoreError> {
    if in_count == 0 {
        return Ok(Vec::new());
    }
    let (mut inputs, used) = decode_input_run_prefix(raw, in_count)?;
    check_trailing_zero_pad(raw, used)?;
    if let Some(sec) = secret {
        for inp in &mut inputs {
            if !inp.script_sig.is_empty() {
                sec.xor_bytes(0, &mut inp.script_sig);
            }
            for (wi, item) in inp.witness.iter_mut().enumerate() {
                sec.xor_bytes(u64::from(wi as u32).saturating_add(1) << 16, item);
            }
        }
    }
    if inputs.len() as u32 != in_count {
        return Err(StoreError::Corrupt("inwit count mismatch"));
    }
    Ok(inputs)
}

/// After walking a packed payload to `logical_end`, accept only zero pad to `raw.len()`.
#[inline]
pub(super) fn check_trailing_zero_pad(raw: &[u8], logical_end: usize) -> Result<(), StoreError> {
    if logical_end > raw.len() {
        return Err(StoreError::Corrupt("packed Class A short payload"));
    }
    if raw[logical_end..].iter().any(|&b| b != 0) {
        return Err(StoreError::Corrupt("packed Class A trailing non-zero"));
    }
    Ok(())
}

/// Decode `txout` with optional de-obfuscation of scriptPubKey.
pub fn decode_packed_tx_with_spender_rels_secret(
    raw: &[u8],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<super::PackedTxRels, StoreError> {
    let (meta, outputs, rels) = decode_packed_tx_outs_with_spender_rels_secret(raw, secret)?;
    Ok((meta, Vec::new(), outputs, rels))
}

/// True when every `need_vouts` entry `skip_at`s inside `raw`.
///
/// Empty need is all outs. Stops after the last needed vout so a truncated
/// first page can skip a full-span extend.
pub fn txout_first_page_covers_need(raw: &[u8], need_vouts: &[u32]) -> bool {
    let Ok((meta, mut off)) = TxRecord::decode_body_meta(raw) else {
        return false;
    };
    let take_all = need_vouts.is_empty();
    let mut need_i = 0usize;
    for vout in 0..meta.output_count {
        if !take_all && need_i == need_vouts.len() {
            return true;
        }
        match OutputRecord::skip_at(&raw[off..]) {
            Ok(n) => off += n,
            Err(_) => return false,
        }
        if !take_all && need_i < need_vouts.len() && need_vouts[need_i] == vout {
            need_i = need_i.saturating_add(1);
        }
    }
    take_all || need_i == need_vouts.len()
}

/// Prevout edges from an `inwit.body` payload (`in_count` from `txout` meta).
///
/// Each edge is `(create_fk, vout)`; coinbase → `(Fk::NULL, u32::MAX)`.
pub fn scan_inwit_prevouts(raw: &[u8], in_count: u32) -> Result<Vec<(Fk, u32)>, StoreError> {
    let mut off = 0usize;
    let mut prevouts = Vec::with_capacity(in_count as usize);
    for _ in 0..in_count {
        let (create_fk, prev_index, used) = InputRecord::decode_prevout_at(&raw[off..])?;
        off += used;
        prevouts.push((create_fk, prev_index));
    }
    Ok(prevouts)
}

/// Decode packed `txout` body (meta + outputs) plus dense relative offsets of each
/// output's start within the packed txout payload.
pub fn decode_packed_tx_outs_with_spender_rels(
    raw: &[u8],
) -> Result<(TxRecord, Vec<OutputRecord>, Vec<u32>), StoreError> {
    decode_packed_tx_outs_with_spender_rels_secret(raw, None)
}

pub fn decode_packed_tx_outs_with_spender_rels_secret(
    raw: &[u8],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<(TxRecord, Vec<OutputRecord>, Vec<u32>), StoreError> {
    let (meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let n_out = meta.output_count as usize;
    let mut outputs = Vec::with_capacity(n_out);
    let mut spender_rels = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        if off >= raw.len() {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        spender_rels.push(off as u32);
        let (mut rec, used) = OutputRecord::decode_at_secret(&raw[off..], secret)?;
        off += used;
        rec.spender_field = Fk::NULL;
        rec.multi_spender = false;
        outputs.push(rec);
    }
    check_trailing_zero_pad(raw, off)?;
    if outputs.len() as u32 != meta.output_count {
        return Err(StoreError::Corrupt("packed Class A count mismatch"));
    }
    Ok((meta, outputs, spender_rels))
}

/// BIP341 P2TR outs only: no `OutputRecord` heap, no script alloc for other types.
///
/// `(vout, x-only, value_sats)`. Used by thin BIP-352 serve.
pub fn scan_packed_p2tr_outs(
    raw: &[u8],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<Vec<(u32, [u8; 32], u64)>, StoreError> {
    let (meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let mut out = Vec::new();
    for vout in 0..meta.output_count {
        if off >= raw.len() {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        if raw.len() - off < 2 {
            return Err(StoreError::Corrupt("short output record"));
        }
        let kind = raw[off] & 0x0f;
        let mut o = off + 1;
        let (v, n) = read_uleb128(&raw[o..])?;
        o += n;
        let value = if v > i64::MAX as u64 {
            return Err(StoreError::Corrupt("output value too large"));
        } else {
            v
        };
        let used = crate::compact::script_kind_v17_disk_used(kind, &raw[o..])?;
        if kind == crate::compact::SCRIPT_KIND_V17_P2TR && used == 32 {
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&raw[o..o + 32]);
            if let Some(sec) = secret {
                sec.xor_bytes(0, &mut xonly);
            }
            out.push((vout, xonly, value));
        }
        off = o + used;
    }
    check_trailing_zero_pad(raw, off)?;
    Ok(out)
}

/// SHA256(scriptPubKey) for every packed out. No `OutputRecord` vec.
pub fn visit_packed_script_hashes(
    raw: &[u8],
    secret: Option<&crate::store_secret::StoreSecret>,
    mut f: impl FnMut([u8; 32]) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let (meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let mut payload = Vec::new();
    for _ in 0..meta.output_count {
        if off >= raw.len() || raw.len() - off < 1 {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        let flags = raw[off];
        if flags & 0xf0 != 0 {
            return Err(StoreError::Corrupt("v17 txout reserved output flags"));
        }
        let kind = flags & 0x0f;
        let mut o = off + 1;
        let (_v, n) = read_uleb128(&raw[o..])?;
        o += n;
        let used = crate::compact::script_kind_v17_disk_used(kind, &raw[o..])?;
        payload.clear();
        payload.extend_from_slice(&raw[o..o + used]);
        if let Some(sec) = secret {
            xor_script_kind_v17_payload(kind, &mut payload, sec);
        }
        let script = crate::compact::decode_script_kind_v17(kind, &payload)?.0;
        f(crate::scripthash::script_hash(&script))?;
        off = o + used;
    }
    check_trailing_zero_pad(raw, off)?;
    Ok(())
}

/// Sparse pin decode: only materialize `need_vouts` scripts + denserel slots.
///
/// Non-empty `need_vouts` (sorted unique) walks through the last needed vout
/// and returns; later outs and trailing pad are not required. Empty need
/// walks every out and checks trailing zero pad (same as full denserels).
pub fn decode_packed_tx_need_outs_with_spender_rels_secret(
    raw: &[u8],
    need_vouts: &[u32],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<super::SparseOutsRow, StoreError> {
    let (meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let n_out = meta.output_count;
    // Empty need → all vouts (full materialize path without a second full decode).
    let take_all = need_vouts.is_empty();
    let mut need_i = 0usize;
    let mut live = Vec::with_capacity(if take_all {
        n_out as usize
    } else {
        need_vouts.len()
    });
    let mut sparse = Vec::with_capacity(live.capacity());
    for vout in 0..n_out {
        if off >= raw.len() {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        let rel = off as u32;
        let want = take_all || (need_i < need_vouts.len() && need_vouts[need_i] == vout);
        if want {
            let (mut rec, used) = OutputRecord::decode_at_secret(&raw[off..], secret)?;
            off += used;
            rec.spender_field = Fk::NULL;
            rec.multi_spender = false;
            live.push((vout, rec));
            sparse.push((vout, rel));
            if !take_all {
                need_i = need_i.saturating_add(1);
                if need_i == need_vouts.len() {
                    return Ok((meta, live, sparse));
                }
            }
        } else {
            off += OutputRecord::skip_at(&raw[off..])?;
        }
    }
    if !take_all && need_i != need_vouts.len() {
        return Err(StoreError::Corrupt(
            "packed need_vouts missing (vout past output_count)",
        ));
    }
    check_trailing_zero_pad(raw, off)?;
    Ok((meta, live, sparse))
}

/// Segmented `tx.head` occupancy for IBD size logs.
///
/// Name is historical (`HeadResizeSizeSnapshot`); there is no shadow resize.
#[derive(Clone, Copy, Debug, Default)]
pub struct HeadResizeSizeSnapshot {
    pub class_a_n: u64,
    pub primary_bits: u32,
    pub primary_slots: u64,
    pub primary_entry_b: u8,
    pub primary_occupied: u64,
    /// Logical size of one segment head file (`slots × entry_bytes`).
    pub primary_body_bytes: u64,
    pub segment_count: u64,
    pub sealed_segments: u64,
    /// In-RAM sealed fuse8 fingerprints (process heap).
    pub fuse8_bytes: u64,
    /// In-RAM BDZ `g` arrays (0 after FdOnly open).
    pub mphf_g_bytes: u64,
    /// Open-segment fuse-key Vec (`count × 8`).
    pub open_keys_bytes: u64,
    /// Class C L2 images (strong_tx + confirmed + header_txs).
    pub class_c_l2_bytes: u64,
}

#[cfg(test)]
mod scan_p2tr_tests {
    use super::*;
    use crate::compact::{write_uleb128, SCRIPT_KIND_V17_P2TR};

    fn packed_p2tr_body(value: u64) -> Vec<u8> {
        let meta = TxRecord {
            txid: [0u8; 32],
            version: 2,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let mut raw = Vec::new();
        meta.encode_body_meta_into(&mut raw);
        raw.push(SCRIPT_KIND_V17_P2TR);
        write_uleb128(&mut raw, value);
        raw.extend_from_slice(&[0u8; 32]);
        raw
    }

    #[test]
    fn scan_packed_p2tr_outs_ok_value() {
        let raw = packed_p2tr_body(50_000);
        let rows = scan_packed_p2tr_outs(&raw, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 0);
        assert_eq!(rows[0].2, 50_000);
        OutputRecord::decode_at_secret(&raw[TxRecord::decode_body_meta(&raw).unwrap().1..], None)
            .unwrap();
    }

    #[test]
    fn scan_packed_p2tr_outs_overflow_is_corrupt() {
        let raw = packed_p2tr_body(i64::MAX as u64 + 1);
        let err = scan_packed_p2tr_outs(&raw, None).unwrap_err();
        assert!(format!("{err}").contains("output value too large"), "{err}");
        let meta_n = TxRecord::decode_body_meta(&raw).unwrap().1;
        let dec = OutputRecord::decode_at_secret(&raw[meta_n..], None).unwrap_err();
        assert!(format!("{dec}").contains("output value too large"), "{dec}");
    }

    fn three_out_packed() -> (Vec<u8>, usize) {
        let tx = TxRecord {
            txid: [0x11u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 3,
        };
        let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let outputs = vec![
            OutputRecord::unspent(1, vec![0x51]),
            OutputRecord::unspent(2, vec![0x52; 80]),
            OutputRecord::unspent(3, vec![0x53; 80]),
        ];
        let mut raw = Vec::new();
        encode_packed_tx(&tx, &inputs, &outputs, &mut raw);
        let (_, mut off) = TxRecord::decode_body_meta(&raw).unwrap();
        off += OutputRecord::skip_at(&raw[off..]).unwrap();
        (raw, off)
    }

    #[test]
    fn decode_packed_tx_need_outs_truncated_after_last_need() {
        let (raw, after_vout0) = three_out_packed();
        let truncated = &raw[..after_vout0];
        let (meta, live, sparse) =
            decode_packed_tx_need_outs_with_spender_rels_secret(truncated, &[0], None).unwrap();
        assert_eq!(meta.output_count, 3);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, 0);
        assert_eq!(live[0].1.script, vec![0x51]);
        assert_eq!(sparse.len(), 1);
        assert_eq!(sparse[0].0, 0);
        let empty_need = decode_packed_tx_need_outs_with_spender_rels_secret(truncated, &[], None);
        assert!(
            empty_need.is_err(),
            "empty need still requires a full outs walk"
        );
        assert!(txout_first_page_covers_need(truncated, &[0]));
        assert!(!txout_first_page_covers_need(truncated, &[]));
    }

    #[test]
    fn decode_packed_tx_need_outs_empty_need_still_pad_checks() {
        let (mut raw, _) = three_out_packed();
        raw.push(0x01);
        let err = decode_packed_tx_need_outs_with_spender_rels_secret(&raw, &[], None).unwrap_err();
        assert!(format!("{err}").contains("trailing non-zero"), "{err}");
        let (meta, live, _) =
            decode_packed_tx_need_outs_with_spender_rels_secret(&raw[..raw.len() - 1], &[0], None)
                .unwrap();
        assert_eq!(meta.output_count, 3);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, 0);
    }
}
