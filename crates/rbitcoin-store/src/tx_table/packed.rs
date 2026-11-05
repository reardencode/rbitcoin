//! Packed tx body encode/decode (schema Class A payload).

use super::*;
use rbitcoin_primitives::{read_compact_size, write_compact_size};

/// Encode a per-tx output run (concat of compact outputs; count is loc `n_out`).
pub fn encode_output_run_secret(
    recs: &[OutputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    for r in recs {
        encode_unspent_output_into_secret(r.value, &r.script, out, secret);
    }
}

/// Encode one unspent output (optional at-rest XOR of scriptPubKey).
pub fn encode_unspent_output_into_secret(
    value: u64,
    script: &[u8],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    let start = out.len();
    OutputRecord::encode_unspent_into(value, script, out);
    if let Some(sec) = secret {
        xor_script_region_in_output(out, start, sec);
    }
}

/// Class A append pin: tx meta + outs (records or encode-from-wire).
pub trait PackedCreate {
    fn packed_txid(&self) -> [u8; 32];
    fn packed_tx(&self) -> &TxRecord;
    fn packed_n_out(&self) -> u32;
    fn packed_outs_est(&self) -> usize;
    fn encode_txout_body(
        &self,
        buf: &mut Vec<u8>,
        secret: Option<&crate::store_secret::StoreSecret>,
    );
}

impl<T: PackedCreate + ?Sized> PackedCreate for std::sync::Arc<T> {
    #[inline]
    fn packed_txid(&self) -> [u8; 32] {
        (**self).packed_txid()
    }
    #[inline]
    fn packed_tx(&self) -> &TxRecord {
        (**self).packed_tx()
    }
    #[inline]
    fn packed_n_out(&self) -> u32 {
        (**self).packed_n_out()
    }
    #[inline]
    fn packed_outs_est(&self) -> usize {
        (**self).packed_outs_est()
    }
    fn encode_txout_body(
        &self,
        buf: &mut Vec<u8>,
        secret: Option<&crate::store_secret::StoreSecret>,
    ) {
        (**self).encode_txout_body(buf, secret);
    }
}

impl PackedCreate for std::sync::Arc<(TxRecord, Vec<OutputRecord>)> {
    #[inline]
    fn packed_txid(&self) -> [u8; 32] {
        self.0.txid
    }
    #[inline]
    fn packed_tx(&self) -> &TxRecord {
        &self.0
    }
    #[inline]
    fn packed_n_out(&self) -> u32 {
        self.1.len() as u32
    }
    #[inline]
    fn packed_outs_est(&self) -> usize {
        16 + TxRecord::BODY_META_LEN + self.1.iter().map(|o| o.encoded_len()).sum::<usize>()
    }
    fn encode_txout_body(
        &self,
        buf: &mut Vec<u8>,
        secret: Option<&crate::store_secret::StoreSecret>,
    ) {
        encode_txout_meta_and_outs(&self.0, &self.1, buf, secret);
    }
}

/// Parent edge after decode. A null fk is only coinbase or not-yet-stamped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputParent {
    /// `PREV_ON_INPUTS`: `input.body` has not been applied.
    Unstamped,
    /// Legacy `NULL_PREV` / consensus coinbase null prevout.
    Coinbase,
    /// Wire input whose Class A parent fk is not known yet. Vout is the wire index.
    Unlinked { vout: u32 },
    /// Non-null parent create.
    Prevout { create_fk: Fk, vout: u32 },
}

impl InputParent {
    pub fn create_fk(self) -> Fk {
        match self {
            Self::Prevout { create_fk, .. } => create_fk,
            Self::Coinbase | Self::Unstamped | Self::Unlinked { .. } => Fk::NULL,
        }
    }

    pub fn prev_index(self) -> u32 {
        match self {
            Self::Prevout { vout, .. } | Self::Unlinked { vout } => vout,
            Self::Coinbase => u32::MAX,
            Self::Unstamped => 0,
        }
    }

    pub fn is_coinbase(self) -> bool {
        matches!(self, Self::Coinbase)
    }
}

/// Class A input + BIP141 witness.
///
/// `seqsigwit` stores sequence, scriptSig, and witness. The parent edge is
/// `input.body`. New records set [`input_flags::PREV_ON_INPUTS`] and omit
/// `create_fk` and vout. A record without that bit is the legacy layout:
/// coinbase `NULL_PREV`, otherwise `create_fk:u64` LE plus CompactSize vout.
///
/// [`Self::prev_txid`] is a soft cache for wire rebuild. Encoding never writes it.
/// [`Self::parent`] on a new record is filled from `input.body` after decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputRecord {
    /// Soft: wire txid of parent create (`[0;32]` if unknown / coinbase).
    pub prev_txid: [u8; 32],
    pub parent: InputParent,
    pub sequence: u32,
    pub script_sig: Vec<u8>,
    /// Witness stack items (empty = no witness).
    pub witness: Vec<Vec<u8>>,
}

impl InputRecord {
    pub fn parent(&self) -> InputParent {
        self.parent
    }

    pub fn is_coinbase(&self) -> bool {
        self.parent.is_coinbase()
    }

    pub fn create_fk(&self) -> Fk {
        self.parent.create_fk()
    }

    pub fn prev_index(&self) -> u32 {
        self.parent.prev_index()
    }

    /// Stamp a resolved Class A parent. Keeps the wire vout already on this record.
    pub fn stamp_create_fk(&mut self, create_fk: Fk) {
        debug_assert!(!create_fk.is_null());
        let vout = self.prev_index();
        self.parent = InputParent::Prevout { create_fk, vout };
    }

    /// Non-null parent. `create_fk` must not be null.
    pub fn prevout(
        prev_txid: [u8; 32],
        create_fk: Fk,
        vout: u32,
        sequence: u32,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
    ) -> Self {
        debug_assert!(!create_fk.is_null());
        Self {
            prev_txid,
            parent: InputParent::Prevout { create_fk, vout },
            sequence,
            script_sig,
            witness,
        }
    }

    /// `PREV_ON_INPUTS` before [`apply_input_edges`].
    pub fn unstamped(
        prev_txid: [u8; 32],
        sequence: u32,
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            prev_txid,
            parent: InputParent::Unstamped,
            sequence,
            script_sig,
            witness,
        }
    }

    /// Coinbase null prevout.
    pub fn coinbase(sequence: u32, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Self {
        Self {
            prev_txid: [0u8; 32],
            parent: InputParent::Coinbase,
            sequence,
            script_sig,
            witness,
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        encode_seqsigwit_input(
            self.sequence,
            &self.script_sig,
            self.witness.iter().map(Vec::as_slice),
            out,
        );
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Skip past one legacy input after reading its inline prevout.
    ///
    /// Returns `(create_fk, prev_index, bytes_consumed)`. Coinbase → `(NULL, u32::MAX, …)`.
    /// A [`input_flags::PREV_ON_INPUTS`] record has no prevout here.
    pub fn decode_prevout_at(buf: &[u8]) -> Result<(Fk, u32, usize), StoreError> {
        if buf.is_empty() {
            return Err(StoreError::Corrupt("short input record"));
        }
        let flags = buf[0];
        let mut off = 1usize;
        check_seqsigwit_flags(flags)?;
        let Some((create_fk, prev_index)) = read_inline_prevout(buf, flags, &mut off)? else {
            return Err(StoreError::Corrupt("seqsigwit prevout is on inputs"));
        };
        skip_seq_script_witness(buf, flags, &mut off)?;
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
        check_seqsigwit_flags(flags)?;
        let parent = match read_inline_prevout(buf, flags, &mut off)? {
            Some((create_fk, prev_index)) => {
                if create_fk.is_null() {
                    if prev_index != u32::MAX {
                        return Err(StoreError::Corrupt("invariant: input parent sentinel"));
                    }
                    InputParent::Coinbase
                } else {
                    InputParent::Prevout {
                        create_fk,
                        vout: prev_index,
                    }
                }
            }
            None => InputParent::Unstamped,
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
            if !u64_span_fits(buf.len(), off, slen) {
                return Err(StoreError::Corrupt("input script truncated"));
            }
            let slen = slen as usize;
            let s = buf[off..off + slen].to_vec();
            off += slen;
            s
        };
        let witness = if flags & input_flags::EMPTY_WITNESS != 0 {
            Vec::new()
        } else {
            let (nw, n) = read_compact_size(&buf[off..])?;
            off += n;
            if !u64_span_fits(buf.len(), off, nw) {
                return Err(StoreError::Corrupt("witness item truncated"));
            }
            let mut witness = Vec::with_capacity(nw as usize);
            for _ in 0..nw {
                let (ilen, n) = read_compact_size(&buf[off..])?;
                off += n;
                if !u64_span_fits(buf.len(), off, ilen) {
                    return Err(StoreError::Corrupt("witness item truncated"));
                }
                let ilen = ilen as usize;
                witness.push(buf[off..off + ilen].to_vec());
                off += ilen;
            }
            witness
        };
        Ok((
            Self {
                prev_txid: [0u8; 32],
                parent,
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
        seqsigwit_input_len_upper(self.script_sig.len(), self.witness.iter().map(|i| i.len()))
    }

    /// Exact on-wire length matching [`Self::encode_into`] (for denserels layout).
    pub fn encoded_len_exact(&self) -> usize {
        use rbitcoin_primitives::compact_size_len;
        let mut n = 1usize;
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

/// Same flags and payload as [`InputRecord::encode_into`].
#[doc(hidden)]
pub fn encode_seqsigwit_input<'a>(
    sequence: u32,
    script_sig: &[u8],
    witness: impl ExactSizeIterator<Item = &'a [u8]>,
    out: &mut Vec<u8>,
) {
    let mut flags = input_flags::PREV_ON_INPUTS;
    if sequence == u32::MAX {
        flags |= input_flags::SEQ_FINAL;
    }
    if script_sig.is_empty() {
        flags |= input_flags::EMPTY_SCRIPT;
    }
    if witness.len() == 0 {
        flags |= input_flags::EMPTY_WITNESS;
    }
    out.push(flags);
    if flags & input_flags::SEQ_FINAL == 0 {
        out.extend_from_slice(&sequence.to_le_bytes());
    }
    if flags & input_flags::EMPTY_SCRIPT == 0 {
        write_compact_size(out, script_sig.len() as u64);
        out.extend_from_slice(script_sig);
    }
    if flags & input_flags::EMPTY_WITNESS == 0 {
        write_compact_size(out, witness.len() as u64);
        for item in witness {
            write_compact_size(out, item.len() as u64);
            out.extend_from_slice(item);
        }
    }
}

/// Capacity upper bound matching [`InputRecord::encoded_len`] (not byte-exact).
pub fn seqsigwit_input_len_upper(
    script_len: usize,
    witness_item_lens: impl Iterator<Item = usize>,
) -> usize {
    1 + 8 + 9 + 4 + 9 + script_len + 9 + witness_item_lens.map(|n| 9 + n).sum::<usize>()
}

/// One `seqsigwit` input from wire slices, XOR included when `secret` is set.
pub fn encode_wire_seqsigwit_input<'a>(
    sequence: u32,
    script_sig: &[u8],
    witness: impl ExactSizeIterator<Item = &'a [u8]>,
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    let start = out.len();
    encode_seqsigwit_input(sequence, script_sig, witness, out);
    if let Some(sec) = secret {
        xor_script_regions_in_input(out, start, sec);
    }
}

/// Encode a per-tx input run (concat of compact inputs; count lives on TxRecord).
pub fn encode_input_run_secret(
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
pub fn xor_script_regions_in_input(
    buf: &mut [u8],
    start: usize,
    secret: &crate::store_secret::StoreSecret,
) {
    if start >= buf.len() {
        return;
    }
    let flags = buf[start];
    let mut off = start + 1;
    let inline_prev = flags & (input_flags::NULL_PREV | input_flags::PREV_ON_INPUTS) == 0;
    if inline_prev {
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
        if !u64_span_fits(buf.len(), off, slen) {
            return;
        }
        let slen = slen as usize;
        secret.xor_bytes(0, &mut buf[off..off + slen]);
        off += slen;
    }
    if flags & input_flags::EMPTY_WITNESS == 0 {
        let Ok((nw, n)) = read_compact_size(&buf[off..]) else {
            return;
        };
        off += n;
        if !u64_span_fits(buf.len(), off, nw) {
            return;
        }
        for wi in 0..nw {
            let Ok((ilen, n)) = read_compact_size(&buf[off..]) else {
                return;
            };
            off += n;
            if !u64_span_fits(buf.len(), off, ilen) {
                return;
            }
            let ilen = ilen as usize;
            secret.xor_bytes(
                u64::from(wi as u32).saturating_add(1) << 16,
                &mut buf[off..off + ilen],
            );
            off += ilen;
        }
    }
}

/// XOR scriptPubKey bytes inside an already-encoded `txout` output record.
pub fn xor_script_region_in_output(
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
pub fn xor_script_kind_v17_payload(
    kind: u8,
    disk: &mut [u8],
    secret: &crate::store_secret::StoreSecret,
) {
    use crate::compact::{
        SCRIPT_KIND_V17_EMPTY, SCRIPT_KIND_V17_OP_RETURN_PUSH, SCRIPT_KIND_V17_OP_TRUE,
        SCRIPT_KIND_V17_P2A, SCRIPT_KIND_V17_P2PKH, SCRIPT_KIND_V17_P2SH, SCRIPT_KIND_V17_P2TR,
        SCRIPT_KIND_V17_P2WPKH, SCRIPT_KIND_V17_P2WSH, SCRIPT_KIND_V17_RAW,
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
                if u64_span_fits(disk.len(), n, slen) {
                    let slen = slen as usize;
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

/// Encode `txout.body` (schema 17) with optional at-rest XOR of scriptPubKey.
///
/// Inputs and witness go to [`encode_seqsigwit_with_secret`]. Spender slots
/// go to [`encode_spent_zeros`]. `inputs` is the count assert only.
/// `secret: None` is the no-XOR path.
pub fn encode_packed_tx_with_secret(
    tx: &TxRecord,
    inputs: &[InputRecord],
    outputs: &[OutputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    debug_assert_eq!(inputs.len() as u32, tx.input_count);
    debug_assert_eq!(outputs.len() as u32, tx.output_count);
    encode_txout_meta_and_outs(tx, outputs, out, secret);
}

/// `txout.body` meta + output run (no input-count assert).
pub fn encode_txout_meta_and_outs(
    tx: &TxRecord,
    outputs: &[OutputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    debug_assert_eq!(outputs.len() as u32, tx.output_count);
    tx.encode_body_meta_into(out);
    encode_output_run_secret(outputs, out, secret);
}

/// Encode `seqsigwit.body` payload (input-side + witness).
pub fn encode_seqsigwit_with_secret(
    inputs: &[InputRecord],
    out: &mut Vec<u8>,
    secret: Option<&crate::store_secret::StoreSecret>,
) {
    encode_input_run_secret(inputs, out, secret);
}

/// Encode a `spent.body` run (`8 × n_out` bytes) with optional sole-spender overlays.
///
/// Duplicate `vout` last-wins. `vout >= n_out`, `fk ≥ 2^40`, or `vin ≥ 2^16` is Corrupt.
pub fn encode_spent_slots(
    n_out: u32,
    pairs: &[(u32, Fk, u32)],
    out: &mut Vec<u8>,
) -> Result<(), StoreError> {
    let n = (n_out as usize).saturating_mul(OutputRecord::SPENT_SLOT_LEN);
    let start = out.len();
    out.resize(start.saturating_add(n), 0);
    for &(vout, fk, vin) in pairs {
        if vout >= n_out {
            return Err(StoreError::Corrupt("spent overlay vout"));
        }
        let slot = encode_spent_slot(0, fk, vin)?;
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

/// Published `spent.body` span for one create (`8 × n_out`).
#[inline]
pub fn spent_record_len(n_out: u32) -> u64 {
    u64::from(n_out).saturating_mul(OutputRecord::SPENT_SLOT_LEN as u64)
}

#[doc(hidden)]
pub const SPENT_FK_U40_MAX: u64 = (1u64 << 40) - 1;
#[doc(hidden)]
pub const SPENT_VIN_U16_MAX: u32 = (1u32 << 16) - 1;

/// `n` bytes starting at `off` stay inside `buf_len` without wrapping the end.
#[doc(hidden)]
pub fn u64_span_fits(buf_len: usize, off: usize, n: u64) -> bool {
    match buf_len.checked_sub(off) {
        Some(rest) => n <= rest as u64,
        None => false,
    }
}

#[doc(hidden)]
pub fn check_seqsigwit_flags(flags: u8) -> Result<(), StoreError> {
    if flags & input_flags::RESERVED_HIGH != 0 {
        return Err(StoreError::Corrupt("seqsigwit reserved flags"));
    }
    Ok(())
}

#[doc(hidden)]
pub fn skip_seq_script_witness(buf: &[u8], flags: u8, off: &mut usize) -> Result<(), StoreError> {
    skip_sequence(buf, flags, off)?;
    skip_script(buf, flags, off)?;
    skip_witness(buf, flags, off)
}

#[doc(hidden)]
pub fn skip_sequence(buf: &[u8], flags: u8, off: &mut usize) -> Result<(), StoreError> {
    if flags & input_flags::SEQ_FINAL != 0 {
        return Ok(());
    }
    if buf.len() < *off + 4 {
        return Err(StoreError::Corrupt("input sequence truncated"));
    }
    *off += 4;
    Ok(())
}

#[doc(hidden)]
pub fn skip_script(buf: &[u8], flags: u8, off: &mut usize) -> Result<(), StoreError> {
    if flags & input_flags::EMPTY_SCRIPT != 0 {
        return Ok(());
    }
    let (slen, n) = read_compact_size(&buf[*off..])?;
    *off += n;
    if !u64_span_fits(buf.len(), *off, slen) {
        return Err(StoreError::Corrupt("input script truncated"));
    }
    *off += slen as usize;
    Ok(())
}

#[doc(hidden)]
pub fn skip_witness(buf: &[u8], flags: u8, off: &mut usize) -> Result<(), StoreError> {
    if flags & input_flags::EMPTY_WITNESS != 0 {
        return Ok(());
    }
    let (nw, n) = read_compact_size(&buf[*off..])?;
    *off += n;
    if !u64_span_fits(buf.len(), *off, nw) {
        return Err(StoreError::Corrupt("witness item truncated"));
    }
    for _ in 0..nw {
        skip_witness_item(buf, off)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn skip_witness_item(buf: &[u8], off: &mut usize) -> Result<(), StoreError> {
    let (ilen, n) = read_compact_size(&buf[*off..])?;
    *off += n;
    if !u64_span_fits(buf.len(), *off, ilen) {
        return Err(StoreError::Corrupt("witness item truncated"));
    }
    *off += ilen as usize;
    Ok(())
}

/// `Some` is a legacy inline prevout. `None` means [`input_flags::PREV_ON_INPUTS`].
#[doc(hidden)]
pub fn read_inline_prevout(
    buf: &[u8],
    flags: u8,
    off: &mut usize,
) -> Result<Option<(Fk, u32)>, StoreError> {
    if flags & input_flags::PREV_ON_INPUTS != 0 {
        return Ok(None);
    }
    if flags & input_flags::NULL_PREV != 0 {
        return Ok(Some((Fk::NULL, u32::MAX)));
    }
    if buf.len() < *off + 8 {
        return Err(StoreError::Corrupt("input create_fk truncated"));
    }
    let id = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
    *off += 8;
    if id == 0 {
        return Err(StoreError::Corrupt("non-coinbase create_fk is null"));
    }
    let (vout, n) = read_compact_size(&buf[*off..])?;
    *off += n;
    if vout > u64::from(u32::MAX) {
        return Err(StoreError::Corrupt("prev_index too large"));
    }
    Ok(Some((Fk(id), vout as u32)))
}

/// Fill [`InputRecord::parent`] from `input.body`. Coinbase edge → null prevout.
pub fn apply_input_edges(
    ins: &mut [InputRecord],
    edges: &[crate::input::InputEdge],
) -> Result<(), StoreError> {
    if ins.len() != edges.len() {
        return Err(StoreError::Corrupt("input edge count"));
    }
    for (inp, edge) in ins.iter_mut().zip(edges.iter()) {
        inp.parent = if edge.parent.is_null() {
            InputParent::Coinbase
        } else {
            InputParent::Prevout {
                create_fk: edge.parent,
                vout: edge.vout,
            }
        };
    }
    Ok(())
}

/// Prevouts in the shape [`scan_seqsigwit_prevouts`] returns. Coinbase → `(NULL, u32::MAX)`.
pub fn prevouts_from_edges(edges: &[crate::input::InputEdge]) -> Vec<(Fk, u32)> {
    edges
        .iter()
        .map(|e| {
            if e.parent.is_null() {
                (Fk::NULL, u32::MAX)
            } else {
                (e.parent, e.vout)
            }
        })
        .collect()
}

#[doc(hidden)]
pub fn check_spent_flags(flags: u8) -> Result<(), StoreError> {
    if flags & !output_flags::MULTI_SPENDER != 0 {
        return Err(StoreError::Corrupt("spent reserved flags"));
    }
    Ok(())
}

/// Pack spender fk + vin into 56 bits: `(vin as u64) << 40 | (fk.0 & (2^40-1))`.
pub fn pack_spent_field(fk: Fk, vin: u32) -> Result<u64, StoreError> {
    if fk.0 > SPENT_FK_U40_MAX {
        return Err(StoreError::Corrupt("spent fk exceeds u40"));
    }
    if vin > SPENT_VIN_U16_MAX {
        return Err(StoreError::Corrupt("spent vin exceeds u16"));
    }
    Ok(((vin as u64) << 40) | fk.0)
}

/// Unpack [`pack_spent_field`]. High 8 bits of the u64 must be zero.
pub fn unpack_spent_field(packed: u64) -> Result<(Fk, u32), StoreError> {
    if packed >> 56 != 0 {
        return Err(StoreError::Corrupt("spent field exceeds u56"));
    }
    Ok((Fk(packed & SPENT_FK_U40_MAX), (packed >> 40) as u32))
}

/// Encode flags + u40 spender field + u16 vin. Caps are Corrupt (no wrap).
pub fn encode_spent_slot(flags: u8, field: Fk, vin: u32) -> Result<[u8; 8], StoreError> {
    check_spent_flags(flags)?;
    let packed = pack_spent_field(field, vin)?;
    let mut slot = [0u8; 8];
    slot[0] = flags;
    let le = packed.to_le_bytes();
    slot[1..8].copy_from_slice(&le[..7]);
    Ok(slot)
}

/// Decode an 8-byte spent slot: `(flags, fk, vin)`.
pub fn decode_spent_slot(raw: &[u8]) -> Result<(u8, Fk, u32), StoreError> {
    if raw.len() < OutputRecord::SPENT_SLOT_LEN {
        return Err(StoreError::Corrupt("short spent slot"));
    }
    let flags = raw[0];
    check_spent_flags(flags)?;
    let mut le = [0u8; 8];
    le[..7].copy_from_slice(&raw[1..8]);
    let (field, vin) = unpack_spent_field(u64::from_le_bytes(le))?;
    Ok((flags, field, vin))
}

/// Spent abs for `vout` given the create's `spent.body` range start.
#[inline]
pub fn spent_abs(spent_off: u64, vout: u32) -> u64 {
    spent_off.saturating_add(u64::from(vout).saturating_mul(OutputRecord::SPENT_SLOT_LEN as u64))
}

/// Decode `seqsigwit.body` payload into input records (script_sig + witness).
pub fn decode_seqsigwit_secret(
    raw: &[u8],
    in_count: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<Vec<InputRecord>, StoreError> {
    if in_count == 0 {
        return decode_seqsigwit_secret_to_end(raw, secret);
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
    Ok(inputs)
}

pub fn decode_seqsigwit_secret_to_end(
    raw: &[u8],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<Vec<InputRecord>, StoreError> {
    let mut inputs = Vec::new();
    let mut off = 0usize;
    loop {
        if off >= raw.len() || raw[off..].iter().all(|&b| b == 0) {
            break;
        }
        let (rec, used) = InputRecord::decode_at(&raw[off..])?;
        off += used;
        inputs.push(rec);
    }
    check_trailing_zero_pad(raw, off)?;
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
    Ok(inputs)
}

/// After walking a packed payload to `logical_end`, accept only zero pad to `raw.len()`.
#[inline]
pub fn check_trailing_zero_pad(raw: &[u8], logical_end: usize) -> Result<(), StoreError> {
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
    n_out: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<super::PackedTxRels, StoreError> {
    let (meta, outputs, rels) = decode_packed_tx_outs_with_spender_rels_secret(raw, n_out, secret)?;
    Ok((meta, Vec::new(), outputs, rels))
}

/// True when every `need_vouts` entry `skip_at`s inside `raw`.
///
/// Empty need is all outs. Stops after the last needed vout so a truncated
/// first page can skip a full-span extend.
pub fn txout_first_page_covers_need(raw: &[u8], n_out: u32, need_vouts: &[u32]) -> bool {
    let Ok((meta, mut off)) = TxRecord::decode_body_meta(raw) else {
        return false;
    };
    let _ = meta;
    let take_all = need_vouts.is_empty();
    let mut need_i = 0usize;
    for vout in 0..n_out {
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

/// Prevout edges from an `seqsigwit.body` payload (`in_count` from `txout` meta).
///
/// Each edge is `(create_fk, vout)`; coinbase → `(Fk::NULL, u32::MAX)`.
pub fn scan_seqsigwit_prevouts(raw: &[u8], in_count: u32) -> Result<Vec<(Fk, u32)>, StoreError> {
    let mut off = 0usize;
    let mut prevouts = Vec::with_capacity(in_count as usize);
    for _ in 0..in_count {
        let (create_fk, prev_index, used) = InputRecord::decode_prevout_at(&raw[off..])?;
        off += used;
        prevouts.push((create_fk, prev_index));
    }
    check_trailing_zero_pad(raw, off)?;
    Ok(prevouts)
}

/// Decode packed `txout` body (meta + outputs) plus dense relative offsets of each
/// output's start within the packed txout payload.
pub fn decode_packed_tx_outs_with_spender_rels(
    raw: &[u8],
    n_out: u32,
) -> Result<(TxRecord, Vec<OutputRecord>, Vec<u32>), StoreError> {
    decode_packed_tx_outs_with_spender_rels_secret(raw, n_out, None)
}

pub fn decode_packed_tx_outs_with_spender_rels_secret(
    raw: &[u8],
    n_out: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<(TxRecord, Vec<OutputRecord>, Vec<u32>), StoreError> {
    let (mut meta, mut off) = TxRecord::decode_body_meta(raw)?;
    if n_out == 0 {
        return Err(StoreError::Corrupt("invariant: create n_out"));
    }
    meta.output_count = n_out;
    let mut outputs = Vec::with_capacity(n_out as usize);
    let mut spender_rels = Vec::with_capacity(n_out as usize);
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
    Ok((meta, outputs, spender_rels))
}

/// BIP341 P2TR outs only: no `OutputRecord` heap, no script alloc for other types.
///
/// `(vout, x-only, value_sats)`. Used by thin BIP-352 serve.
pub fn scan_packed_p2tr_outs(
    raw: &[u8],
    n_out: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<Vec<(u32, [u8; 32], u64)>, StoreError> {
    let (_meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let mut out = Vec::new();
    for vout in 0..n_out {
        if off >= raw.len() {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        if raw.len() - off < 2 {
            return Err(StoreError::Corrupt("short output record"));
        }
        let (kind, exp) = split_output_flags(raw[off])?;
        let mut o = off + 1;
        let (v, n) = decode_output_amount(exp, &raw[o..])?;
        o += n;
        let used = crate::compact::script_kind_v17_disk_used(kind, &raw[o..])?;
        if kind == crate::compact::SCRIPT_KIND_V17_P2TR && used == 32 {
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&raw[o..o + 32]);
            if let Some(sec) = secret {
                sec.xor_bytes(0, &mut xonly);
            }
            out.push((vout, xonly, v));
        }
        off = o + used;
    }
    check_trailing_zero_pad(raw, off)?;
    Ok(out)
}

/// SHA256(scriptPubKey) for every packed out. No `OutputRecord` vec.
pub fn visit_packed_script_hashes(
    raw: &[u8],
    n_out: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
    mut f: impl FnMut([u8; 32]) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    visit_packed_scripts(raw, n_out, secret, |script| {
        f(crate::scripthash::script_hash(script))
    })
}

/// Decode every output script of one packed create, in vout order.
pub fn visit_packed_scripts(
    raw: &[u8],
    n_out: u32,
    secret: Option<&crate::store_secret::StoreSecret>,
    mut f: impl FnMut(&[u8]) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let (_meta, mut off) = TxRecord::decode_body_meta(raw)?;
    let mut payload = Vec::new();
    for _ in 0..n_out {
        if off >= raw.len() || raw.len() - off < 1 {
            return Err(StoreError::Corrupt("packed outputs short"));
        }
        let flags = raw[off];
        let (kind, exp) = split_output_flags(flags)?;
        let mut o = off + 1;
        let (_v, n) = decode_output_amount(exp, &raw[o..])?;
        o += n;
        let used = crate::compact::script_kind_v17_disk_used(kind, &raw[o..])?;
        payload.clear();
        payload.extend_from_slice(&raw[o..o + used]);
        if let Some(sec) = secret {
            xor_script_kind_v17_payload(kind, &mut payload, sec);
        }
        let script = crate::compact::decode_script_kind_v17(kind, &payload)?.0;
        f(&script)?;
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
    n_out: u32,
    need_vouts: &[u32],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<super::SparseOutsRow, StoreError> {
    // Empty need → all vouts (full materialize path without a second full decode).
    decode_packed_outs(raw, n_out, need_vouts, need_vouts.is_empty(), secret, false)
}

/// Exactly `need_vouts` (sorted unique, possibly none) decoded; every other
/// output is skipped by its own length rules through the trailing pad. A row
/// a full decode rejects is `Corrupt` even when nothing is asked of it, so a
/// prevout read past the output count cannot turn corruption into a miss.
pub fn decode_packed_tx_outs_exact(
    raw: &[u8],
    n_out: u32,
    need_vouts: &[u32],
    secret: Option<&crate::store_secret::StoreSecret>,
) -> Result<super::SparseOutsRow, StoreError> {
    decode_packed_outs(raw, n_out, need_vouts, false, secret, true)
}

/// `take_all` decodes every output and ignores `need_vouts`; `through_end`
/// keeps walking after the last needed output and checks the trailing pad.
fn decode_packed_outs(
    raw: &[u8],
    n_out: u32,
    need_vouts: &[u32],
    take_all: bool,
    secret: Option<&crate::store_secret::StoreSecret>,
    through_end: bool,
) -> Result<super::SparseOutsRow, StoreError> {
    let (mut meta, mut off) = TxRecord::decode_body_meta(raw)?;
    if n_out == 0 {
        return Err(StoreError::Corrupt("invariant: create n_out"));
    }
    meta.output_count = n_out;
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
                if need_i == need_vouts.len() && !through_end {
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
    pub primary_occupied: u64,
    /// Logical size of one segment head file (`slots × 4 B`).
    pub primary_body_bytes: u64,
    pub segment_count: u64,
    pub sealed_segments: u64,
    /// Heap-owned sealed fuse8 fingerprints (**0** after mmap open/seal).
    pub fuse8_bytes: u64,
    /// In-RAM BDZ `g` arrays (0 after FdOnly open).
    pub mphf_g_bytes: u64,
    /// Mapped slot arrays of the unsealed `tx.head` segments (file-backed, not heap).
    pub head_map_bytes: u64,
    /// Compact BDZ occupancy heap (supers after mmap; 0 occ copy).
    pub mphf_occ_bytes: u64,
    /// Class C L2 images (strong_tx + confirmed + header_txs).
    pub class_c_l2_bytes: u64,
}
