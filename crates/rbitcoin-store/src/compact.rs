//! Class A amount exponent and script-kind flags.
//!
//! CompactSize / ULEB128 live in `rbitcoin-primitives`. Flags collapse common
//! constant cases (final sequence, empty script/witness).

use crate::error::StoreError;
use rbitcoin_primitives::{
    read_compact_size, read_uleb128, write_compact_size, OP_EQUAL, OP_PUSHBYTES_75, OP_PUSHDATA1,
    OP_RETURN, OP_TRUE, P2A_SCRIPT, P2PKH_PREFIX, P2PKH_SUFFIX, P2SH_PREFIX, P2TR_PREFIX,
    P2WPKH_PREFIX, P2WSH_PREFIX,
};

/// Trailing decimal zeros stripped from a satoshi amount, capped at 9.
/// Nibble values 10–15 are Corrupt (soft-extend), not extra exponent.
pub const AMOUNT_EXP_MAX: u8 = 9;

#[doc(hidden)]
pub const POW10: [u64; (AMOUNT_EXP_MAX as usize) + 1] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

pub fn amount_exp_mantissa(sats: u64) -> (u8, u64) {
    if sats == 0 {
        return (0, 0);
    }
    let mut e = 0u8;
    let mut n = sats;
    while e < AMOUNT_EXP_MAX && n.is_multiple_of(10) {
        n /= 10;
        e += 1;
    }
    (e, n)
}

pub fn split_output_flags(flags: u8) -> Result<(u8, u8), StoreError> {
    let exp = flags >> 4;
    if exp > AMOUNT_EXP_MAX {
        return Err(StoreError::Corrupt("txout amount exp"));
    }
    Ok((flags & 0x0f, exp))
}

pub fn scale_amount_exp(exp: u8, mantissa: u64) -> Result<u64, StoreError> {
    if exp > AMOUNT_EXP_MAX {
        return Err(StoreError::Corrupt("txout amount exp"));
    }
    if mantissa == 0 {
        if exp != 0 {
            return Err(StoreError::Corrupt("txout amount exp"));
        }
        return Ok(0);
    }
    if exp < AMOUNT_EXP_MAX && mantissa.is_multiple_of(10) {
        return Err(StoreError::Corrupt("txout amount exp"));
    }
    mantissa
        .checked_mul(POW10[exp as usize])
        .ok_or(StoreError::Corrupt("output value too large"))
}

/// `(sats, uleb bytes)`. `buf` starts at the mantissa ULEB. Above `i64::MAX` is Corrupt.
pub fn decode_output_amount(exp: u8, buf: &[u8]) -> Result<(u64, usize), StoreError> {
    let (mantissa, n) = read_uleb128(buf)?;
    let v = scale_amount_exp(exp, mantissa)?;
    if v > i64::MAX as u64 {
        return Err(StoreError::Corrupt("output value too large"));
    }
    Ok((v, n))
}

/// Input record flags (schema v10).
pub mod input_flags {
    /// `sequence == 0xffff_ffff`
    pub const SEQ_FINAL: u8 = 1 << 0;
    /// Empty `script_sig`
    pub const EMPTY_SCRIPT: u8 = 1 << 1;
    /// Empty witness stack
    pub const EMPTY_WITNESS: u8 = 1 << 2;
    /// Legacy coinbase: no inline `create_fk` payload; `prev_index` is `u32::MAX`.
    /// New records leave the parent edge on `input.body` and set [`PREV_ON_INPUTS`] instead.
    pub const NULL_PREV: u8 = 1 << 3;
    /// Parent `create_fk` and vout are not in this record. They live on `input.body`.
    /// Bit 4 was v9 `LOCAL_PREV`, then reserved.
    pub const PREV_ON_INPUTS: u8 = 1 << 4;
    /// Bits 5–7 reserved (schema 17 freeze). Reject so a later Δfk writer
    /// cannot be silently misparsed.
    pub const RESERVED_HIGH: u8 = 0xE0;
}

/// Output record flags (schema v5).
pub mod output_flags {
    /// Empty scriptPubKey
    pub const EMPTY_SCRIPT: u8 = 1 << 0;
    /// Script is exactly `OP_TRUE` (0x51) — anyone-can-spend fixture
    pub const OP_TRUE: u8 = 1 << 1;
    /// `spender_field` is a `spent.ovf` list head (not a sole spending_tx_fk).
    pub const MULTI_SPENDER: u8 = 1 << 2;
}

/// Schema-17 `txout` script-kind nibble (bits 0–3). Production still uses
/// [`output_flags`] until Class A cutover.
pub const SCRIPT_KIND_V17_RAW: u8 = 0;
pub const SCRIPT_KIND_V17_EMPTY: u8 = 1;
pub const SCRIPT_KIND_V17_OP_TRUE: u8 = 2;
pub const SCRIPT_KIND_V17_P2PKH: u8 = 3;
pub const SCRIPT_KIND_V17_P2SH: u8 = 4;
pub const SCRIPT_KIND_V17_P2WPKH: u8 = 5;
pub const SCRIPT_KIND_V17_P2WSH: u8 = 6;
pub const SCRIPT_KIND_V17_P2TR: u8 = 7;
pub const SCRIPT_KIND_V17_OP_RETURN_PUSH: u8 = 8;
pub const SCRIPT_KIND_V17_P2A: u8 = 9;

#[doc(hidden)]
pub const SCRIPT_KIND_V17_MAX: u8 = SCRIPT_KIND_V17_P2A;

/// Classify a wire scriptPubKey into a v17 kind and template payload (no CompactSize).
pub fn classify_script(script: &[u8]) -> (u8, &[u8]) {
    if script.is_empty() {
        return (SCRIPT_KIND_V17_EMPTY, &[]);
    }
    if script == [OP_TRUE] {
        return (SCRIPT_KIND_V17_OP_TRUE, &[]);
    }
    if script == P2A_SCRIPT {
        return (SCRIPT_KIND_V17_P2A, &[]);
    }
    if script.len() == 25 && script.starts_with(&P2PKH_PREFIX) && script.ends_with(&P2PKH_SUFFIX) {
        return (SCRIPT_KIND_V17_P2PKH, &script[3..23]);
    }
    if script.len() == 23 && script.starts_with(&P2SH_PREFIX) && script[22] == OP_EQUAL {
        return (SCRIPT_KIND_V17_P2SH, &script[2..22]);
    }
    if script.len() == 22 && script.starts_with(&P2WPKH_PREFIX) {
        return (SCRIPT_KIND_V17_P2WPKH, &script[2..]);
    }
    if script.len() == 34 && script.starts_with(&P2WSH_PREFIX) {
        return (SCRIPT_KIND_V17_P2WSH, &script[2..]);
    }
    if script.len() == 34 && script.starts_with(&P2TR_PREFIX) {
        return (SCRIPT_KIND_V17_P2TR, &script[2..]);
    }
    if let Some(data) = canonical_op_return_push(script) {
        return (SCRIPT_KIND_V17_OP_RETURN_PUSH, data);
    }
    (SCRIPT_KIND_V17_RAW, script)
}

/// Expand a v17 kind + classify payload to the wire scriptPubKey.
pub fn expand_script_kind(kind: u8, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    match kind {
        SCRIPT_KIND_V17_RAW => Ok(payload.to_vec()),
        SCRIPT_KIND_V17_EMPTY => {
            if !payload.is_empty() {
                return Err(StoreError::Corrupt("v17 empty script kind has payload"));
            }
            Ok(Vec::new())
        }
        SCRIPT_KIND_V17_OP_TRUE => {
            if !payload.is_empty() {
                return Err(StoreError::Corrupt("v17 OP_TRUE kind has payload"));
            }
            Ok(vec![OP_TRUE])
        }
        SCRIPT_KIND_V17_P2PKH => {
            let h = hash160_payload(payload)?;
            let mut s = P2PKH_PREFIX.to_vec();
            s.extend_from_slice(h);
            s.extend_from_slice(&P2PKH_SUFFIX);
            Ok(s)
        }
        SCRIPT_KIND_V17_P2SH => {
            let h = hash160_payload(payload)?;
            let mut s = P2SH_PREFIX.to_vec();
            s.extend_from_slice(h);
            s.push(OP_EQUAL);
            Ok(s)
        }
        SCRIPT_KIND_V17_P2WPKH => {
            let h = hash160_payload(payload)?;
            let mut s = P2WPKH_PREFIX.to_vec();
            s.extend_from_slice(h);
            Ok(s)
        }
        SCRIPT_KIND_V17_P2WSH => {
            let h = hash256_payload(payload)?;
            let mut s = P2WSH_PREFIX.to_vec();
            s.extend_from_slice(h);
            Ok(s)
        }
        SCRIPT_KIND_V17_P2TR => {
            let h = hash256_payload(payload)?;
            let mut s = P2TR_PREFIX.to_vec();
            s.extend_from_slice(h);
            Ok(s)
        }
        SCRIPT_KIND_V17_OP_RETURN_PUSH => Ok(encode_op_return_push(payload)?),
        SCRIPT_KIND_V17_P2A => {
            if !payload.is_empty() {
                return Err(StoreError::Corrupt("v17 P2A kind has payload"));
            }
            Ok(P2A_SCRIPT.to_vec())
        }
        _ => Err(StoreError::Corrupt("v17 reserved script kind")),
    }
}

/// Write the on-disk v17 script payload (after the output value). Returns the kind.
pub fn encode_script_kind_v17(script: &[u8], out: &mut Vec<u8>) -> u8 {
    let (kind, payload) = classify_script(script);
    match kind {
        SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
            write_compact_size(out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
        _ => out.extend_from_slice(payload),
    }
    kind
}

/// Read an on-disk v17 script payload and expand it to the wire scriptPubKey.
#[doc(hidden)]
pub fn span_fits(buf_len: usize, off: usize, n: u64) -> bool {
    match buf_len.checked_sub(off) {
        Some(rest) => n <= rest as u64,
        None => false,
    }
}

pub fn decode_script_kind_v17(kind: u8, buf: &[u8]) -> Result<(Vec<u8>, usize), StoreError> {
    if kind > SCRIPT_KIND_V17_MAX {
        return Err(StoreError::Corrupt("v17 reserved script kind"));
    }
    match kind {
        SCRIPT_KIND_V17_EMPTY | SCRIPT_KIND_V17_OP_TRUE | SCRIPT_KIND_V17_P2A => {
            Ok((expand_script_kind(kind, &[])?, 0))
        }
        SCRIPT_KIND_V17_P2PKH | SCRIPT_KIND_V17_P2SH | SCRIPT_KIND_V17_P2WPKH => {
            if buf.len() < 20 {
                return Err(StoreError::Corrupt("short v17 hash160 script payload"));
            }
            Ok((expand_script_kind(kind, &buf[..20])?, 20))
        }
        SCRIPT_KIND_V17_P2WSH | SCRIPT_KIND_V17_P2TR => {
            if buf.len() < 32 {
                return Err(StoreError::Corrupt("short v17 hash256 script payload"));
            }
            Ok((expand_script_kind(kind, &buf[..32])?, 32))
        }
        SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
            let (slen, n) = read_compact_size(buf)?;
            if !span_fits(buf.len(), n, slen) {
                return Err(StoreError::Corrupt("v17 script payload truncated"));
            }
            let slen = slen as usize;
            Ok((expand_script_kind(kind, &buf[n..n + slen])?, n + slen))
        }
        _ => Err(StoreError::Corrupt("v17 reserved script kind")),
    }
}

#[doc(hidden)]
pub fn hash160_payload(payload: &[u8]) -> Result<&[u8], StoreError> {
    if payload.len() != 20 {
        return Err(StoreError::Corrupt("v17 script kind expects 20-byte hash"));
    }
    Ok(payload)
}

#[doc(hidden)]
pub fn hash256_payload(payload: &[u8]) -> Result<&[u8], StoreError> {
    if payload.len() != 32 {
        return Err(StoreError::Corrupt("v17 script kind expects 32-byte hash"));
    }
    Ok(payload)
}

/// Canonical single-push `OP_RETURN`: direct push 1..=75, or PUSHDATA1 only when n≥76.
#[doc(hidden)]
pub fn canonical_op_return_push(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&OP_RETURN) {
        return None;
    }
    let rest = &script[1..];
    let n0 = *rest.first()?;
    if (1..=OP_PUSHBYTES_75).contains(&n0) {
        let n = n0 as usize;
        if rest.len() == 1 + n {
            return Some(&rest[1..]);
        }
        return None;
    }
    if n0 == OP_PUSHDATA1 && rest.len() >= 2 {
        let n = rest[1] as usize;
        if n >= 76 && rest.len() == 2 + n {
            return Some(&rest[2..]);
        }
    }
    None
}

#[doc(hidden)]
pub fn encode_op_return_push(data: &[u8]) -> Result<Vec<u8>, StoreError> {
    if data.is_empty() || data.len() > 255 {
        return Err(StoreError::Corrupt("v17 OP_RETURN push length"));
    }
    let mut s = vec![OP_RETURN];
    if data.len() <= usize::from(OP_PUSHBYTES_75) {
        s.push(data.len() as u8);
    } else {
        s.push(OP_PUSHDATA1);
        s.push(data.len() as u8);
    }
    s.extend_from_slice(data);
    Ok(s)
}

/// On-disk payload length for a v17 script kind (no expand).
pub fn script_kind_v17_disk_used(kind: u8, buf: &[u8]) -> Result<usize, StoreError> {
    match kind {
        SCRIPT_KIND_V17_EMPTY | SCRIPT_KIND_V17_OP_TRUE | SCRIPT_KIND_V17_P2A => Ok(0),
        SCRIPT_KIND_V17_P2PKH | SCRIPT_KIND_V17_P2SH | SCRIPT_KIND_V17_P2WPKH => {
            if buf.len() < 20 {
                return Err(StoreError::Corrupt("short v17 hash160 script payload"));
            }
            Ok(20)
        }
        SCRIPT_KIND_V17_P2WSH | SCRIPT_KIND_V17_P2TR => {
            if buf.len() < 32 {
                return Err(StoreError::Corrupt("short v17 hash256 script payload"));
            }
            Ok(32)
        }
        SCRIPT_KIND_V17_RAW | SCRIPT_KIND_V17_OP_RETURN_PUSH => {
            let (slen, n) = read_compact_size(buf)?;
            if !span_fits(buf.len(), n, slen) {
                return Err(StoreError::Corrupt("v17 script payload truncated"));
            }
            Ok(n + slen as usize)
        }
        _ => Err(StoreError::Corrupt("v17 reserved script kind")),
    }
}
