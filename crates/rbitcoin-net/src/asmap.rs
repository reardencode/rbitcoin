//! Core-compatible asmap bytecode (`src/util/asmap.cpp`).
//!
//! Bits in the file are little-endian (LSB of each byte first). IP bits are
//! consumed most-significant-first. IPv4 lookups use the IPv4-mapped prefix
//! `::ffff:0:0/96` then 32 IPv4 bits (Core `GetMappedAS`).

use std::net::IpAddr;
use std::path::Path;

#[doc(hidden)]
pub const INVALID: u32 = 0xFFFFFFFF;

#[doc(hidden)]
pub const TYPE_BIT_SIZES: [u8; 3] = [0, 0, 1];
#[doc(hidden)]
pub const ASN_BIT_SIZES: [u8; 10] = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
#[doc(hidden)]
pub const MATCH_BIT_SIZES: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
#[doc(hidden)]
pub const JUMP_BIT_SIZES: [u8; 26] = [
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

#[doc(hidden)]
pub const RETURN: u32 = 0;
#[doc(hidden)]
pub const JUMP: u32 = 1;
#[doc(hidden)]
pub const MATCH: u32 = 2;
#[doc(hidden)]
pub const DEFAULT: u32 = 3;

/// Validated asmap bytecode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsMap {
    pub bytes: Vec<u8>,
}

impl AsMap {
    /// `None` when the bytes fail Core `SanityCheckAsmap` (128-bit inputs).
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if !sanity_check(&bytes) {
            return None;
        }
        Some(Self { bytes })
    }

    pub fn from_path(path: &Path) -> std::io::Result<Option<Self>> {
        let bytes = std::fs::read(path)?;
        Ok(Self::from_bytes(bytes))
    }

    // An empty file fails sanity, so a loaded map is never empty.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn interpret_ip16(&self, ip16: &[u8; 16]) -> u32 {
        interpret(self, ip16)
    }

    pub fn mapped_as(&self, ip: IpAddr) -> u32 {
        interpret(self, &ip16_for_lookup(ip))
    }

    pub fn digest_hex8(&self) -> String {
        use bitcoin::hashes::{sha256, Hash};
        let hex = sha256::Hash::hash(&self.bytes).to_string();
        hex.chars().take(8).collect()
    }
}

/// Two-prefix DecodeAsmap fixture: IPv4 `1.2.0.0/16` → ASN 1, `3.4.0.0/16` → ASN 2.
pub const TWO_PREFIX_ASMAP: &[u8] = &[
    0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0,
    0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0xff, 0xff, 0xfe, 0xff, 0xfb, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01,
];

/// `::ffff:127.0.0.1` → ASN 1, `.2` → ASN 2, `.3` → ASN 9.
///
/// Default ASN 9, a one-bit match then an eight-bit match, the shared
/// `::ffff:127.0.0.0/120` prefix, then a jump on the bit that separates `.1`
/// from `.2` and `.3`. The fall-through consumes the last IP bit and returns 1.
/// The jump target returns 2, or the default when that bit does not match (`.3`).
pub const LOOPBACK_ASMAP: &[u8] = &[
    0x07, 0x80, 0x18, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f,
    0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x07, 0xd8, 0xff, 0x7f, 0xff, 0xff, 0xfd, 0xfd,
    0xf7, 0x07, 0xd8, 0x1f, 0x60, 0x1f, 0x10, 0x3a, 0x01, 0x00, 0x0c, 0x00, 0x80,
];

/// Every address returns ASN 1. Length 3, digest `709e80c8`.
pub const LONE_RETURN_ASMAP: &[u8] = &[0x00, 0x00, 0x00];

/// A second `DEFAULT`. Sanity rejects it.
pub const ASMAP_SECOND_DEFAULT: &[u8] = &[0x07, 0x00, 0x38, 0x00, 0xc0, 0x00, 0x00, 0x08];

/// Return ASN 1 plus a trailing one bit.
pub const ASMAP_TRAILING_ONE: &[u8] = &[0x00, 0x00, 0x02];

/// Return ASN 1 plus eight trailing zero bits.
pub const ASMAP_EIGHT_TRAILING_ZEROS: &[u8] = &[0x00, 0x00, 0x00, 0x00];

/// Two one-bit matches in a row, then a return.
pub const ASMAP_TWO_SHORT_MATCHES: &[u8] = &[0x63, 0x00, 0x00, 0x00];

/// Sixteen full-byte matches, then one more match bit.
pub const ASMAP_MATCH_PAST_END: &[u8] = &[
    0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0,
    0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0,
    0x3f, 0xc0, 0xfe, 0x00, 0x03, 0x00, 0x00,
];

/// A jump of 5000 bits, then a return.
pub const ASMAP_JUMP_PAST_FILE: &[u8] = &[0xfd, 0x71, 0x3a, 0x00, 0x00];

/// A jump that leaves too few IP bits for the match after it.
pub const ASMAP_JUMP_SHORT_TAIL: &[u8] = &[
    0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0,
    0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0, 0x3f, 0xc0, 0xfe, 0x00, 0xfb, 0x03, 0xec, 0x0f, 0xb0,
    0x3f, 0x40, 0x00, 0x00, 0x80, 0xfd, 0x01, 0x00, 0x00, 0x02,
];

/// Smallest jump, with nothing after it.
pub const ASMAP_JUMP_OFF_END: &[u8] = &[0x01];

/// IPv4 as `::ffff:0:0/96` + 32 bits; IPv6 as 16 raw bytes.
pub fn ip16_for_lookup(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut a = [0u8; 16];
            a[10] = 0xff;
            a[11] = 0xff;
            a[12..16].copy_from_slice(&v4.octets());
            a
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[doc(hidden)]
pub fn consume_bit_le(bitpos: &mut usize, data: &[u8]) -> Option<bool> {
    if *bitpos >= data.len().saturating_mul(8) {
        return None;
    }
    let b = (data[*bitpos / 8] >> (*bitpos % 8)) & 1 == 1;
    *bitpos += 1;
    Some(b)
}

#[doc(hidden)]
pub fn consume_bit_be(bitpos: &mut usize, data: &[u8]) -> Option<bool> {
    if *bitpos >= data.len().saturating_mul(8) {
        return None;
    }
    let b = (data[*bitpos / 8] >> (7 - (*bitpos % 8))) & 1 == 1;
    *bitpos += 1;
    Some(b)
}

#[doc(hidden)]
pub fn decode_bits(bitpos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let mut val = minval;
    for (i, &sz) in bit_sizes.iter().enumerate() {
        let last = i + 1 == bit_sizes.len();
        let bit = if last {
            false
        } else {
            match consume_bit_le(bitpos, data) {
                Some(b) => b,
                None => break,
            }
        };
        if bit {
            val = val.saturating_add(1u32 << sz);
        } else {
            for b in 0..sz {
                let Some(bit) = consume_bit_le(bitpos, data) else {
                    return INVALID;
                };
                if bit {
                    val = val.saturating_add(1u32 << (sz - 1 - b));
                }
            }
            return val;
        }
    }
    INVALID
}

#[doc(hidden)]
pub fn decode_type(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 0, &TYPE_BIT_SIZES)
}

#[doc(hidden)]
pub fn decode_asn(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 1, &ASN_BIT_SIZES)
}

#[doc(hidden)]
pub fn decode_match(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 2, &MATCH_BIT_SIZES)
}

#[doc(hidden)]
pub fn decode_jump(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 17, &JUMP_BIT_SIZES)
}

#[doc(hidden)]
pub fn bit_width(x: u32) -> u32 {
    32 - x.leading_zeros()
}

/// Core `Interpret`. Aborts return `0` (never panic).
///
/// There is no `pos` bound. At or past the last bit, [`decode_type`] yields
/// an invalid opcode and this returns 0, the same result as stopping when
/// `pos` reaches the bit length.
pub fn interpret(asmap: &AsMap, ip16: &[u8; 16]) -> u32 {
    let bytes = asmap.bytes.as_slice();
    let mut pos = 0usize;
    let mut ip_bit = 0usize;
    let ip_bits_end = 128usize;
    let mut default_asn = 0u32;
    loop {
        let opcode = decode_type(&mut pos, bytes);
        if opcode == RETURN {
            let asn = decode_asn(&mut pos, bytes);
            if asn == INVALID {
                break;
            }
            return asn;
        } else if opcode == JUMP {
            let jump = decode_jump(&mut pos, bytes);
            if jump == INVALID {
                break;
            }
            if ip_bit == ip_bits_end {
                break;
            }
            let Some(bit) = consume_bit_be(&mut ip_bit, ip16) else {
                break;
            };
            if bit {
                pos += jump as usize;
            }
        } else if opcode == MATCH {
            let matchv = decode_match(&mut pos, bytes);
            if matchv == INVALID {
                break;
            }
            let matchlen = bit_width(matchv) as i32 - 1;
            if matchlen <= 0 {
                break;
            }
            let matchlen = matchlen as usize;
            if ip_bits_end.saturating_sub(ip_bit) < matchlen {
                break;
            }
            let mut ok = true;
            for bit in 0..matchlen {
                let Some(got) = consume_bit_be(&mut ip_bit, ip16) else {
                    ok = false;
                    break;
                };
                let want = ((matchv >> (matchlen - 1 - bit)) & 1) == 1;
                if got != want {
                    return default_asn;
                }
            }
            if !ok {
                break;
            }
        } else if opcode == DEFAULT {
            default_asn = decode_asn(&mut pos, bytes);
            if default_asn == INVALID {
                break;
            }
        } else {
            break;
        }
    }
    0
}

/// Core `SanityCheckAsmap(data, 128)`.
pub fn sanity_check(asmap: &[u8]) -> bool {
    sanity_check_bits(asmap, 128)
}

#[doc(hidden)]
pub fn sanity_return(
    pos: &mut usize,
    asmap: &[u8],
    endpos: usize,
    prevopcode: u32,
    jumps: &mut Vec<(usize, i32)>,
    bits: &mut i32,
) -> Option<bool> {
    if prevopcode == DEFAULT {
        return Some(false);
    }
    let asn = decode_asn(pos, asmap);
    if asn == INVALID {
        return Some(false);
    }
    if jumps.is_empty() {
        if endpos - *pos > 7 {
            return Some(false);
        }
        while *pos != endpos {
            match consume_bit_le(pos, asmap) {
                Some(true) => return Some(false),
                Some(false) => {}
                None => return Some(false),
            }
        }
        return Some(true);
    }
    let Some((target, restore)) = jumps.pop() else {
        return Some(false);
    };
    if *pos != target {
        return Some(false);
    }
    *bits = restore;
    None
}

#[doc(hidden)]
pub fn sanity_jump(
    pos: &mut usize,
    asmap: &[u8],
    bits: &mut i32,
    jumps: &mut Vec<(usize, i32)>,
) -> bool {
    let jump = decode_jump(pos, asmap);
    if jump == INVALID {
        return false;
    }
    // A jump to EOF or past it cannot be popped onto a finishing RETURN
    // (the target compare fails, or the walker falls off and returns false).
    if *bits == 0 {
        return false;
    }
    *bits -= 1;
    let jump_offset = *pos + jump as usize;
    if let Some(&(prev, _)) = jumps.last() {
        if jump_offset >= prev {
            return false;
        }
    }
    jumps.push((jump_offset, *bits));
    true
}

#[doc(hidden)]
pub fn sanity_match(
    pos: &mut usize,
    asmap: &[u8],
    prevopcode: u32,
    had_incomplete_match: &mut bool,
    bits: &mut i32,
) -> bool {
    let matchv = decode_match(pos, asmap);
    if matchv == INVALID {
        return false;
    }
    let matchlen = bit_width(matchv) as i32 - 1;
    if prevopcode != MATCH {
        *had_incomplete_match = false;
    }
    if matchlen < 8 && *had_incomplete_match {
        return false;
    }
    *had_incomplete_match = matchlen < 8;
    if *bits < matchlen {
        return false;
    }
    *bits -= matchlen;
    true
}

#[doc(hidden)]
pub fn sanity_check_bits(asmap: &[u8], mut bits: i32) -> bool {
    let mut pos = 0usize;
    let endpos = asmap.len().saturating_mul(8);
    let mut jumps: Vec<(usize, i32)> = Vec::new();
    let mut prevopcode = JUMP;
    let mut had_incomplete_match = false;

    while pos != endpos {
        if jumps.last().is_some_and(|&(p, _)| pos >= p) {
            return false;
        }

        let opcode = decode_type(&mut pos, asmap);
        if opcode == RETURN {
            match sanity_return(&mut pos, asmap, endpos, prevopcode, &mut jumps, &mut bits) {
                Some(done) => return done,
                None => prevopcode = JUMP,
            }
        } else if opcode == JUMP {
            if !sanity_jump(&mut pos, asmap, &mut bits, &mut jumps) {
                return false;
            }
            prevopcode = JUMP;
        } else if opcode == MATCH {
            if !sanity_match(
                &mut pos,
                asmap,
                prevopcode,
                &mut had_incomplete_match,
                &mut bits,
            ) {
                return false;
            }
            prevopcode = MATCH;
        } else if opcode == DEFAULT {
            if prevopcode == DEFAULT {
                return false;
            }
            let asn = decode_asn(&mut pos, asmap);
            if asn == INVALID {
                return false;
            }
            prevopcode = DEFAULT;
        } else {
            return false;
        }
    }
    false
}

#[cfg(debug_assertions)]
pub fn two_prefix_asmap_bytes() -> Vec<u8> {
    encode_two_prefix_asmap()
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn encode_bits(val: u32, minval: u32, bit_sizes: &[u8]) -> Vec<bool> {
    let mut x = val - minval;
    let mut out = Vec::new();
    for (i, &sz) in bit_sizes.iter().enumerate() {
        let last = i + 1 == bit_sizes.len();
        let span = 1u32 << sz;
        if !last {
            if x >= span {
                out.push(true);
                x -= span;
                continue;
            }
            out.push(false);
            for b in (0..sz).rev() {
                out.push((x >> b) & 1 == 1);
            }
            return out;
        }
        for b in (0..sz).rev() {
            out.push((x >> b) & 1 == 1);
        }
        return out;
    }
    out
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn pack_le(bits: &[bool]) -> Vec<u8> {
    if bits.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn instr_type(t: u32) -> Vec<bool> {
    encode_bits(t, 0, &TYPE_BIT_SIZES)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn instr_return(asn: u32) -> Vec<bool> {
    let mut out = instr_type(RETURN);
    out.extend(encode_bits(asn, 1, &ASN_BIT_SIZES));
    out
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn instr_jump(offset: u32) -> Vec<bool> {
    let mut out = instr_type(JUMP);
    out.extend(encode_bits(offset, 17, &JUMP_BIT_SIZES));
    out
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn instr_match(pattern: &[bool]) -> Vec<bool> {
    let n = pattern.len();
    assert!((1..=8).contains(&n));
    let mut matchv = 1u32 << n;
    for (i, &b) in pattern.iter().enumerate() {
        if b {
            matchv |= 1 << (n - 1 - i);
        }
    }
    let mut out = instr_type(MATCH);
    out.extend(encode_bits(matchv, 2, &MATCH_BIT_SIZES));
    out
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn encode_two_prefix_asmap() -> Vec<u8> {
    let mut bits = Vec::new();
    for _ in 0..10 {
        bits.extend(instr_match(&[false; 8]));
    }
    for _ in 0..2 {
        bits.extend(instr_match(&[true; 8]));
    }
    bits.extend(instr_match(&[false; 6]));
    let left = instr_return(1);
    assert_eq!(left.len(), 17);
    bits.extend(instr_jump(left.len() as u32));
    bits.extend(left);
    bits.extend(instr_return(2));
    pack_le(&bits)
}
