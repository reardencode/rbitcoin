//! Minimal hex encode/decode (replaces the `hex` crate).

use std::fmt;

/// Failed to parse a hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexError {
    pub message: &'static str,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for HexError {}

/// Failed to parse Core / Electrum / Esplora display-order 32-byte hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayHashError {
    Hex(HexError),
    WrongLength { got: usize },
}

impl fmt::Display for DisplayHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(e) => write!(f, "{e}"),
            Self::WrongLength { got } => {
                write!(f, "hash/txid must be 32 bytes hex (got {got})")
            }
        }
    }
}

impl std::error::Error for DisplayHashError {}

impl From<HexError> for DisplayHashError {
    fn from(e: HexError) -> Self {
        Self::Hex(e)
    }
}

/// Core / Electrum / Esplora **display order** hex for a 32-byte hash or txid.
///
/// Store and rust-bitcoin `to_byte_array()` use **internal** byte order; RPC
/// clients expect the reversed hex (same as `BlockHash`/`Txid` `Display`).
pub fn display_hash_hex(h: &[u8; 32]) -> String {
    let mut rev = *h;
    rev.reverse();
    encode(rev)
}

/// Parse display-order 32-byte hex → internal byte order.
pub fn parse_display_hash32(hex: &str) -> Result<[u8; 32], DisplayHashError> {
    let mut b = decode(hex)?;
    if b.len() != 32 {
        return Err(DisplayHashError::WrongLength { got: b.len() });
    }
    b.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

/// Lowercase hex encoding of `data`.
pub fn encode(data: impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode a hex string (even length, optional `0x` prefix). Accepts a-f/A-F.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(HexError {
            message: "odd hex length",
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_digit(bytes[i])?;
        let lo = from_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn from_digit(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError {
            message: "invalid hex digit",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0u8, 1, 0xab, 0xff];
        assert_eq!(encode(data), "0001abff");
        assert_eq!(decode("0001abff").unwrap(), data);
        assert_eq!(decode("0001ABFF").unwrap(), data);
        assert_eq!(decode("0x0a").unwrap(), vec![0x0a]);
    }

    #[test]
    fn rejects_bad() {
        assert!(decode("0").is_err());
        assert!(decode("zz").is_err());
    }

    #[test]
    fn hex_error_display_and_0x_prefix() {
        let e = decode("0").unwrap_err();
        assert_eq!(format!("{e}"), "odd hex length");
        let _ = &e as &dyn std::error::Error;
        assert_eq!(decode("0Xff").unwrap(), vec![0xff]);
        assert_eq!(encode([]), "");
    }

    #[test]
    fn display_hash_roundtrips_known_internal_bytes() {
        let mut internal = [0u8; 32];
        internal[0] = 0xab;
        internal[31] = 0xcd;
        let display = "cd000000000000000000000000000000000000000000000000000000000000ab";
        assert_eq!(display_hash_hex(&internal), display);
        assert_eq!(parse_display_hash32(display).unwrap(), internal);
    }

    #[test]
    fn parse_display_hash32_rejects_odd_length_and_non_hex() {
        assert_eq!(
            parse_display_hash32("c").unwrap_err().to_string(),
            "odd hex length"
        );
        assert_eq!(
            parse_display_hash32("zz").unwrap_err().to_string(),
            "invalid hex digit"
        );
        let e = parse_display_hash32("abcd").unwrap_err();
        assert!(
            matches!(e, DisplayHashError::WrongLength { got: 2 }),
            "{e:?}"
        );
    }
}
