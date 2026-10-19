//! Bitcoin script integer encode/decode (Core scriptnum).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptNumError {
    Overflow,
    NonMinimal,
}

impl fmt::Display for ScriptNumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("scriptnum overflow"),
            Self::NonMinimal => f.write_str("SCRIPTNUM"),
        }
    }
}

impl std::error::Error for ScriptNumError {}

pub fn scriptnum_encode(mut n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if out.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = out.last_mut().unwrap();
        *last |= 0x80;
    }
    out
}

pub fn scriptnum_is_minimal(vch: &[u8]) -> bool {
    if vch.is_empty() {
        return true;
    }
    if vch[vch.len() - 1] & 0x7f == 0 && (vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0) {
        return false;
    }
    true
}

// btc-lean: INV-058 SCR-050 SCR-051 SCR-057 SCR-075 SCR-076 SCR-079 SCR-080 SCR-081 SCR-082 SCR-083
// btc-lean: SCR-084 SCR-085 SCR-086 SCR-091 SCR-105
pub fn scriptnum_decode(v: &[u8], require_minimal: bool) -> Result<i64, ScriptNumError> {
    scriptnum_decode_width(v, 4, require_minimal)
}

/// `max_len` 4 is arithmetic; CLTV/CSV use 5 so a full u32 encodes as positive.
pub fn scriptnum_decode_width(
    v: &[u8],
    max_len: usize,
    require_minimal: bool,
) -> Result<i64, ScriptNumError> {
    if v.len() > max_len {
        return Err(ScriptNumError::Overflow);
    }
    if require_minimal && !scriptnum_is_minimal(v) {
        return Err(ScriptNumError::NonMinimal);
    }
    if v.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &b) in v.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    if v.last().unwrap() & 0x80 != 0 {
        result &= !(0x80i64 << (8 * (v.len() - 1)));
        result = -result;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scriptnum_minimal_encoding() {
        assert!(scriptnum_is_minimal(&[]));
        assert!(!scriptnum_is_minimal(&[0x00]));
        assert!(!scriptnum_is_minimal(&[0x80]));
        assert!(scriptnum_is_minimal(&[0x01]));
        assert!(!scriptnum_is_minimal(&[0x01, 0x00]));
        assert!(scriptnum_is_minimal(&[0xff, 0x00]));
        assert!(scriptnum_is_minimal(&[0xff, 0x80]));
    }

    #[test]
    fn roundtrip_and_width() {
        for n in [0i64, 1, -1, 127, 128, 255, -255, i32::MAX as i64] {
            let enc = scriptnum_encode(n);
            assert_eq!(scriptnum_decode(&enc, true).unwrap(), n, "{n}");
            assert!(scriptnum_is_minimal(&enc), "{n}");
        }
        let min32 = scriptnum_encode(i32::MIN as i64);
        assert_eq!(min32.len(), 5);
        assert_eq!(
            scriptnum_decode_width(&min32, 5, true).unwrap(),
            i32::MIN as i64
        );
        assert_eq!(scriptnum_decode_width(&[0x80], 5, false).unwrap(), 0);
        assert!(matches!(
            scriptnum_decode(&[0x00], true),
            Err(ScriptNumError::NonMinimal)
        ));
        assert!(matches!(
            scriptnum_decode(&[0, 0, 0, 0, 1], false),
            Err(ScriptNumError::Overflow)
        ));
        assert_eq!(
            scriptnum_decode_width(&[0, 0, 0, 0, 1], 5, false).unwrap(),
            1 << 32
        );
    }

    #[cfg(miri)]
    #[test]
    fn miri_scriptnum_range_width5_nonminimal() {
        for n in -1000i64..=1000 {
            let enc = scriptnum_encode(n);
            assert_eq!(scriptnum_decode_width(&enc, 5, true).unwrap(), n);
        }
        assert_eq!(scriptnum_decode_width(&[0x80], 5, false).unwrap(), 0);
        assert!(scriptnum_decode(&[0x00], true).is_err());
        assert!(scriptnum_decode(&[0x80], true).is_err());
        assert!(scriptnum_decode_width(&[0xff, 0x00], 5, true).is_ok());
    }
}
