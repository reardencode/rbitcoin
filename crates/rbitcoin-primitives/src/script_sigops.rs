//! Core-style legacy sigop count (CHECKSIG=1, CHECKMULTISIG=20 or accurate N).

/// Count CHECKSIG / CHECKMULTISIG in `script`.
///
/// `accurate`: CHECKMULTISIG after OP_1..OP_16 counts that N; else 20.
#[must_use]
pub fn script_sigop_count(script: &[u8], accurate: bool) -> u64 {
    let mut n = 0u64;
    let mut i = 0usize;
    let mut last_opcode = 0xffu8;
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        let push = if opcode <= 0x4b {
            Some(opcode as usize)
        } else if opcode == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            i += 1;
            Some(n)
        } else if opcode == 0x4d {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            Some(n)
        } else if opcode == 0x4e {
            if i + 3 >= script.len() {
                break;
            }
            let n = u32::from_le_bytes(script[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
            i += 4;
            Some(n)
        } else {
            None
        };
        if let Some(push) = push {
            if i.saturating_add(push) > script.len() {
                break;
            }
            i += push;
        } else if opcode == 0xac || opcode == 0xad {
            n = n.saturating_add(1);
        } else if opcode == 0xae || opcode == 0xaf {
            if accurate && (0x51..=0x60).contains(&last_opcode) {
                n = n.saturating_add(u64::from(last_opcode - 0x50));
            } else {
                n = n.saturating_add(20);
            }
        }
        last_opcode = opcode;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accurate_checkmultisig_uses_op_n() {
        assert_eq!(script_sigop_count(&[0xac], false), 1);
        assert_eq!(script_sigop_count(&[0xad], false), 1);
        assert_eq!(script_sigop_count(&[0xae], false), 20);
        assert_eq!(script_sigop_count(&[0xaf], false), 20);
        assert_eq!(script_sigop_count(&[0x52, 0xae], true), 2);
        assert_eq!(script_sigop_count(&[0x53, 0xae], true), 3);
        assert_eq!(script_sigop_count(&[0x01, 0xff, 0xac], false), 1);
        assert_eq!(script_sigop_count(&[0x4c, 0x01, 0xab, 0xac], false), 1);
    }

    #[test]
    fn truncated_pushdata2_does_not_count_leftover_checksig() {
        assert_eq!(script_sigop_count(&[0x4d, 0xac], false), 0);
        assert_eq!(script_sigop_count(&[0x4e, 0xac], false), 0);
        assert_eq!(script_sigop_count(&[0x4d, 0xac, 0xad], false), 0);
        assert_eq!(
            script_sigop_count(&[0x4d, 0x01, 0x00, 0xcd, 0xac], false),
            1
        );
    }
}
