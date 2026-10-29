//! Core-style legacy sigop count (CHECKSIG=1, CHECKMULTISIG=20 or accurate N).

use crate::script_opcode::{
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_PUSHBYTES_75,
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_PUSHNUM_16, OP_RESERVED, OP_TRUE,
};

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
        let push = if opcode <= OP_PUSHBYTES_75 {
            Some(opcode as usize)
        } else if opcode == OP_PUSHDATA1 {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            i += 1;
            Some(n)
        } else if opcode == OP_PUSHDATA2 {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            Some(n)
        } else if opcode == OP_PUSHDATA4 {
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
        } else if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY {
            n = n.saturating_add(1);
        } else if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
            if accurate && (OP_TRUE..=OP_PUSHNUM_16).contains(&last_opcode) {
                n = n.saturating_add(u64::from(last_opcode - OP_RESERVED));
            } else {
                n = n.saturating_add(20);
            }
        }
        last_opcode = opcode;
    }
    n
}
