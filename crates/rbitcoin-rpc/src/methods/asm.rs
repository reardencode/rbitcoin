//! Core `ScriptToAsmStr` (`core_io.cpp`) and `GetOpName` (`script/script.cpp`).

use bitcoin::opcodes::all::{OP_CHECKSIGADD, OP_INVALIDOPCODE, OP_PUSHDATA1};
use bitcoin::opcodes::Opcode;
use bitcoin::script::Instruction;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::Script;
use rbitcoin_consensus::policy::is_unspendable;
use rbitcoin_consensus::script::crypto::{is_defined_hashtype, is_valid_signature_encoding};
use rbitcoin_primitives::{hex_encode, scriptnum_decode};

/// How a push shaped like a strict-DER signature prints. Core decodes the
/// sighash byte only in a transaction input's scriptSig.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SighashAsm {
    Decode,
    Hex,
}

pub(super) fn script_asm(script: &Script, sighash: SighashAsm) -> String {
    let decode = sighash == SighashAsm::Decode && !is_unspendable(script.as_bytes());
    let mut asm = String::new();
    for ins in script.instructions() {
        if !asm.is_empty() {
            asm.push(' ');
        }
        match ins {
            Ok(Instruction::PushBytes(push)) => asm.push_str(&push_asm(push.as_bytes(), decode)),
            Ok(Instruction::Op(op)) => asm.push_str(op_asm(op)),
            Err(_) => {
                asm.push_str("[error]");
                break;
            }
        }
    }
    asm
}

fn push_asm(data: &[u8], decode_sighash: bool) -> String {
    if let Ok(n) = scriptnum_decode(data, false) {
        return n.to_string();
    }
    let named = decode_sighash.then(|| sighash_suffix(data)).flatten();
    match named {
        Some((der, name)) => format!("{}[{name}]", hex_encode(der)),
        None => hex_encode(data),
    }
}

/// Core `CheckSignatureEncoding` under `SCRIPT_VERIFY_STRICTENC`, then the
/// `mapSigHashTypes` name of the trailing byte.
fn sighash_suffix(sig: &[u8]) -> Option<(&[u8], &'static str)> {
    if !is_valid_signature_encoding(sig) || !is_defined_hashtype(sig) {
        return None;
    }
    let (&byte, der) = sig.split_last()?;
    let name = match EcdsaSighashType::from_standard(u32::from(byte)).ok()? {
        EcdsaSighashType::All => "ALL",
        EcdsaSighashType::None => "NONE",
        EcdsaSighashType::Single => "SINGLE",
        EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
        EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
        EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
    };
    Some((der, name))
}

/// Core `GetOpName` for an opcode outside the data pushes: the small numbers
/// print as `-1` and `1`..`16`, and every byte past `OP_CHECKSIGADD` but
/// `OP_INVALIDOPCODE` is `OP_UNKNOWN`.
fn op_asm(op: Opcode) -> &'static str {
    if op == OP_INVALIDOPCODE {
        return "OP_INVALIDOPCODE";
    }
    let index = op.to_u8().wrapping_sub(FIRST_NAMED_OP);
    CORE_OP_NAMES
        .get(usize::from(index))
        .copied()
        .unwrap_or("OP_UNKNOWN")
}

const FIRST_NAMED_OP: u8 = OP_PUSHDATA1.to_u8();
const LAST_NAMED_OP: u8 = OP_CHECKSIGADD.to_u8();

/// Core `GetOpName` from `OP_PUSHDATA1` through `OP_CHECKSIGADD`.
const CORE_OP_NAMES: [&str; (LAST_NAMED_OP - FIRST_NAMED_OP + 1) as usize] = [
    "OP_PUSHDATA1",
    "OP_PUSHDATA2",
    "OP_PUSHDATA4",
    "-1",
    "OP_RESERVED",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    "13",
    "14",
    "15",
    "16",
    "OP_NOP",
    "OP_VER",
    "OP_IF",
    "OP_NOTIF",
    "OP_VERIF",
    "OP_VERNOTIF",
    "OP_ELSE",
    "OP_ENDIF",
    "OP_VERIFY",
    "OP_RETURN",
    "OP_TOALTSTACK",
    "OP_FROMALTSTACK",
    "OP_2DROP",
    "OP_2DUP",
    "OP_3DUP",
    "OP_2OVER",
    "OP_2ROT",
    "OP_2SWAP",
    "OP_IFDUP",
    "OP_DEPTH",
    "OP_DROP",
    "OP_DUP",
    "OP_NIP",
    "OP_OVER",
    "OP_PICK",
    "OP_ROLL",
    "OP_ROT",
    "OP_SWAP",
    "OP_TUCK",
    "OP_CAT",
    "OP_SUBSTR",
    "OP_LEFT",
    "OP_RIGHT",
    "OP_SIZE",
    "OP_INVERT",
    "OP_AND",
    "OP_OR",
    "OP_XOR",
    "OP_EQUAL",
    "OP_EQUALVERIFY",
    "OP_RESERVED1",
    "OP_RESERVED2",
    "OP_1ADD",
    "OP_1SUB",
    "OP_2MUL",
    "OP_2DIV",
    "OP_NEGATE",
    "OP_ABS",
    "OP_NOT",
    "OP_0NOTEQUAL",
    "OP_ADD",
    "OP_SUB",
    "OP_MUL",
    "OP_DIV",
    "OP_MOD",
    "OP_LSHIFT",
    "OP_RSHIFT",
    "OP_BOOLAND",
    "OP_BOOLOR",
    "OP_NUMEQUAL",
    "OP_NUMEQUALVERIFY",
    "OP_NUMNOTEQUAL",
    "OP_LESSTHAN",
    "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL",
    "OP_GREATERTHANOREQUAL",
    "OP_MIN",
    "OP_MAX",
    "OP_WITHIN",
    "OP_RIPEMD160",
    "OP_SHA1",
    "OP_SHA256",
    "OP_HASH160",
    "OP_HASH256",
    "OP_CODESEPARATOR",
    "OP_CHECKSIG",
    "OP_CHECKSIGVERIFY",
    "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    "OP_NOP1",
    "OP_CHECKLOCKTIMEVERIFY",
    "OP_CHECKSEQUENCEVERIFY",
    "OP_NOP4",
    "OP_NOP5",
    "OP_NOP6",
    "OP_NOP7",
    "OP_NOP8",
    "OP_NOP9",
    "OP_NOP10",
    "OP_CHECKSIGADD",
];
