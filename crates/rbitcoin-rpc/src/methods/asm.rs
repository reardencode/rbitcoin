//! Core `ScriptToAsmStr` (`core_io.cpp`) and `GetOpName` (`script/script.cpp`).

use bitcoin::opcodes::all::*;
use bitcoin::opcodes::{Class, ClassifyContext, Opcode};
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
            Ok(Instruction::Op(op)) => asm.push_str(&op_asm(op)),
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

fn op_asm(op: Opcode) -> String {
    match op.classify(ClassifyContext::Legacy) {
        Class::PushNum(n) => n.to_string(),
        _ => core_op_name(op).to_string(),
    }
}

/// Core `GetOpName` for every opcode that is not a push or a small number.
fn core_op_name(op: Opcode) -> &'static str {
    match op {
        OP_PUSHDATA1 => "OP_PUSHDATA1",
        OP_PUSHDATA2 => "OP_PUSHDATA2",
        OP_PUSHDATA4 => "OP_PUSHDATA4",
        OP_RESERVED => "OP_RESERVED",
        OP_NOP => "OP_NOP",
        OP_VER => "OP_VER",
        OP_IF => "OP_IF",
        OP_NOTIF => "OP_NOTIF",
        OP_VERIF => "OP_VERIF",
        OP_VERNOTIF => "OP_VERNOTIF",
        OP_ELSE => "OP_ELSE",
        OP_ENDIF => "OP_ENDIF",
        OP_VERIFY => "OP_VERIFY",
        OP_RETURN => "OP_RETURN",
        OP_TOALTSTACK => "OP_TOALTSTACK",
        OP_FROMALTSTACK => "OP_FROMALTSTACK",
        OP_2DROP => "OP_2DROP",
        OP_2DUP => "OP_2DUP",
        OP_3DUP => "OP_3DUP",
        OP_2OVER => "OP_2OVER",
        OP_2ROT => "OP_2ROT",
        OP_2SWAP => "OP_2SWAP",
        OP_IFDUP => "OP_IFDUP",
        OP_DEPTH => "OP_DEPTH",
        OP_DROP => "OP_DROP",
        OP_DUP => "OP_DUP",
        OP_NIP => "OP_NIP",
        OP_OVER => "OP_OVER",
        OP_PICK => "OP_PICK",
        OP_ROLL => "OP_ROLL",
        OP_ROT => "OP_ROT",
        OP_SWAP => "OP_SWAP",
        OP_TUCK => "OP_TUCK",
        OP_CAT => "OP_CAT",
        OP_SUBSTR => "OP_SUBSTR",
        OP_LEFT => "OP_LEFT",
        OP_RIGHT => "OP_RIGHT",
        OP_SIZE => "OP_SIZE",
        OP_INVERT => "OP_INVERT",
        OP_AND => "OP_AND",
        OP_OR => "OP_OR",
        OP_XOR => "OP_XOR",
        OP_EQUAL => "OP_EQUAL",
        OP_EQUALVERIFY => "OP_EQUALVERIFY",
        OP_RESERVED1 => "OP_RESERVED1",
        OP_RESERVED2 => "OP_RESERVED2",
        OP_1ADD => "OP_1ADD",
        OP_1SUB => "OP_1SUB",
        OP_2MUL => "OP_2MUL",
        OP_2DIV => "OP_2DIV",
        OP_NEGATE => "OP_NEGATE",
        OP_ABS => "OP_ABS",
        OP_NOT => "OP_NOT",
        OP_0NOTEQUAL => "OP_0NOTEQUAL",
        OP_ADD => "OP_ADD",
        OP_SUB => "OP_SUB",
        OP_MUL => "OP_MUL",
        OP_DIV => "OP_DIV",
        OP_MOD => "OP_MOD",
        OP_LSHIFT => "OP_LSHIFT",
        OP_RSHIFT => "OP_RSHIFT",
        OP_BOOLAND => "OP_BOOLAND",
        OP_BOOLOR => "OP_BOOLOR",
        OP_NUMEQUAL => "OP_NUMEQUAL",
        OP_NUMEQUALVERIFY => "OP_NUMEQUALVERIFY",
        OP_NUMNOTEQUAL => "OP_NUMNOTEQUAL",
        OP_LESSTHAN => "OP_LESSTHAN",
        OP_GREATERTHAN => "OP_GREATERTHAN",
        OP_LESSTHANOREQUAL => "OP_LESSTHANOREQUAL",
        OP_GREATERTHANOREQUAL => "OP_GREATERTHANOREQUAL",
        OP_MIN => "OP_MIN",
        OP_MAX => "OP_MAX",
        OP_WITHIN => "OP_WITHIN",
        OP_RIPEMD160 => "OP_RIPEMD160",
        OP_SHA1 => "OP_SHA1",
        OP_SHA256 => "OP_SHA256",
        OP_HASH160 => "OP_HASH160",
        OP_HASH256 => "OP_HASH256",
        OP_CODESEPARATOR => "OP_CODESEPARATOR",
        OP_CHECKSIG => "OP_CHECKSIG",
        OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
        OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
        OP_NOP1 => "OP_NOP1",
        OP_CLTV => "OP_CHECKLOCKTIMEVERIFY",
        OP_CSV => "OP_CHECKSEQUENCEVERIFY",
        OP_NOP4 => "OP_NOP4",
        OP_NOP5 => "OP_NOP5",
        OP_NOP6 => "OP_NOP6",
        OP_NOP7 => "OP_NOP7",
        OP_NOP8 => "OP_NOP8",
        OP_NOP9 => "OP_NOP9",
        OP_NOP10 => "OP_NOP10",
        OP_CHECKSIGADD => "OP_CHECKSIGADD",
        OP_INVALIDOPCODE => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}
