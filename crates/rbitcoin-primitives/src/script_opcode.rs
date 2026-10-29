//! Raw script opcode bytes.
//!
//! rust-bitcoin owns the opcode type. These are the `u8` values used when a
//! walk looks at script bytes directly. A consensus test checks each one
//! against `bitcoin::opcodes`.

/// `OP_0` / `OP_PUSHBYTES_0`.
pub const OP_0: u8 = 0x00;
/// Direct push of the next 2 bytes.
pub const OP_PUSHBYTES_2: u8 = 0x02;
/// Direct push of the next 20 bytes.
pub const OP_PUSHBYTES_20: u8 = 0x14;
/// Direct push of the next 32 bytes.
pub const OP_PUSHBYTES_32: u8 = 0x20;
/// Largest direct push. The next opcode is [`OP_PUSHDATA1`].
pub const OP_PUSHBYTES_75: u8 = 0x4b;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
/// `OP_1NEGATE`.
pub const OP_1NEGATE: u8 = 0x4f;
/// `OP_RESERVED`. `OP_1` is this plus 1. BIP341 annex tags also use this byte.
pub const OP_RESERVED: u8 = 0x50;
/// `OP_1` / `OP_TRUE`.
pub const OP_TRUE: u8 = 0x51;
/// `OP_16`.
pub const OP_PUSHNUM_16: u8 = 0x60;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_DUP: u8 = 0x76;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

/// BIP341 pay-to-anchor witness program (`Ns`).
pub const P2A_PROGRAM: [u8; 2] = [b'N', b's'];

/// `OP_1 OP_PUSHBYTES_2 Ns`.
pub const P2A_SCRIPT: [u8; 4] = [OP_TRUE, OP_PUSHBYTES_2, P2A_PROGRAM[0], P2A_PROGRAM[1]];

pub const P2PKH_PREFIX: [u8; 3] = [OP_DUP, OP_HASH160, OP_PUSHBYTES_20];
pub const P2PKH_SUFFIX: [u8; 2] = [OP_EQUALVERIFY, OP_CHECKSIG];
pub const P2SH_PREFIX: [u8; 2] = [OP_HASH160, OP_PUSHBYTES_20];
pub const P2WPKH_PREFIX: [u8; 2] = [OP_0, OP_PUSHBYTES_20];
pub const P2WSH_PREFIX: [u8; 2] = [OP_0, OP_PUSHBYTES_32];
pub const P2TR_PREFIX: [u8; 2] = [OP_TRUE, OP_PUSHBYTES_32];
