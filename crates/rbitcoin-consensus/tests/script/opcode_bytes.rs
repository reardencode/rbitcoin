//! The raw script bytes match rust-bitcoin's opcode numbers.

use bitcoin::opcodes::all::{
    OP_2DIV, OP_2MUL, OP_AND, OP_CAT, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG,
    OP_CHECKSIGVERIFY, OP_CODESEPARATOR, OP_DIV, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160,
    OP_INVERT, OP_LEFT, OP_LSHIFT, OP_MOD, OP_MUL, OP_OR, OP_PUSHBYTES_0, OP_PUSHBYTES_2,
    OP_PUSHBYTES_20, OP_PUSHBYTES_32, OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1, OP_RESERVED, OP_RETURN, OP_RIGHT, OP_RSHIFT,
    OP_SUBSTR, OP_VERIF, OP_VERNOTIF, OP_XOR,
};
use rbitcoin_primitives::script_opcode as b;

#[test]
fn script_opcode_bytes_match_rust_bitcoin() {
    let pairs = [
        (b::OP_0, OP_PUSHBYTES_0.to_u8()),
        (b::OP_PUSHBYTES_2, OP_PUSHBYTES_2.to_u8()),
        (b::OP_PUSHBYTES_20, OP_PUSHBYTES_20.to_u8()),
        (b::OP_PUSHBYTES_32, OP_PUSHBYTES_32.to_u8()),
        (b::OP_PUSHBYTES_75, OP_PUSHBYTES_75.to_u8()),
        (b::OP_PUSHDATA1, OP_PUSHDATA1.to_u8()),
        (b::OP_PUSHDATA2, OP_PUSHDATA2.to_u8()),
        (b::OP_PUSHDATA4, OP_PUSHDATA4.to_u8()),
        (b::OP_1NEGATE, OP_PUSHNUM_NEG1.to_u8()),
        (b::OP_RESERVED, OP_RESERVED.to_u8()),
        (b::OP_TRUE, OP_PUSHNUM_1.to_u8()),
        (b::OP_PUSHNUM_16, OP_PUSHNUM_16.to_u8()),
        (b::OP_VERIF, OP_VERIF.to_u8()),
        (b::OP_VERNOTIF, OP_VERNOTIF.to_u8()),
        (b::OP_RETURN, OP_RETURN.to_u8()),
        (b::OP_DUP, OP_DUP.to_u8()),
        (b::OP_CAT, OP_CAT.to_u8()),
        (b::OP_SUBSTR, OP_SUBSTR.to_u8()),
        (b::OP_LEFT, OP_LEFT.to_u8()),
        (b::OP_RIGHT, OP_RIGHT.to_u8()),
        (b::OP_INVERT, OP_INVERT.to_u8()),
        (b::OP_AND, OP_AND.to_u8()),
        (b::OP_OR, OP_OR.to_u8()),
        (b::OP_XOR, OP_XOR.to_u8()),
        (b::OP_EQUAL, OP_EQUAL.to_u8()),
        (b::OP_EQUALVERIFY, OP_EQUALVERIFY.to_u8()),
        (b::OP_2MUL, OP_2MUL.to_u8()),
        (b::OP_2DIV, OP_2DIV.to_u8()),
        (b::OP_MUL, OP_MUL.to_u8()),
        (b::OP_DIV, OP_DIV.to_u8()),
        (b::OP_MOD, OP_MOD.to_u8()),
        (b::OP_LSHIFT, OP_LSHIFT.to_u8()),
        (b::OP_RSHIFT, OP_RSHIFT.to_u8()),
        (b::OP_HASH160, OP_HASH160.to_u8()),
        (b::OP_CODESEPARATOR, OP_CODESEPARATOR.to_u8()),
        (b::OP_CHECKSIG, OP_CHECKSIG.to_u8()),
        (b::OP_CHECKSIGVERIFY, OP_CHECKSIGVERIFY.to_u8()),
        (b::OP_CHECKMULTISIG, OP_CHECKMULTISIG.to_u8()),
        (b::OP_CHECKMULTISIGVERIFY, OP_CHECKMULTISIGVERIFY.to_u8()),
    ];
    for (ours, core) in pairs {
        assert_eq!(ours, core);
    }
    assert_eq!(b::P2A_PROGRAM, [b'N', b's']);
    assert_eq!(b::P2A_SCRIPT, [b::OP_TRUE, b::OP_PUSHBYTES_2, b'N', b's']);
}
