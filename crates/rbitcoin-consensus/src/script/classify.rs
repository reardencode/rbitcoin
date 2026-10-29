//! Classify standard `scriptPubKey` templates.

use bitcoin::script::Script;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    /// OP_0 OP_PUSHBYTES_20 <20>
    P2wpkh,
    /// OP_0 OP_PUSHBYTES_32 <32>
    P2wsh,
    /// OP_1 OP_PUSHBYTES_32 <32>
    P2tr,
    /// OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20> OP_EQUALVERIFY OP_CHECKSIG
    P2pkh,
    /// OP_HASH160 OP_PUSHBYTES_20 <20> OP_EQUAL
    P2sh,
    /// Bare (P2PK, custom, empty spk) — run interpreter
    Bare,
}

/// Anyone-can-spend templates only. **Empty** `scriptPubKey` is **not** ACS
/// (empty stack → fail without TRUE). Only explicit `OP_TRUE`.
///
/// **Not** a short-circuit past scriptSig: scriptSig still runs (CLTV/CSV may
/// live there). Callers must evaluate scriptSig first or use the bare path.
pub fn is_anyone_can_spend(script: &Script) -> bool {
    script.as_bytes() == [rbitcoin_primitives::OP_TRUE]
}

/// BIP141 witness program: `OP_0`/`OP_1`..`OP_16` + a single push of 2..=40 bytes.
/// Returns `(version, program)` where version is 0 for OP_0 and 1..=16 for OP_1..OP_16.
pub fn witness_program(script: &Script) -> Option<(u8, &[u8])> {
    let version = script.witness_version()?;
    Some((version.to_num(), &script.as_bytes()[2..]))
}

pub fn classify(script: &Script) -> ScriptKind {
    if script.is_p2wpkh() {
        ScriptKind::P2wpkh
    } else if script.is_p2wsh() {
        ScriptKind::P2wsh
    } else if script.is_p2tr() {
        ScriptKind::P2tr
    } else if script.is_p2pkh() {
        ScriptKind::P2pkh
    } else if script.is_p2sh() {
        ScriptKind::P2sh
    } else {
        ScriptKind::Bare
    }
}
