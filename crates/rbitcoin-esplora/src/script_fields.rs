//! Pure Esplora script → asm / type / address projection.
//!
//! Matches the documented Esplora API.md vin/vout script fields (not electrs-only
//! extensions). Address is best-effort when the script is a standard pay-to form.

use bitcoin::address::Address;
use bitcoin::script::Script;
use bitcoin::Network;

/// Documented Esplora scriptpubkey / scriptsig projection fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EsploraScriptFields {
    pub hex: String,
    pub asm: String,
    /// e.g. `p2pkh`, `v0_p2wpkh`, `v1_p2tr`, `p2sh`, `unknown`.
    pub script_type: &'static str,
    pub address: Option<String>,
}

/// Project a scriptPubKey (or scriptSig) into Esplora JSON fields.
pub fn esplora_script_fields(script: &[u8], network: Network) -> EsploraScriptFields {
    let s = Script::from_bytes(script);
    let hex = rbitcoin_primitives::hex_encode(script);
    let asm = s.to_asm_string();
    let script_type = classify_script(s);
    let address = Address::from_script(s, network).ok().map(|a| a.to_string());
    EsploraScriptFields {
        hex,
        asm,
        script_type,
        address,
    }
}

#[doc(hidden)]
pub fn classify_script(s: &Script) -> &'static str {
    if s.is_p2pkh() {
        "p2pkh"
    } else if s.is_p2sh() {
        "p2sh"
    } else if s.is_p2wpkh() {
        "v0_p2wpkh"
    } else if s.is_p2wsh() {
        "v0_p2wsh"
    } else if s.is_p2tr() {
        "v1_p2tr"
    } else if s.is_op_return() {
        "op_return"
    } else if s.is_p2pk() {
        "p2pk"
    } else if is_bare_multisig(s) {
        "multisig"
    } else {
        "unknown"
    }
}

/// Minimal bare multisig: ends with CHECKMULTISIG / CHECKMULTISIGVERIFY.
#[doc(hidden)]
pub fn is_bare_multisig(s: &Script) -> bool {
    let b = s.as_bytes();
    if b.len() < 3 {
        return false;
    }
    matches!(
        b[b.len() - 1],
        rbitcoin_primitives::OP_CHECKMULTISIG | rbitcoin_primitives::OP_CHECKMULTISIGVERIFY
    )
}
