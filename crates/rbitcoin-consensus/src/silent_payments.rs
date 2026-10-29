//! BIP-352 Silent Payments **tweak server** (scan-side `A_tweak` only).
//!
//! libsecp256k1 has a `silentpayments` C module; rust-secp256k1 0.29 (bitcoin
//! 0.32) does not bind it. This module uses `PublicKey::combine_keys` +
//! `mul_tweak` plus script extract. Tweak *index* never stores a scan key.
//! Frigate `blockchain.silentpayments.subscribe` may pass a scan private key
//! in RAM for the session only.

use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};
use bitcoin::key::{Parity, XOnlyPublicKey};
use bitcoin::script::{Instruction, Script};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{OutPoint, Transaction, TxOut, Witness};
use std::sync::OnceLock;

/// BIP341 NUMS internal key *H* (SHA256 of uncompressed *G* as x-only).
#[doc(hidden)]
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// One Taproot output listed for Electrum tweaks `output_pubkeys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootOut {
    pub vout: u32,
    pub xonly: [u8; 32],
    pub value: u64,
}

/// Server tweak plus Taproot outs for one eligible tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxTweak {
    /// `input_hash · ΣA` — 33-byte compressed.
    pub tweak: [u8; 33],
    pub output_pubkeys: Vec<TaprootOut>,
}

#[doc(hidden)]
pub fn secp() -> &'static Secp256k1<All> {
    static S: OnceLock<Secp256k1<All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

/// Compute the BIP-352 server tweak for `tx` given prevout scripts.
///
/// `prevouts.len()` must equal `tx.input.len()`. Returns `None` if the tx is
/// not silent-payment eligible (or the pubkey sum is infinity / invalid hash).
pub fn tweak_from_tx(tx: &Transaction, prevouts: &[TxOut]) -> Option<TxTweak> {
    if tx.input.len() != prevouts.len() {
        return None;
    }
    let output_pubkeys = taproot_outs(tx);
    if output_pubkeys.is_empty() {
        return None;
    }
    if prevouts
        .iter()
        .any(|p| p.script_pubkey.witness_version().map(|v| v.to_num()) > Some(1))
    {
        return None;
    }

    let mut keys = Vec::new();
    for (vin, prev) in tx.input.iter().zip(prevouts.iter()) {
        if let Some(pk) = extract_input_pubkey(
            prev.script_pubkey.as_script(),
            vin.script_sig.as_script(),
            &vin.witness,
        ) {
            keys.push(pk);
        }
    }
    if keys.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let a = PublicKey::combine_keys(&refs).ok()?;
    let tweak = input_hash_mul_a(tx, &a)?;
    Some(TxTweak {
        tweak,
        output_pubkeys,
    })
}

#[doc(hidden)]
pub fn input_hash_mul_a(tx: &Transaction, a: &PublicKey) -> Option<[u8; 33]> {
    let mut smallest = outpoint_bytes(&tx.input[0].previous_output);
    for vin in tx.input.iter().skip(1) {
        smallest = smallest.min(outpoint_bytes(&vin.previous_output));
    }
    let ser_a = a.serialize();
    let mut msg = [0u8; 36 + 33];
    msg[..36].copy_from_slice(&smallest);
    msg[36..].copy_from_slice(&ser_a);
    let h = tagged_hash(b"BIP0352/Inputs", &msg);
    if h == [0u8; 32] {
        return None;
    }
    let scalar = Scalar::from_be_bytes(h).ok()?;
    let tweaked = a.mul_tweak(secp(), &scalar).ok()?;
    Some(tweaked.serialize())
}

/// BIP-352 `P_k = B_spend + t_k·G` for tweak `A` and integer `k`.
pub fn taproot_matches_scan(
    tweak_compressed: &[u8; 33],
    output_xonly: &[u8; 32],
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    k: u32,
) -> bool {
    let Ok(a) = PublicKey::from_slice(tweak_compressed) else {
        return false;
    };
    let Ok(scan_scalar) = Scalar::from_be_bytes(scan_sk.secret_bytes()) else {
        return false;
    };
    let Ok(shared) = a.mul_tweak(secp(), &scan_scalar) else {
        return false;
    };
    let mut payload = [0u8; 37];
    payload[..33].copy_from_slice(&shared.serialize());
    payload[33..].copy_from_slice(&k.to_be_bytes());
    let t = tagged_hash(b"BIP0352/SharedSecret", &payload);
    let Ok(tk) = SecretKey::from_slice(&t) else {
        return false;
    };
    let tg = PublicKey::from_secret_key(secp(), &tk);
    let Ok(p) = PublicKey::combine_keys(&[spend_pk, &tg]) else {
        return false;
    };
    p.x_only_public_key().0.serialize() == *output_xonly
}

#[doc(hidden)]
pub fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tagh = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tagh.as_ref());
    eng.input(tagh.as_ref());
    eng.input(payload);
    sha256::Hash::from_engine(eng).to_byte_array()
}

#[doc(hidden)]
pub fn outpoint_bytes(op: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(op.txid.as_byte_array());
    b[32..].copy_from_slice(&op.vout.to_le_bytes());
    b
}

#[doc(hidden)]
pub fn taproot_outs(tx: &Transaction) -> Vec<TaprootOut> {
    let mut out = Vec::new();
    for (i, o) in tx.output.iter().enumerate() {
        if !o.script_pubkey.is_p2tr() {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&o.script_pubkey.as_bytes()[2..34]);
        out.push(TaprootOut {
            vout: i as u32,
            xonly,
            value: o.value.to_sat(),
        });
    }
    out
}

#[doc(hidden)]
pub fn extract_input_pubkey(
    prev: &Script,
    script_sig: &Script,
    witness: &Witness,
) -> Option<PublicKey> {
    if prev.is_p2tr() {
        return extract_p2tr(prev.as_bytes(), witness);
    }
    if prev.is_p2wpkh() {
        return last_compressed_witness_pubkey(witness);
    }
    if prev.is_p2sh() {
        if !is_p2sh_p2wpkh_redeem(script_sig) {
            return None;
        }
        return last_compressed_witness_pubkey(witness);
    }
    if prev.is_p2pkh() {
        return p2pkh_script_pubkey(prev.as_bytes(), script_sig);
    }
    None
}

#[doc(hidden)]
pub fn extract_p2tr(spk: &[u8], witness: &Witness) -> Option<PublicKey> {
    if nums_h_script_path(witness) {
        return None;
    }
    let xonly = XOnlyPublicKey::from_slice(&spk[2..34]).ok()?;
    // Even-Y lift (BIP340 / BIP-352 taproot inputs).
    Some(xonly.public_key(Parity::Even))
}

#[doc(hidden)]
pub fn nums_h_script_path(witness: &Witness) -> bool {
    let items = witness_items_no_annex(witness);
    if items.len() < 2 {
        return false;
    }
    let cb = items[items.len() - 1];
    if cb.len() < 33 {
        return false;
    }
    cb[1..33] == NUMS_H
}

#[doc(hidden)]
pub fn witness_items_no_annex(witness: &Witness) -> Vec<&[u8]> {
    let mut items: Vec<&[u8]> = witness.iter().collect();
    if items.len() >= 2 {
        if let Some(last) = items.last() {
            if !last.is_empty() && last[0] == rbitcoin_primitives::OP_RESERVED {
                items.pop();
            }
        }
    }
    items
}

#[doc(hidden)]
pub fn last_compressed_witness_pubkey(witness: &Witness) -> Option<PublicKey> {
    let items = witness_items_no_annex(witness);
    let last = items.last()?;
    compressed_pubkey(last)
}

/// P2PKH scriptSigs are third-party malleable. Take the compressed key whose
/// HASH160 matches the prevout (BIP-352: parse even if the template is wrapped).
#[doc(hidden)]
pub fn p2pkh_script_pubkey(spk: &[u8], script_sig: &Script) -> Option<PublicKey> {
    if spk.len() != 25 {
        return None;
    }
    let want = &spk[3..23];
    let mut last = None;
    for ins in script_sig.instructions() {
        let Ok(Instruction::PushBytes(b)) = ins else {
            continue;
        };
        if let Some(pk) = compressed_pubkey(b.as_bytes()) {
            let h = hash160::Hash::hash(&pk.serialize());
            if h.as_byte_array() == want {
                last = Some(pk);
            }
        }
    }
    last
}

#[doc(hidden)]
pub fn compressed_pubkey(b: &[u8]) -> Option<PublicKey> {
    if b.len() == 33 && (b[0] == 0x02 || b[0] == 0x03) {
        PublicKey::from_slice(b).ok()
    } else {
        None
    }
}

#[doc(hidden)]
pub fn is_p2sh_p2wpkh_redeem(script_sig: &Script) -> bool {
    let mut push: Option<Vec<u8>> = None;
    let mut n = 0usize;
    for ins in script_sig.instructions() {
        match ins {
            Ok(Instruction::PushBytes(b)) => {
                n += 1;
                push = Some(b.as_bytes().to_vec());
            }
            Ok(_) => return false,
            Err(_) => return false,
        }
    }
    if n != 1 {
        return false;
    }
    let Some(r) = push else {
        return false;
    };
    r.len() == 22 && r.starts_with(&rbitcoin_primitives::P2WPKH_PREFIX)
}
