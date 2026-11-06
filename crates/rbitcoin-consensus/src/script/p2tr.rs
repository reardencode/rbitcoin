//! Taproot (P2TR) verification: BIP341 key-path and script-path.
//!
//! Script-path checks the output-key commitment in `output_key_matches_tweak`.
//! A tweak at or above the curve order is a commitment failure.
//! `TapTweakHash::to_scalar` panics on those bytes, and so does
//! `ControlBlock::verify_taproot_commitment`.

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::Script;
use bitcoin::secp256k1::{Message, Parity};
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};
use bitcoin::{Amount, Transaction, Witness};

use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    tap_spent: &crypto::TapSpentHashes,
    amount: Amount,
    spk: &[u8],
) -> Result<(), ConsensusError> {
    debug_assert!(spk.len() == 34 && spk.starts_with(&rbitcoin_primitives::P2TR_PREFIX));
    let output_key = &spk[2..34];

    let input = &tx.input[input_index.get()];
    let wit_len = input.witness.len();
    if wit_len == 0 {
        return Err(ConsensusError::Script("p2tr empty witness".into()));
    }

    // Key-path: one element, or sig + annex (BIP341: annex = last stack item
    // starting with 0x50 when there are ≥2 items).
    if wit_len == 1 || (wit_len == 2 && bip341_annex(&input.witness).is_some()) {
        return verify_key_path(job, input_index, tx, output_key, tap_spent, amount, spk);
    }
    verify_script_path(job, input_index, tx, output_key, tap_spent, amount, spk)
}

/// BIP341 annex: last witness item, only when `len ≥ 2` and first byte is `0x50`.
#[doc(hidden)]
pub fn bip341_annex(witness: &Witness) -> Option<&[u8]> {
    if witness.len() < 2 {
        return None;
    }
    let last = witness.last()?;
    if !last.is_empty() && last[0] == rbitcoin_primitives::OP_RESERVED {
        Some(last)
    } else {
        None
    }
}

#[doc(hidden)]
pub fn verify_key_path(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    output_key: &[u8],
    tap_spent: &crypto::TapSpentHashes,
    amount: Amount,
    spent_script: &[u8],
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index.get()];
    let sig_raw = input
        .witness
        .nth(0)
        .ok_or_else(|| ConsensusError::Script("p2tr sig".into()))?;

    let (sig_bytes, sighash_ty) = if sig_raw.len() == 64 {
        (sig_raw, TapSighashType::Default)
    } else if sig_raw.len() == 65 {
        // BIP341: 65-byte form with sighash byte 0x00 is invalid (Core /
        // EvalChecksigTapscript). Mirror tapscript `checksig_schnorr`.
        if sig_raw[64] == 0x00 {
            return Err(ConsensusError::Script("p2tr sighash type".into()));
        }
        let ty = TapSighashType::from_consensus_u8(sig_raw[64])
            .map_err(|_| ConsensusError::Script("p2tr sighash type".into()))?;
        (&sig_raw[..64], ty)
    } else {
        return Err(ConsensusError::Script("p2tr sig len".into()));
    };

    let xonly = XOnlyPublicKey::from_slice(output_key)
        .map_err(|_| ConsensusError::Script("p2tr xonly".into()))?;
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|_| ConsensusError::Script("p2tr schnorr parse".into()))?;

    // BIP341: when the annex is present it is part of spend_type / sighash.
    // Key path is the same message as script path with ext flag 0 (`leaf` absent).
    let annex_hash = bip341_annex(&input.witness).map(crypto::annex_hash);
    let single = std::cell::OnceCell::new();
    let sighash = crypto::tap_signature_hash(
        job,
        input_index,
        sighash_ty,
        tap_spent,
        annex_hash,
        None,
        &single,
        amount.to_sat(),
        spent_script,
    )?;
    let msg = Message::from_digest(sighash);
    crypto::SECP.with(|secp| {
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|_| ConsensusError::Script("p2tr schnorr".into()))
    })
}

#[doc(hidden)]
pub const TAPSCRIPT_LEAF: u8 = 0xc0;
#[doc(hidden)]
pub const CONTROL_BASE: usize = 33;
#[doc(hidden)]
pub const CONTROL_NODE: usize = 32;
#[doc(hidden)]
pub const CONTROL_MAX_NODES: usize = 128;

/// BIP341 commitment. Returns the even leaf version byte and the tapleaf hash.
#[doc(hidden)]
pub fn verify_control_commitment(
    control: &[u8],
    output_key_bytes: &[u8],
    script: &Script,
) -> Result<(u8, TapLeafHash), ConsensusError> {
    if control.len() < CONTROL_BASE {
        return Err(ConsensusError::Script("TAPROOT_WRONG_CONTROL_SIZE".into()));
    }
    let extra = control.len() - CONTROL_BASE;
    let nodes = extra / CONTROL_NODE;
    if !extra.is_multiple_of(CONTROL_NODE) || nodes > CONTROL_MAX_NODES {
        return Err(ConsensusError::Script("TAPROOT_WRONG_CONTROL_SIZE".into()));
    }
    let leaf = control[0] & 0xfe;
    let parity = if control[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    let internal = XOnlyPublicKey::from_slice(&control[1..CONTROL_BASE])
        .map_err(|_| ConsensusError::Script("WITNESS_PROGRAM_MISMATCH".into()))?;
    let output_key = XOnlyPublicKey::from_slice(output_key_bytes)
        .map_err(|_| ConsensusError::Script("WITNESS_PROGRAM_MISMATCH".into()))?;

    let mut eng = TapLeafHash::engine();
    leaf.consensus_encode(&mut eng)
        .expect("hash engines do not error");
    script
        .consensus_encode(&mut eng)
        .expect("hash engines do not error");
    let tapleaf_hash = TapLeafHash::from_engine(eng);
    let mut curr = TapNodeHash::from_byte_array(tapleaf_hash.to_byte_array());
    for i in 0..nodes {
        let start = CONTROL_BASE + i * CONTROL_NODE;
        let node = TapNodeHash::from_byte_array(
            control[start..start + CONTROL_NODE]
                .try_into()
                .expect("32-byte merkle node"),
        );
        curr = TapNodeHash::from_node_hashes(curr, node);
    }
    let tweak = TapTweakHash::from_key_and_tweak(internal, Some(curr));
    let ok = output_key_matches_tweak(&internal, &output_key, parity, &tweak.to_byte_array());
    if !ok {
        return Err(ConsensusError::Script("WITNESS_PROGRAM_MISMATCH".into()));
    }
    Ok((leaf, tapleaf_hash))
}

/// BIP341 output-key check for one 32-byte tweak.
///
/// A value at or above the curve order is not a scalar. Core's
/// `secp256k1_ec_pubkey_tweak_add_helper` returns 0, and `CheckTapTweak`
/// is then false. `TapTweakHash::to_scalar` panics on those bytes.
fn output_key_matches_tweak(
    internal: &XOnlyPublicKey,
    output_key: &XOnlyPublicKey,
    parity: Parity,
    tweak: &[u8; 32],
) -> bool {
    let Ok(scalar) = bitcoin::secp256k1::Scalar::from_be_bytes(*tweak) else {
        return false;
    };
    crypto::SECP.with(|secp| internal.tweak_add_check(secp, output_key, parity, scalar))
}

#[doc(hidden)]
pub fn verify_script_path(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    output_key_bytes: &[u8],
    tap_spent: &crypto::TapSpentHashes,
    amount: Amount,
    spent_script: &[u8],
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index.get()];
    let mut items: Vec<Vec<u8>> = (0..input.witness.len())
        .filter_map(|i| input.witness.nth(i).map(|b| b.to_vec()))
        .collect();

    // Strip annex from the initial stack (still included in CHECKSIG sighash).
    let annex = bip341_annex(&input.witness);
    if annex.is_some() {
        items.pop();
    }
    if items.len() < 2 {
        return Err(ConsensusError::Script("p2tr script path short".into()));
    }
    let control_bytes = items.pop().unwrap();
    let script_bytes = items.pop().unwrap();
    let mut stack = items;

    let script = Script::from_bytes(&script_bytes);
    // Leaf byte is raw consensus (`c[0] & 0xfe`). `LeafVersion::from_consensus`
    // rejects 0x50, which Core accepts as a future leaf.
    let (leaf, tapleaf_hash) = verify_control_commitment(&control_bytes, output_key_bytes, script)?;

    // Unknown leaf versions are valid consensus spends. The script is not run.
    // DISCOURAGE_UPGRADABLE_TAPROOT_VERSION is standardness. Confirm never sets it.
    if leaf != TAPSCRIPT_LEAF {
        return Ok(());
    }

    let exec = crypto::TapscriptExecData::new(
        job,
        input_index,
        tap_spent,
        tapleaf_hash,
        amount.to_sat(),
        spent_script,
        annex,
    );
    let ctx = EvalContext::from_job(job, tx, input_index, amount, script, SigVersion::TapScript)?
        .with_tapscript(exec);
    if interpreter::eval_script(script, &mut stack, &ctx)? {
        interpreter::require_clean_true(&stack)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, SecretKey};
    use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};

    use super::{output_key_matches_tweak, verify_control_commitment};

    /// secp256k1 order n.
    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    fn sub32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let v = i16::from(a[i]) - i16::from(b[i]) - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "underflow");
        out
    }

    #[test]
    fn tweak_at_or_above_order_is_not_a_commitment() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let (internal, _) = sk.x_only_public_key(&secp);
        // n reduced to 0 is P + 0*G = P. That must still fail.
        assert!(!output_key_matches_tweak(
            &internal,
            &internal,
            Parity::Even,
            &ORDER
        ));
        // 2^256-1 reduced mod n is a non-zero residue. Q = P + rG must still fail.
        let above = [0xffu8; 32];
        let residue = sub32(above, ORDER);
        let scalar = Scalar::from_be_bytes(residue).unwrap();
        let (q, parity) = internal.add_tweak(&secp, &scalar).unwrap();
        assert!(!output_key_matches_tweak(&internal, &q, parity, &above));
        let mut max = ORDER;
        max[31] = 0x40;
        let scalar = Scalar::from_be_bytes(max).unwrap();
        let (output, parity) = internal.add_tweak(&secp, &scalar).unwrap();
        assert!(output_key_matches_tweak(&internal, &output, parity, &max));
    }

    #[test]
    fn control_commitment_uses_the_same_tweak_check() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let (internal, _) = sk.x_only_public_key(&secp);
        let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        let mut eng = TapLeafHash::engine();
        0xc0u8
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        script
            .consensus_encode(&mut eng)
            .expect("hash engines do not error");
        let tapleaf = TapLeafHash::from_engine(eng);
        let curr = TapNodeHash::from_byte_array(tapleaf.to_byte_array());
        let tweak = TapTweakHash::from_key_and_tweak(internal, Some(curr));
        let scalar = Scalar::from_be_bytes(tweak.to_byte_array()).unwrap();
        let (output, parity) = internal.add_tweak(&secp, &scalar).unwrap();
        let mut control = vec![0xc0 | parity.to_u8()];
        control.extend_from_slice(&internal.serialize());
        let (leaf, _) =
            verify_control_commitment(&control, &output.serialize(), script.as_script()).unwrap();
        assert_eq!(leaf, 0xc0);
        let err = verify_control_commitment(&control, &internal.serialize(), script.as_script())
            .unwrap_err();
        match err {
            crate::error::ConsensusError::Script(msg) => {
                assert!(msg.contains("WITNESS_PROGRAM_MISMATCH"), "{msg}");
            }
            other => panic!("{other}"),
        }
    }
}
