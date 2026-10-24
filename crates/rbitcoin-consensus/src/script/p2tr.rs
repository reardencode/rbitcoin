//! Taproot (P2TR) verification: BIP341 key-path and script-path.
//!
//! Script-path fully re-checks the BIP341 output-key commitment via
//! [`bitcoin::taproot::ControlBlock::verify_taproot_commitment`] (merkle path +
//! `TapTweak` + `tweak_add_check` against the prevout x-only key).

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::Script;
use bitcoin::secp256k1::{Message, Parity};
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};
use bitcoin::{Transaction, Witness};

use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    tap_spent: &crypto::TapSpentHashes,
) -> Result<(), ConsensusError> {
    let spk = job.prevout_script(input_index)?;
    debug_assert!(spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20);
    let output_key = &spk[2..34];

    let input = &tx.input[input_index.get()];
    let wit_len = input.witness.len();
    if wit_len == 0 {
        return Err(ConsensusError::Script("p2tr empty witness".into()));
    }

    // Key-path: one element, or sig + annex (BIP341: annex = last stack item
    // starting with 0x50 when there are ≥2 items).
    if wit_len == 1 || (wit_len == 2 && bip341_annex(&input.witness).is_some()) {
        return verify_key_path(job, input_index, tx, output_key, tap_spent);
    }
    verify_script_path(job, input_index, tx, output_key, tap_spent)
}

/// BIP341 annex: last witness item, only when `len ≥ 2` and first byte is `0x50`.
#[doc(hidden)]
pub fn bip341_annex(witness: &Witness) -> Option<&[u8]> {
    if witness.len() < 2 {
        return None;
    }
    let last = witness.last()?;
    if !last.is_empty() && last[0] == 0x50 {
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
    let tweak = TapTweakHash::from_key_and_tweak(internal, Some(curr)).to_scalar();
    let ok = crypto::SECP.with(|secp| internal.tweak_add_check(secp, &output_key, parity, tweak));
    if !ok {
        return Err(ConsensusError::Script("WITNESS_PROGRAM_MISMATCH".into()));
    }
    Ok((leaf, tapleaf_hash))
}

#[doc(hidden)]
pub fn verify_script_path(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    output_key_bytes: &[u8],
    tap_spent: &crypto::TapSpentHashes,
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

    let exec = crypto::TapscriptExecData::new(job, input_index, tap_spent, tapleaf_hash, annex);
    let ctx = EvalContext::from_job(job, tx, input_index, script, SigVersion::TapScript)?
        .with_tapscript(exec);
    if interpreter::eval_script(script, &mut stack, &ctx)? {
        interpreter::require_clean_true(&stack)?;
    }
    Ok(())
}
