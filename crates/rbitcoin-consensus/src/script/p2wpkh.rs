//! Native P2WPKH verification (SegWit v0).

use bitcoin::script::Script;
use bitcoin::Transaction;

use super::{crypto, interpreter, p2wsh};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;
use crate::TxScriptPrecompute;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    pre: &TxScriptPrecompute,
) -> Result<(), ConsensusError> {
    let spk = job.prevout_script(input_index)?;
    debug_assert!(spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14);
    let mut keyhash = [0u8; 20];
    keyhash.copy_from_slice(&spk[2..22]);

    let input = &tx.input[input_index.get()];
    if input.witness.len() != 2 {
        return Err(ConsensusError::Script("p2wpkh witness len".into()));
    }
    let sig_raw = input
        .witness
        .nth(0)
        .ok_or_else(|| ConsensusError::Script("p2wpkh witness".into()))?;
    let pubkey_raw = input
        .witness
        .nth(1)
        .ok_or_else(|| ConsensusError::Script("p2wpkh witness".into()))?;
    if sig_raw.is_empty() || pubkey_raw.is_empty() {
        return Err(ConsensusError::Script("p2wpkh empty witness item".into()));
    }
    verify_with_keyhash(job, input_index, tx, &keyhash, spk, pre)
}

/// Nested P2SH-P2WPKH: `witness_program` is the 22-byte redeem (not outer P2SH spk).
pub fn verify_with_keyhash(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    keyhash: &[u8; 20],
    witness_program: &[u8],
    pre: &TxScriptPrecompute,
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index.get()];
    if input.witness.len() != 2 {
        return Err(ConsensusError::Script("p2wpkh witness len".into()));
    }
    let sig_raw = input
        .witness
        .nth(0)
        .ok_or_else(|| ConsensusError::Script("p2wpkh witness".into()))?;
    let pubkey_raw = input
        .witness
        .nth(1)
        .ok_or_else(|| ConsensusError::Script("p2wpkh witness".into()))?;
    check_element_sizes(sig_raw, pubkey_raw)?;

    let pk_hash = crypto::hash160(pubkey_raw);
    if &pk_hash != keyhash {
        return Err(ConsensusError::Script("p2wpkh pubkey hash".into()));
    }

    if job.witness_pubkeytype && !crypto::is_compressed_pubkey(pubkey_raw) {
        return Err(ConsensusError::Script("WITNESS_PUBKEYTYPE".into()));
    }
    let (sig, sighash_ty) = crypto::parse_der_sig(sig_raw, job.bip66_active)?;
    let pubkey = crypto::parse_pubkey(pubkey_raw)?;

    let amount = job.prevout_amount(input_index)?;
    let spk = bitcoin::script::Script::from_bytes(witness_program);
    let sighash =
        crypto::bip143_p2wpkh_signature_hash(tx, input_index, spk, amount, sighash_ty, pre)?;
    if crypto::verify_ecdsa(sighash, &sig, &pubkey) {
        Ok(())
    } else {
        Err(ConsensusError::Script("p2wpkh ecdsa".into()))
    }
}

/// Core `ExecuteWitnessScript`: every initial witness stack element is at
/// most MAX_SCRIPT_ELEMENT_SIZE.
#[doc(hidden)]
pub fn check_element_sizes(sig_raw: &[u8], pubkey_raw: &[u8]) -> Result<(), ConsensusError> {
    if sig_raw.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE
        || pubkey_raw.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE
    {
        return Err(ConsensusError::Script("PUSH_SIZE".into()));
    }
    Ok(())
}

/// P2WPKH through the interpreter: Core `ExecuteWitnessScript` on
/// `DUP HASH160 <keyhash> EQUALVERIFY CHECKSIG`. Used when LOW_S, STRICTENC,
/// or NULLFAIL is set; the typed paths above do not apply those flags.
pub fn verify_interpreted(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    keyhash: &[u8],
) -> Result<(), ConsensusError> {
    let witness = &tx.input[input_index.get()].witness;
    if witness.len() != 2 {
        return Err(ConsensusError::Script("p2wpkh witness len".into()));
    }
    let mut script_code = Vec::with_capacity(25);
    script_code.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script_code.extend_from_slice(keyhash);
    script_code.extend_from_slice(&[0x88, 0xac]);
    p2wsh::execute_witness_v0(
        job,
        input_index,
        tx,
        Script::from_bytes(&script_code),
        witness.iter(),
    )
}
