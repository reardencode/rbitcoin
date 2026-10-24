//! Native P2PKH verification (legacy).

use bitcoin::hashes::Hash;
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;

use super::{crypto, interpreter};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    cache: &mut SighashCache<&Transaction>,
) -> Result<(), ConsensusError> {
    let _ = tx;
    let spk = job.prevout_script(input_index)?;
    debug_assert!(spk.len() == 25);
    let keyhash = &spk[3..23];

    let input = &tx.input[input_index.get()];
    let (sig_raw, pubkey_raw) = parse_two_pushes(input.script_sig.as_script())?;

    let pk_hash = crypto::hash160(&pubkey_raw);
    if pk_hash.as_slice() != keyhash {
        return Err(ConsensusError::Script("p2pkh pubkey hash".into()));
    }

    let (sig, sighash_ty) = crypto::parse_der_sig(&sig_raw, job.bip66_active)?;
    let pubkey = crypto::parse_pubkey(&pubkey_raw)?;

    let script_code = Script::from_bytes(job.prevout_script(input_index)?);
    // Raw hashtype byte (may be 0 — must not normalize to SIGHASH_ALL).
    let sighash = cache
        .legacy_signature_hash(input_index.get(), script_code, sighash_ty)
        .map_err(|_| ConsensusError::Script("p2pkh sighash".into()))?;
    if crypto::verify_ecdsa(sighash.to_byte_array(), &sig, &pubkey) {
        Ok(())
    } else {
        Err(ConsensusError::Script("p2pkh ecdsa".into()))
    }
}

#[doc(hidden)]
pub fn parse_two_pushes(script: &Script) -> Result<(Vec<u8>, Vec<u8>), ConsensusError> {
    let mut items = Vec::with_capacity(2);
    for ins in script.instructions() {
        match ins.map_err(|_| ConsensusError::Script("p2pkh scriptSig".into()))? {
            // Over-size pushes are a shape error so the interpreter reports
            // PUSH_SIZE. Two pushes of at most 520 bytes keep the scriptSig
            // far below MAX_SCRIPT_SIZE.
            Instruction::PushBytes(b) if b.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE => {
                return Err(ConsensusError::Script("p2pkh scriptSig".into()));
            }
            Instruction::PushBytes(b) => items.push(b.as_bytes().to_vec()),
            // OP_1..=OP_16 and every other opcode are the same shape error.
            Instruction::Op(_) => {
                return Err(ConsensusError::Script(
                    "p2pkh scriptSig unexpected op".into(),
                ));
            }
        }
    }
    if items.len() != 2 {
        return Err(ConsensusError::Script("p2pkh scriptSig len".into()));
    }
    Ok((items[0].clone(), items[1].clone()))
}
