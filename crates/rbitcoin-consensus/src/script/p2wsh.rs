//! Native P2WSH verification (SegWit v0).

use bitcoin::script::Script;
use bitcoin::Transaction;

use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub fn verify(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
) -> Result<(), ConsensusError> {
    let spk = job.prevout_script(input_index)?;
    debug_assert!(spk.len() == 34 && spk.starts_with(&rbitcoin_primitives::P2WSH_PREFIX));
    let mut scripthash = [0u8; 32];
    scripthash.copy_from_slice(&spk[2..34]);
    verify_with_scripthash(job, input_index, tx, &scripthash)
}

pub fn verify_with_scripthash(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    scripthash: &[u8; 32],
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index.get()];
    if input.witness.is_empty() {
        return Err(ConsensusError::Script("p2wsh empty witness".into()));
    }
    // P2WSH: pop witnessScript first, then enforce MAX_SCRIPT_ELEMENT_SIZE on
    // the **remaining** stack only. The witnessScript itself may exceed 520
    // (capped by MAX_SCRIPT_SIZE 10_000 during eval) — applying 520 to the
    // script rejects valid mainnet spends (e.g. h=842472).
    let wit_len = input.witness.len();
    let script_bytes = input
        .witness
        .nth(wit_len - 1)
        .ok_or_else(|| ConsensusError::Script("p2wsh witness".into()))?;
    let actual = crypto::sha256(script_bytes);
    if &actual != scripthash {
        return Err(ConsensusError::Script("p2wsh script hash".into()));
    }

    execute_witness_v0(
        job,
        input_index,
        tx,
        Script::from_bytes(script_bytes),
        input.witness.iter().take(wit_len - 1),
    )
}

/// Core `ExecuteWitnessScript` for witness v0: every initial stack item is
/// at most 520 bytes, then `script` runs and must leave exactly one true item.
pub fn execute_witness_v0<'w>(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    script: &Script,
    items: impl Iterator<Item = &'w [u8]>,
) -> Result<(), ConsensusError> {
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(items.size_hint().0);
    for item in items {
        if item.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ConsensusError::Script("PUSH_SIZE".into()));
        }
        stack.push(item.to_vec());
    }
    let ctx = EvalContext::from_job(job, tx, input_index, script, SigVersion::WitnessV0)?;
    // Witness v0 eval returns `Ok(true)` or `Err`. `Ok(false)` is tapscript OP_SUCCESS.
    interpreter::eval_script(script, &mut stack, &ctx)?;
    interpreter::require_clean_true(&stack)?;
    Ok(())
}
