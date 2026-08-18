//! Native P2WSH verification (SegWit v0).

use bitcoin::script::Script;
use bitcoin::Transaction;

use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub(crate) fn verify(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
) -> Result<(), ConsensusError> {
    let spk = job.prevouts[input_index].script_pubkey.as_bytes();
    debug_assert!(spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20);
    let mut scripthash = [0u8; 32];
    scripthash.copy_from_slice(&spk[2..34]);
    verify_with_scripthash(job, input_index, tx, &scripthash)
}

pub(crate) fn verify_with_scripthash(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    scripthash: &[u8; 32],
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index];
    if input.witness.is_empty() {
        return Err(ConsensusError::Script("p2wsh empty witness".into()));
    }
    // Core `VerifyWitnessProgram` P2WSH: pop witnessScript first, then enforce
    // MAX_SCRIPT_ELEMENT_SIZE on the **remaining** stack only. The witnessScript
    // itself may exceed 520 (capped by MAX_SCRIPT_SIZE 10_000 during eval) —
    // applying 520 to the script rejects valid mainnet spends (e.g. h=842472).
    let wit_len = input.witness.len();
    let script_bytes = input
        .witness
        .nth(wit_len - 1)
        .ok_or_else(|| ConsensusError::Script("p2wsh witness".into()))?;
    let actual = crypto::sha256(script_bytes);
    if &actual != scripthash {
        return Err(ConsensusError::Script("p2wsh script hash".into()));
    }

    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(wit_len.saturating_sub(1));
    for i in 0..wit_len - 1 {
        let item = input
            .witness
            .nth(i)
            .ok_or_else(|| ConsensusError::Script("p2wsh witness".into()))?;
        if item.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ConsensusError::Script("PUSH_SIZE".into()));
        }
        stack.push(item.to_vec());
    }

    let script = Script::from_bytes(script_bytes);
    let ctx = EvalContext::from_job(job, tx, input_index, script, SigVersion::WitnessV0);
    if interpreter::eval_script(script, &mut stack, &ctx)? {
        interpreter::require_clean_true(&stack)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ScriptCheckJob;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    #[test]
    fn empty_witness_and_hash_mismatch() {
        let mut spk = vec![0x00, 0x20];
        spk.extend([0u8; 32]);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(10),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            tx: crate::block::JobTx::owned(Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }),
            bip65_active: true,
            bip112_active: true,
            bip66_active: true,
            bip16_active: true,
            taproot_active: true,
            minimal_if: false,
            nullfail: false,
            low_s: false,
            strictenc: false,
            null_dummy: false,
            minimal_data: false,
            witness_pubkeytype: false,
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            pre: std::sync::OnceLock::new(),
        };
        assert!(verify(&job, 0, &*job.tx).is_err());

        let mut job2 = job;
        job2.tx.input[0].witness = Witness::from_slice(&[vec![0x51]]); // OP_TRUE script
        assert!(verify_with_scripthash(&job2, 0, &*job2.tx, &[0u8; 32]).is_err());
    }
}
