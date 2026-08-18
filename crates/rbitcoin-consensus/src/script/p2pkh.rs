//! Native P2PKH verification (legacy).

use bitcoin::hashes::Hash;
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;

use super::crypto;
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

pub(crate) fn verify(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    cache: &mut SighashCache<&Transaction>,
) -> Result<(), ConsensusError> {
    let _ = tx;
    let spk = job.prevouts[input_index].script_pubkey.as_bytes();
    debug_assert!(spk.len() == 25);
    let keyhash = &spk[3..23];

    let input = &tx.input[input_index];
    let (sig_raw, pubkey_raw) = parse_two_pushes(input.script_sig.as_script())?;

    let pk_hash = crypto::hash160(&pubkey_raw);
    if pk_hash.as_slice() != keyhash {
        return Err(ConsensusError::Script("p2pkh pubkey hash".into()));
    }

    let (sig, sighash_ty) = crypto::parse_der_sig(&sig_raw, job.bip66_active)?;
    let pubkey = crypto::parse_pubkey(&pubkey_raw)?;

    let script_code = job.prevouts[input_index].script_pubkey.as_script();
    // Raw hashtype byte (may be 0 — must not normalize to SIGHASH_ALL).
    let sighash = cache
        .legacy_signature_hash(input_index, script_code, sighash_ty)
        .map_err(|_| ConsensusError::Script("p2pkh sighash".into()))?;
    if crypto::verify_ecdsa(sighash.to_byte_array(), &sig, &pubkey) {
        Ok(())
    } else {
        Err(ConsensusError::Script("p2pkh ecdsa".into()))
    }
}

fn parse_two_pushes(script: &Script) -> Result<(Vec<u8>, Vec<u8>), ConsensusError> {
    let mut items = Vec::with_capacity(2);
    for ins in script.instructions() {
        match ins.map_err(|_| ConsensusError::Script("p2pkh scriptSig".into()))? {
            Instruction::PushBytes(b) => items.push(b.as_bytes().to_vec()),
            Instruction::Op(op) if op.to_u8() >= 0x51 && op.to_u8() <= 0x60 => {
                return Err(ConsensusError::Script("p2pkh scriptSig op".into()));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ScriptCheckJob;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    #[test]
    fn parse_two_pushes_errors() {
        assert!(parse_two_pushes(Script::from_bytes(&[0x51])).is_err()); // OP_1
        assert!(parse_two_pushes(Script::from_bytes(&[0x00])).is_err()); // OP_0 unexpected
        assert!(parse_two_pushes(Script::from_bytes(&[0x01, 0xaa])).is_err()); // len
        assert!(parse_two_pushes(Script::from_bytes(&[0x05, 0x01])).is_err()); // decode
        let ok = parse_two_pushes(Script::from_bytes(&[0x01, 0xaa, 0x01, 0xbb])).unwrap();
        assert_eq!(ok, (vec![0xaa], vec![0xbb]));
    }

    #[test]
    fn verify_pubkey_hash_mismatch() {
        let mut spk = vec![0x76, 0xa9, 0x14];
        spk.extend([0u8; 20]);
        spk.extend([0x88, 0xac]);
        let mut ss = vec![0x01, 0x30, 0x21];
        ss.extend([0x02; 33]); // fake compressed pubkey
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(10),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            tx: crate::block::JobTx::owned(tx.clone()),
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
        let mut cache = SighashCache::new(&*job.tx);
        let err = verify(&job, 0, &*job.tx, &mut cache).unwrap_err();
        assert!(format!("{err}").contains("p2pkh"));
    }
}
