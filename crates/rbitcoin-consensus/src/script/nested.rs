//! P2SH nested SegWit and legacy redeem scripts.

use bitcoin::script::{Instruction, Script};
use bitcoin::Transaction;

use bitcoin::sighash::SighashCache;

use super::classify;
use super::crypto;
use super::interpreter::{self, EvalContext, SigVersion};
use super::p2wpkh;
use super::p2wsh;
use crate::block::ScriptCheckJob;
use crate::error::ConsensusError;

/// Nested P2SH + witness-program redeem (BIP16 + BIP141).
///
/// When `job.witness_active` and the redeem (last push) is a BIP141 witness program
/// (any version, program 2..=40 bytes):
/// - `scriptSig` must **byte-equal** the minimal single-push encoding of that redeem
///   (`WITNESS_MALLEATED_P2SH` otherwise — multi-push or non-minimal encoding).
/// - Dispatch: v0/20 → P2WPKH, v0/32 → P2WSH, v0 other → `WITNESS_PROGRAM_WRONG_LENGTH`,
///   v1..=16 → anyone-can-spend success (no BIP341 on P2SH-wrapped programs).
///
/// Non-witness redeems return `None` so the caller falls through to
/// [`verify_p2sh_legacy`] (legacy multisig multi-push, etc.).
///
/// When `!job.witness_active`, always `None` (pre-segwit: redeem is ordinary Base script).
pub(crate) fn try_p2sh_nested_segwit(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
    _cache: &mut SighashCache<&Transaction>,
    pre: &crate::TxPrecompute,
) -> Option<Result<(), ConsensusError>> {
    if !job.witness_active {
        return None;
    }

    let script_sig = &tx.input[input_index].script_sig;
    let items = match push_only_items(script_sig) {
        Ok(i) => i,
        Err(e) => return Some(Err(e)),
    };
    if items.is_empty() {
        return None;
    }
    let redeem = items.last().unwrap().as_slice();
    let Some((version, program)) = classify::witness_program(Script::from_bytes(redeem)) else {
        return None;
    };

    // Core: scriptSig must be exactly CScript() << redeem (minimal single push).
    let canonical = minimal_push_encoding(redeem);
    if items.len() != 1 || script_sig.as_bytes() != canonical.as_slice() {
        return Some(Err(ConsensusError::Script("WITNESS_MALLEATED_P2SH".into())));
    }

    if let Err(e) =
        check_p2sh_redeem_hash(job.prevouts[input_index].script_pubkey.as_bytes(), redeem)
    {
        return Some(Err(e));
    }

    Some(match (version, program.len()) {
        (0, 20) => {
            let mut keyhash = [0u8; 20];
            keyhash.copy_from_slice(program);
            p2wpkh::verify_with_keyhash(job, input_index, tx, &keyhash, redeem, pre)
        }
        (0, 32) => {
            let mut scripthash = [0u8; 32];
            scripthash.copy_from_slice(program);
            p2wsh::verify_with_scripthash(job, input_index, tx, &scripthash)
        }
        (0, _) => Err(ConsensusError::Script(
            "WITNESS_PROGRAM_WRONG_LENGTH".into(),
        )),
        // v1..=16 in P2SH: Core VerifyWitnessProgram else-branch → success (ACS).
        _ => Ok(()),
    })
}

/// Legacy P2SH: scriptSig is `<…data pushes…> <redeemScript>`; evaluate redeem.
pub(crate) fn verify_p2sh_legacy(
    job: &ScriptCheckJob,
    input_index: usize,
    tx: &Transaction,
) -> Result<(), ConsensusError> {
    let input = &tx.input[input_index];
    let (mut stack, redeem) = split_script_sig_redeem(input.script_sig.as_script())?;
    check_p2sh_redeem_hash(job.prevouts[input_index].script_pubkey.as_bytes(), &redeem)?;

    let redeem_script = Script::from_bytes(&redeem);
    let ctx = EvalContext::from_job(job, tx, input_index, redeem_script, SigVersion::Base);
    if interpreter::eval_script(redeem_script, &mut stack, &ctx)? {
        // BIP16: true top only. Witness nested paths use cleanstack separately.
        interpreter::require_true_top(&stack)?;
    }
    Ok(())
}

/// P2SH spk shape + HASH160(redeem) match (shared by nested and legacy paths).
#[inline]
fn check_p2sh_redeem_hash(spk: &[u8], redeem: &[u8]) -> Result<(), ConsensusError> {
    if spk.len() != 23 {
        return Err(ConsensusError::Script("p2sh spk".into()));
    }
    let expected_hash = &spk[2..22];
    let actual = crypto::hash160(redeem);
    if actual.as_slice() != expected_hash {
        return Err(ConsensusError::Script("p2sh redeem hash".into()));
    }
    Ok(())
}

/// Core `MAX_SCRIPT_ELEMENT_SIZE` on a collected push (P2SH scriptSig path).
#[inline]
fn push_item_checked(bytes: &[u8]) -> Result<Vec<u8>, ConsensusError> {
    if bytes.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE {
        return Err(ConsensusError::Script("PUSH_SIZE".into()));
    }
    Ok(bytes.to_vec())
}

/// Minimal `CScript() << data` encoding for data lengths 0..=75 (witness-program redeems).
fn minimal_push_encoding(data: &[u8]) -> Vec<u8> {
    // Witness-program scripts are 4..=42 bytes → always direct OP_PUSHBYTES_n.
    debug_assert!(data.len() <= 75);
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(data.len() as u8);
    v.extend_from_slice(data);
    v
}

/// Collect push-only items from scriptSig (OP_0 / OP_1..16 / PushBytes). Non-push → Err.
/// Enforces [`interpreter::MAX_SCRIPT_ELEMENT_SIZE`] on every data push (Core EvalScript).
fn push_only_items(
    script_sig: &bitcoin::script::ScriptBuf,
) -> Result<Vec<Vec<u8>>, ConsensusError> {
    let mut items = Vec::new();
    for ins in script_sig.instructions() {
        match ins.map_err(|_| ConsensusError::Script("p2sh scriptSig".into()))? {
            Instruction::PushBytes(b) => items.push(push_item_checked(b.as_bytes())?),
            Instruction::Op(op) => {
                let n = op.to_u8();
                if n == 0x00 {
                    items.push(vec![]);
                } else if (0x51..=0x60).contains(&n) {
                    items.push(vec![n - 0x50]);
                } else {
                    return Err(ConsensusError::Script("p2sh scriptSig op".into()));
                }
            }
        }
    }
    Ok(items)
}

/// All pushes except the last form the initial stack; last push is redeemScript.
fn split_script_sig_redeem(script: &Script) -> Result<(Vec<Vec<u8>>, Vec<u8>), ConsensusError> {
    let mut items = Vec::new();
    for ins in script.instructions() {
        match ins.map_err(|_| ConsensusError::Script("p2sh scriptSig".into()))? {
            Instruction::PushBytes(b) => items.push(push_item_checked(b.as_bytes())?),
            Instruction::Op(op) => {
                let n = op.to_u8();
                if n == 0x00 {
                    items.push(vec![]);
                } else if (0x51..=0x60).contains(&n) {
                    items.push(vec![n - 0x50]);
                } else {
                    return Err(ConsensusError::Script("p2sh scriptSig op".into()));
                }
            }
        }
    }
    if items.is_empty() {
        return Err(ConsensusError::Script("p2sh empty scriptSig".into()));
    }
    let redeem = items.pop().unwrap();
    Ok((items, redeem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ScriptCheckJob;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    fn dummy_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn p2sh_spk(redeem: &[u8]) -> ScriptBuf {
        let h = crypto::hash160(redeem);
        let mut v = vec![0xa9, 0x14];
        v.extend_from_slice(&h);
        v.push(0x87);
        ScriptBuf::from_bytes(v)
    }

    fn job_for(tx: Transaction, spk: ScriptBuf, witness_active: bool) -> ScriptCheckJob {
        ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: spk,
            }],
            tx: crate::block::JobTx::owned(tx),
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
            witness_active,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            pre: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn push_only_and_split_helpers() {
        // Multi-push collects both items
        let multi = ScriptBuf::from_bytes(vec![0x01, 0xaa, 0x01, 0xbb]);
        assert_eq!(
            push_only_items(&multi).unwrap(),
            vec![vec![0xaa], vec![0xbb]]
        );
        // OP_1 as push
        let op = ScriptBuf::from_bytes(vec![0x51]);
        assert_eq!(push_only_items(&op).unwrap(), vec![vec![0x01]]);
        // Single push
        let one = ScriptBuf::from_bytes(vec![0x02, 0xde, 0xad]);
        assert_eq!(push_only_items(&one).unwrap(), vec![vec![0xde, 0xad]]);
        // Malformed truncated push → Err
        let bad = ScriptBuf::from_bytes(vec![0x05, 0x01]);
        assert!(push_only_items(&bad).is_err());
        // Non-push opcode → Err
        assert!(push_only_items(&ScriptBuf::from_bytes(vec![0xac])).is_err());

        // split: OP_0 and OP_1 as stack items
        let ss = Script::from_bytes(&[0x00, 0x51, 0x01, 0xac]);
        let (stack, redeem) = split_script_sig_redeem(ss).unwrap();
        assert_eq!(stack, vec![vec![], vec![0x01]]);
        assert_eq!(redeem, vec![0xac]);
        // empty
        assert!(split_script_sig_redeem(Script::from_bytes(&[])).is_err());
        // unexpected op
        assert!(split_script_sig_redeem(Script::from_bytes(&[0xac])).is_err());
    }

    /// Finding 006: Core MAX_SCRIPT_ELEMENT_SIZE on every P2SH scriptSig push.
    #[test]
    fn p2sh_scriptsig_push_over_520_rejected() {
        // Redeem = OP_TRUE padded with OP_DROP + 521-byte push inside redeem would be
        // redeem-eval path. Here the **scriptSig push** of redeem itself is 521 bytes.
        let mut redeem = vec![0x51]; // OP_TRUE
        redeem.extend(std::iter::repeat_n(0x61u8, 520)); // pad so len=521
        assert!(redeem.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE);

        // Minimal encoding of 521-byte push uses PUSHDATA2 (0x4d).
        let mut ss = vec![0x4d];
        ss.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
        ss.extend_from_slice(&redeem);

        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);

        let err = verify_p2sh_legacy(&job, 0, &*job.tx).expect_err("PUSH_SIZE");
        let msg = format!("{err}");
        assert!(
            msg.contains("PUSH_SIZE") || msg.contains("520") || msg.contains("element"),
            "expected PUSH_SIZE-class error, got {err}"
        );

        // Collector helpers fail the same way.
        assert!(push_only_items(&job.tx.input[0].script_sig).is_err());
        assert!(split_script_sig_redeem(job.tx.input[0].script_sig.as_script()).is_err());
    }

    /// Finding 007 (a): non-minimal redeem push → WITNESS_MALLEATED_P2SH.
    #[test]
    fn p2sh_nested_non_minimal_redeem_push_malleated() {
        let redeem = {
            let mut r = vec![0x00, 0x14];
            r.extend([0xab; 20]);
            r
        };
        // PUSHDATA1 instead of direct OP_PUSHBYTES_22
        let mut ss = vec![0x4c, redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        // Valid witness for shape (still malleated on scriptSig).
        tx.input[0].witness = Witness::from_slice(&[vec![0u8; 64], vec![0x02; 33]]);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
        let mut cache = SighashCache::new(&*job.tx);
        let r = try_p2sh_nested_segwit(
            &job,
            0,
            &*job.tx,
            &mut cache,
            &crate::TxPrecompute::from_tx(&*job.tx),
        );
        match r {
            Some(Err(e)) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("WITNESS_MALLEATED_P2SH"),
                    "expected malleated, got {e}"
                );
            }
            other => panic!("expected Some(Err malleated), got {other:?}"),
        }
    }

    /// Finding 007 (b): multi-push last = witness program → malleated (not legacy).
    #[test]
    fn p2sh_nested_multi_push_witness_program_malleated() {
        let redeem = {
            let mut r = vec![0x00, 0x20];
            r.extend([0xcd; 32]);
            r
        };
        let mut ss = vec![0x01, 0xaa];
        ss.push(redeem.len() as u8);
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        // Empty witness — must not succeed via legacy truthy-top.
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
        let mut cache = SighashCache::new(&*job.tx);
        let r = try_p2sh_nested_segwit(
            &job,
            0,
            &*job.tx,
            &mut cache,
            &crate::TxPrecompute::from_tx(&*job.tx),
        );
        match r {
            Some(Err(e)) => {
                assert!(format!("{e}").contains("WITNESS_MALLEATED_P2SH"), "got {e}");
            }
            other => panic!("expected malleated, got {other:?}"),
        }
        // Full verify_input must not legacy-accept either.
        assert!(crate::script::verify_job_all_inputs(&job).is_err());
    }

    /// Finding 007 (c): v0 wrong-length program → WITNESS_PROGRAM_WRONG_LENGTH.
    #[test]
    fn p2sh_nested_v0_wrong_length_program_rejected() {
        // 0x00 0x12 <18 bytes> — IsWitnessProgram, not 20/32.
        let redeem = {
            let mut r = vec![0x00, 0x12];
            r.extend([0x11; 18]);
            r
        };
        let mut ss = vec![redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
        let mut cache = SighashCache::new(&*job.tx);
        let r = try_p2sh_nested_segwit(
            &job,
            0,
            &*job.tx,
            &mut cache,
            &crate::TxPrecompute::from_tx(&*job.tx),
        );
        match r {
            Some(Err(e)) => {
                assert!(
                    format!("{e}").contains("WITNESS_PROGRAM_WRONG_LENGTH"),
                    "got {e}"
                );
            }
            other => panic!("expected wrong length, got {other:?}"),
        }
    }

    /// Pre-segwit: nested gate is off; multi-push/single-push both fall through.
    #[test]
    fn p2sh_nested_inactive_witness_flag_returns_none() {
        let redeem = {
            let mut r = vec![0x00, 0x14];
            r.extend([0xab; 20]);
            r
        };
        let mut ss = vec![redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), false);
        let mut cache = SighashCache::new(&*job.tx);
        assert!(
            try_p2sh_nested_segwit(
                &job,
                0,
                &*job.tx,
                &mut cache,
                &crate::TxPrecompute::from_tx(&*job.tx)
            )
            .is_none(),
            "without witness_active nested must not fire"
        );
    }

    /// Control: multi-push non-witness redeem still falls through to legacy.
    #[test]
    fn p2sh_legacy_multi_push_non_witness_fallthrough() {
        let redeem = vec![0x51]; // OP_TRUE
        let mut ss = vec![0x01, 0xaa, redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
        let mut cache = SighashCache::new(&*job.tx);
        assert!(
            try_p2sh_nested_segwit(
                &job,
                0,
                &*job.tx,
                &mut cache,
                &crate::TxPrecompute::from_tx(&*job.tx)
            )
            .is_none(),
            "non-witness multi-push must not enter nested gate"
        );
        assert!(verify_p2sh_legacy(&job, 0, &*job.tx).is_ok());
    }

    /// Control: v1 program in P2SH + exact scriptSig → ACS success.
    #[test]
    fn p2sh_nested_v1_program_anyone_can_spend() {
        let redeem = {
            let mut r = vec![0x51, 0x20]; // OP_1 + 32-byte program
            r.extend([0xee; 32]);
            r
        };
        let mut ss = vec![redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
        let mut cache = SighashCache::new(&*job.tx);
        let r = try_p2sh_nested_segwit(
            &job,
            0,
            &*job.tx,
            &mut cache,
            &crate::TxPrecompute::from_tx(&*job.tx),
        );
        assert!(matches!(r, Some(Ok(()))), "v1-in-P2SH ACS, got {r:?}");
    }

    #[test]
    fn try_nested_error_paths() {
        let mut tx = dummy_tx();
        // Redeem looks like P2WPKH program but wrong outer P2SH hash / spk length
        let redeem = {
            let mut r = vec![0x00, 0x14];
            r.extend([0u8; 20]);
            r
        };
        let mut ss = vec![redeem.len() as u8];
        ss.extend_from_slice(&redeem);
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]), // not 23-byte P2SH
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
        let r = try_p2sh_nested_segwit(
            &job,
            0,
            &*job.tx,
            &mut cache,
            &crate::TxPrecompute::from_tx(&*job.tx),
        );
        assert!(matches!(r, Some(Err(_))));

        // Wrong redeem hash
        let job2 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&[0xff]),
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
        let mut cache2 = SighashCache::new(&*job2.tx);
        assert!(matches!(
            try_p2sh_nested_segwit(
                &job2,
                0,
                &*job2.tx,
                &mut cache2,
                &crate::TxPrecompute::from_tx(&*job2.tx)
            ),
            Some(Err(_))
        ));

        // P2WSH redeem shape
        let redeem_wsh = {
            let mut r = vec![0x00, 0x20];
            r.extend([0u8; 32]);
            r
        };
        let mut ss2 = vec![redeem_wsh.len() as u8];
        ss2.extend_from_slice(&redeem_wsh);
        let mut tx3 = dummy_tx();
        tx3.input[0].script_sig = ScriptBuf::from_bytes(ss2);
        let job3 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00]), // short spk
            }],
            tx: crate::block::JobTx::owned(tx3.clone()),
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
        assert!(matches!(
            try_p2sh_nested_segwit(
                &job3,
                0,
                &*job3.tx,
                &mut SighashCache::new(&*job3.tx),
                &crate::TxPrecompute::from_tx(&*job3.tx)
            ),
            Some(Err(_))
        ));
        // wrong hash
        let job4 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&[0x01]),
            }],
            tx: crate::block::JobTx::owned(tx3.clone()),
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
        assert!(matches!(
            try_p2sh_nested_segwit(
                &job4,
                0,
                &*job4.tx,
                &mut SighashCache::new(&*job4.tx),
                &crate::TxPrecompute::from_tx(&*job4.tx)
            ),
            Some(Err(_))
        ));

        // Multi-push non-witness → None (fallthrough)
        let mut tx5 = dummy_tx();
        tx5.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0xaa, 0x01, 0xbb]);
        let job5 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&[0xaa]),
            }],
            tx: crate::block::JobTx::owned(tx5.clone()),
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
        let mut c5 = SighashCache::new(&*job5.tx);
        assert!(try_p2sh_nested_segwit(
            &job5,
            0,
            &*job5.tx,
            &mut c5,
            &crate::TxPrecompute::from_tx(&*job5.tx)
        )
        .is_none());

        // Legacy wrong spk / hash / empty
        assert!(verify_p2sh_legacy(&job3, 0, &*job3.tx).is_err());
        let mut tx_empty = dummy_tx();
        tx_empty.input[0].script_sig = ScriptBuf::new();
        let job_e = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&[0x51]),
            }],
            tx: crate::block::JobTx::owned(tx_empty.clone()),
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
        assert!(verify_p2sh_legacy(&job_e, 0, &*job_e.tx).is_err());
        // Hash mismatch on legacy
        let mut tx_leg = dummy_tx();
        tx_leg.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x51]);
        let job_h = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&[0xff]),
            }],
            tx: crate::block::JobTx::owned(tx_leg.clone()),
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
        assert!(verify_p2sh_legacy(&job_h, 0, &*job_h.tx).is_err());
    }

    /// Matching outer hash routes into p2wsh/p2wpkh verify (covers scripthash copy path).
    #[test]
    fn try_nested_matching_hash_enters_witness_verify() {
        let redeem_wsh = {
            let mut r = vec![0x00, 0x20];
            r.extend([0xab; 32]);
            r
        };
        let mut ss = vec![redeem_wsh.len() as u8];
        ss.extend_from_slice(&redeem_wsh);
        let mut tx = dummy_tx();
        tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
        let job = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&redeem_wsh),
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
        // Empty witness → p2wsh fails, but nested path reached scripthash copy + call.
        assert!(matches!(
            try_p2sh_nested_segwit(
                &job,
                0,
                &*job.tx,
                &mut SighashCache::new(&*job.tx),
                &crate::TxPrecompute::from_tx(&*job.tx),
            ),
            Some(Err(_))
        ));

        let redeem_wpkh = {
            let mut r = vec![0x00, 0x14];
            r.extend([0xcd; 20]);
            r
        };
        let mut ss2 = vec![redeem_wpkh.len() as u8];
        ss2.extend_from_slice(&redeem_wpkh);
        let mut tx2 = dummy_tx();
        tx2.input[0].script_sig = ScriptBuf::from_bytes(ss2);
        let job2 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&redeem_wpkh),
            }],
            tx: crate::block::JobTx::owned(tx2.clone()),
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
        let mut cache = SighashCache::new(&*job2.tx);
        assert!(matches!(
            try_p2sh_nested_segwit(
                &job2,
                0,
                &*job2.tx,
                &mut cache,
                &crate::TxPrecompute::from_tx(&*job2.tx),
            ),
            Some(Err(_))
        ));

        // Legacy OP_TRUE redeem succeeds (require_true_top path).
        let redeem = vec![0x51]; // OP_TRUE
        let mut ss3 = vec![0x01, 0xaa, redeem.len() as u8];
        ss3.extend_from_slice(&redeem);
        // stack push 0xaa + redeem OP_TRUE
        let mut tx3 = dummy_tx();
        tx3.input[0].script_sig = ScriptBuf::from_bytes(ss3);
        let job3 = ScriptCheckJob {
            txid: [0u8; 32],
            prevouts: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: p2sh_spk(&redeem),
            }],
            tx: crate::block::JobTx::owned(tx3.clone()),
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
        assert!(verify_p2sh_legacy(&job3, 0, &*job3.tx).is_ok());

        // OP_0 as first stack item in split (covers n==0x00 branch already hit);
        // also OP_16 small-int push.
        let ss_op = Script::from_bytes(&[0x00, 0x60, 0x01, 0x51]);
        let (stack, redeem) = split_script_sig_redeem(ss_op).unwrap();
        assert_eq!(stack, vec![vec![], vec![0x10]]);
        assert_eq!(redeem, vec![0x51]);
    }
}
