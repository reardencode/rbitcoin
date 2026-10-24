//! P2SH nested SegWit and legacy redeem scripts.

use bitcoin::script::Script;
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
///   v1..=16 → anyone-can-spend success (no BIP341 on P2SH-wrapped programs) unless
///   `discourage_upgradable_witness`.
///
/// Non-witness redeems return `None` so the caller falls through to
/// [`verify_p2sh_legacy`] (legacy multisig multi-push, etc.).
///
/// When `!job.witness_active`, always `None` (pre-segwit: redeem is ordinary Base script).
pub fn try_p2sh_nested_segwit(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    _cache: &mut SighashCache<&Transaction>,
    pre: &crate::TxScriptPrecompute,
    items: &[Vec<u8>],
) -> Option<Result<(), ConsensusError>> {
    if !job.witness_active {
        return None;
    }

    let script_sig = &tx.input[input_index.get()].script_sig;
    if items.is_empty() {
        return None;
    }
    let redeem = items.last().unwrap().as_slice();
    let (version, program) = classify::witness_program(Script::from_bytes(redeem))?;

    // Core: scriptSig must be exactly CScript() << redeem (minimal single push).
    let canonical = minimal_push_encoding(redeem);
    if items.len() != 1 || script_sig.as_bytes() != canonical.as_slice() {
        return Some(Err(ConsensusError::Script("WITNESS_MALLEATED_P2SH".into())));
    }

    let outer = match job.prevout_script(input_index) {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    if let Err(e) = check_p2sh_redeem_hash(outer, redeem) {
        return Some(Err(e));
    }
    if !bitcoin::script::read_scriptbool(program) {
        return Some(Err(ConsensusError::Script("EVAL_FALSE".into())));
    }

    Some(match (version, program.len()) {
        (0, 20) if super::needs_interpreted_ecdsa(job) => {
            p2wpkh::verify_interpreted(job, input_index, tx, program)
        }
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
        // v1..=16 in P2SH: Core VerifyWitnessProgram else-branch (no Taproot,
        // no anchor when `is_p2sh`) → success unless discouraged.
        _ if job.discourage_upgradable_witness => Err(ConsensusError::Script(
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM".into(),
        )),
        _ => Ok(()),
    })
}

/// Legacy P2SH: scriptSig is `<…data pushes…> <redeemScript>`; evaluate redeem.
pub fn verify_p2sh_legacy(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
    mut stack: Vec<Vec<u8>>,
) -> Result<(), ConsensusError> {
    if stack.is_empty() {
        return Err(ConsensusError::Script("p2sh empty scriptSig".into()));
    }
    let redeem = stack.pop().unwrap();
    check_p2sh_redeem_hash(job.prevout_script(input_index)?, &redeem)?;

    let redeem_script = Script::from_bytes(&redeem);
    let ctx = EvalContext::from_job(job, tx, input_index, redeem_script, SigVersion::Base)?;
    // Base eval returns `Ok(true)` or `Err`. `Ok(false)` is tapscript OP_SUCCESS.
    // BIP16: true top unless CLEANSTACK. Witness nested paths clean separately.
    interpreter::eval_script(redeem_script, &mut stack, &ctx)?;
    if job.cleanstack {
        interpreter::require_clean_true(&stack)?;
    } else {
        interpreter::require_true_top(&stack)?;
    }
    Ok(())
}

pub fn p2sh_script_sig_stack(
    job: &ScriptCheckJob,
    input_index: crate::block::InputIndex,
    tx: &Transaction,
) -> Result<Vec<Vec<u8>>, ConsensusError> {
    let script_sig = tx.input[input_index.get()].script_sig.as_script();
    let ctx = EvalContext::from_job(job, tx, input_index, script_sig, SigVersion::Base)?;
    let mut stack = Vec::new();
    let _ = interpreter::eval_script(script_sig, &mut stack, &ctx)?;
    require_room_for_p2sh_hash_push(&stack)?;
    if !script_sig.is_push_only() {
        return Err(ConsensusError::Script("p2sh scriptSig op".into()));
    }
    Ok(stack)
}

/// Core `VerifyScript` runs the scriptPubKey `HASH160 <20> EQUAL` on the
/// scriptSig stack before the push-only check and the redeemScript. The
/// `<20>` push is the one step that grows the stack, so a scriptSig that
/// leaves `MAX_STACK_SIZE` items fails there with `stack size`.
///
/// CPU/RAM trade: this depth check stands in for running the scriptPubKey,
/// which would clone the stack and hash the redeemScript a second time on
/// every P2SH input. The hash match itself is [`check_p2sh_redeem_hash`].
#[doc(hidden)]
pub fn require_room_for_p2sh_hash_push(stack: &[Vec<u8>]) -> Result<(), ConsensusError> {
    if stack.len() >= interpreter::MAX_STACK_SIZE {
        return Err(ConsensusError::Script("stack size".into()));
    }
    Ok(())
}

/// P2SH spk shape + HASH160(redeem) match (shared by nested and legacy paths).
#[inline]
#[doc(hidden)]
pub fn check_p2sh_redeem_hash(spk: &[u8], redeem: &[u8]) -> Result<(), ConsensusError> {
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

/// Minimal `CScript() << data` encoding for data lengths 0..=75 (witness-program redeems).
#[doc(hidden)]
pub fn minimal_push_encoding(data: &[u8]) -> Vec<u8> {
    // Witness-program scripts are 4..=42 bytes → always direct OP_PUSHBYTES_n.
    debug_assert!(data.len() <= 75);
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(data.len() as u8);
    v.extend_from_slice(data);
    v
}
