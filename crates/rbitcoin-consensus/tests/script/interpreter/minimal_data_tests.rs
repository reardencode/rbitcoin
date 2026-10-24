use bitcoin::absolute::LockTime;
use bitcoin::script::Script;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, Sequence, Transaction};
use bitcoin::{OutPoint, TxIn, TxOut, Witness};
use rbitcoin_consensus::script::interpreter::*;

fn eval_md(script_bytes: &[u8], md: bool) -> Result<(), String> {
    let tx = Transaction {
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
    };
    let script = Script::from_bytes(script_bytes);
    let mut ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, SigVersion::Base);
    ctx.minimal_data = md;
    let mut stack = Vec::new();
    eval_script(script, &mut stack, &ctx).map_err(|e| format!("{e}"))?;
    require_true_top(&stack).map_err(|e| format!("{e}"))
}

fn push_is_minimal(data: &[u8], opcode: u8) -> bool {
    check_minimal_push(ScriptElem::new(data).unwrap(), opcode)
}

#[test]
fn check_minimal_push_table() {
    assert!(push_is_minimal(&[], 0x00));
    assert!(!push_is_minimal(&[], 0x4c)); // empty must be OP_0
    assert!(push_is_minimal(&[5], 0x55)); // OP_5
    assert!(!push_is_minimal(&[5], 0x01)); // direct push of 5 non-minimal
    assert!(push_is_minimal(&[0x81], 0x4f)); // OP_1NEGATE
    assert!(!push_is_minimal(&[0x81], 0x01));
    assert!(push_is_minimal(&[0x00], 0x01)); // one zero byte is fine
    assert!(push_is_minimal(&[0x11], 0x01)); // 17 as direct push
    assert!(push_is_minimal(&[0u8; 76], 0x4c)); // PUSHDATA1 for 76
    assert!(!push_is_minimal(&[0u8; 76], 0x4d));
}

#[test]
fn executed_nonminimal_push_rejects_when_flag_on() {
    // PUSHDATA1 empty (0x4c 0x00) then DROP OP_1
    let script = vec![0x4c, 0x00, 0x75, 0x51];
    let err = eval_md(&script, true).unwrap_err();
    assert!(err.contains("MINIMALDATA"), "{err}");
    // Same script OK without the flag.
    eval_md(&script, false).expect("without MINIMALDATA");
}

#[test]
fn unexecuted_nonminimal_push_ignored() {
    // OP_0 IF PUSHDATA1-empty ENDIF OP_1 — Core ignores non-minimal in false branch.
    let script = vec![0x00, 0x63, 0x4c, 0x00, 0x68, 0x51];
    eval_md(&script, true).expect("unexecuted non-minimal push OK");
}

#[test]
fn nonminimal_scriptnum_rejects_when_flag_on() {
    // Push 0x00 (one zero byte) then NOT DROP OP_1 → SCRIPTNUM under flag.
    let script = vec![0x01, 0x00, 0x91, 0x75, 0x51];
    let err = eval_md(&script, true).unwrap_err();
    assert!(err.contains("SCRIPTNUM"), "{err}");
    // Without flag the zero-pad is accepted as 0; NOT → true; DROP; OP_1 → OK.
    eval_md(&script, false).expect("without require_minimal");
}

#[test]
fn production_default_minimal_data_off() {
    let tx = Transaction {
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
    };
    let script = Script::from_bytes(&[0x51]);
    let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), script, SigVersion::Base);
    assert!(!ctx.minimal_data);
    assert!(!ctx.nullfail && !ctx.low_s && !ctx.strictenc && !ctx.null_dummy);
}

/// DERSIG: invalid DER encoding hard-fails; pre-BIP66 soft-fails CHECKSIG.
#[test]
fn dersig_hard_fails_invalid_encoding() {
    // Push 0xff + OP_0 + CHECKSIG
    let script = vec![0x01, 0xff, 0x00, 0xac];
    let tx = Transaction {
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
    };
    let sc = Script::from_bytes(&script);
    let ctx_on = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(50_000),
        sc,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack = Vec::new();
    let err = eval_script(sc, &mut stack, &ctx_on).unwrap_err();
    assert!(format!("{err}").contains("SIG_DER"), "{err}");

    let ctx_off = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(50_000),
        sc,
        SigVersion::Base,
        true,
        true,
        false,
    );
    let mut stack = Vec::new();
    eval_script(sc, &mut stack, &ctx_off).expect("pre-bip66 soft-false CHECKSIG");
    assert!(!bitcoin::script::read_scriptbool(stack.last().unwrap()));

    let mut flags =
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false);
    flags.low_s = true;
    let job = rbitcoin_consensus::block::ScriptCheckJob::new(
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
        tx.clone(),
        flags,
    );
    let ctx_low_s = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(50_000),
        sc,
        SigVersion::Base,
        false,
        false,
        false,
    )
    .apply_job_flags(&job);
    assert!(ctx_low_s.bip66_active, "LOW_S implies DERSIG");
    let err = eval_script(sc, &mut Vec::new(), &ctx_low_s).unwrap_err();
    assert!(format!("{err}").contains("SIG_DER"), "{err}");

    let mut ctx_only_low_s = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(50_000),
        sc,
        SigVersion::Base,
        false,
        false,
        false,
    );
    ctx_only_low_s.low_s = true;
    ctx_only_low_s.bip66_active = false;
    ctx_only_low_s.strictenc = false;
    let err = eval_script(sc, &mut Vec::new(), &ctx_only_low_s).unwrap_err();
    assert!(format!("{err}").contains("SIG_DER"), "{err}");
}

#[test]
fn nullfail_hard_fails_nonzero_bad_sig() {
    // Non-empty invalid-but-DER-shaped? Use empty-key path: push minimal DER-like
    // garbage that fails DER under bip66 is SIG_DER not NULLFAIL. Use valid-shaped
    // non-verifying: 9-byte minimal DER + ALL with OP_0 pubkey — soft false under
    // DERSIG only; with NULLFAIL → hard fail.
    let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
    let mut script = vec![sig.len() as u8];
    script.extend_from_slice(&sig);
    script.push(0x00); // empty/invalid pubkey as OP_0
    script.push(0xac); // CHECKSIG
    let tx = Transaction {
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
    };
    let sc = Script::from_bytes(&script);
    let mut ctx = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(50_000),
        sc,
        SigVersion::Base,
        true,
        true,
        true,
    );
    ctx.nullfail = true;
    let mut stack = Vec::new();
    let err = eval_script(sc, &mut stack, &ctx).unwrap_err();
    assert!(format!("{err}").contains("NULLFAIL"), "{err}");
}
