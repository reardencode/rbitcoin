use bitcoin::absolute::LockTime;
use bitcoin::script::Script;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, Sequence, Transaction};
use bitcoin::{OutPoint, TxIn, TxOut, Witness};
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::script::interpreter::*;

fn fad(script: &[u8], data: &[u8]) -> Vec<u8> {
    find_and_delete(script, ScriptElem::new(data).unwrap())
}

fn eval(script_bytes: &[u8], sig_version: SigVersion) -> Result<bool, ConsensusError> {
    eval_with_null_dummy(script_bytes, sig_version, false)
}

fn eval_with_null_dummy(
    script_bytes: &[u8],
    sig_version: SigVersion,
    null_dummy: bool,
) -> Result<bool, ConsensusError> {
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
    let mut ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, sig_version);
    ctx.null_dummy = null_dummy;
    let mut stack = Vec::new();
    eval_script(script, &mut stack, &ctx)
}

fn eval_stack(
    script_bytes: &[u8],
    sig_version: SigVersion,
) -> Result<Vec<Vec<u8>>, ConsensusError> {
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
    let ctx = EvalContext::new(&tx, 0, Amount::from_sat(50_000), script, sig_version);
    let mut stack = Vec::new();
    eval_script(script, &mut stack, &ctx)?;
    Ok(stack)
}

fn num(n: u8) -> Vec<u8> {
    vec![n]
}

#[test]
fn tapscript_op_success126_accepts() {
    // Real signet leaf fragment starts with normal ops then hits 0x7e (OP_SUCCESS126).
    let leaf = hex_literal(
        "60947600a2697601409f697601407c94b2750200006b760120a2636c04000000007e6b012094687660a2636c0200007e6b6094687658a2636c01007e",
    );
    assert!(tapscript_has_op_success(Script::from_bytes(&leaf)));
    let need_clean = eval(&leaf, SigVersion::TapScript).expect("tapscript success");
    assert!(!need_clean, "OP_SUCCESS skips cleanstack");
}

#[test]
fn legacy_op_cat_disabled_rejects() {
    // Minimal: push empty, push empty, OP_CAT
    let script = vec![0x00, 0x00, 0x7e];
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("disabled") || msg.contains("0x7e"),
        "unexpected: {msg}"
    );
}

/// Core: disabled opcodes fail even in unexecuted IF branches.
#[test]
fn unexecuted_disabled_opcode_still_rejects() {
    // OP_0 IF OP_CAT ELSE OP_1 ENDIF → IF body not taken, but CAT still fails.
    let script = vec![0x00, 0x63, 0x7e, 0x67, 0x51, 0x68];
    let err = eval(&script, SigVersion::Base).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("disabled") || msg.contains("0x7e"),
        "Core rejects unexecuted CAT: {msg}"
    );
}

/// Core: OP_VERIF always fails even when not executing.
#[test]
fn unexecuted_verif_still_rejects() {
    // OP_0 IF OP_VERIF ELSE OP_1 ENDIF
    let script = vec![0x00, 0x63, 0x65, 0x67, 0x51, 0x68];
    let err = eval(&script, SigVersion::Base).unwrap_err();
    assert!(
        format!("{err}").contains("VERIF") || format!("{err}").contains("opcode"),
        "{err}"
    );
}

#[test]
fn bare_op_success_byte_not_success_on_legacy() {
    // On legacy, 0x7e is disabled CAT, not SUCCESS.
    assert!(!tapscript_has_op_success(Script::from_bytes(&[0x51]))); // no success
    let script = vec![0x7e];
    assert!(eval(&script, SigVersion::Base).is_err());
}

fn hex_literal(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// strip_op_codeseparator + script_code_bytes + OP_PUSHDATA lengths.
#[test]
fn strip_codeseparator_and_pushdata_lens() {
    // CODESEPARATOR (0xab) stripped; surrounding ops kept.
    let script = vec![0x51, 0xab, 0x52]; // OP_1 CODESEPARATOR OP_2
    let stripped = strip_op_codeseparator(&script);
    assert_eq!(stripped, vec![0x51, 0x52]);
    // PUSHDATA1 / 2 / 4 inside strip
    let mut s = vec![0x4c, 0x02, 0xaa, 0xbb, 0xab, 0x51];
    let st = strip_op_codeseparator(&s);
    assert!(st.contains(&0x4c));
    assert!(!st.contains(&0xab));
    s = vec![0x4d, 0x01, 0x00, 0xcc, 0xab];
    let st = strip_op_codeseparator(&s);
    assert!(st.windows(2).any(|w| w == [0x4d, 0x01]));
    s = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xdd];
    let st = strip_op_codeseparator(&s);
    assert_eq!(st.last(), Some(&0xdd));
    // Truncated pushdata lengths break cleanly
    let _ = strip_op_codeseparator(&[0x4c]);
    let _ = strip_op_codeseparator(&[0x4d, 0x01]);
    let _ = strip_op_codeseparator(&[0x4e, 0x01, 0x00]);
    // script_code_bytes via EvalContext with codeseparator offset
    let need = eval(&[0x51], SigVersion::Base).unwrap();
    assert!(need);
}

#[test]
fn tapscript_checksigadd_empty_sig_keeps_n() {
    // stack: empty_sig, n=2, unknown_key(1 byte) → CHECKSIGADD → n=2; OP_TRUE
    // Unknown key + empty sig → EmptySig path; push n.
    let script = vec![
        0x00, // empty sig
        0x52, // OP_2 (n)
        0x01, 0xaa, // push 1-byte unknown key type
        0xba, // OP_CHECKSIGADD
        0x52, // OP_2
        0x87, // OP_EQUAL
    ];
    let need = eval(&script, SigVersion::TapScript).expect("eval");
    assert!(need);
}

#[test]
fn tapscript_checksigadd_unknown_key_nonempty_sig_increments() {
    // nonempty garbage sig + unknown key = Valid (soft-fork hook) → n+1
    let script = vec![
        0x01, 0x01, // 1-byte sig (non-empty)
        0x51, // OP_1 (n=1)
        0x01, 0xaa, // unknown key
        0xba, // CHECKSIGADD → 2
        0x52, // OP_2
        0x87, // EQUAL
    ];
    let need = eval(&script, SigVersion::TapScript).expect("eval");
    assert!(need);
}

#[test]
fn tapscript_checksigadd_legacy_unknown() {
    // On witness v0, 0xba is still unknown.
    let script = vec![0x00, 0x51, 0x01, 0xaa, 0xba];
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    assert!(format!("{err}").contains("0xba"));
}

#[test]
fn tapscript_checkmultisig_disabled() {
    let script = vec![0x00, 0x00, 0x00, 0x51, 0x51, 0xae]; // junk + CHECKMULTISIG
    let err = eval(&script, SigVersion::TapScript).unwrap_err();
    assert!(format!("{err}").contains("CHECKMULTISIG"));
}

#[test]
fn tapscript_checksig_empty_pubkey_fails() {
    // empty sig, empty pubkey (OP_0 OP_0 CHECKSIG)
    let script = vec![0x00, 0x00, 0xac];
    let err = eval(&script, SigVersion::TapScript).unwrap_err();
    assert!(format!("{err}").contains("empty pubkey"));
}

#[test]
fn tapscript_empty_pubkey_reports_weight_when_budget_exhausted() {
    // OP_1 OP_1 CHECKSIG then OP_1 OP_0 CHECKSIG.
    // Dummy witness init weight is 51; first non-empty sig burns 50.
    // Core decrements weight before the empty-pubkey fail, so the second
    // CHECKSIG is TAPSCRIPT_VALIDATION_WEIGHT, not empty pubkey.
    let script = vec![0x51, 0x51, 0xac, 0x51, 0x00, 0xac];
    let err = eval(&script, SigVersion::TapScript).unwrap_err();
    assert!(
        format!("{err}").contains("validation weight"),
        "Core order: weight before empty pubkey, got {err}"
    );

    // One nonempty unknown-key sig at remaining weight exactly 0 is allowed.
    let script = vec![0x01, 0x02, 0x01, 0xaa, 0xac];
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
    let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), sc, SigVersion::TapScript);
    ctx.validation_weight_left
        .set(TAPSCRIPT_VALIDATION_WEIGHT_PER_SIGOP);
    eval_script(sc, &mut Vec::new(), &ctx).expect("remaining weight 0 still passes");
}

#[test]
fn tapscript_allows_scripts_over_10k() {
    // Legacy would reject; tapscript must accept (BIP342).
    let mut script = vec![0x51]; // OP_TRUE
    script.resize(10_001, 0x61); // pad with OP_NOP
    script.push(0x51); // end with TRUE so cleanstack ok if executed
                       // Actually NOPs leave stack; final TRUE needed as only element — start empty,
                       // fill with NOPs, end OP_1.
    let mut script = vec![0x61; 10_001];
    script.push(0x51);
    let need = eval(&script, SigVersion::TapScript).expect("tapscript large script");
    assert!(need);
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    assert!(format!("{err}").contains("too large"));

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
    let nop = Script::from_bytes(&[0x61]);
    let ctx = EvalContext::new(&tx, 0, Amount::from_sat(1), nop, SigVersion::TapScript);
    let mut at_limit = vec![vec![1u8]; MAX_STACK_SIZE];
    eval_script(nop, &mut at_limit, &ctx).expect("1000 stack items");
    let mut over_stack = vec![vec![1u8]; MAX_STACK_SIZE + 1];
    let err = eval_script(nop, &mut over_stack, &ctx).unwrap_err();
    assert!(format!("{err}").contains("stack size"), "{err}");
    let mut at_elem = vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE]];
    eval_script(nop, &mut at_elem, &ctx).expect("520-byte element");
    let mut over_elem = vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE + 1]];
    let err = eval_script(nop, &mut over_elem, &ctx).unwrap_err();
    assert!(format!("{err}").contains("PUSH_SIZE"), "{err}");
}

/// Every consensus-enabled opcode must not report "unknown opcode".
/// Disabled/reserved still error, but with a specific reason.
#[test]
fn no_unknown_opcode_for_enabled_set() {
    // Minimal stacks so each op runs far enough to prove it is recognized.
    // Format: (name, script_bytes, sig_version) — success or known error, not unknown.
    let cases: &[(&str, Vec<u8>, SigVersion)] = &[
        ("1ADD", vec![0x51, 0x8b, 0x52, 0x87], SigVersion::WitnessV0),
        ("1SUB", vec![0x52, 0x8c, 0x51, 0x87], SigVersion::WitnessV0),
        (
            "NEGATE",
            vec![0x51, 0x8f, 0x4f, 0x87],
            SigVersion::WitnessV0,
        ),
        ("ABS", vec![0x4f, 0x90, 0x51, 0x87], SigVersion::WitnessV0),
        (
            "SHA1",
            vec![0x00, 0xa7, 0x82, 0x01, 0x14, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "RIPEMD160",
            vec![0x00, 0xa6, 0x82, 0x01, 0x14, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "SHA256",
            vec![0x00, 0xa8, 0x82, 0x01, 0x20, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "HASH160",
            vec![0x00, 0xa9, 0x82, 0x01, 0x14, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "HASH256",
            vec![0x00, 0xaa, 0x82, 0x01, 0x20, 0x87],
            SigVersion::WitnessV0,
        ),
        ("SIZE", vec![0x00, 0x82, 0x00, 0x87], SigVersion::WitnessV0),
        (
            "WITHIN",
            vec![0x51, 0x00, 0x52, 0xa5, 0x51, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "MIN",
            vec![0x51, 0x52, 0xa3, 0x51, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "MAX",
            vec![0x51, 0x52, 0xa4, 0x52, 0x87],
            SigVersion::WitnessV0,
        ),
        (
            "CHECKSIGADD",
            vec![0x00, 0x51, 0x01, 0xff, 0xba, 0x51, 0x87],
            SigVersion::TapScript,
        ),
    ];
    for (name, script, sv) in cases {
        match eval(script, *sv) {
            Ok(_) => {}
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    !msg.contains("unknown opcode"),
                    "{name}: unexpected unknown opcode: {msg}"
                );
            }
        }
    }
    // Disabled must fail with disabled/reserved, not "unknown"
    for code in [0x7e_u8, 0x8d, 0x95] {
        let script = vec![0x51, 0x51, code];
        let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disabled") || msg.contains("unknown") || msg.contains("RESERVED"),
            "0x{code:02x}: {msg}"
        );
    }
}

/// BIP147: a non-empty CHECKMULTISIG dummy fails only when the flag is on.
#[test]
fn nulldummy_rejects_nonempty_dummy() {
    // 0-of-0 multisig: n=0, m=0, dummy non-empty → NULLDUMMY when the flag is set.
    let script = vec![0x01, 0xff, 0x00, 0x00, 0xae, 0x51];
    let err = eval_with_null_dummy(&script, SigVersion::WitnessV0, true).unwrap_err();
    assert!(
        format!("{err}").contains("NULLDUMMY"),
        "expected NULLDUMMY, got {err}"
    );
    let err = eval_with_null_dummy(&script, SigVersion::Base, true).unwrap_err();
    assert!(
        format!("{err}").contains("NULLDUMMY"),
        "base flag on, got {err}"
    );
    // Empty dummy 0-of-0 succeeds (CMS pushes true).
    let script_ok = vec![0x00, 0x00, 0x00, 0xae];
    eval_with_null_dummy(&script_ok, SigVersion::WitnessV0, true).expect("0-of-0 empty dummy");
}

/// Witness v0 follows SCRIPT_VERIFY_NULLDUMMY. Flag off accepts, matching
/// Core VerifyScript. Base with the flag off accepts the same dummy.
#[test]
fn witness_v0_nulldummy_follows_the_flag() {
    let script = vec![0x01, 0xff, 0x00, 0x00, 0xae];
    eval_with_null_dummy(&script, SigVersion::WitnessV0, false)
        .expect("witness v0 flag off accepts");
    let err = eval_with_null_dummy(&script, SigVersion::WitnessV0, true).unwrap_err();
    assert!(
        format!("{err}").contains("NULLDUMMY"),
        "witness v0 flag on, got {err}"
    );
    eval(&script, SigVersion::Base).expect("base with NULLDUMMY off allows the dummy");
}

/// BIP112: OP_CSV fails when tx.nVersion < 2 (unsigned), matching Core.
/// (`docs/external_findings/004-csv-nop-and-scriptnum-width.md`).
#[test]
fn csv_fails_when_tx_version_below_2() {
    // Script: push 1, CSV, DROP, OP_TRUE — v1 must fail CSV version gate.
    let script_bytes = [0x51u8, 0xb2, 0x75, 0x51]; // 1 CSV DROP TRUE
    let script = Script::from_bytes(&script_bytes);
    let mk = |ver: i32| Transaction {
        version: bitcoin::transaction::Version(ver),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0), // would fail real CSV
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    // v1: Core fails (not NOP) when BIP112 active and disable bit clear.
    let tx1 = mk(1);
    let ctx1 = EvalContext::new_with_flags(
        &tx1,
        0,
        Amount::from_sat(50_000),
        script,
        SigVersion::Base,
        true,
        true, // bip112 active
        true,
    );
    let mut stack1 = Vec::new();
    let err = eval_script(script, &mut stack1, &ctx1).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s.contains("CSV")),
        "v1 must fail CSV version gate, got {err:?}"
    );

    // v2: CSV enforces → fails with seq=0 vs csv=1
    let tx2 = mk(2);
    let ctx2 = EvalContext::new_with_flags(
        &tx2,
        0,
        Amount::from_sat(50_000),
        script,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack2 = Vec::new();
    let err = eval_script(script, &mut stack2, &ctx2).unwrap_err();
    assert!(
        format!("{err}").contains("CSV"),
        "v2 should enforce CSV, got {err}"
    );

    // The CSV operand's disable bit is a NOP, before the version gate.
    let nop = [0x05u8, 0x00, 0x00, 0x00, 0x80, 0x00, 0xb2, 0x75, 0x51];
    let nop_script = Script::from_bytes(&nop);
    let ctx_nop = EvalContext::new_with_flags(
        &tx1,
        0,
        Amount::from_sat(50_000),
        nop_script,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack_nop = Vec::new();
    eval_script(nop_script, &mut stack_nop, &ctx_nop).expect("CSV disable bit does not enforce");

    // Input disable flag fails even when the numeric lock would pass.
    let tx_dis = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0x8000_0001),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let ctx_dis = EvalContext::new_with_flags(
        &tx_dis,
        0,
        Amount::from_sat(50_000),
        script,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack_dis = Vec::new();
    let err = eval_script(script, &mut stack_dis, &ctx_dis).unwrap_err();
    assert!(
        format!("{err}").contains("CSV"),
        "input disable flag fails CSV, got {err}"
    );
}

#[test]
fn script_sig_pushes_op_n_and_1negate() {
    let mut stack = Vec::new();
    // OP_0, OP_1NEGATE, OP_1, push bytes
    let ss = Script::from_bytes(&[0x00, 0x4f, 0x51, 0x01, 0xaa]);
    eval_script_sig_pushes(ss, &mut stack).unwrap();
    assert_eq!(stack.len(), 4);
    assert_eq!(stack[0], Vec::<u8>::new());
    assert_eq!(stack[1], vec![0x81]);
    assert_eq!(stack[2], vec![0x01]);
    assert_eq!(stack[3], vec![0xaa]);
    // Non-push opcode fails.
    let mut s2 = Vec::new();
    assert!(eval_script_sig_pushes(Script::from_bytes(&[0xac]), &mut s2).is_err());
}

#[test]
fn find_and_delete_pushdata_lengths() {
    let data = vec![0x11u8; 3];
    let mut script = vec![0x03];
    script.extend_from_slice(&data);
    script.push(0x51);
    let out = fad(&script, &data);
    assert_eq!(out, vec![0x51]);
    assert_eq!(
        fad(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x51], &[]),
        vec![0x02, 0x00, 0x00, 0x51]
    );

    // PUSHDATA1 needle
    let big = vec![0x22u8; 80];
    let mut sc = vec![0x4c, 80];
    sc.extend_from_slice(&big);
    sc.push(0x52);
    let out2 = fad(&sc, &big);
    assert_eq!(out2, vec![0x52]);

    // PUSHDATA2
    let bigger = vec![0x33u8; 300];
    let mut sc2 = vec![0x4d];
    sc2.extend_from_slice(&(300u16).to_le_bytes());
    sc2.extend_from_slice(&bigger);
    sc2.push(0x53);
    assert_eq!(fad(&sc2, &bigger), vec![0x53]);

    // Non-matching copy through PUSHDATA encodings
    let passthrough = vec![0x4c, 0x01, 0xaa, 0x4d, 0x01, 0x00, 0xbb];
    assert_eq!(fad(&passthrough, &[0xff]), passthrough);

    // Length 76 is PUSHDATA1, not a direct push.
    let wide = vec![0x44u8; 76];
    let mut wide_script = vec![0x4c, 76];
    wide_script.extend_from_slice(&wide);
    wide_script.push(0x51);
    assert_eq!(fad(&wide_script, &wide), vec![0x51]);

    // Truncated PUSHDATA2 stops before the missing length byte.
    assert_eq!(fad(&[0x4d, 0x01], &[0xff]), vec![0x4d]);
    // Truncated PUSHDATA4 of four bytes: three length bytes are not enough.
    assert_eq!(fad(&[0x4e, 0x01, 0x00, 0x00], &[0xff]), vec![0x4e]);

    let needle = [0x11u8, 0x11, 0x11];
    let mut pd2 = vec![0x4d, 0x02, 0x00, 0xaa, 0xbb];
    pd2.extend_from_slice(&[0x03, 0x11, 0x11, 0x11]);
    assert_eq!(fad(&pd2, &needle), vec![0x4d, 0x02, 0x00, 0xaa, 0xbb]);

    // NOPs after the payload: a direct-push opcode here would swallow the needle.
    // Index 10 and 15 differ from the zero length bytes at i+2 and i+3.
    let mut pd4 = vec![0x61; 4];
    pd4.extend_from_slice(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xee]);
    pd4.extend_from_slice(&[0x61; 6]);
    pd4.extend_from_slice(&[0x03, 0x11, 0x11, 0x11]);
    let out4 = fad(&pd4, &needle);
    assert!(out4.contains(&0xee), "{out4:?}");
    assert!(
        out4.windows(3).all(|w| w != needle),
        "payload must not swallow the following push: {out4:?}"
    );
}

#[test]
fn strip_codeseparator_keeps_pushdata() {
    // OP_1, CODESEPARATOR, PUSHDATA1 payload, OP_TRUE
    let sc = vec![0x51, 0xab, 0x4c, 0x02, 0xde, 0xad, 0x51];
    let stripped = strip_op_codeseparator(&sc);
    assert!(!stripped.contains(&0xab));
    assert!(stripped.windows(2).any(|w| w == [0xde, 0xad]));

    let sc2 = vec![0x4d, 0x01, 0x00, 0xee, 0xab, 0x51];
    let s2 = strip_op_codeseparator(&sc2);
    assert_eq!(s2.last(), Some(&0x51));
    assert!(!s2.contains(&0xab));

    let sc3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0x01, 0xab];
    let s3 = strip_op_codeseparator(&sc3);
    assert!(!s3.contains(&0xab));

    let pd2 = vec![0x4d, 0x02, 0x00, 0xde, 0xad, 0xab];
    assert_eq!(
        strip_op_codeseparator(&pd2),
        vec![0x4d, 0x02, 0x00, 0xde, 0xad]
    );
    assert_eq!(
        strip_op_codeseparator(&[0x4e, 0x01, 0x00, 0x00]),
        vec![0x4e]
    );
    // Four prefixes put the length word at i=5. At i=2, i*2 equals i+2.
    // Index 15 is in range and is not the same byte as i+3.
    let mut pd4 = vec![0x61; 4];
    pd4.extend_from_slice(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xee, 0xab]);
    pd4.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x11, 0x02]);
    let stripped4 = strip_op_codeseparator(&pd4);
    assert!(
        stripped4.windows(2).any(|w| w == [0x4e, 0x01]),
        "{stripped4:?}"
    );
    assert!(stripped4.contains(&0xee), "{stripped4:?}");
    assert!(!stripped4.contains(&0xab), "{stripped4:?}");
    let _ = (sc, sc2, sc3);
}

#[test]
fn tapscript_has_op_success_pushdata_scan() {
    // OP_SUCCESS via direct byte after PUSHDATA1 skip
    let leaf = vec![0x4c, 0x02, 0x00, 0x00, 0x7e]; // push 2 then OP_SUCCESS126
    assert!(tapscript_has_op_success(Script::from_bytes(&leaf)));
    let leaf2 = vec![0x4d, 0x01, 0x00, 0xff, 0x7e];
    assert!(tapscript_has_op_success(Script::from_bytes(&leaf2)));
    let leaf3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xaa, 0x7e];
    assert!(tapscript_has_op_success(Script::from_bytes(&leaf3)));
    // Truncated pushdata — no success past end
    assert!(!tapscript_has_op_success(Script::from_bytes(&[0x4c])));
    assert!(!tapscript_has_op_success(Script::from_bytes(&[0x4d, 0x01])));
    assert!(!tapscript_has_op_success(Script::from_bytes(&[
        0x4e, 0x01, 0x00
    ])));
    // OP_SUCCESS inside a push is data. The same byte after the push is success.
    assert!(!tapscript_has_op_success(Script::from_bytes(&[
        0x4c, 0x01, 0x7e
    ])));
    assert!(!tapscript_has_op_success(Script::from_bytes(&[
        0x4d, 0x01, 0x00, 0x7e
    ])));
    assert!(!tapscript_has_op_success(Script::from_bytes(&[
        0x4e, 0x01, 0x00, 0x00, 0x00, 0x7e
    ])));
    assert!(tapscript_has_op_success(Script::from_bytes(&[
        0x4c, 0x01, 0x00, 0x7e
    ])));
    let _ = (leaf, leaf2, leaf3);
}

#[test]
fn cltv_type_mismatch_and_final_sequence() {
    // locktime height vs time type mismatch
    let script_bytes = [0x51u8, 0xb1, 0x75, 0x51]; // 1 CLTV DROP TRUE
    let script = Script::from_bytes(&script_bytes);
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::from_time(500_000_001).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let ctx = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(1),
        script,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack = Vec::new();
    let err = eval_script(script, &mut stack, &ctx).unwrap_err();
    assert!(format!("{err}").contains("CLTV"), "got {err}");

    // Final sequence rejects CLTV even when locktime ok
    let script2 = Script::from_bytes(&[0x00, 0xb1, 0x75, 0x51]); // 0 CLTV DROP TRUE
    let tx2 = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::from_height(10).unwrap(),
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
    let ctx2 = EvalContext::new_with_flags(
        &tx2,
        0,
        Amount::from_sat(1),
        script2,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack2 = Vec::new();
    let err2 = eval_script(script2, &mut stack2, &ctx2).unwrap_err();
    assert!(
        format!("{err2}").contains("CLTV") || format!("{err2}").contains("final"),
        "got {err2}"
    );
}

#[test]
fn checkmultisig_verify_fail_and_tapscript_disabled() {
    // 1-of-1 CMSVERIFY with empty sigs fails
    // stack: dummy empty, sig empty, m=1, pk empty, n=1 → will fail verify
    let script = vec![0x00, 0x00, 0x51, 0x00, 0x51, 0xaf];
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("CHECKMULTISIG") || msg.contains("NULLDUMMY") || msg.contains("stack"),
        "{msg}"
    );
    // Tapscript: CHECKMULTISIG disabled
    let err2 = eval(&[0x00, 0x00, 0x00, 0xae], SigVersion::TapScript).unwrap_err();
    assert!(
        format!("{err2}").contains("CHECKMULTISIG") || format!("{err2}").contains("disabled"),
        "{err2}"
    );
    let err3 = eval(&[0x00, 0x00, 0x00, 0xaf], SigVersion::TapScript).unwrap_err();
    assert!(
        format!("{err3}").to_lowercase().contains("checkmultisig")
            || format!("{err3}").contains("disabled"),
        "{err3}"
    );
}

#[test]
fn minimalif_rejects_nonminimal_arg() {
    // TapScript MINIMALIF: push byte 0x00 (non-minimal false), IF, TRUE, ENDIF.
    // OP_0 empty is minimal; length-1 push of 0x00 is not.
    let script = vec![0x01, 0x00, 0x63, 0x51, 0x68];
    let err = eval(&script, SigVersion::TapScript).unwrap_err();
    assert!(format!("{err}").contains("MINIMALIF"), "got {err}");
    // OP_0 empty is minimal false → IF skipped → OP_TRUE after ENDIF succeeds.
    let script_ok = vec![0x00, 0x63, 0x51, 0x68, 0x51];
    assert!(eval(&script_ok, SigVersion::TapScript).expect("minimal empty if"));
}

/// Local extras dropped from `script_tests.json` when pinning Core v31.1.
/// VERIFY must abort so a trailing `OP_1` cannot turn a failed check into success.
#[test]
fn checksigverify_then_op1_does_not_succeed() {
    // <empty sig> <33-byte key> CHECKSIGVERIFY OP_1
    let mut script = vec![0x00, 0x21];
    script.extend_from_slice(&[
        0x02, 0x86, 0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7, 0xb1, 0xe1, 0x06,
        0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99, 0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53, 0xe6, 0x92,
        0x56, 0xda, 0xc0,
    ]);
    script.extend_from_slice(&[0xad, 0x51]); // CHECKSIGVERIFY 1
    let err = eval(&script, SigVersion::Base).unwrap_err();
    assert!(
        format!("{err}").contains("CHECKSIGVERIFY"),
        "VERIFY must hard-fail (not push false): {err}"
    );

    // Same with CHECKSIG (not VERIFY): false then 1 → script succeeds.
    let mut soft = script.clone();
    let n = soft.len();
    soft[n - 2] = 0xac; // CHECKSIG
    eval(&soft, SigVersion::Base).expect("CHECKSIG + OP_1 must succeed on a failed check");
}

#[test]
fn checkmultisigverify_then_op1_does_not_succeed() {
    // dummy, empty sig, m=1, <key>, n=1, CHECKMULTISIGVERIFY, OP_1
    let mut script = vec![0x00, 0x00, 0x51, 0x21];
    script.extend_from_slice(&[
        0x02, 0x86, 0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7, 0xb1, 0xe1, 0x06,
        0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99, 0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53, 0xe6, 0x92,
        0x56, 0xda, 0xc0,
    ]);
    script.extend_from_slice(&[0x51, 0xaf, 0x51]);
    let err = eval(&script, SigVersion::Base).unwrap_err();
    assert!(
        format!("{err}").contains("CHECKMULTISIGVERIFY"),
        "CMSVERIFY must hard-fail (not push false): {err}"
    );
}

#[test]
fn cltv_empty_stack_is_invalid() {
    let err = eval(&[0xb1], SigVersion::Base).unwrap_err();
    assert!(
        format!("{err}").contains("stack"),
        "empty-stack CLTV: {err}"
    );
}

#[test]
fn cltv_and_csv_negative_zero_is_not_negative() {
    // 0x80 is scriptnum negative-zero → 0, not < 0.
    assert_eq!(
        rbitcoin_primitives::scriptnum_decode_width(&[0x80], 5, false).unwrap(),
        0
    );

    // eval() uses nLockTime=0 and final nSequence (Core script_tests template).
    // CLTV(0) then fails final-sequence / unsatisfied — never "negative".
    let cltv = vec![0x01, 0x80, 0xb1];
    let err = eval(&cltv, SigVersion::Base).unwrap_err();
    let msg = format!("{err}");
    assert!(
        !msg.to_lowercase().contains("negative"),
        "0x80 must not take the CLTV-negative branch: {msg}"
    );
    assert!(
        msg.contains("CLTV") || msg.contains("final"),
        "expected unsatisfied/final, got {msg}"
    );

    let csv = vec![0x01, 0x80, 0xb2];
    let err = eval(&csv, SigVersion::Base).unwrap_err();
    let msg = format!("{err}");
    assert!(
        !msg.to_lowercase().contains("negative"),
        "0x80 must not take the CSV-negative branch: {msg}"
    );
}

#[test]
fn cltv_negative_locktime_rejected() {
    // OP_1NEGATE CLTV …
    let script_bytes = [0x4fu8, 0xb1, 0x75, 0x51];
    let script = Script::from_bytes(&script_bytes);
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::from_height(10).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let ctx = EvalContext::new_with_flags(
        &tx,
        0,
        Amount::from_sat(1),
        script,
        SigVersion::Base,
        true,
        true,
        true,
    );
    let mut stack = Vec::new();
    let err = eval_script(script, &mut stack, &ctx).unwrap_err();
    assert!(
        format!("{err}").contains("CLTV") || format!("{err}").contains("negative"),
        "got {err}"
    );
}

#[test]
fn stack_size_limit_on_2dup() {
    let top3 =
        eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x6f], SigVersion::WitnessV0).expect("3DUP");
    assert_eq!(
        top3,
        vec![
            num(1),
            num(2),
            num(3),
            num(4),
            num(5),
            num(3),
            num(4),
            num(5)
        ]
    );
    let over =
        eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x70], SigVersion::WitnessV0).expect("2OVER");
    assert_eq!(
        over,
        vec![num(1), num(2), num(3), num(4), num(5), num(2), num(3)]
    );
    let rot = eval_stack(
        &[0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x71],
        SigVersion::WitnessV0,
    )
    .expect("2ROT");
    assert_eq!(
        rot,
        vec![num(1), num(4), num(5), num(6), num(7), num(2), num(3)]
    );
    let swap4 = eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x72], SigVersion::WitnessV0).expect("2SWAP");
    assert_eq!(swap4, vec![num(3), num(4), num(1), num(2)]);
    let swap5 =
        eval_stack(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x72], SigVersion::WitnessV0).expect("2SWAP");
    assert_eq!(swap5, vec![num(1), num(4), num(5), num(2), num(3)]);

    eval(&vec![0x61; 201], SigVersion::WitnessV0).expect("201 ops is the limit");
    let err = eval(&vec![0x61; 202], SigVersion::WitnessV0).unwrap_err();
    assert!(format!("{err}").contains("op count"), "{err}");
    eval(&vec![0x60; 202], SigVersion::WitnessV0).expect("OP_16 is not an op-count");

    // MAX_STACK_SIZE is typically 1000; push 999 ones then 2DUP overflows.
    let mut script = vec![0x51; 999];
    script.push(0x6e); // OP_2DUP
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    assert!(
        format!("{err}").contains("stack") || format!("{err}").contains("size"),
        "got {err}"
    );
}

/// Core: main stack + altstack share MAX_STACK_SIZE. Direct PushBytes used
/// to skip the opcode-end combined check (`push()` only counted the main
/// stack). 201 TOALTSTACK (op budget) + 799 OP_1 + one PushBytes = 1001.
#[test]
fn stack_and_altstack_share_max_size_on_pushdata() {
    let mut script = vec![0x51; 201];
    script.extend(std::iter::repeat_n(0x6b, 201)); // OP_TOALTSTACK
    script.extend(std::iter::repeat_n(0x51, 799));
    script.extend_from_slice(&[0x01, 0x01]); // PushBytes, not OP_1
    let err = eval(&script, SigVersion::WitnessV0).unwrap_err();
    assert!(format!("{err}").contains("stack size"), "got {err}");

    // Both stacks non-empty and the product exceeds 1000 while the sum does not.
    let mut shared = vec![0x51, 0x51, 0x6b, 0x6b];
    shared.extend(std::iter::repeat_n(0x51, 501));
    shared.push(0x61);
    eval(&shared, SigVersion::WitnessV0).expect("sum under the shared limit");
}

/// Short `OP_PUSHDATA4` inside a legacy scriptCode. The payload must not be
/// read as an opcode: needle `11 11 11` is encoded `03 11 11 11` and sits
/// inside the four-byte push, so FindAndDelete leaves the script unchanged.
#[test]
fn find_and_delete_short_pushdata4_payload_is_not_an_opcode() {
    let script = vec![0x4e, 0x04, 0x00, 0x00, 0x00, 0x03, 0x11, 0x11, 0x11, 0x51];
    let needle = [0x11u8, 0x11, 0x11];
    let out = fad(&script, &needle);
    assert_eq!(out, script);
    assert_eq!(out.last(), Some(&0x51));
    assert!(out.windows(3).any(|w| w == needle));
    let short = vec![0x4e, 0x01, 0x00];
    let truncated = fad(&short, &[0xff]);
    assert_eq!(truncated.first(), Some(&0x4e));
}
