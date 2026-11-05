//! Interpreter and Taproot arms that used to abort now return script errors.
//! Each case builds a real job and calls the shipped checker.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use rbitcoin_consensus::block::{ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::script::script_fail::{consensus_ordinal, ScriptFail};
use rbitcoin_consensus::script::verify_job_all_inputs;
use rbitcoin_consensus::ConsensusError;

fn flags() -> ScriptVerifyFlags {
    ScriptVerifyFlags::buried(true, true, true, true, true)
}

fn job(spk: ScriptBuf, script_sig: ScriptBuf, witness: Witness) -> ScriptCheckJob {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    ScriptCheckJob::new(
        vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: spk,
        }],
        tx,
        flags(),
    )
}

fn token(res: Result<(), ConsensusError>) -> String {
    match res {
        Ok(()) => panic!("expected a script error"),
        Err(ConsensusError::Script(msg)) => msg.split(" txid=").next().unwrap_or(&msg).to_string(),
        Err(err) => panic!("expected a script error, got {err}"),
    }
}

fn p2tr_program(key: &[u8]) -> ScriptBuf {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(key);
    ScriptBuf::from_bytes(spk)
}

#[test]
fn empty_stack_is_a_script_error() {
    let spk = ScriptBuf::from_bytes(vec![0x76]);
    let got = token(verify_job_all_inputs(&job(
        spk,
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "stack empty");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::InvalidStackOperation.ordinal())
    );
}

#[test]
fn short_key_path_witness_is_a_script_error() {
    let spk = p2tr_program(&[0x11; 32]);
    let witness = Witness::from_slice(&[&[0u8; 10][..]]);
    let got = token(verify_job_all_inputs(&job(spk, ScriptBuf::new(), witness)));
    assert_eq!(got, "p2tr sig len");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::SchnorrSigSize.ordinal())
    );
}

#[test]
fn short_control_block_is_a_script_error() {
    let spk = p2tr_program(&[0x22; 32]);
    let witness = Witness::from_slice(&[&[0x51][..], &[0u8; 10][..]]);
    let got = token(verify_job_all_inputs(&job(spk, ScriptBuf::new(), witness)));
    assert_eq!(got, "TAPROOT_WRONG_CONTROL_SIZE");
    assert_eq!(consensus_ordinal(&got), Some(48));
}

#[test]
fn short_tapscript_schnorr_is_a_script_error() {
    let secp = Secp256k1::new();
    let internal = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let internal_kp = Keypair::from_secret_key(&secp, &internal);
    let (internal_xonly, _) = internal_kp.x_only_public_key();
    let leaf = ScriptBuf::from_bytes(vec![0xac]);
    let spend = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal_xonly)
        .unwrap();
    let output_key = spend.output_key().to_x_only_public_key();
    let control = spend
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    let pubkey = [0x33; 32];
    let short_sig = [0u8; 10];
    let witness = Witness::from_slice(&[
        short_sig.as_slice(),
        pubkey.as_slice(),
        leaf.as_bytes(),
        control.as_slice(),
    ]);
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&output_key.serialize()),
        ScriptBuf::new(),
        witness,
    )));
    assert_eq!(got, "SCHNORR_SIG_SIZE");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::SchnorrSigSize.ordinal())
    );

    let zeros = [0u8; 64];
    let witness = Witness::from_slice(&[
        zeros.as_slice(),
        pubkey.as_slice(),
        leaf.as_bytes(),
        control.as_slice(),
    ]);
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&output_key.serialize()),
        ScriptBuf::new(),
        witness,
    )));
    assert_eq!(got, "tapscript CHECKSIG failed");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::SchnorrSig.ordinal())
    );
}

#[test]
fn scriptnum_overflow_op_return_and_empty_taproot_keep_core_ordinals() {
    let overflow = ScriptBuf::from_bytes(vec![0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8b]);
    let got = token(verify_job_all_inputs(&job(
        overflow,
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "scriptnum overflow");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::ScriptNum.ordinal())
    );

    let op_return = ScriptBuf::from_bytes(vec![0x6a]);
    let got = token(verify_job_all_inputs(&job(
        op_return,
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "unknown opcode 0x6a");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::OpReturn.ordinal())
    );

    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&[0x11; 32]),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "p2tr empty witness");
    assert_eq!(
        consensus_ordinal(&got),
        Some(ScriptFail::WitnessProgramWitnessEmpty.ordinal())
    );
}

#[test]
fn high_s_under_low_s_is_a_script_error() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp)).to_bytes();
    let spk = ScriptBuf::from_bytes(vec![0xac]);
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
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
    let sighash = SighashCache::new(&tx)
        .legacy_signature_hash(0, &spk, EcdsaSighashType::All as u32)
        .unwrap();
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk);
    let mut compact = sig.serialize_compact();
    let mut s = [0u8; 32];
    s.copy_from_slice(&compact[32..]);
    compact[32..].copy_from_slice(&negate_scalar(&s));
    let high = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
    let mut der = high.serialize_der().to_vec();
    der.push(EcdsaSighashType::All as u8);
    let sig_push = bitcoin::script::PushBytesBuf::try_from(der).unwrap();
    let pk_push = bitcoin::script::PushBytesBuf::try_from(pk).unwrap();
    tx.input[0].script_sig = bitcoin::script::Builder::new()
        .push_slice(sig_push)
        .push_slice(pk_push)
        .into_script();
    let mut spent = job(spk, tx.input[0].script_sig.clone(), Witness::new());
    spent.tx = rbitcoin_consensus::block::JobTx::owned(tx);
    spent.low_s = true;
    let got = token(verify_job_all_inputs(&spent));
    assert_eq!(got, "SIG_HIGH_S");
    assert_eq!(consensus_ordinal(&got), None);
}

fn negate_scalar(s: &[u8; 32]) -> [u8; 32] {
    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

#[test]
fn pinned_interpreter_strings_stay() {
    let eval_false = ScriptBuf::from_bytes(vec![0x52, 0x02, 0x00, 0x00]);
    let got = token(verify_job_all_inputs(&job(
        eval_false,
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "EVAL_FALSE");

    let mut nulldummy = job(
        ScriptBuf::from_bytes(vec![0x01, 0xff, 0x00, 0x00, 0xae]),
        ScriptBuf::new(),
        Witness::new(),
    );
    nulldummy.null_dummy = true;
    assert_eq!(token(verify_job_all_inputs(&nulldummy)), "NULLDUMMY");

    let pk = {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        bitcoin::PublicKey::new(sk.public_key(&secp)).to_bytes()
    };
    let pk_push = bitcoin::script::PushBytesBuf::try_from(pk).unwrap();
    let bad = bitcoin::script::PushBytesBuf::try_from(vec![0xff]).unwrap();
    let script_sig = bitcoin::script::Builder::new()
        .push_slice(bad)
        .push_slice(pk_push)
        .into_script();
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(vec![0xac]),
        script_sig,
        Witness::new(),
    )));
    assert_eq!(got, "SIG_DER");

    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(vec![0x01, 0x81, 0xb1]),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "CLTV negative");

    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(vec![0x01, 0x81, 0xb2]),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "CSV negative");

    let mut wrong = vec![0x00, 0x0a, 0x01];
    wrong.extend_from_slice(&[0u8; 9]);
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(wrong),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "WITNESS_PROGRAM_WRONG_LENGTH");

    let redeem = ScriptBuf::from_bytes(vec![0x51]);
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::new_p2sh(&redeem.script_hash()),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "p2sh empty scriptSig");
}

#[test]
fn interpreter_only_p2wpkh_witness_count_is_mismatch() {
    let mut program = vec![0x00, 0x14];
    program.extend_from_slice(&[0x11; 20]);
    let spk = ScriptBuf::from_bytes(program);
    for witness in [
        Witness::new(),
        Witness::from_slice(&[&[0x01][..]]),
        Witness::from_slice(&[&[0x01][..], &[0x02][..], &[0x03][..]]),
    ] {
        let mut spent = job(spk.clone(), ScriptBuf::new(), witness);
        spent.interpreter_only = true;
        let got = token(verify_job_all_inputs(&spent));
        assert_eq!(got, "WITNESS_PROGRAM_MISMATCH", "{got}");
        assert_eq!(
            consensus_ordinal(&got),
            Some(ScriptFail::WitnessProgramMismatch.ordinal())
        );
    }
    let typed = token(verify_job_all_inputs(&job(
        spk,
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(typed, "p2wpkh witness len");
    assert_eq!(consensus_ordinal(&typed), None);
}

fn bare(script: &[u8]) -> String {
    token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(script.to_vec()),
        ScriptBuf::new(),
        Witness::new(),
    )))
}

fn expect_ordinal(got: &str, ordinal: i32) {
    assert_eq!(consensus_ordinal(got), Some(ordinal), "{got}");
}

#[test]
fn interpreter_tokens_keep_core_ordinals() {
    let cases: &[(&[u8], &str, i32)] = &[
        (&[0x00, 0x69], "OP_VERIFY", 11),
        (&[0x67], "OP_ELSE", 20),
        (&[0x68], "OP_ENDIF", 20),
        (&[0x51, 0x63], "unbalanced IF", 20),
        (&[0x01], "script parse", 16),
        (&[0x65], "OP_VERIF", 16),
        (&[0xba], "unknown opcode 0xba", 16),
        (&[0xff], "unknown opcode 0xff", 16),
        (&[0x7e], "disabled opcode 0x7e", 17),
        (&[0x51, 0x79], "OP_PICK", 18),
        (&[0x51, 0x7a], "OP_ROLL", 18),
        (&[0x01, 0x15, 0xae], "multisig n", 10),
        (&[0x00, 0x51, 0x00, 0xae], "multisig m", 9),
        (&[0x51, 0x52, 0x9d], "OP_NUMEQUALVERIFY", 15),
    ];
    for (script, expect, ordinal) in cases {
        let got = bare(script);
        assert_eq!(&got, expect, "{got}");
        expect_ordinal(&got, *ordinal);
    }

    let mut big = vec![0x4d, 0x09, 0x02];
    big.extend(std::iter::repeat_n(0x11, 521));
    let got = bare(&big);
    assert_eq!(got, "push too large");
    expect_ordinal(&got, 6);

    let mut program = vec![0x00, 0x20];
    program.extend_from_slice(&[0x11; 32]);
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(program.clone()),
        ScriptBuf::new(),
        Witness::new(),
    )));
    assert_eq!(got, "p2wsh empty witness");
    expect_ordinal(&got, 39);
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(program),
        ScriptBuf::new(),
        Witness::from_slice(&[&[0x51][..]]),
    )));
    assert_eq!(got, "p2wsh script hash");
    expect_ordinal(&got, 40);

    let leaf = vec![0x51, 0x51];
    let digest = sha256::Hash::hash(&leaf);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(digest.as_byte_array());
    let got = token(verify_job_all_inputs(&job(
        ScriptBuf::from_bytes(spk),
        ScriptBuf::new(),
        Witness::from_slice(&[&leaf[..]]),
    )));
    assert_eq!(got, "cleanstack");
    expect_ordinal(&got, 30);

    let redeem = ScriptBuf::from_bytes(vec![0x51]);
    let p2sh = ScriptBuf::new_p2sh(&redeem.script_hash());
    let mismatch = token(verify_job_all_inputs(&job(
        p2sh.clone(),
        ScriptBuf::from_bytes(vec![0x61, 0x01, 0x52]),
        Witness::new(),
    )));
    assert_eq!(mismatch, "p2sh redeem hash");
    expect_ordinal(&mismatch, 2);
    let push = token(verify_job_all_inputs(&job(
        p2sh,
        ScriptBuf::from_bytes(vec![0x61, 0x01, 0x51]),
        Witness::new(),
    )));
    assert_eq!(push, "p2sh scriptSig op");
    expect_ordinal(&push, 26);

    // All-zero program is a false scriptPubKey (EVAL_FALSE) before key-path
    // parsing. A non-zero invalid x-only reaches `p2tr xonly`.
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&[0xff; 32]),
        ScriptBuf::new(),
        Witness::from_slice(&[&[0u8; 64][..]]),
    )));
    assert_eq!(got, "p2tr xonly");
    expect_ordinal(&got, 47);

    let secp = Secp256k1::new();
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
    let (internal_xonly, _) = internal.x_only_public_key();
    let leaf = ScriptBuf::from_bytes(vec![0xad]);
    let spend = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal_xonly)
        .unwrap();
    let control = spend
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    let witness = Witness::from_slice(&[
        &[][..],
        &[0x11; 32][..],
        leaf.as_bytes(),
        control.as_slice(),
    ]);
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&spend.output_key().to_x_only_public_key().serialize()),
        ScriptBuf::new(),
        witness,
    )));
    assert_eq!(got, "CHECKSIGVERIFY empty");
    expect_ordinal(&got, 14);

    let leaf = ScriptBuf::from_bytes(vec![0xac]);
    let spend = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal_xonly)
        .unwrap();
    let control = spend
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    let witness = Witness::from_slice(&[
        &[0u8; 64][..],
        &[0xff; 32][..],
        leaf.as_bytes(),
        control.as_slice(),
    ]);
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&spend.output_key().to_x_only_public_key().serialize()),
        ScriptBuf::new(),
        witness,
    )));
    assert_eq!(got, "tapscript xonly");
    expect_ordinal(&got, 47);
}

#[test]
fn script_fail_ordinals_match_core_v32() {
    assert_eq!(ScriptFail::EvalFalse.ordinal(), 2);
    assert_eq!(ScriptFail::ScriptNum.ordinal(), 4);
    assert_eq!(ScriptFail::SigDer.ordinal(), 24);
    assert_eq!(ScriptFail::TaprootWrongControlSize.ordinal(), 48);
    assert_eq!(ScriptFail::SigFindAndDelete.ordinal(), 54);
    assert_eq!(ScriptFail::EvalFalse.token(), "EVAL_FALSE");
    assert_eq!(ScriptFail::SigNullDummy.token(), "NULLDUMMY");
    assert_eq!(consensus_ordinal("script false"), Some(2));
    assert_eq!(consensus_ordinal("SIG_DER txid=abc vin=1"), Some(24));
    assert_eq!(consensus_ordinal("p2wpkh ecdsa"), None);
    assert_eq!(consensus_ordinal("p2tr schnorr"), Some(47));
    assert_eq!(consensus_ordinal("stack empty"), Some(18));
    assert_eq!(consensus_ordinal("CLTV"), Some(22));
    assert_eq!(consensus_ordinal("scriptnum overflow"), Some(4));
    assert_eq!(consensus_ordinal("SCRIPTNUM"), Some(4));
    assert_eq!(consensus_ordinal("p2tr sig len"), Some(45));
    assert_eq!(consensus_ordinal("p2tr sighash type"), Some(46));
    assert_eq!(consensus_ordinal("SIG_HIGH_S"), None);
}

#[test]
fn shipped_script_tokens_map_to_core_ordinals() {
    assert_eq!(ScriptFail::SigPushOnly.ordinal(), 26);
    assert_eq!(ScriptFail::CleanStack.ordinal(), 30);
    assert_eq!(ScriptFail::SigPushOnly.token(), "p2sh scriptSig op");
    assert_eq!(ScriptFail::CleanStack.token(), "cleanstack");
    for token in [
        "MINIMALIF",
        "NULLFAIL",
        "PUBKEYTYPE",
        "WITNESS_PUBKEYTYPE",
        "p2wpkh witness len",
        "p2pkh ecdsa",
        "p2tr schnorr parse",
        "p2tr sig",
        "p2tr script path short",
        "p2wsh witness",
        "p2sh spk",
    ] {
        assert_eq!(consensus_ordinal(token), None, "{token}");
    }
    for (token, ordinal) in [
        ("OP_VERIFY", 11),
        ("OP_ELSE", 20),
        ("OP_ENDIF", 20),
        ("unbalanced IF", 20),
        ("push too large", 6),
        ("script parse", 16),
        ("OP_VERIF", 16),
        ("unknown opcode 0xba", 16),
        ("unknown opcode 0xff", 16),
        ("unknown opcode 0x6a", 3),
        ("disabled opcode 0x7e", 17),
        ("disabled opcode 0x7f", 17),
        ("OP_PICK", 18),
        ("OP_ROLL", 18),
        ("multisig n", 10),
        ("multisig m", 9),
        ("CHECKSIGVERIFY empty", 14),
        ("OP_NUMEQUALVERIFY", 15),
        ("p2wsh empty witness", 39),
        ("p2wsh script hash", 40),
        ("p2sh empty scriptSig", 18),
        ("p2sh redeem hash", 2),
        ("p2sh scriptSig op", 26),
        ("cleanstack", 30),
        ("tapscript xonly", 47),
        ("p2tr xonly", 47),
    ] {
        assert_eq!(consensus_ordinal(token), Some(ordinal), "{token}");
    }
}

#[test]
fn sixty_four_byte_key_path_failure_is_a_script_error() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let output_key = kp.x_only_public_key().0;
    let witness = Witness::from_slice(&[&[0u8; 64][..]]);
    let got = token(verify_job_all_inputs(&job(
        p2tr_program(&output_key.serialize()),
        ScriptBuf::new(),
        witness,
    )));
    assert!(
        got == "p2tr schnorr" || got == "p2tr schnorr parse",
        "{got}"
    );
}
