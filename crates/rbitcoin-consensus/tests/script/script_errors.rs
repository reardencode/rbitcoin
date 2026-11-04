//! Interpreter and Taproot arms that used to abort now return script errors.
//! Each case builds a real job and calls the shipped checker.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
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
