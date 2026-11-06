//! `--script-interpreter-only` forces standard ECDSA spends through the
//! interpreter. The default job keeps the typed fast paths.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

use rbitcoin_consensus::block::{ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::script::verify_job_all_inputs;
use rbitcoin_consensus::ConsensusError;

fn flags() -> ScriptVerifyFlags {
    ScriptVerifyFlags::buried(true, true, true, true, true)
}

fn spend(
    prevouts: Vec<TxOut>,
    tx: Transaction,
    interpreter_only: bool,
) -> Result<(), ConsensusError> {
    let mut job = ScriptCheckJob::new(prevouts, tx, flags());
    job.interpreter_only = interpreter_only;
    verify_job_all_inputs(&job)
}

fn err_text(res: Result<(), ConsensusError>) -> String {
    match res {
        Ok(()) => panic!("expected a script error"),
        Err(e) => e.to_string(),
    }
}

struct EcdsaSpend {
    sk: SecretKey,
    pk: Vec<u8>,
    program: ScriptBuf,
}

fn ecdsa_identity() -> EcdsaSpend {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp)).to_bytes();
    let program = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(&pk));
    EcdsaSpend { sk, pk, program }
}

fn shell(_prev: TxOut, script_sig: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn witness_sig(tx: &Transaction, program: &ScriptBuf, value: Amount, sk: &SecretKey) -> Vec<u8> {
    let secp = Secp256k1::new();
    let sighash = SighashCache::new(tx)
        .p2wpkh_signature_hash(0, program, value, EcdsaSighashType::All)
        .unwrap();
    let mut sig = secp
        .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), sk)
        .serialize_der()
        .to_vec();
    sig.push(EcdsaSighashType::All as u8);
    sig
}

fn p2wpkh_tx(who: &EcdsaSpend, signer: &SecretKey) -> (Transaction, TxOut) {
    let prev = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: who.program.clone(),
    };
    let mut tx = shell(prev.clone(), ScriptBuf::new());
    let sig = witness_sig(&tx, &who.program, prev.value, signer);
    tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), who.pk.as_slice()]);
    (tx, prev)
}

fn p2pkh_tx(who: &EcdsaSpend, signer: &SecretKey) -> (Transaction, TxOut) {
    let secp = Secp256k1::new();
    let spk = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(&who.pk));
    let prev = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: spk.clone(),
    };
    let mut tx = shell(prev.clone(), ScriptBuf::new());
    tx.version = bitcoin::transaction::Version::ONE;
    let sighash = SighashCache::new(&tx)
        .legacy_signature_hash(0, &spk, EcdsaSighashType::All as u32)
        .unwrap();
    let mut sig = secp
        .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), signer)
        .serialize_der()
        .to_vec();
    sig.push(EcdsaSighashType::All as u8);
    let sig_push = bitcoin::script::PushBytesBuf::try_from(sig).unwrap();
    let pk_push = bitcoin::script::PushBytesBuf::try_from(who.pk.clone()).unwrap();
    tx.input[0].script_sig = bitcoin::script::Builder::new()
        .push_slice(&sig_push)
        .push_slice(&pk_push)
        .into_script();
    (tx, prev)
}

fn nested_tx(who: &EcdsaSpend, signer: &SecretKey) -> (Transaction, TxOut) {
    let redeem = bitcoin::script::PushBytesBuf::try_from(who.program.to_bytes()).unwrap();
    let script_sig = bitcoin::script::Builder::new()
        .push_slice(&redeem)
        .into_script();
    let prev = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2sh(&who.program.script_hash()),
    };
    let mut tx = shell(prev.clone(), script_sig);
    let sig = witness_sig(&tx, &who.program, prev.value, signer);
    tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), who.pk.as_slice()]);
    (tx, prev)
}

#[test]
fn default_job_keeps_fast_paths() {
    let job = ScriptCheckJob::new(vec![], empty_tx(), flags());
    assert!(!job.interpreter_only);
}

fn empty_tx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    }
}

#[test]
fn standard_spends_accept_on_both_paths_and_bad_p2wpkh_splits() {
    let who = ecdsa_identity();
    let other = SecretKey::from_slice(&[6u8; 32]).unwrap();

    let (good_wpkh, prev_wpkh) = p2wpkh_tx(&who, &who.sk);
    assert!(spend(vec![prev_wpkh.clone()], good_wpkh.clone(), false).is_ok());
    assert!(spend(vec![prev_wpkh.clone()], good_wpkh, true).is_ok());

    let (bad_wpkh, _) = p2wpkh_tx(&who, &other);
    let typed = err_text(spend(vec![prev_wpkh.clone()], bad_wpkh.clone(), false));
    let interpreted = err_text(spend(vec![prev_wpkh], bad_wpkh, true));
    assert!(
        typed.contains("p2wpkh ecdsa"),
        "typed path must keep its error, got {typed}"
    );
    assert!(
        !interpreted.contains("p2wpkh ecdsa"),
        "interpreter-only must not use the typed checker, got {interpreted}"
    );
    assert!(
        interpreted.contains("script false"),
        "interpreter script error, got {interpreted}"
    );

    let (good_pkh, prev_pkh) = p2pkh_tx(&who, &who.sk);
    assert!(spend(vec![prev_pkh.clone()], good_pkh.clone(), false).is_ok());
    assert!(spend(vec![prev_pkh.clone()], good_pkh, true).is_ok());
    let (bad_pkh, _) = p2pkh_tx(&who, &other);
    let typed = err_text(spend(vec![prev_pkh.clone()], bad_pkh.clone(), false));
    let interpreted = err_text(spend(vec![prev_pkh], bad_pkh, true));
    assert!(typed.contains("p2pkh ecdsa"), "{typed}");
    assert!(interpreted.contains("script false"), "{interpreted}");
    assert!(!interpreted.contains("p2pkh ecdsa"), "{interpreted}");

    let (good_nested, prev_nested) = nested_tx(&who, &who.sk);
    assert!(spend(vec![prev_nested.clone()], good_nested.clone(), false).is_ok());
    assert!(spend(vec![prev_nested.clone()], good_nested, true).is_ok());
    let (bad_nested, _) = nested_tx(&who, &other);
    let typed = err_text(spend(vec![prev_nested.clone()], bad_nested.clone(), false));
    let interpreted = err_text(spend(vec![prev_nested], bad_nested, true));
    assert!(typed.contains("p2wpkh ecdsa"), "{typed}");
    assert!(interpreted.contains("script false"), "{interpreted}");
    assert!(!interpreted.contains("p2wpkh ecdsa"), "{interpreted}");
}

#[test]
fn taproot_key_path_still_runs_when_interpreter_is_forced() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let tweaked = kp.tap_tweak(&secp, None);
    let output_key = tweaked.to_keypair().x_only_public_key().0;
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(output_key.serialize().as_ref());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let mut tx = shell(prevout.clone(), ScriptBuf::new());
    tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let mut cache = SighashCache::new(&tx);
    let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
        .unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(sighash.to_byte_array()),
        &tweaked.to_keypair(),
    );
    tx.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
    assert!(spend(vec![prevout.clone()], tx.clone(), false).is_ok());
    assert!(spend(vec![prevout], tx, true).is_ok());
}
