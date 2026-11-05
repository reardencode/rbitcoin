//! Shipped `equiv_verify` entry. Feature `equiv` only.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use rbitcoin_consensus::block::{ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::script::equiv::{equiv_verify, EquivFail, EQUIV_ALLOWED};
use rbitcoin_consensus::script::verify_job_all_inputs;

const LOW_S: u64 = 1 << 3;
const DISCOURAGE_UPGRADABLE_WITNESS: u64 = 1 << 12;

fn shell(inputs: Vec<TxIn>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn one_in(script_sig: ScriptBuf, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint::null(),
        script_sig,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness,
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

fn p2wpkh(who: &EcdsaSpend, signer: &SecretKey) -> (Transaction, Vec<TxOut>) {
    let prev = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: who.program.clone(),
    };
    let mut tx = shell(vec![one_in(ScriptBuf::new(), Witness::new())]);
    let sig = witness_sig(&tx, &who.program, prev.value, signer);
    tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), who.pk.as_slice()]);
    (tx, vec![prev])
}

fn interpreter_only(
    prevouts: &[TxOut],
    tx: &Transaction,
) -> Result<(), rbitcoin_consensus::ConsensusError> {
    let mut job = ScriptCheckJob::new(
        prevouts.to_vec(),
        tx.clone(),
        ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    job.interpreter_only = true;
    verify_job_all_inputs(&job)
}

#[test]
fn pass_fail_and_bad_input() {
    let who = ecdsa_identity();
    let (good, prevouts) = p2wpkh(&who, &who.sk);
    assert_eq!(equiv_verify(&good, &prevouts, 0, EQUIV_ALLOWED), Ok(()));
    assert!(interpreter_only(&prevouts, &good).is_ok());

    let other = SecretKey::from_slice(&[6u8; 32]).unwrap();
    let (bad, prevouts) = p2wpkh(&who, &other);
    assert_eq!(
        equiv_verify(&bad, &prevouts, 0, EQUIV_ALLOWED),
        Err(EquivFail::Script(2))
    );
    let interpreted = interpreter_only(&prevouts, &bad).unwrap_err().to_string();
    assert!(interpreted.contains("script false"), "{interpreted}");
    assert!(!interpreted.contains("p2wpkh ecdsa"), "{interpreted}");

    assert_eq!(
        equiv_verify(&good, &prevouts, 0, EQUIV_ALLOWED | LOW_S),
        Err(EquivFail::BadInput)
    );
    assert_eq!(
        equiv_verify(
            &good,
            &prevouts,
            0,
            EQUIV_ALLOWED | DISCOURAGE_UPGRADABLE_WITNESS
        ),
        Err(EquivFail::BadInput)
    );
    assert_eq!(
        equiv_verify(&good, &[], 0, EQUIV_ALLOWED),
        Err(EquivFail::BadInput)
    );
    assert_eq!(
        equiv_verify(&good, &prevouts, 1, EQUIV_ALLOWED),
        Err(EquivFail::BadInput)
    );
}

#[test]
fn two_input_taproot_gets_every_prevout() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let tweaked = kp.tap_tweak(&secp, None);
    let output_key = tweaked.to_keypair().x_only_public_key().0;
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(output_key.serialize().as_ref());
    let spent = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk.clone()),
    };
    let other = TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let prevouts = vec![spent.clone(), other.clone()];
    let mut tx = shell(vec![
        one_in(ScriptBuf::new(), Witness::new()),
        one_in(ScriptBuf::new(), Witness::new()),
    ]);
    let sigs = {
        let mut cache = SighashCache::new(&tx);
        let all = Prevouts::All(&prevouts);
        let mut sigs = Vec::with_capacity(2);
        for index in 0..2 {
            let sighash = cache
                .taproot_key_spend_signature_hash(index, &all, TapSighashType::Default)
                .unwrap();
            sigs.push(secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(sighash.to_byte_array()),
                &tweaked.to_keypair(),
            ));
        }
        sigs
    };
    for (index, sig) in sigs.iter().enumerate() {
        tx.input[index].witness = Witness::from_slice(&[sig.as_ref()]);
    }

    assert_eq!(equiv_verify(&tx, &prevouts, 0, EQUIV_ALLOWED), Ok(()));
    assert_eq!(equiv_verify(&tx, &prevouts, 1, EQUIV_ALLOWED), Ok(()));
    assert!(interpreter_only(&prevouts, &tx).is_ok());
    assert_eq!(
        equiv_verify(&tx, std::slice::from_ref(&spent), 0, EQUIV_ALLOWED),
        Err(EquivFail::BadInput)
    );
}

fn p2tr_program(key: &[u8]) -> ScriptBuf {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(key);
    ScriptBuf::from_bytes(spk)
}

/// Core `SignatureHashSchnorr` fails `SIGHASH_SINGLE` when `nIn >= nOut`
/// as `SCHNORR_SIG_HASHTYPE` (46), before the signature is checked.
#[test]
fn sighash_single_past_outputs_is_schnorr_hashtype() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let mut sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest([1u8; 32]), &kp)
        .as_ref()
        .to_vec();
    sig.push(0x03);
    let spk = p2tr_program(&xonly.serialize());
    let prevouts = vec![
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: spk.clone(),
        },
        TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: spk,
        },
    ];
    let tx = shell(vec![
        one_in(ScriptBuf::new(), Witness::new()),
        one_in(ScriptBuf::new(), Witness::from_slice(&[sig.as_slice()])),
    ]);
    assert_eq!(
        equiv_verify(&tx, &prevouts, 1, EQUIV_ALLOWED),
        Err(EquivFail::Script(46))
    );

    let leaf = ScriptBuf::from_bytes(vec![0xac]);
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[8u8; 32]).unwrap());
    let (internal_xonly, _) = internal.x_only_public_key();
    let spend = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal_xonly)
        .unwrap();
    let control = spend
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    let mut sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest([2u8; 32]), &kp)
        .as_ref()
        .to_vec();
    sig.push(0x83);
    let witness = Witness::from_slice(&[
        sig.as_slice(),
        xonly.serialize().as_ref(),
        leaf.as_bytes(),
        control.as_slice(),
    ]);
    let program = p2tr_program(&spend.output_key().to_x_only_public_key().serialize());
    let prevouts = vec![
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: program.clone(),
        },
        TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: program,
        },
    ];
    let tx = shell(vec![
        one_in(ScriptBuf::new(), Witness::new()),
        one_in(ScriptBuf::new(), witness),
    ]);
    assert_eq!(
        equiv_verify(&tx, &prevouts, 1, EQUIV_ALLOWED),
        Err(EquivFail::Script(46))
    );
}
