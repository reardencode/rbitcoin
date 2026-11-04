//! Shipped `equiv_verify` entry. Feature `equiv` only.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
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
