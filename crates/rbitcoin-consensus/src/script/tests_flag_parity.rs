//! Script flag parity with Bitcoin Core `interpreter.cpp`: signed spends run
//! through [`script::verify_job_all_inputs`] with policy flags on or off.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::block::{ScriptCheckJob, ScriptVerifyFlags};
use crate::script;

const VALUE: Amount = Amount::from_sat(50_000);

fn secret(n: u8) -> SecretKey {
    SecretKey::from_slice(&[n; 32]).unwrap()
}

fn compressed_pubkey(n: u8) -> Vec<u8> {
    let secp = Secp256k1::new();
    secret(n).public_key(&secp).serialize().to_vec()
}

fn spend(script_sig: Vec<u8>, witness: &[Vec<u8>]) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// Consensus flags at a post-Taproot height, then `policy` on top.
fn job(
    spk: Vec<u8>,
    tx: Transaction,
    policy: impl FnOnce(&mut ScriptVerifyFlags),
) -> ScriptCheckJob {
    let mut flags = ScriptVerifyFlags::buried(true, true, true, true, true);
    policy(&mut flags);
    let prevout = TxOut {
        value: VALUE,
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    ScriptCheckJob::new(vec![prevout], tx, flags)
}

fn der_with_hashtype(digest: [u8; 32], key: u8, hashtype: u8) -> Vec<u8> {
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest(digest), &secret(key));
    let mut raw = sig.serialize_der().to_vec();
    raw.push(hashtype);
    raw
}

fn sign_bip143(tx: &Transaction, script_code: &[u8], key: u8) -> Vec<u8> {
    let digest = SighashCache::new(tx)
        .p2wsh_signature_hash(
            0,
            Script::from_bytes(script_code),
            VALUE,
            EcdsaSighashType::All,
        )
        .unwrap();
    der_with_hashtype(digest.to_byte_array(), key, 0x01)
}

fn p2wsh_spk(witness_script: &[u8]) -> Vec<u8> {
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(bitcoin::hashes::sha256::Hash::hash(witness_script).as_byte_array());
    spk
}

fn push(script: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() < 0x4c);
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

/// `OP_1 <key 1> <key 2> OP_2 OP_CHECKMULTISIG`.
fn one_of_two() -> Vec<u8> {
    let mut script = vec![0x51];
    push(&mut script, &compressed_pubkey(1));
    push(&mut script, &compressed_pubkey(2));
    script.extend_from_slice(&[0x52, 0xae]);
    script
}

/// Core checks the last-pushed key first. A signature for the first key
/// fails that comparison and then matches; NULLFAIL only applies when the
/// whole CHECKMULTISIG fails.
#[test]
fn nullfail_p2wsh_multisig_sig_matching_later_key_accepts() {
    let ws = one_of_two();
    let unsigned = spend(Vec::new(), &[]);
    let sig = sign_bip143(&unsigned, &ws, 1);
    let tx = spend(Vec::new(), &[Vec::new(), sig, ws.clone()]);
    let job = job(p2wsh_spk(&ws), tx, |f| f.nullfail = true);
    script::verify_job_all_inputs(&job).expect("1-of-2 with NULLFAIL");
}

fn uncompressed_pubkey(n: u8) -> Vec<u8> {
    let secp = Secp256k1::new();
    secret(n)
        .public_key(&secp)
        .serialize_uncompressed()
        .to_vec()
}

/// Core `CheckPubKeyEncoding` runs for an empty signature: CHECKSIG and every
/// CHECKMULTISIG pair the key walk examines.
#[test]
fn empty_sig_still_checks_pubkey_encoding() {
    let bad_key = [0x05u8; 33];

    let mut checksig_not = Vec::new();
    push(&mut checksig_not, &bad_key);
    checksig_not.extend_from_slice(&[0xac, 0x91]);
    let mut multisig_not = vec![0x51];
    push(&mut multisig_not, &bad_key);
    multisig_not.extend_from_slice(&[0x51, 0xae, 0x91]);

    for (spk, script_sig) in [(checksig_not, vec![0x00]), (multisig_not, vec![0x00, 0x00])] {
        let tx = spend(script_sig, &[]);
        let consensus = job(spk.clone(), tx.clone(), |_| {});
        script::verify_job_all_inputs(&consensus).expect("consensus: empty sig is false");
        let strict = job(spk, tx, |f| f.strictenc = true);
        let err = script::verify_job_all_inputs(&strict).expect_err("STRICTENC");
        assert!(format!("{err}").contains("PUBKEYTYPE"), "{err}");
    }

    let mut ws = Vec::new();
    push(&mut ws, &uncompressed_pubkey(1));
    ws.extend_from_slice(&[0xac, 0x91]);
    let tx = spend(Vec::new(), &[Vec::new(), ws.clone()]);
    let consensus = job(p2wsh_spk(&ws), tx.clone(), |_| {});
    script::verify_job_all_inputs(&consensus).expect("consensus: empty sig is false");
    let typed = job(p2wsh_spk(&ws), tx, |f| f.witness_pubkeytype = true);
    let err = script::verify_job_all_inputs(&typed).expect_err("WITNESS_PUBKEYTYPE");
    assert!(format!("{err}").contains("WITNESS_PUBKEYTYPE"), "{err}");
}

/// Core `VerifyWitnessProgram`: pay-to-anchor and a v1 32-byte program
/// before Taproot activates succeed without reaching the
/// DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM branch.
#[test]
fn discourage_skips_native_p2a_and_pre_taproot_v1() {
    let p2a = vec![0x51, 0x02, 0x4e, 0x73];
    let tx = spend(Vec::new(), &[]);
    let anchor = job(p2a, tx.clone(), |f| f.discourage_upgradable_witness = true);
    script::verify_job_all_inputs(&anchor).expect("P2A is not discouraged");

    let mut v1 = vec![0x51, 0x20];
    v1.extend_from_slice(&[0x11; 32]);
    let pre_taproot = job(v1, tx, |f| {
        f.taproot_active = false;
        f.discourage_upgradable_witness = true;
    });
    script::verify_job_all_inputs(&pre_taproot).expect("v1/32 before Taproot");
}
