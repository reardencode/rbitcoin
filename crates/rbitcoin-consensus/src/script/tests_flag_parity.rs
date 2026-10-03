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
