//! Script verification unit tests — pure `(tx, prevouts)` vectors, no UTXO set.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::block::ScriptCheckJob;
use crate::script;

fn make_p2wpkh_spend() -> (ScriptCheckJob, bool) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let pk_bytes = pk.to_bytes();
    let keyhash = hash160::Hash::hash(&pk_bytes);

    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(keyhash.as_byte_array());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk.clone()),
    };

    // Unsigned shell first for sighash
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            ScriptBuf::from_bytes(spk).as_script(),
            prevout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_raw = sig.serialize_der().to_vec();
    sig_raw.push(EcdsaSighashType::All as u8);

    tx.input[0].witness = Witness::from_slice(&[sig_raw.as_slice(), pk_bytes.as_slice()]);

    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    (job, true)
}

#[test]
fn p2wpkh_valid_signature_accepts() {
    let (job, _) = make_p2wpkh_spend();
    script::verify_job_all_inputs(&job).expect("valid p2wpkh");
}

#[test]
fn p2wpkh_bad_signature_rejects() {
    let (mut job, _) = make_p2wpkh_spend();
    // Corrupt last byte of witness sig
    let mut sig = job.tx.input[0].witness.nth(0).unwrap().to_vec();
    let n = sig.len();
    sig[n - 2] ^= 0xff;
    let pk = job.tx.input[0].witness.nth(1).unwrap().to_vec();
    job.tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), pk.as_slice()]);
    let err = script::verify_job_all_inputs(&job).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("p2wpkh ecdsa"),
        "expected ecdsa failure, got {msg}"
    );
    // Operator diagnosis: failing spend identity on IBD logs.
    let txid = job.tx.compute_txid();
    assert!(
        msg.contains(&format!("txid={txid}")) && msg.contains("vin=0"),
        "expected txid/vin annotation, got {msg}"
    );
}

/// Mainnet block 508011 tip-stall: nested P2SH-P2WPKH with **non-standard** sighash
/// type byte `0x65`. Core hashes the raw `nHashType`; rust-bitcoin's
/// `p2wpkh_signature_hash` encodes `from_consensus(0x65).to_u32() == 1`, which
/// fails ECDSA. Fixture is consensus-valid on mainnet (confirmed).
/// **RB-003** in `docs/rust-bitcoin-limitations.md`.
///
/// Log: `p2wpkh ecdsa txid=969c4f11…d50d vin=0` (2026-07-25 mainnet IBD).
#[test]
fn mainnet_508011_nested_p2wpkh_raw_sighash_0x65() {
    use bitcoin::consensus::encode::deserialize;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // Wire hex from mempool.space for confirmed mainnet tx.
    let hex = include_str!("../../tests/fixtures/mainnet_508011_p2sh_p2wpkh_tx.hex").trim();
    let raw = decode_hex(hex);
    let tx: Transaction = deserialize(&raw).expect("tx decode");
    assert_eq!(
        tx.compute_txid().to_string(),
        "969c4f116f0a68406d30dc80bf17991fb8fe7fa1b240382baefa2c324b79d50d"
    );
    assert_eq!(tx.input.len(), 1);
    // Witness hashtype is the last byte of the DER push.
    let sig = tx.input[0].witness.nth(0).unwrap();
    assert_eq!(*sig.last().unwrap(), 0x65, "fixture must use raw type 0x65");

    let prevout = TxOut {
        value: Amount::from_sat(99_830_000),
        script_pubkey: ScriptBuf::from_bytes(decode_hex(
            "a914e93f9e95f6d5cb1736a94de992d0d18819072fa587",
        )),
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).unwrap_or_else(|e| {
        panic!(
            "mainnet-valid nested P2WPKH must accept (got {e}); \
             if this fails, BIP143 raw nHashType is still wrong"
        )
    });
}

#[test]
fn anyone_can_spend_accepts() {
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
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
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("op_true");
}

/// Pre-taproot: witness v1 (P2TR shape) is anyone-can-spend.
#[test]
fn pretaproot_v1_witness_program_anyone_can_spend() {
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&[0x42u8; 32]);
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x01]]), // garbage witness OK pre-activation
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: false,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("pre-taproot v1 ACS");
}

/// Empty scriptPubKey is not anyone-can-spend (Core: empty stack after eval → fail).
#[test]
fn empty_script_pubkey_rejects() {
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new(),
    };
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
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    assert!(
        script::verify_job_all_inputs(&job).is_err(),
        "empty spk + empty scriptSig must fail"
    );
}

#[test]
fn p2pkh_valid_signature_accepts() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let pk_bytes = pk.to_bytes();
    let keyhash = hash160::Hash::hash(&pk_bytes);

    let mut spk = vec![0x76, 0xa9, 0x14];
    spk.extend_from_slice(keyhash.as_byte_array());
    spk.extend_from_slice(&[0x88, 0xac]);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk.clone()),
    };

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
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };

    let cache = SighashCache::new(&tx);
    let sighash = cache
        .legacy_signature_hash(
            0,
            ScriptBuf::from_bytes(spk).as_script(),
            EcdsaSighashType::All as u32,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_raw = sig.serialize_der().to_vec();
    sig_raw.push(EcdsaSighashType::All as u8);

    // scriptSig: <sig> <pubkey>
    let mut script_sig = Vec::new();
    script_sig.push(sig_raw.len() as u8);
    script_sig.extend_from_slice(&sig_raw);
    script_sig.push(pk_bytes.len() as u8);
    script_sig.extend_from_slice(&pk_bytes);
    tx.input[0].script_sig = ScriptBuf::from_bytes(script_sig);

    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("valid p2pkh");
}

#[test]
fn p2wsh_op_true_accepts() {
    // Witness script = OP_TRUE; scripthash = SHA256(0x51)
    let witness_script = vec![0x51u8];
    let sh = {
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&witness_script)
    };
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(sh.as_byte_array());
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[witness_script.as_slice()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("p2wsh op_true");
}

#[test]
fn p2wsh_wrong_script_hash_rejects() {
    let witness_script = vec![0x51u8];
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&[0u8; 32]); // wrong hash
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[witness_script.as_slice()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    assert!(script::verify_job_all_inputs(&job).is_err());
}

#[test]
fn p2sh_p2wpkh_nested_accepts() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let pk_bytes = pk.to_bytes();
    let keyhash = hash160::Hash::hash(&pk_bytes);

    // redeem = 00 14 <20>
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(keyhash.as_byte_array());
    let redeem_hash = hash160::Hash::hash(&redeem);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(redeem_hash.as_byte_array());
    spk.push(0x87);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };

    // scriptSig: push redeem
    let mut ss = Vec::new();
    ss.push(redeem.len() as u8);
    ss.extend_from_slice(&redeem);
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            ScriptBuf::from_bytes(redeem.clone()).as_script(),
            prevout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_raw = sig.serialize_der().to_vec();
    sig_raw.push(EcdsaSighashType::All as u8);
    tx.input[0].witness = Witness::from_slice(&[sig_raw.as_slice(), pk_bytes.as_slice()]);

    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("p2sh-p2wpkh");
}

/// Legacy P2SH with multi-push scriptSig must not die in nested-segwit probe
/// (`p2sh scriptSig multi push`). Signet 204802 hit that false positive.
#[test]
fn p2sh_legacy_multi_push_op_true_accepts() {
    // redeem = OP_DROP OP_TRUE — consumes dummy push, leaves true.
    let redeem = vec![0x75u8, 0x51];
    let redeem_hash = hash160::Hash::hash(&redeem);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(redeem_hash.as_byte_array());
    spk.push(0x87);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };

    // two pushes: dummy + redeem (must not error in try_p2sh_p2w*)
    let mut ss = Vec::new();
    ss.push(0x01);
    ss.push(0xaa);
    ss.push(redeem.len() as u8);
    ss.extend_from_slice(&redeem);

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx.clone()),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("p2sh multi-push legacy");
}

/// Mainnet height 183: historical high-S P2PK spend of an early coinbase-style output.
/// libsecp rejects high-S unless we normalize like Core (`ecdsa_signature_normalize`).
#[test]
fn mainnet_block_183_high_s_p2pk_accepts() {
    use bitcoin::consensus::deserialize;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    // Parent of the spend (2 outputs); spend uses vout=1.
    let prev: Transaction = deserialize(&hx(
        "0100000001be141eb442fbc446218b708f40caeb7507affe8acff58ed992eb5ddde43c6fa1010000004847304402201f27e51caeb9a0988a1e50799ff0af94a3902403c3ad4068b063e7b4d1b0a76702206713f69bd344058b0dee55a9798759092d0916dbbc3e592fee43060005ddc17401ffffffff0200e1f5050000000043410401518fa1d1e1e3e162852d68d9be1c0abad5e3d6297ec95f1f91b909dc1afe616d6876f92918451ca387c4387609ae1a895007096195a824baf9c38ea98c09c3ac007ddaac0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "010000000173805864da01f15093f7837607ab8be7c3705e29a9d4a12c9116d709f8911e590100000049483045022052ffc1929a2d8bd365c6a2a4e3421711b4b1e1b8781698ca9075807b4227abcb0221009984107ddb9e3813782b095d0d84361ed4c76e5edaf6561d252ae162c2341cfb01ffffffff0200e1f50500000000434104baa9d36653155627c740b3409a734d4eaf5dcca9fb4f736622ee18efcf0aec2b758b2ec40db18fbae708f691edb2d4a2a3775eb413d16e2e3c0f8d4c69119fd1ac009ce4a60000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
    ))
    .unwrap();
    let vout = spend.input[0].previous_output.vout as usize;
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[vout].clone()],
        tx: crate::block::JobTx::owned(spend),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("mainnet 183 high-S P2PK must verify");
}

/// Mainnet height 110300: P2PKH spend with **sighash type byte 0x00**.
///
/// `EcdsaSighashType::from_consensus(0)` becomes `All` (`to_u32()==1`), but Core
/// hashes with the raw byte. Using the normalized type rejects this real chain tx
/// and stalls tip (block blacklisted after confirm reject).
#[test]
fn mainnet_block_110300_sighash_type_zero_p2pkh() {
    use bitcoin::consensus::deserialize;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let prev: Transaction = deserialize(&hx(
        "01000000017fd8dfdb54b5212c4e3151a39f4ffe279fd7f238d516a2ca731529c095d97449010000008b483045022100b6a7fe5eea81894bbdd0df61043e42780543457fa5581ac1af023761a098e92202201d4752785be5f9d1b9f8d362b8cf3b05e298a78c4abff874b838bb500dcf2a120141042e3c4aeac1ffb1c86ce3621afb1ca92773e02badf0d4b1c836eb26bd27d0c2e59ffec3d6ab6b8bbeca81b0990ab5224ebdd73696c4255d1d0c6b3c518a1a053effffffff01404b4c00000000001976a914dc44b1164188067c3a32d4780f5996fa14a4f2d988ac00000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d00000000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac00000000",
    ))
    .unwrap();
    // Last byte of first push is 0x00 (hashtype 0).
    let ss = spend.input[0].script_sig.as_bytes();
    assert_eq!(ss[1 + 72], 0x00);
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[0].clone()],
        tx: crate::block::JobTx::owned(spend),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("hashtype 0 P2PKH must verify");
}

/// Mainnet height 124276: non-strict (lax) DER with double zero padding on R.
/// Pre-BIP66 this must accept; post-BIP66 it must fail.
#[test]
fn mainnet_block_124276_lax_der_pre_bip66() {
    use bitcoin::consensus::deserialize;
    use bitcoin::secp256k1::ecdsa::Signature;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let prev: Transaction = deserialize(&hx(
        "0100000001ba988c49d024d5ec33b49f74071b2157b1530e1301c3210d92c5dc08e04b63d0010000008b48304502200f18c2d1fe6513b90f44513e975e05cc498e7f5a565b46c65b1d448734392c6f022100917766d14f2e9933eb269c83b3ad440ed8432da8beb5733f34046509e48b1d850141049ba39856eec011b79f1acb997760ed9d3f90d477077d17df2571d94b2fa2137bf0976d786b6aabc903746e269628b2c28e4b5db753845e5713a48ee7d6b97aafffffffff01c0c62d00000000001976a9147a2a3b481ca80c4ba7939c54d9278e50189d94f988ac00000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "01000000012316aac445c13ff31af5f3d1e2cebcada83e54ba10d15e01f49ec28bddc285aa000000008e4b3048022200002b83d59c1d23c08efd82ee0662fec23309c3adbcbd1f0b8695378db4b14e736602220000334a96676e58b1bb01784cb7c556dd8ce1c220171904da22e18fe1e7d1510db5014104d0fe07ff74c9ef5b00fed1104fad43ecf72dbab9e60733e4f56eacf24b20cf3b8cd945bcabcc73ba0158bf9ce769d43e94bd58c5c7e331a188922b3fe9ca1f5affffffff01c0c62d00000000001976a9147a2a3b481ca80c4ba7939c54d9278e50189d94f988ac00000000",
    ))
    .unwrap();
    // Signature push is non-strict DER (0x22 length with 0x00 0x00 prefix).
    let ss = spend.input[0].script_sig.as_bytes();
    let n = ss[0] as usize;
    let der = &ss[1..1 + n - 1];
    assert!(
        Signature::from_der(der).is_err(),
        "fixture must be non-strict"
    );
    assert!(
        Signature::from_der_lax(der).is_ok(),
        "fixture must be lax-parseable"
    );

    let mut job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[0].clone()],
        tx: crate::block::JobTx::owned(spend),
        bip65_active: true,
        bip112_active: true,
        bip66_active: false, // height 124276 << bip66 363725
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("pre-BIP66 lax DER must verify");

    job.bip66_active = true;
    let err = script::verify_job_all_inputs(&job).expect_err("post-BIP66 must reject lax DER");
    assert!(
        err.to_string().contains("der"),
        "expected der error, got {err}"
    );
}

/// Unit: parse_der_sig strict vs lax.
#[test]
fn parse_der_sig_strict_vs_lax_on_double_zero_r() {
    use super::crypto::{is_valid_signature_encoding, parse_der_sig};
    use bitcoin::secp256k1::ecdsa::Signature;
    // From mainnet 124276 spend (sig push only, includes hashtype 0x01).
    let sig_raw = {
        let s = "3048022200002b83d59c1d23c08efd82ee0662fec23309c3adbcbd1f0b8695378db4b14e736602220000334a96676e58b1bb01784cb7c556dd8ce1c220171904da22e18fe1e7d1510db501";
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let der = &sig_raw[..sig_raw.len() - 1];
    assert!(Signature::from_der(der).is_err());
    assert!(Signature::from_der_lax(der).is_ok());
    assert!(!is_valid_signature_encoding(&sig_raw));
    assert!(parse_der_sig(&sig_raw, true).is_err());
    let (sig, ht) = parse_der_sig(&sig_raw, false).expect("lax");
    assert_eq!(ht, 1);
    let _ = sig;
}

/// Mainnet 140493: high-bit S without `0x00` pad.
///
/// libsecp `from_der` returns Ok with **wrong** (R,S) (S→0); only `from_der_lax`
/// recovers the OpenSSL values. Preferring strict-first rejected this tip block.
#[test]
fn parse_der_sig_never_prefers_strict_when_lax_differs() {
    use super::crypto::{is_valid_signature_encoding, parse_der_sig};
    use bitcoin::secp256k1::ecdsa::Signature;
    // scriptSig first push from mainnet tx 70f7c15c… (block 140493).
    let sig_raw = {
        let s = "304402206b5c3b1c86748dcf328b9f3a65e10085afcf5d1af5b40970d8ce3a9355e06b5b0220cdbdc23e6d3618e47056fccc60c5f73d1a542186705197e5791e97f0e6582a3201";
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let der = &sig_raw[..sig_raw.len() - 1];
    assert!(!is_valid_signature_encoding(&sig_raw), "not BIP66");
    // Both parsers succeed — but they must not agree (this is the landmine).
    let strict = Signature::from_der(der).expect("from_der wrongly accepts");
    let lax = Signature::from_der_lax(der).expect("from_der_lax");
    assert_ne!(
        strict.serialize_der().as_ref(),
        lax.serialize_der().as_ref(),
        "fixture must demonstrate from_der≠from_der_lax"
    );
    // Our helper must always take the lax values pre-BIP66.
    let (sig, ht) = parse_der_sig(&sig_raw, false).expect("pre-BIP66");
    assert_eq!(ht, 1);
    assert_eq!(sig.serialize_der().as_ref(), lax.serialize_der().as_ref());
    // Post-BIP66: encoding check rejects before any parse.
    assert!(parse_der_sig(&sig_raw, true).is_err());
}

/// libsecp256k1 / Bitcoin Core lax-DER corpus (must parse pre-BIP66).
#[test]
fn secp256k1_lax_der_corpus_parses() {
    use bitcoin::secp256k1::ecdsa::Signature;
    // From secp256k1 `signature_lax_der` unit test (also used by Core).
    const VECS: &[&str] = &[
        "304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c",
        "304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f",
        "3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a",
        "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45",
        "3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1",
        "3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60",
        "3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf",
    ];
    for hex in VECS {
        let der: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert!(
            Signature::from_der_lax(&der).is_ok(),
            "lax parse failed for {hex}"
        );
        // Append SIGHASH_ALL for our parse_der_sig helper.
        let mut with_ht = der;
        with_ht.push(0x01);
        assert!(super::crypto::parse_der_sig(&with_ht, false).is_ok());
    }
}

/// BIP66 height on mainnet is 363725 — document gate used by confirm.
#[test]
fn bip66_height_mainnet_documented() {
    use crate::params::ChainParams;
    let p = ChainParams::mainnet();
    assert_eq!(p.btc.bip66_height, 363_725);
    assert!(!p.bip66_active_at(124_276));
    assert!(p.bip66_active_at(363_725));
    assert!(p.bip66_active_at(840_000));
}

/// Mainnet height 170060: P2SH-**shaped** bare spend before BIP16 activation.
///
/// scriptSig is a single push of `OP_1 <pk> OP_1 CHECKMULTISIG`; scriptPubKey is
/// HASH160/EQUAL. Pre-BIP16 this is bare (hash of the push equals), **not**
/// redeem evaluation (which leaves an empty stack → CHECKMULTISIG "stack empty").
/// This is also Core's `BIP16Exception` block hash.
#[test]
fn mainnet_block_170060_pre_bip16_p2sh_as_bare() {
    use bitcoin::consensus::deserialize;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let prev: Transaction = deserialize(&hx(
        "010000000168781ca236d8e70e4af8285852defabeff61c73db259cbbbebdf7bdac918c234010000004847304402206d186984373e0b781b85f49334cc9a249ffd13a448a5d1732096b011a10063e102206d280df8f4b5e6805f48eb04601ca6d97edd78f2b2d1104dc577e08fd788c78001ffffffff02cce80900000000001976a914fe58bbf690824bdaffb0431a709c27d7bdb6105e88ac801a06000000000017a91419a7d869032368fd1f1e26e5e73a4ad0e474960e8700000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "0100000001f6ea284ec7521f8a7d094a6cf4e6873098b90f90725ffd372b343189d7a4089c0100000026255121029b6d2c97b8b7c718c325d7be3ac30f7c9d67651bce0c929f55ee77ce58efcf8451aeffffffff0130570500000000001976a9145a3acbc7bbcc97c5ff16f5909c9d7d3fadb293a888ac00000000",
    ))
    .unwrap();
    assert_eq!(
        spend.compute_txid().to_string(),
        "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192"
    );
    let vout = spend.input[0].previous_output.vout as usize;
    assert_eq!(vout, 1);
    // Outer spk is P2SH template.
    let spk = prev.output[vout].script_pubkey.as_bytes();
    assert_eq!(spk[0], 0xa9);
    assert_eq!(spk[spk.len() - 1], 0x87);

    let mut job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[vout].clone()],
        tx: crate::block::JobTx::owned(spend.clone()),
        bip65_active: false,
        bip112_active: false,
        bip66_active: false,
        bip16_active: false, // pre-BIP16 / exception block
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("pre-BIP16 P2SH-shape must verify as bare");

    // With BIP16 on, redeem is 1-of-1 CHECKMULTISIG with empty stack → fail.
    job.bip16_active = true;
    let err = script::verify_job_all_inputs(&job).expect_err("post-BIP16 redeem needs sigs");
    assert!(
        err.to_string().contains("stack") || err.to_string().contains("script"),
        "got {err}"
    );
}

/// Mainnet height 163685: bare spend with **non-push scriptSig**
/// (`OP_CODESEPARATOR` + 1-of-1 `CHECKMULTISIG`) then pre-BIP65 `OP_NOP2`+`DROP`
/// scriptPubKey. Consensus evaluates scriptSig fully (not push-only).
#[test]
fn mainnet_block_163685_scriptsig_codeseparator_checkmultisig() {
    use bitcoin::consensus::deserialize;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let prev: Transaction = deserialize(&hx(
        "01000000017ea56cd68c74b4cd1a2f478f361b8a67c15a6629d73d95ef21d96ae213eb5b2d010000006a4730440220228e4deb3bc5b47fc526e2a7f5e9434a52616f8353b55dbc820ccb69d5fbded502206a2874f7f84b20015614694fe25c4d76f10e31571f03c240e3e4bbf1f9985be201210232abdc893e7f0631364d7fd01cb33d24da45329a00357b3a7886211ab414d55affffffff0230c11d00000000001976a914709dcb44da534c550dacf4296f75cba1ba3b317788acc0c62d000000000017142a9bc5447d664c1d0141392a842d23dba45c4f13b17500000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "01000000024de8b0c4c2582db95fa6b3567a989b664484c7ad6672c85a3da413773e63fdb8000000006b48304502205b282fbc9b064f3bc823a23edcc0048cbb174754e7aa742e3c9f483ebe02911c022100e4b0b3a117d36cab5a67404dddbf43db7bea3c1530e0fe128ebc15621bd69a3b0121035aa98d5f77cd9a2d88710e6fc66212aff820026f0dad8f32d1f7ce87457dde50ffffffff4de8b0c4c2582db95fa6b3567a989b664484c7ad6672c85a3da413773e63fdb8010000006f004730440220276d6dad3defa37b5f81add3992d510d2f44a317fd85e04f93a1e2daea64660202200f862a0da684249322ceb8ed842fb8c859c0cb94c81e1c5308b4868157a428ee01ab51210232abdc893e7f0631364d7fd01cb33d24da45329a00357b3a7886211ab414d55a51aeffffffff02e0fd1c00000000001976a914380cb3c594de4e7e9b8e18db182987bebb5a4f7088acc0c62d000000000017142a9bc5447d664c1d0141392a842d23dba45c4f13b17500000000",
    ))
    .unwrap();
    assert_eq!(
        spend.compute_txid().to_string(),
        "eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb"
    );
    // scriptSig input 1 must contain OP_CODESEPARATOR (0xab).
    assert!(spend.input[1].script_sig.as_bytes().contains(&0xab));
    // Bare scriptPubKey: push20 + OP_NOP2/CLTV (0xb1) + OP_DROP.
    assert_eq!(prev.output[1].script_pubkey.as_bytes()[21], 0xb1);

    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[0].clone(), prev.output[1].clone()],
        tx: crate::block::JobTx::owned(spend),
        // height 163685: pre-BIP65 / pre-BIP66 / pre-CSV
        bip65_active: false,
        bip112_active: false,
        bip66_active: false,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job)
        .expect("bare CODESEPARATOR+CHECKMULTISIG scriptSig must verify");
}

/// Mainnet height 140493: P2PKH with high-bit S (no `0x00` pad) — pre-BIP66.
///
/// Tip stall: confirm rejected `p2pkh ecdsa` when parse preferred `from_der`
/// (wrong S=0) over `from_der_lax` (correct OpenSSL-era values).
#[test]
fn mainnet_block_140493_high_bit_s_lax_der_p2pkh() {
    use bitcoin::consensus::deserialize;
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    // Parent of 70f7c15c… (vout 1 is the P2PKH being spent).
    let prev: Transaction = deserialize(&hx(
        "01000000014213d2fe8f942dd7a72df14e656baab0e8b2b7f59571771ddf170b588379a2b6010000008b483045022037183e3e47b23634eeebe6fd155f0adbde756bf00a6843a1317b6548a03f3cfe0221009f96bec8759837f844478a35e102618918662869188f99d32dffe6ef7f81427e014104a7d3b0dda6d4d0a44b137a65105cdfed890b09ce2d283d5683029f46a00e531bff1deb3ad3862e0648dca953a4250b83610c4f20861555a2f5638bd3d7aff93dffffffff02ddfb1100000000001976a9142256ff6b9b9fea32bfa8e64aed10ee695ffe100988ac40420f00000000001976a914c62301ef02dfeec757fb8dedb8a45eda5fb5ee4d88ac00000000",
    ))
    .unwrap();
    let spend: Transaction = deserialize(&hx(
        "0100000001289eb02e8ddc1ee3486aadc1cd1335fba22a8e3e87e3f41b7c5bbe7fb4391d81010000008a47304402206b5c3b1c86748dcf328b9f3a65e10085afcf5d1af5b40970d8ce3a9355e06b5b0220cdbdc23e6d3618e47056fccc60c5f73d1a542186705197e5791e97f0e6582a32014104f25ec495fa21ad14d69f45bf277129488cfb1a339aba1fed3c5099bb6d8e9716491a14050fbc0b2fed2963dc1e56264b3adf52a81b953222a2180d48b54d1e18ffffffff0140420f00000000001976a914e6ba8cc407375ce1623ec17b2f1a59f2503afc6788ac00000000",
    ))
    .unwrap();
    assert_eq!(
        spend.compute_txid().to_string(),
        "70f7c15c6f62139cc41afa858894650344eda9975b46656d893ee59df8914a3d"
    );
    let vout = spend.input[0].previous_output.vout as usize;
    assert_eq!(vout, 1);

    let mut job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prev.output[vout].clone()],
        tx: crate::block::JobTx::owned(spend),
        bip65_active: true,
        bip112_active: true,
        bip66_active: false, // height 140493 << bip66 363725
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("pre-BIP66 high-bit-S DER must verify");

    job.bip66_active = true;
    let err = script::verify_job_all_inputs(&job).expect_err("post-BIP66 must reject");
    assert!(
        err.to_string().contains("der"),
        "expected der error, got {err}"
    );
}

/// Mainnet height 443992 tx `5fec539b…`: P2SH redeem with multiple
/// `OP_CODESEPARATOR`s. Legacy sighash must **omit** CODESEPARATOR bytes from
/// the serialized scriptCode (Core `SerializeScriptCode`). Without that strip,
/// CHECKSIGVERIFY fails and tip stalls after blacklisting the block.
#[test]
fn mainnet_block_443992_p2sh_codeseparator_scriptcode() {
    use bitcoin::consensus::deserialize;
    use bitcoin::{Amount, ScriptBuf, TxOut};
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let spend: Transaction = deserialize(&hx(
        "01000000016aaa18f4ab91fab80ecda666c4def68b8b75cc6bb1169ecd81716eab03ff14d007000000fd8701483045022100ac4319cf798ab10d864ad5f206cd405b7a15957eef2b0094ab24ffcf2c28fbfb022012053c8142d9e4f832d85c6ce7dba82d44d011c7713fb584771fb8770da97c0c012102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf47304402202feedc3b54cd87868406e93ee650742b61ce39162d70b6fde5a805fd40a56c900220015970a2fc874c32edfcd6341981d35e5b019a14b17662e00f49e363db72b93c014cd22102fb6827937707bf432d85b094bc180ab93394ee013b3ecaafa04b9135e3ab6e50ad74926404162c5658b15167762103db22e387923ad0552e1c4a4355324313af85926d4266c0eaa86f02eb1e01b2d28763ac67762102c8662aaa171b5c98fef66c02138165f600c7c5743380686958e395edf8eb36bf886e6b6b0064ab05636f6e643175ac687664756c6c6e6b6bab05636f6e643275ac687664756c6c6e6b6bab05636f6e643375ac687664756c6c6e6b6bab05636f6e643475ac687664756c6c6e6b6bab05636f6e643575ac686868ffffffff01204e0000000000001976a914648a4310b84426f426398ef27e3388a4d2c05a2888ac342c5658",
    ))
    .unwrap();
    assert_eq!(
        spend.compute_txid().to_string(),
        "5fec539b26083b26d9d77014402e5942566a3c8c6e1b2b0c9cd245d51a0a5c61"
    );
    let prevout = TxOut {
        value: Amount::from_sat(70_000),
        script_pubkey: ScriptBuf::from_bytes(hx("a9143ae52dbc43c884ef43211a43082d01a0091ef1e387")),
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(spend),
        bip65_active: true,  // 388381
        bip112_active: true, // 419328
        bip66_active: true,  // 363725
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job)
        .expect("P2SH redeem with CODESEPARATOR must verify under Core scriptCode rules");
}

/// Core: OP_TRUE scriptPubKey still runs EvalScript(scriptSig). CLTV in scriptSig must fail.
#[test]
fn cltv_in_scriptsig_with_op_true_spk_enforced() {
    // scriptSig: OP_1 CLTV; spk: OP_TRUE; locktime=0, seq non-final → CLTV fails (1 > 0).
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51, 0xb1]), // 1 CLTV
            sequence: Sequence::from_consensus(0),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: false,
        bip66_active: false,
        bip16_active: false,
        taproot_active: false,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: false,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    let err = script::verify_job_all_inputs(&job).expect_err("CLTV in scriptSig must run");
    assert!(
        format!("{err}").contains("CLTV"),
        "expected CLTV failure, got {err}"
    );
}

/// BIP141: unknown witness version is anyone-can-spend when not discouraged.
#[test]
fn unknown_witness_v16_accepts_without_discourage() {
    // OP_16 + 20-byte program (same shape as Core tx_valid #197 vin1).
    let mut spk = vec![0x60u8, 0x14];
    spk.extend_from_slice(&[0x4cu8; 20]);
    let prevout = TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x01], vec![0x02]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect("unknown v16 ACS without discourage");
}

/// BIP141: non-empty scriptSig on a witness program is WITNESS_MALLEATED.
#[test]
fn unknown_witness_v16_malleated_scriptsig() {
    let spk = vec![0x60u8, 0x02, 0x00, 0x01];
    let prevout = TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    let err = script::verify_job_all_inputs(&job).expect_err("malleated");
    assert!(
        format!("{err}").contains("WITNESS_MALLEATED") || format!("{err}").contains("MALLEAT"),
        "got {err}"
    );
}

/// DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM rejects unknown versions.
#[test]
fn unknown_witness_v16_discourage_rejects() {
    let mut spk = vec![0x60u8, 0x21];
    spk.extend_from_slice(&[0xffu8; 33]);
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: true,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    let err = script::verify_job_all_inputs(&job).expect_err("discourage");
    assert!(format!("{err}").contains("DISCOURAGE"), "got {err}");
}

/// P2WSH **initial stack** items (not the witnessScript) must be ≤ 520.
#[test]
fn p2wsh_oversized_witness_element_rejected() {
    // redeem: DROP TRUE
    let redeem = vec![0x75u8, 0x51];
    let hash = bitcoin::hashes::sha256::Hash::hash(&redeem);
    let mut spk = vec![0x00u8, 0x20];
    spk.extend_from_slice(hash.as_byte_array());
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let oversized = vec![0u8; 521];
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            // stack item oversized, then witnessScript
            witness: Witness::from_slice(&[oversized, redeem]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    let err = script::verify_job_all_inputs(&job).expect_err("oversized element");
    let s = format!("{err}");
    assert!(
        s.contains("PUSH_SIZE") || s.contains("element") || s.contains("520") || s.contains("size"),
        "got {err}"
    );
}

/// Regression: mainnet h=842472 rejected with PUSH_SIZE because we applied the
/// 520-byte cap to the **witnessScript** (last stack item). Core pops the script
/// first and only limits remaining stack items to 520; script size ≤ 10_000.
#[test]
fn p2wsh_witness_script_larger_than_520_is_valid() {
    // Two max-size (520) pushes + DROP each + TRUE → script ≫ 520, no single
    // push > 520, low op count. Matches Core: script size ≠ stack-item size.
    let mut redeem = Vec::with_capacity(1100);
    for _ in 0..2 {
        redeem.push(0x4d); // OP_PUSHDATA2
        redeem.extend_from_slice(&520u16.to_le_bytes());
        redeem.extend(std::iter::repeat_n(0u8, 520));
        redeem.push(0x75); // OP_DROP
    }
    redeem.push(0x51); // OP_1
    assert!(redeem.len() > 520);
    let hash = bitcoin::hashes::sha256::Hash::hash(&redeem);
    let mut spk = vec![0x00u8, 0x20];
    spk.extend_from_slice(hash.as_byte_array());
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            // Witness is only the large script (empty initial stack).
            witness: Witness::from_slice(&[redeem]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: vec![prevout],
        tx: crate::block::JobTx::owned(tx),
        bip65_active: true,
        bip112_active: true,
        bip66_active: true,
        bip16_active: true,
        taproot_active: true,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: true,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        pre: std::sync::OnceLock::new(),
    };
    script::verify_job_all_inputs(&job).expect(
        "P2WSH witnessScript >520 must verify (Core ExecuteWitnessScript after SpanPopBack)",
    );
}
