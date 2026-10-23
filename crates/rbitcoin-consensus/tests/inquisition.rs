//! BIP 448 on the default signet: `OP_TEMPLATEHASH`, `OP_CHECKSIGFROMSTACK`,
//! and `OP_INTERNALKEY`, at the Inquisition buried heights.

use std::borrow::Cow;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::ffi::{self, CPtr};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::block::{ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::heretical::{
    HereticalFlags, SIGNET_CSFS_HEIGHT, SIGNET_INTERNALKEY_HEIGHT, SIGNET_TEMPLATEHASH_HEIGHT,
};
use rbitcoin_consensus::script::crypto::{self, TapSpentHashes};
use rbitcoin_consensus::script::interpreter::{eval_script, EvalContext, SigVersion};
use rbitcoin_consensus::tx_precompute::TxPrecompute;
use rbitcoin_consensus::{ChainParams, ConsensusError};

fn bare_tx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn eval_tapscript(
    script: &[u8],
    flags: HereticalFlags,
    exec: Option<crypto::TapscriptExecData<'_>>,
    tx: &Transaction,
) -> Result<Vec<Vec<u8>>, ConsensusError> {
    let code = Script::from_bytes(script);
    let mut ctx = EvalContext::from_eval_parts(
        tx,
        0,
        Amount::from_sat(1_000),
        code,
        SigVersion::TapScript,
        true,
        true,
        true,
        Cow::Owned(TxPrecompute::from_tx(tx)),
    );
    ctx.heretical = flags;
    if let Some(exec) = exec {
        ctx.tapscript = Some(exec);
    }
    let mut stack = Vec::new();
    eval_script(code, &mut stack, &ctx)?;
    Ok(stack)
}

fn sign_custom(msg: &[u8]) -> ([u8; 64], [u8; 32]) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11; 32]).expect("secret");
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let mut sig = [0u8; 64];
    // SAFETY: `msg` and `sig` live for this call. `extra_params` null selects
    // the default BIP340 nonce. The keypair is a valid signing key.
    let ok = unsafe {
        ffi::secp256k1_schnorrsig_sign_custom(
            secp.ctx().as_ptr(),
            sig.as_mut_ptr(),
            msg.as_ptr(),
            msg.len(),
            kp.as_c_ptr(),
            std::ptr::null(),
        )
    };
    assert_eq!(ok, 1, "schnorr sign");
    (sig, xonly.serialize())
}

#[test]
fn activation_heights_follow_the_default_signet_only() {
    let signet = ChainParams::signet();
    let before = signet.heretical_at(SIGNET_CSFS_HEIGHT - 1);
    assert!(!before.csfs && !before.internal_key && !before.template_hash);

    let csfs = signet.heretical_at(SIGNET_CSFS_HEIGHT);
    assert!(csfs.csfs && csfs.internal_key && !csfs.template_hash);
    assert_eq!(SIGNET_CSFS_HEIGHT, SIGNET_INTERNALKEY_HEIGHT);

    assert!(
        !signet
            .heretical_at(SIGNET_TEMPLATEHASH_HEIGHT - 1)
            .template_hash
    );
    assert!(
        signet
            .heretical_at(SIGNET_TEMPLATEHASH_HEIGHT)
            .template_hash
    );

    let regtest = ChainParams::regtest().heretical_at(0);
    assert!(regtest.csfs && regtest.internal_key && regtest.template_hash);

    assert_eq!(
        ChainParams::mainnet().heretical_at(1_000_000),
        HereticalFlags::default()
    );
    let mut custom = ChainParams::signet();
    custom.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(
        custom.heretical_at(SIGNET_TEMPLATEHASH_HEIGHT),
        HereticalFlags::default()
    );
}

#[test]
fn op_checksigfromstack_verifies_the_raw_message() {
    let msg = b"not prehashed";
    let (sig, pk) = sign_custom(msg);
    let mut script = Vec::new();
    script.push(sig.len() as u8);
    script.extend_from_slice(&sig);
    script.push(msg.len() as u8);
    script.extend_from_slice(msg);
    script.push(pk.len() as u8);
    script.extend_from_slice(&pk);
    script.push(0xcc);
    let on = HereticalFlags {
        csfs: true,
        ..HereticalFlags::default()
    };
    let tx = bare_tx();
    let stack = eval_tapscript(&script, on, None, &tx).expect("csfs");
    assert_eq!(stack, vec![vec![0x01]]);

    script[1] ^= 0xff;
    let err = eval_tapscript(&script, on, None, &tx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s == "CSFS failed"),
        "{err:?}"
    );

    // Empty signature pushes false and does not verify.
    let mut empty = vec![0x00, msg.len() as u8];
    empty.extend_from_slice(msg);
    empty.push(32);
    empty.extend_from_slice(&pk);
    empty.push(0xcc);
    let stack = eval_tapscript(&empty, on, None, &tx).expect("empty sig");
    assert_eq!(stack, vec![Vec::<u8>::new()]);

    // Flag off: the byte is still OP_SUCCESS.
    let skipped = eval_tapscript(&[0xcc], HereticalFlags::default(), None, &tx).expect("success");
    assert!(skipped.is_empty());
}

#[test]
fn op_internalkey_pushes_the_control_block_key() {
    let tx = bare_tx();
    let job = ScriptCheckJob::new(
        vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
        tx.clone(),
        ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    let leaf = ScriptBuf::from_bytes(vec![0xcb]);
    let leaf_hash =
        bitcoin::TapLeafHash::from_script(&leaf, bitcoin::taproot::LeafVersion::TapScript);
    let key = [0xab; 32];
    let spent = TapSpentHashes::default();
    let exec = crypto::TapscriptExecData::new(&job, 0, &spent, leaf_hash, None, key);
    let on = HereticalFlags {
        internal_key: true,
        ..HereticalFlags::default()
    };
    let stack = eval_tapscript(&[0xcb], on, Some(exec), &tx).expect("internalkey");
    assert_eq!(stack, vec![key.to_vec()]);

    let skipped = eval_tapscript(&[0xcb], HereticalFlags::default(), None, &tx).expect("success");
    assert!(skipped.is_empty());
}

#[test]
fn op_templatehash_matches_an_independent_preimage() {
    let tx = bare_tx();
    let pre = TxPrecompute::from_tx(&tx);
    let got = crypto::template_hash(&tx, &pre, 0, None).expect("hash");

    let mut payload = Vec::new();
    tx.version.consensus_encode(&mut payload).unwrap();
    tx.lock_time.consensus_encode(&mut payload).unwrap();
    payload.extend_from_slice(&pre.sha_sequences.expect("sequences"));
    payload.extend_from_slice(&pre.sha_outputs.expect("outputs"));
    payload.push(0);
    payload.extend_from_slice(&0u32.to_le_bytes());
    let tag = sha256::Hash::hash(b"TemplateHash");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&payload);
    let expect = sha256::Hash::from_engine(eng).to_byte_array();
    assert_eq!(got, expect);

    let other = crypto::template_hash(&tx, &pre, 1, None).expect("index");
    assert_ne!(got, other);
    let annex = crypto::template_hash(&tx, &pre, 0, Some([0x44; 32])).expect("annex");
    assert_ne!(got, annex);
}
