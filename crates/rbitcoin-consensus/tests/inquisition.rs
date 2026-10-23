//! `SIGHASH_ANYPREVOUT` on the default signet.

use std::borrow::Cow;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::block::{ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::heretical::{HereticalFlags, SIGNET_APO_HEIGHT};
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

#[test]
fn activation_heights_follow_the_default_signet_only() {
    let signet = ChainParams::signet();
    assert!(!signet.heretical_at(SIGNET_APO_HEIGHT - 1).apo);
    assert!(signet.heretical_at(SIGNET_APO_HEIGHT).apo);

    assert!(ChainParams::regtest().heretical_at(0).apo);
    assert_eq!(
        ChainParams::mainnet().heretical_at(1_000_000),
        HereticalFlags::default()
    );
    let mut custom = ChainParams::signet();
    custom.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(
        custom.heretical_at(SIGNET_APO_HEIGHT),
        HereticalFlags::default()
    );
}

#[test]
fn anyprevout_verifies_and_stays_upgradable_when_inactive() {
    let tx = bare_tx();
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let job = ScriptCheckJob::new(
        vec![prevout],
        tx.clone(),
        ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    let leaf = ScriptBuf::from_bytes(vec![0xac]);
    let leaf_hash =
        bitcoin::TapLeafHash::from_script(&leaf, bitcoin::taproot::LeafVersion::TapScript);
    let spent = TapSpentHashes::default();
    let internal = [0u8; 32];
    let exec = crypto::TapscriptExecData::new(&job, 0, &spent, leaf_hash, None, internal);
    let sighash = exec.anyprevout_hash(0, 0xFFFF_FFFF).expect("apo hash");

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x22; 32]).expect("secret");
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp)
        .serialize();
    let pk = xonly.serialize();

    let mut pubkey = vec![0x01];
    pubkey.extend_from_slice(&pk);
    let mut script = Vec::new();
    script.push(sig.len() as u8);
    script.extend_from_slice(&sig);
    script.push(pubkey.len() as u8);
    script.extend_from_slice(&pubkey);
    script.push(0xac);

    let on = HereticalFlags { apo: true };
    let exec = crypto::TapscriptExecData::new(&job, 0, &spent, leaf_hash, None, internal);
    let stack = eval_tapscript(&script, on, Some(exec), &tx).expect("apo");
    assert_eq!(stack, vec![vec![0x01]]);

    script[1] ^= 0xff;
    let exec = crypto::TapscriptExecData::new(&job, 0, &spent, leaf_hash, None, internal);
    let err = eval_tapscript(&script, on, Some(exec), &tx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s == "tapscript CHECKSIG failed"),
        "{err:?}"
    );

    // One-byte APO key is an upgradable success while the deployment is off.
    let up = [0x40];
    let mut upgradable = up.to_vec();
    upgradable.extend_from_slice(&[0x11; 64]);
    upgradable.extend_from_slice(&[0x01, 0x01, 0xac]);
    let stack = eval_tapscript(&upgradable, HereticalFlags::default(), None, &tx).expect("upgrade");
    assert_eq!(stack, vec![vec![0x01]]);
}
