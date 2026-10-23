//! `OP_CHECKTEMPLATEVERIFY` on the default signet.

use std::borrow::Cow;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::heretical::{HereticalFlags, SIGNET_CTV_HEIGHT};
use rbitcoin_consensus::script::crypto;
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

#[test]
fn activation_heights_follow_the_default_signet_only() {
    let signet = ChainParams::signet();
    assert!(!signet.heretical_at(SIGNET_CTV_HEIGHT - 1).ctv);
    assert!(signet.heretical_at(SIGNET_CTV_HEIGHT).ctv);

    assert!(ChainParams::regtest().heretical_at(0).ctv);
    assert_eq!(
        ChainParams::mainnet().heretical_at(1_000_000),
        HereticalFlags::default()
    );
    let mut custom = ChainParams::signet();
    custom.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(
        custom.heretical_at(SIGNET_CTV_HEIGHT),
        HereticalFlags::default()
    );
}

#[test]
fn op_checktemplateverify_matches_the_default_hash() {
    let tx = bare_tx();
    let pre = TxPrecompute::from_tx(&tx);
    let expect = crypto::ctv_default_hash(&tx, &pre, 0).expect("hash");
    let mut script = vec![0x20];
    script.extend_from_slice(&expect);
    script.push(0xb3);
    let code = Script::from_bytes(&script);
    let mut ctx = EvalContext::from_eval_parts(
        &tx,
        0,
        Amount::ZERO,
        code,
        SigVersion::Base,
        true,
        true,
        true,
        Cow::Owned(pre),
    );
    ctx.heretical.ctv = true;
    assert!(eval_script(code, &mut Vec::new(), &ctx).expect("ctv"));

    script[1] ^= 0xff;
    let code = Script::from_bytes(&script);
    let pre = TxPrecompute::from_tx(&tx);
    let mut ctx = EvalContext::from_eval_parts(
        &tx,
        0,
        Amount::ZERO,
        code,
        SigVersion::Base,
        true,
        true,
        true,
        Cow::Owned(pre),
    );
    ctx.heretical.ctv = true;
    let err = eval_script(code, &mut Vec::new(), &ctx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s == "TEMPLATE_MISMATCH"),
        "{err:?}"
    );

    // A non-32-byte argument stays a NOP.
    let nop = Script::from_bytes(&[0x01, 0x00, 0xb3]);
    let pre = TxPrecompute::from_tx(&tx);
    let mut ctx = EvalContext::from_eval_parts(
        &tx,
        0,
        Amount::ZERO,
        nop,
        SigVersion::Base,
        true,
        true,
        true,
        Cow::Owned(pre),
    );
    ctx.heretical.ctv = true;
    let mut stack = Vec::new();
    assert!(eval_script(nop, &mut stack, &ctx).expect("nop"));
    assert_eq!(stack, vec![vec![0x00]]);
}
