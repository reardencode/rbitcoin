use bitcoin::script::Script;
use bitcoin::{Amount, Sequence, Transaction};
use std::borrow::Cow;

use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{OutPoint, TxIn, TxOut, Witness};
use rbitcoin_consensus::script::interpreter::*;

fn tx_with_inputs(n: usize) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: (0..n)
            .map(|_| TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn tapscript_checksig_without_leaf_facts_fails() {
    let tx = tx_with_inputs(1);
    let mut script = vec![0x40];
    script.extend_from_slice(&[0x11; 64]);
    script.push(0x20);
    script.extend_from_slice(&[0x02; 32]);
    script.push(0xac);
    let sc = Script::from_bytes(&script);
    let idx = rbitcoin_consensus::block::InputIndex::in_tx(&tx, 0).expect("input index");
    let ctx = EvalContext::from_eval_parts(
        &tx,
        idx,
        Amount::ZERO,
        sc,
        SigVersion::TapScript,
        false,
        false,
        false,
        Cow::Owned(rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx)),
    );
    let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
    assert!(format!("{err}").contains("tapleaf"), "{err}");
}

#[test]
fn tapscript_checksig_rejects_a_signature_that_is_not_64_or_65_bytes() {
    let tx = tx_with_inputs(1);
    let mut script = vec![0x01, 0x11, 0x20];
    script.extend_from_slice(&[0x02; 32]);
    script.push(0xac);
    let sc = Script::from_bytes(&script);
    let idx = rbitcoin_consensus::block::InputIndex::in_tx(&tx, 0).expect("input index");
    let ctx = EvalContext::from_eval_parts(
        &tx,
        idx,
        Amount::ZERO,
        sc,
        SigVersion::TapScript,
        false,
        false,
        false,
        Cow::Owned(rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx)),
    );
    let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
    assert!(format!("{err}").contains("CHECKSIG"), "{err}");
}

#[test]
fn tapscript_checksigverify_rejects_an_empty_signature_on_a_32_byte_key() {
    let tx = tx_with_inputs(1);
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&[0x02; 32]);
    script.push(0xad);
    let sc = Script::from_bytes(&script);
    let idx = rbitcoin_consensus::block::InputIndex::in_tx(&tx, 0).expect("input index");
    let ctx = EvalContext::from_eval_parts(
        &tx,
        idx,
        Amount::ZERO,
        sc,
        SigVersion::TapScript,
        false,
        false,
        false,
        Cow::Owned(rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx)),
    );
    let err = eval_script(sc, &mut Vec::new(), &ctx).unwrap_err();
    assert!(format!("{err}").contains("CHECKSIGVERIFY"), "{err}");
}
