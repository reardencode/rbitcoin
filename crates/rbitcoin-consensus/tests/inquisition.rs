//! `OP_CAT` on the default signet.

use std::borrow::Cow;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::heretical::{HereticalFlags, SIGNET_CAT_HEIGHT};
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
    let mut stack = Vec::new();
    eval_script(code, &mut stack, &ctx)?;
    Ok(stack)
}

#[test]
fn activation_heights_follow_the_default_signet_only() {
    let signet = ChainParams::signet();
    assert!(!signet.heretical_at(SIGNET_CAT_HEIGHT - 1).cat);
    assert!(signet.heretical_at(SIGNET_CAT_HEIGHT).cat);

    assert!(ChainParams::regtest().heretical_at(0).cat);
    assert_eq!(
        ChainParams::mainnet().heretical_at(1_000_000),
        HereticalFlags::default()
    );
    let mut custom = ChainParams::signet();
    custom.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(
        custom.heretical_at(SIGNET_CAT_HEIGHT),
        HereticalFlags::default()
    );
}

#[test]
fn op_cat_concat_size_and_activation() {
    let tx = bare_tx();
    let on = HereticalFlags { cat: true };
    let script = [0x02, b'a', b'b', 0x02, b'c', b'd', 0x7e];
    let stack = eval_tapscript(&script, on, &tx).expect("cat");
    assert_eq!(stack, vec![b"abcd".to_vec()]);

    let err = eval_tapscript(&[0x7e], on, &tx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s == "stack empty"),
        "{err:?}"
    );

    let mut big = vec![0x4c, 200];
    big.extend(std::iter::repeat_n(0x11, 200));
    big.push(0x4c);
    big.push(200);
    big.extend(std::iter::repeat_n(0x22, 200));
    // 200 + 200 is within 520. A third piece pushes it over.
    big.extend_from_slice(&[0x7e, 0x4c, 121]);
    big.extend(std::iter::repeat_n(0x33, 121));
    big.push(0x7e);
    let err = eval_tapscript(&big, on, &tx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s == "PUSH_SIZE"),
        "{err:?}"
    );

    // Inactive CAT is still OP_SUCCESS: the script succeeds without running.
    let skipped = eval_tapscript(&[0x7e], HereticalFlags::default(), &tx).expect("success");
    assert!(skipped.is_empty());

    let code = Script::from_bytes(&[0x7e]);
    let mut legacy = EvalContext::from_eval_parts(
        &tx,
        0,
        Amount::ZERO,
        code,
        SigVersion::Base,
        true,
        true,
        true,
        Cow::Owned(TxPrecompute::from_tx(&tx)),
    );
    legacy.heretical.cat = true;
    let err = eval_script(code, &mut Vec::new(), &legacy).unwrap_err();
    assert!(
        matches!(err, ConsensusError::Script(ref s) if s.contains("disabled opcode")),
        "{err:?}"
    );
}
