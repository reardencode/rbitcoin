use bitcoin::script::Script;
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;
use rbitcoin_consensus::block::ScriptCheckJob;
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::script::crypto;
use rbitcoin_consensus::script::interpreter::{self};
use rbitcoin_consensus::script::nested::*;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

fn dummy_tx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn p2sh_spk(redeem: &[u8]) -> ScriptBuf {
    let h = crypto::hash160(redeem);
    let mut v = vec![0xa9, 0x14];
    v.extend_from_slice(&h);
    v.push(0x87);
    ScriptBuf::from_bytes(v)
}

fn job_for(tx: Transaction, spk: ScriptBuf, witness_active: bool) -> ScriptCheckJob {
    {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: spk,
        }];
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            witness_active,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    }
}

fn try_nested(
    job: &ScriptCheckJob,
    cache: &mut SighashCache<&Transaction>,
    pre: &rbitcoin_consensus::TxScriptPrecompute,
) -> Option<Result<(), ConsensusError>> {
    let stack = {
        let i = job.inputs().next().unwrap();
        p2sh_script_sig_stack(job, i, &job.tx)
    };
    match stack {
        Err(e) => Some(Err(e)),
        Ok(items) => {
            let i = job.inputs().next().unwrap();
            try_p2sh_nested_segwit(job, i, &job.tx, cache, pre, &items)
        }
    }
}

fn verify_legacy(job: &ScriptCheckJob) -> Result<(), ConsensusError> {
    let stack = {
        let i = job.inputs().next().unwrap();
        p2sh_script_sig_stack(job, i, &job.tx)
    }?;
    {
        let i = job.inputs().next().unwrap();
        verify_p2sh_legacy(job, i, &job.tx, stack)
    }
}

fn stack_for(ss: ScriptBuf) -> Result<Vec<Vec<u8>>, ConsensusError> {
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ss;
    let job = job_for(tx, p2sh_spk(&[0x51]), true);
    {
        let i = job.inputs().next().unwrap();
        p2sh_script_sig_stack(&job, i, &job.tx)
    }
}

#[test]
fn push_only_and_split_helpers() {
    assert_eq!(
        stack_for(ScriptBuf::from_bytes(vec![0x01, 0xaa, 0x01, 0xbb])).unwrap(),
        vec![vec![0xaa], vec![0xbb]]
    );
    assert_eq!(
        stack_for(ScriptBuf::from_bytes(vec![0x51])).unwrap(),
        vec![vec![0x01]]
    );
    assert_eq!(
        stack_for(ScriptBuf::from_bytes(vec![0x02, 0xde, 0xad])).unwrap(),
        vec![vec![0xde, 0xad]]
    );
    assert!(stack_for(ScriptBuf::from_bytes(vec![0x05, 0x01])).is_err());
    assert!(stack_for(ScriptBuf::from_bytes(vec![0xac])).is_err());
    assert_eq!(
        stack_for(ScriptBuf::from_bytes(vec![0x00, 0x4f, 0x51, 0x01, 0xaa])).unwrap(),
        vec![vec![], vec![0x81], vec![0x01], vec![0xaa]]
    );
    let err = stack_for(ScriptBuf::from_bytes(vec![0x61])).unwrap_err();
    assert!(
        format!("{err}").contains("p2sh scriptSig"),
        "shipped BIP16 push-only: {err}"
    );
    assert!(!Script::from_bytes(&[0xac]).is_push_only());
    assert!(Script::from_bytes(&[0x4f, 0x51]).is_push_only());

    let mut items = stack_for(ScriptBuf::from_bytes(vec![0x00, 0x51, 0x01, 0xac])).unwrap();
    let redeem = items.pop().unwrap();
    assert_eq!(items, vec![vec![], vec![0x01]]);
    assert_eq!(redeem, vec![0xac]);
    assert!(stack_for(ScriptBuf::new()).unwrap().is_empty());
}

/// Finding 006: Core MAX_SCRIPT_ELEMENT_SIZE on every P2SH scriptSig push.
#[test]
fn p2sh_scriptsig_push_over_520_rejected() {
    // Redeem = OP_TRUE padded with OP_DROP + 521-byte push inside redeem would be
    // redeem-eval path. Here the **scriptSig push** of redeem itself is 521 bytes.
    let mut redeem = vec![0x51]; // OP_TRUE
    redeem.extend(std::iter::repeat_n(0x61u8, 520)); // pad so len=521
    assert!(redeem.len() > interpreter::MAX_SCRIPT_ELEMENT_SIZE);

    // Minimal encoding of 521-byte push uses PUSHDATA2 (0x4d).
    let mut ss = vec![0x4d];
    ss.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    ss.extend_from_slice(&redeem);

    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);

    let err = verify_legacy(&job).expect_err("PUSH_SIZE");
    let msg = format!("{err}");
    assert!(
        msg.contains("PUSH_SIZE")
            || msg.contains("520")
            || msg.contains("element")
            || msg.contains("push too large"),
        "expected PUSH_SIZE-class error, got {err}"
    );
}

#[test]
fn p2sh_legacy_op_1negate_scriptsig_accepted() {
    let redeem = vec![0x75, 0x51];
    let mut ss = vec![0x4f];
    ss.push(redeem.len() as u8);
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    verify_legacy(&job).expect("OP_1NEGATE is a P2SH push");
}

#[test]
fn p2sh_legacy_scriptsig_over_10k_rejected() {
    let redeem = vec![0x51];
    let mut ss = vec![0x00; 43];
    for _ in 0..131 {
        ss.push(0x4b);
        ss.extend_from_slice(&[0u8; 75]);
    }
    ss.push(redeem.len() as u8);
    ss.extend_from_slice(&redeem);
    assert_eq!(ss.len(), 10_001);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let err = verify_legacy(&job).expect_err("script too large");
    let msg = format!("{err}");
    assert!(
        msg.contains("script too large"),
        "expected script too large, got {msg}"
    );
}

/// Finding 007 (a): non-minimal redeem push → WITNESS_MALLEATED_P2SH.
#[test]
fn p2sh_nested_non_minimal_redeem_push_malleated() {
    let redeem = {
        let mut r = vec![0x00, 0x14];
        r.extend([0xab; 20]);
        r
    };
    // PUSHDATA1 instead of direct OP_PUSHBYTES_22
    let mut ss = vec![0x4c, redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    // Valid witness for shape (still malleated on scriptSig).
    tx.input[0].witness = Witness::from_slice(&[vec![0u8; 64], vec![0x02; 33]]);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let mut cache = SighashCache::new(&*job.tx);
    let r = try_nested(
        &job,
        &mut cache,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx),
    );
    match r {
        Some(Err(e)) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("WITNESS_MALLEATED_P2SH"),
                "expected malleated, got {e}"
            );
        }
        other => panic!("expected Some(Err malleated), got {other:?}"),
    }
}

/// Finding 007 (b): multi-push last = witness program → malleated (not legacy).
#[test]
fn p2sh_nested_multi_push_witness_program_malleated() {
    let redeem = {
        let mut r = vec![0x00, 0x20];
        r.extend([0xcd; 32]);
        r
    };
    let mut ss = vec![0x01, 0xaa];
    ss.push(redeem.len() as u8);
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    // Empty witness — must not succeed via legacy truthy-top.
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let mut cache = SighashCache::new(&*job.tx);
    let r = try_nested(
        &job,
        &mut cache,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx),
    );
    match r {
        Some(Err(e)) => {
            assert!(format!("{e}").contains("WITNESS_MALLEATED_P2SH"), "got {e}");
        }
        other => panic!("expected malleated, got {other:?}"),
    }
    // Full verify_input must not legacy-accept either.
    assert!(rbitcoin_consensus::script::verify_job_all_inputs(&job).is_err());
}

/// Finding 007 (c): v0 wrong-length program → WITNESS_PROGRAM_WRONG_LENGTH.
#[test]
fn p2sh_nested_v0_wrong_length_program_rejected() {
    // 0x00 0x12 <18 bytes> — IsWitnessProgram, not 20/32.
    let redeem = {
        let mut r = vec![0x00, 0x12];
        r.extend([0x11; 18]);
        r
    };
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let mut cache = SighashCache::new(&*job.tx);
    let r = try_nested(
        &job,
        &mut cache,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx),
    );
    match r {
        Some(Err(e)) => {
            assert!(
                format!("{e}").contains("WITNESS_PROGRAM_WRONG_LENGTH"),
                "got {e}"
            );
        }
        other => panic!("expected wrong length, got {other:?}"),
    }
}

/// Pre-segwit: nested gate is off; multi-push/single-push both fall through.
#[test]
fn p2sh_nested_inactive_witness_flag_returns_none() {
    let redeem = {
        let mut r = vec![0x00, 0x14];
        r.extend([0xab; 20]);
        r
    };
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), false);
    let mut cache = SighashCache::new(&*job.tx);
    assert!(
        try_nested(
            &job,
            &mut cache,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx)
        )
        .is_none(),
        "without witness_active nested must not fire"
    );
}

/// Control: multi-push non-witness redeem still falls through to legacy.
#[test]
fn p2sh_legacy_multi_push_non_witness_fallthrough() {
    let redeem = vec![0x51]; // OP_TRUE
    let mut ss = vec![0x01, 0xaa, redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let mut cache = SighashCache::new(&*job.tx);
    assert!(
        try_nested(
            &job,
            &mut cache,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx)
        )
        .is_none(),
        "non-witness multi-push must not enter nested gate"
    );
    assert!(verify_legacy(&job).is_ok());
}

/// Control: v1 program in P2SH + exact scriptSig → ACS success.
#[test]
fn p2sh_nested_v1_program_anyone_can_spend() {
    let redeem = {
        let mut r = vec![0x51, 0x20]; // OP_1 + 32-byte program
        r.extend([0xee; 32]);
        r
    };
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = job_for(tx.clone(), p2sh_spk(&redeem), true);
    let mut cache = SighashCache::new(&*job.tx);
    let r = try_nested(
        &job,
        &mut cache,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx),
    );
    assert!(matches!(r, Some(Ok(()))), "v1-in-P2SH ACS, got {r:?}");
}

#[test]
fn try_nested_error_paths() {
    let mut tx = dummy_tx();
    // Redeem looks like P2WPKH program but wrong outer P2SH hash / spk length
    let redeem = {
        let mut r = vec![0x00, 0x14];
        r.extend([0u8; 20]);
        r
    };
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }];
        let tx = tx.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut cache = SighashCache::new(&*job.tx);
    let r = try_nested(
        &job,
        &mut cache,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx),
    );
    assert!(matches!(r, Some(Err(_))));

    // Wrong redeem hash
    let job2 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&[0xff]),
        }];
        let tx = tx.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut cache2 = SighashCache::new(&*job2.tx);
    assert!(matches!(
        try_nested(
            &job2,
            &mut cache2,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job2.tx)
        ),
        Some(Err(_))
    ));

    // P2WSH redeem shape
    let redeem_wsh = {
        let mut r = vec![0x00, 0x20];
        r.extend([0u8; 32]);
        r
    };
    let mut ss2 = vec![redeem_wsh.len() as u8];
    ss2.extend_from_slice(&redeem_wsh);
    let mut tx3 = dummy_tx();
    tx3.input[0].script_sig = ScriptBuf::from_bytes(ss2);
    let job3 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
        }];
        let tx = tx3.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut c3 = SighashCache::new(&*job3.tx);
    assert!(matches!(
        try_nested(
            &job3,
            &mut c3,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job3.tx)
        ),
        Some(Err(_))
    ));
    // wrong hash
    let job4 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&[0x01]),
        }];
        let tx = tx3.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut c4 = SighashCache::new(&*job4.tx);
    assert!(matches!(
        try_nested(
            &job4,
            &mut c4,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job4.tx)
        ),
        Some(Err(_))
    ));

    // Multi-push non-witness → None (fallthrough)
    let mut tx5 = dummy_tx();
    tx5.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0xaa, 0x01, 0xbb]);
    let job5 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&[0xaa]),
        }];
        let tx = tx5.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut c5 = SighashCache::new(&*job5.tx);
    assert!(try_nested(
        &job5,
        &mut c5,
        &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job5.tx)
    )
    .is_none());

    // Legacy wrong spk / hash / empty
    assert!(verify_legacy(&job3).is_err());
    let mut tx_empty = dummy_tx();
    tx_empty.input[0].script_sig = ScriptBuf::new();
    let job_e = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&[0x51]),
        }];
        let tx = tx_empty.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    assert!(verify_legacy(&job_e).is_err());
    // Hash mismatch on legacy
    let mut tx_leg = dummy_tx();
    tx_leg.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x51]);
    let job_h = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&[0xff]),
        }];
        let tx = tx_leg.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    assert!(verify_legacy(&job_h).is_err());
}

/// Matching outer hash routes into p2wsh/p2wpkh verify (covers scripthash copy path).
#[test]
fn try_nested_matching_hash_enters_witness_verify() {
    let redeem_wsh = {
        let mut r = vec![0x00, 0x20];
        r.extend([0xab; 32]);
        r
    };
    let mut ss = vec![redeem_wsh.len() as u8];
    ss.extend_from_slice(&redeem_wsh);
    let mut tx = dummy_tx();
    tx.input[0].script_sig = ScriptBuf::from_bytes(ss);
    let job = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&redeem_wsh),
        }];
        let tx = tx.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    // Empty witness → p2wsh fails, but nested path reached scripthash copy + call.
    let mut c = SighashCache::new(&*job.tx);
    assert!(matches!(
        try_nested(
            &job,
            &mut c,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx)
        ),
        Some(Err(_))
    ));

    let redeem_wpkh = {
        let mut r = vec![0x00, 0x14];
        r.extend([0xcd; 20]);
        r
    };
    let mut ss2 = vec![redeem_wpkh.len() as u8];
    ss2.extend_from_slice(&redeem_wpkh);
    let mut tx2 = dummy_tx();
    tx2.input[0].script_sig = ScriptBuf::from_bytes(ss2);
    let job2 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&redeem_wpkh),
        }];
        let tx = tx2.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    let mut cache = SighashCache::new(&*job2.tx);
    assert!(matches!(
        try_nested(
            &job2,
            &mut cache,
            &rbitcoin_consensus::TxScriptPrecompute::from_tx(&job2.tx)
        ),
        Some(Err(_))
    ));

    // Legacy OP_TRUE redeem succeeds (require_true_top path).
    let redeem = vec![0x51]; // OP_TRUE
    let mut ss3 = vec![0x01, 0xaa, redeem.len() as u8];
    ss3.extend_from_slice(&redeem);
    // stack push 0xaa + redeem OP_TRUE
    let mut tx3 = dummy_tx();
    tx3.input[0].script_sig = ScriptBuf::from_bytes(ss3);
    let job3 = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2sh_spk(&redeem),
        }];
        let tx = tx3.clone();
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
    };
    assert!(verify_legacy(&job3).is_ok());

    let mut items = stack_for(ScriptBuf::from_bytes(vec![0x00, 0x60, 0x01, 0x51])).unwrap();
    let redeem = items.pop().unwrap();
    assert_eq!(items, vec![vec![], vec![0x10]]);
    assert_eq!(redeem, vec![0x51]);
}

#[test]
fn push_only_scan_rejects_a_truncated_script() {
    assert!(!Script::from_bytes(&[0x4e, 0x01]).is_push_only());
}
