use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use rbitcoin_consensus::block::ScriptCheckJob;
use rbitcoin_consensus::error::ConsensusError;
use rbitcoin_consensus::script::*;

use bitcoin::absolute::LockTime;

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

fn witness_job(spk: Vec<u8>, script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> ScriptCheckJob {
    let refs: Vec<&[u8]> = witness.iter().map(|v| v.as_slice()).collect();
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&refs),
        }],
        output: vec![],
    };
    ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }]),
        tx: rbitcoin_consensus::block::JobTx::owned(tx),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
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
            heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
        },
        pre: std::sync::OnceLock::new(),
    }
}

#[test]
fn false_witness_program_is_eval_false() {
    let native = witness_job(vec![0x52, 0x02, 0x00, 0x00], vec![], vec![]);
    let err = verify_job_all_inputs(&native).expect_err("zero program");
    assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");

    let neg = witness_job(vec![0x60, 0x03, 0x00, 0x00, 0x80], vec![], vec![]);
    let err = verify_job_all_inputs(&neg).expect_err("negative zero");
    assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");

    let live = witness_job(vec![0x52, 0x02, 0x00, 0x01], vec![], vec![]);
    verify_job_all_inputs(&live).expect("nonzero unknown version");

    let redeem = vec![0x52, 0x02, 0x00, 0x00];
    let hash = rbitcoin_consensus::script::crypto::hash160(&redeem);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(hash.as_slice());
    spk.push(0x87);
    let mut script_sig = vec![redeem.len() as u8];
    script_sig.extend_from_slice(&redeem);
    let nested = witness_job(spk, script_sig, vec![]);
    let err = verify_job_all_inputs(&nested).expect_err("p2sh zero program");
    assert!(format!("{err}").contains("EVAL_FALSE"), "{err}");
}

#[test]
fn prevout_count_must_match_inputs() {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![]),
        tx: rbitcoin_consensus::block::JobTx::owned(tx),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags::buried(true, true, true, true, true),
        pre: std::sync::OnceLock::new(),
    };
    let err = verify_job_all_inputs(&job).expect_err("empty prevouts");
    assert!(format!("{err}").contains("prevout count"), "{err}");
}

#[test]
fn empty_prevouts_and_index_errors() {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![]),
        tx: rbitcoin_consensus::block::JobTx::owned(tx.clone()),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
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
            heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
        },
        pre: std::sync::OnceLock::new(),
    };
    assert!(verify_job_all_inputs(&job).is_ok());

    let job2 = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }]),
        tx: rbitcoin_consensus::block::JobTx::owned(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        }),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
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
            heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
        },
        pre: std::sync::OnceLock::new(),
    };
    let cache = bitcoin::sighash::SighashCache::new(&*job2.tx);
    let pre = rbitcoin_consensus::TxPrecompute::from_tx(&job2.tx);
    let mut cache_slot = Some(cache);
    let tap_spent = crypto::TapSpentHashes::default();
    assert!(verify_input(&job2, 0, &job2.tx, &mut cache_slot, &pre, &tap_spent).is_err());
}

#[test]
fn verify_job_uses_stashed_pre_for_bip143() {
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x30; 71], vec![0x51]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let pre = std::sync::Arc::new(rbitcoin_consensus::TxPrecompute::from_tx(&tx));
    let wscript = bitcoin::script::Script::from_bytes(&[0x51]);
    let ours = crypto::bip143_p2wsh_signature_hash(
        &tx,
        0,
        wscript,
        Amount::from_sat(50_000),
        0x01,
        pre.as_ref(),
    )
    .unwrap();
    let mut cache = SighashCache::new(&tx);
    let theirs = cache
        .p2wsh_signature_hash(0, wscript, Amount::from_sat(50_000), EcdsaSighashType::All)
        .unwrap()
        .to_byte_array();
    assert_eq!(ours, theirs);
    let pres: std::sync::Arc<[rbitcoin_consensus::TxPrecompute]> =
        std::sync::Arc::from([(*pre).clone()]);
    let job = ScriptCheckJob::with_txid(
        pre.txid,
        vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(
                vec![0x00, 0x20].into_iter().chain([0; 32]).collect(),
            ),
        }],
        tx,
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(true, true, true, true, true),
    )
    .with_pre_slice(pres, 0);
    assert_eq!(job.pre().txid, job.txid);
}

#[test]
fn from_tx_connect_bip143_fails_closed_without_midstate() {
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let pre = rbitcoin_consensus::TxPrecompute::from_tx_connect(&tx);
    let wscript = bitcoin::script::Script::from_bytes(&[0x51]);
    let amt = Amount::from_sat(50_000);
    let err = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x01, &pre)
        .expect_err("connect-only precompute must not sighash");
    let msg = err.to_string();
    assert!(
        msg.contains("invariant: sighash midstate missing"),
        "got: {msg}"
    );
}

#[test]
fn annotate_preserves_non_script_and_existing_txid() {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([2; 32]),
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
    };
    let job = ScriptCheckJob::new(
        vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        tx,
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    let e = annotate_script_err(ConsensusError::MissingPrevout, &job, 0);
    assert!(matches!(e, ConsensusError::MissingPrevout));
    let e2 = annotate_script_err(
        ConsensusError::Script("already txid=abc vin=0".into()),
        &job,
        3,
    );
    match e2 {
        ConsensusError::Script(m) => assert_eq!(m, "already txid=abc vin=0"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn taproot_inactive_is_anyone_can_spend() {
    let mut spk = vec![0x51, 0x20];
    spk.extend([0u8; 31]);
    spk.push(1);
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }]),
        tx: rbitcoin_consensus::block::JobTx::owned(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([3; 32]),
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
        }),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
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
            cleanstack: false,
            heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
        },
        pre: std::sync::OnceLock::new(),
    };
    verify_job_all_inputs(&job).expect("pre-taproot v1 ACS");
}

#[test]
fn p2pkh_shape_error_detection() {
    assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
        "p2pkh scriptSig len".into()
    )));
    assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
        "p2pkh scriptSig".into()
    )));
    assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
        "p2pkh scriptSig op".into()
    )));
    assert!(p2pkh_scriptsig_shape_error(&ConsensusError::Script(
        "p2pkh scriptSig unexpected op".into()
    )));
    assert!(!p2pkh_scriptsig_shape_error(&ConsensusError::Script(
        "p2pkh ecdsa".into()
    )));
    assert!(!p2pkh_scriptsig_shape_error(
        &ConsensusError::MissingPrevout
    ));
}

#[test]
fn bip143_sighash_arms_single_acp_and_p2wsh() {
    use bitcoin::script::Script;
    use bitcoin::Amount;

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2; 32]),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(1),
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            },
        ],
    };
    let sc = Script::from_bytes(&[0x51]);
    let amt = Amount::from_sat(50_000);

    let pre = rbitcoin_consensus::TxPrecompute::from_tx(&tx);
    assert!(crypto::bip143_signature_hash(&tx, 9, sc, amt, 0x01, &pre).is_err());

    // All / Single / None + AnyoneCanPay variants.
    for ty in [0x01u32, 0x02, 0x03, 0x81, 0x82, 0x83] {
        let h = crypto::bip143_signature_hash(&tx, 0, sc, amt, ty, &pre).expect("sighash");
        assert_ne!(h, [0u8; 32]);
    }
    // Single at index with matching output (input 1 → output 1).
    let h_single = crypto::bip143_signature_hash(&tx, 1, sc, amt, 0x03, &pre).unwrap();
    // Single with no matching output (only 2 outs; index 1 ok; use 1-input for zero outputs arm).
    let tx1 = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx.input[0].clone()],
        output: vec![],
    };
    let pre1 = rbitcoin_consensus::TxPrecompute::from_tx(&tx1);
    let h_none_out = crypto::bip143_signature_hash(&tx1, 0, sc, amt, 0x03, &pre1).unwrap();
    assert_ne!(h_single, h_none_out);

    // Non-standard raw type 0x65 uses the same midstates + raw nHashType.
    let wscript = Script::from_bytes(&[0x51]);
    let h_fast = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x01, &pre).unwrap();
    let h_slow = crypto::bip143_p2wsh_signature_hash(&tx, 0, wscript, amt, 0x65, &pre).unwrap();
    assert_ne!(h_fast, [0u8; 32]);
    assert_ne!(h_slow, [0u8; 32]);
    // Standard and non-standard types must differ (raw_ty in digest).
    assert_ne!(h_fast, h_slow);
}

/// Tapscript and key-path sighash from borrowed prevout scripts matches
/// rust-bitcoin's `taproot_signature_hash` on every BIP341 hash type.
#[test]
fn tapscript_sighash_matches_rust_bitcoin_on_every_hash_type() {
    use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::LeafVersion;
    use bitcoin::TapLeafHash;

    let outpoint = |n: u8| OutPoint {
        txid: bitcoin::Txid::from_byte_array([n; 32]),
        vout: u32::from(n),
    };
    let input = |n: u8| TxIn {
        previous_output: outpoint(n),
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_fff0 - u32::from(n)),
        witness: Witness::new(),
    };
    let output = |n: u8| TxOut {
        value: Amount::from_sat(1_000 * u64::from(n)),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51; usize::from(n)]),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_consensus(500),
        input: vec![input(1), input(2), input(3)],
        output: vec![output(4), output(5)],
    };
    let prevouts = vec![output(6), output(7), output(8)];
    let leaf = ScriptBuf::from_bytes(vec![0x51, 0x75, 0x51]);
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let annex_bytes = [0x50, 0x01, 0x02];
    let types = [
        TapSighashType::Default,
        TapSighashType::All,
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ];
    let flags = rbitcoin_consensus::block::ScriptVerifyFlags::buried(true, true, true, true, true);
    let job = rbitcoin_consensus::block::ScriptCheckJob::new(prevouts.clone(), tx.clone(), flags);

    let tap_spent = crypto::TapSpentHashes::default();
    for annex in [None, Some(&annex_bytes[..])] {
        for input_index in 0..tx.input.len() {
            let exec =
                crypto::TapscriptExecData::new(&job, input_index, &tap_spent, leaf_hash, annex);
            let annex_oracle = annex.map(|a| Annex::new(a).unwrap());
            let annex_hash = annex.map(crypto::annex_hash);
            for ty in types {
                let single = std::cell::OnceCell::new();
                let key_ours = crypto::tap_signature_hash(
                    &job,
                    input_index,
                    ty,
                    &tap_spent,
                    annex_hash,
                    None,
                    &single,
                );
                let key_oracle = SighashCache::new(&tx).taproot_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    annex_oracle.clone(),
                    None,
                    ty,
                );
                match key_oracle {
                    Ok(h) => assert_eq!(
                        key_ours.expect("key path"),
                        h.to_byte_array(),
                        "key vin={input_index} {ty:?} annex={annex:?}"
                    ),
                    Err(_) => assert!(
                        key_ours.is_err(),
                        "key vin={input_index} {ty:?}: rust-bitcoin rejects, ours accepts"
                    ),
                }
                for codesep in [0xFFFF_FFFF, 0, 7] {
                    let ours = exec.signature_hash(ty, codesep);
                    let oracle = SighashCache::new(&tx).taproot_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        annex_oracle.clone(),
                        Some((leaf_hash, codesep)),
                        ty,
                    );
                    match oracle {
                        Ok(h) => assert_eq!(
                            ours.expect("ours"),
                            h.to_byte_array(),
                            "vin={input_index} {ty:?} codesep={codesep} annex={annex:?}"
                        ),
                        Err(_) => assert!(
                            ours.is_err(),
                            "vin={input_index} {ty:?}: rust-bitcoin rejects, ours accepts"
                        ),
                    }
                }
            }
        }
    }

    let short_job =
        rbitcoin_consensus::block::ScriptCheckJob::new(prevouts[..2].to_vec(), tx.clone(), flags);
    let tap_spent = crypto::TapSpentHashes::default();
    let exec = crypto::TapscriptExecData::new(&short_job, 0, &tap_spent, leaf_hash, None);
    assert!(exec.signature_hash(TapSighashType::Default, 0).is_err());
}

#[test]
fn bip16_inactive_treats_p2sh_as_bare() {
    // P2SH template spent as bare HASH160/EQUAL when bip16 off.
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend([0u8; 20]);
    p2sh.push(0x87);
    // scriptSig that just pushes 20 zero bytes (equal fails — but exercises bare path)
    let mut ss = vec![0x14];
    ss.extend([0u8; 20]);
    let job = ScriptCheckJob {
        txid: [0u8; 32],
        prevouts: rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(p2sh),
        }]),
        tx: rbitcoin_consensus::block::JobTx::owned(Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([4; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }),
        flags: rbitcoin_consensus::block::ScriptVerifyFlags {
            bip65_active: false,
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
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
            heretical: rbitcoin_consensus::heretical::HereticalFlags::default(),
        },
        pre: std::sync::OnceLock::new(),
    };
    // Bare HASH160 equal of zeros vs hash160([]) — should fail script, not p2sh redeem.
    let err = verify_job_all_inputs(&job).unwrap_err();
    assert!(matches!(err, ConsensusError::Script(_)));
}

/// Fast path and interpreter agree on a real P2PKH signature, and both
/// reject the only push that `FindAndDelete` could remove from the
/// 25-byte template (the 20-byte pubkey hash). That stack item is not a
/// verifying signature, so the different sighash is not a chain split.
#[test]
fn p2pkh_fast_path_matches_interpreter_including_hash_collision() {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let spk = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(&pk.to_bytes()));
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: spk.clone(),
    };
    let shell = Transaction {
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
    let sighash = SighashCache::new(&shell)
        .legacy_signature_hash(0, spk.as_script(), EcdsaSighashType::All as u32)
        .unwrap();
    let mut sig = secp
        .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk)
        .serialize_der()
        .to_vec();
    sig.push(EcdsaSighashType::All as u8);
    let mut script_sig = Vec::new();
    script_sig.push(sig.len() as u8);
    script_sig.extend_from_slice(&sig);
    script_sig.push(pk.to_bytes().len() as u8);
    script_sig.extend_from_slice(&pk.to_bytes());
    let mut good = shell.clone();
    good.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
    let flags =
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, true, true, false);
    let job = ScriptCheckJob::new(vec![prevout.clone()], good, flags);
    assert!(verify_job_all_inputs(&job).is_ok());
    assert!(verify_bare(&job, 0, &job.tx).is_ok());

    let keyhash = bitcoin::PubkeyHash::hash(&pk.to_bytes());
    let mut bad_sig = Vec::new();
    bad_sig.push(20);
    bad_sig.extend_from_slice(keyhash.as_byte_array());
    bad_sig.push(pk.to_bytes().len() as u8);
    bad_sig.extend_from_slice(&pk.to_bytes());
    let mut bad = shell;
    bad.input[0].script_sig = ScriptBuf::from_bytes(bad_sig);
    let job = ScriptCheckJob::new(vec![prevout], bad, flags);
    assert!(verify_job_all_inputs(&job).is_err());
    assert!(verify_bare(&job, 0, &job.tx).is_err());
}

#[test]
fn tap_sighash_rejects_a_bad_index_and_a_prevout_count_mismatch() {
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
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let prevout = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let flags =
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, true, true);
    let job = ScriptCheckJob::new(vec![prevout.clone()], tx.clone(), flags);
    let spent = crypto::TapSpentHashes::default();
    let single = std::cell::OnceCell::new();
    let err = crypto::tap_signature_hash(
        &job,
        3,
        bitcoin::sighash::TapSighashType::Default,
        &spent,
        None,
        None,
        &single,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("sighash input"), "{err}");

    let mismatch = ScriptCheckJob::new(vec![prevout.clone(), prevout], tx, flags);
    let err = crypto::tap_signature_hash(
        &mismatch,
        0,
        bitcoin::sighash::TapSighashType::Default,
        &spent,
        None,
        None,
        &single,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("sighash prevouts"), "{err}");
}
