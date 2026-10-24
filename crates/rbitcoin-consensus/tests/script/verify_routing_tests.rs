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
    {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
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
            witness_active: true,
            discourage_upgradable_witness: false,
            const_scriptcode: false,
            cleanstack: false,
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
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
    let pre = std::sync::Arc::new(rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx));
    let wscript = bitcoin::script::Script::from_bytes(&[0x51]);
    let ours = {
        let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::script::ScriptBuf::new(),
                };
                tx.input.len()
            ],
            tx.clone(),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let i = _idx_job.inputs().next().unwrap();
        crypto::bip143_p2wsh_signature_hash(
            &tx,
            i,
            wscript,
            Amount::from_sat(50_000),
            0x01,
            pre.as_ref(),
        )
    }
    .unwrap();
    let mut cache = SighashCache::new(&tx);
    let theirs = cache
        .p2wsh_signature_hash(0, wscript, Amount::from_sat(50_000), EcdsaSighashType::All)
        .unwrap()
        .to_byte_array();
    assert_eq!(ours, theirs);
    let pres: std::sync::Arc<[rbitcoin_consensus::TxPrecompute]> =
        std::sync::Arc::from([rbitcoin_consensus::TxPrecompute::Script((*pre).clone())]);
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
    let e = {
        let i = job.inputs().next().unwrap();
        annotate_script_err(ConsensusError::MissingPrevout, &job, i)
    };
    assert!(matches!(e, ConsensusError::MissingPrevout));
    let e2 = {
        let i = job.inputs().next().unwrap();
        annotate_script_err(
            ConsensusError::Script("already txid=abc vin=0".into()),
            &job,
            i,
        )
    };
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
    let job = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }];
        let tx = Transaction {
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
        };
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
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

    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx);

    // All / Single / None + AnyoneCanPay variants.
    for ty in [0x01u32, 0x02, 0x03, 0x81, 0x82, 0x83] {
        let h = {
            let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
                vec![
                    bitcoin::TxOut {
                        value: bitcoin::Amount::ZERO,
                        script_pubkey: bitcoin::script::ScriptBuf::new(),
                    };
                    tx.input.len()
                ],
                tx.clone(),
                rbitcoin_consensus::block::ScriptVerifyFlags::buried(
                    false, false, false, false, false,
                ),
            );
            let i = _idx_job.inputs().next().unwrap();
            crypto::bip143_signature_hash(&tx, i, sc, amt, ty, &pre)
        }
        .expect("sighash");
        assert_ne!(h, [0u8; 32]);
    }
    // Single at index with matching output (input 1 → output 1).
    let h_single = {
        let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::script::ScriptBuf::new(),
                };
                tx.input.len()
            ],
            tx.clone(),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let i = _idx_job.inputs().nth(1).unwrap();
        crypto::bip143_signature_hash(&tx, i, sc, amt, 0x03, &pre)
    }
    .unwrap();
    // Single with no matching output (only 2 outs; index 1 ok; use 1-input for zero outputs arm).
    let tx1 = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx.input[0].clone()],
        output: vec![],
    };
    let pre1 = rbitcoin_consensus::TxScriptPrecompute::from_tx(&tx1);
    let h_none_out = {
        let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::script::ScriptBuf::new(),
                };
                tx1.input.len()
            ],
            tx1.clone(),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let i = _idx_job.inputs().next().unwrap();
        crypto::bip143_signature_hash(&tx1, i, sc, amt, 0x03, &pre1)
    }
    .unwrap();
    assert_ne!(h_single, h_none_out);

    // Non-standard raw type 0x65 uses the same midstates + raw nHashType.
    let wscript = Script::from_bytes(&[0x51]);
    let h_fast = {
        let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::script::ScriptBuf::new(),
                };
                tx.input.len()
            ],
            tx.clone(),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let i = _idx_job.inputs().next().unwrap();
        crypto::bip143_p2wsh_signature_hash(&tx, i, wscript, amt, 0x01, &pre)
    }
    .unwrap();
    let h_slow = {
        let _idx_job = rbitcoin_consensus::block::ScriptCheckJob::new(
            vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::script::ScriptBuf::new(),
                };
                tx.input.len()
            ],
            tx.clone(),
            rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, false, false),
        );
        let i = _idx_job.inputs().next().unwrap();
        crypto::bip143_p2wsh_signature_hash(&tx, i, wscript, amt, 0x65, &pre)
    }
    .unwrap();
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
    let inputs: Vec<_> = job.inputs().collect();
    for annex in [None, Some(&annex_bytes[..])] {
        for input_index in inputs.iter().copied() {
            let vin = input_index.get();
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
                    vin,
                    &Prevouts::All(&prevouts),
                    annex_oracle.clone(),
                    None,
                    ty,
                );
                match key_oracle {
                    Ok(h) => assert_eq!(
                        key_ours.expect("key path"),
                        h.to_byte_array(),
                        "key vin={vin} {ty:?} annex={annex:?}"
                    ),
                    Err(_) => assert!(
                        key_ours.is_err(),
                        "key vin={vin} {ty:?}: rust-bitcoin rejects, ours accepts"
                    ),
                }
                for codesep in [0xFFFF_FFFF, 0, 7] {
                    let ours = exec.signature_hash(ty, codesep);
                    let oracle = SighashCache::new(&tx).taproot_signature_hash(
                        vin,
                        &Prevouts::All(&prevouts),
                        annex_oracle.clone(),
                        Some((leaf_hash, codesep)),
                        ty,
                    );
                    match oracle {
                        Ok(h) => assert_eq!(
                            ours.expect("ours"),
                            h.to_byte_array(),
                            "vin={vin} {ty:?} codesep={codesep} annex={annex:?}"
                        ),
                        Err(_) => assert!(
                            ours.is_err(),
                            "vin={vin} {ty:?}: rust-bitcoin rejects, ours accepts"
                        ),
                    }
                }
            }
        }
    }
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
    let job = {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(p2sh),
        }];
        let tx = Transaction {
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
        };
        let flags = rbitcoin_consensus::block::ScriptVerifyFlags {
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
        };
        ScriptCheckJob::with_txid(txid, prevouts, tx, flags)
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
    assert!({
        let i = job.inputs().next().unwrap();
        verify_bare(&job, i, &job.tx)
    }
    .is_ok());

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
    assert!({
        let i = job.inputs().next().unwrap();
        verify_bare(&job, i, &job.tx)
    }
    .is_err());
}

/// A wire slot past the parent output count fails when the job is built.
#[test]
fn wire_vout_past_n_out_is_missing_prevout() {
    use bitcoin::block::{Header, Version};
    use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
    use std::sync::Arc;

    let parent = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let spend = Transaction {
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
    let block = Arc::new(Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![parent, spend],
    });
    let flags =
        rbitcoin_consensus::block::ScriptVerifyFlags::buried(false, false, false, true, true);
    let built = ScriptCheckJob::try_from_parts(
        [0u8; 32],
        rbitcoin_consensus::block::JobPrevouts::Shared(vec![
            rbitcoin_consensus::block::SharedPrevout::Wire {
                tx_index: 0,
                vout: 1,
            },
        ]),
        rbitcoin_consensus::block::JobTx::shared(Arc::clone(&block), 1),
        flags,
    );
    let Err(err) = built else {
        panic!("vout past n_out");
    };
    assert!(matches!(err, ConsensusError::MissingPrevout), "{err}");
    assert_eq!(
        rbitcoin_consensus::block_reject_reason(&err),
        "bad-txns-inputs-missingorspent"
    );

    let job = ScriptCheckJob::try_from_parts(
        [0u8; 32],
        rbitcoin_consensus::block::JobPrevouts::Shared(vec![
            rbitcoin_consensus::block::SharedPrevout::Wire {
                tx_index: 0,
                vout: 0,
            },
        ]),
        rbitcoin_consensus::block::JobTx::shared(block, 1),
        flags,
    )
    .expect("in-range wire vout");
    let i = job.inputs().next().expect("one input");
    let (value, script) = job.prevout_parts(i).expect("resolved wire prevout");
    assert_eq!(value, 50);
    assert_eq!(script, &[0x51]);
}
