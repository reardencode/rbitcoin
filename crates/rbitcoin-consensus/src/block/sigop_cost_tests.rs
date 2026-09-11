//! sigop_cost_tests (peeled from block.rs).

use super::{
    is_p2sh_script, last_script_push, p2sh_sigop_count, prevout_spk_sigops, script_sigop_count,
    tx_gbt_sigops, tx_sigop_cost, witness_sigop_count,
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

fn spks(prevouts: &[TxOut]) -> Vec<&[u8]> {
    prevouts
        .iter()
        .map(|o| o.script_pubkey.as_bytes())
        .collect()
}

#[test]
fn gbt_sigops_scales_legacy_checksig() {
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
        }],
    };
    assert_eq!(tx_gbt_sigops(&tx), 4);
    let empty = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_eq!(tx_gbt_sigops(&empty), 0);
}

#[test]
fn last_push_pushdata_and_non_push_skip() {
    let mut sc = vec![0x51];
    sc.extend_from_slice(&[0x4c, 0x02, 0xab, 0xcd]);
    assert_eq!(last_script_push(&sc), Some(&[0xabu8, 0xcd][..]));

    let mut sc2 = vec![0x4d, 0x02, 0x00, 0x11, 0x22];
    sc2.extend_from_slice(&[0xac]);
    assert!(last_script_push(&sc2).is_none());

    let sc3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xee];
    assert_eq!(last_script_push(&sc3), Some(&[0xeeu8][..]));

    assert!(last_script_push(&[0x4c, 0x05, 0x01]).is_none());
    assert!(last_script_push(&[0x4e, 0x10, 0x00, 0x00, 0x00]).is_none());
    assert_eq!(last_script_push(&[0x02, 0xaa, 0xbb, 0x51]), Some(&[][..]));
    assert!(is_p2sh_script(&[
        0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87
    ]));
    assert!(!is_p2sh_script(&[0x51]));
}

#[test]
fn p2sh_sigops_non_push_scriptsig_is_zero() {
    let redeem = vec![0xac; 20];
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    ss.push(0x61);
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0u8; 20]);
    p2sh.push(0x87);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    let spk = p2sh.as_slice();
    assert_eq!(p2sh_sigop_count(&tx, &[spk]), 0);
}

#[test]
fn p2sh_and_witness_sigop_paths() {
    // Nested P2SH-P2WPKH: redeem is 0x0014||20, scriptSig last push = redeem.
    let redeem = {
        let mut r = vec![0x00, 0x14];
        r.extend([0x11u8; 20]);
        r
    };
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let p2sh_spk = {
        use bitcoin::hashes::{hash160, Hash};
        let h = hash160::Hash::hash(&redeem);
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(h.as_byte_array());
        spk.push(0x87);
        spk
    };
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x00], vec![0x01; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(p2sh_spk),
    }];
    assert!(witness_sigop_count(&tx, &spks(&prevouts)) >= 1);
    // P2SH bare redeem with CHECKSIG
    let redeem2 = vec![0xac];
    let mut ss2 = vec![0x01];
    ss2.extend_from_slice(&redeem2);
    let mut spk2 = vec![0xa9, 0x14];
    {
        use bitcoin::hashes::{hash160, Hash};
        let h = hash160::Hash::hash(&redeem2);
        spk2.extend_from_slice(h.as_byte_array());
    }
    spk2.push(0x87);
    let tx2 = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([2; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(ss2),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prev2 = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(spk2),
    }];
    assert!(p2sh_sigop_count(&tx2, &spks(&prev2)) >= 1);
    assert!(tx_sigop_cost(&tx2, &spks(&prev2), true, true) >= 4);
    // Nested P2SH without redeem push → continue (0 witness sigops).
    let tx3 = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([3; 32]),
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
    let prev3 = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(vec![
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ]),
    }];
    assert_eq!(witness_sigop_count(&tx3, &spks(&prev3)), 0);
}

#[test]
fn last_push_and_p2sh_shape() {
    // OP_1 push of 0xac (CHECKSIG) as redeem
    let ss = [0x01, 0xac];
    assert_eq!(last_script_push(&ss), Some(&[0xacu8][..]));
    let p2sh = {
        let mut v = vec![0xa9, 0x14];
        v.extend([0u8; 20]);
        v.push(0x87);
        v
    };
    assert!(is_p2sh_script(&p2sh));
    assert!(!is_p2sh_script(&[0x51]));
}

#[test]
fn accurate_multisig_count() {
    // OP_2 <key> <key> <key> OP_3 OP_CHECKMULTISIG → 3 when accurate
    let redeem = vec![
        0x52, // OP_2
        0x21, // push 33
    ];
    let mut r = redeem;
    r.extend([0x02; 33]);
    r.push(0x21);
    r.extend([0x02; 33]);
    r.push(0x21);
    r.extend([0x02; 33]);
    r.push(0x53); // OP_3
    r.push(0xae); // CHECKMULTISIG
    assert_eq!(script_sigop_count(&r, true), 3);
    assert_eq!(script_sigop_count(&r, false), 20);
}

#[test]
fn p2sh_sigops_from_redeem() {
    let mut p2sh_spk = vec![0xa9, 0x14];
    p2sh_spk.extend([0u8; 20]);
    p2sh_spk.push(0x87);
    // redeem = single CHECKSIG
    let redeem = [0xac];
    let mut ss = vec![0x01]; // push 1 byte
    ss.extend_from_slice(&redeem);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
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
    let prevouts = vec![TxOut {
        value: Amount::from_sat(10),
        script_pubkey: ScriptBuf::from_bytes(p2sh_spk),
    }];
    assert_eq!(p2sh_sigop_count(&tx, &spks(&prevouts)), 1);
    // legacy×4 + p2sh×4 = 0 + 4 (no legacy CHECKSIG in ss/spk for bare count of redeem)
    let cost = tx_sigop_cost(&tx, &spks(&prevouts), true, true);
    // scriptSig has push only (0 legacy), output OP_1 (0), p2sh redeem 1×4 = 4
    assert_eq!(cost, 4);
}

#[test]
fn witness_p2wpkh_counts_one() {
    let mut spk = vec![0x00, 0x14];
    spk.extend([0u8; 20]);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([2; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x30], vec![0x02; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(10),
        script_pubkey: ScriptBuf::from_bytes(spk),
    }];
    assert_eq!(witness_sigop_count(&tx, &spks(&prevouts)), 1);
}

#[test]
fn witness_sigops_gated_on_segwit() {
    let mut spk = vec![0x00, 0x14];
    spk.extend([0u8; 20]);
    let inp = TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    assert_eq!(prevout_spk_sigops(&inp, &spk, false, false), 0);
    assert_eq!(prevout_spk_sigops(&inp, &spk, false, true), 1);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![inp],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(10),
        script_pubkey: ScriptBuf::from_bytes(spk),
    }];
    assert_eq!(tx_sigop_cost(&tx, &spks(&prevouts), false, false), 0);
    assert_eq!(tx_sigop_cost(&tx, &spks(&prevouts), false, true), 1);
}

#[test]
fn script_sigop_pushdata_encodings_and_checksigverify() {
    // PUSHDATA1 / 2 / 4 skip payload without counting ops inside.
    let mut s = vec![0x4c, 0x02, 0xac, 0xad]; // push 2 bytes that look like CHECKSIG
    s.push(0xac); // real CHECKSIG after
    assert_eq!(script_sigop_count(&s, false), 1);

    let mut s2 = vec![0x4d, 0x02, 0x00, 0xac, 0xad];
    s2.push(0xad); // CHECKSIGVERIFY
    assert_eq!(script_sigop_count(&s2, false), 1);

    let mut s3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xac];
    s3.push(0xae); // CHECKMULTISIG → 20
    assert_eq!(script_sigop_count(&s3, false), 20);

    // last_script_push with PUSHDATA*
    let lp = vec![0x4c, 0x01, 0xab];
    assert_eq!(last_script_push(&lp), Some(&[0xabu8][..]));
    let lp2 = vec![0x4d, 0x01, 0x00, 0xcd];
    assert_eq!(last_script_push(&lp2), Some(&[0xcdu8][..]));
    let lp3 = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0xef];
    assert_eq!(last_script_push(&lp3), Some(&[0xefu8][..]));
    let _ = (lp, lp2, lp3);
}

#[test]
fn witness_p2wsh_and_nested_p2sh() {
    // Native P2WSH: last witness item is script with CHECKSIG.
    let ws = vec![0xac];
    let scripthash = {
        use bitcoin::hashes::{sha256, Hash};
        *sha256::Hash::hash(&ws).as_byte_array()
    };
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&scripthash);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([3; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x01], ws.clone()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(10),
        script_pubkey: ScriptBuf::from_bytes(spk),
    }];
    assert_eq!(witness_sigop_count(&tx, &spks(&prevouts)), 1);

    // Nested P2SH-P2WPKH: redeem in scriptSig.
    let mut redeem = vec![0x00, 0x14];
    redeem.extend([0u8; 20]);
    let mut ss = vec![redeem.len() as u8];
    ss.extend_from_slice(&redeem);
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend([0u8; 20]);
    p2sh.push(0x87);
    let tx2 = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x30], vec![0x02; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevouts2 = vec![TxOut {
        value: Amount::from_sat(10),
        script_pubkey: ScriptBuf::from_bytes(p2sh),
    }];
    assert_eq!(witness_sigop_count(&tx2, &spks(&prevouts2)), 1);

    // p2sh_sigop prevouts short / non-p2sh skip
    assert_eq!(p2sh_sigop_count(&tx2, &[]), 0);
    assert_eq!(p2sh_sigop_count(&tx2, &[(&[0x51u8][..])]), 0);
    // witness_sigop missing prevout
    assert_eq!(witness_sigop_count(&tx, &[]), 0);
}

#[test]
fn verify_one_script_job_skips_anyone_can_spend() {
    use super::{verify_one_script_job, ScriptCheckJob};
    let job = ScriptCheckJob::new(
        vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]), // OP_TRUE ACS
        }],
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9; 32]),
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
        },
        crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    assert!(verify_one_script_job(&job).is_ok());
}

#[test]
fn job_tx_traits_and_shared_mut_panic() {
    use super::{block_subsidy, is_anyone_can_spend, is_final_tx, JobTx};
    use crate::params::ChainParams;
    use bitcoin::block::{Header, Version};
    use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode};
    use std::borrow::Borrow;
    use std::sync::Arc;

    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let owned: JobTx = tx.clone().into();
    assert_eq!(owned.as_ref().output.len(), 1);
    assert_eq!(Borrow::<Transaction>::borrow(&owned).output.len(), 1);
    let mut owned_mut = JobTx::owned(tx.clone());
    assert_eq!(owned_mut.output.len(), 1);
    owned_mut.output[0].value = Amount::from_sat(2); // DerefMut owned

    // Minimal block shell for shared JobTx.
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let block = Arc::new(Block {
        header,
        txdata: vec![
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            },
            tx.clone(),
        ],
    });
    let shared = JobTx::shared(Arc::clone(&block), 1);
    assert_eq!(shared.as_ref().output.len(), 1);
    let mut shared_mut = JobTx::shared(block, 1);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = &mut shared_mut.output;
    }));
    assert!(r.is_err(), "shared JobTx must panic on DerefMut");

    let p = ChainParams::mainnet();
    assert_eq!(block_subsidy(0, &p), 50 * 100_000_000);
    assert_eq!(block_subsidy(210_000, &p), 25 * 100_000_000);
    assert_eq!(block_subsidy(6_930_000, &p), 0);
    assert!(is_anyone_can_spend(
        ScriptBuf::from_bytes(vec![0x51]).as_script()
    ));
    assert!(!is_anyone_can_spend(
        ScriptBuf::from_bytes(vec![0x00]).as_script()
    ));
    let final_tx = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    assert!(is_final_tx(&final_tx, 0, 0));
}
