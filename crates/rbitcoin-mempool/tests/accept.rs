use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use rbitcoin_consensus::policy::{self};
use rbitcoin_mempool::accept::*;
use rbitcoin_mempool::error::MempoolError;
use rbitcoin_mempool::graph::{MAX_CLUSTER_COUNT, MAX_CLUSTER_VSIZE, MAX_CLUSTER_WEIGHT};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn tmp_dir() -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled("mempool-accept").unwrap()
}

/// Tip high enough that maturity/finality/BIP68 do not block normal test txs.
const TIP_OK: ChainTipCtx = ChainTipCtx {
    height: 1_000_000,
    mtp: u32::MAX,
};

fn coin(txout: TxOut) -> Coin {
    Coin {
        txout,
        // Height 0 is the genesis coinbase. A resolved non-coinbase is later.
        create_height: 1,
        create_mtp: 0,
        is_coinbase: false,
        create_fk: None,
    }
}

fn chain_utxo(value: u64) -> (OutPoint, TxOut, MapUtxoProvider) {
    let op = OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: 0,
    };
    let txout = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let mut map = HashMap::new();
    map.insert(op, coin(txout.clone()));
    (op, txout, MapUtxoProvider { map })
}

/// Several chain coins in one map. `chain_utxo` always uses vout 0, so a
/// second call is the same outpoint.
fn chain_coins(values: &[u64]) -> (Vec<OutPoint>, MapUtxoProvider) {
    let mut map = HashMap::new();
    let mut ops = Vec::with_capacity(values.len());
    for (i, &value) in values.iter().enumerate() {
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: i as u32,
        };
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        map.insert(op, coin(txout));
        ops.push(op);
    }
    (ops, MapUtxoProvider { map })
}

/// Finding 011: absolute nLockTime height form not final at tip+1.
#[test]
fn reject_non_final_locktime_height() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    // Height lock: need block_height > 500; tip.height+1 = 101 → not final.
    tx.lock_time = LockTime::from_height(500).unwrap();
    // Non-final sequence so locktime is enforced.
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let tip = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
    assert!(matches!(err, AcceptError::NotFinal), "got {err}");
    // At tip 500, next height 501 > 500 → final.
    let tip2 = ChainTipCtx {
        height: 500,
        mtp: u32::MAX,
    };
    mp.accept_tx(&tx, &utxos, tip2).expect("final at tip 500");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Finding 011: immature coinbase spend rejected.
#[test]
fn reject_immature_coinbase() {
    let dir = tmp_dir();
    let op = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        Coin {
            txout: TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 50,
            create_mtp: 0,
            is_coinbase: true,
            create_fk: None,
        },
    );
    let utxos = MapUtxoProvider { map };
    let tx = spend_tx(op, 49_0000_0000);
    // tip 100 → next 101; need create+100 = 150.
    let tip = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
    assert!(matches!(err, AcceptError::ImmatureCoinbase), "got {err}");
    let tip2 = ChainTipCtx {
        height: 149,
        mtp: u32::MAX,
    };
    mp.accept_tx(&tx, &utxos, tip2)
        .expect("mature at tip 149 (next=150)");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bip68_time_lock_uses_coin_create_mtp() {
    let dir = tmp_dir();
    let op = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        Coin {
            txout: TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 10,
            create_mtp: 1_000_000,
            is_coinbase: false,
            create_fk: None,
        },
    );
    let utxos = MapUtxoProvider { map };
    let mut tx = spend_tx(op, 49_000);
    tx.version = Version::TWO;
    // Time-type relative lock of 2 units (2 << 9 = 1024 seconds).
    tx.input[0].sequence = Sequence::from_consensus((1 << 22) | 2);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    // prev MTP 1_000_000 + 1024 - 1 = 1_001_023; tip MTP 1_001_000 → not final.
    let err = mp
        .accept_tx(
            &tx,
            &utxos,
            ChainTipCtx {
                height: 20,
                mtp: 1_001_000,
            },
        )
        .unwrap_err();
    assert!(matches!(err, AcceptError::NonBip68Final), "got {err}");
    mp.accept_tx(
        &tx,
        &utxos,
        ChainTipCtx {
            height: 20,
            mtp: 1_002_000,
        },
    )
    .expect("time lock satisfied");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stage timers are recorded on a successful chain-spend accept.
#[test]
fn accept_records_stage_us_on_success() {
    let dir = tmp_dir();
    let (op, _txout, utxos) = chain_utxo(50_000);
    let tx = spend_tx(op, 49_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK).expect("accept");
    let s = mp.last_accept_stages;
    // Detached script hop + durable append should register µs on typical hosts.
    assert!(
        s.script_us > 0 || s.durable_us > 0 || s.utxo_us > 0,
        "expected non-zero stage sample, got {s:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The rolling floor starts at the configured minimum. A lower
/// `-minrelaytxfee` is the advertised floor. An eviction that already
/// raised the rolling floor stays above that new minimum.
#[test]
fn lowered_min_relay_is_the_fee_floor_until_eviction() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(
        mp.mempool_min_fee_sat_kvb(),
        policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB
    );
    mp.set_min_relay_sat_kvb(10);
    assert_eq!(mp.mempool_min_fee_sat_kvb(), 10);
    mp.rolling_min_sat_kvb = 5_000;
    mp.set_min_relay_sat_kvb(10);
    assert_eq!(mp.mempool_min_fee_sat_kvb(), 5_000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mempool_under_pressure() {
    assert_eq!(decayed_relay_floor(5_000, 100, 0), 5_000);
    assert_eq!(
        decayed_relay_floor(5_000, 100, ROLLING_FEE_HALFLIFE_MS),
        100 + ((5_000 - 100) >> 1)
    );
    assert_eq!(
        relay_floor(100, 5_000, 0, ROLLING_FEE_HALFLIFE_MS, true),
        5_000
    );
    assert_eq!(
        relay_floor(100, 5_000, 0, ROLLING_FEE_HALFLIFE_MS, false),
        100 + ((5_000 - 100) >> 1)
    );
    assert_eq!(
        decayed_relay_floor(5_000, 100, 2 * ROLLING_FEE_HALFLIFE_MS),
        100 + ((5_000 - 100) >> 2)
    );
    assert_eq!(
        decayed_relay_floor(u64::MAX, 100, 63 * ROLLING_FEE_HALFLIFE_MS),
        100
    );
    assert_eq!(ROLLING_FEE_HALFLIFE_MS, 43_200_000);
    assert!(unix_ms() > 1_700_000_000_000);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(10_000_000);
    let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 800).unwrap();
    let before = mp.mempool_min_fee_sat_kvb();
    assert!(before > policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB);
    for i in 0u8..8 {
        let spend = OutPoint {
            txid: Txid::from_byte_array([i.wrapping_add(1); 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            spend,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
        let out = 99_000u64 - u64::from(i) * 100;
        mp.accept_tx(&spend_tx(spend, out), &MapUtxoProvider { map }, TIP_OK)
            .unwrap_or_else(|e| panic!("i={i}: {e}"));
    }
    let after = mp.mempool_min_fee_sat_kvb();
    assert!(
        after > before,
        "eviction must raise the floor above the static bump ({before} -> {after})"
    );
    let probe_op = OutPoint {
        txid: Txid::from_byte_array([0xee; 32]),
        vout: 0,
    };
    let probe = spend_tx(probe_op, 99_000);
    let vsize = bitcoin::Weight::from_wu(probe.weight().to_wu()).to_vbytes_ceil();
    let fee = vsize.saturating_mul(before).div_ceil(1_000);
    let tx = spend_tx(probe_op, 100_000 - fee);
    let mut map = HashMap::new();
    map.insert(
        probe_op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }),
    );
    let err = mp
        .accept_tx(&tx, &MapUtxoProvider { map }, TIP_OK)
        .expect_err("same static-bump rate must not re-enter");
    assert!(
        matches!(
            err,
            AcceptError::Policy("mempool min fee") | AcceptError::Policy("min relay fee")
        ),
        "{err}"
    );

    mp.max_weight = mp
        .graph
        .total_weight()
        .saturating_add(policy::MAX_STANDARD_TX_WEIGHT);
    mp.rolling_min_sat_kvb = 5_000;
    mp.rolling_updated_ms = 0;
    mp.min_relay_sat_kvb = 100;
    assert_eq!(
        mp.mempool_min_fee_sat_kvb(),
        100,
        "one more standard tx exactly filling must let the floor decay"
    );

    mp.max_weight = policy::MAX_STANDARD_TX_WEIGHT.saturating_mul(64);
    // 4001 legacy CHECKSIG × witness scale 4 = 16004, over Core's 16000
    // standard cap. The tx fits the mempool's block-template sigop budget.
    let sigops = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0xac; 4_001]),
        }],
    };
    mp.accept_tx(&sigops, &utxos, TIP_OK)
        .expect("16004 sigop cost fits a block");
    assert_eq!(
        mp.graph
            .get(&sigops.compute_txid())
            .map(|entry| entry.sigop_cost),
        Some(16_004)
    );

    mp.set_cluster_limits(Some(50), Some(1));
    let mut wide = spend_tx(op, 9_000_000);
    wide.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 4_000]);
    let err = mp.accept_tx(&wide, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::ClusterTooLarge { .. }), "{err}");

    mp.set_cluster_limits(Some(2), None);
    let tx1 = spend_tx(op, 9_000_000);
    mp.accept_tx(&tx1, &utxos, TIP_OK).unwrap();
    let tx2 = spend_tx(
        OutPoint {
            txid: tx1.compute_txid(),
            vout: 0,
        },
        8_000_000,
    );
    mp.accept_tx(&tx2, &utxos, TIP_OK).unwrap();
    let tx3 = spend_tx(
        OutPoint {
            txid: tx2.compute_txid(),
            vout: 0,
        },
        7_000_000,
    );
    let err = mp.accept_tx(&tx3, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::ClusterTooLarge { count: 3, .. }),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn spend_tx(op: OutPoint, out_value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn prepare_admit_output_sum_overflow_is_policy_not_panic() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let half = (u64::MAX / 2) + 2;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(half),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(half),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    };
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp
        .prepare_admit(
            &tx,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .expect_err("overflowing output sum");
    assert!(
        matches!(err, AcceptError::Policy("bad-txns-txouttotal-toolarge")),
        "got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prepare_admit_rejects_negative_fee() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 100_001);
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp
        .prepare_admit(
            &tx,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .expect_err("outputs exceed inputs");
    assert!(matches!(err, AcceptError::Policy("negative fee")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Consensus script check must reject spends of real templates with empty witness.
/// (Regression: accept used to skip verify and only apply Libre policy.)
#[test]
fn reject_invalid_p2wpkh_script() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    // Standard P2WPKH spk — not anyone-can-spend; empty witness fails.
    let wpkh = WPubkeyHash::from_byte_array([0x11; 20]);
    let spk = ScriptBuf::new_p2wpkh(&wpkh);
    let op = OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: 0,
    };
    let txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: spk,
    };
    let mut map = HashMap::new();
    map.insert(op, coin(txout));
    let utxos = MapUtxoProvider { map };
    let tx = spend_tx(op, 99_000); // empty scriptSig + empty witness
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Script(_)),
        "expected Script reject, got {err}"
    );
    assert_eq!(mp.live_count(), 0);
    // Sanity: ACS still accepted (Libre + consensus anyone-can-spend).
    let (op2, _, utxos2) = chain_utxo(50_000);
    let ok = spend_tx(op2, 49_000);
    mp.accept_tx(&ok, &utxos2, TIP_OK).expect("ACS still ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn accept_tx_nonstandard_version_is_ok() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 50_000);
    tx.version = Version::non_standard(0xffff_ffffu32 as i32);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK)
        .expect("Libre P2P admits nVersion outside 1/2");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dust_and_op_true_allowed() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    // 1-sat output is dust under Core; Libre allows it.
    let tx = spend_tx(op, 1);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK).expect("dust ok");
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 0);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("dust")),
        "0-value spendable must be dust, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 0);
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK)
        .expect("0-value OP_RETURN ok");
    let _ = std::fs::remove_dir_all(&dir);
}

fn ver_tx(inputs: &[OutPoint], version: i32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::non_standard(version),
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .copied()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

fn pay(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn truc_return_pad(n: usize) -> TxOut {
    let mut script = vec![0x6a];
    script.resize(1 + n, 0);
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

#[test]
fn truc_topology_and_sizes() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[500_000, 500_000, 500_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

    let confirmed = ver_tx(&[ops[0]], 3, vec![pay(490_000)]);
    mp.accept_tx(&confirmed, &utxos, TIP_OK)
        .expect("version 3 spending a confirmed output");

    let v2_parent = ver_tx(&[ops[1]], 2, vec![pay(200_000), pay(200_000)]);
    mp.accept_tx(&v2_parent, &utxos, TIP_OK).unwrap();
    let onto_v2 = ver_tx(
        &[OutPoint {
            txid: v2_parent.compute_txid(),
            vout: 0,
        }],
        3,
        vec![pay(150_000)],
    );
    let err = mp.accept_tx(&onto_v2, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("truc-ancestor")), "{err}");

    let v3_parent = ver_tx(&[ops[2]], 3, vec![pay(200_000), pay(200_000)]);
    mp.accept_tx(&v3_parent, &utxos, TIP_OK).unwrap();
    let v2_child = ver_tx(
        &[OutPoint {
            txid: v3_parent.compute_txid(),
            vout: 0,
        }],
        2,
        vec![pay(150_000)],
    );
    let err = mp.accept_tx(&v2_child, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("truc-descendant")),
        "{err}"
    );

    let child = ver_tx(
        &[OutPoint {
            txid: v3_parent.compute_txid(),
            vout: 0,
        }],
        3,
        vec![pay(150_000)],
    );
    mp.accept_tx(&child, &utxos, TIP_OK)
        .expect("one version-3 child");
    let sibling = ver_tx(
        &[OutPoint {
            txid: v3_parent.compute_txid(),
            vout: 1,
        }],
        3,
        vec![pay(150_000)],
    );
    let err = mp.accept_tx(&sibling, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("truc-descendant-count")),
        "{err}"
    );
    let grandchild = ver_tx(
        &[OutPoint {
            txid: child.compute_txid(),
            vout: 0,
        }],
        3,
        vec![pay(100_000)],
    );
    let err = mp.accept_tx(&grandchild, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("truc-ancestor-count")),
        "{err}"
    );

    let replacement = ver_tx(
        &[OutPoint {
            txid: v3_parent.compute_txid(),
            vout: 0,
        }],
        3,
        vec![pay(100_000)],
    );
    mp.accept_tx(&replacement, &utxos, TIP_OK)
        .expect("replacing the only child is not a second descendant");
    assert!(!mp.graph.contains(&child.compute_txid()));
    assert!(mp.graph.contains(&replacement.compute_txid()));

    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[400_000, 400_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let left = ver_tx(&[ops[0]], 3, vec![pay(300_000)]);
    let right = ver_tx(&[ops[1]], 3, vec![pay(300_000)]);
    mp.accept_tx(&left, &utxos, TIP_OK).unwrap();
    mp.accept_tx(&right, &utxos, TIP_OK).unwrap();
    let two_parents = ver_tx(
        &[
            OutPoint {
                txid: left.compute_txid(),
                vout: 0,
            },
            OutPoint {
                txid: right.compute_txid(),
                vout: 0,
            },
        ],
        3,
        vec![pay(500_000)],
    );
    let err = mp.accept_tx(&two_parents, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("truc-ancestor-count")),
        "{err}"
    );

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(2_000_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let huge = ver_tx(&[op], 3, vec![pay(100_000), truc_return_pad(40_100)]);
    let err = mp.accept_tx(&huge, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("truc-size")), "{err}");

    let parent = ver_tx(&[op], 3, vec![pay(1_500_000)]);
    mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
    let wide_child = ver_tx(
        &[OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        }],
        3,
        vec![pay(1_000_000), truc_return_pad(4_100)],
    );
    let err = mp.accept_tx(&wide_child, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("truc-child-size")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(2_000_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let wide_confirmed = ver_tx(&[op], 2, vec![pay(100_000), truc_return_pad(4_100)]);
    mp.accept_tx(&wide_confirmed, &utxos, TIP_OK)
        .expect("a non-version-3 transaction is not under the TRUC child cap");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `n` bare `OP_CHECKMULTISIG` outputs: legacy cost `n × 20 × 4`.
fn multisig_outputs_tx(op: OutPoint, n: usize) -> Transaction {
    let mut tx = spend_tx(op, 1);
    tx.output = vec![
        TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
        };
        n
    ];
    tx
}

/// Chain coins at P2SH and P2WSH of `0 <pk> <pk> 2 CHECKMULTISIG` (2 accurate
/// sigops, zero-sig so it verifies) plus a spend of each. Legacy ×4 is 0 for
/// both; full cost is 8 (P2SH ×4) and 2 (witness ×1).
fn p2sh_p2wsh_multisig_spends() -> (MapUtxoProvider, Transaction, Transaction) {
    use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2};
    use bitcoin::opcodes::OP_0;
    let pk = [0x02u8; 33];
    let redeem = bitcoin::script::Builder::new()
        .push_opcode(OP_0)
        .push_slice(pk)
        .push_slice(pk)
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let p2sh_op = OutPoint {
        txid: Txid::from_byte_array([0xa1; 32]),
        vout: 0,
    };
    let p2wsh_op = OutPoint {
        txid: Txid::from_byte_array([0xa2; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    for (op, spk) in [
        (p2sh_op, ScriptBuf::new_p2sh(&redeem.script_hash())),
        (p2wsh_op, ScriptBuf::new_p2wsh(&redeem.wscript_hash())),
    ] {
        map.insert(
            op,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk,
            }),
        );
    }
    let mut p2sh = spend_tx(p2sh_op, 90_000);
    p2sh.input[0].script_sig = bitcoin::script::Builder::new()
        .push_opcode(OP_0)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap())
        .into_script();
    let mut p2wsh = spend_tx(p2wsh_op, 90_000);
    p2wsh.input[0].witness = Witness::from_slice(&[&[][..], redeem.as_bytes()]);
    (MapUtxoProvider { map }, p2sh, p2wsh)
}

fn live_sigops(mp: &ActiveMempool, tx: &Transaction) -> u64 {
    mp.graph.get(&tx.compute_txid()).unwrap().sigop_cost
}

#[test]
fn package_and_reorg_readmit_record_sigop_cost() {
    let dir = tmp_dir();
    let (utxos, parent, _) = p2sh_p2wsh_multisig_spends();
    let pid = parent.compute_txid();
    let mut child = spend_tx(OutPoint { txid: pid, vout: 0 }, 80_000);
    child.output.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
    });
    let pkg = [parent.clone(), child.clone()];
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_package(&pkg, &utxos, TIP_OK).expect("package");
    assert_eq!(live_sigops(&mp, &parent), 8);
    assert_eq!(live_sigops(&mp, &child), 80);

    mp.remove_for_block(&[pid, child.compute_txid()]).unwrap();
    assert_eq!(mp.live_count(), 0);
    let readmitted: Vec<Txid> = mp
        .reorg_disconnect_reaccept(&pkg, &utxos, TIP_OK)
        .into_iter()
        .map(|r| r.expect("reorg re-admit").txid)
        .collect();
    assert_eq!(readmitted, [pid, child.compute_txid()]);
    assert_eq!(live_sigops(&mp, &parent), 8);
    assert_eq!(live_sigops(&mp, &child), 80);
}

/// Schema-2 pool: costs unknown after migrate; the open-time pass recomputes
/// from live parents + chain coins, evicts unresolvable / over-budget
/// entries, and writes costs back so the next open needs no pass.
#[test]
fn schema2_pool_recomputes_sigops_after_open() {
    let dir = tmp_dir();
    let (mut utxos, p2sh, p2wsh) = p2sh_p2wsh_multisig_spends();
    let mut child = spend_tx(
        OutPoint {
            txid: p2sh.compute_txid(),
            vout: 0,
        },
        80_000,
    );
    child.output.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
    });
    let (gone_op, _, extra) = chain_utxo(100_000);
    utxos.map.extend(extra.map);
    let gone = spend_tx(gone_op, 90_000);
    let probe_op = OutPoint {
        txid: Txid::from_byte_array([0xa3; 32]),
        vout: 0,
    };
    utxos.map.insert(probe_op, utxos.map[&gone_op].clone());
    let probe = multisig_outputs_tx(probe_op, 1001);
    {
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        for tx in [&p2sh, &p2wsh, &child, &gone] {
            mp.accept_tx(tx, &utxos, TIP_OK).unwrap();
        }
        // Admitted by a pre-sigop-check build.
        let (pid, pw) = (probe.compute_txid(), probe.compute_wtxid());
        mp.store
            .append_live_tx(
                &probe,
                &pid,
                &pw,
                1_000,
                probe.weight().to_wu(),
                0,
                1_700_000_000,
                &[],
            )
            .unwrap();
        mp.flush().unwrap();
    }
    crate::store_tests::downgrade_to_schema2(dir.as_ref());
    utxos.map.remove(&gone_op);

    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 5);
    assert!(mp.graph.iter().all(|(_, e)| e.sigop_cost == u64::MAX));
    mp.recompute_missing_sigops(&utxos);
    assert_eq!(mp.live_count(), 3);
    assert!(!mp.graph.contains(&gone.compute_txid()), "prevout gone");
    assert!(!mp.graph.contains(&probe.compute_txid()), "over budget");
    assert_eq!(live_sigops(&mp, &p2sh), 8);
    assert_eq!(live_sigops(&mp, &p2wsh), 2);
    assert_eq!(live_sigops(&mp, &child), 80);
    drop(mp);

    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 3);
    assert_eq!(live_sigops(&mp, &p2sh), 8, "written back");
    assert_eq!(live_sigops(&mp, &child), 80);
}

#[test]
fn evaluate_after_script_rbf_leaves_conflict() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let low = spend_tx(op, 99_000);
    let high = spend_tx(op, 50_000);
    let low_id = low.compute_txid();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&low, &utxos, TIP_OK).unwrap();
    let prep = mp
        .prepare_admit(
            &high,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: true,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .unwrap();
    let r = mp.evaluate_after_script(&high, prep).expect("preview");
    assert!(r.replaced.contains(&low_id));
    assert!(mp.graph.contains(&low_id));
    assert!(!mp.graph.contains(&high.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// testmempoolaccept preview enforces cluster count and raw-weight vsize
/// limits itself (only the accept path re-checks after insert): exactly at
/// each limit previews Ok, one past is ClusterTooLarge with exact totals.
#[test]
fn evaluate_after_script_enforces_cluster_limits() {
    let (op, _, utxos) = chain_utxo(100_000);
    let parent = spend_tx(op, 99_000);
    let pw = parent.weight().to_wu();
    let pad_child = |total_w: u64| {
        let mut c = spend_tx(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            98_000,
        );
        while pw + c.weight().to_wu() < total_w {
            c.output[0]
                .script_pubkey
                .push_opcode(bitcoin::opcodes::OP_TRUE);
        }
        assert_eq!(pw + c.weight().to_wu(), total_w);
        c
    };
    let preview = |count: u32, child: &Transaction| {
        let dir = tmp_dir();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.set_cluster_limits(Some(count), Some(1)); // 1 kvB = 4_000 WU
        mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
        let prep = mp
            .prepare_admit(
                child,
                &utxos,
                TIP_OK,
                PrepareOpts {
                    fee_delta: 0,
                    report_orphans: true,
                    min_relay: None,
                    waive: false,
                    ephemeral_ok: false,
                },
            )
            .unwrap();
        mp.evaluate_after_script(child, prep).map(|r| r.txid)
    };
    let at = pad_child(4_000);
    assert_eq!(preview(2, &at).unwrap(), at.compute_txid());
    let over = pad_child(4_004);
    assert!(matches!(
        preview(2, &over),
        Err(AcceptError::ClusterTooLarge {
            count: 2,
            weight: 4_004
        })
    ));
    assert!(matches!(
        preview(1, &at),
        Err(AcceptError::ClusterTooLarge {
            count: 2,
            weight: 4_000
        })
    ));
}

#[test]
fn commit_after_script_does_not_take_utxo_provider() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 99_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let prep = mp
        .prepare_admit(
            &tx,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: true,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .unwrap();
    mp.commit_after_script(&tx, prep)
        .expect("commit uses prep.chain_coins");
    assert!(mp.graph.contains(&tx.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prepare_admit_stashes_txid() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 99_000);
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    let prep = mp
        .prepare_admit(
            &tx,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: true,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .unwrap();
    assert_eq!(prep.txid, tx.compute_txid());
    assert_eq!(prep.wtxid, tx.compute_wtxid());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn commit_after_script_parent_body_missing_is_durable() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let parent = spend_tx(op, 90_000);
    let pid = parent.compute_txid();
    let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 80_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
    let prep = mp
        .prepare_admit(
            &child,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: true,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .unwrap();
    mp.bodies.remove(&pid);
    let err = mp.commit_after_script(&child, prep).unwrap_err();
    assert!(
        matches!(err, AcceptError::Durable(ref s) if s == "parent body missing"),
        "got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rbf_pays_helper() {
    assert!(rbf_pays_for_replacement(10_000, 4000, 1000, 4000));
    assert!(!rbf_pays_for_replacement(1000, 4000, 10_000, 4000));
    assert!(!rbf_pays_for_replacement(1000, 4000, 1000, 4000));
    // 1000 vB at 100000 sat vs 1001 vB at 100101 sat: true feerate is
    // higher and the incremental ceiling is exact, but both truncated
    // sat/kvB rates are 100000.
    assert!(rbf_pays_for_replacement(100_101, 4004, 100_000, 4000));
    // One sat short of the incremental ceiling at the same vsize.
    assert!(!rbf_pays_for_replacement(100_099, 4000, 100_000, 4000));
    assert!(!rbf_pays_for_replacement(1, 0, 0, 4000));
    // vsize 101_000 makes `fee * vsize` exceed u64::MAX for a fee still
    // under MAX_MONEY. Same vsize, so the higher fee is a higher rate.
    // The incremental ceiling at this vsize is 10_100 sat.
    let old_fee = 200_000_000_000_000u64;
    let weight = 404_000u64;
    assert!(rbf_pays_for_replacement(
        old_fee + 10_100,
        weight,
        old_fee,
        weight
    ));
    assert!(!rbf_pays_for_replacement(
        old_fee + 10_099,
        weight,
        old_fee,
        weight
    ));
}

#[test]
fn pure_rbfr_1_25x_ratio() {
    // Same weight: new fee ≥ 1.25× old fee.
    // old fee 1000 @ 4000 WU → need new ≥ 1250 same weight.
    assert!(pure_rbfr_pays(1_250, 4000, 1_000, 4000));
    assert!(!pure_rbfr_pays(1_249, 4000, 1_000, 4000));
    assert!(!pure_rbfr_pays(1_250, 0, 1_000, 4000));
    assert!(!pure_rbfr_pays(1_250, 4000, 1_000, 0));
    // Higher rate, lower absolute fee vs a fat conflict set still passes pure RBFR
    // (BIP125 would fail): direct 1000@4000, conflict set pretends 50k@40k.
    assert!(!rbf_pays_for_replacement(2_000, 4000, 50_000, 40_000));
    assert!(pure_rbfr_pays(2_000, 4000, 1_000, 4000));
    assert!(rbf_allows_replacement(
        2_000, 4000, 50_000, 40_000, 1_000, 4000
    ));
    // TESTING.md True journeys: pure arithmetic. A session cannot reach
    // this product without a near-supply fee. Equal fees are not 1.25×.
    // Saturating `u64` products both become `u64::MAX` and would pass.
    let near = u64::MAX / 4 + 1;
    assert!(!pure_rbfr_pays(near, 4000, near, 4000));
}

#[test]
fn compact_reclaims_dead_and_preserves_live() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    let txid = tx.compute_txid();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    let body_before = mp.store.body_logical_len().unwrap();
    // Confirm-remove leaves a DEAD slot (body still holds the old payload).
    mp.remove_for_block(&[txid]).unwrap();
    // Re-accept so we have live + dead history in the body file.
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    let (_f, live, dead) = mp.store.slot_stats();
    assert_eq!(live, 1);
    // remove_for_block may already have auto-compacted; either way compact is safe.
    let _ = dead;
    let (live_after, body_after) = mp.compact().unwrap();
    assert_eq!(live_after, 1);
    assert!(body_after <= body_before + 256);
    assert_eq!(body_after, mp.store.body_logical_len().unwrap());
    assert_eq!(mp.live_count(), 1);
    mp.flush().unwrap();
    let mp2 = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp2.live_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `mempool_cluster.py` cleanup mines the mempool empty and `maybe_compact`
/// rebuilds the graph. Overlay limits must survive that rebuild.
#[test]
fn compact_preserves_cluster_size_overlay() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    let txid = tx.compute_txid();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.set_cluster_limits(None, Some(10));
    assert_eq!(mp.graph.cluster_vsize_limit(), 10_000);
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    mp.remove_for_block(&[txid]).unwrap();
    let _ = mp.maybe_compact().unwrap();
    assert_eq!(
        mp.graph.cluster_vsize_limit(),
        10_000,
        "compact must keep -limitclustersize overlay"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(clippy::cognitive_complexity)] // one fixture, many reject arms
#[test]
fn accept_error_display_and_reject_paths() {
    use std::error::Error;
    let errs = [
        AcceptError::Policy("x"),
        AcceptError::MissingPrevout(OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        }),
        AcceptError::Orphaned {
            txid: Txid::from_byte_array([4; 32]),
            missing: BTreeSet::new(),
            fresh: true,
        },
        AcceptError::Duplicate(Txid::from_byte_array([2; 32])),
        AcceptError::ClusterTooLarge {
            count: 3,
            weight: 9,
        },
        AcceptError::PackageTooLarge {
            count: 2,
            weight: 8,
        },
        AcceptError::PackageEmpty,
        AcceptError::PackageNotTopo,
        AcceptError::RbfInsufficient,
        AcceptError::Coinbase,
        AcceptError::NotFound(Txid::from_byte_array([3; 32])),
        AcceptError::Durable("d".into()),
        AcceptError::Script("s".into()),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
        let _ = e as &dyn Error;
    }
    let from_io: AcceptError = MempoolError::BadMagic.into();
    assert!(from_io.to_string().contains("durable"));
    let from_full: AcceptError = MempoolError::Full.into();
    assert!(matches!(from_full, AcceptError::Policy("mempool full")));

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

    let cb = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(matches!(
        mp.accept_tx(&cb, &utxos, TIP_OK),
        Err(AcceptError::Coinbase)
    ));

    assert!(matches!(
        mp.accept_package(&[], &utxos, TIP_OK),
        Err(AcceptError::PackageEmpty)
    ));
    let many: Vec<Transaction> = (0..MAX_PACKAGE_COUNT + 1)
        .map(|i| {
            spend_tx(
                OutPoint {
                    txid: Txid::from_byte_array({
                        let mut b = [0u8; 32];
                        b[0] = i as u8;
                        b
                    }),
                    vout: 0,
                },
                1,
            )
        })
        .collect();
    assert!(matches!(
        mp.accept_package(&many, &utxos, TIP_OK),
        Err(AcceptError::PackageTooLarge { .. })
    ));

    let tx = spend_tx(op, 99_000);
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    assert!(matches!(
        mp.accept_tx(&tx, &utxos, TIP_OK),
        Err(AcceptError::Duplicate(_))
    ));

    let (_op2, _, empty) = chain_utxo(50_000);
    let missing = spend_tx(
        OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        },
        1,
    );
    let missing_id = missing.compute_txid();
    assert!(matches!(
        mp.accept_tx(&missing, &empty, TIP_OK),
        Err(AcceptError::Orphaned { .. })
    ));
    assert!(mp.orphanage.contains(&missing_id));
    assert_eq!(mp.orphan_count(), 1);

    assert!(mp.maybe_compact().unwrap().is_none());

    assert!(matches!(
        mp.accept_package(&[cb], &utxos, TIP_OK),
        Err(AcceptError::Coinbase)
    ));
    let a = spend_tx(op, 98_000);
    let b = spend_tx(
        OutPoint {
            txid: a.compute_txid(),
            vout: 0,
        },
        97_000,
    );
    assert!(matches!(
        mp.accept_package(&[b.clone(), a.clone()], &utxos, TIP_OK),
        Err(AcceptError::PackageNotTopo)
    ));
    assert!(matches!(
        mp.accept_package(&[a.clone(), a.clone()], &utxos, TIP_OK),
        Err(AcceptError::Duplicate(_))
    ));

    assert!(matches!(
        mp.remove_txid(&Txid::from_byte_array([0xee; 32])),
        Err(AcceptError::NotFound(_))
    ));

    // Negative fee.
    let fat = spend_tx(op, 200_000);
    assert!(matches!(
        mp.accept_tx(&fat, &utxos, TIP_OK),
        Err(AcceptError::Policy(_))
    ));

    assert!(!rbf_pays_for_replacement(100, 400, 100, 400));
    assert!(!rbf_pays_for_replacement(100, 400, 200, 400));
    assert!(rbf_pays_for_replacement(50_000, 400, 1_000, 400));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn witness_unexpected_script_is_not_txid_invalid() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let stripped =
        AcceptError::Script("script verification failed: p2tr empty witness txid=00 vin=0".into());
    assert!(
        ActiveMempool::accept_failure_record(&tx, &stripped).is_none(),
        "stripped-witness fail must not poison txid"
    );
    let bad_sig = AcceptError::Script("script verification failed: SIG_DER".into());
    assert!(
        matches!(
            ActiveMempool::accept_failure_record(&tx, &bad_sig),
            Some(AcceptFailureRecord::Invalid(_))
        ),
        "non-witness script fail still poisons txid"
    );
}

#[test]
fn remove_txid_notes_extra_compact() {
    let dir = tmp_dir();
    let (op, txout, utxos) = chain_utxo(100_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let tx = spend_tx(op, txout.value.to_sat() - 1_000);
    let txid = tx.compute_txid();
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    mp.remove_txid(&txid).unwrap();
    assert!(
        mp.extra_compact_txs().any(|t| t.compute_txid() == txid),
        "confirm/evict strip must keep the body for compact fill"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remove_live_txids_syncs_deaths_once() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let mut txs = Vec::new();
    let mut map = HashMap::new();
    for i in 0..6u8 {
        let op = OutPoint {
            txid: Txid::from_byte_array([i.saturating_add(1); 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        map.insert(op, coin(txout));
        txs.push(spend_tx(op, 40_000));
    }
    let utxos = MapUtxoProvider { map };
    let ids: Vec<Txid> = txs.iter().map(|tx| tx.compute_txid()).collect();
    for tx in &txs {
        mp.accept_tx(tx, &utxos, TIP_OK).unwrap();
    }
    mp.flush().unwrap();
    let (meta_before, slots_before) = mp.death_sync_counts();
    // Two deaths, one sync. Leave a live majority so compact does not sync meta again.
    let n = mp.remove_live_txids(&ids[..2]).unwrap();
    assert_eq!(n, 2);
    let (meta_after, slots_after) = mp.death_sync_counts();
    assert_eq!(meta_after, meta_before + 1, "block strip syncs meta once");
    assert_eq!(
        slots_after,
        slots_before + 1,
        "block strip syncs slots once"
    );
    assert_eq!(mp.live_count(), 4);
    drop(mp);
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 4, "flushed strip must not resurrect");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remove_block_txids_syncs_confirmed_and_conflicts_once() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let mut map = HashMap::new();
    let mut ids = Vec::new();
    for i in 0..6u8 {
        let op = OutPoint {
            txid: Txid::from_byte_array([i.saturating_add(1); 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        map.insert(op, coin(txout));
        let tx = spend_tx(op, 40_000);
        ids.push(tx.compute_txid());
        mp.accept_tx(&tx, &MapUtxoProvider { map: map.clone() }, TIP_OK)
            .unwrap();
    }
    mp.flush().unwrap();
    let (meta_before, slots_before) = mp.death_sync_counts();
    let (n, conflicts) = mp.remove_block_txids(&ids[..2], &[]).unwrap();
    assert_eq!(n, 2);
    assert!(conflicts.is_empty());
    let (meta_after, slots_after) = mp.death_sync_counts();
    assert_eq!(meta_after, meta_before + 1);
    assert_eq!(slots_after, slots_before + 1);
    assert_eq!(mp.live_count(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remember_extra_compact_skips_coinbase() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let cb = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(cb.is_coinbase());
    mp.remember_extra_compact(&cb);
    assert_eq!(
        mp.extra_compact_txs().count(),
        0,
        "coinbase prefill must not consume extra_compact"
    );
    let spend = spend_tx(
        OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout: 0,
        },
        1_000,
    );
    mp.remember_extra_compact(&spend);
    assert_eq!(mp.extra_compact_txs().count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Slot table growth under accept: legacy tiny sidecar must not fail as Durable corrupt.
#[test]
fn accept_grows_legacy_tiny_slot_table() {
    use std::fs;
    let dir = tmp_dir();
    fs::create_dir_all(&dir).unwrap();
    // 4-slot meta/slots/body (same layout as store unit test).
    {
        let mut meta = [0u8; 64];
        meta[0..4].copy_from_slice(b"rBMP");
        meta[4..6].copy_from_slice(&2u16.to_le_bytes());
        meta[16..20].copy_from_slice(&4u32.to_le_bytes());
        fs::write(dir.join("meta"), meta).unwrap();
        let mut slots = vec![0u8; 16 + 4 * 48];
        slots[0..4].copy_from_slice(b"rBMP");
        slots[4..6].copy_from_slice(&2u16.to_le_bytes());
        slots[8..12].copy_from_slice(&4u32.to_le_bytes());
        fs::write(dir.join("slots"), &slots).unwrap();
        let mut body = vec![0u8; 16];
        body[0..4].copy_from_slice(b"rBMP");
        body[4..6].copy_from_slice(&2u16.to_le_bytes());
        body[8..16].copy_from_slice(&16u64.to_le_bytes());
        fs::write(dir.join("tx.body"), &body).unwrap();
    }
    // Large weight budget so eviction is not the free-slot path.
    let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 300_000_000).unwrap();
    assert_eq!(mp.store.meta().slot_cap, 4);
    for i in 0..4u8 {
        let op = OutPoint {
            txid: Txid::from_byte_array({
                let mut b = [0xab; 32];
                b[0] = i;
                b
            }),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 99_000);
        mp.accept_tx(&tx, &utxos, TIP_OK)
            .unwrap_or_else(|e| panic!("accept {i}: {e}"));
    }
    assert_eq!(mp.live_count(), 4);
    // Fifth must grow slots, not Durable(corrupt: slot table full).
    let op = OutPoint {
        txid: Txid::from_byte_array([0xcd; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let tx = spend_tx(op, 99_000);
    let r = mp.accept_tx(&tx, &utxos, TIP_OK);
    assert!(
        r.is_ok(),
        "expected grow (weight budget has headroom), got {:?}",
        r.err().map(|e| e.to_string())
    );
    assert!(
        mp.store.meta().slot_cap > 4,
        "ensure_free_slot must grow before it evicts"
    );
    assert_eq!(mp.live_count(), 5);
    let _ = fs::remove_dir_all(&dir);
}

/// P2WSH spend whose witness script holds `n` unexecuted sigops, output an
/// OP_RETURN push of `pad` bytes (Core `mempool_sigoplimit.py` fixture).
fn witness_sigops_spend(n: usize, pad: usize) -> (MapUtxoProvider, Transaction) {
    use bitcoin::opcodes::all::{
        OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHNUM_1, OP_RETURN,
    };
    use bitcoin::opcodes::OP_FALSE;
    let mut b = bitcoin::script::Builder::new()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);
    for _ in 0..n / 20 {
        b = b.push_opcode(OP_CHECKMULTISIG);
    }
    for _ in 0..n % 20 {
        b = b.push_opcode(OP_CHECKSIG);
    }
    let ws = b
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_PUSHNUM_1)
        .into_script();
    let op = OutPoint {
        txid: Txid::from_byte_array([0xa3; 32]),
        vout: 0,
    };
    let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let map = HashMap::from([(
        op,
        coin(TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: spk,
        }),
    )]);
    let mut tx = spend_tx(op, 0);
    tx.input[0].witness = Witness::from_slice(&[ws.as_bytes()]);
    let data = bitcoin::script::PushBytesBuf::try_from(vec![b'X'; pad]).unwrap();
    tx.output[0].script_pubkey = bitcoin::script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script();
    (MapUtxoProvider { map }, tx)
}

fn vsize_of(tx: &Transaction) -> u64 {
    bitcoin::Weight::from_wu(tx.weight().to_wu()).to_vbytes_ceil()
}

/// Zero-fee parent + heavy-sigop child: 200 sat pays the raw package
/// vsize, not the sigop-adjusted one.
fn cpfp_heavy_child(op: OutPoint) -> (Transaction, Transaction) {
    let parent = spend_tx(op, 100_000);
    let mut child = multisig_outputs_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        10,
    );
    child.output[0].value = Amount::from_sat(100_000 - 200 - 9);
    (parent, child)
}

/// A parent-then-child package must admit a child that was already parked
/// on that parent, and a failed package must leave that child parked.
#[test]
fn package_admits_its_parked_child() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: ops[0],
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    };
    let parent_id = parent.compute_txid();
    let child = spend_tx(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        39_000,
    );
    let sibling = spend_tx(
        OutPoint {
            txid: parent_id,
            vout: 1,
        },
        39_000,
    );
    let child_id = child.compute_txid();
    let sibling_id = sibling.compute_txid();
    for tx in [&child, &sibling] {
        let err = mp.accept_tx(tx, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { .. }),
            "spend of the missing parent must park, got {err}"
        );
    }
    let accepted = mp
        .accept_package(&[parent.clone(), child.clone()], &utxos, TIP_OK)
        .expect("package contains the parked child");
    assert_eq!(accepted.len(), 2);
    assert!(mp.graph.contains(&parent_id));
    assert!(mp.graph.contains(&child_id));
    assert!(
        mp.graph.contains(&sibling_id),
        "a parked sibling that is not in the package must still be admitted"
    );
    assert_eq!(mp.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent = spend_tx(ops[1], 99_000);
    let child = spend_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        98_000,
    );
    let child_id = child.compute_txid();
    let err = mp.accept_tx(&child, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
    let bad = spend_tx(ops[1], 100_000);
    let err = mp
        .accept_package(&[parent, bad], &utxos, TIP_OK)
        .expect_err("second member overspends");
    assert!(
        !matches!(err, AcceptError::Duplicate(id) if id == child_id),
        "a failed package must not report the parked child as a duplicate, got {err}"
    );
    assert!(
        mp.orphanage.contains(&child_id),
        "a failed package must leave the parked child in the orphanage"
    );
    assert!(!mp.graph.contains(&child_id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// One parent arriving must leave an orphan that still misses the other.
#[test]
fn promote_keeps_orphan_that_still_misses_a_parent() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent_a = spend_tx(ops[0], 99_000);
    let parent_b = spend_tx(ops[1], 99_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_a.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_b.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(197_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = child.compute_txid();
    let err = mp.accept_tx(&child, &utxos, TIP_OK).unwrap_err();
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "child waits on both parents, got {err}"
    );
    mp.accept_tx(&parent_a, &utxos, TIP_OK)
        .expect("first parent");
    assert!(
        mp.orphanage.contains(&child_id),
        "child still missing the second parent must stay parked"
    );
    assert!(!mp.graph.contains(&child_id));
    mp.accept_tx(&parent_b, &utxos, TIP_OK)
        .expect("second parent");
    assert!(
        mp.graph.contains(&child_id),
        "both parents present must admit the parked child"
    );
    assert_eq!(mp.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Conflicts removed by a replacement come back after that replacement's
/// package child is evicted, even when the rolling floor now prices them
/// out. Includes a CPFP parent that cannot pay min relay alone.
///
/// The child spends the low-fee anchor. The replacement does not: the
/// anchor is not a parent of the conflict.
#[test]
fn failed_replacement_restores_below_floor_and_cpfp_set() {
    let value = 50_000_000u64;
    let dir = tmp_dir();
    let utxos = coins(&[(0x11, value), (0x22, value)]);
    let anchor_op = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let low_op = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let anchor_wu = fat_spend(anchor_op, value, 0).weight().to_wu();
    let victim_wu = spend_tx_fee(low_op, value, 0).weight().to_wu();
    mp.max_weight = anchor_wu + victim_wu + 500;
    let floor = mp.mempool_min_fee_sat_kvb();
    let anchor = fat_spend(anchor_op, value, fee_at_least(anchor_wu, floor));
    let victim_fee = fee_at_least(victim_wu, floor);
    let victim = spend_tx_fee(low_op, value, victim_fee);
    let victim_id = victim.compute_txid();
    let victim_rate = policy::fee_rate_sat_per_kvb(victim_fee, victim_wu);
    mp.accept_tx(&anchor, &utxos, TIP_OK).expect("anchor");
    mp.accept_tx(&victim, &utxos, TIP_OK)
        .expect("victim at the pre-eviction floor");
    let replacement = spend_tx_fee(low_op, value, 30_000);
    let replacement_id = replacement.compute_txid();
    let held = anchor_wu + replacement.weight().to_wu();
    assert!(
        held <= mp.max_weight,
        "replacement must fit beside the anchor"
    );
    let child = child_evicted_with_anchor(&replacement, &anchor, 50_000, mp.max_weight - held);
    let err = mp
        .accept_package(&[replacement, child], &utxos, TIP_OK)
        .expect_err("child over budget");
    assert!(matches!(err, AcceptError::Policy("mempool full")), "{err}");
    let enforced = mp.mempool_min_fee_sat_kvb();
    assert!(
        enforced > victim_rate,
        "eviction must price out the victim ({victim_rate} vs {enforced})"
    );
    assert!(!mp.graph.contains(&replacement_id));
    assert!(
        mp.graph.contains(&victim_id),
        "below-floor conflict must stay"
    );
    assert_eq!(mp.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let utxos = coins(&[(0x41, value), (0x42, value)]);
    let anchor_op = OutPoint {
        txid: Txid::from_byte_array([0x41; 32]),
        vout: 0,
    };
    let parent_op = OutPoint {
        txid: Txid::from_byte_array([0x42; 32]),
        vout: 0,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let (parent, child) = cpfp_child_sorts_first(parent_op, value);
    assert!(child.compute_txid() < parent.compute_txid());
    let anchor_wu = fat_spend(anchor_op, value, 0).weight().to_wu();
    mp.max_weight = anchor_wu + parent.weight().to_wu() + child.weight().to_wu() + 500;
    let floor = mp.mempool_min_fee_sat_kvb();
    let anchor = fat_spend(anchor_op, value, fee_at_least(anchor_wu, floor));
    mp.accept_tx(&anchor, &utxos, TIP_OK).expect("anchor");
    mp.accept_package(&[parent.clone(), child.clone()], &utxos, TIP_OK)
        .expect("CPFP package");
    let replacement = spend_tx_fee(parent_op, value, 90_000);
    let held = anchor.weight().to_wu() + replacement.weight().to_wu();
    assert!(
        held <= mp.max_weight,
        "replacement must fit beside the anchor"
    );
    let over = child_evicted_with_anchor(&replacement, &anchor, 50_000, mp.max_weight - held);
    let err = mp
        .accept_package(&[replacement, over], &utxos, TIP_OK)
        .expect_err("child over budget");
    assert!(matches!(err, AcceptError::Policy("mempool full")), "{err}");
    assert!(
        mp.graph.contains(&parent.compute_txid()),
        "below-min-relay parent must stay"
    );
    assert!(
        mp.graph.contains(&child.compute_txid()),
        "paying child must stay"
    );
    assert_eq!(mp.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict put back after a failed replacement keeps the accept time it
/// was admitted with. The sidecar must not take the restore instant.
#[test]
fn failed_replacement_restore_keeps_accept_time_on_disk() {
    let value = 50_000_000u64;
    let dir = tmp_dir();
    let utxos = coins(&[(0x11, value), (0x22, value)]);
    let anchor_op = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let low_op = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let clock = Arc::new(AtomicU64::new(0));
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.set_node_clock(Arc::clone(&clock));
    let anchor_wu = fat_spend(anchor_op, value, 0).weight().to_wu();
    let victim_wu = spend_tx_fee(low_op, value, 0).weight().to_wu();
    mp.max_weight = anchor_wu + victim_wu + 500;
    let floor = mp.mempool_min_fee_sat_kvb();
    let anchor = fat_spend(anchor_op, value, fee_at_least(anchor_wu, floor));
    let victim = spend_tx_fee(low_op, value, fee_at_least(victim_wu, floor));
    let victim_id = victim.compute_txid();
    let t0 = 1_700_000_000u64;
    clock.store(t0, Ordering::Relaxed);
    mp.accept_tx(&anchor, &utxos, TIP_OK).expect("anchor");
    mp.accept_tx(&victim, &utxos, TIP_OK).expect("victim");
    clock.store(t0 + 600, Ordering::Relaxed);
    let replacement = spend_tx_fee(low_op, value, 30_000);
    let held = anchor_wu + replacement.weight().to_wu();
    assert!(
        held <= mp.max_weight,
        "replacement must fit beside the anchor"
    );
    let child = child_evicted_with_anchor(&replacement, &anchor, 50_000, mp.max_weight - held);
    let err = mp
        .accept_package(&[replacement, child], &utxos, TIP_OK)
        .expect_err("child over budget");
    assert!(matches!(err, AcceptError::Policy("mempool full")), "{err}");
    assert!(mp.graph.contains(&victim_id), "conflict restored");
    mp.store.flush().unwrap();
    drop(mp);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let loaded = mp.take_loaded_accept_times();
    let at = loaded
        .iter()
        .find(|(t, _, _)| *t == victim_id)
        .map(|(_, _, s)| *s);
    assert_eq!(at, Some(t0), "restored conflict keeps its accept time");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A package member that replaced a conflict, followed by a member that
/// fails, rolls back. The restored conflict keeps its own accept time.
#[test]
fn package_rollback_restore_keeps_accept_time_on_disk() {
    let value = 50_000_000u64;
    let dir = tmp_dir();
    let utxos = coins(&[(0x33, value)]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x33; 32]),
        vout: 0,
    };
    let clock = Arc::new(AtomicU64::new(0));
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.set_node_clock(Arc::clone(&clock));
    let low = spend_tx_fee(op, value, 1_000);
    let low_id = low.compute_txid();
    let high = spend_tx_fee(op, value, 100_000);
    let mut bad_child = spend_tx_fee(
        OutPoint {
            txid: high.compute_txid(),
            vout: 0,
        },
        high.output[0].value.to_sat(),
        10_000,
    );
    bad_child.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
    let t0 = 1_700_000_000u64;
    clock.store(t0, Ordering::Relaxed);
    mp.accept_tx(&low, &utxos, TIP_OK).expect("low");
    clock.store(t0 + 600, Ordering::Relaxed);
    mp.accept_package(&[high.clone(), bad_child], &utxos, TIP_OK)
        .expect_err("annex child fails");
    assert!(!mp.graph.contains(&high.compute_txid()));
    assert!(mp.graph.contains(&low_id), "victim restored");
    mp.store.flush().unwrap();
    drop(mp);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let at = mp
        .take_loaded_accept_times()
        .iter()
        .find(|(t, _, _)| *t == low_id)
        .map(|(_, _, s)| *s);
    assert_eq!(at, Some(t0), "restored victim keeps its accept time");
    let _ = std::fs::remove_dir_all(&dir);
}

fn coins(specs: &[(u8, u64)]) -> MapUtxoProvider {
    let mut map = HashMap::new();
    for &(tag, value) in specs {
        let op = OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        };
        map.insert(
            op,
            coin(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
    }
    MapUtxoProvider { map }
}

fn spend_tx_fee(op: OutPoint, input_value: u64, fee: u64) -> Transaction {
    spend_tx(op, input_value - fee)
}

fn fat_spend(op: OutPoint, input_value: u64, fee: u64) -> Transaction {
    let mut fat = Vec::new();
    for _ in 0..6 {
        fat.push(0x4d);
        fat.extend_from_slice(&520u16.to_le_bytes());
        fat.extend(std::iter::repeat_n(0u8, 520));
        fat.push(0x75);
    }
    fat.push(0x51);
    let mut tx = spend_tx_fee(op, input_value, fee);
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(fat);
    tx
}

fn fee_at_least(weight: u64, sat_kvb: u64) -> u64 {
    let vsize = weight.div_ceil(4);
    vsize.saturating_mul(sat_kvb).div_ceil(1000).max(1)
}

/// Package child of `replacement` that also spends `anchor`.
///
/// Weight above `over_wu` (the room left after the replacement sits beside
/// the anchor) makes eviction drop this child with the anchor.
fn child_evicted_with_anchor(
    replacement: &Transaction,
    anchor: &Transaction,
    fee: u64,
    over_wu: u64,
) -> Transaction {
    let input_value = replacement.output[0].value.to_sat() + anchor.output[0].value.to_sat();
    let mut n = 1usize;
    loop {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: replacement.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: anchor.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(input_value - fee),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51; n]),
            }],
        };
        if tx.weight().to_wu() > over_wu {
            return tx;
        }
        n += 32;
        assert!(n < 10_000, "package child never got heavy enough");
    }
}

fn cpfp_child_sorts_first(parent_op: OutPoint, input_value: u64) -> (Transaction, Transaction) {
    for n in 0..10_000u32 {
        let mut parent = spend_tx_fee(parent_op, input_value, 1);
        parent.lock_time = LockTime::from_consensus(n);
        let child = spend_tx(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            parent.output[0].value.to_sat() - 40_000,
        );
        if child.compute_txid() < parent.compute_txid() {
            return (parent, child);
        }
    }
    panic!("no locktime put the child txid first");
}

#[test]
fn relay_floor_generation_and_sidecar_persist_are_the_stored_values() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(
        mp.min_relay_sat_kvb(),
        rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB
    );
    mp.set_min_relay_sat_kvb(50_000);
    assert_eq!(mp.min_relay_sat_kvb(), 50_000);
    mp.store.set_now_ms(0);
    mp.flush().unwrap();
    mp.flush().unwrap();
    assert_eq!(mp.generation(), 2);
    let txid = tx.compute_txid();
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    mp.store
        .set_now_ms(rbitcoin_mempool::store::PERSIST_INTERVAL_MS);
    mp.persist_due().unwrap();
    drop(mp);
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 1, "persist_due wrote {txid}");
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.store.set_now_ms(0);
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    mp.store
        .set_now_ms(rbitcoin_mempool::store::PERSIST_INTERVAL_MS);
    mp.persist_if_dirty().unwrap();
    drop(mp);
    let mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 1, "persist_if_dirty wrote the admit");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dead-slot quarter of the slot cap. Compacting or not leaves the same
/// live txs a client reads back. A session runs this when dead slots
/// reach a quarter of the table; the pin uses a 4-slot and a 5-slot cap
/// because the default table never gets there in a journey.
#[test]
fn maybe_compact_runs_when_dead_catches_live_or_nothing_live_remains() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 80_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let _a = mp
        .accept_tx(&spend_tx(ops[0], 90_000), &utxos, TIP_OK)
        .unwrap();
    let b = mp
        .accept_tx(&spend_tx(ops[1], 70_000), &utxos, TIP_OK)
        .unwrap();
    mp.store.mark_slot_dead(b.slot).unwrap();
    let (_f, live, dead) = mp.store.slot_stats();
    assert_eq!((live, dead), (1, 1));
    assert!(mp.maybe_compact().unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let a = mp.accept_tx(&spend_tx(op, 90_000), &utxos, TIP_OK).unwrap();
    mp.store.mark_slot_dead(a.slot).unwrap();
    let (_f, live, dead) = mp.store.slot_stats();
    assert_eq!((live, dead), (0, 1));
    assert!(mp.maybe_compact().unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);

    // Quarter of a cap of 4 is one dead slot, still under the live count.
    // `dead * 4 >= cap` compacts; `dead / 4 >= cap` does not.
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 90_000, 80_000, 70_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let mut slots = Vec::new();
    for (op, value) in ops.iter().zip([90_000, 80_000, 70_000, 60_000]) {
        slots.push(
            mp.accept_tx(&spend_tx(*op, value), &utxos, TIP_OK)
                .unwrap()
                .slot,
        );
    }
    mp.store.testing_pin_full_slot_table();
    mp.store.mark_slot_dead(slots[0]).unwrap();
    let (_f, live, dead) = mp.store.slot_stats();
    assert_eq!((mp.store.meta().slot_cap, live, dead), (4, 3, 1));
    assert!(
        mp.maybe_compact().unwrap().is_some(),
        "one dead slot is a quarter of a 4-slot table"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // Cap 5, one dead, three live: `dead * 4 >= cap` is false and dead is
    // still under live. `dead + 4 >= cap` would compact.
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 90_000, 80_000, 70_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let mut slots = Vec::new();
    for (op, value) in ops.iter().zip([90_000, 80_000, 70_000, 60_000]) {
        slots.push(
            mp.accept_tx(&spend_tx(*op, value), &utxos, TIP_OK)
                .unwrap()
                .slot,
        );
    }
    mp.store.testing_set_slot_cap(5);
    mp.store.mark_slot_dead(slots[0]).unwrap();
    let (_f, live, dead) = mp.store.slot_stats();
    assert_eq!((mp.store.meta().slot_cap, live, dead), (5, 3, 1));
    assert!(
        mp.maybe_compact().unwrap().is_none(),
        "one dead slot is under a quarter of a 5-slot table and under the live count"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Prepare/commit gap. A second `sendrawtransaction` takes `accept_tx`,
/// not a `PreparedAdmit` another thread already committed. The hub hits
/// this when the tx lands between prepare and commit.
#[test]
fn duplicate_commit_after_prepare_is_duplicate() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let prep = mp
        .prepare_admit(
            &tx,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
            },
        )
        .unwrap();
    mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
    let err = mp.commit_after_script(&tx, prep).unwrap_err();
    assert!(matches!(err, AcceptError::Duplicate(_)), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `IsChildWithParents` for `submitpackage` when
/// `RBITCOIN_RPC_PACKAGE_DIALECT` is on. Setting that variable in a test
/// races every other package RPC in the process, so this stays on the
/// function the RPC calls. A session with the flag rejects a package
/// whose last tx does not spend every other member.
#[test]
fn package_direct_parents_require_the_child_to_spend_each_member() {
    let (op, _, _) = chain_utxo(100_000);
    let parent = spend_tx(op, 90_000);
    let child = spend_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        80_000,
    );
    assert!(!ActiveMempool::package_is_child_with_direct_parents(
        std::slice::from_ref(&parent)
    ));
    assert!(ActiveMempool::package_is_child_with_direct_parents(&[
        parent.clone(),
        child.clone()
    ]));
    assert!(!ActiveMempool::package_is_child_with_direct_parents(&[
        child, parent
    ]));
    // The index compare is gone. A one-tx self-spend is not a peer
    // message, because the txid commits to the prevout. `seen.contains`
    // is what `testmempoolaccept` rejects.
    let src = include_str!("accept.rs");
    let start = src.find("pub fn check_package_shape(").expect("shape");
    let end = start
        + src[start..]
            .find("pub fn package_is_child_with_direct_parents(")
            .expect("child");
    let shape = &src[start..end];
    assert!(!shape.contains("p <"), "index compare must stay deleted");
    assert!(!shape.contains("i > p"));
    assert!(!shape.contains("<="));
    assert!(!shape.contains(">="));
}

/// Recent-reject and extra-txn maps. No RPC returns them. A later peer
/// announcement of the same invalid txid consults the map instead of
/// re-running script.
#[test]
fn recent_rejects_keep_every_id_under_the_cap() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let a = Txid::from_byte_array([0x11; 32]);
    let b = Txid::from_byte_array([0x22; 32]);
    mp.note_invalid(a);
    mp.note_invalid(b);
    assert!(mp.recent_invalid.contains(&a));
    assert!(mp.recent_invalid.contains(&b));
    let (op, _, _) = chain_utxo(50_000);
    let t1 = spend_tx(op, 40_000);
    let (op2, _, _) = chain_utxo(40_000);
    let t2 = spend_tx(op2, 30_000);
    mp.note_extra(&t1);
    mp.note_extra(&t2);
    assert!(mp.extra_by_txid(t1.compute_txid()).is_some());
    assert!(mp.extra_by_txid(t2.compute_txid()).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Filling the invalid set must not erase the oldest id. A new id past
/// the cap is not stored.
#[test]
fn recent_invalid_keeps_the_oldest() {
    let dir = tmp_dir();
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let first = Txid::from_byte_array({
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    });
    mp.note_invalid(first);
    // 2..4097 is 4095 ids and does not collide with `first`.
    for i in 2..4_097u32 {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&i.to_le_bytes());
        mp.note_invalid(Txid::from_byte_array(b));
    }
    let extra = Txid::from_byte_array([0xff; 32]);
    mp.note_invalid(extra);
    assert!(mp.recent_invalid.contains(&first));
    assert!(!mp.recent_invalid.contains(&extra));
    assert_eq!(mp.recent_invalid.len(), RECENT_INVALID_CAP);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Free-slot eviction. A session reaches it only when the slot table is
/// at `MAX_SLOT_CAP` (1_048_576) and every row is live. The pin pretends
/// the table is already there. Weight-budget eviction is the full-pool
/// journey; this is the slot-table stop.
#[test]
fn a_full_pinned_slot_table_evicts_one_chunk_then_stops() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 90_000, 80_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let cheap = spend_tx(ops[0], 70_000);
    let mid = spend_tx(ops[1], 60_000);
    let incoming = spend_tx(ops[2], 50_000);
    mp.accept_tx(&cheap, &utxos, TIP_OK).unwrap();
    mp.accept_tx(&mid, &utxos, TIP_OK).unwrap();
    mp.store.testing_pin_full_slot_table();
    mp.accept_tx(&incoming, &utxos, TIP_OK).unwrap();
    assert_eq!(mp.live_count(), 2, "one eviction frees the pinned table");
    assert!(mp.graph.contains(&incoming.compute_txid()));
    // DEAD is a free slot, so eviction stops on the next pass. The old
    // `guard += 1` / 10000 cap cannot be reached by a freed slot.
    let src = include_str!("accept.rs");
    let start = src.find("fn evict_worst_chunks(").expect("evict");
    let end = start
        + src[start..]
            .find("fn evict_worst_chunk_once(")
            .expect("once");
    let evict = &src[start..end];
    assert!(!evict.contains("+="), "eviction cap must stay deleted");
    assert!(!evict.contains("10_000"));
    assert!(!evict.contains("saturating_add"));
    assert!(!evict.contains("||"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn trust_logs() -> String {
    rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn waive_opts() -> PrepareOpts {
    PrepareOpts {
        fee_delta: 0,
        report_orphans: true,
        min_relay: None,
        waive: true,
        ephemeral_ok: false,
    }
}

/// The session bit is `PrepareOpts::waive`. Script faults are stashed the
/// same way `accept_tx_with` stashes them, then logged only after commit.
fn prepare_waived(
    mp: &ActiveMempool,
    tx: &Transaction,
    utxos: &MapUtxoProvider,
    tip: ChainTipCtx,
) -> Result<PreparedAdmit, AcceptError> {
    let mut prep = mp.prepare_admit(tx, utxos, tip, waive_opts())?;
    if let Err(e) = verify_tx_scripts(tx, prep.prevouts.clone()) {
        let reason = e.mempool_reject_reason();
        if !rbitcoin_consensus::reason_is_warn_and_apply(&reason) {
            return Err(e);
        }
        prep.trust_warn.get_or_insert_with(Vec::new).push(reason);
    }
    Ok(prep)
}

fn admit_waived(
    mp: &mut ActiveMempool,
    tx: &Transaction,
    utxos: &MapUtxoProvider,
    tip: ChainTipCtx,
) -> Result<AcceptResult, AcceptError> {
    let prep = prepare_waived(mp, tx, utxos, tip)?;
    mp.commit_after_script(tx, prep)
}

/// A failed replacement puts a warned tx back. Reopening with the mode off
/// drops the mark, so the next non-final eviction removes the tx.
#[test]
fn trust_kept_survives_failed_replacement_and_restart() {
    let dir = tmp_dir();
    let op = OutPoint {
        txid: Txid::from_byte_array([0x61; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut victim = spend_tx(op, 99_000);
    victim.lock_time = LockTime::from_height(500).unwrap();
    victim.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let tip = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &victim, &utxos, tip)
        .expect("nonfinal")
        .txid;
    assert!(mp.trust_kept.contains(&id));

    mp.store.fail_next_append = true;
    let err = mp
        .accept_tx(&spend_tx(op, 90_000), &utxos, tip)
        .expect_err("replacement insert fails");
    assert!(matches!(err, AcceptError::Policy("mempool full")), "{err}");
    assert!(
        mp.graph.contains(&id),
        "failed replacement dropped the warned tx"
    );
    assert!(mp.trust_kept.contains(&id), "trust mark was not restored");
    mp.evict_nonfinal(&utxos, tip);
    assert!(mp.graph.contains(&id), "evict dropped the restored tx");

    mp.flush().unwrap();
    drop(mp);
    let mut again = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(
        again.trust_kept.contains(&id),
        "flag-on open keeps the mark"
    );
    again.discard_trust_marks().unwrap();
    drop(again);
    let mut off = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(
        !off.trust_kept.contains(&id),
        "flag-off reopen reloaded the mark"
    );
    off.evict_nonfinal(&utxos, tip);
    assert!(
        !off.graph.contains(&id),
        "eviction after a flag-off reopen kept the tx"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A script-invalid tx is not put back once the mode is off.
#[test]
fn review_trust_flag_off_does_not_restore_bad_script() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x21; 20]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x62; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut bad = spend_tx(op, 99_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &bad, &utxos, TIP_OK)
        .expect("script warns")
        .txid;
    assert!(mp.trust_kept.contains(&id));
    let child = spend_tx(OutPoint { txid: id, vout: 0 }, 80_000);
    let child_id = mp
        .accept_tx(&child, &utxos, TIP_OK)
        .expect("child of marked")
        .txid;
    mp.flush().unwrap();
    drop(mp);
    let mut again = ActiveMempool::open_or_create(&dir).unwrap();
    again.discard_trust_marks().unwrap();
    assert!(!again.graph.contains(&id), "discard left the marked body");
    assert!(
        !again.graph.contains(&child_id),
        "discard left a descendant"
    );
    assert!(!again.trust_kept.contains(&id));
    drop(again);
    let mut off = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(!off.graph.contains(&id), "flag-off open reloaded the body");
    assert!(!off.graph.contains(&child_id));
    assert!(!off.trust_kept.contains(&id));
    let picked = off.select_block_template(off.template_budget(0), |_| 0);
    assert!(
        picked
            .iter()
            .all(|(_, s)| s.txid != id && s.txid != child_id),
        "a dropped tx was selected"
    );
    let err = off.accept_tx(&bad, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::Script(_)), "{err}");
    assert!(!off.graph.contains(&id));
    assert!(!off.trust_kept.contains(&id), "absent tx still marked");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing body makes unlink fail. The mark stays, and a reopen does not
/// load the body as an ordinary pool transaction.
#[test]
fn review_trust_flag_off_unlink_failure_keeps_the_mark() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x31; 20]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x63; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut bad = spend_tx(op, 99_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &bad, &utxos, TIP_OK)
        .expect("script warns")
        .txid;
    mp.flush().unwrap();
    mp.bodies.remove(&id);
    let err = mp.discard_trust_marks().unwrap_err();
    assert!(
        mp.trust_kept.contains(&id),
        "failed removal cleared the mark: {err}"
    );
    assert!(mp.graph.contains(&id), "failed removal dropped the entry");
    drop(mp);
    let off = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(off.trust_kept.contains(&id), "reopen lost the mark");
    let picked = off.select_block_template(off.template_budget(0), |_| 0);
    assert!(
        picked.iter().all(|(_, s)| s.txid != id),
        "a marked body was selected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing child body fails before the parent is unlinked. The mark stays,
/// the child stays in the graph, and the parent's death is not synced.
#[test]
fn review_trust_flag_off_child_unlink_keeps_the_mark() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x33; 20]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x65; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut bad = spend_tx(op, 99_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &bad, &utxos, TIP_OK)
        .expect("script warns")
        .txid;
    let child = spend_tx(OutPoint { txid: id, vout: 0 }, 80_000);
    let child_id = mp
        .accept_tx(&child, &utxos, TIP_OK)
        .expect("child of marked")
        .txid;
    mp.flush().unwrap();
    let syncs = mp.death_sync_counts();
    mp.bodies.remove(&child_id);
    let err = mp.discard_trust_marks().unwrap_err();
    assert!(
        mp.trust_kept.contains(&id),
        "failed child removal cleared the mark: {err}"
    );
    assert!(
        mp.graph.contains(&id),
        "failed child removal dropped the parent"
    );
    assert!(
        mp.graph.contains(&child_id),
        "failed child removal dropped the child"
    );
    assert_eq!(
        mp.death_sync_counts(),
        syncs,
        "a failed discard synced deaths"
    );
    drop(mp);
    let off = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(off.trust_kept.contains(&id), "reopen lost the parent mark");
    assert!(off.graph.contains(&child_id), "reopen lost the child");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two LIVE slots for one warned txid. Flag-off open must not leave the
/// leftover slot as an unmarked body a template can select.
#[test]
fn review_trust_flag_off_duplicate_live_slot_is_not_ordinary() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x32; 20]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x64; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut bad = spend_tx(op, 99_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &bad, &utxos, TIP_OK)
        .expect("script warns")
        .txid;
    mp.flush().unwrap();
    duplicate_live_trust_slot(&mut mp);
    mp.flush().unwrap();
    drop(mp);
    let mut again = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(again.graph.contains(&id));
    assert!(again.trust_kept.contains(&id));
    again.discard_trust_marks().unwrap();
    drop(again);
    let off = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(!off.graph.contains(&id), "duplicate slot reloaded the body");
    assert!(!off.trust_kept.contains(&id));
    let picked = off.select_block_template(off.template_budget(0), |_| 0);
    assert!(
        picked.iter().all(|(_, s)| s.txid != id),
        "an unmarked leftover was selected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Copy one LIVE trust slot onto a free index. The node never writes this.
fn duplicate_live_trust_slot(mp: &mut ActiveMempool) {
    use rbitcoin_mempool::store::{SLOTS_HEADER, SLOT_FREE, SLOT_LIVE, SLOT_REC};

    let cap = mp.store.slot_cap as usize;
    let mut src = None;
    let mut dst = None;
    for slot in 0..cap {
        let off = SLOTS_HEADER + slot * SLOT_REC;
        match mp.store.slots[off] {
            SLOT_LIVE if src.is_none() => src = Some(off),
            SLOT_FREE if dst.is_none() => dst = Some(off),
            _ => {}
        }
    }
    let src = src.expect("live slot");
    let dst = dst.expect("free slot");
    let rec = mp.store.slots[src..src + SLOT_REC].to_vec();
    mp.store.slots[dst..dst + SLOT_REC].copy_from_slice(&rec);
    mp.store.set_live_count(mp.store.live_count + 1);
}

/// A waived admit that does not warn is not marked. A later low tip evicts it,
/// and a restart does not bring the mark back.
#[test]
fn review_trust_clean_admit_is_not_marked() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    tx.lock_time = LockTime::from_height(500).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let low = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &tx, &utxos, TIP_OK)
        .expect("final at TIP_OK")
        .txid;
    assert!(!mp.trust_kept.contains(&id), "a clean admit was marked");
    mp.evict_nonfinal(&utxos, low);
    assert!(!mp.graph.contains(&id));
    mp.flush().unwrap();
    drop(mp);
    let mut again = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(!again.trust_kept.contains(&id));
    again.evict_nonfinal(&utxos, low);
    assert!(!again.graph.contains(&id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A warned tx put back while it is currently valid keeps the slot byte.
#[test]
fn review_trust_restored_mark_survives_restart() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    tx.lock_time = LockTime::from_height(500).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let low = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &tx, &utxos, low)
        .expect("nonfinal")
        .txid;
    assert!(mp.trust_kept.contains(&id));
    mp.store.fail_next_append = true;
    let err = mp
        .accept_tx(&spend_tx(op, 90_000), &utxos, TIP_OK)
        .expect_err("replacement insert fails");
    assert!(matches!(err, AcceptError::Policy("mempool full")), "{err}");
    assert!(mp.graph.contains(&id));
    assert!(mp.trust_kept.contains(&id));
    mp.flush().unwrap();
    drop(mp);
    let mut again = ActiveMempool::open_or_create(&dir).unwrap();
    assert!(again.trust_kept.contains(&id), "restart dropped the mark");
    again.evict_nonfinal(&utxos, low);
    assert!(
        again.graph.contains(&id),
        "eviction after restart dropped the warned tx"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A package that fails after replacing a warned tx puts that tx back marked.
#[test]
fn review_trust_package_rollback_keeps_warned_victim() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    tx.lock_time = LockTime::from_height(500).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let low = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &tx, &utxos, low)
        .expect("nonfinal")
        .txid;
    let replacement = spend_tx(op, 90_000);
    let mut child = spend_tx(
        OutPoint {
            txid: replacement.compute_txid(),
            vout: 0,
        },
        80_000,
    );
    child.lock_time = LockTime::from_height(500).unwrap();
    child.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let err = mp
        .accept_package(&[replacement.clone(), child], &utxos, low)
        .unwrap_err();
    assert!(matches!(err, AcceptError::NotFinal), "{err}");
    assert!(!mp.graph.contains(&replacement.compute_txid()));
    assert!(
        mp.graph.contains(&id),
        "failed package lost the warned victim"
    );
    assert!(mp.trust_kept.contains(&id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A victim that cannot be put back does not keep its mark.
#[test]
fn review_trust_failed_restore_drops_mark() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    tx.lock_time = LockTime::from_height(500).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let low = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let id = admit_waived(&mut mp, &tx, &utxos, low)
        .expect("nonfinal")
        .txid;
    let replacement = spend_tx(op, 90_000);
    let prep = mp
        .prepare_admit(
            &replacement,
            &utxos,
            TIP_OK,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: Some(0),
                waive: false,
                ephemeral_ok: false,
            },
        )
        .expect("replacement prepares");
    mp.store.fail_next_append = true;
    assert!(mp.commit_after_script(&replacement, prep).is_err());
    let empty = MapUtxoProvider {
        map: HashMap::new(),
    };
    mp.restore_undone(&empty, low);
    assert!(!mp.graph.contains(&id));
    assert!(!mp.trust_kept.contains(&id), "absent tx still marked");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A marked tx is not mined, and neither is a child that needs it.
/// A clean tx in the same pool still is.
#[test]
fn review_trust_template_skips_marked_chunk() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let clean = spend_tx(ops[0], 90_000);
    let mut bad = spend_tx(ops[1], 90_000);
    bad.lock_time = LockTime::from_height(500).unwrap();
    bad.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let low = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let clean_id = mp.accept_tx(&clean, &utxos, TIP_OK).expect("clean").txid;
    let bad_id = admit_waived(&mut mp, &bad, &utxos, low)
        .expect("nonfinal")
        .txid;
    assert!(mp.trust_kept.contains(&bad_id));
    let child = spend_tx(
        OutPoint {
            txid: bad_id,
            vout: 0,
        },
        80_000,
    );
    let child_id = mp
        .accept_tx(&child, &utxos, TIP_OK)
        .expect("child of marked")
        .txid;
    let picked = mp.select_block_template(mp.template_budget(0), |_| 0);
    let ids: Vec<_> = picked.iter().map(|(_, s)| s.txid).collect();
    assert!(ids.contains(&clean_id), "clean tx was skipped");
    assert!(!ids.contains(&bad_id), "marked tx was selected");
    assert!(
        !ids.contains(&child_id),
        "child of a marked tx was selected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Script, non-final, immature, and BIP68 faults admit when the session
/// waive bit is set, and stay through non-final eviction. `accept_tx` stays
/// strict even when the process flag is on. Policy and a missing parent drop.
#[test]
fn trust_peer_admit_keeps_fee_and_skips_evict() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x11; 20]);
    let spk = ScriptBuf::new_p2wpkh(&wpkh);
    let op = OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: 0,
    };
    let txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: spk,
    };
    let mut map = HashMap::new();
    map.insert(op, coin(txout));
    let utxos = MapUtxoProvider { map };
    let mut parent = spend_tx(op, 99_000);
    parent.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let off = mp.accept_tx(&parent, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(off, AcceptError::Script(_)), "{off}");
    assert_eq!(mp.live_count(), 0);
    let off_log = trust_logs();
    assert!(!off_log.contains("trust-peer:"), "{off_log}");

    rbitcoin_log::capture_logs(true);
    let local = mp.accept_tx(&parent, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(local, AcceptError::Script(_)), "{local}");
    assert_eq!(mp.live_count(), 0);
    let local_log = trust_logs();
    assert!(!local_log.contains("trust-peer:"), "{local_log}");

    rbitcoin_log::capture_logs(true);
    let got = admit_waived(&mut mp, &parent, &utxos, TIP_OK).expect("script warns");
    assert_eq!(got.fee_sat, 1_000);
    let parent_id = parent.compute_txid();
    let entry = mp.graph.get(&parent_id).expect("stored");
    assert_eq!(entry.fee_sat, 1_000);
    let on = trust_logs();
    assert!(
        on.contains(&format!("trust-peer: applied tx {parent_id}:")),
        "{on}"
    );
    assert!(on.contains("script verification"), "{on}");

    let child = spend_tx(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        98_000,
    );
    let child_got = mp.accept_tx(&child, &utxos, TIP_OK).expect("child");
    assert_eq!(child_got.fee_sat, 1_000);
    let child_id = child.compute_txid();
    assert!(mp
        .graph
        .get(&child_id)
        .expect("child stored")
        .parents
        .contains(&parent_id));

    let mut dusty = spend_tx(op, 0);
    dusty.lock_time = LockTime::from_height(500).unwrap();
    dusty.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    dusty.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
    rbitcoin_log::capture_logs(true);
    let policy = mp.accept_tx(&dusty, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(policy, AcceptError::Policy("dust")), "{policy}");
    let policy_log = trust_logs();
    assert!(!policy_log.contains("trust-peer:"), "{policy_log}");

    let (nf_id, op_n, nutxos) = waived_lock_faults_stay(&mut mp);
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    mp.evict_nonfinal(
        &MapUtxoProvider {
            map: HashMap::new(),
        },
        ChainTipCtx {
            height: 100,
            mtp: u32::MAX,
        },
    );
    assert!(!mp.graph.contains(&nf_id), "a missing parent still leaves");
    let gone = trust_logs();
    assert!(!gone.contains("trust-peer:"), "{gone}");
    assert_duplicate_inputs_not_applied(&mut mp, &nutxos, op_n);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Non-final, immature, and BIP68 admits stay through eviction.
fn waived_lock_faults_stay(mp: &mut ActiveMempool) -> (Txid, OutPoint, MapUtxoProvider) {
    let op_n = OutPoint {
        txid: Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let mut nmap = HashMap::new();
    nmap.insert(
        op_n,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }),
    );
    let nutxos = MapUtxoProvider { map: nmap };
    let mut nonfinal = spend_tx(op_n, 99_000);
    nonfinal.lock_time = LockTime::from_height(500).unwrap();
    nonfinal.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let tip = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    rbitcoin_log::capture_logs(true);
    let nf = admit_waived(mp, &nonfinal, &nutxos, tip).expect("nonfinal");
    let nf_id = nonfinal.compute_txid();
    assert_eq!(nf.fee_sat, 1_000);
    let nf_log = trust_logs();
    assert!(
        nf_log.contains(&format!("trust-peer: applied tx {nf_id}:")),
        "{nf_log}"
    );
    assert!(nf_log.contains("not final"), "{nf_log}");
    mp.evict_nonfinal(&nutxos, tip);
    assert!(mp.graph.contains(&nf_id), "evict keeps the warned fault");

    let op_i = OutPoint {
        txid: Txid::from_byte_array([0x33; 32]),
        vout: 0,
    };
    let mut imap = HashMap::new();
    imap.insert(
        op_i,
        Coin {
            txout: TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 50,
            create_mtp: 0,
            is_coinbase: true,
            create_fk: None,
        },
    );
    let iutxos = MapUtxoProvider { map: imap };
    let immature = spend_tx(op_i, 49_0000_0000);
    admit_waived(mp, &immature, &iutxos, tip).expect("immature");
    let im_id = immature.compute_txid();
    mp.evict_nonfinal(&iutxos, tip);
    assert!(mp.graph.contains(&im_id));

    let op_b = OutPoint {
        txid: Txid::from_byte_array([0x44; 32]),
        vout: 0,
    };
    let mut bmap = HashMap::new();
    bmap.insert(
        op_b,
        Coin {
            txout: TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 10,
            create_mtp: 1_000_000,
            is_coinbase: false,
            create_fk: None,
        },
    );
    let butxos = MapUtxoProvider { map: bmap };
    let mut bip68 = spend_tx(op_b, 49_000);
    bip68.version = Version::TWO;
    bip68.input[0].sequence = Sequence::from_consensus((1 << 22) | 2);
    let btip = ChainTipCtx {
        height: 20,
        mtp: 1_001_000,
    };
    admit_waived(mp, &bip68, &butxos, btip).expect("bip68");
    let b_id = bip68.compute_txid();
    mp.evict_nonfinal(&butxos, btip);
    assert!(mp.graph.contains(&b_id));
    (nf_id, op_n, nutxos)
}

fn assert_duplicate_inputs_not_applied(
    mp: &mut ActiveMempool,
    utxos: &MapUtxoProvider,
    op: OutPoint,
) {
    let mut dup = spend_tx(op, 50_000);
    dup.input.push(dup.input[0].clone());
    rbitcoin_log::capture_logs(true);
    let dup_err = mp.accept_tx(&dup, utxos, TIP_OK).unwrap_err();
    assert!(matches!(dup_err, AcceptError::InputsDuplicate), "{dup_err}");
    let dup_id = dup.compute_txid();
    let local_log = trust_logs();
    assert!(!local_log.contains("trust-peer:"), "{local_log}");
    rbitcoin_log::capture_logs(true);
    let waived = mp
        .prepare_admit(&dup, utxos, TIP_OK, waive_opts())
        .unwrap_err();
    assert!(matches!(waived, AcceptError::InputsDuplicate), "{waived}");
    let dup_log = trust_logs();
    assert!(
        dup_log.contains(&format!("trust-peer: not applied tx {dup_id}:")),
        "{dup_log}"
    );
    assert!(dup_log.contains("inputs-duplicate"), "{dup_log}");
    assert!(!mp.graph.contains(&dup_id));
}

/// `repark_lifted` is a local retry. The process flag does not waive it.
#[test]
fn review_trust_repark_does_not_use_process_bit() {
    let dir = tmp_dir();
    let (op, _, utxos) = chain_utxo(100_000);
    let mut tx = spend_tx(op, 99_000);
    tx.lock_time = LockTime::from_height(500).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let tip = ChainTipCtx {
        height: 100,
        mtp: u32::MAX,
    };
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let lifted = LiftedOrphan {
        tx: tx.clone(),
        announcers: vec![1],
        taken_gen: 0,
    };
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let ready = mp.repark_lifted(std::slice::from_ref(&lifted), &utxos, tip, &|_| 0, None);
    assert!(ready.is_empty(), "a local non-final orphan is not ready");
    assert!(!mp.graph.contains(&tx.compute_txid()));
    let logs = trust_logs();
    assert!(!logs.contains("trust-peer:"), "{logs}");
    rbitcoin_log::capture_logs(false);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A waived script is logged only after the tx is in the pool. A script
/// fault that then loses the cluster limit logs nothing and stays out.
#[test]
fn review_trust_applied_tx_logs_after_commit() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let wpkh = WPubkeyHash::from_byte_array([0x11; 20]);
    let spk = ScriptBuf::new_p2wpkh(&wpkh);
    let op = OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        }),
    );
    let utxos = MapUtxoProvider { map };
    let mut bad = spend_tx(op, 99_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let local = mp.accept_tx(&bad, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(local, AcceptError::Script(_)), "{local}");
    assert!(!mp.graph.contains(&bad.compute_txid()));
    let local_log = trust_logs();
    assert!(!local_log.contains("trust-peer:"), "{local_log}");

    rbitcoin_log::capture_logs(true);
    let got = admit_waived(&mut mp, &bad, &utxos, TIP_OK).expect("script warns");
    let txid = bad.compute_txid();
    assert_eq!(got.txid, txid);
    assert!(mp.graph.contains(&txid));
    let on = trust_logs();
    let needle = format!("trust-peer: applied tx {txid}:");
    assert_eq!(on.matches(&needle).count(), 1, "{on}");
    assert!(on.contains("script verification"), "{on}");

    let op2 = OutPoint {
        txid: Txid::from_byte_array([0xcd; 32]),
        vout: 0,
    };
    let mut map2 = HashMap::new();
    map2.insert(
        op2,
        coin(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        }),
    );
    let utxos2 = MapUtxoProvider { map: map2 };
    let mut crowded = spend_tx(op2, 99_000);
    crowded.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let prep = prepare_waived(&mp, &crowded, &utxos2, TIP_OK).expect("script stashed");
    assert!(prep.trust_warn.is_some());
    mp.set_cluster_limits(None, Some(0));
    rbitcoin_log::capture_logs(true);
    let err = mp.commit_after_script(&crowded, prep).unwrap_err();
    assert!(matches!(err, AcceptError::ClusterTooLarge { .. }), "{err}");
    let crowded_id = crowded.compute_txid();
    assert!(!mp.graph.contains(&crowded_id));
    let lost = trust_logs();
    assert!(
        !lost.contains("trust-peer:"),
        "a waived script that does not commit must not log: {lost}"
    );
    rbitcoin_log::capture_logs(false);
    let _ = std::fs::remove_dir_all(&dir);
}

include!("accept_life_journey.rs");

#[test]
fn promote_keeps_the_announcer_of_a_multi_parent_orphan() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent_a = spend_tx(ops[0], 99_000);
    let parent_b = spend_tx(ops[1], 99_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_a.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_b.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(197_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent_a.compute_txid());
    missing.insert(parent_b.compute_txid());
    mp.park_orphan_from(&child, missing, Some(4));
    mp.accept_tx(&parent_a, &utxos, TIP_OK)
        .expect("first parent");
    assert_eq!(
        mp.orphanage.announcers_of(&child_id),
        vec![4],
        "the repark must keep the announcing peer"
    );
    mp.orphanage.erase_for_peer(4);
    assert!(
        !mp.orphanage.contains(&child_id),
        "a disconnect of the only announcer must drop the orphan"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disconnect_while_the_orphan_is_out_is_not_reparked() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent_a = spend_tx(ops[0], 99_000);
    let parent_b = spend_tx(ops[1], 99_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_a.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_b.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(197_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent_a.compute_txid());
    missing.insert(parent_b.compute_txid());
    mp.park_orphan_from(&child, missing.clone(), Some(4));
    mp.orphanage.add_announcer(&child_id, 8);
    let _taken = mp.orphanage.take_children_of(&parent_a.compute_txid());
    mp.orphanage.erase_for_peer(4);
    let _ = mp.park_announced(&child, missing.clone(), &[4, 8]);
    assert_eq!(
        mp.orphanage.announcers_of(&child_id),
        vec![8],
        "only the peer that is still connected is restored"
    );
    let _taken = mp.orphanage.take_children_of(&parent_b.compute_txid());
    mp.orphanage.erase_for_peer(8);
    let _ = mp.park_announced(&child, missing, &[8]);
    assert!(
        !mp.orphanage.contains(&child_id),
        "the last live announcer disconnecting while the orphan is out drops it on repark"
    );
    let _ = utxos;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn older_promote_forget_does_not_clear_a_newer_take() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent_a = spend_tx(ops[0], 99_000);
    let parent_b = spend_tx(ops[1], 99_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_a.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_b.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(197_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent_a.compute_txid());
    missing.insert(parent_b.compute_txid());
    mp.park_orphan_from(&child, missing.clone(), Some(4));
    let first = mp.orphanage.take_children_of(&parent_a.compute_txid());
    let old_gen = first[0].taken_gen;
    let _ = mp.park_announced(&child, missing.clone(), &[4]);
    let second = mp.orphanage.take_children_of(&parent_b.compute_txid());
    assert_eq!(
        second.len(),
        1,
        "the second promote took the reparked child"
    );
    mp.orphanage.forget_taken_gen(&child_id, old_gen);
    mp.orphanage.erase_for_peer(4);
    let _ = mp.park_announced(&child, missing, &[4]);
    assert!(
        !mp.orphanage.contains(&child_id),
        "a forget from the first promote must not drop the second promote's disconnect"
    );
    let _ = utxos;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn package_lift_disconnect_is_not_reparked() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent_a = spend_tx(ops[0], 99_000);
    let parent_b = spend_tx(ops[1], 99_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_a.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: parent_b.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(197_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent_a.compute_txid());
    missing.insert(parent_b.compute_txid());
    mp.park_orphan_from(&child, missing.clone(), Some(4));
    mp.orphanage.add_announcer(&child_id, 8);
    let lifted = mp.lift_parked_member(&child).unwrap();
    mp.orphanage.erase_for_peer(4);
    let _ = mp.park_announced(&lifted.tx, missing.clone(), &lifted.announcers);
    assert_eq!(
        mp.orphanage.announcers_of(&child_id),
        vec![8],
        "a disconnect during a package lift drops that peer"
    );
    let lifted = mp.lift_parked_member(&child).unwrap();
    mp.orphanage.erase_for_peer(8);
    let _ = mp.park_announced(&lifted.tx, missing, &lifted.announcers);
    assert!(
        !mp.orphanage.contains(&child_id),
        "the last announcer disconnecting during a package lift drops the orphan"
    );
    let _ = utxos;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn package_admit_drops_the_inflight_row() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent = spend_tx(ops[0], 99_000);
    let child = spend_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        98_000,
    );
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent.compute_txid());
    mp.park_orphan_from(&child, missing, Some(4));
    mp.accept_package(&[parent, child], &utxos, TIP_OK)
        .expect("package admits the parked child");
    assert!(mp.graph.contains(&child_id));
    assert!(
        !mp.orphanage.has_announcer(4),
        "an admitted lift must not keep the peer in the in-flight map"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn package_rollback_admit_drops_the_inflight_row() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000, 50_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent = spend_tx(ops[0], 99_000);
    mp.accept_tx(&parent, &utxos, TIP_OK).expect("parent");
    let child = spend_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        98_000,
    );
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent.compute_txid());
    mp.park_orphan_from(&child, missing, Some(4));
    let bad = spend_tx(ops[1], 60_000);
    let err = mp
        .accept_package(&[child, bad], &utxos, TIP_OK)
        .expect_err("the overspend fails the package");
    assert!(
        mp.graph.contains(&child_id),
        "the lifted child is admitted on its own, got {err}"
    );
    assert!(
        !mp.orphanage.has_announcer(4),
        "that admit must not keep the peer in the in-flight map"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn package_rollback_reject_drops_the_inflight_row() {
    use bitcoin::WPubkeyHash;

    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[100_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20]));
    let parent = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: ops[0],
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: spk,
        }],
    };
    mp.accept_tx(&parent, &utxos, TIP_OK).expect("parent");
    let child = spend_tx(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        98_000,
    );
    let child_id = child.compute_txid();
    let mut missing = BTreeSet::new();
    missing.insert(parent.compute_txid());
    mp.park_orphan_from(&child, missing, Some(4));
    let err = mp
        .accept_package(std::slice::from_ref(&child), &utxos, TIP_OK)
        .expect_err("empty witness cannot spend the parent");
    assert!(
        matches!(err, AcceptError::Script(_)),
        "script failure, got {err}"
    );
    assert!(!mp.graph.contains(&child_id));
    assert!(
        !mp.orphanage.contains(&child_id),
        "a script failure must not put the lifted child back"
    );
    assert!(
        !mp.orphanage.has_announcer(4),
        "a rejected lift must not keep its peer"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn anchor_tx(inputs: &[OutPoint], pay: u64, anchor: u64) -> Transaction {
    Transaction {
        version: Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .copied()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![
            TxOut {
                value: Amount::from_sat(pay),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(anchor),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    }
}

#[test]
fn ephemeral_anchor_enters_only_inside_a_package() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(&[50_000, 20_000, 50_000, 20_000, 50_000]);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

    let lone = anchor_tx(&[ops[0]], 50_000, 0);
    let err = mp.accept_tx(&lone, &utxos, TIP_OK).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("dust")), "{err}");

    let parent = anchor_tx(&[ops[0]], 50_000, 0);
    let child = anchor_tx(
        &[
            OutPoint {
                txid: parent.compute_txid(),
                vout: 1,
            },
            ops[1],
        ],
        10_000,
        1,
    );
    mp.accept_package(&[parent.clone(), child], &utxos, TIP_OK)
        .expect("0-fee parent with one 0-value output, spent by the child");

    let paying = anchor_tx(&[ops[2]], 40_000, 0);
    let paying_child = anchor_tx(
        &[
            OutPoint {
                txid: paying.compute_txid(),
                vout: 1,
            },
            ops[3],
        ],
        10_000,
        1,
    );
    let err = mp
        .accept_package(&[paying, paying_child], &utxos, TIP_OK)
        .unwrap_err();
    assert!(matches!(err, AcceptError::Policy("dust")), "{err}");

    let skipped = anchor_tx(&[ops[4]], 50_000, 0);
    let spends_value = Transaction {
        version: Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: skipped.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = mp
        .accept_package(&[skipped, spends_value], &utxos, TIP_OK)
        .unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("missing-ephemeral-spends")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
