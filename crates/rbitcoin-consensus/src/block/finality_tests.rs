//! finality_tests (peeled from block.rs).

use super::{is_final_tx, sequence_locks_satisfied, LOCKTIME_THRESHOLD};
use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

fn bare_tx(version: i32, lock_time: LockTime, sequence: Sequence) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
// btc-lean: BLK-066 BLK-067 BLK-068 INV-011 INV-012 INV-013 INV-014 INV-015 INV-016 INV-017 INV-018
// btc-lean: INV-019 INV-020 INV-021 INV-108 TXV-027 TXV-028 TXV-029 TXV-030 TXV-031 TXV-032 TXV-034
// btc-lean: TXV-035 TXV-036 TXV-037 TXV-038 TXV-039 TXV-040
fn sequence_final_ignores_locktime() {
    let tx = bare_tx(1, LockTime::from_height(100).unwrap(), Sequence::MAX);
    assert!(is_final_tx(&tx, 50, 1_000_000));
}

#[test]
fn time_locktime_uses_cutoff() {
    let t = LOCKTIME_THRESHOLD + 1000;
    let tx = bare_tx(1, LockTime::from_time(t).unwrap(), Sequence::ZERO);
    assert!(!is_final_tx(&tx, 1, t)); // need lt < cutoff
    assert!(is_final_tx(&tx, 1, t + 1));
}

#[test]
fn bip68_height_relative_lock() {
    // version 2, seq = 10 (height), coin at height 100 → minHeight = 100+10-1 = 109
    // needs block_height > 109
    let tx = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(10));
    assert!(!sequence_locks_satisfied(&tx, &[100], &[0], 109, 0));
    assert!(sequence_locks_satisfied(&tx, &[100], &[0], 110, 0));
}

#[test]
fn bip68_disabled_by_version_1() {
    let tx = bare_tx(1, LockTime::ZERO, Sequence::from_consensus(10));
    assert!(sequence_locks_satisfied(&tx, &[100], &[0], 50, 0));
}

/// Core treats nVersion as unsigned: 0xFFFFFFFF ≥ 2 → BIP68 enforced
/// (`docs/external_findings/003-bip68-version-signedness-consensus-split.md`).
#[test]
fn bip68_enforced_when_version_high_bit_set() {
    // rust-bitcoin Version(i32): -1 is wire 0xFFFFFFFF.
    let tx = bare_tx(-1, LockTime::ZERO, Sequence::from_consensus(10));
    assert!(super::bip68_active_for_tx(&tx));
    // Same relative height lock as bip68_height_relative_lock — must fail at h=109.
    assert!(!sequence_locks_satisfied(&tx, &[100], &[0], 109, 0));
    assert!(sequence_locks_satisfied(&tx, &[100], &[0], 110, 0));
}

#[test]
fn bip68_disable_flag_and_time_type() {
    // DISABLE bit → ignore relative lock.
    let disable = 1u32 << 31;
    let tx = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(disable | 10));
    assert!(sequence_locks_satisfied(&tx, &[100], &[0], 50, 0));

    // Time-based: TYPE_FLAG | n, granularity 512s.
    let type_flag = 1u32 << 22;
    let n = 2u32; // 2 × 512s relative
    let tx = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(type_flag | n));
    // coin MTP = 1000; minTime ≈ 1000 + (2<<9) - 1
    let coin_mtp = 1000u32;
    let min_time = coin_mtp as i64 + ((n as i64) << 9) - 1;
    assert!(!sequence_locks_satisfied(
        &tx,
        &[100],
        &[coin_mtp],
        200,
        (min_time as u32).saturating_sub(1)
    ));
    assert!(sequence_locks_satisfied(
        &tx,
        &[100],
        &[coin_mtp],
        200,
        min_time as u32 + 1
    ));
}

/// A missing height slice or a zero coin MTP fails closed.
/// Height 0 is the genesis coin. Same-block callers pass spend height.
#[test]
fn bip68_unresolved_coin_age_fails_closed() {
    let type_flag = 1u32 << 22;
    let tx_h = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(10));
    let tx_t = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(type_flag | 2));
    // Missing height entry.
    assert!(!sequence_locks_satisfied(&tx_h, &[], &[0], 110, 1_000_000));
    // Height 0 is the genesis coin (relative height 10 spends from block 10).
    assert!(sequence_locks_satisfied(&tx_h, &[0], &[0], 10, 1_000_000));
    assert!(!sequence_locks_satisfied(&tx_h, &[0], &[0], 9, 1_000_000));
    // Time-type with MTP 0 / missing.
    assert!(!sequence_locks_satisfied(
        &tx_t,
        &[100],
        &[0],
        200,
        1_000_000
    ));
    assert!(!sequence_locks_satisfied(
        &tx_t,
        &[100],
        &[],
        200,
        1_000_000
    ));
    // Control: known ages still work.
    assert!(sequence_locks_satisfied(&tx_h, &[100], &[0], 110, 0));
}

#[test]
fn bip68_height_zero_time_lock_uses_the_median() {
    let type_flag = 1u32 << 22;
    let tx = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(type_flag));
    let mtp = 1_231_006_505u32;
    assert!(
        !sequence_locks_satisfied(&tx, &[0], &[0], 1, mtp),
        "a zero median is unresolved"
    );
    assert!(sequence_locks_satisfied(&tx, &[0], &[mtp], 1, mtp));
    assert!(!sequence_locks_satisfied(
        &tx,
        &[0],
        &[mtp],
        1,
        mtp.saturating_sub(1)
    ));
}

/// Exactly 500_000_000 is a timestamp. One below the threshold is a height.
#[test]
fn locktime_at_threshold_is_a_timestamp() {
    let t = LOCKTIME_THRESHOLD;
    let tx = bare_tx(1, LockTime::from_time(t).unwrap(), Sequence::ZERO);
    assert!(
        is_final_tx(&tx, 1, t + 1),
        "exactly {t} compares as a time, so a later cutoff is final"
    );
    assert!(!is_final_tx(&tx, 1, t));
}

#[test]
fn bip68_height_type_ignores_zero_mtp() {
    let tx = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(10));
    assert!(sequence_locks_satisfied(&tx, &[100], &[0], 110, 0));
    // bogus MTP must not affect height-type check
    assert!(sequence_locks_satisfied(&tx, &[100], &[u32::MAX], 110, 0));
    assert!(!sequence_locks_satisfied(&tx, &[100], &[0], 109, 0));
}

/// The coinbase relative lock in the connect pin fails when that tx is checked as a spend.
#[test]
fn coinbase_relative_lock_fails_as_a_normal_tx() {
    let coinbase = bare_tx(2, LockTime::ZERO, Sequence::from_consensus(200));
    assert!(
        !sequence_locks_satisfied(&coinbase, &[], &[], 1, 0),
        "the same lock fails closed when the coinbase is treated as a normal tx"
    );
}
