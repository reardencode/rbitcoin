use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
use bitcoin::{Transaction, Weight};
use rbitcoin_consensus::policy::*;

#[test]
fn min_relay_fee_point_one_sat_vb() {
    assert!(meets_min_relay_fee(100, 4000));
    assert!(!meets_min_relay_fee(99, 4000));
    assert_eq!(fee_rate_sat_per_kvb(100, 4000), 100);
    assert!(meets_min_relay_fee_at(1, 4000, 0));
    assert!(!meets_min_relay_fee_at(1, 4000, 100));
}

#[test]
fn nonstandard_version_is_version() {
    let mut tx = bare_tx(1);
    tx.version = Version::non_standard(0xffff_ffffu32 as i32);
    let weight = tx.weight().to_wu();
    assert_eq!(
        check_libre_admission_at(&tx, 50_000, weight, 0),
        PolicyResult::Standard
    );
    tx.version = Version::ONE;
    assert_eq!(
        check_libre_admission_at(&tx, 50_000, weight, 0),
        PolicyResult::Standard
    );
}

#[test]
fn oversized_spk_is_scriptpubkey() {
    let mut tx = bare_tx(1);
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 10_001]);
    let weight = tx.weight().to_wu();
    assert_eq!(
        check_libre_admission_at(&tx, 50_000, weight, 0),
        PolicyResult::NonStandard("scriptpubkey")
    );
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 10_000]);
    assert_eq!(
        check_libre_admission_at(&tx, 50_000, weight, 0),
        PolicyResult::Standard
    );
    let mut opreturn = vec![0x6a];
    opreturn.extend(std::iter::repeat_n(0x01, 10_001));
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(opreturn);
    let weight = tx.weight().to_wu();
    assert_eq!(
        check_libre_admission_at(&tx, 50_000, weight, 0),
        PolicyResult::Standard
    );
}

#[test]
fn annex_libre_rules() {
    assert!(is_annex_standard(&[]));
    assert!(is_annex_standard(&[0x50]));
    assert!(is_annex_standard(&[0x50, 0x00]));
    assert!(is_annex_standard(&[0x50, 0x00, 0xab]));
    assert!(!is_annex_standard(&[0x50, 0x01]));
    assert!(!is_annex_standard(&[0x50, 0xff, 0x00]));
    // A one-item stack is never an annex, even when it starts with 0x50.
    let mut lone = bare_tx(1);
    lone.input[0].witness = Witness::from_slice(&[vec![0x50, 0x01]]);
    assert!(check_libre_annex(&lone).is_standard());
    // An empty last item is not an annex. `&&` must not become `||`.
    let mut empty_last = bare_tx(1);
    empty_last.input[0].witness = Witness::from_slice(&[vec![0x01], vec![]]);
    assert!(check_libre_annex(&empty_last).is_standard());
    let mut untagged = bare_tx(1);
    untagged.input[0].witness = Witness::from_slice(&[vec![0x50, 0x01], vec![0x51]]);
    assert!(check_libre_annex(&untagged).is_standard());
    let mut standard_annex = bare_tx(1);
    standard_annex.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x00]]);
    assert!(check_libre_annex(&standard_annex).is_standard());
}

fn bare_tx(fee_out: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(fee_out),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]), // OP_TRUE — dust-ish / nonstd OK under Libre
        }],
    }
}

#[test]
fn libre_allows_op_true_and_dust_outputs() {
    let tx = bare_tx(1);
    let weight = tx.weight().to_wu();
    let fee = 50_000u64.saturating_sub(1);
    assert!(check_libre_admission(&tx, fee, weight).is_ok());

    let zero = bare_tx(0);
    assert_eq!(
        check_libre_admission(&zero, 50_000, zero.weight().to_wu()),
        PolicyResult::NonStandard("dust")
    );
    let mut opreturn = bare_tx(0);
    opreturn.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
    assert!(check_libre_admission(&opreturn, 50_000, opreturn.weight().to_wu()).is_ok());
}

#[test]
fn libre_rejects_low_feerate() {
    let tx = bare_tx(50_000);
    let weight = tx.weight().to_wu();
    assert_eq!(
        check_libre_admission(&tx, 0, weight),
        PolicyResult::NonStandard("min relay fee")
    );
}

#[test]
fn policy_result_is_ok_alias() {
    assert!(PolicyResult::Standard.is_ok());
    assert!(!PolicyResult::NonStandard("x").is_ok());
}

#[test]
fn saturated_weight_stays_a_huge_vsize() {
    assert_eq!(vbytes_ceil(u64::MAX), u64::MAX / 4);
    assert_eq!(vbytes_ceil(u64::MAX - 3), u64::MAX / 4);
    assert_eq!(
        vbytes_ceil(u64::MAX - 4),
        Weight::from_wu(u64::MAX - 4).to_vbytes_ceil()
    );
    assert_eq!(fee_rate_sat_per_kvb(1_000, u64::MAX), 0);
}

#[test]
fn vsize_fee_zero_and_libre_gates() {
    assert!(!meets_min_relay_fee(1, 0));
    assert_eq!(fee_rate_sat_per_kvb(100, 0), 0);
    assert_eq!(Weight::from_wu(1).to_vbytes_ceil(), 1);

    let cb = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_eq!(
        check_libre_admission(&cb, 0, 100),
        PolicyResult::NonStandard("coinbase")
    );

    // Weight cap. The exact maximum is still standard.
    let tx = bare_tx(1);
    assert!(check_libre_shape(&tx, MAX_STANDARD_TX_WEIGHT).is_standard());
    assert_eq!(
        check_libre_admission(&tx, 1_000_000, MAX_STANDARD_TX_WEIGHT + 1),
        PolicyResult::NonStandard("tx weight")
    );
    // 10_000 bytes is spendable. One more byte, or equality, is not.
    assert!(!is_unspendable(&[0x51; 10_000]));
    assert!(is_unspendable(&[0x51; 10_001]));
    let mut zero_exact = bare_tx(0);
    zero_exact.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 10_000]);
    assert_eq!(
        check_libre_shape(&zero_exact, 100),
        PolicyResult::NonStandard("dust")
    );

    // Annex not tagged 0x50 is ignored by is_annex_standard.
    assert!(is_annex_standard(&[0x01, 0x02]));
    // Libre annex scan: non-annex last item is fine.
    let mut ok = bare_tx(1);
    ok.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x02]]);
    assert!(check_libre_annex(&ok).is_standard());
}
