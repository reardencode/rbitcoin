use bitcoin::Transaction;
use rbitcoin_consensus::block::ScriptCheckJob;
use rbitcoin_consensus::script::p2wpkh::*;

use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

fn job_with_witness(items: &[&[u8]]) -> ScriptCheckJob {
    let mut spk = vec![0x00, 0x14];
    spk.extend([0u8; 20]);
    {
        let txid = [0u8; 32];
        let prevouts = vec![TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }];
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(items),
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
fn witness_shape_errors() {
    let job = job_with_witness(&[]);
    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx);
    assert!({
        let i = job.inputs().next().unwrap();
        verify(&job, i, &job.tx, &pre)
    }
    .is_err());

    let job = job_with_witness(&[&[0x01]]);
    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx);
    assert!({
        let i = job.inputs().next().unwrap();
        verify(&job, i, &job.tx, &pre)
    }
    .is_err());

    let job = job_with_witness(&[&[], &[0x02; 33]]);
    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx);
    assert!({
        let i = job.inputs().next().unwrap();
        verify(&job, i, &job.tx, &pre)
    }
    .is_err());

    let job = job_with_witness(&[&[0x30, 0x01, 0x01, 0x01], &[0x02; 33]]);
    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx);
    let err = {
        let i = job.inputs().next().unwrap();
        verify(&job, i, &job.tx, &pre)
    }
    .unwrap_err();
    assert!(format!("{err}").contains("p2wpkh"));

    let redeem = {
        let mut r = vec![0x00, 0x14];
        r.extend([0u8; 20]);
        r
    };
    let job = job_with_witness(&[&[0x01]]);
    let pre = rbitcoin_consensus::TxScriptPrecompute::from_tx(&job.tx);
    assert!({
        let i = job.inputs().next().unwrap();
        verify_with_keyhash(&job, i, &job.tx, &[0u8; 20], &redeem, &pre)
    }
    .is_err());
}
