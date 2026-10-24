use bitcoin::Transaction;
use rbitcoin_consensus::block::ScriptCheckJob;
use rbitcoin_consensus::script::p2wsh::*;

use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

#[test]
fn empty_witness_and_hash_mismatch() {
    let mut spk = vec![0x00, 0x20];
    spk.extend([0u8; 32]);
    let job = {
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
    assert!({
        let i = job.inputs().next().unwrap();
        verify(&job, i, &job.tx)
    }
    .is_err());

    let mut job2 = job;
    job2.tx.input[0].witness = Witness::from_slice(&[vec![0x51]]); // OP_TRUE script
    assert!({
        let i = job2.inputs().next().unwrap();
        verify_with_scripthash(&job2, i, &job2.tx, &[0u8; 32])
    }
    .is_err());
}
