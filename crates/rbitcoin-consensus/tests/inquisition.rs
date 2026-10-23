//! BIP 54 consensus cleanup on the default signet.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::block::{
    bip54_input_sigops, reject_bip54_coinbase, reject_bip54_legacy_sigops, reject_bip54_tx_size,
};
use rbitcoin_consensus::heretical::{
    bip54_header_time, HereticalFlags, MAX_TIMEWARP_BIP54, MAX_TX_BIP54_SIGOPS,
    SIGNET_CLEANUP_HEIGHT,
};
use rbitcoin_consensus::tx_precompute::TxPrecompute;
use rbitcoin_consensus::{bip34_height_script, genesis_block, ChainParams, ConsensusError};

#[test]
fn activation_heights_follow_the_default_signet_only() {
    let signet = ChainParams::signet();
    assert!(
        !signet
            .heretical_at(SIGNET_CLEANUP_HEIGHT - 1)
            .consensus_cleanup
    );
    assert!(signet.heretical_at(SIGNET_CLEANUP_HEIGHT).consensus_cleanup);

    assert!(!ChainParams::regtest().heretical_at(0).consensus_cleanup);
    assert_eq!(
        ChainParams::mainnet().heretical_at(1_000_000),
        HereticalFlags::default()
    );
    let mut custom = ChainParams::signet();
    custom.signet_challenge = Some(ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(
        custom.heretical_at(SIGNET_CLEANUP_HEIGHT),
        HereticalFlags::default()
    );
}

#[test]
fn bip54_header_time_rejects_timewarp_and_a_negative_interval() {
    let interval = 2016u32;
    let parent = 1_000_000u32;
    let too_early = (i64::from(parent) - MAX_TIMEWARP_BIP54 - 1) as u32;
    let err = bip54_header_time(parent, too_early, interval, interval, None).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s == "time-timewarp-attack"),
        "{err:?}"
    );

    let edge = (i64::from(parent) - MAX_TIMEWARP_BIP54) as u32;
    assert!(bip54_header_time(parent, edge, interval, interval, None).is_ok());

    let last = interval * 2 - 1;
    let err = bip54_header_time(parent, 50, last, interval, None).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s == "missing bip54 period open"),
        "{err:?}"
    );
    let err = bip54_header_time(parent, 49, last, interval, Some(50)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s == "time-negative-interval"),
        "{err:?}"
    );
    assert!(bip54_header_time(parent, 50, last, interval, Some(50)).is_ok());
    // A block in the middle of the period does not consult the open time.
    assert!(bip54_header_time(parent, 1, interval + 1, interval, None).is_ok());
}

#[test]
fn bip54_rejects_core_coinbases_and_sixty_four_byte_transactions() {
    let height = SIGNET_CLEANUP_HEIGHT;
    let mut ss = bip34_height_script(height);
    while ss.len() < 2 {
        ss.push(0x00);
    }
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let block = bitcoin::block::Block {
        header: genesis_block(&ChainParams::signet()).header,
        txdata: vec![coinbase.clone()],
    };
    let err = reject_bip54_coinbase(&block, height).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s == "bad-cb-locktime"),
        "{err:?}"
    );

    let mut coinbase = coinbase;
    coinbase.lock_time = LockTime::from_consensus(height - 1);
    let block = bitcoin::block::Block {
        header: block.header,
        txdata: vec![coinbase.clone()],
    };
    let err = reject_bip54_coinbase(&block, height).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s == "bad-cb-sequence"),
        "{err:?}"
    );

    coinbase.input[0].sequence = Sequence::ZERO;
    let block = bitcoin::block::Block {
        header: block.header,
        txdata: vec![coinbase],
    };
    assert!(reject_bip54_coinbase(&block, height).is_ok());
    assert!(reject_bip54_coinbase(&block, 0).is_ok());

    let wide = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![1, 2, 3, 4]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let pres = vec![
        TxPrecompute::from_tx(&block.txdata[0]),
        TxPrecompute::from_tx(&wide),
    ];
    assert_eq!(pres[1].base_size, 64, "fixture must be the BIP54 size");
    let err = reject_bip54_tx_size(&pres).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s == "bad-txns-size"),
        "{err:?}"
    );
}

#[test]
fn bip54_legacy_sigops_count_script_sig_and_prevout() {
    let mut tx = Transaction {
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
    };
    tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0xac; MAX_TX_BIP54_SIGOPS as usize]);
    let empty: &[u8] = &[];
    assert!(reject_bip54_legacy_sigops(&tx, &[empty]).is_ok());
    tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0xac; (MAX_TX_BIP54_SIGOPS as usize) + 1]);
    let err = reject_bip54_legacy_sigops(&tx, &[empty]).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s == "bad-txns-legacy-sigops"),
        "{err:?}"
    );

    let bare = vec![0xac; 3];
    assert_eq!(bip54_input_sigops(&[], &bare), 3);
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend([0u8; 20]);
    p2sh.push(0x87);
    // scriptSig pushes a redeem of two CHECKSIGs. The P2SH template itself is not counted.
    let script_sig = vec![0x02, 0xac, 0xac];
    assert_eq!(bip54_input_sigops(&script_sig, &p2sh), 2);
}
