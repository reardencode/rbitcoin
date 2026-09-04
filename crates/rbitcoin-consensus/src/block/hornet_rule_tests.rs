//! Hornet spec.h block-validation rules: happy path + exact boundaries.
//!
//! IDs match published spec.html (H01–H06, L01–L13, C01–C07, S01–S09).
//! Cross-reference: `docs/peer-clients.md`.

use super::{
    apply_witness_commitment, bip34_height_script, block_subsidy, check_tx_local,
    merkle_root_bytes, validate_block_structure, witness_commitment_script, ValidationContext,
    MAX_BLOCK_STRIPPED_SIZE,
};
use crate::error::ConsensusError;
use crate::header::check_header_version_and_future_time;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};
use rbitcoin_primitives::Height;

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn ctx_h(height: u32) -> ValidationContext<'static> {
    let p = Box::leak(Box::new(params()));
    ValidationContext::at(p, Height(height), Milestone::NONE)
}

fn ctx_main(height: u32) -> ValidationContext<'static> {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    ValidationContext::at(p, Height(height), Milestone::NONE)
}

fn ctx_signet(height: u32) -> ValidationContext<'static> {
    let p = Box::leak(Box::new(ChainParams::signet()));
    ValidationContext::at(p, Height(height), Milestone::NONE)
}

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend(n: u8) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn block_with(txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1_290_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: txs,
    };
    if !block.txdata.is_empty() {
        block.header.merkle_root = block.compute_merkle_root().unwrap();
    }
    block
}

fn stripped_size(block: &Block) -> usize {
    let n = block.txdata.len();
    80usize + VarInt(n as u64).size() + block.txdata.iter().map(|t| t.base_size()).sum::<usize>()
}

fn weight_wu(block: &Block) -> u64 {
    let n = block.txdata.len();
    let vi = VarInt(n as u64).size();
    let base = 80 + vi + block.txdata.iter().map(|t| t.base_size()).sum::<usize>();
    let total = 80 + vi + block.txdata.iter().map(|t| t.total_size()).sum::<usize>();
    (base.saturating_mul(3).saturating_add(total)) as u64
}

fn set_coinbase_pad(block: &mut Block, data_len: usize) {
    const COMMIT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let mut spk = Vec::with_capacity(data_len.saturating_add(6));
    spk.push(0x6a);
    spk.push(0x4e);
    spk.extend_from_slice(&(data_len as u32).to_le_bytes());
    spk.extend(std::iter::repeat_n(0x61, data_len));
    let pad = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let pad_at = block.txdata[0].output.iter().position(|o| {
        let b = o.script_pubkey.as_bytes();
        b.first() == Some(&0x6a) && (b.len() < 6 || b[..6] != COMMIT_MAGIC)
    });
    match pad_at {
        Some(i) => block.txdata[0].output[i] = pad,
        None => block.txdata[0].output.push(pad),
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

fn refresh_witness_commitment(block: &mut Block) {
    let reserved = [0u8; 32];
    block.txdata[0].input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
    let wtxids = block
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_wtxid().to_byte_array());
    let spk = witness_commitment_script(wtxids, &reserved);
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    if let Some(out) = block.txdata[0].output.iter_mut().rev().find(|o| {
        let b = o.script_pubkey.as_bytes();
        b.len() >= 38 && b[..6] == MAGIC
    }) {
        out.script_pubkey = ScriptBuf::from_bytes(spk);
    } else {
        block.txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk),
        });
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

fn extend_spend_witness_one_byte(block: &mut Block) {
    let items: Vec<Vec<u8>> = block.txdata[1].input[0]
        .witness
        .iter()
        .map(|s| {
            let mut v = s.to_vec();
            v.push(0xcd);
            v
        })
        .collect();
    block.txdata[1].input[0].witness = Witness::from_slice(&items);
    refresh_witness_commitment(block);
}

fn pad_stripped_to(block: &mut Block, target: usize) {
    let before = stripped_size(block);
    assert!(
        before < target,
        "fixture already {before}, want pad to {target}"
    );
    let guess = target.saturating_sub(before).saturating_sub(24).max(1);
    set_coinbase_pad(block, guess);
    let got = stripped_size(block);
    if got != target {
        let adj = if got < target {
            guess + (target - got)
        } else {
            guess.saturating_sub(got - target)
        };
        set_coinbase_pad(block, adj);
    }
    assert_eq!(
        stripped_size(block),
        target,
        "stripped pad missed target (before {before})"
    );
}

fn assert_bad_block(err: ConsensusError, needle: &str) {
    match err {
        ConsensusError::BadBlock(s) => {
            assert!(
                s.contains(needle),
                "expected BadBlock containing {needle:?}, got {s:?}"
            );
        }
        other => panic!("expected BadBlock({needle:?}), got {other:?}"),
    }
}

fn assert_bad_tx(err: ConsensusError, needle: &str) {
    match err {
        ConsensusError::BadTx(s) => {
            assert!(
                s.contains(needle),
                "expected BadTx containing {needle:?}, got {s:?}"
            );
        }
        other => panic!("expected BadTx({needle:?}), got {other:?}"),
    }
}

fn padded_spend(data_len: usize) -> Transaction {
    let mut spk = Vec::with_capacity(data_len.saturating_add(6));
    spk.push(0x6a);
    spk.push(0x4e);
    spk.extend_from_slice(&(data_len as u32).to_le_bytes());
    spk.extend(std::iter::repeat_n(0x61, data_len));
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    }
}

#[test]
fn l01_accepts_single_coinbase_rejects_empty() {
    validate_block_structure(&block_with(vec![coinbase(0)]), &ctx_h(0)).unwrap();
    let err = validate_block_structure(&block_with(vec![]), &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "no transactions");
}

#[test]
fn l02_accepts_matching_merkle_rejects_mismatch() {
    let good = block_with(vec![coinbase(0), spend(1)]);
    validate_block_structure(&good, &ctx_h(0)).unwrap();
    let mut bad = good;
    bad.header.merkle_root = TxMerkleNode::from_byte_array([0x11; 32]);
    assert_bad_block(
        validate_block_structure(&bad, &ctx_h(0)).unwrap_err(),
        "merkle",
    );
}

#[test]
fn l03_stripped_size_1_000_000_accepts_1_000_001_rejects() {
    let mut ok = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut ok, MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(stripped_size(&ok), MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(weight_wu(&ok), 4_000_000);
    validate_block_structure(&ok, &ctx_h(0)).expect("exactly 1_000_000 stripped");

    let mut over = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut over, MAX_BLOCK_STRIPPED_SIZE + 1);
    assert_eq!(stripped_size(&over), MAX_BLOCK_STRIPPED_SIZE + 1);
    assert_bad_block(
        validate_block_structure(&over, &ctx_h(0)).unwrap_err(),
        "stripped",
    );
}

#[test]
fn l04_accepts_coinbase_first_only_rejects_later_or_missing() {
    validate_block_structure(&block_with(vec![coinbase(0), spend(1)]), &ctx_h(0)).unwrap();
    assert_bad_block(
        validate_block_structure(&block_with(vec![spend(1)]), &ctx_h(1)).unwrap_err(),
        "first tx not coinbase",
    );
    assert_bad_block(
        validate_block_structure(&block_with(vec![coinbase(1), coinbase(1)]), &ctx_h(1))
            .unwrap_err(),
        "coinbase not first",
    );
}

#[test]
fn l05_legacy_sigops_20_000_accepts_20_001_rejects() {
    let mut ok = coinbase(0);
    ok.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_000]);
    validate_block_structure(&block_with(vec![ok]), &ctx_h(0)).expect("20_000 legacy sigops");

    let mut bad = coinbase(0);
    bad.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_001]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![bad]), &ctx_h(0)).unwrap_err(),
        "sigops",
    );
}

#[test]
fn l06_accepts_one_input_rejects_empty_vin() {
    validate_block_structure(&block_with(vec![coinbase(0), spend(1)]), &ctx_h(0)).unwrap();
    let empty = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_bad_tx(
        validate_block_structure(&block_with(vec![coinbase(0), empty]), &ctx_h(0)).unwrap_err(),
        "no inputs",
    );
}

#[test]
fn l07_accepts_one_output_rejects_empty_vout() {
    validate_block_structure(&block_with(vec![coinbase(0)]), &ctx_h(0)).unwrap();
    let mut cb = coinbase(0);
    cb.output.clear();
    assert_bad_tx(
        validate_block_structure(&block_with(vec![cb]), &ctx_h(0)).unwrap_err(),
        "no outputs",
    );
}

#[test]
fn l08_tx_stripped_size_1_000_000_accepts_1_000_001_rejects() {
    let mut lo = 0usize;
    let mut hi = MAX_BLOCK_STRIPPED_SIZE;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if padded_spend(mid).base_size() < MAX_BLOCK_STRIPPED_SIZE {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut data_ok = lo;
    while padded_spend(data_ok).base_size() > MAX_BLOCK_STRIPPED_SIZE {
        data_ok -= 1;
    }
    while padded_spend(data_ok).base_size() < MAX_BLOCK_STRIPPED_SIZE {
        data_ok += 1;
    }
    let ok = padded_spend(data_ok);
    assert_eq!(ok.base_size(), MAX_BLOCK_STRIPPED_SIZE);
    check_tx_local(&ok, ok.base_size()).expect("tx stripped == 1_000_000");

    let over = padded_spend(data_ok + 1);
    assert!(over.base_size() > MAX_BLOCK_STRIPPED_SIZE);
    assert_bad_tx(
        check_tx_local(&over, over.base_size()).unwrap_err(),
        "oversize",
    );
}

#[test]
fn l09_zero_output_is_non_negative() {
    let mut cb = coinbase(0);
    cb.output[0].value = Amount::ZERO;
    validate_block_structure(&block_with(vec![cb]), &ctx_h(0)).unwrap();
}

#[test]
fn l10_max_money_accepts_max_plus_one_rejects() {
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
    let mut ok = coinbase(0);
    ok.output[0].value = Amount::from_sat(MAX_MONEY);
    validate_block_structure(&block_with(vec![ok]), &ctx_h(0)).expect("exactly MAX_MONEY");

    let mut one = coinbase(0);
    one.output[0].value = Amount::from_sat(MAX_MONEY + 1);
    assert_bad_block(
        validate_block_structure(&block_with(vec![one]), &ctx_h(0)).unwrap_err(),
        "toolarge",
    );

    let half = 11_000_000 * 100_000_000u64;
    let mut sum = coinbase(0);
    sum.output = vec![
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
    ];
    assert_bad_block(
        validate_block_structure(&block_with(vec![sum]), &ctx_h(0)).unwrap_err(),
        "txouttotal",
    );
}

#[test]
fn l11_unique_inputs_accept_duplicate_reject() {
    validate_block_structure(&block_with(vec![coinbase(0), spend(1)]), &ctx_h(0)).unwrap();
    let op = OutPoint {
        txid: bitcoin::Txid::from_byte_array([3; 32]),
        vout: 0,
    };
    let dup = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_bad_tx(
        validate_block_structure(&block_with(vec![coinbase(0), dup]), &ctx_h(0)).unwrap_err(),
        "duplicate",
    );
}

#[test]
fn l12_coinbase_scriptsig_2_and_100_accept_1_and_101_reject() {
    let mut two = coinbase(0);
    two.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
    validate_block_structure(&block_with(vec![two]), &ctx_h(0)).unwrap();

    let mut hundred = coinbase(0);
    hundred.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01; 100]);
    validate_block_structure(&block_with(vec![hundred]), &ctx_h(0)).unwrap();

    let mut short = coinbase(0);
    short.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![short]), &ctx_h(0)).unwrap_err(),
        "bad-cb-length",
    );
    let mut long = coinbase(0);
    long.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01; 101]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![long]), &ctx_h(0)).unwrap_err(),
        "bad-cb-length",
    );
}

#[test]
fn l13_non_coinbase_null_prevout_rejected_non_null_accepted() {
    validate_block_structure(&block_with(vec![coinbase(0), spend(1)]), &ctx_h(0)).unwrap();
    let mixed = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([4; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_bad_tx(
        validate_block_structure(&block_with(vec![coinbase(0), mixed]), &ctx_h(0)).unwrap_err(),
        "prevout-null",
    );
}

#[test]
fn c02_pre_segwit_accepts_no_witness_rejects_witness() {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    assert!(!p.segwit_active_at(1));
    validate_block_structure(&block_with(vec![coinbase(1)]), &ctx_main(1)).unwrap();

    let mut spend = spend(10);
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut cb = coinbase(1);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let err = validate_block_structure(&block_with(vec![cb, spend]), &ctx_main(1)).unwrap_err();
    assert_bad_block(err, "before segwit");
}

#[test]
fn c03_weight_4_000_000_accepts_4_000_001_rejects() {
    let mut ok = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut ok, MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(weight_wu(&ok), 4_000_000);
    validate_block_structure(&ok, &ctx_h(0)).expect("exactly 4_000_000 WU");

    let mut spend = spend(11);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let mut wblock = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut wblock);
    while !weight_wu(&wblock).is_multiple_of(4) {
        extend_spend_witness_one_byte(&mut wblock);
    }
    let w = weight_wu(&wblock);
    assert!(w < 4_000_000);
    let gap = 4_000_000 - w;
    let target = stripped_size(&wblock) + (gap / 4) as usize;
    pad_stripped_to(&mut wblock, target);
    assert_eq!(weight_wu(&wblock), 4_000_000);
    validate_block_structure(&wblock, &ctx_h(1)).expect("witness block at 4_000_000 WU");

    extend_spend_witness_one_byte(&mut wblock);
    assert_eq!(weight_wu(&wblock), 4_000_001);
    assert!(stripped_size(&wblock) <= MAX_BLOCK_STRIPPED_SIZE);
    assert_bad_block(
        validate_block_structure(&wblock, &ctx_h(1)).unwrap_err(),
        "weight",
    );
}

#[test]
fn c04_bip34_height_push_accepts_at_activation_rejects_missing() {
    let h = {
        let p = ChainParams::signet();
        p.btc.bip34_height
    };
    assert_eq!(h, 1);
    validate_block_structure(&block_with(vec![coinbase(h)]), &ctx_signet(h))
        .expect("BIP34 height push at activation");
    let mut missing = coinbase(h);
    missing.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![missing]), &ctx_signet(h)).unwrap_err(),
        "bip34",
    );
}

#[test]
fn c05_c06_c07_witness_commitment_nonce_merkle() {
    validate_block_structure(&block_with(vec![coinbase(1)]), &ctx_h(1))
        .expect("no witness, no commitment");

    let mut spend = spend(9);
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![coinbase(1), spend.clone()]), &ctx_h(1))
            .unwrap_err(),
        "witness commitment",
    );

    let mut committed = block_with(vec![coinbase(1), spend.clone()]);
    apply_witness_commitment(&mut committed);
    validate_block_structure(&committed, &ctx_h(1)).expect("commitment + 32-byte nonce");

    committed.txdata[0].input[0].witness = Witness::new();
    committed.header.merkle_root = committed.compute_merkle_root().unwrap();
    let err = validate_block_structure(&committed, &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("witness") || s.contains("nonce")),
        "empty nonce: {err:?}"
    );

    let mut wrong = spend.clone();
    wrong.input[0].witness = Witness::from_slice(&[vec![0x02]]);
    let mut cb = coinbase(1);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    cb.input[0].witness = Witness::from_slice(&[[0u8; 32].as_slice()]);
    let err = validate_block_structure(&block_with(vec![cb, wrong]), &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("witness")),
        "wrong merkle: {err:?}"
    );
}

#[test]
fn h05_timestamp_exactly_two_hours_accepts_plus_one_rejects() {
    let params = ChainParams::regtest();
    let mut h = crate::params::genesis_block(&params).header;
    h.version = Version::from_consensus(4);
    crate::clock::with_now(1_700_000_000, || {
        h.time = 1_700_000_000 + 2 * 60 * 60;
        check_header_version_and_future_time(&params, Height(1), &h).unwrap();
        h.time = 1_700_000_000 + 2 * 60 * 60 + 1;
        let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
            "{err:?}"
        );
    });
}

#[test]
fn h06_version_floors_at_bip34_66_65() {
    let rt = ChainParams::regtest();
    let mut h = crate::params::genesis_block(&rt).header;
    crate::clock::with_now(1_700_000_000, || {
        h.time = 1_700_000_000;
        h.version = Version::from_consensus(3);
        let err = check_header_version_and_future_time(&rt, Height(1), &h).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
        h.version = Version::from_consensus(4);
        check_header_version_and_future_time(&rt, Height(1), &h).unwrap();
    });

    let main = ChainParams::mainnet();
    let mut mh = crate::params::genesis_block(&main).header;
    crate::clock::with_now(1_700_000_000, || {
        mh.time = 1_700_000_000;
        let bip34 = main.btc.bip34_height;
        mh.version = Version::from_consensus(1);
        check_header_version_and_future_time(&main, Height(bip34 - 1), &mh).unwrap();
        let err = check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
        mh.version = Version::from_consensus(2);
        check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap();

        let bip66 = main.btc.bip66_height;
        mh.version = Version::from_consensus(2);
        let err = check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(2)), "{err:?}");
        mh.version = Version::from_consensus(3);
        check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap();

        let bip65 = main.btc.bip65_height;
        mh.version = Version::from_consensus(3);
        let err = check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap_err();
        assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
        mh.version = Version::from_consensus(4);
        check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap();
    });
}

#[test]
fn s04_sigop_cost_80_000_accepts_80_004_rejects() {
    let mut ok = coinbase(0);
    ok.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_000]);
    validate_block_structure(&block_with(vec![ok]), &ctx_h(0)).expect("cost 80_000");
    let mut bad = coinbase(0);
    bad.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_001]);
    assert_bad_block(
        validate_block_structure(&block_with(vec![bad]), &ctx_h(0)).unwrap_err(),
        "sigops",
    );
}

#[test]
fn s05_subsidy_exact_halving_boundaries() {
    let main = ChainParams::mainnet();
    assert_eq!(block_subsidy(0, &main), 50_0000_0000);
    assert_eq!(block_subsidy(209_999, &main), 50_0000_0000);
    assert_eq!(block_subsidy(210_000, &main), 25_0000_0000);
    let rt = ChainParams::regtest();
    assert_eq!(block_subsidy(149, &rt), 50_0000_0000);
    assert_eq!(block_subsidy(150, &rt), 25_0000_0000);
}

#[test]
fn merkle_odd_leaf_duplication_is_unique_root() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert_ne!(merkle_root_bytes(&[a, b]), merkle_root_bytes(&[a, b, a]));
}
