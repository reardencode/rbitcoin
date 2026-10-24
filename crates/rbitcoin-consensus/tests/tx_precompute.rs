use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::{Transaction, TxOut};
use rbitcoin_consensus::tx_precompute::*;
use rbitcoin_primitives::script_sigop_count;

use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, TxIn, Witness};

fn oracle_sha_prevouts(tx: &Transaction) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for i in &tx.input {
        i.previous_output.consensus_encode(&mut e).unwrap();
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn oracle_sha_sequences(tx: &Transaction) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for i in &tx.input {
        i.sequence.consensus_encode(&mut e).unwrap();
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn oracle_sha_outputs(tx: &Transaction) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for o in &tx.output {
        o.consensus_encode(&mut e).unwrap();
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn oracle_sigops(tx: &Transaction) -> u64 {
    let mut n = 0u64;
    for inp in &tx.input {
        n = n.saturating_add(script_sigop_count(inp.script_sig.as_bytes(), false));
    }
    for out in &tx.output {
        n = n.saturating_add(script_sigop_count(out.script_pubkey.as_bytes(), false));
    }
    n
}

fn assert_matches_rust_bitcoin(tx: &Transaction) {
    let p = TxPrecompute::from_tx(tx);
    assert_eq!(p.txid, tx.compute_txid().to_byte_array(), "txid");
    assert_eq!(p.wtxid, tx.compute_wtxid().to_byte_array(), "wtxid");
    assert_eq!(p.base_size, tx.base_size(), "base_size");
    assert_eq!(p.total_size, tx.total_size(), "total_size");
    assert_eq!(p.weight_wu(), tx.weight().to_wu(), "weight");
    assert_eq!(p.sigops, oracle_sigops(tx), "sigops");
    assert_eq!(
        p.sha_prevouts(),
        Some(oracle_sha_prevouts(tx)),
        "sha_prevouts"
    );
    assert_eq!(
        p.sha_sequences(),
        Some(oracle_sha_sequences(tx)),
        "sha_sequences"
    );
    assert_eq!(p.sha_outputs(), Some(oracle_sha_outputs(tx)), "sha_outputs");
    assert_eq!(
        p.hash_prevouts(),
        Some(
            sha256::Hash::from_byte_array(p.sha_prevouts().unwrap())
                .hash_again()
                .to_byte_array()
        )
    );
}

fn assert_connect_matches_ids(tx: &Transaction) {
    let full = TxPrecompute::from_tx(tx);
    let c = TxPrecompute::from_tx_connect(tx);
    assert_eq!(c.txid, full.txid, "txid");
    assert_eq!(c.wtxid, full.wtxid, "wtxid");
    assert_eq!(c.base_size, full.base_size, "base_size");
    assert_eq!(c.total_size, full.total_size, "total_size");
    assert_eq!(c.weight_wu(), full.weight_wu(), "weight");
    assert_eq!(c.sigops, full.sigops, "sigops");
    assert_eq!(c.out_sum, full.out_sum, "out_sum");
    assert_eq!(c.has_witness, full.has_witness, "has_witness");
    assert_eq!(c.sha_prevouts(), None);
    assert_eq!(c.sha_sequences(), None);
    assert_eq!(c.sha_outputs(), None);
    assert_eq!(c.hash_prevouts(), None);
    assert_eq!(c.hash_sequence(), None);
    assert_eq!(c.hash_outputs(), None);
}

fn legacy_1in() -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(vec![0x51, 0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn p2wpkh_like() -> Transaction {
    let mut tx = legacy_1in();
    tx.input[0].script_sig = ScriptBuf::new();
    tx.input[0].witness = Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]);
    tx
}

/// One empty witness and one non-empty, so the witness section is not a single stack.
fn two_input_witness() -> Transaction {
    let mut tx = legacy_1in();
    tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 3,
        },
        script_sig: ScriptBuf::from_bytes(vec![0x01, 0x02]),
        sequence: Sequence::ZERO,
        witness: Witness::new(),
    });
    tx.input[0].script_sig = ScriptBuf::new();
    tx.input[0].witness = Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]);
    tx.output.push(TxOut {
        value: Amount::from_sat(9),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x52]),
    });
    tx
}

fn coinbase_witness_nonce() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0xab; 32]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn tx_precompute_matches_legacy() {
    assert_matches_rust_bitcoin(&legacy_1in());
}

#[test]
fn tx_precompute_matches_p2wpkh_witness() {
    assert_matches_rust_bitcoin(&p2wpkh_like());
}

#[test]
fn tx_precompute_matches_zero_input_bip144() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_matches_rust_bitcoin(&tx);
    assert!(TxPrecompute::from_tx(&tx).has_witness);
}

#[test]
fn from_tx_connect_omits_sighash_midstates() {
    assert_connect_matches_ids(&legacy_1in());
    assert_connect_matches_ids(&p2wpkh_like());
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_connect_matches_ids(&tx);
    assert_eq!(
        TxPrecompute::from_tx_connect(&tx).wtxid,
        tx.compute_wtxid().to_byte_array()
    );
}

fn assert_wire_matches_from_tx(tx: &Transaction) {
    use bitcoin::consensus::encode::serialize;
    let raw = serialize(tx);
    let spans = witness_wire(tx, &raw);
    if uses_segwit_serialization(tx) {
        let spans = spans.expect("witness wire spans");
        let base = spans.version.len() + spans.vin.len() + spans.vout.len() + spans.locktime.len();
        assert_eq!(base, tx.base_size());
    } else {
        assert!(spans.is_none());
    }
    let w = TxPrecompute::from_tx_wire(tx, &raw, true).expect("spans");
    let full = TxPrecompute::from_tx(tx);
    assert_eq!(w.txid, tx.compute_txid().to_byte_array(), "txid");
    assert_eq!(w.wtxid, sha256d::Hash::hash(&raw).to_byte_array(), "wtxid");
    assert_eq!(w.base_size, tx.base_size(), "base_size");
    assert_eq!(w.total_size, raw.len(), "total_size");
    assert_eq!(w.total_size, tx.total_size());
    assert_eq!(w.txid, full.txid);
    assert_eq!(w.wtxid, full.wtxid);
    assert_eq!(w.sigops, full.sigops, "sigops");
    assert_eq!(w.out_sum, full.out_sum, "out_sum");
    assert_eq!(w.has_witness, full.has_witness, "has_witness");
    assert_eq!(w.sha_prevouts(), full.sha_prevouts());
    let c = TxPrecompute::from_tx_wire(tx, &raw, false).expect("spans");
    assert_eq!(c.txid, full.txid);
    assert_eq!(c.wtxid, full.wtxid);
    assert_eq!(c.sha_prevouts(), None);
    if !c.has_witness {
        assert_eq!(c.txid, c.wtxid, "legacy wtxid == txid");
    }
}

#[test]
fn from_tx_wire_matches_from_tx_on_legacy_and_witness() {
    for tx in [
        legacy_1in(),
        p2wpkh_like(),
        two_input_witness(),
        coinbase_witness_nonce(),
    ] {
        assert_wire_matches_from_tx(&tx);
    }
}

#[test]
fn flag_zero_wire_is_one_slice() {
    let raw = [2u8, 0, 0, 0, 0, 0, 7, 0, 0, 0];
    let flag = decode_flag_zero_tx(&raw).expect("flag zero");
    assert!(
        witness_wire(&flag, &raw).is_none(),
        "flag-zero is one slice"
    );
    let w = TxPrecompute::from_tx_wire(&flag, &raw, false).expect("flag zero");
    assert_eq!(w.txid, sha256d::Hash::hash(&raw).to_byte_array());
    assert_eq!(w.wtxid, w.txid);
    assert_eq!(w.base_size, flag.base_size());
    assert_eq!(w.total_size, raw.len());
    assert!(TxPrecompute::from_tx_wire(&p2wpkh_like(), &raw, false).is_none());
}

#[test]
fn sighash_midstates_come_from_wire_spans() {
    use bitcoin::consensus::encode::serialize;
    let tx = two_input_witness();
    let raw = serialize(&tx);
    let spans = witness_wire(&tx, &raw).expect("spans");
    let (txid, mids) = hash_wire_sighash(&tx, &spans).expect("span sighash");
    assert_eq!(txid, tx.compute_txid().to_byte_array());
    assert_eq!(mids[0], Some(oracle_sha_prevouts(&tx)));
    assert_eq!(mids[1], Some(oracle_sha_sequences(&tx)));
    assert_eq!(mids[2], Some(oracle_sha_outputs(&tx)));
    let w = TxPrecompute::from_tx_wire(&tx, &raw, true).expect("wire");
    assert_eq!(w.sha_prevouts(), mids[0]);
    assert_eq!(w.sha_sequences(), mids[1]);
    assert_eq!(w.sha_outputs(), mids[2]);
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for input in &tx.input {
        input
            .previous_output
            .consensus_encode(&mut prevouts)
            .unwrap();
        input.sequence.consensus_encode(&mut sequences).unwrap();
    }
    let mut outputs = Vec::new();
    for output in &tx.output {
        output.consensus_encode(&mut outputs).unwrap();
    }
    assert_eq!(
        w.sha_prevouts().unwrap(),
        sha256::Hash::hash(&prevouts).to_byte_array()
    );
    assert_eq!(
        w.hash_prevouts().unwrap(),
        sha256d::Hash::hash(&prevouts).to_byte_array()
    );
    let script = w.as_script().expect("wire sighash");
    assert_eq!(w.hash_prevouts(), script.prevouts_d.get().copied());
    assert_eq!(
        w.sha_sequences().unwrap(),
        sha256::Hash::hash(&sequences).to_byte_array()
    );
    assert_eq!(
        w.hash_sequence().unwrap(),
        sha256d::Hash::hash(&sequences).to_byte_array()
    );
    assert_eq!(w.hash_sequence(), script.sequences_d.get().copied());
    assert_eq!(
        w.sha_outputs().unwrap(),
        sha256::Hash::hash(&outputs).to_byte_array()
    );
    assert_eq!(
        w.hash_outputs().unwrap(),
        sha256d::Hash::hash(&outputs).to_byte_array()
    );
    assert_eq!(w.hash_outputs(), script.outputs_d.get().copied());
}

#[test]
fn block_tx_count_fits_uses_ten_byte_floor() {
    assert!(block_tx_count_fits(1, 10));
    assert!(block_tx_count_fits(0, 0));
    assert!(!block_tx_count_fits(2, 15));
    assert!(!block_tx_count_fits(1, 9));
}

#[test]
fn decode_block_precomputes_rejects_tx_count_past_payload() {
    // Header plus a u64 tx count. No transaction bytes follow.
    let mut payload = vec![0u8; 80];
    payload.push(0xff);
    payload.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_block_precomputes(&payload, false).is_none());
}

#[test]
fn decode_block_precomputes_accepts_minimum_serialized_tx() {
    use bitcoin::consensus::encode::serialize;
    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let raw_tx = serialize(&tx);
    assert!(
        (10..20).contains(&raw_tx.len()),
        "one tx must sit on the 10-byte floor, got {}",
        raw_tx.len()
    );
    let mut payload = vec![0u8; 80];
    payload.push(1);
    payload.extend_from_slice(&raw_tx);
    let (block, pres, _) = decode_block_precomputes(&payload, false).expect("one minimum tx");
    assert_eq!(block.txdata.len(), 1);
    assert_eq!(pres.len(), 1);
    assert!(block.txdata[0].input.is_empty());
    assert!(block.txdata[0].output.is_empty());
}

/// Core's `UnserializeTransaction` reads an empty vin and flag 0 as a tx
/// with no inputs and no outputs; the locktime follows.
const FLAG_ZERO_TX: [u8; 10] = [2, 0, 0, 0, 0x00, 0x00, 7, 0, 0, 0];

#[test]
fn flag_zero_tx_decodes_with_core_txid() {
    use bitcoin::consensus::encode::serialize;
    let mut raw = vec![0u8; 80];
    raw.push(3);
    raw.extend_from_slice(&serialize(&legacy_1in()));
    raw.extend_from_slice(&FLAG_ZERO_TX);
    raw.extend_from_slice(&serialize(&legacy_1in()));
    let (block, pres, _) = decode_block_precomputes(&raw, false).unwrap();
    let tx = &block.txdata[1];
    assert!(tx.input.is_empty() && tx.output.is_empty());
    assert_eq!(
        (tx.version, tx.lock_time),
        (Version::TWO, LockTime::from_consensus(7))
    );
    let core = sha256d::Hash::hash(&FLAG_ZERO_TX).to_byte_array();
    assert_eq!(pres[1].txid, core);
    assert_eq!(tx.compute_txid().to_byte_array(), core);
    assert_eq!(pres[1].wtxid, core, "no witness: wtxid is the txid");
    assert_eq!(
        pres[2].txid, pres[0].txid,
        "the next tx starts after locktime"
    );
}

#[test]
fn decode_block_precomputes_hashes_payload_slices() {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    let genesis = genesis_block(Network::Regtest);
    let raw = serialize(&genesis);
    let (block, pres, _ns) = decode_block_precomputes(&raw, false).expect("decode");
    assert_eq!(block.header, genesis.header);
    assert_eq!(pres.len(), genesis.txdata.len());
    let want = TxPrecompute::from_tx_connect(&genesis.txdata[0]);
    assert_eq!(pres[0].txid, want.txid);
    assert_eq!(pres[0].wtxid, want.wtxid);
    assert_eq!(pres[0].sha_prevouts(), None);
}

/// Queue-depth bytes are header + tx-count + each pres wire length.
/// A witness tx's `total_size` includes the witness; `base_size` does not.
#[test]
fn witness_block_wire_len_matches_payload() {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    let mut block = genesis_block(Network::Regtest);
    block.txdata = vec![p2wpkh_like(), legacy_1in()];
    let raw = serialize(&block);
    let (decoded, pres, _) = decode_block_precomputes(&raw, false).expect("decode");
    assert!(pres[0].has_witness);
    assert!(pres[0].total_size > pres[0].base_size);
    assert!(!pres[1].has_witness);
    assert_eq!(
        block_wire_len_from_pres(decoded.txdata.len(), &pres),
        raw.len()
    );
}

#[test]
fn pres_for_tip_connects_live_and_hashes_the_rest() {
    let live = p2wpkh_like();
    let other = legacy_1in();
    let live_id = live.compute_txid().to_byte_array();
    let (pres, skip) = pres_for_tip(&[live.clone(), other.clone()], false, |tid| tid == live_id);
    assert_eq!(pres.len(), 2);
    assert_eq!(pres[0].txid, live_id);
    assert_eq!(
        pres[0].sha_prevouts(),
        None,
        "live tx must skip sighash midstates"
    );
    assert_eq!(
        pres[1].sha_prevouts(),
        Some(oracle_sha_prevouts(&other)),
        "non-live must keep midstates"
    );
    assert_eq!(skip.len(), 1);
    assert!(skip.contains(&live_id));
}

#[test]
fn pres_for_tip_empty_live_set_uses_from_tx() {
    let tx = p2wpkh_like();
    let (pres, skip) = pres_for_tip(std::slice::from_ref(&tx), true, |_| {
        panic!("empty live-set must not probe")
    });
    assert!(skip.is_empty());
    assert_eq!(pres[0].sha_prevouts(), Some(oracle_sha_prevouts(&tx)));
}

#[test]
fn from_connect_midstates_match_from_tx() {
    let tx = p2wpkh_like();
    let c = TxPrecompute::from_tx_connect(&tx);
    assert!(c.sha_prevouts().is_none());
    let filled = TxScriptPrecompute::from_connect(c.into_connect(), &tx);
    let full = TxScriptPrecompute::from_tx(&tx);
    assert_eq!(filled.txid, full.txid);
    assert_eq!(filled.wtxid, full.wtxid);
    assert_eq!(filled.sha_prevouts, full.sha_prevouts);
    assert_eq!(filled.sha_sequences, full.sha_sequences);
    assert_eq!(filled.sha_outputs, full.sha_outputs);
}

#[test]
fn tx_precompute_finish_spent_matches_amount_spk_walk() {
    let tx = p2wpkh_like();
    let prev = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes(
            vec![0x00, 0x14].into_iter().chain([0xab; 20]).collect(),
        ),
    };
    let mut p = TxPrecompute::from_tx(&tx);
    p.finish_spent(std::slice::from_ref(&prev));
    let mut ea = sha256::Hash::engine();
    let mut es = sha256::Hash::engine();
    prev.value.consensus_encode(&mut ea).unwrap();
    prev.script_pubkey.consensus_encode(&mut es).unwrap();
    assert_eq!(
        p.sha_amounts(),
        Some(sha256::Hash::from_engine(ea).to_byte_array())
    );
    assert_eq!(
        p.sha_scriptpubkeys(),
        Some(sha256::Hash::from_engine(es).to_byte_array())
    );
}
