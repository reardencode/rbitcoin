use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, Witness,
};
use rbitcoin_consensus::{ChainParams, ConsensusError, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_query::confirm_run::lookup::*;
use rbitcoin_query::confirm_run::*;
use rbitcoin_query::ConfirmError;
use rbitcoin_query::IdMap;
use rbitcoin_query::Query;
use rbitcoin_store::HeaderRecord;
use rbitcoin_store::StoreError;
use std::sync::Arc;
fn tmp_query() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("stamp-archived")
}

fn spend_block(prev: [u8; 32]) -> Block {
    Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(prev),
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
        }],
    }
}

/// plan=None rehydrate and the query helper stamp the same skeleton parent.
#[test]
fn archived_stamp_matches_shared_helper_on_skeleton() {
    use rbitcoin_query::BatchParentIds;
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let parent_txid = {
        let mut t = [0u8; 32];
        t[0] = 0x81;
        t
    };
    let mut m = IdMap::default();
    m.insert(parent_txid, (rbitcoin_primitives::Fk(88), (4000, 32)));
    let skel = BatchParentIds {
        ids: std::sync::Arc::new(m),
        spent: std::sync::Arc::new(rbitcoin_query::U64Map::default()),
        n_out: Default::default(),
        need_vouts: rbitcoin_query::U64Map::default(),
    };

    let helper = rbitcoin_query::stamp_external_parents(
        q.store(),
        &[parent_txid],
        &rbitcoin_query::InFlight::new(),
        Some(&skel),
        q.confirm_stats(),
    )
    .expect("shared helper");

    let meta = BodyMeta {
        height: Height(params.btc.bip34_height),
        hash: [0u8; 32],
        header_fk: rbitcoin_primitives::Fk::NULL,
        header_rec: HeaderRecord {
            prev_fk: rbitcoin_primitives::Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [0u8; 32],
            hash: [0u8; 32],
            size: 0,
            weight: 0,
        },
        tx_fks: Vec::new(),
        txids: Vec::new(),
        pres: std::sync::Arc::from(Vec::new()),
    };
    let stamp = stamp_parent_pin_archived(
        &q,
        &params,
        std::slice::from_ref(&meta),
        &[std::sync::Arc::new(spend_block(parent_txid))],
        None,
        Some(&skel),
        Some(&[parent_txid][..]),
    )
    .expect("archived stamp");
    assert_eq!(
        stamp.body_range(88),
        helper.idents.get(&88).and_then(|p| p.body)
    );
    assert_eq!(
        stamp.create_txid(88),
        helper.idents.get(&88).map(|p| p.txid)
    );
    assert_eq!(stamp.resolved.get(&parent_txid), Some(&88));
    let empty_wire = stamp_parent_pin_archived(
        &q,
        &params,
        std::slice::from_ref(&meta),
        &[std::sync::Arc::new(spend_block(parent_txid))],
        None,
        Some(&skel),
        Some(&[]),
    )
    .expect("empty carried_need skips wire inputs");
    assert!(
        !empty_wire.resolved.contains_key(&parent_txid),
        "skeleton stamp must not re-walk wire inputs"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Loadq already hashed; stamp must succeed with the caller pres on the meta.
#[test]
fn stamp_uses_caller_pres() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::accept_and_connect_block;
    use rbitcoin_query::TxPrecompute;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let pres: Arc<[TxPrecompute]> = b1
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let items = [(Height(1), Arc::new(b1), Some(Arc::clone(&pres)))];
    let stamped = confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
        .expect("coinbase-only stamp");
    assert!(
        Arc::ptr_eq(&stamped.wire_blocks[0], &items[0].1),
        "stamp must share caller Arc<Block>"
    );
    assert_eq!(stamped.metas[0].pres.len(), pres.len());
    assert_eq!(stamped.metas[0].pres[0].txid, pres[0].txid);
    let plan = stamped.plan.as_ref().expect("new body plans");
    assert_eq!(plan.packed.len(), 1);
    assert!(
        plan.packed[0].1.is_empty(),
        "wire plan must not retain scriptSig or witness"
    );
    assert!(
        !plan.edges.is_empty(),
        "wire plan keeps spend edges for commit"
    );
    let want = items[0].1.txdata[0].output[0].script_pubkey.as_bytes();
    let want_ptr = want.as_ptr();
    assert_eq!(
        plan.batch_pin[0].with_out_parts(0, |_, script| script.to_vec()),
        Some(want.to_vec()),
        "CreatePin outs from wire script_pubkey"
    );
    assert_eq!(
        plan.batch_pin[0].with_out_parts(0, |_, script| script.as_ptr()),
        Some(want_ptr),
        "plan must not copy scriptPubKey"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn stamp_skips_header_ensure_when_pipeline_carries_fk() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::accept_and_connect_block;
    use std::sync::atomic::Ordering;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let hash = b1.block_hash().to_byte_array();
    let genesis_fk = q
        .get_header_by_hash(&genesis.block_hash().to_byte_array())
        .unwrap()
        .unwrap()
        .0;
    let rec = rbitcoin_query::header_to_record(genesis_fk, &b1.header, hash);
    let hfk = q.store().put_header(&rec).unwrap();
    let n_headers = q.store().headers.count();
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: vec![hfk],
        carried_header_hashes: vec![hash],
    };
    let items = [(Height(1), Arc::new(b1), None)];
    let _ = q
        .confirm_stats()
        .phase_prep_header_skip_n
        .swap(0, Ordering::Relaxed);
    let stamped = confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
        .expect("carried header stamp");
    assert_eq!(
        q.confirm_stats()
            .phase_prep_header_skip_n
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(q.store().headers.count(), n_headers);
    assert_eq!(stamped.metas[0].header_fk, hfk);
    assert_eq!(stamped.metas[0].hash, hash);
    let plan = stamped.plan.as_ref().expect("plan");
    assert_eq!(plan.per_header_ranges[0].0, hfk);

    let pipe_bad = WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: vec![hfk],
        carried_header_hashes: vec![[0x11; 32]],
    };
    match confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe_bad)) {
        Err(ConfirmError::Rules(ConsensusError::BadBlock("carried header hash mismatch"))) => {}
        Err(e) => panic!("expected hash mismatch, got {e}"),
        Ok(_) => panic!("expected hash mismatch, got Ok"),
    }
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn wire_lookup_uses_carried_header_hash() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::accept_and_connect_block;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let hash = b1.block_hash().to_byte_array();
    let genesis_fk = q
        .get_header_by_hash(&genesis.block_hash().to_byte_array())
        .unwrap()
        .unwrap()
        .0;
    let rec = rbitcoin_query::header_to_record(genesis_fk, &b1.header, hash);
    let hfk = q.store().put_header(&rec).unwrap();
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = |hashes: Vec<[u8; 32]>, fks: Vec<rbitcoin_primitives::Fk>| WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: fks,
        carried_header_hashes: hashes,
    };
    let items = [(Height(1), Arc::new(b1.clone()), None)];
    let stamped = confirm_wire_lookup_stamp(
        &q,
        &params,
        Milestone::NONE,
        &items,
        Some(&pipe(vec![hash], vec![hfk])),
    )
    .expect("carried header");
    assert_eq!(stamped.metas[0].hash, hash);
    assert_eq!(stamped.metas[0].header_fk, hfk);

    let bare = confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None)
        .expect("no carried hash still stamps");
    assert_eq!(bare.metas[0].hash, hash);

    let mut tweaked = b1;
    tweaked.header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x22; 32]);
    let tweaked_items = [(Height(1), Arc::new(tweaked), None)];
    match confirm_wire_lookup_stamp(
        &q,
        &params,
        Milestone::NONE,
        &tweaked_items,
        Some(&pipe(vec![hash], vec![hfk])),
    ) {
        Err(ConfirmError::Rules(ConsensusError::BadBlock("carried header hash mismatch"))) => {}
        Err(e) => panic!("prev change must stay a carried-hash mismatch, got {e}"),
        Ok(_) => panic!("prev change must not adopt the stored header hash"),
    }
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn stamp_does_not_bind_carried_fk_when_store_hash_differs() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::accept_and_connect_block;
    use std::sync::atomic::Ordering;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let genesis_fk = q
        .get_header_by_hash(&genesis.block_hash().to_byte_array())
        .unwrap()
        .unwrap()
        .0;
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let hash = b1.block_hash().to_byte_array();
    let n_headers = q.store().headers.count();
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: vec![genesis_fk],
        carried_header_hashes: vec![hash],
    };
    let items = [(Height(1), Arc::new(b1), None)];
    let _ = q
        .confirm_stats()
        .phase_prep_header_skip_n
        .swap(0, Ordering::Relaxed);
    let stamped = confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe))
        .expect("dummy BQ fk still ensures");
    assert_eq!(
        q.confirm_stats()
            .phase_prep_header_skip_n
            .load(Ordering::Relaxed),
        0
    );
    assert!(q.store().headers.count() > n_headers);
    assert_ne!(stamped.metas[0].header_fk, genesis_fk);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn stamp_rejects_carried_header_length_mismatch() {
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::accept_and_connect_block;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let hash = b1.block_hash().to_byte_array();
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: q.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: vec![rbitcoin_primitives::Fk(1), rbitcoin_primitives::Fk(1)],
        carried_header_hashes: vec![hash],
    };
    let fks_only = WireLoadPipeline {
        path_lo: 1,
        parent_hash: None,
        next_tx_start: pipe.next_tx_start,
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: Vec::new(),
        carried_header_hashes: vec![hash],
    };
    let items = [(Height(1), Arc::new(b1), None)];
    match confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&pipe)) {
        Err(ConfirmError::Store(StoreError::Corrupt("invariant: carried header length"))) => {}
        Err(e) => panic!("expected carried header length, got {e}"),
        Ok(_) => panic!("expected carried header length, got Ok"),
    }
    match confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, Some(&fks_only)) {
        Err(ConfirmError::Store(StoreError::Corrupt("invariant: carried header length"))) => {}
        Err(e) => panic!("one carried side must still be checked, got {e}"),
        Ok(_) => panic!("empty fks with a hash must fail the length check"),
    }
    let _ = std::fs::remove_dir_all(&path);
}

fn empty_header_rec() -> HeaderRecord {
    HeaderRecord {
        prev_fk: rbitcoin_primitives::Fk::NULL,
        version: 1,
        timestamp: 1,
        bits: 1,
        nonce: 1,
        merkle_root: [0u8; 32],
        hash: [0u8; 32],
        size: 0,
        weight: 0,
    }
}

fn meta_with(txids: Vec<[u8; 32]>, tx_fks: Vec<rbitcoin_primitives::Fk>) -> BodyMeta {
    BodyMeta {
        height: Height(1),
        hash: [2u8; 32],
        header_fk: rbitcoin_primitives::Fk(1),
        header_rec: empty_header_rec(),
        tx_fks,
        txids,
        pres: std::sync::Arc::from(Vec::new()),
    }
}

#[test]
fn archived_create_pairs_len_mismatch_is_corrupt() {
    let meta = meta_with(vec![[1u8; 32], [2u8; 32]], vec![rbitcoin_primitives::Fk(1)]);
    match archived_create_pairs(std::slice::from_ref(&meta)) {
        Err(ConfirmError::Store(StoreError::Corrupt(m))) => {
            assert_eq!(m, "invariant: archived stamp tx_fks/txids length");
        }
        other => panic!("expected length Corrupt, got {other:?}"),
    }
}

#[test]
fn archived_create_pairs_header_txs_hole_is_skip() {
    let hole = meta_with(vec![[1u8; 32]], vec![]);
    assert!(archived_create_pairs(std::slice::from_ref(&hole))
        .expect("empty tx_fks is a header_txs hole")
        .is_empty());
    let tid = [9u8; 32];
    let fk = rbitcoin_primitives::Fk(7);
    let pairs =
        archived_create_pairs(&[hole, meta_with(vec![tid], vec![fk])]).expect("hole then match");
    assert_eq!(pairs, vec![(tid, fk)]);
}

#[test]
fn archived_create_pairs_from_stamp_metas() {
    let blank = meta_with(vec![[0u8; 32]], vec![rbitcoin_primitives::Fk(1)]);
    assert!(archived_create_pairs(std::slice::from_ref(&blank))
        .expect("zero txid skipped")
        .is_empty());
}
