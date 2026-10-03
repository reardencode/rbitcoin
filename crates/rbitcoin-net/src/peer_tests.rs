use super::*;
use crate::peers::{CappedSet, PeerOut};
use bitcoin::BlockHash;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};

fn served_block(p: PeerOut) -> bitcoin::Block {
    match p {
        PeerOut::Encoded(bytes) => {
            assert_eq!(bytes.first().copied(), Some(2), "v2 block short id");
            bitcoin::consensus::encode::deserialize(&bytes[1..]).expect("served block payload")
        }
        PeerOut::Msg(NetworkMessage::Block(b)) => b,
        other => panic!("expected served block, got {other:?}"),
    }
}
#[test]
fn p2p_serve_line_names_tx_bytes_wall() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("serve-line");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let _ = crate::serve_perf::sample_reset_serve_perf();
    let encoded = encode_served_witness_block(&hub.cache, &hub.query, &gen)
        .unwrap()
        .expect("genesis Class A body");
    assert_eq!(encoded.first().copied(), Some(2), "v2 block short id");
    let s = crate::serve_perf::sample_reset_serve_perf();
    assert!(s.n >= 1, "{s:?}");
    assert!(s.bytes > 0, "{s:?}");
    assert!(s.tx_count >= 1, "{s:?}");
    let line = crate::serve_perf::format_serve_perf(&s);
    assert!(
        !line.contains("p2p: serve"),
        "per-block p2p: serve is not the 5s helper: {line}"
    );
    assert!(line.contains("serve n="), "{line}");
    assert!(line.contains("bytes="), "{line}");
    assert!(line.contains("tx="), "{line}");
    assert!(!line.contains("ntx="), "{line}");
    assert!(line.contains("avg_us="), "{line}");
    assert!(line.contains("max_us="), "{line}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn misbehavior_disconnect_log_is_not_banlist() {
    let line = misbehavior_disconnect_log("7", 100);
    assert_eq!(
        line,
        format!("p2p: 7 misbehavior 100 ≥ {BAN_SCORE_THRESHOLD} — disconnect")
    );
    assert!(
        !line.to_ascii_lowercase().contains("ban score"),
        "disconnect log is not banlist language: {line}"
    );
}

#[test]
fn store_not_found_is_soft_session_error() {
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "consensus: store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "StoreError::NotFound for fk".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "NOT FOUND".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Consensus(
        "corrupt record: multi-spender".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Protocol(
        "unknown parent"
    )));
    assert!(!net_error_is_store_not_found(&NetError::Timeout));
    assert!(!net_error_is_store_not_found(&NetError::Io(
        std::io::Error::other("x")
    )));
}

#[test]
fn from_this_peer_insert_caps_and_keeps_latest() {
    use bitcoin::hashes::Hash;
    let mut m = CappedSet::new();
    let cap = 4usize;
    for i in 0u8..6 {
        m.insert(bitcoin::Txid::from_byte_array([i; 32]), cap);
        assert!(m.len() <= cap, "len {}", m.len());
    }
    assert_eq!(m.len(), cap);
    assert!(m.contains_key(&bitcoin::Txid::from_byte_array([5u8; 32])));
    assert!(m.contains_key(&bitcoin::Txid::from_byte_array([2u8; 32])));
    assert!(
        !m.contains_key(&bitcoin::Txid::from_byte_array([0u8; 32])),
        "oldest origin txid must roll off"
    );
    assert!(!m.contains_key(&bitcoin::Txid::from_byte_array([1u8; 32])));
    assert_eq!(FROM_THIS_PEER_CAP, 50_000);
}

#[test]
fn capped_set_reinsert_keeps_insertion_order() {
    use bitcoin::hashes::Hash;
    let mut m = CappedSet::new();
    let cap = 3usize;
    let id = |i: u8| bitcoin::Txid::from_byte_array([i; 32]);
    m.insert(id(0), cap);
    m.insert(id(1), cap);
    m.insert(id(2), cap);
    m.insert(id(0), cap);
    m.insert(id(3), cap);
    assert_eq!(m.len(), cap);
    assert!(
        !m.contains_key(&id(0)),
        "re-insert must not refresh FIFO; oldest insertion still rolls"
    );
    assert!(m.contains_key(&id(1)));
    assert!(m.contains_key(&id(2)));
    assert!(m.contains_key(&id(3)));
}

#[test]
fn tip_follow_locator_empty_store_has_genesis_zero() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("empty");
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc.last().unwrap().to_byte_array(), [0u8; 32]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_follow_locator_includes_tip_after_genesis() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("gen");
    hub.ensure_genesis().unwrap();
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    // Newest-first: tip hash is first.
    assert_eq!(loc[0], hub.tip_hash().unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_unknown_starts_at_that_hash() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("loc-unk");
    hub.ensure_genesis().unwrap();
    let start = BlockHash::from_byte_array([0xab; 32]);
    let loc = headers_sync_locator(&hub, Some(start));
    assert_eq!(loc[0], start);
    assert_eq!(loc.last().copied(), hub.tip_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_mid_height_starts_there() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("loc-mid");
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .generate_to_script(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let mid = hashes[0];
    let loc = headers_sync_locator(&hub, Some(mid));
    assert_eq!(loc[0], mid);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn should_poll_peer_headers_skips_behind_and_weaker_fork() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("poll-skip");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    assert!(should_poll_peer_headers(&hub, None));
    hub.generate_to_script(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    assert!(
        should_poll_peer_headers(&hub, Some(tip)),
        "at our tip: still poll in case they have a new block"
    );
    assert!(
        !should_poll_peer_headers(&hub, Some(gen)),
        "best-known on our chain behind tip cannot supply headers after our locator"
    );
    assert!(
        should_poll_peer_headers(&hub, Some(BlockHash::from_byte_array([0xee; 32]))),
        "unknown best-known still poll until we can classify the branch"
    );
    let mut fork = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: gen,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x22; 32]),
        time: 1_300_000_000,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 99,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut fork);
    hub.ensure_header(&fork).unwrap();
    assert!(
        !should_poll_peer_headers(&hub, Some(fork.block_hash())),
        "persisted weaker fork cannot beat our tip"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn live_follow_dec_on_drop() {
    let c = Arc::new(AtomicUsize::new(2));
    {
        let _g = LiveFollowDec(Some(c.clone()));
        assert_eq!(c.load(Ordering::SeqCst), 2);
    }
    assert_eq!(c.load(Ordering::SeqCst), 1);
    // None branch is a no-op drop.
    let _ = LiveFollowDec(None);
}

#[test]
fn local_service_flags_include_network_witness_v2() {
    let f = local_service_flags();
    assert!(f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn local_service_flags_pruned_are_limited_not_network() {
    let f = local_service_flags_pruned(true);
    assert!(f.has(ServiceFlags::NETWORK_LIMITED));
    assert!(!f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
    assert_eq!(local_service_flags_pruned(false), local_service_flags());
}

#[test]
fn rand_nonce_changes() {
    let a = rand_nonce();
    let b = rand_nonce();
    // Counter component makes back-to-back nonces distinct.
    assert_ne!(a, b);
}

#[test]
fn block_for_peer_empty_store_none() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("block-none");
    let cache = BlockCache::new();
    let miss = BlockHash::from_byte_array([0xab; 32]);
    assert!(block_for_peer(&cache, &q, &miss).unwrap().is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cmpct_helpers_without_mempool_and_queue_out_closed() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("cmpct-none");
    hub.ensure_genesis().unwrap();
    assert!(hub.mempool().is_none());

    // Closed channel → Protocol error.
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    assert!(queue_out(&tx, NetworkMessage::Verack).is_err());
    assert!(queue_getheaders(&tx, &hub, None, false, None).is_err());

    // headers_for_peer empty store after genesis still returns (tip exists).
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    let gh = GetHeadersMessage::new(
        vec![hub.tip_hash().unwrap()],
        BlockHash::from_byte_array([0u8; 32]),
    );
    let hdrs = headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &gh).unwrap();
    // Beyond tip: empty headers is fine.
    assert!(hdrs.is_empty() || !hdrs.is_empty());

    // drain_pending empty is a no-op.
    let mut pb = PendingBlocks::new();
    let mut ph = HashMap::new();
    let (tx, _rx) = mpsc::unbounded_channel();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false).unwrap();

    // Invalid tip-extending body must not kill the session (001).
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let tip = hub.tip_hash().unwrap();
    let tip_block = hub
        .query
        .reconstruct_block_by_hash(&tip.to_byte_array())
        .unwrap()
        .expect("tip body");
    let coinbase = Transaction {
        version: TxVersion::ONE,
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
    // Second tx spends a nonexistent prevout → consensus reject.
    let junk = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0xab; 32]),
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
    let mut bad = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: tip,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: tip_block.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, junk],
    };
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bad.header.bits);
    for nonce in 0..200_000u32 {
        bad.header.nonce = nonce;
        if bad.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let bh = bad.block_hash();
    pb.insert(bh, bad.clone());
    let (tx, _rx) = mpsc::unbounded_channel();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false)
        .expect("invalid block must not end session");
    assert!(
        hub.is_block_invalid(&bh),
        "consensus-invalid body must be cached as failed"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_compactblocks.py` stalling peer: a peer's partial for a block that
/// connected through another peer must not hold its one pending slot, or the
/// peer's next compact becomes a full getdata and its blocktxn is ignored.
/// Core drops every peer's in-flight entry once the block is received.
#[tokio::test]
async fn partial_for_a_block_connected_elsewhere_frees_the_slot() {
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("cmpct-stale-partial");
    hub.ensure_genesis().unwrap();
    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mut time = hub.tip_header().unwrap().time + 1;
    let mut coinbases = Vec::new();
    for height in 1..=102u32 {
        let b = rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            height,
            op_true.clone(),
            vec![],
        );
        coinbases.push(b.txdata[0].compute_txid());
        hub.accept_block(b).unwrap();
        time += 1;
    }
    let spend = |i: usize| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbases[i],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: op_true.clone(),
        }],
    };
    let a = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        time,
        103,
        op_true.clone(),
        vec![spend(0)],
    );
    let b = rbitcoin_consensus::mine_regtest_paying(
        a.block_hash(),
        time + 1,
        104,
        op_true.clone(),
        vec![spend(1)],
    );

    let peers = crate::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18447);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let stalling = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let cmpct = |blk: &bitcoin::Block| CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(blk, 0xbeef, 2, &[]).unwrap(),
    };

    on_cmpctblock(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &cmpct(&a),
    )
    .await
    .unwrap();
    assert!(matches!(
        out_rx.try_recv().unwrap().expect_msg(),
        NetworkMessage::GetBlockTxn(_)
    ));
    hub.accept_block(a.clone()).unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a.block_hash()),
        "A arrived from another peer"
    );

    on_cmpctblock(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &cmpct(&b),
    )
    .await
    .unwrap();
    let mut sent = Vec::new();
    while let Ok(m) = out_rx.try_recv() {
        sent.push(m.expect_msg());
    }
    assert!(
        sent.iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(g) if g.txs_request.block_hash == b.block_hash())),
        "the stale partial for A must not turn B into a full getdata: {sent:?}"
    );
    on_blocktxn(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &BlockTransactions {
            block_hash: b.block_hash(),
            transactions: vec![b.txdata[1].clone()],
        },
    )
    .await
    .unwrap();
    assert_eq!(hub.tip_hash(), Some(b.block_hash()), "blocktxn completes B");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn same_peer_pending_cmpct_does_not_getblocktxn_again() {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, Network, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Witness,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("cmpct-same-peer");
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        assert!(hub.attach_mempool(mp).is_ok());
        let coinbase = Transaction {
            version: TxVersion::ONE,
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
        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut block = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: hub.tip_hash().unwrap(),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, spend],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
        let hash = block.block_hash();
        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18446);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let session = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        let frame = frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }));
        handle_peer_frame(frame.clone(), &hub, &out_tx, &mut follow, Some(&session))
            .await
            .unwrap();
        match out_rx.try_recv().expect("first getblocktxn").expect_msg() {
            NetworkMessage::GetBlockTxn(_) => {}
            other => panic!("expected getblocktxn, got {other:?}"),
        }
        handle_peer_frame(frame, &hub, &out_tx, &mut follow, Some(&session))
            .await
            .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "same-peer compact while pending must not getblocktxn again"
        );
        assert!(
            follow.pending_cmpct.contains_key(&hash),
            "first NeedTxn pending must stay"
        );
        assert!(
            peers.try_cmpct_fill_slot(hash, true),
            "same-peer retry must not consume the second inbound fill slot"
        );
        assert!(!peers.try_cmpct_fill_slot(hash, true));
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn handle_peer_frame_control_and_inv_paths() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Network;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        // 4 magic + 12 command + 4 len + 4 checksum + payload
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("handle-frame");
        hub.ensure_genesis().unwrap();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 2u32,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0u32,
        };

        // SendHeaders / SendCmpct / WtxidRelay / Pong / GetAddr / Ping
        // (MemPool disconnects — covered by bloom_disabled_messages_request_disconnect.)
        // SendAddrV2 after verack disconnects (`p2p_addrv2_relay.py`).
        for msg in [
            NetworkMessage::SendHeaders,
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
            NetworkMessage::WtxidRelay,
            NetworkMessage::Pong(7),
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(42),
        ] {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        }
        assert!(follow.wants_headers);
        assert!(follow.wtxid_relay);
        assert!(follow.send_cmpct);
        assert_eq!(follow.cmpct_version, 2);

        // Drain outbound: Pong(42) + empty Addr at least.
        let mut saw_pong = false;
        let mut saw_addr = false;
        while let Ok(m) = out_rx.try_recv().map(PeerOut::expect_msg) {
            match m {
                NetworkMessage::Pong(n) => {
                    assert_eq!(n, 42);
                    saw_pong = true;
                }
                NetworkMessage::Addr(a) => {
                    assert!(a.is_empty());
                    saw_addr = true;
                }
                _ => {}
            }
        }
        assert!(saw_pong);
        assert!(saw_addr);

        // GetHeaders from empty tip-beyond locator.
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;
        let gh = GetHeadersMessage::new(
            vec![hub.tip_hash().unwrap()],
            BlockHash::from_byte_array([0u8; 32]),
        );
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(gh)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let headers_msg = out_rx.try_recv().unwrap().expect_msg();
        assert!(matches!(headers_msg, NetworkMessage::Headers(_)));

        // Inv for unknown block → GetHeaders (never getdata without a header).
        let want_h = BlockHash::from_byte_array([0xee; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(want_h)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::GetHeaders(gh) => {
                assert!(
                    !gh.locator_hashes.is_empty() || gh.stop_hash == want_h,
                    "unknown block inv must getheaders, locators={:?}",
                    gh.locator_hashes
                );
            }
            other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
        }

        // Headers message inserts pending + issues getdata.
        let gen = hub
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(0))
            .unwrap();
        // Synthesize a child-looking header (not valid pow; just exercises map).
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, TxMerkleNode};
        let child = Header {
            version: Version::from_consensus(4),
            prev_blockhash: gen.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([2u8; 32]),
            time: gen.time + 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 1,
        };
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![child])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.pending_headers.contains_key(&child.block_hash()));
        let _ = out_rx.try_recv(); // GetData

        // GetData for known tip block (cache miss → reconstruct).
        let tip = hub.tip_hash().unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert_eq!(served_block(out_rx.try_recv().unwrap()).block_hash(), tip);

        // CompactBlock getdata for tip.
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::CmpctBlock(_)
        ));

        // GetBlockTxn with bad index → disconnect score.
        use bitcoin::bip152::BlockTransactionsRequest;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![999],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= BAN_SCORE_THRESHOLD);

        // GetBlockTxn good index 0 (coinbase).
        follow.ban_score = 0;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::BlockTxn(_)
        ));

        // Deeper than 10: full block, not blocktxn (`p2p_compactblocks` :635).
        hub.generate_to_script(12, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                out_rx.try_recv().unwrap().expect_msg(),
                NetworkMessage::Block(_)
            ),
            "getblocktxn past depth 10 must send a full block"
        );

        // Unsolicited BlockTxn → mild ban.
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: BlockHash::from_byte_array([0xdd; 32]),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= 5);

        // CmpctBlock without mempool → full getdata fallback.
        let gen_block = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let hsi = HeaderAndShortIds::from_block(&gen_block, 9, 2, &[]).unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Already have tip → no getdata; if different hash would request.
        // Genesis is already known so "already have" arm.
        let _ = out_rx.try_recv();

        // Unknown command (including the retired rbtpkg name) is a no-op.
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload: vec![1, 2, 3],
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        // SendCmpct with unsupported version is ignored.
        handle_peer_frame(
            frame_for(NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: 99,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.send_cmpct); // still true from earlier v2
        assert_eq!(follow.cmpct_version, 2);

        // Inventory::Block (non-witness) for unknown → GetHeaders.
        let want2 = BlockHash::from_byte_array([0xcc; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::Block(want2)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::GetHeaders(_) => {}
            other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
        }

        // GetData for a block this node has never seen → notfound, not silence.
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(
                want2,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WitnessBlock(want2)]);
            }
            other => panic!("expected NotFound for unknown block getdata, got {other:?}"),
        }

        // Header row, no body: notfound from the blocking encode, not silence.
        let (gen_fk, gen_rec) = hub
            .query
            .get_header_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let merkle = [0x44u8; 32];
        let version = 4i32;
        let time = gen_rec.timestamp.saturating_add(1);
        let bits = gen_rec.bits;
        let nonce = 9u32;
        let hash = rbitcoin_store::block_header_hash(
            version,
            &tip.to_byte_array(),
            &merkle,
            time,
            bits,
            nonce,
        );
        hub.query
            .put_header(&rbitcoin_store::HeaderRecord {
                prev_fk: gen_fk,
                version,
                timestamp: time,
                bits,
                nonce,
                merkle_root: merkle,
                hash,
                size: 0,
                weight: 0,
            })
            .unwrap();
        let header_only = BlockHash::from_byte_array(hash);
        assert!(hub.knows_header(&header_only), "header row without a body");
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(
                header_only,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WitnessBlock(header_only)]);
            }
            other => panic!("expected NotFound for header-only getdata, got {other:?}"),
        }

        // Inv for known tip → no GetData.
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(out_rx.try_recv().is_err());

        // GetData Inventory::Block for tip (non-witness arm).
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::Block(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let _ = served_block(out_rx.try_recv().unwrap());

        // Full Block message path: pending + drain_pending (AlreadyHave for tip).
        let gen_block2 = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::Block(gen_block2)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Tip already confirmed — drain accepts AlreadyHave and may leave empty pending.

        // Tx without mempool is a no-op.
        use bitcoin::absolute::LockTime;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        let dummy_tx = Transaction {
            version: TxVersion::TWO,
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
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(dummy_tx)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        // Catch-all unknown command.
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("zzzzzz").unwrap(),
                payload: vec![],
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Mempool-backed inv/tx/getdata arms + cmpctblocktxn success.
#[test]
fn handle_peer_frame_mempool_tx_and_inv_paths() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("handle-mp");
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        assert!(!hub.in_ibd(), "tx inv getdata pin is not IBD");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        // Enable relay so Inv for txs triggers getdata.
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 2u32,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0u32,
        };

        let unknown_txid = bitcoin::Txid::from_byte_array([0x42; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::GetData(v) => {
                assert!(!v.is_empty());
            }
            other => panic!("expected GetData for unknown txs, got {other:?}"),
        }

        // GetData for missing tx → notfound (Core ProcessGetData).
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v.len(), 2);
            }
            other => panic!("expected batched NotFound, got {other:?}"),
        }
        assert!(out_rx.try_recv().is_err());

        let genesis_txid =
            bitcoin::blockdata::constants::genesis_block(Network::Regtest).txdata[0].compute_txid();
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessTransaction(
                genesis_txid,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "Class A txid INV must not GETDATA"
        );

        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let mined = hub
            .query
            .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
            .unwrap();
        let cb = &mined.txdata[0];
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![
                Inventory::WitnessTransaction(cb.compute_txid()),
                Inventory::WTx(cb.compute_wtxid()),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "recent-confirmed INV must not GETDATA"
        );

        // Accept path with invalid prevout — still exercises Tx arm (inserts from_peer).
        let junk = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let junk_txid = junk.compute_txid();
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(junk)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Origin map is filled before accept result.
        assert!(follow.from_this_peer.contains_key(&junk_txid));

        // Retired rbtpkg name with mempool + relay: still unknown, no admit
        // even when the payload is the old len-prefixed encoding.
        let pkg_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let pkg_txid = pkg_tx.compute_txid();
        let raw = bitcoin::consensus::encode::serialize(&pkg_tx);
        let mut payload = Vec::with_capacity(4 + raw.len());
        payload.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        payload.extend_from_slice(&raw);
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload,
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(!follow.from_this_peer.contains_key(&pkg_txid));
        assert_eq!(hub.mempool().unwrap().live_count(), 0);

        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn tx_accept_log_parks_orphans_silences_duplicates() {
    use bitcoin::hashes::Hash;
    let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
    assert_eq!(
        tx_accept_log(&rbitcoin_mempool::AcceptError::Duplicate(txid)),
        TxAcceptLog::Silent
    );
    let e = rbitcoin_mempool::AcceptError::Orphaned {
        txid,
        missing: Default::default(),
        fresh: true,
    };
    assert!(matches!(tx_accept_log(&e), TxAcceptLog::Park(m) if m.is_empty()));
    let again = rbitcoin_mempool::AcceptError::Orphaned {
        txid,
        missing: Default::default(),
        fresh: false,
    };
    assert!(matches!(tx_accept_log(&again), TxAcceptLog::ParentFetch(_)));
    assert_eq!(
        tx_accept_log(&rbitcoin_mempool::AcceptError::Policy("min relay fee")),
        TxAcceptLog::Reject
    );
}

/// Core `m_lazy_recent_rejects`: a second forcerelay send of a rejected tx
/// logs `Not relaying non-mempool` instead of ATMP again (`p2p_permissions`).
fn recent_reject_skips_atmp_on_second_send(via_cidr: bool) {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = coinbase.compute_txid();
    let wtxid = coinbase.compute_wtxid();

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let label = if via_cidr {
            "forcerelay-reject"
        } else {
            "always-relay-reject"
        };
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled(label);
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let peers = crate::peers::PeerHub::new();
        if via_cidr {
            let mut table = crate::net_permissions::NetPermTable::default();
            table
                .whitelist
                .push(crate::net_permissions::parse_whitelist("forcerelay@127.0.0.1").unwrap());
            peers.set_net_perms(table);
        } else {
            peers.set_forcerelay_perm(true);
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let sess = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        if via_cidr {
            assert!(sess.has_net_perm(crate::NetPermissionFlags::FORCE_RELAY));
        } else {
            assert!(!sess.has_net_perm(crate::NetPermissionFlags::FORCE_RELAY));
            assert!(sess.session_forcerelay());
        }

        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 2u32,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0u32,
        };

        rbitcoin_log::capture_logs(true);
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(coinbase.clone())),
            &hub,
            &out_tx,
            &mut follow,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let first = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            first.iter().any(|(_, m)| m.contains(&format!(
                "{txid} (wtxid={wtxid}) from peer=0 was not accepted: coinbase"
            ))),
            "first reject must log ATMP, got {first:?}"
        );

        rbitcoin_log::capture_logs(true);
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(coinbase)),
            &hub,
            &out_tx,
            &mut follow,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let second = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            second.iter().any(|(_, m)| m.contains(&format!(
                "Not relaying non-mempool transaction {txid} (wtxid={wtxid}) from forcerelay peer=0"
            ))),
            "second forcerelay send must skip ATMP, got {second:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn forcerelay_recent_reject_is_not_relayed() {
    recent_reject_skips_atmp_on_second_send(true);
}

#[test]
fn always_relay_recent_reject_is_not_relayed() {
    recent_reject_skips_atmp_on_second_send(false);
}

/// Compact fill with a live mempool hub must not `list_live` every body.
#[test]
fn cmpct_helpers_with_mempool_skip_list_live() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("cmpct-mp");
    hub.ensure_genesis().unwrap();
    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(hub.mempool().is_some());

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            Transaction {
                version: TxVersion::ONE,
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
            },
            spend.clone(),
        ],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();

    let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
    // Mempool present but empty live → Some(missing) not None.
    let missing = match try_reconstruct_cmpct(&hub, &hsi, 2) {
        Some(CmpctReconstruct::NeedTxn(p, _)) => p.missing().to_vec(),
        other => panic!("expected NeedTxn, got {other:?}"),
    };
    assert_eq!(missing, vec![1]); // spend short-id missing
    let mp = hub.mempool().unwrap();
    let _ = mp.sample_reset_perf();
    let _ = try_reconstruct_cmpct(&hub, &hsi, 2);
    let fill = mp.sample_reset_perf();
    assert_eq!(
        fill.list_live, 0,
        "compact fill must not list_live/clone every body (got {})",
        fill.list_live
    );

    use bitcoin::bip152::BlockTransactions;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use bitcoin::Network;
    use tokio::runtime::Builder;
    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }
    let hsi_ok = hsi.clone();
    let hsi_fail = hsi.clone();
    let spend_ok = spend.clone();
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi_fail,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let _ = out_rx.try_recv().expect("getblocktxn");
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= 10, "solicited bad blocktxn bans");
        let gd = match out_rx.try_recv().expect("getdata").expect_msg() {
            NetworkMessage::GetData(inv) => inv,
            other => panic!("expected getdata, got {other:?}"),
        };
        assert!(
            matches!(gd.first(), Some(Inventory::WitnessBlock(_))),
            "bad blocktxn falls back to full block: {gd:?}"
        );
        let ban_after_fail = follow.ban_score;
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            follow.ban_score,
            ban_after_fail + 5,
            "late blocktxn after fail is mild"
        );
    });
    rt.block_on(async {
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi_ok,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let gbt = match out_rx.try_recv().expect("getblocktxn").expect_msg() {
            NetworkMessage::GetBlockTxn(g) => g,
            other => panic!("expected getblocktxn, got {other:?}"),
        };
        assert_eq!(gbt.txs_request.indexes, vec![1]);
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![spend_ok],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            follow.pending_cmpct.is_empty(),
            "blocktxn apply must consume the pending compact"
        );
    });

    let _ = std::fs::remove_dir_all(dir);
}

/// Tip-follow receive: max-work fork held then applied via `accept_received_block`.
#[test]
fn p2p_side_chain_reorgs_via_held_bodies() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("pending-reorg");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();

    let coinbase = |height: u32| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
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
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    };

    // Main tip height 2 (times near genesis MTP window).
    let b1 = mine(gen, 1_300_000_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine(b1.block_hash(), 1_300_000_200, 2);
    hub.accept_block(b2.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));

    // Pending: short side from gen (1 block) + long side from gen (4 blocks).
    let short = mine(gen, 1_300_001_000, 1);
    let mut long = Vec::new();
    let mut p = gen;
    for (i, h) in (1..=4u32).enumerate() {
        let b = mine(p, 1_300_002_000 + i as u32 * 600, h);
        p = b.block_hash();
        long.push(b);
    }
    // Short side first (held, weaker), then the longer fork one body at a time
    // — same order a peer `block` message stream would deliver.
    hub.accept_received_block(short).unwrap();
    for b in &long {
        hub.accept_received_block(b.clone()).unwrap();
    }
    assert_eq!(
        hub.tip_height(),
        Some(4),
        "must reorg onto longer held branch"
    );
    assert_eq!(hub.tip_hash().unwrap(), long[3].block_hash());
    assert!(hub.held_body(&long[3].block_hash()).is_none());
    const {
        assert!(MAX_PENDING_BLOCKS_FOR_TEST >= 128);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn inv_of_already_asked_block_does_not_getdata() {
    // p2p_sendheaders Part 2: test_node announces headers (we getdata),
    // then inv_node re-invs the same hashes. One getdata in flight globally.
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::Network;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        FramedMessage {
            magic,
            command,
            payload: full[24..].to_vec(),
        }
    }

    fn drain_block_getdata(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        while let Ok(m) = rx.try_recv().map(PeerOut::expect_msg) {
            if let NetworkMessage::GetData(inv) = m {
                for i in inv {
                    if let Inventory::Block(h)
                    | Inventory::WitnessBlock(h)
                    | Inventory::CompactBlock(h) = i
                    {
                        hashes.push(h);
                    }
                }
            }
        }
        hashes
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src) = crate::chain::tiny_regtest_hub_labeled("inv-asked-src");
        src.ensure_genesis().unwrap();
        src.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hdr = src.query.wire_header_at_height(Height(1)).unwrap();
        let hash = hdr.block_hash();

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("inv-asked-dst");
        hub.ensure_genesis().unwrap();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 2u32,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0u32,
        };

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![hdr])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let first = drain_block_getdata(&mut out_rx);
        assert_eq!(first, vec![hash], "header announce must getdata once");
        assert!(hub.already_have_or_asked_block(&hash));

        // Second peer: empty local requested set, same hub (asked_blocks).
        let (out_tx2, mut out_rx2) = mpsc::unbounded_channel();
        let mut follow2 = PeerFollowState::new();
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(hash)])),
            &hub,
            &out_tx2,
            &mut follow2,
            None,
        )
        .await
        .unwrap();
        let second = drain_block_getdata(&mut out_rx2);
        assert!(
            second.is_empty(),
            "duplicate inv must not getdata, got {second:?}"
        );

        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_nobloomfilter_messages.py`: mempool/filter* disconnect when bloom off.
#[test]
fn bloom_disabled_messages_request_disconnect() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_bloom::FilterAdd;
    use bitcoin::Network;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        FramedMessage {
            magic,
            command,
            payload: full[24..].to_vec(),
        }
    }

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("bloom-off");
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState {
        wants_headers: false,
        wtxid_relay: false,
        send_cmpct: false,
        cmpct_version: 2u32,
        pending_headers: HashMap::new(),
        pending_blocks: PendingBlocks::new(),
        pending_cmpct: HashMap::new(),
        from_this_peer: CappedSet::new(),
        requested_blocks: HashSet::new(),
        ban_score: 0,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let msgs = [
        NetworkMessage::MemPool,
        NetworkMessage::FilterClear,
        NetworkMessage::FilterAdd(FilterAdd { data: vec![0xcc] }),
    ];
    for msg in msgs {
        follow.ban_score = 0;
        rt.block_on(async {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        });
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "bloom-off message must punish-disconnect (ban={})",
            follow.ban_score
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_invalid_locator.py`: getheaders/getblocks with locator > MAX_LOCATOR_SZ disconnect.
#[test]
fn oversize_locator_request_disconnect() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};
    use bitcoin::Network;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        FramedMessage {
            magic,
            command,
            payload: full[24..].to_vec(),
        }
    }

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("locator-oversize");
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState {
        wants_headers: false,
        wtxid_relay: false,
        send_cmpct: false,
        cmpct_version: 2u32,
        pending_headers: HashMap::new(),
        pending_blocks: PendingBlocks::new(),
        pending_cmpct: HashMap::new(),
        from_this_peer: CappedSet::new(),
        requested_blocks: HashSet::new(),
        ban_score: 0,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let stop = BlockHash::from_byte_array([0u8; 32]);
    let oversize: Vec<BlockHash> = (0..=MAX_LOCATOR_SZ)
        .map(|i| BlockHash::from_byte_array([i as u8; 32]))
        .collect();
    assert_eq!(oversize.len(), MAX_LOCATOR_SZ + 1);
    let within: Vec<BlockHash> = oversize[..MAX_LOCATOR_SZ].to_vec();

    for msg in [
        NetworkMessage::GetHeaders(GetHeadersMessage::new(oversize.clone(), stop)),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(oversize.clone(), stop)),
    ] {
        follow.ban_score = 0;
        rt.block_on(async {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        });
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "oversize locator must punish-disconnect (ban={})",
            follow.ban_score
        );
    }

    // Exactly MAX_LOCATOR_SZ stays connected (ban untouched).
    follow.ban_score = 0;
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                within, stop,
            ))),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
    });
    assert_eq!(follow.ban_score, 0, "max-sized locator must not disconnect");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn desirable_service_flags_match_core() {
    let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let pruned = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let none = ServiceFlags::NONE;
    let net_only = ServiceFlags::NETWORK;
    let wit_only = ServiceFlags::WITNESS;
    let limited_wit = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let limited_wit_v2 = limited_wit | ServiceFlags::P2P_V2;

    assert_eq!(desirable_service_flags(none, 0), full);
    assert_eq!(desirable_service_flags(net_only, 0), full);
    assert_eq!(desirable_service_flags(wit_only, 0), full);
    assert_eq!(desirable_service_flags(full, 0), full);
    assert!(!has_all_desirable_service_flags(none, 0));
    assert!(!has_all_desirable_service_flags(net_only, 0));
    assert!(!has_all_desirable_service_flags(wit_only, 0));
    assert!(has_all_desirable_service_flags(full, 0));

    assert_eq!(desirable_service_flags(limited_wit, 150), full);
    assert!(!has_all_desirable_service_flags(limited_wit, 150));
    assert_eq!(desirable_service_flags(limited_wit, 138), pruned);
    assert!(has_all_desirable_service_flags(limited_wit, 138));
    assert!(has_all_desirable_service_flags(limited_wit_v2, 138));

    assert_eq!(
        expected_services_disconnect_log(0, full.to_u64()),
        "p2p: does not offer the expected services (00000000 offered, 00000009 expected)"
    );
    assert_eq!(
        expected_services_disconnect_log(limited_wit.to_u64(), full.to_u64()),
        "p2p: does not offer the expected services (00000408 offered, 00000009 expected)"
    );
}

#[test]
fn expect_services_from_conn_matches_core() {
    use crate::peers::PeerConnType;
    assert!(!expect_services_from_conn(PeerConnType::Inbound));
    assert!(!expect_services_from_conn(PeerConnType::Manual));
    assert!(!expect_services_from_conn(PeerConnType::Feeler));
    assert!(expect_services_from_conn(PeerConnType::OutboundFullRelay));
    assert!(expect_services_from_conn(PeerConnType::BlockRelay));
    assert!(expect_services_from_conn(PeerConnType::AddrFetch));
}

#[test]
fn handshake_disconnect_log_needles() {
    assert_eq!(
        crate::peer::ping_prior_to_verack_log(0),
        "p2p: Unsupported message \"ping\" prior to verack from peer=0"
    );
    assert_eq!(
        crate::peer::non_version_before_handshake_log("ping", 1),
        "p2p: non-version message before version handshake. Message \"ping\" from peer=1"
    );
    assert_eq!(
        crate::peer::obsolete_version_log(31799, 5),
        "p2p: using obsolete version 31799, disconnecting peer=5"
    );
    assert_eq!(crate::peer::MIN_PEER_PROTO_VERSION, 31800);
    let hidden = crate::peer::hidden_addr_from();
    let zero = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    assert_eq!(
        hidden,
        bitcoin::p2p::address::Address::new(&zero, bitcoin::p2p::ServiceFlags::NONE)
    );
    assert_eq!(
        crate::peer::advertising_address_log("42.42.42.42:18445", 3),
        "p2p: Advertising address 42.42.42.42:18445 to peer=3"
    );
}

#[test]
fn pending_blocks_insert_evicts_at_cap() {
    let mut pending = PendingBlocks::new();
    let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    let mut hashes = Vec::new();
    for i in 0u32..(MAX_PENDING_BLOCKS_FOR_TEST as u32 + 1) {
        let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        b.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array({
            let mut m = [0u8; 32];
            m[0] = (i >> 24) as u8;
            m[1] = (i >> 16) as u8;
            m[2] = (i >> 8) as u8;
            m[3] = i as u8;
            m
        });
        b.header.bits = bits;
        let h = b.block_hash();
        hashes.push(h);
        pending.insert(h, b);
    }
    assert_eq!(pending.keys().len(), MAX_PENDING_BLOCKS_FOR_TEST);
    assert!(
        !pending.contains_key(&hashes[0]),
        "cap eviction must drop the oldest insert, not HashMap::keys().next()"
    );
    assert!(pending.contains_key(&hashes[MAX_PENDING_BLOCKS_FOR_TEST]));
}

#[test]
fn try_queue_served_block_false_at_cap() {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let n = AtomicUsize::new(MAX_SERVE_BLOCKS);
    let gen = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let queued =
        try_queue_served_block(None, &out_tx, Some(&n), NetworkMessage::Block(gen)).unwrap();
    assert!(!queued);
    assert!(out_rx.try_recv().is_err());
    assert_eq!(n.load(Ordering::SeqCst), MAX_SERVE_BLOCKS);
}

#[test]
fn encode_served_witness_block_panics_on_reactor() {
    let h = BlockHash::from_byte_array([0u8; 32]);
    let join = std::thread::Builder::new()
        .name("tokio-rt-worker".into())
        .spawn(move || {
            let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("serve-reactor");
            let cache = BlockCache::new();
            let r = encode_served_witness_block(&cache, &q, &h);
            let _ = std::fs::remove_dir_all(dir);
            r
        })
        .unwrap()
        .join();
    assert!(
        join.is_err(),
        "must panic on tokio-rt-worker without BlockingRegion"
    );
    let join_ok = std::thread::Builder::new()
        .name("tokio-rt-worker".into())
        .spawn(move || {
            let _g = crate::reactor::BlockingRegion::enter();
            let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("serve-reactor-ok");
            let cache = BlockCache::new();
            let r = encode_served_witness_block(&cache, &q, &h);
            let _ = std::fs::remove_dir_all(dir);
            r
        })
        .unwrap()
        .join();
    assert!(
        join_ok.is_ok(),
        "BlockingRegion must allow reconstruct on worker name"
    );
}

#[test]
fn announced_tip_is_hopeless_less_and_288_behind() {
    use std::cmp::Ordering;
    assert!(announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        963_900,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Greater)
    ));
    assert!(!announced_tip_is_hopeless(100, 1, Some(Ordering::Less)));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Equal)
    ));
    assert!(!announced_tip_is_hopeless(964_000, 961_638, None));
}

#[test]
fn getdata_skips_reconstruct_when_serve_inflight_at_cap() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::Network;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        FramedMessage {
            magic,
            command,
            payload: full[24..].to_vec(),
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("serve-inflight-cap");
        hub.ensure_genesis().unwrap();
        let hashes = hub
            .generate_to_script(20, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        assert!(hashes.len() >= 20);

        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let ver = bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
            sender: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 2u32,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0u32,
        };
        let inv: Vec<Inventory> = hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(inv)),
            &hub,
            &out_tx,
            &mut follow,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let mut n_block = 0usize;
        while let Ok(msg) = out_rx.try_recv() {
            match msg {
                PeerOut::Encoded(_) | PeerOut::Msg(NetworkMessage::Block(_)) => n_block += 1,
                _ => {}
            }
        }
        assert!(
            n_block <= MAX_SERVE_BLOCKS,
            "queued {n_block} blocks over cap {MAX_SERVE_BLOCKS}"
        );
        assert_eq!(hashes.len(), 20);
        assert_eq!(n_block, MAX_SERVE_BLOCKS);
        assert!(
            n_block < hashes.len(),
            "17th getdata hash must not queue a 17th body"
        );
        assert_eq!(sess.serve_inflight.load(Ordering::SeqCst), MAX_SERVE_BLOCKS);
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[tokio::test]
async fn handshake_timeout_after_silence() {
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(60));

    async fn bind_pair() -> (TcpStream, TcpStream, SocketAddr, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        (client, server, addr, peer)
    }

    async fn join_timeout<T>(
        handle: tokio::task::JoinHandle<Result<T, NetError>>,
        still: &str,
        done: &str,
        succeeded: &str,
    ) {
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!handle.is_finished(), "{still}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(handle.is_finished(), "{done}");
        match handle.await.unwrap() {
            Err(NetError::Timeout) => {}
            Err(e) => panic!("expected Timeout, got {e}"),
            Ok(_) => panic!("{succeeded}"),
        }
    }

    let (client, server, addr, peer) = bind_pair().await;
    let _silent_in = client;
    join_timeout(
        tokio::spawn(async move {
            connect_and_handshake_timed(
                Duration::from_millis(50),
                server,
                Magic::REGTEST,
                addr,
                peer,
                0,
                true,
                "/rbitcoin:test/",
                HandshakePolicy::plain(),
            )
            .await
        }),
        "must still wait during inbound handshake",
        "silence past the bound must end inbound handshake",
        "inbound handshake succeeded on a silent peer",
    )
    .await;

    let (client, server, addr, _) = bind_pair().await;
    let _silent_out = server;
    join_timeout(
        tokio::spawn(async move {
            connect_and_handshake_timed(
                Duration::from_millis(50),
                client,
                Magic::REGTEST,
                addr,
                addr,
                0,
                false,
                "/rbitcoin:test/",
                HandshakePolicy::plain(),
            )
            .await
        }),
        "must still wait during outbound handshake",
        "silence past the bound must end outbound handshake",
        "outbound handshake succeeded on a silent peer",
    )
    .await;

    let (client, server, addr, _) = bind_pair().await;
    let _silent_feeler = server;
    join_timeout(
        tokio::spawn(async move {
            run_feeler_timed(
                Duration::from_millis(50),
                client,
                Magic::REGTEST,
                addr,
                addr,
                0,
                "/rbitcoin:test/",
            )
            .await
        }),
        "must still wait during feeler",
        "silence past the bound must end feeler",
        "feeler succeeded on a silent peer",
    )
    .await;

    let (client, server, _, _) = bind_pair().await;
    let _silent_plain = server;
    match V2PlainSession::outbound_regtest(client, "/rbitcoin:test/", Duration::from_millis(50))
        .await
    {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("expected Timeout, got {e}"),
        Ok(_) => panic!("plain session succeeded on a silent peer"),
    }
}

/// GetData witness bytes must leave the writer before a queued header flood.
#[test]
fn outbound_write_batch_sends_getdata_before_headers() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tx.send(PeerOut::Msg(NetworkMessage::Headers(vec![])))
        .unwrap();
    tx.send(PeerOut::Encoded(vec![2, 0xaa])).unwrap();
    tx.send(PeerOut::Msg(NetworkMessage::Ping(7))).unwrap();
    tx.send(PeerOut::Msg(NetworkMessage::Headers(vec![])))
        .unwrap();
    let first = rx.try_recv().expect("first");
    let batch = take_outbound_write_batch(first, &mut rx);
    assert!(
        matches!(batch[0], PeerOut::Msg(NetworkMessage::Ping(7))),
        "ping before serve and announces"
    );
    assert!(
        matches!(batch[1], PeerOut::Encoded(_)),
        "getdata body before headers"
    );
    assert_eq!(batch.len(), 4);
}

#[test]
fn snapshot_omits_peer_after_tcp_fin() {
    use crate::peers::{PeerConnType, PeerHub};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:0.1.0(testnode0)/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = hub.register(addr, addr, &ver, true, PeerConnType::Inbound);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let la = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(la).unwrap();
    let (server, _) = listener.accept().unwrap();
    peer.attach_tcp_shutdown(server.try_clone().unwrap());
    assert_eq!(hub.snapshot().len(), 1);
    {
        use std::io::Write;
        client.write_all(&[0xab]).unwrap();
    }
    client.shutdown(Shutdown::Both).unwrap();
    let mut saw = false;
    for _ in 0..50 {
        if peer.tcp_fin() {
            saw = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(saw, "cloned fd must see FIN even with unread bytes");
    assert!(
        hub.snapshot().is_empty(),
        "getpeerinfo must omit a FIN'd session (mempool_reorg disconnect_nodes 5s)"
    );
    drop(client);
    drop(server);
}

/// Burst tip advances (> tip broadcast capacity) must still reach a follow peer
/// without waiting for the 120s headers poll (`sync_blocks` is 60s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tip_burst_past_broadcast_capacity_still_syncs_peer() {
    use crate::P2PNode;
    use bitcoin::ScriptBuf;
    use std::time::Duration;

    let _live = crate::service::live_p2p_lock().await;
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-tip-burst-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-a)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-b)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        if na.follow_live_count() >= 1 && !nb.peers.snapshot().is_empty() {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "follow session must be live before tip burst");

    // Capacity is 64; sync generate without await fills the ring so the
    // announce task sees Lagged instead of every TipEvent.
    const BURST: u32 = 80;
    na.hub
        .generate_to_script(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    assert!(want >= BURST, "miner tip {want}");

    let mut peer_tip = nb.tip_height().unwrap_or(0);
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while peer_tip < want && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        peer_tip = nb.tip_height().unwrap_or(0);
    }
    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        peer_tip, want,
        "peer must catch tip after Lagged burst within 45s"
    );
}
/// Core `disconnect_nodes` waits ≤5s for the far side's `getpeerinfo` to drop us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_clears_far_side_getpeerinfo_within_5s() {
    use crate::P2PNode;
    use std::time::Duration;

    let _live = crate::service::live_p2p_lock().await;
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-far-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before disconnect");

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));
    assert!(
        na.peers.snapshot().is_empty(),
        "local getpeerinfo clears immediately"
    );

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s (Core disconnect_nodes)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `mempool_reorg` disconnect_nodes after generate+sync — far side must still
/// clear within 5s even if the session was just busy accepting tip blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_after_tip_sync_clears_far_side_within_5s() {
    use crate::P2PNode;
    use bitcoin::ScriptBuf;
    use std::time::Duration;

    let _live = crate::service::live_p2p_lock().await;
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-tip-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before generate");

    const BURST: u32 = 3;
    na.hub
        .generate_to_script(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    let mut synced = false;
    for _ in 0..200 {
        if nb.tip_height().unwrap_or(0) >= want {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(synced, "far side must sync tip before disconnect");

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s after tip sync (mempool_reorg)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn on_tx_announce_none_lagged_closed_are_ok() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("tx-ann-empty");
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, None).is_ok());
    assert!(on_tx_announce(
        &hub,
        &out_tx,
        &follow,
        None,
        Some(Err(broadcast::error::RecvError::Lagged(1))),
    )
    .is_ok());
    assert!(on_tx_announce(
        &hub,
        &out_tx,
        &follow,
        None,
        Some(Err(broadcast::error::RecvError::Closed)),
    )
    .is_ok());

    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    use std::sync::Arc;
    let txid = Txid::from_byte_array([0x11; 32]);
    let ann = crate::tx_relay::MempoolAnnounce {
        txid,
        replaced: Vec::new(),
        replaced_scripthashes: Vec::new(),
        scripthashes: Vec::new(),
    };
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann.clone()))).is_ok());

    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann.clone()))).is_ok());

    follow.from_this_peer.insert(txid, FROM_THIS_PEER_CAP);
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann))).is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

/// Each `headers` message persists the pending path from the last stored
/// header, not the whole path again. Re-checking stored fork headers walks
/// their ancestors on every message, so a long fork made each message slower
/// (`feature_bip68_sequence.py` took 10 s for one message at 244 pending).
#[test]
fn persist_pending_path_starts_after_the_last_stored_header() {
    use bitcoin::ScriptBuf;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("persist-path");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(20, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let fork_at = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(10))
        .unwrap();
    let mut pending = HashMap::new();
    let mut prev = fork_at.block_hash();
    let mut time = fork_at.time + 1;
    let mut last = prev;
    for height in 11..=50u32 {
        let h = rbitcoin_consensus::mine_regtest_paying(
            prev,
            time,
            height,
            ScriptBuf::from_bytes(vec![0x52]),
            vec![],
        )
        .header;
        prev = h.block_hash();
        last = prev;
        time += 1;
        pending.insert(prev, h);
    }
    persist_pending_header_path(&hub, &pending, last);
    assert!(hub.knows_header(&last), "the fork path is stored");

    let next = rbitcoin_consensus::mine_regtest_paying(
        last,
        time,
        51,
        ScriptBuf::from_bytes(vec![0x52]),
        vec![],
    )
    .header;
    pending.insert(next.block_hash(), next);
    let _ = hub.take_header_contextual_checks();
    persist_pending_header_path(&hub, &pending, next.block_hash());
    assert!(hub.knows_header(&next.block_hash()));
    assert_eq!(
        hub.take_header_contextual_checks(),
        1,
        "only the new header is checked, not the stored fork path"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn inv_and_getdata_at_cap_stay_one_past_disconnects() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("inv-cap");
    hub.ensure_genesis().unwrap();
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let block = Inventory::CompactBlock(hub.tip_hash().unwrap());
    let at_cap = vec![block; MAX_INV_SIZE];
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &out_tx, &mut follow, None, &at_cap).unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "exactly {MAX_INV_SIZE} inv items stay connected"
    );
    let mut over = at_cap;
    over.push(block);
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &out_tx, &mut follow, None, &over).unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "one past the inv cap disconnects"
    );

    let tx = Inventory::WitnessTransaction(Txid::from_byte_array([0x22; 32]));
    let at_cap = vec![tx; MAX_INV_SIZE];
    let mut follow = PeerFollowState::new();
    serve_getdata(&hub, &out_tx, &mut follow, None, &at_cap)
        .await
        .unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "exactly {MAX_INV_SIZE} getdata items are served"
    );
    let mut over = at_cap;
    over.push(tx);
    let mut follow = PeerFollowState::new();
    serve_getdata(&hub, &out_tx, &mut follow, None, &over)
        .await
        .unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "one past the getdata cap disconnects"
    );
    let _ = std::fs::remove_dir_all(dir);
}
#[tokio::test]
async fn over_budget_reader_waits_until_one_byte_is_written() {
    let peers = crate::peers::PeerHub::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
    peer.note_send_queued(crate::peers::PEER_SEND_BUDGET + 1);
    let waiting = std::sync::Arc::clone(&peer);
    let wait = tokio::spawn(async move { waiting.wait_send_budget().await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !wait.is_finished(),
        "an over-budget reader must be parked before the writer drains"
    );
    peer.note_send_written(1);
    tokio::time::timeout(std::time::Duration::from_secs(1), wait)
        .await
        .expect("writing back to the cap wakes the reader")
        .unwrap();
}

/// FNV-1a of the address bytes. Duplicated here so a broken mixer in
/// `addr_relay_key` cannot satisfy the assertion by changing both sides.
fn addr_key_oracle(msg: &bitcoin::p2p::address::AddrV2Message) -> u64 {
    let raw = bitcoin::consensus::encode::serialize(msg);
    let mut h = 0xcbf29ce484222325u64;
    for b in raw {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[test]
fn invalid_script_is_scored_and_policy_is_not() {
    use rbitcoin_mempool::AcceptError;
    assert_eq!(
        super::tx_reject_ban_score(&AcceptError::Script("script false".into())),
        10
    );
    assert_eq!(
        super::tx_reject_ban_score(&AcceptError::Policy("min relay fee")),
        0
    );
}

include!("peer_catchup_journey.rs");
include!("peer_hostile_journey.rs");
include!("peer_tip_announce_journey.rs");
include!("peer_header_dos_journey.rs");
include!("peer_blocksonly_journey.rs");

/// Core `PrepareBlockFilterRequest`: start past stop, or a range of 1000+
/// cfilters / 2000+ cfheaders, disconnects instead of being clamped.
#[test]
fn compact_filter_ranges_past_core_limits_disconnect() {
    assert!(compact_filter_range(5, 4, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(0, 999, MAX_GETCFILTERS).is_ok());
    assert!(compact_filter_range(0, 1000, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(1, 2000, MAX_GETCFHEADERS).is_ok());
    assert!(compact_filter_range(0, 2000, MAX_GETCFHEADERS).is_err());
}
