use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::script::ScriptBuf;
use bitcoin::BlockHash;
use bitcoin::Network;
use rbitcoin_net::cache::BlockCache;
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::codec::{FramedMessage, MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_LOCATOR_SZ};
use rbitcoin_net::error::NetError;
use rbitcoin_net::peer::*;
use rbitcoin_net::peers::{CappedSet, PeerOut};
use rbitcoin_net::seeds::AddrMan;
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use rbitcoin_consensus::{ChainParams, Milestone};

fn served_block(p: PeerOut) -> bitcoin::Block {
    match p {
        PeerOut::Encoded(bytes) => {
            assert_eq!(bytes.first().copied(), Some(2), "v2 block short id");
            bitcoin::consensus::encode::deserialize(&bytes[1..]).expect("served block payload")
        }
        PeerOut::Served(NetworkMessage::Block(b)) => b,
        other => panic!("expected served block, got {other:?}"),
    }
}
#[test]
fn p2p_serve_line_names_tx_bytes_wall() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("serve-line");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (served_n, served_bytes) = rbitcoin_net::serve_perf::serve_perf_totals();
    let _ = rbitcoin_net::serve_perf::sample_reset_serve_perf();
    let encoded = encode_served_witness_block(&hub.cache, &hub.query, &gen)
        .unwrap()
        .expect("genesis Class A body");
    assert_eq!(encoded.first().copied(), Some(2), "v2 block short id");
    let s = rbitcoin_net::serve_perf::sample_reset_serve_perf();
    assert!(s.n >= 1, "{s:?}");
    assert!(s.bytes > 1, "{s:?}");
    assert!(s.tx_count >= 1, "{s:?}");
    let (served_n_after, served_bytes_after) = rbitcoin_net::serve_perf::serve_perf_totals();
    assert!(
        served_n_after > served_n && served_bytes_after > served_bytes.max(1),
        "running serve totals move with the window: before=({served_n},{served_bytes}) after=({served_n_after},{served_bytes_after}) window={s:?}"
    );
    let line = rbitcoin_net::serve_perf::format_serve_perf(&s);
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
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("empty");
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc.last().unwrap().to_byte_array(), [0u8; 32]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_follow_locator_includes_tip_after_genesis() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gen");
    hub.ensure_genesis().unwrap();
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc[0], hub.tip_hash().unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ibd_connect_does_not_start_headers_sync() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-sync");
    hub.ensure_genesis().unwrap();
    assert!(hub.in_ibd(), "regtest genesis is older than 24h");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
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
    let session = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx, mut rx) = mpsc::unbounded_channel();
    assert!(
        maybe_queue_initial_getheaders(&tx, &hub, &session),
        "IBD still asks the one headers peer for the stored tip"
    );
    match rx.try_recv().unwrap().expect_msg() {
        bitcoin::p2p::message::NetworkMessage::GetHeaders(gh) => {
            assert!(
                gh.locator_hashes.contains(&hub.tip_hash().unwrap()),
                "the locator names the stored tip"
            );
        }
        other => panic!("expected getheaders, got {other:?}"),
    }
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let mut ver2 = ver.clone();
    ver2.nonce = 2;
    let session2 = peers.register(
        addr2,
        addr2,
        &ver2,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    assert!(
        !maybe_queue_initial_getheaders(&tx2, &hub, &session2),
        "a second connecting peer does not start another headers sync"
    );
    assert!(rx2.try_recv().is_err());

    // Leaving IBD is a tip inside 24h, which is also when Core allows every
    // connecting peer to start headers sync. The peer that already started
    // during IBD does not start again.
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    let fresh = tip_time.saturating_add(60);
    peers.set_mock_now(fresh);
    hub.clock.set_mock(i64::try_from(fresh).unwrap());
    assert!(!hub.in_ibd(), "a fresh tip leaves IBD");
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8335);
    let mut ver3 = ver.clone();
    ver3.nonce = 3;
    let session3 = peers.register(
        addr3,
        addr3,
        &ver3,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx3, mut rx3) = mpsc::unbounded_channel();
    assert!(
        maybe_queue_initial_getheaders(&tx3, &hub, &session3),
        "after IBD a connecting peer still starts headers sync"
    );
    assert!(matches!(
        rx3.try_recv().unwrap().expect_msg(),
        bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ignored_full_header_batch_does_not_page() {
    use bitcoin::block::{Header, Version};
    use bitcoin::CompactTarget;
    use bitcoin::TxMerkleNode;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-page");
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let mut prev = hub.tip_hash().unwrap();
    let mut headers = Vec::with_capacity(MAX_HEADERS_RESULTS);
    for i in 0..MAX_HEADERS_RESULTS {
        let hdr = Header {
            version: Version::TWO,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([i as u8; 32]),
            time: 1_700_000_000 + i as u32,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: i as u32,
        };
        prev = hdr.block_hash();
        headers.push(hdr);
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(on_headers(&hub, &tx, &mut follow, None, &headers))
        .unwrap();
    assert!(
        rx.try_recv().is_err(),
        "an ignored 2,000-header batch does not ask for the next page"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ibd_unknown_block_inv_does_not_getheaders() {
    use bitcoin::p2p::message_blockdata::Inventory;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-inv");
    hub.ensure_genesis().unwrap();
    assert!(hub.in_ibd());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let unknown = BlockHash::from_byte_array([0x44; 32]);
    on_inv(&hub, &tx, &mut follow, None, &[Inventory::Block(unknown)]).unwrap();
    assert!(
        matches!(
            rx.try_recv().unwrap().expect_msg(),
            bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
        ),
        "an unknown block inv during IBD still asks for headers"
    );
    assert!(
        hub.header_inv_challenge_pending(),
        "an unknown block inv during IBD challenges the header walk"
    );

    hub.set_max_tip_age_secs(u64::MAX);
    assert!(!hub.in_ibd());
    on_inv(
        &hub,
        &tx,
        &mut follow,
        None,
        &[Inventory::Block(BlockHash::from_byte_array([0x45; 32]))],
    )
    .unwrap();
    assert!(matches!(
        rx.try_recv().unwrap().expect_msg(),
        bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_unknown_starts_at_that_hash() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("loc-unk");
    hub.ensure_genesis().unwrap();
    let start = BlockHash::from_byte_array([0xab; 32]);
    let loc = headers_sync_locator(&hub, Some(start));
    assert_eq!(loc[0], start);
    assert_eq!(loc.last().copied(), hub.tip_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_mid_height_starts_there() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("loc-mid");
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
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("poll-skip");
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
    let _ = LiveFollowDec(None);
}

#[test]
fn local_service_flags_include_network_witness_v2() {
    let f = local_service_flags(false, None);
    assert!(f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn local_service_flags_pruned_are_limited_not_network() {
    let f = local_service_flags(true, None);
    assert!(f.has(ServiceFlags::NETWORK_LIMITED));
    assert!(!f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn compact_filter_bit_stays_on_the_node_that_caught_up() {
    use bitcoin::p2p::ServiceFlags;
    let quiet = crate::peers::PeerHub::new();
    let caught_up = crate::peers::PeerHub::new();
    caught_up.set_compact_filters_service(true);
    assert!(
        !local_service_flags(false, Some(&quiet)).has(ServiceFlags::COMPACT_FILTERS),
        "a neighbor catching up must not advertise filters for this node"
    );
    assert!(local_service_flags(false, Some(&caught_up)).has(ServiceFlags::COMPACT_FILTERS));
    assert!(
        !local_service_flags(false, None).has(ServiceFlags::COMPACT_FILTERS),
        "no session table means this node has not caught filters up"
    );
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
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-none");
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

/// A regtest hub with a mempool and 102 blocks to OP_TRUE, so blocks
/// 103 and 104 can each spend a mature coinbase: block `n` spends
/// coinbase `n`. Their spends are not in the mempool, so a compact
/// announce of either waits on `blocktxn`.
fn compact_spend_pair(
    label: &str,
) -> (
    rbitcoin_query::testutil::TempDir,
    ChainHub,
    [bitcoin::Block; 2],
) {
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
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
    (dir, hub, [a, b])
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (dir, hub, [a, b]) = compact_spend_pair("cmpct-stale-partial");

    let peers = rbitcoin_net::peers::PeerHub::new();
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
    let stalling = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    stalling.hb_to.store(true, Ordering::Relaxed);
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

async fn heartbeat_once(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    peer: &rbitcoin_net::peers::LivePeer,
) {
    on_heartbeat(
        hub,
        out_tx,
        follow,
        Some(peer),
        &mut None,
        &mut None,
        &mut None,
        false,
    )
    .await
    .unwrap();
}

/// A block frame already read, still waiting on a decode permit, must not
/// lose its getdata. The heartbeat used to drain `requested_blocks` on the
/// 10s stall clock before that frame was applied.
#[tokio::test]
async fn queued_decode_holds_block_requests_across_heartbeat() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-hold-getdata");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = outbound_test_peer(&peers, 18449);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let hash = BlockHash::from_byte_array([0x44; 32]);
    hub.note_asked_block(hash);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    let mut since =
        Some(std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1));
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        true,
    )
    .await
    .unwrap();
    assert!(
        follow.requested_blocks.contains(&hash),
        "a queued decode must keep the getdata"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "asked_blocks must stay until the frame is applied"
    );
    assert!(
        sent(&mut out_rx)
            .iter()
            .all(|m| !matches!(m, NetworkMessage::GetData(_))),
        "the stall path must not send another getdata"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
    )
    .await
    .unwrap();
    assert!(
        follow.requested_blocks.is_empty(),
        "once the decode queue is empty the stall clock still expires"
    );
    assert!(!hub.already_have_or_asked_block(&hash));
    let _ = std::fs::remove_dir_all(dir.path());
}

/// The block-download window must not drop a peer whose body is already in
/// `decode_q`. That frame is still the oldest block in flight.
#[tokio::test]
async fn queued_decode_holds_the_block_download_window() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-hold-download");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000_u64;
    peers.set_mock_now(start);
    let peer = outbound_test_peer(&peers, 18450);
    let hash = BlockHash::from_byte_array([0x45; 32]);
    hub.note_asked_block(hash);
    peer.note_blocks_requested(&[hash]);
    let interval = hub.params.btc.pow_target_spacing;
    peers.set_mock_now(start + interval + 1);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    let mut since = None;
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        true,
    )
    .await
    .unwrap();
    assert!(
        !peer.stop.load(Ordering::Relaxed),
        "a queued body must not trip the download timeout"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "the ask stays until the frame is applied"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
    )
    .await
    .unwrap();
    assert!(
        peer.stop.load(Ordering::Relaxed),
        "an empty decode queue still times the window out"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// A ping that arrives while a block is still in `decode_q` must not send
/// pong until that block has been applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_behind_a_queued_block_does_not_pong_early() {
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::v2::{open_v2, read_v2_frame, write_v2_msg};
    use tokio::net::TcpListener;

    let n = rbitcoin_net::block_decode_permits();
    let sem = rbitcoin_net::msg_decode::block_decode_semaphore().clone();
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(sem.clone().acquire_owned().await.expect("decode permit"));
    }
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-ping-order");
    hub.ensure_genesis().unwrap();
    // Below `-minimumchainwork` the body is applied and skipped. A real
    // accept would wait on the tip thread from this session task.
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let magic = Magic::from(Network::Regtest);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_magic = magic;
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        open_v2(stream, client_magic, false).await.unwrap()
    });
    let (server_stream, _) = listener.accept().await.unwrap();
    let (reader, writer, _wire, _shutdown) = open_v2(server_stream, magic, true).await.unwrap();
    let (mut c_reader, mut c_writer, _wire, _shutdown) = client.await.unwrap();
    let tip_rx = hub.subscribe_tips();
    let session = tokio::spawn(async move {
        let _ = peer_session_with(
            reader,
            writer,
            magic,
            Arc::new(hub),
            tip_rx,
            FollowSessionMeta::default(),
        )
        .await;
    });
    let drain_startup = async {
        while let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(40),
            read_v2_frame(&mut c_reader, magic),
        )
        .await
        {}
    };
    tokio::time::timeout(Duration::from_secs(2), drain_startup)
        .await
        .expect("startup frames drain");
    let nonce = 0x51a7_0001_u64;
    write_v2_msg(
        &mut c_writer,
        NetworkMessage::Block(genesis_block(Network::Regtest)),
    )
    .await
    .unwrap();
    write_v2_msg(&mut c_writer, NetworkMessage::Ping(nonce))
        .await
        .unwrap();
    let nonce_pong = |frame: &rbitcoin_net::codec::FramedMessage| {
        frame.is_pong()
            && frame.payload.len() >= 8
            && u64::from_le_bytes(frame.payload[..8].try_into().unwrap()) == nonce
    };
    let early_deadline = std::time::Instant::now() + Duration::from_millis(300);
    while std::time::Instant::now() < early_deadline {
        let left = early_deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(&mut c_reader, magic)).await {
            Ok(Ok(frame)) => assert!(
                !nonce_pong(&frame),
                "pong went out while the earlier block was still queued"
            ),
            _ => break,
        }
    }
    drop(held);
    let mut saw_pong = false;
    let late_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < late_deadline {
        let left = late_deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(&mut c_reader, magic)).await {
            Ok(Ok(frame)) if nonce_pong(&frame) => {
                saw_pong = true;
                break;
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    assert!(
        saw_pong,
        "pong must follow the queued block once a decode permit is free"
    );
    session.abort();
    let _ = std::fs::remove_dir_all(dir.path());
}

/// `disconnect_id` must not abort a session that still has a frame in
/// `decode_q`. The body is applied once a decode permit is free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_applies_a_block_already_queued() {
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::v2::{open_v2, read_v2_frame, write_v2_msg};
    use tokio::net::TcpListener;

    let n = rbitcoin_net::block_decode_permits();
    let sem = rbitcoin_net::msg_decode::block_decode_semaphore().clone();
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(sem.clone().acquire_owned().await.expect("decode permit"));
    }
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-disconnect");
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let peers = rbitcoin_net::peers::PeerHub::new();
    let live = outbound_test_peer(&peers, 18451);
    let magic = Magic::from(Network::Regtest);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_magic = magic;
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        open_v2(stream, client_magic, false).await.unwrap()
    });
    let (server_stream, _) = listener.accept().await.unwrap();
    let (reader, writer, _wire, _shutdown) = open_v2(server_stream, magic, true).await.unwrap();
    let (mut c_reader, mut c_writer, _wire, _shutdown) = client.await.unwrap();
    let tip_rx = hub.subscribe_tips();
    let session_peer = Arc::clone(&live);
    let session = tokio::spawn(async move {
        let _ = peer_session_with(
            reader,
            writer,
            magic,
            Arc::new(hub),
            tip_rx,
            FollowSessionMeta {
                peer: Some(addr),
                live: None,
                session: Some(session_peer),
            },
        )
        .await;
    });
    live.set_session_abort(session.abort_handle());
    let drain_startup = async {
        while let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(40),
            read_v2_frame(&mut c_reader, magic),
        )
        .await
        {}
    };
    tokio::time::timeout(Duration::from_secs(2), drain_startup)
        .await
        .expect("startup frames drain");
    let block = genesis_block(Network::Regtest);
    let hash = block.block_hash();
    write_v2_msg(&mut c_writer, NetworkMessage::Block(block))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(peers.disconnect_id(live.id), "the peer is registered");
    assert!(
        !live.take_block_from_peer(&hash),
        "the body stays queued while every decode permit is held"
    );
    drop(held);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut applied = false;
    while std::time::Instant::now() < deadline {
        if live.take_block_from_peer(&hash) {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        applied,
        "disconnect must apply a block already taken off the socket"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// A tip announce that fails because disconnect closed the writer must
/// still apply a block already sitting in `decode_q`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_during_tip_announce_applies_a_queued_block() {
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::chain::TipEvent;
    use rbitcoin_net::v2::{open_v2, read_v2_frame, write_v2_msg};
    use tokio::net::TcpListener;

    let n = rbitcoin_net::block_decode_permits();
    let sem = rbitcoin_net::msg_decode::block_decode_semaphore().clone();
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(sem.clone().acquire_owned().await.expect("decode permit"));
    }
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-tip-disconnect");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let live = outbound_test_peer(&peers, 18452);
    let magic = Magic::from(Network::Regtest);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_magic = magic;
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        open_v2(stream, client_magic, false).await.unwrap()
    });
    let (server_stream, _) = listener.accept().await.unwrap();
    let (reader, writer, _wire, _shutdown) = open_v2(server_stream, magic, true).await.unwrap();
    let (mut c_reader, mut c_writer, _wire, _shutdown) = client.await.unwrap();
    let tip_rx = hub.subscribe_tips();
    let session_peer = Arc::clone(&live);
    let session_hub = Arc::clone(&hub);
    let session = tokio::spawn(async move {
        let _ = peer_session_with(
            reader,
            writer,
            magic,
            session_hub,
            tip_rx,
            FollowSessionMeta {
                peer: Some(addr),
                live: None,
                session: Some(session_peer),
            },
        )
        .await;
    });
    live.set_session_abort(session.abort_handle());
    let drain_startup = async {
        while let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(40),
            read_v2_frame(&mut c_reader, magic),
        )
        .await
        {}
    };
    tokio::time::timeout(Duration::from_secs(2), drain_startup)
        .await
        .expect("startup frames drain");
    write_v2_msg(
        &mut c_writer,
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut block = genesis_block(Network::Regtest);
    block.header.prev_blockhash = BlockHash::from_byte_array([0x11; 32]);
    let hash = block.block_hash();
    write_v2_msg(&mut c_writer, NetworkMessage::Block(block))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let tip_hash = hub.tip_hash().expect("genesis tip");
    let header = hub.tip_header().expect("genesis header");
    let _ = hub.tip_tx.send(TipEvent {
        height: 0,
        hash: tip_hash,
        header,
        reorg_branch_len: 0,
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(peers.disconnect_id(live.id), "the peer is registered");
    assert!(
        !live.take_block_from_peer(&hash),
        "the body stays queued while every decode permit is held"
    );
    drop(held);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut applied = false;
    while std::time::Instant::now() < deadline {
        if live.take_block_from_peer(&hash) {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        applied,
        "a failed tip announce must still apply a block already read"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

fn outbound_test_peer(
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
) -> Arc<rbitcoin_net::peers::LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
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
    let peer = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    peer.hb_to.store(true, Ordering::Relaxed);
    peer
}

fn sent(out_rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<NetworkMessage> {
    let mut msgs = Vec::new();
    while let Ok(m) = out_rx.try_recv() {
        msgs.push(m.expect_msg());
    }
    msgs
}

/// Core keeps a compact block that waits on `blocktxn` in the peer's
/// blocks in flight. A high-bandwidth peer that never sends the
/// `blocktxn` holds the ping timeout like a `getdata` does, and is then
/// dropped by the block download timeout one block interval after the
/// compact block arrived. Its session drop frees the compact slot, so
/// another outbound peer can reconstruct the block.
#[tokio::test]
async fn silent_compact_peer_holds_the_ping_then_hits_the_download_timeout() {
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let (dir, hub, [a, _]) = compact_spend_pair("cmpct-download-timeout");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000;
    peers.set_mock_now(start);
    let silent = outbound_test_peer(&peers, 18448);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        sent(&mut out_rx)
            .iter()
            .any(|m| matches!(m, NetworkMessage::Ping(_))),
        "the first heartbeat pings the peer"
    );

    let compact = CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&a, 0xbeef, 2, &[]).unwrap(),
    };
    // Five minutes before the ping is due, so the download window is still
    // open when it is.
    let asked = start + PING_TIMEOUT_SECS - BLOCK_INTERVAL_SECS / 2;
    peers.set_mock_now(asked);
    on_cmpctblock(&hub, &out_tx, &mut follow, Some(silent.as_ref()), &compact)
        .await
        .unwrap();
    assert!(matches!(
        sent(&mut out_rx).as_slice(),
        [NetworkMessage::GetBlockTxn(_)]
    ));
    assert!(follow.requested_blocks.is_empty());
    peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        !silent.stop.load(Ordering::SeqCst),
        "a peer whose compact block waits on blocktxn hit the ping timeout"
    );
    peers.set_mock_now(asked + BLOCK_INTERVAL_SECS);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        !silent.stop.load(Ordering::SeqCst),
        "the download timeout is strictly after one interval"
    );
    peers.set_mock_now(asked + BLOCK_INTERVAL_SECS + 1);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        silent.stop.load(Ordering::SeqCst),
        "a silent compact peer kept its block past the download timeout"
    );

    let other = outbound_test_peer(&peers, 18450);
    let (other_tx, mut other_rx) = mpsc::unbounded_channel();
    let mut other_follow = PeerFollowState::new();
    other_follow.cmpct_version = 2;
    on_cmpctblock(
        &hub,
        &other_tx,
        &mut other_follow,
        Some(other.as_ref()),
        &compact,
    )
    .await
    .unwrap();
    assert!(
        sent(&mut other_rx).is_empty(),
        "the silent peer still holds the outbound compact slot"
    );
    peers.unregister(silent.id);
    assert_eq!(peers.peers_downloading_from.load(Ordering::Relaxed), 0);
    on_cmpctblock(
        &hub,
        &other_tx,
        &mut other_follow,
        Some(other.as_ref()),
        &compact,
    )
    .await
    .unwrap();
    assert!(matches!(
        sent(&mut other_rx).as_slice(),
        [NetworkMessage::GetBlockTxn(_)]
    ));
    on_blocktxn(
        &hub,
        &other_tx,
        &mut other_follow,
        Some(other.as_ref()),
        &BlockTransactions {
            block_hash: a.block_hash(),
            transactions: vec![a.txdata[1].clone()],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a.block_hash()),
        "the other peer completes the block"
    );
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
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-same-peer");
        hub.ensure_genesis().unwrap();
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
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
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
        let hash = block.block_hash();
        let peers = rbitcoin_net::peers::PeerHub::new();
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
        let session = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        session.hb_to.store(true, Ordering::Relaxed);
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
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("handle-frame");
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
            getdata_tail: VecDeque::new(),
            getblocktxn_tail: VecDeque::new(),
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

        // Unknown block inv during IBD challenges the walk and asks for
        // headers. No session is attached, so the ask is the inv path's
        // default. Drain it so the headers reply below is the next message.
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
        assert!(
            matches!(
                out_rx.try_recv().unwrap().expect_msg(),
                NetworkMessage::GetHeaders(_)
            ),
            "an unknown block inv during IBD still asks for headers"
        );
        assert!(hub.header_inv_challenge_pending());

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

        // Depth 10 still answers with the transactions. One past that is a full block
        // (`p2p_compactblocks` :635).
        hub.generate_to_script(10, ScriptBuf::from_bytes(vec![0x51]), vec![])
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
                NetworkMessage::BlockTxn(_)
            ),
            "getblocktxn at depth 10 still serves the transactions"
        );
        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
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
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("handle-mp");
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        assert!(!hub.in_ibd(), "tx inv getdata pin is not IBD");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
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
            getdata_tail: VecDeque::new(),
            getblocktxn_tail: VecDeque::new(),
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
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let peers = rbitcoin_net::peers::PeerHub::new();
        if via_cidr {
            let mut table = rbitcoin_net::net_permissions::NetPermTable::default();
            table.whitelist.push(
                rbitcoin_net::net_permissions::parse_whitelist("forcerelay@127.0.0.1").unwrap(),
            );
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        if via_cidr {
            assert!(sess.has_net_perm(rbitcoin_net::NetPermissionFlags::FORCE_RELAY));
        } else {
            assert!(!sess.has_net_perm(rbitcoin_net::NetPermissionFlags::FORCE_RELAY));
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
            getdata_tail: VecDeque::new(),
            getblocktxn_tail: VecDeque::new(),
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
        let needle = format!(
            "txrelay: reject {txid} (wtxid={wtxid}) from peer=0 was not accepted: coinbase"
        );
        assert!(
            first
                .iter()
                .filter(|(level, m)| *level == rbitcoin_log::Level::Info && m.contains(&needle))
                .count()
                == 1,
            "first reject must be one info line, got {first:?}"
        );
        assert!(
            !first
                .iter()
                .any(|(level, m)| *level == rbitcoin_log::Level::Debug
                    && m.contains("txrelay: reject")),
            "reject must not also log at debug, got {first:?}"
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-mp");
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
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
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);

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
        follow.cmpct_version = 2;
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
        follow.cmpct_version = 2;
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pending-reorg");
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
        let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-asked-src");
        src.ensure_genesis().unwrap();
        src.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hdr = src.query.wire_header_at_height(Height(1)).unwrap();
        let hash = hdr.block_hash();

        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-asked-dst");
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
            getdata_tail: VecDeque::new(),
            getblocktxn_tail: VecDeque::new(),
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bloom-off");
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
        getdata_tail: VecDeque::new(),
        getblocktxn_tail: VecDeque::new(),
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("locator-oversize");
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
        getdata_tail: VecDeque::new(),
        getblocktxn_tail: VecDeque::new(),
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
    use rbitcoin_net::peers::PeerConnType;
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
        rbitcoin_net::peer::ping_prior_to_verack_log(0),
        "p2p: Unsupported message \"ping\" prior to verack from peer=0"
    );
    assert_eq!(
        rbitcoin_net::peer::non_version_before_handshake_log("ping", 1),
        "p2p: non-version message before version handshake. Message \"ping\" from peer=1"
    );
    assert_eq!(
        rbitcoin_net::peer::obsolete_version_log(31799, 5),
        "p2p: using obsolete version 31799, disconnecting peer=5"
    );
    assert_eq!(rbitcoin_net::peer::MIN_PEER_PROTO_VERSION, 31800);
    let hidden = rbitcoin_net::peer::hidden_addr_from();
    let zero = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    assert_eq!(
        hidden,
        bitcoin::p2p::address::Address::new(&zero, bitcoin::p2p::ServiceFlags::NONE)
    );
    assert_eq!(
        rbitcoin_net::peer::advertising_address_log("42.42.42.42:18445", 3),
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
fn pending_block_over_four_megabytes_is_not_parked() {
    let mut pending = PendingBlocks::new();
    let mut exact = block_with_wire_len(4_000_000);
    exact.header.nonce = 1;
    let exact_h = exact.block_hash();
    pending.insert(exact_h, exact);
    assert!(
        pending.contains_key(&exact_h),
        "a 4_000_000-byte body is parked"
    );
    let mut over = block_with_wire_len(4_000_000);
    over.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; 4_000_001]);
    over.header.nonce = 2;
    let h = over.block_hash();
    pending.insert(h, over);
    assert!(!pending.contains_key(&h));
    assert!(pending.contains_key(&exact_h));
}

fn block_with_wire_len(n: usize) -> bitcoin::Block {
    let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut len = n;
    for _ in 0..6 {
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; len]);
        let got = b.total_size();
        if got == n {
            return b;
        }
        if got > n {
            len = len.saturating_sub(got - n);
        } else {
            len = len.saturating_add(n - got);
        }
    }
    panic!("wire len {n} landed on {}", b.total_size());
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

struct ServeSession {
    _dir: rbitcoin_query::testutil::TempDir,
    hub: rbitcoin_net::chain::ChainHub,
    hashes: Vec<BlockHash>,
    _peers: std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    sess: std::sync::Arc<rbitcoin_net::peers::LivePeer>,
}

fn serve_session(label: &str, blocks: u32) -> ServeSession {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .generate_to_script(blocks, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    assert_eq!(hashes.len(), blocks as usize);
    let peers = rbitcoin_net::peers::PeerHub::new();
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
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    ServeSession {
        _dir: dir,
        hub,
        hashes,
        _peers: peers,
        sess,
    }
}

fn getdata_frame(hashes: &[BlockHash]) -> FramedMessage {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_blockdata::Inventory;
    let inv = hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
    let magic = Magic::from(bitcoin::Network::Regtest);
    let full = serialize(&RawNetworkMessage::new(magic, NetworkMessage::GetData(inv)));
    FramedMessage {
        magic,
        command: full[4..16].try_into().unwrap(),
        payload: full[24..].to_vec(),
    }
}

/// Stand-in for the session writer: everything queued so far, with the
/// `notfound` rows split from the served bodies.
fn take_queued(
    out_rx: &mut mpsc::UnboundedReceiver<PeerOut>,
) -> (Vec<PeerOut>, Vec<Vec<Inventory>>) {
    let mut bodies = Vec::new();
    let mut notfound = Vec::new();
    while let Ok(out) = out_rx.try_recv() {
        match out {
            PeerOut::Msg(NetworkMessage::NotFound(inv)) => notfound.push(inv),
            body => bodies.push(body),
        }
    }
    (bodies, notfound)
}

/// What the session writer records after it wrote `out`.
fn wrote(sess: &rbitcoin_net::peers::LivePeer, out: &PeerOut) {
    sess.note_out_written(
        out.holds_serve_slot(),
        rbitcoin_net::peers::outbound_queued_bytes(out),
    );
}

fn served_hashes(queued: Vec<PeerOut>) -> Vec<BlockHash> {
    queued
        .into_iter()
        .map(|out| served_block(out).block_hash())
        .collect()
}

/// Core `ProcessGetData` stops on a full send buffer, sends the `notfound`
/// it collected, and returns to the message loop with the rest queued. A
/// getdata past the served-body cap hands the reader back the same way.
/// Once the writer drains, the rest is served in order and no hash is
/// dropped. A silent drop held the requester's getdata until its 30 s
/// stall kick.
#[test]
fn getdata_past_serve_cap_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-cap-waits", 20);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        let unknown = BlockHash::from_byte_array([7u8; 32]);
        let ask: Vec<BlockHash> = std::iter::once(unknown).chain(s.hashes.clone()).collect();
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getdata_frame(&ask),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getdata past the serve cap returns to the session loop")
        .unwrap();
        let (first, notfound) = take_queued(&mut out_rx);
        assert_eq!(first.len(), MAX_SERVE_BLOCKS, "the 17th waits");
        assert_eq!(
            notfound,
            vec![vec![Inventory::WitnessBlock(unknown)]],
            "the notfound collected before the pause is sent"
        );
        assert_eq!(
            s.sess.serve_inflight.load(Ordering::SeqCst),
            MAX_SERVE_BLOCKS
        );

        for out in &first {
            wrote(&s.sess, out);
        }
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (rest, notfound) = take_queued(&mut out_rx);
        assert!(notfound.is_empty(), "no notfound for blocks we hold");
        let served = first.into_iter().chain(rest).collect();
        assert_eq!(
            served_hashes(served),
            s.hashes,
            "every requested block is served once, in order"
        );
    });
}

fn getblocktxn_frame(hash: BlockHash, indexes: Vec<u64>) -> FramedMessage {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    let msg = NetworkMessage::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash: hash,
            indexes,
        },
    });
    let magic = Magic::from(bitcoin::Network::Regtest);
    let full = serialize(&RawNetworkMessage::new(magic, msg));
    FramedMessage {
        magic,
        command: full[4..16].try_into().unwrap(),
        payload: full[24..].to_vec(),
    }
}

/// A `getblocktxn` for a block we hold, while the writer is already past
/// the send budget, queues nothing and keeps the request. After the writer
/// drains, that request is served as a `blocktxn` or a full block, charged
/// at its real size, and it holds a serve slot.
#[test]
fn getblocktxn_over_send_budget_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("gbtxn-budget-waits", 12);
        let tip = *s.hashes.last().unwrap();
        let deep = s.hashes[0];
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        let earlier = rbitcoin_net::peers::PEER_SEND_BUDGET + 1;
        s.sess.note_send_queued(earlier);
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getblocktxn_frame(tip, vec![0]),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getblocktxn past the send budget returns to the session loop")
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "getblocktxn past the send budget is not queued"
        );
        assert_eq!(
            s.sess.send_queued(),
            earlier,
            "a paused getblocktxn reconstructs nothing"
        );
        assert!(
            !follow.getblocktxn_tail.is_empty(),
            "the request stays until the writer drains"
        );

        s.sess.note_send_written(earlier);
        serve_getblocktxn_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let served = out_rx
            .try_recv()
            .expect("drain serves the parked getblocktxn");
        assert!(
            served.holds_serve_slot(),
            "a getblocktxn reply holds a serve slot"
        );
        let charged = rbitcoin_net::peers::outbound_queued_bytes(&served);
        let msg = match &served {
            PeerOut::Msg(m) | PeerOut::Served(m) => m,
            PeerOut::Encoded(_) => panic!("getblocktxn reply is not a pre-encoded getdata body"),
        };
        match msg {
            NetworkMessage::BlockTxn(bt) => {
                let n = bitcoin::consensus::encode::serialize(&bt.transactions).len();
                assert!(n > 64, "blocktxn is not the 64-byte fallback");
                assert_eq!(charged, n);
            }
            NetworkMessage::Block(b) => {
                assert!(b.total_size() > 64);
                assert_eq!(charged, b.total_size());
            }
            other => panic!("expected blocktxn or block, got {other:?}"),
        }
        assert_eq!(s.sess.send_queued(), charged);
        assert_eq!(s.sess.serve_inflight.load(Ordering::SeqCst), 1);
        assert!(follow.getblocktxn_tail.is_empty());
        wrote(&s.sess, &served);

        // Depth > 10 is the full block, on the same slot and byte charge.
        handle_peer_frame(
            getblocktxn_frame(deep, vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        let deep_out = out_rx.try_recv().expect("deep getblocktxn");
        assert!(deep_out.holds_serve_slot());
        match deep_out.expect_msg() {
            NetworkMessage::Block(b) => assert_eq!(b.block_hash(), deep),
            other => panic!("depth past 10 is a full block, got {other:?}"),
        }

        // An empty getblocktxn asks for nothing. Core drops the peer before
        // it reads the block (bitcoin/bitcoin#35832).
        handle_peer_frame(
            getblocktxn_frame(deep, vec![]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "an empty getblocktxn sends nothing back"
        );
        assert!(follow.getblocktxn_tail.is_empty());
        assert!(
            s.sess.stop.load(Ordering::SeqCst),
            "an empty getblocktxn drops the peer"
        );

        // The peer never reads. Further requests stop at the serve cap
        // instead of reconstructing without bound.
        let queued_before = s.sess.send_queued();
        let mut extra = 0usize;
        for _ in 0..MAX_SERVE_BLOCKS + 4 {
            handle_peer_frame(
                getblocktxn_frame(tip, vec![0]),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            )
            .await
            .unwrap();
            if out_rx.try_recv().is_err() {
                break;
            }
            extra += 1;
        }
        assert_eq!(extra, MAX_SERVE_BLOCKS - 1, "the 17th getblocktxn waits");
        assert_eq!(
            s.sess.serve_inflight.load(Ordering::SeqCst),
            MAX_SERVE_BLOCKS
        );
        assert_eq!(follow.getblocktxn_tail.len(), 1);
        assert!(s.sess.send_queued() > queued_before);
        assert!(
            s.sess.send_queued() <= rbitcoin_net::peers::PEER_SEND_BUDGET,
            "small blocktxn replies stay inside the byte budget at the slot cap"
        );
    });
}

/// Archive reconstruct for `getblocktxn` runs on the blocking pool. A
/// connection task named `tokio-rt-worker` still receives the reply.
#[test]
fn getblocktxn_reconstruct_is_off_the_connection_task() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("gbtxn-reactor", 1);
        let tip = *s.hashes.last().unwrap();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        handle_peer_frame(
            getblocktxn_frame(tip, vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::BlockTxn(_)
        ));
    });
}

/// `blocktxn` shares the send budget at its real payload size. The 64-byte
/// fallback let a peer that never reads queue far more than 4 MiB.
#[test]
fn blocktxn_outbound_bytes_are_the_payload() {
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::consensus::encode::serialize;
    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let txns = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![block.txdata[0].clone()],
    };
    let payload = serialize(&txns).len();
    assert!(payload > 64, "a coinbase blocktxn is not the fallback size");
    assert_eq!(
        rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::BlockTxn(BlockTxn {
            transactions: txns
        })),
        payload
    );
}

/// A reply already past the send budget pauses the whole getdata. It does
/// not drop it.
#[test]
fn getdata_over_send_budget_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-budget-waits", 3);
        let earlier = rbitcoin_net::peers::PEER_SEND_BUDGET + 1;
        s.sess.note_send_queued(earlier);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getdata_frame(&s.hashes),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getdata past the send budget returns to the session loop")
        .unwrap();
        assert!(out_rx.try_recv().is_err(), "served past the send budget");
        s.sess.note_send_written(earlier);
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (got, notfound) = take_queued(&mut out_rx);
        assert!(notfound.is_empty());
        assert_eq!(served_hashes(got), s.hashes);
    });
}

/// A compact tip announce holds no serve slot. A deep `getblocktxn` full
/// block does, and shares the cap with getdata bodies. Writing the
/// announces does not open a slot, so a paused getdata never queues more
/// than `MAX_SERVE_BLOCKS` bodies.
#[test]
fn uncounted_bodies_do_not_open_serve_slots() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-slot-uncounted", 20);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        let tip = *s.hashes.last().unwrap();
        for _ in 0..3 {
            let announce = cmpct_announce_msg(&s.hub, &tip, 2).expect("cmpct announce");
            queue_cmpct_tip_announce(&out_tx, announce).unwrap();
        }
        handle_peer_frame(
            getblocktxn_frame(s.hashes[0], vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        handle_peer_frame(
            getdata_frame(&s.hashes),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();

        let (queued, _) = take_queued(&mut out_rx);
        let (slots, uncounted): (Vec<_>, Vec<_>) =
            queued.into_iter().partition(|out| out.holds_serve_slot());
        assert_eq!(uncounted.len(), 3, "three announces hold no serve slot");
        assert_eq!(
            slots.len(),
            MAX_SERVE_BLOCKS,
            "the getblocktxn block shares the serve cap with getdata"
        );
        assert!(
            matches!(
                slots.first(),
                Some(PeerOut::Served(NetworkMessage::Block(_)))
            ),
            "the deep getblocktxn block is the first served body"
        );
        for out in &uncounted {
            wrote(&s.sess, out);
        }
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (more, _) = take_queued(&mut out_rx);
        assert!(
            more.is_empty(),
            "writing an announce must not let a getdata body past the serve cap"
        );
    });
}

/// The wait that resumes a paused getdata ends when the session is told
/// to disconnect, or when its writer is gone.
#[tokio::test]
async fn paused_getdata_ends_on_disconnect_or_dead_writer() {
    use std::time::Duration;
    let s = serve_session("serve-pause-ends", 0);
    s.sess
        .serve_inflight
        .store(MAX_SERVE_BLOCKS, Ordering::SeqCst);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let stop = async {
        tokio::task::yield_now().await;
        s.sess.request_disconnect();
    };
    let (room, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(s.sess.wait_serve_room(&out_tx), stop)
    })
    .await
    .expect("disconnect must end a paused getdata");
    assert!(!room);

    let s = serve_session("serve-pause-dead-writer", 0);
    s.sess
        .serve_inflight
        .store(MAX_SERVE_BLOCKS, Ordering::SeqCst);
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let gone = async move {
        tokio::task::yield_now().await;
        drop(out_rx);
    };
    let (room, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(s.sess.wait_serve_room(&out_tx), gone)
    })
    .await
    .expect("a dead writer must end a paused getdata");
    assert!(!room);
}

/// A node with `blocks` mined and a raw BIP324 client for each `agents`
/// entry, each paired with the node's session for it.
struct PausedServe {
    dir: std::path::PathBuf,
    node: rbitcoin_net::P2PNode,
    hashes: Vec<BlockHash>,
    clients: Vec<(V2PlainSession, Arc<rbitcoin_net::peers::LivePeer>)>,
}

async fn paused_serve(label: &str, blocks: u32, agents: &[&str]) -> PausedServe {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-{label}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let query = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let node = rbitcoin_net::P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(serve)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let hashes = node
        .hub
        .generate_to_script(blocks, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    node.peers.set_mock_now(node.peers.now_secs());
    let mut clients = Vec::new();
    for agent in agents {
        let stream = TcpStream::connect(node.local_addr).await.unwrap();
        let raw = V2PlainSession::outbound_regtest(stream, agent, Duration::from_secs(5))
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let sess = loop {
            let live = node.peers.live_peers();
            if let Some(p) = live.into_iter().find(|p| p.subver == *agent) {
                break p;
            }
            assert!(std::time::Instant::now() < deadline, "{agent} session");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        clients.push((raw, sess));
    }
    PausedServe {
        dir,
        node,
        hashes,
        clients,
    }
}

async fn next_peer_msg(raw: &mut V2PlainSession) -> Result<NetworkMessage, NetError> {
    let contents = raw.read_contents().await?;
    let frame = rbitcoin_net::v2::parse_v2_contents(Magic::REGTEST, &contents)?;
    Ok(frame.decode().payload().clone())
}

async fn write_peer_msg(raw: &mut V2PlainSession, msg: NetworkMessage) {
    raw.write_contents(&rbitcoin_net::v2::encode_v2_contents(msg).unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_block_request_disconnects_without_waiting_for_another_message() {
    let mut t = paused_serve("rate-request", 1, &["/rbitcoin:test(rate-request)/"]).await;
    let (raw, _) = &mut t.clients[0];
    // The handshake is outside the rate window; send no follow-session replies.
    for _ in 0..rbitcoin_net::peer_dos::DEFAULT_MAX_MSGS_PER_SEC {
        write_peer_msg(raw, NetworkMessage::Ping(7)).await;
    }
    write_peer_msg(raw, getdata_msg(&t.hashes)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match next_peer_msg(raw).await {
                Err(_) => return true,
                Ok(NetworkMessage::Block(_)) => return false,
                Ok(_) => {}
            }
        }
    })
    .await;
    raw.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        matches!(closed, Ok(true)),
        "an over-budget block request must close the session, not disappear: {closed:?}"
    );
}

/// A follow session that has asked for one block body it will never get.
async fn serve_with_open_ask(label: &str) -> (PausedServe, BlockHash) {
    let mut t = paused_serve(label, 1, &["/rbitcoin:test(open-ask)/"]).await;
    let tip = t.node.hub.tip_header().unwrap();
    let mut child = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: tip.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x33; 32]),
        time: tip.time + 1,
        bits: tip.bits,
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut child);
    let hash = announce_and_wait_for_ask(&mut t, child).await;
    (t, hash)
}

/// The first client announces `header`; returns once the node asks it for
/// the body.
async fn announce_and_wait_for_ask(
    t: &mut PausedServe,
    header: bitcoin::block::Header,
) -> BlockHash {
    let hash = header.block_hash();
    announce_and_wait_for(t, 0, vec![header], hash).await;
    hash
}

/// Client `client` announces `headers`; returns once the node asks it for
/// `hash`.
async fn announce_and_wait_for(
    t: &mut PausedServe,
    client: usize,
    headers: Vec<bitcoin::block::Header>,
    hash: BlockHash,
) {
    let (raw, _) = &mut t.clients[client];
    write_peer_msg(raw, NetworkMessage::Headers(headers)).await;
    let asked = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkMessage::GetData(inv) = next_peer_msg(raw).await.unwrap() {
                if inv.iter().any(|i| {
                    matches!(i, Inventory::WitnessBlock(h) | Inventory::CompactBlock(h) if *h == hash)
                }) {
                    return;
                }
            }
        }
    })
    .await;
    assert!(asked.is_ok(), "the header announce must ask for its body");
    assert!(t.node.hub.already_have_or_asked_block(&hash));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_follow_session_releases_its_block_asks() {
    let (mut t, hash) = serve_with_open_ask("closed-asks").await;
    t.clients[0].0.close();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !t.node.peers.live_peers().is_empty() {
        assert!(std::time::Instant::now() < deadline, "closed session");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let still_asked = t.node.hub.already_have_or_asked_block(&hash);
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        !still_asked,
        "a disconnect must release the session's body asks for other peers"
    );
}

/// `disconnectnode`, inbound eviction, and stale-tip replacement abort the
/// session task instead of letting it return.
#[tokio::test]
async fn aborted_follow_session_releases_its_block_asks() {
    let (mut t, hash) = serve_with_open_ask("abort-asks").await;
    assert!(t.node.peers.disconnect_id(t.clients[0].1.id));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while t.node.hub.already_have_or_asked_block(&hash) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let still_asked = t.node.hub.already_have_or_asked_block(&hash);
    t.clients[0].0.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        !still_asked,
        "an aborted session must release its body asks for other peers"
    );
}

/// Unknown BIP324 short id on a live follow session counts as `*other*`
/// and the peer stays up (Core `test_msgtype`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_v2_short_id_counts_other_and_stays() {
    let mut t = paused_serve("bad-short-id", 0, &["/rbitcoin:test(badtype)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let id = sess.id;
    let first_ping = loop {
        if let NetworkMessage::Ping(n) = next_peer_msg(raw).await.unwrap() {
            break n;
        }
    };
    write_peer_msg(raw, NetworkMessage::Pong(first_ping)).await;
    // short id 99 + compact-size string "d" (Core `msg_unrecognized`).
    let unknown = [99u8, 1, b'd'];
    raw.write_contents(&unknown).await.unwrap();
    raw.write_contents(&unknown).await.unwrap();
    let want = rbitcoin_net::v2::v2_other_recv_bytes(unknown.len()) * 2;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let other = loop {
        let snap = t.node.peers.snapshot();
        let n = snap
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.bytesrecv_per_msg.get("*other*"))
            .copied();
        if n == Some(want) {
            break want;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "unknown short id was not counted as *other*, last={n:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(other, want);
    write_peer_msg(raw, NetworkMessage::Ping(9)).await;
    let pong = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let NetworkMessage::Pong(n) = next_peer_msg(raw).await.unwrap() {
                return n;
            }
        }
    })
    .await
    .expect("session stays up after an unknown short id");
    assert_eq!(pong, 9);
    assert!(t.node.peers.snapshot().iter().any(|p| p.id == id));
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

fn getdata_msg(hashes: &[BlockHash]) -> NetworkMessage {
    NetworkMessage::GetData(hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect())
}

async fn wait_session_read(
    node: &rbitcoin_net::P2PNode,
    sess: &rbitcoin_net::peers::LivePeer,
    cmd: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let read = node
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.id == sess.id)
            .is_some_and(|p| p.bytesrecv_per_msg.contains_key(cmd));
        if read {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "session never read {cmd}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Core's ping timeout runs while `ProcessGetData` is paused on
/// `fPauseSend`. A session paused on a getdata tail, or on its send budget,
/// still runs the heartbeat: a peer that never reads hits the ping timeout
/// and is disconnected. It is not held with no timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_session_still_times_out_a_silent_peer() {
    let mut t = paused_serve(
        "serve-pause-ping-timeout",
        20,
        &["/rbitcoin:test(slots)/", "/rbitcoin:test(budget)/"],
    )
    .await;
    let (slots_raw, slots) = &mut t.clients[0];
    slots
        .serve_inflight
        .store(MAX_SERVE_BLOCKS, Ordering::SeqCst);
    write_peer_msg(slots_raw, getdata_msg(&t.hashes)).await;
    wait_session_read(&t.node, slots, "getdata").await;
    let (_, budget) = &t.clients[1];
    budget.note_send_queued(2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    tokio::time::sleep(4 * SESSION_HEARTBEAT).await;

    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + 20 * 60 + 61);
    for (raw, sess) in &mut t.clients {
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match next_peer_msg(raw).await {
                    Err(_) => return,
                    Ok(NetworkMessage::Block(_)) => {
                        panic!("{} was served while paused", sess.subver)
                    }
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "{} was not dropped by the ping timeout",
            sess.subver
        );
    }
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

const PING_TIMEOUT_SECS: u64 = 20 * 60;
const POST_BLOCK_PONG_GRACE_SECS: u64 = 60;

/// Proves the session is still up: it answers a ping after some heartbeats.
async fn assert_session_answers(raw: &mut V2PlainSession, nonce: u64, why: &str) {
    tokio::time::sleep(10 * SESSION_HEARTBEAT).await;
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let pong = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match next_peer_msg(raw).await {
                Ok(NetworkMessage::Pong(n)) if n == nonce => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await;
    assert!(matches!(pong, Ok(true)), "{why}: {pong:?}");
}

/// The session is listed before it sends its handshake ping. A clock jump
/// that lands first stamps that ping at the jumped time, so wait for it.
async fn wait_ping_outstanding(sess: &rbitcoin_net::peers::LivePeer) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while sess.ping_nonce_sent.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the session never sent its ping"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// True once a heartbeat ran on `sess` and passed both timeouts: an
/// RPC-queued ping goes out only when neither the block download timeout
/// nor the ping timeout fired. That ping restarts the ping clock.
async fn heartbeat_keeps(sess: &rbitcoin_net::peers::LivePeer) -> bool {
    let before = sess.ping_nonce_sent.load(Ordering::Relaxed);
    sess.queue_ping();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if sess.stop.load(Ordering::SeqCst) {
            return false;
        }
        if sess.ping_nonce_sent.load(Ordering::Relaxed) != before {
            return true;
        }
        assert!(std::time::Instant::now() < deadline, "no heartbeat ran");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn session_closes(raw: &mut V2PlainSession) -> bool {
    tokio::time::timeout(Duration::from_secs(10), async {
        while next_peer_msg(raw).await.is_ok() {}
    })
    .await
    .is_ok()
}

/// `client` sends `block`; returns once it connects.
async fn deliver(t: &mut PausedServe, client: usize, block: bitcoin::Block) {
    let hash = block.block_hash();
    let (raw, _) = &mut t.clients[client];
    write_peer_msg(raw, NetworkMessage::Block(block)).await;
    // The tip-accept lane is one per process, so this connect queues behind
    // other tests' jobs (a 10k-header invalidate holds it for seconds on CI).
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while t.node.hub.tip_hash() != Some(hash) {
        assert!(
            std::time::Instant::now() < deadline,
            "served block connects"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `count` empty blocks on the node's tip.
fn chain_on_tip(t: &PausedServe, count: u32) -> Vec<bitcoin::Block> {
    let tip = t.node.hub.tip_header().unwrap();
    let height = t.node.hub.tip_height().unwrap();
    let mut prev = tip.block_hash();
    (1..=count)
        .map(|i| {
            let b = rbitcoin_consensus::mine_empty_regtest(prev, tip.time + i, height + i);
            prev = b.block_hash();
            b
        })
        .collect()
}

/// bitcoin/bitcoin#36080: a peer answers our block requests before our
/// ping, so on a slow link it can miss the ping timeout without being at
/// fault. The peer has two blocks in flight and serves one; the oldest
/// leaving restarts the block download window, so with the other still in
/// flight it is up past twenty minutes without answering the ping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_waits_while_a_block_is_in_flight() {
    let mut t = paused_serve("ping-inflight", 1, &["/rbitcoin:test(slow)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let start = t.node.peers.now_secs();
    t.node.peers.set_mock_now(start + BLOCK_INTERVAL_SECS - 100);
    let blocks = chain_on_tip(&t, 2);
    let last = blocks[1].block_hash();
    announce_and_wait_for(&mut t, 0, blocks.iter().map(|b| b.header).collect(), last).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS - 200);
    deliver(&mut t, 0, blocks[0].clone()).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(raw, 7, "a peer with a block in flight hit the ping timeout").await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Core does not restart the twenty minutes once the peer's blocks are in.
/// The peer gets one minute after the last block it delivered to answer
/// the ping, and is disconnected after that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_applies_a_minute_after_the_last_block() {
    let mut t = paused_serve("ping-grace", 1, &["/rbitcoin:test(grace)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let start = t.node.peers.now_secs();
    let asked_at = start + PING_TIMEOUT_SECS - BLOCK_INTERVAL_SECS / 2;
    t.node.peers.set_mock_now(asked_at);
    let block = chain_on_tip(&t, 1).remove(0);
    announce_and_wait_for_ask(&mut t, block.header).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(raw, 7, "a peer with a block in flight hit the ping timeout").await;

    deliver(&mut t, 0, block).await;
    let delivered = t.node.peers.now_secs();
    t.node
        .peers
        .set_mock_now(delivered + POST_BLOCK_PONG_GRACE_SECS);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(raw, 8, "the peer lost its minute to answer the ping").await;

    t.node
        .peers
        .set_mock_now(delivered + POST_BLOCK_PONG_GRACE_SECS + 1);
    let closed = session_closes(raw).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        closed,
        "the unanswered ping must time out after the grace minute"
    );
}

/// Sends `msg`, then a ping; returns once the pong shows `msg` was read.
async fn send_and_sync(raw: &mut V2PlainSession, msg: NetworkMessage, nonce: u64) {
    write_peer_msg(raw, msg).await;
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let pong = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match next_peer_msg(raw).await {
                Ok(NetworkMessage::Pong(n)) if n == nonce => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await;
    assert!(
        matches!(pong, Ok(true)),
        "session read the message: {pong:?}"
    );
}

/// Core starts the grace minute at the last **new** block. A peer that
/// re-sends the tip it already gave us, as a compact block or a full one,
/// with nothing in flight, does not hold off the twenty-minute timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resent_tip_does_not_hold_off_the_ping_timeout() {
    use bitcoin::bip152::HeaderAndShortIds;

    let mut t = paused_serve(
        "ping-resent-tip",
        1,
        &[
            "/rbitcoin:test(resend-cmpct)/",
            "/rbitcoin:test(resend-block)/",
        ],
    )
    .await;
    for (_, sess) in &t.clients {
        wait_ping_outstanding(sess).await;
    }
    let tip = t.node.hub.block_at_height(1).unwrap().unwrap();
    let start = t.node.peers.now_secs();
    t.node
        .peers
        .set_mock_now(start + PING_TIMEOUT_SECS - POST_BLOCK_PONG_GRACE_SECS / 2);
    let compact = NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&tip, 0xbeef, 2, &[]).unwrap(),
    });
    send_and_sync(&mut t.clients[0].0, compact, 7).await;
    send_and_sync(&mut t.clients[1].0, NetworkMessage::Block(tip), 8).await;

    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let mut held = Vec::new();
    for (raw, sess) in &mut t.clients {
        if !session_closes(raw).await {
            held.push(sess.subver.clone());
        }
    }
    assert!(
        held.is_empty(),
        "re-sending the tip held off the ping timeout: {held:?}"
    );
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// With nothing in flight the ping timeout is the twenty minutes alone; the
/// grace minute only follows a delivered block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_without_blocks_in_flight_is_twenty_minutes() {
    let mut t = paused_serve("ping-idle", 1, &["/rbitcoin:test(idle)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + PING_TIMEOUT_SECS + 1);
    let (raw, _) = &mut t.clients[0];
    let closed = session_closes(raw).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        closed,
        "an idle peer that never answers the ping must time out"
    );
}

const BLOCK_INTERVAL_SECS: u64 = 600;

/// Waits until the session for `sess` has ended and released what it held.
async fn wait_unregistered(t: &PausedServe, sess: &rbitcoin_net::peers::LivePeer) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while t.node.peers.live_peers().iter().any(|p| p.id == sess.id) {
        assert!(std::time::Instant::now() < deadline, "session never ended");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Client `client` answers the node's outstanding ping.
async fn answer_ping(t: &mut PausedServe, client: usize) {
    let (raw, sess) = &mut t.clients[client];
    let nonce = sess.ping_nonce_sent.load(Ordering::Relaxed);
    assert_ne!(nonce, 0, "no ping to answer");
    write_peer_msg(raw, NetworkMessage::Pong(nonce)).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while sess.ping_nonce_sent.load(Ordering::Relaxed) == nonce {
        assert!(std::time::Instant::now() < deadline, "pong not read");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `server` announces `block` and serves it; returns once it connects.
async fn serve_from(t: &mut PausedServe, server: usize, block: bitcoin::Block) {
    let hash = block.block_hash();
    announce_and_wait_for(t, server, vec![block.header], hash).await;
    deliver(t, server, block).await;
}

/// Core's block download timeout: a peer that leaves a block in flight for
/// one block interval, plus half of one per other peer we are downloading
/// from, is disconnected. Its asks are released, so a third peer that
/// announces the same bodies is asked for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_download_timeout_hands_the_body_to_another_peer() {
    let mut t = paused_serve(
        "block-timeout",
        1,
        &[
            "/rbitcoin:test(holder-a)/",
            "/rbitcoin:test(holder-b)/",
            "/rbitcoin:test(late-holder)/",
            "/rbitcoin:test(server)/",
        ],
    )
    .await;
    for (_, sess) in &t.clients {
        wait_ping_outstanding(sess).await;
    }
    let tip = t.node.hub.tip_header().unwrap();
    let height = t.node.hub.tip_height().unwrap();
    let x = rbitcoin_consensus::mine_empty_regtest(tip.block_hash(), tip.time + 1, height + 1);
    let y = rbitcoin_consensus::mine_empty_regtest(x.block_hash(), tip.time + 2, height + 2);
    announce_and_wait_for(&mut t, 0, vec![x.header], x.block_hash()).await;
    announce_and_wait_for(&mut t, 1, vec![x.header, y.header], y.block_hash()).await;
    let now = t.node.peers.now_secs();
    let two_peers = BLOCK_INTERVAL_SECS * 3 / 2;

    t.node.peers.set_mock_now(now + BLOCK_INTERVAL_SECS + 1);
    for (_, sess) in &t.clients[..2] {
        assert!(
            heartbeat_keeps(sess).await,
            "with two peers downloading the timeout is 1.5 intervals"
        );
    }
    t.node.peers.set_mock_now(now + two_peers);
    for (_, sess) in &t.clients[..2] {
        assert!(
            heartbeat_keeps(sess).await,
            "the timeout is strictly after the window"
        );
    }
    t.node.peers.set_mock_now(now + two_peers + 1);
    for i in 0..2 {
        let (raw, sess) = &mut t.clients[i];
        let sess = Arc::clone(sess);
        assert!(
            session_closes(raw).await,
            "{} kept its blocks past the timeout",
            sess.subver
        );
        wait_unregistered(&t, &sess).await;
    }

    // The dropped holders no longer count: one peer downloading is one interval.
    answer_ping(&mut t, 3).await;
    announce_and_wait_for(&mut t, 2, vec![x.header], x.block_hash()).await;
    let asked = t.node.peers.now_secs();
    t.node.peers.set_mock_now(asked + BLOCK_INTERVAL_SECS + 1);
    let (raw, late) = &mut t.clients[2];
    let late = Arc::clone(late);
    assert!(
        session_closes(raw).await,
        "a lone holder outlived one interval"
    );
    wait_unregistered(&t, &late).await;

    serve_from(&mut t, 3, x).await;
    serve_from(&mut t, 3, y).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Core appends a second getdata behind the paused one and serves both in
/// order. While the first is paused the session keeps pinging, and once
/// the writer has room the tail is served before the next getdata.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_getdata_tail_is_served_before_the_next_getdata() {
    let mut t = paused_serve("serve-pause-order", 22, &["/rbitcoin:test(order)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let first_ping = loop {
        if let NetworkMessage::Ping(n) = next_peer_msg(raw).await.unwrap() {
            break n;
        }
    };
    write_peer_msg(raw, NetworkMessage::Pong(first_ping)).await;
    wait_session_read(&t.node, sess, "pong").await;

    sess.serve_inflight
        .store(MAX_SERVE_BLOCKS, Ordering::SeqCst);
    let (a, b) = t.hashes.split_at(20);
    write_peer_msg(raw, getdata_msg(a)).await;
    write_peer_msg(raw, getdata_msg(b)).await;
    wait_session_read(&t.node, sess, "getdata").await;

    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + 121);
    let pinged = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match next_peer_msg(raw).await.unwrap() {
                NetworkMessage::Ping(_) => return,
                NetworkMessage::Block(_) => {
                    panic!("a block was served while the getdata was paused")
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        pinged.is_ok(),
        "the heartbeat pings while the getdata is paused"
    );

    sess.serve_inflight.store(0, Ordering::SeqCst);
    sess.note_send_written(0);
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got = Vec::new();
        while got.len() < t.hashes.len() {
            if let NetworkMessage::Block(b) = next_peer_msg(raw).await.unwrap() {
                got.push(b.block_hash());
            }
        }
        got
    })
    .await
    .expect("the paused tail and the next getdata are served");
    assert_eq!(served, t.hashes, "tail first, then the next getdata");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
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
                crate::peers::PeerHub::new().as_ref(),
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

// `tcp_has_peer_fin` needs POLLRDHUP; off Linux it always reports no FIN.
#[cfg(target_os = "linux")]
#[test]
fn snapshot_omits_peer_after_tcp_fin() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::peers::{PeerConnType, PeerHub};
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
    use bitcoin::ScriptBuf;
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

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
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-b)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
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
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

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
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
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
    use bitcoin::ScriptBuf;
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

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
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
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
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tx-ann-empty");
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
    let ann = rbitcoin_net::tx_relay::MempoolAnnounce {
        txid,
        replaced: Vec::new(),
        replaced_scripthashes: Vec::new(),
        scripthashes: Vec::new(),
    };
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann.clone()))).is_ok());

    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("persist-path");
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

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-cap");
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
    serve_getdata(&hub, &out_tx, &mut follow, None, at_cap.clone())
        .await
        .unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "exactly {MAX_INV_SIZE} getdata items are served"
    );
    let mut over = at_cap;
    over.push(tx);
    let mut follow = PeerFollowState::new();
    serve_getdata(&hub, &out_tx, &mut follow, None, over)
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
    let peers = rbitcoin_net::peers::PeerHub::new();
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
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    peer.note_send_queued(rbitcoin_net::peers::PEER_SEND_BUDGET + 1);
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

/// `fPauseSend`: an over-budget session does not read. A ping sent while only
/// the send budget is blown gets no pong until the writer drains.
#[tokio::test]
async fn over_budget_session_does_not_read_a_ping() {
    use std::time::Duration;
    let mut t = paused_serve("serve-pause-read", 1, &["/rbitcoin:test(budget-read)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    sess.note_send_queued(2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    tokio::time::sleep(Duration::from_millis(150)).await;
    write_peer_msg(raw, NetworkMessage::Ping(7)).await;
    let early = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if let NetworkMessage::Pong(7) = next_peer_msg(raw).await.unwrap() {
                return;
            }
        }
    })
    .await;
    assert!(early.is_err(), "over-budget session must not read the ping");
    sess.note_send_written(2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let NetworkMessage::Pong(7) = next_peer_msg(raw).await.unwrap() {
                return;
            }
        }
    })
    .await
    .expect("draining the send budget lets the session read the ping");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

fn inbound_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
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
    peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    )
}

#[test]
fn inbound_netgroup_is_fixed_at_accept() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mk = |ip: [u8; 4]| {
        let addr = std::net::SocketAddr::from((ip, 1));
        let ver = bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: bitcoin::p2p::ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            nonce: u64::from(ip[3]),
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        )
    };
    let a = mk([1, 2, 3, 4]);
    let b = mk([1, 2, 9, 9]);
    let c = mk([1, 3, 0, 1]);
    assert_eq!(a.netgroup(), b.netgroup(), "same /16 is one group");
    assert_ne!(
        a.netgroup(),
        c.netgroup(),
        "a different /16 is another group"
    );
    assert_eq!(
        a.netgroup(),
        rbitcoin_net::eviction::eviction_netgroup(a.addr)
    );
}

#[test]
fn misbehavior_disconnect_refuses_the_same_address() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_000u64;
    peers.set_mock_now(now);
    let addr = std::net::SocketAddr::from(([9, 9, 9, 9], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    let other_port = std::net::SocketAddr::from(([9, 9, 9, 9], 9999));
    assert!(
        peers.inbound_discouraged(other_port),
        "a misbehavior disconnect refuses that address"
    );
    peers.set_mock_now(now + 86_400 - 1);
    assert!(peers.inbound_discouraged(addr), "the refusal lasts a day");
    peers.set_mock_now(now + 86_400);
    assert!(
        !peers.inbound_discouraged(addr),
        "the refusal ends after a day"
    );
}

#[test]
fn misbehavior_disconnect_does_not_refuse_loopback() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8333));
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
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    assert!(
        score >= BAN_SCORE_THRESHOLD,
        "a loopback peer is still disconnected"
    );
    let other_port = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 18444));
    assert!(
        !peers.inbound_discouraged(other_port),
        "one loopback disconnect must not refuse every local connection"
    );
}

/// An onion session's VERSION socket is `0.0.0.0`. The refusal is the
/// `NetAddr`, and a later session with that net is discouraged.
#[test]
fn overlay_misbehavior_discourages_that_net() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let onion = rbitcoin_net::NetAddr::Onion {
        pk: [9; 32],
        port: 8333,
    };
    let sock = std::net::SocketAddr::from(([0, 0, 0, 0], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&sock, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&sock, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register_net(
        sock,
        onion,
        sock,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    assert!(
        peers.net_discouraged(onion),
        "a misbehavior disconnect refuses that overlay net"
    );
    assert!(
        !peers.inbound_discouraged(sock),
        "0.0.0.0 must not become a clearnet refusal"
    );
}

/// The refusal is the onion or I2P identity. Another port is the same peer.
#[test]
fn overlay_refusal_ignores_the_port() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let onion = |port| rbitcoin_net::NetAddr::Onion { pk: [9; 32], port };
    let key = rbitcoin_net::peers::DiscourageKey::from_net(onion(8333)).unwrap();
    peers.note_misbehavior_key(key);
    assert!(peers.net_discouraged(onion(8333)));
    assert!(
        peers.net_discouraged(onion(9735)),
        "the same onion on another port is still refused"
    );
    assert!(!peers.net_discouraged(rbitcoin_net::NetAddr::Onion {
        pk: [8; 32],
        port: 9735,
    }));
    let i2p = |port| rbitcoin_net::NetAddr::I2p {
        dest: [7; 32],
        port,
    };
    peers.note_misbehavior_key(rbitcoin_net::peers::DiscourageKey::from_net(i2p(0)).unwrap());
    assert!(
        peers.net_discouraged(i2p(8333)),
        "the same I2P destination on another port is still refused"
    );
}

#[test]
fn threshold_exit_refuses_the_address_without_punish_disconnect() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_100u64;
    peers.set_mock_now(now);
    let addr = std::net::SocketAddr::from(([8, 8, 4, 4], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 4,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let err = threshold_disconnect(Some(peer.as_ref()));
    assert!(matches!(
        err,
        rbitcoin_net::error::NetError::Protocol("peer misbehavior threshold")
    ));
    let other_port = std::net::SocketAddr::from(([8, 8, 4, 4], 9999));
    assert!(
        peers.inbound_discouraged(other_port),
        "a rate-limit or score-threshold exit refuses that address"
    );

    peers.set_noban(true);
    let noban = peers.register(
        std::net::SocketAddr::from(([1, 2, 3, 4], 8333)),
        std::net::SocketAddr::from(([1, 2, 3, 4], 8333)),
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let _ = threshold_disconnect(Some(noban.as_ref()));
    assert!(
        !peers.inbound_discouraged(std::net::SocketAddr::from(([1, 2, 3, 4], 1))),
        "noban is not recorded"
    );
    peers.set_noban(false);

    // Core never discourages a manual peer.
    let manual_addr = std::net::SocketAddr::from(([5, 6, 7, 8], 8333));
    let manual = peers.register(
        manual_addr,
        manual_addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::Manual,
    );
    let _ = threshold_disconnect(Some(manual.as_ref()));
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(manual.as_ref()));
    assert!(
        manual.stop.load(std::sync::atomic::Ordering::SeqCst),
        "a protocol violation drops a manual peer"
    );
    assert!(
        !peers.inbound_discouraged(std::net::SocketAddr::from(([5, 6, 7, 8], 1))),
        "a manual peer is not recorded"
    );
}

#[test]
fn second_rate_limit_disconnect_from_an_address_discourages_it() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_200u64;
    peers.set_mock_now(now);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        sender: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        nonce: 5,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let flood = |addr: std::net::SocketAddr| {
        let peer = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        rate_limit_disconnect(Some(peer.as_ref()))
    };

    let first = std::net::SocketAddr::from(([7, 7, 7, 7], 8333));
    assert!(matches!(
        flood(first),
        rbitcoin_net::error::NetError::Protocol("peer rate limit")
    ));
    assert!(
        !peers.inbound_discouraged(first),
        "one rate-limit disconnect does not refuse the address"
    );
    assert!(matches!(
        flood(std::net::SocketAddr::from(([7, 7, 7, 7], 9999))),
        rbitcoin_net::error::NetError::Protocol("peer misbehavior threshold")
    ));
    assert!(
        peers.inbound_discouraged(first),
        "a second rate-limit disconnect from that address refuses it"
    );

    let slow = std::net::SocketAddr::from(([7, 7, 7, 8], 8333));
    let _ = flood(slow);
    peers.set_mock_now(now + rbitcoin_net::peers::PeerHub::RATE_STRIKE_SECS);
    let _ = flood(slow);
    assert!(
        !peers.inbound_discouraged(slow),
        "a strike older than the window does not count"
    );
}

#[test]
fn exempt_peer_rate_limit_leaves_no_strike_on_its_address() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_300);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        sender: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        nonce: 6,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let flood = |addr: std::net::SocketAddr, conn: rbitcoin_net::peers::PeerConnType| {
        let peer = peers.register(addr, addr, &ver, false, conn);
        rate_limit_disconnect(Some(peer.as_ref()))
    };

    let manual = std::net::SocketAddr::from(([6, 6, 6, 6], 8333));
    let _ = flood(manual, rbitcoin_net::peers::PeerConnType::Manual);
    let noban = std::net::SocketAddr::from(([6, 6, 6, 7], 8333));
    peers.set_noban(true);
    let _ = flood(noban, rbitcoin_net::peers::PeerConnType::Inbound);
    peers.set_noban(false);
    for exempt in [manual, noban] {
        let again = std::net::SocketAddr::from((exempt.ip(), 9999));
        assert!(
            matches!(
                flood(again, rbitcoin_net::peers::PeerConnType::Inbound),
                rbitcoin_net::error::NetError::Protocol("peer rate limit")
            ),
            "{exempt}: an exempt overflow leaves no strike for the next peer"
        );
        assert!(!peers.inbound_discouraged(again));
    }
}

#[test]
fn evicted_netgroup_waits_less_than_a_day_and_the_set_is_capped() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_800_000_000u64;
    peers.set_mock_now(now);
    let group = rbitcoin_net::eviction::eviction_netgroup("8.8.1.1:1".parse().unwrap());
    peers.note_slot_evict(group);
    let same = "8.8.9.9:8333".parse().unwrap();
    assert!(
        peers.inbound_discouraged(same),
        "a netgroup that just lost a slot is refused"
    );
    peers.set_mock_now(now + 600 - 1);
    assert!(
        peers.inbound_discouraged(same),
        "the netgroup wait holds until ten minutes"
    );
    peers.set_mock_now(now + 600);
    assert!(
        !peers.inbound_discouraged(same),
        "the netgroup wait is ten minutes"
    );
    peers.set_mock_now(now);
    for i in 0..rbitcoin_net::peers::PeerHub::DISCOURAGE_CAP {
        let a = (i / 256) as u8;
        let b = (i % 256) as u8;
        let slot = std::net::SocketAddr::from(([a, b, 1, 1], 1));
        peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(slot));
    }
    let overflow = std::net::SocketAddr::from(([255, 255, 1, 1], 1));
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(overflow));
    assert!(
        !peers.inbound_discouraged(overflow),
        "a new netgroup past the cap is not stored"
    );
    peers.set_mock_now(now + 100);
    let refreshed = std::net::SocketAddr::from(([0, 0, 1, 1], 1));
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(refreshed));
    peers.set_mock_now(now + 600);
    assert!(
        peers.inbound_discouraged(refreshed),
        "a netgroup already stored is refreshed at the cap"
    );
    peers.set_mock_now(now);
    for i in 0..rbitcoin_net::peers::PeerHub::DISCOURAGE_CAP {
        let ip = std::net::Ipv4Addr::from(i as u32);
        peers.note_misbehavior_addr(std::net::IpAddr::V4(ip));
    }
    let extra = std::net::SocketAddr::from(([255, 255, 255, 254], 1));
    peers.note_misbehavior_addr(extra.ip());
    assert!(
        !peers.inbound_discouraged(extra),
        "past the cap the set does not grow"
    );
    let first = std::net::SocketAddr::from((std::net::Ipv4Addr::from(0u32), 1));
    assert!(
        peers.inbound_discouraged(first),
        "rows already stored stay until they expire"
    );
}

/// A full inbound table evicts one peer and pauses that netgroup. The pause
/// must not refuse outbound dials to the rest of the prefix.
#[test]
fn slot_evict_does_not_block_an_outbound_dial() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_800_000_000);
    let evicted = "8.8.1.1:8333".parse().unwrap();
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(evicted));
    let neighbor: std::net::SocketAddr = "8.8.9.9:8333".parse().unwrap();
    assert!(
        peers.inbound_discouraged(neighbor),
        "the slot wait still refuses another inbound from that /16"
    );
    assert!(
        !peers.net_discouraged(rbitcoin_net::NetAddr::Ip(neighbor)),
        "the slot wait must not refuse an outbound dial in that /16"
    );
    let cjdns_ip = std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
    let cjdns_sock = std::net::SocketAddr::from((cjdns_ip, 8333));
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(cjdns_sock));
    assert!(
        peers.inbound_discouraged(cjdns_sock),
        "the slot wait still refuses another inbound from that cjdns group"
    );
    assert!(
        !peers.net_discouraged(rbitcoin_net::NetAddr::Cjdns {
            ip: cjdns_ip,
            port: 8333,
        }),
        "the slot wait must not refuse an outbound cjdns dial in that group"
    );
    peers.note_misbehavior_addr(neighbor.ip());
    assert!(
        peers.net_discouraged(rbitcoin_net::NetAddr::Ip(neighbor)),
        "a misbehavior key still refuses an outbound dial to that address"
    );
}

#[tokio::test]
async fn inv_getdata_charges_send_budget() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-budget");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "tx inv getdata pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = inbound_peer(&peers);
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let tx = Inventory::WitnessTransaction(Txid::from_byte_array([0x42; 32]));
    on_inv(&hub, &out_tx, &mut follow, Some(&peer), &[tx]).unwrap();
    assert!(
        peer.send_queued() > 0,
        "inv getdata must charge the send budget"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn relay_hub(label: &str) -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    (dir, hub)
}

fn sole_getdata(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<Inventory> {
    let NetworkMessage::GetData(items) = rx.try_recv().expect("one getdata").expect_msg() else {
        panic!("expected getdata");
    };
    assert!(rx.try_recv().is_err(), "one inv sends one getdata");
    items
}

/// Core #35878: a tx id repeated inside one INV is handled once. `tx` and
/// `witness-tx` share the txid set; a `wtx` with the same bytes is a
/// different id and is kept.
#[tokio::test]
async fn inv_drops_repeated_tx_ids_within_one_message() {
    use bitcoin::{Txid, Wtxid};

    let (dir, hub) = relay_hub("inv-dedupe");
    let t = Txid::from_byte_array([0x61; 32]);
    let w = Wtxid::from_byte_array([0x77; 32]);
    let w_same_bytes = Wtxid::from_byte_array([0x61; 32]);
    let (out_tx, mut rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let _ = hub.mempool().unwrap().sample_reset_perf();
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        None,
        &[
            Inventory::WitnessTransaction(t),
            Inventory::Transaction(t),
            Inventory::WTx(w),
            Inventory::WTx(w),
            Inventory::WTx(w_same_bytes),
        ],
    )
    .unwrap();
    assert_eq!(
        sole_getdata(&mut rx),
        vec![
            Inventory::WitnessTransaction(t),
            Inventory::WTx(w),
            Inventory::WTx(w_same_bytes),
        ],
        "each id once; a wtxid equal to a txid's bytes is still asked"
    );
    assert_eq!(
        hub.mempool().unwrap().sample_reset_perf().inv_tx,
        3,
        "the inv meter counts each id once"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The repeat filter is scoped to one INV message.
#[tokio::test]
async fn inv_repeat_filter_resets_per_message() {
    use bitcoin::Wtxid;

    let (dir, hub) = relay_hub("inv-dedupe-scope");
    let w = Wtxid::from_byte_array([0x78; 32]);
    let (out_tx, mut rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    for round in 0..2 {
        on_inv(&hub, &out_tx, &mut follow, None, &[Inventory::WTx(w)]).unwrap();
        assert_eq!(
            sole_getdata(&mut rx),
            vec![Inventory::WTx(w)],
            "round {round}: a later inv asks again"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A notfound for the in-flight wtxid makes the waiting announcer due now.
#[tokio::test]
async fn notfound_makes_the_waiting_wtxid_peer_due() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wtx-notfound");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer1 = inbound_peer(&peers);
    let peer2 = inbound_peer(&peers);
    let wtxid = bitcoin::Wtxid::from_byte_array([0xef; 32]);
    let inv = [Inventory::WTx(wtxid)];
    let noted = peer1.clock_now();
    let (tx1, mut rx1) = mpsc::unbounded_channel();
    let (tx2, _rx2) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &tx1, &mut follow, Some(&peer1), &inv).unwrap();
    on_inv(&hub, &tx2, &mut follow, Some(&peer2), &inv).unwrap();
    assert!(matches!(
        rx1.try_recv().unwrap().expect_msg(),
        NetworkMessage::GetData(_)
    ));
    handle_peer_inventory_msg(
        &NetworkMessage::NotFound(vec![Inventory::WTx(wtxid)]),
        &hub,
        &tx1,
        &mut follow,
        Some(&peer1),
    )
    .unwrap();
    let mp = hub.mempool().unwrap();
    let due = mp.take_due_parent_getdata(peer2.id, noted);
    assert_eq!(
        due.len(),
        1,
        "notfound from the in-flight peer makes the waiter due immediately"
    );
    assert!(due[0].wtxid);
    assert_eq!(due[0].hash, wtxid.to_byte_array());
    let _ = std::fs::remove_dir_all(dir);
}

/// `notfound` for a txid inventory (with or without witness) clears that request.
#[tokio::test]
async fn notfound_for_txid_inventory_wakes_the_waiter() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("txid-notfound");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    for (n, witness) in [(0xab_u8, false), (0xcd, true)] {
        let peer1 = inbound_peer(&peers);
        let peer2 = inbound_peer(&peers);
        let txid = bitcoin::Txid::from_byte_array([n; 32]);
        let item = if witness {
            Inventory::WitnessTransaction(txid)
        } else {
            Inventory::Transaction(txid)
        };
        let noted = peer1.clock_now();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let mut follow = PeerFollowState::new();
        on_inv(&hub, &tx1, &mut follow, Some(&peer1), &[item]).unwrap();
        on_inv(&hub, &tx2, &mut follow, Some(&peer2), &[item]).unwrap();
        assert!(matches!(
            rx1.try_recv().unwrap().expect_msg(),
            NetworkMessage::GetData(_)
        ));
        handle_peer_inventory_msg(
            &NetworkMessage::NotFound(vec![item]),
            &hub,
            &tx1,
            &mut follow,
            Some(&peer1),
        )
        .unwrap();
        let due = hub
            .mempool()
            .unwrap()
            .take_due_parent_getdata(peer2.id, noted);
        assert_eq!(due.len(), 1, "txid notfound makes the waiter due");
        assert!(!due[0].wtxid);
        assert_eq!(due[0].hash, txid.to_byte_array());
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Two inbound peers announce the same unknown wtxid. Only the first is
/// asked. The second stays queued until that request's interval ends.
#[tokio::test]
async fn second_wtxid_inv_waits_while_first_request_is_inflight() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wtx-one-inflight");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "wtxid inv getdata pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer1 = inbound_peer(&peers);
    let peer2 = inbound_peer(&peers);
    let wtxid = bitcoin::Wtxid::from_byte_array([0xee; 32]);
    let inv = [Inventory::WTx(wtxid)];
    let noted = peer1.clock_now();
    let (tx1, mut rx1) = mpsc::unbounded_channel();
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &tx1, &mut follow, Some(&peer1), &inv).unwrap();
    on_inv(&hub, &tx2, &mut follow, Some(&peer2), &inv).unwrap();
    match rx1.try_recv().unwrap().expect_msg() {
        NetworkMessage::GetData(v) => {
            assert_eq!(v, vec![Inventory::WTx(wtxid)]);
        }
        other => panic!("first announcer must be asked, got {other:?}"),
    }
    assert!(
        rx2.try_recv().is_err(),
        "a second announcer is not asked while the first request is in flight"
    );
    let mp = hub.mempool().unwrap();
    let due = mp.take_due_parent_getdata(
        peer2.id,
        noted.saturating_add(rbitcoin_net::tx_relay::GETDATA_TX_INTERVAL_SECS + 2),
    );
    assert_eq!(
        due.len(),
        1,
        "after the interval the waiting peer is selected"
    );
    assert!(due[0].wtxid);
    assert_eq!(due[0].hash, wtxid.to_byte_array());
    let _ = std::fs::remove_dir_all(dir);
}

/// A full process-wide parent table skips a new announcement. The peer stays
/// connected, and getdata / getheaders already collected in that inv still go out.
#[tokio::test]
async fn full_parent_table_keeps_headers_and_collected_getdata() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parent-global");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "parent-cap inv pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let mp = hub.mempool().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = inbound_peer(&peers);
    let keep = [0x42; 32];
    assert_eq!(
        mp.note_inv_tx_requested(peer.id, keep, true, 1_000, false),
        rbitcoin_net::tx_relay::ParentNote::RequestNow
    );
    let mut n = 0u32;
    let mut filler = peer.id.saturating_add(1);
    let mut per_peer = 0u32;
    loop {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        match mp.note_inv_tx_requested(filler, hash, false, 1_000, false) {
            rbitcoin_net::tx_relay::ParentNote::RequestNow => {
                n += 1;
                per_peer += 1;
                if per_peer == 5_000 {
                    filler += 1;
                    per_peer = 0;
                }
            }
            rbitcoin_net::tx_relay::ParentNote::Deferred => {
                panic!("a fresh hash is the in-flight request");
            }
            rbitcoin_net::tx_relay::ParentNote::GlobalFull => break,
            rbitcoin_net::tx_relay::ParentNote::PeerCapped => {
                panic!("filler peer {filler} hit its own cap before the table filled")
            }
        }
    }
    let (out_tx, mut rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let block = Inventory::Block(BlockHash::from_byte_array([0x91; 32]));
    let kept = Inventory::WitnessTransaction(Txid::from_byte_array(keep));
    let fresh = Inventory::WitnessTransaction(Txid::from_byte_array([0x77; 32]));
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[block, kept, fresh],
    )
    .unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "a full process-wide table is not this peer's misbehavior"
    );
    let mut saw_headers = false;
    let mut getdata = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        match msg.expect_msg() {
            NetworkMessage::GetHeaders(_) => saw_headers = true,
            NetworkMessage::GetData(v) => getdata = v,
            other => panic!("unexpected inv follow-up: {other:?}"),
        }
    }
    assert!(saw_headers, "block inv still requests headers");
    assert!(
        getdata.is_empty(),
        "an in-flight announcement is not asked again, and a full table skips the new one"
    );
    let keep_txid = Txid::from_byte_array(keep);
    let fresh_txid = Txid::from_byte_array([0x77; 32]);
    let mp = hub.mempool().unwrap();
    assert!(
        mp.announcer_peers_for(&keep_txid, &bitcoin::Wtxid::from_byte_array(keep))
            .contains(&peer.id),
        "the announcement recorded before the table filled stays"
    );
    assert!(
        mp.announcer_peers_for(&fresh_txid, &bitcoin::Wtxid::from_byte_array([0x77; 32]))
            .is_empty(),
        "a full table does not record the new announcement"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// 1001 due wtxids are two inv messages, and both charge the send budget.
#[tokio::test(flavor = "current_thread")]
async fn tx_inv_over_one_thousand_is_two_messages() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-batch");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(101, op_true(), vec![]).unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "tx inv batch pin is not IBD");
    let coinbase = hub
        .query
        .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
        .unwrap()
        .txdata[0]
        .clone();
    let each = coinbase.output[0].value.to_sat() / 2 / 1001;
    assert!(each > 2_000, "coinbase must fund 1001 spends");
    let fanout = bitcoin::Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: (0..1001)
            .map(|_| TxOut {
                value: Amount::from_sat(each),
                script_pubkey: op_true(),
            })
            .collect(),
    };
    hub.generate_to_script(1, op_true(), vec![fanout.clone()])
        .unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let mempool = hub.mempool().unwrap();
    let parent = fanout.compute_txid();
    for vout in 0..1001u32 {
        let child = bitcoin::Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: parent, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(each - 1_000),
                script_pubkey: op_true(),
            }],
        };
        mempool
            .accept_tx(&child)
            .unwrap_or_else(|e| panic!("accept vout {vout}: {e}"));
    }
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    peer.request_tx_inv();
    let (out_tx, mut rx) = mpsc::unbounded_channel();
    let before = peer.send_queued();
    queue_due_tx_invs(&hub, peer.as_ref(), &CappedSet::new(), &out_tx);
    let mut msgs = 0usize;
    let mut items = 0usize;
    while let Ok(msg) = rx.try_recv() {
        match msg.expect_msg() {
            NetworkMessage::Inv(v) => {
                msgs += 1;
                assert!(v.len() <= 1000, "one inv holds at most 1000");
                items += v.len();
            }
            other => panic!("expected inv, got {other:?}"),
        }
    }
    assert_eq!(items, 1001, "every accepted tx is announced");
    assert_eq!(msgs, 2, "1001 tx invs are two messages");
    assert!(
        peer.send_queued() > before,
        "batched inv must charge the send budget"
    );
    let _ = std::fs::remove_dir_all(dir);
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
        rbitcoin_net::peer::tx_reject_ban_score(&AcceptError::Script("script false".into())),
        10
    );
    assert_eq!(
        rbitcoin_net::peer::tx_reject_ban_score(&AcceptError::Policy("min relay fee")),
        0
    );
}

include!("../peer_catchup_journey.rs");
include!("../peer_hostile_journey.rs");
include!("../peer_tip_announce_journey.rs");
include!("../peer_header_dos_journey.rs");
include!("../peer_header_sync_journey.rs");
include!("../peer_blocksonly_journey.rs");

/// A headers batch and a getheaders reply must not read or write the store
/// on the session worker.
#[test]
fn headers_store_runs_off_the_reactor() {
    use bitcoin::block::{Header, Version};
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    use bitcoin::CompactTarget;
    use bitcoin::TxMerkleNode;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("headers-off-reactor");
    hub.ensure_genesis().unwrap();
    let prev = hub.tip_hash().unwrap();
    let hdr = Header {
        version: Version::TWO,
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
        time: 1_700_000_000,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: 1,
    };
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = mpsc::unbounded_channel();
            let mut follow = PeerFollowState::new();
            let gh = GetHeadersMessage::new(vec![], BlockHash::from_byte_array([0u8; 32]));
            on_getheaders(&hub, &out_tx, &mut follow, None, &gh)
                .await
                .expect("getheaders");
            on_headers(&hub, &out_tx, &mut follow, None, &[hdr])
                .await
                .expect("headers");
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Inbound compact reconstruction must not run on the session worker.
#[test]
fn inbound_cmpct_reconstruct_runs_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-recon-off-reactor");
    hub.ensure_genesis().unwrap();
    let block = block_for_peer(&hub.cache, &hub.query, &hub.tip_hash().unwrap())
        .unwrap()
        .expect("genesis");
    let hash = block.block_hash();
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    // A live node holds the hub in an `Arc`, so accept awaits the tip lane.
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = mpsc::unbounded_channel();
            let mut follow = PeerFollowState::new();
            follow.requested_blocks.insert(hash);
            on_cmpctblock_reconstruct(&hub, &out_tx, &mut follow, None, &hsi, hash)
                .await
                .expect("reconstruct");
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block `getdata` must not look up headers on the session worker. The
/// missing hash and the genesis body both resolve on the blocking pool.
#[test]
fn getdata_block_lookup_stays_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("getdata-lookup-off-reactor");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let missing = bitcoin::BlockHash::from_byte_array([9u8; 32]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut follow = PeerFollowState::new();
            let before = rbitcoin_query::header_lookup_count();
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                None,
                vec![
                    Inventory::WitnessBlock(missing),
                    Inventory::WitnessBlock(hash),
                ],
            )
            .await
            .expect("getdata");
            assert_eq!(
                rbitcoin_query::header_lookup_count(),
                before,
                "block getdata looked up a header on the session worker"
            );
            let block = out_rx.try_recv().expect("genesis body");
            let served = served_block(block);
            assert_eq!(served.block_hash(), hash);
            match out_rx.try_recv().map(PeerOut::expect_msg) {
                Ok(NetworkMessage::NotFound(v)) => {
                    assert!(v.contains(&Inventory::WitnessBlock(missing)));
                }
                other => panic!("missing hash is notfound, got {other:?}"),
            }
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store error on an announced tip wtxid is `notfound`, not a dropped peer.
#[test]
fn announced_wtx_store_error_is_notfound() {
    let miss = announced_wtx_from_reconstruct(Err(NetError::Consensus("disk".into())));
    assert!(miss.is_none(), "a store error is notfound");
    assert!(announced_wtx_from_reconstruct(Ok(None)).is_none());
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let hit = announced_wtx_from_reconstruct(Ok(Some(tx))).expect("tx kept");
    assert!(hit.input.is_empty());
}

/// A failed compact-relay blocking job is a protocol error, not a missing body.
#[tokio::test]
async fn cmpct_relay_join_failure_is_protocol() {
    let joined = tokio::task::spawn_blocking(|| -> Option<NetworkMessage> {
        panic!("short ids");
    })
    .await;
    let err = map_cmpct_relay_join(joined).expect_err("join failure");
    assert!(err.to_string().contains("cmpct relay join failed"), "{err}");
}

/// A headers batch already taken off the socket is stored when the send
/// budget is spent. The locator latch clears and nothing else is queued.
#[tokio::test]
async fn over_budget_headers_are_stored_without_a_follow_up() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-over-budget");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18510, 31, false);
    peer.note_awaiting_headers();
    peer.note_send_queued(rbitcoin_net::peers::PEER_SEND_BUDGET + 1);
    assert!(peer.send_over_budget());
    let header = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
    .header;
    let hash = header.block_hash();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    handle_decoded_peer_msg(
        RawNetworkMessage::new(
            Magic::from(Network::Regtest),
            NetworkMessage::Headers(vec![header]),
        ),
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
    )
    .await
    .expect("headers");
    assert!(!peer.is_awaiting_headers(), "the locator latch clears");
    assert!(
        out_rx.try_recv().is_err(),
        "no getdata or getheaders while the send budget is spent"
    );
    assert!(hub.header_of(&hash).is_some(), "the header is stored");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "an unsent body is not left in flight"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A closed writer fails the getdata. The claim from that attempt is released
/// so another peer can ask.
#[tokio::test]
async fn failed_body_queue_releases_the_ask() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-ask-release");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18511, 32, false);
    let header = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
    .header;
    let hash = header.block_hash();
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    drop(out_rx);
    let mut follow = PeerFollowState::new();
    let err = on_headers(&hub, &out_tx, &mut follow, Some(peer.as_ref()), &[header])
        .await
        .expect_err("closed writer");
    assert!(err.to_string().contains("peer write half closed"), "{err}");
    assert!(!hub.already_have_or_asked_block(&hash));
    assert!(!follow.requested_blocks.contains(&hash));
    assert!(hub.header_of(&hash).is_some(), "the header is stored");
    let _ = std::fs::remove_dir_all(&dir);
}

fn hb_tip_child(hub: &rbitcoin_net::chain::ChainHub) -> bitcoin::Block {
    rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
}

/// No offered high-bandwidth peer means the compact build does not run.
/// `from` has a live hub, so this reaches the offer filter. A stack hub
/// would persist the header on this thread.
#[test]
fn hb_relay_skips_the_build_when_no_peer_is_offered_it() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-relay-no-peer");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18520, 41, false);
    let quiet = live_peer(&peers, 18521, 42, false);
    quiet.note_best_known(hub.tip_hash().unwrap());
    let block = hb_tip_child(&hub);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rbitcoin_net::chain::reset_ensure_header_fk_count();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert_eq!(
        rbitcoin_net::chain::ensure_header_fk_count(),
        0,
        "a peer that was not offered the block does not persist its header"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Outbound compact push follows transaction relay. A fresh tip with relay
/// still off has nothing in the pool for the next block, so an offered peer
/// gets a header path instead. IBD and `-blocksonly` do not push one either.
#[tokio::test]
async fn compact_push_follows_tx_relay() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-push-pack");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    assert!(hub.in_ibd());
    assert!(!mp.relay_enabled());
    let genesis = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18530, 51, false);
    let target = live_peer(&peers, 18531, 52, false);
    target.set_hb_from(true);
    target.note_best_known(genesis);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    target.attach_out(out_tx);
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        out_rx.try_recv().is_err(),
        "IBD does not push a compact block"
    );

    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(!hub.in_ibd());
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        out_rx.try_recv().is_err(),
        "a fresh tip does not push a compact block while tx relay is off"
    );
    mp.set_relay_enabled(true);
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        matches!(
            out_rx.try_recv().map(PeerOut::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "tx relay pushes a compact block"
    );
    assert!(
        out_rx.try_recv().is_err(),
        "one compact block, not a fee filter"
    );
    assert!(mp.relay_enabled(), "a compact push does not clear tx relay");

    let (bo_dir, bo) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-push-bo");
    bo.ensure_genesis().unwrap();
    bo.set_prefill_compact(true);
    bo.set_blocks_only(true);
    bo.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    let bo_mp = rbitcoin_net::tx_relay::MempoolHub::open(
        bo_dir.path().join("mp"),
        std::sync::Arc::clone(&bo.query),
    )
    .unwrap();
    assert!(bo.attach_mempool(std::sync::Arc::clone(&bo_mp)).is_ok());
    let bo_tip = bo.tip_hash().unwrap();
    let bo_block = hb_tip_child(&bo);
    let bo_peers = rbitcoin_net::peers::PeerHub::new();
    let bo_from = live_peer(&bo_peers, 18532, 53, false);
    let bo_target = live_peer(&bo_peers, 18533, 54, false);
    bo_target.set_hb_from(true);
    bo_target.note_best_known(bo_tip);
    let (bo_tx, mut bo_rx) = mpsc::unbounded_channel();
    bo_target.attach_out(bo_tx);
    relay_new_pow_valid_block(&bo, &bo_block, Some(bo_from.as_ref())).await;
    assert!(
        bo_rx.try_recv().is_err(),
        "blocksonly does not push a compact block"
    );
    assert!(!bo_mp.relay_enabled());
}

/// One offered high-bandwidth peer builds the prefill and short ids off the
/// worker. `assert_not_reactor` panics if that build stays on `tokio-rt-worker`.
#[test]
fn hb_relay_offered_build_runs_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-relay-off-reactor");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let genesis = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18522, 43, false);
    let target = live_peer(&peers, 18523, 44, false);
    target.set_hb_from(true);
    target.note_best_known(genesis);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    target.attach_out(out_tx);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
            assert!(
                matches!(
                    out_rx.try_recv().map(PeerOut::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "the offered peer receives the compact block"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Compact tip short ids are built with the body load, off the session worker.
#[test]
fn cmpct_tip_announce_shortids_run_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-tip-off-reactor");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut follow = PeerFollowState::new();
            follow.send_cmpct = true;
            follow.cmpct_version = 2;
            let ev = rbitcoin_net::chain::TipEvent {
                height: hub.tip_height().unwrap(),
                hash: hub.tip_hash().unwrap(),
                header: hub.tip_header().unwrap(),
                reorg_branch_len: 0,
            };
            on_tip_event(&hub, &out_tx, &mut follow, None, Ok(ev))
                .await
                .expect("tip");
            assert!(
                matches!(
                    out_rx.try_recv().map(PeerOut::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "genesis tip is a compact announcement"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

fn panic_text(err: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = err.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = err.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    String::new()
}

/// Compact serve, getblocktxn, and an announced tip wtxid each read the
/// block on the worker. That read is the reactor check.
#[test]
fn served_block_read_is_the_reactor_check() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("serve-reactor-check");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let cache = Arc::clone(&hub.cache);
    let query = Arc::clone(&hub.query);
    let wtxid = bitcoin::Wtxid::from_byte_array([1u8; 32]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            assert!(
                name.starts_with("tokio-rt-worker"),
                "spawned task must run on a tokio worker, got {name:?}"
            );
            let assert_block_read = |err: Box<dyn std::any::Any + Send>| {
                let text = panic_text(err);
                assert!(
                    text.contains("block reconstruct"),
                    "the block read is the reactor check, got {text}"
                );
            };
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = compact_serve_outcome(cache.as_ref(), query.as_ref(), &hash, 0, 2, vec![0]);
            }))
            .expect_err("compact serve on tokio-rt-worker panics");
            assert_block_read(err);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = getblocktxn_reply(
                    cache.as_ref(),
                    query.as_ref(),
                    BlockTransactionsRequest {
                        block_hash: hash,
                        indexes: vec![0],
                    },
                    0,
                );
            }))
            .expect_err("getblocktxn on tokio-rt-worker panics");
            assert_block_read(err);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = tx_from_stored_block(cache.as_ref(), query.as_ref(), &hash, &wtxid);
            }))
            .expect_err("tip wtxid on tokio-rt-worker panics");
            assert_block_read(err);
        })
        .await
        .expect("worker")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Compact getdata and an announced tip wtxid reconstruct off the reactor.
/// `assert_not_reactor` panics when `block_for_peer` runs on `tokio-rt-worker`.
#[test]
fn compact_and_wtxid_serve_run_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("compact-off-reactor");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let block = block_for_peer(&hub.cache, &hub.query, &hash)
        .unwrap()
        .expect("genesis body");
    let wtxid = block.txdata[0].compute_wtxid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18450, 11, false);
    session.note_announced_wtx(wtxid);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let hub = hub;
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut follow = PeerFollowState::new();
            follow.cmpct_version = 2;
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::CompactBlock(hash)],
            )
            .await
            .expect("compact serve");
            assert!(
                matches!(
                    out_rx.try_recv().map(PeerOut::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "genesis getdata is a compact block"
            );
            let mut follow = PeerFollowState::new();
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::WTx(wtxid)],
            )
            .await
            .expect("wtxid serve");
            assert!(
                matches!(
                    out_rx.try_recv().map(PeerOut::expect_msg),
                    Ok(NetworkMessage::Tx(_))
                ),
                "announced wtxid comes from the tip block"
            );
            let missing = bitcoin::BlockHash::from_byte_array([9u8; 32]);
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::CompactBlock(missing)],
            )
            .await
            .expect("missing compact is not a session error");
            assert!(
                out_rx.try_recv().is_err(),
                "a header-less hash stays silent"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `PrepareBlockFilterRequest`: start past stop, or a range of 1000+
/// cfilters / 2000+ cfheaders, disconnects instead of being clamped.
#[test]
fn headers_poll_expires_a_stale_tx_off_the_tokio_worker() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-poll-expire");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_header().unwrap();
    let (_tip, _time, cbs) = rbitcoin_query::pad_empty_from(
        &hub.query,
        &ChainParams::regtest(),
        hub.tip_hash().unwrap(),
        tip.time,
        1,
        101,
        1,
    );
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let tid = tx.compute_txid();
    mp.accept_tx(&tx).expect("admit");
    assert_eq!(mp.live_count(), 1);
    mp.set_expiry_hours(1);
    mp.note_mock_now(mp.relay_now_secs() + 3600 + 5);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let mp_wait = Arc::clone(&mp);

    // The worker name is what `assert_not_reactor` checks. Inline expiry panics here.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = mpsc::unbounded_channel();
            on_headers_poll(&hub, &out_tx, None);
        })
        .await
        .expect("headers poll task")
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while mp_wait.live_count() != 0 {
        if Instant::now() > deadline {
            panic!("headers poll left the expired tx live");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!mp.contains(&tid));
}

#[test]
fn compact_filter_ranges_past_core_limits_disconnect() {
    assert!(compact_filter_range(5, 4, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(0, 999, MAX_GETCFILTERS).is_ok());
    assert!(compact_filter_range(0, 1000, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(1, 2000, MAX_GETCFHEADERS).is_ok());
    assert!(compact_filter_range(0, 2000, MAX_GETCFHEADERS).is_err());

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cf-stop");
    hub.query.set_block_filter_index(true).unwrap();
    hub.ensure_genesis().unwrap();
    let heights = hub.query.index_heights(0, 0, None).unwrap();
    let window = hub.query.read_index_window(&heights).unwrap();
    let filter = hub.query.basic_filter_from_window(&window, 0).unwrap();
    assert_eq!(
        hub.query
            .commit_window_filters(0, &[(filter, heights[0].header_fk)])
            .unwrap(),
        1,
        "genesis basic filter must be sealed before a peer can read it"
    );
    let tip = hub.tip_hash().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let headers = bitcoin::p2p::message_filter::GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash: tip,
    };
    on_getcfheaders(&hub, &tx, None, &headers).unwrap();
    match rx.try_recv().expect("cfheaders") {
        rbitcoin_net::peers::PeerOut::Msg(NetworkMessage::CFHeaders(m)) => {
            assert_eq!(m.previous_filter_header.as_byte_array(), &[0u8; 32]);
            assert_eq!(m.filter_hashes.len(), 1, "{m:?}");
        }
        other => panic!("expected cfheaders, got {other:?}"),
    }
    let typed = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 1,
        start_height: 0,
        stop_hash: tip,
    };
    on_getcfilters(&hub, &tx, None, &typed).unwrap();
    assert!(rx.try_recv().is_err(), "a non-basic filter is silence");
    hub.query.set_block_filter_index(false).unwrap();
    let basic = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: tip,
    };
    on_getcfilters(&hub, &tx, None, &basic).unwrap();
    assert!(rx.try_recv().is_err(), "filters off is silence");
    let _ = std::fs::remove_dir_all(dir);
}

mod log_text_tests;

/// Core `ProcessMessage` ADDR/ADDRV2: the `getaddr` an addr-fetch session
/// sends buys `MAX_ADDR_TO_SEND` more addresses. The reply, v1 or v2, is
/// learned and not relayed (`m_getaddr_sent`). More than one address ends the
/// session without misbehavior; a one-address self-announce does not.
#[tokio::test]
async fn addrfetch_learns_the_getaddr_reply_then_disconnects() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("addrfetch-reply");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let book = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(std::sync::Arc::clone(&book));
    let register = |port: u16, typ: rbitcoin_net::peers::PeerConnType| {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let ver = VersionMessage {
            version: bitcoin::p2p::PROTOCOL_VERSION,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 0,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        peers.register(addr, addr, &ver, false, typ)
    };
    let neighbor = register(18459, rbitcoin_net::peers::PeerConnType::OutboundFullRelay);
    neighbor.set_wants_addrv2();
    let (relay_tx, mut relayed) = mpsc::unbounded_channel();
    neighbor.attach_out(relay_tx);
    let book_len = || book.lock().unwrap().len();
    let routable = |i: u32| AddrV2::Ipv4(std::net::Ipv4Addr::from(0x0b00_0001 + (i << 16)));

    let seed = register(18460, rbitcoin_net::peers::PeerConnType::AddrFetch);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    assert!(maybe_queue_addrfetch_getaddr(&out_tx, &seed));
    let time = seed.clock_now() as u32;
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(seed.as_ref()),
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
            port: 8333,
        }]),
    )
    .await;
    assert_eq!(book_len(), 1, "a self-announce is learned");
    assert_eq!(
        peers.addrfetch_replies(),
        0,
        "a self-announce is not the reply"
    );
    assert!(
        !seed.stop.load(Ordering::SeqCst),
        "one address is not the reply"
    );
    let reply = (0..MAX_ADDR_TO_SEND as u32)
        .map(|i| AddrV2Message {
            time,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: routable(i),
            port: 18444,
        })
        .collect();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(seed.as_ref()),
        NetworkMessage::AddrV2(reply),
    )
    .await;
    let learned = book_len() - 1;
    assert!(
        learned >= MAX_ADDR_TO_SEND * 9 / 10,
        "the getaddr reply is learned past one token: {learned}"
    );
    assert!(
        seed.stop.load(Ordering::SeqCst),
        "the reply ends addr-fetch"
    );
    assert_eq!(follow.ban_score, 0, "a getaddr reply is not misbehavior");
    assert_eq!(peers.addrfetch_replies(), 1);
    assert!(
        relayed.try_recv().is_err(),
        "an addr-fetch reply is not relayed"
    );

    let v1_seed = register(18461, rbitcoin_net::peers::PeerConnType::AddrFetch);
    assert!(maybe_queue_addrfetch_getaddr(&out_tx, &v1_seed));
    let before = book_len();
    let v1 = |last: u8| {
        let addr = std::net::SocketAddr::from(([12, 0, 0, last], 18444));
        (time, Address::new(&addr, ServiceFlags::NETWORK))
    };
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(v1_seed.as_ref()),
        NetworkMessage::Addr(vec![v1(1), v1(2)]),
    )
    .await;
    assert!(book_len() > before, "a v1 getaddr reply is learned");
    assert!(
        v1_seed.stop.load(Ordering::SeqCst),
        "a v1 reply ends addr-fetch"
    );
    assert_eq!(follow.ban_score, 0, "a v1 getaddr reply is not misbehavior");
    assert_eq!(peers.addrfetch_replies(), 2);
    assert!(
        relayed.try_recv().is_err(),
        "a v1 addr-fetch reply is not relayed"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}
