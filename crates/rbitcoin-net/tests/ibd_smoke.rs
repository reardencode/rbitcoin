//! Short regtest IBD smoke: seed node with a few blocks, peer catch-up via
//! [`P2PNode::sync`]. Hits the main IBD loop, archive pipeline, confirm engine,
//! peer_io, and dial/events paths without live datadirs.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
    Witness,
};
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::{IbdConfig, P2PNode};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn tmp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-ibd-smoke-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        rbitcoin_consensus::bip34_height_script(height)
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

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut block = Block {
        header,
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
}

async fn start_node(dir: &std::path::Path) -> P2PNode {
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
    )
    .await
    .expect("listen")
}

fn seed_chain(node: &P2PNode, blocks: u32) {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    node.ingest_block(0, genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=blocks {
        let b = mine(tip, time + 600, h);
        tip = b.block_hash();
        time = b.header.time;
        node.ingest_block(h, b).unwrap();
    }
}

/// Two-node IBD: seed has 6 blocks; peer syncs tip via public sync API.
///
/// Ignored in default suite: full confirm pipeline under parallel load can stall
/// on plan claim (multi-minute hang). Covered by `integration_multinode` two-node
/// when run in isolation / `scripts/integration.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full IBD smoke; run via scripts/integration.sh or -- --ignored"]
async fn short_regtest_ibd_two_node() {
    let seed_dir = tmp_dir("seed");
    let peer_dir = tmp_dir("peer");

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 6);
    assert_eq!(seed.query.tip_height(), Some(Height(6)));

    let peer = start_node(&peer_dir).await;
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    cfg.window = 16;
    let n = peer.sync(&[seed.local_addr], cfg).await.expect("ibd sync");
    assert!(n >= 6, "accepted={n}");
    peer.wait_height(6, Duration::from_secs(15))
        .await
        .expect("tip height");
    assert_eq!(peer.query.tip_height(), Some(Height(6)));
    assert_eq!(peer.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());

    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// Cancel flag exits IBD cooperatively without hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_cancellable_exits_when_flag_set() {
    let seed_dir = tmp_dir("seed-cancel");
    let peer_dir = tmp_dir("peer-cancel");

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 4);

    let peer = start_node(&peer_dir).await;
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_c = cancel.clone();
    // Flip cancel after a short delay so dial/handshake may start.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel_c.store(true, Ordering::SeqCst);
    });
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    // Cancelled IBD should return Ok (partial) or complete if race finishes first.
    let _ = peer
        .sync_cancellable(&[seed.local_addr], cfg, Some(cancel))
        .await;

    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// `follow_from` must return after handshake (node `--connect` uses an 8s
/// timeout around it). The session stays live, and the post-verack keepalive
/// is the tracked ping — a second ping 50ms later makes the first pong look
/// like a nonce mismatch on real RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_from_returns_live_with_one_keepalive_ping() {
    let seed_dir = tmp_dir("follow-seed");
    let peer_dir = tmp_dir("follow-peer");

    let seed = start_node(&seed_dir).await;
    let mut peer = start_node(&peer_dir).await;

    tokio::time::timeout(Duration::from_secs(5), peer.follow_from(seed.local_addr))
        .await
        .expect("follow_from must return after handshake, not run the session")
        .expect("follow handshake");
    assert!(
        peer.follow_live_count() >= 1,
        "outbound session must stay live after follow_from returns"
    );

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        peer.follow_live_count() >= 1,
        "session must still be live after the 50ms ping tick"
    );

    let inbound = seed
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.inbound)
        .expect("seed inbound session");
    let ping = inbound.bytesrecv_per_msg.get("ping").copied().unwrap_or(0);
    assert_eq!(
        ping, 32,
        "one 8-byte ping (acct +24), not a second interval ping on top: {ping}"
    );
    let outbound = peer
        .peers
        .snapshot()
        .into_iter()
        .find(|p| !p.inbound)
        .expect("outbound session");
    let pong = outbound.bytesrecv_per_msg.get("pong").copied().unwrap_or(0);
    assert!(pong >= 29, "connect_nodes pong bytes {pong}");
    assert!(
        outbound.pingwait.is_none(),
        "first pong must match the outstanding nonce (pingwait={:?})",
        outbound.pingwait
    );

    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// Empty peer list is a clean protocol error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_no_peers_errors() {
    let dir = tmp_dir("empty");
    let node = start_node(&dir).await;
    let err = node.sync(&[], IbdConfig::for_test()).await.unwrap_err();
    assert!(err.to_string().contains("no peers") || err.to_string().contains("protocol"));
    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unreachable peer → dial fail / no peers connected (main-loop error arm).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_unreachable_peer_errors() {
    let dir = tmp_dir("unreachable");
    let node = start_node(&dir).await;
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    cfg.connect_timeout = Duration::from_millis(150);
    // TEST-NET-1 documentation address — closed / non-listening.
    let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let err = node.sync(&[dead], cfg).await.unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("no peers") || s.contains("protocol") || s.contains("connect"),
        "unexpected: {s}"
    );
    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Longer short chain (12 blocks) exercises multi-batch archive + confirm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full IBD smoke 12-block; run via scripts/integration.sh or -- --ignored"]
async fn short_regtest_ibd_twelve_blocks() {
    let seed_dir = tmp_dir("seed12");
    let peer_dir = tmp_dir("peer12");

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 12);
    assert_eq!(seed.query.tip_height(), Some(Height(12)));

    let peer = start_node(&peer_dir).await;
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    cfg.window = 32;
    let n = peer
        .sync(&[seed.local_addr], cfg)
        .await
        .expect("ibd sync 12");
    assert!(n >= 12, "accepted={n}");
    peer.wait_height(12, Duration::from_secs(30))
        .await
        .expect("tip 12");
    assert_eq!(peer.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());

    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}
