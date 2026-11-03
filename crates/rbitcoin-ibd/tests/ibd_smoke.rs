//! Short regtest IBD smoke: seed node with a few blocks, peer catch-up via
//! [`P2PNode::sync`]. Hits the main IBD loop, archive pipeline, confirm engine,
//! peer_io, and dial/events paths without live datadirs.
use rbitcoin_ibd::ibd::IbdConfig;
use rbitcoin_net::service::P2PNode;

use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash};
use rbitcoin_consensus::{ChainParams, Milestone};

use rbitcoin_query::Query;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn tmp_dir(label: &str) -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled(label).unwrap()
}

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    rbitcoin_consensus::mine_empty_regtest(prev, time, height)
}

async fn start_node(dir: &std::path::Path) -> P2PNode {
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("listen")
}

fn seed_chain(node: &P2PNode, blocks: u32) {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    node.ingest_block(genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=blocks {
        let b = mine(tip, time + 600, h);
        tip = b.block_hash();
        time = b.header.time;
        node.ingest_block(b).unwrap();
    }
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
    let _ = rbitcoin_ibd::sync_cancellable(
        &peer,
        &[rbitcoin_net::NetAddr::Ip(seed.local_addr)],
        cfg,
        Some(cancel),
    )
    .await;

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
    let err = rbitcoin_ibd::sync(&node, &[], IbdConfig::for_test())
        .await
        .unwrap_err();
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
    let err = rbitcoin_ibd::sync(&node, &[rbitcoin_net::NetAddr::Ip(dead)], cfg)
        .await
        .unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("no peers") || s.contains("protocol") || s.contains("connect"),
        "unexpected: {s}"
    );
    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `Peerless::Redial` the last initial wave is not the end of
/// catch-up: it waits, sweeps the book again, and reaches the seed that the
/// same one-wave `GiveUp` config never dials. With only dead addresses it
/// keeps sweeping until cancelled, then stops without an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_redial_keeps_dialing_until_a_peer_or_cancel() {
    let seed_dir = tmp_dir("seed-redial");
    let peer_dir = tmp_dir("peer-redial");
    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 2);
    let peer = start_node(&peer_dir).await;
    let dead: Vec<rbitcoin_net::NetAddr> = ["127.0.0.1:1", "127.0.0.1:2"]
        .iter()
        .map(|a| rbitcoin_net::NetAddr::Ip(a.parse().unwrap()))
        .collect();
    let redial_cfg = |book: rbitcoin_net::AddrMan| {
        let mut cfg = IbdConfig::for_test();
        cfg.target_peers = 1;
        cfg.connect_timeout = Duration::from_millis(300);
        cfg.initial_dial_waves = 1;
        cfg.peerless = rbitcoin_ibd::Peerless::Redial {
            cap: Duration::from_millis(100),
        };
        cfg.peers = Some(Arc::new(std::sync::Mutex::new(book)));
        cfg
    };
    let mut book = rbitcoin_net::AddrMan::new();
    for a in &dead {
        book.add_addr(*a);
    }
    book.add_addr(rbitcoin_net::NetAddr::Ip(seed.local_addr));
    let synced = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync(&peer, &dead, redial_cfg(book)),
    )
    .await
    .expect("catch-up finishes");
    assert!(
        synced.is_ok(),
        "the next sweep reaches the seed: {synced:?}"
    );
    assert_eq!(peer.tip_height(), Some(2));

    let dark_dir = tmp_dir("peer-redial-dark");
    let dark = start_node(&dark_dir).await;
    let mut book = rbitcoin_net::AddrMan::new();
    for a in &dead {
        book.add_addr(*a);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&cancel);
    let clock = Arc::clone(&dark.hub.clock);
    tokio::spawn(async move {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while clock.connection_attempt_at() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "redial never issued a dial"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.store(true, Ordering::SeqCst);
    });
    let stopped = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync_cancellable(&dark, &dead, redial_cfg(book), Some(cancel)),
    )
    .await
    .expect("cancel ends a dark catch-up");
    assert_ne!(
        dark.hub.clock.connection_attempt_at(),
        0,
        "dead addresses alone do not end catch-up before a dial"
    );
    assert_eq!(stopped.ok(), Some(0));
    assert_eq!(dark.tip_height(), Some(0));
    dark.shutdown().await;
    let _ = std::fs::remove_dir_all(&dark_dir);
    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

fn logs_from_sync() -> impl Fn() -> Vec<String> {
    rbitcoin_log::capture_logs(true);
    || {
        rbitcoin_log::take_logs()
            .into_iter()
            .map(|(_, line)| line)
            .collect()
    }
}

/// One live seed and a higher target reaches the redial clock. An empty body
/// queue must not claim it noted rows, and a store with no Class A bodies must
/// not announce a seed count of zero.
#[tokio::test(flavor = "current_thread")]
async fn ibd_redials_immediately_and_does_not_invent_a_rehydrate() {
    let seed_dir = tmp_dir("seed-redial");
    let peer_dir = tmp_dir("peer-redial");
    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 2);
    let peer = start_node(&peer_dir).await;
    peer.hub.ensure_genesis().unwrap();
    let archived = peer.hub.query.archived_block_count().unwrap();
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 2;
    let take = logs_from_sync();
    // This chain is two blocks, so catch-up exits on its own.
    let finished = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync_cancellable(
            &peer,
            &[rbitcoin_net::NetAddr::Ip(seed.local_addr)],
            cfg,
            None,
        ),
    )
    .await;
    let logs = take();
    rbitcoin_log::capture_logs(false);
    assert!(finished.is_ok(), "short-chain ibd did not finish: {logs:?}");
    assert!(
        logs.iter().any(|line| line.contains("ibd: redialing")),
        "a short peer set redials on the first loop: {logs:?}"
    );
    assert!(
        logs.iter().all(|line| !line.contains("noted 0")),
        "an empty body queue is not reported as noted: {logs:?}"
    );
    let seed_line = format!("store has {archived} Class A bodies (seed)");
    if archived > 0 {
        assert!(
            logs.iter().any(|line| line.contains(&seed_line)),
            "Class A bodies already in the store are named: {logs:?}"
        );
    } else {
        assert!(
            logs.iter()
                .all(|line| !line.contains("Class A bodies (seed)")),
            "an empty store does not announce a Class A seed: {logs:?}"
        );
    }
    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// A block left in the RAM body queue above the tip is noted into confirm.
#[tokio::test(flavor = "current_thread")]
async fn ibd_notes_a_body_queue_row_above_the_tip() {
    let seed_dir = tmp_dir("seed-bq");
    let peer_dir = tmp_dir("peer-bq");
    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 1);
    let peer = start_node(&peer_dir).await;
    peer.hub.ensure_genesis().unwrap();
    let gen = peer.hub.tip_hash().unwrap();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let block = mine(gen, genesis.header.time + 600, 1);
    let fk = peer.hub.ensure_header_fk(&block.header).unwrap();
    let raw = bitcoin::consensus::encode::serialize(&block);
    peer.hub
        .query
        .block_queue_enqueue(1, block.block_hash().to_byte_array(), fk.0, &raw)
        .unwrap();
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    let take = logs_from_sync();
    let finished = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync_cancellable(
            &peer,
            &[rbitcoin_net::NetAddr::Ip(seed.local_addr)],
            cfg,
            None,
        ),
    )
    .await;
    let logs = take();
    rbitcoin_log::capture_logs(false);
    assert!(finished.is_ok(), "short-chain ibd did not finish: {logs:?}");
    assert!(
        logs.iter()
            .any(|line| line.contains("ibd: rehydrate: noted 1 in-RAM body queue entries")),
        "the queued block is noted: {logs:?}"
    );
    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// A first dial wave that reaches no one is not the end of catch-up while the
/// book still has untried addresses (Core keeps opening connections). With
/// `initial_dial_waves = 1`, as the stale-tip retry runs, it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_dials_a_second_wave_when_the_first_reaches_no_one() {
    let seed_dir = tmp_dir("seed-wave");
    let peer_dir = tmp_dir("peer-wave");
    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 2);
    let peer = start_node(&peer_dir).await;
    let dead: Vec<rbitcoin_net::NetAddr> = ["127.0.0.1:1", "127.0.0.1:2"]
        .iter()
        .map(|a| rbitcoin_net::NetAddr::Ip(a.parse().unwrap()))
        .collect();
    let mut book = rbitcoin_net::AddrMan::new();
    for a in &dead {
        book.add_addr(*a);
    }
    book.add_addr(rbitcoin_net::NetAddr::Ip(seed.local_addr));
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    cfg.connect_timeout = Duration::from_millis(300);
    cfg.peers = Some(Arc::new(std::sync::Mutex::new(book)));
    let synced = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync(&peer, &dead, cfg),
    )
    .await
    .expect("catch-up finishes");
    assert!(
        synced.is_ok(),
        "the second wave reaches the seed: {synced:?}"
    );
    assert_eq!(peer.tip_height(), Some(2));

    let fresh_dir = tmp_dir("peer-wave-cap");
    let fresh = start_node(&fresh_dir).await;
    let mut book = rbitcoin_net::AddrMan::new();
    for a in &dead {
        book.add_addr(*a);
    }
    book.add_addr(rbitcoin_net::NetAddr::Ip(seed.local_addr));
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    cfg.connect_timeout = Duration::from_millis(300);
    cfg.initial_dial_waves = 1;
    cfg.peers = Some(Arc::new(std::sync::Mutex::new(book)));
    let capped = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync(&fresh, &dead, cfg),
    )
    .await
    .expect("a capped catch-up returns");
    assert!(
        capped.is_err(),
        "one wave stops before the seed: {capped:?}"
    );
    assert_eq!(fresh.tip_height(), Some(0));
    fresh.shutdown().await;
    let _ = std::fs::remove_dir_all(&fresh_dir);
    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}

/// The coordinator task does no header lookup and no store read while it holds
/// `shared`, across a seeded header batch and the getdata that connects it.
/// The header thread still reads the store on its own.
#[tokio::test(flavor = "current_thread")]
async fn coord_shared_lock_skips_header_and_store_io() {
    let seed_dir = tmp_dir("seed-coord-lock");
    let peer_dir = tmp_dir("peer-coord-lock");
    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 2);
    let peer = start_node(&peer_dir).await;
    peer.hub.ensure_genesis().unwrap();
    let unrelated = mine(peer.hub.tip_hash().unwrap(), 1_300_123_456, 1).header;
    peer.hub.ensure_header(&unrelated).unwrap();
    peer.hub.note_invalid_block(unrelated.block_hash());
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 1;
    let finished = tokio::time::timeout(
        Duration::from_secs(20),
        rbitcoin_ibd::sync_cancellable(
            &peer,
            &[rbitcoin_net::NetAddr::Ip(seed.local_addr)],
            cfg,
            None,
        ),
    )
    .await;
    assert!(finished.is_ok(), "seeded catch-up did not finish");
    let synced = finished.expect("timeout").expect("sync");
    assert!(synced >= 2, "getdata drain accepted {synced}");
    assert_eq!(peer.tip_height(), Some(2));
    assert_eq!(peer.hub.best_header_height(), 2);
    assert_eq!(
        rbitcoin_query::header_lookups_under_coord_lock(),
        0,
        "header lookups while shared was held"
    );
    assert_eq!(
        rbitcoin_store::coord_lock_store_reads(),
        0,
        "store reads while shared was held"
    );
    assert!(
        rbitcoin_store::header_thread_store_reads() > 0,
        "header thread still reads the store"
    );
    seed.shutdown().await;
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&peer_dir);
}
