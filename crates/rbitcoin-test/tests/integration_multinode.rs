//! Multi-node P2P integration tests.
//!
//! **Tier A (default + CI `multinode` job):** single-hop IBD (8 blocks), cold
//! reconstruct serve (10 blocks). Hard wall timeouts; hang-free on CI-class hosts.
//! **Tier B (default suite):** handshake timeout / GetAddr / keepalive ping,
//! hub reorg (including leftover/BadPrev orphan that must not blacklist).
//! **Tier C (`#[ignore]`):** multi-hop, tip-follow, 48-block dual seeder, mesh —
//! `scripts/integration.sh` or `-- --ignored` only.

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::{IbdConfig, P2PNode};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};
use rbitcoin_test::TempDir;
use std::net::SocketAddr;
use std::time::Duration;

async fn start_node(dir: &TempDir) -> P2PNode {
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
    )
    .await
    .expect("listen")
}

async fn seed_chain(node: &P2PNode, blocks: u32) {
    let genesis = regtest_genesis();
    node.ingest_block(0, genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=blocks {
        let b = mine_regtest_block(tip, time + 600, h, vec![]);
        tip = b.block_hash();
        time = b.header.time;
        node.ingest_block(h, b).unwrap();
    }
}

/// IBD from a single peer (test helper).
async fn sync_ibd(node: &P2PNode, peer: SocketAddr) -> u32 {
    node.sync(&[peer], IbdConfig::for_test())
        .await
        .expect("ibd sync")
}

/// Two nodes, seed has 8 blocks, peer syncs tip (tier A — default + CI multinode).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_header_and_block_sync() {
    let fut = async {
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 8).await;
        assert_eq!(seed.cache.tip_height(), Some(8));
        assert_eq!(seed.query.tip_height(), Some(Height(8)));

        let peer = start_node(&peer_dir).await;
        let n = sync_ibd(&peer, seed.local_addr).await;
        assert!(n >= 8, "downloaded {n}");
        peer.wait_height(8, Duration::from_secs(5))
            .await
            .expect("tip");

        // IBD confirm writes Class C tip; RAM BlockCache may stay cold.
        assert_eq!(peer.query.tip_height(), Some(Height(8)));
        assert_eq!(peer.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());

        seed.shutdown().await;
        peer.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(60), fut)
        .await
        .expect("two_node_header_and_block_sync wall timeout (60s)");
}

/// In-tree P2P client (no Core functional): peertimeout of a v1-magic inbound,
/// AddrFetch GetAddr, and one post-verack keepalive ping/pong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_timeout_getaddr_and_keepalive_ping() {
    use rbitcoin_net::{AddrMan, PeerConnType};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    let fut = async {
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();
        let seed = start_node(&seed_dir).await;
        seed.peers.set_peer_timeout_secs(1);

        let mut book = AddrMan::new();
        book.add(std::net::SocketAddr::from(([1, 2, 3, 4], 8333)));
        seed.peers.set_addrman(Arc::new(Mutex::new(book)));

        let mut peer = start_node(&peer_dir).await;
        tokio::time::timeout(Duration::from_secs(5), peer.follow_from(seed.local_addr))
            .await
            .expect("follow_from must return after handshake")
            .expect("follow handshake");
        assert!(
            peer.follow_live_count() >= 1,
            "outbound session must stay live after follow_from"
        );

        tokio::time::sleep(Duration::from_millis(250)).await;
        let inbound = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound && !p.subver.is_empty())
            .expect("seed inbound after handshake");
        let ping = inbound.bytesrecv_per_msg.get("ping").copied().unwrap_or(0);
        assert_eq!(
            ping, 32,
            "one 8-byte ping (acct +24), not a second interval ping: {ping}"
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

        let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest).to_bytes();
        let mut raw = tokio::net::TcpStream::connect(seed.local_addr)
            .await
            .expect("tcp to seed");
        raw.write_all(&magic).await.expect("write v1 magic");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut saw_connecting = false;
        loop {
            let connecting = seed
                .peers
                .snapshot()
                .into_iter()
                .filter(|p| p.inbound && p.subver.is_empty())
                .count();
            if connecting >= 1 {
                saw_connecting = true;
            }
            if saw_connecting && connecting == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "v1-magic inbound must register then drop at peertimeout=1s \
                     (saw_connecting={saw_connecting} still={connecting})"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(raw);

        for id in peer
            .peers
            .snapshot()
            .into_iter()
            .filter(|p| !p.inbound)
            .map(|p| p.id)
        {
            peer.peers.disconnect_id(id);
        }
        let drop_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let follow_in = seed
                .peers
                .snapshot()
                .into_iter()
                .any(|p| p.inbound && !p.subver.is_empty());
            if !follow_in {
                break;
            }
            if tokio::time::Instant::now() >= drop_deadline {
                panic!("follow inbound must drop before AddrFetch");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        peer.peers
            .addconnection(seed.local_addr, PeerConnType::AddrFetch)
            .expect("addrfetch dial");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let seed_got_getaddr = seed
                .peers
                .snapshot()
                .into_iter()
                .any(|p| p.bytesrecv_per_msg.get("getaddr").copied().unwrap_or(0) > 0);
            let fetch_got_addr = peer.peers.snapshot().into_iter().any(|p| {
                p.conn_type == PeerConnType::AddrFetch
                    && (p.bytesrecv_per_msg.get("addrv2").copied().unwrap_or(0) > 0
                        || p.bytesrecv_per_msg.get("addr").copied().unwrap_or(0) > 0)
            });
            if seed_got_getaddr && fetch_got_addr {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "AddrFetch must GetAddr and receive addr/addrv2 \
                     (seed_getaddr={seed_got_getaddr})"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for id in peer
            .peers
            .snapshot()
            .into_iter()
            .filter(|p| p.conn_type == PeerConnType::AddrFetch)
            .map(|p| p.id)
        {
            peer.peers.disconnect_id(id);
        }

        seed.shutdown().await;
        peer.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("p2p_timeout_getaddr_and_keepalive_ping wall timeout (20s)");
}

/// Phase 4: seeder restarts with empty RAM cache; peer IBD-syncs via reconstruct
/// (CI **multinode** job only — `coverage.sh` also skips this name).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multinode job"]
async fn serve_after_restart_via_reconstruct() {
    let fut = async {
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 10).await;
        let tip_hash = seed.cache.tip_hash().unwrap();
        seed.shutdown().await;

        // Restart seeder on same store — cache is empty; serve must use reconstruct.
        let seed = start_node(&seed_dir).await;
        assert!(
            seed.cache.is_empty(),
            "restarted seeder must not rely on warm RAM cache"
        );
        assert_eq!(seed.query.tip_height(), Some(Height(10)));

        let peer = start_node(&peer_dir).await;
        let n = sync_ibd(&peer, seed.local_addr).await;
        assert!(n >= 10, "downloaded {n}");
        peer.wait_height(10, Duration::from_secs(10))
            .await
            .expect("tip");

        assert_eq!(peer.query.tip_height(), Some(Height(10)));
        let peer_tip = peer
            .query
            .header_at_height(Height(10))
            .unwrap()
            .unwrap()
            .1
            .hash;
        assert_eq!(peer_tip, tip_hash.to_byte_array());

        // Peer can reconstruct every height from its own store.
        for h in 0..=10u32 {
            let b = peer
                .query
                .reconstruct_block_at_height(Height(h))
                .expect("peer reconstruct");
            assert_eq!(
                b.header.block_hash().to_byte_array(),
                peer.query
                    .header_at_height(Height(h))
                    .unwrap()
                    .unwrap()
                    .1
                    .hash
            );
        }

        seed.shutdown().await;
        peer.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(90), fut)
        .await
        .expect("serve_after_restart_via_reconstruct wall timeout (90s)");
}

/// Multi-hop serve after sync (mid → leaf). Ignored: longer wall + parallel IBD flakiness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multi-hop P2P; run via scripts/integration.sh"]
async fn three_node_relay_path() {
    let d0 = TempDir::new().unwrap();
    let d1 = TempDir::new().unwrap();
    let d2 = TempDir::new().unwrap();

    let seed = start_node(&d0).await;
    seed_chain(&seed, 5).await;

    let mid = start_node(&d1).await;
    sync_ibd(&mid, seed.local_addr).await;
    mid.wait_height(5, Duration::from_secs(5)).await.unwrap();

    let leaf = start_node(&d2).await;
    // Sync from mid (not original seed) — exercises serve after sync.
    sync_ibd(&leaf, mid.local_addr).await;
    leaf.wait_height(5, Duration::from_secs(5)).await.unwrap();

    assert_eq!(leaf.hub.tip_hash(), seed.hub.tip_hash());
    assert_eq!(leaf.query.tip_height(), Some(Height(5)));

    seed.shutdown().await;
    mid.shutdown().await;
    leaf.shutdown().await;
}

/// IBD with two seeder peers (48-block seed). Ignored: multi-minute under load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "dual-seeder 48-block IBD; run via scripts/integration.sh"]
async fn ibd_two_peers() {
    let seed_dir = TempDir::new().unwrap();
    let mid_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 48).await;

    // Second server: hop-sync then both serve the client.
    let mid = start_node(&mid_dir).await;
    sync_ibd(&mid, seed.local_addr).await;
    mid.wait_height(48, Duration::from_secs(15)).await.unwrap();

    let client = start_node(&peer_dir).await;
    let n = client
        .sync(&[seed.local_addr, mid.local_addr], IbdConfig::for_test())
        .await
        .expect("ibd");
    assert!(n >= 40, "accepted {n}");
    client
        .wait_height(48, Duration::from_secs(15))
        .await
        .expect("tip");
    assert_eq!(client.query.tip_height(), Some(Height(48)));
    assert_eq!(client.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());

    seed.shutdown().await;
    mid.shutdown().await;
    client.shutdown().await;
}

/// Multi-peer IBD: dead address + live seeder (dial book tries both).
/// Slim (4 blocks) — required **multinode** job (`coverage.sh` also skips).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multinode job"]
async fn ibd_skips_dead_peer() {
    let seed_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 4).await;

    let peer = start_node(&peer_dir).await;
    let bad: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let n = peer
        .sync(&[bad, seed.local_addr], IbdConfig::for_test())
        .await
        .expect("ibd with bad+good");
    assert!(n >= 4, "downloaded {n}");
    peer.wait_height(4, Duration::from_secs(5)).await.unwrap();

    seed.shutdown().await;
    peer.shutdown().await;
}

/// Phase 5: after IBD, seed announces a new tip; follower picks it up via inv/headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "tip-follow after IBD; run via scripts/integration.sh"]
async fn tip_follow_after_ibd() {
    let seed_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 5).await;

    let mut peer = start_node(&peer_dir).await;
    // Catch-up via IBD, then long-lived follow for tip announce.
    sync_ibd(&peer, seed.local_addr).await;
    peer.wait_height(5, Duration::from_secs(10))
        .await
        .expect("ibd");
    peer.follow_from(seed.local_addr).await.expect("follow");
    assert!(
        peer.follow_live_count() >= 1,
        "outbound follow session should be live"
    );

    // Seed mines block 6 — inbound peer_session should announce to follower.
    let tip = seed.cache.tip_hash().unwrap();
    let tip_time = seed
        .query
        .header_at_height(Height(5))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let b6 = mine_regtest_block(tip, tip_time + 600, 6, vec![]);
    let h6 = b6.block_hash();
    seed.ingest_block(6, b6).unwrap();

    peer.wait_tip_hash(h6, Duration::from_secs(10))
        .await
        .expect("tip follow");
    assert_eq!(peer.query.tip_height(), Some(Height(6)));

    seed.shutdown().await;
    peer.shutdown().await;
}

/// Regression: blocks mined while disconnected are pulled via post-connect
/// `getheaders` (not only unsolicited inv/headers announces).
///
/// Models post-IBD SH materialize gap: follow peers connect after tip advanced
/// on the network; without getheaders the follower would stall forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "getheaders gap fill; run via scripts/integration.sh"]
async fn tip_follow_getheaders_catches_missed_blocks() {
    let seed_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 5).await;

    let mut peer = start_node(&peer_dir).await;
    sync_ibd(&peer, seed.local_addr).await;
    peer.wait_height(5, Duration::from_secs(10))
        .await
        .expect("ibd");

    // Peer is NOT following yet — mine several tips on the seed only.
    let mut tip = seed.hub.tip_hash().unwrap();
    let mut tip_time = seed
        .query
        .header_at_height(Height(5))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let mut last = tip;
    for h in 6..=9 {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        tip = b.block_hash();
        tip_time = b.header.time;
        last = tip;
        seed.ingest_block(h, b).unwrap();
    }
    assert_eq!(peer.query.tip_height(), Some(Height(5)));
    assert_eq!(seed.query.tip_height(), Some(Height(9)));

    // Connect follow — session must getheaders + getdata the gap.
    peer.follow_from(seed.local_addr).await.expect("follow");
    peer.wait_tip_hash(last, Duration::from_secs(15))
        .await
        .expect("getheaders gap fill");
    assert_eq!(peer.query.tip_height(), Some(Height(9)));
    assert_eq!(peer.follow_live_count(), 1);

    seed.shutdown().await;
    peer.shutdown().await;
}

/// IBD to seeder tip → long-lived follow → new tip via announce, and
/// a third peer can download history from the client (block relay / serve).
///
/// Guards the post-IBD transition: once at peer tip we must leave IBD
/// and stay in tip-tracking + serve mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "IBD→follow + third-peer relay; run via scripts/integration.sh"]
async fn ibd_to_tip_tracking_and_block_relay() {
    let seed_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();
    let third_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 20).await;
    let seed_tip_hash = seed.hub.tip_hash().unwrap();

    // 1) Catch-up to the highest tip the seeder has.
    let mut client = start_node(&client_dir).await;
    let n = client
        .sync(&[seed.local_addr], IbdConfig::for_test())
        .await
        .expect("ibd");
    assert!(n >= 20, "accepted {n}");
    client
        .wait_height(20, Duration::from_secs(15))
        .await
        .expect("client tip after ibd");
    assert_eq!(client.query.tip_height(), Some(Height(20)));
    assert_eq!(client.hub.tip_hash().unwrap(), seed_tip_hash);

    // 2) Transition: persistent follow (tip tracking).
    client
        .follow_from(seed.local_addr)
        .await
        .expect("follow after ibd");

    // 3) Seeder extends tip — client must pick it up via inv/headers on the
    //    follow session (steady-state path).
    let tip = seed.hub.tip_hash().unwrap();
    let tip_time = seed
        .query
        .header_at_height(Height(20))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let b21 = mine_regtest_block(tip, tip_time + 600, 21, vec![]);
    let h21 = b21.block_hash();
    seed.ingest_block(21, b21).unwrap();

    client
        .wait_tip_hash(h21, Duration::from_secs(15))
        .await
        .expect("tip tracking after ibd");
    assert_eq!(client.query.tip_height(), Some(Height(21)));

    // 4) Block relay / serve: a third node IBD-syncs **from the client** (not
    //    the original seeder), proving post-IBD history serve works.
    let third = start_node(&third_dir).await;
    let n3 = sync_ibd(&third, client.local_addr).await;
    assert!(n3 >= 20, "third downloaded {n3}");
    third
        .wait_height(21, Duration::from_secs(15))
        .await
        .expect("third tip");
    assert_eq!(third.hub.tip_hash().unwrap(), h21);

    seed.shutdown().await;
    client.shutdown().await;
    third.shutdown().await;
}

/// Phase 5: most-work reorg — longer branch wins after disconnect/connect.
#[tokio::test]
async fn reorg_to_longer_branch() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{AcceptOutcome, ChainHub};

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);

    let genesis = regtest_genesis();
    hub.accept_block(genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=4u32 {
        let b = mine_regtest_block(tip, time + 600, h, vec![]);
        tip = b.block_hash();
        time = b.header.time;
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(4));

    // Fork from height 2: build longer branch 3',4',5',6'
    let fork_parent = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let mut branch = Vec::new();
    let mut p = BlockHash::from_byte_array(fork_parent);
    let mut t = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    for h in 3..=6u32 {
        // Distinct nonces via time offset so hashes differ from original chain
        let b = mine_regtest_block(p, t + 601, h, vec![]);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }

    let outcome = hub.accept_branch(&branch).unwrap();
    assert!(matches!(outcome, AcceptOutcome::Accepted { height: 6 }));
    assert_eq!(hub.tip_height(), Some(6));
    assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());
}

/// Leftover/BadPrev: an orphan whose parent is not on the tip must be held, not
/// `BLOCK_FAILED`. Applying the full winner path then reconstructs the new tip.
#[test]
fn badprev_orphan_does_not_blacklist_then_reorg_reconstructs() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{AcceptOutcome, ChainHub};

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);

    let genesis = regtest_genesis();
    hub.accept_block(genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=2u32 {
        let b = mine_regtest_block(tip, time + 600, h, vec![]);
        tip = b.block_hash();
        time = b.header.time;
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(2));
    let lose_tip = hub.tip_hash().unwrap();

    let mut p = genesis.block_hash();
    let mut t = genesis.header.time;
    let mut winner = Vec::new();
    for h in 1..=3u32 {
        let b = mine_regtest_block(p, t + 601, h, vec![]);
        p = b.block_hash();
        t = b.header.time;
        winner.push(b);
    }
    let w3 = winner.last().unwrap().clone();
    let outcome = hub.accept_received_block(w3.clone()).unwrap();
    assert!(
        matches!(outcome, AcceptOutcome::IgnoredWeaker),
        "orphan whose prev is not on the tip must not connect: {outcome:?}"
    );
    assert_eq!(hub.tip_height(), Some(2));
    assert_eq!(hub.tip_hash().unwrap(), lose_tip);
    assert!(
        hub.held_body(&w3.block_hash()).is_some(),
        "orphan body is held, not permanent-blacklist"
    );

    let outcome = hub.accept_branch(&winner).unwrap();
    assert!(matches!(outcome, AcceptOutcome::Accepted { height: 3 }));
    assert_eq!(hub.tip_height(), Some(3));
    assert_eq!(hub.tip_hash().unwrap(), w3.block_hash());
    assert_eq!(
        hub.query
            .reconstruct_block_at_height(Height(3))
            .unwrap()
            .block_hash(),
        w3.block_hash()
    );
    assert_eq!(
        hub.query
            .reconstruct_block_at_height(Height(2))
            .unwrap()
            .block_hash(),
        winner[1].block_hash()
    );
}

/// Competing spends of the same coinbase on two forks promote multi-list
/// annotations (reorg path). Extending the winning tip must resolve multi via
/// confirmed-strong walk — not hard-fail `structural multi-spender` (mainnet
/// tip-follow freeze at 961396 after reorg annotate near tip).
#[test]
fn reorg_competing_spend_extends_without_multi_fail() {
    use bitcoin::Amount;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{AcceptOutcome, ChainHub};
    use rbitcoin_test::mine::spend_anyone_can_spend;

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    let maturity = ChainParams::regtest().coinbase_maturity();

    let genesis = regtest_genesis();
    hub.accept_block(genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;

    // Height 1: coinbase we will double-spend across forks after maturity.
    let b1 = mine_regtest_block(tip, time + 600, 1, vec![]);
    let cb1 = b1.txdata[0].compute_txid();
    tip = b1.block_hash();
    time = b1.header.time;
    hub.accept_block(b1).unwrap();

    // Pad until height-1 has `maturity` confirmations (spendable next).
    let last_pad = maturity + 1;
    for h in 2..=last_pad {
        let b = mine_regtest_block(tip, time + 600, h, vec![]);
        tip = b.block_hash();
        time = b.header.time;
        hub.accept_block(b).unwrap();
    }
    let fork_parent = tip;
    let fork_time = time;
    let fork_h = last_pad;

    // Main branch: spend coinbase once at fork_h+1.
    let spend_a = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let main = mine_regtest_block(fork_parent, fork_time + 600, fork_h + 1, vec![spend_a]);
    hub.accept_block(main).unwrap();
    assert_eq!(hub.tip_height(), Some(fork_h + 1));

    // Longer competing branch from fork_parent: different spend of same out + pad.
    let spend_b = spend_anyone_can_spend(cb1, 0, Amount::from_sat(48_5000_0000));
    let mut branch = Vec::new();
    let mut p = fork_parent;
    let mut t = fork_time;
    for (i, h) in (fork_h + 1..=fork_h + 3).enumerate() {
        let extra = if i == 0 {
            vec![spend_b.clone()]
        } else {
            vec![]
        };
        // Distinct time so PoW/hash differs from main.
        let b = mine_regtest_block(p, t + 601 + i as u32, h, extra);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }

    let outcome = hub.accept_branch(&branch).unwrap();
    match outcome {
        AcceptOutcome::Accepted { height } => {
            assert_eq!(height, fork_h + 3, "reorg should land at fork_h+3");
        }
        other => panic!("expected reorg to longer competing-spend branch, got {other:?}"),
    }
    assert_eq!(hub.tip_height(), Some(fork_h + 3));

    // Coinbase is multi-list (main spend_a + winning spend_b) with spend_b strong.
    // A third spend must be PrevoutSpent — **not** `structural multi-spender`
    // hard-fail (that was the mainnet tip freeze after tip-follow reorgs).
    let spend_c = spend_anyone_can_spend(cb1, 0, Amount::from_sat(47_0000_0000));
    let double = mine_regtest_block(p, t + 600, fork_h + 4, vec![spend_c]);
    let err = hub
        .accept_block(double)
        .expect_err("double-spend of multi+strong coinbase must fail");
    let msg = err.to_string();
    assert!(
        !msg.contains("multi-spender"),
        "reorg multi-list must not hard-fail structural; got: {msg}"
    );
    assert!(
        msg.to_ascii_lowercase().contains("spent")
            || msg.to_ascii_lowercase().contains("prevout")
            || msg.to_ascii_lowercase().contains("double"),
        "expected prevout-spent class error, got: {msg}"
    );

    // Honest tip extension still works after multi-list exists on disk.
    let ext = mine_regtest_block(p, t + 600, fork_h + 4, vec![]);
    let o = hub
        .accept_block(ext)
        .expect("tip extension after multi-list reorg must succeed");
    match o {
        AcceptOutcome::Accepted { height } => assert_eq!(height, fork_h + 4),
        other => panic!("expected Accepted, got {other:?}"),
    }
    assert_eq!(hub.tip_height(), Some(fork_h + 4));
}

/// Same-height competing tip with more work wins; then multi-block reorg to a
/// longer side branch (tip-mode accept path, not IBD body-queue).
#[test]
fn reorg_same_height_then_multi_block_branch() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{AcceptOutcome, ChainHub};

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);

    let genesis = regtest_genesis();
    hub.accept_block(genesis.clone()).unwrap();
    let mut tip = genesis.block_hash();
    let mut time = genesis.header.time;
    for h in 1..=3u32 {
        let b = mine_regtest_block(tip, time + 600, h, vec![]);
        tip = b.block_hash();
        time = b.header.time;
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(3));
    let parent_h2 = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let parent = BlockHash::from_byte_array(parent_h2);
    let t2 = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .timestamp;

    // Competing tip at height 3 (more work via later timestamp when PoW allows).
    let rival = mine_regtest_block(parent, t2 + 900, 3, vec![]);
    let outcome = hub.accept_block(rival.clone()).unwrap();
    match outcome {
        AcceptOutcome::Accepted { height: 3 } => {
            assert_eq!(hub.tip_hash().unwrap(), rival.block_hash());
        }
        AcceptOutcome::IgnoredWeaker => {
            // Equal work is OK for this network — still exercise multi-block reorg below.
            assert_eq!(hub.tip_height(), Some(3));
        }
        other => panic!("unexpected same-height outcome: {other:?}"),
    }

    // Multi-block reorg from height 1: longer path 2'..5'.
    let fork_parent = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let mut p = BlockHash::from_byte_array(fork_parent);
    let mut t = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let mut branch = Vec::new();
    for h in 2..=5u32 {
        let b = mine_regtest_block(p, t + 700 + h, h, vec![]);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }
    let o = hub.accept_branch(&branch).unwrap();
    assert!(
        matches!(o, AcceptOutcome::Accepted { height: 5 }),
        "multi-block reorg to height 5, got {o:?}"
    );
    assert_eq!(hub.tip_height(), Some(5));
    assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());

    // Tip extension after multi-block reorg.
    let ext = mine_regtest_block(p, t + 600, 6, vec![]);
    assert!(matches!(
        hub.accept_block(ext).unwrap(),
        AcceptOutcome::Accepted { height: 6 }
    ));
}

/// Class A archived ahead of tip, then wire confirm: second confirm attempt
/// must not grow Class A body count (idempotent commit after partial fail shape).
#[test]
fn confirm_wire_idempotent_when_class_a_already_present() {
    use rbitcoin_consensus::{
        accept_and_connect_block, commit_class_a_block, confirm_wire_run, header_to_record,
        ChainParams, Milestone,
    };
    use rbitcoin_primitives::Height as H;

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone { height: 1_000_000 };
    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, H::GENESIS, &genesis, ms).unwrap();
    let g_fk = q
        .get_header_by_hash(&genesis.block_hash().to_byte_array())
        .unwrap()
        .unwrap()
        .0;
    let b1 = mine_regtest_block(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
    let hfk = q
        .ensure_header(&header_to_record(
            g_fk,
            &b1.header,
            b1.header.block_hash().to_byte_array(),
        ))
        .unwrap();
    commit_class_a_block(&q, &params, H(1), &b1, ms).unwrap();
    assert!(q
        .is_block_archived(&b1.block_hash().to_byte_array())
        .unwrap());
    let n_before = q.tx_body_count();

    // Wire confirm with Class A already present — plan should be empty / no-op commit.
    confirm_wire_run(&q, &params, ms, &[(H(1), b1.clone())]).unwrap();
    assert_eq!(q.tip_height(), Some(H(1)));
    let n_mid = q.tx_body_count();
    assert_eq!(n_mid, n_before, "confirm must not re-append Class A");

    // Idempotent re-entry (AlreadyHave / no tip change).
    let tip = q.tip_height();
    let _ = confirm_wire_run(&q, &params, ms, &[(H(1), b1)]);
    assert_eq!(q.tip_height(), tip);
    assert_eq!(q.tx_body_count(), n_before);
    let _ = hfk;
}

/// Full `run_p2p` entry: listen, connect to seeder, exit via max_run_secs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full run_p2p entry; run via scripts/integration.sh"]
async fn node_run_p2p_short() {
    use rbitcoin_node::{run_p2p, NodeConfig};
    use rbitcoin_primitives::Network;

    let seed_dir = TempDir::new().unwrap();
    let node_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 3).await;
    let seed_addr = seed.local_addr;

    let mut cfg = NodeConfig::default()
        .with_datadir(node_dir.path())
        .with_network(Network::Regtest)
        .with_p2p_listen("127.0.0.1:0".parse().unwrap())
        .with_tiny_heads();
    cfg.listen.connect = vec![seed_addr];
    cfg.listen.use_seeds = false;
    cfg.max_run_secs = Some(0); // sync then exit immediately

    run_p2p(cfg).await.expect("run_p2p");

    // Reopen store — should have synced chain
    let q = Query::open_or_create_tiny(node_dir.path().join("store")).unwrap();
    assert_eq!(q.tip_height(), Some(Height(3)));

    seed.shutdown().await;
}

/// Periodic / holistic mesh: larger chain, multi-hop, concurrent peers.
/// Run: `cargo test -p rbitcoin-test --test integration_multinode -- --ignored --nocapture`
#[tokio::test]
#[ignore = "periodic multi-node mesh; run via scripts/integration.sh"]
async fn multinode_mesh_periodic() {
    const HEIGHT: u32 = 40;
    let dirs: Vec<TempDir> = (0..4).map(|_| TempDir::new().unwrap()).collect();

    let seed = start_node(&dirs[0]).await;
    seed_chain(&seed, HEIGHT).await;

    // Fan-out: three peers IBD-sync from seed.
    let mut peers = Vec::new();
    for d in dirs.iter().skip(1) {
        peers.push(start_node(d).await);
    }

    let addr = seed.local_addr;
    for p in &peers {
        sync_ibd(p, addr).await;
        p.wait_height(HEIGHT, Duration::from_secs(30))
            .await
            .expect("height");
        assert_eq!(p.hub.tip_hash(), seed.hub.tip_hash());
    }

    // Cross-link: peer[1] re-syncs from peer[0] (idempotent / already at tip).
    let n = peers[1]
        .sync(&[peers[0].local_addr], IbdConfig::for_test())
        .await
        .unwrap();
    let _ = n;
    assert_eq!(peers[1].query.tip_height(), Some(Height(HEIGHT)));

    seed.shutdown().await;
    for p in peers {
        p.shutdown().await;
    }
}
