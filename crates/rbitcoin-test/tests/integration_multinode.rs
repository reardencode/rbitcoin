//! Multi-node P2P integration tests (all default `cargo test` + coverage).
//!
//! Single-hop IBD (genesis+1), cold reconstruct serve (10 blocks), dead-peer
//! skip, hop serve, dual live seeders, post-IBD tip follow, getheaders gap
//! fill, product `run_p2p --blocksonly --connect`. Hard wall timeouts; hang-free on
//! CI-class hosts. Handshake / compact / feeler / inbound-full / hub reorg
//! live in the same binary. Live `P2PNode` tests serialize on `live_p2p_lock`
//! (process-wide script pool); hub-only reorgs do not.

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::{
    rehydrate_block_queue_residue, run_feeler_timed, select_inbound_eviction, IbdConfig,
    InboundEvictCandidate, NetAddr, NetError, P2PNode,
};
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

async fn start_node_inbound(dir: &TempDir, max_inbound: usize) -> P2PNode {
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:test/".into(),
        max_inbound,
    )
    .await
    .expect("listen")
}

fn open_padded_query(dir: &TempDir) -> Query {
    use rbitcoin_consensus::accept_and_connect_block;
    use rbitcoin_test::pad_empty_from;

    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let last = params.coinbase_maturity() + 1;
    pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        last,
    );
    q
}

async fn start_padded(dir: &TempDir) -> P2PNode {
    let q = open_padded_query(dir);
    q.set_block_filter_index(true);
    q.backfill_block_filters_through(1)
        .expect("filters through height 1");
    rbitcoin_net::set_compact_filters_service(true);
    P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
    )
    .await
    .expect("listen")
}

async fn wait_ms_until(
    ms: u64,
    mut pred: impl FnMut() -> bool,
    on_timeout: impl FnOnce() -> String,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        if pred() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("{}", on_timeout());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_v2_eof(sess: &mut rbitcoin_net::V2PlainSession, label: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout(Duration::from_millis(100), sess.read_contents()).await {
            Ok(Err(_)) => return,
            Ok(Ok(_)) => {}
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("{label}");
                }
            }
        }
    }
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
    node.sync(&[rbitcoin_net::NetAddr::Ip(peer)], IbdConfig::for_test())
        .await
        .expect("ibd sync")
}

fn llvm_cov_wall(default_secs: u64, llvm_secs: u64) -> Duration {
    if std::env::var_os("CARGO_LLVM_COV").is_some() {
        Duration::from_secs(llvm_secs)
    } else {
        Duration::from_secs(default_secs)
    }
}

/// One live `P2PNode` topology at a time: process-wide `rbtc-scripts` steal
/// plus confirm OS threads (overlapping abort under llvm-cov heap-corrupts).
async fn live_p2p_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

const RPC_BEARER: &str = "Bearer pass"; // `{datadir}/rpc.token` written by the tests

fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_listeners(addrs: &[SocketAddr]) {
    use std::time::Instant;
    use tokio::net::TcpStream;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut missing = None;
        for addr in addrs {
            if TcpStream::connect(addr).await.is_err() {
                missing = Some(*addr);
                break;
            }
        }
        if missing.is_none() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("listeners not up ({missing:?}): {addrs:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn jsonrpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let body = serde_json::json!({"jsonrpc":"1.0","id":"test","method":method,"params":params})
        .to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {RPC_BEARER}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("rpc connect");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let json_body = text.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    serde_json::from_str(json_body)
        .unwrap_or_else(|e| panic!("rpc {method} json: {e} body={json_body}"))
}

async fn electrum_rpc(
    addr: SocketAddr,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    let mut stream = TcpStream::connect(addr).await.expect("electrum connect");
    let req = serde_json::json!({"id":1,"jsonrpc":"2.0","method":method,"params":params})
        .to_string()
        + "\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .await
        .expect("electrum read");
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("electrum {method} json: {e} body={line}"))
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("esplora connect");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    (status, body)
}

/// Two nodes, seed has genesis+1, peer IBD-syncs the short path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_header_and_block_sync() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 1).await;
        assert_eq!(seed.cache.tip_height(), Some(1));
        assert_eq!(seed.query.tip_height(), Some(Height(1)));

        let peer = start_node(&peer_dir).await;
        let n = sync_ibd(&peer, seed.local_addr).await;
        assert!(n >= 1, "downloaded {n}");
        peer.wait_height(1, Duration::from_secs(5))
            .await
            .expect("tip");

        // IBD confirm writes Class C tip; RAM BlockCache may stay cold.
        assert_eq!(peer.query.tip_height(), Some(Height(1)));
        assert_eq!(peer.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());
        let write = peer.query.confirm_stats().last_write_phases();
        assert!(
            write.n_blocks >= 1,
            "IBD write meter must move on the peer: {write:?}"
        );

        seed.shutdown().await;
        peer.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("two_node_header_and_block_sync wall timeout ({wall:?})"));
}

/// In-tree P2P client (no Core functional): peertimeout of a v1-magic inbound,
/// obsolete VERSION / pre-verack ping disconnect, full-relay GetAddr cache
/// (1000 / 23%), AddrFetch GetAddr (no getheaders), one post-verack keepalive
/// ping/pong, and headers-sync stall replace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_timeout_getaddr_and_keepalive_ping() {
    use bitcoin::p2p::message::NetworkMessage;
    use rbitcoin_net::{AddrMan, PeerConnType};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();
        let dummy_dir = TempDir::new().unwrap();
        let seed = start_node(&seed_dir).await;

        let mut book = AddrMan::new();
        for i in 0..5_000u32 {
            book.add(std::net::SocketAddr::from((
                [(i >> 8) as u8, (i & 0xff) as u8, 1, 1],
                8333,
            )));
        }
        seed.peers.set_addrman(Arc::new(Mutex::new(book)));

        let mut peer = start_node(&peer_dir).await;
        let dummy = start_node(&dummy_dir).await;
        tokio::time::timeout(Duration::from_secs(5), peer.follow_from(seed.local_addr))
            .await
            .expect("follow_from must return after handshake")
            .expect("follow handshake");
        assert!(
            peer.follow_live_count() >= 1,
            "outbound session must stay live after follow_from"
        );
        seed.peers
            .addconnection(dummy.local_addr, PeerConnType::OutboundFullRelay)
            .expect("preferred outbound for stall");
        wait_ms_until(
            3_000,
            || {
                seed.peers.snapshot().into_iter().any(|p| {
                    !p.inbound
                        && p.conn_type == PeerConnType::OutboundFullRelay
                        && !p.subver.is_empty()
                })
            },
            || {
                format!(
                    "seed outbound to dummy must complete (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;

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

        wait_ms_until(
            3_000,
            || {
                peer.peers.live_peers().into_iter().any(|p| {
                    !p.inbound && p.handshake_complete() && p.queue_msg(NetworkMessage::GetAddr)
                })
            },
            || {
                format!(
                    "follower outbound must take GetAddr (peer={:?})",
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            5_000,
            || {
                peer.peers.snapshot().into_iter().any(|p| {
                    !p.inbound && p.bytesrecv_per_msg.get("addrv2").copied().unwrap_or(0) > 0
                })
            },
            || {
                format!(
                    "full-relay GetAddr must return addrv2 (peer={:?})",
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        let bind = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound && !p.subver.is_empty())
            .map(|p| p.addrbind)
            .unwrap_or(seed.local_addr);
        let cached = seed.peers.addr_response_for_bind(bind);
        assert_eq!(
            cached.len(),
            1000,
            "GetAddr must cap at MAX_ADDR_TO_SEND (23% of 5000 is 1150)"
        );
        assert_eq!(
            cached,
            seed.peers.addr_response_for_bind(bind),
            "same listen bind must reuse the 24h GetAddr cache"
        );

        let now = seed.peers.now_secs();
        seed.peers.set_mock_now(now + 40 * 60);
        wait_ms_until(
            3_000,
            || {
                !seed
                    .peers
                    .snapshot()
                    .into_iter()
                    .any(|p| p.inbound && !p.subver.is_empty())
            },
            || {
                format!(
                    "stalling headers-sync inbound must drop when a preferred outbound exists \
                     (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        seed.peers.set_mock_now(0);

        seed.peers
            .addconnection(seed.local_addr, PeerConnType::OutboundFullRelay)
            .expect("self-connect dial");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !seed
                .peers
                .snapshot()
                .into_iter()
                .any(|p| p.addr == seed.local_addr && !p.subver.is_empty()),
            "self-connect must not complete handshake: {:?}",
            seed.peers.snapshot()
        );

        seed.peers.set_peer_timeout_secs(1);

        let mut one = AddrMan::new();
        one.add(std::net::SocketAddr::from(([1, 2, 3, 4], 8333)));
        seed.peers.set_addrman(Arc::new(Mutex::new(one)));

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
            tokio::task::yield_now().await;
        }
        drop(raw);

        let seed_addr = seed.local_addr;
        let mut obsolete = rbitcoin_net::V2PlainSession::outbound_bip324(
            tokio::net::TcpStream::connect(seed_addr)
                .await
                .expect("obsolete VERSION dial"),
        )
        .await
        .expect("obsolete VERSION BIP324");
        let obsolete_ver = {
            use bitcoin::p2p::address::Address;
            use bitcoin::p2p::message_network::VersionMessage;
            use bitcoin::p2p::ServiceFlags;
            VersionMessage {
                version: 31799,
                services: ServiceFlags::NONE,
                timestamp: 0,
                receiver: Address::new(&seed_addr, ServiceFlags::NONE),
                sender: Address::new(&seed_addr, ServiceFlags::NONE),
                nonce: 1,
                user_agent: "/rbitcoin:test/".into(),
                start_height: 0,
                relay: true,
            }
        };
        obsolete
            .write_contents(
                &rbitcoin_net::encode_v2_contents(NetworkMessage::Version(obsolete_ver))
                    .expect("encode obsolete VERSION"),
            )
            .await
            .expect("write obsolete VERSION");
        wait_v2_eof(&mut obsolete, "obsolete VERSION must close the peer").await;

        let mut pre_verack = rbitcoin_net::V2PlainSession::outbound_bip324(
            tokio::net::TcpStream::connect(seed_addr)
                .await
                .expect("pre-verack ping dial"),
        )
        .await
        .expect("pre-verack BIP324");
        let ok_ver = {
            use bitcoin::p2p::address::Address;
            use bitcoin::p2p::message_network::VersionMessage;
            use bitcoin::p2p::ServiceFlags;
            VersionMessage {
                version: 70016,
                services: ServiceFlags::NONE,
                timestamp: 0,
                receiver: Address::new(&seed_addr, ServiceFlags::NONE),
                sender: Address::new(&seed_addr, ServiceFlags::NONE),
                nonce: 2,
                user_agent: "/rbitcoin:test/".into(),
                start_height: 0,
                relay: true,
            }
        };
        pre_verack
            .write_contents(
                &rbitcoin_net::encode_v2_contents(NetworkMessage::Version(ok_ver))
                    .expect("encode VERSION"),
            )
            .await
            .expect("write VERSION");
        pre_verack
            .write_contents(
                &rbitcoin_net::encode_v2_contents(NetworkMessage::Ping(1)).expect("encode ping"),
            )
            .await
            .expect("write ping prior to verack");
        wait_v2_eof(
            &mut pre_verack,
            "pre-verack ping must close at peertimeout=1",
        )
        .await;

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

        let t = seed.peers.now_secs();
        seed.peers.set_mock_now(t + 24 * 60 * 60 + 1);
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
        let fetch = peer
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.conn_type == PeerConnType::AddrFetch)
            .expect("AddrFetch session");
        assert_eq!(
            fetch
                .bytessent_per_msg
                .get("getheaders")
                .copied()
                .unwrap_or(0),
            0,
            "AddrFetch must not GetHeaders: {:?}",
            fetch.bytessent_per_msg
        );
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
        dummy.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("p2p_timeout_getaddr_and_keepalive_ping wall timeout (20s)");
}

/// Heights 0 and 1 are sealed; the tip is not. The seeder still advertises
/// `NODE_COMPACT_FILTERS`. A stop past the watermark is silence.
async fn pin_compact_filters(peer: &P2PNode, seed: &P2PNode) {
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};

    let hash_at = |h: u32| {
        let (_, rec) = seed
            .query
            .header_at_height(Height(h))
            .unwrap()
            .unwrap_or_else(|| panic!("header {h}"));
        BlockHash::from_byte_array(rec.hash)
    };
    let tip = seed.hub.tip_hash().expect("pad tip");
    let sealed = hash_at(1);
    const COMPACT: u64 = 1 << 6;
    wait_ms_until(
        3_000,
        || {
            peer.peers
                .live_peers()
                .into_iter()
                .any(|p| !p.inbound && p.handshake_complete() && p.services & COMPACT != 0)
        },
        || {
            format!(
                "version must advertise COMPACT_FILTERS while the index lags (peer={:?})",
                peer.peers.snapshot()
            )
        },
    )
    .await;
    wait_ms_until(
        3_000,
        || {
            peer.peers.live_peers().into_iter().any(|p| {
                !p.inbound
                    && p.handshake_complete()
                    && p.queue_msg(NetworkMessage::GetCFilters(GetCFilters {
                        filter_type: 0,
                        start_height: 0,
                        stop_hash: tip,
                    }))
            })
        },
        || {
            format!(
                "outbound must take getcfilters for the tip (peer={:?})",
                peer.peers.snapshot()
            )
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let early = peer
        .peers
        .snapshot()
        .into_iter()
        .any(|p| !p.inbound && p.bytesrecv_per_msg.get("cfilter").copied().unwrap_or(0) > 0);
    assert!(
        !early,
        "stop past the watermark is silence (peer={:?})",
        peer.peers.snapshot()
    );
    let queued = peer.peers.live_peers().into_iter().any(|p| {
        !p.inbound
            && p.handshake_complete()
            && p.queue_msg(NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: 0,
                stop_hash: sealed,
            }))
            && p.queue_msg(NetworkMessage::GetCFHeaders(GetCFHeaders {
                filter_type: 0,
                start_height: 1,
                stop_hash: sealed,
            }))
            && p.queue_msg(NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                filter_type: 0,
                stop_hash: sealed,
            }))
    });
    assert!(
        queued,
        "outbound must take filter requests inside the watermark"
    );
    wait_ms_until(
        5_000,
        || {
            peer.peers.snapshot().into_iter().any(|p| {
                !p.inbound
                    && p.bytesrecv_per_msg.get("cfilter").copied().unwrap_or(0) > 0
                    && p.bytesrecv_per_msg.get("cfheaders").copied().unwrap_or(0) > 0
                    && p.bytesrecv_per_msg.get("cfcheckpt").copied().unwrap_or(0) > 0
            })
        },
        || {
            format!(
                "seed must answer sealed filters (peer={:?})",
                peer.peers.snapshot()
            )
        },
    )
    .await;
}

fn mine_on(node: &P2PNode, height: u32) -> BlockHash {
    let tip = node.hub.tip_hash().expect("tip hash");
    let tip_time = node.hub.tip_header().expect("tip header").time;
    let b = mine_regtest_block(tip, tip_time + 600, height, vec![]);
    let h = b.block_hash();
    node.ingest_block(height, b).unwrap();
    h
}

/// Mature-pad follow: HB coinbase compact, 2-tx compact → getblocktxn, same-peer
/// compact retry while pending, then blocktxn connect; unique short-id fill
/// that fails header merkle → getdata (not BLOCK_FAILED), honest full block
/// connects, then orphan child GetData + parent accept (INV of parked child
/// is AlreadyHave).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_compact_hb_getblocktxn_and_orphan() {
    use bitcoin::bip152::{HeaderAndShortIds, ShortId};
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::Amount;
    use rbitcoin_test::mine::spend_anyone_can_spend;

    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();
        let seed = start_padded(&seed_dir).await;
        let mut peer = start_padded(&peer_dir).await;
        attach_relay_mempool(&peer, &peer_dir);
        let pad_h = seed.query.tip_height().expect("pad tip").0;
        tokio::time::timeout(Duration::from_secs(5), peer.follow_from(seed.local_addr))
            .await
            .expect("follow_from handshake")
            .expect("follow");
        assert!(
            peer.follow_live_count() >= 1,
            "outbound follow must stay live"
        );
        pin_compact_filters(&peer, &seed).await;

        let h_empty = mine_on(&seed, pad_h + 1);
        peer.wait_tip_hash(h_empty, Duration::from_secs(5))
            .await
            .expect("first tip via headers/inv");
        assert!(
            peer.peers
                .snapshot()
                .into_iter()
                .any(|p| !p.inbound && p.bip152_hb_to),
            "HB sendcmpct(1) must be decided before the new tip is visible \
             (peer={:?} seed={:?})",
            peer.peers.snapshot(),
            seed.peers.snapshot()
        );
        wait_ms_until(
            3_000,
            || {
                seed.peers
                    .snapshot()
                    .into_iter()
                    .any(|p| p.inbound && p.bip152_hb_from)
            },
            || {
                format!(
                    "seed inbound must see sendcmpct(1) after first tip \
                     (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;

        let cb1 = seed
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let extra = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
        let tip = seed.hub.tip_hash().expect("tip");
        let tip_time = seed.hub.tip_header().expect("tip time").time;
        let with_extra = mine_regtest_block(tip, tip_time + 600, pad_h + 2, vec![extra]);
        assert_eq!(with_extra.txdata.len(), 2, "coinbase + extra");
        let h_extra = with_extra.block_hash();
        let hsi_extra = HeaderAndShortIds::from_block(&with_extra, 0xdead_beef, 2, &[]).unwrap();
        seed.ingest_block(pad_h + 2, with_extra).unwrap();
        wait_ms_until(
            5_000,
            || {
                seed.peers.snapshot().into_iter().any(|p| {
                    p.inbound && p.bytesrecv_per_msg.get("getblocktxn").copied().unwrap_or(0) > 0
                })
            },
            || {
                format!(
                    "follower must GetBlockTxn the missing extra tx \
                     (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::CmpctBlock(CmpctBlock {
                            compact_block: hsi_extra.clone(),
                        }))
                })
            },
            || {
                format!(
                    "seed inbound writer must take same-peer compact retry (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        peer.wait_tip_hash(h_extra, Duration::from_secs(5))
            .await
            .expect("2-tx compact via getblocktxn");
        assert_eq!(peer.query.tip_height(), Some(Height(pad_h + 2)));

        let cb3 = seed
            .query
            .reconstruct_block_at_height(Height(3))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let cb4 = seed
            .query
            .reconstruct_block_at_height(Height(4))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let bait = spend_anyone_can_spend(cb3, 0, Amount::from_sat(49_0000_0000));
        let honest_extra = spend_anyone_can_spend(cb4, 0, Amount::from_sat(49_0000_0000));
        let bait_txid = bait.compute_txid();
        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::Tx(bait.clone()))
                })
            },
            || {
                format!(
                    "seed inbound writer must take the compact-fill bait tx (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            5_000,
            || peer.hub.mempool().is_some_and(|m| m.contains(&bait_txid)),
            || {
                format!(
                    "follower must admit bait tx for unique short-id fill \
                     (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        let tip_after_extra = seed.hub.tip_hash().expect("tip after 2-tx");
        let time_after_extra = seed.hub.tip_header().expect("tip time").time;
        let honest = mine_regtest_block(
            tip_after_extra,
            time_after_extra + 600,
            pad_h + 3,
            vec![honest_extra],
        );
        assert_eq!(honest.txdata.len(), 2, "coinbase + honest extra");
        let h_honest = honest.block_hash();
        let mut hsi = HeaderAndShortIds::from_block(&honest, 0xdead_beef, 2, &[]).unwrap();
        assert_eq!(hsi.short_ids.len(), 1, "one non-coinbase short-id");
        let keys = ShortId::calculate_siphash_keys(&honest.header, hsi.nonce);
        hsi.short_ids[0] = ShortId::with_siphash_keys(&bait.compute_wtxid().to_raw_hash(), keys);
        let getdata_before = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0))
            .unwrap_or(0);
        let getblocktxn_before = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getblocktxn").copied().unwrap_or(0))
            .unwrap_or(0);
        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::CmpctBlock(CmpctBlock {
                            compact_block: hsi.clone(),
                        }))
                })
            },
            || {
                format!(
                    "seed inbound writer must take mutated compact (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            5_000,
            || {
                seed.peers.snapshot().into_iter().any(|p| {
                    p.inbound
                        && p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0) > getdata_before
                })
            },
            || {
                format!(
                    "merkle-mutated unique short-id fill must GetData, not getblocktxn \
                     (seed={:?} peer={:?} getdata_before={getdata_before} \
                      getblocktxn_before={getblocktxn_before})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        let getblocktxn_after = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getblocktxn").copied().unwrap_or(0))
            .unwrap_or(0);
        assert_eq!(
            getblocktxn_after, getblocktxn_before,
            "merkle-mutated unique fill must GetData, not GetBlockTxn"
        );
        assert!(
            !peer.hub.is_block_invalid(&h_honest),
            "compact merkle fail must not BLOCK_FAILED the header"
        );
        assert_eq!(peer.query.tip_height(), Some(Height(pad_h + 2)));
        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::Block(honest.clone()))
                })
            },
            || {
                format!(
                    "seed inbound writer must take honest full block (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        peer.wait_tip_hash(h_honest, Duration::from_secs(5))
            .await
            .expect("honest block after compact merkle getdata");
        assert!(
            !peer.hub.is_block_invalid(&h_honest),
            "honest getdata recovery must keep the header valid"
        );
        let getdata_after_honest = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0))
            .unwrap_or(0);

        let cb2 = seed
            .query
            .reconstruct_block_at_height(Height(2))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let parent = spend_anyone_can_spend(cb2, 0, Amount::from_sat(49_0000_0000));
        let child =
            spend_anyone_can_spend(parent.compute_txid(), 0, Amount::from_sat(48_0000_0000));
        let child_txid = child.compute_txid();
        let child_wtxid = child.compute_wtxid();

        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::Tx(child.clone()))
                })
            },
            || {
                format!(
                    "seed inbound writer must take the child tx (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            5_000,
            || {
                let parked = peer.hub.mempool().map(|m| m.orphan_count()).unwrap_or(0);
                let getdata = seed
                    .peers
                    .snapshot()
                    .into_iter()
                    .find(|p| p.inbound)
                    .map(|p| p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0))
                    .unwrap_or(0);
                parked == 1 && getdata > getdata_after_honest
            },
            || {
                format!(
                    "peer must park the child and GetData the parent \
                     (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        let getdata_parked = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0))
            .unwrap_or(0);
        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::Inv(vec![
                            Inventory::WitnessTransaction(child_txid),
                            Inventory::WTx(child_wtxid),
                        ]))
                })
            },
            || {
                format!(
                    "seed inbound writer must take orphan INV (seed={:?})",
                    seed.peers.snapshot()
                )
            },
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let getdata_after_inv = seed
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("getdata").copied().unwrap_or(0))
            .unwrap_or(0);
        assert!(
            getdata_after_inv > getdata_parked,
            "INV of orphanage txid must GetData (same-txid different witness)"
        );

        wait_ms_until(
            3_000,
            || {
                seed.peers.live_peers().into_iter().any(|p| {
                    p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::Tx(parent.clone()))
                })
            },
            || {
                format!(
                    "seed inbound writer must take the parent tx (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            5_000,
            || {
                let Some(mp) = peer.hub.mempool() else {
                    return false;
                };
                mp.orphan_count() == 0
                    && mp.contains(&parent.compute_txid())
                    && mp.contains(&child_txid)
            },
            || {
                format!(
                    "parent accept must promote the parked child \
                     (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;

        use bitcoin::p2p::message_blockdata::GetBlocksMessage;
        use bitcoin::p2p::message_bloom::{BloomFlags, FilterLoad};
        let genesis = seed
            .query
            .reconstruct_block_at_height(Height::GENESIS)
            .unwrap()
            .block_hash();
        let inv_before = peer
            .peers
            .snapshot()
            .into_iter()
            .find(|p| !p.inbound)
            .map(|p| p.bytesrecv_per_msg.get("inv").copied().unwrap_or(0))
            .unwrap_or(0);
        let gb = GetBlocksMessage::new(vec![genesis], BlockHash::from_byte_array([0u8; 32]));
        wait_ms_until(
            3_000,
            || {
                peer.peers.live_peers().into_iter().any(|p| {
                    !p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::GetBlocks(gb.clone()))
                })
            },
            || {
                format!(
                    "follower outbound must queue getblocks (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            3_000,
            || {
                peer.peers.snapshot().into_iter().any(|p| {
                    !p.inbound
                        && p.bytesrecv_per_msg.get("inv").copied().unwrap_or(0) > inv_before
                })
            },
            || {
                format!(
                    "getblocks must be answered with inv (seed={:?} peer={:?} inv_before={inv_before})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            3_000,
            || {
                peer.peers.live_peers().into_iter().any(|p| {
                    !p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::FeeFilter(1_234))
                })
            },
            || {
                format!(
                    "follower outbound must queue feefilter (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            3_000,
            || {
                seed.peers
                    .snapshot()
                    .into_iter()
                    .any(|p| p.inbound && p.minfeefilter_sat_kvb == 1_234)
            },
            || {
                format!(
                    "seed inbound must record feefilter (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        let bloom = FilterLoad {
            filter: vec![],
            hash_funcs: 1,
            tweak: 0,
            flags: BloomFlags::None,
        };
        wait_ms_until(
            3_000,
            || {
                peer.peers.live_peers().into_iter().any(|p| {
                    !p.inbound
                        && p.handshake_complete()
                        && p.queue_msg(NetworkMessage::FilterLoad(bloom.clone()))
                })
            },
            || {
                format!(
                    "follower outbound must queue filterload (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;
        wait_ms_until(
            3_000,
            || {
                !seed
                    .peers
                    .snapshot()
                    .into_iter()
                    .any(|p| p.inbound && !p.subver.is_empty())
            },
            || {
                format!(
                    "filterload must disconnect the seeder inbound (seed={:?} peer={:?})",
                    seed.peers.snapshot(),
                    peer.peers.snapshot()
                )
            },
        )
        .await;

        seed.shutdown().await;
        peer.shutdown().await;
    };
    tokio::time::timeout(llvm_cov_wall(30, 90), fut)
        .await
        .expect("p2p_compact_hb_getblocktxn_and_orphan wall timeout");
}

fn attach_relay_mempool(node: &P2PNode, dir: &TempDir) {
    use rbitcoin_net::MempoolHub;
    use std::sync::Arc;

    let mp = MempoolHub::open(dir.path().join("mp"), Arc::clone(&node.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(node.hub.attach_mempool(mp).is_ok(), "attach mempool once");
    node.hub.set_max_tip_age_secs(u64::MAX);
    assert!(
        !node.hub.in_ibd(),
        "maxtipage must leave IBD so P2P tx accept runs"
    );
}

/// Outbound feeler: VERSION completes, then the session closes (no live follow).
async fn pin_feeler_handshake_timeout_after_silence() {
    use bitcoin::p2p::Magic;
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    let _silent = server;
    match run_feeler_timed(
        Duration::from_millis(50),
        client,
        Magic::REGTEST,
        addr,
        peer,
        0,
        "/rbitcoin:test/",
    )
    .await
    {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("feeler silence must Timeout, got {e}"),
        Ok(()) => panic!("feeler succeeded on a silent peer"),
    }
}

fn pin_select_node_to_evict_ranking() {
    fn cand(
        id: u64,
        connected_at: u64,
        min_ping: Option<f64>,
        last_block: u64,
        last_tx: u64,
    ) -> InboundEvictCandidate {
        InboundEvictCandidate {
            id,
            connected_at,
            min_ping,
            last_block,
            last_tx,
            netgroup: 1,
            noban: false,
        }
    }
    let mut cands = Vec::new();
    for i in 0..4 {
        cands.push(cand(i, 100 + i, Some(0.05), 1000 + i, 0));
    }
    for i in 4..9 {
        cands.push(cand(i, 200 + i, Some(0.5), 0, 0));
    }
    for i in 9..13 {
        cands.push(cand(i, 300 + i, Some(0.05), 0, 1000 + i));
    }
    for i in 13..21 {
        cands.push(cand(i, 400 + i, Some(0.01), 0, 0));
    }
    let victim = select_inbound_eviction(cands).expect("one unprotected slow");
    assert!((4..9).contains(&victim), "victim={victim}");
}

#[tokio::test]
async fn p2p_feeler_completes_and_closes() {
    use rbitcoin_net::PeerConnType;

    let fut = async {
        let _live = live_p2p_lock().await;
        rbitcoin_log::capture_logs(true);
        let seed_dir = TempDir::new().unwrap();
        let dummy_dir = TempDir::new().unwrap();
        let seed = start_node(&seed_dir).await;
        let dummy = start_node(&dummy_dir).await;
        seed.peers
            .addconnection(dummy.local_addr, PeerConnType::Feeler)
            .expect("feeler dial");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if rbitcoin_log::take_logs()
                .iter()
                .any(|(_, m)| m.contains("feeler connection completed"))
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                rbitcoin_log::capture_logs(false);
                panic!(
                    "feeler must complete VERSION then close \
                     (seed_live={} dummy={:?})",
                    seed.follow_live_count(),
                    dummy.peers.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rbitcoin_log::capture_logs(false);
        assert_eq!(
            seed.follow_live_count(),
            0,
            "feeler must not stay as a follow session"
        );
        assert!(
            !dummy
                .peers
                .snapshot()
                .into_iter()
                .any(|p| p.inbound && !p.subver.is_empty()),
            "feeler must not leave a completed inbound on the dummy: {:?}",
            dummy.peers.snapshot()
        );
        pin_feeler_handshake_timeout_after_silence().await;

        seed.shutdown().await;
        dummy.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("p2p_feeler_completes_and_closes wall timeout (20s)");
}

/// `max_inbound=1`: a second outbound follow is refused; the first session stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_inbound_full_rejects_extra() {
    let fut = async {
        let _live = live_p2p_lock().await;
        pin_select_node_to_evict_ranking();
        let seed_dir = TempDir::new().unwrap();
        let a_dir = TempDir::new().unwrap();
        let b_dir = TempDir::new().unwrap();
        let seed = start_node_inbound(&seed_dir, 1).await;
        let mut a = start_node(&a_dir).await;
        let mut b = start_node(&b_dir).await;

        tokio::time::timeout(Duration::from_secs(5), a.follow_from(seed.local_addr))
            .await
            .expect("first follow handshake")
            .expect("first follow");
        let wait = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let n = seed
                .peers
                .snapshot()
                .into_iter()
                .filter(|p| p.inbound && !p.subver.is_empty())
                .count();
            if n >= 1 {
                break;
            }
            if tokio::time::Instant::now() >= wait {
                panic!(
                    "first follow must occupy the inbound slot (seed={:?})",
                    seed.peers.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let second =
            tokio::time::timeout(Duration::from_secs(5), b.follow_from(seed.local_addr)).await;
        if let Ok(Ok(())) = second {
            panic!(
                "second follow must not complete handshake at max_inbound=1 (seed={:?} b={:?})",
                seed.peers.snapshot(),
                b.peers.snapshot()
            );
        }

        let n = seed
            .peers
            .snapshot()
            .into_iter()
            .filter(|p| p.inbound && !p.subver.is_empty())
            .count();
        assert_eq!(
            n,
            1,
            "first inbound must stay; extra must be refused: {:?}",
            seed.peers.snapshot()
        );
        assert!(
            a.follow_live_count() >= 1,
            "first outbound follow must stay live"
        );
        assert_eq!(
            b.follow_live_count(),
            0,
            "rejected follow must not stay live"
        );

        seed.shutdown().await;
        a.shutdown().await;
        b.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("p2p_inbound_full_rejects_extra wall timeout (20s)");
}

/// Seeder restarts with empty RAM cache; peer IBD-syncs via reconstruct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serve_after_restart_via_reconstruct() {
    let fut = async {
        let _live = live_p2p_lock().await;
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
        pin_restart_empty_and_same_process_bq_residue(&seed);

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
    let wall = llvm_cov_wall(90, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("serve_after_restart_via_reconstruct wall timeout ({wall:?})"));
}

fn pin_restart_empty_and_same_process_bq_residue(seed: &P2PNode) {
    assert_eq!(
        seed.query.block_queue_count(),
        0,
        "restart RAM body queue is empty"
    );
    let tip = seed.hub.tip_height().expect("seed tip");
    let below = tip.saturating_sub(1);
    let below_hash = seed
        .query
        .header_at_height(Height(below))
        .unwrap()
        .expect("below-tip header")
        .1
        .hash;
    seed.query
        .block_queue_offer(below, below_hash, 0, b"stale")
        .unwrap();
    seed.query
        .block_queue_offer(tip + 1, [0xAB; 32], 0, b"")
        .unwrap();
    seed.query
        .block_queue_offer(tip + 2, [0xCD; 32], 0, b"wire")
        .unwrap();
    seed.query
        .block_queue_offer(u32::MAX, [0x11; 32], 0, b"unk")
        .unwrap();

    let n = rehydrate_block_queue_residue(&seed.hub).expect("same-process rehydrate");
    assert_eq!(n, 1, "only above-tip wire is ready");
    assert!(
        !seed.query.block_queue_has_height(below),
        "drop at/below tip"
    );
    assert!(
        !seed.query.block_queue_has_height(tip + 1),
        "empty payload skip"
    );
    assert!(
        seed.query.block_queue_has_height(tip + 2),
        "keep above-tip wire"
    );
    assert!(
        seed.query.block_queue_has_height(u32::MAX),
        "unknown height stays queued"
    );
    let _ = seed.query.block_queue_dequeue_height(tip + 2);
    let _ = seed.query.block_queue_dequeue_height(u32::MAX);
}

/// Mid-node serve after IBD: leaf syncs from mid, not the original seeder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_relay_path() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let d0 = TempDir::new().unwrap();
        let d1 = TempDir::new().unwrap();
        let d2 = TempDir::new().unwrap();

        let seed = start_node(&d0).await;
        seed_chain(&seed, 5).await;

        let mid = start_node(&d1).await;
        sync_ibd(&mid, seed.local_addr).await;
        mid.wait_height(5, Duration::from_secs(5)).await.unwrap();

        let leaf = start_node(&d2).await;
        sync_ibd(&leaf, mid.local_addr).await;
        leaf.wait_height(5, Duration::from_secs(5)).await.unwrap();

        assert_eq!(leaf.hub.tip_hash(), seed.hub.tip_hash());
        assert_eq!(leaf.query.tip_height(), Some(Height(5)));

        seed.shutdown().await;
        mid.shutdown().await;
        leaf.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("three_node_relay_path wall timeout ({wall:?})"));
}

/// IBD with two live seeder peers (8-block seed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ibd_two_peers() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let mid_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 8).await;

        let mid = start_node(&mid_dir).await;
        sync_ibd(&mid, seed.local_addr).await;
        mid.wait_height(8, Duration::from_secs(10)).await.unwrap();

        let client = start_node(&peer_dir).await;
        let n = client
            .sync(
                &[
                    rbitcoin_net::NetAddr::Ip(seed.local_addr),
                    rbitcoin_net::NetAddr::Ip(mid.local_addr),
                ],
                IbdConfig::for_test(),
            )
            .await
            .expect("ibd");
        assert!(n >= 8, "accepted {n}");
        client
            .wait_height(8, Duration::from_secs(10))
            .await
            .expect("tip");
        assert_eq!(client.query.tip_height(), Some(Height(8)));
        assert_eq!(client.hub.tip_hash().unwrap(), seed.hub.tip_hash().unwrap());

        seed.shutdown().await;
        mid.shutdown().await;
        client.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("ibd_two_peers wall timeout ({wall:?})"));
}

/// Multi-peer IBD: dead address + live seeder (dial book tries both). Slim (4 blocks).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_skips_dead_peer() {
    let _live = live_p2p_lock().await;
    let seed_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();

    let seed = start_node(&seed_dir).await;
    seed_chain(&seed, 4).await;

    let peer = start_node(&peer_dir).await;
    let bad: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let n = peer
        .sync(
            &[
                rbitcoin_net::NetAddr::Ip(bad),
                rbitcoin_net::NetAddr::Ip(seed.local_addr),
            ],
            IbdConfig::for_test(),
        )
        .await
        .expect("ibd with bad+good");
    assert!(n >= 4, "downloaded {n}");
    peer.wait_height(4, Duration::from_secs(5)).await.unwrap();

    seed.shutdown().await;
    peer.shutdown().await;
}

/// After IBD, seed announces a new tip; follower picks it up via inv/headers.
/// Basic filters wait for the materialize step, then seal each followed block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tip_follow_after_ibd() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 5).await;

        let mut peer = start_node(&peer_dir).await;
        peer.query.set_block_filter_index(true);
        sync_ibd(&peer, seed.local_addr).await;
        peer.wait_height(5, Duration::from_secs(10))
            .await
            .expect("ibd");
        assert_eq!(
            peer.query.basic_filter_hwm().unwrap(),
            None,
            "IBD confirm leaves basic filters to the materialize step"
        );
        peer.query
            .backfill_block_filters()
            .expect("materialize filters");
        assert_eq!(peer.query.basic_filter_hwm().unwrap(), Some(5));
        peer.follow_from(seed.local_addr).await.expect("follow");
        assert!(
            peer.follow_live_count() >= 1,
            "outbound follow session should be live"
        );

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
        assert_eq!(
            peer.query.basic_filter_hwm().unwrap(),
            Some(6),
            "tip follow seals the new block's filter"
        );

        seed.shutdown().await;
        peer.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("tip_follow_after_ibd wall timeout ({wall:?})"));
}

/// Blocks mined while disconnected are pulled via post-connect `getheaders`
/// (not only unsolicited inv/headers announces).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tip_follow_getheaders_catches_missed_blocks() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let seed_dir = TempDir::new().unwrap();
        let peer_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 5).await;

        let mut peer = start_node(&peer_dir).await;
        sync_ibd(&peer, seed.local_addr).await;
        peer.wait_height(5, Duration::from_secs(10))
            .await
            .expect("ibd");

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

        peer.follow_from(seed.local_addr).await.expect("follow");
        peer.wait_tip_hash(last, Duration::from_secs(15))
            .await
            .expect("getheaders gap fill");
        assert_eq!(peer.query.tip_height(), Some(Height(9)));
        assert_eq!(peer.follow_live_count(), 1);

        seed.shutdown().await;
        peer.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut).await.unwrap_or_else(|_| {
        panic!("tip_follow_getheaders_catches_missed_blocks wall timeout ({wall:?})")
    });
}

/// Most-work reorg — longer branch wins after disconnect/connect.
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
fn pin_competing_spend_extends_without_multi_fail(
    hub: &rbitcoin_net::ChainHub,
    cb1: bitcoin::Txid,
    fork_h: u32,
) {
    use bitcoin::Amount;
    use rbitcoin_net::AcceptOutcome;
    use rbitcoin_test::mine::spend_anyone_can_spend;

    let fork_rec = hub
        .query
        .header_at_height(Height(fork_h))
        .unwrap()
        .unwrap()
        .1;
    let fork_parent = BlockHash::from_byte_array(fork_rec.hash);
    let fork_time = fork_rec.timestamp;

    let spend_a = spend_anyone_can_spend(cb1, 0, Amount::from_sat(49_0000_0000));
    let main = mine_regtest_block(fork_parent, fork_time + 600, fork_h + 1, vec![spend_a]);
    hub.accept_block(main).unwrap();
    assert_eq!(hub.tip_height(), Some(fork_h + 1));

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

fn pin_precious_held_chaintips(hub: &rbitcoin_net::ChainHub, ext: bitcoin::Block, tip_h: u32) {
    use rbitcoin_net::AcceptOutcome;

    let tips = hub.chaintips();
    assert!(
        tips.iter()
            .any(|t| t.status == "active" && t.hash == ext.block_hash() && t.height == tip_h),
        "{tips:?}"
    );
    assert!(
        tips.iter().any(|t| t.status == "valid-fork"),
        "disconnected stem must be valid-fork: {tips:?}"
    );

    let p_prev = hub
        .query
        .header_at_height(Height(tip_h - 1))
        .unwrap()
        .unwrap()
        .1;
    let p_prev_hash = BlockHash::from_byte_array(p_prev.hash);
    let sibling = mine_regtest_block(p_prev_hash, p_prev.timestamp + 900, tip_h, vec![]);
    assert!(matches!(
        hub.accept_received_block(sibling.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&sibling.block_hash()).is_some());
    pin_held_sixteen_vs_seventeen(hub, p_prev_hash, p_prev.timestamp, tip_h);
    let tips = hub.chaintips();
    assert!(
        tips.iter()
            .any(|t| t.status == "valid-headers" && t.hash == sibling.block_hash()),
        "{tips:?}"
    );
    assert_eq!(hub.tip_hash().unwrap(), ext.block_hash());
    hub.precious_block(sibling.block_hash()).unwrap();
    assert_eq!(hub.tip_hash().unwrap(), sibling.block_hash());
    let h1 = BlockHash::from_byte_array(
        hub.query
            .header_at_height(Height(1))
            .unwrap()
            .unwrap()
            .1
            .hash,
    );
    hub.precious_block(h1).unwrap();
    assert_eq!(
        hub.tip_hash().unwrap(),
        sibling.block_hash(),
        "precious of less work must not activate"
    );
    let err = hub
        .precious_block(BlockHash::from_byte_array([0xab; 32]))
        .unwrap_err();
    assert!(err.to_string().contains("Block not found"), "{err}");
}

/// Product `HeldBodies` cap is 320; 16 vs 17 equal-work siblings all park.
/// FIFO eviction at the cap stays `hold_body_caps_fifo`.
fn pin_held_sixteen_vs_seventeen(
    hub: &rbitcoin_net::ChainHub,
    parent: BlockHash,
    timestamp: u32,
    height: u32,
) {
    use rbitcoin_net::AcceptOutcome;

    let mut hashes = Vec::with_capacity(17);
    for i in 0..17u32 {
        let b = mine_regtest_block(parent, timestamp.saturating_add(910 + i), height, vec![]);
        let h = b.block_hash();
        assert!(
            matches!(
                hub.accept_received_block(b).unwrap(),
                AcceptOutcome::IgnoredWeaker
            ),
            "equal-work sibling {i} must park"
        );
        hashes.push(h);
        assert!(
            hub.held_body(&h).is_some(),
            "sibling {i} must stay held (product cap 320)"
        );
    }
    assert!(
        hub.held_body(&hashes[0]).is_some(),
        "17th equal-work sibling must not FIFO-evict the first (cap 320)"
    );
    assert!(hub.held_body(&hashes[16]).is_some());
    assert!(hub.held_body_count() >= 17);
    let parked = hub
        .chaintips()
        .into_iter()
        .filter(|t| t.status == "valid-headers")
        .count();
    assert!(
        parked >= 16,
        "16 equal-work siblings as valid-headers, got {parked}"
    );
}

/// Same-height competing tip with more work wins; then multi-block reorg to a
/// longer side branch (tip-mode accept path, not IBD body-queue).
#[test]
fn reorg_same_height_then_multi_block_branch() {
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_net::{AcceptOutcome, ChainHub};
    use rbitcoin_test::pad_empty_from;

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let genesis = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_regtest_block(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
    let cb1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let last_pad = params.coinbase_maturity() + 1;
    pad_empty_from(&q, &params, b1.block_hash(), b1.header.time, 2, last_pad);
    let hub = ChainHub::new(q, params, Milestone::NONE);
    assert_eq!(hub.tip_height(), Some(last_pad));

    pin_competing_spend_extends_without_multi_fail(&hub, cb1, last_pad);
    let tip_h = hub.tip_height().unwrap();

    let parent_rec = hub
        .query
        .header_at_height(Height(tip_h - 1))
        .unwrap()
        .unwrap()
        .1;
    let parent = BlockHash::from_byte_array(parent_rec.hash);
    let t_parent = parent_rec.timestamp;

    let rival = mine_regtest_block(parent, t_parent + 900, tip_h, vec![]);
    let outcome = hub.accept_block(rival.clone()).unwrap();
    match outcome {
        AcceptOutcome::Accepted { height } if height == tip_h => {
            assert_eq!(hub.tip_hash().unwrap(), rival.block_hash());
        }
        AcceptOutcome::IgnoredWeaker => {
            assert_eq!(hub.tip_height(), Some(tip_h));
        }
        other => panic!("unexpected same-height outcome: {other:?}"),
    }

    let fork_parent_h = tip_h - 2;
    let fork_parent = hub
        .query
        .header_at_height(Height(fork_parent_h))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let mut p = BlockHash::from_byte_array(fork_parent);
    let mut t = hub
        .query
        .header_at_height(Height(fork_parent_h))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let mut branch = Vec::new();
    let lo = tip_h - 1;
    let hi = tip_h + 2;
    for h in lo..=hi {
        let b = mine_regtest_block(p, t + 700 + h, h, vec![]);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }
    let o = hub.accept_branch(&branch).unwrap();
    match o {
        AcceptOutcome::Accepted { height } => {
            assert_eq!(height, hi, "multi-block reorg to {hi}");
        }
        other => panic!("multi-block reorg to {hi}, got {other:?}"),
    }
    assert_eq!(hub.tip_height(), Some(hi));
    assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());

    let ext_h = hi + 1;
    let ext = mine_regtest_block(p, t + 600, ext_h, vec![]);
    match hub.accept_block(ext.clone()).unwrap() {
        AcceptOutcome::Accepted { height } => assert_eq!(height, ext_h),
        other => panic!("expected Accepted {ext_h}, got {other:?}"),
    }
    pin_precious_held_chaintips(&hub, ext, ext_h);
}

/// After catch-up (`initialblockdownload` false; `-maxtipage` so the 2011
/// pad is not stale), `-blocksonly` keeps `localrelay` / mempool relay off;
/// RPC `sendrawtransaction` is not the serving-only refuse.
async fn pin_blocksonly_relay_off_after_ibd(rpc_addr: SocketAddr) {
    use serde_json::json;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let bc = jsonrpc(rpc_addr, "getblockchaininfo", json!([])).await;
        if bc["result"]["initialblockdownload"] == false {
            break;
        }
        if Instant::now() >= deadline {
            panic!("IBD never cleared after height 3: {bc}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let net = jsonrpc(rpc_addr, "getnetworkinfo", json!([])).await;
    assert_eq!(net["result"]["localrelay"], false, "{net}");
    let mem = jsonrpc(rpc_addr, "getmempoolinfo", json!([])).await;
    assert_eq!(mem["result"]["relay_enabled"], false, "{mem}");
    let raw = jsonrpc(rpc_addr, "sendrawtransaction", json!(["00"])).await;
    let msg = raw["error"]["message"].as_str().unwrap_or("");
    assert!(
        !msg.contains("relay disabled"),
        "RPC sendraw must admit while -blocksonly, got {raw}"
    );
}

async fn pin_blocksonly_electrum_esplora_broadcast(
    electrum_addr: SocketAddr,
    esplora_addr: SocketAddr,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use serde_json::json;

    let junk = electrum_rpc(
        electrum_addr,
        "blockchain.transaction.broadcast",
        json!(["zz"]),
    )
    .await;
    let junk_msg = junk["error"]["message"].as_str().unwrap_or("");
    assert!(
        !junk_msg.contains("mempool not available") && !junk_msg.contains("relay disabled"),
        "electrum broadcast must admit (decode), got {junk}"
    );
    assert!(
        junk_msg.contains("hex") || junk_msg.contains("Invalid") || junk["error"].is_object(),
        "non-hex electrum broadcast: {junk}"
    );

    let miss = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let miss_hex = serialize_hex(&miss);
    let bad = electrum_rpc(
        electrum_addr,
        "blockchain.transaction.broadcast",
        json!([miss_hex]),
    )
    .await;
    let bad_msg = bad["error"]["message"].as_str().unwrap_or("");
    assert!(
        bad_msg.contains("broadcast reject"),
        "electrum consensus-invalid must hit hub, got {bad}"
    );
    assert!(
        !bad_msg.contains("mempool not available") && !bad_msg.contains("relay disabled"),
        "electrum broadcast hub-attached: {bad}"
    );

    let (st, body) = http_post(esplora_addr, "/tx", "zz").await;
    assert_ne!(
        st, 503,
        "esplora POST /tx must not be hub-missing: {st} {body}"
    );
    assert!(
        !body.contains("mempool not available") && !body.contains("relay disabled"),
        "esplora POST /tx junk: {st} {body}"
    );
    let (st, body) = http_post(esplora_addr, "/tx", &miss_hex).await;
    assert_ne!(st, 503, "esplora POST /tx must hit hub: {st} {body}");
    assert!(
        !body.contains("mempool not available") && !body.contains("relay disabled"),
        "esplora POST /tx consensus-invalid: {st} {body}"
    );
    assert_eq!(st, 400, "esplora reject is 400, got {st} {body}");
}

/// Seeder inbound `tx` after IBD is a protocol violation (`p2p_blocksonly`).
async fn pin_blocksonly_seeder_tx_disconnects(
    rpc_addr: SocketAddr,
    seed_peers: &rbitcoin_net::PeerHub,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use serde_json::json;
    use std::time::Instant;

    let dummy = Transaction {
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
    wait_ms_until(
        3_000,
        || {
            seed_peers.live_peers().into_iter().any(|p| {
                p.inbound
                    && p.handshake_complete()
                    && p.queue_msg(NetworkMessage::Tx(dummy.clone()))
            })
        },
        || {
            format!(
                "seed inbound must queue unsolicited tx (seed={:?})",
                seed_peers.snapshot()
            )
        },
    )
    .await;
    let gone_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let peers = jsonrpc(rpc_addr, "getpeerinfo", json!([])).await;
        if peers["result"].as_array().is_some_and(|a| a.is_empty()) {
            break;
        }
        if Instant::now() >= gone_deadline {
            panic!("blocksonly node still connected after unsolicited tx: {peers}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Product `run_p2p --blocksonly`: `--connect` to a live seeder; process RPC
/// while connected. `max_run_secs=0` stays a node-crate unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_run_p2p_short() {
    let fut = async {
        let _live = live_p2p_lock().await;
        use rbitcoin_node::{run_p2p, NodeConfig};
        use rbitcoin_primitives::Network;
        use serde_json::json;
        use std::time::Instant;

        let seed_dir = TempDir::new().unwrap();
        let node_dir = TempDir::new().unwrap();

        let seed = start_node(&seed_dir).await;
        seed_chain(&seed, 3).await;
        let seed_addr = seed.local_addr;
        let rpc_addr = ephemeral_addr();
        let electrum_addr = ephemeral_addr();
        let esplora_addr = ephemeral_addr();

        let mut cfg = NodeConfig::default()
            .with_datadir(node_dir.path())
            .with_network(Network::Regtest)
            .with_p2p_listen("127.0.0.1:0".parse().unwrap())
            .with_tiny_heads();
        cfg.listen.connect = vec![NetAddr::Ip(seed_addr)];
        cfg.listen.use_seeds = false;
        cfg.listen.electrum = Some(electrum_addr);
        cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora_addr));
        cfg.shindex = true;
        cfg.rpc.listen = Some(rpc_addr);
        std::fs::write(node_dir.path().join("rpc.token"), "pass").unwrap();
        cfg.max_run_secs = Some(60);
        cfg.mempool.blocksonly = true;
        cfg.max_tip_age_secs = Some(u64::MAX);

        let seed_peers = seed.peers.clone();
        let pin = tokio::spawn(async move {
            wait_listeners(&[rpc_addr, electrum_addr, esplora_addr]).await;

            let deadline = Instant::now() + Duration::from_secs(20);
            let mut count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
            while count["result"] != 3 {
                if Instant::now() >= deadline {
                    panic!("getblockcount never reached 3: {count}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
            }

            let peers = jsonrpc(rpc_addr, "getpeerinfo", json!([])).await;
            let rows = peers["result"].as_array().expect("getpeerinfo array");
            assert_eq!(rows.len(), 1, "{peers}");
            assert_eq!(rows[0]["inbound"], false, "{peers}");
            assert_eq!(rows[0]["connection_type"], "outbound-full-relay", "{peers}");
            assert_eq!(rows[0]["transport_protocol_type"], "v2", "{peers}");
            assert!(
                rows[0]["bytesrecv"].as_u64().unwrap_or(0) > 0,
                "IBD must receive bytes: {peers}"
            );
            let addr = rows[0]["addr"].as_str().expect("addr").to_string();
            assert_eq!(addr, seed_addr.to_string(), "{peers}");
            assert!(
                rows[0]["startingheight"].as_i64().unwrap() >= 0,
                "handshake-complete startingheight must not be connecting dummy -1: {peers}"
            );
            assert!(
                rows[0]["timeoffset"].as_i64().is_some(),
                "peer timeoffset: {peers}"
            );
            assert_eq!(
                rows[0]["startingheight"].as_i64(),
                Some(3),
                "VERSION start_height is the seeder tip: {peers}"
            );
            assert_eq!(
                rows[0]["synced_headers"].as_i64(),
                Some(-1),
                "empty getheaders at tip does not set best_known: {peers}"
            );
            assert_eq!(
                rows[0]["synced_blocks"].as_i64(),
                Some(-1),
                "synced_blocks follows best_known, not startingheight: {peers}"
            );
            assert!(
                rows[0]["servicesnames"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "servicesnames: {peers}"
            );

            let n = jsonrpc(rpc_addr, "getconnectioncount", json!([])).await;
            assert_eq!(n["result"], 1, "{n}");
            let net = jsonrpc(rpc_addr, "getnetworkinfo", json!([])).await;
            assert_eq!(net["result"]["connections"], 1, "{net}");
            assert_eq!(net["result"]["connections_out"], 1, "{net}");
            assert!(
                net["result"]["timeoffset"].as_i64().is_some(),
                "getnetworkinfo.timeoffset: {net}"
            );
            let totals = jsonrpc(rpc_addr, "getnettotals", json!([])).await;
            assert!(
                totals["result"]["totalbytesrecv"].as_u64().unwrap_or(0) > 0,
                "{totals}"
            );
            let ping = jsonrpc(rpc_addr, "ping", json!([])).await;
            assert!(ping["result"].is_null(), "{ping}");
            pin_blocksonly_relay_off_after_ibd(rpc_addr).await;
            pin_blocksonly_electrum_esplora_broadcast(electrum_addr, esplora_addr).await;

            let inbound = jsonrpc(
                rpc_addr,
                "addconnection",
                json!([seed_addr.to_string(), "inbound"]),
            )
            .await;
            assert!(
                inbound["error"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("cannot create inbound"),
                "{inbound}"
            );

            let miss_id = jsonrpc(rpc_addr, "disconnectnode", json!({"nodeid": 99})).await;
            assert!(miss_id["error"].is_object(), "unknown nodeid: {miss_id}");
            let miss_empty = jsonrpc(rpc_addr, "disconnectnode", json!([])).await;
            assert!(
                miss_empty["error"].is_object(),
                "empty disconnectnode: {miss_empty}"
            );

            let disc = jsonrpc(rpc_addr, "disconnectnode", json!([addr.clone()])).await;
            assert!(disc["error"].is_null(), "{disc}");
            let gone_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let peers = jsonrpc(rpc_addr, "getpeerinfo", json!([])).await;
                if peers["result"].as_array().is_some_and(|a| a.is_empty()) {
                    break;
                }
                if Instant::now() >= gone_deadline {
                    panic!("getpeerinfo still occupied after disconnectnode: {peers}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            let added = jsonrpc(
                rpc_addr,
                "addnode",
                json!([seed_addr.to_string(), "onetry"]),
            )
            .await;
            assert!(added["error"].is_null(), "{added}");
            let re_deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let peers = jsonrpc(rpc_addr, "getpeerinfo", json!([])).await;
                let ok = peers["result"].as_array().is_some_and(|rows| {
                    rows.iter()
                        .any(|p| p["inbound"] == false && p["connection_type"] == "manual")
                });
                if ok {
                    break;
                }
                if Instant::now() >= re_deadline {
                    panic!("addnode onetry did not produce a manual peer: {peers}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            pin_blocksonly_seeder_tx_disconnects(rpc_addr, &seed_peers).await;
            let _ = jsonrpc(rpc_addr, "stop", json!([])).await;
        });

        run_p2p(cfg).await.expect("run_p2p");
        match pin.await {
            Ok(()) => {}
            Err(e) => panic!("rpc pin join: {e}"),
        }

        let q = Query::open_or_create_tiny(node_dir.path().join("store")).unwrap();
        assert_eq!(q.tip_height(), Some(Height(3)));

        seed.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("node_run_p2p_short wall timeout ({wall:?})"));
}

/// `feature_bip68_sequence` unconfirmed-inputs: 10× `setmocktime(+600)` plus
/// generate must not ping-timeout a peer that pongs on localhost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mocktime_generate_keeps_ponging_peer() {
    let fut = async {
        let _live = live_p2p_lock().await;
        let a_dir = TempDir::new().unwrap();
        let b_dir = TempDir::new().unwrap();
        let a = start_node(&a_dir).await;
        let mut b = start_node(&b_dir).await;
        tokio::time::timeout(Duration::from_secs(5), b.follow_from(a.local_addr))
            .await
            .expect("follow")
            .expect("handshake");
        wait_ms_until(
            3_000,
            || !a.peers.snapshot().is_empty() && !b.peers.snapshot().is_empty(),
            || {
                format!(
                    "connected a={:?} b={:?}",
                    a.peers.snapshot(),
                    b.peers.snapshot()
                )
            },
        )
        .await;

        let t0 = a.peers.now_secs();
        let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        for i in 1..=10u64 {
            a.peers.set_mock_now(t0 + i * 600);
            let hub = a.hub.clone();
            let script = script.clone();
            tokio::task::spawn_blocking(move || {
                let _g = rbitcoin_net::BlockingRegion::enter();
                hub.generate_to_script(1, script, vec![]).expect("generate");
            })
            .await
            .expect("join");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !a.peers.snapshot().is_empty(),
            "miner must keep the ponging peer after 6000s mocktime+generate: {:?}",
            a.peers.snapshot()
        );
        assert!(
            !b.peers.snapshot().is_empty(),
            "follower must stay connected: {:?}",
            b.peers.snapshot()
        );
        a.shutdown().await;
        b.shutdown().await;
    };
    let wall = llvm_cov_wall(60, 180);
    tokio::time::timeout(wall, fut)
        .await
        .unwrap_or_else(|_| panic!("mocktime_generate_keeps_ponging_peer wall timeout ({wall:?})"));
}
