//! Labeled overlay-functional journeys over private Tor / i2pd / cjdns meshes.
//!
//! Default `cargo test` never builds this binary. Run only via
//! `./scripts/overlay-functional/run.sh`.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Amount;
use rbitcoin_net::{NetAddr, OnlyNet};
use rbitcoin_node::{NodeConfig, P2pListen};
use rbitcoin_test::mine::spend_anyone_can_spend;
use rbitcoin_test::overlay::{
    base_node, ephemeral_addr, i2p_b32_from_dest, jsonrpc, jsonrpc_try, localaddresses,
    require_env, socks_electrum_rpc, socks_http_get, spawn_node, wait_file, wait_i2p_stream,
    wait_jsonrpc, wait_onion_port, wait_p2p_onion, wait_peer_network, wait_socks_onion,
    write_rpc_token, OverlayEnv,
};
use rbitcoin_test::TempDir;
use serde_json::json;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tor_b(env: &OverlayEnv, datadir: &std::path::Path, rpc: SocketAddr) -> NodeConfig {
    write_rpc_token(datadir);
    let mut cfg = base_node(datadir);
    cfg.listen.p2p = P2pListen::Off;
    cfg.listen.listen_onion = true;
    cfg.tor.control = Some(env.tor_control);
    cfg.tor.cookie = Some(env.tor_cookie.clone());
    cfg.rpc.listen = Some(rpc);
    cfg
}

fn tor_a(
    env: &OverlayEnv,
    datadir: &std::path::Path,
    rpc: SocketAddr,
    onion: &str,
    port: u16,
) -> NodeConfig {
    write_rpc_token(datadir);
    let mut cfg = base_node(datadir);
    cfg.listen.p2p = P2pListen::Off;
    cfg.listen.proxy = Some(env.tor_socks);
    cfg.listen.only_net = vec![OnlyNet::Onion];
    cfg.listen.connect = vec![format!("{onion}:{port}").parse::<NetAddr>().unwrap()];
    cfg.rpc.listen = Some(rpc);
    cfg
}

async fn generate_n(rpc: SocketAddr, n: u32) {
    let r = jsonrpc(rpc, "generate", json!([n])).await;
    assert!(r["error"].is_null(), "generate: {r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_onion_two_node_v2() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let b = spawn_node(tor_b(&env, b_dir.path(), b_rpc), b_rpc).await;
    generate_n(b_rpc, 3).await;
    let (onion, port) = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let a = spawn_node(tor_a(&env, a_dir.path(), a_rpc, &onion, port), a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(90),
        |v| v["result"] == 3,
    )
    .await;
    let peers = wait_peer_network(a_rpc, "onion", false, Duration::from_secs(30)).await;
    let row = &peers["result"].as_array().unwrap()[0];
    assert_eq!(row["network"], "onion", "{peers}");
    assert_eq!(row["inbound"], false, "{peers}");
    assert_eq!(row["transport_protocol_type"], "v2", "{peers}");
    assert!(row["addr"].as_str().unwrap().contains(".onion"), "{peers}");
    assert_ne!(row["addr"], "0.0.0.0", "{peers}");

    let bin = wait_peer_network(b_rpc, "ipv4", true, Duration::from_secs(30)).await;
    let brow = bin["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["inbound"] == true)
        .expect("B inbound");
    assert_eq!(brow["transport_protocol_type"], "v2", "{bin}");

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_wallet_hs_electrum_esplora() {
    let env = require_env();
    let dir = TempDir::new().unwrap();
    let rpc = ephemeral_addr();
    let electrum = ephemeral_addr();
    let esplora = ephemeral_addr();

    write_rpc_token(dir.path());
    let mut cfg = tor_b(&env, dir.path(), rpc);
    cfg.listen.electrum = Some(electrum);
    cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora));
    cfg.electrum_onion = true;
    cfg.esplora_onion = true;
    cfg.shindex = true;
    let node = spawn_node(cfg, rpc).await;
    generate_n(rpc, 1).await;

    let e_host = wait_onion_port(rpc, electrum.port(), Duration::from_secs(90)).await;
    wait_socks_onion(
        env.tor_socks,
        &e_host,
        electrum.port(),
        Duration::from_secs(90),
    )
    .await;
    let s_host = wait_onion_port(rpc, esplora.port(), Duration::from_secs(90)).await;
    wait_socks_onion(
        env.tor_socks,
        &s_host,
        esplora.port(),
        Duration::from_secs(90),
    )
    .await;

    let features = socks_electrum_rpc(
        env.tor_socks,
        &e_host,
        electrum.port(),
        "server.features",
        json!([]),
    )
    .await;
    let hosts = &features["result"]["hosts"];
    assert!(
        hosts
            .get(&e_host)
            .is_some_and(|h| h["tcp_port"] == electrum.port()),
        "features.hosts: {features}"
    );
    assert!(
        hosts.get(&e_host).and_then(|h| h.get("ssl_port")).is_none(),
        "ssl_port must stay unset: {features}"
    );

    let (st, body) =
        socks_http_get(env.tor_socks, &s_host, esplora.port(), "/blocks/tip/height").await;
    assert_eq!(st, 200, "esplora GET {body}");
    assert_eq!(body.trim(), "1", "tip height: {body}");

    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i2p_sam_two_node() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(ephemeral_addr());
    cfg_b.listen.i2p_sam = Some(env.i2p_sam_b);
    cfg_b.listen.i2p_accept_incoming = true;
    cfg_b.listen.only_net = vec![OnlyNet::I2p];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b, b_rpc).await;
    generate_n(b_rpc, 3).await;

    let dest = wait_file(
        &b_dir.path().join("i2p").join("p2p.priv"),
        Duration::from_secs(180),
    )
    .await;
    let again = std::fs::read_to_string(b_dir.path().join("i2p").join("p2p.priv")).unwrap();
    assert_eq!(dest, again.trim(), "persistent dest round-trip");
    let b32 = i2p_b32_from_dest(&dest);
    let info = jsonrpc(b_rpc, "getnetworkinfo", json!([])).await;
    let published = localaddresses(&info)
        .iter()
        .find(|r| {
            r["address"]
                .as_str()
                .is_some_and(|a| a.ends_with(".b32.i2p"))
        })
        .unwrap_or_else(|| panic!("i2p local address missing: {info}"));
    assert_eq!(published["address"], b32, "{info}");
    assert_eq!(published["port"], 0, "SAM 3.1 port is 0: {info}");
    let dest_addr: NetAddr = format!("{b32}:0").parse().unwrap();
    wait_i2p_stream(env.i2p_sam, &b32, Duration::from_secs(180)).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Off;
    cfg_a.listen.i2p_sam = Some(env.i2p_sam);
    cfg_a.listen.only_net = vec![OnlyNet::I2p];
    cfg_a.listen.connect = vec![dest_addr];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(180),
        |v| v["result"] == 3,
    )
    .await;
    let peers = wait_peer_network(a_rpc, "i2p", false, Duration::from_secs(60)).await;
    assert_eq!(peers["result"][0]["network"], "i2p", "{peers}");
    assert_eq!(
        peers["result"][0]["transport_protocol_type"], "v2",
        "{peers}"
    );
    let addr = peers["result"][0]["addr"].as_str().unwrap_or("");
    assert!(
        addr.starts_with(&b32) && addr.ends_with(":0"),
        "dialed peer must be the published dest: {peers}"
    );
    let addrv2 = peers["result"][0]["bytesrecv_per_msg"]["addrv2"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        addrv2 > 0,
        "inbound I2P node must addrv2 its destination: {peers}"
    );

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cjdns_tun_two_node() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let b_p2p = {
        let l = std::net::TcpListener::bind((env.cjdns_b, 0)).unwrap_or_else(|e| {
            panic!("bind {} (TUN missing?): {e}", env.cjdns_b);
        });
        l.local_addr().unwrap()
    };
    let a_p2p = {
        let l = std::net::TcpListener::bind((env.cjdns_a, 0)).unwrap_or_else(|e| {
            panic!("bind {} (TUN missing?): {e}", env.cjdns_a);
        });
        l.local_addr().unwrap()
    };

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(b_p2p);
    cfg_b.listen.cjdns_reachable = true;
    cfg_b.listen.discover = true;
    cfg_b.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b, b_rpc).await;
    generate_n(b_rpc, 3).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Socket(a_p2p);
    cfg_a.listen.cjdns_reachable = true;
    cfg_a.listen.discover = true;
    cfg_a.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_a.listen.connect = vec![NetAddr::from_str(&b_p2p.to_string()).unwrap()];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(30),
        |v| v["result"] == 3,
    )
    .await;
    let peers = wait_peer_network(a_rpc, "cjdns", false, Duration::from_secs(20)).await;
    assert_eq!(peers["result"][0]["network"], "cjdns", "{peers}");
    assert_eq!(
        peers["result"][0]["transport_protocol_type"], "v2",
        "{peers}"
    );
    let bin = wait_peer_network(b_rpc, "cjdns", true, Duration::from_secs(20)).await;
    assert!(
        bin["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["inbound"] == true && p["network"] == "cjdns"),
        "{bin}"
    );
    let binfo = jsonrpc(b_rpc, "getnetworkinfo", json!([])).await;
    assert!(
        localaddresses(&binfo)
            .iter()
            .any(|r| { r["address"] == env.cjdns_b.to_string() && r["port"] == b_p2p.port() }),
        "cjdns listen must be a local address: {binfo}"
    );
    let ainfo = jsonrpc(a_rpc, "getnetworkinfo", json!([])).await;
    assert!(
        localaddresses(&ainfo)
            .iter()
            .any(|r| { r["address"] == env.cjdns_a.to_string() && r["port"] == a_p2p.port() }),
        "cjdns listen must be a local address: {ainfo}"
    );

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_socks_isolated_broadcast() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let b = spawn_node(tor_b(&env, b_dir.path(), b_rpc), b_rpc).await;
    generate_n(b_rpc, 101).await;
    let (onion, port) = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let a = spawn_node(tor_a(&env, a_dir.path(), a_rpc, &onion, port), a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(90),
        |v| v["result"] == 101,
    )
    .await;
    wait_peer_network(a_rpc, "onion", false, Duration::from_secs(30)).await;

    let hash = jsonrpc(b_rpc, "getblockhash", json!([1])).await["result"]
        .as_str()
        .unwrap()
        .to_string();
    let blk = jsonrpc(b_rpc, "getblock", json!([hash, 2])).await;
    let coinbase = blk["result"]["tx"][0]["txid"].as_str().unwrap();
    let txid = bitcoin::Txid::from_str(coinbase).unwrap();
    let spend = spend_anyone_can_spend(txid, 0, Amount::from_sat(4_999_990_000));
    let hex = serialize_hex(&spend);
    let sent = jsonrpc(a_rpc, "sendrawtransaction", json!([hex])).await;
    assert!(sent["error"].is_null(), "sendrawtransaction: {sent}");
    let want = spend.compute_txid().to_string();

    tokio::time::sleep(Duration::from_millis(400)).await;
    let standing = jsonrpc(a_rpc, "getpeerinfo", json!([])).await;
    for p in standing["result"].as_array().unwrap() {
        let inv = p["bytessent_per_msg"]
            .get("inv")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert_eq!(inv, 0, "standing session must not INV local tx: {standing}");
    }

    wait_jsonrpc(
        b_rpc,
        "getrawmempool",
        json!([]),
        Duration::from_secs(90),
        |v| {
            v["result"]
                .as_array()
                .is_some_and(|m| m.iter().any(|t| t == &want))
        },
    )
    .await;

    a.stop().await;
    b.stop().await;
}

#[tokio::test]
#[should_panic(expected = "rpc getblockcount json:")]
async fn jsonrpc_try_panics_when_the_body_is_not_json() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope";
        sock.write_all(resp).await.unwrap();
    });
    let _ = jsonrpc_try(addr, "getblockcount", serde_json::json!([])).await;
}
