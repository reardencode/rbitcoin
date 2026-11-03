//! Post-catch-up outbound full-relay refill up to `--max-outbound`.
//!
//! Drives `run_p2p` against one local listener. Routable addresses are required
//! in the address book, so the body runs in its own process, and in a network
//! namespace when the machine allows one. That listener binds `0.0.0.0` and
//! the book lists each `45.x.0.1` on its port. One store reserves a 256 MiB
//! map; a store per address does not fit the suite runner's 6 GiB hard cap.

use bitcoin::Block;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::{AddrMan, NetAddr, P2PNode};
use rbitcoin_node::{run_p2p, NodeConfig, NodeError, P2pListen};
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};
use rbitcoin_test::TestDatadir;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const MAX_OUT: u32 = 5;
/// One seed plus enough other listeners that a `getaddr` reply (23% of the
/// book, at least one) is more than 3 addresses.
const LEARNED_PEERS: usize = 18;

fn llvm_cov_wall(default_secs: u64, llvm_secs: u64) -> Duration {
    if std::env::var_os("CARGO_LLVM_COV").is_some() {
        Duration::from_secs(llvm_secs)
    } else {
        Duration::from_secs(default_secs)
    }
}

fn ip_output(args: &[String]) -> Output {
    let direct = Command::new("ip").args(args).output();
    if let Ok(out) = direct {
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || err.contains("File exists") {
            return out;
        }
    }
    let mut sudo_args = vec!["-n".to_string(), "ip".to_string()];
    sudo_args.extend(args.iter().cloned());
    Command::new("sudo")
        .args(&sudo_args)
        .output()
        .unwrap_or_else(|e| panic!("ip {args:?} failed and sudo is unavailable: {e}"))
}

fn ip_ok(args: &[String]) {
    let out = ip_output(args);
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || err.contains("File exists") {
        return;
    }
    panic!("ip {args:?} -> {} {err}", out.status);
}

/// Addresses added on the host `lo`. A netns child leaves them: the namespace
/// dies with the process.
struct HostLo {
    ips: Vec<Ipv4Addr>,
    host: bool,
}

impl Drop for HostLo {
    fn drop(&mut self) {
        if !self.host {
            return;
        }
        for ip in &self.ips {
            let cidr = format!("{ip}/32");
            let _ = ip_output(&["addr".into(), "del".into(), cidr, "dev".into(), "lo".into()]);
        }
    }
}

fn routable_locals(n: u8) -> (Vec<Ipv4Addr>, HostLo) {
    let host = std::env::var_os("RBITCOIN_REFILL_NS").is_none();
    let mut guard = HostLo {
        ips: Vec::new(),
        host,
    };
    ip_ok(&["link".into(), "set".into(), "lo".into(), "up".into()]);
    let mut ips = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let ip: Ipv4Addr = format!("45.{i}.0.1").parse().expect("ip");
        let cidr = format!("{ip}/32");
        ip_ok(&["addr".into(), "add".into(), cidr, "dev".into(), "lo".into()]);
        if host {
            guard.ips.push(ip);
        }
        ips.push(ip);
    }
    (ips, guard)
}

fn user_netns_available() -> bool {
    Command::new("unshare")
        .args(["--net", "--user", "--map-root-user", "--", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn two_blocks() -> Vec<Block> {
    let genesis = regtest_genesis();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as u32;
    let first = mine_regtest_block(genesis.block_hash(), now, 1, vec![]);
    let second = mine_regtest_block(first.block_hash(), now.saturating_add(1), 2, vec![]);
    vec![first, second]
}

/// One store, one `0.0.0.0` socket. Each routable local uses that port.
/// A socket bound to one `45.x` address would not accept the others.
async fn listen_shared(
    dir: &Path,
    ips: &[Ipv4Addr],
    blocks: &[Block],
) -> (P2PNode, Vec<SocketAddr>) {
    let query = Query::open_or_create_tiny(dir.join("listener")).expect("listener store");
    let node = P2PNode::start(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap_or_else(|e| panic!("listen: {e}"));
    for (h, block) in blocks.iter().enumerate() {
        node.ingest_block(block.clone())
            .unwrap_or_else(|e| panic!("ingest block {}: {e}", h + 1));
    }
    let port = node.local_addr.port();
    let addrs = ips.iter().map(|ip| SocketAddr::from((*ip, port))).collect();
    (node, addrs)
}

fn write_book(dir: &Path, addrs: &[SocketAddr]) {
    let mut book = AddrMan::new();
    for addr in addrs {
        book.add(*addr);
    }
    assert_eq!(book.len(), addrs.len(), "routable book rows");
    book.save(&dir.join("peers")).expect("peers file");
}

fn token(dir: &Path) {
    std::fs::create_dir_all(dir).expect("datadir");
    let path = dir.join("rpc.token");
    std::fs::write(&path, "pass").expect("rpc token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("token mode");
    }
}

fn base_cfg(dir: &Path) -> NodeConfig {
    token(dir);
    let mut cfg = NodeConfig::default()
        .with_datadir(dir)
        .with_network(Network::Regtest)
        .with_tiny_heads();
    cfg.listen.p2p = P2pListen::Off;
    cfg.listen.p2p_explicit = true;
    cfg.listen.use_seeds = false;
    cfg.listen.discover = false;
    cfg.listen.max_inbound = 0;
    cfg.listen.max_outbound = MAX_OUT;
    cfg.rpc.listen = Some("127.0.0.1:0".parse().expect("rpc"));
    cfg.max_tip_age_secs = Some(u64::MAX);
    cfg.connect_redial = rbitcoin_net::REDIAL_INTERVAL_TEST;
    cfg
}

fn published(dir: &Path, name: &str) -> PathBuf {
    dir.join("run").join(format!("{name}.addr"))
}

async fn published_listener(
    dir: &Path,
    name: &str,
    wait: Duration,
    join: &mut JoinHandle<Result<(), NodeError>>,
) -> SocketAddr {
    let path = published(dir, name);
    tokio::select! {
        biased;
        addr = rbitcoin_node::run::wait_published_listener(dir, name, wait) => addr,
        result = &mut *join => match result {
            Ok(Ok(())) => panic!("{name} exited before publishing {}", path.display()),
            Ok(Err(e)) => panic!("{name} exited before publishing {}: {e}", path.display()),
            Err(e) => panic!("{name} task ended before publishing {}: {e}", path.display()),
        },
    }
}

fn spawn_run(cfg: NodeConfig) -> JoinHandle<Result<(), NodeError>> {
    match std::fs::remove_dir_all(cfg.datadir.path().join("run")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("clear published listeners: {e}"),
    }
    tokio::task::spawn_blocking(move || {
        let _block = rbitcoin_net::BlockingRegion::enter();
        tokio::runtime::Handle::current().block_on(run_p2p(cfg))
    })
}

async fn peer_rows(rpc: SocketAddr) -> Vec<Value> {
    let v = rbitcoin_test::jsonrpc::try_jsonrpc(rpc, "getpeerinfo", json!([])).await;
    let Ok(v) = v else {
        return Vec::new();
    };
    v["result"].as_array().cloned().unwrap_or_default()
}

/// One kind from `outboundpass`. `0` until that pass has been recorded.
async fn outbound_pass_count(rpc: SocketAddr, key: &str) -> u64 {
    let Ok(v) = rbitcoin_test::jsonrpc::try_jsonrpc(rpc, "outboundpass", json!([])).await else {
        return 0;
    };
    if !v["error"].is_null() {
        return 0;
    }
    v["result"][key].as_u64().unwrap_or(0)
}

fn conn_type(row: &Value) -> &str {
    row["connection_type"].as_str().unwrap_or("")
}

fn full_relay(rows: &[Value]) -> Vec<&Value> {
    rows.iter()
        .filter(|row| conn_type(row) == "outbound-full-relay")
        .collect()
}

fn type_list(rows: &[Value]) -> String {
    rows.iter().map(conn_type).collect::<Vec<_>>().join(",")
}

fn ids_of(rows: &[&Value]) -> BTreeSet<u64> {
    rows.iter().filter_map(|row| row["id"].as_u64()).collect()
}

/// Count of live `outbound-full-relay` rows. A short stall is not a shortfall:
/// only the deadline fails a count that never reaches `want`.
async fn wait_full_relay(rpc: SocketAddr, want: usize, max_out: usize) -> Vec<Value> {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(25);
    loop {
        let rows = peer_rows(rpc).await;
        let n = full_relay(&rows).len();
        assert!(
            n <= max_out,
            "outbound-full-relay {n} exceeded --max-outbound {max_out}: {}",
            type_list(&rows)
        );
        if n >= want {
            assert_eq!(n, want, "live outbound-full-relay must equal the quota");
            return rows;
        }
        if Instant::now() >= deadline {
            panic!(
                "outbound-full-relay still {n} after {}s, want {want}; types=[{}]",
                start.elapsed().as_secs(),
                type_list(&rows)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop_node(rpc: SocketAddr, join: JoinHandle<Result<(), NodeError>>) {
    let _ = rbitcoin_test::jsonrpc::try_jsonrpc(rpc, "stop", json!([])).await;
    let joined = tokio::time::timeout(Duration::from_secs(30), join).await;
    match joined {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => panic!("run_p2p: {e}"),
        Ok(Err(e)) => panic!("run_p2p join: {e}"),
        Err(_) => panic!("run_p2p did not stop"),
    }
}

async fn book_refill(root: &Path, addrs: &[SocketAddr]) {
    let dir = root.join("book");
    write_book(&dir, addrs);
    let cfg = base_cfg(&dir);
    let mut join = spawn_run(cfg);
    let rpc = published_listener(&dir, "rpc", Duration::from_secs(40), &mut join).await;
    let rows = wait_full_relay(rpc, MAX_OUT as usize, MAX_OUT as usize).await;
    let before = ids_of(&full_relay(&rows));
    assert!(
        before.len() > 3,
        "first post-catch-up dial must exceed 3 outbound-full-relay, got {}",
        type_list(&rows)
    );
    assert_eq!(before.len(), MAX_OUT as usize);
    for id in &before {
        let _ = rbitcoin_test::jsonrpc::try_jsonrpc(rpc, "disconnectnode", json!(["", id])).await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rows = peer_rows(rpc).await;
        let live = full_relay(&rows);
        let ids = ids_of(&live);
        let n = live.len();
        assert!(
            n <= MAX_OUT as usize,
            "refill grew past --max-outbound: {}",
            type_list(&rows)
        );
        let old_gone = before.iter().all(|id| !ids.contains(id));
        if n == MAX_OUT as usize && old_gone {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "after disconnect outbound-full-relay={n} (want {MAX_OUT} with the old ids gone) without a stale-tip wait; types=[{}]",
                type_list(&rows)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_node(rpc, join).await;
}

async fn learned_book(root: &Path, seed: &P2PNode, seed_addr: SocketAddr, others: &[SocketAddr]) {
    let mut book = AddrMan::new();
    for addr in others {
        book.add(*addr);
    }
    let expect = (others.len() * rbitcoin_net::peer::MAX_PCT_ADDR_TO_SEND / 100).max(1);
    assert!(
        expect > 3,
        "seed book must make getaddr return more than 3 addresses"
    );
    assert_eq!(
        book.len(),
        others.len(),
        "seed must advertise the other listeners"
    );
    seed.peers
        .set_addrman(std::sync::Arc::new(std::sync::Mutex::new(book)));
    let dir = root.join("fetch");
    let mut cfg = base_cfg(&dir);
    cfg.listen.seednodes = vec![seed_addr.to_string()];
    let mut join = spawn_run(cfg);
    let rpc = published_listener(&dir, "rpc", Duration::from_secs(40), &mut join).await;
    // getaddr returns 23% of the book. Every returned row is dialed as
    // outbound-full-relay; the seed session itself stays addr-fetch.
    let rows = wait_learned_relay(rpc, others, MAX_OUT as usize, expect).await;
    let want: std::collections::BTreeSet<String> =
        others.iter().map(|addr| addr.to_string()).collect();
    let learned = full_relay(&rows)
        .iter()
        .filter(|row| want.contains(row["addr"].as_str().unwrap_or("")))
        .count();
    assert_eq!(
        learned,
        expect,
        "addresses learned into an empty book were not dialed as outbound-full-relay: {}",
        type_list(&rows)
    );
    stop_node(rpc, join).await;
}

async fn wait_learned_relay(
    rpc: SocketAddr,
    others: &[SocketAddr],
    max_out: usize,
    expect: usize,
) -> Vec<Value> {
    let want: std::collections::BTreeSet<String> =
        others.iter().map(|addr| addr.to_string()).collect();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(40);
    loop {
        let rows = peer_rows(rpc).await;
        let live = full_relay(&rows);
        assert!(
            live.len() <= max_out,
            "outbound-full-relay {} exceeded --max-outbound {max_out}: {}",
            live.len(),
            type_list(&rows)
        );
        for row in &live {
            let addr = row["addr"].as_str().unwrap_or("");
            assert!(
                want.contains(addr),
                "learned dial left the seed book: {addr} types=[{}]",
                type_list(&rows)
            );
        }
        let n = live.len();
        if n >= expect {
            assert_eq!(n, expect, "learned dials must match the getaddr reply");
            return rows;
        }
        if Instant::now() >= deadline {
            panic!(
                "outbound-full-relay still {n} after {}s, want {expect} from the learned book; types=[{}]",
                start.elapsed().as_secs(),
                type_list(&rows)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// At `--max-outbound`, a short stale-tip wait rotates one outbound
/// full-relay peer when seeds are on, and does not rotate when they are off.
async fn stale_rotation(root: &Path, addrs: &[SocketAddr], seeds: bool) {
    let dir = root.join(if seeds { "stale-on" } else { "stale-off" });
    assert_eq!(addrs.len(), 6, "one spare address past --max-outbound");
    write_book(&dir, addrs);
    let mut cfg = base_cfg(&dir);
    cfg.listen.use_seeds = seeds;
    // Seeds on: once the quota is full the next stale poll may rotate.
    // Seeds off stays at 1s so the decline is a stagnant pass, not the
    // first poll of the run.
    cfg.stale_tip = if seeds {
        Duration::from_millis(1)
    } else {
        Duration::from_secs(1)
    };
    cfg.stale_poll = Duration::from_millis(200);
    let mut join = spawn_run(cfg);
    let rpc = published_listener(&dir, "rpc", Duration::from_secs(40), &mut join).await;
    let _ = wait_full_relay(rpc, MAX_OUT as usize, MAX_OUT as usize).await;
    let pass_key = if seeds {
        "rotated"
    } else {
        "skipped_seeds_off"
    };
    // A rotation drops one row before the replacement connects. Only a full
    // quota is a snapshot. The next full quota is the pass under test.
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut prev: Option<(u64, BTreeSet<u64>)> = None;
    loop {
        let pass = outbound_pass_count(rpc, pass_key).await;
        let rows = peer_rows(rpc).await;
        let live = full_relay(&rows);
        let ids = ids_of(&live);
        assert!(
            live.len() <= MAX_OUT as usize,
            "stale rotation grew past --max-outbound: {}",
            type_list(&rows)
        );
        if live.len() == MAX_OUT as usize {
            if let Some((seen, before)) = &prev {
                if pass > *seen {
                    if seeds {
                        let replaced = before.difference(&ids).count() == 1
                            && ids.difference(before).count() == 1;
                        if replaced {
                            break;
                        }
                    } else {
                        assert_eq!(
                            ids, *before,
                            "seeds off must not rotate an outbound-full-relay"
                        );
                        break;
                    }
                }
            }
            prev = Some((pass, ids));
        }
        if Instant::now() >= deadline {
            panic!(
                "stale tip pass {pass_key} did not settle (last {prev:?}); types=[{}]",
                type_list(&rows)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    stop_node(rpc, join).await;
}

async fn assert_no_book_peers(rpc: SocketAddr, book: &[SocketAddr], label: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut pinned_at = None;
    loop {
        let rows = peer_rows(rpc).await;
        if !full_relay(&rows).is_empty() {
            panic!(
                "{label} gained outbound-full-relay from the book: {}",
                type_list(&rows)
            );
        }
        let mut manual = false;
        for row in &rows {
            let addr = row["addr"].as_str().unwrap_or("");
            if book.iter().any(|b| b.to_string() == addr) {
                panic!("{label} dialed book address {addr}: {}", type_list(&rows));
            }
            if conn_type(row) == "manual" {
                manual = true;
            }
        }
        if manual && pinned_at.is_none() {
            pinned_at = Some(outbound_pass_count(rpc, "skipped_pinned").await);
        }
        if let Some(at) = pinned_at {
            if outbound_pass_count(rpc, "skipped_pinned").await > at {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!(
                "{label} did not keep a manual session clear of the book; types=[{}]",
                type_list(&rows)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn pinned_connect(root: &Path, pinned: SocketAddr, book: &[SocketAddr]) {
    let dir = root.join("connect");
    write_book(&dir, book);
    let mut cfg = base_cfg(&dir);
    cfg.listen.connect = vec![NetAddr::Ip(pinned)];
    let mut join = spawn_run(cfg);
    let rpc = published_listener(&dir, "rpc", Duration::from_secs(40), &mut join).await;
    assert_no_book_peers(rpc, book, "--connect").await;
    stop_node(rpc, join).await;
}

async fn pinned_trust(root: &Path, pinned: SocketAddr, book: &[SocketAddr]) {
    let dir = root.join("trust");
    write_book(&dir, book);
    let mut cfg = base_cfg(&dir);
    cfg.trust_peer = Some(NetAddr::Ip(pinned));
    cfg.seal_trust_peer().expect("trust-peer");
    cfg.connect_redial = rbitcoin_net::REDIAL_INTERVAL_TEST;
    cfg.rpc.listen = Some("127.0.0.1:0".parse().expect("rpc"));
    cfg.max_tip_age_secs = Some(u64::MAX);
    let mut join = spawn_run(cfg);
    let rpc = published_listener(&dir, "rpc", Duration::from_secs(40), &mut join).await;
    assert_no_book_peers(rpc, book, "--trust-peer").await;
    stop_node(rpc, join).await;
}

fn output_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<_> = text.lines().collect();
    let start = lines.len().saturating_sub(40);
    let tail = lines[start..].join("\n");
    let Some(i) = lines.iter().position(|line| line.contains("panicked at")) else {
        return tail;
    };
    if i >= start {
        return tail;
    }
    let end = (i + 3).min(lines.len());
    format!("{}\n...\n{tail}", lines[i..end].join("\n"))
}

async fn journey() {
    let (ips, _lo) = routable_locals((LEARNED_PEERS + 1) as u8);
    let home = TestDatadir::new().expect("temp");
    let root = home.path();
    let blocks = two_blocks();
    let (listener, addrs) = listen_shared(&root, &ips, &blocks).await;
    book_refill(&root, &addrs[..MAX_OUT as usize]).await;
    let others = &addrs[1..];
    assert_eq!(others.len(), LEARNED_PEERS);
    learned_book(&root, &listener, addrs[0], others).await;
    let pinned = addrs[0];
    let book = &addrs[1..5];
    pinned_connect(&root, pinned, book).await;
    pinned_trust(&root, pinned, book).await;
    stale_rotation(&root, &addrs[..6], true).await;
    stale_rotation(&root, &addrs[..6], false).await;
    listener.shutdown().await;
}

fn spawn_journey(netns: bool) -> Output {
    let exe = std::env::current_exe().expect("test executable");
    let mut cmd;
    let child: &mut Command = if netns {
        cmd = Command::new("unshare");
        cmd.args(["--net", "--user", "--map-root-user", "--"])
            .arg(&exe)
            .env("RBITCOIN_REFILL_NS", "1")
    } else {
        // Own process: the suite shares one address space, and a listener
        // store reserves a 256 MiB strong-bit map. GitHub's test runner hard-caps
        // that space at 6 GiB.
        cmd = Command::new(&exe);
        cmd.env("RBITCOIN_REFILL_CHILD", "1")
    };
    child
        .arg("--exact")
        .arg("outbound_refill_journey::outbound_full_relay_refills_to_max_outbound")
        .arg("--test-threads=1")
        .output()
        .expect("journey process")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_full_relay_refills_to_max_outbound() {
    let isolated = std::env::var_os("RBITCOIN_REFILL_NS").is_some()
        || std::env::var_os("RBITCOIN_REFILL_CHILD").is_some();
    if !isolated {
        let netns = user_netns_available();
        let output = spawn_journey(netns);
        assert!(
            output.status.success(),
            "refill journey failed (netns={netns}): {}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            output.status,
            output_tail(&output.stderr),
            output_tail(&output.stdout)
        );
        return;
    }
    let wall = llvm_cov_wall(180, 300);
    tokio::time::timeout(wall, journey())
        .await
        .expect("outbound_full_relay_refills_to_max_outbound wall");
}
