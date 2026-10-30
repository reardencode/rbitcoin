use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::middleware::{self};
use axum::routing::{get, post};
use axum::Router;
use bitcoin::Network;
use rbitcoin_electrum::ServeLimits;
use rbitcoin_esplora::handlers;
use rbitcoin_esplora::server::*;
use rbitcoin_esplora::tx_json::tx_status_json;
use rbitcoin_primitives::Fk;
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use rbitcoin_query::TxApply;
use rbitcoin_store::script_hash;
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use rbitcoin_query::testutil::FixtureChain;

/// `store(true)` ends the serve task without waiting out the shutdown poll.
#[tokio::test]
async fn esplora_shutdown_wakes_without_the_fifty_ms_poll() {
    tokio::time::pause();
    let (_dir, q) = temp_query("esplora-stop-wake");
    let (h0, cb0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[cb0]).unwrap();
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let mut handle = run_esplora(cfg, Arc::new(q), None).await.expect("listen");
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    handle.shutdown.store(true);
    tokio::task::yield_now().await;
    let joined = tokio::time::timeout(Duration::ZERO, &mut handle.task).await;
    tokio::time::resume();
    joined
        .expect("esplora stayed in the 50 ms shutdown poll")
        .expect("serve task");
}

fn temp_query(label: &str) -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled(label)
}

fn coinbase(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
    let version = 1;
    let timestamp = h + 1;
    let bits = 0x207fffff;
    let nonce = h;
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&h.to_le_bytes());
    merkle[5] = 0xab;
    let hash = match parent_hash {
        None => merkle,
        Some(ph) => {
            rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
        }
    };
    let header = HeaderRecord {
        prev_fk: prev,
        version,
        timestamp,
        bits,
        nonce,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    let mut txid = [0u8; 32];
    txid[0..4].copy_from_slice(&h.to_le_bytes());
    txid[31] = 0xcb;
    let ta = TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![h as u8],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    };
    (header, ta)
}

fn header_value(text: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    text.split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(&want))
        .map(|(_, v)| v.trim().to_string())
}

async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let (status, _hdrs, body) = http_get_raw(addr, path).await;
    (status, body)
}

async fn http_get_raw(addr: SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    (status, text, body)
}

async fn http_post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
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

#[test]
fn esplora_listen_parse_tcp_and_path() {
    assert!(matches!(
        EsploraListen::parse("127.0.0.1:3000", 3000).unwrap(),
        EsploraListen::Tcp(_)
    ));
    assert!(matches!(
        EsploraListen::parse("", 3000).unwrap(),
        EsploraListen::Tcp(a) if a.port() == 3000
    ));
    #[cfg(unix)]
    {
        assert!(matches!(
            EsploraListen::parse("/run/rbitcoin/esplora.sock", 3000).unwrap(),
            EsploraListen::Unix(_)
        ));
        assert!(matches!(
            EsploraListen::parse("./esplora.sock", 3000).unwrap(),
            EsploraListen::Unix(_)
        ));
    }
    assert!(EsploraListen::parse("not-an-addr", 3000).is_err());
}

#[test]
fn join_idle_evicts_after_ttl() {
    let mut map = HashMap::new();
    let now = Instant::now();
    map.insert(
        "stale".into(),
        ClientJoins {
            last_req: now.checked_sub(JOIN_IDLE + Duration::from_secs(1)).unwrap(),
            ..ClientJoins::default()
        },
    );
    map.insert(
        "fresh".into(),
        ClientJoins {
            last_req: now,
            ..ClientJoins::default()
        },
    );
    sweep_clients(&mut map, now);
    assert!(!map.contains_key("stale"));
    assert!(map.contains_key("fresh"));
}

fn join_only_state(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>) -> AppState {
    AppState {
        query: q,
        network: Network::Regtest,
        mempool: None,
        max_body: 1 << 20,
        sh_join: cache,
        join_header_trusted: true,
        block_template: None,
        gbt_cache: Arc::new(Mutex::new(None)),
    }
}

#[test]
fn with_sh_join_empty_slot_unblocks_waiter() {
    let (_dir, q) = temp_query("join-empty-waiter");
    let st = Arc::new(join_only_state(
        Arc::new(q),
        Arc::new(Mutex::new(JoinCache::default())),
    ));
    let sh = [0x11u8; 32];
    let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let st_l = Arc::clone(&st);
    let leader = std::thread::spawn(move || {
        st_l.with_sh_join(Some("c1"), &sh, |slot| {
            *slot = None;
            let _ = leader_in.send(());
            let _ = release_rx.recv();
        });
    });
    leader_in_rx.recv().expect("leader entered f");
    let inf = st
        .sh_join
        .lock()
        .unwrap()
        .clients
        .get("c1")
        .and_then(|c| c.inflight.get(&sh).cloned())
        .expect("leader inflight");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let st_w = Arc::clone(&st);
    let waiter = std::thread::spawn(move || {
        st_w.with_sh_join(Some("c1"), &sh, |slot| {
            let _ = done_tx.send(slot.is_none());
        });
    });
    assert!(
        inf.wait_queued(Duration::from_secs(2)),
        "waiter did not queue on the empty join"
    );
    let _ = release.send(());
    leader.join().expect("leader");
    let empty = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter unblocked after empty join");
    assert!(empty, "finished empty slot");
    waiter.join().expect("waiter");
}

#[test]
fn with_sh_join_leader_panic_unblocks_waiter() {
    let (_dir, q) = temp_query("join-panic-waiter");
    let st = Arc::new(join_only_state(
        Arc::new(q),
        Arc::new(Mutex::new(JoinCache::default())),
    ));
    let sh = [0x22u8; 32];
    let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let st_l = Arc::clone(&st);
    let leader = std::thread::spawn(move || {
        st_l.with_sh_join(Some("c1"), &sh, |_slot| {
            let _ = leader_in.send(());
            let _ = release_rx.recv();
            panic!("join leader unwind");
        });
    });
    leader_in_rx.recv().expect("leader entered f");
    let inf = st
        .sh_join
        .lock()
        .unwrap()
        .clients
        .get("c1")
        .and_then(|c| c.inflight.get(&sh).cloned())
        .expect("leader inflight");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let st_w = Arc::clone(&st);
    let waiter = std::thread::spawn(move || {
        st_w.with_sh_join(Some("c1"), &sh, |_slot| {
            let _ = done_tx.send(());
        });
    });
    assert!(
        inf.wait_queued(Duration::from_secs(2)),
        "waiter did not queue before the leader unwound"
    );
    let _ = release.send(());
    let _ = leader.join();
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter unblocked after leader panic");
    waiter.join().expect("waiter");
}

#[tokio::test]
async fn with_sh_join_last1_clone_visible_to_overlapping_get() {
    use rbitcoin_store::script_hash;

    let (_a1, spk1) = regtest_p2wpkh();
    let (dir, q) = temp_query("join-last1-clone");
    let (h0, t0) = coinbase(0, Fk::NULL, None);
    let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
    q.connect_block(Height(1), &h1, &[cb1, two_script_pay(0x11, spk1.clone())])
        .unwrap();
    let q = Arc::new(q);
    let sh1 = script_hash(spk1.as_bytes());
    let h1hex = block_hash_hex(&sh1);
    let cache = Arc::new(Mutex::new(JoinCache::default()));
    let app = app_with_join(Arc::clone(&q), Arc::clone(&cache), true);
    let (st, body) =
        oneshot_http(&app, get_with_client(&format!("/scripthash/{h1hex}"), "c1")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(cache.lock().unwrap().last_sh_key("c1"), Some(sh1));

    let st = Arc::new(join_only_state(Arc::clone(&q), Arc::clone(&cache)));
    let (holder_in, holder_in_rx) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let st_a = Arc::clone(&st);
    let holder = std::thread::spawn(move || {
        st_a.with_sh_join(Some("c1"), &sh1, |slot| {
            assert!(slot.is_some(), "holder must see warm last-1");
            let _ = holder_in.send(());
            let _ = release_rx.recv();
        });
    });
    holder_in_rx.recv().expect("holder entered f");
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let st_b = Arc::clone(&st);
    let overlap = std::thread::spawn(move || {
        st_b.with_sh_join(Some("c1"), &sh1, |slot| {
            let _ = seen_tx.send(slot.is_some());
        });
    });
    let saw = seen_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("overlap entered f");
    assert!(
        saw,
        "overlapping same-sh GET must clone last-1, not take it"
    );
    let _ = release.send(());
    holder.join().expect("holder");
    overlap.join().expect("overlap");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn with_sh_join_drops_last_sh_over_bulk_cap() {
    let (_dir, q) = temp_query("join-oversize-last-sh");
    let cache = Arc::new(Mutex::new(JoinCache::default()));
    let st = join_only_state(Arc::new(q), Arc::clone(&cache));
    let sh = [0x33u8; 32];
    let slot = rbitcoin_query::testutil::sh_join_slot_over_16mib();
    assert!(
        slot.packed_bytes() > JOIN_BULK_CAP,
        "fixture must exceed 16 MiB packed"
    );
    st.with_sh_join(Some("c1"), &sh, |s| {
        *s = Some(Arc::clone(&slot));
    });
    assert!(
        cache.lock().unwrap().last_sh_key("c1").is_none(),
        "oversize last-1 is used then not retained"
    );
}

#[test]
fn late_waiter_keeps_a_newer_last_sh() {
    let (_dir, q) = temp_query("join-late-waiter-last-sh");
    let cache = Arc::new(Mutex::new(JoinCache::default()));
    let st = Arc::new(join_only_state(Arc::new(q), Arc::clone(&cache)));
    let sh_old = [0x11u8; 32];
    let sh_new = [0x22u8; 32];
    let slot = rbitcoin_query::testutil::sh_join_slot_small();
    let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let st_l = Arc::clone(&st);
    let slot_l = Arc::clone(&slot);
    let leader = std::thread::spawn(move || {
        st_l.with_sh_join(Some("c1"), &sh_old, |s| {
            *s = Some(slot_l);
            let _ = leader_in.send(());
            let _ = release_rx.recv();
        });
    });
    leader_in_rx.recv().expect("leader entered f");
    let slot_b = Arc::clone(&slot);
    st.with_sh_join(Some("c1"), &sh_new, |n| {
        *n = Some(slot_b);
    });
    assert_eq!(
        cache.lock().unwrap().last_sh_key("c1"),
        Some(sh_new),
        "a newer script that finishes while the older leader is inside f is last-1"
    );
    let (waiter_in, waiter_in_rx) = std::sync::mpsc::channel::<()>();
    let (waiter_go, waiter_go_rx) = std::sync::mpsc::channel::<()>();
    let st_w = Arc::clone(&st);
    let slot_w = Arc::clone(&slot);
    let waiter = std::thread::spawn(move || {
        st_w.with_sh_join(Some("c1"), &sh_old, |s| {
            *s = Some(slot_w);
            let _ = waiter_in.send(());
            let _ = waiter_go_rx.recv();
        });
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        waiter_in_rx.try_recv().is_err(),
        "waiter must block on the leader, not run the join itself"
    );
    let _ = release.send(());
    leader.join().expect("leader");
    assert_eq!(
        cache.lock().unwrap().last_sh_key("c1"),
        Some(sh_new),
        "an older leader that finishes after a newer script must not replace last-1"
    );
    waiter_in_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter entered f after the leader finished");
    let _ = waiter_go.send(());
    waiter.join().expect("waiter");
    assert_eq!(
        cache.lock().unwrap().last_sh_key("c1"),
        Some(sh_new),
        "a late waiter must not put the old scripthash back over a newer last-1"
    );
}

#[cfg(unix)]
#[cfg(unix)]
#[tokio::test]
async fn bind_unix_socket_does_not_strip_dir_search() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    // SAFETY: `umask` is process-global. This test restores `old` before return.
    let old = unsafe { umask(0o022) };
    let stop = Arc::new(AtomicBool::new(false));
    let bare = Arc::new(AtomicBool::new(false));
    let worker = {
        let stop = Arc::clone(&stop);
        let bare = Arc::clone(&bare);
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let path = std::env::temp_dir().join(format!(
                    "rbitcoin-umask-probe-esplora-{}-{}",
                    std::process::id(),
                    n
                ));
                n += 1;
                if std::fs::create_dir(&path).is_err() {
                    continue;
                }
                let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o111);
                let _ = std::fs::remove_dir(&path);
                if mode.is_ok_and(|m| m == 0) {
                    bare.store(true, Ordering::Relaxed);
                    break;
                }
            }
        })
    };
    let dir = rbitcoin_query::testutil::TempDir::for_socket().expect("temp dir");
    for i in 0..200 {
        let sock = dir.path().join(format!("s{i}.sock"));
        let listener = rbitcoin_esplora::server::bind_unix_mode(&sock, 0o660).expect("bind");
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket mode");
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        if bare.load(Ordering::Relaxed) {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    // SAFETY: restores the umask saved at the start of this test.
    unsafe { umask(old) };
    assert!(
        !bare.load(Ordering::Relaxed),
        "unix bind changed umask and a temp dir lost search permission"
    );
}

fn two_script_pay(tag: u8, spk: bitcoin::ScriptBuf) -> TxApply {
    let mut txid = [0u8; 32];
    txid[0] = tag;
    txid[31] = 0xaa;
    TxApply {
        tx: TxRecord {
            txid,
            version: 2,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(1_0000_0000, spk.to_bytes())],
    }
}

fn app_with_join(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>, trusted: bool) -> Router {
    let state = AppState {
        query: q,
        network: Network::Regtest,
        mempool: None,
        max_body: 1 << 20,
        sh_join: cache,
        join_header_trusted: trusted,
        block_template: None,
        gbt_cache: Arc::new(Mutex::new(None)),
    };
    Router::new()
        .route("/scripthash/{hash}", get(handlers::scripthash_info))
        .route("/scripthash/{hash}/utxo", get(handlers::scripthash_utxo))
        .route("/scripthash/{hash}/txs", get(handlers::scripthash_txs))
        .route(
            "/scripthash/{hash}/txs/chain",
            get(handlers::scripthash_txs_chain),
        )
        .route(
            "/scripthash/{hash}/txs/summary",
            get(handlers::scripthash_txs_summary),
        )
        .route("/address/{addr}/utxo", get(handlers::address_utxo))
        .route("/scripthashes/txs", post(handlers::post_scripthashes_txs))
        .route(
            "/scripthashes/txs/summary",
            post(handlers::post_scripthashes_txs_summary),
        )
        .with_state(state)
}

async fn oneshot_http(app: &Router, req: axum::http::Request<axum::body::Body>) -> (u16, String) {
    use tower::ServiceExt;
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn get_with_client(path: &str, client: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri(path)
        .header("X-Rbitcoin-Client", client)
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn address_without_sh_index_is_503_disabled() {
    let (dir, q) = temp_query("esplora-sh-off");
    q.set_sh_index_enabled(false);
    let (h0, t0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let state = AppState {
        query: Arc::new(q),
        network: Network::Regtest,
        mempool: None,
        max_body: 1024,
        sh_join: Arc::new(Mutex::new(JoinCache::default())),
        join_header_trusted: false,
        block_template: None,
        gbt_cache: Arc::new(Mutex::new(None)),
    };
    let app = Router::new()
        .route("/address/{addr}/utxo", get(handlers::address_utxo))
        .route("/blocks/tip/height", get(tip_height))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            stamp_chain_view_mw,
        ))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dummy = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8z5y2";
    let (st, body) = http_get(addr, &format!("/address/{dummy}/utxo")).await;
    assert_eq!(st, 503, "{body}");
    assert_eq!(body, rbitcoin_query::SCRIPTHASH_INDEX_DISABLED);
    let (st, body) = http_get(addr, "/blocks/tip/height").await;
    assert_eq!(st, 200, "tip must work without SH: {body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn http_503_chain_view_moved_omits_tip_header() {
    let (dir, q) = temp_query("http-503-moved");
    let (h0, t0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let state = AppState {
        query: Arc::new(q),
        network: Network::Regtest,
        mempool: None,
        max_body: 1024,
        sh_join: Arc::new(Mutex::new(JoinCache::default())),
        join_header_trusted: false,
        block_template: None,
        gbt_cache: Arc::new(Mutex::new(None)),
    };
    async fn die_tip(State(st): State<AppState>) -> &'static str {
        st.query.disconnect_tip().unwrap();
        "ok"
    }
    let app = Router::new()
        .route("/blocks/tip/hash", get(die_tip))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            stamp_chain_view_mw,
        ))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (st, raw, body) = http_get_raw(addr, "/blocks/tip/hash").await;
    assert_eq!(st, 503, "body={body}");
    assert!(
        body.contains("chain view moved"),
        "503 body must name the move: {body}"
    );
    assert!(
        header_value(&raw, HDR_CHAIN_TIP).is_none(),
        "503 must not stamp a fork tip"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn output_by_position_paths_accept_asof() {
    assert!(path_accepts_asof("/block-height/1/tx/0"));
    assert!(path_accepts_asof("/block-height/1/tx/0/out/0"));
    assert!(path_accepts_asof("/tx/ab/out/0"));
    assert!(path_accepts_asof("/block-heights/txs/outs"));
    assert!(!path_accepts_asof("/block-height/1"));
    assert!(!path_accepts_asof("/tx/ab"));
    assert!(!path_accepts_asof("/block/ab/tx/0"));
}

#[test]
fn config_defaults_use_public_proxy_limits() {
    let cfg = EsploraConfig::new("0.0.0.0:3000".parse().unwrap());
    assert_eq!(cfg.limits, ServeLimits::for_public_proxy());
}

#[test]
fn asof_query_is_gated_to_documented_routes() {
    assert!(path_accepts_asof("/tx/ab/status"));
    assert!(path_accepts_asof("/tx/ab/outspends"));
    assert!(path_accepts_asof("/tx/ab/outspend/0"));
    assert!(path_accepts_asof("/scripthash/ab/utxo"));
    assert!(path_accepts_asof("/address/bcrt1q/txs/chain/cd"));
    assert!(path_accepts_asof("/address/bcrt1q/txs/summary"));
    assert!(path_accepts_asof("/scripthash/ab/txs/summary/cd"));
    assert!(!path_accepts_asof("/address/bcrt1q/txs/mempool"));
    assert!(!path_accepts_asof("/tx/ab"));
    assert!(!path_accepts_asof("/block-height/1"));
    assert!(!path_accepts_asof("/mempool"));
    assert!(!path_accepts_asof("/scripthash/ab/txs/mempool"));
    assert!(path_never_pins("/mempool"));
    assert!(path_never_pins("/mempool/txids"));
    assert!(path_never_pins("/fee-estimates"));
    assert!(path_never_pins("/tx"));
    assert!(!path_never_pins("/tx/ab"));
    assert!(parse_asof_param(&AsOfQuery { asof: None })
        .unwrap()
        .is_none());
    assert!(parse_asof_param(&AsOfQuery {
        asof: Some(String::new())
    })
    .is_err());
    assert!(parse_asof_param(&AsOfQuery {
        asof: Some("zz".into())
    })
    .is_err());
    assert!(parse_hash32("aa").is_err());
    assert!(parse_hash32("zz".repeat(32).as_str()).is_err());
}

/// No-hub Esplora: empty mempool, flat fee estimates, POST /tx is 503.
/// Live `esplora_broadcast` always has a hub.
#[tokio::test]
async fn remaining_routes_fixture() {
    let (dir, q) = temp_query("remain");
    let (header, ta) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &header, &[ta]).unwrap();
    let q = Arc::new(q);
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let handle = run_esplora(cfg, Arc::clone(&q), None)
        .await
        .expect("listen");
    let addr = handle.local_addr;

    let (st, body) = http_get(addr, "/mempool").await;
    assert_eq!(st, 200, "{body}");
    let mem: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(mem["count"], 0);

    // No mempool, no estimate. Regtest returns an empty map so a client can
    // apply its own fallback. It must not invent a sat/vB.
    let (st, body) = http_get(addr, "/fee-estimates").await;
    assert_eq!(st, 200, "{body}");
    let estimates: Value = serde_json::from_str(&body).expect("fee-estimates json");
    assert_eq!(
        estimates,
        json!({}),
        "an empty estimator must not invent a target: {body}"
    );

    let main_cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Bitcoin);
    let main_handle = run_esplora(main_cfg, Arc::clone(&q), None)
        .await
        .expect("mainnet listen");
    let (st, body) = http_get(main_handle.local_addr, "/fee-estimates").await;
    assert_eq!(st, 503, "{body}");
    assert!(body.contains("fee estimates unavailable"), "{body}");

    // mempool.space's tiers are its backend's /api/v1 surface, not Esplora's.
    for path in ["/fees/recommended", "/v1/fees/recommended"] {
        let (st, body) = http_get(addr, path).await;
        assert_eq!(st, 404, "{path}: {body}");
    }

    // mempool.space's websocket is its backend's /api/v1/ws, not Esplora's.
    for path in ["/ws", "/v1/ws"] {
        let (st, body) = http_get(addr, path).await;
        assert_eq!(st, 404, "{path}: {body}");
    }

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req =
        "POST /tx HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab";
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("503") || text.contains("mempool"),
        "expected 503 without hub: {text}"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reconstruct meters + no-hub empty mempool lists (HTTP JSON/raw/status ride
/// `esplora_broadcast_visible_in_rpc_and_electrum`).
#[allow(clippy::cognitive_complexity)] // meters + leftover header/height/status needles
#[tokio::test]
async fn block_raw_summary_status_and_mempool_routes() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, MerkleBlock};

    let (dir, q) = temp_query("p0-block");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut hashes = Vec::new();
    let mut coinbase_txids = Vec::new();
    for h in 0..3u32 {
        let (header, ta) = coinbase(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        hashes.push(header.hash);
        coinbase_txids.push(ta.tx.txid);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    let q = Arc::new(q);
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let handle = run_esplora(cfg, Arc::clone(&q), None)
        .await
        .expect("listen");
    let addr = handle.local_addr;

    let _ = q.sample_reset_reconstruct_archived();
    let h1 = block_hash_hex(&hashes[1]);
    let (st, body) = http_get(addr, &format!("/block/{h1}")).await;
    assert_eq!(st, 200, "block json {body}");
    assert_eq!(
        q.sample_reset_reconstruct_archived(),
        0,
        "/block JSON uses stamped size/weight"
    );

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req =
        format!("GET /block/{h1}/raw HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http headers");
    let raw = &buf[sep + 4..];
    assert!(
        String::from_utf8_lossy(&buf[..sep]).contains("200"),
        "raw status"
    );
    let block: Block = deserialize(raw).expect("decode raw block");
    assert_eq!(block.txdata.len(), 1);
    assert!(
        q.sample_reset_reconstruct_archived() >= 1,
        "/block/:hash/raw must reconstruct wire"
    );

    let _ = q.sample_reset_reconstruct_archived();
    let (st, _) = http_get(addr, "/blocks").await;
    assert_eq!(st, 200);
    assert_eq!(
        q.sample_reset_reconstruct_archived(),
        0,
        "/blocks summaries use stamped size/weight"
    );

    let txid0 = block_hash_hex(&coinbase_txids[0]);
    let _ = q.sample_reset_reconstruct_archived();
    let (st, body) = http_get(addr, &format!("/tx/{txid0}/merkleblock-proof")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        q.sample_reset_reconstruct_archived(),
        0,
        "merkleblock-proof uses txid.body + header, not full reconstruct"
    );
    let mb_bytes = rbitcoin_primitives::hex_decode(&body).unwrap();
    let mb: MerkleBlock = deserialize(&mb_bytes).expect("merkleblock");
    let mut matches = Vec::new();
    let mut indexes = Vec::new();
    mb.extract_matches(&mut matches, &mut indexes).unwrap();
    assert_eq!(indexes, vec![0]);
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0],
        bitcoin::Txid::from_byte_array(coinbase_txids[0])
    );

    let (st, body) = http_get(addr, "/mempool/txids").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, "[]");
    let (st, body) = http_get(addr, "/mempool/recent").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, "[]");

    let sh = rbitcoin_store::script_hash(&[0x51]);
    let sh_hex = block_hash_hex(&sh);
    let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/mempool")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, "[]");

    let (st, body) = http_get(addr, "/block-height/1").await;
    assert_eq!(st, 200, "block-height body={body}");
    assert_eq!(body, block_hash_hex(&hashes[1]));
    let (st, _) = http_get(addr, "/block-height/99").await;
    assert_eq!(st, 404);

    let hash_disp = block_hash_hex(&hashes[1]);
    let (st, body) = http_get(addr, &format!("/block/{hash_disp}/header")).await;
    assert_eq!(st, 200, "header body len={}", body.len());
    assert_eq!(body.len(), 160);
    let wire = q.wire_header_at_height(Height(1)).unwrap();
    let expected = encode_header_hex(&wire).unwrap();
    assert_eq!(body, expected);
    let miss = "ff".repeat(32);
    let (st, _) = http_get(addr, &format!("/block/{miss}/header")).await;
    assert_eq!(st, 404);

    let (fk, _) = q.get_tx_by_txid(&coinbase_txids[0]).unwrap().unwrap();
    let st_json = tx_status_json(&q, fk).unwrap();
    assert_eq!(st_json["confirmed"], true);
    assert_eq!(st_json["block_height"], 0);

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regtest P2WPKH address + scriptPubKey.
fn regtest_p2wpkh() -> (String, bitcoin::ScriptBuf) {
    regtest_p2wpkh_sk(7)
}

fn regtest_p2wpkh_sk(fill: u8) -> (String, bitcoin::ScriptBuf) {
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, PrivateKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[fill; 32]).expect("sk");
    let pk = PrivateKey::new(sk, Network::Regtest);
    let cpk = CompressedPublicKey::from_private_key(&secp, &pk).expect("cpk");
    let addr = Address::p2wpkh(&cpk, Network::Regtest);
    let spk = addr.script_pubkey();
    (addr.to_string(), spk)
}

fn display_txid(txid: bitcoin::Txid) -> String {
    txid.to_string()
}

/// electrs: a start index at or past the last tx is 404, not an empty page.
#[tokio::test]
async fn block_txs_past_end_is_not_found() {
    let (dir, q) = temp_query("txs-range");
    let (header, ta) = coinbase(0, Fk::NULL, None);
    let hash = header.hash;
    q.connect_block(Height(0), &header, &[ta]).unwrap();
    let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    let handle = run_esplora(cfg, Arc::new(q), None).await.expect("listen");
    let h = block_hash_hex(&hash);
    let (st, body) = http_get(handle.local_addr, &format!("/block/{h}/txs/0")).await;
    assert_eq!(st, 200, "{body}");
    let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(rows.as_array().map(|a| a.len()), Some(1), "{body}");
    let (st, body) = http_get(handle.local_addr, &format!("/block/{h}/txs/25")).await;
    assert_eq!(st, 404, "{body}");
    assert!(body.contains("start index out of range"), "{body}");
    let (st, body) = http_get(handle.local_addr, &format!("/block/{h}/txs/1")).await;
    assert_eq!(st, 400, "{body}");
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

struct ScriptHold {
    gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

impl ScriptHold {
    fn all() -> Self {
        let n = rbitcoin_consensus::script_pool::worker_spawn_count();
        assert!(n >= 1, "script pool did not start");
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parked = Arc::new((Mutex::new(()), std::sync::Condvar::new()));
        for _ in 0..n {
            let entered = Arc::clone(&entered);
            let gate = Arc::clone(&gate);
            let parked = Arc::clone(&parked);
            rbitcoin_consensus::script_pool::spawn_detached(move || {
                {
                    let _g = parked.0.lock().unwrap_or_else(|p| p.into_inner());
                    entered.fetch_add(1, Ordering::SeqCst);
                    parked.1.notify_all();
                }
                let (lock, cv) = &*gate;
                let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
                while !*g {
                    g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
                }
            });
        }
        let start = Instant::now();
        let (lock, cv) = &*parked;
        let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
        while entered.load(Ordering::SeqCst) < n {
            let left = Duration::from_secs(2).saturating_sub(start.elapsed());
            assert!(!left.is_zero(), "script workers did not park");
            let (next, timeout) = cv.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner());
            g = next;
            assert!(!timeout.timed_out(), "script workers did not park");
        }
        Self { gate }
    }
}

impl Drop for ScriptHold {
    fn drop(&mut self) {
        let (lock, cv) = &*self.gate;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
    }
}

/// A template at 4 KiB keeps `cache-control: no-store` and does not encode
/// until a script worker is free.
#[test]
fn heavy_template_encode_waits_for_a_script_worker() {
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;

    let chars = rbitcoin_electrum::JSON_CPU_MIN - 2;
    let body = Arc::new(Value::String("a".repeat(chars)));
    assert!(rbitcoin_electrum::json_is_cpu_heavy(&body));
    let hold = ScriptHold::all();
    let resp = handlers::gbt_json(&body);
    let cc = resp
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "no-store");

    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut pending = Box::pin(ensure_json(resp));
    assert!(
        matches!(pending.as_mut().poll(&mut cx), Poll::Pending),
        "a template at 4 KiB encoded while script workers were held"
    );
    drop(hold);
    let start = Instant::now();
    let ready = loop {
        match pending.as_mut().poll(&mut cx) {
            Poll::Ready(resp) => break resp,
            Poll::Pending => {
                assert!(start.elapsed() < Duration::from_secs(2));
                thread::park_timeout(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(ready.status(), axum::http::StatusCode::OK);
    let mut body_fut = Box::pin(axum::body::to_bytes(ready.into_body(), usize::MAX));
    let bytes = loop {
        match body_fut.as_mut().poll(&mut cx) {
            Poll::Ready(bytes) => break bytes.expect("template body"),
            Poll::Pending => {
                assert!(start.elapsed() < Duration::from_secs(2));
                thread::park_timeout(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(bytes.as_ref(), serde_json::to_vec(body.as_ref()).unwrap());
}

include!("esplora_sh_journey.rs");
include!("esplora_http_journey.rs");
include!("blindbit_journey.rs");
