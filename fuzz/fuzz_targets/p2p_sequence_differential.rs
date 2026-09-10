#![no_main]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rbitcoin_consensus::Milestone;
use rbitcoin_fuzz::{
    check_diff_env, compare_one, diff_regtest_params, encode_getheaders_empty_v2, encode_ping_v2,
    encode_pong_v2, genesis_diff_tip, CompareOne, DiffTip,
};
use rbitcoin_fuzz::{parse_p2p_sequence, spawn_bitcoind_p2p, tmp_dir, CoreChild, P2pSeqKind};
use rbitcoin_net::{classify_v2_cmpct_peer, ChainHub, CmpctPeerFrame, V2PlainSession};
use rbitcoin_query::Query;
use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};

struct Base {
    hub: ChainHub,
    core: CoreChild,
    tip: std::sync::Mutex<DiffTip>,
    rt: Runtime,
    session: Mutex<Option<V2PlainSession>>,
    _store: PathBuf,
}

static BASE: OnceLock<Base> = OnceLock::new();
static COMPARISONS: AtomicU64 = AtomicU64::new(0);
static PING_SEQ: AtomicU64 = AtomicU64::new(1);
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
const READ_WAIT: Duration = Duration::from_millis(200);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== P2P-SEQUENCE FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    std::process::exit(2);
}

fn note_comparison() {
    let n = COMPARISONS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(100) {
        eprintln!("p2p-sequence: comparisons={n}");
    }
}

fn base() -> &'static Base {
    BASE.get_or_init(|| {
        if std::env::var_os("RBITCOIN_IO").is_none() {
            std::env::set_var("RBITCOIN_IO", "fd");
        }
        let io = std::env::var("RBITCOIN_IO").ok();
        if let Err(e) = check_diff_env(None, io.as_deref()) {
            harness_failure(e);
        }
        let bin = std::env::var("RBITCOIN_CORE_BITCOIND").unwrap_or_default();
        if bin.is_empty() {
            harness_failure("RBITCOIN_CORE_BITCOIND unset");
        }
        let store = tmp_dir("rbtc-p2p-seq-store");
        let core_dir = tmp_dir("rbtc-p2p-seq-core");
        let q = Query::open_or_create_tiny(store.join("store")).unwrap_or_else(|e| {
            harness_failure(&format!("query open: {e}"));
        });
        let params = diff_regtest_params();
        let hub = ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis()
            .unwrap_or_else(|e| harness_failure(&format!("genesis: {e}")));
        let (core, p2p) = spawn_bitcoind_p2p(std::path::Path::new(&bin), &core_dir)
            .unwrap_or_else(|e| harness_failure(&e));
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| harness_failure(&format!("tokio runtime: {e}")));
        let session = rt
            .block_on(connect_session(p2p))
            .unwrap_or_else(|e| harness_failure(&format!("initial handshake: {e}")));
        Base {
            hub,
            core,
            tip: std::sync::Mutex::new(genesis_diff_tip(&params)),
            rt,
            session: Mutex::new(Some(session)),
            _store: store,
        }
    })
}

async fn connect_session(p2p: SocketAddr) -> Result<V2PlainSession, String> {
    let stream = TcpStream::connect(p2p).await.map_err(|e| e.to_string())?;
    V2PlainSession::outbound_regtest(stream, "/rbitcoin:fuzz/", HANDSHAKE_LIMIT)
        .await
        .map_err(|e| format!("handshake: {e}"))
}

fn ping_compare(b: &Base) -> bool {
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = slot.as_mut() else {
        return false;
    };
    let nonce = PING_SEQ.fetch_add(1, Ordering::Relaxed);
    let Ok(ping) = encode_ping_v2(nonce) else {
        return false;
    };
    b.rt.block_on(async {
        if sess.write_contents(&ping).await.is_err() {
            return false;
        }
        let deadline = tokio::time::Instant::now() + READ_WAIT;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, sess.read_contents()).await {
                Err(_) => return false,
                Ok(Err(_)) => return false,
                Ok(Ok(contents)) => match classify_v2_cmpct_peer(&contents) {
                    CmpctPeerFrame::Pong(n) if n == nonce => return true,
                    CmpctPeerFrame::Ping(n) => {
                        let Ok(pong) = encode_pong_v2(n) else {
                            return false;
                        };
                        if sess.write_contents(&pong).await.is_err() {
                            return false;
                        }
                    }
                    _ => {}
                },
            }
        }
        false
    })
}

fn headers_live(b: &Base) -> bool {
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = slot.as_mut() else {
        return false;
    };
    let Ok(frame) = encode_getheaders_empty_v2() else {
        return false;
    };
    b.rt.block_on(async { sess.write_contents(&frame).await.ok() })
        .is_some()
}

fuzz_target!(|data: &[u8]| {
    let b = base();
    let steps = parse_p2p_sequence(data);
    let mut tip = b.tip.lock().unwrap_or_else(|e| e.into_inner());
    for step in steps {
        if step.skip {
            continue;
        }
        match step.kind {
            P2pSeqKind::Ping => {
                if ping_compare(b) {
                    note_comparison();
                }
            }
            P2pSeqKind::Headers => {
                let _ = headers_live(b);
            }
            P2pSeqKind::Block => match compare_one(&b.hub, &mut tip, &b.core.rpc, data) {
                CompareOne::Agreed { .. } => note_comparison(),
                CompareOne::NotABlock | CompareOne::Skipped => {}
                CompareOne::Disagreed { ours, core, hex } => {
                    panic!("p2p-sequence block: ours={ours} core={core} hex={hex}");
                }
                CompareOne::Harness(msg) if msg == "oracle dead" => {}
                CompareOne::Harness(msg) => harness_failure(msg),
            },
        }
    }
});
