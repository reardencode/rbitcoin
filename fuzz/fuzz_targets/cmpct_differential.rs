#![no_main]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rbitcoin_fuzz::{spawn_bitcoind_p2p, tmp_dir, CoreChild};
use rbitcoin_net::{
    classify_v2_cmpct_peer, cmpct_hsi_regtest_connectable, cmpct_missing_empty_mempool,
    decode_cmpct_hsi, encode_cmpctblock_v2, encode_pong_v2, encode_sendcmpct_hb_v2, CmpctPeerFrame,
    NetError, V2PlainSession,
};
use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};

struct Base {
    _core: CoreChild,
    p2p: SocketAddr,
    rt: Runtime,
    session: Mutex<Option<V2PlainSession>>,
    _datadir: PathBuf,
}

static BASE: OnceLock<Base> = OnceLock::new();
static COMPARISONS: AtomicU64 = AtomicU64::new(0);
static SESSION_FAIL_STREAK: AtomicU64 = AtomicU64::new(0);
const MAX_SESSION_FAIL_STREAK: u64 = 20;
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
const DRAIN: Duration = Duration::from_millis(200);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== CMPCT-DIFFERENTIAL FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    eprintln!(
        "comparisons_before_failure={}",
        COMPARISONS.load(Ordering::Relaxed)
    );
    std::process::exit(2);
}

fn note_comparison() {
    SESSION_FAIL_STREAK.store(0, Ordering::Relaxed);
    let n = COMPARISONS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(100) {
        eprintln!("cmpct-differential: comparisons={n}");
    }
}

fn base() -> &'static Base {
    BASE.get_or_init(|| {
        let bin = std::env::var("RBITCOIN_CORE_BITCOIND").unwrap_or_default();
        if bin.is_empty() {
            harness_failure("RBITCOIN_CORE_BITCOIND unset");
        }
        let datadir = tmp_dir("rbtc-cmpct-core");
        let (core, p2p) = spawn_bitcoind_p2p(std::path::Path::new(&bin), &datadir)
            .unwrap_or_else(|e| harness_failure(&e));
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| harness_failure(&format!("tokio runtime: {e}")));
        let session = rt
            .block_on(connect_session(p2p))
            .unwrap_or_else(|e| harness_failure(&format!("initial handshake: {e}")));
        Base {
            _core: core,
            p2p,
            rt,
            session: Mutex::new(Some(session)),
            _datadir: datadir,
        }
    })
}

async fn connect_session(p2p: SocketAddr) -> Result<V2PlainSession, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match TcpStream::connect(p2p).await {
            Ok(stream) => {
                match V2PlainSession::outbound_regtest(stream, "/rbitcoin:fuzz/", HANDSHAKE_LIMIT)
                    .await
                {
                    Ok(mut s) => {
                        let sendcmpct = encode_sendcmpct_hb_v2().map_err(|e| e.to_string())?;
                        s.write_contents(&sendcmpct)
                            .await
                            .map_err(|e| e.to_string())?;
                        let _ = drain_frames(&mut s, None).await;
                        return Ok(s);
                    }
                    Err(e) => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(format!("handshake: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("connect {p2p}: {e}"));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Drain Core chatter. `want_txn` collects the first `getblocktxn` indexes.
async fn drain_frames(
    sess: &mut V2PlainSession,
    mut want_txn: Option<&mut Option<Vec<u64>>>,
) -> Result<(), NetError> {
    let deadline = tokio::time::Instant::now() + DRAIN;
    while tokio::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, sess.read_contents()).await {
            Err(_) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Ok(Ok(contents)) => match classify_v2_cmpct_peer(&contents) {
                CmpctPeerFrame::Ping(n) => {
                    let pong = encode_pong_v2(n).map_err(|_| NetError::Protocol("pong encode"))?;
                    sess.write_contents(&pong).await?;
                }
                CmpctPeerFrame::GetBlockTxn(idx) => {
                    if let Some(slot) = want_txn.as_mut() {
                        if slot.is_none() {
                            **slot = Some(idx);
                            return Ok(());
                        }
                    }
                }
                CmpctPeerFrame::Other => {}
            },
        }
    }
    Ok(())
}

fn session_dead(err: &NetError) -> bool {
    !matches!(err, NetError::InvalidV2Type { .. } | NetError::Timeout)
}

fn ensure_session(b: &Base) -> bool {
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return true;
    }
    match b.rt.block_on(connect_session(b.p2p)) {
        Ok(s) => {
            *slot = Some(s);
            true
        }
        Err(_) => false,
    }
}

enum SendOutcome {
    Live,
    Dead,
    Compared,
}

fn send_one(b: &Base, data: &[u8]) -> SendOutcome {
    let Some(hsi) = decode_cmpct_hsi(data) else {
        return SendOutcome::Live;
    };
    if !cmpct_hsi_regtest_connectable(&hsi) {
        return SendOutcome::Live;
    }
    let Some(ours) = cmpct_missing_empty_mempool(&hsi) else {
        return SendOutcome::Live;
    };
    let Ok(payload) = encode_cmpctblock_v2(&hsi) else {
        return SendOutcome::Live;
    };
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = slot.as_mut() else {
        return SendOutcome::Dead;
    };
    let result = b.rt.block_on(async {
        if let Err(e) = sess.write_contents(&payload).await {
            return Err(e);
        }
        let mut core_idx = None;
        drain_frames(sess, Some(&mut core_idx)).await?;
        Ok(core_idx)
    });
    match result {
        Err(e) if session_dead(&e) => {
            if let Some(mut s) = slot.take() {
                s.close();
            }
            SendOutcome::Dead
        }
        Err(_) => SendOutcome::Live,
        Ok(Some(core_idx)) => {
            if core_idx != ours {
                panic!("cmpct missing-index split: ours={ours:?} core={core_idx:?}");
            }
            SendOutcome::Compared
        }
        Ok(None) => SendOutcome::Live,
    }
}

fuzz_target!(|data: &[u8]| {
    let b = base();
    let mut outcome = SendOutcome::Dead;
    for _ in 0..2 {
        if !ensure_session(b) {
            continue;
        }
        outcome = send_one(b, data);
        match outcome {
            SendOutcome::Dead => continue,
            SendOutcome::Compared => {
                note_comparison();
                return;
            }
            SendOutcome::Live => {
                SESSION_FAIL_STREAK.store(0, Ordering::Relaxed);
                return;
            }
        }
    }
    if matches!(outcome, SendOutcome::Dead) {
        let n = SESSION_FAIL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_SESSION_FAIL_STREAK {
            harness_failure("handshake/session dead streak 20");
        }
    }
});
