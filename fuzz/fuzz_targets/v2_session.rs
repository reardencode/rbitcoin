#![no_main]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rbitcoin_fuzz::{
    encode_getheaders_empty_v2, encode_ping_v2, encode_pong_v2, encode_sendcmpct_hb_v2,
    encode_verack_v2,
};
use rbitcoin_fuzz::{spawn_bitcoind_p2p, tmp_dir, CoreChild};
use rbitcoin_net::{classify_v2_cmpct_peer, CmpctPeerFrame, NetError, V2PlainSession};
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
const READ_WAIT: Duration = Duration::from_millis(200);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== V2-SESSION FUZZ HARNESS FAILURE ===");
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
        eprintln!("v2-session: comparisons={n}");
    }
}

fn base() -> &'static Base {
    BASE.get_or_init(|| {
        let bin = std::env::var("RBITCOIN_CORE_BITCOIND").unwrap_or_default();
        if bin.is_empty() {
            harness_failure("RBITCOIN_CORE_BITCOIND unset");
        }
        let datadir = tmp_dir("rbtc-v2-session-core");
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
                    Ok(s) => return Ok(s),
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

fn nonce_from(rest: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = rest.len().min(8);
    b[..n].copy_from_slice(&rest[..n]);
    u64::from_le_bytes(b)
}

fn structured(data: &[u8]) -> (Vec<u8>, Option<u64>) {
    if data.is_empty() {
        return (Vec::new(), None);
    }
    let nonce = nonce_from(&data[1..]);
    let enc = |r: Result<Vec<u8>, NetError>| r.unwrap_or_else(|_| data.to_vec());
    match data[0] % 6 {
        0 => (enc(encode_ping_v2(nonce)), Some(nonce)),
        1 => (enc(encode_pong_v2(nonce)), None),
        2 => (enc(encode_sendcmpct_hb_v2()), None),
        3 => (enc(encode_verack_v2()), None),
        4 => (enc(encode_getheaders_empty_v2()), None),
        _ => (data[1..].to_vec(), None),
    }
}

enum SendOutcome {
    Dead,
    Live,
    Compared,
}

fn send_one(b: &Base, data: &[u8]) -> SendOutcome {
    let (payload, want_pong) = structured(data);
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = slot.as_mut() else {
        return SendOutcome::Dead;
    };
    let result = b.rt.block_on(async {
        if payload.is_empty() {
            return Ok(false);
        }
        if let Err(e) = sess.write_contents(&payload).await {
            return Err(e);
        }
        let Some(nonce) = want_pong else {
            match tokio::time::timeout(READ_WAIT, sess.read_frame()).await {
                Ok(Ok(())) => return Ok(false),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(false),
            }
        };
        let deadline = tokio::time::Instant::now() + READ_WAIT;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, sess.read_contents()).await {
                Err(_) => return Ok(false),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(contents)) => match classify_v2_cmpct_peer(&contents) {
                    CmpctPeerFrame::Pong(n) if n == nonce => return Ok(true),
                    CmpctPeerFrame::Ping(n) => {
                        let pong =
                            encode_pong_v2(n).map_err(|_| NetError::Protocol("pong encode"))?;
                        sess.write_contents(&pong).await?;
                    }
                    _ => {}
                },
            }
        }
        Ok(false)
    });
    match result {
        Err(e) if session_dead(&e) => {
            if let Some(mut s) = slot.take() {
                s.close();
            }
            SendOutcome::Dead
        }
        Err(_) => SendOutcome::Live,
        Ok(true) => SendOutcome::Compared,
        Ok(false) => SendOutcome::Live,
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
