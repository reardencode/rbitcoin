#![no_main]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rbitcoin_fuzz::{spawn_bitcoind_p2p, tmp_dir, CoreChild};
use rbitcoin_net::{NetError, V2PlainSession};
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
static SESSION_FAIL_STREAK: AtomicU64 = AtomicU64::new(0);
const MAX_SESSION_FAIL_STREAK: u64 = 20;
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
const READ_WAIT: Duration = Duration::from_millis(50);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== V2-SESSION FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    std::process::exit(2);
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

fn try_write(b: &Base, data: &[u8]) -> bool {
    let mut slot = b.session.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = slot.as_mut() else {
        return false;
    };
    let live = b.rt.block_on(async {
        if let Err(e) = sess.write_contents(data).await {
            return !session_dead(&e);
        }
        match tokio::time::timeout(READ_WAIT, sess.read_frame()).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => !session_dead(&e),
            Err(_) => true,
        }
    });
    if !live {
        if let Some(mut s) = slot.take() {
            s.close();
        }
    }
    live
}

fuzz_target!(|data: &[u8]| {
    let b = base();
    let mut live = false;
    for _ in 0..2 {
        if !ensure_session(b) {
            continue;
        }
        if try_write(b, data) {
            live = true;
            break;
        }
    }
    if live {
        SESSION_FAIL_STREAK.store(0, Ordering::Relaxed);
    } else {
        let n = SESSION_FAIL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_SESSION_FAIL_STREAK {
            harness_failure("handshake/session dead streak 20");
        }
    }
});
