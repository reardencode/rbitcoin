//! Stratum v2 Template Distribution Protocol server (sv2-spec 07).
//!
//! Noise_NX over TCP is the only transport. Plan and constraints:
//! `docs/sv2-template-provider.md`.

mod job;
mod messages;
mod session;
mod template;
pub mod testutil;
mod transport;

use bitcoin::secp256k1::{Keypair, Secp256k1};
use rbitcoin_net::{ChainHub, RequestMeter};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub use transport::Frame;

/// Concurrent TDP sessions. RAM trade (CONTRIBUTING 9): each session keeps
/// up to 64 templates sharing the mempool's tx bodies (about 24 KB of
/// pointers per full template). Bodies that leave the pool stay alive while
/// a template holds them: at most 64 × ~4 MB per session if every template's
/// txs were replaced, ~2 GB across the cap, which costs the replacer
/// replacement fees on every interval.
pub(crate) const MAX_SESSIONS: usize = 8;

/// Default [`Sv2TpConfig::setup_timeout`]. A session holds a slot from TCP
/// accept, so without it `MAX_SESSIONS` silent sockets lock clients out.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default [`Sv2TpConfig::write_timeout`].
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default [`Sv2TpConfig::provide_timeout`]: a JDS relays the request to
/// its JDC and the answer back, so the wait is two hops over the internet.
pub const PROVIDE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default [`Sv2TpConfig::fee_delta`] (stratum-mining `sv2-tp`
/// `-sv2feedelta`).
pub const FEE_DELTA: u64 = 1000;

/// Default [`Sv2TpConfig::template_interval`] (stratum-mining `sv2-tp`
/// `-templateinterval`).
pub const TEMPLATE_INTERVAL: Duration = Duration::from_secs(5);

/// Lower bound on [`Sv2TpConfig::template_interval`]. CPU trade: each check
/// after a mempool change is one build under the mempool read lock, so a
/// session costs at most ten per second.
pub(crate) const MIN_TEMPLATE_INTERVAL: Duration = Duration::from_millis(100);

/// Upper bound on [`Sv2TpConfig::template_interval`]; each check deadline is
/// `Instant + template_interval`, which panics on overflow.
pub const MAX_TEMPLATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Upper bound on [`Sv2TpConfig::stale_grace`]; the grace deadline is
/// `Instant + stale_grace`, which panics on overflow.
pub const MAX_STALE_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Sv2TpConfig {
    pub listen: SocketAddr,
    /// Tip, params, and the attached mempool the templates are built from.
    pub chain: Arc<ChainHub>,
    /// Authority secret key; clients pin its x-only public key.
    pub authority_secret: [u8; 32],
    /// Validity of the per-connection Noise certificate signed by the authority.
    pub cert_validity: Duration,
    /// How long a template on a replaced prev hash still answers requests.
    pub stale_grace: Duration,
    /// Deadline from TCP accept through the Noise handshake,
    /// `SetupConnection`, and the first `CoinbaseOutputConstraints` (without
    /// which the session never writes). No read deadline after that: TDP has
    /// no keepalive and a client may stay silent while the TP pushes.
    pub setup_timeout: Duration,
    /// A socket write that makes no progress this long closes the session,
    /// so a client that stops reading cannot hold a slot.
    pub write_timeout: Duration,
    /// How long a `ProposeTemplate` the node answered
    /// `ProvideMissingTransactions` waits for the
    /// `ProvideMissingTransactions.Success`; a later one is
    /// `unknown-request-id`.
    pub provide_timeout: Duration,
    /// With the tip unchanged, a rebuild is pushed only when its fees are at
    /// least this many sats above the session's last template.
    pub fee_delta: u64,
    /// Minimum time from a session's last push to a fee push; the mempool
    /// is checked once per interval.
    pub template_interval: Duration,
}

/// Template work across this listener's sessions, for `tip: perf` and
/// `/metrics`.
#[derive(Default)]
pub struct Sv2TpStats {
    /// Fee checks: one per session per interval once it has a template.
    /// Counted only; a check that builds is timed under `builds`.
    pub fee_checks: RequestMeter,
    /// Template builds (constraints, tip, fee check), wall time each.
    pub builds: RequestMeter,
}

pub struct Sv2TpHandle {
    pub local_addr: SocketAddr,
    stats: Arc<Sv2TpStats>,
    /// X-only authority public key the clients verify the certificate against.
    pub(crate) authority_pubkey: [u8; 32],
    task: JoinHandle<()>,
    sessions: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Sv2TpHandle {
    /// The authority public key as SRI `key-utils` prints it (the form JDC
    /// and pool configs take): base58check of version `1u16` LE, then the
    /// x-only key.
    pub fn authority_key(&self) -> String {
        let mut v = [0u8; 34];
        v[..2].copy_from_slice(&1u16.to_le_bytes());
        v[2..].copy_from_slice(&self.authority_pubkey);
        bitcoin::base58::encode_check(&v)
    }

    pub fn stats(&self) -> Arc<Sv2TpStats> {
        Arc::clone(&self.stats)
    }

    pub async fn shutdown(self) {
        self.task.abort();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        for t in sessions.drain(..) {
            t.abort();
        }
    }
}

/// Bind the listener and serve TDP sessions until [`Sv2TpHandle::shutdown`].
///
/// At `MAX_SESSIONS` the next connection is closed before the handshake;
/// existing sessions are not touched.
pub async fn run_sv2_tp(config: Sv2TpConfig) -> io::Result<Sv2TpHandle> {
    // noise_sv2 casts `cert_validity.as_secs()` to u32; a larger value wraps.
    if u32::try_from(config.cert_validity.as_secs()).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sv2 cert_validity: over u32::MAX seconds",
        ));
    }
    if config.stale_grace > MAX_STALE_GRACE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sv2 stale_grace: over {}s", MAX_STALE_GRACE.as_secs()),
        ));
    }
    if !(MIN_TEMPLATE_INTERVAL..=MAX_TEMPLATE_INTERVAL).contains(&config.template_interval) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "sv2 template_interval: want {}ms to {}s",
                MIN_TEMPLATE_INTERVAL.as_millis(),
                MAX_TEMPLATE_INTERVAL.as_secs()
            ),
        ));
    }
    let keypair =
        Keypair::from_seckey_slice(&Secp256k1::new(), &config.authority_secret).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("sv2 authority key: {e}"),
            )
        })?;
    let authority_pubkey = keypair.x_only_public_key().0.serialize();
    let authority_secret = config.authority_secret;
    let cert_validity = config.cert_validity;
    let stale_grace = config.stale_grace;
    let setup_timeout = config.setup_timeout;
    let write_timeout = config.write_timeout;
    let provide_timeout = config.provide_timeout;
    let fee_push = session::FeePush {
        delta: config.fee_delta,
        interval: config.template_interval,
    };
    let chain = config.chain;
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let stats = Arc::new(Sv2TpStats::default());
    let slots = Arc::new(Semaphore::new(MAX_SESSIONS));
    let sessions: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let sessions_c = sessions.clone();
    let stats_c = Arc::clone(&stats);

    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(a) => a,
                Err(e) => {
                    rbitcoin_log::warn!("sv2: accept failed ({e})");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Linux autotunes SO_SNDBUF up to tcp_wmem max. write() keeps
            // completing into that buffer after the peer stops reading, so
            // the deadline does not start. The write-deadline test pins a
            // small buffer on the accepted socket.
            #[cfg(all(test, target_os = "linux"))]
            test_send_buffer::apply(&stream);
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                rbitcoin_log::warn!("sv2: reject {peer} (at max_sessions={MAX_SESSIONS})");
                drop(stream);
                continue;
            };
            let responder = match noise_sv2::Responder::from_authority_kp(
                &authority_pubkey,
                &authority_secret,
                cert_validity,
            ) {
                Ok(r) => r,
                Err(e) => {
                    rbitcoin_log::warn!("sv2: responder for {peer} ({e:?})");
                    continue;
                }
            };
            rbitcoin_log::info!("sv2: connect {peer}");
            let chain = Arc::clone(&chain);
            let stats = Arc::clone(&stats_c);
            let h = tokio::spawn(async move {
                let _slot = slot;
                match session::serve(
                    stream,
                    responder,
                    chain,
                    stale_grace,
                    setup_timeout,
                    write_timeout,
                    provide_timeout,
                    fee_push,
                    stats,
                )
                .await
                {
                    Ok(()) => rbitcoin_log::info!("sv2: disconnect {peer}"),
                    Err(e) => rbitcoin_log::info!("sv2: disconnect {peer} ({e})"),
                }
            });
            let mut g = sessions_c.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|t| !t.is_finished());
            g.push(h);
        }
    });

    Ok(Sv2TpHandle {
        local_addr,
        stats,
        authority_pubkey,
        task,
        sessions,
    })
}

/// Accepted-socket `SO_SNDBUF` for one listener.
///
/// `write()` returns as soon as the bytes fit in the send buffer. With
/// autotune that is several MiB, so a client that never reads still looks
/// like a live writer and the deadline never starts. The pin is keyed by
/// the listener address so another test's accept keeps autotune.
#[cfg(all(test, target_os = "linux"))]
mod test_send_buffer {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::sync::{LazyLock, Mutex};
    use tokio::net::TcpStream;

    static PINS: LazyLock<Mutex<HashMap<SocketAddr, u32>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(crate) struct Guard {
        addr: SocketAddr,
    }

    pub(crate) fn pin(addr: SocketAddr, bytes: u32) -> Guard {
        PINS.lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(addr, bytes);
        Guard { addr }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            PINS.lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.addr);
        }
    }

    pub(super) fn apply(stream: &TcpStream) {
        let Ok(addr) = stream.local_addr() else {
            return;
        };
        let n = {
            let pins = PINS.lock().unwrap_or_else(|e| e.into_inner());
            let Some(n) = pins.get(&addr).copied() else {
                return;
            };
            n
        };
        unsafe extern "C" {
            fn setsockopt(fd: i32, level: i32, opt: i32, val: *const i32, len: u32) -> i32;
            fn getsockopt(fd: i32, level: i32, opt: i32, val: *mut i32, len: *mut u32) -> i32;
        }
        // linux/asm-generic/socket.h: SOL_SOCKET = 1, SO_SNDBUF = 7.
        let fd = stream.as_raw_fd();
        let val = n as i32;
        // SAFETY: `fd` is the accepted stream. `val` is one i32 and `len` is
        // its size. SOL_SOCKET / SO_SNDBUF take that pointer.
        let rc = unsafe { setsockopt(fd, 1, 7, &val, 4) };
        assert_eq!(rc, 0, "SO_SNDBUF: {}", std::io::Error::last_os_error());
        let mut got = 0i32;
        let mut len = 4u32;
        // SAFETY: same socket. `got` is one i32 and `len` is in-out its size.
        let rc = unsafe { getsockopt(fd, 1, 7, &mut got, &mut len) };
        assert_eq!(rc, 0, "SO_SNDBUF get: {}", std::io::Error::last_os_error());
        // The kernel doubles the value for bookkeeping. Above 64KiB means the
        // pin did not stick and autotune is still in effect.
        assert!(
            got > 0 && got <= 64 * 1024,
            "SO_SNDBUF stayed {got} after requesting {n}"
        );
    }
}

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod template_tests;
#[cfg(test)]
mod test_chain;
