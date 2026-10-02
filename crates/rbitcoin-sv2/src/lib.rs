//! Stratum v2 Template Distribution Protocol server (sv2-spec 07).
//!
//! Noise_NX over TCP is the only transport. Plan and constraints:
//! `docs/sv2-template-provider.md`.

mod session;
mod template;
pub mod testutil;
mod transport;

use bitcoin::secp256k1::{Keypair, Secp256k1};
use rbitcoin_net::ChainHub;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub use transport::Frame;

/// Concurrent TDP sessions. RAM trade (CONTRIBUTING 9): each session retains
/// the witness-serialized txs of its live templates (≤ ~4 MB × ~3), so the
/// cap bounds retention at ≤ ~96 MB.
pub(crate) const MAX_SESSIONS: usize = 8;

/// Default [`Sv2TpConfig::setup_timeout`]. A session holds a slot from TCP
/// accept, so without it `MAX_SESSIONS` silent sockets lock clients out.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default [`Sv2TpConfig::write_timeout`].
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

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
}

pub struct Sv2TpHandle {
    pub local_addr: SocketAddr,
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
    let chain = config.chain;
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let slots = Arc::new(Semaphore::new(MAX_SESSIONS));
    let sessions: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let sessions_c = sessions.clone();

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
            let h = tokio::spawn(async move {
                let _slot = slot;
                match session::serve(
                    stream,
                    responder,
                    chain,
                    stale_grace,
                    setup_timeout,
                    write_timeout,
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
        authority_pubkey,
        task,
        sessions,
    })
}

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod template_tests;
#[cfg(test)]
mod test_chain;
