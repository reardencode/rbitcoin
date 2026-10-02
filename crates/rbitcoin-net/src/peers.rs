//! Live P2P session table for RPC (`getpeerinfo` / `addnode` / `disconnectnode`).

use crate::error::NetError;
use bitcoin::p2p::address::{AddrV2Message, Address};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{BlockHash, Wtxid};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use tokio::sync::mpsc;

/// Per-peer outbound queue cap (a few megabytes). Not a configuration knob.
///
/// Core's `-maxsendbuffer` is the same idea. One reply may land past the cap;
/// the next inbound request from that peer waits until the writer drains.
pub const PEER_SEND_BUDGET: usize = 4 * 1024 * 1024;

/// Queued-byte estimate. Headers are 81 wire bytes, inv-like rows are 36,
/// legacy addr rows are 30. Encoded block bodies use their buffer length.
pub(crate) fn outbound_msg_bytes(msg: &NetworkMessage) -> usize {
    match msg {
        NetworkMessage::Headers(h) => h.len().saturating_mul(81),
        NetworkMessage::Inv(v) | NetworkMessage::NotFound(v) | NetworkMessage::GetData(v) => {
            v.len().saturating_mul(36)
        }
        NetworkMessage::Tx(tx) => tx.total_size(),
        NetworkMessage::Block(b) => b.total_size(),
        NetworkMessage::Addr(a) => a.len().saturating_mul(30),
        NetworkMessage::AddrV2(a) => a.len().saturating_mul(61),
        NetworkMessage::CmpctBlock(_) => 1024,
        _ => 64,
    }
}

pub(crate) fn outbound_queued_bytes(out: &PeerOut) -> usize {
    match out {
        PeerOut::Msg(m) => outbound_msg_bytes(m),
        PeerOut::Encoded(b) => b.len(),
    }
}

/// Session writer payload: application messages or pre-encoded v2 block bytes.
#[derive(Debug)]
pub enum PeerOut {
    Msg(NetworkMessage),
    Encoded(Vec<u8>),
}

impl PeerOut {
    #[cfg(test)]
    pub(crate) fn expect_msg(self) -> NetworkMessage {
        match self {
            PeerOut::Msg(m) => m,
            PeerOut::Encoded(_) => panic!("expected application message, got encoded block"),
        }
    }
}

/// Insertion-order set that drops the oldest key at `cap` (INV / origin skip).
/// Re-insert of a live key is a no-op; it does not refresh FIFO position.
#[derive(Debug)]
pub(crate) struct CappedSet<T> {
    set: HashSet<T>,
    fifo: VecDeque<T>,
}

impl<T> CappedSet<T> {
    pub(crate) fn new() -> Self {
        Self {
            set: HashSet::new(),
            fifo: VecDeque::new(),
        }
    }

    pub(crate) fn contains(&self, item: &T) -> bool
    where
        T: Eq + Hash,
    {
        self.set.contains(item)
    }

    pub(crate) fn contains_key(&self, item: &T) -> bool
    where
        T: Eq + Hash,
    {
        self.contains(item)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.set.len()
    }

    pub(crate) fn insert(&mut self, item: T, cap: usize)
    where
        T: Eq + Hash + Copy,
    {
        if cap == 0 || self.set.contains(&item) {
            return;
        }
        if self.set.len() >= cap {
            if let Some(old) = self.fifo.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(item);
        self.fifo.push_back(item);
    }
}

/// How we classified the session (`getpeerinfo.connection_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerConnType {
    Inbound,
    OutboundFullRelay,
    /// Operator addnode / connect (`connection_type` = `manual`).
    Manual,
    BlockRelay,
    AddrFetch,
    Feeler,
}

impl PeerConnType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::OutboundFullRelay => "outbound-full-relay",
            Self::Manual => "manual",
            Self::BlockRelay => "block-relay-only",
            Self::AddrFetch => "addr-fetch",
            Self::Feeler => "feeler",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound-full-relay" => Ok(Self::OutboundFullRelay),
            "manual" => Ok(Self::Manual),
            "block-relay-only" => Ok(Self::BlockRelay),
            "addr-fetch" => Ok(Self::AddrFetch),
            "feeler" => Ok(Self::Feeler),
            other => Err(format!("unknown connection type {other}")),
        }
    }
}

pub(crate) fn trying_connection_log(typ: PeerConnType, addr: impl std::fmt::Display) -> String {
    format!("p2p: trying connection ({}) to {addr}", typ.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialTarget {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

impl DialTarget {
    pub(crate) fn from_net(addr: crate::NetAddr) -> Self {
        match addr {
            crate::NetAddr::Ip(s) => Self::Socket(s),
            crate::NetAddr::Cjdns { ip, port } => Self::Socket(SocketAddr::from((ip, port))),
            other => Self::Domain {
                host: other.host_str(),
                port: other.port(),
            },
        }
    }

    /// VERSION v1 `Address` field. Overlay Domain has no SocketAddr; Core uses 0.0.0.0.
    pub fn version_socket(&self) -> SocketAddr {
        match self {
            Self::Socket(addr) => *addr,
            Self::Domain { port, .. } => SocketAddr::from(([0, 0, 0, 0], *port)),
        }
    }

    pub fn peer_hint(&self) -> SocketAddr {
        self.version_socket()
    }

    pub fn net_addr(&self) -> crate::NetAddr {
        match self {
            Self::Socket(addr) => crate::NetAddr::from_socket(*addr),
            Self::Domain { host, port } => format!("{host}:{port}")
                .parse()
                .expect("DialTarget::Domain is host:port from overlay NetAddr"),
        }
    }
}

impl std::fmt::Display for DialTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Request that the node dial `addr` as `typ`.
#[derive(Clone, Debug)]
pub struct DialRequest {
    pub target: DialTarget,
    pub typ: PeerConnType,
}

#[derive(Clone, Debug)]
pub struct PeerEndpoint {
    pub addr: SocketAddr,
    pub net: crate::NetAddr,
    pub addrbind: SocketAddr,
}

/// Queued `sendcmpct` to write on the next heartbeat (`AtomicU8` payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PendingSendCmpct {
    None = 0,
    Lb = 1,
    Hb = 2,
}

impl PendingSendCmpct {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Lb,
            2 => Self::Hb,
            _ => Self::None,
        }
    }
}

/// One live session (RPC snapshot + disconnect flag + byte counters).
pub struct LivePeer {
    pub id: u64,
    pub addr: SocketAddr,
    pub net: crate::NetAddr,
    pub addrbind: SocketAddr,
    pub subver: String,
    pub inbound: bool,
    pub services: u64,
    pub startingheight: i32,
    pub conn_type: PeerConnType,
    /// Their `version.relay`. False or `block-relay-only` → `relaytxes=false`.
    pub relay: bool,
    pub stop: AtomicBool,
    /// Full `Block`/`CmpctBlock` messages queued to this session's writer.
    pub serve_inflight: AtomicUsize,
    /// Bytes sitting in this session's outbound queue (estimate).
    send_queued: AtomicUsize,
    /// Wakes the reader after the writer drains under [`PEER_SEND_BUDGET`].
    send_resume: tokio::sync::Notify,
    /// Inbound `getaddr` is answered once per connection.
    getaddr_answered: AtomicBool,
    /// We announce new tips as `cmpctblock` to this peer (`sendcmpct` they sent).
    pub hb_to: AtomicBool,
    /// They announce new tips as `cmpctblock` to us (`sendcmpct` they sent).
    pub hb_from: AtomicBool,
    /// Session should send `sendcmpct` (`PendingSendCmpct` as u8).
    pub pending_sendcmpct: std::sync::atomic::AtomicU8,
    /// Last header we announced to this peer.
    best_header_sent: Mutex<Option<BlockHash>>,
    /// Best connected block this peer advertised.
    best_known: Mutex<Option<BlockHash>>,
    /// Block hashes this peer just sent us — do not announce them back.
    recently_from: Mutex<HashSet<BlockHash>>,
    /// We already sent inv-triggered getheaders this session (before sync).
    inv_asked_headers: AtomicBool,
    /// This session is the headers-sync peer (or one of them after catch-up).
    sync_started: AtomicBool,
    /// Unix seconds when initial headers sync times out (`0` = none).
    headers_sync_timeout: AtomicU64,
    /// Waiting for a headers reply to our getheaders (no BIP130 cap).
    awaiting_headers: AtomicBool,
    /// Wtxids we INV'd to this peer. GetData for a live mempool tx is
    /// answered only if announced here or the tx is reorg-servable.
    announced_wtx: Mutex<CappedSet<Wtxid>>,
    /// Compact fill slots taken by this session (hub-global `cmpct_fills`).
    taken_cmpct: Mutex<Vec<BlockHash>>,
    /// Mempool sequence at last tx INV (starts at 1).
    last_inv_sequence: AtomicU64,
    /// Queued tx INV hashes not yet sent.
    inv_to_send: AtomicU32,
    /// Last clock we considered for delayed tx INV (`0` = not initialized).
    last_tx_inv_now: AtomicU64,
    /// Set when mocktime jumps; next ping/tick announces mempool txs.
    tx_inv_requested: AtomicBool,
    /// Outstanding ping nonce (`0` = none).
    ping_nonce_sent: AtomicU64,
    /// When the last ping was sent, or `0` if never.
    ping_start_secs: AtomicU64,
    /// RPC `ping` queued a probe.
    ping_queued: AtomicBool,
    pingtime: Mutex<Option<f64>>,
    minping: Mutex<Option<f64>>,
    owner: std::sync::Weak<PeerHub>,
    recv: Mutex<HashMap<String, u64>>,
    sent: Mutex<HashMap<String, u64>>,
    last_block: AtomicU64,
    last_transaction: AtomicU64,
    minfeefilter_sat_kvb: AtomicU64,
    /// Shared with the TCP reader so split-header bytes count (`p2p_invalid_messages`).
    wire_recv: Mutex<Option<std::sync::Arc<AtomicU64>>>,
    wire_sent: Mutex<Option<std::sync::Arc<AtomicU64>>>,
    /// Compact hashes whose first `blocktxn` reconstruct already failed.
    failed_cmpct: Mutex<HashSet<BlockHash>>,
    /// Heights of blocks we have requested from this peer and not yet received
    /// (`getpeerinfo.inflight`).
    inflight: Mutex<Vec<u32>>,
    /// Session writer. RPC/accept flushes tx INVs onto this (`p2p_blocksonly`).
    out_tx: Mutex<Option<mpsc::UnboundedSender<PeerOut>>>,
    /// Addr relay tokens still available, and the millisecond they were last filled.
    addr_tokens: Mutex<f64>,
    addr_token_ms: AtomicU64,
    /// Unix seconds when this session was registered.
    connected_at: AtomicU64,
    /// Skip INV for mempool txs with `accept_gen < floor` (post-verack privacy).
    inv_gen_floor: AtomicU64,
    /// Age-INV due-log cursor (`due_secs`, `accept_gen`).
    age_inv_seen_due: AtomicU64,
    age_inv_seen_gen: AtomicU64,
    /// Writer-task abort — FIN via dropping the write half.
    writer_abort: Mutex<Option<tokio::task::AbortHandle>>,
    /// Whole session-task abort — drops reader+writer if the loop is stuck.
    session_abort: Mutex<Option<tokio::task::AbortHandle>>,
    /// Cloned std TCP fd for `Shutdown::Both` on `disconnectnode` so the far
    /// side sees EOF even if our session task is mid-frame.
    tcp_shutdown: Mutex<Option<std::net::TcpStream>>,
    /// VERSION+VERACK finished. Connecting rows stay false (`p2p_timeouts`).
    handshake_complete: AtomicBool,
    /// BIP324 transport finished. False while EARLY_KEY_RESPONSE / garbage.
    v2_transport_ready: AtomicBool,
    /// Peer sent BIP155 `sendaddrv2` (use `addrv2` for self-announce / GETADDR).
    wants_addrv2: AtomicBool,
    /// Peer sent BIP339 `wtxidrelay` (handshake, before VERACK).
    wtxid_relay: AtomicBool,
    /// Next self-announce unix seconds (`0` = never sent).
    next_local_addr_send: AtomicU64,
    /// VERSION timestamp (unix seconds; `0` on the connecting placeholder).
    version_timestamp: i64,
}

#[cfg(target_os = "linux")]
fn tcp_has_peer_fin(tcp: &std::net::TcpStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: tcp.as_raw_fd(),
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: fd is a live TcpStream as_raw_fd, timeout 0.
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n >= 0 && pfd.revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR) != 0
}

#[cfg(not(target_os = "linux"))]
fn tcp_has_peer_fin(_tcp: &std::net::TcpStream) -> bool {
    false
}

impl LivePeer {
    pub fn attach_wire(&self, wire: crate::v2::WireBytes) {
        *self.wire_recv.lock().unwrap_or_else(|e| e.into_inner()) = Some(wire.recv);
        *self.wire_sent.lock().unwrap_or_else(|e| e.into_inner()) = Some(wire.sent);
    }

    pub fn has_wire(&self) -> bool {
        self.wire_recv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub fn raw_recv(&self) -> u64 {
        self.wire_recv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|a| a.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn raw_sent(&self) -> u64 {
        self.wire_sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|a| a.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn note_recv(&self, cmd: &str, nbytes: u64) {
        let n = acct_bytes(cmd, nbytes);
        *self
            .recv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(cmd.into())
            .or_insert(0) += n;
    }

    /// Store an already-computed wire size (v2 `*other*` = contents + expansion).
    pub fn note_recv_raw(&self, cmd: &str, nbytes: u64) {
        *self
            .recv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(cmd.into())
            .or_insert(0) += nbytes;
    }

    pub fn note_sent(&self, cmd: &str, nbytes: u64) {
        let n = acct_bytes(cmd, nbytes);
        *self
            .sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(cmd.into())
            .or_insert(0) += n;
    }

    pub fn request_disconnect(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn mark_handshake_complete(&self) {
        self.handshake_complete.store(true, Ordering::Release);
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete.load(Ordering::Acquire)
    }

    pub fn mark_v2_transport_ready(&self) {
        self.v2_transport_ready.store(true, Ordering::Release);
    }

    pub fn v2_transport_ready(&self) -> bool {
        self.v2_transport_ready.load(Ordering::Acquire)
    }

    pub fn set_wants_addrv2(&self) {
        self.wants_addrv2.store(true, Ordering::Relaxed);
    }

    pub fn wants_addrv2(&self) -> bool {
        self.wants_addrv2.load(Ordering::Relaxed)
    }

    pub fn set_wtxid_relay(&self) {
        self.wtxid_relay.store(true, Ordering::Relaxed);
    }

    pub fn wtxid_relay(&self) -> bool {
        self.wtxid_relay.load(Ordering::Relaxed)
    }

    /// Whether the local-address broadcast timer has elapsed (~24h).
    pub fn take_local_addr_due(&self, now: u64) -> Option<SocketAddr> {
        const DAY: u64 = 24 * 60 * 60;
        let hub = self.owner.upgrade()?;
        let sock = hub.advertise_local_socket()?;
        let prev = self.next_local_addr_send.load(Ordering::Relaxed);
        if prev != 0 && now < prev {
            return None;
        }
        let next = now.saturating_add(DAY).max(1);
        self.next_local_addr_send
            .compare_exchange(prev, next, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        Some(sock)
    }

    pub fn take_self_announce_msg(&self) -> Option<NetworkMessage> {
        if matches!(
            self.conn_type,
            PeerConnType::Feeler | PeerConnType::BlockRelay | PeerConnType::AddrFetch
        ) {
            return None;
        }
        let hub = self.owner.upgrade()?;
        let onion = hub.p2p_onion();
        let i2p = hub.p2p_i2p();
        let sock = hub.advertise_local_socket();
        if onion.is_none() && i2p.is_none() && sock.is_none() {
            return None;
        }
        const DAY: u64 = 24 * 60 * 60;
        let now = self.clock_now();
        let prev = self.next_local_addr_send.load(Ordering::Relaxed);
        if prev != 0 && now < prev {
            return None;
        }
        let next = now.saturating_add(DAY).max(1);
        self.next_local_addr_send
            .compare_exchange(prev, next, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        let services = crate::peer::local_service_flags_pruned(hub.is_pruned());
        let t = now as u32;
        if self.wants_addrv2() {
            let mut v = Vec::new();
            if let Some(addr) = onion {
                rbitcoin_log::debug!("{}", crate::peer::advertising_address_log(addr, self.id));
                v.push(AddrV2Message {
                    time: t,
                    services,
                    addr: addr.to_addrv2(),
                    port: addr.port(),
                });
            }
            if let Some(addr) = i2p {
                rbitcoin_log::debug!("{}", crate::peer::advertising_address_log(addr, self.id));
                v.push(AddrV2Message {
                    time: t,
                    services,
                    addr: addr.to_addrv2(),
                    port: addr.port(),
                });
            }
            if let Some(sock) = sock {
                rbitcoin_log::debug!("{}", crate::peer::advertising_address_log(sock, self.id));
                let net = crate::NetAddr::from_socket(sock);
                v.push(AddrV2Message {
                    time: t,
                    services,
                    addr: net.to_addrv2(),
                    port: net.port(),
                });
            }
            if v.is_empty() {
                return None;
            }
            Some(NetworkMessage::AddrV2(v))
        } else {
            let sock = match sock {
                Some(s) if matches!(crate::NetAddr::from_socket(s), crate::NetAddr::Ip(_)) => s,
                _ => return None,
            };
            rbitcoin_log::debug!("{}", crate::peer::advertising_address_log(sock, self.id));
            Some(NetworkMessage::Addr(vec![(
                t,
                Address::new(&sock, services),
            )]))
        }
    }

    pub fn queue_self_announce_if_due(&self) {
        let Some(msg) = self.take_self_announce_msg() else {
            return;
        };
        let g = self.out_tx.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = g.as_ref() {
            let _ = tx.send(PeerOut::Msg(msg));
        }
    }

    pub fn connected_at_secs(&self) -> u64 {
        self.connected_at.load(Ordering::Relaxed)
    }

    pub fn set_writer_abort(&self, handle: tokio::task::AbortHandle) {
        *self.writer_abort.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    pub fn set_session_abort(&self, handle: tokio::task::AbortHandle) {
        *self.session_abort.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    pub fn attach_tcp_shutdown(&self, stream: std::net::TcpStream) {
        *self.tcp_shutdown.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
    }

    pub fn tcp_fin(&self) -> bool {
        let g = self.tcp_shutdown.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tcp) = g.as_ref() else {
            return false;
        };
        if tcp_has_peer_fin(tcp) {
            return true;
        }
        let _ = tcp.set_nonblocking(true);
        let mut b = [0u8; 1];
        match tcp.peek(&mut b) {
            Ok(0) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => false,
            Err(_) => true,
            Ok(_) => false,
        }
    }

    fn take_writer_abort(&self) -> Option<tokio::task::AbortHandle> {
        self.writer_abort
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    fn take_session_abort(&self) -> Option<tokio::task::AbortHandle> {
        self.session_abort
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    fn take_tcp_shutdown(&self) -> Option<std::net::TcpStream> {
        self.tcp_shutdown
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    fn clear_out_tx(&self) {
        *self.out_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn note_failed_cmpct(&self, hash: BlockHash) {
        self.failed_cmpct
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(hash);
    }

    pub fn has_failed_cmpct(&self, hash: &BlockHash) -> bool {
        self.failed_cmpct
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(hash)
    }

    pub fn set_hb_to(&self, v: bool) {
        self.hb_to.store(v, Ordering::Relaxed);
    }

    pub fn set_hb_from(&self, v: bool) {
        self.hb_from.store(v, Ordering::Relaxed);
    }

    pub fn note_best_header_sent(&self, hash: BlockHash) {
        *self
            .best_header_sent
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hash);
    }

    pub fn note_best_known(&self, hash: BlockHash) {
        *self.best_known.lock().unwrap_or_else(|e| e.into_inner()) = Some(hash);
    }

    pub fn best_known(&self) -> Option<BlockHash> {
        *self.best_known.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn header_marks(&self) -> (Option<BlockHash>, Option<BlockHash>) {
        (
            *self
                .best_header_sent
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            *self.best_known.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    pub fn note_block_from_peer(&self, hash: BlockHash) {
        let mut g = self.recently_from.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= 256 {
            g.clear();
        }
        g.insert(hash);
    }

    pub fn take_block_from_peer(&self, hash: &BlockHash) -> bool {
        self.recently_from
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(hash)
    }

    pub fn try_ask_headers_for_inv(&self) -> bool {
        !self.inv_asked_headers.swap(true, Ordering::Relaxed)
    }

    pub fn is_sync_started(&self) -> bool {
        self.sync_started.load(Ordering::Relaxed)
    }

    pub fn advertises_network(&self) -> bool {
        self.services & service_flags_u64(ServiceFlags::NETWORK) != 0
    }

    /// NETWORK or NETWORK_LIMITED — this peer can serve blocks.
    pub fn can_serve_blocks(&self) -> bool {
        let net = service_flags_u64(ServiceFlags::NETWORK);
        let lim = service_flags_u64(ServiceFlags::NETWORK_LIMITED);
        self.services & (net | lim) != 0
    }

    pub fn note_awaiting_headers(&self) {
        self.awaiting_headers.store(true, Ordering::Relaxed);
    }

    pub fn is_awaiting_headers(&self) -> bool {
        self.awaiting_headers.load(Ordering::Relaxed)
    }

    pub fn take_awaiting_headers(&self) -> bool {
        self.awaiting_headers.swap(false, Ordering::Relaxed)
    }

    pub fn note_announced_wtx(&self, wtxid: Wtxid) {
        self.announced_wtx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(wtxid, 50_000);
    }

    pub fn has_announced_wtx(&self, wtxid: &Wtxid) -> bool {
        self.announced_wtx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(wtxid)
    }

    pub(crate) fn try_cmpct_fill(&self, hash: BlockHash) -> bool {
        let Some(ph) = self.peer_hub() else {
            return true;
        };
        if !ph.try_cmpct_fill_slot(hash, self.inbound) {
            return false;
        }
        self.taken_cmpct
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(hash);
        true
    }

    pub(crate) fn release_cmpct_taken(&self, hash: BlockHash) {
        let mut g = self.taken_cmpct.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = g.iter().position(|h| *h == hash) else {
            return;
        };
        g.remove(i);
        drop(g);
        if let Some(ph) = self.peer_hub() {
            ph.release_cmpct_fill(hash, self.inbound);
        }
    }

    fn release_all_cmpct(&self) {
        let taken =
            std::mem::take(&mut *self.taken_cmpct.lock().unwrap_or_else(|e| e.into_inner()));
        let Some(ph) = self.peer_hub() else {
            return;
        };
        for h in taken {
            ph.release_cmpct_fill(h, self.inbound);
        }
    }

    pub fn last_inv_sequence(&self) -> u64 {
        self.last_inv_sequence.load(Ordering::Relaxed)
    }

    pub fn inv_to_send(&self) -> u32 {
        self.inv_to_send.load(Ordering::Relaxed)
    }

    pub fn set_inv_to_send(&self, n: u32) {
        self.inv_to_send.store(n, Ordering::Relaxed);
    }

    pub fn note_tx_inv_seq(&self, mempool_seq: u64) {
        self.last_inv_sequence.store(mempool_seq, Ordering::Relaxed);
    }

    pub fn request_tx_inv(&self) {
        self.tx_inv_requested.store(true, Ordering::Relaxed);
    }

    /// True when mock/wall clock jumped enough to announce queued mempool txs.
    pub fn take_tx_inv_due(&self, now: u64) -> bool {
        if self.tx_inv_requested.swap(false, Ordering::Relaxed) {
            self.last_tx_inv_now.store(now, Ordering::Relaxed);
            return true;
        }
        let prev = self.last_tx_inv_now.load(Ordering::Relaxed);
        if prev == 0 {
            self.last_tx_inv_now.store(now, Ordering::Relaxed);
            return false;
        }
        if now.saturating_sub(prev) >= 30 {
            self.last_tx_inv_now.store(now, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn queue_ping(&self) {
        self.ping_queued.store(true, Ordering::Relaxed);
    }

    pub fn queue_msg(&self, msg: NetworkMessage) -> bool {
        let n = outbound_msg_bytes(&msg);
        let ok = self
            .writer()
            .is_some_and(|tx| tx.send(PeerOut::Msg(msg)).is_ok());
        if ok {
            self.note_send_queued(n);
        }
        ok
    }

    pub(crate) fn send_queued(&self) -> usize {
        self.send_queued.load(Ordering::Relaxed)
    }

    /// True after a reply has already pushed this peer past [`PEER_SEND_BUDGET`].
    pub(crate) fn send_over_budget(&self) -> bool {
        self.send_queued() > PEER_SEND_BUDGET
    }

    pub(crate) fn note_send_queued(&self, n: usize) {
        if n > 0 {
            self.send_queued.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Writer finished (or dropped) `n` queued bytes. Wakes a paused reader.
    pub(crate) fn note_send_written(&self, n: usize) {
        let prev = self
            .send_queued
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            })
            .unwrap_or(0);
        if prev.saturating_sub(n) <= PEER_SEND_BUDGET {
            self.send_resume.notify_waiters();
        }
    }

    /// Reader pause. Registers the waiter before the budget check.
    pub(crate) async fn wait_send_budget(&self) {
        loop {
            let notified = self.send_resume.notified();
            if !self.send_over_budget() {
                return;
            }
            notified.await;
        }
    }

    /// First inbound `getaddr` wins. Later ones are ignored.
    pub(crate) fn take_getaddr(&self) -> bool {
        !self.getaddr_answered.swap(true, Ordering::Relaxed)
    }

    pub(crate) fn attach_out(&self, tx: mpsc::UnboundedSender<PeerOut>) {
        *self.out_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    pub(crate) fn take_addr_relay(&self, want: usize, now_ms: u64) -> usize {
        let mut tokens = self.addr_tokens.lock().unwrap_or_else(|e| e.into_inner());
        let at = self.addr_token_ms.load(Ordering::Relaxed);
        let filled = crate::peer::addr_relay_tokens(*tokens, at, now_ms);
        self.addr_token_ms.store(now_ms.max(at), Ordering::Relaxed);
        let take = (filled.floor() as usize).min(want);
        *tokens = filled - take as f64;
        take
    }

    pub(crate) fn writer(&self) -> Option<mpsc::UnboundedSender<PeerOut>> {
        self.out_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn note_last_block(&self) {
        self.last_block.store(self.clock_now(), Ordering::Relaxed);
    }

    pub fn note_last_transaction(&self) {
        self.last_transaction
            .store(self.clock_now(), Ordering::Relaxed);
    }

    pub fn note_minfeefilter_sat_kvb(&self, sat_kvb: u64) {
        self.minfeefilter_sat_kvb.store(sat_kvb, Ordering::Relaxed);
    }

    pub fn note_block_inflight(&self, height: u32) {
        let mut g = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if !g.contains(&height) {
            g.push(height);
        }
    }

    pub fn clear_block_inflight(&self, height: u32) {
        self.inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|h| *h != height);
    }

    pub fn minfeefilter_sat_kvb(&self) -> u64 {
        self.minfeefilter_sat_kvb.load(Ordering::Relaxed)
    }

    pub fn clock_now(&self) -> u64 {
        self.owner
            .upgrade()
            .map(|h| h.now_secs())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            })
    }

    pub fn connected_at(&self) -> u64 {
        self.connected_at.load(Ordering::Relaxed)
    }

    pub fn peer_hub(&self) -> Option<Arc<PeerHub>> {
        self.owner.upgrade()
    }

    pub fn net_perm_flags(&self) -> crate::net_permissions::NetPermissionFlags {
        self.owner
            .upgrade()
            .map(|h| {
                h.net_perms
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .flags_for_net(self.net, self.inbound, self.addrbind)
            })
            .unwrap_or(crate::net_permissions::NetPermissionFlags::NONE)
    }

    pub fn has_net_perm(&self, flag: crate::net_permissions::NetPermissionFlags) -> bool {
        self.net_perm_flags().has(flag)
    }

    /// CIDR/bind table plus operator `--trusted`.
    pub fn session_noban(&self) -> bool {
        self.peer_hub().is_some_and(|h| h.is_noban())
            || self
                .net_perm_flags()
                .has(crate::net_permissions::NetPermissionFlags::NOBAN)
    }

    /// CIDR/bind table plus operator `--relay` / `--always-relay`.
    pub fn session_relay_perm(&self) -> bool {
        self.peer_hub().is_some_and(|h| h.is_relay_perm())
            || self
                .net_perm_flags()
                .has(crate::net_permissions::NetPermissionFlags::RELAY)
    }

    /// CIDR/bind table plus operator `--always-relay`.
    pub fn session_forcerelay(&self) -> bool {
        self.peer_hub().is_some_and(|h| h.is_forcerelay_perm())
            || self
                .net_perm_flags()
                .has(crate::net_permissions::NetPermissionFlags::FORCE_RELAY)
    }

    pub fn set_inv_gen_floor(&self, floor: u64) {
        self.inv_gen_floor.store(floor, Ordering::Relaxed);
    }

    pub fn inv_gen_floor(&self) -> u64 {
        self.inv_gen_floor.load(Ordering::Relaxed)
    }

    pub fn age_inv_seen(&self) -> (u64, u64) {
        (
            self.age_inv_seen_due.load(Ordering::Relaxed),
            self.age_inv_seen_gen.load(Ordering::Relaxed),
        )
    }

    pub fn note_age_inv_seen(&self, due: u64, gen: u64) {
        self.age_inv_seen_due.store(due, Ordering::Relaxed);
        self.age_inv_seen_gen.store(gen, Ordering::Relaxed);
    }

    /// Timeout first, then RPC-queued / interval probe.
    ///
    /// Never-sent peers keep `ping_start_secs == 0`, so any `now_secs` above
    /// 120 is interval-due (same comparison as a last ping at Unix epoch 0).
    pub fn take_ping_action(&self, now_secs: u64) -> Option<PingAction> {
        const PING_INTERVAL: u64 = 120;
        const TIMEOUT_INTERVAL: u64 = 20 * 60;
        let nonce = self.ping_nonce_sent.load(Ordering::Relaxed);
        let start = self.ping_start_secs.load(Ordering::Relaxed);
        // Core `RunInactivityChecks`: no ping timeout until `-peertimeout`
        // has passed since connect (both on the mockable clock).
        let inactivity_checks = self.peer_hub().is_none_or(|h| {
            now_secs
                > self
                    .connected_at_secs()
                    .saturating_add(h.peer_timeout_secs())
        });
        if inactivity_checks && nonce != 0 && now_secs > start.saturating_add(TIMEOUT_INTERVAL) {
            let elapsed = now_secs.saturating_sub(start) as f64;
            return Some(PingAction::Timeout {
                elapsed_secs: elapsed,
            });
        }
        let queued = self.ping_queued.load(Ordering::Relaxed);
        let interval_due = nonce == 0 && now_secs > start.saturating_add(PING_INTERVAL);
        if !queued && !interval_due {
            return None;
        }
        let mut n = rand_ping_nonce();
        while n == 0 {
            n = rand_ping_nonce();
        }
        self.ping_queued.store(false, Ordering::Relaxed);
        self.ping_start_secs.store(now_secs, Ordering::Relaxed);
        self.ping_nonce_sent.store(n, Ordering::Relaxed);
        Some(PingAction::Send { nonce: n })
    }

    /// Core pong handling (`p2p_ping.py` needles).
    pub fn on_pong(&self, payload: &[u8], now_secs: u64) -> Option<String> {
        let expected = self.ping_nonce_sent.load(Ordering::Relaxed);
        let (problem, received, finish) = if payload.len() < 8 {
            (Some("Short payload"), 0u64, true)
        } else {
            let received = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8]));
            if expected == 0 {
                (Some("Unsolicited pong without ping"), received, false)
            } else if received == expected {
                let start = self.ping_start_secs.load(Ordering::Relaxed);
                if now_secs >= start {
                    let rtt = (now_secs - start) as f64;
                    *self.pingtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(rtt);
                    let mut minp = self.minping.lock().unwrap_or_else(|e| e.into_inner());
                    *minp = Some(minp.map_or(rtt, |m| m.min(rtt)));
                }
                (None, received, true)
            } else if received == 0 {
                (Some("Nonce zero"), received, true)
            } else {
                (Some("Nonce mismatch"), received, false)
            }
        };
        if finish {
            self.ping_nonce_sent.store(0, Ordering::Relaxed);
        }
        problem.map(|p| {
            format!(
                "p2p: pong peer={}: {p}, {expected:x} expected, {received:x} received, {} bytes",
                self.id,
                payload.len()
            )
        })
    }

    pub(crate) fn ping_rpc_fields(&self, now_secs: u64) -> (Option<f64>, Option<f64>, Option<f64>) {
        let pingtime = *self.pingtime.lock().unwrap_or_else(|e| e.into_inner());
        let minping = *self.minping.lock().unwrap_or_else(|e| e.into_inner());
        let nonce = self.ping_nonce_sent.load(Ordering::Relaxed);
        let start = self.ping_start_secs.load(Ordering::Relaxed);
        let pingwait = if nonce != 0 && start != 0 {
            Some(now_secs.saturating_sub(start) as f64)
        } else {
            None
        };
        (pingtime, minping, pingwait)
    }

    /// We just accepted a new tip from this peer — consider them for HB.
    pub fn maybe_select_as_hb(&self) {
        if let Some(hub) = self.owner.upgrade() {
            hub.maybe_select_hb(self.id);
        }
    }

    fn snapshot(&self, now_secs: u64) -> PeerInfo {
        let (pingtime, minping, pingwait) = self.ping_rpc_fields(now_secs);
        let bytesrecv_per_msg = self.recv.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let bytessent_per_msg = self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (bytesrecv, bytessent) = if self.has_wire() {
            (self.raw_recv(), self.raw_sent())
        } else {
            (
                bytesrecv_per_msg.values().sum(),
                bytessent_per_msg.values().sum(),
            )
        };
        PeerInfo {
            id: self.id,
            addr: self.addr,
            net: self.net,
            addrbind: self.addrbind,
            subver: self.subver.clone(),
            inbound: self.inbound,
            services: self.services,
            startingheight: self.startingheight,
            bytesrecv_per_msg,
            bytessent_per_msg,
            conn_type: self.conn_type,
            relay: self.relay,
            bip152_hb_to: self.hb_to.load(Ordering::Relaxed),
            bip152_hb_from: self.hb_from.load(Ordering::Relaxed),
            pingtime,
            minping,
            pingwait,
            last_block: self.last_block.load(Ordering::Relaxed),
            last_transaction: self.last_transaction.load(Ordering::Relaxed),
            minfeefilter_sat_kvb: self.minfeefilter_sat_kvb.load(Ordering::Relaxed),
            last_inv_sequence: self.last_inv_sequence(),
            inv_to_send: self.inv_to_send(),
            bytesrecv,
            bytessent,
            inflight: self
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            permissions: self
                .owner
                .upgrade()
                .map(|h| h.permission_strings(self.addr, self.inbound, self.addrbind))
                .unwrap_or_default(),
            mapped_as: self.owner.upgrade().and_then(|h| {
                h.asmap().and_then(|m| {
                    let asn = m.mapped_as(self.addr.ip());
                    (asn != 0).then_some(asn)
                })
            }),
            handshake_complete: self.handshake_complete(),
            time_offset_secs: if self.handshake_complete() {
                self.version_timestamp
                    .saturating_sub(self.connected_at.load(Ordering::Relaxed) as i64)
            } else {
                0
            },
            best_known: self.best_known(),
        }
    }
}

/// Result of [`LivePeer::take_ping_action`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PingAction {
    Send { nonce: u64 },
    Timeout { elapsed_secs: f64 },
}

fn rand_ping_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static N: AtomicU64 = AtomicU64::new(1);
    let seq = N.fetch_add(1, Ordering::Relaxed);
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    tick.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_mul(0xBF58_476D_1CE4_E5B9))
        | 1
}

/// Count at least Core's 24-byte header; `pong` must be ≥29 for `connect_nodes`.
fn acct_bytes(cmd: &str, payload: u64) -> u64 {
    let n = payload.saturating_add(24);
    if cmd == "pong" {
        n.max(29)
    } else {
        n
    }
}

/// `(inbound, outbound)` among `peers`: `getnetworkinfo.connections_in` /
/// `connections_out` over a [`PeerHub::snapshot`].
pub fn connection_counts(peers: &[PeerInfo]) -> (u64, u64) {
    let inbound = peers.iter().filter(|p| p.inbound).count();
    (inbound as u64, (peers.len() - inbound) as u64)
}

/// `getnetworkinfo.timeoffset`: median VERSION offset of completed outbound peers.
/// Even counts use the upper middle. Inbound-only or empty is 0.
pub fn outbound_time_offset(peers: &[PeerInfo]) -> i64 {
    let mut offs: Vec<i64> = peers
        .iter()
        .filter(|p| !p.inbound && p.handshake_complete)
        .map(|p| p.time_offset_secs)
        .collect();
    if offs.is_empty() {
        return 0;
    }
    offs.sort_unstable();
    offs[offs.len() / 2]
}

/// RPC-facing snapshot.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: u64,
    pub addr: SocketAddr,
    pub net: crate::NetAddr,
    pub addrbind: SocketAddr,
    pub subver: String,
    pub inbound: bool,
    pub services: u64,
    pub startingheight: i32,
    pub bytesrecv_per_msg: HashMap<String, u64>,
    pub bytessent_per_msg: HashMap<String, u64>,
    pub conn_type: PeerConnType,
    pub relay: bool,
    pub bip152_hb_to: bool,
    pub bip152_hb_from: bool,
    pub pingtime: Option<f64>,
    pub minping: Option<f64>,
    pub pingwait: Option<f64>,
    /// Unix seconds of last block from this peer (`0` = never).
    pub last_block: u64,
    /// Unix seconds of last accepted tx from this peer (`0` = never).
    pub last_transaction: u64,
    /// Fee filter they sent us, sat/kvB (`0` = none).
    pub minfeefilter_sat_kvb: u64,
    /// `getpeerinfo.last_inv_sequence`.
    pub last_inv_sequence: u64,
    /// `getpeerinfo.inv_to_send` (queued tx INV count).
    pub inv_to_send: u32,
    /// Raw TCP bytes (`getpeerinfo.bytesrecv`), including BIP324 handshake.
    pub bytesrecv: u64,
    /// Raw TCP bytes (`getpeerinfo.bytessent`), including BIP324 handshake.
    pub bytessent: u64,
    /// RPC permission strings (`relay`, `noban`, …).
    pub permissions: Vec<String>,
    /// Block heights in flight from this peer (`getpeerinfo.inflight`).
    pub inflight: Vec<u32>,
    /// `getpeerinfo.mapped_as` when an asmap mapped this peer (omit/`None` otherwise).
    pub mapped_as: Option<u32>,
    /// VERSION+VERACK finished. Connecting rows stay false.
    pub handshake_complete: bool,
    /// VERSION clock minus connect time, seconds (`0` before handshake).
    pub time_offset_secs: i64,
    /// Best block this peer advertised (`None` until they send a header/block).
    pub best_known: Option<BlockHash>,
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Thread-safe session table + addnode remembered addrs.
pub struct PeerHub {
    next_id: AtomicU64,
    live: RwLock<HashMap<u64, Arc<LivePeer>>>,
    added: Mutex<HashSet<crate::NetAddr>>,
    /// Raw `addnode add` strings. Re-resolved on each redial so a Warnet name
    /// that is not in DNS yet is kept.
    manual_hosts: Mutex<HashSet<String>>,
    /// `--connect` hostnames that are not a [`crate::NetAddr`] (clearnet DNS).
    connect_hosts: Mutex<Vec<String>>,
    /// Network P2P port used when a remembered host omits `:port`. `0` = unset.
    connect_default_port: AtomicU16,
    dial_tx: Mutex<Option<mpsc::UnboundedSender<DialRequest>>>,
    /// Peers we asked to send us compact (BIP152 HB, max 3, prefer outbound).
    hb_selected: Mutex<Vec<u64>>,
    /// `setmocktime` seconds; `0` means wall clock.
    mock_now: AtomicU64,
    /// Count of sessions currently in headers-sync.
    headers_sync_peers: AtomicU64,
    /// Last inv hash that started headers sync with a not-yet-sync peer.
    last_inv_headers_sync: Mutex<Option<BlockHash>>,
    /// Trusted inbound — do not disconnect a stalling headers-sync peer.
    noban: AtomicBool,
    /// Accept txs even when the node is blocks-only.
    relay_perm: AtomicBool,
    /// No outbound `feefilter` (relay all).
    forcerelay_perm: AtomicBool,
    /// Parallel compact-fill slots per block: up to 2 inbound + 1 outbound.
    cmpct_fills: Mutex<HashMap<BlockHash, (u8, bool)>>,
    /// Version nonces of outbound sessions still in handshake (Core self-connect).
    pending_outbound_nonces: Mutex<HashSet<u64>>,
    /// Shared addrman for GetAddr responses (optional until node wires it).
    addrman: Mutex<Option<std::sync::Arc<Mutex<crate::seeds::AddrMan>>>>,
    /// Per-listen GetAddr cache: canonical bind + addrv2 → (cached_at, addrs).
    addr_response_cache: Mutex<HashMap<(SocketAddr, bool), (u64, Vec<(u32, crate::NetAddr)>)>>,
    /// VERSION/VERACK handshake timeout seconds. Default 60.
    peer_timeout_secs: AtomicU64,
    /// Addresses we advertise (`getnetworkinfo.localaddresses`).
    external_ips: Mutex<Vec<IpAddr>>,
    wallet_onions: Mutex<Vec<(String, u16)>>,
    p2p_onion: Mutex<Option<(String, u16)>>,
    p2p_i2p: Mutex<Option<crate::NetAddr>>,
    /// P2P listen port used with advertised external IPs.
    listen_port: AtomicU16,
    /// Core `-discover`. Off: never self-announce, even with `--external-ip`.
    discover: AtomicBool,
    /// Clearnet P2P bind (not onion-only loopback). Needed to gossip `--external-ip`.
    clearnet_listen: AtomicBool,
    cjdns_reachable: AtomicBool,
    /// Core `-i2psam`: I2P rows may enter addrman. Off, they are still relayed.
    i2p_reachable: AtomicBool,
    pruned: AtomicBool,
    asmap: Mutex<Option<Arc<crate::asmap::AsMap>>>,
    /// Tip-mode mempool for Core `EraseForPeer` on disconnect.
    mempool: Mutex<Option<Weak<crate::tx_relay::MempoolHub>>>,
    /// Core `-whitelist` / `-whitebind` grants (`getpeerinfo.permissions`).
    net_perms: Mutex<crate::net_permissions::NetPermTable>,
}

fn canonical_bind(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::from((v4, v6.port())))
            .unwrap_or(addr),
        v4 => v4,
    }
}

fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn addr_sample_seed(bind: SocketAddr, now: u64) -> u64 {
    let bind = canonical_bind(bind);
    let mut s = mix64(now);
    s ^= mix64(u64::from(bind.port()));
    match bind.ip() {
        IpAddr::V4(v) => {
            s ^= mix64(u32::from_be_bytes(v.octets()).into());
        }
        IpAddr::V6(v) => {
            let o = v.octets();
            let mut hi = [0u8; 8];
            let mut lo = [0u8; 8];
            hi.copy_from_slice(&o[..8]);
            lo.copy_from_slice(&o[8..]);
            s ^= mix64(u64::from_be_bytes(hi));
            s ^= mix64(u64::from_be_bytes(lo));
        }
    }
    s
}

fn ip_is_advertisable(ip: &IpAddr, cjdns_reachable: bool) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_unspecified() || v.is_loopback() || v.is_private()),
        IpAddr::V6(v) => {
            if v.is_unspecified() || v.is_loopback() {
                return false;
            }
            if crate::netaddr::is_cjdns_ip(*v) {
                return cjdns_reachable;
            }
            true
        }
    }
}

impl PeerHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(0),
            live: RwLock::new(HashMap::new()),
            added: Mutex::new(HashSet::new()),
            manual_hosts: Mutex::new(HashSet::new()),
            connect_hosts: Mutex::new(Vec::new()),
            connect_default_port: AtomicU16::new(0),
            dial_tx: Mutex::new(None),
            hb_selected: Mutex::new(Vec::new()),
            mock_now: AtomicU64::new(0),
            headers_sync_peers: AtomicU64::new(0),
            last_inv_headers_sync: Mutex::new(None),
            noban: AtomicBool::new(false),
            relay_perm: AtomicBool::new(false),
            forcerelay_perm: AtomicBool::new(false),
            cmpct_fills: Mutex::new(HashMap::new()),
            pending_outbound_nonces: Mutex::new(HashSet::new()),
            addrman: Mutex::new(None),
            addr_response_cache: Mutex::new(HashMap::new()),
            peer_timeout_secs: AtomicU64::new(60),
            external_ips: Mutex::new(Vec::new()),
            wallet_onions: Mutex::new(Vec::new()),
            p2p_onion: Mutex::new(None),
            p2p_i2p: Mutex::new(None),
            listen_port: AtomicU16::new(0),
            discover: AtomicBool::new(true),
            clearnet_listen: AtomicBool::new(true),
            cjdns_reachable: AtomicBool::new(false),
            i2p_reachable: AtomicBool::new(false),
            pruned: AtomicBool::new(false),
            asmap: Mutex::new(None),
            mempool: Mutex::new(None),
            net_perms: Mutex::new(crate::net_permissions::NetPermTable::default()),
        })
    }

    pub fn attach_mempool(&self, mp: &Arc<crate::tx_relay::MempoolHub>) {
        *self.mempool.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(mp));
    }

    pub fn set_net_perms(&self, t: crate::net_permissions::NetPermTable) {
        *self.net_perms.lock().unwrap_or_else(|e| e.into_inner()) = t;
    }

    pub fn permission_flags(
        &self,
        addr: SocketAddr,
        inbound: bool,
        bind: SocketAddr,
    ) -> crate::net_permissions::NetPermissionFlags {
        self.net_perms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flags_for(addr.ip(), inbound, bind)
    }

    pub fn permission_strings(
        &self,
        addr: SocketAddr,
        inbound: bool,
        bind: SocketAddr,
    ) -> Vec<String> {
        self.permission_flags(addr, inbound, bind)
            .to_strings()
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    pub fn set_asmap(&self, m: Option<Arc<crate::asmap::AsMap>>) {
        *self.asmap.lock().unwrap_or_else(|e| e.into_inner()) = m;
    }

    pub fn asmap(&self) -> Option<Arc<crate::asmap::AsMap>> {
        self.asmap.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_peer_timeout_secs(&self, secs: u64) {
        self.peer_timeout_secs.store(secs.max(1), Ordering::Relaxed);
    }

    pub fn set_external_ips(&self, ips: Vec<IpAddr>) {
        *self.external_ips.lock().unwrap_or_else(|e| e.into_inner()) = ips;
    }

    pub fn set_wallet_onion(&self, host: String, port: u16) {
        self.wallet_onions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((host, port));
    }

    pub fn set_p2p_onion(&self, host: String, port: u16) {
        *self.p2p_onion.lock().unwrap_or_else(|e| e.into_inner()) = Some((host, port));
    }

    pub fn p2p_onion(&self) -> Option<crate::NetAddr> {
        let (host, port) = self
            .p2p_onion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        format!("{host}:{port}").parse().ok()
    }

    pub fn set_p2p_i2p(&self, addr: crate::NetAddr) {
        if matches!(addr, crate::NetAddr::I2p { .. }) {
            *self.p2p_i2p.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
        }
    }

    pub fn p2p_i2p(&self) -> Option<crate::NetAddr> {
        *self.p2p_i2p.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_clearnet_listen(&self, on: bool) {
        self.clearnet_listen.store(on, Ordering::Relaxed);
    }

    pub fn set_cjdns_reachable(&self, on: bool) {
        self.cjdns_reachable.store(on, Ordering::Relaxed);
    }

    /// Core sets `NET_I2P` reachable only when `-i2psam` is configured.
    pub fn set_i2p_reachable(&self, on: bool) {
        self.i2p_reachable.store(on, Ordering::Relaxed);
    }

    pub fn set_pruned(&self, on: bool) {
        self.pruned.store(on, Ordering::Relaxed);
    }

    pub fn is_pruned(&self) -> bool {
        self.pruned.load(Ordering::Relaxed)
    }

    pub fn set_listen_port(&self, port: u16) {
        self.listen_port.store(port, Ordering::Relaxed);
    }

    pub fn set_discover(&self, on: bool) {
        self.discover.store(on, Ordering::Relaxed);
    }

    /// `getnetworkinfo.localaddresses` rows for operator-advertised IPs.
    pub fn rpc_local_addresses(&self) -> Vec<(String, u16, i32)> {
        const LOCAL_MANUAL: i32 = 4;
        let mut rows: Vec<(String, u16, i32)> = self
            .wallet_onions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .map(|(address, port)| (address, port, LOCAL_MANUAL))
            .collect();
        if let Some((host, port)) = self
            .p2p_onion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            rows.push((host, port, LOCAL_MANUAL));
        }
        if let Some(addr) = self.p2p_i2p() {
            rows.push((addr.host_str(), addr.port(), LOCAL_MANUAL));
        }
        if !self.discover.load(Ordering::Relaxed) {
            return rows;
        }
        let port = self.listen_port.load(Ordering::Relaxed);
        if port == 0 {
            return rows;
        }
        let ips = self
            .external_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        rows.extend(
            ips.into_iter()
                .map(|ip| (ip.to_string(), port, LOCAL_MANUAL)),
        );
        rows
    }

    pub fn advertise_local_socket(&self) -> Option<SocketAddr> {
        if !self.discover.load(Ordering::Relaxed) {
            return None;
        }
        if !self.clearnet_listen.load(Ordering::Relaxed) {
            return None;
        }
        let port = self.listen_port.load(Ordering::Relaxed);
        if port == 0 {
            return None;
        }
        let g = self.external_ips.lock().unwrap_or_else(|e| e.into_inner());
        let cjdns = self.cjdns_reachable.load(Ordering::Relaxed);
        let ip = g.iter().copied().find(|ip| ip_is_advertisable(ip, cjdns))?;
        Some(SocketAddr::new(ip, port))
    }

    pub fn peer_timeout_secs(&self) -> u64 {
        self.peer_timeout_secs.load(Ordering::Relaxed).max(1)
    }

    /// Attach the process addrman so inbound GetAddr can sample peers.
    pub fn set_addrman(&self, am: std::sync::Arc<Mutex<crate::seeds::AddrMan>>) {
        *self.addrman.lock().unwrap_or_else(|e| e.into_inner()) = Some(am);
    }

    /// Learn IPv4/IPv6/Tor v3/I2P rows from BIP155 `addrv2`.
    pub fn learn_addrv2(&self, list: &[bitcoin::p2p::address::AddrV2Message]) {
        let g = self.addrman.lock().unwrap_or_else(|e| e.into_inner());
        let Some(am) = g.as_ref() else {
            return;
        };
        let i2p_ok = self.i2p_reachable.load(Ordering::Relaxed);
        let mut book = am.lock().unwrap_or_else(|e| e.into_inner());
        for a in list {
            // No `-i2psam`: relay the addrv2 row, do not store it. Core
            // `p2p_addrv2_relay` expects `getnodeaddresses network=i2p` empty.
            if matches!(a.addr, bitcoin::p2p::address::AddrV2::I2p(_)) && !i2p_ok {
                continue;
            }
            if let Some(addr) = crate::NetAddr::from_addrv2(a) {
                book.add_learned_addr(addr, crate::seeds::MAX_ADDR_MAN);
            }
        }
    }

    /// Core GetAddr reply: per-listen cache (24h) of
    /// [`crate::peer::MAX_ADDR_TO_SEND`] / [`crate::peer::MAX_PCT_ADDR_TO_SEND`]
    /// of addrman. `v2` includes onion / i2p / CJDNS; v1 ADDR is clearnet `Ip`.
    pub(crate) fn addr_response_net(
        &self,
        bind: SocketAddr,
        v2: bool,
    ) -> Vec<(u32, crate::NetAddr)> {
        const CACHE_SECS: u64 = 24 * 60 * 60;
        let key = (canonical_bind(bind), v2);
        let now = self.now_secs();
        let mut cache = self
            .addr_response_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((cached_at, addrs)) = cache.get(&key) {
            if now.saturating_sub(*cached_at) < CACHE_SECS {
                return addrs.clone();
            }
        }
        let am = {
            let g = self.addrman.lock().unwrap_or_else(|e| e.into_inner());
            g.clone()
        };
        let Some(am) = am else {
            return Vec::new();
        };
        let entries = {
            let g = am.lock().unwrap_or_else(|e| e.into_inner());
            g.entries()
        };
        let addrs: Vec<crate::NetAddr> = entries
            .iter()
            .map(|e| e.addr)
            .filter(|a| v2 || matches!(a, crate::NetAddr::Ip(_)))
            .collect();
        let n = addrs.len();
        let pct_cap = (n * crate::peer::MAX_PCT_ADDR_TO_SEND / 100).max(1);
        let cap = crate::peer::MAX_ADDR_TO_SEND.min(pct_cap).min(n);
        if cap == 0 {
            return Vec::new();
        }
        let mut idxs: Vec<usize> = (0..n).collect();
        let mut state = addr_sample_seed(key.0, now);
        for i in (1..idxs.len()).rev() {
            state = mix64(state);
            let j = (state as usize) % (i + 1);
            idxs.swap(i, j);
        }
        let mut out = Vec::with_capacity(cap);
        for &i in idxs.iter().take(cap) {
            out.push((now as u32, addrs[i]));
        }
        cache.insert(key, (now, out.clone()));
        out
    }

    /// v1 ADDR view of [`Self::addr_response_net`] (clearnet `Ip` only).
    pub fn addr_response_for_bind(
        &self,
        bind: SocketAddr,
    ) -> Vec<(u32, bitcoin::p2p::address::Address)> {
        let services = crate::peer::local_service_flags();
        self.addr_response_net(bind, false)
            .into_iter()
            .filter_map(|(t, a)| match a {
                crate::NetAddr::Ip(s) => {
                    Some((t, bitcoin::p2p::address::Address::new(&s, services)))
                }
                crate::NetAddr::Onion { .. }
                | crate::NetAddr::I2p { .. }
                | crate::NetAddr::Cjdns { .. } => None,
            })
            .collect()
    }

    /// Core: register local version nonce while an outbound handshake is open.
    pub fn note_outbound_nonce(&self, nonce: u64) {
        self.pending_outbound_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce);
    }

    pub fn clear_outbound_nonce(&self, nonce: u64) {
        self.pending_outbound_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&nonce);
    }

    /// `false` means this inbound nonce matches an outbound handshake (self-connect).
    pub fn check_incoming_nonce(&self, nonce: u64) -> bool {
        !self
            .pending_outbound_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&nonce)
    }

    /// BIP152: at most two inbound `getblocktxn` plus one outbound for a hash.
    /// Same-peer retry while that hash is already pending does not take a slot.
    pub fn try_cmpct_fill_slot(&self, hash: BlockHash, inbound: bool) -> bool {
        let mut g = self.cmpct_fills.lock().unwrap_or_else(|e| e.into_inner());
        let (n_in, has_out) = g.entry(hash).or_insert((0, false));
        if inbound {
            if *n_in >= 2 {
                return false;
            }
            *n_in = n_in.saturating_add(1);
            true
        } else if *has_out {
            false
        } else {
            *has_out = true;
            true
        }
    }

    pub fn clear_cmpct_fill(&self, hash: BlockHash) {
        self.cmpct_fills
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&hash);
    }

    pub fn release_cmpct_fill(&self, hash: BlockHash, inbound: bool) {
        let mut g = self.cmpct_fills.lock().unwrap_or_else(|e| e.into_inner());
        let Some((n_in, has_out)) = g.get_mut(&hash) else {
            return;
        };
        if inbound {
            *n_in = n_in.saturating_sub(1);
        } else {
            *has_out = false;
        }
        if *n_in == 0 && !*has_out {
            g.remove(&hash);
        }
    }

    pub fn set_noban(&self, v: bool) {
        self.noban.store(v, Ordering::Relaxed);
    }

    /// Bypass low-work header anti-DoS.
    pub fn is_noban(&self) -> bool {
        self.noban.load(Ordering::Relaxed)
    }

    pub fn set_relay_perm(&self, v: bool) {
        self.relay_perm.store(v, Ordering::Relaxed);
    }

    /// P2P txs allowed while the node is blocks-only.
    pub fn is_relay_perm(&self) -> bool {
        self.relay_perm.load(Ordering::Relaxed)
    }

    pub fn set_forcerelay_perm(&self, v: bool) {
        self.forcerelay_perm.store(v, Ordering::Relaxed);
    }

    /// Operator `--always-relay`: skip `feefilter` and force-rebroadcast.
    pub fn is_forcerelay_perm(&self) -> bool {
        self.forcerelay_perm.load(Ordering::Relaxed)
    }

    fn is_preferred_download(p: &LivePeer) -> bool {
        matches!(
            p.conn_type,
            PeerConnType::OutboundFullRelay | PeerConnType::BlockRelay
        )
    }

    /// Core: only one initial headers-sync peer unless the tip is within 24h.
    pub fn try_start_headers_sync(&self, peer: &LivePeer, now: u64, best_header_time: u64) -> bool {
        if peer.sync_started.load(Ordering::Relaxed) {
            return false;
        }
        if !peer.can_serve_blocks() {
            return false;
        }
        let caught_up = now.saturating_sub(best_header_time) < 24 * 3600;
        if !caught_up {
            // Two sessions can observe 0 after a noban timeout; only one
            // extra getheaders (`p2p_initial_headers_sync` count==1).
            if self
                .headers_sync_peers
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
        } else {
            self.headers_sync_peers.fetch_add(1, Ordering::Relaxed);
        }
        peer.sync_started.store(true, Ordering::Relaxed);
        let timeout = crate::chain::headers_download_timeout_secs(now, best_header_time);
        peer.headers_sync_timeout.store(timeout, Ordering::Relaxed);
        true
    }

    /// Core inv-triggered extra headers-sync peer (at most one new peer per block).
    pub fn should_getheaders_for_inv(&self, peer: &LivePeer, hash: BlockHash) -> bool {
        if peer.sync_started.load(Ordering::Relaxed) {
            return true;
        }
        if peer.inv_asked_headers.load(Ordering::Relaxed) {
            return false;
        }
        let mut last = self
            .last_inv_headers_sync
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *last == Some(hash) {
            return false;
        }
        *last = Some(hash);
        peer.inv_asked_headers.store(true, Ordering::Relaxed);
        true
    }

    fn end_headers_sync(&self, peer: &LivePeer) {
        if peer.sync_started.swap(false, Ordering::Relaxed) {
            self.headers_sync_peers.fetch_sub(1, Ordering::Relaxed);
            peer.headers_sync_timeout.store(0, Ordering::Relaxed);
        }
    }

    fn check_headers_sync_timeouts(&self, now: u64) {
        let n = self.headers_sync_peers.load(Ordering::Relaxed);
        if n != 1 {
            return;
        }
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let n_preferred = g
            .values()
            .filter(|p| Self::is_preferred_download(p))
            .count();
        for p in g.values() {
            if !p.sync_started.load(Ordering::Relaxed) {
                continue;
            }
            let deadline = p.headers_sync_timeout.load(Ordering::Relaxed);
            if deadline == 0 || now <= deadline {
                continue;
            }
            let stalling_pref = Self::is_preferred_download(p);
            if n_preferred.saturating_sub(stalling_pref as usize) < 1 {
                continue;
            }
            if p.session_noban() {
                rbitcoin_log::info!("{}", crate::chain::headers_timeout_noban_log(p.id));
                p.sync_started.store(false, Ordering::Relaxed);
                p.headers_sync_timeout.store(0, Ordering::Relaxed);
                let _ = p.take_awaiting_headers();
                self.headers_sync_peers.fetch_sub(1, Ordering::Relaxed);
            } else {
                rbitcoin_log::info!("{}", crate::chain::headers_timeout_disconnect_log(p.id));
                p.request_disconnect();
            }
        }
    }

    pub fn now_secs(&self) -> u64 {
        let mock = self.mock_now.load(Ordering::Acquire);
        if mock != 0 {
            return mock;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Ask every live session to flush due tx INVs (`p2p_blocksonly` RPC relay).
    pub fn request_all_tx_inv(&self) {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        for p in g.values() {
            p.request_tx_inv();
        }
    }

    pub fn set_mock_now(&self, ts: u64) {
        self.mock_now.store(ts, Ordering::Release);
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        for p in g.values() {
            p.request_tx_inv();
            p.queue_self_announce_if_due();
        }
        drop(g);
        self.on_session_heartbeat();
    }

    /// Session 50ms heartbeat: replace a stalling initial-headers-sync peer.
    pub(crate) fn on_session_heartbeat(&self) {
        let now = self.now_secs();
        self.check_headers_sync_timeouts(now);
        self.check_handshake_timeouts(now);
    }

    pub(crate) fn handshake_timed_out(&self, peer: &LivePeer, now: u64) -> bool {
        if peer.handshake_complete() {
            return false;
        }
        now.saturating_sub(peer.connected_at_secs()) >= self.peer_timeout_secs()
    }

    pub(crate) fn check_handshake_timeouts(&self, now: u64) {
        let mut timed_out: Vec<Arc<LivePeer>> = self
            .live_peers()
            .into_iter()
            .filter(|p| self.handshake_timed_out(p, now))
            .collect();
        timed_out.sort_unstable_by_key(|p| p.id);
        for p in &timed_out {
            let line = if p.v2_transport_ready() {
                crate::peer::version_handshake_timeout_log(p.id)
            } else {
                crate::v2::v2_handshake_timeout_log(p.id)
            };
            rbitcoin_log::debug!("{}", line);
        }
        for p in timed_out {
            let _ = self.disconnect_id(p.id);
        }
    }

    pub fn queue_pings(&self) {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        for p in g.values() {
            p.queue_ping();
        }
    }

    pub fn set_dialer(&self, tx: mpsc::UnboundedSender<DialRequest>) {
        *self.dial_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    /// Placeholder row after TCP connect, before VERSION.
    pub fn register_connecting(
        self: &Arc<Self>,
        addr: SocketAddr,
        addrbind: SocketAddr,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        self.register_connecting_net(
            addr,
            crate::NetAddr::from_socket(addr),
            addrbind,
            inbound,
            conn_type,
        )
    }

    pub fn register_connecting_net(
        self: &Arc<Self>,
        addr: SocketAddr,
        net: crate::NetAddr,
        addrbind: SocketAddr,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        use bitcoin::p2p::address::Address;
        use bitcoin::p2p::ServiceFlags;
        let ver = VersionMessage {
            version: bitcoin::p2p::PROTOCOL_VERSION,
            services: ServiceFlags::NONE,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addrbind, ServiceFlags::NONE),
            nonce: 0,
            user_agent: String::new(),
            start_height: -1,
            relay: false,
        };
        let endpoint = PeerEndpoint {
            addr,
            net,
            addrbind,
        };
        self.register_with_id_net(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            endpoint,
            &ver,
            inbound,
            conn_type,
        )
    }

    pub fn register(
        self: &Arc<Self>,
        addr: SocketAddr,
        addrbind: SocketAddr,
        ver: &VersionMessage,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        self.register_net(
            addr,
            crate::NetAddr::from_socket(addr),
            addrbind,
            ver,
            inbound,
            conn_type,
        )
    }

    pub fn register_net(
        self: &Arc<Self>,
        addr: SocketAddr,
        net: crate::NetAddr,
        addrbind: SocketAddr,
        ver: &VersionMessage,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let p = self.register_with_id_net(
            id,
            PeerEndpoint {
                addr,
                net,
                addrbind,
            },
            ver,
            inbound,
            conn_type,
        );
        p.mark_handshake_complete();
        p.note_recv("version", 100);
        p.note_recv("verack", 0);
        p
    }

    pub fn register_with_id(
        self: &Arc<Self>,
        id: u64,
        addr: SocketAddr,
        addrbind: SocketAddr,
        ver: &VersionMessage,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        self.register_with_id_net(
            id,
            PeerEndpoint {
                addr,
                net: crate::NetAddr::from_socket(addr),
                addrbind,
            },
            ver,
            inbound,
            conn_type,
        )
    }

    pub fn register_with_id_net(
        self: &Arc<Self>,
        id: u64,
        endpoint: PeerEndpoint,
        ver: &VersionMessage,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        let _ = self
            .next_id
            .fetch_max(id.saturating_add(1), Ordering::Relaxed);
        let services = service_flags_u64(ver.services);
        let connected_at = self.now_secs();
        let peer = Arc::new(LivePeer {
            id,
            addr: endpoint.addr,
            net: endpoint.net,
            addrbind: endpoint.addrbind,
            subver: ver.user_agent.clone(),
            inbound,
            services,
            startingheight: ver.start_height,
            conn_type,
            relay: ver.relay,
            stop: AtomicBool::new(false),
            serve_inflight: AtomicUsize::new(0),
            send_queued: AtomicUsize::new(0),
            send_resume: tokio::sync::Notify::new(),
            getaddr_answered: AtomicBool::new(false),
            hb_to: AtomicBool::new(false),
            hb_from: AtomicBool::new(false),
            pending_sendcmpct: std::sync::atomic::AtomicU8::new(0),
            best_header_sent: Mutex::new(None),
            best_known: Mutex::new(None),
            recently_from: Mutex::new(HashSet::new()),
            inv_asked_headers: AtomicBool::new(false),
            sync_started: AtomicBool::new(false),
            headers_sync_timeout: AtomicU64::new(0),
            awaiting_headers: AtomicBool::new(false),
            announced_wtx: Mutex::new(CappedSet::new()),
            taken_cmpct: Mutex::new(Vec::new()),
            last_inv_sequence: AtomicU64::new(1),
            inv_to_send: AtomicU32::new(0),
            last_tx_inv_now: AtomicU64::new(0),
            tx_inv_requested: AtomicBool::new(false),
            ping_nonce_sent: AtomicU64::new(0),
            ping_start_secs: AtomicU64::new(0),
            ping_queued: AtomicBool::new(false),
            pingtime: Mutex::new(None),
            minping: Mutex::new(None),
            owner: Arc::downgrade(self),
            recv: Mutex::new(HashMap::new()),
            sent: Mutex::new(HashMap::new()),
            last_block: AtomicU64::new(0),
            last_transaction: AtomicU64::new(0),
            minfeefilter_sat_kvb: AtomicU64::new(0),
            wire_recv: Mutex::new(None),
            wire_sent: Mutex::new(None),
            failed_cmpct: Mutex::new(HashSet::new()),
            inflight: Mutex::new(Vec::new()),
            out_tx: Mutex::new(None),
            addr_tokens: Mutex::new(crate::peer::ADDR_RELAY_BURST),
            addr_token_ms: AtomicU64::new(0),
            connected_at: AtomicU64::new(connected_at),
            inv_gen_floor: AtomicU64::new(0),
            age_inv_seen_due: AtomicU64::new(0),
            age_inv_seen_gen: AtomicU64::new(0),
            writer_abort: Mutex::new(None),
            session_abort: Mutex::new(None),
            tcp_shutdown: Mutex::new(None),
            handshake_complete: AtomicBool::new(false),
            v2_transport_ready: AtomicBool::new(false),
            wants_addrv2: AtomicBool::new(false),
            wtxid_relay: AtomicBool::new(false),
            next_local_addr_send: AtomicU64::new(0),
            version_timestamp: ver.timestamp,
        });
        self.live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&peer));
        rbitcoin_log::debug!("p2p: Added connection peer={id}");
        peer
    }

    pub fn unregister(&self, id: u64) {
        if let Some(mp) = self
            .mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
        {
            mp.erase_orphans_for_peer(id);
        }
        let removed = self
            .live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        if let Some(p) = removed {
            p.release_all_cmpct();
            self.end_headers_sync(&p);
        }
        self.hb_selected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|x| *x != id);
    }

    pub fn live_peers(&self) -> Vec<Arc<LivePeer>> {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        g.values().cloned().collect()
    }

    /// Re-advertise BIP133 feefilter after IBD/minrelay change (skip block-relay / forcerelay).
    pub fn queue_feefilter_all(&self, sat_kvb: i64) {
        for s in self.live_peers() {
            if s.conn_type == PeerConnType::BlockRelay || s.session_forcerelay() {
                continue;
            }
            if let Some(tx) = s.writer() {
                let _ = tx.send(PeerOut::Msg(NetworkMessage::FeeFilter(sat_kvb)));
            }
        }
    }

    pub fn snapshot(&self) -> Vec<PeerInfo> {
        let now = self.now_secs();
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = g
            .values()
            .filter(|p| {
                if p.stop.load(Ordering::SeqCst) {
                    return false;
                }
                // Connecting rows stay visible during BIP324 (EARLY_KEY_RESPONSE
                // may FIN the clone while the row is still the getpeerinfo target).
                // Completed sessions hide on TCP FIN (`mempool_reorg` disconnect_nodes).
                !p.handshake_complete() || !p.tcp_fin()
            })
            .map(|p| p.snapshot(now))
            .collect();
        v.sort_by_key(|p| p.id);
        v
    }

    /// Sum of per-peer byte counters (`getnettotals`).
    /// Prefers raw TCP (partial frames) when attached.
    pub fn byte_totals(&self) -> (u64, u64) {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let mut recv = 0u64;
        let mut sent = 0u64;
        for p in g.values() {
            let raw_r = p.raw_recv();
            let raw_s = p.raw_sent();
            if p.has_wire() {
                recv = recv.saturating_add(raw_r);
                sent = sent.saturating_add(raw_s);
            } else {
                let now = self.now_secs();
                let snap = p.snapshot(now);
                recv = recv.saturating_add(snap.bytesrecv_per_msg.values().sum());
                sent = sent.saturating_add(snap.bytessent_per_msg.values().sum());
            }
        }
        (recv, sent)
    }

    pub fn get(&self, id: u64) -> Option<Arc<LivePeer>> {
        self.live
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
    }

    pub fn addnode(&self, addr: SocketAddr, cmd: &str) -> Result<(), String> {
        self.addnode_net(crate::NetAddr::Ip(addr), cmd)
    }

    fn dial_manual_net(&self, addr: &crate::NetAddr) -> Result<(), String> {
        match addr.socket_addr() {
            Some(ip) => self.dial(ip, PeerConnType::Manual),
            None => self.dial_domain(addr.host_str(), addr.port(), PeerConnType::Manual),
        }
    }

    pub fn addnode_net(&self, addr: crate::NetAddr, cmd: &str) -> Result<(), String> {
        match cmd {
            "onetry" => self.dial_manual_net(&addr),
            "add" => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(addr);
                let _ = self.dial_manual_net(&addr);
                Ok(())
            }
            "remove" => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&addr);
                self.disconnect_net(addr);
                Ok(())
            }
            other => Err(format!("unknown addnode command {other}")),
        }
    }

    /// `addnode` with the operator string. IP, onion, I2P, and CJDNS parse as
    /// [`crate::NetAddr`]. Anything else is clearnet DNS, resolved at dial.
    /// `add` keeps the string when DNS fails so a later redial can succeed.
    /// `onetry` fails if the name does not resolve now.
    pub fn addnode_host(&self, node: &str, cmd: &str, default_port: u16) -> Result<(), String> {
        self.note_default_port(default_port);
        match cmd {
            "onetry" => self.dial_resolved(node, PeerConnType::Manual),
            "add" => {
                self.manual_hosts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(node.to_string());
                let _ = self.dial_resolved(node, PeerConnType::Manual);
                Ok(())
            }
            "remove" => {
                self.manual_hosts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(node);
                if let Ok(target) = self.host_dial_target(node) {
                    self.disconnect_target(&target);
                }
                Ok(())
            }
            other => Err(format!("unknown addnode command {other}")),
        }
    }

    pub fn set_connect_hosts(&self, hosts: Vec<String>, default_port: u16) {
        self.note_default_port(default_port);
        *self.connect_hosts.lock().unwrap_or_else(|e| e.into_inner()) = hosts;
    }

    fn note_default_port(&self, default_port: u16) {
        if default_port != 0 && self.connect_default_port.load(Ordering::Relaxed) == 0 {
            self.connect_default_port
                .store(default_port, Ordering::Relaxed);
        }
    }

    fn default_port_opt(&self) -> Option<u16> {
        let port = self.connect_default_port.load(Ordering::Relaxed);
        (port != 0).then_some(port)
    }

    fn host_dial_target(&self, node: &str) -> Result<DialTarget, String> {
        let with_port = ensure_host_port(node, self.default_port_opt())?;
        if let Ok(net) = parse_peer_net(&with_port) {
            return Ok(DialTarget::from_net(net));
        }
        let addr =
            parse_peer_addr_with_port(node, self.default_port_opt()).map_err(|e| e.to_string())?;
        Ok(DialTarget::Socket(addr))
    }

    fn dial_resolved(&self, node: &str, typ: PeerConnType) -> Result<(), String> {
        let target = self.host_dial_target(node)?;
        match &target {
            DialTarget::Socket(addr) => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(crate::NetAddr::from_socket(*addr));
            }
            DialTarget::Domain { .. } => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(target.net_addr());
            }
        }
        self.dial_target(target, typ)
    }

    fn dial_target(&self, target: DialTarget, typ: PeerConnType) -> Result<(), String> {
        match target {
            DialTarget::Socket(addr) => self.dial(addr, typ),
            DialTarget::Domain { host, port } => self.dial_domain(host, port, typ),
        }
    }

    fn disconnect_target(&self, target: &DialTarget) -> bool {
        match target {
            DialTarget::Socket(addr) => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&crate::NetAddr::from_socket(*addr));
                self.disconnect_addr(*addr)
            }
            DialTarget::Domain { .. } => {
                let net = target.net_addr();
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&net);
                self.disconnect_net(net)
            }
        }
    }

    fn is_target_live(&self, target: &DialTarget) -> bool {
        let peers = self.snapshot();
        match target {
            DialTarget::Socket(addr) => peers.iter().any(|p| p.addr == *addr),
            DialTarget::Domain { host, port } => peers
                .iter()
                .any(|p| p.net.host_str() == *host && p.net.port() == *port),
        }
    }

    fn remembered_redials(&self) -> Vec<(String, PeerConnType)> {
        let mut out = Vec::new();
        for host in self
            .manual_hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push((host.clone(), PeerConnType::Manual));
        }
        for host in self
            .connect_hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            out.push((host.clone(), PeerConnType::OutboundFullRelay));
        }
        out
    }

    /// One dial per resolved endpoint in this pass. `addnode add` and
    /// `--connect` of the same host share that dial (Manual wins). A later
    /// pass dials again when the session is still not live. DNS lookup is
    /// synchronous; callers on a Tokio worker use
    /// [`Self::redial_remembered_off_runtime`].
    pub fn redial_remembered_with(&self, resolve: impl Fn(&str) -> Result<DialTarget, String>) {
        let mut seen = HashSet::<String>::new();
        for (host, typ) in self.remembered_redials() {
            let Ok(target) = resolve(&host) else {
                continue;
            };
            if !seen.insert(target.to_string()) {
                continue;
            }
            if self.is_target_live(&target) {
                continue;
            }
            let _ = self.dial_target(target, typ);
        }
    }

    pub fn redial_remembered(&self) {
        self.redial_remembered_with(|node| self.host_dial_target(node));
    }

    /// `ToSocketAddrs` on the blocking pool so a slow resolver cannot stall
    /// the Tokio worker that owns the retry interval.
    pub async fn redial_remembered_off_runtime(self: &Arc<Self>) {
        let peers = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || peers.redial_remembered()).await;
    }

    /// Select `id` as a BIP152 high-bandwidth peer (we send them sendcmpct(1)).
    /// Evicts the oldest inbound if we already have 3; never evict the last outbound
    /// when adding an inbound.
    pub fn maybe_select_hb(&self, id: u64) {
        let Some(peer) = self.get(id) else {
            return;
        };
        let inbound = peer.inbound;
        let mut sel = self.hb_selected.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = sel.iter().position(|x| *x == id) {
            sel.remove(pos);
            sel.push(id);
            return;
        }
        if sel.len() >= 3 {
            let evict_at = if inbound {
                // Prefer evicting an inbound; keep a lone outbound.
                let outbounds: Vec<usize> = sel
                    .iter()
                    .enumerate()
                    .filter(|(_, pid)| self.get(**pid).is_some_and(|p| !p.inbound))
                    .map(|(i, _)| i)
                    .collect();
                if outbounds.len() == 1 && outbounds[0] == 0 {
                    1
                } else {
                    0
                }
            } else {
                0
            };
            if evict_at < sel.len() {
                let evicted = sel.remove(evict_at);
                if let Some(p) = self.get(evicted) {
                    p.set_hb_to(false);
                    if let Some(out) = p.writer() {
                        let _ = out.send(PeerOut::Msg(NetworkMessage::SendCmpct(
                            bitcoin::p2p::message_compact_blocks::SendCmpct {
                                send_compact: false,
                                version: 2,
                            },
                        )));
                        p.pending_sendcmpct.store(0, Ordering::Relaxed);
                    } else {
                        p.pending_sendcmpct
                            .store(PendingSendCmpct::Lb as u8, Ordering::Relaxed);
                    }
                }
            }
        }
        sel.push(id);
        peer.set_hb_to(true);
        if let Some(out) = peer.writer() {
            let _ = out.send(PeerOut::Msg(NetworkMessage::SendCmpct(
                bitcoin::p2p::message_compact_blocks::SendCmpct {
                    send_compact: true,
                    version: 2,
                },
            )));
            peer.pending_sendcmpct.store(0, Ordering::Relaxed);
        } else {
            peer.pending_sendcmpct
                .store(PendingSendCmpct::Hb as u8, Ordering::Relaxed);
        }
    }

    pub fn addconnection(&self, addr: SocketAddr, typ: PeerConnType) -> Result<(), String> {
        if matches!(typ, PeerConnType::Inbound) {
            return Err("addconnection cannot create inbound".into());
        }
        self.dial(addr, typ)
    }

    pub fn dial_net(&self, addr: crate::NetAddr, typ: PeerConnType) -> Result<(), String> {
        let g = self.dial_tx.lock().unwrap_or_else(|e| e.into_inner());
        let tx = g.as_ref().ok_or("no dialer attached")?;
        tx.send(DialRequest {
            target: DialTarget::from_net(addr),
            typ,
        })
        .map_err(|_| "dialer closed".to_string())
    }

    /// Outbound full-relay sessions eligible for stale-tip slot rotation.
    /// Empty when this hub is `noban` (functional keep-alive).
    pub fn outbound_full_relay_ids(&self) -> Vec<u64> {
        self.outbound_full_relay_rows()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    pub fn outbound_full_relay_addrs(&self) -> Vec<SocketAddr> {
        self.outbound_full_relay_rows()
            .into_iter()
            .map(|(_, a)| a)
            .collect()
    }

    fn outbound_full_relay_rows(&self) -> Vec<(u64, SocketAddr)> {
        if self.is_noban() {
            return Vec::new();
        }
        let mut rows: Vec<(u64, SocketAddr)> = self
            .live_peers()
            .into_iter()
            .filter(|p| p.conn_type == PeerConnType::OutboundFullRelay && !p.inbound)
            .map(|p| (p.id, p.addr))
            .collect();
        rows.sort_unstable_by_key(|(id, _)| *id);
        rows
    }

    /// Live outbound full-relay addrs (not `noban`-gated) for diversity occupied.
    pub fn live_outbound_full_relay_addrs(&self) -> Vec<SocketAddr> {
        self.live_outbound_full_relay_nets()
            .into_iter()
            .filter_map(crate::NetAddr::socket_addr)
            .collect()
    }

    /// Overlay identity of live outbound full-relay peers (exclude for redial).
    pub fn live_outbound_full_relay_nets(&self) -> Vec<crate::NetAddr> {
        let mut rows: Vec<(u64, crate::NetAddr)> = self
            .live_peers()
            .into_iter()
            .filter(|p| p.conn_type == PeerConnType::OutboundFullRelay && !p.inbound)
            .map(|p| (p.id, p.net))
            .collect();
        rows.sort_unstable_by_key(|(id, _)| *id);
        rows.into_iter().map(|(_, a)| a).collect()
    }

    pub fn disconnect_id(&self, id: u64) -> bool {
        let Some(p) = self.get(id) else {
            return false;
        };
        p.request_disconnect();
        // Hard-close TCP first so the far side's read sees EOF inside the
        // Core `disconnect_nodes` 5s wait (`mempool_reorg`).
        if let Some(s) = p.take_tcp_shutdown() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        // Drop writer channel + abort writer/session so local halves tear down
        // even if the read loop is mid-frame.
        p.clear_out_tx();
        if let Some(h) = p.take_writer_abort() {
            h.abort();
        }
        if let Some(h) = p.take_session_abort() {
            h.abort();
        }
        // Drop from getpeerinfo before teardown finishes.
        self.unregister(id);
        true
    }

    /// Disconnect one unprotected inbound when inbound slots are full.
    pub fn try_evict_inbound(&self) -> bool {
        let now = self.now_secs();
        let cands: Vec<crate::eviction::InboundEvictCandidate> = self
            .live_peers()
            .into_iter()
            .filter(|p| p.inbound && !p.stop.load(Ordering::Relaxed))
            .map(|p| {
                let (_pt, minping, _pw) = p.ping_rpc_fields(now);
                crate::eviction::InboundEvictCandidate {
                    id: p.id,
                    connected_at: p.connected_at(),
                    min_ping: minping,
                    last_block: p.last_block.load(Ordering::Relaxed),
                    last_tx: p.last_transaction.load(Ordering::Relaxed),
                    netgroup: crate::eviction::eviction_netgroup(p.addr),
                    noban: p.session_noban(),
                }
            })
            .collect();
        let Some(id) = crate::eviction::select_inbound_eviction(cands) else {
            return false;
        };
        rbitcoin_log::info!("p2p: evict inbound peer={id} (inbound full)");
        self.disconnect_id(id)
    }

    pub fn disconnect_addr(&self, addr: SocketAddr) -> bool {
        self.disconnect_net(crate::NetAddr::Ip(addr))
    }

    pub fn disconnect_net(&self, addr: crate::NetAddr) -> bool {
        let ids: Vec<u64> = {
            let g = self.live.read().unwrap_or_else(|e| e.into_inner());
            g.values().filter(|p| p.net == addr).map(|p| p.id).collect()
        };
        let mut n = 0usize;
        for id in ids {
            if self.disconnect_id(id) {
                n += 1;
            }
        }
        n > 0
    }

    pub fn dial(&self, addr: SocketAddr, typ: PeerConnType) -> Result<(), String> {
        let g = self.dial_tx.lock().unwrap_or_else(|e| e.into_inner());
        let tx = g.as_ref().ok_or("no dialer attached")?;
        tx.send(DialRequest {
            target: DialTarget::from_net(crate::NetAddr::Ip(addr)),
            typ,
        })
        .map_err(|_| "dialer closed".to_string())
    }

    pub fn dial_domain(
        &self,
        host: impl Into<String>,
        port: u16,
        typ: PeerConnType,
    ) -> Result<(), String> {
        let g = self.dial_tx.lock().unwrap_or_else(|e| e.into_inner());
        let tx = g.as_ref().ok_or("no dialer attached")?;
        tx.send(DialRequest {
            target: DialTarget::Domain {
                host: host.into(),
                port,
            },
            typ,
        })
        .map_err(|_| "dialer closed".to_string())
    }
}

/// Pick one live outbound id to drop so a stale-tip extra can dial.
/// Prefer an id whose netgroup is shared with another outbound (break a
/// duplicate). If every candidate is unique, `ids[salt % len]` as before.
pub fn pick_stale_follow_evict(ids: &[u64], salt: u64, groups: &[u64]) -> Option<u64> {
    if ids.is_empty() {
        return None;
    }
    if groups.len() == ids.len() {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for &g in groups {
            *counts.entry(g).or_insert(0) += 1;
        }
        let dup: Vec<usize> = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| counts.get(g).copied().unwrap_or(0) > 1)
            .map(|(i, _)| i)
            .collect();
        if !dup.is_empty() {
            return Some(ids[dup[(salt as usize) % dup.len()]]);
        }
    }
    Some(ids[(salt as usize) % ids.len()])
}

fn service_flags_u64(f: ServiceFlags) -> u64 {
    // rust-bitcoin 0.32: ServiceFlags is a bitflags newtype.
    f.to_u64()
}

/// Parse Core `ip:port` / `[v6]:port`.
pub fn parse_peer_addr(s: &str) -> Result<SocketAddr, NetError> {
    s.parse()
        .map_err(|_| NetError::Encode(format!("bad peer address {s}")))
}

pub fn parse_peer_net(s: &str) -> Result<crate::NetAddr, NetError> {
    s.parse()
        .map_err(|_| NetError::Encode(format!("bad peer address {s}")))
}

fn ensure_host_port(node: &str, default_port: Option<u16>) -> Result<String, String> {
    if node.parse::<SocketAddr>().is_ok() {
        return Ok(node.to_string());
    }
    if let Some((host, port_s)) = node.rsplit_once(':') {
        if !host.is_empty() && !host.starts_with('[') && port_s.parse::<u16>().is_ok() {
            return Ok(node.to_string());
        }
    }
    let port = default_port.ok_or_else(|| format!("bad peer address {node}"))?;
    if node.is_empty() || node.contains(char::is_whitespace) {
        return Err(format!("bad peer address {node}"));
    }
    Ok(format!("{node}:{port}"))
}

/// Parse `ip:port`, `[v6]:port`, `host:port`, or `host` (uses `default_port`).
///
/// Hostnames resolve at call time (`ToSocketAddrs`). Dual-stack names prefer
/// IPv4 so `localhost` reaches a `127.0.0.1` listener.
pub fn parse_peer_addr_with_port(
    s: &str,
    default_port: Option<u16>,
) -> Result<SocketAddr, NetError> {
    let bad = || NetError::Encode(format!("bad peer address {s}"));
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        let port = default_port.ok_or_else(bad)?;
        return Ok(SocketAddr::new(ip, port));
    }
    let with_port = ensure_host_port(s, default_port).map_err(|_| bad())?;
    let addrs: Vec<SocketAddr> = with_port.to_socket_addrs().map_err(|_| bad())?.collect();
    addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first().copied())
        .ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::address::Address;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn ver(ua: &str) -> VersionMessage {
        VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            timestamp: 0,
            receiver: Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                ServiceFlags::NONE,
            ),
            sender: Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
                ServiceFlags::NONE,
            ),
            nonce: 1,
            user_agent: ua.into(),
            start_height: 0,
            relay: true,
        }
    }

    #[test]
    fn pending_sendcmpct_from_u8_maps_wire_payload() {
        assert_eq!(PendingSendCmpct::from_u8(0), PendingSendCmpct::None);
        assert_eq!(PendingSendCmpct::from_u8(1), PendingSendCmpct::Lb);
        assert_eq!(PendingSendCmpct::from_u8(2), PendingSendCmpct::Hb);
        assert_eq!(PendingSendCmpct::from_u8(3), PendingSendCmpct::None);
        assert_eq!(PendingSendCmpct::from_u8(255), PendingSendCmpct::None);
        assert_eq!(PendingSendCmpct::None as u8, 0);
        assert_eq!(PendingSendCmpct::Lb as u8, 1);
        assert_eq!(PendingSendCmpct::Hb as u8, 2);
    }

    #[test]
    fn trying_connection_log_is_p2p_not_v1() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(25, 0, 0, 1)), 8333);
        assert_eq!(
            trying_connection_log(PeerConnType::OutboundFullRelay, addr),
            "p2p: trying connection (outbound-full-relay) to 25.0.0.1:8333"
        );
        assert_eq!(
            trying_connection_log(PeerConnType::AddrFetch, addr),
            "p2p: trying connection (addr-fetch) to 25.0.0.1:8333"
        );
    }

    #[test]
    fn snapshot_hides_fin_completed_keeps_connecting() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let local = std::net::TcpStream::connect(addr).unwrap();
        let (far, _) = listener.accept().unwrap();
        drop(far);
        let _ = local.shutdown(std::net::Shutdown::Both);

        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let connecting = hub.register_connecting(a, a, true, PeerConnType::Inbound);
        connecting.attach_tcp_shutdown(local.try_clone().unwrap());
        assert_eq!(
            hub.snapshot().len(),
            1,
            "connecting peer stays in getpeerinfo during v2 handshake"
        );

        let done = hub.register(a, a, &ver("/rbitcoin:test/"), false, PeerConnType::Inbound);
        done.attach_tcp_shutdown(local);
        assert!(
            hub.snapshot().iter().all(|p| p.id != done.id),
            "completed FIN'd peer must not appear in getpeerinfo"
        );
        connecting.request_disconnect();
        assert!(
            hub.snapshot().iter().all(|p| p.id != connecting.id),
            "stopped connecting peer is omitted"
        );
    }

    #[test]
    fn disconnect_id_shuts_down_tcp_so_far_side_sees_eof() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut local = std::net::TcpStream::connect(addr).unwrap();
        let (mut far, _) = listener.accept().unwrap();
        far.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
        let p = hub.register(
            a,
            b,
            &ver("/rbitcoin:0.1.0(testnode0)/"),
            false,
            PeerConnType::OutboundFullRelay,
        );
        let killer = local.try_clone().unwrap();
        p.attach_tcp_shutdown(killer);

        assert!(hub.disconnect_id(0));

        let start = Instant::now();
        let mut buf = [0u8; 1];
        let n = far.read(&mut buf);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "far side must observe close promptly, took {:?}",
            start.elapsed()
        );
        match n {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                ) => {}
            other => panic!("expected EOF/reset after disconnect_id, got {other:?}"),
        }
        let _ = local.write(&[1]);
    }

    #[test]
    fn connecting_peer_v2_timeout_log_before_transport() {
        rbitcoin_log::capture_logs(true);
        let hub = PeerHub::new();
        hub.set_peer_timeout_secs(3);
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let p = hub.register_connecting(a, a, true, PeerConnType::Inbound);
        assert!(!p.handshake_complete());
        hub.set_mock_now(1_700_000_002);
        assert!(!p.stop.load(Ordering::SeqCst), "still inside peertimeout");
        hub.set_mock_now(1_700_000_003);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            p.stop.load(Ordering::SeqCst),
            "peertimeout must disconnect pre-verack"
        );
        assert!(
            hub.get(p.id).is_none(),
            "timed-out connecting peer is dropped"
        );
        assert!(
            logs.iter()
                .any(|(_, m)| m.contains("V2 handshake timeout, disconnecting peer=0")),
            "expected V2 handshake timeout, got {logs:?}"
        );
    }

    #[test]
    fn p2p_timeouts_v2_logs_all_three_connecting_peer_ids() {
        rbitcoin_log::capture_logs(true);
        let hub = PeerHub::new();
        hub.set_peer_timeout_secs(3);
        hub.set_mock_now(1_700_000_000);
        let addr = |p| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p);
        let peers: Vec<_> = (1..=3)
            .map(|p| {
                let s = hub.register_connecting(addr(p), addr(p), true, PeerConnType::Inbound);
                s.mark_v2_transport_ready();
                s
            })
            .collect();
        assert_eq!(peers.iter().map(|p| p.id).collect::<Vec<_>>(), [0, 1, 2]);
        hub.set_mock_now(1_700_000_003);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let got: Vec<u64> = logs
            .iter()
            .filter_map(|(_, m)| {
                [0u64, 1, 2].into_iter().find(|id| {
                    m.contains(&format!(
                        "version handshake timeout, disconnecting peer={id}"
                    ))
                })
            })
            .collect();
        assert_eq!(
            got,
            vec![0, 1, 2],
            "timeout needles before TCP close, id order, got {logs:?}"
        );
    }

    #[test]
    fn handshake_timeout_tick_logs_when_stop_already_set() {
        rbitcoin_log::capture_logs(true);
        let hub = PeerHub::new();
        hub.set_peer_timeout_secs(3);
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let p = hub.register_connecting(a, a, true, PeerConnType::Inbound);
        p.mark_v2_transport_ready();
        p.request_disconnect();
        let _ = rbitcoin_log::take_logs();
        hub.mock_now.store(1_700_000_003, Ordering::Release);
        let policy = crate::peer::HandshakePolicy {
            hub: None,
            peers: Some(&hub),
            session: Some(p.as_ref()),
            conn_type: PeerConnType::Inbound,
        };
        let err = crate::peer::fail_if_handshake_timed_out(&policy);
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            matches!(err, Err(crate::error::NetError::Timeout)),
            "got {err:?}"
        );
        assert!(
            logs.iter()
                .any(|(_, m)| m.contains("version handshake timeout, disconnecting peer=0")),
            "pre-verack ping vs mocktime must still log the needle, got {logs:?}"
        );
    }

    /// One PeerHub while peers come and go: compact high-bandwidth
    /// selection and its evictions, compact fill slots, per-peer block and
    /// header marks, the single initial headers-sync peer, and each peer's
    /// announced-wtxid set.
    #[allow(clippy::cognitive_complexity)] // one hub, many peer-state arms
    #[test]
    fn peerhub_hb_select() {
        let hub = PeerHub::new();
        let join = |port: u16, inbound: bool| {
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let conn = if inbound {
                PeerConnType::Inbound
            } else {
                PeerConnType::OutboundFullRelay
            };
            hub.register(a, a, &ver("/rbitcoin:0.1.0(testnode0)/"), inbound, conn)
        };
        let hb = |p: &LivePeer| p.hb_to.load(Ordering::Relaxed);
        let pending = |p: &LivePeer| p.pending_sendcmpct.load(Ordering::Relaxed);
        let sendcmpct = |rx: &mut mpsc::UnboundedReceiver<PeerOut>| match rx
            .try_recv()
            .expect("sendcmpct")
            .expect_msg()
        {
            NetworkMessage::SendCmpct(sc) => {
                assert_eq!(sc.version, 2);
                sc.send_compact
            }
            other => panic!("expected sendcmpct, got {other:?}"),
        };

        // An unknown id is ignored. A lone outbound is selected first.
        hub.maybe_select_hb(9_999);
        let out = join(18444, false);
        hub.maybe_select_hb(out.id);
        assert!(hb(&out));

        // Without a writer the HB choice waits as pending; with one it goes
        // out as sendcmpct at once.
        let a = join(18445, true);
        hub.maybe_select_hb(a.id);
        hub.maybe_select_hb(a.id);
        assert!(hb(&a));
        assert_eq!(pending(&a), PendingSendCmpct::Hb as u8);
        let b = join(18446, true);
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        b.attach_out(b_tx);
        hub.maybe_select_hb(b.id);
        assert!(hb(&b) && sendcmpct(&mut b_rx));
        assert_eq!(pending(&b), 0);

        // A third inbound evicts the oldest inbound and keeps the lone
        // outbound. The evicted peer's LB choice waits as pending.
        let c = join(18447, true);
        hub.maybe_select_hb(c.id);
        assert!(hb(&out) && hb(&b) && hb(&c));
        assert!(
            !hb(&a),
            "lone outbound stays; first inbound is the eviction"
        );
        assert_eq!(pending(&a), PendingSendCmpct::Lb as u8);

        // Re-selecting b refreshes it (Core LRU), so the next inbound evicts c.
        hub.maybe_select_hb(b.id);
        let d = join(18448, true);
        hub.maybe_select_hb(d.id);
        assert!(hb(&b), "re-selected inbound stays HB");
        assert!(!hb(&c), "oldest unrefreshed inbound is evicted");
        assert!(hb(&d));

        // d leaves. Its slot is free, so e does not evict a live HB peer.
        hub.unregister(d.id);
        let e = join(18449, true);
        hub.maybe_select_hb(e.id);
        assert!(hb(&out) && hb(&b) && hb(&e));

        // The outbound leaves too. With no outbound the oldest HB peer, b,
        // is evicted, and its writer gets sendcmpct LB.
        hub.unregister(out.id);
        let f = join(18450, true);
        hub.maybe_select_hb(f.id);
        let g = join(18451, true);
        hub.maybe_select_hb(g.id);
        assert!(!hb(&b) && !sendcmpct(&mut b_rx));
        assert_eq!(pending(&b), 0);
        assert!(hb(&e) && hb(&f) && hb(&g));

        // Two compact fill slots per block. A release frees one; a peer that
        // leaves releases its slot.
        let blk = BlockHash::from_byte_array([0x11; 32]);
        assert!(hub.try_cmpct_fill_slot(blk, true));
        assert!(hub.try_cmpct_fill_slot(blk, true));
        assert!(!hub.try_cmpct_fill_slot(blk, true));
        hub.release_cmpct_fill(blk, true);
        assert!(hub.try_cmpct_fill_slot(blk, true));
        assert!(!hub.try_cmpct_fill_slot(blk, true));
        hub.release_cmpct_fill(blk, true);
        hub.release_cmpct_fill(blk, true);
        let blk = BlockHash::from_byte_array([0x22; 32]);
        assert!(g.try_cmpct_fill(blk));
        hub.unregister(g.id);
        assert!(hub.try_cmpct_fill_slot(blk, true));
        assert!(hub.try_cmpct_fill_slot(blk, true));
        assert!(!hub.try_cmpct_fill_slot(blk, true));

        // A block e sent is not announced back to e, once. Header marks.
        let blk = BlockHash::from_byte_array([0xab; 32]);
        assert!(!e.take_block_from_peer(&blk));
        e.note_block_from_peer(blk);
        assert!(e.take_block_from_peer(&blk));
        assert!(!e.take_block_from_peer(&blk));
        assert!(e.try_ask_headers_for_inv());
        assert!(!e.try_ask_headers_for_inv());
        e.note_best_header_sent(blk);
        e.note_best_known(blk);
        assert_eq!(e.header_marks(), (Some(blk), Some(blk)));
        assert!(e.advertises_network());

        // With an old tip only one peer runs initial headers sync. Inv adds
        // at most one extra getheaders peer per hash. When the sync peer
        // leaves, another may start.
        let now = 1_700_000_000;
        let genesis_time = 1_231_006_505;
        assert!(hub.try_start_headers_sync(&a, now, genesis_time));
        assert!(a.is_sync_started());
        assert!(!hub.try_start_headers_sync(&c, now, genesis_time));
        assert!(!c.is_sync_started());
        let (h1, h2) = (
            BlockHash::from_byte_array([1u8; 32]),
            BlockHash::from_byte_array([2u8; 32]),
        );
        assert!(hub.should_getheaders_for_inv(&a, h1));
        assert!(hub.should_getheaders_for_inv(&c, h1));
        assert!(!hub.should_getheaders_for_inv(&f, h1));
        assert!(hub.should_getheaders_for_inv(&f, h2));
        hub.unregister(a.id);
        assert!(!a.is_sync_started());
        assert!(hub.try_start_headers_sync(&c, now, genesis_time));

        // Announced wtxids are per peer, roll the oldest at the cap, and
        // tx inv is due on a timer or on request.
        let wtxid_n = |i: u32| {
            let mut w = [0u8; 32];
            w[..4].copy_from_slice(&i.to_le_bytes());
            Wtxid::from_byte_array(w)
        };
        e.note_announced_wtx(wtxid_n(0));
        assert!(e.has_announced_wtx(&wtxid_n(0)));
        assert!(!e.has_announced_wtx(&wtxid_n(1)));
        assert!(!f.has_announced_wtx(&wtxid_n(0)));
        assert!(!e.take_tx_inv_due(1_700_000_000));
        assert!(!e.take_tx_inv_due(1_700_000_010));
        assert!(e.take_tx_inv_due(1_700_000_040));
        e.request_tx_inv();
        assert!(e.take_tx_inv_due(1_700_000_041));
        for i in 1..=50_000 {
            e.note_announced_wtx(wtxid_n(i));
        }
        assert!(!e.has_announced_wtx(&wtxid_n(0)));
        assert!(e.has_announced_wtx(&wtxid_n(1)));
        assert!(e.has_announced_wtx(&wtxid_n(50_000)));
    }

    #[test]
    fn session_heartbeat_keeps_sole_preferred_headers_sync_peer() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let outbound = hub.register(
            a,
            a,
            &ver("/rbitcoin:0.1.0/"),
            false,
            PeerConnType::OutboundFullRelay,
        );
        let wall = hub.now_secs();
        let start = wall.saturating_sub(16 * 60);
        assert!(hub.try_start_headers_sync(&outbound, start, start));
        hub.on_session_heartbeat();
        assert!(
            !outbound.stop.load(Ordering::SeqCst),
            "must not disconnect the only preferred download peer"
        );
        assert!(outbound.is_sync_started());
    }

    #[test]
    fn noban_headers_timeout_clears_awaiting_so_a_new_getheaders_can_send() {
        pin_noban_headers_timeout_keep(true);
        pin_noban_headers_timeout_keep(false);
    }

    fn pin_noban_headers_timeout_keep(via_cidr: bool) {
        let hub = PeerHub::new();
        if via_cidr {
            let mut t = crate::NetPermTable::default();
            t.whitelist
                .push(crate::parse_whitelist("noban@127.0.0.1").unwrap());
            hub.set_net_perms(t);
        } else {
            hub.set_noban(true);
        }
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
        let inbound = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let _outbound = hub.register(
            b,
            b,
            &ver("/rbitcoin:0.1.0/"),
            false,
            PeerConnType::OutboundFullRelay,
        );
        if via_cidr {
            assert!(!hub.is_noban(), "CIDR noban must not set hub --trusted");
            assert!(inbound.session_noban());
        }
        let now = 1_700_000_000u64;
        let best = 1_231_006_505u64;
        assert!(hub.try_start_headers_sync(&inbound, now, best));
        inbound.note_awaiting_headers();
        assert!(inbound.is_awaiting_headers());
        let deadline = crate::chain::headers_download_timeout_secs(now, best);
        hub.set_mock_now(deadline + 1);
        assert!(
            !inbound.stop.load(Ordering::SeqCst),
            "noban stall must keep the TCP session (via_cidr={via_cidr})"
        );
        assert!(
            !inbound.is_sync_started(),
            "noban timeout must end the stalling sync (via_cidr={via_cidr})"
        );
        assert!(
            !inbound.is_awaiting_headers(),
            "in-flight getheaders must be released so a replacement can send"
        );
        assert!(
            hub.try_start_headers_sync(&inbound, deadline + 1, best),
            "after timeout another getheaders start must be allowed"
        );
    }

    #[test]
    fn snapshot_permissions_are_cidr_table_not_hub_noban() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
        hub.register(
            a,
            bind,
            &ver("/rbitcoin:0.1.0/"),
            false,
            PeerConnType::OutboundFullRelay,
        );
        hub.set_noban(true);
        assert!(
            hub.snapshot()[0].permissions.is_empty(),
            "hub --trusted is a DoS bypass, not getpeerinfo.permissions"
        );
        let mut t = crate::NetPermTable::default();
        t.whitelist
            .push(crate::parse_whitelist("noban,out@127.0.0.1").unwrap());
        hub.set_net_perms(t);
        assert_eq!(hub.snapshot()[0].permissions, ["noban", "download"]);
    }

    #[test]
    fn cidr_noban_is_per_peer_not_hub_wide() {
        let hub = PeerHub::new();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
        let local = hub.register(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444),
            bind,
            &ver("/rbitcoin:0.1.0/"),
            true,
            PeerConnType::Inbound,
        );
        let other = hub.register(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 18444),
            bind,
            &ver("/rbitcoin:0.1.0/"),
            true,
            PeerConnType::Inbound,
        );
        let mut t = crate::NetPermTable::default();
        t.whitelist
            .push(crate::parse_whitelist("noban@127.0.0.1").unwrap());
        hub.set_net_perms(t);
        assert!(!hub.is_noban(), "a CIDR grant must not set hub --trusted");
        assert!(local.session_noban());
        assert!(
            !other.session_noban(),
            "non-matching inbound must not inherit CIDR noban"
        );
        hub.set_noban(true);
        assert!(
            other.session_noban(),
            "operator --trusted still covers every session"
        );
    }

    #[test]
    fn addnode_unknown_command() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        assert!(hub.addnode(a, "nope").is_err());
    }

    fn take_dials(rx: &mut mpsc::UnboundedReceiver<DialRequest>) -> Vec<DialRequest> {
        let mut out = Vec::new();
        while let Ok(req) = rx.try_recv() {
            out.push(req);
        }
        out
    }

    #[test]
    fn parse_peer_addr_localhost_and_default_port() {
        let with_port = parse_peer_addr_with_port("localhost:18444", None).expect("localhost:port");
        assert!(with_port.is_ipv4());
        assert_eq!(with_port.port(), 18444);
        let bare = parse_peer_addr_with_port("localhost", Some(18444)).expect("localhost default");
        assert!(bare.is_ipv4());
        assert_eq!(bare.port(), 18444);
        let lit = "127.0.0.1:18444".parse::<SocketAddr>().unwrap();
        assert_eq!(
            parse_peer_addr_with_port("127.0.0.1:18444", None).unwrap(),
            lit
        );
        assert!(parse_peer_addr_with_port("not-a-real-host.invalid", Some(18444)).is_err());
    }

    #[test]
    fn addnode_add_keeps_unresolved_host_for_redial() {
        let hub = PeerHub::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        hub.set_dialer(tx);
        hub.addnode_host("not-a-real-host.invalid", "add", 18444)
            .expect("unresolved add is remembered");
        assert!(take_dials(&mut rx).is_empty());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        hub.redial_remembered_with(|_| Ok(DialTarget::Socket(addr)));
        let got = take_dials(&mut rx);
        assert_eq!(got.len(), 1, "later resolve must dial: {got:?}");
        assert!(matches!(got[0].target, DialTarget::Socket(a) if a == addr));
        assert!(hub
            .addnode_host("not-a-real-host.invalid", "onetry", 18444)
            .is_err());
    }

    #[test]
    fn redial_same_endpoint_in_addnode_and_connect_dials_once() {
        let hub = PeerHub::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        hub.set_dialer(tx);
        hub.addnode_host("127.0.0.1:18444", "add", 18444).unwrap();
        assert_eq!(take_dials(&mut rx).len(), 1);
        hub.set_connect_hosts(vec!["127.0.0.1:18444".into()], 18444);
        hub.redial_remembered();
        let got = take_dials(&mut rx);
        assert_eq!(
            got.len(),
            1,
            "addnode and --connect of one endpoint share one dial per pass: {got:?}"
        );
        assert!(matches!(got[0].typ, PeerConnType::Manual));
    }

    #[tokio::test]
    async fn slow_redial_resolve_does_not_stall_runtime() {
        let hub = PeerHub::new();
        hub.set_connect_hosts(vec!["slow.example".into()], 18444);
        let flag = Arc::new(AtomicBool::new(false));
        let flag2 = Arc::clone(&flag);
        let progress = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            flag2.store(true, Ordering::SeqCst);
        });
        let hub2 = Arc::clone(&hub);
        let slow = tokio::task::spawn_blocking(move || {
            hub2.redial_remembered_with(|_| {
                std::thread::sleep(std::time::Duration::from_millis(150));
                Err("slow".into())
            });
        });
        progress.await.unwrap();
        assert!(
            flag.load(Ordering::SeqCst),
            "a blocking resolve must not stall other Tokio tasks"
        );
        slow.await.unwrap();
    }

    /// Core runs the ping timeout only once `-peertimeout` has passed since
    /// connect. Core's functional framework sets `peertimeout=999999999` so a
    /// `setmocktime` jump cannot drop peers (`feature_bip68_sequence.py`).
    #[test]
    fn ping_timeout_waits_for_the_peer_timeout() {
        let hub = PeerHub::new();
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let p = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let now = hub.now_secs();
        let Some(PingAction::Send { .. }) = p.take_ping_action(now) else {
            panic!("expected send");
        };
        hub.set_peer_timeout_secs(999_999_999);
        assert!(
            !matches!(
                p.take_ping_action(now + 6_000),
                Some(PingAction::Timeout { .. })
            ),
            "inside the peer timeout the ping does not time out"
        );
        hub.set_peer_timeout_secs(60);
        assert!(matches!(
            p.take_ping_action(now + 6_000),
            Some(PingAction::Timeout { .. })
        ));
    }

    #[test]
    fn pick_stale_follow_evict_none_on_empty() {
        assert!(pick_stale_follow_evict(&[], 7, &[]).is_none());
    }

    #[test]
    fn pick_stale_follow_evict_picks_only_from_candidates() {
        let ids = [3u64, 9, 12];
        let groups = [1u64, 2, 3];
        for salt in 0..16u64 {
            let got = pick_stale_follow_evict(&ids, salt, &groups).unwrap();
            assert!(ids.contains(&got), "salt={salt} got={got}");
        }
        assert_eq!(pick_stale_follow_evict(&ids, 0, &groups), Some(3));
        assert_eq!(pick_stale_follow_evict(&ids, 1, &groups), Some(9));
        assert_eq!(pick_stale_follow_evict(&ids, 2, &groups), Some(12));
        assert_eq!(pick_stale_follow_evict(&ids, 3, &groups), Some(3));
    }

    #[test]
    fn pick_stale_follow_evict_prefers_duplicate_group() {
        let ids = [1u64, 2, 3];
        let groups = [10u64, 10, 20];
        assert_eq!(pick_stale_follow_evict(&ids, 0, &groups), Some(1));
        assert_eq!(pick_stale_follow_evict(&ids, 1, &groups), Some(2));
        for salt in 0..16u64 {
            let got = pick_stale_follow_evict(&ids, salt, &groups).unwrap();
            assert!(got == 1 || got == 2, "salt={salt} got={got}");
        }
    }

    #[test]
    fn outbound_full_relay_ids_skips_inbound_and_noban() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
        let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3);
        let _in = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let out = hub.register(
            b,
            b,
            &ver("/rbitcoin:0.1.0/"),
            false,
            PeerConnType::OutboundFullRelay,
        );
        let _br = hub.register(
            c,
            c,
            &ver("/rbitcoin:0.1.0/"),
            false,
            PeerConnType::BlockRelay,
        );
        let ids = hub.outbound_full_relay_ids();
        assert_eq!(ids, vec![out.id]);
        hub.set_noban(true);
        assert!(
            hub.outbound_full_relay_ids().is_empty(),
            "noban hub must not offer rotate victims"
        );
    }

    fn fill_addrman(n: usize) -> crate::seeds::AddrMan {
        let mut am = crate::seeds::AddrMan::new();
        for i in 0..n {
            let a = (i >> 8) as u8;
            let b = (i & 0xff) as u8;
            am.add_with_flags(
                SocketAddr::from(([a, b, 1, 1], 8333)),
                crate::seeds::PeerFlags::empty(),
            );
        }
        am
    }

    fn addr_ips(v: &[(u32, Address)]) -> Vec<IpAddr> {
        v.iter()
            .filter_map(|(_, a)| a.socket_addr().ok().map(|s| s.ip()))
            .collect()
    }

    #[test]
    fn getaddr_cache_bind_key_and_ttl() {
        let hub = PeerHub::new();
        hub.set_mock_now(1_700_000_000);
        hub.set_addrman(Arc::new(Mutex::new(fill_addrman(5_000))));
        let a = addr_ips(&hub.addr_response_for_bind(SocketAddr::from(([127, 0, 0, 1], 18444))));
        let b = addr_ips(&hub.addr_response_for_bind(SocketAddr::from(([127, 0, 0, 1], 18445))));
        let c = addr_ips(&hub.addr_response_for_bind(SocketAddr::from(([127, 0, 0, 1], 18446))));
        let mapped = addr_ips(&hub.addr_response_for_bind(SocketAddr::from((
            Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(),
            18444,
        ))));
        assert_eq!(a.len(), 1000);
        assert_eq!(b.len(), 1000);
        assert_eq!(c.len(), 1000);
        assert_eq!(
            a, mapped,
            "IPv4-mapped IPv6 must share the clearnet cache key"
        );
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        hub.set_mock_now(1_700_000_000 + 24 * 60 * 60);
        let expired =
            addr_ips(&hub.addr_response_for_bind(SocketAddr::from(([127, 0, 0, 1], 18444))));
        assert_eq!(expired.len(), 1000);
        assert_ne!(a, expired);
    }

    include!("overlay_addrman_journey.rs");
}
