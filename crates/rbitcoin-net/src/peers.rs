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
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Arc, Mutex, RwLock, Weak};
use tokio::sync::{mpsc, watch, Notify};

/// Per-peer outbound queue cap (a few megabytes). Not a configuration knob.
///
/// Core's `-maxsendbuffer` is the same idea. One reply may land past the cap;
/// the next inbound request from that peer waits until the writer drains.
pub const PEER_SEND_BUDGET: usize = 4 * 1024 * 1024;

/// Queued-byte estimate. Headers are 81 wire bytes, inv-like rows are 36,
/// legacy addr rows are 30. Encoded block bodies use their buffer length.
pub fn outbound_msg_bytes(msg: &NetworkMessage) -> usize {
    match msg {
        NetworkMessage::Headers(h) => h.len().saturating_mul(81),
        NetworkMessage::Inv(v) | NetworkMessage::NotFound(v) | NetworkMessage::GetData(v) => {
            v.len().saturating_mul(36)
        }
        NetworkMessage::Tx(tx) => tx.total_size(),
        NetworkMessage::Block(b) => b.total_size(),
        NetworkMessage::BlockTxn(bt) => {
            // BlockTransactions: hash, compact count, then each transaction.
            let txs = &bt.transactions.transactions;
            32 + bitcoin::consensus::encode::VarInt(txs.len() as u64).size()
                + txs.iter().map(|tx| tx.total_size()).sum::<usize>()
        }
        NetworkMessage::Addr(a) => a.len().saturating_mul(30),
        NetworkMessage::AddrV2(a) => a.len().saturating_mul(61),
        NetworkMessage::CmpctBlock(_) => 1024,
        _ => 64,
    }
}

pub fn outbound_queued_bytes(out: &PeerOut) -> usize {
    match out {
        PeerOut::Msg(m) | PeerOut::Served(m) => outbound_msg_bytes(m),
        PeerOut::Encoded(b) => b.len(),
    }
}

/// Session writer payload: application messages or pre-encoded v2 block bytes.
#[derive(Debug)]
pub enum PeerOut {
    Msg(NetworkMessage),
    /// A getdata witness block, pre-encoded. Holds one serve slot.
    Encoded(Vec<u8>),
    /// A getdata `block` or `cmpctblock`. Holds one serve slot.
    Served(NetworkMessage),
}

impl PeerOut {
    /// A getdata body or a `getblocktxn` reply (`blocktxn` or the deep
    /// full block) that holds one [`LivePeer::serve_inflight`] slot until
    /// the writer is done with it. A compact tip announce is a
    /// [`PeerOut::Msg`] and holds none.
    pub fn holds_serve_slot(&self) -> bool {
        matches!(self, PeerOut::Encoded(_) | PeerOut::Served(_))
    }

    #[cfg(debug_assertions)]
    pub fn expect_msg(self) -> NetworkMessage {
        match self {
            PeerOut::Msg(m) | PeerOut::Served(m) => m,
            PeerOut::Encoded(_) => panic!("expected application message, got encoded block"),
        }
    }
}

/// Insertion-order set that drops the oldest key at `cap` (INV / origin skip).
/// Re-insert of a live key is a no-op; it does not refresh FIFO position.
#[derive(Debug)]
pub struct CappedSet<T> {
    pub set: HashSet<T>,
    pub fifo: VecDeque<T>,
}

impl<T> Default for CappedSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> CappedSet<T> {
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
            fifo: VecDeque::new(),
        }
    }

    pub fn contains(&self, item: &T) -> bool
    where
        T: Eq + Hash,
    {
        self.set.contains(item)
    }

    pub fn contains_key(&self, item: &T) -> bool
    where
        T: Eq + Hash,
    {
        self.contains(item)
    }

    #[cfg(debug_assertions)]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    #[cfg(debug_assertions)]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn insert(&mut self, item: T, cap: usize)
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
    /// Isolated local-tx broadcast. Never in the peer table, and not an
    /// `addconnection` type (Core's is not either).
    PrivateBroadcast,
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
            Self::PrivateBroadcast => "private-broadcast",
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

pub fn trying_connection_log(typ: PeerConnType, addr: impl std::fmt::Display) -> String {
    format!("p2p: trying connection ({}) to {addr}", typ.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialTarget {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

impl DialTarget {
    pub fn from_net(addr: crate::NetAddr) -> Self {
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

    /// An overlay host is its own `NetAddr`. A DNS name (a `--proxy` seed
    /// addr-fetch) has no address until the proxy resolves it, so it is the
    /// [`Self::version_socket`] `0.0.0.0:port`.
    pub fn net_addr(&self) -> crate::NetAddr {
        match self {
            Self::Socket(addr) => crate::NetAddr::from_socket(*addr),
            Self::Domain { host, port } => format!("{host}:{port}")
                .parse()
                .unwrap_or_else(|_| crate::NetAddr::from_socket(self.version_socket())),
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

/// One in-flight dial of `net`. `n` stacks only when [`PeerHub::dial_in_flight`]
/// is taken again for the same target; [`PeerHub::claim_dial`] refuses that.
#[derive(Clone, Copy, Debug)]
pub struct InFlightCount {
    pub n: usize,
    pub net: crate::NetAddr,
}

/// An outbound dial counted in [`PeerHub::dial_in_flight`]; dropping it
/// ends the count.
#[derive(Debug)]
pub struct DialInFlight {
    pub counts: Arc<Mutex<HashMap<String, InFlightCount>>>,
    pub key: String,
}

impl Drop for DialInFlight {
    fn drop(&mut self) {
        let mut g = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = g.get_mut(&self.key) {
            slot.n -= 1;
            if slot.n == 0 {
                g.remove(&self.key);
            }
        }
    }
}

/// Request that the node dial `addr` as `typ`.
#[derive(Debug)]
pub struct DialRequest {
    pub target: DialTarget,
    pub typ: PeerConnType,
    /// Counts the dial from the moment it is queued, so a redial or
    /// `addnode` that runs before the dial task picks it up sees it. `None`
    /// for a feeler, which registers no session and is never counted.
    pub in_flight: Option<DialInFlight>,
}

/// [`PeerHub`] with a dial channel already attached.
pub struct DialReady<'a> {
    hub: &'a PeerHub,
    tx: mpsc::UnboundedSender<DialRequest>,
}

impl DialReady<'_> {
    pub fn addnode_host(&self, node: &str, cmd: &str, default_port: u16) -> Result<(), String> {
        self.hub
            .addnode_host_ready(&self.tx, node, cmd, default_port)
    }
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
    pub send_queued: AtomicUsize,
    /// Wakes the reader after the writer drains under [`PEER_SEND_BUDGET`].
    pub send_resume: tokio::sync::Notify,
    /// Inbound `getaddr` is answered once per connection.
    pub getaddr_answered: AtomicBool,
    /// We sent `sendcmpct(1)`: this peer should announce compact blocks to us.
    pub hb_to: AtomicBool,
    /// They sent `sendcmpct(1)`: we announce compact blocks to this peer.
    pub hb_from: AtomicBool,
    /// Session should send `sendcmpct` (`PendingSendCmpct` as u8).
    pub pending_sendcmpct: std::sync::atomic::AtomicU8,
    /// Last header we announced to this peer.
    pub best_header_sent: Mutex<Option<BlockHash>>,
    /// Best connected block this peer advertised.
    pub best_known: Mutex<Option<BlockHash>>,
    /// Block hashes this peer just sent us — do not announce them back.
    pub recently_from: Mutex<HashSet<BlockHash>>,
    /// We already sent inv-triggered getheaders this session (before sync).
    pub inv_asked_headers: AtomicBool,
    /// This session is the headers-sync peer (or one of them after catch-up).
    pub sync_started: AtomicBool,
    /// Unix seconds when initial headers sync times out (`0` = none).
    pub headers_sync_timeout: AtomicU64,
    /// Waiting for a headers reply to our getheaders (no BIP130 cap).
    pub awaiting_headers: AtomicBool,
    /// Wtxids we INV'd to this peer. GetData for a live mempool tx is
    /// answered only if announced here or the tx is reorg-servable.
    pub announced_wtx: Mutex<CappedSet<Wtxid>>,
    /// Compact fill slots taken by this session (hub-global `cmpct_fills`).
    pub taken_cmpct: Mutex<Vec<BlockHash>>,
    /// Mempool sequence at last tx INV (starts at 1).
    pub last_inv_sequence: AtomicU64,
    /// Queued tx INV hashes not yet sent.
    pub inv_to_send: AtomicU32,
    /// Last clock we considered for delayed tx INV (`0` = not initialized).
    pub last_tx_inv_now: AtomicU64,
    /// Set when mocktime jumps; next ping/tick announces mempool txs.
    pub tx_inv_requested: AtomicBool,
    /// Outstanding ping nonce (`0` = none).
    pub ping_nonce_sent: AtomicU64,
    /// When the last ping was sent, or `0` if never.
    pub ping_start_secs: AtomicU64,
    /// RPC `ping` queued a probe.
    pub ping_queued: AtomicBool,
    pub pingtime: Mutex<Option<f64>>,
    pub minping: Mutex<Option<f64>>,
    pub owner: std::sync::Weak<PeerHub>,
    pub recv: Mutex<HashMap<String, u64>>,
    pub sent: Mutex<HashMap<String, u64>>,
    pub last_block: AtomicU64,
    pub last_transaction: AtomicU64,
    pub minfeefilter_sat_kvb: AtomicU64,
    /// Last BIP133 feefilter we sent (`-1` = none yet).
    pub sent_feefilter_sat_kvb: AtomicI64,
    /// Shared with the TCP reader so split-header bytes count (`p2p_invalid_messages`).
    pub wire: Mutex<Option<crate::v2::WireBytes>>,
    /// Compact hashes whose first `blocktxn` reconstruct already failed.
    pub failed_cmpct: Mutex<HashSet<BlockHash>>,
    /// Heights of blocks we have requested from this peer and not yet received
    /// (`getpeerinfo.inflight`).
    pub inflight: Mutex<Vec<u32>>,
    pub block_download: Mutex<BlockDownload>,
    /// Session writer. RPC/accept flushes tx INVs onto this (`p2p_blocksonly`).
    pub out_tx: Mutex<Option<mpsc::UnboundedSender<PeerOut>>>,
    /// Addresses this peer may still send us (Core `m_addr_token_bucket`).
    pub addr_bucket: Mutex<crate::peer::AddrTokenBucket>,
    /// `getpeerinfo.addr_processed` / `addr_rate_limited`.
    pub addr_processed: AtomicU64,
    pub addr_rate_limited: AtomicU64,
    /// Unix seconds when this session was registered.
    pub connected_at: AtomicU64,
    /// Unix seconds the connection was created (Core `m_connected`). The
    /// post-VERSION row carries the connecting row's value.
    pub conntime: AtomicU64,
    /// Netgroup fixed at accept. Inbound eviction compares this integer
    /// and does not read asmap.
    pub netgroup: u64,
    /// Skip INV for mempool txs with `accept_gen < floor` (post-verack privacy).
    pub inv_gen_floor: AtomicU64,
    /// Age-INV due-log cursor (`due_secs`, `accept_gen`).
    pub age_inv_seen_due: AtomicU64,
    pub age_inv_seen_gen: AtomicU64,
    /// Writer-task abort — FIN via dropping the write half.
    pub writer_abort: Mutex<Option<tokio::task::AbortHandle>>,
    /// Whole session-task abort — drops reader+writer if the loop is stuck.
    pub session_abort: Mutex<Option<tokio::task::AbortHandle>>,
    /// Cloned std TCP fd for `Shutdown::Both` on `disconnectnode` so the far
    /// side sees EOF even if our session task is mid-frame.
    pub tcp_shutdown: Mutex<Option<std::net::TcpStream>>,
    /// VERSION+VERACK finished. Connecting rows stay false (`p2p_timeouts`).
    pub handshake_complete: AtomicBool,
    /// BIP324 transport finished. False while EARLY_KEY_RESPONSE / garbage.
    pub v2_transport_ready: AtomicBool,
    /// Peer sent BIP155 `sendaddrv2` (use `addrv2` for self-announce / GETADDR).
    pub wants_addrv2: AtomicBool,
    /// Peer sent BIP339 `wtxidrelay` (handshake, before VERACK).
    pub wtxid_relay: AtomicBool,
    /// Next self-announce unix seconds (`0` = never sent).
    pub next_local_addr_send: AtomicU64,
    /// VERSION timestamp (unix seconds; `0` on the connecting placeholder).
    pub version_timestamp: i64,
    /// VERSION protocol version (`0` on the connecting placeholder).
    pub version: u32,
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn tcp_has_peer_fin(tcp: &std::net::TcpStream) -> bool {
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
#[doc(hidden)]
pub fn tcp_has_peer_fin(_tcp: &std::net::TcpStream) -> bool {
    false
}

/// Hub clock (mock-aware), or system time once the hub is gone.
fn hub_secs(owner: &Weak<PeerHub>) -> u64 {
    owner
        .upgrade()
        .map(|h| h.now_secs())
        .unwrap_or_else(crate::v2::system_secs)
}

impl LivePeer {
    pub fn attach_wire(&self, wire: crate::v2::WireBytes) {
        *self.wire.lock().unwrap_or_else(|e| e.into_inner()) = Some(wire);
    }

    /// Socket counters stamped with the hub clock, attached to this row.
    pub fn new_wire(&self) -> crate::v2::WireBytes {
        let owner = self.owner.clone();
        let wire = crate::v2::WireBytes::with_clock(Arc::new(move || hub_secs(&owner)));
        self.attach_wire(wire.clone());
        wire
    }

    pub fn has_wire(&self) -> bool {
        self.wire
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn wire_load(&self, field: fn(&crate::v2::WireBytes) -> &Arc<AtomicU64>) -> u64 {
        self.wire
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|w| field(w).load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn raw_recv(&self) -> u64 {
        self.wire_load(|w| &w.recv)
    }

    pub fn raw_sent(&self) -> u64 {
        self.wire_load(|w| &w.sent)
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
        self.send_resume.notify_waiters();
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
        let services = crate::peer::local_service_flags(hub.is_pruned(), Some(&hub));
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

    #[doc(hidden)]
    pub fn take_writer_abort(&self) -> Option<tokio::task::AbortHandle> {
        self.writer_abort
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    #[doc(hidden)]
    pub fn take_session_abort(&self) -> Option<tokio::task::AbortHandle> {
        self.session_abort
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    #[doc(hidden)]
    pub fn take_tcp_shutdown(&self) -> Option<std::net::TcpStream> {
        self.tcp_shutdown
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    #[doc(hidden)]
    pub fn clear_out_tx(&self) {
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
        self.services & ServiceFlags::NETWORK.to_u64() != 0
    }

    /// NETWORK or NETWORK_LIMITED — this peer can serve blocks.
    pub fn can_serve_blocks(&self) -> bool {
        let net = ServiceFlags::NETWORK.to_u64();
        let lim = ServiceFlags::NETWORK_LIMITED.to_u64();
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

    pub fn try_cmpct_fill(&self, hash: BlockHash) -> bool {
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

    pub fn release_cmpct_taken(&self, hash: BlockHash) {
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

    #[doc(hidden)]
    pub fn release_all_cmpct(&self) {
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

    pub fn send_queued(&self) -> usize {
        self.send_queued.load(Ordering::Relaxed)
    }

    /// True after a reply has already pushed this peer past [`PEER_SEND_BUDGET`].
    pub fn send_over_budget(&self) -> bool {
        self.send_queued() > PEER_SEND_BUDGET
    }

    pub fn note_send_queued(&self, n: usize) {
        if n > 0 {
            self.send_queued.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Writer finished (or dropped) `n` queued bytes. Wakes a paused reader.
    pub fn note_send_written(&self, n: usize) {
        let prev = self
            .send_queued
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            })
            .unwrap_or(0);
        if prev.saturating_sub(n) <= PEER_SEND_BUDGET {
            self.send_resume.notify_waiters();
        }
    }

    /// The writer is done with one queued message of `bytes`. The serve slot
    /// is freed before the bytes: [`Self::note_send_written`] wakes a paused
    /// getdata tail, which must see the slot.
    pub fn note_out_written(&self, serve_slot: bool, bytes: usize) {
        if serve_slot {
            self.free_serve_slot();
        }
        self.note_send_written(bytes);
    }

    /// Saturating, so a double free cannot wrap to `usize::MAX`.
    pub fn free_serve_slot(&self) {
        let _ = self
            .serve_inflight
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Reader pause. Registers the waiter before the budget check.
    pub async fn wait_send_budget(&self) {
        loop {
            let notified = self.send_resume.notified();
            if !self.send_over_budget() {
                return;
            }
            notified.await;
        }
    }

    /// Room for the next getdata item: the writer is under
    /// [`PEER_SEND_BUDGET`] and holds fewer than [`crate::MAX_SERVE_BLOCKS`]
    /// served bodies. The session reader is the only task that queues
    /// served bodies, so room seen here still holds when it queues.
    pub fn has_serve_room(&self) -> bool {
        !self.send_over_budget()
            && self.serve_inflight.load(Ordering::SeqCst) < crate::MAX_SERVE_BLOCKS
    }

    /// Getdata pause, Core `fPauseSend`: a paused getdata tail resumes once
    /// [`Self::has_serve_room`]. `false` once the session is told to
    /// disconnect or its writer (`out`'s receiver) is gone.
    pub async fn wait_serve_room(&self, out: &mpsc::UnboundedSender<PeerOut>) -> bool {
        loop {
            let notified = self.send_resume.notified();
            if self.stop.load(Ordering::SeqCst) {
                return false;
            }
            if self.has_serve_room() {
                return true;
            }
            tokio::select! {
                () = notified => {}
                () = out.closed() => return false,
            }
        }
    }

    /// First inbound `getaddr` wins. Later ones are ignored.
    pub fn take_getaddr(&self) -> bool {
        !self.getaddr_answered.swap(true, Ordering::Relaxed)
    }

    pub fn attach_out(&self, tx: mpsc::UnboundedSender<PeerOut>) {
        *self.out_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    /// Core `m_addr_token_bucket += MAX_ADDR_TO_SEND` on `getaddr`: the
    /// reply may exceed the bucket cap.
    pub(crate) fn credit_getaddr_reply(&self) {
        self.addr_bucket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .credit(crate::peer::MAX_ADDR_TO_SEND);
    }

    /// How many of the `want` addresses in one message this peer may have
    /// processed (learned and relayed). The rest count as rate limited. A
    /// peer with the `addr` permission spends tokens but is never limited.
    pub fn take_addr_tokens(&self, want: usize, now_ms: u64) -> usize {
        let took = self
            .addr_bucket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(want, now_ms);
        let allow = if self
            .net_perm_flags()
            .has(crate::net_permissions::NetPermissionFlags::ADDR)
        {
            want
        } else {
            took
        };
        self.addr_processed
            .fetch_add(allow as u64, Ordering::Relaxed);
        self.addr_rate_limited
            .fetch_add((want - allow) as u64, Ordering::Relaxed);
        allow
    }

    pub fn writer(&self) -> Option<mpsc::UnboundedSender<PeerOut>> {
        self.out_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Core `m_last_block_time`: stamped only when a block from this peer
    /// is new to us, not for one we already had.
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

    pub fn note_sent_feefilter(&self, sat_kvb: i64) {
        self.sent_feefilter_sat_kvb
            .store(sat_kvb, Ordering::Relaxed);
    }

    pub fn sent_feefilter_sat_kvb(&self) -> i64 {
        self.sent_feefilter_sat_kvb.load(Ordering::Relaxed)
    }

    pub fn clock_now(&self) -> u64 {
        hub_secs(&self.owner)
    }

    pub fn connected_at(&self) -> u64 {
        self.connected_at.load(Ordering::Relaxed)
    }

    pub fn netgroup(&self) -> u64 {
        self.netgroup
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

    /// Core `BlockRequested`: the first block in flight from this peer
    /// starts its download window. A re-ask of a block already in flight
    /// keeps its place and does not restart the window.
    pub fn note_blocks_requested(&self, hashes: &[BlockHash]) {
        let now = self.clock_now();
        let mut d = self
            .block_download
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if d.since.is_none() {
            d.since = Some(now);
            if let Some(h) = self.peer_hub() {
                h.peers_downloading_from.fetch_add(1, Ordering::Relaxed);
            }
        }
        for h in hashes {
            if !d.queue.contains(h) {
                d.queue.push_back(*h);
            }
        }
    }

    /// Core `RemoveBlockRequest`: once the oldest block in flight is gone
    /// the window restarts at `now`, and once none is left it ends.
    pub fn sync_block_download(&self, now: u64, in_flight: impl Fn(&BlockHash) -> bool) {
        let mut d = self
            .block_download
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(since) = d.since else {
            return;
        };
        let mut front_left = false;
        while d.queue.front().is_some_and(|h| !in_flight(h)) {
            d.queue.pop_front();
            front_left = true;
        }
        if d.queue.is_empty() {
            drop(d);
            self.end_block_download();
        } else if front_left {
            d.since = Some(since.max(now));
        }
    }

    pub fn end_block_download(&self) {
        let mut d = self
            .block_download
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        d.queue.clear();
        if d.since.take().is_some() {
            if let Some(h) = self.peer_hub() {
                h.peers_downloading_from.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Core's block download timeout: the oldest block in flight, once the
    /// window has been open longer than one block interval plus half of one
    /// per other peer we are downloading from.
    pub fn block_download_timed_out(&self, now: u64, block_interval: u64) -> Option<BlockHash> {
        let d = self
            .block_download
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let since = d.since?;
        let downloading = self
            .peer_hub()
            .map_or(1, |h| h.peers_downloading_from.load(Ordering::Relaxed))
            .max(1) as u64;
        let timeout = block_interval.saturating_mul(downloading + 1) / 2;
        if now > since.saturating_add(timeout) {
            d.queue.front().copied()
        } else {
            None
        }
    }

    /// Core's ping timeout, which bitcoin/bitcoin#36080 moved out of
    /// `MaybeSendPing`. The caller suspends this while the peer still has
    /// blocks in flight. The last block it delivered leaves it a minute to
    /// answer. Returns the seconds waited.
    pub fn ping_timeout(&self, now_secs: u64) -> Option<f64> {
        const TIMEOUT_INTERVAL: u64 = 20 * 60;
        const POST_BLOCK_PONG_GRACE: u64 = 60;
        let last_block = self.last_block.load(Ordering::Relaxed);
        if now_secs <= last_block.saturating_add(POST_BLOCK_PONG_GRACE) {
            return None;
        }
        // Core `RunInactivityChecks`: no ping timeout until `-peertimeout`
        // has passed since connect (both on the mockable clock).
        let inactivity_checks = self.peer_hub().is_none_or(|h| {
            now_secs
                > self
                    .connected_at_secs()
                    .saturating_add(h.peer_timeout_secs())
        });
        let nonce = self.ping_nonce_sent.load(Ordering::Relaxed);
        let start = self.ping_start_secs.load(Ordering::Relaxed);
        (inactivity_checks && nonce != 0 && now_secs > start.saturating_add(TIMEOUT_INTERVAL))
            .then(|| now_secs.saturating_sub(start) as f64)
    }

    /// Core `MaybeSendPing`: the nonce of an RPC-queued ping, or of the
    /// interval probe once the last ping was answered.
    ///
    /// Never-sent peers keep `ping_start_secs == 0`, so any `now_secs` above
    /// 120 is interval-due (same comparison as a last ping at Unix epoch 0).
    pub fn take_ping_send(&self, now_secs: u64) -> Option<u64> {
        const PING_INTERVAL: u64 = 120;
        let nonce = self.ping_nonce_sent.load(Ordering::Relaxed);
        let start = self.ping_start_secs.load(Ordering::Relaxed);
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
        Some(n)
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

    pub fn ping_rpc_fields(&self, now_secs: u64) -> (Option<f64>, Option<f64>, Option<f64>) {
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

    #[doc(hidden)]
    pub fn snapshot(&self, now_secs: u64) -> PeerInfo {
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
            addr_processed: self.addr_processed.load(Ordering::Relaxed),
            addr_rate_limited: self.addr_rate_limited.load(Ordering::Relaxed),
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
            version: self.version,
            conntime: self.conntime.load(Ordering::Relaxed),
            last_send: self.wire_load(|w| &w.last_sent),
            last_recv: self.wire_load(|w| &w.last_recv),
        }
    }
}

/// Core `m_downloading_since` (`None` while nothing is in flight) and the
/// request order of `vBlocksInFlight` for one peer.
#[doc(hidden)]
#[derive(Default)]
pub struct BlockDownload {
    since: Option<u64>,
    queue: VecDeque<BlockHash>,
}

#[doc(hidden)]
pub fn rand_ping_nonce() -> u64 {
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
#[doc(hidden)]
pub fn acct_bytes(cmd: &str, payload: u64) -> u64 {
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
    /// `getpeerinfo.addr_processed`: addresses not dropped by the rate limit.
    pub addr_processed: u64,
    /// `getpeerinfo.addr_rate_limited`: addresses the rate limit dropped.
    pub addr_rate_limited: u64,
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
    /// VERSION protocol version (`0` before handshake).
    pub version: u32,
    /// Unix seconds the connection was created.
    pub conntime: u64,
    /// Unix seconds of the last byte written (`0` = never).
    pub last_send: u64,
    /// Unix seconds of the last byte read (`0` = never).
    pub last_recv: u64,
}

/// In-memory misbehavior key. Clearnet and CJDNS are the IP. Onion and I2P
/// are the 32-byte identity. The port is not part of the key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscourageKey {
    Ip(IpAddr),
    Onion([u8; 32]),
    I2p([u8; 32]),
}

impl DiscourageKey {
    pub fn from_net(net: crate::NetAddr) -> Option<Self> {
        match net {
            crate::NetAddr::Onion { pk, .. } => Some(Self::Onion(pk)),
            crate::NetAddr::I2p { dest, .. } => Some(Self::I2p(dest)),
            crate::NetAddr::Cjdns { ip, .. } => Some(Self::Ip(IpAddr::V6(ip))),
            crate::NetAddr::Ip(sock) => {
                let ip = sock.ip();
                if ip_skips_discourage(ip) {
                    None
                } else {
                    Some(Self::Ip(ip))
                }
            }
        }
    }
}

#[doc(hidden)]
pub fn ip_skips_discourage(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.octets()[0] == 0,
        IpAddr::V6(v) => v.is_loopback(),
    }
}

#[allow(clippy::type_complexity)] // session table: live peers, manual hosts, dials
/// Thread-safe session table + addnode remembered addrs.
pub struct PeerHub {
    pub next_id: AtomicU64,
    pub live: RwLock<HashMap<u64, Arc<LivePeer>>>,
    /// One tx-relay inbound count-and-evict at a time, so two newcomers
    /// cannot both claim one victim.
    tx_relay_room: Mutex<()>,
    pub added: Mutex<HashSet<crate::NetAddr>>,
    /// Raw `addnode add` strings. Re-resolved on each redial so a Warnet name
    /// that is not in DNS yet is kept.
    pub manual_hosts: Mutex<HashSet<String>>,
    /// `--connect` hostnames that are not a [`crate::NetAddr`] (clearnet DNS).
    pub connect_hosts: Mutex<Vec<String>>,
    /// `--connect` targets given as a [`crate::NetAddr`] (IP, onion, I2P, CJDNS).
    pub connect_addrs: Mutex<Vec<crate::NetAddr>>,
    /// `--trust-peer` address. `addnode` of anyone else fails.
    trust_addr: Mutex<Option<crate::NetAddr>>,
    /// `--trust-peer` DNS host (`host:port`).
    trust_host: Mutex<Option<String>>,
    /// One current socket per hostname, for `--trust-peer` and `--connect`.
    host_sockets: Mutex<HashMap<String, SocketAddr>>,
    /// Outbound dials still before session registration, by target. The
    /// redial pass skips these, so a slow connect is not stacked every 2 s.
    pub dials_in_flight: Arc<Mutex<HashMap<String, InFlightCount>>>,
    /// Addr-fetch `getaddr` replies (more than one address) learned into the
    /// book. A self-announce does not count.
    addrfetch_replies: AtomicU64,
    /// One stored permit when an addr-fetch reply is learned, so tip-follow
    /// can dial a book that was empty at catch-up.
    addrfetch_learned: Notify,
    /// Network P2P port used when a remembered host omits `:port`. `0` = unset.
    pub connect_default_port: AtomicU16,
    pub dial_tx: Mutex<Option<mpsc::UnboundedSender<DialRequest>>>,
    /// Peers we asked to send us compact (BIP152 HB, max 3, prefer outbound).
    pub hb_selected: Mutex<Vec<u64>>,
    /// `setmocktime` seconds; `0` means wall clock.
    pub mock_now: AtomicU64,
    /// Bumped by [`Self::set_mock_now`] so a live session runs its heartbeat
    /// on that call. A `watch` keeps the jump if it lands between waits.
    session_heartbeat: watch::Sender<u64>,
    /// Times a session has entered `on_heartbeat`. The wait, not the contract.
    heartbeat_laps: AtomicU64,
    /// Outbound version nonces registered. Stays after the nonce is cleared.
    outbound_attempts: AtomicU64,
    /// Refill and stale-tip passes. The wait, not the peer-row contract.
    pass_skipped_pinned: AtomicU64,
    pass_not_stagnant: AtomicU64,
    pass_skipped_seeds_off: AtomicU64,
    pass_rotated: AtomicU64,
    pass_no_spare: AtomicU64,
    /// Count of sessions currently in headers-sync.
    pub headers_sync_peers: AtomicU64,
    /// Last inv hash that started headers sync with a not-yet-sync peer.
    pub last_inv_headers_sync: Mutex<Option<BlockHash>>,
    /// Trusted inbound — do not disconnect a stalling headers-sync peer.
    pub noban: AtomicBool,
    /// Accept txs even when the node is blocks-only.
    pub relay_perm: AtomicBool,
    /// No outbound `feefilter` (relay all).
    pub forcerelay_perm: AtomicBool,
    /// Parallel compact-fill slots per block: up to 2 inbound + 1 outbound.
    pub cmpct_fills: Mutex<HashMap<BlockHash, (u8, bool)>>,
    /// Version nonces of outbound sessions still in handshake (Core self-connect).
    pub pending_outbound_nonces: Mutex<HashSet<u64>>,
    /// Shared addrman for GetAddr responses (optional until node wires it).
    pub addrman: Mutex<Option<std::sync::Arc<Mutex<crate::seeds::AddrMan>>>>,
    /// Per-listen GetAddr cache: canonical bind + addrv2 → (cached_at, addrs).
    pub addr_response_cache: Mutex<HashMap<(SocketAddr, bool), (u64, Vec<(u32, crate::NetAddr)>)>>,
    /// VERSION/VERACK handshake timeout seconds. Default 60.
    pub peer_timeout_secs: AtomicU64,
    /// Core `m_peers_downloading_from`: sessions with a block in flight.
    pub peers_downloading_from: AtomicUsize,
    /// Addresses we advertise (`getnetworkinfo.localaddresses`).
    pub external_ips: Mutex<Vec<IpAddr>>,
    pub wallet_onions: Mutex<Vec<(String, u16)>>,
    pub p2p_onion: Mutex<Option<(String, u16)>>,
    pub p2p_i2p: Mutex<Option<crate::NetAddr>>,
    /// P2P listen port used with advertised external IPs.
    pub listen_port: AtomicU16,
    /// Core `-discover`. Off: never self-announce, even with `--external-ip`.
    pub discover: AtomicBool,
    /// Clearnet P2P bind (not onion-only loopback). Needed to gossip `--external-ip`.
    pub clearnet_listen: AtomicBool,
    pub cjdns_reachable: AtomicBool,
    proxies: Mutex<crate::socks::NetProxies>,
    /// Core `-i2psam`: I2P rows may enter addrman. Off, they are still relayed.
    i2p_reachable: AtomicBool,
    pruned: AtomicBool,
    asmap: Mutex<Option<Arc<crate::asmap::AsMap>>>,
    /// Tip-mode mempool for Core `EraseForPeer` on disconnect.
    pub mempool: Mutex<Option<Weak<crate::tx_relay::MempoolHub>>>,
    /// Core `-whitelist` / `-whitebind` grants (`getpeerinfo.permissions`).
    pub net_perms: Mutex<crate::net_permissions::NetPermTable>,
    /// Misbehavior keys → unix second the refusal ends. In memory only.
    pub discouraged_addrs: Mutex<HashMap<DiscourageKey, u64>>,
    /// Netgroup → unix second a slot-loss refusal ends.
    pub discouraged_groups: Mutex<HashMap<u64, u64>>,
    /// Rate-limit disconnect key → unix second its strike ends.
    pub rate_strikes: Mutex<HashMap<DiscourageKey, u64>>,
    /// This node's version messages include `NODE_COMPACT_FILTERS`.
    ///
    /// Per hub, not process-wide: one process runs many nodes in tests, and
    /// only the node whose filters reached the tip may advertise the bit.
    pub compact_filters: AtomicBool,
}

/// Why one outbound refill or stale-tip pass declined, or that it rotated
/// one full-relay peer. The count is only the wait.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundPass {
    SkippedPinned,
    NotStagnant,
    SkippedSeedsOff,
    Rotated,
    NoSpare,
}

/// Per-kind totals from [`PeerHub::note_outbound_pass`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboundPassCounts {
    pub skipped_pinned: u64,
    pub not_stagnant: u64,
    pub skipped_seeds_off: u64,
    pub rotated: u64,
    pub no_spare: u64,
}

#[doc(hidden)]
pub fn canonical_bind(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::from((v4, v6.port())))
            .unwrap_or(addr),
        v4 => v4,
    }
}

#[doc(hidden)]
pub fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[doc(hidden)]
pub fn addr_sample_seed(bind: SocketAddr, now: u64) -> u64 {
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

#[doc(hidden)]
pub fn ip_is_advertisable(ip: &IpAddr, cjdns_reachable: bool) -> bool {
    if let IpAddr::V6(v) = ip {
        if crate::netaddr::is_cjdns_ip(*v) {
            return cjdns_reachable;
        }
    }
    !crate::netaddr::clearnet_unroutable(*ip)
}

impl PeerHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(0),
            live: RwLock::new(HashMap::new()),
            tx_relay_room: Mutex::new(()),
            added: Mutex::new(HashSet::new()),
            manual_hosts: Mutex::new(HashSet::new()),
            connect_hosts: Mutex::new(Vec::new()),
            connect_addrs: Mutex::new(Vec::new()),
            trust_addr: Mutex::new(None),
            trust_host: Mutex::new(None),
            host_sockets: Mutex::new(HashMap::new()),
            dials_in_flight: Arc::new(Mutex::new(HashMap::new())),
            addrfetch_replies: AtomicU64::new(0),
            addrfetch_learned: Notify::new(),
            connect_default_port: AtomicU16::new(0),
            dial_tx: Mutex::new(None),
            hb_selected: Mutex::new(Vec::new()),
            mock_now: AtomicU64::new(0),
            session_heartbeat: watch::channel(0).0,
            heartbeat_laps: AtomicU64::new(0),
            outbound_attempts: AtomicU64::new(0),
            pass_skipped_pinned: AtomicU64::new(0),
            pass_not_stagnant: AtomicU64::new(0),
            pass_skipped_seeds_off: AtomicU64::new(0),
            pass_rotated: AtomicU64::new(0),
            pass_no_spare: AtomicU64::new(0),
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
            peers_downloading_from: AtomicUsize::new(0),
            external_ips: Mutex::new(Vec::new()),
            wallet_onions: Mutex::new(Vec::new()),
            p2p_onion: Mutex::new(None),
            p2p_i2p: Mutex::new(None),
            listen_port: AtomicU16::new(0),
            discover: AtomicBool::new(true),
            clearnet_listen: AtomicBool::new(true),
            cjdns_reachable: AtomicBool::new(false),
            proxies: Mutex::new(crate::socks::NetProxies::default()),
            i2p_reachable: AtomicBool::new(false),
            pruned: AtomicBool::new(false),
            asmap: Mutex::new(None),
            mempool: Mutex::new(None),
            net_perms: Mutex::new(crate::net_permissions::NetPermTable::default()),
            discouraged_addrs: Mutex::new(HashMap::new()),
            discouraged_groups: Mutex::new(HashMap::new()),
            rate_strikes: Mutex::new(HashMap::new()),
            compact_filters: AtomicBool::new(false),
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

    pub fn set_proxies(&self, proxies: crate::socks::NetProxies) {
        *self.proxies.lock().unwrap_or_else(|e| e.into_inner()) = proxies;
    }

    pub fn proxies(&self) -> crate::socks::NetProxies {
        self.proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Core sets `NET_I2P` reachable only when `-i2psam` is configured.
    pub fn set_i2p_reachable(&self, on: bool) {
        self.i2p_reachable.store(on, Ordering::Relaxed);
        let am = self
            .addrman
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(am) = am {
            am.lock()
                .unwrap_or_else(|e| e.into_inner())
                .set_i2p_reachable(on);
        }
    }

    pub fn set_pruned(&self, on: bool) {
        self.pruned.store(on, Ordering::Relaxed);
    }

    pub fn is_pruned(&self) -> bool {
        self.pruned.load(Ordering::Relaxed)
    }

    /// Version, feeler, addr, and `getnetworkinfo` include `NODE_COMPACT_FILTERS`
    /// after this node's filters reach the tip.
    pub fn set_compact_filters_service(&self, on: bool) {
        self.compact_filters.store(on, Ordering::Release);
    }

    pub fn compact_filters_advertised(&self) -> bool {
        self.compact_filters.load(Ordering::Acquire)
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
    ///
    /// Copies the I2P reachability bit onto that book. `learn_addrv2` stores
    /// only rows the book will dial.
    /// How many addr-fetch `getaddr` replies have been learned so far.
    pub fn addrfetch_replies(&self) -> u64 {
        self.addrfetch_replies.load(Ordering::Acquire)
    }

    pub(crate) fn note_addrfetch_reply(&self) {
        self.addrfetch_replies.fetch_add(1, Ordering::Release);
        self.addrfetch_learned.notify_one();
    }

    /// Wakes when an addr-fetch `getaddr` reply of more than one address is learned.
    /// Tip-follow dials a book that was empty at catch-up.
    pub fn addrfetch_learned(&self) -> &Notify {
        &self.addrfetch_learned
    }

    pub fn set_addrman(&self, am: std::sync::Arc<Mutex<crate::seeds::AddrMan>>) {
        let on = self.i2p_reachable.load(Ordering::Relaxed);
        am.lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_i2p_reachable(on);
        *self.addrman.lock().unwrap_or_else(|e| e.into_inner()) = Some(am);
    }

    /// Learn IPv4/IPv6/Tor v3/I2P/CJDNS rows from BIP155 `addrv2`.
    ///
    /// Rows for a net this process cannot dial are not stored. Unroutable
    /// clearnet is not stored. Relaying is separate and drops the same rows.
    pub fn learn_addrv2(&self, list: &[bitcoin::p2p::address::AddrV2Message]) {
        let g = self.addrman.lock().unwrap_or_else(|e| e.into_inner());
        let Some(am) = g.as_ref() else {
            return;
        };
        let mut book = am.lock().unwrap_or_else(|e| e.into_inner());
        for a in list {
            if let Some(addr) = crate::NetAddr::from_addrv2(a) {
                if crate::netaddr::netaddr_unroutable_gossip(addr) {
                    continue;
                }
                book.add_learned_addr(addr, crate::seeds::MAX_ADDR_MAN);
            }
        }
    }

    /// Core GetAddr reply: per-listen cache (24h) of
    /// [`crate::peer::MAX_ADDR_TO_SEND`] / [`crate::peer::MAX_PCT_ADDR_TO_SEND`]
    /// of addrman. `v2` includes onion / i2p / CJDNS; v1 ADDR is clearnet `Ip`.
    pub fn addr_response_net(&self, bind: SocketAddr, v2: bool) -> Vec<(u32, crate::NetAddr)> {
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
            .filter(|a| !crate::netaddr::netaddr_unroutable_gossip(*a))
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
        let services = crate::peer::local_service_flags(self.is_pruned(), Some(self));
        self.addr_response_net(bind, false)
            .into_iter()
            .filter_map(|(t, a)| {
                let crate::NetAddr::Ip(s) = a else {
                    return None;
                };
                Some((t, bitcoin::p2p::address::Address::new(&s, services)))
            })
            .collect()
    }

    /// Core: register local version nonce while an outbound handshake is open.
    pub fn note_outbound_nonce(&self, nonce: u64) {
        self.outbound_attempts.fetch_add(1, Ordering::Release);
        self.pending_outbound_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce);
    }

    /// Outbound handshakes that registered a version nonce.
    #[doc(hidden)]
    pub fn outbound_attempts(&self) -> u64 {
        self.outbound_attempts.load(Ordering::Acquire)
    }

    /// How many times a live session has entered its heartbeat.
    #[doc(hidden)]
    pub fn heartbeat_laps(&self) -> u64 {
        self.heartbeat_laps.load(Ordering::Acquire)
    }

    pub(crate) fn note_heartbeat_lap(&self) {
        self.heartbeat_laps.fetch_add(1, Ordering::Release);
    }

    /// One refill or stale-tip decision. Callers in the tip-follow loop.
    #[doc(hidden)]
    pub fn note_outbound_pass(&self, kind: OutboundPass) {
        let slot = match kind {
            OutboundPass::SkippedPinned => &self.pass_skipped_pinned,
            OutboundPass::NotStagnant => &self.pass_not_stagnant,
            OutboundPass::SkippedSeedsOff => &self.pass_skipped_seeds_off,
            OutboundPass::Rotated => &self.pass_rotated,
            OutboundPass::NoSpare => &self.pass_no_spare,
        };
        slot.fetch_add(1, Ordering::Release);
    }

    /// How many times each outbound pass has been recorded.
    #[doc(hidden)]
    pub fn outbound_pass_counts(&self) -> OutboundPassCounts {
        OutboundPassCounts {
            skipped_pinned: self.pass_skipped_pinned.load(Ordering::Acquire),
            not_stagnant: self.pass_not_stagnant.load(Ordering::Acquire),
            skipped_seeds_off: self.pass_skipped_seeds_off.load(Ordering::Acquire),
            rotated: self.pass_rotated.load(Ordering::Acquire),
            no_spare: self.pass_no_spare.load(Ordering::Acquire),
        }
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

    /// Core `fPreferredDownload` counts `manual` (`addnode`, `--connect`)
    /// outbound peers, so a node dialled only that way can still replace a
    /// stalling headers-sync peer.
    #[doc(hidden)]
    pub fn is_preferred_download(p: &LivePeer) -> bool {
        matches!(
            p.conn_type,
            PeerConnType::OutboundFullRelay | PeerConnType::BlockRelay | PeerConnType::Manual
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

    #[doc(hidden)]
    pub fn end_headers_sync(&self, peer: &LivePeer) {
        if peer.sync_started.swap(false, Ordering::Relaxed) {
            self.headers_sync_peers.fetch_sub(1, Ordering::Relaxed);
            peer.headers_sync_timeout.store(0, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn check_headers_sync_timeouts(&self, now: u64) {
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

    /// One day. Not a configuration flag.
    pub const DISCOURAGE_TTL_SECS: u64 = 24 * 60 * 60;
    /// Shorter than [`Self::DISCOURAGE_TTL_SECS`]. A netgroup that just lost
    /// an inbound slot cannot refill it immediately.
    pub const NETGROUP_SLOT_WAIT_SECS: u64 = 10 * 60;
    /// The in-memory set does not grow past this many addresses.
    pub const DISCOURAGE_CAP: usize = 10_000;
    /// A rate-limit strike counts toward the next one for this long.
    pub const RATE_STRIKE_SECS: u64 = 60 * 60;

    #[doc(hidden)]
    pub fn sweep_discouraged(&self, now: u64) {
        self.discouraged_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, until| *until > now);
        self.discouraged_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, until| *until > now);
    }

    /// Record `ip` until [`Self::DISCOURAGE_TTL_SECS`] from now. At the cap a
    /// new address is ignored; an address already stored is refreshed.
    #[cfg(debug_assertions)]
    pub fn note_misbehavior_addr(&self, ip: IpAddr) {
        self.note_misbehavior_key(DiscourageKey::Ip(ip));
    }

    pub fn note_misbehavior_key(&self, key: DiscourageKey) {
        let now = self.now_secs();
        let until = now.saturating_add(Self::DISCOURAGE_TTL_SECS);
        let mut g = self
            .discouraged_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&key) && g.len() >= Self::DISCOURAGE_CAP {
            return;
        }
        g.insert(key, until);
    }

    /// True when `ip` still has a strike from an earlier rate-limit
    /// disconnect; that strike is spent. Otherwise records one for
    /// [`Self::RATE_STRIKE_SECS`]. Expired strikes are dropped here. At
    /// [`Self::DISCOURAGE_CAP`] a new address is not recorded.
    pub fn note_rate_strike(&self, key: DiscourageKey) -> bool {
        let now = self.now_secs();
        let mut g = self.rate_strikes.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, until| *until > now);
        if g.remove(&key).is_some() {
            return true;
        }
        if g.len() < Self::DISCOURAGE_CAP {
            g.insert(key, now.saturating_add(Self::RATE_STRIKE_SECS));
        }
        false
    }

    /// The netgroup that just lost an inbound slot waits
    /// [`Self::NETGROUP_SLOT_WAIT_SECS`].
    pub fn note_slot_evict(&self, group: u64) {
        let until = self
            .now_secs()
            .saturating_add(Self::NETGROUP_SLOT_WAIT_SECS);
        let mut g = self
            .discouraged_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&group) && g.len() >= Self::DISCOURAGE_CAP {
            return;
        }
        g.insert(group, until);
    }

    /// Misbehavior key for this net. A slot-eviction netgroup stays inbound-only.
    pub fn net_discouraged(&self, net: crate::NetAddr) -> bool {
        DiscourageKey::from_net(net).is_some_and(|key| self.key_refused(key))
    }

    #[doc(hidden)]
    pub fn key_refused(&self, key: DiscourageKey) -> bool {
        let now = self.now_secs();
        self.sweep_discouraged(now);
        self.discouraged_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&key)
    }

    /// True when this inbound address or its accept-time netgroup is still
    /// refused. Expired rows are dropped here, which is the only sweep.
    pub fn inbound_discouraged(&self, addr: SocketAddr) -> bool {
        // `key_refused` drops expired rows.
        if self.key_refused(DiscourageKey::Ip(addr.ip())) {
            return true;
        }
        let group = crate::eviction::eviction_netgroup(addr);
        self.discouraged_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&group)
            .is_some()
    }

    pub fn now_secs(&self) -> u64 {
        let mock = self.mock_now.load(Ordering::Acquire);
        if mock != 0 {
            return mock;
        }
        crate::v2::system_secs()
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
        self.session_heartbeat
            .send_modify(|n| *n = n.wrapping_add(1));
    }

    pub(crate) fn subscribe_session_heartbeat(&self) -> watch::Receiver<u64> {
        self.session_heartbeat.subscribe()
    }

    /// Session 50ms heartbeat: replace a stalling initial-headers-sync peer.
    pub fn on_session_heartbeat(&self) {
        let now = self.now_secs();
        self.check_headers_sync_timeouts(now);
        self.check_handshake_timeouts(now);
    }

    pub fn handshake_timed_out(&self, peer: &LivePeer, now: u64) -> bool {
        if peer.handshake_complete() {
            return false;
        }
        now.saturating_sub(peer.connected_at_secs()) >= self.peer_timeout_secs()
    }

    pub fn check_handshake_timeouts(&self, now: u64) {
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

    pub fn dial_ready(&self) -> Result<DialReady<'_>, String> {
        let g = self.dial_tx.lock().unwrap_or_else(|e| e.into_inner());
        let tx = g
            .as_ref()
            .cloned()
            .ok_or_else(|| "no dialer attached".to_string())?;
        Ok(DialReady { hub: self, tx })
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
            version: 0,
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
        self.insert_live(self.new_live(id, endpoint, ver, inbound, conn_type))
    }

    /// The row that replaces connecting row `from` after VERSION, under the
    /// same id. It keeps `from`'s `conntime`, negotiated flags and socket
    /// counters, and is complete before it is in the table, so no reader
    /// sees it half set.
    pub fn register_handshaken_net(
        self: &Arc<Self>,
        from: &LivePeer,
        endpoint: PeerEndpoint,
        ver: &VersionMessage,
        conn_type: PeerConnType,
        wire: crate::v2::WireBytes,
    ) -> Arc<LivePeer> {
        let peer = self.new_live(from.id, endpoint, ver, from.inbound, conn_type);
        peer.conntime
            .store(from.conntime.load(Ordering::Relaxed), Ordering::Relaxed);
        if from.wants_addrv2() {
            peer.set_wants_addrv2();
        }
        if from.wtxid_relay() {
            peer.set_wtxid_relay();
        }
        peer.note_recv("version", 100);
        peer.note_recv("verack", 0);
        peer.attach_wire(wire);
        peer.mark_handshake_complete();
        self.unregister(from.id);
        self.insert_live(peer)
    }

    fn new_live(
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
        let services = ver.services.to_u64();
        let connected_at = self.now_secs();
        Arc::new(LivePeer {
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
            sent_feefilter_sat_kvb: AtomicI64::new(-1),
            wire: Mutex::new(None),
            failed_cmpct: Mutex::new(HashSet::new()),
            inflight: Mutex::new(Vec::new()),
            block_download: Mutex::new(BlockDownload::default()),
            out_tx: Mutex::new(None),
            addr_bucket: Mutex::new(crate::peer::AddrTokenBucket::new(
                connected_at.saturating_mul(1000),
            )),
            addr_processed: AtomicU64::new(0),
            addr_rate_limited: AtomicU64::new(0),
            connected_at: AtomicU64::new(connected_at),
            conntime: AtomicU64::new(connected_at),
            netgroup: crate::eviction::eviction_netgroup(endpoint.addr),
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
            version: ver.version,
        })
    }

    fn insert_live(&self, peer: Arc<LivePeer>) -> Arc<LivePeer> {
        let id = peer.id;
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
            p.end_block_download();
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
                if tx
                    .send(PeerOut::Msg(NetworkMessage::FeeFilter(sat_kvb)))
                    .is_ok()
                {
                    s.note_sent_feefilter(sat_kvb);
                }
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

    #[doc(hidden)]
    pub fn dial_manual_net(&self, addr: &crate::NetAddr) -> Result<(), String> {
        self.dial_manual_target(DialTarget::from_net(*addr))
    }

    /// Core `AlreadyConnectedToHost` / `AlreadyConnectedToAddressPort`:
    /// `addnode` and the redial pass open no second session to an endpoint
    /// that is connected or still dialling, and the RPC still succeeds.
    #[doc(hidden)]
    pub fn dial_manual_target(&self, target: DialTarget) -> Result<(), String> {
        let ready = self.dial_ready()?;
        self.dial_manual_ready(&ready.tx, target)
    }

    fn dial_manual_ready(
        &self,
        tx: &mpsc::UnboundedSender<DialRequest>,
        target: DialTarget,
    ) -> Result<(), String> {
        self.trust_allows_target(&target)?;
        // Claim before the live check: a dial registers its session before
        // it drops its claim, so no window shows the endpoint as neither.
        let Some(claim) = self.claim_dial(&target) else {
            return Ok(());
        };
        if self.is_target_live(&target) {
            return Ok(());
        }
        self.enqueue_dial(tx, target, PeerConnType::Manual, Some(claim))
    }

    pub fn addnode_net(&self, addr: crate::NetAddr, cmd: &str) -> Result<(), String> {
        let ready = self.dial_ready()?;
        self.trust_allows_spec(&addr.to_string())?;
        match cmd {
            "onetry" => self.dial_manual_ready(&ready.tx, DialTarget::from_net(addr)),
            "add" => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(addr);
                let _ = self.dial_manual_ready(&ready.tx, DialTarget::from_net(addr));
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
        let ready = self.dial_ready()?;
        ready.addnode_host(node, cmd, default_port)
    }

    fn addnode_host_ready(
        &self,
        tx: &mpsc::UnboundedSender<DialRequest>,
        node: &str,
        cmd: &str,
        default_port: u16,
    ) -> Result<(), String> {
        self.note_default_port(default_port);
        self.trust_allows_spec(node)?;
        match cmd {
            "onetry" => self.dial_resolved_ready(tx, node),
            "add" => {
                self.manual_hosts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(node.to_string());
                let _ = self.dial_resolved_ready(tx, node);
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

    /// `--connect` targets that parse as a [`crate::NetAddr`]. The redial pass
    /// dials each one that has no live session, as Core keeps reconnecting
    /// every `-connect` address.
    pub fn set_connect_addrs(&self, addrs: Vec<crate::NetAddr>) {
        *self.connect_addrs.lock().unwrap_or_else(|e| e.into_inner()) = addrs;
    }

    /// Pin the sole peer. Further dials and `addnode` of any other address fail.
    pub fn set_trust_peer(&self, addr: Option<crate::NetAddr>, host: Option<String>) {
        if let Some(prev) = self
            .trust_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if let Some(key) = self.host_key(&prev) {
                self.host_sockets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
            }
        }
        *self.trust_addr.lock().unwrap_or_else(|e| e.into_inner()) = addr;
        *self.trust_host.lock().unwrap_or_else(|e| e.into_inner()) = host;
    }

    /// Remember the socket the trusted hostname resolved to. A later answer
    /// replaces that socket.
    pub fn note_trust_resolved(&self, addr: SocketAddr) {
        let Some(host) = self
            .trust_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return;
        };
        self.note_host_resolved(&host, addr);
    }

    fn host_key(&self, node: &str) -> Option<String> {
        ensure_host_port(node, self.default_port_opt())
            .ok()
            .map(|key| key.to_ascii_lowercase())
    }

    /// Store `addr` as the current socket for `host`. Disconnect the previous
    /// socket when no remaining target still uses it.
    fn note_host_resolved(&self, host: &str, addr: SocketAddr) {
        let Some(key) = self.host_key(host) else {
            return;
        };
        let prev = {
            let mut map = self.host_sockets.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(key, addr)
        };
        let Some(prev) = prev.filter(|prev| *prev != addr) else {
            return;
        };
        if self.socket_still_current(prev) {
            return;
        }
        self.disconnect_addr(prev);
    }

    fn socket_still_current(&self, addr: SocketAddr) -> bool {
        if self
            .host_sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|kept| *kept == addr)
        {
            return true;
        }
        let pinned = *self.trust_addr.lock().unwrap_or_else(|e| e.into_inner());
        if pinned.is_some_and(|a| a == crate::NetAddr::Ip(addr)) {
            return true;
        }
        self.connect_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&crate::NetAddr::Ip(addr))
    }

    fn trust_current_socket(&self) -> Option<SocketAddr> {
        let host = self
            .trust_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        let key = self.host_key(&host)?;
        self.host_sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .copied()
    }

    /// True when `--trust-peer` is set and this live session is that peer.
    pub fn session_is_trusted_peer(&self, session: &LivePeer) -> bool {
        self.trust_label().is_some() && self.trust_allows_net(session.net).is_ok()
    }

    /// Same allow check as `addnode`, for a dial target that is already a [`crate::NetAddr`].
    pub fn trust_allows_net(&self, addr: crate::NetAddr) -> Result<(), String> {
        self.trust_allows_target(&DialTarget::from_net(addr))
    }

    /// Address or hostname named by `--trust-peer`, when the mode is on.
    pub fn trust_peer_label(&self) -> Option<String> {
        self.trust_label()
    }

    fn trust_label(&self) -> Option<String> {
        let addr = *self.trust_addr.lock().unwrap_or_else(|e| e.into_inner());
        let host = self
            .trust_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if addr.is_none() && host.is_none() {
            return None;
        }
        Some(addr.map(|a| a.to_string()).or(host).unwrap_or_default())
    }

    fn trust_allows_spec(&self, spec: &str) -> Result<(), String> {
        let Some(label) = self.trust_label() else {
            return Ok(());
        };
        if spec.eq_ignore_ascii_case(&label) {
            return Ok(());
        }
        let pinned = *self.trust_addr.lock().unwrap_or_else(|e| e.into_inner());
        if pinned.is_some_and(|addr| spec.parse::<crate::NetAddr>().ok() == Some(addr)) {
            return Ok(());
        }
        Err(format!("trust-peer allows only {label}"))
    }

    fn trust_allows_target(&self, target: &DialTarget) -> Result<(), String> {
        if self.trust_label().is_none() {
            return Ok(());
        }
        match target {
            DialTarget::Socket(addr) => {
                if self.trust_allows_spec(&addr.to_string()).is_ok() {
                    return Ok(());
                }
                if self.trust_current_socket() == Some(*addr) {
                    return Ok(());
                }
                self.trust_allows_spec(&addr.to_string())
            }
            DialTarget::Domain { host, port } => {
                let spec = format!("{host}:{port}");
                if self.trust_allows_spec(&spec).is_ok() || self.trust_allows_spec(host).is_ok() {
                    Ok(())
                } else {
                    self.trust_allows_spec(&spec)
                }
            }
        }
    }

    #[doc(hidden)]
    pub fn note_default_port(&self, default_port: u16) {
        if default_port != 0 && self.connect_default_port.load(Ordering::Relaxed) == 0 {
            self.connect_default_port
                .store(default_port, Ordering::Relaxed);
        }
    }

    #[doc(hidden)]
    pub fn default_port_opt(&self) -> Option<u16> {
        let port = self.connect_default_port.load(Ordering::Relaxed);
        (port != 0).then_some(port)
    }

    #[doc(hidden)]
    pub fn host_dial_target(&self, node: &str) -> Result<DialTarget, String> {
        let with_port = ensure_host_port(node, self.default_port_opt())?;
        if let Ok(net) = parse_peer_net(&with_port) {
            return Ok(DialTarget::from_net(net));
        }
        let addr =
            parse_peer_addr_with_port(node, self.default_port_opt()).map_err(|e| e.to_string())?;
        if self.trust_host_matches(node) {
            self.note_trust_resolved(addr);
        }
        Ok(DialTarget::Socket(addr))
    }

    fn trust_host_matches(&self, node: &str) -> bool {
        let Some(host) = self
            .trust_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return false;
        };
        if node.eq_ignore_ascii_case(&host) {
            return true;
        }
        let Ok(with_port) = ensure_host_port(node, self.default_port_opt()) else {
            return false;
        };
        with_port.eq_ignore_ascii_case(&host)
    }

    #[doc(hidden)]
    pub fn dial_resolved(&self, node: &str) -> Result<(), String> {
        let ready = self.dial_ready()?;
        self.dial_resolved_ready(&ready.tx, node)
    }

    fn dial_resolved_ready(
        &self,
        tx: &mpsc::UnboundedSender<DialRequest>,
        node: &str,
    ) -> Result<(), String> {
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
        self.dial_manual_ready(tx, target)
    }

    #[doc(hidden)]
    pub fn disconnect_target(&self, target: &DialTarget) -> bool {
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

    /// Count an outbound dial to `target` until the guard drops. Taken when
    /// the dial is queued (a direct follow dial takes it before the TCP /
    /// SOCKS connect) and held until the session is registered or the dial
    /// fails, whichever path ends it.
    pub fn dial_in_flight(&self, target: &DialTarget) -> DialInFlight {
        let key = target.to_string();
        let net = target.net_addr();
        let _ = self
            .dials_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .and_modify(|slot| slot.n += 1)
            .or_insert(InFlightCount { n: 1, net });
        DialInFlight {
            counts: Arc::clone(&self.dials_in_flight),
            key,
        }
    }

    /// [`Self::dial_in_flight`], or `None` when `target` already has a dial
    /// queued or connecting. Check and count are one step.
    #[doc(hidden)]
    pub fn claim_dial(&self, target: &DialTarget) -> Option<DialInFlight> {
        let key = target.to_string();
        let mut g = self
            .dials_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&key) {
            return None;
        }
        g.insert(
            key.clone(),
            InFlightCount {
                n: 1,
                net: target.net_addr(),
            },
        );
        Some(DialInFlight {
            counts: Arc::clone(&self.dials_in_flight),
            key,
        })
    }

    /// Targets with a dial queued or still connecting.
    pub fn in_flight_nets(&self) -> Vec<crate::NetAddr> {
        self.dials_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|slot| slot.net)
            .collect()
    }

    /// Queue one `outbound-full-relay` dial.
    ///
    /// False when that target is already live, already in flight, or the
    /// dialer is gone. [`Self::claim_dial`] is the only gate, so a second
    /// call does not stack a connect.
    #[doc(hidden)]
    pub fn dial_outbound_full_relay(&self, addr: crate::NetAddr) -> bool {
        let target = DialTarget::from_net(addr);
        let Some(claim) = self.claim_dial(&target) else {
            return false;
        };
        if self.is_target_live(&target) {
            return false;
        }
        let Ok(ready) = self.dial_ready() else {
            return false;
        };
        self.enqueue_dial(
            &ready.tx,
            target,
            PeerConnType::OutboundFullRelay,
            Some(claim),
        )
        .is_ok()
    }

    #[doc(hidden)]
    pub fn is_target_live(&self, target: &DialTarget) -> bool {
        let peers = self.snapshot();
        match target {
            DialTarget::Socket(addr) => peers.iter().any(|p| p.addr == *addr),
            DialTarget::Domain { host, port } => peers
                .iter()
                .any(|p| p.net.host_str() == *host && p.net.port() == *port),
        }
    }

    #[doc(hidden)]
    pub fn remembered_redials(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .manual_hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect();
        out.extend(
            self.connect_hosts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned(),
        );
        out
    }

    /// One `manual` dial per resolved endpoint in this pass, as Core dials
    /// `-addnode` and `-connect`. `addnode add` and `--connect` of the same
    /// host share that dial, as do a `--connect` hostname and address that
    /// meet at one endpoint. A later pass dials again when the session is
    /// still not live. DNS lookup is synchronous; callers on a Tokio worker
    /// use [`Self::redial_remembered_off_runtime`].
    pub fn redial_remembered_with(&self, resolve: impl Fn(&str) -> Result<DialTarget, String>) {
        let mut seen = HashSet::<String>::new();
        let addrs = self
            .connect_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut targets = Vec::new();
        for host in self.remembered_redials() {
            let Ok(target) = resolve(&host) else {
                continue;
            };
            if let DialTarget::Socket(addr) = target {
                self.note_host_resolved(&host, addr);
            }
            targets.push(target);
        }
        targets.extend(addrs.into_iter().map(DialTarget::from_net));
        for target in targets {
            if !seen.insert(target.to_string()) {
                continue;
            }
            let _ = self.dial_manual_target(target);
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
        if matches!(typ, PeerConnType::Inbound | PeerConnType::PrivateBroadcast) {
            return Err(format!("addconnection cannot create {}", typ.as_str()));
        }
        self.dial(addr, typ)
    }

    pub fn dial_net(&self, addr: crate::NetAddr, typ: PeerConnType) -> Result<(), String> {
        self.queue_dial(DialTarget::from_net(addr), typ)
    }

    /// Queue a dial, counted in flight from now on. A feeler is not counted:
    /// it registers no session, and its probe has no connect deadline, so a
    /// stuck one would block the redial pass for that endpoint.
    #[doc(hidden)]
    pub fn queue_dial(&self, target: DialTarget, typ: PeerConnType) -> Result<(), String> {
        self.trust_allows_target(&target)?;
        let in_flight = (typ != PeerConnType::Feeler).then(|| self.dial_in_flight(&target));
        self.send_dial(target, typ, in_flight)
    }

    /// Queue a dial. The request carries `in_flight` to the dial task; if it
    /// is never sent, dropping it ends the count.
    #[doc(hidden)]
    pub fn send_dial(
        &self,
        target: DialTarget,
        typ: PeerConnType,
        in_flight: Option<DialInFlight>,
    ) -> Result<(), String> {
        let ready = self.dial_ready()?;
        self.enqueue_dial(&ready.tx, target, typ, in_flight)
    }

    fn enqueue_dial(
        &self,
        tx: &mpsc::UnboundedSender<DialRequest>,
        target: DialTarget,
        typ: PeerConnType,
        in_flight: Option<DialInFlight>,
    ) -> Result<(), String> {
        self.trust_allows_target(&target)?;
        tx.send(DialRequest {
            target,
            typ,
            in_flight,
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

    #[doc(hidden)]
    pub fn outbound_full_relay_rows(&self) -> Vec<(u64, SocketAddr)> {
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
        self.evict_inbound_from(|_| true, "inbound full")
    }

    /// Core `MaybeDisconnectForTxRelayCapacity`: past
    /// [`crate::peer_dos::FULL_RELAY_INBOUND_PCT`] of `max_inbound`, a
    /// tx-relaying `newcomer` evicts another tx-relaying inbound. `false` when
    /// every other one is protected and `newcomer` must go instead.
    #[doc(hidden)]
    pub fn make_room_for_tx_relay_inbound(&self, newcomer: &LivePeer, max_inbound: usize) -> bool {
        if !newcomer.relay {
            return true;
        }
        let _room = self.tx_relay_room.lock().unwrap_or_else(|e| e.into_inner());
        let cap = max_inbound * crate::peer_dos::FULL_RELAY_INBOUND_PCT / 100;
        let tx_relay = self
            .live_peers()
            .iter()
            .filter(|p| p.inbound && p.relay && !p.stop.load(Ordering::Relaxed))
            .count();
        if tx_relay <= cap {
            return true;
        }
        self.evict_inbound_from(|p| p.relay && p.id != newcomer.id, "tx-relay inbound full")
    }

    fn evict_inbound_from(&self, eligible: impl Fn(&LivePeer) -> bool, why: &str) -> bool {
        let now = self.now_secs();
        let cands: Vec<crate::eviction::InboundEvictCandidate> = self
            .live_peers()
            .into_iter()
            .filter(|p| p.inbound && !p.stop.load(Ordering::Relaxed) && eligible(p))
            .map(|p| {
                let (_pt, minping, _pw) = p.ping_rpc_fields(now);
                crate::eviction::InboundEvictCandidate {
                    id: p.id,
                    connected_at: p.connected_at(),
                    min_ping: minping,
                    last_block: p.last_block.load(Ordering::Relaxed),
                    last_tx: p.last_transaction.load(Ordering::Relaxed),
                    netgroup: p.netgroup,
                    noban: p.session_noban(),
                }
            })
            .collect();
        let Some(id) = crate::eviction::select_inbound_eviction(cands) else {
            return false;
        };
        if let Some(p) = self.get(id) {
            self.note_slot_evict(p.netgroup());
        }
        rbitcoin_log::info!("p2p: evict inbound peer={id} ({why})");
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
        self.dial_net(crate::NetAddr::Ip(addr), typ)
    }

    pub fn dial_domain(
        &self,
        host: impl Into<String>,
        port: u16,
        typ: PeerConnType,
    ) -> Result<(), String> {
        let target = DialTarget::Domain {
            host: host.into(),
            port,
        };
        self.queue_dial(target, typ)
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

/// Parse Core `ip:port` / `[v6]:port`.
pub fn parse_peer_addr(s: &str) -> Result<SocketAddr, NetError> {
    s.parse()
        .map_err(|_| NetError::Encode(format!("bad peer address {s}")))
}

pub fn parse_peer_net(s: &str) -> Result<crate::NetAddr, NetError> {
    s.parse()
        .map_err(|_| NetError::Encode(format!("bad peer address {s}")))
}

#[doc(hidden)]
pub fn ensure_host_port(node: &str, default_port: Option<u16>) -> Result<String, String> {
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
mod addrfetch_notify {
    use super::PeerHub;

    #[tokio::test]
    async fn reply_wakes_tip_follow() {
        let hub = PeerHub::new();
        let notified = hub.addrfetch_learned().notified();
        hub.note_addrfetch_reply();
        tokio::time::timeout(std::time::Duration::from_secs(1), notified)
            .await
            .expect("an addr-fetch reply must wake tip-follow");
    }
}
