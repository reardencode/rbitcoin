//! Peer handshake, serve, tip follow, and announce (BIP324 v2 transport).

use crate::cache::BlockCache;
use crate::chain::{
    accept_block_header_nodos_log, ignoring_low_work_chain_log, received_getdata_wtx_log,
    synchronizing_blockheaders_log, AcceptOutcome, ChainHub,
};
use crate::codec::{FramedMessage, MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_LOCATOR_SZ};
use crate::error::NetError;
use crate::msg_decode::decode_framed_offload;
use crate::peer_dos::{PeerRateLimiter, OVERSIZE_BAN_SCORE, RATE_LIMIT_BAN_SCORE};
use crate::peers::PingAction;
use crate::v2::{
    open_v2, read_v2_contents, read_v2_frame, write_v2_contents, write_v2_msg,
    write_v2_msg_offload, V2Reader, V2Writer,
};
use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::{Block, BlockHash, Transaction};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

/// Protocol version we advertise (BIP339 wtxidrelay needs ≥70016; rust-bitcoin's
/// `PROTOCOL_VERSION` is still 70001).
const OUR_PROTOCOL_VERSION: u32 = 70016;

/// How often an established session re-issues `getheaders` so a quiet peer or
/// a gap opened while we were offline still gets filled (signet ~10m blocks).
const HEADERS_POLL_SECS: u64 = 120;

/// Core `10 * AVG_ADDRESS_BROADCAST_INTERVAL` (30s) for addr-fetch lifetime.
const ADDRFETCH_TIMEOUT_SECS: u64 = 300;

/// Core `MAX_BLOCKS_TO_ANNOUNCE`: more than this on a reorg falls back to inv.
const MAX_BLOCKS_TO_ANNOUNCE: u32 = 8;

/// True when a session error is a missing store row (not peer malice / corrupt IO).
///
/// These must not tear down the TCP session: re-request or skip and keep the peer.
pub(crate) fn net_error_is_store_not_found(e: &NetError) -> bool {
    match e {
        NetError::Consensus(s) => {
            let l = s.to_ascii_lowercase();
            l.contains("record not found")
                || l.contains("not found")
                || l.contains("storeerror::notfound")
        }
        _ => false,
    }
}

/// Per-session misbehavior score that triggers disconnect (Core-like order).
pub const BAN_SCORE_THRESHOLD: u32 = 100;

/// `-blocksonly` (relay off, no whitelist `relay`) or a block-relay-only
/// session must not receive txs / tx invs (`p2p_blocksonly`).
fn reject_unsolicited_tx(hub: &ChainHub, session: Option<&crate::peers::LivePeer>) -> bool {
    if hub.in_ibd() {
        return false;
    }
    if session.is_some_and(|s| s.conn_type == crate::peers::PeerConnType::BlockRelay) {
        return true;
    }
    let node_relay = hub.mempool().is_none_or(|m| m.relay_enabled());
    if node_relay {
        return false;
    }
    !session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_relay_perm()))
}

/// BIP152 HB is only for tx-relay peers. `-blocksonly` must not send
/// `sendcmpct(announce=1)` (`p2p_compactblocks_blocksonly`).
fn maybe_select_hb_if_relay(hub: &ChainHub, session: Option<&crate::peers::LivePeer>) {
    if hub.mempool().is_some_and(|m| !m.relay_enabled()) {
        return;
    }
    if let Some(s) = session {
        s.maybe_select_as_hb();
    }
}

fn punish_disconnect(ban_score: &mut u32, session: Option<&crate::peers::LivePeer>) {
    *ban_score = ban_score.saturating_add(BAN_SCORE_THRESHOLD);
    if let Some(s) = session {
        s.request_disconnect();
    }
}
/// Cap on incomplete compact blocks awaiting `blocktxn` (DoS).
const MAX_PENDING_CMPCT: usize = 8;
/// Cap on headers held while assembling tip/reorg work (DoS / process RAM).
const MAX_PENDING_HEADERS: usize = 8_000;
/// Cap on decoded bodies stashed per session (DoS / process RAM). Must be
/// ≥99 so tip-follow can assemble a 99-block competing branch; apply is
/// `ChainHub::accept_received_block` (see `docs/architecture.md`).
/// Inflight `getdata` is [`MAX_SERVE_BLOCKS`] (peer reconstruct cap).
const MAX_PENDING_BLOCKS: usize = 128;
/// Max reconstructed full bodies queued on one session writer, and the
/// matching catch-up `getdata` window (extra hashes stick in `requested`).
pub(crate) const MAX_SERVE_BLOCKS: usize = 16;

/// INV-origin txids this session sent us. Cap matches `announced_wtx` (clear on overflow).
pub(crate) const FROM_THIS_PEER_CAP: usize = 50_000;

pub(crate) fn insert_capped_txid(
    map: &mut HashMap<bitcoin::Txid, ()>,
    txid: bitcoin::Txid,
    cap: usize,
) {
    if map.len() >= cap {
        map.clear();
    }
    map.insert(txid, ());
}

/// Test/assert surface for the tip-follow pending-body cap (equals production).
#[cfg(test)]
pub(crate) const MAX_PENDING_BLOCKS_FOR_TEST: usize = MAX_PENDING_BLOCKS;

/// Tip-follow decoded bodies waiting for a connectable parent. Cap 128;
/// insert evicts the oldest hash (FIFO), not `HashMap::keys().next()`.
#[derive(Default)]
pub(crate) struct PendingBlocks {
    map: HashMap<BlockHash, bitcoin::Block>,
    fifo: VecDeque<BlockHash>,
}

impl PendingBlocks {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn contains_key(&self, hash: &BlockHash) -> bool {
        self.map.contains_key(hash)
    }

    pub(crate) fn values(
        &self,
    ) -> std::collections::hash_map::Values<'_, BlockHash, bitcoin::Block> {
        self.map.values()
    }

    pub(crate) fn keys(&self) -> std::collections::hash_map::Keys<'_, BlockHash, bitcoin::Block> {
        self.map.keys()
    }

    pub(crate) fn insert(&mut self, hash: BlockHash, block: bitcoin::Block) {
        stash_pending_block(self, hash, block);
    }

    pub(crate) fn remove(&mut self, hash: &BlockHash) -> Option<bitcoin::Block> {
        let b = self.map.remove(hash)?;
        if let Some(i) = self.fifo.iter().position(|h| h == hash) {
            self.fifo.remove(i);
        }
        Some(b)
    }
}

fn stash_pending_block(pending: &mut PendingBlocks, hash: BlockHash, block: bitcoin::Block) {
    if pending.map.len() >= MAX_PENDING_BLOCKS && !pending.map.contains_key(&hash) {
        if let Some(k) = pending.fifo.pop_front() {
            pending.map.remove(&k);
        }
    }
    if !pending.map.contains_key(&hash) {
        pending.fifo.push_back(hash);
    }
    pending.map.insert(hash, block);
}

/// Services we advertise once store-backed reconstruct serve is available.
pub fn local_service_flags() -> ServiceFlags {
    crate::seeds::required_seed_services()
}

/// Core `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS` (~24h at 10m spacing).
pub const NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS: i64 = 144;

/// Core `CNode::ExpectServicesFromConn`.
pub fn expect_services_from_conn(typ: crate::peers::PeerConnType) -> bool {
    matches!(
        typ,
        crate::peers::PeerConnType::OutboundFullRelay
            | crate::peers::PeerConnType::BlockRelay
            | crate::peers::PeerConnType::AddrFetch
    )
}

/// Core `PeerManagerImpl::GetDesirableServiceFlags`.
pub fn desirable_service_flags(offered: ServiceFlags, tip_depth_blocks: i64) -> ServiceFlags {
    if offered.has(ServiceFlags::NETWORK_LIMITED)
        && tip_depth_blocks < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS
    {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS
    } else {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    }
}

/// Core `PeerManagerImpl::HasAllDesirableServiceFlags`.
pub fn has_all_desirable_service_flags(offered: ServiceFlags, tip_depth_blocks: i64) -> bool {
    let want = desirable_service_flags(offered, tip_depth_blocks);
    offered.has(want)
}

pub fn expected_services_disconnect_log(offered: u64, expected: u64) -> String {
    format!("does not offer the expected services ({offered:08x} offered, {expected:08x} expected)")
}

pub fn feeler_connection_completed_log() -> &'static str {
    "feeler connection completed"
}

pub fn connected_to_self_log(addr: impl std::fmt::Display) -> String {
    format!("connected to self at {addr}, disconnecting")
}

/// Core `ApproximateBestBlockDepth`: `(now - tip_time) / pow_target_spacing`.
pub fn approximate_best_block_depth(hub: &ChainHub) -> i64 {
    let Some(h) = hub.tip_header() else {
        return i64::MAX;
    };
    let spacing = hub.params.btc.pow_target_spacing.max(1) as i64;
    let age = hub.clock.now_secs().saturating_sub(u64::from(h.time)) as i64;
    age / spacing
}

/// Optional bookkeeping for outbound tip-follow sessions.
#[derive(Clone, Default)]
pub struct FollowSessionMeta {
    /// Peer address (logging).
    pub peer: Option<SocketAddr>,
    /// Live outbound follow count (inc on start, dec on exit).
    pub live: Option<Arc<AtomicUsize>>,
    /// RPC session row (bytes + disconnect).
    pub session: Option<Arc<crate::peers::LivePeer>>,
}

/// Decrements the live follow counter when a session task exits.
/// Increment happens in [`crate::service::P2PNode::follow_from`] so the count
/// is visible as soon as handshake succeeds (before the task is scheduled).
struct LiveFollowDec(Option<Arc<AtomicUsize>>);

impl Drop for LiveFollowDec {
    fn drop(&mut self) {
        if let Some(ref c) = self.0 {
            c.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Optional hub/peers policy for VERSION checks (services + self-connect nonce).
#[derive(Clone, Copy)]
pub struct HandshakePolicy<'a> {
    pub hub: Option<&'a ChainHub>,
    pub peers: Option<&'a crate::peers::PeerHub>,
    pub conn_type: crate::peers::PeerConnType,
}

impl HandshakePolicy<'static> {
    pub fn plain() -> Self {
        Self {
            hub: None,
            peers: None,
            conn_type: crate::peers::PeerConnType::OutboundFullRelay,
        }
    }
}

/// Outbound BIP324 session after VERSION/VERACK with [`HandshakePolicy::plain`].
pub struct V2PlainSession {
    reader: V2Reader,
    writer: V2Writer,
    tcp_shutdown: std::net::TcpStream,
}

impl V2PlainSession {
    /// Dial-side handshake on `stream`; `limit` bounds VERSION/VERACK.
    pub async fn outbound_regtest(
        stream: TcpStream,
        user_agent: &str,
        limit: Duration,
    ) -> Result<Self, NetError> {
        let our_addr = stream.local_addr()?;
        let their_addr = stream.peer_addr()?;
        let magic = Magic::REGTEST;
        let (_ver, reader, writer, _wire, tcp_shutdown) = connect_and_handshake_timed(
            limit,
            stream,
            magic,
            our_addr,
            their_addr,
            0,
            false,
            user_agent,
            HandshakePolicy::plain(),
        )
        .await?;
        Ok(Self {
            reader,
            writer,
            tcp_shutdown,
        })
    }

    pub async fn write_contents(&mut self, contents: &[u8]) -> Result<(), NetError> {
        write_v2_contents(&mut self.writer, contents).await
    }

    pub async fn read_contents(&mut self) -> Result<Vec<u8>, NetError> {
        read_v2_contents(&mut self.reader).await
    }

    pub async fn read_frame(&mut self) -> Result<(), NetError> {
        self.read_contents().await.map(|_| ())
    }

    pub fn close(&mut self) {
        let _ = self.tcp_shutdown.shutdown(std::net::Shutdown::Both);
    }
}

/// Open BIP324 v2 transport + perform the version/verack exchange.
///
/// Returns the peer's version and the encrypted read/write halves. All further
/// messages must use those halves — production has no v1 wire path.
pub async fn connect_and_handshake(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    inbound: bool,
    user_agent: &str,
    policy: HandshakePolicy<'_>,
) -> Result<
    (
        VersionMessage,
        V2Reader,
        V2Writer,
        crate::v2::WireBytes,
        std::net::TcpStream,
    ),
    NetError,
> {
    let (mut reader, mut writer, wire, tcp_shutdown) = open_v2(stream, magic, inbound).await?;
    let their_version = application_handshake(
        &mut reader,
        &mut writer,
        magic,
        our_addr,
        their_addr,
        start_height,
        inbound,
        user_agent,
        policy,
    )
    .await?;
    Ok((their_version, reader, writer, wire, tcp_shutdown))
}

/// Core VERSION/VERACK bound: 60s from TCP connect/accept. Timeout drops the stream.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn inbound_connect_and_handshake(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
    policy: HandshakePolicy<'_>,
) -> Result<
    (
        VersionMessage,
        V2Reader,
        V2Writer,
        crate::v2::WireBytes,
        std::net::TcpStream,
    ),
    NetError,
> {
    connect_and_handshake_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        our_addr,
        their_addr,
        start_height,
        true,
        user_agent,
        policy,
    )
    .await
}

pub(crate) async fn connect_and_handshake_timed(
    limit: Duration,
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    inbound: bool,
    user_agent: &str,
    policy: HandshakePolicy<'_>,
) -> Result<
    (
        VersionMessage,
        V2Reader,
        V2Writer,
        crate::v2::WireBytes,
        std::net::TcpStream,
    ),
    NetError,
> {
    tokio::time::timeout(
        limit,
        connect_and_handshake(
            stream,
            magic,
            our_addr,
            their_addr,
            start_height,
            inbound,
            user_agent,
            policy,
        ),
    )
    .await
    .map_err(|_| NetError::Timeout)?
}

/// Feeler: send version (relay=0), read their version, close. No verack, no session.
pub async fn run_feeler(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
) -> Result<(), NetError> {
    run_feeler_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        our_addr,
        their_addr,
        start_height,
        user_agent,
    )
    .await
}

pub(crate) async fn run_feeler_timed(
    limit: Duration,
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
) -> Result<(), NetError> {
    tokio::time::timeout(
        limit,
        run_feeler_inner(
            stream,
            magic,
            our_addr,
            their_addr,
            start_height,
            user_agent,
        ),
    )
    .await
    .map_err(|_| NetError::Timeout)?
}

async fn run_feeler_inner(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
) -> Result<(), NetError> {
    let (mut reader, mut writer, _wire, _tcp_shutdown) = open_v2(stream, magic, false).await?;
    let services = local_service_flags();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let version = VersionMessage {
        version: OUR_PROTOCOL_VERSION.max(PROTOCOL_VERSION),
        services,
        timestamp: now,
        receiver: Address::new(&their_addr, ServiceFlags::NONE),
        sender: Address::new(&our_addr, services),
        nonce: rand_nonce(),
        user_agent: user_agent.to_string(),
        start_height,
        relay: false,
    };
    write_v2_msg(&mut writer, NetworkMessage::Version(version)).await?;
    loop {
        let frame = read_v2_frame(&mut reader, magic).await?;
        let msg = frame.decode();
        if matches!(msg.payload(), NetworkMessage::Version(_)) {
            break;
        }
    }
    rbitcoin_log::info!("{}", feeler_connection_completed_log());
    Ok(())
}

/// Perform the version/verack exchange over an established BIP324 session.
async fn application_handshake(
    reader: &mut V2Reader,
    writer: &mut V2Writer,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    inbound: bool,
    user_agent: &str,
    policy: HandshakePolicy<'_>,
) -> Result<VersionMessage, NetError> {
    let services = local_service_flags();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let our_nonce = rand_nonce();
    let version = VersionMessage {
        version: OUR_PROTOCOL_VERSION.max(PROTOCOL_VERSION),
        services,
        timestamp: now,
        receiver: Address::new(&their_addr, ServiceFlags::NONE),
        sender: Address::new(&our_addr, services),
        nonce: our_nonce,
        user_agent: user_agent.to_string(),
        start_height,
        relay: true,
    };

    struct OutboundNonceGuard<'a> {
        peers: Option<&'a crate::peers::PeerHub>,
        nonce: u64,
        clear: bool,
    }
    impl Drop for OutboundNonceGuard<'_> {
        fn drop(&mut self) {
            if self.clear {
                if let Some(p) = self.peers {
                    p.clear_outbound_nonce(self.nonce);
                }
            }
        }
    }
    let mut nonce_guard = OutboundNonceGuard {
        peers: None,
        nonce: our_nonce,
        clear: false,
    };
    if !inbound {
        if let Some(peers) = policy.peers {
            peers.note_outbound_nonce(our_nonce);
            nonce_guard.peers = Some(peers);
            nonce_guard.clear = true;
        }
        write_v2_msg(writer, NetworkMessage::Version(version.clone())).await?;
    }

    let their_version = loop {
        let frame = read_v2_frame(reader, magic).await?;
        let msg = frame.decode();
        match msg.payload() {
            NetworkMessage::Version(v) => break v.clone(),
            other => {
                if matches!(other, NetworkMessage::Verack) {
                    return Err(NetError::Protocol("verack before version"));
                }
                let _ = other;
            }
        }
    };

    if inbound {
        if let Some(peers) = policy.peers {
            if !peers.check_incoming_nonce(their_version.nonce) {
                rbitcoin_log::info!("{}", connected_to_self_log(their_addr));
                return Err(NetError::Protocol("connected to self"));
            }
        }
        write_v2_msg(writer, NetworkMessage::Version(version)).await?;
    } else if expect_services_from_conn(policy.conn_type) {
        if let Some(hub) = policy.hub {
            let depth = approximate_best_block_depth(hub);
            if !has_all_desirable_service_flags(their_version.services, depth) {
                let expected = desirable_service_flags(their_version.services, depth);
                rbitcoin_log::info!(
                    "{}",
                    expected_services_disconnect_log(
                        their_version.services.to_u64(),
                        expected.to_u64()
                    )
                );
                return Err(NetError::Protocol("peer missing desirable services"));
            }
        }
    }

    // BIP339: wtxidrelay MUST be sent after version and before verack when both
    // sides speak ≥70016. Late (post-verack) messages are ignored/invalid.
    if their_version.version >= 70016 {
        write_v2_msg(writer, NetworkMessage::WtxidRelay).await?;
    }
    // BIP155: advertise addrv2 before verack (`p2p_invalid_messages` wait_for_sendaddrv2).
    write_v2_msg(writer, NetworkMessage::SendAddrV2).await?;
    write_v2_msg(writer, NetworkMessage::Verack).await?;

    loop {
        let frame = read_v2_frame(reader, magic).await?;
        let msg = frame.decode();
        match msg.payload() {
            NetworkMessage::Verack => break,
            NetworkMessage::Ping(n) => {
                write_v2_msg(writer, NetworkMessage::Pong(*n)).await?;
            }
            _ => {}
        }
    }

    nonce_guard.clear = false;
    if let Some(peers) = policy.peers {
        if !inbound {
            peers.clear_outbound_nonce(our_nonce);
        }
    }

    Ok(their_version)
}

fn framed_cmd(frame: &FramedMessage) -> String {
    let end = frame.command.iter().position(|&b| b == 0).unwrap_or(12);
    String::from_utf8_lossy(&frame.command[..end]).into_owned()
}

fn rand_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Concurrent dials often share the same wall-clock instant; a counter keeps
    // version nonces unique (Core self-connect / loop detection uses nonce).
    static N: AtomicU64 = AtomicU64::new(1);
    let seq = N.fetch_add(1, Ordering::Relaxed);
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    tick.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_mul(0xBF58_476D_1CE4_E5B9))
}

/// Bidirectional peer session: serve history, tip follow, announce our tip.
///
/// After handshake preferences (`sendheaders` / `sendcmpct`), the session
/// **actively** `getheaders` from our tip locator so blocks mined while we were
/// offline or mid–SH materialize are pulled — not only unsolicited announces.
/// Long history catch-up remains [`crate::ibd`] / [`crate::service::P2PNode::sync`].
///
/// A dedicated writer drains outbound messages while the reader keeps draining
/// the encrypted channel. `meta` labels the peer for logs and optionally tracks
/// live outbound follow count.
pub async fn peer_session_with(
    mut reader: V2Reader,
    mut writer: V2Writer,
    magic: Magic,
    hub: Arc<ChainHub>,
    mut tip_rx: broadcast::Receiver<crate::chain::TipEvent>,
    meta: FollowSessionMeta,
) -> Result<(), NetError> {
    let _live_dec = LiveFollowDec(meta.live.clone());
    let peer_s = meta
        .peer
        .map(|p| p.to_string())
        .unwrap_or_else(|| "peer".into());

    let _ = write_v2_msg(&mut writer, NetworkMessage::SendHeaders).await;
    // BIP152: compact v2 low-bandwidth. HB is selected later (max 3, prefer outbound).
    let _ = write_v2_msg(
        &mut writer,
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: false,
            version: 2,
        }),
    )
    .await;
    // Handshake-writer ping, same nonce as LivePeer: connect_nodes needs pong
    // bytes before the writer task; a second ping makes the first pong mismatch.
    let keepalive = if let Some(s) = meta.session.as_ref() {
        match s.take_ping_action(s.clock_now()) {
            Some(PingAction::Send { nonce }) => Some(nonce),
            _ => None,
        }
    } else {
        Some(rand_nonce())
    };
    if let Some(n) = keepalive {
        let _ = write_v2_msg(&mut writer, NetworkMessage::Ping(n)).await;
    }
    if let Some(fee_sat) = outbound_feefilter_sats(&hub, meta.session.as_deref()) {
        let _ = write_v2_msg(&mut writer, NetworkMessage::FeeFilter(fee_sat)).await;
    }

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<NetworkMessage>();
    if let Some(s) = meta.session.as_ref() {
        s.attach_out(out_tx.clone());
    }

    let writer_session = meta.session.clone();
    let mut writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let full = matches!(
                msg,
                NetworkMessage::Block(_) | NetworkMessage::CmpctBlock(_)
            );
            let err = write_v2_msg_offload(&mut writer, msg).await.is_err();
            if full {
                if let Some(s) = &writer_session {
                    note_served_write(&s.serve_inflight);
                }
            }
            if err {
                break;
            }
        }
    });
    if let Some(s) = meta.session.as_ref() {
        s.set_writer_abort(writer_task.abort_handle());
    }

    if let Some(s) = meta.session.as_ref() {
        let _ = maybe_queue_addrfetch_getaddr(&out_tx, s);
        let _ = maybe_queue_initial_getheaders(&out_tx, hub.as_ref(), s);
    } else if let Err(e) = queue_getheaders(&out_tx, hub.as_ref(), None, true, None) {
        rbitcoin_log::warn!("p2p: {peer_s} initial getheaders queue failed: {e}");
    }

    let mut peer_wants_headers = false;
    let mut peer_wtxid_relay = false;
    let mut peer_send_cmpct = false;
    // 0 until the peer sends `sendcmpct` v2. Defaulting to 2 made every
    // relay peer getdata CMPCT and broke tests that only serve `msg_block`.
    let mut peer_cmpct_version: u32 = 0;
    let mut pending_headers: HashMap<BlockHash, bitcoin::block::Header> = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct: HashMap<BlockHash, PendingCmpct> = HashMap::new();
    let mut from_this_peer: HashMap<bitcoin::Txid, ()> = HashMap::new();
    let mut requested_blocks: HashSet<BlockHash> = HashSet::new();
    let mut ban_score: u32 = 0;
    let mut rate = PeerRateLimiter::default_limits();
    let mut tx_announce_rx = hub.mempool().map(|m| m.subscribe_announces());
    let mut inv_flush_rx = hub.mempool().map(|m| m.subscribe_inv_flush());
    let mut headers_poll = tokio::time::interval(Duration::from_secs(HEADERS_POLL_SECS));
    headers_poll.tick().await;

    let session = meta.session.clone();
    let result = async {
        loop {
            if session
                .as_ref()
                .is_some_and(|s| s.stop.load(Ordering::Relaxed))
            {
                return Ok(());
            }
            tokio::select! {
                biased;
                // Peer half-close / write failure: tear down so getpeerinfo
                // clears without waiting on a stuck read/decode arm.
                writer_done = &mut writer_task => {
                    let _ = writer_done;
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_millis(50)), if session.is_some() => {
                    if tx_announce_rx.is_none() {
                        tx_announce_rx = hub.mempool().map(|m| m.subscribe_announces());
                    }
                    if inv_flush_rx.is_none() {
                        inv_flush_rx = hub.mempool().map(|m| m.subscribe_inv_flush());
                    }
                    if let Some(s) = session.as_ref() {
                        if addrfetch_timed_out(s) {
                            rbitcoin_log::debug!("addrfetch connection timeout");
                            s.request_disconnect();
                        }
                        match s.take_ping_action(s.clock_now()) {
                            Some(PingAction::Send { nonce }) => {
                                let _ = queue_out(&out_tx, NetworkMessage::Ping(nonce));
                            }
                            Some(PingAction::Timeout { elapsed_secs }) => {
                                rbitcoin_log::info!("ping timeout: {elapsed_secs:.6}s");
                                s.request_disconnect();
                            }
                            None => {}
                        }
                        if let Some(ph) = s.hub() {
                            ph.on_session_heartbeat();
                        }
                        queue_due_tx_invs(hub.as_ref(), s, &from_this_peer, &out_tx);
                        let _ = maybe_queue_initial_getheaders(&out_tx, hub.as_ref(), s);
                        match s.pending_sendcmpct.swap(0, Ordering::Relaxed) {
                            1 => {
                                let _ = queue_out(
                                    &out_tx,
                                    NetworkMessage::SendCmpct(SendCmpct {
                                        send_compact: false,
                                        version: 2,
                                    }),
                                );
                            }
                            2 => {
                                let _ = queue_out(
                                    &out_tx,
                                    NetworkMessage::SendCmpct(SendCmpct {
                                        send_compact: true,
                                        version: 2,
                                    }),
                                );
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
                tip = tip_rx.recv() => {
                    let ev = match tip_event_for_announce(tip, hub.as_ref()) {
                        TipRecvAnnounce::Closed => return Ok(()),
                        TipRecvAnnounce::Skip => continue,
                        TipRecvAnnounce::Announce(ev) => ev,
                    };
                    // Below `-minimumchainwork` stay in IBD: do not relay blocks.
                    if !hub.meets_minimum_chain_work() {
                        continue;
                    }
                    let from_peer = session
                        .as_ref()
                        .is_some_and(|s| s.take_block_from_peer(&ev.hash));
                    let (sent, known) = session
                        .as_ref()
                        .map(|s| s.header_marks())
                        .unwrap_or((None, None));
                    // sendcmpct announce=1: Core sends cmpctblock even
                    // without sendheaders (`p2p_compactblocks` :249).
                    // Skip if NewPoWValidBlock already announced this hash.
                    if peer_send_cmpct && !from_peer && sent != Some(ev.hash) {
                        if let Some(msg) = cmpct_announce_msg(
                            hub.as_ref(),
                            &ev.hash,
                            peer_cmpct_version,
                        ) {
                            queue_cmpct_tip_announce(&out_tx, msg)?;
                            if let Some(s) = session.as_ref() {
                                s.note_best_header_sent(ev.hash);
                            }
                            // Compact-only when the peer did not send
                            // sendheaders. Node-to-node always sends
                            // sendheaders; also announce headers so a
                            // longer fork can reorg (`p2p_sendheaders`).
                            if !peer_wants_headers {
                                continue;
                            }
                        }
                    }
                    match tip_announce_decision(
                        hub.as_ref(),
                        &ev,
                        peer_wants_headers,
                        sent,
                        known,
                        from_peer,
                    ) {
                        TipAnnounce::Skip => continue,
                        TipAnnounce::Inv(h) => {
                            // Core block *announcements* use MSG_BLOCK
                            // (`p2p_compactblocks` TestP2PConn.on_inv).
                            queue_out(
                                &out_tx,
                                NetworkMessage::Inv(vec![Inventory::Block(h)]),
                            )?;
                        }
                        TipAnnounce::Headers(hs) => {
                            if let Some(last) = hs.last() {
                                if let Some(s) = session.as_ref() {
                                    s.note_best_header_sent(last.block_hash());
                                }
                            }
                            queue_out(&out_tx, NetworkMessage::Headers(hs))?;
                        }
                    }
                }
                _ = headers_poll.tick() => {
                    let skip = session.as_ref().is_some_and(|s| {
                        s.conn_type == crate::peers::PeerConnType::AddrFetch
                            || !should_poll_peer_headers(hub.as_ref(), s.best_known())
                    });
                    if !skip {
                        let _ = queue_getheaders(
                            &out_tx,
                            hub.as_ref(),
                            session.as_deref(),
                            false,
                            None,
                        );
                    }
                }
                ann = async {
                    if let Some(rx) = tx_announce_rx.as_mut() {
                        Some(rx.recv().await)
                    } else {
                        std::future::pending::<()>().await;
                        None
                    }
                } => {
                    if let Some(ann) = ann {
                        match ann {
                            Ok(ann) => {
                                let txid = ann.txid;
                                if from_this_peer.contains_key(&txid) {
                                    continue;
                                }
                                if let Some(mp) = hub.mempool() {
                                    let peer_ok = session.as_ref().is_none_or(|s| {
                                        s.conn_type != crate::peers::PeerConnType::BlockRelay
                                            && (s.relay || mp.is_unbroadcast(&txid))
                                            // Inbound waits 30s when relay is on
                                            // (`mempool_reorg.py:71`). Noban and
                                            // `-blocksonly` unbroadcast skip it.
                                            && (!s.inbound
                                                || s.hub().is_some_and(|h| h.is_noban())
                                                || !mp.relay_enabled())
                                    });
                                    if peer_ok
                                        && mp.try_contains(&txid)
                                        && (mp.relay_enabled() || mp.is_unbroadcast(&txid))
                                    {
                                        let peer_min = session
                                            .as_ref()
                                            .map(|s| s.minfeefilter_sat_kvb())
                                            .unwrap_or(0);
                                        if peer_min > 0 {
                                            if let Some((fee, weight)) = mp.try_get_live_meta(&txid)
                                            {
                                                let rate =
                                                    rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
                                                        fee, weight,
                                                    );
                                                if rate < peer_min {
                                                    continue;
                                                }
                                            }
                                        }
                                        let inv = if let Some(tx) = mp.try_get_tx(&txid) {
                                            Inventory::WTx(tx.compute_wtxid())
                                        } else {
                                            Inventory::WitnessTransaction(txid)
                                        };
                                        if let Some(s) = session.as_ref() {
                                            if let Inventory::WTx(w) = inv {
                                                s.note_announced_wtx(w);
                                                // Only this tx existed at INV time.
                                                // Never snap to current_relay_seq()
                                                // (`mempool_reorg.py:122`).
                                                if let Some(seq) = mp.relay_seq_of(&w) {
                                                    s.note_tx_inv_seq(
                                                        s.last_inv_sequence()
                                                            .max(seq.saturating_add(1)),
                                                    );
                                                }
                                            }
                                        }
                                        queue_out(&out_tx, NetworkMessage::Inv(vec![inv]))?;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => {}
                        }
                    }
                }
                flush = async {
                    if let Some(rx) = inv_flush_rx.as_mut() {
                        Some(rx.recv().await)
                    } else {
                        std::future::pending::<()>().await;
                        None
                    }
                } => {
                    if matches!(flush, Some(Ok(()))) {
                        if let Some(s) = session.as_ref() {
                            s.request_tx_inv();
                            queue_due_tx_invs(hub.as_ref(), s, &from_this_peer, &out_tx);
                            // setmocktime also ends a stalling headers-sync.
                            // Restart getheaders here — waiting for the 50ms
                            // tick loses p2p_initial_headers_sync noban
                            // assert_single_getheaders_recipient.
                            let _ = maybe_queue_initial_getheaders(
                                &out_tx,
                                hub.as_ref(),
                                s,
                            );
                        }
                    }
                }
                frame = read_v2_frame(&mut reader, magic) => {
                    let frame = match frame {
                        Ok(f) => f,
                        // Any socket Io means the peer is gone — exit cleanly so
                        // unregister runs inside the Core disconnect_nodes 5s wait.
                        Err(NetError::Io(_)) => return Ok(()),
                        Err(NetError::MessageTooLarge(n)) => {
                            ban_score = ban_score.saturating_add(OVERSIZE_BAN_SCORE);
                            rbitcoin_log::warn!(
                                "p2p: {peer_s} oversize frame ({n}) ban_score={ban_score}"
                            );
                            if ban_score >= BAN_SCORE_THRESHOLD {
                                return Err(NetError::Protocol("peer ban score threshold"));
                            }
                            return Err(NetError::MessageTooLarge(n));
                        }
                        Err(NetError::InvalidV2Type { contents_len }) => {
                            // Core stays connected; counts raw v2 size as `*other*`.
                            if let Some(ref sess) = session {
                                sess.note_recv_raw(
                                    "*other*",
                                    crate::v2::v2_other_recv_bytes(contents_len),
                                );
                            }
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if let Some(ref sess) = session {
                        sess.note_recv(&framed_cmd(&frame), frame.payload_len() as u64);
                    }
                    let frame_len = frame.payload_len();
                    if !rate.note(frame_len) {
                        ban_score = ban_score.saturating_add(RATE_LIMIT_BAN_SCORE);
                        rbitcoin_log::warn!(
                            "p2p: {peer_s} rate limit exceeded ban_score={ban_score}"
                        );
                        if ban_score >= BAN_SCORE_THRESHOLD {
                            return Err(NetError::Protocol("peer ban score threshold"));
                        }
                        continue;
                    }
                    // Ping/pong: cheap 8-byte path — never leave the I/O task for decode.
                    if frame.is_ping() {
                        if let Some(n) = frame.ping_nonce() {
                            queue_out(&out_tx, NetworkMessage::Pong(n))?;
                        }
                        continue;
                    }
                    if frame.is_pong() {
                        if let Some(s) = session.as_ref() {
                            if let Some(line) = s.on_pong(&frame.payload, s.clock_now()) {
                                rbitcoin_log::info!("{line}");
                            }
                        }
                        continue;
                    }
                    handle_peer_frame(
                        frame,
                        hub.as_ref(),
                        &out_tx,
                        &mut peer_wants_headers,
                        &mut peer_wtxid_relay,
                        &mut peer_send_cmpct,
                        &mut peer_cmpct_version,
                        &mut pending_headers,
                        &mut pending_blocks,
                        &mut pending_cmpct,
                        &mut from_this_peer,
                        &mut requested_blocks,
                        &mut ban_score,
                        session.as_deref(),
                    )
                    .await?;
                    if ban_score >= BAN_SCORE_THRESHOLD {
                        rbitcoin_log::warn!(
                            "p2p: {peer_s} ban score {ban_score} ≥ {BAN_SCORE_THRESHOLD} — disconnect"
                        );
                        return Err(NetError::Protocol("peer ban score threshold"));
                    }
                }
            }
        }
    }
    .await;

    drop(out_tx);
    // If select! already joined the writer, do not await again (would pend).
    if writer_task.is_finished() {
        drop(writer_task);
    } else {
        writer_task.abort();
        let _ = writer_task.await;
    }
    match &result {
        Ok(()) => rbitcoin_log::debug!("p2p: session {peer_s} closed"),
        Err(e) => rbitcoin_log::warn!("p2p: session {peer_s} ended: {e}"),
    }
    result
}

/// Tip locator for post-handshake `getheaders` (store chain; genesis fallback).
pub(crate) fn tip_follow_locator(hub: &ChainHub) -> Vec<BlockHash> {
    match hub.query.locator_hashes() {
        Ok(mut v) if !v.is_empty() => {
            if v.len() > MAX_LOCATOR_SZ {
                v.truncate(MAX_LOCATOR_SZ);
            }
            v
        }
        _ => {
            let mut v = Vec::new();
            if let Some(t) = hub.tip_hash() {
                v.push(t);
            }
            v.push(BlockHash::from_byte_array([0u8; 32]));
            v
        }
    }
}

/// Locator for `getheaders`. `from` is the last header of a full 2000-header
/// reply so the next batch starts after it (Core continues from that hash).
pub(crate) fn headers_sync_locator(hub: &ChainHub, from: Option<BlockHash>) -> Vec<BlockHash> {
    match from {
        None => tip_follow_locator(hub),
        Some(start) => locator_from_start(hub, start),
    }
}

fn locator_from_start(hub: &ChainHub, start: BlockHash) -> Vec<BlockHash> {
    if let Ok(Some(h)) = hub.query.height_of_hash(&start.to_byte_array()) {
        return locator_from_height(hub, h.0);
    }
    let mut out = vec![start];
    push_genesis_locator(hub, &mut out);
    out
}

fn locator_from_height(hub: &ChainHub, start: u32) -> Vec<BlockHash> {
    let mut out = Vec::new();
    let mut h = start as i64;
    let mut step = 1i64;
    while h >= 0 {
        match hub.query.header_at_height(Height(h as u32)) {
            Ok(Some((_, rec))) => out.push(BlockHash::from_byte_array(rec.hash)),
            _ => break,
        }
        if out.len() >= 10 {
            step *= 2;
        }
        h -= step;
        if out.len() >= MAX_LOCATOR_SZ {
            break;
        }
    }
    push_genesis_locator(hub, &mut out);
    out
}

fn push_genesis_locator(hub: &ChainHub, out: &mut Vec<BlockHash>) {
    let g = hub
        .query
        .header_at_height(Height::GENESIS)
        .ok()
        .flatten()
        .map(|(_, rec)| BlockHash::from_byte_array(rec.hash))
        .unwrap_or_else(|| BlockHash::from_byte_array([0u8; 32]));
    if out.last() != Some(&g) {
        out.push(g);
    }
}

/// Periodic getheaders is for discovering more work. Skip peers whose best
/// known header is already on our chain behind tip, or a connecting fork that
/// cannot beat us.
pub(crate) fn should_poll_peer_headers(hub: &ChainHub, best_known: Option<BlockHash>) -> bool {
    let Some(best) = best_known else {
        return true;
    };
    let our_tip = hub.tip_height().unwrap_or(0);
    if let Ok(Some(h)) = hub.query.height_of_hash(&best.to_byte_array()) {
        return h.0 >= our_tip;
    }
    let empty = HashMap::new();
    !matches!(
        header_branch_vs_tip(hub, &empty, best),
        Some(std::cmp::Ordering::Less)
    )
}

/// Start Core initial headers-sync on this session if we are allowed to.
fn maybe_queue_initial_getheaders(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
) -> bool {
    if session.conn_type == crate::peers::PeerConnType::AddrFetch {
        return false;
    }
    if session.is_sync_started() {
        return false;
    }
    let now = session.clock_now();
    let best_t = hub.tip_header().map(|h| u64::from(h.time)).unwrap_or(0);
    let started = session
        .hub()
        .is_some_and(|ph| ph.try_start_headers_sync(session, now, best_t));
    if started {
        let h = hub.tip_height().unwrap_or(0);
        rbitcoin_log::info!("{}", crate::chain::initial_getheaders_log(h, session.id));
        let _ = queue_getheaders(out, hub, Some(session), true, None);
    }
    started
}

fn maybe_queue_addrfetch_getaddr(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    session: &crate::peers::LivePeer,
) -> bool {
    if session.conn_type != crate::peers::PeerConnType::AddrFetch {
        return false;
    }
    let _ = queue_out(out, NetworkMessage::GetAddr);
    true
}

fn addrfetch_timed_out(session: &crate::peers::LivePeer) -> bool {
    session.conn_type == crate::peers::PeerConnType::AddrFetch
        && session.clock_now().saturating_sub(session.connected_at()) > ADDRFETCH_TIMEOUT_SECS
}

fn queue_getheaders(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    mark_awaiting: bool,
    from: Option<BlockHash>,
) -> Result<(), NetError> {
    if mark_awaiting {
        if let Some(s) = session {
            // Core `MaybeSendGetHeaders`: one in-flight getheaders at a time
            // (or after HEADERS_RESPONSE_TIME = 2 min).
            if s.is_awaiting_headers() {
                return Ok(());
            }
            s.note_awaiting_headers();
        }
    }
    let locator = headers_sync_locator(hub, from);
    let gh = GetHeadersMessage::new(locator, BlockHash::from_byte_array([0u8; 32]));
    queue_out(out, NetworkMessage::GetHeaders(gh))
}

/// BIP152: request `MSG_CMPCT_BLOCK` when the peer speaks compact v2 and we
/// relay txs. `-blocksonly` keeps `MSG_WITNESS_BLOCK` (`p2p_compactblocks_blocksonly`).
fn getdata_use_compact(hub: &ChainHub, peer_cmpct_version: u32) -> bool {
    peer_cmpct_version == 2 && hub.mempool().is_none_or(|m| m.relay_enabled())
}

fn queue_block_getdata(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<NetworkMessage>,
    requested_blocks: &mut HashSet<BlockHash>,
    want: &[BlockHash],
    compact: bool,
) -> Result<(), NetError> {
    if want.is_empty() {
        return Ok(());
    }
    let inv: Vec<Inventory> = want
        .iter()
        .map(|h| {
            if compact {
                Inventory::CompactBlock(*h)
            } else {
                Inventory::WitnessBlock(*h)
            }
        })
        .collect();
    for h in want {
        requested_blocks.insert(*h);
        hub.note_asked_block(*h);
    }
    for chunk in inv.chunks(MAX_INV_SIZE.min(500)) {
        queue_out(out, NetworkMessage::GetData(chunk.to_vec()))?;
    }
    Ok(())
}

/// Incomplete compact block waiting for `blocktxn`.
struct PendingCmpct {
    hsi: HeaderAndShortIds,
    missing: Vec<u64>,
    /// BIP152 version (1 = txid short-ids, 2 = wtxid).
    version: u32,
}

/// Clone only mempool bodies whose short-ids appear in `hsi` (never `list_live`).
fn mempool_shortid_txs(
    hub: &ChainHub,
    header: &bitcoin::block::Header,
    nonce: u64,
    version: u32,
    short_ids: &[bitcoin::bip152::ShortId],
) -> Vec<Transaction> {
    hub.mempool()
        .and_then(|mp| mp.try_clone_matching_shortids(header, nonce, version, short_ids))
        .unwrap_or_default()
}

/// Reconstruct a compact block from prefilled txs plus mempool short-ids.
/// Coinbase-only compact has no short-ids; an empty mempool map still fills.
fn try_fill_cmpct(hub: &ChainHub, hsi: &HeaderAndShortIds, version: u32) -> Option<Block> {
    let live = mempool_shortid_txs(hub, &hsi.header, hsi.nonce, version, &hsi.short_ids);
    let avail = crate::compact::shortid_map_from_txs(&hsi.header, hsi.nonce, version, live.iter());
    crate::compact::try_reconstruct(hsi, &avail, version).ok()
}

/// Absolute indexes still missing after mempool fill (for `getblocktxn`).
///
/// Returns `None` when there is no mempool hub (caller should full-getdata).
/// Returns `Some(empty)` only when reconstruct claimed success with no txs
/// (degenerate); peer path treats empty as getdata fallback.
fn try_cmpct_missing(hub: &ChainHub, hsi: &HeaderAndShortIds, version: u32) -> Option<Vec<u64>> {
    if hub.mempool().is_none() {
        return None;
    }
    let live = mempool_shortid_txs(hub, &hsi.header, hsi.nonce, version, &hsi.short_ids);
    let avail = crate::compact::shortid_map_from_txs(&hsi.header, hsi.nonce, version, live.iter());
    match crate::compact::try_reconstruct(hsi, &avail, version) {
        Ok(_) => Some(Vec::new()),
        Err(m) => Some(m),
    }
}

/// Flush due / unbroadcast tx INVs onto every live session writer.
/// Used by RPC sendraw and whitelist-relay accept (`p2p_blocksonly`).
pub fn flush_tx_invs(hub: &ChainHub, peers: &crate::peers::PeerHub) {
    let rows = peers.live_peers();
    for s in rows {
        s.request_tx_inv();
        if let Some(out) = s.writer() {
            queue_due_tx_invs(hub, s.as_ref(), &HashMap::new(), &out);
        }
    }
}

/// INV one live mempool tx to every peer that has not seen it, ignoring the
/// inbound age gate and `inv_gen_floor` (Core same-nonwitness rebroadcast).
pub fn force_announce_txid(hub: &ChainHub, peers: &crate::peers::PeerHub, txid: bitcoin::Txid) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    let Some(tx) = mp.try_get_tx(&txid) else {
        return;
    };
    let w = tx.compute_wtxid();
    for s in peers.live_peers() {
        if s.conn_type == crate::peers::PeerConnType::BlockRelay {
            continue;
        }
        if s.has_announced_wtx(&w) {
            continue;
        }
        let peer_min = s.minfeefilter_sat_kvb();
        if peer_min > 0 {
            if let Some((fee, weight)) = mp.try_get_live_meta(&txid) {
                let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee, weight);
                if rate < peer_min {
                    continue;
                }
            }
        }
        let Some(out) = s.writer() else {
            continue;
        };
        s.note_announced_wtx(w);
        let _ = queue_out(&out, NetworkMessage::Inv(vec![Inventory::WTx(w)]));
        if let Some(seq) = mp.relay_seq_of(&w) {
            s.note_tx_inv_seq(s.last_inv_sequence().max(seq.saturating_add(1)));
        }
    }
}

fn tx_inv_candidate_ok(
    mp: &crate::tx_relay::MempoolHub,
    session: &crate::peers::LivePeer,
    from_this_peer: &HashMap<bitcoin::Txid, ()>,
    txid: bitcoin::Txid,
    w: bitcoin::Wtxid,
    clock_due: bool,
    inbound_age_gate: bool,
) -> bool {
    if from_this_peer.contains_key(&txid) {
        return false;
    }
    if session.conn_type == crate::peers::PeerConnType::BlockRelay {
        return false;
    }
    if !mp.relay_enabled() && !mp.is_unbroadcast(&txid) {
        return false;
    }
    if session.has_announced_wtx(&w) {
        return false;
    }
    if mp
        .accept_gen(&w)
        .is_some_and(|g| g < session.inv_gen_floor())
    {
        return false;
    }
    let peer_min = session.minfeefilter_sat_kvb();
    if peer_min > 0 {
        if let Some((fee, weight)) = mp.try_get_live_meta(&txid) {
            let rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(fee, weight);
            if rate < peer_min {
                return false;
            }
        }
    }
    let local = !mp.relay_enabled() && mp.is_unbroadcast(&txid);
    let age_due_this = mp.tx_inv_due(&w);
    if inbound_age_gate {
        if !age_due_this {
            return false;
        }
    } else if !clock_due && !local && !age_due_this {
        return false;
    }
    true
}

fn queue_due_tx_invs(
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
    from_this_peer: &HashMap<bitcoin::Txid, ()>,
    out_tx: &mpsc::UnboundedSender<NetworkMessage>,
) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    if session.conn_type == crate::peers::PeerConnType::BlockRelay {
        return;
    }
    // `-blocksonly` (relay off) still INV locally submitted (unbroadcast)
    // txs immediately (`p2p_blocksonly.py:48`). When relay is on, inbound
    // keeps the 30s age gate (`mempool_reorg.py:71`).
    let now = session.clock_now();
    let clock_due = session.take_tx_inv_due(now);
    let age_due = mp.any_tx_inv_due();
    let unbroadcast_due = !mp.relay_enabled() && mp.unbroadcast_count() > 0;
    if !clock_due && !age_due && !unbroadcast_due {
        return;
    }
    let inbound_age_gate =
        session.inbound && mp.relay_enabled() && !session.hub().is_some_and(|h| h.is_noban());
    let mut n = 0u32;
    let mut max_ann = session.last_inv_sequence();
    let mp_now = mp.relay_now_secs();
    if clock_due || unbroadcast_due {
        let Some(live_wtx) = mp.try_list_live_wtxids() else {
            return;
        };
        for (txid, w) in live_wtx {
            if !tx_inv_candidate_ok(
                mp,
                session,
                from_this_peer,
                txid,
                w,
                clock_due,
                inbound_age_gate,
            ) {
                continue;
            }
            session.note_announced_wtx(w);
            let _ = queue_out(out_tx, NetworkMessage::Inv(vec![Inventory::WTx(w)]));
            n += 1;
            if let Some(seq) = mp.relay_seq_of(&w) {
                max_ann = max_ann.max(seq.saturating_add(1));
            }
        }
        if let Some((due, gen)) = mp.try_age_inv_watermark(mp_now) {
            session.note_age_inv_seen(due, gen);
        }
    } else {
        let Some((last, due_wtx)) = mp.try_age_inv_since(session.age_inv_seen(), mp_now) else {
            return;
        };
        session.note_age_inv_seen(last.0, last.1);
        for (txid, w) in due_wtx {
            if !tx_inv_candidate_ok(
                mp,
                session,
                from_this_peer,
                txid,
                w,
                false,
                inbound_age_gate,
            ) {
                continue;
            }
            session.note_announced_wtx(w);
            let _ = queue_out(out_tx, NetworkMessage::Inv(vec![Inventory::WTx(w)]));
            n += 1;
            if let Some(seq) = mp.relay_seq_of(&w) {
                max_ann = max_ann.max(seq.saturating_add(1));
            }
        }
    }
    if n > 0 {
        // Core `m_last_inv_sequence`: only txs that existed at INV time.
        // Never snap to current_relay_seq() — a later accept can race in
        // and make the new entry servable (mempool_reorg.py:122).
        session.note_tx_inv_seq(max_ann.max(session.last_inv_sequence()));
    }
}

/// Finish a pending compact block with a `blocktxn` payload.
fn apply_cmpct_blocktxn(
    hub: &ChainHub,
    pc: &PendingCmpct,
    bt: &BlockTransactions,
) -> Result<Block, ()> {
    let live = mempool_shortid_txs(
        hub,
        &pc.hsi.header,
        pc.hsi.nonce,
        pc.version,
        &pc.hsi.short_ids,
    );
    let avail =
        crate::compact::shortid_map_from_txs(&pc.hsi.header, pc.hsi.nonce, pc.version, live.iter());
    crate::compact::apply_block_transactions(&pc.hsi, &pc.missing, bt, &avail, pc.version)
        .map_err(|_| ())
}

async fn handle_peer_frame(
    frame: FramedMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<NetworkMessage>,
    peer_wants_headers: &mut bool,
    peer_wtxid_relay: &mut bool,
    peer_send_cmpct: &mut bool,
    peer_cmpct_version: &mut u32,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
    pending_blocks: &mut PendingBlocks,
    pending_cmpct: &mut HashMap<BlockHash, PendingCmpct>,
    from_this_peer: &mut HashMap<bitcoin::Txid, ()>,
    requested_blocks: &mut HashSet<BlockHash>,
    ban_score: &mut u32,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let msg = match decode_framed_offload(frame).await {
        Ok(m) => m,
        Err(NetError::MessageTooLarge(n)) => {
            *ban_score = ban_score.saturating_add(OVERSIZE_BAN_SCORE);
            return Err(NetError::MessageTooLarge(n));
        }
        Err(e) => return Err(e),
    };
    match msg.payload() {
        NetworkMessage::Version(_) => {
            if let Some(s) = session {
                rbitcoin_log::info!("redundant version message from peer={}", s.id);
            } else {
                rbitcoin_log::info!("redundant version message from peer");
            }
        }
        NetworkMessage::Verack => {
            if let Some(s) = session {
                rbitcoin_log::info!("ignoring redundant verack message from peer={}", s.id);
            } else {
                rbitcoin_log::info!("ignoring redundant verack message");
            }
        }
        NetworkMessage::Ping(n) => {
            if let Some(s) = session {
                queue_due_tx_invs(hub, s, from_this_peer, out_tx);
                // Noban headers-timeout reset: Core re-issues getheaders in the
                // same SendMessages turn; hook the ping so the official test
                // sees it before sync_with_ping returns.
                let _ = maybe_queue_initial_getheaders(out_tx, hub, s);
            }
            queue_out(out_tx, NetworkMessage::Pong(*n))?;
        }
        NetworkMessage::Pong(_) => {}
        NetworkMessage::FeeFilter(amt) => {
            if let Some(s) = session {
                s.note_minfeefilter_sat_kvb((*amt).max(0) as u64);
            }
        }
        NetworkMessage::SendHeaders => {
            *peer_wants_headers = true;
        }
        NetworkMessage::SendCmpct(sc) => {
            // Segwit networks: only version 2 (wtxid short-ids) enables HB.
            // Version 1 and version > 2 are ignored (p2p_compactblocks).
            if sc.version == 2 {
                *peer_send_cmpct = sc.send_compact;
                *peer_cmpct_version = 2;
                if let Some(sess) = session {
                    sess.set_hb_from(sc.send_compact);
                }
            }
        }
        NetworkMessage::WtxidRelay => {
            // BIP339 mutual: we already sent wtxidrelay pre-verack; remember theirs.
            *peer_wtxid_relay = true;
        }
        NetworkMessage::SendAddrV2 => {
            // BIP155: we advertise sendaddrv2 pre-verack; inbound advertise is enough.
        }
        NetworkMessage::Addr(list) => {
            if session.is_some_and(|s| {
                s.conn_type == crate::peers::PeerConnType::AddrFetch && list.len() > 1
            }) {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
        }
        NetworkMessage::AddrV2(list) => {
            if session.is_some_and(|s| {
                s.conn_type == crate::peers::PeerConnType::AddrFetch && list.len() > 1
            }) {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
        }
        NetworkMessage::GetHeaders(gh) => {
            if gh.locator_hashes.len() > MAX_LOCATOR_SZ {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            let headers = headers_reply_for_getheaders(hub, gh)?;
            let withhold_stale = headers.is_empty()
                && gh.locator_hashes.is_empty()
                && gh.stop_hash.to_byte_array() != [0u8; 32]
                && hub.header_of(&gh.stop_hash).is_some()
                && !hub.stale_relay_allowed(&gh.stop_hash);
            if !withhold_stale {
                if let Some(s) = session {
                    if let Some(last) = headers.last() {
                        s.note_best_header_sent(last.block_hash());
                    } else if let Some(tip) = hub.tip_hash() {
                        s.note_best_header_sent(tip);
                    }
                }
                queue_out(out_tx, NetworkMessage::Headers(headers))?;
            }
        }
        NetworkMessage::GetBlocks(gb) => {
            if gb.locator_hashes.len() > MAX_LOCATOR_SZ {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            let headers = headers_for_peer(
                hub.cache.as_ref(),
                hub.query.as_ref(),
                &GetHeadersMessage {
                    version: gb.version,
                    locator_hashes: gb.locator_hashes.clone(),
                    stop_hash: gb.stop_hash,
                },
            )?;
            let inv: Vec<Inventory> = headers
                .into_iter()
                .take(500)
                .map(|h| Inventory::WitnessBlock(h.block_hash()))
                .collect();
            if !inv.is_empty() {
                queue_out(out_tx, NetworkMessage::Inv(inv))?;
            }
        }
        NetworkMessage::GetData(inv) => {
            let inflight = session.map(|s| &s.serve_inflight);
            for item in inv.iter().take(MAX_INV_SIZE) {
                match item {
                    Inventory::Block(h) | Inventory::WitnessBlock(h) => {
                        if inflight.is_some_and(|n| n.load(Ordering::SeqCst) >= MAX_SERVE_BLOCKS) {
                            continue;
                        }
                        if !hub.stale_relay_allowed(h) {
                            continue;
                        }
                        if let Some(block) =
                            block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), h)?
                        {
                            let _ = try_queue_served_block(
                                out_tx,
                                inflight,
                                NetworkMessage::Block(block),
                            )?;
                        }
                    }
                    Inventory::CompactBlock(h) => {
                        if inflight.is_some_and(|n| n.load(Ordering::SeqCst) >= MAX_SERVE_BLOCKS) {
                            continue;
                        }
                        if let Some(block) =
                            block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), h)?
                        {
                            // Core `MAX_CMPCTBLOCK_DEPTH` (5): older tips get a
                            // full `block` (`p2p_compactblocks` :689).
                            const MAX_CMPCTBLOCK_DEPTH: u32 = 5;
                            let tip_h = hub.tip_height().unwrap_or(0);
                            let block_h = hub
                                .query
                                .height_of_hash(&h.to_byte_array())
                                .ok()
                                .flatten()
                                .map(|ht| ht.0)
                                .unwrap_or(0);
                            if tip_h.saturating_sub(block_h) > MAX_CMPCTBLOCK_DEPTH {
                                let _ = try_queue_served_block(
                                    out_tx,
                                    inflight,
                                    NetworkMessage::Block(block),
                                )?;
                            } else {
                                let ver = (*peer_cmpct_version).max(1).min(2);
                                if let Ok(hsi) =
                                    HeaderAndShortIds::from_block(&block, rand_nonce(), ver, &[0])
                                {
                                    let _ = try_queue_served_block(
                                        out_tx,
                                        inflight,
                                        NetworkMessage::CmpctBlock(CmpctBlock {
                                            compact_block: hsi,
                                        }),
                                    )?;
                                } else {
                                    let _ = try_queue_served_block(
                                        out_tx,
                                        inflight,
                                        NetworkMessage::Block(block),
                                    )?;
                                }
                            }
                        }
                    }
                    Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                        if let Some(mp) = hub.mempool() {
                            if let Some(tx) = mp.try_get_tx(txid) {
                                let w = tx.compute_wtxid();
                                let announced = session.is_some_and(|s| s.has_announced_wtx(&w));
                                let last_inv = session.map(|s| s.last_inv_sequence()).unwrap_or(1);
                                // Core FindTxForGetData: info_for_relay (seq < last
                                // INV) plus announced-to-this-peer. Reorg-reaccept
                                // uses seq=0 (servable while last_inv starts at 1);
                                // do not keep a sticky reorg set — a later regular
                                // accept of the same wtxid must notfound
                                // (mempool_reorg.py:122).
                                if announced || mp.is_relay_servable(&w, last_inv) {
                                    mp.mark_broadcast(txid);
                                    queue_out(out_tx, NetworkMessage::Tx(tx))?;
                                } else {
                                    queue_out(
                                        out_tx,
                                        NetworkMessage::NotFound(vec![item.clone()]),
                                    )?;
                                }
                            } else {
                                queue_out(out_tx, NetworkMessage::NotFound(vec![item.clone()]))?;
                            }
                        }
                    }
                    Inventory::WTx(wtxid) => {
                        if let Some(s) = session {
                            rbitcoin_log::trace!("{}", received_getdata_wtx_log(wtxid, s.id));
                        }
                        if let Some(mp) = hub.mempool() {
                            if let Some(tx) = mp.try_get_tx_by_wtxid(wtxid) {
                                let announced = session.is_some_and(|s| s.has_announced_wtx(wtxid));
                                let last_inv = session.map(|s| s.last_inv_sequence()).unwrap_or(1);
                                if announced || mp.is_relay_servable(wtxid, last_inv) {
                                    mp.mark_broadcast(&tx.compute_txid());
                                    queue_out(out_tx, NetworkMessage::Tx(tx))?;
                                } else {
                                    queue_out(
                                        out_tx,
                                        NetworkMessage::NotFound(vec![item.clone()]),
                                    )?;
                                }
                            } else {
                                queue_out(out_tx, NetworkMessage::NotFound(vec![item.clone()]))?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        NetworkMessage::GetBlockTxn(GetBlockTxn { txs_request }) => {
            // Serve missing txs for a compact block we hold (BIP152).
            let hash = txs_request.block_hash;
            let block = match block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &hash) {
                Ok(b) => b,
                Err(e) => {
                    rbitcoin_log::warn!("p2p: getblocktxn reconstruct {hash}: {e}");
                    None
                }
            };
            if let Some(block) = block {
                let mut transactions = Vec::with_capacity(txs_request.indexes.len());
                let mut bad = false;
                for idx in &txs_request.indexes {
                    let i = *idx as usize;
                    match block.txdata.get(i) {
                        Some(tx) => transactions.push(tx.clone()),
                        None => {
                            bad = true;
                            break;
                        }
                    }
                }
                if bad {
                    rbitcoin_log::info!("getblocktxn with out-of-bounds tx indices");
                    // Core Misbehaving: disconnect (p2p_compactblocks :643).
                    *ban_score = ban_score.saturating_add(BAN_SCORE_THRESHOLD);
                    if let Some(s) = session {
                        s.request_disconnect();
                    }
                } else {
                    // Core: past `MAX_GETBLOCKTXN_DEPTH` (10) send the full block.
                    const MAX_GETBLOCKTXN_DEPTH: u32 = 10;
                    let tip_h = hub.tip_height().unwrap_or(0);
                    let block_h = hub
                        .query
                        .height_of_hash(&hash.to_byte_array())
                        .ok()
                        .flatten()
                        .map(|h| h.0)
                        .unwrap_or(0);
                    if tip_h.saturating_sub(block_h) > MAX_GETBLOCKTXN_DEPTH {
                        queue_out(out_tx, NetworkMessage::Block(block))?;
                    } else {
                        queue_out(
                            out_tx,
                            NetworkMessage::BlockTxn(BlockTxn {
                                transactions: BlockTransactions {
                                    block_hash: hash,
                                    transactions,
                                },
                            }),
                        )?;
                    }
                }
            }
        }
        NetworkMessage::Inv(items) => {
            let mut want = Vec::new();
            let mut inv_tx_n = 0u64;
            let mut need_headers = false;
            let mut tx_inv_hex: Option<String> = None;
            let relay = !hub.in_ibd()
                && (hub.mempool().map(|m| m.relay_enabled()).unwrap_or(false)
                    || session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_relay_perm())));
            for item in items.iter().take(MAX_INV_SIZE) {
                match item {
                    Inventory::Block(h) | Inventory::WitnessBlock(h) => {
                        if let Some(s) = session {
                            s.note_block_from_peer(*h);
                            s.note_best_known(*h);
                        }
                        if !hub.is_connected(h) {
                            if !hub.knows_header(h) && !pending_headers.contains_key(h) {
                                if session.is_none_or(|s| {
                                    s.hub()
                                        .is_some_and(|ph| ph.should_getheaders_for_inv(s, *h))
                                }) {
                                    need_headers = true;
                                }
                            } else {
                                // Have a header: do not getdata from inv. Bodies
                                // come from header-announcement direct fetch
                                // (BIP130) or a getheaders reply. Inv of a
                                // known hash from a second peer (p2p_sendheaders
                                // inv_node) must not steal or duplicate getdata.
                            }
                        }
                    }
                    Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                        if tx_inv_hex.is_none() {
                            tx_inv_hex = Some(txid.to_string());
                        }
                        if relay {
                            if let Some(mp) = hub.mempool() {
                                if !mp.try_contains(txid) {
                                    want.push(Inventory::WitnessTransaction(*txid));
                                    inv_tx_n = inv_tx_n.saturating_add(1);
                                }
                            }
                        }
                    }
                    Inventory::WTx(wtxid) => {
                        if tx_inv_hex.is_none() {
                            tx_inv_hex = Some(wtxid.to_string());
                        }
                        if relay {
                            if let Some(mp) = hub.mempool() {
                                if !mp.try_contains_wtxid(wtxid) {
                                    want.push(Inventory::WTx(*wtxid));
                                    inv_tx_n = inv_tx_n.saturating_add(1);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(mp) = hub.mempool() {
                mp.note_inv_tx(inv_tx_n);
                let gd_tx = want
                    .iter()
                    .filter(|i| {
                        matches!(
                            i,
                            Inventory::Transaction(_)
                                | Inventory::WitnessTransaction(_)
                                | Inventory::WTx(_)
                        )
                    })
                    .count() as u64;
                mp.note_getdata_tx(gd_tx);
            }
            if let Some(hx) = tx_inv_hex {
                if reject_unsolicited_tx(hub, session) {
                    rbitcoin_log::info!(
                        "transaction ({hx}) inv sent in violation of protocol, disconnecting peer"
                    );
                    punish_disconnect(ban_score, session);
                    return Ok(());
                }
            }
            if need_headers {
                let _ = queue_getheaders(out_tx, hub, session, true, None);
            }
            if !want.is_empty() {
                queue_out(out_tx, NetworkMessage::GetData(want))?;
            }
        }
        NetworkMessage::Headers(headers) => {
            let n = headers.len();
            let _ = session.is_some_and(|s| s.take_awaiting_headers());
            if n == 0 {
                // Empty headers is a failed getheaders response, not an announcement.
            } else if let Some(first) = headers.first() {
                let prev = first.prev_blockhash;
                if hub.is_block_invalid(&prev)
                    || headers
                        .iter()
                        .take(n)
                        .any(|h| hub.is_block_invalid(&h.block_hash()))
                {
                    // Headers on a cached-invalid chain: disconnect
                    // (`p2p_unrequested_blocks` step 8 follow-up header).
                    punish_disconnect(ban_score, session);
                    return Ok(());
                }
                let connecting = header_announcement_connects(hub, pending_headers, prev);
                for hdr in headers.iter().take(n) {
                    let hash = hdr.block_hash();
                    if let Some(s) = session {
                        s.note_block_from_peer(hash);
                        s.note_best_known(hash);
                    }
                    if pending_headers.len() >= MAX_PENDING_HEADERS
                        && !pending_headers.contains_key(&hash)
                    {
                        pending_headers.clear();
                    }
                    pending_headers.insert(hash, *hdr);
                }
                if !connecting {
                    if n < MAX_HEADERS_RESULTS {
                        let _ = queue_getheaders(out_tx, hub, session, true, None);
                    }
                } else {
                    let last = headers[n - 1].block_hash();
                    // Core `chain_start.nHeight + headers.size()`. One-header
                    // tip announces still accumulate via `pending_headers`
                    // (`p2p_headers_sync_with_minchainwork` height=14).
                    let announced_h = announced_headers_height(hub, pending_headers, last);
                    let noban = session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_noban()));
                    let work_cmp = announced_work_cmp(hub, pending_headers, last);
                    let our_tip = hub.tip_height().unwrap_or(0);
                    if announced_tip_is_hopeless(our_tip, announced_h, work_cmp) && !noban {
                        rbitcoin_log::info!(
                            "p2p: disconnect stale fork tip announced={announced_h} our={our_tip}"
                        );
                        if let Some(s) = session {
                            s.request_disconnect();
                        }
                        return Ok(());
                    }
                    if !header_path_meets_minwork(hub, pending_headers, last) {
                        if noban {
                            persist_pending_header_path(hub, pending_headers, last);
                            rbitcoin_log::info!("{}", synchronizing_blockheaders_log(announced_h));
                        } else {
                            rbitcoin_log::info!("{}", ignoring_low_work_chain_log(announced_h));
                        }
                        // Core: do not download bodies until the chain meets
                        // `-minimumchainwork` (`p2p_headers_sync_with_minchainwork`).
                    } else {
                        persist_pending_header_path(hub, pending_headers, last);
                        rbitcoin_log::info!("{}", synchronizing_blockheaders_log(announced_h));
                        let mut want = fetchable_header_path_bodies(
                            hub,
                            pending_headers,
                            last,
                            pending_blocks,
                            requested_blocks,
                        );
                        want.truncate(MAX_SERVE_BLOCKS.saturating_sub(requested_blocks.len()));
                        queue_block_getdata(
                            hub,
                            out_tx,
                            requested_blocks,
                            &want,
                            getdata_use_compact(hub, *peer_cmpct_version),
                        )?;
                    }
                }
            }
            if n >= MAX_HEADERS_RESULTS {
                let from = headers.get(n - 1).map(|h| h.block_hash());
                let _ = queue_getheaders(out_tx, hub, session, true, from);
            }
        }
        NetworkMessage::Block(block) => {
            let hash = block.block_hash();
            if let Some(s) = session {
                s.note_block_from_peer(hash);
                s.note_best_known(hash);
                s.note_last_block();
            }
            if !requested_blocks.contains(&hash) {
                if hub.header_below_minwork(&block.header) {
                    rbitcoin_log::info!("{}", accept_block_header_nodos_log(hash));
                    return Ok(());
                }
                let prev = block.header.prev_blockhash;
                if prev.to_byte_array() != [0u8; 32]
                    && !hub.knows_header(&prev)
                    && !pending_headers.contains_key(&prev)
                {
                    return Err(NetError::Protocol(
                        "unrequested block with missing parent header",
                    ));
                }
                if hub.unrequested_weaker_than_tip(&block.header) {
                    let _ = hub.ensure_header(&block.header);
                    return Ok(());
                }
                if hub.unrequested_too_far_ahead(&block.header) {
                    let _ = hub.ensure_header(&block.header);
                    return Ok(());
                }
            }
            let _ = hub.ensure_header(&block.header);
            pending_cmpct.remove(&hash);
            requested_blocks.remove(&hash);
            pending_headers.entry(hash).or_insert(block.header);
            if !any_header_path_meets_minwork(hub, pending_headers, hash) {
                pending_blocks.insert(hash, block.clone());
                return Ok(());
            }
            relay_new_pow_valid_block(hub, block, session);
            match hub.accept_received_block_async(block.clone()).await {
                Ok(AcceptOutcome::Accepted { .. }) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    maybe_select_hb_if_relay(hub, session);
                    drain_pending(
                        hub,
                        out_tx,
                        pending_blocks,
                        pending_headers,
                        requested_blocks,
                        getdata_use_compact(hub, *peer_cmpct_version),
                        session,
                    )
                    .await?;
                }
                Ok(AcceptOutcome::AlreadyHave) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    drain_pending(
                        hub,
                        out_tx,
                        pending_blocks,
                        pending_headers,
                        requested_blocks,
                        getdata_use_compact(hub, *peer_cmpct_version),
                        session,
                    )
                    .await?;
                }
                Ok(AcceptOutcome::IgnoredWeaker) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    drain_pending(
                        hub,
                        out_tx,
                        pending_blocks,
                        pending_headers,
                        requested_blocks,
                        getdata_use_compact(hub, *peer_cmpct_version),
                        session,
                    )
                    .await?;
                }
                Err(e) if net_error_is_store_not_found(&e) => {
                    rbitcoin_log::warn!(
                        "p2p: accept dropped {hash} (store not found — keep session): {e}"
                    );
                }
                Err(e) => {
                    // Rule rejects (`bad-txns-nonfinal`, BIP68/112 locktime,
                    // `feature_csv_activation`) must keep the session so the
                    // peer can send the next block. Cached-invalid is still
                    // noted; compact children of a failed hash still disconnect.
                    rbitcoin_log::warn!("p2p: accept dropped {hash} (invalid — keep session): {e}");
                }
            }
        }
        NetworkMessage::CmpctBlock(cb) => {
            let hsi = cb.compact_block.clone();
            let hash = hsi.header.block_hash();
            if let Some(s) = session {
                s.note_block_from_peer(hash);
                s.note_best_known(hash);
                s.note_last_block();
            }
            if !crate::compact::prefilled_indexes_ok(&hsi) {
                rbitcoin_log::info!("invalid index in cmpctblock message");
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            // Child of a cached-invalid block: Core `BLOCK_INVALID_PREV`.
            // Same-hash cached invalid via compact stays connected
            // (`p2p_compactblocks` `test_invalid_tx_in_compactblock`).
            if hub.is_block_invalid(&hsi.header.prev_blockhash) {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            if hub.is_block_invalid(&hash) {
                return Ok(());
            }
            if hsi.header.prev_blockhash.to_byte_array() != [0u8; 32]
                && !hub.knows_header(&hsi.header.prev_blockhash)
            {
                // Better-work compact of a long fork announces only the
                // tip (`mempool_reorg` 20-block submitblock). Ask for the
                // header path before reconstruct.
                let _ = queue_getheaders(out_tx, hub, session, true, None);
            }
            pending_headers.entry(hash).or_insert(hsi.header);
            if !any_header_path_meets_minwork(hub, pending_headers, hash) {
                // Below -minimumchainwork: keep header, do not reconstruct/accept.
            } else {
                let mut ancestors: Vec<BlockHash> = fetchable_header_path_bodies(
                    hub,
                    pending_headers,
                    hash,
                    pending_blocks,
                    requested_blocks,
                )
                .into_iter()
                .filter(|h| *h != hash)
                .collect();
                ancestors.truncate(MAX_SERVE_BLOCKS.saturating_sub(requested_blocks.len()));
                queue_block_getdata(
                    hub,
                    out_tx,
                    requested_blocks,
                    &ancestors,
                    getdata_use_compact(hub, *peer_cmpct_version),
                )?;
                if compact_header_low_work(hub, &hsi.header) {
                    let id = session.map(|s| s.id).unwrap_or(0);
                    rbitcoin_log::info!("Ignoring low-work compact block from peer {id}");
                } else if hub.tip_hash() != Some(hsi.header.prev_blockhash)
                    && hub.tip_hash() != Some(hash)
                    && !requested_blocks.contains(&hash)
                    && hub.unrequested_weaker_than_tip(&hsi.header)
                {
                    // Unsolicited weaker compact that does not extend our tip:
                    // header-only (fingerprint / stale). A better-work fork
                    // must reconstruct (`p2p_sendheaders` mine_reorg).
                    let prev = hsi.header.prev_blockhash;
                    if hub.knows_header(&prev) || pending_headers.contains_key(&prev) {
                        let _ = hub.ensure_header(&hsi.header);
                    } else {
                        let _ = queue_getheaders(out_tx, hub, session, false, None);
                    }
                } else if hub.has_block(&hash) {
                    requested_blocks.remove(&hash);
                } else if let Some(block) = try_fill_cmpct(hub, &hsi, 2) {
                    requested_blocks.remove(&hash);
                    pending_cmpct.remove(&hash);
                    relay_new_pow_valid_block(hub, &block, session);
                    let accepted = matches!(
                        hub.accept_received_block_async(block).await,
                        Ok(AcceptOutcome::Accepted { .. })
                    );
                    if accepted {
                        maybe_select_hb_if_relay(hub, session);
                    } else if !hub.knows_header(&hsi.header.prev_blockhash) {
                        // Filled a better-work compact whose parent bodies
                        // we lack (`mempool_reorg` 20-block submitblock).
                        let _ = queue_getheaders(out_tx, hub, session, true, None);
                    }
                    drain_pending(
                        hub,
                        out_tx,
                        pending_blocks,
                        pending_headers,
                        requested_blocks,
                        getdata_use_compact(hub, *peer_cmpct_version),
                        session,
                    )
                    .await?;
                } else if let Some(missing) = try_cmpct_missing(hub, &hsi, 2) {
                    if missing.is_empty() {
                        queue_out(
                            out_tx,
                            NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
                        )?;
                    } else if pending_cmpct.len() >= MAX_PENDING_CMPCT
                        && !pending_cmpct.contains_key(&hash)
                    {
                        *ban_score = ban_score.saturating_add(10);
                        queue_out(
                            out_tx,
                            NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
                        )?;
                    } else {
                        let inbound = session.is_some_and(|s| s.inbound);
                        let may_fill = session
                            .and_then(|s| s.hub())
                            .is_none_or(|ph| ph.try_cmpct_fill_slot(hash, inbound));
                        if !may_fill {
                            // Parallel inbound slot already taken
                            // (`p2p_compactblocks` :929).
                        } else {
                            pending_cmpct.insert(
                                hash,
                                PendingCmpct {
                                    hsi: hsi.clone(),
                                    missing: missing.clone(),
                                    version: 2,
                                },
                            );
                            queue_out(
                                out_tx,
                                NetworkMessage::GetBlockTxn(GetBlockTxn {
                                    txs_request: crate::compact::missing_request(hash, &missing),
                                }),
                            )?;
                        }
                    }
                } else {
                    queue_out(
                        out_tx,
                        NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
                    )?;
                }
            }
        }
        NetworkMessage::BlockTxn(BlockTxn { transactions: bt }) => {
            let hash = bt.block_hash;
            if session.is_some_and(|s| s.has_failed_cmpct(&hash)) {
                rbitcoin_log::info!("previous compact block reconstruction attempt failed");
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            if let Some(pc) = pending_cmpct.remove(&hash) {
                match apply_cmpct_blocktxn(hub, &pc, bt) {
                    Ok(block) => {
                        relay_new_pow_valid_block(hub, &block, session);
                        match hub.accept_received_block_async(block).await {
                            Ok(AcceptOutcome::Accepted { .. }) => {
                                requested_blocks.remove(&hash);
                                maybe_select_hb_if_relay(hub, session);
                                if let Some(s) = session {
                                    if let Some(ph) = s.hub() {
                                        ph.clear_cmpct_fill(hash);
                                    }
                                }
                                drain_pending(
                                    hub,
                                    out_tx,
                                    pending_blocks,
                                    pending_headers,
                                    requested_blocks,
                                    getdata_use_compact(hub, *peer_cmpct_version),
                                    session,
                                )
                                .await?;
                            }
                            Ok(_) => {
                                requested_blocks.remove(&hash);
                                drain_pending(
                                    hub,
                                    out_tx,
                                    pending_blocks,
                                    pending_headers,
                                    requested_blocks,
                                    getdata_use_compact(hub, *peer_cmpct_version),
                                    session,
                                )
                                .await?;
                            }
                            Err(_) => {
                                // Reconstructed but unconnectable (swapped txs):
                                // Core falls back to getdata and remembers the fail
                                // (`p2p_compactblocks` `test_multiple_blocktxn_response`).
                                rbitcoin_log::info!(
                                    "previous compact block reconstruction attempt failed"
                                );
                                if let Some(s) = session {
                                    s.note_failed_cmpct(hash);
                                }
                                *ban_score = ban_score.saturating_add(10);
                                queue_out(
                                    out_tx,
                                    NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
                                )?;
                            }
                        }
                    }
                    Err(()) => {
                        rbitcoin_log::info!("previous compact block reconstruction attempt failed");
                        if let Some(s) = session {
                            s.note_failed_cmpct(hash);
                        }
                        *ban_score = ban_score.saturating_add(10);
                        queue_out(
                            out_tx,
                            NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
                        )?;
                    }
                }
            } else {
                // Unsolicited or late blocktxn — mild penalty.
                *ban_score = ban_score.saturating_add(5);
            }
        }
        NetworkMessage::Tx(tx) => {
            rbitcoin_log::info!("received: tx");
            if hub.in_ibd() {
                return Ok(());
            }
            if reject_unsolicited_tx(hub, session) {
                let id = session.map(|s| s.id).unwrap_or(0);
                rbitcoin_log::info!(
                    "transaction sent in violation of protocol, disconnecting peer={id}"
                );
                punish_disconnect(ban_score, session);
                return Ok(());
            }
            if let Some(mp) = hub.mempool() {
                if mp.relay_enabled()
                    || session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_relay_perm()))
                {
                    let txid = tx.compute_txid();
                    insert_capped_txid(from_this_peer, txid, FROM_THIS_PEER_CAP);
                    match mp.accept_tx_async(tx.clone()).await {
                        Ok(r) => {
                            if let Some(s) = session {
                                s.note_last_transaction();
                            }
                            // Only when P2P relay is off: accept-time announce
                            // is skipped (not yet unbroadcast). Re-announce so
                            // other tx-relay peers INV (`p2p_blocksonly` :74).
                            // Do not do this when relay is on — that INVs every
                            // accepted tx back at the sender and broke
                            // feature_csv_activation (P2PInterface getdata storm).
                            if !mp.relay_enabled() {
                                mp.note_unbroadcast(r.txid);
                                mp.rebroadcast_unbroadcast();
                                mp.notify_inv_flush();
                                if let Some(s) = session {
                                    if let Some(ph) = s.hub() {
                                        flush_tx_invs(hub, ph.as_ref());
                                    }
                                }
                            }
                        }
                        Err(rbitcoin_mempool::AcceptError::Duplicate(_)) => {}
                        Err(e) => {
                            let id = session.map(|s| s.id).unwrap_or(0);
                            rbitcoin_log::info!(
                                "{txid} (wtxid={}) from peer={id} was not accepted: {e}",
                                tx.compute_wtxid()
                            );
                            rbitcoin_log::debug!("txrelay: reject {txid}: {e}");
                        }
                    }
                }
            }
        }
        // No BIP37 bloom product (Core v31 default `-peerbloomfilters=0`).
        // Disconnect peers that send mempool/filter* (`p2p_nobloomfilter_messages.py`).
        NetworkMessage::MemPool
        | NetworkMessage::FilterLoad(_)
        | NetworkMessage::FilterAdd(_)
        | NetworkMessage::FilterClear => {
            punish_disconnect(ban_score, session);
            return Ok(());
        }
        NetworkMessage::GetAddr => {
            let bind = session
                .map(|s| s.addrbind)
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
            let addrs = match session.and_then(|s| s.peer_hub()) {
                Some(hub) => hub.addr_response_for_bind(bind),
                None => Vec::new(),
            };
            queue_out(out_tx, NetworkMessage::Addr(addrs))?;
        }
        NetworkMessage::Unknown { .. } => {}
        _ => {}
    }
    Ok(())
}

#[derive(Debug)]
enum TipAnnounce {
    Headers(Vec<bitcoin::block::Header>),
    Inv(BlockHash),
    Skip,
}

#[derive(Debug)]
pub(crate) enum TipRecvAnnounce {
    Announce(crate::chain::TipEvent),
    Skip,
    Closed,
}

/// Map a `tip_rx.recv()` result to the tip we should announce.
///
/// `Lagged` means missed tip advances — announce the **current** hub tip so the
/// peer can catch up inside functional `sync_blocks` (60s), not via the 120s
/// headers poll.
pub(crate) fn tip_event_for_announce(
    recv: Result<crate::chain::TipEvent, broadcast::error::RecvError>,
    hub: &ChainHub,
) -> TipRecvAnnounce {
    match recv {
        Ok(ev) => TipRecvAnnounce::Announce(ev),
        Err(broadcast::error::RecvError::Closed) => TipRecvAnnounce::Closed,
        Err(broadcast::error::RecvError::Lagged(_)) => {
            match (hub.tip_height(), hub.tip_hash(), hub.tip_header()) {
                (Some(height), Some(hash), Some(header)) => {
                    TipRecvAnnounce::Announce(crate::chain::TipEvent {
                        height,
                        hash,
                        header,
                        reorg_branch_len: 0,
                    })
                }
                _ => TipRecvAnnounce::Skip,
            }
        }
    }
}

fn peer_has_header(
    hub: &ChainHub,
    sent: Option<BlockHash>,
    known: Option<BlockHash>,
    hash: BlockHash,
) -> bool {
    if hash.to_byte_array() == [0u8; 32] {
        return true;
    }
    for mark in [sent, known].into_iter().flatten() {
        if mark == hash || hub.is_header_ancestor(hash, mark) {
            return true;
        }
    }
    false
}

/// BIP152 compact tip announcement (coinbase prefilled) from an in-RAM body.
fn cmpct_announce_from_block(block: &Block, cmpct_version: u32) -> Option<NetworkMessage> {
    let nonce = rand_nonce();
    let hsi =
        HeaderAndShortIds::from_block(block, nonce, cmpct_version.max(1).min(2), &[0]).ok()?;
    Some(NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: hsi,
    }))
}

/// BIP152 compact tip announcement (coinbase prefilled). `None` if the body
/// is not in cache/store yet.
fn cmpct_announce_msg(
    hub: &ChainHub,
    hash: &BlockHash,
    cmpct_version: u32,
) -> Option<NetworkMessage> {
    let block = block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), hash).ok()??;
    cmpct_announce_from_block(&block, cmpct_version)
}

/// Core `NewPoWValidBlock`: send `cmpctblock` to HB peers as soon as a
/// reconstructed/received body has a PoW-valid header that extends our tip,
/// **before** `tip-accept` connect. Does not mark the block connected.
///
/// Only the current tip-child (not a reorg branch). Sender is skipped.
fn relay_new_pow_valid_block(hub: &ChainHub, block: &Block, from: Option<&crate::peers::LivePeer>) {
    if !hub.meets_minimum_chain_work() {
        return;
    }
    if hub.mempool().is_some_and(|m| !m.relay_enabled()) {
        return;
    }
    let hash = block.block_hash();
    if hub.has_block(&hash) {
        return;
    }
    let Some(tip) = hub.tip_hash() else {
        return;
    };
    if block.header.prev_blockhash != tip {
        return;
    }
    if hub.ensure_header(&block.header).is_err() {
        return;
    }
    let Some(ph) = from.and_then(|s| s.hub()) else {
        return;
    };
    let from_id = from.map(|s| s.id);
    for s in ph.live_peers() {
        if from_id == Some(s.id) {
            continue;
        }
        if !s.hb_to.load(Ordering::Relaxed) {
            continue;
        }
        if s.conn_type == crate::peers::PeerConnType::BlockRelay {
            continue;
        }
        let Some(out) = s.writer() else {
            continue;
        };
        let Some(msg) = cmpct_announce_from_block(block, 2) else {
            continue;
        };
        if queue_cmpct_tip_announce(&out, msg).is_ok() {
            s.note_best_header_sent(hash);
        }
    }
}

fn tip_announce_decision(
    hub: &ChainHub,
    ev: &crate::chain::TipEvent,
    wants_headers: bool,
    best_header_sent: Option<BlockHash>,
    best_known: Option<BlockHash>,
    from_this_peer: bool,
) -> TipAnnounce {
    if from_this_peer {
        return TipAnnounce::Skip;
    }
    if ev.reorg_branch_len > MAX_BLOCKS_TO_ANNOUNCE {
        if hub.tip_hash() == Some(ev.hash) {
            return TipAnnounce::Inv(ev.hash);
        }
        return TipAnnounce::Skip;
    }
    if !wants_headers {
        return TipAnnounce::Inv(ev.hash);
    }
    if peer_has_header(hub, best_header_sent, best_known, ev.hash) {
        return TipAnnounce::Skip;
    }
    let mut out = vec![ev.header];
    let mut prev = ev.header.prev_blockhash;
    if peer_has_header(hub, best_header_sent, best_known, prev) {
        return TipAnnounce::Headers(out);
    }
    for _ in 1..MAX_BLOCKS_TO_ANNOUNCE {
        let Some(hdr) = hub.header_of(&prev) else {
            return TipAnnounce::Inv(ev.hash);
        };
        out.push(hdr);
        prev = hdr.prev_blockhash;
        if peer_has_header(hub, best_header_sent, best_known, prev) {
            out.reverse();
            return TipAnnounce::Headers(out);
        }
    }
    TipAnnounce::Inv(ev.hash)
}

fn is_genesis_hash(h: &BlockHash) -> bool {
    h.to_byte_array() == [0u8; 32]
}

/// Walk `pending` toward genesis. Returns the first hash **not** in `pending`
/// and how many pending headers were consumed. Store is not consulted.
fn pending_walk(
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> (BlockHash, u32) {
    let mut h = start;
    let mut steps = 0u32;
    while steps < 10_000 {
        if is_genesis_hash(&h) {
            return (h, steps);
        }
        let Some(hdr) = pending.get(&h) else {
            return (h, steps);
        };
        steps = steps.saturating_add(1);
        h = hdr.prev_blockhash;
    }
    (h, steps)
}

/// Height of `tip` from stored headers or a walk of this peer's pending path.
///
/// Core logs `chain_start.nHeight + headers.size()` on the *batch*. Node-to-node
/// generate announces one header per tip; ignored headers are not stored, so
/// height must come from the pending walk (14 one-header announces → 14).
fn announced_headers_height(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> u32 {
    if is_genesis_hash(&tip) {
        return 0;
    }
    if let Some(h) = hub.header_height(&tip) {
        return h;
    }
    let (join, steps) = pending_walk(pending, tip);
    if is_genesis_hash(&join) {
        return steps;
    }
    hub.header_height(&join).unwrap_or(0).saturating_add(steps)
}

/// Persist `tip`'s pending path oldest-first so `ensure_header` has parents.
fn persist_pending_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) {
    let mut path = Vec::new();
    let mut h = tip;
    for _ in 0..10_000 {
        let Some(hdr) = pending.get(&h) else {
            break;
        };
        path.push(*hdr);
        h = hdr.prev_blockhash;
        if is_genesis_hash(&h) {
            break;
        }
    }
    path.reverse();
    for hdr in &path {
        let _ = hub.ensure_header(hdr);
    }
}

fn header_announcement_connects(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    prev: BlockHash,
) -> bool {
    if is_genesis_hash(&prev) || hub.knows_header(&prev) {
        return true;
    }
    let (join, _) = pending_walk(pending, prev);
    is_genesis_hash(&join) || hub.knows_header(&join)
}

/// Headers more than this many blocks behind our tip are not useful for
/// tip-follow (Core `NODE_NETWORK_LIMITED` window, ~2 days).
pub(crate) const ANCIENT_TIP_BLOCKS: u32 = 288;

/// Connecting header path whose **work** cannot beat our tip and whose announced
/// height is more than [`ANCIENT_TIP_BLOCKS`] behind — BIP-110-class minority fork.
pub(crate) fn announced_tip_is_hopeless(
    our_tip: u32,
    announced_h: u32,
    work_cmp: Option<std::cmp::Ordering>,
) -> bool {
    matches!(work_cmp, Some(std::cmp::Ordering::Less))
        && announced_h.saturating_add(ANCIENT_TIP_BLOCKS) < our_tip
}

/// Announced path work vs our tip work. `None` if the walk cannot sum work.
fn announced_work_cmp(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> Option<std::cmp::Ordering> {
    let announced = work_of_header_path(hub, pending, start)?;
    let ours = hub.chain_work().ok()?;
    Some(announced.cmp(&ours))
}

/// Compare announced header-chain length (equal-bits ≈ work) to our path
/// from the same ancestor. `None` if the header walk does not reach our chain.
fn header_branch_vs_tip(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> Option<std::cmp::Ordering> {
    if hub.is_connected(&start) {
        let ancestor = hub
            .query
            .height_of_hash(&start.to_byte_array())
            .ok()
            .flatten()?
            .0;
        let tip = hub.tip_height()?;
        return Some(0u32.cmp(&tip.saturating_sub(ancestor)));
    }
    let (mut h, mut n_new) = pending_walk(pending, start);
    if is_genesis_hash(&h) {
        return Some(std::cmp::Ordering::Greater);
    }
    for _ in 0..10_000 {
        if hub.is_connected(&h) {
            let ancestor = hub
                .query
                .height_of_hash(&h.to_byte_array())
                .ok()
                .flatten()?
                .0;
            let tip = hub.tip_height()?;
            return Some(n_new.cmp(&tip.saturating_sub(ancestor)));
        }
        let prev = hub.prev_of(&h)?;
        n_new = n_new.saturating_add(1);
        h = prev;
        if is_genesis_hash(&h) {
            return Some(std::cmp::Ordering::Greater);
        }
    }
    None
}

/// Core: do not download/connect a peer's chain until its best-known work
/// meets `-minimumchainwork` (`feature_minchainwork.py`).
fn header_path_meets_minwork(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> bool {
    let Some(min) = hub.min_chain_work_floor() else {
        return true;
    };
    if hub.meets_minimum_chain_work() {
        return true;
    }
    let Some(work) = work_of_header_path(hub, pending, tip) else {
        return false;
    };
    work.to_be_bytes() >= min
}

fn any_header_path_meets_minwork(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    extra_tip: BlockHash,
) -> bool {
    if header_path_meets_minwork(hub, pending, extra_tip) {
        return true;
    }
    pending
        .keys()
        .any(|h| *h != extra_tip && header_path_meets_minwork(hub, pending, *h))
}

fn work_of_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> Option<bitcoin::Work> {
    let mut extra: Vec<bitcoin::Work> = Vec::new();
    let mut h = tip;
    for _ in 0..10_000 {
        if hub.is_connected(&h) {
            let height = hub
                .query
                .height_of_hash(&h.to_byte_array())
                .ok()
                .flatten()?
                .0;
            let base = hub.work_through_height(height).ok()?;
            extra.reverse();
            return Some(crate::most_work::sum_work(
                std::iter::once(base).chain(extra),
            ));
        }
        let hdr = pending.get(&h)?;
        extra.push(hdr.work());
        h = hdr.prev_blockhash;
        if h.to_byte_array() == [0u8; 32] {
            extra.reverse();
            return Some(crate::most_work::sum_work(extra.into_iter()));
        }
    }
    None
}

/// Bodies on `tip`'s connecting header path that we may `getdata`.
/// Weaker-than-tip and below `-minimumchainwork` stay header-only.
fn fetchable_header_path_bodies(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
    pending_blocks: &PendingBlocks,
    requested: &HashSet<BlockHash>,
) -> Vec<BlockHash> {
    if !header_path_meets_minwork(hub, pending, tip) {
        return Vec::new();
    }
    if matches!(
        announced_work_cmp(hub, pending, tip),
        Some(std::cmp::Ordering::Less)
    ) {
        return Vec::new();
    }
    missing_blocks_on_header_path(hub, pending, tip, pending_blocks, requested)
}

/// Bodies on `tip`'s header path that we have not connected, stashed, or asked for.
fn missing_blocks_on_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
    pending_blocks: &PendingBlocks,
    requested: &HashSet<BlockHash>,
) -> Vec<BlockHash> {
    let mut path = Vec::new();
    let mut h = tip;
    for _ in 0..10_000 {
        if hub.is_connected(&h) {
            break;
        }
        if !pending_blocks.contains_key(&h)
            && !requested.contains(&h)
            && !hub.already_have_or_asked_block(&h)
        {
            path.push(h);
        }
        let prev = pending
            .get(&h)
            .map(|hdr| hdr.prev_blockhash)
            .or_else(|| hub.prev_of(&h));
        let Some(prev) = prev else {
            break;
        };
        h = prev;
        if h.to_byte_array() == [0u8; 32] {
            break;
        }
    }
    path.reverse();
    path
}

/// Compact (or header) whose prev is far behind tip: one block cannot beat
/// the intervening path. `p2p_compactblocks` low-work compact.
fn compact_header_low_work(hub: &ChainHub, header: &bitcoin::block::Header) -> bool {
    let prev = header.prev_blockhash;
    let Some(ph) = hub
        .query
        .height_of_hash(&prev.to_byte_array())
        .ok()
        .flatten()
    else {
        return false;
    };
    let Some(tip) = hub.tip_height() else {
        return false;
    };
    // Deeper than compact-serve window: ignore (150-block anti-dos in
    // `p2p_compactblocks.test_low_work_compactblocks`). Depth 5 is still
    // stored as headers-only (`test_compactblocks_not_at_tip`).
    tip.saturating_sub(ph.0) > 6
}

/// BIP133 feefilter to send after handshake. None = do not send (blocksonly,
/// forcerelay, block-relay-only). IBD still sends rounded MAX_MONEY.
pub(crate) fn outbound_feefilter_sats(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
) -> Option<i64> {
    if session.is_some_and(|s| {
        s.conn_type == crate::peers::PeerConnType::BlockRelay
            || s.hub().is_some_and(|h| h.is_forcerelay_perm())
    }) {
        return None;
    }
    if hub.in_ibd() {
        return Some(hub.feefilter_sat_kvb() as i64);
    }
    if hub.mempool().is_none_or(|m| !m.relay_enabled()) {
        return None;
    }
    Some(hub.feefilter_sat_kvb() as i64)
}

fn queue_out(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    out.send(msg)
        .map_err(|_| NetError::Protocol("peer write half closed"))
}

/// Queue a reconstructed `Block`/`CmpctBlock` if this session is under the serve cap.
///
/// `None` inflight (tests without a session) always queues.
pub(crate) fn try_queue_served_block(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    inflight: Option<&AtomicUsize>,
    msg: NetworkMessage,
) -> Result<bool, NetError> {
    if let Some(n) = inflight {
        if n.load(Ordering::SeqCst) >= MAX_SERVE_BLOCKS {
            return Ok(false);
        }
        n.fetch_add(1, Ordering::SeqCst);
        if let Err(e) = queue_out(out, msg) {
            note_served_write(n);
            return Err(e);
        }
        return Ok(true);
    }
    queue_out(out, msg)?;
    Ok(true)
}

/// BIP152 high-bandwidth tip announce. Does **not** count on
/// `serve_inflight` (that cap is reconstruct getdata). Writer still
/// saturating-subs every `CmpctBlock`, so an unpaired decrement cannot wrap.
fn queue_cmpct_tip_announce(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    queue_out(out, msg)
}

fn note_served_write(n: &AtomicUsize) {
    let _ = n.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_sub(1))
    });
}

fn pending_header_leaves(pending: &HashMap<BlockHash, bitcoin::block::Header>) -> Vec<BlockHash> {
    let prevs: HashSet<BlockHash> = pending.values().map(|h| h.prev_blockhash).collect();
    pending
        .keys()
        .copied()
        .filter(|h| !prevs.contains(h))
        .collect()
}

/// Try to accept pending blocks that connect to tip or form a better branch.
async fn drain_pending(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<NetworkMessage>,
    pending_blocks: &mut PendingBlocks,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
    requested_blocks: &mut HashSet<BlockHash>,
    compact: bool,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    // A reorg can make a held block the child of the *new* tip after the
    // greedy pass already ran. Repeat until the tip is stable.
    loop {
        let tip_before = hub.tip_hash();
        drain_pending_once(hub, pending_blocks, pending_headers, session).await?;
        if hub.tip_hash() == tip_before {
            break;
        }
    }

    let mut missing: Vec<BlockHash> = hub.held_missing_parents();
    for b in pending_blocks.values() {
        let prev = b.header.prev_blockhash;
        if prev.to_byte_array() != [0u8; 32]
            && !hub.is_connected(&prev)
            && !pending_blocks.contains_key(&prev)
            && hub.held_body(&prev).is_none()
            && !missing.contains(&prev)
        {
            missing.push(prev);
        }
    }
    for last in pending_header_leaves(pending_headers) {
        for h in fetchable_header_path_bodies(
            hub,
            pending_headers,
            last,
            pending_blocks,
            requested_blocks,
        ) {
            if !missing.contains(&h) {
                missing.push(h);
            }
        }
    }
    missing.retain(|h| !requested_blocks.contains(h));
    missing.truncate(MAX_SERVE_BLOCKS.saturating_sub(requested_blocks.len()));
    queue_block_getdata(hub, out, requested_blocks, &missing, compact)?;
    Ok(())
}

pub(crate) fn drain_pending_now(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<NetworkMessage>,
    pending_blocks: &mut PendingBlocks,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
    requested_blocks: &mut HashSet<BlockHash>,
    compact: bool,
) -> Result<(), NetError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("drain_pending test runtime")
        .block_on(drain_pending(
            hub,
            out,
            pending_blocks,
            pending_headers,
            requested_blocks,
            compact,
            None,
        ))
}

/// Feed complete pending bodies into the hub receive path. Pending is a
/// download window, not a second most-work assembler.
async fn drain_pending_once(
    hub: &ChainHub,
    pending_blocks: &mut PendingBlocks,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let mut progress = true;
    while progress {
        progress = false;
        let candidates: Vec<BlockHash> = pending_blocks.keys().copied().collect();
        for h in candidates {
            let Some(block) = pending_blocks.remove(&h) else {
                continue;
            };
            pending_headers.remove(&h);
            relay_new_pow_valid_block(hub, &block, session);
            match hub.accept_received_block_async(block.clone()).await {
                Ok(AcceptOutcome::Accepted { .. })
                | Ok(AcceptOutcome::AlreadyHave)
                | Ok(AcceptOutcome::IgnoredWeaker) => {
                    progress = true;
                }
                Err(NetError::Protocol("unknown parent")) => {
                    pending_blocks.insert(h, block);
                }
                // Invalid body: reject the block, keep the peer. BIP-152
                // high-bandwidth can deliver PoW-valid-but-invalid blocks
                // from honest Core peers that have not validated yet
                // (docs/external_findings/001-disconnect-on-invalid-block.md).
                Err(e) if net_error_is_store_not_found(&e) => {
                    rbitcoin_log::warn!(
                        "p2p: accept dropped {} (store not found — keep session): {e}",
                        h
                    );
                }
                Err(e) => {
                    rbitcoin_log::warn!(
                        "p2p: accept dropped {} (invalid/unconnectable — keep session): {e}",
                        h
                    );
                }
            }
        }
    }
    Ok(())
}

/// Inbound `getheaders` reply. Empty while tip work is below `-minimumchainwork`.
pub(crate) fn headers_reply_for_getheaders(
    hub: &ChainHub,
    gh: &bitcoin::p2p::message_blockdata::GetHeadersMessage,
) -> Result<Vec<bitcoin::block::Header>, NetError> {
    if !hub.meets_minimum_chain_work() {
        return Ok(Vec::new());
    }
    if gh.locator_hashes.is_empty() {
        let stop = gh.stop_hash;
        if stop.to_byte_array() != [0u8; 32] {
            if !hub.stale_relay_allowed(&stop) {
                return Ok(Vec::new());
            }
            if let Some(h) = hub.header_of(&stop) {
                return Ok(vec![h]);
            }
            return Ok(Vec::new());
        }
    }
    headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), gh)
}

fn headers_for_peer(
    cache: &BlockCache,
    query: &Query,
    gh: &bitcoin::p2p::message_blockdata::GetHeadersMessage,
) -> Result<Vec<bitcoin::block::Header>, NetError> {
    match query.headers_after_locator(&gh.locator_hashes, gh.stop_hash, MAX_HEADERS_RESULTS) {
        Ok(h) if !h.is_empty() || query.tip_height().is_some() => Ok(h),
        Ok(_) => Ok(cache.headers_after_locator(&gh.locator_hashes, gh.stop_hash)),
        Err(e) => Err(NetError::Consensus(e.to_string())),
    }
}

fn block_for_peer(
    cache: &BlockCache,
    query: &Query,
    hash: &BlockHash,
) -> Result<Option<bitcoin::Block>, NetError> {
    if let Some(block) = cache.get_block(hash) {
        return Ok(Some(block));
    }
    match query.reconstruct_block_by_hash(&hash.to_byte_array()) {
        Ok(b) => Ok(b),
        Err(e) => Err(NetError::Consensus(e.to_string())),
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
