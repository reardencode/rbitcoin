//! Peer handshake, serve, tip follow, and announce (BIP324 v2 transport).

use crate::cache::BlockCache;
use crate::chain::{
    accept_block_header_nodos_log, accept_prev_not_found_log, ignoring_low_work_chain_log,
    received_getdata_wtx_log, received_tx_log, synchronizing_blockheaders_log, AcceptOutcome,
    ChainHub,
};
use crate::codec::{
    FramedMessage, MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_LOCATOR_SZ, TX_INV_BATCH,
};
use crate::error::NetError;
use crate::msg_decode::decode_framed_offload;
use crate::peer_dos::{PeerRateLimiter, OVERSIZE_BAN_SCORE, RATE_LIMIT_BAN_SCORE};
use crate::peers::{CappedSet, PeerOut};
use crate::v2::{
    open_v2, open_v2_with_wire, read_v2_contents, read_v2_frame, read_v2_frame_with_progress,
    write_v2_contents, write_v2_msg, write_v2_msg_offload, V2Reader, V2Writer,
};
use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::{AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::{Block, BlockHash, Transaction};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

/// Protocol version we advertise (BIP339 wtxidrelay needs ≥70016; rust-bitcoin's
/// `PROTOCOL_VERSION` is still 70001).
#[doc(hidden)]
pub const OUR_PROTOCOL_VERSION: u32 = 70016;

/// How often an established session re-issues `getheaders` so a quiet peer or
/// a gap opened while we were offline still gets filled (signet ~10m blocks).
#[doc(hidden)]
pub const HEADERS_POLL_SECS: u64 = 120;

#[doc(hidden)]
pub const SESSION_HEARTBEAT: Duration = Duration::from_millis(50);

/// Addr-fetch sessions expire after this many seconds.
#[doc(hidden)]
pub const ADDRFETCH_TIMEOUT_SECS: u64 = 300;

/// On a reorg larger than this, announce via inv instead of a header list.
#[doc(hidden)]
pub const MAX_BLOCKS_TO_ANNOUNCE: u32 = 8;

/// Quiet period before announcing a reorg tip. A direct child of the header we
/// already sent goes out immediately. `p2p_sendheaders` part 3 needs the whole
/// reorg in one inv (nine blocks) or one headers list (eight).
#[doc(hidden)]
pub const TIP_ANNOUNCE_BATCH: Duration = Duration::from_millis(200);

/// True when a session error is a missing store row (not peer malice / corrupt IO).
///
/// These must not tear down the TCP session: re-request or skip and keep the peer.
pub fn net_error_is_store_not_found(e: &NetError) -> bool {
    match e {
        NetError::Consensus(s) | NetError::Store(s) => {
            let l = s.to_ascii_lowercase();
            l.contains("record not found")
                || l.contains("not found")
                || l.contains("storeerror::notfound")
        }
        _ => false,
    }
}

/// Per-session misbehavior score that triggers disconnect.
pub const BAN_SCORE_THRESHOLD: u32 = 100;

pub fn misbehavior_disconnect_log(peer: &str, score: u32) -> String {
    format!("p2p: {peer} misbehavior {score} ≥ {BAN_SCORE_THRESHOLD} — disconnect")
}

/// `-blocksonly` (relay off, no whitelist `relay`) or a block-relay-only
/// session must not receive txs / tx invs (`p2p_blocksonly`).
#[doc(hidden)]
pub fn reject_unsolicited_tx(hub: &ChainHub, session: Option<&crate::peers::LivePeer>) -> bool {
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
    !session.is_some_and(|s| s.session_relay_perm())
}

/// Reconstruct compact blocks when this node is not `-blocksonly` and
/// either it has no mempool or it is accepting transactions.
///
/// High-bandwidth selection and compact `getdata` use this. A tip
/// announcement does not: this node already has the block, and the peer
/// fills short ids. Coinbase is the prefill when there is nothing to
/// guess from.
#[doc(hidden)]
pub fn compact_blocks_ok(hub: &ChainHub) -> bool {
    if hub.blocks_only.load(Ordering::Acquire) {
        return false;
    }
    match hub.mempool() {
        None => true,
        Some(mp) => mp.relay_enabled(),
    }
}

/// A connect that leaves IBD after the scripthash pack starts peer tx relay
/// before compact selection. The tip-follow loop may not have run yet.
/// Direct mode is the pack: relay stays off. A purge fault leaves the bit
/// clear and sends no fee filter.
fn start_relay_after_tip_connect(hub: &ChainHub, peers: Option<&crate::peers::PeerHub>) {
    let Some(peers) = peers else {
        return;
    };
    let Some(mp) = hub.mempool() else {
        return;
    };
    if !hub.query.index_mode().is_ok_and(|mode| mode.is_tip()) {
        return;
    }
    let want =
        hub.meets_minimum_chain_work() && !hub.blocks_only.load(Ordering::Acquire) && !hub.in_ibd();
    if !want || mp.relay_enabled() {
        return;
    }
    mp.set_relay_enabled(true);
    if !mp.relay_enabled() {
        return;
    }
    peers.queue_feefilter_all(hub.feefilter_sat_kvb() as i64);
    rbitcoin_log::info!("ibd: leaving IBD — enabling tx relay");
}

/// BIP152 HB is only for peers we will take compact blocks from.
#[doc(hidden)]
pub fn maybe_select_hb_if_relay(hub: &ChainHub, session: Option<&crate::peers::LivePeer>) {
    if !compact_blocks_ok(hub) {
        return;
    }
    let Some(s) = session else {
        return;
    };
    // Compact-block reconstruction stays. The trusted session is not asked
    // for high-bandwidth announcements.
    if s.peer_hub().is_some_and(|ph| ph.session_is_trusted_peer(s)) {
        return;
    }
    s.maybe_select_as_hb();
}

#[doc(hidden)]
pub fn note_accepted_hb(
    r: &Result<AcceptOutcome, NetError>,
    hb: &Option<(std::sync::Arc<crate::peers::PeerHub>, u64)>,
) {
    if matches!(r, Ok(AcceptOutcome::Accepted { .. })) {
        if let Some((ph, id)) = hb {
            if ph.get(*id).is_some_and(|s| ph.session_is_trusted_peer(&s)) {
                return;
            }
            ph.maybe_select_hb(*id);
        }
    }
}

pub async fn accept_received_from_peer(
    hub: &ChainHub,
    block: Block,
    session: Option<&crate::peers::LivePeer>,
) -> Result<AcceptOutcome, NetError> {
    let waive =
        session.is_some_and(|s| s.peer_hub().is_some_and(|ph| ph.session_is_trusted_peer(s)));
    // Relay may flip inside this connect once the index is in tip mode.
    // Compact selection reads that bit afterwards.
    let peers = session.and_then(|s| s.peer_hub());
    let hb = session.and_then(|s| s.peer_hub().map(|ph| (ph, s.id)));
    // The tip is visible before this await returns. Stamp the clock from
    // before the wait so a caller that moves time once it sees the tip does
    // not extend the post-block ping grace.
    let received_at = session.map(|s| s.clock_now());
    let r = if let Some(hub) = hub.shared_arc() {
        crate::tip_accept::run_on_tip_accept_async(move || {
            let r = hub.accept_received_on_lane(block, waive);
            start_relay_after_tip_connect(&hub, peers.as_deref());
            let chosen = if compact_blocks_ok(&hub) { hb } else { None };
            note_accepted_hb(&r, &chosen);
            r
        })
        .await
    } else {
        // A stack hub (unit tests) has no `Arc`. Join before return so the
        // borrow outlives the job.
        crate::tip_accept::run_on_tip_accept(|| {
            let r = hub.accept_received_on_lane(block, waive);
            start_relay_after_tip_connect(hub, peers.as_deref());
            let chosen = if compact_blocks_ok(hub) { hb } else { None };
            note_accepted_hb(&r, &chosen);
            r
        })
    };
    if let (Some(s), Some(at), Ok(AcceptOutcome::Accepted { .. })) = (session, received_at, &r) {
        s.note_last_block_at(at);
    }
    r
}

/// The hub and key a misbehavior exit may record. Noban and manual peers
/// are not recorded. A loopback or `0.0.0.0` identity is every local
/// connection, so Core disconnects that peer and does not discourage it.
/// Onion and I2P use [`crate::peers::LivePeer::net`], not that socket.
#[doc(hidden)]
pub fn refusable_addr(
    session: Option<&crate::peers::LivePeer>,
) -> Option<(Arc<crate::peers::PeerHub>, crate::peers::DiscourageKey)> {
    let s = session.filter(|s| !misbehavior_exempt(s))?;
    let key = crate::peers::DiscourageKey::from_net(s.net)?;
    Some((s.peer_hub()?, key))
}

/// One-day in-memory refusal.
#[doc(hidden)]
pub fn note_threshold_refusal(session: Option<&crate::peers::LivePeer>) {
    if let Some((hub, key)) = refusable_addr(session) {
        hub.note_misbehavior_key(key);
    }
}

/// Disconnect error for a score that is already at the misbehavior line.
/// Records the address, including when the caller is not [`punish_disconnect`].
#[doc(hidden)]
pub fn threshold_disconnect(session: Option<&crate::peers::LivePeer>) -> NetError {
    note_threshold_refusal(session);
    NetError::Protocol("peer misbehavior threshold")
}

/// The first rate-limit exit from a recordable address leaves a strike. A
/// second one within [`crate::peers::PeerHub::RATE_STRIKE_SECS`] is a
/// threshold exit, as two overflows in one session were.
#[doc(hidden)]
pub fn rate_limit_disconnect(session: Option<&crate::peers::LivePeer>) -> NetError {
    if refusable_addr(session).is_some_and(|(hub, key)| hub.note_rate_strike(key)) {
        return threshold_disconnect(session);
    }
    NetError::Protocol("peer rate limit")
}

/// Core `MaybeDiscourageAndDisconnect`: misbehavior never disconnects or
/// discourages a noban peer or a manual one (`--connect`, `addnode`).
#[doc(hidden)]
pub fn misbehavior_exempt(s: &crate::peers::LivePeer) -> bool {
    s.session_noban() || s.conn_type == crate::peers::PeerConnType::Manual
}

/// Core `Misbehaving`. Unlike [`punish_disconnect`], it also keeps a manual
/// peer connected.
#[doc(hidden)]
pub fn misbehaving(ban_score: &mut u32, session: Option<&crate::peers::LivePeer>) {
    if let Some(s) =
        session.filter(|s| s.conn_type == crate::peers::PeerConnType::Manual && !s.session_noban())
    {
        rbitcoin_log::info!("Warning: not punishing manually connected peer {}!", s.id);
        return;
    }
    punish_disconnect(ban_score, session);
}

/// Disconnects and refuses the address; a noban peer is kept. Used where Core
/// sets `fDisconnect`, which drops a manual peer too. Core `Misbehaving`
/// sites call [`misbehaving`].
#[doc(hidden)]
pub fn punish_disconnect(ban_score: &mut u32, session: Option<&crate::peers::LivePeer>) {
    if let Some(s) = session.filter(|s| s.session_noban()) {
        rbitcoin_log::info!("Warning: not punishing noban peer {}!", s.id);
        return;
    }
    *ban_score = ban_score.saturating_add(BAN_SCORE_THRESHOLD);
    if let Some(s) = session {
        s.request_disconnect();
        note_threshold_refusal(Some(s));
    }
}

/// Core `MaybeDiscourageAndDisconnect`: misbehavior never drops a noban or
/// manual peer.
#[doc(hidden)]
pub fn misbehavior_disconnects(ban_score: u32, session: Option<&crate::peers::LivePeer>) -> bool {
    ban_score >= BAN_SCORE_THRESHOLD && !session.is_some_and(misbehavior_exempt)
}
/// Cap on incomplete compact blocks awaiting `blocktxn` (DoS).
#[doc(hidden)]
pub const MAX_PENDING_CMPCT: usize = 1;
/// Cap on headers held while assembling tip/reorg work (DoS / process RAM).
#[doc(hidden)]
pub const MAX_PENDING_HEADERS: usize = 8_000;
/// One more step than a full pending map plus one `headers` batch, so the
/// walk can still see genesis or our tip after the last header.
#[doc(hidden)]
pub const PENDING_WALK_LIMIT: usize = MAX_PENDING_HEADERS + MAX_HEADERS_RESULTS + 1;

/// A new hash at the cap is refused. The headers already held stay.
#[doc(hidden)]
pub fn admit_pending_header(
    pending: &mut HashMap<BlockHash, bitcoin::block::Header>,
    hash: BlockHash,
    header: bitcoin::block::Header,
) {
    if pending.len() >= MAX_PENDING_HEADERS && !pending.contains_key(&hash) {
        return;
    }
    pending.insert(hash, header);
}
/// Cap on decoded bodies stashed per session (DoS / process RAM). Must be
/// ≥99 so tip-follow can assemble a 99-block competing branch; apply is
/// `ChainHub::accept_received_block` (see `docs/architecture.md`).
/// Inflight `getdata` is [`MAX_SERVE_BLOCKS`] (peer reconstruct cap).
#[doc(hidden)]
pub const MAX_PENDING_BLOCKS: usize = 128;
/// Honest maximum block serialization. One larger body is not parked.
#[doc(hidden)]
pub const MAX_BLOCK_SERIALIZED: usize = 4_000_000;
/// Max reconstructed full bodies queued on one session writer, and the
/// matching catch-up `getdata` window (extra hashes stick in `requested`).
pub const MAX_SERVE_BLOCKS: usize = 16;
/// Compact getdata/serve only near the validated tip. Deeper catch-up uses
/// `MSG_WITNESS_BLOCK`.
#[doc(hidden)]
pub const MAX_CMPCTBLOCK_DEPTH: u32 = 5;
/// Drop inflight `getdata` hashes that the peer never sent so catch-up can
/// ask again. `sync_blocks` is 60s; 120s headers poll is too late.
pub const BLOCK_GETDATA_TIMEOUT: Duration = Duration::from_secs(10);

/// INV-origin txids this session sent us. Cap matches `announced_wtx` (FIFO roll).
pub const FROM_THIS_PEER_CAP: usize = 50_000;

/// Test/assert surface for the tip-follow pending-body cap (equals production).
#[cfg(debug_assertions)]
pub const MAX_PENDING_BLOCKS_FOR_TEST: usize = MAX_PENDING_BLOCKS;

/// Tip-follow decoded bodies waiting for a connectable parent. Cap 128;
/// insert evicts the oldest hash (FIFO), not `HashMap::keys().next()`.
#[derive(Default)]
pub struct PendingBlocks {
    pub map: HashMap<BlockHash, bitcoin::Block>,
    pub fifo: VecDeque<BlockHash>,
}

impl PendingBlocks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains_key(&self, hash: &BlockHash) -> bool {
        self.map.contains_key(hash)
    }

    pub fn values(&self) -> std::collections::hash_map::Values<'_, BlockHash, bitcoin::Block> {
        self.map.values()
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, BlockHash, bitcoin::Block> {
        self.map.keys()
    }

    pub fn insert(&mut self, hash: BlockHash, block: bitcoin::Block) {
        stash_pending_block(self, hash, block);
    }

    pub fn remove(&mut self, hash: &BlockHash) -> Option<bitcoin::Block> {
        let b = self.map.remove(hash)?;
        if let Some(i) = self.fifo.iter().position(|h| h == hash) {
            self.fifo.remove(i);
        }
        Some(b)
    }
}

#[doc(hidden)]
pub fn block_wire_len(block: &bitcoin::Block) -> usize {
    block.total_size()
}

#[doc(hidden)]
pub fn stash_pending_block(pending: &mut PendingBlocks, hash: BlockHash, block: bitcoin::Block) {
    let nbytes = block_wire_len(&block);
    if nbytes > MAX_BLOCK_SERIALIZED {
        return;
    }
    if let std::collections::hash_map::Entry::Occupied(mut e) = pending.map.entry(hash) {
        e.insert(block);
        return;
    }
    while pending.map.len() >= MAX_PENDING_BLOCKS {
        let Some(k) = pending.fifo.pop_front() else {
            break;
        };
        pending.map.remove(&k);
    }
    if pending.map.len() >= MAX_PENDING_BLOCKS {
        return;
    }
    pending.fifo.push_back(hash);
    pending.map.insert(hash, block);
}

/// Service bits for one node.
///
/// BIP159: a pruned node offers `NETWORK_LIMITED`, not `NETWORK`.
/// `NODE_COMPACT_FILTERS` is that hub's bit. No hub means this node has
/// not caught filters up.
pub fn local_service_flags(pruned: bool, peers: Option<&crate::peers::PeerHub>) -> ServiceFlags {
    let mut base = if pruned {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::P2P_V2
    } else {
        crate::seeds::required_seed_services()
    };
    if peers.is_some_and(|p| p.compact_filters_advertised()) {
        base.add(ServiceFlags::COMPACT_FILTERS);
    }
    base
}

/// NETWORK_LIMITED is enough when the tip is shallower than this (~24h at 10m).
pub const NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS: i64 = 144;

/// Outbound-full, block-relay, and addr-fetch sessions must offer NETWORK.
pub fn expect_services_from_conn(typ: crate::peers::PeerConnType) -> bool {
    matches!(
        typ,
        crate::peers::PeerConnType::OutboundFullRelay
            | crate::peers::PeerConnType::BlockRelay
            | crate::peers::PeerConnType::AddrFetch
    )
}

/// Service bits we want from a peer given what they offered and how deep the tip is.
pub fn desirable_service_flags(offered: ServiceFlags, tip_depth_blocks: i64) -> ServiceFlags {
    if offered.has(ServiceFlags::NETWORK_LIMITED)
        && tip_depth_blocks < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS
    {
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS
    } else {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    }
}

/// Whether offered flags already include what we want for this tip depth.
pub fn has_all_desirable_service_flags(offered: ServiceFlags, tip_depth_blocks: i64) -> bool {
    let want = desirable_service_flags(offered, tip_depth_blocks);
    offered.has(want)
}

pub fn expected_services_disconnect_log(offered: u64, expected: u64) -> String {
    format!(
        "p2p: does not offer the expected services ({offered:08x} offered, {expected:08x} expected)"
    )
}

pub fn feeler_connection_completed_log() -> &'static str {
    "p2p: feeler connection completed"
}

pub fn connected_to_self_log(addr: impl std::fmt::Display) -> String {
    format!("p2p: connected to self at {addr}, disconnecting")
}

pub fn version_handshake_timeout_log(peer: u64) -> String {
    format!("p2p: version handshake timeout, disconnecting peer={peer}")
}

/// Max addresses in one ADDR / addrv2. Interop size — do not change without
/// a named reason to diverge (see COMPAT.md).
pub const MAX_ADDR_TO_SEND: usize = 1000;
/// Core `MAX_ADDR_RATE_PER_SECOND`: a peer earns one address token per 10 s.
pub const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;
/// Core `MAX_ADDR_PROCESSING_TOKEN_BUCKET`: refill stops at this many tokens.
pub const MAX_ADDR_PROCESSING_TOKEN_BUCKET: f64 = MAX_ADDR_TO_SEND as f64;

/// Core `Peer::m_addr_token_bucket`. It starts at one token. Each address a
/// peer sends costs one, and an address with no token left is dropped before
/// AddrMan and relay.
#[derive(Debug, Clone, Copy)]
pub struct AddrTokenBucket {
    pub tokens: f64,
    pub at_ms: u64,
}

impl AddrTokenBucket {
    pub fn new(now_ms: u64) -> Self {
        Self {
            tokens: 1.0,
            at_ms: now_ms,
        }
    }

    /// Refill for the time since the last call (only below the cap), then
    /// take up to `want` tokens. Returns how many addresses may be processed.
    pub fn take(&mut self, want: usize, now_ms: u64) -> usize {
        if self.tokens < MAX_ADDR_PROCESSING_TOKEN_BUCKET {
            let dt = now_ms.saturating_sub(self.at_ms) as f64 / 1000.0;
            self.tokens =
                (self.tokens + dt * MAX_ADDR_RATE_PER_SECOND).min(MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        self.at_ms = self.at_ms.max(now_ms);
        let take = (self.tokens.floor() as usize).min(want);
        self.tokens -= take as f64;
        take
    }

    pub(crate) fn credit(&mut self, n: usize) {
        self.tokens += n as f64;
    }
}

#[doc(hidden)]
pub fn addr_relay_key(msg: &bitcoin::p2p::address::AddrV2Message) -> u64 {
    let raw = bitcoin::consensus::encode::serialize(msg);
    let mut h = 0xcbf29ce484222325u64;
    for b in raw {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// GetAddr returns at most this percent of AddrMan (then `MAX_ADDR_TO_SEND`).
/// Interop size — do not change without a named reason to diverge
/// (see COMPAT.md).
pub const MAX_PCT_ADDR_TO_SEND: usize = 23;

pub fn sendaddrv2_after_verack_log(peer: u64) -> String {
    format!("p2p: sendaddrv2 received after verack, disconnecting peer={peer}")
}

pub fn addrv2_message_size_log(n: usize) -> String {
    format!("p2p: addrv2 message size = {n}")
}

pub fn received_addrv2_log(nbytes: usize, peer: u64) -> String {
    format!("p2p: received: addrv2 ({nbytes} bytes) peer={peer}")
}

pub fn sending_addrv2_log(nbytes: usize, peer: u64) -> String {
    format!("p2p: sending addrv2 ({nbytes} bytes) peer={peer}")
}

pub fn block_download_timeout_log(hash: BlockHash, peer: u64) -> String {
    format!("p2p: Timeout downloading block {hash}, disconnecting peer={peer}")
}

pub fn ping_timeout_log(elapsed_secs: f64) -> String {
    format!("p2p: ping timeout: {elapsed_secs:.6}s")
}

pub fn ping_prior_to_verack_log(peer: u64) -> String {
    unsupported_before_verack_log("ping", peer)
}

pub fn unsupported_before_verack_log(cmd: &str, peer: u64) -> String {
    let cmd = peer_log_text(cmd);
    format!("p2p: Unsupported message \"{cmd}\" prior to verack from peer={peer}")
}

/// One log line: peer-controlled bytes cannot insert a raw newline.
#[doc(hidden)]
pub fn peer_log_text(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

/// Disconnect peers advertising protocol version below this.
pub const MIN_PEER_PROTO_VERSION: i32 = 31800;

pub fn obsolete_version_log(version: i32, peer: u64) -> String {
    format!("p2p: using obsolete version {version}, disconnecting peer={peer}")
}

pub fn advertising_address_log(addr_port: impl std::fmt::Display, peer: u64) -> String {
    format!("p2p: Advertising address {addr_port} to peer={peer}")
}

#[doc(hidden)]
pub fn queue_addr_list(
    session: Option<&crate::peers::LivePeer>,
    out: &mpsc::UnboundedSender<PeerOut>,
    addrs: Vec<(u32, crate::NetAddr)>,
    v2: bool,
) -> Result<(), NetError> {
    let services = session
        .and_then(|s| s.peer_hub())
        .map(|h| local_service_flags(h.is_pruned(), Some(&h)))
        .unwrap_or_else(|| local_service_flags(false, None));
    if v2 {
        let list: Vec<AddrV2Message> = addrs
            .into_iter()
            .map(|(t, a)| AddrV2Message {
                time: t,
                services,
                addr: a.to_addrv2(),
                port: a.port(),
            })
            .collect();
        queue_accounted(session, out, NetworkMessage::AddrV2(list))
    } else {
        let list: Vec<(u32, Address)> = addrs
            .into_iter()
            .filter_map(|(t, a)| match a {
                crate::NetAddr::Ip(s) => Some((t, Address::new(&s, services))),
                crate::NetAddr::Onion { .. }
                | crate::NetAddr::I2p { .. }
                | crate::NetAddr::Cjdns { .. } => None,
            })
            .collect();
        queue_accounted(session, out, NetworkMessage::Addr(list))
    }
}

#[doc(hidden)]
pub fn maybe_queue_local_addr(
    _hub: &ChainHub,
    session: &crate::peers::LivePeer,
    out: &mpsc::UnboundedSender<PeerOut>,
) -> Result<(), NetError> {
    if let Some(msg) = session.take_self_announce_msg() {
        queue_out(out, msg)?;
    }
    Ok(())
}

pub fn hidden_addr_from() -> Address {
    Address::new(
        &SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        ServiceFlags::NONE,
    )
}

pub fn non_version_before_handshake_log(cmd: &str, peer: u64) -> String {
    let cmd = peer_log_text(cmd);
    format!("p2p: non-version message before version handshake. Message \"{cmd}\" from peer={peer}")
}

/// Tip age in blocks: `(now - tip_time) / pow_target_spacing`.
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
#[doc(hidden)]
pub struct LiveFollowDec(pub Option<Arc<AtomicUsize>>);

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
    pub session: Option<&'a crate::peers::LivePeer>,
    pub conn_type: crate::peers::PeerConnType,
}

impl HandshakePolicy<'static> {
    pub fn plain() -> Self {
        Self {
            hub: None,
            peers: None,
            session: None,
            conn_type: crate::peers::PeerConnType::OutboundFullRelay,
        }
    }

    /// Core's private broadcast handshake: one constant VERSION
    /// (`private_broadcast_version`), no WTXIDRELAY or SENDADDRV2, and a peer
    /// whose own VERSION has relay off is dropped before VERACK.
    pub(crate) fn private_broadcast() -> Self {
        Self {
            conn_type: crate::peers::PeerConnType::PrivateBroadcast,
            ..Self::plain()
        }
    }
}

/// Core's user agent on a private broadcast connection (#29415).
pub(crate) const PRIVATE_BROADCAST_USER_AGENT: &str = "/pynode:0.0.1/";

/// Core `PushNodeVersion` on a private broadcast connection. Every such
/// connection sends these bytes, the nonce aside, so they say nothing about us.
/// Both addresses are Core's `CService{}` (16 zero bytes, port 0).
fn private_broadcast_version(nonce: u64) -> VersionMessage {
    let unset = Address {
        services: ServiceFlags::NONE,
        address: [0; 8],
        port: 0,
    };
    VersionMessage {
        version: OUR_PROTOCOL_VERSION.max(PROTOCOL_VERSION),
        services: ServiceFlags::NONE,
        timestamp: 0,
        receiver: unset.clone(),
        sender: unset,
        nonce,
        user_agent: PRIVATE_BROADCAST_USER_AGENT.to_string(),
        start_height: 0,
        relay: false,
    }
}

/// Outbound BIP324 session. [`Self::outbound_regtest`] completes VERSION/VERACK;
/// [`Self::outbound_bip324`] stops after transport so the caller can send a
/// custom first application message.
pub struct V2PlainSession {
    pub reader: V2Reader,
    pub writer: V2Writer,
    pub tcp_shutdown: std::net::TcpStream,
}

impl V2PlainSession {
    /// Dial-side BIP324 only (no VERSION). Caller sends the first application message.
    pub async fn outbound_bip324(stream: TcpStream) -> Result<Self, NetError> {
        let magic = Magic::REGTEST;
        let (reader, writer, _wire, tcp_shutdown) = open_v2(stream, magic, false).await?;
        Ok(Self {
            reader,
            writer,
            tcp_shutdown,
        })
    }

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
        write_v2_contents(&mut self.writer, contents.to_vec()).await
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

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
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
    let wire = policy.session.map(|s| s.new_wire()).unwrap_or_default();
    let (mut reader, mut writer, wire, tcp_shutdown) =
        open_v2_with_wire(stream, magic, inbound, wire).await?;
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

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn inbound_connect_and_handshake(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    bind: SocketAddr,
) -> Result<
    (
        VersionMessage,
        V2Reader,
        V2Writer,
        std::net::TcpStream,
        std::sync::Arc<crate::peers::LivePeer>,
    ),
    NetError,
> {
    let _ = stream.set_nodelay(true);
    let std = stream.into_std().map_err(NetError::Io)?;
    std.set_nonblocking(true).map_err(NetError::Io)?;
    let tcp_pre = std.try_clone().map_err(NetError::Io)?;
    let stream = TcpStream::from_std(std).map_err(NetError::Io)?;
    let sess =
        peers.register_connecting(their_addr, bind, true, crate::peers::PeerConnType::Inbound);
    let wire = sess.new_wire();
    sess.attach_tcp_shutdown(tcp_pre);
    let (mut reader, mut writer, wire, tcp_shutdown) =
        match open_v2_with_wire(stream, magic, true, wire).await {
            Ok(x) => x,
            Err(NetError::Protocol("magic-prefixed ellswift")) => {
                while !sess.stop.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                return Err(NetError::Timeout);
            }
            Err(e) => {
                let _ = peers.disconnect_id(sess.id);
                return Err(e);
            }
        };
    sess.mark_v2_transport_ready();
    if let Ok(clone) = tcp_shutdown.try_clone() {
        sess.attach_tcp_shutdown(clone);
    }
    let policy = HandshakePolicy {
        hub: None,
        peers: Some(peers),
        session: Some(sess.as_ref()),
        conn_type: crate::peers::PeerConnType::Inbound,
    };
    let their_version = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        application_handshake(
            &mut reader,
            &mut writer,
            magic,
            our_addr,
            their_addr,
            start_height,
            true,
            user_agent,
            policy,
        ),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let _ = peers.disconnect_id(sess.id);
            return Err(e);
        }
        Err(_) => {
            rbitcoin_log::debug!("{}", version_handshake_timeout_log(sess.id));
            let _ = peers.disconnect_id(sess.id);
            return Err(NetError::Timeout);
        }
    };
    let sess = peers.register_handshaken_net(
        &sess,
        crate::peers::PeerEndpoint {
            addr: their_addr,
            net: crate::NetAddr::from_socket(their_addr),
            addrbind: bind,
        },
        &their_version,
        crate::peers::PeerConnType::Inbound,
        wire,
    );
    Ok((their_version, reader, writer, tcp_shutdown, sess))
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn connect_and_handshake_timed(
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
    peers: &crate::peers::PeerHub,
) -> Result<(), NetError> {
    run_feeler_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        our_addr,
        their_addr,
        start_height,
        user_agent,
        peers,
    )
    .await
}

/// Feeler handshake with an explicit timeout (production uses [`HANDSHAKE_TIMEOUT`]).
#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn run_feeler_timed(
    limit: Duration,
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
    peers: &crate::peers::PeerHub,
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
            peers,
        ),
    )
    .await
    .map_err(|_| NetError::Timeout)?
}

pub async fn run_feeler_inner(
    stream: TcpStream,
    magic: Magic,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    user_agent: &str,
    peers: &crate::peers::PeerHub,
) -> Result<(), NetError> {
    let (mut reader, mut writer, _wire, _tcp_shutdown) = open_v2(stream, magic, false).await?;
    let services = local_service_flags(peers.is_pruned(), Some(peers));
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

#[doc(hidden)]
pub fn command_label(cmd: &[u8; 12]) -> String {
    let n = cmd.iter().position(|&b| b == 0).unwrap_or(12);
    String::from_utf8_lossy(&cmd[..n]).into_owned()
}

pub fn fail_if_handshake_timed_out(policy: &HandshakePolicy<'_>) -> Result<(), NetError> {
    let Some(s) = policy.session else {
        return Ok(());
    };
    let Some(peers) = policy.peers else {
        return Ok(());
    };
    if !peers.handshake_timed_out(s, peers.now_secs()) {
        return Ok(());
    }
    let line = if s.v2_transport_ready() {
        version_handshake_timeout_log(s.id)
    } else {
        crate::v2::v2_handshake_timeout_log(s.id)
    };
    rbitcoin_log::debug!("{}", line);
    let _ = peers.disconnect_id(s.id);
    Err(NetError::Timeout)
}

pub async fn read_handshake_frame(
    reader: &mut V2Reader,
    magic: Magic,
    policy: &HandshakePolicy<'_>,
) -> Result<FramedMessage, NetError> {
    loop {
        fail_if_handshake_timed_out(policy)?;
        if let Some(s) = policy.session {
            if s.stop.load(Ordering::Relaxed) {
                return Err(NetError::Disconnected);
            }
        }
        match tokio::time::timeout(Duration::from_millis(50), read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => return Ok(frame),
            Ok(Err(e)) => {
                fail_if_handshake_timed_out(policy)?;
                return Err(e);
            }
            Err(_) => continue,
        }
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Perform the version/verack exchange over an established BIP324 session.
pub async fn application_handshake(
    reader: &mut V2Reader,
    writer: &mut V2Writer,
    magic: Magic,
    _our_addr: SocketAddr,
    their_addr: SocketAddr,
    start_height: i32,
    inbound: bool,
    user_agent: &str,
    policy: HandshakePolicy<'_>,
) -> Result<VersionMessage, NetError> {
    let private = policy.conn_type == crate::peers::PeerConnType::PrivateBroadcast;
    let our_nonce = rand_nonce();
    let version = if private {
        private_broadcast_version(our_nonce)
    } else {
        let pruned = policy.peers.map(|p| p.is_pruned()).unwrap_or(false);
        let services = local_service_flags(pruned, policy.peers);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        VersionMessage {
            version: OUR_PROTOCOL_VERSION.max(PROTOCOL_VERSION),
            services,
            timestamp: now,
            receiver: Address::new(&their_addr, ServiceFlags::NONE),
            sender: hidden_addr_from(),
            nonce: our_nonce,
            user_agent: user_agent.to_string(),
            start_height,
            relay: true,
        }
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

    let their_version = read_peer_version(reader, magic, &policy).await?;

    if inbound {
        if let Some(peers) = policy.peers {
            if !peers.check_incoming_nonce(their_version.nonce) {
                rbitcoin_log::info!("{}", connected_to_self_log(their_addr));
                return Err(NetError::Protocol("connected to self"));
            }
        }
        write_v2_msg(writer, NetworkMessage::Version(version)).await?;
    } else if private && !their_version.relay {
        return Err(NetError::Protocol("peer does not relay transactions"));
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

    // BIP339 / BIP155 feature negotiation starts at 70016 (`p2p_leak` pre-wtxid).
    if !private && their_version.version >= 70016 {
        write_v2_msg(writer, NetworkMessage::WtxidRelay).await?;
        write_v2_msg(writer, NetworkMessage::SendAddrV2).await?;
    }
    write_v2_msg(writer, NetworkMessage::Verack).await?;
    wait_peer_verack(reader, magic, &policy).await?;

    nonce_guard.clear = false;
    if let Some(peers) = policy.peers {
        if !inbound {
            peers.clear_outbound_nonce(our_nonce);
        }
    }

    Ok(their_version)
}

pub async fn read_peer_version(
    reader: &mut V2Reader,
    magic: Magic,
    policy: &HandshakePolicy<'_>,
) -> Result<VersionMessage, NetError> {
    loop {
        let frame = read_handshake_frame(reader, magic, policy).await?;
        let cmd = command_label(&frame.command);
        let msg = frame.decode();
        match msg.payload() {
            NetworkMessage::Version(v) => {
                if (v.version as i32) < MIN_PEER_PROTO_VERSION {
                    if let Some(s) = policy.session {
                        rbitcoin_log::debug!("{}", obsolete_version_log(v.version as i32, s.id));
                        if let Some(peers) = policy.peers {
                            let _ = peers.disconnect_id(s.id);
                        }
                    }
                    return Err(NetError::Protocol("obsolete version"));
                }
                return Ok(v.clone());
            }
            NetworkMessage::Verack => return Err(NetError::Protocol("verack before version")),
            other => {
                if let Some(s) = policy.session {
                    rbitcoin_log::debug!("{}", non_version_before_handshake_log(&cmd, s.id));
                }
                let _ = other;
                fail_if_handshake_timed_out(policy)?;
            }
        }
    }
}

pub async fn wait_peer_verack(
    reader: &mut V2Reader,
    magic: Magic,
    policy: &HandshakePolicy<'_>,
) -> Result<(), NetError> {
    loop {
        let frame = read_handshake_frame(reader, magic, policy).await?;
        let cmd = command_label(&frame.command);
        let msg = frame.decode();
        if apply_pre_verack(policy.session, msg.payload(), &cmd) {
            return Ok(());
        }
        if !matches!(
            msg.payload(),
            NetworkMessage::SendAddrV2 | NetworkMessage::WtxidRelay
        ) {
            fail_if_handshake_timed_out(policy)?;
        }
    }
}

/// Remember BIP339 / BIP155 features sent before VERACK. `true` = VERACK seen.
#[doc(hidden)]
pub fn apply_pre_verack(
    session: Option<&crate::peers::LivePeer>,
    payload: &NetworkMessage,
    cmd: &str,
) -> bool {
    match payload {
        NetworkMessage::Verack => true,
        NetworkMessage::SendAddrV2 => {
            if let Some(s) = session {
                s.set_wants_addrv2();
            }
            false
        }
        NetworkMessage::WtxidRelay => {
            if let Some(s) = session {
                s.set_wtxid_relay();
            }
            false
        }
        NetworkMessage::Ping(_) => {
            if let Some(s) = session {
                rbitcoin_log::debug!("{}", ping_prior_to_verack_log(s.id));
            }
            false
        }
        _ => {
            if let Some(s) = session {
                rbitcoin_log::debug!("{}", unsupported_before_verack_log(cmd, s.id));
            }
            false
        }
    }
}

#[doc(hidden)]
pub fn framed_cmd(frame: &FramedMessage) -> String {
    let end = frame.command.iter().position(|&b| b == 0).unwrap_or(12);
    String::from_utf8_lossy(&frame.command[..end]).into_owned()
}

#[doc(hidden)]
pub fn rand_nonce() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("CSPRNG for version nonce");
    u64::from_le_bytes(buf)
}

/// Bidirectional peer session: serve history, tip follow, announce our tip.
///
/// After handshake preferences (`sendheaders` / `sendcmpct`), the session
/// **actively** `getheaders` from our tip locator so blocks mined while we were
/// offline or mid–SH materialize are pulled — not only unsolicited announces.
/// Long history catch-up remains `rbitcoin-ibd`. Tip-follow is
/// [`crate::service::P2PNode::follow_from`].
///
/// A dedicated writer drains outbound messages while the reader keeps draining
/// the encrypted channel. `meta` labels the peer for logs and optionally tracks
/// live outbound follow count.
/// Control (ping/pong/`sendcmpct`) first, then full bodies, then headers/inv.
#[doc(hidden)]
pub fn outbound_write_rank(out: &PeerOut) -> u8 {
    match out {
        PeerOut::Msg(
            NetworkMessage::Ping(_) | NetworkMessage::Pong(_) | NetworkMessage::SendCmpct(_),
        ) => 0,
        PeerOut::Encoded(_)
        | PeerOut::Served(_)
        | PeerOut::Msg(NetworkMessage::Block(_))
        | PeerOut::Msg(NetworkMessage::NotFound(_))
        | PeerOut::Msg(NetworkMessage::CmpctBlock(_)) => 1,
        _ => 2,
    }
}

#[doc(hidden)]
pub fn take_outbound_write_batch(
    first: PeerOut,
    rx: &mut mpsc::UnboundedReceiver<PeerOut>,
) -> Vec<PeerOut> {
    let mut batch = Vec::with_capacity(32);
    batch.push(first);
    while batch.len() < 64 {
        match rx.try_recv() {
            Ok(x) => batch.push(x),
            Err(_) => break,
        }
    }
    batch.sort_by_key(outbound_write_rank);
    batch
}

pub async fn run_writer_task(
    mut writer: V2Writer,
    mut out_rx: mpsc::UnboundedReceiver<PeerOut>,
    writer_session: Option<Arc<crate::peers::LivePeer>>,
) {
    while let Some(first) = out_rx.recv().await {
        for out in take_outbound_write_batch(first, &mut out_rx) {
            let n = crate::peers::outbound_queued_bytes(&out);
            let serve_slot = out.holds_serve_slot();
            let err = match out {
                PeerOut::Msg(msg) | PeerOut::Served(msg) => {
                    write_v2_msg_offload(&mut writer, msg).await.is_err()
                }
                PeerOut::Encoded(bytes) => write_v2_contents(&mut writer, bytes).await.is_err(),
            };
            if let Some(s) = &writer_session {
                s.note_out_written(serve_slot, n);
            }
            if err {
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn on_heartbeat(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    requested_since: &mut Option<std::time::Instant>,
    tx_announce_rx: &mut Option<broadcast::Receiver<crate::tx_relay::MempoolAnnounce>>,
    inv_flush_rx: &mut Option<broadcast::Receiver<()>>,
    decode_queued: bool,
) -> Result<(), NetError> {
    if tx_announce_rx.is_none() {
        *tx_announce_rx = hub.mempool().map(|m| m.subscribe_announces());
    }
    if inv_flush_rx.is_none() {
        *inv_flush_rx = hub.mempool().map(|m| m.subscribe_inv_flush());
    }
    let Some(s) = session else {
        return Ok(());
    };
    maybe_queue_feefilter(hub, out_tx, s);
    if addrfetch_timed_out(s) {
        rbitcoin_log::debug!("addrfetch connection timeout");
        s.request_disconnect();
    }
    let now = s.clock_now();
    s.sync_block_download(now, |h| follow.block_in_flight(h));
    // Blocks in flight, or a frame already read and waiting to decode,
    // suspend the ping timeout. A due ping still sends. The next TCP read
    // stays armed, so this is the heartbeat side of that same wait.
    let ping_elapsed = if decode_queued || follow.has_blocks_in_flight() {
        None
    } else {
        s.ping_timeout(now)
    };
    // A body already in `decode_q` is still the oldest block in flight.
    // Timing that window out would drop the frame before it is applied.
    let download_timed_out = if decode_queued {
        None
    } else {
        s.block_download_timed_out(now, hub.params.btc.pow_target_spacing)
    };
    if let Some(hash) = download_timed_out {
        rbitcoin_log::info!("{}", block_download_timeout_log(hash, s.id));
        s.request_disconnect();
    } else if let Some(elapsed_secs) = ping_elapsed {
        rbitcoin_log::info!("{}", ping_timeout_log(elapsed_secs));
        s.request_disconnect();
    } else if let Some(nonce) = s.take_ping_send(now) {
        let _ = queue_out(out_tx, NetworkMessage::Ping(nonce));
    }
    if let Some(ph) = s.peer_hub() {
        ph.on_session_heartbeat();
    }
    // A block or compact frame already sits in `decode_q`. Expiring the
    // ask here forgets it before that frame is applied.
    if !decode_queued {
        if maybe_expire_block_requests(
            hub,
            &mut follow.requested_blocks,
            requested_since,
            std::time::Instant::now(),
            session,
        ) {
            drain_pending(
                hub,
                out_tx,
                &mut follow.pending_blocks,
                &mut follow.pending_headers,
                &mut follow.requested_blocks,
                getdata_use_compact(hub, follow.cmpct_version),
                session,
            )
            .await?;
            if !follow.requested_blocks.is_empty() {
                *requested_since = Some(std::time::Instant::now());
            }
        }
        maybe_expire_pending_cmpct(hub, follow, session, out_tx, std::time::Instant::now())?;
    }
    queue_due_tx_invs(hub, s, &follow.from_this_peer, out_tx);
    queue_due_parent_getdata(hub, s, out_tx);
    let _ = maybe_queue_local_addr(hub, s, out_tx);
    let _ = maybe_queue_initial_getheaders(out_tx, hub, s);
    match crate::peers::PendingSendCmpct::from_u8(s.pending_sendcmpct.swap(0, Ordering::Relaxed)) {
        crate::peers::PendingSendCmpct::Lb => {
            let _ = queue_out(
                out_tx,
                NetworkMessage::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: 2,
                }),
            );
        }
        crate::peers::PendingSendCmpct::Hb => {
            let _ = queue_out(
                out_tx,
                NetworkMessage::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: 2,
                }),
            );
        }
        crate::peers::PendingSendCmpct::None => {}
    }
    Ok(())
}

/// `true` means the tip broadcast closed; the session should exit.
pub async fn on_tip_event(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    tip: Result<crate::chain::TipEvent, broadcast::error::RecvError>,
) -> Result<bool, NetError> {
    let ev = match tip_event_for_announce(tip, hub) {
        TipRecvAnnounce::Closed => return Ok(true),
        TipRecvAnnounce::Skip => return Ok(false),
        TipRecvAnnounce::Announce(ev) => ev,
    };
    if !hub.meets_minimum_chain_work() {
        return Ok(false);
    }
    let from_peer = session.is_some_and(|s| s.take_block_from_peer(&ev.hash));
    let (sent, known) = session.map(|s| s.header_marks()).unwrap_or((None, None));
    // Core NewPoWValidBlock / SendMessages: compact is one-block tip-relay.
    // A lagged TipEvent (generate burst) or a peer who lacks pprev gets headers.
    if follow.send_cmpct
        && !from_peer
        && sent != Some(ev.hash)
        && hub.tip_hash() == Some(ev.hash)
        && (session.is_none()
            || (peer_has_header(hub, sent, known, ev.header.prev_blockhash)
                && !peer_has_header(hub, sent, known, ev.hash)))
    {
        if let Some(msg) = cmpct_tip_announce(hub, &ev.hash, follow.cmpct_version).await? {
            queue_cmpct_tip_announce(out_tx, msg)?;
            if let Some(s) = session {
                s.note_best_header_sent(ev.hash);
            }
            if !follow.wants_headers {
                return Ok(false);
            }
        }
    }
    match tip_announce_decision(hub, &ev, follow.wants_headers, sent, known, from_peer) {
        TipAnnounce::Skip => {}
        TipAnnounce::Inv(h) => {
            queue_out(out_tx, NetworkMessage::Inv(vec![Inventory::Block(h)]))?;
        }
        TipAnnounce::Headers(hs) => {
            if let Some(last) = hs.last() {
                if let Some(s) = session {
                    s.note_best_header_sent(last.block_hash());
                }
            }
            queue_out(out_tx, NetworkMessage::Headers(hs))?;
        }
    }
    Ok(false)
}

#[doc(hidden)]
pub fn on_headers_poll(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
) {
    let skip = session.is_some_and(|s| {
        s.conn_type == crate::peers::PeerConnType::AddrFetch
            || !should_poll_peer_headers(hub, s.best_known())
    });
    if !skip {
        let _ = queue_getheaders(out_tx, hub, session, false, None);
    }
    if let Some(mp) = hub.mempool() {
        mp.expire_stale_from_session();
    }
}

#[doc(hidden)]
pub fn on_tx_announce(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    ann: Option<Result<crate::tx_relay::MempoolAnnounce, broadcast::error::RecvError>>,
) -> Result<(), NetError> {
    let Some(ann) = ann else {
        return Ok(());
    };
    match ann {
        Ok(ann) => on_tx_announce_ok(hub, out_tx, follow, session, ann)?,
        Err(broadcast::error::RecvError::Lagged(_)) | Err(broadcast::error::RecvError::Closed) => {}
    }
    Ok(())
}

#[doc(hidden)]
pub fn on_tx_announce_ok(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    ann: crate::tx_relay::MempoolAnnounce,
) -> Result<(), NetError> {
    let txid = ann.txid;
    if follow.from_this_peer.contains_key(&txid) {
        return Ok(());
    }
    let Some(mp) = hub.mempool() else {
        return Ok(());
    };
    tx_announce_maybe_count(session, mp, &txid);
    if !tx_announce_should_queue(session, mp, &txid) {
        return Ok(());
    }
    let inv = tx_announce_inv(mp, &txid);
    // Flush already recorded this wtxid. A later rebroadcast, including the
    // 15-minute unbroadcast pass, still reaches a peer that has not heard it.
    if let Inventory::WTx(w) = inv {
        if session.is_some_and(|s| s.has_announced_wtx(&w)) {
            return Ok(());
        }
    }
    tx_announce_note_wtx(session, mp, inv);
    queue_out(out_tx, NetworkMessage::Inv(vec![inv]))
}

#[doc(hidden)]
pub fn tx_announce_maybe_count(
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) {
    let Some(s) = session else {
        return;
    };
    if !tx_announce_inbound_gated(s, mp, txid) {
        return;
    }
    if s.session_noban() {
        return;
    }
    if mp.try_contains(txid) {
        s.set_inv_to_send(s.inv_to_send().saturating_add(1));
    }
}

#[doc(hidden)]
pub fn tx_announce_inbound_gated(
    s: &crate::peers::LivePeer,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> bool {
    s.inbound && tx_inv_peer_ok(s, mp, txid) && mp.relay_enabled()
}

/// A tx inv may go to `s`: not block-relay-only, and it asked for txs in
/// VERSION unless the tx is our own unbroadcast one.
fn tx_inv_peer_ok(
    s: &crate::peers::LivePeer,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> bool {
    s.conn_type != crate::peers::PeerConnType::BlockRelay && (s.relay || mp.is_unbroadcast(txid))
}

#[doc(hidden)]
pub fn tx_announce_should_queue(
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> bool {
    !mp.skip_standing_inv(txid)
        && tx_announce_peer_ok(session, mp, txid)
        && mp.try_contains(txid)
        && (mp.relay_enabled() || mp.is_unbroadcast(txid))
        && !tx_announce_below_feefilter(session, mp, txid)
}

#[doc(hidden)]
pub fn tx_announce_inv(mp: &crate::tx_relay::MempoolHub, txid: &bitcoin::Txid) -> Inventory {
    match mp.try_get_tx(txid) {
        Some(tx) => Inventory::WTx(tx.compute_wtxid()),
        None => Inventory::WitnessTransaction(*txid),
    }
}

#[doc(hidden)]
pub fn tx_announce_note_wtx(
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    inv: Inventory,
) {
    let Some(s) = session else {
        return;
    };
    let Inventory::WTx(w) = inv else {
        return;
    };
    s.note_announced_wtx(w);
    if let Some(seq) = mp.relay_seq_of(&w) {
        s.note_tx_inv_seq(s.last_inv_sequence().max(seq.saturating_add(1)));
    }
}

#[doc(hidden)]
pub fn tx_announce_peer_ok(
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> bool {
    session.is_none_or(|s| {
        tx_inv_peer_ok(s, mp, txid) && (!s.inbound || s.session_noban() || !mp.relay_enabled())
    })
}

#[doc(hidden)]
pub fn announce_fee_rate_sat_kvb(
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> Option<u64> {
    let (fee, weight) = mp.try_get_live_meta(txid)?;
    // `prioritisetransaction` changes what we relay, not the base fee.
    let modified = i128::from(fee)
        .saturating_add(i128::from(mp.fee_delta(txid)))
        .max(0) as u64;
    Some(rbitcoin_consensus::policy::fee_rate_sat_per_kvb(
        modified, weight,
    ))
}

#[doc(hidden)]
pub fn tx_announce_below_feefilter(
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    txid: &bitcoin::Txid,
) -> bool {
    let peer_min = session.map(|s| s.minfeefilter_sat_kvb()).unwrap_or(0);
    if peer_min == 0 {
        return false;
    }
    announce_fee_rate_sat_kvb(mp, txid).is_some_and(|rate| rate < peer_min)
}

#[doc(hidden)]
pub fn on_inv_flush(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    flush: Option<Result<(), broadcast::error::RecvError>>,
) {
    if matches!(flush, Some(Ok(()))) {
        if let Some(s) = session {
            s.request_tx_inv();
            queue_due_tx_invs(hub, s, &follow.from_this_peer, out_tx);
            queue_due_parent_getdata(hub, s, out_tx);
            let _ = maybe_queue_initial_getheaders(out_tx, hub, s);
        }
    }
}

struct OpenedPeerWriter {
    peer_s: String,
    out_tx: mpsc::UnboundedSender<PeerOut>,
    writer_task: tokio::task::JoinHandle<()>,
}

/// Handshake bytes and the writer task. The read loop starts only after this
/// returns, so a pong can land before the first inbound frame is applied.
async fn open_peer_writer(
    mut writer: V2Writer,
    hub: &ChainHub,
    meta: &FollowSessionMeta,
) -> OpenedPeerWriter {
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
        s.take_ping_send(s.clock_now())
    } else {
        Some(rand_nonce())
    };
    if let Some(n) = keepalive {
        let _ = write_v2_msg(&mut writer, NetworkMessage::Ping(n)).await;
    }
    if let Some(fee_sat) = outbound_feefilter_sats(hub, meta.session.as_deref()) {
        if write_v2_msg(&mut writer, NetworkMessage::FeeFilter(fee_sat))
            .await
            .is_ok()
        {
            if let Some(s) = meta.session.as_ref() {
                s.note_sent_feefilter(fee_sat);
            }
        }
    }

    let (out_tx, out_rx) = mpsc::unbounded_channel::<PeerOut>();
    if let Some(s) = meta.session.as_ref() {
        s.attach_out(out_tx.clone());
        let _ = maybe_queue_local_addr(hub, s, &out_tx);
    }

    let writer_session = meta.session.clone();
    let writer_task = tokio::spawn(run_writer_task(writer, out_rx, writer_session));
    if let Some(s) = meta.session.as_ref() {
        s.set_writer_abort(writer_task.abort_handle());
    }

    if let Some(s) = meta.session.as_ref() {
        let _ = maybe_queue_addrfetch_getaddr(&out_tx, s);
        let _ = maybe_queue_initial_getheaders(&out_tx, hub, s);
    } else if let Err(e) = queue_getheaders(&out_tx, hub, None, true, None) {
        rbitcoin_log::warn!("p2p: {peer_s} initial getheaders queue failed: {e}");
    }

    OpenedPeerWriter {
        peer_s,
        out_tx,
        writer_task,
    }
}

pub async fn peer_session_with(
    mut reader: V2Reader,
    writer: V2Writer,
    magic: Magic,
    hub: Arc<ChainHub>,
    mut tip_rx: broadcast::Receiver<crate::chain::TipEvent>,
    meta: FollowSessionMeta,
) -> Result<(), NetError> {
    let _live_dec = LiveFollowDec(meta.live.clone());
    let opened = open_peer_writer(writer, hub.as_ref(), &meta).await;
    let peer_s = opened.peer_s;
    let out_tx = opened.out_tx;
    let mut writer_task = opened.writer_task;

    let mut owned_follow = SessionFollow {
        hub: hub.clone(),
        state: PeerFollowState::new(),
    };
    let follow = &mut owned_follow.state;
    if let Some(s) = meta.session.as_ref() {
        follow.wtxid_relay = s.wtxid_relay();
    }
    let mut requested_since: Option<std::time::Instant> = None;
    // Heavy decodes wait for a pool-sized permit on the decode task. This
    // loop keeps reading: a ping or pong already on the socket must not sit
    // in the kernel buffer until a permit frees. Later frames stay behind
    // earlier ones in `decode_q`. Inbound bytes are bounded by the rate
    // limiter and by not assigning more getdata, not by pausing the read.
    let mut decode_q: VecDeque<
        tokio::sync::oneshot::Receiver<Result<RawNetworkMessage, NetError>>,
    > = VecDeque::new();
    let mut decode_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut rate = PeerRateLimiter::default_limits();
    let decoy_score = AtomicU32::new(0);
    let mut logged_invalid_v2 = false;
    let mut tx_announce_rx = hub.mempool().map(|m| m.subscribe_announces());
    let mut inv_flush_rx = hub.mempool().map(|m| m.subscribe_inv_flush());
    let mut headers_poll = tokio::time::interval(Duration::from_secs(HEADERS_POLL_SECS));
    headers_poll.tick().await;

    let session = meta.session.clone();
    let mut last_hb = std::time::Instant::now();
    let mut pending_tip: Option<Result<crate::chain::TipEvent, broadcast::error::RecvError>> = None;
    let mut tip_deadline: Option<tokio::time::Instant> = None;
    let result = async {
        loop {
            if session
                .as_ref()
                .is_some_and(|s| s.stop.load(Ordering::Relaxed))
            {
                apply_queued_decodes(
                    &mut decode_q,
                    hub.as_ref(),
                    &out_tx,
                    follow,
                    session.as_deref(),
                    &mut requested_since,
                    &peer_s,
                )
                .await?;
                return Ok(());
            }
            // Core `fPauseSend`: no inbound message is read while the writer
            // is past the send budget or a getdata / getblocktxn tail waits
            // for serve room. Heartbeat (ping timeout, block-request expiry)
            // still runs.
            let over_budget = session.as_ref().is_some_and(|s| s.send_over_budget());
            let tail_pending =
                !follow.getdata_tail.is_empty() || !follow.getblocktxn_tail.is_empty();
            let reading = !over_budget && !tail_pending;
            let hb_wait = SESSION_HEARTBEAT.saturating_sub(last_hb.elapsed());
            decoy_score.store(follow.ban_score, Ordering::Relaxed);
            tokio::select! {
                biased;
                // Peer half-close / write failure: tear down so getpeerinfo
                // clears without waiting on a stuck read/decode arm.
                decoded = std::future::poll_fn(|cx| {
                    let Some(rx) = decode_q.front_mut() else {
                        return Poll::Pending;
                    };
                    std::pin::Pin::new(rx).poll(cx)
                }), if !decode_q.is_empty() => {
                    decode_q.pop_front();
                    let mut slot = ReadyDecode {
                        queue: &mut decode_q,
                        requested_since: &mut requested_since,
                        peer: &peer_s,
                    };
                    apply_ready_decode(
                        decoded,
                        &mut slot,
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                    )
                    .await?;
                }
                writer_done = &mut writer_task => {
                    let _ = writer_done;
                    apply_queued_decodes(
                        &mut decode_q,
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                        &mut requested_since,
                        &peer_s,
                    )
                    .await?;
                    return Ok(());
                }
                // Inbound before local tip announce so GetData during a
                // generate burst is not queued behind hundreds of cmpctblocks.
                frame = read_v2_frame_with_progress(&mut reader, magic, |_| {}, |n| {
                    let mut score = decoy_score.load(Ordering::Relaxed);
                    let keep = crate::peer_dos::decoy_stays(
                        &mut rate,
                        &mut score,
                        n,
                        BAN_SCORE_THRESHOLD,
                    );
                    decoy_score.store(score, Ordering::Relaxed);
                    if keep {
                        Ok(())
                    } else {
                        Err(NetError::Protocol("peer misbehavior threshold"))
                    }
                }), if reading => {
                    follow.ban_score = decoy_score.load(Ordering::Relaxed);
                    let frame = match frame {
                        Ok(f) => f,
                        // Any socket Io means the peer is gone — exit cleanly so
                        // unregister runs inside the Core disconnect_nodes 5s wait.
                        Err(NetError::Io(_)) => {
                            apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(NetError::Protocol("peer misbehavior threshold")) => {
                            apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await?;
                            return Err(threshold_disconnect(session.as_deref()));
                        }
                        Err(NetError::MessageTooLarge(n)) => {
                            follow.ban_score = follow.ban_score.saturating_add(OVERSIZE_BAN_SCORE);
                            rbitcoin_log::warn!(
                                "p2p: {peer_s} oversize frame ({n}) misbehavior={}",
                                follow.ban_score
                            );
                            apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await?;
                            if follow.ban_score >= BAN_SCORE_THRESHOLD {
                                return Err(threshold_disconnect(session.as_deref()));
                            }
                            return Err(NetError::MessageTooLarge(n));
                        }
                        Err(NetError::InvalidV2Type { contents_len }) => {
                            // Core stays connected; counts raw v2 size as `*other*`.
                            if !logged_invalid_v2 {
                                logged_invalid_v2 = true;
                                rbitcoin_log::debug!("{}", crate::v2::v2_invalid_message_type_log());
                            }
                            if let Some(ref sess) = session {
                                sess.note_recv_raw(
                                    "*other*",
                                    crate::v2::v2_other_recv_bytes(contents_len),
                                );
                            }
                            if !rate.note(contents_len) {
                                follow.ban_score =
                                    follow.ban_score.saturating_add(RATE_LIMIT_BAN_SCORE);
                                rbitcoin_log::warn!(
                                    "p2p: {peer_s} rate limit exceeded misbehavior={}",
                                    follow.ban_score
                                );
                                if follow.ban_score >= BAN_SCORE_THRESHOLD {
                                    apply_queued_decodes(
                                        &mut decode_q,
                                        hub.as_ref(),
                                        &out_tx,
                                        follow,
                                        session.as_deref(),
                                        &mut requested_since,
                                        &peer_s,
                                    )
                                    .await?;
                                    return Err(threshold_disconnect(session.as_deref()));
                                }
                            }
                            continue;
                        }
                        Err(e) => {
                            apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await?;
                            return Err(e);
                        }
                    };
                    if let Some(ref sess) = session {
                        sess.note_recv(&framed_cmd(&frame), frame.payload_len() as u64);
                    }
                    let frame_len = frame.payload_len();
                    if !rate.note(frame_len) {
                        follow.ban_score = follow.ban_score.saturating_add(RATE_LIMIT_BAN_SCORE);
                        rbitcoin_log::warn!(
                            "p2p: {peer_s} rate limit exceeded misbehavior={}",
                            follow.ban_score
                        );
                        if follow.ban_score >= BAN_SCORE_THRESHOLD {
                            apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await?;
                            return Err(threshold_disconnect(session.as_deref()));
                        }
                        apply_queued_decodes(
                            &mut decode_q,
                            hub.as_ref(),
                            &out_tx,
                            follow,
                            session.as_deref(),
                            &mut requested_since,
                            &peer_s,
                        )
                        .await?;
                        // Close to free this session's asks. A second strike refuses the address.
                        return Err(rate_limit_disconnect(session.as_deref()));
                    }
                    // Ping/pong stays on this task when nothing is queued. A
                    // frame already in `decode_q` must be applied first, or a
                    // later pong updates the clock ahead of an earlier block.
                    if (frame.is_ping() || frame.is_pong()) && !decode_q.is_empty() {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let _ = tx.send(frame.try_decode());
                        decode_q.push_back(rx);
                        continue;
                    }
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
                    let n_req = follow.requested_blocks.len();
                    if frame.is_block() || frame.decode_is_cpu_heavy() {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let task = tokio::spawn(async move {
                            let _ = tx.send(decode_framed_offload(frame).await);
                        });
                        decode_tasks.retain(|t| !t.is_finished());
                        decode_tasks.push(task);
                        decode_q.push_back(rx);
                        continue;
                    }
                    if !decode_q.is_empty() {
                        // A heavy decode is still in flight. This frame is
                        // cheap (no permit). Hold it behind the frames already
                        // queued so a block is not overtaken by the tx or inv
                        // that followed it on the wire.
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let _ = tx.send(frame.try_decode());
                        decode_q.push_back(rx);
                        continue;
                    }
                    handle_peer_frame(
                        frame,
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                    )
                    .await?;
                    let n_after = follow.requested_blocks.len();
                    if n_after == 0 {
                        requested_since = None;
                    } else if n_after < n_req || n_req == 0 {
                        requested_since = Some(std::time::Instant::now());
                    }
                    if misbehavior_disconnects(follow.ban_score, session.as_deref()) {
                        rbitcoin_log::warn!(
                            "{}",
                            misbehavior_disconnect_log(&peer_s, follow.ban_score)
                        );
                        return Err(threshold_disconnect(session.as_deref()));
                    }
                }
                tip = tip_rx.recv(), if !over_budget => {
                    let mut tip = tip;
                    loop {
                        match tip_rx.try_recv() {
                            Ok(ev) => tip = Ok(ev),
                            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                                tip = Err(broadcast::error::RecvError::Lagged(0));
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    // A reorg is not a child of the header this peer was sent.
                    // Hold it so a burst becomes one announcement. A normal
                    // extend, and a closed channel, go out immediately.
                    let batch = pending_tip.is_some()
                        || tip_is_reorg_vs_sent(hub.as_ref(), session.as_deref(), &tip);
                    if batch {
                        pending_tip = Some(tip);
                        tip_deadline = Some(tokio::time::Instant::now() + TIP_ANNOUNCE_BATCH);
                    } else if on_tip_event(
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                        tip,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
                _ = async {
                    match tip_deadline {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending::<()>().await,
                    }
                }, if pending_tip.is_some() && !over_budget => {
                    tip_deadline = None;
                    if let Some(tip) = pending_tip.take() {
                        if on_tip_event(
                            hub.as_ref(),
                            &out_tx,
                            follow,
                            session.as_deref(),
                            tip,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                }
                _ = headers_poll.tick(), if !over_budget => {
                    on_headers_poll(hub.as_ref(), &out_tx, session.as_deref());
                }
                ann = async {
                    if let Some(rx) = tx_announce_rx.as_mut() {
                        Some(rx.recv().await)
                    } else {
                        std::future::pending::<()>().await;
                        None
                    }
                }, if !over_budget => {
                    on_tx_announce(
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                        ann,
                    )?;
                }
                flush = async {
                    if let Some(rx) = inv_flush_rx.as_mut() {
                        Some(rx.recv().await)
                    } else {
                        std::future::pending::<()>().await;
                        None
                    }
                }, if !over_budget => {
                    on_inv_flush(
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                        flush,
                    );
                }
                // Inbound is biased first so a queued pong beats ping-timeout.
                _ = tokio::time::sleep(hb_wait), if session.is_some() => {
                    on_heartbeat(
                        hub.as_ref(),
                        &out_tx,
                        follow,
                        session.as_deref(),
                        &mut requested_since,
                        &mut tx_announce_rx,
                        &mut inv_flush_rx,
                        !decode_q.is_empty(),
                    )
                    .await?;
                    last_hb = std::time::Instant::now();
                    continue;
                }
                // After the heartbeat: a tail that keeps finding room must
                // not starve the ping timeout.
                () = async {
                    if let Some(s) = session.as_deref() {
                        s.wait_send_budget().await;
                    }
                }, if over_budget && !tail_pending => {}
                room = async {
                    match session.as_deref() {
                        Some(s) => s.wait_serve_room(&out_tx).await,
                        None => true,
                    }
                }, if tail_pending => {
                    if !room {
                        apply_queued_decodes(
                            &mut decode_q,
                            hub.as_ref(),
                            &out_tx,
                            follow,
                            session.as_deref(),
                            &mut requested_since,
                            &peer_s,
                        )
                        .await?;
                        return Ok(());
                    }
                    if !follow.getdata_tail.is_empty() {
                        if let Err(e) = serve_getdata_tail(
                            hub.as_ref(),
                            &out_tx,
                            follow,
                            session.as_deref(),
                        )
                        .await
                        {
                            let _ = apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await;
                            return Err(e);
                        }
                    }
                    if !follow.getblocktxn_tail.is_empty() {
                        if let Err(e) = serve_getblocktxn_tail(
                            hub.as_ref(),
                            &out_tx,
                            follow,
                            session.as_deref(),
                        )
                        .await
                        {
                            let _ = apply_queued_decodes(
                                &mut decode_q,
                                hub.as_ref(),
                                &out_tx,
                                follow,
                                session.as_deref(),
                                &mut requested_since,
                                &peer_s,
                            )
                            .await;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
    .await;

    // A `?` in the tip or tx-announce arm leaves frames that were already
    // read. Apply them before `SessionFollow` forgets their getdata.
    let drained = apply_queued_decodes(
        &mut decode_q,
        hub.as_ref(),
        &out_tx,
        follow,
        session.as_deref(),
        &mut requested_since,
        &peer_s,
    )
    .await;
    let result = match (result, drained) {
        (Err(e), _) => Err(e),
        (Ok(()), drained) => drained,
    };

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
pub fn tip_follow_locator(hub: &ChainHub) -> Vec<BlockHash> {
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
pub fn headers_sync_locator(hub: &ChainHub, from: Option<BlockHash>) -> Vec<BlockHash> {
    match from {
        None => tip_follow_locator(hub),
        Some(start) => locator_from_start(hub, start),
    }
}

#[doc(hidden)]
pub fn locator_from_start(hub: &ChainHub, start: BlockHash) -> Vec<BlockHash> {
    if let Some(h) = hub.query.published_height_of_hash(&start.to_byte_array()) {
        return locator_from_height(hub, h.0);
    }
    let mut out = vec![start];
    push_genesis_locator(hub, &mut out);
    out
}

#[doc(hidden)]
pub fn locator_from_height(hub: &ChainHub, start: u32) -> Vec<BlockHash> {
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

#[doc(hidden)]
pub fn push_genesis_locator(hub: &ChainHub, out: &mut Vec<BlockHash>) {
    let g = hub.params.genesis_hash;
    if out.last() != Some(&g) {
        out.push(g);
    }
}

/// Periodic getheaders is for discovering more work. Skip peers whose best
/// known header is already on our chain behind tip, or a connecting fork that
/// cannot beat us.
pub fn should_poll_peer_headers(hub: &ChainHub, best_known: Option<BlockHash>) -> bool {
    let Some(best) = best_known else {
        return true;
    };
    let our_tip = hub.tip_height().unwrap_or(0);
    if let Some(h) = hub.query.published_height_of_hash(&best.to_byte_array()) {
        return h.0 >= our_tip;
    }
    let empty = HashMap::new();
    !matches!(
        header_branch_vs_tip(hub, &empty, best),
        Some(std::cmp::Ordering::Less)
    )
}

/// Start Core's single initial headers sync on this session.
///
/// The header walk does not see this session. Skipping the ask while the
/// tip is older than 24 hours left regtest peers with an empty block queue.
/// [`crate::peers::PeerHub::try_start_headers_sync`] still allows one peer
/// until the tip is caught up.
#[doc(hidden)]
pub fn maybe_queue_initial_getheaders(
    out: &mpsc::UnboundedSender<PeerOut>,
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
        .peer_hub()
        .is_some_and(|ph| ph.try_start_headers_sync(session, now, best_t));
    if started {
        let h = hub.tip_height().unwrap_or(0);
        rbitcoin_log::info!("{}", crate::chain::initial_getheaders_log(h, session.id));
        let _ = queue_getheaders(out, hub, Some(session), true, None);
    }
    started
}

#[doc(hidden)]
pub fn maybe_queue_addrfetch_getaddr(
    out: &mpsc::UnboundedSender<PeerOut>,
    session: &crate::peers::LivePeer,
) -> bool {
    if session.conn_type != crate::peers::PeerConnType::AddrFetch {
        return false;
    }
    session.credit_getaddr_reply();
    let _ = queue_out(out, NetworkMessage::GetAddr);
    true
}

#[doc(hidden)]
pub fn addrfetch_timed_out(session: &crate::peers::LivePeer) -> bool {
    session.conn_type == crate::peers::PeerConnType::AddrFetch
        && session.clock_now().saturating_sub(session.connected_at()) > ADDRFETCH_TIMEOUT_SECS
}

#[doc(hidden)]
pub fn queue_getheaders(
    out: &mpsc::UnboundedSender<PeerOut>,
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

/// BIP152: request `MSG_CMPCT_BLOCK` when the peer speaks compact v2 and
/// [`compact_blocks_ok`] is true. Blocks-only, and a mempool that is not
/// receiving transactions, keep `MSG_WITNESS_BLOCK`.
#[doc(hidden)]
pub fn getdata_use_compact(hub: &ChainHub, peer_cmpct_version: u32) -> bool {
    peer_cmpct_version == 2 && compact_blocks_ok(hub)
}

/// Drop inflight body asks the peer never answered so `asked_blocks` cannot
/// permanently skip the same hashes (`rpc_createmultisig` generate-149
/// `sync_blocks` 60s).
pub fn maybe_expire_block_requests(
    hub: &ChainHub,
    requested: &mut HashSet<BlockHash>,
    since: &mut Option<std::time::Instant>,
    now: std::time::Instant,
    session: Option<&crate::peers::LivePeer>,
) -> bool {
    if requested.is_empty() {
        *since = None;
        return false;
    }
    let start = *since.get_or_insert(now);
    if now.saturating_duration_since(start) < BLOCK_GETDATA_TIMEOUT {
        return false;
    }
    for h in requested.drain() {
        hub.forget_asked_block(&h);
        if let Some(s) = session {
            s.release_cmpct_taken(h);
        }
    }
    *since = None;
    true
}

#[doc(hidden)]
pub fn maybe_expire_pending_cmpct(
    hub: &ChainHub,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    out: &mpsc::UnboundedSender<PeerOut>,
    now: std::time::Instant,
) -> Result<bool, NetError> {
    let stale: Vec<BlockHash> = follow
        .pending_cmpct
        .iter()
        .filter(|(_, pc)| now.saturating_duration_since(pc.since) >= BLOCK_GETDATA_TIMEOUT)
        .map(|(h, _)| *h)
        .collect();
    if stale.is_empty() {
        return Ok(false);
    }
    for hash in stale {
        drop_pending_cmpct(follow, session, hash);
        queue_block_getdata(
            hub,
            out,
            session,
            &mut follow.requested_blocks,
            &[hash],
            false,
        )?;
    }
    Ok(true)
}

#[doc(hidden)]
pub fn queue_block_getdata(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
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
            if compact && compact_getdata_near_tip(hub, h) {
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
    if let Some(s) = session {
        s.note_blocks_requested(want);
    }
    for chunk in inv.chunks(MAX_INV_SIZE.min(500)) {
        queue_accounted(session, out, NetworkMessage::GetData(chunk.to_vec()))?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn take_requested_block(hub: &ChainHub, requested: &mut HashSet<BlockHash>, hash: &BlockHash) {
    requested.remove(hash);
    hub.forget_asked_block(hash);
}

#[doc(hidden)]
pub fn net_error_needs_parent(e: &NetError) -> bool {
    matches!(e, NetError::UnknownParent)
}

/// Incomplete compact block waiting for `blocktxn`.
#[doc(hidden)]
pub struct PendingCmpct {
    pub hsi: HeaderAndShortIds,
    pub partial: crate::compact::CmpctPartial,
    pub fill: Option<crate::compact::CmpctFillSets>,
    pub since: std::time::Instant,
}

/// Clone only mempool bodies whose short-ids appear in `hsi` (never `list_live`).
#[doc(hidden)]
pub fn mempool_shortid_avail(
    hub: &ChainHub,
    hsi: &HeaderAndShortIds,
    version: u32,
) -> (
    HashMap<bitcoin::bip152::ShortId, Vec<Transaction>>,
    Option<crate::compact::CmpctFillSets>,
) {
    shortid_avail(hub.mempool().map(Arc::as_ref), hsi, version)
}

fn shortid_avail(
    mp: Option<&crate::tx_relay::MempoolHub>,
    hsi: &HeaderAndShortIds,
    version: u32,
) -> (
    HashMap<bitcoin::bip152::ShortId, Vec<Transaction>>,
    Option<crate::compact::CmpctFillSets>,
) {
    let pref: Vec<bitcoin::Wtxid> = hsi
        .prefilled_txs
        .iter()
        .map(|p| p.tx.compute_wtxid())
        .collect();
    match mp
        .and_then(|mp| mp.try_cmpct_avail(&hsi.header, hsi.nonce, version, &hsi.short_ids, &pref))
    {
        Some((txs, fill)) => (txs, Some(fill)),
        None => (HashMap::new(), None),
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub enum CmpctReconstruct {
    Block(Block, Option<Box<crate::compact::CmpctFillSets>>),
    NeedTxn(
        crate::compact::CmpctPartial,
        Option<Box<crate::compact::CmpctFillSets>>,
    ),
    GetData,
}

/// One reconstruct: full block, getblocktxn indexes, or no mempool (`None` → getdata).
#[doc(hidden)]
pub fn try_reconstruct_cmpct(
    hub: &ChainHub,
    hsi: &HeaderAndShortIds,
    version: u32,
) -> Option<CmpctReconstruct> {
    reconstruct_cmpct_from_mempool(hub.mempool().map(Arc::as_ref), hsi, version)
}

fn reconstruct_cmpct_from_mempool(
    mp: Option<&crate::tx_relay::MempoolHub>,
    hsi: &HeaderAndShortIds,
    version: u32,
) -> Option<CmpctReconstruct> {
    crate::reactor::assert_not_reactor("compact reconstruct");
    let (owned, fill) = shortid_avail(mp, hsi, version);
    match crate::compact::reconstruct(hsi, &owned) {
        crate::compact::Reconstruct::Block(block) => {
            Some(CmpctReconstruct::Block(block, fill.map(Box::new)))
        }
        crate::compact::Reconstruct::Fail => Some(CmpctReconstruct::GetData),
        crate::compact::Reconstruct::Partial(_) if mp.is_none() => None,
        crate::compact::Reconstruct::Partial(p) => {
            Some(CmpctReconstruct::NeedTxn(p, fill.map(Box::new)))
        }
    }
}

#[doc(hidden)]
pub fn log_cmpct_filled(
    hub: &ChainHub,
    hsi: &HeaderAndShortIds,
    block: &Block,
    fetched: &[u64],
    fill: Option<&crate::compact::CmpctFillSets>,
) {
    let stats = crate::compact::reconstruct_stats(
        hsi,
        block,
        fill.unwrap_or(&crate::compact::CmpctFillSets::default()),
        fetched,
    );
    rbitcoin_log::info!("{stats}");
    if let Some(indexes) = crate::compact::outbound_prefill_indexes(block, fill) {
        hub.remember_cmpct_prefill(block.block_hash(), block.header.prev_blockhash, indexes);
    }
}

#[doc(hidden)]
pub fn log_cmpct_getdata(hash: BlockHash, missing_n: usize) {
    rbitcoin_log::info!(
        "{}",
        crate::compact::reconstruct_getdata_stats(hash, missing_n)
    );
}

/// Flush due / unbroadcast tx INVs onto every live session writer.
/// Used by RPC sendraw and whitelist-relay accept (`p2p_blocksonly`).
pub fn flush_tx_invs(hub: &ChainHub, peers: &crate::peers::PeerHub) {
    let rows = peers.live_peers();
    for s in rows {
        s.request_tx_inv();
        if let Some(out) = s.writer() {
            queue_due_tx_invs(hub, s.as_ref(), &CappedSet::new(), &out);
            queue_due_parent_getdata(hub, s.as_ref(), &out);
        }
    }
}

/// INV one live mempool tx to every peer that has not seen it, ignoring the
/// inbound age gate and `inv_gen_floor` (Core same-nonwitness rebroadcast).
pub fn force_announce_txid(hub: &ChainHub, peers: &crate::peers::PeerHub, txid: bitcoin::Txid) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    if mp.skip_standing_inv(&txid) {
        return;
    }
    let Some(tx) = mp.try_get_tx(&txid) else {
        return;
    };
    let w = tx.compute_wtxid();
    for s in peers.live_peers() {
        if !tx_inv_peer_ok(&s, mp, &txid) {
            continue;
        }
        if s.has_announced_wtx(&w) {
            continue;
        }
        let peer_min = s.minfeefilter_sat_kvb();
        if peer_min > 0 && announce_fee_rate_sat_kvb(mp, &txid).is_some_and(|rate| rate < peer_min)
        {
            continue;
        }
        let Some(out) = s.writer() else {
            continue;
        };
        s.note_announced_wtx(w);
        queue_tx_inv_batches(&s, &out, vec![Inventory::WTx(w)]);
        if let Some(seq) = mp.relay_seq_of(&w) {
            s.note_tx_inv_seq(s.last_inv_sequence().max(seq.saturating_add(1)));
        }
    }
}

#[doc(hidden)]
pub fn maybe_force_relay_recent_reject(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    mp: &crate::tx_relay::MempoolHub,
    txid: bitcoin::Txid,
    wtxid: bitcoin::Wtxid,
) {
    if !session.is_some_and(|s| s.session_forcerelay()) {
        return;
    }
    let id = session.map(|s| s.id).unwrap_or(0);
    if mp.try_contains(&txid) {
        rbitcoin_log::info!("p2p: Force relaying tx {txid} (wtxid={wtxid}) from peer={id}");
        if let Some(ph) = session.and_then(|s| s.peer_hub()) {
            force_announce_txid(hub, ph.as_ref(), txid);
        }
    } else {
        rbitcoin_log::info!(
            "p2p: Not relaying non-mempool transaction {txid} (wtxid={wtxid}) from forcerelay peer={id}"
        );
    }
}

#[doc(hidden)]
pub fn maybe_force_relay_duplicate(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    tx: &Transaction,
    tid: bitcoin::Txid,
) {
    if !session.is_some_and(|s| s.session_forcerelay()) {
        return;
    }
    let id = session.map(|s| s.id).unwrap_or(0);
    rbitcoin_log::info!(
        "p2p: Force relaying tx {tid} (wtxid={}) from peer={id}",
        tx.compute_wtxid()
    );
    if let Some(ph) = session.and_then(|s| s.peer_hub()) {
        force_announce_txid(hub, ph.as_ref(), tid);
    }
}

#[doc(hidden)]
pub fn tx_inv_candidate_ok(
    mp: &crate::tx_relay::MempoolHub,
    session: &crate::peers::LivePeer,
    from_this_peer: &CappedSet<bitcoin::Txid>,
    txid: bitcoin::Txid,
    w: bitcoin::Wtxid,
    clock_due: bool,
    inbound_age_gate: bool,
) -> bool {
    if mp.skip_standing_inv(&txid) {
        return false;
    }
    if from_this_peer.contains_key(&txid) {
        return false;
    }
    if !tx_inv_peer_ok(session, mp, &txid) {
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
    if peer_min > 0 && announce_fee_rate_sat_kvb(mp, &txid).is_some_and(|rate| rate < peer_min) {
        return false;
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

#[doc(hidden)]
pub fn queue_due_tx_invs(
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
    from_this_peer: &CappedSet<bitcoin::Txid>,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    if session.conn_type == crate::peers::PeerConnType::BlockRelay
        || (!session.relay && mp.unbroadcast_count() == 0)
    {
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
    let inbound_age_gate = session.inbound && mp.relay_enabled() && !session.session_noban();
    let mut n = 0u32;
    let mut max_ann = session.last_inv_sequence();
    let mp_now = mp.relay_now_secs();
    if clock_due || unbroadcast_due {
        let Some(live_wtx) = mp.try_list_live_wtxids() else {
            return;
        };
        let mut due = Vec::new();
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
            due.push(Inventory::WTx(w));
            n += 1;
            if let Some(seq) = mp.relay_seq_of(&w) {
                max_ann = max_ann.max(seq.saturating_add(1));
            }
        }
        queue_tx_inv_batches(session, out_tx, due);
        if let Some((due, gen)) = mp.try_age_inv_watermark(mp_now) {
            session.note_age_inv_seen(due, gen);
        }
    } else {
        let Some((last, due_wtx)) = mp.try_age_inv_since(session.age_inv_seen(), mp_now) else {
            return;
        };
        session.note_age_inv_seen(last.0, last.1);
        let mut due = Vec::new();
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
            due.push(Inventory::WTx(w));
            n += 1;
            if let Some(seq) = mp.relay_seq_of(&w) {
                max_ann = max_ann.max(seq.saturating_add(1));
            }
        }
        queue_tx_inv_batches(session, out_tx, due);
    }
    if n > 0 {
        // Only INV txs that existed when this INV was built.
        // Never snap to current_relay_seq() — a later accept can race in
        // and make the new entry servable (mempool_reorg.py:122).
        session.note_tx_inv_seq(max_ann.max(session.last_inv_sequence()));
        session.set_inv_to_send(0);
    }
}

/// Finish a pending compact block with a `blocktxn` payload.
#[doc(hidden)]
#[allow(clippy::result_unit_err)] // a short blocktxn is (); the caller scores the peer
pub fn apply_cmpct_blocktxn(
    pc: &PendingCmpct,
    bt: &BlockTransactions,
) -> Result<(Block, Option<crate::compact::CmpctFillSets>), ()> {
    crate::compact::apply_block_transactions(&pc.hsi, &pc.partial, bt)
        .map(|block| (block, pc.fill.clone()))
        .map_err(|_| ())
}

#[doc(hidden)]
pub struct PeerFollowState {
    pub wants_headers: bool,
    pub wtxid_relay: bool,
    pub send_cmpct: bool,
    pub cmpct_version: u32,
    pub pending_headers: HashMap<BlockHash, bitcoin::block::Header>,
    pub pending_blocks: PendingBlocks,
    pub pending_cmpct: HashMap<BlockHash, PendingCmpct>,
    pub from_this_peer: CappedSet<bitcoin::Txid>,
    pub requested_blocks: HashSet<BlockHash>,
    pub ban_score: u32,
    /// Unserved rest of an inbound `getdata` paused on the writer (Core
    /// `m_getdata_requests`). The session reads no frame while it is
    /// non-empty, so it holds at most one message: `MAX_INV_SIZE` items,
    /// about 2 MB per session. That RAM keeps every hash served in order
    /// instead of dropping the rest or holding the reader across items.
    pub getdata_tail: VecDeque<Inventory>,
    /// One parked `getblocktxn`. The session reads no frame while this is
    /// non-empty, so a peer that never reads cannot stack reconstructs.
    pub getblocktxn_tail: VecDeque<BlockTransactionsRequest>,
}

/// A live session's follow state. Dropping it, including when
/// `PeerHub::disconnect_id` aborts the session task, releases the body asks
/// the peer never answered: `asked_blocks` is hub-wide, so a held ask would
/// keep every other peer from fetching that body.
#[doc(hidden)]
pub struct SessionFollow {
    pub hub: Arc<ChainHub>,
    pub state: PeerFollowState,
}

impl Drop for SessionFollow {
    fn drop(&mut self) {
        for h in self.state.requested_blocks.drain() {
            self.hub.forget_asked_block(&h);
        }
    }
}

impl PeerFollowState {
    /// Core `vBlocksInFlight`: a body asked by `getdata`, or a compact
    /// block waiting on `blocktxn`.
    pub fn has_blocks_in_flight(&self) -> bool {
        !self.requested_blocks.is_empty() || !self.pending_cmpct.is_empty()
    }

    pub fn block_in_flight(&self, hash: &BlockHash) -> bool {
        self.requested_blocks.contains(hash) || self.pending_cmpct.contains_key(hash)
    }

    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            wants_headers: false,
            wtxid_relay: false,
            send_cmpct: false,
            cmpct_version: 0,
            pending_headers: HashMap::new(),
            pending_blocks: PendingBlocks::new(),
            pending_cmpct: HashMap::new(),
            from_this_peer: CappedSet::new(),
            requested_blocks: HashSet::new(),
            ban_score: 0,
            getdata_tail: VecDeque::new(),
            getblocktxn_tail: VecDeque::new(),
        }
    }
}

#[doc(hidden)]
pub fn serve_mempool_getdata(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    tx: Option<bitcoin::Transaction>,
) -> Result<bool, NetError> {
    let Some(mp) = hub.mempool() else {
        return Ok(false);
    };
    let Some(tx) = tx else {
        return Ok(false);
    };
    let wtxid = tx.compute_wtxid();
    let announced = session.is_some_and(|s| s.has_announced_wtx(&wtxid));
    let last_inv = session.map(|s| s.last_inv_sequence()).unwrap_or(1);
    if announced || mp.is_relay_servable(&wtxid, last_inv) {
        mp.mark_broadcast(&tx.compute_txid());
        queue_accounted(session, out_tx, NetworkMessage::Tx(tx))?;
        return Ok(true);
    }
    Ok(false)
}

fn note_block_request_window(
    follow: &PeerFollowState,
    n_req: usize,
    requested_since: &mut Option<std::time::Instant>,
) {
    let n_after = follow.requested_blocks.len();
    if n_after == 0 {
        *requested_since = None;
    } else if n_after < n_req || n_req == 0 {
        *requested_since = Some(std::time::Instant::now());
    }
}

struct ReadyDecode<'a> {
    queue: &'a mut VecDeque<tokio::sync::oneshot::Receiver<Result<RawNetworkMessage, NetError>>>,
    requested_since: &'a mut Option<std::time::Instant>,
    peer: &'a str,
}

/// Apply one frame that already left the socket. A dropped decode task or a
/// failed apply still drains frames behind it, so `SessionFollow` does not
/// forget their getdata.
async fn apply_ready_decode(
    decoded: Result<Result<RawNetworkMessage, NetError>, tokio::sync::oneshot::error::RecvError>,
    slot: &mut ReadyDecode<'_>,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let decoded = match decoded {
        Ok(r) => r,
        Err(_) => {
            let _ = apply_queued_decodes(
                slot.queue,
                hub,
                out_tx,
                follow,
                session,
                slot.requested_since,
                slot.peer,
            )
            .await;
            return Err(NetError::Protocol("decode task dropped"));
        }
    };
    let n_req = follow.requested_blocks.len();
    let applied = apply_decoded_peer_msg(decoded, hub, out_tx, follow, session).await;
    note_block_request_window(follow, n_req, slot.requested_since);
    if let Err(e) = applied {
        let _ = apply_queued_decodes(
            slot.queue,
            hub,
            out_tx,
            follow,
            session,
            slot.requested_since,
            slot.peer,
        )
        .await;
        return Err(e);
    }
    if misbehavior_disconnects(follow.ban_score, session) {
        rbitcoin_log::warn!(
            "{}",
            misbehavior_disconnect_log(slot.peer, follow.ban_score)
        );
        let _ = apply_queued_decodes(
            slot.queue,
            hub,
            out_tx,
            follow,
            session,
            slot.requested_since,
            slot.peer,
        )
        .await;
        return Err(threshold_disconnect(session));
    }
    Ok(())
}

/// Apply frames already taken off the socket, in order, before a later read
/// error tears the session down. `SessionFollow`'s drop would otherwise
/// forget getdata for a block that is still sitting in `decode_q`.
async fn apply_queued_decodes(
    decode_q: &mut VecDeque<tokio::sync::oneshot::Receiver<Result<RawNetworkMessage, NetError>>>,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    requested_since: &mut Option<std::time::Instant>,
    peer_s: &str,
) -> Result<(), NetError> {
    let mut first_err: Option<NetError> = None;
    while let Some(rx) = decode_q.pop_front() {
        let decoded = match rx.await {
            Ok(r) => r,
            Err(_) => {
                if first_err.is_none() {
                    first_err = Some(NetError::Protocol("decode task dropped"));
                }
                continue;
            }
        };
        let n_req = follow.requested_blocks.len();
        if let Err(e) = apply_decoded_peer_msg(decoded, hub, out_tx, follow, session).await {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
        note_block_request_window(follow, n_req, requested_since);
        if misbehavior_disconnects(follow.ban_score, session) && first_err.is_none() {
            rbitcoin_log::warn!("{}", misbehavior_disconnect_log(peer_s, follow.ban_score));
            first_err = Some(threshold_disconnect(session));
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

async fn apply_decoded_peer_msg(
    decoded: Result<RawNetworkMessage, NetError>,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let msg = match decoded {
        Ok(m) => m,
        Err(NetError::MessageTooLarge(n)) => {
            follow.ban_score = follow.ban_score.saturating_add(OVERSIZE_BAN_SCORE);
            return Err(NetError::MessageTooLarge(n));
        }
        Err(e) => return Err(e),
    };
    handle_decoded_peer_msg(msg, hub, out_tx, follow, session).await
}

pub async fn handle_peer_frame(
    frame: FramedMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let msg = match decode_framed_offload(frame).await {
        Ok(m) => m,
        Err(NetError::MessageTooLarge(n)) => {
            follow.ban_score = follow.ban_score.saturating_add(OVERSIZE_BAN_SCORE);
            return Err(NetError::MessageTooLarge(n));
        }
        Err(e) => return Err(e),
    };
    handle_decoded_peer_msg(msg, hub, out_tx, follow, session).await
}

pub async fn handle_decoded_peer_msg(
    msg: RawNetworkMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    match msg.into_payload() {
        NetworkMessage::GetData(inv) => serve_getdata(hub, out_tx, follow, session, inv).await?,
        NetworkMessage::GetHeaders(gh) => {
            if session.is_some_and(|s| s.send_over_budget()) {
                return Ok(());
            }
            on_getheaders(hub, out_tx, follow, session, &gh).await?
        }
        NetworkMessage::GetBlocks(gb) => {
            if session.is_some_and(|s| s.send_over_budget()) {
                return Ok(());
            }
            on_getblocks(hub, out_tx, follow, session, &gb).await?
        }
        NetworkMessage::Headers(headers) => {
            // The frame is already off the socket. Store it and clear the
            // locator latch. Getdata and the next getheaders wait in
            // `apply_headers` until the writer drains.
            on_headers(hub, out_tx, follow, session, &headers).await?
        }
        NetworkMessage::Block(block) => on_block(hub, out_tx, follow, session, &block).await?,
        NetworkMessage::CmpctBlock(cb) => on_cmpctblock(hub, out_tx, follow, session, &cb).await?,
        NetworkMessage::BlockTxn(BlockTxn { transactions: bt }) => {
            on_blocktxn(hub, out_tx, follow, session, &bt).await?
        }
        NetworkMessage::Tx(tx) => on_tx(hub, out_tx, follow, session, &tx).await?,
        NetworkMessage::GetBlockTxn(GetBlockTxn { txs_request }) => {
            serve_getblocktxn(hub, out_tx, follow, session, txs_request).await?
        }
        other => handle_peer_sync_msg(&other, hub, out_tx, follow, session)?,
    }
    Ok(())
}

#[doc(hidden)]
pub fn handle_peer_sync_msg(
    payload: &NetworkMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    if handle_peer_control_msg(payload, hub, out_tx, follow, session)? {
        return Ok(());
    }
    handle_peer_inventory_msg(payload, hub, out_tx, follow, session)
}

#[doc(hidden)]
pub fn handle_peer_control_msg(
    payload: &NetworkMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<bool, NetError> {
    match payload {
        NetworkMessage::Version(_) => on_redundant_version(session),
        NetworkMessage::Verack => on_redundant_verack(session),
        NetworkMessage::Ping(n) => on_ping(hub, out_tx, follow, session, *n)?,
        // A pong that waited behind `decode_q` is applied here. The read arm
        // only handles a pong when that queue is empty.
        NetworkMessage::Pong(n) => {
            if let Some(s) = session {
                let payload = n.to_le_bytes();
                if let Some(line) = s.on_pong(&payload, s.clock_now()) {
                    rbitcoin_log::info!("{line}");
                }
            }
        }
        NetworkMessage::FeeFilter(amt) => on_feefilter(session, *amt),
        NetworkMessage::SendHeaders => on_sendheaders(follow),
        NetworkMessage::SendCmpct(sc) => on_sendcmpct(follow, session, sc),
        // rust-bitcoin rejects announce bytes other than 0 or 1 at decode,
        // so a bad sendcmpct arrives as Unknown. BIP152 disconnects that.
        NetworkMessage::Unknown { command, .. } if command.as_ref() == "sendcmpct" => {
            rbitcoin_log::info!("invalid sendcmpct announce field");
            punish_disconnect(&mut follow.ban_score, session);
        }
        NetworkMessage::WtxidRelay => on_wtxid_relay(follow, session),
        NetworkMessage::SendAddrV2 => on_sendaddrv2(follow, session),
        _ => return Ok(false),
    }
    Ok(true)
}

#[doc(hidden)]
pub fn filter_q<T>(r: Result<T, rbitcoin_store::StoreError>) -> Result<T, NetError> {
    r.map_err(|e| NetError::Consensus(e.to_string()))
}

#[doc(hidden)]
pub fn on_compact_filters(
    payload: &NetworkMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    match payload {
        NetworkMessage::GetCFilters(m) => on_getcfilters(hub, out_tx, session, m),
        NetworkMessage::GetCFHeaders(m) => on_getcfheaders(hub, out_tx, session, m),
        NetworkMessage::GetCFCheckpt(m) => on_getcfcheckpt(hub, out_tx, session, m),
        _ => Ok(()),
    }
}

/// Core `MAX_GETCFILTERS_SIZE` / `MAX_GETCFHEADERS_SIZE`.
#[doc(hidden)]
pub const MAX_GETCFILTERS: u32 = 1000;
#[doc(hidden)]
pub const MAX_GETCFHEADERS: u32 = 2000;

/// Core `PrepareBlockFilterRequest` range rule: start past stop, or `max`
/// or more heights, disconnects the peer.
#[doc(hidden)]
pub fn compact_filter_range(start: u32, stop: u32, max: u32) -> Result<(), NetError> {
    if start > stop {
        return Err(NetError::Protocol("compact filter request start past stop"));
    }
    if stop - start >= max {
        return Err(NetError::Protocol("compact filter request range too large"));
    }
    Ok(())
}

/// Stop height of a basic-filter request. `None` (silence: not a short
/// batch, not an empty filter) when the index is off, the stop hash is not
/// on the best chain, or the stop is past the filter watermark.
#[doc(hidden)]
pub fn compact_filter_stop(
    hub: &ChainHub,
    filter_type: u8,
    stop_hash: &[u8; 32],
) -> Result<Option<u32>, NetError> {
    if filter_type != 0 || !hub.query.block_filter_enabled() {
        return Ok(None);
    }
    Ok(filter_q(hub.query.height_of_hash(stop_hash))?.map(|h| h.0))
}

#[doc(hidden)]
pub fn within_filter_watermark(hub: &ChainHub, stop: u32) -> Result<bool, NetError> {
    Ok(filter_q(hub.query.basic_filter_hwm())?.is_some_and(|hwm| stop <= hwm))
}

#[doc(hidden)]
pub fn on_getcfilters(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    m: &bitcoin::p2p::message_filter::GetCFilters,
) -> Result<(), NetError> {
    use bitcoin::hashes::Hash;
    let Some(stop) = compact_filter_stop(hub, m.filter_type, m.stop_hash.as_byte_array())? else {
        return Ok(());
    };
    compact_filter_range(m.start_height, stop, MAX_GETCFILTERS)?;
    if !within_filter_watermark(hub, stop)? {
        return Ok(());
    }
    let Some(filters) = filter_q(hub.query.basic_filters(m.start_height, stop))? else {
        return Ok(());
    };
    for (h, body) in (m.start_height..).zip(filters) {
        let Some((_, rec)) = filter_q(hub.query.header_at_height(rbitcoin_primitives::Height(h)))?
        else {
            return Ok(());
        };
        queue_accounted(
            session,
            out_tx,
            NetworkMessage::CFilter(bitcoin::p2p::message_filter::CFilter {
                filter_type: 0,
                block_hash: bitcoin::BlockHash::from_byte_array(rec.hash),
                filter: body,
            }),
        )?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn on_getcfheaders(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    m: &bitcoin::p2p::message_filter::GetCFHeaders,
) -> Result<(), NetError> {
    use bitcoin::bip158::FilterHeader;
    use bitcoin::hashes::Hash;
    let Some(stop) = compact_filter_stop(hub, m.filter_type, m.stop_hash.as_byte_array())? else {
        return Ok(());
    };
    compact_filter_range(m.start_height, stop, MAX_GETCFHEADERS)?;
    if !within_filter_watermark(hub, stop)? {
        return Ok(());
    }
    // One idx read covers the previous header and every hash in range.
    let first = m.start_height.saturating_sub(1);
    let Some(rows) = filter_q(hub.query.basic_filter_hashes_and_headers(first, stop))? else {
        return Ok(());
    };
    let (previous, hashes) = if m.start_height == 0 {
        (FilterHeader::from_byte_array([0u8; 32]), &rows[..])
    } else {
        (rows[0].1, &rows[1..])
    };
    queue_accounted(
        session,
        out_tx,
        NetworkMessage::CFHeaders(bitcoin::p2p::message_filter::CFHeaders {
            filter_type: 0,
            stop_hash: m.stop_hash,
            previous_filter_header: previous,
            filter_hashes: hashes.iter().map(|(hash, _)| *hash).collect(),
        }),
    )?;
    Ok(())
}

#[doc(hidden)]
pub fn on_getcfcheckpt(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    m: &bitcoin::p2p::message_filter::GetCFCheckpt,
) -> Result<(), NetError> {
    use bitcoin::hashes::Hash;
    let Some(stop) = compact_filter_stop(hub, m.filter_type, m.stop_hash.as_byte_array())? else {
        return Ok(());
    };
    if !within_filter_watermark(hub, stop)? {
        return Ok(());
    }
    let mut filter_headers = Vec::new();
    let mut h = 1000u32;
    while h <= stop {
        let Some(row) = filter_q(hub.query.basic_filter_hashes_and_headers(h, h))? else {
            return Ok(());
        };
        filter_headers.push(row[0].1);
        h = h.saturating_add(1000);
    }
    queue_accounted(
        session,
        out_tx,
        NetworkMessage::CFCheckpt(bitcoin::p2p::message_filter::CFCheckpt {
            filter_type: 0,
            stop_hash: m.stop_hash,
            filter_headers,
        }),
    )?;
    Ok(())
}

#[doc(hidden)]
pub fn handle_peer_inventory_msg(
    payload: &NetworkMessage,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    // The reply that crossed the budget is already queued. Do not serve
    // another request until the writer drains.
    if session.is_some_and(|s| s.send_over_budget()) {
        return Ok(());
    }
    match payload {
        NetworkMessage::Addr(list) => on_addr_list(follow, session, list)?,
        NetworkMessage::AddrV2(list) => on_addrv2(follow, session, list)?,
        NetworkMessage::Inv(items) => on_inv(hub, out_tx, follow, session, items)?,
        NetworkMessage::NotFound(items) => on_notfound(hub, session, items),
        NetworkMessage::MemPool
        | NetworkMessage::FilterLoad(_)
        | NetworkMessage::FilterAdd(_)
        | NetworkMessage::FilterClear => on_bloom_forbidden(follow, session)?,
        NetworkMessage::GetAddr => on_getaddr(hub, out_tx, session)?,
        NetworkMessage::GetCFilters(_)
        | NetworkMessage::GetCFHeaders(_)
        | NetworkMessage::GetCFCheckpt(_) => on_compact_filters(payload, hub, out_tx, session)?,
        NetworkMessage::Unknown { .. }
        | NetworkMessage::GetData(_)
        | NetworkMessage::GetBlockTxn(_)
        | NetworkMessage::Block(_)
        | NetworkMessage::CmpctBlock(_)
        | NetworkMessage::BlockTxn(_)
        | NetworkMessage::Tx(_) => {}
        NetworkMessage::Headers(_)
        | NetworkMessage::GetHeaders(_)
        | NetworkMessage::GetBlocks(_) => {
            return Err(NetError::Protocol(
                "header work is not on the sync inventory path",
            ));
        }
        _ => {}
    }
    Ok(())
}

#[doc(hidden)]
pub fn on_redundant_version(session: Option<&crate::peers::LivePeer>) {
    if let Some(s) = session {
        rbitcoin_log::info!("p2p: redundant version message from peer={}", s.id);
    } else {
        rbitcoin_log::info!("p2p: redundant version message from peer");
    }
}

#[doc(hidden)]
pub fn on_redundant_verack(session: Option<&crate::peers::LivePeer>) {
    if let Some(s) = session {
        rbitcoin_log::info!("p2p: ignoring redundant verack message from peer={}", s.id);
    } else {
        rbitcoin_log::info!("p2p: ignoring redundant verack message");
    }
}

#[doc(hidden)]
pub fn on_ping(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    n: u64,
) -> Result<(), NetError> {
    if let Some(s) = session {
        queue_due_tx_invs(hub, s, &follow.from_this_peer, out_tx);
        queue_due_parent_getdata(hub, s, out_tx);
        let _ = maybe_queue_local_addr(hub, s, out_tx);
        // Noban headers-timeout reset: Core re-issues getheaders in the
        // same SendMessages turn; hook the ping so the official test
        // sees it before sync_with_ping returns.
        let _ = maybe_queue_initial_getheaders(out_tx, hub, s);
    }
    queue_out(out_tx, NetworkMessage::Pong(n))?;
    Ok(())
}

#[doc(hidden)]
pub fn on_feefilter(session: Option<&crate::peers::LivePeer>, amt: i64) {
    if let Some(s) = session {
        s.note_minfeefilter_sat_kvb(amt.max(0) as u64);
    }
}

#[doc(hidden)]
pub fn on_sendheaders(follow: &mut PeerFollowState) {
    follow.wants_headers = true;
}

#[doc(hidden)]
pub fn on_sendcmpct(
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    sc: &SendCmpct,
) {
    // Segwit networks: only version 2 (wtxid short-ids) enables HB.
    // Version 1 and version > 2 are ignored.
    if sc.version == 2 {
        follow.send_cmpct = sc.send_compact;
        follow.cmpct_version = 2;
        if let Some(sess) = session {
            sess.set_hb_from(sc.send_compact);
        }
    }
}

#[doc(hidden)]
pub fn on_wtxid_relay(follow: &mut PeerFollowState, session: Option<&crate::peers::LivePeer>) {
    // BIP339 mutual: we already sent wtxidrelay pre-verack; remember theirs.
    follow.wtxid_relay = true;
    if let Some(s) = session {
        s.set_wtxid_relay();
    }
}

#[doc(hidden)]
pub fn on_sendaddrv2(follow: &mut PeerFollowState, session: Option<&crate::peers::LivePeer>) {
    let id = session.map(|s| s.id).unwrap_or(0);
    rbitcoin_log::info!("{}", sendaddrv2_after_verack_log(id));
    punish_disconnect(&mut follow.ban_score, session);
}

/// v1 `addr` is learned only as an addr-fetch session's `getaddr` reply.
#[doc(hidden)]
pub fn on_addr_list(
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    list: &[(u32, bitcoin::p2p::address::Address)],
) -> Result<(), NetError> {
    let Some(s) = session.filter(|s| s.conn_type == crate::peers::PeerConnType::AddrFetch) else {
        return Ok(());
    };
    if list.len() > MAX_ADDR_TO_SEND {
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    let v2: Vec<_> = list
        .iter()
        .filter_map(|(time, a)| {
            let sock = a.socket_addr().ok()?;
            Some(bitcoin::p2p::address::AddrV2Message {
                time: *time,
                services: a.services,
                addr: crate::NetAddr::from_socket(sock).to_addrv2(),
                port: sock.port(),
            })
        })
        .collect();
    learn_addrfetch_reply(s, &v2, list.len());
    Ok(())
}

/// Core `ProcessMessage` ADDR/ADDRV2 on an addr-fetch session: the reply to
/// the `getaddr` it sent is learned and not relayed (`m_getaddr_sent`).
/// More than one address ends the session, without misbehavior.
fn learn_addrfetch_reply(
    s: &crate::peers::LivePeer,
    list: &[bitcoin::p2p::address::AddrV2Message],
    n: usize,
) {
    if let Some(ph) = s.peer_hub() {
        // Node time, as the bucket's start (`connected_at`) is.
        let now_ms = s.clock_now().saturating_mul(1000);
        let allow = s.take_addr_tokens(list.len(), now_ms);
        ph.learn_addrv2(&list[..allow]);
        if n > 1 {
            ph.note_addrfetch_reply();
        }
    }
    if n > 1 {
        s.request_disconnect();
    }
}

#[doc(hidden)]
pub fn on_addrv2(
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    list: &[bitcoin::p2p::address::AddrV2Message],
) -> Result<(), NetError> {
    let n = list.len();
    let nbytes =
        bitcoin::consensus::encode::serialize(&NetworkMessage::AddrV2(list.to_vec())).len();
    let id = session.map(|s| s.id).unwrap_or(0);
    rbitcoin_log::info!("{}", received_addrv2_log(nbytes, id));
    if n > MAX_ADDR_TO_SEND {
        rbitcoin_log::info!("{}", addrv2_message_size_log(n));
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    if let Some(s) = session.filter(|s| s.conn_type == crate::peers::PeerConnType::AddrFetch) {
        learn_addrfetch_reply(s, list, n);
        return Ok(());
    }
    if let Some(s) = session {
        if let Some(ph) = s.peer_hub() {
            // Node time, as the bucket's start (`connected_at`) is.
            let now_ms = s.clock_now().saturating_mul(1000);
            let allow = s.take_addr_tokens(list.len(), now_ms);
            ph.learn_addrv2(&list[..allow]);
            let mut neighbors: Vec<_> = ph
                .live_peers()
                .into_iter()
                .filter(|other| {
                    other.id != s.id && other.wants_addrv2() && other.writer().is_some()
                })
                .collect();
            neighbors.sort_by_key(|other| other.id);
            let mut batches: Vec<Vec<bitcoin::p2p::address::AddrV2Message>> =
                vec![Vec::new(); neighbors.len()];
            for addr in list.iter().take(allow) {
                if crate::netaddr::addrv2_skip_relay(addr) {
                    continue;
                }
                let key = addr_relay_key(addr);
                let n_dest = if neighbors.len() <= 1 {
                    neighbors.len()
                } else if key & 1 == 0 {
                    1
                } else {
                    2
                };
                if n_dest == 0 {
                    continue;
                }
                let start = (key as usize) % neighbors.len();
                for step in 0..n_dest {
                    let idx = match step {
                        0 => start,
                        _ => {
                            if start + 1 == neighbors.len() {
                                0
                            } else {
                                start + 1
                            }
                        }
                    };
                    batches[idx].push(addr.clone());
                }
            }
            for (other, batch) in neighbors.iter().zip(batches) {
                if batch.is_empty() {
                    continue;
                }
                if let Some(tx) = other.writer() {
                    let msg = NetworkMessage::AddrV2(batch);
                    let sent = bitcoin::consensus::encode::serialize(&msg).len();
                    rbitcoin_log::info!("{}", sending_addrv2_log(sent, other.id));
                    queue_out(&tx, msg)?;
                }
            }
        }
    }
    Ok(())
}

#[doc(hidden)]
async fn header_pool_permit() -> Result<tokio::sync::OwnedSemaphorePermit, NetError> {
    crate::msg_decode::ctrl_decode_semaphore()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| NetError::Protocol("decode semaphore closed"))
}

/// Store work for headers. A live node holds `hub` in an `Arc` and runs `job`
/// on the blocking pool. A stack hub (unit tests) runs `job` on the caller.
async fn run_header_job<T, F>(hub: &ChainHub, job: F) -> Result<T, NetError>
where
    T: Send + 'static,
    F: FnOnce(&ChainHub) -> T + Send + 'static,
{
    let Some(owned) = hub.shared_arc() else {
        return Ok(job(hub));
    };
    let permit = header_pool_permit().await?;
    tokio::task::spawn_blocking(move || {
        let _region = crate::reactor::BlockingRegion::enter();
        let _permit = permit;
        job(owned.as_ref())
    })
    .await
    .map_err(|_| NetError::Protocol("header job join failed"))
}

pub async fn on_getheaders(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    gh: &GetHeadersMessage,
) -> Result<(), NetError> {
    if gh.locator_hashes.len() > MAX_LOCATOR_SZ {
        punish_disconnect(&mut follow.ban_score, session);
        return Ok(());
    }
    let gh = gh.clone();
    let (headers, withhold_stale, empty_tip) =
        run_header_job(hub, move |hub| getheaders_apply(hub, &gh)).await??;
    if !withhold_stale {
        if let Some(s) = session {
            if let Some(last) = headers.last() {
                s.note_best_header_sent(last.block_hash());
            } else if let Some(tip) = empty_tip {
                s.note_best_header_sent(tip);
            }
        }
        queue_accounted(session, out_tx, NetworkMessage::Headers(headers))?;
    }
    Ok(())
}

fn getheaders_apply(
    hub: &ChainHub,
    gh: &GetHeadersMessage,
) -> Result<(Vec<bitcoin::block::Header>, bool, Option<BlockHash>), NetError> {
    let headers = headers_reply_for_getheaders(hub, gh)?;
    let withhold_stale = headers.is_empty()
        && gh.locator_hashes.is_empty()
        && gh.stop_hash.to_byte_array() != [0u8; 32]
        && hub.header_of(&gh.stop_hash).is_some()
        && !hub.stale_relay_allowed(&gh.stop_hash);
    let empty_tip = if headers.is_empty() {
        hub.tip_hash()
    } else {
        None
    };
    Ok((headers, withhold_stale, empty_tip))
}

#[doc(hidden)]
pub async fn on_getblocks(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    gb: &GetBlocksMessage,
) -> Result<(), NetError> {
    if gb.locator_hashes.len() > MAX_LOCATOR_SZ {
        punish_disconnect(&mut follow.ban_score, session);
        return Ok(());
    }
    let gh = GetHeadersMessage {
        version: gb.version,
        locator_hashes: gb.locator_hashes.clone(),
        stop_hash: gb.stop_hash,
    };
    let headers = run_header_job(hub, move |hub| {
        headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &gh)
    })
    .await??;
    let inv: Vec<Inventory> = headers
        .into_iter()
        .take(500)
        .map(|h| Inventory::WitnessBlock(h.block_hash()))
        .collect();
    if !inv.is_empty() {
        queue_accounted(session, out_tx, NetworkMessage::Inv(inv))?;
    }
    Ok(())
}

pub async fn serve_getdata(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    inv: Vec<Inventory>,
) -> Result<(), NetError> {
    if inv.len() > MAX_INV_SIZE {
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    follow.getdata_tail.extend(inv);
    serve_getdata_tail(hub, out_tx, follow, session).await
}

/// Core `ProcessGetData`: serve queued getdata items in order until the
/// writer has no serve room (`fPauseSend`). The rest stays in
/// `follow.getdata_tail` for the session loop to resume. The `notfound`
/// collected so far is sent either way.
pub async fn serve_getdata_tail(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let mut notfound: Vec<Inventory> = Vec::new();
    while session.is_none_or(|s| s.has_serve_room()) {
        let Some(item) = follow.getdata_tail.pop_front() else {
            break;
        };
        match &item {
            // A block-relay-only session does not serve transactions and
            // does not answer notfound for them (`p2p_blocksonly`).
            Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
                if session
                    .is_some_and(|s| s.conn_type == crate::peers::PeerConnType::BlockRelay) => {}
            // MSG_FILTERED_BLOCK. NODE_BLOOM is off, so this is a disconnect.
            Inventory::Unknown { inv_type, .. } if *inv_type & 0x3fff_ffff == 3 => {
                rbitcoin_log::info!(
                    "filtered block request received when NODE_BLOOM service disabled"
                );
                punish_disconnect(&mut follow.ban_score, session);
                return Ok(());
            }
            // Unknown hash: Core ProcessGetData answers notfound. Silence
            // holds the requester's getdata until the stall floor.
            // The header check and the body reconstruct both run on the
            // blocking pool. A missing header or body is `false`.
            Inventory::Block(h) | Inventory::WitnessBlock(h)
                if !serve_getdata_full_block(hub, out_tx, session, h).await? =>
            {
                notfound.push(item);
            }
            Inventory::CompactBlock(h) => {
                serve_getdata_compact(hub, out_tx, follow, session, h).await?;
            }
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                let tx = hub.mempool().and_then(|mp| mp.try_get_tx(txid));
                if !serve_mempool_getdata(hub, out_tx, session, tx)? && hub.mempool().is_some() {
                    notfound.push(item);
                }
            }
            Inventory::WTx(wtxid) => {
                serve_getdata_wtx(hub, out_tx, session, item, wtxid, &mut notfound).await?;
            }
            _ => {}
        }
    }
    if !notfound.is_empty() {
        queue_accounted(session, out_tx, NetworkMessage::NotFound(notfound))?;
    }
    Ok(())
}

pub async fn serve_getdata_full_block(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    h: &bitcoin::BlockHash,
) -> Result<bool, NetError> {
    let query = Arc::clone(&hub.query);
    let cache = Arc::clone(&hub.cache);
    let hash = *h;
    let encoded = tokio::task::spawn_blocking(move || {
        let _g = crate::reactor::BlockingRegion::enter();
        encode_served_witness_block(cache.as_ref(), query.as_ref(), &hash)
    })
    .await
    .map_err(|_| NetError::Protocol("serve reconstruct join failed"))??;
    let Some(bytes) = encoded else {
        // Header-only or pruned. Notfound comes from this blocking encode,
        // not from reconstructing the block on the async task.
        return Ok(false);
    };
    // A body we have but will not relay (month-old side block) stays silent.
    if !hub.stale_relay_allowed(h) {
        return Ok(true);
    }
    queue_served(session, out_tx, PeerOut::Encoded(bytes))?;
    Ok(true)
}

#[doc(hidden)]
pub enum CompactServe {
    Missing,
    Full(Block),
    Cmpct(HeaderAndShortIds),
}

/// Reconstruct and, when the block is near the tip, build the compact
/// announcement. Store reads and `from_block` stay off the session task.
#[doc(hidden)]
pub fn compact_serve_outcome(
    cache: &BlockCache,
    query: &Query,
    hash: &BlockHash,
    tip_h: u32,
    ver: u32,
    pref: Vec<usize>,
) -> Result<CompactServe, NetError> {
    let Some(block) = block_for_peer(cache, query, hash)? else {
        return Ok(CompactServe::Missing);
    };
    let block_h = query
        .height_of_hash(&hash.to_byte_array())
        .ok()
        .flatten()
        .map(|ht| ht.0)
        .unwrap_or(0);
    if tip_h.saturating_sub(block_h) > MAX_CMPCTBLOCK_DEPTH {
        return Ok(CompactServe::Full(block));
    }
    match HeaderAndShortIds::from_block(&block, rand_nonce(), ver, &pref) {
        Ok(hsi) => {
            rbitcoin_log::info!(
                "{}",
                crate::compact::cmpct_send_line(block.block_hash(), block.txdata.len(), &hsi)
            );
            Ok(CompactServe::Cmpct(hsi))
        }
        Err(_) => Ok(CompactServe::Full(block)),
    }
}

async fn block_reconstruct_permit() -> Result<tokio::sync::OwnedSemaphorePermit, NetError> {
    crate::msg_decode::block_decode_semaphore()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| NetError::Protocol("decode semaphore closed"))
}

#[doc(hidden)]
pub async fn serve_getdata_compact(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    h: &bitcoin::BlockHash,
) -> Result<(), NetError> {
    let permit = block_reconstruct_permit().await?;
    let cache = Arc::clone(&hub.cache);
    let query = Arc::clone(&hub.query);
    let hash = *h;
    let tip_h = hub.tip_height().unwrap_or(0);
    let ver = follow.cmpct_version.clamp(1, 2);
    let pref = hub.cmpct_prefill_indexes(h).unwrap_or_else(|| vec![0]);
    let outcome = tokio::task::spawn_blocking(move || {
        let _region = crate::reactor::BlockingRegion::enter();
        let _permit = permit;
        compact_serve_outcome(cache.as_ref(), query.as_ref(), &hash, tip_h, ver, pref)
    })
    .await
    .map_err(|_| NetError::Protocol("compact serve join failed"))??;
    match outcome {
        CompactServe::Missing => Ok(()),
        CompactServe::Full(block) => queue_served(
            session,
            out_tx,
            PeerOut::Served(NetworkMessage::Block(block)),
        ),
        CompactServe::Cmpct(hsi) => queue_served(
            session,
            out_tx,
            PeerOut::Served(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
        ),
    }
}

#[doc(hidden)]
pub async fn serve_getdata_wtx(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    item: Inventory,
    wtxid: &bitcoin::Wtxid,
    notfound: &mut Vec<Inventory>,
) -> Result<(), NetError> {
    if let Some(s) = session {
        rbitcoin_log::trace!("{}", received_getdata_wtx_log(wtxid, s.id));
    }
    let tx = hub.mempool().and_then(|mp| mp.try_get_tx_by_wtxid(wtxid));
    if serve_mempool_getdata(hub, out_tx, session, tx)? {
        return Ok(());
    }
    let announced = session.is_some_and(|s| s.has_announced_wtx(wtxid));
    if announced {
        if let Some(hash) = hub.tip_hash() {
            let permit = block_reconstruct_permit().await?;
            let cache = Arc::clone(&hub.cache);
            let query = Arc::clone(&hub.query);
            let wtxid = *wtxid;
            let found = tokio::task::spawn_blocking(move || {
                let _region = crate::reactor::BlockingRegion::enter();
                let _permit = permit;
                tx_from_stored_block(cache.as_ref(), query.as_ref(), &hash, &wtxid)
            })
            .await
            .map_err(|_| NetError::Protocol("tip wtxid serve join failed"))?;
            if let Some(tx) = announced_wtx_from_reconstruct(found) {
                queue_accounted(session, out_tx, NetworkMessage::Tx(tx))?;
                return Ok(());
            }
        }
    }
    notfound.push(item);
    Ok(())
}

/// Core: past this depth a `getblocktxn` is answered with the full block.
#[doc(hidden)]
pub const MAX_GETBLOCKTXN_DEPTH: u32 = 10;

#[doc(hidden)]
pub enum GetBlockTxnServe {
    BadIndex,
    Block(Block),
    Txns(BlockTransactions),
}

/// Park one `getblocktxn` and serve it while the writer has room. A full
/// queue keeps the request on [`PeerFollowState::getblocktxn_tail`]. An
/// empty request disconnects before the block is read, as in Core.
pub async fn serve_getblocktxn(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    txs_request: BlockTransactionsRequest,
) -> Result<(), NetError> {
    if txs_request.indexes.is_empty() {
        let id = session.map(|s| s.id).unwrap_or(0);
        rbitcoin_log::info!(
            "p2p: getblocktxn received with no transaction indexes, disconnecting peer={id}"
        );
        punish_disconnect(&mut follow.ban_score, session);
        return Ok(());
    }
    follow.getblocktxn_tail.push_back(txs_request);
    serve_getblocktxn_tail(hub, out_tx, follow, session).await
}

pub async fn serve_getblocktxn_tail(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    while session.is_none_or(|s| s.has_serve_room()) {
        let Some(req) = follow.getblocktxn_tail.pop_front() else {
            break;
        };
        serve_one_getblocktxn(hub, out_tx, follow, session, req).await?;
    }
    Ok(())
}

pub async fn serve_one_getblocktxn(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    txs_request: BlockTransactionsRequest,
) -> Result<(), NetError> {
    let query = Arc::clone(&hub.query);
    let cache = Arc::clone(&hub.cache);
    let reply = tokio::task::spawn_blocking(move || {
        let _g = crate::reactor::BlockingRegion::enter();
        let tip_h = query
            .tip_height()
            .map(|h| h.0)
            .or_else(|| cache.tip_height())
            .unwrap_or(0);
        getblocktxn_reply(cache.as_ref(), query.as_ref(), txs_request, tip_h)
    })
    .await
    .map_err(|_| NetError::Protocol("getblocktxn reconstruct join failed"))??;
    match reply {
        None => Ok(()),
        Some(GetBlockTxnServe::BadIndex) => {
            rbitcoin_log::info!("p2p: getblocktxn with out-of-bounds tx indices");
            // Core `Misbehaving`: noban and manual peers stay connected.
            misbehaving(&mut follow.ban_score, session);
            Ok(())
        }
        Some(GetBlockTxnServe::Block(block)) => queue_served(
            session,
            out_tx,
            PeerOut::Served(NetworkMessage::Block(block)),
        ),
        Some(GetBlockTxnServe::Txns(transactions)) => queue_served(
            session,
            out_tx,
            PeerOut::Served(NetworkMessage::BlockTxn(BlockTxn { transactions })),
        ),
    }
}

/// Serve missing txs for a compact block we hold (BIP152). Archive
/// reconstruct stays off the connection task.
#[doc(hidden)]
pub fn getblocktxn_reply(
    cache: &BlockCache,
    query: &Query,
    txs_request: BlockTransactionsRequest,
    tip_h: u32,
) -> Result<Option<GetBlockTxnServe>, NetError> {
    let hash = txs_request.block_hash;
    let block = match block_for_peer(cache, query, &hash) {
        Ok(b) => b,
        Err(e) => {
            rbitcoin_log::warn!("p2p: getblocktxn reconstruct {hash}: {e}");
            return Ok(None);
        }
    };
    let Some(block) = block else {
        return Ok(None);
    };
    let mut transactions = Vec::with_capacity(txs_request.indexes.len());
    for idx in &txs_request.indexes {
        match block.txdata.get(*idx as usize) {
            Some(tx) => transactions.push(tx.clone()),
            None => return Ok(Some(GetBlockTxnServe::BadIndex)),
        }
    }
    let block_h = query
        .height_of_hash(&hash.to_byte_array())
        .ok()
        .flatten()
        .map(|h| h.0)
        .unwrap_or(0);
    if tip_h.saturating_sub(block_h) > MAX_GETBLOCKTXN_DEPTH {
        return Ok(Some(GetBlockTxnServe::Block(block)));
    }
    Ok(Some(GetBlockTxnServe::Txns(BlockTransactions {
        block_hash: hash,
        transactions,
    })))
}

#[doc(hidden)]
pub fn on_inv(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    items: &[Inventory],
) -> Result<(), NetError> {
    if items.len() > MAX_INV_SIZE {
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    let mut want = Vec::new();
    let mut inv_tx_n = 0u64;
    let mut parent_capped = false;
    let mut need_headers = false;
    let mut tx_inv_hex: Option<String> = None;
    let mut seen_txids: HashSet<bitcoin::Txid> = HashSet::new();
    let mut seen_wtxids: HashSet<bitcoin::Wtxid> = HashSet::new();
    let relay = !hub.in_ibd()
        && (hub.mempool().map(|m| m.relay_enabled()).unwrap_or(false)
            || session.is_some_and(|s| s.session_relay_perm()));
    for item in items {
        match item {
            Inventory::Block(h) | Inventory::WitnessBlock(h) => {
                if let Some(s) = session {
                    s.note_block_from_peer(*h);
                    s.note_best_known(*h);
                }
                if on_inv_block_needs_headers(hub, follow, session, h) {
                    need_headers = true;
                }
            }
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                if tx_inv_hex.is_none() {
                    tx_inv_hex = Some(txid.to_string());
                }
                if !seen_txids.insert(*txid) {
                    continue;
                }
                if let Some(inv) = on_inv_txid(hub, session, relay, txid, &mut parent_capped) {
                    want.push(inv);
                    inv_tx_n = inv_tx_n.saturating_add(1);
                }
            }
            Inventory::WTx(wtxid) => {
                if tx_inv_hex.is_none() {
                    tx_inv_hex = Some(wtxid.to_string());
                }
                if !seen_wtxids.insert(*wtxid) {
                    continue;
                }
                if let Some(inv) = on_inv_wtxid(hub, session, relay, wtxid, &mut parent_capped) {
                    want.push(inv);
                    inv_tx_n = inv_tx_n.saturating_add(1);
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
    if parent_capped {
        punish_disconnect(&mut follow.ban_score, session);
        return Ok(());
    }
    if let Some(hx) = tx_inv_hex {
        if reject_unsolicited_tx(hub, session) {
            rbitcoin_log::info!(
                "p2p: transaction ({hx}) inv sent in violation of protocol, disconnecting peer"
            );
            punish_disconnect(&mut follow.ban_score, session);
            return Ok(());
        }
    }
    if need_headers {
        let _ = queue_getheaders(out_tx, hub, session, true, None);
    }
    if !want.is_empty() {
        queue_accounted(session, out_tx, NetworkMessage::GetData(want))?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn on_inv_block_needs_headers(
    hub: &ChainHub,
    follow: &PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    h: &bitcoin::BlockHash,
) -> bool {
    if hub.is_connected(h) {
        return false;
    }
    if hub.knows_header(h) || follow.pending_headers.contains_key(h) {
        return false;
    }
    if hub.in_ibd() {
        hub.note_header_inv_challenge();
    }
    session.is_none_or(|s| {
        s.peer_hub()
            .is_some_and(|ph| ph.should_getheaders_for_inv(s, *h))
    })
}

#[doc(hidden)]
pub fn on_notfound(hub: &ChainHub, session: Option<&crate::peers::LivePeer>, items: &[Inventory]) {
    let Some(s) = session else {
        return;
    };
    let Some(mp) = hub.mempool() else {
        return;
    };
    for item in items {
        let hash = match item {
            Inventory::WTx(w) => w.to_byte_array(),
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                txid.to_byte_array()
            }
            _ => continue,
        };
        mp.note_tx_not_found(s.id, hash);
    }
}

#[doc(hidden)]
pub fn on_inv_txid(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    relay: bool,
    txid: &bitcoin::Txid,
    parent_capped: &mut bool,
) -> Option<Inventory> {
    if !relay {
        return None;
    }
    let mp = hub.mempool()?;
    let in_orphan = mp.try_orphan_missing(txid).is_some();
    if mp.try_contains(txid) && !in_orphan {
        if let Some(s) = session {
            let _ = mp.add_orphan_announcer(txid, s.id);
        }
        return None;
    }
    if let Some(s) = session {
        match mp.note_inv_tx_requested(s.id, txid.to_byte_array(), s.inbound, s.clock_now(), false)
        {
            crate::tx_relay::ParentNote::RequestNow => {}
            crate::tx_relay::ParentNote::Deferred | crate::tx_relay::ParentNote::GlobalFull => {
                return None;
            }
            crate::tx_relay::ParentNote::PeerCapped => {
                *parent_capped = true;
                return None;
            }
        }
    }
    Some(Inventory::WitnessTransaction(*txid))
}

#[doc(hidden)]
pub fn on_inv_wtxid(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    relay: bool,
    wtxid: &bitcoin::Wtxid,
    parent_capped: &mut bool,
) -> Option<Inventory> {
    if !relay {
        return None;
    }
    let mp = hub.mempool()?;
    if !mp.try_contains_wtxid(wtxid) {
        if let Some(s) = session {
            match mp.note_inv_tx_requested(
                s.id,
                wtxid.to_byte_array(),
                s.inbound,
                s.clock_now(),
                true,
            ) {
                crate::tx_relay::ParentNote::RequestNow => {}
                crate::tx_relay::ParentNote::Deferred | crate::tx_relay::ParentNote::GlobalFull => {
                    return None;
                }
                crate::tx_relay::ParentNote::PeerCapped => {
                    *parent_capped = true;
                    return None;
                }
            }
        }
        return Some(Inventory::WTx(*wtxid));
    }
    let s = session?;
    let _ = mp.add_orphan_announcer_wtxid(wtxid, s.id);
    if let Some(tx) = mp.try_orphan_tx_wtxid(wtxid) {
        let missing = mp.orphan_getdata_parents(&tx);
        mp.schedule_orphan_parents(&missing, s.id, s.inbound, s.clock_now());
    }
    None
}

struct HeadersApply {
    from_peer: Vec<BlockHash>,
    best_known: Vec<BlockHash>,
    admits: Vec<(BlockHash, bitcoin::block::Header)>,
    misbehave: bool,
    /// `(announced height, our tip)` when the peer is a stale fork.
    disconnect: Option<(u32, u32)>,
    sync_height: Option<u32>,
    ignore_height: Option<u32>,
    /// Asks `release_asks_off_path` already forgot on the hub.
    drop_asks: Vec<BlockHash>,
    want_bodies: Vec<BlockHash>,
    /// Locator for one follow-up `getheaders`, if the batch still wants a page.
    getheaders: Option<Vec<BlockHash>>,
}

fn classify_headers(
    hub: &ChainHub,
    headers: &[bitcoin::block::Header],
    pending_before: &HashMap<BlockHash, bitcoin::block::Header>,
    requested_before: &HashSet<BlockHash>,
    have_bodies: &HashSet<BlockHash>,
    noban: bool,
) -> HeadersApply {
    let n = headers.len();
    let mut pending = pending_before.clone();
    let mut apply = HeadersApply {
        from_peer: Vec::new(),
        best_known: Vec::new(),
        admits: Vec::new(),
        misbehave: false,
        disconnect: None,
        sync_height: None,
        ignore_height: None,
        drop_asks: Vec::new(),
        want_bodies: Vec::new(),
        getheaders: None,
    };
    let mut ignored_below_floor = false;
    if n == 0 {
        // Empty headers is a failed getheaders response, not an announcement.
    } else if n > 0 && !noban && headers_are_below_floor(hub, pending_before, headers) {
        // Work stays under the floor from the pending headers alone. Do not
        // read parent headers, do not move this peer's best-known tip, and
        // do not ask for the next page of a batch we refused.
        for hdr in headers.iter().take(n) {
            let hash = hdr.block_hash();
            apply.from_peer.push(hash);
            admit_pending_header(&mut pending, hash, *hdr);
            apply.admits.push((hash, *hdr));
        }
        let last = headers[n - 1].block_hash();
        apply.ignore_height = Some(pending_announced_height(&pending, last));
        ignored_below_floor = true;
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
            apply.misbehave = true;
            return apply;
        }
        let connecting = header_announcement_connects(hub, pending_before, prev);
        for hdr in headers.iter().take(n) {
            let hash = hdr.block_hash();
            apply.from_peer.push(hash);
            apply.best_known.push(hash);
            admit_pending_header(&mut pending, hash, *hdr);
            apply.admits.push((hash, *hdr));
        }
        if !connecting {
            if n < MAX_HEADERS_RESULTS {
                apply.getheaders = Some(headers_sync_locator(hub, None));
            }
        } else {
            let last = headers[n - 1].block_hash();
            // Core `chain_start.nHeight + headers.size()`. One-header
            // tip announces still accumulate via `follow.pending_headers`
            // (`p2p_headers_sync_with_minchainwork` height=14).
            let announced_h = announced_headers_height(hub, &pending, last);
            let work_cmp = announced_work_cmp(hub, &pending, last);
            let our_tip = hub.tip_height().unwrap_or(0);
            if announced_tip_is_hopeless(our_tip, announced_h, work_cmp) && !noban {
                apply.disconnect = Some((announced_h, our_tip));
                return apply;
            }
            if !header_path_meets_minwork(hub, &pending, last) {
                if noban {
                    persist_pending_header_path(hub, &pending, last);
                    apply.sync_height = Some(announced_h);
                } else {
                    apply.ignore_height = Some(announced_h);
                    ignored_below_floor = true;
                }
                // Core: do not download bodies until the chain meets
                // `-minimumchainwork` (`p2p_headers_sync_with_minchainwork`).
            } else {
                persist_pending_header_path(hub, &pending, last);
                apply.sync_height = Some(announced_h);
                let keep = connecting_header_path(hub, &pending, last);
                let mut requested = requested_before.clone();
                release_asks_off_path(hub, &mut requested, &keep);
                apply.drop_asks = requested_before
                    .iter()
                    .copied()
                    .filter(|h| !requested.contains(h))
                    .collect();
                let mut want = fetchable_header_path_bodies(
                    hub,
                    &pending,
                    last,
                    &PendingBlocks::new(),
                    &requested,
                );
                want.retain(|h| !have_bodies.contains(h) && !requested.contains(h));
                want.truncate(MAX_SERVE_BLOCKS.saturating_sub(requested.len()));
                apply.want_bodies = want;
            }
        }
    }
    if n >= MAX_HEADERS_RESULTS && !ignored_below_floor {
        let from = headers.get(n - 1).map(|h| h.block_hash());
        apply.getheaders = Some(headers_sync_locator(hub, from));
    }
    apply
}

fn apply_headers(
    apply: HeadersApply,
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    if apply.misbehave {
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    for hash in apply.from_peer {
        if let Some(s) = session {
            s.note_block_from_peer(hash);
        }
    }
    for hash in apply.best_known {
        if let Some(s) = session {
            s.note_best_known(hash);
        }
    }
    for (hash, hdr) in apply.admits {
        admit_pending_header(&mut follow.pending_headers, hash, hdr);
    }
    if let Some((announced_h, our_tip)) = apply.disconnect {
        rbitcoin_log::info!("p2p: disconnect stale fork tip announced={announced_h} our={our_tip}");
        if let Some(s) = session {
            s.request_disconnect();
        }
        return Ok(());
    }
    if let Some(announced_h) = apply.sync_height {
        rbitcoin_log::info!("{}", synchronizing_blockheaders_log(announced_h));
    }
    if let Some(announced_h) = apply.ignore_height {
        rbitcoin_log::info!("{}", ignoring_low_work_chain_log(announced_h));
    }
    for hash in &apply.drop_asks {
        follow.requested_blocks.remove(hash);
    }
    // The batch is already persisted. A spent send budget does not claim
    // bodies or queue another locator. The 120s poll can ask again.
    if session.is_some_and(|s| s.send_over_budget()) {
        return Ok(());
    }
    // Claim on this session, next to the queue. The header job only
    // filters. An aborted join never publishes an ask that was not sent.
    queue_claimed_block_getdata(
        hub,
        out_tx,
        session,
        &mut follow.requested_blocks,
        &apply.want_bodies,
        getdata_use_compact(hub, follow.cmpct_version),
    )?;
    if let Some(locator) = apply.getheaders {
        queue_headers_locator(out_tx, session, locator)?;
    }
    Ok(())
}

/// Claim each body on the hub, then queue one `getdata` on this session.
/// A body another session already claimed is skipped. A failed send
/// releases every claim it took, so the next announcement can ask.
fn queue_claimed_block_getdata(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    requested_blocks: &mut HashSet<BlockHash>,
    want: &[BlockHash],
    compact: bool,
) -> Result<(), NetError> {
    let claimed: Vec<BlockHash> = want
        .iter()
        .copied()
        .filter(|hash| hub.claim_block_ask(hash))
        .collect();
    let sent = queue_block_getdata(hub, out_tx, session, requested_blocks, &claimed, compact);
    if sent.is_err() {
        for hash in &claimed {
            requested_blocks.remove(hash);
            hub.forget_asked_block(hash);
        }
    }
    sent
}

/// Send a locator the header job already built. Same in-flight gate as
/// [`queue_getheaders`].
fn queue_headers_locator(
    out: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    locator: Vec<BlockHash>,
) -> Result<(), NetError> {
    if let Some(s) = session {
        if s.is_awaiting_headers() {
            return Ok(());
        }
        s.note_awaiting_headers();
    }
    let gh = GetHeadersMessage::new(locator, BlockHash::from_byte_array([0u8; 32]));
    queue_out(out, NetworkMessage::GetHeaders(gh))
}

#[doc(hidden)]
pub async fn on_headers(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    headers: &[bitcoin::block::Header],
) -> Result<(), NetError> {
    let _ = session.is_some_and(|s| s.take_awaiting_headers());
    let noban = session.is_some_and(|s| s.session_noban());
    let pending = follow.pending_headers.clone();
    let requested = follow.requested_blocks.clone();
    let have_bodies: HashSet<BlockHash> = follow.pending_blocks.keys().copied().collect();
    let headers = headers.to_vec();
    let apply = run_header_job(hub, move |hub| {
        classify_headers(hub, &headers, &pending, &requested, &have_bodies, noban)
    })
    .await?;
    apply_headers(apply, hub, out_tx, follow, session)
}

pub async fn on_block(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    block: &Block,
) -> Result<(), NetError> {
    let hash = block.block_hash();
    let merkle = crate::compact::block_txid_merkle(&block.txdata);
    if merkle.is_none_or(|(root, _)| root != block.header.merkle_root.to_byte_array()) {
        rbitcoin_log::info!("Block mutated: bad-txnmrklroot, hashMerkleRoot mismatch");
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    if merkle.is_some_and(|(_, mutated)| mutated) {
        rbitcoin_log::info!("Block mutated: bad-txns-duplicate");
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    if rbitcoin_consensus::block_mutated_without_coinbase(block) {
        rbitcoin_log::info!("Block mutated: 64-byte transaction without a coinbase");
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    if let Some(s) = session {
        s.note_block_from_peer(hash);
        s.note_best_known(hash);
    }
    let prev = block.header.prev_blockhash;
    if prev.to_byte_array() != [0u8; 32]
        && !hub.knows_header(&prev)
        && !follow.pending_headers.contains_key(&prev)
        && follow.requested_blocks.contains(&hash)
    {
        rbitcoin_log::info!("{}", accept_prev_not_found_log(hash));
        if let Some(s) = session {
            let _ = s.take_awaiting_headers();
        }
        let _ = queue_getheaders(out_tx, hub, session, true, None);
        admit_pending_header(&mut follow.pending_headers, hash, block.header);
        follow.pending_blocks.insert(hash, block.clone());
        hub.forget_asked_block(&hash);
        return Ok(());
    }
    if on_block_unrequested_skip(hub, follow, session, block, hash)? {
        return Ok(());
    }
    if let Err(e) = ensure_peer_header(hub, &block.header) {
        if !crate::chain::accept_err_is_temporary_time(&e) {
            misbehaving(&mut follow.ban_score, session);
        }
        return Ok(());
    }
    drop_pending_cmpct(follow, session, hash);
    follow.requested_blocks.remove(&hash);
    admit_pending_header(&mut follow.pending_headers, hash, block.header);
    if !any_header_path_meets_minwork(hub, &follow.pending_headers, hash) {
        follow.pending_blocks.insert(hash, block.clone());
        return Ok(());
    }
    relay_new_pow_valid_block(hub, block, session).await;
    on_block_accept(hub, out_tx, follow, session, block, hash).await
}

#[doc(hidden)]
pub fn on_block_unrequested_skip(
    hub: &ChainHub,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    block: &Block,
    hash: BlockHash,
) -> Result<bool, NetError> {
    if follow.requested_blocks.contains(&hash) {
        return Ok(false);
    }
    let prev = block.header.prev_blockhash;
    if prev.to_byte_array() != [0u8; 32]
        && !hub.knows_header(&prev)
        && !follow.pending_headers.contains_key(&prev)
    {
        rbitcoin_log::info!("{}", accept_prev_not_found_log(hash));
        misbehaving(&mut follow.ban_score, session);
        return Ok(true);
    }
    if let Err(e) = ensure_peer_header(hub, &block.header) {
        if !crate::chain::accept_err_is_temporary_time(&e) {
            misbehaving(&mut follow.ban_score, session);
        }
        return Ok(true);
    }
    if hub.header_below_minwork(&block.header) {
        rbitcoin_log::info!("{}", accept_block_header_nodos_log(hash));
        return Ok(true);
    }
    if hub.header_below_anti_dos(&block.header) && !follow.pending_headers.contains_key(&hash) {
        return Ok(true);
    }
    if hub.unrequested_too_far_ahead(&block.header) {
        return Ok(true);
    }
    Ok(false)
}

/// Local IO fault: keep the session, and release the hub body ask so a later
/// getdata can claim the same hash. The block is not a verdict.
fn note_store_fault_keep_session(hub: &ChainHub, hash: BlockHash, e: &NetError) {
    rbitcoin_log::warn!("p2p: accept dropped {hash} (local fault — keep session): {e}");
    hub.forget_asked_block(&hash);
}

pub async fn on_block_accept(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    block: &Block,
    hash: BlockHash,
) -> Result<(), NetError> {
    match accept_received_from_peer(hub, block.clone(), session).await {
        Ok(AcceptOutcome::Accepted { .. }) => {
            drain_after_accept(hub, out_tx, follow, session, hash, false).await
        }
        Ok(AcceptOutcome::AlreadyHave) | Ok(AcceptOutcome::IgnoredWeaker) => {
            drain_after_accept(hub, out_tx, follow, session, hash, false).await
        }
        Err(e) if net_error_is_store_not_found(&e) => {
            rbitcoin_log::warn!("p2p: accept dropped {hash} (store not found — keep session): {e}");
            Ok(())
        }
        Err(e) if net_error_needs_parent(&e) => {
            hub.forget_asked_block(&hash);
            follow.pending_blocks.insert(hash, block.clone());
            drain_pending(
                hub,
                out_tx,
                &mut follow.pending_blocks,
                &mut follow.pending_headers,
                &mut follow.requested_blocks,
                getdata_use_compact(hub, follow.cmpct_version),
                session,
            )
            .await
        }
        Err(e @ NetError::Store(_)) => {
            note_store_fault_keep_session(hub, hash, &e);
            Ok(())
        }
        Err(e) => {
            rbitcoin_log::warn!("p2p: accept dropped {hash} (invalid — keep session): {e}");
            Ok(())
        }
    }
}

#[doc(hidden)]
pub fn drop_pending_cmpct(
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
) {
    follow.pending_cmpct.remove(&hash);
    if let Some(s) = session {
        s.release_cmpct_taken(hash);
    }
}

/// Core `MarkBlockAsReceived` clears every peer's in-flight entry for a
/// received block. Ours are per session, so a partial whose block connected
/// through another peer is dropped here before it counts against the cap.
#[doc(hidden)]
pub fn drop_connected_pending_cmpct(
    hub: &ChainHub,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) {
    let done: Vec<BlockHash> = follow
        .pending_cmpct
        .keys()
        .filter(|h| hub.is_connected(h))
        .copied()
        .collect();
    for hash in done {
        if let (Some(s), Some(h)) = (session, hub.header_height(&hash)) {
            s.clear_block_inflight(h);
        }
        drop_pending_cmpct(follow, session, hash);
    }
}

pub async fn on_cmpctblock(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    cb: &CmpctBlock,
) -> Result<(), NetError> {
    let hsi = cb.compact_block.clone();
    let hash = hsi.header.block_hash();
    if on_cmpctblock_reject_early(hub, follow, session, &hsi, hash)? {
        return Ok(());
    }
    if hsi.header.prev_blockhash.to_byte_array() != [0u8; 32]
        && !hub.knows_header(&hsi.header.prev_blockhash)
    {
        // Keep in-session; persist only once prev is stored.
        if let Some(s) = session {
            let _ = s.take_awaiting_headers();
        }
        let _ = queue_getheaders(out_tx, hub, session, true, None);
    }
    admit_pending_header(&mut follow.pending_headers, hash, hsi.header);
    if !any_header_path_meets_minwork(hub, &follow.pending_headers, hash) {
        return Ok(());
    }
    let keep = keep_pending_connecting_paths(hub, &follow.pending_headers);
    release_asks_off_path(hub, &mut follow.requested_blocks, &keep);
    on_cmpctblock_queue_ancestors(hub, out_tx, follow, session, hash)?;
    if hub.header_below_anti_dos(&hsi.header) && !follow.requested_blocks.contains(&hash) {
        let id = session.map(|s| s.id).unwrap_or(0);
        rbitcoin_log::info!("p2p: ignore low-work compact block from peer {id}");
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        return Ok(());
    }
    if hub.has_block(&hash) {
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        return Ok(());
    }
    if !follow.requested_blocks.contains(&hash)
        && !compact_unsolicited_reconstruct(hub, session, &hsi.header)
    {
        return on_cmpctblock_header_announce(hub, out_tx, follow, session, hash).await;
    }
    on_cmpctblock_reconstruct(hub, out_tx, follow, session, &hsi, hash).await
}

/// An unsolicited compact block we do not reconstruct is a header
/// announcement. The header path is stored and the bodies
/// [`fetchable_header_path_bodies`] returns are a full-block `getdata` to
/// this peer, as Core's block download asks once the announcement moved
/// the peer's best block. The ask follows the headers path: a spent send
/// budget asks nothing, and each body is one hub claim.
async fn on_cmpctblock_header_announce(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
) -> Result<(), NetError> {
    let pending = follow.pending_headers.clone();
    run_header_job(hub, move |hub| {
        persist_pending_header_path(hub, &pending, hash);
    })
    .await?;
    if session.is_some_and(|s| s.send_over_budget()) {
        return Ok(());
    }
    let mut want = fetchable_header_path_bodies(
        hub,
        &follow.pending_headers,
        hash,
        &follow.pending_blocks,
        &follow.requested_blocks,
    );
    want.truncate(MAX_SERVE_BLOCKS.saturating_sub(follow.requested_blocks.len()));
    queue_claimed_block_getdata(
        hub,
        out_tx,
        session,
        &mut follow.requested_blocks,
        &want,
        false,
    )
}

#[doc(hidden)]
pub fn on_cmpctblock_reject_early(
    hub: &ChainHub,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hsi: &HeaderAndShortIds,
    hash: BlockHash,
) -> Result<bool, NetError> {
    // `-blocksonly` does not reconstruct compact blocks, solicited or not.
    // The peer still gets a full-block getdata from the headers path.
    if hub.blocks_only.load(Ordering::Acquire) {
        return Ok(true);
    }
    if follow.cmpct_version != 2 {
        rbitcoin_log::debug!("p2p: cmpctblock from a peer that never sent sendcmpct version 2");
        return Ok(true);
    }
    if session.is_some_and(|s| s.has_failed_cmpct(&hash)) {
        rbitcoin_log::info!("p2p: previous compact block reconstruction attempt failed");
        misbehaving(&mut follow.ban_score, session);
        return Ok(true);
    }
    if !crate::compact::cmpct_init_data_ok(hsi) {
        rbitcoin_log::info!("p2p: invalid compact block");
        misbehaving(&mut follow.ban_score, session);
        return Ok(true);
    }
    // Child of a cached-invalid block: disconnect. Same-hash cached invalid
    // via compact stays connected.
    if hub.is_block_invalid(&hsi.header.prev_blockhash) {
        misbehaving(&mut follow.ban_score, session);
        return Ok(true);
    }
    if hub.is_block_invalid(&hash) {
        return Ok(true);
    }
    // Claimed proof of work before any peer or header-sync state. Once the
    // tip meets minimum chain work the work-path walk does not check this header.
    if !hub.header_claimed_pow_ok(&hsi.header) {
        rbitcoin_log::info!("{}", crate::chain::accept_block_header_nodos_log(hash));
        misbehaving(&mut follow.ban_score, session);
        take_requested_block(hub, &mut follow.requested_blocks, &hash);
        return Ok(true);
    }
    if let Some(s) = session {
        s.note_block_from_peer(hash);
        s.note_best_known(hash);
    }
    Ok(false)
}

#[doc(hidden)]
pub fn on_cmpctblock_queue_ancestors(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
) -> Result<(), NetError> {
    let mut ancestors: Vec<BlockHash> = fetchable_header_path_bodies(
        hub,
        &follow.pending_headers,
        hash,
        &follow.pending_blocks,
        &follow.requested_blocks,
    )
    .into_iter()
    .filter(|h| *h != hash)
    .collect();
    ancestors.truncate(MAX_SERVE_BLOCKS.saturating_sub(follow.requested_blocks.len()));
    queue_block_getdata(
        hub,
        out_tx,
        session,
        &mut follow.requested_blocks,
        &ancestors,
        getdata_use_compact(hub, follow.cmpct_version),
    )
}

pub async fn on_cmpctblock_reconstruct(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hsi: &HeaderAndShortIds,
    hash: BlockHash,
) -> Result<(), NetError> {
    // Reconstruct after the message is in hand. The permit is the same
    // budget as block decode and compact serve. Session state stays here.
    let permit = block_reconstruct_permit().await?;
    let mp = hub.mempool().cloned();
    let owned_hsi = hsi.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let _region = crate::reactor::BlockingRegion::enter();
        let _permit = permit;
        reconstruct_cmpct_from_mempool(mp.as_deref(), &owned_hsi, 2)
    })
    .await
    .map_err(|_| NetError::Protocol("compact reconstruct join failed"))?;
    match outcome {
        Some(CmpctReconstruct::Block(block, fill)) => {
            on_cmpct_got_block(hub, out_tx, follow, session, hsi, hash, block, fill).await
        }
        Some(CmpctReconstruct::GetData) => on_cmpct_need_getdata(out_tx, session, hash),
        Some(CmpctReconstruct::NeedTxn(partial, fill)) => {
            on_cmpct_need_txn(hub, out_tx, follow, session, hsi, hash, partial, fill)
        }
        None => {
            log_cmpct_getdata(hash, 0);
            queue_out(
                out_tx,
                NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)] // one compact-block fill; call site stays unbundled
pub async fn on_cmpct_got_block(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hsi: &HeaderAndShortIds,
    hash: BlockHash,
    block: Block,
    fill: Option<Box<crate::compact::CmpctFillSets>>,
) -> Result<(), NetError> {
    log_cmpct_filled(hub, hsi, &block, &[], fill.as_deref());
    follow.requested_blocks.remove(&hash);
    drop_pending_cmpct(follow, session, hash);
    relay_new_pow_valid_block(hub, &block, session).await;
    match accept_received_from_peer(hub, block.clone(), session).await {
        Ok(AcceptOutcome::Accepted { .. }) => {
            hub.forget_asked_block(&hash);
        }
        Err(e) if net_error_needs_parent(&e) => {
            hub.forget_asked_block(&hash);
            follow.pending_blocks.insert(hash, block);
            maybe_select_hb_if_relay(hub, session);
        }
        Ok(_) => {
            hub.forget_asked_block(&hash);
        }
        Err(e @ NetError::Store(_)) if !net_error_is_store_not_found(&e) => {
            note_store_fault_keep_session(hub, hash, &e);
        }
        _ => {
            if !hub.knows_header(&hsi.header.prev_blockhash) {
                let _ = queue_getheaders(out_tx, hub, session, true, None);
            }
        }
    }
    drain_pending(
        hub,
        out_tx,
        &mut follow.pending_blocks,
        &mut follow.pending_headers,
        &mut follow.requested_blocks,
        getdata_use_compact(hub, follow.cmpct_version),
        session,
    )
    .await
}

#[doc(hidden)]
pub fn on_cmpct_need_getdata(
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
) -> Result<(), NetError> {
    log_cmpct_getdata(hash, 0);
    if let Some(s) = session {
        s.note_failed_cmpct(hash);
    }
    queue_out(
        out_tx,
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
    )
}

#[allow(clippy::too_many_arguments)] // one getblocktxn ask; call site stays unbundled
#[doc(hidden)]
pub fn on_cmpct_need_txn(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hsi: &HeaderAndShortIds,
    hash: BlockHash,
    partial: crate::compact::CmpctPartial,
    fill: Option<Box<crate::compact::CmpctFillSets>>,
) -> Result<(), NetError> {
    if follow.pending_cmpct.contains_key(&hash) {
        return Ok(());
    }
    let missing_n = partial.missing().len();
    drop_connected_pending_cmpct(hub, follow, session);
    if follow.pending_cmpct.len() >= MAX_PENDING_CMPCT {
        log_cmpct_getdata(hash, missing_n);
        return queue_out(
            out_tx,
            NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
        );
    }
    let may_fill = session.is_none_or(|s| s.try_cmpct_fill(hash));
    if !may_fill {
        return Ok(());
    }
    let missing = partial.missing().to_vec();
    follow.pending_cmpct.insert(
        hash,
        PendingCmpct {
            hsi: hsi.clone(),
            partial,
            fill: fill.map(|b| *b),
            since: std::time::Instant::now(),
        },
    );
    if let Some(s) = session {
        let h = hub
            .query
            .height_of_hash(&hsi.header.prev_blockhash.to_byte_array())
            .ok()
            .flatten()
            .map(|ht| ht.0.saturating_add(1))
            .unwrap_or_else(|| hub.tip_height().unwrap_or(0).saturating_add(1));
        s.note_block_inflight(h);
        s.note_blocks_requested(&[hash]);
    }
    queue_out(
        out_tx,
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: crate::compact::missing_request(hash, &missing),
        }),
    )?;
    rbitcoin_log::debug!("cmpct reconstruct {hash} missing={missing_n} awaiting blocktxn");
    Ok(())
}

pub async fn on_blocktxn(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    bt: &BlockTransactions,
) -> Result<(), NetError> {
    let hash = bt.block_hash;
    if let Some(mp) = hub.mempool() {
        mp.try_note_extra_compact_txs(bt.transactions.iter());
    }
    if session.is_some_and(|s| s.has_failed_cmpct(&hash)) {
        rbitcoin_log::info!("p2p: previous compact block reconstruction attempt failed");
        misbehaving(&mut follow.ban_score, session);
        return Ok(());
    }
    let Some(pc) = follow.pending_cmpct.remove(&hash) else {
        follow.ban_score = follow.ban_score.saturating_add(5);
        return Ok(());
    };
    match apply_cmpct_blocktxn(&pc, bt) {
        Ok((block, fill)) => {
            on_blocktxn_got_block(hub, out_tx, follow, session, &pc, hash, block, fill).await
        }
        Err(()) => on_blocktxn_apply_fail(out_tx, follow, session, &pc, hash),
    }
}

#[allow(clippy::too_many_arguments)] // one blocktxn fill; call site stays unbundled
pub async fn on_blocktxn_got_block(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    pc: &PendingCmpct,
    hash: BlockHash,
    block: Block,
    fill: Option<crate::compact::CmpctFillSets>,
) -> Result<(), NetError> {
    log_cmpct_filled(hub, &pc.hsi, &block, pc.partial.missing(), fill.as_ref());
    relay_new_pow_valid_block(hub, &block, session).await;
    match accept_received_from_peer(hub, block.clone(), session).await {
        Ok(AcceptOutcome::Accepted { .. }) => {
            take_requested_block(hub, &mut follow.requested_blocks, &hash);
            if let Some(s) = session {
                if let Some(h) = hub.tip_height() {
                    s.clear_block_inflight(h);
                }
                if let Some(ph) = s.peer_hub() {
                    ph.clear_cmpct_fill(hash);
                }
            }
            drain_pending(
                hub,
                out_tx,
                &mut follow.pending_blocks,
                &mut follow.pending_headers,
                &mut follow.requested_blocks,
                getdata_use_compact(hub, follow.cmpct_version),
                session,
            )
            .await
        }
        Ok(_) => {
            take_requested_block(hub, &mut follow.requested_blocks, &hash);
            if let Some(s) = session {
                s.release_cmpct_taken(hash);
            }
            drain_pending(
                hub,
                out_tx,
                &mut follow.pending_blocks,
                &mut follow.pending_headers,
                &mut follow.requested_blocks,
                getdata_use_compact(hub, follow.cmpct_version),
                session,
            )
            .await
        }
        Err(e) if net_error_needs_parent(&e) => {
            take_requested_block(hub, &mut follow.requested_blocks, &hash);
            follow.pending_blocks.insert(hash, block);
            maybe_select_hb_if_relay(hub, session);
            if let Some(s) = session {
                s.release_cmpct_taken(hash);
            }
            drain_pending(
                hub,
                out_tx,
                &mut follow.pending_blocks,
                &mut follow.pending_headers,
                &mut follow.requested_blocks,
                getdata_use_compact(hub, follow.cmpct_version),
                session,
            )
            .await
        }
        Err(_) => on_blocktxn_unconnectable(out_tx, follow, session, hash),
    }
}

#[doc(hidden)]
pub fn on_blocktxn_apply_fail(
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    pc: &PendingCmpct,
    hash: BlockHash,
) -> Result<(), NetError> {
    rbitcoin_log::info!("p2p: previous compact block reconstruction attempt failed");
    log_cmpct_getdata(hash, pc.partial.missing().len());
    if let Some(s) = session {
        s.note_failed_cmpct(hash);
        s.release_cmpct_taken(hash);
    }
    follow.ban_score = follow.ban_score.saturating_add(10);
    queue_out(
        out_tx,
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
    )
}

#[doc(hidden)]
pub fn on_blocktxn_unconnectable(
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
) -> Result<(), NetError> {
    rbitcoin_log::info!("p2p: previous compact block reconstruction attempt failed");
    if let Some(s) = session {
        s.note_failed_cmpct(hash);
        s.release_cmpct_taken(hash);
    }
    follow.ban_score = follow.ban_score.saturating_add(10);
    queue_out(
        out_tx,
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TxAcceptLog<'a> {
    Silent,
    Park(&'a BTreeSet<bitcoin::Txid>),
    ParentFetch(&'a BTreeSet<bitcoin::Txid>),
    Reject,
}

/// Invalid-script announcements are misbehavior. Policy rejects are not.
pub fn tx_reject_ban_score(e: &rbitcoin_mempool::AcceptError) -> u32 {
    match e {
        rbitcoin_mempool::AcceptError::Script(_) => 10,
        _ => 0,
    }
}

#[doc(hidden)]
pub fn tx_accept_log(e: &rbitcoin_mempool::AcceptError) -> TxAcceptLog<'_> {
    match e {
        rbitcoin_mempool::AcceptError::Duplicate(_) => TxAcceptLog::Silent,
        rbitcoin_mempool::AcceptError::Orphaned {
            missing,
            fresh: true,
            ..
        } => TxAcceptLog::Park(missing),
        rbitcoin_mempool::AcceptError::Orphaned {
            missing,
            fresh: false,
            ..
        } => TxAcceptLog::ParentFetch(missing),
        _ => TxAcceptLog::Reject,
    }
}

#[doc(hidden)]
pub fn schedule_orphan_parent_getdata(
    mp: &crate::tx_relay::MempoolHub,
    tx: &Transaction,
    session: Option<&crate::peers::LivePeer>,
    extra_from: &[u64],
) {
    let Some(s) = session else {
        return;
    };
    let missing = mp.orphan_getdata_parents(tx);
    let now = s.clock_now();
    mp.schedule_orphan_parents(&missing, s.id, s.inbound, now);
    let Some(ph) = s.peer_hub() else {
        return;
    };
    for id in extra_from {
        if *id == s.id {
            continue;
        }
        if let Some(p) = ph.live_peers().into_iter().find(|p| p.id == *id) {
            mp.schedule_orphan_parents(&missing, p.id, p.inbound, now);
        }
    }
}

#[doc(hidden)]
pub fn queue_due_parent_getdata(
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    let want = mp.take_due_parent_getdata(session.id, session.clock_now());
    if want.is_empty() {
        return;
    }
    mp.note_getdata_tx(want.len() as u64);
    let inv = want
        .into_iter()
        .map(|due| {
            if due.wtxid {
                Inventory::WTx(bitcoin::Wtxid::from_byte_array(due.hash))
            } else {
                Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(due.hash))
            }
        })
        .collect();
    let _ = queue_accounted(Some(session), out_tx, NetworkMessage::GetData(inv));
}

pub async fn on_tx(
    hub: &ChainHub,
    _out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    tx: &Transaction,
) -> Result<(), NetError> {
    rbitcoin_log::trace!("{}", received_tx_log());
    if hub.in_ibd() {
        return Ok(());
    }
    if reject_unsolicited_tx(hub, session) {
        let id = session.map(|s| s.id).unwrap_or(0);
        rbitcoin_log::info!(
            "p2p: transaction sent in violation of protocol, disconnecting peer={id}"
        );
        punish_disconnect(&mut follow.ban_score, session);
        return Ok(());
    }
    if let Some(mp) = hub.mempool() {
        if mp.relay_enabled() || session.is_some_and(|s| s.session_relay_perm()) {
            let txid = tx.compute_txid();
            let wtxid = tx.compute_wtxid();
            follow.from_this_peer.insert(txid, FROM_THIS_PEER_CAP);
            let from = session.map(|s| s.id);
            let trusted = session
                .is_some_and(|s| s.peer_hub().is_some_and(|ph| ph.session_is_trusted_peer(s)));
            // A recent reject is final for every peer except the trusted one.
            // That session already accepted the tx, so judge it again.
            if mp.try_recent_reject(&wtxid) && !trusted {
                mp.resolve_tx_request(&txid, &wtxid, false);
                maybe_force_relay_recent_reject(hub, session, mp, txid, wtxid);
                return Ok(());
            }
            if trusted {
                mp.set_trusted_session(from);
            }
            let mp_task = Arc::clone(mp);
            let tx_task = tx.clone();
            let peers = session.and_then(|s| s.peer_hub());
            let hub_arc = hub.shared_arc();
            // The blocksonly note shares the admit task. Aborting this
            // session during script verify must not skip the rebroadcast.
            let admitted = crate::reactor::spawn_with_store_budget(async move {
                let result = mp_task
                    .accept_tx_from_async(tx_task, crate::tx_relay::TxOrigin::Relay(from))
                    .await;
                if let Ok(r) = &result {
                    if !mp_task.relay_enabled() {
                        mp_task.note_unbroadcast(r.txid);
                        mp_task.rebroadcast_unbroadcast();
                        mp_task.notify_inv_flush();
                        if let (Some(h), Some(ph)) = (hub_arc.as_ref(), peers.as_ref()) {
                            flush_tx_invs(h, ph.as_ref());
                        }
                    }
                }
                result
            })
            .await
            .expect("tx admit");
            match admitted {
                Ok(_r) => {
                    mp.resolve_tx_request(&txid, &wtxid, true);
                    if let Some(s) = session {
                        s.note_last_transaction();
                    }
                    // A hub that is not `into_arc` has no detached handle.
                    // Flush here so the other inbound still sees the INV.
                    // An `into_arc` hub already flushed inside the admit task.
                    if !mp.relay_enabled() && hub.shared_arc().is_none() {
                        if let Some(s) = session {
                            if let Some(ph) = s.peer_hub() {
                                flush_tx_invs(hub, ph.as_ref());
                            }
                        }
                    }
                }
                Err(e) => {
                    let extra_from = matches!(
                        tx_accept_log(&e),
                        TxAcceptLog::Park(_) | TxAcceptLog::ParentFetch(_)
                    )
                    .then(|| mp.announcer_peers_for(&txid, &wtxid))
                    .unwrap_or_default();
                    mp.resolve_tx_request(&txid, &wtxid, false);
                    match tx_accept_log(&e) {
                        TxAcceptLog::Silent => {
                            if let rbitcoin_mempool::AcceptError::Duplicate(tid) = &e {
                                maybe_force_relay_duplicate(hub, session, tx, *tid);
                            }
                        }
                        TxAcceptLog::Park(_missing) => {
                            rbitcoin_log::debug!("txrelay: park {txid} missingorspent");
                            for p in &extra_from {
                                let _ = mp.add_orphan_announcer(&txid, *p);
                            }
                            if mp.try_orphan_missing(&txid).is_some() {
                                schedule_orphan_parent_getdata(mp, tx, session, &extra_from);
                            }
                        }
                        TxAcceptLog::ParentFetch(_missing) => {
                            for p in &extra_from {
                                let _ = mp.add_orphan_announcer(&txid, *p);
                            }
                            if mp.try_orphan_missing(&txid).is_some() {
                                schedule_orphan_parent_getdata(mp, tx, session, &extra_from);
                            }
                        }
                        TxAcceptLog::Reject => {
                            follow.ban_score =
                                follow.ban_score.saturating_add(tx_reject_ban_score(&e));
                            let id = session.map(|s| s.id).unwrap_or(0);
                            rbitcoin_log::info!(
                                "txrelay: reject {txid} (wtxid={wtxid}) from peer={id} was not accepted: {}",
                                e.mempool_reject_reason()
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn on_bloom_forbidden(
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    punish_disconnect(&mut follow.ban_score, session);
    Ok(())
}

#[doc(hidden)]
pub fn on_getaddr(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    if let Some(s) = session {
        if !s.take_getaddr() {
            return Ok(());
        }
        let _ = maybe_queue_local_addr(hub, s, out_tx);
    }
    let bind = session
        .map(|s| s.addrbind)
        .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let v2 = session.is_some_and(|s| s.wants_addrv2());
    let addrs = match session.and_then(|s| s.peer_hub()) {
        Some(ph) => ph.addr_response_net(bind, v2),
        None => Vec::new(),
    };
    queue_addr_list(session, out_tx, addrs, v2)?;
    Ok(())
}

pub async fn drain_after_accept(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
    hash: BlockHash,
    select_hb: bool,
) -> Result<(), NetError> {
    follow.pending_blocks.remove(&hash);
    follow.pending_headers.remove(&hash);
    hub.forget_asked_block(&hash);
    if select_hb {
        maybe_select_hb_if_relay(hub, session);
    }
    drain_pending(
        hub,
        out_tx,
        &mut follow.pending_blocks,
        &mut follow.pending_headers,
        &mut follow.requested_blocks,
        getdata_use_compact(hub, follow.cmpct_version),
        session,
    )
    .await
}

#[derive(Debug)]
#[doc(hidden)]
pub enum TipAnnounce {
    Headers(Vec<bitcoin::block::Header>),
    Inv(BlockHash),
    Skip,
}

#[derive(Debug)]
pub enum TipRecvAnnounce {
    Announce(crate::chain::TipEvent),
    Skip,
    Closed,
}

#[doc(hidden)]
pub fn current_tip_announce(hub: &ChainHub) -> TipRecvAnnounce {
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

/// True when `tip` is not the header we last sent this peer, and not a
/// descendant of it. Those announcements wait [`TIP_ANNOUNCE_BATCH`] so a
/// reorg is one message.
#[doc(hidden)]
pub fn tip_is_reorg_vs_sent(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    tip: &Result<crate::chain::TipEvent, broadcast::error::RecvError>,
) -> bool {
    if matches!(tip, Err(broadcast::error::RecvError::Closed)) {
        return false;
    }
    let Some(mark) = session.and_then(|s| s.header_marks().0) else {
        return false;
    };
    let hash = match tip {
        Ok(ev) => ev.hash,
        Err(_) => match hub.tip_hash() {
            Some(h) => h,
            None => return false,
        },
    };
    hash != mark && !hub.is_header_ancestor(mark, hash)
}

/// Map a `tip_rx.recv()` result to the tip we should announce.
///
/// `Lagged` and a queued `TipEvent` whose hash is no longer `hub.tip` both
/// announce the **current** hub tip so a generate burst does not enqueue one
/// headers/cmpct per height ahead of GetData bodies.
pub fn tip_event_for_announce(
    recv: Result<crate::chain::TipEvent, broadcast::error::RecvError>,
    hub: &ChainHub,
) -> TipRecvAnnounce {
    match recv {
        Ok(ev) if hub.tip_hash() == Some(ev.hash) => TipRecvAnnounce::Announce(ev),
        Ok(_) => current_tip_announce(hub),
        Err(broadcast::error::RecvError::Closed) => TipRecvAnnounce::Closed,
        Err(broadcast::error::RecvError::Lagged(_)) => current_tip_announce(hub),
    }
}

#[doc(hidden)]
pub fn peer_has_header(
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

/// BIP152 compact tip announcement from an in-RAM body.
#[doc(hidden)]
pub fn cmpct_announce_from_block(
    hub: &ChainHub,
    block: &Block,
    cmpct_version: u32,
) -> Option<NetworkMessage> {
    crate::reactor::assert_not_reactor("cmpct announce");
    let ver = cmpct_version.clamp(1, 2);
    let pref = hub
        .cmpct_prefill_indexes(&block.block_hash())
        .unwrap_or_else(|| vec![0]);
    cmpct_from_parts(block, rand_nonce(), ver, &pref)
}

/// Short ids for a block already in hand. No store read.
fn cmpct_from_parts(block: &Block, nonce: u64, ver: u32, pref: &[usize]) -> Option<NetworkMessage> {
    crate::reactor::assert_not_reactor("cmpct short ids");
    let hsi = HeaderAndShortIds::from_block(block, nonce, ver, pref)
        .or_else(|_| HeaderAndShortIds::from_block(block, nonce, ver, &[0]))
        .ok()?;
    rbitcoin_log::info!(
        "{}",
        crate::compact::cmpct_send_line(block.block_hash(), block.txdata.len(), &hsi)
    );
    Some(NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: hsi,
    }))
}

async fn cmpct_from_parts_cpu(
    block: Block,
    nonce: u64,
    ver: u32,
    pref: Vec<usize>,
) -> Result<Option<NetworkMessage>, NetError> {
    match rbitcoin_consensus::script_pool::run_cpu(move || {
        cmpct_from_parts(&block, nonce, ver, &pref)
    })
    .await
    {
        Some(msg) => Ok(msg),
        None => Err(NetError::Protocol("cmpct relay join failed")),
    }
}

/// BIP152 compact tip announcement (coinbase prefilled). `None` if the body
/// is not in cache/store yet.
#[doc(hidden)]
pub fn cmpct_announce_msg(
    hub: &ChainHub,
    hash: &BlockHash,
    cmpct_version: u32,
) -> Option<NetworkMessage> {
    let block = block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), hash).ok()??;
    cmpct_announce_from_block(hub, &block, cmpct_version)
}

/// A header from the current peer. While the mode is on that peer is the trusted one.
/// Flag-off does not write the waive cell. Runs on the same thread as the header store.
fn ensure_peer_header(hub: &ChainHub, header: &bitcoin::block::Header) -> Result<(), NetError> {
    rbitcoin_query::confirm_run::waive_batch(hub.query.trust_peer(), || hub.ensure_header(header))
}

/// Tip `cmpctblock`. The body load stays on the blocking pool. Short ids
/// run on `rbtc-scripts-*` once that body is in hand. A missing body is
/// `None` and the caller sends headers.
async fn cmpct_tip_announce(
    hub: &ChainHub,
    hash: &BlockHash,
    cmpct_version: u32,
) -> Result<Option<NetworkMessage>, NetError> {
    let Some(owned) = hub.shared_arc() else {
        return Ok(cmpct_announce_msg(hub, hash, cmpct_version));
    };
    let permit = block_reconstruct_permit().await?;
    let hash = *hash;
    let ver = cmpct_version.clamp(1, 2);
    let loaded = tokio::task::spawn_blocking(move || {
        let _region = crate::reactor::BlockingRegion::enter();
        let _permit = permit;
        let block = block_for_peer(owned.cache.as_ref(), owned.query.as_ref(), &hash).ok()??;
        let pref = owned
            .cmpct_prefill_indexes(&block.block_hash())
            .unwrap_or_else(|| vec![0]);
        Some((block, pref, rand_nonce()))
    })
    .await
    .map_err(|_| NetError::Protocol("cmpct announce join failed"))?;
    let Some((block, pref, nonce)) = loaded else {
        return Ok(None);
    };
    cmpct_from_parts_cpu(block, nonce, ver, pref).await
}

/// Header persist and prefill for a block already in hand, then short ids.
///
/// An `Arc` hub persists the header on the blocking pool and builds short
/// ids on `rbtc-scripts-*`. A stack hub (tests) does both inline.
/// `Ok(None)` is a header the store refused or a body that did not become
/// a compact message. A closed permit or a failed join is `Err`, the same
/// class as [`cmpct_tip_announce`].
async fn cmpct_announce_off_session(
    hub: &ChainHub,
    block: Block,
    cmpct_version: u32,
) -> Result<Option<NetworkMessage>, NetError> {
    let Some(owned) = hub.shared_arc() else {
        return Ok(hb_relay_message(hub, &block, cmpct_version));
    };
    let permit = block_reconstruct_permit().await?;
    let joined = tokio::task::spawn_blocking(move || {
        let _region = crate::reactor::BlockingRegion::enter();
        let _permit = permit;
        hb_relay_prepare(owned.as_ref(), block, cmpct_version)
    })
    .await;
    let Some((block, ver, pref, nonce)) = map_cmpct_relay_join(joined)? else {
        return Ok(None);
    };
    cmpct_from_parts_cpu(block, nonce, ver, pref).await
}

fn hb_relay_prepare(
    hub: &ChainHub,
    block: Block,
    cmpct_version: u32,
) -> Option<(Block, u32, Vec<usize>, u64)> {
    if ensure_peer_header(hub, &block.header).is_err() {
        return None;
    }
    hub.remember_cmpct_prefill_from_block(&block);
    let ver = cmpct_version.clamp(1, 2);
    let pref = hub
        .cmpct_prefill_indexes(&block.block_hash())
        .unwrap_or_else(|| vec![0]);
    Some((block, ver, pref, rand_nonce()))
}

fn hb_relay_message(hub: &ChainHub, block: &Block, cmpct_version: u32) -> Option<NetworkMessage> {
    let (block, ver, pref, nonce) = hb_relay_prepare(hub, block.clone(), cmpct_version)?;
    cmpct_from_parts(&block, nonce, ver, &pref)
}

/// A panicked or cancelled blocking job is not "no compact message".
#[doc(hidden)]
pub fn map_cmpct_relay_join<T>(joined: Result<T, tokio::task::JoinError>) -> Result<T, NetError> {
    joined.map_err(|_| NetError::Protocol("cmpct relay join failed"))
}

fn hb_peer_offered_block(
    hub: &ChainHub,
    peer: &crate::peers::LivePeer,
    from_id: Option<u64>,
    hash: BlockHash,
    prev: BlockHash,
) -> bool {
    if from_id == Some(peer.id) {
        return false;
    }
    if !peer.hb_from.load(Ordering::Relaxed) {
        return false;
    }
    if peer.conn_type == crate::peers::PeerConnType::BlockRelay {
        return false;
    }
    let (sent, known) = peer.header_marks();
    !peer_has_header(hub, sent, known, hash) && peer_has_header(hub, sent, known, prev)
}

/// Send `cmpctblock` to peers who asked for high-bandwidth announcements
/// (`hb_from`: they sent `sendcmpct` announce=1) as soon as a reconstructed
/// or received body has a PoW-valid header that extends our tip, **before**
/// `tip-accept` connect. Does not mark the block connected.
///
/// The compact message is built only when one of those peers would be
/// offered the block. No such peer returns before the clone and the
/// blocking job.
///
/// Core `NewPoWValidBlock`: the peer already has the parent header and not
/// this one. `hb_to` is the opposite direction (we asked them to announce
/// to us). Only the current tip-child (not a reorg branch). Sender is skipped.
#[doc(hidden)]
pub async fn relay_new_pow_valid_block(
    hub: &ChainHub,
    block: &Block,
    from: Option<&crate::peers::LivePeer>,
) {
    if !hub.meets_minimum_chain_work() {
        return;
    }
    if !compact_blocks_ok(hub) {
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
    let Some(ph) = from.and_then(|s| s.peer_hub()) else {
        return;
    };
    let from_id = from.map(|s| s.id);
    let prev = block.header.prev_blockhash;
    let targets: Vec<_> = ph
        .live_peers()
        .into_iter()
        .filter(|s| hb_peer_offered_block(hub, s, from_id, hash, prev))
        .collect();
    if targets.is_empty() {
        return;
    }
    let msg = match cmpct_announce_off_session(hub, block.clone(), 2).await {
        Ok(Some(msg)) => msg,
        Ok(None) => return,
        Err(e) => {
            rbitcoin_log::warn!("p2p: high-bandwidth compact relay skipped: {e}");
            return;
        }
    };
    for s in targets {
        let Some(out) = s.writer() else {
            continue;
        };
        if queue_cmpct_tip_announce(&out, msg.clone()).is_ok() {
            s.note_best_header_sent(hash);
        }
    }
}

#[doc(hidden)]
pub fn tip_announce_decision(
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

#[doc(hidden)]
pub fn is_genesis_hash(h: &BlockHash) -> bool {
    h.to_byte_array() == [0u8; 32]
}

/// Walk `pending` toward genesis. Returns the first hash **not** in `pending`
/// and how many pending headers were consumed. Store is not consulted.
/// `true` when this batch's pending work is under `-minimumchainwork`.
///
/// The sum uses the pending headers and, when they sit on our tip or another
/// indexed block, that block's cached chain work. It does not walk parent
/// headers in the store. `None` means the walk never reached an indexed
/// block. While our chain is under the floor, that is still the ignore path.
#[doc(hidden)]
pub fn headers_are_below_floor(
    hub: &ChainHub,
    pending_before: &HashMap<BlockHash, bitcoin::block::Header>,
    headers: &[bitcoin::block::Header],
) -> bool {
    let Some(min) = hub.min_chain_work_floor() else {
        return false;
    };
    if hub.meets_minimum_chain_work() {
        return false;
    }
    let mut pending = pending_before.clone();
    for hdr in headers {
        pending.insert(hdr.block_hash(), *hdr);
    }
    let Some(last) = headers.last().map(|h| h.block_hash()) else {
        return false;
    };
    match pending_path_work(hub, &pending, last) {
        Some(work) => work.to_be_bytes() < min,
        None => true,
    }
}

#[doc(hidden)]
pub fn pending_path_work(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> Option<bitcoin::Work> {
    let mut extra: Vec<bitcoin::Work> = Vec::new();
    let mut h = tip;
    for _ in 0..PENDING_WALK_LIMIT {
        if is_genesis_hash(&h) {
            extra.reverse();
            return crate::most_work::sum_work(extra.into_iter()).ok();
        }
        if hub.tip_hash() == Some(h) {
            let base = hub.cached_chain_work()?;
            extra.reverse();
            return crate::most_work::sum_work(std::iter::once(base).chain(extra)).ok();
        }
        let Some(hdr) = pending.get(&h).copied() else {
            // An indexed ancestor is our chain. Do not walk the header store
            // to discover a parent this batch did not connect.
            let height = hub.query.published_height_of_hash(&h.to_byte_array())?;
            let base = hub.work_through_height(height.0).ok()?;
            extra.reverse();
            return crate::most_work::sum_work(std::iter::once(base).chain(extra)).ok();
        };
        if !hub.header_claimed_pow_ok(&hdr) {
            return None;
        }
        extra.push(hdr.work());
        h = hdr.prev_blockhash;
    }
    None
}

/// Height of a pending path that reaches genesis. No header-store read.
#[doc(hidden)]
pub fn pending_announced_height(
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> u32 {
    if is_genesis_hash(&tip) {
        return 0;
    }
    pending_walk(pending, tip).1
}

#[doc(hidden)]
pub fn pending_walk(
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> (BlockHash, u32) {
    let mut h = start;
    let mut steps = 0u32;
    while steps < PENDING_WALK_LIMIT as u32 {
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
#[doc(hidden)]
pub fn announced_headers_height(
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
/// Store the pending headers from `tip` back to the last stored one. Headers
/// already stored were checked when they were written.
#[doc(hidden)]
pub fn persist_pending_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) {
    let mut path = Vec::new();
    let mut h = tip;
    for _ in 0..PENDING_WALK_LIMIT {
        let Some(hdr) = pending.get(&h) else {
            break;
        };
        if header_is_stored(hub, &h) {
            break;
        }
        path.push(*hdr);
        h = hdr.prev_blockhash;
        if is_genesis_hash(&h) {
            break;
        }
    }
    path.reverse();
    // One store batch. Per-header ensure walks parent heights to genesis, so a
    // full below-floor chain (thousands of headers) is quadratic.
    for chunk in path.chunks(MAX_HEADERS_RESULTS) {
        if hub.ensure_headers_batch(chunk).is_err() {
            break;
        }
    }
}

#[doc(hidden)]
pub fn header_is_stored(hub: &ChainHub, hash: &BlockHash) -> bool {
    hub.query
        .get_header_by_hash(&hash.to_byte_array())
        .ok()
        .flatten()
        .is_some()
}

#[doc(hidden)]
pub fn header_announcement_connects(
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
pub const ANCIENT_TIP_BLOCKS: u32 = 288;

/// Connecting header path whose **work** cannot beat our tip and whose announced
/// height is more than [`ANCIENT_TIP_BLOCKS`] behind — BIP-110-class minority fork.
pub fn announced_tip_is_hopeless(
    our_tip: u32,
    announced_h: u32,
    work_cmp: Option<std::cmp::Ordering>,
) -> bool {
    matches!(work_cmp, Some(std::cmp::Ordering::Less))
        && announced_h.saturating_add(ANCIENT_TIP_BLOCKS) < our_tip
}

/// Announced path work vs our tip work. `None` if the walk cannot sum work.
#[doc(hidden)]
pub fn announced_work_cmp(
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
#[doc(hidden)]
pub fn header_branch_vs_tip(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> Option<std::cmp::Ordering> {
    if hub.is_connected(&start) {
        let ancestor = hub
            .query
            .published_height_of_hash(&start.to_byte_array())?
            .0;
        let tip = hub.tip_height()?;
        return Some(0u32.cmp(&tip.saturating_sub(ancestor)));
    }
    let (mut h, mut n_new) = pending_walk(pending, start);
    if is_genesis_hash(&h) {
        return Some(std::cmp::Ordering::Greater);
    }
    for _ in 0..PENDING_WALK_LIMIT {
        if hub.is_connected(&h) {
            let ancestor = hub.query.published_height_of_hash(&h.to_byte_array())?.0;
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
#[doc(hidden)]
pub fn header_path_meets_minwork(
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

#[doc(hidden)]
pub fn any_header_path_meets_minwork(
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

#[doc(hidden)]
pub fn work_of_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> Option<bitcoin::Work> {
    let mut extra: Vec<bitcoin::Work> = Vec::new();
    let mut h = tip;
    for _ in 0..PENDING_WALK_LIMIT {
        if hub.is_connected(&h) {
            let height = hub.query.published_height_of_hash(&h.to_byte_array())?.0;
            let base = hub.work_through_height(height).ok()?;
            extra.reverse();
            return crate::most_work::sum_work(std::iter::once(base).chain(extra)).ok();
        }
        let hdr = pending.get(&h).copied().or_else(|| hub.header_of(&h))?;
        if !hub.header_claimed_pow_ok(&hdr) {
            return None;
        }
        extra.push(hdr.work());
        h = hdr.prev_blockhash;
        if h.to_byte_array() == [0u8; 32] {
            extra.reverse();
            return crate::most_work::sum_work(extra.into_iter()).ok();
        }
    }
    None
}

/// Connecting header path from `tip` back to our chain, oldest first.
/// Empty below `-minimumchainwork` or when the walk cannot join our chain.
/// Includes a still-weaker competitor so stale-fork getdata can be dropped.
#[doc(hidden)]
pub fn connecting_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> Vec<BlockHash> {
    if !header_path_meets_minwork(hub, pending, tip) {
        return Vec::new();
    }
    if work_of_header_path(hub, pending, tip).is_none() {
        return Vec::new();
    }
    let mut path = Vec::new();
    let mut h = tip;
    for _ in 0..PENDING_WALK_LIMIT {
        if hub.is_connected(&h) {
            break;
        }
        path.push(h);
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

/// Connecting header path from `tip` back to our chain, oldest first.
/// Empty when the path is weaker than tip or below `-minimumchainwork`.
#[doc(hidden)]
pub fn better_connecting_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
) -> Vec<BlockHash> {
    if matches!(
        announced_work_cmp(hub, pending, tip),
        Some(std::cmp::Ordering::Less)
    ) {
        return Vec::new();
    }
    connecting_header_path(hub, pending, tip)
}

/// Bodies on `tip`'s connecting header path that we may `getdata`.
/// Weaker-than-tip and below `-minimumchainwork` stay header-only.
#[doc(hidden)]
pub fn fetchable_header_path_bodies(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
    pending_blocks: &PendingBlocks,
    requested: &HashSet<BlockHash>,
) -> Vec<BlockHash> {
    better_connecting_header_path(hub, pending, tip)
        .into_iter()
        .filter(|h| {
            !pending_blocks.contains_key(h)
                && !requested.contains(h)
                && !hub.already_have_or_asked_block(h)
        })
        .collect()
}

/// Compact getdata is the next block (prev is our tip). Catch-up and competing
/// forks use `MSG_WITNESS_BLOCK`.
#[doc(hidden)]
pub fn compact_getdata_near_tip(hub: &ChainHub, hash: &BlockHash) -> bool {
    if hub.tip_hash() == Some(*hash) {
        return true;
    }
    hub.header_of(hash)
        .is_some_and(|hdr| hub.tip_hash() == Some(hdr.prev_blockhash))
}

/// Core CMPCTBLOCK: reconstruct unsolicited compact only from a peer we sent
/// `sendcmpct(1)` (BIP152 high-bandwidth, Core #32606), when claimed work
/// beats the tip and `nHeight <= tipHeight + 2`. The next block (prev is
/// tip) is always near-tip even if the header is not yet in the work prefix.
/// In-tree callers with no session are not a peer and skip the
/// high-bandwidth rule.
#[doc(hidden)]
pub fn compact_unsolicited_reconstruct(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    header: &bitcoin::block::Header,
) -> bool {
    if !session.is_none_or(|s| s.hb_to.load(Ordering::Relaxed)) {
        return false;
    }
    if hub.tip_hash() == Some(header.prev_blockhash) || hub.tip_hash() == Some(header.block_hash())
    {
        return true;
    }
    let Ok(tip_w) = hub.chain_work() else {
        return true;
    };
    if hub.work_with_header(header) <= tip_w {
        return false;
    }
    let Some(tip_h) = hub.tip_height() else {
        return true;
    };
    let Some(h) = compact_claimed_height(hub, header) else {
        return false;
    };
    h <= tip_h.saturating_add(2)
}

#[doc(hidden)]
pub fn compact_claimed_height(hub: &ChainHub, header: &bitcoin::block::Header) -> Option<u32> {
    let hash = header.block_hash();
    if let Some(h) = hub.header_height(&hash) {
        return Some(h);
    }
    hub.header_height(&header.prev_blockhash)
        .map(|p| p.saturating_add(1))
}

/// Resend BIP133 feefilter when the published floor moved since the last send.
#[doc(hidden)]
pub fn maybe_queue_feefilter(
    hub: &ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    session: &crate::peers::LivePeer,
) {
    let Some(fee) = outbound_feefilter_sats(hub, Some(session)) else {
        return;
    };
    if session.sent_feefilter_sat_kvb() == fee {
        return;
    }
    if queue_out(out_tx, NetworkMessage::FeeFilter(fee)).is_ok() {
        session.note_sent_feefilter(fee);
    }
}

/// BIP133 feefilter to send after handshake. None = do not send (blocksonly,
/// forcerelay, block-relay-only). IBD still sends rounded MAX_MONEY.
pub fn outbound_feefilter_sats(
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
) -> Option<i64> {
    if session.is_some_and(|s| {
        s.conn_type == crate::peers::PeerConnType::BlockRelay || s.session_forcerelay()
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

#[doc(hidden)]
pub fn queue_out(
    out: &mpsc::UnboundedSender<PeerOut>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    queue_accounted(None, out, msg)
}

/// Send filtered tx announcements in [`TX_INV_BATCH`] chunks.
///
/// The caller already owns the filtered inventories. Chunking does not clone
/// the live wtxid set and does not hold the mempool lock across the send.
#[doc(hidden)]
pub fn queue_tx_inv_batches(
    session: &crate::peers::LivePeer,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    inv: Vec<Inventory>,
) {
    for chunk in inv.chunks(TX_INV_BATCH) {
        let _ = queue_accounted(Some(session), out_tx, NetworkMessage::Inv(chunk.to_vec()));
    }
}

#[doc(hidden)]
pub fn queue_accounted(
    session: Option<&crate::peers::LivePeer>,
    out: &mpsc::UnboundedSender<PeerOut>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    queue_charged(session, out, PeerOut::Msg(msg))
}

#[doc(hidden)]
pub fn queue_charged(
    session: Option<&crate::peers::LivePeer>,
    out: &mpsc::UnboundedSender<PeerOut>,
    item: PeerOut,
) -> Result<(), NetError> {
    let n = crate::peers::outbound_queued_bytes(&item);
    out.send(item)
        .map_err(|_| NetError::Protocol("peer write half closed"))?;
    if let Some(s) = session {
        s.note_send_queued(n);
    }
    Ok(())
}

/// Queue a getdata body ([`PeerOut::holds_serve_slot`]) and count it on
/// `serve_inflight`. [`crate::peers::LivePeer::has_serve_room`] already
/// held the getdata until the cap had room.
#[doc(hidden)]
pub fn queue_served(
    session: Option<&crate::peers::LivePeer>,
    out: &mpsc::UnboundedSender<PeerOut>,
    item: PeerOut,
) -> Result<(), NetError> {
    let Some(s) = session else {
        return queue_charged(None, out, item);
    };
    s.serve_inflight.fetch_add(1, Ordering::SeqCst);
    queue_charged(session, out, item).inspect_err(|_| s.free_serve_slot())
}

/// BIP152 high-bandwidth tip announce. Takes no `serve_inflight` slot
/// (that cap is reconstruct getdata), and the writer frees none for it.
#[doc(hidden)]
pub fn queue_cmpct_tip_announce(
    out: &mpsc::UnboundedSender<PeerOut>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    queue_out(out, msg)
}

#[doc(hidden)]
pub fn pending_header_leaves(
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
) -> Vec<BlockHash> {
    let prevs: HashSet<BlockHash> = pending.values().map(|h| h.prev_blockhash).collect();
    pending
        .keys()
        .copied()
        .filter(|h| !prevs.contains(h))
        .collect()
}

#[doc(hidden)]
pub fn keep_pending_connecting_paths(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
) -> Vec<BlockHash> {
    let mut keep: Vec<BlockHash> = Vec::new();
    for last in pending_header_leaves(pending) {
        for h in connecting_header_path(hub, pending, last) {
            if !keep.contains(&h) {
                keep.push(h);
            }
        }
    }
    keep
}

#[doc(hidden)]
pub fn release_asks_off_path(
    hub: &ChainHub,
    requested: &mut HashSet<BlockHash>,
    path: &[BlockHash],
) {
    if path.is_empty() {
        return;
    }
    let drop: Vec<BlockHash> = requested
        .iter()
        .copied()
        .filter(|h| !path.contains(h))
        .collect();
    for h in drop {
        take_requested_block(hub, requested, &h);
    }
}

/// Try to accept pending blocks that connect to tip or form a better branch.
pub async fn drain_pending(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<PeerOut>,
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

    let keep = keep_pending_connecting_paths(hub, pending_headers);
    let mut missing: Vec<BlockHash> = Vec::new();
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
    release_asks_off_path(hub, requested_blocks, &keep);
    missing.retain(|h| !requested_blocks.contains(h));
    for h in hub.held_missing_parents() {
        if !missing.contains(&h) {
            missing.push(h);
        }
    }
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
    missing.retain(|h| !requested_blocks.contains(h));
    let room = MAX_SERVE_BLOCKS.saturating_sub(requested_blocks.len());
    missing.truncate(room);
    queue_block_getdata(hub, out, session, requested_blocks, &missing, compact)?;
    Ok(())
}

pub fn drain_pending_now(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<PeerOut>,
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
pub async fn drain_pending_once(
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
            relay_new_pow_valid_block(hub, &block, session).await;
            match accept_received_from_peer(hub, block.clone(), session).await {
                Ok(AcceptOutcome::Accepted { .. })
                | Ok(AcceptOutcome::AlreadyHave)
                | Ok(AcceptOutcome::IgnoredWeaker) => {
                    progress = true;
                }
                Err(e) if net_error_needs_parent(&e) => {
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
                Err(e @ NetError::Store(_)) => {
                    note_store_fault_keep_session(hub, h, &e);
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
pub fn headers_reply_for_getheaders(
    hub: &ChainHub,
    gh: &bitcoin::p2p::message_blockdata::GetHeadersMessage,
) -> Result<Vec<bitcoin::block::Header>, NetError> {
    if !hub.meets_minimum_chain_work() {
        return Ok(Vec::new());
    }
    if gh.locator_hashes.is_empty() {
        let stop = gh.stop_hash;
        if stop.to_byte_array() != [0u8; 32] {
            if hub.is_connected(&stop) {
                if let Some(h) = hub.header_of(&stop) {
                    return Ok(vec![h]);
                }
            } else if hub.stale_relay_allowed(&stop) {
                let have_body = hub.cache.get_block(&stop).is_some()
                    || hub
                        .query
                        .is_block_archived(&stop.to_byte_array())
                        .unwrap_or(false);
                if have_body {
                    if let Some(h) = hub.header_of(&stop) {
                        return Ok(vec![h]);
                    }
                }
            }
            return Ok(Vec::new());
        }
    }
    headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), gh)
}

#[doc(hidden)]
pub fn headers_for_peer(
    cache: &BlockCache,
    query: &Query,
    gh: &bitcoin::p2p::message_blockdata::GetHeadersMessage,
) -> Result<Vec<bitcoin::block::Header>, NetError> {
    crate::reactor::assert_not_reactor("header reply");
    match query.headers_after_locator(&gh.locator_hashes, gh.stop_hash, MAX_HEADERS_RESULTS) {
        Ok(h) if !h.is_empty() || query.tip_height().is_some() => Ok(h),
        Ok(_) => Ok(cache.headers_after_locator(&gh.locator_hashes, gh.stop_hash)),
        Err(e) => Err(NetError::Consensus(e.to_string())),
    }
}

/// A store error while reading an announced tip wtxid is `notfound`.
/// The caller still turns a join failure into [`NetError`].
#[doc(hidden)]
pub fn announced_wtx_from_reconstruct(
    found: Result<Option<Transaction>, NetError>,
) -> Option<Transaction> {
    found.ok().flatten()
}

#[doc(hidden)]
pub fn tx_from_tip_block(hub: &ChainHub, wtxid: &bitcoin::Wtxid) -> Option<Transaction> {
    let hash = hub.tip_hash()?;
    announced_wtx_from_reconstruct(tx_from_stored_block(
        hub.cache.as_ref(),
        hub.query.as_ref(),
        &hash,
        wtxid,
    ))
}

#[doc(hidden)]
pub fn tx_from_stored_block(
    cache: &BlockCache,
    query: &Query,
    hash: &BlockHash,
    wtxid: &bitcoin::Wtxid,
) -> Result<Option<Transaction>, NetError> {
    let Some(block) = block_for_peer(cache, query, hash)? else {
        return Ok(None);
    };
    Ok(block
        .txdata
        .into_iter()
        .find(|tx| tx.compute_wtxid() == *wtxid))
}

#[doc(hidden)]
pub fn block_for_peer(
    cache: &BlockCache,
    query: &Query,
    hash: &BlockHash,
) -> Result<Option<bitcoin::Block>, NetError> {
    crate::reactor::assert_not_reactor("block reconstruct");
    if let Some(block) = cache.get_block(hash) {
        return Ok(Some(block));
    }
    match query.reconstruct_block_by_hash(&hash.to_byte_array()) {
        Ok(b) => Ok(b),
        Err(rbitcoin_store::StoreError::Pruned { .. }) => Ok(None),
        Err(e) => Err(NetError::Consensus(e.to_string())),
    }
}

#[doc(hidden)]
pub fn payload_tx_count(payload: &[u8]) -> u32 {
    use bitcoin::consensus::Decodable;
    if payload.len() < 81 {
        return 0;
    }
    bitcoin::consensus::encode::VarInt::consensus_decode(&mut &payload[80..])
        .map(|v| v.0 as u32)
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn encode_served_witness_block(
    cache: &BlockCache,
    query: &Query,
    hash: &BlockHash,
) -> Result<Option<Vec<u8>>, NetError> {
    crate::reactor::assert_not_reactor("getdata reconstruct");
    let t0 = std::time::Instant::now();
    if let Some(block) = cache.get_block(hash) {
        let tx_count = block.txdata.len() as u32;
        let encoded = crate::v2::encode_v2_contents(NetworkMessage::Block(block))?;
        let payload_len = encoded.len().saturating_sub(1);
        crate::serve_perf::note_serve(tx_count, payload_len, t0.elapsed().as_nanos());
        return Ok(Some(encoded));
    }
    match query.witness_block_bytes_by_hash(&hash.to_byte_array()) {
        Ok(Some(payload)) => {
            let tx_count = payload_tx_count(&payload);
            crate::serve_perf::note_serve(tx_count, payload.len(), t0.elapsed().as_nanos());
            let mut contents = Vec::with_capacity(1 + payload.len());
            contents.push(2);
            contents.extend_from_slice(&payload);
            Ok(Some(contents))
        }
        Ok(None) => Ok(None),
        Err(rbitcoin_store::StoreError::Pruned { .. }) => Ok(None),
        Err(e) => Err(NetError::Consensus(e.to_string())),
    }
}
