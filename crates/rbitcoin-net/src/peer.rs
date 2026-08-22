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
use crate::v2::{open_v2, read_v2_frame, write_v2_msg, write_v2_msg_offload, V2Reader, V2Writer};
use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags, PROTOCOL_VERSION};
use bitcoin::{Block, BlockHash, Transaction};
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};
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
/// Cap on the per-peer download window and missing-parent getdata burst
/// (DoS / process RAM). Must be ≥99 so tip-follow can *request* a 99-block
/// competing branch; apply is `ChainHub::accept_received_block` (see
/// `docs/architecture.md` most-work chain selection).
const MAX_PENDING_BLOCKS: usize = 128;

/// Test/assert surface for the tip-follow pending-body cap (equals production).
#[cfg(test)]
pub(crate) const MAX_PENDING_BLOCKS_FOR_TEST: usize = MAX_PENDING_BLOCKS;

/// Services we advertise once store-backed reconstruct serve is available.
pub fn local_service_flags() -> ServiceFlags {
    crate::seeds::required_seed_services()
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
) -> Result<(VersionMessage, V2Reader, V2Writer, crate::v2::WireBytes), NetError> {
    let (mut reader, mut writer, wire) = open_v2(stream, magic, inbound).await?;
    let their_version = application_handshake(
        &mut reader,
        &mut writer,
        magic,
        our_addr,
        their_addr,
        start_height,
        inbound,
        user_agent,
    )
    .await?;
    Ok((their_version, reader, writer, wire))
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
    let (mut reader, mut writer, _wire) = open_v2(stream, magic, false).await?;
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
) -> Result<VersionMessage, NetError> {
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
        relay: true,
    };

    if !inbound {
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
        write_v2_msg(writer, NetworkMessage::Version(version)).await?;
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
    let fee_sat = hub
        .mempool()
        .map(|m| m.min_relay_sat_kvb())
        .unwrap_or(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB);
    let _ = write_v2_msg(&mut writer, NetworkMessage::FeeFilter(fee_sat as i64)).await;

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<NetworkMessage>();
    if let Some(s) = meta.session.as_ref() {
        s.attach_out(out_tx.clone());
    }

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_v2_msg_offload(&mut writer, msg).await.is_err() {
                break;
            }
        }
    });

    if let Some(s) = meta.session.as_ref() {
        let _ = maybe_queue_initial_getheaders(&out_tx, hub.as_ref(), s);
    } else if let Err(e) = queue_getheaders(&out_tx, hub.as_ref(), None, true) {
        rbitcoin_log::warn!("p2p: {peer_s} initial getheaders queue failed: {e}");
    }

    let mut peer_wants_headers = false;
    let mut peer_wtxid_relay = false;
    let mut peer_send_cmpct = false;
    // 0 until the peer sends `sendcmpct` v2. Defaulting to 2 made every
    // relay peer getdata CMPCT and broke tests that only serve `msg_block`.
    let mut peer_cmpct_version: u32 = 0;
    let mut pending_headers: HashMap<BlockHash, bitcoin::block::Header> = HashMap::new();
    let mut pending_blocks: HashMap<BlockHash, bitcoin::Block> = HashMap::new();
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
                _ = tokio::time::sleep(Duration::from_millis(50)), if session.is_some() => {
                    if tx_announce_rx.is_none() {
                        tx_announce_rx = hub.mempool().map(|m| m.subscribe_announces());
                    }
                    if inv_flush_rx.is_none() {
                        inv_flush_rx = hub.mempool().map(|m| m.subscribe_inv_flush());
                    }
                    if let Some(s) = session.as_ref() {
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
                    match tip {
                        Ok(ev) => {
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
                            if peer_send_cmpct && !from_peer {
                                if let Some(msg) = cmpct_announce_msg(
                                    hub.as_ref(),
                                    &ev.hash,
                                    peer_cmpct_version,
                                ) {
                                    if let Some(s) = session.as_ref() {
                                        s.note_best_header_sent(ev.hash);
                                    }
                                    queue_out(&out_tx, msg)?;
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
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                }
                _ = headers_poll.tick() => {
                    let _ = queue_getheaders(&out_tx, hub.as_ref(), session.as_deref(), false);
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
                                        && mp.contains(&txid)
                                        && (mp.relay_enabled() || mp.is_unbroadcast(&txid))
                                    {
                                        let inv = if let Some(tx) = mp.get_tx(&txid) {
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
                        Err(NetError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Ok(());
                        }
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
    writer_task.abort();
    let _ = writer_task.await;
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

/// Start Core initial headers-sync on this session if we are allowed to.
fn maybe_queue_initial_getheaders(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
) -> bool {
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
        let _ = queue_getheaders(out, hub, Some(session), true);
    }
    started
}

fn queue_getheaders(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    mark_awaiting: bool,
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
    let locator = tip_follow_locator(hub);
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

/// Snapshot live mempool txs for short-id fill (owned so map can borrow them).
fn mempool_live_txs(hub: &ChainHub) -> Vec<Transaction> {
    hub.mempool()
        .map(|mp| mp.list_live().into_iter().map(|(_, _, _, tx)| tx).collect())
        .unwrap_or_default()
}

/// Reconstruct a compact block fully from mempool short-ids (version 1/2).
fn try_fill_cmpct(hub: &ChainHub, hsi: &HeaderAndShortIds, version: u32) -> Option<Block> {
    if hub.mempool().is_none() {
        return None;
    }
    let live = mempool_live_txs(hub);
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
    let live = mempool_live_txs(hub);
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
    let mut n = 0u32;
    let mut max_ann = session.last_inv_sequence();
    for (txid, w) in mp.list_live_wtxids() {
        if from_this_peer.contains_key(&txid) {
            continue;
        }
        if session.conn_type == crate::peers::PeerConnType::BlockRelay {
            continue;
        }
        if !mp.relay_enabled() && !mp.is_unbroadcast(&txid) {
            continue;
        }
        if session.has_announced_wtx(&w) {
            continue;
        }
        let local = !mp.relay_enabled() && mp.is_unbroadcast(&txid);
        let age_due_this = mp.tx_inv_due(&w);
        // Inbound + relay on: a mocktime jump / request_tx_inv only
        // flushes txs whose own 30s clock has elapsed. clock_due must
        // not INV a brand-new sendraw (`mempool_reorg.py:122`).
        let inbound_age_gate =
            session.inbound && mp.relay_enabled() && !session.hub().is_some_and(|h| h.is_noban());
        if inbound_age_gate {
            if !age_due_this {
                continue;
            }
        } else if !clock_due && !local && !age_due_this {
            continue;
        }
        session.note_announced_wtx(w);
        let _ = queue_out(out_tx, NetworkMessage::Inv(vec![Inventory::WTx(w)]));
        n += 1;
        if let Some(seq) = mp.relay_seq_of(&w) {
            max_ann = max_ann.max(seq.saturating_add(1));
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
    let live = mempool_live_txs(hub);
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
    pending_blocks: &mut HashMap<BlockHash, bitcoin::Block>,
    pending_cmpct: &mut HashMap<BlockHash, PendingCmpct>,
    from_this_peer: &mut HashMap<bitcoin::Txid, ()>,
    requested_blocks: &mut HashSet<BlockHash>,
    ban_score: &mut u32,
    session: Option<&crate::peers::LivePeer>,
) -> Result<(), NetError> {
    let msg = decode_framed_offload(frame).await?;
    match msg.payload() {
        NetworkMessage::Version(_) => {
            if let Some(s) = session {
                rbitcoin_log::info!("redundant version message from peer={}", s.id);
            } else {
                rbitcoin_log::info!("redundant version message from peer");
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
        NetworkMessage::AddrV2(_) => {
            // BIP155 payload. Invalid encodings are rejected at decode; stay
            // connected on a well-formed (including empty-list) message.
        }
        NetworkMessage::GetHeaders(gh) => {
            let headers = headers_reply_for_getheaders(hub, gh)?;
            if let Some(s) = session {
                if let Some(last) = headers.last() {
                    s.note_best_header_sent(last.block_hash());
                } else if let Some(tip) = hub.tip_hash() {
                    s.note_best_header_sent(tip);
                }
            }
            queue_out(out_tx, NetworkMessage::Headers(headers))?;
        }
        NetworkMessage::GetBlocks(gb) => {
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
            for item in inv.iter().take(MAX_INV_SIZE) {
                match item {
                    Inventory::Block(h) | Inventory::WitnessBlock(h) => {
                        if let Some(block) =
                            block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), h)?
                        {
                            queue_out(out_tx, NetworkMessage::Block(block))?;
                        }
                    }
                    Inventory::CompactBlock(h) => {
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
                                queue_out(out_tx, NetworkMessage::Block(block))?;
                            } else {
                                let ver = (*peer_cmpct_version).max(1).min(2);
                                if let Ok(hsi) =
                                    HeaderAndShortIds::from_block(&block, rand_nonce(), ver, &[0])
                                {
                                    queue_out(
                                        out_tx,
                                        NetworkMessage::CmpctBlock(CmpctBlock {
                                            compact_block: hsi,
                                        }),
                                    )?;
                                }
                            }
                        }
                    }
                    Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                        if let Some(mp) = hub.mempool() {
                            if let Some(tx) = mp.get_tx(txid) {
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
                            if let Some(tx) = mp.get_tx_by_wtxid(wtxid) {
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
            let relay = hub.mempool().map(|m| m.relay_enabled()).unwrap_or(false)
                || session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_relay_perm()));
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
                                if !mp.contains(txid) {
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
                                if !mp.contains_wtxid(wtxid) {
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
                let _ = queue_getheaders(out_tx, hub, session, true);
            }
            if !want.is_empty() {
                queue_out(out_tx, NetworkMessage::GetData(want))?;
            }
        }
        NetworkMessage::Headers(headers) => {
            let n = headers.len().min(MAX_HEADERS_RESULTS);
            let headers_reply = session.is_some_and(|s| s.take_awaiting_headers());
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
                    let _ = queue_getheaders(out_tx, hub, session, true);
                } else {
                    let last = headers[n - 1].block_hash();
                    // Core `chain_start.nHeight + headers.size()`. One-header
                    // tip announces still accumulate via `pending_headers`
                    // (`p2p_headers_sync_with_minchainwork` height=14).
                    let announced_h = announced_headers_height(hub, pending_headers, last);
                    let noban = session.is_some_and(|s| s.hub().is_some_and(|ph| ph.is_noban()));
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
                        let mut want = Vec::new();
                        if header_path_meets_minwork(hub, pending_headers, last) {
                            want = missing_blocks_on_header_path(
                                hub,
                                pending_headers,
                                last,
                                pending_blocks,
                                requested_blocks,
                            );
                            match header_branch_vs_tip(hub, pending_headers, last) {
                                Some(std::cmp::Ordering::Less) => want.clear(),
                                // BIP130 cap is for unsolicited announcements only.
                                // A getheaders reply (rejoin / catch-up) must fetch
                                // the whole offered path.
                                Some(std::cmp::Ordering::Equal) if !headers_reply => {
                                    let room = 16usize.saturating_sub(requested_blocks.len());
                                    want.truncate(room);
                                }
                                Some(std::cmp::Ordering::Greater) if !headers_reply => {
                                    let side = header_path_join(hub, pending_headers, last)
                                        .is_some_and(|h| hub.tip_hash() != Some(h));
                                    if side {
                                        let room = 16usize.saturating_sub(requested_blocks.len());
                                        want.truncate(room);
                                    }
                                }
                                _ => {}
                            }
                        }
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
                let _ = queue_getheaders(out_tx, hub, session, true);
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
            match hub.accept_received_block(block.clone()) {
                Ok(AcceptOutcome::Accepted { .. }) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    maybe_select_hb_if_relay(hub, session);
                    drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
                }
                Ok(AcceptOutcome::AlreadyHave) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
                }
                Ok(AcceptOutcome::IgnoredWeaker) => {
                    pending_blocks.remove(&hash);
                    pending_headers.remove(&hash);
                    drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
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
                let _ = queue_getheaders(out_tx, hub, session, true);
            }
            pending_headers.entry(hash).or_insert(hsi.header);
            if !any_header_path_meets_minwork(hub, pending_headers, hash) {
                // Below -minimumchainwork: keep header, do not reconstruct/accept.
            } else {
                let ancestors: Vec<BlockHash> = missing_blocks_on_header_path(
                    hub,
                    pending_headers,
                    hash,
                    pending_blocks,
                    requested_blocks,
                )
                .into_iter()
                .filter(|h| *h != hash)
                .collect();
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
                        let _ = queue_getheaders(out_tx, hub, session, false);
                    }
                } else if hub.has_block(&hash) {
                } else if let Some(block) = try_fill_cmpct(hub, &hsi, 2) {
                    let accepted = matches!(
                        hub.accept_received_block(block),
                        Ok(AcceptOutcome::Accepted { .. })
                    );
                    if accepted {
                        maybe_select_hb_if_relay(hub, session);
                    } else if !hub.knows_header(&hsi.header.prev_blockhash) {
                        // Filled a better-work compact whose parent bodies
                        // we lack (`mempool_reorg` 20-block submitblock).
                        let _ = queue_getheaders(out_tx, hub, session, true);
                    }
                    drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
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
                    Ok(block) => match hub.accept_received_block(block) {
                        Ok(AcceptOutcome::Accepted { .. }) => {
                            maybe_select_hb_if_relay(hub, session);
                            if let Some(s) = session {
                                if let Some(ph) = s.hub() {
                                    ph.clear_cmpct_fill(hash);
                                }
                            }
                            drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
                        }
                        Ok(_) => {
                            drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
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
                    },
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
                    from_this_peer.insert(txid, ());
                    match mp.accept_tx(tx) {
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
                        Err(rbitcoin_mempool::AcceptError::Orphaned(_)) => {}
                        Err(rbitcoin_mempool::AcceptError::Policy("mempool full")) => {}
                        Err(e) => {
                            rbitcoin_log::debug!("txrelay: reject {txid}: {e}");
                        }
                    }
                }
            }
        }
        // Core `-peerbloomfilters=0`: disconnect mempool/filter* peers
        // (`p2p_nobloomfilter_messages.py`). Default is on — do not disconnect.
        NetworkMessage::MemPool
        | NetworkMessage::FilterLoad(_)
        | NetworkMessage::FilterAdd(_)
        | NetworkMessage::FilterClear => {
            if !hub.peer_bloom_filters() {
                punish_disconnect(ban_score, session);
                return Ok(());
            }
        }
        NetworkMessage::GetAddr => {
            queue_out(out_tx, NetworkMessage::Addr(vec![]))?;
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

/// BIP152 compact tip announcement (coinbase prefilled). `None` if the body
/// is not in cache/store yet.
fn cmpct_announce_msg(
    hub: &ChainHub,
    hash: &BlockHash,
    cmpct_version: u32,
) -> Option<NetworkMessage> {
    let block = block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), hash).ok()??;
    let nonce = rand_nonce();
    let hsi =
        HeaderAndShortIds::from_block(&block, nonce, cmpct_version.max(1).min(2), &[0]).ok()?;
    Some(NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: hsi,
    }))
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
    if tip.to_byte_array() == [0u8; 32] {
        return 0;
    }
    if let Some(h) = hub.header_height(&tip) {
        return h;
    }
    let mut steps = 0u32;
    let mut h = tip;
    for _ in 0..10_000 {
        if h.to_byte_array() == [0u8; 32] {
            return steps;
        }
        if let Some(known) = hub.header_height(&h) {
            return known.saturating_add(steps);
        }
        let Some(hdr) = pending.get(&h) else {
            return steps;
        };
        steps = steps.saturating_add(1);
        h = hdr.prev_blockhash;
    }
    steps
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
        if hub
            .query
            .get_header_by_hash(h.as_byte_array())
            .ok()
            .flatten()
            .is_some()
        {
            break;
        }
        let Some(hdr) = pending.get(&h) else {
            break;
        };
        path.push(*hdr);
        h = hdr.prev_blockhash;
        if h.to_byte_array() == [0u8; 32] {
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
    if prev.to_byte_array() == [0u8; 32] || hub.knows_header(&prev) {
        return true;
    }
    let mut h = prev;
    for _ in 0..10_000 {
        if hub.knows_header(&h) {
            return true;
        }
        let next = pending
            .get(&h)
            .map(|hdr| hdr.prev_blockhash)
            .or_else(|| hub.prev_of(&h));
        let Some(next) = next else {
            return false;
        };
        h = next;
        if h.to_byte_array() == [0u8; 32] {
            return true;
        }
    }
    false
}

fn header_path_join(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> Option<BlockHash> {
    let mut h = start;
    for _ in 0..10_000 {
        if hub.is_connected(&h) {
            return Some(h);
        }
        let hdr = pending.get(&h)?;
        h = hdr.prev_blockhash;
        if h.to_byte_array() == [0u8; 32] {
            return None;
        }
    }
    None
}

/// Compare announced header-chain length (equal-bits ≈ work) to our path
/// from the same ancestor. `None` if the header walk does not reach our chain.
fn header_branch_vs_tip(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    start: BlockHash,
) -> Option<std::cmp::Ordering> {
    let mut n_new = 0u32;
    let mut h = start;
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
        let hdr = pending.get(&h)?;
        n_new = n_new.saturating_add(1);
        h = hdr.prev_blockhash;
        if h.to_byte_array() == [0u8; 32] {
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

/// Bodies on `tip`'s header path that we have not connected, stashed, or asked for.
fn missing_blocks_on_header_path(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    tip: BlockHash,
    pending_blocks: &HashMap<BlockHash, bitcoin::Block>,
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

fn queue_out(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    out.send(msg)
        .map_err(|_| NetError::Protocol("peer write half closed"))
}

/// Try to accept pending blocks that connect to tip or form a better branch.
fn drain_pending(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<NetworkMessage>,
    pending_blocks: &mut HashMap<BlockHash, bitcoin::Block>,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
) -> Result<(), NetError> {
    // A reorg can make a held block the child of the *new* tip after the
    // greedy pass already ran. Repeat until the tip is stable.
    loop {
        let tip_before = hub.tip_hash();
        drain_pending_once(hub, pending_blocks, pending_headers)?;
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
    if !missing.is_empty() {
        missing.truncate(MAX_PENDING_BLOCKS);
        let want: Vec<Inventory> = missing.into_iter().map(Inventory::WitnessBlock).collect();
        queue_out(out, NetworkMessage::GetData(want))?;
    }
    Ok(())
}

/// Feed complete pending bodies into the hub receive path. Pending is a
/// download window, not a second most-work assembler.
fn drain_pending_once(
    hub: &ChainHub,
    pending_blocks: &mut HashMap<BlockHash, bitcoin::Block>,
    pending_headers: &mut HashMap<BlockHash, bitcoin::block::Header>,
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
            match hub.accept_received_block(block) {
                Ok(AcceptOutcome::Accepted { .. })
                | Ok(AcceptOutcome::AlreadyHave)
                | Ok(AcceptOutcome::IgnoredWeaker) => {
                    progress = true;
                }
                // Invalid or unconnectable body: reject the block, keep the
                // peer. BIP-152 high-bandwidth (and getdata we solicited) can
                // deliver PoW-valid-but-invalid blocks from honest Core peers
                // that have not validated yet — never disconnect or ban-score
                // for that (docs/external_findings/001-disconnect-on-invalid-block.md).
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
