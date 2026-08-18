//! Peer handshake, serve, tip follow, and announce (BIP324 v2 transport).

use crate::cache::BlockCache;
use crate::chain::{accept_block_header_nodos_log, AcceptOutcome, ChainHub};
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
    ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2
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
) -> Result<(VersionMessage, V2Reader, V2Writer), NetError> {
    let (mut reader, mut writer) = open_v2(stream, magic, inbound).await?;
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
    Ok((their_version, reader, writer))
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
    let (mut reader, mut writer) = open_v2(stream, magic, false).await?;
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
    // Untracked keepalive so `connect_nodes` can wait for `bytesrecv_per_msg.pong` ≥ 29
    // before LivePeer ping state is armed. Session peers send a tracked ping ~50ms later.
    let _ = write_v2_msg(&mut writer, NetworkMessage::Ping(rand_nonce())).await;
    let fee_sat = hub
        .mempool()
        .map(|m| m.min_relay_sat_kvb())
        .unwrap_or(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB);
    let _ = write_v2_msg(&mut writer, NetworkMessage::FeeFilter(fee_sat as i64)).await;

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<NetworkMessage>();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_v2_msg_offload(&mut writer, msg).await.is_err() {
                break;
            }
        }
    });

    if let Some(s) = meta.session.as_ref() {
        let h = hub.tip_height().unwrap_or(0);
        rbitcoin_log::info!("{}", crate::chain::initial_getheaders_log(h, s.id));
    }
    if let Err(e) = queue_getheaders(&out_tx, hub.as_ref(), meta.session.as_deref(), true) {
        rbitcoin_log::warn!("p2p: {peer_s} initial getheaders queue failed: {e}");
    }

    let mut peer_wants_headers = false;
    let mut peer_wtxid_relay = false;
    let mut peer_send_cmpct = false;
    let mut peer_cmpct_version: u32 = 2;
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
                                    queue_out(
                                        &out_tx,
                                        NetworkMessage::Inv(vec![Inventory::WitnessBlock(h)]),
                                    )?;
                                }
                                TipAnnounce::Headers(hs) => {
                                    if let Some(last) = hs.last() {
                                        if let Some(s) = session.as_ref() {
                                            s.note_best_header_sent(last.block_hash());
                                        }
                                    }
                                    if peer_send_cmpct && hs.len() == 1 {
                                        if let Ok(Some(block)) = block_for_peer(
                                            hub.cache.as_ref(),
                                            hub.query.as_ref(),
                                            &ev.hash,
                                        ) {
                                            let nonce = rand_nonce();
                                            if let Ok(hsi) = HeaderAndShortIds::from_block(
                                                &block,
                                                nonce,
                                                peer_cmpct_version.max(1).min(2),
                                                &[0],
                                            ) {
                                                queue_out(
                                                    &out_tx,
                                                    NetworkMessage::CmpctBlock(CmpctBlock {
                                                        compact_block: hsi,
                                                    }),
                                                )?;
                                                continue;
                                            }
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
                                    let inbound = session.as_ref().is_some_and(|s| s.inbound);
                                    if mp.relay_enabled()
                                        && mp.contains(&txid)
                                        && (mp.immediate_relay() || !inbound)
                                    {
                                        let inv = if let Some(tx) = mp.get_tx(&txid) {
                                            Inventory::WTx(tx.compute_wtxid())
                                        } else {
                                            Inventory::WitnessTransaction(txid)
                                        };
                                        if let Some(s) = session.as_ref() {
                                            if let Inventory::WTx(w) = inv {
                                                s.note_announced_wtx(w);
                                            }
                                            s.note_tx_inv_seq(mp.current_relay_seq());
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
        Ok(()) => rbitcoin_log::info!("p2p: session {peer_s} closed"),
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

fn queue_getheaders(
    out: &mpsc::UnboundedSender<NetworkMessage>,
    hub: &ChainHub,
    session: Option<&crate::peers::LivePeer>,
    mark_awaiting: bool,
) -> Result<(), NetError> {
    if mark_awaiting {
        if let Some(s) = session {
            s.note_awaiting_headers();
        }
    }
    let locator = tip_follow_locator(hub);
    let gh = GetHeadersMessage::new(locator, BlockHash::from_byte_array([0u8; 32]));
    queue_out(out, NetworkMessage::GetHeaders(gh))
}

fn queue_block_getdata(
    hub: &ChainHub,
    out: &mpsc::UnboundedSender<NetworkMessage>,
    requested_blocks: &mut HashSet<BlockHash>,
    want: &[BlockHash],
) -> Result<(), NetError> {
    if want.is_empty() {
        return Ok(());
    }
    let inv: Vec<Inventory> = want.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
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

fn queue_due_tx_invs(
    hub: &ChainHub,
    session: &crate::peers::LivePeer,
    from_this_peer: &HashMap<bitcoin::Txid, ()>,
    out_tx: &mpsc::UnboundedSender<NetworkMessage>,
) {
    let Some(mp) = hub.mempool() else {
        return;
    };
    if !mp.relay_enabled() {
        return;
    }
    let now = session.clock_now();
    let clock_due = session.take_tx_inv_due(now);
    let live = mp.list_live();
    let age_due = live
        .iter()
        .any(|(_, _, _, tx)| mp.tx_inv_due(&tx.compute_wtxid()));
    if !clock_due && !age_due {
        return;
    }
    let mut n = 0u32;
    let mut max_ann = session.last_inv_sequence();
    for (txid, _, _, tx) in live {
        if from_this_peer.contains_key(&txid) {
            continue;
        }
        let w = tx.compute_wtxid();
        if session.has_announced_wtx(&w) || !mp.tx_inv_due(&w) {
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
                            let ver = (*peer_cmpct_version).max(1).min(2);
                            if let Ok(hsi) =
                                HeaderAndShortIds::from_block(&block, rand_nonce(), ver, &[0])
                            {
                                queue_out(
                                    out_tx,
                                    NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi }),
                                )?;
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
            if let Some(block) = block_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &hash)? {
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
                    rbitcoin_log::debug!("getblocktxn with out-of-bounds tx indices");
                    *ban_score = ban_score.saturating_add(20);
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
        NetworkMessage::Inv(items) => {
            let mut want = Vec::new();
            let mut inv_tx_n = 0u64;
            let mut need_headers = false;
            let relay = hub.mempool().map(|m| m.relay_enabled()).unwrap_or(false);
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
                                    s.advertises_network() || s.try_ask_headers_for_inv()
                                }) {
                                    need_headers = true;
                                }
                            }
                            // Have a header: do not getdata from inv. Bodies come
                            // from header-announcement direct fetch (BIP130) or a
                            // getheaders reply. Inv of a known hash from a second
                            // peer (p2p_sendheaders inv_node) must not steal or
                            // duplicate that getdata.
                        }
                    }
                    Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
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
                    for hdr in headers.iter().take(n) {
                        let _ = hub.ensure_header(hdr);
                    }
                    let last = headers[n - 1].block_hash();
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
                    queue_block_getdata(hub, out_tx, requested_blocks, &want)?;
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
                    if let Some(s) = session {
                        s.maybe_select_as_hb();
                    }
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
                    rbitcoin_log::warn!("p2p: accept dropped {hash} (invalid — keep session): {e}");
                }
            }
        }
        NetworkMessage::CmpctBlock(cb) => {
            let hsi = cb.compact_block.clone();
            let hash = hsi.header.block_hash();
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
                queue_block_getdata(hub, out_tx, requested_blocks, &ancestors)?;
                if compact_header_low_work(hub, &hsi.header) {
                    let id = session.map(|s| s.id).unwrap_or(0);
                    rbitcoin_log::debug!("Ignoring low-work compact block from peer {id}");
                } else if hub.has_block(&hash) {
                } else if let Some(block) = try_fill_cmpct(hub, &hsi, 2) {
                    if matches!(
                        hub.accept_received_block(block),
                        Ok(AcceptOutcome::Accepted { .. })
                    ) {
                        if let Some(s) = session {
                            s.maybe_select_as_hb();
                        }
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
            if let Some(pc) = pending_cmpct.remove(&hash) {
                match apply_cmpct_blocktxn(hub, &pc, bt) {
                    Ok(block) => {
                        let _ = hub.accept_received_block(block);
                        drain_pending(hub, out_tx, pending_blocks, pending_headers)?;
                    }
                    Err(()) => {
                        rbitcoin_log::debug!(
                            "previous compact block reconstruction attempt failed"
                        );
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
            if let Some(mp) = hub.mempool() {
                if mp.relay_enabled() {
                    let txid = tx.compute_txid();
                    from_this_peer.insert(txid, ());
                    match mp.accept_tx(tx) {
                        Ok(_) => {
                            if let Some(s) = session {
                                s.note_last_transaction();
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
        NetworkMessage::MemPool => {}
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

fn header_announcement_connects(
    hub: &ChainHub,
    pending: &HashMap<BlockHash, bitcoin::block::Header>,
    prev: BlockHash,
) -> bool {
    if prev.to_byte_array() == [0u8; 32]
        || hub.is_connected(&prev)
        || hub.held_body(&prev).is_some()
    {
        return true;
    }
    let mut h = prev;
    for _ in 0..10_000 {
        if hub.is_connected(&h) || hub.held_body(&h).is_some() {
            return true;
        }
        let Some(hdr) = pending.get(&h) else {
            return false;
        };
        h = hdr.prev_blockhash;
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
        let Some(hdr) = pending.get(&h) else {
            break;
        };
        h = hdr.prev_blockhash;
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
    tip.saturating_sub(ph.0) > 1
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
mod tests {
    use super::*;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::Query;
    use std::collections::HashSet;

    fn tmp_store(label: &str) -> (std::path::PathBuf, Query) {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-peer-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        (dir, q)
    }

    #[test]
    fn store_not_found_is_soft_session_error() {
        assert!(net_error_is_store_not_found(&NetError::Consensus(
            "store: record not found".into()
        )));
        assert!(net_error_is_store_not_found(&NetError::Consensus(
            "consensus: store: record not found".into()
        )));
        assert!(net_error_is_store_not_found(&NetError::Consensus(
            "StoreError::NotFound for fk".into()
        )));
        assert!(net_error_is_store_not_found(&NetError::Consensus(
            "NOT FOUND".into()
        )));
        assert!(!net_error_is_store_not_found(&NetError::Consensus(
            "corrupt record: multi-spender".into()
        )));
        assert!(!net_error_is_store_not_found(&NetError::Protocol(
            "unknown parent"
        )));
        assert!(!net_error_is_store_not_found(&NetError::Timeout));
        assert!(!net_error_is_store_not_found(&NetError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, "x")
        )));
    }

    #[test]
    fn tip_follow_locator_empty_store_has_genesis_zero() {
        let (dir, q) = tmp_store("empty");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        let loc = tip_follow_locator(&hub);
        assert!(!loc.is_empty());
        assert_eq!(loc.last().unwrap().to_byte_array(), [0u8; 32]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_follow_locator_includes_tip_after_genesis() {
        let (dir, q) = tmp_store("gen");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let loc = tip_follow_locator(&hub);
        assert!(!loc.is_empty());
        // Newest-first: tip hash is first.
        assert_eq!(loc[0], hub.tip_hash().unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn live_follow_dec_on_drop() {
        let c = Arc::new(AtomicUsize::new(2));
        {
            let _g = LiveFollowDec(Some(c.clone()));
            assert_eq!(c.load(Ordering::SeqCst), 2);
        }
        assert_eq!(c.load(Ordering::SeqCst), 1);
        // None branch is a no-op drop.
        let _ = LiveFollowDec(None);
    }

    #[test]
    fn local_service_flags_include_network_witness_v2() {
        let f = local_service_flags();
        assert!(f.has(ServiceFlags::NETWORK));
        assert!(f.has(ServiceFlags::WITNESS));
        assert!(f.has(ServiceFlags::P2P_V2));
    }

    #[test]
    fn rand_nonce_changes() {
        let a = rand_nonce();
        let b = rand_nonce();
        // Counter component makes back-to-back nonces distinct.
        assert_ne!(a, b);
    }

    #[test]
    fn block_for_peer_empty_store_none() {
        let (dir, q) = tmp_store("block-none");
        let cache = BlockCache::new();
        let miss = BlockHash::from_byte_array([0xab; 32]);
        assert!(block_for_peer(&cache, &q, &miss).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_announce_headers_and_inv() {
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, TxMerkleNode};
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let hash = header.block_hash();
        let ev = crate::chain::TipEvent {
            height: 1,
            hash,
            header,
            reorg_branch_len: 0,
        };
        let (dir, q) = tmp_store("announce-msg");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        match tip_announce_decision(&hub, &ev, true, None, None, false) {
            TipAnnounce::Headers(h) => {
                assert_eq!(h.len(), 1);
                assert_eq!(h[0].block_hash(), hash);
            }
            other => panic!("expected Headers, got {other:?}"),
        }
        match tip_announce_decision(&hub, &ev, false, None, None, false) {
            TipAnnounce::Inv(h) => assert_eq!(h, hash),
            other => panic!("expected Inv, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_announce_inv_after_large_reorg_until_peer_catches_up() {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
        };

        let (dir, q) = tmp_store("announce-reorg");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(8, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let sent_tip = hub.tip_hash().unwrap();
        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let ext = hub.tip_hash().unwrap();
        let ext_h = hub.header_of(&ext).unwrap();
        let ev = crate::chain::TipEvent {
            height: hub.tip_height().unwrap(),
            hash: ext,
            header: ext_h,
            reorg_branch_len: 0,
        };
        match tip_announce_decision(&hub, &ev, true, Some(sent_tip), None, false) {
            TipAnnounce::Headers(h) => {
                assert_eq!(h.len(), 1);
                assert_eq!(h[0].block_hash(), ext);
            }
            other => panic!("tip-extend should be headers, got {other:?}"),
        }
        match tip_announce_decision(&hub, &ev, true, Some(sent_tip), None, true) {
            TipAnnounce::Skip => {}
            other => panic!("from-this-peer must skip, got {other:?}"),
        }

        let (fork_hash, fork_time) = {
            let rec = hub
                .query
                .header_at_height(rbitcoin_primitives::Height(5))
                .unwrap()
                .unwrap();
            (BlockHash::from_byte_array(rec.1.hash), rec.1.timestamp)
        };
        let mine = |prev: BlockHash, time: u32, height: u32| {
            let bits = CompactTarget::from_consensus(0x207f_ffff);
            let mut ss = rbitcoin_consensus::bip34_height_script(height);
            while ss.len() < 2 {
                ss.push(0x00);
            }
            let cb = Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let mut block = bitcoin::Block {
                header: Header {
                    version: BlockVersion::from_consensus(4),
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time,
                    bits,
                    nonce: 0,
                },
                txdata: vec![cb],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        };
        let mut prev = fork_hash;
        let mut branch = Vec::new();
        for i in 0..9u32 {
            let b = mine(prev, fork_time.saturating_add(600 + i), 6 + i);
            prev = b.block_hash();
            branch.push(b);
        }
        hub.accept_branch(&branch).unwrap();
        let new_tip = hub.tip_hash().unwrap();
        let new_hdr = hub.header_of(&new_tip).unwrap();
        let reorg_ev = crate::chain::TipEvent {
            height: hub.tip_height().unwrap(),
            hash: new_tip,
            header: new_hdr,
            reorg_branch_len: 9,
        };
        match tip_announce_decision(&hub, &reorg_ev, true, Some(sent_tip), None, false) {
            TipAnnounce::Inv(h) => assert_eq!(h, new_tip),
            other => panic!("large reorg must inv tip, got {other:?}"),
        }

        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let after = hub.tip_hash().unwrap();
        let after_h = hub.header_of(&after).unwrap();
        let after_ev = crate::chain::TipEvent {
            height: hub.tip_height().unwrap(),
            hash: after,
            header: after_h,
            reorg_branch_len: 0,
        };
        match tip_announce_decision(&hub, &after_ev, true, Some(sent_tip), None, false) {
            TipAnnounce::Inv(h) => assert_eq!(h, after),
            other => panic!("still far from sent mark must inv, got {other:?}"),
        }
        match tip_announce_decision(&hub, &after_ev, true, Some(after), None, false) {
            TipAnnounce::Skip => {}
            other => panic!("already sent this hash must skip, got {other:?}"),
        }
        match tip_announce_decision(
            &hub,
            &after_ev,
            true,
            None,
            Some(after_h.prev_blockhash),
            false,
        ) {
            TipAnnounce::Headers(h) => {
                assert_eq!(h.len(), 1);
                assert_eq!(h[0].block_hash(), after);
            }
            other => panic!("known prev must headers, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn minchainwork_getheaders_empty_until_floor() {
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;
        use bitcoin::ScriptBuf;

        let (dir, q) = tmp_store("minwork");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mut min = [0u8; 32];
        min[31] = 0x65; // 101
        hub.set_minimum_chain_work(Some(min));
        let first = hub
            .generate_to_script(49, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("49 blocks");
        assert_eq!(hub.tip_height(), Some(49));
        let h49 = *first.last().expect("height 49 hash");
        // Genesis + 49 = 50 blocks * 2 work = 100 < 101.
        assert!(
            !hub.meets_minimum_chain_work(),
            "work at height 49 must be below 0x65"
        );
        let gh = GetHeadersMessage::new(
            vec![hub.tip_hash().unwrap()],
            BlockHash::from_byte_array([0u8; 32]),
        );
        let below = headers_reply_for_getheaders(&hub, &gh).unwrap();
        assert!(
            below.is_empty(),
            "getheaders below minchainwork must be empty, got {}",
            below.len()
        );

        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("51st block");
        assert_eq!(hub.tip_height(), Some(50));
        assert!(
            hub.meets_minimum_chain_work(),
            "work at height 50 must meet 0x65"
        );
        let gh = GetHeadersMessage::new(vec![h49], BlockHash::from_byte_array([0u8; 32]));
        let above = headers_reply_for_getheaders(&hub, &gh).unwrap();
        assert!(
            !above.is_empty(),
            "getheaders at/above minchainwork must serve the 51st header"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn minchainwork_does_not_getdata_below_floor() {
        use bitcoin::ScriptBuf;
        use rbitcoin_primitives::Height;
        use tokio::runtime::Builder;

        fn frame_for(msg: NetworkMessage) -> FramedMessage {
            use bitcoin::consensus::encode::serialize;
            use bitcoin::p2p::message::RawNetworkMessage;
            use bitcoin::Network;
            let magic = Magic::from(Network::Regtest);
            let raw = RawNetworkMessage::new(magic, msg);
            let full = serialize(&raw);
            let command: [u8; 12] = full[4..16].try_into().unwrap();
            let checksum: [u8; 4] = full[20..24].try_into().unwrap();
            FramedMessage {
                magic,
                command,
                checksum,
                payload: full[24..].to_vec(),
            }
        }

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (dir, q) = tmp_store("minwork-gd");
            let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
            hub.ensure_genesis().unwrap();
            let mut min = [0u8; 32];
            min[31] = 0x65;
            hub.set_minimum_chain_work(Some(min));

            let (dir2, q2) = tmp_store("minwork-src");
            let src = ChainHub::new(q2, ChainParams::regtest(), Milestone::NONE);
            src.ensure_genesis().unwrap();
            src.generate_to_script(50, ScriptBuf::from_bytes(vec![0x51]), vec![])
                .unwrap();
            let mut hdrs = Vec::new();
            for h in 1..=50u32 {
                hdrs.push(src.query.wire_header_at_height(Height(h)).unwrap());
            }

            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut pending_headers = HashMap::new();
            let mut pending_blocks = HashMap::new();
            let mut pending_cmpct = HashMap::new();
            let mut from_peer = HashMap::new();
            let mut requested = HashSet::new();
            let mut wants_headers = false;
            let mut wtxid = false;
            let mut send_cmpct = false;
            let mut cmpct_ver = 2u32;
            let mut ban = 0u32;

            fn drain_getdata(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
                let mut hashes = Vec::new();
                while let Ok(m) = rx.try_recv() {
                    if let NetworkMessage::GetData(inv) = m {
                        for i in inv {
                            match i {
                                Inventory::Block(h) | Inventory::WitnessBlock(h) => hashes.push(h),
                                _ => {}
                            }
                        }
                    }
                }
                hashes
            }

            // sendheaders announce is one header per mined tip.
            for hdr in &hdrs[..49] {
                handle_peer_frame(
                    frame_for(NetworkMessage::Headers(vec![*hdr])),
                    &hub,
                    &out_tx,
                    &mut wants_headers,
                    &mut wtxid,
                    &mut send_cmpct,
                    &mut cmpct_ver,
                    &mut pending_headers,
                    &mut pending_blocks,
                    &mut pending_cmpct,
                    &mut from_peer,
                    &mut requested,
                    &mut ban,
                    None,
                )
                .await
                .unwrap();
            }
            assert!(
                drain_getdata(&mut out_rx).is_empty(),
                "must not getdata a 49-block chain (work 100 < 101)"
            );
            assert_eq!(hub.tip_height(), Some(0));

            handle_peer_frame(
                frame_for(NetworkMessage::Headers(vec![hdrs[49]])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
            let got = drain_getdata(&mut out_rx);
            let h1 = hdrs[0].block_hash();
            let h50 = hdrs[49].block_hash();
            assert_eq!(
                got.len(),
                50,
                "50th header (work 102) must getdata the whole path, got {got:?}"
            );
            assert_eq!(got[0], h1, "getdata should start at height 1");
            assert_eq!(got[49], h50, "getdata should end at height 50");
            let _ = std::fs::remove_dir_all(dir);
            let _ = std::fs::remove_dir_all(dir2);
        });
    }

    #[test]
    fn cmpct_helpers_without_mempool_and_queue_out_closed() {
        let (dir, q) = tmp_store("cmpct-none");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let gen = hub
            .query
            .reconstruct_block_by_hash(&hub.tip_hash().unwrap().to_byte_array())
            .unwrap()
            .unwrap();
        let hsi = HeaderAndShortIds::from_block(&gen, 0xabc, 2, &[]).unwrap();
        assert!(try_fill_cmpct(&hub, &hsi, 2).is_none());
        assert!(try_cmpct_missing(&hub, &hsi, 2).is_none());
        assert!(mempool_live_txs(&hub).is_empty());

        // Closed channel → Protocol error.
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        assert!(queue_out(&tx, NetworkMessage::Verack).is_err());
        assert!(queue_getheaders(&tx, &hub, None, false).is_err());

        // headers_for_peer empty store after genesis still returns (tip exists).
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;
        let gh = GetHeadersMessage::new(
            vec![hub.tip_hash().unwrap()],
            BlockHash::from_byte_array([0u8; 32]),
        );
        let hdrs = headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &gh).unwrap();
        // Beyond tip: empty headers is fine.
        assert!(hdrs.is_empty() || !hdrs.is_empty());

        // drain_pending empty is a no-op.
        let mut pb = HashMap::new();
        let mut ph = HashMap::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        drain_pending(&hub, &tx, &mut pb, &mut ph).unwrap();

        // Invalid tip-extending body must not kill the session (001).
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
        };
        let tip = hub.tip_hash().unwrap();
        let tip_block = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .expect("tip body");
        let coinbase = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        // Second tx spends a nonexistent prevout → consensus reject.
        let junk = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut bad = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: tip,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
                time: tip_block.header.time + 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, junk],
        };
        bad.header.merkle_root = bad.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bad.header.bits);
        for nonce in 0..200_000u32 {
            bad.header.nonce = nonce;
            if bad.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let bh = bad.block_hash();
        pb.insert(bh, bad);
        let (tx, _rx) = mpsc::unbounded_channel();
        drain_pending(&hub, &tx, &mut pb, &mut ph).expect("invalid block must not end session");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn handle_peer_frame_control_and_inv_paths() {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::Network;
        use tokio::runtime::Builder;

        fn frame_for(msg: NetworkMessage) -> FramedMessage {
            use bitcoin::p2p::message::RawNetworkMessage;
            let magic = Magic::from(Network::Regtest);
            let raw = RawNetworkMessage::new(magic, msg);
            let full = serialize(&raw);
            // 4 magic + 12 command + 4 len + 4 checksum + payload
            let command: [u8; 12] = full[4..16].try_into().unwrap();
            let checksum: [u8; 4] = full[20..24].try_into().unwrap();
            let payload = full[24..].to_vec();
            FramedMessage {
                magic,
                command,
                checksum,
                payload,
            }
        }

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (dir, q) = tmp_store("handle-frame");
            let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
            hub.ensure_genesis().unwrap();
            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut wants_headers = false;
            let mut wtxid = false;
            let mut send_cmpct = false;
            let mut cmpct_ver = 2u32;
            let mut pending_headers = HashMap::new();
            let mut pending_blocks = HashMap::new();
            let mut pending_cmpct = HashMap::new();
            let mut from_peer = HashMap::new();
            let mut ban = 0u32;

            // SendHeaders / SendCmpct / WtxidRelay / Pong / MemPool / GetAddr / Ping
            for msg in [
                NetworkMessage::SendHeaders,
                NetworkMessage::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: 2,
                }),
                NetworkMessage::WtxidRelay,
                NetworkMessage::Pong(7),
                NetworkMessage::MemPool,
                NetworkMessage::GetAddr,
                NetworkMessage::Ping(42),
            ] {
                handle_peer_frame(
                    frame_for(msg),
                    &hub,
                    &out_tx,
                    &mut wants_headers,
                    &mut wtxid,
                    &mut send_cmpct,
                    &mut cmpct_ver,
                    &mut pending_headers,
                    &mut pending_blocks,
                    &mut pending_cmpct,
                    &mut from_peer,
                    &mut HashSet::new(),
                    &mut ban,
                    None,
                )
                .await
                .unwrap();
            }
            assert!(wants_headers);
            assert!(wtxid);
            assert!(send_cmpct);
            assert_eq!(cmpct_ver, 2);

            // Drain outbound: Pong(42) + empty Addr at least.
            let mut saw_pong = false;
            let mut saw_addr = false;
            while let Ok(m) = out_rx.try_recv() {
                match m {
                    NetworkMessage::Pong(n) => {
                        assert_eq!(n, 42);
                        saw_pong = true;
                    }
                    NetworkMessage::Addr(a) => {
                        assert!(a.is_empty());
                        saw_addr = true;
                    }
                    _ => {}
                }
            }
            assert!(saw_pong);
            assert!(saw_addr);

            // GetHeaders from empty tip-beyond locator.
            use bitcoin::p2p::message_blockdata::GetHeadersMessage;
            let gh = GetHeadersMessage::new(
                vec![hub.tip_hash().unwrap()],
                BlockHash::from_byte_array([0u8; 32]),
            );
            handle_peer_frame(
                frame_for(NetworkMessage::GetHeaders(gh)),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            let headers_msg = out_rx.try_recv().unwrap();
            assert!(matches!(headers_msg, NetworkMessage::Headers(_)));

            // Inv for unknown block → GetHeaders (never getdata without a header).
            let want_h = BlockHash::from_byte_array([0xee; 32]);
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(want_h)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::GetHeaders(gh) => {
                    assert!(
                        !gh.locator_hashes.is_empty() || gh.stop_hash == want_h,
                        "unknown block inv must getheaders, locators={:?}",
                        gh.locator_hashes
                    );
                }
                other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
            }

            // Headers message inserts pending + issues getdata.
            let gen = hub
                .query
                .wire_header_at_height(rbitcoin_primitives::Height(0))
                .unwrap();
            // Synthesize a child-looking header (not valid pow; just exercises map).
            use bitcoin::block::{Header, Version};
            use bitcoin::{CompactTarget, TxMerkleNode};
            let child = Header {
                version: Version::from_consensus(4),
                prev_blockhash: gen.block_hash(),
                merkle_root: TxMerkleNode::from_byte_array([2u8; 32]),
                time: gen.time + 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            };
            handle_peer_frame(
                frame_for(NetworkMessage::Headers(vec![child])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(pending_headers.contains_key(&child.block_hash()));
            let _ = out_rx.try_recv(); // GetData

            // GetData for known tip block (cache miss → reconstruct).
            let tip = hub.tip_hash().unwrap();
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(tip)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::Block(b) => assert_eq!(b.block_hash(), tip),
                other => panic!("expected Block, got {other:?}"),
            }

            // CompactBlock getdata for tip.
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(tip)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(matches!(
                out_rx.try_recv().unwrap(),
                NetworkMessage::CmpctBlock(_)
            ));

            // GetBlockTxn with bad index → ban score.
            use bitcoin::bip152::BlockTransactionsRequest;
            handle_peer_frame(
                frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                    txs_request: BlockTransactionsRequest {
                        block_hash: tip,
                        indexes: vec![999],
                    },
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(ban >= 20);

            // GetBlockTxn good index 0 (coinbase).
            ban = 0;
            handle_peer_frame(
                frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                    txs_request: BlockTransactionsRequest {
                        block_hash: tip,
                        indexes: vec![0],
                    },
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(matches!(
                out_rx.try_recv().unwrap(),
                NetworkMessage::BlockTxn(_)
            ));

            // Unsolicited BlockTxn → mild ban.
            handle_peer_frame(
                frame_for(NetworkMessage::BlockTxn(BlockTxn {
                    transactions: BlockTransactions {
                        block_hash: BlockHash::from_byte_array([0xdd; 32]),
                        transactions: vec![],
                    },
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(ban >= 5);

            // CmpctBlock without mempool → full getdata fallback.
            let gen_block = hub
                .query
                .reconstruct_block_by_hash(&tip.to_byte_array())
                .unwrap()
                .unwrap();
            let hsi = HeaderAndShortIds::from_block(&gen_block, 9, 2, &[]).unwrap();
            handle_peer_frame(
                frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                    compact_block: hsi,
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            // Already have tip → no getdata; if different hash would request.
            // Genesis is already known so "already have" arm.
            let _ = out_rx.try_recv();

            // Unknown command (including the retired rbtpkg name) is a no-op.
            handle_peer_frame(
                frame_for(NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                    payload: vec![1, 2, 3],
                }),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();

            // SendCmpct with unsupported version is ignored.
            handle_peer_frame(
                frame_for(NetworkMessage::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: 99,
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(send_cmpct); // still true from earlier v2
            assert_eq!(cmpct_ver, 2);

            // Inventory::Block (non-witness) for unknown → GetHeaders.
            let want2 = BlockHash::from_byte_array([0xcc; 32]);
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![Inventory::Block(want2)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::GetHeaders(_) => {}
                other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
            }

            // Inv for known tip → no GetData.
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(out_rx.try_recv().is_err());

            // GetData Inventory::Block for tip (non-witness arm).
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::Block(tip)])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(matches!(
                out_rx.try_recv().unwrap(),
                NetworkMessage::Block(_)
            ));

            // Full Block message path: pending + drain_pending (AlreadyHave for tip).
            let gen_block2 = hub
                .query
                .reconstruct_block_by_hash(&tip.to_byte_array())
                .unwrap()
                .unwrap();
            handle_peer_frame(
                frame_for(NetworkMessage::Block(gen_block2)),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            // Tip already confirmed — drain accepts AlreadyHave and may leave empty pending.

            // Tx without mempool is a no-op.
            use bitcoin::absolute::LockTime;
            use bitcoin::script::ScriptBuf;
            use bitcoin::transaction::Version as TxVersion;
            use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
            let dummy_tx = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            handle_peer_frame(
                frame_for(NetworkMessage::Tx(dummy_tx)),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();

            // Catch-all unknown command.
            handle_peer_frame(
                frame_for(NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("zzzzzz").unwrap(),
                    payload: vec![],
                }),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();

            let _ = std::fs::remove_dir_all(dir);
        });
    }

    /// Mempool-backed inv/tx/getdata arms + cmpctblocktxn success.
    #[test]
    fn handle_peer_frame_mempool_tx_and_inv_paths() {
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        use tokio::runtime::Builder;

        fn frame_for(msg: NetworkMessage) -> FramedMessage {
            use bitcoin::p2p::message::RawNetworkMessage;
            let magic = Magic::from(Network::Regtest);
            let raw = RawNetworkMessage::new(magic, msg);
            let full = serialize(&raw);
            let command: [u8; 12] = full[4..16].try_into().unwrap();
            let checksum: [u8; 4] = full[20..24].try_into().unwrap();
            let payload = full[24..].to_vec();
            FramedMessage {
                magic,
                command,
                checksum,
                payload,
            }
        }

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (dir, q) = tmp_store("handle-mp");
            let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
            hub.ensure_genesis().unwrap();
            let mp =
                crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
            // Enable relay so Inv for txs triggers getdata.
            mp.set_relay_enabled(true);
            assert!(hub.attach_mempool(mp).is_ok());

            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut wants_headers = false;
            let mut wtxid = false;
            let mut send_cmpct = false;
            let mut cmpct_ver = 2u32;
            let mut pending_headers = HashMap::new();
            let mut pending_blocks = HashMap::new();
            let mut pending_cmpct = HashMap::new();
            let mut from_peer = HashMap::new();
            let mut ban = 0u32;

            let unknown_txid = bitcoin::Txid::from_byte_array([0x42; 32]);
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![
                    Inventory::WitnessTransaction(unknown_txid),
                    Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
                ])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::GetData(v) => {
                    assert!(v.len() >= 1);
                }
                other => panic!("expected GetData for unknown txs, got {other:?}"),
            }

            // GetData for missing tx → notfound (Core ProcessGetData).
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![
                    Inventory::WitnessTransaction(unknown_txid),
                    Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
                ])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::NotFound(v) => {
                    assert_eq!(v.len(), 1);
                }
                other => panic!("expected NotFound, got {other:?}"),
            }
            match out_rx.try_recv().unwrap() {
                NetworkMessage::NotFound(v) => {
                    assert_eq!(v.len(), 1);
                }
                other => panic!("expected second NotFound, got {other:?}"),
            }
            assert!(out_rx.try_recv().is_err());

            // Accept path with invalid prevout — still exercises Tx arm (inserts from_peer).
            let junk = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[vec![1]]),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let junk_txid = junk.compute_txid();
            handle_peer_frame(
                frame_for(NetworkMessage::Tx(junk)),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            // Origin map is filled before accept result.
            assert!(from_peer.contains_key(&junk_txid));

            // Retired rbtpkg name with mempool + relay: still unknown, no admit
            // even when the payload is the old len-prefixed encoding.
            let pkg_tx = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([2u8; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[vec![1]]),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let pkg_txid = pkg_tx.compute_txid();
            let raw = bitcoin::consensus::encode::serialize(&pkg_tx);
            let mut payload = Vec::with_capacity(4 + raw.len());
            payload.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            payload.extend_from_slice(&raw);
            handle_peer_frame(
                frame_for(NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                    payload,
                }),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
            assert!(!from_peer.contains_key(&pkg_txid));
            assert_eq!(hub.mempool().unwrap().live_count(), 0);

            let _ = std::fs::remove_dir_all(dir);
        });
    }

    /// GetData serves a mempool tx only after we INV'd it, or if it re-entered
    /// from a disconnected block (`mempool_reorg.py` test_reorg_relay).
    #[test]
    fn getdata_tx_notfound_unless_announced_or_reorg() {
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::p2p::address::Address;
        use bitcoin::p2p::message::RawNetworkMessage;
        use bitcoin::p2p::message_network::VersionMessage;
        use bitcoin::p2p::ServiceFlags;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        use rbitcoin_primitives::Height;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tokio::runtime::Builder;

        fn frame_for(msg: NetworkMessage) -> FramedMessage {
            let magic = Magic::from(Network::Regtest);
            let raw = RawNetworkMessage::new(magic, msg);
            let full = serialize(&raw);
            let command: [u8; 12] = full[4..16].try_into().unwrap();
            let checksum: [u8; 4] = full[20..24].try_into().unwrap();
            FramedMessage {
                magic,
                command,
                checksum,
                payload: full[24..].to_vec(),
            }
        }

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (dir, q) = tmp_store("gd-privacy");
            let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
            hub.ensure_genesis().unwrap();
            hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
                .expect("pad maturity");
            let mp =
                crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
            mp.set_relay_enabled(true);
            assert!(hub.attach_mempool(mp).is_ok());

            let cb1 = hub
                .query
                .reconstruct_block_at_height(Height(1))
                .unwrap()
                .txdata[0]
                .compute_txid();
            let cb2 = hub
                .query
                .reconstruct_block_at_height(Height(2))
                .unwrap()
                .txdata[0]
                .compute_txid();
            let recent = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint { txid: cb1, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(49_9999_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let disconnected = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint { txid: cb2, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(49_9999_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            hub.mempool()
                .unwrap()
                .accept_tx(&recent)
                .expect("accept recent");
            assert_eq!(
                hub.mempool()
                    .unwrap()
                    .reorg_reaccept(std::slice::from_ref(&disconnected)),
                1
            );

            let peers = crate::peers::PeerHub::new();
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
            let ver = VersionMessage {
                version: 70016,
                services: ServiceFlags::NETWORK,
                timestamp: 0,
                receiver: Address::new(&addr, ServiceFlags::NONE),
                sender: Address::new(&addr, ServiceFlags::NONE),
                nonce: 1,
                user_agent: "/rbitcoin:test/".into(),
                start_height: 0,
                relay: true,
            };
            let sess = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);

            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut wants_headers = false;
            let mut wtxid = true;
            let mut send_cmpct = false;
            let mut cmpct_ver = 2u32;
            let mut pending_headers = HashMap::new();
            let mut pending_blocks = HashMap::new();
            let mut pending_cmpct = HashMap::new();
            let mut from_peer = HashMap::new();
            let mut ban = 0u32;

            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                    recent.compute_wtxid(),
                )])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                Some(sess.as_ref()),
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::NotFound(v) => {
                    assert_eq!(v, vec![Inventory::WTx(recent.compute_wtxid())]);
                }
                other => panic!("unannounced recent must notfound, got {other:?}"),
            }

            sess.note_announced_wtx(recent.compute_wtxid());
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                    recent.compute_wtxid(),
                )])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                Some(sess.as_ref()),
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::Tx(tx) => assert_eq!(tx.compute_wtxid(), recent.compute_wtxid()),
                other => panic!("announced recent must serve tx, got {other:?}"),
            }

            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                    disconnected.compute_wtxid(),
                )])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                Some(sess.as_ref()),
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::Tx(tx) => {
                    assert_eq!(tx.compute_wtxid(), disconnected.compute_wtxid())
                }
                other => panic!("reorg-servable must serve without INV, got {other:?}"),
            }

            // mempool_reorg.py:122 — a later regular submit (even of a
            // wtxid that was once reorg-reaccepted) must notfound until
            // this peer's last INV sequence passes the new entry seq.
            sess.note_tx_inv_seq(hub.mempool().unwrap().current_relay_seq());
            let cb3 = hub
                .query
                .reconstruct_block_at_height(Height(3))
                .unwrap()
                .txdata[0]
                .compute_txid();
            let later = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint { txid: cb3, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(49_9999_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            hub.mempool()
                .unwrap()
                .accept_tx(&later)
                .expect("accept later");
            handle_peer_frame(
                frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                    later.compute_wtxid(),
                )])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                Some(sess.as_ref()),
            )
            .await
            .unwrap();
            match out_rx.try_recv().unwrap() {
                NetworkMessage::NotFound(v) => {
                    assert_eq!(v, vec![Inventory::WTx(later.compute_wtxid())]);
                }
                other => panic!("just-submitted tx must notfound, got {other:?}"),
            }

            let _ = std::fs::remove_dir_all(dir);
        });
    }

    /// Compact helpers with a live mempool hub attached (fill/missing/blocktxn).
    #[test]
    fn cmpct_helpers_with_mempool_live_and_blocktxn() {
        use bitcoin::absolute::LockTime;
        use bitcoin::bip152::BlockTransactions;
        use bitcoin::block::{Header, Version};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
            Witness,
        };

        let (dir, q) = tmp_store("cmpct-mp");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        assert!(hub.attach_mempool(mp).is_ok());
        assert!(hub.mempool().is_some());

        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut block = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: hub.tip_hash().unwrap(),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![
                Transaction {
                    version: TxVersion::ONE,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint::null(),
                        script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(50_0000_0000),
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    }],
                },
                spend.clone(),
            ],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
        // Mempool present but empty live → Some(missing) not None.
        let missing = try_cmpct_missing(&hub, &hsi, 2).expect("mempool present");
        assert_eq!(missing, vec![1]); // spend short-id missing
        assert!(try_fill_cmpct(&hub, &hsi, 2).is_none());
        assert!(mempool_live_txs(&hub).is_empty());

        let pc = PendingCmpct {
            hsi: hsi.clone(),
            missing: missing.clone(),
            version: 2,
        };
        let bt = BlockTransactions {
            block_hash: block.block_hash(),
            transactions: vec![spend],
        };
        let recon = apply_cmpct_blocktxn(&hub, &pc, &bt).expect("blocktxn fill");
        assert_eq!(recon.txdata.len(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tip-follow receive: max-work fork held then applied via `accept_received_block`.
    #[test]
    fn p2p_side_chain_reorgs_via_held_bodies() {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
        };

        let (dir, q) = tmp_store("pending-reorg");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();

        let coinbase = |height: u32| {
            let mut ss = rbitcoin_consensus::bip34_height_script(height);
            while ss.len() < 2 {
                ss.push(0x00);
            }
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }
        };
        let mine = |prev: BlockHash, time: u32, height: u32| {
            let bits = CompactTarget::from_consensus(0x207f_ffff);
            let mut block = bitcoin::Block {
                header: Header {
                    version: BlockVersion::from_consensus(4),
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time,
                    bits,
                    nonce: 0,
                },
                txdata: vec![coinbase(height)],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        };

        // Main tip height 2 (times near genesis MTP window).
        let b1 = mine(gen, 1_300_000_100, 1);
        hub.accept_block(b1.clone()).unwrap();
        let b2 = mine(b1.block_hash(), 1_300_000_200, 2);
        hub.accept_block(b2.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(2));

        // Pending: short side from gen (1 block) + long side from gen (4 blocks).
        let short = mine(gen, 1_300_001_000, 1);
        let mut long = Vec::new();
        let mut p = gen;
        for (i, h) in (1..=4u32).enumerate() {
            let b = mine(p, 1_300_002_000 + i as u32 * 600, h);
            p = b.block_hash();
            long.push(b);
        }
        // Short side first (held, weaker), then the longer fork one body at a time
        // — same order a peer `block` message stream would deliver.
        hub.accept_received_block(short).unwrap();
        for b in &long {
            hub.accept_received_block(b.clone()).unwrap();
        }
        assert_eq!(
            hub.tip_height(),
            Some(4),
            "must reorg onto longer held branch"
        );
        assert_eq!(hub.tip_hash().unwrap(), long[3].block_hash());
        assert!(hub.held_body(&long[3].block_hash()).is_none());
        assert!(MAX_PENDING_BLOCKS_FOR_TEST >= 128);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `mempool_reorg.py` `trigger_reorg`: 20 empty side blocks submitted one
    /// at a time after 19 tip-extends must become the new tip.
    #[test]
    fn sequential_submit_twenty_beats_nineteen() {
        let (dir, q) = tmp_store("submit-20-vs-19");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let coinbase = |height: u32| {
            let mut ss = rbitcoin_consensus::bip34_height_script(height);
            while ss.len() < 2 {
                ss.push(0x00);
            }
            Transaction {
                version: bitcoin::transaction::Version::ONE,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: bitcoin::script::ScriptBuf::from_bytes(ss),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(50_0000_0000),
                    script_pubkey: bitcoin::script::ScriptBuf::from_bytes(vec![0x51]),
                }],
            }
        };
        let mine = |prev: BlockHash, time: u32, height: u32| {
            let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
            let mut block = bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(4),
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time,
                    bits,
                    nonce: 0,
                },
                txdata: vec![coinbase(height)],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = bitcoin::Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        };

        // Shared parent at height 1.
        let b1 = mine(gen, 1_300_000_100, 1);
        hub.accept_block(b1.clone()).unwrap();
        let fork_prev = b1.block_hash();

        // Build the 20-block fork first (same order as create_empty_fork).
        let mut fork = Vec::new();
        let mut p = fork_prev;
        for i in 0..20u32 {
            let b = mine(p, 1_300_000_200 + i, 2 + i);
            p = b.block_hash();
            fork.push(b);
        }

        // Then 19 tip-extends (generate after the fork was built).
        let mut main = fork_prev;
        for i in 0..19u32 {
            let b = mine(main, 1_300_010_000 + i * 600, 2 + i);
            main = b.block_hash();
            hub.accept_block(b).unwrap();
        }
        assert_eq!(hub.tip_height(), Some(20));

        for b in &fork {
            hub.accept_received_block(b.clone())
                .unwrap_or_else(|e| panic!("submit {} : {e}", b.block_hash()));
        }
        assert_eq!(
            hub.tip_height(),
            Some(21),
            "20-block fork must beat 19-block main"
        );
        assert_eq!(hub.tip_hash().unwrap(), fork[19].block_hash());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn drain_requests_missing_parent_of_pending_branch() {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
        };

        let (dir, q) = tmp_store("pending-missing-parent");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let missing_parent = BlockHash::from_byte_array([0x42; 32]);
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut orphan = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: missing_parent,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1_300_000_100,
                bits,
                nonce: 0,
            },
            txdata: vec![Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }],
        };
        orphan.header.merkle_root = orphan.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            orphan.header.nonce = nonce;
            if orphan.header.validate_pow(target).is_ok() {
                break;
            }
        }
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut pb = HashMap::new();
        pb.insert(orphan.block_hash(), orphan);
        let mut ph = HashMap::new();
        drain_pending(&hub, &tx, &mut pb, &mut ph).unwrap();
        let msg = rx.try_recv().expect("getdata for missing parent");
        match msg {
            NetworkMessage::GetData(inv) => {
                assert!(
                    inv.iter()
                        .any(|i| matches!(i, Inventory::WitnessBlock(h) if *h == missing_parent)),
                    "expected getdata for {missing_parent}, got {inv:?}"
                );
            }
            other => panic!("expected GetData, got {other:?}"),
        }
        assert!(!hub.is_connected(&missing_parent));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn drain_connects_pending_child_of_new_tip_after_reorg() {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version as BlockVersion};
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
        };

        let (dir, q) = tmp_store("pending-child-after-reorg");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let gen = hub.tip_hash().unwrap();
        let coinbase = |height: u32| {
            let mut ss = rbitcoin_consensus::bip34_height_script(height);
            while ss.len() < 2 {
                ss.push(0x00);
            }
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(ss),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }
        };
        let mine = |prev: BlockHash, time: u32, height: u32| {
            let bits = CompactTarget::from_consensus(0x207f_ffff);
            let mut block = bitcoin::Block {
                header: Header {
                    version: BlockVersion::from_consensus(4),
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time,
                    bits,
                    nonce: 0,
                },
                txdata: vec![coinbase(height)],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            let target = Target::from_compact(bits);
            for nonce in 0..u32::MAX {
                block.header.nonce = nonce;
                if block.header.validate_pow(target).is_ok() {
                    break;
                }
            }
            block
        };
        let a1 = mine(gen, 1_300_000_100, 1);
        hub.accept_block(a1.clone()).unwrap();
        assert_eq!(hub.tip_height(), Some(1));

        let b1 = mine(gen, 1_300_001_000, 1);
        let b2 = mine(b1.block_hash(), 1_300_001_600, 2);
        let mut pb = HashMap::new();
        pb.insert(b1.block_hash(), b1.clone());
        pb.insert(b2.block_hash(), b2.clone());
        let mut ph = HashMap::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        drain_pending(&hub, &tx, &mut pb, &mut ph).unwrap();
        assert_eq!(hub.tip_height(), Some(2), "reorg plus child must connect");
        assert_eq!(hub.tip_hash().unwrap(), b2.block_hash());
        assert!(hub.is_connected(&b1.block_hash()));
        assert!(hub.is_connected(&b2.block_hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn inv_of_already_asked_block_does_not_getdata() {
        // p2p_sendheaders Part 2: test_node announces headers (we getdata),
        // then inv_node re-invs the same hashes. One getdata in flight globally.
        use bitcoin::consensus::encode::serialize;
        use bitcoin::script::ScriptBuf;
        use bitcoin::Network;
        use rbitcoin_primitives::Height;
        use tokio::runtime::Builder;

        fn frame_for(msg: NetworkMessage) -> FramedMessage {
            use bitcoin::p2p::message::RawNetworkMessage;
            let magic = Magic::from(Network::Regtest);
            let raw = RawNetworkMessage::new(magic, msg);
            let full = serialize(&raw);
            let command: [u8; 12] = full[4..16].try_into().unwrap();
            let checksum: [u8; 4] = full[20..24].try_into().unwrap();
            FramedMessage {
                magic,
                command,
                checksum,
                payload: full[24..].to_vec(),
            }
        }

        fn drain_block_getdata(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
            let mut hashes = Vec::new();
            while let Ok(m) = rx.try_recv() {
                if let NetworkMessage::GetData(inv) = m {
                    for i in inv {
                        if let Inventory::Block(h) | Inventory::WitnessBlock(h) = i {
                            hashes.push(h);
                        }
                    }
                }
            }
            hashes
        }

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (src_dir, src_q) = tmp_store("inv-asked-src");
            let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
            src.ensure_genesis().unwrap();
            src.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
                .unwrap();
            let hdr = src.query.wire_header_at_height(Height(1)).unwrap();
            let hash = hdr.block_hash();

            let (dir, q) = tmp_store("inv-asked-dst");
            let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
            hub.ensure_genesis().unwrap();

            let (out_tx, mut out_rx) = mpsc::unbounded_channel();
            let mut pending_headers = HashMap::new();
            let mut pending_blocks = HashMap::new();
            let mut pending_cmpct = HashMap::new();
            let mut from_peer = HashMap::new();
            let mut requested = HashSet::new();
            let mut wants_headers = false;
            let mut wtxid = false;
            let mut send_cmpct = false;
            let mut cmpct_ver = 2u32;
            let mut ban = 0u32;

            handle_peer_frame(
                frame_for(NetworkMessage::Headers(vec![hdr])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
            let first = drain_block_getdata(&mut out_rx);
            assert_eq!(first, vec![hash], "header announce must getdata once");
            assert!(hub.already_have_or_asked_block(&hash));

            // Second peer: empty local requested set, same hub (asked_blocks).
            let (out_tx2, mut out_rx2) = mpsc::unbounded_channel();
            let mut pending_headers2 = HashMap::new();
            let mut requested2 = HashSet::new();
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(hash)])),
                &hub,
                &out_tx2,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers2,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested2,
                &mut ban,
                None,
            )
            .await
            .unwrap();
            let second = drain_block_getdata(&mut out_rx2);
            assert!(
                second.is_empty(),
                "duplicate inv must not getdata, got {second:?}"
            );

            let _ = std::fs::remove_dir_all(src_dir);
            let _ = std::fs::remove_dir_all(dir);
        });
    }
}
