//! IBD download peer: split read/write over BIP324 v2.
//!
//! Socket tasks stay **I/O-only**:
//! - reader: decrypt frame + cheap ping handling; heavy decode off-thread
//! - writer: encode offloaded for heavy payloads; then encrypt + write

use super::rate::PeerRate;
use crate::codec::MAX_INV_SIZE;
use crate::error::NetError;
use crate::msg_decode::spawn_decode_then_with_err;
use crate::peer::{
    connect_and_handshake_timed, HandshakePolicy, BAN_SCORE_THRESHOLD, HANDSHAKE_TIMEOUT,
};
use crate::peer_dos::{PeerRateLimiter, RATE_LIMIT_BAN_SCORE};
use crate::v2::{read_v2_frame_with_progress, write_v2_msg_offload};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::BlockHash;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// Block and witness-block entries from an `inv` or `notfound`.
fn block_inventory_hashes(inv: &[Inventory]) -> Vec<BlockHash> {
    inv.iter()
        .filter_map(|i| match i {
            Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(*h),
            _ => None,
        })
        .collect()
}

pub(crate) enum PeerCmd {
    GetHeaders { locator: Vec<BlockHash> },
    GetData { hashes: Vec<BlockHash> },
    Shutdown,
}

pub(crate) enum PeerEvent {
    Headers {
        peer: usize,
        headers: Vec<Header>,
    },
    /// Full `block` frame on the wire: hash from header bytes + **raw payload**.
    ///
    /// No full `Block` deserialize on the peer path — body queue stores these
    /// bytes; confirm pack decodes. Free getdata slots immediately.
    BlockFramed {
        peer: usize,
        hash: BlockHash,
        /// Consensus-serialized block (frame payload).
        payload: Vec<u8>,
    },
    /// Framed as `block` but unusable (e.g. truncated header) — re-request.
    BlockDecodeFailed {
        peer: usize,
        hash: BlockHash,
    },
    /// Peer answered `notfound` for these block hashes (does not have them).
    NotFound {
        peer: usize,
        hashes: Vec<BlockHash>,
    },
    /// Block `inv` during IBD. A peer retired from the header walk can rejoin.
    BlocksInv {
        peer: usize,
        hashes: Vec<BlockHash>,
    },
    /// Addresses learned from `addr` / `addrv2` (for IBD redial pool growth).
    Addrs {
        peer: usize,
        addrs: Vec<crate::NetAddr>,
    },
    /// Peer failed or closed.
    Dead {
        peer: usize,
        reason: String,
    },
}

/// Dual fan-out so body delivery is never stuck behind header floods on one FIFO.
///
/// - **body**: `BlockFramed` / fail / `NotFound` / `Dead` — drain first
/// - **ctrl**: `Headers` — budgeted so multi-peer header spam cannot livelock apply
#[derive(Clone)]
pub(crate) struct PeerEventSinks {
    pub body: mpsc::UnboundedSender<PeerEvent>,
    pub ctrl: mpsc::UnboundedSender<PeerEvent>,
}

impl PeerEventSinks {
    pub(crate) fn send_body(&self, ev: PeerEvent) {
        let _ = self.body.send(ev);
    }
    pub(crate) fn send_ctrl(&self, ev: PeerEvent) {
        let _ = self.ctrl.send(ev);
    }
}

pub(crate) struct PeerSlot {
    pub id: usize,
    pub addr: SocketAddr,
    pub net: crate::NetAddr,
    pub cmd_tx: mpsc::UnboundedSender<PeerCmd>,
    /// Hashes currently requested from this peer.
    pub in_flight: HashSet<BlockHash>,
    /// Same hashes, shared with the reader. One extra set per live peer so a
    /// block check does not take the IBD work state.
    pub requested: Arc<Mutex<HashSet<BlockHash>>>,
    /// Bytes of blocks this peer was asked for. Stall-clock input.
    pub solicited_bytes: Arc<AtomicU64>,
    /// Mono ms of the last solicited block the reader accepted.
    pub solicited_ms: Arc<AtomicU64>,
    /// Peer's `version.start_height` (best-effort network tip signal).
    pub peer_height: u32,
    /// Mono ms when the slot became live (post-handshake).
    pub connected_ms: u64,
    /// First block-payload mono ms (0 = none yet). IBD main thread only.
    pub first_data_ms: u64,
    /// All streamed wire bytes. Reader-only `fetch_add`. Not the stall clock.
    pub bytes_rx_total: Arc<AtomicU64>,
    pub rate: PeerRate,
    pub alive: bool,
    pub task: JoinHandle<()>,
}

/// Empty side-set and solicited counters for a new [`PeerSlot`].
pub(crate) fn solicit_track() -> (
    Arc<Mutex<HashSet<BlockHash>>>,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
) {
    (
        Arc::new(Mutex::new(HashSet::new())),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    )
}

/// In-flight light decodes (inv, addr, tx, cmpct) per IBD peer. Not a knob.
const LIGHT_DECODE_PERMITS: usize = 32;

impl PeerSlot {
    fn requested_set(&self) -> std::sync::MutexGuard<'_, HashSet<BlockHash>> {
        self.requested.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn track_insert(&mut self, hash: BlockHash) {
        self.in_flight.insert(hash);
        self.requested_set().insert(hash);
    }

    pub(crate) fn track_remove(&mut self, hash: &BlockHash) -> bool {
        let removed = self.in_flight.remove(hash);
        self.requested_set().remove(hash);
        removed
    }

    pub(crate) fn track_clear(&mut self) {
        self.in_flight.clear();
        self.requested_set().clear();
    }

    pub(crate) fn track_retain(&mut self, mut keep: impl FnMut(&BlockHash) -> bool) {
        self.in_flight.retain(|h| keep(h));
        self.requested_set().retain(|h| keep(h));
    }

    pub(crate) fn track_drain(&mut self) -> Vec<BlockHash> {
        let drained: Vec<BlockHash> = self.in_flight.drain().collect();
        self.requested_set().clear();
        drained
    }
}

/// `true` when `hash` was requested: record `len` and the read time.
/// An absent hash leaves both counters unchanged.
pub(crate) fn note_solicited_block(
    requested: &Mutex<HashSet<BlockHash>>,
    bytes: &AtomicU64,
    ms: &AtomicU64,
    hash: &BlockHash,
    len: usize,
) -> bool {
    let present = requested
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(hash);
    if !present {
        return false;
    }
    bytes.fetch_add(len as u64, Ordering::Relaxed);
    ms.store(ibd_mono_ms(), Ordering::Relaxed);
    true
}

/// One light-decode slot, or `None` without waiting.
pub(crate) fn try_light_decode_permit(sem: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(sem).try_acquire_owned().ok()
}

fn misbehavior_disconnect(rate: &mut PeerRateLimiter, ban_score: &mut u32, n: usize) -> bool {
    if rate.note(n) {
        return false;
    }
    *ban_score = ban_score.saturating_add(RATE_LIMIT_BAN_SCORE);
    *ban_score >= BAN_SCORE_THRESHOLD
}

fn apply_decoded_message(
    id: usize,
    sinks: &PeerEventSinks,
    msg: bitcoin::p2p::message::RawNetworkMessage,
) {
    match msg.into_payload() {
        NetworkMessage::Headers(h) => {
            sinks.send_ctrl(PeerEvent::Headers {
                peer: id,
                headers: h,
            });
        }
        NetworkMessage::NotFound(inv) => {
            let hashes = block_inventory_hashes(&inv);
            if !hashes.is_empty() {
                sinks.send_body(PeerEvent::NotFound { peer: id, hashes });
            }
        }
        NetworkMessage::Addr(list) => {
            let addrs = net_addrs_from_addr(&list);
            if !addrs.is_empty() {
                sinks.send_ctrl(PeerEvent::Addrs { peer: id, addrs });
            }
        }
        NetworkMessage::AddrV2(list) => {
            let addrs = net_addrs_from_addrv2(&list);
            if !addrs.is_empty() {
                sinks.send_ctrl(PeerEvent::Addrs { peer: id, addrs });
            }
        }
        NetworkMessage::SendAddrV2 => {}
        NetworkMessage::Block(_) => {}
        NetworkMessage::Inv(inv) => {
            let hashes = block_inventory_hashes(&inv);
            if !hashes.is_empty() {
                sinks.send_ctrl(PeerEvent::BlocksInv { peer: id, hashes });
            }
        }
        _other => {}
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(PeerCmd::Shutdown);
        self.task.abort();
    }
}

/// Monotonic milliseconds for IBD stall clocks (process-relative).
pub(crate) fn ibd_mono_ms() -> u64 {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    T0.get_or_init(Instant::now).elapsed().as_millis() as u64
}

pub(crate) fn note_stream_bytes(counter: &AtomicU64, n: u64) {
    if n == 0 {
        return;
    }
    counter.fetch_add(n, Ordering::Relaxed);
}

pub(crate) fn sample_peer_rates(slots: &mut [PeerSlot], now_ms: u64) {
    for s in slots {
        if !s.alive {
            continue;
        }
        // Read-time credit. Decoys stay in `bytes_rx_total` and do not move this.
        let mark = s.solicited_ms.load(Ordering::Relaxed);
        if mark > s.rate.progress_ms {
            s.rate.progress_ms = mark;
        }
        let bytes = s.solicited_bytes.load(Ordering::Relaxed);
        s.rate.sample(now_ms, bytes, !s.in_flight.is_empty());
    }
}

pub(crate) fn note_block_progress(slots: &mut [PeerSlot], peer: usize) {
    if let Some(s) = slots.iter_mut().find(|s| s.id == peer) {
        s.rate.note_rx(ibd_mono_ms());
    }
}

pub(crate) fn note_block_rx(slots: &mut [PeerSlot], peer: usize, wire_bytes: usize) {
    if let Some(s) = slots.iter_mut().find(|s| s.id == peer) {
        let now = ibd_mono_ms();
        s.rate.note_rx(now);
        if wire_bytes > 0 && s.first_data_ms == 0 {
            s.first_data_ms = now;
        }
    }
}

pub(crate) async fn spawn_peer(
    id: usize,
    addr: crate::NetAddr,
    magic: Magic,
    local: SocketAddr,
    tip_h: Option<u32>,
    sinks: PeerEventSinks,
    dialer: crate::socks::Dialer,
) -> Result<PeerSlot, NetError> {
    let stream = dialer.connect_net(addr).await?;
    let version_socket = addr
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], addr.port())));
    let ua = rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
        .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")));
    let (ver, reader, writer, _wire, _tcp_shutdown) = connect_and_handshake_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        local,
        version_socket,
        tip_h.map(|h| h as i32).unwrap_or(0),
        false,
        &ua,
        HandshakePolicy::plain(),
    )
    .await?;
    let peer_height = u32::try_from(ver.start_height).unwrap_or(0);

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<PeerCmd>();
    // Reader → writer for pongs (must not write on the read task — that would
    // stall the receive half and look like a peer stall).
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<NetworkMessage>();
    let bytes_rx_total = Arc::new(AtomicU64::new(0));
    let bytes_io = Arc::clone(&bytes_rx_total);
    let (requested, solicited_bytes, solicited_ms) = solicit_track();
    let req_r = Arc::clone(&requested);
    let sol_bytes_r = Arc::clone(&solicited_bytes);
    let sol_ms_r = Arc::clone(&solicited_ms);
    let light_decode = Arc::new(Semaphore::new(LIGHT_DECODE_PERMITS));

    // Parent owns concurrent read + write tasks. Aborting the parent (PeerSlot
    // Drop / stall disconnect) must abort both children — plain JoinHandle drop
    // only detaches.
    let task = tokio::spawn(async move {
        /// Aborts both halves if the parent task is cancelled mid-flight.
        struct PeerIoTasks {
            reader: tokio::task::JoinHandle<()>,
            writer: tokio::task::JoinHandle<()>,
        }
        impl Drop for PeerIoTasks {
            fn drop(&mut self) {
                self.reader.abort();
                self.writer.abort();
            }
        }

        // Reader first: Core pipelines sendheaders/sendcmpct/… right after verack.
        // July 18 cold-start worked with **no** post-handshake getaddr/sendaddrv2
        // before getheaders; those writes raced Core's pipeline and peers closed
        // (ordered=0 / inflight=0 / never archive).
        let mut reader = reader;
        let sinks_r = sinks.clone();
        let reader_task = tokio::spawn(async move {
            let mut prog_mark = 0usize;
            // Decoys and unknown types only. Requested block bodies stay off
            // this window so a fast peer is not clipped at the tip-follow cap.
            let mut rate = PeerRateLimiter::default_limits();
            let mut logged_invalid_v2 = false;
            let mut ban_score = 0u32;
            loop {
                let frame = read_v2_frame_with_progress(
                    &mut reader,
                    magic,
                    |buffered| {
                        let delta = buffered.saturating_sub(prog_mark);
                        note_stream_bytes(&bytes_io, delta as u64);
                        prog_mark = buffered;
                    },
                    |n| {
                        if rate.note(n) {
                            Ok(())
                        } else {
                            Err(NetError::Protocol("peer misbehavior threshold"))
                        }
                    },
                )
                .await;
                prog_mark = 0;
                match frame {
                    Ok(frame) => {
                        if frame.is_ping() {
                            if let Some(n) = frame.ping_nonce() {
                                let _ = out_tx.send(NetworkMessage::Pong(n));
                            }
                            continue;
                        }

                        if frame.is_block() {
                            match frame.block_hash_from_header() {
                                Some(hash) if frame.payload.len() >= 80 => {
                                    // Unsolicited bodies stay off the channel.
                                    // Requested bodies are not rate-capped.
                                    let n = frame.payload.len();
                                    if note_solicited_block(
                                        &req_r,
                                        &sol_bytes_r,
                                        &sol_ms_r,
                                        &hash,
                                        n,
                                    ) {
                                        sinks_r.send_body(PeerEvent::BlockFramed {
                                            peer: id,
                                            hash,
                                            payload: frame.payload,
                                        });
                                    } else if misbehavior_disconnect(&mut rate, &mut ban_score, n) {
                                        sinks_r.send_body(PeerEvent::Dead {
                                            peer: id,
                                            reason: "peer misbehavior threshold".to_string(),
                                        });
                                        break;
                                    }
                                }
                                Some(hash) => {
                                    sinks_r
                                        .send_body(PeerEvent::BlockDecodeFailed { peer: id, hash });
                                }
                                None => {
                                    rbitcoin_log::debug!(
                                        "ibd: peer[{id}] block frame without usable header hash"
                                    );
                                }
                            }
                            continue;
                        }

                        // Headers and notfound stay on the heavy decode pool.
                        // Light frames take a permit without waiting.
                        if !frame.decode_is_cpu_heavy() {
                            let n = frame.payload.len();
                            match try_light_decode_permit(&light_decode) {
                                Some(permit) => {
                                    let sinks_d = sinks_r.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        match frame.try_decode() {
                                            Ok(msg) => apply_decoded_message(id, &sinks_d, msg),
                                            Err(e) => {
                                                sinks_d.send_body(PeerEvent::Dead {
                                                    peer: id,
                                                    reason: e.to_string(),
                                                });
                                            }
                                        }
                                    });
                                }
                                None => {
                                    if misbehavior_disconnect(&mut rate, &mut ban_score, n) {
                                        sinks_r.send_body(PeerEvent::Dead {
                                            peer: id,
                                            reason: "peer misbehavior threshold".to_string(),
                                        });
                                        break;
                                    }
                                }
                            }
                            continue;
                        }

                        let sinks_d = sinks_r.clone();
                        // Never await a decode permit on the reader (stalls TCP).
                        spawn_decode_then_with_err(
                            frame,
                            move |msg| apply_decoded_message(id, &sinks_d, msg),
                            {
                                let sinks_e = sinks_r.clone();
                                move |e| {
                                    sinks_e.send_body(PeerEvent::Dead {
                                        peer: id,
                                        reason: e.to_string(),
                                    });
                                }
                            },
                        );
                    }
                    Err(NetError::InvalidV2Type { contents_len }) => {
                        if !logged_invalid_v2 {
                            logged_invalid_v2 = true;
                            rbitcoin_log::debug!("{}", crate::v2::v2_invalid_message_type_log());
                        }
                        if misbehavior_disconnect(&mut rate, &mut ban_score, contents_len) {
                            sinks_r.send_body(PeerEvent::Dead {
                                peer: id,
                                reason: "peer misbehavior threshold".to_string(),
                            });
                            break;
                        }
                        continue;
                    }
                    Err(NetError::Io(e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            || e.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        sinks_r.send_body(PeerEvent::Dead {
                            peer: id,
                            reason: format!("eof: {e}"),
                        });
                        break;
                    }
                    Err(e) => {
                        sinks_r.send_body(PeerEvent::Dead {
                            peer: id,
                            reason: e.to_string(),
                        });
                        break;
                    }
                }
            }
        });

        // Let the reader poll once before we accept write work (getheaders).
        tokio::task::yield_now().await;

        let mut writer = writer;
        let sinks_w = sinks;
        let writer_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(PeerCmd::GetHeaders { locator }) => {
                                let locator = if locator.len() > crate::codec::MAX_LOCATOR_SZ {
                                    locator[..crate::codec::MAX_LOCATOR_SZ].to_vec()
                                } else {
                                    locator
                                };
                                let gh = GetHeadersMessage::new(
                                    locator,
                                    BlockHash::from_byte_array([0u8; 32]),
                                );
                                if write_v2_msg_offload(
                                    &mut writer,
                                    NetworkMessage::GetHeaders(gh),
                                )
                                .await
                                .is_err()
                                {
                                    sinks_w.send_body(PeerEvent::Dead {
                                        peer: id,
                                        reason: "write getheaders failed".into(),
                                    });
                                    break;
                                }
                            }
                            Some(PeerCmd::GetData { hashes }) => {
                                for chunk in hashes.chunks(MAX_INV_SIZE) {
                                    let inv: Vec<_> = chunk
                                        .iter()
                                        .copied()
                                        .map(Inventory::WitnessBlock)
                                        .collect();
                                    if inv.is_empty() {
                                        continue;
                                    }
                                    if write_v2_msg_offload(
                                        &mut writer,
                                        NetworkMessage::GetData(inv),
                                    )
                                    .await
                                    .is_err()
                                    {
                                        sinks_w.send_body(PeerEvent::Dead {
                                            peer: id,
                                            reason: "write getdata failed".into(),
                                        });
                                        return;
                                    }
                                }
                            }
                            Some(PeerCmd::Shutdown) | None => break,
                        }
                    }
                    msg = out_rx.recv() => {
                        match msg {
                            Some(payload) => {
                                if write_v2_msg_offload(&mut writer, payload).await.is_err() {
                                    sinks_w.send_body(PeerEvent::Dead {
                                        peer: id,
                                        reason: "write outbound failed".into(),
                                    });
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        let mut guard = PeerIoTasks {
            reader: reader_task,
            writer: writer_task,
        };
        tokio::select! {
            _ = &mut guard.reader => {}
            _ = &mut guard.writer => {}
        }
    });

    Ok(PeerSlot {
        id,
        addr: version_socket,
        net: addr,
        cmd_tx,
        in_flight: HashSet::new(),
        requested,
        solicited_bytes,
        solicited_ms,
        peer_height,
        connected_ms: ibd_mono_ms(),
        first_data_ms: 0,
        bytes_rx_total,
        rate: PeerRate::default(),
        alive: true,
        task,
    })
}

/// IPv4/IPv6 sockets that advertise full/limited network **and** `P2P_V2`.
fn net_addrs_from_addr(list: &[(u32, bitcoin::p2p::address::Address)]) -> Vec<crate::NetAddr> {
    socket_addrs_from_addr(list)
        .into_iter()
        .map(crate::NetAddr::Ip)
        .collect()
}

/// BIP155 rows that advertise full/limited network **and** `P2P_V2`, including onion.
fn net_addrs_from_addrv2(list: &[bitcoin::p2p::address::AddrV2Message]) -> Vec<crate::NetAddr> {
    let mut out = Vec::with_capacity(list.len().min(32));
    for a in list {
        if !services_useful_for_ibd(a.services) {
            continue;
        }
        let Some(addr) = crate::NetAddr::from_addrv2(a) else {
            continue;
        };
        match addr {
            crate::NetAddr::Ip(sa) if !usable_dial_addr(&sa) => {}
            ok => out.push(ok),
        }
    }
    out
}

/// IPv4/IPv6 sockets that advertise full/limited network **and** `P2P_V2`.
fn socket_addrs_from_addr(list: &[(u32, bitcoin::p2p::address::Address)]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(list.len().min(32));
    for (_ts, a) in list {
        if !services_useful_for_ibd(a.services) {
            continue;
        }
        if let Ok(sa) = a.socket_addr() {
            if usable_dial_addr(&sa) {
                out.push(sa);
            }
        }
    }
    out
}

fn services_useful_for_ibd(flags: ServiceFlags) -> bool {
    (flags.has(ServiceFlags::NETWORK) || flags.has(ServiceFlags::NETWORK_LIMITED))
        && flags.has(ServiceFlags::P2P_V2)
}

fn usable_dial_addr(sa: &SocketAddr) -> bool {
    if sa.port() == 0 {
        return false;
    }
    match sa {
        SocketAddr::V4(v4) => {
            let ip = *v4.ip();
            !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
        }
        SocketAddr::V6(v6) => {
            let ip = *v6.ip();
            !ip.is_unspecified() && !ip.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::Ordering;

    fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18444),
            net: crate::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                18444,
            )),
            cmd_tx,
            in_flight: HashSet::new(),
            requested: Arc::new(Mutex::new(HashSet::new())),
            solicited_bytes: Arc::new(AtomicU64::new(0)),
            solicited_ms: Arc::new(AtomicU64::new(0)),
            peer_height: 100,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            alive: true,
            task,
        }
    }

    #[test]
    fn usable_dial_and_services_filters() {
        assert!(!services_useful_for_ibd(ServiceFlags::NETWORK));
        assert!(!services_useful_for_ibd(ServiceFlags::NETWORK_LIMITED));
        assert!(!services_useful_for_ibd(ServiceFlags::P2P_V2));
        assert!(!services_useful_for_ibd(ServiceFlags::NONE));
        assert!(services_useful_for_ibd(
            ServiceFlags::NETWORK | ServiceFlags::P2P_V2
        ));
        assert!(services_useful_for_ibd(
            ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2
        ));

        let good = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        assert!(usable_dial_addr(&good));
        let zero_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0);
        assert!(!usable_dial_addr(&zero_port));
        let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333);
        assert!(!usable_dial_addr(&unspec));
        let bcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 8333);
        assert!(!usable_dial_addr(&bcast));
        let multi = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 8333);
        assert!(!usable_dial_addr(&multi));
        let v6_good = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
        assert!(usable_dial_addr(&v6_good));
        let v6_unspec = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8333);
        assert!(!usable_dial_addr(&v6_unspec));
    }

    #[test]
    fn stream_bytes_sample_and_first_data() {
        let mut s = dummy_slot(7);
        note_stream_bytes(&s.bytes_rx_total, 0);
        assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 0);
        note_stream_bytes(&s.bytes_rx_total, 100);
        note_stream_bytes(&s.bytes_rx_total, 50);
        assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 150);

        s.in_flight.insert(BlockHash::from_byte_array([1u8; 32]));
        sample_peer_rates(std::slice::from_mut(&mut s), 0);
        sample_peer_rates(std::slice::from_mut(&mut s), 5_000);
        assert!(s.rate.bps().is_some());

        while ibd_mono_ms() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        note_block_rx(std::slice::from_mut(&mut s), 7, 0);
        assert_eq!(s.first_data_ms, 0);
        note_block_progress(std::slice::from_mut(&mut s), 7);
        note_block_rx(std::slice::from_mut(&mut s), 7, 1000);
        assert!(s.first_data_ms > 0);
        note_block_progress(std::slice::from_mut(&mut s), 99);
        note_block_rx(std::slice::from_mut(&mut s), 99, 1);
        assert!(ibd_mono_ms() > 0);
    }

    #[test]
    fn unsolicited_block_does_not_refresh_progress() {
        let hash = BlockHash::from_byte_array([7u8; 32]);
        let requested = Mutex::new(HashSet::new());
        let bytes = AtomicU64::new(0);
        let ms = AtomicU64::new(0);
        assert!(
            !note_solicited_block(&requested, &bytes, &ms, &hash, 80),
            "an unsolicited block does not count"
        );
        assert_eq!(bytes.load(Ordering::Relaxed), 0);
        assert_eq!(ms.load(Ordering::Relaxed), 0);

        while ibd_mono_ms() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        requested.lock().unwrap().insert(hash);
        let len = crate::ibd::rate::PROGRESS_STEP as usize;
        assert!(
            note_solicited_block(&requested, &bytes, &ms, &hash, len),
            "a requested block records its bytes"
        );
        assert_eq!(bytes.load(Ordering::Relaxed), len as u64);
        let marked = ms.load(Ordering::Relaxed);
        assert!(marked > 0, "a requested block stamps the read time");

        let mut quiet = PeerRate::default();
        quiet.sample(0, 0, true);
        quiet.sample(10_000, 0, true);
        assert_eq!(
            quiet.progress_ms, 0,
            "zero solicited bytes over 10s leave the stall clock"
        );
        let mut moved = PeerRate::default();
        moved.sample(0, 0, true);
        moved.sample(1_000, bytes.load(Ordering::Relaxed), true);
        assert_eq!(moved.progress_ms, 1_000);

        let mut slot = dummy_slot(4);
        slot.in_flight.insert(hash);
        assert_eq!(slot.solicited_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(slot.solicited_ms.load(Ordering::Relaxed), 0);
        sample_peer_rates(std::slice::from_mut(&mut slot), 0);
        note_stream_bytes(&slot.bytes_rx_total, 8_000_000);
        sample_peer_rates(std::slice::from_mut(&mut slot), 10_000);
        assert_eq!(
            slot.rate.progress_ms, 0,
            "unsolicited stream bytes do not refresh progress"
        );

        slot.solicited_ms.store(marked, Ordering::Relaxed);
        sample_peer_rates(std::slice::from_mut(&mut slot), 0);
        assert_eq!(slot.rate.progress_ms, marked);
    }

    #[test]
    fn light_decode_permit_does_not_wait() {
        let sem = Arc::new(Semaphore::new(1));
        let first = try_light_decode_permit(&sem);
        assert!(first.is_some(), "one permit is available immediately");
        assert!(
            try_light_decode_permit(&sem).is_none(),
            "a second permit does not wait"
        );
        drop(first);
        assert!(try_light_decode_permit(&sem).is_some());
    }

    #[test]
    fn block_inventory_hashes_keeps_blocks_only() {
        let block = BlockHash::from_byte_array([1u8; 32]);
        let witness = BlockHash::from_byte_array([2u8; 32]);
        let tx = bitcoin::Txid::from_byte_array([3u8; 32]);
        let inv = vec![
            Inventory::Transaction(tx),
            Inventory::Block(block),
            Inventory::WitnessBlock(witness),
        ];
        assert_eq!(block_inventory_hashes(&inv), vec![block, witness]);
    }

    #[test]
    fn event_sinks_send_body_and_ctrl() {
        let (body_tx, mut body_rx) = mpsc::unbounded_channel();
        let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
        let sinks = PeerEventSinks {
            body: body_tx,
            ctrl: ctrl_tx,
        };
        sinks.send_body(PeerEvent::Dead {
            peer: 1,
            reason: "x".into(),
        });
        sinks.send_ctrl(PeerEvent::Headers {
            peer: 1,
            headers: vec![],
        });
        assert!(matches!(
            body_rx.try_recv().unwrap(),
            PeerEvent::Dead { .. }
        ));
        assert!(matches!(
            ctrl_rx.try_recv().unwrap(),
            PeerEvent::Headers { .. }
        ));
    }

    #[test]
    fn socket_addrs_from_addr_and_addrv2_filter() {
        use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
        use bitcoin::p2p::ServiceFlags;

        let v2_net = ServiceFlags::NETWORK | ServiceFlags::P2P_V2;
        let v2_limited = ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2;
        let good = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let limited_sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);
        let no_svc = Address::new(&good, ServiceFlags::NONE);
        let net_only = Address::new(&good, ServiceFlags::NETWORK);
        let net_v2 = Address::new(&good, v2_net);
        let limited_only = Address::new(&limited_sa, ServiceFlags::NETWORK_LIMITED);
        let limited_v2 = Address::new(&limited_sa, v2_limited);
        let unusable = Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333),
            v2_net,
        );
        let out = socket_addrs_from_addr(&[
            (1, no_svc),
            (2, net_only),
            (3, net_v2),
            (4, limited_only),
            (5, limited_v2),
            (6, unusable),
        ]);
        assert_eq!(out, vec![good, limited_sa]);

        let v2_good = AddrV2Message {
            time: 1,
            services: v2_net,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 18444,
        };
        let v2_net_only = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 8)),
            port: 18444,
        };
        let v2_bad_svc = AddrV2Message {
            time: 1,
            services: ServiceFlags::NONE,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 10)),
            port: 18444,
        };
        let v2_zero_port = AddrV2Message {
            time: 1,
            services: v2_net,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 11)),
            port: 0,
        };
        let out2 = net_addrs_from_addrv2(&[v2_good, v2_net_only, v2_bad_svc, v2_zero_port]);
        assert_eq!(
            out2,
            vec![crate::NetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                18444
            ))]
        );

        let v6_multi =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), 8333);
        assert!(!usable_dial_addr(&v6_multi));
        let v6_net = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
        let v2_v6 = AddrV2Message {
            time: 1,
            services: v2_limited,
            addr: AddrV2::Ipv6(Ipv6Addr::LOCALHOST),
            port: 8333,
        };
        let out3 = net_addrs_from_addrv2(&[v2_v6]);
        assert_eq!(out3, vec![crate::NetAddr::Ip(v6_net)]);

        let onion: crate::NetAddr =
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
                .parse()
                .unwrap();
        let crate::NetAddr::Onion { pk, port } = onion else {
            panic!("fixture");
        };
        let v2_onion = AddrV2Message {
            time: 1,
            services: v2_net,
            addr: AddrV2::TorV3(pk),
            port,
        };
        let nets = net_addrs_from_addrv2(&[v2_onion]);
        assert_eq!(nets, vec![onion]);
    }
}
