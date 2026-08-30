//! IBD download peer: split read/write over BIP324 v2.
//!
//! Socket tasks stay **I/O-only**:
//! - reader: decrypt frame + cheap ping handling; heavy decode off-thread
//! - writer: encode offloaded for heavy payloads; then encrypt + write

use crate::codec::MAX_INV_SIZE;
use crate::error::NetError;
use crate::msg_decode::spawn_decode_then_with_err;
use crate::peer::{connect_and_handshake_timed, HandshakePolicy, HANDSHAKE_TIMEOUT};
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
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
    /// Addresses learned from `addr` / `addrv2` (for IBD redial pool growth).
    Addrs {
        peer: usize,
        addrs: Vec<SocketAddr>,
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
    pub cmd_tx: mpsc::UnboundedSender<PeerCmd>,
    /// Hashes currently requested from this peer.
    pub in_flight: HashSet<BlockHash>,
    /// Last block-download progress as [`ibd_mono_ms`].
    pub block_progress_ms: Arc<AtomicU64>,
    /// Peer's `version.start_height` (best-effort network tip signal).
    pub peer_height: u32,
    /// Mono ms when the slot became live (post-handshake).
    pub connected_ms: u64,
    /// First block-payload mono ms (0 = none yet).
    pub first_data_ms: AtomicU64,
    /// Cumulative block payload bytes (speed sample).
    pub bytes_rx: AtomicU64,
    /// All streamed wire bytes (EWMA input). Reader-only `fetch_add`.
    pub bytes_rx_total: Arc<AtomicU64>,
    pub alive: bool,
    pub task: JoinHandle<()>,
}

impl PeerSlot {
    /// Record received block payload bytes for FAST/SLOW classification.
    pub fn note_rx_bytes(&self, n: u64) {
        if n == 0 {
            return;
        }
        let now = ibd_mono_ms();
        let _ = self
            .first_data_ms
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
        self.bytes_rx.fetch_add(n, Ordering::Relaxed);
    }

    /// `(latency_ms, bytes_per_sec)` once we have ≥64 KiB of block data.
    pub fn speed_sample(&self) -> Option<(u64, u64)> {
        let first = self.first_data_ms.load(Ordering::Relaxed);
        if first == 0 {
            return None;
        }
        let bytes = self.bytes_rx.load(Ordering::Relaxed);
        if bytes < 64 * 1024 {
            return None;
        }
        let latency_ms = first.saturating_sub(self.connected_ms);
        let elapsed_ms = ibd_mono_ms().saturating_sub(first).max(1);
        let bps = bytes.saturating_mul(1000) / elapsed_ms;
        Some((latency_ms, bps))
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

pub(crate) fn touch_block_progress(ms: &AtomicU64) {
    ms.store(ibd_mono_ms(), Ordering::Relaxed);
}

pub(crate) fn note_stream_bytes(counter: &AtomicU64, n: u64) {
    if n == 0 {
        return;
    }
    counter.fetch_add(n, Ordering::Relaxed);
}

pub(crate) fn note_block_progress(slots: &mut [PeerSlot], peer: usize) {
    if let Some(s) = slots.iter_mut().find(|s| s.id == peer) {
        touch_block_progress(&s.block_progress_ms);
    }
}

pub(crate) fn note_block_rx(slots: &mut [PeerSlot], peer: usize, wire_bytes: usize) {
    if let Some(s) = slots.iter_mut().find(|s| s.id == peer) {
        touch_block_progress(&s.block_progress_ms);
        s.note_rx_bytes(wire_bytes as u64);
    }
}

pub(crate) async fn spawn_peer(
    id: usize,
    addr: SocketAddr,
    magic: Magic,
    local: SocketAddr,
    tip_h: Option<u32>,
    sinks: PeerEventSinks,
) -> Result<PeerSlot, NetError> {
    let stream = TcpStream::connect(addr).await?;
    let ua = rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
        .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")));
    let (ver, reader, writer, _wire, _tcp_shutdown) = connect_and_handshake_timed(
        HANDSHAKE_TIMEOUT,
        stream,
        magic,
        local,
        addr,
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
    let block_progress_ms = Arc::new(AtomicU64::new(ibd_mono_ms()));
    let bytes_rx_total = Arc::new(AtomicU64::new(0));
    let bytes_io = Arc::clone(&bytes_rx_total);

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
            loop {
                let frame = read_v2_frame_with_progress(&mut reader, magic, |buffered| {
                    let delta = buffered.saturating_sub(prog_mark);
                    note_stream_bytes(&bytes_io, delta as u64);
                    prog_mark = buffered;
                })
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
                                    sinks_r.send_body(PeerEvent::BlockFramed {
                                        peer: id,
                                        hash,
                                        payload: frame.payload,
                                    });
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

                        let sinks_d = sinks_r.clone();
                        // Non-block: decode off-thread. Never await a decode permit
                        // on the reader (stalls TCP). Soft budgets gate *requests* only.
                        spawn_decode_then_with_err(
                            frame,
                            move |msg| {
                                match msg.into_payload() {
                                    NetworkMessage::Headers(h) => {
                                        sinks_d.send_ctrl(PeerEvent::Headers {
                                            peer: id,
                                            headers: h,
                                        });
                                    }
                                    NetworkMessage::NotFound(inv) => {
                                        let hashes: Vec<BlockHash> = inv
                                            .iter()
                                            .filter_map(|i| match i {
                                                Inventory::Block(h)
                                                | Inventory::WitnessBlock(h) => Some(*h),
                                                _ => None,
                                            })
                                            .collect();
                                        if !hashes.is_empty() {
                                            sinks_d.send_body(PeerEvent::NotFound {
                                                peer: id,
                                                hashes,
                                            });
                                        }
                                    }
                                    NetworkMessage::Addr(list) => {
                                        let addrs = socket_addrs_from_addr(&list);
                                        if !addrs.is_empty() {
                                            sinks_d.send_ctrl(PeerEvent::Addrs { peer: id, addrs });
                                        }
                                    }
                                    NetworkMessage::AddrV2(list) => {
                                        let addrs = socket_addrs_from_addrv2(&list);
                                        if !addrs.is_empty() {
                                            sinks_d.send_ctrl(PeerEvent::Addrs { peer: id, addrs });
                                        }
                                    }
                                    NetworkMessage::SendAddrV2 => {}
                                    // Blocks must not reach decode (handled above).
                                    NetworkMessage::Block(_) => {}
                                    _other => {}
                                }
                            },
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
                    Err(NetError::InvalidV2Type { .. }) => {
                        // Core logs and stays connected (same as tip-follow).
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
        addr,
        cmd_tx,
        in_flight: HashSet::new(),
        block_progress_ms,
        peer_height,
        connected_ms: ibd_mono_ms(),
        first_data_ms: AtomicU64::new(0),
        bytes_rx: AtomicU64::new(0),
        bytes_rx_total,
        alive: true,
        task,
    })
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

/// IPv4/IPv6 sockets that advertise full/limited network **and** `P2P_V2`.
fn socket_addrs_from_addrv2(list: &[bitcoin::p2p::address::AddrV2Message]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(list.len().min(32));
    for a in list {
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
            cmd_tx,
            in_flight: HashSet::new(),
            block_progress_ms: Arc::new(AtomicU64::new(0)),
            peer_height: 100,
            connected_ms: 1,
            first_data_ms: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
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
    fn speed_sample_and_progress_helpers() {
        let mut s = dummy_slot(7);
        assert!(s.speed_sample().is_none());
        s.note_rx_bytes(0); // no-op
                            // first_data_ms==0 is treated as "no sample yet"; wait so mono ms > 0.
        while ibd_mono_ms() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        s.note_rx_bytes(32 * 1024);
        assert!(s.speed_sample().is_none()); // need ≥64 KiB
        s.note_rx_bytes(64 * 1024);
        assert!(s.first_data_ms.load(Ordering::Relaxed) > 0);
        let sample = s.speed_sample().expect("bps after ≥64KiB");
        assert!(sample.1 > 0);

        note_stream_bytes(&s.bytes_rx_total, 0);
        assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 0);
        note_stream_bytes(&s.bytes_rx_total, 100);
        note_stream_bytes(&s.bytes_rx_total, 50);
        assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 150);

        touch_block_progress(&s.block_progress_ms);
        assert!(s.block_progress_ms.load(Ordering::Relaxed) > 0);
        note_block_progress(std::slice::from_mut(&mut s), 7);
        note_block_rx(std::slice::from_mut(&mut s), 7, 1000);
        note_block_progress(std::slice::from_mut(&mut s), 99); // missing peer
        note_block_rx(std::slice::from_mut(&mut s), 99, 1);
        assert!(ibd_mono_ms() > 0);
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
        let out2 = socket_addrs_from_addrv2(&[v2_good, v2_net_only, v2_bad_svc, v2_zero_port]);
        assert_eq!(
            out2,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                18444
            )]
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
        let out3 = socket_addrs_from_addrv2(&[v2_v6]);
        assert_eq!(out3, vec![v6_net]);
    }
}
