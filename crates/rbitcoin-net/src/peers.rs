//! Live P2P session table for RPC (`getpeerinfo` / `addnode` / `disconnectnode`).

use crate::error::NetError;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{BlockHash, Wtxid};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

/// Session writer payload: application messages or pre-encoded v2 block bytes.
#[derive(Debug)]
pub(crate) enum PeerOut {
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

/// How we classified the session (Core `connection_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerConnType {
    Inbound,
    OutboundFullRelay,
    /// Core `addnode` / `connect_nodes` (`connection_type` = `manual`).
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

/// Request that the node dial `addr` as `typ`.
#[derive(Clone, Debug)]
pub struct DialRequest {
    pub addr: SocketAddr,
    pub typ: PeerConnType,
}

/// One live session (RPC snapshot + disconnect flag + byte counters).
pub struct LivePeer {
    pub id: u64,
    pub addr: SocketAddr,
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
    /// We announce new tips as `cmpctblock` to this peer (`sendcmpct` they sent).
    pub hb_to: AtomicBool,
    /// They announce new tips as `cmpctblock` to us (`sendcmpct` they sent).
    pub hb_from: AtomicBool,
    /// Session should send `sendcmpct`: 0 = none, 1 = off, 2 = on.
    pub pending_sendcmpct: std::sync::atomic::AtomicU8,
    /// Last header we announced to this peer (Core `pindexBestHeaderSent`).
    best_header_sent: Mutex<Option<BlockHash>>,
    /// Best connected block this peer advertised (Core `pindexBestKnownBlock`).
    best_known: Mutex<Option<BlockHash>>,
    /// Block hashes this peer just sent us — do not announce them back.
    recently_from: Mutex<HashSet<BlockHash>>,
    /// We already sent inv-triggered getheaders this session (before sync).
    inv_asked_headers: AtomicBool,
    /// Core `fSyncStarted` — this peer is the initial headers-sync peer.
    sync_started: AtomicBool,
    /// Unix seconds when initial headers sync times out (`0` = none).
    headers_sync_timeout: AtomicU64,
    /// Waiting for a headers reply to our getheaders (no BIP130 cap).
    awaiting_headers: AtomicBool,
    /// Wtxids we INV'd to this peer. GetData for a live mempool tx is
    /// answered only if announced here or the tx is reorg-servable.
    announced_wtx: Mutex<HashSet<Wtxid>>,
    /// Mempool sequence at last tx INV (Core `m_last_inv_sequence`, starts at 1).
    last_inv_sequence: AtomicU64,
    /// Last clock we considered for delayed tx INV (`0` = not initialized).
    last_tx_inv_now: AtomicU64,
    /// Set when mocktime jumps; next ping/tick announces mempool txs.
    tx_inv_requested: AtomicBool,
    /// Outstanding ping nonce (`0` = none). Core `m_ping_nonce_sent`.
    ping_nonce_sent: AtomicU64,
    /// When the last ping was sent, or `0` if never (`m_ping_start` seconds).
    ping_start_secs: AtomicU64,
    /// RPC `ping` queued a probe (`m_ping_queued`).
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
    /// Compact hashes whose first `blocktxn` reconstruct already failed
    /// (`p2p_compactblocks` `test_multiple_blocktxn_response`).
    failed_cmpct: Mutex<HashSet<BlockHash>>,
    /// Heights of blocks we have requested from this peer and not yet received
    /// (`getpeerinfo.inflight`).
    inflight: Mutex<Vec<u32>>,
    /// Session writer. RPC/accept flushes tx INVs onto this (`p2p_blocksonly`).
    out_tx: Mutex<Option<mpsc::UnboundedSender<PeerOut>>>,
    /// Unix seconds when this session was registered (Core `m_connected`).
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
    /// Peer sent BIP155 `sendaddrv2` (use `addrv2` for self-announce / GETADDR).
    wants_addrv2: AtomicBool,
    /// Next self-announce unix seconds (`0` = never sent).
    next_local_addr_send: AtomicU64,
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

    pub fn set_wants_addrv2(&self) {
        self.wants_addrv2.store(true, Ordering::Relaxed);
    }

    pub fn wants_addrv2(&self) -> bool {
        self.wants_addrv2.load(Ordering::Relaxed)
    }

    /// Core `MaybeSendAddr` local-address timer (`AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL`).
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
        let sock = self.take_local_addr_due(self.clock_now())?;
        rbitcoin_log::debug!("{}", crate::peer::advertising_address_log(sock, self.id));
        let now = self.clock_now() as u32;
        Some(if self.wants_addrv2() {
            NetworkMessage::AddrV2(vec![AddrV2Message {
                time: now,
                services: crate::peer::local_service_flags(),
                addr: match sock.ip() {
                    IpAddr::V4(v) => AddrV2::Ipv4(v),
                    IpAddr::V6(v) => AddrV2::Ipv6(v),
                },
                port: sock.port(),
            }])
        } else {
            NetworkMessage::Addr(vec![(
                now,
                Address::new(&sock, crate::peer::local_service_flags()),
            )])
        })
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

    /// Core `CanServeBlocks`: NETWORK or NETWORK_LIMITED.
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
        let mut g = self.announced_wtx.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= 50_000 {
            g.clear();
        }
        g.insert(wtxid);
    }

    pub fn has_announced_wtx(&self, wtxid: &Wtxid) -> bool {
        self.announced_wtx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(wtxid)
    }

    pub fn last_inv_sequence(&self) -> u64 {
        self.last_inv_sequence.load(Ordering::Relaxed)
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

    pub(crate) fn attach_out(&self, tx: mpsc::UnboundedSender<PeerOut>) {
        *self.out_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
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

    pub(crate) fn hub(&self) -> Option<Arc<PeerHub>> {
        self.owner.upgrade()
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

    /// Core `MaybeSendPing`: timeout first, then RPC-queued / interval probe.
    ///
    /// Never-sent peers keep `ping_start_secs == 0`, so any `now_secs` above
    /// 120 is interval-due (same comparison as a last ping at Unix epoch 0).
    pub fn take_ping_action(&self, now_secs: u64) -> Option<PingAction> {
        const PING_INTERVAL: u64 = 120;
        const TIMEOUT_INTERVAL: u64 = 20 * 60;
        let nonce = self.ping_nonce_sent.load(Ordering::Relaxed);
        let start = self.ping_start_secs.load(Ordering::Relaxed);
        if nonce != 0 && now_secs > start.saturating_add(TIMEOUT_INTERVAL) {
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
                "pong peer={}: {p}, {expected:x} expected, {received:x} received, {} bytes",
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
        PeerInfo {
            id: self.id,
            addr: self.addr,
            addrbind: self.addrbind,
            subver: self.subver.clone(),
            inbound: self.inbound,
            services: self.services,
            startingheight: self.startingheight,
            bytesrecv_per_msg: self.recv.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            bytessent_per_msg: self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone(),
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
            inflight: self
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            permissions: {
                let mut p = Vec::new();
                if let Some(h) = self.owner.upgrade() {
                    if h.is_noban() {
                        p.push("noban".into());
                    }
                    if h.is_relay_perm() {
                        p.push("relay".into());
                    }
                }
                p
            },
        }
    }
}

/// Result of Core `MaybeSendPing`.
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

/// RPC-facing snapshot.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: u64,
    pub addr: SocketAddr,
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
    /// Core whitelist permission strings (`relay`, `noban`, …).
    pub permissions: Vec<String>,
    /// Block heights in flight from this peer (`getpeerinfo.inflight`).
    pub inflight: Vec<u32>,
}

/// Thread-safe session table + addnode remembered addrs.
pub struct PeerHub {
    next_id: AtomicU64,
    live: RwLock<HashMap<u64, Arc<LivePeer>>>,
    added: Mutex<HashSet<SocketAddr>>,
    dial_tx: Mutex<Option<mpsc::UnboundedSender<DialRequest>>>,
    /// Peers we asked to send us compact (BIP152 HB, max 3, prefer outbound).
    hb_selected: Mutex<Vec<u64>>,
    /// `setmocktime` seconds; `0` means wall clock.
    mock_now: AtomicU64,
    /// Core `nSyncStarted`.
    n_sync_started: AtomicU64,
    /// Last inv hash that started headers sync with a not-yet-sync peer.
    last_inv_headers_sync: Mutex<Option<BlockHash>>,
    /// Core whitelist `noban` — do not disconnect a stalling headers-sync peer.
    noban: AtomicBool,
    /// Core whitelist `relay` — accept txs even when the node is `-blocksonly`.
    relay_perm: AtomicBool,
    /// Core whitelist `forcerelay` — no outbound `feefilter` (relay all).
    forcerelay_perm: AtomicBool,
    /// Parallel compact-fill slots per block: up to 2 inbound + 1 outbound.
    cmpct_fills: Mutex<HashMap<BlockHash, (u8, bool)>>,
    /// Version nonces of outbound sessions still in handshake (Core self-connect).
    pending_outbound_nonces: Mutex<HashSet<u64>>,
    /// Shared addrman for GetAddr responses (optional until node wires it).
    addrman: Mutex<Option<std::sync::Arc<Mutex<crate::seeds::AddrMan>>>>,
    /// Per-bind GetAddr response cache: bind → (cached_at_secs, addrs).
    addr_response_cache:
        Mutex<HashMap<SocketAddr, (u64, Vec<(u32, bitcoin::p2p::address::Address)>)>>,
    /// Core `-peertimeout` seconds (VERSION/VERACK). Default 60.
    peer_timeout_secs: AtomicU64,
    /// Core `-externalip` addresses we advertise (`getnetworkinfo.localaddresses`).
    external_ips: Mutex<Vec<IpAddr>>,
    /// P2P listen port used with `-externalip`.
    listen_port: AtomicU16,
}

fn ip_is_advertisable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_unspecified() || v.is_loopback() || v.is_private()),
        IpAddr::V6(v) => !(v.is_unspecified() || v.is_loopback()),
    }
}

impl PeerHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(0),
            live: RwLock::new(HashMap::new()),
            added: Mutex::new(HashSet::new()),
            dial_tx: Mutex::new(None),
            hb_selected: Mutex::new(Vec::new()),
            mock_now: AtomicU64::new(0),
            n_sync_started: AtomicU64::new(0),
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
            listen_port: AtomicU16::new(0),
        })
    }

    pub fn set_peer_timeout_secs(&self, secs: u64) {
        self.peer_timeout_secs.store(secs.max(1), Ordering::Relaxed);
    }

    pub fn set_external_ips(&self, ips: Vec<IpAddr>) {
        *self.external_ips.lock().unwrap_or_else(|e| e.into_inner()) = ips;
    }

    pub fn set_listen_port(&self, port: u16) {
        self.listen_port.store(port, Ordering::Relaxed);
    }

    /// Core `LOCAL_MANUAL` (`-externalip`) rows for `getnetworkinfo.localaddresses`.
    pub fn rpc_local_addresses(&self) -> Vec<(String, u16, i32)> {
        const LOCAL_MANUAL: i32 = 4;
        let port = self.listen_port.load(Ordering::Relaxed);
        if port == 0 {
            return Vec::new();
        }
        let ips = self
            .external_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        ips.into_iter()
            .map(|ip| (ip.to_string(), port, LOCAL_MANUAL))
            .collect()
    }

    pub fn advertise_local_socket(&self) -> Option<SocketAddr> {
        let port = self.listen_port.load(Ordering::Relaxed);
        if port == 0 {
            return None;
        }
        let g = self.external_ips.lock().unwrap_or_else(|e| e.into_inner());
        let ip = g.iter().copied().find(ip_is_advertisable)?;
        Some(SocketAddr::new(ip, port))
    }

    pub fn peer_timeout_secs(&self) -> u64 {
        self.peer_timeout_secs.load(Ordering::Relaxed).max(1)
    }

    /// Attach the process addrman so inbound GetAddr can sample peers.
    pub fn set_addrman(&self, am: std::sync::Arc<Mutex<crate::seeds::AddrMan>>) {
        *self.addrman.lock().unwrap_or_else(|e| e.into_inner()) = Some(am);
    }

    /// Core GetAddr reply: per-bind cache (24h) of up to 1000 / 23% of addrman.
    pub fn addr_response_for_bind(
        &self,
        bind: SocketAddr,
    ) -> Vec<(u32, bitcoin::p2p::address::Address)> {
        const MAX_ADDR_TO_SEND: usize = 1000;
        const MAX_PCT_ADDR_TO_SEND: usize = 23;
        const CACHE_SECS: u64 = 24 * 60 * 60;
        let now = self.now_secs();
        {
            let cache = self
                .addr_response_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((cached_at, addrs)) = cache.get(&bind) {
                if now.saturating_sub(*cached_at) < CACHE_SECS {
                    return addrs.clone();
                }
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
        let n = entries.len();
        let pct_cap = (n * MAX_PCT_ADDR_TO_SEND / 100).max(1);
        let cap = MAX_ADDR_TO_SEND.min(pct_cap).min(n);
        if cap == 0 {
            return Vec::new();
        }
        // Deterministic shuffle from mocktime + bind so same bind caches stably,
        // different binds diverge.
        let mut idxs: Vec<usize> = (0..n).collect();
        let mut state = now
            ^ (bind.port() as u64)
            ^ bind.ip().to_string().bytes().map(|b| b as u64).sum::<u64>();
        for i in (1..idxs.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (state as usize) % (i + 1);
            idxs.swap(i, j);
        }
        let services = crate::peer::local_service_flags();
        let mut out = Vec::with_capacity(cap);
        for &i in idxs.iter().take(cap) {
            let addr = entries[i].addr;
            out.push((
                now as u32,
                bitcoin::p2p::address::Address::new(&addr, services),
            ));
        }
        self.addr_response_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(bind, (now, out.clone()));
        out
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

    /// Core `CConnman::CheckIncomingNonce`: `false` means connected to self.
    pub fn check_incoming_nonce(&self, nonce: u64) -> bool {
        !self
            .pending_outbound_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&nonce)
    }

    /// BIP152: at most two inbound `getblocktxn` plus one outbound for a hash.
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

    pub fn set_noban(&self, v: bool) {
        self.noban.store(v, Ordering::Relaxed);
    }

    /// Core whitelist `noban` — bypass low-work header anti-DoS.
    pub fn is_noban(&self) -> bool {
        self.noban.load(Ordering::Relaxed)
    }

    pub fn set_relay_perm(&self, v: bool) {
        self.relay_perm.store(v, Ordering::Relaxed);
    }

    /// Core whitelist `relay` — P2P txs allowed while `-blocksonly`.
    pub fn is_relay_perm(&self) -> bool {
        self.relay_perm.load(Ordering::Relaxed)
    }

    pub fn set_forcerelay_perm(&self, v: bool) {
        self.forcerelay_perm.store(v, Ordering::Relaxed);
    }

    /// Core whitelist `forcerelay` — do not send `feefilter`.
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
                .n_sync_started
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
        } else {
            self.n_sync_started.fetch_add(1, Ordering::Relaxed);
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
            self.n_sync_started.fetch_sub(1, Ordering::Relaxed);
            peer.headers_sync_timeout.store(0, Ordering::Relaxed);
        }
    }

    fn check_headers_sync_timeouts(&self, now: u64) {
        let n = self.n_sync_started.load(Ordering::Relaxed);
        if n != 1 {
            return;
        }
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let n_preferred = g
            .values()
            .filter(|p| Self::is_preferred_download(p))
            .count();
        let noban_all = self.noban.load(Ordering::Relaxed);
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
            if noban_all {
                rbitcoin_log::info!("{}", crate::chain::headers_timeout_noban_log(p.id));
                p.sync_started.store(false, Ordering::Relaxed);
                p.headers_sync_timeout.store(0, Ordering::Relaxed);
                // In-flight getheaders timed out; allow a new one
                // (`p2p_initial_headers_sync` noban recipient).
                let _ = p.take_awaiting_headers();
                self.n_sync_started.fetch_sub(1, Ordering::Relaxed);
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
        let peers: Vec<Arc<LivePeer>> = self.live_peers();
        for p in peers {
            if self.handshake_timed_out(&p, now) {
                rbitcoin_log::debug!("{}", crate::peer::version_handshake_timeout_log(p.id));
                let _ = self.disconnect_id(p.id);
            }
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

    /// Placeholder row after TCP connect, before VERSION (Core `CNode` timing).
    pub fn register_connecting(
        self: &Arc<Self>,
        addr: SocketAddr,
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
            start_height: 0,
            relay: false,
        };
        self.register_with_id(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            addr,
            addrbind,
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
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let p = self.register_with_id(id, addr, addrbind, ver, inbound, conn_type);
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
        let _ = self
            .next_id
            .fetch_max(id.saturating_add(1), Ordering::Relaxed);
        let services = service_flags_u64(ver.services);
        let connected_at = self.now_secs();
        let peer = Arc::new(LivePeer {
            id,
            addr,
            addrbind,
            subver: ver.user_agent.clone(),
            inbound,
            services,
            startingheight: ver.start_height,
            conn_type,
            relay: ver.relay,
            stop: AtomicBool::new(false),
            serve_inflight: AtomicUsize::new(0),
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
            announced_wtx: Mutex::new(HashSet::new()),
            last_inv_sequence: AtomicU64::new(1),
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
            connected_at: AtomicU64::new(connected_at),
            inv_gen_floor: AtomicU64::new(0),
            age_inv_seen_due: AtomicU64::new(0),
            age_inv_seen_gen: AtomicU64::new(0),
            writer_abort: Mutex::new(None),
            session_abort: Mutex::new(None),
            tcp_shutdown: Mutex::new(None),
            handshake_complete: AtomicBool::new(false),
            wants_addrv2: AtomicBool::new(false),
            next_local_addr_send: AtomicU64::new(0),
        });
        self.live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&peer));
        rbitcoin_log::debug!("Added connection peer={id}");
        peer
    }

    pub fn unregister(&self, id: u64) {
        let removed = self
            .live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        if let Some(p) = removed {
            self.end_headers_sync(&p);
        }
    }

    pub fn live_peers(&self) -> Vec<Arc<LivePeer>> {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        g.values().cloned().collect()
    }

    /// Re-advertise BIP133 feefilter after IBD/minrelay change (skip block-relay / forcerelay).
    pub fn queue_feefilter_all(&self, sat_kvb: i64) {
        if self.is_forcerelay_perm() {
            return;
        }
        for s in self.live_peers() {
            if s.conn_type == PeerConnType::BlockRelay {
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
        let mut v: Vec<_> = g.values().map(|p| p.snapshot(now)).collect();
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
        match cmd {
            "onetry" => self.dial(addr, PeerConnType::Manual),
            "add" => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(addr);
                let _ = self.dial(addr, PeerConnType::Manual);
                Ok(())
            }
            "remove" => {
                self.added
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&addr);
                self.disconnect_addr(addr);
                Ok(())
            }
            other => Err(format!("unknown addnode command {other}")),
        }
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
        if sel.contains(&id) {
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
                    p.pending_sendcmpct.store(1, Ordering::Relaxed);
                }
            }
        }
        sel.push(id);
        peer.set_hb_to(true);
        peer.pending_sendcmpct.store(2, Ordering::Relaxed);
    }

    pub fn addconnection(&self, addr: SocketAddr, typ: PeerConnType) -> Result<(), String> {
        if matches!(typ, PeerConnType::Inbound) {
            return Err("addconnection cannot create inbound".into());
        }
        self.dial(addr, typ)
    }

    /// Outbound full-relay sessions eligible for stale-tip slot rotation.
    /// Empty when this hub is `noban` (functional keep-alive).
    pub fn outbound_full_relay_ids(&self) -> Vec<u64> {
        if self.is_noban() {
            return Vec::new();
        }
        let mut ids: Vec<u64> = self
            .live_peers()
            .into_iter()
            .filter(|p| p.conn_type == PeerConnType::OutboundFullRelay && !p.inbound)
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        ids
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

    /// Core `AttemptToEvictConnection`: disconnect one unprotected inbound.
    pub fn try_evict_inbound(&self) -> bool {
        let noban = self.is_noban();
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
                    noban,
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
        let ids: Vec<u64> = {
            let g = self.live.read().unwrap_or_else(|e| e.into_inner());
            g.values()
                .filter(|p| p.addr == addr)
                .map(|p| p.id)
                .collect()
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
        tx.send(DialRequest { addr, typ })
            .map_err(|_| "dialer closed".to_string())
    }
}

/// Pick one live outbound id to drop so a stale-tip extra can dial.
pub fn pick_stale_follow_evict(ids: &[u64], salt: u64) -> Option<u64> {
    if ids.is_empty() {
        return None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::address::Address;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn peerhub_register_snapshot_disconnect() {
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
        p.note_recv("pong", 8);
        let snap = hub.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, 0);
        assert_eq!(snap[0].subver, "/rbitcoin:0.1.0(testnode0)/");
        assert!(!snap[0].inbound);
        assert!(snap[0].bytesrecv_per_msg.get("pong").copied().unwrap() >= 29);
        assert!(hub.disconnect_id(0));
        assert!(p.stop.load(Ordering::SeqCst));
        // disconnectnode must clear getpeerinfo immediately (mempool_reorg
        // disconnect_nodes waits ≤5s on the far side seeing us gone).
        assert!(
            hub.snapshot().is_empty(),
            "disconnect_id must unregister before the session task exits"
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
    fn connecting_peer_times_out_at_peertimeout() {
        let hub = PeerHub::new();
        hub.set_peer_timeout_secs(3);
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let p = hub.register_connecting(a, a, true, PeerConnType::Inbound);
        assert!(!p.handshake_complete());
        hub.set_mock_now(1_700_000_002);
        hub.on_session_heartbeat();
        assert!(!p.stop.load(Ordering::SeqCst), "still inside peertimeout");
        hub.set_mock_now(1_700_000_003);
        hub.on_session_heartbeat();
        assert!(
            p.stop.load(Ordering::SeqCst),
            "peertimeout must disconnect pre-verack"
        );
        assert!(
            hub.get(p.id).is_none(),
            "timed-out connecting peer is dropped"
        );
    }

    #[test]
    fn completed_handshake_survives_peertimeout() {
        let hub = PeerHub::new();
        hub.set_peer_timeout_secs(3);
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let p = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        assert!(p.handshake_complete());
        hub.set_mock_now(1_700_000_100);
        hub.on_session_heartbeat();
        assert!(!p.stop.load(Ordering::SeqCst));
        assert!(hub.get(p.id).is_some());
    }

    #[test]
    fn outbound_nonce_detects_self_connect() {
        let hub = PeerHub::new();
        assert!(hub.check_incoming_nonce(42));
        hub.note_outbound_nonce(42);
        assert!(!hub.check_incoming_nonce(42));
        assert!(hub.check_incoming_nonce(43));
        hub.clear_outbound_nonce(42);
        assert!(hub.check_incoming_nonce(42));
    }

    #[test]
    fn announced_wtx_is_per_peer() {
        use bitcoin::hashes::Hash;
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let p = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let w = Wtxid::from_byte_array([0x11; 32]);
        assert!(!p.has_announced_wtx(&w));
        p.note_announced_wtx(w);
        assert!(p.has_announced_wtx(&w));
        assert!(!p.has_announced_wtx(&Wtxid::from_byte_array([0x22; 32])));
        assert!(!p.take_tx_inv_due(1_700_000_000));
        assert!(!p.take_tx_inv_due(1_700_000_010));
        assert!(p.take_tx_inv_due(1_700_000_040));
        p.request_tx_inv();
        assert!(p.take_tx_inv_due(1_700_000_041));
    }

    #[test]
    fn skip_announce_of_block_this_peer_sent() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let p = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let h = BlockHash::from_byte_array([0xab; 32]);
        assert!(!p.take_block_from_peer(&h));
        p.note_block_from_peer(h);
        assert!(p.take_block_from_peer(&h));
        assert!(!p.take_block_from_peer(&h));
        assert!(p.try_ask_headers_for_inv());
        assert!(!p.try_ask_headers_for_inv());
        p.note_best_header_sent(h);
        p.note_best_known(h);
        assert_eq!(p.header_marks(), (Some(h), Some(h)));
        assert!(p.advertises_network());
    }

    #[test]
    fn only_one_initial_headers_sync_peer_when_tip_is_old() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
        let p1 = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let p2 = hub.register(b, b, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let now = 1_700_000_000;
        // genesis-era header: not caught up.
        assert!(hub.try_start_headers_sync(&p1, now, 1_231_006_505));
        assert!(p1.is_sync_started());
        assert!(!hub.try_start_headers_sync(&p2, now, 1_231_006_505));
        assert!(!p2.is_sync_started());
        let h1 = BlockHash::from_byte_array([1u8; 32]);
        let h2 = BlockHash::from_byte_array([2u8; 32]);
        // Sync peer always gets inv-triggered getheaders.
        assert!(hub.should_getheaders_for_inv(&p1, h1));
        // First extra peer for this hash.
        assert!(hub.should_getheaders_for_inv(&p2, h1));
        let p3 = hub.register(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3),
            b,
            &ver("/rbitcoin:0.1.0/"),
            true,
            PeerConnType::Inbound,
        );
        // Same hash: no third peer.
        assert!(!hub.should_getheaders_for_inv(&p3, h1));
        // New hash: remaining peer.
        assert!(hub.should_getheaders_for_inv(&p3, h2));
        hub.unregister(p1.id);
        assert!(!p1.is_sync_started());
        // After the sync peer leaves, another inbound may start.
        assert!(hub.try_start_headers_sync(&p2, now, 1_231_006_505));
    }

    #[test]
    fn session_heartbeat_disconnects_stalling_headers_sync() {
        let hub = PeerHub::new();
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
        // Deadline is computed from the `now` passed to try_start, not the hub
        // clock. Start 16 minutes behind wall time with a tip of the same age
        // so variable timeout is 0: deadline = wall − 60s.
        let wall = hub.now_secs();
        let start = wall.saturating_sub(16 * 60);
        assert!(hub.try_start_headers_sync(&inbound, start, start));
        assert!(inbound.is_sync_started());
        assert!(!inbound.stop.load(Ordering::SeqCst));
        hub.on_session_heartbeat();
        assert!(
            inbound.stop.load(Ordering::SeqCst),
            "stalling inbound must disconnect when another preferred peer exists"
        );
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
        let hub = PeerHub::new();
        hub.set_noban(true);
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
        let now = 1_700_000_000u64;
        let best = 1_231_006_505u64;
        assert!(hub.try_start_headers_sync(&inbound, now, best));
        inbound.note_awaiting_headers();
        assert!(inbound.is_awaiting_headers());
        let deadline = crate::chain::headers_download_timeout_secs(now, best);
        hub.set_mock_now(deadline + 1);
        assert!(
            !inbound.is_sync_started(),
            "noban timeout must end the stalling sync"
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
    fn addnode_unknown_command() {
        let hub = PeerHub::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        assert!(hub.addnode(a, "nope").is_err());
    }

    #[test]
    fn ping_pong_logs_core_needles() {
        let hub = PeerHub::new();
        hub.set_mock_now(1_700_000_000);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let p = hub.register(a, a, &ver("/rbitcoin:0.1.0/"), true, PeerConnType::Inbound);
        let PingAction::Send { nonce } = p.take_ping_action(hub.now_secs()).unwrap() else {
            panic!("expected send");
        };
        assert_ne!(nonce, 0);
        let wait = hub.snapshot()[0].pingwait;
        assert_eq!(wait, Some(0.0));

        hub.set_mock_now(1_700_000_003);
        assert_eq!(hub.snapshot()[0].pingwait, Some(3.0));

        let short = p.on_pong(&[], hub.now_secs()).expect("short");
        assert!(short.starts_with("pong peer=0: Short payload"), "{short}");
        assert!(p
            .on_pong(&0u64.to_le_bytes(), hub.now_secs())
            .unwrap()
            .contains("Unsolicited pong without ping, 0 expected, 0 received, 8 bytes"));

        let PingAction::Send { nonce } = p.take_ping_action(hub.now_secs() + 121).unwrap() else {
            panic!("interval send");
        };
        let wrong = (nonce.wrapping_sub(1)).to_le_bytes();
        let mm = p.on_pong(&wrong, hub.now_secs() + 121).unwrap();
        assert!(mm.contains("Nonce mismatch"), "{mm}");
        let zero = p
            .on_pong(&0u64.to_le_bytes(), hub.now_secs() + 121)
            .unwrap();
        assert!(zero.contains("Nonce zero"), "{zero}");

        let PingAction::Send { nonce } = p.take_ping_action(hub.now_secs() + 250).unwrap() else {
            panic!("rpc-style send");
        };
        let now = hub.now_secs() + 279;
        assert!(p.on_pong(&nonce.to_le_bytes(), now).is_none());
        let snap = {
            hub.set_mock_now(now);
            hub.snapshot()
        };
        assert_eq!(snap[0].pingtime, Some(29.0));
        assert_eq!(snap[0].minping, Some(29.0));
        assert_eq!(snap[0].pingwait, None);

        p.queue_ping();
        let PingAction::Send { .. } = p.take_ping_action(now).unwrap() else {
            panic!("queued");
        };
        let to = p.take_ping_action(now + 1201).unwrap();
        match to {
            PingAction::Timeout { elapsed_secs } => {
                assert!((elapsed_secs - 1201.0).abs() < 0.01, "{elapsed_secs}");
                let line = format!("ping timeout: {elapsed_secs:.6}s");
                assert_eq!(line, "ping timeout: 1201.000000s");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn pick_stale_follow_evict_none_on_empty() {
        assert!(pick_stale_follow_evict(&[], 7).is_none());
    }

    #[test]
    fn pick_stale_follow_evict_picks_only_from_candidates() {
        let ids = [3u64, 9, 12];
        for salt in 0..16u64 {
            let got = pick_stale_follow_evict(&ids, salt).unwrap();
            assert!(ids.contains(&got), "salt={salt} got={got}");
        }
        assert_eq!(pick_stale_follow_evict(&ids, 0), Some(3));
        assert_eq!(pick_stale_follow_evict(&ids, 1), Some(9));
        assert_eq!(pick_stale_follow_evict(&ids, 2), Some(12));
        assert_eq!(pick_stale_follow_evict(&ids, 3), Some(3));
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
}
