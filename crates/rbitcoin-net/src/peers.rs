//! Live P2P session table for RPC (`getpeerinfo` / `addnode` / `disconnectnode`).

use crate::error::NetError;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{BlockHash, Wtxid};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

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
    pub stop: AtomicBool,
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
    /// We already sent inv-triggered getheaders this session.
    inv_asked_headers: AtomicBool,
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
}

impl LivePeer {
    pub fn note_recv(&self, cmd: &str, nbytes: u64) {
        let n = acct_bytes(cmd, nbytes);
        *self
            .recv
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(cmd.into())
            .or_insert(0) += n;
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

    pub fn advertises_network(&self) -> bool {
        self.services & service_flags_u64(ServiceFlags::NETWORK) != 0
    }

    pub fn note_awaiting_headers(&self) {
        self.awaiting_headers.store(true, Ordering::Relaxed);
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

    fn ping_rpc_fields(&self, now_secs: u64) -> (Option<f64>, Option<f64>, Option<f64>) {
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
            bip152_hb_to: self.hb_to.load(Ordering::Relaxed),
            bip152_hb_from: self.hb_from.load(Ordering::Relaxed),
            pingtime,
            minping,
            pingwait,
            last_block: self.last_block.load(Ordering::Relaxed),
            last_transaction: self.last_transaction.load(Ordering::Relaxed),
            minfeefilter_sat_kvb: self.minfeefilter_sat_kvb.load(Ordering::Relaxed),
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
        })
    }

    pub fn now_secs(&self) -> u64 {
        let mock = self.mock_now.load(Ordering::Relaxed);
        if mock != 0 {
            return mock;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn set_mock_now(&self, ts: u64) {
        self.mock_now.store(ts, Ordering::Relaxed);
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        for p in g.values() {
            p.request_tx_inv();
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

    pub fn register(
        self: &Arc<Self>,
        addr: SocketAddr,
        addrbind: SocketAddr,
        ver: &VersionMessage,
        inbound: bool,
        conn_type: PeerConnType,
    ) -> Arc<LivePeer> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let services = service_flags_u64(ver.services);
        let peer = Arc::new(LivePeer {
            id,
            addr,
            addrbind,
            subver: ver.user_agent.clone(),
            inbound,
            services,
            startingheight: ver.start_height,
            conn_type,
            stop: AtomicBool::new(false),
            hb_to: AtomicBool::new(false),
            hb_from: AtomicBool::new(false),
            pending_sendcmpct: std::sync::atomic::AtomicU8::new(0),
            best_header_sent: Mutex::new(None),
            best_known: Mutex::new(None),
            recently_from: Mutex::new(HashSet::new()),
            inv_asked_headers: AtomicBool::new(false),
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
        });
        // Handshake already exchanged version + verack (+ maybe ping).
        peer.note_recv("version", 100);
        peer.note_recv("verack", 0);
        self.live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&peer));
        rbitcoin_log::debug!("Added connection peer={id}");
        peer
    }

    pub fn unregister(&self, id: u64) {
        self.live
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    pub fn snapshot(&self) -> Vec<PeerInfo> {
        let now = self.now_secs();
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = g.values().map(|p| p.snapshot(now)).collect();
        v.sort_by_key(|p| p.id);
        v
    }

    /// Sum of per-peer message byte counters (`getnettotals`).
    pub fn byte_totals(&self) -> (u64, u64) {
        let mut recv = 0u64;
        let mut sent = 0u64;
        for p in self.snapshot() {
            recv = recv.saturating_add(p.bytesrecv_per_msg.values().sum());
            sent = sent.saturating_add(p.bytessent_per_msg.values().sum());
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

    pub fn disconnect_id(&self, id: u64) -> bool {
        if let Some(p) = self.get(id) {
            p.request_disconnect();
            true
        } else {
            false
        }
    }

    pub fn disconnect_addr(&self, addr: SocketAddr) -> bool {
        let g = self.live.read().unwrap_or_else(|e| e.into_inner());
        let mut n = 0usize;
        for p in g.values() {
            if p.addr == addr {
                p.request_disconnect();
                n += 1;
            }
        }
        n > 0
    }

    fn dial(&self, addr: SocketAddr, typ: PeerConnType) -> Result<(), String> {
        let g = self.dial_tx.lock().unwrap_or_else(|e| e.into_inner());
        let tx = g.as_ref().ok_or("no dialer attached")?;
        tx.send(DialRequest { addr, typ })
            .map_err(|_| "dialer closed".to_string())
    }
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
        hub.unregister(0);
        assert!(hub.snapshot().is_empty());
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
}
