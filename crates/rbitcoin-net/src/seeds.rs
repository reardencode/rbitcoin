//! Fixed seeds, DNS seed names, and the process peer book ([`AddrMan`]).
//!
//! Each remembered address carries a **byte of informational flags** used to
//! rank dial candidates: prefer untried / known-good / fast peers; only fall
//! back to incompatible or recently-failed hosts when the good set is empty.
//!
//! The book can be **persisted** under the datadir (`peers` file) so discovered
//! addrs and flags survive restarts.

use bitcoin::p2p::ServiceFlags;
use rbitcoin_primitives::Network;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::asmap::AsMap;
use crate::netaddr::{parse_net_addr, NetAddr, OnlyNet};
use crate::netgroup::{netgroup, select_diverse};

#[doc(hidden)]
pub fn net_addr_unspecified(addr: NetAddr) -> bool {
    matches!(addr, NetAddr::Ip(s) if s.ip().is_unspecified())
}

/// Skip a recently dialed addr while any other candidate remains.
pub const DIAL_ATTEMPT_RECENT: Duration = Duration::from_secs(10 * 60);

#[doc(hidden)]
pub fn attempt_is_recent(when: Instant, now: Instant) -> bool {
    matches!(
        now.saturating_duration_since(when)
            .cmp(&DIAL_ATTEMPT_RECENT),
        std::cmp::Ordering::Less
    )
}

/// Service bits we advertise and ask DNS seeds for (`NETWORK|WITNESS|P2P_V2` = `0x809`).
pub fn required_seed_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2
}

/// DNS seed service-bit filter hostname (`x<hex>.<seed>`).
pub fn dns_seed_query_host(seed: &str, services: ServiceFlags) -> String {
    format!("x{:x}.{seed}", services.to_u64())
}

/// DNS seed hostnames (resolve at runtime with default port).
///
/// Core `vSeeds` in `src/kernel/chainparams.cpp`, in Core's order.
pub fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &[
            "dnsseed.bluematt.me",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz",
            "seed.mainnet.achownodes.xyz",
        ],
        Network::Testnet => &[
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "testnet-seed.bluematt.me",
            "seed.testnet.achownodes.xyz",
        ],
        Network::Signet => &[
            "seed.signet.bitcoin.sprovoost.nl",
            "seed.signet.achownodes.xyz",
        ],
        Network::Regtest => &[],
    }
}

/// Core `contrib/seeds/nodes_<net>.txt`, the input to Core's
/// `chainparamsseeds.h`. Refresh with `scripts/core-fixed-seeds.sh COMMIT`.
fn fixed_seed_text(network: Network) -> &'static str {
    match network {
        Network::Mainnet => include_str!("../seeds/nodes_main.txt"),
        Network::Testnet => include_str!("../seeds/nodes_test.txt"),
        Network::Signet => include_str!("../seeds/nodes_signet.txt"),
        Network::Regtest => "",
    }
}

/// Core's fixed seeds for `network` (IPv4, IPv6, Tor v3, I2P, CJDNS), in
/// Core's order.
///
/// The table stays Core's text so a refresh is a byte copy that diffs
/// against Core. The parse runs once per start, over about 2,000 lines.
#[doc(hidden)]
pub fn fixed_seeds(network: Network) -> Vec<NetAddr> {
    fixed_seed_text(network)
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(addr, _)| addr).trim())
        .filter(|addr| !addr.is_empty())
        .map(|addr| parse_net_addr(addr).expect("Core fixed seed parses"))
        .collect()
}

/// Default P2P port for a network.
pub fn default_port(network: Network) -> u16 {
    network.default_p2p_port()
}

/// Default JSON-RPC TCP port for a network (Core-matching).
pub fn default_rpc_port(network: Network) -> u16 {
    network.default_rpc_port()
}

/// Per listed seed: Core `x<hex>.` filter hostname first, then the bare seed.
pub fn seed_lookup_names(network: Network) -> Vec<Vec<String>> {
    let bits = required_seed_services();
    dns_seeds(network)
        .iter()
        .map(|seed| vec![dns_seed_query_host(seed, bits), (*seed).to_string()])
        .collect()
}

/// Prefer the x-filter A/AAAA set when it is non-empty; otherwise the unfiltered set.
pub fn pick_seed_results(x_ips: &[SocketAddr], plain_ips: &[SocketAddr]) -> Vec<SocketAddr> {
    if !x_ips.is_empty() {
        x_ips.to_vec()
    } else {
        plain_ips.to_vec()
    }
}

#[doc(hidden)]
pub fn resolve_host_port(host: &str, port: u16) -> Vec<SocketAddr> {
    let with_port = format!("{host}:{port}");
    match with_port.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolve DNS seed hostnames to socket addresses using the network default port.
///
/// Each seed is queried as `x809.<seed>` first. If that name returns no
/// addresses, the unfiltered seed name is tried. First success wins per seed
/// so the same IPs are not injected twice.
pub fn resolve_dns_seeds(network: Network) -> Vec<SocketAddr> {
    let port = default_port(network);
    let mut out = Vec::new();
    for names in seed_lookup_names(network) {
        let x_ips = names
            .first()
            .map(|h| resolve_host_port(h, port))
            .unwrap_or_default();
        let plain_ips = if x_ips.is_empty() {
            names
                .get(1)
                .map(|h| resolve_host_port(h, port))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for a in pick_seed_results(&x_ips, &plain_ips) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

/// DNS seed hostnames with the network default port for SOCKS domain CONNECT.
///
/// Does not call [`ToSocketAddrs`] — the proxy performs remote DNS.
pub fn socks_dns_seed_dests(network: Network) -> Vec<(String, u16)> {
    let port = default_port(network);
    dns_seeds(network)
        .iter()
        .map(|host| ((*host).to_string(), port))
        .collect()
}

/// Informational peer flags packed into one byte (more bits reserved for later).
///
/// | bit | name | meaning |
/// |-----|------|---------|
/// | 0 | `HAS_CONNECTED` | Successful BIP324 handshake at least once |
/// | 1 | `FAST` | Observed <100 ms first-data latency and >10 Mbps |
/// | 2 | `SLOW` | Observed >250 ms latency or <1 Mbps |
/// | 3 | `INCOMPATIBLE` | No v2 transport (or similar protocol reject) |
/// | 4 | `FAILED_LAST_CONNECT` | Last dial failed for network/timeout reasons |
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct PeerFlags(pub u8);

impl PeerFlags {
    pub const HAS_CONNECTED: u8 = 1 << 0;
    pub const FAST: u8 = 1 << 1;
    pub const SLOW: u8 = 1 << 2;
    pub const INCOMPATIBLE: u8 = 1 << 3;
    pub const FAILED_LAST_CONNECT: u8 = 1 << 4;

    /// Latency below this and throughput above [`Self::FAST_BPS_MIN`] → `FAST`.
    pub const FAST_LATENCY_MS: u64 = 100;
    /// Throughput floor for `FAST` (10 Mbps = 1.25 MB/s).
    pub const FAST_BPS_MIN: u64 = 10_000_000 / 8;
    /// Latency above this **or** throughput below [`Self::SLOW_BPS_MAX`] → `SLOW`.
    pub const SLOW_LATENCY_MS: u64 = 250;
    /// Throughput ceiling for `SLOW` (1 Mbps = 125 KB/s).
    pub const SLOW_BPS_MAX: u64 = 1_000_000 / 8;

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    #[inline]
    pub fn insert(&mut self, bit: u8) {
        self.0 |= bit;
    }

    #[inline]
    pub fn remove(&mut self, bit: u8) {
        self.0 &= !bit;
    }

    #[inline]
    pub fn set(&mut self, bit: u8, on: bool) {
        if on {
            self.insert(bit);
        } else {
            self.remove(bit);
        }
    }

    pub fn has_connected(self) -> bool {
        self.contains(Self::HAS_CONNECTED)
    }
    pub fn is_fast(self) -> bool {
        self.contains(Self::FAST)
    }
    pub fn is_slow(self) -> bool {
        self.contains(Self::SLOW)
    }
    pub fn is_incompatible(self) -> bool {
        self.contains(Self::INCOMPATIBLE)
    }
    pub fn failed_last_connect(self) -> bool {
        self.contains(Self::FAILED_LAST_CONNECT)
    }

    /// Never dialed / no outcome recorded yet.
    pub fn is_untried(self) -> bool {
        self.0 == 0
    }

    /// Dial preference tier: **0 = preferred**, **1 = ok**, **2 = last resort**.
    ///
    /// Preferred: untried, fast, or previously connected without failure/slow/incompat.
    /// Last resort: incompatible or failed last connect.
    pub fn dial_tier(self) -> u8 {
        if self.is_incompatible() || self.failed_last_connect() {
            return 2;
        }
        if self.is_slow() && !self.is_fast() {
            return 1;
        }
        0
    }

    /// Update `FAST` / `SLOW` from a measured sample. Clears the opposite bit.
    pub fn apply_speed_sample(&mut self, latency_ms: u64, bytes_per_sec: u64) {
        let fast = latency_ms < Self::FAST_LATENCY_MS && bytes_per_sec > Self::FAST_BPS_MIN;
        let slow = latency_ms > Self::SLOW_LATENCY_MS || bytes_per_sec < Self::SLOW_BPS_MAX;
        if fast {
            self.insert(Self::FAST);
            self.remove(Self::SLOW);
        } else if slow {
            self.insert(Self::SLOW);
            self.remove(Self::FAST);
        }
        // else: mid-range — leave prior classification
    }
}

/// One remembered peer address + flags.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub addr: NetAddr,
    pub flags: PeerFlags,
}

/// Hard cap for learned / `peers` file / addrv2 (not `--connect` / DNS inject).
///
/// Ours, not a Core constant (Core uses new/tried buckets). Must stay
/// strictly above Core GetAddr
/// [`MAX_ADDR_TO_SEND`](crate::peer::MAX_ADDR_TO_SEND) /
/// [`MAX_PCT_ADDR_TO_SEND`](crate::peer::MAX_PCT_ADDR_TO_SEND)
/// (`1000 / 0.23`) so a reply can still be 1000 addresses.
pub const MAX_ADDR_MAN: usize = 8192;

/// Peer book: seeds, learned addrs, and dial ranking.
#[derive(Debug, Default, Clone)]
pub struct AddrMan {
    /// Insertion-order keys (IPv4 preferred on inject).
    pub order: Vec<NetAddr>,
    pub by_addr: HashMap<NetAddr, PeerFlags>,
    pub asmap: Option<Arc<AsMap>>,
    pub last_attempt: HashMap<NetAddr, Instant>,
    pub only_net: Vec<OnlyNet>,
    /// `--proxy` or `--onion`. Default off: an onion row is not a peer.
    pub onion_reachable: bool,
    /// `--i2p-sam`. Default off.
    pub i2p_reachable: bool,
    pub cjdns_reachable: bool,
}

impl AddrMan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_asmap(&mut self, asmap: Option<Arc<AsMap>>) {
        self.asmap = asmap;
    }

    pub fn asmap(&self) -> Option<&AsMap> {
        self.asmap.as_deref()
    }

    pub fn inject(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for a in addrs {
            if crate::netaddr::clearnet_unroutable(a.ip()) {
                continue;
            }
            self.add(a);
        }
        self.sort_order_ipv4_first();
    }

    /// Core's fixed-seed fallback (`ThreadOpenConnections`): add `network`'s
    /// [`fixed_seeds`] for each net this process can dial that has no row in
    /// the book. Returns how many rows were added.
    pub fn add_fixed_seeds(&mut self, network: Network) -> usize {
        let present: Vec<OnlyNet> = OnlyNet::ALL
            .into_iter()
            .filter(|net| self.order.iter().any(|a| OnlyNet::of(*a) == *net))
            .collect();
        let mut added = 0;
        for addr in fixed_seeds(network) {
            let net = OnlyNet::of(addr);
            if present.contains(&net) || !self.reachable(net) || self.by_addr.contains_key(&addr) {
                continue;
            }
            self.add_addr(addr);
            added += 1;
        }
        self.sort_order_ipv4_first();
        added
    }

    pub fn set_only_net(&mut self, only: Vec<OnlyNet>) {
        self.only_net = only;
        self.retain_dialable();
    }

    pub fn set_onion_reachable(&mut self, on: bool) {
        self.onion_reachable = on;
        self.retain_dialable();
    }

    pub fn set_i2p_reachable(&mut self, on: bool) {
        self.i2p_reachable = on;
        self.retain_dialable();
    }

    pub fn set_cjdns_reachable(&mut self, on: bool) {
        self.cjdns_reachable = on;
        self.retain_dialable();
    }

    pub fn reachable(&self, net: OnlyNet) -> bool {
        if !self.only_net.is_empty() && !self.only_net.contains(&net) {
            return false;
        }
        match net {
            OnlyNet::Ipv4 | OnlyNet::Ipv6 => true,
            OnlyNet::Onion => self.onion_reachable,
            OnlyNet::I2p => self.i2p_reachable,
            OnlyNet::Cjdns => self.cjdns_reachable,
        }
    }

    #[doc(hidden)]
    pub fn dialable(&self, addr: NetAddr) -> bool {
        self.reachable(OnlyNet::of(addr))
    }

    #[doc(hidden)]
    pub fn retain_dialable(&mut self) {
        let gone: Vec<NetAddr> = self
            .order
            .iter()
            .copied()
            .filter(|a| !self.dialable(*a))
            .collect();
        for addr in gone {
            self.evict_one(addr);
        }
    }

    /// Like [`Self::take_dial_candidates`] plus onion and I2P rows this process can dial.
    pub fn take_dial_candidates_net(
        &self,
        max: usize,
        exclude: &HashSet<NetAddr>,
        occupied: &[SocketAddr],
    ) -> Vec<NetAddr> {
        let ip_ex: HashSet<SocketAddr> = exclude
            .iter()
            .copied()
            .filter_map(NetAddr::socket_addr)
            .collect();
        let ip: Vec<NetAddr> = self
            .take_dial_candidates(max, &ip_ex, occupied)
            .into_iter()
            .map(NetAddr::from_socket)
            .collect();
        let now = Instant::now();
        let mut overlay: Vec<(u8, NetAddr)> = self
            .order
            .iter()
            .copied()
            .filter(|a| matches!(a, NetAddr::Onion { .. } | NetAddr::I2p { .. }))
            .filter(|a| self.dialable(*a) && !exclude.contains(a))
            .map(|a| (self.flags_of(&a).dial_tier(), a))
            .collect();
        overlay.sort_by_key(|(tier, _)| *tier);
        let ip_has_fresh = ip.iter().any(|a| self.flags_of(a).dial_tier() < 2);
        if ip_has_fresh {
            overlay.retain(|(tier, a)| {
                *tier < 2
                    && !self.flags_of(a).is_incompatible()
                    && !self.recently_attempted_addr(*a, now)
            });
        } else if overlay
            .iter()
            .any(|(_, a)| !self.flags_of(a).is_incompatible())
        {
            overlay.retain(|(_, a)| !self.flags_of(a).is_incompatible());
            if overlay
                .iter()
                .any(|(_, a)| !self.recently_attempted_addr(*a, now))
            {
                overlay.retain(|(_, a)| !self.recently_attempted_addr(*a, now));
            }
        }
        let mut out = ip;
        // A full clearnet batch used to return before any onion or I2P row.
        // Keep one slot for the best eligible overlay when the batch has room
        // for more than a single peer.
        if !overlay.is_empty() && out.len() >= max && max >= 2 {
            out.pop();
        }
        for (_, a) in overlay {
            if out.len() >= max {
                break;
            }
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    #[doc(hidden)]
    pub fn recently_attempted_addr(&self, addr: NetAddr, now: Instant) -> bool {
        self.last_attempt
            .get(&addr)
            .is_some_and(|&t| attempt_is_recent(t, now))
    }

    pub fn add(&mut self, addr: SocketAddr) {
        self.add_addr(NetAddr::from_socket(addr));
    }

    pub fn add_addr(&mut self, addr: NetAddr) {
        if !self.dialable(addr) {
            return;
        }
        if self.by_addr.contains_key(&addr) {
            return;
        }
        if self.order.len() >= MAX_ADDR_MAN {
            let _ = self.evict_oldest_new();
        }
        self.by_addr.insert(addr, PeerFlags::empty());
        self.order.push(addr);
    }

    /// Insert or keep existing; never clears known flags when already present.
    ///
    /// Uncapped so `merge_from` can union then trim. A row this process cannot
    /// dial is dropped. [`Self::load`] restores the file, then the caller sets
    /// reachability.
    pub fn add_with_flags(&mut self, addr: SocketAddr, flags: PeerFlags) {
        self.add_with_flags_addr(NetAddr::from_socket(addr), flags);
    }

    pub fn add_with_flags_addr(&mut self, addr: NetAddr, flags: PeerFlags) {
        if !self.dialable(addr) {
            if self.by_addr.contains_key(&addr) {
                self.evict_one(addr);
            }
            return;
        }
        self.remember(addr, flags);
    }

    /// Insert without a reachability check. [`Self::load`] restores the file,
    /// then the caller sets which nets this process can dial.
    #[doc(hidden)]
    pub fn remember(&mut self, addr: NetAddr, flags: PeerFlags) {
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.0 |= flags.0;
            return;
        }
        self.by_addr.insert(addr, flags);
        self.order.push(addr);
    }

    /// Insert a newly learned addr, evicting last-resort then oldest new at `cap`.
    ///
    /// Returns true when `addr` is now in the book. Duplicates, an already
    /// over-cap book (`add` exceed), and a full book of only tried addrs
    /// return false. Never exceeds `cap`.
    pub fn add_learned(&mut self, addr: SocketAddr, cap: usize) -> bool {
        self.add_learned_addr(NetAddr::from_socket(addr), cap)
    }

    pub fn add_learned_addr(&mut self, addr: NetAddr, cap: usize) -> bool {
        if !self.dialable(addr) {
            return false;
        }
        if self.by_addr.contains_key(&addr) || cap == 0 {
            return false;
        }
        if self.order.len() > cap {
            return false;
        }
        if self.order.len() == cap && !self.evict_for_learn() {
            return false;
        }
        self.by_addr.insert(addr, PeerFlags::empty());
        self.order.push(addr);
        true
    }

    #[doc(hidden)]
    pub fn evict_one(&mut self, addr: NetAddr) {
        self.by_addr.remove(&addr);
        self.last_attempt.remove(&addr);
        self.order.retain(|a| *a != addr);
    }

    #[doc(hidden)]
    pub fn evict_oldest_new(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| !self.flags_of(a).has_connected());
        let Some(addr) = victim else {
            return false;
        };
        self.evict_one(addr);
        true
    }

    #[doc(hidden)]
    pub fn evict_for_learn(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| self.flags_of(a).is_incompatible())
            .or_else(|| {
                self.order
                    .iter()
                    .copied()
                    .find(|a| self.flags_of(a).failed_last_connect())
            });
        if let Some(addr) = victim {
            self.evict_one(addr);
            return true;
        }
        self.evict_oldest_new()
    }

    #[doc(hidden)]
    pub fn trim_to_cap(&mut self, cap: usize) {
        if self.order.len() <= cap {
            return;
        }
        let mut keep: Vec<NetAddr> = self
            .order
            .iter()
            .copied()
            .filter(|a| self.flags_of(a).has_connected())
            .collect();
        keep.extend(
            self.order
                .iter()
                .copied()
                .filter(|a| !self.flags_of(a).has_connected()),
        );
        keep.truncate(cap);
        let keep_set: HashSet<NetAddr> = keep.iter().copied().collect();
        self.order = keep;
        self.by_addr.retain(|a, _| keep_set.contains(a));
        self.last_attempt.retain(|a, _| keep_set.contains(a));
    }

    /// Merge another book into this one (flag bits OR'd for shared addrs).
    ///
    /// Rows this process cannot dial are left out. Trim after the union.
    pub fn merge_from(&mut self, other: &AddrMan) {
        for e in other.entries() {
            self.add_with_flags_addr(e.addr, e.flags);
        }
        self.trim_to_cap(MAX_ADDR_MAN);
        self.sort_order_ipv4_first();
    }

    #[doc(hidden)]
    pub fn sort_order_ipv4_first(&mut self) {
        // Prefer IPv4: many lab hosts have no IPv6 route, and IPv6 seeds only
        // burn connect-timeout slots during IBD dial.
        self.order.sort_by_key(|a| a.is_ipv6());
    }

    pub fn peers(&self) -> Vec<SocketAddr> {
        self.order
            .iter()
            .copied()
            .filter_map(NetAddr::socket_addr)
            .collect()
    }

    pub fn flags(&self, addr: &SocketAddr) -> PeerFlags {
        self.flags_of(&NetAddr::from_socket(*addr))
    }

    pub fn connect_failed(&self, addr: NetAddr) -> bool {
        self.flags_of(&addr).failed_last_connect()
    }

    #[doc(hidden)]
    pub fn flags_of(&self, addr: &NetAddr) -> PeerFlags {
        self.by_addr
            .get(addr)
            .copied()
            .unwrap_or_else(PeerFlags::empty)
    }

    #[doc(hidden)]
    pub fn entry_of(&self, addr: &NetAddr) -> Option<PeerEntry> {
        self.by_addr
            .get(addr)
            .map(|&flags| PeerEntry { addr: *addr, flags })
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Successful BIP324 handshake.
    pub fn note_connected_addr(&mut self, addr: NetAddr) {
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.remove(PeerFlags::FAILED_LAST_CONNECT);
            f.remove(PeerFlags::INCOMPATIBLE);
        }
    }

    /// Record a dial attempt at `when`. Not persisted.
    pub fn note_attempt_at(&mut self, addr: SocketAddr, when: Instant) {
        self.last_attempt.insert(NetAddr::from_socket(addr), when);
    }

    pub fn last_attempt_of(&self, addr: NetAddr) -> Option<Instant> {
        self.last_attempt.get(&addr).copied()
    }

    pub fn dial_order(&self) -> &[NetAddr] {
        &self.order
    }

    pub fn is_dialable(&self, addr: NetAddr) -> bool {
        self.by_addr.contains_key(&addr) && self.dialable(addr)
    }

    pub fn note_attempt_addr(&mut self, addr: NetAddr) {
        self.last_attempt.insert(addr, Instant::now());
    }

    #[doc(hidden)]
    pub fn recently_attempted(&self, addr: SocketAddr, now: Instant) -> bool {
        self.recently_attempted_addr(NetAddr::from_socket(addr), now)
    }

    /// Dial failed. `incompatible` = no v2 / protocol reject; else network/timeout.
    pub fn note_connect_failed_addr(&mut self, addr: NetAddr, incompatible: bool) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            if incompatible {
                f.insert(PeerFlags::INCOMPATIBLE);
                f.remove(PeerFlags::FAILED_LAST_CONNECT);
            } else {
                f.insert(PeerFlags::FAILED_LAST_CONNECT);
            }
        }
    }

    /// Throughput / latency sample from an active session.
    pub fn note_speed_addr(&mut self, addr: NetAddr, latency_ms: u64, bytes_per_sec: u64) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.apply_speed_sample(latency_ms, bytes_per_sec);
        }
    }

    /// IBD stall / relative-slow: force `SLOW`, clear `FAST` (mid-range samples
    /// would otherwise leave a prior FAST bit and keep `dial_tier` 0).
    pub fn note_ibd_slow_addr(&mut self, addr: NetAddr) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.insert(PeerFlags::SLOW);
            f.remove(PeerFlags::FAST);
        }
    }

    /// `Dead` speed sample, then IBD-outlier override when `ibd_outlier`.
    pub fn apply_ibd_dead_speed_addr(
        &mut self,
        addr: NetAddr,
        latency_ms: u64,
        bps: Option<u64>,
        ibd_outlier: bool,
    ) {
        if net_addr_unspecified(addr) {
            return;
        }
        if let Some(bps) = bps {
            self.note_speed_addr(addr, latency_ms, bps);
        }
        if ibd_outlier {
            self.note_ibd_slow_addr(addr);
        }
    }

    /// Ranked dial list: tier 0 first (untried / fast / good history), then slow,
    /// then failed-last-connect. Within a tier, IPv4 before IPv6.
    ///
    /// `INCOMPATIBLE` is omitted while any other candidate remains so a mixed
    /// book does not burn outbound slots on known-v1. If every remaining addr
    /// is incompatible, those are returned as last-resort.
    ///
    /// [`select_diverse`] runs **per tier**: unused netgroups of `occupied`
    /// (live peers) first, then fill. An occupied-group tier-0 addr always
    /// beats an unused-group last-resort addr.
    ///
    /// Addrs attempted within [`DIAL_ATTEMPT_RECENT`] are omitted while any
    /// other candidate remains.
    pub fn take_dial_candidates(
        &self,
        max: usize,
        exclude: &HashSet<SocketAddr>,
        occupied: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        if max == 0 || self.order.is_empty() {
            return Vec::new();
        }
        let mut ranked: Vec<(u8, bool, bool, SocketAddr)> = self
            .order
            .iter()
            .copied()
            .filter_map(|a| {
                if !self.dialable(a) {
                    return None;
                }
                let sock = a.socket_addr()?;
                if exclude.contains(&sock) {
                    return None;
                }
                let f = self.flags_of(&a);
                Some((f.dial_tier(), sock.is_ipv6(), f.is_incompatible(), sock))
            })
            .collect();
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        if ranked.iter().any(|(_, _, incompat, _)| !*incompat) {
            ranked.retain(|(_, _, incompat, _)| !*incompat);
        }
        let now = Instant::now();
        if ranked
            .iter()
            .any(|(_, _, _, a)| !self.recently_attempted(*a, now))
        {
            ranked.retain(|(_, _, _, a)| !self.recently_attempted(*a, now));
        }
        let asmap = self.asmap.as_deref();
        let mut occupied_groups: HashSet<u64> =
            occupied.iter().map(|a| netgroup(*a, asmap)).collect();
        let mut out = Vec::new();
        for tier in 0u8..=2 {
            if out.len() >= max {
                break;
            }
            let slice: Vec<SocketAddr> = ranked
                .iter()
                .filter(|(t, _, _, _)| *t == tier)
                .map(|(_, _, _, a)| *a)
                .collect();
            if slice.is_empty() {
                continue;
            }
            let need = max - out.len();
            let picked = select_diverse(&slice, need, &occupied_groups, |a| netgroup(a, asmap));
            for &a in &picked {
                occupied_groups.insert(netgroup(a, asmap));
            }
            out.extend(picked);
        }
        out
    }

    /// Round-robin-ish: take up to `max` peers starting at `offset`.
    /// Still prefers better dial tiers by walking a ranked list.
    pub fn take_outbound_offset_occupied(
        &self,
        max: usize,
        offset: usize,
        occupied: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        if self.order.is_empty() || max == 0 {
            return Vec::new();
        }
        let exclude: HashSet<SocketAddr> = occupied.iter().copied().collect();
        let ranked = self.take_dial_candidates(self.order.len(), &exclude, occupied);
        if ranked.is_empty() {
            return Vec::new();
        }
        let n = ranked.len();
        let mut out = Vec::with_capacity(max.min(n));
        for i in 0..max.min(n) {
            out.push(ranked[(offset + i) % n]);
        }
        out
    }

    /// Snapshot of all entries (for tests / diagnostics).
    pub fn entries(&self) -> Vec<PeerEntry> {
        self.order.iter().filter_map(|a| self.entry_of(a)).collect()
    }

    /// On-disk format magic line (text, one peer per line).
    pub const PEERS_FILE_MAGIC: &'static str = "rbitcoin-peers-v1";
    pub const PEERS_FILE_MAGIC_V2: &'static str = "rbitcoin-peers-v2";

    /// Load peers + flags from `path`. Missing file → empty book (not an error).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let f = std::fs::File::open(path)?;
        let reader = BufReader::new(f);
        let mut am = Self::new();
        let mut saw_magic = false;
        for (lineno, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !saw_magic {
                if line != Self::PEERS_FILE_MAGIC && line != Self::PEERS_FILE_MAGIC_V2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: expected magic `{}` or `{}`",
                            path.display(),
                            lineno + 1,
                            Self::PEERS_FILE_MAGIC,
                            Self::PEERS_FILE_MAGIC_V2
                        ),
                    ));
                }
                saw_magic = true;
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(addr_s) = parts.next() else {
                continue;
            };
            let flags_s = parts.next().unwrap_or("0");
            let addr: NetAddr = addr_s.parse().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "peers file {}:{}: bad addr: {e}",
                        path.display(),
                        lineno + 1
                    ),
                )
            })?;
            let flags_u: u8 = if let Some(hex) = flags_s
                .strip_prefix("0x")
                .or_else(|| flags_s.strip_prefix("0X"))
            {
                u8::from_str_radix(hex, 16).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: bad flags: {e}",
                            path.display(),
                            lineno + 1
                        ),
                    )
                })?
            } else {
                flags_s.parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: bad flags: {e}",
                            path.display(),
                            lineno + 1
                        ),
                    )
                })?
            };
            if crate::netaddr::netaddr_unroutable_gossip(addr) {
                continue;
            }
            am.remember(addr, PeerFlags(flags_u));
        }
        if !saw_magic && am.is_empty() {
            // Empty or comment-only without magic — treat as empty book.
            return Ok(Self::new());
        }
        am.trim_to_cap(MAX_ADDR_MAN);
        am.sort_order_ipv4_first();
        Ok(am)
    }

    /// Atomic save of peers + flags to `path` (`path.tmp` then rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            writeln!(f, "{}", Self::PEERS_FILE_MAGIC_V2)?;
            writeln!(
                f,
                "# addr flags  (flags: bit0=connected bit1=fast bit2=slow bit3=incompat bit4=fail)"
            )?;
            for e in self.entries() {
                writeln!(f, "{} 0x{:02x}", e.addr, e.flags.0)?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
