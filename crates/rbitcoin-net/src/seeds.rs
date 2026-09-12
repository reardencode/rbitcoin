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
use crate::netgroup::{netgroup, select_diverse};

/// Skip a recently dialed addr while any other candidate remains (Core `nLastTry`).
pub(crate) const DIAL_ATTEMPT_RECENT: Duration = Duration::from_secs(10 * 60);

/// Service bits we advertise and ask DNS seeds for (`NETWORK|WITNESS|P2P_V2` = `0x809`).
pub fn required_seed_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2
}

/// Core `x<hex>.<seed>` hostname (`strprintf("x%x.%s", nRequiredServiceBits, seed)`).
pub fn dns_seed_query_host(seed: &str, services: ServiceFlags) -> String {
    format!("x{:x}.{seed}", services.to_u64())
}

/// DNS seed hostnames (resolve at runtime with default port).
pub fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &[
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz",
        ],
        Network::Testnet => &[
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "testnet-seed.bluematt.me",
            "testnet-seed.bitcoin.schildbach.de",
        ],
        Network::Signet => &["seed.signet.bitcoin.sprovoost.nl"],
        Network::Regtest => &[],
    }
}

/// Hard-coded fallback seed addresses (host:port). Sparse; DNS is preferred.
pub fn fixed_seed_hosts(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &["seed.bitcoin.sipa.be:8333", "dnsseed.emzy.de:8333"],
        Network::Testnet => &["testnet-seed.bitcoin.jonasschnelli.ch:18333"],
        Network::Signet => &["seed.signet.bitcoin.sprovoost.nl:38333"],
        Network::Regtest => &[],
    }
}

/// Default P2P port for a network.
pub fn default_port(network: Network) -> u16 {
    match network {
        Network::Mainnet => 8333,
        Network::Testnet => 18333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
    }
}

/// Resolve fixed seed host strings to socket addresses (best-effort).
pub fn resolve_fixed_seeds(network: Network) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for host in fixed_seed_hosts(network) {
        if let Ok(iter) = host.to_socket_addrs() {
            out.extend(iter);
        }
    }
    out
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

fn resolve_host_port(host: &str, port: u16) -> Vec<SocketAddr> {
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

/// Resolve DNS + fixed seeds (DNS first, then fixed fallbacks). Deduplicated.
pub fn resolve_all_seeds(network: Network) -> Vec<SocketAddr> {
    let mut out = resolve_dns_seeds(network);
    for a in resolve_fixed_seeds(network) {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
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
    pub addr: SocketAddr,
    pub flags: PeerFlags,
}

/// Hard cap for learned / `peers` file / addrv2 (not `--connect` / DNS inject).
pub const MAX_ADDR_MAN: usize = 4096;

/// Peer book: seeds, learned addrs, and dial ranking.
#[derive(Debug, Default, Clone)]
pub struct AddrMan {
    /// Insertion-order keys (IPv4 preferred on inject).
    order: Vec<SocketAddr>,
    by_addr: HashMap<SocketAddr, PeerFlags>,
    asmap: Option<Arc<AsMap>>,
    last_attempt: HashMap<SocketAddr, Instant>,
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

    /// Populate from DNS seeds and fixed seed hosts.
    pub fn with_seeds(network: Network) -> Self {
        let mut a = Self::new();
        a.inject(resolve_all_seeds(network));
        a
    }

    pub fn inject(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for a in addrs {
            self.add(a);
        }
        self.sort_order_ipv4_first();
    }

    pub fn add(&mut self, addr: SocketAddr) {
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
    /// Uncapped so `load` can keep tried-first then trim. `merge_from` trims.
    pub fn add_with_flags(&mut self, addr: SocketAddr, flags: PeerFlags) {
        if let Some(f) = self.by_addr.get_mut(&addr) {
            // Union: remember the best information we have.
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

    fn evict_one(&mut self, addr: SocketAddr) {
        self.by_addr.remove(&addr);
        self.last_attempt.remove(&addr);
        self.order.retain(|a| *a != addr);
    }

    fn evict_oldest_new(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| !self.flags(a).has_connected());
        let Some(addr) = victim else {
            return false;
        };
        self.evict_one(addr);
        true
    }

    fn evict_for_learn(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| self.flags(a).is_incompatible())
            .or_else(|| {
                self.order
                    .iter()
                    .copied()
                    .find(|a| self.flags(a).failed_last_connect())
            });
        if let Some(addr) = victim {
            self.evict_one(addr);
            return true;
        }
        self.evict_oldest_new()
    }

    fn trim_to_cap(&mut self, cap: usize) {
        if self.order.len() <= cap {
            return;
        }
        let mut keep: Vec<SocketAddr> = self
            .order
            .iter()
            .copied()
            .filter(|a| self.flags(a).has_connected())
            .collect();
        keep.extend(
            self.order
                .iter()
                .copied()
                .filter(|a| !self.flags(a).has_connected()),
        );
        keep.truncate(cap);
        let keep_set: HashSet<SocketAddr> = keep.iter().copied().collect();
        self.order = keep;
        self.by_addr.retain(|a, _| keep_set.contains(a));
        self.last_attempt.retain(|a, _| keep_set.contains(a));
    }

    /// Merge another book into this one (flag bits OR'd for shared addrs).
    ///
    /// `add_with_flags` is uncapped so `load` can keep tried-first then trim.
    /// This path is not load: trim after the union.
    pub fn merge_from(&mut self, other: &AddrMan) {
        for e in other.entries() {
            self.add_with_flags(e.addr, e.flags);
        }
        self.trim_to_cap(MAX_ADDR_MAN);
        self.sort_order_ipv4_first();
    }

    fn sort_order_ipv4_first(&mut self) {
        // Prefer IPv4: many lab hosts have no IPv6 route, and IPv6 seeds only
        // burn connect-timeout slots during IBD dial.
        self.order.sort_by_key(|a| a.is_ipv6());
    }

    pub fn peers(&self) -> &[SocketAddr] {
        &self.order
    }

    pub fn flags(&self, addr: &SocketAddr) -> PeerFlags {
        self.by_addr
            .get(addr)
            .copied()
            .unwrap_or_else(PeerFlags::empty)
    }

    pub fn entry(&self, addr: &SocketAddr) -> Option<PeerEntry> {
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
    pub fn note_connected(&mut self, addr: SocketAddr) {
        self.add(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.remove(PeerFlags::FAILED_LAST_CONNECT);
            f.remove(PeerFlags::INCOMPATIBLE);
        }
    }

    /// Record a dial attempt. Not persisted.
    pub fn note_attempt(&mut self, addr: SocketAddr) {
        self.note_attempt_at(addr, Instant::now());
    }

    pub(crate) fn note_attempt_at(&mut self, addr: SocketAddr, when: Instant) {
        self.last_attempt.insert(addr, when);
    }

    fn recently_attempted(&self, addr: SocketAddr, now: Instant) -> bool {
        self.last_attempt
            .get(&addr)
            .is_some_and(|&t| now.saturating_duration_since(t) < DIAL_ATTEMPT_RECENT)
    }

    /// Dial failed. `incompatible` = no v2 / protocol reject; else network/timeout.
    pub fn note_connect_failed(&mut self, addr: SocketAddr, incompatible: bool) {
        self.add(addr);
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
    pub fn note_speed(&mut self, addr: SocketAddr, latency_ms: u64, bytes_per_sec: u64) {
        self.add(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.apply_speed_sample(latency_ms, bytes_per_sec);
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
            .filter(|a| !exclude.contains(*a))
            .map(|&a| {
                let f = self.flags(&a);
                (f.dial_tier(), a.is_ipv6(), f.is_incompatible(), a)
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

    /// Round-robin-ish: take up to `max` peers starting at `offset` (legacy helper).
    /// Still prefers better dial tiers by walking a ranked list.
    pub fn take_outbound_offset(&self, max: usize, offset: usize) -> Vec<SocketAddr> {
        self.take_outbound_offset_occupied(max, offset, &[])
    }

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

    /// Best up-to-`max` outbound candidates (ranked).
    pub fn take_outbound(&self, max: usize) -> Vec<SocketAddr> {
        self.take_dial_candidates(max, &HashSet::new(), &[])
    }

    pub fn take_outbound_occupied(&self, max: usize, occupied: &[SocketAddr]) -> Vec<SocketAddr> {
        let exclude: HashSet<SocketAddr> = occupied.iter().copied().collect();
        self.take_dial_candidates(max, &exclude, occupied)
    }

    /// Snapshot of all entries (for tests / diagnostics).
    pub fn entries(&self) -> Vec<PeerEntry> {
        self.order.iter().filter_map(|a| self.entry(a)).collect()
    }

    /// On-disk format magic line (text, one peer per line).
    pub const PEERS_FILE_MAGIC: &'static str = "rbitcoin-peers-v1";

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
                if line != Self::PEERS_FILE_MAGIC {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: expected magic `{}`",
                            path.display(),
                            lineno + 1,
                            Self::PEERS_FILE_MAGIC
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
            let addr: SocketAddr = addr_s.parse().map_err(|e| {
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
            am.add_with_flags(addr, PeerFlags(flags_u));
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
            writeln!(f, "{}", Self::PEERS_FILE_MAGIC)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, o)), 8333)
    }

    fn addr_n(i: u32) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            )),
            8333,
        )
    }

    #[test]
    fn dial_tier_preferred_vs_last_resort() {
        assert_eq!(PeerFlags::empty().dial_tier(), 0); // untried
        let mut f = PeerFlags::empty();
        f.insert(PeerFlags::HAS_CONNECTED);
        assert_eq!(f.dial_tier(), 0);
        f.insert(PeerFlags::FAST);
        assert_eq!(f.dial_tier(), 0);

        let mut slow = PeerFlags::empty();
        slow.insert(PeerFlags::HAS_CONNECTED);
        slow.insert(PeerFlags::SLOW);
        assert_eq!(slow.dial_tier(), 1);

        let mut bad = PeerFlags::empty();
        bad.insert(PeerFlags::FAILED_LAST_CONNECT);
        assert_eq!(bad.dial_tier(), 2);
        let mut inc = PeerFlags::empty();
        inc.insert(PeerFlags::INCOMPATIBLE);
        assert_eq!(inc.dial_tier(), 2);
    }

    #[test]
    fn speed_sample_sets_fast_or_slow() {
        let mut f = PeerFlags::empty();
        f.apply_speed_sample(50, PeerFlags::FAST_BPS_MIN + 1);
        assert!(f.is_fast());
        assert!(!f.is_slow());
        f.apply_speed_sample(300, 1000);
        assert!(f.is_slow());
        assert!(!f.is_fast());
    }

    #[test]
    fn take_dial_prefers_untried_and_good_over_failed() {
        let mut am = AddrMan::new();
        let good = addr(1);
        let untried = addr(2);
        let failed = addr(3);
        let incompat = addr(4);
        am.add(failed);
        am.add(incompat);
        am.add(good);
        am.add(untried);
        am.note_connected(good);
        am.note_connect_failed(failed, false);
        am.note_connect_failed(incompat, true);

        let got = am.take_dial_candidates(4, &HashSet::new(), &[]);
        assert_eq!(got.len(), 3);
        assert!(!got.contains(&incompat));
        let tiers: Vec<u8> = got.iter().map(|a| am.flags(a).dial_tier()).collect();
        assert_eq!(tiers[0], 0);
        assert_eq!(tiers[1], 0);
        assert_eq!(tiers[2], 2);
        assert!(am.flags(&got[2]).failed_last_connect());
    }

    #[test]
    fn take_dial_skips_incompatible_while_good_remain() {
        let mut am = AddrMan::new();
        let good = addr(1);
        let untried = addr(2);
        let failed = addr(3);
        let incompat_a = addr(4);
        let incompat_b = addr(5);
        am.add(good);
        am.add(untried);
        am.add(failed);
        am.add(incompat_a);
        am.add(incompat_b);
        am.note_connected(good);
        am.note_connect_failed(failed, false);
        am.note_connect_failed(incompat_a, true);
        am.note_connect_failed(incompat_b, true);

        let got = am.take_dial_candidates(48, &HashSet::new(), &[]);
        assert!(
            got.iter().all(|a| !am.flags(a).is_incompatible()),
            "INCOMPATIBLE must not fill the batch while any other addr remains: {got:?}"
        );
        assert!(got.contains(&good));
        assert!(got.contains(&untried));
        assert!(got.contains(&failed), "FAILED_LAST_CONNECT stays retryable");
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn take_dial_incompatible_when_nothing_else() {
        let mut am = AddrMan::new();
        let a = addr(1);
        let b = addr(2);
        am.add(a);
        am.add(b);
        am.note_connect_failed(a, true);
        am.note_connect_failed(b, true);
        let got = am.take_dial_candidates(48, &HashSet::new(), &[]);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&a));
        assert!(got.contains(&b));
    }

    #[test]
    fn exclude_skips_blocked() {
        let mut am = AddrMan::new();
        am.add(addr(1));
        am.add(addr(2));
        let mut ex = HashSet::new();
        ex.insert(addr(1));
        let got = am.take_dial_candidates(10, &ex, &[]);
        assert_eq!(got, vec![addr(2)]);
    }

    fn slash16(a: u8, b: u8, host: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, 0, host)), 8333)
    }

    #[test]
    fn take_dial_same_slash16_still_fills() {
        let mut am = AddrMan::new();
        for i in 1..=16 {
            am.add(slash16(1, 2, i));
        }
        let got = am.take_dial_candidates(16, &HashSet::new(), &[]);
        assert_eq!(got.len(), 16);
    }

    #[test]
    fn take_dial_mixed_groups_picks_distinct() {
        let mut am = AddrMan::new();
        for g in 1u8..=32 {
            am.add(slash16(g, 0, 1));
        }
        let got = am.take_dial_candidates(16, &HashSet::new(), &[]);
        assert_eq!(got.len(), 16);
        let groups: HashSet<u64> = got.iter().map(|a| netgroup(*a, None)).collect();
        assert_eq!(groups.len(), 16);
    }

    #[test]
    fn take_dial_skips_occupied_group() {
        let mut am = AddrMan::new();
        am.add(slash16(1, 2, 1));
        am.add(slash16(1, 3, 1));
        let occupied = [slash16(1, 2, 9)];
        let got = am.take_dial_candidates(1, &HashSet::new(), &occupied);
        assert_eq!(got, vec![slash16(1, 3, 1)]);
    }

    #[test]
    fn take_dial_occupied_group_tier0_beats_unused_group_last_resort() {
        let mut am = AddrMan::new();
        let good_same = slash16(1, 2, 1);
        let lemon = slash16(9, 9, 1);
        am.add(good_same);
        am.add(lemon);
        am.note_connected(good_same);
        am.note_connect_failed(lemon, false);
        let occupied = [slash16(1, 2, 9)];
        let got = am.take_dial_candidates(1, &HashSet::new(), &occupied);
        assert_eq!(
            got,
            vec![good_same],
            "diversity must not pick a last-resort unused group ahead of a preferred occupied-group addr"
        );
    }

    #[test]
    fn take_dial_skips_recent_attempt_while_others_remain() {
        let mut am = AddrMan::new();
        am.add(addr(1));
        am.add(addr(2));
        am.note_attempt(addr(1));
        let got = am.take_dial_candidates(2, &HashSet::new(), &[]);
        assert_eq!(got, vec![addr(2)]);

        let mut only = AddrMan::new();
        only.add(addr(1));
        only.note_attempt(addr(1));
        assert_eq!(
            only.take_dial_candidates(1, &HashSet::new(), &[]),
            vec![addr(1)],
            "sole remaining addr is still dialed even if recently attempted"
        );

        let mut aged = AddrMan::new();
        aged.add(addr(1));
        aged.add(addr(2));
        let old = Instant::now()
            .checked_sub(DIAL_ATTEMPT_RECENT + Duration::from_secs(1))
            .expect("clock");
        aged.note_attempt_at(addr(1), old);
        let got = aged.take_dial_candidates(2, &HashSet::new(), &[]);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&addr(1)));
        assert!(got.contains(&addr(2)));
    }

    #[test]
    fn add_learned_evicts_failed_when_at_cap() {
        let mut am = AddrMan::new();
        for i in 1..=3 {
            am.add(addr(i));
            am.note_connect_failed(addr(i), i == 1);
        }
        assert!(am.add_learned(addr(9), 3));
        assert_eq!(am.len(), 3);
        assert!(am.entry(&addr(9)).is_some());
        assert!(
            am.entry(&addr(1)).is_none(),
            "incompatible is evicted before failed-last-connect"
        );
    }

    #[test]
    fn add_learned_keeps_good_when_full() {
        let mut am = AddrMan::new();
        for i in 1..=3 {
            am.add(addr(i));
            am.note_connected(addr(i));
        }
        assert!(!am.add_learned(addr(9), 3));
        assert_eq!(am.len(), 3);
        assert!(am.entry(&addr(9)).is_none());
        assert!(!am.add_learned(addr(1), 3));
    }

    #[test]
    fn add_learned_evicts_oldest_new_when_at_cap() {
        let mut am = AddrMan::new();
        for i in 1..=3 {
            am.add(addr(i));
        }
        assert!(am.add_learned(addr(9), 3));
        assert_eq!(am.len(), 3);
        assert!(am.entry(&addr(9)).is_some());
        assert!(
            am.entry(&addr(1)).is_none(),
            "oldest new is evicted after incompat/failed"
        );
        assert!(am.entry(&addr(2)).is_some());
        assert!(am.entry(&addr(3)).is_some());
    }

    #[test]
    fn add_learned_fills_past_getaddr_cache_pct() {
        // Core p2p_getaddr_caching: getnodeaddresses(0) must be >
        // MAX_ADDR_TO_SEND / (MAX_PCT_ADDR_TO_SEND/100) so a GetAddr
        // reply can still be 1000 (23% of the book).
        const NEED: usize = 1000 * 100 / 23;
        let mut am = AddrMan::new();
        for i in 0..=NEED {
            assert!(
                am.add_learned(addr_n(i as u32), MAX_ADDR_MAN),
                "MAX_ADDR_MAN={} rejected insert {i} (need len > {NEED})",
                MAX_ADDR_MAN
            );
        }
        assert!(am.len() > NEED, "len={} need > {NEED}", am.len());
    }

    #[test]
    fn add_keeps_tried_and_may_exceed_cap() {
        let mut am = AddrMan::new();
        for i in 0..MAX_ADDR_MAN {
            let a = addr_n(i as u32);
            am.add(a);
            am.note_connected(a);
        }
        let extra = addr_n(MAX_ADDR_MAN as u32);
        am.add(extra);
        assert_eq!(am.len(), MAX_ADDR_MAN + 1);
        assert!(am.entry(&extra).is_some());
        assert!(am.entry(&addr_n(0)).is_some());
        assert!(!am.add_learned(addr_n(MAX_ADDR_MAN as u32 + 1), MAX_ADDR_MAN));
        assert_eq!(am.len(), MAX_ADDR_MAN + 1);
        assert!(am.entry(&extra).is_some());
    }

    #[test]
    fn add_evicts_oldest_new_at_cap() {
        let mut am = AddrMan::new();
        for i in 0..MAX_ADDR_MAN {
            am.add(addr_n(i as u32));
        }
        let extra = addr_n(MAX_ADDR_MAN as u32);
        am.add(extra);
        assert_eq!(am.len(), MAX_ADDR_MAN);
        assert!(am.entry(&extra).is_some());
        assert!(am.entry(&addr_n(0)).is_none());
        assert!(am.entry(&addr_n(1)).is_some());
    }

    #[test]
    fn merge_from_trims_to_cap_keeping_tried() {
        let mut a = AddrMan::new();
        for i in 0..MAX_ADDR_MAN {
            let x = addr_n(i as u32);
            a.add(x);
            a.note_connected(x);
        }
        let mut b = AddrMan::new();
        for i in 0..8 {
            b.add(addr_n(MAX_ADDR_MAN as u32 + i));
        }
        a.merge_from(&b);
        assert_eq!(a.len(), MAX_ADDR_MAN);
        assert!(
            a.entry(&addr_n(0)).is_some(),
            "tried addrs must survive merge trim"
        );
        assert!(
            a.entry(&addr_n(MAX_ADDR_MAN as u32)).is_none(),
            "extra new from the other book must not grow past cap"
        );
    }

    #[test]
    fn load_trims_tried_then_new_to_cap() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-peers-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("peers");
        let mut body = String::from("rbitcoin-peers-v1\n");
        let n_tried = 2000u32;
        let n_total = 5000u32;
        for i in 0..n_tried {
            body.push_str(&format!("{} 0x01\n", addr_n(i)));
        }
        for i in n_tried..n_total {
            body.push_str(&format!("{} 0x00\n", addr_n(i)));
        }
        std::fs::write(&path, body).unwrap();
        let loaded = AddrMan::load(&path).unwrap();
        assert_eq!(loaded.len(), MAX_ADDR_MAN);
        for i in 0..n_tried {
            assert!(
                loaded.entry(&addr_n(i)).is_some(),
                "tried {i} must survive trim"
            );
            assert!(loaded.flags(&addr_n(i)).has_connected());
        }
        let n_new_kept = MAX_ADDR_MAN - n_tried as usize;
        assert!(loaded.entry(&addr_n(n_tried)).is_some());
        assert!(loaded
            .entry(&addr_n(n_tried + n_new_kept as u32 - 1))
            .is_some());
        assert!(loaded.entry(&addr_n(n_total - 1)).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peers_file_roundtrip_preserves_flags() {
        let dir = std::env::temp_dir().join(format!("rbitcoin-peers-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("peers");
        let mut am = AddrMan::new();
        let a = addr(10);
        let b = addr(20);
        am.add(a);
        am.note_connected(a);
        am.note_speed(a, 40, PeerFlags::FAST_BPS_MIN + 100);
        am.add(b);
        am.note_connect_failed(b, true);
        am.save(&path).unwrap();

        let loaded = AddrMan::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.flags(&a).has_connected());
        assert!(loaded.flags(&a).is_fast());
        assert!(loaded.flags(&b).is_incompatible());

        // merge does not wipe flags when re-adding seed
        let mut merged = loaded;
        merged.add(a);
        assert!(merged.flags(&a).is_fast());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_lookup_names_x_filter_before_unfiltered() {
        let names = seed_lookup_names(Network::Mainnet);
        assert!(!names.is_empty());
        assert_eq!(names[0][0], "x809.seed.bitcoin.sipa.be");
        assert_eq!(names[0][1], "seed.bitcoin.sipa.be");
        for pair in &names {
            assert_eq!(pair.len(), 2);
            assert!(pair[0].starts_with("x809."), "{pair:?}");
            assert!(!pair[1].starts_with("x809."), "{pair:?}");
        }
        let signet = seed_lookup_names(Network::Signet);
        assert_eq!(
            signet,
            vec![vec![
                "x809.seed.signet.bitcoin.sprovoost.nl".to_string(),
                "seed.signet.bitcoin.sprovoost.nl".to_string(),
            ]]
        );
        assert!(seed_lookup_names(Network::Regtest).is_empty());
    }

    #[test]
    fn pick_seed_results_first_success_wins() {
        let x = addr(1);
        let plain = addr(2);
        assert_eq!(pick_seed_results(&[x], &[plain]), vec![x]);
        assert_eq!(pick_seed_results(&[], &[plain]), vec![plain]);
        assert!(pick_seed_results(&[], &[]).is_empty());
        assert_eq!(pick_seed_results(&[x, addr(3)], &[plain]), vec![x, addr(3)]);
    }

    #[test]
    fn dns_seed_query_host_matches_core_x_filter() {
        use bitcoin::p2p::ServiceFlags;
        let bits = required_seed_services();
        assert!(bits.has(ServiceFlags::NETWORK));
        assert!(bits.has(ServiceFlags::WITNESS));
        assert!(bits.has(ServiceFlags::P2P_V2));
        assert_eq!(bits.to_u64(), 0x809);
        assert_eq!(
            dns_seed_query_host("seed.bitcoin.sipa.be", bits),
            "x809.seed.bitcoin.sipa.be"
        );
        assert_eq!(
            dns_seed_query_host("seed.signet.bitcoin.sprovoost.nl", bits),
            "x809.seed.signet.bitcoin.sprovoost.nl"
        );
    }

    #[test]
    fn network_ports_and_seed_lists() {
        assert_eq!(default_port(Network::Mainnet), 8333);
        assert_eq!(default_port(Network::Testnet), 18333);
        assert_eq!(default_port(Network::Signet), 38333);
        assert_eq!(default_port(Network::Regtest), 18444);
        assert!(!dns_seeds(Network::Mainnet).is_empty());
        assert!(!dns_seeds(Network::Testnet).is_empty());
        assert_eq!(dns_seeds(Network::Signet).len(), 1);
        assert!(dns_seeds(Network::Regtest).is_empty());
        assert!(!fixed_seed_hosts(Network::Mainnet).is_empty());
        assert!(!fixed_seed_hosts(Network::Testnet).is_empty());
        assert!(!fixed_seed_hosts(Network::Signet).is_empty());
        assert!(fixed_seed_hosts(Network::Regtest).is_empty());
        // Regtest has no seeds → resolve paths stay empty (no network I/O).
        assert!(resolve_dns_seeds(Network::Regtest).is_empty());
        assert!(resolve_fixed_seeds(Network::Regtest).is_empty());
        assert!(resolve_all_seeds(Network::Regtest).is_empty());
    }

    #[test]
    fn peer_flags_set_remove_and_mid_range_speed() {
        let mut f = PeerFlags::empty();
        assert!(f.is_untried());
        f.set(PeerFlags::HAS_CONNECTED, true);
        assert!(f.has_connected());
        f.set(PeerFlags::HAS_CONNECTED, false);
        assert!(!f.has_connected());
        // Mid-range sample leaves prior classification alone.
        f.insert(PeerFlags::FAST);
        f.apply_speed_sample(150, PeerFlags::FAST_BPS_MIN / 2);
        assert!(f.is_fast());
        assert!(!f.is_slow());
    }

    #[test]
    fn addrman_merge_offset_and_ipv4_sort() {
        use std::net::{IpAddr, Ipv6Addr};
        let v4 = addr(1);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
        let mut a = AddrMan::new();
        a.add(v6);
        a.add(v4);
        a.inject([v6, v4]); // already present no-op + re-sort
        assert_eq!(a.peers()[0], v4, "IPv4 preferred over IPv6");

        let mut b = AddrMan::new();
        b.add_with_flags(addr(9), {
            let mut f = PeerFlags::empty();
            f.insert(PeerFlags::SLOW);
            f
        });
        a.merge_from(&b);
        assert!(a.flags(&addr(9)).is_slow());
        assert!(a.entry(&addr(9)).is_some());
        assert!(!a.is_empty());

        // Ranked outbound + offset wrap.
        let ranked = a.take_outbound(2);
        assert_eq!(ranked.len(), 2);
        let offset = a.take_outbound_offset(3, 1);
        assert_eq!(offset.len(), 3.min(a.len()));
        assert!(a.take_outbound_offset(0, 0).is_empty());
        assert!(a.take_dial_candidates(0, &HashSet::new(), &[]).is_empty());
    }

    #[test]
    fn peers_file_load_errors_and_empty() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-peers-err-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let missing = dir.join("no-such-peers");
        assert!(AddrMan::load(&missing).unwrap().is_empty());

        // Bad magic.
        let bad = dir.join("bad");
        std::fs::write(&bad, "not-magic\n1.2.3.4:8333 0\n").unwrap();
        assert!(AddrMan::load(&bad).is_err());

        // Comment-only / empty after trim → empty book.
        let emptyish = dir.join("emptyish");
        std::fs::write(&emptyish, "# just a comment\n\n").unwrap();
        assert!(AddrMan::load(&emptyish).unwrap().is_empty());

        // Hex + decimal flags parse.
        let ok = dir.join("ok");
        std::fs::write(
            &ok,
            format!(
                "{}\n{} 0x03\n{} 16\n# trailing\n",
                AddrMan::PEERS_FILE_MAGIC,
                addr(1),
                addr(2)
            ),
        )
        .unwrap();
        let loaded = AddrMan::load(&ok).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.flags(&addr(1)).has_connected());
        assert!(loaded.flags(&addr(1)).is_fast()); // bits 0|1
        assert!(loaded.flags(&addr(2)).failed_last_connect()); // bit 4 = 16

        // Bad address token.
        let bad_addr = dir.join("bad-addr");
        std::fs::write(
            &bad_addr,
            format!("{}\nnot-an-addr 0\n", AddrMan::PEERS_FILE_MAGIC),
        )
        .unwrap();
        assert!(AddrMan::load(&bad_addr).is_err());

        // Bad hex flags.
        let bad_hex = dir.join("bad-hex");
        std::fs::write(
            &bad_hex,
            format!("{}\n{} 0xZZ\n", AddrMan::PEERS_FILE_MAGIC, addr(1)),
        )
        .unwrap();
        assert!(AddrMan::load(&bad_hex).is_err());

        // Bad decimal flags + 0X uppercase hex prefix path.
        let bad_dec = dir.join("bad-dec");
        std::fs::write(
            &bad_dec,
            format!("{}\n{} not-a-number\n", AddrMan::PEERS_FILE_MAGIC, addr(1)),
        )
        .unwrap();
        assert!(AddrMan::load(&bad_dec).is_err());

        let ok_upper = dir.join("ok-upper");
        std::fs::write(
            &ok_upper,
            format!("{}\n{} 0X01\n", AddrMan::PEERS_FILE_MAGIC, addr(7)),
        )
        .unwrap();
        let u = AddrMan::load(&ok_upper).unwrap();
        assert!(u.flags(&addr(7)).has_connected());

        // Save creates parent dir; note_connected clears fail/incompat bits.
        let nested = dir.join("nested").join("peers");
        let mut am = AddrMan::new();
        am.add(addr(3));
        am.note_connect_failed(addr(3), true);
        assert!(am.flags(&addr(3)).is_incompatible());
        am.note_connected(addr(3));
        assert!(am.flags(&addr(3)).has_connected());
        assert!(!am.flags(&addr(3)).is_incompatible());
        am.save(&nested).unwrap();
        assert!(nested.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
