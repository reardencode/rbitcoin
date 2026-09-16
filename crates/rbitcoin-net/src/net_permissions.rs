//! Core v31.1 `NetPermissions` (`net_permissions.cpp` / `.h`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Core `NetPermissionFlags` bits (multiflags include their implied bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetPermissionFlags(u32);

impl NetPermissionFlags {
    pub const NONE: Self = Self(0);
    pub const BLOOM: Self = Self(1 << 1);
    pub const RELAY: Self = Self(1 << 3);
    pub const FORCE_RELAY: Self = Self((1 << 2) | (1 << 3));
    pub const DOWNLOAD: Self = Self(1 << 6);
    pub const NOBAN: Self = Self((1 << 4) | (1 << 6));
    pub const MEMPOOL: Self = Self(1 << 5);
    pub const ADDR: Self = Self(1 << 7);
    pub const IMPLICIT: Self = Self(1 << 31);
    pub const ALL: Self = Self(
        Self::BLOOM.0
            | Self::FORCE_RELAY.0
            | Self::RELAY.0
            | Self::NOBAN.0
            | Self::MEMPOOL.0
            | Self::DOWNLOAD.0
            | Self::ADDR.0,
    );

    pub const fn has(self, f: Self) -> bool {
        (self.0 & f.0) == f.0
    }

    pub fn add(&mut self, f: Self) {
        self.0 |= f.0;
    }

    pub fn clear_implicit(&mut self) {
        self.0 &= !Self::IMPLICIT.0;
    }

    pub fn to_strings(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.has(Self::BLOOM) {
            v.push("bloomfilter");
        }
        if self.has(Self::NOBAN) {
            v.push("noban");
        }
        if self.has(Self::FORCE_RELAY) {
            v.push("forcerelay");
        }
        if self.has(Self::RELAY) {
            v.push("relay");
        }
        if self.has(Self::MEMPOOL) {
            v.push("mempool");
        }
        if self.has(Self::DOWNLOAD) {
            v.push("download");
        }
        if self.has(Self::ADDR) {
            v.push("addr");
        }
        v
    }
}

impl std::ops::BitOr for NetPermissionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for NetPermissionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subnet {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Subnet {
    pub fn contains(self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else {
            return false;
        };
        let mask = if self.prefix == 0 {
            0
        } else if self.prefix >= 32 {
            u32::MAX
        } else {
            !((1u32 << (32 - self.prefix)) - 1)
        };
        u32::from(v4) & mask == u32::from(self.addr) & mask
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhitelistGrant {
    pub subnet: Subnet,
    pub flags: NetPermissionFlags,
    pub inbound: bool,
    pub outbound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhitebindGrant {
    pub addr: SocketAddr,
    pub flags: NetPermissionFlags,
}

/// Core `DEFAULT_WHITELISTRELAY`.
pub const DEFAULT_WHITELISTRELAY: bool = true;
/// Core `DEFAULT_WHITELISTFORCERELAY`.
pub const DEFAULT_WHITELISTFORCERELAY: bool = false;

pub fn apply_implicit(
    mut flags: NetPermissionFlags,
    whitelist_relay: bool,
    whitelist_forcerelay: bool,
) -> NetPermissionFlags {
    if !flags.has(NetPermissionFlags::IMPLICIT) {
        return flags;
    }
    flags.clear_implicit();
    flags.add(NetPermissionFlags::NOBAN);
    flags.add(NetPermissionFlags::MEMPOOL);
    if whitelist_relay {
        flags.add(NetPermissionFlags::RELAY);
    }
    if whitelist_forcerelay {
        flags.add(NetPermissionFlags::FORCE_RELAY);
    }
    flags
}

struct ParsedFlags {
    flags: NetPermissionFlags,
    inbound: bool,
    outbound: bool,
    offset: usize,
}

fn parse_permission_flags(s: &str, allow_out: bool) -> Result<ParsedFlags, String> {
    let Some(at) = s.find('@') else {
        return Ok(ParsedFlags {
            flags: NetPermissionFlags::IMPLICIT,
            inbound: true,
            outbound: false,
            offset: 0,
        });
    };
    let mut flags = NetPermissionFlags::NONE;
    let mut inbound = false;
    let mut outbound = false;
    for permission in s[..at].split(',') {
        match permission {
            "bloomfilter" | "bloom" => flags.add(NetPermissionFlags::BLOOM),
            "noban" => flags.add(NetPermissionFlags::NOBAN),
            "forcerelay" => flags.add(NetPermissionFlags::FORCE_RELAY),
            "mempool" => flags.add(NetPermissionFlags::MEMPOOL),
            "download" => flags.add(NetPermissionFlags::DOWNLOAD),
            "all" => flags.add(NetPermissionFlags::ALL),
            "relay" => flags.add(NetPermissionFlags::RELAY),
            "addr" => flags.add(NetPermissionFlags::ADDR),
            "in" => inbound = true,
            "out" => {
                if !allow_out {
                    return Err(
                        "whitebind may only be used for incoming connections (\"out\" was passed)"
                            .into(),
                    );
                }
                outbound = true;
            }
            "" => {}
            other => return Err(format!("Invalid P2P permission: '{other}'")),
        }
    }
    if !inbound && !outbound {
        inbound = true;
    } else if flags == NetPermissionFlags::NONE {
        return Err(format!("Only direction was set, no permissions: '{s}'"));
    }
    Ok(ParsedFlags {
        flags,
        inbound,
        outbound,
        offset: at + 1,
    })
}

fn parse_subnet(net: &str) -> Result<Subnet, String> {
    if net.contains(':') {
        return Err(format!("Invalid netmask specified in -whitelist: '{net}'"));
    }
    let (host, prefix) = match net.split_once('/') {
        Some((h, p)) => {
            let n: u8 = p
                .parse()
                .map_err(|_| format!("Invalid netmask specified in -whitelist: '{net}'"))?;
            if n > 32 {
                return Err(format!("Invalid netmask specified in -whitelist: '{net}'"));
            }
            (h, n)
        }
        None => (net, 32),
    };
    let addr: Ipv4Addr = host
        .parse()
        .map_err(|_| format!("Invalid netmask specified in -whitelist: '{net}'"))?;
    Ok(Subnet { addr, prefix })
}

pub fn parse_whitelist(s: &str) -> Result<WhitelistGrant, String> {
    let p = parse_permission_flags(s, true)?;
    let subnet = parse_subnet(&s[p.offset..])?;
    Ok(WhitelistGrant {
        subnet,
        flags: p.flags,
        inbound: p.inbound,
        outbound: p.outbound,
    })
}

pub fn parse_whitebind(s: &str) -> Result<WhitebindGrant, String> {
    let p = parse_permission_flags(s, false)?;
    let bind = &s[p.offset..];
    if bind.contains('/') {
        return Err(format!("Cannot resolve -whitebind address: '{bind}'"));
    }
    let addr: SocketAddr = bind.parse().map_err(|_| {
        if !bind.contains(':') {
            format!("Need to specify a port with -whitebind: '{bind}'")
        } else {
            format!("Cannot resolve -whitebind address: '{bind}'")
        }
    })?;
    if addr.port() == 0 {
        return Err(format!("Need to specify a port with -whitebind: '{bind}'"));
    }
    Ok(WhitebindGrant {
        addr,
        flags: p.flags,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetPermTable {
    pub whitelist: Vec<WhitelistGrant>,
    pub whitebind: Vec<WhitebindGrant>,
}

impl NetPermTable {
    pub fn flags_for(&self, ip: IpAddr, inbound: bool, bind: SocketAddr) -> NetPermissionFlags {
        let mut flags = NetPermissionFlags::NONE;
        for g in &self.whitelist {
            if !g.subnet.contains(ip) {
                continue;
            }
            if inbound && !g.inbound {
                continue;
            }
            if !inbound && !g.outbound {
                continue;
            }
            flags |= g.flags;
        }
        if inbound {
            for g in &self.whitebind {
                if g.addr == bind || (g.addr.ip() == bind.ip() && g.addr.port() == bind.port()) {
                    flags |= g.flags;
                }
            }
        }
        flags
    }

    pub fn strings_for(&self, ip: IpAddr, inbound: bool, bind: SocketAddr) -> Vec<String> {
        self.flags_for(ip, inbound, bind)
            .to_strings()
            .into_iter()
            .map(str::to_string)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn bind() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18444))
    }

    #[test]
    fn implicit_whitelist_defaults() {
        let g = parse_whitelist("127.0.0.1").unwrap();
        assert!(g.flags.has(NetPermissionFlags::IMPLICIT));
        assert!(g.inbound);
        assert!(!g.outbound);
        let flags = apply_implicit(g.flags, true, false);
        assert_eq!(
            flags.to_strings(),
            ["noban", "relay", "mempool", "download"]
        );
    }

    #[test]
    fn empty_explicit_is_none_even_with_forcerelay() {
        let g = parse_whitelist("@127.0.0.1").unwrap();
        assert!(!g.flags.has(NetPermissionFlags::IMPLICIT));
        let flags = apply_implicit(g.flags, true, true);
        assert!(flags.to_strings().is_empty());
    }

    #[test]
    fn whitelistrelay_off_drops_relay() {
        let g = parse_whitelist("127.0.0.1").unwrap();
        let flags = apply_implicit(g.flags, false, false);
        assert_eq!(flags.to_strings(), ["noban", "mempool", "download"]);
    }

    #[test]
    fn whitelistforcerelay_adds_forcerelay() {
        let g = parse_whitelist("127.0.0.1").unwrap();
        let flags = apply_implicit(g.flags, true, true);
        assert_eq!(
            flags.to_strings(),
            ["noban", "forcerelay", "relay", "mempool", "download"]
        );
    }

    #[test]
    fn explicit_noban_implies_download() {
        let g = parse_whitelist("noban@127.0.0.1").unwrap();
        assert_eq!(g.flags.to_strings(), ["noban", "download"]);
    }

    #[test]
    fn all_lists_core_names() {
        let g = parse_whitelist("all@127.0.0.1").unwrap();
        assert_eq!(
            g.flags.to_strings(),
            [
                "bloomfilter",
                "noban",
                "forcerelay",
                "relay",
                "mempool",
                "download",
                "addr"
            ]
        );
    }

    #[test]
    fn direction_only_is_init_error() {
        let err = parse_whitelist("in,out@127.0.0.1").unwrap_err();
        assert!(
            err.contains("Only direction was set, no permissions"),
            "{err}"
        );
    }

    #[test]
    fn unknown_perm_is_init_error() {
        let err = parse_whitelist("oopsie@127.0.0.1").unwrap_err();
        assert!(err.contains("Invalid P2P permission"), "{err}");
    }

    #[test]
    fn whitelist_port_is_invalid_netmask() {
        let err = parse_whitelist("noban@127.0.0.1:230").unwrap_err();
        assert!(err.contains("Invalid netmask specified in"), "{err}");
    }

    #[test]
    fn whitebind_cidr_cannot_resolve() {
        let err = parse_whitebind("noban@127.0.0.1/10").unwrap_err();
        assert!(err.contains("Cannot resolve -whitebind address"), "{err}");
    }

    #[test]
    fn outbound_only_noban() {
        let g = parse_whitelist("noban,out@127.0.0.1").unwrap();
        let mut t = NetPermTable::default();
        t.whitelist.push(WhitelistGrant {
            subnet: g.subnet,
            flags: apply_implicit(g.flags, true, false),
            inbound: g.inbound,
            outbound: g.outbound,
        });
        assert_eq!(t.strings_for(ip(), false, bind()), ["noban", "download"]);
        assert!(t.strings_for(ip(), true, bind()).is_empty());
    }

    #[test]
    fn inbound_default_misses_outbound() {
        let g = parse_whitelist("noban@127.0.0.1").unwrap();
        let mut t = NetPermTable::default();
        t.whitelist.push(WhitelistGrant {
            subnet: g.subnet,
            flags: g.flags,
            inbound: g.inbound,
            outbound: g.outbound,
        });
        assert!(t.strings_for(ip(), false, bind()).is_empty());
        assert_eq!(t.strings_for(ip(), true, bind()), ["noban", "download"]);
    }

    #[test]
    fn whitebind_merges_with_whitelist() {
        let wb = parse_whitebind("bloomfilter,forcerelay@127.0.0.1:18444").unwrap();
        let wl = parse_whitelist("noban@127.0.0.1").unwrap();
        let mut t = NetPermTable::default();
        t.whitebind.push(wb);
        t.whitelist.push(WhitelistGrant {
            subnet: wl.subnet,
            flags: wl.flags,
            inbound: wl.inbound,
            outbound: wl.outbound,
        });
        let s = t.strings_for(ip(), true, bind());
        assert_eq!(
            s,
            ["bloomfilter", "noban", "forcerelay", "relay", "download"]
        );
    }

    #[test]
    fn whitebind_out_is_init_error() {
        let err = parse_whitebind("noban,out@127.0.0.1:18444").unwrap_err();
        assert!(
            err.contains("whitebind may only be used for incoming connections"),
            "{err}"
        );
    }

    #[test]
    fn whitelist_prefix_and_ipv6() {
        let g = parse_whitelist("noban@127.0.0.1/0").unwrap();
        assert!(g.subnet.contains(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!g.subnet.contains(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        let err = parse_whitelist("noban@127.0.0.1/33").unwrap_err();
        assert!(err.contains("Invalid netmask specified in"), "{err}");
        let err = parse_whitelist("noban@127.0.0.1/nope").unwrap_err();
        assert!(err.contains("Invalid netmask specified in"), "{err}");
    }

    #[test]
    fn whitebind_port_zero_and_missing() {
        let err = parse_whitebind("noban@127.0.0.1").unwrap_err();
        assert!(
            err.contains("Need to specify a port with -whitebind"),
            "{err}"
        );
        let err = parse_whitebind("noban@127.0.0.1:0").unwrap_err();
        assert!(
            err.contains("Need to specify a port with -whitebind"),
            "{err}"
        );
        let err = parse_whitebind("noban@not-an-addr:18444").unwrap_err();
        assert!(err.contains("Cannot resolve -whitebind address"), "{err}");
    }

    #[test]
    fn flags_bitor_and_unmatched_subnet() {
        let a = NetPermissionFlags::NOBAN | NetPermissionFlags::RELAY;
        assert!(a.has(NetPermissionFlags::NOBAN));
        assert!(a.has(NetPermissionFlags::RELAY));
        let mut b = NetPermissionFlags::BLOOM;
        b |= NetPermissionFlags::ADDR;
        assert_eq!(b.to_strings(), ["bloomfilter", "addr"]);
        let g = parse_whitelist("noban@10.0.0.1/32").unwrap();
        let mut t = NetPermTable::default();
        t.whitelist.push(g);
        assert!(t.strings_for(ip(), true, bind()).is_empty());
    }
}
