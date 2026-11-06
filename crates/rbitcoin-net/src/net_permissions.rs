//! Core v31.1 `NetPermissions` (`net_permissions.cpp` / `.h`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Core `NetPermissionFlags` bits (multiflags include their implied bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetPermissionFlags(pub u32);

impl NetPermissionFlags {
    pub const NONE: Self = Self(0);
    pub const BLOOM: Self = Self(1 << 1);
    pub const RELAY: Self = Self(1 << 3);
    /// Bits 2 and 3. ForceRelay implies Relay.
    pub const FORCE_RELAY: Self = Self(0b1100);
    pub const DOWNLOAD: Self = Self(1 << 6);
    /// Bits 4 and 6. NoBan implies Download.
    pub const NOBAN: Self = Self(0b0101_0000);
    pub const MEMPOOL: Self = Self(1 << 5);
    pub const ADDR: Self = Self(1 << 7);
    /// Not Core: plain v1 framing on a `--net-permission-bind` listener for a
    /// local wallet indexer. Outside [`Self::ALL`] and the implicit grant.
    pub const V1: Self = Self(1 << 8);
    pub const IMPLICIT: Self = Self(1 << 31);
    /// Bits 1 through 7. Relay sits inside ForceRelay, and Download sits inside NoBan.
    pub const ALL: Self = Self(0b1111_1110);

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
        if self.has(Self::V1) {
            v.push("v1");
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
pub enum Subnet {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl Subnet {
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { addr, prefix }, IpAddr::V4(v4)) => {
                let mask = ipv4_mask(prefix);
                u32::from(v4) & mask == u32::from(addr) & mask
            }
            (Self::V6 { addr, prefix }, IpAddr::V6(v6)) => {
                let mask = ipv6_mask(prefix);
                u128::from(v6) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

#[doc(hidden)]
pub fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    }
}

#[doc(hidden)]
pub fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - prefix)) - 1)
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

#[doc(hidden)]
pub struct ParsedFlags {
    pub flags: NetPermissionFlags,
    pub inbound: bool,
    pub outbound: bool,
    pub offset: usize,
}

#[doc(hidden)]
pub fn parse_permission_flags(s: &str, allow_out: bool) -> Result<ParsedFlags, String> {
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
            "v1" => flags.add(NetPermissionFlags::V1),
            "in" => inbound = true,
            "out" => {
                if !allow_out {
                    return Err(
                        "--net-permission-bind may only be used for incoming connections (\"out\" was passed)"
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

#[doc(hidden)]
pub fn parse_subnet(net: &str) -> Result<Subnet, String> {
    let err = || format!("Invalid netmask specified in --net-permission: '{net}'");
    let (host_raw, prefix_s) = match net.rsplit_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (net, None),
    };
    let host = host_raw.trim_matches(|c| c == '[' || c == ']');
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        let prefix = match prefix_s {
            None => 32,
            Some(p) => {
                let n: u8 = p.parse().map_err(|_| err())?;
                if n > 32 {
                    return Err(err());
                }
                n
            }
        };
        return Ok(Subnet::V4 { addr, prefix });
    }
    if let Ok(addr) = host.parse::<Ipv6Addr>() {
        let prefix = match prefix_s {
            None => 128,
            Some(p) => {
                let n: u8 = p.parse().map_err(|_| err())?;
                if n > 128 {
                    return Err(err());
                }
                n
            }
        };
        return Ok(Subnet::V6 { addr, prefix });
    }
    Err(err())
}

pub fn parse_whitelist(s: &str) -> Result<WhitelistGrant, String> {
    let p = parse_permission_flags(s, true)?;
    if p.flags.has(NetPermissionFlags::V1) {
        return Err(format!(
            "v1 is a --net-permission-bind permission, not --net-permission: '{s}'"
        ));
    }
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
        return Err(format!(
            "Cannot resolve --net-permission-bind address: '{bind}'"
        ));
    }
    let addr: SocketAddr = bind.parse().map_err(|_| {
        if !bind.contains(':') {
            format!("Need to specify a port with --net-permission-bind: '{bind}'")
        } else {
            format!("Cannot resolve --net-permission-bind address: '{bind}'")
        }
    })?;
    if addr.port() == 0 {
        return Err(format!(
            "Need to specify a port with --net-permission-bind: '{bind}'"
        ));
    }
    if p.flags.has(NetPermissionFlags::V1) && !wallet_sync_ip(addr.ip()) {
        return Err(format!(
            "--net-permission-bind v1 needs a loopback or private address: '{bind}'"
        ));
    }
    Ok(WhitebindGrant {
        addr,
        flags: p.flags,
    })
}

/// Loopback, RFC 1918, RFC 6598 shared space, or unique-local IPv6 outside
/// CJDNS `fc00::/8`. `::ffff:0.0.0.0` binds every IPv4 interface, so the
/// address is unmapped first.
fn wallet_sync_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || crate::netaddr::ipv4_shared(v),
        IpAddr::V6(v) => {
            v.is_loopback() || (v.is_unique_local() && !crate::netaddr::is_cjdns_ip(v))
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetPermTable {
    pub whitelist: Vec<WhitelistGrant>,
    pub whitebind: Vec<WhitebindGrant>,
}

impl NetPermTable {
    pub fn flags_for_net(
        &self,
        net: crate::NetAddr,
        inbound: bool,
        bind: SocketAddr,
    ) -> NetPermissionFlags {
        match net {
            crate::NetAddr::Onion { .. } | crate::NetAddr::I2p { .. } => NetPermissionFlags::NONE,
            crate::NetAddr::Ip(s) => self.flags_for(s.ip(), inbound, bind),
            crate::NetAddr::Cjdns { ip, .. } => self.flags_for(IpAddr::V6(ip), inbound, bind),
        }
    }

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
