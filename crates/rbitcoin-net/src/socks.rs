//! SOCKS5 CONNECT client for P2P outbound (system Tor / generic proxy).

use crate::error::NetError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn install_i2p_dialer(dialer: crate::i2p_sam::I2pDialer) {
    crate::i2p_sam::install(dialer);
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCreds {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl std::fmt::Debug for ProxyCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyCreds(<redacted>)")
    }
}

impl ProxyCreds {
    pub fn fresh() -> Self {
        let mut username = vec![0u8; 16];
        let mut password = vec![0u8; 16];
        getrandom::fill(&mut username).expect("CSPRNG for SOCKS creds");
        getrandom::fill(&mut password).expect("CSPRNG for SOCKS creds");
        Self { username, password }
    }
}

#[doc(hidden)]
pub enum SocksDest<'a> {
    Socket(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

pub async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    creds: Option<&ProxyCreds>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Socket(target), creds).await
}

pub async fn socks5_connect_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    creds: Option<&ProxyCreds>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Domain { host, port }, creds).await
}

pub async fn dial_isolated(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream, NetError> {
    let creds = ProxyCreds::fresh();
    socks5_connect(proxy, target, Some(&creds)).await
}

pub async fn dial_isolated_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<TcpStream, NetError> {
    let creds = ProxyCreds::fresh();
    socks5_connect_domain(proxy, host, port, Some(&creds)).await
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Dialer {
    #[default]
    Direct,
    Socks {
        proxy: Option<SocketAddr>,
        onion: Option<SocketAddr>,
        randomize: bool,
        shared_creds: Option<Arc<(Vec<u8>, Vec<u8>)>>,
        /// Least [`Dialer::connect_timeout`] for a dial through this proxy.
        connect_floor: Duration,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetProxies {
    pub dialer: Dialer,
    pub i2p_sam: Option<SocketAddr>,
}

impl NetProxies {
    pub fn proxy_for(&self, net: crate::OnlyNet) -> Option<(SocketAddr, bool)> {
        match net {
            crate::OnlyNet::I2p => self.i2p_sam.map(|sam| (sam, false)),
            _ => self
                .dialer
                .proxy_for(net)
                .map(|proxy| (proxy, self.dialer.randomizes_credentials())),
        }
    }
}

/// Each isolated SOCKS dial builds its own Tor circuit, and a wave of them
/// queues inside Tor for longer than a clearnet RTT.
const SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// I2P STREAM CONNECT waits on tunnel + leaseset lookup.
const I2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

impl Dialer {
    /// Dial bound for `addr` over this dialer: `base` for a direct socket,
    /// at least the production SOCKS floor (30s) through a proxy, at least
    /// 90s for I2P. A floor lowered under that 30s is the bound itself, so
    /// a stalled-proxy test does not also wait out `base`.
    ///
    /// IBD `dial_batch` and tip-follow wrap connect and handshake in this one
    /// bound, so a slow peer is skipped rather than held through a wave.
    /// `prepare_outbound_session` bounds only the connect with it, then gives
    /// the handshake its own `HANDSHAKE_TIMEOUT`.
    pub fn connect_timeout(&self, addr: crate::NetAddr, base: Duration) -> Duration {
        match (self, addr) {
            (_, crate::NetAddr::I2p { .. }) => base.max(I2P_CONNECT_TIMEOUT),
            (Dialer::Socks { connect_floor, .. }, crate::NetAddr::Onion { .. })
            | (
                Dialer::Socks {
                    proxy: Some(_),
                    connect_floor,
                    ..
                },
                crate::NetAddr::Ip(_),
            ) => {
                if *connect_floor < SOCKS_CONNECT_TIMEOUT {
                    *connect_floor
                } else {
                    base.max(*connect_floor)
                }
            }
            _ => base,
        }
    }

    /// The same dialer with a different SOCKS floor, for a test that waits
    /// out a stalled proxy. A floor under the production 30s replaces `base`.
    #[doc(hidden)]
    pub fn with_connect_floor(mut self, floor: Duration) -> Self {
        if let Dialer::Socks { connect_floor, .. } = &mut self {
            *connect_floor = floor;
        }
        self
    }

    pub fn proxy_for(&self, net: crate::OnlyNet) -> Option<SocketAddr> {
        let Dialer::Socks { proxy, onion, .. } = self else {
            return None;
        };
        match net {
            crate::OnlyNet::Ipv4 | crate::OnlyNet::Ipv6 => *proxy,
            crate::OnlyNet::Onion => onion.or(*proxy),
            crate::OnlyNet::I2p | crate::OnlyNet::Cjdns => None,
        }
    }

    fn randomizes_credentials(&self) -> bool {
        matches!(
            self,
            Dialer::Socks {
                randomize: true,
                ..
            }
        )
    }

    pub fn socks(proxy: SocketAddr, randomize: bool) -> Self {
        Self::with_proxies(Some(proxy), None, randomize)
    }

    pub fn with_proxies(
        proxy: Option<SocketAddr>,
        onion: Option<SocketAddr>,
        randomize: bool,
    ) -> Self {
        if proxy.is_none() && onion.is_none() {
            return Self::Direct;
        }
        let shared_creds = (!randomize).then(|| {
            let creds = ProxyCreds::fresh();
            Arc::new((creds.username, creds.password))
        });
        Self::Socks {
            proxy,
            onion,
            randomize,
            shared_creds,
            connect_floor: SOCKS_CONNECT_TIMEOUT,
        }
    }

    #[doc(hidden)]
    pub fn dial_creds(
        randomize: bool,
        shared_creds: Option<&Arc<(Vec<u8>, Vec<u8>)>>,
    ) -> Option<ProxyCreds> {
        if randomize {
            Some(ProxyCreds::fresh())
        } else {
            shared_creds.map(|c| ProxyCreds {
                username: c.0.clone(),
                password: c.1.clone(),
            })
        }
    }

    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream, NetError> {
        match self {
            Dialer::Direct => Ok(TcpStream::connect(target).await?),
            Dialer::Socks {
                proxy,
                randomize,
                shared_creds,
                ..
            } => match proxy {
                Some(proxy) => {
                    let creds = Self::dial_creds(*randomize, shared_creds.as_ref());
                    socks5_connect(*proxy, target, creds.as_ref()).await
                }
                None => Ok(TcpStream::connect(target).await?),
            },
        }
    }

    pub async fn connect_domain(&self, host: &str, port: u16) -> Result<TcpStream, NetError> {
        if host.ends_with(".onion") || host.ends_with(".b32.i2p") {
            let addr: crate::NetAddr = format!("{host}:{port}").parse()?;
            return self.connect_net(addr).await;
        }
        match self {
            Dialer::Direct => {
                let mut addrs = tokio::net::lookup_host((host, port)).await?;
                let addr = addrs.next().ok_or(NetError::Protocol("dns lookup empty"))?;
                self.connect(addr).await
            }
            Dialer::Socks {
                proxy,
                randomize,
                shared_creds,
                ..
            } => {
                let Some(proxy) = proxy else {
                    let mut addrs = tokio::net::lookup_host((host, port)).await?;
                    let addr = addrs.next().ok_or(NetError::Protocol("dns lookup empty"))?;
                    return self.connect(addr).await;
                };
                let creds = Self::dial_creds(*randomize, shared_creds.as_ref());
                socks5_connect_domain(*proxy, host, port, creds.as_ref()).await
            }
        }
    }

    pub async fn connect_isolated_net(&self, addr: crate::NetAddr) -> Result<TcpStream, NetError> {
        match addr {
            crate::NetAddr::Ip(s) => {
                let proxy = self.proxy_for(crate::OnlyNet::of(addr)).ok_or_else(|| {
                    NetError::Encode("isolated broadcast needs --proxy for an IP peer".into())
                })?;
                dial_isolated(proxy, s).await
            }
            crate::NetAddr::Onion { port, .. } => {
                let socks = self.proxy_for(crate::OnlyNet::Onion).ok_or_else(|| {
                    NetError::Encode("onion dial requires SOCKS (--proxy or --onion)".into())
                })?;
                dial_isolated_domain(socks, &addr.host_str(), port).await
            }
            crate::NetAddr::I2p { .. } => {
                Err(NetError::Encode("i2p dial requires SAM (--i2p-sam)".into()))
            }
            crate::NetAddr::Cjdns { .. } => Err(NetError::Encode(
                "isolated broadcast never dials cjdns".into(),
            )),
        }
    }

    pub async fn connect_net(&self, addr: crate::NetAddr) -> Result<TcpStream, NetError> {
        match addr {
            crate::NetAddr::Ip(s) => self.connect(s).await,
            crate::NetAddr::Onion { port, .. } => {
                let Some(socks) = self.proxy_for(crate::OnlyNet::Onion) else {
                    return Err(NetError::Encode(
                        "onion dial requires SOCKS (--proxy or --onion)".into(),
                    ));
                };
                let creds = match self {
                    Dialer::Socks {
                        randomize,
                        shared_creds,
                        ..
                    } => Self::dial_creds(*randomize, shared_creds.as_ref()),
                    Dialer::Direct => None,
                };
                socks5_connect_domain(socks, &addr.host_str(), port, creds.as_ref()).await
            }
            crate::NetAddr::I2p { .. } => {
                crate::i2p_sam::stream_connect_installed(&addr.host_str()).await
            }
            crate::NetAddr::Cjdns { ip, port } => {
                Ok(TcpStream::connect(SocketAddr::from((ip, port))).await?)
            }
        }
    }
}

pub async fn socks5_connect_dest(
    proxy: SocketAddr,
    dest: SocksDest<'_>,
    creds: Option<&ProxyCreds>,
) -> Result<TcpStream, NetError> {
    let mut s = TcpStream::connect(proxy).await?;
    greet(&mut s, creds).await?;
    write_connect(&mut s, dest).await?;
    read_connect_reply(&mut s).await?;
    Ok(s)
}

pub async fn greet(s: &mut TcpStream, creds: Option<&ProxyCreds>) -> Result<(), NetError> {
    match creds {
        None => {
            s.write_all(&[5, 1, 0x00]).await?;
            let mut sel = [0u8; 2];
            s.read_exact(&mut sel).await?;
            if sel[0] != 5 || sel[1] != 0x00 {
                return Err(NetError::Protocol("socks method rejected"));
            }
            Ok(())
        }
        Some(c) => {
            if c.username.is_empty()
                || c.username.len() > 255
                || c.password.is_empty()
                || c.password.len() > 255
            {
                return Err(NetError::Protocol("socks username/password length"));
            }
            s.write_all(&[5, 1, 0x02]).await?;
            let mut sel = [0u8; 2];
            s.read_exact(&mut sel).await?;
            if sel[0] != 5 || sel[1] != 0x02 {
                return Err(NetError::Protocol("socks method rejected"));
            }
            let mut auth = Vec::with_capacity(3 + c.username.len() + c.password.len());
            auth.push(1);
            auth.push(c.username.len() as u8);
            auth.extend_from_slice(&c.username);
            auth.push(c.password.len() as u8);
            auth.extend_from_slice(&c.password);
            s.write_all(&auth).await?;
            let mut st = [0u8; 2];
            s.read_exact(&mut st).await?;
            if st[0] != 1 || st[1] != 0 {
                return Err(NetError::Protocol("socks username/password rejected"));
            }
            Ok(())
        }
    }
}

pub async fn write_connect(s: &mut TcpStream, dest: SocksDest<'_>) -> Result<(), NetError> {
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[5, 1, 0]);
    match dest {
        SocksDest::Socket(SocketAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocksDest::Socket(SocketAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
        SocksDest::Domain { host, port } => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(NetError::Protocol("socks domain length"));
            }
            req.push(3);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    s.write_all(&req).await?;
    Ok(())
}

pub async fn read_connect_reply(s: &mut TcpStream) -> Result<(), NetError> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(NetError::Protocol("socks reply version"));
    }
    if hdr[1] != 0 {
        return Err(NetError::Protocol("socks CONNECT refused"));
    }
    match hdr[3] {
        1 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await?;
        }
        4 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest).await?;
        }
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            let mut rest = vec![0u8; n[0] as usize + 2];
            s.read_exact(&mut rest).await?;
        }
        _ => return Err(NetError::Protocol("socks reply ATYP")),
    }
    Ok(())
}
