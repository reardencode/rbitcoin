//! SOCKS5 CONNECT client for P2P outbound (system Tor / generic proxy).

use crate::error::NetError;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) struct ProxyCreds {
    pub(crate) username: Vec<u8>,
    pub(crate) password: Vec<u8>,
}

impl ProxyCreds {
    pub(crate) fn fresh() -> Self {
        let mut username = vec![0u8; 16];
        let mut password = vec![0u8; 16];
        getrandom::fill(&mut username).expect("CSPRNG for SOCKS creds");
        getrandom::fill(&mut password).expect("CSPRNG for SOCKS creds");
        Self { username, password }
    }
}

enum SocksDest<'a> {
    Socket(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

pub(crate) async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    creds: Option<&ProxyCreds>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Socket(target), creds).await
}

pub(crate) async fn socks5_connect_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    creds: Option<&ProxyCreds>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Domain { host, port }, creds).await
}

pub(crate) async fn dial_isolated(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream, NetError> {
    let creds = ProxyCreds::fresh();
    socks5_connect(proxy, target, Some(&creds)).await
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Dialer {
    #[default]
    Direct,
    Socks {
        proxy: SocketAddr,
        randomize: bool,
    },
}

impl Dialer {
    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream, NetError> {
        match self {
            Dialer::Direct => Ok(TcpStream::connect(target).await?),
            Dialer::Socks { proxy, randomize } => {
                if *randomize {
                    let creds = ProxyCreds::fresh();
                    socks5_connect(*proxy, target, Some(&creds)).await
                } else {
                    socks5_connect(*proxy, target, None).await
                }
            }
        }
    }

    pub async fn connect_domain(&self, host: &str, port: u16) -> Result<TcpStream, NetError> {
        match self {
            Dialer::Direct => {
                let mut addrs = tokio::net::lookup_host((host, port)).await?;
                let addr = addrs.next().ok_or(NetError::Protocol("dns lookup empty"))?;
                self.connect(addr).await
            }
            Dialer::Socks { proxy, randomize } => {
                if *randomize {
                    let creds = ProxyCreds::fresh();
                    socks5_connect_domain(*proxy, host, port, Some(&creds)).await
                } else {
                    socks5_connect_domain(*proxy, host, port, None).await
                }
            }
        }
    }

    pub async fn connect_isolated(&self, target: SocketAddr) -> Result<TcpStream, NetError> {
        match self {
            Dialer::Direct => self.connect(target).await,
            Dialer::Socks { proxy, .. } => dial_isolated(*proxy, target).await,
        }
    }
}

async fn socks5_connect_dest(
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

async fn greet(s: &mut TcpStream, creds: Option<&ProxyCreds>) -> Result<(), NetError> {
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

async fn write_connect(s: &mut TcpStream, dest: SocksDest<'_>) -> Result<(), NetError> {
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

async fn read_connect_reply(s: &mut TcpStream) -> Result<(), NetError> {
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

#[cfg(test)]
mod tests {
    use super::{dial_isolated, socks5_connect, socks5_connect_domain, Dialer, ProxyCreds};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn socks5_connect_ipv4_against_fake_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let target = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 8333));

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut ver_n = [0u8; 2];
            s.read_exact(&mut ver_n).await.unwrap();
            assert_eq!(ver_n[0], 5, "SOCKS version");
            let nmethods = ver_n[1] as usize;
            let mut methods = vec![0u8; nmethods];
            s.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0x00), "NOAUTH offered, got {methods:?}");
            s.write_all(&[5, 0x00]).await.unwrap();

            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 5);
            assert_eq!(hdr[1], 1, "CONNECT");
            assert_eq!(hdr[2], 0);
            assert_eq!(hdr[3], 1, "ATYP IPv4");
            let mut addr = [0u8; 4];
            s.read_exact(&mut addr).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(addr, [203, 0, 113, 7]);
            assert_eq!(u16::from_be_bytes(port), 8333);

            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();

            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });

        let mut stream = socks5_connect(proxy, target, None).await.unwrap();
        stream.write_all(&[0xab]).await.unwrap();
        let mut echo = [0u8; 1];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, [0xab]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_domain_does_not_resolve_locally() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let host = "seed.example";
        let port = 8333u16;

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut ver_n = [0u8; 2];
            s.read_exact(&mut ver_n).await.unwrap();
            let nmethods = ver_n[1] as usize;
            let mut methods = vec![0u8; nmethods];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[5, 0x00]).await.unwrap();

            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 5);
            assert_eq!(hdr[1], 1, "CONNECT");
            assert_eq!(hdr[2], 0);
            assert_eq!(hdr[3], 3, "ATYP domain; must not resolve locally");
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await.unwrap();
            let mut name = vec![0u8; n[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            assert_eq!(name, b"seed.example");
            assert_eq!(u16::from_be_bytes(p), 8333);

            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        socks5_connect_domain(proxy, host, port, None)
            .await
            .unwrap();
        server.await.unwrap();
    }

    async fn accept_domain_connect(
        listener: TcpListener,
        want_host: &'static [u8],
        want_port: u16,
    ) {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut ver_n = [0u8; 2];
        s.read_exact(&mut ver_n).await.unwrap();
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await.unwrap();
        if methods.contains(&0x02) {
            s.write_all(&[5, 0x02]).await.unwrap();
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).await.unwrap();
            let mut ulen = [0u8; 1];
            s.read_exact(&mut ulen).await.unwrap();
            let mut user = vec![0u8; ulen[0] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
        } else {
            s.write_all(&[5, 0x00]).await.unwrap();
        }
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 3, "ATYP domain");
        let mut n = [0u8; 1];
        s.read_exact(&mut n).await.unwrap();
        let mut name = vec![0u8; n[0] as usize];
        s.read_exact(&mut name).await.unwrap();
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(name, want_host);
        assert_eq!(u16::from_be_bytes(p), want_port);
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    }

    #[tokio::test]
    async fn dialer_connect_domain_covers_socks_and_direct() {
        let host = "seed.example";
        let port = 8333u16;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_domain_connect(listener, b"seed.example", port));
        Dialer::Socks {
            proxy,
            randomize: true,
        }
        .connect_domain(host, port)
        .await
        .unwrap();
        server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_domain_connect(listener, b"seed.example", port));
        Dialer::Socks {
            proxy,
            randomize: false,
        }
        .connect_domain(host, port)
        .await
        .unwrap();
        server.await.unwrap();

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let mut stream = Dialer::Direct
            .connect_domain("127.0.0.1", echo_addr.port())
            .await
            .unwrap();
        stream.write_all(&[0x42]).await.unwrap();
        let mut got = [0u8; 1];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x42]);
        server.await.unwrap();
    }

    async fn serve_userpass_ipv4(
        s: &mut tokio::net::TcpStream,
        want_ip: [u8; 4],
        want_port: u16,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut ver_n = [0u8; 2];
        s.read_exact(&mut ver_n).await.unwrap();
        assert_eq!(ver_n[0], 5);
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0x02), "USERPASS offered, got {methods:?}");
        s.write_all(&[5, 0x02]).await.unwrap();

        let mut ver = [0u8; 1];
        s.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 1);
        let mut ulen = [0u8; 1];
        s.read_exact(&mut ulen).await.unwrap();
        let mut user = vec![0u8; ulen[0] as usize];
        s.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        s.read_exact(&mut pass).await.unwrap();
        s.write_all(&[1, 0]).await.unwrap();

        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 1);
        let mut addr = [0u8; 4];
        s.read_exact(&mut addr).await.unwrap();
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(addr, want_ip);
        assert_eq!(u16::from_be_bytes(p), want_port);
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        (user, pass)
    }

    #[tokio::test]
    async fn socks5_username_password_seen_by_fake_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let target = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 8333));
        let creds = ProxyCreds {
            username: b"alice".to_vec(),
            password: b"secret".to_vec(),
        };
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            serve_userpass_ipv4(&mut s, [198, 51, 100, 1], 8333).await
        });
        socks5_connect(proxy, target, Some(&creds)).await.unwrap();
        let (user, pass) = server.await.unwrap();
        assert_eq!(user, b"alice");
        assert_eq!(pass, b"secret");
    }

    #[tokio::test]
    async fn dial_isolated_uses_new_creds_each_call() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let target = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), 8333));
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                let creds = serve_userpass_ipv4(&mut s, [198, 51, 100, 2], 8333).await;
                tx.send(creds).await.unwrap();
            }
        });
        dial_isolated(proxy, target).await.unwrap();
        dial_isolated(proxy, target).await.unwrap();
        let (u1, _) = rx.recv().await.unwrap();
        let (u2, _) = rx.recv().await.unwrap();
        server.await.unwrap();
        assert_ne!(u1, u2, "each isolated dial must use fresh SOCKS creds");
        assert!(!u1.is_empty() && !u2.is_empty());
    }

    async fn splice_one_socks(
        listener: TcpListener,
        saw: tokio::sync::oneshot::Sender<SocketAddr>,
    ) {
        let (mut c, _) = listener.accept().await.unwrap();
        let mut ver_n = [0u8; 2];
        c.read_exact(&mut ver_n).await.unwrap();
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        c.read_exact(&mut methods).await.unwrap();
        if methods.contains(&0x02) {
            c.write_all(&[5, 0x02]).await.unwrap();
            let mut ver = [0u8; 1];
            c.read_exact(&mut ver).await.unwrap();
            let mut ulen = [0u8; 1];
            c.read_exact(&mut ulen).await.unwrap();
            let mut user = vec![0u8; ulen[0] as usize];
            c.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            c.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            c.read_exact(&mut pass).await.unwrap();
            c.write_all(&[1, 0]).await.unwrap();
        } else {
            c.write_all(&[5, 0x00]).await.unwrap();
        }
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 1);
        let dest = match hdr[3] {
            1 => {
                let mut a = [0u8; 4];
                c.read_exact(&mut a).await.unwrap();
                let mut p = [0u8; 2];
                c.read_exact(&mut p).await.unwrap();
                SocketAddr::from((Ipv4Addr::new(a[0], a[1], a[2], a[3]), u16::from_be_bytes(p)))
            }
            _ => panic!("test splice expects IPv4 CONNECT"),
        };
        let mut peer = TcpStream::connect(dest).await.unwrap();
        c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let _ = saw.send(dest);
        let _ = tokio::io::copy_bidirectional(&mut c, &mut peer).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outbound_dial_uses_proxy_when_set() {
        use crate::peer::{connect_and_handshake_timed, HandshakePolicy, HANDSHAKE_TIMEOUT};
        use bitcoin::p2p::Magic;
        use std::time::Duration;

        let bitcoin_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = bitcoin_l.local_addr().unwrap();
        let inbound = tokio::spawn(async move {
            let (stream, from) = bitcoin_l.accept().await.unwrap();
            connect_and_handshake_timed(
                Duration::from_secs(5),
                stream,
                Magic::REGTEST,
                peer_addr,
                from,
                0,
                true,
                "/rbitcoin:test/",
                HandshakePolicy::plain(),
            )
            .await
        });

        let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = socks_l.local_addr().unwrap();
        let (saw_tx, saw_rx) = tokio::sync::oneshot::channel();
        let splice = tokio::spawn(splice_one_socks(socks_l, saw_tx));

        let stream = Dialer::Socks {
            proxy,
            randomize: true,
        }
        .connect(peer_addr)
        .await
        .unwrap();
        assert_eq!(saw_rx.await.unwrap(), peer_addr);

        connect_and_handshake_timed(
            Duration::from_secs(5),
            stream,
            Magic::REGTEST,
            proxy,
            peer_addr,
            0,
            false,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        inbound.await.unwrap().unwrap();
        splice.abort();

        let direct_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct_l.local_addr().unwrap();
        let inbound = tokio::spawn(async move {
            let (stream, from) = direct_l.accept().await.unwrap();
            connect_and_handshake_timed(
                HANDSHAKE_TIMEOUT,
                stream,
                Magic::REGTEST,
                direct_addr,
                from,
                0,
                true,
                "/rbitcoin:test/",
                HandshakePolicy::plain(),
            )
            .await
        });
        let stream = Dialer::Direct.connect(direct_addr).await.unwrap();
        connect_and_handshake_timed(
            Duration::from_secs(5),
            stream,
            Magic::REGTEST,
            direct_addr,
            direct_addr,
            0,
            false,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        inbound.await.unwrap().unwrap();
    }
}
