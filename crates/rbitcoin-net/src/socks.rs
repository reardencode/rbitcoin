//! SOCKS5 CONNECT client for P2P outbound (system Tor / generic proxy).

use crate::error::NetError;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

enum SocksDest<'a> {
    Socket(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

pub(crate) async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    creds: Option<&[u8]>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Socket(target), creds).await
}

pub(crate) async fn socks5_connect_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    creds: Option<&[u8]>,
) -> Result<TcpStream, NetError> {
    socks5_connect_dest(proxy, SocksDest::Domain { host, port }, creds).await
}

async fn socks5_connect_dest(
    proxy: SocketAddr,
    dest: SocksDest<'_>,
    creds: Option<&[u8]>,
) -> Result<TcpStream, NetError> {
    let mut s = TcpStream::connect(proxy).await?;
    greet(&mut s, creds).await?;
    write_connect(&mut s, dest).await?;
    read_connect_reply(&mut s).await?;
    Ok(s)
}

async fn greet(s: &mut TcpStream, creds: Option<&[u8]>) -> Result<(), NetError> {
    if creds.is_some() {
        return Err(NetError::Protocol(
            "socks username/password not implemented",
        ));
    }
    s.write_all(&[5, 1, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 5 || sel[1] != 0x00 {
        return Err(NetError::Protocol("socks method rejected"));
    }
    Ok(())
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
    use super::{socks5_connect, socks5_connect_domain};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
}
