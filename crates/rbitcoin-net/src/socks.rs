//! SOCKS5 CONNECT client for P2P outbound (system Tor / generic proxy).

use crate::error::NetError;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    creds: Option<&[u8]>,
) -> Result<TcpStream, NetError> {
    let mut s = TcpStream::connect(proxy).await?;
    greet(&mut s, creds).await?;
    connect_ipv4(&mut s, target).await?;
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

async fn connect_ipv4(s: &mut TcpStream, target: SocketAddr) -> Result<(), NetError> {
    let SocketAddr::V4(v4) = target else {
        return Err(NetError::Protocol("socks CONNECT needs IPv4"));
    };
    let ip: Ipv4Addr = *v4.ip();
    let port = v4.port().to_be_bytes();
    let mut req = [0u8; 10];
    req[0] = 5;
    req[1] = 1;
    req[3] = 1;
    req[4..8].copy_from_slice(&ip.octets());
    req[8..10].copy_from_slice(&port);
    s.write_all(&req).await?;
    read_connect_reply(s).await
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
    use super::socks5_connect;
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
}
