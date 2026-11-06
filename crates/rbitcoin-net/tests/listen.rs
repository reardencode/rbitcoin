//! Windows only: a default listener there lets a `SO_REUSEADDR` socket from
//! the same user bind a specific address on its wildcard port (Core #36169,
//! #36305).

use std::net::{Ipv4Addr, SocketAddr};

use rbitcoin_net::listen::bind_tcp;
use tokio::net::TcpSocket;

#[tokio::test]
async fn reuseaddr_specific_bind_cannot_take_a_wildcard_listen_port() {
    let listener = bind_tcp((Ipv4Addr::UNSPECIFIED, 0).into()).expect("bind");
    let port = listener.local_addr().unwrap().port();

    let hijack = TcpSocket::new_v4().unwrap();
    hijack.set_reuseaddr(true).unwrap();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(
        hijack.bind(target).is_err(),
        "a SO_REUSEADDR socket bound {target} while 0.0.0.0:{port} was listening"
    );
}
