//! TCP listen sockets for every server (P2P, RPC, Electrum, Esplora, health, SV2).

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket};

/// `listen(2)` backlog: what `tokio::net::TcpListener::bind` passed.
const BACKLOG: u32 = 128;

/// Bind and listen on `addr`. Must run inside a tokio runtime.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    // Rebind a port still in TIME_WAIT after a restart.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(BACKLOG)
}
