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
    // Windows SO_REUSEADDR lets another process bind the port and take its
    // connections; claim it outright (Core #36169, #36305).
    #[cfg(windows)]
    set_exclusive_addr_use(&socket)?;
    // Rebind a port still in TIME_WAIT after a restart.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(BACKLOG)
}

#[cfg(windows)]
fn set_exclusive_addr_use(socket: &TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };

    let on: i32 = 1;
    // SAFETY: `socket` owns a live SOCKET for this call, and `optval` points
    // at an `i32` that outlives it, with `optlen` its size.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&on as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        // SAFETY: reads the calling thread's WinSock error; no arguments.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}
