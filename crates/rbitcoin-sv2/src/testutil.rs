//! Test-only TDP client: a Noise initiator pinned to the TP's authority key.

use crate::transport::{Frame, NoiseConn};
use binary_sv2::{GetSize, Serialize, Str0255, B016M, B064K};
use common_messages_sv2::{Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION};
use std::io;
use std::net::SocketAddr;
use template_distribution_sv2::{
    CoinbaseOutputConstraints, RequestTransactionData, SubmitSolution,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};
use tokio::net::TcpSocket;

pub struct TpClient {
    conn: NoiseConn,
}

impl TpClient {
    /// TCP connect and complete the NX handshake against `authority_pubkey`.
    pub async fn connect(addr: SocketAddr, authority_pubkey: [u8; 32]) -> io::Result<Self> {
        Self::connect_recv_buffer(addr, authority_pubkey, None).await
    }

    /// [`Self::connect`] with `SO_RCVBUF` pinned when `recv_buffer` is set.
    ///
    /// An unset buffer autotunes up to `tcp_rmem` max. The peer's `write()`
    /// then keeps completing, because this socket ACKs everything into that
    /// window. Setting the option turns autotune off. The kernel doubles the
    /// value; the handshake reply still fits.
    pub(crate) async fn connect_recv_buffer(
        addr: SocketAddr,
        authority_pubkey: [u8; 32],
        recv_buffer: Option<u32>,
    ) -> io::Result<Self> {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        if let Some(n) = recv_buffer {
            socket.set_recv_buffer_size(n)?;
            // Doubled for bookkeeping, and at least `tcp_rmem` min.
            let got = socket.recv_buffer_size()?;
            if got > 64 * 1024 {
                return Err(io::Error::other(format!(
                    "SO_RCVBUF stayed {got} after requesting {n}"
                )));
            }
        }
        let stream = socket.connect(addr).await?;
        let initiator = noise_sv2::Initiator::from_raw_k(authority_pubkey)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        Ok(Self {
            conn: NoiseConn::connect(stream, initiator, crate::WRITE_TIMEOUT).await?,
        })
    }

    /// Send `SetupConnection`; `protocol` is the raw discriminant (2 = TDP).
    pub async fn setup_connection(
        &mut self,
        protocol: u8,
        min_version: u16,
        max_version: u16,
        flags: u32,
    ) -> io::Result<()> {
        let protocol = Protocol::try_from(protocol)
            .map_err(|()| io::Error::new(io::ErrorKind::InvalidInput, "protocol"))?;
        let s = |v: &'static str| Str0255::try_from(v).expect("short literal");
        let msg = SetupConnection {
            protocol,
            min_version,
            max_version,
            flags,
            endpoint_host: s("127.0.0.1"),
            endpoint_port: 0,
            vendor: s("rbitcoin-test"),
            hardware_version: s(""),
            firmware: s(""),
            device_id: s(""),
        };
        self.conn.send(MESSAGE_TYPE_SETUP_CONNECTION, msg).await
    }

    pub async fn coinbase_output_constraints(
        &mut self,
        max_additional_size: u32,
        max_additional_sigops: u16,
    ) -> io::Result<()> {
        let msg = CoinbaseOutputConstraints {
            coinbase_output_max_additional_size: max_additional_size,
            coinbase_output_max_additional_sigops: max_additional_sigops,
        };
        self.conn
            .send(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, msg)
            .await
    }

    pub async fn request_transaction_data(&mut self, template_id: u64) -> io::Result<()> {
        let msg = RequestTransactionData { template_id };
        self.conn
            .send(MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, msg)
            .await
    }

    pub async fn submit_solution(
        &mut self,
        template_id: u64,
        version: u32,
        header_timestamp: u32,
        header_nonce: u32,
        coinbase_tx: &[u8],
    ) -> io::Result<()> {
        let coinbase_tx = B064K::try_from(coinbase_tx)
            .map_err(|e| io::Error::other(format!("sv2 coinbase: {e:?}")))?;
        let msg = SubmitSolution {
            template_id,
            version,
            header_timestamp,
            header_nonce,
            coinbase_tx,
        };
        self.conn.send(MESSAGE_TYPE_SUBMIT_SOLUTION, msg).await
    }

    /// Send any SV2 message under `msg_type`.
    pub async fn send<T: Serialize + GetSize>(&mut self, msg_type: u8, msg: T) -> io::Result<()> {
        self.conn.send(msg_type, msg).await
    }

    /// Send `payload` as one `B016M` field under an arbitrary message type.
    pub async fn send_bytes(&mut self, msg_type: u8, payload: &[u8]) -> io::Result<()> {
        let msg = B016M::try_from(payload)
            .map_err(|e| io::Error::other(format!("sv2 payload: {e:?}")))?;
        self.conn.send(msg_type, msg).await
    }

    pub async fn recv(&mut self) -> io::Result<Frame> {
        self.conn.recv().await
    }
}
