//! Plain v1 framing (Core `V1Transport`) for a wallet-sync listener.
//!
//! Only an inbound peer on a `--net-permission-bind` listener whose grant has
//! [`crate::NetPermissionFlags::V1`] gets here. Every other listener and every
//! outbound dial stay BIP324 v2 ([`crate::v2`]).

use crate::codec::{command_bytes_ok, FramedMessage, MAX_PROTOCOL_MESSAGE_LENGTH};
use crate::error::NetError;
use crate::net_permissions::NetPermissionFlags;
use crate::v2::{
    bip324_halves, counted_halves, encode_v2_contents, encode_v2_payload, read_v2_frame,
    read_v2_frame_with_progress, v1_prefix, wait_v1_prefix_mismatch, write_v2_contents,
    write_v2_msg, CountRead, CountWrite, PrefixedRead, V2Reader, V2Writer, WireBytes,
};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Magic, 12-byte command, length, checksum.
pub const V1_HEADER_LEN: usize = 24;

/// A frame at least this large is checksummed on `rbtc-scripts-*`.
const V1_OFFLOAD_LEN: usize = 64 * 1024;

fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = sha256d::Hash::hash(payload).to_byte_array();
    [h[0], h[1], h[2], h[3]]
}

/// One v1 frame for `command` and `payload`.
#[doc(hidden)]
pub fn v1_frame(magic: Magic, command: [u8; 12], payload: &[u8]) -> Result<Vec<u8>, NetError> {
    let len = u32::try_from(payload.len()).map_err(|_| NetError::MessageTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(V1_HEADER_LEN + payload.len());
    frame.extend_from_slice(&magic.to_bytes());
    frame.extend_from_slice(&command);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&checksum(payload));
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Cancellation-safe v1 reader. Header and body progress live here, so a
/// read dropped by `select!` or a timeout loses no bytes.
pub struct V1Reader<R> {
    inner: R,
    head: [u8; V1_HEADER_LEN],
    head_read: usize,
    body: Option<Vec<u8>>,
    body_read: usize,
}

impl<R: AsyncRead + Unpin + Send> V1Reader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            head: [0u8; V1_HEADER_LEN],
            head_read: 0,
            body: None,
            body_read: 0,
        }
    }

    /// Next frame. A wrong magic, a bad command, or a length over
    /// [`MAX_PROTOCOL_MESSAGE_LENGTH`] is an error before any body byte is
    /// read. A bad checksum drops that message and reads on, as Core does;
    /// `on_drop` counts it the way the session counts a v2 decoy. The
    /// checksum runs inline, as the v2 reader decrypts inline.
    pub async fn read_frame<D>(
        &mut self,
        magic: Magic,
        mut on_drop: D,
    ) -> Result<FramedMessage, NetError>
    where
        D: FnMut(usize) -> Result<(), NetError>,
    {
        loop {
            if self.body.is_none() {
                self.fill_head().await?;
                let len = self.check_head(magic)?;
                self.body = Some(vec![0u8; len]);
                self.body_read = 0;
            }
            if let Some(body) = self.body.as_mut() {
                while self.body_read < body.len() {
                    let n = self.inner.read(&mut body[self.body_read..]).await?;
                    if n == 0 {
                        return Err(eof("v1 body eof"));
                    }
                    self.body_read += n;
                }
            }
            let payload = self.body.take().unwrap_or_default();
            self.head_read = 0;
            let mut command = [0u8; 12];
            command.copy_from_slice(&self.head[4..16]);
            if checksum(&payload) != self.head[20..24] {
                rbitcoin_log::debug!(
                    "p2p: v1 checksum error, {} byte message dropped",
                    payload.len()
                );
                on_drop(payload.len())?;
                continue;
            }
            return Ok(FramedMessage {
                magic,
                command,
                payload,
            });
        }
    }

    async fn fill_head(&mut self) -> Result<(), NetError> {
        while self.head_read < V1_HEADER_LEN {
            let n = self.inner.read(&mut self.head[self.head_read..]).await?;
            if n == 0 {
                return Err(eof("v1 header eof"));
            }
            self.head_read += n;
        }
        Ok(())
    }

    fn check_head(&self, magic: Magic) -> Result<usize, NetError> {
        if self.head[..4] != magic.to_bytes() {
            return Err(NetError::BadMagic);
        }
        let mut command = [0u8; 12];
        command.copy_from_slice(&self.head[4..16]);
        if !command_bytes_ok(&command) {
            return Err(NetError::Protocol("invalid message command"));
        }
        let len = u32::from_le_bytes([self.head[16], self.head[17], self.head[18], self.head[19]]);
        let len = usize::try_from(len).map_err(|_| NetError::MessageTooLarge(usize::MAX))?;
        if len > MAX_PROTOCOL_MESSAGE_LENGTH {
            return Err(NetError::MessageTooLarge(len));
        }
        Ok(len)
    }
}

fn eof(what: &'static str) -> NetError {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, what).into()
}

/// v1 writer. Takes the same BIP324 application contents the v2 writer does
/// (short id or long command, then payload) and frames them for v1.
pub struct V1Writer<W> {
    inner: W,
    magic: Magic,
}

impl<W: AsyncWrite + Unpin + Send> V1Writer<W> {
    pub fn new(inner: W, magic: Magic) -> Self {
        Self { inner, magic }
    }

    pub async fn write_contents(&mut self, contents: Vec<u8>) -> Result<(), NetError> {
        let magic = self.magic;
        let frame = if contents.len() < V1_OFFLOAD_LEN {
            contents_to_v1(magic, &contents)?
        } else {
            rbitcoin_consensus::script_pool::run_cpu(move || contents_to_v1(magic, &contents))
                .await
                .ok_or(NetError::Protocol("encode task join failed"))??
        };
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

fn contents_to_v1(magic: Magic, contents: &[u8]) -> Result<Vec<u8>, NetError> {
    let (command, prefix) = crate::v2::v2_command(contents)?;
    v1_frame(magic, command, &contents[prefix..])
}

pub type V1SessionReader = V1Reader<PrefixedRead<BufReader<CountRead<OwnedReadHalf>>>>;
pub type V1SessionWriter = V1Writer<CountWrite<OwnedWriteHalf>>;

/// Read half of an inbound session: BIP324, or v1 on a `v1@` listener.
pub enum PeerReader {
    V2(V2Reader),
    V1(V1SessionReader),
}

/// Write half of an inbound session.
pub enum PeerWriter {
    V2(V2Writer),
    V1(V1SessionWriter),
}

impl From<V2Reader> for PeerReader {
    fn from(r: V2Reader) -> Self {
        Self::V2(r)
    }
}

impl From<V2Writer> for PeerWriter {
    fn from(w: V2Writer) -> Self {
        Self::V2(w)
    }
}

/// Inbound accept. Nothing is written before the 16-byte v1 prefix check.
/// A peer that sends the whole prefix gets v1 when `perms` has
/// [`NetPermissionFlags::V1`], and [`NetError::V1Peer`] otherwise.
pub async fn open_inbound_with_wire(
    stream: TcpStream,
    magic: Magic,
    wire: WireBytes,
    perms: NetPermissionFlags,
) -> Result<(PeerReader, PeerWriter, WireBytes, std::net::TcpStream), NetError> {
    let (mut reader, writer, tcp_shutdown) = counted_halves(stream, &wire)?;
    let prefix = match wait_v1_prefix_mismatch(&mut reader, magic.to_bytes()).await {
        Err(NetError::V1Peer) if perms.has(NetPermissionFlags::V1) => {
            let reader = PrefixedRead {
                prefix: v1_prefix(magic.to_bytes()).to_vec(),
                pos: 0,
                inner: reader,
            };
            return Ok((
                PeerReader::V1(V1Reader::new(reader)),
                PeerWriter::V1(V1Writer::new(writer, magic)),
                wire,
                tcp_shutdown,
            ));
        }
        other => other?,
    };
    let (r, w) = bip324_halves(reader, writer, prefix, magic, true).await?;
    Ok((PeerReader::V2(r), PeerWriter::V2(w), wire, tcp_shutdown))
}

/// `getpeerinfo.transport_protocol_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    V1,
    V2,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl PeerReader {
    /// [`read_v2_frame_with_progress`] for v2. For v1, `on_decoy` counts a
    /// message dropped for a bad checksum.
    pub async fn read_frame_with_progress<F, D>(
        &mut self,
        magic: Magic,
        on_progress: F,
        on_decoy: D,
    ) -> Result<FramedMessage, NetError>
    where
        F: FnMut(usize),
        D: FnMut(usize) -> Result<(), NetError>,
    {
        match self {
            Self::V2(r) => read_v2_frame_with_progress(r, magic, on_progress, on_decoy).await,
            Self::V1(r) => r.read_frame(magic, on_decoy).await,
        }
    }
}

impl PeerWriter {
    pub async fn write_contents(&mut self, contents: Vec<u8>) -> Result<(), NetError> {
        match self {
            Self::V2(w) => write_v2_contents(w, contents).await,
            Self::V1(w) => w.write_contents(contents).await,
        }
    }

    /// A heavy payload encodes on `rbtc-scripts-*`.
    pub async fn write_msg_offload(&mut self, msg: NetworkMessage) -> Result<(), NetError> {
        let contents = encode_v2_payload(msg).await?;
        self.write_contents(contents).await
    }
}

/// The version/verack exchange reads through this.
pub trait FrameRead: Send {
    fn read_frame(
        &mut self,
        magic: Magic,
    ) -> impl Future<Output = Result<FramedMessage, NetError>> + Send;
}

/// The version/verack exchange writes through this.
pub trait FrameWrite: Send {
    fn write_msg(
        &mut self,
        msg: NetworkMessage,
    ) -> impl Future<Output = Result<(), NetError>> + Send;
}

impl FrameRead for V2Reader {
    fn read_frame(
        &mut self,
        magic: Magic,
    ) -> impl Future<Output = Result<FramedMessage, NetError>> + Send {
        read_v2_frame(self, magic)
    }
}

impl FrameWrite for V2Writer {
    fn write_msg(
        &mut self,
        msg: NetworkMessage,
    ) -> impl Future<Output = Result<(), NetError>> + Send {
        write_v2_msg(self, msg)
    }
}

impl FrameRead for PeerReader {
    fn read_frame(
        &mut self,
        magic: Magic,
    ) -> impl Future<Output = Result<FramedMessage, NetError>> + Send {
        self.read_frame_with_progress(magic, |_| {}, |_| Ok(()))
    }
}

impl FrameWrite for PeerWriter {
    async fn write_msg(&mut self, msg: NetworkMessage) -> Result<(), NetError> {
        let contents = encode_v2_contents(msg)?;
        self.write_contents(contents).await
    }
}
