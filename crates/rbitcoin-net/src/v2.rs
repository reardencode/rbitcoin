//! BIP324 v2-only encrypted transport.
//!
//! Production peers complete a BIP324 handshake first; application `version` /
//! `verack` and all later messages travel as encrypted packets whose plaintext
//! is the BIP324 v2 message encoding (1-byte short ID or 13-byte long command +
//! payload — no network magic, length, or checksum).
//!
//! Peers that only speak v1 are disconnected ([`NetError::V1Peer`]).

use crate::codec::{
    command_bytes_ok, encode_is_cpu_heavy, FramedMessage, MAX_HEADERS_RESULTS, MAX_INV_SIZE,
    MAX_LOCATOR_SZ, MAX_PROTOCOL_MESSAGE_LENGTH,
};
use crate::error::NetError;
use bip324::futures::{Protocol, ProtocolReader, ProtocolSessionReader, ProtocolWriter};
use bip324::io::{Payload, ProtocolError, ProtocolFailureSuggestion};
use bip324::{Error as Bip324Error, InboundCipher, PacketType, Role};
use bitcoin::consensus::serialize;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Raw TCP bytes observed after connect (Core `nRecvBytes` / `nSendBytes`).
#[derive(Clone, Debug)]
pub struct WireBytes {
    pub recv: Arc<AtomicU64>,
    pub sent: Arc<AtomicU64>,
}

impl WireBytes {
    pub fn new() -> Self {
        Self {
            recv: Arc::new(AtomicU64::new(0)),
            sent: Arc::new(AtomicU64::new(0)),
        }
    }
}

pub(crate) struct CountRead<R> {
    inner: R,
    n: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let added = buf.filled().len().saturating_sub(before);
                self.n.fetch_add(added as u64, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub(crate) struct CountWrite<W> {
    inner: W,
    n: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.n.fetch_add(n as u64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Core `V2Transport` max BIP324 contents: long-type byte + 12-byte command + payload.
/// One byte tighter than `bip324`'s alloc cap (`4000014`), matching `net.cpp`.
pub const MAX_V2_CONTENTS_LEN: usize = 1 + 12 + MAX_PROTOCOL_MESSAGE_LENGTH;

/// Ciphertext after the 3-byte length: 1-byte ignore header + Poly1305 tag.
const V2_PACKET_REST_OVERHEAD: usize = 1 + 16;

/// Core `BIP324Cipher::EXPANSION`: 3-byte length + header + Poly1305 tag.
/// `bytesrecv_per_msg['*other*']` = contents + this (test_msgtype expects 23).
pub const V2_CIPHER_EXPANSION: usize = 3 + V2_PACKET_REST_OVERHEAD;

/// Raw `getpeerinfo` bytes for a rejected v2 type (`*other*`).
pub fn v2_other_recv_bytes(contents_len: usize) -> u64 {
    (contents_len + V2_CIPHER_EXPANSION) as u64
}

/// `p2p_invalid_messages.py` v2 needle for an oversized length prefix.
pub fn v2_packet_too_large_log(n: usize) -> String {
    format!("V2 transport error: packet too large ({n} bytes)")
}

/// Cancellation-safe BIP324 application read (length prefix, then body).
enum DecryptState {
    ReadingLength {
        length_bytes: [u8; 3],
        bytes_read: usize,
    },
    ReadingPayload {
        packet_bytes: Vec<u8>,
        bytes_read: usize,
    },
}

impl DecryptState {
    fn reading_length() -> Self {
        Self::ReadingLength {
            length_bytes: [0u8; 3],
            bytes_read: 0,
        }
    }
}

/// Post-handshake v2 reader. Rejects Core-oversized length prefixes before
/// allocating / decrypting the body (`p2p_invalid_messages.py` `test_size`).
pub struct V2SessionReader<R> {
    inbound_cipher: InboundCipher,
    reader: ProtocolSessionReader<R>,
    state: DecryptState,
}

impl<R: AsyncRead + Unpin + Send> V2SessionReader<R> {
    fn from_protocol_reader(r: ProtocolReader<R>) -> Self {
        let (inbound_cipher, reader) = r.into_inner();
        Self {
            inbound_cipher,
            reader,
            state: DecryptState::reading_length(),
        }
    }
    /// Next genuine application contents (skips decoys). Checks the decrypted
    /// length prefix against [`MAX_V2_CONTENTS_LEN`] before reading the body.
    async fn read_genuine_contents<F>(&mut self, mut on_progress: F) -> Result<Vec<u8>, NetError>
    where
        F: FnMut(usize),
    {
        loop {
            let (packet_type, plaintext) = self.read_packet(&mut on_progress).await?;
            if packet_type == PacketType::Decoy {
                continue;
            }
            // plaintext = 1-byte ignore header + application contents
            if plaintext.is_empty() {
                return Err(NetError::Protocol("empty v2 packet plaintext"));
            }
            return Ok(plaintext[1..].to_vec());
        }
    }

    async fn read_packet<F>(
        &mut self,
        on_progress: &mut F,
    ) -> Result<(PacketType, Vec<u8>), NetError>
    where
        F: FnMut(usize),
    {
        loop {
            match &mut self.state {
                DecryptState::ReadingLength {
                    length_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < length_bytes.len() {
                        let n = self.reader.read(&mut length_bytes[*bytes_read..]).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "v2 length prefix eof",
                            )
                            .into());
                        }
                        *bytes_read += n;
                    }
                    let rest = self.inbound_cipher.decrypt_packet_len(*length_bytes);
                    let contents_len = rest.saturating_sub(V2_PACKET_REST_OVERHEAD);
                    if contents_len > MAX_V2_CONTENTS_LEN {
                        rbitcoin_log::info!("{}", v2_packet_too_large_log(contents_len));
                        self.state = DecryptState::reading_length();
                        return Err(NetError::MessageTooLarge(contents_len));
                    }
                    self.state = DecryptState::ReadingPayload {
                        packet_bytes: vec![0u8; rest],
                        bytes_read: 0,
                    };
                }
                DecryptState::ReadingPayload {
                    packet_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < packet_bytes.len() {
                        let n = self.reader.read(&mut packet_bytes[*bytes_read..]).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "v2 packet body eof",
                            )
                            .into());
                        }
                        *bytes_read += n;
                        on_progress(*bytes_read);
                    }
                    let mut plaintext = vec![0u8; packet_bytes.len().saturating_sub(16)];
                    let packet_type = self
                        .inbound_cipher
                        .decrypt(packet_bytes, &mut plaintext, None)
                        .map_err(|e| NetError::Bip324(e.to_string()))?;
                    self.state = DecryptState::reading_length();
                    return Ok((packet_type, plaintext));
                }
            }
        }
    }
}

/// Async read half after BIP324 handshake (buffered TCP).
pub type V2Reader = V2SessionReader<BufReader<CountRead<OwnedReadHalf>>>;
/// Async write half after BIP324 handshake.
pub type V2Writer = ProtocolWriter<CountWrite<OwnedWriteHalf>>;

/// Short ID → command name. Index 0 is the long-form escape (not a real message).
/// Matches Bitcoin Core `V2_MESSAGE_IDS` (net.cpp).
const SHORT_IDS: &[&str] = &[
    "", // 0: long encoding follows
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
    // 29–36 unimplemented placeholders (empty)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "feature", // 37
];

fn short_id_for_command(cmd: &str) -> Option<u8> {
    SHORT_IDS
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, name)| !name.is_empty() && **name == cmd)
        .map(|(i, _)| i as u8)
}

fn command_for_short_id(id: u8) -> Option<&'static str> {
    let idx = id as usize;
    if idx == 0 || idx >= SHORT_IDS.len() {
        return None;
    }
    let name = SHORT_IDS[idx];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn command_to_12(cmd: &str) -> [u8; 12] {
    let mut out = [0u8; 12];
    let b = cmd.as_bytes();
    let n = b.len().min(12);
    out[..n].copy_from_slice(&b[..n]);
    out
}

/// `p2p_invalid_messages.py` v2 needle for an unknown short/long type.
pub fn v2_invalid_message_type_log() -> &'static str {
    "V2 transport error: invalid message type"
}

fn command_from_12(cmd12: &[u8; 12]) -> Result<String, NetError> {
    if !command_bytes_ok(cmd12) {
        return Err(NetError::Protocol("invalid message command"));
    }
    let end = cmd12.iter().position(|&b| b == 0).unwrap_or(12);
    std::str::from_utf8(&cmd12[..end])
        .map(|s| s.to_string())
        .map_err(|_| NetError::Protocol("invalid message command"))
}

/// Encode a P2P application message as BIP324 packet contents (short/long type + payload).
pub fn encode_v2_contents(payload: NetworkMessage) -> Result<Vec<u8>, NetError> {
    match &payload {
        NetworkMessage::Inv(v) | NetworkMessage::GetData(v) | NetworkMessage::NotFound(v) => {
            if v.len() > MAX_INV_SIZE {
                return Err(NetError::MessageTooLarge(v.len()));
            }
        }
        NetworkMessage::Headers(h) => {
            if h.len() > MAX_HEADERS_RESULTS {
                return Err(NetError::MessageTooLarge(h.len()));
            }
        }
        NetworkMessage::GetHeaders(gh) => {
            if gh.locator_hashes.len() > MAX_LOCATOR_SZ {
                return Err(NetError::MessageTooLarge(gh.locator_hashes.len()));
            }
        }
        NetworkMessage::GetBlocks(gb) => {
            if gb.locator_hashes.len() > MAX_LOCATOR_SZ {
                return Err(NetError::MessageTooLarge(gb.locator_hashes.len()));
            }
        }
        _ => {}
    }

    let cmd = match &payload {
        NetworkMessage::Unknown { command, .. } => command.to_string(),
        _ => payload.cmd().to_string(),
    };
    let body = serialize(&payload);
    if body.len() > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(NetError::MessageTooLarge(body.len()));
    }

    if let Some(id) = short_id_for_command(&cmd) {
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(id);
        out.extend_from_slice(&body);
        Ok(out)
    } else {
        // Long form: 0x00 + 12-byte ASCII command (null-padded) + payload.
        let mut out = Vec::with_capacity(1 + 12 + body.len());
        out.push(0);
        out.extend_from_slice(&command_to_12(&cmd));
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Parse BIP324 packet contents into a [`FramedMessage`].
///
/// v2 plaintext is command + payload only (no checksum).
pub fn parse_v2_contents(magic: Magic, contents: &[u8]) -> Result<FramedMessage, NetError> {
    if contents.is_empty() {
        return Err(NetError::Protocol("empty v2 message contents"));
    }
    let first = contents[0];
    let (command, payload) = if first != 0 {
        match command_for_short_id(first) {
            Some(name) => (command_to_12(name), contents[1..].to_vec()),
            None => {
                rbitcoin_log::info!("{}", v2_invalid_message_type_log());
                return Err(NetError::InvalidV2Type {
                    contents_len: contents.len(),
                });
            }
        }
    } else {
        if contents.len() < 1 + 12 {
            return Err(NetError::Protocol("truncated v2 long command"));
        }
        let mut cmd12 = [0u8; 12];
        cmd12.copy_from_slice(&contents[1..13]);
        if command_from_12(&cmd12).is_err() {
            rbitcoin_log::info!("{}", v2_invalid_message_type_log());
            return Err(NetError::InvalidV2Type {
                contents_len: contents.len(),
            });
        }
        (cmd12, contents[13..].to_vec())
    };

    if payload.len() > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(NetError::MessageTooLarge(payload.len()));
    }

    Ok(FramedMessage {
        magic,
        command,
        payload,
    })
}

/// Parse BIP324 application contents with regtest magic, then try-decode.
pub fn parse_v2_regtest(contents: &[u8]) -> Result<(), NetError> {
    let frame = parse_v2_contents(Magic::from(bitcoin::Network::Regtest), contents)?;
    frame.try_decode().map(|_| ())
}

/// Long-form v2 contents for `command` then `payload`. Must not panic.
pub fn parse_v2_regtest_named(command: &str, payload: &[u8]) -> Result<(), NetError> {
    let mut contents = Vec::with_capacity(1 + 12 + payload.len());
    contents.push(0);
    let mut cmd12 = [0u8; 12];
    let n = command.len().min(12);
    cmd12[..n].copy_from_slice(&command.as_bytes()[..n]);
    contents.extend_from_slice(&cmd12);
    contents.extend_from_slice(payload);
    parse_v2_regtest(&contents)
}

fn map_protocol_error(e: ProtocolError) -> NetError {
    match e {
        // bip324 suggests RetryV1 on many hard closes — including peers that
        // completed v2 then dropped us. Prefer the IO detail when present so
        // logs are not all "does not speak BIP324 v2".
        ProtocolError::Io(io, ProtocolFailureSuggestion::RetryV1) => {
            if matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
            ) {
                NetError::Io(io)
            } else {
                NetError::V1Peer
            }
        }
        ProtocolError::Io(io, _) => NetError::Io(io),
        ProtocolError::Internal(Bip324Error::V1Protocol) => NetError::V1Peer,
        ProtocolError::Internal(inner) => NetError::Bip324(inner.to_string()),
    }
}

/// Complete BIP324 handshake on a connected TCP stream; return split encrypted halves.
///
/// The fourth value is a cloned std TCP handle for [`std::net::TcpStream::shutdown`]
/// on `disconnectnode` (far-side EOF without waiting on our session task).
///
/// Not cancellation-safe (BIP324 handshake). Callers should not wrap this in
/// `select!` without a dedicated task.
pub async fn open_v2(
    stream: TcpStream,
    magic: Magic,
    inbound: bool,
) -> Result<(V2Reader, V2Writer, WireBytes, std::net::TcpStream), NetError> {
    let _ = stream.set_nodelay(true);
    let std = stream.into_std().map_err(NetError::Io)?;
    std.set_nonblocking(true).map_err(NetError::Io)?;
    let tcp_shutdown = std.try_clone().map_err(NetError::Io)?;
    let stream = TcpStream::from_std(std).map_err(NetError::Io)?;
    let role = if inbound {
        Role::Responder
    } else {
        Role::Initiator
    };
    let magic_bytes = magic.to_bytes();
    let (rh, wh) = stream.into_split();
    let wire = WireBytes::new();
    let reader = BufReader::new(CountRead {
        inner: rh,
        n: Arc::clone(&wire.recv),
    });
    let writer = CountWrite {
        inner: wh,
        n: Arc::clone(&wire.sent),
    };
    // Protocol performs many small reads; BufReader is required for performance.
    let protocol = Protocol::new(magic_bytes, role, None, None, reader, writer)
        .await
        .map_err(map_protocol_error)?;
    let (r, w) = protocol.into_split();
    Ok((
        V2SessionReader::from_protocol_reader(r),
        w,
        wire,
        tcp_shutdown,
    ))
}

/// Encrypt and send raw BIP324 application contents (short/long command + payload).
pub async fn write_v2_contents<W>(
    writer: &mut ProtocolWriter<W>,
    contents: Vec<u8>,
) -> Result<(), NetError>
where
    W: AsyncWrite + Unpin + Send,
{
    writer
        .write(&Payload::genuine(contents))
        .await
        .map_err(map_protocol_error)
}

/// Encrypt and send one application message.
pub async fn write_v2_msg(writer: &mut V2Writer, payload: NetworkMessage) -> Result<(), NetError> {
    let contents = encode_v2_contents(payload)?;
    write_v2_contents(writer, contents).await
}

/// Like [`write_v2_msg`]; heavy payloads encode on the blocking pool before encrypt.
pub async fn write_v2_msg_offload(
    writer: &mut V2Writer,
    payload: NetworkMessage,
) -> Result<(), NetError> {
    let contents = if encode_is_cpu_heavy(&payload) {
        tokio::task::spawn_blocking(move || encode_v2_contents(payload))
            .await
            .map_err(|_| NetError::Protocol("encode task join failed"))??
    } else {
        encode_v2_contents(payload)?
    };
    write_v2_contents(writer, contents).await
}

/// Next genuine application contents (skips decoy packets).
pub async fn read_v2_contents<R>(reader: &mut V2SessionReader<R>) -> Result<Vec<u8>, NetError>
where
    R: AsyncRead + Unpin + Send,
{
    reader.read_genuine_contents(|_| {}).await
}

/// Read the next genuine application frame (skips decoy packets).
///
/// Cancellation-safe (length/body state lives on [`V2SessionReader`]).
pub async fn read_v2_frame<R>(
    reader: &mut V2SessionReader<R>,
    magic: Magic,
) -> Result<FramedMessage, NetError>
where
    R: AsyncRead + Unpin + Send,
{
    read_v2_frame_with_progress(reader, magic, |_| {}).await
}

/// Read the next genuine frame; `on_progress` is invoked as ciphertext body
/// bytes arrive, then again with decrypted content length.
pub async fn read_v2_frame_with_progress<R, F>(
    reader: &mut V2SessionReader<R>,
    magic: Magic,
    mut on_progress: F,
) -> Result<FramedMessage, NetError>
where
    R: AsyncRead + Unpin + Send,
    F: FnMut(usize),
{
    let contents = reader.read_genuine_contents(&mut on_progress).await?;
    on_progress(contents.len());
    parse_v2_contents(magic, &contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use tokio::io::duplex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn signet_magic() -> Magic {
        Magic::from(Network::Signet)
    }

    #[test]
    fn short_id_roundtrip_common() {
        assert_eq!(short_id_for_command("block"), Some(2));
        assert_eq!(short_id_for_command("ping"), Some(18));
        assert_eq!(short_id_for_command("version"), None); // long form
        assert_eq!(command_for_short_id(2), Some("block"));
        assert_eq!(command_for_short_id(18), Some("ping"));
    }

    /// Live IBD + tip-follow + tip-tx command set must map to Core BIP324 short IDs.
    #[test]
    fn short_ids_cover_live_ibd_tip_commands() {
        // Commands used on current sync / tip follow / tip tx relay paths.
        let live = [
            ("addr", 1u8),
            ("block", 2),
            ("blocktxn", 3),
            ("cmpctblock", 4),
            ("feefilter", 5),
            ("getblocks", 9),
            ("getblocktxn", 10),
            ("getdata", 11),
            ("getheaders", 12),
            ("headers", 13),
            ("inv", 14),
            ("mempool", 15),
            ("notfound", 17),
            ("ping", 18),
            ("pong", 19),
            ("sendcmpct", 20),
            ("tx", 21),
            ("addrv2", 28),
        ];
        for (cmd, id) in live {
            assert_eq!(short_id_for_command(cmd), Some(id), "short id for {cmd}");
            assert_eq!(command_for_short_id(id), Some(cmd));
            // Round-trip through encode/parse for empty-payload or simple msgs.
        }
        // Application handshake uses long form (not short-id).
        assert!(short_id_for_command("version").is_none());
        assert!(short_id_for_command("verack").is_none());
        assert_eq!(
            v2_invalid_message_type_log(),
            "V2 transport error: invalid message type"
        );
        assert_eq!(MAX_V2_CONTENTS_LEN, 4_000_013);
        assert_eq!(
            v2_packet_too_large_log(4_000_014),
            "V2 transport error: packet too large (4000014 bytes)"
        );
        assert_eq!(V2_CIPHER_EXPANSION, 20);
        assert_eq!(v2_other_recv_bytes(3), 23);
        assert!(short_id_for_command("wtxidrelay").is_none());
        assert!(short_id_for_command("sendheaders").is_none());
        assert!(short_id_for_command("sendaddrv2").is_none());
        // Placeholder slots 29–36 stay empty (unknown short id → protocol error).
        for id in 29u8..=36 {
            assert!(command_for_short_id(id).is_none(), "slot {id} empty");
        }
        assert_eq!(command_for_short_id(37), Some("feature"));
    }

    #[test]
    fn encode_parse_live_short_id_messages() {
        let magic = signet_magic();
        for payload in [
            NetworkMessage::Ping(1),
            NetworkMessage::Pong(1),
            NetworkMessage::MemPool,
            NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact: true,
                version: 2,
            }),
        ] {
            let contents = encode_v2_contents(payload.clone()).unwrap();
            assert_ne!(contents[0], 0, "expected short id for {:?}", payload.cmd());
            let frame = parse_v2_contents(magic, &contents).unwrap();
            assert_eq!(frame.decode().payload().cmd(), payload.cmd());
        }
    }

    #[test]
    fn parse_v2_regtest_named_junk_does_not_panic() {
        for cmd in ["addrv2", "inv", "getdata"] {
            let _ = parse_v2_regtest_named(cmd, &[]);
            let _ = parse_v2_regtest_named(cmd, &[0xff; 64]);
            let _ = parse_v2_regtest_named(cmd, &[0x00, 0x01, 0x02]);
        }
    }

    #[test]
    fn encode_parse_verack_long_form() {
        let magic = signet_magic();
        let contents = encode_v2_contents(NetworkMessage::Verack).unwrap();
        // version/verack use long form: 0x00 + "verack" + pad + empty payload
        assert_eq!(contents[0], 0);
        assert_eq!(&contents[1..7], b"verack");
        let frame = parse_v2_contents(magic, &contents).unwrap();
        assert!(matches!(frame.decode().payload(), NetworkMessage::Verack));
    }

    /// Regression: `sendaddrv2` contains a digit — long-form parse must accept it
    /// (Core IsCommandValid allows printable ASCII). Rejecting digits killed
    /// post-handshake IBD peers that advertise BIP155.
    #[test]
    fn encode_parse_sendaddrv2_long_form_with_digit() {
        let magic = signet_magic();
        let contents = encode_v2_contents(NetworkMessage::SendAddrV2).unwrap();
        assert_eq!(contents[0], 0); // long form
        assert_eq!(&contents[1..11], b"sendaddrv2");
        let frame = parse_v2_contents(magic, &contents).expect("digit in command ok");
        assert!(matches!(
            frame.decode().payload(),
            NetworkMessage::SendAddrV2
        ));
    }

    /// `test_msgtype`: unknown short id logs and is not a hard disconnect.
    #[test]
    fn unknown_short_id_is_invalid_type_not_protocol() {
        let magic = signet_magic();
        // short id 99 + compact-size string "d" (Core `msg_unrecognized`).
        let contents = vec![99u8, 1, b'd'];
        match parse_v2_contents(magic, &contents) {
            Err(NetError::InvalidV2Type { contents_len }) => {
                assert_eq!(contents_len, 3);
                assert_eq!(v2_other_recv_bytes(contents_len), 23);
            }
            other => panic!("expected InvalidV2Type, got {other:?}"),
        }
    }

    #[test]
    fn encode_parse_ping_short_id() {
        let magic = signet_magic();
        let contents = encode_v2_contents(NetworkMessage::Ping(0xdead_beef)).unwrap();
        assert_eq!(contents[0], 18); // ping short id
        assert_eq!(contents.len(), 1 + 8);
        let frame = parse_v2_contents(magic, &contents).unwrap();
        assert!(frame.is_ping());
        assert_eq!(frame.ping_nonce(), Some(0xdead_beef));
    }

    /// v2 has no checksum; decode must not require sha256d of the payload.
    #[test]
    fn parse_v2_block_zero_checksum_decodes() {
        use bitcoin::blockdata::constants::genesis_block;
        let magic = Magic::from(Network::Bitcoin);
        let genesis = genesis_block(Network::Bitcoin);
        let want = genesis.block_hash();
        let contents = encode_v2_contents(NetworkMessage::Block(genesis)).unwrap();
        let frame = parse_v2_contents(magic, &contents).unwrap();
        match frame.decode().payload() {
            NetworkMessage::Block(b) => assert_eq!(b.block_hash(), want),
            other => panic!("expected block, got {other:?}"),
        }
    }

    /// Two ends of a tokio duplex complete BIP324 + application ping/pong.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bip324_duplex_ping_pong() {
        let magic = signet_magic();
        let magic_b = magic.to_bytes();
        let (client, server) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let (rh, wh) = tokio::io::split(server);
            let reader = BufReader::new(rh);
            let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
                .await
                .expect("server handshake");
            let (mut r, mut w) = protocol.into_split();
            // read genuine packet
            loop {
                let p = r.read().await.expect("server read");
                if p.packet_type() == PacketType::Genuine {
                    let frame = parse_v2_contents(magic, p.contents()).unwrap();
                    assert!(frame.is_ping());
                    let n = frame.ping_nonce().unwrap();
                    let contents = encode_v2_contents(NetworkMessage::Pong(n)).unwrap();
                    w.write(&Payload::genuine(contents)).await.unwrap();
                    break;
                }
            }
        });

        let client_task = async move {
            let (rh, wh) = tokio::io::split(client);
            let reader = BufReader::new(rh);
            let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
                .await
                .expect("client handshake");
            let (r, mut w) = protocol.into_split();
            let contents = encode_v2_contents(NetworkMessage::Ping(42)).unwrap();
            write_v2_contents(&mut w, contents).await.unwrap();
            let mut reader = V2SessionReader::from_protocol_reader(r);
            let got = read_v2_contents(&mut reader).await.unwrap();
            let frame = parse_v2_contents(magic, &got).unwrap();
            assert!(matches!(frame.decode().payload(), NetworkMessage::Pong(42)));
            server_task.await.unwrap();
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
            .await
            .expect("bip324 duplex timed out");
    }

    /// V1-looking ellswift slot (network magic in first 4 of 64 bytes) → V1Peer.
    ///
    /// bip324 detects this only after a full 64-byte key read — sending fewer
    /// bytes would hang on `read_exact`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v1_peer_rejected() {
        let magic = signet_magic();
        let (mut client, server) = duplex(8 * 1024);

        let server_task = tokio::spawn(async move {
            let (rh, wh) = tokio::io::split(server);
            let reader = BufReader::new(rh);
            Protocol::new(magic.to_bytes(), Role::Responder, None, None, reader, wh).await
        });

        // Drain responder's ellswift key first so its write does not block.
        let mut their_key = [0u8; 64];
        client.read_exact(&mut their_key).await.unwrap();

        // Fake "key" whose first 4 bytes are network magic (Core/bip324 V1 probe).
        let mut v1_key = [0u8; 64];
        v1_key[..4].copy_from_slice(&magic.to_bytes());
        client.write_all(&v1_key).await.unwrap();
        client.flush().await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("v1 detect timed out")
            .expect("server task join");
        let err = match result {
            Ok(_) => panic!("v1-looking peer must fail BIP324 handshake"),
            Err(e) => e,
        };
        let mapped = map_protocol_error(err);
        assert!(
            matches!(mapped, NetError::V1Peer),
            "expected V1Peer, got {mapped}"
        );
    }

    /// Core `test_size`: reject on the decrypted length prefix — do not wait
    /// for the 4 MiB ciphertext. Only the 3-byte length is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_v2_length_prefix_rejects_before_body() {
        use bip324::OutboundCipher;
        use tokio::io::AsyncWriteExt;

        let magic = signet_magic();
        let magic_b = magic.to_bytes();
        // Handshake + 3-byte length only; body is never sent.
        let (client, server) = duplex(8 * 1024);

        let server_task = tokio::spawn(async move {
            let (rh, wh) = tokio::io::split(server);
            let reader = BufReader::new(rh);
            let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
                .await
                .expect("server handshake");
            let (r, _w) = protocol.into_split();
            let mut reader = V2SessionReader::from_protocol_reader(r);
            read_v2_frame(&mut reader, magic).await
        });

        let (rh, wh) = tokio::io::split(client);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
            .await
            .expect("client handshake");
        let (_r, w) = protocol.into_split();
        let (mut cipher, mut raw_w) = w.into_inner();
        let too_big = MAX_V2_CONTENTS_LEN + 1;
        let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(too_big)];
        let plaintext = vec![0u8; too_big];
        cipher
            .encrypt(&plaintext, &mut packet, PacketType::Genuine, None)
            .expect("encrypt oversized length");
        // Length prefix only — Core disconnects here.
        raw_w.write_all(&packet[..3]).await.unwrap();
        raw_w.flush().await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("oversize detect timed out")
            .expect("server task join");
        match result {
            Err(NetError::MessageTooLarge(n)) => assert_eq!(n, too_big),
            other => panic!("expected MessageTooLarge({too_big}), got {other:?}"),
        }
    }

    #[test]
    fn truncated_v2_long_command_is_protocol() {
        assert!(matches!(
            parse_v2_contents(signet_magic(), &[0u8, b'v', b'e']),
            Err(NetError::Protocol("truncated v2 long command"))
        ));
    }

    fn v2_fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn v2_ping_fixture_matches_encode() {
        let expected = encode_v2_contents(NetworkMessage::Ping(0xdead_beef)).unwrap();
        let path = v2_fixture_path("v2_ping.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        parse_v2_regtest(&raw).unwrap();
    }

    #[test]
    fn v2_verack_fixture_matches_encode() {
        let expected = encode_v2_contents(NetworkMessage::Verack).unwrap();
        let path = v2_fixture_path("v2_verack.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        parse_v2_regtest(&raw).unwrap();
    }

    #[test]
    fn v2_sendaddrv2_fixture_matches_encode() {
        let expected = encode_v2_contents(NetworkMessage::SendAddrV2).unwrap();
        let path = v2_fixture_path("v2_sendaddrv2.bin");
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(raw, expected);
        parse_v2_regtest(&raw).unwrap();
    }

    #[test]
    fn parse_v2_regtest_rejects_empty_and_unknown_short_id() {
        assert!(parse_v2_regtest(&[]).is_err());
        assert!(parse_v2_regtest(&[99u8, 1, b'd']).is_err());
    }
}
