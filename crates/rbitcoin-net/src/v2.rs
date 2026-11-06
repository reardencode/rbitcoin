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

/// Core `V1_PREFIX_LEN`: network magic + `"version\x00\x00\x00\x00\x00"`.
#[doc(hidden)]
pub const V1_PREFIX_LEN: usize = 16;

#[doc(hidden)]
pub fn v1_prefix(magic: [u8; 4]) -> [u8; V1_PREFIX_LEN] {
    let mut p = [0u8; V1_PREFIX_LEN];
    p[..4].copy_from_slice(&magic);
    p[4..11].copy_from_slice(b"version");
    p
}

/// Replay bytes already read during EARLY_KEY_RESPONSE before the TCP tail.
pub struct PrefixedRead<R> {
    pub prefix: Vec<u8>,
    pub pos: usize,
    pub inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rest = &self.prefix[self.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// A v2 handshake that never finished. The functional debug-log map emits
/// Core's sentence; this line is what an operator reads.
pub fn v2_handshake_timeout_log(peer: u64) -> String {
    format!("p2p: v2 handshake timed out, disconnecting peer={peer}")
}

pub fn v2_missing_garbage_terminator_log() -> &'static str {
    "p2p: v2 handshake had no garbage terminator"
}

pub fn v2_packet_decryption_failure_log() -> &'static str {
    "p2p: v2 packet did not decrypt"
}

/// Unix seconds for [`WireBytes`] stamps.
pub type WireClock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(crate) fn system_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Raw TCP bytes observed after connect, and the unix seconds they last
/// moved (`0` = never, Core `m_last_recv` / `m_last_send`).
#[derive(Clone)]
pub struct WireBytes {
    pub recv: Arc<AtomicU64>,
    pub sent: Arc<AtomicU64>,
    pub last_recv: Arc<AtomicU64>,
    pub last_sent: Arc<AtomicU64>,
    clock: WireClock,
}

impl std::fmt::Debug for WireBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireBytes")
            .field("recv", &self.recv)
            .field("sent", &self.sent)
            .field("last_recv", &self.last_recv)
            .field("last_sent", &self.last_sent)
            .finish_non_exhaustive()
    }
}

impl Default for WireBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl WireBytes {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(system_secs))
    }

    pub fn with_clock(clock: WireClock) -> Self {
        Self {
            recv: Arc::new(AtomicU64::new(0)),
            sent: Arc::new(AtomicU64::new(0)),
            last_recv: Arc::new(AtomicU64::new(0)),
            last_sent: Arc::new(AtomicU64::new(0)),
            clock,
        }
    }

    pub fn count_read<R>(&self, inner: R) -> CountRead<R> {
        CountRead {
            inner,
            n: Arc::clone(&self.recv),
            at: Arc::clone(&self.last_recv),
            clock: Arc::clone(&self.clock),
        }
    }

    pub fn count_write<W>(&self, inner: W) -> CountWrite<W> {
        CountWrite {
            inner,
            n: Arc::clone(&self.sent),
            at: Arc::clone(&self.last_sent),
            clock: Arc::clone(&self.clock),
        }
    }
}

pub struct CountRead<R> {
    inner: R,
    n: Arc<AtomicU64>,
    at: Arc<AtomicU64>,
    clock: WireClock,
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
                if added > 0 {
                    self.n.fetch_add(added as u64, Ordering::Relaxed);
                    self.at.store((self.clock)(), Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub struct CountWrite<W> {
    inner: W,
    n: Arc<AtomicU64>,
    at: Arc<AtomicU64>,
    clock: WireClock,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.n.fetch_add(n as u64, Ordering::Relaxed);
                    self.at.store((self.clock)(), Ordering::Relaxed);
                }
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
#[doc(hidden)]
pub const V2_PACKET_REST_OVERHEAD: usize = 1 + 16;

/// Fixed ciphertext scratch for one IBD reader. Covers the largest v2 packet
/// body (`MAX_V2_CONTENTS_LEN` + header + tag) and is never resized.
#[doc(hidden)]
pub const IBD_CIPHERTEXT_BUF_LEN: usize = 4 * 1024 * 1024;
const _: () = assert!(MAX_V2_CONTENTS_LEN + V2_PACKET_REST_OVERHEAD <= IBD_CIPHERTEXT_BUF_LEN);

/// Core `BIP324Cipher::EXPANSION`: 3-byte length + header + Poly1305 tag.
/// `bytesrecv_per_msg['*other*']` = contents + this (test_msgtype expects 23).
pub const V2_CIPHER_EXPANSION: usize = 3 + V2_PACKET_REST_OVERHEAD;

/// Raw `getpeerinfo` bytes for a rejected v2 type (`*other*`).
pub fn v2_other_recv_bytes(contents_len: usize) -> u64 {
    (contents_len + V2_CIPHER_EXPANSION) as u64
}

/// A v2 length prefix past the cap. The functional debug-log map emits
/// Core's sentence; this line is what an operator reads.
pub fn v2_packet_too_large_log(n: usize) -> String {
    format!("p2p: v2 packet is longer than the cap ({n} bytes)")
}

/// Ciphertext for the packet in progress. An IBD read moves the reader's
/// fixed buffer here, so the payload arm has one slice.
#[doc(hidden)]
pub enum CipherBuf {
    Owned(Vec<u8>),
    Ibd(Box<[u8]>),
}

/// Cancellation-safe BIP324 application read (length prefix, then body).
#[doc(hidden)]
pub enum DecryptState {
    ReadingLength {
        length_bytes: [u8; 3],
        bytes_read: usize,
    },
    ReadingPayload {
        buf: CipherBuf,
        packet_len: usize,
        bytes_read: usize,
    },
}

impl DecryptState {
    #[doc(hidden)]
    pub fn reading_length() -> Self {
        Self::ReadingLength {
            length_bytes: [0u8; 3],
            bytes_read: 0,
        }
    }
}

/// Post-handshake v2 reader. Rejects Core-oversized length prefixes before
/// allocating / decrypting the body (`p2p_invalid_messages.py` `test_size`).
pub struct V2SessionReader<R> {
    pub inbound_cipher: InboundCipher,
    pub reader: ProtocolSessionReader<R>,
    pub state: DecryptState,
    /// Fixed IBD ciphertext. Empty on tip-follow, and while a packet body
    /// is in progress (the buffer then lives on [`DecryptState`]).
    ibd_ciphertext: Option<Box<[u8]>>,
}

impl<R: AsyncRead + Unpin + Send> V2SessionReader<R> {
    pub fn from_protocol_reader(r: ProtocolReader<R>) -> Self {
        let (inbound_cipher, reader) = r.into_inner();
        Self {
            inbound_cipher,
            reader,
            state: DecryptState::reading_length(),
            ibd_ciphertext: None,
        }
    }

    /// Keep one 4 MiB ciphertext buffer for the rest of this reader.
    /// IBD calls this once. Tip-follow does not.
    pub fn enable_ibd_ciphertext_buf(&mut self) {
        if self.ibd_ciphertext.is_none() {
            self.ibd_ciphertext = Some(vec![0u8; IBD_CIPHERTEXT_BUF_LEN].into_boxed_slice());
        }
    }

    #[doc(hidden)]
    pub fn ibd_ciphertext_buf(&self) -> Option<&[u8]> {
        self.ibd_ciphertext.as_deref()
    }
    /// Next genuine application contents (skips decoys). Checks the decrypted
    /// length prefix against [`MAX_V2_CONTENTS_LEN`] before reading the body.
    pub async fn read_genuine_contents<F, D>(
        &mut self,
        on_progress: F,
        on_decoy: D,
    ) -> Result<Vec<u8>, NetError>
    where
        F: FnMut(usize),
        D: FnMut(usize) -> Result<(), NetError>,
    {
        let mut plaintext = self.read_genuine_plaintext(on_progress, on_decoy).await?;
        slide_off(&mut plaintext, 1);
        Ok(plaintext)
    }

    /// Genuine plaintext, including the 1-byte ignore header. Skips decoys.
    async fn read_genuine_plaintext<F, D>(
        &mut self,
        mut on_progress: F,
        mut on_decoy: D,
    ) -> Result<Vec<u8>, NetError>
    where
        F: FnMut(usize),
        D: FnMut(usize) -> Result<(), NetError>,
    {
        loop {
            let (packet_type, plaintext) = self.read_packet(&mut on_progress).await?;
            if packet_type == PacketType::Decoy {
                on_decoy(plaintext.len())?;
                continue;
            }
            if plaintext.is_empty() {
                return Err(NetError::Protocol("empty v2 packet plaintext"));
            }
            return Ok(plaintext);
        }
    }

    pub async fn read_packet<F>(
        &mut self,
        on_progress: &mut F,
    ) -> Result<(PacketType, Vec<u8>), NetError>
    where
        F: FnMut(usize),
    {
        let Self {
            inbound_cipher,
            reader,
            state,
            ibd_ciphertext,
        } = self;
        loop {
            match state {
                DecryptState::ReadingLength {
                    length_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < length_bytes.len() {
                        let n = reader.read(&mut length_bytes[*bytes_read..]).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "v2 length prefix eof",
                            )
                            .into());
                        }
                        *bytes_read += n;
                    }
                    let rest = inbound_cipher.decrypt_packet_len(*length_bytes);
                    let contents_len = rest.saturating_sub(V2_PACKET_REST_OVERHEAD);
                    if contents_len > MAX_V2_CONTENTS_LEN {
                        rbitcoin_log::info!("{}", v2_packet_too_large_log(contents_len));
                        *state = DecryptState::reading_length();
                        return Err(NetError::MessageTooLarge(contents_len));
                    }
                    let buf = match ibd_ciphertext.take() {
                        Some(scratch) => CipherBuf::Ibd(scratch),
                        None => CipherBuf::Owned(vec![0u8; rest]),
                    };
                    *state = DecryptState::ReadingPayload {
                        buf,
                        packet_len: rest,
                        bytes_read: 0,
                    };
                }
                DecryptState::ReadingPayload {
                    buf,
                    packet_len,
                    bytes_read,
                } => {
                    let packet_len = *packet_len;
                    let packet = match buf {
                        CipherBuf::Owned(owned) => owned.as_mut_slice(),
                        CipherBuf::Ibd(scratch) => &mut scratch[..packet_len],
                    };
                    fill_packet(reader, packet, bytes_read, on_progress).await?;
                    let packet = match buf {
                        CipherBuf::Owned(owned) => owned.as_slice(),
                        CipherBuf::Ibd(scratch) => &scratch[..packet_len],
                    };
                    let decrypted = decrypt_packet(inbound_cipher, packet)?;
                    if let DecryptState::ReadingPayload {
                        buf: CipherBuf::Ibd(scratch),
                        ..
                    } = std::mem::replace(state, DecryptState::reading_length())
                    {
                        *ibd_ciphertext = Some(scratch);
                    }
                    return Ok(decrypted);
                }
            }
        }
    }
}

async fn fill_packet<R, F>(
    reader: &mut ProtocolSessionReader<R>,
    packet: &mut [u8],
    filled: &mut usize,
    on_progress: &mut F,
) -> Result<(), NetError>
where
    R: AsyncRead + Unpin + Send,
    F: FnMut(usize),
{
    while *filled < packet.len() {
        let n = reader.read(&mut packet[*filled..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "v2 packet body eof",
            )
            .into());
        }
        *filled += n;
        on_progress(*filled);
    }
    Ok(())
}

fn decrypt_packet(
    cipher: &mut InboundCipher,
    packet: &[u8],
) -> Result<(PacketType, Vec<u8>), NetError> {
    let mut plaintext = vec![0u8; packet.len().saturating_sub(16)];
    let packet_type = cipher
        .decrypt(packet, &mut plaintext, None)
        .map_err(|e| NetError::Bip324(e.to_string()))?;
    Ok((packet_type, plaintext))
}

fn slide_off(buf: &mut Vec<u8>, n: usize) {
    buf.copy_within(n.., 0);
    buf.truncate(buf.len() - n);
}

/// Async read half after BIP324 handshake (buffered TCP).
pub type V2Reader = V2SessionReader<PrefixedRead<BufReader<CountRead<OwnedReadHalf>>>>;
/// Async write half after BIP324 handshake.
pub type V2Writer = ProtocolWriter<CountWrite<OwnedWriteHalf>>;

/// Short ID → command name. Index 0 is the long-form escape (not a real message).
/// Matches Bitcoin Core `V2_MESSAGE_IDS` (net.cpp).
#[doc(hidden)]
pub const SHORT_IDS: &[&str] = &[
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

#[doc(hidden)]
pub fn short_id_for_command(cmd: &str) -> Option<u8> {
    SHORT_IDS
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, name)| !name.is_empty() && **name == cmd)
        .map(|(i, _)| i as u8)
}

#[doc(hidden)]
pub fn command_for_short_id(id: u8) -> Option<&'static str> {
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

#[doc(hidden)]
pub fn command_to_12(cmd: &str) -> [u8; 12] {
    let mut out = [0u8; 12];
    let b = cmd.as_bytes();
    let n = b.len().min(12);
    out[..n].copy_from_slice(&b[..n]);
    out
}

/// An unknown v2 message type. The functional debug-log map emits Core's
/// sentence; this line is what an operator reads.
pub fn v2_invalid_message_type_log() -> &'static str {
    "p2p: v2 peer sent a message type we do not know"
}

#[doc(hidden)]
pub fn command_from_12(cmd12: &[u8; 12]) -> Result<String, NetError> {
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
        NetworkMessage::Inv(v) | NetworkMessage::GetData(v) | NetworkMessage::NotFound(v)
            if v.len() > MAX_INV_SIZE =>
        {
            return Err(NetError::MessageTooLarge(v.len()));
        }
        NetworkMessage::Headers(h) if h.len() > MAX_HEADERS_RESULTS => {
            return Err(NetError::MessageTooLarge(h.len()));
        }
        NetworkMessage::GetHeaders(gh) if gh.locator_hashes.len() > MAX_LOCATOR_SZ => {
            return Err(NetError::MessageTooLarge(gh.locator_hashes.len()));
        }
        NetworkMessage::GetBlocks(gb) if gb.locator_hashes.len() > MAX_LOCATOR_SZ => {
            return Err(NetError::MessageTooLarge(gb.locator_hashes.len()));
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
    parse_v2_contents_vec(magic, contents.to_vec())
}

/// [`parse_v2_contents`] for a buffer this reader already owns. The command
/// prefix is slid off in place; the payload `Vec` keeps that allocation.
fn parse_v2_contents_vec(magic: Magic, mut contents: Vec<u8>) -> Result<FramedMessage, NetError> {
    let (command, prefix) = v2_command(&contents)?;
    slide_off(&mut contents, prefix);
    framed_payload(magic, command, contents)
}

/// Packet plaintext still has the ignore byte. One slide drops that byte
/// and the command, so a block body is moved once.
fn parse_v2_packet(magic: Magic, mut plaintext: Vec<u8>) -> Result<FramedMessage, NetError> {
    if plaintext.is_empty() {
        return Err(NetError::Protocol("empty v2 packet plaintext"));
    }
    let (command, prefix) = v2_command(&plaintext[1..])?;
    slide_off(&mut plaintext, 1 + prefix);
    framed_payload(magic, command, plaintext)
}

fn v2_command(contents: &[u8]) -> Result<([u8; 12], usize), NetError> {
    if contents.is_empty() {
        return Err(NetError::Protocol("empty v2 message contents"));
    }
    let first = contents[0];
    if first != 0 {
        let Some(name) = command_for_short_id(first) else {
            return Err(NetError::InvalidV2Type {
                contents_len: contents.len(),
            });
        };
        return Ok((command_to_12(name), 1));
    }
    if contents.len() < 1 + 12 {
        return Err(NetError::Protocol("truncated v2 long command"));
    }
    let mut cmd12 = [0u8; 12];
    cmd12.copy_from_slice(&contents[1..13]);
    if command_from_12(&cmd12).is_err() {
        return Err(NetError::InvalidV2Type {
            contents_len: contents.len(),
        });
    }
    Ok((cmd12, 13))
}

fn framed_payload(
    magic: Magic,
    command: [u8; 12],
    payload: Vec<u8>,
) -> Result<FramedMessage, NetError> {
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

#[doc(hidden)]
pub fn map_protocol_error(e: ProtocolError) -> NetError {
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
        ProtocolError::Internal(Bip324Error::NoGarbageTerminator) => {
            rbitcoin_log::info!("{}", v2_missing_garbage_terminator_log());
            NetError::Bip324(v2_missing_garbage_terminator_log().to_string())
        }
        ProtocolError::Internal(Bip324Error::Decryption(_)) => {
            rbitcoin_log::info!("{}", v2_packet_decryption_failure_log());
            NetError::Bip324(v2_packet_decryption_failure_log().to_string())
        }
        ProtocolError::Internal(inner) => NetError::Bip324(inner.to_string()),
    }
}

/// Inbound EARLY_KEY_RESPONSE: wait until a received byte mismatches the 16-byte
/// v1 prefix before sending ellswift (`p2p_v2_misbehaving.py`).
pub async fn wait_v1_prefix_mismatch<R: AsyncRead + Unpin>(
    reader: &mut R,
    magic: [u8; 4],
) -> Result<Vec<u8>, NetError> {
    let prefix = v1_prefix(magic);
    let mut got = Vec::with_capacity(V1_PREFIX_LEN);
    let mut one = [0u8; 1];
    loop {
        let n = reader.read(&mut one).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "v2 inbound eof before v1-prefix mismatch",
            )
            .into());
        }
        got.push(one[0]);
        if got.as_slice() != &prefix[..got.len()] {
            return Ok(got);
        }
        if got.len() == V1_PREFIX_LEN {
            return Err(NetError::V1Peer);
        }
    }
}

/// BIP324 garbage cap (Core `MAX_GARBAGE_LEN`).
const MAX_GARBAGE_LEN: usize = 4095;

/// Core `GenerateRandomGarbage`. A u16 modulo 4096 has no bias.
fn handshake_garbage() -> Vec<u8> {
    let mut len = [0u8; 2];
    getrandom::fill(&mut len).expect("CSPRNG for BIP324 garbage length");
    let mut garbage = vec![0u8; usize::from(u16::from_le_bytes(len)) % (MAX_GARBAGE_LEN + 1)];
    getrandom::fill(&mut garbage).expect("CSPRNG for BIP324 garbage");
    garbage
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
    open_v2_with_wire(stream, magic, inbound, WireBytes::new()).await
}

pub async fn open_v2_with_wire(
    stream: TcpStream,
    magic: Magic,
    inbound: bool,
    wire: WireBytes,
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
    let reader = BufReader::new(wire.count_read(rh));
    let writer = wire.count_write(wh);
    // Protocol performs many small reads; BufReader is required for performance.
    let mut reader = reader;
    let prefix = if inbound {
        wait_v1_prefix_mismatch(&mut reader, magic_bytes).await?
    } else {
        Vec::new()
    };
    let reader = PrefixedRead {
        prefix,
        pos: 0,
        inner: reader,
    };
    let garbage = Some(handshake_garbage());
    let protocol = match Protocol::new(magic_bytes, role, garbage, None, reader, writer).await {
        Ok(p) => p,
        Err(e) => {
            let mapped = map_protocol_error(e);
            // After EARLY_KEY_RESPONSE mismatch, a 64-byte key that starts with
            // network magic is still v2 ellswift (p2p_v2_misbehaving.py). bip324
            // reports V1Protocol; park until peertimeout instead of dropping.
            if inbound && matches!(mapped, NetError::V1Peer) {
                return Err(NetError::Protocol("magic-prefixed ellswift"));
            }
            return Err(mapped);
        }
    };
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

/// Like [`write_v2_msg`]. A heavy payload encodes on `rbtc-scripts-*`.
/// A short header batch and an inv list of 64 or fewer stay on the caller.
pub async fn write_v2_msg_offload(
    writer: &mut V2Writer,
    payload: NetworkMessage,
) -> Result<(), NetError> {
    let contents = encode_v2_payload(payload).await?;
    write_v2_contents(writer, contents).await
}

/// Encode one v2 payload. Heavy messages hop to `rbtc-scripts-*`.
#[doc(hidden)]
pub async fn encode_v2_payload(payload: NetworkMessage) -> Result<Vec<u8>, NetError> {
    if !encode_is_cpu_heavy(&payload) {
        return encode_v2_contents(payload);
    }
    match rbitcoin_consensus::script_pool::run_cpu(move || encode_v2_contents(payload)).await {
        Some(contents) => contents,
        None => Err(NetError::Protocol("encode task join failed")),
    }
}

/// Next genuine application contents (skips decoy packets).
pub async fn read_v2_contents<R>(reader: &mut V2SessionReader<R>) -> Result<Vec<u8>, NetError>
where
    R: AsyncRead + Unpin + Send,
{
    reader.read_genuine_contents(|_| {}, |_| Ok(())).await
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
    read_v2_frame_with_progress(reader, magic, |_| {}, |_| Ok(())).await
}

/// Read the next genuine frame; `on_progress` is invoked as ciphertext body
/// bytes arrive, then again with decrypted content length.
pub async fn read_v2_frame_with_progress<R, F, D>(
    reader: &mut V2SessionReader<R>,
    magic: Magic,
    mut on_progress: F,
    on_decoy: D,
) -> Result<FramedMessage, NetError>
where
    R: AsyncRead + Unpin + Send,
    F: FnMut(usize),
    D: FnMut(usize) -> Result<(), NetError>,
{
    let plaintext = reader
        .read_genuine_plaintext(&mut on_progress, on_decoy)
        .await?;
    on_progress(plaintext.len() - 1);
    parse_v2_packet(magic, plaintext)
}
