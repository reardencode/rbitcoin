//! Noise_NX transport over one TCP stream: handshake, then encrypted SV2 frames.

use crate::messages::{
    MESSAGE_TYPE_PROPOSE_TEMPLATE, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
};
use binary_sv2::{GetSize, Serialize};
use codec_sv2::{
    Decoded, Decrypted, Handshake, MessageFrame, NoiseDecoder, NoiseEncoder, TransportDecryptState,
    TransportEncryptState, ENCRYPTED_SV2_FRAME_HEADER_SIZE, SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
};
use noise_sv2::{Initiator, Responder, AEAD_MAC_LEN};
use rbitcoin_consensus::MAX_BLOCK_WEIGHT;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// One decrypted SV2 frame: header message type and owned payload.
pub struct Frame {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

/// Largest client→TP payload for every message but the job-validation
/// pair: `SubmitSolution`, 20 fixed bytes plus a `B064K` coinbase (2-byte
/// length, ≤ 65535 bytes). The 24-bit frame length would otherwise let a
/// client make the session buffer ~16 MB per frame.
const MAX_CLIENT_PAYLOAD: usize = 20 + 2 + u16::MAX as usize;

/// `SEQ0_64K` element count.
const SEQ: usize = u16::MAX as usize;

/// Largest `ProposeTemplate` payload: 8 fixed bytes, three `B064K` fields
/// (coinbase prefix, suffix, excess data) and a full `SEQ0_64K[U256]` wtxid
/// list (~2.3 MB).
pub(crate) const MAX_PROPOSE_TEMPLATE_PAYLOAD: usize = 4 + 4 + 3 * (2 + SEQ) + (2 + SEQ * 32);

/// Largest `ProvideMissingTransactions.Success` payload: 4 fixed bytes and a
/// `SEQ0_64K[B016M]` transaction list whose txs together fit a block (weight
/// is never below serialized size) with a 3-byte length each.
///
/// RAM trade (CONTRIBUTING 9): a session buffers one in-flight client frame
/// of at most this size (~4.2 MB), so at `MAX_SESSIONS` client frames hold
/// ≤ ~34 MB on top of template retention (lib.rs).
pub(crate) const MAX_PROVIDE_MISSING_TRANSACTIONS_PAYLOAD: usize =
    4 + 2 + SEQ * 3 + MAX_BLOCK_WEIGHT as usize;

/// Payload cap by client message type.
const fn client_payload_cap(msg_type: u8) -> usize {
    match msg_type {
        MESSAGE_TYPE_PROPOSE_TEMPLATE => MAX_PROPOSE_TEMPLATE_PAYLOAD,
        MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS => {
            MAX_PROVIDE_MISSING_TRANSACTIONS_PAYLOAD
        }
        _ => MAX_CLIENT_PAYLOAD,
    }
}

/// Encrypted bytes on the wire for a frame carrying `payload` bytes.
const fn encrypted_frame_len(payload: usize) -> usize {
    ENCRYPTED_SV2_FRAME_HEADER_SIZE
        + payload
        + payload.div_ceil(SV2_FRAME_PLAINTEXT_CHUNK_SIZE) * AEAD_MAC_LEN
}

fn no_cap(_: u8) -> usize {
    usize::MAX
}

/// Size bounds on the frames one direction carries.
#[derive(Clone, Copy)]
struct FrameCap {
    /// Encrypted bytes one frame may take, counted while it is read.
    max_frame: usize,
    /// Payload cap by message type, applied once the frame is whole.
    payload: fn(u8) -> usize,
}

impl FrameCap {
    /// Client→TP: the largest client message while reading, then
    /// [`client_payload_cap`] for the type.
    const CLIENT: Self = Self {
        max_frame: encrypted_frame_len(MAX_PROVIDE_MISSING_TRANSACTIONS_PAYLOAD),
        payload: client_payload_cap,
    };
    /// TP→client: the 24-bit frame length only.
    const UNBOUNDED: Self = Self {
        max_frame: usize::MAX,
        payload: no_cap,
    };
}

pub(crate) struct NoiseConn {
    reader: NoiseReader,
    writer: NoiseWriter,
}

/// Receive half. `recv` is not cancel-safe: a dropped call loses a partly
/// read frame, so a session that selects over input reads from a task.
pub(crate) struct NoiseReader {
    stream: OwnedReadHalf,
    decoder: NoiseDecoder,
    // `next_transport_frame` consumes the state; a failed round leaves `None`
    // and the connection must close (codec_sv2 nonce rule).
    rx: Option<TransportDecryptState>,
    cap: FrameCap,
    /// Encrypted bytes read so far for the frame being decoded.
    frame_read: usize,
}

pub(crate) struct NoiseWriter {
    stream: OwnedWriteHalf,
    encoder: NoiseEncoder,
    tx: TransportEncryptState,
    /// Longest one socket write may make no progress.
    write_timeout: Duration,
}

fn codec_err(e: codec_sv2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("sv2 codec: {e:?}"))
}

impl NoiseConn {
    pub(crate) async fn accept(
        mut stream: TcpStream,
        responder: Box<Responder>,
        write_timeout: Duration,
    ) -> io::Result<Self> {
        let mut decoder = NoiseDecoder::new();
        let mut encoder = NoiseEncoder::new();
        let first = loop {
            match decoder
                .next_handshake_frame::<Responder>()
                .map_err(codec_err)?
            {
                Decoded::Frame(m) => break m,
                Decoded::Incomplete(_) => stream.read_exact(decoder.writable()).await?,
            };
        };
        let re_pub = first
            .payload()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sv2: handshake size"))?;
        let (reply, transport) = Handshake::responder(responder)
            .step_1(re_pub)
            .map_err(codec_err)?;
        stream
            .write_all(encoder.encode_handshake(reply).as_ref())
            .await?;
        let (tx, rx) = transport.split();
        Ok(Self::new(
            stream,
            encoder,
            decoder,
            tx,
            rx,
            write_timeout,
            FrameCap::CLIENT,
        ))
    }

    pub(crate) async fn connect(
        mut stream: TcpStream,
        initiator: Box<Initiator>,
        write_timeout: Duration,
    ) -> io::Result<Self> {
        let mut decoder = NoiseDecoder::new();
        let mut encoder = NoiseEncoder::new();
        let (first, sent) = Handshake::initiator(initiator)
            .step_0()
            .map_err(codec_err)?;
        stream
            .write_all(encoder.encode_handshake(first).as_ref())
            .await?;
        let reply = loop {
            match decoder
                .next_handshake_frame::<codec_sv2::InitiatorSent>()
                .map_err(codec_err)?
            {
                Decoded::Frame(m) => break m,
                Decoded::Incomplete(_) => stream.read_exact(decoder.writable()).await?,
            };
        };
        let reply = reply
            .payload()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sv2: handshake size"))?;
        let (tx, rx) = sent.step_2(reply).map_err(codec_err)?.split();
        Ok(Self::new(
            stream,
            encoder,
            decoder,
            tx,
            rx,
            write_timeout,
            FrameCap::UNBOUNDED,
        ))
    }

    fn new(
        stream: TcpStream,
        encoder: NoiseEncoder,
        decoder: NoiseDecoder,
        tx: TransportEncryptState,
        rx: TransportDecryptState,
        write_timeout: Duration,
        cap: FrameCap,
    ) -> Self {
        let (read, write) = stream.into_split();
        Self {
            reader: NoiseReader {
                stream: read,
                decoder,
                rx: Some(rx),
                cap,
                frame_read: 0,
            },
            writer: NoiseWriter {
                stream: write,
                encoder,
                tx,
                write_timeout,
            },
        }
    }

    pub(crate) fn into_split(self) -> (NoiseReader, NoiseWriter) {
        (self.reader, self.writer)
    }

    pub(crate) async fn send<T: Serialize + GetSize>(
        &mut self,
        msg_type: u8,
        msg: T,
    ) -> io::Result<()> {
        self.writer.send(msg_type, msg).await
    }

    pub(crate) async fn recv(&mut self) -> io::Result<Frame> {
        self.reader.recv().await
    }
}

impl NoiseWriter {
    pub(crate) async fn send<T: Serialize + GetSize>(
        &mut self,
        msg_type: u8,
        msg: T,
    ) -> io::Result<()> {
        let frame = MessageFrame::from_message(msg, msg_type, 0, false).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("sv2 frame: {e:?}"))
        })?;
        let bytes = self
            .encoder
            .encode_transport(frame, &mut self.tx)
            .map_err(codec_err)?;
        // Deadline per write call, not per frame: a slow reader still gets
        // a multi-MB RequestTransactionData.Success, one that stops does not
        // hold the session.
        let mut buf: &[u8] = bytes.as_ref();
        while !buf.is_empty() {
            let n = tokio::time::timeout(self.write_timeout, self.stream.write(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sv2: write stalled"))??;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}

impl NoiseReader {
    pub(crate) async fn recv(&mut self) -> io::Result<Frame> {
        loop {
            let state = self
                .rx
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sv2: decrypt failed"))?;
            match self
                .decoder
                .next_transport_frame(state)
                .map_err(codec_err)?
            {
                Decrypted::Frame(mut frame, state) => {
                    self.rx = Some(state);
                    self.frame_read = 0;
                    let msg_type = frame.header().msg_type();
                    let payload = frame.payload();
                    // codec_sv2 decrypts the header into a private buffer, so
                    // the type is only visible with the whole frame: the
                    // running count bounds every frame at the largest client
                    // message, and the per-type cap applies here.
                    if payload.len() > (self.cap.payload)(msg_type) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sv2: frame over the size cap",
                        ));
                    }
                    return Ok(Frame {
                        msg_type,
                        payload: payload.to_vec(),
                    });
                }
                Decrypted::Incomplete(n, state) => {
                    self.rx = Some(state);
                    // codec_sv2 keeps the decrypted header private and asks
                    // for at most one chunk per read, so the declared length
                    // is not visible. Reads never cross a frame boundary, so
                    // the running count closes an oversized frame before the
                    // chunk that would exceed the cap is read.
                    self.frame_read += n;
                    if self.frame_read > self.cap.max_frame {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sv2: frame over the size cap",
                        ));
                    }
                    self.stream.read_exact(self.decoder.writable()).await?;
                }
            }
        }
    }
}
