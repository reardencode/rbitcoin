//! Bitcoin P2P message framing helpers (limits + [`FramedMessage`]).
//!
//! **Transport:** production wire is **BIP324 v2 only** — see [`crate::v2`].
//! This module holds Core-aligned size limits, CPU-heavy encode/decode hints,
//! and the framed-message type used after decrypt.
//!
//! **I/O vs CPU split:** socket tasks obtain a [`FramedMessage`] via
//! [`crate::v2::read_v2_frame`] and run [`FramedMessage::decode`] on a
//! blocking worker. Never deserialize multi‑MB `block` payloads on the async
//! I/O worker.

use bitcoin::consensus::encode::Decodable;
use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;

/// Bitcoin Core `MAX_PROTOCOL_MESSAGE_LENGTH` — max P2P payload bytes.
///
/// Note: rust-bitcoin's `MAX_MSG_SIZE` is 5_000_000; Core enforces 4_000_000.
/// We use Core's limit so we never accept (or send) messages Core would reject.
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 4_000_000;

/// Bitcoin Core `MAX_INV_SZ` — max inventory items in inv/getdata/notfound.
pub const MAX_INV_SIZE: usize = 50_000;

/// Tx announcements per `inv`. Separate from [`MAX_INV_SIZE`]: one message
/// stays at a thousand even though the wire cap is fifty thousand.
pub const TX_INV_BATCH: usize = 1_000;

/// Bitcoin Core `MAX_HEADERS_RESULTS` — max headers in a `headers` message.
pub const MAX_HEADERS_RESULTS: usize = 2_000;

/// Bitcoin Core `MAX_LOCATOR_SZ` — max block locator hashes.
pub const MAX_LOCATOR_SZ: usize = 101;

/// Header batches at or under this stay on the writer. Not a configuration knob.
const INLINE_HEADER_BATCH: usize = 8;

/// Whether encoding this payload is heavy enough to keep off async I/O workers.
#[inline]
pub fn encode_is_cpu_heavy(payload: &NetworkMessage) -> bool {
    match payload {
        NetworkMessage::Headers(h) if h.len() <= INLINE_HEADER_BATCH => false,
        NetworkMessage::Block(_) | NetworkMessage::Headers(_) => true,
        NetworkMessage::Inv(v) | NetworkMessage::GetData(v) | NetworkMessage::NotFound(v) => {
            v.len() > 64
        }
        _ => false,
    }
}

/// One fully framed P2P message: header fields + raw payload bytes.
///
/// Produced on the socket task; [`FramedMessage::decode`] is CPU and must run
/// off the async I/O worker (blocking pool / rayon / dedicated thread).
#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub magic: Magic,
    /// 12-byte null-padded command (wire form).
    pub command: [u8; 12],
    pub payload: Vec<u8>,
}

impl FramedMessage {
    #[inline]
    pub fn is_block(&self) -> bool {
        self.command == *b"block\0\0\0\0\0\0\0"
    }

    #[inline]
    pub fn is_headers(&self) -> bool {
        self.command == *b"headers\0\0\0\0\0"
    }

    #[inline]
    /// Framed application payload length (for per-peer byte rate accounting).
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_ping(&self) -> bool {
        self.command == *b"ping\0\0\0\0\0\0\0\0"
    }

    pub fn is_pong(&self) -> bool {
        self.command == *b"pong\0\0\0\0\0\0\0\0"
    }

    #[inline]
    pub fn is_notfound(&self) -> bool {
        self.command == *b"notfound\0\0\0\0"
    }

    #[inline]
    #[doc(hidden)]
    pub fn is_inv_like(&self) -> bool {
        self.command == *b"inv\0\0\0\0\0\0\0\0\0"
            || self.command == *b"getdata\0\0\0\0\0"
            || self.is_notfound()
    }

    /// Cheap ping nonce extract (8-byte LE payload). No full message deserialize.
    pub fn ping_nonce(&self) -> Option<u64> {
        if !self.is_ping() || self.payload.len() < 8 {
            return None;
        }
        Some(u64::from_le_bytes(self.payload[..8].try_into().ok()?))
    }

    /// Block hash from the wire header (first 80 payload bytes) — no full deserialize.
    ///
    /// Used so IBD can free getdata in-flight as soon as the TCP frame is complete,
    /// while `block` payload decode still runs on the blocking pool. Waiting for
    /// full deserialize to free slots made healthy peers look stalled (socket idle
    /// with `in_flight` still full).
    pub fn block_hash_from_header(&self) -> Option<bitcoin::BlockHash> {
        if !self.is_block() || self.payload.len() < 80 {
            return None;
        }
        use bitcoin::hashes::{sha256d, Hash as _};
        let header = &self.payload[..80];
        let dig = sha256d::Hash::hash(header);
        Some(bitcoin::BlockHash::from_byte_array(dig.to_byte_array()))
    }

    /// Extra bytes / unknown command → [`NetworkMessage::Unknown`].
    /// Oversize `headers` (`n > MAX_HEADERS_RESULTS`), oversize inv-like
    /// messages, and a `tx` / `block` / `cmpctblock` / `blocktxn` whose
    /// compact-size count cannot fit in the remaining bytes are
    /// [`NetError::MessageTooLarge`] before `consensus_decode` allocates.
    pub fn try_decode(self) -> Result<RawNetworkMessage, crate::error::NetError> {
        if self.is_headers() {
            let mut sl = self.payload.as_slice();
            if let Ok(n) = bitcoin::consensus::encode::VarInt::consensus_decode(&mut sl) {
                let n = n.0 as usize;
                if n > MAX_HEADERS_RESULTS {
                    return Err(crate::error::NetError::MessageTooLarge(n));
                }
            }
        }
        if self.is_inv_like() {
            let mut sl = self.payload.as_slice();
            if let Ok(n) = bitcoin::consensus::encode::VarInt::consensus_decode(&mut sl) {
                let n = n.0 as usize;
                if n > MAX_INV_SIZE {
                    return Err(crate::error::NetError::MessageTooLarge(n));
                }
            }
        }
        if let Some(n) = tx_family_too_large(&self.command, &self.payload) {
            return Err(crate::error::NetError::MessageTooLarge(n));
        }
        Ok(self.decode())
    }

    /// Deserialize the application payload (no v1 header, no checksum).
    ///
    /// Extra bytes / unknown command → [`NetworkMessage::Unknown`].
    pub fn decode(self) -> RawNetworkMessage {
        let cmd = command_from_header(&self.command);
        let mut sl = self.payload.as_slice();
        match decode_cmd_payload(cmd.as_ref(), &mut sl) {
            Ok(Some(msg)) if sl.is_empty() => RawNetworkMessage::new(self.magic, msg),
            _ => RawNetworkMessage::new(
                self.magic,
                NetworkMessage::Unknown {
                    command: cmd,
                    payload: self.payload,
                },
            ),
        }
    }

    /// Commands whose decode cost should never run on an async I/O worker.
    #[inline]
    pub fn decode_is_cpu_heavy(&self) -> bool {
        self.is_block() || self.is_headers() || self.is_notfound()
    }
}

/// Core `CMessageHeader::IsCommandValid`: printable ASCII (0x20–0x7E), null-padded.
///
/// Digits are required — long-form commands include `sendaddrv2` (and short-id
/// names like `addrv2` when encoded long). Restricting to a–z rejected those
/// and killed post-handshake IBD peers that send `sendaddrv2`.
pub fn command_bytes_ok(cmd12: &[u8]) -> bool {
    if cmd12.len() != 12 {
        return false;
    }
    let mut seen_null = false;
    let mut any = false;
    for &b in cmd12 {
        if b == 0 {
            seen_null = true;
            continue;
        }
        if seen_null {
            return false;
        }
        if !b.is_ascii_graphic() && b != b' ' {
            return false;
        }
        any = true;
    }
    any
}

/// Outpoint, empty script compact-size, and sequence.
#[doc(hidden)]
pub const MIN_INPUT_BYTES: u64 = 41;
/// Value plus an empty script compact-size.
#[doc(hidden)]
pub const MIN_OUTPUT_BYTES: u64 = 9;
/// Marker, flag, empty input list, empty output list, and locktime.
#[doc(hidden)]
pub const MIN_TX_BYTES: u64 = 12;

#[doc(hidden)]
pub enum Bound {
    Fits,
    /// Compact-size count cannot fit in the bytes still unread.
    TooLarge(usize),
    /// Truncated or non-minimal. `consensus_decode` decides.
    Undecided,
}

#[doc(hidden)]
pub fn too_large_n(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

#[doc(hidden)]
pub fn exceeds(count: u64, min_each: u64, remaining: usize) -> bool {
    count.saturating_mul(min_each) > u64::try_from(remaining).unwrap_or(u64::MAX)
}

#[doc(hidden)]
pub fn skip(data: &mut &[u8], n: usize) -> bool {
    if data.len() < n {
        return false;
    }
    *data = &data[n..];
    true
}

#[doc(hidden)]
pub fn read_compact_size(data: &mut &[u8]) -> Option<u64> {
    let mut cur = *data;
    match bitcoin::consensus::encode::VarInt::consensus_decode(&mut cur) {
        Ok(n) => {
            *data = cur;
            Some(n.0)
        }
        Err(_) => None,
    }
}

#[doc(hidden)]
pub fn take_len_bytes(data: &mut &[u8]) -> Bound {
    let Some(n) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    if n > u64::try_from(data.len()).unwrap_or(u64::MAX) {
        return Bound::TooLarge(too_large_n(n));
    }
    let Some(n) = usize::try_from(n).ok() else {
        return Bound::TooLarge(usize::MAX);
    };
    if skip(data, n) {
        Bound::Fits
    } else {
        Bound::Undecided
    }
}

#[doc(hidden)]
pub fn walk_input(data: &mut &[u8]) -> Bound {
    if !skip(data, 36) {
        return Bound::Undecided;
    }
    match take_len_bytes(data) {
        Bound::Fits => {}
        other => return other,
    }
    if skip(data, 4) {
        Bound::Fits
    } else {
        Bound::Undecided
    }
}

#[doc(hidden)]
pub fn walk_output(data: &mut &[u8]) -> Bound {
    if !skip(data, 8) {
        return Bound::Undecided;
    }
    take_len_bytes(data)
}

#[doc(hidden)]
pub fn walk_counted(
    data: &mut &[u8],
    count: u64,
    min_each: u64,
    one: fn(&mut &[u8]) -> Bound,
) -> Bound {
    if exceeds(count, min_each, data.len()) {
        return Bound::TooLarge(too_large_n(count));
    }
    let Some(n) = usize::try_from(count).ok() else {
        return Bound::TooLarge(usize::MAX);
    };
    for _ in 0..n {
        match one(data) {
            Bound::Fits => {}
            other => return other,
        }
    }
    Bound::Fits
}

/// Witness stack. Each element is at least one byte, so a count past the
/// remaining bytes is rejected before `Witness::consensus_decode` allocates
/// `count * 4 + 128`.
#[doc(hidden)]
pub fn walk_witness(data: &mut &[u8]) -> Bound {
    let Some(count) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    if count > u64::try_from(data.len()).unwrap_or(u64::MAX) {
        return Bound::TooLarge(too_large_n(count));
    }
    let Some(n) = usize::try_from(count).ok() else {
        return Bound::TooLarge(usize::MAX);
    };
    for _ in 0..n {
        match take_len_bytes(data) {
            Bound::Fits => {}
            other => return other,
        }
    }
    Bound::Fits
}

#[doc(hidden)]
pub fn walk_tx(data: &mut &[u8]) -> Bound {
    if !skip(data, 4) {
        return Bound::Undecided;
    }
    let Some(marker_or_vin) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    let (vin, segwit) = if marker_or_vin == 0 {
        let Some((flag, rest)) = data.split_first() else {
            return Bound::Undecided;
        };
        *data = rest;
        if *flag != 1 {
            return Bound::Undecided;
        }
        let Some(vin) = read_compact_size(data) else {
            return Bound::Undecided;
        };
        (vin, true)
    } else {
        (marker_or_vin, false)
    };
    match walk_counted(data, vin, MIN_INPUT_BYTES, walk_input) {
        Bound::Fits => {}
        other => return other,
    }
    let Some(vout) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    match walk_counted(data, vout, MIN_OUTPUT_BYTES, walk_output) {
        Bound::Fits => {}
        other => return other,
    }
    if segwit {
        let Some(n) = usize::try_from(vin).ok() else {
            return Bound::TooLarge(usize::MAX);
        };
        for _ in 0..n {
            match walk_witness(data) {
                Bound::Fits => {}
                other => return other,
            }
        }
    }
    if skip(data, 4) {
        Bound::Fits
    } else {
        Bound::Undecided
    }
}

#[doc(hidden)]
pub fn walk_tx_list(data: &mut &[u8], count: u64) -> Bound {
    if exceeds(count, MIN_TX_BYTES, data.len()) {
        return Bound::TooLarge(too_large_n(count));
    }
    let Some(n) = usize::try_from(count).ok() else {
        return Bound::TooLarge(usize::MAX);
    };
    for _ in 0..n {
        match walk_tx(data) {
            Bound::Fits => {}
            other => return other,
        }
    }
    Bound::Fits
}

#[doc(hidden)]
pub fn walk_cmpctblock(data: &mut &[u8]) -> Bound {
    if !skip(data, 88) {
        return Bound::Undecided;
    }
    let Some(shorts) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    if exceeds(shorts, 6, data.len()) {
        return Bound::TooLarge(too_large_n(shorts));
    }
    let Some(nbytes) = usize::try_from(shorts).ok().and_then(|n| n.checked_mul(6)) else {
        return Bound::TooLarge(usize::MAX);
    };
    if !skip(data, nbytes) {
        return Bound::Undecided;
    }
    let Some(prefills) = read_compact_size(data) else {
        return Bound::Undecided;
    };
    if exceeds(prefills, 1 + MIN_TX_BYTES, data.len()) {
        return Bound::TooLarge(too_large_n(prefills));
    }
    let Some(n) = usize::try_from(prefills).ok() else {
        return Bound::TooLarge(usize::MAX);
    };
    for _ in 0..n {
        if read_compact_size(data).is_none() {
            return Bound::Undecided;
        }
        match walk_tx(data) {
            Bound::Fits => {}
            other => return other,
        }
    }
    Bound::Fits
}

/// `Some(count)` when a transaction-carrying payload declares a compact-size
/// count the remaining bytes cannot hold. `None` lets `decode` run.
#[doc(hidden)]
pub fn tx_family_too_large(command: &[u8; 12], payload: &[u8]) -> Option<usize> {
    let mut data = payload;
    let bound = if command == b"tx\0\0\0\0\0\0\0\0\0\0" {
        walk_tx(&mut data)
    } else if command == b"blocktxn\0\0\0\0" {
        if !skip(&mut data, 32) {
            return None;
        }
        let n = read_compact_size(&mut data)?;
        walk_tx_list(&mut data, n)
    } else if command == b"block\0\0\0\0\0\0\0" {
        if !skip(&mut data, 80) {
            return None;
        }
        let n = read_compact_size(&mut data)?;
        walk_tx_list(&mut data, n)
    } else if command == b"cmpctblock\0\0" {
        walk_cmpctblock(&mut data)
    } else {
        return None;
    };
    match bound {
        Bound::TooLarge(n) => Some(n),
        Bound::Fits | Bound::Undecided => None,
    }
}

/// BIP152 `HeaderAndShortIds` as Core reads it. A prefilled tx follows
/// [`decode_core_prefilled_tx`], and like Core's
/// deserializer a tx count past 16 bits fails the decode, which the session
/// drops with no score.
fn decode_header_and_short_ids(
    d: &mut &[u8],
) -> Result<bitcoin::bip152::HeaderAndShortIds, bitcoin::consensus::encode::Error> {
    use bitcoin::bip152::{HeaderAndShortIds, PrefilledTransaction, ShortId};
    let header = bitcoin::block::Header::consensus_decode(d)?;
    let nonce = u64::consensus_decode(d)?;
    let short_ids = Vec::<ShortId>::consensus_decode(d)?;
    let n = bitcoin::consensus::encode::VarInt::consensus_decode(d)?.0;
    let mut prefilled_txs = Vec::new();
    for _ in 0..n {
        let idx = bitcoin::consensus::encode::VarInt::consensus_decode(d)?.0;
        let idx = u16::try_from(idx).map_err(|_| {
            bitcoin::consensus::encode::Error::ParseFailed(
                "BIP152 prefilled tx index out of bounds",
            )
        })?;
        let tx = decode_core_prefilled_tx(d)?;
        prefilled_txs.push(PrefilledTransaction { idx, tx });
    }
    if short_ids.len().saturating_add(prefilled_txs.len()) > usize::from(u16::MAX) {
        return Err(bitcoin::consensus::encode::Error::ParseFailed(
            "BIP152 indexes overflowed 16 bits",
        ));
    }
    Ok(HeaderAndShortIds {
        header,
        nonce,
        short_ids,
        prefilled_txs,
    })
}

/// A prefilled tx as Core's `UnserializeTransaction` reads it. Only an empty
/// vin differs from rust-bitcoin: flags 0 is [`take_core_null_tx`], and flag 1
/// followed by a second empty vin carries no witness, which Core refuses as a
/// superfluous witness record and rust-bitcoin accepts.
fn decode_core_prefilled_tx(
    d: &mut &[u8],
) -> Result<bitcoin::Transaction, bitcoin::consensus::encode::Error> {
    if d.get(4..7) == Some(&[0u8, 1, 0][..]) {
        return Err(bitcoin::consensus::encode::Error::ParseFailed(
            "superfluous witness record",
        ));
    }
    match take_core_null_tx(d) {
        Some(tx) => Ok(tx),
        None => bitcoin::Transaction::consensus_decode(d),
    }
}

/// Core `UnserializeTransaction` reads an empty vin, then flags 0, and leaves
/// vout empty: `CTransaction::IsNull`. rust-bitcoin rejects those bytes as
/// segwit flag 0, so a compact block carrying one would decode as `Unknown`
/// instead of reaching the `InitData` reject.
fn take_core_null_tx(d: &mut &[u8]) -> Option<bitcoin::Transaction> {
    let (b, rest) = d.split_first_chunk::<10>()?;
    if b[4] != 0 || b[5] != 0 {
        return None;
    }
    let version = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let lock_time = u32::from_le_bytes([b[6], b[7], b[8], b[9]]);
    *d = rest;
    Some(bitcoin::Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
        input: Vec::new(),
        output: Vec::new(),
    })
}

#[doc(hidden)]
pub fn decode_cmd_payload(
    cmd: &str,
    d: &mut &[u8],
) -> Result<Option<NetworkMessage>, bitcoin::consensus::encode::Error> {
    fn one<T: Decodable>(
        d: &mut &[u8],
        f: fn(T) -> NetworkMessage,
    ) -> Result<NetworkMessage, bitcoin::consensus::encode::Error> {
        Ok(f(Decodable::consensus_decode(d)?))
    }
    Ok(Some(match cmd {
        "verack" => NetworkMessage::Verack,
        "sendheaders" => NetworkMessage::SendHeaders,
        "getaddr" => NetworkMessage::GetAddr,
        "mempool" => NetworkMessage::MemPool,
        "filterclear" => NetworkMessage::FilterClear,
        "wtxidrelay" => NetworkMessage::WtxidRelay,
        "sendaddrv2" => NetworkMessage::SendAddrV2,
        "version" => one(d, NetworkMessage::Version)?,
        "addr" => one(d, NetworkMessage::Addr)?,
        "inv" => one(d, NetworkMessage::Inv)?,
        "getdata" => one(d, NetworkMessage::GetData)?,
        "notfound" => one(d, NetworkMessage::NotFound)?,
        "getblocks" => one(d, NetworkMessage::GetBlocks)?,
        "getheaders" => one(d, NetworkMessage::GetHeaders)?,
        "block" => one(d, NetworkMessage::Block)?,
        "tx" => one(d, NetworkMessage::Tx)?,
        "ping" => one(d, NetworkMessage::Ping)?,
        "pong" => one(d, NetworkMessage::Pong)?,
        // Bloom is off. `PartialMerkleTree` allocates `n * 8` bools from the
        // flags compact-size before a short payload can fail the read.
        "merkleblock" => return Ok(None),
        "filterload" => one(d, NetworkMessage::FilterLoad)?,
        "filteradd" => one(d, NetworkMessage::FilterAdd)?,
        "getcfilters" => one(d, NetworkMessage::GetCFilters)?,
        "cfilter" => one(d, NetworkMessage::CFilter)?,
        "getcfheaders" => one(d, NetworkMessage::GetCFHeaders)?,
        "cfheaders" => one(d, NetworkMessage::CFHeaders)?,
        "getcfcheckpt" => one(d, NetworkMessage::GetCFCheckpt)?,
        "cfcheckpt" => one(d, NetworkMessage::CFCheckpt)?,
        "reject" => one(d, NetworkMessage::Reject)?,
        "alert" => one(d, NetworkMessage::Alert)?,
        "sendcmpct" => one(d, NetworkMessage::SendCmpct)?,
        "cmpctblock" => {
            NetworkMessage::CmpctBlock(bitcoin::p2p::message_compact_blocks::CmpctBlock {
                compact_block: decode_header_and_short_ids(d)?,
            })
        }
        "getblocktxn" => one(d, NetworkMessage::GetBlockTxn)?,
        "blocktxn" => one(d, NetworkMessage::BlockTxn)?,
        "addrv2" => one(d, NetworkMessage::AddrV2)?,
        "feefilter" => {
            let fee: i64 = Decodable::consensus_decode(d)?;
            let upper: i64 = bitcoin::Amount::MAX_MONEY
                .to_sat()
                .try_into()
                .expect("Amount::MAX_MONEY < i64::MAX");
            if fee < 0 || fee > upper {
                return Err(bitcoin::consensus::encode::Error::ParseFailed(
                    "feefilter value out of range",
                ));
            }
            NetworkMessage::FeeFilter(fee)
        }
        "headers" => {
            let n = bitcoin::consensus::encode::VarInt::consensus_decode(d)?.0 as usize;
            if n > MAX_HEADERS_RESULTS {
                return Err(bitcoin::consensus::encode::Error::ParseFailed(
                    "too many headers",
                ));
            }
            let mut hs = Vec::with_capacity(n);
            for _ in 0..n {
                hs.push(bitcoin::block::Header::consensus_decode(d)?);
                let txn: u8 = Decodable::consensus_decode(d)?;
                if txn != 0 {
                    return Err(bitcoin::consensus::encode::Error::ParseFailed(
                        "Headers message should not contain transactions",
                    ));
                }
            }
            NetworkMessage::Headers(hs)
        }
        _ => return Ok(None),
    }))
}

#[doc(hidden)]
pub fn command_from_header(cmd12: &[u8]) -> CommandString {
    let end = cmd12.iter().position(|&b| b == 0).unwrap_or(12);
    let s = std::str::from_utf8(&cmd12[..end]).unwrap_or("unknown");
    CommandString::try_from(s)
        .unwrap_or_else(|_| CommandString::try_from("unknown").expect("literal command string"))
}
