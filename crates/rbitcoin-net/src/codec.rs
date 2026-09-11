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

/// Bitcoin Core `MAX_HEADERS_RESULTS` — max headers in a `headers` message.
pub const MAX_HEADERS_RESULTS: usize = 2_000;

/// Bitcoin Core `MAX_LOCATOR_SZ` — max block locator hashes.
pub const MAX_LOCATOR_SZ: usize = 101;

/// Whether encoding this payload is heavy enough to keep off async I/O workers.
#[inline]
pub fn encode_is_cpu_heavy(payload: &NetworkMessage) -> bool {
    match payload {
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
    /// Oversize `headers` (`n > MAX_HEADERS_RESULTS`) is [`NetError::MessageTooLarge`].
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
pub(crate) fn command_bytes_ok(cmd12: &[u8]) -> bool {
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

fn decode_cmd_payload(
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
        "merkleblock" => one(d, NetworkMessage::MerkleBlock)?,
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
        "cmpctblock" => one(d, NetworkMessage::CmpctBlock)?,
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

fn command_from_header(cmd12: &[u8]) -> CommandString {
    let end = cmd12.iter().position(|&b| b == 0).unwrap_or(12);
    let s = std::str::from_utf8(&cmd12[..end]).unwrap_or("unknown");
    CommandString::try_from(s)
        .unwrap_or_else(|_| CommandString::try_from("unknown").expect("literal command string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::serialize;
    use bitcoin::Network;

    fn signet_magic() -> Magic {
        Magic::from(Network::Signet)
    }

    #[test]
    fn frame_decode_verack_ignores_checksum() {
        let frame = FramedMessage {
            magic: signet_magic(),
            command: *b"verack\0\0\0\0\0\0",
            payload: Vec::new(),
        };
        assert!(!frame.decode_is_cpu_heavy());
        assert!(matches!(frame.decode().payload(), NetworkMessage::Verack));
    }

    #[test]
    fn block_hash_from_header_matches_full_block() {
        let magic = Magic::from(Network::Bitcoin);
        let genesis = genesis_block(Network::Bitcoin);
        let want = genesis.block_hash();
        let payload = serialize(&genesis);
        let frame = FramedMessage {
            magic,
            command: *b"block\0\0\0\0\0\0\0",
            payload,
        };
        assert!(frame.is_block());
        assert_eq!(frame.block_hash_from_header().expect("header hash"), want);
        match frame.decode().payload() {
            NetworkMessage::Block(b) => assert_eq!(b.block_hash(), want),
            _ => panic!("expected block"),
        }
    }

    #[test]
    fn command_bytes_ok_accepts_null_padded() {
        assert!(command_bytes_ok(b"version\0\0\0\0\0"));
        assert!(command_bytes_ok(b"ping\0\0\0\0\0\0\0\0"));
        // Digits: BIP155 sendaddrv2 / addrv2 (long form).
        assert!(command_bytes_ok(b"sendaddrv2\0\0"));
        assert!(command_bytes_ok(b"addrv2\0\0\0\0\0\0"));
        assert!(!command_bytes_ok(b"\xff\xfe\0\0\0\0\0\0\0\0\0\0"));
        assert!(!command_bytes_ok(b"ping\0x\0\0\0\0\0\0\0")); // non-zero after null
        assert!(!command_bytes_ok(b"\x01ping\0\0\0\0\0\0\0")); // control char
    }

    #[test]
    fn core_limits_documented() {
        assert_eq!(MAX_PROTOCOL_MESSAGE_LENGTH, 4_000_000);
        assert_eq!(MAX_INV_SIZE, 50_000);
        assert_eq!(MAX_HEADERS_RESULTS, 2_000);
        assert_eq!(MAX_LOCATOR_SZ, 101);
        // Stricter than rust-bitcoin's 5MB
        const {
            assert!(MAX_PROTOCOL_MESSAGE_LENGTH < bitcoin::p2p::message::MAX_MSG_SIZE);
        }
    }

    #[test]
    fn headers_count_over_2000_is_message_too_large() {
        use crate::error::NetError;
        use bitcoin::consensus::encode::{Encodable, VarInt};

        fn count_payload(n: u64) -> Vec<u8> {
            let mut v = Vec::new();
            VarInt(n).consensus_encode(&mut v).unwrap();
            v
        }

        let over = FramedMessage {
            magic: signet_magic(),
            command: *b"headers\0\0\0\0\0",
            payload: count_payload((MAX_HEADERS_RESULTS as u64) + 1),
        };
        match over.try_decode() {
            Err(NetError::MessageTooLarge(n)) => assert_eq!(n, MAX_HEADERS_RESULTS + 1),
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }

        let at_cap = FramedMessage {
            magic: signet_magic(),
            command: *b"headers\0\0\0\0\0",
            payload: count_payload(MAX_HEADERS_RESULTS as u64),
        };
        assert!(
            !matches!(at_cap.try_decode(), Err(NetError::MessageTooLarge(_))),
            "n=2000 must not be MessageTooLarge"
        );
    }

    #[test]
    fn frame_helpers_ping_headers_notfound_and_encode_cost() {
        let magic = signet_magic();
        let nonce: u64 = 0x1122_3344_5566_7788;
        let payload = nonce.to_le_bytes().to_vec();
        let ping = FramedMessage {
            magic,
            command: *b"ping\0\0\0\0\0\0\0\0",
            payload: payload.clone(),
        };
        assert!(ping.is_ping());
        assert_eq!(ping.ping_nonce(), Some(nonce));
        assert!(!ping.decode_is_cpu_heavy());

        let short = FramedMessage {
            magic,
            command: *b"ping\0\0\0\0\0\0\0\0",
            payload: vec![1, 2, 3],
        };
        assert!(short.ping_nonce().is_none());

        let headers = FramedMessage {
            magic,
            command: *b"headers\0\0\0\0\0",
            payload: vec![],
        };
        assert!(headers.is_headers());
        assert!(headers.decode_is_cpu_heavy());
        assert!(headers.block_hash_from_header().is_none());

        let nf = FramedMessage {
            magic,
            command: *b"notfound\0\0\0\0",
            payload: vec![],
        };
        assert!(nf.is_notfound());
        assert!(nf.decode_is_cpu_heavy());

        // Corrupt payload → Unknown path (not a panic).
        let bad = FramedMessage {
            magic,
            command: *b"block\0\0\0\0\0\0\0",
            payload: vec![0u8; 10],
        };
        match bad.decode().payload() {
            NetworkMessage::Unknown { command, .. } => {
                assert_eq!(command.to_string(), "block");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }

        assert!(!encode_is_cpu_heavy(&NetworkMessage::Verack));
        assert!(encode_is_cpu_heavy(&NetworkMessage::Headers(vec![])));
        // Small inv is cheap; large is heavy.
        use bitcoin::hashes::Hash as _;
        use bitcoin::p2p::message_blockdata::Inventory;
        let small = NetworkMessage::Inv(vec![Inventory::Block(
            bitcoin::BlockHash::from_byte_array([0; 32]),
        )]);
        assert!(!encode_is_cpu_heavy(&small));
        let large = NetworkMessage::Inv(vec![
            Inventory::Block(bitcoin::BlockHash::from_byte_array(
                [0; 32]
            ));
            65
        ]);
        assert!(encode_is_cpu_heavy(&large));
    }
}
