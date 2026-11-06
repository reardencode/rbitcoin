use std::fmt;
use std::io;

#[derive(Debug)]
pub enum NetError {
    Io(io::Error),
    Encode(String),
    Protocol(&'static str),
    /// Peer does not speak BIP324 v2 (or closed during v2 handshake).
    /// Disconnect and do not fall back to v1, except on a `v1@` listener
    /// ([`crate::v1::open_inbound_with_wire`]).
    V1Peer,
    /// BIP324 crypto / session error detail.
    Bip324(String),
    Timeout,
    Disconnected,
    MessageTooLarge(usize),
    /// Unknown v2 short/long type: log + `*other*` bytes, stay connected (Core).
    InvalidV2Type {
        contents_len: usize,
    },
    BadMagic,
    Consensus(String),
    /// A consensus rule failure. Callers match this variant. [`Self::Consensus`]
    /// stays the string bag for faults that are not a rule (`header parent
    /// unknown`, `Block not found`, `zero target`).
    Rules(rbitcoin_consensus::ConsensusError),
    /// Local store / engine fault during connect (IO, invariant, io_uring).
    /// Not a verdict on the block: never cached as invalid.
    Store(String),
    /// IBD / tip-accept cooperative abort. Display matches confirm-engine logs.
    Cancelled,
    /// Compact/body does not match the header (`BLOCK_MUTATED`). Do not cache as failed.
    Mutated(String),
    /// Header prev is not the expected tip / batch parent.
    BadPrev,
    /// Height occupied by a different block — hold and try `accept_branch`.
    SideBlock,
    /// Parent header is not on our chain.
    UnknownParent,
    /// `accept_branch` connect failed at this hash (only this hash is invalid).
    ConnectFailed {
        hash: [u8; 32],
        msg: String,
        /// Set when the failure is a [`rbitcoin_consensus::ConsensusError`].
        /// Classification uses this. `msg` is the BIP22 text for Display.
        rules: Option<rbitcoin_consensus::ConsensusError>,
    },
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io: {e}"),
            NetError::Encode(s) => write!(f, "encode: {s}"),
            NetError::Protocol(s) => write!(f, "protocol: {s}"),
            NetError::V1Peer => f.write_str("peer does not speak BIP324 v2"),
            NetError::Bip324(s) => write!(f, "bip324: {s}"),
            NetError::Timeout => f.write_str("timeout"),
            NetError::Disconnected => f.write_str("peer disconnected"),
            NetError::MessageTooLarge(n) => write!(f, "message too large ({n} bytes)"),
            NetError::InvalidV2Type { contents_len } => {
                write!(f, "invalid v2 message type ({contents_len} bytes contents)")
            }
            NetError::BadMagic => f.write_str("wrong network magic"),
            NetError::Consensus(s) => write!(f, "consensus: {s}"),
            NetError::Rules(e) => write!(f, "consensus: {e}"),
            NetError::Store(s) => write!(f, "store: {s}"),
            NetError::Cancelled => f.write_str("confirm cancelled"),
            NetError::Mutated(s) => write!(f, "consensus: {s}"),
            NetError::BadPrev => f.write_str("consensus: unexpected previous header"),
            NetError::SideBlock => f.write_str("protocol: side block; use accept_branch for reorg"),
            NetError::UnknownParent => f.write_str("protocol: unknown parent"),
            NetError::ConnectFailed { msg, .. } => write!(f, "consensus: {msg}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        NetError::Io(e)
    }
}

impl NetError {
    pub fn from_consensus(e: rbitcoin_consensus::ConsensusError) -> Self {
        match e {
            rbitcoin_consensus::ConsensusError::Cancelled => NetError::Cancelled,
            rbitcoin_consensus::ConsensusError::BadPrev => NetError::BadPrev,
            // Pool-adapted store text. Not a block verdict.
            rbitcoin_consensus::ConsensusError::Internal(m) => NetError::store(m),
            other => NetError::Rules(other),
        }
    }

    /// The rule failure inside this error, when the failure is a consensus rule.
    pub fn consensus_rules(&self) -> Option<&rbitcoin_consensus::ConsensusError> {
        match self {
            NetError::Rules(e) => Some(e),
            NetError::ConnectFailed { rules: Some(e), .. } => Some(e),
            _ => None,
        }
    }

    pub fn from_confirm(e: rbitcoin_query::ConfirmError) -> Self {
        match e {
            rbitcoin_query::ConfirmError::Rules(r) => Self::from_consensus(r),
            rbitcoin_query::ConfirmError::Store(se) => NetError::store(se),
        }
    }

    /// `BLOCK_MUTATED`: the body may not be the one the header commits to,
    /// so the block hash must not be cached as failed.
    pub fn is_mutated(&self) -> bool {
        match self {
            NetError::Mutated(_) => true,
            NetError::Rules(e) => {
                crate::chain::reject_is_mutated(&rbitcoin_consensus::block_reject_reason(e))
            }
            NetError::ConnectFailed {
                rules: Some(e),
                msg,
                ..
            } => {
                crate::chain::reject_is_mutated(&rbitcoin_consensus::block_reject_reason(e))
                    || crate::chain::reject_is_mutated(msg)
            }
            NetError::ConnectFailed { msg, .. } | NetError::Consensus(msg) => {
                crate::chain::reject_is_mutated(msg)
            }
            _ => false,
        }
    }

    /// Local store / query read or write fault.
    pub fn store(e: impl fmt::Display) -> Self {
        NetError::Store(e.to_string())
    }

    /// Local store fault or cooperative abort: not a verdict on the block.
    pub fn is_local_fault(&self) -> bool {
        matches!(self, NetError::Store(_) | NetError::Cancelled)
    }

    /// Hash of the block that failed connect, when known.
    pub fn failing_block_hash(&self) -> Option<[u8; 32]> {
        match self {
            NetError::ConnectFailed { hash, .. } => Some(*hash),
            _ => None,
        }
    }
}
