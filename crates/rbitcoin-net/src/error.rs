use std::fmt;
use std::io;

#[derive(Debug)]
pub enum NetError {
    Io(io::Error),
    Encode(String),
    Protocol(&'static str),
    /// Peer does not speak BIP324 v2 (or closed during v2 handshake).
    /// Production is v2-only: disconnect and do not fall back to v1.
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
            other => NetError::Consensus(other.to_string()),
        }
    }

    /// `BLOCK_MUTATED`: the body may not be the one the header commits to,
    /// so the block hash must not be cached as failed.
    pub fn is_mutated(&self) -> bool {
        match self {
            NetError::Mutated(_) => true,
            NetError::ConnectFailed { msg, .. } | NetError::Consensus(msg) => {
                crate::chain::reject_is_mutated(msg)
            }
            _ => false,
        }
    }

    /// Hash of the block that failed connect, when known.
    pub fn failing_block_hash(&self) -> Option<[u8; 32]> {
        match self {
            NetError::ConnectFailed { hash, .. } => Some(*hash),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_and_source_surface() {
        let cases: Vec<(NetError, &str)> = vec![
            (NetError::Io(io::Error::other("x")), "io:"),
            (NetError::Encode("e".into()), "encode: e"),
            (NetError::Protocol("p"), "protocol: p"),
            (NetError::V1Peer, "peer does not speak BIP324 v2"),
            (NetError::Bip324("b".into()), "bip324: b"),
            (NetError::Timeout, "timeout"),
            (NetError::Disconnected, "peer disconnected"),
            (NetError::MessageTooLarge(9), "message too large (9 bytes)"),
            (
                NetError::InvalidV2Type { contents_len: 3 },
                "invalid v2 message type (3 bytes contents)",
            ),
            (NetError::BadMagic, "wrong network magic"),
            (NetError::Consensus("c".into()), "consensus: c"),
            (NetError::Cancelled, "confirm cancelled"),
            (
                NetError::Mutated("bad-txnmrklroot".into()),
                "consensus: bad-txnmrklroot",
            ),
            (NetError::BadPrev, "consensus: unexpected previous header"),
            (
                NetError::SideBlock,
                "protocol: side block; use accept_branch for reorg",
            ),
            (NetError::UnknownParent, "protocol: unknown parent"),
            (
                NetError::ConnectFailed {
                    hash: [1u8; 32],
                    msg: "bad spend".into(),
                },
                "consensus: bad spend",
            ),
        ];
        for (err, needle) in cases {
            let s = err.to_string();
            assert!(s.contains(needle), "display={s:?} needle={needle}");
            // Only Io exposes a source.
            match &err {
                NetError::Io(_) => assert!(err.source().is_some()),
                _ => assert!(err.source().is_none()),
            }
        }
        let from_io: NetError = io::Error::other("z").into();
        assert!(matches!(from_io, NetError::Io(_)));
    }
}
