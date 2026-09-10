//! Shared primitives for the rbitcoin workspace.
//!
//! Keep consensus-heavy types in rust-bitcoin once wired; this crate holds
//! store and node newtypes that must stay stable across crates.

mod hex;
mod median_time;
mod script_sigops;

pub use hex::{
    decode as hex_decode, display_hash_hex, encode as hex_encode, parse_display_hash32,
    DisplayHashError, HexError,
};
pub use median_time::median_time_past_times;
pub use script_sigops::script_sigop_count;

use std::fmt;

/// Workspace schema / API version string for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// BIP14 user-agent / `getnetworkinfo.subversion`.
///
/// Core shape: `/rbitcoin:0.1.0/` or `/rbitcoin:0.1.0(testnode0; foo)/`.
/// Rejects `/ : ( )` and non-ASCII in comments; total length must be ≤256.
pub fn rbitcoin_subversion(
    pkg_version: &str,
    comments: &[impl AsRef<str>],
) -> Result<String, String> {
    for c in comments {
        let c = c.as_ref();
        for ch in c.chars() {
            if matches!(ch, '/' | ':' | '(' | ')') || !ch.is_ascii() {
                return Err(format!(
                    "Error: User Agent comment ({ch}) contains unsafe characters."
                ));
            }
        }
    }
    let s = if comments.is_empty() {
        format!("/rbitcoin:{pkg_version}/")
    } else {
        let joined = comments
            .iter()
            .map(|c| c.as_ref())
            .collect::<Vec<_>>()
            .join("; ");
        format!("/rbitcoin:{pkg_version}({joined})/")
    };
    if s.len() > 256 {
        return Err(format!(
            "Error: Total length of network version string ({}) exceeds maximum length (256). Reduce the number or size of uacomments.",
            s.len()
        ));
    }
    Ok(s)
}

/// File magic for store tables: ASCII `RBT1`.
pub const STORE_MAGIC: [u8; 4] = *b"RBT1";

/// Current on-disk schema version. Live layout: workspace `SCHEMA.md`.
/// Historic versions: `SCHEMA_HISTORY.md`.
///
/// **20:** Sealed `tx.head` value-assigned packed BDZ (no `.rel`). Occupied
///         schema **18/19** `tx.head` is refused (wipe `store/tx.head`, keep
///         Class A + SH). Empty `tx.head` rewrites `meta` and rebuilds.
/// **19:** Megakey SH extent pack8 mode 11 (`ver=2` last page). Soft-open **18**
///         with occupied indexes (rewrite `meta`). 18 binary refuses 19 `meta`.
/// **18:** MPHF SH main + sealed `tx.head`; no IBD SH runs. Soft-open **17**
///         only when `tx.head` occupancy and `scripthash*` data are absent
///         (rewrite `meta`); otherwise refuse (wipe those indexes, keep Class A).
/// **17:** SH `key_len=40`; Class A thin meta + kinds 0–9 + 8 B spent;
///         megakey pages are uleb deltas.
/// **16:** Drop `tx_height.body`; create height is a RAM fence from `confirmed[]` +
///         `header_txs_*`. Soft-open schema 15 (unlink leftover file). Class A unchanged.
/// **15:** Class A split (`txout` / `inwit` / `spent`) + Class B SH slabs / sorted heads.
///         Refuse packed schema-13/14 Class A with txs; refuse materialized page-era SH.
/// **14:** Class B SH head = Empty/Inline/Paged (4 KiB page chains); refuse schema-13 slabs.
/// **13:** dense `txid.body` sidefile; Class A packed body meta **without** leading txid.
pub const SCHEMA_VERSION: u16 = 20;

/// True if `ver` may appear in store `meta` / table headers this binary can open.
///
/// Schema **20** is current. Schema **18/19** with occupied `tx.head` or
/// `scripthash*` are refused; empty 18/19 indexes rewrite `meta`. Schema **17**
/// still refuses populated `tx.head` / `scripthash*` or rewrites empty indexes.
/// Schema **13**–**16** still soft-open empty Class A / empty SH (meta rewrite).
#[inline]
pub fn schema_file_openable(ver: u16) -> bool {
    ver == SCHEMA_VERSION || (SCHEMA_VERSION == 20 && matches!(ver, 13..=19))
}

/// 1-based foreign key into a store table body. Zero means null / absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fk(pub u64);

impl Fk {
    pub const NULL: Fk = Fk(0);

    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    pub fn new(id: u64) -> Option<Fk> {
        if id == 0 {
            None
        } else {
            Some(Fk(id))
        }
    }

    pub fn get(self) -> Option<u64> {
        if self.is_null() {
            None
        } else {
            Some(self.0)
        }
    }
}

impl fmt::Display for Fk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "Fk(null)")
        } else {
            write!(f, "Fk({})", self.0)
        }
    }
}

/// Block height (genesis = 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(pub u32);

impl Height {
    pub const GENESIS: Height = Height(0);

    pub fn next(self) -> Option<Height> {
        self.0.checked_add(1).map(Height)
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Bitcoin network selection for the node process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    pub fn parse(s: &str) -> Result<Network, ParseNetworkError> {
        match s.to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Ok(Network::Mainnet),
            "test" | "testnet" | "testnet3" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            other => Err(ParseNetworkError {
                input: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unknown network name from CLI / config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetworkError {
    pub input: String,
}

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown network `{}`", self.input)
    }
}

impl std::error::Error for ParseNetworkError {}

/// Table kind identifiers stored in file headers ([`SCHEMA.md`](../../SCHEMA.md)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TableKind {
    Meta = 1,
    Header = 2,
    /// Class A outputs body (`txout.body`); was `Tx` through schema 14.
    TxOut = 3,
    StrongTx = 7,
    Confirmed = 8,
    ArrayLink = 9,
    HashHead = 10,
    /// Electrum scripthash multimap (SHA256(scriptPubKey)).
    ScriptHash = 11,
    /// Multi-spender list nodes (16 B: spending_tx_fk | next).
    Spender = 13,
    /// Dense create_fk-ordered txid sidefile (`txid.body`).
    TxidBody = 14,
    /// Optional BIP-352 thin tweak body (`sp_tweaks.body`). Schema 14 side product.
    SpTweaks = 15,
    /// Class A input-side + witness (`inwit.body`).
    Inwit = 16,
    /// Class A sole-spender slots (`spent.body`, 8 B × n_out).
    Spent = 17,
}

impl TableKind {
    pub fn from_u16(v: u16) -> Option<TableKind> {
        match v {
            1 => Some(TableKind::Meta),
            2 => Some(TableKind::Header),
            3 => Some(TableKind::TxOut),
            // 4, 5, 6 reserved (retired Input / Output / Point)
            7 => Some(TableKind::StrongTx),
            8 => Some(TableKind::Confirmed),
            9 => Some(TableKind::ArrayLink),
            10 => Some(TableKind::HashHead),
            11 => Some(TableKind::ScriptHash),
            // 12 reserved (retired TxHeight)
            13 => Some(TableKind::Spender),
            14 => Some(TableKind::TxidBody),
            15 => Some(TableKind::SpTweaks),
            16 => Some(TableKind::Inwit),
            17 => Some(TableKind::Spent),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fk_display_and_get() {
        assert!(Fk::NULL.is_null());
        assert_eq!(Fk::NULL.get(), None);
        assert_eq!(format!("{}", Fk::NULL), "Fk(null)");
        assert_eq!(Fk::new(0), None);
        let f = Fk::new(7).unwrap();
        assert_eq!(f.get(), Some(7));
        assert_eq!(format!("{f}"), "Fk(7)");
    }

    #[test]
    fn height_display_and_next() {
        assert_eq!(Height::GENESIS.0, 0);
        assert_eq!(format!("{}", Height(42)), "42");
        assert_eq!(Height(u32::MAX).next(), None);
        assert_eq!(Height(0).next(), Some(Height(1)));
    }

    #[test]
    fn network_parse_display_and_error() {
        assert_eq!(Network::parse("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(Network::parse("TESTNET3").unwrap(), Network::Testnet);
        assert_eq!(Network::parse("signet").unwrap().as_str(), "signet");
        assert_eq!(format!("{}", Network::Regtest), "regtest");
        let err = Network::parse("bogus").unwrap_err();
        assert_eq!(format!("{err}"), "unknown network `bogus`");
        let _ = &err as &dyn std::error::Error;
    }

    #[test]
    fn table_kind_roundtrip() {
        for v in [1u16, 2, 3, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17] {
            let k = TableKind::from_u16(v).expect("kind");
            assert_eq!(k.as_u16(), v);
        }
        assert!(TableKind::from_u16(4).is_none());
        assert!(TableKind::from_u16(5).is_none());
        assert!(TableKind::from_u16(6).is_none());
        assert!(TableKind::from_u16(12).is_none());
        assert!(TableKind::from_u16(0).is_none());
        assert!(TableKind::from_u16(99).is_none());
        assert_eq!(TableKind::TxOut.as_u16(), 3);
        assert_eq!(TableKind::Spender.as_u16(), 13);
        assert_eq!(TableKind::TxidBody.as_u16(), 14);
        assert_eq!(TableKind::SpTweaks.as_u16(), 15);
        assert_eq!(TableKind::Inwit.as_u16(), 16);
        assert_eq!(TableKind::Spent.as_u16(), 17);
    }

    #[test]
    fn constants_stable() {
        assert_eq!(STORE_MAGIC, *b"RBT1");
        assert_eq!(SCHEMA_VERSION, 20);
        assert!(!VERSION.is_empty());
        assert!(schema_file_openable(20));
        assert!(schema_file_openable(19));
        assert!(schema_file_openable(18));
        assert!(schema_file_openable(17));
        assert!(schema_file_openable(16));
        assert!(schema_file_openable(15));
        assert!(schema_file_openable(14));
        assert!(schema_file_openable(13));
        assert!(!schema_file_openable(12));
        assert!(!schema_file_openable(0));
    }

    #[test]
    fn subversion_comments_and_rejects() {
        assert_eq!(
            rbitcoin_subversion("0.1.0", &[] as &[&str]).unwrap(),
            "/rbitcoin:0.1.0/"
        );
        let s = rbitcoin_subversion("0.1.0", &["testnode0"]).unwrap();
        assert_eq!(s, "/rbitcoin:0.1.0(testnode0)/");
        assert_eq!(&s[s.len() - 12..s.len() - 1], "(testnode0)");
        let s = rbitcoin_subversion("0.1.0", &["testnode0", "foo"]).unwrap();
        assert_eq!(s, "/rbitcoin:0.1.0(testnode0; foo)/");
        assert!(rbitcoin_subversion("0.1.0", &["a/b"])
            .unwrap_err()
            .contains("unsafe"));
        assert!(rbitcoin_subversion("0.1.0", &["a".repeat(256)])
            .unwrap_err()
            .contains("exceeds maximum"));
    }

    #[test]
    fn live_version_feeds_subversion() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        let s = rbitcoin_subversion(VERSION, &[] as &[&str]).unwrap();
        assert_eq!(s, format!("/rbitcoin:{VERSION}/"));
    }
}
