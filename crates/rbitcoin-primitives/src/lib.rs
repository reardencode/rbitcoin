//! Shared primitives for the rbitcoin workspace.
//!
//! Keep consensus-heavy types in rust-bitcoin once wired; this crate holds
//! store and node newtypes that must stay stable across crates.

mod compact;
mod hex;
mod loc_simd;
mod median_time;
mod script_sigops;
mod scriptnum;

pub use compact::{
    compact_size_len, read_compact_size, read_compact_size_from, read_uleb128, uleb128_len,
    write_compact_size, write_uleb128, write_uleb128_into, PackError,
};
pub use hex::{
    decode as hex_decode, display_hash_hex, encode as hex_encode, parse_display_hash32,
    DisplayHashError, HexError,
};
pub use loc_simd::{deinterleave_pairs_u8x8, inclusive_u8x8_times_8};
pub use median_time::median_time_past_times;
pub use script_sigops::script_sigop_count;
pub use scriptnum::{
    scriptnum_decode, scriptnum_decode_width, scriptnum_encode, scriptnum_is_minimal,
    ScriptNumError,
};

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
                    "User Agent comment ({ch}) contains unsafe characters."
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
            "Total length of network version string ({}) exceeds maximum length (256). Reduce the number or size of uacomments.",
            s.len()
        ));
    }
    Ok(s)
}

/// Default Electrum TCP port (electrs convention) when `--electrum-listen` omits ADDR.
pub const DEFAULT_ELECTRUM_PORT: u16 = 50001;
/// Default Esplora HTTP port when `--esplora-listen` omits ADDR.
pub const DEFAULT_ESPLORA_PORT: u16 = 3000;
/// Default health HTTP port when `--health-listen` omits ADDR.
pub const DEFAULT_HEALTH_PORT: u16 = 9332;

pub const STORE_MAGIC: [u8; 4] = *b"RBT1";

/// Current on-disk schema version. Live layout: workspace `SCHEMA.md`.
/// Historic versions: `SCHEMA_HISTORY.md`.
///
/// **26:** `header.body` is 88 B again. Occupied 24/25 strips the trailing
///         `size:u32` + `weight:u32`. Block size and weight come from `txstat`.
///         A 25 binary refuses 26 `meta`.
/// **25:** `txstat.body` 8 B/create (ULEB `fee_sat`/`base`/`wit_extra`,
///         per-header remaining-byte overflow). Occupied 24 rewrites `meta`
///         and extends a zeroed `txstat.body` to loc count (no `txout.body`
///         rewrite). Unreleased leftover `txfixed.body` is unlinked. A 24
///         binary refuses 25 `meta`.
/// **24:** `header.body` 96 B (trailing `size:u32` + `weight:u32`). Occupied 23
///         rewrites 88 B rows (`header.body.grow` then rename); zeros until
///         confirm stamps. SH extent last-page reserved is create count.
/// **23:** `create.loc.ovf` rows are 16 B (`fk:u64` + strides/`n_out` u32) so a
///         ~1 MiB consensus-valid txout (and `n_out > 65535`) stores. Occupied
///         22 Class A rewrites 12 B ovf rows and `meta`.
/// **22:** `create.loc` + `seqsigwit.loc`; LAYOUT17 omits `output_count`. Spent
///         slot is flags + u40 spend fk + u16 vin. This is the oldest meta
///         this binary opens.
/// **21 and older:** not opened. Meta below 22 is one wipe-and-IBD refuse.
///         Those layouts are archaeology in `SCHEMA_HISTORY.md`.
pub const SCHEMA_VERSION: u16 = 26;

/// True if `ver` may appear in store `meta` / table headers this binary can open.
///
/// Schema **26** is current. Meta **22** through **26** opens. Occupied **22**
/// rewrites `create.loc.ovf` 12 B rows to 16 B. Occupied **24/25** strips
/// trailing size/weight from 96 B `header.body` rows. Any meta below **26**
/// is rewritten to 26; a short `txstat.body` is aligned to the loc count.
/// Meta older than **22** is not
/// openable: those Class A bodies (`tx.body`, `txout.body`, `inwit.body` /
/// `seqsigwit.body`) were wiped, not rewritten.
#[inline]
pub fn schema_file_openable(ver: u16) -> bool {
    (22..=SCHEMA_VERSION).contains(&ver)
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

    /// Core-matching P2P listen port.
    pub fn default_p2p_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    /// Core-matching JSON-RPC TCP port.
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Mainnet => 8332,
            Network::Testnet => 18332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
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
    /// Class A input-side + witness (`seqsigwit.body`).
    SeqSigWit = 16,
    /// Class A sole-spender slots (`spent.body`, 8 B × n_out).
    Spent = 17,
    /// Create/seqsigwit delta locators (`create.loc` / `seqsigwit.loc` and `.ovf`).
    DeltaLoc = 18,
    /// Dense create_fk-ordered confirm-time econ (`txstat.body`, 8 B).
    TxStat = 19,
    /// Per-header remaining-byte overflow (`txstat.ovf`).
    TxStatOvf = 20,
    /// Per-header overflow locator (`txstat.blk`, 16 B/header).
    TxStatBlk = 21,
    /// Spender → parent edges (`input.body`, 8 B/input).
    Input = 22,
    /// Per-create `n_in` (`input.loc`, 2 B/create).
    InputLoc = 23,
    /// Optional BIP158 basic filter bytes (`blockfilter.body`).
    BlockFilter = 24,
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
            16 => Some(TableKind::SeqSigWit),
            17 => Some(TableKind::Spent),
            18 => Some(TableKind::DeltaLoc),
            19 => Some(TableKind::TxStat),
            20 => Some(TableKind::TxStatOvf),
            21 => Some(TableKind::TxStatBlk),
            22 => Some(TableKind::Input),
            23 => Some(TableKind::InputLoc),
            24 => Some(TableKind::BlockFilter),
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
        assert_eq!(Network::Mainnet.default_p2p_port(), 8333);
        assert_eq!(Network::Mainnet.default_rpc_port(), 8332);
        assert_eq!(Network::Testnet.default_p2p_port(), 18333);
        assert_eq!(Network::Testnet.default_rpc_port(), 18332);
        assert_eq!(Network::Signet.default_p2p_port(), 38333);
        assert_eq!(Network::Signet.default_rpc_port(), 38332);
        assert_eq!(Network::Regtest.default_p2p_port(), 18444);
        assert_eq!(Network::Regtest.default_rpc_port(), 18443);
        assert_eq!(DEFAULT_ELECTRUM_PORT, 50001);
        assert_eq!(DEFAULT_ESPLORA_PORT, 3000);
    }

    #[test]
    fn table_kind_roundtrip() {
        for v in [
            1u16, 2, 3, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        ] {
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
        assert_eq!(TableKind::SeqSigWit.as_u16(), 16);
        assert_eq!(TableKind::Spent.as_u16(), 17);
        assert_eq!(TableKind::DeltaLoc.as_u16(), 18);
        assert_eq!(TableKind::TxStat.as_u16(), 19);
        assert_eq!(TableKind::TxStatOvf.as_u16(), 20);
        assert_eq!(TableKind::TxStatBlk.as_u16(), 21);
        assert_eq!(TableKind::Input.as_u16(), 22);
        assert_eq!(TableKind::InputLoc.as_u16(), 23);
        assert_eq!(TableKind::from_u16(24), Some(TableKind::BlockFilter));
    }

    #[test]
    fn schema_file_openable_is_22_through_current() {
        assert!(!schema_file_openable(21));
        assert!(!schema_file_openable(13));
        assert!(schema_file_openable(22));
        assert!(schema_file_openable(SCHEMA_VERSION));
        assert!(!schema_file_openable(SCHEMA_VERSION + 1));
        eprintln!(
            "schema_file_openable false below 22 (21={} 13={}) true from 22 through current {} (22={} current={})",
            schema_file_openable(21),
            schema_file_openable(13),
            SCHEMA_VERSION,
            schema_file_openable(22),
            schema_file_openable(SCHEMA_VERSION)
        );
    }

    #[test]
    fn constants_stable() {
        assert_eq!(STORE_MAGIC, *b"RBT1");
        assert_eq!(SCHEMA_VERSION, 26);
        assert!(!VERSION.is_empty());
        assert!(schema_file_openable(26));
        assert!(schema_file_openable(25));
        assert!(schema_file_openable(24));
        assert!(schema_file_openable(23));
        assert!(schema_file_openable(22));
        assert!(!schema_file_openable(21));
        assert!(!schema_file_openable(20));
        assert!(!schema_file_openable(16));
        assert!(!schema_file_openable(13));
        assert!(!schema_file_openable(12));
        assert!(!schema_file_openable(27));
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
