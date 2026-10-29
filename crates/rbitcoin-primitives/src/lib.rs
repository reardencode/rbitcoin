//! Shared primitives for the rbitcoin workspace.
//!
//! Keep consensus-heavy types in rust-bitcoin once wired; this crate holds
//! store and node newtypes that must stay stable across crates.

#[doc(hidden)]
pub mod compact;
#[doc(hidden)]
pub mod hex;
#[doc(hidden)]
pub mod loc_simd;
#[doc(hidden)]
pub mod median_time;
#[doc(hidden)]
pub mod merkle;
#[doc(hidden)]
pub mod script_opcode;
#[doc(hidden)]
pub mod script_sigops;
#[doc(hidden)]
pub mod script_worker;
#[doc(hidden)]
pub mod scriptnum;

pub use compact::{
    compact_size_len, read_compact_size, read_compact_size_from, read_uleb128, uleb128_len,
    write_compact_size, write_uleb128, write_uleb128_into, PackError,
};
pub use hex::{
    decode as hex_decode, display_hash_hex, encode as hex_encode, parse_display_hash32,
    scripthash_display_hex, HexToArrayError, HexToBytesError,
};
pub use loc_simd::{deinterleave_pairs_u8x8, inclusive_u8x8_times_8};
pub use median_time::{median_time_past_times, MedianWindow};
pub use merkle::{
    merkle_branch, merkle_root_from_branch, merkle_root_from_txids, merkle_root_mutated,
};
pub use script_opcode::{
    OP_0, OP_1NEGATE, OP_2DIV, OP_2MUL, OP_AND, OP_CAT, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CODESEPARATOR, OP_DIV, OP_DUP, OP_EQUAL, OP_EQUALVERIFY,
    OP_HASH160, OP_INVERT, OP_LEFT, OP_LSHIFT, OP_MOD, OP_MUL, OP_OR, OP_PUSHBYTES_2,
    OP_PUSHBYTES_20, OP_PUSHBYTES_32, OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_PUSHNUM_16, OP_RESERVED, OP_RETURN, OP_RIGHT, OP_RSHIFT, OP_SUBSTR, OP_TRUE, OP_VERIF,
    OP_VERNOTIF, OP_XOR, P2A_PROGRAM, P2A_SCRIPT, P2PKH_PREFIX, P2PKH_SUFFIX, P2SH_PREFIX,
    P2TR_PREFIX, P2WPKH_PREFIX, P2WSH_PREFIX,
};
pub use script_sigops::script_sigop_count;
pub use script_worker::{assert_not_script_worker, on_script_worker, set_script_worker};
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
