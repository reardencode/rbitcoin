//! Electrum protocol 1.4+ server for **wallet clients** (confirmed + optional
//! mempool / libre-relay-class).
//!
//! Not a graphical block-explorer backend: clients are expected to already
//! know their scripthashes / txids.
//!
//! `server.version[0]` is `rbitcoin-electrs <workspace.package.version>`.
//! We are not electrs. Cake Wallet `getNodeIsElectrs()` requires the
//! substring `electrs` before it will probe `blockchain.tweaks.subscribe`.
//! Other tweaks clients (kiss-bdk) use the same stream without that probe.

mod server;
mod tweaks;
mod unspent;

pub use server::{
    electrum_scripthash_hex, parse_electrum_request_line, read_line_capped, run_electrum,
    sample_reset_perf, ElectrumConfig, ElectrumHandle, ServeLimits, TipNotify,
    DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_BROADCAST_HEX, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_SCRIPTHASH_SUBS,
};
pub use unspent::{
    scripthash_mempool_stats, scripthash_mempool_stats_slot, scripthash_utxos_with_mempool,
    scripthash_utxos_with_mempool_slot, scripthash_utxos_with_mempool_slot_in, MempoolShStats,
};
