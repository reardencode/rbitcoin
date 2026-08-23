//! Esplora-compatible REST HTTP for **wallet clients and APIs** (plain HTTP;
//! TLS via reverse proxy).
//!
//! Serves exact address/scripthash history, tx/block by id, and broadcast—not a
//! graphical block-explorer product (no address-prefix search / explorer UI
//! catalogue APIs).

mod handlers;
mod script_fields;
mod server;
mod tx_json;
mod ws;

pub use script_fields::{esplora_script_fields, EsploraScriptFields};
pub use server::{
    run_esplora, sample_reset_perf, EsploraConfig, EsploraHandle, DEFAULT_MAX_TRACK_ADDRESSES,
    DEFAULT_MAX_TRACK_TXS, DEFAULT_MAX_WS_CONNECTIONS, DEFAULT_MAX_WS_MESSAGE_BYTES,
};
pub use tx_json::{
    build_tx_json, history_items_to_tx_json, tx_status_json, tx_status_json_in, utxo_list_json,
};
