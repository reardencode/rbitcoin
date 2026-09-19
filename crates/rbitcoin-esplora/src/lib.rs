//! Esplora-compatible REST HTTP for **wallet clients and APIs** (plain HTTP;
//! TLS via reverse proxy).
//!
//! Serves exact address/scripthash history, tx/block by id, and broadcast.
//! **0.8:** mempool/electrs `/internal/*` bulk routes + unix listen so this
//! process can replace electrs behind mempool.space `/api/`. Address-prefix
//! search is out. Surface: [`COMPAT.md`](../../../COMPAT.md).
//! `GET …/txs/summary` is a mempool.space-shaped compact dialect (not
//! Blockstream Esplora `API.md`). Opt-in `GET /block-template` is GBT.

mod handlers;
mod script_fields;
mod server;
mod tx_json;
mod ws;

pub use server::{
    run_esplora, sample_reset_perf, BlockTemplateFn, EsploraConfig, EsploraHandle, EsploraListen,
};
