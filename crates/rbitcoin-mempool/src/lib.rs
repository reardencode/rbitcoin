//! Cluster mempool with **InRam** buffers + private sidecar durability under
//! `{datadir}/mempool/` — **not** Class A (`{datadir}/store/tx.body`).
//!
//! # Layout (private namespace)
//!
//! | File | Role |
//! |------|------|
//! | `meta` | Magic, schema, commit generation **G**, slot capacity, live count |
//! | `slots` | Fixed-size slot records (status + body range + txid) |
//! | `tx.body` | Unconfirmed payloads only: `fee(8)‖weight(8)‖raw_tx` per LIVE slot |
//!
//! **Commit model:** body complete → slot LIVE → RAM graph → no fsync per tx.
//! [`ActiveMempool::flush`] bumps `G` and `sync_data`s sidecars. Kill loses at
//! most the last unflushed batch; never claim incomplete bodies.
//!
//! **Memory rule:** graph + body buffers stay proportional to the live set.
//! Sidecars use process `Vec` + file write (no `memmap2`).
//!
//! # Phases (plan.md)
//!
//! - **P1:** open / flush / reopen empty skeleton  
//! - **P2:** TxGraph + linearization + Libre single-tx accept + durable commit  
//! - **P3:** package accept (CPFP), durable remove, block/reorg hooks  
//! - **P5:** full RBF + pure RBFR (1.25×) + package RBF + worst-chunk eviction  

mod accept;
mod error;
mod fee_est;
mod fee_flow;
mod graph;
mod orphanage;
mod store;

pub use accept::{
    check_mempool_structural, AcceptError, AcceptFailureRecord, AcceptResult, AcceptStageUs,
    ActiveMempool, ChainPrevout, ChainTipCtx, Coin, PreparedAdmit, UtxoProvider,
    DEFAULT_MAX_MEMPOOL_WEIGHT, MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT,
};
pub use error::MempoolError;
pub use fee_est::{
    blend_sat_kvb, default_candidate_rates, enforce_monotone_desc, fine_candidate_rates,
    flow_for_depth, historical_far_sat_kvb, min_rate_for_capacity, percentile_sat, BLOCK_WEIGHT_WU,
};
pub use fee_flow::FeeFlowMeter;
pub use graph::{
    frontier_feerate_from_chunks, weight_above_from_chunks, Chunk, Cluster, MempoolGraphStats,
    TxEntry, TxGraph,
};
pub use orphanage::{OrphanSnapshot, Orphanage};
pub use store::{Mempool, MempoolMeta};
