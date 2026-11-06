//! Cluster mempool with **InRam** buffers + private sidecar durability under
//! `{datadir}/mempool/` — **not** Class A (`{datadir}/store/tx.body`).
//!
//! # Layout (private namespace)
//!
//! | File | Role |
//! |------|------|
//! | `meta` | Magic, schema **4**, commit generation **G**, slot capacity, live count |
//! | `slots` | Fixed-size slot records (status + body range + txid) |
//! | `tx.body` | Packed live records (fee, weight, sigop cost, accept time, txid, wtxid, packed tx, vin aux) |
//!
//! **Commit model:** body tail complete → slot LIVE → RAM graph. No fsync per
//! tx. Admits persist on a 5 s timer ([`ActiveMempool::persist_due`]); that path
//! appends the body tail and `pwrite`s only new LIVE slot records. Tip-follow
//! drives it from the perf tick. Confirm/RBF DEAD of an already-durable slot
//! is a one-byte `pwrite`. The removal's owner `fdatasync`s `slots` once, then
//! `meta` (a block's confirms and conflict spends share that pair; not a full
//! slot dump, not one sync per tx).
//! [`ActiveMempool::flush`] bumps `G`, rewrites slots, and `sync_data`s. Crash
//! may lose ≤5 s of admits; never LIVE slots past durable `tx.body`. Leftover
//! schema 1–3 converts on open. Schema 1 has empty vin aux (SH reindex
//! batch-fills), schema ≤ 2 has unknown sigops until the hub recomputes them,
//! and every upgraded record takes the migrate's wall-clock second as its
//! accept time.
//!
//! Packed decode uses stored txid/wtxid (no SHA256d). Vin aux is hashed at
//! admit from resolved prevouts. Compact copies packed payload ranges.
//!
//! **Memory rule:** graph + body buffers stay proportional to the live set
//! (`Arc<Transaction>` shared by load/accept). Sidecars use process `Vec` +
//! file write (no `memmap2`).
//!
//! # Phases (plan.md)
//!
//! - **P1:** open / flush / reopen empty skeleton  
//! - **P2:** TxGraph + linearization + Libre single-tx accept + durable commit  
//! - **P3:** package accept (CPFP), durable remove, block/reorg hooks  
//! - **P5:** full RBF + pure RBFR (1.25×) + package RBF + worst-chunk eviction  

#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod accept;
mod core_dat;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod fee_analog;
#[doc(hidden)]
pub mod fee_est;
#[doc(hidden)]
pub mod fee_flow;
#[doc(hidden)]
pub mod graph;
#[doc(hidden)]
pub mod linearize;
#[doc(hidden)]
pub mod orphanage;
#[doc(hidden)]
pub mod packed;
#[doc(hidden)]
pub mod store;
pub mod testutil;

pub use accept::{
    check_mempool_structural, trust_keeps_structural, AcceptError, AcceptFailureRecord,
    AcceptResult, AcceptStageUs, ActiveMempool, ChainPrevout, ChainTipCtx, Coin, LiftedOrphan,
    PrepareOpts, PreparedAdmit, SiblingEviction, UtxoProvider, DEFAULT_MAX_MEMPOOL_WEIGHT,
    MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT,
};
pub use core_dat::{CoreDatTx, CoreMempoolDat};
pub use error::MempoolError;
pub use fee_analog::{AnalogHistory, HISTORICAL_CONFIDENCE_FAR};
pub use fee_est::{
    block_individual_p10_sat_kvb, default_candidate_rates, depth_rate_sat_kvb,
    enforce_monotone_desc, fee_at_target_sat_kvb, fine_candidate_rates, flow_for_depth,
    hold_defined_then_monotone, min_rate_for_capacity, percentile_sat, published_depth_rate,
    warmup_blend, BLOCK_WEIGHT_WU, CONFIDENCE_FAR, CONFIDENCE_NEAR,
};
pub use fee_flow::FeeFlowMeter;
pub use graph::{
    frontier_feerate_from_chunks, weight_above_from_chunks, Chunk, Cluster, MempoolGraphStats,
    SelectBudget, Selected, StockAbove, TxEntry, TxGraph, MAX_CLUSTER_COUNT, MAX_CLUSTER_VSIZE,
};
pub use orphanage::{OrphanSnapshot, Orphanage};
pub use packed::VinAux;
pub use store::{Mempool, MempoolMeta};
