//! Map-free relational store (libbitcoin-class tables; fd pread/pwrite + uring).
//!
//! Class A bodies are append-oriented. Class B multimaps use mutable hash heads.
//! Class C (confirmed / strong_tx) is tip-mutable for reorgs.

mod address_head;
mod array_table;
mod bdz;
mod binary_fuse8;
mod block_queue;
mod block_wire;
mod bulk_io;
mod chain;
mod compact;
mod error;
mod file;
mod fuse8_filter;
mod hashhead;
mod head_resolve_denserels;
mod head_resolve_pick;
pub mod head_resolve_stats;
mod header_table;
mod height_fence;
mod idx_body_pipeline;
mod int_map;
mod integrity;
mod io_backend;
mod io_handle;
#[cfg(windows)]
mod io_session_iocp;
mod io_session_pool;
mod open_address;
mod point_table;
mod scripthash;
mod scripthash_head;
mod scripthash_layout;
mod scripthash_materialize;
mod scripthash_mphf;
mod scripthash_overflow;
mod scripthash_pages;
mod scripthash_slabs;
mod scripthash_sorted_head;
mod segmented_head;
mod sorted_run;
mod sp_tweaks;
mod sp_tweaks_uring;
pub mod spend_annotate_uring;
mod spender_table;
mod store;
mod store_secret;
pub mod testutil;
mod tx_head_mphf;
mod tx_idx;
mod tx_table;
mod txid_body;
mod uring_session;
mod var_table;

pub use crate::compact::output_flags;
pub use address_head::{is_probe_exhausted_error, is_store_corrupt_display};
#[cfg(any(test, debug_assertions))]
pub use block_queue::take_raw_clone_n;
pub use block_queue::{BlockQueue, QueuedBlockMeta, TakenRaw};
pub use block_wire::block_wire_input_count;
pub use error::StoreError;
pub use file::ensure_nofile_budget;
pub use hashhead::{HeadOpenOpts, HeadScale};
pub use head_resolve_stats::{leftover_probe_diag_ready, leftover_probe_diag_recorded};
pub use header_table::{block_header_hash, HeaderRecord};
pub use height_fence::HeightFence;
pub(crate) use idx_body_pipeline::run_idx_body_pipeline;
pub use idx_body_pipeline::{BodyMode as IdxBodyMode, IdxBodyJob};
pub use int_map::{FkMap, FkSet, U32Map, U64IdentityHasher, U64Map, U64Set};
pub use integrity::merkle_root_from_txids;
pub use io_backend::{ReadIoBackend, WriteIoBackend};
pub use point_table::PointRecord;
pub use scripthash::{
    script_hash, sh_heads_insert_capped, ColdProgress, ScriptHashRecord, INCLUDE_HWM_NAME,
    SH_HEADS_CAP,
};
pub use scripthash_layout::ShHeadValue;
pub use scripthash_materialize::{
    clear_unsorted_shard_dir, collect_unsorted_shard_files, materialize_sh_unsorted_from_class_a,
    unsorted_collect_workers, unsorted_done_last_fk, unsorted_pack_workers, unsorted_shard_dir,
};
pub(crate) use sorted_run::host_mem_available_bytes;
pub use sorted_run::{
    free_gib_label, list_materialize_claims, list_runs, next_run_path, write_sorted_run,
};
pub use sp_tweaks::SpTweaksTable;
pub use sp_tweaks_uring::load_tweak_wave;
pub use spend_annotate_uring::spend_ann_backend;
pub use store::{keep_unspent_vout_subsequence, Store, StoreLayout};
#[cfg(debug_assertions)]
pub use store::{reset_tx_full_gets, reset_txid_get_many, tx_full_gets, txid_get_many_fks};
pub use store_secret::StoreSecret;
pub use tx_table::HeadResizeSizeSnapshot;
pub use tx_table::{
    decode_inwit_secret, decode_packed_tx_outs_with_spender_rels,
    decode_packed_tx_outs_with_spender_rels_secret, decode_packed_tx_with_spender_rels_secret,
    encode_packed_tx, encode_packed_tx_with_secret, spend_meta_backend, spent_abs, InputRecord,
    OutputRecord, TxRecord,
};
pub(crate) use uring_session::IoCtx;
