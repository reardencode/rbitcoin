//! Map-free relational store (Class A/B/C; fd pread/pwrite + uring).
//!
//! Class A bodies are append-oriented. Class B multimaps use mutable hash heads.
//! Class C (confirmed / strong_tx) is tip-mutable for reorgs.

#[doc(hidden)]
pub mod address_head;
#[doc(hidden)]
pub mod array_table;
#[doc(hidden)]
pub mod bdz;
#[doc(hidden)]
pub mod binary_fuse8;
#[doc(hidden)]
pub mod block_filter;
#[doc(hidden)]
pub mod block_queue;
#[doc(hidden)]
pub mod block_wire;
#[doc(hidden)]
pub mod bulk_io;
#[doc(hidden)]
pub mod chain;
#[doc(hidden)]
pub mod compact;
#[doc(hidden)]
pub mod coord_io;
pub mod create_loc;
#[doc(hidden)]
pub mod delta_loc;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod file;
#[doc(hidden)]
pub mod fuse8_filter;
#[doc(hidden)]
pub mod hashhead;
#[doc(hidden)]
pub mod head_resolve_denserels;
#[doc(hidden)]
pub mod head_resolve_pick;
pub mod head_resolve_stats;
#[doc(hidden)]
pub mod header_table;
#[doc(hidden)]
pub mod height_fence;
#[doc(hidden)]
pub mod idx_body_pipeline;
#[doc(hidden)]
pub mod index_build_uring;
#[doc(hidden)]
pub mod input;
#[doc(hidden)]
pub mod int_map;
#[doc(hidden)]
pub mod integrity;
#[doc(hidden)]
pub mod io_backend;
#[doc(hidden)]
pub mod io_handle;
#[cfg(windows)]
#[doc(hidden)]
pub mod io_session_iocp;
#[doc(hidden)]
pub mod io_session_pool;
#[doc(hidden)]
pub mod open_address;
#[doc(hidden)]
pub mod point_table;
#[doc(hidden)]
pub mod readonly_map;
#[doc(hidden)]
pub mod scripthash;
#[doc(hidden)]
pub mod scripthash_head;
#[doc(hidden)]
pub mod scripthash_layout;
#[doc(hidden)]
pub mod scripthash_materialize;
#[doc(hidden)]
pub mod scripthash_mphf;
#[doc(hidden)]
pub mod scripthash_overflow;
#[doc(hidden)]
pub mod scripthash_pages;
#[doc(hidden)]
pub mod scripthash_slabs;
#[doc(hidden)]
pub mod scripthash_sorted_head;
#[doc(hidden)]
pub mod seg_pair;
#[doc(hidden)]
pub mod segmented_head;
#[doc(hidden)]
pub mod sorted_run;
#[doc(hidden)]
pub mod sp_tweaks;
#[doc(hidden)]
pub mod sp_tweaks_uring;
pub mod spend_annotate_uring;
#[doc(hidden)]
pub mod spend_durable;
#[doc(hidden)]
pub mod spender_table;
#[doc(hidden)]
pub mod store;
#[doc(hidden)]
pub mod store_secret;
#[doc(hidden)]
pub mod sync;
pub mod testutil;
#[doc(hidden)]
pub mod tx_head_mphf;
#[doc(hidden)]
pub mod tx_table;
#[doc(hidden)]
pub mod txid_body;
#[doc(hidden)]
pub mod txstat;
#[doc(hidden)]
pub mod uring_session;
#[doc(hidden)]
pub mod var_table;

pub use crate::chain::HeaderTxsTable;
pub use crate::compact::output_flags;
pub use address_head::{is_probe_exhausted_error, is_store_corrupt_display};
pub use block_filter::{BlockFilterRecord, BlockFilterSlot, BlockFilterTable, StoredBlockFilter};
pub use block_queue::{BlockQueue, QueuedBlockMeta, TakenRaw};
pub use block_wire::block_wire_input_count;
pub use coord_io::{
    coord_lock_store_reads, coord_shared_lock_held, header_thread_store_reads, note_store_read,
    CoordSharedLock, HeaderThreadProbe,
};
pub use create_loc::CreateLocPair;
pub use error::StoreError;
pub use file::ensure_nofile_budget;
pub use hashhead::{HeadOpenOpts, HeadScale};
pub use head_resolve_stats::{leftover_probe_diag_ready, leftover_probe_diag_recorded};
pub use header_table::{block_header_hash, HeaderRecord};
pub use height_fence::HeightFence;
pub use idx_body_pipeline::run_idx_body_pipeline;
pub use idx_body_pipeline::{BodyMode as IdxBodyMode, IdxBodyJob, SpendSlotRun};
pub use index_build_uring::{read_index_window, IndexBlock, IndexHeight, IndexWindow};
pub use input::InputEdge;
pub use int_map::{FkMap, FkSet, U32Map, U64IdentityHasher, U64Map, U64Set};
pub use integrity::VERIFY_TIP_BLOCKS;
pub use io_backend::{ReadIoBackend, WriteIoBackend};
pub use point_table::PointRecord;
pub use rbitcoin_primitives::{
    merkle_branch, merkle_root_from_branch, merkle_root_from_txids, merkle_root_mutated,
};
pub use scripthash::{script_hash, ColdProgress, ScriptHashRecord, INCLUDE_HWM_NAME};
pub use scripthash_layout::ShHeadValue;
pub use scripthash_materialize::{
    clear_unsorted_shard_dir, collect_unsorted_shard_files, materialize_sh_unsorted_from_class_a,
    unsorted_collect_workers, unsorted_done_last_fk, unsorted_pack_workers, unsorted_shard_dir,
};
pub use sorted_run::free_gib_label;
pub use sorted_run::host_mem_available_bytes;
pub use sp_tweaks::{SpTweaksTable, TrimLast};
pub use sp_tweaks_uring::{load_tweak_wave, LoadedTweakTx};
pub use spend_annotate_uring::spend_ann_backend;
pub use spend_durable::{
    elapsed_after_checkpoint, spend_sync_due, SPEND_DURABLE_INTERVAL_MS, SPEND_DURABLE_NAME,
};
pub use store::{keep_unspent_vout_subsequence, SpindleHold, Store, StoreLayout};
pub use store_secret::StoreSecret;
pub use tx_table::HeadResizeSizeSnapshot;
pub use tx_table::{
    decode_packed_tx_outs_with_spender_rels, decode_packed_tx_outs_with_spender_rels_secret,
    decode_packed_tx_with_spender_rels_secret, decode_seqsigwit_secret,
    encode_packed_tx_with_secret, encode_seqsigwit_with_secret, encode_txout_meta_and_outs,
    encode_unspent_output_into_secret, encode_wire_seqsigwit_input, seqsigwit_input_len_upper,
    spend_meta_backend, spent_abs, InputParent, InputRecord, OutputRecord, PackedCreate, TxRecord,
};
pub use txstat::TxStatRow;
pub use uring_session::IoCtx;
pub use uring_session::{
    abort_uring_unusable, note_uring_recover, uring_recover_count, uring_slow_drain_count,
};
