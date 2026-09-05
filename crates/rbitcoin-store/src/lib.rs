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
mod tx_head_mphf;
mod tx_idx;
mod tx_table;
mod txid_body;
mod uring_session;
mod var_table;

pub use crate::compact::output_flags;
pub use address_head::{
    bits_for_scale, entry_bytes_for_bits, is_probe_exhausted_error, layout_for_count,
    load_needs_roll, page_index, probe_depth_stats_snapshot, probe_index, sample_probe_depth_stats,
    AddressHead, HeadLayout, HEAD_LOAD_CEILING, HEAD_LOAD_START, HEAD_LOAD_WARN, MAINNET_BITS,
    MAX_BITS, MAX_PROBE, MIN_BITS, PAGE_SLOTS, PAGE_SLOT_BITS, PROBE_DEPTH_WARN,
    PROBE_REGION_BYTES, TINY_BITS,
};
#[cfg(any(test, debug_assertions))]
pub use block_queue::take_raw_clone_n;
pub use block_queue::{BlockQueue, QueuedBlock, QueuedBlockMeta, TakenRaw};
pub use block_wire::block_wire_input_count;
pub use bulk_io::{bulk_io_workers, io_uring_enabled};
pub use error::StoreError;
pub use file::{ensure_nofile_budget, ensure_nofile_budget_at_least, NOFILE_SOFT_TARGET};
pub use hashhead::{
    initial_slots_for, sh_main_shard_count, HeadRole, HeadScale, SH_MAIN_SHARDS_MAINNET,
};
pub use head_resolve_pick::{classify_leftover_miss, LeftoverMissOn};
pub use head_resolve_stats::{
    leftover_probe_diag_ready, leftover_probe_diag_recorded, Sample as HeadResolveSample,
};
pub use header_table::{block_header_hash, HeaderRecord, HeaderTable};
pub use height_fence::{FenceRun, HeightFence};
pub use idx_body_pipeline::{run_idx_body_pipeline, BodyMode as IdxBodyMode, IdxBodyJob};
pub use int_map::{FkMap, FkSet, U32Map, U64IdentityHasher, U64Map, U64Set};
pub use integrity::{
    merkle_root_from_txids, TipRevalidateReport, TipSeal, TIP_SEAL_NAME, VERIFY_TIP_BLOCKS,
};
pub use io_backend::{read_io_backend, write_io_backend, ReadIoBackend, WriteIoBackend};
pub use io_handle::IoHandle;
pub use point_table::PointRecord;
pub use scripthash::{
    copy_sh_body_range, detect_sh_body_layout, load_include_hwm, remap_copied_page_chain,
    remap_sh_head_value, script_hash, sh_heads_insert_capped, sh_run_catalog_key_len_ok,
    store_include_hwm, ColdProgress, ScriptHashBulkSession, ScriptHashRecord, ScriptHashTable,
    ShBodyLayout, ShShardPack, COLD_PROGRESS_NAME, INCLUDE_HWM_NAME, SH_HEADS_CAP,
    SH_RUN_SORT_KEY_LEN,
};
pub use scripthash_head::{
    prefix_shard_of, sh_per_shard_key_budget, sh_slots_for_keys, sh_unique_hint_default,
    LiveShardTable,
};
pub use scripthash_layout::ShHeadValue;
pub use scripthash_layout::SH_MAX_SLAB_CLASS;
pub use scripthash_materialize::{
    clear_unsorted_shard_dir, collect_unsorted_shard_files, materialize_sh_from_unsorted,
    materialize_sh_unsorted_from_class_a, unsorted_collect_workers, unsorted_done_last_fk,
    unsorted_manifest_ok, unsorted_pack_workers, unsorted_shard_dir, unsorted_shard_path,
    MaterializeStageNs, ShShardMaterialize, UnsortedShardCollect, SH_UNSORTED_PACK_RAM_BYTES,
    UNSORTED_SHARD_DIR,
};
pub use scripthash_slabs::{
    decode_fk_delta_stream, decode_fk_delta_stream_into, decode_slab_payload,
    decode_slab_payload_into, encode_fk_delta_stream, encode_fk_delta_stream_into,
    encode_slab_payload, encode_slab_payload_into, page_alloc_bytes_for_n_fks,
    slab_alloc_bytes_for_n_fks, slab_class_for_n_fks, slab_class_for_n_fks_with_slack,
    slab_class_for_packed_len, SH_MEGAKEY_MIN_FKS,
};
pub use scripthash_sorted_head::{SortedHead, SortedHeadFilter, SH_SORTED_RECS_PER_PAGE};
pub use segmented_head::{
    sample_lookup_stats as sample_head_lookup_stats,
    snapshot_lookup_stats as snapshot_head_lookup_stats, HeadLookupStats, SegmentedTxHead,
    SEGMENT_HEAD_BITS,
};
pub use sorted_run::{
    commit_run_to_catalog, crc32, detach_run, free_gib_label, host_mem_available_bytes,
    list_materialize_claims, list_runs, lookup_key, next_run_path, open_run, read_run_body,
    remove_run, verify_run_body, workers_for_free_ram, write_sorted_run,
    write_sorted_run_file_with_policy, RunWritePolicy, SortedRunPath,
};
pub use sp_tweaks::{SpTweaksTable, TWEAK_LEN};
pub use sp_tweaks_uring::{load_tweak_wave, LoadedTweakTx, TweakWave};
pub use spend_annotate_uring::{spend_ann_backend, SpendAnnBackend};
#[cfg(debug_assertions)]
pub use store::{reset_tx_full_gets, reset_txid_get_many, tx_full_gets, txid_get_many_fks};
pub use store::{Store, StoreLayout, TxidResolveMode, INWIT_RELOC_NAME};
pub use store_secret::{StoreSecret, SECRET_FILE, SECRET_LEN};
pub use tx_table::HeadResizeSizeSnapshot;
pub use tx_table::{
    clear_output_spender_fields, decode_inwit_secret, decode_packed_tx,
    decode_packed_tx_need_outs_with_spender_rels_secret, decode_packed_tx_outs_with_spender_rels,
    decode_packed_tx_outs_with_spender_rels_secret, decode_packed_tx_with_spender_rels,
    decode_packed_tx_with_spender_rels_secret, encode_inwit_with_secret, encode_packed_tx,
    encode_packed_tx_with_secret, encode_spent_zeros, is_packed_tx_payload, next_tx_body_start,
    scan_inwit_prevouts, scan_packed_meta_and_prevouts, spend_meta_backend, spent_abs, InputRecord,
    OutputRecord, SpendMetaBackend, TxRecord, BODY_PAGE_SIZE, SCRIPT_HASH_COLLECT_SPAN,
    TXID_PAGE_MAX_OFF,
};
pub use txid_body::{TxidBody, TXID_BODY_HEADER, TXID_ENTRY_LEN};
pub use uring_session::{
    with_forced_session_kind, with_thread_local, IoCtx, SessionKind, UringSession, DEFAULT_ENTRIES,
};
