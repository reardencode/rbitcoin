//! Pin the crate-root names other crates actually import (X-04 keep list).
//! This test only asserts those names still resolve. Dropped names
//! (`AddressHead`, `NetConfig`, `P2PHandle`, `LiveShardTable`, …) are
//! denied by `lint/ast-grep/rules/crate-root-dropped-pub.yml`.

use rbitcoin_store::{
    block_header_hash, block_wire_input_count, clear_unsorted_shard_dir,
    collect_unsorted_shard_files, decode_inwit_secret, decode_packed_tx_outs_with_spender_rels,
    decode_packed_tx_outs_with_spender_rels_secret, decode_packed_tx_with_spender_rels_secret,
    encode_packed_tx, encode_packed_tx_with_secret, ensure_nofile_budget, free_gib_label,
    is_probe_exhausted_error, is_store_corrupt_display, leftover_probe_diag_ready,
    leftover_probe_diag_recorded, list_materialize_claims, list_runs, load_tweak_wave,
    materialize_sh_unsorted_from_class_a, merkle_root_from_txids, next_run_path, output_flags,
    script_hash, sh_heads_insert_capped, spend_ann_backend, spend_meta_backend, spent_abs,
    unsorted_collect_workers, unsorted_done_last_fk, unsorted_pack_workers, unsorted_shard_dir,
    write_sorted_run, BlockQueue, ColdProgress, FkMap, FkSet, HeadOpenOpts, HeadResizeSizeSnapshot,
    HeadScale, HeaderRecord, HeightFence, IdxBodyJob, IdxBodyMode, InputRecord, OutputRecord,
    PointRecord, QueuedBlockMeta, ReadIoBackend, ScriptHashRecord, ShHeadValue, SpTweaksTable,
    Store, StoreError, StoreLayout, StoreSecret, TakenRaw, TxRecord, U32Map, U64IdentityHasher,
    U64Map, U64Set, WriteIoBackend, INCLUDE_HWM_NAME, SH_HEADS_CAP,
};

#[test]
fn crate_root_exports_cross_crate_names() {
    let _ = std::any::type_name::<Store>();
    let _ = std::any::type_name::<StoreError>();
    let _ = std::any::type_name::<StoreLayout>();
    let _ = std::any::type_name::<HeadScale>();
    let _ = std::any::type_name::<HeadOpenOpts>();
    let _ = std::any::type_name::<StoreSecret>();
    let _ = std::any::type_name::<BlockQueue>();
    let _ = std::any::type_name::<QueuedBlockMeta>();
    let _ = std::any::type_name::<TakenRaw>();
    let _ = std::any::type_name::<HeaderRecord>();
    let _ = std::any::type_name::<HeightFence>();
    let _ = std::any::type_name::<FkMap<()>>();
    let _ = std::any::type_name::<FkSet>();
    let _ = std::any::type_name::<U32Map<()>>();
    let _ = std::any::type_name::<U64Map<()>>();
    let _ = std::any::type_name::<U64Set>();
    let _ = std::any::type_name::<U64IdentityHasher>();
    let _ = std::any::type_name::<PointRecord>();
    let _ = std::any::type_name::<ScriptHashRecord>();
    let _ = std::any::type_name::<ShHeadValue>();
    let _ = std::any::type_name::<ColdProgress>();
    let _ = std::any::type_name::<IdxBodyMode>();
    let _ = std::any::type_name::<IdxBodyJob>();
    let _ = std::any::type_name::<InputRecord>();
    let _ = std::any::type_name::<OutputRecord>();
    let _ = std::any::type_name::<TxRecord>();
    let _ = std::any::type_name::<SpTweaksTable>();
    let _ = std::any::type_name::<ReadIoBackend>();
    let _ = std::any::type_name::<WriteIoBackend>();
    let _ = std::any::type_name::<HeadResizeSizeSnapshot>();
    let _ = INCLUDE_HWM_NAME;
    let _ = SH_HEADS_CAP;
    let _ = block_header_hash;
    let _ = block_wire_input_count;
    let _ = ensure_nofile_budget;
    let _ = leftover_probe_diag_ready;
    let _ = leftover_probe_diag_recorded;
    let _ = load_tweak_wave;
    let _ = merkle_root_from_txids;
    let _ = next_run_path;
    let _ = script_hash;
    let _ = sh_heads_insert_capped;
    let _ = spend_ann_backend;
    let _ = spend_meta_backend;
    let _ = spent_abs;
    let _ = write_sorted_run;
    let _ = clear_unsorted_shard_dir;
    let _ = collect_unsorted_shard_files;
    let _ = decode_inwit_secret;
    let _ = decode_packed_tx_outs_with_spender_rels;
    let _ = decode_packed_tx_outs_with_spender_rels_secret;
    let _ = decode_packed_tx_with_spender_rels_secret;
    let _ = encode_packed_tx;
    let _ = encode_packed_tx_with_secret;
    let _ = free_gib_label;
    let _ = is_probe_exhausted_error;
    let _ = is_store_corrupt_display;
    let _ = list_materialize_claims;
    let _ = list_runs;
    let _ = materialize_sh_unsorted_from_class_a;
    let _ = output_flags::MULTI_SPENDER;
    let _ = unsorted_collect_workers;
    let _ = unsorted_done_last_fk;
    let _ = unsorted_pack_workers;
    let _ = unsorted_shard_dir;
}
