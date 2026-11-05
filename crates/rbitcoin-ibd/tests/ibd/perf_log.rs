use rbitcoin_ibd::ibd::confirm::ConfirmPipelineSizes;
use rbitcoin_ibd::ibd::perf_log::*;
use rbitcoin_ibd::ibd::state::WorkStructureSizes;
use rbitcoin_ibd::ibd::status::LoopStats;
use rbitcoin_log::Level;
use rbitcoin_query::ProcessOwnedSizes;
use std::sync::atomic::Ordering;

#[test]
fn ibd_perf_sample_is_one_timestamped_json_debug_line() {
    let s = IbdPerfSample {
        inflight: 7,
        ..Default::default()
    };
    rbitcoin_log::capture_logs(true);
    log_sample(&s);
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let meters: Vec<_> = logs
        .iter()
        .filter(|(_, m)| {
            m.starts_with("ibd: perf")
                || m.starts_with("ibd: sizes")
                || m.starts_with("ibd: perf_dbg")
        })
        .collect();
    assert_eq!(meters.len(), 1, "{logs:?}");
    let (level, msg) = meters[0];
    assert_eq!(*level, Level::Debug, "{msg}");
    let json = msg
        .strip_prefix("ibd: perf ")
        .unwrap_or_else(|| panic!("{msg}"));
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}"));
    let obj = v.as_object().unwrap_or_else(|| panic!("{json}"));
    assert_eq!(obj.get("inflight"), Some(&serde_json::json!(7)));
    assert_eq!(obj.get("peers"), Some(&serde_json::json!(0)));
    assert!(obj.get("ts").and_then(|t| t.as_u64()).is_some(), "{json}");
    for name in SAMPLE_FIELDS.split(',') {
        assert!(obj.contains_key(name), "missing {name}");
    }
    assert_eq!(
        obj.len(),
        SAMPLE_FIELDS.split(',').count() + 1,
        "ts plus every sample field"
    );
    assert!(obj["write"].get("class_a_ms").is_some());
    assert!(obj["work"]["body"].get("known").is_some());
    assert!(obj["owned"]["head"].get("class_a_n").is_some());
    assert!(obj["conf_pipe"].get("load_batches").is_some());
    assert!(obj["live"].is_null());
    let progress = rbitcoin_ibd::ibd::progress::format_progress_line(
        &rbitcoin_ibd::ibd::progress::ProgressLineInput {
            pct: 1,
            tip: 2,
            tip_rate: 0.0,
            tip_hole: 3,
            peers: 4,
            conf_q: "ready=0".to_string(),
            txs: 5,
            horizon: 6,
            eta: "eta=n/a".to_string(),
            bq_bytes: 0,
            bq_count: 0,
            bq_soft_stop: 0,
        },
    );
    assert!(progress.starts_with("ibd: progress "), "{progress}");
    assert!(!progress.contains('{'), "{progress}");
}

const SAMPLE_FIELDS: &str = "inflight,inflight_cap,bq_bytes,bq_count,bq_soft_stop,buf_ahead,hole,peers,headers_done,confirm_ms,confirm_blocks,confirm_reject_stops,confirm_us_per_block,assign_ms,assign_issued,drain_ms,drain_events,status_scan_ms,dominant,live,phase_blks,connect_ms,script_ms,idx_asm_ms,write,ensure_res_hit,ensure_cold_n,pins_take_ms,pins_map_ms,asm_prevout_ms,asm_sigop_ms,asm_final_ms,asm_job_ms,asm_in_n,asm_prev_batch_n,asm_prev_same_n,asm_prev_cold_n,asm_cold_null_fk_n,asm_cold_not_pin_n,asm_cold_txid_mismatch_n,asm_cold_vout_miss_n,strong_ms,structural_spent_ms,spent_abs_ms,spent_strong_ms,spent_cold_ms,spent_pending_ms,structural_create_h_ms,structural_bip68_ms,spend_ranged,ann_ms,ann_n,ann_pread_skip,ann_sync_ms,spend_replay_ms,meta_ms,meta_n,ovl_n,load_ms,prep_wire_arc_ms,prep_struct_ms,prep_header_ms,prep_header_skip_n,prep_prepare_ms,prep_filter_plan_ms,connect_ns,script_ns,milestone_gate_ns,strong_ns,tip_ns,structural_spent_ns,structural_create_h_ns,structural_bip68_ns,load_ns,sh_runs,wf_body_store,wf_store_body_ms,sh_collect_ms,sh_sort_ms,sh_seed_ms,sh_body_ms,sh_head_ms,sh_collect_pin,sh_collect_cold,load_win_ms,load_blocks,load_utxo_parents,load_parent_unique,load_pin_cache_body,load_pin_plan,load_pin_new,load_pin_body_ms,load_plan_pin_ms,load_pin_range_fill_ms,load_pin_recent_outs_ms,load_pin_contract_ms,load_cold_io_ms,load_cold_range_ms,load_cold_range_n,load_cold_range_body_ms,load_cold_range_decode_ms,load_cold_range_extend_n,load_cold_range_body_sqe_n,load_cold_range_guess_full_n,load_body_tx_reads,conf_ready,conf_script_q,conf_write_q,conf_script_q_cap,conf_write_q_cap,conf_script_q_hwm,conf_write_q_hwm,thr_lookup_claim_ms,thr_lookup_stamp_ms,thr_lookup_other_ms,thr_lookup_send_wait_ms,stamp_struct_ms,stamp_struct_txid_ms,stamp_struct_walk_ms,stamp_prepare_ms,stamp_filter_ms,stamp_batch_ms,stamp_batch_assign_ms,stamp_batch_collect_ms,stamp_batch_head_ms,stamp_batch_head_fk_ms,stamp_batch_stamp_ms,stamp_batch_finish_ms,thr_load_recv_wait_ms,thr_load_pack_ms,thr_load_clone_ms,thr_load_stamp_ms,thr_load_pin_ms,thr_load_asm_ms,thr_load_prune_ms,thr_load_reject_ms,thr_load_send_wait_ms,script_jobs,script_skip,thr_script_recv_wait_ms,thr_script_work_ms,thr_script_send_wait_ms,thr_write_recv_wait_ms,thr_write_work_ms,plan_blks,plan_ms,plan_collect_ms,plan_head_ms,plan_cold_io_ms,lookup_decode_ms,lookup_precompute_ms,lookup_wave_head_ms,lookup_wave_head_probe_ms,lookup_wave_head_io_ms,lookup_wave_head_preads,lookup_wave_spent_ms,plan_parents,plan_already,plan_cold,plan_same_batch,load_thin_ms,load_thin_edges_ms,load_thin_fill_ms,load_thin_reject_ms,load_parent_pin_ms,arch_ext_need,arch_head_need,arch_head_hit,leftover_pend,leftover_cdf0_pct,leftover_cdf3_pct,leftover_age_n,arch_pin_txid,arch_pin_txid_ms,arch_recent_n,arch_recent_ms,arch_batch_stamp,arch_resolve_ns,arch_resolve_blocks,arch_prep_assign_ms,arch_prep_collect_ms,arch_prep_inflight_ms,arch_prep_head_ms,arch_prep_head_fk_ms,arch_prep_probe_ms,arch_prep_idx_ms,arch_prep_body_txid_ms,arch_prep_head_keys,arch_prep_head_cands,arch_prep_hit_rank_avg_x100,arch_prep_hit_rank_n,arch_prep_miss_peeks,arch_prep_pending_hits,arch_prep_age_cdf0_pct,arch_prep_age_cdf3_pct,arch_prep_age_cdf7_pct,arch_prep_age_cdf15_pct,arch_prep_age_cdf31_pct,arch_prep_age_hit_compact,arch_prep_age_hit_n,arch_prep_body_lookups,arch_prep_stamp_ms,arch_prep_finish_ms,arch_write_total_ms,arch_write_reserve_ms,arch_write_body_ms,arch_write_head_ms,arch_write_spend_ms,arch_write_htxs_ms,arch_write_txstat_ms,arch_write_flush_ms,arch_write_blocks,rss_kb,rss_anon_kb,rss_file_kb,vm_hwm_kb,rss_locked_kb,work,owned,conf_pipe,uring_recover_n,uring_slow_drain,lookup_faults";

#[test]
fn write_inventory_stage_ms_sums_the_table() {
    let write = WriteStageSample {
        class_a_ms: 1,
        ensure_ms: 2,
        structural_ms: 3,
        class_c_ms: 4,
        sh_ms: 5,
        utxo_ms: 6,
        pins_ms: 8,
        head_sub_ms: 9,
        class_c_join_ms: 10,
        drain_join_ms: 11,
        dequeue_ms: 12,
        idx_put_ms: 13,
        ..Default::default()
    };
    assert_eq!(write.stage_ms(), 84);
    let s = IbdPerfSample {
        write: write.clone(),
        ..Default::default()
    };
    assert_eq!(write_stage_ms(&s), 84);
    let s = IbdPerfSample {
        write,
        load_ms: 30,
        connect_ms: 8,
        ..Default::default()
    };
    assert_eq!(load_stage_wall_ms(&s), 38);
}

#[cfg(target_os = "linux")]
#[test]
fn fill_rss_from_status_and_smaps_edges() {
    let mut r = ProcessRss::default();
    fill_rss_from_status(
        &mut r,
        "Name:\trbitcoin\nVmRSS:\t  1024 kB\nVmHWM:\t  2048 kB\nRssAnon:\t512 kB\nRssFile:\t256 kB\nRssShmem:\t128 kB\n",
    );
    assert_eq!(r.rss_kb, 1024);
    assert_eq!(r.hwm_kb, 2048);
    assert_eq!(r.anon_kb, 512);
    assert_eq!(r.file_kb, 384);

    let mut r = ProcessRss::default();
    fill_rss_from_smaps_rollup(
        &mut r,
        "Rss:\t  800 kB\nAnonymous:\t  300 kB\nRssAnon:\t  1 kB\nRssFile:\t  2 kB\nLocked:\t  16 kB\n",
    );
    assert_eq!(r.rss_kb, 800);
    assert_eq!(r.anon_kb, 300);
    assert_eq!(r.file_kb, 2);
    assert_eq!(r.locked_kb, 16);

    let mut r = ProcessRss::default();
    fill_rss_from_smaps_rollup(&mut r, "Rss:\t  900 kB\nAnonymous:\t  400 kB\n");
    assert_eq!(r.rss_kb, 900);
    assert_eq!(r.anon_kb, 400);
    assert_eq!(r.file_kb, 500);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn read_platform_rss_reports_resident_size() {
    let r = read_platform_rss();
    assert!(r.rss_kb > 0, "expected a resident size, got {r:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn read_platform_rss_splits_anon_and_file_on_linux() {
    let r = read_platform_rss();
    assert!(r.hwm_kb >= r.rss_kb, "hwm should not trail rss, got {r:?}");
    assert!(
        r.anon_kb > 0 || r.file_kb > 0,
        "expected anon/file split from status or smaps_rollup, got {r:?}"
    );
    assert!(r.anon_kb <= r.rss_kb.saturating_add(256), "{r:?}");
    assert!(r.file_kb <= r.rss_kb.saturating_add(256), "{r:?}");
    let sum = r.anon_kb.saturating_add(r.file_kb);
    let skew = sum.abs_diff(r.rss_kb);
    assert!(
        skew <= 1024,
        "anon+file should ≈ rss (±1MiB): sum={sum} skew={skew} {r:?}"
    );
}

#[test]
fn sample_pulls_atomics() {
    let loop_stats = LoopStats::default();
    loop_stats.confirm_ns.store(2_000_000, Ordering::Relaxed);
    loop_stats.confirm_blocks.store(1, Ordering::Relaxed);
    loop_stats.assign_issued.store(7, Ordering::Relaxed);
    let s = sample(
        &loop_stats,
        4,
        256,
        (0, 0, 256),
        100,
        1,
        8,
        true,
        0,
        0,
        0,
        (0, 0),
        1,
        WorkStructureSizes::default(),
        ProcessOwnedSizes::default(),
        ConfirmPipelineSizes::default(),
        read_platform_rss(),
        &rbitcoin_query::ConfirmStats::default(),
    );
    assert_eq!(s.inflight, 4);
    assert_eq!(s.peers, 8);
    assert!(s.headers_done);
    assert_eq!(s.assign_issued, 7);
    assert_eq!(s.confirm_blocks, 1);
    assert_eq!(s.sh_runs, 1);
    assert_eq!(s.conf_ready, 0);
    log_sample(&s);
    let mut slow = s;
    slow.phase_blks = 1;
    slow.write.class_c_ms = 2000;
    slow.write.sh_ms = 2000;
    slow.load_ms = 6000;
    slow.write.class_a_ms = 6000;
    log_sample(&slow);
}

#[test]
fn tip_perf_json_is_timestamped() {
    let line = tip_perf_json(&TipPerfLog {
        rss: ProcessRss {
            rss_kb: 2048,
            anon_kb: 1024,
            file_kb: 512,
            hwm_kb: 3072,
            locked_kb: 0,
        },
        cache_bodies: 3,
        held_bodies: 1,
        mp_live: 4,
        follow_live: 5,
        blocks: 6,
        accepts: 7,
        rejects: 1,
        accept_avg_us: 9,
        accept_max_us: 10,
        accept_lock_us: 11,
        accept_utxo_us: 12,
        accept_script_us: 13,
        accept_durable_us: 14,
        inv_tx: 15,
        getdata_tx: 16,
        announce: 17,
        esplora_n: 18,
        esplora_avg_us: 19,
        esplora_max_us: 20,
        electrum_n: 21,
        electrum_avg_us: 22,
        electrum_max_us: 23,
        serve_n: 24,
        serve_bytes: 25,
        serve_tx: 26,
        serve_avg_us: 27,
        serve_max_us: 28,
        sv2_checks: 29,
        sv2_builds: 2,
        sv2_build_avg_us: 30,
        sv2_build_max_us: 31,
    });
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(v["ts"].as_u64().unwrap() > 0, "{line}");
    assert_eq!(v["rss"]["rss_kb"], 2048);
    assert_eq!(v["accepts"], 7);
    assert_eq!(v["serve_n"], 24);
    assert_eq!(v["blocks"], 6);
    assert_eq!(v["mp_live"], 4);
    assert_eq!(v["sv2_checks"], 29);
    assert_eq!(v["sv2_builds"], 2);
    assert_eq!(v["sv2_build_avg_us"], 30);
    assert_eq!(v["sv2_build_max_us"], 31);
}
