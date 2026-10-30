//! Consolidated IBD performance sampling and logging.
//!
//! **Cadence:** one centralized ~5s status tick (see `ibd` main loop) emits
//! `ibd: progress` and one `ibd: perf` JSON line together. Housekeeping that
//! is not confirm progress (assign, peer-slow, hygiene, header locator poll)
//! is wall-clock gated in that same loop — not run on every peer frame.
//!
//! | Level | Message | Contents |
//! |-------|---------|----------|
//! | INFO  | `ibd: progress …` | Tip rate over the **last 5s**, `hole=` fetch gap tip→next claim-ready body, loadq=/scriptq/writeq, txs=, horizon, tip ETA, body `bq soft=n/stop RAM=` |
//! | DEBUG | `ibd: perf {json}` | One timestamped JSON object of [`IbdPerfSample`] (zeros included). `ts` is unix milliseconds. |
//!
//! **Pins:** pipeline-local (plan batch_pin / BatchParents).
//!
//! Sample **once** per tick and reset all atomics, then log `ibd: progress`
//! at INFO and one `ibd: perf` JSON object at DEBUG from the same sample.
//!
//! Unified path: peer → **body queue** → confirm **lookup** (stamp) → **load**
//! (pin+assemble) → **scripts** → **write** (sole Class A append + Class C / spends / tip).
//!
//! Stage walls (window sums; stages overlap on OS threads):
//! - **lookup** = lookup-thread TipOnly wave (`plan_ms` / `lookup_thr wave=`
//!   with nested `decode=` / `precompute=` / `collect=` /
//!   `head=(probe= io= preads=)` / `loc=`)
//! - **load=** = pin (`LOAD_NS`) + assemble (`CONNECT_NS`) only — **not** the
//!   load OS-thread wall. Load thread also does pack decode, leftover stamp
//!   (plan=None / S0 only), clone, post-stamp prune on a marked last load
//!   batch, and a stamp or pin reject's rewind of the wave
//!   (`load_thr pack/stamp/pin/asm/prune`). `reject=` is a lone block's
//!   missing-parent check after a stamp miss: the wait for its parent to be
//!   the tip with `tx.head` holding every connected create, one TipOnly
//!   read, and on a miss a `txid.body` scan of every unsealed `tx.head`
//!   segment that stops with confirm. It can hold the load thread for
//!   seconds, so it stays out of `prune=`.
//! - **script=** = `SCRIPT_NS` (publish → script-verify complete per batch on
//!   `ibd-confirm`; excludes head-of-line wait for write handoff).
//!   `idx_asm=` is filter and tweak execution only: first index job through
//!   index-wave completion, not time queued behind the script wave, and not
//!   inside `script=`. `thr script work` is the stage wall, the later of the
//!   two completion offsets from batch start. It is not `script=` plus
//!   `idx_asm=`. Recv/send are wait. The next batch is published when both
//!   waves have nothing left to claim. The publisher does not `wait_done`
//!   until both waves have finished executing.
//! - **write** = Class A + ensure + structural + class_c + spend
//!   + `pins=` / `head_sub=` / `drain_join=` / `dequeue=` / `idx_put=`.
//!     `other=` is write-thread work minus that inventory.
//!
//! **Inventory:** write-stage names live on [`WriteStageSample`]. A new counter
//! is a field on [`IbdPerfSample`]; JSON includes it because the struct
//! serializes. Same-commit rule: `docs/concurrency.md`.
//! `write=` must equal `write_stage_ms`.
//!
//! **Long-pole diagnosis:** do **not** rank stages by work-sum alone when
//! `scriptq` can stay empty. Prefer `lookup_thr busy=` / `thr load=busy/wait=` /
//! `ready=` + `scriptq_hwm=` (OS-thread occupancy + queue high-water). High
//! `load_thr stamp=` nests `pack=` (plan HashMap) vs `head=` (leftover TipOnly
//! `prep_head_fk_ns`). IBD skeleton path keeps `head=` ~0. High `head=` +
//! `ready>0` + `scriptq=1` ⇒ leftover TipOnly on load, not “scripts hungry.”
//! High load_recv_wait + ready=0 ⇒ lookup is the pole.
//!
use super::confirm::ConfirmPipelineSizes;
use super::state::WorkStructureSizes;
use super::status::LoopStats;
use rbitcoin_log::debug;
use rbitcoin_query::ProcessOwnedSizes;

/// Write-stage tokens that must sum to `write=` / [`write_stage_ms`].
///
/// Exclusive names live in [`WriteStageSample::INVENTORY`]; `format_info` /
/// `format_debug` emit from that table. Nested mix (ensure pin/cold, struct
/// spent/create_h/bip68, pins take/map, spend `r=`) is not exclusive.
/// `other=` is write-thread work minus this inventory.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct WriteStageSample {
    /// `archive_commit_plan`
    pub class_a_ms: u64,
    pub class_a_ns: u64,
    /// fill planned layout + ensure spend abs
    pub ensure_ms: u64,
    pub ensure_ns: u64,
    /// spentness / create-height / BIP68
    pub structural_ms: u64,
    pub structural_ns: u64,
    /// strong + tip tables (`flush_class_c_tip`)
    pub class_c_ms: u64,
    pub class_c_ns: u64,
    /// SH filter+collect (parallel with strong)
    pub sh_ms: u64,
    pub sh_ns: u64,
    /// spend annotate (`spend=`)
    pub utxo_ms: u64,
    pub utxo_apply_ns: u64,
    /// Write-thread pin Arc copies: plan take + create-pin FkMap (`pins=`)
    pub pins_ms: u64,
    pub pins_ns: u64,
    /// `take_pending_queued` + `submit_head_insert` (`head_sub=`)
    pub head_sub_ms: u64,
    pub head_sub_ns: u64,
    /// `class_c_commit` join/flush minus tables (`class_c_join=`)
    pub class_c_join_ms: u64,
    pub class_c_join_ns: u64,
    /// Commit wait for the previous batch's background tip flush (`tip_flush_wait=`)
    pub tip_flush_wait_ms: u64,
    pub tip_flush_wait_ns: u64,
    /// Residual `head_insert_queued` join after Class C (`drain_join=`).
    /// Includes seal-sidecar collect of `txid.body` keys plus fuse/MPHF build.
    pub drain_join_ms: u64,
    pub drain_join_ns: u64,
    /// Body-queue dequeue after confirm (`dequeue=`)
    pub dequeue_ms: u64,
    pub dequeue_ns: u64,
    /// Live filter and tweak put (`idx_put=`)
    pub idx_put_ms: u64,
    pub idx_put_ns: u64,
}

#[doc(hidden)]
pub type WriteInvTok = (
    &'static str,
    fn(&WriteStageSample) -> u64,
    fn(&WriteStageSample) -> u64,
);

impl WriteStageSample {
    /// Sum of the exclusive write inventory tokens (ms).
    pub fn stage_ms(&self) -> u64 {
        Self::INVENTORY
            .iter()
            .fold(0, |acc, (_, ms, _)| acc.saturating_add(ms(self)))
    }

    /// Exclusive write inventory: one row per token (`write=` = this sum).
    /// `format_info` / `format_debug` emit `{name}` from this table.
    #[doc(hidden)]
    pub const INVENTORY: &'static [WriteInvTok] = &[
        ("class_a", |s| s.class_a_ms, |s| s.class_a_ns),
        ("ensure", |s| s.ensure_ms, |s| s.ensure_ns),
        ("struct", |s| s.structural_ms, |s| s.structural_ns),
        ("class_c", |s| s.class_c_ms, |s| s.class_c_ns),
        ("sh", |s| s.sh_ms, |s| s.sh_ns),
        ("spend", |s| s.utxo_ms, |s| s.utxo_apply_ns),
        ("pins", |s| s.pins_ms, |s| s.pins_ns),
        ("head_sub", |s| s.head_sub_ms, |s| s.head_sub_ns),
        ("class_c_join", |s| s.class_c_join_ms, |s| s.class_c_join_ns),
        (
            "tip_flush_wait",
            |s| s.tip_flush_wait_ms,
            |s| s.tip_flush_wait_ns,
        ),
        ("drain_join", |s| s.drain_join_ms, |s| s.drain_join_ns),
        ("dequeue", |s| s.dequeue_ms, |s| s.dequeue_ns),
        ("idx_put", |s| s.idx_put_ms, |s| s.idx_put_ns),
    ];
}

/// One 5s window of IBD counters (post sample-and-reset).
///
/// Serialized as one `ibd: perf` JSON object. Every field is a key, including
/// zeros. `owned` is the only field whose type lives outside this crate.
#[derive(Clone, Debug, serde::Serialize)]
pub struct IbdPerfSample {
    pub inflight: usize,
    pub inflight_cap: usize,
    /// In-RAM block queue used bytes / count (process heap wire payloads).
    pub bq_bytes: u64,
    pub bq_count: usize,
    /// Soft densify confirm-window target (block count ≈ 1 min tip rate).
    pub bq_soft_stop: u32,
    /// Claim-ready HWM (+ inflight) ahead of tip — densify headroom (not a progress lead token).
    pub buf_ahead: u32,
    pub hole: usize,
    pub peers: usize,
    pub headers_done: bool,

    pub confirm_ms: u64,
    pub confirm_blocks: u64,
    pub confirm_reject_stops: u64,
    pub confirm_us_per_block: u64,
    pub assign_ms: u64,
    pub assign_issued: u64,
    pub drain_ms: u64,
    pub drain_events: u64,
    pub status_scan_ms: u64,
    pub dominant: &'static str,
    /// `(first, batch_n, batch_inputs, elapsed_ms)` if confirm mid-batch.
    pub live: Option<(u32, u32, u32, u64)>,

    pub phase_blks: u64,
    pub connect_ms: u64,
    pub script_ms: u64,
    /// Filter and tweak assemble on the scripts stage (`idx_asm=`).
    pub idx_asm_ms: u64,
    /// Write-stage exclusive tokens (`write=` = [`WriteStageSample::stage_ms`]).
    pub write: WriteStageSample,
    /// Ensure mix: residency/pin hits vs cold denserels body loads.
    pub ensure_res_hit: u64,
    pub ensure_cold_n: u64,
    /// `pins=` part: planned_fks clone + pin Arc vec before Class A.
    pub pins_take_ms: u64,
    /// `pins=` part: write_create_pins FkMap insert after Class A.
    pub pins_map_ms: u64,
    /// Assemble subtimers (ms; sum ≈ connect/assemble).
    pub asm_prevout_ms: u64,
    pub asm_sigop_ms: u64,
    pub asm_final_ms: u64,
    pub asm_job_ms: u64,
    /// Non-coinbase inputs resolved (us/in = prevout_ns / max(1, asm_in_n)).
    pub asm_in_n: u64,
    /// Prevout path: batch pin hit count.
    pub asm_prev_batch_n: u64,
    /// Prevout path: same-block count.
    pub asm_prev_same_n: u64,
    /// Prevout path: cold Class A count.
    pub asm_prev_cold_n: u64,
    /// N1: cold success reasons (sum ≈ asm_prev_cold_n).
    pub asm_cold_null_fk_n: u64,
    pub asm_cold_not_pin_n: u64,
    pub asm_cold_txid_mismatch_n: u64,
    pub asm_cold_vout_miss_n: u64,
    pub strong_ms: u64,
    /// Structural sub: durable spentness probes.
    pub structural_spent_ms: u64,
    /// Spent sub: pin abs + on-disk 8-byte meta pread.
    pub spent_abs_ms: u64,
    /// Spent sub: is_confirmed_strong_at on non-null fields.
    pub spent_strong_ms: u64,
    /// Spent sub: cold unspent / null-create path.
    pub spent_cold_ms: u64,
    /// Spent sub: pending_spent order gate.
    pub spent_pending_ms: u64,
    /// Structural sub: create-height + coinbase maturity.
    pub structural_create_h_ms: u64,
    /// Structural sub: BIP68 + coin MTP.
    pub structural_bip68_ms: u64,
    pub spend_ranged: u64,
    /// Pure-write annotate wall ms / edge count.
    pub ann_ms: u64,
    pub ann_n: u64,
    /// Annotate edges without body pread (should equal annotate edges).
    pub ann_pread_skip: u64,
    /// Periodic Class A `sync_data` that advances the spend-durable marker.
    pub ann_sync_ms: u64,
    /// Pending spend annotate a failed write left, replayed before the next
    /// write. Nested in `spend=`, not an exclusive write token.
    pub spend_replay_ms: u64,
    /// Structural meta bulk read wall ms / peek count.
    pub meta_ms: u64,
    pub meta_n: u64,
    /// Same-batch overlay slots that skipped the structural meta pread.
    pub ovl_n: u64,
    pub load_ms: u64,
    /// Wire load residual (inside load/pre_asm, outside pin): Arc clone.
    pub prep_wire_arc_ms: u64,
    /// Structure validate.
    pub prep_struct_ms: u64,
    /// Header validate/put + cache seed.
    pub prep_header_ms: u64,
    /// IBD stamp used BQ `header_fk` (skipped POW / header-table ensure).
    pub prep_header_skip_n: u64,
    /// prepare_block_for_archive.
    pub prep_prepare_ms: u64,
    /// filter need + plan batch + tx_fks wiring.
    pub prep_filter_plan_ms: u64,
    pub connect_ns: u64,
    pub script_ns: u64,
    /// Ancestor + min-work milestone gate (lookup / assemble).
    pub milestone_gate_ns: u64,
    pub strong_ns: u64,
    pub tip_ns: u64,
    pub structural_spent_ns: u64,
    pub structural_create_h_ns: u64,
    pub structural_bip68_ns: u64,
    pub load_ns: u64,

    pub sh_runs: usize,

    /// Wire rebuild: store body decode count + wall ms.
    pub wf_body_store: u64,
    pub wf_store_body_ms: u64,

    pub sh_collect_ms: u64,
    pub sh_sort_ms: u64,
    pub sh_seed_ms: u64,
    pub sh_body_ms: u64,
    pub sh_head_ms: u64,
    /// SH collect create sources: write-pin / residency / cold Class A body.
    pub sh_collect_pin: u64,
    pub sh_collect_cold: u64,

    pub load_win_ms: u64,
    pub load_blocks: u64,
    pub load_utxo_parents: u64,
    pub load_parent_unique: u64,
    pub load_pin_cache_body: u64,
    /// Pin hits from pipeline pins (subset of pin_cache when residency filled).
    /// Wire plan / in-flight parent pins (not denserels hits).
    pub load_pin_plan: u64,
    pub load_pin_new: u64,
    pub prefetch_bytes: u64,
    pub prefetch_ns: u64,
    pub load_pin_body_ms: u64,
    pub load_plan_pin_ms: u64,
    /// Pin residual sub-walls (recent-outs / range-fill insert / contract).
    pub load_pin_range_fill_ms: u64,
    pub load_pin_recent_outs_ms: u64,
    pub load_pin_contract_ms: u64,
    pub load_cold_io_ms: u64,
    /// Cold denserels by plan body range (ms / create count).
    pub load_cold_range_ms: u64,
    pub load_cold_range_n: u64,
    /// N2.0: body pread vs sparse denserels decode (ms; sum ≈ cold_range).
    pub load_cold_range_body_ms: u64,
    pub load_cold_range_decode_ms: u64,
    /// Outs second-wave remainder extends (jobs whose need missed the first peek).
    pub load_cold_range_extend_n: u64,
    /// Body pread SQEs after page grouping (first wave + extend).
    pub load_cold_range_body_sqe_n: u64,
    /// First-wave Outs jobs that pread the full idx span (spill guess).
    pub load_cold_range_guess_full_n: u64,
    pub load_body_tx_reads: u64,
    pub conf_ready: usize,
    pub conf_script_q: usize,
    pub conf_write_q: usize,
    pub conf_script_q_cap: usize,
    pub conf_write_q_cap: usize,
    /// Max scriptq depth since last 5s sample.
    pub conf_script_q_hwm: usize,
    pub conf_write_q_hwm: usize,
    pub thr_lookup_claim_ms: u64,
    pub thr_lookup_stamp_ms: u64,
    pub thr_lookup_other_ms: u64,
    pub thr_lookup_send_wait_ms: u64,
    /// Stamp sub-walls (structure / prepare / filter / plan_batch).
    pub stamp_struct_ms: u64,
    /// Split of structure: one-pass txid/wtxid encode vs remaining walks.
    pub stamp_struct_txid_ms: u64,
    pub stamp_struct_walk_ms: u64,
    pub stamp_prepare_ms: u64,
    pub stamp_filter_ms: u64,
    pub stamp_batch_ms: u64,
    /// plan_batch internals (from ConfirmWindow archive prep).
    pub stamp_batch_assign_ms: u64,
    pub stamp_batch_collect_ms: u64,
    /// head_fk + head_dens (legacy total).
    pub stamp_batch_head_ms: u64,
    /// Pure get_fk_by_txid_batch wall.
    pub stamp_batch_head_fk_ms: u64,
    pub stamp_batch_stamp_ms: u64,
    pub stamp_batch_finish_ms: u64,
    pub thr_load_recv_wait_ms: u64,
    pub thr_load_pack_ms: u64,
    pub thr_load_clone_ms: u64,
    pub thr_load_stamp_ms: u64,
    pub thr_load_pin_ms: u64,
    pub thr_load_asm_ms: u64,
    pub thr_load_prune_ms: u64,
    /// A lone block's missing-parent check after its load stamp missed.
    pub thr_load_reject_ms: u64,
    pub thr_load_send_wait_ms: u64,
    pub script_jobs: u64,
    pub script_skip: u64,
    pub thr_script_recv_wait_ms: u64,
    pub thr_script_work_ms: u64,
    pub thr_script_send_wait_ms: u64,
    pub thr_write_recv_wait_ms: u64,
    pub thr_write_work_ms: u64,
    pub plan_blks: u64,
    pub plan_ms: u64,
    pub plan_collect_ms: u64,
    pub plan_head_ms: u64,
    pub plan_cold_io_ms: u64,
    /// Lookup-wave `consensus_decode` (`decode=`).
    pub lookup_decode_ms: u64,
    /// Lookup-wave `from_tx_wire` on payload slices (`precompute=`).
    pub lookup_precompute_ms: u64,
    /// Lookup-wave TipOnly `get_fk_by_txid_batch_cancellable` (`wave=… head=`). Not load stamp.
    pub lookup_wave_head_ms: u64,
    /// TipOnly CPU (slot/fuse probe + fence snapshot) inside `head=`.
    pub lookup_wave_head_probe_ms: u64,
    /// TipOnly body+idx pread wall inside `head=`.
    pub lookup_wave_head_io_ms: u64,
    /// TipOnly `txid.body` / identity preads this window.
    pub lookup_wave_head_preads: u64,
    /// Lookup-wave `create.loc` fill inside TipOnly `head=` (`wave=… loc=`).
    /// One batch after the sealed walk; not on the probe ring.
    pub lookup_wave_spent_ms: u64,
    pub plan_parents: u64,
    pub plan_already: u64,
    pub plan_cold: u64,
    pub plan_same_batch: u64,
    pub load_thin_ms: u64,
    pub load_parent_pin_ms: u64,

    pub arch_ext_need: u64,
    pub arch_head_need: u64,
    pub arch_head_hit: u64,
    pub leftover_pend: u64,
    pub leftover_cdf0_pct: u64,
    pub leftover_cdf3_pct: u64,
    pub leftover_age_n: u64,
    /// Unique prev_txids resolved from live pipeline pins (not in-flight).
    pub arch_pin_txid: u64,
    pub arch_pin_txid_ms: u64,
    /// Write-published recent-create identity hits (after published, before leftover).
    pub arch_recent_n: u64,
    pub arch_recent_ms: u64,
    pub arch_batch_stamp: u64,
    pub arch_resolve_ns: u64,
    pub arch_resolve_blocks: u64,
    pub arch_prep_assign_ms: u64,
    pub arch_prep_collect_ms: u64,
    pub arch_prep_inflight_ms: u64,
    pub arch_prep_head_ms: u64,
    pub arch_prep_head_fk_ms: u64,
    pub arch_prep_probe_ms: u64,
    pub arch_prep_idx_ms: u64,
    pub arch_prep_body_txid_ms: u64,
    pub arch_prep_head_keys: u64,
    pub arch_prep_head_cands: u64,
    /// Mean winning cand rank (1 = first probe body peek).
    pub arch_prep_hit_rank_avg_x100: u64,
    pub arch_prep_hit_rank_n: u64,
    pub arch_prep_miss_peeks: u64,
    /// Write-behind pending txid→fk hits.
    pub arch_prep_pending_hits: u64,
    /// Winner sealed-age CDF % (0/3/7/15/31); `cdf3` ≈ wave1 hit % under ages≤3 policy.
    pub arch_prep_age_cdf0_pct: u64,
    pub arch_prep_age_cdf3_pct: u64,
    pub arch_prep_age_cdf7_pct: u64,
    pub arch_prep_age_cdf15_pct: u64,
    pub arch_prep_age_cdf31_pct: u64,
    /// Winner age hist compact `h0:h1:…:h7+tail`.
    pub arch_prep_age_hit_compact: String,
    pub arch_prep_age_hit_n: u64,
    pub arch_prep_body_lookups: u64,
    pub arch_prep_stamp_ms: u64,
    pub arch_prep_finish_ms: u64,
    pub arch_write_total_ms: u64,
    pub arch_write_reserve_ms: u64,
    pub arch_write_body_ms: u64,
    pub arch_write_head_ms: u64,
    pub arch_write_spend_ms: u64,
    pub arch_write_htxs_ms: u64,
    pub arch_write_txstat_ms: u64,
    pub arch_write_flush_ms: u64,
    pub arch_write_blocks: u64,

    /// Process RSS / smaps (kB); 0 when `/proc` unavailable.
    pub rss_kb: u64,
    pub rss_anon_kb: u64,
    pub rss_file_kb: u64,
    pub vm_hwm_kb: u64,
    /// `mlock`ed pages only (usually 0); RSS is **not** limited to these.
    pub rss_locked_kb: u64,
    /// Work-path + body presence occupancy (O(1) lens).
    pub work: WorkStructureSizes,
    /// Query-side process-owned caches (residency + header plans + SH + tx.head).
    #[serde(serialize_with = "ser_process_owned")]
    pub owned: ProcessOwnedSizes,
    /// Confirm load/scripts/write queue contents + feed.
    pub conf_pipe: ConfirmPipelineSizes,
    pub uring_recover_n: u64,
    pub uring_slow_drain: u64,
    pub lookup_faults: u64,
}

impl Default for IbdPerfSample {
    fn default() -> Self {
        Self {
            inflight: 0,
            inflight_cap: 0,
            bq_bytes: 0,
            bq_count: 0,
            bq_soft_stop: 0,
            buf_ahead: 0,
            hole: 0,
            peers: 0,
            headers_done: false,
            confirm_ms: 0,
            confirm_blocks: 0,
            confirm_reject_stops: 0,
            confirm_us_per_block: 0,
            assign_ms: 0,
            assign_issued: 0,
            drain_ms: 0,
            drain_events: 0,
            status_scan_ms: 0,
            dominant: "idle",
            live: None,
            phase_blks: 0,
            connect_ms: 0,
            script_ms: 0,
            idx_asm_ms: 0,
            write: WriteStageSample::default(),
            ensure_res_hit: 0,
            ensure_cold_n: 0,
            pins_take_ms: 0,
            pins_map_ms: 0,
            asm_prevout_ms: 0,
            asm_sigop_ms: 0,
            asm_final_ms: 0,
            asm_job_ms: 0,
            asm_in_n: 0,
            asm_prev_batch_n: 0,
            asm_prev_same_n: 0,
            asm_prev_cold_n: 0,
            asm_cold_null_fk_n: 0,
            asm_cold_not_pin_n: 0,
            asm_cold_txid_mismatch_n: 0,
            asm_cold_vout_miss_n: 0,
            strong_ms: 0,
            structural_spent_ms: 0,
            spent_abs_ms: 0,
            spent_strong_ms: 0,
            spent_cold_ms: 0,
            spent_pending_ms: 0,
            structural_create_h_ms: 0,
            structural_bip68_ms: 0,
            spend_ranged: 0,
            ann_ms: 0,
            ann_n: 0,
            ann_pread_skip: 0,
            ann_sync_ms: 0,
            spend_replay_ms: 0,
            meta_ms: 0,
            meta_n: 0,
            ovl_n: 0,
            load_ms: 0,
            prep_wire_arc_ms: 0,
            prep_struct_ms: 0,
            prep_header_ms: 0,
            prep_header_skip_n: 0,
            prep_prepare_ms: 0,
            prep_filter_plan_ms: 0,
            connect_ns: 0,
            script_ns: 0,
            milestone_gate_ns: 0,
            strong_ns: 0,
            tip_ns: 0,
            structural_spent_ns: 0,
            structural_create_h_ns: 0,
            structural_bip68_ns: 0,
            load_ns: 0,
            sh_runs: 0,
            wf_body_store: 0,
            wf_store_body_ms: 0,
            sh_collect_ms: 0,
            sh_sort_ms: 0,
            sh_seed_ms: 0,
            sh_body_ms: 0,
            sh_head_ms: 0,
            sh_collect_pin: 0,
            sh_collect_cold: 0,
            load_win_ms: 0,
            load_blocks: 0,
            load_utxo_parents: 0,
            load_parent_unique: 0,
            load_pin_cache_body: 0,
            load_pin_plan: 0,
            load_pin_new: 0,
            prefetch_bytes: 0,
            prefetch_ns: 0,
            load_pin_body_ms: 0,
            load_plan_pin_ms: 0,
            load_pin_range_fill_ms: 0,
            load_pin_recent_outs_ms: 0,
            load_pin_contract_ms: 0,
            load_cold_io_ms: 0,
            load_cold_range_ms: 0,
            load_cold_range_n: 0,
            load_cold_range_body_ms: 0,
            load_cold_range_decode_ms: 0,
            load_cold_range_extend_n: 0,
            load_cold_range_body_sqe_n: 0,
            load_cold_range_guess_full_n: 0,
            load_body_tx_reads: 0,
            conf_ready: 0,
            conf_script_q: 0,
            conf_write_q: 0,
            conf_script_q_cap: super::confirm::script_queue_cap(),
            conf_write_q_cap: super::confirm::write_queue_cap(),
            conf_script_q_hwm: 0,
            conf_write_q_hwm: 0,
            thr_lookup_claim_ms: 0,
            thr_lookup_stamp_ms: 0,
            thr_lookup_other_ms: 0,
            thr_lookup_send_wait_ms: 0,
            stamp_struct_ms: 0,
            stamp_struct_txid_ms: 0,
            stamp_struct_walk_ms: 0,
            stamp_prepare_ms: 0,
            stamp_filter_ms: 0,
            stamp_batch_ms: 0,
            stamp_batch_assign_ms: 0,
            stamp_batch_collect_ms: 0,
            stamp_batch_head_ms: 0,
            stamp_batch_head_fk_ms: 0,
            stamp_batch_stamp_ms: 0,
            stamp_batch_finish_ms: 0,
            thr_load_recv_wait_ms: 0,
            thr_load_pack_ms: 0,
            thr_load_clone_ms: 0,
            thr_load_stamp_ms: 0,
            thr_load_pin_ms: 0,
            thr_load_asm_ms: 0,
            thr_load_prune_ms: 0,
            thr_load_reject_ms: 0,
            thr_load_send_wait_ms: 0,
            script_jobs: 0,
            script_skip: 0,
            thr_script_recv_wait_ms: 0,
            thr_script_work_ms: 0,
            thr_script_send_wait_ms: 0,
            thr_write_recv_wait_ms: 0,
            thr_write_work_ms: 0,
            plan_blks: 0,
            plan_ms: 0,
            plan_collect_ms: 0,
            plan_head_ms: 0,
            plan_cold_io_ms: 0,
            lookup_decode_ms: 0,
            lookup_precompute_ms: 0,
            lookup_wave_head_ms: 0,
            lookup_wave_head_probe_ms: 0,
            lookup_wave_head_io_ms: 0,
            lookup_wave_head_preads: 0,
            lookup_wave_spent_ms: 0,
            plan_parents: 0,
            plan_already: 0,
            plan_cold: 0,
            plan_same_batch: 0,
            load_thin_ms: 0,
            load_parent_pin_ms: 0,
            arch_ext_need: 0,
            arch_head_need: 0,
            arch_head_hit: 0,
            leftover_pend: 0,
            leftover_cdf0_pct: 0,
            leftover_cdf3_pct: 0,
            leftover_age_n: 0,
            arch_pin_txid: 0,
            arch_pin_txid_ms: 0,
            arch_recent_n: 0,
            arch_recent_ms: 0,
            arch_batch_stamp: 0,
            arch_resolve_ns: 0,
            arch_resolve_blocks: 0,
            arch_prep_assign_ms: 0,
            arch_prep_collect_ms: 0,
            arch_prep_inflight_ms: 0,
            arch_prep_head_ms: 0,
            arch_prep_head_fk_ms: 0,
            arch_prep_probe_ms: 0,
            arch_prep_idx_ms: 0,
            arch_prep_body_txid_ms: 0,
            arch_prep_head_keys: 0,
            arch_prep_head_cands: 0,
            arch_prep_hit_rank_avg_x100: 0,
            arch_prep_hit_rank_n: 0,
            arch_prep_miss_peeks: 0,
            arch_prep_pending_hits: 0,
            arch_prep_age_cdf0_pct: 0,
            arch_prep_age_cdf3_pct: 0,
            arch_prep_age_cdf7_pct: 0,
            arch_prep_age_cdf15_pct: 0,
            arch_prep_age_cdf31_pct: 0,
            arch_prep_age_hit_compact: String::new(),
            arch_prep_age_hit_n: 0,
            arch_prep_body_lookups: 0,
            arch_prep_stamp_ms: 0,
            arch_prep_finish_ms: 0,
            arch_write_total_ms: 0,
            arch_write_reserve_ms: 0,
            arch_write_body_ms: 0,
            arch_write_head_ms: 0,
            arch_write_spend_ms: 0,
            arch_write_htxs_ms: 0,
            arch_write_txstat_ms: 0,
            arch_write_flush_ms: 0,
            arch_write_blocks: 0,
            rss_kb: 0,
            rss_anon_kb: 0,
            rss_file_kb: 0,
            vm_hwm_kb: 0,
            rss_locked_kb: 0,
            work: WorkStructureSizes::default(),
            owned: ProcessOwnedSizes::default(),
            conf_pipe: ConfirmPipelineSizes::default(),
            uring_recover_n: 0,
            uring_slow_drain: 0,
            lookup_faults: 0,
        }
    }
}

/// Process memory from `/proc` (Linux). All fields kB; zeros if unavailable.
///
/// **RSS includes all resident pages**, not only `mlock`ed ones. Ordinary
/// anonymous heap and **file-backed mmap pages that have been faulted in**
/// (e.g. store `tx.head` / table maps) both count toward VmRSS until the kernel
/// reclaims them under pressure (or `MADV_DONTNEED` / unmap).
///
/// Split:
/// - `anon_kb` — process-private anonymous (heap, stacks, MAP_ANON)
/// - `file_kb` — file-backed resident (shared libs + **our table mmaps**)
/// - `locked_kb` — `mlock`/`mlockall` only (usually 0 for us)
///
/// Which fields `read_platform_rss` can fill depends on the target: Linux
/// answers all of them, Darwin only `rss_kb`, other targets none. A zero is
/// therefore "not measurable here" as often as it is a real zero — see the
/// `read_platform_rss` arm for the target you are reading.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct ProcessRss {
    pub rss_kb: u64,
    pub anon_kb: u64,
    pub file_kb: u64,
    pub hwm_kb: u64,
    /// Pages locked into RAM (`Locked:` / mlock). Not required for RSS membership.
    pub locked_kb: u64,
}

/// Cheap once-per-tick resident-size read (not hot path).
///
/// Reads `/proc/self/status` for the fields modern kernels expose (`VmRSS`,
/// `VmHWM`, `RssAnon`, `RssFile`), then `smaps_rollup` (`Rss:`, `Anonymous:`,
/// `Locked:`) to fill a missing split — older rollups do **not** expose
/// `RssAnon:` / `RssFile:` (that bug made `ibd: sizes` print `anon=0 file=0`).
#[cfg(target_os = "linux")]
pub fn read_platform_rss() -> ProcessRss {
    let mut out = ProcessRss::default();
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        fill_rss_from_status(&mut out, &s);
    }
    if let Ok(s) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        fill_rss_from_smaps_rollup(&mut out, &s);
    }
    out
}

/// Cheap once-per-tick resident-size read (not hot path).
///
/// Darwin has no `/proc`, so this asks `proc_pid_rusage`. That flavor gives
/// `rss` alone: no anon/file resident split and no resident peak, so `anon` /
/// `file` / `hwm` / `locked` stay zero and the `ibd: sizes` `residual≈` heap
/// cross-check (anon minus accounted) reads as `0` here rather than meaning
/// the heap matched. Darwin's only lifetime peak is over `phys_footprint`,
/// which excludes clean file-backed pages and so can read below a mapped-file
/// RSS — a "peak" under the current value is worse than none, so `hwm` is
/// left at zero instead.
#[cfg(target_os = "macos")]
pub fn read_platform_rss() -> ProcessRss {
    let mut out = ProcessRss::default();
    fill_rss_from_rusage(&mut out);
    out
}

/// Cheap once-per-tick resident-size read (not hot path).
///
/// Windows has neither `/proc` nor `proc_pid_rusage`, and the `libc` we depend
/// on exposes no process-memory call there, so every field reads zero. Real
/// numbers would need `GetProcessMemoryInfo` (psapi) and a new dependency.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn read_platform_rss() -> ProcessRss {
    ProcessRss::default()
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn fill_rss_from_rusage(out: &mut ProcessRss) {
    // SAFETY: all-zero is a valid `rusage_info_v0`.
    let mut info: libc::rusage_info_v0 = unsafe { std::mem::zeroed() };
    // SAFETY: RUSAGE_INFO_V0 selects the `rusage_info_v0` layout being written
    // here; an unsupported flavor returns non-zero without touching `info`.
    let rc = unsafe {
        libc::proc_pid_rusage(
            std::process::id() as libc::c_int,
            libc::RUSAGE_INFO_V0,
            std::ptr::addr_of_mut!(info).cast(),
        )
    };
    if rc == 0 {
        out.rss_kb = info.ri_resident_size / 1024;
    }
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn fill_rss_from_status(out: &mut ProcessRss, s: &str) {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            out.rss_kb = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            out.hwm_kb = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("RssAnon:") {
            out.anon_kb = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("RssFile:") {
            out.file_kb = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("RssShmem:") {
            let sh = parse_kb_field(rest);
            if sh > 0 {
                out.file_kb = out.file_kb.saturating_add(sh);
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn fill_rss_from_smaps_rollup(out: &mut ProcessRss, s: &str) {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Rss:") {
            if out.rss_kb == 0 {
                out.rss_kb = parse_kb_field(rest);
            }
        } else if let Some(rest) = line.strip_prefix("Anonymous:") {
            if out.anon_kb == 0 {
                out.anon_kb = parse_kb_field(rest);
            }
        } else if let Some(rest) = line.strip_prefix("RssAnon:") {
            if out.anon_kb == 0 {
                out.anon_kb = parse_kb_field(rest);
            }
        } else if let Some(rest) = line.strip_prefix("RssFile:") {
            if out.file_kb == 0 {
                out.file_kb = parse_kb_field(rest);
            }
        } else if let Some(rest) = line.strip_prefix("Locked:") {
            out.locked_kb = parse_kb_field(rest);
        }
    }
    if out.file_kb == 0 && out.rss_kb > 0 && out.anon_kb > 0 && out.anon_kb <= out.rss_kb {
        out.file_kb = out.rss_kb.saturating_sub(out.anon_kb);
    }
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn parse_kb_field(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn ns_ms(ns: u64) -> u64 {
    ns / 1_000_000
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub fn sample(
    loop_stats: &LoopStats,
    inflight: usize,
    inflight_cap: usize,
    // In-RAM block queue: (bytes, count, soft_stop_n).
    bq: (u64, usize, u32),
    buf_ahead: u32,
    hole: usize,
    peers: usize,
    headers_done: bool,
    conf_ready: usize,
    conf_script_q: usize,
    conf_write_q: usize,
    conf_q_hwm: (usize, usize),
    sh_runs: usize,
    work: WorkStructureSizes,
    owned: ProcessOwnedSizes,
    conf_pipe: ConfirmPipelineSizes,
    rss: ProcessRss,
    stats: &rbitcoin_query::ConfirmStats,
) -> IbdPerfSample {
    let (bq_bytes, bq_count, bq_soft_stop) = bq;
    let hot = loop_stats.sample_and_reset();
    let w = stats.take_window();
    let connect_ns = w.connect_ns;
    let script_ns = w.script_ns;
    let idx_asm_ns = w.idx_asm_ns;
    let idx_put_ns = w.idx_put_ns;
    let milestone_gate_ns = w.milestone_gate_ns;
    let class_c_ns = w.class_c_ns;
    let strong_ns = w.strong_ns;
    let sh_ns = w.scripthash_ns;
    let tip_ns = w.tip_ns;
    let utxo_apply_ns = w.utxo_apply_ns;
    let phase_blks = w.phase_blocks;
    let load_ns = w.load_ns;
    let spend_ranged = w.spend_annotate_ranged;
    let structural_ns = w.structural_ns;
    let structural_spent_ns = w.structural_spent_ns;
    let structural_create_h_ns = w.structural_create_h_ns;
    let structural_bip68_ns = w.structural_bip68_ns;
    let class_a_ns = w.class_a_ns;
    let ensure_ns = w.ensure_layout_ns;
    let drain_join_ns = w.write_drain_join_ns;
    let tip_flush_wait_ns = w.write_tip_flush_wait_ns;
    let dequeue_ns = w.write_dequeue_ns;
    let pins_take_ns = w.write_plan_take_ns;
    let pins_map_ns = w.write_create_map_ns;
    let head_sub_ns = w.write_head_sub_ns;
    let pins_ns = pins_take_ns.saturating_add(pins_map_ns);
    let class_c_join_ns = w.write_class_c_join_ns;
    let spent_abs_ns = w.structural_spent_abs_ns;
    let spent_strong_ns = w.structural_spent_strong_ns;
    let spent_cold_ns = w.structural_spent_cold_ns;
    let spent_pending_ns = w.structural_spent_pending_ns;
    let script_jobs = w.script_jobs;
    let script_skip = w.script_skip_mempool;
    let ann_ns = w.spend_ann_ns;
    let ann_n = w.spend_ann_n;
    let ann_pread_skip = w.spend_ann_pread_skip;
    let ann_sync_ns = w.spend_durable_ns;
    let spend_replay_ns = w.spend_replay_ns;
    let meta_ns = w.spend_meta_ns;
    let meta_n = w.spend_meta_n;
    let ovl_n = w.spend_overlay_skip_n;
    let ensure_res_hit = w.ensure_res_hit;
    let ensure_cold_n = w.ensure_cold_n;
    let asm_prevout_ns = w.asm_prevout_ns;
    let asm_sigop_ns = w.asm_sigop_ns;
    let asm_final_ns = w.asm_final_ns;
    let asm_job_ns = w.asm_job_ns;
    let asm_in_n = w.asm_in_n;
    let asm_prev_batch_n = w.asm_prev_batch_n;
    let asm_prev_same_n = w.asm_prev_same_n;
    let asm_prev_cold_n = w.asm_prev_cold_n;
    let asm_cold_null_fk_n = w.asm_prev_cold_null_fk_n;
    let asm_cold_not_pin_n = w.asm_prev_cold_not_pin_n;
    let asm_cold_txid_mismatch_n = w.asm_prev_cold_txid_mismatch_n;
    let asm_cold_vout_miss_n = w.asm_prev_cold_vout_miss_n;
    let prep_wire_arc_ns = w.phase_prep_wire_arc_ns;
    let prep_struct_ns = w.phase_prep_struct_ns;
    let prep_header_ns = w.phase_prep_header_ns;
    let prep_header_skip_n = w.phase_prep_header_skip_n;
    let prep_prepare_ns = w.phase_prep_prepare_ns;
    let prep_filter_plan_ns = w.phase_prep_filter_plan_ns;
    let sh_collect = w.sh_collect_ns;
    let sh_sort = w.sh_sort_ns;
    let sh_seed = w.sh_seed_ns;
    let sh_body = w.sh_body_ns;
    let sh_head = w.sh_head_ns;
    let sh_collect_pin = w.sh_collect_pin;
    let sh_collect_cold = w.sh_collect_cold;
    let wf_body_store = w.wf_body_store;
    let wf_store_body_ns = w.wf_body_store_ns;
    let head_res = rbitcoin_store::head_resolve_stats::sample_and_reset();
    IbdPerfSample {
        inflight,
        inflight_cap,
        bq_bytes,
        bq_count,
        bq_soft_stop,
        buf_ahead,
        hole,
        peers,
        headers_done,
        confirm_ms: hot.confirm_ms(),
        confirm_blocks: hot.confirm_blocks,
        confirm_reject_stops: hot.confirm_reject_stops,
        confirm_us_per_block: hot.confirm_us_per_block(),
        assign_ms: hot.assign_ms(),
        assign_issued: hot.assign_issued,
        drain_ms: hot.drain_ms(),
        drain_events: hot.drain_events,
        status_scan_ms: hot.status_scan_ms(),
        dominant: hot.dominant(),
        live: hot.confirm_live,
        phase_blks,
        connect_ms: ns_ms(connect_ns),
        script_ms: ns_ms(script_ns),
        idx_asm_ms: ns_ms(idx_asm_ns),
        write: WriteStageSample {
            class_a_ms: ns_ms(class_a_ns),
            class_a_ns,
            ensure_ms: ns_ms(ensure_ns),
            ensure_ns,
            structural_ms: ns_ms(structural_ns),
            structural_ns,
            class_c_ms: ns_ms(class_c_ns),
            class_c_ns,
            sh_ms: ns_ms(sh_ns),
            sh_ns,
            utxo_ms: ns_ms(utxo_apply_ns),
            utxo_apply_ns,
            pins_ms: ns_ms(pins_ns),
            pins_ns,
            head_sub_ms: ns_ms(head_sub_ns),
            head_sub_ns,
            class_c_join_ms: ns_ms(class_c_join_ns),
            class_c_join_ns,
            tip_flush_wait_ms: ns_ms(tip_flush_wait_ns),
            tip_flush_wait_ns,
            drain_join_ms: ns_ms(drain_join_ns),
            drain_join_ns,
            dequeue_ms: ns_ms(dequeue_ns),
            dequeue_ns,
            idx_put_ms: ns_ms(idx_put_ns),
            idx_put_ns,
        },
        ensure_res_hit,
        ensure_cold_n,
        pins_take_ms: ns_ms(pins_take_ns),
        pins_map_ms: ns_ms(pins_map_ns),
        asm_prevout_ms: ns_ms(asm_prevout_ns),
        asm_sigop_ms: ns_ms(asm_sigop_ns),
        asm_final_ms: ns_ms(asm_final_ns),
        asm_job_ms: ns_ms(asm_job_ns),
        asm_in_n,
        asm_prev_batch_n,
        asm_prev_same_n,
        asm_prev_cold_n,
        asm_cold_null_fk_n,
        asm_cold_not_pin_n,
        asm_cold_txid_mismatch_n,
        asm_cold_vout_miss_n,
        strong_ms: ns_ms(strong_ns),
        structural_spent_ms: ns_ms(structural_spent_ns),
        spent_abs_ms: ns_ms(spent_abs_ns),
        spent_strong_ms: ns_ms(spent_strong_ns),
        spent_cold_ms: ns_ms(spent_cold_ns),
        spent_pending_ms: ns_ms(spent_pending_ns),
        structural_create_h_ms: ns_ms(structural_create_h_ns),
        structural_bip68_ms: ns_ms(structural_bip68_ns),
        spend_ranged,
        ann_ms: ns_ms(ann_ns),
        ann_n,
        ann_pread_skip,
        ann_sync_ms: ns_ms(ann_sync_ns),
        spend_replay_ms: ns_ms(spend_replay_ns),
        meta_ms: ns_ms(meta_ns),
        meta_n,
        ovl_n,
        load_ms: ns_ms(load_ns),
        prep_wire_arc_ms: ns_ms(prep_wire_arc_ns),
        prep_struct_ms: ns_ms(prep_struct_ns),
        prep_header_ms: ns_ms(prep_header_ns),
        prep_header_skip_n,
        prep_prepare_ms: ns_ms(prep_prepare_ns),
        prep_filter_plan_ms: ns_ms(prep_filter_plan_ns),
        connect_ns,
        script_ns,
        milestone_gate_ns,
        strong_ns,
        tip_ns,
        structural_spent_ns,
        structural_create_h_ns,
        structural_bip68_ns,
        load_ns,
        sh_runs,
        wf_body_store,
        wf_store_body_ms: ns_ms(wf_store_body_ns),
        sh_collect_ms: ns_ms(sh_collect),
        sh_sort_ms: ns_ms(sh_sort),
        sh_seed_ms: ns_ms(sh_seed),
        sh_body_ms: ns_ms(sh_body),
        sh_head_ms: ns_ms(sh_head),
        sh_collect_pin,
        sh_collect_cold,
        load_win_ms: ns_ms(w.load_win_ns),
        load_blocks: w.load_blocks,
        load_utxo_parents: w.utxo_parents,
        load_parent_unique: w.parent_unique,
        load_pin_cache_body: w.pin_cache_body,
        load_pin_plan: w.pin_plan,
        load_pin_new: w.pin_new,
        prefetch_bytes: w.prefetch_bytes,
        prefetch_ns: ns_ms(w.prefetch_ns),
        load_pin_body_ms: ns_ms(w.pin_body_ns),
        load_plan_pin_ms: ns_ms(w.plan_pin_ns),
        load_pin_range_fill_ms: ns_ms(w.pin_range_fill_ns),
        load_pin_recent_outs_ms: ns_ms(w.pin_recent_outs_ns),
        load_pin_contract_ms: ns_ms(w.pin_contract_ns),
        load_cold_io_ms: ns_ms(w.cold_io_ns),
        load_cold_range_ms: ns_ms(w.cold_range_ns),
        load_cold_range_n: w.cold_range_n,
        load_cold_range_body_ms: ns_ms(w.cold_range_body_ns),
        load_cold_range_decode_ms: ns_ms(w.cold_range_decode_ns),
        load_cold_range_extend_n: w.cold_range_extend_n,
        load_cold_range_body_sqe_n: w.cold_range_body_sqe_n,
        load_cold_range_guess_full_n: w.cold_range_guess_full_n,
        load_body_tx_reads: w.body_tx_reads,
        conf_ready,
        conf_script_q,
        conf_write_q,
        conf_script_q_cap: super::confirm::script_queue_cap(),
        conf_write_q_cap: super::confirm::write_queue_cap(),
        conf_script_q_hwm: conf_q_hwm.0,
        conf_write_q_hwm: conf_q_hwm.1,
        thr_lookup_claim_ms: ns_ms(w.thr_lookup_claim_ns),
        thr_lookup_stamp_ms: ns_ms(w.thr_lookup_stamp_ns),
        thr_lookup_other_ms: ns_ms(w.thr_lookup_other_ns),
        thr_lookup_send_wait_ms: ns_ms(w.thr_lookup_send_wait_ns),
        stamp_struct_ms: ns_ms(w.stamp_struct_ns),
        stamp_struct_txid_ms: ns_ms(w.stamp_struct_txid_ns),
        stamp_struct_walk_ms: ns_ms(w.stamp_struct_walk_ns),
        stamp_prepare_ms: ns_ms(w.stamp_prepare_ns),
        stamp_filter_ms: ns_ms(w.stamp_filter_ns),
        stamp_batch_ms: ns_ms(w.stamp_batch_ns),
        stamp_batch_assign_ms: ns_ms(w.arch_prep_assign_ns),
        stamp_batch_collect_ms: ns_ms(w.arch_prep_collect_ns),
        stamp_batch_head_ms: ns_ms(w.arch_prep_head_ns),
        stamp_batch_head_fk_ms: ns_ms(w.arch_prep_head_fk_ns),
        stamp_batch_stamp_ms: ns_ms(w.arch_prep_stamp_ns),
        stamp_batch_finish_ms: ns_ms(w.arch_prep_finish_ns),
        thr_load_recv_wait_ms: ns_ms(w.thr_load_recv_wait_ns),
        thr_load_pack_ms: ns_ms(w.thr_load_pack_ns),
        thr_load_clone_ms: ns_ms(w.thr_load_clone_ns),
        thr_load_stamp_ms: ns_ms(w.thr_load_stamp_ns),
        thr_load_pin_ms: ns_ms(w.thr_load_pin_ns),
        thr_load_asm_ms: ns_ms(w.thr_load_asm_ns),
        thr_load_prune_ms: ns_ms(w.thr_load_prune_ns),
        thr_load_reject_ms: ns_ms(w.thr_load_reject_ns),
        thr_load_send_wait_ms: ns_ms(w.thr_load_send_wait_ns),
        script_jobs,
        script_skip,
        thr_script_recv_wait_ms: ns_ms(w.thr_script_recv_wait_ns),
        thr_script_work_ms: ns_ms(w.thr_script_work_ns),
        thr_script_send_wait_ms: ns_ms(w.thr_script_send_wait_ns),
        thr_write_recv_wait_ms: ns_ms(w.thr_write_recv_wait_ns),
        thr_write_work_ms: ns_ms(w.thr_write_work_ns),
        plan_blks: w.lookup_blocks,
        plan_ms: ns_ms(w.lookup_total_ns),
        plan_collect_ms: ns_ms(w.lookup_collect_ns),
        plan_head_ms: ns_ms(w.lookup_head_ns),
        plan_cold_io_ms: ns_ms(w.lookup_cold_io_ns),
        lookup_decode_ms: ns_ms(w.lookup_decode_ns),
        lookup_precompute_ms: ns_ms(w.lookup_precompute_ns),
        lookup_wave_head_ms: ns_ms(w.lookup_wave_head_ns),
        lookup_wave_head_probe_ms: ns_ms(head_res.probe_ns),
        lookup_wave_head_io_ms: ns_ms(head_res.body_ns.saturating_add(head_res.idx_ns)),
        lookup_wave_head_preads: head_res.body_lookups,
        lookup_wave_spent_ms: ns_ms(head_res.idx_ns),
        plan_parents: w.lookup_parents,
        plan_already: w.lookup_already,
        plan_cold: w.lookup_cold,
        plan_same_batch: w.lookup_unresolved,
        load_thin_ms: ns_ms(w.thin_ns),
        load_parent_pin_ms: ns_ms(w.parent_pin_ns),
        arch_ext_need: w.ext_need,
        arch_head_need: w.head_need,
        arch_head_hit: w.head_hit,
        leftover_pend: w.leftover_pend,
        leftover_cdf0_pct: w.leftover_cdf0_pct,
        leftover_cdf3_pct: w.leftover_cdf3_pct,
        leftover_age_n: w.leftover_age_n,
        arch_pin_txid: w.pin_txid_n,
        arch_pin_txid_ms: ns_ms(w.pin_txid_ns),
        arch_recent_n: w.recent_n,
        arch_recent_ms: ns_ms(w.recent_ns),
        arch_batch_stamp: w.batch_stamp,
        arch_resolve_ns: w.resolve_ns(),
        arch_resolve_blocks: w.arch_blocks,
        arch_prep_assign_ms: ns_ms(w.arch_prep_assign_ns),
        arch_prep_collect_ms: ns_ms(w.arch_prep_collect_ns),
        arch_prep_inflight_ms: ns_ms(w.arch_prep_inflight_ns),
        arch_prep_head_ms: ns_ms(w.arch_prep_head_ns),
        arch_prep_head_fk_ms: ns_ms(w.arch_prep_head_fk_ns),
        arch_prep_probe_ms: ns_ms(head_res.probe_ns),
        arch_prep_idx_ms: ns_ms(head_res.idx_ns),
        arch_prep_body_txid_ms: ns_ms(head_res.body_ns),
        arch_prep_head_keys: head_res.keys,
        arch_prep_head_cands: head_res.cands,
        arch_prep_hit_rank_avg_x100: (head_res.hit_rank_avg() * 100.0).round() as u64,
        arch_prep_hit_rank_n: head_res.hit_rank_n,
        arch_prep_miss_peeks: head_res.miss_peeks,
        arch_prep_pending_hits: head_res.pending_hits,
        arch_prep_age_cdf0_pct: head_res.age_cdf_pct(0),
        arch_prep_age_cdf3_pct: head_res.age_cdf_pct(3),
        arch_prep_age_cdf7_pct: head_res.age_cdf_pct(7),
        arch_prep_age_cdf15_pct: head_res.age_cdf_pct(15),
        arch_prep_age_cdf31_pct: head_res.age_cdf_pct(31),
        arch_prep_age_hit_compact: head_res.age_hit_compact(),
        arch_prep_age_hit_n: head_res.age_hit_n(),
        arch_prep_body_lookups: head_res.body_lookups,
        arch_prep_stamp_ms: ns_ms(w.arch_prep_stamp_ns),
        arch_prep_finish_ms: ns_ms(w.arch_prep_finish_ns),
        arch_write_total_ms: ns_ms(w.arch_write_total_ns),
        arch_write_reserve_ms: ns_ms(w.arch_write_reserve_ns),
        arch_write_body_ms: ns_ms(w.arch_write_body_ns),
        arch_write_head_ms: ns_ms(w.arch_write_head_ns),
        arch_write_spend_ms: ns_ms(w.arch_write_spend_ns),
        arch_write_htxs_ms: ns_ms(w.arch_write_htxs_ns),
        arch_write_txstat_ms: ns_ms(w.arch_write_txstat_ns),
        arch_write_flush_ms: ns_ms(w.arch_write_flush_ns),
        arch_write_blocks: w.arch_write_blocks,
        rss_kb: rss.rss_kb,
        rss_anon_kb: rss.anon_kb,
        rss_file_kb: rss.file_kb,
        vm_hwm_kb: rss.hwm_kb,
        rss_locked_kb: rss.locked_kb,
        work,
        owned,
        conf_pipe,
        uring_recover_n: rbitcoin_store::uring_recover_count(),
        uring_slow_drain: rbitcoin_store::uring_slow_drain_count(),
        lookup_faults: super::confirm::take_lookup_wave_faults(),
    }
}

#[doc(hidden)]
pub fn ser_process_owned<S: serde::Serializer>(
    o: &ProcessOwnedSizes,
    ser: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    let h = &o.head;
    serde_json::json!({
        "conf_plans": o.conf_plans,
        "sh_runs": o.sh_runs,
        "inflight_layers": o.inflight_layers,
        "inflight_pins": o.inflight_pins,
        "inflight_bytes": o.inflight_bytes,
        "h2h_keys": o.h2h_keys,
        "fence_runs": o.fence_runs,
        "bq_promoted": o.bq_promoted,
        "wloc_packs": o.wloc_packs,
        "wloc_pairs": o.wloc_pairs,
        "wloc_bytes": o.wloc_bytes,
        "head": {
            "class_a_n": h.class_a_n,
            "primary_bits": h.primary_bits,
            "primary_slots": h.primary_slots,
            "primary_occupied": h.primary_occupied,
            "primary_body_bytes": h.primary_body_bytes,
            "segment_count": h.segment_count,
            "sealed_segments": h.sealed_segments,
            "fuse8_bytes": h.fuse8_bytes,
            "mphf_g_bytes": h.mphf_g_bytes,
            "head_map_bytes": h.head_map_bytes,
            "mphf_occ_bytes": h.mphf_occ_bytes,
            "class_c_l2_bytes": h.class_c_l2_bytes
        }
    })
    .serialize(ser)
}

/// Pin + assemble stage wall. Not the load OS-thread total.
#[doc(hidden)]
pub fn load_stage_wall_ms(s: &IbdPerfSample) -> u64 {
    s.load_ms.saturating_add(s.connect_ms)
}

/// Exclusive write inventory sum.
#[doc(hidden)]
pub fn write_stage_ms(s: &IbdPerfSample) -> u64 {
    s.write.stage_ms()
}

/// Counters for one `tip: perf` JSON line. `tip_perf_json` adds `ts`.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct TipPerfLog {
    pub rss: ProcessRss,
    pub cache_bodies: usize,
    pub held_bodies: usize,
    pub mp_live: usize,
    pub follow_live: usize,
    pub blocks: u64,
    pub accepts: u64,
    pub rejects: u64,
    pub accept_avg_us: u64,
    pub accept_max_us: u64,
    pub accept_lock_us: u64,
    pub accept_utxo_us: u64,
    pub accept_script_us: u64,
    pub accept_durable_us: u64,
    pub inv_tx: u64,
    pub getdata_tx: u64,
    pub announce: u64,
    pub esplora_n: u64,
    pub esplora_avg_us: u64,
    pub esplora_max_us: u64,
    pub electrum_n: u64,
    pub electrum_avg_us: u64,
    pub electrum_max_us: u64,
    pub serve_n: u64,
    pub serve_bytes: u64,
    pub serve_tx: u64,
    pub serve_avg_us: u64,
    pub serve_max_us: u64,
    pub sv2_checks: u64,
    pub sv2_builds: u64,
    pub sv2_build_avg_us: u64,
    pub sv2_build_max_us: u64,
}

/// `tip: perf` body. Compact JSON, `ts` is unix milliseconds.
pub fn tip_perf_json(s: &TipPerfLog) -> String {
    let mut v = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "ts".to_string(),
            serde_json::Value::from(rbitcoin_consensus::clock::unix_ms()),
        );
    }
    v.to_string()
}

/// `ibd: perf` body. Compact JSON of [`IbdPerfSample`] plus `ts` (unix ms).
/// Zeros stay so every key is present on every line.
pub fn perf_sample_json(s: &IbdPerfSample) -> String {
    let mut v = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "ts".to_string(),
            serde_json::Value::from(rbitcoin_consensus::clock::unix_ms()),
        );
    }
    v.to_string()
}

/// Emit one DEBUG line (`ibd: progress` is a separate INFO tick).
pub fn log_sample(s: &IbdPerfSample) {
    debug!("ibd: perf {}", perf_sample_json(s));
    if s.phase_blks > 0 {
        let c_ms = s.write.class_c_ms / s.phase_blks.max(1);
        let sh_ms = s.write.sh_ms / s.phase_blks.max(1);
        let load_wall_ms = load_stage_wall_ms(s) / s.phase_blks.max(1);
        let write_ms = write_stage_ms(s) / s.phase_blks.max(1);
        if c_ms >= 1000 || sh_ms >= 1000 || load_wall_ms >= 5000 || write_ms >= 5000 {
            rbitcoin_log::warn!(
                "ibd: slow confirm phase ms/blk load={} script={} write={} class_a={} class_c={} sh={} (sh_collect={}ms window) store_body={}ms blks={}",
                load_wall_ms,
                s.script_ms / s.phase_blks.max(1),
                write_ms,
                s.write.class_a_ms / s.phase_blks.max(1),
                c_ms,
                sh_ms,
                s.sh_collect_ms,
                s.wf_store_body_ms,
                s.phase_blks,
            );
        }
    }
    let _ = std::io::Write::flush(&mut std::io::stderr());
}
