//! Consolidated IBD performance sampling and logging.
//!
//! **Cadence:** one centralized ~5s status tick (see `ibd` main loop) emits
//! `ibd: progress`, `ibd: perf`, and `ibd: sizes` together.
//!
//! | Level | Message | Contents |
//! |-------|---------|----------|
//! | INFO  | `ibd: progress …` | Tip rate over the **last 5s**, `hole=` fetch gap tip→next claim-ready body, loadq=/scriptq/writeq, txs=, horizon, tip ETA, body `bq soft=n/stop RAM=` |
//! | DEBUG | `ibd: perf …` | Download + in-RAM body-queue soft depth; **load_budget** + pin cold_range/idx us/new + assemble us/in path splits; queues |
//! | DEBUG | `ibd: sizes …` | RSS + work path + **bq soft/RAM** + conf pipe + tx.head |
//! | DEBUG | `ibd: perf_dbg …` | µs/blk, pin/edge detail; plan_batch head resolve; class_a commit |
//!
//! **Pins:** pipeline-local (plan batch_pin / BatchParents).
//!
//! Sample **once** per tick and reset all atomics, then format `ibd: progress`
//! at INFO and meters (`perf` / `sizes` / `perf_dbg`) at DEBUG from the same
//! sample.
//!
//! Unified path: peer → **body queue** → confirm **lookup** (stamp) → **load**
//! (pin+assemble) → **scripts** → **write** (sole Class A append + Class C / spends / tip).
//!
//! Stage walls (window sums; stages overlap on OS threads):
//! - **lookup** = lookup-thread TipOnly wave (`plan_ms` / `lookup_thr wave=`
//!   with nested `decode=` / `precompute=` / `collect=` /
//!   `head=(probe= io= preads=)` / `spent=`)
//! - **load=** = pin (`LOAD_NS`) + assemble (`CONNECT_NS`) only — **not** the
//!   load OS-thread wall. Load thread also does pack decode, leftover stamp
//!   (plan=None / S0 only), clone, and post-stamp prune on a marked last load
//!   batch (`load_thr pack/stamp/pin/asm/prune`).
//! - **script=** = `SCRIPT_NS` (publish → first `is_complete` per batch on
//!   `ibd-confirm`; excludes head-of-line wait for write handoff). `thr script work`
//!   is that same ns. Recv/send are wait. Publisher parks; it does not `wait_done`
//!   on steal workers.
//! - **write** = Class A + ensure + structural + class_c + spend + tweaks + tip GC
//!   + `recent_pub=` / `pins=` / `head_sub=` / `drain_join=` / `dequeue=`.
//!   `other=` is write-thread work minus that inventory.
//!
//! **Inventory rule:** new work on lookup / load / scripts / write (or a sidecar
//! the write thread joins) must add a named token here in the **same commit**.
//! Same-commit rule: `AGENTS.md`. `write=` must equal `write_stage_ms`.
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
use rbitcoin_log::{debug, enabled, Level};
use rbitcoin_query::ProcessOwnedSizes;

/// Write-stage tokens that must sum to `write=` / [`write_stage_ms`].
///
/// Inventory: `class_a` + `ensure` + `struct` + `class_c` + `sh` + `spend`
/// + `tweaks` + `tip_gc` + `recent_pub` + `pins` + `head_sub` + `drain_join`
/// + `dequeue`. `other=` is write-thread work minus this inventory.
/// Subtimers (spent_sub, ann, class_a_sub, pins take/map) stay on the outer
/// sample until a later nest.
#[derive(Clone, Debug, Default)]
pub(crate) struct WriteStageSample {
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
    /// Tip write-through `index_sp_tweaks_batch` (`tweaks=`)
    pub tweak_ms: u64,
    pub tweak_ns: u64,
    /// `advance_parent_cache_tip` (`tip_gc=`)
    pub cache_tip_ms: u64,
    pub cache_tip_ns: u64,
    /// RecentCreates note+expire+one snapshot (`recent_pub=`)
    pub recent_pub_ms: u64,
    pub recent_pub_ns: u64,
    /// Write-thread pin Arc copies: plan take + create-pin FkMap (`pins=`)
    pub pins_ms: u64,
    pub pins_ns: u64,
    /// `take_pending_queued` + `submit_head_insert` (`head_sub=`)
    pub head_sub_ms: u64,
    pub head_sub_ns: u64,
    /// `class_c_commit` join/flush minus tables (`class_c_join=`)
    pub class_c_join_ms: u64,
    pub class_c_join_ns: u64,
    /// Residual `head_insert_queued` join after Class C (`drain_join=`)
    pub drain_join_ms: u64,
    pub drain_join_ns: u64,
    /// Body-queue dequeue after confirm (`dequeue=`)
    pub dequeue_ms: u64,
    pub dequeue_ns: u64,
}

impl WriteStageSample {
    /// Sum of the exclusive write inventory tokens (ms).
    pub fn stage_ms(&self) -> u64 {
        self.class_a_ms
            .saturating_add(self.ensure_ms)
            .saturating_add(self.structural_ms)
            .saturating_add(self.class_c_ms)
            .saturating_add(self.sh_ms)
            .saturating_add(self.utxo_ms)
            .saturating_add(self.tweak_ms)
            .saturating_add(self.cache_tip_ms)
            .saturating_add(self.recent_pub_ms)
            .saturating_add(self.pins_ms)
            .saturating_add(self.head_sub_ms)
            .saturating_add(self.class_c_join_ms)
            .saturating_add(self.drain_join_ms)
            .saturating_add(self.dequeue_ms)
    }

    /// Same inventory in nanoseconds (`format_debug` us/blk write=).
    pub fn stage_ns(&self) -> u64 {
        self.class_a_ns
            .saturating_add(self.ensure_ns)
            .saturating_add(self.structural_ns)
            .saturating_add(self.class_c_ns)
            .saturating_add(self.sh_ns)
            .saturating_add(self.utxo_apply_ns)
            .saturating_add(self.tweak_ns)
            .saturating_add(self.cache_tip_ns)
            .saturating_add(self.recent_pub_ns)
            .saturating_add(self.pins_ns)
            .saturating_add(self.head_sub_ns)
            .saturating_add(self.class_c_join_ns)
            .saturating_add(self.drain_join_ns)
            .saturating_add(self.dequeue_ns)
    }
}

/// One 5s window of IBD counters (post sample-and-reset).
#[derive(Clone, Debug)]
pub(crate) struct IbdPerfSample {
    pub inflight: usize,
    pub inflight_cap: usize,
    /// In-RAM block queue used bytes / count (process heap wire payloads).
    pub bq_bytes: u64,
    pub bq_count: usize,
    /// Soft densify confirm-window target (block count ≈ 1 min tip rate).
    pub bq_soft_stop: u32,
    /// Claim-ready HWM (+ inflight) ahead of tip — densify headroom (not a progress lead token).
    pub arch_ahead: u32,
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
    pub recon_ms: u64,
    pub wire_ms: u64,
    pub connect_ms: u64,
    pub script_ms: u64,
    /// Write-stage exclusive tokens (`write=` = [`WriteStageSample::stage_ms`]).
    pub write: WriteStageSample,
    /// Ensure mix: residency/pin hits vs cold denserels body loads.
    pub ensure_res_hit: u64,
    pub ensure_cold_n: u64,
    /// RecentCreates idx vs snapshot clone (`recent_idx=` / `recent_clone=`).
    pub recent_idx_ms: u64,
    pub recent_clone_ms: u64,
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
    /// Prevout path: batch pin hit ms / count.
    pub asm_prev_batch_ms: u64,
    pub asm_prev_batch_n: u64,
    /// Prevout path: residency hit ms / count.
    /// Prevout path: same-block ms / count.
    pub asm_prev_same_ms: u64,
    pub asm_prev_same_n: u64,
    /// Prevout path: cold Class A ms / count.
    pub asm_prev_cold_ms: u64,
    pub asm_prev_cold_n: u64,
    /// N1: cold success reasons (sum ≈ asm_prev_cold_n).
    pub asm_cold_null_fk_n: u64,
    pub asm_cold_not_pin_n: u64,
    pub asm_cold_txid_mismatch_n: u64,
    pub asm_cold_vout_miss_n: u64,
    /// Prevout path: durable txid→fk lookup ms.
    pub asm_prev_fk_ms: u64,
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
    pub spend_idx: u64,
    pub spend_skip: u64,
    /// Pure-write annotate wall ms / edge count.
    pub ann_ms: u64,
    pub ann_n: u64,
    /// Annotate edges without body pread (should equal annotate edges).
    pub ann_pread_skip: u64,
    /// Annotate body preads (must stay 0 on pure-write path).
    pub ann_pread: u64,
    /// Structural meta bulk read wall ms / peek count.
    pub meta_ms: u64,
    pub meta_n: u64,
    pub resolve_ms: u64,
    pub load_ms: u64,
    /// Wire load residual (inside load/pre_asm, outside pin): Arc clone.
    pub prep_wire_arc_ms: u64,
    /// Structure validate.
    pub prep_struct_ms: u64,
    /// Header validate/put + cache seed.
    pub prep_header_ms: u64,
    /// prepare_block_for_archive.
    pub prep_prepare_ms: u64,
    /// filter need + plan batch + tx_fks wiring.
    pub prep_filter_plan_ms: u64,
    pub recon_ns: u64,
    pub wire_ns: u64,
    pub connect_ns: u64,
    pub script_ns: u64,
    pub strong_ns: u64,
    pub tip_ns: u64,
    pub structural_spent_ns: u64,
    pub structural_create_h_ns: u64,
    pub structural_bip68_ns: u64,
    pub resolve_ns: u64,
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
    pub load_creates: u64,
    pub load_parent_unique: u64,
    pub load_pin_cache_body: u64,
    /// Pin hits from pipeline pins (subset of pin_cache when residency filled).
    /// Wire plan / in-flight parent pins (not denserels hits).
    pub load_pin_plan: u64,
    pub load_pin_new: u64,
    pub load_pin_body_ms: u64,
    pub load_pin_new_meta_ms: u64,
    pub load_plan_pin_ms: u64,
    /// Pin residual sub-walls (adopt / recent-outs / range-fill insert / contract / publish).
    pub load_pin_adopt_ms: u64,
    pub load_pin_range_fill_ms: u64,
    pub load_pin_recent_outs_ms: u64,
    pub load_pin_contract_ms: u64,
    pub load_pin_publish_ms: u64,
    pub load_cold_io_ms: u64,
    /// Cold denserels by plan body range (ms / create count).
    pub load_cold_range_ms: u64,
    pub load_cold_range_n: u64,
    /// N2.0: body pread vs sparse denserels decode (ms; sum ≈ cold_range).
    pub load_cold_range_body_ms: u64,
    pub load_cold_range_decode_ms: u64,
    /// Cold denserels by idx→body (ms / create count).
    pub load_cold_idx_ms: u64,
    pub load_cold_idx_n: u64,
    pub load_cold_decode_ms: u64,
    /// pipeline pins lock: write wait/hold ms, write count.
    /// pipeline pins lock: read wait/hold ms, read count.
    pub load_body_tx_reads: u64,
    pub load_parent_tx_reads: u64,
    pub load_missing_parents: u64,
    pub load_ready_through: u32,
    pub cache_bodies: usize,
    pub cache_plans: usize,
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
    /// plan_batch internals (from archive_phase_stats).
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
    /// Lookup-wave `TxPrecompute::from_tx` / `from_tx_connect` (`precompute=`).
    pub lookup_precompute_ms: u64,
    /// Lookup-wave TipOnly `get_fk_by_txid_batch` (`wave=… head=`). Not load stamp.
    pub lookup_wave_head_ms: u64,
    /// TipOnly CPU (slot/fuse probe + fence snapshot) inside `head=`.
    pub lookup_wave_head_probe_ms: u64,
    /// TipOnly body+idx pread wall inside `head=`.
    pub lookup_wave_head_io_ms: u64,
    /// TipOnly `txid.body` / identity preads this window.
    pub lookup_wave_head_preads: u64,
    /// Lookup-wave `tx_spent_range_batch` for TipOnly hits (`wave=… spent=`).
    pub lookup_wave_spent_ms: u64,
    pub plan_parents: u64,
    pub plan_already: u64,
    pub plan_cold: u64,
    pub plan_same_batch: u64,
    pub load_hdr_ms: u64,
    pub load_decode_ms: u64,
    pub load_thin_ms: u64,
    pub load_parent_pin_ms: u64,
    pub load_cache_put_ms: u64,
    pub load_edge_same: u64,
    pub load_edge_fk: u64,
    pub load_edge_cb: u64,

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
    pub owned: ProcessOwnedSizes,
    /// Confirm load/scripts/write queue contents + feed.
    pub conf_pipe: ConfirmPipelineSizes,
}

impl Default for IbdPerfSample {
    fn default() -> Self {
        Self {
            inflight: 0,
            inflight_cap: 0,
            bq_bytes: 0,
            bq_count: 0,
            bq_soft_stop: 0,
            arch_ahead: 0,
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
            recon_ms: 0,
            wire_ms: 0,
            connect_ms: 0,
            script_ms: 0,
            write: WriteStageSample::default(),
            ensure_res_hit: 0,
            ensure_cold_n: 0,
            recent_idx_ms: 0,
            recent_clone_ms: 0,
            pins_take_ms: 0,
            pins_map_ms: 0,
            asm_prevout_ms: 0,
            asm_sigop_ms: 0,
            asm_final_ms: 0,
            asm_job_ms: 0,
            asm_in_n: 0,
            asm_prev_batch_ms: 0,
            asm_prev_batch_n: 0,
            asm_prev_same_ms: 0,
            asm_prev_same_n: 0,
            asm_prev_cold_ms: 0,
            asm_prev_cold_n: 0,
            asm_cold_null_fk_n: 0,
            asm_cold_not_pin_n: 0,
            asm_cold_txid_mismatch_n: 0,
            asm_cold_vout_miss_n: 0,
            asm_prev_fk_ms: 0,
            strong_ms: 0,
            structural_spent_ms: 0,
            spent_abs_ms: 0,
            spent_strong_ms: 0,
            spent_cold_ms: 0,
            spent_pending_ms: 0,
            structural_create_h_ms: 0,
            structural_bip68_ms: 0,
            spend_ranged: 0,
            spend_idx: 0,
            spend_skip: 0,
            ann_ms: 0,
            ann_n: 0,
            ann_pread_skip: 0,
            ann_pread: 0,
            meta_ms: 0,
            meta_n: 0,
            resolve_ms: 0,
            load_ms: 0,
            prep_wire_arc_ms: 0,
            prep_struct_ms: 0,
            prep_header_ms: 0,
            prep_prepare_ms: 0,
            prep_filter_plan_ms: 0,
            recon_ns: 0,
            wire_ns: 0,
            connect_ns: 0,
            script_ns: 0,
            strong_ns: 0,
            tip_ns: 0,
            structural_spent_ns: 0,
            structural_create_h_ns: 0,
            structural_bip68_ns: 0,
            resolve_ns: 0,
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
            load_creates: 0,
            load_parent_unique: 0,
            load_pin_cache_body: 0,
            load_pin_plan: 0,
            load_pin_new: 0,
            load_pin_body_ms: 0,
            load_pin_new_meta_ms: 0,
            load_plan_pin_ms: 0,
            load_pin_adopt_ms: 0,
            load_pin_range_fill_ms: 0,
            load_pin_recent_outs_ms: 0,
            load_pin_contract_ms: 0,
            load_pin_publish_ms: 0,
            load_cold_io_ms: 0,
            load_cold_range_ms: 0,
            load_cold_range_n: 0,
            load_cold_range_body_ms: 0,
            load_cold_range_decode_ms: 0,
            load_cold_idx_ms: 0,
            load_cold_idx_n: 0,
            load_cold_decode_ms: 0,
            load_body_tx_reads: 0,
            load_parent_tx_reads: 0,
            load_missing_parents: 0,
            load_ready_through: 0,
            cache_bodies: 0,
            cache_plans: 0,
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
            load_hdr_ms: 0,
            load_decode_ms: 0,
            load_thin_ms: 0,
            load_parent_pin_ms: 0,
            load_cache_put_ms: 0,
            load_edge_same: 0,
            load_edge_fk: 0,
            load_edge_cb: 0,
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
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcRss {
    pub rss_kb: u64,
    pub anon_kb: u64,
    pub file_kb: u64,
    pub hwm_kb: u64,
    /// Pages locked into RAM (`Locked:` / mlock). Not required for RSS membership.
    pub locked_kb: u64,
}

/// Cheap once-per-tick `/proc` read (not hot path).
///
/// Prefer `/proc/self/status` fields present on modern kernels (`RssAnon` /
/// `RssFile` / `VmRSS`). Fall back to `smaps_rollup` (`Anonymous:`, `Rss:`,
/// `Locked:`) when status split is missing — older rollups do **not** expose
/// `RssAnon:` / `RssFile:` (that bug made `ibd: sizes` print `anon=0 file=0`).
pub fn read_proc_rss() -> ProcRss {
    let mut out = ProcRss::default();
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
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
                // Shmem is neither classic anon nor file-backed table mmap; fold
                // into file for operator "not heap" view if present.
                let sh = parse_kb_field(rest);
                if sh > 0 {
                    out.file_kb = out.file_kb.saturating_add(sh);
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Rss:") {
                if out.rss_kb == 0 {
                    out.rss_kb = parse_kb_field(rest);
                }
            } else if let Some(rest) = line.strip_prefix("Anonymous:") {
                // Rollup name when status RssAnon missing.
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
        // If we have RSS + anon but no file split, residual is file-backed.
        if out.file_kb == 0 && out.rss_kb > 0 && out.anon_kb > 0 && out.anon_kb <= out.rss_kb {
            out.file_kb = out.rss_kb.saturating_sub(out.anon_kb);
        }
    }
    out
}

fn parse_kb_field(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn kb_mib(kb: u64) -> u64 {
    kb / 1024
}

/// Occupancy + RSS for the tip-follow 5s DEBUG `tip: perf` line.
#[derive(Clone, Copy, Debug, Default)]
pub struct TipPerfSizes {
    pub rss: ProcRss,
    pub cache_bodies: usize,
    pub held_bodies: usize,
    pub sh_heads: usize,
    pub mp_live: usize,
}

/// `rss=` `anon=` `file=` `hwm=` (MiB) plus O(1) retain counts. Not the IBD residual line.
pub fn format_tip_perf_sizes(s: &TipPerfSizes) -> String {
    format!(
        "rss={}MiB anon={}MiB file={}MiB hwm={}MiB cache={} held={} sh_heads={} mp_live={}",
        kb_mib(s.rss.rss_kb),
        kb_mib(s.rss.anon_kb),
        kb_mib(s.rss.file_kb),
        kb_mib(s.rss.hwm_kb),
        s.cache_bodies,
        s.held_bodies,
        s.sh_heads,
        s.mp_live,
    )
}

/// Sample every counter once and reset atomics.
pub(crate) fn sample(
    loop_stats: &LoopStats,
    inflight: usize,
    inflight_cap: usize,
    // In-RAM block queue: (bytes, count, soft_stop_n).
    bq: (u64, usize, u32),
    arch_ahead: u32,
    hole: usize,
    peers: usize,
    headers_done: bool,
    // (ready_through, ahead, parents, bodies, plans).
    load: (u32, u32, usize, usize, usize),
    conf_ready: usize,
    conf_script_q: usize,
    conf_write_q: usize,
    conf_q_hwm: (usize, usize, usize),
    sh_runs: usize,
    work: WorkStructureSizes,
    owned: ProcessOwnedSizes,
    conf_pipe: ConfirmPipelineSizes,
    rss: ProcRss,
) -> IbdPerfSample {
    let (bq_bytes, bq_count, bq_soft_stop) = bq;
    let hot = loop_stats.sample_and_reset();
    let thr = super::confirm::confirm_thr_stats::sample_and_reset();
    let stamp_sub = rbitcoin_consensus::plan_stamp_sub_stats::sample_and_reset();
    let (
        recon_ns,
        wire_ns,
        connect_ns,
        script_ns,
        class_c_ns,
        strong_ns,
        sh_ns,
        tip_ns,
        utxo_apply_ns,
        phase_blks,
        resolve_ns,
        load_ns,
        _unpin_ns,
        cache_tip_ns,
        spend_ranged,
        spend_idx,
        spend_skip,
        structural_ns,
        structural_spent_ns,
        structural_create_h_ns,
        structural_bip68_ns,
    ) = rbitcoin_consensus::confirm_phase_stats::sample_and_reset();
    let (class_a_ns, ensure_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_class_a_ensure_and_reset();
    let recent_pub_ns = rbitcoin_consensus::confirm_phase_stats::sample_write_recent_and_reset();
    let (recent_idx_ns, recent_clone_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_write_recent_parts_and_reset();
    let (drain_join_ns, dequeue_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_write_residuals_and_reset();
    let (pins_take_ns, pins_map_ns, head_sub_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_write_pins_and_reset();
    let pins_ns = pins_take_ns.saturating_add(pins_map_ns);
    let class_c_join_ns = rbitcoin_consensus::confirm_phase_stats::sample_class_c_join_and_reset();
    let tweak_ns = rbitcoin_consensus::confirm_phase_stats::sample_tweak_and_reset();
    let (spent_abs_ns, spent_strong_ns, spent_cold_ns, spent_pending_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_spent_sub_and_reset();
    let (script_jobs, script_skip) =
        rbitcoin_consensus::confirm_phase_stats::sample_script_mix_and_reset();
    let (ann_ns, ann_n, ann_pread_skip, ann_pread) =
        rbitcoin_consensus::confirm_phase_stats::sample_spend_ann_and_reset();
    let (meta_ns, meta_n) = rbitcoin_consensus::confirm_phase_stats::sample_spend_meta_and_reset();
    let (ensure_res_hit, ensure_cold_n) =
        rbitcoin_consensus::confirm_phase_stats::sample_ensure_mix_and_reset();
    let (asm_prevout_ns, asm_sigop_ns, asm_final_ns, asm_job_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_assemble_and_reset();
    let (
        asm_in_n,
        asm_prev_batch_ns,
        asm_prev_batch_n,
        asm_prev_same_ns,
        asm_prev_same_n,
        asm_prev_cold_ns,
        asm_prev_cold_n,
        asm_prev_fk_ns,
    ) = rbitcoin_consensus::confirm_phase_stats::sample_assemble_prevout_detail_and_reset();
    let (asm_cold_null_fk_n, asm_cold_not_pin_n, asm_cold_txid_mismatch_n, asm_cold_vout_miss_n) =
        rbitcoin_consensus::confirm_phase_stats::sample_assemble_cold_why_and_reset();
    let (prep_wire_arc_ns, prep_struct_ns, prep_header_ns, prep_prepare_ns, prep_filter_plan_ns) =
        rbitcoin_consensus::confirm_phase_stats::sample_prep_residual_and_reset();
    let (sh_collect, sh_sort, sh_seed, sh_body, sh_head) =
        rbitcoin_query::class_c_phase_stats::sample_sh_sub_and_reset();
    let (sh_collect_pin, sh_collect_cold) =
        rbitcoin_query::class_c_phase_stats::sample_sh_collect_src_and_reset();
    let (wf_body_store, wf_store_body_ns) =
        rbitcoin_query::wave_fill_stats::sample_store_and_reset();
    let pw = rbitcoin_query::confirm_load_stats::sample_and_reset();
    let dens = rbitcoin_consensus::lookup_stage_stats::sample_and_reset();
    let arch_res = rbitcoin_query::archive_phase_stats::sample_and_reset();
    let head_res = rbitcoin_store::head_resolve_stats::sample_and_reset();
    let (load_ready_through, _cache_ahead, _cache_parents, cache_bodies, cache_plans) = load;

    IbdPerfSample {
        inflight,
        inflight_cap,
        bq_bytes,
        bq_count,
        bq_soft_stop,
        arch_ahead,
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
        recon_ms: ns_ms(recon_ns),
        wire_ms: ns_ms(wire_ns),
        connect_ms: ns_ms(connect_ns),
        script_ms: ns_ms(script_ns),
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
            tweak_ms: ns_ms(tweak_ns),
            tweak_ns,
            cache_tip_ms: ns_ms(cache_tip_ns),
            cache_tip_ns,
            recent_pub_ms: ns_ms(recent_pub_ns),
            recent_pub_ns,
            pins_ms: ns_ms(pins_ns),
            pins_ns,
            head_sub_ms: ns_ms(head_sub_ns),
            head_sub_ns,
            class_c_join_ms: ns_ms(class_c_join_ns),
            class_c_join_ns,
            drain_join_ms: ns_ms(drain_join_ns),
            drain_join_ns,
            dequeue_ms: ns_ms(dequeue_ns),
            dequeue_ns,
        },
        ensure_res_hit,
        ensure_cold_n,
        recent_idx_ms: ns_ms(recent_idx_ns),
        recent_clone_ms: ns_ms(recent_clone_ns),
        pins_take_ms: ns_ms(pins_take_ns),
        pins_map_ms: ns_ms(pins_map_ns),
        asm_prevout_ms: ns_ms(asm_prevout_ns),
        asm_sigop_ms: ns_ms(asm_sigop_ns),
        asm_final_ms: ns_ms(asm_final_ns),
        asm_job_ms: ns_ms(asm_job_ns),
        asm_in_n,
        asm_prev_batch_ms: ns_ms(asm_prev_batch_ns),
        asm_prev_batch_n,
        asm_prev_same_ms: ns_ms(asm_prev_same_ns),
        asm_prev_same_n,
        asm_prev_cold_ms: ns_ms(asm_prev_cold_ns),
        asm_prev_cold_n,
        asm_cold_null_fk_n,
        asm_cold_not_pin_n,
        asm_cold_txid_mismatch_n,
        asm_cold_vout_miss_n,
        asm_prev_fk_ms: ns_ms(asm_prev_fk_ns),
        strong_ms: ns_ms(strong_ns),
        structural_spent_ms: ns_ms(structural_spent_ns),
        spent_abs_ms: ns_ms(spent_abs_ns),
        spent_strong_ms: ns_ms(spent_strong_ns),
        spent_cold_ms: ns_ms(spent_cold_ns),
        spent_pending_ms: ns_ms(spent_pending_ns),
        structural_create_h_ms: ns_ms(structural_create_h_ns),
        structural_bip68_ms: ns_ms(structural_bip68_ns),
        spend_ranged,
        spend_idx,
        spend_skip,
        ann_ms: ns_ms(ann_ns),
        ann_n,
        ann_pread_skip,
        ann_pread,
        meta_ms: ns_ms(meta_ns),
        meta_n,
        resolve_ms: ns_ms(resolve_ns),
        load_ms: ns_ms(load_ns),
        prep_wire_arc_ms: ns_ms(prep_wire_arc_ns),
        prep_struct_ms: ns_ms(prep_struct_ns),
        prep_header_ms: ns_ms(prep_header_ns),
        prep_prepare_ms: ns_ms(prep_prepare_ns),
        prep_filter_plan_ms: ns_ms(prep_filter_plan_ns),
        recon_ns,
        wire_ns,
        connect_ns,
        script_ns,
        strong_ns,
        tip_ns,
        structural_spent_ns,
        structural_create_h_ns,
        structural_bip68_ns,
        resolve_ns,
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
        load_win_ms: ns_ms(pw.ns),
        load_blocks: pw.blocks,
        load_utxo_parents: pw.utxo_parents,
        load_creates: pw.creates,
        load_parent_unique: pw.parent_unique,
        load_pin_cache_body: pw.pin_cache_body,
        load_pin_plan: pw.pin_plan,
        load_pin_new: pw.pin_new,
        load_pin_body_ms: ns_ms(pw.pin_body_ns),
        load_pin_new_meta_ms: ns_ms(pw.pin_new_meta_ns),
        load_plan_pin_ms: ns_ms(pw.plan_pin_ns),
        load_pin_adopt_ms: ns_ms(pw.pin_adopt_ns),
        load_pin_range_fill_ms: ns_ms(pw.pin_range_fill_ns),
        load_pin_recent_outs_ms: ns_ms(pw.pin_recent_outs_ns),
        load_pin_contract_ms: ns_ms(pw.pin_contract_ns),
        load_pin_publish_ms: ns_ms(pw.pin_publish_ns),
        load_cold_io_ms: ns_ms(pw.cold_io_ns),
        load_cold_range_ms: ns_ms(pw.cold_range_ns),
        load_cold_range_n: pw.cold_range_n,
        load_cold_range_body_ms: ns_ms(pw.cold_range_body_ns),
        load_cold_range_decode_ms: ns_ms(pw.cold_range_decode_ns),
        load_cold_idx_ms: ns_ms(pw.cold_idx_ns),
        load_cold_idx_n: pw.cold_idx_n,
        load_cold_decode_ms: ns_ms(pw.cold_decode_ns),
        load_body_tx_reads: pw.body_tx,
        load_parent_tx_reads: pw.parent_tx,
        load_missing_parents: pw.missing,
        load_ready_through,
        cache_bodies,
        cache_plans,
        conf_ready,
        conf_script_q,
        conf_write_q,
        conf_script_q_cap: super::confirm::script_queue_cap(),
        conf_write_q_cap: super::confirm::write_queue_cap(),
        conf_script_q_hwm: conf_q_hwm.1,
        conf_write_q_hwm: conf_q_hwm.2,
        thr_lookup_claim_ms: ns_ms(thr.lookup_claim_ns),
        thr_lookup_stamp_ms: ns_ms(thr.lookup_stamp_ns),
        thr_lookup_other_ms: ns_ms(thr.lookup_other_ns),
        thr_lookup_send_wait_ms: ns_ms(thr.lookup_send_wait_ns),
        stamp_struct_ms: ns_ms(stamp_sub.struct_ns),
        stamp_struct_txid_ms: ns_ms(stamp_sub.struct_txid_ns),
        stamp_struct_walk_ms: ns_ms(stamp_sub.struct_walk_ns),
        stamp_prepare_ms: ns_ms(stamp_sub.prepare_ns),
        stamp_filter_ms: ns_ms(stamp_sub.filter_ns),
        stamp_batch_ms: ns_ms(stamp_sub.batch_ns),
        stamp_batch_assign_ms: ns_ms(arch_res.prep_assign_ns),
        stamp_batch_collect_ms: ns_ms(arch_res.prep_collect_ns),
        stamp_batch_head_ms: ns_ms(arch_res.prep_head_ns),
        stamp_batch_head_fk_ms: ns_ms(arch_res.prep_head_fk_ns),
        stamp_batch_stamp_ms: ns_ms(arch_res.prep_stamp_ns),
        stamp_batch_finish_ms: ns_ms(arch_res.prep_finish_ns),
        thr_load_recv_wait_ms: ns_ms(thr.load_recv_wait_ns),
        thr_load_pack_ms: ns_ms(thr.load_pack_ns),
        thr_load_clone_ms: ns_ms(thr.load_clone_ns),
        thr_load_stamp_ms: ns_ms(thr.load_stamp_ns),
        thr_load_pin_ms: ns_ms(thr.load_pin_ns),
        thr_load_asm_ms: ns_ms(thr.load_asm_ns),
        thr_load_prune_ms: ns_ms(thr.load_prune_ns),
        thr_load_send_wait_ms: ns_ms(thr.load_send_wait_ns),
        script_jobs,
        script_skip,
        thr_script_recv_wait_ms: ns_ms(thr.script_recv_wait_ns),
        thr_script_work_ms: ns_ms(thr.script_work_ns),
        thr_script_send_wait_ms: ns_ms(thr.script_send_wait_ns),
        thr_write_recv_wait_ms: ns_ms(thr.write_recv_wait_ns),
        thr_write_work_ms: ns_ms(thr.write_work_ns),
        plan_blks: dens.blocks,
        plan_ms: ns_ms(dens.total_ns),
        plan_collect_ms: ns_ms(dens.collect_ns),
        plan_head_ms: ns_ms(dens.head_ns),
        plan_cold_io_ms: ns_ms(dens.cold_io_ns),
        lookup_decode_ms: ns_ms(dens.decode_ns),
        lookup_precompute_ms: ns_ms(dens.precompute_ns),
        lookup_wave_head_ms: ns_ms(dens.wave_head_ns),
        lookup_wave_head_probe_ms: ns_ms(head_res.probe_ns),
        lookup_wave_head_io_ms: ns_ms(head_res.body_ns.saturating_add(head_res.idx_ns)),
        lookup_wave_head_preads: head_res.body_lookups,
        lookup_wave_spent_ms: ns_ms(dens.wave_spent_ns),
        plan_parents: dens.parents,
        plan_already: dens.already,
        plan_cold: dens.cold,
        plan_same_batch: dens.unresolved,
        load_hdr_ms: ns_ms(pw.header_ns),
        load_decode_ms: ns_ms(pw.body_decode_ns),
        load_thin_ms: ns_ms(pw.thin_ns),
        load_parent_pin_ms: ns_ms(pw.parent_pin_ns),
        load_cache_put_ms: ns_ms(pw.cache_put_ns),
        load_edge_same: pw.edge_same_batch,
        load_edge_fk: pw.edge_fk,
        load_edge_cb: pw.edge_coinbase,
        arch_ext_need: arch_res.ext_need,
        arch_head_need: arch_res.head_need,
        arch_head_hit: arch_res.head_hit,
        leftover_pend: arch_res.leftover_pend,
        leftover_cdf0_pct: arch_res.leftover_cdf0_pct,
        leftover_cdf3_pct: arch_res.leftover_cdf3_pct,
        leftover_age_n: arch_res.leftover_age_n,
        arch_pin_txid: arch_res.pin_txid_n,
        arch_pin_txid_ms: ns_ms(arch_res.pin_txid_ns),
        arch_recent_n: arch_res.recent_n,
        arch_recent_ms: ns_ms(arch_res.recent_ns),
        arch_batch_stamp: arch_res.batch_stamp,
        arch_resolve_ns: arch_res.resolve_ns,
        arch_resolve_blocks: arch_res.blocks,
        arch_prep_assign_ms: ns_ms(arch_res.prep_assign_ns),
        arch_prep_collect_ms: ns_ms(arch_res.prep_collect_ns),
        arch_prep_inflight_ms: ns_ms(arch_res.prep_inflight_ns),
        arch_prep_head_ms: ns_ms(arch_res.prep_head_ns),
        arch_prep_head_fk_ms: ns_ms(arch_res.prep_head_fk_ns),
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
        arch_prep_stamp_ms: ns_ms(arch_res.prep_stamp_ns),
        arch_prep_finish_ms: ns_ms(arch_res.prep_finish_ns),
        arch_write_total_ms: ns_ms(arch_res.write_total_ns),
        arch_write_reserve_ms: ns_ms(arch_res.write_reserve_ns),
        arch_write_body_ms: ns_ms(arch_res.write_body_ns),
        arch_write_head_ms: ns_ms(arch_res.write_head_ns),
        arch_write_spend_ms: ns_ms(arch_res.write_spend_ns),
        arch_write_htxs_ms: ns_ms(arch_res.write_htxs_ns),
        arch_write_flush_ms: ns_ms(arch_res.write_flush_ns),
        arch_write_blocks: arch_res.write_blocks,
        rss_kb: rss.rss_kb,
        rss_anon_kb: rss.anon_kb,
        rss_file_kb: rss.file_kb,
        vm_hwm_kb: rss.hwm_kb,
        rss_locked_kb: rss.locked_kb,
        work,
        owned,
        conf_pipe,
    }
}

fn ns_ms(ns: u64) -> u64 {
    ns / 1_000_000
}

fn pin_txid_pct(s: &IbdPerfSample) -> u64 {
    let tot = s.arch_pin_txid.saturating_add(s.arch_head_need);
    if tot == 0 {
        0
    } else {
        (100 * s.arch_pin_txid) / tot
    }
}

fn us_pin_txid(s: &IbdPerfSample) -> u64 {
    if s.arch_pin_txid == 0 {
        0
    } else {
        s.arch_pin_txid_ms.saturating_mul(1000) / s.arch_pin_txid
    }
}

/// Append ` key=value` only when `v != 0` (keeps DEBUG free of ghost columns).
#[inline]
fn append_nz(out: &mut String, key: &str, v: u64) {
    if v != 0 {
        out.push_str(&format!(" {key}={v}"));
    }
}

/// Pin + assemble stage wall (`load=` on INFO). Not the load OS-thread total.
fn load_stage_wall_ms(s: &IbdPerfSample) -> u64 {
    s.load_ms.saturating_add(s.connect_ms)
}

/// Plan-batch sub-wall sum (assign/collect/head/stamp/finish) when present.
fn plan_batch_ms(s: &IbdPerfSample) -> u64 {
    s.arch_prep_assign_ms
        .saturating_add(s.arch_prep_collect_ms)
        .saturating_add(s.arch_prep_inflight_ms)
        .saturating_add(s.arch_prep_head_ms)
        .saturating_add(s.arch_prep_stamp_ms)
        .saturating_add(s.arch_prep_finish_ms)
}

/// Write-stage exclusive work sum for this window (may exceed join wall slightly).
///
/// Class A + denserels ensure + structural + **Class C tables** (strong+tip) +
/// **SH** (parallel with strong on tip; was previously folded into a join-wall
/// `class_c`) + spend annotate + SP tweaks + tip GC.
fn write_stage_ms(s: &IbdPerfSample) -> u64 {
    s.write.stage_ms()
}

/// Stable DEBUG meter line (unified load→scripts→write).
pub(crate) fn format_info(s: &IbdPerfSample) -> String {
    let bq_mib = s.bq_bytes / (1024 * 1024);
    let write_ms = write_stage_ms(s);
    let mut out = format!(
        "ibd: perf inflight={}/{} bq soft={}/{} RAM={}MiB buf_ahead={} hole={} peers={}",
        s.inflight,
        s.inflight_cap,
        s.bq_count,
        s.bq_soft_stop,
        bq_mib,
        s.arch_ahead,
        s.hole,
        s.peers,
    );
    let load_wall_ms = load_stage_wall_ms(s);
    let thr_lookup_busy = s.thr_lookup_stamp_ms.saturating_add(s.thr_lookup_other_ms);
    let thr_lookup_wait = s
        .thr_lookup_claim_ms
        .saturating_add(s.thr_lookup_send_wait_ms);
    let thr_load_busy = s
        .thr_load_pack_ms
        .saturating_add(s.thr_load_clone_ms)
        .saturating_add(s.thr_load_stamp_ms)
        .saturating_add(s.thr_load_pin_ms)
        .saturating_add(s.thr_load_asm_ms)
        .saturating_add(s.thr_load_prune_ms);
    let thr_load_wait = s
        .thr_load_recv_wait_ms
        .saturating_add(s.thr_load_send_wait_ms);
    let thr_script_wait = s
        .thr_script_recv_wait_ms
        .saturating_add(s.thr_script_send_wait_ms);
    let stamp_head_ms = s.stamp_batch_head_fk_ms;
    let stamp_pack_ms = s.thr_load_stamp_ms.saturating_sub(stamp_head_ms);
    out.push_str(&format!(
        " | conf blks={} lookup={}ms load={}ms script={}ms(jobs={} skip={}) write={}ms \
         lookup_thr busy={}ms(claim={}ms wave={}ms(decode={}ms precompute={}ms collect={}ms head={}ms(probe={}ms io={}ms preads={}) spent={}ms) other={}ms send_w={}ms) \
         load_thr busy/wait={}/{}ms(pack={}ms clone={}ms stamp={}ms(pack={}ms head={}ms) pin={}ms asm={}ms prune={}ms send_w={}ms) \
         thr script={}/{}ms write={}/{}ms \
         ready={} scriptq_hwm={}/{} writeq_hwm={}/{}",
        s.phase_blks.max(s.plan_blks),
        s.plan_ms,
        load_wall_ms,
        s.script_ms,
        s.script_jobs,
        s.script_skip,
        write_ms,
        thr_lookup_busy,
        s.thr_lookup_claim_ms,
        s.thr_lookup_stamp_ms,
        s.lookup_decode_ms,
        s.lookup_precompute_ms,
        s.plan_collect_ms,
        s.lookup_wave_head_ms,
        s.lookup_wave_head_probe_ms,
        s.lookup_wave_head_io_ms,
        s.lookup_wave_head_preads,
        s.lookup_wave_spent_ms,
        s.thr_lookup_other_ms,
        s.thr_lookup_send_wait_ms,
        thr_load_busy,
        thr_load_wait,
        s.thr_load_pack_ms,
        s.thr_load_clone_ms,
        s.thr_load_stamp_ms,
        stamp_pack_ms,
        stamp_head_ms,
        s.thr_load_pin_ms,
        s.thr_load_asm_ms,
        s.thr_load_prune_ms,
        s.thr_load_send_wait_ms,
        s.thr_script_work_ms,
        thr_script_wait,
        s.thr_write_work_ms,
        s.thr_write_recv_wait_ms,
        s.conf_ready,
        s.conf_script_q_hwm,
        s.conf_script_q_cap,
        s.conf_write_q_hwm,
        s.conf_write_q_cap,
    ));
    let _ = thr_lookup_wait;
    if s.stamp_struct_ms > 0
        || s.stamp_prepare_ms > 0
        || s.stamp_batch_ms > 0
        || s.thr_lookup_stamp_ms > 0
    {
        out.push_str(&format!(
            " stamp_sub(struct={}ms struct_txid={}ms struct_walk={}ms prepare={}ms filter={}ms batch={}ms \
             batch_assign={}ms collect={}ms pin_txid={} pin_txid%={} pin_txid_ms={} \
             leftover_n={} leftover_hit={} leftover_ms={} leftover_pend={} leftover_cdf0={} leftover_cdf3={} leftover_age_n={} \
             recent={} recent_ms={} \
             head={}ms stamp={}ms finish={}ms)",
            s.stamp_struct_ms,
            s.stamp_struct_txid_ms,
            s.stamp_struct_walk_ms,
            s.stamp_prepare_ms,
            s.stamp_filter_ms,
            s.stamp_batch_ms,
            s.stamp_batch_assign_ms,
            s.stamp_batch_collect_ms,
            s.arch_pin_txid,
            pin_txid_pct(s),
            s.arch_pin_txid_ms,
            s.arch_head_need,
            s.arch_head_hit,
            s.stamp_batch_head_fk_ms,
            s.leftover_pend,
            s.leftover_cdf0_pct,
            s.leftover_cdf3_pct,
            s.leftover_age_n,
            s.arch_recent_n,
            s.arch_recent_ms,
            s.stamp_batch_head_ms,
            s.stamp_batch_stamp_ms,
            s.stamp_batch_finish_ms,
        ));
    }
    if s.arch_prep_age_hit_n > 0 {
        out.push_str(&format!(
            " head_loc(cdf0={} cdf3={} cdf7={} cdf15={} cdf31={} n={})",
            s.arch_prep_age_cdf0_pct,
            s.arch_prep_age_cdf3_pct,
            s.arch_prep_age_cdf7_pct,
            s.arch_prep_age_cdf15_pct,
            s.arch_prep_age_cdf31_pct,
            s.arch_prep_age_hit_n,
        ));
    }
    if s.plan_blks > 0 || s.plan_ms > 0 {
        out.push_str(&format!(
            " lookup_sub(blks={} parents={} already={} cold={} same={} collect={}ms decode={}ms precompute={}ms head={}ms spent={}ms stamp_head={}ms cold_io={}ms)",
            s.plan_blks,
            s.plan_parents,
            s.plan_already,
            s.plan_cold,
            s.plan_same_batch,
            s.plan_collect_ms,
            s.lookup_decode_ms,
            s.lookup_precompute_ms,
            s.lookup_wave_head_ms,
            s.lookup_wave_spent_ms,
            s.plan_head_ms,
            s.plan_cold_io_ms,
        ));
    }
    append_nz(&mut out, "recon_ms", s.recon_ms);
    append_nz(&mut out, "wire_ms", s.wire_ms);
    append_nz(&mut out, "resolve_ms", s.resolve_ms);

    // CACHE_BODY is adopt / plan / in-flight / same-batch only — this
    // window's cold range-fills increment PIN_NEW, not cache.
    let pin_hit_pct = {
        let hits = s.load_pin_cache_body;
        let tot = hits.saturating_add(s.load_pin_new);
        if tot > 0 {
            (100 * hits) / tot
        } else {
            0
        }
    };
    let plan_pin_ms = if s.load_plan_pin_ms > 0 {
        s.load_plan_pin_ms
    } else {
        s.load_pin_body_ms
    };
    let cold_io_ms = if s.load_cold_io_ms > 0 {
        s.load_cold_io_ms
    } else {
        s.load_pin_new_meta_ms
    };
    let cold_dec_ms = s.load_cold_decode_ms;
    let cold_range_ms = s.load_cold_range_ms;
    let cold_idx_ms = s.load_cold_idx_ms;
    let cold_for_us = if cold_range_ms + cold_idx_ms > 0 {
        cold_range_ms.saturating_add(cold_idx_ms)
    } else {
        cold_io_ms
    };
    let pin_cold_us_per = if s.load_pin_new > 0 {
        (cold_for_us.saturating_mul(1000)) / s.load_pin_new
    } else {
        0
    };
    let asm_prev_us_per_in = if s.asm_in_n > 0 {
        (s.asm_prevout_ms.saturating_mul(1000)) / s.asm_in_n
    } else {
        0
    };
    let plan_batch = plan_batch_ms(s);
    let pre_assemble = s.load_ms;
    let pin_budget_ms = s.load_parent_pin_ms;
    let asm_budget_ms = s.connect_ms;
    let other_budget_ms = load_wall_ms
        .saturating_sub(pin_budget_ms)
        .saturating_sub(asm_budget_ms);
    out.push_str(&format!(
        " | load_budget total={}ms pin={}ms asm={}ms other={}ms",
        load_wall_ms, pin_budget_ms, asm_budget_ms, other_budget_ms,
    ));
    out.push_str(&format!(
        " | load blks={} total={}ms pre_asm={}ms(wire_arc={}ms struct={}ms header={}ms prepare={}ms \
         filter_plan={}ms plan_batch={}ms pin={}ms) \
         assemble={}ms(prevout={} us/in={} batch={}/n={} same={}/n={} cold={}/n={} \
         cold_why(null_fk={} not_pin={} mismatch={} vout_miss={}) fk={}ms \
         sigop={} final={} job={}) \
         pin(thin={}ms plan={}ms/n={} cold_range={}ms(body={} dec={})/n={} cold_idx={}ms/n={} cold_io={}ms cold_dec={}ms us/new={} \
         adopt={}ms recent_outs={}ms range_fill={}ms contract={}ms publish={}ms) \
         pin_hit%={} pin_plan={} pin_new={} body_io={} parent_io={}",
        s.load_blocks,
        load_wall_ms,
        pre_assemble,
        s.prep_wire_arc_ms,
        s.prep_struct_ms,
        s.prep_header_ms,
        s.prep_prepare_ms,
        s.prep_filter_plan_ms,
        plan_batch,
        s.load_parent_pin_ms,
        s.connect_ms,
        s.asm_prevout_ms,
        asm_prev_us_per_in,
        s.asm_prev_batch_ms,
        s.asm_prev_batch_n,
        s.asm_prev_same_ms,
        s.asm_prev_same_n,
        s.asm_prev_cold_ms,
        s.asm_prev_cold_n,
        s.asm_cold_null_fk_n,
        s.asm_cold_not_pin_n,
        s.asm_cold_txid_mismatch_n,
        s.asm_cold_vout_miss_n,
        s.asm_prev_fk_ms,
        s.asm_sigop_ms,
        s.asm_final_ms,
        s.asm_job_ms,
        s.load_thin_ms,
        plan_pin_ms,
        s.load_pin_plan,
        cold_range_ms,
        s.load_cold_range_body_ms,
        s.load_cold_range_decode_ms,
        s.load_cold_range_n,
        cold_idx_ms,
        s.load_cold_idx_n,
        cold_io_ms,
        cold_dec_ms,
        pin_cold_us_per,
        s.load_pin_adopt_ms,
        s.load_pin_recent_outs_ms,
        s.load_pin_range_fill_ms,
        s.load_pin_contract_ms,
        s.load_pin_publish_ms,
        pin_hit_pct,
        s.load_pin_plan,
        s.load_pin_new,
        s.load_body_tx_reads,
        s.load_parent_tx_reads,
    ));
    if s.load_win_ms > 0 {
        out.push_str(&format!(" pin_win={}ms", s.load_win_ms));
    }
    if s.load_edge_same > 0 || s.load_edge_fk > 0 || s.load_edge_cb > 0 {
        out.push_str(&format!(
            " edges same={} fk={} cb={}",
            s.load_edge_same, s.load_edge_fk, s.load_edge_cb
        ));
    }
    if s.load_missing_parents > 0 {
        out.push_str(&format!(" miss_p={}", s.load_missing_parents));
    }

    out.push_str(&format!(
        " | write class_a={}ms ensure={}ms(pin={} cold={}) struct={}ms(spent={} create_h={} bip68={}) \
         spent_sub(abs={} strong={} cold={} pending={}) \
         class_c={}ms class_c_join={}ms sh={}ms spend={}ms tweaks={}ms tip_gc={}ms recent_pub={}ms(idx={} clone={}) \
         pins={}ms(take={} map={}) head_sub={}ms drain_join={}ms dequeue={}ms other={}ms \
         ann={}ms/n={} pread_skip={} pread={} \
         meta={}ms/n={}",
        s.write.class_a_ms,
        s.write.ensure_ms,
        s.ensure_res_hit,
        s.ensure_cold_n,
        s.write.structural_ms,
        s.structural_spent_ms,
        s.structural_create_h_ms,
        s.structural_bip68_ms,
        s.spent_abs_ms,
        s.spent_strong_ms,
        s.spent_cold_ms,
        s.spent_pending_ms,
        s.write.class_c_ms,
        s.write.class_c_join_ms,
        s.write.sh_ms,
        s.write.utxo_ms,
        s.write.tweak_ms,
        s.write.cache_tip_ms,
        s.write.recent_pub_ms,
        s.recent_idx_ms,
        s.recent_clone_ms,
        s.write.pins_ms,
        s.pins_take_ms,
        s.pins_map_ms,
        s.write.head_sub_ms,
        s.write.drain_join_ms,
        s.write.dequeue_ms,
        s.thr_write_work_ms.saturating_sub(write_stage_ms(s)),
        s.ann_ms,
        s.ann_n,
        s.ann_pread_skip,
        s.ann_pread,
        s.meta_ms,
        s.meta_n,
    ));
    if s.arch_write_body_ms > 0 || s.arch_write_head_ms > 0 || s.arch_write_htxs_ms > 0 {
        out.push_str(&format!(
            " class_a_sub(body={} head={} htxs={} reserve={})",
            s.arch_write_body_ms,
            s.arch_write_head_ms,
            s.arch_write_htxs_ms,
            s.arch_write_reserve_ms,
        ));
    }
    append_nz(&mut out, "strong_ms", s.strong_ms);
    if s.spend_idx > 0 || s.spend_skip > 0 {
        out.push_str(&format!(
            " spend_mix(r={} i={} skip={})",
            s.spend_ranged, s.spend_idx, s.spend_skip
        ));
    }

    let conf_q = super::confirm::format_conf_q(
        s.conf_pipe.load_batches,
        s.conf_script_q,
        s.conf_write_q,
        super::confirm::load_queue_cap(),
        s.conf_script_q_cap,
        s.conf_write_q_cap,
    );
    out.push_str(&format!(
        " | {conf_q} thru={} sh_runs={}",
        s.load_ready_through, s.sh_runs,
    ));

    out.push_str(&format!(
        " | loop {} conf={}ms assign={}ms",
        s.dominant, s.confirm_ms, s.assign_ms,
    ));
    append_nz(&mut out, "getdata", s.assign_issued);
    append_nz(&mut out, "drain_ms", s.drain_ms);
    if s.confirm_reject_stops > 0 {
        out.push_str(&format!(" reject={}", s.confirm_reject_stops));
    }
    if let Some((first, n, inputs, elapsed_ms)) = s.live {
        out.push_str(&format!(
            " | live h={first} n={n} in={inputs} {elapsed_ms}ms"
        ));
    }
    if s.headers_done {
        out.push_str(" headers_done");
    }
    out
}

/// DEBUG detail: µs/blk + pin/edge; class_a commit detail.
pub(crate) fn format_debug(s: &IbdPerfSample) -> String {
    let denom = s.phase_blks.max(1);
    let us = |ns: u64| (ns / denom) / 1000;
    let prep_ns = s.load_ns.saturating_add(s.connect_ns);
    // Exclusive write attribution: class_c is tables-only; include SH separately
    // (parallel with strong — sum may exceed join wall by ~strong).
    let write_ns = s.write.stage_ns();
    let mut out = format!(
        "ibd: perf_dbg us/blk load={} (pre_asm={} assemble={}) script={} write={} \
         class_a={} ensure={} struct={} spent={} create_h={} bip68={} class_c={} sh={} \
         spend={}(r={} i={} skip={}) tweaks={} tip_gc={} recent_pub={} pins={} head_sub={} drain_join={} dequeue={}",
        us(prep_ns),
        us(s.load_ns),
        us(s.connect_ns),
        us(s.script_ns),
        us(write_ns),
        us(s.write.class_a_ns),
        us(s.write.ensure_ns),
        us(s.write.structural_ns),
        us(s.structural_spent_ns),
        us(s.structural_create_h_ns),
        us(s.structural_bip68_ns),
        us(s.write.class_c_ns),
        us(s.write.sh_ns),
        us(s.write.utxo_apply_ns),
        s.spend_ranged,
        s.spend_idx,
        s.spend_skip,
        us(s.write.tweak_ns),
        us(s.write.cache_tip_ns),
        us(s.write.recent_pub_ns),
        us(s.write.pins_ns),
        us(s.write.head_sub_ns),
        us(s.write.drain_join_ns),
        us(s.write.dequeue_ns),
    );
    append_nz(&mut out, "recon_us", us(s.recon_ns));
    append_nz(&mut out, "wire_us", us(s.wire_ns));
    append_nz(&mut out, "resolve_us", us(s.resolve_ns));
    append_nz(&mut out, "strong_us", us(s.strong_ns));
    append_nz(&mut out, "tip_us", us(s.tip_ns));
    if s.wf_body_store > 0 || s.wf_store_body_ms > 0 {
        out.push_str(&format!(
            " | wire_body store={} store_ms={}",
            s.wf_body_store, s.wf_store_body_ms,
        ));
    }
    out.push_str(&format!(" | sh collect={}", s.sh_collect_ms));
    append_nz(&mut out, "sort", s.sh_sort_ms);
    append_nz(&mut out, "seed", s.sh_seed_ms);
    append_nz(&mut out, "body", s.sh_body_ms);
    append_nz(&mut out, "head", s.sh_head_ms);
    if s.sh_collect_pin > 0 || s.sh_collect_cold > 0 {
        out.push_str(&format!(
            " sh_src pin={} cold={}",
            s.sh_collect_pin, s.sh_collect_cold
        ));
    }

    let conf_q = super::confirm::format_conf_q(
        s.conf_pipe.load_batches,
        s.conf_script_q,
        s.conf_write_q,
        super::confirm::load_queue_cap(),
        s.conf_script_q_cap,
        s.conf_write_q_cap,
    );
    let bq_mib = s.bq_bytes / (1024 * 1024);
    out.push_str(&format!(
        " | bq soft={}/{} RAM={}MiB | {conf_q} | load thru={} bodies={} plans={} win_ms={} blks={} utxo_p={} creates={} uniq_p={} pin_cache={} pin_new={} body_io={} parent_io={}",
        s.bq_count,
        s.bq_soft_stop,
        bq_mib,
        s.load_ready_through,
        s.cache_bodies,
        s.cache_plans,
        s.load_win_ms,
        s.load_blocks,
        s.load_utxo_parents,
        s.load_creates,
        s.load_parent_unique,
        s.load_pin_cache_body,
        s.load_pin_new,
        s.load_body_tx_reads,
        s.load_parent_tx_reads,
    ));
    append_nz(&mut out, "miss_p", s.load_missing_parents);
    out.push_str(&format!(
        " phases hdr={} dec={} thin={} pin={} put={} pin_sub body={} new={}",
        s.load_hdr_ms,
        s.load_decode_ms,
        s.load_thin_ms,
        s.load_parent_pin_ms,
        s.load_cache_put_ms,
        s.load_pin_body_ms,
        s.load_pin_new_meta_ms,
    ));
    out.push_str(&format!(
        " edges same={} fk={} cb={}",
        s.load_edge_same, s.load_edge_fk, s.load_edge_cb,
    ));
    out.push_str(&format!(" sh_runs={}", s.sh_runs));

    if s.arch_ext_need > 0 || s.arch_prep_assign_ms > 0 {
        let resolve_us_blk = if s.arch_resolve_blocks > 0 {
            (s.arch_resolve_ns / s.arch_resolve_blocks) / 1000
        } else {
            0
        };
        out.push_str(&format!(
            " | plan_batch assign={} collect={} inflight={} pin_txid={}/{} pin_txid_ms={} \
             us/pin_txid={} recent={} recent_ms={} head_fk={} head={} \
             stamp={} finish={} resolve_us/blk={} ext={} head_hit={}/{} \
             stamp_n batch={}",
            s.arch_prep_assign_ms,
            s.arch_prep_collect_ms,
            s.arch_prep_inflight_ms,
            s.arch_pin_txid,
            s.arch_head_need,
            s.arch_pin_txid_ms,
            us_pin_txid(s),
            s.arch_recent_n,
            s.arch_recent_ms,
            s.arch_prep_head_fk_ms,
            s.arch_prep_head_ms,
            s.arch_prep_stamp_ms,
            s.arch_prep_finish_ms,
            resolve_us_blk,
            s.arch_ext_need,
            s.arch_head_hit,
            s.arch_head_need,
            s.arch_batch_stamp,
        ));
        if s.arch_prep_probe_ms > 0
            || s.arch_prep_idx_ms > 0
            || s.arch_prep_body_txid_ms > 0
            || s.arch_prep_head_keys > 0
        {
            let avg_cands = if s.arch_prep_head_keys > 0 {
                s.arch_prep_head_cands / s.arch_prep_head_keys
            } else {
                0
            };
            let avg_lookups = if s.arch_prep_head_keys > 0 {
                s.arch_prep_body_lookups / s.arch_prep_head_keys
            } else {
                0
            };
            let hit_rank_avg = s.arch_prep_hit_rank_avg_x100 as f64 / 100.0;
            let probe_us_key = if s.arch_prep_head_keys > 0 {
                (s.arch_prep_probe_ms * 1000) / s.arch_prep_head_keys
            } else {
                0
            };
            let idx_us_key = if s.arch_prep_head_keys > 0 {
                (s.arch_prep_idx_ms * 1000) / s.arch_prep_head_keys
            } else {
                0
            };
            let body_us_key = if s.arch_prep_head_keys > 0 {
                (s.arch_prep_body_txid_ms * 1000) / s.arch_prep_head_keys
            } else {
                0
            };
            out.push_str(&format!(
                " head_rd(probe={} idx={} body={} keys={} cands={} lookups={} \
                 avg_cands={} avg_lookups={} hit_rank_avg={hit_rank_avg:.2} hit_n={} miss_peeks={} \
                 pend={} \
                 probe_us/key={} idx_us/key={} body_us/key={} \
                 age_cdf(0={} 3={} 7={} 15={} 31={}) age_hit={} age_n={})",
                s.arch_prep_probe_ms,
                s.arch_prep_idx_ms,
                s.arch_prep_body_txid_ms,
                s.arch_prep_head_keys,
                s.arch_prep_head_cands,
                s.arch_prep_body_lookups,
                avg_cands,
                avg_lookups,
                s.arch_prep_hit_rank_n,
                s.arch_prep_miss_peeks,
                s.arch_prep_pending_hits,
                probe_us_key,
                idx_us_key,
                body_us_key,
                s.arch_prep_age_cdf0_pct,
                s.arch_prep_age_cdf3_pct,
                s.arch_prep_age_cdf7_pct,
                s.arch_prep_age_cdf15_pct,
                s.arch_prep_age_cdf31_pct,
                if s.arch_prep_age_hit_compact.is_empty() {
                    "0:0:0:0:0:0:0:0:0"
                } else {
                    s.arch_prep_age_hit_compact.as_str()
                },
                s.arch_prep_age_hit_n,
            ));
        }
    }
    if s.arch_write_blocks > 0 || s.arch_write_total_ms > 0 {
        let ca_head_us_blk = if s.arch_write_blocks > 0 {
            (s.arch_write_head_ms * 1000) / s.arch_write_blocks
        } else {
            0
        };
        let ca_body_us_blk = if s.arch_write_blocks > 0 {
            (s.arch_write_body_ms * 1000) / s.arch_write_blocks
        } else {
            0
        };
        out.push_str(&format!(
            " | class_a_commit total={} body={} head={} htxs={} reserve={} spend={} flush={} blks={} \
             ca_head_us/blk={} ca_body_us/blk={}",
            s.arch_write_total_ms,
            s.arch_write_body_ms,
            s.arch_write_head_ms,
            s.arch_write_htxs_ms,
            s.arch_write_reserve_ms,
            s.arch_write_spend_ms,
            s.arch_write_flush_ms,
            s.arch_write_blocks,
            ca_head_us_blk,
            ca_body_us_blk,
        ));
    }
    out.push_str(&format!(
        " | loop confirm_blks={} confirm_us/blk={} events={}",
        s.confirm_blocks, s.confirm_us_per_block, s.drain_events,
    ));
    append_nz(&mut out, "reject_stops", s.confirm_reject_stops);
    append_nz(&mut out, "status_scan_ms", s.status_scan_ms);
    out
}

/// Format process RSS + known retain-structure occupancy (leak triage).
///
/// All counts are O(1) lens / brief mutex snaps taken on the 5s tick. Compare
/// `anon=` growth to heap caches and `file=` growth to store mmaps (segmented
/// `tx.head.*` + fuse8). `locked=` is mlock only (usually 0) — **not** a
/// filter on what enters RSS.
///
/// Process-owned occupancy: body queue + confirm pipeline + header plans + SH + head.
pub(crate) fn format_sizes(s: &IbdPerfSample) -> String {
    let w = &s.work;
    let b = &w.body;
    let o = &s.owned;
    let h = &o.head;
    let cp = &s.conf_pipe;
    let primary_mib = h.primary_body_bytes / (1024 * 1024);
    let load_wire_mib = cp.load_wire_bytes / (1024 * 1024);
    let script_wire_mib = cp.script_wire_bytes / (1024 * 1024);
    let write_wire_mib = cp.write_wire_bytes / (1024 * 1024);
    let file_pct = if s.rss_kb > 0 {
        (100 * s.rss_file_kb) / s.rss_kb
    } else {
        0
    };
    let bq_mib = s.bq_bytes / (1024 * 1024);
    let if_mib = o.inflight_bytes / (1024 * 1024);
    let ps_mib = o.pstore_bytes / (1024 * 1024);
    // CreatePin payload bytes (Arc-shared with in-flight while overlapping).
    let recent_bytes = o.recent_pin_bytes;
    let recent_mib = recent_bytes / (1024 * 1024);
    let h2h_mib = (o.h2h_keys as u64).saturating_mul(48) / (1024 * 1024);
    let fence_mib = (o.fence_runs as u64).saturating_mul(16) / (1024 * 1024);
    let conf_wire_mib = (load_wire_mib
        .saturating_add(script_wire_mib)
        .saturating_add(write_wire_mib)) as u64;
    let fuse8_mib = h.fuse8_bytes / (1024 * 1024);
    let mphf_g_mib = h.mphf_g_bytes / (1024 * 1024);
    let open_keys_mib = h.open_keys_bytes / (1024 * 1024);
    let class_c_l2_mib = h.class_c_l2_bytes / (1024 * 1024);
    let accounted_mib = bq_mib
        .saturating_add(if_mib)
        .saturating_add(ps_mib)
        .saturating_add(recent_mib)
        .saturating_add(h2h_mib)
        .saturating_add(fence_mib)
        .saturating_add(conf_wire_mib)
        .saturating_add(fuse8_mib)
        .saturating_add(mphf_g_mib)
        .saturating_add(open_keys_mib)
        .saturating_add(class_c_l2_mib);
    let anon_mib = kb_mib(s.rss_anon_kb);
    let residual_mib = anon_mib.saturating_sub(accounted_mib);
    format!(
        "ibd: sizes rss={}MiB anon={}MiB file={}MiB({}%) hwm={}MiB locked={}MiB \
         | work ordered={}/set={} hash_h={} h2h={} hdr_fk={} known_hdr={} inflight={}/peer={} cooldown={} \
         | body known={} pend={} miss={} rej={} \
         | bq soft={}/{} RAM={}MiB \
         | conf_plans={} \
         | conf loadq={}/{} blks={} wire={}MiB scriptq={}/{} blks={} wire={}MiB writeq={}/{} blks={} wire={}MiB parents={} \
           feed ready={} inflight={} \
         | heap bq={}MiB iflight={}L/{}pin≈{}MiB recent={}h live={}k/pub={}k/ov={} fifo={}k≈{}MiB \
           h2h={}k≈{}MiB fence={}≈{}MiB \
           pstore weak={}/live={}≈{}MiB \
           wire={}MiB fuse8={}MiB mphf_g={}MiB open_keys={}MiB class_c_l2={}MiB \
           accounted≈{}MiB residual≈{}MiB \
         | txhead bits={} entry={}B slots={} occ={} body={}MiB segs={} sealed={} class_a={} \
         | sh runs={} heads={}",
        kb_mib(s.rss_kb),
        anon_mib,
        kb_mib(s.rss_file_kb),
        file_pct,
        kb_mib(s.vm_hwm_kb),
        kb_mib(s.rss_locked_kb),
        w.ordered,
        w.ordered_set,
        w.hash_height,
        w.height_to_hash,
        w.header_fks,
        w.known_headers,
        w.inflight,
        w.peer_inflight,
        w.addr_cooldown,
        b.known,
        b.pending,
        b.missing,
        b.rejected,
        s.bq_count,
        s.bq_soft_stop,
        bq_mib,
        o.conf_plans,
        cp.load_batches,
        super::confirm::load_queue_cap(),
        cp.load_blocks,
        load_wire_mib,
        cp.script_batches,
        s.conf_script_q_cap,
        cp.script_blocks,
        script_wire_mib,
        cp.write_batches,
        s.conf_write_q_cap,
        cp.write_blocks,
        write_wire_mib,
        cp.parents_total(),
        cp.feed_ready,
        cp.feed_inflight,
        bq_mib,
        o.inflight_layers,
        o.inflight_pins,
        if_mib,
        o.recent_heights,
        o.recent_keys,
        o.recent_pub_keys,
        o.recent_overlay_keys,
        o.recent_fifo_keys,
        recent_mib,
        o.h2h_keys,
        h2h_mib,
        o.fence_runs,
        fence_mib,
        o.pstore_weak,
        o.pstore_live,
        ps_mib,
        conf_wire_mib,
        fuse8_mib,
        mphf_g_mib,
        open_keys_mib,
        class_c_l2_mib,
        accounted_mib,
        residual_mib,
        h.primary_bits,
        h.primary_entry_b,
        h.primary_slots,
        h.primary_occupied,
        primary_mib,
        h.segment_count,
        h.sealed_segments,
        h.class_a_n,
        o.sh_runs,
        o.sh_heads,
    )
}

/// Emit meters at DEBUG (`ibd: progress` is a separate INFO tick).
pub(crate) fn log_sample(s: &IbdPerfSample) {
    debug!("{}", format_info(s));
    debug!("{}", format_sizes(s));
    if enabled(Level::Debug) {
        debug!("{}", format_debug(s));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn write_stage_sample_inventory_sums_to_write_token() {
        let mut write = WriteStageSample::default();
        write.class_a_ms = 1;
        write.ensure_ms = 2;
        write.structural_ms = 4;
        write.class_c_ms = 8;
        write.sh_ms = 16;
        write.utxo_ms = 32;
        write.tweak_ms = 64;
        write.cache_tip_ms = 128;
        write.drain_join_ms = 0;
        write.dequeue_ms = 0;
        assert_eq!(
            write.stage_ms(),
            255,
            "inventory: class_a+ensure+struct+class_c+sh+spend+tweaks+tip_gc+recent_pub+pins+head_sub+drain_join+dequeue"
        );
        let mut s = IbdPerfSample::default();
        s.write = write;
        assert_eq!(write_stage_ms(&s), 255);
        let line = format_info(&s);
        assert!(line.contains("write=255ms"), "{line}");
        assert!(line.contains("tweaks=64ms"), "{line}");
        assert!(line.contains("tip_gc=128ms"), "{line}");
        assert!(line.contains("spend=32ms"), "{line}");
        assert!(line.contains("recent_pub=0ms(idx=0 clone=0)"), "{line}");
        assert!(line.contains("class_c_join=0ms"), "{line}");
        assert!(line.contains("drain_join=0ms"), "{line}");
        assert!(line.contains("dequeue=0ms"), "{line}");
        assert!(line.contains("other=0ms"), "{line}");
    }

    #[test]
    fn write_other_classifies_pins_and_head_sub() {
        let mut s = IbdPerfSample::default();
        s.thr_write_work_ms = 500;
        s.write.pins_ms = 300;
        s.write.pins_ns = 300_000_000;
        s.write.head_sub_ms = 50;
        s.write.head_sub_ns = 50_000_000;
        s.pins_take_ms = 200;
        s.pins_map_ms = 100;
        let line = format_info(&s);
        assert!(line.contains("pins=300ms(take=200 map=100)"), "{line}");
        assert!(line.contains("head_sub=50ms"), "{line}");
        assert!(line.contains("write=350ms"), "{line}");
        assert!(
            line.contains("other=150ms"),
            "pins+head_sub must leave the write-thread residual: {line}"
        );
        let dbg = format_debug(&s);
        assert!(dbg.contains("pins="), "{dbg}");
        assert!(dbg.contains("head_sub="), "{dbg}");
    }

    #[test]
    fn load_and_write_stage_walls_sum_parts() {
        let mut s = IbdPerfSample::default();
        s.load_ms = 30;
        s.connect_ms = 8;
        assert_eq!(load_stage_wall_ms(&s), 38);
        s.write.class_a_ms = 15;
        s.write.ensure_ms = 2;
        s.write.structural_ms = 50;
        s.write.class_c_ms = 40; // tables only
        s.write.sh_ms = 100; // SH exclusive (parallel with strong; counted separately)
        s.write.utxo_ms = 25;
        s.write.tweak_ms = 80;
        s.write.cache_tip_ms = 5;
        // 15+2+50+40+100+25+80+5 = 317
        assert_eq!(write_stage_ms(&s), 317);
    }

    #[test]
    fn log_sample_perf_and_sizes_are_debug() {
        rbitcoin_log::capture_logs(true);
        log_sample(&IbdPerfSample::default());
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let meters: Vec<_> = logs
            .iter()
            .filter(|(_, m)| m.starts_with("ibd: perf ") || m.starts_with("ibd: sizes "))
            .collect();
        assert_eq!(meters.len(), 2, "{logs:?}");
        for (level, msg) in &meters {
            assert_eq!(*level, Level::Debug, "{level:?} {msg}");
        }
    }

    #[test]
    fn format_info_has_stable_tokens() {
        let mut s = IbdPerfSample::default();
        s.inflight = 3;
        s.inflight_cap = 256;
        s.bq_count = 7;
        s.bq_bytes = 128 * 1024 * 1024;
        s.bq_soft_stop = 180;
        s.arch_ahead = 224;
        s.hole = 0;
        s.peers = 16;
        s.phase_blks = 32;
        s.recon_ms = 100;
        s.script_ms = 20;
        s.load_ms = 30;
        s.connect_ms = 8;
        s.write.class_a_ms = 12;
        s.write.ensure_ms = 3;
        s.write.class_c_ms = 40;
        s.write.utxo_ms = 25;
        s.write.tweak_ms = 7;
        s.write.cache_tip_ms = 5;
        s.dominant = "confirm";
        s.live = Some((100, 32, 8000, 1500));
        s.confirm_reject_stops = 2;
        let line = format_info(&s);
        assert!(line.starts_with("ibd: perf "), "{line}");
        assert!(line.contains("inflight=3/256"), "{line}");
        assert!(!line.contains("body_soft="), "{line}");
        assert!(!line.contains("body_pend="), "{line}");
        assert!(!line.contains("bq n="), "{line}");
        assert!(!line.contains(" disk="), "{line}");
        assert!(line.contains("bq soft=7/180 RAM=128MiB"), "{line}");
        assert!(line.contains("buf_ahead=224"), "{line}");
        assert!(
            !line.contains("lead="),
            "schema12: no Class A lead= on perf: {line}"
        );
        assert!(!line.contains("arch_hwm"), "{line}");
        assert!(!line.contains("arch_q="), "{line}");
        assert!(line.contains("conf blks=32"), "{line}");
        assert!(line.contains("script=20ms"), "{line}");
        assert!(line.contains("script=20ms(jobs=0 skip=0)"), "{line}");
        assert!(line.contains("load_thr busy/wait="), "{line}");
        assert!(line.contains("pack=0ms"), "{line}");
        assert!(line.contains("prune=0ms"), "{line}");
        s.thr_load_pack_ms = 100;
        s.thr_load_stamp_ms = 1700;
        s.thr_load_pin_ms = 700;
        s.thr_load_prune_ms = 50;
        s.thr_load_recv_wait_ms = 200;
        s.script_jobs = 12;
        s.script_skip = 3;
        let split = format_info(&s);
        assert!(split.contains("load_thr busy/wait=2550/200ms"), "{split}");
        assert!(split.contains("pack=100ms"), "{split}");
        assert!(
            split.contains("stamp=1700ms(pack=1700ms head=0ms)"),
            "{split}"
        );
        s.stamp_batch_head_fk_ms = 200;
        let nested = format_info(&s);
        assert!(
            nested.contains("stamp=1700ms(pack=1500ms head=200ms)"),
            "{nested}"
        );
        assert!(split.contains("pin=700ms"), "{split}");
        assert!(split.contains("prune=50ms"), "{split}");
        assert!(split.contains("script=20ms(jobs=12 skip=3)"), "{split}");
        s.thr_load_clone_ms = 75;
        let with_clone = format_info(&s);
        assert!(with_clone.contains("clone=75ms"), "{with_clone}");
        assert!(
            with_clone.contains("load_thr busy/wait=2625/200ms"),
            "clone is load-thread work: {with_clone}"
        );
        // load wall = load_ms(30)+assemble(8) = 38
        assert!(line.contains("load=38ms"), "{line}");
        assert!(
            !line.contains("connect="),
            "assemble is inside load, not a peer stage: {line}"
        );
        // write = class_a(12)+ensure(3)+class_c(40)+sh(0)+spend(25)+tweaks(7)+tip_gc(5) = 92
        assert!(line.contains("write=92ms"), "{line}");
        assert!(line.contains("class_a=12ms"), "{line}");
        assert!(line.contains("ensure=3ms"), "{line}");
        assert!(line.contains("class_c=40ms"), "{line}");
        assert!(line.contains("spend=25ms"), "{line}");
        assert!(line.contains("tweaks=7ms"), "{line}");
        assert!(line.contains("struct=0ms"), "{line}");
        assert!(line.contains("recon_ms=100"), "{line}"); // non-zero only
        assert!(!line.contains("prefetch"), "{line}");
        assert!(!line.contains("unpin"), "{line}");
        assert!(line.contains("loop confirm"), "{line}");
        assert!(line.contains("reject=2"), "{line}");
        assert!(line.contains("live h=100 n=32 in=8000 1500ms"), "{line}");
        s.conf_ready = 0;
        s.conf_script_q = 1;
        s.conf_write_q = 2;
        s.conf_script_q_cap = 2;
        s.conf_write_q_cap = 2;
        s.load_ready_through = 200;
        s.load_blocks = 32;
        s.load_pin_cache_body = 8;
        s.load_pin_new = 12;
        s.load_body_tx_reads = 400;
        s.load_parent_tx_reads = 12;
        s.load_win_ms = 40;
        s.load_thin_ms = 5;
        s.load_decode_ms = 15;
        s.load_cache_put_ms = 2;
        s.load_parent_pin_ms = 18;
        s.load_pin_body_ms = 4;
        s.load_pin_new_meta_ms = 14;
        s.sh_runs = 3;
        s.write.structural_ms = 50;
        s.structural_spent_ms = 30;
        s.structural_create_h_ms = 5;
        s.structural_bip68_ms = 20;
        s.arch_write_body_ms = 7;
        s.arch_write_head_ms = 2;
        let line = format_info(&s);
        assert!(line.contains("loadq<0/14 scriptq=1/2 writeq=2/2"), "{line}");
        assert!(line.contains("thru=200"), "{line}");
        // pin_residency slot always 0 (process pin FIFO removed); pin_plan_cache label retired.
        assert!(!line.contains("pin_res="), "{line}");
        assert!(line.contains("pin_new=12"), "{line}");
        assert!(line.contains("body_io=400 parent_io=12"), "{line}");
        s.spent_abs_ms = 20;
        s.spent_strong_ms = 5;
        s.spent_cold_ms = 3;
        s.spent_pending_ms = 2;
        let line = format_info(&s);
        assert!(
            line.contains("struct=50ms(spent=30 create_h=5 bip68=20)"),
            "{line}"
        );
        assert!(
            line.contains("spent_sub(abs=20 strong=5 cold=3 pending=2)"),
            "{line}"
        );
        // write = 12+3+50+40+25+7+5 = 142
        assert!(line.contains("write=142ms"), "{line}");
        assert!(line.contains("class_a_sub(body=7 head=2"), "{line}");
        assert!(line.contains("pre_asm=30ms"), "{line}");
        assert!(line.contains("assemble=8ms"), "{line}");
        assert!(line.contains("wire_arc="), "{line}");
        assert!(line.contains("prepare="), "{line}");
        assert!(line.contains("pin_win=40ms"), "{line}");
        // pin_hit% = cache / (cache+new). Cache is adopt/plan reuse only
        // (this-window range-fills are pin_new). 8/(8+12)=40; 1+2 → 33.
        assert!(line.contains("pin_hit%=40"), "{line}");
        s.load_pin_cache_body = 1;
        s.load_pin_new = 2;
        let line33 = format_info(&s);
        assert!(line33.contains("pin_hit%=33"), "{line33}");
        s.load_pin_cache_body = 8;
        s.load_pin_new = 12;
        assert!(!line.contains("denserels_hit%"), "{line}");
        assert!(line.contains("cold_io=14ms"), "{line}");
        // I1–I4 fields present with zero path counts when unset.
        assert!(line.contains("load_budget total="), "{line}");
        assert!(line.contains("us/in="), "{line}");
        assert!(line.contains("us/new="), "{line}");
        assert!(line.contains("cold_range="), "{line}");
        assert!(line.contains("cold_idx="), "{line}");
        assert!(line.contains("batch="), "{line}");
        assert!(!line.contains("thin[col="), "{line}");
        assert!(!line.contains("by_fk="), "{line}");
        assert!(!line.contains("pin_cached="), "{line}");
        assert!(line.contains("sh_runs=3"), "{line}");
        assert!(!line.contains("reserved"), "{line}");
        assert!(!line.contains("runway"), "{line}");
    }

    #[test]
    fn format_info_load_instrumentation_i1_i4() {
        let mut s = IbdPerfSample::default();
        s.load_ms = 2000;
        s.connect_ms = 3000;
        s.load_parent_pin_ms = 1800;
        s.load_blocks = 10;
        s.asm_prevout_ms = 2500;
        s.asm_in_n = 50_000;
        s.asm_prev_batch_ms = 2000;
        s.asm_prev_batch_n = 40_000;
        s.asm_prev_same_ms = 50;
        s.asm_prev_same_n = 2_000;
        s.asm_prev_cold_ms = 250;
        s.asm_prev_cold_n = 3_000;
        s.asm_prev_fk_ms = 10;
        s.asm_sigop_ms = 2;
        s.asm_final_ms = 0;
        s.asm_job_ms = 40;
        s.load_thin_ms = 7;
        s.load_plan_pin_ms = 100;
        s.load_pin_plan = 20_000;
        s.load_pin_adopt_ms = 15;
        s.load_pin_recent_outs_ms = 8;
        s.load_pin_range_fill_ms = 40;
        s.load_pin_contract_ms = 25;
        s.load_pin_publish_ms = 12;
        s.load_cold_range_ms = 1200;
        s.load_cold_range_n = 4_000;
        s.load_cold_idx_ms = 400;
        s.load_cold_idx_n = 2_000;
        s.load_cold_io_ms = 1600;
        s.load_cold_decode_ms = 10;
        s.load_pin_new = 6_000;
        s.load_pin_cache_body = 30_000;
        let line = format_info(&s);
        // Residual pin sub-timers named in pin(...) block.
        assert!(line.contains("thin=7ms"), "{line}");
        assert!(line.contains("adopt=15ms"), "{line}");
        assert!(line.contains("recent_outs=8ms"), "{line}");
        assert!(line.contains("range_fill=40ms"), "{line}");
        assert!(line.contains("contract=25ms"), "{line}");
        assert!(line.contains("publish=12ms"), "{line}");
        // I1: total = load+connect = 5000; pin=1800; asm=3000; other=200
        assert!(
            line.contains("load_budget total=5000ms pin=1800ms asm=3000ms other=200ms"),
            "{line}"
        );
        // I3: us/in = 2500*1000/50000 = 50
        assert!(line.contains("us/in=50"), "{line}");
        assert!(line.contains("batch=2000/n=40000"), "{line}");
        assert!(!line.contains("res=/n="), "{line}");
        assert!(!line.contains("res_lk"), "{line}");
        assert!(line.contains("same=50/n=2000"), "{line}");
        assert!(line.contains("cold=250/n=3000"), "{line}");
        assert!(line.contains("cold_why(null_fk="), "{line}");
        assert!(line.contains("fk=10ms"), "{line}");
        // N1 reason breakdown when set.
        s.asm_cold_null_fk_n = 10;
        s.asm_cold_not_pin_n = 2900;
        s.asm_cold_txid_mismatch_n = 50;
        s.asm_cold_vout_miss_n = 40;
        let line = format_info(&s);
        assert!(
            line.contains("cold_why(null_fk=10 not_pin=2900 mismatch=50 vout_miss=40)"),
            "{line}"
        );
        // I2: us/new = (1200+400)*1000/6000 = 266
        assert!(line.contains("cold_range=1200ms(body="), "{line}");
        s.load_cold_range_body_ms = 800;
        s.load_cold_range_decode_ms = 400;
        let line = format_info(&s);
        assert!(
            line.contains("cold_range=1200ms(body=800 dec=400)/n=4000"),
            "{line}"
        );
        assert!(line.contains("cold_idx=400ms/n=2000"), "{line}");
        assert!(line.contains("us/new=266"), "{line}");
        assert!(!line.contains("res_lk"), "{line}");
        assert!(!line.contains("pin_res="), "{line}");
    }

    /// Drive the remaining format_* optional branches (stamp_sub, head_loc,
    /// lookup_sub, plan_batch head_rd / dens) so LCOV hits those arms.
    #[test]
    fn format_info_and_debug_optional_subblocks() {
        let mut s = IbdPerfSample::default();
        s.phase_blks = 8;
        s.plan_blks = 4;
        s.plan_ms = 12;
        s.plan_parents = 100;
        s.plan_already = 10;
        s.plan_cold = 20;
        s.plan_same_batch = 5;
        s.plan_collect_ms = 3;
        s.lookup_decode_ms = 40;
        s.lookup_precompute_ms = 30;
        s.lookup_wave_head_ms = 20;
        s.plan_head_ms = 4;
        s.plan_cold_io_ms = 5;
        s.stamp_struct_ms = 1;
        s.stamp_prepare_ms = 2;
        s.stamp_filter_ms = 3;
        s.stamp_batch_ms = 4;
        s.stamp_batch_assign_ms = 1;
        s.stamp_batch_collect_ms = 1;
        s.stamp_batch_head_fk_ms = 1;
        s.stamp_batch_head_ms = 2;
        s.stamp_batch_stamp_ms = 1;
        s.stamp_batch_finish_ms = 1;
        s.arch_prep_age_hit_n = 50;
        s.arch_prep_age_cdf0_pct = 10;
        s.arch_prep_age_cdf3_pct = 40;
        s.arch_prep_age_cdf7_pct = 70;
        s.arch_prep_age_cdf15_pct = 90;
        s.arch_prep_age_cdf31_pct = 100;
        s.arch_ext_need = 30;
        s.arch_prep_assign_ms = 6;
        s.arch_prep_collect_ms = 2;
        s.arch_prep_inflight_ms = 1;
        s.arch_prep_head_fk_ms = 1;
        s.arch_prep_head_ms = 3;
        s.arch_prep_stamp_ms = 1;
        s.arch_prep_finish_ms = 1;
        s.arch_resolve_ns = 8_000_000;
        s.arch_resolve_blocks = 4;
        s.arch_head_hit = 20;
        s.arch_head_need = 25;
        s.arch_pin_txid = 15;
        s.arch_pin_txid_ms = 2;
        s.arch_recent_n = 9;
        s.arch_recent_ms = 3;
        s.arch_batch_stamp = 4;
        s.arch_prep_probe_ms = 8;
        s.arch_prep_idx_ms = 4;
        s.arch_prep_body_txid_ms = 2;
        s.arch_prep_head_keys = 100;
        s.arch_prep_head_cands = 300;
        s.arch_prep_body_lookups = 200;
        s.arch_prep_hit_rank_avg_x100 = 150;
        s.arch_prep_hit_rank_n = 20;
        s.arch_prep_miss_peeks = 5;
        s.arch_prep_pending_hits = 3;
        s.arch_prep_age_hit_compact = "1:2:3:0:0:0:0:0:0".into();
        s.sh_collect_pin = 7;
        s.sh_collect_cold = 3;
        s.sh_collect_ms = 9;
        s.sh_sort_ms = 1;
        s.sh_seed_ms = 2;
        s.sh_body_ms = 3;
        s.sh_head_ms = 4;
        s.wf_body_store = 1;
        s.wf_store_body_ms = 2;
        s.load_missing_parents = 3;
        s.thr_lookup_stamp_ms = 1;
        s.stamp_struct_ms = 8;
        s.stamp_struct_txid_ms = 6;
        s.stamp_struct_walk_ms = 2;
        let info = format_info(&s);
        assert!(info.contains("stamp_sub("), "{info}");
        assert!(info.contains("struct_txid=6ms"), "{info}");
        assert!(info.contains("struct_walk=2ms"), "{info}");
        assert!(info.contains("pin_txid=15"), "{info}");
        assert!(info.contains("pin_txid%=37"), "{info}");
        assert!(info.contains("pin_txid_ms=2"), "{info}");
        assert!(info.contains("leftover_n=25"), "{info}");
        assert!(info.contains("leftover_hit="), "{info}");
        assert!(info.contains("recent=9"), "{info}");
        assert!(info.contains("recent_ms=3"), "{info}");
        assert!(info.contains("head_loc(cdf0=10"), "{info}");
        assert!(info.contains("lookup_sub(blks=4"), "{info}");
        assert!(info.contains("decode=40ms"), "{info}");
        assert!(info.contains("precompute=30ms"), "{info}");
        assert!(info.contains("collect=3ms"), "{info}");
        assert!(
            info.contains(
                "wave=1ms(decode=40ms precompute=30ms collect=3ms head=20ms(probe=0ms io=0ms preads=0) spent=0ms)"
            ),
            "{info}"
        );
        let dbg = format_debug(&s);
        assert!(dbg.contains("plan_batch "), "{dbg}");
        assert!(dbg.contains("pin_txid=15/25"), "{dbg}");
        assert!(dbg.contains("us/pin_txid=133"), "{dbg}");
        assert!(dbg.contains("recent=9"), "{dbg}");
        assert!(dbg.contains("recent_ms=3"), "{dbg}");
        assert!(dbg.contains("head_rd("), "{dbg}");
        assert!(dbg.contains("pend=3"), "{dbg}");
        assert!(dbg.contains("probe_us/key="), "{dbg}");
        assert!(
            dbg.contains("sh_src pin=7 cold=3") || dbg.contains("sh collect=9"),
            "{dbg}"
        );
        // Zero-key / zero-block edge arms in the same helpers.
        s.arch_resolve_blocks = 0;
        s.arch_prep_head_keys = 0;
        s.arch_prep_age_hit_compact.clear();
        let dbg2 = format_debug(&s);
        assert!(dbg2.contains("plan_batch "), "{dbg2}");
        // Empty compact string uses the 0:0:… default when head_rd runs with hit_n.
        s.arch_prep_probe_ms = 1;
        s.arch_prep_head_keys = 0; // still enter outer if, but avg_* zero arms
        let _ = format_debug(&s);
        // read_proc_rss residual file_kb path exercised on Linux.
        let rss = read_proc_rss();
        assert!(rss.rss_kb > 0 || cfg!(not(target_os = "linux")));
    }

    #[test]
    fn format_debug_has_detail_tokens() {
        let mut s = IbdPerfSample::default();
        s.phase_blks = 10;
        s.recon_ns = 10_000_000; // 1ms/blk → 1000 us/blk
        s.write.utxo_apply_ns = 5_000_000; // 500 us/blk
        s.write.tweak_ns = 3_000_000; // 300 us/blk
        s.spend_ranged = 10;
        s.spend_idx = 2;
        s.spend_skip = 0;
        s.wf_body_store = 3;
        s.wf_store_body_ms = 50;
        // (no cache/lock fields — pruned)
        s.conf_ready = 0;
        s.conf_script_q = 0;
        s.conf_write_q = 1;
        s.conf_script_q_cap = 2;
        s.conf_write_q_cap = 2;
        s.load_ready_through = 200;
        s.load_blocks = 16;
        s.load_utxo_parents = 100;
        s.load_creates = 50;
        s.load_body_tx_reads = 200;
        s.load_parent_tx_reads = 50;
        s.load_pin_cache_body = 0;
        s.load_pin_new = 38;
        s.load_edge_same = 10;
        s.load_edge_fk = 5;
        s.load_edge_cb = 1;
        s.sh_collect_ms = 12;
        s.sh_runs = 2;
        s.arch_ext_need = 100;
        s.bq_count = 3;
        s.bq_bytes = 64 * 1024 * 1024;
        s.bq_soft_stop = 256;
        let line = format_debug(&s);
        assert!(line.starts_with("ibd: perf_dbg "), "{line}");
        assert!(line.contains("us/blk load="), "{line}");
        assert!(line.contains("pre_asm="), "{line}");
        assert!(line.contains("assemble="), "{line}");
        assert!(line.contains("class_a="), "{line}");
        assert!(line.contains("ensure="), "{line}");
        assert!(line.contains("write="), "{line}");
        assert!(line.contains("spend=500(r=10 i=2 skip=0)"), "{line}");
        assert!(line.contains("tweaks=300"), "{line}");
        assert!(!line.contains("prefetch="), "{line}");
        assert!(!line.contains("wave body="), "{line}");
        assert!(!line.contains("sh seed="), "{line}");
        assert!(!line.contains("thin[col="), "{line}");
        assert!(line.contains("wire_body"), "{line}");
        assert!(line.contains("store_ms=50"), "{line}");
        assert!(line.contains("sh collect=12"), "{line}");
        assert!(line.contains("pin_sub body="), "{line}");
        assert!(line.contains("bq soft=3/256 RAM=64MiB"), "{line}");
        assert!(!line.contains("bq n="), "{line}");
        assert!(!line.contains(" disk="), "{line}");
        // Depth 0 → `<` (consumer waiting on empty queue).
        assert!(
            line.contains("loadq<0/14 scriptq<0/2 writeq=1/2") || line.contains("loadq="),
            "{line}"
        );
        assert!(line.contains("thru=200"), "{line}");
        assert!(line.contains("utxo_p=100"), "{line}");
        assert!(line.contains("creates=50"), "{line}");
        assert!(line.contains("body_io=200 parent_io=50"), "{line}");
        assert!(line.contains("pin_cache=0"), "{line}");
        assert!(!line.contains("pin_res="), "{line}");
        assert!(line.contains("pin_new=38"), "{line}");
        assert!(!line.contains("pin_cached="), "{line}");
        assert!(line.contains("edges same=10 fk=5 cb=1"), "{line}");
        assert!(line.contains("sh_runs=2"), "{line}");
        assert!(line.contains("plan_batch "), "{line}");
        assert!(!line.contains("res_txid"), "{line}");
        assert!(!line.contains("res_seed"), "{line}");
        assert!(!line.contains("sticky="), "{line}");
        assert!(!line.contains("dual_pipe "), "{line}");
        assert!(line.contains("loop "), "{line}");
        assert!(!line.contains("runway"), "{line}");
        assert!(!line.contains("connect wave%="), "{line}");
        // Demap first-class tokens (present when head keys / write blocks sampled).
        if s.arch_prep_head_keys > 0 {
            assert!(line.contains("probe_us/key="), "{line}");
            assert!(line.contains("idx_us/key="), "{line}");
            assert!(line.contains("body_us/key="), "{line}");
        }
        if s.arch_prep_age_hit_n > 0 {
            assert!(line.contains("age_cdf("), "{line}");
            assert!(line.contains("age_hit="), "{line}");
        }
    }

    #[test]
    fn format_debug_class_a_commit_without_dual_pipe() {
        let mut s = IbdPerfSample::default();
        s.phase_blks = 4;
        s.arch_write_blocks = 4;
        s.arch_write_total_ms = 20;
        s.write.class_a_ns = 20_000_000;
        let line = format_debug(&s);
        assert!(!line.contains("dual_pipe "), "{line}");
        assert!(line.contains("class_a="), "{line}");
        assert!(line.contains("class_a_commit total=20"), "{line}");
        assert!(line.contains("ca_head_us/blk="), "{line}");
        assert!(line.contains("ca_body_us/blk="), "{line}");
    }

    #[test]
    fn format_sizes_has_rss_and_structure_tokens() {
        let mut s = IbdPerfSample::default();
        s.rss_kb = 2 * 1024; // 2 MiB
        s.rss_anon_kb = 1024;
        s.rss_file_kb = 512; // 0 MiB after integer MiB; still shows file=0MiB(25%)
        s.vm_hwm_kb = 3 * 1024;
        s.rss_locked_kb = 0;
        s.work.ordered = 100;
        s.work.ordered_set = 90;
        s.work.body.pending = 5;
        s.owned.conf_plans = 80;
        s.owned.inflight_layers = 3;
        s.owned.inflight_pins = 12_000;
        s.owned.inflight_bytes = 48 * 1024 * 1024;
        s.owned.recent_heights = 12;
        s.owned.recent_keys = 400;
        s.owned.recent_pub_keys = 400;
        s.owned.recent_overlay_keys = 0;
        s.owned.recent_fifo_keys = 400;
        s.owned.h2h_keys = 50;
        s.owned.fence_runs = 10;
        s.owned.pstore_weak = 20_000;
        s.owned.pstore_live = 8_000;
        s.owned.pstore_bytes = 16 * 1024 * 1024;
        s.bq_count = 4;
        s.bq_bytes = 32 * 1024 * 1024;
        s.bq_soft_stop = 256;
        s.owned.bq_promoted = 3;
        s.owned.head.primary_bits = 25;
        s.owned.head.primary_entry_b = 4;
        s.owned.head.primary_slots = 1 << 25;
        s.owned.head.primary_body_bytes = (1u64 << 25) * 4;
        s.owned.head.primary_occupied = 1_000_000;
        s.owned.head.segment_count = 3;
        s.owned.head.sealed_segments = 2;
        s.owned.head.class_a_n = 2_000_000;
        s.conf_pipe.load_batches = 3;
        s.conf_pipe.load_blocks = 8;
        s.conf_pipe.load_wire_bytes = 2 * 1024 * 1024;
        s.conf_pipe.script_batches = 2;
        s.conf_pipe.script_blocks = 16;
        s.conf_pipe.script_wire_bytes = 12 * 1024 * 1024;
        s.conf_pipe.script_parents = 500;
        s.conf_pipe.write_batches = 1;
        s.conf_pipe.write_blocks = 16;
        s.conf_pipe.write_wire_bytes = 4 * 1024 * 1024;
        s.conf_pipe.feed_ready = 8;
        s.conf_pipe.feed_inflight = 32;
        s.conf_ready = 40;
        s.conf_script_q_cap = 5;
        s.conf_write_q_cap = 5;
        let line = format_sizes(&s);
        assert!(line.starts_with("ibd: sizes "), "{line}");
        assert!(line.contains("rss=2MiB"), "{line}");
        assert!(line.contains("anon=1MiB"), "{line}");
        assert!(line.contains("file=0MiB(25%)"), "{line}"); // 512kB → 0 MiB; pct from kB
        assert!(line.contains("hwm=3MiB"), "{line}");
        assert!(line.contains("locked=0MiB"), "{line}");
        assert!(line.contains("ordered=100/set=90"), "{line}");
        assert!(line.contains("pend=5"), "{line}");
        assert!(line.contains("miss="), "{line}");
        assert!(!line.contains("body_soft"), "{line}");
        assert!(line.contains("bq soft=4/256 RAM=32MiB"), "{line}");
        assert!(!line.contains("bq_dec="), "{line}");
        assert!(!line.contains("bq n="), "{line}");
        assert!(!line.contains(" disk="), "{line}");
        assert!(line.contains("conf_plans=80"), "{line}");
        assert!(!line.contains("cache="), "{line}");
        assert!(!line.contains("outfifo"), "{line}");
        assert!(!line.contains("sticky_fk="), "{line}");
        assert!(line.contains("loadq=3/14 blks=8 wire=2MiB"), "{line}");
        assert!(line.contains("scriptq=2/5 blks=16 wire=12MiB"), "{line}");
        assert!(
            line.contains("writeq=1/5 blks=16 wire=4MiB parents=500"),
            "{line}"
        );
        assert!(line.contains("feed ready=8 inflight=32"), "{line}");
        assert!(line.contains("txhead bits=25"), "{line}");
        assert!(line.contains("segs=3 sealed=2"), "{line}");
        assert!(line.contains("class_a=2000000"), "{line}");
        assert!(
            line.contains("heap bq=32MiB iflight=3L/12000pin≈48MiB recent=12h live=400k/pub=400k/ov=0 fifo=400k≈0MiB"),
            "{line}"
        );
        assert!(!line.contains("union="), "{line}");
        assert!(line.contains("h2h=50k≈0MiB"), "{line}");
        assert!(line.contains("fence=10≈0MiB"), "{line}");
        assert!(line.contains("pstore weak=20000/live=8000≈16MiB"), "{line}");
        assert!(line.contains("accounted≈"), "{line}");
        assert!(line.contains("residual≈"), "{line}");
        assert!(line.contains("fuse8="), "{line}");
        assert!(line.contains("mphf_g="), "{line}");
        assert!(line.contains("class_c_l2="), "{line}");
        assert!(line.contains("open_keys="), "{line}");
        assert!(!line.contains("shadow"), "{line}");
        assert!(!line.contains("contig parked="), "{line}");
    }

    #[test]
    fn format_sizes_no_residency_token() {
        let mut s = IbdPerfSample::default();
        s.rss_kb = 1024;
        s.owned.conf_plans = 10;
        let line = format_sizes(&s);
        assert!(
            !line.contains("residency creates=") && line.contains("conf_plans=10"),
            "{line}"
        );
        assert!(!line.contains("cache="), "{line}");
        assert!(!line.contains("outfifo"), "{line}");
        assert!(!line.contains("sticky_fk="), "{line}");
    }

    #[test]
    fn read_proc_rss_returns_nonzero_on_linux() {
        let r = read_proc_rss();
        // Agent VM is Linux with /proc; RSS should be readable for this process.
        assert!(
            r.rss_kb > 0,
            "expected VmRSS from /proc/self/status, got {r:?}"
        );
        // Modern kernels expose RssAnon/RssFile on status; at least one side
        // of the split should be non-zero for a running process with heap+.text.
        assert!(
            r.anon_kb > 0 || r.file_kb > 0,
            "expected anon/file split from status or smaps_rollup, got {r:?}"
        );
        // Parts should not wildly exceed total RSS.
        assert!(r.anon_kb <= r.rss_kb.saturating_add(256), "{r:?}");
        assert!(r.file_kb <= r.rss_kb.saturating_add(256), "{r:?}");
        // anon+file ≈ rss (shmem folded into file; allow small accounting skew).
        let sum = r.anon_kb.saturating_add(r.file_kb);
        let skew = sum.abs_diff(r.rss_kb);
        assert!(
            skew <= 1024,
            "anon+file should ≈ rss (±1MiB): sum={sum} skew={skew} {r:?}"
        );
    }

    #[test]
    fn sample_pulls_atomics_and_format_edge_arms() {
        let loop_stats = LoopStats::default();
        loop_stats.confirm_ns.store(2_000_000, Ordering::Relaxed);
        loop_stats.confirm_blocks.store(1, Ordering::Relaxed);
        loop_stats.assign_issued.store(7, Ordering::Relaxed);

        let work = WorkStructureSizes::default();
        let owned = ProcessOwnedSizes::default();
        let conf_pipe = ConfirmPipelineSizes::default();
        let rss = read_proc_rss();
        let s = sample(
            &loop_stats,
            4,           // inflight
            256,         // cap
            (0, 0, 256), // bq bytes/count/soft_stop
            100,         // arch_ahead
            1,           // hole
            8,           // peers
            true,        // headers_done
            (50, 10, 0, 0, 0),
            0,         // ready
            0,         // script_q
            0,         // write_q
            (0, 0, 0), // q hwm
            1,         // sh_runs
            work,
            owned,
            conf_pipe,
            rss,
        );
        assert_eq!(s.inflight, 4);
        assert_eq!(s.peers, 8);
        assert!(s.headers_done);
        assert_eq!(s.assign_issued, 7);
        assert_eq!(s.confirm_blocks, 1);
        assert_eq!(s.sh_runs, 1);
        // thr / hwm fields present (zero when idle).
        assert_eq!(s.conf_ready, 0);
        let line = format_info(&s);
        assert!(line.contains("lookup_thr busy="), "{line}");
        assert!(line.contains("ready=0"), "{line}");

        // Edge format arms: spend_mix, miss_p, headers_done, zero pin_hit.
        let mut edge = s.clone();
        edge.spend_idx = 2;
        edge.spend_skip = 1;
        edge.spend_ranged = 3;
        edge.load_missing_parents = 4;
        edge.load_pin_cache_body = 0;
        edge.load_pin_new = 0;
        edge.headers_done = true;
        edge.wire_ms = 9;
        edge.strong_ms = 1;
        edge.resolve_ms = 2;
        edge.drain_ms = 3;
        let info = format_info(&edge);
        assert!(info.contains("spend_mix"), "{info}");
        assert!(info.contains("miss_p=4"), "{info}");
        assert!(info.contains("headers_done"), "{info}");
        assert!(info.contains("wire_ms=9"), "{info}");
        assert!(info.contains("getdata=7"), "{info}");
        assert!(info.contains("pin_hit%=0"), "{info}");

        // log_sample should not panic (INFO path always; DEBUG optional).
        log_sample(&edge);
        // Slow-phase warn arm (ms/blk thresholds).
        let mut slow = edge;
        slow.phase_blks = 1;
        slow.write.class_c_ms = 2000;
        slow.write.sh_ms = 2000;
        slow.load_ms = 6000;
        slow.write.class_a_ms = 6000;
        log_sample(&slow);
    }

    #[test]
    fn format_tip_perf_sizes_tokens_and_mib() {
        let line = super::format_tip_perf_sizes(&super::TipPerfSizes {
            rss: super::ProcRss {
                rss_kb: 2 * 1024,
                anon_kb: 1024,
                file_kb: 512,
                hwm_kb: 3 * 1024,
                locked_kb: 0,
            },
            cache_bodies: 4,
            held_bodies: 1,
            sh_heads: 8,
            mp_live: 12,
        });
        assert!(line.contains("rss=2MiB"), "{line}");
        assert!(line.contains("anon=1MiB"), "{line}");
        assert!(line.contains("file=0MiB"), "{line}");
        assert!(line.contains("hwm=3MiB"), "{line}");
        assert!(line.contains("cache=4"), "{line}");
        assert!(line.contains("held=1"), "{line}");
        assert!(line.contains("sh_heads=8"), "{line}");
        assert!(line.contains("mp_live=12"), "{line}");
        assert!(!line.contains("accounted="), "{line}");
        assert!(!line.contains("residual="), "{line}");
    }
}
