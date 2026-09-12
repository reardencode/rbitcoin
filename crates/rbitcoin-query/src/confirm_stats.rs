//! Instance-owned confirm window meters (IBD `ibd: perf` / `ibd: sizes` / `ibd: perf_dbg`).
//!
//! [`Query`](crate::Query) owns one [`ConfirmStats`]. Hot path notes through `&self`.
//! Window sample is field-wise take (swap to 0) — not a process-global last-writer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[inline]
pub fn add(a: &AtomicU64, n: u64) {
    if n > 0 {
        a.fetch_add(n, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_dur(a: &AtomicU64, d: Duration) {
    add(a, d.as_nanos() as u64);
}

macro_rules! confirm_window {
    ($($field:ident),+ $(,)?) => {
        #[derive(Debug)]
        pub struct ConfirmStats {
            $(pub $field: AtomicU64,)+
            last_write_n: AtomicU64,
            last_write_wall_ns: AtomicU64,
            last_write_class_a_ns: AtomicU64,
            last_write_ensure_ns: AtomicU64,
            last_write_structural_ns: AtomicU64,
            last_write_spent_ns: AtomicU64,
            last_write_create_h_ns: AtomicU64,
            last_write_bip68_ns: AtomicU64,
            last_write_class_c_ns: AtomicU64,
            last_write_spend_ann_ns: AtomicU64,
            last_write_tweak_ns: AtomicU64,
            last_pin_plan_ns: AtomicU64,
            last_pin_cold_ns: AtomicU64,
            last_pin_contract_ns: AtomicU64,
            last_pin_plan_n: AtomicU64,
            last_pin_new_n: AtomicU64,
            last_head_need: AtomicU64,
            last_head_hit: AtomicU64,
            last_miss_n: AtomicU64,
            last_miss_pend: AtomicU64,
            last_miss_on: AtomicU64,
            last_miss_cands: AtomicU64,
            last_miss_txid: [AtomicU64; 4],
            leftover_age0: AtomicU64,
            leftover_age3: AtomicU64,
            leftover_age_n: AtomicU64,
        }

        impl Default for ConfirmStats {
            fn default() -> Self {
                Self {
                    $($field: AtomicU64::new(0),)+
                    last_write_n: AtomicU64::new(0),
                    last_write_wall_ns: AtomicU64::new(0),
                    last_write_class_a_ns: AtomicU64::new(0),
                    last_write_ensure_ns: AtomicU64::new(0),
                    last_write_structural_ns: AtomicU64::new(0),
                    last_write_spent_ns: AtomicU64::new(0),
                    last_write_create_h_ns: AtomicU64::new(0),
                    last_write_bip68_ns: AtomicU64::new(0),
                    last_write_class_c_ns: AtomicU64::new(0),
                    last_write_spend_ann_ns: AtomicU64::new(0),
                    last_write_tweak_ns: AtomicU64::new(0),
                    last_pin_plan_ns: AtomicU64::new(0),
                    last_pin_cold_ns: AtomicU64::new(0),
                    last_pin_contract_ns: AtomicU64::new(0),
                    last_pin_plan_n: AtomicU64::new(0),
                    last_pin_new_n: AtomicU64::new(0),
                    last_head_need: AtomicU64::new(0),
                    last_head_hit: AtomicU64::new(0),
                    last_miss_n: AtomicU64::new(0),
                    last_miss_pend: AtomicU64::new(0),
                    last_miss_on: AtomicU64::new(0),
                    last_miss_cands: AtomicU64::new(0),
                    last_miss_txid: [
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                    ],
                    leftover_age0: AtomicU64::new(0),
                    leftover_age3: AtomicU64::new(0),
                    leftover_age_n: AtomicU64::new(0),
                }
            }
        }

        #[derive(Debug, Default, Clone, Copy)]
        pub struct ConfirmWindow {
            $(pub $field: u64,)+
            pub leftover_age_n: u64,
            pub leftover_cdf0_pct: u64,
            pub leftover_cdf3_pct: u64,
        }

        impl ConfirmStats {
            pub fn take_window(&self) -> ConfirmWindow {
                let leftover_age_n = self.leftover_age_n.swap(0, Ordering::Relaxed);
                let a0 = self.leftover_age0.swap(0, Ordering::Relaxed);
                let a3 = self.leftover_age3.swap(0, Ordering::Relaxed);
                let leftover_cdf0_pct = if leftover_age_n == 0 {
                    0
                } else {
                    a0.saturating_mul(100) / leftover_age_n
                };
                let leftover_cdf3_pct = if leftover_age_n == 0 {
                    0
                } else {
                    a3.saturating_mul(100) / leftover_age_n
                };
                ConfirmWindow {
                    $($field: self.$field.swap(0, Ordering::Relaxed),)+
                    leftover_age_n,
                    leftover_cdf0_pct,
                    leftover_cdf3_pct,
                }
            }
        }
    };
}

confirm_window! {
    // lookup / load / scripts / write (isolation pin)
    load_ns,
    script_ns,
    class_a_ns,
    connect_ns,
    script_jobs,
    script_skip_mempool,
    structural_ns,
    structural_spent_ns,
    structural_spent_abs_ns,
    structural_spent_strong_ns,
    structural_spent_cold_ns,
    structural_spent_pending_ns,
    structural_create_h_ns,
    structural_bip68_ns,
    class_c_ns,
    tweak_ns,
    ensure_layout_ns,
    write_class_c_join_ns,
    write_drain_join_ns,
    write_dequeue_ns,
    write_plan_take_ns,
    write_create_map_ns,
    write_head_sub_ns,
    ensure_res_hit,
    ensure_cold_n,
    asm_prevout_ns,
    asm_sigop_ns,
    asm_final_ns,
    asm_job_ns,
    asm_in_n,
    asm_prev_batch_n,
    asm_prev_same_n,
    asm_prev_cold_n,
    asm_prev_cold_null_fk_n,
    asm_prev_cold_not_pin_n,
    asm_prev_cold_txid_mismatch_n,
    asm_prev_cold_vout_miss_n,
    utxo_apply_ns,
    spend_annotate_ranged,
    spend_ann_ns,
    spend_ann_n,
    spend_ann_pread_skip,
    spend_meta_ns,
    spend_meta_n,
    phase_prep_wire_arc_ns,
    phase_prep_struct_ns,
    phase_prep_header_ns,
    phase_prep_prepare_ns,
    phase_prep_filter_plan_ns,
    phase_blocks,
    // load pin
    load_win_ns,
    load_blocks,
    utxo_parents,
    parent_unique,
    pin_cache_body,
    pin_plan,
    pin_new,
    pin_body_ns,
    plan_pin_ns,
    pin_range_fill_ns,
    pin_recent_outs_ns,
    pin_contract_ns,
    cold_io_ns,
    cold_range_ns,
    cold_range_n,
    cold_range_body_ns,
    cold_range_decode_ns,
    cold_range_extend_n,
    body_tx_reads,
    thin_ns,
    parent_pin_ns,
    // class C / SH
    strong_ns,
    scripthash_ns,
    tip_ns,
    sh_collect_ns,
    sh_sort_ns,
    sh_seed_ns,
    sh_body_ns,
    sh_head_ns,
    sh_collect_pin,
    sh_collect_cold,
    sh_create_n,
    sh_unique_n,
    sh_written_n,
    // archive prep/write
    arch_blocks,
    ext_need,
    head_need,
    head_hit,
    pin_txid_n,
    pin_txid_ns,
    recent_n,
    recent_ns,
    leftover_pend,
    batch_stamp,
    resolved_stamp,
    fill_missing_n,
    arch_prep_total_ns,
    arch_prep_struct_ns,
    arch_prep_filter_ns,
    arch_prep_assign_ns,
    arch_prep_collect_ns,
    arch_prep_inflight_ns,
    arch_prep_head_ns,
    arch_prep_head_fk_ns,
    arch_prep_stamp_ns,
    arch_prep_finish_ns,
    arch_prep_publish_ns,
    arch_prep_qwait_ns,
    arch_prep_blocks,
    arch_write_total_ns,
    arch_write_reserve_ns,
    arch_write_body_ns,
    arch_write_head_ns,
    arch_write_spend_ns,
    arch_write_htxs_ns,
    arch_write_flush_ns,
    arch_write_blocks,
    // lookup wave
    lookup_blocks,
    lookup_parents,
    lookup_already,
    lookup_cold,
    lookup_unresolved,
    lookup_total_ns,
    lookup_collect_ns,
    lookup_head_ns,
    lookup_cold_io_ns,
    lookup_decode_ns,
    lookup_precompute_ns,
    lookup_wave_head_ns,
    lookup_wave_spent_ns,
    // plan stamp sub
    stamp_struct_ns,
    stamp_struct_txid_ns,
    stamp_struct_wtxid_ns,
    stamp_struct_walk_ns,
    stamp_prepare_ns,
    stamp_filter_ns,
    stamp_batch_ns,
    // wire reconstruct
    wf_body_store,
    wf_body_store_ns,
    // IBD OS-thread occupancy
    thr_lookup_claim_ns,
    thr_lookup_stamp_ns,
    thr_lookup_other_ns,
    thr_lookup_send_wait_ns,
    thr_load_recv_wait_ns,
    thr_load_pack_ns,
    thr_load_clone_ns,
    thr_load_stamp_ns,
    thr_load_pin_ns,
    thr_load_asm_ns,
    thr_load_prune_ns,
    thr_load_send_wait_ns,
    thr_script_recv_wait_ns,
    thr_script_work_ns,
    thr_script_send_wait_ns,
    thr_write_recv_wait_ns,
    thr_write_work_ns,
}

impl ConfirmWindow {
    pub fn prep_phases_sum_ns(&self) -> u64 {
        self.arch_prep_struct_ns
            .saturating_add(self.arch_prep_filter_ns)
            .saturating_add(self.arch_prep_assign_ns)
            .saturating_add(self.arch_prep_collect_ns)
            .saturating_add(self.arch_prep_inflight_ns)
            .saturating_add(self.arch_prep_head_ns)
            .saturating_add(self.arch_prep_stamp_ns)
            .saturating_add(self.arch_prep_finish_ns)
            .saturating_add(self.arch_prep_publish_ns)
            .saturating_add(self.arch_prep_qwait_ns)
    }

    pub fn write_phases_sum_ns(&self) -> u64 {
        self.arch_write_reserve_ns
            .saturating_add(self.arch_write_body_ns)
            .saturating_add(self.arch_write_head_ns)
            .saturating_add(self.arch_write_spend_ns)
            .saturating_add(self.arch_write_htxs_ns)
            .saturating_add(self.arch_write_flush_ns)
    }

    pub fn resolve_ns(&self) -> u64 {
        self.arch_prep_inflight_ns
            .saturating_add(self.arch_prep_head_fk_ns)
    }
}

impl ConfirmStats {
    #[inline]
    pub fn add_load_ns(&self, ns: u64) {
        add(&self.load_ns, ns);
    }
    #[inline]
    pub fn add_script_ns(&self, ns: u64) {
        add(&self.script_ns, ns);
    }
    #[inline]
    pub fn add_class_a_ns(&self, ns: u64) {
        add(&self.class_a_ns, ns);
    }

    #[inline]
    pub fn add_sh_part(&self, part: &AtomicU64, ns: u64) {
        if ns == 0 {
            return;
        }
        part.fetch_add(ns, Ordering::Relaxed);
        self.scripthash_ns.fetch_add(ns, Ordering::Relaxed);
    }

    pub fn note_last_write(&self, p: LastWritePhases) {
        self.last_write_n
            .store(u64::from(p.n_blocks), Ordering::Relaxed);
        self.last_write_wall_ns.store(p.wall_ns, Ordering::Relaxed);
        self.last_write_class_a_ns
            .store(p.class_a_ns, Ordering::Relaxed);
        self.last_write_ensure_ns
            .store(p.ensure_ns, Ordering::Relaxed);
        self.last_write_structural_ns
            .store(p.structural_ns, Ordering::Relaxed);
        self.last_write_spent_ns
            .store(p.spent_ns, Ordering::Relaxed);
        self.last_write_create_h_ns
            .store(p.create_h_ns, Ordering::Relaxed);
        self.last_write_bip68_ns
            .store(p.bip68_ns, Ordering::Relaxed);
        self.last_write_class_c_ns
            .store(p.class_c_ns, Ordering::Relaxed);
        self.last_write_spend_ann_ns
            .store(p.spend_ann_ns, Ordering::Relaxed);
        self.last_write_tweak_ns
            .store(p.tweak_ns, Ordering::Relaxed);
    }

    pub fn last_write_phases(&self) -> LastWritePhases {
        LastWritePhases {
            n_blocks: self.last_write_n.load(Ordering::Relaxed) as u32,
            wall_ns: self.last_write_wall_ns.load(Ordering::Relaxed),
            class_a_ns: self.last_write_class_a_ns.load(Ordering::Relaxed),
            ensure_ns: self.last_write_ensure_ns.load(Ordering::Relaxed),
            structural_ns: self.last_write_structural_ns.load(Ordering::Relaxed),
            spent_ns: self.last_write_spent_ns.load(Ordering::Relaxed),
            create_h_ns: self.last_write_create_h_ns.load(Ordering::Relaxed),
            bip68_ns: self.last_write_bip68_ns.load(Ordering::Relaxed),
            class_c_ns: self.last_write_class_c_ns.load(Ordering::Relaxed),
            spend_ann_ns: self.last_write_spend_ann_ns.load(Ordering::Relaxed),
            tweak_ns: self.last_write_tweak_ns.load(Ordering::Relaxed),
        }
    }

    pub fn note_last_pin(
        &self,
        plan_pin_ns: u64,
        cold_ns: u64,
        contract_ns: u64,
        pin_plan_n: u64,
        pin_new_n: u64,
    ) {
        self.last_pin_plan_ns.store(plan_pin_ns, Ordering::Relaxed);
        self.last_pin_cold_ns.store(cold_ns, Ordering::Relaxed);
        self.last_pin_contract_ns
            .store(contract_ns, Ordering::Relaxed);
        self.last_pin_plan_n.store(pin_plan_n, Ordering::Relaxed);
        self.last_pin_new_n.store(pin_new_n, Ordering::Relaxed);
    }

    pub fn last_pin_phases(&self) -> LastPinPhases {
        LastPinPhases {
            plan_pin_ns: self.last_pin_plan_ns.load(Ordering::Relaxed),
            cold_ns: self.last_pin_cold_ns.load(Ordering::Relaxed),
            contract_ns: self.last_pin_contract_ns.load(Ordering::Relaxed),
            pin_plan_n: self.last_pin_plan_n.load(Ordering::Relaxed),
            pin_new_n: self.last_pin_new_n.load(Ordering::Relaxed),
        }
    }

    pub fn note_resolve_counts(
        &self,
        blocks: u64,
        ext_need: u64,
        head_need: u64,
        head_hit: u64,
        batch_stamp: u64,
        resolved_stamp: u64,
    ) {
        add(&self.arch_blocks, blocks);
        add(&self.ext_need, ext_need);
        add(&self.head_need, head_need);
        add(&self.head_hit, head_hit);
        add(&self.batch_stamp, batch_stamp);
        add(&self.resolved_stamp, resolved_stamp);
        if head_need > 0 {
            self.last_head_need.store(head_need, Ordering::Relaxed);
            self.last_head_hit.store(head_hit, Ordering::Relaxed);
        }
    }

    pub fn last_plan_batch(&self) -> LastPlanBatch {
        LastPlanBatch {
            head_need: self.last_head_need.load(Ordering::Relaxed),
            head_hit: self.last_head_hit.load(Ordering::Relaxed),
        }
    }

    pub fn note_fill_missing(&self) {
        add(&self.fill_missing_n, 1);
    }

    pub fn note_leftover_mix(&self, pend: u64, age0: u64, age3: u64, age_n: u64) {
        add(&self.leftover_pend, pend);
        add(&self.leftover_age0, age0);
        add(&self.leftover_age3, age3);
        add(&self.leftover_age_n, age_n);
    }

    pub fn note_pin_txid(&self, n: u64, ns: u64) {
        add(&self.pin_txid_n, n);
        add(&self.pin_txid_ns, ns);
    }

    pub fn note_recent(&self, n: u64, ns: u64) {
        add(&self.recent_n, n);
        add(&self.recent_ns, ns);
    }

    pub fn note_prep_plan(
        &self,
        assign_ns: u64,
        collect_ns: u64,
        inflight_ns: u64,
        head_fk_ns: u64,
        stamp_ns: u64,
        finish_ns: u64,
    ) {
        add(&self.arch_prep_assign_ns, assign_ns);
        add(&self.arch_prep_collect_ns, collect_ns);
        add(&self.arch_prep_inflight_ns, inflight_ns);
        add(&self.arch_prep_head_fk_ns, head_fk_ns);
        add(&self.arch_prep_head_ns, head_fk_ns);
        add(&self.arch_prep_stamp_ns, stamp_ns);
        add(&self.arch_prep_finish_ns, finish_ns);
    }

    pub fn note_prep_batch(
        &self,
        total_ns: u64,
        struct_ns: u64,
        filter_ns: u64,
        publish_ns: u64,
        qwait_ns: u64,
        blocks: u64,
    ) {
        add(&self.arch_prep_total_ns, total_ns);
        add(&self.arch_prep_struct_ns, struct_ns);
        add(&self.arch_prep_filter_ns, filter_ns);
        add(&self.arch_prep_publish_ns, publish_ns);
        add(&self.arch_prep_qwait_ns, qwait_ns);
        add(&self.arch_prep_blocks, blocks);
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    pub fn note_write_commit(
        &self,
        total_ns: u64,
        reserve_ns: u64,
        body_ns: u64,
        head_ns: u64,
        spend_ns: u64,
        htxs_ns: u64,
        blocks: u64,
    ) {
        add(&self.arch_write_total_ns, total_ns);
        add(&self.arch_write_reserve_ns, reserve_ns);
        add(&self.arch_write_body_ns, body_ns);
        add(&self.arch_write_head_ns, head_ns);
        add(&self.arch_write_spend_ns, spend_ns);
        add(&self.arch_write_htxs_ns, htxs_ns);
        add(&self.arch_write_blocks, blocks);
    }

    pub fn note_write_flush(&self, ns: u64) {
        add(&self.arch_write_flush_ns, ns);
        add(&self.arch_write_total_ns, ns);
    }

    fn miss_on_code(on: Option<&str>) -> u64 {
        match on {
            Some("head") => 1,
            Some("body") => 2,
            Some("idx") => 3,
            Some("fence") => 4,
            _ => 0,
        }
    }

    fn miss_on_from_code(code: u64) -> Option<&'static str> {
        match code {
            1 => Some("head"),
            2 => Some("body"),
            3 => Some("idx"),
            4 => Some("fence"),
            _ => None,
        }
    }

    pub fn note_union_miss(
        &self,
        txid: [u8; 32],
        n: u64,
        pending: bool,
        miss_on: Option<&str>,
        miss_cands: u64,
    ) {
        self.last_miss_n.store(n, Ordering::Relaxed);
        self.last_miss_pend
            .store(u64::from(pending), Ordering::Relaxed);
        self.last_miss_on
            .store(Self::miss_on_code(miss_on), Ordering::Relaxed);
        self.last_miss_cands.store(miss_cands, Ordering::Relaxed);
        for (i, slot) in self.last_miss_txid.iter().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&txid[i.saturating_mul(8)..i.saturating_mul(8).saturating_add(8)]);
            slot.store(u64::from_le_bytes(b), Ordering::Relaxed);
        }
    }

    pub fn last_union_miss(&self) -> LastUnionMiss {
        let n = self.last_miss_n.load(Ordering::Relaxed);
        if n == 0 {
            return LastUnionMiss::default();
        }
        let mut txid = [0u8; 32];
        for (i, slot) in self.last_miss_txid.iter().enumerate() {
            let off = i.saturating_mul(8);
            txid[off..off.saturating_add(8)]
                .copy_from_slice(&slot.load(Ordering::Relaxed).to_le_bytes());
        }
        LastUnionMiss {
            n,
            pending: self.last_miss_pend.load(Ordering::Relaxed) != 0,
            txid: Some(txid),
            miss_on: Self::miss_on_from_code(self.last_miss_on.load(Ordering::Relaxed)),
            miss_cands: self.last_miss_cands.load(Ordering::Relaxed),
        }
    }

    pub fn note_stamp(&self, struct_ns: u64, prepare_ns: u64, filter_ns: u64, batch_ns: u64) {
        add(&self.stamp_struct_ns, struct_ns);
        add(&self.stamp_prepare_ns, prepare_ns);
        add(&self.stamp_filter_ns, filter_ns);
        add(&self.stamp_batch_ns, batch_ns);
    }

    pub fn note_struct_parts(&self, txid_ns: u64, wtxid_ns: u64, walk_ns: u64) {
        add(&self.stamp_struct_txid_ns, txid_ns);
        add(&self.stamp_struct_wtxid_ns, wtxid_ns);
        add(&self.stamp_struct_walk_ns, walk_ns);
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    pub fn note_lookup(
        &self,
        blocks: u64,
        parents: u64,
        already: u64,
        cold: u64,
        unresolved: u64,
        total_ns: u64,
        collect_ns: u64,
        head_ns: u64,
        cold_io_ns: u64,
    ) {
        add(&self.lookup_blocks, blocks);
        add(&self.lookup_parents, parents);
        add(&self.lookup_already, already);
        add(&self.lookup_cold, cold);
        add(&self.lookup_unresolved, unresolved);
        add(&self.lookup_total_ns, total_ns);
        add(&self.lookup_collect_ns, collect_ns);
        add(&self.lookup_head_ns, head_ns);
        add(&self.lookup_cold_io_ns, cold_io_ns);
    }

    pub fn note_wave_decode(
        &self,
        decode_ns: u64,
        precompute_ns: u64,
        collect_ns: u64,
        head_ns: u64,
        spent_ns: u64,
    ) {
        add(&self.lookup_decode_ns, decode_ns);
        add(&self.lookup_precompute_ns, precompute_ns);
        add(&self.lookup_collect_ns, collect_ns);
        add(&self.lookup_wave_head_ns, head_ns);
        add(&self.lookup_wave_spent_ns, spent_ns);
    }

    pub fn sample_tip_sh(&self) -> TipShSnap {
        TipShSnap {
            collect_ns: self.sh_collect_ns.swap(0, Ordering::Relaxed),
            sort_ns: self.sh_sort_ns.swap(0, Ordering::Relaxed),
            seed_ns: self.sh_seed_ns.swap(0, Ordering::Relaxed),
            body_ns: self.sh_body_ns.swap(0, Ordering::Relaxed),
            head_ns: self.sh_head_ns.swap(0, Ordering::Relaxed),
            pin: self.sh_collect_pin.swap(0, Ordering::Relaxed),
            cold: self.sh_collect_cold.swap(0, Ordering::Relaxed),
            creates: self.sh_create_n.swap(0, Ordering::Relaxed),
            unique: self.sh_unique_n.swap(0, Ordering::Relaxed),
            written: self.sh_written_n.swap(0, Ordering::Relaxed),
        }
    }
}

/// Snapshot of the most recent successful write phase (not a window).
#[derive(Debug, Clone, Copy, Default)]
pub struct LastWritePhases {
    pub n_blocks: u32,
    pub wall_ns: u64,
    pub class_a_ns: u64,
    pub ensure_ns: u64,
    pub structural_ns: u64,
    pub spent_ns: u64,
    pub create_h_ns: u64,
    pub bip68_ns: u64,
    pub class_c_ns: u64,
    pub spend_ann_ns: u64,
    pub tweak_ns: u64,
}

impl LastWritePhases {
    #[inline]
    pub fn ms(ns: u64) -> u64 {
        ns / 1_000_000
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LastPinPhases {
    pub plan_pin_ns: u64,
    pub cold_ns: u64,
    pub contract_ns: u64,
    pub pin_plan_n: u64,
    pub pin_new_n: u64,
}

impl LastPinPhases {
    #[inline]
    pub fn ms(ns: u64) -> u64 {
        ns / 1_000_000
    }

    pub fn format_slow_pin(&self) -> String {
        format!(
            "pin(plan={}ms/n={} cold={}ms/n={} contract={}ms)",
            Self::ms(self.plan_pin_ns),
            self.pin_plan_n,
            Self::ms(self.cold_ns),
            self.pin_new_n,
            Self::ms(self.contract_ns),
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LastPlanBatch {
    pub head_need: u64,
    pub head_hit: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LastUnionMiss {
    pub n: u64,
    pub pending: bool,
    pub txid: Option<[u8; 32]>,
    pub miss_on: Option<&'static str>,
    pub miss_cands: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TipShSnap {
    pub collect_ns: u64,
    pub sort_ns: u64,
    pub seed_ns: u64,
    pub body_ns: u64,
    pub head_ns: u64,
    pub pin: u64,
    pub cold: u64,
    pub creates: u64,
    pub unique: u64,
    pub written: u64,
}

impl TipShSnap {
    pub fn append_ns(&self) -> u64 {
        self.sort_ns
            .saturating_add(self.seed_ns)
            .saturating_add(self.body_ns)
            .saturating_add(self.head_ns)
    }

    pub fn total_sh_ns(&self) -> u64 {
        self.collect_ns.saturating_add(self.append_ns())
    }
}
