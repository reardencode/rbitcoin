//! Class A archive write path.
//!
//! Split for IBD dual-thread (prep/write may overlap with a small plan queue):
//! - **Plan** ([`Query::archive_plan_batch_from_wire`] IBD;
//!   [`Query::archive_plan_batch_from_store`] TxApply tests):
//!   store **reads** — assign create fks (optionally from a reserved HWM),
//!   in-flight planned creates + `tx.head` resolve, stamp inputs.
//!   Head-miss parents use **fk-only** head resolve (no denserels on plan stamp);
//!   load pin denserels by stamped `txout` range.
//! - **Commit** ([`Query::archive_commit_plan`]): store **writes** — body append,
//!   head index, header_txs. Pipeline pins stay on the plan (`batch_pin`); no
//!   process create FIFO seed.
//!
//! Overlap requires the in-flight map: a later plan batch may spend outputs from a
//! prior plan that is still queued/committing (not yet in head).

use super::*;

/// Shared immutable create pin: tx meta + full outs.
///
/// One Arc per create — plan `packed` pin half, `batch_pin`, and prep-ahead
/// `in_flight_outs` all Arc-clone this (no deep outs clone between stages).
pub type CreatePin = std::sync::Arc<(TxRecord, Vec<OutputRecord>)>;

/// Approx heap bytes for one [`CreatePin`] payload (for IBD `sizes` metering).
///
/// Counts owned output scripts + fixed record overhead — not Arc
/// refcount sharing (each strong Arc still "owns" the allocation once).
#[inline]
pub fn create_pin_approx_bytes(pin: &CreatePin) -> usize {
    let (_tx, outs) = pin.as_ref();
    let mut n = 96usize; // TxRecord + Arc shell overhead (order-of-magnitude)
    for o in outs {
        n = n.saturating_add(24).saturating_add(o.script.len());
    }
    n = n.saturating_add(outs.capacity().saturating_mul(24)); // Vec spare
    n
}

/// Write-ready plan batch from lookup/load to commit (writer).
///
/// Planned create fks match `txs.count()+1…` at plan time; commit fails if the
/// appender returns different fks (another writer interleave — must not happen).
#[derive(Debug)]
pub struct ArchiveWritePlan {
    /// Body-append rows: shared [`CreatePin`] (tx + outs) + inputs.
    /// IBD wire planner leaves ins empty; write fills from wire + [`Self::edges`].
    /// Outs live once in the pin Arc (not duplicated alongside inputs).
    pub packed: Vec<(CreatePin, Vec<InputRecord>)>,
    pub planned_fks: Vec<Fk>,
    pub per_header_ranges: Vec<(Fk, Fk, u32)>,
    /// Pin-time spend edges (create_fk stamped). Survives freeze; packed ins do not.
    pub edges: crate::SpendEdges,
    pub spends: Vec<([u8; 32], u32, Fk, u32)>,
    /// Creates from **this** batch only (txid→fk for in-flight / publish).
    pub batch_creates: Vec<([u8; 32], Fk)>,
    /// External parent identity stamped at lookup (`txid` + optional body/spent/pin).
    ///
    /// Load pin denserels by `ParentIdent.body` (skip `tx.idx`). Prep pin fills
    /// schema-13 zero body `TxRecord.txid` from `ParentIdent.txid` — **never**
    /// re-pread `txid.body` on the pin path.
    pub external_parents: crate::U64Map<crate::ParentIdent>,
    /// create_fk_id → spent need-vouts, filled while packing (load pin reuses).
    pub external_parent_vouts: crate::U64Map<Vec<u32>>,
    /// Prep-ahead pin material for **this batch's creates**, parallel to
    /// [`Self::planned_fks`]: same [`CreatePin`] Arcs as [`Self::packed`] (refcount
    /// only). Confirm `note_lookup_ok` only `Arc::clone`s into in-flight outs.
    pub batch_pin: Vec<CreatePin>,
    pub index_tx: bool,
    pub body_est: u64,
}

impl ArchiveWritePlan {
    pub fn empty() -> Self {
        Self {
            packed: Vec::new(),
            planned_fks: Vec::new(),
            per_header_ranges: Vec::new(),
            edges: crate::SpendEdges::default(),
            spends: Vec::new(),
            batch_creates: Vec::new(),
            external_parents: crate::U64Map::default(),
            external_parent_vouts: crate::U64Map::default(),
            batch_pin: Vec::new(),
            index_tx: false,
            body_est: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packed.is_empty()
    }

    /// Wire `prev_txid` known for this create_fk at plan stamp (RAM only).
    #[inline]
    pub fn external_parent_txid(&self, create_fk_id: u64) -> Option<[u8; 32]> {
        self.external_parents
            .get(&create_fk_id)
            .map(|p| p.txid)
            .filter(|t| *t != [0u8; 32])
    }

    /// Same-header create: assemble uses the wire `TxOut` (do not pin).
    #[inline]
    pub fn create_in_header_ranges(
        per_header: &[(Fk, Fk, u32)],
        spend: Fk,
        create_id: u64,
    ) -> bool {
        let Some(sid) = spend.get() else {
            return false;
        };
        for &(_, first, n) in per_header {
            let Some(start) = first.get() else {
                continue;
            };
            let end = start.saturating_add(u64::from(n));
            if sid >= start && sid < end {
                return create_id >= start && create_id < end;
            }
        }
        false
    }

    #[inline]
    pub fn create_in_spend_header(&self, spend: Fk, create_id: u64) -> bool {
        if self.per_header_ranges.is_empty() {
            return self.planned_fks.iter().any(|f| f.get() == Some(create_id));
        }
        Self::create_in_header_ranges(&self.per_header_ranges, spend, create_id)
    }

    /// Drop stamp staging (ranges + txid reverse) after pin.
    ///
    /// Sparse need-vouts already live in [`crate::BatchParents`]; commit never
    /// reads these maps.
    pub fn clear_external_parent_outs(&mut self) {
        self.external_parents.clear();
        self.external_parents.shrink_to_fit();
        self.external_parent_vouts.clear();
        self.external_parent_vouts.shrink_to_fit();
    }

    /// Freeze plan for write batch: drop pin-staging maps and `batch_creates`.
    ///
    /// After this, the plan is a **commit payload** only (`packed` / `planned_fks`
    /// / headers / spends / `batch_pin`). In-flight still binds from `batch_pin`.
    /// Prep must call this (or [`Self::clear_external_parent_outs`]) before
    /// enqueue to scripts/write so batch-merge never mutates growing stamp maps.
    pub fn freeze_after_pin(&mut self) {
        self.clear_external_parent_outs();
        self.batch_creates.clear();
        self.batch_creates.shrink_to_fit();
    }

    /// Drop headers that already have Class A body (partial-commit / retry).
    ///
    /// Returns `true` if anything remains to append. Used by
    /// [`Query::archive_commit_plan`] so a second confirm attempt after Class A
    /// succeeded but tip failed does not re-append the same txs.
    pub fn retain_headers_needing_body(
        &mut self,
        mut has_body: impl FnMut(Fk) -> Result<bool, QueryError>,
    ) -> Result<bool, QueryError> {
        if self.per_header_ranges.is_empty() {
            return Ok(!self.packed.is_empty());
        }
        let mut keep_fks: crate::U64Set = crate::U64Set::default();
        let mut new_ranges: Vec<(Fk, Fk, u32)> = Vec::with_capacity(self.per_header_ranges.len());
        for &(hfk, first, n) in &self.per_header_ranges {
            if has_body(hfk)? {
                continue;
            }
            new_ranges.push((hfk, first, n));
            let start = self
                .planned_fks
                .iter()
                .position(|f| *f == first)
                .ok_or(StoreError::Corrupt("invariant: retain first fk missing"))?;
            let end = start.saturating_add(n as usize).min(self.planned_fks.len());
            for f in &self.planned_fks[start..end] {
                if let Some(id) = f.get() {
                    keep_fks.insert(id);
                }
            }
        }
        if new_ranges.is_empty() {
            *self = Self::empty();
            return Ok(false);
        }
        if new_ranges.len() == self.per_header_ranges.len() {
            return Ok(true);
        }
        let old_packed = std::mem::take(&mut self.packed);
        let old_fks = std::mem::take(&mut self.planned_fks);
        let old_pin = std::mem::take(&mut self.batch_pin);
        let mut new_packed = Vec::with_capacity(keep_fks.len());
        let mut new_fks = Vec::with_capacity(keep_fks.len());
        let mut new_pin = Vec::with_capacity(keep_fks.len());
        for (i, fk) in old_fks.into_iter().enumerate() {
            let Some(id) = fk.get() else {
                continue;
            };
            if !keep_fks.contains(&id) {
                continue;
            }
            new_fks.push(fk);
            if i < old_packed.len() {
                new_packed.push(old_packed[i].clone());
            }
            if i < old_pin.len() {
                new_pin.push(std::sync::Arc::clone(&old_pin[i]));
            }
        }
        self.packed = new_packed;
        self.planned_fks = new_fks;
        self.batch_pin = new_pin;
        self.per_header_ranges = new_ranges;
        self.edges.retain(|id, _| keep_fks.contains(id));
        self.spends
            .retain(|(_, _, spend_fk, _)| spend_fk.get().is_some_and(|id| keep_fks.contains(&id)));
        self.batch_creates
            .retain(|(_, fk)| fk.get().is_some_and(|id| keep_fks.contains(&id)));
        // body_est is an upper bound; leave as-is (overestimate is safe for reserve).
        Ok(!self.packed.is_empty())
    }

    /// Append another **frozen** plan for write batch (height-ordered Class A).
    ///
    /// Callers must drain scripts→write in height order so `planned_fks` stay
    /// contiguous and match the sole Class A appender sequence.
    ///
    /// External staging maps are **discarded** (not union-merged): they are
    /// pin-time only and must already be empty after [`Self::freeze_after_pin`].
    /// Commit composition is pure vector concat of the frozen halves.
    pub fn append(&mut self, mut other: Self) {
        if other.is_empty() && other.per_header_ranges.is_empty() {
            return;
        }
        other.external_parents.clear();
        other.external_parent_vouts.clear();
        self.external_parents.clear();
        self.external_parent_vouts.clear();

        self.packed.append(&mut other.packed);
        self.planned_fks.append(&mut other.planned_fks);
        self.per_header_ranges.append(&mut other.per_header_ranges);
        self.edges.extend(other.edges);
        self.spends.append(&mut other.spends);
        self.batch_creates.append(&mut other.batch_creates);
        self.batch_pin.append(&mut other.batch_pin);
        self.index_tx |= other.index_tx;
        self.body_est = self.body_est.saturating_add(other.body_est);
    }
}

struct PlanIn {
    prev_txid: [u8; 32],
    prev_index: u32,
    is_coinbase: bool,
}

struct PlanRow {
    tx_fk: Fk,
    tx: TxRecord,
    ins: Vec<PlanIn>,
    outs: Vec<OutputRecord>,
    packed_ins: Vec<InputRecord>,
    ins_est: u64,
}

fn plan_in_from_record(inp: &InputRecord) -> PlanIn {
    PlanIn {
        prev_txid: inp.prev_txid,
        prev_index: inp.prev_index,
        is_coinbase: inp.is_coinbase(),
    }
}

fn plan_in_from_txin(inp: &bitcoin::TxIn) -> PlanIn {
    use bitcoin::hashes::Hash;
    let is_coinbase = inp.previous_output.is_null()
        || (inp.previous_output.txid.to_byte_array() == [0u8; 32]
            && inp.previous_output.vout == u32::MAX);
    PlanIn {
        prev_txid: inp.previous_output.txid.to_byte_array(),
        prev_index: if is_coinbase {
            u32::MAX
        } else {
            inp.previous_output.vout
        },
        is_coinbase,
    }
}

fn wire_ins_est(tx: &bitcoin::Transaction) -> u64 {
    tx.input
        .iter()
        .map(|inp| {
            (1 + 8
                + 9
                + 4
                + 9
                + inp.script_sig.len()
                + 9
                + inp.witness.iter().map(|w| 9 + w.len()).sum::<usize>()) as u64
        })
        .sum()
}

fn tx_record_from_wire(tx: &bitcoin::Transaction, txid: [u8; 32]) -> TxRecord {
    TxRecord {
        txid,
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        input_start_fk: Fk::NULL,
        input_count: tx.input.len() as u32,
        output_start_fk: Fk::NULL,
        output_count: tx.output.len() as u32,
    }
}

impl Query {
    /// Class A only (header + bodies + `tx.head` / `header_txs`). Does **not**
    /// set tip / fence / strong.
    ///
    /// Crash and `plan=None` tests. Not a production IBD API — confirm write
    /// uses [`Self::archive_plan_batch_from_store`] + [`Self::archive_commit_plan`].
    ///
    pub fn commit_class_a_only(
        &self,
        header: &HeaderRecord,
        txs: &[TxApply],
    ) -> Result<Fk, QueryError> {
        let mut items = vec![(header.clone(), txs.to_vec())];
        let mut out = self.archive_prepared_owned(&mut items)?;
        Ok(out.pop().expect("one archive result"))
    }

    /// Class A for a **contiguous** prepared run (same-batch parent resolve).
    ///
    /// Crash / `plan=None` tests. Not a production IBD API.
    pub fn commit_class_a_batch(
        &self,
        items: &mut [(HeaderRecord, Vec<TxApply>)],
    ) -> Result<Vec<Fk>, QueryError> {
        self.archive_prepared_owned(items)
    }

    /// Plan + commit Class A for prepared blocks (no tip / Class C).
    pub(crate) fn archive_prepared_owned(
        &self,
        items: &mut [(HeaderRecord, Vec<TxApply>)],
    ) -> Result<Vec<Fk>, QueryError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut with_fk: Vec<(Fk, HeaderRecord, Vec<TxApply>)> = Vec::with_capacity(items.len());
        for (header, txs) in items.iter_mut() {
            let fk = if let Some((fk, _)) = self.get_header_by_hash(&header.hash)? {
                fk
            } else {
                self.store.put_header(header)?
            };
            with_fk.push((fk, header.clone(), std::mem::take(txs)));
        }
        self.archive_prepared_with_fks(&mut with_fk)
    }

    /// **Idempotent** Class A commit when `header_fk` is already known.
    pub(crate) fn archive_prepared_with_fks(
        &self,
        items: &mut [(Fk, HeaderRecord, Vec<TxApply>)],
    ) -> Result<Vec<Fk>, QueryError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut header_fks = Vec::with_capacity(items.len());
        let mut need: Vec<(Fk, Vec<TxApply>)> = Vec::with_capacity(items.len());
        let mut seen_headers = crate::FkSet::default();
        for (fk, _header, txs) in items.iter_mut() {
            header_fks.push(*fk);
            if !seen_headers.insert(*fk) {
                let _ = std::mem::take(txs);
                continue;
            }
            if self.store.header_txs.has_body(*fk)? {
                let _ = std::mem::take(txs);
                continue;
            }
            if !txs.is_empty() {
                need.push((*fk, std::mem::take(txs)));
            }
        }
        if !need.is_empty() {
            let start = self.store.txs.count().saturating_add(1);
            let plan = self.archive_plan_batch_from_store(
                &mut need,
                start,
                &crate::InFlightView::empty(),
                None,
            )?;
            self.archive_commit_plan(plan)?;
        }
        Ok(header_fks)
    }

    /// Filter already-archived headers (store **read**). Returns items that still
    /// need Class A, plus the header_fk list for the caller's result order.
    ///
    /// Used by IBD prep after structure decode.
    pub fn archive_filter_need_bodies(
        &self,
        items: &mut [(Fk, HeaderRecord, Vec<TxApply>)],
    ) -> Result<(Vec<Fk>, Vec<(Fk, Vec<TxApply>)>), QueryError> {
        let mut header_fks = Vec::with_capacity(items.len());
        let mut need: Vec<(Fk, Vec<TxApply>)> = Vec::with_capacity(items.len());
        let mut seen_headers = crate::FkSet::default();
        for (fk, _header, txs) in items.iter_mut() {
            header_fks.push(*fk);
            if !seen_headers.insert(*fk) {
                let _ = std::mem::take(txs);
                continue;
            }
            if self.store.header_txs.has_body(*fk)? {
                let _ = std::mem::take(txs);
                continue;
            }
            if !txs.is_empty() {
                need.push((*fk, std::mem::take(txs)));
            }
        }
        Ok((header_fks, need))
    }

    /// Header-only need-body filter (IBD wire planner). No [`TxApply`].
    pub fn archive_filter_need_header_fks(&self, header_fks: &[Fk]) -> Result<Vec<Fk>, QueryError> {
        let mut need = Vec::with_capacity(header_fks.len());
        let mut seen_headers = crate::FkSet::default();
        for &fk in header_fks {
            if !seen_headers.insert(fk) {
                continue;
            }
            if self.store.header_txs.has_body(fk)? {
                continue;
            }
            need.push(fk);
        }
        Ok(need)
    }

    /// **Prep / read path:** assign create fks, identity resolve, stamp
    /// inputs. No Class A body/head writes (those are [`Self::archive_commit_plan`]).
    ///
    /// IBD prep keeps a local reserved HWM: after each successful non-empty plan,
    /// advance to `planned_fks.last()+1` so the next plan batch can be planned
    /// while a prior batch is still committing (ordered writer preserves match).
    ///
    /// `in_flight`: create txid→fk from prior plans that are queued/committing
    /// but not yet in head. Required for queue depth &gt; 1 when a later
    /// batch spends a prior batch's creates.
    ///
    /// Remaining externals take a TipOnly batch — they are not an invariant miss.
    /// Pipeline parent store is outs only (pin), not a create_fk source.
    pub fn archive_plan_batch_from_store(
        &self,
        need: &mut [(Fk, Vec<TxApply>)],
        next_tx_start: u64,
        in_flight: &crate::InFlightView,
        published: Option<&crate::PublishedIds>,
    ) -> Result<ArchiveWritePlan, QueryError> {
        use std::collections::{HashMap, HashSet};
        use std::time::Instant;

        self.on_load_pack()?;
        if need.is_empty() {
            return Ok(ArchiveWritePlan::empty());
        }

        let mut next_tx = next_tx_start.max(1);
        let n_headers = need.iter().filter(|(_, t)| !t.is_empty()).count() as u64;

        let t_assign = Instant::now();
        let mut batch_map: HashMap<[u8; 32], Fk> = HashMap::new();
        let mut work: Vec<PlanRow> = Vec::new();
        let mut per_header_ranges: Vec<(Fk, Fk, u32)> = Vec::with_capacity(need.len());

        for (header_fk, txs) in need.iter_mut() {
            if txs.is_empty() {
                continue;
            }
            // Same block hash must not reach here twice: caller drops duplicates
            // mid-pipeline / has_body. Fresh contiguous create fks for this body.
            let first_tx_fk = Fk(next_tx);
            let n_txs = txs.len() as u32;
            let mut seen_in_block: HashSet<[u8; 32]> = HashSet::with_capacity(txs.len());
            for ta in txs.drain(..) {
                let n_in = ta.inputs.len() as u32;
                let n_out = ta.outputs.len() as u32;
                if !seen_in_block.insert(ta.tx.txid) {
                    return Err(StoreError::Corrupt(
                        "duplicate txid in block body (consensus violation)",
                    )
                    .into());
                }
                let tx_fk = Fk(next_tx);
                next_tx += 1;

                let mut tx = ta.tx;
                tx.input_start_fk = Fk::NULL;
                tx.input_count = n_in;
                tx.output_start_fk = Fk::NULL;
                tx.output_count = n_out;

                batch_map.insert(tx.txid, tx_fk);
                let ins: Vec<PlanIn> = ta.inputs.iter().map(plan_in_from_record).collect();
                let ins_est = ta.inputs.iter().map(|x| x.encoded_len() as u64).sum();
                work.push(PlanRow {
                    tx_fk,
                    tx,
                    ins,
                    outs: ta.outputs,
                    packed_ins: ta.inputs,
                    ins_est,
                });
            }
            per_header_ranges.push((*header_fk, first_tx_fk, n_txs));
        }
        let assign_ns = t_assign.elapsed().as_nanos() as u64;
        self.finish_archive_plan(
            work,
            batch_map,
            per_header_ranges,
            n_headers,
            assign_ns,
            in_flight,
            published,
        )
    }

    /// IBD stamp: CreatePin + SpendEdges from wire txs. Packed ins stay empty.
    ///
    /// Does not build [`TxApply`] / clone `script_sig` / witness. Write fills
    /// packed ins from `Arc<Block>` + edges. `body_est` uses wire compact sizes.
    pub fn archive_plan_batch_from_wire(
        &self,
        need: &[(Fk, &bitcoin::Block, &[[u8; 32]])],
        next_tx_start: u64,
        in_flight: &crate::InFlightView,
        published: Option<&crate::PublishedIds>,
    ) -> Result<ArchiveWritePlan, QueryError> {
        use std::collections::{HashMap, HashSet};
        use std::time::Instant;

        self.on_load_pack()?;
        if need.is_empty() {
            return Ok(ArchiveWritePlan::empty());
        }

        let mut next_tx = next_tx_start.max(1);
        let n_headers = need.iter().filter(|(_, b, _)| !b.txdata.is_empty()).count() as u64;

        let t_assign = Instant::now();
        let mut batch_map: HashMap<[u8; 32], Fk> = HashMap::new();
        let mut work: Vec<PlanRow> = Vec::new();
        let mut per_header_ranges: Vec<(Fk, Fk, u32)> = Vec::with_capacity(need.len());

        for (header_fk, block, txids) in need {
            if block.txdata.is_empty() {
                continue;
            }
            if block.txdata.len() != txids.len() {
                return Err(StoreError::Corrupt("txid count mismatch").into());
            }
            let first_tx_fk = Fk(next_tx);
            let n_txs = block.txdata.len() as u32;
            let mut seen_in_block: HashSet<[u8; 32]> = HashSet::with_capacity(block.txdata.len());
            for (tx, txid) in block.txdata.iter().zip(txids.iter()) {
                if !seen_in_block.insert(*txid) {
                    return Err(StoreError::Corrupt(
                        "duplicate txid in block body (consensus violation)",
                    )
                    .into());
                }
                let tx_fk = Fk(next_tx);
                next_tx += 1;
                let rec = tx_record_from_wire(tx, *txid);
                batch_map.insert(*txid, tx_fk);
                let ins: Vec<PlanIn> = tx.input.iter().map(plan_in_from_txin).collect();
                let outs: Vec<OutputRecord> = tx
                    .output
                    .iter()
                    .map(|o| {
                        OutputRecord::unspent(o.value.to_sat() as i64, o.script_pubkey.to_bytes())
                    })
                    .collect();
                work.push(PlanRow {
                    tx_fk,
                    tx: rec,
                    ins,
                    outs,
                    packed_ins: Vec::new(),
                    ins_est: wire_ins_est(tx),
                });
            }
            per_header_ranges.push((*header_fk, first_tx_fk, n_txs));
        }
        let assign_ns = t_assign.elapsed().as_nanos() as u64;
        self.finish_archive_plan(
            work,
            batch_map,
            per_header_ranges,
            n_headers,
            assign_ns,
            in_flight,
            published,
        )
    }

    fn finish_archive_plan(
        &self,
        work: Vec<PlanRow>,
        batch_map: std::collections::HashMap<[u8; 32], Fk>,
        per_header_ranges: Vec<(Fk, Fk, u32)>,
        n_headers: u64,
        assign_ns: u64,
        in_flight: &crate::InFlightView,
        published: Option<&crate::PublishedIds>,
    ) -> Result<ArchiveWritePlan, QueryError> {
        use std::collections::HashSet;
        use std::time::Instant;

        let mut spends: Vec<([u8; 32], u32, Fk, u32)> = Vec::new();
        let archive_spends = self.spend_index_enabled() && self.index_mode().is_tip();
        let index_tx = self.tx_index_enabled();

        let t_collect = Instant::now();
        let mut need_external: HashSet<[u8; 32]> = HashSet::new();
        for row in &work {
            for (i, inp) in row.ins.iter().enumerate() {
                if inp.is_coinbase {
                    continue;
                }
                if row
                    .packed_ins
                    .get(i)
                    .is_some_and(|r| !r.create_fk.is_null())
                {
                    continue;
                }
                if batch_map.contains_key(&inp.prev_txid) {
                    continue;
                }
                if inp.prev_txid == [0u8; 32] {
                    continue;
                }
                need_external.insert(inp.prev_txid);
            }
        }
        let need_vec: Vec<[u8; 32]> = need_external.iter().copied().collect();
        let collect_ns = t_collect.elapsed().as_nanos() as u64;

        // External parents: in-flight → published live_union → recent creates
        // → leftover TipOnly, then idx range-fill. Same helper as plan=None.
        let ext = crate::stamp_external_parents(
            &self.store,
            &need_vec,
            in_flight,
            published.unwrap_or(self.published_ids.as_ref()),
            self.recent_creates.as_ref(),
        )?;
        let inflight_ns = ext.inflight_ns;
        let head_fk_ns = ext.head_fk_ns;
        let resolved = ext.resolved;
        let mut external_parents = ext.idents;
        crate::archive_phase_stats::note_resolve_counts(
            n_headers,
            need_vec.len() as u64,
            ext.head_need_n,
            ext.head_hit_n,
            0,
            0,
        );

        let t_stamp = Instant::now();
        let mut packed: Vec<(CreatePin, Vec<InputRecord>)> = Vec::with_capacity(work.len());
        let mut batch_pin: Vec<CreatePin> = Vec::with_capacity(work.len());
        let mut planned_fks: Vec<Fk> = Vec::with_capacity(work.len());
        let mut body_est = 0u64;
        let mut edges: crate::SpendEdges = crate::SpendEdges::default();
        let mut external_parent_vouts: crate::U64Map<Vec<u32>> = crate::U64Map::default();
        let mut batch_stamp = 0u64;
        let mut resolved_stamp = 0u64;
        let mut batch_create_ids: crate::U64Set =
            crate::U64Set::with_capacity_and_hasher(batch_map.len(), Default::default());
        for fk in batch_map.values() {
            if let Some(id) = fk.get() {
                batch_create_ids.insert(id);
            }
        }
        let mut prestamp_parents = false;
        for row in work {
            let PlanRow {
                tx_fk,
                tx,
                ins,
                outs,
                mut packed_ins,
                ins_est,
            } = row;
            let mut tx_edges: Vec<crate::SpendEdge> = Vec::with_capacity(ins.len());
            for (i, inp) in ins.iter().enumerate() {
                if inp.is_coinbase {
                    if let Some(rec) = packed_ins.get_mut(i) {
                        rec.create_fk = Fk::NULL;
                        rec.prev_index = u32::MAX;
                    }
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: tx_fk,
                        create_fk: Fk::NULL,
                    });
                    continue;
                }
                let mut create_fk = packed_ins.get(i).map(|r| r.create_fk).unwrap_or(Fk::NULL);
                if create_fk.is_null() {
                    if let Some(&cfk) = batch_map.get(&inp.prev_txid) {
                        create_fk = cfk;
                        batch_stamp = batch_stamp.saturating_add(1);
                    } else if let Some(&cfk) = resolved.get(&inp.prev_txid) {
                        create_fk = cfk;
                        resolved_stamp = resolved_stamp.saturating_add(1);
                    } else {
                        return Err(StoreError::Corrupt(
                            "archive: parent create_fk unresolved (contiguous batch required)",
                        ));
                    }
                }
                if let Some(rec) = packed_ins.get_mut(i) {
                    rec.create_fk = create_fk;
                }
                if let Some(pid) = create_fk.get() {
                    if !ArchiveWritePlan::create_in_header_ranges(&per_header_ranges, tx_fk, pid) {
                        external_parent_vouts
                            .entry(pid)
                            .or_default()
                            .push(inp.prev_index);
                    }
                    if !batch_create_ids.contains(&pid)
                        && !external_parents.contains_key(&pid)
                        && inp.prev_txid != [0u8; 32]
                    {
                        external_parents.insert(pid, crate::ParentIdent::new(inp.prev_txid));
                        prestamp_parents = true;
                    }
                }
                if archive_spends {
                    spends.push((inp.prev_txid, inp.prev_index, tx_fk, i as u32));
                }
                if inp.prev_index == u32::MAX {
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: tx_fk,
                        create_fk: Fk::NULL,
                    });
                } else {
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: inp.prev_txid,
                        vout: inp.prev_index,
                        spend_fk: tx_fk,
                        create_fk,
                    });
                }
            }
            if let Some(sid) = tx_fk.get() {
                edges.insert(sid, tx_edges);
            }
            planned_fks.push(tx_fk);
            let ins_bytes = if packed_ins.is_empty() {
                ins_est
            } else {
                packed_ins.iter().map(|x| x.encoded_len() as u64).sum()
            };
            let pin = std::sync::Arc::new((tx, outs));
            body_est = body_est
                .saturating_add((1 + TxRecord::ENCODED_LEN) as u64)
                .saturating_add(ins_bytes)
                .saturating_add(pin.1.iter().map(|x| x.encoded_len() as u64).sum::<u64>());
            batch_pin.push(std::sync::Arc::clone(&pin));
            packed.push((pin, packed_ins));
        }
        let stamp_ns = t_stamp.elapsed().as_nanos() as u64;
        for vouts in external_parent_vouts.values_mut() {
            vouts.sort_unstable();
            vouts.dedup();
        }
        if prestamp_parents {
            crate::fill_missing_parent_ranges(&self.store, in_flight, &mut external_parents)?;
        }

        let t_finish = Instant::now();
        let batch_creates: Vec<([u8; 32], Fk)> = packed
            .iter()
            .zip(planned_fks.iter())
            .map(|((pin, _), fk)| (pin.0.txid, *fk))
            .collect();

        // Finish is cheap: body_est + batch_creates only.
        // No `count_bodies` / far-ahead scan — Class A never leads tip (unified
        // confirm commit is the sole Class A appender); body DONTNEED lead
        // heuristics were dead work that cost O(headers) RwLock gets per plan.
        let finish_ns = t_finish.elapsed().as_nanos() as u64;

        crate::archive_phase_stats::note_resolve_counts(0, 0, 0, 0, batch_stamp, resolved_stamp);
        crate::archive_phase_stats::note_prep_plan(
            assign_ns,
            collect_ns,
            inflight_ns,
            head_fk_ns,
            stamp_ns,
            finish_ns,
        );

        Ok(ArchiveWritePlan {
            packed,
            planned_fks,
            per_header_ranges,
            edges,
            spends,
            batch_creates,
            external_parents,
            external_parent_vouts,
            batch_pin,
            index_tx,
            body_est,
        })
    }

    /// **Writer / write path:** durable Class A put (body / head / spends / htxs).
    ///
    /// **Idempotent:** headers that already have `header_txs` body are stripped
    /// (partial prior commit after structural/tip fail). If every header is
    /// already archived, this is a no-op and returns `Ok(false)` — no second
    /// body append / fk mismatch. Returns `Ok(true)` when body was appended.
    ///
    /// Phase walls go to [`crate::archive_phase_stats`] (body vs head split).
    ///
    /// Drains write-behind `tx.head` before return. Confirm write uses
    /// [`Self::archive_commit_plan_defer_head`] to overlap drain with Class C.
    pub fn archive_commit_plan(&self, plan: ArchiveWritePlan) -> Result<bool, QueryError> {
        let committed = self.archive_commit_plan_defer_head(plan)?;
        if committed {
            let _ = self.drain_pending_tx_head()?;
        }
        Ok(committed)
    }

    /// Like [`Self::archive_commit_plan`] but leaves `tx.head` in the pending map.
    pub fn archive_commit_plan_defer_head(
        &self,
        mut plan: ArchiveWritePlan,
    ) -> Result<bool, QueryError> {
        use std::time::Instant;
        if plan.packed.is_empty() {
            return Ok(false);
        }
        if !plan.retain_headers_needing_body(|hfk| self.store.header_txs.has_body(hfk))? {
            return Ok(false);
        }
        let t0 = Instant::now();
        let n_blocks = plan.per_header_ranges.len() as u64;

        let t = Instant::now();
        self.store
            .txs
            .reserve_append(plan.body_est, plan.packed.len() as u64)?;
        let reserve_ns = t.elapsed().as_nanos() as u64;

        let t = Instant::now();
        let got_tx_fks = self
            .store
            .put_tx_full_batch_from_pins(&plan.packed, /*index=*/ false)?;
        let body_ns = t.elapsed().as_nanos() as u64;
        if got_tx_fks.len() != plan.packed.len() {
            return Err(StoreError::Corrupt("tx put_full_batch length"));
        }
        if got_tx_fks != plan.planned_fks {
            return Err(StoreError::Corrupt(
                "tx put_full_batch fk mismatch (plan not committed in order)",
            ));
        }

        // Head write-behind: publish pending txid→fk so resolve can hit before drain.
        let t = Instant::now();
        if plan.index_tx {
            let heads: Vec<([u8; 32], Fk)> = plan
                .packed
                .iter()
                .zip(got_tx_fks.iter())
                .map(|((pin, _), fk)| (pin.0.txid, *fk))
                .collect();
            self.drain_pending_tx_head_if_full()?;
            self.store.txs.head_note_pending(&heads);
        }
        let head_ns = t.elapsed().as_nanos() as u64;

        let t = Instant::now();
        if !plan.spends.is_empty() {
            self.store.put_spend_batch(&plan.spends)?;
        }
        let spend_ns = t.elapsed().as_nanos() as u64;

        let t = Instant::now();
        if !plan.per_header_ranges.is_empty() {
            self.store
                .header_txs
                .put_ranges_batch(&plan.per_header_ranges)?;
        }
        let htxs_ns = t.elapsed().as_nanos() as u64;

        let total_ns = t0.elapsed().as_nanos() as u64;
        crate::archive_phase_stats::note_write_commit(
            total_ns,
            reserve_ns,
            body_ns,
            head_ns,
            spend_ns,
            htxs_ns,
            n_blocks.max(1),
        );
        Ok(true)
    }

    /// Drain write-behind `tx.head` inserts (page-grouped).
    ///
    /// Insert queued `tx.head` and publish drain-fk HWM.
    pub fn drain_pending_tx_head(&self) -> Result<u64, QueryError> {
        let batch = self.store.txs.take_pending_queued();
        let n = self.store.txs.head_insert_queued(&batch)?;
        if let Some(max_fk) = batch.iter().filter_map(|(_, fk)| fk.get()).max() {
            self.note_head_drain_fk(max_fk);
        }
        Ok(n)
    }

    fn drain_pending_tx_head_if_full(&self) -> Result<(), QueryError> {
        if self.store.txs.pending_head_is_full() {
            self.drain_pending_tx_head()?;
        }
        Ok(())
    }

    /// Resolve prev outpoint txid for an input.
    ///
    /// Schema v10: soft `prev_txid` may be zero after disk decode; fall back to
    /// create body txid via `create_fk`. Parent **txid** only (not prevout outs).
    pub fn resolve_prev_txid(&self, inp: &InputRecord) -> Result<[u8; 32], QueryError> {
        if inp.is_coinbase() {
            return Ok([0u8; 32]);
        }
        if inp.prev_txid != [0u8; 32] {
            return Ok(inp.prev_txid);
        }
        if inp.create_fk.is_null() {
            return Err(StoreError::Corrupt("input missing create_fk for prev_txid"));
        }
        Ok(self.store.txs.body_txid(inp.create_fk)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Query, TxApply};
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_query(label: &str) -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-arch-{label}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(&dir).unwrap();
        (dir, q)
    }

    fn coinbase_apply(i: u64) -> TxApply {
        let mut txid = [0u8; 32];
        txid[0..8].copy_from_slice(&i.to_le_bytes());
        txid[8] = 0xcb;
        TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![i as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50 * 100_000_000, vec![0x51])],
        }
    }

    #[test]
    fn commit_class_a_only_does_not_advance_tip() {
        use rbitcoin_store::HeaderRecord;

        let (dir, q) = temp_query("class-a-only-no-tip");
        assert!(q.tip_height().is_none());
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [2u8; 32],
        };
        let hfk = q
            .commit_class_a_only(&header, &[coinbase_apply(1)])
            .unwrap();
        assert!(q.tip_height().is_none(), "Class A helper must not set tip");
        assert!(q.store().header_txs.has_body(hfk).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// batch_pin Arc denserels match encode+decode layout (PR-A/B pin handoff).
    #[test]
    fn plan_batch_pin_arc_denserels_match_layout() {
        use std::sync::Arc;
        let (dir, q) = temp_query("batch-pin-arc");
        let mut need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
            .unwrap();
        assert_eq!(plan.batch_pin.len(), plan.planned_fks.len());
        assert_eq!(plan.batch_pin.len(), plan.packed.len());
        // packed pin half and batch_pin share the same Arc (no outs double-store).
        for ((pin_packed, _), pin) in plan.packed.iter().zip(plan.batch_pin.iter()) {
            assert!(
                Arc::ptr_eq(pin_packed, pin),
                "packed and batch_pin must share CreatePin Arc"
            );
            // plan construction: one Arc for packed + one for batch_pin.
            assert_eq!(Arc::strong_count(pin), 2);
        }
        // Simulated note_lookup_ok: Arc::clone only (strong_count rises, no deep clone).
        let mut ifo: crate::U64Map<super::CreatePin> = crate::U64Map::default();
        for (fk, pin) in plan.planned_fks.iter().zip(plan.batch_pin.iter()) {
            if let Some(id) = fk.get() {
                ifo.insert(id, Arc::clone(pin));
                assert_eq!(Arc::strong_count(pin), 3);
            }
        }
        for ((pin, ins), _) in plan.packed.iter().zip(plan.batch_pin.iter()) {
            let (tx, outs) = pin.as_ref();
            let mut raw = Vec::new();
            rbitcoin_store::encode_packed_tx(tx, ins, outs, &mut raw);
            let (meta, dec_outs, _) =
                rbitcoin_store::decode_packed_tx_outs_with_spender_rels(&raw).unwrap();
            assert_eq!(meta.output_count as usize, dec_outs.len());
            assert_eq!(outs.len(), dec_outs.len());
        }
        assert_eq!(ifo.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_phase_stats_cover_plan_and_commit_wall() {
        // Exclusive lock so a parallel sample_and_reset cannot steal this
        // window (llvm-cov / cargo test --workspace).
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let (dir, q) = temp_query("arch-phases");
            let mut need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
            let plan = q
                .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
                .unwrap();
            assert_eq!(plan.planned_fks.len(), 2);
            q.archive_commit_plan(plan).unwrap();
            let s = crate::archive_phase_stats::sample_and_reset();
            // Counts always fire; Instant slices can be 0 ns on a coarse clock.
            assert!(
                s.blocks >= 1 || s.prep_assign_ns > 0 || s.prep_stamp_ns > 0,
                "plan noted"
            );
            assert!(s.write_blocks >= 1 || s.write_total_ns > 0, "commit total");
            assert!(s.write_blocks >= 1 || s.write_body_ns > 0, "body put timed");
            let wsum = s.write_phases_sum_ns();
            // Sequential Instant slices: sum ≤ total + small clock noise.
            assert!(
                wsum <= s.write_total_ns.saturating_add(200_000),
                "write sum {} ≫ total {}",
                wsum,
                s.write_total_ns
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn plan_from_reserves_fks_for_overlap_then_commit_in_order() {
        let (dir, q) = temp_query("plan-from");
        // Seed one body so count starts at 1.
        let seed = vec![(Fk(1), vec![coinbase_apply(1)])];
        // Need a real header_fk path: plan only needs Vec<(Fk, Vec<TxApply>)>.
        let mut need0 = seed;
        let p0 = q
            .archive_plan_batch_from_store(
                &mut need0,
                q.tx_body_count() + 1,
                &crate::InFlightView::empty(),
                None,
            )
            .unwrap();
        q.archive_commit_plan(p0).unwrap();
        assert_eq!(q.tx_body_count(), 1);

        // Reserve two plans as prep would with write queue depth 2.
        let empty = crate::InFlightView::empty();
        let mut next = q.tx_body_count() + 1;
        let mut need_a = vec![(Fk(10), vec![coinbase_apply(10), coinbase_apply(11)])];
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, next, &empty, None)
            .unwrap();
        assert_eq!(plan_a.planned_fks, vec![Fk(2), Fk(3)]);
        next = plan_a.planned_fks.last().unwrap().0 + 1;
        assert_eq!(next, 4);

        let mut need_b = vec![(Fk(20), vec![coinbase_apply(20)])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, next, &empty, None)
            .unwrap();
        assert_eq!(plan_b.planned_fks, vec![Fk(4)]);
        // Durable count still 1 until commit.
        assert_eq!(q.tx_body_count(), 1);

        q.archive_commit_plan(plan_a).unwrap();
        assert_eq!(q.tx_body_count(), 3);
        q.archive_commit_plan(plan_b).unwrap();
        assert_eq!(q.tx_body_count(), 4);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Overlapping plan must resolve parents from a prior uncommitted plan batch.
    /// Without `in_flight`, this is the "parent create_fk unresolved" corruption.
    #[test]
    fn overlap_plan_resolves_parent_via_inflight_creates() {
        let (dir, q) = temp_query("inflight-parent");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        assert_eq!(plan_a.planned_fks, vec![Fk(1)]);
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;

        // Child spends parent — not in head until plan_a commits.
        let mut child_txid = [0u8; 32];
        child_txid[0] = 0xee;
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL, // must resolve
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need_b = vec![(Fk(2), vec![child])];

        // Without in_flight → unresolved.
        let err = q
            .archive_plan_batch_from_store(&mut need_b, 2, &empty, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("create_fk unresolved"),
            "expected unresolved without inflight, got {err}"
        );

        // Rebuild child (need_b was drained on failure).
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need_b = vec![(Fk(2), vec![child])];
        let mut inflight_log = crate::InFlightLog::new();
        inflight_log.note_layer(crate::InFlightLayer::from_plan_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
        ));
        let inflight = inflight_log.snapshot();
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &inflight, None)
            .expect("inflight parent resolve");
        assert_eq!(plan_b.planned_fks, vec![Fk(2)]);
        assert_eq!(
            plan_b.packed[0].1[0].create_fk, parent_fk,
            "child input must stamp prior planned create_fk"
        );

        q.archive_commit_plan(plan_a).unwrap();
        q.archive_commit_plan(plan_b).unwrap();
        assert_eq!(q.tx_body_count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn child_spend(prev_txid: [u8; 32], marker: u8) -> TxApply {
        let mut child_txid = [0u8; 32];
        child_txid[0] = marker;
        TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        }
    }

    /// n−1: in-flight still has the parent at child bind (prune is after pin).
    #[test]
    fn inflight_binds_parent_after_commit_before_prune() {
        let (dir, q) = temp_query("inflight-n-minus-1");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_plan_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
        ));
        q.archive_commit_plan(plan_a).unwrap();
        assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);

        let mut need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xef)])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &log.snapshot(), None)
            .expect("in-flight must stamp n−1 without leftover");
        assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_keeps_prev_pack_after_drain_done() {
        let (dir, q) = temp_query("leftover-keep-prev");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let header_fk = plan_a.per_header_ranges[0].0;
        q.archive_commit_plan(plan_a).unwrap();
        q.store()
            .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
            .unwrap();
        q.on_load_pack().unwrap();
        let mut child_txid = [0u8; 32];
        child_txid[0] = 0xea;
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need_b = vec![(Fk(2), vec![child])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &empty, None)
            .expect("height-1 child must bind prev pack after drain HWM");
        assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_gcs_header_plans_from_store_tip() {
        let (dir, q) = temp_query("tip-gc");
        let rec = rbitcoin_store::HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [9u8; 32],
        };
        q.confirm_parent_cache()
            .put_header_plan(1, Fk(2), rec, vec![Fk(2)], [0u8; 32]);
        assert!(q.confirm_parent_cache().get_header_plan(1).is_some());
        q.on_load_pack().unwrap();
        assert!(
            q.confirm_parent_cache().get_header_plan(1).is_some(),
            "store tip below the plan — do not GC height 1"
        );
        q.store()
            .confirmed
            .set(rbitcoin_primitives::Height(0), Fk(1))
            .unwrap();
        q.store()
            .confirmed
            .set(rbitcoin_primitives::Height(1), Fk(2))
            .unwrap();
        q.on_load_pack().unwrap();
        assert!(
            q.confirm_parent_cache().get_header_plan(1).is_none(),
            "load pack must GC header plans <= store tip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drain done, fence not yet: TipOnly would miss. In-flight still binds.
    #[test]
    fn inflight_binds_after_drain_before_fence() {
        let (dir, q) = temp_query("inflight-drain-before-fence");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_plan_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
        ));
        q.archive_commit_plan(plan_a).unwrap();
        assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);
        log.prune_if_head_ready(&q.store().height_fence_snapshot(), q.head_drain_fk());
        assert!(
            log.snapshot().get_create_fk(&parent_txid).is_some(),
            "fence missing: prune must keep"
        );
        let mut need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xee)])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &log.snapshot(), None)
            .expect("in-flight binds after drain, before fence");
        assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After drain+fence, empty in-flight: TipOnly stamps the connected head.
    #[test]
    fn leftover_tiponly_after_fence_clears_pending() {
        let (dir, q) = temp_query("leftover-fence-clears-pending");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let header_fk = plan_a.per_header_ranges[0].0;
        q.archive_commit_plan(plan_a).unwrap();
        q.store()
            .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
            .unwrap();
        q.on_load_pack().unwrap();

        let mut need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xed)])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &empty, None)
            .expect("TipOnly must stamp after fence, without leftover pending");
        assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Leftover miss (unknown parent) hop-dumps once. Lookup TipOnly does not.
    #[test]
    fn leftover_miss_dumps_probe_diag() {
        let (dir, q) = temp_query("leftover-miss-diag");
        let empty = crate::InFlightView::empty();
        let ghost = [0xDDu8; 32];
        let mut need = vec![(Fk(1), vec![child_spend(ghost, 0xaa)])];
        let _ = q.archive_plan_batch_from_store(&mut need, 1, &empty, None);
        assert!(
            rbitcoin_store::leftover_probe_diag_ready(),
            "leftover miss must hop-dump once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fence before drain (67438): prune keeps the layer; bind uses in-flight.
    #[test]
    fn inflight_binds_after_fence_before_drain() {
        let (dir, q) = temp_query("inflight-fence-before-drain");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let header_fk = plan_a.per_header_ranges[0].0;
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_plan_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
        ));
        q.archive_commit_plan_defer_head(plan_a).unwrap();
        assert!(
            q.store().txs.pending_head_len() >= 1,
            "create must still be queued — drain has not inserted tx.head"
        );
        q.store()
            .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
            .unwrap();
        log.prune_if_head_ready(&q.store().height_fence_snapshot(), q.head_drain_fk());
        assert!(
            log.snapshot().get_create_fk(&parent_txid).is_some(),
            "drain_fk 0: prune must keep"
        );
        let mut need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xec)])];
        let plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &log.snapshot(), None)
            .expect("in-flight binds after fence, before drain");
        assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prep pin identity: reverse map + range denserels (no sidefile re-read).
    #[test]
    fn plan_external_parent_txid_fills_range_denserels_pin() {
        let (dir, q) = temp_query("plan-parent-txid-ram");
        let parent = coinbase_apply(7);
        let parent_txid = parent.tx.txid;
        let fks = q
            .store
            .txs
            .put_full_batch_indexed(
                &[(
                    parent.tx.clone(),
                    parent.inputs.clone(),
                    parent.outputs.clone(),
                )],
                true,
            )
            .unwrap();
        let parent_fk = fks[0];
        let pid = parent_fk.get().unwrap();
        let range = q.store.txs.body_range(parent_fk).unwrap();

        // Simulate plan stamp reverse map (txid→fk invert).
        let mut plan = super::ArchiveWritePlan::empty();
        plan.external_parents
            .insert(pid, crate::ParentIdent::with_body(parent_txid, range));

        let known = plan.external_parent_txid(pid).expect("reverse map");
        let (rows, _body_ns, _dec_ns) = q
            .store
            .get_outs_by_range_batch(&[(parent_fk, range, known, vec![0])])
            .unwrap();
        let (tx, live, sparse) = rows[0].as_ref().expect("denserels");
        assert_eq!(
            tx.txid, parent_txid,
            "API sets known_txid (RAM), not sidefile"
        );
        assert_eq!(live.len(), 1);
        assert_eq!(sparse.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Plan head path stamps create_fk + range only — pin denserels by range;
    /// commit does not process-seed parents or creates into a pin FIFO.
    #[test]
    fn plan_head_resolved_parents_plan_local_only() {
        let (dir, q) = temp_query("plan-creates-only");
        // Parent connected (TipOnly plan stamp).
        use rbitcoin_primitives::Height;
        use rbitcoin_store::HeaderRecord;
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let ph = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [1u8; 32],
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        assert_eq!(q.tx_body_count(), 1);

        let mut child_txid = [0u8; 32];
        child_txid[0] = 0xcd;
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need = vec![(Fk(2), vec![child])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 2, &crate::InFlightView::empty(), None)
            .expect("parent via head");
        assert_eq!(plan.planned_fks, vec![Fk(2)]);
        assert_eq!(plan.packed[0].1[0].create_fk, Fk(1));
        assert_eq!(plan.batch_creates.len(), 1);
        assert_eq!(plan.batch_creates[0].0, child_txid);
        // Plan stamp is fk+range only — denserels load at pin by offset.
        assert!(
            plan.external_parents
                .get(&1)
                .and_then(|p| p.body)
                .is_some_and(|r| r.1 > 0),
            "plan must record Class A body range for head-resolved parent"
        );
        assert_eq!(
            plan.external_parent_txid(1),
            Some(parent_txid),
            "plan reverse map: create_fk → prev_txid from stamp resolve (RAM)"
        );

        // Commit succeeds; batch_pin retained on plan path only (dropped with plan).
        let batch_pin_len = plan.batch_pin.len();
        q.archive_commit_plan(plan).unwrap();
        assert_eq!(batch_pin_len, 1);
        assert_eq!(q.tx_body_count(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same-header spend is not a pin parent; later header in the pack is.
    #[test]
    fn plan_batch_same_header_vouts_skipped_cross_height_pinned() {
        let (dir, q) = temp_query("plan-same-header-vouts");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let child = child_spend(parent_txid, 0xcd);
        let mut same = vec![(Fk(1), vec![parent.clone(), child.clone()])];
        let plan_same = q
            .archive_plan_batch_from_store(&mut same, 1, &crate::InFlightView::empty(), None)
            .expect("same header");
        assert_eq!(plan_same.planned_fks, vec![Fk(1), Fk(2)]);
        assert!(
            plan_same.external_parent_vouts.get(&1).is_none(),
            "same-header create must not be in parent_vouts"
        );

        let mut cross = vec![
            (Fk(10), vec![parent]),
            (Fk(11), vec![child_spend(parent_txid, 0xce)]),
        ];
        let plan_cross = q
            .archive_plan_batch_from_store(&mut cross, 1, &crate::InFlightView::empty(), None)
            .expect("cross height");
        assert_eq!(
            plan_cross
                .external_parent_vouts
                .get(&1)
                .map(|v| v.as_slice()),
            Some(&[0u32][..]),
            "later header in the pack must pin the earlier create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S0 plan: stamp_external already idx-filled; do not fill_missing twice.
    #[test]
    fn plan_batch_one_fill_missing_when_parents_already_stamped() {
        use std::sync::atomic::Ordering;
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::FILL_MISSING_N.swap(0, Ordering::Relaxed);
            let (dir, q) = temp_query("plan-one-fill-missing");
            use rbitcoin_primitives::Height;
            use rbitcoin_store::HeaderRecord;
            let parent = coinbase_apply(1);
            let parent_txid = parent.tx.txid;
            let ph = HeaderRecord {
                prev_fk: Fk::NULL,
                version: 1,
                timestamp: 1,
                bits: 1,
                nonce: 1,
                merkle_root: [1u8; 32],
                hash: [1u8; 32],
            };
            q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
            let spent = q.store.txs.spent_range(Fk(1)).expect("spent.idx");
            let _ = crate::archive_phase_stats::FILL_MISSING_N.swap(0, Ordering::Relaxed);
            let mut need = vec![(Fk(2), vec![child_spend(parent_txid, 0xcd)])];
            let plan = q
                .archive_plan_batch_from_store(&mut need, 2, &crate::InFlightView::empty(), None)
                .expect("parent via head");
            assert_eq!(plan.packed[0].1[0].create_fk, Fk(1));
            assert!(plan
                .external_parents
                .get(&1)
                .and_then(|p| p.body)
                .is_some_and(|r| r.1 > 0));
            assert_eq!(
                plan.external_parents.get(&1).and_then(|p| p.spent),
                Some(spent)
            );
            assert_eq!(
                crate::archive_phase_stats::FILL_MISSING_N.swap(0, Ordering::Relaxed),
                1,
                "stamp_external fill_missing is enough when packed adds no new fks"
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// Packed reconstruct already has create_fk: still idx-fill (not in need).
    #[test]
    fn plan_batch_prestamp_create_fk_still_idx_fills() {
        use rbitcoin_primitives::Height;
        use rbitcoin_store::HeaderRecord;
        let (dir, q) = temp_query("plan-prestamp-fk");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let ph = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [1u8; 32],
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        let spent = q.store.txs.spent_range(Fk(1)).expect("spent.idx");
        let mut child = child_spend(parent_txid, 0xcf);
        child.inputs[0].create_fk = Fk(1);
        let mut need = vec![(Fk(2), vec![child])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 2, &crate::InFlightView::empty(), None)
            .expect("prestamp parent");
        assert_eq!(plan.packed[0].1[0].create_fk, Fk(1));
        assert!(
            plan.external_parents
                .get(&1)
                .and_then(|p| p.body)
                .is_some_and(|r| r.1 > 0),
            "pre-stamped create_fk must still receive body_range"
        );
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.spent),
            Some(spent)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Creates-only in_flight (txid→fk, no denserels outs) must still get
    /// body_range via idx so load denserels-by-range works (mainnet 961466 class).
    #[test]
    fn plan_inflight_creates_only_fills_parent_body_range() {
        let (dir, q) = temp_query("plan-inflight-range");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        q.store
            .txs
            .put_full_batch_indexed(
                &[(parent.tx, parent.inputs, parent.outputs)],
                /*index=*/ true,
            )
            .unwrap();
        // Creates-only layer: fk known, no CreatePin outs (archived mid-head race).
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_txid_fks([(parent_txid, Fk(1))]));
        let ifo = log.snapshot();
        assert!(ifo.get_out(1).is_none());

        let mut child_txid = [0u8; 32];
        child_txid[0] = 0xee;
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need = vec![(Fk(2), vec![child])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 2, &ifo, None)
            .expect("parent via creates-only in_flight");
        assert_eq!(plan.packed[0].1[0].create_fk, Fk(1));
        assert!(
            plan.external_parents
                .get(&1)
                .and_then(|p| p.body)
                .is_some_and(|r| r.1 > 0),
            "creates-only in_flight must still stamp body_range for load denserels"
        );
        assert_eq!(plan.external_parent_txid(1), Some(parent_txid));
        assert_eq!(
            plan.external_parent_vouts.get(&1).map(|v| v.as_slice()),
            Some(&[0u32][..]),
            "lookup packing must publish parent need-vouts for load pin"
        );
        let spent = q.store.txs.spent_range(Fk(1)).expect("archived spent.idx");
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.spent),
            Some(spent),
            "creates-only in_flight must stamp spent.idx range (write ensure skip)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TipOnly leftover parent: body range from head, spent.idx range on the stamp.
    #[test]
    fn fill_missing_parent_ranges_stamps_spent_idx_for_archived() {
        use rbitcoin_primitives::Height;
        use rbitcoin_store::HeaderRecord;
        let (dir, q) = temp_query("stamp-spent-idx");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let ph = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [1u8; 32],
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        let spent = q.store.txs.spent_range(Fk(1)).expect("spent.idx");
        let helper = crate::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &crate::InFlightView::empty(),
            q.published_ids().as_ref(),
            q.recent_creates().as_ref(),
        )
        .expect("stamp archived parent");
        assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(1)));
        assert!(helper
            .idents
            .get(&1)
            .and_then(|p| p.body)
            .is_some_and(|r| r.1 > 0));
        assert_eq!(
            helper.idents.get(&1).and_then(|p| p.spent),
            Some(spent),
            "archived parent must carry spent.idx range on the lookup stamp"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// In-flight CreatePin on the oldest layer still skips idx (no store row).
    #[test]
    fn fill_missing_skips_idx_when_oldest_layer_has_outs() {
        let (dir, q) = temp_query("fill-skip-oldest-outs");
        let pin = std::sync::Arc::new((
            TxRecord {
                txid: [1u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        ));
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_plan_pins([(Fk(1), &pin)]));
        for i in 10u8..18 {
            let mut tid = [0u8; 32];
            tid[0] = i;
            log.note_layer(crate::InFlightLayer::from_txid_fks([(tid, Fk(i as u64))]));
        }
        let mut idents = crate::U64Map::default();
        idents.insert(1, crate::ParentIdent::new([1u8; 32]));
        crate::fill_missing_parent_ranges(q.store(), &log.snapshot(), &mut idents)
            .expect("in-flight outs skip idx even on the oldest layer");
        assert!(
            idents.get(&1).and_then(|p| p.body).is_none(),
            "skip must not invent a body_range"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_filter_need_header_fks_drops_archived() {
        use rbitcoin_store::HeaderRecord;
        let (dir, q) = temp_query("filter-header-fks");
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [2u8; 32],
        };
        let hfk = q
            .commit_class_a_only(&header, &[coinbase_apply(1)])
            .unwrap();
        let need = q
            .archive_filter_need_header_fks(&[hfk, hfk, Fk(99)])
            .unwrap();
        assert_eq!(need, vec![Fk(99)], "archived + dup dropped; missing kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stamp emits SpendEdges (create_fk) so pin/write need not walk packed ins.
    #[test]
    fn plan_batch_emits_spend_edges() {
        let (dir, q) = temp_query("plan-spend-edges");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let mut need = vec![(Fk(1), vec![parent, child_spend(parent_txid, 0xee)])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
            .expect("plan");
        assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2)]);
        let cb = plan.edges.get(&1).expect("coinbase edges");
        assert_eq!(cb.len(), 1);
        assert!(cb[0].create_fk.is_null());
        let edges = plan
            .edges
            .get(&2)
            .expect("plan stamp must emit spend edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].prev_txid, parent_txid);
        assert_eq!(edges[0].vout, 0);
        assert_eq!(edges[0].spend_fk, Fk(2));
        assert_eq!(edges[0].create_fk, Fk(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn wire_parent_child_big_script_sig() -> (bitcoin::Block, Vec<[u8; 32]>, Vec<u8>) {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction,
            TxIn, TxMerkleNode, TxOut, Witness,
        };
        let parent = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0xaa]),
            }],
        };
        let parent_txid = parent.compute_txid();
        let script_sig = vec![0xab; 10_000];
        let child = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(script_sig.clone()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0xbb]),
            }],
        };
        let txids = vec![
            parent.compute_txid().to_byte_array(),
            child.compute_txid().to_byte_array(),
        ];
        let block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![parent, child],
        };
        (block, txids, script_sig)
    }

    /// D1: wire planner never builds TxApply; packed ins empty; CreatePin matches wire outs.
    #[test]
    fn plan_batch_from_wire_skips_tx_apply() {
        let (dir, q) = temp_query("plan-from-wire");
        let (block, txids, _script_sig) = wire_parent_child_big_script_sig();
        let parent_spk = block.txdata[0].output[0].script_pubkey.to_bytes();
        let child_spk = block.txdata[1].output[0].script_pubkey.to_bytes();
        let parent_txid = txids[0];
        let plan = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlightView::empty(),
                None,
            )
            .expect("wire plan");
        assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2)]);
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "wire planner must not clone script_sig into packed ins"
        );
        assert_eq!(plan.batch_pin.len(), 2);
        assert_eq!(plan.batch_pin[0].1[0].script, parent_spk);
        assert_eq!(plan.batch_pin[1].1[0].script, child_spk);
        let cb = plan.edges.get(&1).expect("coinbase edges");
        assert_eq!(cb.len(), 1);
        assert!(cb[0].create_fk.is_null());
        let edges = plan.edges.get(&2).expect("child edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].prev_txid, parent_txid);
        assert_eq!(edges[0].vout, 0);
        assert_eq!(edges[0].spend_fk, Fk(2));
        assert_eq!(edges[0].create_fk, Fk(1));
        assert!(
            plan.body_est >= 10_000,
            "body_est must count wire ins, got {}",
            plan.body_est
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// packed pin half and batch_pin share one CreatePin Arc (no outs double-store).
    #[test]
    fn plan_packed_and_batch_pin_share_create_pin_arc() {
        use std::sync::Arc;
        let (dir, q) = temp_query("shared-create-pin");
        let mut need = vec![(Fk(1), vec![coinbase_apply(1)])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
            .unwrap();
        assert_eq!(plan.packed.len(), 1);
        assert_eq!(plan.batch_pin.len(), 1);
        assert!(
            Arc::ptr_eq(&plan.packed[0].0, &plan.batch_pin[0]),
            "outs must live in one Arc shared by packed and batch_pin"
        );
        // note_lookup_ok only Arc-clones into in-flight.
        let ifo_pin = Arc::clone(&plan.batch_pin[0]);
        assert!(Arc::ptr_eq(&ifo_pin, &plan.batch_pin[0]));
        assert_eq!(Arc::strong_count(&plan.batch_pin[0]), 3);
        q.archive_commit_plan(plan).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live pipeline pin is outs-only: stamp does not use `bulk_lookup_txid`.
    #[test]
    fn archive_plan_batch_from_store_pstore_is_not_stamp_source() {
        use crate::{BatchParents, PipelineParentStore};
        use std::sync::Arc;
        let (dir, q) = temp_query("pin-txid-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x11;
            t
        };
        let store = Arc::new(PipelineParentStore::new());
        let mut bp = BatchParents::with_store(Arc::clone(&store), 1);
        bp.insert_owned(
            Fk(99),
            TxRecord {
                txid: parent_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![(0, OutputRecord::unspent(1, vec![0x51]))],
            vec![0],
            Some(false),
            Some((5000, 40)),
            Vec::new(),
        );
        bp.publish_to_store();
        let _keep = bp;

        let child_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x22;
            t
        };
        let child = TxApply {
            tx: TxRecord {
                txid: child_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: parent_txid,
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let mut need = vec![(Fk(1), vec![child])];
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let err = q
                .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
                .expect_err("pstore pin is not a stamp source");
            assert!(
                err.to_string().contains("parent create_fk unresolved"),
                "got: {err}"
            );
            let mix = crate::archive_phase_stats::sample_and_reset();
            assert_eq!(mix.pin_txid_n, 0);
            assert!(mix.head_need > 0, "pstore-only parent must leftover");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BQ-ahead facts live on the published layer. A leftover hits map is not
    /// a stamp source (shipped IBD already passes `None`).
    #[test]
    fn archive_plan_batch_from_store_bq_hits_map_is_not_stamp_source() {
        let (dir, q) = temp_query("bq-hits-not-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x33;
            t
        };
        let child = child_spend(parent_txid, 0x44);
        let mut need = vec![(Fk(1), vec![child])];
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let err = q
                .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
                .expect_err("bq parent_hits map is not a stamp source");
            assert!(
                err.to_string().contains("parent create_fk unresolved"),
                "got: {err}"
            );
            let mix = crate::archive_phase_stats::sample_and_reset();
            assert_eq!(mix.pin_txid_n, 0);
            assert!(mix.head_need > 0, "bq-map-only parent must leftover");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Published union supplies create_fk + range with no pin, BQ hits, or head row.
    #[test]
    fn archive_plan_batch_from_store_hits_published_ids() {
        use crate::IdMap;
        use std::sync::Arc;
        let (dir, q) = temp_query("published-ids-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x55;
            t
        };
        let published = q.published_ids();
        let mut m = IdMap::default();
        m.insert(parent_txid, (Fk(66), (3000, 24)));
        published.publish(Arc::new(m));
        let child = child_spend(parent_txid, 0x66);
        let mut need = vec![(Fk(1), vec![child])];
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let plan = q
                .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
                .expect("published union stamp");
            assert_eq!(plan.packed[0].1[0].create_fk, Fk(66));
            assert_eq!(
                plan.external_parents.get(&66).and_then(|p| p.body),
                Some((3000, 24))
            );
            assert_eq!(plan.external_parent_txid(66), Some(parent_txid));
            let mix = crate::archive_phase_stats::sample_and_reset();
            assert_eq!(
                mix.pin_txid_n, 1,
                "published union hits use the id_cache meter"
            );
            assert_eq!(
                mix.head_need, 0,
                "published union must skip leftover TipOnly"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S0 plan and the shared helper stamp the same published parent (one union).
    #[test]
    fn stamp_external_parents_matches_plan_batch_on_published() {
        use crate::IdMap;
        use std::sync::Arc;
        let (dir, q) = temp_query("stamp-helper-plan");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x71;
            t
        };
        let published = q.published_ids();
        let mut m = IdMap::default();
        m.insert(parent_txid, (Fk(88), (4000, 32)));
        published.publish(Arc::new(m));

        let helper = crate::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &crate::InFlightView::empty(),
            published.as_ref(),
            q.recent_creates().as_ref(),
        )
        .expect("shared helper");
        assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(88)));
        assert_eq!(
            helper.idents.get(&88).and_then(|p| p.body),
            Some((4000, 32))
        );
        assert_eq!(helper.idents.get(&88).map(|p| p.txid), Some(parent_txid));

        let child = child_spend(parent_txid, 0x72);
        let mut need = vec![(Fk(1), vec![child])];
        let plan = q
            .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
            .expect("S0 plan");
        assert_eq!(plan.packed[0].1[0].create_fk, Fk(88));
        assert_eq!(
            plan.external_parents.get(&88).and_then(|p| p.body),
            helper.idents.get(&88).and_then(|p| p.body)
        );
        assert_eq!(
            plan.external_parent_txid(88),
            helper.idents.get(&88).map(|p| p.txid)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Write-published recent identity skips leftover TipOnly (`head_need=0`).
    #[test]
    fn stamp_hits_recent_creates_skips_leftover() {
        let (dir, q) = temp_query("recent-creates-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x91;
            t
        };
        q.recent_creates()
            .note(10, [(parent_txid, Fk(91), (5000, 16))]);
        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let helper = crate::stamp_external_parents(
                q.store(),
                &[parent_txid],
                &crate::InFlightView::empty(),
                q.published_ids().as_ref(),
                q.recent_creates().as_ref(),
            )
            .expect("recent stamp");
            assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(91)));
            assert_eq!(
                helper.idents.get(&91).and_then(|p| p.body),
                Some((5000, 16))
            );
            assert_eq!(helper.recent_n, 1);
            assert_eq!(helper.head_need_n, 0, "recent hit must skip leftover");
            assert!(
                helper
                    .idents
                    .get(&91)
                    .and_then(|p| p.pin.as_ref())
                    .is_none(),
                "identity-only recent note must not carry a CreatePin"
            );

            let child = child_spend(parent_txid, 0x92);
            let mut need = vec![(Fk(1), vec![child])];
            let plan = q
                .archive_plan_batch_from_store(&mut need, 1, &crate::InFlightView::empty(), None)
                .expect("S0 recent");
            assert_eq!(plan.packed[0].1[0].create_fk, Fk(91));
            assert_eq!(
                plan.external_parents.get(&91).and_then(|p| p.body),
                Some((5000, 16))
            );
            let mix = crate::archive_phase_stats::sample_and_reset();
            assert_eq!(mix.head_need, 0, "plan path must skip leftover too");
            assert!(mix.recent_n >= 1, "recent hits must be metered: {mix:?}");
        });
        q.recent_creates().drop_from(10);
        assert!(q.recent_creates().get(&parent_txid).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamp_recent_hit_carries_create_pin() {
        use std::sync::Arc;
        let (dir, q) = temp_query("recent-creates-pin");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x93;
            t
        };
        let pin: crate::CreatePin = Arc::new((
            rbitcoin_store::TxRecord {
                txid: parent_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![rbitcoin_store::OutputRecord::unspent(1, vec![0x51])],
        ));
        q.recent_creates().note_pins(
            10,
            [(parent_txid, Fk(93), (5000, 16), Some(Arc::clone(&pin)))],
        );
        let helper = crate::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &crate::InFlightView::empty(),
            q.published_ids().as_ref(),
            q.recent_creates().as_ref(),
        )
        .expect("recent stamp");
        let got = helper
            .idents
            .get(&93)
            .and_then(|p| p.pin.as_ref())
            .expect("stamp must carry CreatePin");
        assert!(Arc::ptr_eq(got, &pin));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After Class A + idx, `publish_recent_creates` is what write uses.
    #[test]
    fn publish_recent_creates_after_commit_skips_leftover() {
        let (dir, q) = temp_query("recent-publish");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlightView::empty();
        let plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &empty, None)
            .unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let header_fk = plan_a.per_header_ranges[0].0;
        let creates = plan_a.batch_creates.clone();
        q.archive_commit_plan(plan_a).unwrap();
        q.store()
            .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
            .unwrap();
        q.publish_recent_creates(0, creates).unwrap();
        assert!(
            q.recent_creates().get(&parent_txid).is_some(),
            "write publish must expose committed identity"
        );

        crate::archive_phase_stats::with_exclusive(|| {
            let _ = crate::archive_phase_stats::sample_and_reset();
            let mut need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xec)])];
            let plan_b = q
                .archive_plan_batch_from_store(&mut need_b, 2, &empty, None)
                .expect("recent publish must stamp");
            assert_eq!(plan_b.packed[0].1[0].create_fk, parent_fk);
            let mix = crate::archive_phase_stats::sample_and_reset();
            assert_eq!(mix.head_need, 0, "published recent must skip leftover");
            assert!(mix.recent_n >= 1, "recent publish must meter: {mix:?}");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Freeze + append: batch-merge is vector concat of frozen commit halves;
    /// external staging maps are dropped (not union-mutated).
    #[test]
    fn freeze_after_pin_then_append_preserves_fk_order() {
        let (dir, q) = temp_query("freeze-append");
        let mut need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let mut plan_a = q
            .archive_plan_batch_from_store(&mut need_a, 1, &crate::InFlightView::empty(), None)
            .unwrap();
        // Simulate residual stamp staging (must not survive freeze/append).
        plan_a
            .external_parents
            .insert(99, crate::ParentIdent::with_body([9u8; 32], (0, 1)));
        let txid = plan_a.batch_pin[0].0.txid;
        let fk = plan_a.planned_fks[0];
        plan_a.freeze_after_pin();
        assert!(plan_a.external_parents.is_empty());
        assert!(
            plan_a.batch_creates.is_empty(),
            "freeze drops batch_creates; in-flight binds from batch_pin"
        );
        let mut log = crate::InFlightLog::new();
        log.note_layer(crate::InFlightLayer::from_plan_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
        ));
        assert_eq!(
            log.snapshot().get_create_fk(&txid),
            Some(fk),
            "in-flight still has txid→fk after freeze"
        );

        let mut need_b = vec![(Fk(2), vec![coinbase_apply(2), coinbase_apply(3)])];
        let mut plan_b = q
            .archive_plan_batch_from_store(&mut need_b, 2, &crate::InFlightView::empty(), None)
            .unwrap();
        plan_b
            .external_parents
            .insert(88, crate::ParentIdent::with_body([0u8; 32], (0, 1)));
        plan_b.freeze_after_pin();

        let fks_a = plan_a.planned_fks.clone();
        let fks_b = plan_b.planned_fks.clone();
        assert_eq!(fks_a.len(), 1);
        assert_eq!(fks_b.len(), 2);

        plan_a.append(plan_b);
        assert!(
            plan_a.external_parents.is_empty(),
            "append must not keep stamp staging maps"
        );
        assert_eq!(plan_a.planned_fks.len(), 3);
        assert_eq!(&plan_a.planned_fks[..1], &fks_a[..]);
        assert_eq!(&plan_a.planned_fks[1..], &fks_b[..]);
        assert_eq!(plan_a.packed.len(), 3);
        assert_eq!(plan_a.batch_pin.len(), 3);
        // Contiguous Class A commit of the merged frozen plan.
        assert!(q.archive_commit_plan(plan_a).unwrap());
        assert_eq!(q.tx_body_count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Second commit after header_txs is linked must not re-append body (partial
    /// confirm retry / crash recovery).
    #[test]
    fn archive_commit_plan_idempotent_when_header_already_has_body() {
        use rbitcoin_store::HeaderRecord;

        let (dir, q) = temp_query("arch-idempotent");
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [2u8; 32],
        };
        let hfk = q.ensure_header(&header).unwrap();
        let mut need = vec![(hfk, vec![coinbase_apply(42)])];
        let plan = q
            .archive_plan_batch_from_store(
                &mut need,
                q.tx_body_count() + 1,
                &crate::InFlightView::empty(),
                None,
            )
            .unwrap();
        assert!(!plan.is_empty());
        assert!(q.archive_commit_plan(plan).unwrap(), "first commit appends");
        let n = q.tx_body_count();
        assert!(n >= 1);
        assert!(q.store().header_txs.has_body(hfk).unwrap());

        // Rebuild a plan as if lookup incorrectly re-planned the same header.
        let mut need2 = vec![(hfk, vec![coinbase_apply(42)])];
        let plan2 = q
            .archive_plan_batch_from_store(
                &mut need2,
                q.tx_body_count() + 1,
                &crate::InFlightView::empty(),
                None,
            )
            .unwrap();
        // filter_need empties txs when has_body — plan may be empty. Force a
        // non-empty plan by planning against a fresh need then swapping ranges.
        if plan2.is_empty() {
            // Production path: archive_filter_need_bodies clears need → empty plan.
            // Commit empty is no-op.
            assert!(!q.archive_commit_plan(plan2).unwrap());
        } else {
            assert!(
                !q.archive_commit_plan(plan2).unwrap(),
                "second commit must skip re-append"
            );
        }
        assert_eq!(
            q.tx_body_count(),
            n,
            "tx body count must not grow on idempotent re-commit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retain_headers_needing_body_strips_archived() {
        let mut plan = super::ArchiveWritePlan::empty();
        plan.planned_fks = vec![Fk(1), Fk(2), Fk(3)];
        plan.per_header_ranges = vec![(Fk(10), Fk(1), 2), (Fk(20), Fk(3), 1)];
        // Minimal packed rows so retain can compact.
        let dummy_pin = |i: u8| {
            std::sync::Arc::new((
                TxRecord {
                    txid: [i; 32],
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                },
                Vec::new(),
            ))
        };
        plan.packed = vec![
            (dummy_pin(1), Vec::new()),
            (dummy_pin(2), Vec::new()),
            (dummy_pin(3), Vec::new()),
        ];
        plan.batch_pin = vec![dummy_pin(1), dummy_pin(2), dummy_pin(3)];
        plan.spends = vec![([0u8; 32], 0, Fk(1), 0), ([0u8; 32], 0, Fk(3), 0)];
        // Header 10 already has body; 20 needs body.
        let keep = plan
            .retain_headers_needing_body(|hfk| Ok(hfk == Fk(10)))
            .unwrap();
        assert!(keep);
        assert_eq!(plan.per_header_ranges, vec![(Fk(20), Fk(3), 1)]);
        assert_eq!(plan.planned_fks, vec![Fk(3)]);
        assert_eq!(plan.packed.len(), 1);
        assert_eq!(plan.spends.len(), 1);
        assert_eq!(plan.spends[0].2, Fk(3));
    }

    /// retain_headers edges: empty ranges, all have body, no-op full keep, null fks.
    #[test]
    fn retain_headers_needing_body_edge_matrix() {
        let dummy_pin = |i: u8| {
            std::sync::Arc::new((
                TxRecord {
                    txid: [i; 32],
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                },
                Vec::new(),
            ))
        };

        // No per_header_ranges: keep iff packed non-empty.
        let mut empty_ranges = super::ArchiveWritePlan::empty();
        empty_ranges.packed = vec![(dummy_pin(1), Vec::new())];
        assert!(empty_ranges
            .retain_headers_needing_body(|_| Ok(false))
            .unwrap());
        let mut empty_all = super::ArchiveWritePlan::empty();
        assert!(!empty_all
            .retain_headers_needing_body(|_| Ok(false))
            .unwrap());

        // All headers already have body → clear plan, false.
        let mut all_have = super::ArchiveWritePlan::empty();
        all_have.planned_fks = vec![Fk(1), Fk(2)];
        all_have.per_header_ranges = vec![(Fk(10), Fk(1), 1), (Fk(20), Fk(2), 1)];
        all_have.packed = vec![(dummy_pin(1), Vec::new()), (dummy_pin(2), Vec::new())];
        all_have.batch_pin = vec![dummy_pin(1), dummy_pin(2)];
        all_have.batch_creates = vec![([1u8; 32], Fk(1)), ([2u8; 32], Fk(2))];
        assert!(!all_have.retain_headers_needing_body(|_| Ok(true)).unwrap());
        assert!(all_have.is_empty());
        assert!(all_have.per_header_ranges.is_empty());

        // Full keep (no strip): true without compact.
        let mut full = super::ArchiveWritePlan::empty();
        full.planned_fks = vec![Fk(1)];
        full.per_header_ranges = vec![(Fk(10), Fk(1), 1)];
        full.packed = vec![(dummy_pin(1), Vec::new())];
        full.batch_pin = vec![dummy_pin(1)];
        assert!(full.retain_headers_needing_body(|_| Ok(false)).unwrap());
        assert_eq!(full.planned_fks, vec![Fk(1)]);

        // Null planned fk skipped during compact.
        let mut with_null = super::ArchiveWritePlan::empty();
        with_null.planned_fks = vec![Fk::NULL, Fk(5)];
        with_null.per_header_ranges = vec![(Fk(1), Fk::NULL, 1), (Fk(2), Fk(5), 1)];
        with_null.packed = vec![(dummy_pin(0), Vec::new()), (dummy_pin(5), Vec::new())];
        with_null.batch_pin = vec![dummy_pin(0), dummy_pin(5)];
        // Header 1 already has body; header 2 needs body (first=Fk(5)).
        assert!(with_null
            .retain_headers_needing_body(|hfk| Ok(hfk == Fk(1)))
            .unwrap());
        assert_eq!(with_null.planned_fks, vec![Fk(5)]);

        // external_parent_txid / clear_external / append empty other.
        let mut plan = super::ArchiveWritePlan::empty();
        plan.external_parents
            .insert(7, crate::ParentIdent::new([0xab; 32]));
        assert_eq!(plan.external_parent_txid(7), Some([0xab; 32]));
        assert!(plan.external_parent_txid(8).is_none());
        plan.clear_external_parent_outs();
        assert!(plan.external_parents.is_empty());
        plan.append(super::ArchiveWritePlan::empty());
        assert!(plan.is_empty());
    }

    #[test]
    fn retain_headers_missing_first_fk_is_corrupt() {
        let dummy_pin = std::sync::Arc::new((
            TxRecord {
                txid: [5u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 0,
            },
            Vec::new(),
        ));
        let mut plan = super::ArchiveWritePlan::empty();
        plan.planned_fks = vec![Fk(5)];
        plan.per_header_ranges = vec![(Fk(10), Fk(99), 1)];
        plan.packed = vec![(dummy_pin, Vec::new())];
        let err = plan
            .retain_headers_needing_body(|_| Ok(false))
            .expect_err("missing first fk must not keep the wrong span");
        let msg = err.to_string();
        assert!(
            msg.contains("invariant") && msg.contains("retain first fk"),
            "unexpected err: {msg}"
        );
    }
}
