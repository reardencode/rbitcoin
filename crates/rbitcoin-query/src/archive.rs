//! Class A archive write path.
//!
//! Split for IBD dual-thread (prep/write may overlap with a small plan queue):
//! - **Plan** ([`Query::archive_plan_batch_from_wire`]):
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
use rbitcoin_store::{
    encode_seqsigwit_with_secret, encode_txout_meta_and_outs, encode_unspent_output_into_secret,
    encode_wire_seqsigwit_input, seqsigwit_input_len_upper, InputEdge, PackedCreate,
};
use std::sync::Arc;

/// Shared immutable create pin: tx meta + outs (records or wire).
///
/// One Arc per create — plan `packed` pin half, `batch_pin`, and prep-ahead
/// `in_flight_outs` all Arc-clone this (no deep outs clone between stages).
/// Wire pins borrow `scriptPubKey` from [`Arc<bitcoin::Block>`] until write
/// encodes Class A; records pins own [`OutputRecord`] scripts (tests / SH).
pub type CreatePin = Arc<CreatePinArc>;

/// One header's wire block + txids for Class A plan/commit.
pub type WirePlanNeed<'a> = (Fk, &'a Arc<bitcoin::Block>, &'a [[u8; 32]]);

/// Shared pin: Class A loc is filled once after append (later-wave stamp reads it).
#[derive(Debug)]
pub struct CreatePinArc {
    loc: std::sync::OnceLock<rbitcoin_store::CreateLocPair>,
    inner: CreatePinInner,
}

impl CreatePinArc {
    fn wrap(inner: CreatePinInner) -> CreatePin {
        Arc::new(Self {
            loc: std::sync::OnceLock::new(),
            inner,
        })
    }

    /// Loc from Class A append (None until write sets it).
    #[inline]
    pub fn loc(&self) -> Option<&rbitcoin_store::CreateLocPair> {
        self.loc.get()
    }

    /// Set loc once after Class A append. Second set is ignored.
    pub fn set_loc(&self, pair: rbitcoin_store::CreateLocPair) {
        let _ = self.loc.set(pair);
    }
}

impl std::ops::Deref for CreatePinArc {
    type Target = CreatePinInner;
    fn deref(&self) -> &CreatePinInner {
        &self.inner
    }
}

/// [`CreatePin`] payload.
#[derive(Debug)]
pub enum CreatePinInner {
    Records {
        tx: TxRecord,
        outs: Vec<OutputRecord>,
    },
    Wire {
        block: Arc<bitcoin::Block>,
        tx_index: u32,
        tx: TxRecord,
    },
}

impl CreatePinInner {
    pub fn records(tx: TxRecord, outs: Vec<OutputRecord>) -> CreatePin {
        CreatePinArc::wrap(Self::Records { tx, outs })
    }

    pub fn wire(block: Arc<bitcoin::Block>, tx_index: u32, tx: TxRecord) -> CreatePin {
        CreatePinArc::wrap(Self::Wire {
            block,
            tx_index,
            tx,
        })
    }

    #[inline]
    pub fn tx(&self) -> &TxRecord {
        match self {
            Self::Records { tx, .. } | Self::Wire { tx, .. } => tx,
        }
    }

    #[inline]
    pub fn n_out(&self) -> usize {
        match self {
            Self::Records { outs, .. } => outs.len(),
            Self::Wire {
                block, tx_index, ..
            } => block
                .txdata
                .get(*tx_index as usize)
                .map(|t| t.output.len())
                .unwrap_or(0),
        }
    }

    #[inline]
    pub fn out_parts(&self, vout: u32) -> Option<(i64, &[u8])> {
        match self {
            Self::Records { outs, .. } => {
                let o = outs.get(vout as usize)?;
                Some((o.value, o.script.as_slice()))
            }
            Self::Wire {
                block, tx_index, ..
            } => {
                let o = block
                    .txdata
                    .get(*tx_index as usize)?
                    .output
                    .get(vout as usize)?;
                Some((o.value.to_sat() as i64, o.script_pubkey.as_bytes()))
            }
        }
    }

    pub fn out_record(&self, vout: u32) -> Option<OutputRecord> {
        let (value, script) = self.out_parts(vout)?;
        Some(OutputRecord::unspent(value, script.to_vec()))
    }

    pub fn for_each_script(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Self::Records { outs, .. } => {
                for o in outs {
                    f(o.script.as_slice());
                }
            }
            Self::Wire {
                block, tx_index, ..
            } => {
                if let Some(tx) = block.txdata.get(*tx_index as usize) {
                    for o in &tx.output {
                        f(o.script_pubkey.as_bytes());
                    }
                }
            }
        }
    }

    pub(crate) fn wire_tx(&self) -> Option<&bitcoin::Transaction> {
        match self {
            Self::Wire {
                block, tx_index, ..
            } => block.txdata.get(*tx_index as usize),
            Self::Records { .. } => None,
        }
    }
}

impl PackedCreate for CreatePinArc {
    #[inline]
    fn packed_txid(&self) -> [u8; 32] {
        self.inner.packed_txid()
    }
    #[inline]
    fn packed_tx(&self) -> &TxRecord {
        self.inner.packed_tx()
    }
    #[inline]
    fn packed_n_out(&self) -> u32 {
        self.inner.packed_n_out()
    }
    #[inline]
    fn packed_has_negative_amount(&self) -> bool {
        self.inner.packed_has_negative_amount()
    }
    #[inline]
    fn packed_outs_est(&self) -> usize {
        self.inner.packed_outs_est()
    }
    fn encode_txout_body(&self, buf: &mut Vec<u8>, secret: Option<&rbitcoin_store::StoreSecret>) {
        self.inner.encode_txout_body(buf, secret)
    }
}

impl PackedCreate for CreatePinInner {
    #[inline]
    fn packed_txid(&self) -> [u8; 32] {
        self.tx().txid
    }
    #[inline]
    fn packed_tx(&self) -> &TxRecord {
        self.tx()
    }
    #[inline]
    fn packed_n_out(&self) -> u32 {
        self.n_out() as u32
    }
    #[inline]
    fn packed_has_negative_amount(&self) -> bool {
        match self {
            Self::Records { outs, .. } => outs.iter().any(|o| o.value < 0),
            Self::Wire { .. } => false,
        }
    }
    fn packed_outs_est(&self) -> usize {
        let scripts: usize = match self {
            Self::Records { outs, .. } => outs.iter().map(|o| o.encoded_len()).sum(),
            Self::Wire { .. } => self
                .wire_tx()
                .map(|tx| {
                    tx.output
                        .iter()
                        .map(|o| OutputRecord::encoded_len_for_script(o.script_pubkey.len()))
                        .sum()
                })
                .unwrap_or(0),
        };
        16 + TxRecord::BODY_META_LEN + scripts
    }
    fn encode_txout_body(&self, buf: &mut Vec<u8>, secret: Option<&rbitcoin_store::StoreSecret>) {
        match self {
            Self::Records { tx, outs } => {
                encode_txout_meta_and_outs(tx, outs, buf, secret);
            }
            Self::Wire { tx, .. } => {
                let mut meta = tx.clone();
                meta.input_start_fk = Fk::NULL;
                meta.output_start_fk = Fk::NULL;
                meta.encode_body_meta_into(buf);
                if let Some(wtx) = self.wire_tx() {
                    for o in &wtx.output {
                        encode_unspent_output_into_secret(
                            o.value.to_sat() as i64,
                            o.script_pubkey.as_bytes(),
                            buf,
                            secret,
                        );
                    }
                }
            }
        }
    }
}

/// Approx heap bytes for one [`CreatePin`] payload (for IBD `sizes` metering).
///
/// Counts owned output scripts + fixed record overhead — not Arc
/// refcount sharing (each strong Arc still "owns" the allocation once).
/// Wire pins meter scriptPubKey lengths on the shared [`bitcoin::Block`].
#[inline]
pub fn create_pin_approx_bytes(pin: &CreatePin) -> usize {
    let mut n = 96usize; // TxRecord + Arc shell overhead (order-of-magnitude)
    match &pin.inner {
        CreatePinInner::Records { outs, .. } => {
            for o in outs {
                n = n.saturating_add(24).saturating_add(o.script.len());
            }
            n = n.saturating_add(outs.capacity().saturating_mul(24));
        }
        CreatePinInner::Wire { .. } => {
            if let Some(tx) = pin.wire_tx() {
                for o in &tx.output {
                    n = n.saturating_add(24).saturating_add(o.script_pubkey.len());
                }
            }
        }
    }
    n
}

/// Write-ready plan batch from lookup/load to commit (writer).
///
/// Planned create fks match `txs.count()+1…` at plan time; commit fails if the
/// appender returns different fks (another writer interleave — must not happen).
#[derive(Debug)]
pub struct ArchiveWritePlan {
    /// Body-append rows: shared [`CreatePin`] (tx + outs) + inputs.
    /// Wire pins leave `ins` empty; commit encodes `seqsigwit` from the wire
    /// tx and [`Self::edges`]. A records pin (no wire tx) with empty ins is
    /// Corrupt. Outs live once in the pin Arc.
    pub packed: Vec<(CreatePin, Vec<InputRecord>)>,
    pub planned_fks: Vec<Fk>,
    pub per_header_ranges: Vec<(Fk, Fk, u32)>,
    /// Empty. Block size and weight are summed from `txstat`, not stored here.
    pub per_header_sw: Vec<(u32, u32)>,
    /// Pin-time spend edges (create_fk stamped). Survives freeze. Wire commit
    /// reads `input.loc` from these edges and script bytes from the wire tx.
    pub edges: crate::SpendEdges,
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
    /// Per-tx fee in satoshis, parallel to [`Self::packed`], from assemble.
    ///
    /// Empty means commit recomputes the fee from prevouts (connect / tests).
    /// A non-empty slice must match `packed` and skips that walk.
    pub tx_fees: Vec<u64>,
    /// Per-tx `(base_size, total_size)` from the lookup precompute, parallel
    /// to [`Self::packed`]. Empty means the fee stamp still walks the wire tx.
    pub tx_sizes: Vec<(u32, u32)>,
}

impl ArchiveWritePlan {
    pub fn empty() -> Self {
        Self {
            packed: Vec::new(),
            planned_fks: Vec::new(),
            per_header_ranges: Vec::new(),
            per_header_sw: Vec::new(),
            edges: crate::SpendEdges::default(),
            batch_creates: Vec::new(),
            external_parents: crate::U64Map::default(),
            external_parent_vouts: crate::U64Map::default(),
            batch_pin: Vec::new(),
            index_tx: false,
            body_est: 0,
            tx_fees: Vec::new(),
            tx_sizes: Vec::new(),
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

    /// Per-packed-row `(vout, spend_fk)` for creates in this plan (Class A overlay).
    ///
    /// Coinbase / external parents are omitted — those slots stay zero until
    /// annotate after tip.
    pub fn same_batch_spent_overlay(&self) -> Vec<Vec<(u32, Fk, u32)>> {
        let mut overlay: Vec<Vec<(u32, Fk, u32)>> = vec![Vec::new(); self.packed.len()];
        if overlay.is_empty() {
            return overlay;
        }
        let mut idx: crate::U64Map<usize> = crate::U64Map::default();
        for (i, fk) in self.planned_fks.iter().enumerate() {
            if let Some(id) = fk.get() {
                idx.insert(id, i);
            }
        }
        for eds in self.edges.values() {
            for e in eds {
                let Some(cid) = e.create_fk.get() else {
                    continue;
                };
                let Some(&i) = idx.get(&cid) else {
                    continue;
                };
                overlay[i].push((e.vout, e.spend_fk, e.vin));
            }
        }
        overlay
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

    /// Drop stamp staging before pin.
    ///
    /// Load calls this before pin. Pin does not read `external_parents` or
    /// `batch_creates`. After this, the plan is a commit payload (`packed` /
    /// `planned_fks` / headers / `batch_pin`). Wire packed `ins` stay empty;
    /// commit encodes seqsigwit from the wire transaction. Prep must call this
    /// (or [`Self::clear_external_parent_outs`]) before enqueue to scripts/write
    /// so batch-merge never mutates growing stamp maps.
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
        let mut new_sw: Vec<(u32, u32)> = Vec::with_capacity(self.per_header_ranges.len());
        for (i, &(hfk, first, n)) in self.per_header_ranges.iter().enumerate() {
            if has_body(hfk)? {
                continue;
            }
            new_ranges.push((hfk, first, n));
            if i < self.per_header_sw.len() {
                new_sw.push(self.per_header_sw[i]);
            }
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
        let old_fees = std::mem::take(&mut self.tx_fees);
        let old_sizes = std::mem::take(&mut self.tx_sizes);
        let fees_aligned = old_fees.len() == old_packed.len();
        let sizes_aligned = old_sizes.len() == old_packed.len();
        let mut new_packed = Vec::with_capacity(keep_fks.len());
        let mut new_fks = Vec::with_capacity(keep_fks.len());
        let mut new_pin = Vec::with_capacity(keep_fks.len());
        let mut new_fees = Vec::with_capacity(keep_fks.len());
        let mut new_sizes = Vec::with_capacity(keep_fks.len());
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
            if fees_aligned {
                new_fees.push(old_fees[i]);
            }
            if sizes_aligned {
                new_sizes.push(old_sizes[i]);
            }
        }
        self.packed = new_packed;
        self.planned_fks = new_fks;
        self.batch_pin = new_pin;
        self.tx_fees = new_fees;
        self.tx_sizes = new_sizes;
        self.per_header_ranges = new_ranges;
        self.per_header_sw = new_sw;
        self.edges.retain(|id, _| keep_fks.contains(id));
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

        let fees_aligned =
            self.tx_fees.len() == self.packed.len() && other.tx_fees.len() == other.packed.len();
        let sizes_aligned =
            self.tx_sizes.len() == self.packed.len() && other.tx_sizes.len() == other.packed.len();
        self.packed.append(&mut other.packed);
        if fees_aligned {
            self.tx_fees.append(&mut other.tx_fees);
        } else {
            self.tx_fees.clear();
        }
        if sizes_aligned {
            self.tx_sizes.append(&mut other.tx_sizes);
        } else {
            self.tx_sizes.clear();
        }
        self.planned_fks.append(&mut other.planned_fks);
        self.per_header_ranges.append(&mut other.per_header_ranges);
        self.per_header_sw.append(&mut other.per_header_sw);
        self.edges.extend(other.edges);
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
    block: Arc<bitcoin::Block>,
    tx_index: u32,
}

fn collect_plan_need_external(
    work: &[PlanRow],
    batch_map: &crate::TxidMap<Fk>,
    carried_need: Option<&[[u8; 32]]>,
) -> Vec<[u8; 32]> {
    let mut need_external: crate::TxidSet = crate::TxidSet::with_hasher(Default::default());
    if let Some(keys) = carried_need {
        for &prev in keys {
            if prev == [0u8; 32] || batch_map.contains_key(&prev) {
                continue;
            }
            need_external.insert(prev);
        }
        return need_external.into_iter().collect();
    }
    for row in work {
        for inp in row.ins.iter() {
            if inp.is_coinbase {
                continue;
            }
            if batch_map.contains_key(&inp.prev_txid) || inp.prev_txid == [0u8; 32] {
                continue;
            }
            need_external.insert(inp.prev_txid);
        }
    }
    need_external.into_iter().collect()
}

/// Class A ins from wire + stamped spend edges (plan fill; write does not refill).
pub fn input_records_from_wire(
    tx: &bitcoin::Transaction,
    spend_fk: Fk,
    edges: &[crate::SpendEdge],
) -> Result<Vec<InputRecord>, StoreError> {
    if tx.input.len() != edges.len() {
        return Err(StoreError::Corrupt(
            "invariant: write encode spends/tx input mismatch",
        ));
    }
    let mut out = Vec::with_capacity(tx.input.len());
    for (inp, e) in tx.input.iter().zip(edges.iter()) {
        if e.spend_fk != spend_fk {
            return Err(StoreError::Corrupt(
                "invariant: write encode spend_fk mismatch",
            ));
        }
        let is_cb = inp.previous_output.is_null();
        if is_cb {
            out.push(InputRecord::coinbase(
                inp.sequence.to_consensus_u32(),
                inp.script_sig.to_bytes(),
                inp.witness.to_vec(),
            ));
            continue;
        }
        if e.create_fk.is_null() {
            return Err(StoreError::Corrupt(
                "invariant: write encode missing create_fk",
            ));
        }
        if e.prev_txid != inp.previous_output.txid.to_byte_array()
            || e.vout != inp.previous_output.vout
        {
            return Err(StoreError::Corrupt(
                "invariant: write encode edge/wire prevout mismatch",
            ));
        }
        out.push(InputRecord {
            prev_txid: inp.previous_output.txid.to_byte_array(),
            create_fk: e.create_fk,
            prev_index: inp.previous_output.vout,
            sequence: inp.sequence.to_consensus_u32(),
            script_sig: inp.script_sig.to_bytes(),
            witness: inp.witness.to_vec(),
        });
    }
    Ok(out)
}

fn wire_input_is_coinbase(inp: &bitcoin::TxIn) -> bool {
    inp.previous_output.is_null()
}

/// Edge/wire agreement without copying script or witness bytes.
fn wire_edges_match(
    tx: &bitcoin::Transaction,
    spend_fk: Fk,
    edges: &[crate::SpendEdge],
) -> Result<(), StoreError> {
    if tx.input.len() != edges.len() {
        return Err(StoreError::Corrupt(
            "invariant: write encode spends/tx input mismatch",
        ));
    }
    for (inp, e) in tx.input.iter().zip(edges.iter()) {
        if e.spend_fk != spend_fk {
            return Err(StoreError::Corrupt(
                "invariant: write encode spend_fk mismatch",
            ));
        }
        if wire_input_is_coinbase(inp) {
            continue;
        }
        if e.create_fk.is_null() {
            return Err(StoreError::Corrupt(
                "invariant: write encode missing create_fk",
            ));
        }
        if e.prev_txid != inp.previous_output.txid.to_byte_array()
            || e.vout != inp.previous_output.vout
        {
            return Err(StoreError::Corrupt(
                "invariant: write encode edge/wire prevout mismatch",
            ));
        }
    }
    Ok(())
}

fn wire_seqsigwit_upper(tx: &bitcoin::Transaction) -> u64 {
    tx.input
        .iter()
        .map(|inp| {
            seqsigwit_input_len_upper(inp.script_sig.len(), inp.witness.iter().map(|w| w.len()))
                as u64
        })
        .sum()
}

fn plan_in_from_txin(inp: &bitcoin::TxIn) -> PlanIn {
    use bitcoin::hashes::Hash;
    let is_coinbase = inp.previous_output.is_null();
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

fn stamp_txstat_rows(
    query: &Query,
    plan: &ArchiveWritePlan,
    parents: Option<&crate::BatchParents>,
) -> Result<Vec<rbitcoin_store::TxStatRow>, QueryError> {
    if plan.tx_fees.len() == plan.packed.len() && !plan.tx_fees.is_empty() {
        return stamp_txstat_from_fees(&plan.tx_fees, &plan.tx_sizes);
    }
    if !plan.tx_fees.is_empty() {
        return Err(StoreError::Corrupt("invariant: txstat fee length"));
    }
    let packed = &plan.packed;
    let mut idx: crate::U64Map<usize> = crate::U64Map::default();
    for (i, fk) in plan.planned_fks.iter().enumerate() {
        if let Some(id) = fk.get() {
            idx.insert(id, i);
        }
    }
    let mut out = Vec::with_capacity(packed.len());
    for i in 0..packed.len() {
        out.push(stamp_one_txstat(query, plan, &idx, parents, i)?);
    }
    Ok(out)
}

/// Fee and `(base, total)` already recorded at assemble from the lookup precompute.
fn stamp_txstat_from_fees(
    fees: &[u64],
    sizes: &[(u32, u32)],
) -> Result<Vec<rbitcoin_store::TxStatRow>, QueryError> {
    if sizes.len() != fees.len() {
        return Err(StoreError::Corrupt("invariant: txstat size length"));
    }
    let mut out = Vec::with_capacity(fees.len());
    for (fee, &(base, total)) in fees.iter().zip(sizes.iter()) {
        if total < base {
            return Err(StoreError::Corrupt("invariant: txstat size total"));
        }
        out.push(rbitcoin_store::TxStatRow {
            fee_sat: *fee,
            base,
            wit_extra: total - base,
        });
    }
    Ok(out)
}

fn stamp_one_txstat(
    query: &Query,
    plan: &ArchiveWritePlan,
    idx: &crate::U64Map<usize>,
    parents: Option<&crate::BatchParents>,
    i: usize,
) -> Result<rbitcoin_store::TxStatRow, QueryError> {
    let packed = &plan.packed;
    let (pin, ins) = &packed[i];
    let Some(tx) = pin.wire_tx() else {
        return Ok(txstat_placeholder_query(pin.tx().input_count));
    };
    let in_sum = if tx.is_coinbase() {
        None
    } else if ins.is_empty() {
        let sid = plan
            .planned_fks
            .get(i)
            .and_then(|fk| fk.get())
            .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
        let eds = plan
            .edges
            .get(&sid)
            .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
        if eds.len() != tx.input.len() {
            return Err(StoreError::Corrupt("invariant: wire plan edges missing"));
        }
        let mut in_sum = 0u64;
        for e in eds {
            if e.create_fk.is_null() {
                return Err(StoreError::Corrupt("invariant: spend missing create_fk"));
            }
            let val = prevout_value_at(query, packed, idx, parents, e.create_fk, e.vout)?;
            in_sum = in_sum
                .checked_add(val)
                .ok_or(StoreError::Corrupt("txstat in_sum overflow"))?;
        }
        Some(in_sum)
    } else {
        let mut in_sum = 0u64;
        for inp in ins {
            if inp.is_coinbase() {
                return Err(StoreError::Corrupt("invariant: mixed coinbase vin"));
            }
            let val = prevout_value_at(query, packed, idx, parents, inp.create_fk, inp.prev_index)?;
            in_sum = in_sum
                .checked_add(val)
                .ok_or(StoreError::Corrupt("txstat in_sum overflow"))?;
        }
        Some(in_sum)
    };
    txstat_row_from_tx(tx, in_sum)
}

fn txstat_size(tx: &bitcoin::Transaction) -> Result<(u32, u32), QueryError> {
    let base_sz = tx.base_size();
    let total = tx.total_size();
    let base = u32::try_from(base_sz).map_err(|_| StoreError::Corrupt("txstat base"))?;
    let wit_extra = u32::try_from(total.saturating_sub(base_sz))
        .map_err(|_| StoreError::Corrupt("txstat wit_extra"))?;
    Ok((base, wit_extra))
}

pub(crate) fn txstat_row_from_tx(
    tx: &bitcoin::Transaction,
    in_sum: Option<u64>,
) -> Result<rbitcoin_store::TxStatRow, QueryError> {
    let (base, wit_extra) = txstat_size(tx)?;
    let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = match in_sum {
        None => 0u64,
        Some(in_sum) => {
            if in_sum < out_sum {
                return Err(StoreError::Corrupt("txstat fee underflow"));
            }
            in_sum - out_sum
        }
    };
    Ok(rbitcoin_store::TxStatRow {
        fee_sat: fee,
        base,
        wit_extra,
    })
}

fn txstat_placeholder_query(_n_in: u32) -> rbitcoin_store::TxStatRow {
    // No wire body: leave the cell unstamped (all-zero) so getblockstats
    // reconstructs instead of reporting a zero-size row.
    rbitcoin_store::TxStatRow {
        fee_sat: 0,
        base: 0,
        wit_extra: 0,
    }
}

fn prevout_value_at(
    query: &Query,
    packed: &[(CreatePin, Vec<InputRecord>)],
    idx: &crate::U64Map<usize>,
    parents: Option<&crate::BatchParents>,
    create_fk: Fk,
    vout: u32,
) -> Result<u64, QueryError> {
    let Some(cid) = create_fk.get() else {
        return Err(StoreError::Corrupt("invariant: spend missing create_fk"));
    };
    if let Some(&i) = idx.get(&cid) {
        let (val, _) = packed[i]
            .0
            .out_parts(vout)
            .ok_or(StoreError::Corrupt("invariant: same-batch prevout"))?;
        if val < 0 {
            return Err(StoreError::Corrupt("txstat prevout negative"));
        }
        return Ok(val as u64);
    }
    if let Some(p) = parents {
        if let Some(val) = p.get_parent_txout_parts(create_fk, vout, |v, _, _| v) {
            if val < 0 {
                return Err(StoreError::Corrupt("txstat prevout negative"));
            }
            return Ok(val as u64);
        }
        return Err(StoreError::Corrupt("txstat parent not pinned"));
    }
    let o = query.tx_output_at_fk(create_fk, vout)?;
    if o.value < 0 {
        return Err(StoreError::Corrupt("txstat prevout negative"));
    }
    Ok(o.value as u64)
}

fn edge_of(parent: Fk, vout: u32) -> InputEdge {
    if parent.is_null() {
        InputEdge::coinbase()
    } else {
        InputEdge { parent, vout }
    }
}

fn commit_input_edge_rows(plan: &ArchiveWritePlan) -> Result<Vec<Vec<InputEdge>>, StoreError> {
    let mut rows = Vec::with_capacity(plan.packed.len());
    for (i, (pin, ins)) in plan.packed.iter().enumerate() {
        if pin.wire_tx().is_some() {
            let fk = plan
                .planned_fks
                .get(i)
                .copied()
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            let sid = fk
                .get()
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            let eds = plan
                .edges
                .get(&sid)
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            let n_in = pin
                .wire_tx()
                .map(|tx| tx.input.len())
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            if eds.len() != n_in {
                return Err(StoreError::Corrupt("invariant: wire plan edges missing"));
            }
            rows.push(eds.iter().map(|e| edge_of(e.create_fk, e.vout)).collect());
        } else if ins.is_empty() {
            return Err(StoreError::Corrupt("invariant: packed ins empty at write"));
        } else {
            rows.push(
                ins.iter()
                    .map(|inp| {
                        if inp.is_coinbase() {
                            InputEdge::coinbase()
                        } else {
                            edge_of(inp.create_fk, inp.prev_index)
                        }
                    })
                    .collect(),
            );
        }
    }
    Ok(rows)
}

fn seqsigwit_append_est(plan: &ArchiveWritePlan) -> usize {
    let mut n = 0usize;
    for (pin, ins) in &plan.packed {
        n = n.saturating_add(16);
        if let Some(tx) = pin.wire_tx() {
            n = n.saturating_add(wire_seqsigwit_upper(tx) as usize);
        } else {
            n = n.saturating_add(ins.iter().map(|i| i.encoded_len()).sum());
        }
    }
    n
}

fn encode_plan_row_seqsigwit(
    plan: &ArchiveWritePlan,
    i: usize,
    buf: &mut Vec<u8>,
    secret: &rbitcoin_store::StoreSecret,
) {
    let (pin, ins) = &plan.packed[i];
    let Some(tx) = pin.wire_tx() else {
        encode_seqsigwit_with_secret(ins, buf, Some(secret));
        return;
    };
    for inp in &tx.input {
        encode_wire_seqsigwit_input(
            inp.sequence.to_consensus_u32(),
            inp.script_sig.as_bytes(),
            inp.witness.iter(),
            buf,
            Some(secret),
        );
    }
}

/// Owned `seqsigwit` rows for the prune RAM window.
///
/// Wire pins keep `packed` ins empty. Prune mode is the only path that still
/// needs those bytes after the block `Arc` drops, so it builds them here from
/// the wire tx and the spend edges. A records pin contributes its ins. An
/// empty records pin is Corrupt (the caller must not cache an empty vector).
fn seqsigwit_rows_for_prune(
    plan: &mut ArchiveWritePlan,
) -> Result<Vec<Vec<InputRecord>>, StoreError> {
    let mut rows = Vec::with_capacity(plan.packed.len());
    for i in 0..plan.packed.len() {
        if !plan.packed[i].1.is_empty() {
            rows.push(std::mem::take(&mut plan.packed[i].1));
            continue;
        }
        let fk = plan
            .planned_fks
            .get(i)
            .copied()
            .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
        let sid = fk
            .get()
            .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
        let recs = {
            let (pin, _) = &plan.packed[i];
            let tx = pin.wire_tx().ok_or(StoreError::Corrupt(
                "invariant: prune seqsigwit missing inputs",
            ))?;
            let eds = plan
                .edges
                .get(&sid)
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            input_records_from_wire(tx, fk, eds)?
        };
        rows.push(recs);
    }
    Ok(rows)
}

impl Query {
    /// Class A plan + commit from wire blocks. Does not set tip.
    pub fn archive_class_a_from_wire(&self, items: &[WirePlanNeed<'_>]) -> Result<(), QueryError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut need = Vec::with_capacity(items.len());
        for &(fk, block, txids) in items {
            if self.store.header_txs.has_body(fk)? {
                continue;
            }
            if !block.txdata.is_empty() {
                need.push((fk, block, txids));
            }
        }
        if need.is_empty() {
            return Ok(());
        }
        let start = self.store.txs.count().saturating_add(1);
        let plan =
            self.archive_plan_batch_from_wire(&need, start, &crate::InFlight::new(), None, None)?;
        if plan.is_empty() {
            return Ok(());
        }
        self.archive_commit_plan(plan)?;
        Ok(())
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

    /// IBD stamp: CreatePin + SpendEdges from wire txs. Packed ins stay empty.
    /// Class A encodes `seqsigwit` from the wire tx. A records row with empty
    /// ins at commit is Corrupt.
    ///
    /// Does not build [`TxApply`]. `body_est` uses packed encoded lengths.
    /// Same txid in one block is Corrupt. Same txid across headers in the wave
    /// is BIP30 (91842/91880): both rows are planned; `batch_map` keeps the
    /// later fk.
    pub fn archive_plan_batch_from_wire(
        &self,
        need: &[WirePlanNeed<'_>],
        next_tx_start: u64,
        in_flight: &crate::InFlight,
        skeleton: Option<&crate::BatchParentIds>,
        carried_need: Option<&[[u8; 32]]>,
    ) -> Result<ArchiveWritePlan, QueryError> {
        use std::time::Instant;

        self.on_load_pack()?;
        if need.is_empty() {
            return Ok(ArchiveWritePlan::empty());
        }

        let mut next_tx = next_tx_start.max(1);
        let n_headers = need.iter().filter(|(_, b, _)| !b.txdata.is_empty()).count() as u64;

        let t_assign = Instant::now();
        let mut batch_map: crate::TxidMap<Fk> = crate::TxidMap::default();
        let mut work: Vec<PlanRow> = Vec::new();
        let mut per_header_ranges: Vec<(Fk, Fk, u32)> = Vec::with_capacity(need.len());

        for (header_fk, block, txids) in need {
            if block.txdata.is_empty() {
                continue;
            }
            if block.txdata.len() != txids.len() {
                return Err(StoreError::Corrupt("txid count mismatch"));
            }
            let first_tx_fk = Fk(next_tx);
            let n_txs = block.txdata.len() as u32;
            let mut in_block =
                crate::TxidSet::with_capacity_and_hasher(txids.len(), Default::default());
            for (tx_index, (tx, txid)) in block.txdata.iter().zip(txids.iter()).enumerate() {
                if !in_block.insert(*txid) {
                    return Err(StoreError::Corrupt(
                        "duplicate txid in block body (consensus violation)",
                    ));
                }
                let tx_fk = Fk(next_tx);
                next_tx += 1;
                batch_map.insert(*txid, tx_fk);
                let rec = tx_record_from_wire(tx, *txid);
                let ins: Vec<PlanIn> = tx.input.iter().map(plan_in_from_txin).collect();
                work.push(PlanRow {
                    tx_fk,
                    tx: rec,
                    ins,
                    block: Arc::clone(block),
                    tx_index: tx_index as u32,
                });
            }
            per_header_ranges.push((*header_fk, first_tx_fk, n_txs));
        }
        let assign_ns = t_assign.elapsed().as_nanos() as u64;
        let plan = self.finish_archive_plan(
            work,
            batch_map,
            per_header_ranges,
            n_headers,
            assign_ns,
            in_flight,
            skeleton,
            carried_need,
        )?;
        Ok(plan)
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    fn finish_archive_plan(
        &self,
        work: Vec<PlanRow>,
        batch_map: crate::TxidMap<Fk>,
        per_header_ranges: Vec<(Fk, Fk, u32)>,
        n_headers: u64,
        assign_ns: u64,
        in_flight: &crate::InFlight,
        skeleton: Option<&crate::BatchParentIds>,
        carried_need: Option<&[[u8; 32]]>,
    ) -> Result<ArchiveWritePlan, QueryError> {
        use std::time::Instant;

        let index_tx = self.tx_index_enabled();

        let t_collect = Instant::now();
        let need_vec = collect_plan_need_external(&work, &batch_map, carried_need);
        let collect_ns = t_collect.elapsed().as_nanos() as u64;

        let ext = crate::stamp_external_parents(
            &self.store,
            &need_vec,
            in_flight,
            skeleton,
            self.confirm_stats(),
        )?;
        let inflight_ns = ext.inflight_ns;
        let head_fk_ns = ext.head_fk_ns;
        let resolved = ext.resolved;
        let external_parents = ext.idents;
        self.confirm_stats().note_resolve_counts(
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
        for row in work {
            let PlanRow {
                tx_fk,
                tx,
                ins,
                block,
                tx_index,
            } = row;
            let mut tx_edges: Vec<crate::SpendEdge> = Vec::with_capacity(ins.len());
            for (i, inp) in ins.iter().enumerate() {
                if inp.is_coinbase {
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: tx_fk,
                        create_fk: Fk::NULL,
                        vin: i as u32,
                    });
                    continue;
                }
                let create_fk = if let Some(&cfk) = batch_map.get(&inp.prev_txid) {
                    batch_stamp = batch_stamp.saturating_add(1);
                    cfk
                } else if let Some(&cfk) = resolved.get(&inp.prev_txid) {
                    resolved_stamp = resolved_stamp.saturating_add(1);
                    cfk
                } else {
                    return Err(StoreError::Corrupt(
                        "archive: parent create_fk unresolved (contiguous batch required)",
                    ));
                };
                if let Some(pid) = create_fk.get() {
                    if !ArchiveWritePlan::create_in_header_ranges(&per_header_ranges, tx_fk, pid) {
                        external_parent_vouts
                            .entry(pid)
                            .or_default()
                            .push(inp.prev_index);
                    }
                }
                if inp.prev_index == u32::MAX {
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: [0u8; 32],
                        vout: u32::MAX,
                        spend_fk: tx_fk,
                        create_fk: Fk::NULL,
                        vin: i as u32,
                    });
                } else {
                    tx_edges.push(crate::SpendEdge {
                        prev_txid: inp.prev_txid,
                        vout: inp.prev_index,
                        spend_fk: tx_fk,
                        create_fk,
                        vin: i as u32,
                    });
                }
            }
            let tx_wire = block
                .txdata
                .get(tx_index as usize)
                .ok_or(StoreError::Corrupt("invariant: plan tx_index"))?;
            wire_edges_match(tx_wire, tx_fk, &tx_edges)?;
            if let Some(sid) = tx_fk.get() {
                edges.insert(sid, tx_edges);
            }
            planned_fks.push(tx_fk);
            let ins_bytes = wire_seqsigwit_upper(tx_wire);
            let pin = CreatePinInner::wire(block, tx_index, tx);
            body_est = body_est
                .saturating_add((1 + TxRecord::ENCODED_LEN) as u64)
                .saturating_add(ins_bytes)
                .saturating_add(pin.packed_outs_est() as u64);
            batch_pin.push(std::sync::Arc::clone(&pin));
            packed.push((pin, Vec::new()));
        }
        let stamp_ns = t_stamp.elapsed().as_nanos() as u64;
        for vouts in external_parent_vouts.values_mut() {
            vouts.sort_unstable();
            vouts.dedup();
        }

        let t_finish = Instant::now();
        let batch_creates: Vec<([u8; 32], Fk)> = packed
            .iter()
            .zip(planned_fks.iter())
            .map(|((pin, _), fk)| (pin.tx().txid, *fk))
            .collect();

        // Finish is cheap: body_est + batch_creates only.
        // No `count_bodies` / far-ahead scan — Class A never leads tip (unified
        // confirm commit is the sole Class A appender); body DONTNEED lead
        // heuristics were dead work that cost O(headers) RwLock gets per plan.
        let finish_ns = t_finish.elapsed().as_nanos() as u64;

        self.confirm_stats()
            .note_resolve_counts(0, 0, 0, 0, batch_stamp, resolved_stamp);
        self.confirm_stats().note_prep_plan(
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
            per_header_sw: Vec::new(),
            edges,
            batch_creates,
            external_parents,
            external_parent_vouts,
            batch_pin,
            index_tx,
            body_est,
            tx_fees: Vec::new(),
            tx_sizes: Vec::new(),
        })
    }

    /// **Writer / write path:** durable Class A put (body / head / htxs).
    ///
    /// **Idempotent:** headers that already have `header_txs` body are stripped
    /// (partial prior commit after structural/tip fail). If every header is
    /// already archived, this is a no-op and returns `Ok(false)` — no second
    /// body append / fk mismatch. Returns `Ok(true)` when body was appended.
    ///
    /// Phase walls go to [`Query::confirm_stats`] (body vs head split).
    ///
    /// Drains write-behind `tx.head` before return. Confirm write uses
    /// [`Self::archive_commit_plan_defer_head`] to overlap drain with Class C.
    pub fn archive_commit_plan(&self, plan: ArchiveWritePlan) -> Result<bool, QueryError> {
        let (committed, _) = self.archive_commit_plan_defer_head(plan)?;
        if committed {
            let _ = self.drain_pending_tx_head()?;
        }
        Ok(committed)
    }

    /// Like [`Self::archive_commit_plan`] but leaves `tx.head` in the pending map.
    /// Loc pairs are the Class A append starts (RAM). Empty when nothing committed.
    pub fn archive_commit_plan_defer_head(
        &self,
        plan: ArchiveWritePlan,
    ) -> Result<(bool, Vec<rbitcoin_store::CreateLocPair>), QueryError> {
        self.archive_commit_plan_defer_head_parents(plan, None)
    }

    /// Class A commit with optional parent pins for `txstat` fee.
    pub fn archive_commit_plan_defer_head_parents(
        &self,
        mut plan: ArchiveWritePlan,
        parents: Option<&crate::BatchParents>,
    ) -> Result<(bool, Vec<rbitcoin_store::CreateLocPair>), QueryError> {
        use std::time::Instant;
        if plan.packed.is_empty() {
            return Ok((false, Vec::new()));
        }
        if !plan.retain_headers_needing_body(|hfk| self.store.header_txs.has_body(hfk))? {
            return Ok((false, Vec::new()));
        }
        let edge_rows = commit_input_edge_rows(&plan)?;
        let seqsigwit_est = seqsigwit_append_est(&plan);
        let t0 = Instant::now();
        let n_blocks = plan.per_header_ranges.len() as u64;

        let t = Instant::now();
        self.store
            .txs
            .reserve_append(plan.body_est, plan.packed.len() as u64)?;
        let reserve_ns = t.elapsed().as_nanos() as u64;

        let t = Instant::now();
        let overlay = plan.same_batch_spent_overlay();
        let txstat = stamp_txstat_rows(self, &plan, parents)?;
        let txstat_ns = t.elapsed().as_nanos() as u64;
        self.confirm_stats().note_write_txstat(txstat_ns);

        let t = Instant::now();
        let secret = self.store.txs.store_secret().clone();
        let pins: Vec<&CreatePin> = plan.packed.iter().map(|(pin, _)| pin).collect();
        let (got_tx_fks, loc) = self.store.put_tx_pins_encoded(
            &pins,
            /*index=*/ false,
            &overlay,
            &txstat,
            &plan.per_header_ranges,
            &edge_rows,
            seqsigwit_est,
            |i, buf| encode_plan_row_seqsigwit(&plan, i, buf, &secret),
        )?;
        let body_ns = t.elapsed().as_nanos() as u64;
        if got_tx_fks.len() != plan.packed.len() {
            return Err(StoreError::Corrupt("tx put_full_batch length"));
        }
        if loc.len() != got_tx_fks.len() {
            return Err(StoreError::Corrupt("invariant: append loc length"));
        }
        if got_tx_fks != plan.planned_fks {
            return Err(StoreError::Corrupt(
                "tx put_full_batch fk mismatch (plan not committed in order)",
            ));
        }
        if self.prune_seqsigwit() {
            let ins = seqsigwit_rows_for_prune(&mut plan)?;
            self.note_appended_seqsigwit_inputs(&got_tx_fks, ins);
        }
        for ((pin, _), pair) in plan.packed.iter().zip(loc.iter()) {
            pin.set_loc(*pair);
        }

        // Head write-behind: publish pending txid→fk so resolve can hit before drain.
        let t = Instant::now();
        if plan.index_tx {
            let heads: Vec<([u8; 32], Fk)> = plan
                .packed
                .iter()
                .zip(got_tx_fks.iter())
                .map(|((pin, _), fk)| (pin.tx().txid, *fk))
                .collect();
            self.drain_pending_tx_head_if_full()?;
            self.store.txs.head_note_pending(&heads);
        }
        let head_ns = t.elapsed().as_nanos() as u64;

        let t = Instant::now();
        if !plan.per_header_ranges.is_empty() {
            self.store
                .header_txs
                .put_ranges_batch(&plan.per_header_ranges)?;
        }
        let htxs_ns = t.elapsed().as_nanos() as u64;

        let total_ns = t0.elapsed().as_nanos() as u64;
        self.confirm_stats().note_write_commit(
            total_ns,
            reserve_ns,
            body_ns,
            head_ns,
            0,
            htxs_ns,
            n_blocks.max(1),
        );
        Ok((true, loc))
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
        self.store.txs.body_txid(inp.create_fk)
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::FixtureChain;
    use crate::{Query, TxApply, WirePlanNeed};
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Arc;

    fn temp_query(label: &str) -> (crate::testutil::TempDir, Query) {
        crate::testutil::tiny_query_labeled(label)
    }

    fn first_edge_create(plan: &crate::ArchiveWritePlan) -> Fk {
        let id = plan.planned_fks[0].get().expect("spend fk");
        plan.edges.get(&id).expect("spend edges")[0].create_fk
    }

    #[test]
    fn txstat_stamp_uses_plan_base_total() {
        let (path, q) = temp_query("txstat-plan-sizes");
        let tx = TxRecord {
            txid: [0x61; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        };
        let mut plan = super::ArchiveWritePlan::empty();
        plan.packed = vec![(crate::CreatePinInner::records(tx, Vec::new()), Vec::new())];
        plan.tx_fees = vec![1];
        plan.tx_sizes = vec![(80, 100)];
        let rows = super::stamp_txstat_rows(&q, &plan, None).expect("sizes without wire");
        assert_eq!(rows[0].fee_sat, 1);
        assert_eq!(rows[0].base, 80);
        assert_eq!(rows[0].wit_extra, 20);
        let _ = path;
    }

    fn size_plan(tag: u8, with_size: bool) -> super::ArchiveWritePlan {
        let mut plan = super::ArchiveWritePlan::empty();
        plan.packed = vec![(
            crate::CreatePinInner::records(
                TxRecord {
                    txid: [tag; 32],
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 0,
                },
                Vec::new(),
            ),
            Vec::new(),
        )];
        if with_size {
            plan.tx_sizes = vec![(u32::from(tag), u32::from(tag) + 10)];
        }
        plan
    }

    #[test]
    fn append_tx_sizes_only_when_both_sides_match_packed() {
        let mut both = size_plan(1, true);
        both.append(size_plan(2, true));
        assert_eq!(both.tx_sizes, vec![(1, 11), (2, 12)]);

        let mut left_only = size_plan(1, true);
        left_only.append(size_plan(2, false));
        assert!(left_only.tx_sizes.is_empty());

        let mut right_only = size_plan(1, false);
        right_only.append(size_plan(2, true));
        assert!(right_only.tx_sizes.is_empty());
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

    fn plan_applies(
        q: &Query,
        need: &[(Fk, Vec<TxApply>)],
        next: u64,
        in_flight: &crate::InFlight,
        skeleton: Option<&crate::BatchParentIds>,
    ) -> Result<crate::ArchiveWritePlan, crate::QueryError> {
        let wires: Vec<_> = need
            .iter()
            .filter(|(_, txs)| !txs.is_empty())
            .map(|(fk, txs)| {
                let (b, ids) = crate::testutil::block_from_applies(txs);
                (*fk, Arc::new(b), ids)
            })
            .collect();
        let refs: Vec<WirePlanNeed<'_>> = wires
            .iter()
            .map(|(fk, b, ids)| (*fk, b, ids.as_slice()))
            .collect();
        let carried: Vec<[u8; 32]> = need
            .iter()
            .flat_map(|(_, txs)| {
                txs.iter().flat_map(|ta| {
                    ta.inputs.iter().filter_map(|inp| {
                        (inp.prev_index != u32::MAX && inp.prev_txid != [0u8; 32])
                            .then_some(inp.prev_txid)
                    })
                })
            })
            .collect();
        let plan = q.archive_plan_batch_from_wire(
            &refs,
            next,
            in_flight,
            skeleton,
            skeleton.is_some().then_some(carried.as_slice()),
        )?;
        Ok(plan)
    }

    #[test]
    fn commit_class_a_only_writes_packed_ins_from_wire() {
        use rbitcoin_store::HeaderRecord;

        let (dir, q) = temp_query("class-a-packed-ins");
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 1,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [3u8; 32],
            size: 0,
            weight: 0,
        };
        let ta = coinbase_apply(1);
        let sig = ta.inputs[0].script_sig.clone();
        let hfk = q.commit_class_a_only(&header, &[ta]).unwrap();
        assert!(q.store().header_txs.has_body(hfk).unwrap());
        let (_tx, ins, _outs) = q.store().get_tx_full(Fk(1)).unwrap();
        assert_eq!(ins.len(), 1, "plan fill must persist packed ins");
        assert_eq!(ins[0].script_sig, sig);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// batch_pin Arc denserels match encode+decode layout (PR-A/B pin handoff).
    #[test]
    fn plan_batch_pin_arc_denserels_match_layout() {
        use std::sync::Arc;
        let (dir, q) = temp_query("batch-pin-arc");
        let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
        let plan = plan_applies(&q, &need, 1, &crate::InFlight::new(), None).unwrap();
        assert_eq!(plan.batch_pin.len(), plan.planned_fks.len());
        assert_eq!(plan.batch_pin.len(), plan.packed.len());
        let mut ifo: crate::U64Map<super::CreatePin> = crate::U64Map::default();
        for (fk, pin) in plan.planned_fks.iter().zip(plan.batch_pin.iter()) {
            if let Some(id) = fk.get() {
                ifo.insert(id, Arc::clone(pin));
            }
        }
        for ((pin, _ins), _) in plan.packed.iter().zip(plan.batch_pin.iter()) {
            let mut raw = Vec::new();
            rbitcoin_store::PackedCreate::encode_txout_body(pin.as_ref(), &mut raw, None);
            let (meta, dec_outs, _) =
                rbitcoin_store::decode_packed_tx_outs_with_spender_rels(&raw, 1).unwrap();
            assert_eq!(meta.output_count as usize, dec_outs.len());
            assert_eq!(pin.n_out(), dec_outs.len());
        }
        assert_eq!(ifo.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_phase_stats_cover_plan_and_commit_wall() {
        // Exclusive lock so a parallel sample_and_reset cannot steal this
        // window (llvm-cov / cargo test --workspace).
        {
            let (dir, q) = temp_query("arch-phases");
            let _ = q.confirm_stats().take_window();
            let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(2)])];
            let plan = plan_applies(&q, &need, 1, &crate::InFlight::new(), None).unwrap();
            assert_eq!(plan.planned_fks.len(), 2);
            q.archive_commit_plan(plan).unwrap();
            let s = q.confirm_stats().take_window();
            assert!(
                s.arch_blocks >= 1 || s.arch_prep_assign_ns > 0 || s.arch_prep_stamp_ns > 0,
                "plan noted"
            );
            assert!(
                s.arch_write_blocks >= 1 || s.arch_write_total_ns > 0,
                "commit total"
            );
            assert!(
                s.arch_write_blocks >= 1 || s.arch_write_body_ns > 0,
                "body put timed"
            );
            let wsum = s.write_phases_sum_ns();
            assert!(
                wsum <= s.arch_write_total_ns.saturating_add(200_000),
                "write sum {} ≫ total {}",
                wsum,
                s.arch_write_total_ns
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn plan_from_reserves_fks_for_overlap_then_commit_in_order() {
        let (dir, q) = temp_query("plan-from");
        // Seed one body so count starts at 1.
        let seed = vec![(Fk(1), vec![coinbase_apply(1)])];
        // Need a real header_fk path: plan only needs Vec<(Fk, Vec<TxApply>)>.
        let need0 = seed;
        let p0 = plan_applies(
            &q,
            &need0,
            q.tx_body_count() + 1,
            &crate::InFlight::new(),
            None,
        )
        .unwrap();
        q.archive_commit_plan(p0).unwrap();
        assert_eq!(q.tx_body_count(), 1);

        // Reserve two plans as prep would with write queue depth 2.
        let empty = crate::InFlight::new();
        let mut next = q.tx_body_count() + 1;
        let need_a = vec![(Fk(10), vec![coinbase_apply(10), coinbase_apply(11)])];
        let plan_a = plan_applies(&q, &need_a, next, &empty, None).unwrap();
        assert_eq!(plan_a.planned_fks, vec![Fk(2), Fk(3)]);
        next = plan_a.planned_fks.last().unwrap().0 + 1;
        assert_eq!(next, 4);

        let need_b = vec![(Fk(20), vec![coinbase_apply(20)])];
        let plan_b = plan_applies(&q, &need_b, next, &empty, None).unwrap();
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
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlight::new();
        let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
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
        let need_b = vec![(Fk(2), vec![child])];

        // Without in_flight → unresolved.
        let err = plan_applies(&q, &need_b, 2, &empty, None).unwrap_err();
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
        let need_b = vec![(Fk(2), vec![child])];
        let mut inflight = crate::InFlight::new();
        inflight.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
        let plan_b =
            plan_applies(&q, &need_b, 2, &inflight, None).expect("inflight parent resolve");
        assert_eq!(plan_b.planned_fks, vec![Fk(2)]);
        assert_eq!(
            first_edge_create(&plan_b),
            parent_fk,
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
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlight::new();
        let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let mut log = crate::InFlight::new();
        log.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
        q.archive_commit_plan(plan_a).unwrap();
        assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);

        let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xef)])];
        let plan_b = plan_applies(&q, &need_b, 2, &log, None)
            .expect("in-flight must stamp n−1 without leftover");
        assert_eq!(first_edge_create(&plan_b), parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_keeps_prev_pack_after_drain_done() {
        let (dir, q) = temp_query("leftover-keep-prev");
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlight::new();
        let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
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
        let need_b = vec![(Fk(2), vec![child])];
        let plan_b = plan_applies(&q, &need_b, 2, &empty, None)
            .expect("height-1 child must bind prev pack after drain HWM");
        assert_eq!(first_edge_create(&plan_b), parent_fk);
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
            size: 0,
            weight: 0,
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
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlight::new();
        let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let mut log = crate::InFlight::new();
        log.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
        q.archive_commit_plan(plan_a).unwrap();
        assert_eq!(q.store().tx_height_get(parent_fk).unwrap(), None);
        log.prune_below_height(q.drain_and_fence_hi());
        assert_eq!(
            q.drain_and_fence_hi(),
            None,
            "drain fk not on fence: keep inflight"
        );
        assert!(
            log.get_create_fk(&parent_txid).is_some(),
            "fence missing: prune must keep"
        );
        let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xee)])];
        let plan_b = plan_applies(&q, &need_b, 2, &log, None)
            .expect("in-flight binds after drain, before fence");
        assert_eq!(first_edge_create(&plan_b), parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Leftover miss (unknown parent) hop-dumps once. Lookup TipOnly does not.
    #[test]
    fn leftover_miss_dumps_probe_diag() {
        let (dir, q) = temp_query("leftover-miss-diag");
        let empty = crate::InFlight::new();
        let ghost = [0xDDu8; 32];
        let need = vec![(Fk(1), vec![child_spend(ghost, 0xaa)])];
        let _ = plan_applies(&q, &need, 1, &empty, None);
        assert!(
            rbitcoin_store::leftover_probe_diag_recorded(&ghost),
            "leftover miss must hop-dump this parent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fence before drain (67438): prune keeps the layer; bind uses in-flight.
    #[test]
    fn inflight_binds_after_fence_before_drain() {
        let (dir, q) = temp_query("inflight-fence-before-drain");
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let empty = crate::InFlight::new();
        let plan_a = plan_applies(&q, &need_a, 1, &empty, None).unwrap();
        let parent_txid = plan_a.batch_creates[0].0;
        let parent_fk = plan_a.batch_creates[0].1;
        let header_fk = plan_a.per_header_ranges[0].0;
        let mut log = crate::InFlight::new();
        log.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
        q.archive_commit_plan_defer_head(plan_a).unwrap();
        assert!(
            q.store().txs.pending_head_len() >= 1,
            "create must still be queued — drain has not inserted tx.head"
        );
        q.store()
            .height_fence_extend(rbitcoin_primitives::Height(0), header_fk)
            .unwrap();
        log.prune_below_height(q.drain_and_fence_hi());
        assert_eq!(q.drain_and_fence_hi(), None, "drain_fk 0: HWM is None");
        assert!(
            log.get_create_fk(&parent_txid).is_some(),
            "drain_fk 0: prune must keep"
        );
        let need_b = vec![(Fk(2), vec![child_spend(parent_txid, 0xec)])];
        let plan_b = plan_applies(&q, &need_b, 2, &log, None)
            .expect("in-flight binds after fence, before drain");
        assert_eq!(first_edge_create(&plan_b), parent_fk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same-header spend is not a pin parent; later header in the pack is.
    #[test]
    fn plan_batch_same_header_vouts_skipped_cross_height_pinned() {
        let (dir, q) = temp_query("plan-same-header-vouts");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let child = child_spend(parent_txid, 0xcd);
        let same = vec![(Fk(1), vec![parent.clone(), child.clone()])];
        let plan_same =
            plan_applies(&q, &same, 1, &crate::InFlight::new(), None).expect("same header");
        assert_eq!(plan_same.planned_fks, vec![Fk(1), Fk(2)]);
        assert!(
            !plan_same.external_parent_vouts.contains_key(&1),
            "same-header create must not be in parent_vouts"
        );

        let cross = vec![
            (Fk(10), vec![parent]),
            (Fk(11), vec![child_spend(parent_txid, 0xce)]),
        ];
        let plan_cross =
            plan_applies(&q, &cross, 1, &crate::InFlight::new(), None).expect("cross height");
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
        {
            let (dir, q) = temp_query("plan-one-fill-missing");
            let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
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
                size: 0,
                weight: 0,
            };
            q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
            let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
            let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
            let need = vec![(Fk(2), vec![child_spend(parent_txid, 0xcd)])];
            let plan =
                plan_applies(&q, &need, 2, &crate::InFlight::new(), None).expect("parent via head");
            assert_eq!(first_edge_create(&plan), Fk(1));
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
                q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed),
                0,
                "stamp_external already bound loc; finish must not fill_missing"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
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
            size: 0,
            weight: 0,
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
        let mut child = child_spend(parent_txid, 0xcf);
        child.inputs[0].create_fk = Fk(1);
        let need = vec![(Fk(2), vec![child])];
        let plan =
            plan_applies(&q, &need, 2, &crate::InFlight::new(), None).expect("prestamp parent");
        assert_eq!(first_edge_create(&plan), Fk(1));
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

    /// IBD skeleton miss + InFlight pin + loc on disk: plan does not loc-by-fk.
    /// Spent stays unset for write TLS / `CreatePin::set_loc` (mainnet 133433).
    #[test]
    fn plan_inflight_skeleton_miss_leaves_spent_unset_despite_disk_loc() {
        use std::sync::atomic::Ordering;
        let (dir, q) = temp_query("plan-inflight-skel-miss");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        let pin = crate::CreatePinInner::records(parent.tx.clone(), parent.outputs.clone());
        q.store
            .txs
            .put_full_batch_indexed(
                &[(parent.tx, parent.inputs, parent.outputs)],
                /*index=*/ true,
            )
            .unwrap();
        assert!(q.store.txs.spent_range(Fk(1)).expect("spent range").1 > 0);
        let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
        let mut log = crate::InFlight::new();
        log.note_pins([(Fk(1), &pin)], Some(1));
        let child = child_spend(parent_txid, 0xee);
        let need = vec![(Fk(2), vec![child])];
        let skel = crate::BatchParentIds::default();
        let plan = plan_applies(&q, &need, 2, &log, Some(&skel))
            .expect("inflight + empty skeleton with loc on disk");
        assert_eq!(first_edge_create(&plan), Fk(1));
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.spent),
            None,
            "IBD stamp must not loc-by-fk"
        );
        assert!(
            plan.external_parents
                .get(&1)
                .and_then(|p| p.pin.as_ref())
                .is_some(),
            "inflight pin is kept"
        );
        assert_eq!(
            q.confirm_stats().fill_missing_n.load(Ordering::Relaxed),
            0,
            "IBD skeleton path must not fill_missing"
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
        // Creates-only: fk known, no CreatePin outs (archived mid-head race).
        let mut log = crate::InFlight::new();
        log.note_creates([(parent_txid, Fk(1))], None);
        let ifo = &log;
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
        let need = vec![(Fk(2), vec![child])];
        let plan =
            plan_applies(&q, &need, 2, ifo, None).expect("parent via creates-only in_flight");
        assert_eq!(first_edge_create(&plan), Fk(1));
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
        let spent = q
            .store
            .txs
            .spent_range(Fk(1))
            .expect("archived spent range");
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.spent),
            Some(spent),
            "creates-only in_flight must stamp spent range (write ensure skip)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IBD skeleton miss + creates-only InFlight: load does not loc-by-fk even
    /// when loc is on disk. Lookup leftover (skeleton = None) still fills.
    #[test]
    fn plan_inflight_creates_only_ibd_skeleton_miss_does_not_loc_fill() {
        use std::sync::atomic::Ordering;
        let (dir, q) = temp_query("plan-inflight-creates-skel-miss");
        let parent = coinbase_apply(1);
        let parent_txid = parent.tx.txid;
        q.store
            .txs
            .put_full_batch_indexed(
                &[(parent.tx, parent.inputs, parent.outputs)],
                /*index=*/ true,
            )
            .unwrap();
        let mut log = crate::InFlight::new();
        log.note_creates([(parent_txid, Fk(1))], None);
        assert!(log.get_out(1).is_none());
        let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
        let child = child_spend(parent_txid, 0xee);
        let need = vec![(Fk(2), vec![child])];
        let skel = crate::BatchParentIds::default();
        let plan = plan_applies(&q, &need, 2, &log, Some(&skel))
            .expect("creates-only identity with empty skeleton");
        assert_eq!(first_edge_create(&plan), Fk(1));
        assert_eq!(
            plan.external_parents.get(&1).and_then(|p| p.body),
            None,
            "IBD stamp must not loc-by-fk for creates-only"
        );
        assert_eq!(plan.external_parents.get(&1).and_then(|p| p.spent), None);
        assert_eq!(q.confirm_stats().fill_missing_n.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TipOnly leftover parent: body range from head, spent range on the stamp.
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
            size: 0,
            weight: 0,
        };
        q.connect_block(Height::GENESIS, &ph, &[parent]).unwrap();
        let spent = q.store.txs.spent_range(Fk(1)).expect("spent range");
        let helper = crate::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &crate::InFlight::new(),
            None,
            q.confirm_stats(),
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
            "archived parent must carry spent range on the lookup stamp"
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
            size: 0,
            weight: 0,
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
        let wit_push = vec![0x21; 33];
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
                witness: Witness::from_slice(&[b"wit-item-1".as_slice(), wit_push.as_slice()]),
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

    #[test]
    fn create_pin_loc_set_once_after_append() {
        use rbitcoin_store::CreateLocPair;
        let pin = crate::CreatePinInner::records(
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
        );
        let first = CreateLocPair {
            txout: (8, 16),
            spent: (8, 8),
            n_out: 1,
        };
        pin.set_loc(first);
        pin.set_loc(CreateLocPair {
            txout: (99, 1),
            spent: (99, 1),
            n_out: 9,
        });
        assert_eq!(pin.loc().copied(), Some(first));
    }

    /// D1: wire planner never builds TxApply; packed ins from stamp edges; CreatePin matches wire outs.
    #[test]
    fn plan_batch_from_wire_skips_tx_apply() {
        use std::sync::Arc;
        let (dir, q) = temp_query("plan-from-wire");
        let (block, txids, script_sig) = wire_parent_child_big_script_sig();
        let parent_txid = txids[0];
        let block = Arc::new(block);
        let parent_spk = block.txdata[0].output[0].script_pubkey.as_bytes();
        let child_spk = block.txdata[1].output[0].script_pubkey.as_bytes();
        let parent_ptr = parent_spk.as_ptr();
        let child_ptr = child_spk.as_ptr();
        let parent_spk = parent_spk.to_vec();
        let child_spk = child_spk.to_vec();
        let plan = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlight::new(),
                None,
                None,
            )
            .expect("wire plan");
        assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2)]);
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "wire plan must not retain scriptSig or witness"
        );
        assert_eq!(
            plan.batch_pin[0]
                .out_parts(0)
                .expect("parent out")
                .1
                .as_ptr(),
            parent_ptr,
            "plan must not copy scriptPubKey"
        );
        assert_eq!(
            plan.batch_pin[1]
                .out_parts(0)
                .expect("child out")
                .1
                .as_ptr(),
            child_ptr,
            "plan must not copy scriptPubKey"
        );
        assert_eq!(plan.batch_pin.len(), 2);
        assert_eq!(plan.batch_pin[0].out_parts(0).unwrap().1, parent_spk);
        assert_eq!(plan.batch_pin[1].out_parts(0).unwrap().1, child_spk);
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
        q.archive_commit_plan(plan).expect("commit from wire");
        let (_tx, ins, _outs) = q.store().get_tx_full(Fk(2)).unwrap();
        assert_eq!(ins[0].script_sig, script_sig);
        assert_eq!(ins[0].witness, vec![b"wit-item-1".to_vec(), vec![0x21; 33]]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prune mode serves confirmed script bytes from the append cache.
    /// A wire commit must fill that cache. Falling through to `get_tx_full`
    /// re-reads every transaction during IBD.
    #[test]
    fn pruned_wire_commit_serves_seqsigwit_without_reread() {
        use rbitcoin_primitives::Height;
        use std::sync::Arc;
        let (dir, q) = temp_query("prune-wire-seqsigwit");
        q.set_prune_seqsigwit(true).unwrap();
        q.set_seqsigwit_ram_threshold_bytes(1 << 20).unwrap();
        let (block, txids, script_sig) = wire_parent_child_big_script_sig();
        let block = Arc::new(block);
        let plan = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlight::new(),
                None,
                None,
            )
            .expect("wire plan");
        let fks = plan.planned_fks.clone();
        assert!(plan.packed.iter().all(|(_, ins)| ins.is_empty()));
        q.archive_commit_plan(plan).expect("commit");

        q.note_seqsigwit_ram_for_confirmed(Height(1), &fks)
            .expect("ram window from append cache");

        let cached = q
            .seqsigwit_cached_inputs(Fk(2), 1)
            .expect("cache")
            .expect("child inputs");
        assert_eq!(cached[0].script_sig, script_sig);
        assert!(!cached[0].witness.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_refuses_empty_packed_ins() {
        use std::sync::Arc;
        let (dir, q) = temp_query("commit-empty-packed-ins");
        let (block, txids, _) = wire_parent_child_big_script_sig();
        let block = Arc::new(block);
        let plan = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlight::new(),
                None,
                None,
            )
            .expect("wire plan");
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "wire plan leaves packed ins empty"
        );
        q.archive_commit_plan(plan)
            .expect("wire edges encode seqsigwit");
        let (_tx, ins, _outs) = q.store().get_tx_full(Fk(2)).unwrap();
        assert_eq!(ins[0].script_sig.len(), 10_000);

        let mut missing = q
            .archive_plan_batch_from_wire(
                &[(Fk(3), &block, txids.as_slice())],
                3,
                &crate::InFlight::new(),
                None,
                None,
            )
            .expect("second wire plan");
        missing.edges.clear();
        match q.archive_commit_plan(missing) {
            Err(e) => {
                let s = e.to_string();
                assert!(s.contains("invariant: wire plan edges missing"), "{s}");
            }
            Ok(_) => panic!("missing edges must be corrupt"),
        }

        let pin = crate::CreatePinInner::records(
            TxRecord {
                txid: [9u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        );
        let mut records = crate::ArchiveWritePlan::empty();
        records.packed.push((pin, Vec::new()));
        records.planned_fks.push(Fk(9));
        match q.archive_commit_plan(records) {
            Err(e) => {
                let s = e.to_string();
                assert!(s.contains("invariant: packed ins empty at write"), "{s}");
            }
            Ok(_) => panic!("records pin with empty ins must be corrupt"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mainnet 91842/91880 share a coinbase txid with 91812/91722. A 144-block
    /// load wave includes both; batch_map must not treat that as in-block dup.
    #[test]
    fn plan_batch_from_wire_bip30_same_txid_across_headers() {
        let (dir, q) = temp_query("bip30-wave-txid");
        let txid = coinbase_apply(1).tx.txid;
        let child = child_spend(txid, 0x99);
        let child_txid = child.tx.txid;
        let need = vec![
            (Fk(1), vec![coinbase_apply(1)]),
            (Fk(2), vec![coinbase_apply(1)]),
            (Fk(3), vec![child]),
        ];
        let plan = plan_applies(&q, &need, 1, &crate::InFlight::new(), None)
            .expect("BIP30 same-txid across headers in one wave");
        assert_eq!(plan.planned_fks, vec![Fk(1), Fk(2), Fk(3)]);
        assert_eq!(plan.packed[0].0.tx().txid, txid);
        assert_eq!(plan.packed[1].0.tx().txid, txid);
        assert_eq!(
            plan.batch_creates,
            vec![(txid, Fk(1)), (txid, Fk(2)), (child_txid, Fk(3))]
        );
        let spend = plan.edges.get(&3).expect("child");
        assert_eq!(
            spend[0].create_fk,
            Fk(2),
            "same-wave spend binds newest BIP30 create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_batch_from_wire_duplicate_txid_in_one_block_is_corrupt() {
        let (dir, q) = temp_query("dup-txid-in-block");
        let need = vec![(Fk(1), vec![coinbase_apply(1), coinbase_apply(1)])];
        let err = plan_applies(&q, &need, 1, &crate::InFlight::new(), None)
            .expect_err("in-block duplicate txid");
        assert!(
            err.to_string()
                .contains("duplicate txid in block body (consensus violation)"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Packed plan commits the coinbase prevout the apply carried.
    #[test]
    fn plan_packed_and_batch_pin_share_create_pin_arc() {
        let (dir, q) = temp_query("shared-create-pin");
        let need = vec![(Fk(1), vec![coinbase_apply(1)])];
        let plan = plan_applies(&q, &need, 1, &crate::InFlight::new(), None).unwrap();
        assert_eq!(plan.packed.len(), 1);
        assert_eq!(plan.batch_pin.len(), 1);
        let (value, script) = plan.batch_pin[0].out_parts(0).expect("vout 0");
        assert_eq!(value, 50 * 100_000_000);
        assert_eq!(script, &[0x51]);
        q.archive_commit_plan(plan).unwrap();
        let (_tx, _ins, outs) = q.store().get_tx_full(Fk(1)).unwrap();
        assert_eq!(outs[0].value, 50 * 100_000_000);
        assert_eq!(outs[0].script, vec![0x51]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BQ-ahead facts live on the published layer. A leftover hits map is not
    /// a stamp source (shipped IBD already passes `None`).
    #[test]
    fn plan_batch_from_wire_bq_hits_map_is_not_stamp_source() {
        let (dir, q) = temp_query("bq-hits-not-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x33;
            t
        };
        let child = child_spend(parent_txid, 0x44);
        let need = vec![(Fk(1), vec![child])];
        {
            let _ = q.confirm_stats().take_window();
            let err = plan_applies(&q, &need, 1, &crate::InFlight::new(), None)
                .expect_err("bq parent_hits map is not a stamp source");
            assert!(
                err.to_string().contains("parent create_fk unresolved"),
                "got: {err}"
            );
            let mix = q.confirm_stats().take_window();
            assert_eq!(mix.pin_txid_n, 0);
            assert!(mix.head_need > 0, "bq-map-only parent must leftover");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Published union supplies create_fk + range with no pin, BQ hits, or head row.
    #[test]
    fn plan_batch_from_wire_hits_skeleton() {
        use crate::{BatchParentIds, IdMap};
        use std::sync::Arc;
        let (dir, q) = temp_query("skeleton-ids-stamp");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x55;
            t
        };
        let mut m = IdMap::default();
        m.insert(parent_txid, (Fk(66), (3000, 24)));
        let skel = BatchParentIds {
            ids: Arc::new(m),
            spent: Arc::new(crate::U64Map::default()),
            n_out: Default::default(),
            need_vouts: crate::U64Map::default(),
        };
        let child = child_spend(parent_txid, 0x66);
        let need = vec![(Fk(1), vec![child])];
        {
            let _ = q.confirm_stats().take_window();
            let plan = plan_applies(&q, &need, 1, &crate::InFlight::new(), Some(&skel))
                .expect("skeleton stamp");
            assert_eq!(first_edge_create(&plan), Fk(66));
            assert_eq!(
                plan.external_parents.get(&66).and_then(|p| p.body),
                Some((3000, 24))
            );
            assert_eq!(plan.external_parent_txid(66), Some(parent_txid));
            let mix = q.confirm_stats().take_window();
            assert_eq!(mix.pin_txid_n, 1, "skeleton hits use the id_cache meter");
            assert_eq!(mix.head_need, 0, "skeleton must skip leftover TipOnly");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_batch_skeleton_empty_carried_does_not_walk_ins() {
        use crate::{BatchParentIds, IdMap};
        use std::sync::Arc;
        let (dir, q) = temp_query("skeleton-carried-not-ins");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x55;
            t
        };
        let mut m = IdMap::default();
        m.insert(parent_txid, (Fk(66), (3000, 24)));
        let skel = BatchParentIds {
            ids: Arc::new(m),
            spent: Arc::new(crate::U64Map::default()),
            n_out: Default::default(),
            need_vouts: crate::U64Map::default(),
        };
        let child = child_spend(parent_txid, 0x66);
        let (block, txids) = crate::testutil::block_from_applies(std::slice::from_ref(&child));
        let block = Arc::new(block);
        let err = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlight::new(),
                Some(&skel),
                Some(&[]),
            )
            .expect_err("empty carried_need must not collect PlanIn prevs");
        assert!(
            err.to_string().contains("parent create_fk unresolved"),
            "got: {err}"
        );
        let plan = q
            .archive_plan_batch_from_wire(
                &[(Fk(1), &block, txids.as_slice())],
                1,
                &crate::InFlight::new(),
                Some(&skel),
                Some(&[parent_txid][..]),
            )
            .expect("carried key stamps without a second input walk");
        let inp = plan
            .edges
            .values()
            .flatten()
            .find(|e| e.vout != u32::MAX)
            .expect("spend");
        assert_eq!(inp.create_fk, Fk(66));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S0 plan and the shared helper stamp the same skeleton parent.
    #[test]
    fn stamp_external_parents_matches_plan_batch_on_skeleton() {
        use crate::{BatchParentIds, IdMap};
        use std::sync::Arc;
        let (dir, q) = temp_query("stamp-helper-plan");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x71;
            t
        };
        let mut m = IdMap::default();
        m.insert(parent_txid, (Fk(88), (4000, 32)));
        let skel = BatchParentIds {
            ids: Arc::new(m),
            spent: Arc::new(crate::U64Map::default()),
            n_out: Default::default(),
            need_vouts: crate::U64Map::default(),
        };

        let helper = crate::stamp_external_parents(
            q.store(),
            &[parent_txid],
            &crate::InFlight::new(),
            Some(&skel),
            q.confirm_stats(),
        )
        .expect("shared helper");
        assert_eq!(helper.resolved.get(&parent_txid), Some(&Fk(88)));
        assert_eq!(
            helper.idents.get(&88).and_then(|p| p.body),
            Some((4000, 32))
        );
        assert_eq!(helper.idents.get(&88).map(|p| p.txid), Some(parent_txid));

        let child = child_spend(parent_txid, 0x72);
        let need = vec![(Fk(1), vec![child])];
        let plan =
            plan_applies(&q, &need, 1, &crate::InFlight::new(), Some(&skel)).expect("S0 plan");
        assert_eq!(first_edge_create(&plan), Fk(88));
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

    /// In-flight CreatePin skips leftover TipOnly (`head_need=0`) and stamps the pin.
    #[test]
    fn stamp_inflight_hit_carries_create_pin() {
        use std::sync::Arc;
        let (dir, q) = temp_query("inflight-creates-pin");
        let parent_txid = {
            let mut t = [0u8; 32];
            t[0] = 0x93;
            t
        };
        let pin = crate::CreatePinInner::records(
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
        );
        let mut log = crate::InFlight::new();
        log.note_pins([(Fk(93), &pin)], None);
        let ifo = &log;
        {
            let _ = q.confirm_stats().take_window();
            let helper = crate::stamp_external_parents(
                q.store(),
                &[parent_txid],
                ifo,
                None,
                q.confirm_stats(),
            )
            .expect("inflight stamp");
            assert_eq!(helper.head_need_n, 0, "inflight hit must skip leftover");
            let got = helper
                .idents
                .get(&93)
                .and_then(|p| p.pin.as_ref())
                .expect("stamp must carry CreatePin");
            assert!(Arc::ptr_eq(got, &pin));

            let child = child_spend(parent_txid, 0x94);
            let need = vec![(Fk(1), vec![child])];
            let plan = plan_applies(&q, &need, 1, ifo, None).expect("S0 inflight");
            assert_eq!(first_edge_create(&plan), Fk(93));
            let mix = q.confirm_stats().take_window();
            assert_eq!(mix.head_need, 0, "plan path must skip leftover too");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Freeze + append: batch-merge is vector concat of frozen commit halves;
    /// external staging maps are dropped (not union-mutated).
    #[test]
    fn freeze_after_pin_then_append_preserves_fk_order() {
        let (dir, q) = temp_query("freeze-append");
        let need_a = vec![(Fk(1), vec![coinbase_apply(1)])];
        let mut plan_a = plan_applies(&q, &need_a, 1, &crate::InFlight::new(), None).unwrap();
        // Simulate residual stamp staging (must not survive freeze/append).
        plan_a
            .external_parents
            .insert(99, crate::ParentIdent::with_body([9u8; 32], (0, 1)));
        let txid = plan_a.batch_pin[0].tx().txid;
        let fk = plan_a.planned_fks[0];
        plan_a.freeze_after_pin();
        assert!(plan_a.external_parents.is_empty());
        assert!(
            plan_a.batch_creates.is_empty(),
            "freeze drops batch_creates; in-flight binds from batch_pin"
        );
        let mut log = crate::InFlight::new();
        log.note_pins(
            plan_a
                .planned_fks
                .iter()
                .zip(plan_a.batch_pin.iter())
                .map(|(fk, pin)| (*fk, pin)),
            None,
        );
        assert_eq!(
            log.get_create_fk(&txid),
            Some(fk),
            "in-flight still has txid→fk after freeze"
        );

        let need_b = vec![(Fk(2), vec![coinbase_apply(2), coinbase_apply(3)])];
        let mut plan_b = plan_applies(&q, &need_b, 2, &crate::InFlight::new(), None).unwrap();
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

    #[test]
    fn retain_headers_needing_body_strips_archived() {
        let mut plan = super::ArchiveWritePlan::empty();
        plan.planned_fks = vec![Fk(1), Fk(2), Fk(3)];
        plan.per_header_ranges = vec![(Fk(10), Fk(1), 2), (Fk(20), Fk(3), 1)];
        // Minimal packed rows so retain can compact.
        let dummy_pin = |i: u8| {
            crate::CreatePinInner::records(
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
            )
        };
        plan.packed = vec![
            (dummy_pin(1), Vec::new()),
            (dummy_pin(2), Vec::new()),
            (dummy_pin(3), Vec::new()),
        ];
        plan.batch_pin = vec![dummy_pin(1), dummy_pin(2), dummy_pin(3)];
        // Header 10 already has body; 20 needs body.
        let keep = plan
            .retain_headers_needing_body(|hfk| Ok(hfk == Fk(10)))
            .unwrap();
        assert!(keep);
        assert_eq!(plan.per_header_ranges, vec![(Fk(20), Fk(3), 1)]);
        assert_eq!(plan.planned_fks, vec![Fk(3)]);
        assert_eq!(plan.packed.len(), 1);
    }

    /// retain_headers edges: empty ranges, all have body, no-op full keep, null fks.
    #[test]
    fn retain_headers_needing_body_edge_matrix() {
        let dummy_pin = |i: u8| {
            crate::CreatePinInner::records(
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
            )
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
        let dummy_pin = crate::CreatePinInner::records(
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
        );
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
