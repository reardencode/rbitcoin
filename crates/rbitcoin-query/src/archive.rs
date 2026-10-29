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
use std::sync::{Arc, Mutex};

/// Shared immutable create pin: tx meta + outs (records or wire).
///
/// One Arc per create — plan `packed` pin half, `batch_pin`, and prep-ahead
/// `in_flight_outs` all Arc-clone this (no deep outs clone between stages).
/// A wire pin shares the decoded block with the other pins of that block until
/// Class A commit copies outputs into one blob and drops the block. Records
/// pins own [`OutputRecord`] scripts (tests / SH).
pub type CreatePin = Arc<CreatePinArc>;

/// One header's wire block + txids for Class A plan/commit.
pub type WirePlanNeed<'a> = (Fk, &'a Arc<bitcoin::Block>, &'a [[u8; 32]]);

/// Shared pin: Class A loc is filled once after append (later-wave stamp reads it).
#[derive(Debug)]
pub struct CreatePinArc {
    pub loc: std::sync::OnceLock<rbitcoin_store::CreateLocPair>,
    pub inner: CreatePinInner,
}

impl CreatePinArc {
    #[doc(hidden)]
    pub fn wrap(inner: CreatePinInner) -> CreatePin {
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

/// Outputs of one block, shared by that block's pins after Class A commit.
///
/// One allocation for every output script. A `Vec<OutputRecord>` per tx would
/// spend the RAM the decoded block was spending.
#[derive(Debug)]
struct PackedBlockOuts {
    /// `tx_start[tx]` is the first output. Length is `n_tx + 1`.
    tx_start: Vec<u32>,
    values: Vec<u64>,
    scripts: Vec<u8>,
    /// Parallel to `values`: `(offset, len)` into `scripts`.
    script_at: Vec<(u32, u32)>,
}

impl PackedBlockOuts {
    fn from_block(block: &bitcoin::Block) -> Self {
        let n = block.txdata.len();
        let mut n_out = 0usize;
        let mut script_len = 0usize;
        for tx in &block.txdata {
            n_out += tx.output.len();
            for o in &tx.output {
                script_len += o.script_pubkey.len();
            }
        }
        let mut tx_start = Vec::with_capacity(n.saturating_add(1));
        let mut values = Vec::with_capacity(n_out);
        let mut scripts = Vec::with_capacity(script_len);
        let mut script_at = Vec::with_capacity(n_out);
        for tx in &block.txdata {
            tx_start.push(values.len() as u32);
            for o in &tx.output {
                let script = o.script_pubkey.as_bytes();
                let off = scripts.len() as u32;
                script_at.push((off, script.len() as u32));
                scripts.extend_from_slice(script);
                values.push(o.value.to_sat());
            }
        }
        tx_start.push(values.len() as u32);
        Self {
            tx_start,
            values,
            scripts,
            script_at,
        }
    }

    fn output_range(&self, tx_index: u32) -> Option<(usize, usize)> {
        let i = tx_index as usize;
        let start = *self.tx_start.get(i)? as usize;
        let end = *self.tx_start.get(i.saturating_add(1))? as usize;
        Some((start, end))
    }

    fn n_out(&self, tx_index: u32) -> Option<usize> {
        let (start, end) = self.output_range(tx_index)?;
        Some(end.saturating_sub(start))
    }

    fn parts(&self, tx_index: u32, vout: u32) -> Option<(u64, &[u8])> {
        let (start, end) = self.output_range(tx_index)?;
        let i = start.saturating_add(vout as usize);
        if i >= end {
            return None;
        }
        let (off, len) = *self.script_at.get(i)?;
        let script = self
            .scripts
            .get(off as usize..off as usize + len as usize)?;
        Some((*self.values.get(i)?, script))
    }

    fn for_each_script(&self, tx_index: u32, mut f: impl FnMut(&[u8])) {
        let Some((start, end)) = self.output_range(tx_index) else {
            return;
        };
        for i in start..end {
            let Some((off, len)) = self.script_at.get(i).copied() else {
                return;
            };
            let Some(script) = self.scripts.get(off as usize..off as usize + len as usize) else {
                return;
            };
            f(script);
        }
    }

    fn script_bytes(&self, tx_index: u32) -> usize {
        let Some((start, end)) = self.output_range(tx_index) else {
            return 0;
        };
        self.script_at
            .get(start..end)
            .map(|rows| rows.iter().map(|(_, len)| *len as usize).sum())
            .unwrap_or(0)
    }
}

/// One decoded block, shared by every wire pin of that block.
///
/// Commit publishes [`PackedBlockOuts`] and drops `block`. Until then a reader
/// that needs script bytes holds its own [`Arc`] across the read (`PinOuts`
/// clones one when it is built). The blob then lives as long as the pins.
#[doc(hidden)]
pub struct WireShared {
    block: Mutex<Option<Arc<bitcoin::Block>>>,
    outs: std::sync::OnceLock<Arc<PackedBlockOuts>>,
}

impl WireShared {
    fn new(block: Arc<bitcoin::Block>) -> Arc<Self> {
        Arc::new(Self {
            block: Mutex::new(Some(block)),
            outs: std::sync::OnceLock::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Arc<bitcoin::Block>>> {
        self.block.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` on a cloned block `Arc`. The mutex is not held across `f`, so
    /// txout and seqsigwit encode do not stall a reader of this block.
    fn with_block<R>(&self, f: impl FnOnce(&bitcoin::Block) -> R) -> Option<R> {
        let block = self.clone_block()?;
        Some(f(&block))
    }

    fn clone_block(&self) -> Option<Arc<bitcoin::Block>> {
        self.lock().clone()
    }

    /// Blob if commit has published it, otherwise the decoded block.
    ///
    /// `release` installs the blob before it clears the slot. A reader that
    /// missed the blob and then found the slot empty looks once more.
    fn bytes(&self) -> Option<WireBytes<'_>> {
        if let Some(blob) = self.sealed() {
            return Some(WireBytes::Outs(blob));
        }
        if let Some(block) = self.clone_block() {
            return Some(WireBytes::Block(block));
        }
        self.sealed().map(WireBytes::Outs)
    }

    /// Copy this block's outputs outside the lock, then publish the blob and
    /// drop the decoded block. A reader waits only for that pointer update.
    ///
    /// Idempotent. Pins of one block share this value, so the first call
    /// publishes and the rest only clear an already-empty slot.
    fn release(&self) {
        let block = {
            let mut guard = self.lock();
            if self.outs.get().is_some() {
                *guard = None;
                return;
            }
            let Some(block) = guard.clone() else {
                return;
            };
            block
        };
        let packed = Arc::new(PackedBlockOuts::from_block(&block));
        let mut guard = self.lock();
        if self.outs.get().is_none() {
            let _ = self.outs.set(packed);
        }
        *guard = None;
    }

    fn sealed(&self) -> Option<&PackedBlockOuts> {
        self.outs.get().map(|a| a.as_ref())
    }
}

enum WireBytes<'a> {
    Block(Arc<bitcoin::Block>),
    Outs(&'a PackedBlockOuts),
}

impl std::fmt::Debug for WireShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireShared")
            .field("block", &self.lock().is_some())
            .field("outs", &self.outs.get().is_some())
            .finish()
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
        shared: Arc<WireShared>,
        tx_index: u32,
        tx: TxRecord,
    },
}

impl CreatePinInner {
    pub fn records(tx: TxRecord, outs: Vec<OutputRecord>) -> CreatePin {
        CreatePinArc::wrap(Self::Records { tx, outs })
    }

    /// Each call owns a new `WireShared`. Every transaction of one block
    /// must use `wire_share` so that block is packed once.
    #[doc(hidden)]
    pub fn wire(block: Arc<bitcoin::Block>, tx_index: u32, tx: TxRecord) -> CreatePin {
        Self::wire_shared(WireShared::new(block), tx_index, tx)
    }

    fn wire_shared(shared: Arc<WireShared>, tx_index: u32, tx: TxRecord) -> CreatePin {
        CreatePinArc::wrap(Self::Wire {
            shared,
            tx_index,
            tx,
        })
    }

    /// Share one [`WireShared`] across pins built from the same block `Arc`.
    pub(crate) fn wire_share(
        slot: &mut Option<(*const bitcoin::Block, Arc<WireShared>)>,
        block: &Arc<bitcoin::Block>,
        tx_index: u32,
        tx: TxRecord,
    ) -> CreatePin {
        let ptr = Arc::as_ptr(block);
        if let Some((prev, shared)) = slot.as_ref() {
            if *prev == ptr {
                return Self::wire_shared(Arc::clone(shared), tx_index, tx);
            }
        }
        let shared = WireShared::new(Arc::clone(block));
        *slot = Some((ptr, Arc::clone(&shared)));
        Self::wire_shared(shared, tx_index, tx)
    }

    #[inline]
    pub fn tx(&self) -> &TxRecord {
        match self {
            Self::Records { tx, .. } | Self::Wire { tx, .. } => tx,
        }
    }

    #[inline]
    pub fn wire_tx_index(&self) -> Option<u32> {
        match self {
            Self::Wire { tx_index, .. } => Some(*tx_index),
            Self::Records { .. } => None,
        }
    }

    /// Block `Arc` while Class A still holds it. `None` for records pins and
    /// after [`Self::release_wire_block`].
    pub fn clone_wire_block(&self) -> Option<Arc<bitcoin::Block>> {
        match self {
            Self::Wire { shared, .. } => shared.clone_block(),
            Self::Records { .. } => None,
        }
    }

    /// Publish this block's output blob and drop the decoded block.
    pub fn release_wire_block(&self) {
        if let Self::Wire { shared, .. } = self {
            shared.release();
        }
    }

    #[inline]
    pub fn n_out(&self) -> usize {
        match self {
            Self::Records { outs, .. } => outs.len(),
            Self::Wire { tx, .. } => tx.output_count as usize,
        }
    }

    pub fn contains_vout(&self, vout: u32) -> bool {
        (vout as usize) < self.n_out()
    }

    /// Value and script.
    ///
    /// Records pins and a wire pin after commit borrow stable bytes. Before
    /// commit a wire pin's script still lives in the decoded block: use
    /// [`Self::with_out_parts`] so the block `Arc` stays alive for the read.
    pub fn out_parts(&self, vout: u32) -> Option<(u64, &[u8])> {
        match self {
            Self::Records { outs, .. } => {
                let o = outs.get(vout as usize)?;
                Some((o.value, o.script.as_slice()))
            }
            Self::Wire {
                shared, tx_index, ..
            } => shared.sealed()?.parts(*tx_index, vout),
        }
    }

    /// Run `f` on one output. Holds the decoded block for the callback when
    /// the retained blob is not published yet.
    pub fn with_out_parts<R>(&self, vout: u32, f: impl FnOnce(u64, &[u8]) -> R) -> Option<R> {
        match self {
            Self::Records { .. } => self.out_parts(vout).map(|(value, script)| f(value, script)),
            Self::Wire {
                shared, tx_index, ..
            } => match shared.bytes() {
                Some(WireBytes::Outs(blob)) => blob
                    .parts(*tx_index, vout)
                    .map(|(value, script)| f(value, script)),
                Some(WireBytes::Block(block)) => {
                    let o = block
                        .txdata
                        .get(*tx_index as usize)?
                        .output
                        .get(vout as usize)?;
                    Some(f(o.value.to_sat(), o.script_pubkey.as_bytes()))
                }
                None => None,
            },
        }
    }

    #[doc(hidden)]
    pub fn retained_outs_addr(&self) -> Option<usize> {
        match self {
            Self::Wire { shared, .. } => shared.outs.get().map(|a| Arc::as_ptr(a) as usize),
            Self::Records { .. } => None,
        }
    }

    pub fn out_record(&self, vout: u32) -> Option<OutputRecord> {
        self.with_out_parts(vout, |value, script| {
            OutputRecord::unspent(value, script.to_vec())
        })
    }

    pub fn for_each_script(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Self::Records { outs, .. } => {
                for o in outs {
                    f(o.script.as_slice());
                }
            }
            Self::Wire {
                shared, tx_index, ..
            } => match shared.bytes() {
                Some(WireBytes::Outs(blob)) => blob.for_each_script(*tx_index, f),
                Some(WireBytes::Block(block)) => {
                    if let Some(tx) = block.txdata.get(*tx_index as usize) {
                        for o in &tx.output {
                            f(o.script_pubkey.as_bytes());
                        }
                    }
                }
                None => {}
            },
        }
    }

    /// Borrow the wire tx while the decoded block is still held.
    ///
    /// `None` for a records pin and after [`Self::release_wire_block`].
    /// Commit calls this before the release. The callback keeps the block
    /// `Arc` alive for the length of the use.
    pub fn with_wire_tx<R>(&self, f: impl FnOnce(&bitcoin::Transaction) -> R) -> Option<R> {
        match self {
            Self::Wire {
                shared, tx_index, ..
            } => shared.with_block(|block| block.txdata.get(*tx_index as usize).map(f)),
            Self::Records { .. } => None,
        }
        .flatten()
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
    fn packed_outs_est(&self) -> usize {
        let scripts: usize = match self {
            Self::Records { outs, .. } => outs.iter().map(|o| o.encoded_len()).sum(),
            Self::Wire {
                shared, tx_index, ..
            } => match shared.bytes() {
                Some(WireBytes::Outs(blob)) => {
                    let (start, end) = blob.output_range(*tx_index).unwrap_or((0, 0));
                    blob.script_at
                        .get(start..end)
                        .map(|rows| {
                            rows.iter()
                                .map(|(_, len)| OutputRecord::encoded_len_for_script(*len as usize))
                                .sum()
                        })
                        .unwrap_or(0)
                }
                Some(WireBytes::Block(block)) => block
                    .txdata
                    .get(*tx_index as usize)
                    .map(|tx| {
                        tx.output
                            .iter()
                            .map(|o| OutputRecord::encoded_len_for_script(o.script_pubkey.len()))
                            .sum()
                    })
                    .unwrap_or(0),
                None => 0,
            },
        };
        16 + TxRecord::BODY_META_LEN + scripts
    }
    fn encode_txout_body(&self, buf: &mut Vec<u8>, secret: Option<&rbitcoin_store::StoreSecret>) {
        match self {
            Self::Records { tx, outs } => {
                encode_txout_meta_and_outs(tx, outs, buf, secret);
            }
            Self::Wire {
                shared,
                tx_index,
                tx,
            } => {
                tx.encode_body_meta_into(buf);
                shared.with_block(|block| {
                    if let Some(wtx) = block.txdata.get(*tx_index as usize) {
                        for o in &wtx.output {
                            encode_unspent_output_into_secret(
                                o.value.to_sat(),
                                o.script_pubkey.as_bytes(),
                                buf,
                                secret,
                            );
                        }
                    }
                });
            }
        }
    }
}

/// Approx heap bytes for one [`CreatePin`] payload (for IBD `sizes` metering).
///
/// Counts owned output scripts + fixed record overhead — not Arc
/// refcount sharing (each strong Arc still "owns" the allocation once).
/// Wire pins meter scriptPubKey lengths (the decoded block before commit,
/// the shared output blob after).
pub fn create_pin_approx_bytes(pin: &CreatePin) -> usize {
    let mut n = 96usize; // TxRecord + Arc shell overhead (order-of-magnitude)
    match &pin.inner {
        CreatePinInner::Records { outs, .. } => {
            for o in outs {
                n = n.saturating_add(24).saturating_add(o.script.len());
            }
            n = n.saturating_add(outs.capacity().saturating_mul(24));
        }
        CreatePinInner::Wire {
            shared, tx_index, ..
        } => {
            let add = |n: &mut usize, len: usize| {
                *n = n.saturating_add(24).saturating_add(len);
            };
            match shared.bytes() {
                Some(WireBytes::Outs(blob)) => {
                    let bytes = blob.script_bytes(*tx_index);
                    let n_out = blob.n_out(*tx_index).unwrap_or(0);
                    n = n
                        .saturating_add(24usize.saturating_mul(n_out))
                        .saturating_add(bytes);
                }
                Some(WireBytes::Block(block)) => {
                    if let Some(tx) = block.txdata.get(*tx_index as usize) {
                        for o in &tx.output {
                            add(&mut n, o.script_pubkey.len());
                        }
                    }
                }
                None => {}
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
        }
        if sizes_aligned {
            self.tx_sizes.append(&mut other.tx_sizes);
        }
        self.planned_fks.append(&mut other.planned_fks);
        self.per_header_ranges.append(&mut other.per_header_ranges);
        self.edges.extend(other.edges);
        self.batch_creates.append(&mut other.batch_creates);
        self.batch_pin.append(&mut other.batch_pin);
        self.index_tx |= other.index_tx;
        self.body_est = self.body_est.saturating_add(other.body_est);
    }
}

#[doc(hidden)]
pub struct PlanIn {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    pub is_coinbase: bool,
}

#[doc(hidden)]
pub struct PlanRow {
    pub tx_fk: Fk,
    pub tx: TxRecord,
    pub ins: Vec<PlanIn>,
    pub block: Arc<bitcoin::Block>,
    pub tx_index: u32,
}

/// Newest in-batch create of this txid strictly before `spender`.
///
/// `repeats` holds every fk when the txid occurs more than once. Otherwise
/// `latest` is the only copy. A copy created later in the wave is not a coin yet.
/// The fresh plan and the archived stamp share this.
pub fn batch_copy_before(latest: Option<Fk>, repeats: Option<&[Fk]>, spender: Fk) -> Option<Fk> {
    match repeats {
        Some(fks) => fks.iter().rev().find(|f| f.0 < spender.0).copied(),
        None => latest.filter(|f| f.0 < spender.0),
    }
}

/// Parents to resolve outside this batch. A txid this batch only creates after
/// the spend is asked for when `outside` can have it (an earlier copy); otherwise
/// it stays a later in-batch create, which structural rejects as not yet a coin.
#[doc(hidden)]
pub fn collect_plan_need_external(
    work: &[PlanRow],
    batch_map: &crate::TxidMap<Fk>,
    batch_repeats: &crate::TxidMap<Vec<Fk>>,
    carried_need: Option<&[[u8; 32]]>,
    outside: impl Fn(&[u8; 32]) -> bool,
) -> Vec<[u8; 32]> {
    let mut need_external: crate::TxidSet = crate::TxidSet::with_hasher(Default::default());
    if let Some(keys) = carried_need {
        let mut created_here = false;
        for &prev in keys {
            if prev == [0u8; 32] {
                continue;
            }
            if batch_map.contains_key(&prev) {
                created_here = true;
                continue;
            }
            need_external.insert(prev);
        }
        // The wave asked about a txid this batch creates (below BIP34, or a
        // spend before its create): only a per-input walk knows which copy.
        if !created_here {
            return need_external.into_iter().collect();
        }
    }
    for row in work {
        for inp in row.ins.iter() {
            if inp.is_coinbase || inp.prev_txid == [0u8; 32] {
                continue;
            }
            if batch_copy_before(
                batch_map.get(&inp.prev_txid).copied(),
                batch_repeats.get(&inp.prev_txid).map(Vec::as_slice),
                row.tx_fk,
            )
            .is_some()
            {
                continue;
            }
            if batch_map.contains_key(&inp.prev_txid) && !outside(&inp.prev_txid) {
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
            parent: rbitcoin_store::InputParent::Prevout {
                create_fk: e.create_fk,
                vout: inp.previous_output.vout,
            },
            sequence: inp.sequence.to_consensus_u32(),
            script_sig: inp.script_sig.to_bytes(),
            witness: inp.witness.to_vec(),
        });
    }
    Ok(out)
}

#[doc(hidden)]
pub fn wire_input_is_coinbase(inp: &bitcoin::TxIn) -> bool {
    inp.previous_output.is_null()
}

/// Edge/wire agreement without copying script or witness bytes.
#[doc(hidden)]
pub fn wire_edges_match(
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

#[doc(hidden)]
pub fn wire_seqsigwit_upper(tx: &bitcoin::Transaction) -> u64 {
    tx.input
        .iter()
        .map(|inp| {
            seqsigwit_input_len_upper(inp.script_sig.len(), inp.witness.iter().map(|w| w.len()))
                as u64
        })
        .sum()
}

#[doc(hidden)]
pub fn plan_in_from_txin(inp: &bitcoin::TxIn) -> PlanIn {
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

#[doc(hidden)]
pub fn tx_record_from_wire(tx: &bitcoin::Transaction, txid: [u8; 32]) -> TxRecord {
    TxRecord {
        txid,
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        input_count: tx.input.len() as u32,
        output_count: tx.output.len() as u32,
    }
}

#[doc(hidden)]
pub fn stamp_txstat_rows(
    plan: &ArchiveWritePlan,
) -> Result<Vec<rbitcoin_store::TxStatRow>, QueryError> {
    if plan.packed.is_empty() {
        return Ok(Vec::new());
    }
    if plan.tx_fees.len() != plan.packed.len() || plan.tx_sizes.len() != plan.packed.len() {
        return Err(StoreError::Corrupt("invariant: txstat fee length"));
    }
    stamp_txstat_from_fees(&plan.tx_fees, &plan.tx_sizes)
}

/// Fee and size rows for a wire plan that did not pass confirm assemble.
/// Commit refuses a non-empty plan whose vectors are empty or mis-sized.
/// A records pin has no wire body: that is corrupt, not a zero row.
#[doc(hidden)]
pub fn stamp_wire_plan_txstat(
    query: &Query,
    plan: &mut ArchiveWritePlan,
) -> Result<(), QueryError> {
    if plan.packed.is_empty() {
        return Ok(());
    }
    let mut idx: crate::U64Map<usize> = crate::U64Map::default();
    for (i, fk) in plan.planned_fks.iter().enumerate() {
        if let Some(id) = fk.get() {
            idx.insert(id, i);
        }
    }
    let mut fees = Vec::with_capacity(plan.packed.len());
    let mut sizes = Vec::with_capacity(plan.packed.len());
    for i in 0..plan.packed.len() {
        let Some((is_cb, n_in)) = plan.packed[i]
            .0
            .with_wire_tx(|tx| (tx.is_coinbase(), tx.input.len()))
        else {
            return Err(StoreError::Corrupt("invariant: txstat missing wire"));
        };
        let in_sum = if is_cb {
            None
        } else {
            Some(txstat_in_sum(query, plan, &idx, i, n_in)?)
        };
        let row = plan.packed[i]
            .0
            .with_wire_tx(|tx| txstat_row_from_tx(tx, in_sum))
            .ok_or(StoreError::Corrupt("invariant: txstat missing wire"))??;
        let total = row
            .base
            .checked_add(row.wit_extra)
            .ok_or(StoreError::Corrupt("invariant: txstat size total"))?;
        fees.push(row.fee_sat);
        sizes.push((row.base, total));
    }
    plan.tx_fees = fees;
    plan.tx_sizes = sizes;
    Ok(())
}

#[doc(hidden)]
pub fn txstat_in_sum(
    query: &Query,
    plan: &ArchiveWritePlan,
    idx: &crate::U64Map<usize>,
    i: usize,
    n_in: usize,
) -> Result<u64, QueryError> {
    let sid = plan
        .planned_fks
        .get(i)
        .and_then(|fk| fk.get())
        .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
    let eds = plan
        .edges
        .get(&sid)
        .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
    if eds.len() != n_in {
        return Err(StoreError::Corrupt("invariant: wire plan edges missing"));
    }
    let mut in_sum = 0u64;
    for e in eds {
        if e.create_fk.is_null() {
            return Err(StoreError::Corrupt("invariant: spend missing create_fk"));
        }
        let val = prevout_value_at(query, plan, idx, e.create_fk, e.vout)?;
        in_sum = in_sum
            .checked_add(val)
            .ok_or(StoreError::Corrupt("txstat in_sum overflow"))?;
    }
    Ok(in_sum)
}

#[doc(hidden)]
pub fn prevout_value_at(
    query: &Query,
    plan: &ArchiveWritePlan,
    idx: &crate::U64Map<usize>,
    create_fk: Fk,
    vout: u32,
) -> Result<u64, QueryError> {
    let Some(cid) = create_fk.get() else {
        return Err(StoreError::Corrupt("invariant: spend missing create_fk"));
    };
    if let Some(&i) = idx.get(&cid) {
        let val = plan.packed[i]
            .0
            .with_out_parts(vout, |val, _| val)
            .ok_or(StoreError::Corrupt("invariant: same-batch prevout"))?;
        return Ok(val);
    }
    Ok(query.tx_output_at_fk(create_fk, vout)?.value)
}

/// Fee and `(base, total)` already recorded at assemble from the lookup precompute.
#[doc(hidden)]
pub fn stamp_txstat_from_fees(
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

#[doc(hidden)]
pub fn txstat_size(tx: &bitcoin::Transaction) -> Result<(u32, u32), QueryError> {
    let base_sz = tx.base_size();
    let total = tx.total_size();
    let base = u32::try_from(base_sz).map_err(|_| StoreError::Corrupt("txstat base"))?;
    let wit_extra = u32::try_from(total.saturating_sub(base_sz))
        .map_err(|_| StoreError::Corrupt("txstat wit_extra"))?;
    Ok((base, wit_extra))
}

pub fn txstat_row_from_tx(
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

#[doc(hidden)]
pub fn edge_of(parent: Fk, vout: u32) -> InputEdge {
    if parent.is_null() {
        InputEdge::coinbase()
    } else {
        InputEdge { parent, vout }
    }
}

#[doc(hidden)]
pub fn commit_input_edge_rows(plan: &ArchiveWritePlan) -> Result<Vec<Vec<InputEdge>>, StoreError> {
    let mut rows = Vec::with_capacity(plan.packed.len());
    for (i, (pin, ins)) in plan.packed.iter().enumerate() {
        if pin.wire_tx_index().is_some() {
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
            let n_in = pin.tx().input_count as usize;
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
                            edge_of(inp.create_fk(), inp.prev_index())
                        }
                    })
                    .collect(),
            );
        }
    }
    Ok(rows)
}

#[doc(hidden)]
pub fn seqsigwit_append_est(plan: &ArchiveWritePlan) -> usize {
    let mut n = 0usize;
    for (pin, ins) in &plan.packed {
        n = n.saturating_add(16);
        if let Some(upper) = pin.with_wire_tx(|tx| wire_seqsigwit_upper(tx) as usize) {
            n = n.saturating_add(upper);
        } else {
            n = n.saturating_add(ins.iter().map(|i| i.encoded_len()).sum());
        }
    }
    n
}

#[doc(hidden)]
pub fn encode_plan_row_seqsigwit(
    plan: &ArchiveWritePlan,
    i: usize,
    buf: &mut Vec<u8>,
    secret: &rbitcoin_store::StoreSecret,
) {
    let (pin, ins) = &plan.packed[i];
    let encoded = pin.with_wire_tx(|tx| {
        for inp in &tx.input {
            encode_wire_seqsigwit_input(
                inp.sequence.to_consensus_u32(),
                inp.script_sig.as_bytes(),
                inp.witness.iter(),
                buf,
                Some(secret),
            );
        }
    });
    if encoded.is_none() {
        encode_seqsigwit_with_secret(ins, buf, Some(secret));
    }
}

/// Owned `seqsigwit` rows for the prune RAM window.
///
/// Wire pins keep `packed` ins empty. Prune mode is the only path that still
/// needs those bytes after the block `Arc` drops, so it builds them here from
/// the wire tx and the spend edges. A records pin contributes its ins. An
/// empty records pin is Corrupt (the caller must not cache an empty vector).
#[doc(hidden)]
pub fn seqsigwit_rows_for_prune(
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
            let eds = plan
                .edges
                .get(&sid)
                .ok_or(StoreError::Corrupt("invariant: wire plan edges missing"))?;
            pin.with_wire_tx(|tx| input_records_from_wire(tx, fk, eds))
                .ok_or(StoreError::Corrupt(
                    "invariant: prune seqsigwit missing inputs",
                ))??
        };
        rows.push(recs);
    }
    Ok(rows)
}

/// `committed`, Class A locators, and header ranges still to store.
pub type ArchiveHeadParents = (bool, Vec<rbitcoin_store::CreateLocPair>, Vec<(Fk, Fk, u32)>);

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
        let mut plan =
            self.archive_plan_batch_from_wire(&need, start, &crate::InFlight::new(), None, None)?;
        if plan.is_empty() {
            return Ok(());
        }
        // Confirm assemble records fees before write. This wrapper is the
        // other Class A planner: stamp here so commit never walks prevouts.
        stamp_wire_plan_txstat(self, &mut plan)?;
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
    /// is BIP30 (91842/91880, or regtest below BIP34): both rows are planned,
    /// and a spend uses the newest copy created before it.
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
        let mut batch_repeats: crate::TxidMap<Vec<Fk>> = crate::TxidMap::default();
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
            let span_hi = first_tx_fk.0.saturating_add(u64::from(n_txs));
            for (tx_index, (tx, txid)) in block.txdata.iter().zip(txids.iter()).enumerate() {
                let tx_fk = Fk(next_tx);
                next_tx += 1;
                if let Some(prev) = batch_map.insert(*txid, tx_fk) {
                    if prev.0 >= first_tx_fk.0 && prev.0 < span_hi {
                        return Err(StoreError::Corrupt(
                            "duplicate txid in block body (consensus violation)",
                        ));
                    }
                    batch_repeats
                        .entry(*txid)
                        .or_insert_with(|| vec![prev])
                        .push(tx_fk);
                }
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
            batch_repeats,
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
    #[doc(hidden)]
    pub fn finish_archive_plan(
        &self,
        work: Vec<PlanRow>,
        batch_map: crate::TxidMap<Fk>,
        batch_repeats: crate::TxidMap<Vec<Fk>>,
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
        // With a skeleton, a key the wave did not resolve is Corrupt, so ask
        // only for what in-flight or the skeleton holds.
        let need_vec =
            collect_plan_need_external(&work, &batch_map, &batch_repeats, carried_need, |t| {
                skeleton.is_none_or(|s| s.get(t).is_some()) || in_flight.get_create_fk(t).is_some()
            });
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
        let mut block_shared: Option<(*const bitcoin::Block, Arc<WireShared>)> = None;
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
                let create_fk = if let Some(cfk) = batch_copy_before(
                    batch_map.get(&inp.prev_txid).copied(),
                    batch_repeats.get(&inp.prev_txid).map(Vec::as_slice),
                    tx_fk,
                ) {
                    batch_stamp = batch_stamp.saturating_add(1);
                    cfk
                } else if let Some(&cfk) = resolved.get(&inp.prev_txid) {
                    resolved_stamp = resolved_stamp.saturating_add(1);
                    cfk
                } else if let Some(&cfk) = batch_map.get(&inp.prev_txid) {
                    // Only a later copy here: not a coin yet; structural rejects it.
                    batch_stamp = batch_stamp.saturating_add(1);
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
            let pin = CreatePinInner::wire_share(&mut block_shared, &block, tx_index, tx);
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
        let (committed, loc, ranges) = self.archive_commit_plan_defer_head_parents(plan)?;
        if !ranges.is_empty() {
            // Class A append above overlaps the in-flight tip flush. This put
            // is Class C, so it waits until that flush stops excluding stores.
            let _commit = self.lock_tip_commit()?;
            let t = std::time::Instant::now();
            let write = rbitcoin_store::ClassCWrite::new();
            self.store.header_txs.put_ranges_batch(&write, &ranges)?;
            self.confirm_stats()
                .note_write_commit(0, 0, 0, 0, 0, t.elapsed().as_nanos() as u64, 0);
        }
        Ok((committed, loc))
    }

    /// Class A commit. Fees and sizes were recorded before this call
    /// (confirm assemble, or [`stamp_wire_plan_txstat`] on the Class A wire
    /// planner). A non-empty plan whose vectors do not match `packed` is
    /// corrupt. This function does not walk prevouts. It does not store
    /// header ranges: the returned list is Class C. [`Self::archive_commit_plan_defer_head`]
    /// stores it after `tip_commit` joins the in-flight tip flush. The
    /// confirm-write path does the same put after that join, including when a
    /// later phase of that write rejects the batch. `header_txs` is what a retry
    /// uses to skip a second body append.
    pub fn archive_commit_plan_defer_head_parents(
        &self,
        mut plan: ArchiveWritePlan,
    ) -> Result<ArchiveHeadParents, QueryError> {
        use std::time::Instant;
        if plan.packed.is_empty() {
            return Ok((false, Vec::new(), Vec::new()));
        }
        if !plan.retain_headers_needing_body(|hfk| self.store.header_txs.has_body(hfk))? {
            return Ok((false, Vec::new(), Vec::new()));
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
        let txstat = stamp_txstat_rows(&plan)?;
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
        // seqsigwit and txout encode have finished with the wire tx. Later
        // spends read the output blob. Drop the decoded block before head
        // index work so the extra window does not keep it.
        for (pin, _) in &plan.packed {
            pin.release_wire_block();
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

        let ranges = std::mem::take(&mut plan.per_header_ranges);
        let total_ns = t0.elapsed().as_nanos() as u64;
        self.confirm_stats().note_write_commit(
            total_ns,
            reserve_ns,
            body_ns,
            head_ns,
            0,
            0,
            n_blocks.max(1),
        );
        Ok((true, loc, ranges))
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

    #[doc(hidden)]
    pub fn drain_pending_tx_head_if_full(&self) -> Result<(), QueryError> {
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
        if inp.create_fk().is_null() {
            return Err(StoreError::Corrupt("input missing create_fk for prev_txid"));
        }
        self.store.txs.body_txid(inp.create_fk())
    }
}

#[cfg(test)]
mod packed_outs_reserve {
    use super::PackedBlockOuts;

    #[test]
    fn from_block_reserves_script_bytes() {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{
            Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction,
            TxIn, TxMerkleNode, TxOut, Witness,
        };
        let scripts = [vec![0x51u8; 3], vec![0x52u8; 5], vec![0x53u8; 9]];
        let tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: scripts
                .iter()
                .map(|script| TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(script.clone()),
                })
                .collect(),
        };
        let block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };
        let packed = PackedBlockOuts::from_block(&block);
        assert_eq!(packed.scripts.len(), 17);
        assert_eq!(
            packed.scripts.capacity(),
            packed.scripts.len(),
            "script bytes should be reserved once"
        );
        assert_eq!(packed.values.capacity(), packed.values.len());
        assert_eq!(packed.script_at.capacity(), packed.script_at.len());
        assert_eq!(&packed.scripts[..3], &[0x51; 3]);
        assert_eq!(&packed.scripts[3..8], &[0x52; 5]);
        assert_eq!(&packed.scripts[8..], &[0x53; 9]);
    }
}
