//! BIP158 basic filters over [`rbitcoin_store::BlockFilterTable`].
//!
//! Additive index under the store dir; Class A is unchanged. Filters are
//! built from Class A (output scripts plus spent prevout scripts through
//! `input.body` parent edges), so heights below a seqsigwit prune still build.
//! The watermark is the last committed height.

use bitcoin::bip158::{BlockFilter, FilterHash, FilterHeader, GcsFilterWriter};
use bitcoin::hashes::Hash;
use bitcoin::{Block, OutPoint};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_store::{
    read_index_window, BlockFilterRecord, BlockFilterSlot, BlockFilterTable, IndexHeight,
    IndexWindow, StoreError,
};

use crate::{Query, QueryError};
use std::sync::atomic::Ordering;
use std::sync::{Condvar, Mutex};

/// Core `getblockfilter` when the index has not reached this block.
#[doc(hidden)]
pub const FILTER_STILL_INDEXING: &str =
    "Filter not found. Block filters are still in the process of being indexed.";

/// BIP158 basic filter Golomb-Rice parameters (`M`, `P`).
#[doc(hidden)]
pub const BASIC_FILTER_M: u64 = 784_931;
#[doc(hidden)]
pub const BASIC_FILTER_P: u8 = 19;
pub struct BlockFilterWriteBehind {
    /// Serializes commits against disconnect truncate.
    pub appender: Mutex<()>,
    pub wake: Mutex<()>,
    pub wake_cv: Condvar,
}

impl Default for BlockFilterWriteBehind {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockFilterWriteBehind {
    pub fn new() -> Self {
        Self {
            appender: Mutex::new(()),
            wake: Mutex::new(()),
            wake_cv: Condvar::new(),
        }
    }

    pub fn notify(&self) {
        self.wake_cv.notify_one();
    }

    pub fn lock_appender(&self) -> std::sync::MutexGuard<'_, ()> {
        self.appender.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[doc(hidden)]
    pub fn wait(&self, d: std::time::Duration) {
        let g = self.wake.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.wake_cv.wait_timeout(g, d);
    }
}

/// Basic filter of `window.blocks[i]` using a hash the caller already loaded.
///
/// No store IO. A missing prevout is corrupt.
pub fn basic_filter_of(
    block_hash: &[u8; 32],
    window: &IndexWindow,
    i: usize,
) -> Result<BlockFilter, QueryError> {
    let block = &window.blocks[i];
    let mut spent = Vec::new();
    for e in block.edges.iter().flatten().filter(|e| !e.parent.is_null()) {
        let out = window.prevout(e.parent, e.vout).ok_or(StoreError::Corrupt(
            "invariant: blockfilter prevout missing",
        ))?;
        spent.push(out.script.as_slice());
    }
    let outputs = block
        .txs
        .iter()
        .flat_map(|tx| tx.outs.iter().map(|o| o.script.as_slice()));
    basic_filter_from_scripts(block_hash, outputs, spent)
}

/// GCS-encode a basic filter. Non-`OP_RETURN` output scripts, then each spent
/// prevout script. `block_hash` is internal byte order.
pub fn basic_filter_from_scripts<'a>(
    block_hash: &[u8; 32],
    output_scripts: impl IntoIterator<Item = &'a [u8]>,
    spent_scripts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<BlockFilter, QueryError> {
    let elements = output_scripts
        .into_iter()
        .filter(|script| script.first() != Some(&rbitcoin_primitives::OP_RETURN))
        .chain(spent_scripts);
    encode_basic_filter(block_hash, elements)
}

/// GCS-encode a basic filter keyed by `block_hash` (internal byte order).
#[doc(hidden)]
pub fn encode_basic_filter<'a>(
    block_hash: &[u8; 32],
    elements: impl Iterator<Item = &'a [u8]>,
) -> Result<BlockFilter, QueryError> {
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().unwrap());
    let mut content = Vec::new();
    let mut writer = GcsFilterWriter::new(&mut content, k0, k1, BASIC_FILTER_M, BASIC_FILTER_P);
    for e in elements {
        writer.add_element(e);
    }
    writer
        .finish()
        .map_err(|_| StoreError::Corrupt("invariant: blockfilter encode"))?;
    Ok(BlockFilter::new(&content))
}

impl Query {
    /// Confirmed heights `start..=end` as reads for [`Self::read_index_window`];
    /// heights at or above `tweaks_from` also read what tweaks need.
    pub fn index_heights(
        &self,
        start: u32,
        end: u32,
        tweaks_from: Option<u32>,
    ) -> Result<Vec<IndexHeight>, QueryError> {
        (start..=end)
            .map(|h| {
                let header_fk = self
                    .store
                    .confirmed
                    .get(Height(h))?
                    .ok_or(StoreError::Corrupt("invariant: index height not confirmed"))?;
                let (first, n) = self
                    .store
                    .header_txs
                    .get_range(header_fk)?
                    .ok_or(StoreError::Corrupt("confirmed header missing body list"))?;
                Ok(IndexHeight {
                    height: Height(h),
                    header_fk,
                    first,
                    n,
                    tweaks: tweaks_from.is_some_and(|t| h >= t),
                })
            })
            .collect()
    }

    /// Read a window of blocks and the parents they spend (completion session).
    pub fn read_index_window(&self, heights: &[IndexHeight]) -> Result<IndexWindow, QueryError> {
        read_index_window(&self.store.txs, heights)
    }

    /// Basic filter of `window.blocks[i]`. Reads the block hash from the header.
    pub fn basic_filter_from_window(
        &self,
        window: &IndexWindow,
        i: usize,
    ) -> Result<BlockFilter, QueryError> {
        let hash = self.store.get_header(window.blocks[i].header_fk)?.hash;
        basic_filter_of(&hash, window, i)
    }

    pub fn block_filter_enabled(&self) -> bool {
        self.block_filter_enabled.load(Ordering::SeqCst)
    }

    /// Turn the index on (opening or creating the table) or off.
    ///
    /// Open drops committed slots that are not on the best chain: above the
    /// tip, or whose `header_fk` is not `confirmed[h]` (a crash between a
    /// disconnect and its filter truncate, or a torn slot).
    pub fn set_block_filter_index(&self, enabled: bool) -> Result<(), QueryError> {
        if enabled && self.block_filters.get().is_none() {
            let table = BlockFilterTable::open_or_create(self.store.cold_files_dir())?;
            self.trim_block_filters_to_best_chain(&table)?;
            let _ = self.block_filters.set(table);
        }
        self.block_filter_enabled.store(enabled, Ordering::SeqCst);
        Ok(())
    }

    #[doc(hidden)]
    pub fn trim_block_filters_to_best_chain(
        &self,
        table: &BlockFilterTable,
    ) -> Result<(), QueryError> {
        table.truncate_through(self.tip_height())?;
        let was = table.next_height().0;
        let mut keep = was.checked_sub(1);
        while let Some(h) = keep {
            let slot = table.slot(Height(h))?.map(|s| s.header_fk);
            if slot.is_some() && slot == self.store.confirmed.get(Height(h))? {
                break;
            }
            keep = h.checked_sub(1);
        }
        if keep.map_or(0, |h| h + 1) != was {
            rbitcoin_log::warn!(
                "blockfilter: dropping slots off the best chain: keep through {keep:?} (had {was})"
            );
            table.truncate_through(keep.map(Height))?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn block_filter_table(&self) -> Option<&BlockFilterTable> {
        if self.block_filter_enabled() {
            self.block_filters.get()
        } else {
            None
        }
    }

    /// Heights the tip leads the committed filter watermark (0 when off).
    pub fn block_filter_lag_heights(&self) -> u32 {
        let Some(table) = self.block_filter_table() else {
            return 0;
        };
        match self.tip_height() {
            None => 0,
            Some(tip) => tip
                .0
                .saturating_add(1)
                .saturating_sub(table.next_height().0),
        }
    }

    /// Last committed filter height.
    pub fn basic_filter_hwm(&self) -> Result<Option<u32>, QueryError> {
        Ok(self
            .block_filter_table()
            .and_then(|t| t.next_height().0.checked_sub(1)))
    }

    /// Filter bytes and header for `hash`.
    ///
    /// A sealed best-chain row is that row. Otherwise the parent filter
    /// header is resolved first: a sealed best-chain parent, the zero
    /// genesis header, or a stale branch walked back to that sealed fork
    /// point. An unsealed best-chain gap is refused before the body is
    /// rebuilt.
    pub fn basic_filter_for_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Vec<u8>, FilterHeader)>, QueryError> {
        if let Some(h) = self.height_of_hash(hash)? {
            if let Some(row) = self.basic_filter_at(h.0)? {
                return Ok(Some(row));
            }
        }
        let Some(prev) = self.header_prev_hash(hash)? else {
            return Ok(None);
        };
        let parent_header = self.parent_basic_filter_header(&prev)?;
        let Some(block) = self.block_body_for_filter(hash)? else {
            return Ok(None);
        };
        let spent = self.spent_scripts(&block)?;
        let filter = self.basic_filter_content(&block, &spent)?;
        Ok(Some((
            filter.content.clone(),
            filter.filter_header(&parent_header),
        )))
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn basic_filter_from_wire_block(
        &self,
        block: &Block,
    ) -> Result<(Vec<u8>, FilterHeader), QueryError> {
        let spent = self.spent_scripts(block)?;
        let filter = self.basic_filter_content(block, &spent)?;
        let prev = self.parent_basic_filter_header(&block.header.prev_blockhash.to_byte_array())?;
        let header = filter.filter_header(&prev);
        Ok((filter.content.clone(), header))
    }

    #[doc(hidden)]
    pub fn basic_filter_content(
        &self,
        block: &Block,
        spent: &[Vec<u8>],
    ) -> Result<BlockFilter, QueryError> {
        let hash = block.block_hash().to_byte_array();
        let outputs: Vec<&[u8]> = block
            .txdata
            .iter()
            .flat_map(|tx| tx.output.iter().map(|o| o.script_pubkey.as_bytes()))
            .collect();
        let spent_refs: Vec<&[u8]> = spent.iter().map(|s| s.as_slice()).collect();
        basic_filter_from_scripts(&hash, outputs, spent_refs)
    }

    /// Header of `prev_hash`. Zeros are the genesis prev-header. A sealed
    /// best-chain block is that row. A stale block is rebuilt back to the
    /// best-chain fork point, and only when that fork point is sealed.
    #[doc(hidden)]
    pub fn parent_basic_filter_header(
        &self,
        prev_hash: &[u8; 32],
    ) -> Result<FilterHeader, QueryError> {
        if *prev_hash == [0u8; 32] {
            return Ok(FilterHeader::from_byte_array([0u8; 32]));
        }
        let mut pending = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut cursor = *prev_hash;
        let anchor = loop {
            if cursor == [0u8; 32] {
                break FilterHeader::from_byte_array([0u8; 32]);
            }
            if let Some(h) = self.height_of_hash(&cursor)? {
                if let Some((_, header)) = self.basic_filter_at(h.0)? {
                    break header;
                }
                return Err(StoreError::Rejected(FILTER_STILL_INDEXING));
            }
            if !seen.insert(cursor) {
                return Err(StoreError::Corrupt("invariant: blockfilter header cycle"));
            }
            pending.push(cursor);
            cursor = self.prev_header_hash(&cursor)?;
        };
        let mut header = anchor;
        for hash in pending.iter().rev() {
            let Some(block) = self.block_body_for_filter(hash)? else {
                return Err(StoreError::Corrupt(
                    "invariant: blockfilter parent body missing",
                ));
            };
            let spent = self.spent_scripts(&block)?;
            let filter = self.basic_filter_content(&block, &spent)?;
            header = filter.filter_header(&header);
        }
        Ok(header)
    }

    #[doc(hidden)]
    pub fn header_prev_hash(&self, hash: &[u8; 32]) -> Result<Option<[u8; 32]>, QueryError> {
        let Some((_, rec)) = self.get_header_by_hash(hash)? else {
            return Ok(None);
        };
        if rec.prev_fk.is_null() {
            return Ok(Some([0u8; 32]));
        }
        Ok(Some(self.get_header(rec.prev_fk)?.hash))
    }

    #[doc(hidden)]
    pub fn prev_header_hash(&self, hash: &[u8; 32]) -> Result<[u8; 32], QueryError> {
        self.header_prev_hash(hash)?.ok_or(StoreError::Corrupt(
            "invariant: blockfilter parent header missing",
        ))
    }

    #[doc(hidden)]
    pub fn block_body_for_filter(&self, hash: &[u8; 32]) -> Result<Option<Block>, QueryError> {
        if let Some(h) = self.height_of_hash(hash)? {
            return Ok(Some(self.reconstruct_block_at_height(h)?));
        }
        self.reconstruct_archived_block(hash)
    }

    #[doc(hidden)]
    pub fn spent_scripts(&self, block: &Block) -> Result<Vec<Vec<u8>>, QueryError> {
        let mut spent = Vec::new();
        for tx in &block.txdata {
            for inp in &tx.input {
                if inp.previous_output == OutPoint::null() {
                    continue;
                }
                let txid = inp.previous_output.txid.to_byte_array();
                let Some((_, rec)) = self.get_tx_by_txid(&txid)? else {
                    return Err(StoreError::Corrupt(
                        "invariant: blockfilter prevout missing",
                    ));
                };
                let out = self.tx_output(&rec, inp.previous_output.vout)?;
                spent.push(out.script);
            }
        }
        Ok(spent)
    }

    /// Filter bytes and header at `height`. `None` past the watermark.
    pub fn basic_filter_at(
        &self,
        height: u32,
    ) -> Result<Option<(Vec<u8>, FilterHeader)>, QueryError> {
        let Some(table) = self.block_filter_table() else {
            return Ok(None);
        };
        Ok(table
            .filter(Height(height))?
            .map(|(body, slot)| (body, FilterHeader::from_byte_array(slot.filter_header))))
    }

    /// Filter bytes for `start..=end` in one idx and one body read per
    /// segment. `None` when the index is off or `end` is past the watermark.
    pub fn basic_filters(&self, start: u32, end: u32) -> Result<Option<Vec<Vec<u8>>>, QueryError> {
        let Some(table) = self.block_filter_table() else {
            return Ok(None);
        };
        Ok(table
            .filters(Height(start), Height(end))?
            .map(|v| v.into_iter().map(|(body, _)| body).collect()))
    }

    /// Filter hash and header for `start..=end` without filter bytes.
    /// `None` when the index is off or `end` is past the watermark.
    pub fn basic_filter_hashes_and_headers(
        &self,
        start: u32,
        end: u32,
    ) -> Result<Option<Vec<(FilterHash, FilterHeader)>>, QueryError> {
        let Some(table) = self.block_filter_table() else {
            return Ok(None);
        };
        Ok(table.slots(Height(start), Height(end))?.map(|v| {
            v.into_iter()
                .map(|s| {
                    (
                        FilterHash::from_byte_array(s.filter_hash),
                        FilterHeader::from_byte_array(s.filter_header),
                    )
                })
                .collect()
        }))
    }

    /// Heights index write-behind may seal now: released through tip.
    pub fn index_target(&self) -> Option<u32> {
        let tip = self.tip_height()?.0;
        Some(self.index_released_through_height()?.min(tip))
    }

    #[doc(hidden)]
    pub fn commit_basic_filters(
        &self,
        table: &BlockFilterTable,
        start: u32,
        built: &[(BlockFilter, Fk)],
    ) -> Result<u32, QueryError> {
        let _appender = self.bf_wb.lock_appender();
        if table.next_height().0 != start {
            return Ok(0);
        }
        for (h, (_, header_fk)) in (start..).zip(built) {
            if self.store.confirmed.get(Height(h))? != Some(*header_fk) {
                return Ok(0);
            }
        }
        let mut prev = match start.checked_sub(1) {
            None => FilterHeader::from_byte_array([0u8; 32]),
            Some(h) => FilterHeader::from_byte_array(
                table
                    .slot(Height(h))?
                    .ok_or(StoreError::Corrupt(
                        "invariant: blockfilter slot below next",
                    ))?
                    .filter_header,
            ),
        };
        let mut recs = Vec::with_capacity(built.len());
        for (h, (filter, header_fk)) in (start..).zip(built) {
            let header = filter.filter_header(&prev);
            recs.push(BlockFilterRecord {
                height: Height(h),
                slot: BlockFilterSlot {
                    header_fk: *header_fk,
                    filter_hash: FilterHash::hash(&filter.content).to_byte_array(),
                    filter_header: header.to_byte_array(),
                },
                filter: &filter.content,
            });
            prev = header;
        }
        table.put(&recs)?;
        Ok(built.len() as u32)
    }

    /// Confirm may append filter and tweak rows for batches it connects.
    pub fn index_live(&self) -> bool {
        self.index_live.load(Ordering::Acquire)
    }

    /// The write side of [`Self::index_live`]. Startup sets it; confirm does not.
    pub fn set_index_live(&self, on: bool) {
        self.index_live.store(on, Ordering::Release);
    }

    /// Next filter height to seal (`None` when the filter index is off).
    pub fn filter_index_next(&self) -> Option<u32> {
        self.block_filter_table().map(|t| t.next_height().0)
    }

    /// Commit filters built for `start..` (a window). Returns heights
    /// committed; 0 when the watermark or a `confirmed[h]` moved (a reorg).
    pub fn commit_window_filters(
        &self,
        start: u32,
        built: &[(BlockFilter, Fk)],
    ) -> Result<u32, QueryError> {
        let Some(table) = self.block_filter_table() else {
            return Ok(0);
        };
        self.commit_basic_filters(table, start, built)
    }

    /// Wait for an index release (or `d`).
    pub fn wait_index_release(&self, d: std::time::Duration) {
        self.bf_wb.wait(d);
    }

    pub fn truncate_basic_filters_to_tip(&self) -> Result<(), QueryError> {
        match self.block_filters.get() {
            Some(t) => Ok(t.truncate_through(self.tip_height())?),
            None => Ok(()),
        }
    }
}
