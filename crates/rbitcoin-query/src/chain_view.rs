//! Header navigation, locators, height lookup, confirmed-read pin.

use super::*;

/// Published best-chain prefix a confirmed-tx read was built against.
///
/// `still_live` is true while `confirmed[height]` is still this `header_fk`.
/// Tip **extension** leaves a shorter pin live (prefix-stable). Disconnect or
/// same-height replace of that height does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainView {
    pub height: Height,
    pub hash: [u8; 32],
    pub header_fk: Fk,
}

impl ChainView {
    pub fn still_live(&self, query: &Query) -> Result<bool, QueryError> {
        match query.store.confirmed.get(self.height)? {
            Some(fk) if fk == self.header_fk => Ok(true),
            _ => Ok(false),
        }
    }
}

impl Query {
    /// Capture the published tip as a [`ChainView`], or `None` if the chain is empty.
    pub fn pin_chain_view(&self) -> Result<Option<ChainView>, QueryError> {
        let Some(height) = self.tip_height() else {
            return Ok(None);
        };
        let Some((_, rec)) = self.header_at_height(height)? else {
            return Ok(None);
        };
        self.pin_chain_view_at(&rec.hash)
    }

    /// Pin a **best-chain** header hash (tip or buried). `None` if it is not
    /// `confirmed[height]` (unknown, archive-only orphan, or disconnected).
    pub fn pin_chain_view_at(&self, hash: &[u8; 32]) -> Result<Option<ChainView>, QueryError> {
        let Some(height) = self.height_of_hash(hash)? else {
            return Ok(None);
        };
        let Some(header_fk) = self.store.confirmed.get(height)? else {
            return Ok(None);
        };
        let rec = self.store.get_header(header_fk)?;
        if rec.hash != *hash {
            return Ok(None);
        }
        Ok(Some(ChainView {
            height,
            hash: rec.hash,
            header_fk,
        }))
    }

    /// Pin, run `f`, return the body if that pin is still published; else retry.
    ///
    /// Bound is 8. Empty chain is [`StoreError::NotFound`]. A pin that never
    /// stays live is [`StoreError::Stale`], not corruption.
    pub fn run_at_chain_view<T, F>(&self, mut f: F) -> Result<(ChainView, T), QueryError>
    where
        F: FnMut(&ChainView) -> Result<T, QueryError>,
    {
        const BOUND: u32 = 8;
        for _ in 0..BOUND {
            let Some(view) = self.pin_chain_view()? else {
                return Err(StoreError::NotFound);
            };
            let out = f(&view)?;
            if view.still_live(self)? {
                return Ok((view, out));
            }
        }
        Err(StoreError::Stale("chain view moved"))
    }

    pub fn header_at_height(
        &self,
        height: Height,
    ) -> Result<Option<(Fk, HeaderRecord)>, QueryError> {
        match self.store.confirmed.get(height)? {
            None => Ok(None),
            Some(fk) => Ok(Some((fk, self.store.get_header(fk)?))),
        }
    }

    /// Best-chain height of a header hash, if it is **confirmed** on the tip chain.
    ///
    /// Archive may contain orphan header rows (partial connect failures). Those are
    /// not reported here — only hashes reachable as `confirmed[height]`.
    ///
    /// Uses an in-process `hash → height` map (~60 MiB at mainnet tip), rebuilt when
    /// tip jumps; tip±1 updates are incremental. Avoids O(tip) header body walks.
    pub fn height_of_hash(&self, hash: &[u8; 32]) -> Result<Option<Height>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(None);
        };
        if let Some((_, rec)) = self.header_at_height(tip)? {
            if &rec.hash == hash {
                return Ok(Some(tip));
            }
            if tip.0 > 0 {
                if let Some((_, prec)) = self.header_at_height(Height(tip.0 - 1))? {
                    if &prec.hash == hash {
                        return Ok(Some(Height(tip.0 - 1)));
                    }
                }
            }
        }
        // Cheap archive miss before ensuring/using the map.
        if self.get_header_by_hash(hash)?.is_none() {
            return Ok(None);
        }
        self.ensure_height_by_hash_index(tip)?;
        let g = self
            .height_by_hash
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Ok(g.map.get(hash).copied().map(Height))
    }

    /// Ensure height index matches `tip` (incremental tip±1 when possible).
    pub(crate) fn ensure_height_by_hash_index(&self, tip: Height) -> Result<(), QueryError> {
        let mut g = self
            .height_by_hash
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if g.tip == Some(tip.0) {
            return Ok(());
        }
        if let Some(prev_tip) = g.tip {
            if tip.0 == prev_tip.saturating_add(1) {
                if let Some((_, rec)) = self.header_at_height(tip)? {
                    g.map.insert(rec.hash, tip.0);
                    g.tip = Some(tip.0);
                    return Ok(());
                }
            }
            if prev_tip == tip.0.saturating_add(1) {
                // Old tip header may still be loadable via archive by walking map keys —
                // drop any entry whose height is prev_tip.
                g.map.retain(|_, h| *h != prev_tip);
                g.tip = Some(tip.0);
                return Ok(());
            }
        }
        g.map.clear();
        g.map.reserve((tip.0 as usize).saturating_add(1));
        for h in 0..=tip.0 {
            if let Some((_, rec)) = self.header_at_height(Height(h))? {
                g.map.insert(rec.hash, h);
            }
        }
        g.tip = Some(tip.0);
        Ok(())
    }

    /// Drop height index (tests / multi-height reorg / offline confirmed rewrite).
    pub fn invalidate_height_by_hash_index(&self) {
        let mut g = self
            .height_by_hash
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        g.tip = None;
        g.map.clear();
    }

    /// Wire header for a confirmed height (resolves prev hash from archive).
    pub fn wire_header_at_height(&self, height: Height) -> Result<BlockHeader, QueryError> {
        let (_fk, rec) = self.header_at_height(height)?.ok_or(StoreError::NotFound)?;
        self.wire_header_from_record(&rec)
    }

    pub(crate) fn wire_header_from_record(
        &self,
        rec: &HeaderRecord,
    ) -> Result<BlockHeader, QueryError> {
        self.wire_header_from_record_prev(rec, None)
    }

    /// Wire header with optional prev hash (cache package — avoids store get).
    pub(crate) fn wire_header_from_record_prev(
        &self,
        rec: &HeaderRecord,
        prev_hash: Option<[u8; 32]>,
    ) -> Result<BlockHeader, QueryError> {
        let prev_blockhash = if rec.prev_fk.is_null() {
            BlockHash::from_byte_array([0u8; 32])
        } else if let Some(h) = prev_hash {
            BlockHash::from_byte_array(h)
        } else {
            let prev = self.store.get_header(rec.prev_fk)?;
            BlockHash::from_byte_array(prev.hash)
        };
        Ok(wire_header(rec, prev_blockhash))
    }

    /// Reconstruct a full wire block from Class A archive by header hash
    /// (confirmed or not). Requires `header_txs` body.
    pub fn locator_hashes(&self) -> Result<Vec<BlockHash>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(vec![BlockHash::from_byte_array([0u8; 32])]);
        };
        let mut out = Vec::new();
        let mut h = tip.0 as i64;
        let mut step = 1i64;
        while h >= 0 {
            let (_fk, rec) = self
                .header_at_height(Height(h as u32))?
                .ok_or(StoreError::NotFound)?;
            out.push(BlockHash::from_byte_array(rec.hash));
            if out.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        if let Some((_fk, rec)) = self.header_at_height(Height::GENESIS)? {
            let g = BlockHash::from_byte_array(rec.hash);
            if out.last() != Some(&g) {
                out.push(g);
            }
        }
        Ok(out)
    }

    /// Headers on the best chain after the first matching locator entry, up to `limit` (max 2000).
    pub fn headers_after_locator(
        &self,
        locator: &[BlockHash],
        stop: BlockHash,
        limit: usize,
    ) -> Result<Vec<BlockHeader>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(Vec::new());
        };
        let limit = limit.min(2000);
        // Empty locator: Core treats hashstop as a single-block request
        // (`p2p_sendheaders` null-locator). Unknown / zero stop → no headers.
        if locator.is_empty() {
            if stop.to_byte_array() == [0u8; 32] {
                return Ok(Vec::new());
            }
            return match self.height_of_hash(&stop.to_byte_array())? {
                Some(h) => Ok(vec![self.wire_header_at_height(h)?]),
                None => Ok(Vec::new()),
            };
        }
        let mut start = 0u32;
        'outer: for loc in locator {
            if loc.to_byte_array() == [0u8; 32] {
                start = 0;
                break;
            }
            if let Some(h) = self.height_of_hash(&loc.to_byte_array())? {
                start = h.0.saturating_add(1);
                break 'outer;
            }
        }
        // If no locator matched, Bitcoin peers typically start from genesis; we start at 0.
        let mut out = Vec::new();
        let mut h = start;
        while h <= tip.0 && out.len() < limit {
            let hdr = self.wire_header_at_height(Height(h))?;
            let hash = hdr.block_hash();
            out.push(hdr);
            if hash == stop && stop.to_byte_array() != [0u8; 32] {
                break;
            }
            h += 1;
        }
        Ok(out)
    }
}
