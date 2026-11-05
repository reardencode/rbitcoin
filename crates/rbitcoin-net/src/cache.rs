//! In-memory wire block cache for P2P serve and ordered sync.
//!
//! Full block bodies are kept only for a recent tip window (default
//! [`DEFAULT_BODY_DEPTH`], compact/`getblocktxn` serve). Best-chain **hashes**
//! are retained for locator construction without holding decoded IBD history.

use bitcoin::block::{Block, Header};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use std::collections::HashMap;
use std::sync::RwLock;

/// How many recent full block bodies to retain (compact/`getblocktxn` serve
/// depths are 5 and 10; hashes stay for locators).
pub const DEFAULT_BODY_DEPTH: usize = 16;

#[derive(Debug)]
pub struct BlockCache {
    pub inner: RwLock<Inner>,
    /// Max full bodies in `by_hash` (hashes in `chain` are always kept).
    pub body_depth: usize,
}

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct Inner {
    pub by_hash: HashMap<BlockHash, Block>,
    /// Best-chain hashes by height (contiguous from 0).
    pub chain: Vec<BlockHash>,
    /// Unconnected bodies a compact announce may serve. Not best-chain.
    servable: HashMap<BlockHash, Block>,
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::with_body_depth(DEFAULT_BODY_DEPTH)
    }
}

impl BlockCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_body_depth(body_depth: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            body_depth: body_depth.max(1),
        }
    }

    pub fn tip_height(&self) -> Option<u32> {
        let g = self.inner.read().unwrap();
        if g.chain.is_empty() {
            None
        } else {
            Some((g.chain.len() - 1) as u32)
        }
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.inner.read().unwrap().chain.last().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().chain.is_empty()
    }

    pub fn stored_bodies(&self) -> usize {
        self.inner.read().unwrap().by_hash.len()
    }

    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        self.inner.read().unwrap().by_hash.get(hash).cloned()
    }

    pub fn get_header(&self, hash: &BlockHash) -> Option<Header> {
        self.inner
            .read()
            .unwrap()
            .by_hash
            .get(hash)
            .map(|b| b.header)
    }

    pub fn hash_at_height(&self, height: u32) -> Option<BlockHash> {
        self.inner
            .read()
            .unwrap()
            .chain
            .get(height as usize)
            .copied()
    }

    pub fn header_at_height(&self, height: u32) -> Option<Header> {
        let g = self.inner.read().unwrap();
        let h = g.chain.get(height as usize)?;
        g.by_hash.get(h).map(|b| b.header)
    }

    /// Drop all blocks above `height` (keep 0..=height). No-op if cache shorter.
    pub fn truncate_to_height(&self, height: u32) {
        let mut g = self.inner.write().unwrap();
        let keep = (height as usize).saturating_add(1);
        if g.chain.len() <= keep {
            return;
        }
        let remove: Vec<BlockHash> = g.chain[keep..].to_vec();
        g.chain.truncate(keep);
        for h in remove {
            g.by_hash.remove(&h);
        }
    }

    /// Clear entire cache (e.g. after full reorg from genesis).
    pub fn clear(&self) {
        let mut g = self.inner.write().unwrap();
        g.by_hash.clear();
        g.chain.clear();
        g.servable.clear();
    }

    /// Park a body so `getblocktxn` can serve it before connect. Best-chain
    /// lookup does not see this map.
    pub fn stage_servable(&self, block: Block) {
        let hash = block.block_hash();
        self.inner.write().unwrap().servable.insert(hash, block);
    }

    pub fn servable(&self, hash: &BlockHash) -> Option<Block> {
        self.inner.read().unwrap().servable.get(hash).cloned()
    }

    pub fn drop_servable(&self, hash: &BlockHash) {
        self.inner.write().unwrap().servable.remove(hash);
    }

    /// Append a block that extends the best chain (or becomes genesis at height 0).
    ///
    /// Evicts full bodies older than `body_depth` while keeping the hash chain.
    pub fn push_best(&self, block: Block) -> Result<(), &'static str> {
        let hash = block.block_hash();
        let mut g = self.inner.write().unwrap();
        if g.chain.is_empty() {
            g.by_hash.insert(hash, block);
            g.chain.push(hash);
            return Ok(());
        }
        let tip = *g.chain.last().unwrap();
        if block.header.prev_blockhash != tip {
            return Err("block does not extend best chain");
        }
        g.by_hash.insert(hash, block);
        g.chain.push(hash);
        let extra = g.chain.len().saturating_sub(self.body_depth);
        if extra != 0 {
            let stale: Vec<BlockHash> = g.chain[..extra].to_vec();
            for h in stale {
                g.by_hash.remove(&h);
            }
        }
        Ok(())
    }

    /// Headers after the best common locator hash, up to Core `MAX_HEADERS_RESULTS` (2000).
    ///
    /// Only returns headers still present as full bodies in the tip window; callers
    /// that need deeper history should use the store reconstruct path.
    pub fn headers_after_locator(&self, locator: &[BlockHash], stop: BlockHash) -> Vec<Header> {
        let g = self.inner.read().unwrap();
        if g.chain.is_empty() {
            return Vec::new();
        }
        let mut start = 0usize;
        'outer: for loc in locator {
            for (i, h) in g.chain.iter().enumerate() {
                if h == loc {
                    start = i + 1;
                    break 'outer;
                }
            }
        }
        let mut out = Vec::new();
        for h in g
            .chain
            .iter()
            .skip(start)
            .take(crate::codec::MAX_HEADERS_RESULTS)
        {
            if let Some(b) = g.by_hash.get(h) {
                out.push(b.header);
                if *h == stop && stop.to_byte_array() != [0u8; 32] {
                    break;
                }
            }
        }
        out
    }
}
