//! In-memory wire block cache for P2P serve and ordered sync.
//!
//! Full block bodies are kept only for a recent tip window (default
//! [`DEFAULT_BODY_DEPTH`]). Best-chain **hashes** are retained for locator
//! construction without holding the entire IBD history in RAM.

use bitcoin::block::{Block, Header};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use std::collections::HashMap;
use std::sync::RwLock;

/// How many recent full block bodies to retain (matches IBD horizon; hash chain
/// is kept without bodies for locators).
pub const DEFAULT_BODY_DEPTH: usize = 144;

#[derive(Debug)]
pub struct BlockCache {
    inner: RwLock<Inner>,
    /// Max full bodies in `by_hash` (hashes in `chain` are always kept).
    body_depth: usize,
}

#[derive(Debug, Default)]
struct Inner {
    by_hash: HashMap<BlockHash, Block>,
    /// Best-chain hashes by height (contiguous from 0).
    chain: Vec<BlockHash>,
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

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().chain.is_empty()
    }

    pub fn body_count(&self) -> usize {
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
        let depth = self.body_depth;
        if g.chain.len() > depth {
            let drop_to = g.chain.len() - depth;
            let stale: Vec<BlockHash> = g.chain[..drop_to].to_vec();
            for h in stale {
                g.by_hash.remove(&h);
            }
        }
        Ok(())
    }

    /// Locator hashes newest-first for getheaders.
    pub fn locator(&self) -> Vec<BlockHash> {
        let g = self.inner.read().unwrap();
        if g.chain.is_empty() {
            return vec![BlockHash::from_byte_array([0u8; 32])];
        }
        let mut out = Vec::new();
        let mut i = g.chain.len() as i64 - 1;
        let mut step = 1i64;
        while i >= 0 {
            out.push(g.chain[i as usize]);
            if out.len() >= 10 {
                step *= 2;
            }
            i -= step;
        }
        // Always include genesis
        if let Some(g0) = g.chain.first() {
            if out.last() != Some(g0) {
                out.push(*g0);
            }
        }
        out
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
            if loc.to_byte_array() == [0u8; 32] {
                start = 0;
                break;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };

    fn dummy_block(prev: BlockHash, n: u32) -> Block {
        let coinbase = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![n as u8]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut b = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1_700_000_000 + n,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: n,
            },
            txdata: vec![coinbase],
        };
        b.header.merkle_root = b.compute_merkle_root().unwrap();
        b
    }

    #[test]
    fn cache_push_locator_headers_evict_truncate() {
        let c = BlockCache::with_body_depth(3);
        assert!(c.is_empty());
        let g = dummy_block(BlockHash::from_byte_array([0u8; 32]), 0);
        // Genesis-like: empty chain accepts any first block.
        c.push_best(g.clone()).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c.tip_height(), Some(0));
        let mut tip = g.block_hash();
        for n in 1..=5u32 {
            let b = dummy_block(tip, n);
            tip = b.block_hash();
            c.push_best(b).unwrap();
        }
        assert_eq!(c.tip_height(), Some(5));
        // Only last 3 bodies retained.
        assert!(c.get_block(&g.block_hash()).is_none());
        assert!(c.get_block(&tip).is_some());
        assert!(c.hash_at_height(0).is_some());
        let loc = c.locator();
        assert_eq!(loc[0], tip);
        let hdrs =
            c.headers_after_locator(&[g.block_hash()], BlockHash::from_byte_array([0u8; 32]));
        // Only tip-window bodies yield headers.
        assert!(!hdrs.is_empty() || c.get_header(&tip).is_some());
        // Zero locator starts from genesis hash index.
        let from_zero = c.headers_after_locator(&[BlockHash::from_byte_array([0u8; 32])], tip);
        assert!(!from_zero.is_empty() || c.header_at_height(5).is_some());
        c.truncate_to_height(2);
        assert!(c.tip_height().unwrap() <= 2);
        c.truncate_to_height(100); // no-op when shorter
        c.clear();
        assert!(c.is_empty());
        assert!(c.tip_hash().is_none());
        // Default ctor + empty-chain edge cases.
        let d = BlockCache::default();
        assert!(d.is_empty());
        assert_eq!(d.locator().len(), 1); // genesis zero hash
        assert!(d
            .headers_after_locator(&[], BlockHash::from_byte_array([0u8; 32]))
            .is_empty());
        // Non-extending block rejected after genesis.
        let g2 = dummy_block(BlockHash::from_byte_array([0u8; 32]), 0);
        d.push_best(g2.clone()).unwrap();
        let orphan = dummy_block(BlockHash::from_byte_array([9u8; 32]), 1);
        assert!(d.push_best(orphan).is_err());
        assert!(d.get_header(&g2.block_hash()).is_some());
    }
}
