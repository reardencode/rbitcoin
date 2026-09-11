//! Shared regtest chain builders so scenarios mine a mature chain once.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, Txid};
use rbitcoin_consensus::{
    accept_and_connect_block, pad_empty_from as consensus_pad, ChainParams, Milestone,
};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;

use crate::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};

/// Blocks `0..=tip` accepted into `query`, including a spend of block-1 coinbase
/// at the tip when maturity allows.
pub struct MatureRegtestChain {
    pub blocks: Vec<Block>,
    /// Height of the block that spends block-1 coinbase (last block).
    pub spend_height: u32,
    /// Coinbase txid of height-1 (the matured output we spend).
    pub matured_coinbase_txid: Txid,
}

impl MatureRegtestChain {
    pub fn tip_height(&self) -> u32 {
        (self.blocks.len() - 1) as u32
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.blocks.last().unwrap().block_hash()
    }
}

/// Build genesis → pad through coinbase maturity → one spend of height-1 coinbase.
///
/// Mines and accepts **once**. Callers should reuse `blocks` for reconstruct / spend
/// assertions instead of rebuilding parallel 100-block chains.
pub fn build_mature_regtest_with_spend(query: &Query, params: &ChainParams) -> MatureRegtestChain {
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    let genesis = regtest_genesis();
    accept_and_connect_block(query, params, Height::GENESIS, &genesis, ms).unwrap();

    let mut blocks = vec![genesis.clone()];
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_regtest_block(tip, tip_time + 600, 1, vec![]);
    let matured_coinbase_txid = b1.txdata[0].compute_txid();
    accept_and_connect_block(query, params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    blocks.push(b1);

    // Pad until height-1 has `maturity` confirmations → spendable at height `1 + maturity`.
    // After connecting height H, confs of h1 = H - 1. Need H - 1 >= maturity ⇒ H >= maturity + 1.
    let last_pad = maturity + 1; // inclusive; at this height spend is allowed for next block
    for h in 2..=last_pad {
        let b = mine_regtest_block(tip, tip_time + 600, h, vec![]);
        accept_and_connect_block(query, params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
        blocks.push(b);
    }

    let spend_height = last_pad + 1;
    let spend = spend_anyone_can_spend(matured_coinbase_txid, 0, Amount::from_sat(49_0000_0000));
    let b_spend = mine_regtest_block(tip, tip_time + 600, spend_height, vec![spend]);
    accept_and_connect_block(query, params, Height(spend_height), &b_spend, ms).unwrap();
    blocks.push(b_spend);
    query.apply_sh_pending().unwrap();

    MatureRegtestChain {
        blocks,
        spend_height,
        matured_coinbase_txid,
    }
}

/// Fast empty pad via [`rbitcoin_consensus::pad_empty_from`].
///
/// Mines heights `from_h..=last` on top of `tip` / `tip_time`. Prefer this for
/// coinbase-maturity padding instead of looping `confirm_wire_run`.
///
/// Returns `(new_tip_hash, new_tip_time)`.
pub fn pad_empty_from(
    query: &Query,
    params: &ChainParams,
    tip: BlockHash,
    tip_time: u32,
    from_h: u32,
    last: u32,
) -> (BlockHash, u32) {
    let (tip, tip_time, _) = consensus_pad(query, params, tip, tip_time, from_h, last, 0);
    (tip, tip_time)
}

/// Assert reconstructed wire matches `original` at `height`.
pub fn assert_reconstruct_eq(query: &Query, height: u32, original: &Block) {
    use bitcoin::consensus::Encodable;

    let recon = query
        .reconstruct_block_at_height(Height(height))
        .unwrap_or_else(|e| panic!("reconstruct height {height}: {e}"));
    assert_eq!(
        recon.block_hash(),
        original.block_hash(),
        "hash height {height}"
    );
    assert_eq!(recon.header, original.header, "header height {height}");
    assert_eq!(recon.txdata.len(), original.txdata.len());
    for (i, (a, b)) in recon.txdata.iter().zip(original.txdata.iter()).enumerate() {
        let mut ra = Vec::new();
        let mut rb = Vec::new();
        a.consensus_encode(&mut ra).unwrap();
        b.consensus_encode(&mut rb).unwrap();
        assert_eq!(ra, rb, "tx wire height {height} index {i}");
    }
    let by_hash = query
        .reconstruct_block_by_hash(&original.block_hash().to_byte_array())
        .unwrap()
        .expect("by hash");
    assert_eq!(by_hash.block_hash(), original.block_hash());
}
