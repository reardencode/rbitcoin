use bitcoin::{Network, Txid};
use rbitcoin_consensus::{accept_and_connect_block, pad_empty_from, ChainParams, Milestone};
use rbitcoin_net::{ChainHub, MempoolHub};
use rbitcoin_primitives::Height;
use rbitcoin_query::testutil::{tiny_query_labeled, TempDir};
use std::sync::Arc;

pub(crate) struct TestChain {
    pub _dir: TempDir,
    pub chain: Arc<ChainHub>,
    pub mempool: Arc<MempoolHub>,
    /// Mature OP_TRUE coinbases, oldest first.
    pub coinbases: Vec<Txid>,
    /// Padded tip time: far in the past, so the chain starts in IBD.
    pub tip_time: u32,
}

/// Regtest chain padded to `100 + spendable` with an attached relaying mempool.
/// The node clock is wall time, so the stale tip keeps `in_ibd()` true.
pub(crate) fn padded_chain(label: &str, spendable: u32) -> TestChain {
    let (dir, q) = tiny_query_labeled(label);
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (_, tip_time, coinbases) = pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        100 + spendable,
        spendable,
    );
    let chain = Arc::new(ChainHub::new(q, params, Milestone::NONE));
    let mp = dir.path().join("mempool");
    std::fs::create_dir_all(&mp).unwrap();
    let mempool = MempoolHub::open(&mp, Arc::clone(&chain.query)).unwrap();
    mempool.set_relay_enabled(true);
    assert!(chain.attach_mempool(Arc::clone(&mempool)).is_ok());
    TestChain {
        _dir: dir,
        chain,
        mempool,
        coinbases,
        tip_time,
    }
}
