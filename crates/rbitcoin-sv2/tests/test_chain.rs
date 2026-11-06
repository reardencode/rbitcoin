use bitcoin::{Network, Txid};
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::ChainHub;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Height;
use rbitcoin_query::testutil::{tiny_query_labeled, TempDir};
use rbitcoin_query::{accept_and_connect_block, pad_empty_from};
use std::path::Path;
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
    padded_chain_with(label, 100 + spendable, ChainParams::regtest())
}

/// [`padded_chain`] to height `tip` under `params`, which must accept the
/// regtest padding. The first `tip - 100` coinbases are spendable.
pub(crate) fn padded_chain_with(label: &str, tip: u32, params: ChainParams) -> TestChain {
    let (dir, q) = tiny_query_labeled(label);
    let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (_, tip_time, coinbases) = pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        tip,
        tip.saturating_sub(100),
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

/// A private hub copied from one process-wide regtest pad (3 spendable
/// coinbases). `spendable` is how many of those coinbases the chapter uses.
/// The pad is connected once; each caller gets a copy so parallel tests do
/// not share a tip or a mempool.
pub(crate) fn shared_regtest(spendable: u32) -> TestChain {
    use std::sync::OnceLock;
    assert!(
        spendable <= 3,
        "shared regtest pad has 3 spendable coinbases"
    );
    static PAD: OnceLock<TestChain> = OnceLock::new();
    let src = PAD.get_or_init(|| {
        let tc = padded_chain("sv2-shared", 3);
        tc.chain.query.flush().expect("flush shared pad");
        tc
    });
    // The pad is quiescent after init. Copies only read it.
    copy_quiescent(src, "sv2-shared")
}

fn copy_quiescent(src: &TestChain, label: &str) -> TestChain {
    let dir = TempDir::labeled(label).expect("temp");
    copy_tree_except(src._dir.path(), dir.path(), "mempool");
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).expect("open copy");
    let chain = Arc::new(ChainHub::new(q, src.chain.params.clone(), Milestone::NONE));
    let mp = dir.path().join("mempool");
    std::fs::create_dir_all(&mp).unwrap();
    let mempool = MempoolHub::open(&mp, Arc::clone(&chain.query)).unwrap();
    mempool.set_relay_enabled(true);
    assert!(chain.attach_mempool(Arc::clone(&mempool)).is_ok());
    TestChain {
        _dir: dir,
        chain,
        mempool,
        coinbases: src.coinbases.clone(),
        tip_time: src.tip_time,
    }
}

fn copy_tree_except(src: &Path, dst: &Path, skip: &str) {
    for ent in std::fs::read_dir(src).expect("read store") {
        let ent = ent.expect("store entry");
        if ent.file_name() == skip {
            continue;
        }
        let to = dst.join(ent.file_name());
        let ty = ent.file_type().expect("file type");
        if ty.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_tree_except(&ent.path(), &to, skip);
        } else {
            std::fs::copy(ent.path(), &to).unwrap();
        }
    }
}
