//! Custom job validation for a Job Declarator Server
//! (docs/sv2-job-validation.md §4): resolve the declared wtxids, check the
//! job as a block proposal on the tip, and shape it for retention.

use crate::messages::ProposeTemplate;
use crate::template::{self, Job};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{block, Block, BlockHash, Transaction, TxMerkleNode, Wtxid};
use rbitcoin_net::ChainHub;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

pub(crate) enum Verdict {
    /// 0-indexed positions in `wtxid_list` neither the mempool nor
    /// `transaction_list` resolves.
    Missing(Vec<u16>),
    /// Consensus-valid on the tip: the fee total and the job to retain.
    Valid { fees: u64, job: Job },
    /// `ProposeTemplate.Error.error_code`: a Core reject string or one of
    /// the draft's own codes.
    Rejected(String),
}

/// Reads the store and the mempool: blocking region only. `None`: the
/// payload is not a `ProposeTemplate`.
pub(crate) fn validate(
    chain: &ChainHub,
    mut payload: Vec<u8>,
) -> io::Result<Option<(u32, Verdict)>> {
    let Ok(m) = binary_sv2::from_bytes::<ProposeTemplate>(&mut payload) else {
        return Ok(None);
    };
    Ok(Some((m.request_id, check(chain, &m)?)))
}

/// §4.1 and §4.4, in order. The draft's own codes run before any mempool
/// lookup or transaction decode, so a 32-byte wtxid is never amplified into
/// a copy or an allocation the job did not declare.
fn check(chain: &ChainHub, m: &ProposeTemplate) -> io::Result<Verdict> {
    let rejected = |code: &str| Ok(Verdict::Rejected(code.into()));
    // Same gate as the templates: a stale tip validates nothing.
    if chain.in_ibd() {
        return rejected("job-validation-unavailable");
    }
    let next = template::next_header(chain)?;
    if m.prev_hash.as_ref() != next.prev_hash {
        return rejected("stale-prevhash");
    }
    let mut declared = HashSet::with_capacity(m.wtxid_list.len());
    for w in m.wtxid_list.iter() {
        if !declared.insert(w.as_ref()) {
            return rejected("duplicate-wtxid");
        }
    }
    // The wtxid is the hash of the serialization as sent, so a supplied tx
    // is matched to its slot without decoding it.
    let supplied: HashMap<[u8; 32], &[u8]> = m
        .transaction_list
        .iter()
        .map(|raw| {
            (
                sha256d::Hash::hash(raw.as_ref()).to_byte_array(),
                raw.as_ref(),
            )
        })
        .collect();
    if supplied.keys().any(|w| !declared.contains(&w[..])) {
        return rejected("bad-missing-tx");
    }
    let Ok(coinbase) = bitcoin::consensus::deserialize::<Transaction>(m.coinbase_tx.as_ref())
    else {
        return rejected("bad-cb-decode");
    };
    let mut txs = Vec::with_capacity(m.wtxid_list.len());
    let mut missing = Vec::new();
    for (pos, w) in m.wtxid_list.iter().enumerate() {
        let w: [u8; 32] = w.as_ref().try_into().expect("U256 is 32 bytes");
        let tx = match supplied.get(&w) {
            Some(raw) => match bitcoin::consensus::deserialize::<Transaction>(raw) {
                Ok(tx) => Some(tx),
                Err(_) => return rejected("bad-missing-tx"),
            },
            None => chain
                .mempool()
                .and_then(|mp| mp.get_tx_by_wtxid(&Wtxid::from_byte_array(w))),
        };
        match tx {
            Some(tx) => txs.push(tx),
            None => missing.push(u16::try_from(pos).expect("Seq064K holds at most 65535")),
        }
    }
    if !missing.is_empty() {
        return Ok(Verdict::Missing(missing));
    }
    let mut leaves = Vec::with_capacity(1 + txs.len());
    leaves.push(coinbase.compute_txid().to_byte_array());
    leaves.extend(txs.iter().map(|tx| tx.compute_txid().to_byte_array()));
    let header = block::Header {
        version: block::Version::from_consensus(m.version as i32),
        prev_blockhash: BlockHash::from_byte_array(next.prev_hash),
        merkle_root: TxMerkleNode::from_byte_array(rbitcoin_store::merkle_root_from_txids(&leaves)),
        time: next.time,
        bits: next.bits,
        nonce: 0,
    };
    let mut txdata = Vec::with_capacity(1 + txs.len());
    txdata.push(coinbase);
    txdata.extend(txs);
    let mut block = Block { header, txdata };
    // CPU trade (CONTRIBUTING 9): one full proposal check per request
    // (every spend against the chain, structure, weight, sigops, coinbase
    // value; no scripts, no PoW), on the blocking pool. A JDS sends one per
    // declaration; a flood costs blocking threads, not the reactor.
    let fees = match chain.check_block_proposal(&block) {
        Ok(fees) => fees,
        Err(code) => return Ok(Verdict::Rejected(code)),
    };
    let txs = block
        .txdata
        .split_off(1)
        .into_iter()
        .map(Arc::new)
        .collect();
    Ok(Verdict::Valid {
        fees,
        job: next.job(rbitcoin_store::merkle_branch(&leaves, 0), txs),
    })
}
