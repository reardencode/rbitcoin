//! Custom job validation for a Job Declarator Server
//! (docs/sv2-job-validation.md §4): resolve the declared wtxids, check the
//! job as a block proposal on the tip, and shape it for retention.

use crate::messages::ProposeTemplate;
use crate::template::{self, Job};
use binary_sv2::{Seq064K, B016M};
use bitcoin::consensus::encode::{deserialize_partial, VarInt};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{block, Block, BlockHash, Transaction, TxMerkleNode, Wtxid};
use rbitcoin_net::ChainHub;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

pub(crate) enum Verdict {
    /// 0-indexed positions in `wtxid_list` the mempool does not resolve,
    /// the supplied ones included: the TP holds no transactions across the
    /// round trip, so what it was given once it asks for again.
    Missing(Vec<u16>),
    /// Consensus-valid on the tip: the fee total and the job to retain.
    Valid { fees: u64, job: Job },
    /// `ProposeTemplate.Error.error_code`: a Core reject string or one of
    /// the draft's own codes.
    Rejected(String),
}

/// A `ProposeTemplate` as the session keeps it: owned, so it outlives its
/// frame while the TP waits for the transactions it asked for. `excess_data`
/// is not kept (opaque to the TP).
pub(crate) struct Proposal {
    pub request_id: u32,
    version: u32,
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    wtxids: Vec<[u8; 32]>,
}

/// Supplied transactions keyed by the wtxid of their bytes as sent.
pub(crate) type Supplied = HashMap<[u8; 32], Vec<u8>>;

impl Proposal {
    /// `None`: the payload is not a `ProposeTemplate`.
    pub(crate) fn decode(payload: &mut [u8]) -> Option<Self> {
        let m: ProposeTemplate = binary_sv2::from_bytes(payload).ok()?;
        Some(Self {
            request_id: m.request_id,
            version: m.version,
            coinbase_prefix: m.coinbase_tx_prefix.as_ref().to_vec(),
            coinbase_suffix: m.coinbase_tx_suffix.as_ref().to_vec(),
            wtxids: m
                .wtxid_list
                .iter()
                .map(|w| w.as_ref().try_into().expect("U256 is 32 bytes"))
                .collect(),
        })
    }

    /// §4.1: `wtxid_list` has no duplicates. No chain read, so the session
    /// runs it on arrival; [`validate`] runs it again and stays complete on
    /// its own.
    pub(crate) fn precheck(&self) -> Result<(), &'static str> {
        let mut declared = HashSet::with_capacity(self.wtxids.len());
        if self.wtxids.iter().all(|w| declared.insert(w)) {
            Ok(())
        } else {
            Err("duplicate-wtxid")
        }
    }

    /// §4.3: every supplied transaction hashes to a wtxid at one of the
    /// positions the TP asked for, and every asked position is covered,
    /// before any of them is decoded or copied, so a transaction nobody
    /// asked for costs one hash and a short provide costs none. `Err` is
    /// the `Error.error_code`.
    pub(crate) fn accept_supplied(
        &self,
        missing: &[u16],
        transaction_list: &Seq064K<'_, B016M<'_>>,
    ) -> Result<Supplied, &'static str> {
        let asked: HashSet<&[u8; 32]> = missing
            .iter()
            .filter_map(|&pos| self.wtxids.get(usize::from(pos)))
            .collect();
        let mut supplied = Supplied::with_capacity(transaction_list.len());
        for raw in transaction_list.iter() {
            let w = sha256d::Hash::hash(raw.as_ref()).to_byte_array();
            if !asked.contains(&w) {
                return Err("bad-missing-tx");
            }
            supplied.insert(w, raw.as_ref().to_vec());
        }
        if supplied.len() != asked.len() {
            return Err("bad-missing-tx");
        }
        Ok(supplied)
    }
}

/// Reads the store and the mempool: blocking region only.
pub(crate) fn validate(chain: &ChainHub, p: &Proposal, supplied: &Supplied) -> io::Result<Verdict> {
    let rejected = |code: &str| Ok(Verdict::Rejected(code.into()));
    // Same gate as the templates: a stale tip validates nothing.
    if chain.in_ibd() {
        return rejected("job-validation-unavailable");
    }
    let next = template::next_header(chain)?;
    if let Err(code) = p.precheck() {
        return rejected(code);
    }
    let Some(extranonce) = extranonce_len(&p.coinbase_prefix) else {
        return rejected("bad-cb-decode");
    };
    let zeros = vec![0u8; extranonce];
    let raw = [&p.coinbase_prefix[..], &zeros[..], &p.coinbase_suffix[..]].concat();
    let Ok(coinbase) = bitcoin::consensus::deserialize::<Transaction>(&raw) else {
        return rejected("bad-cb-decode");
    };
    let mut txs = Vec::with_capacity(p.wtxids.len());
    let mut missing = Vec::new();
    let mut provided = Vec::new();
    for (pos, w) in p.wtxids.iter().enumerate() {
        let pos = u16::try_from(pos).expect("Seq064K holds at most 65535");
        let tx = match supplied.get(w) {
            Some(raw) => match bitcoin::consensus::deserialize::<Transaction>(raw) {
                Ok(tx) => {
                    provided.push(pos);
                    Some(tx)
                }
                Err(_) => return rejected("bad-missing-tx"),
            },
            None => chain
                .mempool()
                .and_then(|mp| mp.get_tx_by_wtxid(&Wtxid::from_byte_array(*w))),
        };
        match tx {
            Some(tx) => txs.push(tx),
            None => missing.push(pos),
        }
    }
    if !missing.is_empty() {
        missing.extend(provided);
        missing.sort_unstable();
        return Ok(Verdict::Missing(missing));
    }
    let mut leaves = Vec::with_capacity(1 + txs.len());
    leaves.push(coinbase.compute_txid().to_byte_array());
    leaves.extend(txs.iter().map(|tx| tx.compute_txid().to_byte_array()));
    let header = block::Header {
        version: block::Version::from_consensus(p.version as i32),
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
    // value, scripts; no PoW), on the blocking pool. A JDS sends one per
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

/// §4.1: `coinbase_tx_prefix` ends inside the scriptSig and
/// `coinbase_tx_suffix` starts at nSequence, so the extranonce is the
/// scriptSig length the prefix declares minus the scriptSig bytes it
/// carries. `None`: not one input, a length outside the coinbase bounds
/// (2..=100), or fewer bytes declared than present.
fn extranonce_len(prefix: &[u8]) -> Option<usize> {
    let mut at = 4;
    // BIP144: a zero where the input count would be, then flag 1.
    if prefix.get(4..6) == Some(&[0u8, 1][..]) {
        at += 2;
    }
    let (inputs, n) = compact_size(prefix.get(at..)?)?;
    if inputs != 1 {
        return None;
    }
    at += n + 36;
    let (len, n) = compact_size(prefix.get(at..)?)?;
    at += n;
    if !(2..=100).contains(&len) {
        return None;
    }
    (len as usize).checked_sub(prefix.len() - at)
}

fn compact_size(bytes: &[u8]) -> Option<(u64, usize)> {
    let (v, n) = deserialize_partial::<VarInt>(bytes).ok()?;
    Some((v.0, n))
}

#[cfg(test)]
mod tests {
    use super::extranonce_len;

    fn prefix(segwit: bool, inputs: u8, len: u8, present: usize) -> Vec<u8> {
        let mut p = vec![2, 0, 0, 0];
        if segwit {
            p.extend([0, 1]);
        }
        p.push(inputs);
        p.extend([0; 32]);
        p.extend([0xff; 4]);
        p.push(len);
        p.resize(p.len() + present, 0x51);
        p
    }

    #[test]
    fn extranonce_is_the_declared_script_sig_length_past_the_prefix() {
        assert_eq!(extranonce_len(&prefix(false, 1, 11, 3)), Some(8));
        assert_eq!(extranonce_len(&prefix(true, 1, 11, 3)), Some(8));
        assert_eq!(extranonce_len(&prefix(true, 1, 3, 3)), Some(0));
        assert_eq!(extranonce_len(&prefix(true, 1, 100, 0)), Some(100));
        assert_eq!(extranonce_len(&prefix(true, 2, 11, 3)), None, "two inputs");
        assert_eq!(
            extranonce_len(&prefix(true, 1, 2, 3)),
            None,
            "shorter than present"
        );
        assert_eq!(
            extranonce_len(&prefix(true, 1, 101, 0)),
            None,
            "over the coinbase max"
        );
        assert_eq!(
            extranonce_len(&prefix(true, 1, 1, 0)),
            None,
            "under the coinbase min"
        );
        assert_eq!(
            extranonce_len(&prefix(true, 1, 11, 3)[..40]),
            None,
            "truncated"
        );
        assert_eq!(extranonce_len(&[]), None);
    }
}
