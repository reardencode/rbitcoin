//! Custom job validation for a Job Declarator Server
//! (docs/sv2-job-validation.md §4): resolve the declared wtxids, check the
//! job as a block proposal on the tip, and shape it for retention.

use crate::messages::ProposeTemplate;
use crate::template::{self, Job};
use bitcoin::consensus::encode::{deserialize_partial, VarInt};
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

/// `None`: the payload is not a `ProposeTemplate`.
pub(crate) fn decode(payload: &mut [u8]) -> Option<ProposeTemplate<'_>> {
    binary_sv2::from_bytes(payload).ok()
}

/// §4.1 and §4.4: the draft's own codes, before any mempool lookup or
/// transaction decode, so a 32-byte wtxid is never amplified into a copy or
/// an allocation the job did not declare. `Ok` is the supplied txs keyed by
/// the wtxid of their bytes as sent; `Err` is the `Error.error_code`. No
/// chain read, so the session runs it on arrival; [`validate`] runs it
/// again and stays complete on its own.
pub(crate) fn precheck<'m>(
    m: &'m ProposeTemplate<'_>,
) -> Result<HashMap<[u8; 32], &'m [u8]>, &'static str> {
    let mut declared = HashSet::with_capacity(m.wtxid_list.len());
    for w in m.wtxid_list.iter() {
        if !declared.insert(w.as_ref()) {
            return Err("duplicate-wtxid");
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
        return Err("bad-missing-tx");
    }
    Ok(supplied)
}

/// Reads the store and the mempool: blocking region only. `payload` was
/// [`decode`]d once already; a second failure is a broken invariant.
pub(crate) fn validate(chain: &ChainHub, mut payload: Vec<u8>) -> io::Result<(u32, Verdict)> {
    let m = decode(&mut payload).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sv2: ProposeTemplate stopped decoding",
        )
    })?;
    Ok((m.request_id, check(chain, &m)?))
}

/// §4.1 and §4.4 in order: the gate, [`precheck`] again, the coinbase,
/// the resolution, then the proposal check.
fn check(chain: &ChainHub, m: &ProposeTemplate) -> io::Result<Verdict> {
    let rejected = |code: &str| Ok(Verdict::Rejected(code.into()));
    // Same gate as the templates: a stale tip validates nothing.
    if chain.in_ibd() {
        return rejected("job-validation-unavailable");
    }
    let next = template::next_header(chain)?;
    let supplied = match precheck(m) {
        Ok(supplied) => supplied,
        Err(code) => return rejected(code),
    };
    let Some(extranonce) = extranonce_len(m.coinbase_tx_prefix.as_ref()) else {
        return rejected("bad-cb-decode");
    };
    let zeros = vec![0u8; extranonce];
    let raw = [
        m.coinbase_tx_prefix.as_ref(),
        &zeros[..],
        m.coinbase_tx_suffix.as_ref(),
    ]
    .concat();
    let Ok(coinbase) = bitcoin::consensus::deserialize::<Transaction>(&raw) else {
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
