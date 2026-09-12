//! One-pass txid/wtxid/weight + BIP143/BIP341 common hashes (Core
//! `PrecomputedTransactionData` shape).
//!
//! Structure and scripts share this. Spent amounts/scripts are filled later
//! via [`TxPrecompute::finish_spent`] when prevouts exist.

use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::{Transaction, TxOut};
use rbitcoin_primitives::script_sigop_count;
use std::collections::HashSet;
use std::sync::Arc;

/// Job-local hash cache: this tx's ids plus Core-style common midstates.
#[derive(Clone, Debug)]
pub struct TxPrecompute {
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub base_size: usize,
    pub total_size: usize,
    pub sigops: u64,
    pub out_sum: u64,
    /// BIP144 serialization (`uses_segwit_serialization`).
    pub has_witness: bool,
    /// Single SHA256 of all outpoints (BIP341 / rust-bitcoin `CommonCache`).
    /// `None` after [`Self::from_tx_connect`] (scripts skipped).
    pub sha_prevouts: Option<[u8; 32]>,
    pub sha_sequences: Option<[u8; 32]>,
    pub sha_outputs: Option<[u8; 32]>,
    /// Single SHA256 of spent amounts / scriptPubKeys (after [`Self::finish_spent`]).
    pub sha_amounts: Option<[u8; 32]>,
    pub sha_scriptpubkeys: Option<[u8; 32]>,
}

impl TxPrecompute {
    /// One walk of `tx` including BIP143/341 midstates. Does not hash spent prevouts.
    pub fn from_tx(tx: &Transaction) -> Self {
        Self::from_tx_inner(tx, true)
    }

    /// Ids, sizes, sigops, `out_sum` — no sighash midstates (scripts skipped).
    pub fn from_tx_connect(tx: &Transaction) -> Self {
        Self::from_tx_inner(tx, false)
    }

    fn from_tx_inner(tx: &Transaction, sighash: bool) -> Self {
        let has_witness = uses_segwit_serialization(tx);

        let mut txid_eng = sha256d::Hash::engine();
        let mut wtxid_eng = sha256d::Hash::engine();
        let mut sha_prev = sighash.then(sha256::Hash::engine);
        let mut sha_seq = sighash.then(sha256::Hash::engine);
        let mut sha_out = sighash.then(sha256::Hash::engine);
        let mut base_size = 0usize;
        let mut total_size = 0usize;
        let mut sigops = 0u64;
        let mut out_sum = 0u64;

        base_size += enc(&mut txid_eng, &tx.version);
        total_size += enc(&mut wtxid_eng, &tx.version);
        if has_witness {
            total_size += enc(&mut wtxid_eng, &0u8);
            total_size += enc(&mut wtxid_eng, &1u8);
        }

        let n_in = VarInt(tx.input.len() as u64);
        base_size += enc(&mut txid_eng, &n_in);
        total_size += enc(&mut wtxid_eng, &n_in);
        for txin in &tx.input {
            base_size += enc(&mut txid_eng, &txin.previous_output);
            total_size += enc(&mut wtxid_eng, &txin.previous_output);
            if let Some(ref mut e) = sha_prev {
                let _ = txin.previous_output.consensus_encode(e);
            }

            base_size += enc(&mut txid_eng, &txin.script_sig);
            total_size += enc(&mut wtxid_eng, &txin.script_sig);
            sigops = sigops.saturating_add(script_sigop_count(txin.script_sig.as_bytes(), false));

            base_size += enc(&mut txid_eng, &txin.sequence);
            total_size += enc(&mut wtxid_eng, &txin.sequence);
            if let Some(ref mut e) = sha_seq {
                let _ = txin.sequence.consensus_encode(e);
            }
        }

        let n_out = VarInt(tx.output.len() as u64);
        base_size += enc(&mut txid_eng, &n_out);
        total_size += enc(&mut wtxid_eng, &n_out);
        for txout in &tx.output {
            base_size += enc(&mut txid_eng, txout);
            total_size += enc(&mut wtxid_eng, txout);
            if let Some(ref mut e) = sha_out {
                let _ = txout.consensus_encode(e);
            }
            sigops =
                sigops.saturating_add(script_sigop_count(txout.script_pubkey.as_bytes(), false));
            let v = txout.value.to_sat();
            out_sum = out_sum.saturating_add(v);
        }

        if has_witness {
            for txin in &tx.input {
                total_size += enc(&mut wtxid_eng, &txin.witness);
            }
        }

        base_size += enc(&mut txid_eng, &tx.lock_time);
        total_size += enc(&mut wtxid_eng, &tx.lock_time);

        Self {
            txid: sha256d::Hash::from_engine(txid_eng).to_byte_array(),
            wtxid: sha256d::Hash::from_engine(wtxid_eng).to_byte_array(),
            base_size,
            total_size,
            sigops,
            out_sum,
            has_witness,
            sha_prevouts: sha_prev.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_sequences: sha_seq.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_outputs: sha_out.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_amounts: None,
            sha_scriptpubkeys: None,
        }
    }

    /// BIP143 `hashPrevouts` = SHA256(sha_prevouts). `None` after [`Self::from_tx_connect`].
    pub fn hash_prevouts(&self) -> Option<[u8; 32]> {
        self.sha_prevouts.as_ref().map(sha256_again)
    }

    pub fn hash_sequence(&self) -> Option<[u8; 32]> {
        self.sha_sequences.as_ref().map(sha256_again)
    }

    pub fn hash_outputs(&self) -> Option<[u8; 32]> {
        self.sha_outputs.as_ref().map(sha256_again)
    }

    pub fn weight_wu(&self) -> u64 {
        (self
            .base_size
            .saturating_mul(3)
            .saturating_add(self.total_size)) as u64
    }

    /// BIP143/341 common hashes on a [`Self::from_tx_connect`] row (no txid walk).
    pub fn fill_sighash_midstates(&mut self, tx: &Transaction) {
        if self.sha_prevouts.is_some() {
            return;
        }
        let mut sha_prev = sha256::Hash::engine();
        let mut sha_seq = sha256::Hash::engine();
        let mut sha_out = sha256::Hash::engine();
        for txin in &tx.input {
            let _ = txin.previous_output.consensus_encode(&mut sha_prev);
            let _ = txin.sequence.consensus_encode(&mut sha_seq);
        }
        for txout in &tx.output {
            let _ = txout.consensus_encode(&mut sha_out);
        }
        self.sha_prevouts = Some(sha256::Hash::from_engine(sha_prev).to_byte_array());
        self.sha_sequences = Some(sha256::Hash::from_engine(sha_seq).to_byte_array());
        self.sha_outputs = Some(sha256::Hash::from_engine(sha_out).to_byte_array());
    }

    /// BIP341 spent midstates. Call when `prevouts.len() == tx.input.len()`.
    pub fn finish_spent(&mut self, prevouts: &[TxOut]) {
        let mut enc_amt = sha256::Hash::engine();
        let mut enc_spk = sha256::Hash::engine();
        for prev in prevouts {
            let _ = prev.value.consensus_encode(&mut enc_amt);
            let _ = prev.script_pubkey.consensus_encode(&mut enc_spk);
        }
        self.sha_amounts = Some(sha256::Hash::from_engine(enc_amt).to_byte_array());
        self.sha_scriptpubkeys = Some(sha256::Hash::from_engine(enc_spk).to_byte_array());
    }
}

/// Tip-follow precompute: `from_tx_connect` for live mempool txs, fill midstates otherwise.
///
/// `live_empty` is the no-mempool / empty-graph path — all `from_tx`, no probe.
pub fn pres_for_tip(
    txs: &[Transaction],
    live_empty: bool,
    is_live: impl Fn([u8; 32]) -> bool,
) -> (Arc<[TxPrecompute]>, HashSet<[u8; 32]>) {
    if live_empty {
        let v: Vec<TxPrecompute> = txs.iter().map(TxPrecompute::from_tx).collect();
        return (Arc::from(v), HashSet::new());
    }
    let mut skip = HashSet::new();
    let mut v = Vec::with_capacity(txs.len());
    for tx in txs {
        let mut c = TxPrecompute::from_tx_connect(tx);
        if is_live(c.txid) {
            skip.insert(c.txid);
        } else {
            c.fill_sighash_midstates(tx);
        }
        v.push(c);
    }
    (Arc::from(v), skip)
}

fn enc(w: &mut impl bitcoin::io::Write, v: &impl Encodable) -> usize {
    v.consensus_encode(w).expect("hash engines do not error")
}

fn sha256_again(single: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::from_byte_array(*single)
        .hash_again()
        .to_byte_array()
}

/// rust-bitcoin `Transaction::uses_segwit_serialization` (private).
fn uses_segwit_serialization(tx: &Transaction) -> bool {
    if tx.input.iter().any(|i| !i.witness.is_empty()) {
        return true;
    }
    tx.input.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, Witness};

    fn oracle_sha_prevouts(tx: &Transaction) -> [u8; 32] {
        let mut e = sha256::Hash::engine();
        for i in &tx.input {
            i.previous_output.consensus_encode(&mut e).unwrap();
        }
        sha256::Hash::from_engine(e).to_byte_array()
    }

    fn oracle_sha_sequences(tx: &Transaction) -> [u8; 32] {
        let mut e = sha256::Hash::engine();
        for i in &tx.input {
            i.sequence.consensus_encode(&mut e).unwrap();
        }
        sha256::Hash::from_engine(e).to_byte_array()
    }

    fn oracle_sha_outputs(tx: &Transaction) -> [u8; 32] {
        let mut e = sha256::Hash::engine();
        for o in &tx.output {
            o.consensus_encode(&mut e).unwrap();
        }
        sha256::Hash::from_engine(e).to_byte_array()
    }

    fn oracle_sigops(tx: &Transaction) -> u64 {
        let mut n = 0u64;
        for inp in &tx.input {
            n = n.saturating_add(script_sigop_count(inp.script_sig.as_bytes(), false));
        }
        for out in &tx.output {
            n = n.saturating_add(script_sigop_count(out.script_pubkey.as_bytes(), false));
        }
        n
    }

    fn assert_matches_rust_bitcoin(tx: &Transaction) {
        let p = TxPrecompute::from_tx(tx);
        assert_eq!(p.txid, tx.compute_txid().to_byte_array(), "txid");
        assert_eq!(p.wtxid, tx.compute_wtxid().to_byte_array(), "wtxid");
        assert_eq!(p.base_size, tx.base_size(), "base_size");
        assert_eq!(p.total_size, tx.total_size(), "total_size");
        assert_eq!(p.weight_wu(), tx.weight().to_wu(), "weight");
        assert_eq!(p.sigops, oracle_sigops(tx), "sigops");
        assert_eq!(
            p.sha_prevouts,
            Some(oracle_sha_prevouts(tx)),
            "sha_prevouts"
        );
        assert_eq!(
            p.sha_sequences,
            Some(oracle_sha_sequences(tx)),
            "sha_sequences"
        );
        assert_eq!(p.sha_outputs, Some(oracle_sha_outputs(tx)), "sha_outputs");
        assert_eq!(
            p.hash_prevouts(),
            Some(
                sha256::Hash::from_byte_array(p.sha_prevouts.unwrap())
                    .hash_again()
                    .to_byte_array()
            )
        );
    }

    fn assert_connect_matches_ids(tx: &Transaction) {
        let full = TxPrecompute::from_tx(tx);
        let c = TxPrecompute::from_tx_connect(tx);
        assert_eq!(c.txid, full.txid, "txid");
        assert_eq!(c.wtxid, full.wtxid, "wtxid");
        assert_eq!(c.base_size, full.base_size, "base_size");
        assert_eq!(c.total_size, full.total_size, "total_size");
        assert_eq!(c.weight_wu(), full.weight_wu(), "weight");
        assert_eq!(c.sigops, full.sigops, "sigops");
        assert_eq!(c.out_sum, full.out_sum, "out_sum");
        assert_eq!(c.has_witness, full.has_witness, "has_witness");
        assert_eq!(c.sha_prevouts, None);
        assert_eq!(c.sha_sequences, None);
        assert_eq!(c.sha_outputs, None);
        assert_eq!(c.hash_prevouts(), None);
        assert_eq!(c.hash_sequence(), None);
        assert_eq!(c.hash_outputs(), None);
    }

    fn legacy_1in() -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x51]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn p2wpkh_like() -> Transaction {
        let mut tx = legacy_1in();
        tx.input[0].script_sig = ScriptBuf::new();
        tx.input[0].witness = Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]);
        tx
    }

    #[test]
    fn tx_precompute_matches_legacy() {
        assert_matches_rust_bitcoin(&legacy_1in());
    }

    #[test]
    fn tx_precompute_matches_p2wpkh_witness() {
        assert_matches_rust_bitcoin(&p2wpkh_like());
    }

    #[test]
    fn tx_precompute_matches_zero_input_bip144() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert_matches_rust_bitcoin(&tx);
        assert!(TxPrecompute::from_tx(&tx).has_witness);
    }

    #[test]
    fn from_tx_connect_omits_sighash_midstates() {
        assert_connect_matches_ids(&legacy_1in());
        assert_connect_matches_ids(&p2wpkh_like());
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert_connect_matches_ids(&tx);
        assert_eq!(
            TxPrecompute::from_tx_connect(&tx).wtxid,
            tx.compute_wtxid().to_byte_array()
        );
    }

    #[test]
    fn pres_for_tip_connects_live_and_hashes_the_rest() {
        let live = p2wpkh_like();
        let other = legacy_1in();
        let live_id = live.compute_txid().to_byte_array();
        let (pres, skip) =
            super::pres_for_tip(&[live.clone(), other.clone()], false, |tid| tid == live_id);
        assert_eq!(pres.len(), 2);
        assert_eq!(pres[0].txid, live_id);
        assert_eq!(
            pres[0].sha_prevouts, None,
            "live tx must skip sighash midstates"
        );
        assert_eq!(
            pres[1].sha_prevouts,
            Some(oracle_sha_prevouts(&other)),
            "non-live must keep midstates"
        );
        assert_eq!(skip.len(), 1);
        assert!(skip.contains(&live_id));
    }

    #[test]
    fn pres_for_tip_empty_live_set_uses_from_tx() {
        let tx = p2wpkh_like();
        let (pres, skip) = super::pres_for_tip(std::slice::from_ref(&tx), true, |_| {
            panic!("empty live-set must not probe")
        });
        assert!(skip.is_empty());
        assert_eq!(pres[0].sha_prevouts, Some(oracle_sha_prevouts(&tx)));
    }

    #[test]
    fn fill_sighash_midstates_matches_from_tx() {
        let tx = p2wpkh_like();
        let mut c = TxPrecompute::from_tx_connect(&tx);
        assert!(c.sha_prevouts.is_none());
        c.fill_sighash_midstates(&tx);
        let full = TxPrecompute::from_tx(&tx);
        assert_eq!(c.txid, full.txid);
        assert_eq!(c.wtxid, full.wtxid);
        assert_eq!(c.sha_prevouts, full.sha_prevouts);
        assert_eq!(c.sha_sequences, full.sha_sequences);
        assert_eq!(c.sha_outputs, full.sha_outputs);
        c.fill_sighash_midstates(&tx);
        assert_eq!(c.sha_prevouts, full.sha_prevouts);
    }

    #[test]
    fn tx_precompute_finish_spent_matches_amount_spk_walk() {
        let tx = p2wpkh_like();
        let prev = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(
                vec![0x00, 0x14].into_iter().chain([0xab; 20]).collect(),
            ),
        };
        let mut p = TxPrecompute::from_tx(&tx);
        p.finish_spent(std::slice::from_ref(&prev));
        let mut ea = sha256::Hash::engine();
        let mut es = sha256::Hash::engine();
        prev.value.consensus_encode(&mut ea).unwrap();
        prev.script_pubkey.consensus_encode(&mut es).unwrap();
        assert_eq!(
            p.sha_amounts,
            Some(sha256::Hash::from_engine(ea).to_byte_array())
        );
        assert_eq!(
            p.sha_scriptpubkeys,
            Some(sha256::Hash::from_engine(es).to_byte_array())
        );
    }
}
