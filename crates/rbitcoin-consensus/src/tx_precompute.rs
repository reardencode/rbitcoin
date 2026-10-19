//! One-pass txid/wtxid/weight + BIP143/BIP341 common hashes (Core
//! `PrecomputedTransactionData` shape).
//!
//! Structure and scripts share this. Spent amounts/scripts are filled later
//! via [`TxPrecompute::finish_spent`] or [`TxPrecompute::finish_spent_parts`]
//! when prevouts exist.

use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use bitcoin::{Script, Transaction, TxOut};
use rbitcoin_primitives::script_sigop_count;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;

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
    /// BIP143 double-SHA of [`Self::sha_prevouts`], filled on first use.
    prevouts_d: OnceLock<[u8; 32]>,
    sequences_d: OnceLock<[u8; 32]>,
    outputs_d: OnceLock<[u8; 32]>,
}

impl TxPrecompute {
    /// One walk of `tx` including BIP143/341 midstates. Does not hash spent prevouts.
    // btc-lean: BLK-006 SWT-041 TXV-018
    pub fn from_tx(tx: &Transaction) -> Self {
        Self::from_tx_inner(tx, true)
    }

    /// Ids, sizes, sigops, `out_sum` — no sighash midstates (scripts skipped).
    pub fn from_tx_connect(tx: &Transaction) -> Self {
        Self::from_tx_inner(tx, false)
    }

    /// Ids from the **wire slice** (wtxid = `sha256d(wire)`). A witness txid is
    /// SHA256d of `version || vin || vout || locktime` on that slice. Legacy
    /// and the 10-byte flag-zero tx hash the whole slice once.
    ///
    /// `None` when `wire` is not that tx's encoding. `sighash` still fills
    /// BIP143/341 midstates like [`Self::from_tx`].
    pub fn from_tx_wire(tx: &Transaction, wire: &[u8], sighash: bool) -> Option<Self> {
        let has_witness = uses_segwit_serialization(tx);
        let wtxid = sha256d::Hash::hash(wire).to_byte_array();
        let (txid, base_size, [sha_prevouts, sha_sequences, sha_outputs]) =
            if has_witness && !flag_zero_tx(tx, wire) {
                let spans = witness_wire(tx, wire)?;
                if sighash {
                    let (txid, mids) = hash_wire_sighash(tx, &spans)?;
                    (txid, spans.base_len(), mids)
                } else {
                    (
                        hash_witness_txid(&spans),
                        spans.base_len(),
                        [None, None, None],
                    )
                }
            } else if sighash {
                let spans = legacy_spans(tx, wire)?;
                let (txid, mids) = hash_wire_sighash(tx, &spans)?;
                if txid != wtxid {
                    return None;
                }
                (txid, wire.len(), mids)
            } else {
                (wtxid, wire.len(), [None, None, None])
            };
        let (sigops, out_sum) = sigops_and_out_sum(tx);
        Some(Self {
            txid,
            wtxid,
            base_size,
            total_size: wire.len(),
            sigops,
            out_sum,
            has_witness,
            sha_prevouts,
            sha_sequences,
            sha_outputs,
            sha_amounts: None,
            sha_scriptpubkeys: None,
            prevouts_d: OnceLock::new(),
            sequences_d: OnceLock::new(),
            outputs_d: OnceLock::new(),
        })
    }

    // btc-lean: SWT-068
    fn from_tx_inner(tx: &Transaction, sighash: bool) -> Self {
        let has_witness = uses_segwit_serialization(tx);
        if !has_witness {
            return Self::from_tx_legacy_one_engine(tx, sighash);
        }

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
        // btc-lean: SWT-037 SWT-038 SWT-039 SWT-040
        total_size += enc(&mut wtxid_eng, &0u8);
        total_size += enc(&mut wtxid_eng, &1u8);

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

        for txin in &tx.input {
            total_size += enc(&mut wtxid_eng, &txin.witness);
        }

        base_size += enc(&mut txid_eng, &tx.lock_time);
        total_size += enc(&mut wtxid_eng, &tx.lock_time);

        Self {
            // btc-lean: BLK-005 TXV-017
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
            prevouts_d: OnceLock::new(),
            sequences_d: OnceLock::new(),
            outputs_d: OnceLock::new(),
        }
    }

    /// Non-witness tx: stripped == wire, so one SHA256d engine (wtxid = txid).
    fn from_tx_legacy_one_engine(tx: &Transaction, sighash: bool) -> Self {
        let mut eng = sha256d::Hash::engine();
        let mut sha_prev = sighash.then(sha256::Hash::engine);
        let mut sha_seq = sighash.then(sha256::Hash::engine);
        let mut sha_out = sighash.then(sha256::Hash::engine);
        let mut base_size = 0usize;
        let mut sigops = 0u64;
        let mut out_sum = 0u64;

        base_size += enc(&mut eng, &tx.version);
        let n_in = VarInt(tx.input.len() as u64);
        base_size += enc(&mut eng, &n_in);
        for txin in &tx.input {
            base_size += enc(&mut eng, &txin.previous_output);
            if let Some(ref mut e) = sha_prev {
                let _ = txin.previous_output.consensus_encode(e);
            }
            base_size += enc(&mut eng, &txin.script_sig);
            sigops = sigops.saturating_add(script_sigop_count(txin.script_sig.as_bytes(), false));
            base_size += enc(&mut eng, &txin.sequence);
            if let Some(ref mut e) = sha_seq {
                let _ = txin.sequence.consensus_encode(e);
            }
        }
        let n_out = VarInt(tx.output.len() as u64);
        base_size += enc(&mut eng, &n_out);
        for txout in &tx.output {
            base_size += enc(&mut eng, txout);
            if let Some(ref mut e) = sha_out {
                let _ = txout.consensus_encode(e);
            }
            sigops =
                sigops.saturating_add(script_sigop_count(txout.script_pubkey.as_bytes(), false));
            out_sum = out_sum.saturating_add(txout.value.to_sat());
        }
        base_size += enc(&mut eng, &tx.lock_time);
        let txid = sha256d::Hash::from_engine(eng).to_byte_array();
        Self {
            txid,
            wtxid: txid,
            base_size,
            total_size: base_size,
            sigops,
            out_sum,
            has_witness: false,
            sha_prevouts: sha_prev.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_sequences: sha_seq.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_outputs: sha_out.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_amounts: None,
            sha_scriptpubkeys: None,
            prevouts_d: OnceLock::new(),
            sequences_d: OnceLock::new(),
            outputs_d: OnceLock::new(),
        }
    }

    /// BIP143 `hashPrevouts` = SHA256(sha_prevouts). `None` after [`Self::from_tx_connect`].
    ///
    /// The second compression is cached. Ten CHECKSIGs share one block.
    pub fn hash_prevouts(&self) -> Option<[u8; 32]> {
        let single = self.sha_prevouts?;
        Some(*self.prevouts_d.get_or_init(|| sha256_again(&single)))
    }

    pub fn hash_sequence(&self) -> Option<[u8; 32]> {
        let single = self.sha_sequences?;
        Some(*self.sequences_d.get_or_init(|| sha256_again(&single)))
    }

    pub fn hash_outputs(&self) -> Option<[u8; 32]> {
        let single = self.sha_outputs?;
        Some(*self.outputs_d.get_or_init(|| sha256_again(&single)))
    }

    // btc-lean: SWT-019 SWT-020 SWT-067 TXV-019
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
        let [sha_prevouts, sha_sequences, sha_outputs] = sighash_midstates(tx);
        self.sha_prevouts = sha_prevouts;
        self.sha_sequences = sha_sequences;
        self.sha_outputs = sha_outputs;
    }

    /// BIP341 spent midstates. Call when `prevouts.len() == tx.input.len()`.
    pub fn finish_spent(&mut self, prevouts: &[TxOut]) {
        let _ = self.finish_spent_parts(prevouts.len(), |i| {
            let prev = prevouts.get(i)?;
            Some((prev.value.to_sat() as i64, prev.script_pubkey.as_bytes()))
        });
    }

    /// BIP341 spent midstates from borrowed amount and script bytes.
    ///
    /// `parts` is called once per input index. `false` means a prevout was
    /// missing; the midstates are left unset.
    pub fn finish_spent_parts<'a>(
        &mut self,
        n: usize,
        mut parts: impl FnMut(usize) -> Option<(i64, &'a [u8])>,
    ) -> bool {
        let mut enc_amt = sha256::Hash::engine();
        let mut enc_spk = sha256::Hash::engine();
        for i in 0..n {
            let Some((value, script)) = parts(i) else {
                return false;
            };
            let _ = (value as u64).consensus_encode(&mut enc_amt);
            let _ = Script::from_bytes(script).consensus_encode(&mut enc_spk);
        }
        self.sha_amounts = Some(sha256::Hash::from_engine(enc_amt).to_byte_array());
        self.sha_scriptpubkeys = Some(sha256::Hash::from_engine(enc_spk).to_byte_array());
        true
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

/// BIP144 non-witness slices. `None` unless `wire` is `version || 00 01 || vin || vout || witness || locktime`.
struct WitnessWire<'a> {
    version: &'a [u8],
    vin: &'a [u8],
    vout: &'a [u8],
    locktime: &'a [u8],
}

impl WitnessWire<'_> {
    fn base_len(&self) -> usize {
        self.version.len() + self.vin.len() + self.vout.len() + self.locktime.len()
    }
}

fn flag_zero_wire(wire: &[u8]) -> bool {
    wire.len() == FLAG_ZERO_TX_LEN && wire.get(4..6) == Some(&[0, 0])
}

/// Core's flag-0 10-byte tx: empty vin and vout, not a BIP144 marker.
fn flag_zero_tx(tx: &Transaction, wire: &[u8]) -> bool {
    flag_zero_wire(wire) && tx.input.is_empty() && tx.output.is_empty()
}

fn witness_wire<'a>(tx: &Transaction, wire: &'a [u8]) -> Option<WitnessWire<'a>> {
    if !uses_segwit_serialization(tx) || flag_zero_wire(wire) {
        return None;
    }
    if wire.get(4..6) != Some(&[0, 1]) {
        return None;
    }
    let vin_len = VarInt(tx.input.len() as u64).size()
        + tx.input
            .iter()
            .map(|input| input.base_size())
            .sum::<usize>();
    let vout_len = VarInt(tx.output.len() as u64).size()
        + tx.output.iter().map(|output| output.size()).sum::<usize>();
    let wit_len = tx
        .input
        .iter()
        .map(|input| input.witness.size())
        .sum::<usize>();
    let vin_end = 6usize.checked_add(vin_len)?;
    let vout_end = vin_end.checked_add(vout_len)?;
    let lock_at = vout_end.checked_add(wit_len)?;
    if lock_at.checked_add(4)? != wire.len() {
        return None;
    }
    Some(WitnessWire {
        version: wire.get(..4)?,
        vin: wire.get(6..vin_end)?,
        vout: wire.get(vin_end..vout_end)?,
        locktime: wire.get(lock_at..)?,
    })
}

fn hash_witness_txid(spans: &WitnessWire<'_>) -> [u8; 32] {
    let mut eng = sha256d::Hash::engine();
    eng.input(spans.version);
    eng.input(spans.vin);
    eng.input(spans.vout);
    eng.input(spans.locktime);
    sha256d::Hash::from_engine(eng).to_byte_array()
}

/// Legacy layout: `version || vin || vout || locktime` covering all of `wire`.
fn legacy_spans<'a>(tx: &Transaction, wire: &'a [u8]) -> Option<WitnessWire<'a>> {
    if uses_segwit_serialization(tx) && !flag_zero_tx(tx, wire) {
        return None;
    }
    let vin_len = VarInt(tx.input.len() as u64).size()
        + tx.input
            .iter()
            .map(|input| input.base_size())
            .sum::<usize>();
    let vout_len = VarInt(tx.output.len() as u64).size()
        + tx.output.iter().map(|output| output.size()).sum::<usize>();
    let vin_end = 4usize.checked_add(vin_len)?;
    let vout_end = vin_end.checked_add(vout_len)?;
    if vout_end.checked_add(4)? != wire.len() {
        return None;
    }
    Some(WitnessWire {
        version: wire.get(..4)?,
        vin: wire.get(4..vin_end)?,
        vout: wire.get(vin_end..vout_end)?,
        locktime: wire.get(vout_end..)?,
    })
}

/// Outpoint is 32-byte txid + 4-byte vout. Sequence is the last 4 bytes of a base input.
const OUTPOINT_LEN: usize = 36;
const SEQUENCE_LEN: usize = 4;

/// Single SHA-256 of prevouts, sequences, and outputs. `None` is the connect
/// path that skipped sighash.
type SighashMidstates = [Option<[u8; 32]>; 3];

/// Txid from the non-witness slices, and BIP143/341 single-SHA midstates from
/// the same bytes. Outpoint is the first 36 bytes of each input; sequence is
/// the last 4. Outputs are the vout slice after the compact-size count.
fn hash_wire_sighash(
    tx: &Transaction,
    spans: &WitnessWire<'_>,
) -> Option<([u8; 32], SighashMidstates)> {
    let mut txid_eng = sha256d::Hash::engine();
    let mut sha_prev = sha256::Hash::engine();
    let mut sha_seq = sha256::Hash::engine();
    let mut sha_out = sha256::Hash::engine();
    txid_eng.input(spans.version);
    let n_in = VarInt(tx.input.len() as u64).size();
    txid_eng.input(spans.vin.get(..n_in)?);
    let mut at = n_in;
    for input in &tx.input {
        let n = input.base_size();
        let body = spans.vin.get(at..at.checked_add(n)?)?;
        if body.len() < OUTPOINT_LEN + SEQUENCE_LEN {
            return None;
        }
        txid_eng.input(body);
        sha_prev.input(&body[..OUTPOINT_LEN]);
        sha_seq.input(&body[body.len() - SEQUENCE_LEN..]);
        at += n;
    }
    if at != spans.vin.len() {
        return None;
    }
    let n_out = VarInt(tx.output.len() as u64).size();
    txid_eng.input(spans.vout.get(..n_out)?);
    let outs = spans.vout.get(n_out..)?;
    txid_eng.input(outs);
    sha_out.input(outs);
    txid_eng.input(spans.locktime);
    Some((
        sha256d::Hash::from_engine(txid_eng).to_byte_array(),
        [
            Some(sha256::Hash::from_engine(sha_prev).to_byte_array()),
            Some(sha256::Hash::from_engine(sha_seq).to_byte_array()),
            Some(sha256::Hash::from_engine(sha_out).to_byte_array()),
        ],
    ))
}

fn sigops_and_out_sum(tx: &Transaction) -> (u64, u64) {
    let mut sigops = 0u64;
    let mut out_sum = 0u64;
    for txin in &tx.input {
        sigops = sigops.saturating_add(script_sigop_count(txin.script_sig.as_bytes(), false));
    }
    for txout in &tx.output {
        sigops = sigops.saturating_add(script_sigop_count(txout.script_pubkey.as_bytes(), false));
        out_sum = out_sum.saturating_add(txout.value.to_sat());
    }
    (sigops, out_sum)
}

fn sighash_midstates(tx: &Transaction) -> SighashMidstates {
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
    [
        Some(sha256::Hash::from_engine(sha_prev).to_byte_array()),
        Some(sha256::Hash::from_engine(sha_seq).to_byte_array()),
        Some(sha256::Hash::from_engine(sha_out).to_byte_array()),
    ]
}

/// A consensus-serialized tx is at least 10 bytes (version, two compact sizes, locktime).
fn block_tx_count_fits(n: usize, remaining: usize) -> bool {
    n <= remaining / 10
}

const FLAG_ZERO_TX_LEN: usize = 10;

/// Core's `UnserializeTransaction` reads an empty vin followed by segwit flag
/// 0 as a tx with no inputs and no outputs, then the locktime. Those 10 bytes
/// are also that tx's legacy encoding, so the txid matches Core. rust-bitcoin
/// refuses flag 0; without this the block never gets Core's invalid verdict.
fn decode_flag_zero_tx(wire: &[u8]) -> Option<Transaction> {
    let w = wire.get(..FLAG_ZERO_TX_LEN)?;
    if w[4..6] != [0, 0] {
        return None;
    }
    let word = |i: usize| [w[i], w[i + 1], w[i + 2], w[i + 3]];
    Some(Transaction {
        version: bitcoin::transaction::Version(i32::from_le_bytes(word(0))),
        lock_time: bitcoin::absolute::LockTime::from_consensus(u32::from_le_bytes(word(6))),
        input: Vec::new(),
        output: Vec::new(),
    })
}

/// Decode a P2P block payload once: rust-bitcoin `Block` plus per-tx pres from
/// each tx's **wire slice** (txid, wtxid, and sighash midstates read those bytes).
///
/// Third value is `from_tx_wire` wall ns (IBD `precompute=`).
pub fn decode_block_precomputes(
    payload: &[u8],
    sighash: bool,
) -> Option<(bitcoin::block::Block, Vec<TxPrecompute>, u64)> {
    use bitcoin::block::Header;
    use bitcoin::consensus::encode::{Decodable, VarInt};
    use std::io::Cursor;
    use std::time::Instant;
    let mut cur = Cursor::new(payload);
    let header = Header::consensus_decode(&mut cur).ok()?;
    let n_raw = VarInt::consensus_decode(&mut cur).ok()?.0;
    let n = usize::try_from(n_raw).ok()?;
    let remaining = payload.len().saturating_sub(cur.position() as usize);
    if !block_tx_count_fits(n, remaining) {
        return None;
    }
    let mut txdata = Vec::with_capacity(n);
    let mut pres = Vec::with_capacity(n);
    let t = Instant::now();
    for _ in 0..n {
        let start = cur.position() as usize;
        let tx = match decode_flag_zero_tx(&payload[start..]) {
            Some(tx) => {
                cur.set_position((start + FLAG_ZERO_TX_LEN) as u64);
                tx
            }
            None => Transaction::consensus_decode(&mut cur).ok()?,
        };
        let end = cur.position() as usize;
        let wire = payload.get(start..end)?;
        pres.push(TxPrecompute::from_tx_wire(&tx, wire, sighash)?);
        txdata.push(tx);
    }
    let hash_ns = t.elapsed().as_nanos() as u64;
    Some((bitcoin::block::Block { header, txdata }, pres, hash_ns))
}

/// Header + tx-count compact size + each precompute's wire length.
///
/// Matches a block payload when every `total_size` is that tx's slice.
pub fn block_wire_len_from_pres(n_tx: usize, pres: &[TxPrecompute]) -> usize {
    80 + VarInt(n_tx as u64).size() + pres.iter().map(|p| p.total_size).sum::<usize>()
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

    /// One empty witness and one non-empty, so the witness section is not a single stack.
    fn two_input_witness() -> Transaction {
        let mut tx = legacy_1in();
        tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                vout: 3,
            },
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x02]),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });
        tx.input[0].script_sig = ScriptBuf::new();
        tx.input[0].witness = Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]);
        tx.output.push(TxOut {
            value: Amount::from_sat(9),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x52]),
        });
        tx
    }

    fn coinbase_witness_nonce() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0xab; 32]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
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

    fn assert_wire_matches_from_tx(tx: &Transaction) {
        use bitcoin::consensus::encode::serialize;
        let raw = serialize(tx);
        let spans = witness_wire(tx, &raw);
        if uses_segwit_serialization(tx) {
            let spans = spans.expect("witness wire spans");
            let base =
                spans.version.len() + spans.vin.len() + spans.vout.len() + spans.locktime.len();
            assert_eq!(base, tx.base_size());
        } else {
            assert!(spans.is_none());
        }
        let w = TxPrecompute::from_tx_wire(tx, &raw, true).expect("spans");
        let full = TxPrecompute::from_tx(tx);
        assert_eq!(w.txid, tx.compute_txid().to_byte_array(), "txid");
        assert_eq!(w.wtxid, sha256d::Hash::hash(&raw).to_byte_array(), "wtxid");
        assert_eq!(w.base_size, tx.base_size(), "base_size");
        assert_eq!(w.total_size, raw.len(), "total_size");
        assert_eq!(w.total_size, tx.total_size());
        assert_eq!(w.txid, full.txid);
        assert_eq!(w.wtxid, full.wtxid);
        assert_eq!(w.sigops, full.sigops, "sigops");
        assert_eq!(w.out_sum, full.out_sum, "out_sum");
        assert_eq!(w.has_witness, full.has_witness, "has_witness");
        assert_eq!(w.sha_prevouts, full.sha_prevouts);
        let c = TxPrecompute::from_tx_wire(tx, &raw, false).expect("spans");
        assert_eq!(c.txid, full.txid);
        assert_eq!(c.wtxid, full.wtxid);
        assert_eq!(c.sha_prevouts, None);
        if !c.has_witness {
            assert_eq!(c.txid, c.wtxid, "legacy wtxid == txid");
        }
    }

    #[test]
    // btc-lean: BLK-003 BLK-005 BLK-006 SWT-020 SWT-037 SWT-038 SWT-039 SWT-040 SWT-041 SWT-067
    // btc-lean: SWT-068 TXV-017 TXV-018 TXV-019
    fn from_tx_wire_matches_from_tx_on_legacy_and_witness() {
        for tx in [
            legacy_1in(),
            p2wpkh_like(),
            two_input_witness(),
            coinbase_witness_nonce(),
        ] {
            assert_wire_matches_from_tx(&tx);
        }
    }

    #[test]
    fn flag_zero_wire_is_one_slice() {
        let raw = [2u8, 0, 0, 0, 0, 0, 7, 0, 0, 0];
        let flag = decode_flag_zero_tx(&raw).expect("flag zero");
        assert!(
            witness_wire(&flag, &raw).is_none(),
            "flag-zero is one slice"
        );
        let w = TxPrecompute::from_tx_wire(&flag, &raw, false).expect("flag zero");
        assert_eq!(w.txid, sha256d::Hash::hash(&raw).to_byte_array());
        assert_eq!(w.wtxid, w.txid);
        assert_eq!(w.base_size, flag.base_size());
        assert_eq!(w.total_size, raw.len());
        assert!(TxPrecompute::from_tx_wire(&p2wpkh_like(), &raw, false).is_none());
    }

    #[test]
    fn sighash_midstates_come_from_wire_spans() {
        use bitcoin::consensus::encode::serialize;
        let tx = two_input_witness();
        let raw = serialize(&tx);
        let spans = witness_wire(&tx, &raw).expect("spans");
        let (txid, mids) = hash_wire_sighash(&tx, &spans).expect("span sighash");
        assert_eq!(txid, tx.compute_txid().to_byte_array());
        assert_eq!(mids[0], Some(oracle_sha_prevouts(&tx)));
        assert_eq!(mids[1], Some(oracle_sha_sequences(&tx)));
        assert_eq!(mids[2], Some(oracle_sha_outputs(&tx)));
        let w = TxPrecompute::from_tx_wire(&tx, &raw, true).expect("wire");
        assert_eq!(w.sha_prevouts, mids[0]);
        assert_eq!(w.sha_sequences, mids[1]);
        assert_eq!(w.sha_outputs, mids[2]);
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for input in &tx.input {
            input
                .previous_output
                .consensus_encode(&mut prevouts)
                .unwrap();
            input.sequence.consensus_encode(&mut sequences).unwrap();
        }
        let mut outputs = Vec::new();
        for output in &tx.output {
            output.consensus_encode(&mut outputs).unwrap();
        }
        assert_eq!(
            w.sha_prevouts.unwrap(),
            sha256::Hash::hash(&prevouts).to_byte_array()
        );
        assert_eq!(
            w.hash_prevouts().unwrap(),
            sha256d::Hash::hash(&prevouts).to_byte_array()
        );
        assert_eq!(w.hash_prevouts(), w.prevouts_d.get().copied());
        assert_eq!(
            w.sha_sequences.unwrap(),
            sha256::Hash::hash(&sequences).to_byte_array()
        );
        assert_eq!(
            w.hash_sequence().unwrap(),
            sha256d::Hash::hash(&sequences).to_byte_array()
        );
        assert_eq!(w.hash_sequence(), w.sequences_d.get().copied());
        assert_eq!(
            w.sha_outputs.unwrap(),
            sha256::Hash::hash(&outputs).to_byte_array()
        );
        assert_eq!(
            w.hash_outputs().unwrap(),
            sha256d::Hash::hash(&outputs).to_byte_array()
        );
        assert_eq!(w.hash_outputs(), w.outputs_d.get().copied());
    }

    #[test]
    fn block_tx_count_fits_uses_ten_byte_floor() {
        assert!(super::block_tx_count_fits(1, 10));
        assert!(super::block_tx_count_fits(0, 0));
        assert!(!super::block_tx_count_fits(2, 15));
        assert!(!super::block_tx_count_fits(1, 9));
    }

    #[test]
    fn decode_block_precomputes_rejects_tx_count_past_payload() {
        // Header plus a u64 tx count. No transaction bytes follow.
        let mut payload = vec![0u8; 80];
        payload.push(0xff);
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(super::decode_block_precomputes(&payload, false).is_none());
    }

    #[test]
    fn decode_block_precomputes_accepts_minimum_serialized_tx() {
        use bitcoin::consensus::encode::serialize;
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let raw_tx = serialize(&tx);
        assert!(
            (10..20).contains(&raw_tx.len()),
            "one tx must sit on the 10-byte floor, got {}",
            raw_tx.len()
        );
        let mut payload = vec![0u8; 80];
        payload.push(1);
        payload.extend_from_slice(&raw_tx);
        let (block, pres, _) =
            super::decode_block_precomputes(&payload, false).expect("one minimum tx");
        assert_eq!(block.txdata.len(), 1);
        assert_eq!(pres.len(), 1);
        assert!(block.txdata[0].input.is_empty());
        assert!(block.txdata[0].output.is_empty());
    }

    /// Core's `UnserializeTransaction` reads an empty vin and flag 0 as a tx
    /// with no inputs and no outputs; the locktime follows.
    const FLAG_ZERO_TX: [u8; 10] = [2, 0, 0, 0, 0x00, 0x00, 7, 0, 0, 0];

    #[test]
    fn flag_zero_tx_decodes_with_core_txid() {
        use bitcoin::consensus::encode::serialize;
        let mut raw = vec![0u8; 80];
        raw.push(3);
        raw.extend_from_slice(&serialize(&legacy_1in()));
        raw.extend_from_slice(&FLAG_ZERO_TX);
        raw.extend_from_slice(&serialize(&legacy_1in()));
        let (block, pres, _) = super::decode_block_precomputes(&raw, false).unwrap();
        let tx = &block.txdata[1];
        assert!(tx.input.is_empty() && tx.output.is_empty());
        assert_eq!(
            (tx.version, tx.lock_time),
            (Version::TWO, LockTime::from_consensus(7))
        );
        let core = sha256d::Hash::hash(&FLAG_ZERO_TX).to_byte_array();
        assert_eq!(pres[1].txid, core);
        assert_eq!(tx.compute_txid().to_byte_array(), core);
        assert_eq!(pres[1].wtxid, core, "no witness: wtxid is the txid");
        assert_eq!(
            pres[2].txid, pres[0].txid,
            "the next tx starts after locktime"
        );
    }

    #[test]
    fn decode_block_precomputes_hashes_payload_slices() {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::Network;
        let genesis = genesis_block(Network::Regtest);
        let raw = serialize(&genesis);
        let (block, pres, _ns) = super::decode_block_precomputes(&raw, false).expect("decode");
        assert_eq!(block.header, genesis.header);
        assert_eq!(pres.len(), genesis.txdata.len());
        let want = TxPrecompute::from_tx_connect(&genesis.txdata[0]);
        assert_eq!(pres[0].txid, want.txid);
        assert_eq!(pres[0].wtxid, want.wtxid);
        assert_eq!(pres[0].sha_prevouts, None);
    }

    /// Queue-depth bytes are header + tx-count + each pres wire length.
    /// A witness tx's `total_size` includes the witness; `base_size` does not.
    #[test]
    fn witness_block_wire_len_matches_payload() {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::Network;
        let mut block = genesis_block(Network::Regtest);
        block.txdata = vec![p2wpkh_like(), legacy_1in()];
        let raw = serialize(&block);
        let (decoded, pres, _) = super::decode_block_precomputes(&raw, false).expect("decode");
        assert!(pres[0].has_witness);
        assert!(pres[0].total_size > pres[0].base_size);
        assert!(!pres[1].has_witness);
        assert_eq!(
            super::block_wire_len_from_pres(decoded.txdata.len(), &pres),
            raw.len()
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
