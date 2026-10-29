//! One-pass txid/wtxid/weight + BIP143/BIP341 common hashes (Core
//! `PrecomputedTransactionData` shape).
//!
//! Structure and scripts share this. Spent amounts/scripts are filled later
//! via [`TxScriptPrecompute::finish_spent`] or [`TxScriptPrecompute::finish_spent_parts`]
//! when prevouts exist.

use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use bitcoin::{Script, Transaction, TxOut};
use rbitcoin_primitives::script_sigop_count;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::OnceLock;

/// Ids, sizes, sigops, and `out_sum`. No sighash midstates.
#[derive(Clone, Debug)]
pub struct TxConnectPrecompute {
    pub txid: [u8; 32],
    pub wtxid: [u8; 32],
    pub base_size: usize,
    pub total_size: usize,
    pub sigops: u64,
    pub out_sum: u64,
    /// BIP144 serialization (`uses_segwit_serialization`).
    pub has_witness: bool,
}

impl TxConnectPrecompute {
    pub fn weight_wu(&self) -> u64 {
        (self
            .base_size
            .saturating_mul(3)
            .saturating_add(self.total_size)) as u64
    }
}

/// Connect facts plus BIP143/BIP341 common midstates. The three arrays are
/// always present. Spent amount and script hashes are filled by
/// [`TxScriptPrecompute::finish_spent`].
#[derive(Clone, Debug)]
pub struct TxScriptPrecompute {
    pub connect: TxConnectPrecompute,
    pub sha_prevouts: [u8; 32],
    pub sha_sequences: [u8; 32],
    pub sha_outputs: [u8; 32],
    /// Single SHA256 of spent amounts / scriptPubKeys (after [`Self::finish_spent`]).
    pub sha_amounts: Option<[u8; 32]>,
    pub sha_scriptpubkeys: Option<[u8; 32]>,
    /// BIP143 double-SHA of [`Self::sha_prevouts`], filled on first use.
    pub prevouts_d: OnceLock<[u8; 32]>,
    pub sequences_d: OnceLock<[u8; 32]>,
    pub outputs_d: OnceLock<[u8; 32]>,
}

impl Deref for TxScriptPrecompute {
    type Target = TxConnectPrecompute;
    fn deref(&self) -> &Self::Target {
        &self.connect
    }
}

/// One block row: connect-only for a live mempool tx, script midstates otherwise.
///
/// The script row is larger because it keeps the three midstates. Boxing it
/// would allocate once per transaction on the confirm pres slice.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TxPrecompute {
    Connect(TxConnectPrecompute),
    Script(TxScriptPrecompute),
}

impl Deref for TxPrecompute {
    type Target = TxConnectPrecompute;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Connect(c) => c,
            Self::Script(s) => &s.connect,
        }
    }
}

impl TxPrecompute {
    pub fn as_script(&self) -> Option<&TxScriptPrecompute> {
        match self {
            Self::Connect(_) => None,
            Self::Script(s) => Some(s),
        }
    }

    pub fn into_connect(self) -> TxConnectPrecompute {
        match self {
            Self::Connect(c) => c,
            Self::Script(s) => s.connect,
        }
    }

    pub fn sha_prevouts(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.sha_prevouts)
    }

    pub fn sha_sequences(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.sha_sequences)
    }

    pub fn sha_outputs(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.sha_outputs)
    }

    pub fn sha_amounts(&self) -> Option<[u8; 32]> {
        self.as_script().and_then(|s| s.sha_amounts)
    }

    pub fn sha_scriptpubkeys(&self) -> Option<[u8; 32]> {
        self.as_script().and_then(|s| s.sha_scriptpubkeys)
    }

    pub fn hash_prevouts(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.hash_prevouts())
    }

    pub fn hash_sequence(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.hash_sequence())
    }

    pub fn hash_outputs(&self) -> Option<[u8; 32]> {
        self.as_script().map(|s| s.hash_outputs())
    }

    pub fn finish_spent(&mut self, prevouts: &[TxOut]) {
        if let Self::Script(s) = self {
            s.finish_spent(prevouts);
        }
    }
}

fn pack_precompute(
    connect: TxConnectPrecompute,
    sha_prevouts: Option<[u8; 32]>,
    sha_sequences: Option<[u8; 32]>,
    sha_outputs: Option<[u8; 32]>,
) -> TxPrecompute {
    match (sha_prevouts, sha_sequences, sha_outputs) {
        (Some(sha_prevouts), Some(sha_sequences), Some(sha_outputs)) => {
            TxPrecompute::Script(TxScriptPrecompute {
                connect,
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
        _ => TxPrecompute::Connect(connect),
    }
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

    /// Ids from the **wire slice** (wtxid = `sha256d(wire)`). A witness txid is
    /// SHA256d of `version || vin || vout || locktime` on that slice. Legacy
    /// and the 10-byte flag-zero tx hash the whole slice once.
    ///
    /// `None` when `wire` is not that tx's encoding. `sighash` fills BIP143/341
    /// midstates only for a non-coinbase segwit transaction.
    pub fn from_tx_wire(tx: &Transaction, wire: &[u8], sighash: bool) -> Option<Self> {
        let has_witness = uses_segwit_serialization(tx);
        let sighash = sighash && has_witness && !tx.is_coinbase();
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
        Some(pack_precompute(
            TxConnectPrecompute {
                txid,
                wtxid,
                base_size,
                total_size: wire.len(),
                sigops,
                out_sum,
                has_witness,
            },
            sha_prevouts,
            sha_sequences,
            sha_outputs,
        ))
    }

    #[doc(hidden)]
    pub fn from_tx_inner(tx: &Transaction, sighash: bool) -> Self {
        let has_witness = uses_segwit_serialization(tx);
        let sighash = sighash && has_witness && !tx.is_coinbase();
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

        pack_precompute(
            TxConnectPrecompute {
                txid: sha256d::Hash::from_engine(txid_eng).to_byte_array(),
                wtxid: sha256d::Hash::from_engine(wtxid_eng).to_byte_array(),
                base_size,
                total_size,
                sigops,
                out_sum,
                has_witness,
            },
            sha_prev.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_seq.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_out.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
        )
    }

    /// Non-witness tx: stripped == wire, so one SHA256d engine (wtxid = txid).
    #[doc(hidden)]
    pub fn from_tx_legacy_one_engine(tx: &Transaction, sighash: bool) -> Self {
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
        pack_precompute(
            TxConnectPrecompute {
                txid,
                wtxid: txid,
                base_size,
                total_size: base_size,
                sigops,
                out_sum,
                has_witness: false,
            },
            sha_prev.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_seq.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
            sha_out.map(|e| sha256::Hash::from_engine(e).to_byte_array()),
        )
    }
}

impl TxScriptPrecompute {
    /// BIP143/341 midstates for a caller that asked for the script row.
    ///
    /// The connect walk omits these for a legacy transaction and a coinbase.
    /// This fills them anyway, including those shapes.
    pub fn from_tx(tx: &Transaction) -> Self {
        Self::from_connect(TxPrecompute::from_tx_connect(tx).into_connect(), tx)
    }

    /// Midstates on an already-walked connect row. Does not rehash the txid.
    pub fn from_connect(connect: TxConnectPrecompute, tx: &Transaction) -> Self {
        let [sha_prevouts, sha_sequences, sha_outputs] = sighash_midstates(tx);
        Self {
            connect,
            sha_prevouts,
            sha_sequences,
            sha_outputs,
            sha_amounts: None,
            sha_scriptpubkeys: None,
            prevouts_d: OnceLock::new(),
            sequences_d: OnceLock::new(),
            outputs_d: OnceLock::new(),
        }
    }

    /// BIP143 `hashPrevouts` = SHA256(sha_prevouts).
    ///
    /// The second compression is cached. Ten CHECKSIGs share one block.
    pub fn hash_prevouts(&self) -> [u8; 32] {
        *self
            .prevouts_d
            .get_or_init(|| sha256_again(&self.sha_prevouts))
    }

    pub fn hash_sequence(&self) -> [u8; 32] {
        *self
            .sequences_d
            .get_or_init(|| sha256_again(&self.sha_sequences))
    }

    pub fn hash_outputs(&self) -> [u8; 32] {
        *self
            .outputs_d
            .get_or_init(|| sha256_again(&self.sha_outputs))
    }

    /// BIP341 spent midstates. Call when `prevouts.len() == tx.input.len()`.
    pub fn finish_spent(&mut self, prevouts: &[TxOut]) {
        let _ =
            self.finish_spent_parts((0..prevouts.len()).map(crate::block::InputIndex::at), |i| {
                let prev = prevouts.get(i.get())?;
                Some((prev.value.to_sat() as i64, prev.script_pubkey.as_bytes()))
            });
    }

    /// BIP341 spent midstates from borrowed amount and script bytes.
    ///
    /// `parts` is called once per input. `false` means a prevout was missing;
    /// the midstates are left unset.
    pub fn finish_spent_parts<'a>(
        &mut self,
        inputs: impl IntoIterator<Item = crate::block::InputIndex>,
        mut parts: impl FnMut(crate::block::InputIndex) -> Option<(i64, &'a [u8])>,
    ) -> bool {
        let mut enc_amt = sha256::Hash::engine();
        let mut enc_spk = sha256::Hash::engine();
        for i in inputs {
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
        let c = TxPrecompute::from_tx_connect(tx);
        if is_live(c.txid) {
            skip.insert(c.txid);
            v.push(c);
        } else if sighash_midstates_for(tx) {
            v.push(TxPrecompute::Script(TxScriptPrecompute::from_connect(
                c.into_connect(),
                tx,
            )));
        } else {
            v.push(c);
        }
    }
    (Arc::from(v), skip)
}

/// BIP144 non-witness slices. `None` unless `wire` is `version || 00 01 || vin || vout || witness || locktime`.
#[doc(hidden)]
pub struct WitnessWire<'a> {
    pub version: &'a [u8],
    pub vin: &'a [u8],
    pub vout: &'a [u8],
    pub locktime: &'a [u8],
}

impl WitnessWire<'_> {
    #[doc(hidden)]
    pub fn base_len(&self) -> usize {
        self.version.len() + self.vin.len() + self.vout.len() + self.locktime.len()
    }
}

#[doc(hidden)]
pub fn flag_zero_wire(wire: &[u8]) -> bool {
    wire.len() == FLAG_ZERO_TX_LEN && wire.get(4..6) == Some(&[0, 0])
}

/// Core's flag-0 10-byte tx: empty vin and vout, not a BIP144 marker.
#[doc(hidden)]
pub fn flag_zero_tx(tx: &Transaction, wire: &[u8]) -> bool {
    flag_zero_wire(wire) && tx.input.is_empty() && tx.output.is_empty()
}

#[doc(hidden)]
pub fn witness_wire<'a>(tx: &Transaction, wire: &'a [u8]) -> Option<WitnessWire<'a>> {
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

#[doc(hidden)]
pub fn hash_witness_txid(spans: &WitnessWire<'_>) -> [u8; 32] {
    let mut eng = sha256d::Hash::engine();
    eng.input(spans.version);
    eng.input(spans.vin);
    eng.input(spans.vout);
    eng.input(spans.locktime);
    sha256d::Hash::from_engine(eng).to_byte_array()
}

/// Legacy layout: `version || vin || vout || locktime` covering all of `wire`.
#[doc(hidden)]
pub fn legacy_spans<'a>(tx: &Transaction, wire: &'a [u8]) -> Option<WitnessWire<'a>> {
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
#[doc(hidden)]
pub const OUTPOINT_LEN: usize = 36;
#[doc(hidden)]
pub const SEQUENCE_LEN: usize = 4;

/// Single SHA-256 of prevouts, sequences, and outputs. `None` is the connect
/// path that skipped sighash.
#[doc(hidden)]
pub type SighashMidstates = [Option<[u8; 32]>; 3];

/// Txid from the non-witness slices, and BIP143/341 single-SHA midstates from
/// the same bytes. Outpoint is the first 36 bytes of each input; sequence is
/// the last 4. Outputs are the vout slice after the compact-size count.
#[doc(hidden)]
pub fn hash_wire_sighash(
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

#[doc(hidden)]
pub fn sigops_and_out_sum(tx: &Transaction) -> (u64, u64) {
    let sigops = crate::block::legacy_sigop_count(tx);
    let out_sum = tx
        .output
        .iter()
        .fold(0u64, |n, txout| n.saturating_add(txout.value.to_sat()));
    (sigops, out_sum)
}

#[doc(hidden)]
pub fn sighash_midstates(tx: &Transaction) -> [[u8; 32]; 3] {
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
        sha256::Hash::from_engine(sha_prev).to_byte_array(),
        sha256::Hash::from_engine(sha_seq).to_byte_array(),
        sha256::Hash::from_engine(sha_out).to_byte_array(),
    ]
}

/// A consensus-serialized tx is at least 10 bytes (version, two compact sizes, locktime).
#[doc(hidden)]
pub fn block_tx_count_fits(n: usize, remaining: usize) -> bool {
    n <= remaining / 10
}

#[doc(hidden)]
pub const FLAG_ZERO_TX_LEN: usize = 10;

/// Core's `UnserializeTransaction` reads an empty vin followed by segwit flag
/// 0 as a tx with no inputs and no outputs, then the locktime. Those 10 bytes
/// are also that tx's legacy encoding, so the txid matches Core. rust-bitcoin
/// refuses flag 0; without this the block never gets Core's invalid verdict.
#[doc(hidden)]
pub fn decode_flag_zero_tx(wire: &[u8]) -> Option<Transaction> {
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
        let tx = match Transaction::consensus_decode(&mut cur) {
            Ok(tx) => tx,
            Err(_) => {
                cur.set_position(start as u64);
                let tx = decode_flag_zero_tx(&payload[start..])?;
                cur.set_position((start + FLAG_ZERO_TX_LEN) as u64);
                tx
            }
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

#[doc(hidden)]
pub fn enc(w: &mut impl bitcoin::io::Write, v: &impl Encodable) -> usize {
    v.consensus_encode(w).expect("hash engines do not error")
}

#[doc(hidden)]
pub fn sha256_again(single: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::from_byte_array(*single)
        .hash_again()
        .to_byte_array()
}

/// BIP143/341 common midstates are used only by a non-coinbase segwit transaction.
#[doc(hidden)]
pub fn sighash_midstates_for(tx: &Transaction) -> bool {
    !tx.is_coinbase() && uses_segwit_serialization(tx)
}

/// rust-bitcoin `Transaction::uses_segwit_serialization` (private).
#[doc(hidden)]
pub fn uses_segwit_serialization(tx: &Transaction) -> bool {
    if tx.input.iter().any(|i| !i.witness.is_empty()) {
        return true;
    }
    tx.input.is_empty()
}
